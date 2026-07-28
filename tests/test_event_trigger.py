"""Event trigger — the machine-to-machine entry point.

The defining property of this script is something it does NOT do: it sends no
user token. In the plan that was a comment, which is exactly the kind of thing
a later "helpful" edit adds back. It is asserted here instead.

The second thing worth testing is the exit code. This simulates a cron source,
and a cron entry point that exits 0 whether or not it was refused is useless
for the one job it has.
"""
import sys

import pytest

import event_trigger

EVT = "evt-id"
ORCH = "orch-id"


@pytest.fixture(autouse=True)
def trigger_env(monkeypatch):
    monkeypatch.setenv("AGENT_EVENT_TRIGGER_CLIENT_ID", EVT)
    monkeypatch.setenv("AGENT_ORCHESTRATOR_CLIENT_ID", ORCH)
    monkeypatch.setenv("ENTRA_TENANT_ID", "tid")
    from agent_common import registry
    registry.reload()
    yield
    registry.reload()


class FakeProvider:
    """Records what it was asked to mint, and whether it was closed."""

    instances = []

    def __init__(self, identity):
        self.identity = identity
        self.minted = []
        self.closed = False
        FakeProvider.instances.append(self)

    async def get_agent_token(self, callee):
        self.minted.append(callee)
        return f"agent-token-for-{callee}"

    async def close(self):
        self.closed = True


@pytest.fixture
def dispatch(monkeypatch):
    """Capture the request the trigger would send. Returns a mutable control dict."""
    state = {"status": 200, "body": {"principal_type": "machine"}, "raise": None, "sent": None}
    FakeProvider.instances = []
    monkeypatch.setattr(event_trigger, "AgentTokenProvider", FakeProvider)

    class FakeResponse:
        status_code = property(lambda self: state["status"])
        text = "not json"

        def json(self):
            if state["body"] is None:
                raise ValueError("not json")
            return state["body"]

    class FakeClient:
        def __init__(self, *a, **kw):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def post(self, url, json=None, headers=None, timeout=None):
            state["sent"] = {"url": url, "payload": json, "headers": headers or {}}
            if state["raise"]:
                raise state["raise"]
            return FakeResponse()

    monkeypatch.setattr(event_trigger.httpx, "AsyncClient", FakeClient)
    return state


def run_main(monkeypatch, argv=("event_trigger.py", "--task", "status")):
    monkeypatch.setattr(sys, "argv", list(argv))
    with pytest.raises(SystemExit) as exc:
        event_trigger.main()
    return exc.value.code


# --------------------------------------------------------------------------
# What is on the wire
# --------------------------------------------------------------------------


def test_no_user_token_is_ever_sent(dispatch, monkeypatch):
    """The whole point of this entry point.

    A user token here would make the downstream chain resolve a DELEGATED
    principal, and every assertion about the machine path would be quietly
    testing the wrong thing.
    """
    run_main(monkeypatch)

    headers = dispatch["sent"]["headers"]
    assert "X-Delegated-User-Token" not in headers
    assert list(headers) == ["Authorization"], f"unexpected headers: {headers}"


def test_the_token_is_minted_for_the_orchestrator(dispatch, monkeypatch):
    """Audience narrowing starts here — the first token in the chain must name
    the orchestrator, not this agent's own audience or a generic scope."""
    run_main(monkeypatch)

    assert FakeProvider.instances[0].minted == ["orchestrator"]
    assert dispatch["sent"]["headers"]["Authorization"] == "Bearer agent-token-for-orchestrator"


def test_the_task_reaches_the_orchestrator(dispatch, monkeypatch):
    run_main(monkeypatch, ("event_trigger.py", "--task", "audit-sweep"))

    assert dispatch["sent"]["payload"] == {"task": "audit-sweep"}
    assert dispatch["sent"]["url"].endswith("/dispatch")


# --------------------------------------------------------------------------
# Exit codes — a cron source that always exits 0 reports nothing
# --------------------------------------------------------------------------


def test_a_machine_dispatch_exits_zero(dispatch, monkeypatch):
    assert run_main(monkeypatch) == 0


def test_a_refused_dispatch_exits_nonzero(dispatch, monkeypatch):
    """If the orchestrator refuses this agent, a cron run must be able to tell."""
    dispatch["status"] = 403
    dispatch["body"] = {"denial_reason": "unknown_agent"}
    assert run_main(monkeypatch) == 2


def test_a_delegated_result_exits_nonzero(dispatch, monkeypatch):
    """A 200 is not success here. This entry point exists to exercise the
    machine path; if a human appeared in the chain, something upstream is
    wrong in a way that would otherwise go unnoticed."""
    dispatch["body"] = {"principal_type": "delegated", "on_behalf_of": "someone"}
    assert run_main(monkeypatch) == 3


def test_an_unconfigured_agent_exits_with_guidance(monkeypatch, capsys):
    monkeypatch.delenv("AGENT_EVENT_TRIGGER_CLIENT_ID", raising=False)
    from agent_common import registry
    registry.reload()

    assert run_main(monkeypatch) == 1
    assert "ENTRA_AGENT_SETUP" in capsys.readouterr().err


def test_a_transport_failure_exits_cleanly(dispatch, monkeypatch, capsys):
    """No traceback: this runs unattended, where a stack trace in a cron log is
    strictly worse than one line naming the unreachable service."""
    import httpx
    dispatch["raise"] = httpx.ConnectError("connection refused")

    assert run_main(monkeypatch) == 1
    err = capsys.readouterr().err
    assert "Traceback" not in err
    assert "orchestrator" in err.lower()


def test_a_non_json_response_does_not_crash(dispatch, monkeypatch):
    dispatch["body"] = None
    assert run_main(monkeypatch) == 3  # ran, but reported no machine principal


# --------------------------------------------------------------------------
# Resource handling
# --------------------------------------------------------------------------


def test_the_credential_is_closed_even_when_the_call_fails(dispatch, monkeypatch):
    """The provider holds an azure-identity credential with an open HTTP client."""
    import httpx
    dispatch["raise"] = httpx.ConnectError("connection refused")

    run_main(monkeypatch)

    assert FakeProvider.instances[0].closed is True
