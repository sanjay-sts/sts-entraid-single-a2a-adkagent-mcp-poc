"""In-memory ServiceNow mock — used when [servicenow].instance_url is empty.

Same method surface as `servicenow.ServiceNowClient`, including the optional
per-call `token` kwarg (the OBO bearer token). The mock cannot enforce a real
ACL, so it ignores the token for data filtering but records it as
`last_token` so tests can assert the tool layer threaded it through. Wraps the
same {"result": ...} envelope ServiceNow uses on the real REST API so tool
code that consumes either client looks identical.

The mock includes a `u_department` field on incidents (which real SN does
NOT have in this branch — see the spec under 'Decisions Resolved'). This
lets mocked integration tests exercise the developer dept-ABAC paths
end-to-end even though the field won't exist against a live dev instance
until the OBO follow-up.
"""
import copy
import logging
from typing import Any

logger = logging.getLogger("mcp_server.servicenow_mock")


_KB_DATA: list[dict] = [
    {"sys_id": "kb-it-0000000000000000000000000001", "title": "IT KB",      "u_department": "IT"},
    {"sys_id": "kb-hr-0000000000000000000000000002", "title": "HR KB",      "u_department": "HR"},
    {"sys_id": "kb-fn-0000000000000000000000000003", "title": "Finance KB", "u_department": "Finance"},
]


_ARTICLE_DATA: list[dict] = [
    # IT KB
    {"sys_id": "art-it-0001", "number": "KB0010001", "kb_knowledge_base": "kb-it-0000000000000000000000000001", "short_description": "Reset your VPN password",     "text": "<p>Follow these steps...</p>"},
    {"sys_id": "art-it-0002", "number": "KB0010002", "kb_knowledge_base": "kb-it-0000000000000000000000000001", "short_description": "Provision a new laptop",      "text": "<p>Hardware request flow...</p>"},
    {"sys_id": "art-it-0003", "number": "KB0010003", "kb_knowledge_base": "kb-it-0000000000000000000000000001", "short_description": "Set up multifactor auth",     "text": "<p>Open Authenticator...</p>"},
    # HR KB
    {"sys_id": "art-hr-0001", "number": "KB0020001", "kb_knowledge_base": "kb-hr-0000000000000000000000000002", "short_description": "Submitting a PTO request",    "text": "<p>Use the HR portal...</p>"},
    {"sys_id": "art-hr-0002", "number": "KB0020002", "kb_knowledge_base": "kb-hr-0000000000000000000000000002", "short_description": "Health benefits enrollment",  "text": "<p>Open enrollment window...</p>"},
    {"sys_id": "art-hr-0003", "number": "KB0020003", "kb_knowledge_base": "kb-hr-0000000000000000000000000002", "short_description": "Performance review timeline", "text": "<p>Cycle dates...</p>"},
    # Finance KB
    {"sys_id": "art-fn-0001", "number": "KB0030001", "kb_knowledge_base": "kb-fn-0000000000000000000000000003", "short_description": "Submitting an expense report","text": "<p>Use Concur...</p>"},
    {"sys_id": "art-fn-0002", "number": "KB0030002", "kb_knowledge_base": "kb-fn-0000000000000000000000000003", "short_description": "Corporate card guidelines",   "text": "<p>Eligible expenses...</p>"},
    {"sys_id": "art-fn-0003", "number": "KB0030003", "kb_knowledge_base": "kb-fn-0000000000000000000000000003", "short_description": "Vendor payment terms",        "text": "<p>Net 30...</p>"},
]


_INCIDENT_DATA: list[dict] = [
    {"sys_id": "inc-it-0001", "number": "INC0010001", "short_description": "Wi-Fi outage on floor 4", "state": "2", "u_department": "IT"},
    {"sys_id": "inc-it-0002", "number": "INC0010002", "short_description": "Email distribution list missing", "state": "1", "u_department": "IT"},
    {"sys_id": "inc-hr-0001", "number": "INC0020001", "short_description": "Onboarding portal locked", "state": "2", "u_department": "HR"},
    {"sys_id": "inc-fn-0001", "number": "INC0030001", "short_description": "Concur expense rejected", "state": "1", "u_department": "Finance"},
    {"sys_id": "inc-fn-0002", "number": "INC0030002", "short_description": "Bank reconciliation diff", "state": "3", "u_department": "Finance"},
]


def _envelope(result: Any) -> dict:
    """Wrap a result in ServiceNow's REST envelope."""
    return {"result": result}


class ServiceNowMockClient:
    """Drop-in mock for ServiceNowClient.

    State is per-instance (not shared between tests in the same process
    unless the singleton is reused). Tests that want a fresh state should
    reinitialise via init_servicenow_client(""). The `token` kwarg on each
    method is recorded as `last_token` but does not affect returned data.
    """

    def __init__(self) -> None:
        self._kbs = copy.deepcopy(_KB_DATA)
        self._articles = copy.deepcopy(_ARTICLE_DATA)
        self._incidents = copy.deepcopy(_INCIDENT_DATA)
        self._inc_counter = max(int(i["number"][3:]) for i in self._incidents) + 1
        self.last_token: str | None = None

    # ── Knowledge Bases ──────────────────────────────────────────────

    async def list_knowledge_bases(self, token: str | None = None) -> dict:
        self.last_token = token
        return _envelope(list(self._kbs))

    async def get_knowledge_base_metadata(
        self, identifier: str, token: str | None = None
    ) -> dict | None:
        self.last_token = token
        for kb in self._kbs:
            if kb["sys_id"] == identifier or kb["title"] == identifier:
                return kb
        return None

    # ── Articles ─────────────────────────────────────────────────────

    async def list_articles(
        self, kb_sys_id: str, query: str = "", token: str | None = None
    ) -> dict:
        self.last_token = token
        matches = [a for a in self._articles if a["kb_knowledge_base"] == kb_sys_id]
        if query:
            q = query.lower()
            matches = [a for a in matches if q in a["short_description"].lower()]
        return _envelope(matches)

    async def get_article(self, sys_id: str, token: str | None = None) -> dict:
        self.last_token = token
        for a in self._articles:
            if a["sys_id"] == sys_id:
                return _envelope(a)
        return {"error": "record not found", "status": 404}

    # ── Incidents ────────────────────────────────────────────────────

    async def list_incidents(
        self, department: str | None = None, token: str | None = None
    ) -> dict:
        self.last_token = token
        return _envelope(list(self._incidents))

    async def get_incident(self, sys_id: str, token: str | None = None) -> dict:
        self.last_token = token
        for i in self._incidents:
            if i["sys_id"] == sys_id:
                return _envelope(i)
        return {"error": "record not found", "status": 404}

    async def create_incident(
        self,
        short_description: str,
        description: str = "",
        urgency: str = "3",
        token: str | None = None,
        **extras: Any,
    ) -> dict:
        self.last_token = token
        new_num = f"INC{self._inc_counter:07d}"
        self._inc_counter += 1
        record = {
            "sys_id": f"inc-mock-{new_num.lower()}",
            "number": new_num,
            "short_description": short_description,
            "description": description,
            "urgency": urgency,
            "state": "1",
            **{k: v for k, v in extras.items() if k.startswith("u_") or k in ("urgency", "state")},
        }
        self._incidents.append(record)
        return _envelope(record)

    async def update_incident(
        self, sys_id: str, payload: dict, token: str | None = None
    ) -> dict:
        self.last_token = token
        for i in self._incidents:
            if i["sys_id"] == sys_id:
                i.update(payload)
                return _envelope(i)
        return {"error": "record not found", "status": 404}
