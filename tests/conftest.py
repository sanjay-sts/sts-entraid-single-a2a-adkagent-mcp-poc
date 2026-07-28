"""Pytest configuration and fixtures."""
import pytest
import asyncio
import os
from datetime import datetime, timezone, timedelta
from dotenv import load_dotenv

# Load environment variables for tests
load_dotenv()


# ---------------------------------------------------------------------------
# Event loop (shared by all async tests)
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    policy = asyncio.get_event_loop_policy()
    loop = policy.new_event_loop()
    yield loop
    loop.close()


# ---------------------------------------------------------------------------
# Mock-token fixtures (existing, used by test_access_control.py)
# ---------------------------------------------------------------------------

@pytest.fixture
def admin_token():
    """Generate an admin test token (HS256 mock)."""
    from tests.test_access_control import create_test_token
    return create_test_token(
        user_id="admin-user",
        groups=[os.getenv("ADMIN_GROUP_ID", "admin-group-id")],
        scopes="User.Read Files.Read Mail.Send Files.ReadWrite.All"
    )


@pytest.fixture
def developer_token():
    """Generate a developer test token (HS256 mock)."""
    from tests.test_access_control import create_test_token
    return create_test_token(
        user_id="developer-user",
        groups=[os.getenv("DEVELOPER_GROUP_ID", "developer-group-id")],
        scopes="User.Read Files.Read"
    )


@pytest.fixture
def viewer_token():
    """Generate a viewer test token (HS256 mock)."""
    from tests.test_access_control import create_test_token
    return create_test_token(
        user_id="viewer-user",
        groups=[os.getenv("VIEWER_GROUP_ID", "viewer-group-id")],
        scopes="User.Read"
    )


# ---------------------------------------------------------------------------
# Cognito mock-token helpers and fixtures
# ---------------------------------------------------------------------------

def create_cognito_test_token(
    user_id: str,
    groups: list,
    email: str = "test@cognito.example.com",
) -> str:
    """Create a mock Cognito JWT token (HS256 for testing)."""
    import jwt as pyjwt
    return pyjwt.encode(
        {
            "sub": user_id,
            "cognito:groups": groups,
            "cognito:username": user_id,
            "email": email,
            "token_use": "access",
            "scope": "openid profile email ai-agent-api/access_as_user",
            "aud": os.getenv("COGNITO_CLIENT_ID", "test-cognito-client"),
            "iss": f"https://cognito-idp.{os.getenv('COGNITO_REGION', 'us-east-1')}.amazonaws.com/{os.getenv('COGNITO_USER_POOL_ID', 'us-east-1_test')}",
            "exp": datetime.now(timezone.utc) + timedelta(hours=1),
            "iat": datetime.now(timezone.utc),
        },
        "test-secret",
        algorithm="HS256",
    )


@pytest.fixture
def cognito_admin_token():
    """Generate a Cognito admin test token (HS256 mock)."""
    return create_cognito_test_token(
        user_id="cognito-admin",
        groups=["platform-admins"],
        email="admin@test.com",
    )


@pytest.fixture
def cognito_developer_token():
    """Generate a Cognito developer test token (HS256 mock)."""
    return create_cognito_test_token(
        user_id="cognito-developer",
        groups=["platform-developers"],
        email="dev@test.com",
    )


@pytest.fixture
def cognito_viewer_token():
    """Generate a Cognito viewer test token (HS256 mock)."""
    return create_cognito_test_token(
        user_id="cognito-viewer",
        groups=["platform-viewers"],
        email="viewer@test.com",
    )


# ---------------------------------------------------------------------------
# Real Entra ID token fixtures (used by test_security_dashboard.py)
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def real_admin_token():
    """Real Entra ID admin token from TEST_ADMIN_TOKEN env var."""
    token = os.getenv("TEST_ADMIN_TOKEN", "").strip()
    if not token:
        pytest.skip("TEST_ADMIN_TOKEN not set – acquire via Token Inspector")
    return token


@pytest.fixture(scope="session")
def real_developer_token():
    """Real Entra ID developer token from TEST_DEVELOPER_TOKEN env var."""
    token = os.getenv("TEST_DEVELOPER_TOKEN", "").strip()
    if not token:
        pytest.skip("TEST_DEVELOPER_TOKEN not set – acquire via Token Inspector")
    return token


@pytest.fixture(scope="session")
def real_viewer_token():
    """Real Entra ID viewer token from TEST_VIEWER_TOKEN env var."""
    token = os.getenv("TEST_VIEWER_TOKEN", "").strip()
    if not token:
        pytest.skip("TEST_VIEWER_TOKEN not set – acquire via Token Inspector")
    return token


@pytest.fixture(scope="session")
def real_nogroup_token():
    """Real Entra ID token for a user not in any authorized group."""
    token = os.getenv("TEST_NOGROUP_TOKEN", "").strip()
    if not token:
        pytest.skip("TEST_NOGROUP_TOKEN not set – acquire via Token Inspector")
    return token


# ---------------------------------------------------------------------------
# Service URL fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def a2a_url():
    """A2A server base URL."""
    return os.getenv("A2A_URL", "http://localhost:10000")


@pytest.fixture(scope="session")
def adk_url():
    """ADK agent base URL."""
    return os.getenv("ADK_URL", "http://localhost:10001")


@pytest.fixture(scope="session")
def mcp_url():
    """MCP server base URL."""
    return os.getenv("MCP_URL", "http://localhost:10002")


# ---------------------------------------------------------------------------
# Service availability check
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def require_services(a2a_url, adk_url):
    """Skip tests if backend services are not running."""
    import httpx

    for label, url in [("A2A", a2a_url), ("ADK", adk_url)]:
        try:
            resp = httpx.get(f"{url}/health", timeout=5.0)
            if resp.status_code != 200:
                pytest.skip(f"{label} server at {url} returned {resp.status_code}")
        except httpx.ConnectError:
            pytest.skip(f"{label} server not running at {url}")
        except Exception as exc:
            pytest.skip(f"{label} server check failed: {exc}")


# ---------------------------------------------------------------------------
# Helper factories
# ---------------------------------------------------------------------------

@pytest.fixture
def make_a2a_message():
    """Factory for creating A2A JSON-RPC message/send request bodies."""
    def _make(text: str, message_id: str | None = None) -> dict:
        mid = message_id or f"test-{datetime.now(timezone.utc).timestamp()}"
        return {
            "jsonrpc": "2.0",
            "method": "message/send",
            "params": {
                "message": {
                    "messageId": mid,
                    "role": "user",
                    "parts": [{"kind": "text", "text": text}],
                }
            },
            "id": 1,
        }
    return _make


@pytest.fixture
def extract_agent_text():
    """Extract text from an A2A JSON-RPC response.

    Handles both:
      - result.status.message.parts[*].text
      - result.message.parts[*].text
    Returns the concatenated text or empty string.
    """
    def _extract(response_json: dict) -> str:
        result = response_json.get("result", {})
        # Try status.message path first
        message = result.get("status", {}).get("message", {})
        if not message:
            message = result.get("message", {})
        parts = message.get("parts", [])
        texts = [p.get("text", "") for p in parts if p.get("kind") == "text" or "text" in p]
        return " ".join(texts)
    return _extract


# ---------------------------------------------------------------------------
# pytest-html report hooks
# ---------------------------------------------------------------------------

def pytest_html_report_title(report):
    """Set a custom title for the HTML report."""
    report.title = "Security Dashboard Test Report"


def pytest_configure(config):
    """Add metadata to the HTML report."""
    if hasattr(config, "_metadata"):
        config._metadata["Project"] = "Identity-Aware AI Agent System"
        config._metadata["A2A URL"] = os.getenv("A2A_URL", "http://localhost:10000")
        config._metadata["ADK URL"] = os.getenv("ADK_URL", "http://localhost:10001")
        config._metadata["MCP URL"] = os.getenv("MCP_URL", "http://localhost:10002")
        config._metadata["Admin Token"] = "SET" if os.getenv("TEST_ADMIN_TOKEN") else "NOT SET"
        config._metadata["Developer Token"] = "SET" if os.getenv("TEST_DEVELOPER_TOKEN") else "NOT SET"
        config._metadata["Viewer Token"] = "SET" if os.getenv("TEST_VIEWER_TOKEN") else "NOT SET"
        config._metadata["No-Group Token"] = "SET" if os.getenv("TEST_NOGROUP_TOKEN") else "NOT SET"
        config._metadata["Test Date"] = datetime.now(timezone.utc).isoformat()

    # Ensure reports directory exists
    os.makedirs("reports", exist_ok=True)


# ---------------------------------------------------------------------------
# Multi-agent fixtures (real Entra app registrations — see docs/ENTRA_AGENT_SETUP.md)
#
# Every one of these skips rather than fails when its prerequisite is absent,
# and the skip message names exactly what is missing. An integration suite that
# fails when it is merely unconfigured trains people to ignore it.
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def agents_configured():
    """Skip unless every agent app registration and its cert are present."""
    from pathlib import Path

    required = [
        "ENTRA_TENANT_ID",
        "ENTRA_CLIENT_ID",
        "AGENT_ORCHESTRATOR_CLIENT_ID",
        "AGENT_PEER_CLIENT_ID",
        "AGENT_EVENT_TRIGGER_CLIENT_ID",
    ]
    missing = [v for v in required if not os.getenv(v, "").strip()]
    if missing:
        pytest.skip(f"agent identities not configured: {', '.join(missing)}")

    cert_dir = Path(os.getenv("AGENT_CERT_DIR", "pki/certs"))
    for name in ["gateway", "orchestrator", "peer", "event-trigger"]:
        if not (cert_dir / f"{name}.key").exists():
            pytest.skip(f"missing {name} key — run: uv run python pki/generate_certs.py")

    from agent_common import registry
    registry.reload()


@pytest.fixture(scope="session")
def orchestrator_url():
    return os.getenv("ORCHESTRATOR_URL", "http://localhost:10004")


@pytest.fixture(scope="session")
def peer_url():
    return os.getenv("PEER_URL", "http://localhost:10005")


@pytest.fixture(scope="session")
def gateway_url():
    return os.getenv("A2A_URL", "http://localhost:10000")


@pytest.fixture(scope="session")
def require_agent_services(orchestrator_url, peer_url, gateway_url):
    """Skip unless every service the fan-out touches is running.

    The gateway is included even though no test calls it directly: the
    orchestrator fans out to it, and without it that leg comes back as a
    transport failure that reads like an authorization bug.
    """
    import httpx

    services = [
        ("Orchestrator", orchestrator_url),
        ("Peer agent", peer_url),
        ("Gateway", gateway_url),
    ]
    for label, url in services:
        try:
            resp = httpx.get(f"{url}/health", timeout=5.0)
            if resp.status_code != 200:
                pytest.skip(f"{label} at {url} returned {resp.status_code}")
        except Exception:
            pytest.skip(f"{label} not running at {url}")


@pytest.fixture(scope="session")
def delegated_user_token():
    """A real *user* token, for exercising the delegated (OBO) path.

    Audienced to the gateway, because that is what a browser sign-in produces
    and therefore what the first delegated hop actually receives.

    Expiry is checked here rather than left to Entra: an hour-old token
    produces an `invalid_grant` from the OBO endpoint, which reads like a
    misconfigured app registration and sends people to the wrong place.
    """
    import jwt

    token = os.getenv("TEST_ADMIN_TOKEN", "").strip()
    if not token:
        pytest.skip(
            "TEST_ADMIN_TOKEN not set — needed for the delegated path. "
            "Sign in to the frontend and copy the access token."
        )

    try:
        claims = jwt.decode(token, options={"verify_signature": False})
    except Exception as e:
        pytest.skip(f"TEST_ADMIN_TOKEN is not a JWT: {e}")

    import time
    if claims.get("exp", 0) <= time.time():
        pytest.skip("TEST_ADMIN_TOKEN has expired — sign in again and re-copy it")

    return token
