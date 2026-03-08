"""Pytest configuration and fixtures."""
import pytest
import asyncio
import os
from datetime import datetime, timezone
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
