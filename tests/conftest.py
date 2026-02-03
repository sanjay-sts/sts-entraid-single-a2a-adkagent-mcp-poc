"""Pytest configuration and fixtures."""
import pytest
import asyncio
import os
from dotenv import load_dotenv

# Load environment variables for tests
load_dotenv()


@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    policy = asyncio.get_event_loop_policy()
    loop = policy.new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def admin_token():
    """Generate an admin test token."""
    from tests.test_access_control import create_test_token
    return create_test_token(
        user_id="admin-user",
        groups=[os.getenv("ADMIN_GROUP_ID", "admin-group-id")],
        scopes="User.Read Files.Read Mail.Send Files.ReadWrite.All"
    )


@pytest.fixture
def developer_token():
    """Generate a developer test token."""
    from tests.test_access_control import create_test_token
    return create_test_token(
        user_id="developer-user",
        groups=[os.getenv("DEVELOPER_GROUP_ID", "developer-group-id")],
        scopes="User.Read Files.Read"
    )


@pytest.fixture
def viewer_token():
    """Generate a viewer test token."""
    from tests.test_access_control import create_test_token
    return create_test_token(
        user_id="viewer-user",
        groups=[os.getenv("VIEWER_GROUP_ID", "viewer-group-id")],
        scopes="User.Read"
    )
