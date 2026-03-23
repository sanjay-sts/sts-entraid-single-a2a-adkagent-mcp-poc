"""On-Behalf-Of (OBO) token exchange for Microsoft Graph API.

Exchanges the user's custom-audience token (api://{CLIENT_ID}) for a
Graph-scoped token using Azure's OnBehalfOfCredential. This allows MCP
tools to call Graph API endpoints on behalf of the authenticated user.

OBO is Entra-only. Non-Entra users (Cognito, Auth0) cannot exchange
tokens for Graph — they get a clean error; agent-owned tools still work.
"""

import os
import hashlib
import logging

from azure.identity.aio import OnBehalfOfCredential

logger = logging.getLogger("mcp_server.obo")

# Module-level singleton
_exchanger: "GraphOBOExchanger | None" = None


class GraphOBOExchanger:
    """Exchanges user assertion tokens for Graph-scoped tokens via OBO flow."""

    def __init__(self, tenant_id: str, client_id: str, client_secret: str):
        self._tenant_id = tenant_id
        self._client_id = client_id
        self._client_secret = client_secret
        # LRU cache of credentials keyed by assertion hash.
        # Each OnBehalfOfCredential is bound to a specific user assertion.
        self._credentials: dict[str, OnBehalfOfCredential] = {}
        self._max_cache = 128

    def _get_credential(self, user_assertion: str) -> OnBehalfOfCredential:
        """Get or create a cached credential for this user assertion."""
        cache_key = hashlib.sha256(user_assertion.encode()).hexdigest()

        if cache_key not in self._credentials:
            # Evict oldest if at capacity
            if len(self._credentials) >= self._max_cache:
                oldest_key = next(iter(self._credentials))
                del self._credentials[oldest_key]

            self._credentials[cache_key] = OnBehalfOfCredential(
                tenant_id=self._tenant_id,
                client_id=self._client_id,
                client_secret=self._client_secret,
                user_assertion=user_assertion,
            )

        return self._credentials[cache_key]

    async def get_graph_token(
        self, user_assertion: str, scopes: list[str] | None = None
    ) -> str | None:
        """Exchange user token for a Graph-scoped token.

        Args:
            user_assertion: The user's access token (custom-audience JWT)
            scopes: Graph API scopes to request. Defaults to common scopes.

        Returns:
            Graph access token string, or None on failure.
        """
        if not scopes:
            scopes = ["https://graph.microsoft.com/.default"]

        try:
            credential = self._get_credential(user_assertion)
            token = await credential.get_token(*scopes)
            return token.token
        except Exception as e:
            logger.warning("OBO token exchange failed: %s", e)
            return None

    async def close(self) -> None:
        """Close all cached credentials."""
        for cred in self._credentials.values():
            try:
                await cred.close()
            except Exception:
                pass
        self._credentials.clear()


def init_obo_exchanger() -> None:
    """Initialize the module-level OBO exchanger singleton.

    Requires ENTRA_TENANT_ID, ENTRA_CLIENT_ID, and ENTRA_CLIENT_SECRET.
    If ENTRA_CLIENT_SECRET is not set, OBO is disabled (existing fallback preserved).
    """
    global _exchanger

    tenant_id = os.getenv("ENTRA_TENANT_ID")
    client_id = os.getenv("ENTRA_CLIENT_ID")
    client_secret = os.getenv("ENTRA_CLIENT_SECRET")

    if not client_secret:
        logger.info("OBO disabled -- ENTRA_CLIENT_SECRET not set")
        return

    if not tenant_id or not client_id:
        logger.warning("OBO disabled -- ENTRA_TENANT_ID or ENTRA_CLIENT_ID not set")
        return

    _exchanger = GraphOBOExchanger(tenant_id, client_id, client_secret)
    logger.info("OBO exchanger initialized (tenant: %s)", tenant_id)


def get_obo_exchanger() -> "GraphOBOExchanger | None":
    """Get the module-level OBO exchanger, or None if not initialized."""
    return _exchanger
