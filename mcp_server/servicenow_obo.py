"""On-Behalf-Of (OBO) token exchange for the ServiceNow REST API.

Exchanges the user's custom-audience token (api://{CLIENT_ID}) for a
ServiceNow-scoped token using Azure's OnBehalfOfCredential, so MCP tools can
call ServiceNow as the authenticated end user rather than the shared service
account. ServiceNow then applies its own per-user ACLs (KB user_criteria,
incident record rules) against that identity.

OBO is Entra-only. Non-Entra users (Cognito, Auth0) cannot exchange tokens;
the ServiceNow client falls back to service-account Basic auth, and Cedar
remains the only authority for those users.

Mirrors mcp_server/graph_obo.py — the differences are the target scope (the
ServiceNow resource app, from [servicenow].obo_scope) and the method name.
"""
import hashlib
import logging
import os

from azure.identity.aio import OnBehalfOfCredential

logger = logging.getLogger("mcp_server.servicenow_obo")

# Module-level singleton (set by init_sn_obo_exchanger at startup)
_exchanger: "ServiceNowOBOExchanger | None" = None


class ServiceNowOBOExchanger:
    """Exchanges user assertion tokens for ServiceNow-scoped tokens via OBO."""

    def __init__(
        self, tenant_id: str, client_id: str, client_secret: str, scope: str
    ):
        self._tenant_id = tenant_id
        self._client_id = client_id
        self._client_secret = client_secret
        self._scope = scope
        # LRU cache of credentials keyed by assertion hash. Each
        # OnBehalfOfCredential is bound to a specific user assertion.
        self._credentials: dict[str, OnBehalfOfCredential] = {}
        self._max_cache = 128

    def _get_credential(self, user_assertion: str) -> OnBehalfOfCredential:
        """Get or create a cached credential for this user assertion."""
        cache_key = hashlib.sha256(user_assertion.encode()).hexdigest()

        if cache_key not in self._credentials:
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

    async def get_sn_token(self, user_assertion: str) -> str | None:
        """Exchange the user token for a ServiceNow-scoped token.

        Returns the access token string, or None on failure (logged, not
        raised — the caller then falls back to service-account auth).
        """
        try:
            credential = self._get_credential(user_assertion)
            token = await credential.get_token(self._scope)
            return token.token
        except Exception as e:
            logger.warning("ServiceNow OBO token exchange failed: %s", e)
            return None

    async def close(self) -> None:
        """Close all cached credentials."""
        for cred in self._credentials.values():
            try:
                await cred.close()
            except Exception:
                pass
        self._credentials.clear()


def init_sn_obo_exchanger(scope: str) -> None:
    """Initialise the module-level ServiceNow OBO exchanger singleton.

    Reuses the Entra app credentials (ENTRA_TENANT_ID / ENTRA_CLIENT_ID /
    ENTRA_CLIENT_SECRET). `scope` is the ServiceNow resource scope, e.g.
    "api://<servicenow-app-id>/.default", from [servicenow].obo_scope.

    Disabled (no-op; exchanger stays None) when the scope or any Entra
    credential is missing. The ServiceNow client then uses service-account
    Basic auth — same dormancy contract as graph_obo.init_obo_exchanger().
    """
    global _exchanger

    if not scope:
        logger.info("ServiceNow OBO disabled -- obo_scope not set")
        return

    tenant_id = os.getenv("ENTRA_TENANT_ID")
    client_id = os.getenv("ENTRA_CLIENT_ID")
    client_secret = os.getenv("ENTRA_CLIENT_SECRET")

    if not client_secret:
        logger.info("ServiceNow OBO disabled -- ENTRA_CLIENT_SECRET not set")
        return

    if not tenant_id or not client_id:
        logger.warning(
            "ServiceNow OBO disabled -- ENTRA_TENANT_ID or ENTRA_CLIENT_ID not set"
        )
        return

    _exchanger = ServiceNowOBOExchanger(tenant_id, client_id, client_secret, scope)
    logger.info("ServiceNow OBO exchanger initialised (scope: %s)", scope)


def get_sn_obo_exchanger() -> "ServiceNowOBOExchanger | None":
    """Get the module-level ServiceNow OBO exchanger, or None if disabled."""
    return _exchanger
