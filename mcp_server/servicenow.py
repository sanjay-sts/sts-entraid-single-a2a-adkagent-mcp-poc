"""ServiceNow REST client.

Async HTTP client for ServiceNow's Table API. Dual auth: each call may carry
an optional per-user **OBO bearer token** (the end user's Entra identity, so
ServiceNow applies that user's ACLs), and falls back to **service-account HTTP
Basic** when no token is supplied (non-Entra users, or OBO disabled). Errors
are normalised to {"error": ...} dicts to match the existing pattern used for
S3 (mcp_server/server.py:_run_s3_operation).

The OBO token is produced by mcp_server/servicenow_obo.py and threaded in by the
tool layer via `_get_effective_sn_token()`; see the 2026-05-20 hybrid spec.

Configuration in dev_config.toml:
    [servicenow]
    instance_url = ""               # empty → init_servicenow_client picks the mock
    api_user     = "admin"          # service-account fallback
    api_password = "..."
    obo_scope    = ""               # e.g. "api://<sn-app-id>/.default"; empty → OBO off
"""
import logging
from typing import Any

import httpx

logger = logging.getLogger("mcp_server.servicenow")

# Module-level singleton (set by init_servicenow_client at startup)
_client: "ServiceNowClient | ServiceNowMockClient | None" = None

# Map specific status codes to a stable error string. Unmapped 5xx falls
# through to the generic "ServiceNow server error" branch in _request().
_STATUS_ERROR: dict[int, str] = {
    401: "ServiceNow auth failed",
    403: "ServiceNow access denied",
    404: "record not found",
    429: "ServiceNow rate limited; retry later",
}


def _is_sys_id(identifier: str) -> bool:
    """True if `identifier` is a ServiceNow sys_id (32-char hex)."""
    if len(identifier) != 32:
        return False
    try:
        int(identifier, 16)
    except ValueError:
        return False
    return True


class ServiceNowClient:
    """ServiceNow Table API client.

    Per call, an optional `token` selects auth: when set, `Authorization:
    Bearer <token>` (the end user's OBO token) and ServiceNow enforces that
    user's ACLs; when omitted, HTTP Basic with the service account. Methods
    mirror the seven MCP tools' needs and return dicts: success comes from
    ServiceNow's REST envelope ({"result": ...}); errors are normalised.
    """

    def __init__(self, instance_url: str, api_user: str, api_password: str) -> None:
        self._base = instance_url.rstrip("/")
        self._auth = (api_user, api_password)

    async def _request(
        self, method: str, path: str, *, token: str | None = None, **kwargs: Any
    ) -> dict:
        url = f"{self._base}{path}"
        if token:
            # OBO: call ServiceNow AS the end user. SN validates the Entra
            # token and applies that user's ACLs. Overrides service-account auth.
            kwargs["headers"] = {
                **kwargs.get("headers", {}),
                "Authorization": f"Bearer {token}",
            }
        else:
            # Service-account fallback (non-Entra users, or OBO disabled).
            kwargs["auth"] = self._auth
        try:
            async with httpx.AsyncClient(timeout=30.0) as http:
                resp = await http.request(method, url, **kwargs)
        except httpx.ConnectError as e:
            logger.warning("ServiceNow connect error: %s", e)
            return {"error": "ServiceNow unavailable: connection failed"}
        except httpx.TimeoutException:
            return {"error": "ServiceNow timed out"}

        status = resp.status_code
        if status in _STATUS_ERROR:
            return {"error": _STATUS_ERROR[status], "status": status}
        if status >= 500:
            return {"error": "ServiceNow server error", "status": status}

        try:
            body = resp.json()
        except ValueError:
            return {"error": "ServiceNow returned non-JSON", "status": resp.status_code}

        # ServiceNow sometimes returns 200 with an embedded error
        if isinstance(body, dict) and "error" in body and "result" not in body:
            return {"error": body["error"], "status": resp.status_code}

        return body

    # ── Knowledge Bases ──────────────────────────────────────────────

    async def list_knowledge_bases(self, token: str | None = None) -> dict:
        return await self._request(
            "GET", "/api/now/table/kb_knowledge_base",
            params={"sysparm_fields": "sys_id,title,u_department"},
            token=token,
        )

    async def get_knowledge_base_metadata(
        self, identifier: str, token: str | None = None
    ) -> dict | None:
        """Resolve a KB by sys_id (32-hex) or title; return single record or None.

        Returns the SN record dict (with u_department) or None if not found
        or on error.
        """
        fields = "sys_id,title,u_department"

        # Direct sys_id lookup first if identifier looks like one.
        if _is_sys_id(identifier):
            body = await self._request(
                "GET", f"/api/now/table/kb_knowledge_base/{identifier}",
                params={"sysparm_fields": fields},
                token=token,
            )
            if "error" not in body and isinstance(body.get("result"), dict):
                return body["result"]
            # fall through and try by title

        body = await self._request(
            "GET", "/api/now/table/kb_knowledge_base",
            params={
                "sysparm_query": f"title={identifier}",
                "sysparm_limit": "1",
                "sysparm_fields": fields,
            },
            token=token,
        )
        result = body.get("result") if isinstance(body, dict) else None
        if isinstance(result, list) and result:
            return result[0]
        return None

    # ── Articles ─────────────────────────────────────────────────────

    async def list_articles(
        self, kb_sys_id: str, query: str = "", token: str | None = None
    ) -> dict:
        params: dict[str, str] = {"sysparm_query": f"kb_knowledge_base={kb_sys_id}"}
        if query:
            params["sysparm_query"] += f"^short_descriptionLIKE{query}"
        params["sysparm_fields"] = "sys_id,number,short_description,kb_knowledge_base"
        return await self._request(
            "GET", "/api/now/table/kb_knowledge", params=params, token=token,
        )

    async def get_article(self, sys_id: str, token: str | None = None) -> dict:
        return await self._request(
            "GET", f"/api/now/table/kb_knowledge/{sys_id}", token=token,
        )

    # ── Incidents ────────────────────────────────────────────────────

    async def list_incidents(
        self, department: str | None = None, token: str | None = None
    ) -> dict:
        # NOTE: incident u_department field is deferred until OBO is live in SN.
        # In this branch the department parameter is accepted but does not
        # filter against a SN field — Cedar pre-check handles the dept
        # enforcement on the agent side. SN returns the caller's visible
        # incidents (the end user's, once OBO is wired; the service account's
        # otherwise).
        params: dict[str, str] = {
            "sysparm_fields": "sys_id,number,short_description,state,u_department",
            "sysparm_limit": "25",
        }
        return await self._request(
            "GET", "/api/now/table/incident", params=params, token=token,
        )

    async def get_incident(self, sys_id: str, token: str | None = None) -> dict:
        return await self._request(
            "GET", f"/api/now/table/incident/{sys_id}", token=token,
        )

    async def create_incident(
        self,
        short_description: str,
        description: str = "",
        urgency: str = "3",
        token: str | None = None,
        **extras: Any,
    ) -> dict:
        payload = {
            "short_description": short_description,
            "description": description,
            "urgency": urgency,
            **extras,
        }
        return await self._request(
            "POST", "/api/now/table/incident", json=payload, token=token,
        )

    async def update_incident(
        self, sys_id: str, payload: dict, token: str | None = None
    ) -> dict:
        return await self._request(
            "PUT", f"/api/now/table/incident/{sys_id}", json=payload, token=token,
        )


# ── Module singleton ───────────────────────────────────────────────────

def init_servicenow_client(
    instance_url: str,
    api_user: str = "",
    api_password: str = "",
) -> None:
    """Initialise the ServiceNow client.

    Empty `instance_url` → falls back to the in-memory mock from
    servicenow_mock.py (intentional dev-mode behaviour).

    `instance_url` set but `api_user` or `api_password` missing → raises
    RuntimeError. We refuse to silently serve mock data when the operator
    has clearly intended to point at a real instance — that would let
    misconfiguration look like real-but-empty data, which is worse than a
    loud startup failure. (The service account remains required even when OBO
    is configured: it is the fallback for non-Entra users.)

    Tools call get_servicenow_client() without caring which client they got.
    """
    global _client

    if not instance_url:
        # Local import to avoid a hard dependency cycle if the mock is removed
        from servicenow_mock import ServiceNowMockClient
        _client = ServiceNowMockClient()
        logger.info("ServiceNow mock client initialised (instance_url is empty)")
        return

    if not api_user or not api_password:
        raise RuntimeError(
            f"ServiceNow misconfigured: instance_url={instance_url!r} is set but "
            "api_user/api_password is empty. Either populate the credentials in "
            "dev_config.toml / env, or clear instance_url to use the mock."
        )

    _client = ServiceNowClient(instance_url, api_user, api_password)
    logger.info("ServiceNow client initialised (instance: %s)", instance_url)



def get_servicenow_client() -> "ServiceNowClient | ServiceNowMockClient | None":
    """Get the module-level client, or None if not initialised."""
    return _client
