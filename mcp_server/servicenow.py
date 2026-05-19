"""ServiceNow REST client.

Async HTTP client for ServiceNow's Table API. Service-account auth via
HTTP Basic. Errors normalised to {"error": ...} dicts to match the
existing pattern used for S3 (mcp_server/server.py:_run_s3_operation).

For per-user (OBO) auth see the post-plan-exit follow-up in the
2026-05-19 spec — not implemented in this branch.

Configuration in dev_config.toml:
    [servicenow]
    instance_url = ""               # empty → init_servicenow_client picks the mock
    api_user     = "admin"
    api_password = "..."
"""
import logging
from typing import Any

import httpx

logger = logging.getLogger("mcp_server.servicenow")

# Module-level singleton (set by init_servicenow_client at startup)
_client: "ServiceNowClient | ServiceNowMockClient | None" = None


class ServiceNowClient:
    """ServiceNow Table API client (service-account auth).

    Methods mirror the seven MCP tools' needs. All return dicts: success
    shape comes from ServiceNow's REST envelope ({"result": ...}) which
    we unwrap; errors are normalised via _request().
    """

    def __init__(self, instance_url: str, api_user: str, api_password: str) -> None:
        self._base = instance_url.rstrip("/")
        self._auth = (api_user, api_password)

    async def _request(self, method: str, path: str, **kwargs: Any) -> dict:
        url = f"{self._base}{path}"
        try:
            async with httpx.AsyncClient(timeout=30.0) as http:
                resp = await http.request(method, url, auth=self._auth, **kwargs)
        except httpx.ConnectError as e:
            logger.warning("ServiceNow connect error: %s", e)
            return {"error": "ServiceNow unavailable: connection failed"}
        except httpx.TimeoutException:
            return {"error": "ServiceNow timed out"}

        if resp.status_code == 401:
            return {"error": "ServiceNow auth failed", "status": 401}
        if resp.status_code == 403:
            return {"error": "ServiceNow access denied", "status": 403}
        if resp.status_code == 404:
            return {"error": "record not found", "status": 404}
        if resp.status_code == 429:
            return {"error": "ServiceNow rate limited; retry later", "status": 429}
        if resp.status_code >= 500:
            return {"error": "ServiceNow server error", "status": resp.status_code}

        try:
            body = resp.json()
        except ValueError:
            return {"error": "ServiceNow returned non-JSON", "status": resp.status_code}

        # ServiceNow sometimes returns 200 with an embedded error
        if isinstance(body, dict) and "error" in body and "result" not in body:
            return {"error": body["error"], "status": resp.status_code}

        return body

    # ── Knowledge Bases ──────────────────────────────────────────────

    async def list_knowledge_bases(self) -> dict:
        return await self._request(
            "GET", "/api/now/table/kb_knowledge_base",
            params={"sysparm_fields": "sys_id,title,u_department"},
        )

    async def get_knowledge_base_metadata(self, identifier: str) -> dict | None:
        """Resolve a KB by sys_id (32-hex) or title; return single record or None.

        Returns the SN record dict (with u_department) or None if not found
        or on error.
        """
        # Try sys_id-style lookup first if identifier looks hex-y enough
        if len(identifier) == 32 and all(c in "0123456789abcdefABCDEF" for c in identifier):
            body = await self._request(
                "GET", f"/api/now/table/kb_knowledge_base/{identifier}",
                params={"sysparm_fields": "sys_id,title,u_department"},
            )
            if "error" not in body and isinstance(body.get("result"), dict):
                return body["result"]
            # fall through and try by title

        body = await self._request(
            "GET", "/api/now/table/kb_knowledge_base",
            params={
                "sysparm_query": f"title={identifier}",
                "sysparm_limit": "1",
                "sysparm_fields": "sys_id,title,u_department",
            },
        )
        result = body.get("result") if isinstance(body, dict) else None
        if isinstance(result, list) and result:
            return result[0]
        return None

    # ── Articles ─────────────────────────────────────────────────────

    async def list_articles(self, kb_sys_id: str, query: str = "") -> dict:
        params: dict[str, str] = {"sysparm_query": f"kb_knowledge_base={kb_sys_id}"}
        if query:
            params["sysparm_query"] += f"^short_descriptionLIKE{query}"
        params["sysparm_fields"] = "sys_id,number,short_description,kb_knowledge_base"
        return await self._request(
            "GET", "/api/now/table/kb_knowledge", params=params,
        )

    async def get_article(self, sys_id: str) -> dict:
        return await self._request("GET", f"/api/now/table/kb_knowledge/{sys_id}")

    # ── Incidents ────────────────────────────────────────────────────

    async def list_incidents(self, department: str | None = None) -> dict:
        # NOTE: incident u_department field is deferred until OBO branch.
        # In this branch the department parameter is accepted but does not
        # filter against a SN field — Cedar pre-check handles the dept
        # enforcement on the agent side. SN returns the integration user's
        # visible incidents.
        params: dict[str, str] = {
            "sysparm_fields": "sys_id,number,short_description,state,u_department",
            "sysparm_limit": "25",
        }
        return await self._request("GET", "/api/now/table/incident", params=params)

    async def get_incident(self, sys_id: str) -> dict:
        return await self._request("GET", f"/api/now/table/incident/{sys_id}")

    async def create_incident(
        self,
        short_description: str,
        description: str = "",
        urgency: str = "3",
        **extras: Any,
    ) -> dict:
        payload = {
            "short_description": short_description,
            "description": description,
            "urgency": urgency,
            **extras,
        }
        return await self._request("POST", "/api/now/table/incident", json=payload)

    async def update_incident(self, sys_id: str, payload: dict) -> dict:
        return await self._request(
            "PUT", f"/api/now/table/incident/{sys_id}", json=payload,
        )


# ── Module singleton ───────────────────────────────────────────────────

def init_servicenow_client(
    instance_url: str,
    api_user: str = "",
    api_password: str = "",
) -> None:
    """Initialise the ServiceNow client.

    Empty `instance_url` → falls back to the in-memory mock from
    servicenow_mock.py. Tools call get_servicenow_client() without
    caring which one they got.
    """
    global _client

    if not instance_url:
        # Local import to avoid a hard dependency cycle if the mock is removed
        from servicenow_mock import ServiceNowMockClient
        _client = ServiceNowMockClient()
        logger.info("ServiceNow mock client initialised (instance_url is empty)")
        return

    if not api_user or not api_password:
        from servicenow_mock import ServiceNowMockClient
        _client = ServiceNowMockClient()
        logger.warning(
            "ServiceNow mock client initialised — instance_url set (%s) but "
            "api_user/api_password missing", instance_url,
        )
        return

    _client = ServiceNowClient(instance_url, api_user, api_password)
    logger.info("ServiceNow client initialised (instance: %s)", instance_url)


def get_servicenow_client() -> "ServiceNowClient | ServiceNowMockClient | None":
    """Get the module-level client, or None if not initialised."""
    return _client
