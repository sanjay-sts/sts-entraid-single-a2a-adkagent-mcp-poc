"""JWT signature verification for agent-to-agent calls.

Verifies signature, issuer, audience and expiry against Entra's JWKS before any
claim is trusted. Without this, verify_agent_claims() is decoration: an attacker
can hand-craft a token with any azp and roles they like.

One implementation, shared by every agent, so no service can accidentally skip it.
"""
import logging
import os
import time

import httpx
import jwt

logger = logging.getLogger("agent_common.jwt")

# How long a fetched JWKS document is trusted before it is refetched, absent
# a key-not-found event (which always forces an immediate refetch — see
# `_keys_for`). Keeps a compromised/rotated-out key from being honored
# indefinitely just because it happened to still resolve by kid.
DEFAULT_JWKS_TTL_SECONDS = 600


class TokenVerificationError(Exception):
    """Signature, issuer, audience or expiry check failed."""


class EntraJWTValidator:
    """Verifies Entra-issued JWTs against the tenant's JWKS."""

    def __init__(
        self,
        tenant_id: str | None = None,
        jwks_ttl_seconds: float = DEFAULT_JWKS_TTL_SECONDS,
        clock=time.monotonic,
    ):
        self._tenant_id = tenant_id or os.getenv("ENTRA_TENANT_ID", "")
        self._jwks_cache: dict[str, dict] = {}
        self._jwks_fetched_at: dict[str, float] = {}
        self._jwks_ttl_seconds = jwks_ttl_seconds
        self._clock = clock

    @property
    def _jwks_uris(self) -> list[str]:
        return [
            f"https://login.microsoftonline.com/{self._tenant_id}/discovery/v2.0/keys",
            f"https://login.microsoftonline.com/{self._tenant_id}/discovery/keys",
        ]

    @property
    def _issuers(self) -> list[str]:
        return [
            f"https://login.microsoftonline.com/{self._tenant_id}/v2.0",
            f"https://sts.windows.net/{self._tenant_id}/",
        ]

    async def _get_jwks(self, uri: str) -> dict:
        fetched_at = self._jwks_fetched_at.get(uri)
        expired = (
            fetched_at is None
            or (self._clock() - fetched_at) >= self._jwks_ttl_seconds
        )
        if uri not in self._jwks_cache or expired:
            async with httpx.AsyncClient() as client:
                response = await client.get(uri, timeout=10.0)
                response.raise_for_status()
                self._jwks_cache[uri] = response.json()
                self._jwks_fetched_at[uri] = self._clock()
        return self._jwks_cache[uri]

    def clear_cache(self) -> None:
        self._jwks_cache = {}
        self._jwks_fetched_at = {}

    async def _keys_for(self, kid: str) -> list:
        keys = []
        for uri in self._jwks_uris:
            try:
                jwks = await self._get_jwks(uri)
            except Exception as e:
                logger.debug("JWKS fetch failed for %s: %s", uri, e)
                continue
            for key in jwks.get("keys", []):
                if key.get("kid") == kid:
                    keys.append(jwt.algorithms.RSAAlgorithm.from_jwk(key))
        return keys

    async def validate(self, token: str, expected_audience: str) -> dict:
        """Verify the token and return its claims. Raises TokenVerificationError.

        `expected_audience` is checked here as well as in verify_agent_claims —
        belt and braces, because a token accepted for the wrong audience is the
        replay attack we are specifically defending against.
        """
        try:
            kid = jwt.get_unverified_header(token).get("kid")
        except Exception as e:
            raise TokenVerificationError(f"Malformed token: {e}") from e

        keys = await self._keys_for(kid)
        if not keys:
            # Key rotation: drop the cache and try once more before giving up.
            self.clear_cache()
            keys = await self._keys_for(kid)
        if not keys:
            raise TokenVerificationError(f"Signing key '{kid}' not found in JWKS")

        # Entra mints the audience as either the app id or the App ID URI.
        bare_client_id = expected_audience.removeprefix("api://")
        audiences = [expected_audience, bare_client_id]

        last_error: Exception | None = None
        for key in keys:
            try:
                return jwt.decode(
                    token,
                    key,
                    algorithms=["RS256"],
                    audience=audiences,
                    issuer=self._issuers,
                )
            except jwt.InvalidSignatureError as e:
                last_error = e  # wrong key of several — try the next
            except jwt.ExpiredSignatureError as e:
                raise TokenVerificationError("Token has expired") from e
            except jwt.InvalidAudienceError as e:
                raise TokenVerificationError(
                    f"Token audience is not '{expected_audience}'"
                ) from e
            except jwt.InvalidIssuerError as e:
                raise TokenVerificationError("Token issuer is not this tenant") from e
            except Exception as e:
                last_error = e

        raise TokenVerificationError(f"Signature verification failed: {last_error}")
