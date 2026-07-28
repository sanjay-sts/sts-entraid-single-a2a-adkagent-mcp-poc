"""Acquiring tokens for agent-to-agent calls.

Two flows, both certificate-backed (no client secrets):

  AgentTokenProvider      client-credentials — "here is who I am"
                          Mints an app-only token for a specific callee.

  DelegatedTokenExchanger on-behalf-of — "here is who I act for"
                          Exchanges an inbound user token for one narrowed
                          to the next hop. This is what keeps a token captured
                          at hop N from being replayable at hop N+1.

Both cache credentials per (agent, callee); azure-identity caches the tokens
themselves and refreshes them before expiry.
"""
import asyncio
import hashlib
import logging
import os
from collections import OrderedDict

from azure.identity.aio import CertificateCredential, OnBehalfOfCredential

from agent_common.registry import AgentIdentity, get_agent

logger = logging.getLogger("agent_common.tokens")


def _combined_pem(identity: AgentIdentity) -> bytes:
    """Cert + private key, single PEM, as azure-identity's certificate-backed
    credentials (CertificateCredential, OnBehalfOfCredential) expect.

    azure-identity does not accept a public-cert-only path for these flows —
    it needs the private key alongside the certificate in one PEM blob. The
    private key signs the client assertion; it never leaves this process,
    only the public cert lives in Entra.
    """
    return identity.key_path.read_bytes() + b"\n" + identity.cert_path.read_bytes()


class AgentTokenProvider:
    """Mints this agent's own app-only tokens, audience-narrowed per callee."""

    def __init__(self, identity: AgentIdentity, tenant_id: str | None = None):
        self._identity = identity
        self._tenant_id = tenant_id or os.getenv("ENTRA_TENANT_ID", "")
        self._credential: CertificateCredential | None = None

    def _get_credential(self) -> CertificateCredential:
        """One credential per agent — it is not bound to a callee."""
        if self._credential is None:
            self._credential = CertificateCredential(
                tenant_id=self._tenant_id,
                client_id=self._identity.client_id,
                certificate_data=_combined_pem(self._identity),
                password=None,
            )
        return self._credential

    async def get_agent_token(self, callee: str) -> str:
        """An app-only token for calling `callee`.

        The returned token carries aud=api://<callee>, azp=<this agent>,
        idtyp=app, and this agent's app roles on the callee.
        """
        target = get_agent(callee)
        credential = self._get_credential()
        token = await credential.get_token(target.scope)
        logger.debug("Minted agent token for callee %s", callee)
        return token.token

    async def close(self) -> None:
        if self._credential is not None:
            await self._credential.close()
            self._credential = None


class DelegatedTokenExchanger:
    """Exchanges an inbound user token for one scoped to the next hop (OBO)."""

    def __init__(self, identity: AgentIdentity, tenant_id: str | None = None):
        self._identity = identity
        self._tenant_id = tenant_id or os.getenv("ENTRA_TENANT_ID", "")
        self._cert_bytes: bytes | None = None
        # An OnBehalfOfCredential is bound to one user assertion, so it must be
        # cached per (assertion, callee), not globally. OrderedDict so eviction
        # can be true LRU rather than insertion-order FIFO.
        self._credentials: OrderedDict[str, OnBehalfOfCredential] = OrderedDict()
        self._max_cache = 128
        # In-flight close tasks for evicted credentials — see _close_evicted.
        self._closing: set[asyncio.Task] = set()

    def _certificate(self) -> bytes:
        """Cert + private key, PEM, as azure-identity expects for OBO."""
        if self._cert_bytes is None:
            self._cert_bytes = _combined_pem(self._identity)
        return self._cert_bytes

    def _close_evicted(self, credential) -> None:
        """Close an evicted credential without blocking the sync cache path.

        Each OnBehalfOfCredential holds a live HTTP transport, so dropping one
        on the floor leaks a connection every eviction. This method is called
        from a sync context, so the close is scheduled rather than awaited; the
        task reference is kept until done because a fire-and-forget task can be
        garbage-collected mid-flight. When no loop is running (unit tests
        driving `_get_credential` directly), there is no transport to leak
        either — the stand-in never opened one — so doing nothing is correct.
        """
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return

        async def _close_quietly():
            try:
                await credential.close()
            except Exception:
                pass  # eviction is bookkeeping; a close failure must not surface

        task = loop.create_task(_close_quietly())
        self._closing.add(task)
        task.add_done_callback(self._closing.discard)

    def _get_credential(self, user_token: str, callee: str) -> OnBehalfOfCredential:
        digest = hashlib.sha256(f"{user_token}|{callee}".encode()).hexdigest()
        if digest in self._credentials:
            self._credentials.move_to_end(digest)
        else:
            if len(self._credentials) >= self._max_cache:
                # Evict least-recently-used — and close it, not just drop it.
                _, evicted = self._credentials.popitem(last=False)
                self._close_evicted(evicted)
            self._credentials[digest] = OnBehalfOfCredential(
                tenant_id=self._tenant_id,
                client_id=self._identity.client_id,
                client_certificate=self._certificate(),
                user_assertion=user_token,
            )
        return self._credentials[digest]

    async def exchange_for(self, user_token: str, callee: str) -> str:
        """Exchange `user_token` for one whose audience is `callee`.

        The exchanged token keeps the human in `sub` — this agent appears as
        the actor, not as the subject. Delegation, not impersonation.
        """
        target = get_agent(callee)
        credential = self._get_credential(user_token, callee)
        token = await credential.get_token(target.scope)
        logger.debug("Exchanged user token for callee %s", callee)
        return token.token

    async def close(self) -> None:
        for credential in self._credentials.values():
            try:
                await credential.close()
            except Exception:
                pass
        self._credentials.clear()
