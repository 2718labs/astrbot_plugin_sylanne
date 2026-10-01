"""Installed, synchronous D09 bridge to the pinned Authority result read."""

from __future__ import annotations

import asyncio
from concurrent.futures import TimeoutError as FutureTimeout

from ..authority_service.v2_context_reply_result_contract import (
    ContextReplyPaidResultReadV2, ContextReplyResultReadRequestV1,
)
from ..runtime_contracts import InstallationGrantV2
from .authority_client import AuthorityClient
from .authority_profile import AdminInstallationBundle


class InstalledContextReplyResultPortV2:
    """Expose only the mTLS Authority service; D09 still applies its own gate."""

    def __init__(
        self, *, client: AuthorityClient, bundle: AdminInstallationBundle,
        grant: InstallationGrantV2, owner_loop: asyncio.AbstractEventLoop,
    ) -> None:
        if (type(client) is not AuthorityClient
                or type(bundle) is not AdminInstallationBundle
                or type(grant) is not InstallationGrantV2
                or not isinstance(owner_loop, asyncio.AbstractEventLoop)
                or not owner_loop.is_running()
                or (grant.authority_id, grant.installation_id,
                    grant.administrator_holder, grant.manifest_digest) !=
                   (bundle.installation_policy.expected_authority_id,
                    bundle.installation_policy.installation_id,
                    bundle.installation_policy.administrator_holder,
                    bundle.installation_policy.manifest_digest)):
            raise ValueError("installed context reply Authority binding is required")
        self._client = client
        self._bundle = bundle
        self._grant = grant
        self._loop = owner_loop
        self._timeout = max(5.0, 3 * bundle.tls_profile.timeout_seconds)

    def read_current_result_v2(
        self, request: ContextReplyResultReadRequestV1, *, now_utc: float,
    ) -> ContextReplyPaidResultReadV2 | None:
        if type(request) is not ContextReplyResultReadRequestV1:
            raise TypeError("typed context reply result request required")
        if not self._loop.is_running():
            raise RuntimeError("installed Authority event loop is unavailable")
        try:
            running = asyncio.get_running_loop()
        except RuntimeError:
            running = None
        if running is self._loop:
            raise RuntimeError("context reply result read must run on the graph worker")
        # The Authority uses its own trusted clock; the caller's time is not evidence.
        future = asyncio.run_coroutine_threadsafe(
            self._client.context_reply_result_read_v2(
                self._bundle, self._grant, read_request=request), self._loop)
        try:
            return future.result(self._timeout)
        except FutureTimeout as exc:
            future.cancel()
            # An interrupted transport may have left an original read fence.
            # The same original attempt can be completed without releasing content.
            recovery = asyncio.run_coroutine_threadsafe(
                self._client.context_reply_result_recover_finish_v2(
                    self._bundle, self._grant, read_request=request), self._loop)
            try:
                recovery.result(self._timeout)
            except Exception as recovery_exc:
                raise RuntimeError(
                    "context reply read unresolved; original fence recovery required"
                ) from recovery_exc
            raise RuntimeError("context reply read timed out") from exc


__all__ = ("InstalledContextReplyResultPortV2",)
