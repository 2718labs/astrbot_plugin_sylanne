"""Synchronous, content-free Authority terminal fact port for the graph worker."""

from __future__ import annotations

import asyncio
from concurrent.futures import TimeoutError as FutureTimeout

from ..authority_service.v2_model_egress_contract import ModelEgressIntentV1
from ..runtime_contracts import InstallationGrantV2
from .authority_client import AuthorityClient
from .authority_profile import AdminInstallationBundle


class InstalledModelTerminalCostPort:
    """Bridge a worker-thread cost query onto the installed mTLS event loop."""

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
            raise ValueError("installed terminal cost query binding is required")
        self._client = client
        self._bundle = bundle
        self._grant = grant
        self._loop = owner_loop
        self._timeout = max(5.0, 3 * bundle.tls_profile.timeout_seconds)

    def __call__(self, original_intent: ModelEgressIntentV1):
        if type(original_intent) is not ModelEgressIntentV1:
            raise TypeError("original model intent required")
        if not self._loop.is_running():
            raise RuntimeError("installed Authority event loop is unavailable")
        try:
            running = asyncio.get_running_loop()
        except RuntimeError:
            running = None
        if running is self._loop:
            raise RuntimeError("terminal cost query must run on the graph worker")
        future = asyncio.run_coroutine_threadsafe(
            self._client.model_terminal_fact_v2(
                self._bundle, self._grant, intent=original_intent),
            self._loop,
        )
        try:
            record, permit, admission, receipt = future.result(self._timeout)
        except FutureTimeout as exc:
            future.cancel()
            raise RuntimeError("original model terminal query unresolved") from exc
        if record.state != "observed" or receipt is None:
            raise RuntimeError("original model terminal is unresolved")
        return record, permit, admission, receipt


__all__ = ("InstalledModelTerminalCostPort",)
