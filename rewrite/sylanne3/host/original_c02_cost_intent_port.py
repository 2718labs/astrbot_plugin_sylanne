"""Installed Authority lookup for the original committed C02 model intent."""

from __future__ import annotations

import asyncio
from concurrent.futures import TimeoutError as FutureTimeout

from ..runtime.c02_cost_settlement import C02OriginalIntentLookupV1
from ..runtime_contracts import InstallationGrantV2
from .authority_client import AuthorityClient
from .authority_profile import AdminInstallationBundle


class InstalledOriginalC02CostIntentPort:
    """Bridge a graph-worker identity query to the designated mTLS observer."""

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
            raise ValueError("installed original C02 intent observer required")
        self._client = client
        self._bundle = bundle
        self._grant = grant
        self._loop = owner_loop
        self._timeout = max(5.0, 3 * bundle.tls_profile.timeout_seconds)

    def __call__(self, lookup: C02OriginalIntentLookupV1):
        if (type(lookup) is not C02OriginalIntentLookupV1
                or (lookup.namespace, lookup.authority_id,
                    lookup.authority_namespace, lookup.installation_id) !=
                   (self._bundle.installation_policy.namespace,
                    self._grant.authority_id,
                    self._bundle.installation_policy.authority_namespace,
                    self._grant.installation_id)):
            raise ValueError("original C02 intent lookup differs from installation")
        if not self._loop.is_running():
            raise RuntimeError("installed Authority event loop is unavailable")
        try:
            running = asyncio.get_running_loop()
        except RuntimeError:
            running = None
        if running is self._loop:
            raise RuntimeError("original C02 intent lookup must run on graph worker")
        future = asyncio.run_coroutine_threadsafe(
            self._client.model_original_intent_lookup_v1(
                self._bundle, self._grant, lookup=lookup), self._loop)
        try:
            return future.result(self._timeout)
        except FutureTimeout as exc:
            future.cancel()
            raise RuntimeError("original C02 intent lookup unresolved") from exc


__all__ = ("InstalledOriginalC02CostIntentPort",)
