"""Content-free C02 committer read over the installed Authority mTLS loop."""

from __future__ import annotations

import asyncio
from concurrent.futures import TimeoutError as FutureTimeout

from ..authority_service.v2_worker_result_read_fact_contract import (
    WorkerResultReadFactRequestV1, WorkerResultReadFactV1,
)
from ..runtime_contracts import InstallationGrantV2
from .authority_client import AuthorityClient
from .authority_profile import AdminInstallationBundle


class InstalledWorkerResultReadFactPort:
    """Bridge W01's real write permit to the designated C02 committer RPC."""

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
            raise ValueError("installed C02 committer binding is required")
        self._client = client
        self._bundle = bundle
        self._grant = grant
        self._loop = owner_loop
        self._timeout = max(5.0, 3 * bundle.tls_profile.timeout_seconds)

    def current_worker_result_read_fact(
        self, request: WorkerResultReadFactRequestV1,
    ) -> WorkerResultReadFactV1:
        if type(request) is not WorkerResultReadFactRequestV1:
            raise TypeError("typed original worker read fact request required")
        if not self._loop.is_running():
            raise RuntimeError("installed Authority event loop is unavailable")
        try:
            running = asyncio.get_running_loop()
        except RuntimeError:
            running = None
        if running is self._loop:
            raise RuntimeError("worker result fact read must run on the graph worker")
        future = asyncio.run_coroutine_threadsafe(
            self._client.worker_result_read_fact_v1(
                self._bundle, self._grant, fact_request=request),
            self._loop,
        )
        try:
            return future.result(self._timeout)
        except FutureTimeout as exc:
            future.cancel()
            raise RuntimeError("original worker result fact unresolved") from exc


__all__ = ("InstalledWorkerResultReadFactPort",)
