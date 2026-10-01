"""Synchronous installed bridge to the original natural output selector."""

from __future__ import annotations

import asyncio
from concurrent.futures import TimeoutError as FutureTimeout

from ..authority_service.v2_natural_generation_output_contract import (
    NaturalGenerationOriginalOutputV2, NaturalGenerationOutputReadRequestV2,
)
from ..runtime_contracts import InstallationGrantV2
from .authority_client import AuthorityClient
from .authority_profile import AdminInstallationBundle


class InstalledNaturalGenerationOutputPortV2:
    """Return a paid digest from mTLS Authority, never a host supplied body."""

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
            raise ValueError("installed natural output Authority binding is required")
        self._client, self._bundle, self._grant = client, bundle, grant
        self._loop = owner_loop
        self._timeout = max(5.0, 3 * bundle.tls_profile.timeout_seconds)

    def read_original_natural_generation_output_v2(
        self, request: NaturalGenerationOutputReadRequestV2, *, now_utc: float,
    ) -> NaturalGenerationOriginalOutputV2 | None:
        if type(request) is not NaturalGenerationOutputReadRequestV2:
            raise TypeError("typed natural generation output request required")
        if not self._loop.is_running():
            raise RuntimeError("installed Authority event loop is unavailable")
        try:
            running = asyncio.get_running_loop()
        except RuntimeError:
            running = None
        if running is self._loop:
            raise RuntimeError("natural output read must run on the graph worker")
        # The Authority uses its own trusted clock; this argument is not proof.
        future = asyncio.run_coroutine_threadsafe(
            self._client.natural_generation_output_select_v2(
                self._bundle, self._grant, read_request=request), self._loop)
        try:
            return future.result(self._timeout)
        except FutureTimeout as exc:
            future.cancel()
            recovery = asyncio.run_coroutine_threadsafe(
                self._client.natural_generation_output_recover_finish_v2(
                    self._bundle, self._grant, read_request=request), self._loop)
            try:
                recovery.result(self._timeout)
            except Exception as recovery_exc:
                raise RuntimeError(
                    "natural output read unresolved; original fence recovery required"
                ) from recovery_exc
            raise RuntimeError("natural output read timed out") from exc


__all__ = ("InstalledNaturalGenerationOutputPortV2",)
