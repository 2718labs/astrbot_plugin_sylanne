"""Synchronous installed bridge to an Authority current review content read."""

from __future__ import annotations

import asyncio
from concurrent.futures import TimeoutError as FutureTimeout

from ..authority_service.v2_natural_generation_content_contract import (
    NaturalGenerationContentReadRequestV2, NaturalGenerationCurrentContentV2,
)
from ..runtime_contracts import InstallationGrantV2
from .authority_client import AuthorityClient
from .authority_profile import AdminInstallationBundle


class InstalledNaturalGenerationContentPortV2:
    """Fetch original observed text through current mTLS Authority scope."""

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
            raise ValueError("installed natural content Authority binding required")
        self._client, self._bundle, self._grant = client, bundle, grant
        self._loop = owner_loop
        self._timeout = max(5.0, 3 * bundle.tls_profile.timeout_seconds)

    def read_current_natural_generation_content_v2(
        self, request: NaturalGenerationContentReadRequestV2, *, now_utc: float,
    ) -> NaturalGenerationCurrentContentV2:
        if type(request) is not NaturalGenerationContentReadRequestV2:
            raise TypeError("typed natural generation content request required")
        if not self._loop.is_running():
            raise RuntimeError("installed Authority event loop unavailable")
        try:
            running = asyncio.get_running_loop()
        except RuntimeError:
            running = None
        if running is self._loop:
            raise RuntimeError("natural content read must run on graph worker")
        # The server reads its own trusted clock; the caller's time grants nothing.
        future = asyncio.run_coroutine_threadsafe(
            self._client.natural_generation_content_read_v2(
                self._bundle, self._grant, read_request=request), self._loop)
        try:
            result = future.result(self._timeout)
        except FutureTimeout as exc:
            future.cancel()
            raise RuntimeError(
                "natural content read outcome unknown; use a new bounded read attempt"
            ) from exc
        if type(result) is not NaturalGenerationCurrentContentV2 or result.request != request:
            raise RuntimeError("natural content Authority result identity differs")
        return result


__all__ = ("InstalledNaturalGenerationContentPortV2",)
