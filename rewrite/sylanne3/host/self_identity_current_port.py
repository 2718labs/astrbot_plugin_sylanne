"""Synchronous D03 read port over the installed Authority mTLS event loop."""

from __future__ import annotations

import asyncio
from concurrent.futures import TimeoutError as FutureTimeout

from ..authority_service.v2_contract import FencePermitV2
from ..authority_service.v2_self_identity_contract import (
    AuthorityCurrentSelfIdentityV1, SelfIdentityCurrentRequestV1,
)
from ..runtime_contracts import InstallationGrantV2, NamespaceId
from .authority_client import AuthorityClient
from .authority_profile import AdminInstallationBundle


class InstalledCurrentSelfIdentityPort:
    """Use W01's actual fence; Authority alone decides the current mapping."""

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
            raise ValueError("installed self identity read binding is required")
        self._client = client
        self._bundle = bundle
        self._grant = grant
        self._loop = owner_loop
        self._timeout = max(5.0, 3 * bundle.tls_profile.timeout_seconds)

    def current_self_identity(
        self, *, namespace: NamespaceId, authority_namespace: str,
        request_operation_id: str, permit: FencePermitV2,
    ) -> AuthorityCurrentSelfIdentityV1 | None:
        policy = self._bundle.installation_policy
        if (type(namespace) is not NamespaceId
                or type(permit) is not FencePermitV2
                or namespace != policy.namespace
                or authority_namespace != policy.authority_namespace):
            raise ValueError("self identity read namespace differs")
        current_request = SelfIdentityCurrentRequestV1(
            self._grant.authority_id, authority_namespace, namespace,
            self._grant.installation_id, self._grant.manifest_digest,
            request_operation_id, permit,
        )
        if not self._loop.is_running():
            raise RuntimeError("installed Authority event loop is unavailable")
        try:
            running = asyncio.get_running_loop()
        except RuntimeError:
            running = None
        if running is self._loop:
            raise RuntimeError("self identity read must run on the graph worker")
        future = asyncio.run_coroutine_threadsafe(
            self._client.self_identity_current_v1(
                self._bundle, self._grant, current_request=current_request),
            self._loop,
        )
        try:
            return future.result(self._timeout)
        except FutureTimeout as exc:
            future.cancel()
            raise RuntimeError("current self identity read unresolved") from exc


__all__ = ("InstalledCurrentSelfIdentityPort",)
