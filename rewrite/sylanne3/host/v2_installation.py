"""Assemble a v2 graph worker from one administrator installation snapshot."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from ..installation_policy import AdminInstallationPolicy
from ..runtime_contracts import InstallationGrantV2
from .authority_client import (
    AUTHORITY_PROTOCOL, AuthorityClient, AuthorityProvisioningRequest,
    AuthoritySelection, PublisherPackageIdentity,
)
from .authority_profile import (
    AdminIngressClockPolicy, AdminIngressEncodingPolicy, load_admin_installation_bundle,
)
from .installed_package import verify_installed_package
from .mtls_transport import MtlsAuthorityTransport
from .v2_fence_port import V2FencePort


@dataclass(frozen=True, slots=True)
class V2InstallationAssembly:
    """Bound installation facts; the factory creates a worker-owned port."""

    installation_policy: AdminInstallationPolicy
    installation_grant: InstallationGrantV2
    d11_signing_key: bytes
    d02_signing_key: bytes
    fence_port_factory: Callable[[], V2FencePort]
    package_root: Path
    data_dir: Path
    available_cpu_features: frozenset[str] | None = None
    ingress_clock: AdminIngressClockPolicy | None = None
    ingress_encoding: AdminIngressEncodingPolicy | None = None


async def assemble_v2_installation(
    profile_id: str,
    *,
    package_root: Path,
    data_dir: Path,
    available_cpu_features: frozenset[str] | None = None,
) -> V2InstallationAssembly:
    """Verify the installed package and pair the exact administrator identity.

    This prepares dependencies for ``RuntimeContext.start_v2``. It does not
    activate a namespace or make the host ready. The returned port factory is
    called only by the dedicated graph worker and owns its own TLS lifetime.
    """
    selection = AuthoritySelection(profile_id)
    root = Path(package_root)
    data = Path(data_dir)
    if not root.is_absolute() or not data.is_absolute():
        raise ValueError("installation paths must be absolute")
    if available_cpu_features is not None:
        available_cpu_features = frozenset(available_cpu_features)

    bundle = await asyncio.to_thread(load_admin_installation_bundle, selection.profile_id)
    profile, policy = bundle.tls_profile, bundle.installation_policy
    if (profile.profile_id != selection.profile_id
            or profile.expected_authority_id != policy.expected_authority_id
            or profile.prepared_ssl_context is None):
        raise RuntimeError("administrator installation profile identity is invalid")

    package = await asyncio.to_thread(
        verify_installed_package, root, policy.manifest_digest,
        available_cpu_features=available_cpu_features,
    )
    if not package.verified or package.build_mode != "formal-alpha1":
        raise RuntimeError(
            "installed formal-alpha1 package verification failed: "
            + (package.reason if not package.verified else "wrong build mode")
        )

    profiles = {selection.profile_id: profile}
    transport = MtlsAuthorityTransport(profiles)
    try:
        client = AuthorityClient(
            selection, package_root=root, data_dir=data, transport=transport,
        )
        status = await client.status_v2()
        if status.state != "paired":
            raise RuntimeError("v2 Authority pairing failed: " + status.state)
        grant = await client.installation_grant_v2()
        if grant is None:
            raise RuntimeError("v2 Authority installation grant is unavailable")
        if (grant.authority_id != policy.expected_authority_id
                or grant.installation_id != policy.installation_id
                or grant.administrator_holder != policy.administrator_holder
                or grant.manifest_digest != policy.manifest_digest):
            raise RuntimeError("v2 Authority grant differs from administrator installation")
    finally:
        await transport.close()

    request = AuthorityProvisioningRequest(
        protocol=AUTHORITY_PROTOCOL,
        profile_id=selection.profile_id,
        plugin_name="astrbot_plugin_sylanne",
        host_api_version="4.28.1",
        package_root=root,
        data_dir=data,
        publisher_package=PublisherPackageIdentity(policy.manifest_digest),
    )

    def make_fence_port() -> V2FencePort:
        return V2FencePort(request, profiles, grant)

    return V2InstallationAssembly(
        policy, grant, bundle.d11_signing_key, bundle.d02_signing_key, make_fence_port,
        root, data, available_cpu_features, bundle.ingress_clock,
        bundle.ingress_encoding,
    )


__all__ = ("V2InstallationAssembly", "assemble_v2_installation")
