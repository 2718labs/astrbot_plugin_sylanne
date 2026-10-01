"""Bind installed C04 to the administrator's current Host installation."""

from __future__ import annotations

from pathlib import Path

from ..authority_service.contract import AuthorityUnavailable
from ..authority_service.installed_c04_executor_v2 import (
    InstalledC04ExecutorV2, compose_installed_c04_executor_v2,
)
from ..authority_service.internal_work_service import AuthorityInternalWorkService
from ..authority_service.v2_execution_bridge import AuthorityV2ExecutionBridge
from ..graph_coordinator import namespace_ref
from ..runtime_contracts import NamespaceId
from .authority_profile import (
    load_admin_c04_signing_key, load_admin_installation_policy,
)
from .installed_package import verify_installed_backend_runtime_v1


def compose_host_installed_c04_executor_v2(
    *, profile_id: str, bridge: AuthorityV2ExecutionBridge,
    namespace: NamespaceId, graph_db_path: str | Path,
    package_root: str | Path, credential: object,
) -> tuple[AuthorityInternalWorkService, InstalledC04ExecutorV2]:
    """Use an external administrator pin and protected key for C04 startup.

    The package manifest supplies bytes for verification only; its own digest
    is never accepted as the expected digest. Authority independently verifies
    the same pinned package when it constructs the executor.
    """
    policy = load_admin_installation_policy(profile_id)
    if (type(namespace) is not NamespaceId
            or policy.namespace != namespace
            or bridge.namespace != namespace_ref(namespace)):
        raise AuthorityUnavailable("C04 namespace differs from administrator installation")
    pin = policy.manifest_digest
    if (type(pin) is not str or len(pin) != 64
            or any(ch not in "0123456789abcdef" for ch in pin)):
        raise AuthorityUnavailable("C04 administrator manifest pin is unavailable")
    installed = verify_installed_backend_runtime_v1(package_root, pin)
    if not installed.verified:
        raise AuthorityUnavailable("C04 formal installed package is unavailable")
    signing_key = load_admin_c04_signing_key(profile_id)
    return compose_installed_c04_executor_v2(
        bridge=bridge, namespace=namespace, graph_db_path=graph_db_path,
        package_root=package_root, trusted_manifest_sha256=pin,
        component_signing_key=signing_key, credential=credential,
    )


__all__ = ("compose_host_installed_c04_executor_v2",)
