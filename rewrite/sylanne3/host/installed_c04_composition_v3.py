"""Compose the installed C04 V3 executor from administrator-pinned bytes."""

from __future__ import annotations

from pathlib import Path

from ..authority_service.contract import AuthorityUnavailable
from ..authority_service.installed_c04_executor_v3 import (
    InstalledC04ExecutorV3, compose_installed_c04_executor_v3,
)
from ..authority_service.internal_work_service import AuthorityInternalWorkService
from ..authority_service.v2_execution_bridge import AuthorityV2ExecutionBridge
from ..runtime_contracts import namespace_ref
from ..runtime_contracts import NamespaceId
from .authority_profile import (
    load_admin_c04_signing_key, load_admin_installation_policy, load_admin_installation_bundle,
)
from .installed_package import verify_installed_backend_runtime_v1


def compose_host_installed_c04_executor_v3(
    *, profile_id: str, bridge: AuthorityV2ExecutionBridge,
    namespace: NamespaceId, graph_db_path: str | Path,
    package_root: str | Path, credential: object,
) -> tuple[AuthorityInternalWorkService, InstalledC04ExecutorV3]:
    """Bind V3 to the external install pin and protected C04 signing key."""
    policy = load_admin_installation_policy(profile_id)
    if (type(namespace) is not NamespaceId
            or policy.namespace != namespace
            or bridge.namespace != namespace_ref(namespace)):
        raise AuthorityUnavailable("C04 V3 namespace differs from installation")
    pin = policy.manifest_digest
    if (type(pin) is not str or len(pin) != 64
            or any(ch not in "0123456789abcdef" for ch in pin)):
        raise AuthorityUnavailable("C04 V3 administrator manifest pin is absent")
    installed = verify_installed_backend_runtime_v1(package_root, pin)
    if not installed.verified:
        raise AuthorityUnavailable("C04 V3 formal package is unavailable")
    from ..runtime.issuers import D02ResourceIssuer, D11BudgetGrantIssuer
    bundle = load_admin_installation_bundle(profile_id)
    if bundle.installation_policy != policy:
        raise AuthorityUnavailable("C04 protected issuer configuration changed")
    return compose_installed_c04_executor_v3(
        bridge=bridge, namespace=namespace, graph_db_path=graph_db_path,
        package_root=package_root, trusted_manifest_sha256=pin,
        component_signing_key=load_admin_c04_signing_key(profile_id),
        credential=credential,
        resource_issuer=D02ResourceIssuer(bundle.d02_signing_key),
        budget_issuer=D11BudgetGrantIssuer(bundle.d11_signing_key),
    )


__all__ = ["compose_host_installed_c04_executor_v3"]
