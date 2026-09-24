"""Boundary contract for a future Authority-current persona/self pairing.

No production port currently implements this contract.  A namespace, an Owner
principal, and an AstrBot sender account cannot substitute for its result.
"""

from __future__ import annotations

from typing import Protocol

from ...authority_service.v2_contract import FencePermitV2
from ...authority_service.v2_owner_contract import OwnerAuthorizationGuardV1
from ...authority_service.v2_self_identity_contract import AuthorityCurrentSelfIdentityV1
from ...domains.d01 import ActiveRoleQualification
from ...graph_types import AtomKey, GraphAtom, Owner
from ...installation_policy import AdminInstallationPolicy
from ...runtime_contracts import InstallationGrantV2, NamespaceId, canonical_digest
from .self_perspective import SelfIdentityMapping


class AuthorityCurrentSelfIdentityPort(Protocol):
    """Paired Authority current read under W01's actual write permit.

    Select by namespace and operation, never by a caller-proposed self entity.
    The implementation returns None after replacement or revocation.
    """

    def current_self_identity(
        self, *, namespace: NamespaceId, authority_namespace: str,
        request_operation_id: str, permit: FencePermitV2,
    ) -> AuthorityCurrentSelfIdentityV1 | None: ...


def qualify_authority_current_self_identity(
    *,
    role: ActiveRoleQualification,
    activation_atom: GraphAtom,
    policy: AdminInstallationPolicy,
    installation_grant: InstallationGrantV2,
    owner_guard: OwnerAuthorizationGuardV1,
    request_operation_id: str,
    permit: FencePermitV2,
    port: AuthorityCurrentSelfIdentityPort | None,
) -> SelfIdentityMapping:
    """Qualify one mapping candidate; graph issuance remains unavailable.

    ``policy`` comes from the protected installation, ``grant`` and ``port``
    from the paired Authority, and ``role`` from a current D01 read. W01 must
    still validate the fence and source while committing; this DTO does not
    grant a capability.
    """
    if port is None or not callable(getattr(port, "current_self_identity", None)):
        raise ValueError("current Authority self identity port is unavailable")
    if (type(role) is not ActiveRoleQualification or type(activation_atom) is not GraphAtom
            or type(policy) is not AdminInstallationPolicy
            or type(installation_grant) is not InstallationGrantV2
            or type(owner_guard) is not OwnerAuthorizationGuardV1
            or type(permit) is not FencePermitV2
            or type(request_operation_id) is not str or not request_operation_id):
        raise TypeError("current D01, installation, Authority, Owner, and fence proofs are required")
    namespace = role.namespace
    activation_key = AtomKey(Owner("persona", *namespace.as_tuple),
                             "d01.persona_activation.v1", "current")
    versions = {item.key: item.revision for item in role.read_versions}
    activation = activation_atom.value
    if (policy.namespace != namespace or role.plan.namespace != namespace
            or role.head_id != role.plan.head_id
            or activation_atom.key != activation_key or not activation_atom.valid
            or versions.get(activation_key) != activation_atom.revision
            or activation.get("head_id") != role.head_id
            or not activation.get("graph_incarnation")
            or installation_grant.authority_id != policy.expected_authority_id
            or installation_grant.installation_id != policy.installation_id
            or installation_grant.manifest_digest != policy.manifest_digest
            or permit.authority_id != policy.expected_authority_id
            or permit.namespace != policy.authority_namespace
            or permit.subject != installation_grant.subject
            or permit.operation != "write"
            or permit.generation != activation.get("activation_generation")
            or owner_guard.namespace != namespace
            or owner_guard.authority_id != policy.expected_authority_id
            or owner_guard.installation_id != policy.installation_id
            or owner_guard.authorization_revision != role.authorization_revision
            or owner_guard.pending_revoke_operation_id is not None
            or owner_guard.minimum_revocation_revision >= owner_guard.authorization_revision):
        raise ValueError("current installed persona or Owner proof differs")
    try:
        current = port.current_self_identity(
            namespace=namespace, authority_namespace=policy.authority_namespace,
            request_operation_id=request_operation_id, permit=permit,
        )
    except Exception as exc:
        raise ValueError("current Authority self identity is unavailable") from exc
    if type(current) is not AuthorityCurrentSelfIdentityV1:
        raise ValueError("current Authority self identity is unavailable")
    if (current.namespace != namespace
            or current.authority_namespace != policy.authority_namespace
            or current.authority_id != policy.expected_authority_id
            or current.installation_id != policy.installation_id
            or current.manifest_digest != policy.manifest_digest
            or current.activation_generation != activation["activation_generation"]
            or current.graph_incarnation != activation["graph_incarnation"]
            or current.role_head_id != role.head_id
            or current.owner_authorization_revision != owner_guard.authorization_revision
            or current.owner_authorization_head != owner_guard.authorization_head
            or current.owner_minimum_revocation_revision != owner_guard.minimum_revocation_revision
            or current.owner_revocation_epoch != owner_guard.minimum_revocation_epoch
            or current.request_operation_id != request_operation_id
            or current.permit != permit):
        raise ValueError("Authority self identity differs from current role or fence")
    digest = canonical_digest(current)
    return SelfIdentityMapping(
        current.mapping_id,
        current.persona_ref,
        current.self_entity_ref,
        "authority:self-identity:" + digest,
        current.role_head_id,
        current.graph_incarnation,
        "active",
    )


__all__ = (
    "AuthorityCurrentSelfIdentityV1", "AuthorityCurrentSelfIdentityPort",
    "qualify_authority_current_self_identity",
)
