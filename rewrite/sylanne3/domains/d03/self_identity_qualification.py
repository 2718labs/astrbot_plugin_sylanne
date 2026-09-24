"""Boundary contract for a future administrator-certified persona/self pairing.

No production port currently implements this contract.  A namespace, an Owner
principal, and an AstrBot sender account cannot substitute for its result.
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
from datetime import datetime
import re
from typing import Protocol

from ...authority_service.v2_owner_contract import OwnerAuthorizationGuardV1
from ...domains.d01 import ActiveRoleQualification
from ...graph_types import AtomKey, GraphAtom, Owner
from ...installation_policy import AdminInstallationPolicy
from ...runtime_contracts import InstallationGrantV2, NamespaceId, canonical_digest
from .self_perspective import SelfIdentityMapping


_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


@dataclass(frozen=True, slots=True)
class AdminSelfIdentityAttestationV1:
    """Exact administrator assertion consumed only after current verification.

    ``signature`` is opaque here. The installation/Authority port must check
    its cryptographic validity, signer, expiry and revocation on every read.
    Constructing this DTO alone proves none of those properties.
    """

    namespace: NamespaceId
    authority_id: str
    installation_id: str
    manifest_digest: str
    graph_incarnation: str
    role_head_id: str
    persona_ref: str
    self_entity_ref: str
    attestation_id: str
    revision: int
    revocation_epoch: int
    valid_until_utc: str
    signer_key_id: str
    signature: str
    schema: str = "d03.admin_self_identity_attestation.v1"
    signature_scheme: str = "ed25519-canonical-json-v1"

    def __post_init__(self) -> None:
        if (type(self.namespace) is not NamespaceId
                or self.schema != "d03.admin_self_identity_attestation.v1"
                or self.signature_scheme != "ed25519-canonical-json-v1"):
            raise ValueError("self identity attestation schema or namespace is invalid")
        for name in ("authority_id", "installation_id", "graph_incarnation", "role_head_id",
                     "attestation_id", "signer_key_id", "signature"):
            value = getattr(self, name)
            if type(value) is not str or not value:
                raise ValueError(f"self identity attestation {name} is missing")
        try:
            signature_bytes = base64.urlsafe_b64decode(self.signature + "==")
            canonical_signature = base64.urlsafe_b64encode(signature_bytes).decode("ascii").rstrip("=")
        except (ValueError, UnicodeEncodeError, binascii.Error) as exc:
            raise ValueError("self identity attestation signature encoding is invalid") from exc
        if len(signature_bytes) != 64 or canonical_signature != self.signature:
            raise ValueError("self identity attestation signature encoding is invalid")
        if type(self.manifest_digest) is not str or _SHA256.fullmatch(self.manifest_digest) is None:
            raise ValueError("self identity attestation manifest digest is invalid")
        if self.persona_ref != f"persona:{self.namespace.persona_id}":
            raise ValueError("self identity attestation persona differs from namespace")
        if (type(self.self_entity_ref) is not str
                or not self.self_entity_ref.startswith("entity:")
                or self.self_entity_ref.startswith("entity:account-v1:")):
            raise ValueError("self identity attestation needs a role entity, not an account")
        if type(self.revision) is not int or self.revision < 1:
            raise ValueError("self identity attestation revision must be positive")
        if type(self.revocation_epoch) is not int or self.revocation_epoch < 0:
            raise ValueError("self identity attestation revocation epoch is invalid")
        try:
            if (type(self.valid_until_utc) is not str
                    or datetime.strptime(self.valid_until_utc, "%Y-%m-%dT%H:%M:%SZ")
                    .strftime("%Y-%m-%dT%H:%M:%SZ") != self.valid_until_utc):
                raise ValueError("expiry is not canonical")
        except ValueError as exc:
            raise ValueError("self identity attestation expiry is invalid") from exc

    @property
    def signing_payload(self) -> dict[str, object]:
        """Canonical fields that the future issuer must bind into its signature."""
        return {
            "schema": self.schema,
            "signature_scheme": self.signature_scheme,
            "namespace": list(self.namespace.as_tuple),
            "authority_id": self.authority_id,
            "installation_id": self.installation_id,
            "manifest_digest": self.manifest_digest,
            "graph_incarnation": self.graph_incarnation,
            "role_head_id": self.role_head_id,
            "persona_ref": self.persona_ref,
            "self_entity_ref": self.self_entity_ref,
            "attestation_id": self.attestation_id,
            "revision": self.revision,
            "revocation_epoch": self.revocation_epoch,
            "valid_until_utc": self.valid_until_utc,
            "signer_key_id": self.signer_key_id,
        }


class CurrentAdminSelfIdentityPort(Protocol):
    """Fresh independently verified lookup, implemented by W09/D11 only.

    Select by namespace; never echo a caller-supplied proposed entity. The
    implementation must return None after replacement, expiry or revocation.
    """

    def current_attestation(
        self, namespace: NamespaceId,
    ) -> AdminSelfIdentityAttestationV1 | None: ...


def qualify_admin_self_identity(
    *,
    role: ActiveRoleQualification,
    activation_atom: GraphAtom,
    policy: AdminInstallationPolicy,
    installation_grant: InstallationGrantV2,
    owner_guard: OwnerAuthorizationGuardV1,
    port: CurrentAdminSelfIdentityPort | None,
) -> SelfIdentityMapping:
    """Qualify one mapping candidate; graph issuance remains unavailable.

    ``policy`` must come from the protected administrator profile, ``grant``
    from the authenticated Authority channel, ``role`` from a current D01 read,
    and ``port`` from a future administrator pairing store. This function does
    not claim those trust boundaries merely because values have these types.
    """
    if port is None or not callable(getattr(port, "current_attestation", None)):
        raise ValueError("current administrator self identity port is unavailable")
    if (type(role) is not ActiveRoleQualification or type(activation_atom) is not GraphAtom
            or type(policy) is not AdminInstallationPolicy
            or type(installation_grant) is not InstallationGrantV2
            or type(owner_guard) is not OwnerAuthorizationGuardV1):
        raise TypeError("current D01, installation, Authority, and Owner proofs are required")
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
            or owner_guard.namespace != namespace
            or owner_guard.authority_id != policy.expected_authority_id
            or owner_guard.installation_id != policy.installation_id
            or owner_guard.authorization_revision != role.authorization_revision
            or owner_guard.pending_revoke_operation_id is not None
            or owner_guard.minimum_revocation_revision >= owner_guard.authorization_revision
            or owner_guard.minimum_revocation_epoch > 0):
        raise ValueError("current installed persona or Owner proof differs")
    try:
        attestation = port.current_attestation(namespace)
    except Exception as exc:
        raise ValueError("current administrator self identity attestation is unavailable") from exc
    if type(attestation) is not AdminSelfIdentityAttestationV1:
        raise ValueError("current administrator self identity attestation is unavailable")
    if (attestation.namespace != namespace
            or attestation.authority_id != policy.expected_authority_id
            or attestation.installation_id != policy.installation_id
            or attestation.manifest_digest != policy.manifest_digest
            or attestation.graph_incarnation != activation["graph_incarnation"]
            or attestation.role_head_id != role.head_id):
        raise ValueError("administrator self identity attestation differs from current role")
    digest = canonical_digest(attestation.signing_payload)
    return SelfIdentityMapping(
        "self-map:" + digest,
        attestation.persona_ref,
        attestation.self_entity_ref,
        "d11:self-identity:" + digest,
        attestation.role_head_id,
        attestation.graph_incarnation,
        "active",
    )


__all__ = (
    "AdminSelfIdentityAttestationV1", "CurrentAdminSelfIdentityPort",
    "qualify_admin_self_identity",
)
