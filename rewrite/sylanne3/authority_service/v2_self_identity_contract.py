"""Versioned Authority-owned persona to self registration identities.

These values are comparison targets.  Constructing one never authenticates an
administrator, a peer, a graph head, or a live content fence.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, fields
import hashlib
import json
import re

from ..runtime_contracts import NamespaceId
from .contract import identifier
from .v2_contract import FencePermitV2, from_wire as fence_from_wire, to_wire as fence_to_wire


SCHEMA = "sylanne3.authority.self-identity.v1"
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def _digest(value: object, name: str) -> str:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise ValueError(f"{name} must be a lowercase SHA-256 digest")
    return value


def _self_ref(value: object) -> str:
    if (type(value) is not str or not value.startswith("entity:")
            or len(value) <= len("entity:")
            or value.startswith("entity:account-v1:")):
        raise ValueError("self identity must be a non-account entity reference")
    return value


@dataclass(frozen=True, slots=True)
class SelfIdentityMutationV1:
    authority_id: str
    authority_namespace: str
    namespace: NamespaceId
    installation_id: str
    manifest_digest: str
    self_entity_ref: str
    action: str
    operation_id: str
    expected_revision: int
    schema: str = SCHEMA

    def __post_init__(self) -> None:
        if self.schema != SCHEMA or type(self.namespace) is not NamespaceId:
            raise ValueError("self identity mutation schema differs")
        for name in ("authority_id", "authority_namespace", "installation_id",
                     "operation_id"):
            identifier(getattr(self, name), name)
        _digest(self.manifest_digest, "manifest_digest")
        _self_ref(self.self_entity_ref)
        if self.action not in {"set", "revoke"}:
            raise ValueError("self identity action differs")
        if type(self.expected_revision) is not int or self.expected_revision < 0:
            raise ValueError("expected self identity revision differs")

    @property
    def request_digest(self) -> str:
        return hashlib.sha256(json.dumps(
            asdict(self), sort_keys=True, separators=(",", ":"),
            ensure_ascii=False).encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class SelfIdentityCurrentRequestV1:
    authority_id: str
    authority_namespace: str
    namespace: NamespaceId
    installation_id: str
    manifest_digest: str
    request_operation_id: str
    permit: FencePermitV2
    schema: str = SCHEMA

    def __post_init__(self) -> None:
        if self.schema != SCHEMA or type(self.namespace) is not NamespaceId:
            raise ValueError("self identity current request schema differs")
        for name in ("authority_id", "authority_namespace", "installation_id",
                     "request_operation_id"):
            identifier(getattr(self, name), name)
        _digest(self.manifest_digest, "manifest_digest")
        if (type(self.permit) is not FencePermitV2
                or self.permit.operation not in {"read", "write"}
                or (self.permit.authority_id, self.permit.namespace) !=
                   (self.authority_id, self.authority_namespace)):
            raise ValueError("current self identity requires a matching content permit")


@dataclass(frozen=True, slots=True)
class AuthorityCurrentSelfIdentityV1:
    namespace: NamespaceId
    authority_namespace: str
    authority_id: str
    installation_id: str
    manifest_digest: str
    activation_generation: int
    graph_incarnation: str
    role_head_id: str
    persona_ref: str
    self_entity_ref: str
    mapping_id: str
    mapping_revision: int
    mapping_revocation_epoch: int
    registration_operation_id: str
    registration_digest: str
    owner_authorization_revision: int
    owner_authorization_head: str
    owner_minimum_revocation_revision: int
    owner_revocation_epoch: int
    request_operation_id: str
    permit: FencePermitV2
    schema: str = SCHEMA

    def __post_init__(self) -> None:
        if self.schema != SCHEMA or type(self.namespace) is not NamespaceId:
            raise ValueError("current self identity schema differs")
        for name in ("authority_id", "authority_namespace", "installation_id",
                     "graph_incarnation", "role_head_id", "mapping_id",
                     "registration_operation_id", "owner_authorization_head",
                     "request_operation_id"):
            identifier(getattr(self, name), name)
        _digest(self.manifest_digest, "manifest_digest")
        _digest(self.registration_digest, "registration_digest")
        _self_ref(self.self_entity_ref)
        if self.persona_ref != "persona:" + self.namespace.persona_id:
            raise ValueError("current self identity persona differs")
        if not self.mapping_id.startswith("self-map:"):
            raise ValueError("self identity mapping ID differs")
        if (type(self.mapping_revision) is not int or self.mapping_revision < 1
                or type(self.mapping_revocation_epoch) is not int
                or self.mapping_revocation_epoch < 0
                or type(self.activation_generation) is not int
                or self.activation_generation < 1
                or type(self.owner_authorization_revision) is not int
                or self.owner_authorization_revision < 1
                or type(self.owner_minimum_revocation_revision) is not int
                or self.owner_minimum_revocation_revision < 0
                or type(self.owner_revocation_epoch) is not int
                or self.owner_revocation_epoch < 0):
            raise ValueError("current self identity revision differs")
        if (type(self.permit) is not FencePermitV2
                or self.permit.operation not in {"read", "write"}
                or (self.permit.authority_id, self.permit.namespace,
                    self.permit.generation) !=
                   (self.authority_id, self.authority_namespace,
                    self.activation_generation)):
            raise ValueError("current self identity permit differs")


def to_wire(value: SelfIdentityMutationV1 | SelfIdentityCurrentRequestV1 |
            AuthorityCurrentSelfIdentityV1) -> dict[str, object]:
    if type(value) not in (SelfIdentityMutationV1, SelfIdentityCurrentRequestV1,
                           AuthorityCurrentSelfIdentityV1):
        raise TypeError("typed self identity contract required")
    kind = {
        SelfIdentityMutationV1: "self_identity_mutation_v1",
        SelfIdentityCurrentRequestV1: "self_identity_current_request_v1",
        AuthorityCurrentSelfIdentityV1: "authority_current_self_identity_v1",
    }[type(value)]
    raw = asdict(value)
    raw["namespace"] = asdict(value.namespace)
    if "permit" in raw:
        raw["permit"] = fence_to_wire(value.permit)
    return {"kind": kind, **raw}


def from_wire(raw: object) -> (SelfIdentityMutationV1 |
                                SelfIdentityCurrentRequestV1 |
                                AuthorityCurrentSelfIdentityV1):
    if type(raw) is not dict:
        raise ValueError("self identity wire object required")
    target = {
        "self_identity_mutation_v1": SelfIdentityMutationV1,
        "self_identity_current_request_v1": SelfIdentityCurrentRequestV1,
        "authority_current_self_identity_v1": AuthorityCurrentSelfIdentityV1,
    }.get(raw.get("kind"))
    if target is None or set(raw) != {"kind"} | {field.name for field in fields(target)}:
        raise ValueError("self identity wire fields differ")
    parts = {key: value for key, value in raw.items() if key != "kind"}
    namespace = parts["namespace"]
    if type(namespace) is not dict or set(namespace) != {"bot_id", "persona_id"}:
        raise ValueError("self identity namespace wire fields differ")
    parts["namespace"] = NamespaceId(**namespace)
    if "permit" in parts:
        parts["permit"] = fence_from_wire(parts["permit"])
    value = target(**parts)
    if to_wire(value) != raw:
        raise ValueError("noncanonical self identity wire object")
    return value


__all__ = (
    "AuthorityCurrentSelfIdentityV1", "SelfIdentityCurrentRequestV1",
    "SelfIdentityMutationV1", "to_wire", "from_wire",
)
