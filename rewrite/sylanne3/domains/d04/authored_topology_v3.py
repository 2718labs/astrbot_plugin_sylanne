"""Explicit authored topology provenance, separate from observed D06 sources.

The immutable graph marker is only a typed assertion. Runtime replay must also
prove its W01 original, exact edge/history set, common authored root and pinned
installation policy. It is not an event, memory source or numerical certificate.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import math
import re
from uuid import UUID

from ...graph_types import AtomKey, Owner, TypeSpec
from ...runtime_contracts import NamespaceId, schema_hash

TYPE_NAME = "d04.authored_root_topology.v3"
TOPOLOGY_ID = "d04.authored_root_mood_feeling_same_axis.v3"
POLICY_PATH = "resources/catalogue/d04-authored-root-topology.v3.json"
POLICY_SCHEMA = "d04.packaged-authored-root-topology.v3"
TEMPLATE_PAIRS = (
    ("feeling.initial.secondary.v3", "mood.initial.v3"),
    ("feeling.initial.v3", "mood.initial.v3"),
)
_SHA = re.compile(r"[0-9a-f]{64}\Z")


@dataclass(frozen=True, slots=True)
class AuthoredRootTopologyV3:
    operation_id: str
    root_operation_id: str
    root_original_digest: str
    root_freeze_digest: str
    manifest_digest: str
    policy_digest: str
    operator_sha256: str
    preset_digest: str
    active_scheme_ref: str
    active_scheme_revision: int
    active_scheme_digest: str
    owner_binding_digest: str
    request_digest: str
    member_refs: tuple[str, ...]
    edge_write_set_digest: str
    coefficient: float
    effective_from: float
    effective_until: float
    topology_id: str = TOPOLOGY_ID
    schema: str = TYPE_NAME

    def __post_init__(self):
        if self.schema != TYPE_NAME or self.topology_id != TOPOLOGY_ID:
            raise ValueError("unregistered authored topology schema or policy")
        for name in ("operation_id", "root_operation_id"):
            value = getattr(self, name)
            try:
                parsed = UUID(value)
            except (TypeError, ValueError, AttributeError) as exc:
                raise ValueError("authored topology requires canonical UUID4 operations") from exc
            if parsed.version != 4 or str(parsed) != value:
                raise ValueError("authored topology requires canonical UUID4 operations")
        for name in ("root_original_digest", "root_freeze_digest", "manifest_digest", "policy_digest",
                     "operator_sha256", "preset_digest", "active_scheme_digest", "owner_binding_digest",
                     "request_digest", "edge_write_set_digest"):
            if type(getattr(self, name)) is not str or _SHA.fullmatch(getattr(self, name)) is None:
                raise ValueError("authored topology requires exact SHA-256 commitments")
        head = AtomKey.from_token(self.active_scheme_ref)
        if (head.owner.kind != "persona" or head.type_name != "d12.active_scheme_head.v1"
                or head.name != "current" or type(self.active_scheme_revision) is not int
                or self.active_scheme_revision < 1):
            raise ValueError("authored topology requires a current active scheme head")
        if (type(self.member_refs) is not tuple or len(self.member_refs) != 3
                or self.member_refs != tuple(sorted(set(self.member_refs)))):
            raise ValueError("authored topology requires exactly three ordered unique members")
        for ref in self.member_refs:
            key = AtomKey.from_token(ref)
            if key.owner != head.owner or key.type_name != "d04.numeric_checkpoint.v2":
                raise ValueError("authored topology member lineage or namespace differs")
        if type(self.coefficient) not in (int, float) or self.coefficient != 0.125:
            raise ValueError("authored topology requires the registered singleton gain")
        for value in (self.effective_from, self.effective_until):
            if type(value) not in (int, float) or not math.isfinite(value):
                raise ValueError("authored topology interval must be finite")
        if self.effective_until <= self.effective_from:
            raise ValueError("authored topology interval must be positive")


def authored_topology_key_v3(namespace: NamespaceId, operation_id: str) -> AtomKey:
    return AtomKey(Owner("persona", *namespace.as_tuple), TYPE_NAME, operation_id)


def decode_authored_root_topology_v3(value: dict) -> AuthoredRootTopologyV3:
    if type(value) is not dict or set(value) != set(AuthoredRootTopologyV3.__dataclass_fields__):
        raise ValueError("authored topology marker fields differ")
    if type(value["member_refs"]) is not list:
        raise ValueError("authored topology marker members must be an array")
    return AuthoredRootTopologyV3(**{**value, "member_refs": tuple(value["member_refs"])})


def authored_topology_type_spec_v3() -> TypeSpec:
    return TypeSpec(TYPE_NAME, ("persona",), "source", decode_authored_root_topology_v3,
        immutable=True, schema_version=3, writer_domain="d04",
        schema_hash=schema_hash({"type": TYPE_NAME, "version": 3,
            "fields": tuple(AuthoredRootTopologyV3.__dataclass_fields__),
            "topology_id": TOPOLOGY_ID, "pairs": TEMPLATE_PAIRS,
            "edge_count": 48, "gain": 0.125,
            "lineage": "owner_authored_configuration_not_d06_observation"}))
