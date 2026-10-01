"""One immutable consumption of each authenticated event/facet contribution."""
from __future__ import annotations
from dataclasses import dataclass
import math
from ...graph_types import AtomKey, Owner, TypeSpec
from ...runtime_contracts import NamespaceId, canonical_digest, schema_hash

TYPE_NAME = "d04.contribution_ledger.v1"


def contribution_ledger_key_v3(namespace, family_root, event_ref, contribution_key, facet_id):
    return AtomKey(Owner("persona", *namespace.as_tuple), TYPE_NAME,
        "consumption:" + canonical_digest((family_root, event_ref, contribution_key, facet_id)))


@dataclass(frozen=True, slots=True)
class D04ContributionConsumptionV3:
    family_root: str
    event_ref: str
    contribution_key: str
    facet_id: str
    contribution_dose: tuple[float, ...]
    block_shares: tuple[tuple[str, float], ...]
    allocation_ref: str
    mapping_ref: str
    mapping_digest: str
    role_start: float
    role_end: float
    operation_id: str
    numeric_binding_digest: str
    output_original_digest: str
    schema: str = TYPE_NAME

    def __post_init__(self):
        if self.schema != TYPE_NAME or any(type(v) is not str or not v for v in (
                self.family_root, self.event_ref, self.contribution_key, self.facet_id,
                self.allocation_ref, self.mapping_ref, self.operation_id)):
            raise ValueError("D04 contribution consumption identity is incomplete")
        for value in (self.mapping_digest, self.numeric_binding_digest, self.output_original_digest):
            if type(value) is not str or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
                raise ValueError("D04 contribution consumption digest is invalid")
        if (type(self.contribution_dose) is not tuple or len(self.contribution_dose) != 24
                or any(type(v) not in (int, float) or not math.isfinite(v) for v in self.contribution_dose)
                or type(self.block_shares) is not tuple or not self.block_shares
                or tuple(sorted(self.block_shares)) != self.block_shares
                or len({ref for ref, _ in self.block_shares}) != len(self.block_shares)
                or any(type(v) not in (int, float) or not math.isfinite(v) or not 0 < v <= 1 for _, v in self.block_shares)
                or math.fsum(v for _, v in self.block_shares) > 1
                or any(type(v) not in (int, float) or not math.isfinite(v) for v in (self.role_start, self.role_end))
                or self.role_end <= self.role_start):
            raise ValueError("D04 contribution consumption must retain exact bounded complete allocation")
        owner = AtomKey.from_token(self.event_ref).owner
        for ref, _ in self.block_shares:
            key = AtomKey.from_token(ref)
            if (key.owner.bot, key.owner.persona) != (owner.bot, owner.persona) or key.type_name not in {"d04.numeric_checkpoint.v1", "d04.numeric_checkpoint.v2"}:
                raise ValueError("D04 contribution member scope differs")


def decode_contribution_ledger_v3(raw):
    if type(raw) is not dict or set(raw) != set(D04ContributionConsumptionV3.__dataclass_fields__):
        raise ValueError("D04 contribution ledger fields differ")
    return D04ContributionConsumptionV3(**{**raw, "contribution_dose": tuple(raw["contribution_dose"]),
        "block_shares": tuple(tuple(pair) for pair in raw["block_shares"])})


def contribution_ledger_type_spec_v3():
    return TypeSpec(TYPE_NAME, ("persona",), "source", decode_contribution_ledger_v3,
        immutable=True, schema_version=1, writer_domain="d04", schema_hash=schema_hash({
            "type": TYPE_NAME, "fields": tuple(D04ContributionConsumptionV3.__dataclass_fields__),
            "identity": "family_event_contribution_facet_once", "writer": "joint_numeric_atomic_adoption"}))
