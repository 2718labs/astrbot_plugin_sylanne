"""D11's immutable graph address for one dispatch effect claim.

The value is content-free recovery identity. Creating a value or GraphWrite
does not establish current checks or authorize a handoff. Only the private
GraphCoordinator final callback may submit this write under its held graph
transaction after verifying the same P2 and every current domain guard.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, fields
import re

from ..graph_types import AtomKey, GraphWrite, Owner, TypeSpec
from ..runtime_contracts import NamespaceId, schema_hash


CLAIM_TYPE = "d11.dispatch_claim.v1"
_SHA256 = re.compile(r"sha256:[0-9a-f]{64}\Z")
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}\Z")


@dataclass(frozen=True, slots=True)
class DispatchGraphClaimValueV1:
    """One P2 claim identity; all authority and domain facts remain external."""

    bot_id: str
    persona_id: str
    graph_incarnation: str
    activity_id: str
    effect_id: str
    operation_id: str
    handoff_id: str
    admission_ref: str
    authority_namespace: str
    p2_permit_digest: str
    p2_fence_epoch: int
    p2_revision: int
    p2_execution_seq: int
    p2_execution_digest: str
    context_digest: str
    owner_witness_digest: str
    binding_digest: str
    claimed_receipt_digest: str
    current_evidence_digest: str
    schema: str = CLAIM_TYPE

    def __post_init__(self) -> None:
        from ..graph_coordinator import namespace_ref

        if self.schema != CLAIM_TYPE:
            raise ValueError("unknown dispatch graph claim schema")
        for name in ("bot_id", "persona_id", "graph_incarnation",
                     "activity_id", "effect_id", "operation_id", "handoff_id",
                     "admission_ref", "authority_namespace"):
            value = getattr(self, name)
            if type(value) is not str or _IDENTIFIER.fullmatch(value) is None:
                raise ValueError(f"dispatch claim {name} is invalid")
        for name in ("p2_permit_digest", "p2_execution_digest",
                     "context_digest", "owner_witness_digest",
                     "binding_digest", "claimed_receipt_digest",
                     "current_evidence_digest"):
            value = getattr(self, name)
            if type(value) is not str or _SHA256.fullmatch(value) is None:
                raise ValueError(f"dispatch claim {name} is invalid")
        for name, minimum in (("p2_fence_epoch", 1), ("p2_revision", 2),
                              ("p2_execution_seq", 2)):
            value = getattr(self, name)
            if type(value) is not int or value < minimum:
                raise ValueError(f"dispatch claim {name} is invalid")
        namespace = NamespaceId(self.bot_id, self.persona_id)
        if ("/" in self.bot_id or "/" in self.persona_id
                or self.authority_namespace != namespace_ref(namespace)):
            raise ValueError("dispatch claim namespace mapping differs")


def dispatch_claim_key(namespace: NamespaceId, effect_id: str) -> AtomKey:
    """Use one key per effect, so a changed handoff cannot mint another claim."""
    if type(namespace) is not NamespaceId:
        raise TypeError("dispatch claim needs a namespace")
    if type(effect_id) is not str or _IDENTIFIER.fullmatch(effect_id) is None:
        raise ValueError("dispatch claim effect_id is invalid")
    return AtomKey(Owner("persona", *namespace.as_tuple), CLAIM_TYPE, effect_id)


def dispatch_claim_graph_write(value: DispatchGraphClaimValueV1) -> GraphWrite:
    if type(value) is not DispatchGraphClaimValueV1:
        raise TypeError("dispatch claim needs a typed value")
    namespace = NamespaceId(value.bot_id, value.persona_id)
    return GraphWrite(dispatch_claim_key(namespace, value.effect_id), asdict(value))


def dispatch_claim_type_spec() -> TypeSpec:
    """Register an immutable private D11 write; normal proposals reject it."""
    return TypeSpec(
        CLAIM_TYPE, ("persona",), "state", _decode_claim,
        immutable=True, writer_domain="d11",
        schema_hash=schema_hash({
            "type": CLAIM_TYPE, "schema_version": 1,
            "owner_kinds": ["persona"], "storage_role": "state",
            "writer_domain": "d11",
            "fields": [field.name for field in fields(DispatchGraphClaimValueV1)],
        }),
    )


def _decode_claim(payload: object) -> DispatchGraphClaimValueV1:
    if type(payload) is not dict or set(payload) != {
            field.name for field in fields(DispatchGraphClaimValueV1)}:
        raise ValueError("dispatch claim graph fields differ")
    return DispatchGraphClaimValueV1(**payload)


__all__ = [
    "CLAIM_TYPE", "DispatchGraphClaimValueV1", "dispatch_claim_graph_write",
    "dispatch_claim_key", "dispatch_claim_type_spec",
]
