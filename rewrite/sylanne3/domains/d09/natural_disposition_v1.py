"""D09 continuation facts for one adopted, finite natural meaning manifest.

Execution, intent, admission and expenses retain their existing writers.
This metadata stores no generated text and confers no send permission.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import math
import json

from ...graph_types import AtomKey, GraphWrite, Owner, TypeSpec
from ...runtime_contracts import NamespaceId, VersionedRef, canonical_digest, canonical_serialize, schema_hash

TYPE = "d09.natural_batch_disposition.v1"
STATES = frozenset({"ready", "held", "cancelled", "superseded"})
REASONS = frozenset({"owner_stop", "scoped_source_changed", "deadline_expired", "predecessor_unknown", "qualification_unavailable", "relevant_new_turn"})


@dataclass(frozen=True, slots=True)
class NaturalChildDispositionV1:
    index: int
    operation_id: str
    effect_id: str
    segment_id: str
    payload_digest: str
    continuation_state: str = "ready"
    reason_code: str | None = None
    cause_kind: str | None = None
    cause_ref: str | None = None
    cause_digest: str | None = None


@dataclass(frozen=True, slots=True)
class NaturalBatchDispositionV1:
    namespace: NamespaceId
    installation_id: str
    parent_original_id: str
    activity_id: str
    generation_original_operation_id: str
    generation_original_digest: str
    review_original_operation_id: str
    review_original_digest: str
    whole_output_digest: str
    creation_operation_id: str
    identity_manifest_digest: str
    dependency_refs: tuple[VersionedRef, ...]
    expires_at_utc: float
    children: tuple[NaturalChildDispositionV1, ...]
    revision: int = 1
    birth_original_ref: str | None = None
    authority_original_ref: str | None = None
    schema: str = TYPE

    def to_wire(self):
        return json.loads(canonical_serialize(asdict(self)))


def _digest(value):
    return type(value) is str and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def child_identity_manifest_v1(children):
    return tuple((c.index, c.operation_id, c.effect_id, c.segment_id, c.payload_digest) for c in children)


def natural_disposition_from_wire_v1(raw):
    if type(raw) is not dict or set(raw) != set(NaturalBatchDispositionV1.__dataclass_fields__):
        raise ValueError("exact natural disposition fields required")
    data = dict(raw)
    data["namespace"] = NamespaceId(**data["namespace"])
    data["children"] = tuple(NaturalChildDispositionV1(**c) for c in data["children"])
    data["dependency_refs"] = tuple(VersionedRef(**ref) for ref in data["dependency_refs"])
    value = NaturalBatchDispositionV1(**data)
    validate_natural_disposition_v1(raw)
    return value


def validate_natural_disposition_v1(raw):
    if type(raw) is not dict or set(raw) != set(NaturalBatchDispositionV1.__dataclass_fields__) or raw["schema"] != TYPE:
        raise ValueError("exact bounded natural disposition schema required")
    ns = NamespaceId(**raw["namespace"])
    for field in ("installation_id", "parent_original_id", "activity_id", "generation_original_operation_id", "review_original_operation_id", "creation_operation_id"):
        if type(raw[field]) is not str or not 1 <= len(raw[field]) <= 192:
            raise ValueError("natural disposition identity is invalid")
    for field in ("generation_original_digest", "review_original_digest", "whole_output_digest", "identity_manifest_digest"):
        if not _digest(raw[field]):
            raise ValueError("natural disposition original commitment is invalid")
    if (type(raw["revision"]) is not int or raw["revision"] < 1
            or type(raw["expires_at_utc"]) not in (int, float) or not math.isfinite(raw["expires_at_utc"]) or raw["expires_at_utc"] < 0
            or any(type(raw[field]) is not str or not raw[field].startswith("natural-disposition-original:") or len(raw[field])>128
                for field in ("birth_original_ref","authority_original_ref"))
            or type(raw["children"]) is not list or not 1 <= len(raw["children"]) <= 4
            or type(raw["dependency_refs"]) is not list or len(raw["dependency_refs"]) > 128):
        raise ValueError("natural disposition finite bounds differ")
    children = tuple(NaturalChildDispositionV1(**c) for c in raw["children"])
    if (any(type(c.index) is not int for c in children)
            or tuple(c.index for c in children) != tuple(range(len(children)))
            or len({c.operation_id for c in children}) != len(children)
            or len({c.effect_id for c in children}) != len(children)
            or canonical_digest(child_identity_manifest_v1(children)) != raw["identity_manifest_digest"]
            or children[0].operation_id != raw["creation_operation_id"]):
        raise ValueError("natural disposition immutable child identity differs")
    for c in children:
        if (any(type(v) is not str or not 1 <= len(v) <= 192 for v in (c.operation_id, c.effect_id, c.segment_id))
                or not _digest(c.payload_digest) or c.continuation_state not in STATES
                or c.reason_code is not None and c.reason_code not in REASONS
                or c.continuation_state == "ready" and any(v is not None for v in (c.reason_code,c.cause_kind,c.cause_ref,c.cause_digest))
                or c.continuation_state != "ready" and c.reason_code is None
                or (c.cause_ref is None) != (c.cause_digest is None)
                or c.cause_digest is not None and not _digest(c.cause_digest)
                or c.cause_kind is not None and c.cause_kind not in {"owner_stop","graph_dependency_change","clock_deadline","authority_effect_observation","adopted_relevant_ingress"}
                or c.cause_ref is not None and (type(c.cause_ref) is not str or not 1 <= len(c.cause_ref) <= 4096)
                or c.cause_ref is None and (c.cause_kind is not None or c.continuation_state in {"cancelled", "superseded"})):
            raise ValueError("natural continuation state has no qualified cause")
    refs = tuple(VersionedRef(**ref) for ref in raw["dependency_refs"])
    if len({ref.ref for ref in refs}) != len(refs):
        raise ValueError("natural disposition dependency is duplicate")
    for ref in refs:
        key = AtomKey.from_token(ref.ref)
        if NamespaceId.from_key(key) != ns or key.type_name not in {"memory.source", "memory.access", "d06.source_correction_head.v1"}:
            raise ValueError("natural disposition metadata dependency scope differs")


def natural_disposition_key_v1(value):
    return AtomKey(Owner("activity", *value.namespace.as_tuple, value.activity_id), TYPE,
        "natural-batch:" + canonical_digest((value.namespace, value.parent_original_id))[:40])


def natural_disposition_write_v1(value):
    raw = value.to_wire()
    validate_natural_disposition_v1(raw)
    return GraphWrite(natural_disposition_key_v1(value), raw)


def natural_disposition_type_spec_v1():
    return TypeSpec(name=TYPE, owner_kinds=("activity",), storage_role="state", immutable=False,
        schema_version=1, writer_domain="d09", validator=validate_natural_disposition_v1, schema_hash=schema_hash({"type": TYPE, "version": 1, "fields": sorted(NaturalBatchDispositionV1.__dataclass_fields__),
            "children": sorted(NaturalChildDispositionV1.__dataclass_fields__), "bound": 4,
            "authority": "continuation facts only; actual intents admission execution and fees remain external"}))
