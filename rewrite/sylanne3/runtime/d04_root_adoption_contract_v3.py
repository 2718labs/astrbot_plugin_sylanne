"""D04 authored-lineage root V3 evidence; constructing it grants no authority.

The V3 schema and phase are disjoint from the held V2 event-derived root path.
W01 must independently rederive and authenticate every original in its final
Owner-fenced Graph transaction before accepting this evidence.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, fields
import re

from ..graph_types import AtomKey
from ..runtime_contracts import NamespaceId, VersionedRef, canonical_digest


ROOT_ADOPTION_PHASE_V3 = "d11.d04-authored-root-adoption.v3"
ROOT_ADOPTION_SCHEMA_V3 = "d11.d04_authored_root_adoption_evidence.v3"
_CHECKPOINT = "d04.numeric_checkpoint.v2"
_FEELING = "d04.authored_feeling_state.v1"
_MOOD = "d04.authored_mood_state.v1"
_SHA = re.compile(r"[0-9a-f]{64}\Z")
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/@#=+-]{0,255}\Z")


def _digest(value: object, name: str) -> None:
    if type(value) is not str or _SHA.fullmatch(value) is None:
        raise ValueError(f"{name} must be a bare lowercase SHA-256 digest")


def _id(value: object, name: str) -> None:
    if type(value) is not str or _IDENTIFIER.fullmatch(value) is None:
        raise ValueError(f"invalid {name}")


@dataclass(frozen=True, slots=True)
class RootAdoptionWriteV3:
    checkpoint_ref: str
    checkpoint_revision: int
    checkpoint_value_digest: str
    state_ref: str
    state_revision: int
    state_value_digest: str

    def __post_init__(self) -> None:
        checkpoint = AtomKey.from_token(self.checkpoint_ref)
        state = AtomKey.from_token(self.state_ref)
        if (checkpoint.owner.kind != "persona" or state.owner != checkpoint.owner
                or checkpoint.type_name != _CHECKPOINT
                or state.type_name not in {_FEELING, _MOOD}
                or checkpoint.name != state.name
                or type(self.checkpoint_revision) is not int
                or type(self.state_revision) is not int
                or self.checkpoint_revision != 1 or self.state_revision != 1):
            raise ValueError("V3 root write requires paired rev1 authored state")
        _digest(self.checkpoint_value_digest, "checkpoint_value_digest")
        _digest(self.state_value_digest, "state_value_digest")


@dataclass(frozen=True, slots=True)
class RootAdoptionEvidenceV3:
    namespace: NamespaceId
    operation_id: str
    owner_actor: str
    owner_session_ref: str
    owner_session_binding_digest: str
    parent_budget_lease_ref: str
    parent_budget_original_digest: str
    d11_freeze_original_digest: str
    d11_grant_digest: str
    d11_grant_signature_digest: str
    d11_reserve_receipt_digest: str
    active_scheme_head: VersionedRef
    draft_head: VersionedRef
    draft_digest: str
    root_input_digest: str
    candidate_digest: str
    preset_digest: str
    asset_digest: str
    native_manifest_sha256: str
    native_sha256: str
    abi2_initial_box_digest: str
    abi2_readout_digest: str
    output_projection_digest: str
    graph_read_set_digest: str
    writes: tuple[RootAdoptionWriteV3, ...]
    output_write_set_digest: str
    write_commitment_digest: str
    bundle_digest: str
    evidence_digest: str
    phase: str = ROOT_ADOPTION_PHASE_V3
    schema: str = ROOT_ADOPTION_SCHEMA_V3

    def __post_init__(self) -> None:
        if self.schema != ROOT_ADOPTION_SCHEMA_V3 or self.phase != ROOT_ADOPTION_PHASE_V3:
            raise ValueError("V3 root adoption schema or phase differs")
        if type(self.namespace) is not NamespaceId:
            raise TypeError("V3 root namespace must be NamespaceId")
        for name in ("operation_id", "owner_actor", "owner_session_ref",
                     "parent_budget_lease_ref"):
            _id(getattr(self, name), name)
        for name in ("active_scheme_head", "draft_head"):
            value = getattr(self, name)
            if type(value) is not VersionedRef:
                raise TypeError(f"{name} must be VersionedRef")
            key = AtomKey.from_token(value.ref)
            if (NamespaceId.from_key(key) != self.namespace
                    or key.owner.kind != "persona" or value.version < 1):
                raise ValueError(f"{name} must be a current persona head")
        active_head_key = AtomKey.from_token(self.active_scheme_head.ref)
        if (active_head_key.type_name != "d12.active_scheme_head.v1"
                or active_head_key.name != "current"
                or AtomKey.from_token(self.draft_head.ref).type_name
                   != "d12.character_draft.v1"):
            raise ValueError("D12 active scheme or draft head type differs")
        for name in (
            "owner_session_binding_digest", "parent_budget_original_digest",
            "d11_freeze_original_digest", "d11_grant_digest",
            "d11_grant_signature_digest", "d11_reserve_receipt_digest",
            "draft_digest", "root_input_digest", "candidate_digest",
            "preset_digest", "asset_digest", "native_manifest_sha256",
            "native_sha256", "abi2_initial_box_digest", "abi2_readout_digest",
            "output_projection_digest", "graph_read_set_digest",
            "output_write_set_digest", "write_commitment_digest",
            "bundle_digest", "evidence_digest",
        ):
            _digest(getattr(self, name), name)
        if (type(self.writes) is not tuple or len(self.writes) < 3
                or any(type(item) is not RootAdoptionWriteV3 for item in self.writes)):
            raise ValueError("V3 root requires typed authored writes")
        refs = tuple(item.checkpoint_ref for item in self.writes)
        states = tuple(item.state_ref for item in self.writes)
        if (refs != tuple(sorted(set(refs))) or len(set(states)) != len(states)
                or any(NamespaceId.from_key(AtomKey.from_token(ref)) != self.namespace
                       for ref in refs + states)):
            raise ValueError("V3 root writes must be unique, ordered and scoped")
        kinds = tuple(AtomKey.from_token(ref).type_name for ref in states)
        if kinds.count(_FEELING) < 2 or kinds.count(_MOOD) != 1:
            raise ValueError("V3 root requires two authored Feelings and one authored Mood")
        if self.write_commitment_digest != canonical_digest(self.writes):
            raise ValueError("V3 root write commitment digest differs")
        if self.evidence_digest != root_adoption_evidence_digest_v3(self):
            raise ValueError("V3 root evidence digest differs")


def root_adoption_evidence_digest_v3(value: RootAdoptionEvidenceV3 | dict) -> str:
    """Canonical V3-only commitment, including schema and phase."""
    names = tuple(field.name for field in fields(RootAdoptionEvidenceV3)
                  if field.name != "evidence_digest")
    if type(value) is dict:
        if set(value) != set(names):
            raise ValueError("V3 root digest fields differ")
        if value["phase"] != ROOT_ADOPTION_PHASE_V3 or value["schema"] != ROOT_ADOPTION_SCHEMA_V3:
            raise ValueError("V3 root digest schema or phase differs")
        return canonical_digest(tuple(value[name] for name in names))
    if type(value) is not RootAdoptionEvidenceV3:
        raise TypeError("V3 root adoption evidence required")
    return canonical_digest(tuple(
        getattr(value, name) for name in names))


def root_adoption_to_wire_v3(value: RootAdoptionEvidenceV3) -> dict:
    if type(value) is not RootAdoptionEvidenceV3:
        raise TypeError("V3 root adoption evidence required")
    result = asdict(value)
    result["writes"] = [asdict(item) for item in value.writes]
    return result


def root_adoption_from_wire_v3(raw: object) -> RootAdoptionEvidenceV3:
    if type(raw) is not dict or set(raw) != {
            field.name for field in fields(RootAdoptionEvidenceV3)}:
        raise ValueError("V3 root wire fields differ")
    data = dict(raw)
    if type(data["namespace"]) is not dict or set(data["namespace"]) != {
            "bot_id", "persona_id"}:
        raise ValueError("V3 root namespace wire differs")
    data["namespace"] = NamespaceId(**data["namespace"])
    for name in ("active_scheme_head", "draft_head"):
        value = data[name]
        if type(value) is not dict or set(value) != {"ref", "version"}:
            raise ValueError("V3 root head wire differs")
        data[name] = VersionedRef(**value)
    if type(data["writes"]) is not list:
        raise ValueError("V3 root writes wire differs")
    names = {field.name for field in fields(RootAdoptionWriteV3)}
    writes = []
    for value in data["writes"]:
        if type(value) is not dict or set(value) != names:
            raise ValueError("V3 root write wire differs")
        writes.append(RootAdoptionWriteV3(**value))
    data["writes"] = tuple(writes)
    result = RootAdoptionEvidenceV3(**data)
    if root_adoption_to_wire_v3(result) != raw:
        raise ValueError("noncanonical V3 root wire")
    return result


__all__ = [
    "ROOT_ADOPTION_PHASE_V3", "ROOT_ADOPTION_SCHEMA_V3",
    "RootAdoptionWriteV3", "RootAdoptionEvidenceV3",
    "root_adoption_evidence_digest_v3", "root_adoption_to_wire_v3",
    "root_adoption_from_wire_v3",
]
