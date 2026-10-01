"""Candidate evidence for D04 authored root adoption; it grants no write authority.

W01 must rederive every field from current Owner, installation, graph reads,
trusted numeric output, and the fixed issuer inside its final graph transaction.
"""

from __future__ import annotations

from dataclasses import dataclass
import re

from ..graph_types import AtomKey
from ..runtime_contracts import NamespaceId, VersionedRef, canonical_digest


_SHA = re.compile(r"[0-9a-f]{64}\Z")
_CHECKPOINT = "d04.numeric_checkpoint.v1"
_STATE_TYPES = frozenset({"d04.feeling_state.v1", "d04.mood_field.v1"})
ROOT_ADOPTION_PHASE_V2 = "d11.d04-authored-root-adoption.v2"


def _text(value: object, name: str) -> None:
    if type(value) is not str or not value.strip():
        raise ValueError(f"{name} must be nonempty")


def _digest(value: object, name: str) -> None:
    if type(value) is not str or _SHA.fullmatch(value) is None:
        raise ValueError(f"{name} must be a lowercase SHA-256 digest")


@dataclass(frozen=True, slots=True)
class RootAdoptionWriteV2:
    """One revision-1 checkpoint and its Feeling or Mood state value."""

    checkpoint_ref: str
    checkpoint_value_digest: str
    state_ref: str
    state_value_digest: str

    def __post_init__(self) -> None:
        checkpoint = AtomKey.from_token(self.checkpoint_ref)
        state = AtomKey.from_token(self.state_ref)
        if (checkpoint.owner.kind != "persona" or state.owner != checkpoint.owner
                or checkpoint.type_name != _CHECKPOINT
                or state.type_name not in _STATE_TYPES
                or checkpoint.name != state.name):
            raise ValueError("root write keys must be paired persona D04 checkpoint and state")
        _digest(self.checkpoint_value_digest, "checkpoint_value_digest")
        _digest(self.state_value_digest, "state_value_digest")


@dataclass(frozen=True, slots=True)
class RootAdoptionEvidenceV2:
    """Frozen D11 claim for one initial root; W01 must reproduce it atomically."""

    namespace: NamespaceId
    operation_id: str
    owner_actor: str
    owner_session_ref: str
    owner_session_binding_digest: str
    parent_budget_lease_ref: str
    parent_budget_original_digest: str
    d01_head: VersionedRef
    draft_head: VersionedRef
    draft_digest: str
    root_input_digest: str
    candidate_digest: str
    preset_digest: str
    asset_digest: str
    native_manifest_sha256: str
    native_sha256: str
    initial_transcript_digest: str
    output_projection_digest: str
    graph_read_set_digest: str
    writes: tuple[RootAdoptionWriteV2, ...]
    output_write_set_digest: str
    bundle_digest: str
    phase: str = ROOT_ADOPTION_PHASE_V2
    schema: str = "d11.d04_authored_root_adoption_evidence.v2"

    def __post_init__(self) -> None:
        if self.schema != "d11.d04_authored_root_adoption_evidence.v2":
            raise ValueError("unknown root adoption evidence schema")
        if type(self.namespace) is not NamespaceId:
            raise TypeError("namespace must be NamespaceId")
        if self.phase != ROOT_ADOPTION_PHASE_V2:
            raise ValueError("root adoption phase differs")
        for name in ("operation_id", "owner_actor", "owner_session_ref",
                     "parent_budget_lease_ref"):
            _text(getattr(self, name), name)
        for name in ("d01_head", "draft_head"):
            if type(getattr(self, name)) is not VersionedRef:
                raise TypeError(f"{name} must be VersionedRef")
        for name in (
            "owner_session_binding_digest", "parent_budget_original_digest",
            "draft_digest", "root_input_digest",
            "candidate_digest", "preset_digest", "asset_digest",
            "native_manifest_sha256", "native_sha256", "initial_transcript_digest",
            "output_projection_digest", "graph_read_set_digest",
            "output_write_set_digest", "bundle_digest",
        ):
            _digest(getattr(self, name), name)
        if (type(self.writes) is not tuple or len(self.writes) < 3
                or any(type(item) is not RootAdoptionWriteV2 for item in self.writes)):
            raise ValueError("root adoption requires typed Feeling and Mood writes")
        refs = tuple(item.checkpoint_ref for item in self.writes)
        if refs != tuple(sorted(set(refs))):
            raise ValueError("root writes must be unique and ordered")
        states = tuple(item.state_ref for item in self.writes)
        if len(set(states)) != len(states):
            raise ValueError("root state writes must be unique")
        keys = tuple(AtomKey.from_token(ref) for ref in refs + states)
        if any(NamespaceId.from_key(key) != self.namespace for key in keys):
            raise ValueError("root writes cross namespace")
        kinds = tuple(AtomKey.from_token(ref).type_name for ref in states)
        if kinds.count("d04.mood_field.v1") != 1 or kinds.count("d04.feeling_state.v1") < 2:
            raise ValueError("root requires two Feeling blocks and one independent Mood")
        if self.output_write_set_digest != canonical_digest(self.writes):
            raise ValueError("root write set digest differs")
