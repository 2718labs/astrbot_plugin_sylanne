"""Future-at-encoding D04 baseline and projection receipt *candidates*.

These immutable values bind a proposed historical projection to exact graph
versions and numerical identities. They are neither signed nor adopted. W01
must verify the durable joint receipt, current fence, and all read versions in
its atomic graph transaction before registering or issuing this graph type.
"""

from __future__ import annotations

from dataclasses import dataclass
import math
import re

from ...graph_types import AtomKey, GraphSnapshot
from ...runtime_contracts import canonical_digest


SCHEMA = "d04.encoding_baseline.v2"
PROJECTION_SCHEMA = "d04.encoding_projection_receipt.v2"
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_PERSPECTIVE_TYPES = frozenset({
    "d03.entity_anchor", "d03.role_binding", "d03.self_perspective.v1",
})
_INTERPRETATION_TYPES = frozenset({
    "d07.current_interpretation.v1", "d07.belief_revision.v1",
})


def validate_unissued_encoding_baseline_graph_v2(value: object) -> object:
    """Reserve the graph type until W01 can authenticate an issued original.

    The local candidate types deliberately declare themselves unadopted. A
    generic D04 graph write must not turn either candidate into a source atom.
    """
    raise ValueError("D04 v2 encoding baseline has no installed issuer")


def validate_unissued_projection_receipt_graph_v2(value: object) -> object:
    """Reject unsigned projection candidates at the generic graph boundary."""
    raise ValueError("D04 v2 projection receipt has no installed issuer")


def _text(value: object, name: str) -> str:
    if type(value) is not str or not value.strip():
        raise ValueError(f"{name} must be a nonempty string")
    return value


def _digest(value: object, name: str) -> str:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise ValueError(f"{name} must be a lowercase SHA-256 digest")
    return value


def _finite_nonnegative(value: object, name: str) -> float:
    if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
        raise ValueError(f"{name} must be finite and nonnegative")
    return float(value)


def _interval(value: object, name: str, lower: float) -> tuple[float, float]:
    if type(value) is not tuple or len(value) != 2:
        raise ValueError(f"{name} must be a two-value tuple")
    low, high = value
    if (type(low) not in (int, float) or type(high) not in (int, float)
            or not math.isfinite(low) or not math.isfinite(high)
            or not lower <= low <= high <= 1.0):
        raise ValueError(f"{name} must be ordered within [{lower}, 1]")
    return float(low), float(high)


@dataclass(frozen=True, slots=True)
class ExactGraphRefV2:
    ref: str
    revision: int

    def __post_init__(self) -> None:
        AtomKey.from_token(self.ref)
        if type(self.revision) is not int or self.revision < 1:
            raise ValueError("graph revision must be a positive exact integer")

    @property
    def key(self) -> AtomKey:
        return AtomKey.from_token(self.ref)


def _refs(values: object, name: str, *, required: bool) -> tuple[ExactGraphRefV2, ...]:
    if (type(values) is not tuple or (required and not values)
            or any(type(value) is not ExactGraphRefV2 for value in values)
            or len({value.ref for value in values}) != len(values)):
        raise ValueError(f"{name} must contain unique exact graph refs")
    return values


@dataclass(frozen=True, slots=True)
class ProjectionNumericErrorV2:
    inherited_state_error_2norm: float
    solve_state_error_2norm: float
    salience_readout_error: float
    tone_readout_error: float
    numeric_proof_digest: str

    def __post_init__(self) -> None:
        for name in ("inherited_state_error_2norm", "solve_state_error_2norm",
                     "salience_readout_error", "tone_readout_error"):
            object.__setattr__(self, name, _finite_nonnegative(getattr(self, name), name))
        _digest(self.numeric_proof_digest, "numeric_proof_digest")


@dataclass(frozen=True, slots=True)
class ProjectionMemberV2:
    feeling_version: ExactGraphRefV2
    checkpoint_ref: str
    checkpoint_revision: int

    def __post_init__(self) -> None:
        if (type(self.feeling_version) is not ExactGraphRefV2
                or self.feeling_version.key.type_name != "d04.feeling_state.v1"
                or self.feeling_version.key.owner.kind != "persona"):
            raise ValueError("projection member needs an exact persona feeling version")
        checkpoint = AtomKey.from_token(self.checkpoint_ref)
        if (checkpoint.type_name != "d04.numeric_checkpoint.v1"
                or checkpoint.owner != self.feeling_version.key.owner):
            raise ValueError("projection member checkpoint differs from feeling owner")
        if type(self.checkpoint_revision) is not int or self.checkpoint_revision < 1:
            raise ValueError("projection member needs an exact checkpoint revision")


@dataclass(frozen=True, slots=True)
class EncodingProjectionReceiptCandidateV2:
    """Locally checkable numerical claim; W01 has not authenticated its issuer."""

    input_binding_digest: str
    members: tuple[ProjectionMemberV2, ...]
    component_digest: str
    joint_numeric_receipt_digest: str
    joint_adoption_operation_id: str
    joint_adoption_receipt_digest: str
    projection_policy_ref: str
    projection_policy_version: str
    policy_digest: str
    readout_asset_id: str
    readout_asset_version: str
    readout_asset_sha256: str
    native_manifest_sha256: str
    native_sha256: str
    native_abi_version: int
    full_transcript_sha256: str
    projection_proof_digest: str
    mood_receipt_digest: str | None
    graph_incarnation: str
    graph_revision: int
    graph_epoch: int
    access_epoch: int
    delete_epoch: int
    role_start: float
    role_end: float
    salience_interval: tuple[float, float]
    tone_interval: tuple[float, float]
    numeric_error: ProjectionNumericErrorV2
    schema: str = PROJECTION_SCHEMA
    status: str = "candidate_unadopted"

    def __post_init__(self) -> None:
        if self.schema != PROJECTION_SCHEMA or self.status != "candidate_unadopted":
            raise ValueError("projection receipt cannot claim adoption or issuance")
        if (type(self.members) is not tuple or not self.members
                or any(type(member) is not ProjectionMemberV2 for member in self.members)
                or len({member.feeling_version.ref for member in self.members}) != len(self.members)
                or len({member.checkpoint_ref for member in self.members}) != len(self.members)
                or tuple(member.checkpoint_ref for member in self.members)
                   != tuple(sorted(member.checkpoint_ref for member in self.members))):
            raise ValueError("projection needs a complete unique member set")
        for name in ("input_binding_digest", "component_digest",
                     "joint_numeric_receipt_digest", "joint_adoption_receipt_digest",
                     "policy_digest",
                     "readout_asset_sha256", "native_manifest_sha256", "native_sha256",
                     "full_transcript_sha256", "projection_proof_digest"):
            _digest(getattr(self, name), name)
        if self.mood_receipt_digest is not None:
            raise ValueError("encoding baseline cannot bind recall-time mood evidence")
        for name in ("joint_adoption_operation_id", "projection_policy_ref",
                     "projection_policy_version", "readout_asset_id",
                     "readout_asset_version", "graph_incarnation"):
            _text(getattr(self, name), name)
        if type(self.native_abi_version) is not int or self.native_abi_version != 2:
            raise ValueError("joint projection requires native ABI2")
        for name in ("graph_revision", "graph_epoch", "access_epoch", "delete_epoch"):
            value = getattr(self, name)
            if type(value) is not int or value < 0:
                raise ValueError(f"{name} must be a nonnegative exact integer")
        if (type(self.role_start) not in (int, float)
                or type(self.role_end) not in (int, float)
                or not math.isfinite(self.role_start) or not math.isfinite(self.role_end)
                or self.role_start >= self.role_end):
            raise ValueError("projection role interval must be finite and increasing")
        object.__setattr__(self, "salience_interval", _interval(
            self.salience_interval, "salience_interval", 0.0))
        object.__setattr__(self, "tone_interval", _interval(
            self.tone_interval, "tone_interval", -1.0))
        if type(self.numeric_error) is not ProjectionNumericErrorV2:
            raise TypeError("numeric_error must be typed numerical evidence")

    @property
    def receipt_digest(self) -> str:
        return canonical_digest(self)

    def verify_projection_candidate(self, candidate: object) -> None:
        """Cross-bind the held math result; this does not authenticate W01."""
        from .interval_projection_v2 import D04IntervalProjectionCandidateV2

        if type(candidate) is not D04IntervalProjectionCandidateV2:
            raise TypeError("projection must be a typed D04 interval candidate")
        if (candidate.namespace.as_tuple != (
                self.members[0].feeling_version.key.owner.bot,
                self.members[0].feeling_version.key.owner.persona)
                or candidate.status != "unsigned_hold_for_w01_projection_issuer"
                or candidate.semantic_calibration != "unvalidated"
                or tuple((item.checkpoint_ref, item.checkpoint_revision,
                          item.feeling_ref, item.feeling_revision)
                         for item in candidate.member_bindings)
                   != tuple((item.checkpoint_ref, item.checkpoint_revision,
                             item.feeling_version.ref, item.feeling_version.revision)
                            for item in self.members)
                or tuple((item.key.token, item.revision)
                         for item in candidate.then_feeling_versions)
                   != tuple((item.feeling_version.ref, item.feeling_version.revision)
                            for item in self.members)
                or candidate.component_digest != self.component_digest
                or candidate.numeric_receipt_digest != self.joint_numeric_receipt_digest
                or candidate.policy_id != self.projection_policy_ref
                or candidate.policy_version != self.projection_policy_version
                or candidate.policy_digest != self.policy_digest
                or getattr(candidate, "mood_receipt_digest", None) is not None
                or candidate.readout_id != self.readout_asset_id
                or candidate.readout_version != self.readout_asset_version
                or candidate.readout_sha256 != self.readout_asset_sha256
                or candidate.proof_digest != self.projection_proof_digest
                or candidate.graph_incarnation != self.graph_incarnation
                or candidate.graph_revision != self.graph_revision
                or candidate.graph_epoch != self.graph_epoch
                or candidate.access_epoch != self.access_epoch
                or candidate.delete_epoch != self.delete_epoch
                or candidate.role_start != self.role_start
                or candidate.role_end != self.role_end
                or candidate.salience_interval != self.salience_interval
                or candidate.tone_interval != self.tone_interval):
            raise ValueError("projection receipt differs from held interval math")


def encoding_input_binding_digest_v2(
    baseline_id: str, source_versions: tuple[ExactGraphRefV2, ...],
    perspective_version: ExactGraphRefV2,
    interpretation_versions: tuple[ExactGraphRefV2, ...],
    then_feeling_versions: tuple[ExactGraphRefV2, ...], as_known_at: float,
) -> str:
    """Bind a projection to the exact historical inputs, including time."""
    return canonical_digest({
        "schema": SCHEMA,
        "baseline_id": baseline_id,
        "sources": tuple((item.ref, item.revision) for item in source_versions),
        "perspective": (perspective_version.ref, perspective_version.revision),
        "interpretations": tuple((item.ref, item.revision)
                                 for item in interpretation_versions),
        "then_feelings": tuple((item.ref, item.revision)
                               for item in then_feeling_versions),
        "as_known_at": as_known_at,
    })


@dataclass(frozen=True, slots=True)
class EncodingBaselineCandidateV2:
    """Immutable future-at-encoding candidate, never a current product read."""

    baseline_id: str
    source_versions: tuple[ExactGraphRefV2, ...]
    perspective_version: ExactGraphRefV2
    interpretation_versions: tuple[ExactGraphRefV2, ...]
    then_feeling_versions: tuple[ExactGraphRefV2, ...]
    as_known_at: float
    projection_receipt: EncodingProjectionReceiptCandidateV2 | None
    unknown_reasons: tuple[str, ...] = ()
    schema: str = SCHEMA
    semantic_calibration: str = "unvalidated"
    status: str = "candidate_unadopted"

    def __post_init__(self) -> None:
        if (self.schema != SCHEMA or self.semantic_calibration != "unvalidated"
                or self.status != "candidate_unadopted"):
            raise ValueError("baseline cannot claim semantic calibration or adoption")
        _text(self.baseline_id, "baseline_id")
        sources = _refs(self.source_versions, "source_versions", required=True)
        if any(item.key.type_name != "memory.source" or item.key.owner.kind != "event"
               or item.key.name != "record" for item in sources):
            raise ValueError("source_versions must use canonical memory source keys")
        if type(self.perspective_version) is not ExactGraphRefV2:
            raise TypeError("perspective_version must be an exact graph ref")
        perspective = self.perspective_version.key
        if (perspective.type_name not in _PERSPECTIVE_TYPES
                or perspective.owner.kind not in {"persona", "scene"}):
            raise ValueError("perspective_version has unsupported graph type")
        interpretations = _refs(self.interpretation_versions,
                                "interpretation_versions", required=False)
        feelings = _refs(self.then_feeling_versions,
                         "then_feeling_versions", required=False)
        if any(item.key.type_name not in _INTERPRETATION_TYPES
               or item.key.owner.kind not in {"activity", "persona"}
               for item in interpretations):
            raise ValueError("interpretation_versions have unsupported graph type")
        if any(item.key.type_name != "d04.feeling_state.v1"
               or item.key.owner.kind != "persona" for item in feelings):
            raise ValueError("then_feeling_versions must be persona feeling states")
        namespace = {(item.key.owner.bot, item.key.owner.persona) for item in (
            *sources, self.perspective_version, *interpretations, *feelings,
        )}
        if len(namespace) != 1:
            raise ValueError("baseline refs must share one namespace")
        if type(self.as_known_at) not in (int, float) or not math.isfinite(self.as_known_at):
            raise ValueError("as_known_at must be finite")
        object.__setattr__(self, "as_known_at", float(self.as_known_at))
        if (type(self.unknown_reasons) is not tuple
                or len(set(self.unknown_reasons)) != len(self.unknown_reasons)):
            raise ValueError("unknown_reasons must be a unique tuple")
        for reason in self.unknown_reasons:
            _text(reason, "unknown reason")
        if self.projection_receipt is None:
            if not self.unknown_reasons:
                raise ValueError("missing projection requires an unknown reason")
        elif (type(self.projection_receipt) is not EncodingProjectionReceiptCandidateV2
              or self.unknown_reasons
              or tuple(member.feeling_version for member in self.projection_receipt.members)
              != feelings
              or self.projection_receipt.input_binding_digest !=
              encoding_input_binding_digest_v2(
                  self.baseline_id, sources, self.perspective_version,
                  interpretations, feelings, self.as_known_at)):
            raise ValueError("projection receipt does not bind exact baseline inputs")

    @property
    def salience_interval(self) -> tuple[float, float] | None:
        return None if self.projection_receipt is None else self.projection_receipt.salience_interval

    @property
    def tone_interval(self) -> tuple[float, float] | None:
        return None if self.projection_receipt is None else self.projection_receipt.tone_interval

    def verify_refs_in_snapshot(self, snapshot: GraphSnapshot) -> None:
        """Pure reference check; a supplied snapshot is not W01's live fence."""
        if type(snapshot) is not GraphSnapshot:
            raise TypeError("reference verification requires GraphSnapshot")
        for item in (*self.source_versions, self.perspective_version,
                     *self.interpretation_versions, *self.then_feeling_versions):
            atom = snapshot.get(item.key)
            if atom is None or not atom.valid or atom.revision != item.revision:
                raise ValueError("baseline graph ref is absent, invalid, or stale")


__all__ = [
    "SCHEMA", "PROJECTION_SCHEMA", "ExactGraphRefV2", "ProjectionNumericErrorV2",
    "ProjectionMemberV2",
    "EncodingProjectionReceiptCandidateV2", "EncodingBaselineCandidateV2",
    "encoding_input_binding_digest_v2",
    "validate_unissued_encoding_baseline_graph_v2",
    "validate_unissued_projection_receipt_graph_v2",
]
