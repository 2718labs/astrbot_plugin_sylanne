"""Pure D04 affect semantics.

The types in this module are candidates and projections.  They do not own a
database, retrieve memories, choose actions, or certify a numerical solve.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
import math

from ...graph_types import AtomKey, GraphSnapshot, GraphVersion, GraphWrite, Owner, TypeSpec
from ...runtime_contracts import (
    CommandEnvelope,
    DependencySet,
    DomainProposal,
    ProviderDescriptor,
    RUNTIME_SCHEMA,
    schema_hash,
)


def _nonempty(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} must be a nonempty string")
    return value


def _finite(value: object, label: str) -> float:
    if type(value) not in (int, float) or not math.isfinite(value):
        raise ValueError(f"{label} must be finite")
    return float(value)


def _unit(value: object, label: str) -> float:
    result = _finite(value, label)
    if not 0.0 <= result <= 1.0:
        raise ValueError(f"{label} must be in [0, 1]")
    return result


def _refs(values: object, label: str, *, allow_empty: bool = False) -> tuple[str, ...]:
    if not isinstance(values, tuple) or (not allow_empty and not values):
        raise ValueError(f"{label} must be a {'nonempty ' if not allow_empty else ''}tuple")
    if len(values) != len(set(values)):
        raise ValueError(f"{label} must not contain duplicates")
    for value in values:
        _nonempty(value, label)
    return values


def _coordinates(values: object, label: str, *, allow_empty: bool = False) -> tuple[tuple[str, float], ...]:
    if not isinstance(values, tuple) or (not allow_empty and not values):
        raise ValueError(f"{label} must be a {'nonempty ' if not allow_empty else ''}tuple")
    result: list[tuple[str, float]] = []
    for item in values:
        if not isinstance(item, tuple) or len(item) != 2:
            raise ValueError(f"{label} entries must be (axis, value) pairs")
        axis, value = item
        numeric = _finite(value, f"{label} value")
        if not -1.0 <= numeric <= 1.0:
            raise ValueError(f"{label} values must be in [-1, 1] for the alpha1 normalized basis")
        result.append((_nonempty(axis, f"{label} axis"), numeric))
    if len({axis for axis, _ in result}) != len(result):
        raise ValueError(f"{label} axes must be unique")
    return tuple(result)


def _interval(value: object, label: str) -> tuple[float, float]:
    if not isinstance(value, tuple) or len(value) != 2:
        raise ValueError(f"{label} must be a two-value tuple")
    low, high = _finite(value[0], f"{label} low"), _finite(value[1], f"{label} high")
    if low > high:
        raise ValueError(f"{label} low exceeds high")
    return low, high


def _object_payload(payload: object) -> dict:
    if not isinstance(payload, dict):
        raise TypeError("D04 graph payload must be an object")
    return dict(payload)


def _tuple_field(payload: dict, *fields: str) -> dict:
    decoded = dict(payload)
    for field_name in fields:
        if field_name in decoded and isinstance(decoded[field_name], list):
            decoded[field_name] = tuple(decoded[field_name])
    return decoded


def _decode_appraisal(payload: object) -> AppraisalBundle:
    decoded = _tuple_field(
        _object_payload(payload), "meaning_facets", "competing_interpretation_refs", "source_refs",
    )
    if "meaning_facets" in decoded:
        decoded["meaning_facets"] = tuple(
            MeaningFacet(**_tuple_field(_object_payload(item), "unknown_fields", "source_refs"))
            if not isinstance(item, MeaningFacet) else item
            for item in decoded["meaning_facets"]
        )
    return AppraisalBundle(**decoded)


def _decode_feeling(payload: object) -> FeelingState:
    decoded = _tuple_field(
        _object_payload(payload), "coordinates", "meaning_refs", "interpretation_refs",
        "active_driver_refs", "historical_source_refs",
    )
    if "coordinates" in decoded:
        decoded["coordinates"] = tuple(tuple(item) for item in decoded["coordinates"])
    return FeelingState(**decoded)


def _decode_mood(payload: object) -> MoodField:
    decoded = _tuple_field(_object_payload(payload), "coordinates", "source_refs")
    if "coordinates" in decoded:
        decoded["coordinates"] = tuple(tuple(item) for item in decoded["coordinates"])
    return MoodField(**decoded)


def _decode_understanding(payload: object) -> SelfUnderstanding:
    return SelfUnderstanding(**_tuple_field(
        _object_payload(payload), "description_hypotheses", "reason_hypotheses", "unknown_parts",
        "reflection_source_refs",
    ))


def _decode_regulation_attempt(payload: object) -> RegulationAttempt:
    return RegulationAttempt(**_tuple_field(_object_payload(payload), "basis_refs", "expected_effect_refs"))


def _decode_regulation_observation(payload: object) -> RegulationObservation:
    decoded = _tuple_field(_object_payload(payload), "observed_effects", "unknown_effects")
    if "observed_effects" in decoded:
        decoded["observed_effects"] = tuple(tuple(item) for item in decoded["observed_effects"])
    return RegulationObservation(**decoded)


def _decode_recollection_experience(payload: object) -> RecollectionExperience:
    return RecollectionExperience(**_tuple_field(
        _object_payload(payload), "memory_source_refs", "mood_source_refs",
        "salience_interval", "tone_interval",
    ))


@dataclass(frozen=True)
class AffectAxis:
    axis_id: str
    unit: str
    meaning: str

    def __post_init__(self) -> None:
        _nonempty(self.axis_id, "axis_id")
        if self.unit != "normalized":
            raise ValueError("alpha1 affect axes must use normalized units")
        _nonempty(self.meaning, "meaning")


@dataclass(frozen=True)
class AffectScheme:
    schema: str
    scheme_version: str
    operator_version: str
    parameter_version: str
    coupling_version: str
    axes: tuple[AffectAxis, ...]
    parameter_bounds: tuple[tuple[str, float, float], ...]

    def __post_init__(self) -> None:
        if self.schema != "d04.affect.scheme.v1":
            raise ValueError("unsupported D04 affect scheme")
        for name in ("scheme_version", "operator_version", "parameter_version", "coupling_version"):
            _nonempty(getattr(self, name), name)
        axes = tuple(self.axes)
        if not axes or any(not isinstance(axis, AffectAxis) for axis in axes):
            raise ValueError("axes must contain AffectAxis values")
        if len({axis.axis_id for axis in axes}) != len(axes):
            raise ValueError("affect axes must be unique")
        object.__setattr__(self, "axes", axes)
        bounds: list[tuple[str, float, float]] = []
        for item in self.parameter_bounds:
            if not isinstance(item, tuple) or len(item) != 3:
                raise ValueError("parameter bounds must be (name, low, high)")
            name, low, high = item
            low_value, high_value = _finite(low, "parameter lower bound"), _finite(high, "parameter upper bound")
            if low_value > high_value:
                raise ValueError("parameter lower bound exceeds upper bound")
            bounds.append((_nonempty(name, "parameter name"), low_value, high_value))
        if len({name for name, _, _ in bounds}) != len(bounds):
            raise ValueError("parameter bounds must have unique names")
        object.__setattr__(self, "parameter_bounds", tuple(bounds))


@dataclass(frozen=True)
class MeaningFacet:
    facet_id: str
    target_ref: str
    interpretation_ref: str
    value_ref: str
    responsibility_hypothesis: str
    controllability: float | None
    anticipated_impact: float | None
    relation_meaning: str | None
    self_meaning: str | None
    confidence: float | None
    unknown_fields: tuple[str, ...]
    source_refs: tuple[str, ...]

    def __post_init__(self) -> None:
        for name in ("facet_id", "target_ref", "interpretation_ref", "value_ref", "responsibility_hypothesis"):
            _nonempty(getattr(self, name), name)
        for name in ("controllability", "anticipated_impact", "confidence"):
            value = getattr(self, name)
            if value is not None:
                object.__setattr__(self, name, _unit(value, name))
        for name in ("relation_meaning", "self_meaning"):
            value = getattr(self, name)
            if value is not None:
                _nonempty(value, name)
        object.__setattr__(self, "unknown_fields", _refs(self.unknown_fields, "unknown_fields", allow_empty=True))
        recognized_unknowns = {
            "responsibility_hypothesis", "controllability", "anticipated_impact", "relation_meaning",
            "self_meaning", "confidence",
        }
        if not set(self.unknown_fields) <= recognized_unknowns:
            raise ValueError("unknown_fields contains an unsupported appraisal dimension")
        for name in ("controllability", "anticipated_impact", "confidence"):
            if (getattr(self, name) is None) != (name in self.unknown_fields):
                raise ValueError(f"{name} must be either known or explicitly unknown")
        object.__setattr__(self, "source_refs", _refs(self.source_refs, "source_refs"))


@dataclass(frozen=True)
class AppraisalBundle:
    appraisal_id: str
    event_ref: str
    target_ref: str
    meaning_facets: tuple[MeaningFacet, ...]
    competing_interpretation_refs: tuple[str, ...]
    source_refs: tuple[str, ...]
    source_family: str
    content_reality: str
    contribution_key: str
    learned_at: float

    def __post_init__(self) -> None:
        for name in ("appraisal_id", "event_ref", "target_ref", "contribution_key"):
            _nonempty(getattr(self, name), name)
        facets = tuple(self.meaning_facets)
        if not facets or any(not isinstance(item, MeaningFacet) for item in facets):
            raise ValueError("meaning_facets must contain MeaningFacet values")
        if any(item.target_ref != self.target_ref for item in facets):
            raise ValueError("meaning facet target differs from appraisal target")
        if len({item.facet_id for item in facets}) != len(facets):
            raise ValueError("meaning facet IDs must be unique")
        object.__setattr__(self, "meaning_facets", facets)
        object.__setattr__(self, "competing_interpretation_refs", _refs(
            self.competing_interpretation_refs, "competing_interpretation_refs", allow_empty=True,
        ))
        object.__setattr__(self, "source_refs", _refs(self.source_refs, "source_refs"))
        if any(not set(facet.source_refs) <= set(self.source_refs) for facet in facets):
            raise ValueError("meaning facet sources must be covered by appraisal sources")
        if not {facet.interpretation_ref for facet in facets} <= set(self.competing_interpretation_refs):
            raise ValueError("active facet interpretations must remain in the competing interpretation set")
        if self.source_family not in {"observed", "reported", "authored", "simulated", "derived"}:
            raise ValueError("unsupported source_family")
        if self.content_reality not in {
            "external_observation", "external_report", "authored_content", "simulation", "inference"
        }:
            raise ValueError("unsupported content_reality")
        if self.source_family in {"authored", "simulated"} and self.content_reality in {
            "external_observation", "external_report",
        }:
            raise ValueError("authored or simulated appraisal sources cannot claim external reality")
        object.__setattr__(self, "learned_at", _finite(self.learned_at, "learned_at"))


@dataclass(frozen=True)
class FeelingState:
    process_id: str
    target_ref: str
    basis_version: str
    operator_version: str
    coordinates: tuple[tuple[str, float], ...]
    meaning_refs: tuple[str, ...]
    interpretation_refs: tuple[str, ...]
    active_driver_refs: tuple[str, ...]
    historical_source_refs: tuple[str, ...]
    parameter_version: str
    coupling_version: str
    cursor: float
    revision: int = 1

    def __post_init__(self) -> None:
        for name in ("process_id", "target_ref", "basis_version", "operator_version", "parameter_version", "coupling_version"):
            _nonempty(getattr(self, name), name)
        object.__setattr__(self, "coordinates", _coordinates(self.coordinates, "coordinates"))
        for name in ("meaning_refs", "interpretation_refs", "active_driver_refs", "historical_source_refs"):
            object.__setattr__(self, name, _refs(getattr(self, name), name, allow_empty=name == "active_driver_refs"))
        object.__setattr__(self, "cursor", _finite(self.cursor, "cursor"))
        if type(self.revision) is not int or self.revision < 1:
            raise ValueError("revision must be a positive exact integer")


@dataclass(frozen=True)
class MoodField:
    mood_id: str
    basis_version: str
    coordinates: tuple[tuple[str, float], ...]
    source_refs: tuple[str, ...]
    parameter_version: str
    coupling_version: str
    cursor: float
    revision: int = 1

    def __post_init__(self) -> None:
        for name in ("mood_id", "basis_version", "parameter_version", "coupling_version"):
            _nonempty(getattr(self, name), name)
        object.__setattr__(self, "coordinates", _coordinates(self.coordinates, "coordinates"))
        object.__setattr__(self, "source_refs", _refs(self.source_refs, "source_refs"))
        object.__setattr__(self, "cursor", _finite(self.cursor, "cursor"))
        if type(self.revision) is not int or self.revision < 1:
            raise ValueError("revision must be a positive exact integer")


@dataclass(frozen=True)
class AffectCoupling:
    coupling_id: str
    version: str
    mood_axis: str
    feeling_axis: str
    interpretation_gain: float
    recall_salience_gain: float
    recall_tone_gain: float

    def __post_init__(self) -> None:
        for name in ("coupling_id", "version", "mood_axis", "feeling_axis"):
            _nonempty(getattr(self, name), name)
        for name in ("interpretation_gain", "recall_salience_gain", "recall_tone_gain"):
            object.__setattr__(self, name, _finite(getattr(self, name), name))


@dataclass(frozen=True)
class RecollectionInfluence:
    memory_ref: str
    mood_ref: str
    salience_interval: tuple[float, float]
    tone_interval: tuple[float, float]
    evidence_weight_delta: float
    source_refs: tuple[str, ...]
    coupling_version: str

    def __post_init__(self) -> None:
        for name in ("memory_ref", "mood_ref", "coupling_version"):
            _nonempty(getattr(self, name), name)
        object.__setattr__(self, "salience_interval", _interval(self.salience_interval, "salience_interval"))
        object.__setattr__(self, "tone_interval", _interval(self.tone_interval, "tone_interval"))
        object.__setattr__(self, "evidence_weight_delta", _finite(self.evidence_weight_delta, "evidence_weight_delta"))
        object.__setattr__(self, "source_refs", _refs(self.source_refs, "source_refs"))


@dataclass(frozen=True)
class RecollectionExperience:
    experience_id: str
    activity_id: str
    recollection_ref: str
    memory_ref: str
    memory_source_refs: tuple[str, ...]
    mood_ref: str
    mood_source_refs: tuple[str, ...]
    salience_interval: tuple[float, float]
    tone_interval: tuple[float, float]
    coupling_id: str
    coupling_version: str
    evidence_weight_delta: float = 0.0

    def __post_init__(self) -> None:
        for name in ("experience_id", "activity_id", "recollection_ref", "memory_ref",
                     "mood_ref", "coupling_id", "coupling_version"):
            _nonempty(getattr(self, name), name)
        for name in ("memory_source_refs", "mood_source_refs"):
            object.__setattr__(self, name, _refs(getattr(self, name), name))
        salience = _interval(self.salience_interval, "salience_interval")
        tone = _interval(self.tone_interval, "tone_interval")
        if not 0.0 <= salience[0] <= salience[1] <= 1.0:
            raise ValueError("salience_interval must be within [0, 1]")
        if not -1.0 <= tone[0] <= tone[1] <= 1.0:
            raise ValueError("tone_interval must be within [-1, 1]")
        object.__setattr__(self, "salience_interval", salience)
        object.__setattr__(self, "tone_interval", tone)
        if _finite(self.evidence_weight_delta, "evidence_weight_delta") != 0.0:
            raise ValueError("recollection experience cannot add evidence weight")


@dataclass(frozen=True)
class InterpretationInfluence:
    interpretation_ref: str
    mood_ref: str
    sensitivity_interval: tuple[float, float]
    evidence_weight_delta: float
    source_refs: tuple[str, ...]
    coupling_version: str

    def __post_init__(self) -> None:
        for name in ("interpretation_ref", "mood_ref", "coupling_version"):
            _nonempty(getattr(self, name), name)
        object.__setattr__(self, "sensitivity_interval", _interval(
            self.sensitivity_interval, "sensitivity_interval",
        ))
        object.__setattr__(self, "evidence_weight_delta", _finite(
            self.evidence_weight_delta, "evidence_weight_delta",
        ))
        object.__setattr__(self, "source_refs", _refs(self.source_refs, "source_refs"))


@dataclass(frozen=True)
class SelfUnderstanding:
    understanding_id: str
    feeling_ref: str
    description_hypotheses: tuple[str, ...]
    reason_hypotheses: tuple[str, ...]
    unknown_parts: tuple[str, ...]
    confidence: float
    reflection_source_refs: tuple[str, ...]
    revision: int = 1

    def __post_init__(self) -> None:
        _nonempty(self.understanding_id, "understanding_id")
        _nonempty(self.feeling_ref, "feeling_ref")
        for name in ("description_hypotheses", "reason_hypotheses", "unknown_parts", "reflection_source_refs"):
            object.__setattr__(self, name, _refs(getattr(self, name), name, allow_empty=name == "unknown_parts"))
        object.__setattr__(self, "confidence", _unit(self.confidence, "confidence"))
        if type(self.revision) is not int or self.revision < 1:
            raise ValueError("revision must be a positive exact integer")


@dataclass(frozen=True)
class RegulationAttempt:
    attempt_id: str
    strategy_version: str
    target_process_ref: str
    motivation_ref: str
    basis_refs: tuple[str, ...]
    resource_reservation_ref: str
    expected_effect_refs: tuple[str, ...]
    status: str

    def __post_init__(self) -> None:
        for name in ("attempt_id", "strategy_version", "target_process_ref", "motivation_ref", "resource_reservation_ref"):
            _nonempty(getattr(self, name), name)
        object.__setattr__(self, "basis_refs", _refs(self.basis_refs, "basis_refs"))
        object.__setattr__(self, "expected_effect_refs", _refs(self.expected_effect_refs, "expected_effect_refs"))
        if self.status not in {"planned", "executing", "pending_confirmation", "cancelled"}:
            raise ValueError("unsupported regulation attempt status")


@dataclass(frozen=True)
class RegulationObservation:
    attempt_id: str
    execution_receipt_ref: str
    observed_effects: tuple[tuple[str, float], ...]
    unknown_effects: tuple[str, ...]
    cost_settlement_ref: str
    status: str

    def __post_init__(self) -> None:
        for name in ("attempt_id", "execution_receipt_ref", "cost_settlement_ref"):
            _nonempty(getattr(self, name), name)
        object.__setattr__(self, "observed_effects", _coordinates(
            self.observed_effects, "observed_effects", allow_empty=True,
        ))
        object.__setattr__(self, "unknown_effects", _refs(self.unknown_effects, "unknown_effects", allow_empty=True))
        if self.status not in {"complete", "partial", "failed", "pending_confirmation"}:
            raise ValueError("unsupported regulation observation status")


@dataclass(frozen=True)
class NumericCertificate:
    abi_version: int
    certificate_flags: int
    operator_version: str
    parameter_version: str
    coupling_version: str
    from_cursor: float
    to_cursor: float
    residual_error_bound: float
    time_error_bound: float
    truncation_error_bound: float
    assumptions_valid: bool
    stopping_reason: str

    def __post_init__(self) -> None:
        if type(self.abi_version) is not int or self.abi_version < 1:
            raise ValueError("abi_version must be a positive exact integer")
        if type(self.certificate_flags) is not int or self.certificate_flags < 0:
            raise ValueError("certificate_flags must be a nonnegative exact integer")
        for name in ("operator_version", "parameter_version", "coupling_version", "stopping_reason"):
            _nonempty(getattr(self, name), name)
        for name in ("from_cursor", "to_cursor", "residual_error_bound", "time_error_bound", "truncation_error_bound"):
            value = _finite(getattr(self, name), name)
            if "error_bound" in name and value < 0:
                raise ValueError(f"{name} must be nonnegative")
            object.__setattr__(self, name, value)
        if self.to_cursor < self.from_cursor:
            raise ValueError("certificate cursor interval is reversed")
        if type(self.assumptions_valid) is not bool:
            raise ValueError("assumptions_valid must be bool")


@dataclass(frozen=True)
class AdvanceRequirements:
    max_residual_error: float
    max_time_error: float
    max_truncation_error: float
    required_flags: int

    def __post_init__(self) -> None:
        for name in ("max_residual_error", "max_time_error", "max_truncation_error"):
            value = _finite(getattr(self, name), name)
            if value < 0:
                raise ValueError(f"{name} must be nonnegative")
            object.__setattr__(self, name, value)
        if type(self.required_flags) is not int or self.required_flags <= 0:
            raise ValueError("required_flags must be a positive exact bit mask")


@dataclass(frozen=True)
class SemanticDriveRule:
    """A declared semantic-to-coordinate mapping, never a label transition."""

    axis_id: str
    facet_field: str
    gain: float

    def __post_init__(self) -> None:
        _nonempty(self.axis_id, "axis_id")
        if self.facet_field not in {"anticipated_impact", "controllability"}:
            raise ValueError("facet_field must be an implemented semantic dimension")
        object.__setattr__(self, "gain", _finite(self.gain, "gain"))


@dataclass(frozen=True)
class AffectCandidate:
    """A replayable, uncommitted affect result.

    This is deliberately not a graph state.  It records the exact committed
    inputs it was derived from, but cannot assert that its states happened.
    D11 must still validate and commit a proposal after ``adopt_candidate``.
    """

    candidate_id: str
    replay_key: str
    committed_parent_ref: str
    source_refs: tuple[str, ...]
    from_cursor: float
    to_cursor: float
    feeling: FeelingState
    mood: MoodField
    regulation_observation_ref: str | None
    reflection_source_refs: tuple[str, ...]
    status: str = "candidate"

    def __post_init__(self) -> None:
        for name in ("candidate_id", "replay_key", "committed_parent_ref"):
            _nonempty(getattr(self, name), name)
        object.__setattr__(self, "source_refs", _refs(self.source_refs, "source_refs"))
        object.__setattr__(self, "reflection_source_refs", _refs(
            self.reflection_source_refs, "reflection_source_refs", allow_empty=True,
        ))
        if not isinstance(self.feeling, FeelingState) or not isinstance(self.mood, MoodField):
            raise TypeError("candidate must contain D04 feeling and mood values")
        object.__setattr__(self, "from_cursor", _finite(self.from_cursor, "from_cursor"))
        object.__setattr__(self, "to_cursor", _finite(self.to_cursor, "to_cursor"))
        if self.to_cursor <= self.from_cursor:
            raise ValueError("candidate interval must advance time")
        if self.feeling.cursor != self.to_cursor or self.mood.cursor != self.to_cursor:
            raise ValueError("candidate states must end at candidate to_cursor")
        if self.regulation_observation_ref is not None:
            _nonempty(self.regulation_observation_ref, "regulation_observation_ref")
        if self.status != "candidate":
            raise ValueError("only an uncommitted candidate may be constructed here")


@dataclass(frozen=True)
class CandidateRejection:
    candidate_id: str
    replay_key: str
    reason: str

    def __post_init__(self) -> None:
        for name in ("candidate_id", "replay_key", "reason"):
            _nonempty(getattr(self, name), name)


@dataclass(frozen=True)
class CorrectionResult:
    current_state: FeelingState
    invalidated_driver_refs: tuple[str, ...]
    replacement_appraisal_ref: str
    correction_source_ref: str
    learned_at: float
    historical_feeling_preserved: bool

    def __post_init__(self) -> None:
        if not isinstance(self.current_state, FeelingState):
            raise TypeError("current_state must be FeelingState")
        object.__setattr__(self, "invalidated_driver_refs", _refs(
            self.invalidated_driver_refs, "invalidated_driver_refs",
        ))
        _nonempty(self.replacement_appraisal_ref, "replacement_appraisal_ref")
        _nonempty(self.correction_source_ref, "correction_source_ref")
        object.__setattr__(self, "learned_at", _finite(self.learned_at, "learned_at"))
        if type(self.historical_feeling_preserved) is not bool:
            raise ValueError("historical_feeling_preserved must be bool")


class AffectProvider:
    """Pure D04 semantics; persistence and numerical solving stay external."""

    def __init__(self, *, active_scheme: AffectScheme | None = None) -> None:
        if active_scheme is not None and not isinstance(active_scheme, AffectScheme):
            raise TypeError("active_scheme must be an AffectScheme")
        self._active_scheme = active_scheme

    @property
    def descriptor(self) -> ProviderDescriptor:
        return ProviderDescriptor(
            provider_id="d04.affect",
            contract_version=RUNTIME_SCHEMA,
            request_schema_hash=schema_hash({"domain": "d04", "proposal": 1}),
            response_schema_hash=schema_hash({"domain": "d04", "affect": 1}),
            owner_capabilities=("persona", "event"),
            supported_modalities=("structured",),
            supported_purposes=("appraise", "regulate", "interpret", "project"),
            supported_platforms=("runtime",),
            timeout_mode="bounded",
            cancellation_mode="cooperative",
            idempotency_mode="operation_id",
            cost_reporting_mode="actual_or_unconfirmed",
            health_capabilities=("validate",),
            recovery_capabilities=("query_operation",),
        )

    def register_types(self) -> tuple[str, ...]:
        return (
            "d04.appraisal_bundle.v1",
            "d04.feeling_state.v1",
            "d04.mood_field.v1",
            "d04.self_understanding.v1",
            "d04.regulation_attempt.v1",
            "d04.regulation_observation.v1",
            "d04.recollection_experience.v1",
        )

    def type_specs(self) -> tuple[TypeSpec, ...]:
        definitions = (
            ("d04.appraisal_bundle.v1", ("event",), "state", _decode_appraisal),
            ("d04.feeling_state.v1", ("persona",), "state", _decode_feeling),
            ("d04.mood_field.v1", ("persona",), "state", _decode_mood),
            ("d04.self_understanding.v1", ("persona",), "state", _decode_understanding),
            ("d04.regulation_attempt.v1", ("activity",), "state", _decode_regulation_attempt),
            ("d04.regulation_observation.v1", ("activity",), "state", _decode_regulation_observation),
            ("d04.recollection_experience.v1", ("activity",), "source", _decode_recollection_experience),
        )
        return tuple(
            TypeSpec(
                name=name,
                owner_kinds=owner_kinds,
                storage_role=storage_role,
                validator=validator,
                immutable=name == "d04.recollection_experience.v1",
                writer_domain="d04",
                schema_hash=schema_hash({"type": name, "version": 1, "writer_domain": "d04"}),
            )
            for name, owner_kinds, storage_role, validator in definitions
        )

    def compile_scheme(self, draft: AffectScheme, snapshot: object = None) -> AffectScheme:
        if not isinstance(draft, AffectScheme):
            raise TypeError("draft must be AffectScheme")
        return draft

    def prepare_appraisal(self, appraisal: AppraisalBundle) -> AppraisalBundle:
        if not isinstance(appraisal, AppraisalBundle):
            raise TypeError("appraisal must be AppraisalBundle")
        return appraisal

    def proposal_for(
        self,
        envelope: CommandEnvelope,
        *,
        typed_writes: tuple[GraphWrite, ...],
        dependencies: DependencySet,
        contribution_keys: tuple[str, ...],
        required_bundle_parts: tuple[str, ...],
    ) -> DomainProposal:
        if not isinstance(envelope, CommandEnvelope):
            raise TypeError("envelope must be CommandEnvelope")
        if not isinstance(dependencies, DependencySet):
            raise TypeError("dependencies must be DependencySet")
        return DomainProposal(
            domain="d04",
            proposal_schema="d04.proposal.v1",
            proposal_schema_hash=self.descriptor.request_schema_hash,
            envelope=envelope,
            typed_writes=typed_writes,
            dependencies=dependencies,
            contribution_keys=contribution_keys,
            required_bundle_parts=required_bundle_parts,
        )

    def build_feeling(
        self,
        appraisal: AppraisalBundle,
        scheme: AffectScheme,
        *,
        process_id: str,
        coordinates: tuple[tuple[str, float], ...],
        cursor: float,
    ) -> FeelingState:
        if not isinstance(appraisal, AppraisalBundle) or not isinstance(scheme, AffectScheme):
            raise TypeError("appraisal and scheme must be D04 contract values")
        if not coordinates:
            if any(facet.unknown_fields for facet in appraisal.meaning_facets):
                raise ValueError("unknown appraisal cannot be encoded as a neutral feeling")
            raise ValueError("a feeling candidate needs at least one declared coordinate")
        coordinate_values = _coordinates(coordinates, "coordinates")
        registered = {axis.axis_id for axis in scheme.axes}
        if any(axis not in registered for axis, _ in coordinate_values):
            raise ValueError("feeling coordinate is not registered by the active scheme")
        return FeelingState(
            process_id=_nonempty(process_id, "process_id"),
            target_ref=appraisal.target_ref,
            basis_version=scheme.scheme_version,
            operator_version=scheme.operator_version,
            coordinates=coordinate_values,
            meaning_refs=tuple(facet.facet_id for facet in appraisal.meaning_facets),
            interpretation_refs=tuple(dict.fromkeys(facet.interpretation_ref for facet in appraisal.meaning_facets)),
            active_driver_refs=(appraisal.contribution_key,),
            historical_source_refs=appraisal.source_refs,
            parameter_version=scheme.parameter_version,
            coupling_version=scheme.coupling_version,
            cursor=_finite(cursor, "cursor"),
        )

    def propose_mixed_update(
        self,
        *,
        candidate_id: str,
        replay_key: str,
        committed_parent_ref: str,
        appraisal: AppraisalBundle,
        scheme: AffectScheme,
        current_feeling: FeelingState,
        current_mood: MoodField,
        rules: tuple[SemanticDriveRule, ...],
        recovery_rate: float,
        to_cursor: float,
        recollection: RecollectionInfluence | None = None,
        interpretation: InterpretationInfluence | None = None,
        regulation: RegulationObservation | None = None,
        regulation_observation_ref: str | None = None,
        reflection_source_refs: tuple[str, ...] = (),
    ) -> AffectCandidate:
        """Assemble a deterministic candidate from qualified semantic inputs.

        The exponential recovery below is an ordinary f64 *candidate* model.
        It is useful for replay and for handing a proposed interval to the
        native solver, but it has no certificate and therefore no commit power.
        """
        if not all(isinstance(value, expected) for value, expected in (
            (appraisal, AppraisalBundle), (scheme, AffectScheme),
            (current_feeling, FeelingState), (current_mood, MoodField),
        )):
            raise TypeError("mixed update requires D04 appraisal, scheme, feeling, and mood")
        if not isinstance(rules, tuple) or not rules or any(not isinstance(rule, SemanticDriveRule) for rule in rules):
            raise ValueError("mixed update needs declared semantic drive rules")
        if current_feeling.cursor != current_mood.cursor:
            raise ValueError("feeling and mood must share one committed time cursor")
        if (current_feeling.basis_version, current_feeling.operator_version,
                current_feeling.parameter_version, current_feeling.coupling_version) != (
                    scheme.scheme_version, scheme.operator_version,
                    scheme.parameter_version, scheme.coupling_version,
                ):
            raise ValueError("current feeling versions differ from the active scheme")
        if (current_mood.basis_version, current_mood.parameter_version, current_mood.coupling_version) != (
            scheme.scheme_version, scheme.parameter_version, scheme.coupling_version,
        ):
            raise ValueError("current mood versions differ from the active scheme")
        registered = {axis.axis_id for axis in scheme.axes}
        if any(rule.axis_id not in registered for rule in rules):
            raise ValueError("semantic drive rule uses an unregistered axis")
        rate = _finite(recovery_rate, "recovery_rate")
        bounds = dict((name, (low, high)) for name, low, high in scheme.parameter_bounds)
        if "recovery_rate" not in bounds or not bounds["recovery_rate"][0] <= rate <= bounds["recovery_rate"][1]:
            raise ValueError("recovery_rate is not admitted by the active scheme")
        end = _finite(to_cursor, "to_cursor")
        if end <= current_feeling.cursor:
            raise ValueError("mixed update must advance beyond the committed cursor")
        if recollection is not None and not isinstance(recollection, RecollectionInfluence):
            raise TypeError("recollection must be a D04 recollection influence")
        if interpretation is not None and not isinstance(interpretation, InterpretationInfluence):
            raise TypeError("interpretation must be a D04 interpretation influence")
        if regulation is not None and not isinstance(regulation, RegulationObservation):
            raise TypeError("regulation must be a D04 regulation observation")
        if regulation is not None:
            if regulation.status not in {"complete", "partial"}:
                raise ValueError("unconfirmed or failed regulation cannot alter a candidate")
            if regulation_observation_ref is None:
                raise ValueError("observed regulation needs its durable observation reference")
        elif regulation_observation_ref is not None:
            raise ValueError("regulation observation reference needs an observed regulation")
        if recollection is not None and recollection.coupling_version != scheme.coupling_version:
            raise ValueError("recollection coupling version differs from active scheme")
        if interpretation is not None and interpretation.coupling_version != scheme.coupling_version:
            raise ValueError("interpretation coupling version differs from active scheme")

        dt = end - current_feeling.cursor
        decay = math.exp(-rate * dt)
        current_values = dict(current_feeling.coordinates)
        mood_values = dict(current_mood.coordinates)
        drive = {axis: 0.0 for axis in registered}
        for rule in rules:
            for facet in appraisal.meaning_facets:
                value = getattr(facet, rule.facet_field)
                if value is None:
                    raise ValueError("unknown semantic dimension cannot be silently treated as zero")
                drive[rule.axis_id] += rule.gain * value
        # Mood-conditioned recall and interpretation change sensitivity only;
        # neither contributes evidence or upgrades the appraisal's source.
        if recollection is not None:
            drive_axis = next((rule.axis_id for rule in rules if rule.axis_id in current_values), None)
            if drive_axis is not None:
                drive[drive_axis] += sum(recollection.tone_interval) / 2.0 * (sum(recollection.salience_interval) / 2.0)
        if interpretation is not None:
            scale = sum(interpretation.sensitivity_interval) / 2.0
            for axis in drive:
                drive[axis] *= scale
        if regulation is not None:
            for axis, effect in regulation.observed_effects:
                if axis not in registered:
                    raise ValueError("regulation effect uses an axis absent from active scheme")
                drive[axis] += effect

        next_values = {
            axis: max(-1.0, min(1.0, decay * current_values.get(axis, 0.0) + (1.0 - decay) * value))
            for axis, value in drive.items()
        }
        next_mood = {
            axis: max(-1.0, min(1.0, decay * mood_values.get(axis, 0.0) + (1.0 - decay) * next_values[axis]))
            for axis in registered if axis in mood_values or axis in next_values
        }
        feeling = FeelingState(
            process_id=current_feeling.process_id, target_ref=appraisal.target_ref,
            basis_version=scheme.scheme_version, operator_version=scheme.operator_version,
            coordinates=tuple(sorted(next_values.items())),
            meaning_refs=tuple(facet.facet_id for facet in appraisal.meaning_facets),
            interpretation_refs=tuple(dict.fromkeys(facet.interpretation_ref for facet in appraisal.meaning_facets)),
            active_driver_refs=(appraisal.contribution_key,),
            historical_source_refs=tuple(dict.fromkeys(current_feeling.historical_source_refs + appraisal.source_refs)),
            parameter_version=scheme.parameter_version, coupling_version=scheme.coupling_version,
            cursor=end, revision=current_feeling.revision + 1,
        )
        mood = MoodField(
            mood_id=current_mood.mood_id, basis_version=scheme.scheme_version,
            coordinates=tuple(sorted(next_mood.items())),
            source_refs=tuple(dict.fromkeys(current_mood.source_refs + appraisal.source_refs)),
            parameter_version=scheme.parameter_version, coupling_version=scheme.coupling_version,
            cursor=end, revision=current_mood.revision + 1,
        )
        source_refs = tuple(dict.fromkeys(
            appraisal.source_refs
            + (() if recollection is None else recollection.source_refs)
            + (() if interpretation is None else interpretation.source_refs)
            + (() if regulation is None else (regulation.execution_receipt_ref, regulation.cost_settlement_ref))
        ))
        return AffectCandidate(
            candidate_id, replay_key, committed_parent_ref, source_refs, current_feeling.cursor, end,
            feeling, mood, regulation_observation_ref, reflection_source_refs,
        )

    def reject_candidate(self, candidate: AffectCandidate, *, reason: str) -> CandidateRejection:
        if not isinstance(candidate, AffectCandidate):
            raise TypeError("candidate must be an AffectCandidate")
        return CandidateRejection(candidate.candidate_id, candidate.replay_key, _nonempty(reason, "reason"))

    def adopt_candidate(
        self,
        current_feeling: FeelingState,
        candidate: AffectCandidate,
        certificate: NumericCertificate,
        requirements: AdvanceRequirements,
    ) -> FeelingState:
        """Return a certified candidate state; graph persistence remains D11's job."""
        if not isinstance(candidate, AffectCandidate):
            raise TypeError("candidate must be an AffectCandidate")
        return self.adopt_advance(current_feeling, candidate.feeling, certificate, requirements)

    def condition_recollection(
        self,
        *,
        memory_ref: str,
        memory_source_refs: tuple[str, ...],
        base_salience_interval: tuple[float, float],
        base_tone_interval: tuple[float, float],
        mood: MoodField,
        coupling: AffectCoupling,
    ) -> RecollectionInfluence:
        if not isinstance(mood, MoodField) or not isinstance(coupling, AffectCoupling):
            raise TypeError("mood and coupling must be D04 contract values")
        if mood.coupling_version != coupling.version:
            raise ValueError("mood and recollection coupling versions differ")
        mood_coordinates = dict(mood.coordinates)
        if coupling.mood_axis not in mood_coordinates:
            raise ValueError("mood does not declare the coupling axis")
        salience = _interval(base_salience_interval, "base_salience_interval")
        tone = _interval(base_tone_interval, "base_tone_interval")
        mood_value = mood_coordinates[coupling.mood_axis]
        salience_shift = mood_value * coupling.recall_salience_gain
        tone_shift = mood_value * coupling.recall_tone_gain
        return RecollectionInfluence(
            memory_ref=_nonempty(memory_ref, "memory_ref"),
            mood_ref=mood.mood_id,
            salience_interval=(
                min(1.0, max(0.0, salience[0] + salience_shift)),
                min(1.0, max(0.0, salience[1] + salience_shift)),
            ),
            tone_interval=(
                min(1.0, max(-1.0, tone[0] + tone_shift)),
                min(1.0, max(-1.0, tone[1] + tone_shift)),
            ),
            evidence_weight_delta=0.0,
            source_refs=_refs(memory_source_refs, "memory_source_refs"),
            coupling_version=coupling.version,
        )

    def propose_recollection_experience(
        self,
        envelope: CommandEnvelope,
        *,
        experience_id: str,
        recollection_ref: str,
        influence: RecollectionInfluence,
        mood: MoodField,
        coupling: AffectCoupling,
        source_versions: tuple[GraphVersion, ...],
        dependencies: DependencySet,
    ) -> DomainProposal:
        """Record a new activity's felt recollection without adding source evidence."""
        if not isinstance(envelope, CommandEnvelope):
            raise TypeError("envelope must be CommandEnvelope")
        if not isinstance(influence, RecollectionInfluence) or not isinstance(mood, MoodField):
            raise TypeError("influence and mood must be D04 contract values")
        if not isinstance(coupling, AffectCoupling):
            raise TypeError("coupling must be an AffectCoupling")
        if influence.mood_ref != mood.mood_id or influence.coupling_version != coupling.version:
            raise ValueError("recollection influence differs from mood or coupling")
        if mood.coupling_version != coupling.version:
            raise ValueError("mood and recollection coupling versions differ")
        if not source_versions or any(not isinstance(version, GraphVersion) for version in source_versions):
            raise ValueError("recollection experience needs source versions")
        if not isinstance(dependencies, DependencySet):
            raise TypeError("dependencies must be DependencySet")
        if dependencies.current_invalidation:
            raise ValueError("immutable recollection experience cannot have current invalidation")
        experience = RecollectionExperience(
            experience_id=experience_id,
            activity_id=envelope.identity.activity_id,
            recollection_ref=recollection_ref,
            memory_ref=influence.memory_ref,
            memory_source_refs=influence.source_refs,
            mood_ref=mood.mood_id,
            mood_source_refs=mood.source_refs,
            salience_interval=influence.salience_interval,
            tone_interval=influence.tone_interval,
            coupling_id=coupling.coupling_id,
            coupling_version=coupling.version,
            evidence_weight_delta=influence.evidence_weight_delta,
        )
        namespace = envelope.authority.namespace
        write = GraphWrite(
            AtomKey(
                Owner("activity", namespace.bot_id, namespace.persona_id, experience.activity_id),
                "d04.recollection_experience.v1", experience.experience_id,
            ),
            {
                **experience.__dict__,
                "memory_source_refs": list(experience.memory_source_refs),
                "mood_source_refs": list(experience.mood_source_refs),
                "salience_interval": list(experience.salience_interval),
                "tone_interval": list(experience.tone_interval),
            },
            (),
        )
        return self.proposal_for(
            envelope,
            typed_writes=(write,),
            dependencies=replace(dependencies, historical_provenance=tuple(dict.fromkeys(
                (*dependencies.historical_provenance, *source_versions),
            ))),
            contribution_keys=(),
            required_bundle_parts=("experience",),
        )

    def condition_interpretation(
        self,
        *,
        interpretation_ref: str,
        interpretation_source_refs: tuple[str, ...],
        base_sensitivity_interval: tuple[float, float],
        mood: MoodField,
        coupling: AffectCoupling,
    ) -> InterpretationInfluence:
        if not isinstance(mood, MoodField) or not isinstance(coupling, AffectCoupling):
            raise TypeError("mood and coupling must be D04 contract values")
        if mood.coupling_version != coupling.version:
            raise ValueError("mood and interpretation coupling versions differ")
        mood_coordinates = dict(mood.coordinates)
        if coupling.mood_axis not in mood_coordinates:
            raise ValueError("mood does not declare the coupling axis")
        sensitivity = _interval(base_sensitivity_interval, "base_sensitivity_interval")
        shift = mood_coordinates[coupling.mood_axis] * coupling.interpretation_gain
        return InterpretationInfluence(
            interpretation_ref=_nonempty(interpretation_ref, "interpretation_ref"),
            mood_ref=mood.mood_id,
            sensitivity_interval=(
                min(1.0, max(0.0, sensitivity[0] + shift)),
                min(1.0, max(0.0, sensitivity[1] + shift)),
            ),
            evidence_weight_delta=0.0,
            source_refs=_refs(interpretation_source_refs, "interpretation_source_refs"),
            coupling_version=coupling.version,
        )

    def interpret_feeling(
        self,
        feeling: FeelingState,
        *,
        understanding_id: str,
        description_hypotheses: tuple[str, ...],
        reason_hypotheses: tuple[str, ...],
        unknown_parts: tuple[str, ...],
        confidence: float,
        reflection_source_refs: tuple[str, ...],
    ) -> SelfUnderstanding:
        if not isinstance(feeling, FeelingState):
            raise TypeError("feeling must be FeelingState")
        return SelfUnderstanding(
            understanding_id, feeling.process_id, description_hypotheses, reason_hypotheses,
            unknown_parts, confidence, reflection_source_refs,
        )

    def record_regulation(
        self,
        attempt: RegulationAttempt,
        *,
        execution_receipt_ref: str,
        observed_effects: tuple[tuple[str, float], ...],
        unknown_effects: tuple[str, ...],
        cost_settlement_ref: str,
        status: str,
    ) -> RegulationObservation:
        if not isinstance(attempt, RegulationAttempt):
            raise TypeError("attempt must be RegulationAttempt")
        return RegulationObservation(
            attempt.attempt_id, execution_receipt_ref, observed_effects, unknown_effects,
            cost_settlement_ref, status,
        )

    def correct_attribution(
        self,
        state: FeelingState,
        *,
        invalidated_driver_refs: tuple[str, ...],
        replacement_appraisal_ref: str,
        correction_source_ref: str,
        learned_at: float,
    ) -> CorrectionResult:
        if not isinstance(state, FeelingState):
            raise TypeError("state must be FeelingState")
        invalidated = _refs(invalidated_driver_refs, "invalidated_driver_refs")
        if not set(invalidated) <= set(state.active_driver_refs):
            raise ValueError("cannot invalidate a driver absent from the current state")
        next_state = replace(
            state,
            active_driver_refs=tuple(ref for ref in state.active_driver_refs if ref not in set(invalidated)),
            revision=state.revision + 1,
        )
        return CorrectionResult(
            next_state, invalidated, replacement_appraisal_ref, correction_source_ref,
            learned_at, True,
        )

    def adopt_advance(
        self,
        current: FeelingState,
        candidate: FeelingState,
        certificate: NumericCertificate,
        requirements: AdvanceRequirements,
    ) -> FeelingState:
        if not all(isinstance(value, expected) for value, expected in (
            (current, FeelingState), (candidate, FeelingState),
            (certificate, NumericCertificate), (requirements, AdvanceRequirements),
        )):
            raise TypeError("advance values have incorrect D04 contract types")
        if certificate.abi_version != 2:
            raise ValueError("continuous nonlinear affect requires native ABI 2")
        if certificate.certificate_flags == 0 or (
            certificate.certificate_flags & requirements.required_flags
        ) != requirements.required_flags:
            raise ValueError("numeric certificate flags do not cover the requested checks")
        if not certificate.assumptions_valid:
            raise ValueError("numeric certificate assumptions are not valid")
        if certificate.stopping_reason not in {"converged", "completed"}:
            raise ValueError("numeric certificate did not complete")
        if (certificate.operator_version, certificate.parameter_version, certificate.coupling_version) != (
            current.operator_version, current.parameter_version, current.coupling_version,
        ):
            raise ValueError("numeric certificate versions differ from the adopted state")
        if (candidate.operator_version, candidate.parameter_version, candidate.coupling_version) != (
            current.operator_version, current.parameter_version, current.coupling_version,
        ):
            raise ValueError("candidate versions differ from the current state")
        if certificate.from_cursor != current.cursor or certificate.to_cursor != candidate.cursor:
            raise ValueError("numeric certificate does not cover the candidate interval")
        if candidate.process_id != current.process_id or candidate.target_ref != current.target_ref:
            raise ValueError("numeric advance cannot change process or target identity")
        if candidate.revision != current.revision + 1:
            raise ValueError("numeric candidate revision is not the next revision")
        if certificate.residual_error_bound > requirements.max_residual_error:
            raise ValueError("residual error exceeds the requested tolerance")
        if certificate.time_error_bound > requirements.max_time_error:
            raise ValueError("time error exceeds the requested tolerance")
        if certificate.truncation_error_bound > requirements.max_truncation_error:
            raise ValueError("truncation error exceeds the requested tolerance")
        return candidate

    def validate(self, proposal: DomainProposal, snapshot: object = None) -> DomainProposal:
        if not isinstance(proposal, DomainProposal):
            raise TypeError("proposal must be DomainProposal")
        if proposal.domain != "d04" or proposal.proposal_schema != "d04.proposal.v1":
            raise ValueError("proposal is not a D04 affect proposal")
        if proposal.proposal_schema_hash != self.descriptor.request_schema_hash:
            raise ValueError("D04 proposal schema hash is not recognized")
        allowed = frozenset(self.register_types())
        if any(write.key.type_name not in allowed for write in proposal.typed_writes):
            raise ValueError("D04 candidates may only contain D04 graph writes")
        specs = {spec.name: spec for spec in self.type_specs()}
        decoded_writes: list[object] = []
        for write in proposal.typed_writes:
            spec = specs[write.key.type_name]
            if write.key.owner.kind not in spec.owner_kinds:
                raise ValueError("D04 graph write uses an unsupported owner kind")
            decoded = spec.validator(write.value)
            if isinstance(decoded, RecollectionExperience) and (
                write.key.name != decoded.experience_id
                or write.key.owner.subject != decoded.activity_id
                or decoded.activity_id != proposal.envelope.identity.activity_id
            ):
                raise ValueError("recollection experience identity differs from its activity write")
            decoded_writes.append(decoded)
        if proposal.typed_writes:
            scheme = snapshot if isinstance(snapshot, AffectScheme) else (
                self._active_scheme if isinstance(snapshot, GraphSnapshot) else None
            )
            if scheme is None:
                raise ValueError("active D04 scheme is required to validate typed writes")
            if (
                proposal.envelope.version_guard.scheme_version != scheme.scheme_version
                or proposal.envelope.version_guard.operator_version != scheme.operator_version
            ):
                raise ValueError("proposal guard versions differ from the active D04 scheme")
            registered_axes = {axis.axis_id for axis in scheme.axes}
            for decoded in decoded_writes:
                if isinstance(decoded, (FeelingState, MoodField)):
                    if (
                        decoded.basis_version != scheme.scheme_version
                        or decoded.parameter_version != scheme.parameter_version
                        or decoded.coupling_version != scheme.coupling_version
                    ):
                        raise ValueError("D04 state versions differ from the active scheme versions")
                    if isinstance(decoded, FeelingState) and decoded.operator_version != scheme.operator_version:
                        raise ValueError("D04 state versions differ from the active scheme versions")
                    if any(axis not in registered_axes for axis, _ in decoded.coordinates):
                        raise ValueError("D04 state uses an axis absent from the active scheme")
                if isinstance(decoded, RegulationObservation):
                    if any(axis not in registered_axes for axis, _ in decoded.observed_effects):
                        raise ValueError("regulation observation uses an axis absent from the active scheme")
                if isinstance(decoded, RecollectionExperience) and decoded.coupling_version != scheme.coupling_version:
                    raise ValueError("recollection experience coupling differs from the active scheme")
                if isinstance(decoded, AppraisalBundle) and not set(decoded.source_refs) <= set(
                    proposal.envelope.source_qualification.source_refs
                ):
                    raise ValueError("appraisal sources exceed the command source qualification")
        return proposal

    def project(self, query: object, snapshot: object = None) -> object:
        raise ValueError("a typed D04 projection contract with purpose and audience is required")

    def invalidate(self, refs: tuple[object, ...]) -> tuple[object, ...]:
        return tuple(refs)

    def cleanup(self, plan: object) -> tuple[str, object]:
        return "delegated_to_runtime", plan
