"""D07 attention and cognition proposals for the alpha1 runtime.

This package is a deterministic, side-effect-free domain layer.  It ranks
already-authorized attention candidates, assembles bounded working sets and
prepares cognition proposals.  D11 remains the only commit authority and D06
C04 remains the only coordinator that can turn a memory selection into an
actual recollection.
"""

from __future__ import annotations

from dataclasses import dataclass, fields, replace
from enum import Enum
import hashlib
import json
import math

from ...graph_types import AtomKey, GraphVersion, GraphWrite, Owner, TypeSpec
from ...runtime_contracts import (
    CommandEnvelope,
    DependencySet,
    DomainProposal,
    ProviderDescriptor,
    RUNTIME_SCHEMA,
    schema_hash,
)
from ..d06 import CandidateSet, SelectionTicket


_CATEGORIES = ("required", "interaction", "background")
_CONCERN_STATES = frozenset({"open", "waiting", "parked", "resolved", "relinquished"})
_WORKING_KINDS = frozenset({
    "hard_constraint", "counterevidence", "support", "alternative", "retrievable", "context",
    "memory_fragment",
})
_ELIGIBILITIES = frozenset({"subjective_reaction", "simulation", "fact_expression", "action"})


def _nonempty(value: object, label: str) -> str:
    if type(value) is not str or not value.strip():
        raise ValueError(f"{label} must be a nonempty string")
    return value


def _names(value: object, label: str, *, allow_empty: bool = True) -> tuple[str, ...]:
    if type(value) is not tuple:
        raise TypeError(f"{label} must be a tuple")
    if not allow_empty and not value:
        raise ValueError(f"{label} must not be empty")
    for item in value:
        _nonempty(item, f"{label} item")
    if len(set(value)) != len(value):
        raise ValueError(f"{label} must contain unique values")
    return value


def _finite_unit(value: object, label: str) -> float:
    if type(value) not in (int, float) or isinstance(value, bool) or not math.isfinite(value):
        raise ValueError(f"{label} must be finite")
    result = float(value)
    if not 0.0 <= result <= 1.0:
        raise ValueError(f"{label} must be between 0 and 1")
    return result


def _nonnegative_int(value: object, label: str) -> int:
    if type(value) is not int or isinstance(value, bool) or value < 0:
        raise ValueError(f"{label} must be a nonnegative integer")
    return value


def _stable_id(prefix: str, value: object) -> str:
    raw = json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    return f"{prefix}-{hashlib.sha256(raw.encode('utf-8')).hexdigest()[:24]}"


def _payload_tuple(value: object, label: str) -> tuple:
    if type(value) is not list:
        raise TypeError(f"{label} must be a JSON array")
    return tuple(value)


def _graph_validator(expected_schema: str, value_type: type, tuple_fields: tuple[str, ...]):
    """Decode an exact persisted shape and validate its full domain semantics."""

    expected = {"schema"} | {field.name for field in fields(value_type)}

    def validate(value: dict) -> None:
        if type(value) is not dict:
            raise TypeError("graph value must be a dict")
        if value.get("schema") != expected_schema:
            raise ValueError(f"graph value schema must be {expected_schema}")
        if set(value) != expected:
            raise ValueError("graph value fields must match the registered schema exactly")
        decoded = {key: item for key, item in value.items() if key != "schema"}
        for name in tuple_fields:
            decoded[name] = _payload_tuple(decoded[name], name)
        if value_type is WorkingSet:
            decoded["items"] = tuple(
                WorkingSetItem(**{
                    **item,
                    "source_refs": _payload_tuple(item["source_refs"], "source_refs"),
                }) if type(item) is dict else item
                for item in decoded["items"]
            )
            for item in decoded["items"]:
                if not isinstance(item, WorkingSetItem):
                    raise TypeError("working-set item must be an object")
        if value_type is BeliefRevision:
            decoded["stance"] = Stance(decoded["stance"])
            decoded["evidence_status"] = EvidenceStatus(decoded["evidence_status"])
        if value_type is CurrentInterpretationCandidate:
            decoded["stance"] = Stance(decoded["stance"])
            decoded["evidence_status"] = EvidenceStatus(decoded["evidence_status"])
        value_type(**decoded)

    return validate


class Stance(Enum):
    SUPPORT = "support"
    OPPOSE = "oppose"
    SUSPEND = "suspend"


class EvidenceStatus(Enum):
    SUPPORTED = "supported"
    REFUTED = "refuted"
    CONFLICTED = "conflicted"
    INSUFFICIENT = "insufficient"


@dataclass(frozen=True)
class Concern:
    concern_id: str
    anchor_ref: str
    reason_refs: tuple[str, ...]
    resolution_predicate: str | None
    wake_conditions: tuple[str, ...]
    status: str
    version: int

    def __post_init__(self) -> None:
        _nonempty(self.concern_id, "concern_id")
        _nonempty(self.anchor_ref, "anchor_ref")
        _names(self.reason_refs, "reason_refs", allow_empty=False)
        if self.resolution_predicate is not None:
            _nonempty(self.resolution_predicate, "resolution_predicate")
        _names(self.wake_conditions, "wake_conditions")
        if self.status not in _CONCERN_STATES:
            raise ValueError("unknown concern status")
        _nonnegative_int(self.version, "version")
        if self.status in {"open", "waiting", "parked"} and self.resolution_predicate is None and not self.wake_conditions:
            raise ValueError("an unresolved concern needs a resolution predicate or explicit review condition")


@dataclass(frozen=True)
class AttentionTicket:
    ticket_id: str
    question_key: str
    concern_ref: str | None
    causal_root: str
    category: str
    relevance: float
    urgency: float
    information_value: float
    persona_salience: float
    emotional_salience: float
    waiting: float
    switch_cost: float
    fatigue_cost: float
    served_fraction: float
    enqueued_seq: int
    valid_until: float
    eligible: bool
    resources_available: bool
    cancel_refs: tuple[str, ...]

    def __post_init__(self) -> None:
        for name in ("ticket_id", "question_key", "causal_root"):
            _nonempty(getattr(self, name), name)
        if self.concern_ref is not None:
            _nonempty(self.concern_ref, "concern_ref")
        if self.category not in _CATEGORIES:
            raise ValueError("unknown attention category")
        for name in (
            "relevance", "urgency", "information_value", "persona_salience",
            "emotional_salience", "waiting", "switch_cost", "fatigue_cost", "served_fraction",
        ):
            object.__setattr__(self, name, _finite_unit(getattr(self, name), name))
        _nonnegative_int(self.enqueued_seq, "enqueued_seq")
        if type(self.valid_until) not in (int, float) or not math.isfinite(self.valid_until):
            raise ValueError("valid_until must be finite")
        if type(self.eligible) is not bool or type(self.resources_available) is not bool:
            raise TypeError("ticket gates must be bool")
        _names(self.cancel_refs, "cancel_refs")


@dataclass(frozen=True)
class AttentionPolicy:
    relevance_weight: float
    urgency_weight: float
    information_weight: float
    persona_weight: float
    emotion_weight: float
    waiting_weight: float
    switch_cost_weight: float
    fatigue_cost_weight: float
    served_cost_weight: float
    primary_limit: int = 1
    auxiliary_limit: int = 3
    policy_version: str = "d07.attention.v1"

    def __post_init__(self) -> None:
        names = (
            "relevance_weight", "urgency_weight", "information_weight", "persona_weight",
            "emotion_weight", "waiting_weight", "switch_cost_weight", "fatigue_cost_weight",
            "served_cost_weight",
        )
        weights = tuple(_finite_unit(getattr(self, name), name) for name in names)
        if not math.isclose(sum(weights), 1.0, abs_tol=1e-9):
            raise ValueError("attention weights must sum to 1")
        if self.primary_limit != 1 or self.auxiliary_limit != 3:
            raise ValueError("alpha1 focus capacity is one primary plus three auxiliary items")
        _nonempty(self.policy_version, "policy_version")

    @classmethod
    def default(cls) -> "AttentionPolicy":
        return cls(0.22, 0.22, 0.12, 0.10, 0.10, 0.08, 0.06, 0.05, 0.05)


@dataclass(frozen=True)
class RankedAttention:
    ticket: AttentionTicket
    score: float


@dataclass(frozen=True)
class FocusState:
    persona_id: str
    focus_epoch: int
    primary_ticket_ref: str | None
    auxiliary_ticket_refs: tuple[str, ...]
    switch_reason: str

    def __post_init__(self) -> None:
        _nonempty(self.persona_id, "persona_id")
        _nonnegative_int(self.focus_epoch, "focus_epoch")
        if self.primary_ticket_ref is not None:
            _nonempty(self.primary_ticket_ref, "primary_ticket_ref")
        _names(self.auxiliary_ticket_refs, "auxiliary_ticket_refs")
        if len(self.auxiliary_ticket_refs) > 3:
            raise ValueError("focus may have at most three auxiliary tickets")
        _nonempty(self.switch_reason, "switch_reason")


@dataclass(frozen=True)
class WorkingSetItem:
    content_ref: str
    kind: str
    token_cost: int
    relevance: float
    source_eligibility: str
    source_refs: tuple[str, ...]

    def __post_init__(self) -> None:
        _nonempty(self.content_ref, "content_ref")
        if self.kind not in _WORKING_KINDS:
            raise ValueError("unknown working-set item kind")
        _nonnegative_int(self.token_cost, "token_cost")
        _finite_unit(self.relevance, "relevance")
        _nonempty(self.source_eligibility, "source_eligibility")
        _names(self.source_refs, "source_refs", allow_empty=False)


@dataclass(frozen=True)
class WorkingSet:
    activity_id: str
    question_key: str
    items: tuple[WorkingSetItem, ...]
    unknowns: tuple[str, ...]
    coverage: str
    d06_tokens: int
    max_items: int = 16
    max_tokens: int = 4096

    def __post_init__(self) -> None:
        _nonempty(self.activity_id, "activity_id")
        _nonempty(self.question_key, "question_key")
        if type(self.items) is not tuple or any(not isinstance(item, WorkingSetItem) for item in self.items):
            raise TypeError("items must be a tuple of WorkingSetItem")
        _names(self.unknowns, "unknowns")
        if self.coverage not in {"complete", "partial"}:
            raise ValueError("unknown working-set coverage")
        if type(self.max_items) is not int or not 1 <= self.max_items <= 16:
            raise ValueError("max_items must be in [1, 16]")
        if type(self.max_tokens) is not int or not 1 <= self.max_tokens <= 4096:
            raise ValueError("max_tokens must be in [1, 4096]")
        if len(self.items) > self.max_items or sum(item.token_cost for item in self.items) > self.max_tokens:
            raise ValueError("working set exceeds its capacity")
        actual_d06 = sum(item.token_cost for item in self.items if item.kind == "memory_fragment")
        if actual_d06 > 2048 or self.d06_tokens != actual_d06:
            raise ValueError("D06 fragment accounting is inconsistent")


@dataclass(frozen=True)
class Hypothesis:
    hypothesis_id: str
    proposition: str
    support_refs: tuple[str, ...]
    counter_refs: tuple[str, ...]
    source_families: tuple[str, ...]
    evidence_status: EvidenceStatus
    action_eligibility: tuple[str, ...]
    score: float

    def __post_init__(self) -> None:
        _nonempty(self.hypothesis_id, "hypothesis_id")
        _nonempty(self.proposition, "proposition")
        _names(self.support_refs, "support_refs")
        _names(self.counter_refs, "counter_refs")
        _names(self.source_families, "source_families")
        if not isinstance(self.evidence_status, EvidenceStatus):
            raise TypeError("evidence_status must be EvidenceStatus")
        eligibility = _names(self.action_eligibility, "action_eligibility", allow_empty=False)
        if not set(eligibility).issubset(_ELIGIBILITIES):
            raise ValueError("unknown hypothesis eligibility")
        object.__setattr__(self, "score", _finite_unit(self.score, "score"))


@dataclass(frozen=True)
class HypothesisSet:
    question_key: str
    hypotheses: tuple[Hypothesis, ...]
    non_exhaustive: bool
    meaningful_unknowns: tuple[str, ...]


@dataclass(frozen=True)
class BeliefRevision:
    belief_id: str
    question_key: str
    hypothesis_ref: str
    proposition: str
    stance: Stance
    subjective_conviction: float
    evidence_status: EvidenceStatus
    eligibility: tuple[str, ...]
    source_refs: tuple[str, ...]
    source_families: tuple[str, ...]
    current: bool = True
    historical: bool = True
    replaced_by: str | None = None
    invalidation_refs: tuple[str, ...] = ()
    invalidation_kind: str | None = None

    def __post_init__(self) -> None:
        for name in ("belief_id", "question_key", "hypothesis_ref", "proposition"):
            _nonempty(getattr(self, name), name)
        if not isinstance(self.stance, Stance) or not isinstance(self.evidence_status, EvidenceStatus):
            raise TypeError("belief stance and evidence status must be recognized")
        _finite_unit(self.subjective_conviction, "subjective_conviction")
        if not set(_names(self.eligibility, "eligibility", allow_empty=False)).issubset(_ELIGIBILITIES):
            raise ValueError("unknown belief eligibility")
        _names(self.source_refs, "source_refs")
        _names(self.source_families, "source_families")
        _names(self.invalidation_refs, "invalidation_refs")
        if type(self.current) is not bool or type(self.historical) is not bool:
            raise TypeError("belief current/historical flags must be bool")
        if self.replaced_by is not None:
            _nonempty(self.replaced_by, "replaced_by")
        if self.invalidation_kind is not None and self.invalidation_kind not in {
            "correction", "time_change", "scope_change", "identity_correction", "deletion",
        }:
            raise ValueError("unknown invalidation kind")
        if self.current and (self.replaced_by is not None or self.invalidation_refs):
            raise ValueError("current belief cannot also be invalidated")
        if not self.current and not (self.replaced_by or self.invalidation_refs):
            raise ValueError("inactive belief needs replacement or invalidation evidence")


@dataclass(frozen=True)
class RecollectionHandoff:
    selection_ticket: SelectionTicket
    coordinator: str
    creates_recollection: bool
    required_bundle_parts: tuple[str, ...]


@dataclass(frozen=True)
class CurrentInterpretationCandidate:
    interpretation_id: str
    activity_id: str
    question_key: str
    proposition: str
    stance: Stance
    subjective_conviction: float
    evidence_status: EvidenceStatus
    source_refs: tuple[str, ...]
    source_families: tuple[str, ...]
    meaningful_unknowns: tuple[str, ...]
    current: bool = True

    def __post_init__(self) -> None:
        for name in ("interpretation_id", "activity_id", "question_key", "proposition"):
            _nonempty(getattr(self, name), name)
        if not isinstance(self.stance, Stance) or not isinstance(self.evidence_status, EvidenceStatus):
            raise TypeError("interpretation stance and evidence status must be recognized")
        _finite_unit(self.subjective_conviction, "subjective_conviction")
        _names(self.source_refs, "source_refs", allow_empty=False)
        _names(self.source_families, "source_families", allow_empty=False)
        _names(self.meaningful_unknowns, "meaningful_unknowns")
        if self.current is not True:
            raise ValueError("a current interpretation candidate must be current")


@dataclass(frozen=True)
class ReflectionCheckpoint:
    reflection_id: str
    meta_depth: int
    no_progress_count: int
    unresolved_slots: tuple[str, ...]
    discriminating_refs: tuple[str, ...]
    status: str

    def __post_init__(self) -> None:
        _nonempty(self.reflection_id, "reflection_id")
        if not 0 <= self.meta_depth <= 2:
            raise ValueError("meta depth must be between 0 and 2")
        _nonnegative_int(self.no_progress_count, "no_progress_count")
        _names(self.unresolved_slots, "unresolved_slots")
        _names(self.discriminating_refs, "discriminating_refs")
        if self.status not in {"continue", "complete", "waiting_for_new_trigger", "deferred"}:
            raise ValueError("unknown reflection status")


@dataclass(frozen=True)
class SimulationRequest:
    activity_id: str
    snapshot_refs: tuple[str, ...]
    baseline: str
    alternatives: tuple[str, ...]
    predictions: tuple[tuple[str, ...], ...]
    unknowns: tuple[str, ...]

    def __post_init__(self) -> None:
        _nonempty(self.activity_id, "activity_id")
        _names(self.snapshot_refs, "snapshot_refs", allow_empty=False)
        _nonempty(self.baseline, "baseline")
        _names(self.alternatives, "alternatives")
        if type(self.predictions) is not tuple or any(type(item) is not tuple for item in self.predictions):
            raise TypeError("predictions must be a tuple of prediction tuples")
        for index, item in enumerate(self.predictions):
            _names(item, f"predictions[{index}]")
        _names(self.unknowns, "unknowns")


@dataclass(frozen=True)
class SimulationBranch:
    branch_id: str
    changed_assumption: str
    prediction_steps: tuple[str, ...]
    snapshot_refs: tuple[str, ...]
    unknowns: tuple[str, ...]
    content_reality: str = "simulated"
    evidence_eligibility: str = "none"

    def __post_init__(self) -> None:
        _nonempty(self.branch_id, "branch_id")
        _nonempty(self.changed_assumption, "changed_assumption")
        _names(self.prediction_steps, "prediction_steps")
        _names(self.snapshot_refs, "snapshot_refs", allow_empty=False)
        _names(self.unknowns, "unknowns")
        if len(self.prediction_steps) > 2:
            raise ValueError("simulation branch exceeds prediction bound")
        if self.content_reality != "simulated" or self.evidence_eligibility != "none":
            raise ValueError("simulation cannot acquire external evidence eligibility")


@dataclass(frozen=True)
class CognitiveActivity:
    activity_id: str
    effect_id: str
    attempt_id: str
    work_kind: str
    started_at: float
    ended_at: float
    stop_reason: str
    source_refs: tuple[str, ...]
    cost_receipt_refs: tuple[str, ...]

    def __post_init__(self) -> None:
        for name in ("activity_id", "effect_id", "attempt_id", "work_kind", "stop_reason"):
            _nonempty(getattr(self, name), name)
        for name in ("started_at", "ended_at"):
            value = getattr(self, name)
            if type(value) not in (int, float) or not math.isfinite(value):
                raise ValueError(f"{name} must be finite")
        if self.ended_at < self.started_at:
            raise ValueError("activity ends before it starts")
        _names(self.source_refs, "source_refs")
        _names(self.cost_receipt_refs, "cost_receipt_refs")


@dataclass(frozen=True)
class SimulationResult:
    activity_id: str
    branches: tuple[SimulationBranch, ...]
    truncated: bool


class D07DomainProvider:
    """Pure D07 policy and proposal provider; it owns no writable database."""

    @property
    def descriptor(self) -> ProviderDescriptor:
        request_hash = schema_hash({"domain": "d07", "proposal": 1})
        return ProviderDescriptor(
            provider_id="d07.cognition",
            contract_version=RUNTIME_SCHEMA,
            request_schema_hash=request_hash,
            response_schema_hash=schema_hash({"domain": "d07", "projection": 1}),
            owner_capabilities=("persona", "activity"),
            supported_modalities=("structured",),
            supported_purposes=("context", "expression", "consolidation", "audit"),
            supported_platforms=("runtime",),
            timeout_mode="bounded",
            cancellation_mode="cooperative",
            idempotency_mode="operation_id",
            cost_reporting_mode="runtime_receipt",
            health_capabilities=("validate", "rank_attention"),
            recovery_capabilities=("rebuild_working_set", "resume_reflection"),
        )

    @staticmethod
    def register_types() -> tuple[str, ...]:
        return (
            "d07.concern.v1",
            "d07.focus.v1",
            "d07.working_set.v1",
            "d07.belief_revision.v1",
            "d07.cognitive_activity.v1",
            "d07.simulation_branch.v1",
            "d07.selection_ticket.v1",
            "d07.current_interpretation.v1",
        )

    @staticmethod
    def type_specs() -> tuple[TypeSpec, ...]:
        """Return D11 catalogue candidates; D11 still owns migration/activation."""

        definitions = (
            ("d07.concern.v1", ("persona",), "state", Concern,
             ("reason_refs", "wake_conditions"), False),
            ("d07.focus.v1", ("persona",), "state", FocusState,
             ("auxiliary_ticket_refs",), False),
            ("d07.working_set.v1", ("activity",), "cache", WorkingSet,
             ("items", "unknowns"), False),
            ("d07.belief_revision.v1", ("persona",), "state", BeliefRevision,
             ("eligibility", "source_refs", "source_families", "invalidation_refs"), False),
            ("d07.cognitive_activity.v1", ("activity",), "source", CognitiveActivity,
             ("source_refs", "cost_receipt_refs"), True),
            ("d07.simulation_branch.v1", ("activity",), "cache", SimulationBranch,
             ("prediction_steps", "snapshot_refs", "unknowns"), False),
            ("d07.selection_ticket.v1", ("activity",), "state", SelectionTicket,
             ("selected_candidate_ids",), True),
            ("d07.current_interpretation.v1", ("activity",), "state", CurrentInterpretationCandidate,
             ("source_refs", "source_families", "meaningful_unknowns"), True),
        )
        return tuple(
            TypeSpec(
                name=name,
                owner_kinds=owners,
                storage_role=storage_role,
                validator=_graph_validator(name, value_type, tuple_fields),
                immutable=immutable,
                schema_version=1,
                writer_domain="d07",
                schema_hash=schema_hash({
                    "domain": "d07",
                    "type": name,
                    "owner_kinds": owners,
                    "storage_role": storage_role,
                    "required": ("schema",) + tuple(field.name for field in fields(value_type)),
                    "version": 1,
                }),
            )
            for name, owners, storage_role, value_type, tuple_fields, immutable in definitions
        )

    @staticmethod
    def _recollection_dependencies(
        envelope: CommandEnvelope,
        source_dependencies: tuple[AtomKey, ...],
    ) -> tuple[GraphVersion, ...]:
        if type(source_dependencies) is not tuple or any(
            not isinstance(item, AtomKey) for item in source_dependencies
        ):
            raise TypeError("source_dependencies must be a tuple of AtomKey")
        if not source_dependencies:
            raise ValueError("recollection support requires source dependencies")
        if len(set(source_dependencies)) != len(source_dependencies):
            raise ValueError("source_dependencies must be unique")
        namespace = envelope.authority.namespace
        if any(
            item.owner.bot != namespace.bot_id or item.owner.persona != namespace.persona_id
            for item in source_dependencies
        ):
            raise ValueError("source dependency namespace differs from the envelope namespace")
        read_map = {item.key: item for item in envelope.version_guard.read_versions}
        versions = []
        for key in source_dependencies:
            version = read_map.get(key)
            if version is None or version.revision <= 0:
                raise ValueError("source dependencies require positive envelope read proofs")
            versions.append(version)
        return tuple(versions)

    @staticmethod
    def selection_choice_write(
        envelope: CommandEnvelope,
        ticket: SelectionTicket,
        *,
        source_dependencies: tuple[AtomKey, ...],
    ) -> GraphWrite:
        if not isinstance(envelope, CommandEnvelope):
            raise TypeError("envelope must be CommandEnvelope")
        if not isinstance(ticket, SelectionTicket):
            raise TypeError("ticket must be SelectionTicket")
        if ticket.activity_id != envelope.identity.activity_id:
            raise ValueError("selection ticket activity differs from the envelope activity")
        if ticket.ticket_id not in envelope.input_refs or ticket.candidate_set_id not in envelope.input_refs:
            raise ValueError("selection ticket and candidate set must be bound into envelope input_refs")
        if not any(
            item.version == ticket.focus_epoch
            for item in envelope.version_guard.focus_lease_versions
        ):
            raise ValueError("selection ticket focus epoch is not guarded by the envelope")
        D07DomainProvider._recollection_dependencies(envelope, source_dependencies)
        namespace = envelope.authority.namespace
        value = {
            "schema": "d07.selection_ticket.v1",
            "ticket_id": ticket.ticket_id,
            "activity_id": ticket.activity_id,
            "candidate_set_id": ticket.candidate_set_id,
            "selected_candidate_ids": list(ticket.selected_candidate_ids),
            "focus_epoch": ticket.focus_epoch,
        }
        return GraphWrite(
            AtomKey(
                Owner("activity", namespace.bot_id, namespace.persona_id, ticket.activity_id),
                "d07.selection_ticket.v1",
                ticket.ticket_id,
            ),
            value,
            (),
        )

    @staticmethod
    def current_interpretation_write(
        envelope: CommandEnvelope,
        interpretation: CurrentInterpretationCandidate,
        *,
        source_dependencies: tuple[AtomKey, ...],
    ) -> GraphWrite:
        if not isinstance(envelope, CommandEnvelope):
            raise TypeError("envelope must be CommandEnvelope")
        if not isinstance(interpretation, CurrentInterpretationCandidate):
            raise TypeError("interpretation must be CurrentInterpretationCandidate")
        if interpretation.activity_id != envelope.identity.activity_id:
            raise ValueError("interpretation activity differs from the envelope activity")
        D07DomainProvider._recollection_dependencies(envelope, source_dependencies)
        if interpretation.source_refs != tuple(item.token for item in source_dependencies):
            raise ValueError("interpretation source refs must exactly match historical source proofs")
        namespace = envelope.authority.namespace
        value = {
            "schema": "d07.current_interpretation.v1",
            "interpretation_id": interpretation.interpretation_id,
            "activity_id": interpretation.activity_id,
            "question_key": interpretation.question_key,
            "proposition": interpretation.proposition,
            "stance": interpretation.stance.value,
            "subjective_conviction": interpretation.subjective_conviction,
            "evidence_status": interpretation.evidence_status.value,
            "source_refs": list(interpretation.source_refs),
            "source_families": list(interpretation.source_families),
            "meaningful_unknowns": list(interpretation.meaningful_unknowns),
            "current": interpretation.current,
        }
        return GraphWrite(
            AtomKey(
                Owner("activity", namespace.bot_id, namespace.persona_id, interpretation.activity_id),
                "d07.current_interpretation.v1",
                interpretation.interpretation_id,
            ),
            value,
            (),
        )

    def recollection_support_proposal(
        self,
        envelope: CommandEnvelope,
        handoff: RecollectionHandoff,
        interpretation: CurrentInterpretationCandidate,
        *,
        source_dependencies: tuple[AtomKey, ...],
    ) -> DomainProposal:
        if not isinstance(handoff, RecollectionHandoff):
            raise TypeError("handoff must be RecollectionHandoff")
        if not isinstance(interpretation, CurrentInterpretationCandidate):
            raise TypeError("interpretation must be CurrentInterpretationCandidate")
        ticket = handoff.selection_ticket
        if interpretation.activity_id != ticket.activity_id:
            raise ValueError("selection and interpretation activities differ")
        versions = self._recollection_dependencies(envelope, source_dependencies)
        writes = (
            self.selection_choice_write(
                envelope, ticket, source_dependencies=source_dependencies,
            ),
            self.current_interpretation_write(
                envelope, interpretation, source_dependencies=source_dependencies,
            ),
        )
        proposal = DomainProposal(
            domain="d07",
            proposal_schema="d07.proposal.v1",
            proposal_schema_hash=self.descriptor.request_schema_hash,
            envelope=envelope,
            typed_writes=writes,
            dependencies=DependencySet(historical_provenance=versions),
            contribution_keys=(f"recollection-selection:{ticket.activity_id}",),
            required_bundle_parts=(
                "experience", "choice", "d02_settlement", "cost_settlement", "outbox",
            ),
        )
        return self.validate(proposal)

    def proposal_for(
        self,
        envelope: CommandEnvelope,
        *,
        contribution_keys: tuple[str, ...] = (),
        required_bundle_parts: tuple[str, ...] = (),
    ) -> DomainProposal:
        if not isinstance(envelope, CommandEnvelope):
            raise TypeError("envelope must be CommandEnvelope")
        return DomainProposal(
            domain="d07",
            proposal_schema="d07.proposal.v1",
            proposal_schema_hash=self.descriptor.request_schema_hash,
            envelope=envelope,
            typed_writes=(),
            dependencies=DependencySet(),
            contribution_keys=contribution_keys,
            required_bundle_parts=required_bundle_parts,
        )

    def validate(self, proposal: DomainProposal, snapshot: object = None) -> DomainProposal:
        if not isinstance(proposal, DomainProposal):
            raise TypeError("proposal must be DomainProposal")
        if proposal.domain != "d07" or proposal.proposal_schema != "d07.proposal.v1":
            raise ValueError("proposal is not a D07 cognition proposal")
        if proposal.proposal_schema_hash != self.descriptor.request_schema_hash:
            raise ValueError("D07 proposal schema hash is not recognized")
        specs = {spec.name: spec for spec in self.type_specs()}
        selections = []
        interpretations = []
        for write in proposal.typed_writes:
            spec = specs.get(write.key.type_name)
            if spec is None:
                raise ValueError(f"D07 proposal contains an unregistered type: {write.key.type_name}")
            if write.key.owner.kind not in spec.owner_kinds:
                raise ValueError("D07 write owner kind is not valid for its registered type")
            namespace = proposal.envelope.authority.namespace
            if any(
                dependency.owner.bot != namespace.bot_id
                or dependency.owner.persona != namespace.persona_id
                for dependency in write.dependencies
            ):
                raise ValueError("D07 write dependency crosses the envelope namespace")
            spec.validator(write.value)
            activity_id = proposal.envelope.identity.activity_id
            if write.key.owner.kind == "activity" and write.key.owner.subject != activity_id:
                raise ValueError("D07 activity write owner differs from the envelope activity")
            if write.key.type_name == "d07.selection_ticket.v1":
                selections.append(write)
            elif write.key.type_name == "d07.current_interpretation.v1":
                interpretations.append(write)
        if selections:
            if len(selections) != 1:
                raise ValueError("a recollection proposal must contain exactly one SelectionTicket choice")
            if not interpretations:
                raise ValueError("a recollection SelectionTicket requires a current interpretation candidate")
            choice_write = selections[0]
            choice = choice_write.value
            if choice["activity_id"] != proposal.envelope.identity.activity_id:
                raise ValueError("SelectionTicket activity differs from the envelope activity")
            if choice_write.key.name != choice["ticket_id"]:
                raise ValueError("SelectionTicket key does not match its ticket ID")
            if choice["ticket_id"] not in proposal.envelope.input_refs or choice["candidate_set_id"] not in proposal.envelope.input_refs:
                raise ValueError("SelectionTicket inputs are not bound to the envelope")
            expected_id = _stable_id("selection", {
                "activity_id": choice["activity_id"],
                "focus_epoch": choice["focus_epoch"],
                "candidate_set_id": choice["candidate_set_id"],
                "selected": tuple(choice["selected_candidate_ids"]),
            })
            if choice["ticket_id"] != expected_id:
                raise ValueError("D07 choice write does not encode its signed SelectionTicket")
            historical_sources = tuple(
                ref.key.token for ref in proposal.dependencies.historical_provenance)
            for interpretation_write in interpretations:
                interpretation = interpretation_write.value
                if interpretation["activity_id"] != choice["activity_id"]:
                    raise ValueError("current interpretation activity differs from its SelectionTicket")
                if interpretation_write.key.name != interpretation["interpretation_id"]:
                    raise ValueError("current interpretation key does not match its interpretation ID")
                if tuple(interpretation["source_refs"]) != historical_sources:
                    raise ValueError("current interpretation source refs differ from historical provenance")
        return proposal

    @staticmethod
    def rank_attention(
        tickets: tuple[AttentionTicket, ...], policy: AttentionPolicy, *, now: float,
    ) -> tuple[RankedAttention, ...]:
        if type(tickets) is not tuple or any(not isinstance(item, AttentionTicket) for item in tickets):
            raise TypeError("tickets must be a tuple of AttentionTicket")
        if not isinstance(policy, AttentionPolicy):
            raise TypeError("policy must be AttentionPolicy")
        if type(now) not in (int, float) or not math.isfinite(now):
            raise ValueError("now must be finite")
        weights = (
            policy.relevance_weight, policy.urgency_weight, policy.information_weight,
            policy.persona_weight, policy.emotion_weight, policy.waiting_weight,
        )
        cost_weights = (policy.switch_cost_weight, policy.fatigue_cost_weight, policy.served_cost_weight)
        ranked = []
        for item in tickets:
            if not item.eligible or not item.resources_available or item.valid_until < now:
                continue
            benefit = sum(weight * value for weight, value in zip(weights, (
                item.relevance, item.urgency, item.information_value, item.persona_salience,
                item.emotional_salience, item.waiting,
            )))
            cost = sum(weight * value for weight, value in zip(cost_weights, (
                item.switch_cost, item.fatigue_cost, item.served_fraction,
            )))
            ranked.append(RankedAttention(item, max(0.0, min(1.0, benefit - cost))))
        category_index = {value: index for index, value in enumerate(_CATEGORIES)}
        return tuple(sorted(ranked, key=lambda value: (
            category_index[value.ticket.category], -value.score,
            value.ticket.enqueued_seq, value.ticket.ticket_id,
        )))

    def allocate_focus(
        self,
        current: FocusState,
        tickets: tuple[AttentionTicket, ...],
        policy: AttentionPolicy,
        *,
        now: float,
    ) -> FocusState:
        if not isinstance(current, FocusState):
            raise TypeError("current must be FocusState")
        ranked = self.rank_attention(tickets, policy, now=now)
        refs = tuple(item.ticket.ticket_id for item in ranked[: policy.primary_limit + policy.auxiliary_limit])
        primary = refs[0] if refs else None
        return FocusState(
            current.persona_id,
            current.focus_epoch + 1,
            primary,
            refs[1:],
            "selected_by_bounded_attention" if refs else "no_eligible_ticket",
        )

    @staticmethod
    def assemble_working_set(
        activity_id: str,
        question_key: str,
        items: tuple[WorkingSetItem, ...],
        *,
        max_items: int = 16,
        max_tokens: int = 4096,
    ) -> WorkingSet:
        _nonempty(activity_id, "activity_id")
        _nonempty(question_key, "question_key")
        if type(items) is not tuple or any(not isinstance(item, WorkingSetItem) for item in items):
            raise TypeError("items must be a tuple of WorkingSetItem")
        if not 1 <= max_items <= 16 or not 1 <= max_tokens <= 4096:
            raise ValueError("working-set limits exceed the alpha1 bounds")
        mandatory = [item for item in items if item.kind in {"hard_constraint", "counterevidence"}]
        if len(mandatory) > max_items or sum(item.token_cost for item in mandatory) > max_tokens:
            raise ValueError("hard constraints and counterevidence do not fit; narrow the question")
        optional = sorted(
            (item for item in items if item.kind not in {"hard_constraint", "counterevidence"}),
            key=lambda item: (-item.relevance, item.content_ref),
        )
        selected = list(mandatory)
        tokens = sum(item.token_cost for item in selected)
        d06_tokens = sum(item.token_cost for item in selected if item.kind == "memory_fragment")
        for item in optional:
            if len(selected) >= max_items or tokens + item.token_cost > max_tokens:
                continue
            if item.kind == "memory_fragment" and d06_tokens + item.token_cost > 2048:
                continue
            selected.append(item)
            tokens += item.token_cost
            if item.kind == "memory_fragment":
                d06_tokens += item.token_cost
        partial = len(selected) != len(items)
        return WorkingSet(
            activity_id,
            question_key,
            tuple(selected),
            ("capacity",) if partial else (),
            "partial" if partial else "complete",
            d06_tokens,
            max_items,
            max_tokens,
        )

    @staticmethod
    def compare_hypotheses(question_key: str, candidates: tuple[Hypothesis, ...]) -> HypothesisSet:
        _nonempty(question_key, "question_key")
        if type(candidates) is not tuple or any(not isinstance(item, Hypothesis) for item in candidates):
            raise TypeError("candidates must be a tuple of Hypothesis")
        if not candidates:
            raise ValueError("at least one hypothesis is required")
        ids = tuple(item.hypothesis_id for item in candidates)
        if len(set(ids)) != len(ids):
            raise ValueError("hypothesis IDs must be unique")
        ranked = tuple(sorted(candidates, key=lambda item: (-item.score, item.hypothesis_id)))
        selected = ranked[:3]
        return HypothesisSet(question_key, selected, len(ranked) > 3, ("other_reasons",) if len(ranked) > 3 else ())

    @staticmethod
    def adopt_belief(
        hypotheses: HypothesisSet,
        hypothesis_id: str,
        *,
        stance: Stance,
        subjective_conviction: float,
        requested_eligibility: tuple[str, ...],
    ) -> BeliefRevision:
        if not isinstance(hypotheses, HypothesisSet):
            raise TypeError("hypotheses must be HypothesisSet")
        _nonempty(hypothesis_id, "hypothesis_id")
        if not isinstance(stance, Stance):
            raise TypeError("stance must be Stance")
        conviction = _finite_unit(subjective_conviction, "subjective_conviction")
        eligibility = _names(requested_eligibility, "requested_eligibility", allow_empty=False)
        selected = next((item for item in hypotheses.hypotheses if item.hypothesis_id == hypothesis_id), None)
        if selected is None:
            raise ValueError("selected hypothesis is not in the compared set")
        if not set(eligibility).issubset(set(selected.action_eligibility)):
            raise ValueError("belief adoption cannot elevate source eligibility")
        source_refs = tuple(dict.fromkeys(selected.support_refs + selected.counter_refs))
        belief_id = _stable_id("belief", {
            "question": hypotheses.question_key,
            "hypothesis": selected.hypothesis_id,
            "sources": source_refs,
        })
        return BeliefRevision(
            belief_id,
            hypotheses.question_key,
            selected.hypothesis_id,
            selected.proposition,
            stance,
            conviction,
            selected.evidence_status,
            eligibility,
            source_refs,
            selected.source_families,
        )

    @staticmethod
    def invalidate_belief(belief: BeliefRevision, basis_ref: str, kind: str) -> BeliefRevision:
        if not isinstance(belief, BeliefRevision):
            raise TypeError("belief must be BeliefRevision")
        _nonempty(basis_ref, "basis_ref")
        if kind not in {"correction", "time_change", "scope_change", "identity_correction", "deletion"}:
            raise ValueError("unknown invalidation kind")
        if not belief.current:
            return belief
        return replace(
            belief,
            current=False,
            invalidation_refs=(basis_ref,),
            invalidation_kind=kind,
        )

    @staticmethod
    def select_recollection(
        *,
        activity_id: str,
        focus_epoch: int,
        candidates: CandidateSet,
        selected_candidate_ids: tuple[str, ...],
    ) -> RecollectionHandoff:
        _nonempty(activity_id, "activity_id")
        _nonnegative_int(focus_epoch, "focus_epoch")
        if not isinstance(candidates, CandidateSet):
            raise TypeError("candidates must be CandidateSet")
        selected = _names(selected_candidate_ids, "selected_candidate_ids", allow_empty=False)
        known = {item.candidate_id for item in candidates.items}
        if not set(selected).issubset(known):
            raise ValueError("recollection selection contains an unknown candidate")
        ticket_id = _stable_id("selection", {
            "activity_id": activity_id,
            "focus_epoch": focus_epoch,
            "candidate_set_id": candidates.candidate_set_id,
            "selected": selected,
        })
        return RecollectionHandoff(
            SelectionTicket(ticket_id, activity_id, candidates.candidate_set_id, selected, focus_epoch),
            "d06.c04",
            False,
            ("experience", "d02_settlement", "cost_settlement"),
        )

    @staticmethod
    def advance_reflection(
        checkpoint: ReflectionCheckpoint,
        *,
        resolved_slots: tuple[str, ...],
        discriminating_refs: tuple[str, ...],
    ) -> ReflectionCheckpoint:
        if not isinstance(checkpoint, ReflectionCheckpoint):
            raise TypeError("checkpoint must be ReflectionCheckpoint")
        resolved = _names(resolved_slots, "resolved_slots")
        evidence = _names(discriminating_refs, "discriminating_refs")
        if checkpoint.meta_depth >= 2:
            raise ValueError("meta depth limit reached")
        remaining = tuple(slot for slot in checkpoint.unresolved_slots if slot not in resolved)
        progressed = len(remaining) < len(checkpoint.unresolved_slots) or bool(evidence)
        no_progress = 0 if progressed else checkpoint.no_progress_count + 1
        if not remaining:
            status = "complete"
        elif no_progress >= 2:
            status = "waiting_for_new_trigger"
        else:
            status = "continue"
        return ReflectionCheckpoint(
            checkpoint.reflection_id,
            checkpoint.meta_depth,
            no_progress,
            remaining,
            tuple(dict.fromkeys(checkpoint.discriminating_refs + evidence)),
            status,
        )

    @staticmethod
    def simulate(request: SimulationRequest) -> SimulationResult:
        if not isinstance(request, SimulationRequest):
            raise TypeError("request must be SimulationRequest")
        assumptions = (request.baseline,) + request.alternatives[:2]
        branches = []
        for index, assumption in enumerate(assumptions):
            prediction = request.predictions[index] if index < len(request.predictions) else ()
            branches.append(SimulationBranch(
                _stable_id("simulation", {
                    "activity": request.activity_id,
                    "index": index,
                    "assumption": assumption,
                    "snapshot": request.snapshot_refs,
                }),
                assumption,
                prediction[:2],
                request.snapshot_refs,
                request.unknowns,
            ))
        truncated = len(request.alternatives) > 2 or any(len(item) > 2 for item in request.predictions[:3])
        return SimulationResult(request.activity_id, tuple(branches), truncated)


__all__ = [
    "AttentionPolicy", "AttentionTicket", "BeliefRevision", "CognitiveActivity", "Concern",
    "CurrentInterpretationCandidate", "D07DomainProvider",
    "EvidenceStatus", "FocusState", "Hypothesis", "HypothesisSet", "RankedAttention",
    "RecollectionHandoff", "ReflectionCheckpoint", "SimulationBranch", "SimulationRequest",
    "SimulationResult", "Stance", "WorkingSet", "WorkingSetItem",
]
