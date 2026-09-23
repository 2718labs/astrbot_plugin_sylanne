"""D08 goals, commitments, action qualification, and outcome semantics.

This module is deliberately side-effect free.  It validates domain candidates
and combines receipts that other domains already produced.  D11 remains the
only dispatcher and the graph coordinator remains the only persistence path.
"""

from __future__ import annotations

from dataclasses import dataclass
import math

from ...graph_types import TypeSpec
from ...runtime_contracts import (
    CheckReceipt,
    DomainProposal,
    OperationIdentity,
    ProviderDescriptor,
    RUNTIME_SCHEMA,
    VersionedRef,
    canonical_digest,
    schema_hash,
)


_GOAL_STATES = frozenset({
    "proposed", "active", "waiting", "paused", "satisfied", "abandoned", "superseded",
})
_ESTABLISHMENT_STATES = frozenset({
    "private_intention", "offered", "communicated", "acknowledged", "disputed",
})
_FULFILLMENT_STATES = frozenset({
    "pending", "partially_fulfilled", "fulfilled", "overdue", "renegotiating", "withdrawn",
})
_OUTCOME_LEVELS = frozenset({
    "not_dispatched", "accepted", "running", "partially_observed", "completed_verified",
    "failed_verified", "unknown",
})
_PREDICATE_KINDS = frozenset({
    "artifact_verified", "action_postcondition", "communicated", "recipient_acknowledged",
    "domain_state", "explicit_confirmation",
})
_RISK_CLASSES = frozenset({"internal", "reversible", "limited", "irreversible"})

BASE_REQUIRED_PROVIDERS = (
    ("role_binding", "d03.role_binding"),
    ("boundary", "d05.boundary"),
    ("source_grant", "d06.source_grant"),
    ("commitment_conflict", "d08.commitment_conflict"),
    ("dispatch_budget", "d11.dispatch_budget"),
)
PROACTIVE_REQUIRED_PROVIDER = ("contact_policy", "d10.contact_policy")


def _text(value: object, label: str, prefix: str | None = None) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be a nonempty string")
    if prefix is not None and not value.startswith(prefix):
        raise ValueError(f"{label} must start with {prefix!r}")
    return value


def _positive(value: object, label: str) -> int:
    if type(value) is not int or value < 1:
        raise ValueError(f"{label} must be a positive exact integer")
    return value


def _time(value: object, label: str) -> float:
    if type(value) not in (int, float) or not math.isfinite(value):
        raise ValueError(f"{label} must be finite")
    return float(value)


def _strings(values: object, label: str, *, allow_empty: bool = True) -> tuple[str, ...]:
    if isinstance(values, str):
        raise TypeError(f"{label} must be a tuple, not a string")
    try:
        result = tuple(values)  # type: ignore[arg-type]
    except TypeError as exc:
        raise TypeError(f"{label} must be iterable") from exc
    if not allow_empty and not result:
        raise ValueError(f"{label} must not be empty")
    for value in result:
        _text(value, label)
    if len(set(result)) != len(result):
        raise ValueError(f"{label} must not contain duplicates")
    return result


def _typed(values: object, expected: type, label: str, *, allow_empty: bool = True) -> tuple:
    try:
        result = tuple(values)  # type: ignore[arg-type]
    except TypeError as exc:
        raise TypeError(f"{label} must be iterable") from exc
    if not allow_empty and not result:
        raise ValueError(f"{label} must not be empty")
    if any(not isinstance(item, expected) for item in result):
        raise TypeError(f"{label} must contain {expected.__name__} values")
    if len({canonical_digest(item) for item in result}) != len(result):
        raise ValueError(f"{label} must not contain duplicates")
    return result


def _pairs(values: object, label: str) -> tuple[tuple[str, str], ...]:
    try:
        result = tuple(tuple(item) for item in values)  # type: ignore[arg-type]
    except (TypeError, ValueError) as exc:
        raise TypeError(f"{label} must contain pairs") from exc
    if any(len(item) != 2 for item in result):
        raise ValueError(f"{label} entries must be pairs")
    for key, value in result:
        _text(key, f"{label} key")
        _text(value, f"{label} value")
    if len({key for key, _ in result}) != len(result):
        raise ValueError(f"{label} keys must be unique")
    return result


@dataclass(frozen=True)
class GoalPredicate:
    kind: str
    observation_provider: str
    parameters: tuple[tuple[str, str], ...]
    valid_from: float
    valid_until: float | None

    def __post_init__(self) -> None:
        if self.kind not in _PREDICATE_KINDS:
            raise ValueError("unsupported goal predicate kind")
        _text(self.observation_provider, "observation_provider")
        object.__setattr__(self, "parameters", _pairs(self.parameters, "parameters"))
        start = _time(self.valid_from, "valid_from")
        if self.valid_until is not None and _time(self.valid_until, "valid_until") < start:
            raise ValueError("valid_until precedes valid_from")


@dataclass(frozen=True)
class Aspiration:
    aspiration_id: str
    revision: int
    meaning: str
    reality: str
    consideration_conditions: tuple[str, ...]
    source_refs: tuple[str, ...]

    def __post_init__(self) -> None:
        _text(self.aspiration_id, "aspiration_id", "aspiration:")
        _positive(self.revision, "revision")
        _text(self.meaning, "meaning")
        if self.reality not in {"controllable", "partly_controllable", "uncontrollable", "unknown"}:
            raise ValueError("unsupported aspiration reality")
        object.__setattr__(self, "consideration_conditions", _strings(
            self.consideration_conditions, "consideration_conditions"
        ))
        object.__setattr__(self, "source_refs", _strings(self.source_refs, "source_refs", allow_empty=False))


@dataclass(frozen=True)
class Goal:
    goal_id: str
    revision: int
    state: str
    satisfaction_predicate: GoalPredicate
    reason_refs: tuple[str, ...]
    dependency_refs: tuple[str, ...]
    deadline_ref: str | None
    abandon_conditions: tuple[str, ...]
    progress_refs: tuple[str, ...]

    def __post_init__(self) -> None:
        _text(self.goal_id, "goal_id", "goal:")
        _positive(self.revision, "revision")
        if self.state not in _GOAL_STATES:
            raise ValueError("unsupported goal state")
        if not isinstance(self.satisfaction_predicate, GoalPredicate):
            raise TypeError("satisfaction_predicate must be GoalPredicate")
        for name in ("reason_refs", "dependency_refs", "abandon_conditions", "progress_refs"):
            object.__setattr__(self, name, _strings(getattr(self, name), name))
        if self.deadline_ref is not None:
            _text(self.deadline_ref, "deadline_ref")


@dataclass(frozen=True)
class Commitment:
    commitment_id: str
    revision: int
    subject_ref: str
    counterparty_ref: str
    semantic_scope: str
    establishment_kind: str
    establishment_state: str
    fulfillment_state: str
    deadline_ref: str | None
    communicated_refs: tuple[str, ...]
    acknowledged_refs: tuple[str, ...]
    parent_revision_ref: str | None
    source_refs: tuple[str, ...]

    def __post_init__(self) -> None:
        _text(self.commitment_id, "commitment_id", "commitment:")
        _positive(self.revision, "revision")
        _text(self.subject_ref, "subject_ref", "persona:")
        _text(self.counterparty_ref, "counterparty_ref")
        _text(self.semantic_scope, "semantic_scope")
        if self.establishment_kind not in {"unilateral", "bilateral", "joint_plan"}:
            raise ValueError("unsupported establishment_kind")
        if self.establishment_state not in _ESTABLISHMENT_STATES:
            raise ValueError("unsupported establishment_state")
        if self.fulfillment_state not in _FULFILLMENT_STATES:
            raise ValueError("unsupported fulfillment_state")
        if self.deadline_ref is not None:
            _text(self.deadline_ref, "deadline_ref")
        object.__setattr__(self, "communicated_refs", _strings(self.communicated_refs, "communicated_refs"))
        object.__setattr__(self, "acknowledged_refs", _strings(self.acknowledged_refs, "acknowledged_refs"))
        if self.establishment_state == "acknowledged" and not self.acknowledged_refs:
            raise ValueError("acknowledged commitments require inbound evidence")
        if self.establishment_state == "communicated" and not self.communicated_refs:
            raise ValueError("communicated commitments require a delivery receipt")
        if self.parent_revision_ref is not None:
            _text(self.parent_revision_ref, "parent_revision_ref")
        object.__setattr__(self, "source_refs", _strings(self.source_refs, "source_refs", allow_empty=False))


@dataclass(frozen=True)
class JointPlanAcceptance:
    participant_ref: str
    plan_revision: int
    accepted_scope: tuple[str, ...]
    receipt_refs: tuple[str, ...]

    def __post_init__(self) -> None:
        _text(self.participant_ref, "participant_ref")
        _positive(self.plan_revision, "plan_revision")
        object.__setattr__(self, "accepted_scope", _strings(
            self.accepted_scope, "accepted_scope", allow_empty=False
        ))
        object.__setattr__(self, "receipt_refs", _strings(self.receipt_refs, "receipt_refs", allow_empty=False))


@dataclass(frozen=True)
class PlanNode:
    node_id: str
    owner_ref: str
    depends_on: tuple[str, ...]
    action_kind: str
    success_predicate: GoalPredicate
    cancellation_point: bool
    compensation_ref: str | None
    resource_ref: str

    def __post_init__(self) -> None:
        _text(self.node_id, "node_id", "task:")
        _text(self.owner_ref, "owner_ref")
        object.__setattr__(self, "depends_on", _strings(self.depends_on, "depends_on"))
        if self.node_id in self.depends_on:
            raise ValueError("a plan node cannot depend on itself")
        _text(self.action_kind, "action_kind")
        if not isinstance(self.success_predicate, GoalPredicate):
            raise TypeError("success_predicate must be GoalPredicate")
        if type(self.cancellation_point) is not bool:
            raise TypeError("cancellation_point must be bool")
        if self.compensation_ref is not None:
            _text(self.compensation_ref, "compensation_ref")
        _text(self.resource_ref, "resource_ref")


@dataclass(frozen=True)
class JointPlan:
    plan_id: str
    revision: int
    acceptances: tuple[JointPlanAcceptance, ...]
    nodes: tuple[PlanNode, ...]
    exit_rules: tuple[str, ...]
    source_refs: tuple[str, ...]

    def __post_init__(self) -> None:
        _text(self.plan_id, "plan_id", "plan:")
        _positive(self.revision, "revision")
        acceptances = _typed(self.acceptances, JointPlanAcceptance, "acceptances", allow_empty=False)
        nodes = _typed(self.nodes, PlanNode, "nodes", allow_empty=False)
        if len(nodes) > 8:
            raise ValueError("a plan window may contain at most eight nodes")
        node_ids = {node.node_id for node in nodes}
        if len(node_ids) != len(nodes):
            raise ValueError("plan node ids must be unique")
        if any(not set(node.depends_on) <= node_ids for node in nodes):
            raise ValueError("plan dependencies must name nodes in the same window")
        if any(item.plan_revision != self.revision for item in acceptances):
            raise ValueError("acceptance must refer to the exact plan revision")
        if any(not set(item.accepted_scope) <= node_ids for item in acceptances):
            raise ValueError("acceptance scope must name nodes in the plan")
        self._assert_acyclic(nodes)
        object.__setattr__(self, "acceptances", acceptances)
        object.__setattr__(self, "nodes", nodes)
        object.__setattr__(self, "exit_rules", _strings(self.exit_rules, "exit_rules", allow_empty=False))
        object.__setattr__(self, "source_refs", _strings(self.source_refs, "source_refs", allow_empty=False))

    @staticmethod
    def _assert_acyclic(nodes: tuple[PlanNode, ...]) -> None:
        edges = {node.node_id: set(node.depends_on) for node in nodes}
        ready = [node_id for node_id, dependencies in edges.items() if not dependencies]
        visited = 0
        while ready:
            current = ready.pop()
            visited += 1
            for node_id, dependencies in edges.items():
                if current in dependencies:
                    dependencies.remove(current)
                    if not dependencies:
                        ready.append(node_id)
        if visited != len(nodes):
            raise ValueError("plan window must be acyclic")


@dataclass(frozen=True)
class RequiredCheckSpec:
    check_kind: str
    provider_id: str
    subject_ref: str
    action_ref: str
    purpose: str
    criteria_version: str
    required_input_versions: tuple[VersionedRef, ...]

    def __post_init__(self) -> None:
        for name in ("check_kind", "provider_id", "subject_ref", "action_ref", "purpose", "criteria_version"):
            _text(getattr(self, name), name)
        object.__setattr__(self, "required_input_versions", _typed(
            self.required_input_versions, VersionedRef, "required_input_versions"
        ))
        if not any(item.ref == self.criteria_version for item in self.required_input_versions):
            raise ValueError("criteria_version must be pinned in required_input_versions")


@dataclass(frozen=True)
class ActionSchema:
    schema_id: str
    action_kind: str
    proactive: bool
    required_checks: tuple[RequiredCheckSpec, ...]

    def __post_init__(self) -> None:
        _text(self.schema_id, "schema_id")
        _text(self.action_kind, "action_kind")
        if type(self.proactive) is not bool:
            raise TypeError("proactive must be bool")
        checks = _typed(self.required_checks, RequiredCheckSpec, "required_checks", allow_empty=False)
        if len({item.check_kind for item in checks}) != len(checks):
            raise ValueError("an action schema cannot repeat a check kind")
        object.__setattr__(self, "required_checks", checks)


@dataclass(frozen=True)
class ActionIntent:
    action_id: str
    revision: int
    goal_ref: str
    commitment_refs: tuple[str, ...]
    target_ref: str
    action_kind: str
    purpose: str
    risk_class: str
    parameters_digest: str
    identity: OperationIdentity
    schema_id: str
    required_checks: tuple[RequiredCheckSpec, ...]
    success_predicate: GoalPredicate
    effect_scope: tuple[str, ...]
    compensation_ref: str | None
    source_refs: tuple[str, ...]

    def __post_init__(self) -> None:
        _text(self.action_id, "action_id", "action:")
        _positive(self.revision, "revision")
        _text(self.goal_ref, "goal_ref", "goal:")
        object.__setattr__(self, "commitment_refs", _strings(self.commitment_refs, "commitment_refs"))
        _text(self.target_ref, "target_ref")
        _text(self.action_kind, "action_kind")
        _text(self.purpose, "purpose")
        if self.risk_class not in _RISK_CLASSES:
            raise ValueError("unsupported risk_class")
        if not isinstance(self.parameters_digest, str) or len(self.parameters_digest) != 64:
            raise ValueError("parameters_digest must be a SHA-256 digest")
        if not isinstance(self.identity, OperationIdentity):
            raise TypeError("identity must be OperationIdentity")
        if self.identity.effect_id is None:
            raise ValueError("an actionable intent requires a stable effect_id")
        _text(self.schema_id, "schema_id")
        object.__setattr__(self, "required_checks", _typed(
            self.required_checks, RequiredCheckSpec, "required_checks", allow_empty=False
        ))
        if len({item.check_kind for item in self.required_checks}) != len(self.required_checks):
            raise ValueError("an action intent cannot repeat a check kind")
        if not isinstance(self.success_predicate, GoalPredicate):
            raise TypeError("success_predicate must be GoalPredicate")
        object.__setattr__(self, "effect_scope", _strings(self.effect_scope, "effect_scope", allow_empty=False))
        if self.compensation_ref is not None:
            _text(self.compensation_ref, "compensation_ref")
        object.__setattr__(self, "source_refs", _strings(self.source_refs, "source_refs", allow_empty=False))

    def assert_retry_compatible(self, other: "ActionIntent") -> None:
        if not isinstance(other, ActionIntent):
            raise TypeError("other must be ActionIntent")
        stable = (
            "action_id", "goal_ref", "commitment_refs", "target_ref", "action_kind", "purpose",
            "risk_class", "parameters_digest", "schema_id", "required_checks", "success_predicate",
            "effect_scope", "compensation_ref", "source_refs",
        )
        if any(getattr(self, field) != getattr(other, field) for field in stable):
            raise ValueError("retry changed frozen action semantics")
        if self.identity.activity_id != other.identity.activity_id:
            raise ValueError("retry cannot change activity_id")
        if self.identity.effect_id != other.identity.effect_id:
            raise ValueError("retry cannot change effect_id")


@dataclass(frozen=True)
class QualificationDecision:
    status: str
    action_id: str
    schema_id: str
    receipt_digest: str
    dependency_epochs: tuple[tuple[str, int], ...]
    valid_until: float | None
    missing_check_kinds: tuple[str, ...] = ()
    incomplete_check_kinds: tuple[str, ...] = ()
    stale_check_kinds: tuple[str, ...] = ()
    failed_check_kinds: tuple[str, ...] = ()


_COMMUNICATION_CLAIM_KINDS = frozenset({
    "external_fact", "reported_claim", "subjective_judgment", "self_understanding",
    "internal_activity", "simulated", "rhetoric",
})


def _sha256(value: object, label: str) -> str:
    if (type(value) is not str or len(value) != 64
            or any(ch not in "0123456789abcdef" for ch in value)):
        raise ValueError(f"{label} must be a lowercase SHA-256 digest")
    return value


@dataclass(frozen=True)
class CommunicationSegmentSpec:
    """Finite D09 payload proposed for a qualified D08 communication action."""

    segment_id: str
    effect_id: str
    position: int
    payload_digest: str
    max_chars: int
    allowed_media: tuple[str, ...]
    prerequisite_segment_ref: str | None

    def __post_init__(self) -> None:
        _text(self.segment_id, "segment_id", "segment:")
        _text(self.effect_id, "effect_id", "effect:")
        if type(self.position) is not int or self.position < 0:
            raise ValueError("position must be a nonnegative exact integer")
        _sha256(self.payload_digest, "payload_digest")
        _positive(self.max_chars, "max_chars")
        object.__setattr__(self, "allowed_media", _strings(self.allowed_media, "allowed_media"))
        if self.prerequisite_segment_ref is not None:
            _text(self.prerequisite_segment_ref, "prerequisite_segment_ref", "segment:")


@dataclass(frozen=True)
class CommunicationGrantRequest:
    communication_action_id: str
    contact_id: str
    batch_revision: int
    audiences: tuple[str, ...]
    required_slots: tuple[str, ...]
    allowed_claim_kinds: tuple[str, ...]
    promise_grants: tuple[str, ...]
    segment_specs: tuple[CommunicationSegmentSpec, ...]
    cancellation_epoch: int

    def __post_init__(self) -> None:
        _text(self.communication_action_id, "communication_action_id", "communication:")
        _text(self.contact_id, "contact_id", "contact:")
        _positive(self.batch_revision, "batch_revision")
        object.__setattr__(self, "audiences", _strings(self.audiences, "audiences", allow_empty=False))
        object.__setattr__(self, "required_slots", _strings(self.required_slots, "required_slots"))
        kinds = _strings(self.allowed_claim_kinds, "allowed_claim_kinds", allow_empty=False)
        if not set(kinds).issubset(_COMMUNICATION_CLAIM_KINDS):
            raise ValueError("unsupported communication claim kind")
        object.__setattr__(self, "allowed_claim_kinds", kinds)
        object.__setattr__(self, "promise_grants", _strings(self.promise_grants, "promise_grants"))
        specs = _typed(self.segment_specs, CommunicationSegmentSpec, "segment_specs", allow_empty=False)
        if len(specs) > 3:
            raise ValueError("an alpha1 communication grant can contain at most three segments")
        if len({item.segment_id for item in specs}) != len(specs):
            raise ValueError("segment IDs must be unique")
        if len({item.effect_id for item in specs}) != len(specs):
            raise ValueError("segment effects must be unique")
        if tuple(item.position for item in specs) != tuple(range(len(specs))):
            raise ValueError("segment positions must be contiguous and ordered")
        seen: set[str] = set()
        for item in specs:
            if item.prerequisite_segment_ref is not None and item.prerequisite_segment_ref not in seen:
                raise ValueError("a segment prerequisite must refer to an earlier segment")
            seen.add(item.segment_id)
        object.__setattr__(self, "segment_specs", specs)
        if type(self.cancellation_epoch) is not int or self.cancellation_epoch < 0:
            raise ValueError("cancellation_epoch must be a nonnegative exact integer")


@dataclass(frozen=True)
class SegmentGrant:
    segment_id: str
    effect_id: str
    position: int
    payload_digest: str
    max_chars: int
    allowed_media: tuple[str, ...]
    prerequisite_segment_ref: str | None
    required_check_refs: tuple[str, ...]
    valid_until: float
    cancellation_epoch: int

    def __post_init__(self) -> None:
        CommunicationSegmentSpec(
            self.segment_id, self.effect_id, self.position, self.payload_digest,
            self.max_chars, self.allowed_media, self.prerequisite_segment_ref,
        )
        object.__setattr__(self, "required_check_refs", _strings(
            self.required_check_refs, "required_check_refs", allow_empty=False,
        ))
        _time(self.valid_until, "valid_until")
        if type(self.cancellation_epoch) is not int or self.cancellation_epoch < 0:
            raise ValueError("cancellation_epoch must be a nonnegative exact integer")


@dataclass(frozen=True)
class CommunicationIntentGrant:
    """D08 authorization candidate; it is not a D11 final admission or dispatch claim."""

    grant_id: str
    communication_action_id: str
    contact_id: str
    batch_revision: int
    intent_ref: str
    action_id: str
    intent_revision: int
    target_ref: str
    audiences: tuple[str, ...]
    purpose: str
    required_slots: tuple[str, ...]
    allowed_claim_kinds: tuple[str, ...]
    promise_grants: tuple[str, ...]
    segment_grants: tuple[SegmentGrant, ...]
    qualification_receipt_digest: str
    required_check_refs: tuple[str, ...]
    valid_until: float
    cancellation_epoch: int
    contact_policy_check_ref: str | None = None

    def __post_init__(self) -> None:
        _text(self.grant_id, "grant_id", "communication-grant:")
        segments = _typed(
            self.segment_grants, SegmentGrant, "segment_grants", allow_empty=False,
        )
        object.__setattr__(self, "segment_grants", segments)
        request = CommunicationGrantRequest(
            self.communication_action_id,
            self.contact_id,
            self.batch_revision,
            self.audiences,
            self.required_slots,
            self.allowed_claim_kinds,
            self.promise_grants,
            tuple(CommunicationSegmentSpec(
                item.segment_id, item.effect_id, item.position, item.payload_digest,
                item.max_chars, item.allowed_media, item.prerequisite_segment_ref,
            ) for item in segments),
            self.cancellation_epoch,
        )
        _text(self.intent_ref, "intent_ref")
        _text(self.action_id, "action_id", "action:")
        _positive(self.intent_revision, "intent_revision")
        _text(self.target_ref, "target_ref")
        if self.purpose != "expression":
            raise ValueError("communication grant purpose must be expression")
        _sha256(self.qualification_receipt_digest, "qualification_receipt_digest")
        checks = _strings(self.required_check_refs, "required_check_refs", allow_empty=False)
        object.__setattr__(self, "required_check_refs", checks)
        _time(self.valid_until, "valid_until")
        if self.contact_policy_check_ref is not None:
            _text(self.contact_policy_check_ref, "contact_policy_check_ref", "check:")
            if self.contact_policy_check_ref not in checks:
                raise ValueError("contact policy check must be part of required_check_refs")
        for item in segments:
            if item.required_check_refs != checks:
                raise ValueError("every segment must revalidate the complete required-check set")
            if item.valid_until != self.valid_until or item.cancellation_epoch != self.cancellation_epoch:
                raise ValueError("segment authorization window differs from its communication grant")
        # Keep normalized values from the validated request.
        for name in ("audiences", "required_slots", "allowed_claim_kinds", "promise_grants"):
            object.__setattr__(self, name, getattr(request, name))

    @property
    def segment_manifest_digest(self) -> str:
        """Canonical digest of the complete finite segment authorization list."""

        return canonical_digest(self.segment_grants)

    def segment_authorization_ref(self, segment_id: str) -> str:
        """Return the stable per-segment D08 authorization reference for D11."""

        _text(segment_id, "segment_id", "segment:")
        matches = tuple(item for item in self.segment_grants if item.segment_id == segment_id)
        if len(matches) != 1:
            raise ValueError("segment is not present in this communication grant")
        segment = matches[0]
        digest = canonical_digest({
            'grant_id': self.grant_id,
            'segment_manifest_digest': self.segment_manifest_digest,
            'segment_id': segment.segment_id,
            'effect_id': segment.effect_id,
            'payload_digest': segment.payload_digest,
        })
        return f"segment-authorization:{digest}"


@dataclass(frozen=True)
class CommitmentConflictSnapshot:
    input_versions: tuple[VersionedRef, ...]
    coverage: str
    applicable_commitment_refs: tuple[str, ...]
    conflicting_commitment_refs: tuple[str, ...]
    pending_effect_refs: tuple[str, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "input_versions", _typed(
            self.input_versions, VersionedRef, "input_versions"
        ))
        if self.coverage not in {"full", "partial", "none"}:
            raise ValueError("unsupported commitment snapshot coverage")
        for name in ("applicable_commitment_refs", "conflicting_commitment_refs", "pending_effect_refs"):
            object.__setattr__(self, name, _strings(getattr(self, name), name))


class RequiredCheckRegistry:
    """Versioned action schemas and fail-closed receipt aggregation.

    This registry contains configuration and invalidation counters, not domain
    truth.  A qualified decision remains only a candidate for D11 admission.
    """

    def __init__(self) -> None:
        self._schemas: dict[str, ActionSchema] = {}
        self._invalidation_epochs: dict[str, int] = {}
        self._issued_decisions: dict[tuple[str, str, str], QualificationDecision] = {}

    def register(self, schema: ActionSchema) -> None:
        if not isinstance(schema, ActionSchema):
            raise TypeError("schema must be ActionSchema")
        if schema.schema_id in self._schemas:
            raise ValueError("action schema is already registered")
        actual = {(item.check_kind, item.provider_id) for item in schema.required_checks}
        required = set(BASE_REQUIRED_PROVIDERS)
        if schema.proactive:
            required.add(PROACTIVE_REQUIRED_PROVIDER)
        missing = required - actual
        if missing:
            raise ValueError(f"action schema removed required checks: {sorted(missing)!r}")
        self._schemas[schema.schema_id] = schema

    def qualify(
        self, intent: ActionIntent, receipts: tuple[CheckReceipt, ...], *, now: float
    ) -> QualificationDecision:
        if not isinstance(intent, ActionIntent):
            raise TypeError("intent must be ActionIntent")
        timestamp = _time(now, "now")
        try:
            schema = self._schemas[intent.schema_id]
        except KeyError:
            return self._decision("unavailable", intent, (), (), ("schema",), (), (), (), None)
        schema_pairs = {(item.check_kind, item.provider_id) for item in schema.required_checks}
        intent_pairs = {(item.check_kind, item.provider_id) for item in intent.required_checks}
        if not schema_pairs <= intent_pairs or intent.action_kind != schema.action_kind:
            return self._decision("unavailable", intent, (), (), ("schema",), (), (), (), None)
        if not isinstance(receipts, tuple) or any(not isinstance(item, CheckReceipt) for item in receipts):
            raise TypeError("receipts must be CheckReceipt values")

        by_kind: dict[str, list[CheckReceipt]] = {}
        for receipt in receipts:
            by_kind.setdefault(receipt.check_kind, []).append(receipt)
        missing: list[str] = []
        incomplete: list[str] = []
        stale: list[str] = []
        failed: list[str] = []
        conflict = False
        accepted: list[CheckReceipt] = []
        for spec in intent.required_checks:
            matches = by_kind.get(spec.check_kind, [])
            if not matches:
                missing.append(spec.check_kind)
                continue
            if len(matches) != 1:
                conflict = True
                continue
            receipt = matches[0]
            if (
                receipt.issuer != spec.provider_id
                or receipt.subject_ref != spec.subject_ref
                or receipt.action_ref != spec.action_ref
                or receipt.purpose != spec.purpose
            ):
                conflict = True
                continue
            if receipt.result == "fail":
                failed.append(spec.check_kind)
                continue
            if receipt.coverage != "full" or receipt.result in {"unknown", "unavailable"}:
                incomplete.append(spec.check_kind)
                continue
            if receipt.valid_until < timestamp or receipt.input_versions != spec.required_input_versions:
                stale.append(spec.check_kind)
                continue
            if receipt.result != "pass":
                incomplete.append(spec.check_kind)
                continue
            accepted.append(receipt)

        if conflict:
            status = "conflict"
        elif failed:
            status = "rejected"
        elif stale:
            status = "stale"
        elif missing or incomplete:
            status = "unavailable"
        else:
            status = "qualified"
        dependencies = tuple(sorted({version.ref for spec in intent.required_checks
                                     for version in spec.required_input_versions}))
        valid_until = min((item.valid_until for item in accepted), default=None)
        return self._decision(
            status, intent, tuple(accepted), dependencies, tuple(missing), tuple(incomplete),
            tuple(stale), tuple(failed), valid_until,
        )

    def _decision(
        self, status: str, intent: ActionIntent, receipts: tuple[CheckReceipt, ...],
        dependencies: tuple[str, ...], missing: tuple[str, ...], incomplete: tuple[str, ...],
        stale: tuple[str, ...], failed: tuple[str, ...], valid_until: float | None,
    ) -> QualificationDecision:
        epochs = tuple((ref, self._invalidation_epochs.get(ref, 0)) for ref in dependencies)
        decision = QualificationDecision(
            status, intent.action_id, intent.schema_id, canonical_digest(receipts), epochs, valid_until,
            tuple(sorted(missing)), tuple(sorted(incomplete)), tuple(sorted(stale)), tuple(sorted(failed)),
        )
        self._issued_decisions[(decision.action_id, decision.schema_id, decision.receipt_digest)] = decision
        return decision

    def invalidate(self, refs: tuple[str, ...]) -> tuple[tuple[str, int], ...]:
        refs = _strings(refs, "refs", allow_empty=False)
        updated = []
        for ref in refs:
            epoch = self._invalidation_epochs.get(ref, 0) + 1
            self._invalidation_epochs[ref] = epoch
            updated.append((ref, epoch))
        return tuple(updated)

    def is_current(self, decision: QualificationDecision, *, now: float) -> bool:
        if not isinstance(decision, QualificationDecision) or decision.status != "qualified":
            return False
        issued = self._issued_decisions.get(
            (decision.action_id, decision.schema_id, decision.receipt_digest)
        )
        if issued != decision:
            return False
        timestamp = _time(now, "now")
        if decision.valid_until is None or decision.valid_until < timestamp:
            return False
        return all(self._invalidation_epochs.get(ref, 0) == epoch
                   for ref, epoch in decision.dependency_epochs)

    def freeze_communication_grant(
        self,
        intent: ActionIntent,
        decision: QualificationDecision,
        request: CommunicationGrantRequest,
        *,
        now: float,
    ) -> CommunicationIntentGrant:
        """Freeze a finite D09 grant from a currently qualified message action.

        The returned value remains a D08 candidate.  D11 must independently
        revalidate each segment and issue final admission before any handoff.
        """

        if not isinstance(intent, ActionIntent):
            raise TypeError("intent must be ActionIntent")
        if not isinstance(decision, QualificationDecision):
            raise TypeError("decision must be QualificationDecision")
        if not isinstance(request, CommunicationGrantRequest):
            raise TypeError("request must be CommunicationGrantRequest")
        timestamp = _time(now, "now")
        if (
            decision.action_id != intent.action_id
            or decision.schema_id != intent.schema_id
            or not self.is_current(decision, now=timestamp)
        ):
            raise ValueError("communication grant requires the current qualified action decision")
        if intent.action_kind != "message":
            raise ValueError("only a qualified message action can produce a communication grant")
        if intent.target_ref not in request.audiences:
            raise ValueError("communication audiences must include the qualified action target")
        assert decision.valid_until is not None  # guaranteed by is_current
        check_refs = tuple(
            "check:" + canonical_digest({
                'kind': item.check_kind,
                'provider': item.provider_id,
                'subject': item.subject_ref,
                'action': item.action_ref,
                'purpose': item.purpose,
                'criteria_version': item.criteria_version,
                'input_versions': item.required_input_versions,
            })
            for item in intent.required_checks
        )
        contact_policy_refs = tuple(
            ref for item, ref in zip(intent.required_checks, check_refs)
            if item.check_kind == "contact_policy"
        )
        schema = self._schemas[intent.schema_id]
        if len(contact_policy_refs) > 1 or (schema.proactive and len(contact_policy_refs) != 1):
            raise ValueError("proactive communication requires exactly one contact policy check")
        contact_policy_ref = contact_policy_refs[0] if contact_policy_refs else None
        segments = tuple(SegmentGrant(
            item.segment_id,
            item.effect_id,
            item.position,
            item.payload_digest,
            item.max_chars,
            item.allowed_media,
            item.prerequisite_segment_ref,
            check_refs,
            decision.valid_until,
            request.cancellation_epoch,
        ) for item in request.segment_specs)
        identity = {
            "intent_ref": intent.action_id,
            "intent_revision": intent.revision,
            "decision": decision,
            "request": request,
        }
        grant_id = f"communication-grant:{canonical_digest(identity)}"
        return CommunicationIntentGrant(
            grant_id,
            request.communication_action_id,
            request.contact_id,
            request.batch_revision,
            intent.action_id,
            intent.action_id,
            intent.revision,
            intent.target_ref,
            request.audiences,
            "expression",
            request.required_slots,
            request.allowed_claim_kinds,
            request.promise_grants,
            segments,
            decision.receipt_digest,
            check_refs,
            decision.valid_until,
            request.cancellation_epoch,
            contact_policy_ref,
        )


@dataclass(frozen=True)
class ActionOutcome:
    outcome_id: str
    action_id: str
    effect_id: str
    attempt_id: str
    result_level: str
    support_level: str
    observation_refs: tuple[str, ...]
    completed_effects: tuple[str, ...]
    unknown_effects: tuple[str, ...]
    settlement_key: str
    observed_at: float

    def __post_init__(self) -> None:
        _text(self.outcome_id, "outcome_id", "outcome:")
        _text(self.action_id, "action_id", "action:")
        _text(self.effect_id, "effect_id", "effect:")
        _text(self.attempt_id, "attempt_id", "attempt:")
        if self.result_level not in _OUTCOME_LEVELS:
            raise ValueError("unsupported result_level")
        _text(self.support_level, "support_level")
        for name in ("observation_refs", "completed_effects", "unknown_effects"):
            object.__setattr__(self, name, _strings(getattr(self, name), name))
        _text(self.settlement_key, "settlement_key")
        _time(self.observed_at, "observed_at")


@dataclass(frozen=True)
class OutcomeSettlement:
    status: str
    goal_progress: str
    commitment_progress: str
    unresolved_effects: tuple[str, ...]
    requires_verification: bool
    consumed_key: str

    @classmethod
    def from_outcome(cls, intent: ActionIntent, outcome: ActionOutcome) -> "OutcomeSettlement":
        if not isinstance(intent, ActionIntent) or not isinstance(outcome, ActionOutcome):
            raise TypeError("intent and outcome must be typed D08 values")
        if outcome.action_id != intent.action_id or outcome.effect_id != intent.identity.effect_id:
            raise ValueError("outcome does not belong to the action effect")
        if outcome.attempt_id != intent.identity.attempt_id:
            raise ValueError("outcome attempt does not match the frozen action attempt")
        if outcome.result_level == "completed_verified" and not outcome.unknown_effects:
            return cls("settled", "satisfied_candidate", "fulfilled_candidate", (), False,
                       outcome.settlement_key)
        if outcome.result_level == "failed_verified":
            return cls("settled", "blocked", "pending_or_overdue", outcome.unknown_effects, False,
                       outcome.settlement_key)
        unresolved = outcome.unknown_effects or ("postcondition",)
        return cls("pending_confirmation", "pending_verification", "unchanged", unresolved, True,
                   outcome.settlement_key)


@dataclass(frozen=True)
class RepairIntent:
    repair_id: str
    original_effect_id: str
    repair_action: ActionIntent
    qualification_digest: str
    reason_refs: tuple[str, ...]

    @classmethod
    def create(
        cls, repair_id: str, original: ActionIntent, repair: ActionIntent,
        qualification: QualificationDecision, reason_refs: tuple[str, ...],
    ) -> "RepairIntent":
        _text(repair_id, "repair_id", "repair:")
        if not isinstance(original, ActionIntent) or not isinstance(repair, ActionIntent):
            raise TypeError("repair requires typed ActionIntent values")
        if original.action_id == repair.action_id:
            raise ValueError("repair must be a new action intent")
        if original.identity.effect_id == repair.identity.effect_id:
            raise ValueError("repair must use a new effect identity")
        if qualification.status != "qualified" or qualification.action_id != repair.action_id:
            raise ValueError("repair requires its own qualified action")
        reasons = _strings(reason_refs, "reason_refs", allow_empty=False)
        return cls(repair_id, original.identity.effect_id or "", repair,
                   qualification.receipt_digest, reasons)


@dataclass(frozen=True)
class DecisionRecord:
    decision_id: str
    chosen_action_ref: str | None
    eligible_action_refs: tuple[str, ...]
    rejected_reasons: tuple[tuple[str, str], ...]
    unknown_refs: tuple[str, ...]
    source_refs: tuple[str, ...]

    def __post_init__(self) -> None:
        _text(self.decision_id, "decision_id", "decision:")
        if self.chosen_action_ref is not None:
            _text(self.chosen_action_ref, "chosen_action_ref")
        object.__setattr__(self, "eligible_action_refs", _strings(
            self.eligible_action_refs, "eligible_action_refs"
        ))
        object.__setattr__(self, "rejected_reasons", _pairs(self.rejected_reasons, "rejected_reasons"))
        object.__setattr__(self, "unknown_refs", _strings(self.unknown_refs, "unknown_refs"))
        object.__setattr__(self, "source_refs", _strings(self.source_refs, "source_refs", allow_empty=False))


def _tuple_fields(payload: dict, *names: str) -> dict:
    if not isinstance(payload, dict):
        raise TypeError("graph payload must be an object")
    decoded = dict(payload)
    for name in names:
        if name in decoded and isinstance(decoded[name], list):
            decoded[name] = tuple(decoded[name])
    return decoded


def _predicate(value: object) -> GoalPredicate:
    if isinstance(value, GoalPredicate):
        return value
    payload = _tuple_fields(value, "parameters")
    return GoalPredicate(**payload)


def _versioned(value: object) -> VersionedRef:
    return value if isinstance(value, VersionedRef) else VersionedRef(**value)  # type: ignore[arg-type]


def _check_spec(value: object) -> RequiredCheckSpec:
    if isinstance(value, RequiredCheckSpec):
        return value
    payload = _tuple_fields(value, "required_input_versions")
    payload["required_input_versions"] = tuple(_versioned(item) for item in payload["required_input_versions"])
    return RequiredCheckSpec(**payload)


def _operation(value: object) -> OperationIdentity:
    return value if isinstance(value, OperationIdentity) else OperationIdentity(**value)  # type: ignore[arg-type]


def _decode_goal(payload: dict) -> Goal:
    data = _tuple_fields(payload, "reason_refs", "dependency_refs", "abandon_conditions", "progress_refs")
    data["satisfaction_predicate"] = _predicate(data["satisfaction_predicate"])
    return Goal(**data)


def _decode_joint_plan(payload: dict) -> JointPlan:
    data = _tuple_fields(payload, "acceptances", "nodes", "exit_rules", "source_refs")
    data["acceptances"] = tuple(
        item if isinstance(item, JointPlanAcceptance) else JointPlanAcceptance(**_tuple_fields(
            item, "accepted_scope", "receipt_refs"
        )) for item in data["acceptances"]
    )
    nodes = []
    for item in data["nodes"]:
        if isinstance(item, PlanNode):
            nodes.append(item)
            continue
        node = _tuple_fields(item, "depends_on")
        node["success_predicate"] = _predicate(node["success_predicate"])
        nodes.append(PlanNode(**node))
    data["nodes"] = tuple(nodes)
    return JointPlan(**data)


def _decode_intent(payload: dict) -> ActionIntent:
    data = _tuple_fields(payload, "commitment_refs", "required_checks", "effect_scope", "source_refs")
    data["identity"] = _operation(data["identity"])
    data["required_checks"] = tuple(_check_spec(item) for item in data["required_checks"])
    data["success_predicate"] = _predicate(data["success_predicate"])
    return ActionIntent(**data)


def _decode_communication_grant(payload: dict) -> CommunicationIntentGrant:
    data = _tuple_fields(
        payload, "audiences", "required_slots", "allowed_claim_kinds", "promise_grants",
        "segment_grants", "required_check_refs",
    )
    data["segment_grants"] = tuple(
        item if isinstance(item, SegmentGrant) else SegmentGrant(**_tuple_fields(
            item, "allowed_media", "required_check_refs",
        ))
        for item in data["segment_grants"]
    )
    return CommunicationIntentGrant(**data)


def _decode(type_name: str, payload: dict) -> object:
    if type_name == "d08.aspiration.v1":
        return Aspiration(**_tuple_fields(payload, "consideration_conditions", "source_refs"))
    if type_name == "d08.goal.v1":
        return _decode_goal(payload)
    if type_name == "d08.commitment.v1":
        return Commitment(**_tuple_fields(payload, "communicated_refs", "acknowledged_refs", "source_refs"))
    if type_name == "d08.joint_plan.v1":
        return _decode_joint_plan(payload)
    if type_name == "d08.action_intent.v1":
        return _decode_intent(payload)
    if type_name == "d08.communication_intent_grant.v1":
        return _decode_communication_grant(payload)
    if type_name == "d08.action_outcome.v1":
        return ActionOutcome(**_tuple_fields(payload, "observation_refs", "completed_effects", "unknown_effects"))
    if type_name == "d08.decision_record.v1":
        return DecisionRecord(**_tuple_fields(
            payload, "eligible_action_refs", "rejected_reasons", "unknown_refs", "source_refs"
        ))
    raise ValueError("unknown D08 graph type")


class GoalExecutionProvider:
    """D08 proposal validator and pure projection surface."""

    _TYPE_OWNERS = {
        "d08.aspiration.v1": ("persona", "activity"),
        "d08.goal.v1": ("persona", "activity"),
        "d08.commitment.v1": ("persona", "relation", "activity"),
        "d08.joint_plan.v1": ("activity",),
        "d08.action_intent.v1": ("activity",),
        "d08.communication_intent_grant.v1": ("activity",),
        "d08.action_outcome.v1": ("activity",),
        "d08.decision_record.v1": ("activity",),
    }

    @property
    def descriptor(self) -> ProviderDescriptor:
        return ProviderDescriptor(
            provider_id="d08.goals_execution",
            contract_version=RUNTIME_SCHEMA,
            request_schema_hash=schema_hash({"domain": "d08", "proposal": 1}),
            response_schema_hash=schema_hash({"domain": "d08", "goals_execution": 1}),
            owner_capabilities=("persona", "relation", "activity"),
            supported_modalities=("structured",),
            supported_purposes=("decide", "plan", "check", "settle", "repair", "project"),
            supported_platforms=("runtime",),
            timeout_mode="bounded",
            cancellation_mode="cooperative",
            idempotency_mode="operation_id_and_effect_id",
            cost_reporting_mode="actual_or_unconfirmed",
            health_capabilities=("validate", "catalogue"),
            recovery_capabilities=("query_operation", "invalidate_qualification"),
        )

    def register_types(self) -> tuple[TypeSpec, ...]:
        specs = []
        for type_name, owners in self._TYPE_OWNERS.items():
            validator = lambda value, name=type_name: _decode(name, value)
            specs.append(TypeSpec(
                type_name,
                owners,
                "state",
                validator,
                immutable=type_name in {
                    "d08.action_outcome.v1", "d08.decision_record.v1",
                    "d08.communication_intent_grant.v1",
                },
                schema_version=1,
                writer_domain="d08",
                schema_hash=schema_hash({"type": type_name, "version": 1}),
            ))
        return tuple(specs)

    def validate(self, proposal: DomainProposal, snapshot: object = None) -> DomainProposal:
        if not isinstance(proposal, DomainProposal):
            raise TypeError("proposal must be DomainProposal")
        if proposal.domain != "d08" or proposal.proposal_schema != "d08.proposal.v1":
            raise ValueError("D08 provider cannot validate this proposal")
        if proposal.proposal_schema_hash != self.descriptor.request_schema_hash:
            raise ValueError("D08 proposal schema hash is not recognized")
        specs = {spec.name: spec for spec in self.register_types()}
        for write in proposal.typed_writes:
            try:
                spec = specs[write.key.type_name]
            except KeyError:
                raise ValueError("D08 proposals may only contain D08 graph types") from None
            if write.key.owner.kind not in spec.owner_kinds:
                raise ValueError("D08 graph type does not support this owner")
            spec.validator(write.value)
        return proposal

    def provide_required_check(
        self, intent: ActionIntent, snapshot: CommitmentConflictSnapshot, *, valid_until: float
    ) -> CheckReceipt:
        """Provide D08's commitment/conflict check without dispatching anything."""
        if not isinstance(intent, ActionIntent):
            raise TypeError("intent must be ActionIntent")
        if not isinstance(snapshot, CommitmentConflictSnapshot):
            raise TypeError("snapshot must be CommitmentConflictSnapshot")
        candidates = tuple(
            item for item in intent.required_checks
            if item.check_kind == "commitment_conflict" and item.provider_id == "d08.commitment_conflict"
        )
        if len(candidates) != 1:
            raise ValueError("action intent must contain exactly one D08 commitment check")
        spec = candidates[0]
        expiry = _time(valid_until, "valid_until")
        if snapshot.input_versions != spec.required_input_versions:
            return CheckReceipt(
                spec.check_kind, spec.subject_ref, spec.action_ref, spec.purpose,
                snapshot.input_versions, "full" if snapshot.coverage == "full" else snapshot.coverage,
                "unknown", expiry, spec.provider_id,
            )
        if snapshot.coverage != "full":
            return CheckReceipt(
                spec.check_kind, spec.subject_ref, spec.action_ref, spec.purpose,
                snapshot.input_versions, snapshot.coverage, "unknown", expiry, spec.provider_id,
            )
        missing_linked = set(intent.commitment_refs) - set(snapshot.applicable_commitment_refs)
        if missing_linked or snapshot.pending_effect_refs:
            result = "unknown"
        elif snapshot.conflicting_commitment_refs:
            result = "fail"
        else:
            result = "pass"
        return CheckReceipt(
            spec.check_kind, spec.subject_ref, spec.action_ref, spec.purpose,
            snapshot.input_versions, "full", result, expiry, spec.provider_id,
        )

    def compile_scheme(self, draft: object, snapshot: object = None) -> object:
        if not isinstance(draft, tuple) or any(not isinstance(item, ActionSchema) for item in draft):
            raise TypeError("D08 scheme must be a tuple of ActionSchema values")
        registry = RequiredCheckRegistry()
        for item in draft:
            registry.register(item)
        return registry

    def project(self, query: object, snapshot: object = None) -> object:
        return query

    def invalidate(self, refs: tuple[str, ...]) -> tuple[str, ...]:
        return _strings(refs, "refs", allow_empty=False)

    def cleanup(self, plan: object) -> dict:
        return {"domain": "d08", "status": "delegated_to_runtime", "plan": plan}


__all__ = (
    "BASE_REQUIRED_PROVIDERS", "PROACTIVE_REQUIRED_PROVIDER", "ActionIntent", "ActionOutcome",
    "ActionSchema", "Aspiration", "Commitment", "CommitmentConflictSnapshot",
    "CommunicationGrantRequest", "CommunicationIntentGrant", "CommunicationSegmentSpec", "SegmentGrant",
    "DecisionRecord", "Goal", "GoalExecutionProvider",
    "GoalPredicate", "JointPlan", "JointPlanAcceptance", "OutcomeSettlement", "PlanNode",
    "QualificationDecision", "RepairIntent", "RequiredCheckRegistry", "RequiredCheckSpec",
)
