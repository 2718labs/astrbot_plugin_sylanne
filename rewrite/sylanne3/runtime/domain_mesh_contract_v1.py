"""Closed mesh metadata; envelopes and tick records convey no execution authority."""
from dataclasses import dataclass
import math

from ..graph_types import AtomKey, GraphVersion
from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize
from .domain_production_contracts_v1 import (
    ProductionOriginalRefV1, ProductionOwnerGuardV1, ProductionPolicyRefV1,
    ProductionQueryCoverageV1,
)
from .personal_candidate_eligibility_v1 import PersonalMeshRouteV1

ENVELOPE_SCHEMA = "d11.domain-mesh-envelope.v1"
TICK_SCHEMA = "d11.semantic-tick.v1"
TICK_TYPE = "d11.semantic_tick.v1"
KINDS = ("projectionRequest", "projectionResult", "evidenceNotice", "outcome")
RECIPES = ("foreground-projection.v1", "world-history.v1", "joint-habit.v1", "prediction-conditioned.v1")


def _text(value, name):
    if type(value) is not str or not 1 <= len(value) <= 4096:
        raise ValueError(name + " must be an exact bounded locator")


def _digest(value):
    if type(value) is not str or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
        raise ValueError("mesh commitment must be an exact canonical SHA-256")


def _tuple(values, expected, maximum):
    if type(values) is not tuple or len(values) > maximum or any(type(v) is not expected for v in values):
        raise TypeError("mesh field requires its bounded immutable typed tuple")


def _sources(values, namespace):
    _tuple(values, str, 32)
    if len(set(values)) != len(values):
        raise ValueError("mesh Source roots repeat")
    for ref in values:
        key = AtomKey.from_token(ref)
        if key.type_name != "memory.source" or NamespaceId.from_key(key) != namespace:
            raise ValueError("mesh Source root crossed its actual namespace")


@dataclass(frozen=True, slots=True)
class MeshPendingIdentityV1:
    kind: str
    original_ref: str
    original_digest: str
    state: str

    def __post_init__(self):
        if self.kind not in ("job", "call", "effect", "financial"):
            raise ValueError("unknown original in-flight identity kind")
        if self.state not in ("issued", "in_flight", "observed", "unconfirmed", "unknown"):
            raise ValueError("pending identity cannot claim an adopted result")
        _text(self.original_ref, "pending original")
        _digest(self.original_digest)


@dataclass(frozen=True, slots=True)
class MeshWaitV1:
    reason: str
    producer_domain: str
    event_kind: str
    dependency_refs: tuple[str, ...]
    observed_versions: tuple[GraphVersion, ...]
    query_coverage: tuple[ProductionQueryCoverageV1, ...]
    next_due_utc: float | None = None

    def __post_init__(self):
        if self.reason not in ("predecessor_adoption", "external_result", "current_rights", "resource",
                "future_trial", "same_semantic_state", "no_semantic_progress", "scan_eof", "original_deadline_expired"):
            raise ValueError("unregistered semantic wait predicate")
        if self.producer_domain not in tuple("d" + str(i).zfill(2) for i in range(1, 14)):
            raise ValueError("wait requires its actual producer domain")
        _text(self.event_kind, "wait event")
        _tuple(self.dependency_refs, str, 128)
        for ref in self.dependency_refs:
            _text(ref, "wait dependency")
        _tuple(self.observed_versions, GraphVersion, 1024)
        _tuple(self.query_coverage, ProductionQueryCoverageV1, 64)
        if self.next_due_utc is not None and (
                type(self.next_due_utc) not in (int, float) or not math.isfinite(self.next_due_utc)):
            raise ValueError("wait due time must be the original absolute time")


@dataclass(frozen=True, slots=True, kw_only=True)
class MeshTickInputsV1:
    causal_original: ProductionOriginalRefV1
    source_roots: tuple[str, ...]
    predecessors: tuple[ProductionOriginalRefV1, ...]
    semantic_originals: tuple[ProductionOriginalRefV1, ...]
    semantic_versions: tuple[GraphVersion, ...]
    original_deadline_utc: float
    semantic_digest: str
    cancellation_generation: int
    pending: tuple[MeshPendingIdentityV1, ...] = ()
    wait: MeshWaitV1 | None = None

    def __post_init__(self):
        if type(self.causal_original) is not ProductionOriginalRefV1:
            raise TypeError("actual committed causal original required")
        _digest(self.semantic_digest)
        _tuple(self.source_roots, str, 32)
        _tuple(self.predecessors, ProductionOriginalRefV1, 128)
        _tuple(self.semantic_originals, ProductionOriginalRefV1, 128)
        _tuple(self.semantic_versions, GraphVersion, 1024)
        _tuple(self.pending, MeshPendingIdentityV1, 32)
        if type(self.cancellation_generation) is not int or self.cancellation_generation < 0:
            raise ValueError("actual cancellation generation required")
        if self.wait is not None and type(self.wait) is not MeshWaitV1:
            raise TypeError("actual typed semantic wait required")
        if type(self.original_deadline_utc) not in (int, float) or not math.isfinite(self.original_deadline_utc):
            raise ValueError("actual causal deadline is required")


@dataclass(frozen=True, slots=True)
class MeshPayloadRefV1:
    schema: str
    payload_ref: str
    payload_digest: str

    def __post_init__(self):
        _text(self.schema, "fixed payload schema")
        _text(self.payload_ref, "typed payload locator")
        _digest(self.payload_digest)


@dataclass(frozen=True, slots=True, kw_only=True)
class DomainMeshEnvelopeV1:
    namespace: NamespaceId
    route: PersonalMeshRouteV1
    causal_root: ProductionOriginalRefV1
    parent_stage: ProductionOriginalRefV1
    request_ref: str
    correlation_ref: str
    payload: MeshPayloadRefV1
    producer_original: ProductionOriginalRefV1
    producer_operation_id: str
    producer_receipt_digest: str
    reality: str
    qualification: str
    coverage: str
    read_versions: tuple[GraphVersion, ...]
    query_coverage: tuple[ProductionQueryCoverageV1, ...]
    source_roots: tuple[str, ...]
    source_closure_digest: str
    audience: tuple[str, ...]
    provider_policies: tuple[ProductionPolicyRefV1, ...]
    owner_guard: ProductionOwnerGuardV1
    activation_generation: int
    storage_generation: int
    access_epoch: int
    delete_epoch: int
    cancellation_generations: tuple[tuple[str, int], ...]
    parent_budget_lease_ref: str
    original_deadline_utc: float
    recovery_locator: str
    schema: str = ENVELOPE_SCHEMA

    def __post_init__(self):
        if self.schema != ENVELOPE_SCHEMA or type(self.namespace) is not NamespaceId:
            raise ValueError("exact mesh envelope schema/namespace required")
        if type(self.route) is not PersonalMeshRouteV1 or self.route.kind not in KINDS:
            raise ValueError("exact registered five-part mesh route required")
        for value in (self.causal_root, self.parent_stage, self.producer_original):
            if type(value) is not ProductionOriginalRefV1:
                raise TypeError("mesh carries original locators, never caller-supplied bodies")
        if type(self.payload) is not MeshPayloadRefV1 or self.payload.schema != self.route.schema:
            raise ValueError("typed payload schema must equal the exact registered route")
        for value in (self.request_ref, self.correlation_ref, self.producer_operation_id,
                self.parent_budget_lease_ref, self.recovery_locator):
            _text(value, "mesh original identity")
        for value in (self.producer_receipt_digest, self.source_closure_digest):
            _digest(value)
        if self.reality not in ("actual", "reported", "derived", "simulated"):
            raise ValueError("mesh preserves its actual reality qualification")
        if self.qualification not in ("candidate", "current_projection", "adopted", "observed", "declined", "unavailable", "unknown"):
            raise ValueError("unknown mesh qualification")
        if self.coverage not in ("complete", "partial", "unknown"):
            raise ValueError("mesh coverage must remain explicit")
        _tuple(self.read_versions, GraphVersion, 1024)
        _tuple(self.query_coverage, ProductionQueryCoverageV1, 64)
        _sources(self.source_roots, self.namespace)
        _tuple(self.audience, str, 32)
        _tuple(self.provider_policies, ProductionPolicyRefV1, 64)
        if type(self.owner_guard) is not ProductionOwnerGuardV1:
            raise TypeError("mesh records its actual Owner observation")
        if any(type(v) is not int or v < 0 for v in (self.activation_generation, self.storage_generation,
                self.access_epoch, self.delete_epoch)):
            raise ValueError("mesh generations are actual nonnegative counters")
        _tuple(self.cancellation_generations, tuple, 32)
        for pair in self.cancellation_generations:
            if (len(pair) != 2 or type(pair[0]) is not str or not pair[0]
                    or type(pair[1]) is not int or pair[1] < 0):
                raise ValueError("mesh preserves each actual cancellation locator/generation")
        if any(NamespaceId.from_key(v.key) != self.namespace for v in self.read_versions):
            raise ValueError("mesh read versions crossed namespace")
        if any(q.epoch.namespace != self.namespace for q in self.query_coverage):
            raise ValueError("mesh negative-query coverage crossed namespace")
        if type(self.original_deadline_utc) not in (int, float) or not math.isfinite(self.original_deadline_utc):
            raise ValueError("mesh requires the original absolute deadline")
        if len(canonical_serialize(self).encode("utf-8")) > 65536:
            raise ValueError("mesh envelope exceeds its closed metadata bound")

    @property
    def message_id(self):
        return "domain-mesh:" + canonical_digest(self)

    @property
    def dedupe_identity(self):
        return canonical_digest((self.namespace, self.route, self.request_ref, self.correlation_ref,
            self.payload, self.producer_operation_id))


@dataclass(frozen=True, slots=True)
class DomainProjectionRequestV1:
    envelope: DomainMeshEnvelopeV1

    def __post_init__(self):
        _message(self.envelope, "projectionRequest")


@dataclass(frozen=True, slots=True)
class DomainProjectionResultV1:
    envelope: DomainMeshEnvelopeV1
    unknown_refs: tuple[str, ...] = ()

    def __post_init__(self):
        _message(self.envelope, "projectionResult")
        _tuple(self.unknown_refs, str, 128)


@dataclass(frozen=True, slots=True)
class DomainEvidenceNoticeV1:
    envelope: DomainMeshEnvelopeV1

    def __post_init__(self):
        _message(self.envelope, "evidenceNotice")


@dataclass(frozen=True, slots=True)
class DomainOutcomeV1:
    envelope: DomainMeshEnvelopeV1

    def __post_init__(self):
        _message(self.envelope, "outcome")
        if self.envelope.qualification not in ("adopted", "observed", "declined", "unavailable", "unknown"):
            raise ValueError("outcome needs an actual adoption/observation or explicit refusal")


def _message(envelope, kind):
    if type(envelope) is not DomainMeshEnvelopeV1 or envelope.route.kind != kind:
        raise TypeError("mesh message variant differs from its exact route")


@dataclass(frozen=True, slots=True, kw_only=True)
class SemanticTickV1:
    namespace: NamespaceId
    activity_id: str
    recipe_version: str
    causal_original: ProductionOriginalRefV1
    owner_guard: ProductionOwnerGuardV1
    parent_budget_lease_ref: str
    original_deadline_utc: float
    source_roots: tuple[str, ...]
    source_closure: tuple[GraphVersion, ...]
    purpose: str
    audience: tuple[str, ...]
    provider_policies: tuple[ProductionPolicyRefV1, ...]
    storage_generation: int
    activation_generation: int
    access_epoch: int
    delete_epoch: int
    cancellation_generation: int
    wave: int
    stage_cursor: int
    mode: str
    state: str
    producer_operation_id: str
    producer_input_digest: str
    predecessors: tuple[ProductionOriginalRefV1, ...]
    semantic_originals: tuple[ProductionOriginalRefV1, ...]
    semantic_versions: tuple[GraphVersion, ...]
    semantic_digest: str
    semantic_history: tuple[str, ...]
    pending: tuple[MeshPendingIdentityV1, ...]
    wait: MeshWaitV1 | None
    read_versions: tuple[GraphVersion, ...]
    query_coverage: tuple[ProductionQueryCoverageV1, ...]
    schema: str = TICK_SCHEMA

    def __post_init__(self):
        if self.schema != TICK_SCHEMA or self.recipe_version not in RECIPES or type(self.namespace) is not NamespaceId:
            raise ValueError("closed installed semantic tick recipe required")
        if type(self.causal_original) is not ProductionOriginalRefV1 or type(self.owner_guard) is not ProductionOwnerGuardV1:
            raise TypeError("tick requires its actual causal original and Owner observation")
        for value in (self.activity_id, self.parent_budget_lease_ref, self.producer_operation_id):
            _text(value, "tick identity")
        _digest(self.producer_input_digest)
        if self.mode not in ("birth", "checkpoint", "wake", "observe"):
            raise ValueError("tick transition must use a closed validator mode")
        if self.state not in ("ready", "waiting", "stopped", "completed"):
            raise ValueError("tick records software progress, not character state")
        counters = (self.storage_generation, self.activation_generation, self.access_epoch, self.delete_epoch, self.cancellation_generation,
            self.wave, self.stage_cursor)
        if any(type(v) is not int or v < 0 for v in counters):
            raise ValueError("tick generations and cursors cannot regress")
        _sources(self.source_roots, self.namespace)
        _tuple(self.source_closure, GraphVersion, 1024)
        _text(self.purpose, "actual Source purpose")
        _tuple(self.audience, str, 32)
        _tuple(self.provider_policies, ProductionPolicyRefV1, 64)
        _tuple(self.predecessors, ProductionOriginalRefV1, 128)
        _tuple(self.semantic_originals, ProductionOriginalRefV1, 128)
        _tuple(self.semantic_versions, GraphVersion, 1024)
        _tuple(self.semantic_history, str, 128)
        _tuple(self.pending, MeshPendingIdentityV1, 32)
        _tuple(self.read_versions, GraphVersion, 1024)
        _tuple(self.query_coverage, ProductionQueryCoverageV1, 64)
        _digest(self.semantic_digest)
        for value in self.semantic_history:
            _digest(value)
        if self.wait is not None and type(self.wait) is not MeshWaitV1:
            raise TypeError("tick wait is a fixed typed predicate")
        if (self.state in ("waiting", "stopped")) != (self.wait is not None):
            raise ValueError("semantic stop/wait must preserve its concrete predicate")
        if self.state == "completed" and any(p.state != "observed" for p in self.pending):
            raise ValueError("unknown/in-flight obligations cannot disappear at completion")
        if type(self.original_deadline_utc) not in (int, float) or not math.isfinite(self.original_deadline_utc):
            raise ValueError("tick retains its actual finite absolute deadline")
        if len(canonical_serialize(self).encode("utf-8")) > 65536:
            raise ValueError("semantic tick exceeds its bounded metadata record")



@dataclass(frozen=True, slots=True)
class HabitCueObservationV1:
    namespace: NamespaceId
    policy_ref: str
    policy_revision: int
    window_id: str
    cue_original_ref: str
    cue_original_digest: str
    cue_stable_key: str
    clock_lower_utc: float
    clock_upper_utc: float
    execution_state: str
    predicate_digest: str
    source_refs: tuple[str, ...]
    producer_operation_id: str
    observation_original_ref: str
    observation_original_digest: str
    provider: str = "d11.habit-window-cue.v1"

    def __post_init__(self):
        key = AtomKey.from_token(self.policy_ref)
        if (self.provider != "d11.habit-window-cue.v1" or type(self.namespace) is not NamespaceId
                or key.type_name != "d10.habit_policy.v1" or NamespaceId.from_key(key) != self.namespace
                or type(self.policy_revision) is not int or self.policy_revision < 1
                or self.execution_state not in ("due", "skipped", "wait", "reschedule-required")
                or not self.clock_lower_utc <= self.clock_upper_utc):
            raise ValueError("Habit time cue preserves its actual policy/window/clock qualification")
        for value in (self.cue_original_digest, self.cue_stable_key, self.predicate_digest,
                self.observation_original_digest):
            _digest(value)
        if self.cue_stable_key != canonical_digest((self.namespace, key.name, self.window_id)):
            raise ValueError("Habit time cue cannot change its stable original window identity")
        if self.cue_original_ref != "habit-window-cue:" + self.cue_stable_key:
            raise ValueError("Habit time cue is the actual Core original locator")
        _sources(self.source_refs, self.namespace)
        for value in (self.window_id, self.producer_operation_id, self.observation_original_ref):
            _text(value, "actual Habit cue original")
        if any(type(t) not in (int, float) or not math.isfinite(t)
                for t in (self.clock_lower_utc, self.clock_upper_utc)):
            raise ValueError("Habit time cue preserves both finite trusted clock bounds")

    @property
    def occurred_at_utc(self):
        """Conservative observed lower edge; both original error bounds remain available."""
        return self.clock_lower_utc


def project_actual_habit_cue_v1(core_original, *, producer_original, producer_operation_id,
        predicate_digest, source_refs):
    """Project already verified Core/Graph originals; this function grants no rights."""
    from ..authority_service.d10_habit_contract_v1 import HabitWindowCueOriginalV1
    if (type(core_original) is not HabitWindowCueOriginalV1
            or type(producer_original) is not ProductionOriginalRefV1
            or producer_original.kind != "d11.current-record_habit_window_cue_v1"):
        raise TypeError("actual Core clock cue and its actual committed W01 wake original required")
    selector = core_original.selector
    return HabitCueObservationV1(selector.namespace, selector.policy_ref, selector.policy_revision,
        selector.window_id, core_original.original_ref, core_original.digest, selector.cue_stable_key,
        core_original.clock_lower_utc, core_original.clock_upper_utc, core_original.execution_state,
        predicate_digest, source_refs, producer_operation_id,
        producer_original.original_ref, producer_original.original_digest)

@dataclass(frozen=True, slots=True)
class PersonalMeshStageReadsetCompositionV1:
    selector_commitment: str
    core_qualification_readset_digest: str
    host_stage_readset_digest: str
    tick_keys: tuple[AtomKey, ...]
    expected_tick: GraphVersion
    core_read_versions: tuple[GraphVersion, ...]
    core_query_coverage: tuple[ProductionQueryCoverageV1, ...]
    core_source_closure: tuple[GraphVersion, ...]
    schema: str = "d11.personal-mesh-stage-readset-composition.v1"

    def __post_init__(self):
        if (self.schema != "d11.personal-mesh-stage-readset-composition.v1"
                or self.tick_keys != (self.expected_tick.key,)
                or any(len(value) != 64 for value in (self.selector_commitment,
                    self.core_qualification_readset_digest,self.host_stage_readset_digest))):
            raise ValueError("Personal mesh stage composition lost its independently observed readsets")

