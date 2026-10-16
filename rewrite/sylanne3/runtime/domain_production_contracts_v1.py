"""Bounded staging contracts for installed domain production operations.

These values describe authenticated reads and proposed work. They confer no
authority: the coordinator rechecks its installed Owner fence and all reads
before committing domain proposals, jobs, outbox, and originals together.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
import json
import math

from ..graph_types import AtomKey, GraphSnapshot, GraphVersion
from ..runtime_contracts import (
    CommandEnvelope, CommitReceipt, DomainProposal, NamespaceId, QueryEpoch,
    canonical_digest, canonical_serialize,
)
from .jobs import PersistentJob


SCHEMA = "sylanne.domain-production-operation.v1"


def _text(value: str, field: str) -> None:
    if type(value) is not str or not value or len(value) > 4096:
        raise ValueError(f"invalid production {field}")


def _digest(value: str, field: str) -> None:
    if type(value) is not str or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
        raise ValueError(f"invalid production {field} digest")


def _typed(values: tuple, kind: type, field: str) -> None:
    if type(values) is not tuple or any(type(value) is not kind for value in values):
        raise TypeError(f"production {field} requires a tuple of {kind.__name__}")


@dataclass(frozen=True, slots=True)
class ProductionOperationLimitsV1:
    max_source_roots: int = 32
    max_graph_heads: int = 1024
    max_query_rows: int = 128
    max_writes: int = 64
    max_followup_jobs: int = 16
    max_role_segments: int = 16

    def __post_init__(self) -> None:
        ceilings = (32, 1024, 128, 64, 16, 16)
        for (name, value), ceiling in zip(asdict(self).items(), ceilings, strict=True):
            if type(value) is not int or not 1 <= value <= ceiling:
                raise ValueError(f"installed production limit {name} exceeds its bound")


@dataclass(frozen=True, slots=True)
class ProductionOriginalRefV1:
    """Locator and commitment supplied by an installed current-original reader."""
    kind: str
    original_ref: str
    original_digest: str
    read_versions: tuple[GraphVersion, ...] = ()

    def __post_init__(self) -> None:
        _text(self.kind, "original kind")
        _text(self.original_ref, "original ref")
        _digest(self.original_digest, "original")
        _typed(self.read_versions, GraphVersion, "original reads")


@dataclass(frozen=True, slots=True)
class ProductionReadPlanV1:
    """Closed installed operation read recipe, with explicit absent targets."""
    fixed_type_ids: tuple[str, ...]
    exact_keys: tuple[AtomKey, ...]
    source_roots: tuple[str, ...]
    required_original_refs: tuple[str, ...]

    def __post_init__(self):
        _typed(self.exact_keys, AtomKey, "read plan keys")
        for name, limit in (("fixed_type_ids", 64), ("source_roots", 32), ("required_original_refs", 128)):
            values = getattr(self, name)
            if (type(values) is not tuple or len(values) > limit or len(set(values)) != len(values)
                    or any(type(value) is not str or not value for value in values)):
                raise ValueError("invalid bounded production " + name)
        if len(self.exact_keys) > 1024 or len(set(self.exact_keys)) != len(self.exact_keys):
            raise ValueError("production exact read keys exceed the installed bound")
        for ref in self.source_roots:
            if AtomKey.from_token(ref).type_name != "memory.source":
                raise ValueError("production source roots require exact D06 keys")


@dataclass(frozen=True, slots=True)
class ProductionPolicyRefV1:
    policy_ref: str
    revision: int
    policy_digest: str

    def __post_init__(self) -> None:
        _text(self.policy_ref, "policy ref")
        _digest(self.policy_digest, "policy")
        if type(self.revision) is not int or self.revision < 1:
            raise ValueError("production policy revision must be positive")


@dataclass(frozen=True, slots=True)
class ProductionOwnerGuardV1:
    grant_ref: str
    grant_revision: int
    grant_digest: str
    owner_head_digest: str

    def __post_init__(self) -> None:
        _text(self.grant_ref, "Owner grant ref")
        _digest(self.grant_digest, "Owner grant")
        _digest(self.owner_head_digest, "Owner head")
        if type(self.grant_revision) is not int or self.grant_revision < 1:
            raise ValueError("production Owner grant revision must be positive")


@dataclass(frozen=True, slots=True)
class ProductionQueryCoverageV1:
    """One actually observed page, including empty pages and a stable cursor."""
    epoch: QueryEpoch
    type_id: str
    row_versions: tuple[GraphVersion, ...]
    complete: bool
    continuation_ref: str | None

    def __post_init__(self) -> None:
        if type(self.epoch) is not QueryEpoch or type(self.complete) is not bool:
            raise TypeError("production query requires a typed epoch and coverage")
        _text(self.type_id, "query type")
        _typed(self.row_versions, GraphVersion, "query rows")
        if len(self.row_versions) > 128 or len({v.key for v in self.row_versions}) != len(self.row_versions):
            raise ValueError("production query page exceeds its bound or repeats a row")
        if any(NamespaceId.from_key(v.key) != self.epoch.namespace for v in self.row_versions):
            raise ValueError("production query page spans namespaces")
        if self.complete != (self.continuation_ref is None):
            raise ValueError("production partial query requires its continuation")
        if self.continuation_ref is not None:
            _text(self.continuation_ref, "query continuation")


@dataclass(frozen=True, slots=True)
class CurrentOperationFrameV1:
    envelope: CommandEnvelope
    snapshot: GraphSnapshot
    now_utc: float
    owner_guard: ProductionOwnerGuardV1
    activation_generation: int
    query_coverage: tuple[ProductionQueryCoverageV1, ...]
    installed_policy_refs: tuple[ProductionPolicyRefV1, ...]
    observed_originals: tuple[ProductionOriginalRefV1, ...]
    limits: ProductionOperationLimitsV1 = ProductionOperationLimitsV1()
    schema: str = SCHEMA

    def __post_init__(self) -> None:
        if self.schema != SCHEMA:
            raise TypeError("installed production frame schema differs")
        _validate_current_frame_fields_v1(self)
        if (type(self.now_utc) not in {float, int} or not math.isfinite(self.now_utc)
                or self.now_utc >= self.envelope.deadline_utc):
            raise ValueError("production frame time is invalid or expired")


def _validate_current_frame_fields_v1(frame):
    if (type(frame.envelope) is not CommandEnvelope or type(frame.snapshot) is not GraphSnapshot
            or type(frame.owner_guard) is not ProductionOwnerGuardV1
            or type(frame.limits) is not ProductionOperationLimitsV1):
        raise TypeError("installed production frame fields must be typed")
    if (type(frame.activation_generation) is not int or frame.activation_generation < 1
            or frame.activation_generation != frame.envelope.authority.activation_generation):
        raise ValueError("production frame generation differs from its command")
    _typed(frame.query_coverage, ProductionQueryCoverageV1, "query coverage")
    _typed(frame.installed_policy_refs, ProductionPolicyRefV1, "installed policies")
    _typed(frame.observed_originals, ProductionOriginalRefV1, "observed originals")
    ns = frame.envelope.authority.namespace
    if (len(frame.snapshot.atoms) > frame.limits.max_graph_heads
            or any(NamespaceId.from_key(atom.key) != ns for atom in frame.snapshot.atoms)
            or any(page.epoch.namespace != ns for page in frame.query_coverage)
            or any(len(page.row_versions) > frame.limits.max_query_rows for page in frame.query_coverage)):
        raise ValueError("production frame exceeds current namespace/read limits")


@dataclass(frozen=True, slots=True)
class CurrentOwnerStopProjectionFrameV1(CurrentOperationFrameV1):
    issuance: object = field(kw_only=True, repr=False, compare=False)
    schema: str = "d11.owner-stop-projection-frame.v1"

    def __post_init__(self):
        if self.schema != "d11.owner-stop-projection-frame.v1":
            raise TypeError("exact Stop projection metadata frame required")
        _validate_current_frame_fields_v1(self)
        if type(self.now_utc) not in {float, int} or not math.isfinite(self.now_utc):
            raise ValueError("Stop projection observation time must be finite")
        require_owner_stop_projection_frame_v1(self)


def require_owner_stop_projection_frame_v1(frame):
    from .foreground_activity_issuance_v1 import require_owner_stop_projection_issuance_v1
    if type(frame) is not CurrentOwnerStopProjectionFrameV1:
        raise TypeError("actual private Stop metadata frame required")
    issued = frame.issuance
    observed = require_owner_stop_projection_issuance_v1(issued, issued.graph, issued.scope)
    authority, identity = frame.envelope.authority, frame.envelope.identity
    if (identity.phase != "owner_stop_reply_v1" or authority.issuer_domain != "d11"
            or identity.operation_id != observed.initial_original.operation_id
            or authority.namespace != observed.request.namespace or authority.actor != observed.owner_actor_ref
            or frame.activation_generation != observed.permit.generation
            or frame.owner_guard != ProductionOwnerGuardV1(observed.owner_grant_ref,
                observed.owner_grant_revision, observed.owner_grant_digest,
                observed.owner_authorization.authorization_head.removeprefix("sha256:"))
            or frame.snapshot.versions != observed.read_versions
            or len(frame.snapshot.epochs) != 1 or frame.snapshot.epochs[0] != issued.scope.graph_epoch
            or set(frame.envelope.input_refs) != {observed.initial_original.original_ref}):
        raise ValueError("Stop metadata frame changed its actual private Owner/permit/read scope")
    return observed


@dataclass(frozen=True, slots=True)
class ProductionOutboxStageV1:
    namespace: NamespaceId
    causal_operation_id: str
    receiver_domain: str
    event_kind: str
    trigger_original: ProductionOriginalRefV1

    def __post_init__(self) -> None:
        if type(self.namespace) is not NamespaceId or type(self.trigger_original) is not ProductionOriginalRefV1:
            raise TypeError("production outbox requires a namespace and original")
        for name in ("causal_operation_id", "receiver_domain", "event_kind"):
            _text(getattr(self, name), name)
        if self.receiver_domain not in {f"d{i:02d}" for i in range(1, 14)}:
            raise ValueError("production outbox receiver is not registered")

    @property
    def dedupe_key(self) -> str:
        return canonical_digest((self.namespace, self.causal_operation_id, self.receiver_domain, self.event_kind))


@dataclass(frozen=True, slots=True)
class StagedDomainOperationV1:
    domain: str
    operation_kind: str
    namespace: NamespaceId
    activity_id: str
    operation_id: str
    request_digest: str
    read_versions: tuple[GraphVersion, ...]
    query_coverage: tuple[ProductionQueryCoverageV1, ...]
    proposals: tuple[DomainProposal, ...]
    jobs: tuple[PersistentJob, ...]
    outbox: tuple[ProductionOutboxStageV1, ...]
    original_payload_json: str
    original_digest: str
    paid_cost_originals: tuple[ProductionOriginalRefV1, ...]
    coverage: str
    missing_inputs: tuple[str, ...]
    continuation_ref: str | None
    schema: str = SCHEMA

    def __post_init__(self) -> None:
        if self.schema != SCHEMA or self.domain not in {f"d{i:02d}" for i in range(1, 14)}:
            raise ValueError("production staging schema/domain is invalid")
        if type(self.namespace) is not NamespaceId:
            raise TypeError("production staging namespace must be typed")
        for name in ("operation_kind", "activity_id", "operation_id"):
            _text(getattr(self, name), name)
        _digest(self.request_digest, "request")
        _digest(self.original_digest, "staged original")
        for name, kind in (("read_versions", GraphVersion), ("query_coverage", ProductionQueryCoverageV1),
                           ("proposals", DomainProposal), ("jobs", PersistentJob),
                           ("outbox", ProductionOutboxStageV1), ("paid_cost_originals", ProductionOriginalRefV1)):
            _typed(getattr(self, name), kind, name)
        if (len(self.read_versions) > 1024 or sum(len(p.typed_writes) for p in self.proposals) > 64
                or len(self.jobs) > 16 or len(self.outbox) > 16):
            raise ValueError("production staging exceeds its hard bounds")
        if any(NamespaceId.from_key(v.key) != self.namespace for v in self.read_versions):
            raise ValueError("production staging reads span namespaces")
        companions = tuple(p for p in self.proposals if p.domain != self.domain)
        if companions:
            from .d10_habit_v1 import habit_occurrence_companion_matches_v1
            from .habit_schedule_driver_v1 import habit_schedule_companion_matches_v1
            semantic = tuple(p for p in companions if not (
                habit_occurrence_companion_matches_v1(self,p) or habit_schedule_companion_matches_v1(self,p)))
            if semantic:
                from .domain_mesh_tick_v1 import require_semantic_mesh_stage_v1
                trace = require_semantic_mesh_stage_v1(self)
                if (len(semantic) != 1 or semantic[0].domain != 'd11'
                        or semantic[0].typed_writes != (trace.tick_write,)):
                    raise ValueError('Only exact named Habit companions and the unique signed D11 tick may cross domains')
        for p in self.proposals:
            if (p.envelope.authority.namespace != self.namespace
                    or p.envelope.identity.operation_id != self.operation_id
                    or p.envelope.identity.activity_id != self.activity_id):
                raise ValueError("production staging proposal identity/domain differs")
        if any((j.bot_id, j.persona_id, j.operation_id, j.activity_id) !=
               (self.namespace.bot_id, self.namespace.persona_id, self.operation_id, self.activity_id)
               for j in self.jobs):
            raise ValueError("production staging job identity differs")
        if any(o.namespace != self.namespace or o.causal_operation_id != self.operation_id for o in self.outbox):
            raise ValueError("production staging outbox identity differs")
        if self.coverage not in {"complete", "partial", "deferred", "waiting_for_original"}:
            raise ValueError("production staging coverage is invalid")
        if type(self.missing_inputs) is not tuple or any(type(v) is not str or not v for v in self.missing_inputs):
            raise ValueError("production staging missing inputs must be explicit")
        if self.coverage == "complete" and (self.missing_inputs or self.continuation_ref is not None):
            raise ValueError("complete production staging cannot omit work")
        if self.continuation_ref is not None:
            _text(self.continuation_ref, "staging continuation")
        payload = json.loads(self.original_payload_json)
        if canonical_serialize(payload) != self.original_payload_json or canonical_digest(payload) != self.original_digest:
            raise ValueError("production staging original bytes/commitment differ")


@dataclass(frozen=True, slots=True)
class DomainOperationReceiptV1:
    domain: str
    operation_kind: str
    namespace: NamespaceId
    activity_id: str
    operation_id: str
    request_digest: str
    prepared_original: ProductionOriginalRefV1 | None
    terminal_original: ProductionOriginalRefV1 | None
    adopted_original: ProductionOriginalRefV1
    commit_receipt: CommitReceipt
    commit_receipt_digest: str
    job_states: tuple[tuple[str, str], ...]
    paid_cost_originals: tuple[ProductionOriginalRefV1, ...]
    coverage: str
    missing_inputs: tuple[str, ...]
    continuation_ref: str | None
    schema: str = SCHEMA

    def __post_init__(self) -> None:
        if (self.schema != SCHEMA or type(self.namespace) is not NamespaceId
                or type(self.commit_receipt) is not CommitReceipt
                or type(self.adopted_original) is not ProductionOriginalRefV1):
            raise TypeError("production receipt requires actual typed originals and commit")
        _digest(self.request_digest, "receipt request")
        _digest(self.commit_receipt_digest, "receipt commit")
        if (self.commit_receipt.status not in {"committed", "duplicate"}
                or (self.commit_receipt.operation_id, self.commit_receipt.activity_id) !=
                   (self.operation_id, self.activity_id)
                or canonical_digest(self.commit_receipt) != self.commit_receipt_digest):
            raise ValueError("production receipt differs from its committed operation")
        for original in (self.prepared_original, self.terminal_original):
            if original is not None and type(original) is not ProductionOriginalRefV1:
                raise TypeError("production receipt originals must be typed")
        _typed(self.paid_cost_originals, ProductionOriginalRefV1, "receipt costs")
        if self.domain not in {f"d{i:02d}" for i in range(1, 14)}:
            raise ValueError("production receipt domain is not registered")
        if self.coverage not in {"complete", "partial", "deferred", "waiting_for_original"}:
            raise ValueError("production receipt coverage is invalid")
        if type(self.job_states) is not tuple or any(
                type(row) is not tuple or len(row) != 2 or any(type(v) is not str or not v for v in row)
                for row in self.job_states):
            raise ValueError("production receipt job states must be explicit")


def actual_frame_read_versions_v1(frame):
    """Pure stage readset; private Source frames add their actual header CAS facts."""
    from .named_joint_binding_write_v1 import named_joint_host_frame_read_versions_v3
    named=named_joint_host_frame_read_versions_v3(frame)
    if named is not None:return named
    from .current_habit_source_read_v3 import current_habit_frame_read_versions_v3
    from .semantic_recovery_source_v3 import current_semantic_recovery_frame_read_versions_v3
    cold=current_semantic_recovery_frame_read_versions_v3(frame)
    from .artifact_frame_control_reads_v3 import current_artifact_model_frame_read_versions_v3
    artifact=current_artifact_model_frame_read_versions_v3(frame)
    if artifact is not None:return artifact
    return current_habit_frame_read_versions_v3(frame)if cold is None else cold
