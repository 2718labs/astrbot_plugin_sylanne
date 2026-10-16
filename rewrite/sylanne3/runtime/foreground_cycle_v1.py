"""Finite foreground continuation on the existing PersistentJob/Graph ledger.
These SQL functions stage writes only. GraphCoordinator supplies the real
foreground-issued frame and commits job, guard, original and outbox together.
No model, tool, authority RPC or independent commit runs in this module.
"""
from ..authority_service.model_reply_scope_observation_v3 import model_reply_scope_point_v3,model_reply_scope_rows_v3
from .domain_background_read_v3 import background_json_loads_v3,background_json_matches_v3,background_json_digest_v3

from dataclasses import dataclass, replace
from datetime import datetime, timezone
import json
import math

from ..domains.d01.production_operations_v1 import plain_v1, stage_result_v1
from ..graph_types import AtomKey
from ..runtime_contracts import CommitReceipt, NamespaceId, QueryEpoch, VersionedRef, canonical_digest, canonical_serialize
from .d01_production_operations_v1 import CurrentDomainReadV1, MissingProductionOriginalV1, production_read_plan_v1
from .d11_types import D11RuntimeProvider, D11_PROPOSAL_SCHEMA, job_graph_write, runtime_job_key
from .foreground_call_plan_v1 import (
    ForegroundCallPlanV1, ForegroundCallPlanV2, ForegroundModelAttemptV2,
    foreground_call_plan_from_wire_v1, foreground_call_plan_from_wire_v2,
    require_foreground_phase_checkpoint_v2, require_protected_reply_budget_v1,
)
from .foreground_call_plan_v1 import (ForegroundReplyAllocationV1, foreground_reply_budget_ids_v1,
    prepare_foreground_reply_allocation_v1, apply_foreground_reply_allocation_v1)
from .ingress_observation import read_committed_ingress_identity
from .jobs import (PersistentJob, create_job, get_job, wake_job,
    acquire_job, plan_job_acquire, _utc, _utc_text, _save_job, _record_operation, _job_from_dict, _job_dict)
from .issuers import D11BudgetJobIssuer
from .domain_production_contracts_v1 import ProductionOwnerGuardV1
from ..model_broker.artifact_draft_v1 import ArtifactDraftTaskSelectorV1, ArtifactDraftPhaseSelectorV2
from ..memory_types import SourceRecord, source_key

WORK_KIND = "d11.foreground_cycle.v1"
PHASES = ("observe_current", "recall", "revise_plan", "select_step", "draft_content", "prepare_action",
    "execute_effect", "verify_effect", "adopt_progress", "reply_generation", "reply_review", "reply_dispatch", "completed")
SCHEMA = "d11.foreground-cycle-continuation.v1"


@dataclass(frozen=True, slots=True)
class CreateForegroundCycleRequestV1:
    c02_operation_id: str
    source_ref: str
    protected_reply_lease_ref: str


def foreground_deadline_utc_v1(bound):
    """Freeze the existing UTC wire precision conservatively within the exact bound."""
    if type(bound) not in {float, int} or not math.isfinite(bound):
        raise ValueError("foreground deadline requires an actual finite absolute UTC bound")
    wire_time = datetime.fromtimestamp(bound, timezone.utc)
    if wire_time.timestamp() > bound:
        from datetime import timedelta
        wire_time -= timedelta(microseconds=1)
    return wire_time.timestamp()


def foreground_post_c02_cause_ref_v1(namespace, c02_operation_id):
    if type(namespace) is not NamespaceId or type(c02_operation_id) is not str or not c02_operation_id:
        raise TypeError("foreground cause identity requires its actual namespace/C02 selector")
    return "foreground-cause:" + canonical_digest((namespace, c02_operation_id))[:48]


def foreground_responsibility_ref_v1(namespace, c02_operation_id):
    if type(namespace) is not NamespaceId or type(c02_operation_id) is not str or not c02_operation_id:
        raise TypeError("foreground responsibility identity requires its actual namespace/C02 selector")
    return "foreground-responsibility:" + canonical_digest((namespace, c02_operation_id))[:48]


@dataclass(frozen=True, slots=True, kw_only=True)
class CreateForegroundCycleRequestV2(CreateForegroundCycleRequestV1):
    cause_original_ref: str
    draft_root_registration_ref: str | None = None

    def __post_init__(self):
        if type(self.cause_original_ref) is not str or not self.cause_original_ref:
            raise ValueError("new foreground cycle requires its actual adopted cause locator")
        if self.draft_root_registration_ref is not None and (type(self.draft_root_registration_ref) is not str or not self.draft_root_registration_ref):
            raise ValueError("draft responsibility requires its exact existing root locator")


@dataclass(frozen=True, slots=True)
class ForegroundPostC02CauseV1:
    namespace: NamespaceId
    installation_id: str
    manifest_digest: str
    ingress_operation_id: str
    c02_operation_id: str
    source_ref: str
    source_revision: int
    source_digest: str
    c02_receipt_digest: str
    commit_seq: int
    foreground_policy_digest: str
    deadline_policy_digest: str
    clock_sample_digest: str
    cause_frozen_at_utc: float
    schema: str = "d11.foreground-post-c02-cause.v1"

    def __post_init__(self):
        if (self.schema != "d11.foreground-post-c02-cause.v1" or type(self.namespace) is not NamespaceId
                or NamespaceId.from_key(AtomKey.from_token(self.source_ref)) != self.namespace
                or AtomKey.from_token(self.source_ref).type_name != "memory.source"
                or type(self.source_revision) is not int or self.source_revision < 1
                or type(self.commit_seq) is not int or self.commit_seq < 1
                or type(self.cause_frozen_at_utc) is not float or not math.isfinite(self.cause_frozen_at_utc)):
            raise ValueError("foreground cause requires its exact new adopted C02/Source/clock facts")
        for value in (self.installation_id, self.ingress_operation_id, self.c02_operation_id):
            if type(value) is not str or not value or len(value) > 4096:
                raise ValueError("foreground cause original identity differs")
        for value in (self.manifest_digest, self.source_digest, self.c02_receipt_digest,
                self.foreground_policy_digest, self.deadline_policy_digest, self.clock_sample_digest):
            if type(value) is not str or len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
                raise ValueError("foreground cause original commitment differs")


@dataclass(frozen=True, slots=True)
class ForegroundResponsibilityV1:
    namespace: NamespaceId
    installation_id: str
    manifest_digest: str
    mode: str
    foreground_policy_ref: str
    foreground_policy_version: int
    foreground_policy_digest: str
    deadline_policy_digest: str
    ingress_operation_id: str
    c02_operation_id: str
    c02_receipt_digest: str
    c02_commit_seq: int
    source_ref: str
    source_revision: int
    source_digest: str
    cause_original_ref: str
    cause_original_digest: str
    cause_operation_id: str
    cause_commit_seq: int
    cause_frozen_at_utc: float
    root_registration_ref: str | None
    root_registration_digest: str | None
    root_setup_operation_id: str | None
    parent_grant_id: str
    parent_grant_version: int
    parent_grant_digest: str
    parent_budget_lease_ref: str
    self_mapping_ref: str
    self_mapping_digest: str
    owner_guard: "ProductionOwnerGuardV1"
    task_deadline_original_ref: str | None
    task_deadline_original_digest: str | None
    task_deadline_utc: float | None
    deadline_utc: float
    schema: str = "d11.foreground-responsibility.v1"

    def __post_init__(self):
        from .domain_production_contracts_v1 import ProductionOwnerGuardV1
        if (self.schema != "d11.foreground-responsibility.v1" or type(self.namespace) is not NamespaceId
                or self.mode not in {"bounded_causal_window_v1", "signed_scope_intersection_v1"}
                or type(self.owner_guard) is not ProductionOwnerGuardV1
                or type(self.deadline_utc) is not float or not math.isfinite(self.deadline_utc)
                or type(self.cause_frozen_at_utc) is not float or not math.isfinite(self.cause_frozen_at_utc)
                or self.deadline_utc <= self.cause_frozen_at_utc):
            raise ValueError("foreground responsibility has an invalid closed original scope/window")
        for value in (self.foreground_policy_version, self.c02_commit_seq, self.source_revision,
                self.cause_commit_seq, self.parent_grant_version):
            if type(value) is not int or value < 1:
                raise ValueError("foreground responsibility requires actual original positive versions")
        for value in (self.manifest_digest, self.foreground_policy_digest, self.deadline_policy_digest,
                self.c02_receipt_digest, self.source_digest, self.cause_original_digest, self.parent_grant_digest,
                self.self_mapping_digest, self.root_registration_digest, self.task_deadline_original_digest):
            if value is not None and (type(value) is not str or len(value) != 64 or any(char not in "0123456789abcdef" for char in value)):
                raise ValueError("foreground responsibility commitment differs")
        for ref in (self.source_ref, self.self_mapping_ref, self.owner_guard.grant_ref):
            if NamespaceId.from_key(AtomKey.from_token(ref)) != self.namespace:
                raise ValueError("foreground responsibility crossed its original namespace")
        if AtomKey.from_token(self.source_ref).type_name != "memory.source" or AtomKey.from_token(self.self_mapping_ref).type_name != "d03.self_identity_mapping.v1":
            raise ValueError("foreground responsibility actual Source/self locator types differ")
        roots = (self.root_registration_ref, self.root_registration_digest, self.root_setup_operation_id)
        if (self.mode == "signed_scope_intersection_v1" and not all(value is not None for value in roots)
                or self.mode == "bounded_causal_window_v1" and any(value is not None for value in roots)):
            raise ValueError("responsibility root fields differ from its exact natural/draft cause variant")
        if any(value is not None for value in (self.task_deadline_original_ref, self.task_deadline_original_digest, self.task_deadline_utc)):
            if (not all(value is not None for value in (self.task_deadline_original_ref, self.task_deadline_original_digest, self.task_deadline_utc))
                    or type(self.task_deadline_utc) is not float or not math.isfinite(self.task_deadline_utc)
                    or self.deadline_utc > self.task_deadline_utc):
                raise ValueError("foreground task bound requires its independent original and tighter time")

    @property
    def digest(self):
        return canonical_digest(plain_v1(self))


@dataclass(frozen=True, slots=True)
class AcquireForegroundCycleRequestV1:
    job_ref: str
    holder: str
    lease_seconds: int


@dataclass(frozen=True, slots=True)
class CheckpointForegroundCycleRequestV1:
    job_ref: str
    holder: str
    fence: int
    continuation: "ForegroundCycleContinuationV1"
    completion_result_ref: str | None = None


@dataclass(frozen=True, slots=True)
class WakeForegroundCycleRequestV1:
    job_ref: str
    dedupe_key: str


@dataclass(frozen=True, slots=True)
class InstalledForegroundCycleReadersV1:
    issuer: D11BudgetJobIssuer
    installed_bundle: object | None = None


@dataclass(frozen=True, slots=True)
class ForegroundCycleStageV1:
    frame: object
    stage: object
    request: object
    before_job: PersistentJob | None
    after_job: PersistentJob
    reply_allocation: ForegroundReplyAllocationV1 | None = None


@dataclass(frozen=True, slots=True)
class WakeArtifactDraftCycleRequestV1:
    selector: "ArtifactDraftTaskSelectorV1"
    dedupe_key: str

    def __post_init__(self):
        from ..model_broker.artifact_draft_v1 import ArtifactDraftTaskSelectorV1, artifact_draft_model_ids_v1
        if type(self.selector) is not ArtifactDraftTaskSelectorV1 or self.dedupe_key != canonical_digest((
                self.selector.namespace, artifact_draft_model_ids_v1(self.selector)["prepare"], "d11", "artifact_draft_model_queued")):
            raise ValueError("C4 wake requires its actual fixed prepared queued outbox selector")

    @property
    def job_ref(self):
        return self.selector.cycle_job_ref


@dataclass(frozen=True, slots=True)
class WakeArtifactDraftCycleRequestV2(WakeArtifactDraftCycleRequestV1):
    selector: ArtifactDraftPhaseSelectorV2

    def __post_init__(self):
        from ..model_broker.artifact_draft_v1 import artifact_draft_model_ids_v2
        if type(self.selector) is not ArtifactDraftPhaseSelectorV2 or not self.selector.generation:
            raise TypeError("phase wake requires its exact generation selector")
        if self.dedupe_key != canonical_digest((self.selector.task.namespace,
                artifact_draft_model_ids_v2(self.selector)["prepare"], "d11", "artifact_draft_phase_model_queued")):
            raise ValueError("phase wake changed its actual queued original identity")

    @property
    def job_ref(self):
        return self.selector.task.cycle_job_ref


@dataclass(frozen=True, slots=True)
class ForegroundWaitV1:
    producer_domain: str
    event_kind: str
    observed_versions: tuple[VersionedRef, ...]
    query_epoch: QueryEpoch
    consume_cursor: int
    next_due_utc: str | None = None

    def __post_init__(self):
        if (self.producer_domain not in {"d01", "d06", "d07", "d08", "d10", "d11"} or not self.event_kind
                or type(self.query_epoch) is not QueryEpoch or type(self.consume_cursor) is not int or self.consume_cursor < 0
                or type(self.observed_versions) is not tuple or len(self.observed_versions) > 128
                or any(type(row) is not VersionedRef for row in self.observed_versions)
                or len({row.ref for row in self.observed_versions}) != len(self.observed_versions)):
            raise ValueError("foreground waiting requires a bounded real producer/watermark")
        if self.next_due_utc is not None:
            from .jobs import _utc
            _utc(self.next_due_utc, "next_due_utc")


@dataclass(frozen=True, slots=True)
class ForegroundCycleContinuationV1:
    ingress_operation_id: str
    c02_operation_id: str
    source_ref: str
    source_revision: int
    source_barrier_epoch: int
    stage: str
    stage_cursor: int
    cancel_generation: int
    call_plan: ForegroundCallPlanV1
    pending_effect_refs: tuple[str, ...] = ()
    completed_operation_refs: tuple[str, ...] = ()
    wait: ForegroundWaitV1 | None = None
    schema: str = SCHEMA

    def __post_init__(self):
        _validate_foreground_continuation_v1(self, SCHEMA)


def _validate_foreground_continuation_v1(self, expected_schema):
    if (self.schema != expected_schema or self.stage not in PHASES or not self.ingress_operation_id or not self.c02_operation_id
            or AtomKey.from_token(self.source_ref).type_name != "memory.source"
            or type(self.source_revision) is not int or self.source_revision < 1
            or any(type(value) is not int or value < 0 for value in
                (self.source_barrier_epoch, self.stage_cursor, self.cancel_generation))
            or self.stage_cursor > len(PHASES)
            or type(self.call_plan) not in ({ForegroundCallPlanV1, ForegroundCallPlanV2}
                if expected_schema == SCHEMA_V2 else {ForegroundCallPlanV1})):
        raise ValueError("foreground continuation identity/stage/version differs")
    for name in ("pending_effect_refs", "completed_operation_refs"):
        values = getattr(self, name)
        if type(values) is not tuple or len(values) > 32 or len(set(values)) != len(values):
            raise ValueError("foreground continuation exceeds its finite reference window")
    if self.wait is not None and type(self.wait) is not ForegroundWaitV1:
        raise TypeError("foreground wait must use its actual typed watermark")
    if len(canonical_serialize(self).encode("utf-8")) > 65536:
        raise ValueError("foreground descriptor exceeds 64KiB")


SCHEMA_V2 = "d11.foreground-cycle-continuation.v2"


@dataclass(frozen=True, slots=True, kw_only=True)
class ForegroundCycleContinuationV2(ForegroundCycleContinuationV1):
    responsibility_ref: str
    responsibility_digest: str
    schema: str = SCHEMA_V2

    def __post_init__(self):
        _validate_foreground_continuation_v1(self, SCHEMA_V2)
        if (type(self.responsibility_ref) is not str or not self.responsibility_ref.startswith("foreground-responsibility:")
                or type(self.responsibility_digest) is not str or len(self.responsibility_digest) != 64
                or any(char not in "0123456789abcdef" for char in self.responsibility_digest)):
            raise ValueError("new foreground continuation requires its immutable actual responsibility original")


@dataclass(frozen=True, slots=True)
class CheckpointForegroundCycleRequestV2(CheckpointForegroundCycleRequestV1):
    continuation: ForegroundCycleContinuationV2

    def __post_init__(self):
        if type(self.continuation) is not ForegroundCycleContinuationV2:
            raise TypeError("new foreground checkpoint must retain its exact responsibility continuation variant")


def foreground_cycle_from_wire_v1(value):
    if type(value) is not dict:
        raise ValueError("foreground continuation must be an exact versioned object")
    variants = {SCHEMA: ForegroundCycleContinuationV1, SCHEMA_V2: ForegroundCycleContinuationV2}
    if value.get("schema") == "d11.foreground-source-note-continuation.v1":
        from .source_note_foreground_v1 import ForegroundSourceNoteContinuationV1
        variants["d11.foreground-source-note-continuation.v1"] = ForegroundSourceNoteContinuationV1
    variant = variants.get(value.get("schema"))
    if variant is None or set(value) != set(variant.__dataclass_fields__):
        raise ValueError("foreground continuation fields differ from its exact retained version")
    raw = dict(value)
    raw["call_plan"] = (foreground_call_plan_from_wire_v2(raw["call_plan"])
        if type(raw["call_plan"]) is dict and raw["call_plan"].get("schema") == "d11.foreground-call-plan.v2"
        else foreground_call_plan_from_wire_v1(raw["call_plan"]))
    for name in ("pending_effect_refs", "completed_operation_refs"):
        raw[name] = tuple(raw[name])
    if raw["wait"] is not None:
        from ..runtime_contracts import NamespaceId
        wait = dict(raw["wait"])
        wait["observed_versions"] = tuple(VersionedRef(**row) for row in wait["observed_versions"])
        epoch = dict(wait["query_epoch"])
        epoch["namespace"] = NamespaceId(**epoch["namespace"])
        wait["query_epoch"] = QueryEpoch(**epoch)
        raw["wait"] = ForegroundWaitV1(**wait)
    return variant(**raw)


def decode_foreground_job_v1(raw, *, namespace=None):
    """Closed storage decoder shared by current jobs, historical receipts and C09."""
    from dataclasses import fields
    from ..runtime_contracts import NamespaceId
    from .jobs import _identifier
    if type(raw) is not dict or set(raw) != {field.name for field in fields(PersistentJob)}:
        raise ValueError("foreground PersistentJob fields differ from its exact installed schema")
    if (raw["work_kind"] != WORK_KIND or raw["effect_id"] is not None
            or type(raw["operator_versions"]) is not dict or raw["operator_versions"] not in ({}, {"d11.personal-semantic-mesh":"1"})
            or type(raw["usage"]) is not dict or raw["usage"] != {}
            or any(type(raw[name]) is not int for name in ("fence", "cancel_epoch"))):
        raise ValueError("foreground job work/operator/usage/effect fields differ from its actual producer")
    continuation = foreground_cycle_from_wire_v1(raw["continuation"])
    ns = NamespaceId(raw["bot_id"], raw["persona_id"])
    if namespace is not None and ns != namespace:
        raise ValueError("foreground job crossed its actual current/storage namespace")
    for value in (continuation.ingress_operation_id, continuation.c02_operation_id,
            *continuation.pending_effect_refs, *continuation.completed_operation_refs):
        _identifier(value, "foreground original identity")
    if NamespaceId.from_key(AtomKey.from_token(continuation.source_ref)) != ns:
        raise ValueError("foreground continuation Source belongs to another namespace")
    activity_id, job_id = foreground_cycle_ids_v1(ns, continuation.c02_operation_id)
    marker = canonical_digest((ns, continuation.c02_operation_id))[:40]
    if (raw["activity_id"] != activity_id or raw["job_id"] != job_id
            or raw["snapshot_ref"] != "foreground:" + marker or raw["resource_ref"] != "foreground-cycle:" + marker
            or raw["budget_ref"] != continuation.call_plan.parent_budget_lease_ref
            or continuation.call_plan.parent_budget_lease_ref == continuation.call_plan.protected_reply_lease_ref):
        raise ValueError("foreground job origin/activity/budget/resource differs from its actual finite producer")
    if raw["phase"] in {"queued", "running", "waiting", "deferred", "completed"}:
        if raw["cancel_epoch"] != continuation.cancel_generation or raw["cancel_epoch"]:
            raise ValueError("foreground current/resumable job has a conflicting cancellation generation")
    elif raw["cancel_epoch"] < continuation.cancel_generation:
        raise ValueError("foreground retired job lost its original cancellation generation")
    if continuation.wait is not None:
        if continuation.wait.query_epoch.namespace != ns:
            raise ValueError("foreground wait watermark belongs to another namespace")
        for version in continuation.wait.observed_versions:
            if NamespaceId.from_key(AtomKey.from_token(version.ref)) != ns:
                raise ValueError("foreground watched fact belongs to another namespace")
    expected_wake = plain_v1(continuation.wait) if raw["phase"] == "waiting" else None
    if raw["wake_condition"] != expected_wake:
        raise ValueError("foreground durable wake differs from its exact original registered condition")
    if raw["phase"] == "running" and (raw["lease_holder"] is None or not raw["lease_holder"].startswith("entity:")
            or raw["fence"] < 1 or raw["lease_expires_utc"] is None):
        raise ValueError("foreground worker lease must retain its actual independently registered self")
    if raw["phase"] == "completed" and (continuation.stage != "completed" or continuation.pending_effect_refs or raw["result_ref"] is None):
        raise ValueError("completed foreground storage cannot discard an unknown effect or its actual reply result")
    if continuation.stage == "completed" and raw["phase"] != "completed":
        raise ValueError("foreground completed continuation disagrees with its actual job phase")
    if len(canonical_serialize(raw).encode("utf-8")) > 65536:
        raise ValueError("foreground retained job exceeds the actual descriptor byte limit")
    job = PersistentJob(**raw)
    if job.lease_expires_utc is not None and _utc(job.lease_expires_utc, "lease_expires_utc") > _utc(job.deadline_utc, "deadline_utc"):
        raise ValueError("foreground worker lease exceeds its original job deadline")
    return job


def foreground_job_source_refs_v1(job):
    decoded = decode_foreground_job_v1(plain_v1(job))
    continuation = foreground_cycle_from_wire_v1(decoded.continuation)
    refs = {continuation.source_ref}
    if continuation.wait is not None:
        refs.update(version.ref for version in continuation.wait.observed_versions
            if AtomKey.from_token(version.ref).type_name == "memory.source")
    return tuple(sorted(refs))


def foreground_cycle_ids_v1(namespace, c02_operation_id):
    tag = canonical_digest((namespace, c02_operation_id))[:40]
    return "foreground-activity:" + tag, "foreground-job:" + tag


def prepare_foreground_cycle_in_transaction_v1(db, *, frame, c02_receipt, source_ref, call_plan, issuer, reply_allocation=None, responsibility=None):
    if type(c02_receipt) is not CommitReceipt or type(issuer) is not D11BudgetJobIssuer or type(call_plan) is not ForegroundCallPlanV1:
        raise TypeError("foreground cycle requires actual C02, budget and installed issuer")
    read = CurrentDomainReadV1(frame)
    read.check(db)
    ns = frame.envelope.authority.namespace
    source = read.head(db, source_ref, required=True)
    record = SourceRecord.from_dict(source.value)
    ingress = read_committed_ingress_identity(db, ns, record.source_id)
    if ingress is None:
        raise MissingProductionOriginalV1("actual_foreground_ingress_identity")
    ingress_id = json.loads(ingress.identity_json)["operation_id"]
    actual = db.execute("SELECT digest,activity_id,effect_id,commit_seq FROM graph_bundle_operations WHERE bot=? AND persona=? AND operation_id=?",
        (*ns.as_tuple, c02_receipt.operation_id)).fetchone()
    if actual != (c02_receipt.operation_digest, c02_receipt.activity_id, c02_receipt.effect_id, c02_receipt.commit_seq):
        raise ValueError("foreground cycle C02 receipt differs from the actual committed operation")
    episodes = tuple(version for version in c02_receipt.write_versions if version.key.type_name == "memory.episode.v1")
    traces = tuple(version for version in c02_receipt.write_versions if version.key.type_name == "memory.subjective_trace.v2")
    if len(episodes) != 1 or len(traces) != 1:
        raise MissingProductionOriginalV1("actual_foreground_c02_episode_and_trace")
    for version in (*episodes, *traces):
        atom = read.head(db, version.key, required=True)
        history = db.execute("SELECT event_id,value,valid FROM graph_history WHERE token=? AND revision=?",
            (version.key.token, version.revision)).fetchone()
        linked = (source_ref in atom.value["source_refs"] if version.key.type_name == "memory.episode.v1"
            else atom.value["episode_ref"] == episodes[0].key.token)
        if (atom.revision != version.revision or history != (c02_receipt.operation_id, canonical_serialize(atom.value), 1) or not linked):
            raise ValueError("foreground C02 member/source history differs")
    read.source_family(db, (source_ref,))
    if type(reply_allocation) is not ForegroundReplyAllocationV1 or (
            reply_allocation.namespace, reply_allocation.c02_operation_id, reply_allocation.parent_lease_ref,
            reply_allocation.child_lease_id) != (ns, c02_receipt.operation_id, call_plan.parent_budget_lease_ref, call_plan.protected_reply_lease_ref):
        raise ValueError("foreground create needs its pure actual installed reply allocation proposal")
    activity_id, job_id = foreground_cycle_ids_v1(ns, c02_receipt.operation_id)
    if frame.envelope.identity.activity_id != activity_id or frame.envelope.parent_budget_lease_ref != call_plan.parent_budget_lease_ref:
        raise ValueError("foreground creation changed its adopted origin or budget family")
    key = runtime_job_key(*ns.as_tuple, activity_id, job_id)
    previous = read.head(db, key)
    if previous.revision:
        job = get_job(db, job_id)
        continuation = foreground_cycle_from_wire_v1(job.continuation)
        if (continuation.c02_operation_id, continuation.source_ref, job.activity_id, job.budget_ref) != (
                c02_receipt.operation_id, source_ref, activity_id, call_plan.parent_budget_lease_ref):
            raise ValueError("foreground retry changed its original cycle")
        return job, None
    active = db.execute("SELECT COUNT(*) FROM runtime_jobs WHERE phase NOT IN ('completed','failed','cancelled')").fetchone()[0]
    if active >= 256:
        raise MissingProductionOriginalV1("available_global_foreground_descriptor")
    continuation = ForegroundCycleContinuationV1(ingress_id, c02_receipt.operation_id, source_ref, source.revision,
        frame.envelope.version_guard.access_epoch, "observe_current", 0, 0, call_plan)
    if responsibility is not None:
        if (type(responsibility) is not ForegroundResponsibilityV1 or responsibility.deadline_utc != frame.envelope.deadline_utc
                or responsibility.c02_operation_id != c02_receipt.operation_id or responsibility.source_ref != source_ref):
            raise ValueError("new foreground job must use its exact independently derived responsibility deadline")
        continuation = ForegroundCycleContinuationV2(ingress_id, c02_receipt.operation_id, source_ref, source.revision,
            frame.envelope.version_guard.access_epoch, "observe_current", 0, 0, call_plan,
            responsibility_ref=foreground_responsibility_ref_v1(ns, c02_receipt.operation_id),
            responsibility_digest=responsibility.digest)
    from datetime import datetime, timezone
    deadline = datetime.fromtimestamp(frame.envelope.deadline_utc, timezone.utc).isoformat().replace("+00:00", "Z")
    job = PersistentJob(job_id, frame.envelope.identity.operation_id, activity_id, None, *ns.as_tuple,
        "foreground:" + canonical_digest((ns, c02_receipt.operation_id))[:40], "queued", WORK_KIND,
        plain_v1(continuation), None, deadline, call_plan.parent_budget_lease_ref,
        "foreground-cycle:" + canonical_digest((ns, c02_receipt.operation_id))[:40], {"d11.personal-semantic-mesh":"1"} if responsibility is not None else {}, None, None, 0, 0, {}, None)
    stage = stage_result_v1(frame, "d11", "create_foreground_cycle", (c02_receipt.operation_id, source_ref),
        writes=(job_graph_write(job),), provenance={"continuation": continuation, "c02_receipt": c02_receipt},
        receiver_events=(("d11", "foreground_cycle_ready"),), proposal_schema=D11_PROPOSAL_SCHEMA,
        proposal_hash=D11RuntimeProvider().descriptor.request_schema_hash)
    return job, stage


def checkpoint_foreground_cycle_in_transaction_v1(db, *, frame, job_id, holder, fence, continuation, usage,
        completion_result_ref=None, method_completion_history=None, frame_issuer=None, frame_bundle=None):
    read = CurrentDomainReadV1(frame)
    read.check(db)
    job = get_job(db, job_id)
    atom = read.head(db, job_graph_write(job).key, required=True)
    old = foreground_cycle_from_wire_v1(job.continuation)
    from .source_note_foreground_v1 import ForegroundSourceNoteContinuationV1
    if atom.value != job_graph_write(job).value or type(continuation) not in {ForegroundCycleContinuationV1, ForegroundCycleContinuationV2, ForegroundSourceNoteContinuationV1}:
        raise ValueError("foreground current job projection/continuation differs")
    if (continuation.ingress_operation_id, continuation.c02_operation_id, continuation.source_ref) != (
            old.ingress_operation_id, old.c02_operation_id, old.source_ref):
        raise ValueError("foreground phase cannot replace its ingress origin")
    if continuation.stage_cursor < old.stage_cursor or continuation.cancel_generation != job.cancel_epoch:
        raise ValueError("foreground phase cursor/cancellation is stale")
    if not set(old.completed_operation_refs) <= set(continuation.completed_operation_refs):
        raise ValueError("foreground phase cannot forget a completed original")
    if (continuation.call_plan.parent_budget_lease_ref, continuation.call_plan.protected_reply_lease_ref) != (
            old.call_plan.parent_budget_lease_ref, old.call_plan.protected_reply_lease_ref):
        raise ValueError("foreground checkpoint cannot replace its actual budget family")
    require_foreground_phase_checkpoint_v2(old.call_plan, continuation.call_plan)
    attempts = {row.call_id: row for row in continuation.call_plan.attempts}
    for prior in old.call_plan.attempts:
        current = attempts.get(prior.call_id)
        if current is None or (current.slot, current.original_call_id, current.reservation_operation_id,
                current.reservation_digest, current.budget_lease_ref, current.input_ceiling, current.output_ceiling) != (
                prior.slot, prior.original_call_id, prior.reservation_operation_id, prior.reservation_digest,
                prior.budget_lease_ref, prior.input_ceiling, prior.output_ceiling):
            raise ValueError("foreground checkpoint lost or replaced an actual model attempt")
    for operation in set(continuation.completed_operation_refs) - set(old.completed_operation_refs):
        read.committed_operation(db, operation)
    if (not PHASES.index(old.stage) <= PHASES.index(continuation.stage) <= PHASES.index(old.stage) + 1
            or continuation.stage_cursor > old.stage_cursor + 1):
        raise ValueError("foreground phase cannot regress or skip its finite cursor")
    if (continuation.stage == old.stage and continuation.wait is None
            and continuation.call_plan == old.call_plan
            and continuation.completed_operation_refs == old.completed_operation_refs
            and continuation.pending_effect_refs == old.pending_effect_refs):
        raise MissingProductionOriginalV1("new_fact_or_registered_foreground_wait_condition")
    _verify_pending_effect_changes_v1(db, frame.envelope.authority.namespace, old, continuation)
    if job.phase != "running" or job.cancel_epoch or (job.lease_holder, job.fence) != (holder, fence):
        raise ValueError("foreground checkpoint needs its actual uncancelled running worker")
    if _utc(job.lease_expires_utc, "lease_expires_utc").timestamp() <= frame.now_utc:
        raise ValueError("foreground checkpoint worker lease expired")
    if usage != job.usage:
        raise ValueError("foreground metadata checkpoint cannot invent resource usage")
    updated = replace(job, continuation=plain_v1(continuation))
    if continuation.wait is not None:
        updated = replace(updated, phase="waiting", wake_condition=plain_v1(continuation.wait), lease_holder=None, lease_expires_utc=None)
        # Registration and this recheck occur in the same pinned transaction.
        changed = any(read.head(db, row.ref).revision != row.version for row in continuation.wait.observed_versions)
        epoch = frame.snapshot.epochs[0].revision
        changed |= continuation.wait.query_epoch.revision != epoch
        if changed:
            updated = replace(updated, phase="queued", wake_condition=None)
    elif continuation.stage == "completed":
        from .d07_reflection_execution_v1 import require_no_pending_self_reflection_v3
        require_no_pending_self_reflection_v3(db,frame=frame,job=job,continuation=continuation,
            issuer=frame_issuer,installed_bundle=frame_bundle)
        if type(continuation.call_plan) is ForegroundCallPlanV2:
            from ..model_broker.artifact_draft_v1 import artifact_draft_phase_sequence_v2
            group = continuation.call_plan.phase_group
            if len(group.completed_phase_originals) != len(artifact_draft_phase_sequence_v2(group.selector.method_ref)):
                raise MissingProductionOriginalV1("actual_complete_verified_artifact_phase_chain")
            if method_completion_history is None:
                raise MissingProductionOriginalV1('actual_signed_method_Goal_settlement_history_before_cycle_completion')
            from .d11_artifact_draft_content_v1 import ArtifactDraftMethodSettlementHistoryV2,require_artifact_method_settlement_history_v2
            from .domain_production_originals_v1 import read_adopted_domain_operation_v1
            if type(method_completion_history) is not ArtifactDraftMethodSettlementHistoryV2:
                raise TypeError('exact completed method history required at final cycle checkpoint')
            actual=read_adopted_domain_operation_v1(db,frame.envelope.authority.namespace,method_completion_history.settlement_operation_id)
            if actual is None or require_artifact_method_settlement_history_v2(db,namespace=frame.envelope.authority.namespace,
                    original=actual,raw=actual['payload']['provenance']['artifact_method_completion'])!=method_completion_history:
                raise ValueError('cycle final checkpoint cannot invent a completed Goal method history')
        if continuation.pending_effect_refs:
            raise ValueError("foreground UNKNOWN effects cannot disappear at completion")
        if any(not any(row.slot == slot and row.state == "completed" for row in continuation.call_plan.attempts)
                for slot in ("C5", "C6")):
            raise ValueError("foreground reply completion requires actual generation and independent review originals")
        if completion_result_ref is None or completion_result_ref not in continuation.completed_operation_refs:
            raise ValueError("foreground completion requires its actual adopted reply result operation")
        _require_actual_delivered_foreground_reply_v1(db, frame=frame, continuation=continuation,
            completion_result_ref=completion_result_ref)
        updated = replace(updated, phase="completed", result_ref=completion_result_ref,
            wake_condition=None, lease_holder=None, lease_expires_utc=None)
    stage = stage_result_v1(frame, "d11", "checkpoint_foreground_cycle", (job_id, continuation.stage_cursor),
        writes=(job_graph_write(updated),), provenance={"continuation": continuation},
        receiver_events=(("d11", "foreground_cycle_ready"),) if updated.phase == "queued" else (),
        proposal_schema=D11_PROPOSAL_SCHEMA, proposal_hash=D11RuntimeProvider().descriptor.request_schema_hash)
    return updated, stage


def wake_foreground_cycle_from_outbox_in_transaction_v1(db, *, frame, job_id, dedupe_key, issuer):
    read = CurrentDomainReadV1(frame)
    read.check(db)
    job = get_job(db, job_id)
    read.head(db, job_graph_write(job).key, required=True)
    continuation = foreground_cycle_from_wire_v1(job.continuation)
    if type(issuer) is not D11BudgetJobIssuer:
        raise TypeError("foreground outbox recovery needs the installed original issuer")
    from .domain_followup_consumer_v1 import _event
    event, _, _, _ = _event(db, frame.envelope.authority.namespace, dedupe_key, issuer)
    if job.phase not in {"waiting", "deferred"}:
        return job, None
    if continuation.wait is None:
        raise ValueError("foreground wake has no durable registered condition")
    if any(attempt.slot == "C4" for attempt in continuation.call_plan.attempts):
        raise ValueError("C4 terminal wait requires the registered strict artifact wake compiler")
    if event.receiver_domain != "d11" or event.event_kind != continuation.wait.event_kind:
        raise ValueError("outbox wake belongs to another registered condition")
    if not event.trigger_original.kind.startswith(continuation.wait.producer_domain + "."):
        raise ValueError("foreground wake original has a different registered producer")
    changed = any(read.head(db, row.ref).revision != row.version for row in continuation.wait.observed_versions)
    changed |= continuation.wait.query_epoch.revision != frame.snapshot.epochs[0].revision
    if not changed:
        raise MissingProductionOriginalV1("changed_foreground_wait_condition")
    updated = replace(job, phase="queued", wake_condition=None)
    stage = stage_result_v1(frame, "d11", "wake_foreground_cycle", (job_id, dedupe_key),
        writes=(job_graph_write(updated),), provenance={"original_job": job_id, "dedupe_key": dedupe_key},
        proposal_schema=D11_PROPOSAL_SCHEMA, proposal_hash=D11RuntimeProvider().descriptor.request_schema_hash)
    return updated, stage


def wake_artifact_draft_cycle_in_transaction_v1(db, *, frame, request, issuer):
    from ..model_broker.artifact_draft_v1 import artifact_draft_model_ids_v1
    from .d11_artifact_draft_model_v1 import (read_artifact_draft_prepared_v1,
        read_current_artifact_draft_attempt_v1, decode_artifact_draft_original_v1)
    from .d11_life_preparation_v1 import _read
    from .c09_life_originals_v1 import require_c4_model_cost_original_commit_v1
    if type(request) is not WakeArtifactDraftCycleRequestV1:
        raise TypeError("exact registered C4 terminal wake required")
    read = CurrentDomainReadV1(frame)
    read.check(db)
    ns = frame.envelope.authority.namespace
    if request.selector.namespace != ns:
        raise ValueError("C4 terminal wake crossed namespace")
    cycle = get_job(db, AtomKey.from_token(request.job_ref).name)
    current = foreground_cycle_from_wire_v1(cycle.continuation)
    if (cycle.phase != "waiting" or cycle.cancel_epoch or current.wait is None
            or cycle.lease_holder is not None or cycle.lease_expires_utc is not None
            or read.head(db, request.job_ref, required=True).value != job_graph_write(cycle).value):
        raise ValueError("C4 wake requires the actual waiting unleased SQL/Graph cycle")
    ids = artifact_draft_model_ids_v1(request.selector)
    prepared = read_artifact_draft_prepared_v1(db, namespace=ns, issuer=issuer, selector=request.selector)
    if prepared is None:
        raise MissingProductionOriginalV1("actual_c4_prepared_for_terminal_wake")
    if (current.c02_operation_id != request.selector.c02_operation_id
            or cycle.budget_ref != prepared.parent_budget_lease_ref
            or prepared.actor_ref != frame.envelope.authority.actor
            or current.wait.event_kind not in {"artifact_draft_model_queued", "artifact_draft_model_terminal"}):
        raise ValueError("C4 terminal wake changed its original task/self/wait")
    attempts = tuple(attempt for attempt in current.call_plan.attempts if attempt.slot == "C4")
    if len(attempts) != 1:
        raise ValueError("C4 wake must retain its actual single chosen model call")
    actual = read_current_artifact_draft_attempt_v1(db, namespace=ns, continuation=current, attempt=attempts[0], issuer=issuer)
    if actual.state != "completed" or actual.terminal_ref != ids["result"]:
        raise MissingProductionOriginalV1("actual_paid_signed_c4_terminal_result")
    call = _read(db, issuer=issuer, namespace=ns, kind="c4_call", ref=prepared.call_id)
    paid = _read(db, issuer=issuer, namespace=ns, kind="c4_paid", ref=ids["paid"])
    result = _read(db, issuer=issuer, namespace=ns, kind="c4_result", ref=ids["result"])
    if call is None or paid is None or result is None:
        raise MissingProductionOriginalV1("actual_c4_call_paid_result_for_terminal_wake")
    cost = decode_artifact_draft_original_v1("c4_paid", paid[0])
    require_c4_model_cost_original_commit_v1(db, namespace=ns, operation_id=cost.operation_id)
    event = db.execute("SELECT causal_operation_id,receiver_domain,event_kind,original_ref,original_digest,state "
        "FROM graph_domain_production_outbox_v1 WHERE bot=? AND persona=? AND dedupe_key=?",
        (*ns.as_tuple, request.dedupe_key)).fetchone()
    read.committed_operation(db, ids["prepare"])
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    adopted = read_adopted_domain_operation_v1(db, ns, ids["prepare"])
    if (adopted is None or event != (ids["prepare"], "d11", "artifact_draft_model_queued",
            "d11-current:" + adopted["original_digest"][:48], adopted["original_digest"], "pending")):
        raise ValueError("C4 wake is not linked to its actual original queued prepare outbox")
    after = replace(cycle, phase="queued", wake_condition=None)
    stage = stage_result_v1(frame, "d11", "wake_artifact_draft_cycle_v1", request,
        writes=(job_graph_write(after),), provenance={"before_job": cycle, "after_job": after,
            "queued_dedupe_key": request.dedupe_key, "prepared_digest": prepared.digest,
            "paid_ref": ids["paid"], "paid_digest": canonical_digest(paid[0]),
            "result_ref": ids["result"], "result_digest": canonical_digest(result[0])},
        proposal_schema=D11_PROPOSAL_SCHEMA, proposal_hash=D11RuntimeProvider().descriptor.request_schema_hash)
    return after, stage


def record_artifact_draft_wake_disposition_after_cas_v1(db, *, stage, receipt):
    """Dispose the original queued event in the actual self wake transaction."""
    if type(stage) is ForegroundCycleStageV1 and type(stage.request) is WakeArtifactDraftCycleRequestV2:
        return record_artifact_draft_wake_disposition_after_cas_v2(db, stage=stage, receipt=receipt)
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    if (not db.in_transaction or type(stage) is not ForegroundCycleStageV1
            or type(stage.request) is not WakeArtifactDraftCycleRequestV1 or type(receipt) is not CommitReceipt
            or receipt.status != "committed" or receipt.operation_id != stage.stage.operation_id
            or get_job(db, stage.after_job.job_id) != stage.after_job):
        raise ValueError("C4 wake disposition requires its actual same-CAS self receipt/job")
    ns = stage.stage.namespace
    adopted = read_adopted_domain_operation_v1(db, ns, receipt.operation_id)
    provenance = json.loads(stage.stage.original_payload_json)["provenance"]
    if adopted is None or adopted["operation_kind"] != "wake_artifact_draft_cycle_v1" or adopted["receipt"] != receipt:
        raise MissingProductionOriginalV1("actual_adopted_self_C4_terminal_wake")
    row = db.execute("SELECT causal_operation_id,event_kind,original_ref,original_digest,state "
        "FROM graph_domain_production_outbox_v1 WHERE bot=? AND persona=? AND dedupe_key=?",
        (*ns.as_tuple, stage.request.dedupe_key)).fetchone()
    if row is None or row[1] != "artifact_draft_model_queued" or row[4] != "pending":
        raise ValueError("C4 self wake lost its original unconsumed queued cause")
    value = {"schema": "d11.artifact-draft-wake-disposition.v1", "dedupe_key": stage.request.dedupe_key,
        "causal_operation_id": row[0], "trigger_original_ref": row[2], "trigger_original_digest": row[3],
        "state": "completed", "consumer_operation_id": receipt.operation_id,
        "consumer_original_digest": adopted["original_digest"], "consumer_receipt_digest": canonical_digest(receipt),
        "cycle_job_ref": stage.request.selector.cycle_job_ref, "prepared_digest": provenance["prepared_digest"],
        "paid_ref": provenance["paid_ref"], "paid_digest": provenance["paid_digest"],
        "result_ref": provenance["result_ref"], "result_digest": provenance["result_digest"]}
    db.execute("UPDATE graph_domain_production_outbox_v1 SET state='completed',consumer_operation_id=?,receipt_json=? "
        "WHERE bot=? AND persona=? AND dedupe_key=? AND state='pending'",
        (receipt.operation_id, canonical_serialize(value), *ns.as_tuple, stage.request.dedupe_key))
    if db.execute("SELECT changes()").fetchone() != (1,):
        raise ValueError("C4 queued cause changed before its atomic self disposition")
    validate_artifact_draft_wake_disposition_v1(db, namespace=ns, row_data={
        "dedupe_key": stage.request.dedupe_key, "causal_operation_id": row[0], "original_ref": row[2],
        "original_digest": row[3], "consumer_operation_id": receipt.operation_id,
        "event_kind": row[1], "receiver_domain": "d11", "state": "completed"}, value=value)
    return value


def validate_artifact_draft_wake_disposition_v1(db, *, namespace, row_data, value):
    """Recognize only the dedicated wake's immutable stage and actual receipt."""
    if type(value) is dict and value.get("schema") == "d11.artifact-draft-wake-disposition.v2":
        return validate_artifact_draft_wake_disposition_v2(db, namespace=namespace, row_data=row_data, value=value)
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    expected = {"schema", "dedupe_key", "causal_operation_id", "trigger_original_ref", "trigger_original_digest",
        "state", "consumer_operation_id", "consumer_original_digest", "consumer_receipt_digest", "cycle_job_ref",
        "prepared_digest", "paid_ref", "paid_digest", "result_ref", "result_digest"}
    if (db is None or type(value) is not dict or set(value) != expected
            or value["schema"] != "d11.artifact-draft-wake-disposition.v1" or value["state"] != "completed"
            or row_data["state"] != "completed" or row_data["event_kind"] != "artifact_draft_model_queued"
            or row_data["receiver_domain"] != "d11"
            or any(value[name] != row_data[name] for name in
                ("dedupe_key", "causal_operation_id", "state", "consumer_operation_id"))
            or value["trigger_original_ref"] != row_data["original_ref"]
            or value["trigger_original_digest"] != row_data["original_digest"]):
        raise ValueError("C4 self wake disposition is outside its exact original queued event")
    adopted = read_adopted_domain_operation_v1(db, namespace, value["consumer_operation_id"])
    if (adopted is None or adopted["domain"] != "d11" or adopted["operation_kind"] != "wake_artifact_draft_cycle_v1"
            or adopted["original_digest"] != value["consumer_original_digest"]
            or canonical_digest(adopted["receipt"]) != value["consumer_receipt_digest"]):
        raise MissingProductionOriginalV1("C4_actual_self_wake_disposition_receipt")
    request = decode_typed_production_value_v1(adopted["payload"]["request"], WakeArtifactDraftCycleRequestV1)
    proof = adopted["payload"]["provenance"]
    if (request.dedupe_key != value["dedupe_key"] or request.selector.cycle_job_ref != value["cycle_job_ref"]
            or any(proof[name] != value[name] for name in
                ("prepared_digest", "paid_ref", "paid_digest", "result_ref", "result_digest"))):
        raise ValueError("C4 self disposition lost its exact signed terminal predicate")
    producer = read_adopted_domain_operation_v1(db, namespace, value["causal_operation_id"])
    if (producer is None or producer["operation_kind"] != "prepare_artifact_draft_model"
            or value["trigger_original_ref"] != "d11-current:" + producer["original_digest"][:48]
            or value["trigger_original_digest"] != producer["original_digest"]):
        raise MissingProductionOriginalV1("actual_C4_prepare_queued_event_producer")
    return value


def derive_current_foreground_responsibility_v1(db, *, namespace, request, installed_bundle, issuer,
        owner_guard, parent_budget_lease_ref, purpose, audiences, now_utc):
    """Rebuild immutable candidate facts; the caller still needs independent current admission."""
    from dataclasses import asdict
    from ..host.authority_profile import AdminInstallationBundle, AdminForegroundPolicyV1
    from ..host.model_workflows_v4 import AdminModelWorkflowsV4
    from ..host.model_workflows_v5 import AdminModelWorkflowsV5
    from ..host.model_workflows_v6 import AdminModelWorkflowsV6
    from ..host.model_workflows_v7 import AdminModelWorkflowsV7
    from ..host.model_workflows_v8 import AdminModelWorkflowsV8
    from ..domains.d03.self_perspective import self_mapping_key
    from ..graph_types import owner_grant_key
    from .budget import get_budget_lease, require_budget_family_admissible
    from .d11_life_preparation_v1 import _read
    from .d11_artifact_draft_contract_v1 import DraftRootCapabilityV1, draft_from_wire_v1
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    from .c09_life_originals_v1 import read_foreground_post_c02_cause_original_v1
    from ..authority_service.current_foreground_activity_v1 import _source_family_current_sql_v1
    if (not db.in_transaction or type(request) is not CreateForegroundCycleRequestV2
            or type(installed_bundle) is not AdminInstallationBundle
            or type(installed_bundle.model_workflows) not in {AdminModelWorkflowsV4, AdminModelWorkflowsV5, AdminModelWorkflowsV6, AdminModelWorkflowsV7, AdminModelWorkflowsV8}
            or type(installed_bundle.foreground) is not AdminForegroundPolicyV1
            or installed_bundle.installation_policy.namespace != namespace or type(issuer) is not D11BudgetJobIssuer
            or type(owner_guard) is not ProductionOwnerGuardV1):
        raise MissingProductionOriginalV1("actual_installed_foreground_v4_responsibility_policy")
    policy = installed_bundle.foreground
    root_policy = installed_bundle.installation_policy
    grant = issuer.current_budget_grant(db, parent_budget_lease_ref)
    parent = get_budget_lease(db, parent_budget_lease_ref)
    require_budget_family_admissible(db, parent_budget_lease_ref)
    if (grant != root_policy.root_grant or parent.lease_id != root_policy.root_lease.lease_id
            or parent.parent_id is not None or parent.state != "active" or grant.valid_until_utc <= now_utc
            or (parent.bot_id, parent.persona_id) != namespace.as_tuple or WORK_KIND not in grant.allowed_work_kinds):
        raise ValueError("new responsibility must retain the actual signed installed root grant/parent")
    source_key_value = AtomKey.from_token(request.source_ref)
    if NamespaceId.from_key(source_key_value) != namespace or source_key_value.type_name != "memory.source":
        raise ValueError("new responsibility Source belongs to another namespace/type")
    source = db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=? AND bot=? AND persona=?",
        (request.source_ref, *namespace.as_tuple)).fetchone()
    owner = db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=? AND bot=? AND persona=?",
        (owner_grant_key(*namespace.as_tuple).token, *namespace.as_tuple)).fetchone()
    mapping_key = self_mapping_key(namespace)
    mapping = db.execute("SELECT value,valid FROM graph_atoms WHERE token=? AND bot=? AND persona=?",
        (mapping_key.token, *namespace.as_tuple)).fetchone()
    if (source is None or source[2] != 1 or mapping is None or mapping[1] != 1
            or owner is None or owner[2] != 1 or owner[0] != owner_guard.grant_revision
            or canonical_digest(json.loads(owner[1])) != owner_guard.grant_digest):
        raise ValueError("responsibility lost its actual current Source/self/Owner heads")
    _source_family_current_sql_v1(db, namespace=namespace, roots=(request.source_ref,), purpose=purpose, audiences=audiences)
    record = SourceRecord.from_dict(json.loads(source[1]))
    ingress = read_committed_ingress_identity(db, namespace, record.source_id)
    if ingress is None:
        raise MissingProductionOriginalV1("actual_responsibility_ingress_identity")
    ingress_id = json.loads(ingress.identity_json)["operation_id"]
    c02 = _adopted_c02_v1(db, namespace, request.c02_operation_id)
    fore_digest, deadline_digest = canonical_digest(asdict(policy)), canonical_digest(asdict(policy.deadline_policy))
    root_ref = root_digest = root_setup = None
    if request.draft_root_registration_ref is None:
        natural = policy.deadline_policy.natural
        if natural is None or request.cause_original_ref != foreground_post_c02_cause_ref_v1(namespace, request.c02_operation_id):
            raise MissingProductionOriginalV1("explicit_natural_causal_window_and_live_c02_cause")
        cause = read_foreground_post_c02_cause_original_v1(db, namespace=namespace, issuer=issuer,
            original_ref=request.cause_original_ref)
        if (cause.installation_id, cause.manifest_digest, cause.ingress_operation_id, cause.c02_operation_id,
                cause.source_ref, cause.source_revision, cause.source_digest, cause.foreground_policy_digest,
                cause.deadline_policy_digest) != (root_policy.installation_id, root_policy.manifest_digest,
                ingress_id, request.c02_operation_id, request.source_ref, source[0], canonical_digest(json.loads(source[1])),
                fore_digest, deadline_digest):
            raise ValueError("new natural responsibility differs from its actual frozen cause/profile/source")
        mode = "bounded_causal_window_v1"
        cause_digest, cause_op, cause_seq, frozen = canonical_digest(plain_v1(cause)), cause.c02_operation_id, cause.commit_seq, cause.cause_frozen_at_utc
        deadline = min(frozen + natural.window_seconds, grant.valid_until_utc)
    else:
        if (policy.deadline_policy.draft_mode != "signed_scope_intersection_v1"
                or request.cause_original_ref != request.draft_root_registration_ref
                or not {"artifact_draft_v1", "d10.life.artifact_draft.v1"} <= set(grant.allowed_work_kinds)):
            raise MissingProductionOriginalV1("actual_signed_draft_scope_intersection_policy_and_work_kinds")
        signed = _read(db, issuer=issuer, namespace=namespace, kind="draft_root_capability", ref=request.draft_root_registration_ref)
        if signed is None:
            raise MissingProductionOriginalV1("actual_adopted_owner_draft_root_setup")
        root = draft_from_wire_v1(signed[0], DraftRootCapabilityV1)
        original = read_adopted_domain_operation_v1(db, namespace, signed[1])
        if original is None:
            raise ValueError("draft root capability lacks its actual committed setup operation")
        if (original["domain"],original["operation_kind"])==("d10","derive_ingress_artifact_task_scope_v1"):
            from .ingress_artifact_task_scope_v1 import require_task_scope_archive_v1
            require_task_scope_archive_v1(db,namespace=namespace,root=root,producer=original)
        elif (original["domain"],original["operation_kind"])!=("d10","register_artifact_draft_root"):
            raise ValueError("draft root capability has no registered setup producer")
        provenance = original["payload"]["provenance"]
        if (provenance["draft_root_capability"] != signed[0] or root.source_ref != request.source_ref
                or (root.owner_grant_ref, root.owner_grant_revision, root.owner_grant_digest) !=
                   (owner_guard.grant_ref, owner_guard.grant_revision, owner_guard.grant_digest)):
            raise ValueError("new draft responsibility changed its actual adopted root/Source/Owner")
        mode = "signed_scope_intersection_v1"
        root_ref, root_digest, root_setup = root.registration_ref, canonical_digest(signed[0]), signed[1]
        cause_digest, cause_op = root_digest, signed[1]
        cause_seq, frozen = original["receipt"].commit_seq, provenance["cause_frozen_at_utc"]
        deadline = min(_utc(root.valid_until_utc, "root valid_until").timestamp(), grant.valid_until_utc)
    deadline = foreground_deadline_utc_v1(deadline)
    if deadline <= now_utc:
        raise MissingProductionOriginalV1("remaining_original_foreground_responsibility_window")
    return ForegroundResponsibilityV1(namespace, root_policy.installation_id, root_policy.manifest_digest, mode,
        policy.policy_ref, policy.policy_version, fore_digest, deadline_digest, ingress_id, request.c02_operation_id,
        canonical_digest(c02), c02.commit_seq, request.source_ref, source[0], canonical_digest(json.loads(source[1])),
        request.cause_original_ref, cause_digest, cause_op, cause_seq, float(frozen), root_ref, root_digest, root_setup,
        grant.grant_id, grant.version, canonical_digest(grant), parent_budget_lease_ref, mapping_key.token,
        canonical_digest(json.loads(mapping[0])), owner_guard, None, None, None, float(deadline))


def require_current_foreground_responsibility_v1(db, *, namespace, job, installed_bundle, issuer,
        owner_guard, purpose, audiences, now_utc):
    from dataclasses import asdict
    if job.continuation.get("schema") == "d11.foreground-source-note-continuation.v1":
        from .source_note_foreground_v1 import require_current_source_note_responsibility_v1
        return require_current_source_note_responsibility_v1(db, namespace=namespace, job=job,
            installed_bundle=installed_bundle, issuer=issuer, owner_guard=owner_guard,
            purpose=purpose, audiences=audiences, now_utc=now_utc)
    from .c09_life_originals_v1 import read_original_foreground_responsibility_for_c09_v1
    from ..host.authority_profile import AdminForegroundPolicyV1
    from ..domains.d03.self_perspective import self_mapping_key
    from .budget import require_budget_family_admissible
    from ..authority_service.current_foreground_activity_v1 import _source_family_current_sql_v1
    responsibility = read_original_foreground_responsibility_for_c09_v1(db, namespace=namespace, job=job, issuer=issuer)
    if responsibility is None:
        return None
    policy = installed_bundle.foreground
    if type(policy) is not AdminForegroundPolicyV1:
        raise MissingProductionOriginalV1("actual_current_foreground_v4_policy")
    grant = issuer.current_budget_grant(db, job.budget_ref)
    require_budget_family_admissible(db, job.budget_ref)
    source = db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=? AND bot=? AND persona=?",
        (responsibility.source_ref, *namespace.as_tuple)).fetchone()
    mapping = db.execute("SELECT value,valid FROM graph_atoms WHERE token=? AND bot=? AND persona=?",
        (self_mapping_key(namespace).token, *namespace.as_tuple)).fetchone()
    if (responsibility.owner_guard != owner_guard or source is None or source[2] != 1
            or (source[0], canonical_digest(json.loads(source[1]))) != (responsibility.source_revision, responsibility.source_digest)
            or mapping is None or mapping[1] != 1 or canonical_digest(json.loads(mapping[0])) != responsibility.self_mapping_digest
            or (grant.grant_id, grant.version, canonical_digest(grant)) !=
               (responsibility.parent_grant_id, responsibility.parent_grant_version, responsibility.parent_grant_digest)
            or canonical_digest(asdict(policy)) != responsibility.foreground_policy_digest
            or canonical_digest(asdict(policy.deadline_policy)) != responsibility.deadline_policy_digest
            or now_utc >= min(responsibility.deadline_utc, grant.valid_until_utc)):
        raise ValueError("foreground original responsibility lost its current Source/self/Owner/profile/grant qualification")
    _source_family_current_sql_v1(db, namespace=namespace, roots=(responsibility.source_ref,), purpose=purpose, audiences=audiences)
    return responsibility


def foreground_cycle_read_plan_v1(*, namespace, c02_receipt, source_ref):
    activity_id, job_id = foreground_cycle_ids_v1(namespace, c02_receipt.operation_id)
    keys = (runtime_job_key(*namespace.as_tuple, activity_id, job_id),
        *(version.key for version in c02_receipt.write_versions if version.key.type_name in {"memory.episode.v1", "memory.subjective_trace.v2"}))
    return production_read_plan_v1((), keys, (source_ref,), ())


def _adopted_c02_v1(db, namespace, operation_id):
    from .domain_production_originals_v1 import reconstruct_graph_bundle_commit_receipt_v1
    from .domain_production_read_plans_v1 import _committed
    _committed(db, namespace, operation_id)
    bundle = model_reply_scope_point_v3(db, table="graph_bundle_operations",
        columns=("digest", "activity_id", "effect_id", "commit_seq", "receipt_json"),
        key_columns=("bot", "persona", "operation_id"), key=(*namespace.as_tuple, operation_id),
        legacy_reader=lambda: db.execute("SELECT digest,activity_id,effect_id,commit_seq,receipt_json "
            "FROM graph_bundle_operations WHERE bot=? AND persona=? AND operation_id=?",
            (*namespace.as_tuple, operation_id)).fetchone())
    if bundle is None:
        raise MissingProductionOriginalV1("actual_first_ingress_c02_original")
    raw = background_json_loads_v3(bundle[4])
    if "first_ingress_c02" not in raw:
        raise MissingProductionOriginalV1("actual_first_ingress_c02_original")
    event = model_reply_scope_point_v3(db, table="graph_events",
        columns=("reads", "revisions", "epoch_revision"),
        key_columns=("bot", "persona", "session", "event_id"),
        key=(*namespace.as_tuple, bundle[1], operation_id),
        legacy_reader=lambda: db.execute("SELECT reads,revisions,epoch_revision FROM graph_events "
            "WHERE bot=? AND persona=? AND session=? AND event_id=?",
            (*namespace.as_tuple, bundle[1], operation_id)).fetchone())
    return reconstruct_graph_bundle_commit_receipt_v1(namespace, operation_id, bundle, event)


def _original_encoding_attempt_v1(db, *, namespace, c02_operation_id, source_ref, parent_budget_ref, issuer):
    """Retain the paid C1 which happened before this post-C02 cycle existed."""
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    from .terminal_c02_recovery_candidate_v2 import FrozenTerminalC02CandidateV2, inspect_frozen_terminal_c02_candidate_v2
    from .encoding_call_binding import load_binding
    from .foreground_call_plan_v1 import ForegroundModelAttemptV1
    from .model_cost_settlement import original_model_cost_operation_id_v1
    from .domain_production_read_plans_v1 import _committed
    row = db.execute("SELECT seal_json,bundle_json,quote_json,bundle_digest FROM graph_first_ingress_c02_committed_seals_v2 "
        "WHERE bot=? AND persona=? AND operation_id=?", (*namespace.as_tuple, c02_operation_id)).fetchone()
    if row is None:
        raise MissingProductionOriginalV1("actual_archived_encoding_c02_seal")
    seal = decode_typed_production_value_v1(json.loads(row[0]), FrozenTerminalC02CandidateV2)
    inspect_frozen_terminal_c02_candidate_v2(namespace=namespace, operation_id=c02_operation_id,
        seal=seal, bundle_json=row[1], quote_json=row[2])
    signed = issuer.resource_issuer.original_signed_quote(db, seal.quote_id, seal.quote_version)
    from dataclasses import asdict
    if canonical_serialize(asdict(signed)) != row[2] or seal.bundle_digest != row[3]:
        raise ValueError("foreground C1 archived original signed quote differs")
    key = seal.original_key
    binding = load_binding(db, namespace, key.job_id)
    job = get_job(db, key.job_id)
    if (binding is None or binding.call_id != key.call_id or binding.binding_digest != key.binding_digest
            or binding.model_request_digest != key.model_request_digest
            or binding.budget_lease_id != parent_budget_ref or job.phase != "completed"
            or source_ref != source_key(*namespace.as_tuple, binding.source_id).token):
        raise ValueError("foreground C1 must retain its actual completed original encoding identity")
    quote_ref, version = job.operator_versions["resource_quote"].rsplit(":", 1)
    quote = issuer.resource_issuer.original_signed_quote(db, quote_ref, int(version))
    reservation = db.execute("SELECT digest,ceiling_json,state FROM runtime_budget_reservations WHERE lease_id=? AND operation_id=?",
        (parent_budget_ref, binding.budget_reservation_operation_id)).fetchone()
    if reservation is None or json.loads(reservation[1]) != dict(quote.ceiling) or quote.work_kind != "d06.encode_source":
        raise ValueError("foreground C1 lost its real original model reservation")
    terminal_ref = original_model_cost_operation_id_v1(namespace, binding.call_id)
    _committed(db, namespace, terminal_ref)
    return ForegroundModelAttemptV1("C1", binding.call_id, None, binding.budget_reservation_operation_id,
        reservation[0], parent_budget_ref, quote.ceiling["input_tokens"], quote.ceiling["output_tokens"], "completed", terminal_ref)


def _verify_pending_effect_changes_v1(db, namespace, old, current):
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    expected, verified = set(old.pending_effect_refs), set()
    for operation_id in set(current.completed_operation_refs) - set(old.completed_operation_refs):
        original = read_adopted_domain_operation_v1(db, namespace, operation_id)
        if original is None:
            continue
        payload = original["payload"]
        for write in payload.get("writes", ()):
            kind = AtomKey.from_token(write["key"]).type_name
            if kind == "d08.action_intent.v1":
                expected.add(write["value"]["identity"]["effect_id"])
            elif kind == "d10.project_work_version.v1":
                verified.add(write["value"]["effect_id"])
    if set(current.pending_effect_refs) != expected - verified:
        raise ValueError("foreground pending effects must follow actual adopted action and verified work originals")


def _require_actual_delivered_foreground_reply_v1(db, *, frame, continuation, completion_result_ref):
    """Completion means actual delivered outbound adoption for this exact original reply."""
    from .natural_reply_job_v2 import read_original_preparation
    from .natural_dispatch_current_read_v2 import recover_natural_dispatch_candidate_in_transaction_v2
    from .d01_production_operations_v1 import table_exists_v1
    from ..authority_service.v2_contract import from_wire, to_wire, MutationReceiptV2
    ns = frame.envelope.authority.namespace
    generation = read_original_preparation(db, ns, continuation.c02_operation_id, "generation")
    if generation is None or generation.state != "terminal":
        raise MissingProductionOriginalV1("actual_completed_original_foreground_generation")
    plan = generation.frozen.input.plan
    if completion_result_ref != plan.final_operation_id:
        raise ValueError("foreground completion result is not this actual C02's adopted final reply operation")
    review = read_original_preparation(db, ns, continuation.c02_operation_id, "review")
    if review is None or review.state != "terminal":
        raise MissingProductionOriginalV1("actual_completed_original_independent_foreground_review")
    recovered = recover_natural_dispatch_candidate_in_transaction_v2(db, ns, completion_result_ref)
    if (recovered is None or recovered.evidence.generation_original_operation_id != generation.seal.original_operation_id
            or recovered.evidence.review_original_operation_id != review.seal.original_operation_id
            or recovered.evidence.operation_id != plan.final_operation_id or recovered.evidence.effect_id != plan.final_effect_id):
        raise MissingProductionOriginalV1("actual_adopted_final_foreground_reply_batch")
    actual = db.execute("SELECT activity_id,effect_id FROM graph_bundle_operations WHERE bot=? AND persona=? AND operation_id=?",
        (*ns.as_tuple, completion_result_ref)).fetchone()
    if actual != (plan.final_activity_id, plan.final_effect_id):
        raise ValueError("foreground adopted final reply belongs to another original activity/effect")
    if not table_exists_v1(db, "graph_d13_outbound_observations_v1"):
        raise MissingProductionOriginalV1("actual_delivered_foreground_outbound_adoption")
    observations = db.execute("SELECT observation_digest,source_ref,slot_ref,batch_ref,observation_json,original_json,original_digest "
        "FROM graph_d13_outbound_observations_v1 WHERE bot=? AND persona=? AND final_operation_id=? "
        "AND json_extract(observation_json,'$.pending.platform_observation.outcome')='delivered' LIMIT 2",
        (*ns.as_tuple, completion_result_ref)).fetchall()
    for digest, source_ref, slot_ref, batch_ref, encoded, original_json, original_digest in observations:
        observed = from_wire(json.loads(encoded))
        original = json.loads(original_json)
        if (canonical_serialize(to_wire(observed)) != encoded or canonical_digest(observed) != digest
                or canonical_serialize(original) != original_json or canonical_digest(original) != original_digest):
            raise ValueError("foreground outbound adoption lost its actual immutable byte commitments")
        if type(observed) is not MutationReceiptV2 or observed.durable_state != "committed":
            raise ValueError("foreground outbound adoption is not its actual durable observation")
        observation = observed.pending.platform_observation
        if observation is None or observation.outcome != "delivered":
            continue
        if ((observation.binding.origin.operation_id, observation.binding.origin.effect_id) !=
                (plan.final_operation_id, plan.final_effect_id)
                or observation.binding.origin.payload_digest.removeprefix("sha256:") != recovered.evidence.payload_digest
                or batch_ref != recovered.evidence.batch_ref
                or original["source_ref"] != source_ref or original["slot_ref"] != slot_ref
                or original["batch_ref"] != batch_ref or original["observation_digest"] != digest):
            raise ValueError("foreground delivered observation belongs to another exact reviewed reply")
        return _require_delivered_turn_history_v1(db, ns, original["operation_id"], source_ref, slot_ref)
    raise MissingProductionOriginalV1("actual_delivered_foreground_outbound_adoption")


def _require_delivered_turn_history_v1(db, namespace, operation_id, source_ref, slot_ref):
    from ..domains.d09.turn_order import validate_turn_completion_v1
    rows = db.execute("SELECT token,value FROM graph_history WHERE event_bot=? AND event_persona=? AND event_id=? AND valid=1",
        (*namespace.as_tuple, operation_id)).fetchall()
    completions = [json.loads(value) for token, value in rows if AtomKey.from_token(token).type_name == "d09.turn_completion.v1"]
    if len(completions) != 1:
        raise MissingProductionOriginalV1("actual_adopted_delivered_reply_turn_completion")
    value = completions[0]
    validate_turn_completion_v1(value)
    if value["direction"] != "outbound" or value["source_ref"] != source_ref or value["slot_ref"] != slot_ref:
        raise ValueError("foreground delivered turn differs from its actual adopted outbound source/slot")


def _current_attempt_original_v1(db, *, namespace, continuation, attempt, issuer):
    if type(attempt) is ForegroundModelAttemptV2:
        from .d11_artifact_draft_model_v1 import read_current_artifact_draft_attempt_v2
        return read_current_artifact_draft_attempt_v2(db, namespace=namespace,
            continuation=continuation, attempt=attempt, issuer=issuer)
    """A terminal selector is matched to actual adopted originals, never a DTO state."""
    from .foreground_call_plan_v1 import ForegroundModelAttemptV1
    from .model_cost_settlement import original_model_cost_operation_id_v1
    if attempt.slot == "C1":
        return _original_encoding_attempt_v1(db, namespace=namespace, c02_operation_id=continuation.c02_operation_id,
            source_ref=continuation.source_ref, parent_budget_ref=continuation.call_plan.parent_budget_lease_ref, issuer=issuer)
    if attempt.slot == "C2":
        from .d04_product_pipeline_v3 import ids
        from .d04_appraisal_driver_v3 import read_current_d04_appraisal_original_v3, read_d04_original_v3
        from ..model_broker.d04_appraisal import thaw_appraisal_request_v1
        identity = ids(namespace, continuation.c02_operation_id)
        original = read_current_d04_appraisal_original_v3(db, namespace, identity["job"])
        if original is None:
            raise MissingProductionOriginalV1("actual_post_c02_appraisal_original")
        from .domain_production_read_plans_v1 import _committed
        _committed(db, namespace, original.operation_id)
        frozen = thaw_appraisal_request_v1(json.loads(original.frozen_json))
        job = get_job(db, original.job_id)
        quote = issuer.resource_issuer.original_signed_quote(db, original.quote_id, original.quote_version)
        if (original.call_id != identity["call"] or attempt.call_id != original.call_id
                or original.operation_id != identity["operation"] or attempt.original_call_id is not None
                or continuation.source_ref not in {item.source_ref.ref for item in frozen.input.sources}
                or quote.parent_budget_lease_ref != continuation.call_plan.parent_budget_lease_ref
                or quote.work_kind != "d04.appraisal"):
            raise ValueError("foreground C2 must retain its actual chosen C02/source/root appraisal original")
        paid = read_d04_original_v3(db, namespace, "appraisal_cost", original.job_id)
        terminal_ref = None
        if paid is not None:
            result = read_d04_original_v3(db, namespace, "appraisal_result", paid[0]["result_original_ref"])
            if (not paid[0]["paid"] or paid[0]["prepared_digest"] != original.digest or result is None
                    or result[1] != paid[0]["result_original_digest"] or job.phase != "completed"):
                raise ValueError("foreground C2 paid result lost its actual adopted terminal identity")
            terminal_ref = paid[0]["result_original_ref"]
        reservation = db.execute("SELECT digest,state FROM runtime_budget_reservations WHERE lease_id=? AND operation_id=?",
            (quote.parent_budget_lease_ref, quote.operation_id)).fetchone()
        if reservation is None or reservation[0] != original.reservation_digest:
            raise ValueError("foreground C2 reservation differs from its actual signed original")
        state = "completed" if paid is not None else "unknown" if reservation[1] == "unconfirmed" else "dispatch_started" if job.phase == "running" else "reserved"
        return ForegroundModelAttemptV1("C2", original.call_id, None, quote.operation_id,
            reservation[0], quote.parent_budget_lease_ref, quote.ceiling["input_tokens"], quote.ceiling["output_tokens"], state, terminal_ref)
    if attempt.slot == "C3":
        from .d07_execution_v1 import TABLE, read_prepared_d07_execution_v1, D07IngressRecallPreparedV1, D07RelationshipPreparedV2, D07ReflectionPreparedV3
        rows = db.execute("SELECT original_ref FROM " + TABLE + " WHERE bot=? AND persona=? AND kind='prepared' "
            "AND json_extract(payload_json,'$.call_id')=? LIMIT 2", (*namespace.as_tuple, attempt.call_id)).fetchall()
        if len(rows) != 1:
            raise ValueError("C3 lacks its unique actual signed prepared producer")
        prepared = read_prepared_d07_execution_v1(db, issuer, namespace, rows[0][0])
        if type(prepared) is D07IngressRecallPreparedV1:
            from .d07_ingress_recall_preparation_v1 import read_current_ingress_recall_attempt_v1
            return read_current_ingress_recall_attempt_v1(db, namespace=namespace,
                continuation=continuation, attempt=attempt, issuer=issuer)
        from .d07_method_growth_semantic_v2 import D07MethodGrowthPreparedV2
        if type(prepared) in {D07RelationshipPreparedV2, D07MethodGrowthPreparedV2, D07ReflectionPreparedV3}:
            from .foreground_call_plan_v1 import read_current_named_c3_attempt_v2
            return read_current_named_c3_attempt_v2(db, namespace=namespace,
                continuation=continuation, attempt=attempt, issuer=issuer)
        raise ValueError("unregistered actual C3 prepared producer")
    if attempt.slot == "C4":
        from .d11_artifact_draft_model_v1 import read_current_artifact_draft_attempt_v1
        return read_current_artifact_draft_attempt_v1(db, namespace=namespace,
            continuation=continuation, attempt=attempt, issuer=issuer)
    if attempt.slot not in {"C5", "C6"}:
        raise MissingProductionOriginalV1("registered_foreground_" + attempt.slot + "_adopted_model_original")
    from .natural_reply_job_v2 import read_original_preparation
    generation = read_original_preparation(db, namespace, continuation.c02_operation_id, "generation")
    if generation is None:
        raise MissingProductionOriginalV1("actual_natural_generation_original")
    saved = generation if attempt.slot == "C5" else read_original_preparation(
        db, namespace, continuation.c02_operation_id, "review")
    if saved is None:
        raise MissingProductionOriginalV1("actual_independent_natural_review_original")
    seal = saved.seal
    if (attempt.call_id != seal.call_id or attempt.original_call_id is not None
            or attempt.reservation_operation_id != seal.reservation_operation_id
            or attempt.budget_lease_ref != seal.parent_budget_lease_id
            or seal.parent_budget_lease_id != continuation.call_plan.protected_reply_lease_ref):
        raise ValueError("foreground reply call must use its actual adopted protected child binding")
    reservation = db.execute("SELECT digest,ceiling_json,state FROM runtime_budget_reservations WHERE lease_id=? AND operation_id=?",
        (seal.parent_budget_lease_id, seal.reservation_operation_id)).fetchone()
    if reservation is None:
        raise ValueError("foreground natural original lost its actual reserved budget")
    ceiling = json.loads(reservation[1])
    terminal_ref = original_model_cost_operation_id_v1(namespace, seal.call_id) if saved.state == "terminal" else None
    if terminal_ref is not None:
        from .domain_production_read_plans_v1 import _committed
        _committed(db, namespace, terminal_ref)
    state = "completed" if saved.state == "terminal" else "unknown" if reservation[2] == "unconfirmed" else "dispatch_started" if saved.state == "acquired" else "reserved"
    return ForegroundModelAttemptV1(attempt.slot, seal.call_id, None, seal.reservation_operation_id,
        reservation[0], seal.parent_budget_lease_id, ceiling["input_tokens"], ceiling["output_tokens"], state, terminal_ref)


def _reply_event_version_rows_v3(encoded):
    from ..graph_types import AtomKey,GraphVersion
    from .domain_background_read_v3 import BackgroundJSONColumnV3
    if type(encoded)is BackgroundJSONColumnV3:
        return tuple(GraphVersion(AtomKey.from_token(token),revision)for token,revision in background_json_loads_v3(encoded))
    from ..graph_store import GraphStore
    return GraphStore._version_rows(encoded)


def _read_reply_natural_metadata_v1(db, namespace, c02_operation_id, stage):
    """Authenticate the seal against its adopting receipt, without thawing inputs."""
    from .natural_reply_job_v2 import _table, _seal, natural_job_ids_v2
    from .d01_production_operations_v1 import table_exists_v1
    from ..graph_store import GraphStore
    table = _table(stage)
    if not table_exists_v1(db, table):
        return None
    row = model_reply_scope_point_v3(db,table=table,columns=('seal_json', 'state', 'terminal_receipt_digest'),key_columns=('bot', 'persona', 'parent_original_id'),key=(((*namespace.as_tuple, c02_operation_id))[0],((*namespace.as_tuple, c02_operation_id))[1],((*namespace.as_tuple, c02_operation_id))[2],),legacy_reader=lambda:db.execute("SELECT seal_json,state,terminal_receipt_digest FROM " + table +
        " WHERE bot=? AND persona=? AND parent_original_id=?",
        (*namespace.as_tuple, c02_operation_id)).fetchone())
    ids = natural_job_ids_v2(namespace, c02_operation_id, stage)
    if row is None:
        if model_reply_scope_point_v3(db,table='runtime_jobs',columns=('job_id',),key_columns=('job_id',),key=(((ids[0],))[0],),legacy_reader=lambda:db.execute("SELECT 1 FROM runtime_jobs WHERE job_id=?", (ids[0],)).fetchone()) is not None:
            raise MissingProductionOriginalV1("actual_sealed_natural_reply_child")
        return None
    raw = background_json_loads_v3(row[0])
    seal = _seal(stage, raw)
    if (not background_json_matches_v3(row[0],plain_v1(seal)) or seal.namespace != namespace
            or (seal.job_id, seal.original_operation_id, seal.acquire_operation_id,
                seal.call_id, seal.reservation_operation_id) != ids
            or row[1] not in {"queued", "acquired", "terminal"}
            or (row[1] == "terminal") != (row[2] is not None)):
        raise ValueError("natural reply metadata changed its closed seal/state identity")
    job = get_job(db, seal.job_id)
    committed = model_reply_scope_point_v3(db,table='graph_bundle_operations',columns=('activity_id', 'receipt_json'),key_columns=('bot', 'persona', 'operation_id'),key=(((*namespace.as_tuple, seal.original_operation_id))[0],((*namespace.as_tuple, seal.original_operation_id))[1],((*namespace.as_tuple, seal.original_operation_id))[2],),legacy_reader=lambda:db.execute("SELECT activity_id,receipt_json FROM graph_bundle_operations "
        "WHERE bot=? AND persona=? AND operation_id=?", (*namespace.as_tuple, seal.original_operation_id)).fetchone())
    if committed is None:
        raise MissingProductionOriginalV1("actual_adopted_natural_reply_seal")
    receipt = background_json_loads_v3(committed[1])
    key = "seal_digest" if stage == "generation" else "review_seal_digest"
    refkey = "job_ref" if stage == "generation" else "review_job_ref"
    if (receipt[key] != canonical_digest(plain_v1(seal)) or receipt[refkey] != job_graph_write(job).key.token
            or committed[0] != job.activity_id or job.operation_id != seal.original_operation_id
            or job.work_kind != "natural_" + stage or job.budget_ref != seal.parent_budget_lease_id):
        raise ValueError("natural reply seal differs from its actual adopting operation")
    if stage == "generation":
        if receipt["c02_operation_id"] != c02_operation_id or receipt["source_ref"] != seal.source_ref:
            raise ValueError("natural reply seal changed its adopted C02/source")
    else:
        generation = _read_reply_natural_metadata_v1(db, namespace, c02_operation_id, "generation")
        if (generation is None or seal.generation_original_operation_id != generation[0].original_operation_id
                or receipt["generation_original_operation_id"] != generation[0].original_operation_id
                or seal.generation_call_id != generation[0].call_id
                or seal.parent_budget_lease_id != generation[0].parent_budget_lease_id):
            raise ValueError("review metadata changed its original generation lineage")
    event = model_reply_scope_point_v3(db,table='graph_events',columns=('revisions',),key_columns=('bot', 'persona', 'session', 'event_id'),key=(((*namespace.as_tuple, job.activity_id, seal.original_operation_id))[0],((*namespace.as_tuple, job.activity_id, seal.original_operation_id))[1],((*namespace.as_tuple, job.activity_id, seal.original_operation_id))[2],((*namespace.as_tuple, job.activity_id, seal.original_operation_id))[3],),legacy_reader=lambda:db.execute("SELECT revisions FROM graph_events WHERE bot=? AND persona=? AND session=? AND event_id=?",
        (*namespace.as_tuple, job.activity_id, seal.original_operation_id)).fetchone())
    versions = () if event is None else tuple(v for v in _reply_event_version_rows_v3(event[0]) if v.key == job_graph_write(job).key)
    if len(versions) != 1 or model_reply_scope_point_v3(db,table='graph_history',columns=('token',),key_columns=('token', 'revision', 'valid', 'event_bot', 'event_persona', 'event_id'),key=(((versions[0].key.token, versions[0].revision, *namespace.as_tuple, seal.original_operation_id))[0],((versions[0].key.token, versions[0].revision, *namespace.as_tuple, seal.original_operation_id))[1],1,((versions[0].key.token, versions[0].revision, *namespace.as_tuple, seal.original_operation_id))[2],((versions[0].key.token, versions[0].revision, *namespace.as_tuple, seal.original_operation_id))[3],((versions[0].key.token, versions[0].revision, *namespace.as_tuple, seal.original_operation_id))[4],),legacy_reader=lambda:db.execute("SELECT 1 FROM graph_history WHERE token=? AND revision=? AND valid=1 "
            "AND event_bot=? AND event_persona=? AND event_id=?",
            (versions[0].key.token, versions[0].revision, *namespace.as_tuple, seal.original_operation_id)).fetchone()) is None:
        raise MissingProductionOriginalV1("actual_natural_reply_initial_job_CAS_member")
    return seal, row[1], row[2]


def _read_reply_message_metadata_v1(db, *, namespace, generation_seal, review_seal):
    """Read adopted batch identity fields, never model output or message body."""
    from ..graph_store import GraphStore
    rows = model_reply_scope_rows_v3(db,kind='message_history',parameters=(generation_seal.original_operation_id,review_seal.original_operation_id),legacy_reader=lambda:db.execute("SELECT token,revision,event_id,json_extract(value,'$.schema'),"
        "json_extract(value,'$.activity_id'),json_extract(value,'$.operation_id'),"
        "json_extract(value,'$.effect_id'),json_extract(value,'$.batch_id'),"
        "json_extract(value,'$.paid_review.generation_call_id'),"
        "json_extract(value,'$.paid_review.review_call_id') FROM graph_history "
        "WHERE event_bot=? AND event_persona=? AND valid=1 "
        "AND json_extract(value,'$.paid_review.generation_original_operation_id')=? "
        "AND json_extract(value,'$.paid_review.review_original_operation_id')=? "
        "AND json_extract(value,'$.schema') IN ('d09.natural_verified_segment_batch.v2',"
        "'d09.natural_verified_segment_batch.v3') ORDER BY event_id,token,revision LIMIT 5",
        (*namespace.as_tuple, generation_seal.original_operation_id, review_seal.original_operation_id)).fetchall())
    if len(rows) > 4:
        raise ValueError("actual adopted reply child batch exceeds four messages")
    result, seen = [], set()
    for token, revision, producer, schema, activity, operation, effect, batch_id, generation_call, review_call in rows:
        key = AtomKey.from_token(token)
        if (operation != producer or key.type_name != schema or key.name != batch_id
                or key.owner.subject != activity or NamespaceId.from_key(key) != namespace
                or (generation_call, review_call) != (generation_seal.call_id, review_seal.call_id)
                or operation in seen):
            raise ValueError("reply message metadata changed its adopted whole batch lineage")
        seen.add(operation)
        committed = model_reply_scope_point_v3(db,table='graph_bundle_operations',columns=('activity_id', 'effect_id', 'receipt_json'),key_columns=('bot', 'persona', 'operation_id'),key=(((*namespace.as_tuple, operation))[0],((*namespace.as_tuple, operation))[1],((*namespace.as_tuple, operation))[2],),legacy_reader=lambda:db.execute("SELECT activity_id,effect_id,receipt_json FROM graph_bundle_operations "
            "WHERE bot=? AND persona=? AND operation_id=?", (*namespace.as_tuple, operation)).fetchone())
        if committed is None or committed[:2] != (activity, effect):
            raise MissingProductionOriginalV1("actual_reply_whole_batch_adopting_receipt")
        candidate = background_json_loads_v3(committed[2])["natural_dispatch_candidate"]
        if (candidate["schema"] != "sylanne.d11.natural_dispatch_candidate.v2"
                or candidate["status"] != "natural_paid_review_current_hold"
                or len(candidate["refs"]) != 4 or candidate["refs"][3] != [token, revision]):
            raise ValueError("reply whole batch metadata is not the actual closed final receipt")
        event = model_reply_scope_point_v3(db,table='graph_events',columns=('revisions',),key_columns=('bot', 'persona', 'session', 'event_id'),key=(((*namespace.as_tuple, activity, operation))[0],((*namespace.as_tuple, activity, operation))[1],((*namespace.as_tuple, activity, operation))[2],((*namespace.as_tuple, activity, operation))[3],),legacy_reader=lambda:db.execute("SELECT revisions FROM graph_events WHERE bot=? AND persona=? AND session=? AND event_id=?",
            (*namespace.as_tuple, activity, operation)).fetchone())
        versions = {} if event is None else {v.key.token: v.revision for v in _reply_event_version_rows_v3(event[0])}
        if any(versions.get(ref) != version for ref, version in candidate["refs"]):
            raise MissingProductionOriginalV1("actual_reply_final_action_schema_grant_batch_CAS_members")
        jobs = model_reply_scope_rows_v3(db,kind='message_jobs',parameters=(operation,),legacy_reader=lambda:db.execute("SELECT job_id FROM runtime_jobs WHERE bot_id=? AND persona_id=? "
            "AND operation_id=? AND work_kind='message' LIMIT 2", (*namespace.as_tuple, operation)).fetchall())
        if len(jobs) != 1:
            raise MissingProductionOriginalV1("unique_actual_message_child_of_adopted_final")
        job = get_job(db, jobs[0][0])
        if (job.activity_id, job.effect_id, job.budget_ref) != (activity, effect, generation_seal.parent_budget_lease_id):
            raise ValueError("message child changed its actual final action or sealed protected budget")
        digest = canonical_digest(("d11.reply-message-metadata.v1", namespace, token, revision,
            operation, activity, effect, generation_seal.original_operation_id,
            review_seal.original_operation_id, candidate["digest"]))
        result.append((job, token, digest))
    return tuple(result)


def _read_reply_life_binding_metadata_v1(db, *, namespace, prepared_original_ref, issuer):
    """Verify journal bytes and project only the signed execution binding."""
    import hashlib
    from .d11_life_preparation_v1 import TABLE, SIGN_KIND
    from .d11_life_contract_v1 import D11LifeExecutionBindingV1, life_from_wire_v1
    from .domain_production_read_plans_v1 import _committed
    from ..authority_service.model_reply_scope_observation_v3 import _active_observation_v3
    observation = _active_observation_v3(db)
    if observation is not None and not observation.legacy:
        row = model_reply_scope_point_v3(db, table=TABLE,
            columns=('producing_operation_id','payload_json','payload_digest','signature'),
            key_columns=('bot','persona','kind','original_ref'),
            key=(*namespace.as_tuple,'prepared',prepared_original_ref),
            legacy_reader=lambda: None)
        if row is None:
            raise MissingProductionOriginalV1("actual_signed_reply_Life_preparation")
        column = row[1]
        raw = background_json_loads_v3(column)
        if not column.complete or column.sha256 != row[2]:
            raise ValueError("reply Life journal bytes differ from their signed commitment")
        issuer._signer.verify(SIGN_KIND,
            canonical_serialize((namespace,"prepared",prepared_original_ref,row[2])),row[3])
        _committed(db,namespace,row[0])
        kinds = observation.column_kinds.get(column,{})
        final_fields=('requirements_json','graph_revision','graph_epoch','job_projection_json','job_projection_revision')
        if (kinds.get('requirements_json')!='string'
                or any(name not in kinds or kinds[name]=='null' for name in final_fields)):
            raise ValueError("reply Life preparation lost its complete post-CAS metadata")
        binding = life_from_wire_v1(raw['binding'],D11LifeExecutionBindingV1)
        plan = raw['plan']
        if (binding.namespace!=namespace or binding.prepared_original_ref!=prepared_original_ref
                or row[0]!=raw['prepare_operation_id']
                or (binding.activity_id,binding.effect_id,binding.operation_id)!=
                    (plan['activity_id'],plan['effect_id'],plan['operation_id'])):
            raise ValueError("reply Life binding metadata differs from its actual adopted plan")
        return binding,row[2]
    row = db.execute("SELECT producing_operation_id,payload_json,payload_digest,signature,"
        "json_extract(payload_json,'$.binding'),json_extract(payload_json,'$.prepare_operation_id'),"
        "json_extract(payload_json,'$.plan.activity_id'),json_extract(payload_json,'$.plan.effect_id'),"
        "json_extract(payload_json,'$.plan.operation_id'),json_type(payload_json,'$.requirements_json') "
        "FROM " + TABLE + " WHERE bot=? AND persona=? AND kind='prepared' AND original_ref=?",
        (*namespace.as_tuple, prepared_original_ref)).fetchone()
    if row is None:
        raise MissingProductionOriginalV1("actual_signed_reply_Life_preparation")
    if hashlib.sha256(row[1].encode("utf-8")).hexdigest() != row[2]:
        raise ValueError("reply Life journal bytes differ from their signed commitment")
    issuer._signer.verify(SIGN_KIND,
        canonical_serialize((namespace, "prepared", prepared_original_ref, row[2])), row[3])
    _committed(db, namespace, row[0])
    binding = life_from_wire_v1(background_json_loads_v3(row[4]), D11LifeExecutionBindingV1)
    if (binding.namespace != namespace or binding.prepared_original_ref != prepared_original_ref
            or row[0] != row[5] or row[9] != "text"
            or (binding.activity_id, binding.effect_id, binding.operation_id) != row[6:9]):
        raise ValueError("reply Life binding metadata differs from its actual adopted plan")
    return binding, row[2]


def read_original_reply_child_jobs_v1(db, *, namespace: NamespaceId, cycle: PersistentJob,
        issuer: D11BudgetJobIssuer) -> tuple[tuple[PersistentJob, str, str], ...]:
    """Join existing reply work to immutable producers, without granting work."""
    from .d01_production_operations_v1 import table_exists_v1
    from .d11_life_preparation_v1 import TABLE, _read
    from .d11_artifact_draft_model_v1 import decode_artifact_draft_original_v1, read_artifact_draft_prepared_v1

    if (not db.in_transaction or type(namespace) is not NamespaceId
            or type(cycle) is not PersistentJob or type(issuer) is not D11BudgetJobIssuer
            or cycle.work_kind != WORK_KIND or (cycle.bot_id, cycle.persona_id) != namespace.as_tuple
            or get_job(db, cycle.job_id) != cycle):
        raise ValueError("reply child metadata needs the actual pinned foreground job and issuer")
    continuation = foreground_cycle_from_wire_v1(cycle.continuation)
    if (cycle.activity_id, cycle.job_id) != foreground_cycle_ids_v1(namespace, continuation.c02_operation_id):
        raise ValueError("reply child metadata changed its stable C02 cycle")
    children = {}

    def add(job, locator, digest, *, operation_id, activity_id, work_kind):
        if (type(job) is not PersistentJob or (job.bot_id, job.persona_id) != namespace.as_tuple
                or (job.operation_id, job.activity_id, job.work_kind) != (operation_id, activity_id, work_kind)
                or job.job_id == cycle.job_id or job.job_id in children):
            raise ValueError("reply child lost its exact immutable producer identity")
        projection = job_graph_write(job)
        row = model_reply_scope_point_v3(db,table='graph_atoms',columns=('value', 'valid'),key_columns=('token', 'bot', 'persona'),key=(((projection.key.token, *namespace.as_tuple))[0],((projection.key.token, *namespace.as_tuple))[1],((projection.key.token, *namespace.as_tuple))[2],),legacy_reader=lambda:db.execute("SELECT value,valid FROM graph_atoms WHERE token=? AND bot=? AND persona=?",
            (projection.key.token, *namespace.as_tuple)).fetchone())
        if row is None or row[1]!=1 or not background_json_matches_v3(row[0],projection.value):
            raise MissingProductionOriginalV1("actual_reply_child_SQL_Graph_projection:" + job.job_id)
        children[job.job_id] = (job, locator, digest)

    # C2 is the actual appraisal original, even when its worker is terminal.
    if table_exists_v1(db, "graph_d04_originals_v3"):
        from .d04_product_pipeline_v3 import ids
        from .d04_appraisal_driver_v3 import read_current_d04_appraisal_original_v3
        from .domain_production_read_plans_v1 import _committed
        identity = ids(namespace, continuation.c02_operation_id)
        from ..authority_service.model_reply_scope_observation_v3 import _active_observation_v3
        observer=_active_observation_v3(db)
        if observer is not None and not observer.legacy:
            from ..authority_service.model_reply_parentage_v3 import read_appraisal_child_metadata_v3
            metadata=read_appraisal_child_metadata_v3(db,namespace=namespace,job_id=identity["job"],issuer=issuer)
        else:
            appraisal = read_current_d04_appraisal_original_v3(db, namespace, identity["job"])
            metadata=None if appraisal is None else (appraisal.operation_id,appraisal.job_id,appraisal.digest)
        if metadata is not None:
            operation_id,job_id,original_digest=metadata
            _committed(db, namespace, operation_id)
            add(get_job(db, job_id), job_id, original_digest,
                operation_id=operation_id, activity_id=identity["activity"], work_kind="d04.appraisal")

    from .d07_execution_v1 import TABLE as D07_TABLE, read_d07_accounting_prepared_v1, read_d07_original_v1
    from .d07_ingress_recall_preparation_v1 import ingress_recall_model_ids_v1
    if table_exists_v1(db, D07_TABLE):
        ids = ingress_recall_model_ids_v1(namespace, continuation.c02_operation_id)
        prepared = read_d07_accounting_prepared_v1(db, issuer, namespace, ids["job"])
        if prepared is not None:
            original = read_d07_original_v1(db, issuer, namespace, "accounting_prepared", ids["job"])
            committed = read_d07_original_v1(db, issuer, namespace, "prepare_commit", ids["job"])
            if (original[0]["schema"] != "d07.ingress-recall-accounting-prepared.v1"
                    or prepared.work_kind != "recall_need" or prepared.operation_id != ids["prepare"]
                    or prepared.call_id != ids["call"] or prepared.activity_id != cycle.activity_id
                    or prepared.prepare_operation_id != ids["prepare"]
                    or committed is None or committed[0]["prepared_digest"] != prepared.digest
                    or committed[0]["prepare_operation_id"] != ids["prepare"]):
                raise ValueError("Self C3 child lost its exact source-independent preparation identity")
            quote = issuer.resource_issuer.original_signed_quote(db, prepared.quote_id, prepared.quote_version)
            child = get_job(db, prepared.job_id)
            if (canonical_digest(quote) != prepared.quote_digest
                    or quote.parent_budget_lease_ref != cycle.budget_ref
                    or quote.operation_id != prepared.operation_id
                    or quote.graph_job_ref != job_graph_write(child).key.token):
                raise ValueError("Self C3 child borrowed another original grant/lease/job")
            add(child, prepared.job_id, prepared.digest, operation_id=prepared.operation_id,
                activity_id=prepared.activity_id, work_kind="d07.recall_need")

    if table_exists_v1(db, TABLE):
        # Enumerate only bounded metadata; the signed prepared selector proves scope.
        rows = model_reply_scope_rows_v3(db,kind='life_c4',parameters=(job_graph_write(cycle).key.token,),legacy_reader=lambda:db.execute("SELECT original_ref FROM " + TABLE +
            " WHERE bot=? AND persona=? AND kind='c4_prepared' "
            "AND json_extract(payload_json,'$.selector.cycle_job_ref')=? ORDER BY original_ref LIMIT 129",
            (*namespace.as_tuple, job_graph_write(cycle).key.token)).fetchall())
        life_rows = model_reply_scope_rows_v3(db,kind='life_binding',parameters=(cycle.activity_id,),legacy_reader=lambda:db.execute("SELECT original_ref FROM " + TABLE +
            " WHERE bot=? AND persona=? AND kind='prepared' "
            "AND json_extract(payload_json,'$.binding.activity_id')=? ORDER BY original_ref LIMIT 129",
            (*namespace.as_tuple, cycle.activity_id)).fetchall())
        if len(rows) > 128 or len(life_rows) > 128:
            raise MissingProductionOriginalV1("bounded_reply_child_original_inventory")
        for (ref,) in rows:
            original = _read(db, issuer=issuer, namespace=namespace, kind="c4_prepared", ref=ref)
            prepared = decode_artifact_draft_original_v1("c4_prepared", original[0])
            root = _read(db, issuer=issuer, namespace=namespace, kind="draft_root_capability",
                ref=prepared.selector.root_registration_ref)
            if (read_artifact_draft_prepared_v1(db, namespace=namespace, issuer=issuer,
                    selector=prepared.selector) != prepared
                    or prepared.selector.c02_operation_id != continuation.c02_operation_id
                    or root is None or root[0]["source_ref"] != continuation.source_ref
                    or prepared.activity_id != cycle.activity_id):
                raise ValueError("C4 child is outside its actual sealed C02/cycle/source")
            add(get_job(db, prepared.job_id), ref, prepared.digest,
                operation_id=prepared.operation_id, activity_id=prepared.activity_id, work_kind="artifact_draft_v1")
        for (ref,) in life_rows:
            binding, digest = _read_reply_life_binding_metadata_v1(db, namespace=namespace,
                prepared_original_ref=ref, issuer=issuer)
            if binding.activity_id != cycle.activity_id:
                raise ValueError("Life child changed its signed plan/activity/effect binding")
            from .d11_life_contract_v1 import life_work_kind_v1
            add(get_job(db, binding.job_id), ref, digest,
                operation_id=binding.operation_id, activity_id=binding.activity_id, work_kind=life_work_kind_v1(binding))

    sql_scope = model_reply_scope_rows_v3(db,kind='children',parameters=(cycle.activity_id,),legacy_reader=lambda:db.execute("SELECT job_id FROM runtime_jobs WHERE bot_id=? AND persona_id=? AND activity_id=? "
        "AND work_kind IN ('artifact_draft_v1','d10.life.source_note.v1','d10.life.artifact_draft.v1','d07.recall_need') "
        "ORDER BY job_id LIMIT 257", (*namespace.as_tuple, cycle.activity_id)).fetchall())
    if len(sql_scope) > 256 or {item[0] for item in sql_scope} != {
            job_id for job_id, item in children.items() if item[0].work_kind in
            {"artifact_draft_v1", "d10.life.source_note.v1", "d10.life.artifact_draft.v1", "d07.recall_need"}}:
        raise MissingProductionOriginalV1("complete_actual_reply_C4_Life_SQL_original_inventory")
    generation = (_read_reply_natural_metadata_v1(db, namespace, continuation.c02_operation_id, "generation")
        if table_exists_v1(db, "graph_natural_generation_preparations_v2") else None)
    if generation is not None:
        review = (_read_reply_natural_metadata_v1(db, namespace, continuation.c02_operation_id, "review")
            if table_exists_v1(db, "graph_natural_review_preparations_v2") else None)
        for stage, saved in (("generation", generation), ("review", review)):
            if saved is None:
                continue
            seal = saved[0]
            if (seal.parent_budget_lease_id != continuation.call_plan.protected_reply_lease_ref
                    or (stage == "generation" and (seal.c02_operation_id != continuation.c02_operation_id
                        or seal.source_ref != continuation.source_ref))):
                raise ValueError("natural child differs from its sealed C02/protected allocation")
            job = get_job(db, seal.job_id)
            add(job, seal.original_operation_id, canonical_digest(plain_v1(seal)),
                operation_id=seal.original_operation_id, activity_id=job.activity_id,
                work_kind="natural_" + stage)
        if review is not None:
            for job, locator, digest in _read_reply_message_metadata_v1(db, namespace=namespace,
                    generation_seal=generation[0], review_seal=review[0]):
                add(job, locator, digest, operation_id=job.operation_id,
                    activity_id=job.activity_id, work_kind="message")
    return tuple(children[key] for key in sorted(children))


def _read_reply_model_cost_closed_v1(db, *, namespace, job, call_id, quote_id,
        reservation_digest, terminal_digest=None):
    """Read the existing seven-field cost receipt and its financial CAS members."""
    from .model_cost_settlement import OriginalModelCostCommitV1, original_model_cost_operation_id_v1
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    from .d11_types import RuntimeCostSettlement
    from .budget import BudgetReceipt
    from ..graph_store import GraphStore
    operation_id = original_model_cost_operation_id_v1(namespace, call_id)
    row = model_reply_scope_point_v3(db,table='graph_bundle_operations',columns=('activity_id', 'commit_seq', 'receipt_json'),key_columns=('bot', 'persona', 'operation_id'),key=(((*namespace.as_tuple, operation_id))[0],((*namespace.as_tuple, operation_id))[1],((*namespace.as_tuple, operation_id))[2],),legacy_reader=lambda:db.execute("SELECT activity_id,commit_seq,receipt_json FROM graph_bundle_operations "
        "WHERE bot=? AND persona=? AND operation_id=?", (*namespace.as_tuple, operation_id)).fetchone())
    if row is None:
        if terminal_digest is not None:
            raise MissingProductionOriginalV1("actual_reply_model_terminal_cost_commit")
        return False
    raw = background_json_loads_v3(row[2])
    if (set(raw) != {"original_model_cost", "original_intent_digest", "terminal_receipt_digest",
            "quote_id", "quote_version", "work_kind", "accounting_attempt_id"}
            or raw["work_kind"] != job.work_kind or raw["quote_id"] != quote_id):
        raise ValueError("reply model terminal lost its exact existing financial receipt ABI")
    paid = decode_typed_production_value_v1(raw["original_model_cost"], OriginalModelCostCommitV1)
    if (paid.status != "committed" or (paid.operation_id, paid.call_id, paid.quote_id, paid.commit_seq) !=
            (operation_id, call_id, quote_id, row[1]) or paid.terminal_receipt_digest != raw["terminal_receipt_digest"]
            or (terminal_digest is not None and paid.terminal_receipt_digest != terminal_digest)):
        raise ValueError("reply model terminal differs from its actual original cost identity")
    event = model_reply_scope_point_v3(db,table='graph_events',columns=('revisions',),key_columns=('bot', 'persona', 'session', 'event_id'),key=(((*namespace.as_tuple, row[0], operation_id))[0],((*namespace.as_tuple, row[0], operation_id))[1],((*namespace.as_tuple, row[0], operation_id))[2],((*namespace.as_tuple, row[0], operation_id))[3],),legacy_reader=lambda:db.execute("SELECT revisions FROM graph_events WHERE bot=? AND persona=? AND session=? AND event_id=?",
        (*namespace.as_tuple, row[0], operation_id)).fetchone())
    versions = () if event is None else tuple(v for v in _reply_event_version_rows_v3(event[0]) if v.key.token == paid.cost_ref)
    if len(versions) != 1:
        raise MissingProductionOriginalV1("actual_reply_model_cost_Graph_member")
    history = model_reply_scope_point_v3(db,table='graph_history',columns=('value', 'valid', 'event_id'),key_columns=('token', 'revision'),key=(((paid.cost_ref, versions[0].revision))[0],((paid.cost_ref, versions[0].revision))[1],),legacy_reader=lambda:db.execute("SELECT value,valid,event_id FROM graph_history WHERE token=? AND revision=?",
        (paid.cost_ref, versions[0].revision)).fetchone())
    if history is None or history[1:] != (1, operation_id):
        raise MissingProductionOriginalV1("actual_reply_model_cost_immutable_history")
    cost = decode_typed_production_value_v1(background_json_loads_v3(history[0]), RuntimeCostSettlement)
    budget = model_reply_scope_point_v3(db,table='runtime_budget_operations',columns=('digest', 'receipt_json'),key_columns=('bot_id','persona_id','operation_id','phase','lease_id'),key=(*namespace.as_tuple,cost.cost_operation_id,'settle',job.budget_ref),legacy_reader=lambda:db.execute("SELECT digest,receipt_json FROM runtime_budget_operations "
        "WHERE lease_id=? AND operation_id=? AND phase='settle'", (job.budget_ref, cost.cost_operation_id)).fetchone())
    if budget is None or budget[0] != reservation_digest:
        raise MissingProductionOriginalV1("actual_reply_model_terminal_budget_receipt")
    receipt = decode_typed_production_value_v1(background_json_loads_v3(budget[1]), BudgetReceipt)
    if (cost.lease_id != job.budget_ref or cost.bundle_operation_id != operation_id
            or canonical_digest(background_json_loads_v3(budget[1])) != paid.budget_receipt_digest
            or receipt.operation_id != cost.cost_operation_id or receipt.lease_id != job.budget_ref
            or receipt.status != cost.status):
        raise ValueError("reply model terminal lost its actual spent/unconfirmed accounting join")
    return True


def read_original_reply_pending_effects_v1(db, *, namespace: NamespaceId, cycle: PersistentJob,
        children: tuple[PersistentJob, ...], issuer: D11BudgetJobIssuer) -> tuple[str, ...]:
    """Known terminal originals close effects; cancellation phases never do."""
    from .d11_life_preparation_v1 import _read
    from .d11_life_terminal_v1 import read_adopted_life_original_v1
    from .d11_life_contract_v1 import D11LifeTerminalV1, life_from_wire_v1
    from .d01_production_operations_v1 import table_exists_v1, read_adopted_outbound_observation_original_v1
    actual = read_original_reply_child_jobs_v1(db, namespace=namespace, cycle=cycle, issuer=issuer)
    if type(children) is not tuple or children != tuple(item[0] for item in actual):
        raise ValueError("pending-effect metadata must use the complete actual child inventory")
    continuation = foreground_cycle_from_wire_v1(cycle.continuation)
    pending = set(continuation.pending_effect_refs)
    for job, locator, _ in actual:
        unresolved = False
        effect_ref = job.effect_id or job.operation_id
        if job.work_kind in {"d10.life.source_note.v1", "d10.life.artifact_draft.v1"}:
            binding, prepared_digest = _read_reply_life_binding_metadata_v1(db, namespace=namespace,
                prepared_original_ref=locator, issuer=issuer)
            adopted = read_adopted_life_original_v1(db, namespace=namespace,
                result_ref=binding.artifact_ref, issuer=issuer)
            if adopted is None:
                unresolved = True
            else:
                terminal = life_from_wire_v1(adopted["terminal"], D11LifeTerminalV1)
                if terminal.binding != binding or terminal.payload.prepared_digest != prepared_digest:
                    raise ValueError("Life physical terminal changed its signed preparation")
                unresolved = terminal.status == "unknown"
        elif job.work_kind == "message":
            rows = (() if not table_exists_v1(db, "graph_d13_outbound_observations_v1") else
                model_reply_scope_rows_v3(db,kind='outbound',parameters=(job.operation_id,),legacy_reader=lambda:db.execute("SELECT observation_digest FROM graph_d13_outbound_observations_v1 "
                    "WHERE bot=? AND persona=? AND final_operation_id=? ORDER BY observation_digest LIMIT 2",
                    (*namespace.as_tuple, job.operation_id)).fetchall()))
            if len(rows) > 1:
                raise ValueError("reply message has conflicting physical observations")
            if not rows:
                unresolved = True
            else:
                observed, _, _ = read_adopted_outbound_observation_original_v1(db, namespace, rows[0][0])
                platform = observed.pending.platform_observation
                if (platform.binding.origin.operation_id, platform.binding.origin.effect_id) != (job.operation_id, job.effect_id):
                    raise ValueError("reply physical observation belongs to another effect")
                unresolved = platform.outcome not in {"accepted", "delivered", "read", "failed_before_acceptance"}
        elif job.work_kind in {"natural_generation", "natural_review"}:
            stage = "generation" if job.work_kind == "natural_generation" else "review"
            saved = _read_reply_natural_metadata_v1(db, namespace, continuation.c02_operation_id, stage)
            seal, state, terminal_digest = saved
            unresolved = state == "acquired"
            reservation = model_reply_scope_point_v3(db,table='runtime_budget_reservations',columns=('state', 'digest'),key_columns=('lease_id', 'operation_id'),key=(((seal.parent_budget_lease_id, seal.reservation_operation_id))[0],((seal.parent_budget_lease_id, seal.reservation_operation_id))[1],),legacy_reader=lambda:db.execute("SELECT state,digest FROM runtime_budget_reservations WHERE lease_id=? AND operation_id=?",
                (seal.parent_budget_lease_id, seal.reservation_operation_id)).fetchone())
            if reservation is None:
                raise MissingProductionOriginalV1("actual_natural_reply_reservation")
            if state != "queued":
                quote_ref, _, quote_version = job.operator_versions["resource_quote"].rpartition(":")
                quote = issuer.resource_issuer.original_signed_quote(db, quote_ref, int(quote_version))
                if (quote.work_kind != job.work_kind or quote.parent_budget_lease_ref != job.budget_ref
                        or quote.graph_job_ref != job_graph_write(job).key.token
                        or quote.operation_id != seal.reservation_operation_id):
                    raise ValueError("natural reply child lost its original signed quote")
                paid = _read_reply_model_cost_closed_v1(db, namespace=namespace, job=job,
                    call_id=seal.call_id, quote_id=quote.quote_id,
                    reservation_digest=reservation[1], terminal_digest=terminal_digest)
                unresolved = not paid
            unresolved = unresolved or reservation[0] in {"unknown", "partial_unknown", "unconfirmed"}
        elif job.work_kind == "d07.recall_need":
            from .d07_execution_v1 import read_d07_accounting_prepared_v1, read_d07_original_v1
            prepared = read_d07_accounting_prepared_v1(db, issuer, namespace, job.job_id)
            call = read_d07_original_v1(db, issuer, namespace, "call", job.job_id)
            paid = read_d07_original_v1(db, issuer, namespace, "paid_cost", job.job_id)
            reservation = model_reply_scope_point_v3(db,table='runtime_budget_reservations',columns=('digest', 'state'),key_columns=('lease_id', 'operation_id'),key=(((job.budget_ref, prepared.operation_id))[0],((job.budget_ref, prepared.operation_id))[1],),legacy_reader=lambda:db.execute("SELECT digest,state FROM runtime_budget_reservations WHERE lease_id=? AND operation_id=?",
                (job.budget_ref, prepared.operation_id)).fetchone())
            if reservation is None or reservation[0] != prepared.reservation_digest:
                raise MissingProductionOriginalV1("actual_self_c3_reply_reservation")
            if paid is not None:
                cost = paid[0]
                financial = model_reply_scope_point_v3(db,table='runtime_budget_operations',columns=('digest', 'receipt_json'),key_columns=('bot_id','persona_id','operation_id','phase','lease_id'),key=(*namespace.as_tuple,prepared.operation_id,'settle',job.budget_ref),legacy_reader=lambda:db.execute("SELECT digest,receipt_json FROM runtime_budget_operations "
                    "WHERE lease_id=? AND operation_id=? AND phase='settle'",
                    (job.budget_ref, prepared.operation_id)).fetchone())
                atom = model_reply_scope_point_v3(db,table='graph_atoms',columns=('value', 'valid'),key_columns=('token',),key=(((cost["cost_ref"],))[0],),legacy_reader=lambda:db.execute("SELECT value,valid FROM graph_atoms WHERE token=?", (cost["cost_ref"],)).fetchone())
                if (cost["prepared_digest"] != prepared.digest or cost["paid"] is not True or cost["unknown_dimensions"]
                        or financial is None or financial[0]!=prepared.reservation_digest or not background_json_matches_v3(financial[1],cost["budget_receipt"])
                        or atom is None or atom[1]!=1 or not background_json_matches_v3(atom[0],cost["cost_value"])):
                    raise ValueError("Self C3 paid metadata lacks its actual financial CAS/Graph cost")
            unresolved = (call is not None and paid is None) or reservation[1] in {"unknown", "partial_unknown", "unconfirmed"}
        elif job.work_kind == "artifact_draft_v1":
            from .d11_artifact_draft_model_v1 import decode_artifact_draft_original_v1
            from ..model_broker.artifact_draft_v1 import artifact_draft_model_ids_v1
            row = _read(db, issuer=issuer, namespace=namespace, kind="c4_prepared", ref=locator)
            prepared = decode_artifact_draft_original_v1("c4_prepared", row[0])
            ids = artifact_draft_model_ids_v1(prepared.selector)
            call = _read(db, issuer=issuer, namespace=namespace, kind="c4_call", ref=ids["call"])
            paid = _read(db, issuer=issuer, namespace=namespace, kind="c4_paid", ref=ids["paid"])
            reservation = model_reply_scope_point_v3(db,table='runtime_budget_reservations',columns=('state',),key_columns=('lease_id', 'operation_id'),key=(((prepared.parent_budget_lease_ref, prepared.operation_id))[0],((prepared.parent_budget_lease_ref, prepared.operation_id))[1],),legacy_reader=lambda:db.execute("SELECT state FROM runtime_budget_reservations WHERE lease_id=? AND operation_id=?",
                (prepared.parent_budget_lease_ref, prepared.operation_id)).fetchone())
            if reservation is None:
                raise MissingProductionOriginalV1("actual_C4_reply_reservation")
            unresolved = (call is not None and paid is None) or reservation[0] in {"unknown", "partial_unknown", "unconfirmed"}
        elif job.work_kind == "d04.appraisal":
            from .d04_appraisal_driver_v3 import read_current_d04_appraisal_original_v3, read_d04_original_v3
            original = read_current_d04_appraisal_original_v3(db, namespace, job.job_id)
            call = read_d04_original_v3(db, namespace, "appraisal_call", job.job_id)
            paid = read_d04_original_v3(db, namespace, "appraisal_cost", job.job_id)
            reservation = model_reply_scope_point_v3(db,table='runtime_budget_reservations',columns=('state',),key_columns=('lease_id', 'operation_id'),key=(((job.budget_ref, original.operation_id))[0],((job.budget_ref, original.operation_id))[1],),legacy_reader=lambda:db.execute("SELECT state FROM runtime_budget_reservations WHERE lease_id=? AND operation_id=?",
                (job.budget_ref, original.operation_id)).fetchone())
            if reservation is None:
                raise MissingProductionOriginalV1("actual_C2_reply_reservation")
            if paid is not None:
                _read_reply_model_cost_closed_v1(db, namespace=namespace, job=job,
                    call_id=original.call_id, quote_id=original.quote_id, reservation_digest=original.reservation_digest)
            unresolved = (call is not None and paid is None) or reservation[0] in {"unknown", "partial_unknown", "unconfirmed"}
        else:
            raise ValueError("reply pending effects encountered an unregistered child family")
        if unresolved:
            pending.add(effect_ref)
        elif job.effect_id is not None:
            pending.discard(job.effect_id)
    return tuple(sorted(pending))


def _read_observed_foreground_base_attempts_v1(db, *, namespace, continuation, issuer):
    """Rebuild every configured original slot already present for this same C02."""
    from .foreground_call_plan_v1 import ForegroundModelAttemptV1
    from .d01_production_operations_v1 import table_exists_v1
    result = [_original_encoding_attempt_v1(db, namespace=namespace, c02_operation_id=continuation.c02_operation_id,
        source_ref=continuation.source_ref, parent_budget_ref=continuation.call_plan.parent_budget_lease_ref, issuer=issuer)]
    if table_exists_v1(db, "graph_d04_originals_v3"):
        from .d04_product_pipeline_v3 import ids
        from .d04_appraisal_driver_v3 import read_current_d04_appraisal_original_v3
        original = read_current_d04_appraisal_original_v3(db, namespace, ids(namespace, continuation.c02_operation_id)["job"])
        if original is not None:
            quote = issuer.resource_issuer.original_signed_quote(db, original.quote_id, original.quote_version)
            selector = ForegroundModelAttemptV1("C2", original.call_id, None, quote.operation_id,
                original.reservation_digest, quote.parent_budget_lease_ref,
                quote.ceiling["input_tokens"], quote.ceiling["output_tokens"], "reserved")
            result.append(_current_attempt_original_v1(db, namespace=namespace, continuation=continuation, attempt=selector, issuer=issuer))
    if table_exists_v1(db, "graph_natural_generation_preparations_v2"):
        from .natural_reply_job_v2 import read_original_preparation
        generation = read_original_preparation(db, namespace, continuation.c02_operation_id, "generation")
        observed = [] if generation is None else [("C5", generation)]
        if generation is not None and table_exists_v1(db, "graph_natural_review_preparations_v2"):
            review = read_original_preparation(db, namespace, continuation.c02_operation_id, "review")
            if review is not None:
                observed.append(("C6", review))
        for slot, original in observed:
            seal = original.seal
            row = db.execute("SELECT digest,ceiling_json FROM runtime_budget_reservations WHERE lease_id=? AND operation_id=?",
                (seal.parent_budget_lease_id, seal.reservation_operation_id)).fetchone()
            if row is None:
                raise ValueError("actual natural slot has no original existing reservation")
            ceiling = json.loads(row[1])
            selector = ForegroundModelAttemptV1(slot, seal.call_id, None, seal.reservation_operation_id,
                row[0], seal.parent_budget_lease_id, ceiling["input_tokens"], ceiling["output_tokens"], "reserved")
            result.append(_current_attempt_original_v1(db, namespace=namespace, continuation=continuation, attempt=selector, issuer=issuer))
    return result


def read_observed_foreground_call_plan_v1(db, *, namespace, continuation, issuer, installed_bundle=None, owner_guard=None):
    """Rebuild every configured original slot already present for this same C02."""
    if type(continuation.call_plan) is ForegroundCallPlanV2:
        return read_observed_foreground_call_plan_v2(db, namespace=namespace, continuation=continuation, issuer=issuer,
            installed_bundle=installed_bundle, owner_guard=owner_guard)
    result = _read_observed_foreground_base_attempts_v1(db, namespace=namespace, continuation=continuation, issuer=issuer)
    for attempt in continuation.call_plan.attempts:
        if attempt.slot in {"C3", "C4"}:
            result.append(_current_attempt_original_v1(db, namespace=namespace, continuation=continuation, attempt=attempt, issuer=issuer))
    return ForegroundCallPlanV1(continuation.call_plan.parent_budget_lease_ref,
        continuation.call_plan.protected_reply_lease_ref, tuple(result))


def read_observed_foreground_call_plan_v2(db, *, namespace, continuation, issuer, installed_bundle=None, owner_guard=None):
    from .d11_artifact_draft_model_v1 import require_current_artifact_phase_group_v2
    plan = continuation.call_plan
    if type(plan) is not ForegroundCallPlanV2:
        raise TypeError("actual versioned phase call plan required")
    if require_current_artifact_phase_group_v2(db, namespace=namespace, group=plan.phase_group, issuer=issuer,
            installed_bundle=installed_bundle, owner_guard=owner_guard) != plan.phase_group:
        raise ValueError("observed phase plan lost its actual adopted method/source/verified originals")
    result = _read_observed_foreground_base_attempts_v1(db, namespace=namespace, continuation=continuation, issuer=issuer)
    for attempt in plan.attempts:
        if attempt.slot in {"C3", "C4"}:
            result.append(_current_attempt_original_v1(db, namespace=namespace,
                continuation=continuation, attempt=attempt, issuer=issuer))
    return ForegroundCallPlanV2(plan.parent_budget_lease_ref, plan.protected_reply_lease_ref,
        tuple(result), phase_group=plan.phase_group)


def derive_actual_completed_artifact_phase_plan_v2(db, *, namespace, continuation, issuer):
    """Project one actual signed phase verification into the existing checkpoint contract."""
    from .d11_life_preparation_v1 import _read
    from .d11_artifact_draft_content_v1 import read_current_artifact_phase_verified_v2
    from .d11_artifact_draft_model_v1 import require_current_artifact_phase_group_v2
    from .foreground_call_plan_v1 import ForegroundArtifactPhaseGroupV2, require_foreground_phase_checkpoint_v2
    from ..model_broker.artifact_draft_v1 import artifact_draft_phase_sequence_v2, artifact_draft_phase_original_ref_v2
    if type(continuation) is not ForegroundCycleContinuationV2 or type(continuation.call_plan) is not ForegroundCallPlanV2:
        raise TypeError("phase advancement requires the actual versioned foreground continuation")
    observed = read_observed_foreground_call_plan_v2(db, namespace=namespace, continuation=continuation, issuer=issuer)
    group = observed.phase_group; selector = group.selector
    ref = artifact_draft_phase_original_ref_v2(selector) + ":verified"
    original = _read(db, issuer=issuer, namespace=namespace, kind="c4_phase_verified", ref=ref)
    if original is None:
        return observed
    verified = read_current_artifact_phase_verified_v2(db, namespace=namespace, selector=selector, issuer=issuer)
    completed = group.completed_phase_originals
    fact = (verified.original_ref, verified.digest)
    if len(completed) == selector.phase_index + 1:
        if completed[-1] != fact:
            raise ValueError("phase advancement changed its actual already-recorded verification")
        return observed
    completed = (*completed, fact)
    phases = artifact_draft_phase_sequence_v2(selector.method_ref)
    if selector.phase_index + 1 < len(phases):
        selector = replace(selector, phase_index=selector.phase_index + 1, phase_kind=phases[selector.phase_index + 1],
            prev_phase_original_ref=fact[0], prev_phase_original_digest=fact[1])
    current = replace(observed, phase_group=ForegroundArtifactPhaseGroupV2(selector, completed))
    require_foreground_phase_checkpoint_v2(continuation.call_plan, current)
    require_current_artifact_phase_group_v2(db, namespace=namespace, group=current.phase_group, issuer=issuer)
    return current


def stage_current_foreground_cycle_in_transaction_v1(db, *, frame, request, installed_readers):
    from .source_note_foreground_v1 import (CreateSourceNoteForegroundCycleRequestV1, stage_create_source_note_foreground_cycle_v1,
        CheckpointSourceNoteForegroundCycleRequestV1, ForegroundSourceNoteContinuationV1)
    if type(request) is CreateSourceNoteForegroundCycleRequestV1:
        return stage_create_source_note_foreground_cycle_v1(db, frame=frame, request=request, installed_readers=installed_readers)
    if type(installed_readers) is not InstalledForegroundCycleReadersV1 or type(installed_readers.issuer) is not D11BudgetJobIssuer:
        raise TypeError("foreground cycle requires its actual installed original reader")
    ns, issuer = frame.envelope.authority.namespace, installed_readers.issuer
    read = CurrentDomainReadV1(frame)
    read.check(db)
    allocation = None
    responsibility = None
    if type(request) in {CreateForegroundCycleRequestV1, CreateForegroundCycleRequestV2}:
        if type(request) is CreateForegroundCycleRequestV2:
            responsibility = derive_current_foreground_responsibility_v1(db, namespace=ns, request=request,
                installed_bundle=installed_readers.installed_bundle, issuer=issuer, owner_guard=frame.owner_guard,
                parent_budget_lease_ref=frame.envelope.parent_budget_lease_ref, purpose=frame.envelope.authority.purpose,
                audiences=frame.envelope.authority.audience, now_utc=frame.now_utc)
            if responsibility.deadline_utc != frame.envelope.deadline_utc:
                raise ValueError("new foreground create changed its original responsibility window")
        if request.protected_reply_lease_ref != foreground_reply_budget_ids_v1(ns, request.c02_operation_id)[0]:
            raise ValueError("foreground create cannot choose or reuse another reply child identity")
        allocation = prepare_foreground_reply_allocation_v1(db, namespace=ns,
            c02_operation_id=request.c02_operation_id, source_ref=request.source_ref,
            parent_budget_lease_ref=frame.envelope.parent_budget_lease_ref, issuer=issuer,
            installed_bundle=installed_readers.installed_bundle, now_utc=frame.now_utc,
            deadline_utc=frame.envelope.deadline_utc)
        receipt = _adopted_c02_v1(db, ns, request.c02_operation_id)
        attempt = _original_encoding_attempt_v1(db, namespace=ns, c02_operation_id=request.c02_operation_id,
            source_ref=request.source_ref, parent_budget_ref=frame.envelope.parent_budget_lease_ref, issuer=issuer)
        plan = ForegroundCallPlanV1(frame.envelope.parent_budget_lease_ref, request.protected_reply_lease_ref, (attempt,))
        after, primary = prepare_foreground_cycle_in_transaction_v1(db, frame=frame, c02_receipt=receipt,
            source_ref=request.source_ref, call_plan=plan, issuer=issuer, reply_allocation=allocation, responsibility=responsibility)
        if primary is None:
            raise ValueError("foreground creation may only stage its absent target; replay uses its original receipt")
        continuation = foreground_cycle_from_wire_v1(after.continuation)
        observed = read_observed_foreground_call_plan_v1(db, namespace=ns, continuation=continuation, issuer=issuer)
        if observed != continuation.call_plan:
            continuation = replace(continuation, call_plan=observed)
            after = replace(after, continuation=plain_v1(continuation))
            primary = stage_result_v1(frame, "d11", "create_foreground_cycle", request,
                writes=(job_graph_write(after),), provenance={"continuation": continuation, "c02_receipt": receipt},
                receiver_events=(("d11", "foreground_cycle_ready"),), proposal_schema=D11_PROPOSAL_SCHEMA,
                proposal_hash=D11RuntimeProvider().descriptor.request_schema_hash)
        before = None
    else:
        job_key = AtomKey.from_token(request.job_ref)
        before = get_job(db, job_key.name)
        require_current_foreground_responsibility_v1(db, namespace=ns, job=before,
            installed_bundle=installed_readers.installed_bundle, issuer=issuer, owner_guard=frame.owner_guard,
            purpose=frame.envelope.authority.purpose, audiences=frame.envelope.authority.audience, now_utc=frame.now_utc)
        current_plan = foreground_cycle_from_wire_v1(before.continuation).call_plan
        require_protected_reply_budget_v1(db, namespace=ns, plan=current_plan, issuer=issuer, now_utc=frame.now_utc,
            installed_bundle=installed_readers.installed_bundle, owner_guard=frame.owner_guard)
        if job_graph_write(before).key != job_key or before.activity_id != frame.envelope.identity.activity_id:
            raise ValueError("foreground request refers to another exact original cycle")
        atom = read.head(db, job_key, required=True)
        if atom.value != job_graph_write(before).value:
            raise ValueError("foreground SQL/Graph job projection differs before staging")
        if type(request) is AcquireForegroundCycleRequestV1:
            if request.holder != frame.envelope.authority.actor:
                raise ValueError("foreground worker holder must be the actual current registered self")
            after = plan_job_acquire(before, request.holder, now_utc=_utc_text(datetime.fromtimestamp(
                frame.now_utc, timezone.utc)), lease_seconds=request.lease_seconds)
            if _utc(after.lease_expires_utc, "lease_expires_utc").timestamp() > frame.envelope.deadline_utc:
                raise ValueError("foreground worker lease exceeds its independently frozen original deadline")
            primary = stage_result_v1(frame, "d11", "acquire_foreground_cycle", request, writes=(job_graph_write(after),),
                provenance={"before_job": before, "after_job": after}, proposal_schema=D11_PROPOSAL_SCHEMA,
                proposal_hash=D11RuntimeProvider().descriptor.request_schema_hash)
        elif type(request) in {CheckpointForegroundCycleRequestV1, CheckpointForegroundCycleRequestV2, CheckpointSourceNoteForegroundCycleRequestV1}:
            proposed = request.continuation
            prior_continuation = foreground_cycle_from_wire_v1(before.continuation)
            expected_type = (ForegroundSourceNoteContinuationV1 if type(request) is CheckpointSourceNoteForegroundCycleRequestV1 else
                ForegroundCycleContinuationV2 if type(request) is CheckpointForegroundCycleRequestV2 else ForegroundCycleContinuationV1)
            if type(proposed) is not expected_type or type(prior_continuation) is not expected_type:
                raise ValueError("foreground checkpoint cannot change its exact original continuation version")
            if expected_type in {ForegroundCycleContinuationV2, ForegroundSourceNoteContinuationV1} and (proposed.responsibility_ref, proposed.responsibility_digest) != (
                    prior_continuation.responsibility_ref, prior_continuation.responsibility_digest):
                raise ValueError("foreground checkpoint cannot rewrite its original responsibility")
            if expected_type is ForegroundSourceNoteContinuationV1 and (proposed.authorization_original_ref, proposed.authorization_original_digest) != (
                    prior_continuation.authorization_original_ref, prior_continuation.authorization_original_digest):
                raise ValueError("SourceNote checkpoint cannot replace its original signed task authorization")
            from .d11_artifact_draft_content_v1 import artifact_method_settlement_operation_id_v2,read_current_completed_artifact_method_history_v2
            from .domain_production_originals_v1 import read_adopted_domain_operation_v1
            completed_history=None
            if type(proposed.call_plan) is ForegroundCallPlanV2:
                completed_original=read_adopted_domain_operation_v1(db,ns,artifact_method_settlement_operation_id_v2(proposed.call_plan.phase_group.selector))
                if completed_original is not None:
                    completed_history,_=read_current_completed_artifact_method_history_v2(db,namespace=ns,selector=proposed.call_plan.phase_group.selector,
                        issuer=issuer,owner_guard=frame.owner_guard,installed_bundle=installed_readers.installed_bundle)
            if completed_history is None:
                observed = read_observed_foreground_call_plan_v1(db, namespace=ns, continuation=proposed, issuer=issuer,
                    installed_bundle=installed_readers.installed_bundle, owner_guard=frame.owner_guard)
            else:
                if proposed.call_plan.phase_group.completed_phase_originals!=completed_history.ordered_phase_originals:
                    raise ValueError('completed cycle changed actual verified method history')
                attempts=_read_observed_foreground_base_attempts_v1(db,namespace=ns,continuation=proposed,issuer=issuer)
                for attempt in proposed.call_plan.attempts:
                    if attempt.slot in {'C3','C4'}:
                        attempts.append(_current_attempt_original_v1(db,namespace=ns,continuation=proposed,attempt=attempt,issuer=issuer))
                observed=ForegroundCallPlanV2(proposed.call_plan.parent_budget_lease_ref,proposed.call_plan.protected_reply_lease_ref,
                    tuple(attempts),phase_group=proposed.call_plan.phase_group)
            if observed != proposed.call_plan:
                raise ValueError("foreground checkpoint model states differ from their actual adopted originals")
            after, primary = checkpoint_foreground_cycle_in_transaction_v1(db, frame=frame, job_id=before.job_id,
                holder=request.holder, fence=request.fence, continuation=proposed, usage=before.usage,
                completion_result_ref=request.completion_result_ref, method_completion_history=completed_history,
                frame_issuer=issuer,frame_bundle=installed_readers.installed_bundle)
        elif type(request) is WakeArtifactDraftCycleRequestV2:
            after, primary = wake_artifact_draft_cycle_in_transaction_v2(db, frame=frame, request=request, issuer=issuer)
        elif type(request) is WakeArtifactDraftCycleRequestV1:
            after, primary = wake_artifact_draft_cycle_in_transaction_v1(db, frame=frame, request=request, issuer=issuer)
        elif type(request) is WakeForegroundCycleRequestV1:
            after, primary = wake_foreground_cycle_from_outbox_in_transaction_v1(db, frame=frame,
                job_id=before.job_id, dedupe_key=request.dedupe_key, issuer=issuer)
            if primary is None:
                raise ValueError("foreground wake requires its actual registered waiting job")
        else:
            raise TypeError("unregistered foreground cycle request")
    provenance = json.loads(primary.original_payload_json)["provenance"] if type(request) in {WakeArtifactDraftCycleRequestV1, WakeArtifactDraftCycleRequestV2} else {"before_job": before, "after_job": after}
    if allocation is not None:
        provenance["reply_allocation"] = allocation
    if responsibility is not None:
        provenance["foreground_responsibility"] = responsibility
    primary = stage_result_v1(frame, "d11", frame.envelope.identity.phase, request,
        writes=(job_graph_write(after),), provenance=provenance,
        receiver_events=tuple((event.receiver_domain, event.event_kind) for event in primary.outbox),
        proposal_schema=D11_PROPOSAL_SCHEMA, proposal_hash=D11RuntimeProvider().descriptor.request_schema_hash)
    return ForegroundCycleStageV1(frame, primary, request, before, after, allocation)


def verify_foreground_cycle_stage_v1(db, stage, installed_readers, *, applied=False):
    if type(stage) is not ForegroundCycleStageV1:
        raise TypeError("exact foreground pure stage required")
    if applied:
        if get_job(db, stage.after_job.job_id) != stage.after_job:
            raise ValueError("foreground once-applied SQL job differs from its frozen proposal")
        return
    rebuilt = stage_current_foreground_cycle_in_transaction_v1(db, frame=stage.frame,
        request=stage.request, installed_readers=installed_readers)
    if rebuilt != stage:
        raise ValueError("foreground pure stage changed before atomic job adoption")


def apply_foreground_cycle_stage_v1(db, stage, installed_readers):
    verify_foreground_cycle_stage_v1(db, stage, installed_readers)
    request, before, after = stage.request, stage.before_job, stage.after_job
    if before is None:
        if stage.reply_allocation is None:
            raise ValueError("foreground new cycle lacks its actual pure reply allocation")
        apply_foreground_reply_allocation_v1(db, allocation=stage.reply_allocation, issuer=installed_readers.issuer)
        updated = create_job(db, after, stage.stage.operation_id, canonical_digest(after.continuation))
    elif type(request) is AcquireForegroundCycleRequestV1:
        from datetime import datetime, timezone
        updated = acquire_job(db, before.job_id, request.holder,
            now_utc=_utc_text(datetime.fromtimestamp(stage.frame.now_utc, timezone.utc)), lease_seconds=request.lease_seconds)
    elif type(request) in {WakeForegroundCycleRequestV1, WakeArtifactDraftCycleRequestV1, WakeArtifactDraftCycleRequestV2}:
        updated = wake_job(db, before.job_id, stage.stage.operation_id, canonical_digest(request))
    else:
        updated = _job_from_dict(_job_dict(after))
        _save_job(db, updated)
        if after.phase == "queued":
            _record_operation(db, updated, "foreground-recheck:" + stage.stage.operation_id,
                "wake", canonical_digest(request.continuation.wait))
    if updated != after:
        raise ValueError("foreground actual single job mutation differs from the frozen pure proposal")


def read_plan_current_foreground_cycle_v1(db, *, namespace, request):
    if type(request) in {CreateForegroundCycleRequestV1, CreateForegroundCycleRequestV2}:
        plan = foreground_cycle_read_plan_v1(namespace=namespace,
            c02_receipt=_adopted_c02_v1(db, namespace, request.c02_operation_id), source_ref=request.source_ref)
        if type(request) is CreateForegroundCycleRequestV2:
            from ..domains.d03.self_perspective import self_mapping_key
            plan = replace(plan, exact_keys=tuple(dict.fromkeys((*plan.exact_keys, self_mapping_key(namespace)))),
                required_original_refs=tuple(dict.fromkeys((*plan.required_original_refs, request.cause_original_ref))))
        return plan
    if type(request) is WakeArtifactDraftCycleRequestV2:
        from .d11_artifact_draft_model_v1 import read_plan_artifact_draft_model_v2, AcquireArtifactDraftModelRequestV2
        from ..model_broker.artifact_draft_v1 import artifact_draft_model_ids_v2
        plan = read_plan_artifact_draft_model_v2(db, namespace=namespace,
            operation_kind="acquire_artifact_draft_model_v2", request=AcquireArtifactDraftModelRequestV2(request.selector))
        ids = artifact_draft_model_ids_v2(request.selector)
        return replace(plan, required_original_refs=tuple(dict.fromkeys((*plan.required_original_refs, ids["paid"], ids["result"], ids["call"]))))
    if type(request) is WakeArtifactDraftCycleRequestV1:
        from .d11_artifact_draft_model_v1 import read_plan_artifact_draft_model_v1, AcquireArtifactDraftModelRequestV1
        from ..model_broker.artifact_draft_v1 import artifact_draft_model_ids_v1
        plan = read_plan_artifact_draft_model_v1(db, namespace=namespace,
            operation_kind="acquire_artifact_draft_model", request=AcquireArtifactDraftModelRequestV1(request.selector))
        ids = artifact_draft_model_ids_v1(request.selector)
        return replace(plan, required_original_refs=tuple(dict.fromkeys((*plan.required_original_refs, ids["paid"], ids["result"], ids["call"]))))
    job = get_job(db, AtomKey.from_token(request.job_ref).name)
    current = foreground_cycle_from_wire_v1(job.continuation)
    keys = [job_graph_write(job).key]
    from .source_note_foreground_v1 import CheckpointSourceNoteForegroundCycleRequestV1
    if type(request) in {CheckpointForegroundCycleRequestV1, CheckpointForegroundCycleRequestV2, CheckpointSourceNoteForegroundCycleRequestV1} and request.continuation.wait is not None:
        keys.extend(AtomKey.from_token(row.ref) for row in request.continuation.wait.observed_versions)
    if current.wait is not None:
        keys.extend(AtomKey.from_token(row.ref) for row in current.wait.observed_versions)
    from .d07_reflection_execution_v1 import reflection_obligation_read_plan_inputs_v3
    extra_keys,extra_roots,extra_originals=reflection_obligation_read_plan_inputs_v3(db,namespace,job_graph_write(job).key.token)
    return production_read_plan_v1((),(*keys,*extra_keys),(current.source_ref,*extra_roots),extra_originals)


def wake_artifact_draft_cycle_in_transaction_v2(db, *, frame, request, issuer):
    from ..model_broker.artifact_draft_v1 import artifact_draft_model_ids_v2
    from .d11_artifact_draft_model_v1 import (read_artifact_draft_prepared_v2,
        read_current_artifact_draft_attempt_v2, decode_artifact_draft_original_v2)
    from .d11_life_preparation_v1 import _read
    from .c09_life_originals_v1 import require_c4_model_cost_original_commit_v1
    if type(request) is not WakeArtifactDraftCycleRequestV2:
        raise TypeError("exact registered C4 terminal wake required")
    if frame.envelope.identity.operation_id != artifact_draft_phase_wake_operation_id_v2(request.selector):
        raise ValueError('phase wake changed its actual deterministic original once operation')
    read = CurrentDomainReadV1(frame)
    read.check(db)
    ns = frame.envelope.authority.namespace
    if request.selector.task.namespace != ns:
        raise ValueError("C4 terminal wake crossed namespace")
    cycle = get_job(db, AtomKey.from_token(request.job_ref).name)
    current = foreground_cycle_from_wire_v1(cycle.continuation)
    if (cycle.phase != "waiting" or cycle.cancel_epoch or current.wait is None
            or cycle.lease_holder is not None or cycle.lease_expires_utc is not None
            or read.head(db, request.job_ref, required=True).value != job_graph_write(cycle).value):
        raise ValueError("C4 wake requires the actual waiting unleased SQL/Graph cycle")
    ids = artifact_draft_model_ids_v2(request.selector)
    prepared = read_artifact_draft_prepared_v2(db, namespace=ns, issuer=issuer, selector=request.selector)
    if prepared is None:
        raise MissingProductionOriginalV1("actual_c4_prepared_for_terminal_wake")
    if (current.c02_operation_id != request.selector.task.c02_operation_id
            or cycle.budget_ref != prepared.parent_budget_lease_ref
            or prepared.actor_ref != frame.envelope.authority.actor
            or current.wait.event_kind not in {"artifact_draft_phase_model_queued", "artifact_draft_phase_model_terminal"}):
        raise ValueError("C4 terminal wake changed its original task/self/wait")
    if type(current.call_plan) is not ForegroundCallPlanV2 or current.call_plan.phase_group.selector != request.selector:
        raise ValueError("phase wake changed its exact current method group")
    from .d11_artifact_draft_model_v1 import require_current_artifact_phase_group_v2
    if require_current_artifact_phase_group_v2(db, namespace=ns, group=current.call_plan.phase_group, issuer=issuer) != current.call_plan.phase_group:
        raise ValueError("phase wake lost its actual adopted method/source/verification chain")
    attempts = tuple(attempt for attempt in current.call_plan.attempts
        if type(attempt) is ForegroundModelAttemptV2 and attempt.phase_selector == request.selector)
    if len(attempts) != 1:
        raise ValueError("phase wake requires its unique actual generation call")
    actual = read_current_artifact_draft_attempt_v2(db, namespace=ns, continuation=current, attempt=attempts[0], issuer=issuer)
    if actual.state != "completed" or actual.terminal_ref != ids["result"]:
        raise MissingProductionOriginalV1("actual_paid_signed_c4_terminal_result")
    call = _read(db, issuer=issuer, namespace=ns, kind="c4_phase_call", ref=prepared.call_id)
    paid = _read(db, issuer=issuer, namespace=ns, kind="c4_phase_paid", ref=ids["paid"])
    result = _read(db, issuer=issuer, namespace=ns, kind="c4_phase_result", ref=ids["result"])
    if call is None or paid is None or result is None:
        raise MissingProductionOriginalV1("actual_c4_call_paid_result_for_terminal_wake")
    cost = decode_artifact_draft_original_v2("c4_phase_paid", paid[0])
    require_c4_model_cost_original_commit_v1(db, namespace=ns, operation_id=cost.operation_id)
    event = db.execute("SELECT causal_operation_id,receiver_domain,event_kind,original_ref,original_digest,state "
        "FROM graph_domain_production_outbox_v1 WHERE bot=? AND persona=? AND dedupe_key=?",
        (*ns.as_tuple, request.dedupe_key)).fetchone()
    read.committed_operation(db, ids["prepare"])
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    adopted = read_adopted_domain_operation_v1(db, ns, ids["prepare"])
    if (adopted is None or event != (ids["prepare"], "d11", "artifact_draft_phase_model_queued",
            "d11-current:" + adopted["original_digest"][:48], adopted["original_digest"], "pending")):
        raise ValueError("C4 wake is not linked to its actual original queued prepare outbox")
    after = replace(cycle, phase="queued", wake_condition=None)
    stage = stage_result_v1(frame, "d11", "wake_artifact_draft_cycle_v2", request,
        writes=(job_graph_write(after),), provenance={"before_job": cycle, "after_job": after,
            "queued_dedupe_key": request.dedupe_key, "prepared_digest": prepared.digest,
            "paid_ref": ids["paid"], "paid_digest": canonical_digest(paid[0]),
            "result_ref": ids["result"], "result_digest": canonical_digest(result[0])},
        proposal_schema=D11_PROPOSAL_SCHEMA, proposal_hash=D11RuntimeProvider().descriptor.request_schema_hash)
    return after, stage


def record_artifact_draft_wake_disposition_after_cas_v2(db, *, stage, receipt):
    """Dispose the original queued event in the actual self wake transaction."""
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    if (not db.in_transaction or type(stage) is not ForegroundCycleStageV1
            or type(stage.request) is not WakeArtifactDraftCycleRequestV2 or type(receipt) is not CommitReceipt
            or receipt.status != "committed" or receipt.operation_id != stage.stage.operation_id
            or get_job(db, stage.after_job.job_id) != stage.after_job):
        raise ValueError("C4 wake disposition requires its actual same-CAS self receipt/job")
    ns = stage.stage.namespace
    adopted = read_adopted_domain_operation_v1(db, ns, receipt.operation_id)
    provenance = json.loads(stage.stage.original_payload_json)["provenance"]
    if adopted is None or adopted["operation_kind"] != "wake_artifact_draft_cycle_v2" or adopted["receipt"] != receipt:
        raise MissingProductionOriginalV1("actual_adopted_self_C4_terminal_wake")
    row = db.execute("SELECT causal_operation_id,event_kind,original_ref,original_digest,state "
        "FROM graph_domain_production_outbox_v1 WHERE bot=? AND persona=? AND dedupe_key=?",
        (*ns.as_tuple, stage.request.dedupe_key)).fetchone()
    if row is None or row[1] != "artifact_draft_phase_model_queued" or row[4] != "pending":
        raise ValueError("C4 self wake lost its original unconsumed queued cause")
    value = {"schema": "d11.artifact-draft-wake-disposition.v2", "dedupe_key": stage.request.dedupe_key,
        "causal_operation_id": row[0], "trigger_original_ref": row[2], "trigger_original_digest": row[3],
        "state": "completed", "consumer_operation_id": receipt.operation_id,
        "consumer_original_digest": adopted["original_digest"], "consumer_receipt_digest": canonical_digest(receipt),
        "cycle_job_ref": stage.request.job_ref, "prepared_digest": provenance["prepared_digest"],
        "paid_ref": provenance["paid_ref"], "paid_digest": provenance["paid_digest"],
        "result_ref": provenance["result_ref"], "result_digest": provenance["result_digest"]}
    db.execute("UPDATE graph_domain_production_outbox_v1 SET state='completed',consumer_operation_id=?,receipt_json=? "
        "WHERE bot=? AND persona=? AND dedupe_key=? AND state='pending'",
        (receipt.operation_id, canonical_serialize(value), *ns.as_tuple, stage.request.dedupe_key))
    if db.execute("SELECT changes()").fetchone() != (1,):
        raise ValueError("C4 queued cause changed before its atomic self disposition")
    validate_artifact_draft_wake_disposition_v2(db, namespace=ns, row_data={
        "dedupe_key": stage.request.dedupe_key, "causal_operation_id": row[0], "original_ref": row[2],
        "original_digest": row[3], "consumer_operation_id": receipt.operation_id,
        "event_kind": row[1], "receiver_domain": "d11", "state": "completed"}, value=value)
    return value


def validate_artifact_draft_wake_disposition_v2(db, *, namespace, row_data, value):
    """Recognize only the dedicated wake's immutable stage and actual receipt."""
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    expected = {"schema", "dedupe_key", "causal_operation_id", "trigger_original_ref", "trigger_original_digest",
        "state", "consumer_operation_id", "consumer_original_digest", "consumer_receipt_digest", "cycle_job_ref",
        "prepared_digest", "paid_ref", "paid_digest", "result_ref", "result_digest"}
    if (db is None or type(value) is not dict or set(value) != expected
            or value["schema"] != "d11.artifact-draft-wake-disposition.v2" or value["state"] != "completed"
            or row_data["state"] != "completed" or row_data["event_kind"] != "artifact_draft_phase_model_queued"
            or row_data["receiver_domain"] != "d11"
            or any(value[name] != row_data[name] for name in
                ("dedupe_key", "causal_operation_id", "state", "consumer_operation_id"))
            or value["trigger_original_ref"] != row_data["original_ref"]
            or value["trigger_original_digest"] != row_data["original_digest"]):
        raise ValueError("C4 self wake disposition is outside its exact original queued event")
    adopted = read_adopted_domain_operation_v1(db, namespace, value["consumer_operation_id"])
    if (adopted is None or adopted["domain"] != "d11" or adopted["operation_kind"] != "wake_artifact_draft_cycle_v2"
            or adopted["original_digest"] != value["consumer_original_digest"]
            or canonical_digest(adopted["receipt"]) != value["consumer_receipt_digest"]):
        raise MissingProductionOriginalV1("C4_actual_self_wake_disposition_receipt")
    request = decode_typed_production_value_v1(adopted["payload"]["request"], WakeArtifactDraftCycleRequestV2)
    proof = adopted["payload"]["provenance"]
    if (request.dedupe_key != value["dedupe_key"] or request.job_ref != value["cycle_job_ref"]
            or any(proof[name] != value[name] for name in
                ("prepared_digest", "paid_ref", "paid_digest", "result_ref", "result_digest"))):
        raise ValueError("C4 self disposition lost its exact signed terminal predicate")
    producer = read_adopted_domain_operation_v1(db, namespace, value["causal_operation_id"])
    if (producer is None or producer["operation_kind"] != "prepare_artifact_draft_model_v2"
            or value["trigger_original_ref"] != "d11-current:" + producer["original_digest"][:48]
            or value["trigger_original_digest"] != producer["original_digest"]):
        raise MissingProductionOriginalV1("actual_C4_prepare_queued_event_producer")
    return value



def artifact_draft_phase_wake_operation_id_v2(selector):
    from ..model_broker.artifact_draft_v1 import ArtifactDraftPhaseSelectorV2, artifact_draft_phase_original_ref_v2
    if type(selector) is not ArtifactDraftPhaseSelectorV2 or not selector.generation:
        raise TypeError('phase wake requires its original exact generation selector')
    return artifact_draft_phase_original_ref_v2(selector) + ':wake'


def require_actual_c02_cue_source_v1(db, *, namespace, c02_operation_id, source_version):
    """C02 consumes the already committed ingress Source through its frozen read qualification."""
    from .c02_bundle_codec import c02_bundle_from_wire
    from .d01_production_operations_v1 import MissingProductionOriginalV1
    from ..graph_types import GraphVersion
    from ..runtime_contracts import NamespaceId
    if (type(source_version) is not GraphVersion or source_version.revision < 1
            or source_version.key.type_name != 'memory.source' or NamespaceId.from_key(source_version.key) != namespace):
        raise ValueError('actual C02 cue requires its exact namespace Source head')
    receipt = _adopted_c02_v1(db, namespace, c02_operation_id)
    from ..authority_service.model_reply_scope_observation_v3 import require_model_reply_scope_c02_envelope_v3
    envelope=require_model_reply_scope_c02_envelope_v3(db,namespace,c02_operation_id)
    if envelope is None:
        row = db.execute('SELECT bundle_json FROM graph_first_ingress_c02_committed_seals_v2 WHERE bot=? AND persona=? AND operation_id=?',
            (*namespace.as_tuple,c02_operation_id)).fetchone()
        if row is None:
            raise MissingProductionOriginalV1('actual_committed_C02_cue_source_qualification')
        envelope = c02_bundle_from_wire(row[0]).envelope
    if (envelope.authority.namespace != namespace or envelope.identity.operation_id != c02_operation_id
            or source_version.key.token not in envelope.source_qualification.source_refs
            or source_version not in envelope.version_guard.read_versions):
        raise ValueError('C02 cue differs from its actual frozen Source qualification/read version')
    return receipt
