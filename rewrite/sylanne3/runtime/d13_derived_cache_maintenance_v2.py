"""Explicitly installed D13 FIFO maintenance; no model, Source body or grant issuance."""
from dataclasses import asdict, dataclass, fields, replace
from datetime import datetime, timezone
import asyncio
import math
from ..authority_service.contract import AuthorityUnavailable
from ..domains.d13.maintenance_intent_v2 import (WORK_KIND,
    maintenance_intent_key_v2, victim_operation_v2)
from ..graph_types import AtomKey, GraphWrite
from ..runtime_contracts import NamespaceId, canonical_digest
from .budget import get_budget_lease, require_budget_family_admissible, reserve_budget, settle_budget
from .d11_types import job_graph_write
from .jobs import PersistentJob, create_job, get_job, acquire_job, checkpoint_job, transition_job

@dataclass(frozen=True, slots=True)
class AdminD13DerivedCacheMaintenancePolicyV2:
    policy_id: str
    version: int
    namespace: NamespaceId
    installation_id: str
    grant_id: str
    grant_version: int
    lease_id: str
    resource_ref: str
    deadline_after_seconds: int
    use_control_policy_ref: str
    consumer_cohort_digest: str
    policy_pair_digest: str
    coverage_ref: str
    coverage_digest: str
    capacity_eviction_enabled: bool = False
    cold_maintenance_enabled: bool = False
    scope: str = "namespace_derived_payload_only"
    fifo_order: str = "metadata_first_commit_epoch_v1"
    eligible_statuses: tuple = ("standby", "active")
    max_retained_payload_bytes: int = 8388608
    max_retained_blocks: int = 256
    max_victims_per_pass: int = 16
    compute_units_per_pass: int = 1
    originals_policy: str = "preserve_paid_and_history"
    unknown_use_policy: str = "hold"
    schema: str = "d13.derived_cache_maintenance_policy.v2"

    def __post_init__(self):
        if (type(self.version) is not int or self.version < 1 or type(self.namespace) is not NamespaceId or self.schema != "d13.derived_cache_maintenance_policy.v2"
                or self.scope != "namespace_derived_payload_only" or self.fifo_order != "metadata_first_commit_epoch_v1"
                or self.eligible_statuses != ("standby", "active")
                or self.max_retained_payload_bytes != 8388608 or self.max_retained_blocks != 256
                or self.compute_units_per_pass != 1 or type(self.max_victims_per_pass) is not int
                or not 1 <= self.max_victims_per_pass <= 16
                or type(self.deadline_after_seconds) is not int or not 1 <= self.deadline_after_seconds <= 72 * 3600
                or type(self.grant_version) is not int or self.grant_version < 1
                or type(self.capacity_eviction_enabled) is not bool or type(self.cold_maintenance_enabled) is not bool
                or self.originals_policy != "preserve_paid_and_history" or self.unknown_use_policy != "hold"):
            raise ValueError("invalid closed D13 maintenance policy")
        for value in (self.policy_id, self.installation_id, self.grant_id, self.lease_id,
                self.resource_ref, self.use_control_policy_ref, self.coverage_ref):
            if type(value) is not str or not value:
                raise ValueError("maintenance policy requires exact installed references")
        for value in (self.consumer_cohort_digest, self.policy_pair_digest, self.coverage_digest):
            if type(value) is not str or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
                raise ValueError("maintenance policy requires complete actual control commitments")

    @property
    def digest(self):
        return canonical_digest(asdict(self))

    @property
    def policy_ref(self):
        return "d13-derived-cache-policy-v2:sha256:" + self.digest

    @property
    def link_ref(self):
        return "d13-cache-maintenance-policy-v2:" + self.policy_id + ":" + str(self.version)

    @property
    def work_kind(self):
        return WORK_KIND

def maintenance_policy_from_payload_v2(payload, installation_policy, d13_interval):
    raw = payload.get("d13_derived_cache_maintenance_v2")
    if raw is None:
        return None
    if type(raw) is not dict or set(raw) != {f.name for f in fields(AdminD13DerivedCacheMaintenancePolicyV2)}:
        raise ValueError("D13 maintenance requires every exact V2 policy field")
    value = dict(raw)
    value["namespace"] = NamespaceId(**value["namespace"])
    if type(value["eligible_statuses"]) is not list:
        raise ValueError("maintenance statuses require their explicit closed list")
    value["eligible_statuses"] = tuple(value["eligible_statuses"])
    policy = AdminD13DerivedCacheMaintenancePolicyV2(**value)
    root = installation_policy.root_grant
    if (policy.namespace != installation_policy.namespace or policy.installation_id != installation_policy.installation_id
            or (policy.grant_id, policy.grant_version, policy.lease_id) != (root.grant_id, root.version, root.lease_id)
            or policy.deadline_after_seconds > d13_interval):
        raise ValueError("maintenance policy differs from its explicit installed Root or D13 interval")
    if policy.capacity_eviction_enabled or policy.cold_maintenance_enabled:
        if (WORK_KIND not in root.allowed_work_kinds or root.policy_ref != policy.policy_ref
                or root.max_ceiling.get("d13_compute_units", 0) < 1
                or installation_policy.root_lease.limits.get("d13_compute_units", 0) < 1):
            raise ValueError("maintenance needs a newly signed complete V2 Root commitment")
    return policy

def require_d13_maintenance_grant_v2(graph, policy, now):
    """Verify actual current signature and durable resource family; never issue."""
    if type(policy) is not AdminD13DerivedCacheMaintenancePolicyV2:
        raise AuthorityUnavailable("explicit installed maintenance policy is absent")
    db = graph._GraphCoordinator__store._db
    grant = graph._GraphCoordinator__d11_issuer.current_budget_grant(db, policy.lease_id)
    lease = get_budget_lease(db, policy.lease_id)
    require_budget_family_admissible(db, policy.lease_id)
    if ((grant.bot_id, grant.persona_id) != policy.namespace.as_tuple
            or (lease.bot_id, lease.persona_id) != policy.namespace.as_tuple
            or (grant.grant_id, grant.version, grant.lease_id) != (policy.grant_id, policy.grant_version, policy.lease_id)
            or grant.policy_ref != policy.policy_ref or WORK_KIND not in grant.allowed_work_kinds
            or grant.valid_until_utc <= now or lease.state != "active"
            or grant.max_ceiling.get("d13_compute_units", 0) < 1 or lease.limits.get("d13_compute_units", 0) < 1
            or grant.currency != lease.currency):
        raise AuthorityUnavailable("current signed maintenance Root/lease/complete policy is unavailable")
    return grant

def authorize_d13_maintenance_v2(graph, authority, lease):
    policy = graph._GraphCoordinator__d13_derived_cache_maintenance_v2
    port = graph._GraphCoordinator__content_fence_v2
    if (type(policy) is not AdminD13DerivedCacheMaintenancePolicyV2
            or not (policy.capacity_eviction_enabled or policy.cold_maintenance_enabled)
            or policy.namespace != authority.namespace or authority.issuer_domain != "d11"
            or authority.purpose != "context" or authority.worker_fence is not None
            or policy.installation_id != port.installation_grant.installation_id
            or graph._GraphCoordinator__d13_cache_use_coverage_v2 != (policy.coverage_ref, policy.coverage_digest)):
        raise AuthorityUnavailable("actual installed namespace maintenance/control policy is unavailable")
    graph._authorize(lease, authority, frozenset(("d11", "d13")))
    return policy

def _utc(value):
    return datetime.fromtimestamp(value, timezone.utc).isoformat().replace("+00:00", "Z")

def _continuation(intent, ordinal):
    return {"schema": "d13.maintenance-job.v2", "intent_ref": maintenance_intent_key_v2(intent).token,
        "intent_digest": intent.digest, "completed_victim_ordinal": ordinal}

def commit_d13_maintenance_step_v2(graph, authority, lease, proof):
    """Called only by this Work's terminal mapper after closing its READ."""
    from .d13_maintenance_read_v2 import bind_d13_maintenance_v2
    from .d13_derived_product_v6 import _commit_derived_graph
    from ..domains.d13.derived_block_metadata_v2 import derived_block_metadata_value_v2
    reader = proof.require_v2(graph, authority, lease)
    intent = reader.intent
    ordinal = reader.ordinal
    if intent is None:
        if not reader.selected:
            pressure = (reader.retained_bytes + reader.additional_bytes > reader.policy.max_retained_payload_bytes
                or reader.retained_count + reader.additional_count > reader.policy.max_retained_blocks)
            unknown = reader.skipped_unknown > 0
            return {"status": "held" if unknown or pressure else "idle",
                "reason": "derived_cache_use_coverage_unknown" if unknown else
                    "derived_cache_payloads_in_use" if pressure else "no_eligible_payload",
                "retained_bytes": reader.retained_bytes, "retained_count": reader.retained_count,
                "skipped_pinned": reader.skipped_pinned, "skipped_unknown": reader.skipped_unknown}
        intent = reader.new_intent_v2()
        operation_id, digest = intent.operation_id, intent.digest
    else:
        operation_id, digest = victim_operation_v2(intent, ordinal)
    proof.bind_write_identity_v2(operation_id, digest)
    def commit(db, metadata, epoch, now):
        policy = reader.policy
        if now >= intent.original_deadline_utc:
            raise AuthorityUnavailable("original maintenance deadline expired before WRITE")
        require_d13_maintenance_grant_v2(graph, policy, now)
        if reader.intent is None:
            key = maintenance_intent_key_v2(intent)
            if db.execute("SELECT revision FROM graph_atoms WHERE token=?", (key.token,)).fetchone() is not None:
                raise AuthorityUnavailable("maintenance pass cannot replace an existing immutable intent")
            reserve_budget(db, policy.lease_id, intent.operation_id, intent.digest, {"d13_compute_units": 1})
            job = PersistentJob(intent.operation_id, intent.operation_id, intent.operation_id, None,
                *intent.namespace.as_tuple, "d13-maintenance:" + intent.digest[:48], "queued", WORK_KIND,
                _continuation(intent, 0), None, _utc(intent.original_deadline_utc), policy.lease_id,
                policy.resource_ref, {"maintenance_policy": policy.digest}, None, None, 0, 0, {}, None)
            create_job(db, job, intent.operation_id, intent.digest)
            receipt, _ = _commit_derived_graph(graph, db, metadata, epoch, authority, operation_id, now,
                (GraphWrite(key, asdict(intent)), job_graph_write(job)))
            return {"schema": "d13.maintenance-pass-result.v2", "job_id": job.job_id,
                "intent_digest": intent.digest, "ordinal": 0, "status": "queued",
                "graph_receipt": asdict(receipt)}
        job = get_job(db, intent.operation_id)
        if (job.work_kind != WORK_KIND or dict(job.continuation) != _continuation(intent, ordinal)
                or job.budget_ref != policy.lease_id or job.cancel_epoch):
            raise AuthorityUnavailable("maintenance job lost its exact immutable intent/ordinal")
        remaining = int(math.floor(intent.original_deadline_utc - now))
        if remaining < 1:
            raise AuthorityUnavailable("maintenance original lifetime cannot acquire another worker")
        job = acquire_job(db, job.job_id, authority.actor, now_utc=_utc(now), lease_seconds=min(30, remaining))
        victim = intent.victims[ordinal]
        current = reader.victim_metadata
        if current is None or reader.current_victim != victim:
            raise AuthorityUnavailable("fresh complete census lost the original eligible FIFO victim")
        retired = replace(current, status="retired")
        job = checkpoint_job(db, job.job_id, authority.actor, job.fence,
            continuation=_continuation(intent, ordinal + 1), usage={"d13_compute_units": 1})
        last = ordinal + 1 == len(intent.victims)
        if last:
            settle_budget(db, policy.lease_id, intent.operation_id, intent.digest, {"d13_compute_units": 1})
            job = transition_job(db, job.job_id, authority.actor, job.fence, target_phase="completed",
                result_ref="d13-maintenance-result:" + intent.digest[:48])
        receipt, reclaims = _commit_derived_graph(graph, db, metadata, epoch, authority, operation_id, now,
            (GraphWrite(AtomKey.from_token(victim.metadata_ref), derived_block_metadata_value_v2(retired)),
                job_graph_write(job)), retired=(retired,))
        db.execute("UPDATE graph_d13_paid_scene_jobs_v1 SET state='retired' WHERE bot=? AND persona=? AND job_ref=? "
            "AND state IN ('standby','active')", (*intent.namespace.as_tuple, current.job_ref))
        return {"schema": "d13.maintenance-victim-result.v2", "job_id": job.job_id, "operation_id": operation_id,
            "intent_digest": intent.digest, "ordinal": ordinal + 1, "status": "completed" if last else "running",
            "metadata_ref": victim.metadata_ref, "metadata_revision": victim.metadata_revision + 1,
            "reason": victim.reason, "graph_receipt": asdict(receipt), "reclaim": asdict(reclaims[0]),
            "scope": "named_derived_store_logical_payload_only", "paid_source_history": "preserved"}
    with bind_d13_maintenance_v2(proof):
        return graph._d13_worker_write_v2(authority, operation_id, digest, commit, derived_maintenance=proof)

def prepare_d13_maintenance_graph_v2(graph, authority, lease, *, job_id=None, pending=None):
    from .d13_maintenance_read_v2 import prepare_d13_maintenance_read_v2
    authorize_d13_maintenance_v2(graph, authority, lease)
    return prepare_d13_maintenance_read_v2(graph, authority, lease, job_id=job_id, pending=pending)

async def run_installed_d13_maintenance_v2(runtime, *, pending=None):
    """Independent startup/tick entry. No ingress, provider, model or sender."""
    bundle = runtime._v2_model_bundle
    policy = None if bundle is None else bundle.d13_derived_cache_maintenance_v2
    if policy is None or (not policy.cold_maintenance_enabled if pending is None else not policy.capacity_eviction_enabled):
        return {"status": "disabled"}
    worker = runtime._worker
    job_id = None
    result = None
    # One new pass plus at most sixteen immutable victims, each with a new READ.
    for _ in range(policy.max_victims_per_pass + 1):
        def invoke(graph):
            if graph._GraphCoordinator__d13_derived_cache_maintenance_v2 is not policy:
                raise AuthorityUnavailable("runtime maintenance selected another installation policy")
            metadata, _ = graph._v2_graph_stamp(policy.namespace)
            generation = metadata.requirements.activation_generation
            token, cap = graph.grant(runtime._v2_bootstrap, actor=runtime._v2_installation_grant.subject,
                issuer_domain="d11", namespace=policy.namespace, domains=("d11", "d13"),
                activation_generation=generation, operation_id="d13-maintenance-runtime-v2")
            from ..runtime_contracts import AuthorityContext
            from contextlib import ExitStack
            lifetime = ExitStack()
            lifetime.callback(graph.release_authority_lease, runtime._v2_bootstrap, token)
            authority = AuthorityContext(runtime._v2_installation_grant.subject, "d11", cap, policy.namespace,
                ("persona",), "context", ("d13-maintenance:" + "/".join(policy.namespace.as_tuple),),
                policy.policy_ref, generation)
            try:
                work = prepare_d13_maintenance_graph_v2(graph, authority, token, job_id=job_id, pending=pending)
                return work.adopt_request_lifetime_v3(lifetime)
            except BaseException:
                lifetime.close()
                raise
        observed = await worker.call(invoke)
        with runtime._background_graph_result_v3(observed) as value:
            result = dict(value)
        if result["status"] in {"idle", "completed", "disabled", "held"}:
            runtime.resume_d13_cache_use_release_v3()
            return result
        job_id = result["job_id"]
        await asyncio.sleep(0)
    runtime.resume_d13_cache_use_release_v3()
    return result

# Pending size comes only from the actual complete paid Source Work. It is a
# capacity trigger, never an authority or a cached replacement model request.
from weakref import WeakKeyDictionary
_PENDING = WeakKeyDictionary()

class _PendingD13PayloadV2:
    def __init__(self, graph, reader, saved, stage):
        self.graph = graph
        self.namespace = reader.namespace
        self.selection_digest = reader.selection_digest
        self.job_id = saved.job.job_id
        self.worker_fence = saved.call_original.worker_fence
        self.original_digest = saved.original.original_digest
        self.deadline_utc = min(reader.deadline, reader.original_deadline or reader.deadline,
            datetime.fromisoformat(saved.job.deadline_utc.replace("Z", "+00:00")).timestamp(),
            datetime.fromisoformat(saved.job.lease_expires_utc.replace("Z", "+00:00")).timestamp())
        self.additional_bytes = len(stage.payload_bytes)
        self.block_ref = stage.metadata.block_ref
        self.payload_digest = stage.metadata.payload_digest
        self.source_heads = tuple((token, *head) for token, head in sorted(reader.source_heads.items()))
        self.authority_epochs = tuple(reader.epochs)
        _PENDING[self] = (graph, self.namespace, self.selection_digest, self.job_id,
            self.worker_fence, self.original_digest, self.deadline_utc, self.additional_bytes,
            self.block_ref, self.payload_digest, self.source_heads, self.authority_epochs)

def issue_current_d13_pending_maintenance_v2(graph, proof):
    from .d13_paid_original_read_v3 import PreparedD13PaidOriginalReadV3
    from .d13_paid_product_v1 import _read_original_locked
    from .d13_paid_coordinator_v1 import prepare_paid_d13_standby_in_transaction_v1
    from .d11_derived_cache_payload_v1 import prepare_derived_payload_v1
    if type(proof) is not PreparedD13PaidOriginalReadV3:
        raise AuthorityUnavailable("capacity pressure needs its actual complete paid Source Work")
    r = proof.require_current_v3()
    if r.graph is not graph or r.method != "complete_d13_paid_precompression_v1" or r.current_window is None:
        raise AuthorityUnavailable("capacity trigger is not the actual first derived completion")
    policy = graph._GraphCoordinator__d13_derived_cache_maintenance_v2
    assembly = graph._GraphCoordinator__d04_installed_joint_assembly
    if policy is None or not policy.capacity_eviction_enabled:
        return None
    bundle = assembly.admin_bundle
    from ..model_broker.natural_reply_history_v6 import TEMPLATE_VERSION as V6_TEMPLATE
    from ..model_broker.natural_reply_history_v7 import TEMPLATE_VERSION as V7_TEMPLATE
    workflow = bundle.model_workflows.natural_generation
    if workflow is None or workflow.template_version not in {V6_TEMPLATE, V7_TEMPLATE}:
        return None
    selected_main = r.args.get("selected_main")
    if selected_main != graph._GraphCoordinator__d13_paid_precompression_policy.selected_main:
        return None
    saved = _read_original_locked(graph, r.namespace, r.job_id)
    if saved is None or saved.job.phase != "running" or saved.settlement is None or saved.evidence is None:
        return None
    db = r.db
    if db.in_transaction:
        raise AuthorityUnavailable("capacity trigger must precede the fresh completion WRITE")
    db.execute("BEGIN")
    try:
        prepared = prepare_paid_d13_standby_in_transaction_v1(db, saved.original, saved.call_original,
            saved.frozen, r.current_window, selected_main,
            resource_issuer=graph._GraphCoordinator__d02_issuer, budget_issuer=graph._GraphCoordinator__d11_issuer,
            holder=r.authority.actor, fence=saved.call_original.worker_fence, now_utc=r.now_utc)
        if prepared.block is None:
            return None
        stage = prepare_derived_payload_v1(prepared, scene_ref=r.current_window.scene_ref)
        from .d11_derived_cache_payload_v1 import derived_payload_capacity_available_v1
        if derived_payload_capacity_available_v1(db, r.namespace, len(stage.payload_bytes)):
            return None
        return _PendingD13PayloadV2(graph, r, saved, stage)
    finally:
        db.rollback()

def require_pending_d13_payload_v2(pending, graph, selection_digest, now):
    if (type(pending) is not _PendingD13PayloadV2 or _PENDING.get(pending) !=
            (graph, pending.namespace, pending.selection_digest, pending.job_id,
                pending.worker_fence, pending.original_digest, pending.deadline_utc,
                pending.additional_bytes, pending.block_ref, pending.payload_digest, pending.source_heads, pending.authority_epochs)
            or pending.selection_digest != selection_digest or now >= pending.deadline_utc):
        raise AuthorityUnavailable("pending cache pressure lost its actual first-completion original")
    job = get_job(graph._GraphCoordinator__store._db, pending.job_id)
    if (job.phase != "running" or job.fence != pending.worker_fence or job.cancel_epoch
            or job.lease_expires_utc is None or now >= datetime.fromisoformat(
                job.lease_expires_utc.replace("Z", "+00:00")).timestamp()):
        raise AuthorityUnavailable("pending cache original worker/result is no longer live")
    return pending

def require_d13_pending_trigger_metadata_v2(graph, trigger, *, meter):
    """Only metadata, independently current inside this maintenance Work/WRITE."""
    db = graph._GraphCoordinator__store._db
    if isinstance(trigger, _PendingD13PayloadV2):
        namespace, points, epochs, job_id, original = (trigger.namespace, trigger.source_heads,
            trigger.authority_epochs, trigger.job_id, trigger.original_digest)
    else:
        namespace, points, epochs, job_id, original = (trigger.namespace, trigger.trigger_source_heads,
            trigger.trigger_authority_epochs, trigger.trigger_original_ref, trigger.trigger_original_digest)
    actual = meter.read_fixed_row(db, "graph_authority_epochs", ("access_epoch", "delete_epoch"),
        "bot=? AND persona=?", namespace.as_tuple)
    if actual != epochs:
        raise AuthorityUnavailable("pending payload lost its actual original Source/Access epochs")
    for token, revision, valid, cell_id in points:
        row = meter.read_fixed_row(db, "graph_atoms", ("revision", "valid", "value_cell_id"),
            "token=? AND bot=? AND persona=?", (token, *namespace.as_tuple))
        if row != (revision, valid, cell_id):
            raise AuthorityUnavailable("pending payload Source/Access changed before cache maintenance")
    row = meter.read_fixed_row(db, "graph_d13_paid_intent_originals_v1", ("original_digest",),
        "bot=? AND persona=? AND job_ref=?", (*namespace.as_tuple, job_id))
    if row != (original,):
        raise AuthorityUnavailable("pending payload changed its paid original identity")
