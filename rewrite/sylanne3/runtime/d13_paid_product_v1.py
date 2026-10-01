"""Installed D13 product orchestration behind thin Graph/Runtime methods.

The Graph adapters below reuse W01's existing retained write-fence protocol.
Only the Runtime adapter invokes the installed host executor, outside Graph
transactions; its recovery branch never repeats model prepare or dispatch.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, replace
from datetime import datetime, timezone
import json
import time

from ..authority_service.v2_model_egress_contract import ModelEgressDraftV1, ModelEgressIntentV1
from ..contracts import Event, Scope
from ..graph_types import AtomKey, GraphCandidate, GraphVersion, Owner
from ..model_broker.d13_precompression import (
    FrozenD13PrecompressionRequestV1, freeze_d13_precompression_request_v1,
    issue_unadmitted_d13_model_request_v1, thaw_d13_precompression_request_v1,
    D13ExactTokenCountV1,
)
from ..runtime_contracts import (
    AuthorityContext, CommandEnvelope, OperationIdentity, QueryEpoch, RUNTIME_SCHEMA,
    SourceQualification, VersionGuard, VersionedRef, canonical_digest,
)
from .c02_cost_settlement import C02OriginalIntentLookupV1
from .d11_types import job_graph_write
from .d13_current_window import read_current_d13_frozen_window_for_authority_v1
from .d13_paid_coordinator_v1 import (
    D13PaidRecoveryV1, acquire_paid_d13_in_transaction_v1,
    D13PaidStandbyPreparationV1,
    finalize_paid_d13_in_transaction_v1, paid_d13_scene_ledger_in_transaction_v1,
    prepare_paid_d13_standby_in_transaction_v1,
    record_paid_d13_result_read_in_transaction_v1, recover_paid_d13_in_transaction_v1,
    schedule_paid_d13_in_transaction_v1, settle_paid_d13_in_transaction_v1,
)
from .d13_paid_intent_original_v1 import (
    D13PaidIntentOriginalV1, D13PaidCallOriginalV1,
    record_d13_paid_call_original_v1,
)
from .d13_precompression_job import D13PaidPrecompressionIntentV1, prepare_paid_precompression_intent_v1
from .d13_technical_policy import AdminD13PaidPrecompressionPolicyV1
from .jobs import PersistentJob, get_job
from .model_cost_settlement import read_original_model_cost


@dataclass(frozen=True, slots=True)
class D13PaidPreparedCallV1:
    original: D13PaidIntentOriginalV1
    call_original: D13PaidCallOriginalV1
    frozen: FrozenD13PrecompressionRequestV1
    envelope: CommandEnvelope
    draft: ModelEgressDraftV1
    expected_anchor: object
    recovery_only: bool


def _parts(graph):
    return (graph._GraphCoordinator__store, graph._GraphCoordinator__content_fence_v2,
            graph._GraphCoordinator__d13_paid_precompression_policy,
            graph._GraphCoordinator__d02_issuer, graph._GraphCoordinator__d11_issuer)


def _authorize(graph, authority, lease):
    from ..graph_coordinator import UnavailableGuard
    store, port, policy, resource, budget = _parts(graph)
    if (type(policy) is not AdminD13PaidPrecompressionPolicyV1 or port is None or
            authority.namespace != policy.namespace or authority.issuer_domain != "d11" or
            authority.purpose != "context" or authority.worker_fence is not None or
            len(authority.audience) != 1 or
            policy.installation_id != port.installation_grant.installation_id):
        raise UnavailableGuard("installed D13 paid authorities differ")
    graph._authorize(lease, authority, frozenset({"d11", "d13"}))
    return store, port, policy, resource, budget


def _commit_graph(graph, db, metadata, epoch, authority, operation_id, now, writes, reads=()):
    from ..graph_store import GraphStore
    store = graph._GraphCoordinator__store
    versions = list(reads)
    for write in writes:
        row = db.execute("SELECT revision FROM graph_atoms WHERE token=?", (write.key.token,)).fetchone()
        version = GraphVersion(write.key, 0 if row is None else row[0])
        if all(prior.key != write.key for prior in versions):
            versions.append(version)
    event = Event(Scope(*authority.namespace.as_tuple, "d13-paid"), operation_id, now,
                  "d13.paid_lifecycle", {"operation_id": operation_id})
    candidate = GraphCandidate(event, tuple(versions), tuple(writes), (epoch,))

    def sealed(_db, receipt):
        if receipt.status != "committed":
            raise ValueError("D13 paid graph transition did not commit")
        store.cas_graph_recovery_metadata(
            metadata, metadata.requirements,
            _capability=graph._GraphCoordinator__graph_capability)

    return GraphStore._graph_commit_in_transaction(
        store, candidate, _receipt_hook=sealed,
        _capability=graph._GraphCoordinator__graph_capability)


def _read_original_locked(graph, namespace, job_id):
    store = graph._GraphCoordinator__store
    with store._lock:
        db = store._db
        db.execute("BEGIN")
        try:
            result = recover_paid_d13_in_transaction_v1(db, namespace, job_id)
            db.execute("COMMIT")
            return result
        except BaseException:
            db.execute("ROLLBACK")
            raise


def _restore_schedule_intent(raw, digest):
    from .d13_paid_intent_original_v1 import D13PaidOriginalBindingV1
    from ..runtime_contracts import canonical_serialize
    payload = json.loads(raw)
    frozen = thaw_d13_precompression_request_v1(canonical_serialize(payload["frozen"]))
    intent = D13PaidPrecompressionIntentV1(
        frozen.plan, frozen, D13PaidOriginalBindingV1(**payload["binding"]),
        None if payload["exact_count"] is None else D13ExactTokenCountV1(**payload["exact_count"]),
        PersistentJob(**payload["job"]), payload["ceiling"], payload["intent_digest"])
    if canonical_serialize(asdict(intent)) != raw or canonical_digest(asdict(intent)) != digest:
        raise ValueError("D13 original schedule input changed")
    return intent


def schedule_d13_paid_precompression_graph_v1(graph, authority, lease, *, scene_ref):
    """Schedule a paid original or return a namespace-local original to recover."""
    store, _port, policy, resource, budget = _authorize(graph, authority, lease)
    # A prior queued/running original takes precedence over planning a new wire.
    with store._lock:
        rows = store._db.execute(
            "SELECT job_ref FROM graph_d13_paid_scene_jobs_v1 WHERE bot=? AND persona=? "
            "AND state IN ('queued','running')", authority.namespace.as_tuple).fetchall()
        for row in rows:
            saved = _read_original_locked(graph, authority.namespace, row[0])
            if AtomKey.from_token(saved.frozen.window.scene_ref.ref).owner.subject == scene_ref:
                if saved.frozen.window.conversation_ref != authority.audience[0]:
                    raise ValueError("D13 original conversation differs")
                return saved
        pending_input = store._db.execute(
            "SELECT payload_json,payload_digest FROM graph_d13_paid_schedule_inputs_v1 "
            "WHERE bot=? AND persona=? AND scene_ref=? AND pending=1",
            authority.namespace.as_tuple + (scene_ref,)).fetchone()
    intent = None if pending_input is None else _restore_schedule_intent(*pending_input)
    if intent is not None:
        window = intent.frozen.window
        if (window.namespace != authority.namespace or window.conversation_ref != authority.audience[0]
                or intent.frozen.installation != policy.selected_main):
            raise ValueError("D13 pending paid schedule installation changed")
    else:
        window = graph.read_current_d13_conversation_window_v1(
            authority, lease, scene_ref=scene_ref, max_slots=policy.max_slots)
        if not window.turns or window.missing_ranges:
            return None
    with store._lock:
        db = store._db
        db.execute("BEGIN")
        try:
            pending, attempted = paid_d13_scene_ledger_in_transaction_v1(
                db, authority.namespace, window.scene_ref.ref, now_utc=window.trusted_utc)
            jobs = db.execute("SELECT job_id FROM runtime_jobs WHERE bot_id=? AND persona_id=? "
                              "AND work_kind='d13.precompress'", authority.namespace.as_tuple).fetchall()
            shared_jobs = tuple(get_job(db, row[0]) for row in jobs)
            shared_jobs = tuple(job for job in shared_jobs if
                                job.continuation.get("conversation_ref") == window.conversation_ref)
            shared_pending = any(job.phase in {"queued", "running", "waiting", "deferred"}
                                 for job in shared_jobs)
            shared_attempted = frozenset(job.continuation["input_digest"] for job in shared_jobs)
            standby = db.execute("SELECT 1 FROM graph_atoms WHERE bot=? AND persona=? "
                                 "AND type_name='d13.compressed_turn_block.v2' AND valid=1 "
                                 "AND json_extract(value,'$.conversation_ref')=? "
                                 "AND json_extract(value,'$.status')='standby' "
                                 "AND json_extract(value,'$.expires_at_utc')>? LIMIT 1",
                                 authority.namespace.as_tuple + (window.conversation_ref,
                                                                 window.trusted_utc)).fetchone()
            shared_pending = shared_pending or standby is not None
            db.execute("COMMIT")
        except BaseException:
            db.execute("ROLLBACK")
            raise
    deadline = min(window.trusted_utc + policy.deadline_after_seconds,
                   min(turn.trusted_utc for turn in window.turns) + 72 * 3600)
    if intent is None:
        intent = prepare_paid_precompression_intent_v1(
            window, policy.selected_main, history_token_budget=policy.history_token_budget,
            background_capacity=True, outstanding_candidate=pending or shared_pending,
            attempted_input_digests=attempted | shared_attempted,
            parent_budget_lease_ref=policy.lease_id, resource_ref=policy.resource_ref,
            ceiling=dict(policy.quote_ceiling), deadline_utc=deadline)
    if intent is None:
        return None
    operation_id = intent.plan.job_ref
    digest = canonical_digest({"phase": "paid_schedule", "intent": intent.intent_digest})
    if pending_input is None:
        from ..runtime_contracts import canonical_serialize
        with store._lock:
            db = store._db
            db.execute("BEGIN IMMEDIATE")
            try:
                db.execute("INSERT INTO graph_d13_paid_schedule_inputs_v1 "
                           "(bot,persona,job_ref,scene_ref,payload_json,payload_digest) VALUES(?,?,?,?,?,?)",
                           authority.namespace.as_tuple + (operation_id, scene_ref,
                               canonical_serialize(asdict(intent)), canonical_digest(asdict(intent))))
                db.execute("COMMIT")
            except BaseException:
                db.execute("ROLLBACK")
                raise

    def commit(db, metadata, epoch, now):
        if now >= datetime.fromisoformat(intent.job.deadline_utc.replace("Z", "+00:00")).timestamp():
            raise ValueError("D13 paid original schedule deadline elapsed")
        current = read_current_d13_frozen_window_for_authority_v1(db, window, now,
                                                                max_slots=policy.max_slots)
        refreshed = freeze_d13_precompression_request_v1(current, intent.plan, policy.selected_main)
        if refreshed.turns != intent.frozen.turns:
            raise ValueError("D13 paid schedule source changed")
        grant = budget.current_budget_grant(db, policy.lease_id)
        if (grant.grant_id, grant.version) != (policy.grant_id, policy.grant_version):
            raise ValueError("D13 paid installed grant changed")
        receipt = schedule_paid_d13_in_transaction_v1(
            db, intent, window, resource_issuer=resource, budget_issuer=budget,
            valid_until_utc=min(grant.valid_until_utc, intent.plan.expires_at_utc))
        db.execute("UPDATE graph_d13_paid_schedule_inputs_v1 SET pending=0 "
                   "WHERE bot=? AND persona=? AND job_ref=? AND pending=1",
                   authority.namespace.as_tuple + (operation_id,))
        _commit_graph(
            graph, db, metadata, epoch, authority, operation_id, now,
            (job_graph_write(receipt.job),),
            tuple(GraphVersion(AtomKey.from_token(ref.ref), ref.version) for ref in current.read_set))
        seq_row = db.execute("SELECT last_seq FROM graph_bundle_sequence WHERE bot=? AND persona=?",
                             authority.namespace.as_tuple).fetchone()
        seq = (seq_row[0] if seq_row else 0) + 1
        db.execute("INSERT INTO graph_bundle_sequence(bot,persona,last_seq) VALUES(?,?,?) "
                   "ON CONFLICT(bot,persona) DO UPDATE SET last_seq=excluded.last_seq",
                   authority.namespace.as_tuple + (seq,))
        db.execute("INSERT INTO graph_bundle_operations "
                   "(bot,persona,operation_id,digest,activity_id,effect_id,commit_seq,receipt_json) "
                   "VALUES(?,?,?,?,?,NULL,?,?)", authority.namespace.as_tuple + (
                       operation_id, digest, receipt.job.activity_id, seq,
                       json.dumps({"schema": "d13.paid_schedule.v1",
                                   "original_digest": receipt.original.original_digest}, sort_keys=True)))
        return {"job_id": receipt.job.job_id}

    result = graph._d13_worker_write_v2(authority, operation_id, digest, commit)
    return _read_original_locked(graph, authority.namespace, result["job_id"])


def prepare_d13_paid_call_graph_v1(graph, authority, lease, *, job_id, timeout_seconds, privacy_tier,
                                  lease_seconds=300):
    store, port, policy, resource, budget = _authorize(graph, authority, lease)
    saved = _read_original_locked(graph, authority.namespace, job_id)
    if saved is None or saved.frozen.window.conversation_ref != authority.audience[0]:
        raise ValueError("D13 paid original conversation is absent")
    if saved.call_original is not None:
        return saved
    operation_id = "d13-paid-acquire:" + canonical_digest({"job": job_id, "holder": authority.actor})[:48]
    digest = canonical_digest({"job": job_id, "original": saved.original.original_digest,
                               "timeout_seconds": timeout_seconds, "privacy_tier": privacy_tier})

    def commit(db, metadata, epoch, now):
        current = read_current_d13_frozen_window_for_authority_v1(db, saved.frozen.window, now,
                                                                max_slots=policy.max_slots)
        frozen = saved.frozen
        if freeze_d13_precompression_request_v1(current, frozen.plan, policy.selected_main).turns != frozen.turns:
            raise ValueError("D13 paid acquire source changed")
        running = acquire_paid_d13_in_transaction_v1(
            db, authority.namespace, job_id, authority.actor,
            now_utc=datetime.fromtimestamp(now, timezone.utc).isoformat().replace("+00:00", "Z"),
            lease_seconds=lease_seconds)
        guards = dict(db.execute("SELECT kind,version FROM graph_guard_versions "
                                 "WHERE bot=? AND persona=? AND ref='current'",
                                 authority.namespace.as_tuple).fetchall())
        inputs = tuple(ref.ref for ref in frozen.plan.source_dependencies)
        deadline = datetime.fromisoformat(running.deadline_utc.replace("Z", "+00:00")).timestamp()
        model_authority = replace(authority, issuer_domain="d13", worker_fence=running.fence)
        envelope = CommandEnvelope(
            RUNTIME_SCHEMA, OperationIdentity(running.activity_id, None, "d13-paid-model",
                "d13.precompress", running.operation_id, canonical_digest({"input_refs": list(inputs)})),
            model_authority, VersionGuard(
                tuple(GraphVersion(AtomKey.from_token(ref.ref), ref.version) for ref in current.read_set),
                (QueryEpoch(authority.namespace, "all", epoch.revision),), current.access_epoch,
                current.delete_epoch, store._registry.catalogue_hash,
                guards["scheme"], guards["operator"], guards["policy"], (), (),
                (VersionedRef(saved.original.quote_id, saved.original.quote_version),)),
            SourceQualification(tuple(turn.source_ref.ref for turn in frozen.turns),
                "derived", None, now, "inference", "ineligible", None, "actual"),
            inputs, running.budget_ref, deadline, time.monotonic() + deadline - now,
            "d13-short-context-v1", (running.operation_id,))
        request = issue_unadmitted_d13_model_request_v1(
            envelope, frozen, call_id=saved.original.binding.call_id,
            timeout_seconds=timeout_seconds, privacy_tier=privacy_tier)
        call = record_d13_paid_call_original_v1(
            db, saved.original, frozen, current, request,
            resource_issuer=resource, budget_issuer=budget)
        _commit_graph(graph, db, metadata, epoch, authority, operation_id, now,
                      (job_graph_write(running),))
        return {"job_id": job_id, "call_original_digest": call.original_digest}

    graph._d13_worker_write_v2(authority, operation_id, digest, commit)
    acquired = _read_original_locked(graph, authority.namespace, job_id)
    with store._lock:
        db = store._db
        db.execute("BEGIN")
        try:
            from .d13_paid_intent_original_v1 import read_d13_paid_call_original_v1
            call, request = read_d13_paid_call_original_v1(db, authority.namespace, job_id)
            metadata, epoch = graph._v2_graph_stamp(authority.namespace)
            db.execute("COMMIT")
        except BaseException:
            db.execute("ROLLBACK")
            raise
    requirements = metadata.requirements
    original, frozen, running = acquired.original, acquired.frozen, acquired.job
    from ..authority_service.d13_source_identity_v1 import d13_original_source_identity_v1
    sources, source_versions, access_versions = d13_original_source_identity_v1(frozen)
    draft = ModelEgressDraftV1(
        requirements.authority_id, requirements.authority_namespace, running.lease_holder,
        running.operation_id, original.binding.call_id, request.digest, job_id, running.fence,
        sources, source_versions, access_versions, original.access_epoch, original.delete_epoch,
        epoch.revision, metadata.graph_revision, requirements.activation_generation,
        requirements.revocation_epoch, requirements.deletion_seq, requirements.execution_seq,
        running.budget_ref, original.budget_operation_id, original.budget_reservation_digest,
        tuple(sorted(original.ceiling.items())), frozen.installation.provider_id,
        frozen.installation.model_id, frozen.installation.provider_config_digest,
        frozen.installation.max_output_tokens, running.operation_id, original.binding.binding_digest)
    anchor = port.current_anchor(namespace=authority.namespace,
                                 authority_namespace=requirements.authority_namespace)
    if not graph._anchor_matches(requirements, anchor):
        raise ValueError("D13 paid model original anchor changed")
    return D13PaidPreparedCallV1(original, call, frozen, request.envelope, draft, anchor, False)


def record_d13_paid_read_graph_v1(graph, authority, lease, *, job_id, intent, read):
    store, _port, _policy, _resource, _budget = _authorize(graph, authority, lease)
    saved = _read_original_locked(graph, authority.namespace, job_id)
    if saved is None or saved.call_original is None:
        raise ValueError("D13 paid call original missing")
    # Independent credential-owning terminal query before the Graph write fence.
    fact = read_original_model_cost(graph._GraphCoordinator__model_terminal_cost_port, intent)
    operation_id = "d13-paid-read:" + saved.original.binding.binding_digest[:48]
    digest = canonical_digest({"read": read.request.digest, "observation": read.observation.digest})

    def commit(db, metadata, epoch, now):
        evidence = record_paid_d13_result_read_in_transaction_v1(
            db, saved.original, saved.call_original, fact, read,
            holder=authority.actor, fence=saved.call_original.worker_fence, now_utc=now)
        _commit_graph(graph, db, metadata, epoch, authority, operation_id, now,
                      (job_graph_write(get_job(db, job_id)),))
        return {"job_id": job_id, "evidence_digest": evidence.evidence_digest}

    graph._d13_worker_write_v2(authority, operation_id, digest, commit)
    return _read_original_locked(graph, authority.namespace, job_id)


def settle_d13_paid_graph_v1(graph, authority, lease, *, job_id):
    _store, _port, _policy, resource, _budget = _authorize(graph, authority, lease)
    saved = _read_original_locked(graph, authority.namespace, job_id)
    if saved is None or saved.evidence is None:
        raise ValueError("D13 settlement requires original saved read")
    operation_id = "d13-paid-settle:" + saved.original.binding.binding_digest[:48]
    digest = canonical_digest({"evidence": saved.evidence.evidence_digest})

    def commit(db, metadata, epoch, now):
        settlement = settle_paid_d13_in_transaction_v1(
            db, saved.original, saved.call_original, resource_issuer=resource)
        cost_operation_id = settlement.cost_write.value["bundle_operation_id"]
        _commit_graph(graph, db, metadata, epoch, authority, cost_operation_id, now,
                      (settlement.cost_write,))
        seq_row = db.execute("SELECT last_seq FROM graph_bundle_sequence WHERE bot=? AND persona=?",
                             authority.namespace.as_tuple).fetchone()
        seq = (seq_row[0] if seq_row else 0) + 1
        db.execute("INSERT INTO graph_bundle_sequence(bot,persona,last_seq) VALUES(?,?,?) "
                   "ON CONFLICT(bot,persona) DO UPDATE SET last_seq=excluded.last_seq",
                   authority.namespace.as_tuple + (seq,))
        db.execute("INSERT INTO graph_bundle_operations "
                   "(bot,persona,operation_id,digest,activity_id,effect_id,commit_seq,receipt_json) "
                   "VALUES(?,?,?,?,?,NULL,?,?)", authority.namespace.as_tuple + (
                       cost_operation_id, digest, saved.job.activity_id, seq,
                       json.dumps({"schema": "d13.paid_cost.v1",
                                   "evidence_digest": saved.evidence.evidence_digest,
                                   "budget_receipt_digest": canonical_digest(settlement.receipt),
                                   "ledger_refs": [settlement.cost_write.key.token]}, sort_keys=True)))
        return {"job_id": job_id, "receipt": asdict(settlement.receipt)}

    graph._d13_worker_write_v2(authority, operation_id, digest, commit)
    return _read_original_locked(graph, authority.namespace, job_id)


def complete_d13_paid_graph_v1(graph, authority, lease, *, job_id, selected_main):
    _store, _port, policy, resource, budget = _authorize(graph, authority, lease)
    saved = _read_original_locked(graph, authority.namespace, job_id)
    if saved is None or saved.settlement is None:
        raise ValueError("D13 completion requires settled original evidence")
    operation_id = "d13-paid-complete:" + saved.original.binding.binding_digest[:48]
    digest = canonical_digest({"evidence": saved.evidence.evidence_digest,
                               "receipt": saved.settlement.receipt,
                               "selected_main": selected_main})

    def commit(db, metadata, epoch, now):
        from ..graph_coordinator import UnavailableGuard
        current = None
        try:
            current = read_current_d13_frozen_window_for_authority_v1(
                db, saved.frozen.window, now, max_slots=policy.max_slots)
            prepared = prepare_paid_d13_standby_in_transaction_v1(
                db, saved.original, saved.call_original, saved.frozen, current, selected_main,
                resource_issuer=resource, budget_issuer=budget, holder=authority.actor,
                fence=saved.call_original.worker_fence, now_utc=now)
        except (ValueError, UnavailableGuard):
            job = get_job(db, job_id)
            if (job.phase != "running" or job.lease_holder != authority.actor or
                    job.fence != saved.call_original.worker_fence or job.cancel_epoch != 0):
                raise ValueError("D13 paid original worker cannot close stale result")
            prepared = D13PaidStandbyPreparationV1(
                saved.original, saved.evidence.evidence_digest, saved.settlement,
                None, "paid_current_source_model_or_lifetime_invalid", job)
        completed, writes = finalize_paid_d13_in_transaction_v1(
            db, prepared, holder=authority.actor, fence=saved.call_original.worker_fence)
        _commit_graph(graph, db, metadata, epoch, authority, operation_id, now, writes,
                      tuple(GraphVersion(AtomKey.from_token(ref.ref), ref.version)
                            for ref in current.read_set) if prepared.block is not None else ())
        return {"job_id": job_id, "reason": prepared.reason, "job": asdict(completed)}

    result = graph._d13_worker_write_v2(authority, operation_id, digest, commit)
    return result


def recover_d13_paid_graph_v1(graph, authority, lease, *, job_id):
    _authorize(graph, authority, lease)
    saved = _read_original_locked(graph, authority.namespace, job_id)
    if saved is not None and saved.frozen.window.conversation_ref != authority.audience[0]:
        raise ValueError("D13 recovery conversation differs")
    return saved


async def run_installed_d13_paid_runtime_v1(runtime, envelope, ingress_operation_id, *, executor):
    """Run one installed original through durable paid standby or exact recovery."""
    from .first_ingress_v2 import scene_ref_for_conversation
    from ..host.model_egress_executor import HostModelEgressExecutor, d13_paid_worker_read_request_v1
    from ..runtime.first_ingress_v2 import ingress_ids
    from ..host.ingress import HostIngressEnvelope
    bundle, policy, grant = runtime._v2_model_bundle, runtime._v2_policy, runtime._v2_installation_grant
    worker, bootstrap, port = runtime._worker, runtime._v2_bootstrap, runtime._v2_port
    if (type(executor) is not HostModelEgressExecutor or type(envelope) is not HostIngressEnvelope or
            bundle is None or type(bundle.d13_paid_precompression) is not AdminD13PaidPrecompressionPolicyV1 or
            policy is None or grant is None or worker is None or bootstrap is None or port is None or
            not runtime._v2_namespace_provisioned or envelope.namespace != policy.namespace or
            ingress_ids(envelope.lineage.source_ref)[2] != ingress_operation_id):
        return None

    async def graph_call(method, **kwargs):
        def invoke(graph):
            anchor = port.current_anchor(namespace=policy.namespace,
                                          authority_namespace=policy.authority_namespace)
            lease, capability = graph.grant(
                bootstrap, actor=grant.subject, issuer_domain="d11", namespace=policy.namespace,
                domains=("d11", "d13"), activation_generation=anchor.activation_generation,
                operation_id=ingress_operation_id)
            try:
                authority = AuthorityContext(grant.subject, "d11", capability, policy.namespace,
                    ("scene",), "context", (envelope.conversation_ref,),
                    policy.root_grant.policy_ref, anchor.activation_generation)
                return getattr(graph, method)(authority, lease, **kwargs)
            finally:
                graph.release_authority_lease(bootstrap, lease)
        return await worker.call(invoke)

    scene = scene_ref_for_conversation(policy.namespace, envelope.platform_ref, envelope.conversation_ref)
    saved = await graph_call("schedule_d13_paid_precompression_v1", scene_ref=scene)
    if saved is None or saved.next_action == "terminal":
        return saved
    job_id = saved.job.job_id
    prepared = None
    if saved.call_original is None:
        model = bundle.model_workflows.reply
        prepared = await graph_call("prepare_d13_paid_call_v1", job_id=job_id,
                                    timeout_seconds=model.timeout_seconds, privacy_tier=model.privacy_tier,
                                    lease_seconds=max(30, min(3600, int(model.timeout_seconds) + 120)))
        if type(prepared) is D13PaidPreparedCallV1:
            sent = await executor.execute_frozen_d13_once(
                original=prepared.original, call_original=prepared.call_original,
                frozen=prepared.frozen, envelope=prepared.envelope,
                draft=prepared.draft, expected_anchor=prepared.expected_anchor)
            if sent is None:
                return await graph_call("recover_d13_paid_precompression_v1", job_id=job_id)
            intent, terminal = sent.intent, sent.terminal
            saved = await graph_call("recover_d13_paid_precompression_v1", job_id=job_id)
        else:
            saved = prepared
    if saved.evidence is None:
        if prepared is None or type(prepared) is not D13PaidPreparedCallV1:
            # Original lookup reads Authority only. It never calls execute_once.
            lookup = C02OriginalIntentLookupV1(
                saved.original.namespace, grant.authority_id, policy.authority_namespace,
                saved.original.binding.installation_id, job_id,
                saved.original.budget_operation_id, saved.original.binding.original_operation_id,
                saved.original.binding.call_id, saved.original.binding.binding_digest,
                saved.call_original.request_digest, "d13-adopt:" + saved.original.binding.binding_digest)
            try:
                intent = await executor._authority.model_original_intent_lookup_v1(
                    executor._bundle, executor._grant, lookup=lookup)
                terminal = await executor.recover_original_terminal(intent)
            except Exception:
                return saved
        if terminal is None:
            return saved
        first = d13_paid_worker_read_request_v1(saved.original, saved.call_original, intent)
        request = await executor.select_original_worker_read_attempt(first)
        if request is None:
            return saved
        read = await executor.read_original_for_worker(read_request=request, intent=intent, terminal=terminal)
        if read is None:
            return saved
        saved = await graph_call("record_d13_paid_result_read_v1", job_id=job_id, intent=intent, read=read)
    if saved.settlement is None:
        saved = await graph_call("settle_d13_paid_precompression_v1", job_id=job_id)
    try:
        selected_main = await executor._adapter.selected_d13_main_installation_v1()
    except Exception:
        selected_main = None
    return await graph_call("complete_d13_paid_precompression_v1", job_id=job_id,
                            selected_main=selected_main)


__all__ = [name for name in globals() if name.endswith("_graph_v1") or
           name in {"D13PaidPreparedCallV1", "run_installed_d13_paid_runtime_v1"}]
