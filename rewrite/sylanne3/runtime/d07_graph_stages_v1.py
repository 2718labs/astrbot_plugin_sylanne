"""Fixed installed D07 W01 stages; provider and Authority waits stay on host.

Each write rechecks a current signed Owner and paired write fence, then performs
only bounded SQLite/Graph work. The installed service pre-reads paid facts over
mTLS before these methods are invoked. No public request supplies a callback.
"""
from __future__ import annotations

from contextlib import nullcontext
from dataclasses import asdict, replace
from datetime import datetime, timezone
import json
import time

from ..contracts import Event, Scope, StaleRead
from ..graph_store import GraphStore
from ..graph_types import AtomKey, GraphAtom, GraphCandidate, GraphSnapshot, GraphVersion, NamespaceEpoch, owner_grant_key
from ..runtime_contracts import (AuthorityContext, CommandEnvelope, FenceScope, OperationIdentity, QueryEpoch,
    RUNTIME_SCHEMA, SourceQualification, VersionGuard, VersionedRef, canonical_digest, canonical_serialize)
from ..authority_service.v2_contract import to_wire as fence_wire, from_wire as fence_from_wire
from ..authority_service.v2_model_egress_contract import ModelEgressDraftV1, ModelEgressIntentV1
from ..authority_service.v2_model_egress_wire import from_wire as model_from_wire
from ..model_broker.broker import ModelCallRequest
from ..model_broker.d07_cognition_v1 import TEMPLATE_DIGEST, WORK_KIND, thaw_d07_cognition_request_v1
from .d07_execution_v1 import (read_prepared_d07_execution_v1, read_d07_accounting_prepared_v1,
    read_d07_original_v1, record_d07_original_in_transaction_v1, require_current_d07_content_reads_v1,
    read_original_d07_request_v1, seal_d07_request_in_transaction_v1, seal_d07_call_in_transaction_v1,
    settle_d07_original_model_cost_in_transaction_v1, settle_d07_paid_result_in_transaction_v1,
    stage_d07_body_cost_in_transaction_v1, record_d07_body_cost_after_cas_v1,
    stage_d07_execution_original_in_transaction_v1, stage_actual_d07_interpretation_writes_v1,
    record_d07_adopted_interpretations_after_cas_v1)
from .d07_current_behavior_v1 import _json
from .d11_types import job_graph_write, reconcile_runtime_write
from .first_ingress_v2 import trusted_upper
from .jobs import get_job, acquire_job
from .restore_anchor import RestoreAnchor

TABLE = "graph_d07_stage_attempts_v1"


def install_d07_graph_stage_schema_v1(db):
    db.execute(f"""CREATE TABLE IF NOT EXISTS {TABLE} (
        bot TEXT NOT NULL, persona TEXT NOT NULL, stage_operation_id TEXT NOT NULL,
        job_id TEXT NOT NULL, phase TEXT NOT NULL, request_digest TEXT NOT NULL,
        attempt_id TEXT NOT NULL, anchor_json TEXT NOT NULL,
        graph_revision INTEGER NOT NULL, graph_epoch INTEGER NOT NULL,
        permit_json TEXT, receipt_json TEXT, PRIMARY KEY(bot,persona,stage_operation_id))""")


def _service(graph, bootstrap, bundle):
    from .d07_installed_execution_v1 import InstalledD07ExecutionServiceV1
    graph._admin(bootstrap)
    service = getattr(graph, "_GraphCoordinator__d07_execution_service_v1", None)
    if type(service) is not InstalledD07ExecutionServiceV1 or service.graph is not graph or service.bundle is not bundle:
        raise ValueError("D07 stage requires its actual installed W01 service/bundle")
    return service


def _prepared(graph, service, job_id, *, accounting=False):
    ns = service.bundle.installation_policy.namespace
    original = (read_d07_accounting_prepared_v1 if accounting else read_prepared_d07_execution_v1)(
        service._db, service.d11_issuer, ns, job_id)
    if original is None:
        raise ValueError("D07 stage has no actual prepared original")
    return original


def _require_owner(db, prepared, guard):
    # Every current execution/content adoption requires the exact actual Owner
    # grant that authorized preparation. Historical cost does not unseal data.
    expected = json.loads(prepared.owner_guard_json)
    row = db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=?", (expected["grant_ref"],)).fetchone()
    if (row is None or row[2] != 1 or row[0] != expected["grant_revision"]
            or canonical_digest(json.loads(row[1])) != expected["grant_digest"]
            or guard.authorization_head.removeprefix("sha256:") != expected["owner_head_digest"]):
        raise ValueError("D07 actual current Owner grant or revocation head changed")


def _commit_graph_stage(graph, db, metadata, epoch, prepared, operation_id, phase, now, writes, reads, *, extra=None):
    writes, reads = tuple(writes), tuple(reads)
    if not writes:
        return None
    for write in writes:
        if write.key.type_name.startswith("runtime."):
            reconcile_runtime_write(db, write)
    candidate = GraphCandidate(Event(Scope(*prepared.namespace.as_tuple, prepared.activity_id), operation_id,
        now, "d07." + phase + ".v1", {"prepared_digest": prepared.digest, "writes_digest": canonical_digest(writes)}),
        reads, writes, (epoch,))
    receipt = GraphStore._graph_commit_in_transaction(graph._GraphCoordinator__store, candidate,
        _capability=graph._GraphCoordinator__graph_capability)
    if receipt.status != "committed":
        raise ValueError("D07 actual fixed Graph stage CAS did not commit")
    store = graph._GraphCoordinator__store
    store.cas_graph_recovery_metadata(metadata, metadata.requirements, _capability=graph._GraphCoordinator__graph_capability)
    seq = db.execute("SELECT last_seq FROM graph_bundle_sequence WHERE bot=? AND persona=?", prepared.namespace.as_tuple).fetchone()
    sequence = (seq[0] if seq else 0) + 1
    db.execute("INSERT INTO graph_bundle_sequence(bot,persona,last_seq) VALUES(?,?,?) ON CONFLICT(bot,persona) DO UPDATE SET last_seq=excluded.last_seq",
        (*prepared.namespace.as_tuple, sequence))
    payload = {"schema": "d07.actual-graph-stage.v1", "status": "committed", "commit_seq": sequence,
        "phase": phase, "prepared_digest": prepared.digest, "graph_receipt_digest": canonical_digest(receipt),
        **(extra or {})}
    db.execute("INSERT INTO graph_bundle_operations VALUES(?,?,?,?,?,?,?,?)", (*prepared.namespace.as_tuple,
        operation_id, canonical_digest(candidate), prepared.activity_id,
        prepared.effect_id if phase == "behavior_adopted" else None, sequence, canonical_serialize(payload)))
    return receipt


def _write_stage(graph, bootstrap, bundle, *, job_id, phase, commit, accounting=False):
    """Durable, recoverable background stage with the actual current Owner."""
    service = _service(graph, bootstrap, bundle)
    store, port, policy = service._store, graph._GraphCoordinator__content_fence_v2, bundle.installation_policy
    ns = policy.namespace
    with store._lock:
        original = _prepared(graph, service, job_id, accounting=accounting)
        metadata, epoch = graph._v2_graph_stamp(ns)
    operation_id = "d07-stage:" + canonical_digest((ns, original.operation_id, job_id, phase))[:48]
    digest = canonical_digest(("d07.installed-stage.v1", phase, job_id, original.digest))
    attempt = "d07-fence:" + canonical_digest((operation_id, digest))[:48]
    anchor = port.current_anchor(namespace=ns, authority_namespace=policy.authority_namespace)
    if not graph._anchor_matches(metadata.requirements, anchor):
        raise StaleRead("D07 actual Graph/Authority anchor differs")
    with store._lock:
        saved = store._db.execute(f"SELECT job_id,phase,request_digest,attempt_id,anchor_json,graph_revision,graph_epoch,permit_json,receipt_json FROM {TABLE} "
            "WHERE bot=? AND persona=? AND stage_operation_id=?", (*ns.as_tuple, operation_id)).fetchone()
        if phase in {"acquire", "adopt"} and (saved is None or saved[8] is None):
            graph.local_module_admission.require_v1(("d07", "d11"), "d07-stage:" + phase)
        if saved is None:
            store._db.execute("BEGIN IMMEDIATE")
            try:
                if graph._v2_graph_stamp(ns) != (metadata, epoch):
                    raise StaleRead("D07 current Graph changed before fixed stage intent")
                store._db.execute(f"INSERT INTO {TABLE} VALUES(?,?,?,?,?,?,?,?,?,?,NULL,NULL)",
                    (*ns.as_tuple, operation_id, job_id, phase, digest, attempt,
                     canonical_serialize(asdict(anchor)), metadata.graph_revision, epoch.revision))
                store._db.commit()
            except BaseException:
                store._db.rollback()
                raise
        elif saved[:4] != (job_id, phase, digest, attempt):
            raise ValueError("D07 installed stage identity conflict")
    if saved is not None and saved[7] is not None:
        permit = fence_from_wire(json.loads(saved[7]))
        actual, state = port.get_fence_operation(namespace=ns, authority_namespace=policy.authority_namespace, operation_id=attempt)
        if actual != permit or state not in {"active", "finished"}:
            raise ValueError("D07 original installed stage fence unavailable")
    else:
        if saved is not None and (RestoreAnchor(**json.loads(saved[4])) != anchor or saved[5:7] != (metadata.graph_revision, epoch.revision)):
            raise StaleRead("D07 unresolved original stage cannot replace its pinned snapshot")
        permit = port.begin_fence(namespace=ns, authority_namespace=policy.authority_namespace,
            holder=policy.administrator_holder, generation=anchor.activation_generation,
            operation="write", operation_id=attempt, expected_anchor=anchor, retain_on_unknown=True)
        state = "active"
    old_revision, old_epoch = saved[5:7] if saved else (metadata.graph_revision, epoch.revision)
    scope = FenceScope(ns, policy.authority_namespace, anchor.activation_generation, "write", attempt,
        permit, permit.pinned_anchor, NamespaceEpoch(*ns.as_tuple, old_epoch), old_revision)
    finish = "sha256:" + canonical_digest(("d07.installed-stage-finish.v1", operation_id, digest, permit.token))
    if saved is not None and saved[8] is not None:
        if state == "active":
            port.finish_fence(scope, request_id="finish:" + attempt, request_digest=finish)
        return json.loads(saved[8])
    if state != "active" or port.validate_fence(scope) != permit:
        raise ValueError("D07 current stage write fence unavailable")
    from ..authority_service.d12_target_owner_admission_v1 import D12CurrentOwnerAuthorityV1
    guarded, owner_permit = port.get_current_background_owner_authority_for_fence_v1(namespace=ns,
        authority_namespace=policy.authority_namespace, permit=permit)
    if type(guarded) is not D12CurrentOwnerAuthorityV1 or owner_permit != permit:
        raise ValueError("D07 actual signed current background Owner unavailable")
    now = trusted_upper(port.read_ingress_clock(bundle.ingress_clock))
    reader = getattr(graph, "_GraphCoordinator__d04_semantic_mapping_reader", None)
    try:
        with (reader.current_fence(scope) if reader is not None and not accounting else nullcontext()):
            with store._lock:
                db = store._db
                db.execute(f"UPDATE {TABLE} SET permit_json=? WHERE bot=? AND persona=? AND stage_operation_id=? AND permit_json IS NULL",
                    (canonical_serialize(fence_wire(permit)), *ns.as_tuple, operation_id))
                db.execute("BEGIN IMMEDIATE")
                try:
                    if graph._v2_graph_stamp(ns) != (metadata, epoch):
                        raise StaleRead("D07 current Graph changed before fixed stage adoption")
                    graph._scene_binding_state_locked(ns, guarded.guard)
                    if not accounting:
                        _require_owner(db, original, guarded.guard)
                    result = commit(db, metadata, epoch, now, original, guarded.guard, scope)
                    db.execute(f"UPDATE {TABLE} SET receipt_json=? WHERE bot=? AND persona=? AND stage_operation_id=? AND receipt_json IS NULL",
                        (canonical_serialize(_json(result)), *ns.as_tuple, operation_id))
                    if db.execute("SELECT changes()").fetchone() != (1,):
                        raise ValueError("D07 installed stage result CAS changed")
                    db.commit()
                except BaseException:
                    db.rollback()
                    raise
    except (ValueError, TypeError, StaleRead) as exc:
        # A fixed SQL-only stage has definitely rolled back. Closing this
        # exact untouched write permit is safe only while its old stamp and
        # durable intent still match. Transport/SQLite uncertainties are not
        # caught here and remain inspection-only.
        with store._lock:
            db = store._db
            if db.in_transaction or graph._v2_graph_stamp(ns) != (metadata, epoch):
                raise
            found = db.execute(f"SELECT receipt_json FROM {TABLE} WHERE bot=? AND persona=? AND stage_operation_id=?",
                (*ns.as_tuple, operation_id)).fetchone()
            if found != (None,):
                raise
            refusal = {"status": "held", "job_id": job_id, "phase": phase,
                "reason": type(exc).__name__, "attempt_id": attempt,
                "prepared_digest": original.digest, "permit_digest": canonical_digest(fence_wire(permit)),
                "graph_revision": metadata.graph_revision, "graph_epoch": epoch.revision}
            db.execute("BEGIN IMMEDIATE")
            try:
                db.execute(f"UPDATE {TABLE} SET receipt_json=? WHERE bot=? AND persona=? AND stage_operation_id=? AND receipt_json IS NULL",
                    (canonical_serialize(refusal), *ns.as_tuple, operation_id))
                if db.execute("SELECT changes()").fetchone() != (1,):
                    raise ValueError("D07 fixed local refusal receipt raced")
                db.commit()
            except BaseException:
                db.rollback()
                raise
        port.finish_fence(scope, request_id="finish:" + attempt, request_digest=finish)
        raise
    port.finish_fence(scope, request_id="finish:" + attempt, request_digest=finish)
    return _json(result)


def _content_versions(db, issuer, prepared):
    committed = read_d07_original_v1(db, issuer, prepared.namespace, "prepare_commit", prepared.job_id)
    if committed is None:
        raise ValueError("D07 actual prepare commit original absent")
    return tuple(GraphVersion(AtomKey.from_token(r["ref"]), r["revision"]) for r in committed[0]["post_read_rows"])


def acquire_current_d07_execution_v1(graph, bootstrap, bundle, *, job_id):
    service = _service(graph, bootstrap, bundle)
    def commit(db, metadata, epoch, now, prepared, guard, scope):
        job = get_job(db, job_id)
        if job.phase == "completed":
            return {"status": "completed", "job_id": job_id, "terminal_ref": job.result_ref}
        if job.phase == "running":
            # Existing worker/start identity is inspected, never replaced.
            return {"status": "acquired", "job_id": job_id}
        if job.phase != "queued" or job.fence != 0 or job.cancel_epoch:
            return {"status": "original_execution_hold", "job_id": job_id}
        require_current_d07_content_reads_v1(db, prepared, issuer=service.d11_issuer)
        workflow = service._configured(prepared)
        holder = graph._GraphCoordinator__content_fence_v2.installation_grant.subject
        old_atom = db.execute("SELECT revision FROM graph_atoms WHERE token=?", (job_graph_write(job).key.token,)).fetchone()
        if old_atom is None:
            raise ValueError("D07 original queued job has no Graph projection")
        acquired = acquire_job(db, job_id, holder, now_utc=datetime.fromtimestamp(now, timezone.utc).isoformat().replace("+00:00", "Z"),
            lease_seconds=min(3600, int(workflow.timeout_seconds) + 120))
        frozen = thaw_d07_cognition_request_v1(json.loads(prepared.frozen_json))
        refs = tuple(s.source_ref.ref for s in frozen.input.sources)
        deadline = min(datetime.fromisoformat(acquired.deadline_utc.replace("Z", "+00:00")).timestamp(),
            datetime.fromisoformat(acquired.lease_expires_utc.replace("Z", "+00:00")).timestamp())
        content_reads = _content_versions(db, service.d11_issuer, prepared)
        member_writes = (job_graph_write(acquired),)
        extra = None
        from .d07_execution_v1 import D07RelationshipPreparedV2
        from .d07_method_growth_semantic_v2 import D07MethodGrowthPreparedV2
        if type(prepared) in {D07RelationshipPreparedV2, D07MethodGrowthPreparedV2}:
            from .foreground_call_plan_v1 import register_current_named_c3_in_transaction_v2
            cycle_write, cycle_revision = register_current_named_c3_in_transaction_v2(db,
                prepared=prepared, issuer=service.d11_issuer, now_utc=now,
                installed_bundle=bundle, owner_guard=guard)
            member_writes += (cycle_write,)
            binding_kind = "relationship_c3" if type(prepared) is D07RelationshipPreparedV2 else "method_growth_c3"
            extra = {binding_kind: {"cycle_ref": prepared.cycle_ref.key.token,
                "before_cycle_digest": prepared.cycle_digest, "before_call_plan_digest": prepared.call_plan_digest,
                "call_id": prepared.call_id, "semantic_question_digest": prepared.semantic_question_digest}}
        reads = content_reads
        if len(member_writes) == 2:
            reads = tuple(v for v in reads if v.key != cycle_write.key) + (GraphVersion(cycle_write.key, cycle_revision + 1),)
        versions = dict(db.execute("SELECT kind,version FROM graph_guard_versions WHERE bot=? AND persona=? AND ref='current' "
            "AND kind IN ('scheme','operator','policy')", prepared.namespace.as_tuple).fetchall())
        authority = AuthorityContext(holder, "d11", "d07-original:" + prepared.digest, prepared.namespace,
            ("activity", "event", "persona", "scene"), "proposal", prepared.audience,
            workflow.provider_config_ref, prepared.activation_generation, worker_fence=acquired.fence)
        acquire_id = "d07-acquire:" + canonical_digest((prepared.namespace, prepared.operation_id))[:48]
        envelope = CommandEnvelope(RUNTIME_SCHEMA,
            OperationIdentity(prepared.activity_id, prepared.effect_id, acquire_id, WORK_KIND, acquire_id,
                canonical_digest({"input_refs": list(refs)})), authority,
            VersionGuard((*reads, GraphVersion(job_graph_write(acquired).key, old_atom[0] + 1)),
                (QueryEpoch(prepared.namespace, "namespace", epoch.revision + 1),), prepared.access_epoch, prepared.delete_epoch,
                graph._GraphCoordinator__store._registry.catalogue_hash, versions["scheme"], versions["operator"], versions["policy"],
                (), (), (VersionedRef(prepared.quote_id, prepared.quote_version),)),
            SourceQualification(refs, "derived", None, now, "inference", "ineligible", None, "not_applicable"),
            refs, acquired.budget_ref, deadline, time.monotonic() + deadline - now,
            "d07-cognition:" + prepared.operation_id, (prepared.operation_id, prepared.prepare_operation_id))
        call = ModelCallRequest(envelope, prepared.call_id, workflow.provider_id, workflow.model_id,
            frozenset(workflow.required_capabilities), workflow.privacy_tier, TEMPLATE_DIGEST,
            json.loads(frozen.canonical_wire), workflow.timeout_seconds, workflow.max_output_tokens)
        seal_d07_request_in_transaction_v1(db, service.d11_issuer, prepared, call)
        member_reads = (*content_reads, GraphVersion(job_graph_write(acquired).key, old_atom[0]))
        _commit_graph_stage(graph, db, metadata, epoch, prepared, acquire_id, "execution_acquired", now,
            member_writes, member_reads, extra=extra)
        return {"status": "acquired", "job_id": job_id}
    return _write_stage(graph, bootstrap, bundle, job_id=job_id, phase="acquire", commit=commit)


def read_acquired_current_d07_execution_v1(graph, bootstrap, bundle, *, job_id):
    service = _service(graph, bootstrap, bundle)
    ns, policy = bundle.installation_policy.namespace, bundle.installation_policy
    port = graph._GraphCoordinator__content_fence_v2
    now = trusted_upper(port.read_ingress_clock(bundle.ingress_clock))
    with service._store._lock:
        prepared = _prepared(graph, service, job_id)
        job = get_job(service._db, job_id)
        if job.phase == "completed":
            return {"status": "completed", "job_id": job_id, "terminal_ref": job.result_ref}
        metadata, _ = graph._v2_graph_stamp(ns)
    authority = AuthorityContext(port.installation_grant.subject, "d11", "d07-original-read:" + job_id,
        ns, ("activity", "event", "persona", "scene"), "proposal", prepared.audience,
        service._configured(prepared).provider_config_ref, metadata.requirements.activation_generation)
    owner = []
    def observe(scope):
        pair = port.get_current_owner_guard_for_fence(namespace=ns, authority_namespace=policy.authority_namespace, permit=scope.permit)
        if pair[1] != scope.permit:
            raise ValueError("D07 current read Owner permit differs")
        owner[:] = [pair[0]]
        return pair
    def read():
        db = service._db
        db.execute("BEGIN")
        try:
            current, epoch = graph._v2_graph_stamp(ns)
            _require_owner(db, prepared, owner[0])
            require_current_d07_content_reads_v1(db, prepared, issuer=service.d11_issuer)
            job = get_job(db, job_id)
            call = read_original_d07_request_v1(db, service.d11_issuer, prepared)
            if (job.phase != "running" or job.cancel_epoch or job.fence != call.envelope.authority.worker_fence
                    or job.lease_holder != call.envelope.authority.actor):
                raise ValueError("D07 original acquired worker identity changed")
            from .d07_execution_v1 import D07IngressRecallPreparedV1
            if type(prepared) is D07IngressRecallPreparedV1:
                from ..model_broker.d07_cognition_v1 import thaw_d07_ingress_recall_request_v1
                from .d07_ingress_recall_acquisition_v1 import ingress_recall_acquire_operation_id_v1, ACQUIRE_OPERATION
                from .domain_production_originals_v1 import read_adopted_domain_operation_v1
                from ..authority_service.d07_current_execution_v1 import _require_current_ingress_recall_parent_v1
                acquired = read_adopted_domain_operation_v1(db, ns,
                    ingress_recall_acquire_operation_id_v1(ns, prepared.c02_operation_id))
                if (acquired is None or acquired["operation_kind"] != ACQUIRE_OPERATION
                        or acquired["payload"]["provenance"]["prepared_digest"] != prepared.digest
                        or acquired["payload"]["provenance"]["request_digest"] != call.digest):
                    raise ValueError("Self C3 read lacks its actual adopted acquisition")
                frozen = thaw_d07_ingress_recall_request_v1(json.loads(prepared.frozen_json))
                _require_current_ingress_recall_parent_v1(db, prepared=prepared, frozen=frozen, request=call,
                    issuer=service.d11_issuer, installed_bundle=bundle, now=now)
                input_sources = (frozen.input.cue, *frozen.input.known_sources)
            else:
                frozen = thaw_d07_cognition_request_v1(json.loads(prepared.frozen_json))
                input_sources = frozen.input.sources
            sources = tuple((s.record.source_id, s.source_ref.version) for s in input_sources)
            access = []
            from ..memory_types import access_key
            for source in input_sources:
                row = db.execute("SELECT revision,valid FROM graph_atoms WHERE token=?",
                    (access_key(*ns.as_tuple, source.record.source_id).token,)).fetchone()
                if row is None or row[1] != 1:
                    raise ValueError("D07 model source current access absent")
                access.append((source.record.source_id, row[0]))
            quote = service.resource_issuer.original_signed_quote(db, prepared.quote_id, prepared.quote_version)
            target = current.requirements
            draft = ModelEgressDraftV1(target.authority_id, target.authority_namespace, call.envelope.authority.actor,
                call.identity.operation_id, call.call_id, call.digest, job_id, job.fence,
                tuple(ref for ref, _ in sources), sources, tuple(access), prepared.access_epoch, prepared.delete_epoch,
                epoch.revision, current.graph_revision, target.activation_generation, target.revocation_epoch,
                target.deletion_seq, target.execution_seq, job.budget_ref, prepared.operation_id, prepared.reservation_digest,
                tuple(sorted(quote.ceiling.items())), call.provider_id, call.model_id,
                frozen.installation.provider_config_digest, call.max_output_tokens,
                acquire_operation_id=call.identity.operation_id, binding_digest=prepared.digest)
            sealed = read_d07_original_v1(db, service.d11_issuer, ns, "call", job_id)
            intent = None if sealed is None else model_from_wire(sealed[0], ModelEgressIntentV1)
            # Exact private-session routing is taken from the original admitted
            # audience, never guessed from a screen or a recipient's name.
            audience = json.loads(prepared.audience[0])
            if type(audience) is not list or len(audience) != 2 or any(type(v) is not str or not v for v in audience):
                raise ValueError("D07 selected AstrBot session identity is not installed")
            return prepared, job, call, draft, intent, audience[0]
        finally:
            db.rollback()
    value, anchor, _metadata, _epoch = graph._read_v2(authority, read, fence_observer=observe, return_recovery_context=True)
    return (*value[:4], anchor, value[4], value[5])


def seal_current_d07_egress_v1(graph, bootstrap, bundle, *, job_id, intent, permit):
    service = _service(graph, bootstrap, bundle)
    ns, port = bundle.installation_policy.namespace, graph._GraphCoordinator__content_fence_v2
    actual, state = port.get_fence_operation(namespace=ns, authority_namespace=intent.namespace, operation_id=intent.operation_id)
    anchor = port.current_anchor(namespace=ns, authority_namespace=intent.namespace)
    if (actual != permit or state != "active" or permit.operation != "model_egress" or anchor != permit.pinned_anchor
            or permit.subject != intent.subject or permit.token != intent.fence_token
            or permit.revision != intent.fence_revision or permit.fence_epoch != intent.fence_epoch):
        raise ValueError("D07 actual model preparation fence differs")
    with service._store._lock:
        db = service._db
        db.execute("BEGIN IMMEDIATE")
        try:
            metadata, epoch = graph._v2_graph_stamp(ns)
            if (metadata.graph_revision, epoch.revision) != (intent.graph_revision, intent.graph_epoch):
                raise StaleRead("D07 Graph changed before sealing original egress")
            original = _prepared(graph, service, job_id)
            require_current_d07_content_reads_v1(db, original, issuer=service.d11_issuer)
            seal_d07_call_in_transaction_v1(db, service.d11_issuer, original, intent)
            db.commit()
        except BaseException:
            db.rollback()
            raise
    return {"status": "sealed", "job_id": job_id}


def reconcile_current_d07_cost_v1(graph, bootstrap, bundle, *, job_id):
    from .d07_accounting_v1 import reconcile_current_d07_cost_under_accounting_v1
    return reconcile_current_d07_cost_under_accounting_v1(graph, bootstrap, bundle, job_id=job_id)


def read_resume_current_d07_metadata_v1(graph, bootstrap, bundle, *, job_id):
    """Designated installed worker's content-free original lookup, not a send grant."""
    service = _service(graph, bootstrap, bundle)
    with service._store._lock:
        prepared = _prepared(graph, service, job_id, accounting=True)
        job = get_job(service._db, job_id)
        row = read_d07_original_v1(service._db, service.d11_issuer, prepared.namespace, "call", job_id)
        intent = None if row is None else model_from_wire(row[0], ModelEgressIntentV1)
        return job, prepared, intent


def prepare_current_d07_result_read_v1(graph, bootstrap, bundle, *, job_id):
    service = _service(graph, bootstrap, bundle)
    from ..authority_service.d07_current_execution_v1 import D07CognitionResultReadRequestV1, from_wire
    def commit(db, metadata, epoch, now, prepared, guard, scope):
        require_current_d07_content_reads_v1(db, prepared, issuer=service.d11_issuer)
        row = read_d07_original_v1(db, service.d11_issuer, prepared.namespace, "call", job_id)
        if row is None:
            raise ValueError("D07 exact original call missing before scoped result read")
        intent = model_from_wire(row[0], ModelEgressIntentV1)
        attempt = "d07-result-read:" + canonical_digest((prepared.namespace, prepared.job_id, prepared.digest, intent.request_digest))[:48]
        request = D07CognitionResultReadRequestV1(intent.authority_id, intent.namespace, prepared.namespace,
            bundle.installation_policy.installation_id, job_id, intent.acquire_operation_id, prepared.operation_id,
            prepared.call_id, prepared.digest, intent.request_digest, prepared.operation_id, attempt)
        record_d07_original_in_transaction_v1(db, service.d11_issuer, prepared.namespace, "result_attempt", job_id, asdict(request))
        return asdict(request)
    raw = _write_stage(graph, bootstrap, bundle, job_id=job_id, phase="result_read", commit=commit)
    return from_wire(json.loads(canonical_serialize(raw)), D07CognitionResultReadRequestV1)


def finish_current_d07_execution_v1(graph, bootstrap, bundle, *, job_id):
    service = _service(graph, bootstrap, bundle)
    fact, result_read = service.pre_read_cost_fact_v1(job_id), service.pre_read_result_v1(job_id)
    def commit(db, metadata, epoch, now, prepared, guard, scope):
        require_current_d07_content_reads_v1(db, prepared, issuer=service.d11_issuer)
        paid, cost_writes = settle_d07_paid_result_in_transaction_v1(db, prepared=prepared, result_read=result_read, fact=fact,
            issuer=service.d11_issuer, resource_issuer=service.resource_issuer,
            holder=get_job(db, job_id).lease_holder, fence=get_job(db, job_id).fence)
        if cost_writes:
            raise ValueError("D07 independent actual cost must commit before content completion")
        writes, reads, body_original = stage_d07_body_cost_in_transaction_v1(db, prepared=prepared,
            issuer=service.d11_issuer, resource_issuer=service.resource_issuer, body_authority=service.body_authority)
        if writes:
            operation = "d07-body-cost:" + canonical_digest((prepared.namespace, prepared.call_id))[:48]
            receipt = _commit_graph_stage(graph, db, metadata, epoch, prepared, operation, "actual_body_cost", now, writes, reads)
            record_d07_body_cost_after_cas_v1(db, prepared=prepared, issuer=service.d11_issuer, writes=writes, original=body_original)
            metadata, epoch = graph._v2_graph_stamp(prepared.namespace)
        job = get_job(db, job_id)
        execution, job_writes = stage_d07_execution_original_in_transaction_v1(db, prepared=prepared,
            issuer=service.d11_issuer, holder=job.lease_holder, fence=job.fence)
        if job_writes:
            row = db.execute("SELECT revision FROM graph_atoms WHERE token=?", (job_writes[0].key.token,)).fetchone()
            operation = "d07-complete:" + canonical_digest((prepared.namespace, prepared.call_id))[:48]
            _commit_graph_stage(graph, db, metadata, epoch, prepared, operation, "execution_completed", now,
                job_writes, (GraphVersion(job_writes[0].key, row[0]),))
        return {"status": "actual_execution_completed", "job_id": job_id, "terminal_ref": execution.terminal_ref}
    return _write_stage(graph, bootstrap, bundle, job_id=job_id, phase="complete", commit=commit)


def resume_current_d07_behavior_v1(graph, bootstrap, bundle, *, job_id):
    """Adopt the exact completed D07 result, fair round and model interpretations."""
    service = _service(graph, bootstrap, bundle)
    def commit(db, metadata, epoch, now, prepared, guard, scope):
        from ..authority_service.v2_owner_contract import OwnerPrincipalV1
        from ..domains.d07 import D07DomainProvider, SimulationRequest
        from .d07_current_behavior_v1 import ServeCurrentConcernRequestV1, AdvanceCurrentReflectionRequestV1, RunCurrentSimulationRequestV1
        from .domain_production_read_plans_v1 import read_current_domain_original_refs_v1
        from .domain_production_frame_v1 import freeze_domain_production_frame_v1
        from .domain_production_contracts_v1 import ProductionReadPlanV1
        from .d07_production_operations_v1 import read_plan_current_d07_operation_v1, InstalledD07ProductionReadersV1
        from .d07_behavior_stage_codec_v1 import build_d07_staged_behavior_operation_v1
        from .domain_production_originals_v1 import record_adopted_domain_operation_v1
        from ..runtime_contracts import CommitReceipt
        job = get_job(db, job_id)
        if job.phase != "completed" or not job.result_ref:
            return {"status": "waiting_for_actual_terminal", "job_id": job_id}
        existing = db.execute("SELECT receipt_json FROM graph_bundle_operations WHERE bot=? AND persona=? AND operation_id=?",
            (*prepared.namespace.as_tuple, prepared.operation_id)).fetchone()
        if existing is not None:
            return {"status": "adopted", "job_id": job_id, "operation_id": prepared.operation_id,
                "terminal_ref": job.result_ref, "receipt": json.loads(existing[0])}
        require_current_d07_content_reads_v1(db, prepared, issuer=service.d11_issuer)
        execution = service.read_verified_terminal(job.result_ref)
        raw = dict(job.continuation["request"])
        kind = {"concern": "serve_concern", "reflection": "advance_reflection", "simulation": "run_simulation"}[prepared.work_kind]
        if prepared.work_kind == "concern":
            request = ServeCurrentConcernRequestV1(**raw)
        elif prepared.work_kind == "simulation":
            request = RunCurrentSimulationRequestV1(**raw)
        else:
            request = AdvanceCurrentReflectionRequestV1(job.continuation["reflection_ref"], execution.terminal_ref)
        original_authority = json.loads(prepared.owner_authority_json)
        outer_grant = json.loads(db.execute("SELECT value FROM graph_atoms WHERE token=?",
            (owner_grant_key(*prepared.namespace.as_tuple).token,)).fetchone()[0])
        outer_purpose = "workbench_user_action" if "workbench_user_action" in outer_grant["purposes"] else sorted(outer_grant["purposes"])[0]
        outer_audience = "owner" if "owner" in outer_grant["audiences"] else sorted(outer_grant["audiences"])[0]
        outer_authority = AuthorityContext(original_authority["actor"], "d07", "d07-background:" + prepared.digest,
            prepared.namespace, tuple(original_authority["owner_scope"]), outer_purpose, (outer_audience,),
            original_authority["provider_policy_ref"], metadata.requirements.activation_generation)
        owner = graph._owner_graph_binding_locked(outer_authority, OwnerPrincipalV1(**outer_grant["principal"]), current_guard=guard)
        token, capability = graph.grant(bootstrap, actor=original_authority["actor"], issuer_domain="d07",
            namespace=prepared.namespace, domains=("d07", "d11"),
            activation_generation=metadata.requirements.activation_generation, operation_id=prepared.operation_id)
        try:
            reads = _content_versions(db, service.d11_issuer, prepared)
            versions = dict(db.execute("SELECT kind,version FROM graph_guard_versions WHERE bot=? AND persona=? AND ref='current' "
                "AND kind IN ('scheme','operator','policy')", prepared.namespace.as_tuple).fetchall())
            deadline = datetime.fromisoformat(job.deadline_utc.replace("Z", "+00:00")).timestamp()
            authority = AuthorityContext(original_authority["actor"], "d07", capability, prepared.namespace,
                tuple(original_authority["owner_scope"]), prepared.purpose, prepared.audience,
                original_authority["provider_policy_ref"], prepared.activation_generation)
            envelope = CommandEnvelope(RUNTIME_SCHEMA,
                OperationIdentity(prepared.activity_id, prepared.effect_id, prepared.attempt_id, kind, prepared.operation_id,
                    canonical_digest({"input_refs": list(execution.source_refs)})), authority,
                VersionGuard(reads, (QueryEpoch(prepared.namespace, "namespace", epoch.revision),), prepared.access_epoch,
                    prepared.delete_epoch, graph._GraphCoordinator__store._registry.catalogue_hash,
                    versions["scheme"], versions["operator"], versions["policy"], (), (),
                    (VersionedRef(prepared.quote_id, prepared.quote_version),)),
                SourceQualification(execution.source_refs, "derived", None, now, "inference", "ineligible", None, "not_applicable"),
                execution.source_refs, job.budget_ref, deadline, time.monotonic() + deadline - now,
                "d07-current-adoption:" + prepared.operation_id, (prepared.prepare_operation_id,))
            interpretation_writes, interpretation_reads = stage_actual_d07_interpretation_writes_v1(db,
                prepared=prepared, issuer=service.d11_issuer, envelope=envelope)
            from .d07_reflection_execution_v1 import stage_reflection_from_actual_cognition_v1, record_actual_reflection_after_cas_v1
            reflection_request, reflection_writes = stage_reflection_from_actual_cognition_v1(db,
                prepared=prepared, issuer=service.d11_issuer)
            plan = read_plan_current_d07_operation_v1(db, namespace=prepared.namespace,
                activity_id=prepared.activity_id, operation_kind=kind, request=request)
            exact = [*plan.exact_keys, *(v.key for v in interpretation_reads),
                *(w.key for w in reflection_writes),
                *(AtomKey.from_token(ref) for ref in execution.cost_receipt_refs)]
            if prepared.work_kind == "simulation":
                registered = service.read_registered_simulation_request(request.simulation_request_ref)
                simulation = D07DomainProvider.simulate(SimulationRequest(registered.activity_id, registered.snapshot_refs,
                    registered.baseline, registered.alternatives, execution.predictions, registered.unknowns))
                from ..graph_types import Owner
                exact.extend(AtomKey(Owner("activity", *prepared.namespace.as_tuple, prepared.activity_id),
                    "d07.simulation_branch.v1", branch.branch_id) for branch in simulation.branches)
            plan = ProductionReadPlanV1(plan.fixed_type_ids, tuple(dict.fromkeys(exact)),
                tuple(dict.fromkeys((*plan.source_roots, *execution.source_refs))),
                tuple(dict.fromkeys((*plan.required_original_refs, job.result_ref, *execution.cost_receipt_refs,
                    *((raw["trigger_original_ref"],) if prepared.work_kind == "reflection" else ())))))
            readers = InstalledD07ProductionReadersV1(issuer=service.d11_issuer, execution_reader=service)
            originals = read_current_domain_original_refs_v1(db, namespace=prepared.namespace, plan=plan,
                installed_readers=readers)
            frame = freeze_domain_production_frame_v1(graph, db, envelope=envelope, current_owner=owner, scope=scope,
                plan=plan, now_utc=now, observed_originals=originals)
            port = readers.port(db, frame)
            from .d07_current_behavior_v1 import advance_current_concerns_v1, advance_current_reflection_v1, run_current_simulation_v1
            if prepared.work_kind == "concern":
                behavior = advance_current_concerns_v1(frame.envelope, request, port.read_concern(db, frame.envelope, request))
            elif prepared.work_kind == "simulation":
                behavior = run_current_simulation_v1(frame.envelope, request, port.read_simulation(db, frame.envelope, request))
            else:
                behavior = advance_current_reflection_v1(frame.envelope, request, port.read_reflection(db, frame.envelope, request))
                from .d07_reflection_execution_v1 import stage_actual_d07_reflection_stop_v1
                behavior = stage_actual_d07_reflection_stop_v1(db, service.d11_issuer, behavior)
            interpretation_writes, interpretation_reads = stage_actual_d07_interpretation_writes_v1(db,
                prepared=prepared, issuer=service.d11_issuer, envelope=frame.envelope)
            fair_writes = ()
            if prepared.work_kind == "reflection":
                from ..domains.d07.concern_round import ConcernServiceChoiceV1, read_concern_round, settle_concern_segment, concern_round_write
                from .d07_current_behavior_v1 import ServeCurrentConcernRequestV1
                category = job.continuation["reflection_category"]
                concern_input = port.read_concern(db, frame.envelope, ServeCurrentConcernRequestV1(category, raw["trigger_original_ref"]))
                round_state = read_concern_round(frame.snapshot, prepared.namespace, category)[0]
                transition = settle_concern_segment(round_state, ConcernServiceChoiceV1(**job.continuation["choice"]),
                    concern_input.tickets, concern_input.policy, effect_id=execution.effect_id,
                    receipt_ref=execution.terminal_ref, now=now, focus_epoch=concern_input.focus_epoch,
                    previously_committed_effect_ids=concern_input.previously_committed_effect_ids)
                fair_writes = () if transition.next_round == round_state else (concern_round_write(prepared.namespace, transition.next_round),)
            staged = build_d07_staged_behavior_operation_v1(frame, behavior,
                additional_writes=(*interpretation_writes, *reflection_writes, *fair_writes))
            # Re-read every exact input and original before the one fixed final
            # CAS. No callback or public DTO can replace this installed route.
            service.verify_prepared_terminal(execution, frame)
            if prepared.work_kind == "reflection":
                verified = advance_current_reflection_v1(frame.envelope, request, port.read_reflection(db, frame.envelope, request))
                if stage_actual_d07_reflection_stop_v1(db, service.d11_issuer, verified) != behavior:
                    raise ValueError("D07 actual reflection wait changed before final CAS")
            all_writes = tuple(w for p in staged.proposals for w in p.typed_writes)
            if len(all_writes) > frame.limits.max_writes:
                raise ValueError("D07 final adopted result exceeds installed bounded write limit")
            receipt = _commit_graph_stage(graph, db, metadata, epoch, prepared, prepared.operation_id,
                "behavior_adopted", now, all_writes, staged.read_versions)
            if receipt is None:
                return {"status": "already_recorded", "job_id": job_id, "terminal_ref": execution.terminal_ref}
            record_d07_adopted_interpretations_after_cas_v1(db, service.d11_issuer, prepared, interpretation_writes,
                operation_id=prepared.operation_id, receipt=receipt)
            reflection_ref = record_actual_reflection_after_cas_v1(db, service.d11_issuer, prepared, reflection_request,
                operation_id=prepared.operation_id)
            row = db.execute("SELECT digest,commit_seq FROM graph_bundle_operations WHERE bot=? AND persona=? AND operation_id=?",
                (*prepared.namespace.as_tuple, prepared.operation_id)).fetchone()
            committed = CommitReceipt("committed", prepared.operation_id, row[0], prepared.activity_id, prepared.effect_id,
                row[1], staged.read_versions, receipt.revisions, (receipt.epoch,), execution.cost_receipt_refs, ())
            record_adopted_domain_operation_v1(db, staged, committed)
            from .d07_budget_v1 import close_actual_d07_child_after_adoption_v1
            close_actual_d07_child_after_adoption_v1(db, prepared=prepared, issuer=service.d11_issuer)
            return {"status": "adopted", "job_id": job_id, "operation_id": prepared.operation_id,
                "terminal_ref": execution.terminal_ref, "interpretation_refs": tuple(w.key.token for w in interpretation_writes),
                "reflection_request_ref": reflection_ref,
                "graph_receipt_digest": canonical_digest(receipt)}
        finally:
            graph.release_authority_lease(bootstrap, token)
    return _write_stage(graph, bootstrap, bundle, job_id=job_id, phase="adopt", commit=commit)
