"""Fixed installed D07 W01 stages; provider and Authority waits stay on host.

Each write rechecks a current signed Owner and paired write fence, then performs
only bounded SQLite/Graph work. The installed service pre-reads paid facts over
mTLS before these methods are invoked. No public request supplies a callback.
"""
from __future__ import annotations
from .natural_producer_qualification_v1 import _producer_original_point_v3
from .domain_background_read_v3 import background_json_loads_v3,background_inventory_v3

from contextlib import nullcontext
from dataclasses import asdict, replace
from datetime import datetime, timezone
import json
import time

from ..contracts import Event, Scope, StaleRead
from ..graph_store import GraphStore
from ..graph_types import AtomKey, GraphAtom, GraphCandidate, GraphSnapshot, GraphVersion, NamespaceEpoch, owner_grant_key
from ..runtime_contracts import (NamespaceId, AuthorityContext, CommandEnvelope, FenceScope, OperationIdentity, QueryEpoch,
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
    expected = background_json_loads_v3(prepared.owner_guard_json)
    row = _producer_original_point_v3(db,table='graph_atoms',columns=('revision', 'value', 'valid'),key_columns=('token',),key=(expected['grant_ref'],),legacy_reader=lambda:db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=?", (expected["grant_ref"],)).fetchone())
    if (row is None or row[2] != 1 or row[0] != expected["grant_revision"]
            or canonical_digest(background_json_loads_v3(row[1])) != expected["grant_digest"]
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
    from .domain_background_read_v3 import _active_v3,require_bound_d07_write_data_v3
    actual_reader=_active_v3(db)
    binding=previous=None
    if actual_reader is not None and actual_reader.kind=="d07_stage" and actual_reader.sealed:
        previous=getattr(actual_reader,"d07_authored_successor",None)
        if previous is None:
            binding=require_bound_d07_write_data_v3(db)
        else:
            previous.require_current()
            binding=previous.binding
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
    if binding is not None:
        actual_reader.d07_authored_successor=_D07AuthoredSuccessorV3(
            _D07_POST_CAS_ISSUER_V3,graph,prepared,candidate,receipt,binding,previous)
    return receipt


def _write_stage(graph, bootstrap, bundle, *, job_id, phase, commit, accounting=False, prepared_read=None):
    """Durable, recoverable background stage with the actual current Owner."""
    service = _service(graph, bootstrap, bundle)
    from ..runtime_storage_v3 import runtime_storage_v3
    if not accounting and prepared_read is None and runtime_storage_v3(service._db) is not None and _d07_stage_has_owner_parent_v3(service,job_id):
        return _prepare_d07_stage_work_v3(graph,bootstrap,bundle,job_id=job_id,stage=phase)
    if prepared_read is not None:
        prepared_read.require_v3(graph)
        if (prepared_read.kind!="d07_stage" or prepared_read.owner.d07_service is not service
                or prepared_read.owner.d07_selector.parent_job_id!=job_id):
            raise TypeError("D07 WRITE requires its exact fixed sealed parent read")
    store, port, policy = service._store, graph._GraphCoordinator__content_fence_v2, bundle.installation_policy
    ns = policy.namespace
    with store._lock:
        original=(_prepared(graph,service,job_id,accounting=accounting) if prepared_read is None
            else prepared_read.local_result["stage_metadata"])
        metadata, epoch = graph._v2_graph_stamp(ns)
        if prepared_read is not None:
            original.require_v3(prepared_read.owner,job_id)
            if (metadata,epoch)!=prepared_read.owner.graph_stamp:
                raise StaleRead("D07 protected READ identity no longer has its actual data stamp")
    operation_id = "d07-stage:" + canonical_digest((ns, original.operation_id, job_id, phase))[:48]
    digest = canonical_digest(("d07.installed-stage.v1", phase, job_id, original.digest))
    attempt = "d07-fence:" + canonical_digest((operation_id, digest))[:48]
    anchor = port.current_anchor(namespace=ns, authority_namespace=policy.authority_namespace)
    if not graph._anchor_matches(metadata.requirements, anchor):
        raise StaleRead("D07 actual Graph/Authority anchor differs")
    with store._lock:
        saved = store._db.execute(f"SELECT job_id,phase,request_digest,attempt_id,anchor_json,graph_revision,graph_epoch,permit_json,receipt_json FROM {TABLE} "
            "WHERE bot=? AND persona=? AND stage_operation_id=?", (*ns.as_tuple, operation_id)).fetchone()
        if (phase in {"acquire", "adopt"} or phase.startswith("reflection_prepare:")) and (saved is None or saved[8] is None):
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
        permit = fence_from_wire(background_json_loads_v3(saved[7]))
        actual, state = port.get_fence_operation(namespace=ns, authority_namespace=policy.authority_namespace, operation_id=attempt)
        if actual != permit or state not in {"active", "finished"}:
            raise ValueError("D07 original installed stage fence unavailable")
    else:
        if saved is not None and (RestoreAnchor(**background_json_loads_v3(saved[4])) != anchor or saved[5:7] != (metadata.graph_revision, epoch.revision)):
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
        return background_json_loads_v3(saved[8])
    if state != "active" or port.validate_fence(scope) != permit:
        raise ValueError("D07 current stage write fence unavailable")
    from ..authority_service.d12_target_owner_admission_v1 import D12CurrentOwnerAuthorityV1
    guarded, owner_permit = port.get_current_background_owner_authority_for_fence_v1(namespace=ns,
        authority_namespace=policy.authority_namespace, permit=permit)
    if type(guarded) is not D12CurrentOwnerAuthorityV1 or owner_permit != permit:
        raise ValueError("D07 actual signed current background Owner unavailable")
    owner_pairing=None
    if prepared_read is not None:
        owner_pairing=port.current_owner_actor_binding(namespace=ns,authority_namespace=policy.authority_namespace,
            actor_id=prepared_read.owner.authority.actor)
        if owner_pairing is None or owner_pairing.installation_id!=port.installation_grant.installation_id:
            raise ValueError("D07 fresh WRITE has no actual current Owner principal pairing")
    owner_entry=None
    if prepared_read is not None:
        from ..authority_service.owner_location_read_v3 import prepare_current_host_d07_write_owner_entry_v3
        owner_entry=prepare_current_host_d07_write_owner_entry_v3(graph,port=port,
            installed_d07_service=service,bootstrap=bootstrap,bundle=bundle,scope=scope,
            current_authority=guarded,principal=owner_pairing.principal,
            authority=prepared_read.owner.authority,operation=prepared_read.owner.operation)
    try:
        if prepared_read is not None:
            from .d07_stage_content_scope_v3 import require_current_host_d07_stage_source_permission_v3
            require_current_host_d07_stage_source_permission_v3(prepared_read.owner,write_scope=scope)
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
                        if prepared_read is not None:
                            from .domain_background_read_v3 import bind_background_reads_v3
                            from ..runtime_storage_v3 import runtime_storage_quantum_v3
                            actual_reader=prepared_read.owner
                            from ..authority_service.owner_location_read_v3 import resolve_current_host_d07_write_owner_binding_v3
                            with runtime_storage_quantum_v3(db) as meter:
                                owner_binding=resolve_current_host_d07_write_owner_binding_v3(graph,
                                    installed_d07_service=service,bootstrap=bootstrap,bundle=bundle,scope=scope,
                                    current_authority=guarded,principal=owner_pairing.principal,owner_entry=owner_entry,
                                    authority=actual_reader.authority,operation=actual_reader.operation,meter=meter)
                                write_owner=owner_binding.require_for_v3(graph,scope,guarded,actual_reader.authority)
                            with bind_background_reads_v3(actual_reader,db=db,scope=scope,current_owner=write_owner),runtime_storage_quantum_v3(db):
                                from .domain_background_read_v3 import require_bound_d07_write_data_v3
                                actual_reader.d07_active_write_binding=require_bound_d07_write_data_v3(db)
                                try:
                                    current_original=_prepared(graph,service,job_id,accounting=accounting)
                                    if current_original.digest!=original.digest or current_original.operation_id!=original.operation_id:
                                        raise ValueError("D07 current prepared changed after its protected stage metadata")
                                    _require_owner(db,current_original,guarded.guard)
                                    result=commit(db,metadata,epoch,now,current_original,guarded.guard,scope,guarded)
                                finally:
                                    actual_reader.d07_active_write_binding=None
                        else:
                            if not accounting:
                                _require_owner(db, original, guarded.guard)
                            result = commit(db, metadata, epoch, now, original, guarded.guard, scope, guarded)
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
    finally:
        if owner_entry is not None:owner_entry.release_v3()


def _content_versions(db, issuer, prepared):
    committed = read_d07_original_v1(db, issuer, prepared.namespace, "prepare_commit", prepared.job_id)
    if committed is None:
        raise ValueError("D07 actual prepare commit original absent")
    return tuple(GraphVersion(AtomKey.from_token(r["ref"]), r["revision"]) for r in committed[0]["post_read_rows"])


def acquire_current_d07_execution_v1(graph, bootstrap, bundle, *, job_id, prepared_read=None):
    service = _service(graph, bootstrap, bundle)
    def commit(db, metadata, epoch, now, prepared, guard, scope, owner_original):
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
        from .d07_general_growth_execution_v1 import D07GeneralGrowthPreparedV1
        general=type(prepared)is D07GeneralGrowthPreparedV1
        frozen=_thaw_d07_stage_frozen_v3(prepared)
        refs=tuple(source.source_ref.ref for source in _d07_stage_frozen_sources_v3(prepared,frozen))
        if general:
            from ..model_broker.general_growth_cognition_v1 import TEMPLATE_DIGEST as template_digest
            model_purpose="consolidation"
        else:
            template_digest=TEMPLATE_DIGEST;model_purpose="proposal"
        deadline = min(datetime.fromisoformat(acquired.deadline_utc.replace("Z", "+00:00")).timestamp(),
            datetime.fromisoformat(acquired.lease_expires_utc.replace("Z", "+00:00")).timestamp())
        if general:deadline=min(deadline,prepared.original_deadline_utc)
        content_reads = _content_versions(db, service.d11_issuer, prepared)
        member_writes = (job_graph_write(acquired),)
        extra = None
        from .d07_execution_v1 import D07RelationshipPreparedV2, D07ReflectionPreparedV3
        from .d07_method_growth_semantic_v2 import D07MethodGrowthPreparedV2
        if type(prepared) in {D07RelationshipPreparedV2, D07MethodGrowthPreparedV2} or (
                type(prepared) is D07ReflectionPreparedV3 and prepared.cycle_ref is not None):
            from .foreground_call_plan_v1 import register_current_named_c3_in_transaction_v2
            cycle_write, cycle_revision = register_current_named_c3_in_transaction_v2(db,
                prepared=prepared, issuer=service.d11_issuer, now_utc=now,
                installed_bundle=bundle, owner_guard=guard)
            member_writes += (cycle_write,)
            reflection = type(prepared) is D07ReflectionPreparedV3
            binding_kind = "reflection_c3" if reflection else "relationship_c3" if type(prepared) is D07RelationshipPreparedV2 else "method_growth_c3"
            extra = {binding_kind: {"cycle_ref": prepared.cycle_ref.key.token,
                "before_cycle_digest": prepared.cycle_digest, "before_call_plan_digest": prepared.call_plan_digest,
                "call_id": prepared.call_id,
                ("reflection_request_digest" if reflection else "semantic_question_digest"):
                    prepared.reflection_request_digest if reflection else prepared.semantic_question_digest}}
        reads = content_reads
        if len(member_writes) == 2:
            reads = tuple(v for v in reads if v.key != cycle_write.key) + (GraphVersion(cycle_write.key, cycle_revision + 1),)
        versions = dict(db.execute("SELECT kind,version FROM graph_guard_versions WHERE bot=? AND persona=? AND ref='current' "
            "AND kind IN ('scheme','operator','policy')", prepared.namespace.as_tuple).fetchall())
        authority = AuthorityContext(holder, "d11", "d07-original:" + prepared.digest, prepared.namespace,
            ("activity", "event", "persona", "scene"), model_purpose, prepared.audience,
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
            frozenset(workflow.required_capabilities), workflow.privacy_tier, template_digest,
            background_json_loads_v3(frozen.canonical_wire), workflow.timeout_seconds, workflow.max_output_tokens)
        seal_d07_request_in_transaction_v1(db, service.d11_issuer, prepared, call)
        member_reads = (*content_reads, GraphVersion(job_graph_write(acquired).key, old_atom[0]))
        _commit_graph_stage(graph, db, metadata, epoch, prepared, acquire_id, "execution_acquired", now,
            member_writes, member_reads, extra=extra)
        return {"status": "acquired", "job_id": job_id}
    return _write_stage(graph, bootstrap, bundle, job_id=job_id, phase="acquire", commit=commit, prepared_read=prepared_read)


def read_acquired_current_d07_execution_v1(graph, bootstrap, bundle, *, job_id, prepared_read=None):
    service = _service(graph, bootstrap, bundle)
    from ..runtime_storage_v3 import runtime_storage_v3
    if prepared_read is None and runtime_storage_v3(service._db) is not None and _d07_stage_has_owner_parent_v3(service,job_id):
        return _prepare_d07_stage_work_v3(graph,bootstrap,bundle,job_id=job_id,stage="egress_read")
    if prepared_read is not None:
        return prepared_read.local_result["egress"]
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
        db=service._db
        db.execute("BEGIN")
        try:
            return _read_d07_acquired_inputs_v3(graph,bootstrap,bundle,service,job_id=job_id,
                prepared=prepared,now=now,owner_guard=owner[0])
        finally:
            db.rollback()
    value, anchor, _metadata, _epoch = graph._read_v2(authority, read, fence_observer=observe, return_recovery_context=True)
    return (*value[:4], anchor, value[4], value[5])


def seal_current_d07_egress_v1(graph, bootstrap, bundle, *, job_id, intent, permit, prepared_read=None):
    service = _service(graph, bootstrap, bundle)
    ns, port = bundle.installation_policy.namespace, graph._GraphCoordinator__content_fence_v2
    actual, state = port.get_fence_operation(namespace=ns, authority_namespace=intent.namespace, operation_id=intent.operation_id)
    anchor = port.current_anchor(namespace=ns, authority_namespace=intent.namespace)
    if (actual != permit or state != "active" or permit.operation != "model_egress" or anchor != permit.pinned_anchor
            or permit.subject != intent.subject or permit.token != intent.fence_token
            or permit.revision != intent.fence_revision or permit.fence_epoch != intent.fence_epoch):
        raise ValueError("D07 actual model preparation fence differs")
    from ..runtime_storage_v3 import runtime_storage_v3
    if prepared_read is None and runtime_storage_v3(service._db) is not None and _d07_stage_has_owner_parent_v3(service,job_id):
        return _prepare_d07_stage_work_v3(graph,bootstrap,bundle,job_id=job_id,stage="egress_seal",
            egress_pair=(intent,permit))
    if prepared_read is not None:
        prepared_read.require_v3(graph)
        if (prepared_read.kind!="d07_stage" or prepared_read.owner.d07_selector.stage!="egress_seal"
                or prepared_read.owner.d07_egress_pair!=(intent,permit)
                or graph._v2_graph_stamp(ns)!=prepared_read.owner.graph_stamp):
            raise ValueError("D07 sealing lost its actual retained current egress intent/read stamp")
    with service._store._lock:
        db = service._db
        db.execute("BEGIN IMMEDIATE")
        if prepared_read is not None:
            prepared_read.owner.d07_active_egress_seal=prepared_read.owner.d07_egress_pair
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
        finally:
            if prepared_read is not None:
                prepared_read.owner.d07_active_egress_seal=None
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


def prepare_current_d07_result_read_v1(graph, bootstrap, bundle, *, job_id, prepared_read=None):
    service = _service(graph, bootstrap, bundle)
    from ..authority_service.d07_current_execution_v1 import D07CognitionResultReadRequestV1, from_wire
    def commit(db, metadata, epoch, now, prepared, guard, scope, owner_original):
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
    raw = _write_stage(graph, bootstrap, bundle, job_id=job_id, phase="result_read", commit=commit, prepared_read=prepared_read)
    from ..graph_worker import GraphStorageWorkV3
    if type(raw) is GraphStorageWorkV3:
        return raw
    return from_wire(background_json_loads_v3(canonical_serialize(raw)), D07CognitionResultReadRequestV1)


def finish_current_d07_execution_v1(graph, bootstrap, bundle, *, job_id, prepared_read=None):
    service = _service(graph, bootstrap, bundle)
    fact, result_read = service.pre_read_cost_fact_v1(job_id), service.pre_read_result_v1(job_id)
    def commit(db, metadata, epoch, now, prepared, guard, scope, owner_original):
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
    return _write_stage(graph, bootstrap, bundle, job_id=job_id, phase="complete", commit=commit, prepared_read=prepared_read)


def resume_current_d07_behavior_v1(graph, bootstrap, bundle, *, job_id, prepared_read=None):
    """Adopt the exact completed D07 result, fair round and model interpretations."""
    service = _service(graph, bootstrap, bundle)
    def commit(db, metadata, epoch, now, prepared, guard, scope, owner_original):
        from .d07_current_behavior_v1 import advance_current_reflection_v1
        from .d07_reflection_execution_v1 import stage_actual_d07_reflection_stop_v1,record_actual_reflection_after_cas_v1
        from .domain_production_originals_v1 import record_adopted_domain_operation_v1
        from ..runtime_contracts import CommitReceipt
        actual=_read_d07_adoption_inputs_v3(graph,bootstrap,bundle,service,job_id=job_id,
            metadata=metadata,epoch=epoch,now=now,prepared=prepared,guard=guard,scope=scope,owner_original=owner_original)
        if type(actual) is dict:
            return actual
        job,execution,frame,behavior,interpretation_writes,reflection_request,staged,request,port=actual
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
    return _write_stage(graph, bootstrap, bundle, job_id=job_id, phase="adopt", commit=commit, prepared_read=prepared_read)

def prepare_current_d07_reflection_continuation_v3(graph, bootstrap, bundle, *, continuation_ref, prepared_read=None):
    """One original continuation under the same installed current Owner fence."""
    from .d07_reflection_execution_v1 import (prepare_reflection_metadata_v3,
        require_current_reflection_parent_v3, read_reflection_continuation_v3)
    from .d07_execution_v1 import record_d07_preparation_after_cas_v1
    from .d07_current_behavior_v1 import ServeCurrentConcernRequestV1, advance_current_concerns_v1
    from .d07_production_operations_v1 import read_plan_current_d07_operation_v1, InstalledD07ProductionReadersV1
    from .domain_production_frame_v1 import freeze_domain_production_frame_v1
    from .domain_production_read_plans_v1 import read_current_domain_original_refs_v1
    from .domain_production_contracts_v1 import ProductionReadPlanV1
    from ..authority_service.v2_owner_contract import OwnerPrincipalV1
    from ..graph_types import Owner
    service = _service(graph, bootstrap, bundle)
    from ..runtime_storage_v3 import runtime_storage_v3
    if prepared_read is None and runtime_storage_v3(service._db) is not None:
        with service._store._lock:
            locator=service._db.execute("SELECT json_extract(payload_json,'$.parent_job_id') FROM graph_d07_execution_originals_v1 "
                "WHERE bot=? AND persona=? AND kind='reflection_continuation' AND original_ref=?",
                (*bundle.installation_policy.namespace.as_tuple,continuation_ref)).fetchone()
        if locator is None:
            return {"status":"waiting_for_actual_reflection_continuation","original_ref":continuation_ref}
        return _prepare_d07_stage_work_v3(graph,bootstrap,bundle,job_id=locator[0],
            stage="reflection_prepare",continuation_ref=continuation_ref)
    if prepared_read is not None and "status" in prepared_read.local_result:
        return prepared_read.local_result
    if prepared_read is not None:
        proposed=prepared_read.local_result["proposed"]
        continuation=proposed["continuation"]
        metadata,epoch=prepared_read.owner.graph_stamp
        observation=canonical_digest((continuation.original_ref,proposed["continuation_digest"],
            metadata.graph_revision,epoch.revision))
    else:
        now = trusted_upper(graph._GraphCoordinator__content_fence_v2.read_ingress_clock(bundle.ingress_clock))
        with service._store._lock:
            db = service._db
            db.execute("BEGIN")
            try:
                proposed = prepare_reflection_metadata_v3(db, issuer=service.d11_issuer,
                    namespace=bundle.installation_policy.namespace, continuation_ref=continuation_ref, now_utc=now)
                if proposed is None:
                    return {"status": "waiting_for_actual_reflection_continuation", "original_ref": continuation_ref}
                if proposed["status"] == "prepared":
                    return {"status": "prepared", "job_id": proposed["job_id"]}
                continuation = proposed["continuation"]
                metadata, epoch = graph._v2_graph_stamp(continuation.namespace)
                observation = canonical_digest((continuation.original_ref, proposed["continuation_digest"],
                    metadata.graph_revision, epoch.revision))
            finally:
                db.rollback()
    phase = "reflection_prepare:" + observation[:48]
    def commit(db, metadata, epoch, now, parent, guard, scope, owner_original):
        actual=_read_d07_reflection_inputs_v3(graph,bootstrap,bundle,service,
            continuation_ref=continuation_ref,proposed=proposed,continuation=continuation,
            metadata=metadata,epoch=epoch,now=now,parent=parent,guard=guard,scope=scope,owner_original=owner_original)
        if type(actual) is dict:
            return actual
        frame,stage=actual
        preparation = service.prepare_current_stage_in_transaction_v1(db,frame,stage)
        service.verify_preparation_in_transaction_v1(db,preparation)
        writes = (*preparation.stage.proposal.typed_writes,*preparation.writes)
        receipt = _commit_graph_stage(graph,db,metadata,epoch,preparation.prepared,
            preparation.prepared.prepare_operation_id,"reflection_prepared",now,writes,preparation.read_versions,
            extra={"reflection_continuation_ref":continuation_ref,
                "reflection_continuation_digest":proposed["continuation_digest"]})
        if receipt is None:
            raise ValueError("reflection preparation has no actual member CAS")
        record_d07_preparation_after_cas_v1(db,service.d11_issuer,preparation,receipt)
        return {"status":"prepared","job_id":preparation.prepared.job_id,
            "original_ref":continuation_ref,"prepared_digest":preparation.prepared.digest}
    return _write_stage(graph,bootstrap,bundle,job_id=continuation.parent_job_id,phase=phase,commit=commit,prepared_read=prepared_read)


def _read_d07_adoption_inputs_v3(graph, bootstrap, bundle, service, *, job_id, metadata, epoch, now, prepared, guard, scope, owner_original, read_owner=None):
    db=service._db
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
            "terminal_ref": job.result_ref, "receipt": background_json_loads_v3(existing[0])}
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
    original_authority = background_json_loads_v3(prepared.owner_authority_json)
    outer_grant = background_json_loads_v3(_producer_original_point_v3(db,table='graph_atoms',columns=('value',),key_columns=('token',),key=(owner_grant_key(*prepared.namespace.as_tuple).token,),legacy_reader=lambda:db.execute("SELECT value FROM graph_atoms WHERE token=?",
        (owner_grant_key(*prepared.namespace.as_tuple).token,)).fetchone())[0])
    outer_purpose = "workbench_user_action" if "workbench_user_action" in outer_grant["purposes"] else sorted(outer_grant["purposes"])[0]
    outer_audience = "owner" if "owner" in outer_grant["audiences"] else sorted(outer_grant["audiences"])[0]
    outer_authority = AuthorityContext(original_authority["actor"], "d07", "d07-background:" + prepared.digest,
        prepared.namespace, tuple(original_authority["owner_scope"]), outer_purpose, (outer_audience,),
        original_authority["provider_policy_ref"], metadata.requirements.activation_generation)
    owner = read_owner if read_owner is not None else graph._owner_graph_binding_locked(outer_authority, OwnerPrincipalV1(**outer_grant["principal"]),
        target_admission=owner_original.target_admission,storage_admission=owner_original.storage_admission,current_guard=guard)
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
        return job,execution,frame,behavior,interpretation_writes,reflection_request,staged,request,port
    finally:
        graph.release_authority_lease(bootstrap,token)


def _read_d07_reflection_inputs_v3(graph, bootstrap, bundle, service, *, continuation_ref, proposed, continuation, metadata, epoch, now, parent, guard, scope, owner_original, read_owner=None):
    db=service._db
    from .d07_reflection_execution_v1 import read_reflection_continuation_v3,require_current_reflection_parent_v3
    from .d07_current_behavior_v1 import ServeCurrentConcernRequestV1,advance_current_concerns_v1
    from .d07_production_operations_v1 import read_plan_current_d07_operation_v1,InstalledD07ProductionReadersV1
    from .domain_production_frame_v1 import freeze_domain_production_frame_v1
    from .domain_production_read_plans_v1 import read_current_domain_original_refs_v1
    from .domain_production_contracts_v1 import ProductionReadPlanV1
    from ..authority_service.v2_owner_contract import OwnerPrincipalV1
    from ..graph_types import Owner
    actual = read_reflection_continuation_v3(db, service.d11_issuer, continuation.namespace, continuation_ref)
    if actual != (continuation, proposed["continuation_digest"]):
        raise ValueError("reflection continuation changed after its original discovery")
    request_original, verified_parent, parent_job, grant = require_current_reflection_parent_v3(
        db, issuer=service.d11_issuer, namespace=continuation.namespace, continuation=continuation, now_utc=now)
    if verified_parent != parent or parent.activation_generation != metadata.requirements.activation_generation:
        raise ValueError("reflection fixed stage observed another parent preparation")
    original_authority = background_json_loads_v3(parent.owner_authority_json)
    current_grant = _producer_original_point_v3(db,table='graph_atoms',columns=('value', 'valid'),key_columns=('token',),key=(owner_grant_key(*continuation.namespace.as_tuple).token,),legacy_reader=lambda:db.execute("SELECT value,valid FROM graph_atoms WHERE token=?",
        (owner_grant_key(*continuation.namespace.as_tuple).token,)).fetchone())
    if current_grant is None or current_grant[1] != 1:
        raise ValueError("reflection current Owner grant is unavailable")
    principal = OwnerPrincipalV1(**background_json_loads_v3(current_grant[0])["principal"])
    token, capability = graph.grant(bootstrap, actor=original_authority["actor"], issuer_domain="d07",
        namespace=continuation.namespace, domains=("d07", "d11"),
        activation_generation=metadata.requirements.activation_generation, operation_id=continuation.operation_id)
    try:
        authority = AuthorityContext(original_authority["actor"], "d07", capability, continuation.namespace,
            tuple(original_authority["owner_scope"]), parent.purpose, parent.audience,
            original_authority["provider_policy_ref"], metadata.requirements.activation_generation)
        owner = read_owner if read_owner is not None else graph._owner_graph_binding_locked(authority, principal,
            target_admission=owner_original.target_admission, storage_admission=owner_original.storage_admission,
            current_guard=owner_original.guard)
        versions = dict(db.execute("SELECT kind,version FROM graph_guard_versions WHERE bot=? AND persona=? "
            "AND ref='current' AND kind IN ('scheme','operator','policy')", continuation.namespace.as_tuple).fetchall())
        deadline = min(continuation.original_deadline_utc, grant.valid_until_utc)
        identity = OperationIdentity("d07-reflection-activity:" + canonical_digest(continuation.operation_id)[:48],
            "d07-reflection-effect:" + canonical_digest(continuation.operation_id)[:48],
            "d07-reflection-attempt:" + canonical_digest(continuation.operation_id)[:48],
            "serve_concern", continuation.operation_id, canonical_digest({"input_refs":list(continuation.source_refs)}))
        envelope = CommandEnvelope(RUNTIME_SCHEMA, identity, authority,
            VersionGuard((), (QueryEpoch(continuation.namespace,"namespace",epoch.revision),),
                owner.access_epoch, owner.delete_epoch, graph._GraphCoordinator__store._registry.catalogue_hash,
                versions["scheme"],versions["operator"],versions["policy"],(),(),()),
            SourceQualification(continuation.source_refs,"derived",None,now,"inference","ineligible",None,"not_applicable"),
            continuation.source_refs, continuation.parent_budget_lease_ref, deadline,
            time.monotonic()+deadline-now, continuation.operation_id, (parent.prepare_operation_id,parent.operation_id))
        request = ServeCurrentConcernRequestV1(continuation.category, continuation.reflection_request_ref)
        plan = read_plan_current_d07_operation_v1(db, namespace=continuation.namespace,
            activity_id=identity.activity_id, operation_kind="serve_concern", request=request)
        ticket_key = AtomKey(Owner(
            "persona",*continuation.namespace.as_tuple),"d07.attention_ticket.v1",continuation.ticket_id)
        plan = ProductionReadPlanV1(plan.fixed_type_ids,
            tuple(dict.fromkeys((*plan.exact_keys, continuation.checkpoint_ref.key, ticket_key))),
            tuple(dict.fromkeys((*plan.source_roots,*continuation.source_refs))),
            tuple(dict.fromkeys((*plan.required_original_refs,continuation.original_ref,parent.job_id,
                continuation.parent_execution_ref))))
        from .d07_execution_v1 import d07_execution_ids_v1
        ids=d07_execution_ids_v1(continuation.namespace,continuation.operation_id,"reflection")
        negative=(AtomKey(Owner("activity",*continuation.namespace.as_tuple,identity.activity_id),"runtime.job",ids["job"]),
            AtomKey(Owner("activity",*continuation.namespace.as_tuple,identity.activity_id),"d02.reservation.v1",ids["reservation"]),
            AtomKey(Owner("activity",*continuation.namespace.as_tuple,identity.activity_id),"d02.settlement.v1",ids["settlement"]))
        plan=replace(plan,exact_keys=tuple(dict.fromkeys((*plan.exact_keys,*negative))))
        readers = InstalledD07ProductionReadersV1(issuer=service.d11_issuer,execution_reader=service)
        originals = read_current_domain_original_refs_v1(db, namespace=continuation.namespace, plan=plan,
            installed_readers=readers)
        frame = freeze_domain_production_frame_v1(graph, db, envelope=envelope,current_owner=owner,
            scope=scope,plan=plan,now_utc=now,observed_originals=originals)
        port = readers.port(db,frame)
        inputs = port.read_concern(db,frame.envelope,request)
        chosen = advance_current_concerns_v1(frame.envelope,request,inputs)
        if chosen.status != "queued":
            return {"status":"waiting_for_fair_concern","original_ref":continuation_ref}
        choice = chosen.provenance["choice"]
        ticket = next(value for value in chosen.provenance["tickets"] if value.ticket_id==choice.ticket_id)
        if choice.ticket_id!=continuation.ticket_id or set(ticket.source_refs)!=set(continuation.source_refs):
            return {"status":"waiting_for_original_fair_ticket","original_ref":continuation_ref}
        stage = replace(chosen,work_kind="reflection",provenance={**chosen.provenance,
            "reflection_request":asdict(request_original),"reflection_continuation":continuation,
            "reflection_continuation_digest":proposed["continuation_digest"]})
        return frame,stage
    finally:
        graph.release_authority_lease(bootstrap,token)

def _prepare_d07_stage_work_v3(graph, bootstrap, bundle, *, job_id, stage, continuation_ref=None, egress_pair=None):
    from .domain_background_read_v3 import prepare_domain_background_read_v3,D07StageReadSelectorV3
    from .domain_background_read_v3 import raise_background_work_error_v3
    service=_service(graph,bootstrap,bundle)
    ns=bundle.installation_policy.namespace
    with service._store._lock:
        row=service._db.execute("SELECT bot_id,persona_id,deadline_utc,lease_expires_utc FROM runtime_jobs WHERE job_id=?",(job_id,)).fetchone()
        if row is None or row[:2]!=ns.as_tuple:
            raise ValueError("D07 stage locator has no actual namespace parent job")
        metadata,epoch=graph._v2_graph_stamp(ns)
    deadline=datetime.fromisoformat(row[2].replace("Z","+00:00")).timestamp()
    from uuid import uuid4
    operation_id="d07-stage-read:"+uuid4().hex
    selector=D07StageReadSelectorV3(parent_job_id=job_id,stage=stage,continuation_ref=continuation_ref)
    model_seal_binding=None
    if stage=="egress_seal":
        from ..authority_service.owner_location_read_v3 import prepare_current_d07_model_seal_binding_v3
        intent,permit=egress_pair
        model_seal_binding=prepare_current_d07_model_seal_binding_v3(graph._GraphCoordinator__content_fence_v2,
            installed_d07_service=service,installed_bundle=bundle,intent=intent,permit=permit,
            job_id=job_id,graph_stamp=(metadata,epoch),clock_policy=bundle.ingress_clock)
        if row[3]is None:
            model_seal_binding.release_v3()
            raise ValueError("D07 original acquired worker has no immutable lease expiry")
        deadline=min(deadline,model_seal_binding.original_deadline_utc,
            datetime.fromisoformat(row[3].replace("Z","+00:00")).timestamp())
    work=prepare_domain_background_read_v3(graph,bootstrap,bundle,kind="d07_stage",
        operation_id=operation_id,deadline_utc=deadline,d07_service=service,d07_selector=selector,
        d07_model_seal_binding=model_seal_binding)
    if egress_pair is not None:
        if stage!="egress_seal" or type(egress_pair[0]) is not ModelEgressIntentV1:
            raise TypeError("only the fixed actual egress seal can retain its issued intent")
        work.state.d07_egress_pair=egress_pair
        from .source_correction_read_v3 import _heap
        work.state.operation.retain(_heap(egress_pair,set()))
    return work.map_terminal_v3("issuer",lambda prepared:_finish_d07_stage_read_v3(graph,prepared),raise_background_work_error_v3)


def _finish_d07_stage_read_v3(graph, prepared):
    from .domain_background_read_v3 import bind_background_reads_v3
    from ..runtime_storage_v3 import bind_runtime_storage_operation_v3
    prepared.require_v3(graph)
    reader=prepared.owner
    if prepared.kind!="d07_stage":
        raise TypeError("D07 stage mapper requires its exact privately issued Work")
    selected=reader.d07_selector
    service=reader.d07_service
    functions={"acquire":acquire_current_d07_execution_v1,"complete":finish_current_d07_execution_v1,
        "adopt":resume_current_d07_behavior_v1,"result_read":prepare_current_d07_result_read_v1,
        "egress_read":read_acquired_current_d07_execution_v1}
    try:
        with bind_runtime_storage_operation_v3(reader.operation,reader.db),bind_background_reads_v3(reader,db=reader.db):
            if selected.stage=="reflection_prepare":
                return prepare_current_d07_reflection_continuation_v3(graph,service.bootstrap,service.bundle,
                    continuation_ref=selected.continuation_ref,prepared_read=prepared)
            if selected.stage=="egress_seal":
                job=reader.local_result["job"]
                intent,permit=reader.d07_egress_pair
                return seal_current_d07_egress_v1(graph,service.bootstrap,service.bundle,
                    job_id=job.job_id,intent=intent,permit=permit,prepared_read=prepared)
            return functions[selected.stage](graph,service.bootstrap,service.bundle,
                job_id=selected.parent_job_id,prepared_read=prepared)
    finally:
        prepared.release_payload_v3()


def _thaw_d07_stage_frozen_v3(prepared):
    from .d07_general_growth_execution_v1 import D07GeneralGrowthPreparedV1,thaw_current_general_growth_prepared_request_v1
    if type(prepared)is D07GeneralGrowthPreparedV1:return thaw_current_general_growth_prepared_request_v1(prepared)
    return thaw_d07_cognition_request_v1(background_json_loads_v3(prepared.frozen_json))

def _d07_stage_frozen_sources_v3(prepared,frozen):
    from .d07_general_growth_execution_v1 import D07GeneralGrowthPreparedV1,general_growth_frozen_sources_v1
    if type(prepared)is D07GeneralGrowthPreparedV1:return general_growth_frozen_sources_v1(frozen)
    return frozen.input.sources

def _read_d07_stage_frame_v3(reader, prepared, job):
    from .domain_production_contracts_v1 import ProductionReadPlanV1
    from .domain_production_frame_v1 import freeze_domain_production_frame_v1
    from .domain_production_read_plans_v1 import read_current_domain_original_refs_v1
    from .d07_production_operations_v1 import InstalledD07ProductionReadersV1
    frozen=_thaw_d07_stage_frozen_v3(prepared)
    ns=prepared.namespace
    scope=reader.read_scope
    from .domain_background_read_v3 import require_current_d07_content_source_authority_v3
    authority=require_current_d07_content_source_authority_v3(reader)
    versions=dict(reader.db.execute("SELECT kind,version FROM graph_guard_versions WHERE bot=? AND persona=? "
        "AND ref='current' AND kind IN ('scheme','operator','policy')",ns.as_tuple).fetchall())
    source_refs=tuple(source.source_ref.ref for source in _d07_stage_frozen_sources_v3(prepared,frozen))
    envelope=CommandEnvelope(RUNTIME_SCHEMA,OperationIdentity(prepared.activity_id,prepared.effect_id,
        prepared.attempt_id,"d07_stage_read",prepared.operation_id,canonical_digest({"input_refs":list(source_refs)})),
        authority,VersionGuard((),(QueryEpoch(ns,"namespace",reader.graph_stamp[1].revision),),
            reader.owner.access_epoch,reader.owner.delete_epoch,reader.store._registry.catalogue_hash,
            versions["scheme"],versions["operator"],versions["policy"],(),(),()),
        SourceQualification(source_refs,"derived",None,reader.now,"inference","ineligible",None,"not_applicable"),
        source_refs,job.budget_ref,datetime.fromisoformat(job.deadline_utc.replace("Z","+00:00")).timestamp(),
        reader.operation.deadline_utc-reader.now+time.monotonic(),prepared.operation_id,(prepared.prepare_operation_id,))
    committed=read_d07_original_v1(reader.db,reader.d07_service.d11_issuer,ns,"prepare_commit",prepared.job_id)
    if committed is None or committed[0]["prepared_digest"]!=prepared.digest:
        raise ValueError("D07 stage read lost its actual preparation CAS")
    pages=background_json_loads_v3(committed[0]["post_query_inventory_json"])
    resource_quote=reader.d07_service.resource_issuer.original_signed_quote(reader.db,prepared.quote_id,prepared.quote_version)
    keys=tuple(dict.fromkeys((owner_grant_key(*ns.as_tuple),job_graph_write(job).key,
        *(AtomKey.from_token(ref) for ref in resource_quote.d02_settlement_refs),
        *(AtomKey.from_token(row["ref"]) for row in committed[0]["post_read_rows"]),
        AtomKey.from_token(prepared.body_state_ref),AtomKey.from_token(prepared.body_profile_ref),
        AtomKey.from_token(prepared.body_reservation_ref))))
    plan=ProductionReadPlanV1(tuple(page["type_id"] for page in pages),keys,source_refs,())
    readers=InstalledD07ProductionReadersV1(issuer=reader.d07_service.d11_issuer,execution_reader=reader.d07_service)
    originals=read_current_domain_original_refs_v1(reader.db,namespace=ns,plan=plan,installed_readers=readers)
    from .d07_stage_content_scope_v3 import freeze_current_host_d07_stage_read_frame_v3
    return freeze_current_host_d07_stage_read_frame_v3(reader,envelope=envelope,
        scope=scope,plan=plan,now_utc=reader.now,observed_originals=originals)


def prepare_d07_stage_read_data_v3(reader):
    """Fixed, side-effect free READ recipe; it cannot quote, reserve, acquire or commit."""
    from .domain_background_read_v3 import require_actual_background_attachment_owner_v3,background_graph_head_v3
    from .d07_reflection_execution_v1 import prepare_reflection_metadata_v3
    require_actual_background_attachment_owner_v3(reader,db=reader.db)
    if reader.kind!="d07_stage" or reader.d07_service is not _service(reader.graph,reader.bootstrap,reader.bundle):
        raise TypeError("actual installed D07 READ Work required")
    service,selector=reader.d07_service,reader.d07_selector
    material=reader.d07_source_material
    material.require_for_prepared_v3(reader,reader.entry_metadata[0][0])
    prepared=_prepared(reader.graph,service,selector.parent_job_id)
    from .domain_background_read_v3 import require_current_d07_frozen_source_material_v3
    require_current_d07_frozen_source_material_v3(reader,prepared)
    from .d07_general_growth_execution_v1 import D07GeneralGrowthPreparedV1,require_current_general_growth_prepared_v1
    if type(prepared)is D07GeneralGrowthPreparedV1:
        require_current_general_growth_prepared_v1(reader.db,issuer=service.d11_issuer,prepared=prepared,
            installed_bundle=reader.bundle,now=reader.now)
    stage_metadata=_D07VerifiedStageMetadataV3(_D07_POST_CAS_ISSUER_V3,reader,prepared)
    job=get_job(reader.db,selector.parent_job_id)
    _require_owner(reader.db,prepared,reader.owner_guard)
    metadata,epoch=reader.graph_stamp
    if selector.stage=="reflection_prepare":
        proposed=prepare_reflection_metadata_v3(reader.db,issuer=service.d11_issuer,namespace=reader.namespace,
            continuation_ref=selector.continuation_ref,now_utc=reader.now)
        if proposed is None:
            return {"status":"waiting_for_actual_reflection_continuation"}
        if proposed["status"]=="prepared":
            return proposed
        continuation=proposed["continuation"]
        _register_d07_initial_ticket_plan_v3(reader,prepared,job,continuation.operation_id,continuation.source_refs)
        actual=_read_d07_reflection_inputs_v3(reader.graph,reader.bootstrap,reader.bundle,service,
            continuation_ref=selector.continuation_ref,proposed=proposed,continuation=continuation,
            metadata=metadata,epoch=epoch,now=reader.now,parent=prepared,guard=reader.owner_guard,
            scope=reader.read_scope,owner_original=None,read_owner=reader.owner)
        if type(actual) is dict:
            return actual
        frame,stage=actual
        workflow=service.bundle.model_workflows.d07_cognition
        # Pure resource inputs only. The same fixed WRITE performs issuance once.
        from .budget import get_budget_lease,require_budget_family_admissible
        from .d07_execution_v1 import _clock_original
        lease=get_budget_lease(reader.db,continuation.parent_budget_lease_ref)
        require_budget_family_admissible(reader.db,lease.lease_id)
        service.d11_issuer.current_budget_grant(reader.db,lease.lease_id)
        from .d11_role_clock_installation_v1 import read_current_role_clock_installation_v1
        role_reader=reader.graph._GraphCoordinator__d04_semantic_mapping_reader
        clock=read_current_role_clock_installation_v1(role_reader,reader.db,reader.namespace)
        _clock_original(reader.db,service.d11_issuer,reader.namespace,clock)
        policy_id,policy_version=service._current_body_policy(reader.db,reader.namespace)
        service.body_authority.policy(reader.db,reader.namespace,policy_id,policy_version)
        return {"prepared":prepared,"stage_metadata":stage_metadata,"job":job,"proposed":proposed,"frame":frame,"stage":stage}
    if selector.stage=="adopt":
        _register_d07_initial_ticket_plan_v3(reader,prepared,job,prepared.operation_id,
            tuple(source.source_ref.ref for source in _d07_stage_frozen_sources_v3(prepared,_thaw_d07_stage_frozen_v3(prepared))))
        actual=_read_d07_adoption_inputs_v3(reader.graph,reader.bootstrap,reader.bundle,service,
            job_id=job.job_id,metadata=metadata,epoch=epoch,now=reader.now,prepared=prepared,
            guard=reader.owner_guard,scope=reader.read_scope,owner_original=None,read_owner=reader.owner)
        return {"prepared":prepared,"stage_metadata":stage_metadata,"job":job,"adoption":actual}
    if selector.stage=="egress_seal":
        recipe=prepare_current_d07_model_seal_source_recipe_v3(reader,prepared,job)
        return {"prepared":prepared,"stage_metadata":stage_metadata,"job":job,"model_seal_recipe":recipe}
    frame=_read_d07_stage_frame_v3(reader,prepared,job)
    if selector.stage=="egress_read":
        value=_read_d07_acquired_inputs_v3(reader.graph,reader.bootstrap,reader.bundle,service,
            job_id=job.job_id,prepared=prepared,now=reader.now,owner_guard=reader.owner_guard)
        if type(value) is dict:
            return {"prepared":prepared,"stage_metadata":stage_metadata,"job":job,"egress":value}
        return {"prepared":prepared,"stage_metadata":stage_metadata,"job":job,
            "egress":(*value[:4],reader.read_scope.pinned_anchor,value[4],value[5])}
    require_current_d07_content_reads_v1(reader.db,prepared,issuer=service.d11_issuer)
    background_graph_head_v3(reader.db,reader.namespace,job_graph_write(job).key)
    resource_quote=service.resource_issuer.original_signed_quote(reader.db,prepared.quote_id,prepared.quote_version)
    if selector.stage in {"complete","egress_seal","result_read"}:
        service.body_authority.original_body_quote(reader.db,prepared.body_quote_ref,
            prepared.body_quote_version,resource_quote,prepared.operation_id)
    for kind,ref in (("request",job.job_id),("call",job.job_id),("result_attempt",job.job_id),
            ("execution","d07-terminal:"+prepared.call_id),("result","d07-result:"+prepared.call_id),
            ("body_cost",job.job_id),("paid_cost",job.job_id),("accounting_prepared",job.job_id)):
        read_d07_original_v1(reader.db,service.d11_issuer,reader.namespace,kind,ref)
    if selector.stage=="complete":
        from .d07_execution_v1 import _clock_from_json,_clock_original
        _clock_original(reader.db,service.d11_issuer,reader.namespace,_clock_from_json(prepared.clock_mapping_json))
    return {"prepared":prepared,"stage_metadata":stage_metadata,"job":job,"frame":frame}

def _d07_stage_has_owner_parent_v3(service,job_id):
    """SelfIngressRecall keeps its registered worker Source READ protocol."""
    namespace=service.bundle.installation_policy.namespace
    with service._store._lock:
        row=service._db.execute("SELECT json_extract(payload_json,'$.schema') FROM graph_d07_execution_originals_v1 "
            "WHERE bot=? AND persona=? AND kind='prepared' AND original_ref=?",
            (*namespace.as_tuple,job_id)).fetchone()
    return row is None or row[0]!="d07.ingress-recall-prepared.v1"


def _read_d07_acquired_inputs_v3(graph,bootstrap,bundle,service,*,job_id,prepared,now,owner_guard):
    db=service._db
    ns=bundle.installation_policy.namespace
    current, epoch = graph._v2_graph_stamp(ns)
    _require_owner(db, prepared, owner_guard)
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
        frozen = thaw_d07_ingress_recall_request_v1(background_json_loads_v3(prepared.frozen_json))
        _require_current_ingress_recall_parent_v1(db, prepared=prepared, frozen=frozen, request=call,
            issuer=service.d11_issuer, installed_bundle=bundle, now=now)
        input_sources = (frozen.input.cue, *frozen.input.known_sources)
    else:
        frozen = _thaw_d07_stage_frozen_v3(prepared)
        input_sources = _d07_stage_frozen_sources_v3(prepared,frozen)
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
    audience = background_json_loads_v3(prepared.audience[0])
    if type(audience) is not list or len(audience) != 2 or any(type(v) is not str or not v for v in audience):
        raise ValueError("D07 selected AstrBot session identity is not installed")
    return prepared, job, call, draft, intent, audience[0]

from weakref import WeakKeyDictionary
from types import MappingProxyType
_D07_POST_CAS_ISSUER_V3=object()
_D07_POST_CAS_PROOFS_V3=WeakKeyDictionary()


class _D07AuthoredSuccessorV3:
    """Data from this private GraphStore CAS; it grants no execution or Owner scope."""
    def __init__(self, issuer, graph, prepared, candidate, receipt, binding, previous):
        from ..runtime_storage_v3 import runtime_storage_quantum_v3,_runtime_bounded_fixed_row_v3,begin_runtime_cell_read_v3,read_runtime_cell_origin_v3
        from .domain_background_read_v3 import require_actual_background_attachment_owner_v3
        from .source_correction_read_v3 import _heap
        if issuer is not _D07_POST_CAS_ISSUER_V3:
            raise TypeError("actual D07 GraphStore successor issuer required")
        owner,scope,current_owner=binding
        require_actual_background_attachment_owner_v3(owner,db=owner.db)
        if (owner.graph is not graph or owner.kind!="d07_stage" or not owner.sealed
                or owner.d07_active_write_binding is not binding or not owner.db.in_transaction
                or not owner.store._lock._is_owned() or prepared.namespace!=owner.namespace
                or scope.namespace!=owner.namespace or receipt.status!="committed"
                or candidate.event.scope.bot!=owner.namespace.bot_id
                or candidate.event.scope.persona!=owner.namespace.persona_id):
            raise ValueError("D07 successor lost its real writer/namespace/transaction")
        self.owner,self.db,self.binding=owner,owner.db,binding
        self.previous,self.prepared,self.candidate,self.receipt=previous,prepared,candidate,receipt
        self.atoms={} if previous is None else dict(previous.atoms)
        self.histories={} if previous is None else dict(previous.histories)
        self.after_stamp=graph._v2_graph_stamp(owner.namespace)
        before=owner.graph_stamp if previous is None else previous.after_stamp
        if (self.after_stamp[0].graph_revision!=before[0].graph_revision+1
                or self.after_stamp[1]!=receipt.epoch or self.after_stamp[1].revision!=before[1].revision+1):
            raise ValueError("D07 successor is not this one actual CAS progression")
        writes={write.key:write for write in candidate.writes}
        known={request[3][0] for request in owner.points if request[0]=="graph_atoms"}
        if any(version.key.token in known and version.key not in writes for version in receipt.invalidated):
            raise ValueError("D07 invalidation changed a selected head without an authored successor value")
        if any(key.type_name.startswith("memory.") or key==owner_grant_key(*owner.namespace.as_tuple)
                for key in writes):
            raise ValueError("D07 authored successor cannot change its Source or current Owner evidence")
        if len(writes)!=len(candidate.writes) or set(writes)!={version.key for version in receipt.revisions}:
            raise ValueError("D07 successor receipt changed its actual writer members")
        operation_id=candidate.event.event_id
        event_scope=(*owner.namespace.as_tuple,prepared.activity_id,operation_id)
        with runtime_storage_quantum_v3(self.db) as meter:
            for request,task in owner.points.items():
                if request[0]!="graph_atoms" or not task.complete or request[3][0] in self.atoms:
                    continue
                key=AtomKey.from_token(request[3][0])
                if not (key.type_name.startswith("memory.") or key==owner_grant_key(*owner.namespace.as_tuple)
                        or key.type_name.startswith(("d03.","d12."))):
                    continue
                current=_runtime_bounded_fixed_row_v3(self.db,meter,task.table,task.metadata_columns,task.where,task.key)
                if current!=task.metadata:
                    raise ValueError("D07 current Source/Owner/Control pointer changed in the actual CAS")
            event=_runtime_bounded_fixed_row_v3(self.db,meter,"graph_events",
                ("digest","revisions","epoch_revision"),"bot=? AND persona=? AND session=? AND event_id=?",event_scope)
            if (event is None or event[0]!=candidate.event.digest
                    or json.loads(event[1])!=[[version.key.token,version.revision] for version in receipt.revisions]
                    or event[2]!=receipt.epoch.revision):
                raise ValueError("D07 successor lost the actual committed full Graph event")
            for key,write in writes.items():
                version=next(version for version in receipt.revisions if version.key==key)
                head=_runtime_bounded_fixed_row_v3(self.db,meter,"graph_atoms",
                    ("revision","valid","value_cell_id"),"token=? AND bot=? AND persona=?",(key.token,*owner.namespace.as_tuple))
                history=_runtime_bounded_fixed_row_v3(self.db,meter,"graph_history",
                    ("valid","value_cell_id","event_bot","event_persona","event_session","event_id"),
                    "token=? AND revision=?",(key.token,version.revision))
                if (head is None or head[:2]!=(version.revision,1) or history is None
                        or history[:2]!=(1,head[2]) or history[2:]!=event_scope):
                    raise ValueError("D07 successor head/history/cell differs from its actual member CAS")
                cell=begin_runtime_cell_read_v3(self.db,head[2],erasure_owner_ref=key.token)
                origin=read_runtime_cell_origin_v3(self.db,head[2],header=cell.header,meter=meter)
                normalized=owner.store._registry.validate(key,write.value)
                wire=canonical_serialize(normalized);encoded=wire.encode("utf-8")
                offset=0
                while True:
                    fragment=cell.read_fragment(meter=meter)
                    if fragment is None:
                        break
                    if encoded[offset:offset+len(fragment)]!=fragment:
                        raise ValueError("D07 authored value differs from actual sealed cell bytes")
                    offset+=len(fragment)
                digest=cell.finish(meter=meter)
                if (offset!=len(encoded) or digest!=canonical_digest(normalized) or origin is None
                        or origin["operation_id"]!=operation_id or origin["event_digest"]!=event[0]
                        or origin["locator"]!={"table":"graph_atoms","token":key.token,"revision":version.revision}):
                    raise ValueError("D07 authored value lacks its exact actual canonical cell origin and EOF")
                self.atoms[key.token]=(version.revision,wire,1,head[2],key.type_name)
                self.histories[(key.token,version.revision)]=(history,wire)
        owner.operation.retain(_heap((self.atoms,self.histories),set())+4096)
        self.atoms,self.histories=MappingProxyType(self.atoms),MappingProxyType(self.histories)
        _D07_POST_CAS_PROOFS_V3[self]=(self.owner,self.db,self.binding,self.candidate,self.receipt,self.after_stamp,self.atoms,self.histories)

    def require_current(self):
        from .domain_background_read_v3 import require_actual_background_attachment_owner_v3
        owner=self.owner
        require_actual_background_attachment_owner_v3(owner,db=self.db)
        if (_D07_POST_CAS_PROOFS_V3.get(self)!=(self.owner,self.db,self.binding,self.candidate,self.receipt,self.after_stamp,self.atoms,self.histories)
                or getattr(owner,"d07_authored_successor",None) is not self
                or owner.d07_active_write_binding is not self.binding or not self.db.in_transaction
                or not owner.store._lock._is_owned() or owner.graph._v2_graph_stamp(owner.namespace)!=self.after_stamp):
            raise ValueError("D07 authored successor is no longer the same current writer transaction")
        return self


def require_d07_mutable_successor_v3(owner,binding):
    proof=getattr(owner,"d07_authored_successor",None)
    if proof is None:
        return False
    if type(proof) is not _D07AuthoredSuccessorV3 or proof.binding is not binding:
        raise ValueError("D07 mutable data has another actual successor binding")
    proof.require_current()
    return True


def _record_d07_actual_written_original_v3(db,namespace,kind,ref,wire,digest,signature):
    from .domain_background_read_v3 import require_bound_d07_write_data_v3
    # Called only by the fixed D07 signer after its actual INSERT in the held transaction.
    from .domain_background_read_v3 import _active_v3
    owner=_active_v3(db)
    if owner is None or owner.kind!="d07_stage":
        return
    proof=getattr(owner,"d07_authored_successor",None)
    if proof is None and owner.d07_selector.stage=="egress_seal":
        pair=getattr(owner,"d07_active_egress_seal",None)
        if pair is None or pair!=owner.d07_egress_pair or not db.in_transaction or not owner.store._lock._is_owned():
            raise ValueError("new D07 call has no actual active fixed seal writer")
        intent,permit=pair
        if (permit.token!=intent.fence_token or canonical_digest(asdict(permit.pinned_anchor))!=intent.anchor_digest
                or owner.graph._v2_graph_stamp(namespace)!=owner.graph_stamp):
            raise ValueError("new D07 call lost its current actual admitted model permit")
        binding=(owner,permit,None)
    elif proof is None:
        binding=require_bound_d07_write_data_v3(db)
    else:
        proof.require_current()
        binding=proof.binding
    owner=binding[0]
    if namespace!=owner.namespace:
        raise ValueError("D07 authored original crossed its actual writer namespace")
    rows=getattr(owner,"d07_authored_originals",None)
    if rows is None:
        rows={};owner.d07_authored_originals=rows
    actual=db.execute("SELECT payload_digest,signature FROM graph_d07_execution_originals_v1 "
        "WHERE bot=? AND persona=? AND kind=? AND original_ref=?",(*namespace.as_tuple,kind,ref)).fetchone()
    if actual!=(digest,signature) or canonical_digest(json.loads(wire))!=digest:
        raise ValueError("D07 authored signed original lost its actual same-writer INSERT")
    rows[(*namespace.as_tuple,kind,ref)]=(wire,digest,signature)
    from .source_correction_read_v3 import _heap
    owner.operation.retain(_heap(rows[(*namespace.as_tuple,kind,ref)],set())+1024)


def read_bound_d07_authored_successor_attachment_v3(owner,request):
    table,columns,keys,key=request
    originals=getattr(owner,"d07_authored_originals",{})
    if table=="graph_d07_execution_originals_v1" and key in originals:
        wire,digest,signature=originals[key]
        actual=owner.db.execute("SELECT payload_digest,signature FROM graph_d07_execution_originals_v1 "
            "WHERE bot=? AND persona=? AND kind=? AND original_ref=?",key).fetchone()
        if actual!=(digest,signature) or not owner.db.in_transaction or not owner.store._lock._is_owned():
            raise ValueError("D07 authored original lost its immutable actual current row")
        row={"payload_json":wire,"payload_digest":digest,"signature":signature}
        return True,tuple(row[name] for name in columns)
    proof=getattr(owner,"d07_authored_successor",None)
    if proof is None:
        return False,None
    if type(proof) is not _D07AuthoredSuccessorV3:
        raise TypeError("exact privately issued D07 successor required")
    proof.require_current()
    from ..runtime_storage_v3 import runtime_storage_quantum_v3,_runtime_bounded_fixed_row_v3
    if table=="graph_atoms" and key[0] in proof.atoms:
        revision,wire,valid,cell,type_name=proof.atoms[key[0]]
        with runtime_storage_quantum_v3(owner.db) as meter:
            actual=_runtime_bounded_fixed_row_v3(owner.db,meter,"graph_atoms",("revision","valid","value_cell_id"),
                "token=? AND bot=? AND persona=?",(key[0],*owner.namespace.as_tuple))
        if actual!=(revision,valid,cell):
            raise ValueError("D07 authored current head changed after its actual CAS")
        values={"revision":revision,"value":wire,"valid":valid,"type_name":type_name}
        return True,tuple(values[name] for name in columns)
    if table=="graph_history" and key in proof.histories:
        history,wire=proof.histories[key]
        values={"valid":history[0],"value":wire,"event_bot":history[2],"event_persona":history[3],
            "event_session":history[4],"event_id":history[5]}
        if "dependencies" in columns:
            with runtime_storage_quantum_v3(owner.db) as meter:
                actual=_runtime_bounded_fixed_row_v3(owner.db,meter,"graph_history",("dependencies",),
                    "token=? AND revision=?",key)
            values["dependencies"]=actual[0]
        return True,tuple(values[name] for name in columns)
    task=owner.points.get(request)
    if task is None or not task.complete:
        raise ValueError("D07 unchanged successor original was outside its actual sealed input set")
    if table in {"graph_atoms","graph_history"}:
        # All member writes and selected invalidations were verified at this exact CAS boundary.
        return True,task.row
    with runtime_storage_quantum_v3(owner.db) as meter:
        metadata=_runtime_bounded_fixed_row_v3(owner.db,meter,table,task.metadata_columns,
            " AND ".join(name+"=?" for name in keys),key)
        if metadata!=task.metadata:
            raise ValueError("D07 unchanged selected source/original changed after its own CAS")
        return True,task.require_row_v3(meter)

def read_d07_actual_writer_prior_v3(db,namespace,kind,ref,issuer):
    from .domain_background_read_v3 import _active_v3,require_bound_d07_write_data_v3
    owner=_active_v3(db)
    if owner is None or owner.kind!="d07_stage" or not owner.sealed:
        return False,None
    if owner.d07_selector.stage=="egress_seal":
        if getattr(owner,"d07_active_egress_seal",None)!=owner.d07_egress_pair:
            raise ValueError("D07 prior call lookup is outside its actual fixed seal writer")
    else:
        proof=getattr(owner,"d07_authored_successor",None)
        if proof is None:require_bound_d07_write_data_v3(db)
        else:proof.require_current()
    if namespace!=owner.namespace or not db.in_transaction or not owner.store._lock._is_owned():
        raise ValueError("D07 original prior metadata lost its actual current writer")
    actual=db.execute("SELECT payload_digest,signature FROM graph_d07_execution_originals_v1 "
        "WHERE bot=? AND persona=? AND kind=? AND original_ref=?",(*namespace.as_tuple,kind,ref)).fetchone()
    if actual is None:
        return True,None
    return True,read_d07_original_v1(db,issuer,namespace,kind,ref)

def _register_d07_initial_ticket_plan_v3(reader,prepared,job,operation_id,source_refs):
    from .domain_production_contracts_v1 import ProductionReadPlanV1
    from .domain_production_frame_v1 import freeze_domain_production_frame_v1
    ns=reader.namespace
    scope=reader.read_scope
    versions=dict(reader.db.execute("SELECT kind,version FROM graph_guard_versions WHERE bot=? AND persona=? "
        "AND ref='current' AND kind IN ('scheme','operator','policy')",ns.as_tuple).fetchall())
    envelope=CommandEnvelope(RUNTIME_SCHEMA,OperationIdentity(prepared.activity_id,prepared.effect_id,prepared.attempt_id,
        "d07_ticket_census",operation_id,canonical_digest({"input_refs":list(source_refs)})),reader.authority,
        VersionGuard((),(QueryEpoch(ns,"namespace",reader.graph_stamp[1].revision),),
            reader.owner.access_epoch,reader.owner.delete_epoch,reader.store._registry.catalogue_hash,
            versions["scheme"],versions["operator"],versions["policy"],(),(),()),
        SourceQualification(source_refs,"derived",None,reader.now,"inference","ineligible",None,"not_applicable"),
        source_refs,job.budget_ref,reader.operation.deadline_utc,
        time.monotonic()+reader.operation.deadline_utc-reader.now,operation_id,(prepared.prepare_operation_id,))
    plan=ProductionReadPlanV1(("d07.attention_ticket.v1",),(owner_grant_key(*ns.as_tuple),),source_refs,())
    return freeze_domain_production_frame_v1(reader.graph,reader.db,envelope=envelope,current_owner=reader.owner,
        scope=scope,plan=plan,now_utc=reader.now)

_D07_STAGE_METADATA_V3=WeakKeyDictionary()


class _D07VerifiedStageMetadataV3:
    """Verified stage identity only; protected prepared bodies are not part of this locator."""
    def __init__(self,issuer,reader,prepared):
        if issuer is not _D07_POST_CAS_ISSUER_V3:
            raise TypeError("actual D07 protected READ metadata issuer required")
        from .domain_background_read_v3 import PreparedD07StageSourceMaterialV3
        material=reader.d07_source_material
        if type(material) is not PreparedD07StageSourceMaterialV3:
            raise TypeError("D07 stage metadata requires its own current Source-qualified READ")
        material.require_for_prepared_v3(reader,reader.entry_metadata[0][0])
        self.reader,self.namespace=reader,prepared.namespace
        self.job_id,self.operation_id,self.digest=prepared.job_id,prepared.operation_id,prepared.digest
        _D07_STAGE_METADATA_V3[self]=(reader,self.namespace,self.job_id,self.operation_id,self.digest)
    def require_v3(self,reader,job_id):
        if (_D07_STAGE_METADATA_V3.get(self)!=(self.reader,self.namespace,self.job_id,self.operation_id,self.digest)
                or reader is not self.reader or job_id!=self.job_id):
            raise ValueError("D07 handoff stage locator is not this exact protected READ")
        return self


_D07_MODEL_SEAL_RECIPES_V3=WeakKeyDictionary()

class _D07ModelSealSourceReadRecipeV3:
    """The immutable read set of one actual model call, without a business WRITE frame."""
    def __init__(self,issuer,reader,prepared,job,committed,resource_quote):
        from .domain_background_read_v3 import require_actual_background_attachment_owner_v3,require_current_d07_content_source_authority_v3
        from .domain_production_contracts_v1 import ProductionReadPlanV1
        from ..authority_service.owner_location_read_v3 import D07ContentSourceScopeV3,D07ActualModelSealReadBindingV3
        if issuer is not _D07_POST_CAS_ISSUER_V3:
            raise TypeError("actual D07 model seal recipe issuer required")
        require_actual_background_attachment_owner_v3(reader,db=reader.db)
        source= require_current_d07_content_source_authority_v3(reader)
        intent,permit=reader.d07_egress_pair
        if (reader.kind!="d07_stage" or reader.d07_selector.stage!="egress_seal"
                or type(reader.d07_source_scope)is not D07ContentSourceScopeV3
                or type(reader.d07_model_seal_binding)is not D07ActualModelSealReadBindingV3
                or reader.d07_model_seal_binding.scope is not reader.read_scope
                or reader.d07_model_seal_binding.intent is not intent
                or reader.d07_model_seal_binding.permit is not permit
                or reader.read_scope.permit is not permit
                or reader.d07_model_seal_binding.model_authority!=reader.d07_model_authority
                or prepared.namespace!=reader.namespace or prepared.job_id!=job.job_id
                or (job.job_id,job.phase,job.cancel_epoch,job.fence,job.lease_holder)!=
                   (intent.job_id,"running",0,intent.worker_fence,intent.subject)
                or committed[0]["prepared_digest"]!=prepared.digest
                or (intent.binding_digest,intent.call_id)!=(prepared.digest,prepared.call_id)):
            raise ValueError("D07 immutable seal recipe differs from the actual acquired model call")
        reader.d07_source_material.require_for_prepared_v3(reader,reader.entry_metadata[0][0])
        pages=background_json_loads_v3(committed[0]["post_query_inventory_json"])
        rows=committed[0]["post_read_rows"]
        if (not pages or len(pages)>128 or any(set(page)!={"type_id","rows","complete"}
                or not page["complete"] or len(page["rows"])>128 for page in pages)):
            raise ValueError("D07 model seal requires its exact complete original query pages")
        keys=tuple(dict.fromkeys((job_graph_write(job).key,
            *(AtomKey.from_token(row["ref"])for row in rows),
            *(AtomKey.from_token(ref)for ref in resource_quote.d02_settlement_refs),
            AtomKey.from_token(prepared.body_state_ref),AtomKey.from_token(prepared.body_profile_ref),
            AtomKey.from_token(prepared.body_reservation_ref))))
        roots=tuple(reader.d07_source_material.witnesses)
        plan=ProductionReadPlanV1(tuple(page["type_id"]for page in pages),keys,roots,())
        if any(NamespaceId.from_key(key)!=reader.namespace for key in keys):
            raise ValueError("D07 model seal read set crossed its actual namespace")
        for page in pages:reader.store._registry.spec(page["type_id"])
        self.reader,self.prepared,self.job,self.committed=reader,prepared,job,committed
        self.plan,self.pages,self.source=plan,tuple(pages),source
        self.scope,self.source_scope,self.stamp=reader.read_scope,reader.d07_source_scope,reader.graph_stamp
        self.intent,self.permit,self.operation=intent,permit,reader.operation
        _D07_MODEL_SEAL_RECIPES_V3[self]=(reader,prepared.digest,job.job_id,committed[1],plan,self.scope,
            self.source_scope,self.source_scope.commitment,self.stamp,intent,permit,self.operation)
        prior=reader.selected_plans.get(prepared.operation_id)
        if prior is not None and prior!=plan:
            raise ValueError("D07 actual model seal changed its immutable selected read set")
        reader.selected_plans[prepared.operation_id]=plan
        reader.d07_model_seal_recipe=self
    def require_for_v3(self,reader):
        from .domain_background_read_v3 import require_actual_background_attachment_owner_v3,require_current_d07_content_source_authority_v3
        require_actual_background_attachment_owner_v3(reader,db=reader.db)
        if (_D07_MODEL_SEAL_RECIPES_V3.get(self)!=(reader,self.prepared.digest,self.job.job_id,self.committed[1],
                self.plan,self.scope,self.source_scope,self.source_scope.commitment,self.stamp,
                self.intent,self.permit,self.operation)
                or self.reader is not reader or reader.d07_model_seal_recipe is not self
                or (reader.read_scope,reader.d07_source_scope,reader.graph_stamp)!=(self.scope,self.source_scope,self.stamp)
                or reader.d07_egress_pair!=(self.intent,self.permit)
                or require_current_d07_content_source_authority_v3(reader)!=self.source):
            raise ValueError("D07 immutable model seal recipe lost its actual permit/Source scope/read set")
        return self
    def release_v3(self):
        _D07_MODEL_SEAL_RECIPES_V3.pop(self,None)

def prepare_current_d07_model_seal_source_recipe_v3(reader,prepared,job):
    from .domain_background_read_v3 import background_graph_head_v3
    from .budget import get_budget_lease,require_budget_family_admissible
    service=reader.d07_service
    committed=read_d07_original_v1(reader.db,service.d11_issuer,reader.namespace,"prepare_commit",job.job_id)
    if committed is None:raise ValueError("D07 model seal lost its exact actual preparation CAS original")
    quote=service.resource_issuer.original_signed_quote(reader.db,prepared.quote_id,prepared.quote_version)
    recipe=_D07ModelSealSourceReadRecipeV3(_D07_POST_CAS_ISSUER_V3,reader,prepared,job,committed,quote)
    require_current_d07_content_reads_v1(reader.db,prepared,issuer=service.d11_issuer)
    request=read_original_d07_request_v1(reader.db,service.d11_issuer,prepared)
    intent,permit=reader.d07_egress_pair
    if (request.digest!=intent.request_digest or request.envelope.authority!=reader.d07_model_authority
            or request.identity.operation_id!=intent.acquire_operation_id
            or request.call_id!=intent.call_id or reader.operation.deadline_utc>request.envelope.deadline_utc):
        raise ValueError("D07 actual model seal request changed its original executor/call/deadline")
    lease=get_budget_lease(reader.db,job.budget_ref)
    require_budget_family_admissible(reader.db,lease.lease_id)
    background_graph_head_v3(reader.db,reader.namespace,job_graph_write(job).key)
    service.body_authority.original_body_quote(reader.db,prepared.body_quote_ref,
        prepared.body_quote_version,quote,prepared.operation_id)
    return recipe.require_for_v3(reader)
