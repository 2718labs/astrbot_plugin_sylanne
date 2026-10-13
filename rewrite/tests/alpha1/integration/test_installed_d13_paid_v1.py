"""Installed D13 paid standby from real confirmed C02 turns and finite HTTP.

This node assembles RuntimeContext around the donor's actual installation.
It does not start the whole Host or enable a platform sender. The independent
read connection below is a cold reader, not a full process restart.
"""
import asyncio
from dataclasses import replace
from datetime import datetime
import json
from pathlib import Path
import sqlite3
import dis
import hashlib
import sys
import time

import httpx
import pytest

from test_d04_owner_semantic_initialization_v3 import installed_d04_root, real_owner_case
from sylanne3.authority_service.d13_paid_block_verifier_v1 import build_installed_d13_paid_block_verifier_v1
from sylanne3.domains.d13.provider import _block_from_graph_value
from sylanne3.graph_worker import GraphWorker
from sylanne3.graph_coordinator import AuthorityDenied, UnavailableGuard
from sylanne3.host.installed_d13_paid_driver import run_installed_d13_paid_precompression_v1
from sylanne3.host.owner_revoke_orchestration import installed_owner_revoke_orchestrator_v2
from sylanne3.host.v2_installation import V2InstallationAssembly
from sylanne3.model_broker.d13_precompression import INPUT_SCHEMA
from sylanne3.runtime.d13_paid_coordinator_v1 import recover_paid_d13_in_transaction_v1
from sylanne3.runtime.d13_paid_intent_original_v1 import read_d13_paid_call_original_v1
from sylanne3.runtime.d13_paid_product_v1 import D13PaidPreparedCallV1
from sylanne3.runtime.jobs import get_job
from sylanne3.runtime.first_ingress_v2 import ingress_ids, scene_ref_for_conversation
from sylanne3.runtime_context import RuntimeContext
from sylanne3.runtime_contracts import AuthorityContext


TEXT = "Keep this exact detail. " + "Another useful sentence. " * 7


def _paid_schedule_original_evidence(db, original):
    """Read actual installed schedule originals after execution or refusal."""
    import math
    from sylanne3.contracts import Event, Scope
    from sylanne3.runtime.d11_types import RuntimeJobValue, _strict_payload, job_value, runtime_job_key
    from sylanne3.runtime.d13_paid_product_v1 import _restore_schedule_intent
    from sylanne3.runtime.jobs import PersistentJob
    from sylanne3.runtime_contracts import canonical_digest

    ns=original.namespace;operation=original.binding.original_operation_id
    bundle=db.execute("SELECT digest,activity_id,effect_id,commit_seq,receipt_json "
        "FROM graph_bundle_operations WHERE bot=? AND persona=? AND operation_id=?",
        (*ns.as_tuple,operation)).fetchone()
    source=db.execute("SELECT payload_json,payload_digest,pending FROM graph_d13_paid_schedule_inputs_v1 "
        "WHERE bot=? AND persona=? AND job_ref=?",(*ns.as_tuple,original.binding.job_ref)).fetchone()
    worker=db.execute("SELECT request_digest,pre_graph_epoch,receipt_json FROM graph_d13_worker_attempts_v2 "
        "WHERE bot=? AND persona=? AND operation_id=?",(*ns.as_tuple,operation)).fetchone()
    assert bundle is not None and source is not None and worker is not None
    prepared=_restore_schedule_intent(source[0],source[1])
    assert type(source[2]) is int and source[2]==0
    expected_request=canonical_digest({"phase":"paid_schedule","intent":prepared.intent_digest})
    assert bundle[0]==worker[0]==expected_request
    assert bundle[1]==prepared.job.activity_id and bundle[2] is None
    assert type(bundle[3]) is int and bundle[3]>0
    assert json.loads(worker[2])=={"job_id":prepared.job.job_id}
    receipt=json.loads(bundle[4])
    assert set(receipt)=={"schema","original_digest","occurred_at_utc","pre_graph_epoch"}
    assert receipt["schema"]=="d13.paid_schedule.v2"
    assert receipt["original_digest"]==original.original_digest
    assert type(receipt["occurred_at_utc"]) is float and math.isfinite(receipt["occurred_at_utc"])
    assert type(receipt["pre_graph_epoch"]) is int and receipt["pre_graph_epoch"]==worker[1]
    assert receipt["occurred_at_utc"]<datetime.fromisoformat(
        prepared.job.deadline_utc.replace("Z","+00:00")).timestamp()
    event=db.execute("SELECT digest,epoch_reads,revisions,epoch_revision FROM graph_events "
        "WHERE bot=? AND persona=? AND session='d13-paid' AND event_id=?",
        (*ns.as_tuple,operation)).fetchone()
    assert event is not None
    actual=Event(Scope(*ns.as_tuple,"d13-paid"),operation,receipt["occurred_at_utc"],
        "d13.paid_lifecycle",{"operation_id":operation})
    assert event[0]==actual.digest
    assert json.loads(event[1])==[[*ns.as_tuple,receipt["pre_graph_epoch"]]]
    assert event[3]==receipt["pre_graph_epoch"]+1
    created=db.execute("SELECT digest,job_json FROM runtime_job_operations "
        "WHERE bot_id=? AND persona_id=? AND operation_id=? AND phase='create'",
        (*ns.as_tuple,operation)).fetchone()
    assert created is not None and created[0]==original.budget_reservation_digest
    queued=PersistentJob(**json.loads(created[1]))
    assert queued==prepared.job and canonical_digest(queued)==original.job_digest
    revisions=json.loads(event[2]);assert len(revisions)==1
    token,revision=revisions[0]
    assert token==runtime_job_key(*ns.as_tuple,queued.activity_id,queued.job_id).token
    assert type(revision) is int and revision>0
    history=db.execute("SELECT value,valid,event_bot,event_persona,event_session,event_id FROM graph_history "
        "WHERE token=? AND revision=?",(token,revision)).fetchone()
    assert history is not None and history[1]==1 and history[2:]==(*ns.as_tuple,"d13-paid",operation)
    assert _strict_payload(json.loads(history[0]),RuntimeJobValue)==job_value(queued)
    return {"schema":receipt["schema"],"schedule_time_utc":receipt["occurred_at_utc"],
        "schedule_pre_graph_epoch":receipt["pre_graph_epoch"],"event_epoch":event[3],
        "event_digest":event[0],"request_digest":expected_request,
        "schedule_input_digest":source[1],"queued_job_digest":original.job_digest,
        "queued_history_revision":revision,"bundle_commit_seq":bundle[3]}


def _paid_deadline_evidence(prepared, running):
    assert type(prepared) is D13PaidPreparedCallV1
    assert running.phase == "running" and running.lease_expires_utc is not None
    bounds = {
        "job_deadline_utc": datetime.fromisoformat(
            running.deadline_utc.replace("Z", "+00:00")).timestamp(),
        "worker_lease_expires_utc": datetime.fromisoformat(
            running.lease_expires_utc.replace("Z", "+00:00")).timestamp(),
        "binding_expires_at_utc": prepared.original.binding.expires_at_utc,
    }
    assert prepared.envelope.deadline_utc == min(bounds.values())
    return {**bounds, "request_deadline_utc": prepared.envelope.deadline_utc}


def _observe_first_egress_hold(tmp_path, prepared_calls, case):
    """Observe actual coroutine returns; never replace an egress decision."""
    from sylanne3.host.model_egress_executor import HostModelEgressExecutor
    actual = HostModelEgressExecutor.execute_once
    evidence = []

    async def observed(executor, **kwargs):
        prior_trace = sys.gettrace()
        def trace(frame, event, value):
            if frame.f_code is not actual.__code__:
                return None
            if event == "return" and dis.opname[frame.f_code.co_code[frame.f_lasti]].startswith("RETURN"):
                intent, request = kwargs["intent"], kwargs["request"]
                model = executor._adapter._admin_model
                limits = frame.f_locals.get("quote_ceiling", model.quote_ceiling)
                exceeded = {dimension: {"intent": amount, "checked_bound": limits.get(dimension, 0)}
                    for dimension, amount in intent.budget_ceiling if amount > limits.get(dimension, 0)}
                binding_checks = {
                    "request_digest": intent.request_digest == request.digest,
                    "operation": intent.operation_id == request.identity.operation_id,
                    "call": intent.call_id == request.call_id,
                    "provider": intent.provider_id == model.provider_id,
                    "model": intent.model_id == model.model_id,
                    "configuration": intent.provider_config_digest == model.provider_config_digest,
                    "output": intent.max_output_tokens == request.max_output_tokens,
                    "lease": intent.budget_lease_id == request.envelope.parent_budget_lease_ref,
                    "request_allowed": executor._adapter._request_allowed(request),
                }
                prepared = prepared_calls[-1]
                policy = executor._bundle.installation_policy
                link = lambda text: hashlib.sha256(text.encode()).hexdigest()
                evidence.append({"stage": "host.execute_once", "return_line": frame.f_lineno,
                    "reason_code": ("host_budget_ceiling" if value is None and exceeded
                                    and all(binding_checks.values()) else "downstream_hold" if value is None else "terminal"),
                    "binding_checks": binding_checks, "exceeded": exceeded,
                    "job_link": link(intent.job_id), "action_link": link(intent.operation_id),
                    "call_link": link(intent.call_id), "request_digest": intent.request_digest,
                    "grant_link": link(policy.root_grant.grant_id), "grant_version": policy.root_grant.version,
                    "lease_link": link(intent.budget_lease_id),
                    "root_grant_ceiling": dict(policy.root_grant.max_ceiling),
                    "root_lease_limits": dict(policy.root_lease.limits),
                    "d13_policy_ceiling": dict(executor._bundle.d13_paid_precompression.quote_ceiling),
                    "signed_original_ceiling": dict(prepared.original.ceiling),
                    "draft_ceiling": dict(prepared.draft.budget_ceiling),
                    "intent_ceiling": dict(intent.budget_ceiling), "checked_ceiling": dict(limits),
                    "main_reply_ceiling": dict(model.quote_ceiling),
                    "typed_request_digest": request.digest, "authority_checks": len(case["d13_authority_checks"]),
                    "terminal_returned": value is not None})
                (tmp_path / "d13-first-egress-decision.json").write_text(json.dumps(evidence, indent=2) + "\n")
            return trace
        sys.settrace(trace)
        try:
            return await actual(executor, **kwargs)
        finally:
            sys.settrace(prior_trace)
    HostModelEgressExecutor.execute_once = observed
    return actual, evidence


async def _run_installed_d13_paid_case(tmp_path, installed_d04_root, *, expired=False, admission_only=False,derived_v6=False,reclaim_after_expiry=False):
    physical = {}

    async def after_role(case):
        # Reuse the donor's actually installed four-store selection. These
        # are the production close/apply classes, with the same real journals.
        from sylanne3.authority_service.v2_scoped_erasure_store import AuthorityV2ScopedErasureStore
        from sylanne3.authority_service.v2_deletion_recovery_service import AuthorityV2DeletionPendingRecovery
        from sylanne3.authority_service.c09_graph_application_v1 import InstalledC09GraphApplicationV1
        from sylanne3.authority_service.c09_close_apply_v1 import InstalledC09CloseApplyV1

        def install():
            graph, core, server = case["graph"], case["core"], case["server"]
            control = graph._initial_offline_storage_case_v1.storage_control
            assert core._c09_storage_reader_v1 is control
            selected = control.read_verified_current_storage_v1()
            selected.require_current("business")
            graph_path = Path(case["store"]._db.execute("PRAGMA database_list").fetchone()[2]).resolve()
            assert graph_path == Path(next(member["resolved_path"] for member in selected.manifest["members"]
                                           if member["role"] == "graph"))
            fences = server._v2_fences[case["authority_namespace"]]
            bridge = server._v2_execution[case["authority_namespace"]]
            assert bridge.core is core and fences.core is core
            scoped = AuthorityV2ScopedErasureStore(core=core, fences=fences.fences,
                deletion=bridge.deletion, execution=bridge.journal, namespace=case["authority_namespace"])
            recovery = AuthorityV2DeletionPendingRecovery(core=core, fences=fences.fences,
                deletion=bridge.deletion, execution=bridge.journal,
                namespace=case["authority_namespace"], scoped_store=scoped)
            subject = "mtls:sha256:" + case["peer"].certificate_sha256
            application = InstalledC09GraphApplicationV1(control=control, core=core, scoped=scoped,
                coordinator=graph, bootstrap=case["bootstrap"], namespace=case["namespace"],
                subject=subject, credential=case["peer"])
            close = InstalledC09CloseApplyV1(control=control, service=fences, recovery=recovery,
                graph_application=application, subject=subject, credential=case["peer"])
            control.install_applied_reader_v1(close)
            physical.update(control=control, fences=fences, graph_path=graph_path, scoped=scoped)
        await asyncio.to_thread(install)

    async def after_c02(case):
        graph, store, bundle = case["graph"], case["store"], case["installed_bundle"]
        policy, grant = bundle.installation_policy, case["client_grant"]
        from sylanne3.authority_service.current_source_location_v1 import InstalledCurrentSourceLocationQualifierV1
        location = InstalledCurrentSourceLocationQualifierV1(
            fences=physical["fences"], scoped=physical["control"]._applied_reader.scoped,
            control=physical["control"], graph_db_path=physical["graph_path"],
            namespace_id=policy.namespace, installation_id=policy.installation_id)
        assert location.core is case["core"]
        assert location._fences is case["model_service"]._fences
        assert location._scoped is physical["scoped"]
        assert location._graph_db_path == case["model_service"]._graph_verifier._path
        assert location._control is case["core"]._c09_storage_reader_v1
        case["model_service"].install_current_source_location_v1(location)
        assert case["model_service"]._source_location is location
        configured = bundle.d13_paid_precompression
        assert configured is not None
        assert bundle.model_workflows.reply.purpose == "proposal"
        assert graph._GraphCoordinator__d13_paid_precompression_policy == configured
        worker = await GraphWorker.start(lambda: store, lambda _store: graph)
        runtime = RuntimeContext(tmp_path, package_root=installed_d04_root, dependencies=None)
        runtime._worker, runtime._v2_bootstrap, runtime._v2_port = worker, case["bootstrap"], case["port"]
        runtime._v2_namespace_provisioned, runtime._v2_namespace = True, case["namespace"]
        runtime._v2_model_bundle, runtime._v2_policy, runtime._v2_installation_grant = bundle, policy, grant
        installation = V2InstallationAssembly(
            policy, grant, bundle.d11_signing_key, bundle.d02_signing_key,
            lambda: case["port"], installed_d04_root, tmp_path,
            ingress_clock=bundle.ingress_clock, ingress_encoding=bundle.ingress_encoding,
            admin_bundle=bundle)
        transport = case["model_http_client"]._transport
        assert type(transport) is httpx.MockTransport
        original_handler, calls = transport.handler, []

        def finite_response(request):
            assert request.url.host == "mock.invalid"
            data = json.loads(request.content)
            inputs = []
            for message in data["messages"]:
                if message["role"] == "user":
                    try:
                        candidate = json.loads(message["content"])
                    except (TypeError, ValueError):
                        continue
                    if type(candidate) is dict and candidate.get("schema") == INPUT_SCHEMA:
                        inputs.append(candidate)
            response = original_handler(request)
            if not inputs:
                return response
            assert len(inputs) == 1 and len(calls) == 0
            calls.append(data)
            output = {"schema": "d13.extractive_model_output.v1", "turns": [
                {"sequence": turn["sequence"], "beat": "Keep this exact detail.", "details": []}
                for turn in inputs[0]["turns"]]}
            assert all("Keep this exact detail." in turn["text"] for turn in inputs[0]["turns"])
            result = response.json()
            result["choices"][0]["message"]["content"] = json.dumps(output)
            return httpx.Response(response.status_code, json=result)

        transport.handler = finite_response
        envelope = case["ingress"]
        actual_check = case["model_service"]._graph_verifier._check_d13_paid
        authority_checks = []
        case["d13_authority_checks"] = authority_checks
        def observe_check(*args, **kwargs):
            try:
                value = actual_check(*args, **kwargs)
            except Exception as exc:
                authority_checks.append({"stage": "authority.current_d13", "reason_code": type(exc).__name__,
                    "reason": str(exc)})
                raise
            authority_checks.append({"stage": "authority.current_d13", "reason_code": "current"})
            return value
        case["model_service"]._graph_verifier._check_d13_paid = observe_check

        async def confirm(ingress, c02):
            original_confirm = graph.commit_confirmed_d13_inbound_turn_v1
            refusals = []

            def record_actual_refusal(*args, **kwargs):
                try:
                    return original_confirm(*args, **kwargs)
                except Exception as exc:
                    import traceback
                    refusals.append({"type": type(exc).__name__, "message": str(exc),
                                     "traceback": traceback.format_exc()})
                    raise

            graph.commit_confirmed_d13_inbound_turn_v1 = record_actual_refusal
            try:
                turn = await runtime.commit_confirmed_d13_inbound_turn_v1(
                    ingress_operation_id=ingress_ids(ingress.lineage.source_ref)[2],
                    c02_operation_id=c02.operation_id, envelope=ingress)
            finally:
                graph.commit_confirmed_d13_inbound_turn_v1 = original_confirm
            if turn is None:
                diagnostic = {"source_ref": ingress.lineage.source_ref,
                    "ingress_operation_id": ingress_ids(ingress.lineage.source_ref)[2],
                    "c02_operation_id": c02.operation_id, "refusals": refusals,
                    "d13_http_count": len(calls)}
                (tmp_path / "d13-inbound-confirm-refusal.json").write_text(
                    json.dumps(diagnostic, indent=2) + "\n")
            assert turn is not None, refusals

        async def current_window():
            def read(_graph):
                anchor = case["port"].current_anchor(
                    namespace=policy.namespace, authority_namespace=policy.authority_namespace)
                lease, capability = graph.grant(
                    case["bootstrap"], actor=grant.subject, issuer_domain="d11",
                    namespace=policy.namespace, domains=("d11", "d13"),
                    activation_generation=anchor.activation_generation, operation_id="d13-test-current")
                authority = AuthorityContext(
                    grant.subject, "d11", capability, policy.namespace, ("persona",), "context",
                    (envelope.conversation_ref,), policy.root_grant.policy_ref, anchor.activation_generation)
                try:
                    return graph.read_current_d13_conversation_window_v1(
                        authority, lease,
                        scene_ref=scene_ref_for_conversation(
                            policy.namespace, envelope.platform_ref, envelope.conversation_ref),
                        max_slots=configured.max_slots)
                finally:
                    graph.release_authority_lease(case["bootstrap"], lease)
            return await worker.call(read)

        async def saved_state():
            def read(_graph):
                db = store._db
                db.execute("BEGIN")
                try:
                    jobs = db.execute("SELECT job_ref FROM graph_d13_paid_scene_jobs_v1 WHERE bot=? AND persona=?",
                                      policy.namespace.as_tuple).fetchall()
                    assert len(jobs) == 1
                    saved = recover_paid_d13_in_transaction_v1(db, policy.namespace, jobs[0][0])
                    schedule_evidence=_paid_schedule_original_evidence(db,saved.original)
                    (tmp_path / "d13-paid-schedule-original.json").write_text(json.dumps(schedule_evidence,indent=2)+"\n")
                    costs = db.execute("SELECT phase,digest,receipt_json FROM runtime_budget_operations "
                        "WHERE bot_id=? AND persona_id=? AND operation_id=? ORDER BY phase",
                        (*policy.namespace.as_tuple, saved.original.budget_operation_id)).fetchall()
                    if derived_v6:
                        from sylanne3.domains.d13.derived_block_metadata_v2 import decode_derived_block_metadata_v2
                        from sylanne3.runtime.d11_derived_cache_payload_v1 import read_derived_payload_v1
                        rows=db.execute("SELECT value FROM graph_atoms WHERE bot=? AND persona=? AND type_name='d13.derived_block_metadata.v2' AND valid=1",policy.namespace.as_tuple).fetchall()
                        assert len(rows)==1
                        metadata=decode_derived_block_metadata_v2(json.loads(rows[0][0]))
                        assert 'timeline' not in json.loads(rows[0][0]) and 'detail_slots' not in json.loads(rows[0][0])
                        return saved,costs,read_derived_payload_v1(db,metadata,now_utc=window.trusted_utc)
                    rows = db.execute("SELECT value FROM graph_atoms WHERE bot=? AND persona=? "
                        "AND type_name='d13.compressed_turn_block.v2' AND valid=1", policy.namespace.as_tuple).fetchall()
                    assert len(rows) == 1
                    return saved, costs, _block_from_graph_value(json.loads(rows[0][0]))
                finally:
                    db.rollback()
            return await worker.call(read)

        async def drive():
            return await run_installed_d13_paid_precompression_v1(
                runtime, installation, context=case["model_context"],
                trusted_umo=json.loads(envelope.conversation_ref)[0], envelope=envelope,
                ingress_operation_id=ingress_ids(envelope.lineage.source_ref)[2])

        try:
            await confirm(envelope, case["c02"])
            for index in range(1, 6):
                _first, c02, next_envelope = await case["commit_second_c02"](
                    "d13-paid-inbound-" + str(index), TEXT, return_envelope=True)
                await confirm(next_envelope, c02)
            window = await current_window()
            assert len(window.turns) == 6 and not window.missing_ranges
            if expired:
                await _expired_original(case, runtime, installation, worker, envelope, calls, tmp_path)
                return
            # Observe the acquired SQL job and sealed request before completion
            # clears its worker lease. The normal driver retains its actual
            # timeout-derived lease; this hook only records and checks reads.
            actual_prepare = graph.prepare_d13_paid_call_v1
            deadline_evidence = []
            prepared_calls = []

            def observe_actual_prepare(*args, **kwargs):
                prepared = actual_prepare(*args, **kwargs)
                assert type(prepared) is D13PaidPreparedCallV1
                prepared_calls.append(prepared)
                db = store._db
                db.execute("BEGIN")
                try:
                    running = get_job(db, prepared.original.binding.job_ref)
                    call, request = read_d13_paid_call_original_v1(
                        db, policy.namespace, running.job_id)
                    assert call == prepared.call_original and request.envelope == prepared.envelope
                    deadline_evidence.append(_paid_deadline_evidence(prepared, running))
                finally:
                    db.rollback()
                return prepared

            graph.prepare_d13_paid_call_v1 = observe_actual_prepare
            actual_execute, decisions = _observe_first_egress_hold(tmp_path, prepared_calls, case)
            try:
                await drive()
            finally:
                graph.prepare_d13_paid_call_v1 = actual_prepare
                from sylanne3.host.model_egress_executor import HostModelEgressExecutor
                HostModelEgressExecutor.execute_once = actual_execute
            assert len(deadline_evidence) == 1
            (tmp_path / "d13-paid-call-deadline.json").write_text(
                json.dumps(deadline_evidence[0], indent=2) + "\n")
            (tmp_path / "d13-authority-checks.json").write_text(json.dumps(authority_checks, indent=2) + "\n")
            if admission_only:
                assert len(decisions) == 1 and decisions[0]["terminal_returned"], decisions
                assert authority_checks and len(calls) == 1
                return
            saved, costs, block = await saved_state()
            assert saved.job.phase == "completed" and saved.next_action == "terminal"
            assert saved.evidence is not None and saved.settlement.receipt.status == "settled"
            assert [row[0] for row in costs] == ["reserve", "settle"]
            assert block.status == "standby" and len(calls) == 1
            reader = case["server"]._v2_worker_model_result_reads[case["authority_namespace"]]
            with reader._fences.core._tx() as db:
                assert reader._fences.fences._row(
                    db, saved.evidence.read.request.read_attempt_id)[6] == "finished"
            window = await current_window()
            candidate = replace(block, status="candidate")

            def verify(db, *, expected=True):
                db.execute("BEGIN")
                try:
                    if derived_v6:
                        from sylanne3.authority_service.d13_derived_paid_block_verifier_v2 import build_installed_d13_derived_paid_block_verifier_v2
                        verifier=build_installed_d13_derived_paid_block_verifier_v2(db,installation=configured.selected_main,
                            resource_issuer=case['d02_issuer'],budget_issuer=case['d11_issuer'],authority_store=case['model_store'],
                            namespace=policy.namespace,scene_ref=scene_ref_for_conversation(policy.namespace,envelope.platform_ref,envelope.conversation_ref),
                            conversation_ref=envelope.conversation_ref,now_utc=window.trusted_utc,activation_generation=window.activation_epoch,max_slots=256)
                    else:
                        verifier = build_installed_d13_paid_block_verifier_v1(
                            db, installation=configured.selected_main, resource_issuer=case["d02_issuer"],
                            budget_issuer=case["d11_issuer"], authority_store=case["model_store"],
                            max_slots=configured.max_slots)
                    assert verifier.verify_current_paid_model_block_v2(
                        candidate, plan=saved.frozen.plan, window=window) is expected
                finally:
                    db.rollback()

            await worker.call(lambda _graph: verify(store._db))
            def cold():
                with sqlite3.connect((tmp_path / "business.db").resolve().as_uri() + "?mode=ro", uri=True) as db:
                    db.execute("PRAGMA query_only=ON")
                    verify(db)
                    assert db.total_changes == 0
            await asyncio.to_thread(cold)
            await drive()
            replayed, replay_costs, replay_block = await saved_state()
            assert replayed == saved and replay_costs == costs and replay_block == block
            assert len(calls) == 1
            if reclaim_after_expiry:
                assert derived_v6
                from sylanne3.domains.d13.derived_block_metadata_v2 import decode_derived_block_metadata_v2
                def original_selector(_graph):
                    row=store._db.execute("SELECT token,revision,value FROM graph_atoms WHERE bot=? AND persona=? "
                        "AND type_name='d13.derived_block_metadata.v2' AND valid=1",policy.namespace.as_tuple).fetchone()
                    metadata=decode_derived_block_metadata_v2(json.loads(row[2]))
                    assert metadata.status=='standby' and metadata.expires_at_utc<=block.expires_at_utc
                    return row[0],row[1],metadata
                token,original_revision,metadata=await worker.call(original_selector)
                # Wait for the actual signed effective expiry; never replace the Authority clock.
                delay=max(0.0,metadata.expires_at_utc-time.time()+0.15)
                assert delay<=300.2
                while delay>0:
                    await asyncio.sleep(min(45.0,delay))
                    delay=max(0.0,metadata.expires_at_utc-time.time()+0.15)
                async def retire_original():
                    def invoke(_graph):
                        anchor=case['port'].current_anchor(namespace=policy.namespace,authority_namespace=policy.authority_namespace)
                        lease,capability=graph.grant(case['bootstrap'],actor=grant.subject,issuer_domain='d11',
                            namespace=policy.namespace,domains=('d11','d13'),activation_generation=anchor.activation_generation,
                            operation_id='d13-test-current-retirement')
                        authority=AuthorityContext(grant.subject,'d11',capability,policy.namespace,('persona',),'context',
                            (envelope.conversation_ref,),policy.root_grant.policy_ref,anchor.activation_generation)
                        try:
                            return graph.retire_due_d13_derived_cache_v6(authority,lease,
                                block_ref=metadata.block_ref,expected_revision=original_revision)
                        finally:
                            graph.release_authority_lease(case['bootstrap'],lease)
                    return await worker.call(invoke)
                first_retirement=await retire_original()
                # Simulate loss of the caller's acknowledgement by using the unchanged original selectors.
                recovered_retirement=await retire_original()
                assert recovered_retirement==first_retirement
                assert first_retirement['reclaim']['rows_deleted']==1
                assert first_retirement['reclaim']['payload_absent'] is True
                assert first_retirement['reclaim']['derived_cache_payload_reclaimed'] is True
                assert first_retirement['reclaim']['scope']=='named_derived_store_logical_payload_only'
                def retained_evidence(_graph):
                    db=store._db
                    db.execute('BEGIN')
                    try:
                        assert db.execute("SELECT 1 FROM graph_d11_derived_cache_payloads_v1 WHERE bot=? AND persona=? AND block_ref=?",
                            (*policy.namespace.as_tuple,metadata.block_ref)).fetchone() is None
                        row=db.execute("SELECT revision,value FROM graph_atoms WHERE token=?",(token,)).fetchone()
                        assert row[0]==original_revision+1
                        assert decode_derived_block_metadata_v2(json.loads(row[1])).status=='retired'
                        originals=db.execute("SELECT phase,digest,receipt_json FROM runtime_budget_operations "
                            "WHERE bot_id=? AND persona_id=? AND operation_id=? ORDER BY phase",
                            (*policy.namespace.as_tuple,saved.original.budget_operation_id)).fetchall()
                        assert originals==costs
                        assert recover_paid_d13_in_transaction_v1(db,policy.namespace,saved.original.binding.job_ref).original==saved.original
                        history=db.execute("SELECT value FROM graph_history WHERE token=? ORDER BY revision",(token,)).fetchall()
                        assert len(history)==2 and all('timeline' not in json.loads(value) for (value,) in history)
                    finally:
                        db.rollback()
                await worker.call(retained_evidence)
                assert len(calls)==1
                (tmp_path/'d13-v6-retirement-original.json').write_text(
                    json.dumps({'first':first_retirement,'recovered':recovered_retirement},indent=2)+'\n')
            revoked = await installed_owner_revoke_orchestrator_v2(
                graph=graph, bootstrap=case["bootstrap"], namespace=policy.namespace,
                graph_worker=worker, revoke_port=case["port"]).revoke(
                    operation_id="owner-revoke-d13-paid",
                    owner_session_token=case["owner_session_token"],
                    owner_session_request=case["owner_session_request"])
            assert revoked.phase == "committed" and revoked.operation.action == "revoke"
            await worker.call(lambda _graph: verify(store._db, expected=False))
            try:
                denied = await drive()
            except (AuthorityDenied, UnavailableGuard, ValueError):
                denied = None
            assert denied is None and len(calls) == 1
        finally:
            (tmp_path / "d13-authority-checks.json").write_text(json.dumps(authority_checks, indent=2) + "\n")
            case["model_service"]._graph_verifier._check_d13_paid = actual_check
            transport.handler = original_handler
            await worker.close()

    def v6_workflows(old,shared):
        from dataclasses import fields
        from sylanne3.host.model_workflows_v6 import AdminModelWorkflowsV6
        from sylanne3.model_broker.natural_reply_history_v6 import TEMPLATE_VERSION
        from sylanne3.runtime_contracts import NATURAL_REPLY_REVIEW_WORKFLOW_V2
        values={field.name:getattr(old,field.name,None) for field in fields(AdminModelWorkflowsV6) if field.name!='version'}
        values['natural_generation']=replace(old.reply,work_kind='natural_generation',purpose='proposal',template_version=TEMPLATE_VERSION)
        values['natural_review']=replace(old.reply,work_kind='natural_review',purpose='proposal',template_version=NATURAL_REPLY_REVIEW_WORKFLOW_V2)
        return AdminModelWorkflowsV6(6,**values)
    await real_owner_case(
        tmp_path, "owned", installed_package_root=installed_d04_root,
        natural_workflow_builder=v6_workflows if derived_v6 else None,
        enable_d13_paid_precompression=True, after_c02=after_c02,
        enable_d10_offline_ticks=True, after_role_initialization=after_role,
        continue_to_ingress=True,
        d13_paid_deadline_after_seconds=2 if expired else 300,
        extra_owner_purposes=("context", "consolidation"), ingress_text=TEXT)


async def _expired_original(case, runtime, installation, worker, envelope, calls, tmp_path):
    from sylanne3.host.astrbot_model_call import AstrBotModelProvider
    from sylanne3.host.authority_client import AuthorityClient, AuthoritySelection
    from sylanne3.host.installation_grant_identity import same_installed_grant_identity_v2
    from sylanne3.host.model_egress_executor import HostModelEgressExecutor
    from sylanne3.host.mtls_transport import MtlsAuthorityTransport
    from sylanne3.model_broker.broker import ModelProviderDescriptor

    graph, bundle = case["graph"], installation.admin_bundle
    policy, grant, model = bundle.installation_policy, installation.installation_grant, bundle.model_workflows.reply
    assert bundle.d13_paid_precompression.deadline_after_seconds == 2
    scene = scene_ref_for_conversation(policy.namespace, envelope.platform_ref, envelope.conversation_ref)

    async def graph_call(method, **kwargs):
        def invoke(_graph):
            anchor = case["port"].current_anchor(namespace=policy.namespace,
                authority_namespace=policy.authority_namespace)
            lease, capability = graph.grant(case["bootstrap"], actor=grant.subject,
                issuer_domain="d11", namespace=policy.namespace, domains=("d11", "d13"),
                activation_generation=anchor.activation_generation,
                operation_id=ingress_ids(envelope.lineage.source_ref)[2])
            authority = AuthorityContext(grant.subject, "d11", capability, policy.namespace,
                ("persona",), "context", (envelope.conversation_ref,),
                policy.root_grant.policy_ref, anchor.activation_generation)
            try:
                return getattr(graph, method)(authority, lease, **kwargs)
            finally:
                graph.release_authority_lease(case["bootstrap"], lease)
        return await worker.call(invoke)

    # Authenticate the separate installed Host channel before the short job
    # exists. Setup latency must not be disguised as a changed job deadline.
    transport = MtlsAuthorityTransport({bundle.tls_profile.profile_id: bundle.tls_profile})
    try:
        client = AuthorityClient(AuthoritySelection(bundle.tls_profile.profile_id),
            package_root=installation.package_root, data_dir=installation.data_dir, transport=transport)
        assert (await client.status_v2()).state == "paired"
        current_grant = await client.installation_grant_v2()
        assert same_installed_grant_identity_v2(grant, current_grant)
        adapter = AstrBotModelProvider(context=case["model_context"], host_loop=asyncio.get_running_loop(),
            trusted_umo=json.loads(envelope.conversation_ref)[0],
            descriptor=ModelProviderDescriptor(model.provider_id, "astrbot-openai-official-v1", model.model_id,
                frozenset({"text"}), frozenset({"context"}), frozenset({model.privacy_tier}),
                model.provider_config_ref, "unknown", False, False),
            admin_model=model, installation_bundle=bundle)
        executor = HostModelEgressExecutor(authority=client, bundle=bundle, grant=current_grant, adapter=adapter)
        saved = await graph_call("schedule_d13_paid_precompression_v1", scene_ref=scene)
        assert saved is not None and saved.job.phase == "queued"
        prepared = await graph_call("prepare_d13_paid_call_v1", job_id=saved.job.job_id,
            timeout_seconds=model.timeout_seconds, privacy_tier=model.privacy_tier, lease_seconds=30)
        assert type(prepared) is D13PaidPreparedCallV1
        deadline = datetime.fromisoformat(saved.job.deadline_utc.replace("Z", "+00:00")).timestamp()
        assert prepared.envelope.deadline_utc == deadline
        before = await graph_call("recover_d13_paid_precompression_v1", job_id=saved.job.job_id)
        assert before.call_original == prepared.call_original
        deadline_evidence = _paid_deadline_evidence(prepared, before.job)
        assert deadline_evidence["job_deadline_utc"] < deadline_evidence["worker_lease_expires_utc"]
        assert deadline_evidence["job_deadline_utc"] < deadline_evidence["binding_expires_at_utc"]

        async def paired_now():
            reading = await asyncio.to_thread(case["port"].read_ingress_clock, bundle.ingress_clock)
            # Even the lower edge of the real paired sample must be past the
            # deadline; an upper-bound-only comparison could stop too early.
            return reading.sample.utc_seconds - reading.sample.utc_error_seconds
        now = await paired_now()
        if now <= deadline:
            await asyncio.sleep(min(3.0, deadline - now + 0.05))
            now = await paired_now()
        assert now > deadline
        actual_check = case["model_service"]._graph_verifier._check_d13_paid
        refusals = []
        def diagnosed_check(*args, **kwargs):
            try:
                return actual_check(*args, **kwargs)
            except Exception as exc:
                refusals.append((type(exc).__name__, str(exc)))
                raise
        case["model_service"]._graph_verifier._check_d13_paid = diagnosed_check
        try:
            result = await executor.execute_frozen_d13_once(
                original=prepared.original, call_original=prepared.call_original,
                frozen=prepared.frozen, envelope=prepared.envelope, draft=prepared.draft,
                expected_anchor=prepared.expected_anchor)
        finally:
            case["model_service"]._graph_verifier._check_d13_paid = actual_check
        assert result is not None and result.terminal is None and calls == []
        assert result.intent.call_id == prepared.original.binding.call_id
        replay = await executor.execute_frozen_d13_once(
            original=prepared.original, call_original=prepared.call_original,
            frozen=prepared.frozen, envelope=prepared.envelope, draft=prepared.draft,
            expected_anchor=prepared.expected_anchor)
        assert replay is None and calls == []
        assert any("job is no longer current" in message for _kind, message in refusals), refusals
        after = await graph_call("recover_d13_paid_precompression_v1", job_id=saved.job.job_id)
        assert after == before
        model_store = case["model_store"]
        with model_store._lock:
            model_record = model_store._read(model_store._db, result.intent.call_id)
        assert model_record is not None and model_record.state == "prepared"
        fences = case["model_service"]._fences
        with fences.core._tx() as db:
            model_fence = fences.fences._row(db, result.intent.operation_id)
            assert model_fence[6] == "finished"
            assert model_fence[8] == result.intent.call_id
            assert model_fence[9] == fences.fences.model_terminal_finish_digest(
                result.intent, fences.fences._permit(model_fence), "not_dispatched")

        def residual(_graph):
            db = case["store"]._db
            return {
                "d13_http_calls": len(calls), "job_phase": after.job.phase,
                "schedule_original": _paid_schedule_original_evidence(db,after.original),
                "authority_prepared_call_id": result.intent.call_id,
                "authority_model_state": model_record.state,
                "authority_fence_state": model_fence[6],
                "authority_terminal_status": "not_dispatched",
                "job_deadline_utc": after.job.deadline_utc, "observed_trusted_utc": now,
                "call_deadline_bounds": deadline_evidence,
                "d13_budget_phases": [row[0] for row in db.execute(
                    "SELECT phase FROM runtime_budget_operations WHERE bot_id=? AND persona_id=? "
                    "AND operation_id=? ORDER BY phase",
                    (*policy.namespace.as_tuple, after.original.budget_operation_id)).fetchall()],
                "d13_reservation_state": db.execute(
                    "SELECT state FROM runtime_budget_reservations WHERE lease_id=? AND operation_id=?",
                    (after.job.budget_ref, after.original.budget_operation_id)).fetchone()[0],
                "actual_preceding_settlement_count": db.execute(
                    "SELECT count(*) FROM runtime_budget_operations WHERE bot_id=? AND persona_id=? "
                    "AND phase='settle' AND operation_id<>?",
                    (*policy.namespace.as_tuple, after.original.budget_operation_id)).fetchone()[0],
                "current_verifier_refusals": refusals,
            }
        evidence = await worker.call(residual)
        assert evidence["actual_preceding_settlement_count"] >= 6
        assert evidence["d13_budget_phases"] == ["reserve"]
        assert evidence["d13_reservation_state"] == "reserved"
        (tmp_path / "d13-expired-residual.json").write_text(json.dumps(evidence, indent=2))
        # All refusal/no-charge proofs above succeeded. Read the original Core
        # not_dispatched fact to retire only this unadmitted local capacity.
        current_anchor = await transport.v2_current_anchor(
            client._v2_request, client._v2_handshake, policy.authority_namespace)
        closure = await executor.reconcile_capacity_current_v1(
            expected_anchor=current_anchor, draft=prepared.draft)
        assert closure["status"] == "not_dispatched" and calls == []
        assert await worker.call(residual) == evidence
        (tmp_path / "d13-expired-capacity-original.json").write_text(json.dumps(closure, indent=2))
    finally:
        await transport.close()


@pytest.mark.asyncio
async def test_installed_d13_paid_standby_current_cold_and_no_charge_replay(tmp_path, installed_d04_root):
    await _run_installed_d13_paid_case(tmp_path, installed_d04_root)


@pytest.mark.asyncio
async def test_installed_d13_paid_expired_original_never_calls_provider(tmp_path, installed_d04_root):
    await _run_installed_d13_paid_case(tmp_path, installed_d04_root, expired=True)


@pytest.mark.asyncio
async def test_installed_d13_paid_authorized_ceiling_reaches_admission(tmp_path, installed_d04_root):
    await _run_installed_d13_paid_case(tmp_path, installed_d04_root, admission_only=True)


@pytest.mark.asyncio
async def test_installed_d13_v6_paid_derived_current_cold_and_no_charge_replay(tmp_path,installed_d04_root):
    """Actual installed producer reaches the new metadata/body store; this is not a fake paid verifier."""
    await _run_installed_d13_paid_case(tmp_path,installed_d04_root,derived_v6=True)


@pytest.mark.asyncio
async def test_installed_d13_v6_derived_expiry_reclaims_only_named_payload_and_recovers_lost_ack(tmp_path,installed_d04_root):
    await _run_installed_d13_paid_case(tmp_path,installed_d04_root,derived_v6=True,reclaim_after_expiry=True)
