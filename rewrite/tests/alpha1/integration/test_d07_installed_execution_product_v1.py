"""Installed D07 paid concern, exact result adoption and once-only recovery.

Only provider responses are controlled. The package, Owner signature, Core,
independent journals, mTLS, signed D11/Body quotes and Graph CAS are actual.
"""
from __future__ import annotations

import asyncio
from dataclasses import replace
import json
import hmac
from pathlib import Path
import sys
import time
from uuid import uuid4

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_d04_owner_semantic_initialization_v3 import (
    installed_d04_root, real_owner_case, initialize_owner_root_v3, adopt_mapping_and_clock,
)
from sylanne3.host.authority_profile import AdminModelWorkflowV2
from sylanne3.authority_service.d07_cognition_result_service_v1 import AuthorityD07CognitionResultServiceV1
from sylanne3.domains.d02 import BodyProfile, BodyState, WorkComponent
from sylanne3.domains.d02.body_quote_original import FixedBodyPolicyV1, D02BodyQuoteAuthority
from sylanne3.model_broker.d07_cognition_v1 import TEMPLATE_VERSION, OUTPUT_SCHEMA
from sylanne3.runtime.d07_current_behavior_v1 import ServeCurrentConcernRequestV1
from sylanne3.runtime.d07_execution_v1 import read_prepared_d07_execution_v1, read_d07_original_v1
from sylanne3.runtime.d07_installed_execution_v1 import InstalledD07ExecutionServiceV1
from sylanne3.runtime.domain_production_runtime_v1 import InstalledDomainOperationRuntimeV1
from sylanne3.runtime.budget import get_budget_lease
from sylanne3.runtime.jobs import get_job
from sylanne3.graph_types import AtomKey


def d07_workflows(base, shared):
    return replace(base, d07_cognition=AdminModelWorkflowV2(work_kind="d07.cognition", purpose="proposal",
        template_version=TEMPLATE_VERSION, max_output_tokens=128, quote_ceiling={"output_tokens": 128}, **shared))


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ("normal", "reflection_resolved", "terminal_unknown", "source_revoked_after_terminal"))
async def test_installed_actual_d07_concern_and_original_replay(tmp_path, installed_d04_root, mode):
    initialized = {}
    async def after_role(case):
        def initialize():
            initialize_owner_root_v3(case)
            adopt_mapping_and_clock(case)
            initialized.update(case)
        await asyncio.to_thread(initialize)

    async def after_c02(case):
        case = {**initialized, **case}
        graph, store, namespace = case["graph"], case["store"], case["namespace"]
        from sylanne3.host.v2_installation import V2InstallationAssembly
        bundle = replace(case["installed_bundle"], d02_signing_key=b"reply-issuer-key-" * 2,
            d11_signing_key=b"reply-issuer-key-" * 2, ingress_clock=case["ingress_clock"])
        assembly = V2InstallationAssembly(bundle.installation_policy, case["client_grant"], bundle.d11_signing_key,
            bundle.d02_signing_key, lambda: case["port"], installed_d04_root, tmp_path,
            ingress_clock=bundle.ingress_clock, admin_bundle=bundle)
        class Worker:
            async def call(self, call):
                return await asyncio.to_thread(call, graph)
        worker = Worker()
        graph._GraphCoordinator__body_quote_authority = D02BodyQuoteAuthority(hmac.digest(
            bundle.d02_signing_key, b"sylanne3.d02.body_quote_original.v1\0" + bundle.installation_policy.installation_id.encode(), "sha256"))
        service = InstalledD07ExecutionServiceV1(graph=graph, bootstrap=case["bootstrap"], bundle=bundle,
            installation=assembly, worker=worker, authority_client=case["authority_client"],
            client_grant=case["client_grant"], context=case["model_context"], owner_loop=asyncio.get_running_loop())
        graph._GraphCoordinator__d07_execution_service_v1 = service
        graph._GraphCoordinator__body_quote_authority = service.body_authority
        graph._GraphCoordinator__domain_production_runtime_v1 = InstalledDomainOperationRuntimeV1(graph, case["bootstrap"])
        reader = AuthorityD07CognitionResultServiceV1(store=case["model_store"], fences=case["protected"],
            graph_db_path=store._db.execute("PRAGMA database_list").fetchone()[2], d11_issuer=case["d11_issuer"],
            installation_id=bundle.installation_policy.installation_id, read_subject=case["client_grant"].subject,
            holder=bundle.installation_policy.administrator_holder, trusted_now_utc=time.time)
        case["server"].install_d07_cognition_result_reader_v1(case["authority_namespace"], reader)
        async def owner_call(call):
            def perform():
                authority, lease, _ = graph.grant_current_owner(case["bootstrap"], actor="owner-actor-reply", namespace=namespace,
                    domains=("d02", "d07", "d11", "d12"), purpose="workbench_user_action", audience="owner", activation_generation=1,
                    owner_session_token=case["owner_session_token"], owner_session_request=case["owner_session_request"])
                try:
                    return call(authority, lease)
                finally:
                    graph.release_current_owner_lease(case["bootstrap"], lease)
            return await asyncio.to_thread(perform)
        body = FixedBodyPolicyV1("d07-test-body", 1, BodyProfile("d07-test-profile", namespace, 1,
            ("cognitive",), ("d07.cognition",)), BodyState("d07-test-profile", 1, 1.0, {"cognitive": 0.0}, 0.0, 0.0),
            "d07.cognition", WorkComponent("bounded-cognition", "cognitive", 0.0625, 0.0), time.time() + 3600)
        await owner_call(lambda authority, lease: graph.register_current_fixed_body_work_policy_v1(case["bootstrap"],
            authority, lease, operation_id=str(uuid4()), policy=body))
        operation, activity = str(uuid4()), "d07-activity:" + str(uuid4())
        request = ServeCurrentConcernRequestV1("interaction", case["source_ref"])
        semantic_scope = None
        if mode == "reflection_resolved":
            from sylanne3.runtime.d07_execution_v1 import D07SemanticQuestionV1
            from sylanne3.runtime.domain_production_inputs_v1 import RegisterCurrentSemanticQuestionInputRequestV1
            from sylanne3.runtime_contracts import VersionedRef
            semantic_ref = "d07-semantic-question:" + str(uuid4())
            semantic_scope = "d07.speaker-intent:" + str(uuid4())
            source_revision = store._db.execute("SELECT revision FROM graph_atoms WHERE token=?", (case["source_ref"],)).fetchone()[0]
            semantic = D07SemanticQuestionV1(semantic_scope, "What intention does the current greeting communicate?",
                VersionedRef(case["source_ref"], source_revision), (case["source_ref"],))
            registered_question = await owner_call(lambda authority, lease: graph.register_current_domain_input_v1(authority, lease,
                producer_kind="register_semantic_question", request=RegisterCurrentSemanticQuestionInputRequestV1(semantic_ref, semantic),
                operation_id=str(uuid4()), activity_id="d07-register-question:" + str(uuid4()),
                audience_ref='["platform-1:FriendMessage:123456","conversation-1"]',
                parent_budget_lease_ref=bundle.installation_policy.root_grant.lease_id))
            assert registered_question["coverage"] == "complete", registered_question
            request = ServeCurrentConcernRequestV1("interaction", semantic_ref)
        # Prevent this acceptance from racing the production auto-wake; the
        # actual installed runner is awaited explicitly below.
        installed_wake = service.wake_committed_job_v1
        service.wake_committed_job_v1 = lambda ref: True
        outcome = await owner_call(lambda authority, lease: graph.run_current_domain_operation_v1(authority, lease,
            operation_kind="serve_concern", request=request, operation_id=operation, activity_id=activity,
            audience_ref='["platform-1:FriendMessage:123456","conversation-1"]',
            parent_budget_lease_ref=bundle.installation_policy.root_grant.lease_id))
        assert outcome["coverage"] == "deferred", (outcome, repr(getattr(graph._GraphCoordinator__domain_production_runtime_v1,
            "_last_refusal_exception_v1", None)))
        job_id = outcome["job_states"][0][0]
        prepared = read_prepared_d07_execution_v1(store._db, case["d11_issuer"], namespace, job_id)
        frozen = json.loads(prepared.frozen_json)
        if semantic_scope is not None:
            assert frozen["input"]["question_key"] == semantic_scope
            assert frozen["input"]["target_original_kind"] == "graph_head"
            assert json.loads(frozen["input"]["target_original_json"])["source_id"] == AtomKey.from_token(case["source_ref"]).owner.subject
        roots = [s["source_ref"]["ref"] for s in frozen["input"]["sources"]]
        case["model_reply_mode"]["content"] = json.dumps({"schema": OUTPUT_SCHEMA,
            "input_digest": frozen["input_digest"], "question_key": frozen["input"]["question_key"], "work_kind": "concern",
            "resolved_slots": [], "discriminating_refs": [], "predictions": [],
            "findings": [{"proposition": "The source expresses a greeting; further speaker intention is unknown",
                "source_refs": roots, "qualification": "subjective", "stance": "suspend", "subjective_conviction": 0.25,
                "evidence_status": "insufficient"}], "unknowns": ["speaker_intent"], "stop_reason": "bounded_segment_complete"})
        transport = case["model_http_client"]._transport
        original_provider_response = transport.handler
        provider_calls = [0]
        def controlled_provider_response(http_request):
            provider_calls[0] += 1
            if mode == "terminal_unknown":
                raise RuntimeError("controlled provider outcome unknown")
            return original_provider_response(http_request)
        transport.handler = controlled_provider_response
        if mode == "source_revoked_after_terminal":
            actual_account = service._account_original_cost_v1
            revoked = [False]
            async def account_and_revoke(ref):
                paid = await actual_account(ref)
                if not revoked[0]:
                    revoked[0] = True
                    from sylanne3.domains.d06.source_access_revocation import SourceAccessRevocationRequest
                    def revoke():
                        authority, lease, _ = graph.grant_current_owner(case["bootstrap"], actor="owner-actor-reply", namespace=namespace,
                            domains=("d06", "d11"), purpose="audit", audience="owner", activation_generation=1,
                            owner_session_token=case["owner_session_token"], owner_session_request=case["owner_session_request"])
                        try:
                            graph.revoke_source_access_v1(authority, lease, SourceAccessRevocationRequest(
                                AtomKey.from_token(case["source_ref"]).owner.subject, authority.actor, str(uuid4()), time.time()))
                        finally:
                            graph.release_current_owner_lease(case["bootstrap"], lease)
                    await asyncio.to_thread(revoke)
                return paid
            service._account_original_cost_v1 = account_and_revoke
        if mode == "source_revoked_after_terminal":
            with pytest.raises(Exception):
                await service.execute_current_d07_job_v1(get_job(store._db, job_id))
            assert read_d07_original_v1(store._db, case["d11_issuer"], namespace, "paid_cost", job_id)[0]["paid"]
            assert read_d07_original_v1(store._db, case["d11_issuer"], namespace, "body_cost", job_id) is not None
            assert read_d07_original_v1(store._db, case["d11_issuer"], namespace, "result", "d07-result:" + prepared.call_id) is None
            assert store._db.execute("SELECT count(*) FROM graph_atoms WHERE type_name='d07.cognitive_activity.v1' AND subject=?", (activity,)).fetchone() == (0,)
        else:
            result = await service.execute_current_d07_job_v1(get_job(store._db, job_id))
            if mode == "terminal_unknown":
                assert result["status"] == "original_terminal_unknown"
                assert get_job(store._db, job_id).phase == "running"
                assert read_d07_original_v1(store._db, case["d11_issuer"], namespace, "paid_cost", job_id) is None
                reserved = dict(get_budget_lease(store._db, bundle.installation_policy.root_grant.lease_id).reserved)
                assert reserved
                repeated_unknown = await service.execute_current_d07_job_v1(get_job(store._db, job_id))
                assert repeated_unknown["status"] == "original_terminal_unknown"
                assert dict(get_budget_lease(store._db, bundle.installation_policy.root_grant.lease_id).reserved) == reserved
            else:
                assert result["status"] == "adopted", result
                assert get_job(store._db, job_id).phase == "completed"
                assert result["interpretation_refs"]
                if semantic_scope is not None:
                    interpretations = [json.loads(store._db.execute("SELECT value FROM graph_atoms WHERE token=?", (ref,)).fetchone()[0])
                        for ref in result["interpretation_refs"]]
                    assert all(value["question_key"] == semantic_scope for value in interpretations)
                used = dict(get_budget_lease(store._db, bundle.installation_policy.root_grant.lease_id).used)
                repeated = await service.execute_current_d07_job_v1(get_job(store._db, job_id))
                assert repeated == result
                assert dict(get_budget_lease(store._db, bundle.installation_policy.root_grant.lease_id).used) == used
                # The next segment is actually produced by that adopted
                # cognition; an explicit wait must close its self-trigger.
                reflection_ref = result["reflection_request_ref"]
                assert reflection_ref
                reflection_operation, reflection_activity = str(uuid4()), "d07-reflection-activity:" + str(uuid4())
                reflected = await owner_call(lambda authority, lease: graph.run_current_domain_operation_v1(authority, lease,
                    operation_kind="serve_concern", request=ServeCurrentConcernRequestV1("interaction", reflection_ref),
                    operation_id=reflection_operation, activity_id=reflection_activity,
                    audience_ref='["platform-1:FriendMessage:123456","conversation-1"]',
                    parent_budget_lease_ref=bundle.installation_policy.root_grant.lease_id))
                assert reflected["coverage"] == "deferred", (reflected, repr(graph._GraphCoordinator__domain_production_runtime_v1._last_refusal_exception_v1))
                reflection_job = reflected["job_states"][0][0]
                reflection_prepared = read_prepared_d07_execution_v1(store._db, case["d11_issuer"], namespace, reflection_job)
                reflection_frozen = json.loads(reflection_prepared.frozen_json)
                assert reflection_frozen["input"]["work_kind"] == "reflection"
                progress = mode == "reflection_resolved"
                case["model_reply_mode"]["content"] = json.dumps({"schema": OUTPUT_SCHEMA,
                    "input_digest": reflection_frozen["input_digest"], "question_key": reflection_frozen["input"]["question_key"],
                    "work_kind": "reflection", "resolved_slots": ["speaker_intent"] if progress else [],
                    "discriminating_refs": roots if progress else [], "predictions": [],
                    "findings": [], "unknowns": [] if progress else ["speaker_intent"],
                    "stop_reason": "bounded_segment_complete" if progress else "wait_for_new_information"})
                reflection_result = await service.execute_current_d07_job_v1(get_job(store._db, reflection_job))
                assert reflection_result["status"] == "adopted", reflection_result
                original_reflection = read_d07_original_v1(store._db, case["d11_issuer"], namespace, "reflection_request", reflection_ref)[0]
                checkpoint = json.loads(store._db.execute("SELECT value FROM graph_atoms WHERE token=?", (original_reflection["reflection_ref"],)).fetchone()[0])
                assert checkpoint["status"] == ("complete" if progress else "waiting_for_new_trigger")
                assert checkpoint["no_progress_count"] == (0 if progress else 1) and checkpoint["meta_depth"] == original_reflection["causal_depth"]
                assert checkpoint["discriminating_refs"] == (roots if progress else [])
                assert checkpoint["unresolved_slots"] == ([] if progress else ["speaker_intent"])
                reflected_activity = json.loads(store._db.execute("SELECT value FROM graph_atoms WHERE type_name='d07.cognitive_activity.v1' AND subject=?",
                    (reflection_activity,)).fetchone()[0])
                assert reflected_activity["stop_reason"] == ("complete" if progress else "wait_for_new_information")
                assert reflection_result["reflection_request_ref"] is None
                assert await service.execute_current_d07_job_v1(get_job(store._db, reflection_job)) == reflection_result
                held_again = await owner_call(lambda authority, lease: graph.run_current_domain_operation_v1(authority, lease,
                    operation_kind="serve_concern", request=ServeCurrentConcernRequestV1("interaction", reflection_ref),
                    operation_id=str(uuid4()), activity_id="d07-no-self-requeue:" + str(uuid4()),
                    audience_ref='["platform-1:FriendMessage:123456","conversation-1"]',
                    parent_budget_lease_ref=bundle.installation_policy.root_grant.lease_id))
                assert held_again["coverage"] == "waiting_for_original"
                assert store._db.execute("SELECT count(*) FROM runtime_jobs WHERE work_kind IN ('d07.concern','d07.reflection','d07.simulation')").fetchone() == (2,)

                # Simulation has its own actual bounded child, signed Owner
                # intent, original provider predictions, and release receipt.
                from sylanne3.domains.d07 import SimulationRequest
                from sylanne3.runtime.d07_current_behavior_v1 import RunCurrentSimulationRequestV1
                from sylanne3.runtime.domain_production_inputs_v1 import RegisterCurrentSimulationInputRequestV1
                child = await owner_call(lambda authority, lease: graph.allocate_current_d07_cognition_budget_v1(authority, lease,
                    operation_id=str(uuid4()), parent_budget_lease_ref=bundle.installation_policy.root_grant.lease_id,
                    ceiling={"output_tokens": 128}))
                child_ref = child["lease_id"]
                simulation_ref, simulation_activity = "d07-simulation-request:" + str(uuid4()), "d07-simulation-activity:" + str(uuid4())
                simulation = SimulationRequest(simulation_activity, tuple(roots), "Continue the present conversation",
                    ("Ask one clarifying question", "Wait for the speaker"), (), ("speaker_intent",))
                registered = await owner_call(lambda authority, lease: graph.register_current_domain_input_v1(authority, lease,
                    producer_kind="register_simulation", request=RegisterCurrentSimulationInputRequestV1(simulation_ref, simulation),
                    operation_id=str(uuid4()), activity_id=simulation_activity,
                    audience_ref='["platform-1:FriendMessage:123456","conversation-1"]', parent_budget_lease_ref=child_ref))
                assert registered["coverage"] == "complete", (registered, repr(graph._GraphCoordinator__domain_production_runtime_v1._last_refusal_exception_v1))
                simulated = await owner_call(lambda authority, lease: graph.run_current_domain_operation_v1(authority, lease,
                    operation_kind="run_simulation", request=RunCurrentSimulationRequestV1(simulation_ref, case["source_ref"]),
                    operation_id=str(uuid4()), activity_id=simulation_activity,
                    audience_ref='["platform-1:FriendMessage:123456","conversation-1"]', parent_budget_lease_ref=child_ref))
                assert simulated["coverage"] == "deferred", (simulated, repr(graph._GraphCoordinator__domain_production_runtime_v1._last_refusal_exception_v1))
                simulation_job = simulated["job_states"][0][0]
                simulation_prepared = read_prepared_d07_execution_v1(store._db, case["d11_issuer"], namespace, simulation_job)
                simulation_frozen = json.loads(simulation_prepared.frozen_json)
                case["model_reply_mode"]["content"] = json.dumps({"schema": OUTPUT_SCHEMA,
                    "input_digest": simulation_frozen["input_digest"], "question_key": simulation_frozen["input"]["question_key"],
                    "work_kind": "simulation", "resolved_slots": [], "discriminating_refs": [],
                    "predictions": [["The conversation could continue"], ["The speaker could clarify", "The next response could be more specific"],
                        ["No new evidence might arrive"]], "findings": [], "unknowns": ["speaker_intent"],
                    "stop_reason": "bounded_segment_complete"})
                service.wake_committed_job_v1 = installed_wake
                assert installed_wake(simulation_job)
                await asyncio.sleep(0)
                assert service._runner_task is not None
                await asyncio.wait_for(asyncio.shield(service._runner_task), timeout=30)
                simulation_result = await service.execute_current_d07_job_v1(get_job(store._db, simulation_job))
                assert simulation_result["status"] == "adopted", simulation_result
                assert simulation_result["interpretation_refs"] == []
                branches = [json.loads(v[0]) for v in store._db.execute("SELECT value FROM graph_atoms WHERE type_name='d07.simulation_branch.v1' AND subject=?",
                    (simulation_activity,)).fetchall()]
                assert len(branches) == 3 and all(len(b["prediction_steps"]) <= 2 for b in branches)
                assert all(b["content_reality"] == "simulated" and b["evidence_eligibility"] == "none" for b in branches)
                assert get_budget_lease(store._db, child_ref).state == "closed"
                assert read_d07_original_v1(store._db, case["d11_issuer"], namespace, "budget_closed", child_ref) is not None
                assert await service.execute_current_d07_job_v1(get_job(store._db, simulation_job)) == simulation_result
        assert store._db.execute("SELECT count(*) FROM graph_d07_execution_originals_v1 WHERE kind='call'").fetchone() == ((3 if mode in {"normal", "reflection_resolved"} else 1),)
        assert provider_calls[0] == (3 if mode in {"normal", "reflection_resolved"} else 1)
        assert store._db.execute("SELECT count(*) FROM graph_d07_stage_attempts_v1 WHERE job_id=? AND phase='acquire'", (job_id,)).fetchone() == (1,)
        from sylanne3.runtime.c09_d07_execution_v1 import (
            COLUMNS, TABLE, STAGE_COLUMNS, STAGE_TABLE, ACCOUNTING_COLUMNS, ACCOUNTING_TABLE,
            read_d07_inventory_row_v1, validate_d07_schema_v1, validate_d07_stage_attempt_row_v1,
            validate_d07_accounting_attempt_row_v1,
            TIMING_TABLE, TIMING_COLUMNS, validate_d07_timing_row_v1,
        )
        assert validate_d07_schema_v1(store._db)
        for row in store._db.execute(f"SELECT {','.join(COLUMNS)} FROM {TABLE}").fetchall():
            read_d07_inventory_row_v1(COLUMNS, row, authority_namespace=case["authority_namespace"], issuer=case["d11_issuer"])
        for row in store._db.execute(f"SELECT {','.join(STAGE_COLUMNS)} FROM {STAGE_TABLE}").fetchall():
            validate_d07_stage_attempt_row_v1(STAGE_COLUMNS, row)
        for row in store._db.execute(f"SELECT {','.join(ACCOUNTING_COLUMNS)} FROM {ACCOUNTING_TABLE}").fetchall():
            validate_d07_accounting_attempt_row_v1(ACCOUNTING_COLUMNS, row)
        timing_rows = case["model_store"]._db.execute(f"SELECT {','.join(TIMING_COLUMNS)} FROM {TIMING_TABLE}").fetchall()
        assert len(timing_rows) == (3 if mode in {"normal", "reflection_resolved"} else 1)
        for row in timing_rows:
            validate_d07_timing_row_v1(TIMING_COLUMNS, row)
            assert (row[5] is None) == (mode == "terminal_unknown")
    await real_owner_case(tmp_path, "owned", natural_workflow_builder=d07_workflows, installed_package_root=installed_d04_root,
        after_role_initialization=after_role, continue_to_ingress=True, after_c02=after_c02, enable_d09_workbench=True,
        enable_d04_root_cpu=True, extra_owner_capabilities=("d02.body_policy.install", "workbench.correct"), extra_owner_purposes=("audit", "context"))
