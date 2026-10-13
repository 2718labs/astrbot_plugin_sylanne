"""Permanent installed M1 orchestration with an explicitly simulated provider.

Root runs this only against a newly frozen installed package and preserves the
first failure. Source compilation is not this suite's acceptance. The real
paired Owner, Source, budget, C09 and D11 producers supply every original.
"""
from __future__ import annotations

import asyncio
from dataclasses import replace
import json
from pathlib import Path
import sys
from uuid import uuid4

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_d04_owner_semantic_initialization_v3 import installed_d04_root
from m1_artifact_draft_acceptance_support_v1 import (
    adopt_m1_explicit_owner_project_role_v1, assert_original_file_witness_v1,
    cold_originals_v1, run_installed_m1_case_v1,
)
from sylanne3.model_broker.artifact_draft_v1 import OUTPUT_SCHEMA, artifact_draft_model_ids_v1
from sylanne3.model_broker.provider_billing_receipt_v1 import provider_billing_receipt_from_json_v1
from sylanne3.runtime.d11_artifact_draft_model_v1 import (
    decode_artifact_draft_original_v1, execute_prepared_artifact_draft_model_v1, read_artifact_draft_frozen_v1,
    read_artifact_draft_prepared_v1,
)
from sylanne3.runtime.d11_artifact_draft_content_v1 import (
    ArtifactDraftContentAdoptionV1, artifact_draft_content_from_wire_v1,
)
from sylanne3.runtime.d11_life_preparation_v1 import _read
from sylanne3.runtime.jobs import get_job
from sylanne3.runtime_contracts import canonical_digest


async def _operation(case, kind):
    graph = case["graph"]
    bundle = graph._GraphCoordinator__d04_installed_joint_assembly.admin_bundle
    result = await asyncio.to_thread(graph.run_current_post_c02_artifact_draft_operation_v1,
        case["bootstrap"], bundle, c02_operation_id=case["c02"].operation_id,
        source_ref=case["source_ref"], operation_kind=kind)
    if kind == "wake_artifact_draft_cycle_v1":
        assert result["wake"]["receipt"]["status"] == result["acquisition"]["receipt"]["status"] == "committed"
    else:
        assert result["receipt"]["status"] == "committed", result
    return result


async def _resume(case):
    graph = case["graph"]
    bundle = graph._GraphCoordinator__d04_installed_joint_assembly.admin_bundle
    return await asyncio.to_thread(graph.read_current_post_c02_artifact_draft_resume_v1,
        case["bootstrap"], bundle, c02_operation_id=case["c02"].operation_id, source_ref=case["source_ref"])


async def _prepared_model(case):
    prepared_receipt = await _operation(case, "prepare_artifact_draft_model")
    await _operation(case, "acquire_artifact_draft_model")
    resume = await _resume(case)
    with cold_originals_v1(case) as db:
        prepared = read_artifact_draft_prepared_v1(db, namespace=case["namespace"],
            issuer=case["d11_issuer"], selector=resume["selector"])
        assert prepared is not None and prepared_receipt["operation_id"] == prepared.operation_id
        frozen = read_artifact_draft_frozen_v1(db, prepared=prepared, issuer=case["d11_issuer"])
        job = get_job(db, prepared.job_id)
        assert job.phase == "running" and job.fence == 1 and not job.cancel_epoch
    case["model_reply_mode"]["content"] = json.dumps({"schema": OUTPUT_SCHEMA,
        "input_digest": frozen.digest, "draft_text": "这是隔离测试中的一份本地文字草稿。",
        "source_refs": [source.ref for source in frozen.sources], "needs_clarification": False, "gaps": []}, ensure_ascii=False)
    return prepared


def _owner_control_session(case):
    from sylanne3.workbench_api.service import AuthenticatedSession
    scope = "/".join(case["namespace"].as_tuple)
    return AuthenticatedSession("owner-actor-reply", "m1-owner-reply-control",
        {scope: frozenset({"workbench.create", "workbench.read"})},
        {scope: frozenset({"owner"})}, {scope: frozenset({"workbench_user_action", "workbench_view"})},
        owner_session_token=case["owner_console_session_token"],
        owner_session_request=case["owner_console_session_request"])


async def _submit_actual_stop(case, selector):
    from sylanne3.host.owner_stop_reply_port_v1 import InstalledOwnerStopReplyPortV1
    from sylanne3.authority_service.owner_stop_reply_v1 import OwnerStopReplyRequestV1
    bundle = case["graph"]._GraphCoordinator__d04_installed_joint_assembly.admin_bundle
    port = InstalledOwnerStopReplyPortV1(client=case["authority_client"], bundle=bundle, grant=case["client_grant"])
    request = OwnerStopReplyRequestV1(case["namespace"], case["policy"].installation_id,
        str(uuid4()), selector.cycle_job_ref, selector.c02_operation_id, 0)
    original = await port.submit_owner_stop_reply_v1(session=_owner_control_session(case), request=request)
    assert original.result.object_ref == selector.cycle_job_ref
    assert original.result.control == "stop_reply_v1" and not original.result.cancellation_confirmed
    return original


def _submit_actual_stop_on_independent_authority_thread(case, selector):
    """The single RPC worker cannot interleave two RPCs inside an observation.

    This one race invokes the installed authenticated producer directly on an
    independent fixture thread; Model prepare still crosses actual Host mTLS.
    Owner session, selected C09 Graph and final Core/journal checks remain real.
    """
    from sylanne3.authority_service.owner_stop_reply_v1 import OwnerStopReplyRequestV1
    session = _owner_control_session(case)
    request = OwnerStopReplyRequestV1(case["namespace"], case["policy"].installation_id,
        str(uuid4()), selector.cycle_job_ref, selector.c02_operation_id, 0)
    return case["m1_stop_service"].submit_owner_stop_reply_v1(credential=case["peer"],
        subject=case["client_grant"].subject, request=request, actor=session.actor_id,
        session_token=session.owner_session_token, session_request=session.owner_session_request)


@pytest.mark.asyncio
async def test_installed_m1_actual_c4_billing_content_and_draft_pipeline(tmp_path, installed_d04_root):
    async def after_c02(case):
        from sylanne3.model_broker.natural_reply_history_v4 import TEMPLATE_VERSION_V5
        from sylanne3.model_broker.natural_review import REVIEW_TEMPLATE_VERSION_V2
        bundle = case["graph"]._GraphCoordinator__d04_installed_joint_assembly.admin_bundle
        workflows = bundle.model_workflows
        assert workflows is case["m1_initial_configuration"].workflows
        assert workflows.natural_generation.template_version == TEMPLATE_VERSION_V5
        assert workflows.natural_review.template_version == REVIEW_TEMPLATE_VERSION_V2
        assert (bundle.foreground.max_calls, bundle.foreground.max_auxiliary_calls,
                bundle.foreground.selected_steps) == (6, 2, 1)
        assert workflows.d07_cognition is None
        prepared = await _prepared_model(case)
        mock = case["model_http_client"]._transport
        actual_handler = mock.handler
        calls = []

        def count_actual_c4(request):
            metadata = json.loads(request.content)["metadata"]
            if metadata["sylanne_call_id"] == prepared.call_id:
                calls.append(metadata["sylanne_request_digest"])
            return actual_handler(request)

        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(mock, "handler", count_actual_c4)
            executed = await execute_prepared_artifact_draft_model_v1(case["m1_model_runtime"], job_id=prepared.job_id)
        assert executed["status"] == "actual_terminal_and_cost_recorded", executed
        assert len(calls) == 1
        ids = artifact_draft_model_ids_v1(prepared.selector)
        with cold_originals_v1(case) as db:
            paid = _read(db, issuer=case["d11_issuer"], namespace=case["namespace"], kind="c4_paid", ref=ids["paid"])
            result = _read(db, issuer=case["d11_issuer"], namespace=case["namespace"], kind="c4_result", ref=ids["result"])
            assert paid is not None and result is not None
        # Read the actual paired saved observation, not a test-produced fee DTO.
        runtime = case["m1_model_runtime"]
        paired_result = decode_artifact_draft_original_v1("c4_result", result[0])
        paired_paid = decode_artifact_draft_original_v1("c4_paid", paid[0])
        billing = provider_billing_receipt_from_json_v1(paired_result.observation.billing_receipt_json)
        assert billing.evidence_kind == "fixture_simulated_charge" and billing.final_charged_amount == 7
        assert billing.call_id == prepared.call_id and billing.request_digest == calls[0]
        assert dict(paired_result.observation.cost)["model_microusd"] == 7
        with cold_originals_v1(case) as db:
            state, actual_json = db.execute("SELECT state,actual_json FROM runtime_budget_reservations "
                "WHERE lease_id=? AND operation_id=?", (prepared.parent_budget_lease_ref, prepared.operation_id)).fetchone()
            assert state == "settled" and json.loads(actual_json)["model_microusd"] == 7
            assert paired_paid.status == "committed" and paired_paid.call_id == prepared.call_id
            assert db.execute("SELECT count(*) FROM runtime_budget_operations WHERE lease_id=? "
                "AND operation_id=? AND phase='settle'", (prepared.parent_budget_lease_ref, prepared.operation_id)).fetchone() == (1,)
        await _operation(case, "wake_artifact_draft_cycle_v1")
        graph = case["graph"]
        bundle = graph._GraphCoordinator__d04_installed_joint_assembly.admin_bundle
        adopted = await _operation(case, "adopt_artifact_draft_content")
        with cold_originals_v1(case) as db:
            raw, producer = _read(db, issuer=case["d11_issuer"], namespace=case["namespace"], kind="c4_adopted", ref=ids["adopt"])
            content = artifact_draft_content_from_wire_v1(raw, ArtifactDraftContentAdoptionV1)
            assert producer == adopted["operation_id"] == content.adoption_operation_id
            assert content.prepared_digest == prepared.digest
            source = json.loads(db.execute("SELECT value FROM graph_atoms WHERE token=? AND valid=1",
                (content.content.content.ref,)).fetchone()[0])
            assert source["source_kind"] == "authored" and source["assertion_status"] == "unknown"
            assert canonical_digest(source) == content.content.content.digest
            assert get_job(db, prepared.job_id).phase == "completed"
        case.update(m1_content_adoption=content, m1_content_receipt=adopted)
        await _operation(case, "compose_artifact_goal_plan")
        await _operation(case, "create_artifact_project")
        await asyncio.to_thread(adopt_m1_explicit_owner_project_role_v1, case)
        await _operation(case, "initialize_project_checkpoint")
        action = await _operation(case, "propose_artifact_draft_action")
        body = await _operation(case, "prepare_artifact_draft_body")
        plan = await _operation(case, "input:register_artifact_draft_plan_v3")
        preparation = await _operation(case, "prepare_life")
        assert len({action["operation_id"], body["operation_id"], plan["operation_id"], preparation["operation_id"]}) == 4
        from sylanne3.runtime.d11_life_preparation_v1 import read_prepared_life_by_ref_v1
        from sylanne3.runtime.d11_life_contract_v1 import D11DraftExecutionBindingV1
        from sylanne3.runtime.d11_life_preparation_v1 import TABLE
        with cold_originals_v1(case) as db:
            refs = db.execute("SELECT original_ref FROM " + TABLE + " WHERE bot=? AND persona=? "
                "AND kind='prepared' AND producing_operation_id=?", (*case["namespace"].as_tuple, preparation["operation_id"])).fetchall()
            assert len(refs) == 1
            file_prepared = read_prepared_life_by_ref_v1(db, namespace=case["namespace"],
                prepared_original_ref=refs[0][0], issuer=case["d11_issuer"])
            assert type(file_prepared.binding) is D11DraftExecutionBindingV1
            assert file_prepared.plan.content == content.content and file_prepared.plan.target == content.target
        from sylanne3.host.d11_life_port_v1 import InstalledD11LifePortV1
        from sylanne3.host.v2_fence_port import V2FenceOutcomeUnknown
        port = InstalledD11LifePortV1(case["port"])
        actual_execute = port.execute_d11_life_v1
        lost_ack = []

        def execute_then_lose_ack(*, binding):
            result = actual_execute(binding=binding)
            lost_ack.append((result[0].claim_digest, result[1].terminal_digest))
            raise V2FenceOutcomeUnknown("actual draft terminal committed; returned ACK lost")

        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(port, "execute_d11_life_v1", execute_then_lose_ack)
            with pytest.raises(V2FenceOutcomeUnknown, match="actual draft terminal committed"):
                await asyncio.to_thread(port.execute_d11_life_v1, binding=file_prepared.binding)
        cold_port = InstalledD11LifePortV1(case["port"])
        claim, terminal = await asyncio.to_thread(cold_port.read_d11_life_original_v1, binding=file_prepared.binding)
        assert lost_ack == [(claim.claim_digest, terminal.terminal_digest)]
        path, actual_bytes = assert_original_file_witness_v1(case["m1_export_root"], file_prepared, terminal)
        assert claim.binding == terminal.binding == file_prepared.binding
        assert actual_bytes.decode("utf-8") == source["text"]
        assert path.name == content.target.filename
        first_stat = path.stat()
        from sylanne3.runtime_contracts import NamespaceId
        from sylanne3.graph_coordinator import namespace_ref
        from sylanne3.runtime.d11_life_contract_v1 import draft_artifact_ref_v1
        foreign = NamespaceId(case["namespace"].bot_id, case["namespace"].persona_id + ":foreign")
        foreign_binding = replace(file_prepared.binding, namespace=foreign,
            authority_namespace=namespace_ref(foreign), artifact_ref=draft_artifact_ref_v1(foreign, file_prepared.binding.effect_id))
        with pytest.raises(Exception):
            await asyncio.to_thread(cold_port.execute_d11_life_v1, binding=foreign_binding)
        assert await asyncio.to_thread(cold_port.read_d11_life_original_v1,
            binding=file_prepared.binding) == (claim, terminal)
        # Same effect returns its original terminal; it cannot execute a second file write.
        repeated = await asyncio.to_thread(port.execute_d11_life_v1, binding=file_prepared.binding)
        assert repeated == (claim, terminal)
        repeated_stat = path.stat()
        assert path.read_bytes() == actual_bytes and repeated_stat.st_ino == terminal.payload.readback.file_identity.file_id
        assert (repeated_stat.st_mtime_ns, repeated_stat.st_ctime_ns) == (first_stat.st_mtime_ns, first_stat.st_ctime_ns)
        from sylanne3.runtime.d11_life_adoption_v1 import adopt_current_life_v1
        adopted_file = await asyncio.to_thread(adopt_current_life_v1, graph, case["bootstrap"],
            namespace=case["namespace"], prepared_original_ref=file_prepared.binding.prepared_original_ref)
        assert adopted_file["status"] == "completed" and adopted_file["actual_cpu_ms"] == terminal.actual_cpu_ms
        case.update(m1_file_prepared=file_prepared, m1_file_terminal=terminal, m1_file_adoption=adopted_file)
        await _operation(case, "input:register_life_outcome_v2")
        progress = await _operation(case, "advance_life")
        checkpoint = await _operation(case, "settle_project_checkpoint")
        goal = await _operation(case, "settle_personal_goal")
        assert len({progress["operation_id"], checkpoint["operation_id"], goal["operation_id"]}) == 3
        from sylanne3.runtime.d08_personal_plan_v1 import artifact_goal_plan_keys_v1
        from sylanne3.model_broker.artifact_draft_v1 import artifact_draft_file_ids_v1
        from sylanne3.graph_types import AtomKey, Owner
        from sylanne3.domains.d08.personal_plan_v1 import decode_personal_plan_type_v1, PLAN_TYPE
        from sylanne3.runtime.d10_project_checkpoint_v1 import CHECKPOINT_TYPE
        file_ids = artifact_draft_file_ids_v1(case["namespace"], c02_operation_id=case["c02"].operation_id,
            root_registration_ref=content.selector.root_registration_ref)
        keys = artifact_goal_plan_keys_v1(case["namespace"], c02_operation_id=case["c02"].operation_id,
            root_registration_ref=content.selector.root_registration_ref)
        progress_ref = AtomKey(Owner("activity", *case["namespace"].as_tuple, file_ids["activity_id"]),
            "d10.life_progress.v1", file_ids["effect"]).token
        with cold_originals_v1(case) as db:
            goal_value = json.loads(db.execute("SELECT value FROM graph_atoms WHERE token=? AND valid=1", (keys[0].token,)).fetchone()[0])
            plan_value = json.loads(db.execute("SELECT value FROM graph_atoms WHERE token=? AND valid=1", (keys[1].token,)).fetchone()[0])
            checkpoints = db.execute("SELECT value FROM graph_atoms WHERE bot=? AND persona=? AND type_name=? AND valid=1",
                (*case["namespace"].as_tuple, CHECKPOINT_TYPE)).fetchall()
            assert goal_value["state"] == "satisfied" and goal_value["progress_refs"] == [progress_ref]
            assert decode_personal_plan_type_v1(PLAN_TYPE, plan_value).state == "satisfied"
            assert len(checkpoints) == 1
            current_checkpoint = json.loads(checkpoints[0][0])
            assert current_checkpoint["state"] == "completed" and current_checkpoint["next_step"] is None
            assert current_checkpoint["progress_refs"] == [progress_ref]
            assert current_checkpoint["completed_node_refs"] == [file_ids["node"]]
            assert len(current_checkpoint["work_version_refs"]) == 1
        # A completed same-effect check cannot produce a second expense/write.
        assert await asyncio.to_thread(port.execute_d11_life_v1, binding=file_prepared.binding) == (claim, terminal)
        assert path.read_bytes() == actual_bytes
        # Accepted Stop blocks new work; actual started terminal/accounting
        # originals still converge after an independent paired metadata query.
        stopped = await _submit_actual_stop(case, prepared.selector)
        fact_before = runtime.read_cached_cost_fact_v1(prepared.job_id)
        queried = await runtime.authority_client.model_terminal_fact_v2(runtime.bundle, runtime.client_grant,
            intent=fact_before.intent)
        from sylanne3.runtime.model_cost_settlement import read_original_model_cost
        actual_fact = read_original_model_cost(lambda original_intent: queried, fact_before.intent)
        assert actual_fact == fact_before
        recovered_cost = await runtime.worker.call(lambda current_graph:
            current_graph.reconcile_current_artifact_draft_model_cost_v1(runtime.bootstrap, runtime.bundle, prepared=prepared))
        assert recovered_cost == paired_paid
        assert await asyncio.to_thread(cold_port.read_d11_life_original_v1,
            binding=file_prepared.binding) == (claim, terminal)
        assert stopped.result.object_ref == prepared.selector.cycle_job_ref
        with cold_originals_v1(case) as db:
            assert db.execute("SELECT count(*) FROM runtime_budget_operations WHERE lease_id=? "
                "AND operation_id=? AND phase='settle'", (prepared.parent_budget_lease_ref, prepared.operation_id)).fetchone() == (1,)

    await run_installed_m1_case_v1(tmp_path, installed_d04_root, after_c02=after_c02)


@pytest.mark.asyncio
async def test_installed_m1_stop_between_actual_observation_and_final_core(tmp_path, installed_d04_root):
    async def after_c02(case):
        prepared = await _prepared_model(case)
        runtime = case["m1_model_runtime"]
        _, _, draft, anchor, sealed = await runtime.worker.call(
            lambda graph: runtime._read_dispatch_v1(graph, prepared.job_id))
        assert sealed is None
        verifier = case["model_service"]._graph_verifier
        original_observe = verifier.observe_current_reply_scope_for_model_v1
        original_barrier = case["model_service"]._require_reply_scope_in_tx_v1
        loop = asyncio.get_running_loop()
        accepted = []
        final_denials = []

        def observe_then_accept_stop(intent):
            actual_scope = original_observe(intent)
            assert actual_scope is not None and actual_scope.service is case["m1_stop_service"]
            future = asyncio.run_coroutine_threadsafe(asyncio.to_thread(
                _submit_actual_stop_on_independent_authority_thread, case, prepared.selector), loop)
            accepted.append(future.result(timeout=30))
            return actual_scope

        def capture_actual_final_barrier(db, scope, current, *, action):
            from sylanne3.authority_service.contract import AuthorityUnavailable
            try:
                return original_barrier(db, scope, current, action=action)
            except AuthorityUnavailable as error:
                if action == "model_prepare":
                    final_denials.append(str(error))
                raise

        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(verifier, "observe_current_reply_scope_for_model_v1", observe_then_accept_stop)
            patch.setattr(case["model_service"], "_require_reply_scope_in_tx_v1", capture_actual_final_barrier)
            with pytest.raises(Exception):
                await case["authority_client"].model_prepare_fenced_v1(runtime.bundle, runtime.client_grant,
                    draft=draft, expected_anchor=anchor)
        assert len(accepted) == 1
        assert final_denials == ["Owner StopReply is durably accepted; new reply-scope work is denied"]
        with case["model_store"]._lock:
            assert case["model_store"]._read(case["model_store"]._db, prepared.call_id) is None
        with cold_originals_v1(case) as db:
            assert _read(db, issuer=case["d11_issuer"], namespace=case["namespace"], kind="c4_call", ref=prepared.call_id) is None
        assert not (case["m1_export_root"] / "m1-draft.txt").exists()

    await run_installed_m1_case_v1(tmp_path, installed_d04_root, after_c02=after_c02)


@pytest.mark.asyncio
async def test_installed_m1_invalid_billing_keeps_unknown_money_and_no_authored_adoption(tmp_path, installed_d04_root):
    async def after_c02(case):
        import httpx
        from sylanne3.model_broker.provider_billing_receipt_v1 import EXTENSION_KEY
        prepared = await _prepared_model(case)
        mock = case["model_http_client"]._transport
        actual_handler = mock.handler
        rejected_receipts = []

        def actual_provider_with_invalid_signature(request):
            response = actual_handler(request)
            metadata = json.loads(request.content)["metadata"]
            if metadata["sylanne_call_id"] != prepared.call_id:
                return response
            body = response.json()
            assert body[EXTENSION_KEY]["evidence_kind"] == "fixture_simulated_charge"
            body[EXTENSION_KEY]["signature_hex"] = "0" * 128
            rejected_receipts.append(body[EXTENSION_KEY]["receipt_id"])
            return httpx.Response(response.status_code, json=body, request=request)

        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(mock, "handler", actual_provider_with_invalid_signature)
            with pytest.raises(RuntimeError):
                await execute_prepared_artifact_draft_model_v1(case["m1_model_runtime"], job_id=prepared.job_id)
        assert len(rejected_receipts) == 1
        with case["model_store"]._lock:
            record = case["model_store"]._read(case["model_store"]._db, prepared.call_id)
            assert record is not None and record.state in {"observed", "unknown"}
            assert "model_microusd" not in dict(record.cost)
        ids = artifact_draft_model_ids_v1(prepared.selector)
        with cold_originals_v1(case) as db:
            state, actual_json = db.execute("SELECT state,actual_json FROM runtime_budget_reservations "
                "WHERE lease_id=? AND operation_id=?", (prepared.parent_budget_lease_ref, prepared.operation_id)).fetchone()
            assert state == "partial_unknown"
            assert actual_json is None or "model_microusd" not in json.loads(actual_json)
            assert _read(db, issuer=case["d11_issuer"], namespace=case["namespace"], kind="c4_adopted", ref=ids["adopt"]) is None
            assert get_job(db, prepared.job_id).phase != "completed"
        assert not (case["m1_export_root"] / "m1-draft.txt").exists()

    await run_installed_m1_case_v1(tmp_path, installed_d04_root, after_c02=after_c02)


@pytest.fixture
def installed_m1_phase_fixture_v2(installed_d04_root):
    import os
    from test_post_c02_reply_assembly_v2 import M1PhaseFixtureInstallationV2
    selected = os.environ.get("SYLANNE_ARTIFACT_PHASE_FIXTURE_SETUP")
    if not selected:
        pytest.skip("requires Root-prepared protected source35 phase fixture installation")
    installation = M1PhaseFixtureInstallationV2.from_protected_setup_v2(Path(selected))
    assert installation.package_root == Path(installed_d04_root)
    return installation


async def _actual_phase_operation_v2(case, kind):
    worker, bundle = case["phase_worker"], case["installed_bundle"]
    result = await worker.call(lambda graph:
        graph.run_current_post_c02_artifact_phase_operation_v2(case["bootstrap"], bundle,
            c02_operation_id=case["c02"].operation_id, source_ref=case["source_ref"], operation_kind=kind))
    if kind == "wake_artifact_draft_cycle_v2":
        assert result["wake"]["receipt"]["status"] == result["acquisition"]["receipt"]["status"] == "committed", result
    else:
        assert result["receipt"]["status"] == "committed", result
    return result


async def _actual_phase_resume_v2(case):
    return await case["phase_worker"].call(lambda graph:
        graph.read_current_post_c02_artifact_phase_resume_v2(case["bootstrap"], case["installed_bundle"],
            c02_operation_id=case["c02"].operation_id, source_ref=case["source_ref"]))


async def _actual_generation_phase_file_preparation_v2(case, *, expected_method_ref, expected_phase_kind, expected_phase_index):
    """The real C4 and W01 file preparation, before any tool handoff."""
    from sylanne3.model_broker.artifact_draft_v1 import artifact_draft_model_ids_v2
    from sylanne3.runtime.d11_artifact_draft_model_v1 import (
        read_artifact_draft_prepared_v2, read_artifact_draft_frozen_v2,
        execute_prepared_artifact_draft_model_v2, decode_artifact_draft_original_v2,
    )
    from sylanne3.runtime.d11_life_preparation_v1 import TABLE, read_prepared_life_by_ref_v1
    from sylanne3.runtime.d11_artifact_draft_contract_v1 import DraftRootCapabilityV1, draft_from_wire_v1
    selected = await _actual_phase_resume_v2(case)
    assert selected is not None and selected["generation"]
    selector = selected["selector"]
    assert selector.method_ref == expected_method_ref and (selector.phase_index, selector.phase_kind) == (expected_phase_index, expected_phase_kind)
    await _actual_phase_operation_v2(case, selected["checkpoint_activation_operation"])
    await _actual_phase_operation_v2(case, "register_artifact_phase_postcondition_contract_v1")
    await _actual_phase_operation_v2(case, "prepare_artifact_draft_model_v2")
    await _actual_phase_operation_v2(case, "acquire_artifact_draft_model_v2")
    with cold_originals_v1(case) as db:
        prepared = read_artifact_draft_prepared_v2(db, namespace=case["namespace"], selector=selector,
            issuer=case["d11_issuer"])
        frozen = read_artifact_draft_frozen_v2(db, prepared=prepared, issuer=case["d11_issuer"])
        assert frozen.selector == selector and prepared.selector == selector
        assert get_job(db, prepared.job_id).phase == "running"
        root_row = _read(db, issuer=case["d11_issuer"], namespace=case["namespace"],
            kind="draft_root_capability", ref=selector.task.root_registration_ref)
        assert root_row is not None
        root = draft_from_wire_v1(root_row[0], DraftRootCapabilityV1)
    executed = await execute_prepared_artifact_draft_model_v2(case["m1_model_runtime"], job_id=prepared.job_id)
    assert executed["status"] == "actual_terminal_and_cost_recorded", executed
    calls = [value for value in case["phase_provider_calls"] if value[0] == prepared.call_id]
    assert len(calls) == 1
    ids = artifact_draft_model_ids_v2(selector)
    with cold_originals_v1(case) as db:
        paid_row = _read(db, issuer=case["d11_issuer"], namespace=case["namespace"], kind="c4_phase_paid", ref=ids["paid"])
        result_row = _read(db, issuer=case["d11_issuer"], namespace=case["namespace"], kind="c4_phase_result", ref=ids["result"])
        paid = decode_artifact_draft_original_v2("c4_phase_paid", paid_row[0])
        result = decode_artifact_draft_original_v2("c4_phase_result", result_row[0])
        bill = provider_billing_receipt_from_json_v1(result.observation.billing_receipt_json)
        assert paid.status == "committed" and paid.call_id == prepared.call_id
        assert bill.evidence_kind == "fixture_simulated_charge" and bill.final_charged_amount == 7
        assert bill.call_id == prepared.call_id and bill.request_digest == calls[0][1]
        assert db.execute("SELECT count(*) FROM runtime_budget_operations WHERE lease_id=? AND operation_id=? AND phase='settle'",
            (prepared.parent_budget_lease_ref, prepared.operation_id)).fetchone() == (1,)
    await _actual_phase_operation_v2(case, "wake_artifact_draft_cycle_v2")
    await _actual_phase_operation_v2(case, "adopt_artifact_draft_content_v2")
    for kind in ("propose_artifact_draft_phase_action_v2", "prepare_artifact_draft_body",
            "input:register_artifact_phase_draft_plan_v2"):
        await _actual_phase_operation_v2(case, kind)
    preparation = await _actual_phase_operation_v2(case, "prepare_life")
    with cold_originals_v1(case) as db:
        refs = db.execute("SELECT original_ref FROM " + TABLE + " WHERE bot=? AND persona=? AND kind='prepared' AND producing_operation_id=?",
            (*case["namespace"].as_tuple, preparation["operation_id"])).fetchall()
        assert len(refs) == 1
        file_prepared = read_prepared_life_by_ref_v1(db, namespace=case["namespace"],
            prepared_original_ref=refs[0][0], issuer=case["d11_issuer"])
    case.update(phase_generation_prepared=prepared, phase_file_prepared=file_prepared, phase_file_root=root)
    return file_prepared


async def _actual_full_phase_file_preparation_v2(case):
    from sylanne3.domains.d01 import FULL_DRAFT_METHOD_V1
    return await _actual_generation_phase_file_preparation_v2(case, expected_method_ref=FULL_DRAFT_METHOD_V1,
        expected_phase_kind="full", expected_phase_index=0)


async def _actual_generation_phase_file_readback_v2(case, *, expected_content, expected_version,
        expected_method_ref, expected_phase_kind, expected_phase_index):
    """Only actual C4 paid/read originals and the original D11 file executor."""
    from sylanne3.runtime.d11_life_adoption_v1 import adopt_current_life_v1
    from sylanne3.host.d11_life_port_v1 import InstalledD11LifePortV1
    from sylanne3.runtime.d11_artifact_draft_content_v1 import read_current_artifact_phase_verified_v2
    file_prepared = await _actual_generation_phase_file_preparation_v2(case, expected_method_ref=expected_method_ref,
        expected_phase_kind=expected_phase_kind, expected_phase_index=expected_phase_index)
    selector, root = case["phase_generation_prepared"].selector, case["phase_file_root"]
    port = InstalledD11LifePortV1(case["port"])
    claim, terminal = await case["phase_worker"].call(lambda graph:
        port.execute_d11_life_v1(binding=file_prepared.binding))
    path, actual_bytes = assert_original_file_witness_v1(case["m1_export_root"], file_prepared, terminal)
    assert claim.binding == terminal.binding == file_prepared.binding
    assert actual_bytes.decode("utf-8") == expected_content
    assert file_prepared.plan.target.expected_prior_version == expected_version - 1
    assert file_prepared.plan.target.mode == ("create" if expected_version == 1 else "replace")
    adopted = await case["phase_worker"].call(lambda graph: adopt_current_life_v1(graph, case["bootstrap"],
        namespace=case["namespace"], prepared_original_ref=file_prepared.binding.prepared_original_ref))
    assert adopted["status"] == "completed"
    await _actual_phase_operation_v2(case, "verify_artifact_draft_phase_v2")
    with cold_originals_v1(case) as db:
        verified = read_current_artifact_phase_verified_v2(db, namespace=case["namespace"],
            selector=selector, issuer=case["d11_issuer"])
        assert verified.structurally_verified and not verified.method_qualified
        assert verified.readback == terminal.payload.readback and verified.readback.version == expected_version
    case.update(phase_file_prepared=file_prepared, phase_file_terminal=terminal,
        phase_file_adoption=adopted, phase_generation_verified=verified, phase_file_path=path, phase_file_root=root)
    return verified


async def _actual_full_phase_file_readback_v2(case, *, expected_content, expected_version):
    from sylanne3.domains.d01 import FULL_DRAFT_METHOD_V1
    return await _actual_generation_phase_file_readback_v2(case, expected_content=expected_content,
        expected_version=expected_version, expected_method_ref=FULL_DRAFT_METHOD_V1,
        expected_phase_kind="full", expected_phase_index=0)


@pytest.mark.asyncio
async def test_installed_phase_st0_actual_full_generation_file_readback_v2(installed_m1_phase_fixture_v2):
    from m1_artifact_draft_acceptance_support_v1 import (
        run_installed_m1_phase_case_v2, prepare_actual_m1_phase_recall_v2,
        adopt_m1_phase_owner_project_role_v2, M1_PHASE_FULL_TEXT_V2,
    )
    from sylanne3.graph_worker import GraphWorker
    async def after_c02(case):
        worker, bundle = case["phase_worker"], case["installed_bundle"]
        assert type(worker) is GraphWorker and worker is case["phase_fixture_qualification"].worker
        await prepare_actual_m1_phase_recall_v2(case)
        arguments = {"c02_operation_id": case["c02"].operation_id, "source_ref": case["source_ref"]}
        for kind in ("create_artifact_task_plan_v1", "create_artifact_task_project_v1"):
            receipt = await worker.call(lambda graph: graph.run_current_post_c02_artifact_task_setup_v1(
                case["bootstrap"], bundle, operation_kind=kind, **arguments))
            assert receipt["receipt"]["status"] == "committed", receipt
        await worker.call(lambda graph: adopt_m1_phase_owner_project_role_v2(case))
        initialized = await worker.call(lambda graph: graph.run_current_post_c02_artifact_task_setup_v1(
            case["bootstrap"], bundle, operation_kind="initialize_artifact_task_project_checkpoint_v1", **arguments))
        assert initialized["receipt"]["status"] == "committed", initialized
        # The normal Self entry consumes the earlier exact Owner StandingScopeV3 approval.
        choice = await worker.call(lambda graph: graph.prepare_current_post_c02_artifact_phase_choice_v3(
            case["bootstrap"], bundle, **arguments))
        assert choice["status"] == "selected", choice
        verified = await _actual_full_phase_file_readback_v2(case,
            expected_content=M1_PHASE_FULL_TEXT_V2, expected_version=1)
        assert verified.structurally_verified and not verified.method_qualified
    await run_installed_m1_phase_case_v2(installed_m1_phase_fixture_v2, after_c02=after_c02)


async def _actual_phase_checkpoint_v2(case):
    result = await case["phase_worker"].call(lambda graph:
        graph.checkpoint_current_artifact_phase_v2(case["bootstrap"], case["installed_bundle"],
            c02_operation_id=case["c02"].operation_id, source_ref=case["source_ref"]))
    assert result["receipt"]["status"] == "committed", result
    return result


def _phase_accounting_snapshot_v2(case):
    with cold_originals_v1(case) as db:
        return (
            tuple(db.execute("SELECT lease_id,operation_id,state,actual_json FROM runtime_budget_reservations ORDER BY lease_id,operation_id")),
            tuple(db.execute("SELECT * FROM runtime_budget_operations ORDER BY lease_id,operation_id,phase")),
        )


async def _actual_phase_check_and_settlement_v2(case, *, semantic_index):
    """A structural generation never supplies the independent method check."""
    from sylanne3.runtime.artifact_task_observer_v1 import (
        artifact_task_milestone_original_ref_v2, read_current_artifact_task_milestone_v2,
    )
    from sylanne3.runtime.d11_artifact_draft_content_v1 import read_current_artifact_phase_verified_v2
    from sylanne3.domains.d10.project_checkpoint_v1 import project_checkpoint_key_v1
    from sylanne3.runtime.d01_production_operations_v1 import MissingProductionOriginalV1
    from sylanne3.graph_coordinator import UnavailableGuard
    await _actual_phase_checkpoint_v2(case)
    before = await _actual_phase_resume_v2(case)
    assert before["selector"].phase_kind == "check" and not before["generation"]
    calls_before = tuple(case["phase_provider_calls"])
    await _actual_phase_operation_v2(case, "observe_artifact_phase_postconditions_v1")
    observed = await _actual_phase_resume_v2(case)
    assert observed["assessment_registered"] and observed["assessment_statuses"]
    assert tuple(case["phase_provider_calls"]) == calls_before
    # Unknown/violated/conflicting are a genuine HOLD, with no model or billing attempt.
    if any(status != "satisfied" for status in observed["assessment_statuses"]):
        accounting_before = _phase_accounting_snapshot_v2(case)
        with pytest.raises((MissingProductionOriginalV1, UnavailableGuard, ValueError)):
            await case["phase_worker"].call(lambda graph:
                graph.run_current_post_c02_artifact_phase_operation_v2(case["bootstrap"], case["installed_bundle"],
                    c02_operation_id=case["c02"].operation_id, source_ref=case["source_ref"],
                    operation_kind="verify_artifact_draft_phase_v2"))
        assert tuple(case["phase_provider_calls"]) == calls_before
        assert _phase_accounting_snapshot_v2(case) == accounting_before
    assert set(observed["assessment_statuses"]) == {"satisfied"}, observed
    await _actual_phase_operation_v2(case, "verify_artifact_draft_phase_v2")
    with cold_originals_v1(case) as db:
        checked = read_current_artifact_phase_verified_v2(db, namespace=case["namespace"],
            selector=observed["selector"], issuer=case["d11_issuer"])
        assert checked.method_qualified and checked.structurally_verified
        assert checked.readback == case["phase_generation_verified"].readback
    await _actual_phase_checkpoint_v2(case)
    await _actual_phase_operation_v2(case, "register_artifact_task_milestone_v2")
    with cold_originals_v1(case) as db:
        milestone = read_current_artifact_task_milestone_v2(db, namespace=case["namespace"],
            original_ref=artifact_task_milestone_original_ref_v2(checked.selector), issuer=case["d11_issuer"])
        assert milestone.semantic_index == semantic_index and milestone.file_version == semantic_index
        assert milestone.full_check_original_ref == checked.original_ref
        assert milestone.full_check_original_digest == checked.digest
        assert milestone.file_result_ref == checked.readback_original_ref
        assert milestone.file_result_digest == checked.readback_original_digest
        assert milestone.source_head == checked.source_head
        assert milestone.source_value_digest == checked.source_value_digest
    for kind in ("input:register_life_outcome_v2", "advance_life", "settle_project_checkpoint", "settle_personal_goal"):
        result = await case["phase_worker"].call(lambda graph:
            graph.run_current_post_c02_artifact_method_final_operation_v2(case["bootstrap"], case["installed_bundle"],
                c02_operation_id=case["c02"].operation_id, source_ref=case["source_ref"], operation_kind=kind))
        assert result["receipt"]["status"] == "committed", result
    disclosure = await case["phase_worker"].call(lambda graph:
        graph.read_current_completed_artifact_method_v2(case["bootstrap"], case["installed_bundle"],
            c02_operation_id=case["c02"].operation_id, source_ref=case["source_ref"]))
    expected_state = "partial" if semantic_index == 1 else "satisfied"
    assert disclosure["history_state"] == expected_state
    history = disclosure["history"]
    assert history.selector == milestone.selector and history.milestone_original_digest == milestone.digest
    assert history.file_result_ref == milestone.file_result_ref and history.file_result_digest == milestone.file_result_digest
    assert history.source_head == milestone.source_head and history.source_value_digest == milestone.source_value_digest
    assert history.ordered_phase_originals == milestone.ordered_phase_originals
    assert history.original_deadline_utc == milestone.original_deadline_utc
    assert history.completed_at_utc < history.original_deadline_utc
    with cold_originals_v1(case) as db:
        def head(ref):
            row = db.execute("SELECT revision,value,valid FROM graph_atoms WHERE bot=? AND persona=? AND token=?",
                (*case["namespace"].as_tuple, ref)).fetchone()
            assert row is not None and row[2] == 1
            return row[0], json.loads(row[1])
        goal_revision, goal = head(history.goal_ref)
        plan_revision, plan = head(history.plan_ref)
        _, checkpoint = head(project_checkpoint_key_v1(case["namespace"], history.project_ref).token)
        assert goal["state"] == ("active" if semantic_index == 1 else "satisfied")
        assert plan["state"] == ("waiting" if semantic_index == 1 else "satisfied")
        assert plan["goal_ref"] == history.goal_ref and plan["goal_revision"] == goal_revision
        assert checkpoint["plan_ref"] == history.plan_ref and checkpoint["plan_revision"] == plan_revision
        assert checkpoint["state"] == ("waiting" if semantic_index == 1 else "completed")
        assert checkpoint["next_step"] is None and len(checkpoint["work_version_refs"]) == semantic_index
        assert (checkpoint["wait_condition"] is None) == (semantic_index == 2)
        if semantic_index == 1:
            assert plan["waiting_conditions"] == [milestone.objective_ref]
            assert checkpoint["wait_condition"]["objective_ref"] == milestone.objective_ref
            assert milestone.prev_milestone_ref is milestone.amendment_ref is None
        else:
            assert plan["waiting_conditions"] == []
            assert milestone.prev_milestone_ref is not None and milestone.amendment_ref is not None
    # Read-only negative preconditions start from this genuine, current completed history.
    from sylanne3.runtime.d11_artifact_draft_content_v1 import read_current_completed_artifact_method_history_v2
    from sylanne3.runtime.artifact_task_amendment_v1 import read_current_amendment_v1
    accounting_before = _phase_accounting_snapshot_v2(case)
    with cold_originals_v1(case) as db:
        with pytest.raises(ValueError, match="current Owner"):
            read_current_completed_artifact_method_history_v2(db, namespace=case["namespace"],
                selector=history.selector, issuer=case["d11_issuer"], installed_bundle=case["installed_bundle"],
                owner_guard=replace(history.owner_guard, grant_revision=history.owner_guard.grant_revision + 1))
        assert read_current_amendment_v1(db, namespace=case["namespace"],
            root_registration_ref="unregistered-amendment:" + uuid4().hex, issuer=case["d11_issuer"]) is None
    assert tuple(case["phase_provider_calls"]) == calls_before
    assert _phase_accounting_snapshot_v2(case) == accounting_before
    case.update(phase_method_milestone=milestone, phase_method_history=history)
    return milestone, history


async def _assert_actual_phase_protected_reply_v2(case):
    """Require the ordinary C5/C6 terminal originals; progress labels alone cannot pass."""
    from sylanne3.runtime.natural_reply_job_v2 import read_original_preparation
    from m1_artifact_draft_acceptance_support_v1 import run_actual_m1_phase_protected_reply_v2
    await run_actual_m1_phase_protected_reply_v2(case)
    state = await case["phase_worker"].call(lambda graph:
        graph.read_protected_artifact_task_reply_state_v1(case["bootstrap"], case["installed_bundle"],
            c02_operation_id=case["c02"].operation_id))
    assert state["state"] == "settled", "normal installed RuntimeContext C5/C6 composition is required"
    with cold_originals_v1(case) as db:
        for stage in ("generation", "review"):
            saved = read_original_preparation(db, case["namespace"], case["c02"].operation_id, stage)
            assert saved is not None and saved.state == "terminal" and saved.terminal_receipt_digest
            seal = saved.seal
            assert len([call for call in case["phase_provider_calls"] if call[0] == seal.call_id]) == 1
            reservation = db.execute("SELECT state,actual_json FROM runtime_budget_reservations WHERE lease_id=? AND operation_id=?",
                (seal.parent_budget_lease_id, seal.reservation_operation_id)).fetchone()
            assert reservation[0] == "settled" and json.loads(reservation[1])["model_microusd"] == 7
            assert db.execute("SELECT count(*) FROM runtime_budget_operations WHERE lease_id=? AND operation_id=? AND phase='settle'",
                (seal.parent_budget_lease_id, seal.reservation_operation_id)).fetchone() == (1,)


@pytest.mark.asyncio
async def test_installed_phase_st0_two_observed_messages_same_file_goal_v2(installed_m1_phase_fixture_v2):
    """Two real C1 messages, one partial Goal, exact cap-two predecessor replacement.

    The initial Owner-approved V3 scope and canonical C5/C6 drivers are required.
    Root must freeze the formal choice/amendment producers before the first run.
    """
    from m1_artifact_draft_acceptance_support_v1 import (
        run_installed_m1_phase_case_v2, prepare_actual_m1_phase_recall_v2,
        adopt_m1_phase_owner_project_role_v2, M1_PHASE_FULL_TEXT_V2,
        M1_PHASE_REVISION_TASK_TEXT_V2, M1_PHASE_REVISED_FULL_TEXT_V2,
    )
    from sylanne3.runtime.c1_artifact_task_intent_v1 import read_c1_task_intent_original_v1
    from sylanne3.runtime.artifact_task_amendment_v1 import read_current_amendment_v1
    async def after_c02(case):
        worker, bundle = case["phase_worker"], case["installed_bundle"]
        assert bundle.artifact_draft.tool_scope.maximum_artifact_version == 2
        await prepare_actual_m1_phase_recall_v2(case)
        arguments = {"c02_operation_id": case["c02"].operation_id, "source_ref": case["source_ref"]}
        for kind in ("create_artifact_task_plan_v1", "create_artifact_task_project_v1"):
            result = await worker.call(lambda graph: graph.run_current_post_c02_artifact_task_setup_v1(
                case["bootstrap"], bundle, operation_kind=kind, **arguments))
            assert result["receipt"]["status"] == "committed", result
        await worker.call(lambda graph: adopt_m1_phase_owner_project_role_v2(case))
        initialized = await worker.call(lambda graph: graph.run_current_post_c02_artifact_task_setup_v1(
            case["bootstrap"], bundle, operation_kind="initialize_artifact_task_project_checkpoint_v1", **arguments))
        assert initialized["receipt"]["status"] == "committed", initialized
        choice = await worker.call(lambda graph: graph.prepare_current_post_c02_artifact_phase_choice_v3(
            case["bootstrap"], bundle, **arguments))
        assert choice["status"] == "selected", choice
        first_generation = await _actual_full_phase_file_readback_v2(case,
            expected_content=M1_PHASE_FULL_TEXT_V2, expected_version=1)
        first_target, first_path = case["phase_file_prepared"].plan.target, case["phase_file_path"]
        first_root = case["phase_file_root"]
        first_milestone, first_history = await _actual_phase_check_and_settlement_v2(case, semantic_index=1)
        await _assert_actual_phase_protected_reply_v2(case)
        first_c02, first_source = case["c02"], case["source_ref"]
        calls_before = len(case["phase_provider_calls"])
        _, second_c02, second_ingress = await case["commit_second_c02"](
            "phase-revision-" + uuid4().hex, M1_PHASE_REVISION_TASK_TEXT_V2,
            commit_attention=True, return_envelope=True)
        assert second_c02.operation_id != first_c02.operation_id
        assert len(case["phase_provider_calls"]) == calls_before + 1
        with cold_originals_v1(case) as db:
            first_intent = read_c1_task_intent_original_v1(db, namespace=case["namespace"],
                c02_operation_id=first_c02.operation_id, issuer=case["d11_issuer"])
            second_intent = read_c1_task_intent_original_v1(db, namespace=case["namespace"],
                c02_operation_id=second_c02.operation_id, issuer=case["d11_issuer"])
            assert second_intent.intent.kind == "continue" and second_intent.source_ref != first_source
            assert second_intent.c02_commit_seq > first_intent.c02_commit_seq
        case.update(c02=second_c02, source_ref=second_intent.source_ref, ingress=second_ingress)
        arguments = {"c02_operation_id": second_c02.operation_id, "source_ref": second_intent.source_ref}
        for method in ("prepare_post_c02_foreground_cycle_v1", "acquire_post_c02_foreground_cycle_v1"):
            result = await worker.call(lambda graph: getattr(graph, method)(case["bootstrap"], bundle, **arguments))
            assert result["receipt"]["status"] == "committed", result
        await prepare_actual_m1_phase_recall_v2(case)
        # New formal producer must reconstruct Plan revision from the signed first milestone/amendment.
        amendment_preparation = await worker.call(lambda graph:
            graph.prepare_current_post_c02_artifact_phase_amendment_v3(case["bootstrap"], bundle, **arguments))
        assert amendment_preparation["receipt"]["status"] == "committed", amendment_preparation
        choice = await worker.call(lambda graph: graph.prepare_current_post_c02_artifact_phase_choice_v3(
            case["bootstrap"], bundle, **arguments))
        assert choice["status"] == "selected", choice
        second_selected = await _actual_phase_resume_v2(case)
        with cold_originals_v1(case) as db:
            actual = read_current_amendment_v1(db, namespace=case["namespace"],
                root_registration_ref=second_selected["selector"].task.root_registration_ref, issuer=case["d11_issuer"])
            assert actual is not None
            amendment, amendment_ref, _ = actual
            assert (amendment.goal_ref, amendment.project_ref, amendment.objective_ref) == (
                first_history.goal_ref, first_history.project_ref, first_milestone.objective_ref)
            assert amendment.c02_operation_id == second_c02.operation_id and amendment.source_ref == second_intent.source_ref
            assert amendment.filename == first_target.filename
        second_generation = await _actual_full_phase_file_readback_v2(case,
            expected_content=M1_PHASE_REVISED_FULL_TEXT_V2, expected_version=2)
        second_target = case["phase_file_prepared"].plan.target
        assert case["phase_file_path"] == first_path
        assert case["phase_file_root"].valid_until_utc == first_root.valid_until_utc
        assert (second_target.root_resource_id, second_target.root_identity, second_target.filename) == (
            first_target.root_resource_id, first_target.root_identity, first_target.filename)
        assert second_target.expected_prior_digest == first_generation.readback.content_digest
        assert second_target.expected_prior_identity == first_generation.readback.file_identity
        assert second_generation.readback.effect_id != first_generation.readback.effect_id
        milestone, history = await _actual_phase_check_and_settlement_v2(case, semantic_index=2)
        assert milestone.prev_milestone_ref == first_milestone.original_ref
        assert milestone.prev_milestone_digest == first_milestone.digest and milestone.amendment_ref == amendment_ref
        assert milestone.goal_ref == first_milestone.goal_ref and milestone.objective_ref == first_milestone.objective_ref
        assert history.original_deadline_utc == first_history.original_deadline_utc
        assert bundle.artifact_draft.tool_scope.maximum_artifact_version == 2
        await _assert_actual_phase_protected_reply_v2(case)
    await run_installed_m1_phase_case_v2(installed_m1_phase_fixture_v2, after_c02=after_c02)


async def _phase_owner_call_v2(case, method, *, purpose="workbench_user_action", domains=("d08", "d10", "d11", "d12"), **kwargs):
    """Every invocation obtains this actual signed Owner session's current lease."""
    def call(graph):
        authority, lease, _ = graph.grant_current_owner(case["bootstrap"], actor="owner-actor-reply",
            namespace=case["namespace"], domains=domains, purpose=purpose, audience="owner",
            activation_generation=1, owner_session_token=case["owner_session_token"],
            owner_session_request=case["owner_session_request"])
        try:
            return getattr(graph, method)(authority, lease, **kwargs)
        finally:
            graph.release_current_owner_lease(case["bootstrap"], lease)
    return await case["phase_worker"].call(call)


async def _phase_initial_full_choice_v2(case):
    from m1_artifact_draft_acceptance_support_v1 import prepare_actual_m1_phase_recall_v2, adopt_m1_phase_owner_project_role_v2
    await prepare_actual_m1_phase_recall_v2(case)
    arguments = {"c02_operation_id": case["c02"].operation_id, "source_ref": case["source_ref"]}
    worker, bundle = case["phase_worker"], case["installed_bundle"]
    for kind in ("create_artifact_task_plan_v1", "create_artifact_task_project_v1"):
        receipt = await worker.call(lambda graph: graph.run_current_post_c02_artifact_task_setup_v1(
            case["bootstrap"], bundle, operation_kind=kind, **arguments))
        assert receipt["receipt"]["status"] == "committed", receipt
    await worker.call(lambda graph: adopt_m1_phase_owner_project_role_v2(case))
    initialized = await worker.call(lambda graph: graph.run_current_post_c02_artifact_task_setup_v1(
        case["bootstrap"], bundle, operation_kind="initialize_artifact_task_project_checkpoint_v1", **arguments))
    assert initialized["receipt"]["status"] == "committed", initialized
    choice = await worker.call(lambda graph: graph.prepare_current_post_c02_artifact_phase_choice_v3(
        case["bootstrap"], bundle, **arguments))
    assert choice["status"] == "selected", choice
    return choice


def _phase_boundary_evidence_v2(name, value):
    import os
    directory = Path(os.environ["SYLANNE_PHASE_APPLICATION_EVIDENCE"])
    assert directory.is_dir() and directory.stat().st_uid == os.geteuid() == 1000
    target = directory / (name + ".json")
    assert not target.exists()
    target.write_bytes(json.dumps(value, ensure_ascii=False, indent=2).encode("utf-8"))
    target.chmod(0o600)


def _actual_project_control_v2(result):
    from sylanne3.runtime.d08_project_control_v1 import decode_project_control_original_v1
    original = result["actual_original"]
    assert original["payload"]["identity"]["operation_id"] == result["operation_id"]
    return decode_project_control_original_v1(original["payload"]["provenance"]["project_control"])


@pytest.mark.asyncio
async def test_installed_phase_owner_artifact_read_current_identity_source_and_file_v2(installed_m1_phase_fixture_v2):
    """Actual generated Chinese bytes/private BodyV2; >64KiB body is not produced by this recipe."""
    import base64
    import hashlib
    from sylanne3.runtime.d12_owner_artifact_read_v1 import OwnerArtifactReadRequestV1, WIRE_RESULT_SCHEMA
    from sylanne3.authority_service.d12_owner_artifact_rpc_v1 import BODY_METHOD
    from sylanne3.graph_types import AtomKey
    from sylanne3.domains.d06.source_access_revocation import SourceAccessRevocationRequest
    from sylanne3.runtime.first_ingress_v2 import trusted_upper
    from m1_artifact_draft_acceptance_support_v1 import run_installed_m1_phase_case_v2, M1_PHASE_FULL_TEXT_V2
    async def after_c02(case):
        await _phase_initial_full_choice_v2(case)
        await _actual_full_phase_file_readback_v2(case, expected_content=M1_PHASE_FULL_TEXT_V2, expected_version=1)
        prepared, path = case["phase_file_prepared"], case["phase_file_path"]
        project = prepared.plan.project.ref
        options = await _phase_owner_call_v2(case, "read_owner_project_artifact_options_v1",
            purpose="workbench_view", project_ref=project)
        assert options["schema"] == "d12.owner-artifact-options.v1" and len(options["items"]) == 1
        selected = options["items"][0]
        request = OwnerArtifactReadRequestV1(case["namespace"], case["policy"].installation_id, project,
            selected["progress_ref"], selected["artifact_version"], selected["content_digest"])
        calls = tuple(case["phase_provider_calls"])
        async def read(value=request):
            return await _phase_owner_call_v2(case, "read_owner_project_artifact_v1",
                purpose="workbench_view", request=value)
        result = await read()
        body = base64.b64decode(result["body_base64"], validate=True)
        assert result["schema"] == WIRE_RESULT_SCHEMA and result["body_encoding"] == "base64"
        assert body == path.read_bytes() == M1_PHASE_FULL_TEXT_V2.encode("utf-8")
        assert (len(body), hashlib.sha256(body).hexdigest()) == (result["content_length_bytes"], result["content_digest"])
        assert body.decode("utf-8") == M1_PHASE_FULL_TEXT_V2 and "read_binding" not in result
        with pytest.raises(Exception, match="Owner|owner|installation|paired"):
            await read(replace(request, installation_id=request.installation_id + ":foreign"))
        port = case["port"]
        original_observe = port.observe_owner_artifact_for_fence_v1
        def foreign_owner_request(**kwargs):
            actual = kwargs["owner_session_request"]
            kwargs["owner_session_request"] = replace(actual,
                principal=replace(actual.principal, account_ref=actual.principal.account_ref + ":unpaired"))
            return original_observe(**kwargs)
        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(port, "observe_owner_artifact_for_fence_v1", foreign_owner_request)
            with pytest.raises(Exception, match="Owner|owner|principal|session|pair"):
                await read()
        original_rpc = port._transport._content_rpc
        actual_other_channel = case["client_grant"].channel_binding_sha256
        def verify_other_channel():
            assert actual_other_channel != port.installation_grant.channel_binding_sha256
        await case["phase_worker"].call(lambda graph: verify_other_channel())
        crossed = []
        async def cross_actual_response_channel(*args, **kwargs):
            response = await original_rpc(*args, **kwargs)
            if args[2] == BODY_METHOD:
                crossed.append(response["channel_binding_sha256"])
                return {**response, "channel_binding_sha256": actual_other_channel}
            return response
        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(port._transport, "_content_rpc", cross_actual_response_channel)
            with pytest.raises(RuntimeError, match="exact private artifact read response"):
                await read()
        assert len(crossed) == 1 and crossed[0] != actual_other_channel
        original_bytes, original_inode = path.read_bytes(), path.stat().st_ino
        path.write_bytes(original_bytes[:-1] + bytes([original_bytes[-1] ^ 1]))
        try:
            with pytest.raises(Exception, match="artifact|file|digest|readback|bytes"):
                await read()
        finally:
            path.write_bytes(original_bytes)
        assert path.stat().st_ino == original_inode and (await read())["content_digest"] == result["content_digest"]
        clock = await case["phase_worker"].call(lambda graph:
            trusted_upper(port.read_ingress_clock(case["installed_bundle"].ingress_clock)))
        revoked = await _phase_owner_call_v2(case, "revoke_source_access_v1", purpose="audit", domains=("d06", "d12"),
            request=SourceAccessRevocationRequest(AtomKey.from_token(case["source_ref"]).owner.subject,
                "owner-actor-reply", str(uuid4()), clock))
        with pytest.raises(Exception, match="Source|source|current|access|qualified|artifact|eligib"):
            await read()
        assert tuple(case["phase_provider_calls"]) == calls
        _phase_boundary_evidence_v2("owner-artifact-read", {"schema": "phase.owner-artifact-read-acceptance.v1",
            "project_ref": project, "progress_ref": request.progress_ref, "artifact_version": 1,
            "content_digest": result["content_digest"], "content_length_bytes": len(body),
            "source_revocation_operation": revoked.operation_id, "cross_owner_request_rejected": True,
            "cross_installation_rejected": True, "actual_other_channel_response_rejected": True,
            "changed_file_rejected": True, "changed_source_rejected": True, "additional_provider_calls": 0,
            "body_over_65536_installed": "UNREACHED_formal_model_producer_UTF8_limit_32768",
            "billing_evidence_kind": "fixture_simulated_charge", "vendor_token_count_claim": False})
    await run_installed_m1_phase_case_v2(installed_m1_phase_fixture_v2, after_c02=after_c02, owner_controls=True)


@pytest.mark.asyncio
async def test_owner_artifact_named_body_wire_bound_only_v2():
    """Transport boundary only; this is not an adopted large-file/Owner installation proof."""
    import base64
    from sylanne3.host.d12_owner_artifact_read_port_v1 import read_owner_artifact_response_line_v2
    from sylanne3.runtime.d12_owner_artifact_read_v1 import BODY_RESPONSE_MAX_BYTES
    body = ("完整中文传输边界。" * 3000).encode("utf-8")
    wire = json.dumps({"body_encoding": "base64", "body_base64": base64.b64encode(body).decode("ascii")},
        separators=(",", ":")).encode("utf-8") + b"\n"
    assert 65536 < len(wire) < BODY_RESPONSE_MAX_BYTES
    reader = asyncio.StreamReader()
    reader.feed_data(wire)
    reader.feed_eof()
    observed = await read_owner_artifact_response_line_v2(reader, timeout_seconds=1)
    assert observed == wire and base64.b64decode(json.loads(observed)["body_base64"], validate=True) == body
    too_large = asyncio.StreamReader()
    too_large.feed_data(b"x" * BODY_RESPONSE_MAX_BYTES + b"\n")
    too_large.feed_eof()
    with pytest.raises(RuntimeError, match="framing bound"):
        await read_owner_artifact_response_line_v2(too_large, timeout_seconds=1)


def _phase_actual_checkpoint_heads_v2(case, project):
    with cold_originals_v1(case) as db:
        rows = tuple(db.execute("SELECT token,revision,value,valid FROM graph_atoms WHERE bot=? AND persona=? "
            "AND type_name='d10.project_checkpoint.v1' AND json_extract(value,'$.project_ref')=? ORDER BY token LIMIT 2",
            (*case["namespace"].as_tuple, project)))
        assert len(rows) == 1
        return rows


async def _phase_pause_current_v2(case, project):
    from sylanne3.runtime.d08_project_control_v1 import PauseProjectRequestV1
    context = await _phase_owner_call_v2(case, "read_project_control_context_v1", project_ref=project)
    assert context["schema"] == "d12.project-control-context.v1" and "pause_project_v1" in context["permitted_controls"]
    request = PauseProjectRequestV1(project, context["plan_ref"], context["plan_revision"])
    operation = str(uuid4())
    result = await _phase_owner_call_v2(case, "pause_project_v1", request=request, operation_id=operation)
    control = _actual_project_control_v2(result)
    assert control.control == "pause" and not control.noop and control.after_plan_state == "paused"
    assert control.before_plan_revision == context["plan_revision"] and control.after_plan_revision == context["plan_revision"] + 1
    replay = await _phase_owner_call_v2(case, "pause_project_v1", request=request, operation_id=operation)
    assert replay["actual_original"]["original_digest"] == result["actual_original"]["original_digest"]
    with pytest.raises(Exception, match="CAS|changed|stale|revision"):
        await _phase_owner_call_v2(case, "pause_project_v1", request=request, operation_id=str(uuid4()))
    return result, control


async def _phase_resume_actual_pause_v2(case, pause):
    from sylanne3.runtime.d08_project_control_v1 import ResumeProjectRequestV1
    context = await _phase_owner_call_v2(case, "read_project_control_context_v1", project_ref=pause.project_ref)
    assert context["plan_state"] == "paused" and context["pause_original_ref"] == pause.control_original_ref
    request = ResumeProjectRequestV1(pause.project_ref, context["plan_ref"], context["plan_revision"], pause.control_original_ref)
    with pytest.raises(Exception, match="pause|original|origin"):
        await _phase_owner_call_v2(case, "resume_project_v1",
            request=replace(request, pause_original_ref=str(uuid4())), operation_id=str(uuid4()))
    result = await _phase_owner_call_v2(case, "resume_project_v1", request=request, operation_id=str(uuid4()))
    control = _actual_project_control_v2(result)
    assert control.control == "resume" and control.pause_origin == pause.control_original_ref
    return result, control


async def _phase_assert_paused_new_work_refused_v2(case, prepared):
    from sylanne3.runtime.d11_life_preparation_v1 import PrepareCurrentLifeRequestV1
    from sylanne3.host.d11_life_port_v1 import InstalledD11LifePortV1
    provider_calls = tuple(case["phase_provider_calls"])
    accounting = _phase_accounting_snapshot_v2(case)
    operation = str(uuid4())
    attempted = await _phase_owner_call_v2(case, "run_current_domain_operation_v1", operation_kind="prepare_life",
        request=PrepareCurrentLifeRequestV1(prepared.binding.plan_original_ref, operation), operation_id=operation,
        activity_id=prepared.binding.activity_id, audience_ref="owner", parent_budget_lease_ref=prepared.binding.parent_budget_lease_ref)
    assert attempted["coverage"] != "complete" and "current_active_project_Plan_for_new_work" in attempted["missing_inputs"], attempted
    assert not attempted["receipt"]["write_versions"]
    with pytest.raises(Exception, match="current|Plan|active|paused|candidate|HOLD"):
        await case["phase_worker"].call(lambda graph: graph.prepare_current_post_c02_artifact_phase_choice_v3(
            case["bootstrap"], case["installed_bundle"], c02_operation_id=case["c02"].operation_id, source_ref=case["source_ref"]))
    port = InstalledD11LifePortV1(case["port"])
    with pytest.raises(Exception, match="current|Plan|active|paused|prepared|scope|unavailable|admission"):
        await case["phase_worker"].call(lambda graph: port.execute_d11_life_v1(binding=prepared.binding))
    assert tuple(case["phase_provider_calls"]) == provider_calls
    assert _phase_accounting_snapshot_v2(case) == accounting
    return attempted


@pytest.mark.asyncio
async def test_installed_phase_owner_pause_blocks_prepared_and_new_work_v2(installed_m1_phase_fixture_v2):
    """Actual prepare then Owner CAS; blocked worker is retained, never a fabricated terminal."""
    from m1_artifact_draft_acceptance_support_v1 import run_installed_m1_phase_case_v2
    from sylanne3.host.d11_life_port_v1 import InstalledD11LifePortV1
    async def after_c02(case):
        await _phase_initial_full_choice_v2(case)
        prepared = await _actual_full_phase_file_preparation_v2(case)
        port = InstalledD11LifePortV1(case["port"])
        before = await case["phase_worker"].call(lambda graph: port.read_d11_life_original_v1(binding=prepared.binding))
        assert before == (None, None)
        checkpoint_before = _phase_actual_checkpoint_heads_v2(case, prepared.plan.project.ref)
        result, pause = await _phase_pause_current_v2(case, prepared.plan.project.ref)
        refused = await _phase_assert_paused_new_work_refused_v2(case, prepared)
        after = await case["phase_worker"].call(lambda graph: port.read_d11_life_original_v1(binding=prepared.binding))
        assert after == before and not (case["m1_export_root"] / prepared.plan.target.filename).exists()
        resumed, control = await _phase_resume_actual_pause_v2(case, pause)
        # This actual acquired worker/reservation is still pending; no fake wait condition is invented.
        assert control.noop and control.after_plan_state == "paused"
        assert "actual_pending_effect_wait_condition_required" in resumed["missing_inputs"]
        await _phase_assert_paused_new_work_refused_v2(case, prepared)
        with cold_originals_v1(case) as db:
            assert get_job(db, prepared.binding.job_id).phase == "running"
            root = _read(db, issuer=case["d11_issuer"], namespace=case["namespace"],
                kind="draft_root_capability", ref=prepared.binding.root_registration_ref)
            assert root is not None and root[0]["valid_until_utc"] == case["phase_file_root"].valid_until_utc
        assert _phase_actual_checkpoint_heads_v2(case, prepared.plan.project.ref) == checkpoint_before
        _phase_boundary_evidence_v2("pause-prepared", {"schema": "phase.pause-prepared-acceptance.v1",
            "project_ref": pause.project_ref, "plan_ref": pause.plan_ref, "pause_original": pause.control_original_ref,
            "pause_operation": result["operation_id"], "actual_resume_operation": resumed["operation_id"],
            "old_prepared_ref": prepared.binding.prepared_original_ref, "new_prepare_operation": refused["operation_id"],
            "new_model_tool_dispatches": 0, "actual_claim_terminal": "absent", "prepared_job_retained": "running",
            "resume_state": control.after_plan_state, "resume_held_missing_actual_wait_condition": True,
            "original_Root_deadline": case["phase_file_root"].valid_until_utc, "TTL_or_budget_renewed": False})
    await run_installed_m1_phase_case_v2(installed_m1_phase_fixture_v2, after_c02=after_c02, owner_controls=True)


@pytest.mark.asyncio
async def test_installed_phase_owner_pause_preserves_actual_unknown_and_resume_hold_v2(installed_m1_phase_fixture_v2):
    """Lose final readback after a real file handoff; preserve the actual signed UNKNOWN."""
    from m1_artifact_draft_acceptance_support_v1 import run_installed_m1_phase_case_v2
    from sylanne3.host.d11_life_port_v1 import InstalledD11LifePortV1
    from sylanne3.authority_service import d11_artifact_draft_executor_v1 as executor
    from sylanne3.runtime.d11_life_adoption_v1 import adopt_current_life_v1
    async def after_c02(case):
        await _phase_initial_full_choice_v2(case)
        prepared = await _actual_full_phase_file_preparation_v2(case)
        target = case["m1_export_root"] / prepared.plan.target.filename
        original_readback, completed_reads = executor._readback, []
        def lose_actual_target_readback(path, **kwargs):
            actual_identity = original_readback(path, **kwargs)
            if Path(path) == target:
                completed_reads.append((actual_identity.device, actual_identity.file_id))
                raise OSError("fixture loses final readback after the actual physical handoff")
            return actual_identity
        port = InstalledD11LifePortV1(case["port"])
        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(executor, "_readback", lose_actual_target_readback)
            claim, terminal = await case["phase_worker"].call(lambda graph:
                port.execute_d11_life_v1(binding=prepared.binding))
        assert len(completed_reads) == 1 and target.is_file()
        assert terminal.status == "unknown" and terminal.payload.handoff_started and terminal.payload.readback is None
        adopted = await case["phase_worker"].call(lambda graph: adopt_current_life_v1(graph, case["bootstrap"],
            namespace=case["namespace"], prepared_original_ref=prepared.binding.prepared_original_ref))
        assert adopted["status"] == "unknown"
        with cold_originals_v1(case) as db:
            assert get_job(db, prepared.binding.job_id).phase == "pending_confirmation"
        unknown_bytes = target.read_bytes()
        checkpoint_before = _phase_actual_checkpoint_heads_v2(case, prepared.plan.project.ref)
        paused, pause = await _phase_pause_current_v2(case, prepared.plan.project.ref)
        assert pause.execution_summary.unknown >= 1
        accounting = _phase_accounting_snapshot_v2(case)
        provider_calls = tuple(case["phase_provider_calls"])
        resumed, control = await _phase_resume_actual_pause_v2(case, pause)
        assert control.noop and control.after_plan_state == "paused" and control.execution_summary.unknown >= 1
        assert "actual_pending_effect_wait_condition_required" in resumed["missing_inputs"]
        current = await _phase_owner_call_v2(case, "read_project_control_context_v1", project_ref=pause.project_ref)
        assert current["plan_state"] == "paused" and current["resume_preview"]["state"] is None
        assert "resume_project_v1" not in current["permitted_controls"] and current["execution_summary"]["unknown"] >= 1
        assert _phase_accounting_snapshot_v2(case) == accounting and tuple(case["phase_provider_calls"]) == provider_calls
        assert target.read_bytes() == unknown_bytes
        with cold_originals_v1(case) as db:
            assert get_job(db, prepared.binding.job_id).phase == "pending_confirmation"
        assert _phase_actual_checkpoint_heads_v2(case, prepared.plan.project.ref) == checkpoint_before
        _phase_boundary_evidence_v2("pause-actual-unknown", {"schema": "phase.pause-unknown-acceptance.v1",
            "project_ref": pause.project_ref, "pause_operation": paused["operation_id"], "pause_original": pause.control_original_ref,
            "resume_operation": resumed["operation_id"], "actual_claim_digest": claim.claim_digest,
            "actual_terminal_digest": terminal.terminal_digest, "actual_terminal_status": terminal.status,
            "handoff_started": terminal.payload.handoff_started, "actual_adoption_operation": adopted["operation_id"],
            "job_retained": "pending_confirmation", "additional_provider_calls": 0, "additional_tool_handoffs": 0,
            "resume_state": "paused", "unknown_count": current["execution_summary"]["unknown"],
            "TTL_or_budget_renewed": False, "no_fabricated_wait_condition": True})
    await run_installed_m1_phase_case_v2(installed_m1_phase_fixture_v2, after_c02=after_c02, owner_controls=True)


@pytest.mark.asyncio
async def test_installed_method_v4_current_task_no_search_and_missing_gp1_hold(installed_m1_phase_fixture_v2):
    """Actual C1/D07 metadata, then a real missing-semantic refusal; no learned trial is seeded."""
    from m1_artifact_draft_acceptance_support_v1 import run_installed_m1_phase_case_v2
    from test_current_domain_production_v1 import domain_owner
    from sylanne3.graph_types import AtomKey, Owner
    from sylanne3.model_broker.first_ingress_encoding import FIRST_INGRESS_DEPENDENCY_ENCODING_TEMPLATE_VERSION
    from sylanne3.runtime.d01_method_learning_v1 import RegisterScopedMethodTrialRequestV1
    from sylanne3.runtime.d07_task_history_v1 import read_adopted_task_no_search_v1
    from sylanne3.runtime.foreground_cycle_v1 import foreground_cycle_from_wire_v1
    assert installed_m1_phase_fixture_v2.workflows.encode.template_version == FIRST_INGRESS_DEPENDENCY_ENCODING_TEMPLATE_VERSION

    async def after_c02(case):
        worker, bundle = case["phase_worker"], case["installed_bundle"]
        arguments = {"c02_operation_id": case["c02"].operation_id, "source_ref": case["source_ref"]}
        before_calls = tuple(case["phase_provider_calls"])
        before_accounting = _phase_accounting_snapshot_v2(case)
        need = await worker.call(lambda graph: graph.prepare_current_post_c02_recall_need_v1(
            case["bootstrap"], bundle, **arguments))
        assert need["receipt"]["receipt"]["status"] == "committed", need
        adopted = await worker.call(lambda graph: graph.run_current_post_c02_task_no_search_v1(
            case["bootstrap"], bundle, **arguments))
        assert adopted["status"] == "no_search" and adopted["receipt"]["receipt"]["status"] == "committed", adopted
        with cold_originals_v1(case) as db:
            saved = read_adopted_task_no_search_v1(db, namespace=case["namespace"], c02_operation_id=case["c02"].operation_id)
            assert saved is not None
            value, original = saved
            assert value.request.source_ref == case["source_ref"] and value.need.routing == "no_search"
            assert original["receipt"].operation_id == adopted["receipt"]["operation_id"]
            cycle_job = get_job(db, AtomKey.from_token(value.need.cycle_job_ref).name)
            cycle = foreground_cycle_from_wire_v1(cycle_job.continuation)
            assert not any(attempt.slot == "C3" for attempt in cycle.call_plan.attempts)
            missing_gp1 = AtomKey(Owner("activity", *case["namespace"].as_tuple, cycle.activity_id),
                "d07.current_interpretation.v1", "missing-gp1:" + str(uuid4())).token
            assert db.execute("SELECT 1 FROM graph_atoms WHERE token=?", (missing_gp1,)).fetchone() is None
            trial_count = db.execute("SELECT count(*) FROM graph_atoms WHERE bot=? AND persona=? AND type_name='d01.method_scoped_trial.v1'",
                case["namespace"].as_tuple).fetchone()
        assert tuple(case["phase_provider_calls"]) == before_calls
        assert _phase_accounting_snapshot_v2(case) == before_accounting

        def missing_semantic(graph):
            with domain_owner(case) as (authority, lease):
                result = graph.run_current_domain_operation_v1(authority, lease,
                    operation_kind="register_scoped_method_trial_v1", request=RegisterScopedMethodTrialRequestV1(missing_gp1),
                    operation_id=str(uuid4()), activity_id=cycle.activity_id, audience_ref="owner",
                    parent_budget_lease_ref=cycle.budget_ref)
                return result
        held = await worker.call(missing_semantic)
        assert held["schema"] == "sylanne.domain-production-receipt.v1" and held["coverage"] == "waiting_for_original", held
        assert held["missing_inputs"] == ["current_d07.current_interpretation.v1:" + AtomKey.from_token(missing_gp1).name]
        assert not held["receipt"]["write_versions"] and not held["job_states"] and not held["outbox"]
        with cold_originals_v1(case) as db:
            assert db.execute("SELECT count(*) FROM graph_atoms WHERE bot=? AND persona=? AND type_name='d01.method_scoped_trial.v1'",
                case["namespace"].as_tuple).fetchone() == trial_count
        assert tuple(case["phase_provider_calls"]) == before_calls
        assert _phase_accounting_snapshot_v2(case) == before_accounting
        _phase_boundary_evidence_v2("method-v4-no-search-missing-gp1", {"no_search_original_digest": adopted["original_digest"],
            "held": held, "trial_created": False, "measurement_created": False, "method_benefit": "unknown"})

    await run_installed_m1_phase_case_v2(installed_m1_phase_fixture_v2, after_c02=after_c02, owner_controls=True)


async def _actual_initial_method_task_choice_v2(case, *, expected_method_ref):
    """Start only the original registered task and its zero-C3 NoSearch route."""
    from m1_artifact_draft_acceptance_support_v1 import adopt_m1_phase_owner_project_role_v2
    from sylanne3.runtime.d07_task_history_v1 import read_adopted_task_no_search_v1
    from sylanne3.runtime.foreground_cycle_v1 import foreground_cycle_ids_v1, foreground_cycle_from_wire_v1
    worker, bundle = case["phase_worker"], case["installed_bundle"]
    arguments = {"c02_operation_id": case["c02"].operation_id, "source_ref": case["source_ref"]}
    created = await worker.call(lambda graph: graph.prepare_post_c02_foreground_cycle_v1(
        case["bootstrap"], bundle, **arguments))
    acquired = await worker.call(lambda graph: graph.acquire_post_c02_foreground_cycle_v1(
        case["bootstrap"], bundle, **arguments))
    assert created["receipt"]["status"] == acquired["receipt"]["status"] == "committed"
    calls, accounting = tuple(case["phase_provider_calls"]), _phase_accounting_snapshot_v2(case)
    need = await worker.call(lambda graph: graph.prepare_current_post_c02_recall_need_v1(
        case["bootstrap"], bundle, **arguments))
    assert need["receipt"]["receipt"]["status"] == "committed", need
    no_search = await worker.call(lambda graph: graph.run_current_post_c02_task_no_search_v1(
        case["bootstrap"], bundle, **arguments))
    assert no_search["status"] == "no_search" and no_search["receipt"]["receipt"]["status"] == "committed", no_search
    with cold_originals_v1(case) as db:
        original = read_adopted_task_no_search_v1(db, namespace=case["namespace"], c02_operation_id=case["c02"].operation_id)
        assert original is not None and original[0].request.source_ref == case["source_ref"]
        cycle = foreground_cycle_from_wire_v1(get_job(db, foreground_cycle_ids_v1(case["namespace"], case["c02"].operation_id)[1]).continuation)
        assert not any(row.slot == "C3" for row in cycle.call_plan.attempts)
    assert tuple(case["phase_provider_calls"]) == calls and _phase_accounting_snapshot_v2(case) == accounting
    for kind in ("create_artifact_task_plan_v1", "create_artifact_task_project_v1"):
        receipt = await worker.call(lambda graph: graph.run_current_post_c02_artifact_task_setup_v1(
            case["bootstrap"], bundle, operation_kind=kind, **arguments))
        assert receipt["receipt"]["status"] == "committed", receipt
    await worker.call(lambda graph: adopt_m1_phase_owner_project_role_v2(case))
    initialized = await worker.call(lambda graph: graph.run_current_post_c02_artifact_task_setup_v1(
        case["bootstrap"], bundle, operation_kind="initialize_artifact_task_project_checkpoint_v1", **arguments))
    assert initialized["receipt"]["status"] == "committed", initialized
    choice = await worker.call(lambda graph: graph.prepare_current_post_c02_artifact_phase_choice_v3(
        case["bootstrap"], bundle, **arguments))
    assert choice["status"] == "selected", choice
    selected = await _actual_phase_resume_v2(case)
    assert selected["selector"].method_ref == expected_method_ref and selected["selector"].phase_index == 0
    return choice


async def _actual_method_phase_check_v2(case, *, phase_kind, phase_index, expected_file_version):
    """Actual independent installed observer; checks do not dispatch a model."""
    from sylanne3.runtime.d11_artifact_draft_content_v1 import read_current_artifact_phase_verified_v2
    await _actual_phase_checkpoint_v2(case)
    selected = await _actual_phase_resume_v2(case)
    assert not selected["generation"] and (selected["selector"].phase_kind,
        selected["selector"].phase_index) == (phase_kind, phase_index)
    calls, accounting = tuple(case["phase_provider_calls"]), _phase_accounting_snapshot_v2(case)
    await _actual_phase_operation_v2(case, "observe_artifact_phase_postconditions_v1")
    observed = await _actual_phase_resume_v2(case)
    assert observed["assessment_registered"] and set(observed["assessment_statuses"]) == {"satisfied"}, observed
    await _actual_phase_operation_v2(case, "verify_artifact_draft_phase_v2")
    with cold_originals_v1(case) as db:
        verified = read_current_artifact_phase_verified_v2(db, namespace=case["namespace"],
            selector=observed["selector"], issuer=case["d11_issuer"])
        assert verified.method_qualified and verified.structurally_verified
        assert verified.readback == case["phase_generation_verified"].readback
        assert verified.readback.version == expected_file_version
    assert tuple(case["phase_provider_calls"]) == calls
    assert _phase_accounting_snapshot_v2(case) == accounting
    await _actual_phase_checkpoint_v2(case)
    return verified


async def _actual_first_method_milestone_v2(case, *, checked, expected_file_version):
    """The first semantic milestone may contain two physical sample/full versions."""
    from sylanne3.runtime.artifact_task_observer_v1 import (
        artifact_task_milestone_original_ref_v2, read_current_artifact_task_milestone_v2)
    from sylanne3.model_broker.artifact_draft_v1 import artifact_draft_phase_sequence_v2
    assert checked.selector.phase_kind == "check"
    await _actual_phase_operation_v2(case, "register_artifact_task_milestone_v2")
    with cold_originals_v1(case) as db:
        milestone = read_current_artifact_task_milestone_v2(db, namespace=case["namespace"],
            original_ref=artifact_task_milestone_original_ref_v2(checked.selector), issuer=case["d11_issuer"])
        assert milestone.semantic_index == 1 and milestone.file_version == expected_file_version
        assert milestone.prev_milestone_ref is milestone.amendment_ref is None
        assert milestone.full_check_original_ref == checked.original_ref
        assert milestone.full_check_original_digest == checked.digest
        assert milestone.file_result_ref == checked.readback_original_ref
        assert milestone.file_result_digest == checked.readback_original_digest
        assert len(milestone.ordered_phase_originals) == len(artifact_draft_phase_sequence_v2(checked.selector.method_ref))
    for kind in ("input:register_life_outcome_v2", "advance_life", "settle_project_checkpoint", "settle_personal_goal"):
        receipt = await case["phase_worker"].call(lambda graph:
            graph.run_current_post_c02_artifact_method_final_operation_v2(case["bootstrap"], case["installed_bundle"],
                c02_operation_id=case["c02"].operation_id, source_ref=case["source_ref"], operation_kind=kind))
        assert receipt["receipt"]["status"] == "committed", receipt
    completed = await case["phase_worker"].call(lambda graph:
        graph.read_current_completed_artifact_method_v2(case["bootstrap"], case["installed_bundle"],
            c02_operation_id=case["c02"].operation_id, source_ref=case["source_ref"]))
    assert completed["history_state"] == "partial"
    history = completed["history"]
    assert history.selector == milestone.selector and history.milestone_original_digest == milestone.digest
    assert history.file_result_ref == milestone.file_result_ref and history.file_result_digest == milestone.file_result_digest
    assert history.ordered_phase_originals == milestone.ordered_phase_originals
    assert history.completed_at_utc < history.original_deadline_utc == milestone.original_deadline_utc
    case.update(phase_method_milestone=milestone, phase_method_history=history)
    return milestone, history


@pytest.mark.asyncio
async def test_installed_method_growth_gp1_trial_preregistered_v2(installed_m1_phase_fixture_v2):
    """Actual independent Owner assessment and paid GP1 produce only scoped ST1.

    This node reaches no comparison or benefit. The separately prospective pair
    and physical method execution remain mandatory in the complete-method node.
    """
    from m1_artifact_draft_acceptance_support_v1 import (
        run_installed_m1_phase_case_v2, commit_actual_m1_phase_event_v2,
        register_actual_m1_method_trial_v2, install_actual_m1_c3_runtime_v2,
        M1_METHOD_TREATMENT_TEXT_V6, M1_METHOD_ASSESSMENT_TEXT_V6)
    from sylanne3.host.model_workflows_v6 import AdminModelWorkflowsV6
    from sylanne3.host.artifact_draft_paired_policy_v4 import AdminArtifactDraftPairedPolicyV4
    from sylanne3.domains.d01 import _activation_key, method_policy_state_v1
    assert type(installed_m1_phase_fixture_v2.workflows) is AdminModelWorkflowsV6
    assert type(installed_m1_phase_fixture_v2.artifact_draft) is AdminArtifactDraftPairedPolicyV4
    assert installed_m1_phase_fixture_v2.workflows.growth_cognition is not None
    async def after_c02(case):
        # Install on the parent case so its unconditional cleanup owns the real service.
        await install_actual_m1_c3_runtime_v2(case)
        with cold_originals_v1(case) as db:
            active_before = db.execute("SELECT revision,value FROM graph_atoms WHERE token=? AND valid=1",
                (_activation_key(case["namespace"]).token,)).fetchone()
        treatment = await commit_actual_m1_phase_event_v2(case, text=M1_METHOD_TREATMENT_TEXT_V6, scope_only=True)
        assessment = await commit_actual_m1_phase_event_v2(case, text=M1_METHOD_ASSESSMENT_TEXT_V6, scope_only=False)
        assert len({case["c02"].operation_id, treatment["c02"].operation_id, assessment["c02"].operation_id}) == 3
        assert len({case["source_ref"], treatment["source_ref"], assessment["source_ref"]}) == 3
        await register_actual_m1_method_trial_v2(assessment, treatment_case=treatment)
        case["phase_c3_runtime"] = assessment["phase_c3_runtime"]
        with cold_originals_v1(case) as db:
            assert db.execute("SELECT revision,value FROM graph_atoms WHERE token=? AND valid=1",
                (_activation_key(case["namespace"]).token,)).fetchone() == active_before
            assert db.execute("SELECT count(*) FROM graph_atoms WHERE bot=? AND persona=? AND type_name='d01.method_evaluation.v1'",
                case["namespace"].as_tuple).fetchone() == (0,)
            assert db.execute("SELECT count(*) FROM graph_atoms WHERE bot=? AND persona=? AND type_name='d01.method_experiment_plan.v1'",
                case["namespace"].as_tuple).fetchone() == (0,)
            assert db.execute("SELECT count(*) FROM runtime_jobs WHERE bot_id=? AND persona_id=? AND work_kind='artifact_draft_v1'",
                case["namespace"].as_tuple).fetchone() == (0,)
            plans = db.execute("SELECT value FROM graph_atoms WHERE bot=? AND persona=? AND type_name='d01.persona_plan.v1' AND valid=1",
                case["namespace"].as_tuple).fetchall()
            assert all(method_policy_state_v1(block["claim"]) == "ST0"
                for row in plans for block in json.loads(row[0])["blocks"] if block["block_id"] == "CP-tone-order")
        _phase_boundary_evidence_v2("actual_gp1_scoped_trial", {
            "schema": "fixture.method-gp1-boundary.v1", "trial_ref": assessment["method_trial_ref"],
            "gp1_ref": assessment["method_gp1_ref"], "proposal_ref": assessment["method_trial_proposal_ref"],
            "assessment_c02": assessment["c02"].operation_id, "baseline_c02": case["c02"].operation_id,
            "treatment_c02": treatment["c02"].operation_id, "global_strategy": "ST0",
            "trial_state": "scoped_trial", "source_scope": "LOCAL_FIXTURE", "method_benefit": "unknown",
            "comparison_reached": False, "simulated_provider_token_count": True})
    await run_installed_m1_phase_case_v2(installed_m1_phase_fixture_v2, after_c02=after_c02,
        owner_controls=True, prepare_artifact_scope_only=True)


async def _assert_actual_method_request_refusal_v2(case, *, kind, request, reason_fragment, expected_refusal):
    """Use actual Owner W01 against real existing prerequisites; never mutate a ledger."""
    from test_current_domain_production_v1 import domain_owner
    calls, accounting = tuple(case["phase_provider_calls"]), _phase_accounting_snapshot_v2(case)
    with cold_originals_v1(case) as db:
        before = (db.execute("SELECT count(*) FROM runtime_jobs").fetchone(),
            db.execute("SELECT count(*) FROM graph_domain_production_outbox_v1").fetchone())
    def refuse(graph):
        with domain_owner(case) as (authority, lease):
            result = graph.run_current_domain_operation_v1(authority, lease, operation_kind=kind,
                request=request, operation_id=str(uuid4()), activity_id="activity:m1-method-negative",
                audience_ref="owner", parent_budget_lease_ref=case["policy"].root_grant.lease_id)
        if expected_refusal:
            error = graph._GraphCoordinator__domain_production_runtime_v1._last_refusal_exception_v1
            assert reason_fragment in str(error), repr(error)
            assert result["schema"] == "sylanne.domain-production-refusal.v1" and result["status"] == "held", result
        else:
            assert result["schema"] == "sylanne.domain-production-receipt.v1" and result["coverage"] == "waiting_for_original", result
            assert reason_fragment in result["missing_inputs"] and not result["receipt"]["write_versions"], result
        assert not result["job_states"] and not result["outbox"], result
        return result
    held = await case["phase_worker"].call(refuse)
    with cold_originals_v1(case) as db:
        assert (db.execute("SELECT count(*) FROM runtime_jobs").fetchone(),
            db.execute("SELECT count(*) FROM graph_domain_production_outbox_v1").fetchone()) == before
    assert tuple(case["phase_provider_calls"]) == calls and _phase_accounting_snapshot_v2(case) == accounting
    return held


@pytest.mark.asyncio
async def test_installed_method_trial_sample_full_pair_measurement_unknown_benefit_v2(installed_m1_phase_fixture_v2):
    """Prospective actual pair, scoped GP1/ST1 and physical four-phase treatment.

    Local signed simulated bills verify mechanical causality and once charging.
    They never supply rework, elapsed time, blind review or production benefit.
    """
    from m1_artifact_draft_acceptance_support_v1 import (
        run_installed_m1_phase_case_v2, commit_actual_m1_phase_event_v2,
        install_actual_m1_c3_runtime_v2, register_actual_m1_method_trial_v2,
        run_actual_m1_owner_method_operation_v2, finish_actual_m1_method_assessment_reply_v2,
        run_actual_m1_phase_protected_reply_v2, M1_METHOD_TREATMENT_TEXT_V6, M1_METHOD_ASSESSMENT_TEXT_V6,
        M1_METHOD_SAMPLE_TEXT_V6, M1_METHOD_FULL_TEXT_V6)
    from sylanne3.host.model_workflows_v6 import AdminModelWorkflowsV6
    from sylanne3.host.artifact_draft_paired_policy_v4 import AdminArtifactDraftPairedPolicyV4
    from sylanne3.domains.d01 import FULL_DRAFT_METHOD_V1, TONE_SAMPLE_METHOD_V1, _activation_key, method_policy_state_v1
    from sylanne3.domains.d01.method_learning_v1 import (
        MethodExperimentPlanV1, MethodComparisonObservationV2, EXPERIMENT_TYPE,
        method_learning_key_v1)
    from sylanne3.domains.d01.production_operations_v1 import plain_v1
    from sylanne3.runtime.d01_method_learning_v1 import RegisterMethodExperimentRequestV2, EvaluateCurrentMethodOutcomeRequestV1
    from sylanne3.runtime.d11_method_observation_v1 import ObserveMethodComparisonRequestV1, KIND
    from sylanne3.runtime.domain_production_erasure_v1 import decode_typed_production_value_v1
    from sylanne3.runtime.domain_production_originals_v1 import read_adopted_domain_operation_v1
    from sylanne3.runtime.d11_life_preparation_v1 import TABLE, _read
    from sylanne3.runtime.method_pair_shared_input_v1 import read_method_pair_shared_input_original_v1
    from sylanne3.runtime.foreground_call_plan_v1 import foreground_reply_budget_ids_v1
    assert type(installed_m1_phase_fixture_v2.workflows) is AdminModelWorkflowsV6
    assert type(installed_m1_phase_fixture_v2.artifact_draft) is AdminArtifactDraftPairedPolicyV4

    async def after_c02(case):
        await install_actual_m1_c3_runtime_v2(case)
        with cold_originals_v1(case) as db:
            active_before = db.execute("SELECT revision,value FROM graph_atoms WHERE token=? AND valid=1",
                (_activation_key(case["namespace"]).token,)).fetchone()
        treatment = await commit_actual_m1_phase_event_v2(case, text=M1_METHOD_TREATMENT_TEXT_V6, scope_only=True)
        assessment = await commit_actual_m1_phase_event_v2(case, text=M1_METHOD_ASSESSMENT_TEXT_V6, scope_only=False)
        await register_actual_m1_method_trial_v2(assessment, treatment_case=treatment)
        def actual_objective(task_case):
            with cold_originals_v1(case) as db:
                rows = db.execute("SELECT original_ref FROM " + TABLE + " WHERE bot=? AND persona=? AND kind='artifact_task_objective' "
                    "AND json_extract(payload_json,'$.initial_c02_operation_id')=? LIMIT 2",
                    (*case["namespace"].as_tuple, task_case["c02"].operation_id)).fetchall()
                assert len(rows) == 1
                return _read(db, issuer=case["d11_issuer"], namespace=case["namespace"],
                    kind="artifact_task_objective", ref=rows[0][0])[0]
        baseline_objective, treatment_objective = actual_objective(case), actual_objective(treatment)
        protocol = assessment["method_protocol"]
        experiment = MethodExperimentPlanV1(case["namespace"], "m1-experiment:" + uuid4().hex,
            assessment["method_trial_ref"], assessment["method_protocol_ref"], canonical_digest(plain_v1(protocol)),
            treatment_objective["goal_ref"], baseline_objective["goal_ref"], TONE_SAMPLE_METHOD_V1, FULL_DRAFT_METHOD_V1,
            assessment["source_ref"], case["policy"].root_grant.lease_id,
            (assessment["source_ref"], case["source_ref"], treatment["source_ref"]),
            min(protocol.valid_until, baseline_objective["valid_until_utc"], treatment_objective["valid_until_utc"]))
        # A real protected reply child exists, but cannot masquerade as the experiment Root.
        wrong_budget = replace(experiment, experiment_id="m1-negative-budget:" + uuid4().hex,
            parent_budget_lease_ref=foreground_reply_budget_ids_v1(case["namespace"], assessment["c02"].operation_id)[0])
        budget_held = await _assert_actual_method_request_refusal_v2(case, kind="register_method_experiment_v2",
            request=RegisterMethodExperimentRequestV2(wrong_budget), reason_fragment="parent budget", expected_refusal=True)
        registered = await case["phase_worker"].call(lambda graph: run_actual_m1_owner_method_operation_v2(assessment,
            "register_method_experiment_v2", RegisterMethodExperimentRequestV2(experiment), producer=False))
        experiment_ref = method_learning_key_v1(case["namespace"], EXPERIMENT_TYPE, experiment.experiment_id).token
        with cold_originals_v1(case) as db:
            shared, original = read_method_pair_shared_input_original_v1(db, namespace=case["namespace"], experiment_ref=experiment_ref)
            assert shared.operation_id == registered["operation_id"] and shared.common_source_head.key.token == assessment["source_ref"]
            assert tuple(item.goal_head.key.token for item in shared.tasks) == (experiment.treatment_goal_ref, experiment.baseline_goal_ref)
            assert original["receipt"].commit_seq == registered["receipt"]["commit_seq"]
        await finish_actual_m1_method_assessment_reply_v2(assessment)
        await _actual_initial_method_task_choice_v2(case, expected_method_ref=FULL_DRAFT_METHOD_V1)
        await _actual_generation_phase_file_readback_v2(case, expected_content=M1_METHOD_FULL_TEXT_V6,
            expected_version=1, expected_method_ref=FULL_DRAFT_METHOD_V1, expected_phase_kind="full", expected_phase_index=0)
        checked_baseline = await _actual_method_phase_check_v2(case, phase_kind="check", phase_index=1, expected_file_version=1)
        baseline, _ = await _actual_first_method_milestone_v2(case, checked=checked_baseline, expected_file_version=1)
        # The real waiting checkpoint releases the baseline worker before the second task runs.
        await run_actual_m1_phase_protected_reply_v2(case)
        await _actual_initial_method_task_choice_v2(treatment, expected_method_ref=TONE_SAMPLE_METHOD_V1)
        await _actual_generation_phase_file_readback_v2(treatment, expected_content=M1_METHOD_SAMPLE_TEXT_V6,
            expected_version=1, expected_method_ref=TONE_SAMPLE_METHOD_V1, expected_phase_kind="tone_sample", expected_phase_index=0)
        sample = await _actual_method_phase_check_v2(treatment, phase_kind="sample_check", phase_index=1, expected_file_version=1)
        assert sample.method_qualified
        await _actual_generation_phase_file_readback_v2(treatment, expected_content=M1_METHOD_FULL_TEXT_V6,
            expected_version=2, expected_method_ref=TONE_SAMPLE_METHOD_V1, expected_phase_kind="full", expected_phase_index=2)
        checked_treatment = await _actual_method_phase_check_v2(treatment, phase_kind="check", phase_index=3, expected_file_version=2)
        measured_treatment, _ = await _actual_first_method_milestone_v2(treatment, checked=checked_treatment, expected_file_version=2)
        assert baseline.project_ref != measured_treatment.project_ref
        assert baseline.goal_ref != measured_treatment.goal_ref and baseline.file_version == 1 and measured_treatment.file_version == 2
        late = replace(experiment, experiment_id="m1-late-experiment:" + uuid4().hex)
        late_held = await _assert_actual_method_request_refusal_v2(case, kind="register_method_experiment_v2",
            request=RegisterMethodExperimentRequestV2(late), reason_fragment="prospective_uncompleted_method_comparison_goals", expected_refusal=False)
        missing_request = EvaluateCurrentMethodOutcomeRequestV1(experiment_ref, measured_treatment.original_ref,
            baseline.original_ref, "method-comparison-observation:missing:" + uuid4().hex, ())
        missing_held = await _assert_actual_method_request_refusal_v2(case, kind="evaluate_current_method_outcome_v1",
            request=missing_request, reason_fragment="actual_installed_method_comparison_observer_original", expected_refusal=False)
        observed = await case["phase_worker"].call(lambda graph: run_actual_m1_owner_method_operation_v2(case,
            "observe_method_comparison_v1", ObserveMethodComparisonRequestV1(experiment_ref,
                measured_treatment.original_ref, baseline.original_ref), producer=False))
        assert observed["coverage"] == "complete", observed
        with cold_originals_v1(case) as db:
            rows = db.execute("SELECT original_ref FROM " + TABLE + " WHERE bot=? AND persona=? AND kind=? AND producing_operation_id=?",
                (*case["namespace"].as_tuple, KIND, observed["operation_id"])).fetchall()
            assert len(rows) == 1
            measurement_ref = rows[0][0]
            raw = _read(db, issuer=case["d11_issuer"], namespace=case["namespace"], kind=KIND, ref=measurement_ref)[0]
            measurement = decode_typed_production_value_v1(raw, MethodComparisonObservationV2)
            assert measurement.source_scope == "LOCAL_FIXTURE"
            assert all(getattr(measurement.metrics, name) is None for name in (
                "rework_units", "baseline_rework_units", "first_full_elapsed_ms", "baseline_first_full_elapsed_ms",
                "discarded_generated_units", "baseline_discarded_generated_units", "network_wait_ms", "user_wait_ms"))
            assert len(measurement.treatment_call_refs) == 2 and len(measurement.baseline_call_refs) == 1
            assert not set(measurement.treatment_call_refs) & set(measurement.baseline_call_refs)
            assert measurement.metrics.model_input_tokens > 0 and measurement.metrics.model_output_tokens == 10
            source = json.loads(db.execute("SELECT value FROM graph_atoms WHERE token=? AND valid=1",
                (measurement.source_refs[0],)).fetchone()[0])
            assert (source["source_kind"], source["assertion_status"], source["independence"]) == ("internal", "confirmed", "same_root")
            assert source["parent_source_ids"] and source["provenance_root"] == measurement.measurement_family_ref
            producer = read_adopted_domain_operation_v1(db, case["namespace"], observed["operation_id"])
            assert producer["payload"]["provenance"]["method_comparison_observation"] == raw
        evaluation = await case["phase_worker"].call(lambda graph: run_actual_m1_owner_method_operation_v2(case,
            "evaluate_current_method_outcome_v1", replace(missing_request, measurement_original_ref=measurement_ref), producer=False))
        assert evaluation["coverage"] == "partial" and "production_method_observer_qualification" in evaluation["missing_inputs"]
        with cold_originals_v1(case) as db:
            raw_evaluation = read_adopted_domain_operation_v1(db, case["namespace"], evaluation["operation_id"])["payload"]["provenance"]["method_evaluation"]
            assert raw_evaluation["method_benefit"] == "unknown" and not raw_evaluation["blind_reviews"]
            assert db.execute("SELECT revision,value FROM graph_atoms WHERE token=? AND valid=1",
                (_activation_key(case["namespace"]).token,)).fetchone() == active_before
            for row in db.execute("SELECT value FROM graph_atoms WHERE bot=? AND persona=? AND type_name='d01.persona_plan.v1' AND valid=1", case["namespace"].as_tuple):
                for block in json.loads(row[0])["blocks"]:
                    if block["block_id"] == "CP-tone-order": assert method_policy_state_v1(block["claim"]) == "ST0"
        _phase_boundary_evidence_v2("actual_method_pair_measurement", {
            "schema": "fixture.actual-method-comparison.v2", "experiment_ref": experiment_ref,
            "trial_ref": assessment["method_trial_ref"], "gp1_ref": assessment["method_gp1_ref"],
            "baseline_milestone": plain_v1(baseline), "treatment_milestone": plain_v1(measured_treatment),
            "measurement": plain_v1(measurement), "evaluation": raw_evaluation,
            "negative_budget": budget_held, "late_experiment": late_held, "missing_measurement": missing_held,
            "global_strategy": "ST0", "method_benefit": "unknown", "source_scope": "LOCAL_FIXTURE",
            "assessment_cycle_phase": assessment["method_assessment_cycle_phase"],
            "full_main_startup_qualified": False, "simulated_provider_token_count": True})
    await run_installed_m1_phase_case_v2(installed_m1_phase_fixture_v2, after_c02=after_c02,
        owner_controls=True, prepare_artifact_scope_only=True)
