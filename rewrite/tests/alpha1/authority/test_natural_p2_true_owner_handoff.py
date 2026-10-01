"""Natural P2 handoff on one real Owner, mTLS and graph installation.

The paid-consumer readiness methods are an explicit controlled prerequisite;
the installed V2FencePort does not yet advertise these natural capabilities.
Owner, paid ledger, graph claim and AstrBot sender use installed implementations;
the OneBot adapter response is controlled by this test.
"""

import asyncio
from dataclasses import replace
import json
from pathlib import Path
import sys
import time

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "runtime"))
from test_post_c02_reply_assembly_v2 import (  # noqa: E402
    test_paired_reply_assembly_uses_real_c02_and_reply_admission as real_owner_case,
)
from tests.alpha1.runtime.test_d12_true_owner_d09_adoption import (
    _adopt_d09_workbench,
)

from sylanne3.model_broker.natural_reply_history_v4 import TEMPLATE_VERSION
from sylanne3.model_broker.natural_review import REVIEW_TEMPLATE_VERSION
from sylanne3.authority_service.v2_model_egress_contract import HostObservedModelCompletionV2
from sylanne3.authority_service.v2_natural_generation_output_service import (
    AuthorityV2NaturalGenerationOutputService,
    PinnedNaturalGenerationOriginalPaidVerifierV2,
)
from sylanne3.authority_service.v2_natural_generation_content_service import (
    AuthorityV2NaturalGenerationContentService,
    PinnedCurrentNaturalGenerationContentVerifierV2,
)
from sylanne3.authority_service.v2_natural_review_output_service import (
    AuthorityV2NaturalReviewOutputService,
    PinnedNaturalReviewOriginalPaidVerifierV2,
)
from sylanne3.authority_service.v2_natural_paid_review_service import (
    AuthorityV2NaturalPaidReviewService,
    PinnedCurrentNaturalPaidReviewVerifierV2,
)
from sylanne3.model_broker.natural_reply import OUTPUT_SCHEMA
from sylanne3.model_broker.natural_review import OUTPUT_SCHEMA as REVIEW_OUTPUT_SCHEMA
from sylanne3.runtime_contracts import AuthorityContext, canonical_digest, canonical_serialize
from sylanne3.graph_worker import GraphWorker
from sylanne3.graph_coordinator import UnavailableGuard
from sylanne3.host.installed_dispatch_route import InstalledDispatchRoutePort
from sylanne3.host.natural_reply_dispatch_driver import (
    InstalledNaturalReplyContinuationV2, NaturalReplyDispatchDriverV2,
)
from sylanne3.host.owner_revoke_orchestration import (
    installed_owner_revoke_orchestrator_v2,
)


def _pay_generation(case, saved):
    graph = case["graph"]
    namespace = case["namespace"]
    bundle = case["installed_bundle"]
    workflow = bundle.model_workflows.natural_generation
    plan = saved.frozen.input.plan
    unit = plan.units[0]
    speech_act = next(value for value in plan.allowed_speech_acts
                      if value != "promise")
    body = unit.qualified_text
    output = canonical_serialize({
        "schema": OUTPUT_SCHEMA, "body": body,
        "units": [{"start": 0, "end": len(body),
                   "kind": unit.kind.value, "basis_ids": [unit.basis_id],
                   "speech_act": speech_act, "promise_grant_id": None,
                   "slot_ids": list(plan.required_slots)}],
    })
    activation = graph._v2_graph_stamp(namespace)[0].requirements.activation_generation
    lease, capability = graph.grant(
        case["bootstrap"], actor=case["client_grant"].subject,
        issuer_domain="d11", namespace=namespace, domains=("d11",),
        activation_generation=activation,
        operation_id=saved.seal.acquire_operation_id)
    authority = AuthorityContext(
        case["client_grant"].subject, "d11", capability, namespace,
        ("activity",), "proposal", (plan.audience_id,),
        workflow.provider_config_ref, activation)
    try:
        job, call = graph.acquire_post_c02_natural_generation_v2(
            authority, lease, case["c02"].operation_id, bundle,
            lease_seconds=60)
        assert job.phase == "running"
        worker = replace(authority, worker_fence=job.fence)
        current_call, draft, anchor = graph.read_natural_model_egress_preparation_v2(
            worker, lease, case["c02"].operation_id, "generation", bundle)
        assert current_call == call
        service = case["model_service"]
        peer = case["peer"]
        holder = case["policy"].administrator_holder
        prepared, permit = service.prepare_fenced(
            credential=peer, subject=draft.subject, holder=holder,
            draft=draft, expected_anchor=anchor,
            installation_id=saved.seal.installation_id)
        intent = prepared.intent
        _, admitted_permit, admission = service.admit_dispatch_once_v2(
            credential=peer, subject=draft.subject, holder=holder,
            intent=intent, expected_anchor=anchor, request=call,
            installation_id=saved.seal.installation_id,
            observer_peer_sha256=peer.certificate_sha256,
            observer_profile_id="reply",
            manifest_digest=case["policy"].manifest_digest,
            host_incarnation="3" * 64)
        assert admitted_permit == permit
        report = HostObservedModelCompletionV2(
            admission.admission_id, admission.host_incarnation,
            intent.call_id, intent.request_digest, intent.provider_id,
            intent.model_id, intent.provider_config_digest,
            canonical_serialize({"text": output}),
            (("output_tokens", 1),), (), "controlled-natural-provider-call")
        observed, finished_permit, terminal = service.complete_observed_v2(
            credential=peer, subject=draft.subject, holder=holder,
            intent=intent, expected_anchor=anchor, admission=admission,
            report=report, installation_id=saved.seal.installation_id,
            observer_peer_sha256=peer.certificate_sha256,
            observer_profile_id="reply",
            manifest_digest=case["policy"].manifest_digest)
        assert finished_permit == permit
        quote_id, quote_version = job.operator_versions["resource_quote"].rsplit(":", 1)
        cost = graph.commit_natural_generation_model_cost_v2(
            case["bootstrap"], namespace, intent,
            quote_id=quote_id, quote_version=int(quote_version))
        assert cost.status == "committed"
        return authority, lease, job, call, intent, terminal, output, body
    except BaseException:
        graph.release_authority_lease(case["bootstrap"], lease)
        raise


def _complete_generation(case, saved, paid):
    graph, namespace = case["graph"], case["namespace"]
    intent = paid[4]
    reader = AuthorityV2NaturalGenerationOutputService(
        store=case["model_service"]._store,
        fences=case["protected"],
        graph_verifier=PinnedNaturalGenerationOriginalPaidVerifierV2(
            case["store"]._db.execute("PRAGMA database_list").fetchone()[2]),
        installation_id=saved.seal.installation_id,
        read_subject=intent.subject,
        holder=case["policy"].administrator_holder,
        trusted_now_utc=time.time,
    )
    graph._GraphCoordinator__natural_generation_output_port = (
        lambda request, *, now_utc:
            reader.read_original_natural_generation_output_v2(
                credential=case["peer"], request=request, now_utc=now_utc))
    operation_id = "natural-generation-terminal-" + canonical_digest({
        "namespace": namespace.as_tuple,
        "original_operation_id": saved.seal.original_operation_id,
    })[:48]
    activation = graph._v2_graph_stamp(namespace)[0].requirements.activation_generation
    lease, capability = graph.grant(
        case["bootstrap"], actor=case["client_grant"].subject,
        issuer_domain="d11", namespace=namespace, domains=("d11",),
        activation_generation=activation, operation_id=operation_id)
    authority = replace(paid[0], capability_ref=capability, worker_fence=None)
    try:
        completed = graph.complete_natural_generation_model_job_v2(
            authority, lease, case["c02"].operation_id, intent,
            case["installed_bundle"])
        assert completed.phase == "completed"
        output = graph.read_natural_generation_terminal_receipt_v2(
            authority, lease, case["c02"].operation_id,
            case["installed_bundle"])
        assert output.output_digest == canonical_digest(json.loads(paid[6]))
        return reader, authority, lease, output
    except BaseException:
        graph.release_authority_lease(case["bootstrap"], lease)
        raise


def _prepare_review(case, saved, completed):
    graph = case["graph"]
    path = case["store"]._db.execute("PRAGMA database_list").fetchone()[2]
    content = AuthorityV2NaturalGenerationContentService(
        original=completed[0],
        graph=PinnedCurrentNaturalGenerationContentVerifierV2(path, natural_history_verifier=case["model_service"]._graph_verifier._natural_history),
        trusted_now_utc=time.time)
    graph._GraphCoordinator__natural_generation_content_port = (
        lambda request, *, now_utc:
            content.read_current_natural_generation_content_v2(
                credential=case["peer"], request=request, now_utc=now_utc))
    review = graph.prepare_post_c02_natural_review_v2(
        completed[1], completed[2], case["c02"].operation_id,
        case["installed_bundle"])
    assert review.state == "queued"
    return content, review


def _pay_review(case, review):
    graph, namespace = case["graph"], case["namespace"]
    bundle = case["installed_bundle"]
    workflow = bundle.model_workflows.natural_review
    activation = graph._v2_graph_stamp(namespace)[0].requirements.activation_generation
    lease, capability = graph.grant(
        case["bootstrap"], actor=case["client_grant"].subject,
        issuer_domain="d11", namespace=namespace, domains=("d11",),
        activation_generation=activation,
        operation_id=review.seal.acquire_operation_id)
    authority = AuthorityContext(
        case["client_grant"].subject, "d11", capability, namespace,
        ("activity",), "proposal", (case["ingress"].conversation_ref,),
        workflow.provider_config_ref, activation)
    try:
        job, call = graph.acquire_post_c02_natural_review_v2(
            authority, lease, case["c02"].operation_id, bundle,
            lease_seconds=60)
        assert job.phase == "running"
        current_call, draft, anchor = graph.read_natural_model_egress_preparation_v2(
            replace(authority, worker_fence=job.fence), lease,
            case["c02"].operation_id, "review", bundle)
        assert current_call == call
        service = case["model_service"]
        peer = case["peer"]
        holder = case["policy"].administrator_holder
        prepared, permit = service.prepare_fenced(
            credential=peer, subject=draft.subject, holder=holder,
            draft=draft, expected_anchor=anchor,
            installation_id=review.seal.installation_id)
        intent = prepared.intent
        _, admitted_permit, admission = service.admit_dispatch_once_v2(
            credential=peer, subject=draft.subject, holder=holder,
            intent=intent, expected_anchor=anchor, request=call,
            installation_id=review.seal.installation_id,
            observer_peer_sha256=peer.certificate_sha256,
            observer_profile_id="reply",
            manifest_digest=case["policy"].manifest_digest,
            host_incarnation="4" * 64)
        assert admitted_permit == permit
        output = canonical_serialize({
            "schema": REVIEW_OUTPUT_SCHEMA, "verdict": "pass", "issues": []})
        report = HostObservedModelCompletionV2(
            admission.admission_id, admission.host_incarnation,
            intent.call_id, intent.request_digest, intent.provider_id,
            intent.model_id, intent.provider_config_digest,
            canonical_serialize({"text": output}),
            (("output_tokens", 1),), (), "controlled-natural-review-call")
        observed, finished_permit, terminal = service.complete_observed_v2(
            credential=peer, subject=draft.subject, holder=holder,
            intent=intent, expected_anchor=anchor, admission=admission,
            report=report, installation_id=review.seal.installation_id,
            observer_peer_sha256=peer.certificate_sha256,
            observer_profile_id="reply",
            manifest_digest=case["policy"].manifest_digest)
        assert finished_permit == permit
        quote_id, quote_version = job.operator_versions["resource_quote"].rsplit(":", 1)
        cost = graph.commit_natural_review_model_cost_v2(
            case["bootstrap"], namespace, intent,
            quote_id=quote_id, quote_version=int(quote_version))
        assert cost.status == "committed"
        return authority, lease, job, call, intent, terminal, output
    except BaseException:
        graph.release_authority_lease(case["bootstrap"], lease)
        raise


def _complete_review_and_final(case, generation_reader, review, paid):
    graph, namespace = case["graph"], case["namespace"]
    path = case["store"]._db.execute("PRAGMA database_list").fetchone()[2]
    review_reader = AuthorityV2NaturalReviewOutputService(
        store=case["model_service"]._store,
        fences=case["protected"],
        graph_verifier=PinnedNaturalReviewOriginalPaidVerifierV2(path),
        installation_id=review.seal.installation_id,
        read_subject=paid[4].subject,
        holder=case["policy"].administrator_holder,
        trusted_now_utc=time.time)
    graph._GraphCoordinator__natural_review_output_port = (
        lambda request, *, now_utc:
            review_reader.read_original_natural_review_output_v2(
                credential=case["peer"], request=request, now_utc=now_utc))
    terminal_id = "natural-review-terminal-" + canonical_digest({
        "namespace": namespace.as_tuple,
        "original_operation_id": review.seal.original_operation_id,
    })[:48]
    activation = graph._v2_graph_stamp(namespace)[0].requirements.activation_generation
    terminal_lease, cap = graph.grant(
        case["bootstrap"], actor=case["client_grant"].subject,
        issuer_domain="d11", namespace=namespace, domains=("d11",),
        activation_generation=activation, operation_id=terminal_id)
    authority = replace(paid[0], capability_ref=cap, worker_fence=None)
    try:
        finished = graph.complete_natural_review_model_job_v2(
            authority, terminal_lease, case["c02"].operation_id,
            paid[4], case["installed_bundle"])
        assert finished.phase == "completed"
        durable = graph.read_natural_review_terminal_receipt_v2(
            authority, terminal_lease, case["c02"].operation_id,
            case["installed_bundle"])
        assert durable.verdict == "pass"
        assert durable.output_digest == canonical_digest(json.loads(paid[6]))
        paid_service = AuthorityV2NaturalPaidReviewService(
            generation=generation_reader, review=review_reader,
            graph=PinnedCurrentNaturalPaidReviewVerifierV2(path, natural_history_verifier=case["model_service"]._graph_verifier._natural_history),
            trusted_now_utc=time.time)
        graph._GraphCoordinator__natural_paid_review_current_port = (
            lambda request, *, now_utc:
                paid_service.read_current_natural_paid_review_v2(
                    credential=case["peer"], request=request,
                    now_utc=now_utc))
        candidate = graph.read_current_natural_final_candidate_v2(
            authority, terminal_lease, case["c02"].operation_id,
            case["installed_bundle"])
        assert candidate.status == "candidate_hold_w01_final_admission"
        assert candidate.material is not None
        return candidate
    finally:
        graph.release_authority_lease(case["bootstrap"], terminal_lease)


def _commit_final(case, candidate):
    graph, namespace = case["graph"], case["namespace"]
    material = candidate.material
    assert material is not None
    activation = graph._v2_graph_stamp(namespace)[0].requirements.activation_generation
    lease, capability = graph.grant(
        case["bootstrap"], actor=case["client_grant"].subject,
        issuer_domain="d11", namespace=namespace,
        domains=("d08", "d09", "d11"),
        activation_generation=activation,
        operation_id=material.final_operation_id)
    authority = AuthorityContext(
        case["client_grant"].subject, "d11", capability, namespace,
        ("activity",), "expression", (material.audience_id,),
        case["policy"].root_grant.policy_ref, activation)
    try:
        receipt = graph.commit_post_c02_natural_final_v2(
            authority, lease, case["c02"].operation_id,
            case["installed_bundle"])
        assert receipt.status == "committed"
        assert receipt.operation_id == material.final_operation_id
        committed = graph.read_committed_natural_dispatch_v2(
            authority, lease, material.final_operation_id)
        assert committed is not None
        assert committed[1].effect_id == material.final_effect_id
        assert committed[3].operation_id == material.final_operation_id
        return authority, lease, receipt, committed
    except BaseException:
        graph.release_authority_lease(case["bootstrap"], lease)
        raise


class _BorrowedFixtureStore:
    """Temporary workers do not own the outer fixture's shared installation.

    Worker/continuation restart is exercised below. Actual Authority database
    close/reopen is covered separately by test_natural_paid_daemon_reopen.
    """
    def close(self):
        pass


async def _fixture_worker(case):
    return await GraphWorker.start(_BorrowedFixtureStore, lambda _store: case["graph"])


async def _revoke_owner_after_final(case, final):
    assert final[2].status == "committed"
    worker = await _fixture_worker(case)
    try:
        orchestrator = installed_owner_revoke_orchestrator_v2(
            graph=case["graph"], bootstrap=case["bootstrap"],
            namespace=case["namespace"], graph_worker=worker,
            revoke_port=case["port"])
        committed = await orchestrator.revoke(
            operation_id="owner-revoke-natural-p2",
            owner_session_token=case["owner_session_token"],
            owner_session_request=case["owner_session_request"])
        assert committed.phase == "committed"
        assert committed.operation.action == "revoke"
        assert committed.operation.grant_id == case["owner_issue_operation"].grant_id
        assert committed.grant_revision == 2
        assert committed.graph_access_epoch > (
            case["owner_issue_committed"].graph_access_epoch)
        current = await asyncio.to_thread(
            case["port"].get_committed_owner_revoke,
            namespace=case["namespace"],
            authority_namespace=case["authority_namespace"],
            operation_id=committed.operation.operation_id,
            owner_session_token=case["owner_session_token"],
            owner_session_request=case["owner_session_request"])
        assert current == committed
    finally:
        await worker.close()


async def _host_one_shot(case, final, expected_body, onebot_outcome,
                         sends=None, *, expected_promoted_c02=None):
    graph, store = case["graph"], case["store"]
    authority, lease, receipt, _committed = final
    if sends is None:
        sends = []

    async def onebot(action, **kwargs):
        if action == "send_private_msg":
            sends.append((action, kwargs))
            if onebot_outcome == "unknown":
                raise TimeoutError("OneBot response unavailable")
            return {"message_id": 9043}
        return {"user_id": "10001"}

    case["adapter"].bot.call_action.side_effect = onebot
    current_grant = await asyncio.to_thread(
        lambda: case["port"].installation_grant)
    assert current_grant.authority_id == case["policy"].expected_authority_id
    route_port = InstalledDispatchRoutePort(
        context=case["host_context"], host_loop=asyncio.get_running_loop(),
        candidates=case["observed"], coordinator=graph,
        authority=authority, lease=lease, policy=case["policy"],
        grant=current_grant)
    worker = await _fixture_worker(case)
    try:
        focus_before = await worker.call(lambda _graph: store._db.execute(
            "SELECT revision,value FROM graph_atoms WHERE bot=? AND persona=? "
            "AND type_name='d07.focus.v1'",
            case["namespace"].as_tuple,
        ).fetchone())
        writer = await worker.call(
            lambda current_graph:
                current_graph.register_natural_dispatch_final_claim_writer_v2(
                    case["bootstrap"], route_port=route_port,
                    issuer_id="issuer:reply"))
        continuation = InstalledNaturalReplyContinuationV2(
            worker=worker, authority=authority, lease=lease,
            fence_port=case["port"], policy=case["policy"],
            grant=current_grant, server=case["reverse_server"],
            natural_claim_writer=writer, context=case["host_context"],
            candidates=case["observed"],
            clock_policy=case["ingress_clock"],
            adapter_ref="adapter:platform-1")
        driver = NaturalReplyDispatchDriverV2(worker, authority, lease,
                                               continuation)
        result = await driver.run_once(operation_id=receipt.operation_id)
        if onebot_outcome == "observation_ack_lost_restarted":
            assert result.status == "hold", result.reason
            assert len(sends) == 1
            current = await asyncio.to_thread(
                case["port"].read_current_effect,
                namespace=case["namespace"],
                authority_namespace=case["authority_namespace"],
                effect_id=_committed[1].effect_id)
            assert current.state == "observed"
        if onebot_outcome in {"revoked", "revoked_restarted", "pending"}:
            assert result.status == "hold", result.reason
            assert sends == []
            current = await asyncio.to_thread(
                case["port"].read_current_effect,
                namespace=case["namespace"],
                authority_namespace=case["authority_namespace"],
                effect_id=_committed[1].effect_id)
            assert current.state == (
                "unresolved" if onebot_outcome == "pending" else "absent")
            replay = await driver.run_once(operation_id=receipt.operation_id)
            assert replay.status == "hold"
            assert sends == []
        elif onebot_outcome != "observation_ack_lost_restarted":
            assert result.status == (
                "unknown" if onebot_outcome == "observation_ack_lost"
                else onebot_outcome), result.reason
            assert result.original is not None
            assert result.original.payload.payload.decode("utf-8") == expected_body
            assert sends == [("send_private_msg", {
                "self_id": "10001", "user_id": 123456,
                "message": [{"type": "text", "data": {"text": expected_body}}],
            })]
            current = await asyncio.to_thread(
                case["port"].read_current_effect,
                namespace=case["namespace"],
                authority_namespace=case["authority_namespace"],
                effect_id=result.original.effect_id)
            assert current.state == "observed"
            replay = await driver.run_once(operation_id=receipt.operation_id)
            assert replay.status == "hold"
            assert len(sends) == 1
            if onebot_outcome in {"accepted", "unknown"}:
                outbound = await worker.call(lambda current_graph:
                    current_graph.record_natural_outbound_observation_v1(
                        case["bootstrap"], case["namespace"], receipt.operation_id))
                assert outbound == {"status": "committed", "observation_outcome": onebot_outcome}
                outbound_replay = await worker.call(lambda current_graph:
                    current_graph.record_natural_outbound_observation_v1(
                        case["bootstrap"], case["namespace"], receipt.operation_id))
                assert outbound_replay == {"status": "duplicate", "observation_outcome": onebot_outcome}
                actual_outbound = await worker.call(lambda _graph:
                    store._db.execute("SELECT observation_json FROM graph_d13_outbound_observations_v1 "
                        "WHERE bot=? AND persona=? AND final_operation_id=?",
                        (*case["namespace"].as_tuple, receipt.operation_id)).fetchone())
                from sylanne3.authority_service.v2_contract import from_wire as decode_observation
                actual_observation = decode_observation(json.loads(actual_outbound[0]))
                assert actual_observation.pending.binding is None
                assert actual_observation.pending.platform_observation.outcome == onebot_outcome
                if onebot_outcome == "accepted":
                    with pytest.raises(UnavailableGuard):
                        await worker.call(lambda current_graph:
                            current_graph.complete_observed_natural_attention_v2(
                                case["bootstrap"], case["namespace"],
                                receipt.operation_id + "-wrong"))
                    completed_focus = await worker.call(lambda current_graph:
                        current_graph.complete_observed_natural_attention_v2(
                            case["bootstrap"], case["namespace"],
                            receipt.operation_id))
                    assert completed_focus.status == "committed"
                    assert completed_focus.focus_revision == focus_before[0] + 1
                    assert (completed_focus.promoted_c02_operation_id
                            == expected_promoted_c02)
                    duplicate = await worker.call(lambda current_graph:
                        current_graph.complete_observed_natural_attention_v2(
                            case["bootstrap"], case["namespace"],
                            receipt.operation_id))
                    assert duplicate.status == "duplicate"
                    focus_after = await worker.call(lambda _graph:
                        store._db.execute(
                            "SELECT value FROM graph_atoms WHERE bot=? AND persona=? "
                            "AND type_name='d07.focus.v1'",
                            case["namespace"].as_tuple,
                        ).fetchone())
                    assert json.loads(focus_after[0])["primary_ticket_ref"] == (
                        completed_focus.promoted_ticket_ref)
                    if expected_promoted_c02 is not None:
                        page = await worker.call(lambda current_graph:
                            current_graph.discover_released_post_c02_attention_v2(
                                case["bootstrap"], case["namespace"],
                                case["installed_bundle"], limit=1))
                        assert len(page.items) == 1
                        assert page.items[0].c02_operation_id == expected_promoted_c02
                        assert page.items[0].ticket_ref == (
                            completed_focus.promoted_ticket_ref)
                else:
                    with pytest.raises(UnavailableGuard, match="observation"):
                        await worker.call(lambda current_graph:
                            current_graph.complete_observed_natural_attention_v2(
                                case["bootstrap"], case["namespace"],
                                receipt.operation_id))
                    assert await worker.call(lambda _graph: store._db.execute(
                        "SELECT revision,value FROM graph_atoms WHERE bot=? AND "
                        "persona=? AND type_name='d07.focus.v1'",
                        case["namespace"].as_tuple,
                    ).fetchone()) == focus_before
    finally:
        await worker.close()
    if onebot_outcome == "revoked":
        await _host_one_shot(
            case, final, expected_body, "revoked_restarted", sends)
    if onebot_outcome == "observation_ack_lost":
        await _host_one_shot(
            case, final, expected_body, "observation_ack_lost_restarted", sends)


async def _run_true_owner_natural_case(
    tmp_path, monkeypatch, onebot_outcome, *, d09_policy_max=None,
    reply_text="hello",
):
    def workflows(base, _model_shared):
        return replace(
            base,
            natural_generation=replace(base.reply, work_kind="natural_generation",
                                       template_version=TEMPLATE_VERSION),
            natural_review=replace(base.reply, work_kind="natural_review",
                                   template_version=REVIEW_TEMPLATE_VERSION),
        )

    async def after_c02(case):
        port = case["port"]
        namespace = case["namespace"]
        from d13_natural_fixture_v4 import commit_natural_fixture_inbound_turn_v4
        await asyncio.to_thread(commit_natural_fixture_inbound_turn_v4,
            graph=case["graph"], bootstrap=case["bootstrap"], namespace=namespace,
            source_ref=case["source_ref"], c02_operation_id=case["c02"].operation_id,
            now_utc=time.time())
        from sylanne3.authority_service.d13_natural_frame_verifier_v1 import build_authority_d13_natural_frame_verifier_v1
        case["model_service"]._graph_verifier._natural_history = build_authority_d13_natural_frame_verifier_v1(
            bundle=case["installed_bundle"], d11_issuer=case["d11_issuer"], authority_store=case["model_store"])
        if d09_policy_max is not None:
            adopted = await asyncio.to_thread(
                _adopt_d09_workbench, case,
                max_visible_chars=d09_policy_max)
            assert adopted["active_head_revision"] == 2
        with monkeypatch.context() as controlled_consumers:
            controlled_consumers.setattr(
                port, "natural_paid_consumer_ready_v2",
                lambda *, namespace, template_version:
                    namespace == case["namespace"]
                    and template_version == TEMPLATE_VERSION,
                raising=False)
            controlled_consumers.setattr(
                port, "natural_review_paid_consumer_ready_v2",
                lambda *, namespace, template_version:
                    namespace == case["namespace"]
                    and template_version == REVIEW_TEMPLATE_VERSION,
                raising=False)
            held = []
            try:
                saved = await asyncio.to_thread(
                    case["graph"].prepare_post_c02_natural_generation_v2,
                    case["bootstrap"], namespace, case["c02"].operation_id,
                    case["source_ref"], case["installed_bundle"])
                assert saved.state == "queued"
                paid = await asyncio.to_thread(_pay_generation, case, saved)
                held.append(paid[1])
                if len(reply_text) == 20:
                    assert len(paid[7]) == 20
                assert paid[5].call_id == paid[3].call_id
                completed = await asyncio.to_thread(
                    _complete_generation, case, saved, paid)
                held.append(completed[2])
                assert completed[3].status != "no_reply_hold"
                _content, review = await asyncio.to_thread(
                    _prepare_review, case, saved, completed)
                assert review.seal.generation_original_operation_id == (
                    saved.seal.original_operation_id)
                review_paid = await asyncio.to_thread(_pay_review, case, review)
                held.append(review_paid[1])
                assert review_paid[5].call_id == review_paid[3].call_id
                if d09_policy_max == 19:
                    with pytest.raises(UnavailableGuard, match="D09"):
                        await asyncio.to_thread(
                            _complete_review_and_final, case, completed[0],
                            review, review_paid)
                    assert case["store"]._db.execute(
                        "SELECT COUNT(*) FROM graph_atoms WHERE type_name=?",
                        ("d09.natural_verified_segment_batch.v2",),
                    ).fetchone() == (0,)
                    return
                candidate = await asyncio.to_thread(
                    _complete_review_and_final, case, completed[0], review,
                    review_paid)
                assert candidate.material.final_effect_id
                final = await asyncio.to_thread(_commit_final, case, candidate)
                held.append(final[1])
                assert final[3][1].operation_id == final[2].operation_id
                if onebot_outcome == "revoked":
                    await _revoke_owner_after_final(case, final)
                if onebot_outcome == "pending":
                    operation, tombstone = await asyncio.to_thread(
                        case["graph"].freeze_current_owner_revoke_v2,
                        case["bootstrap"], namespace=namespace,
                        operation_id="owner-revoke-natural-p2-pending")
                    assert operation.grant_digest == (
                        "sha256:" + canonical_digest(tombstone))
                    original_claim = port.execution_claim_v2
                    pending = []
                    def reserve_after_claim(**kwargs):
                        claimed = original_claim(**kwargs)
                        if not pending:
                            pending.append(port.reserve_owner_revoke(
                                namespace=namespace,
                                authority_namespace=case["authority_namespace"],
                                operation=operation,
                                owner_session_token=case["owner_session_token"],
                                owner_session_request=case["owner_session_request"]))
                        return claimed
                    controlled_consumers.setattr(
                        port, "execution_claim_v2", reserve_after_claim)
                if onebot_outcome == "observation_ack_lost":
                    original_observe = port.execution_observe_v2
                    lost = []
                    def observe_without_ack(**kwargs):
                        observed = original_observe(**kwargs)
                        if not lost:
                            lost.append(True)
                            raise TimeoutError("Authority observation response lost")
                        return observed
                    controlled_consumers.setattr(
                        port, "execution_observe_v2", observe_without_ack)
                await _host_one_shot(case, final, paid[7], onebot_outcome)
                if onebot_outcome == "pending":
                    assert len(pending) == 1
                    assert pending[0].phase == "pending"
                    assert (pending[0].guard.pending_revoke_operation_id
                            == operation.operation_id)
                if onebot_outcome == "observation_ack_lost":
                    assert lost == [True]
            finally:
                for lease in reversed(held):
                    await asyncio.to_thread(
                        case["graph"].release_authority_lease,
                        case["bootstrap"], lease)

    await real_owner_case(
        tmp_path, "owned", natural_workflow_builder=workflows,
        after_c02=after_c02,
        enable_d09_workbench=d09_policy_max is not None,
        ingress_text=reply_text)


@pytest.mark.asyncio
@pytest.mark.parametrize("onebot_outcome", (
    "accepted", "unknown", "revoked", "pending",
))
async def test_natural_p2_true_owner_one_shot(
    tmp_path, monkeypatch, onebot_outcome,
):
    await _run_true_owner_natural_case(tmp_path, monkeypatch, onebot_outcome)


@pytest.mark.asyncio
async def test_natural_d09_adopted_limit_holds_paid_twenty_char_reply(
        tmp_path, monkeypatch):
    await _run_true_owner_natural_case(
        tmp_path, monkeypatch, "accepted", d09_policy_max=19,
        reply_text="abcdefghijklmnopqrst")


@pytest.mark.asyncio
async def test_natural_d09_default_allows_paid_twenty_char_reply(
        tmp_path, monkeypatch):
    await _run_true_owner_natural_case(
        tmp_path, monkeypatch, "accepted",
        reply_text="abcdefghijklmnopqrst")
