"""V2 context reply creates one original job without rewriting paid V1 identity."""

from dataclasses import asdict, replace
import json
from types import SimpleNamespace

import pytest

from sylanne3.domains.d07 import D07DomainProvider
from sylanne3.domains.d12 import graph_type_specs as d12_graph_type_specs
from sylanne3.domains.d08 import GoalExecutionProvider
from sylanne3.domains.d09 import turn_order_type_specs_v1
from sylanne3.authority_service.v2_contract import FencePermitV2
from sylanne3.authority_service.v2_model_egress_contract import (
    ModelAdmissionV2, ModelEgressIntentV1, ModelEgressRecoveryV1,
    ModelTerminalReceiptV2,
)
from sylanne3.authority_service.current_model_egress_graph_verifier import (
    PinnedCurrentModelEgressGraphVerifier,
)
from sylanne3.graph_coordinator import GraphCoordinator
from sylanne3.host.authority_profile import (
    AdminD06PrivateReplySourcePolicy, AdminD07AttentionPolicy,
    AdminInstallationBundle, AdminModelWorkflowV2, installed_model_config_ref,
)
from sylanne3.host.post_c02_attention_driver import (
    post_c02_attention_operation_id, prepare_post_c02_attention_v1,
)
from sylanne3.host.current_scene import CurrentHostScene
from sylanne3.model_broker.context_reply import CONTEXT_REPLY_TEMPLATE_VERSION
from sylanne3.runtime.first_ingress_v2 import scene_ref_for_conversation, trusted_upper
from sylanne3.runtime_contracts import AuthorityContext, canonical_digest

import test_first_ingress_c02_commit
from test_first_ingress_c02_commit import c02_case
from test_first_ingress_c02_terminal_cost_v2 import _committed_case
from test_first_encoding_cost_graph_commit import AccountingPort
from test_post_c02_reply_model_job_v1 import _reply_workflows
from test_scene_binding_v2 import _session


class ContextReplyC02Case(tuple):
    """Keep the Owner fixture used to construct the C02 case available to tests."""


@pytest.fixture
def context_reply_c02_case(monkeypatch, request):
    private = AdminD06PrivateReplySourcePolicy(1, "private_conversation", True)
    original_scene = test_first_ingress_c02_commit._scene_case
    original_commit = GraphCoordinator.commit_first_ingress_v2
    original_inputs = test_first_ingress_c02_commit._ingress_inputs
    platform_ref = json.dumps(["astrbot", "onebot", "fixture"],
                              separators=(",", ":"))
    conversation_ref = json.dumps(["private", "conversation"],
                                  separators=(",", ":"))
    owner_scene_cases = []

    def canonical_inputs(namespace):
        host, clock, encoding = original_inputs(namespace)
        return (replace(
            host,
            platform_ref=platform_ref,
            conversation_ref=conversation_ref),
                clock, encoding)

    def scene(*args, **kwargs):
        kwargs["owner_capabilities"] = (
            "workbench.create", "workbench.read", "workbench.bind_scene",
            "workbench.correct")
        kwargs["owner_purposes"] = (
            "workbench_user_action", "workbench_view", "audit")
        kwargs["extra_work_kinds"] = tuple(kwargs.get("extra_work_kinds", ())) + (
            "reply", "context_reply", "natural_generation",
            "natural_review", "d07.attention")
        natural_plan = next(spec for spec in GoalExecutionProvider().register_types()
                            if spec.name == "d08.natural_expression_plan.v2")
        kwargs["extra_specs"] = tuple(kwargs.get("extra_specs", ())) + (
            *D07DomainProvider().type_specs(), *d12_graph_type_specs(),
            natural_plan, *turn_order_type_specs_v1())
        case = original_scene(*args, **kwargs)
        owner_scene_cases.append(case)
        prior = case[6]
        ref = scene_ref_for_conversation(case[4], platform_ref, conversation_ref)
        return case[:6] + (replace(
            prior, request=replace(prior.request, scene_ref=ref)),) + case[7:]

    def bind_scene(case):
        _, _, port, coordinator, namespace, principal, prior, *_ = case
        scene = CurrentHostScene(
            namespace, platform_ref, conversation_ref, "private",
            prior.request.scene_ref)
        coordinator._GraphCoordinator__scene_identity_port = SimpleNamespace(
            verify=lambda current, ref, visibility: scene if (
                current, ref, visibility) == (
                    namespace, scene.scene_ref, scene.visibility) else None)
        from sylanne3.host.authority_profile import AdminIngressClockPolicy
        coordinator._GraphCoordinator__scene_clock_policy = AdminIngressClockPolicy(
            "scene-clock", 1.0, 1.0)
        original_clock = port.read_ingress_clock
        port.read_ingress_clock = lambda _: SimpleNamespace(
            utc_upper_bound_seconds=1000.0)
        token, session_request = _session(case)
        try:
            return coordinator.commit_scene_binding_v2(
                namespace=namespace, operation_id="scene-bind-1", scene=scene,
                prior=prior, principal=principal, actor_id="paired-owner",
                request_digest="sha256:" + "a" * 64,
                owner_session_token=token, owner_session_request=session_request)
        finally:
            port.read_ingress_clock = original_clock

    def ingress(self, bootstrap, host, policy, clock, encoding,
                reply_source_policy=None):
        return original_commit(
            self, bootstrap, host, policy, clock, encoding,
            private if reply_source_policy is None else reply_source_policy)

    monkeypatch.setattr(test_first_ingress_c02_commit, "_scene_case", scene)
    monkeypatch.setattr(test_first_ingress_c02_commit, "_bind_scene", bind_scene)
    monkeypatch.setattr(test_first_ingress_c02_commit, "_ingress_inputs", canonical_inputs)
    monkeypatch.setattr(GraphCoordinator, "commit_first_ingress_v2", ingress)
    case = request.getfixturevalue("c02_case")
    d07 = D07DomainProvider()
    case[1].register_provider(
        case[2], "d07", d07, "d07.proposal.v1",
        d07.descriptor.request_schema_hash)
    wrapped = ContextReplyC02Case(case)
    wrapped.owner_scene_case = owner_scene_cases[-1]
    return wrapped


def _context_reply_original_paid_lifecycle_case(
        context_reply_c02_case, monkeypatch, *, paid_fact_factory=None,
        stop_before_paid=False):
    case = context_reply_c02_case
    store, graph, namespace, intent, seal, pinned, _ = _committed_case(case, monkeypatch)
    graph._GraphCoordinator__original_c02_cost_intent_port = lambda request: intent
    graph.recover_committed_first_ingress_c02_unknown_cost_v2_pinned(
        case[2], namespace, seal.consumer_operation_id, pinned)
    config_digest = "a" * 64
    workflow = AdminModelWorkflowV2(
        work_kind="context_reply", purpose="proposal",
        template_version=CONTEXT_REPLY_TEMPLATE_VERSION,
        provider_id="provider", model_id="model",
        provider_config_ref=installed_model_config_ref(
            "provider", "model", config_digest),
        provider_config_digest=config_digest,
        audiences=(json.dumps(["private", "conversation"],
                              separators=(",", ":")),), privacy_tier="private",
        required_capabilities=("text",), timeout_seconds=10.0,
        max_output_tokens=8, quote_ceiling={"output_tokens": 16},
    )
    installed = AdminInstallationBundle(
        object(), case[4], b"d11", b"d02", ingress_clock=case[5],
        d07_attention=AdminD07AttentionPolicy(
            300.0, {"cpu_ms": 1}, "attention-snapshot", "attention-resource"),
        model_workflows=replace(_reply_workflows(), context_reply=workflow),
    )
    c02, snapshot, qualification, audience, guard, anchor, clock, policy, competitor = (
        graph.read_post_c02_attention_inputs_v1(
            case[2], namespace, seal.consumer_operation_id, None, installed))
    assert competitor is None
    source_ref = qualification.source_refs[0]
    attention_operation = post_c02_attention_operation_id(
        c02.operation_id, source_ref)
    lease, capability = graph.grant(
        case[2], actor=case[4].administrator_holder,
        issuer_domain="d11", namespace=namespace, domains=("d07",),
        activation_generation=anchor.activation_generation,
        operation_id=attention_operation)
    try:
        authority = AuthorityContext(
            case[4].administrator_holder, "d11", capability, namespace,
            ("persona",), "expression", (audience,),
            case[4].root_grant.policy_ref, anchor.activation_generation)
        candidate = prepare_post_c02_attention_v1(
            c02_receipt=c02, source_ref=source_ref, snapshot=snapshot,
            qualification=qualification, authority=authority, guard=guard,
            parent_budget_lease_ref=case[4].root_grant.lease_id,
            conversation_ref=audience, now_utc=trusted_upper(clock),
            monotonic_deadline=clock.monotonic_after_seconds + 299.0,
            ticket_lifetime_seconds=299.0,
            current_policy=policy.policy,
            active_head_ref=policy.active_head_ref)
        graph.commit_post_c02_attention_v1(candidate.bundle, lease, installed)
    finally:
        graph.release_authority_lease(case[2], lease)
    if stop_before_paid:
        return {
            "store": store, "graph": graph, "namespace": namespace,
            "c02": c02, "source_ref": source_ref,
            "installed": installed, "case": case,
            "owner_scene_case": case.owner_scene_case,
        }
    # A configured template alone must not create an orphan paid job while
    # Authority's original intent, terminal and result consumer are absent.
    with pytest.raises(Exception, match="installed V2 paid consumer unavailable"):
        graph.prepare_post_c02_context_reply_model_job_v2(
            case[2], namespace, c02.operation_id, source_ref, installed)
    assert store._db.execute(
        "SELECT COUNT(*) FROM runtime_jobs WHERE work_kind='context_reply'"
    ).fetchone() == (0,)
    monkeypatch.setattr(
        graph._GraphCoordinator__content_fence_v2,
        "context_reply_paid_consumer_ready_v2",
        lambda **kwargs: True,
        raising=False,
    )
    saved = graph.prepare_post_c02_context_reply_model_job_v2(
        case[2], namespace, c02.operation_id, source_ref, installed)
    assert saved.state == "queued"
    acquire_lease, acquire_capability = graph.grant(
        case[2], actor=case[4].administrator_holder,
        issuer_domain="d11", namespace=namespace, domains=("d11",),
        activation_generation=anchor.activation_generation,
        operation_id=saved.seal.acquire_operation_id)
    try:
        worker = AuthorityContext(
            case[4].administrator_holder, "d11", acquire_capability,
            namespace, ("activity",), "proposal", (audience,),
            case[4].root_grant.policy_ref, anchor.activation_generation)
        job, call = graph.acquire_post_c02_context_reply_model_job_v2(
            worker, acquire_lease, c02.operation_id, source_ref, installed,
            lease_seconds=60)
        assert job.phase == "running"
        assert call.call_id == saved.seal.call_id
        prepared_call, draft, _ = (
            graph.read_post_c02_context_reply_model_egress_preparation_v2(
                replace(worker, worker_fence=job.fence), acquire_lease,
                c02.operation_id, source_ref, installed))
        assert prepared_call == call
        assert draft.request_digest == call.digest
        terminal_lease, terminal_capability = graph.grant(
            case[2], actor=case[4].administrator_holder,
            issuer_domain="d11", namespace=namespace, domains=("d11",),
            activation_generation=anchor.activation_generation,
            operation_id="context-reply-terminal-" + canonical_digest({
                "namespace": namespace.as_tuple,
                "original_operation_id": saved.seal.original_operation_id,
            })[:48])
        try:
            terminal_worker = replace(worker, capability_ref=terminal_capability,
                                      worker_fence=None)
            intent = ModelEgressIntentV1(
                **asdict(draft), fence_token="m" * 32,
                fence_epoch=1, fence_revision=0,
                anchor_digest=canonical_digest(asdict(anchor)))
            if paid_fact_factory is None:
                observed = ModelEgressRecoveryV1(
                    intent, "observed", "e" * 64, (("output_tokens", 1),), ())
                admission = ModelAdmissionV2(
                    "f" * 64, draft.authority_id, draft.namespace,
                    draft.subject, draft.operation_id, draft.call_id,
                    draft.request_digest, draft.provider_config_digest,
                    saved.seal.installation_id, "1" * 64,
                    "observer", "2" * 64, "3" * 64)
                terminal = ModelTerminalReceiptV2(
                    admission.admission_id, draft.call_id, draft.request_digest,
                    "4" * 64, observed.observation_digest,
                    "sha256:" + "5" * 64,
                    saved.seal.installation_id, "3" * 64)
                permit = FencePermitV2(
                    draft.authority_id, draft.namespace, draft.subject,
                    "holder", 1, "model_egress", draft.operation_id,
                    intent.fence_token, 1, 0, anchor)
                fact = (observed, permit, admission, terminal)
            else:
                intent, fact = paid_fact_factory(
                    intent=intent, draft=draft, anchor=anchor, saved=saved,
                    graph=graph, store=store, installed=installed, case=case)
                assert fact[0].intent == intent
                terminal = fact[3]
            graph_path = store._db.execute(
                "PRAGMA database_list").fetchone()[2]
            verifier = PinnedCurrentModelEgressGraphVerifier(
                graph_path,
                d11_issuer=graph._GraphCoordinator__d11_issuer,
                trusted_now_utc=lambda:
                    saved.frozen_request.input.frozen_at_utc + 1.0,
                trusted_paired_clock=lambda: (
                    saved.frozen_request.input.frozen_at_utc + 1.0,
                    "fixture-clock-epoch"),
            )
            assert verifier.complete_graph_current(intent)
            access_ref = saved.frozen_request.input.evidence[0].access_ref.ref
            store._db.execute(
                "UPDATE graph_atoms SET valid=0 WHERE token=?", (access_ref,))
            store._db.commit()
            assert not verifier.complete_graph_current(intent)
            store._db.execute(
                "UPDATE graph_atoms SET valid=1 WHERE token=?", (access_ref,))
            store._db.commit()
            graph._GraphCoordinator__model_terminal_cost_port = lambda _: fact
            graph._GraphCoordinator__accounting_maintenance_port = (
                AccountingPort(store, fact))
            with pytest.raises(Exception, match="cost is not durable"):
                graph.complete_post_c02_context_reply_model_job_v2(
                    terminal_worker, terminal_lease, c02.operation_id,
                    source_ref, intent)
            cost = graph.commit_context_reply_model_cost_v2(
                case[2], namespace, intent,
                quote_id="context-reply-quote:" + saved.seal.job_id.split(":")[-1],
                quote_version=1)
            assert cost.status == "committed"
            completed = graph.complete_post_c02_context_reply_model_job_v2(
                terminal_worker, terminal_lease, c02.operation_id,
                source_ref, intent)
            assert completed.phase == "completed"
            assert graph.complete_post_c02_context_reply_model_job_v2(
                terminal_worker, terminal_lease, c02.operation_id,
                source_ref, intent) == completed
            result_request = (
                graph.read_post_c02_context_reply_model_result_request_v2(
                    terminal_worker, terminal_lease, c02.operation_id,
                    source_ref, installed))
            assert result_request.call_id == saved.seal.call_id
            assert result_request.model_request_digest == (
                saved.seal.model_request_digest)
            cost_atom_ref = cost.cost_ref
            store._db.execute(
                "UPDATE graph_atoms SET valid=0 WHERE token=?", (cost_atom_ref,))
            store._db.commit()
            with pytest.raises(Exception):
                graph.read_post_c02_context_reply_model_result_request_v2(
                    terminal_worker, terminal_lease, c02.operation_id,
                    source_ref, installed)
            store._db.execute(
                "UPDATE graph_atoms SET valid=1 WHERE token=?", (cost_atom_ref,))
            store._db.commit()
            read_lease, read_capability = graph.grant(
                case[2], actor=case[4].administrator_holder,
                issuer_domain="d06", namespace=namespace, domains=("d06",),
                activation_generation=anchor.activation_generation,
                operation_id="d06-evidence-read-1")
            try:
                read_authority = AuthorityContext(
                    case[4].administrator_holder, "d06", read_capability,
                    namespace, ("event",), "context", (audience,),
                    case[4].root_grant.policy_ref, anchor.activation_generation)
                evidence_page = graph.read_current_memory_evidence_v1(
                    read_authority, read_lease, limit=64)
                assert evidence_page.query_coverage.status == "verified_complete"
                assert evidence_page.graph_epoch.revision >= 1
                assert source_ref in {item.source_ref
                                      for item in evidence_page.candidates}
            finally:
                graph.release_authority_lease(case[2], read_lease)
        finally:
            graph.release_authority_lease(case[2], terminal_lease)
    finally:
        graph.release_authority_lease(case[2], acquire_lease)
    return {
        "store": store, "graph": graph, "namespace": namespace,
        "saved": saved, "intent": intent, "c02": c02,
        "source_ref": source_ref, "installed": installed,
        "anchor": anchor, "terminal": terminal, "fact": fact,
        "result_request": result_request,
        "case": case,
        "owner_scene_case": case.owner_scene_case,
    }


def test_context_reply_original_paid_lifecycle_holds_until_consumer_and_cost(
        context_reply_c02_case, monkeypatch):
    _context_reply_original_paid_lifecycle_case(context_reply_c02_case, monkeypatch)
