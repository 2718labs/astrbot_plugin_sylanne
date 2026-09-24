"""The host retains the original D11 lease through result-read preparation."""

from dataclasses import replace
from types import MethodType, SimpleNamespace

import pytest

from rewrite.host_tests.alpha1 import test_astrbot_model_call as model_fixture
from rewrite.host_tests.alpha1.test_first_ingress_encoding_egress import frozen_case
from rewrite.host_tests.alpha1.test_host_model_egress_executor import fixture_values
from sylanne3.host.ingress import HostIngressEnvelope, IngressReceipt, SourceLineage
from sylanne3.host.authority_profile import (
    AdminD03SelfIdentityProjectionPolicy, AdminD04EncodingBaselinePolicy,
    AdminIngressClockPolicy,
)
from sylanne3.graph_types import AtomKey, GraphVersion, Owner
from sylanne3.host.model_egress_executor import (
    FrozenEncodingEgressResult, HostModelEgressExecutor,
)
from sylanne3.host.worker_result_identity import first_ingress_worker_result_request_v1
from sylanne3.authority_service.v2_model_egress_contract import ModelTerminalReceiptV2
from sylanne3.authority_service.v2_owner_contract import OwnerPrincipalV1
from sylanne3.authority_service.v2_owner_session import OwnerSessionLoginRequestV1
from sylanne3.runtime.first_ingress_v2 import ingress_ids
from sylanne3.runtime.original_model_result_context import OriginalModelResultContextV1
from sylanne3.runtime_context import RuntimeContext
from sylanne3.runtime_contracts import AuthorityContext, CommitReceipt


class Worker:
    def __init__(self, graph):
        self.graph = graph
        self.calls = 0

    async def call(self, fn, *args):
        self.calls += 1
        return fn(self.graph, *args)


@pytest.mark.asyncio
async def test_accepted_ingress_commits_d03_before_d04_and_holds_on_unknown(tmp_path):
    host = model_fixture.AstrBotModelCallTests(
        methodName="test_one_http_request_on_host_loop_with_usage")
    await host.asyncSetUp()
    try:
        bundle, _, _ = host.v2_adapters()
        clock = AdminIngressClockPolicy("clock", 1.0, 1.0)
        d03_policy = AdminD03SelfIdentityProjectionPolicy(
            30.0, {"graph_write": 1}, "snapshot", "resource")
        d04_policy = AdminD04EncodingBaselinePolicy(
            30.0, {"graph_write": 1}, "snapshot", "resource")
        bundle = replace(
            bundle, ingress_clock=clock,
            d03_self_identity_projection=d03_policy,
            d04_encoding_baseline=d04_policy,
        )
        namespace = bundle.installation_policy.namespace
        source_ref = "a" * 64
        envelope = HostIngressEnvelope(
            namespace, "platform", "owner", "sender", "message", "text",
            None, 1.0, "private", SourceLineage(
                source_ref, "reported", "platform", "external_report",
                "reported_claim"),
        )
        _, _, ingress_id, job_id, _, _ = ingress_ids(source_ref)
        accepted = IngressReceipt("accepted", ingress_id)

        def receipt(operation_id, *types):
            return CommitReceipt(
                "committed", operation_id, "a" * 64, "activity", None, 1,
                (), tuple(GraphVersion(
                    AtomKey(Owner("persona", *namespace.as_tuple), name, "record"), 1,
                ) for name in types), (), (), (),
            )

        d03 = receipt("d03-self-projection-original",
                      "d03.self_identity_mapping.v1", "d03.self_perspective.v1")
        d04 = receipt("d04-baseline-original", "d04.encoding_baseline.v1")
        calls = []

        class Graph:
            def commit_d03_self_identity_projection_v1(self, *args):
                calls.append(("d03", args))
                if getattr(self, "identity_unavailable", False):
                    raise RuntimeError("Authority current self unavailable")
                return self.d03_result

            def commit_d04_encoding_baseline_v1(self, *args):
                calls.append(("d04", args))
                return self.d04_result

        graph = Graph()
        graph.d03_result = d03
        graph.d04_result = d04
        runtime = RuntimeContext(tmp_path, dependencies=None)
        runtime._worker = Worker(graph)
        runtime._v2_bootstrap = object()
        runtime._v2_model_bundle = bundle
        runtime._v2_policy = bundle.installation_policy
        runtime._v2_namespace = namespace
        runtime._v2_namespace_provisioned = True
        result = await runtime.commit_first_ingress_pre_encoding_stages_v1(
            envelope, accepted)
        assert result is not None
        assert (result.ingress_operation_id, result.job_id,
                result.d03_receipt, result.d04_receipt) == (
                ingress_id, job_id, d03, d04)
        assert [name for name, _ in calls] == ["d03", "d04"]
        assert all(args[:4] == (runtime._v2_bootstrap, namespace, job_id, ingress_id)
                   for _, args in calls)
        assert calls[0][1][4:] == (bundle.installation_policy, d03_policy, clock)
        assert calls[1][1][4:] == (bundle.installation_policy, d04_policy, clock)

        calls.clear()
        graph.d03_result = replace(d03, status="pending_confirmation", commit_seq=None)
        assert await runtime.commit_first_ingress_pre_encoding_stages_v1(
            envelope, accepted) is None
        assert [name for name, _ in calls] == ["d03"]
        calls.clear()
        graph.d03_result = d03
        graph.d04_result = None
        assert await runtime.commit_first_ingress_pre_encoding_stages_v1(
            envelope, accepted) is None
        assert [name for name, _ in calls] == ["d03", "d04"]
        calls.clear()
        graph.identity_unavailable = True
        assert await runtime.commit_first_ingress_pre_encoding_stages_v1(
            envelope, accepted) is None
        assert [name for name, _ in calls] == ["d03"]
        graph.identity_unavailable = False
        calls.clear()
        runtime._v2_model_bundle = replace(bundle, d03_self_identity_projection=None)
        assert await runtime.commit_first_ingress_pre_encoding_stages_v1(
            envelope, accepted) is None
        assert calls == []
        runtime._v2_model_bundle = bundle
        assert await runtime.commit_first_ingress_pre_encoding_stages_v1(
            envelope, IngressReceipt("duplicate", ingress_id)) is None
        assert calls == []
    finally:
        await host.asyncTearDown()


@pytest.mark.asyncio
async def test_owner_result_reads_current_job_before_authority_query(tmp_path):
    host = model_fixture.AstrBotModelCallTests(
        methodName="test_one_http_request_on_host_loop_with_usage")
    await host.asyncSetUp()
    try:
        bundle, adapter, _ = host.v2_adapters()
        binding, draft, anchor, request = frozen_case(host, bundle)
        intent, _, _, _, grant, client = fixture_values(host, request)
        executor = HostModelEgressExecutor(
            authority=client, bundle=bundle, grant=grant, adapter=adapter)
        order = []

        class Graph:
            def read_first_ingress_model_egress_preparation_v2(
                self, auth, lease, job, acquire,
            ):
                order.append("graph")
                assert job == binding.job_id and acquire == "acquire-1"
                return binding, draft, anchor

        async def read_owner(self, **kwargs):
            order.append("authority")
            assert kwargs["binding"] is binding
            assert kwargs["owner_session_token"] == "current-owner-token"
            return "held-read"

        executor.read_original_for_owner = MethodType(read_owner, executor)
        runtime = RuntimeContext(tmp_path, dependencies=None)
        runtime._worker = Worker(Graph())
        runtime._v2_policy = bundle.installation_policy
        runtime._v2_installation_grant = grant
        runtime._v2_model_bundle = bundle
        runtime._v2_namespace = bundle.installation_policy.namespace
        runtime._v2_namespace_provisioned = True
        auth = AuthorityContext(
            "worker", "d11", "capability", bundle.installation_policy.namespace,
            ("activity",), "consolidation", ("owner",), "policy", 1, 1)
        session = OwnerSessionLoginRequestV1(
            "authority", draft.namespace, grant.installation_id,
            OwnerPrincipalV1("provider", "account", "incarnation"),
            "credential", 1, "owner", "https://dashboard.example")
        assert await runtime.read_first_ingress_encoding_for_owner_v2(
            auth, object(), binding.job_id, "acquire-1", intent=intent,
            owner_actor_id="owner-actor", owner_session_request=session,
            owner_session_token="current-owner-token", executor=executor,
        ) == "held-read"
        assert order == ["graph", "authority"]
    finally:
        await host.asyncTearDown()


@pytest.mark.asyncio
async def test_committed_ingress_acquires_original_job_then_reads_preparation(tmp_path):
    host = model_fixture.AstrBotModelCallTests(
        methodName="test_one_http_request_on_host_loop_with_usage")
    await host.asyncSetUp()
    try:
        bundle, adapter, _ = host.v2_adapters()
        binding, draft, anchor, request = frozen_case(host, bundle)
        original_intent, _anchor, _permit, _admission, grant, authority = fixture_values(
            host, request)
        executor = HostModelEgressExecutor(
            authority=authority, bundle=bundle, grant=grant, adapter=adapter)
        seen = []
        terminal = object()

        async def execute(self, *, binding, draft, expected_anchor):
            seen.append((binding, draft, expected_anchor))
            return terminal

        executor.execute_frozen_encoding_once = MethodType(execute, executor)
        source_ref = "a" * 64
        envelope = HostIngressEnvelope(
            bundle.installation_policy.namespace, "platform", "owner", "sender",
            "message", "text", None, 1.0, "private",
            SourceLineage(source_ref, "reported", "platform",
                          "external_report", "reported_claim"),
        )
        _, _, ingress_op, job_id, _, _ = ingress_ids(source_ref)
        receipt = IngressReceipt("accepted", ingress_op)
        original_context = None
        order = []

        class Graph:
            def grant(self, _bootstrap, **kwargs):
                assert kwargs["actor"] == grant.subject
                assert kwargs["issuer_domain"] == "d11"
                assert kwargs["domains"] == ("d11",)
                assert kwargs["operation_id"].startswith("job-acquire-")
                self.acquire_id = kwargs["operation_id"]
                self.lease = object()
                return self.lease, "capability"

            def release_authority_lease(self, _bootstrap, lease):
                assert lease is self.lease
                self.releases = getattr(self, "releases", 0) + 1

            def acquire_first_ingress_encoding_job_v2(
                self, auth, lease, acquired_job, acquire_id, *, lease_seconds,
            ):
                assert acquired_job == job_id and acquire_id == self.acquire_id
                assert auth.actor == grant.subject and auth.worker_fence is None
                assert 120 < lease_seconds <= 420
                if getattr(self, "fail_acquire", False):
                    raise RuntimeError("original acquire outcome unknown")
                return SimpleNamespace(fence=1)

            def read_first_ingress_model_egress_preparation_v2(
                self, auth, lease, acquired_job, acquire_id,
            ):
                assert acquired_job == job_id and acquire_id == self.acquire_id
                assert auth.worker_fence == 1
                return binding, draft, anchor

            def read_first_ingress_original_model_result_context_v1(
                self, auth, lease, acquired_job, acquire_id,
            ):
                assert acquired_job == job_id and acquire_id == self.acquire_id
                assert lease is self.lease and auth.worker_fence == 1
                assert self.releases == 2
                order.append("context")
                return original_context

        graph = Graph()
        worker = Worker(graph)
        runtime = RuntimeContext(tmp_path, dependencies=None)
        runtime._worker = worker
        runtime._v2_policy = bundle.installation_policy
        runtime._v2_port = SimpleNamespace(current_anchor=lambda **_: anchor)
        runtime._v2_bootstrap = object()
        runtime._v2_installation_grant = grant
        runtime._v2_model_bundle = bundle
        runtime._v2_namespace = envelope.namespace
        runtime._v2_namespace_provisioned = True

        assert await runtime.run_committed_first_ingress_encoding_v2(
            envelope, receipt, executor=executor) is terminal
        assert seen == [(binding, draft, anchor)]
        assert worker.calls == 3 and graph.releases == 1
        assert await runtime.run_committed_first_ingress_encoding_v2(
            envelope, IngressReceipt("duplicate", ingress_op),
            executor=executor) is None
        assert worker.calls == 3
        first_acquire_id = graph.acquire_id
        graph.fail_acquire = True
        assert await runtime.run_committed_first_ingress_encoding_v2(
            envelope, receipt, executor=executor) is None
        assert graph.acquire_id == first_acquire_id
        assert seen == [(binding, draft, anchor)]
        assert graph.releases == 2

        graph.fail_acquire = False
        intent = replace(
            original_intent, authority_id=anchor.authority_id,
            namespace=anchor.namespace, subject=grant.subject,
            operation_id=graph.acquire_id, job_id=job_id, worker_fence=1,
            source_refs=(binding.source_id,),
            source_revisions=((binding.source_id, binding.source_revision),),
            access_revisions=((binding.source_id, binding.access_revision),),
            budget_reservation_operation_id=ingress_op)
        terminal_receipt = ModelTerminalReceiptV2(
            "a" * 64, intent.call_id, intent.request_digest,
            "b" * 64, "c" * 64, "sha256:" + "d" * 64,
            grant.installation_id, "e" * 64)
        original_context = OriginalModelResultContextV1(
            envelope.namespace, intent.authority_id, intent.namespace,
            grant.installation_id, "incarnation", 3, 2, 0, 0,
            job_id, graph.acquire_id, ingress_op, intent.call_id,
            binding.binding_digest, intent.request_digest,
            intent.source_refs[0], intent.source_revisions[0][1],
            intent.access_revisions[0][1], grant.subject, 1,
            "2099-01-01T00:00:00Z", anchor)

        async def execute_observed(self, **_):
            order.append("egress")
            return FrozenEncodingEgressResult(intent, terminal_receipt)

        async def settle_cost(self, result):
            order.append("cost")
            assert result.intent == intent and graph.releases == 2
            return SimpleNamespace(status="committed", call_id=intent.call_id)

        executor.execute_frozen_encoding_once = MethodType(execute_observed, executor)
        runtime.commit_first_ingress_model_cost_v1 = MethodType(settle_cost, runtime)
        async with runtime.prepared_first_ingress_worker_result_v1(
                envelope, receipt, executor=executor) as prepared:
            assert prepared is not None
            assert graph.releases == 2
            assert prepared.egress.intent == intent
            assert prepared.result_context == original_context
            assert prepared.read_request.consumer_operation_id.startswith(
                "first-ingress-c02-")
            assert prepared.read_request == first_ingress_worker_result_request_v1(
                replace(original_context, graph_revision=99, graph_epoch=99))
            assert graph.releases == 2
        assert order == ["egress", "cost", "context"]
        assert graph.releases == 3
    finally:
        await host.asyncTearDown()
