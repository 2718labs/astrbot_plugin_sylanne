"""The host retains the original D11 lease through result-read preparation."""

import asyncio
from dataclasses import replace
from types import MethodType, SimpleNamespace

import pytest

from rewrite.host_tests.alpha1 import test_astrbot_model_call as model_fixture
from rewrite.host_tests.alpha1.test_first_ingress_encoding_egress import frozen_case
from rewrite.host_tests.alpha1.test_host_model_egress_executor import fixture_values
from sylanne3.host.ingress import HostIngressEnvelope, IngressReceipt, SourceLineage
from sylanne3.host.authority_profile import (
    AdminD03SelfIdentityProjectionPolicy, AdminD04EncodingBaselinePolicy,
    AdminD06FirstIngressC02Policy, AdminIngressClockPolicy,
)
from sylanne3.graph_types import AtomKey, GraphVersion, Owner
from sylanne3.host.model_egress_executor import (
    FrozenEncodingEgressResult, HostModelEgressExecutor,
)
from sylanne3.host.astrbot_model_call import AstrBotModelProvider
from sylanne3.host.worker_result_identity import first_ingress_worker_result_request_v1
from sylanne3.authority_service.v2_model_egress_contract import (
    ModelEgressObservationV1, ModelTerminalReceiptV2,
)
from sylanne3.authority_service.v2_worker_model_result_contract import (
    WorkerModelResultReadV1,
)
from sylanne3.authority_service.v2_owner_contract import OwnerPrincipalV1
from sylanne3.authority_service.v2_owner_session import OwnerSessionLoginRequestV1
from sylanne3.runtime.first_ingress_v2 import ingress_ids
from sylanne3.runtime.original_model_result_context import OriginalModelResultContextV1
from sylanne3.runtime_context import RuntimeContext
from sylanne3.runtime_contracts import (
    AuthorityContext, CommitReceipt, canonical_digest, canonical_serialize,
)


class Worker:
    def __init__(self, graph):
        self.graph = graph
        self.calls = 0

    async def call(self, fn, *args):
        self.calls += 1
        return fn(self.graph, *args)


@pytest.mark.asyncio
async def test_auto_c02_handoff_requires_paired_cost_and_w01_continuation(tmp_path):
    host = model_fixture.AstrBotModelCallTests(
        methodName="test_one_http_request_on_host_loop_with_usage")
    await host.asyncSetUp()
    try:
        bundle, _, _ = host.v2_adapters()
        bundle = replace(
            bundle,
            ingress_clock=AdminIngressClockPolicy("clock", 1.0, 1.0),
            d06_first_ingress_c02=AdminD06FirstIngressC02Policy(
                30.0, {"graph_write": 1}, "snapshot", "resource"),
        )

        class Graph:
            installed = True

            def first_ingress_c02_accounting_installed_v1(self):
                return self.installed

        graph = Graph()
        runtime = RuntimeContext(tmp_path, dependencies=None)
        runtime._worker = Worker(graph)
        runtime._v2_namespace_provisioned = True
        runtime._v2_model_bundle = bundle
        runtime._v2_policy = bundle.installation_policy
        runtime._v2_cost_transport = object()
        assert await runtime.first_ingress_c02_accounting_installed_v1() is True
        graph.installed = False
        assert await runtime.first_ingress_c02_accounting_installed_v1() is False
        runtime._v2_cost_transport = None
        assert await runtime.first_ingress_c02_accounting_installed_v1() is False
        assert runtime._worker.calls == 2
        assert host.requests == []
    finally:
        await host.asyncTearDown()


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
async def test_new_encoding_path_holds_legacy_v2_binding_before_egress(tmp_path):
    host = model_fixture.AstrBotModelCallTests(
        methodName="test_one_http_request_on_host_loop_with_usage")
    await host.asyncSetUp()
    try:
        bundle, adapter, _ = host.v2_adapters()
        binding, draft, anchor, request = frozen_case(host, bundle)
        assert binding.request["schema"] == "sylanne.first-ingress-encoding-call.v2"
        _, _, _, _, grant, client = fixture_values(host, request)
        executor = HostModelEgressExecutor(
            authority=client, bundle=bundle, grant=grant, adapter=adapter)

        class Graph:
            def read_first_ingress_model_egress_preparation_v2(self, *_):
                return binding, draft, anchor

        async def forbidden(self, **_):
            pytest.fail("legacy V2 binding reached new provider path")

        executor.execute_frozen_encoding_once = MethodType(forbidden, executor)
        runtime = RuntimeContext(tmp_path, dependencies=None)
        runtime._worker = Worker(Graph())
        runtime._v2_namespace = bundle.installation_policy.namespace
        runtime._v2_namespace_provisioned = True
        runtime._v2_policy = bundle.installation_policy
        runtime._v2_installation_grant = grant
        runtime._v2_model_bundle = bundle
        authority = AuthorityContext(
            grant.subject, "d11", "capability", runtime._v2_namespace,
            ("activity",), "consolidation", ("owner",), "policy", 1, 1)
        assert await runtime.execute_first_ingress_encoding_v2(
            authority, object(), binding.job_id, "acquire-1",
            executor=executor) is None
        assert host.requests == []
    finally:
        await host.asyncTearDown()


@pytest.mark.asyncio
@pytest.mark.parametrize("read_mode", ("original", "wrong_consumer", "unknown_c02"))
async def test_committed_ingress_acquires_original_job_then_reads_preparation(
    tmp_path, read_mode,
):
    host = model_fixture.AstrBotModelCallTests(
        methodName="test_one_http_request_on_host_loop_with_usage")
    await host.asyncSetUp()
    try:
        bundle, _, _ = host.v2_adapters()
        bundle = replace(
            bundle,
            ingress_clock=AdminIngressClockPolicy("clock", 1.0, 1.0),
            d06_first_ingress_c02=AdminD06FirstIngressC02Policy(
                30.0, {"graph_write": 1}, "snapshot", "resource"),
        )
        workflow = bundle.model_workflows.encode
        adapter = AstrBotModelProvider(
            context=host.context, host_loop=asyncio.get_running_loop(),
            trusted_umo=model_fixture.UMO,
            descriptor=replace(
                host.descriptor, purposes=frozenset({workflow.purpose})),
            admin_model=workflow, installation_bundle=bundle,
        )
        binding, draft, anchor, request = frozen_case(
            host, bundle, with_baseline=True)
        assert binding.request["schema"] == "sylanne.first-ingress-encoding-call.v3"
        original_intent, _anchor, _permit, _admission, grant, authority = fixture_values(
            host, request)
        executor = HostModelEgressExecutor(
            authority=authority, bundle=bundle, grant=grant, adapter=adapter)

        async def forbidden(self, **_):
            pytest.fail("retired runner or missing baseline reached model egress")

        executor.execute_frozen_encoding_once = MethodType(forbidden, executor)
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

            def acquire_first_ingress_encoding_job_v3(
                self, auth, lease, acquired_job, acquire_id, *, lease_seconds,
            ):
                assert acquired_job == job_id and acquire_id == self.acquire_id
                assert auth.actor == grant.subject and auth.worker_fence is None
                assert 120 < lease_seconds <= 420
                if not getattr(self, "baseline_committed", False):
                    raise RuntimeError("committed D03/D04 baseline unavailable")
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

            def commit_first_ingress_c02_v1(
                self, bootstrap, original_intent, read, installation_policy,
                admin_policy, clock_policy,
            ):
                assert bootstrap is runtime._v2_bootstrap
                assert original_intent == intent
                assert read.request == first_ingress_worker_result_request_v1(
                    original_context)
                assert read.observation == observation
                assert read.terminal_receipt == terminal_receipt
                assert installation_policy is bundle.installation_policy
                assert admin_policy is bundle.d06_first_ingress_c02
                assert clock_policy is bundle.ingress_clock
                assert self.releases == 2
                order.append("c02")
                return self.c02_result

        graph = Graph()
        graph.baseline_committed = True
        worker = Worker(graph)
        runtime = RuntimeContext(tmp_path, dependencies=None)
        runtime._worker = worker
        runtime._v2_policy = bundle.installation_policy
        runtime._v2_port = SimpleNamespace(current_anchor=lambda **_: anchor)
        runtime._v2_bootstrap = object()
        runtime._v2_installation_grant = grant
        runtime._v2_model_bundle = bundle
        runtime._v2_cost_transport = object()
        runtime._v2_namespace = envelope.namespace
        runtime._v2_namespace_provisioned = True

        assert await runtime.run_committed_first_ingress_encoding_v2(
            envelope, receipt, executor=executor) is None
        assert worker.calls == 0 and host.requests == []
        async with runtime.acquired_first_ingress_encoding_v2(
                envelope, receipt, executor=executor) as acquired:
            assert acquired is not None and acquired.job_id == job_id
            assert getattr(graph, "releases", 0) == 0
        assert worker.calls == 2 and graph.releases == 1
        assert await runtime.run_committed_first_ingress_encoding_v2(
            envelope, IngressReceipt("duplicate", ingress_op),
            executor=executor) is None
        assert worker.calls == 2
        first_acquire_id = graph.acquire_id
        graph.baseline_committed = False
        async with runtime.acquired_first_ingress_encoding_v2(
                envelope, receipt, executor=executor) as acquired:
            assert acquired is None
        assert graph.acquire_id == first_acquire_id
        assert host.requests == []
        assert graph.releases == 2

        graph.baseline_committed = True
        runtime._v2_cost_transport = None
        assert await runtime.commit_first_ingress_c02_v1(
            envelope, receipt, executor=executor) is None
        assert worker.calls == 3 and graph.releases == 2
        runtime._v2_cost_transport = object()
        runtime._v2_model_bundle = replace(bundle, d06_first_ingress_c02=None)
        assert await runtime.commit_first_ingress_c02_v1(
            envelope, receipt, executor=executor) is None
        assert worker.calls == 3 and graph.releases == 2
        runtime._v2_model_bundle = bundle
        intent = replace(
            original_intent, authority_id=anchor.authority_id,
            namespace=anchor.namespace, subject=grant.subject,
            operation_id=graph.acquire_id, job_id=job_id, worker_fence=1,
            anchor_digest=canonical_digest(anchor),
            source_refs=(binding.source_id,),
            source_revisions=((binding.source_id, binding.source_revision),),
            access_revisions=((binding.source_id, binding.access_revision),),
            budget_reservation_operation_id=ingress_op)
        observation = ModelEgressObservationV1(
            intent.authority_id, intent.namespace, intent.subject,
            intent.operation_id, intent.call_id, intent.request_digest,
            "completed", canonical_serialize({"text": "encoded"}),
            (("output_tokens", 2),), (), "provider-call-1")
        terminal_receipt = ModelTerminalReceiptV2(
            "a" * 64, intent.call_id, intent.request_digest,
            "b" * 64, observation.digest, "sha256:" + "d" * 64,
            grant.installation_id, "e" * 64)
        original_context = OriginalModelResultContextV1(
            envelope.namespace, intent.authority_id, intent.namespace,
            grant.installation_id, "incarnation", 3, 2, 0, 0,
            job_id, graph.acquire_id, ingress_op, intent.call_id,
            binding.binding_digest, intent.request_digest,
            intent.source_refs[0], intent.source_revisions[0][1],
            intent.access_revisions[0][1], grant.subject, 1,
            "2099-01-01T00:00:00Z", anchor)
        consumer_id = first_ingress_worker_result_request_v1(
            original_context).consumer_operation_id
        c02_receipt = CommitReceipt(
            "committed", consumer_id, "a" * 64, "activity", None, 1, (),
            (
                GraphVersion(AtomKey(Owner("event", *envelope.namespace.as_tuple,
                                           "episode"), "memory.episode.v1", "record"), 1),
                GraphVersion(AtomKey(Owner("event", *envelope.namespace.as_tuple,
                                           "trace"), "memory.subjective_trace.v2",
                                     "record"), 1),
            ), (), (), (),
        )
        graph.c02_result = (replace(
            c02_receipt, status="pending_confirmation", commit_seq=None)
            if read_mode == "unknown_c02" else c02_receipt)

        async def execute_observed(self, **_):
            order.append("egress")
            return FrozenEncodingEgressResult(intent, terminal_receipt)

        async def settle_cost(self, result):
            order.append("cost")
            assert result.intent == intent and graph.releases == 2
            return SimpleNamespace(status="committed", call_id=intent.call_id)

        executor.execute_frozen_encoding_once = MethodType(execute_observed, executor)
        runtime.commit_first_ingress_model_cost_v1 = MethodType(settle_cost, runtime)

        async def read_original(self, *, read_request, intent, terminal):
            order.append("read")
            assert graph.releases == 2
            assert intent == prepared_intent and terminal == terminal_receipt
            assert read_request == first_ingress_worker_result_request_v1(
                original_context)
            if read_mode == "wrong_consumer":
                read_request = replace(
                    read_request, consumer_operation_id="another-consumer")
            return WorkerModelResultReadV1(
                read_request, observation, terminal_receipt)

        prepared_intent = intent
        executor.read_original_for_worker = MethodType(read_original, executor)
        committed = await runtime.commit_first_ingress_c02_v1(
            envelope, receipt, executor=executor)
        assert committed == (c02_receipt if read_mode == "original" else None)
        assert order == ["egress", "cost", "context", "read"] + (
            ["c02"] if read_mode != "wrong_consumer" else [])
        assert graph.releases == 3
        assert host.requests == []
    finally:
        await host.asyncTearDown()
