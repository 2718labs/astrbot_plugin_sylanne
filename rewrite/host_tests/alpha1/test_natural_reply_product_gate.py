"""A partial installation must not create the first natural paid job."""

import asyncio
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import AsyncMock

from rewrite.tests.alpha1.runtime.test_natural_reply_job_v2 import _case
from sylanne3.graph_coordinator import (
    GraphCoordinator, NaturalOriginalProgressV2, NaturalOriginalStageStatusV2,
    NaturalPendingOriginalItemV2, NaturalPendingOriginalPageV2,
)
from sylanne3.host.authority_profile import AdminInstallationBundle
from sylanne3.host.authority_profile import (
    AdminIngressClockPolicy, AdminModelWorkflowV2, AdminModelWorkflowsV2,
    AdminPrivateReplyDispatchPolicy,
)
from sylanne3.host.authority_client import AuthorityClient, AuthoritySelection
from sylanne3.host.installed_dispatch_route import InstalledDispatchRoutePort
from sylanne3.host.installed_model_capability import InstalledModelCapabilityPort
from sylanne3.host.installation_grant_identity import (
    same_installed_grant_identity_v2,
)
from sylanne3.host.mtls_transport import MtlsAuthorityTransport
from sylanne3.host.natural_generation_content_port import (
    InstalledNaturalGenerationContentPortV2,
)
from sylanne3.host.natural_generation_output_port import (
    InstalledNaturalGenerationOutputPortV2,
)
from sylanne3.host.natural_paid_review_port import InstalledNaturalPaidReviewPortV2
from sylanne3.host.natural_review_output_port import InstalledNaturalReviewOutputPortV2
from sylanne3.host.final_handoff_pairing import (
    TrustedFinalHandoffBindingV1, VerifiedFinalHandoffPairingV1,
)
from sylanne3.host.reverse_handoff import HostReverseGraphClaimServer
from sylanne3.host.scene_candidates import SceneCandidateCatalog
from sylanne3.host.v2_fence_port import V2FencePort
from sylanne3.host.v2_installation import V2InstallationAssembly
from sylanne3.graph_worker import GraphWorker
from sylanne3.installation_policy import AdminInstallationPolicy
from sylanne3.runtime.budget import BudgetLease
from sylanne3.runtime.issuers import BudgetLeaseGrant
from sylanne3.runtime_contracts import (
    CommitReceipt, InstallationGrantV2, NamespaceId, SourceQualification,
)
from sylanne3.runtime_context import (
    RuntimeContext, RuntimeHealth, _InstalledNaturalReplyReadinessReceiptV2,
)
from sylanne3.runtime.natural_reply_job_v2 import SavedNaturalPreparationV2


def test_partial_natural_installation_holds_before_generation_job(tmp_path):
    class Worker:
        calls = 0

        async def call(self, *_args, **_kwargs):
            self.calls += 1
            raise AssertionError("partial natural installation reached graph worker")

    runtime = RuntimeContext(tmp_path, dependencies=None)
    worker = Worker()
    policy, grant, bundle = object(), object(), object()
    installation = V2InstallationAssembly(
        policy, grant, b"d11", b"d02", lambda: None,
        tmp_path, tmp_path, admin_bundle=bundle,
    )
    runtime._worker = worker
    runtime._v2_bootstrap = object()
    runtime._v2_port = object()
    runtime._v2_cost_transport = object()
    runtime._v2_namespace_provisioned = True
    runtime._v2_policy = policy
    runtime._v2_installation_grant = grant
    runtime._v2_model_bundle = bundle
    runtime._v2_natural_generation_output_bound = True
    runtime._v2_natural_generation_content_bound = True
    runtime._v2_natural_review_output_bound = True
    runtime._v2_natural_paid_review_current_bound = True
    sender = dict(server=None, listener=None, candidates=None, context=None)

    assert runtime.natural_reply_product_ready_v2(
        installation, **sender) is False
    assert asyncio.run(runtime.prepare_post_c02_natural_generation_v2(
        installation=installation, c02_operation_id="c02",
        source_ref="source", **sender)) is None
    assert asyncio.run(runtime.run_installed_natural_reply_v2(
        installation, trusted_umo="private", saved=None,
        **sender)) is None
    assert worker.calls == 0


def test_natural_client_grant_accepts_own_channel_only_for_same_installation():
    graph = InstallationGrantV2(
        "authority", "worker", "holder", "install", "a" * 64,
        "publisher", "v2", "b" * 64)
    own_client = replace(graph, channel_binding_sha256="c" * 64)

    assert same_installed_grant_identity_v2(graph, own_client)
    assert not same_installed_grant_identity_v2(
        graph, replace(own_client, installation_id="other"))
    assert not same_installed_grant_identity_v2(
        graph, replace(own_client, manifest_digest="d" * 64))


def test_controlled_full_chain_receipt_rejects_crossed_installation(
    tmp_path, monkeypatch,
):
    """Composition only: the Owner/P2 and TLS acceptance suites remain separate."""
    from astrbot.api.star import Context
    from sylanne3.host import installed_natural_reply_driver as generation_driver
    from sylanne3.host import installed_natural_review_driver as review_driver

    def set_fields(value, **fields):
        for name, field in fields.items():
            object.__setattr__(value, name, field)
        return value

    async def exercise():
        loop = asyncio.get_running_loop()
        namespace = NamespaceId("bot", "persona")
        lease = BudgetLease(
            "root", None, "bot", "persona", "USD",
            {"output_tokens": 128}, {}, {}, {}, 1, "active")
        budget = BudgetLeaseGrant(
            "grant", 1, "bot", "persona", "root", "USD",
            {"output_tokens": 128}, ("reply",), 4102444800, "budget-policy")
        policy = AdminInstallationPolicy(
            namespace, "bot/persona", "install", "a" * 64,
            "holder", "authority", "b" * 64, "scheme", "operator",
            "policy", lease, budget)
        grant = InstallationGrantV2(
            "authority", "worker", "holder", "install", "a" * 64,
            "publisher", "v2", "b" * 64)
        client_grant = replace(grant, channel_binding_sha256="c" * 64)
        generation = set_fields(
            AdminModelWorkflowV2.__new__(AdminModelWorkflowV2),
            template_version="natural-gen", provider_id="provider-gen",
            model_id="model-gen", provider_config_digest="d" * 64)
        review = set_fields(
            AdminModelWorkflowV2.__new__(AdminModelWorkflowV2),
            template_version="natural-review", provider_id="provider-review",
            model_id="model-review", provider_config_digest="e" * 64)
        workflows = set_fields(
            AdminModelWorkflowsV2.__new__(AdminModelWorkflowsV2),
            natural_generation=generation, natural_review=review)
        profile = SimpleNamespace(namespace="bot/persona", installation_id="install")
        bundle = AdminInstallationBundle(
            SimpleNamespace(profile_id="profile"), policy, b"d11", b"d02",
            ingress_clock=AdminIngressClockPolicy.__new__(AdminIngressClockPolicy),
            model_workflows=workflows,
            private_reply_dispatch=AdminPrivateReplyDispatchPolicy.__new__(
                AdminPrivateReplyDispatchPolicy))
        binding = set_fields(
            TrustedFinalHandoffBindingV1.__new__(TrustedFinalHandoffBindingV1),
            profile=profile)
        installation = V2InstallationAssembly(
            policy, grant, b"d11", b"d02", lambda: None,
            tmp_path, tmp_path, admin_bundle=bundle, reverse_handoff=binding)
        context = Context.__new__(Context)
        candidates = SceneCandidateCatalog.__new__(SceneCandidateCatalog)
        server = HostReverseGraphClaimServer.__new__(HostReverseGraphClaimServer)
        server.profile = profile

        class Listener(asyncio.AbstractServer):
            def is_serving(self):
                return True

        listener = Listener()
        worker = GraphWorker.__new__(GraphWorker)
        graph = GraphCoordinator.__new__(GraphCoordinator)
        port = V2FencePort.__new__(V2FencePort)
        transport = MtlsAuthorityTransport.__new__(MtlsAuthorityTransport)
        client = AuthorityClient.__new__(AuthorityClient)
        client._transport = transport
        client._selection = AuthoritySelection("profile")
        client._v2_handshake = SimpleNamespace(channel_binding_sha256="c" * 64)
        selection = InstalledModelCapabilityPort.__new__(InstalledModelCapabilityPort)
        selection._installation_bundle = bundle
        selection._installed_namespace = namespace
        selection._host_loop = loop
        selection._context = context
        specs = (
            (InstalledNaturalGenerationOutputPortV2,
             "read_original_natural_generation_output_v2"),
            (InstalledNaturalGenerationContentPortV2,
             "read_current_natural_generation_content_v2"),
            (InstalledNaturalReviewOutputPortV2,
             "read_original_natural_review_output_v2"),
            (InstalledNaturalPaidReviewPortV2,
             "read_current_natural_paid_review_v2"),
        )
        natural_ports = []
        for kind, method in specs:
            adapter = kind.__new__(kind)
            adapter._bundle, adapter._grant = bundle, client_grant
            adapter._client, adapter._loop = client, loop
            natural_ports.append(getattr(adapter, method))
        authority, p2_lease = object(), object()
        route = InstalledDispatchRoutePort.__new__(InstalledDispatchRoutePort)
        route._context, route._host_loop = context, loop
        route._candidates, route._coordinator = candidates, graph
        route._authority, route._lease = authority, p2_lease
        route._namespace = namespace
        writer = SimpleNamespace(
            graph=graph, port=port, issuer_id="issuer", route_port=route)
        verified = VerifiedFinalHandoffPairingV1("issuer", binding, "digest")
        receipt = _InstalledNaturalReplyReadinessReceiptV2(
            installation, bundle, policy, grant, client_grant,
            worker, graph, port, transport, client, selection, loop,
            tuple(natural_ports), verified, writer, context, candidates)
        runtime = RuntimeContext(tmp_path, dependencies=None)
        runtime._worker, runtime._v2_bootstrap = worker, object()
        runtime._v2_coordinator, runtime._v2_port = graph, port
        runtime._v2_cost_transport = transport
        runtime._v2_policy, runtime._v2_installation_grant = policy, grant
        runtime._v2_model_bundle, runtime._v2_namespace = bundle, namespace
        runtime._v2_namespace_provisioned = True
        runtime._model_selection_port = selection
        runtime._final_claim_writer = writer
        runtime._final_claim_authority, runtime._final_claim_lease = (
            authority, p2_lease)
        runtime._v2_natural_generation_output_bound = True
        runtime._v2_natural_generation_content_bound = True
        runtime._v2_natural_review_output_bound = True
        runtime._v2_natural_paid_review_current_bound = True
        runtime._v2_natural_readiness_receipt = receipt
        runtime.health = RuntimeHealth("limited")

        def expected(stage, **kwargs):
            model = generation if stage == "generation" else review
            return kwargs == dict(
                namespace=namespace, template_version=model.template_version,
                installation_id="install", provider_id=model.provider_id,
                model_id=model.model_id,
                provider_config_digest=model.provider_config_digest)

        monkeypatch.setattr(generation_driver,
                            "NATURAL_GENERATION_TERMINAL_RECOVERY_READY_V2", True,
                            raising=False)
        monkeypatch.setattr(review_driver,
                            "NATURAL_REVIEW_TERMINAL_RECOVERY_READY_V2", True,
                            raising=False)
        monkeypatch.setattr(V2FencePort, "natural_paid_consumer_ready_v2",
                            lambda self, **kwargs: expected("generation", **kwargs))
        monkeypatch.setattr(V2FencePort, "natural_review_paid_consumer_ready_v2",
                            lambda self, **kwargs: expected("review", **kwargs))
        args = dict(server=server, listener=listener, candidates=candidates,
                    context=context)
        assert runtime.natural_reply_product_ready_v2(installation, **args)
        runtime._v2_natural_readiness_receipt = replace(
            receipt, client_grant=replace(client_grant, installation_id="other"))
        assert not runtime.natural_reply_product_ready_v2(installation, **args)
        runtime._v2_natural_readiness_receipt = replace(
            receipt, natural_ports=(natural_ports[1], *natural_ports[1:]))
        assert not runtime.natural_reply_product_ready_v2(installation, **args)

    asyncio.run(exercise())


def test_c02_recovery_source_comes_only_from_fenced_original(tmp_path):
    namespace = NamespaceId("bot", "persona")
    lease = BudgetLease(
        "root", None, "bot", "persona", "USD",
        {"output_tokens": 128}, {}, {}, {}, 1, "active")
    grant = BudgetLeaseGrant(
        "grant", 1, "bot", "persona", "root", "USD",
        {"output_tokens": 128}, ("reply",), 4102444800, "budget-policy")
    policy = AdminInstallationPolicy(
        namespace, "bot/persona", "install", "a" * 64,
        "holder", "authority", "b" * 64, "scheme", "operator",
        "policy", lease, grant)
    bundle = AdminInstallationBundle(None, policy, b"d11", b"d02")
    c02 = CommitReceipt(
        "committed", "c02-original", "c" * 64, "activity", None, 1,
        (), (), (), (), ())
    qualification = SourceQualification(
        ("source:original",), "reported", None, 1.0,
        "external_report", "qualified", None, "not_applicable")

    class Graph:
        def read_post_c02_attention_inputs_v1(
            self, received_bootstrap, received_namespace, operation_id,
            source_selector, received_bundle,
        ):
            assert received_bootstrap is bootstrap
            assert received_namespace == namespace
            assert operation_id == c02.operation_id
            assert source_selector is None
            assert received_bundle is bundle
            return c02, None, qualification, None, None, None, None

    class Worker:
        async def call(self, operation):
            return operation(Graph())

    bootstrap = object()
    runtime = RuntimeContext(tmp_path, dependencies=None)
    runtime._worker = Worker()
    runtime._v2_bootstrap = bootstrap
    runtime._v2_port = object()
    runtime._v2_namespace_provisioned = True
    runtime._v2_policy = policy
    runtime._v2_model_bundle = bundle

    assert asyncio.run(runtime.read_original_c02_source_ref_v2(
        "c02-original")) == "source:original"
    assert asyncio.run(runtime.read_original_c02_source_ref_v2("")) is None


def test_committed_natural_final_recovery_skips_paid_calls(tmp_path):
    namespace, parent, seal, frozen, versions, queries, _ = _case()
    saved = SavedNaturalPreparationV2(
        "generation", parent, seal, frozen, versions, queries,
        2, 3, 4, "queued", None, None, None, None)
    progress = NaturalOriginalProgressV2(
        namespace, parent,
        NaturalOriginalStageStatusV2(
            "generation", "terminal", seal.job_id,
            seal.original_operation_id, seal.acquire_operation_id,
            seal.call_id, None, "a" * 64, "b" * 64),
        None, frozen.input.plan.final_operation_id, 1, 1)
    installation = V2InstallationAssembly(
        SimpleNamespace(namespace=namespace), object(), b"d11", b"d02",
        lambda: None, tmp_path, tmp_path)
    runtime = RuntimeContext(tmp_path, dependencies=None)
    runtime.natural_reply_product_ready_v2 = lambda *_args, **_kwargs: True
    runtime.read_installed_natural_original_progress_v2 = AsyncMock(
        return_value=progress)
    result = object()
    runtime.dispatch_committed_natural_reply_v2 = AsyncMock(
        return_value=result)

    assert asyncio.run(runtime.run_installed_natural_reply_v2(
        installation, context=None, trusted_umo="private", saved=saved,
        server=None, listener=None, candidates=None)) is result
    runtime.dispatch_committed_natural_reply_v2.assert_awaited_once_with(
        installation, operation_id=frozen.input.plan.final_operation_id,
        context=None, server=None, listener=None, candidates=None)


def test_unfinished_natural_scan_uses_original_graph_page(tmp_path):
    namespace = NamespaceId("bot", "persona")
    lease = BudgetLease(
        "root", None, "bot", "persona", "USD",
        {"output_tokens": 128}, {}, {}, {}, 1, "active")
    budget_grant = BudgetLeaseGrant(
        "grant", 1, "bot", "persona", "root", "USD",
        {"output_tokens": 128}, ("reply",), 4102444800, "budget-policy")
    policy = AdminInstallationPolicy(
        namespace, "bot/persona", "install", "a" * 64,
        "holder", "authority", "b" * 64, "scheme", "operator",
        "policy", lease, budget_grant)
    grant = InstallationGrantV2(
        "authority", "worker", "holder", "install", "a" * 64,
        "publisher", "v2", "c" * 64)
    bundle = AdminInstallationBundle(None, policy, b"d11", b"d02")
    installation = V2InstallationAssembly(
        policy, grant, b"d11", b"d02", lambda: None,
        tmp_path, tmp_path, admin_bundle=bundle)
    expected = NaturalPendingOriginalPageV2(
        namespace, (NaturalPendingOriginalItemV2(
            "c02-original", "source:original", "terminal", "terminal"),),
        None, 3, 5)
    calls = []

    class Graph:
        def grant(self, received_bootstrap, **kwargs):
            assert received_bootstrap is bootstrap
            assert kwargs["namespace"] == namespace
            assert kwargs["domains"] == ("d11",)
            return "lease", "capability"

        def discover_pending_post_c02_natural_stages_v2(
            self, authority, received_lease, *, after, limit,
            installed_bundle,
        ):
            assert received_lease == "lease"
            assert authority.namespace == namespace
            assert authority.purpose == "proposal"
            assert installed_bundle is bundle
            assert after is None and limit == 32
            calls.append("read")
            return expected

        def release_authority_lease(self, received_bootstrap, received_lease):
            assert received_bootstrap is bootstrap
            assert received_lease == "lease"
            calls.append("release")

    class Worker:
        async def call(self, operation):
            return operation(Graph())

    bootstrap = object()
    runtime = RuntimeContext(tmp_path, dependencies=None)
    runtime._worker = Worker()
    runtime._v2_bootstrap = bootstrap
    runtime._v2_port = SimpleNamespace(current_anchor=lambda **_kwargs:
                                       SimpleNamespace(activation_generation=1))
    runtime.natural_reply_product_ready_v2 = lambda *_args, **_kwargs: True

    assert asyncio.run(runtime.discover_pending_natural_stages_v2(
        installation, server=None, listener=None, candidates=None,
        context=None)) is expected
    assert calls == ["read", "release"]
    assert asyncio.run(runtime.discover_pending_natural_stages_v2(
        installation, server=None, listener=None, candidates=None,
        context=None, limit=65)) is None
    assert calls == ["read", "release"]
