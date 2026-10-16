"""Installed D13 bridge only reads and projects low-trust raw history."""

from dataclasses import replace
import sys
from types import ModuleType, SimpleNamespace

import pytest

from sylanne3.host.authority_profile import (
    AdminInstallationBundle, AdminModelWorkflowsV2, AdminModelWorkflowV2,
    installed_model_config_ref,
)
from sylanne3.host.ingress import HostIngressEnvelope, SourceLineage
from sylanne3.host.installed_d13_context_frame import (
    read_installed_d13_raw_context_frame_v1,
)
from sylanne3.model_broker.d13_precompression import D13PrecompressionInstallationV1
from sylanne3.model_broker.reply_language import REPLY_TEMPLATE_VERSION
from sylanne3.runtime.d13_technical_policy import AdminD13PrecompressionPolicyV1
from sylanne3.runtime.first_ingress_v2 import ingress_ids
from sylanne3.runtime_contracts import (
    CompletedTurnV1, ConversationWindowProjectionV1, NamespaceId, VersionedRef,
)


class RuntimeContext:
    def installed_d13_main_model_v1(self):
        workflow = self._v2_model_bundle.model_workflows.reply
        return D13PrecompressionInstallationV1(
            self._v2_policy.installation_id, workflow.provider_id,
            workflow.model_id, workflow.provider_config_digest,
            workflow.max_output_tokens)


class _Graph:
    def __init__(self, window):
        self.window = window
        self.reads = self.releases = 0

    def grant(self, *_args, **_kwargs):
        return object(), "capability"

    def read_current_d13_conversation_window_v1(
            self, authority, _lease, *, scene_ref, max_slots):
        assert authority.purpose == "context"
        assert scene_ref == "scene:expected" and max_slots == 8
        self.reads += 1
        return self.window

    def release_authority_lease(self, *_args):
        self.releases += 1


class _Worker:
    def __init__(self, graph):
        self.graph = graph

    async def call(self, function, *args):
        return function(self.graph, *args)


def _case(monkeypatch):
    namespace = NamespaceId("bot", "persona")
    envelope = HostIngressEnvelope(
        namespace, "platform", "conversation", "sender", "message", "hello",
        None, 1.0, "private",
        SourceLineage("a" * 64, "reported", "host", "external_report",
                      "reported_claim"))
    scene, audience = VersionedRef("scene", 1), VersionedRef("audience", 1)
    raw, source, access = (VersionedRef(name, 1) for name in
                           ("raw", "source", "access"))
    turn = CompletedTurnV1(
        "conversation", audience, 0, raw, source, access, "user", "原始消息。",
        100.0, "confirmed", "not_applicable")
    window = ConversationWindowProjectionV1(
        namespace, "owner", "conversation", scene, audience, (turn,), 0,
        120.0, (raw, source, access), (scene, audience, raw, source, access),
        0, 0, 1)
    graph = _Graph(window)
    digest = "b" * 64
    common = dict(
        provider_id="provider", model_id="model",
        provider_config_ref=installed_model_config_ref("provider", "model", digest),
        provider_config_digest=digest, audiences=("conversation",),
        privacy_tier="private", required_capabilities=("text",),
        timeout_seconds=10.0, max_output_tokens=8,
        quote_ceiling={"output_tokens": 16})
    workflows = AdminModelWorkflowsV2(
        2,
        AdminModelWorkflowV2(work_kind="d06.encode_source",
                             purpose="consolidation", template_version="encode-fixture",
                             **common),
        AdminModelWorkflowV2(work_kind="reply", purpose="proposal",
                             template_version=REPLY_TEMPLATE_VERSION, **common))
    policy = SimpleNamespace(
        namespace=namespace, authority_namespace="authority",
        installation_id="install",
        root_grant=SimpleNamespace(policy_ref="policy", grant_id="grant", version=1),
        root_lease=SimpleNamespace(lease_id="lease"))
    d13 = AdminD13PrecompressionPolicyV1(
        namespace, "install", "grant", 1, "lease", 4096,
        {"d13_compute_units": 1}, 300, 8, "d13:cpu")
    runtime = RuntimeContext()
    runtime._v2_policy = policy
    runtime._v2_model_bundle = AdminInstallationBundle(
        object(), policy, b"d11", b"d02", d13_precompression=d13,
        model_workflows=workflows)
    runtime._v2_installation_grant = SimpleNamespace(subject="host")
    runtime._v2_port = SimpleNamespace(current_anchor=lambda **_kwargs:
                                       SimpleNamespace(activation_generation=1))
    runtime._worker = _Worker(graph)
    runtime._v2_bootstrap = object()
    runtime._v2_namespace_provisioned = True
    runtime._v2_namespace = namespace

    class AstrBotModelProvider:
        async def selected_d13_main_installation_v1(self):
            return runtime.installed_d13_main_model_v1()

    model_stub = ModuleType("sylanne3.host.astrbot_model_call")
    model_stub.AstrBotModelProvider = AstrBotModelProvider
    monkeypatch.setitem(sys.modules, model_stub.__name__, model_stub)
    runtime_stub = ModuleType("sylanne3.runtime_context")
    runtime_stub.RuntimeContext = RuntimeContext
    monkeypatch.setitem(sys.modules, runtime_stub.__name__, runtime_stub)
    monkeypatch.setattr(
        "sylanne3.host.installed_d13_context_frame.scene_ref_for_conversation",
        lambda *_args: "scene:expected")
    return runtime, AstrBotModelProvider(), envelope, graph


@pytest.mark.asyncio
async def test_raw_window_projection_is_read_only_and_model_bound(monkeypatch):
    runtime, provider, envelope, graph = _case(monkeypatch)
    original = ingress_ids(envelope.lineage.source_ref)[2]
    result = await read_installed_d13_raw_context_frame_v1(
        runtime, provider, envelope=envelope, ingress_operation_id=original)
    assert result is not None
    assert result.frame.status == "candidate_requires_exact_token_count"
    assert result.frame.stable_history == ()
    assert result.frame.history[0].text == "user: 原始消息。"
    assert graph.reads == graph.releases == 1
    result.close()

    async def changed(_self):
        return replace(runtime.installed_d13_main_model_v1(), model_id="other")

    monkeypatch.setattr(type(provider), "selected_d13_main_installation_v1", changed)
    assert await read_installed_d13_raw_context_frame_v1(
        runtime, provider, envelope=envelope, ingress_operation_id=original) is None
    assert await read_installed_d13_raw_context_frame_v1(
        runtime, provider, envelope=envelope, ingress_operation_id="other") is None
    assert graph.reads == 1
