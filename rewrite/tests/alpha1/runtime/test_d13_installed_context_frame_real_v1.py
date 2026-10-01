"""The installed bridge reads the actual GraphCoordinator D11 window."""

from dataclasses import replace

import pytest

from sylanne3.host.astrbot_model_call import AstrBotModelProvider
from sylanne3.host.authority_profile import AdminInstallationBundle
from sylanne3.host.ingress import HostIngressEnvelope, SourceLineage
from sylanne3.host.installed_d13_context_frame import (
    read_installed_d13_raw_context_frame_v1,
)
from sylanne3.memory_types import access_key
from sylanne3.runtime.d13_technical_policy import AdminD13PrecompressionPolicyV1
from sylanne3.runtime.first_ingress_v2 import ingress_ids
from sylanne3.runtime_context import RuntimeContext

from test_d13_current_conversation_window_v1 import _committed
from test_post_c02_reply_model_job_v1 import _reply_workflows
from test_reply_entity_route_v2 import CANONICAL_CONVERSATION, CANONICAL_PLATFORM
from test_reply_entity_route_v2 import canonical_private_case  # noqa: F401
from test_post_c02_reply_model_job_v1 import private_reply_c02_case  # noqa: F401
from test_first_ingress_c02_commit import c02_case  # noqa: F401


class _Worker:
    def __init__(self, graph):
        self.graph = graph
        self.error = None

    async def call(self, function, *args):
        try:
            return function(self.graph, *args)
        except Exception as exc:
            self.error = exc
            raise


@pytest.mark.asyncio
async def test_current_window_read_and_access_withdrawal_hold(
        canonical_private_case, monkeypatch):
    store, graph, bootstrap, namespace, policy, *_ = canonical_private_case
    _, _, _, source_id = _committed(canonical_private_case)
    original = ingress_ids(source_id)[2]
    port = graph._GraphCoordinator__content_fence_v2
    runtime = object.__new__(RuntimeContext)
    runtime._v2_policy = policy
    runtime._v2_installation_grant = port.installation_grant
    runtime._v2_port = port
    runtime._worker = _Worker(graph)
    runtime._v2_bootstrap = bootstrap
    runtime._v2_namespace_provisioned = True
    runtime._v2_namespace = namespace
    d13 = AdminD13PrecompressionPolicyV1(
        namespace, policy.installation_id, policy.root_grant.grant_id,
        policy.root_grant.version, policy.root_lease.lease_id,
        4096, {"d13_compute_units": 1}, 300, 8, "d13:cpu")
    runtime._v2_model_bundle = AdminInstallationBundle(
        object(), policy, b"d11", b"d02", d13_precompression=d13,
        model_workflows=_reply_workflows())
    envelope = HostIngressEnvelope(
        namespace, CANONICAL_PLATFORM, CANONICAL_CONVERSATION, "sender", "message",
        "hello", None, 1.0, "private",
        SourceLineage(source_id, "reported", "host", "external_report",
                      "reported_claim"))
    provider = object.__new__(AstrBotModelProvider)

    async def selected(_self):
        return runtime.installed_d13_main_model_v1()

    monkeypatch.setattr(AstrBotModelProvider,
                        "selected_d13_main_installation_v1", selected)
    before = store._db.total_changes
    result = await read_installed_d13_raw_context_frame_v1(
        runtime, provider, envelope=envelope, ingress_operation_id=original)
    assert result is not None, repr(runtime._worker.error)
    assert result.query.window.turns[0].source_ref.ref
    assert result.frame.status == "candidate_requires_exact_token_count"
    assert result.frame.history[0].text == "sender: hello"
    assert store._db.total_changes == before

    async def changed(_self):
        return replace(runtime.installed_d13_main_model_v1(), model_id="other")

    monkeypatch.setattr(AstrBotModelProvider,
                        "selected_d13_main_installation_v1", changed)
    assert await read_installed_d13_raw_context_frame_v1(
        runtime, provider, envelope=envelope, ingress_operation_id=original) is None
    monkeypatch.setattr(AstrBotModelProvider,
                        "selected_d13_main_installation_v1", selected)
    access_ref = access_key(*namespace.as_tuple, source_id).token
    with store._lock:
        store._db.execute("BEGIN IMMEDIATE")
        store._db.execute("UPDATE graph_atoms SET valid=0 WHERE token=?", (access_ref,))
        store._db.execute("COMMIT")
    assert await read_installed_d13_raw_context_frame_v1(
        runtime, provider, envelope=envelope, ingress_operation_id=original) is None
