"""The installed host consumes the scheduled D13 original with one D11 holder."""

import asyncio
from datetime import datetime, timezone
import time
from types import SimpleNamespace

import pytest

from sylanne3.host.authority_profile import (
    AdminInstallationBundle, _d13_precompression_from_payload,
    _policy_from_payload,
)
from sylanne3.host.ingress import HostIngressEnvelope, SourceLineage
from sylanne3.runtime_context import RuntimeContext
from sylanne3.runtime.d13_technical_policy import D13ScheduleRecoveryItemV2
from sylanne3.runtime_contracts import InstallationGrantV2

from test_d13_precompression_profile import _d13_payload


class _Worker:
    def __init__(self, graph):
        self.graph = graph

    async def call(self, callback):
        return callback(self.graph)


class _Graph:
    def __init__(self, job_type, receipt_type, budget_type):
        self.events = []
        self.job_type = job_type
        self.receipt_type = receipt_type
        self.budget_type = budget_type

    def grant(self, *_args, **kwargs):
        self.events.append(("grant", kwargs["actor"], kwargs["issuer_domain"]))
        return object(), "capability"

    def acquire_d13_deterministic_precompression_job_v2(
        self, authority, _lease, job_id, *, lease_seconds,
    ):
        self.events.append(("acquire", authority.actor, job_id, lease_seconds))
        return self.job_type(job_id, 7)

    def complete_d13_deterministic_precompression_job_v2(
        self, authority, _lease, job_id, *, fence,
    ):
        self.events.append(("complete", authority.actor, job_id, fence))
        return (self.receipt_type(), self.budget_type(), self.job_type(job_id, fence))

    def release_authority_lease(self, *_args):
        self.events.append("release")

    def discover_d13_precompression_schedule_attempts_v2(self, authority, _lease):
        self.events.append(("discover", authority.audience))
        return (D13ScheduleRecoveryItemV2(
            "original-schedule", "conversation", "scene:original"),)

    def recover_d13_precompression_schedule_v2(
        self, authority, _lease, *, original_operation_id,
    ):
        self.events.append(("recover", authority.audience, original_operation_id))
        job = self.job_type("original-job", 0)
        job.operation_id = original_operation_id
        job.continuation = {"conversation_ref": "conversation"}
        return self.budget_type(), job


@pytest.mark.asyncio
async def test_installed_d13_consumer_acquires_and_completes_original(monkeypatch):
    import sylanne3.runtime_context as context_module

    class Job:
        def __init__(self, job_id, fence):
            self.job_id = job_id
            self.fence = fence

    class Receipt:
        pass

    class Budget:
        pass

    monkeypatch.setattr(context_module, "PersistentJob", Job)
    monkeypatch.setattr(context_module, "D13CacheCommitReceiptV1", Receipt)
    monkeypatch.setattr(context_module, "BudgetReceipt", Budget)
    payload = _d13_payload()
    policy = _policy_from_payload(payload)
    d13 = _d13_precompression_from_payload(payload, policy)
    graph = _Graph(Job, Receipt, Budget)
    runtime = object.__new__(RuntimeContext)
    runtime._v2_policy = policy
    runtime._v2_model_bundle = AdminInstallationBundle(
        None, policy, b"d11", b"d02", d13_precompression=d13)
    runtime._v2_installation_grant = InstallationGrantV2(
        "authority", "mtls:sha256:" + "a" * 64, "holder", "install",
        "a" * 64, "policy", "v2", "b" * 64)
    runtime._v2_port = SimpleNamespace(current_anchor=lambda **_:
                                       SimpleNamespace(activation_generation=1))
    runtime._worker = _Worker(graph)
    runtime._v2_bootstrap = object()
    runtime._v2_namespace_provisioned = True
    runtime._v2_namespace = policy.namespace
    envelope = HostIngressEnvelope(
        policy.namespace, "platform", "conversation", "sender", "message",
        "hello", None, 1.0, "private",
        SourceLineage("a" * 64, "reported", "host", "external_report",
                      "reported_claim"))

    result = await runtime.consume_d13_deterministic_precompression_job_v2(
        job_id="original-job", conversation_ref=envelope.conversation_ref)
    assert result[2].job_id == "original-job"
    holder = runtime._v2_installation_grant.subject
    assert graph.events == [
        ("grant", holder, "d11"),
        ("acquire", holder, "original-job", 30),
        ("complete", holder, "original-job", 7),
        "release",
    ]
    graph.events.clear()
    items = await runtime.discover_d13_precompression_schedule_attempts_v2()
    recovered = await runtime.recover_d13_precompression_schedule_v2(
        original_operation_id=items[0].original_operation_id,
        conversation_ref=items[0].conversation_ref)
    assert recovered[1].job_id == "original-job"
    assert graph.events == [
        ("grant", holder, "d11"), ("discover", ()), "release",
        ("grant", holder, "d11"),
        ("recover", ("conversation",), "original-schedule"), "release",
    ]


@pytest.mark.asyncio
async def test_live_c02_queues_background_then_prepares_natural_without_waiting(monkeypatch):
    from astrbot.api.star import Context
    from rewrite.host_tests.alpha1.test_runtime_bootstrap import load_plugin_module

    module = load_plugin_module()
    events = []

    async def commit_c02(*_args, **_kwargs):
        return SimpleNamespace(operation_id="c02-original")

    async def settle_c02(*_args):
        return True

    monkeypatch.setattr(module, "run_installed_first_ingress_c02_v2", commit_c02)
    monkeypatch.setattr(module, "run_installed_committed_first_ingress_c02_cost_v2",
                        settle_c02)

    class Runtime:
        async def commit_confirmed_d13_inbound_turn_v1(self, **_kwargs):
            return object()

        async def commit_post_c02_attention_v1(self, **_kwargs):
            return SimpleNamespace(status="committed")

        async def schedule_d13_deterministic_precompression_v2(self, **_kwargs):
            pytest.fail("serial C02 must not await optional D13 schedule")

    plugin = module.Sylanne3Plugin(
        Context(asyncio.Queue(), {}, None, None, None, None, None, None, None, None, None),
        {"enabled": True})
    async def prepare_natural(*_args, **_kwargs):
        events.append("reply")

    plugin._prepare_new_post_c02_natural_v2 = prepare_natural
    plugin._queue_d13_schedule_v2 = lambda *_args, **_kwargs: events.append("d13")
    envelope = SimpleNamespace(
        namespace=module.NamespaceId("bot", "persona"),
        lineage=SimpleNamespace(source_ref="source"),
        conversation_ref="conversation")
    await plugin._run_first_ingress_c02(
        Runtime(), object(), "trusted-umo", envelope,
        SimpleNamespace(operation_id="ingress-original"))
    assert events == ["d13", "reply"]


@pytest.mark.asyncio
async def test_optional_d13_drain_runs_without_blocking_reply_task(monkeypatch):
    from astrbot.api.star import Context
    from rewrite.host_tests.alpha1.test_runtime_bootstrap import load_plugin_module

    module = load_plugin_module()
    events = []
    release = asyncio.Event()

    class Runtime:
        async def schedule_d13_deterministic_precompression_v2(self, **_kwargs):
            events.append("schedule")
            return object(), SimpleNamespace(job_id="original-job")

        async def consume_d13_deterministic_precompression_job_v2(self, **_kwargs):
            events.append("consume")
            return object()

    async def reply():
        await release.wait()

    plugin = module.Sylanne3Plugin(
        Context(asyncio.Queue(), {}, None, None, None, None, None, None, None, None, None),
        {"enabled": True})
    async def no_paid_configuration(*_args, **_kwargs):
        return None
    monkeypatch.setattr(module, "run_installed_d13_paid_precompression_v1", no_paid_configuration)
    runtime = Runtime()
    installation = SimpleNamespace(
        installation_policy=SimpleNamespace(namespace=module.NamespaceId("bot", "persona")))
    plugin._runtime = runtime
    plugin._v2_installation = installation
    reply_task = asyncio.create_task(reply())
    plugin._reply_tasks[reply_task] = "reply-job"
    envelope = SimpleNamespace(namespace=installation.installation_policy.namespace,
                               conversation_ref="conversation")
    try:
        plugin._queue_d13_schedule_v2(
            runtime, installation, "ingress-original", envelope, trusted_umo="trusted-umo")
        await plugin._d13_drain_task
        assert not reply_task.done()
        assert events == ["schedule", "consume"]
        release.set()
    finally:
        release.set()
        await reply_task


@pytest.mark.asyncio
async def test_d13_deadline_wake_only_expires_original_job():
    from astrbot.api.star import Context
    from rewrite.host_tests.alpha1.test_runtime_bootstrap import load_plugin_module

    module = load_plugin_module()
    events = []
    deadline = datetime.fromtimestamp(time.time() + 0.05, timezone.utc).isoformat()

    class Runtime:
        async def recover_d13_precompression_schedule_v2(self, **kwargs):
            events.append(("recover", kwargs["original_operation_id"]))
            return object(), SimpleNamespace(
                job_id="original-job", operation_id="original-job",
                continuation={"conversation_ref": "conversation"},
                phase="running", deadline_utc=deadline)

        async def expire_d13_deterministic_precompression_job_v2(self, **kwargs):
            events.append(("expire", kwargs["job_id"]))
            return object()

        async def consume_d13_deterministic_precompression_job_v2(self, **_kwargs):
            pytest.fail("deadline wake must not rerun the worker")

    plugin = module.Sylanne3Plugin(
        Context(asyncio.Queue(), {}, None, None, None, None, None, None, None, None, None),
        {"enabled": True})
    runtime = Runtime()
    installation = object()
    plugin._runtime = runtime
    plugin._v2_installation = installation
    try:
        await plugin._arm_d13_expiry_v2(
            runtime, installation, "original-job", "conversation")
        await plugin._arm_d13_expiry_v2(
            runtime, installation, "original-job", "conversation")
        assert events == [("recover", "original-job")]
        await asyncio.sleep(1.2)
        if plugin._d13_drain_task is not None:
            await plugin._d13_drain_task
        assert events == [("recover", "original-job"), ("expire", "original-job")]
        assert plugin._d13_deadline_wakes == {}
    finally:
        for handle in plugin._d13_deadline_wakes.values():
            handle.cancel()


@pytest.mark.asyncio
async def test_startup_reconciles_d13_fence_before_reply_scan():
    from astrbot.api.star import Context
    from rewrite.host_tests.alpha1.test_runtime_bootstrap import load_plugin_module

    module = load_plugin_module()
    plugin = module.Sylanne3Plugin(
        Context(asyncio.Queue(), {}, None, None, None, None, None, None, None, None, None),
        {"enabled": True})
    events = []

    async def record(name):
        events.append(name)

    async def d13(*, start_drain):
        assert start_drain is False
        await record("d13-fence")

    plugin._restore_d13_original_schedules_v2 = d13
    plugin._restore_committed_first_ingress_c02_cost_v1 = lambda: record("c02-cost")
    plugin._restore_acquired_first_ingress_c02_v1 = lambda: record("c02-acquired")
    plugin._restore_unacquired_first_ingress_c02_v1 = lambda: record("c02-unacquired")
    plugin._restore_pending_post_c02_reply_models_v1 = lambda: record("reply")
    await plugin._run_startup_c02_recovery_v1()
    assert events == ["d13-fence", "c02-cost", "c02-acquired",
                      "c02-unacquired", "reply"]
