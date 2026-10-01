"""The live AstrBot handler owns suppression; workers only carry its deadline."""

import asyncio
from dataclasses import replace
import importlib
from types import SimpleNamespace
import time

import pytest

from rewrite.host_tests.alpha1.test_runtime_bootstrap import (
    Event, _IngressContext, load_plugin_module,
)


class _Port:
    def __init__(self):
        self.calls = []

    async def wait_for_durable_admission_v1(self, **kwargs):
        self.calls.append(("wait", kwargs))
        return None

    async def close_host_default_v1(self, **kwargs):
        self.calls.append(("close", kwargs))
        return object()

    async def activate_reply_ownership_v1(self, **kwargs):
        self.calls.append(("activate", kwargs))
        raise AssertionError("host default must not activate ownership")

    async def recover_reply_ownership_v1(self, **kwargs):
        self.calls.append(("recover", kwargs))
        return None


class _Runtime:
    def __init__(self, module, *, accepted=True):
        self.module = module
        self.accepted = accepted
        self.port = _Port()
        suppression = importlib.import_module(
            "sylanne3.host.reply_suppression")
        self.reply_suppression_registry = suppression.HostReplySuppressionRegistryV1()
        self.port_requests = []

    async def handle_ingress(self, _envelope):
        return self.module.IngressReceipt(
            "accepted" if self.accepted else "duplicate", "ingress-op")

    async def commit_first_ingress_pre_encoding_stages_v1(self, *_):
        return SimpleNamespace(job_id="job", namespace=None)

    async def first_ingress_c02_accounting_installed_v1(self):
        return True

    def reply_takeover_port_v1(self, envelope, receipt, *, deadline_monotonic):
        self.port_requests.append((envelope, receipt, deadline_monotonic))
        return self.port


def _plugin(module, runtime, envelope, *, wait=0.02):
    policy = SimpleNamespace(namespace=envelope.namespace)
    dispatch = module.AdminPrivateReplyDispatchPolicy(
        5.0, {"output_tokens": 1}, "snapshot", "resource", 128, wait)
    bundle = module.AdminInstallationBundle(
        SimpleNamespace(), policy, b"a" * 32, b"b" * 32,
        private_reply_dispatch=dispatch)
    installation = SimpleNamespace(
        installation_policy=policy, admin_bundle=bundle,
        installation_grant=SimpleNamespace(installation_id="install"))
    plugin = module.Sylanne3Plugin.__new__(module.Sylanne3Plugin)
    plugin.context = _IngressContext()
    plugin._enabled = True
    plugin._runtime = runtime
    plugin._encoding_stopping = False
    plugin.runtime_health = module.RuntimeHealth("ready")
    plugin._installed_namespace = envelope.namespace
    plugin._scene_candidates = SimpleNamespace(observe=lambda _: None)
    plugin._v2_installation = installation
    return plugin


@pytest.mark.asyncio
async def test_accepted_private_handler_closes_default_when_queue_fails():
    module = load_plugin_module()
    event = Event()
    envelope = await module.build_astrbot_ingress(event, _IngressContext())
    runtime = _Runtime(module)
    plugin = _plugin(module, runtime, envelope)
    queued = []

    async def schedule(*args, **kwargs):
        queued.append(kwargs)
        return False

    plugin._schedule_first_ingress_c02 = schedule
    await plugin.ingress(event)
    assert len(queued) == 1
    # No paired reverse listener means no sender capacity. The handler closes
    # host default before any stop_event and passes no live takeover identity.
    assert queued[0]["handler_invocation_id"] is None
    assert queued[0]["handler_deadline_utc"] is None
    assert [name for name, _ in runtime.port.calls] == ["close"]
    assert not event.is_stopped()


@pytest.mark.asyncio
async def test_private_handler_keeps_host_default_when_sender_capacity_is_full():
    module = load_plugin_module()
    event = Event()
    envelope = await module.build_astrbot_ingress(event, _IngressContext())
    runtime = _Runtime(module)
    plugin = _plugin(module, runtime, envelope)
    plugin._final_handoff_server = object()
    plugin._final_handoff_listener = object()
    plugin._final_claim_writer = object()
    plugin._reply_tasks = {object(): "busy" for _ in range(8)}
    async def schedule(*_, **__):
        return True
    plugin._schedule_first_ingress_c02 = schedule

    await plugin.ingress(event)
    assert [name for name, _ in runtime.port.calls] == ["close"]
    assert not event.is_stopped()


@pytest.mark.asyncio
async def test_reverse_listener_reserves_only_one_private_dispatch_window():
    module = load_plugin_module()
    envelope = await module.build_astrbot_ingress(Event(), _IngressContext())
    runtime = _Runtime(module)
    plugin = _plugin(module, runtime, envelope)
    plugin._final_handoff_server = object()
    plugin._final_handoff_listener = object()
    plugin._final_claim_writer = object()
    plugin._reply_tasks = {}

    first = plugin._reserve_private_reply_dispatch_v1(
        runtime, plugin._v2_installation, "ingress-one", "handler:one")
    second = plugin._reserve_private_reply_dispatch_v1(
        runtime, plugin._v2_installation, "ingress-two", "handler:two")
    assert first is not None and second is None
    first.set_result(False)
    await asyncio.gather(*tuple(plugin._reply_tasks))


@pytest.mark.asyncio
async def test_duplicate_or_non_private_ingress_never_enters_takeover(monkeypatch):
    module = load_plugin_module()
    event = Event()
    envelope = await module.build_astrbot_ingress(event, _IngressContext())
    runtime = _Runtime(module, accepted=False)
    plugin = _plugin(module, runtime, envelope)
    await plugin.ingress(event)
    assert runtime.port_requests == []
    assert runtime.port.calls == []

    group = replace(envelope, visibility="group")
    runtime.accepted = True
    async def group_envelope(*_):
        return group
    monkeypatch.setattr(module, "build_astrbot_ingress", group_envelope)
    async def schedule(*_, **__):
        return True
    plugin._schedule_first_ingress_c02 = schedule
    await plugin.ingress(event)
    assert runtime.port_requests == []


@pytest.mark.asyncio
@pytest.mark.parametrize("takeover_status,expected_dispatches", [
    ("host_default", 0),
    ("takeover_unknown", 0),
    ("activation_unverified", 0),
    ("sylanne_owned", 1),
])
async def test_private_dispatch_only_scheduled_after_normal_takeover(
        monkeypatch, takeover_status, expected_dispatches):
    module = load_plugin_module()
    event = Event()
    envelope = await module.build_astrbot_ingress(event, _IngressContext())
    runtime = _Runtime(module)
    plugin = _plugin(module, runtime, envelope)
    plugin._final_handoff_server = object()
    plugin._final_handoff_listener = object()
    plugin._final_claim_writer = object()
    plugin._reply_tasks = {}
    dispatched = []

    async def schedule(*args, **kwargs):
        return True

    async def rendezvous(**kwargs):
        if takeover_status != "host_default":
            event.stop_event()
        return SimpleNamespace(status=takeover_status)

    async def dispatch(**kwargs):
        dispatched.append(kwargs)
        return SimpleNamespace(status="accepted")

    plugin._schedule_first_ingress_c02 = schedule
    runtime.dispatch_owned_private_reply_v1 = dispatch
    monkeypatch.setattr(module, "rendezvous_private_reply_v1", rendezvous)
    await plugin.ingress(event)
    if plugin._reply_tasks:
        await asyncio.gather(*tuple(plugin._reply_tasks))
    assert len(dispatched) == expected_dispatches
    assert event.is_stopped() is (takeover_status != "host_default")
    if expected_dispatches:
        assert dispatched[0]["ingress_operation_id"] == "ingress-op"
        assert dispatched[0]["handler_invocation_id"].startswith("handler:")
    assert runtime.port.calls == []


@pytest.mark.asyncio
async def test_new_c02_holds_while_existing_reply_keeps_handler_identity(monkeypatch):
    module = load_plugin_module()
    event = Event()
    envelope = await module.build_astrbot_ingress(event, _IngressContext())
    runtime = _Runtime(module)
    plugin = _plugin(module, runtime, envelope)
    plugin._encoding_pending = asyncio.Queue(maxsize=8)
    plugin._encoding_inflight = set()
    plugin._encoding_waiters = set()
    plugin._encoding_tasks = set()
    plugin._reply_attempted_jobs = set()
    plugin._reply_tasks = {}
    plugin._reply_backlog_waiting = False
    plugin._reply_drain_task = None
    installation = plugin._v2_installation
    receipt = module.IngressReceipt("accepted", "ingress-op")
    seen = []

    async def c02(*_, **__):
        return SimpleNamespace(operation_id="c02-op")
    async def settle(*_):
        return True
    monkeypatch.setattr(module, "run_installed_first_ingress_c02_v2", c02)
    monkeypatch.setattr(module, "run_installed_committed_first_ingress_c02_cost_v2", settle)
    async def attention(**_):
        return SimpleNamespace(status="committed")
    async def prepare(**_):
        raise AssertionError("new C02 must not create a V1 paid reply")
    runtime.commit_post_c02_attention_v1 = attention
    runtime.prepare_post_c02_reply_model_job_v1 = prepare
    def schedule_reply(*_, **kwargs):
        seen.append(kwargs)
    plugin._schedule_post_c02_reply_model_v1 = schedule_reply
    deadline = time.time() + 10
    assert await plugin._queue_first_ingress_c02(
        runtime, installation, "umo", envelope, receipt, "job",
        handler_invocation_id="handler:one", handler_deadline_utc=deadline)
    await asyncio.sleep(0)
    await asyncio.gather(*tuple(plugin._encoding_tasks))
    assert seen == []

    progress = SimpleNamespace(
        run=SimpleNamespace(terminal=SimpleNamespace(terminal=object())),
        cost=object(), candidate=object())
    async def model(*_, **__):
        return progress
    monkeypatch.setattr(module, "run_installed_post_c02_reply_model_v1", model)
    assembled = []
    async def assemble(current, **kwargs):
        assembled.append((current, kwargs))
        return SimpleNamespace(status="committed")
    runtime.assemble_post_c02_reply_v2 = assemble
    await plugin._continue_post_c02_reply_model_v1(
        runtime, installation, object(), "umo",
        handler_invocation_id="handler:one", handler_deadline_utc=deadline)
    await plugin._continue_post_c02_reply_model_v1(
        runtime, installation, object(), "umo")
    assert assembled == [(progress, {"handler_invocation_id": "handler:one",
                                     "handler_deadline_utc": deadline})]
