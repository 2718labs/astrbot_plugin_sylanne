"""A restart discovers original reply jobs before any model continuation."""

import asyncio
import json
from types import SimpleNamespace

import pytest

from astrbot.api.star import Context

from rewrite.host_tests.alpha1.test_runtime_bootstrap import load_plugin_module


@pytest.mark.asyncio
async def test_slow_reply_model_does_not_hold_the_second_c02_ingress(monkeypatch):
    module = load_plugin_module()
    namespace = module.NamespaceId("bot", "persona")
    installation = object()
    model_release = asyncio.Event()
    second_c02 = asyncio.Event()
    committed = []
    model_started = []

    async def commit_c02(_runtime, _installation, **kwargs):
        committed.append(kwargs["envelope"].lineage.source_ref)
        if len(committed) == 2:
            second_c02.set()
        return SimpleNamespace(operation_id="c02-" + committed[-1])

    async def settle_c02(_runtime, _installation, _operation_id):
        return True

    monkeypatch.setattr(module, "run_installed_first_ingress_c02_v2", commit_c02)
    monkeypatch.setattr(
        module, "run_installed_committed_first_ingress_c02_cost_v2", settle_c02)

    class Runtime:
        async def commit_post_c02_attention_v1(self, **_):
            return SimpleNamespace(status="committed")

        async def prepare_post_c02_reply_model_job_v1(self, **kwargs):
            original = "reply-" + kwargs["c02_operation_id"]
            return module.ReplyModelQueuedPreparationV1(
                kwargs["c02_operation_id"], kwargs["source_ref"], original,
                SimpleNamespace(job_id=original, operation_id=original),
                None, "digest", 1)

    plugin = module.Sylanne3Plugin(
        Context(asyncio.Queue(), {}, None, None, None, None,
                None, None, None, None, None), {"enabled": True})
    plugin._runtime = Runtime()
    plugin._v2_installation = installation

    async def slow_original(_runtime, _installation, queued, _trusted_umo):
        model_started.append(queued.job.job_id)
        await model_release.wait()

    plugin._continue_post_c02_reply_model_v1 = slow_original
    for index in (1, 2):
        envelope = SimpleNamespace(
            namespace=namespace,
            lineage=SimpleNamespace(source_ref=f"source-{index}"))
        plugin._encoding_pending.put_nowait((
            ("job", str(index)), plugin._runtime, installation,
            "trusted-umo", envelope, object()))

    worker = asyncio.create_task(plugin._drive_first_ingress_c02_queue())
    try:
        await asyncio.wait_for(second_c02.wait(), timeout=2)
        await worker
        assert committed == ["source-1", "source-2"]
        assert not model_release.is_set()
        await asyncio.sleep(0)
        assert model_started == ["reply-c02-source-1", "reply-c02-source-2"]
        assert len(plugin._reply_tasks) == 2
    finally:
        model_release.set()
        await asyncio.gather(*tuple(plugin._reply_tasks), return_exceptions=True)


@pytest.mark.asyncio
async def test_ninth_durable_reply_job_drains_after_one_slot_opens():
    module = load_plugin_module()
    namespace = module.NamespaceId("bot", "persona")
    installation = SimpleNamespace(
        installation_policy=SimpleNamespace(namespace=namespace),
        installation_grant=SimpleNamespace(installation_id="install"))
    audience = json.dumps(["trusted-umo", "conversation"], separators=(",", ":"))
    queued = tuple(module.ReplyModelQueuedPreparationV1(
        f"c02-{index}", f"source-{index}", f"original-{index}",
        SimpleNamespace(job_id=f"job-{index}", operation_id=f"original-{index}"),
        None, f"digest-{index}", 1) for index in range(1, 10))
    items = tuple(module.ReplyModelRecoveryItemV1(
        job.job.job_id, job, audience, None) for job in queued)
    pages = (
        module.ReplyModelRecoveryPageV1(
            namespace, "install", "incarnation", 5, 5, items[:8], "job-8"),
        module.ReplyModelRecoveryPageV1(
            namespace, "install", "incarnation", 5, 5, items[8:], None),
    )
    scanned = []

    class Runtime:
        v2_ingress_qualified = True

        async def discover_pending_post_c02_reply_model_jobs_v1(
            self, *, cursor, limit,
        ):
            scanned.append(cursor)
            assert limit == 8
            return pages[0 if cursor is None else 1]

    plugin = module.Sylanne3Plugin(
        Context(asyncio.Queue(), {}, None, None, None, None,
                None, None, None, None, None), {"enabled": True})
    plugin._runtime = Runtime()
    plugin._v2_installation = installation
    release = {job.job.job_id: asyncio.Event() for job in queued}
    ninth_started = asyncio.Event()
    started = []

    async def continue_original(_runtime, _installation, job, _trusted_umo):
        started.append(job.job.job_id)
        if job.job.job_id == "job-9":
            ninth_started.set()
        await release[job.job.job_id].wait()

    plugin._continue_post_c02_reply_model_v1 = continue_original
    for job in queued:
        plugin._schedule_post_c02_reply_model_v1(
            plugin._runtime, installation, job, "trusted-umo")
    try:
        assert len(plugin._reply_tasks) == 8
        assert "job-9" not in plugin._reply_attempted_jobs
        await asyncio.sleep(0)
        release["job-1"].set()
        await asyncio.wait_for(ninth_started.wait(), timeout=2)
        assert scanned == [None, "job-8"]
        assert started.count("job-9") == 1
        assert plugin._reply_attempted_jobs == {
            f"job-{index}" for index in range(1, 10)}
    finally:
        for event in release.values():
            event.set()
        await asyncio.gather(*tuple(plugin._reply_tasks), return_exceptions=True)
        if plugin._reply_drain_task is not None:
            await asyncio.gather(plugin._reply_drain_task, return_exceptions=True)


@pytest.mark.asyncio
async def test_restart_snapshots_qualified_jobs_and_holds_changed_pages():
    module = load_plugin_module()
    namespace = module.NamespaceId("bot", "persona")
    identity = SimpleNamespace(
        installation_policy=SimpleNamespace(namespace=namespace),
        installation_grant=SimpleNamespace(installation_id="install"))
    audience = json.dumps(["trusted-umo", "conversation"], separators=(",", ":"))
    first = module.ReplyModelQueuedPreparationV1(
        "c02-1", "source-1", "original-1",
        SimpleNamespace(job_id="job-1"), None, "digest-1", 1)
    second = module.ReplyModelQueuedPreparationV1(
        "c02-2", "source-2", "original-2",
        SimpleNamespace(job_id="job-3"), None, "digest-2", 1)
    pages = (
        module.ReplyModelRecoveryPageV1(
            namespace, "install", "incarnation", 5, 5,
            (module.ReplyModelRecoveryItemV1("job-1", first, audience, None),
             module.ReplyModelRecoveryItemV1("job-2", None, None, "revoked")),
            "job-2"),
        module.ReplyModelRecoveryPageV1(
            namespace, "install", "incarnation", 5, 5,
            (module.ReplyModelRecoveryItemV1("job-3", second, audience, None),),
            None),
    )
    events = []

    class Runtime:
        v2_ingress_qualified = True

        async def discover_pending_post_c02_reply_model_jobs_v1(
            self, *, cursor, limit,
        ):
            events.append(("scan", cursor, limit))
            return pages[0 if cursor is None else 1]

    plugin = module.Sylanne3Plugin(
        Context(asyncio.Queue(), {}, None, None, None, None,
                None, None, None, None, None), {"enabled": True})
    plugin._runtime = Runtime()
    plugin._v2_installation = identity

    async def continue_original(runtime, installation, queued, trusted_umo):
        events.append(("continue", queued.job.job_id, trusted_umo))

    plugin._continue_post_c02_reply_model_v1 = continue_original
    await plugin._restore_pending_post_c02_reply_models_v1()
    assert events == [
        ("scan", None, 8), ("scan", "job-2", 8),
        ("continue", "job-1", "trusted-umo"),
        ("continue", "job-3", "trusted-umo"),
    ]

    events.clear()
    pages = (pages[0], module.ReplyModelRecoveryPageV1(
        namespace, "install", "incarnation", 6, 6,
        pages[1].items, None))
    await plugin._restore_pending_post_c02_reply_models_v1()
    assert events == [("scan", None, 8), ("scan", "job-2", 8)]
