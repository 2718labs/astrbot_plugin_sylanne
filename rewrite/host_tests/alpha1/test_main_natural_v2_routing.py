"""New C02 identities enter only the installed natural path."""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace

from rewrite.host_tests.alpha1.test_runtime_bootstrap import load_plugin_module


def _plugin(module):
    plugin = module.Sylanne3Plugin.__new__(module.Sylanne3Plugin)
    plugin.context = object()
    plugin._final_handoff_server = object()
    plugin._final_handoff_listener = object()
    plugin._scene_candidates = object()
    return plugin


def test_new_c02_holds_without_complete_natural_path():
    module = load_plugin_module()
    plugin = _plugin(module)
    installation = object()
    calls = []

    class Runtime:
        def natural_reply_product_ready_v2(self, *_args, **_kwargs):
            return False

        async def read_original_c02_source_ref_v2(self, *_args):
            calls.append("source")
            return "source-ref"

        async def prepare_post_c02_natural_generation_v2(self, **_kwargs):
            calls.append("natural")

        async def prepare_post_c02_reply_model_job_v1(self, **_kwargs):
            calls.append("legacy")

    asyncio.run(plugin._prepare_new_post_c02_natural_v2(
        Runtime(), installation, "c02:one"))
    assert calls == []


def test_new_c02_uses_original_source_and_schedules_natural_only(monkeypatch):
    module = load_plugin_module()
    plugin = _plugin(module)
    installation = object()
    calls = []

    class Saved:
        stage = "generation"
        seal = SimpleNamespace(c02_operation_id="c02:one", source_ref="source-ref")
        frozen = SimpleNamespace(input=SimpleNamespace(plan=SimpleNamespace(
            audience_id=json.dumps(["trusted-umo", "conversation"]))))

    monkeypatch.setattr(module, "SavedNaturalPreparationV2", Saved)

    class Runtime:
        def natural_reply_product_ready_v2(self, *_args, **kwargs):
            calls.append(("ready", kwargs))
            return True

        async def read_original_c02_source_ref_v2(self, operation_id):
            calls.append(("source", operation_id))
            return "source-ref"

        async def prepare_post_c02_natural_generation_v2(self, **kwargs):
            calls.append(("natural", kwargs))
            return Saved()

        async def prepare_post_c02_reply_model_job_v1(self, **_kwargs):
            raise AssertionError("new C02 must not create legacy paid call")

    plugin._schedule_post_c02_natural_v2 = lambda *args: calls.append(
        ("schedule", args[2], args[3]))
    runtime = Runtime()
    asyncio.run(plugin._prepare_new_post_c02_natural_v2(
        runtime, installation, "c02:one"))
    assert [entry[0] for entry in calls] == [
        "ready", "source", "natural", "schedule"]
    assert calls[2][1]["source_ref"] == "source-ref"
    assert type(calls[3][1]) is Saved
    assert calls[3][2] == "trusted-umo"


def test_restart_recovers_only_discovered_committed_natural_effect():
    module = load_plugin_module()
    plugin = _plugin(module)
    installation = object()
    seen = []

    class Runtime:
        def natural_reply_product_ready_v2(self, *_args, **_kwargs):
            return True

        async def discover_pending_natural_dispatch_v2(self, *_args, **kwargs):
            seen.append(("discover", kwargs["after"]))
            return SimpleNamespace(
                items=(SimpleNamespace(operation_id="natural:original"),),
                next_after=None)

        async def dispatch_committed_natural_reply_v2(self, *_args, **kwargs):
            seen.append(("dispatch", kwargs["operation_id"]))
            return SimpleNamespace(status="unknown")

        async def complete_observed_natural_attention_v2(self, *_args, **_kwargs):
            return None

    plugin._runtime = Runtime()
    plugin._v2_installation = installation
    plugin._encoding_stopping = False
    plugin._reply_tasks = {}
    plugin._natural_backlog = {}
    asyncio.run(plugin._restore_pending_natural_dispatch_v2())
    assert seen == [
        ("discover", None), ("dispatch", "natural:original")]


def test_restart_recovers_terminal_natural_original_without_new_paid_call(
        monkeypatch):
    module = load_plugin_module()
    plugin = _plugin(module)
    installation = object()
    seen = []

    class Saved:
        stage = "generation"
        state = "terminal"
        seal = SimpleNamespace(
            c02_operation_id="c02:one", source_ref="source-ref",
            original_operation_id="generation:original")
        frozen = SimpleNamespace(input=SimpleNamespace(plan=SimpleNamespace(
            audience_id=json.dumps(["trusted-umo", "conversation"]))))

    monkeypatch.setattr(module, "SavedNaturalPreparationV2", Saved)

    class Runtime:
        def natural_reply_product_ready_v2(self, *_args, **_kwargs):
            return True

        async def discover_pending_natural_stages_v2(self, *_args, **kwargs):
            seen.append(("discover", kwargs["after"]))
            return SimpleNamespace(items=(SimpleNamespace(
                parent_original_id="c02:one", source_ref="source-ref"),),
                next_after=None)

        async def read_installed_natural_original_progress_v2(self, parent):
            seen.append(("progress", parent))
            return SimpleNamespace(generation=SimpleNamespace(
                original_operation_id="generation:original"))

        async def read_installed_natural_stage_preparation_v2(self, parent, stage):
            seen.append(("stage", parent, stage))
            return Saved()

        async def prepare_post_c02_reply_model_job_v1(self, **_kwargs):
            raise AssertionError("sealed natural original must not create V1 paid call")

    plugin._runtime = Runtime()
    plugin._v2_installation = installation
    plugin._encoding_stopping = False
    plugin._reply_tasks = {}
    plugin._natural_backlog = {}
    plugin._schedule_post_c02_natural_v2 = lambda *args: seen.append(
        ("schedule", args[2].seal.original_operation_id, args[3]))
    asyncio.run(plugin._restore_pending_natural_stages_v2())
    assert seen == [
        ("discover", None), ("progress", "c02:one"),
        ("stage", "c02:one", "generation"),
        ("schedule", "generation:original", "trusted-umo")]


def test_released_attention_scans_next_page_with_original_c02_identity():
    module = load_plugin_module()
    plugin = _plugin(module)
    installation = object()
    seen = []
    prepared = set()

    class Runtime:
        def natural_reply_product_ready_v2(self, *_args, **_kwargs):
            return True

        async def discover_released_attention_v2(self, *_args, **kwargs):
            after = kwargs["after"]
            seen.append(("page", after))
            c02 = "c02:one" if after is None else "c02:two"
            return SimpleNamespace(items=(SimpleNamespace(c02_operation_id=c02),),
                                   next_after=c02 if after is None else None)

        async def read_installed_natural_original_progress_v2(self, c02):
            return SimpleNamespace(generation=object() if c02 in prepared else None)

        async def read_original_c02_source_ref_v2(self, c02):
            seen.append(("source", c02))
            return "source:" + c02

    async def prepare(_runtime, _installation, c02, *, source_ref):
        seen.append(("prepare", c02, source_ref))
        prepared.add(c02)

    plugin._runtime = Runtime()
    plugin._v2_installation = installation
    plugin._encoding_stopping = False
    plugin._reply_tasks = {}
    plugin._natural_backlog = {}
    plugin._released_attention_scan_after = None
    plugin._released_attention_scan_pending = True
    plugin._released_attention_scan_running = False
    plugin._prepare_new_post_c02_natural_v2 = prepare
    asyncio.run(plugin._restore_released_attention_v2())
    assert seen == [
        ("page", None), ("source", "c02:one"),
        ("prepare", "c02:one", "source:c02:one"),
        ("page", "c02:one"), ("source", "c02:two"),
        ("prepare", "c02:two", "source:c02:two")]
    assert plugin._released_attention_scan_pending is False


def test_accepted_natural_effect_requires_graph_focus_completion_before_release():
    module = load_plugin_module()
    plugin = _plugin(module)
    installation = object()
    seen = []

    class Runtime:
        async def complete_observed_natural_attention_v2(self, *_args, **kwargs):
            seen.append(("complete", kwargs["final_operation_id"]))
            return SimpleNamespace(status="committed")

    plugin._released_attention_scan_pending = False
    plugin._resume_released_attention_scan_v2 = lambda: seen.append(("scan",))
    asyncio.run(plugin._complete_accepted_natural_attention_v2(
        Runtime(), installation, "natural:final"))
    assert seen == [("complete", "natural:final"), ("scan",)]
    assert plugin._released_attention_scan_pending is True


def test_ninth_natural_original_runs_when_a_slot_opens(monkeypatch):
    module = load_plugin_module()
    plugin = _plugin(module)
    installation = object()
    plugin._encoding_stopping = False
    plugin._reply_tasks = {}
    plugin._reply_attempted_jobs = set()
    plugin._natural_backlog = {}
    started = []

    class Saved:
        stage = "generation"
        state = "queued"

        def __init__(self, job_id):
            self.seal = SimpleNamespace(job_id=job_id)

    monkeypatch.setattr(module, "SavedNaturalPreparationV2", Saved)

    async def case():
        release = asyncio.Event()

        class Runtime:
            def natural_reply_product_ready_v2(self, *_args, **_kwargs):
                return True

            async def run_installed_natural_reply_v2(self, *_args, **kwargs):
                started.append(kwargs["saved"].seal.job_id)
                await release.wait()
                return None

        runtime = Runtime()
        plugin._runtime = runtime
        plugin._v2_installation = installation
        for index in range(9):
            plugin._schedule_post_c02_natural_v2(
                runtime, installation, Saved(f"job-{index}"), "trusted-umo")
        await asyncio.sleep(0)
        assert len(started) == 8
        assert list(plugin._natural_backlog) == ["job-8"]
        release.set()
        for _ in range(10):
            await asyncio.sleep(0)
            if "job-8" in started:
                break
        assert started == [*(f"job-{index}" for index in range(8)), "job-8"]
        assert plugin._natural_backlog == {}
        plugin._schedule_post_c02_natural_v2(
            runtime, installation, Saved("job-8"), "trusted-umo")
        await asyncio.sleep(0)
        assert started.count("job-8") == 1

    asyncio.run(case())


def test_natural_backlog_runs_after_legacy_original_releases_shared_slot(
        monkeypatch):
    module = load_plugin_module()
    plugin = _plugin(module)
    installation = object()
    plugin._encoding_stopping = False
    plugin._reply_tasks = {}
    plugin._reply_attempted_jobs = set()
    plugin._natural_backlog = {}
    plugin._reply_backlog_waiting = False
    plugin._continue_post_c02_reply_model_v1 = None
    started = []

    class Queued:
        def __init__(self, index):
            self.job = SimpleNamespace(operation_id=f"legacy-{index}",
                                       job_id=f"legacy-{index}")
            self.original_operation_id = self.job.operation_id

    class Saved:
        stage = "generation"
        state = "queued"
        seal = SimpleNamespace(job_id="natural-original")

    monkeypatch.setattr(module, "ReplyModelQueuedPreparationV1", Queued)
    monkeypatch.setattr(module, "SavedNaturalPreparationV2", Saved)

    async def case():
        release = asyncio.Event()

        class Runtime:
            def natural_reply_product_ready_v2(self, *_args, **_kwargs):
                return True

            async def run_installed_natural_reply_v2(self, *_args, **_kwargs):
                started.append("natural-original")
                return None

        async def run_legacy(*_args, **_kwargs):
            await release.wait()

        runtime = Runtime()
        plugin._runtime = runtime
        plugin._v2_installation = installation
        plugin._continue_post_c02_reply_model_v1 = run_legacy
        for index in range(8):
            plugin._schedule_post_c02_reply_model_v1(
                runtime, installation, Queued(index), "trusted-umo")
        plugin._schedule_post_c02_natural_v2(
            runtime, installation, Saved(), "trusted-umo")
        assert list(plugin._natural_backlog) == ["natural-original"]
        release.set()
        for _ in range(10):
            await asyncio.sleep(0)
            if started:
                break
        assert started == ["natural-original"]
        assert plugin._natural_backlog == {}

    asyncio.run(case())


def test_natural_recovery_resumes_after_bounded_queue_across_pages(monkeypatch):
    module = load_plugin_module()
    plugin = _plugin(module)
    installation = object()
    plugin._encoding_stopping = False
    plugin._reply_tasks = {}
    plugin._reply_attempted_jobs = set()
    plugin._natural_backlog = {}
    plugin._natural_stage_scan_after = None
    plugin._natural_stage_scan_pending = False
    plugin._natural_stage_scan_running = False
    plugin._natural_stage_scan_task = None
    parents = tuple(f"c02-{index:04d}" for index in range(1030))
    started = []

    class Saved:
        stage = "generation"
        state = "queued"

        def __init__(self, parent):
            self.seal = SimpleNamespace(
                job_id=parent, c02_operation_id=parent,
                source_ref="source-ref", original_operation_id=parent)
            self.frozen = SimpleNamespace(input=SimpleNamespace(
                plan=SimpleNamespace(audience_id=json.dumps(
                    ["trusted-umo", "conversation"]))))

    monkeypatch.setattr(module, "SavedNaturalPreparationV2", Saved)

    async def case():
        release = asyncio.Event()

        class Runtime:
            def natural_reply_product_ready_v2(self, *_args, **_kwargs):
                return True

            async def discover_pending_natural_stages_v2(
                    self, *_args, **kwargs):
                after = kwargs["after"]
                remainder = [parent for parent in parents
                             if after is None or parent > after]
                page = remainder[:kwargs["limit"]]
                return SimpleNamespace(
                    items=tuple(SimpleNamespace(
                        parent_original_id=parent, source_ref="source-ref")
                        for parent in page),
                    next_after=page[-1] if len(remainder) > len(page) else None)

            async def read_installed_natural_original_progress_v2(self, parent):
                return SimpleNamespace(generation=SimpleNamespace(
                    original_operation_id=parent))

            async def read_installed_natural_stage_preparation_v2(
                    self, parent, stage):
                assert stage == "generation"
                return Saved(parent)

            async def run_installed_natural_reply_v2(self, *_args, **kwargs):
                started.append(kwargs["saved"].seal.job_id)
                await release.wait()
                return None

        plugin._runtime = Runtime()
        plugin._v2_installation = installation
        await plugin._restore_pending_natural_stages_v2()
        assert len(plugin._natural_backlog) == 256
        assert plugin._natural_stage_scan_pending is True
        release.set()
        for _ in range(500):
            await asyncio.sleep(0)
            if len(started) == len(parents):
                break
        assert started == list(parents)
        assert plugin._natural_backlog == {}
        assert plugin._natural_stage_scan_pending is False

    asyncio.run(case())


def test_new_durable_natural_original_requests_scan_when_queue_is_full(
        monkeypatch):
    module = load_plugin_module()
    plugin = _plugin(module)
    installation = object()
    plugin._encoding_stopping = False
    plugin._reply_tasks = {object(): "busy" for _ in range(8)}
    plugin._reply_attempted_jobs = set()
    plugin._natural_backlog = {f"old-{index}": () for index in range(256)}
    plugin._natural_stage_scan_after = "older-cursor"
    plugin._natural_stage_scan_pending = False

    class Saved:
        stage = "generation"
        state = "queued"
        seal = SimpleNamespace(job_id="new-original")

    monkeypatch.setattr(module, "SavedNaturalPreparationV2", Saved)

    class Runtime:
        def natural_reply_product_ready_v2(self, *_args, **_kwargs):
            return True

    runtime = Runtime()
    plugin._runtime = runtime
    plugin._v2_installation = installation
    plugin._schedule_post_c02_natural_v2(
        runtime, installation, Saved(), "trusted-umo")
    assert plugin._natural_stage_scan_pending is True
    assert plugin._natural_stage_scan_after is None
    assert "new-original" not in plugin._reply_attempted_jobs
