"""Restarted Host resumes a real accepted D07 release by its original C02.

The donor supplies same-DB Owner/mTLS, two C02 originals, paid first reply and
an observed accepted P2 effect. This test controls product readiness because a
formal installed package is not part of the donor; it proves the Host routing
seam, not a production startup claim.
"""

import asyncio
from pathlib import Path
import sys

import pytest

from rewrite.host_tests.alpha1.test_runtime_bootstrap import load_plugin_module
from sylanne3.graph_store import ProductionGraphStore
from sylanne3.runtime.natural_reply_job_v2 import SavedNaturalPreparationV2
from sylanne3.runtime_contracts import AuthorityContext


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "runtime"))
import test_post_c02_attention_two_ticket_v2 as donor  # noqa: E402
from test_natural_p2_true_owner_handoff import _pay_generation  # noqa: E402


@pytest.mark.asyncio
async def test_restarted_host_reads_released_c02_and_starts_its_original_paid_job(
        tmp_path, monkeypatch):
    original_host = donor._host_one_shot

    async def host_with_separate_worker_store(case, *args, **kwargs):
        # The donor's GraphWorker owns and closes its store. Give it a second
        # connection so the original installed coordinator survives this call.
        original_store = case["store"]
        db_path = original_store._db.execute("PRAGMA database_list").fetchone()[2]
        worker_store = ProductionGraphStore(db_path, original_store._registry)
        case["store"] = worker_store
        try:
            return await original_host(case, *args, **kwargs)
        finally:
            case["store"] = original_store
            if not worker_store._closed:
                worker_store.close()

    monkeypatch.setattr(donor, "_host_one_shot", host_with_separate_worker_store)

    async def after_release(case, second_c02, decision, outcome):
        assert outcome == "accepted"
        graph, bootstrap, namespace = (
            case["graph"], case["bootstrap"], case["namespace"])
        bundle, port = case["installed_bundle"], case["port"]
        page = await asyncio.to_thread(
            graph.discover_released_post_c02_attention_v2,
            bootstrap, namespace, bundle, after=None, limit=32)
        assert len(page.items) == 1
        assert page.items[0].c02_operation_id == second_c02.operation_id
        assert page.items[0].attention_operation_id == decision.attention_operation_id

        class InstalledGraphReads:
            def natural_reply_product_ready_v2(self, *_args, **_kwargs):
                # Controlled donor precondition; no formal package is installed.
                return True

            async def discover_released_attention_v2(self, *_args, **kwargs):
                return await asyncio.to_thread(
                    graph.discover_released_post_c02_attention_v2,
                    bootstrap, namespace, bundle,
                    after=kwargs["after"], limit=kwargs["limit"])

            async def read_installed_natural_original_progress_v2(self, parent):
                return await asyncio.to_thread(self._read_progress, parent)

            @staticmethod
            def _read_progress(parent):
                anchor = port.current_anchor(
                    namespace=namespace,
                    authority_namespace=case["authority_namespace"])
                lease, capability = graph.grant(
                    bootstrap, actor=case["client_grant"].subject,
                    issuer_domain="d11", namespace=namespace, domains=("d11",),
                    activation_generation=anchor.activation_generation,
                    operation_id="released-progress-" + parent)
                try:
                    authority = AuthorityContext(
                        case["client_grant"].subject, "d11", capability,
                        namespace, ("activity",), "proposal", ("internal",),
                        case["policy"].root_grant.policy_ref,
                        anchor.activation_generation)
                    return graph.read_natural_original_progress_v2(
                        authority, lease, parent, bundle)
                finally:
                    graph.release_authority_lease(bootstrap, lease)

            async def read_original_c02_source_ref_v2(self, parent):
                values = await asyncio.to_thread(
                    graph.read_post_c02_attention_inputs_v1,
                    bootstrap, namespace, parent, None, bundle)
                assert len(values[2].source_refs) == 1
                return values[2].source_refs[0]

            async def prepare_post_c02_natural_generation_v2(self, **kwargs):
                return await asyncio.to_thread(
                    graph.prepare_post_c02_natural_generation_v2,
                    bootstrap, namespace, kwargs["c02_operation_id"],
                    kwargs["source_ref"], bundle)

        module = load_plugin_module()
        # The donor imports `sylanne3`, while the plugin loader imports the
        # same source as `rewrite.sylanne3`; align only this Python class alias.
        monkeypatch.setattr(module, "SavedNaturalPreparationV2",
                            SavedNaturalPreparationV2)
        restarted = module.Sylanne3Plugin.__new__(module.Sylanne3Plugin)
        runtime = InstalledGraphReads()
        installation = object()
        restarted.context = object()
        restarted._runtime = runtime
        restarted._v2_installation = installation
        restarted._final_handoff_server = object()
        restarted._final_handoff_listener = object()
        restarted._scene_candidates = object()
        restarted._encoding_stopping = False
        restarted._reply_tasks = {}
        restarted._natural_backlog = {}
        restarted._released_attention_scan_after = None
        restarted._released_attention_scan_pending = True
        restarted._released_attention_scan_running = False
        prepared = []
        restarted._schedule_post_c02_natural_v2 = (
            lambda _runtime, _installation, saved, _umo: prepared.append(saved))

        assert (await runtime.read_installed_natural_original_progress_v2(
            second_c02.operation_id)).generation is None
        await restarted._restore_released_attention_v2()
        assert len(prepared) == 1
        saved = prepared[0]
        assert saved.seal.c02_operation_id == second_c02.operation_id
        assert (await runtime.read_installed_natural_original_progress_v2(
            second_c02.operation_id)).generation.original_operation_id == (
                saved.seal.original_operation_id)
        second_case = {**case, "c02": second_c02, "source_ref": saved.seal.source_ref}
        paid = await asyncio.to_thread(_pay_generation, second_case, saved)
        try:
            assert paid[2].phase == "running"
            assert paid[5].finish_digest.startswith("sha256:")
            assert paid[4].call_id == saved.seal.call_id
        finally:
            await asyncio.to_thread(
                graph.release_authority_lease, bootstrap, paid[1])

    await donor._real_two_ticket_case(
        tmp_path, monkeypatch, "accepted", after_release=after_release)
