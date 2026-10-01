"""A real post-C02 reply result read qualifies against its pinned graph."""

import asyncio
from pathlib import Path

from sylanne3.authority_service.current_reply_worker_model_result_graph_verifier import (
    PinnedCurrentReplyWorkerModelResultGraphVerifier,
)
from sylanne3.graph_coordinator import GraphCoordinator


def test_real_reply_result_read_accepts_tuple_source_audience(tmp_path, monkeypatch):
    # The same-installation fixture imports its runtime siblings by module name.
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1] / "runtime"))
    from test_post_c02_reply_assembly_v2 import (
        test_paired_reply_assembly_uses_real_c02_and_reply_admission,
    )

    qualified = []
    original = PinnedCurrentReplyWorkerModelResultGraphVerifier.current

    def record_current(self, request, intent, permit):
        result = original(self, request, intent, permit)
        qualified.append(result)
        return result

    class ReachedAssembly(Exception):
        pass

    def stop_after_result_read(self, *args, **kwargs):
        raise ReachedAssembly

    monkeypatch.setattr(PinnedCurrentReplyWorkerModelResultGraphVerifier,
                        "current", record_current)
    monkeypatch.setattr(GraphCoordinator, "assemble_post_c02_reply_v2",
                        stop_after_result_read)
    try:
        asyncio.run(test_paired_reply_assembly_uses_real_c02_and_reply_admission(tmp_path))
    except ReachedAssembly:
        pass
    else:
        raise AssertionError("real reply result read did not reach assembly")
    assert qualified and all(qualified)
