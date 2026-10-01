"""The host reads natural text only from a committed paid V2 graph original."""

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "runtime"))
from test_natural_final_graph_stage_v2 import (  # noqa: E402
    _real_natural_final_commit_case, context_reply_c02_case, c02_case,
)

from sylanne3.host.natural_reply_dispatch_driver import _read_original
from sylanne3.host.installed_natural_reply_driver import (
    InstalledNaturalGenerationProgressV2,
)
from sylanne3.host.installed_natural_review_driver import (
    InstalledNaturalReviewProgressV2,
)
from sylanne3.runtime.natural_reply_job_v2 import SavedNaturalPreparationV2


def test_real_paid_natural_commit_releases_exact_host_text(
        request, tmp_path, monkeypatch):
    def after_commit(graph, authority, lease, receipt, committed, value):
        original = _read_original(
            graph, authority, lease, receipt.operation_id)
        assert original.operation_id == receipt.operation_id
        assert original.effect_id == committed[2].effect_id
        assert original.admission == committed[0]
        assert original.request == committed[1]
        assert original.evidence == committed[2]
        assert original.payload.payload.decode("utf-8") == (
            value["paid_current"].generation_output["body"])

    _real_natural_final_commit_case(
        request, tmp_path, monkeypatch, after_commit=after_commit)


def test_real_paid_stage_terminals_support_content_free_host_recovery(
        request, tmp_path, monkeypatch):
    def after_commit(graph, authority, lease, receipt, committed, value):
        parent = value["parent_original_id"]
        installed = value["installed"]
        generation = graph.read_natural_original_stage_preparation_v2(
            authority, lease, parent, "generation", installed)
        review = graph.read_natural_original_stage_preparation_v2(
            authority, lease, parent, "review", installed)
        assert type(generation) is SavedNaturalPreparationV2
        assert type(review) is SavedNaturalPreparationV2
        assert generation.state == review.state == "terminal"
        generation_output = graph.read_natural_generation_terminal_receipt_v2(
            authority, lease, parent, installed)
        review_output = graph.read_natural_review_terminal_receipt_v2(
            authority, lease, parent, installed)
        recovered_generation = InstalledNaturalGenerationProgressV2(
            None, None, None, None, None, generation_output, None,
            "review_content_hold")
        recovered_review = InstalledNaturalReviewProgressV2(
            None, None, None, None, None, review_output, None,
            "paid_review_current_hold")
        assert recovered_generation.output.output_digest == (
            generation.terminal_output_digest)
        assert recovered_review.output.output_digest == (
            review.terminal_output_digest)
        assert recovered_review.output.verdict == "pass"

    _real_natural_final_commit_case(
        request, tmp_path, monkeypatch, after_commit=after_commit)
