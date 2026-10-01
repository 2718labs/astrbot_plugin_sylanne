"""Two-member coupled ABI2 source-removal math remains conditional on W01."""

from dataclasses import replace
from pathlib import Path

import pytest

from sylanne3.native_runtime.d04_joint_counterfactual_math import (
    D04JointCounterfactualHold, D04JointSourceDrive,
    run_d04_joint_source_removal_math,
)
from sylanne3.native_runtime.fixed_block_transcript import FixedBlockCSR

from rewrite.tests.alpha1.numerics.test_fixed_block_transcript import _block


@pytest.fixture
def native_handle():
    # Reuse the existing built native target; this focused test does not build
    # the entire Rust project or alter any installed product package.
    native = Path(__file__).resolve().parents[4] / "rewrite/native/target/debug/sylanne3_kernel.dll"
    if not native.is_file():
        pytest.skip("local ABI2 debug library is unavailable")
    from rewrite.tests.alpha1.numerics.test_fixed_block_transcript import (
        FixedBlockTranscriptTests,
    )

    harness = FixedBlockTranscriptTests("runTest")
    harness.native_asset = native
    harness.setUp()
    try:
        yield harness.handle
    finally:
        harness.doCleanups()


def _case():
    joint = replace(_block(), drive=(0.1, 0.1), previous_error=0.0)
    sources = (D04JointSourceDrive("source:one", (0.1, 0.0)),
               D04JointSourceDrive("source:two", (0.0, 0.1)))
    return joint, sources


def test_two_member_coupling_has_conditional_source_removal_intervals(native_handle):
    joint, sources = _case()
    result = run_d04_joint_source_removal_math(
        native_handle, joint=joint, source_drives=sources,
        initial_lower=joint.previous, initial_upper=joint.previous,
        readout=(0.0, 1.0),
    )
    assert result.status == "unsigned_hold_for_w01_fenced_joint_scc_and_source_adoption"
    assert 0.0 <= result.initial_error < 1e-150
    assert tuple(row.source_ref for row in result.source_intervals) == (
        "source:one", "source:two",
    )
    assert all(row.lower <= row.upper and row.counterfactual_transcript_sha256
               for row in result.source_intervals)
    # The small off-diagonal effect is enclosed, but this certificate is too
    # wide to assign its sign. The helper must preserve that uncertainty.
    assert result.source_intervals[0].lower < 0 < result.source_intervals[0].upper


def test_omitted_joint_edge_can_still_get_conditional_math_certificate(native_handle):
    joint, sources = _case()
    coupled = run_d04_joint_source_removal_math(
        native_handle, joint=joint, source_drives=sources,
        initial_lower=joint.previous, initial_upper=joint.previous,
        readout=(0.0, 1.0),
    )
    no_edge = replace(joint, j=FixedBlockCSR(2, 2, (0, 0, 0), (), ()))
    omitted = run_d04_joint_source_removal_math(
        native_handle, joint=no_edge, source_drives=sources,
        initial_lower=joint.previous, initial_upper=joint.previous,
        readout=(0.0, 1.0),
    )
    assert coupled.full_transcript_sha256 != omitted.full_transcript_sha256
    assert (coupled.source_intervals[0].lower,
            coupled.source_intervals[0].upper) != (
                omitted.source_intervals[0].lower,
                omitted.source_intervals[0].upper,
            )
    assert coupled.status == omitted.status == (
        "unsigned_hold_for_w01_fenced_joint_scc_and_source_adoption"
    )


@pytest.mark.parametrize("forgery", ("one_row", "wrong_aggregate", "repeated_source"))
def test_single_source_or_forged_total_cannot_claim_causal_difference(
    native_handle, forgery,
):
    joint, sources = _case()
    if forgery == "one_row":
        sources = sources[:1]
    elif forgery == "wrong_aggregate":
        sources = (sources[0], replace(sources[1], drive=(0.0, 0.2)))
    else:
        sources = (sources[0], replace(sources[1], source_ref="source:one"))
    with pytest.raises(D04JointCounterfactualHold):
        run_d04_joint_source_removal_math(
            native_handle, joint=joint, source_drives=sources,
            initial_lower=joint.previous, initial_upper=joint.previous,
            readout=(0.0, 1.0),
        )
