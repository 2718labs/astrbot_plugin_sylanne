"""A real ABI2 replay of a root original and one falsified inherited error."""

from dataclasses import replace

import pytest

from sylanne3.domains.d04.encoding_baseline import CommittedRef
from sylanne3.domains.d04.root import NumericCheckpoint
from sylanne3.graph_types import AtomKey, Owner
from sylanne3.native_runtime.authored_root_initial_box import run_authored_root_initial_box_math
from sylanne3.native_runtime.d04_root_numeric_replay import (
    D04RootNumericReplayHold, verify_d04_root_numeric_original,
)

from rewrite.tests.alpha1.numerics.test_authored_root_initial_box import (
    _candidate, handles, native_asset,
)


def _checkpoint(handle, original):
    source = original.checkpoints[0]
    box = run_authored_root_initial_box_math(handle, original).blocks[0]
    state = AtomKey(Owner("persona", *source.namespace),
                    "d04.feeling_state.v1", source.block_id)
    return NumericCheckpoint(
        source.block_id, source.namespace, source.block, source.assets,
        source.asset_digest, source.axes, source.latent_state,
        source.ordered_box, box.verified_initial_error,
        "trusted_initial_box", box.initial_box_sha256, source.cursor,
        CommittedRef(state.token, 1), "f" * 64, "root:operation", "none", None,
    )


def test_authored_original_replays_box_and_inherited_error(handles):
    handle, _ = handles
    original = _candidate()
    checkpoint = _checkpoint(handle, original)
    result = verify_d04_root_numeric_original(handle, original, checkpoint)
    assert result.verified_initial_error == checkpoint.numeric_error_bound
    assert result.initial_box_sha256 == checkpoint.certificate_digest
    assert result.status == "conditional_math_hold_for_w01_adoption"


def test_declared_error_cannot_understate_native_radius(handles):
    handle, _ = handles
    original = _candidate()
    checkpoint = _checkpoint(handle, original)
    with pytest.raises(D04RootNumericReplayHold, match="inherited error"):
        verify_d04_root_numeric_original(
            handle, original, replace(checkpoint, numeric_error_bound=0.15),
        )
