"""Replay an authored root's numeric checkpoint without granting adoption.

W01 must obtain the authored candidate from its original, committed operation
and establish the matching graph receipt in the same fenced transaction. A
checkpoint's own certificate fields are claims, never the source of the box.
"""

from __future__ import annotations

from dataclasses import dataclass
import struct

from ..domains.d04.root import AuthoredRootCandidate, NumericCheckpoint
from ..runtime_contracts import canonical_digest
from .authored_root_initial_box import run_authored_root_initial_box_math
from .loader import ABI2NativeLibrary


class D04RootNumericReplayHold(ValueError):
    """The original authored box and current checkpoint do not replay."""


@dataclass(frozen=True, slots=True)
class D04RootNumericReplayV1:
    candidate_digest: str
    checkpoint_id: str
    initial_box_sha256: str
    verified_initial_error: float
    inherited_error: float
    native_transcript_sha256: str
    binding_digest: str
    status: str = "conditional_math_hold_for_w01_adoption"


def _same_numbers(left: tuple[float, ...], right: tuple[float, ...]) -> bool:
    return len(left) == len(right) and all(
        struct.pack("!d", a) == struct.pack("!d", b)
        for a, b in zip(left, right)
    )


def verify_d04_root_numeric_original(
    handle: ABI2NativeLibrary,
    original: AuthoredRootCandidate,
    checkpoint: NumericCheckpoint,
) -> D04RootNumericReplayV1:
    """Recompute ABI2 box math from an original supplied by W01.

    This verifies numeric consistency only. The caller must still authenticate
    the original, graph closure, receipt, Scheme and readout under its fence.
    """
    if (type(original) is not AuthoredRootCandidate
            or type(checkpoint) is not NumericCheckpoint):
        raise TypeError("root replay needs typed original and checkpoint")
    if checkpoint.predecessor_kind != "none" or checkpoint.certificate_source != "trusted_initial_box":
        raise D04RootNumericReplayHold("checkpoint is not an authored root")
    matches = tuple(item for item in original.checkpoints
                    if item.block_id == checkpoint.block.block_id)
    if len(matches) != 1:
        raise D04RootNumericReplayHold("original does not contain exactly one block")
    source = matches[0]
    if (checkpoint.namespace != original.namespace
            or checkpoint.namespace != source.namespace
            or checkpoint.block != source.block
            or checkpoint.assets != source.assets
            or checkpoint.asset_digest != source.asset_digest
            or checkpoint.axes != source.axes
            or checkpoint.cursor != source.cursor
            or checkpoint.certified_box != source.ordered_box
            or not _same_numbers(checkpoint.latent_state, source.latent_state)):
        raise D04RootNumericReplayHold("checkpoint differs from authored original")
    math = run_authored_root_initial_box_math(handle, original)
    index = original.checkpoints.index(source)
    box = math.blocks[index]
    if (checkpoint.certificate_digest != box.initial_box_sha256
            or checkpoint.numeric_error_bound < box.verified_initial_error):
        raise D04RootNumericReplayHold("checkpoint certificate or inherited error differs from ABI2 replay")
    return D04RootNumericReplayV1(
        original.digest, checkpoint.checkpoint_id, box.initial_box_sha256,
        box.verified_initial_error, checkpoint.numeric_error_bound,
        math.transcript_sha256, canonical_digest(math.production_binding),
    )


__all__ = ["D04RootNumericReplayHold", "D04RootNumericReplayV1",
           "verify_d04_root_numeric_original"]
