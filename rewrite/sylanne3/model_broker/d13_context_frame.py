"""Read-only D13 history frame for the installed conversation model.

The frame is low-trust context, never factual evidence or a paid-call grant.
Its byte estimate is not the exact provider token count required at egress.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..domains.d13.provider import (
    D13ShortContextProvider, ShortContextProjectionQueryV1,
    validate_slice_for_consumption,
)
from ..domains.d13.precompression import render_detail_slot
from ..graph_types import AtomKey
from ..runtime_contracts import (
    ConversationWindowProjectionV1, ShortContextSliceV1,
    VersionedRef, canonical_digest,
)
from .context_reply import ContextReplyPartV1
from .d13_precompression import D13PrecompressionInstallationV1


_TTL_SECONDS = 72 * 3600


@dataclass(frozen=True, slots=True)
class D13ContextInputFrameV1:
    installation_id: str
    provider_id: str
    model_id: str
    provider_config_digest: str
    conversation_ref: str
    scene_ref: VersionedRef
    audience_ref: VersionedRef
    stable_history: tuple[ContextReplyPartV1, ...]
    history: tuple[ContextReplyPartV1, ...]
    source_dependencies: tuple[VersionedRef, ...]
    missing_ranges: tuple[tuple[int, int], ...]
    expires_at_utc: float
    estimated_bytes: int
    stable_prefix_digest: str
    frame_digest: str
    status: str = "candidate_requires_exact_token_count"


def build_d13_context_input_frame_v1(
    query: ShortContextProjectionQueryV1, *,
    current_window: ConversationWindowProjectionV1,
    selected_main_model: D13PrecompressionInstallationV1,
    active_block_graph_ref: VersionedRef | None = None,
) -> tuple[D13ContextInputFrameV1, ShortContextSliceV1]:
    """Project current D11 history into bounded, source-linked model parts.

    The host gets ``selected_main_model`` from the current UMO selection.
    D11 must supply ``current_window`` from its held authorized read, and
    recheck it plus actual token count before any model egress.
    """
    if (type(query) is not ShortContextProjectionQueryV1
            or type(current_window) is not ConversationWindowProjectionV1
            or type(selected_main_model) is not D13PrecompressionInstallationV1):
        raise TypeError("typed current D13 window and main model required")
    request = query.request
    if (not request.opt_in
            or request.provider_id != selected_main_model.provider_id
            or request.model_id != selected_main_model.model_id
            or query.window != current_window):
        raise ValueError("D13 request differs from current installed conversation model")
    selected = D13ShortContextProvider().project(query)
    validate_slice_for_consumption(query, selected, current_window)
    if current_window.trusted_utc >= selected.expires_at_utc and (
            selected.blocks or selected.raw_tail):
        raise ValueError("D13 history crossed its 72-hour expiry")
    stable: list[ContextReplyPartV1] = []
    if selected.blocks:
        if (len(selected.blocks) != 1
                or type(active_block_graph_ref) is not VersionedRef
                or active_block_graph_ref.version < 1
                or AtomKey.from_token(active_block_graph_ref.ref).type_name
                   != "d13.compressed_turn_block.v2"):
            raise ValueError("active D13 block needs a current graph cache head")
        block = selected.blocks[0]
        text = "\n".join(f"[{item.sequence} {item.speaker_ref}] {item.text}"
                         for item in block.timeline)
        stable.append(ContextReplyPartV1(
            "d13_history", active_block_graph_ref, current_window.audience_ref,
            block.expires_at_utc, text, block.source_dependencies,
        ))
    elif active_block_graph_ref is not None:
        raise ValueError("D13 raw frame cannot claim an active cache head")
    dynamic: list[ContextReplyPartV1] = []
    for turn in selected.raw_tail:
        dynamic.append(ContextReplyPartV1(
            "d13_history", turn.raw_ref, current_window.audience_ref,
            turn.trusted_utc + _TTL_SECONDS,
            f"{turn.speaker_ref}: {turn.text}",
            (turn.raw_ref, turn.source_ref, turn.access_ref),
        ))
    for key in selected.selected_detail_slots:
        block = selected.blocks[0]
        slot = next(item for item in block.detail_slots if item.key == key)
        dynamic.append(ContextReplyPartV1(
            "d13_history", slot.source_ref, current_window.audience_ref,
            block.expires_at_utc, render_detail_slot(block, slot),
            block.source_dependencies,
        ))
    if len({part.ref for part in (*stable, *dynamic)}) != len(stable) + len(dynamic):
        raise ValueError("D13 history repeats a versioned part reference")
    frame_identity = {
        "schema": "d13.context_input_frame.v1",
        "installation_id": selected_main_model.installation_id,
        "provider_id": selected_main_model.provider_id,
        "model_id": selected_main_model.model_id,
        "provider_config_digest": selected_main_model.provider_config_digest,
        "window": current_window,
        "slice": selected,
        "stable": tuple(stable), "history": tuple(dynamic),
    }
    frame = D13ContextInputFrameV1(
        selected_main_model.installation_id,
        selected_main_model.provider_id, selected_main_model.model_id,
        selected_main_model.provider_config_digest,
        current_window.conversation_ref, current_window.scene_ref,
        current_window.audience_ref, tuple(stable), tuple(dynamic),
        selected.source_dependencies, selected.missing_ranges,
        selected.expires_at_utc, selected.estimated_tokens,
        selected.stable_prefix_digest, canonical_digest(frame_identity),
    )
    return frame, selected


__all__ = ["D13ContextInputFrameV1", "build_d13_context_input_frame_v1"]
