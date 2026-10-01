"""Deterministic, model-free selection of recent committed raw turns."""

from __future__ import annotations

from typing import Iterable

from ...runtime_contracts import (
    ConversationWindowProjectionV1,
    ShortContextRequestV1,
    ShortContextSliceV1,
)
from .prefix import stable_segment_digest

_MAX_AGE_SECONDS = 72 * 60 * 60


def _merge_ranges(ranges: Iterable[tuple[int, int]]) -> tuple[tuple[int, int], ...]:
    ordered = sorted(ranges)
    if not ordered:
        return ()
    merged: list[tuple[int, int]] = []
    start, end = ordered[0]
    for next_start, next_end in ordered[1:]:
        if next_start <= end + 1:
            end = max(end, next_end)
        else:
            merged.append((start, end))
            start, end = next_start, next_end
    merged.append((start, end))
    return tuple(merged)


def _implicit_missing_ranges(window: ConversationWindowProjectionV1) -> tuple[tuple[int, int], ...]:
    """Expose absent committed sequence positions rather than imply continuity."""
    gaps = [(left.sequence + 1, right.sequence - 1)
            for left, right in zip(window.turns, window.turns[1:])
            if right.sequence > left.sequence + 1]
    return tuple(gaps)


def assemble_raw_slice(
    window: ConversationWindowProjectionV1,
    request: ShortContextRequestV1,
) -> ShortContextSliceV1:
    """Select a fitting suffix of recent, same-audience completed turns.

    The local estimate is UTF-8 bytes of the rendered text. D11 performs
    actual provider token counting before dispatch.
    """
    if not request.opt_in:
        raise ValueError("short context requires explicit opt-in")
    if (request.conversation_ref != window.conversation_ref
            or request.scene_ref != window.scene_ref
            or request.audience_ref != window.audience_ref):
        raise ValueError("request and window identity must match")
    recent = [t for t in window.turns if window.trusted_utc - t.trusted_utc < _MAX_AGE_SECONDS]
    missing = [*window.missing_ranges, *_implicit_missing_ranges(window)]
    missing.extend((t.sequence, t.sequence) for t in window.turns
                   if window.trusted_utc - t.trusted_utc >= _MAX_AGE_SECONDS)
    chosen = []
    used = 0
    for turn in reversed(recent):
        if chosen and chosen[-1].sequence != turn.sequence + 1:
            break
        size = used + len(f"{turn.speaker_ref}: {turn.text}".encode("utf-8")) + (1 if chosen else 0)
        if size > request.history_token_budget:
            break
        chosen.append(turn)
        used = size
    chosen.reverse()
    earliest_kept = chosen[0].sequence if chosen else None
    missing.extend((t.sequence, t.sequence) for t in recent
                   if earliest_kept is None or t.sequence < earliest_kept)

    dependencies = tuple(dict.fromkeys(
        ref for turn in chosen for ref in (turn.raw_ref, turn.source_ref, turn.access_ref)
    ))
    expires = min((t.trusted_utc + _MAX_AGE_SECONDS for t in chosen), default=window.trusted_utc)
    return ShortContextSliceV1(
        conversation_ref=window.conversation_ref,
        audience_ref=window.audience_ref,
        blocks=(),
        raw_tail=tuple(chosen),
        selected_detail_slots=(),
        source_dependencies=dependencies,
        missing_ranges=_merge_ranges(missing),
        expires_at_utc=expires,
        stable_prefix_digest=stable_segment_digest(window, request, ""),
        estimated_tokens=used,
    )


def render_raw_slice(context_slice: ShortContextSliceV1) -> str:
    """Render selected source text for D11's later actual-counting stage."""
    if context_slice.blocks:
        raise ValueError("raw renderer cannot silently omit compressed blocks")
    return "\n".join(f"{turn.speaker_ref}: {turn.text}" for turn in context_slice.raw_tail)
