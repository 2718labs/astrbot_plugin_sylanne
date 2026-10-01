"""Current W01 history for the actual V3 foreground model wire.

The stock installation has no authoritative full-wire tokenizer. Raw dialogue
is therefore legal unverified context, never a claim that the model window
fits. This module does not grant a budget, dispatch a call, or activate caches.
"""
from __future__ import annotations

from dataclasses import dataclass, replace

from ..graph_types import AtomKey, GraphVersion
from ..model_broker.natural_reply_history_v3 import (
    D13NaturalHistorySelectionV1, D13NaturalRawTurnV1,
    FrozenNaturalReplyRequestV3, NaturalReplyInputV3,
    freeze_natural_reply_request_v3,
)
from ..runtime_contracts import canonical_digest
from ..domains.d13.raw_slice import _merge_ranges
from .d13_current_window import read_current_d13_window_for_authority_v1

RAW_POLICY_REF = "d13.natural.raw_full_wire_unverified.v1"


@dataclass(frozen=True, slots=True)
class NaturalHistoryDecisionV1:
    selected: str
    token_evidence: str
    activation: str
    policy_digest: str
    wire_digest: str


def freeze_current_raw_natural_frame_v3(
    db, *, namespace, plan, question, installation, now_utc, expires_at_utc,
    activation_generation, max_slots=64, original=None,
):
    """Read the real bounded window in the caller's Owner-fenced transaction.

    Exact recovery revalidates the existing selection; it cannot pick a new
    history, change a call identity, or rewrite the previous frozen wire.
    """
    if not db.in_transaction:
        raise ValueError("D13 foreground history needs the current W01 transaction")
    if original is not None and type(original) is not FrozenNaturalReplyRequestV3:
        raise TypeError("D13 V3 recovery requires its exact frozen original")
    window = read_current_d13_window_for_authority_v1(
        db, namespace, plan.scene_id, plan.audience_id, max_slots, now_utc,
        expected_activation_generation=activation_generation,
    )
    if (window.scene_ref != plan.scene_ref or window.audience_ref != plan.audience_ref
            or question.audience_ref != plan.audience_ref):
        raise ValueError("D13 history and natural plan must share actual D03 originals")
    policy_digest = canonical_digest({
        "schema": RAW_POLICY_REF, "max_slots": max_slots,
        "max_age_seconds": 72 * 3600, "full_wire_counter": None,
        "token_evidence": "token_evidence_unverified",
        "activation": "activation_not_attempted",
        "installation": installation,
    })
    if original is not None:
        selected = original.input.history_selection
        if (selected.policy_ref != RAW_POLICY_REF or selected.policy_digest != policy_digest
                or selected.block_ref is not None or original.input.stable_history
                or original.installation != installation or original.input.plan != plan
                or original.input.question != question
                or now_utc >= original.input.expires_at_utc
                or canonical_digest(replace(window, trusted_utc=original.input.frozen_at_utc))
                   != selected.window_digest):
            raise ValueError("D13 original raw selection is no longer current")
        # Re-freezing is an integrity check only; its time and wire stay original.
        if freeze_natural_reply_request_v3(original.input, original.installation) != original:
            raise ValueError("D13 original foreground wire changed")
        frozen = original
    else:
        turns = tuple(turn for turn in window.turns
            if turn.source_ref != question.ref and 0 <= now_utc - turn.trusted_utc < 72 * 3600)
        raw = tuple(D13NaturalRawTurnV1(turn, turn.raw_ref) for turn in turns)
        coverage = _merge_ranges((turn.sequence, turn.sequence) for turn in turns)
        gaps = _merge_ranges((*window.missing_ranges,
            *((turn.sequence, turn.sequence) for turn in window.turns
              if turn.source_ref != question.ref and now_utc - turn.trusted_utc >= 72 * 3600)))
        expiry = min((expires_at_utc, *(turn.trusted_utc + 72 * 3600 for turn in turns)))
        dependencies = tuple(dict.fromkeys(ref for turn in turns
            for ref in (turn.raw_ref, turn.source_ref, turn.access_ref)))
        selection = D13NaturalHistorySelectionV1(
            window_digest=canonical_digest(window), order_watermark=window.order_watermark,
            coverage=coverage, gaps=gaps, source_dependencies=dependencies,
            read_set=window.read_set, scene_ref=window.scene_ref, audience_ref=window.audience_ref,
            conversation_ref=window.conversation_ref, expires_at_utc=expiry,
            access_epoch=window.access_epoch, deletion_epoch=window.delete_epoch,
            activation_generation=window.activation_epoch, block_ref=None,
            raw_turn_refs=tuple(turn.raw_ref for turn in turns),
            selected_slice_digest=canonical_digest({"stable_history": (),
                "recent_history": raw, "coverage": coverage, "gaps": gaps}),
            policy_ref=RAW_POLICY_REF, policy_digest=policy_digest,
        )
        frozen = freeze_natural_reply_request_v3(NaturalReplyInputV3(
            question, plan, (), raw, selection, now_utc, expiry), installation)
    reads = tuple(GraphVersion(AtomKey.from_token(ref.ref), ref.version)
                  for ref in frozen.input.history_selection.read_set)
    decision = NaturalHistoryDecisionV1("raw", "token_evidence_unverified",
        "activation_not_attempted", policy_digest, frozen.model_request_digest)
    return frozen, reads, decision
