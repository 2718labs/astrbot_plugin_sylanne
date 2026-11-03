"""Shared C02 reply candidate type and durable operation identity."""

from __future__ import annotations

from dataclasses import dataclass

from ..domains.d07 import FocusState
from ..domains.d08 import ActionIntent
from ..runtime_contracts import CommandEnvelope,DomainProposal,canonical_digest


@dataclass(frozen=True)
class PostC02ReplyCandidate:
    """Same-operation domain writes, pending GraphCoordinator/D11 admission."""

    envelope: CommandEnvelope
    proposals: tuple[DomainProposal, ...]
    focus: FocusState
    action: ActionIntent
    batch_id: str


def post_c02_reply_operation_id(c02_operation_id: str, source_ref: str) -> str:
    """One durable reply operation per original C02/source pair."""
    return "post-c02-reply:" + canonical_digest({
        "version": 1, "c02_operation_id": c02_operation_id,
        "source_ref": source_ref,
    })


__all__ = (
    "PostC02ReplyCandidate", "post_c02_reply_operation_id",
)
