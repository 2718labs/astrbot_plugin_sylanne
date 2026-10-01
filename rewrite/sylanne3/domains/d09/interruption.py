"""D09 interruption candidate for a finite batch after a real first handoff."""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Callable

from ...graph_types import GraphVersion
from ...runtime_contracts import VersionedRef
from ..d08.execution import CommunicationIntentGrant
from . import (
    ConversationTrack, D09ExpressionProvider, DeliveryObservation, StagingResult,
)


_REASONS = frozenset({
    "explicit_stop", "source_revoked", "consent_revoked",
    "audience_changed", "quiet_hours", "relevant_new_turn",
})


@dataclass(frozen=True, slots=True)
class SegmentInterruptionReadV1:
    """W01 must verify the original batch, D11 observations and current fence."""

    grant: CommunicationIntentGrant
    staged: StagingResult
    track: ConversationTrack
    track_head: GraphVersion
    observations: tuple[DeliveryObservation, ...]
    current_cancellation_epoch: int
    current_conversation_epoch: int
    change_ref: VersionedRef
    reason: str
    coverage: str

    def __post_init__(self) -> None:
        if (type(self.grant) is not CommunicationIntentGrant
                or type(self.staged) is not StagingResult
                or type(self.track) is not ConversationTrack
                or type(self.track_head) is not GraphVersion
                or type(self.change_ref) is not VersionedRef):
            raise TypeError("typed grant, staged batch and current track required")
        if (self.track_head.key.type_name != "d09.conversation_track.v1"
                or self.track_head.key.name != self.track.track_id
                or self.track_head.revision < 1):
            raise ValueError("conversation track head differs")
        if (type(self.observations) is not tuple
                or any(type(item) is not DeliveryObservation for item in self.observations)
                or len({item.segment_id for item in self.observations}) != len(self.observations)):
            raise ValueError("unique D11 segment observations required")
        for name in ("current_cancellation_epoch", "current_conversation_epoch"):
            value = getattr(self, name)
            if type(value) is not int or value < 0:
                raise ValueError(f"{name} must be nonnegative")
        if (self.current_cancellation_epoch < self.grant.cancellation_epoch
                or self.current_conversation_epoch < self.track.conversation_epoch):
            raise ValueError("current epochs cannot precede the frozen batch")
        if self.reason not in _REASONS or self.coverage not in {"full", "partial", "none"}:
            raise ValueError("known interruption reason and coverage required")


@dataclass(frozen=True, slots=True)
class SegmentInterruptionCandidateV1:
    status: str
    track: ConversationTrack | None
    blocked_segment_refs: tuple[str, ...]
    exposed_segment_refs: tuple[str, ...]
    unknown_segment_refs: tuple[str, ...]
    required_track_head: GraphVersion
    change_ref: VersionedRef
    missing: tuple[str, ...]


def interrupt_remaining_segments_v1(
    read: SegmentInterruptionReadV1, *,
    read_verifier: Callable[[SegmentInterruptionReadV1], bool] | None,
) -> SegmentInterruptionCandidateV1:
    """Preserve handed-off facts, stop unadmitted remainder, never resend unknown.

    This is only a domain transition candidate. D11 must synchronously block
    later admission at its own authority fence; W01 adopts the track by CAS.
    """
    if type(read) is not SegmentInterruptionReadV1:
        raise TypeError("typed interruption read required")

    def hold(*missing: str) -> SegmentInterruptionCandidateV1:
        return SegmentInterruptionCandidateV1(
            "hold", None, (), read.track.exposed_segment_refs,
            read.track.unknown_segment_refs, read.track_head,
            read.change_ref, missing,
        )

    if read.staged.status != "complete":
        return hold("verified_batch")
    check = D09ExpressionProvider.prepare_delivery(read.staged, read.grant, ())
    if check.status == "rejected":
        return hold("grant_manifest")
    grants = {item.segment_id: item for item in read.grant.segment_grants}
    if (len(read.staged.segments) != len(grants)
            or tuple(item.segment_id for item in read.staged.segments)
               != tuple(grants)):
        return hold("grant_manifest")
    for observation in read.observations:
        grant = grants.get(observation.segment_id)
        if grant is None or grant.effect_id != observation.effect_id:
            return hold("observation_identity")
    if (read.reason == "explicit_stop"
            and read.current_cancellation_epoch <= read.grant.cancellation_epoch):
        return hold("cancellation_epoch")
    if (read.reason == "relevant_new_turn"
            and read.current_conversation_epoch <= read.track.conversation_epoch):
        return hold("conversation_epoch")
    if read.coverage != "full" or read_verifier is None:
        return hold("current_read_unavailable")
    try:
        verified = read_verifier(read) is True
    except Exception:
        verified = False
    if not verified:
        return hold("current_read_unverified")

    observed = {item.segment_id: item.transport_status for item in read.observations}
    exposed = tuple(dict.fromkeys((
        *read.track.exposed_segment_refs,
        *(item.segment_id for item in read.observations
          if item.transport_status in {"handed_off", "accepted"}),
    )))
    resolved = {item.segment_id for item in read.observations
                if item.transport_status != "unknown"}
    unknown = tuple(dict.fromkeys((
        *(item for item in read.track.unknown_segment_refs if item not in resolved),
        *(item.segment_id for item in read.observations
          if item.transport_status == "unknown"),
    )))
    blocked = tuple(item.segment_id for item in read.staged.segments
                    if item.segment_id not in exposed
                    and item.segment_id not in unknown
                    and observed.get(item.segment_id) not in {
                        "handed_off", "accepted", "unknown",
                    })
    new_track = replace(
        read.track, conversation_epoch=read.current_conversation_epoch,
        exposed_segment_refs=exposed, unknown_segment_refs=unknown,
        status="interrupted",
    )
    return SegmentInterruptionCandidateV1(
        "interrupted", new_track, blocked, exposed, unknown,
        read.track_head, read.change_ref, (),
    )


__all__ = [
    "SegmentInterruptionReadV1", "SegmentInterruptionCandidateV1",
    "interrupt_remaining_segments_v1",
]
