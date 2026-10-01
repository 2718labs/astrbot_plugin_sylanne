"""A first handoff stays recorded when a later segment loses authority."""

from dataclasses import replace

from sylanne3.domains.d08 import CommunicationIntentGrant, SegmentGrant
from sylanne3.domains.d09 import (
    ClaimKind, ClaimUse, ConversationTrack, D09ExpressionProvider,
    DeliveryObservation, ExpressionClaim, SegmentCandidate, SegmentInterruptionReadV1,
    interrupt_remaining_segments_v1, segment_payload_digest,
)
from sylanne3.graph_types import AtomKey, GraphVersion, Owner
from sylanne3.runtime_contracts import VersionedRef

def _read(*, first_status="accepted", reason="explicit_stop",
          cancellation_epoch=3, coverage="full"):
    first = SegmentCandidate(
        "segment:1", "effect:1", "Hello", (ClaimUse(
            "claim:hello", 0, 5, ClaimKind.RHETORIC),),
        ("answer",), (), 0.0,
    )
    second = SegmentCandidate(
        "segment:2", "effect:2", "World", (ClaimUse(
            "claim:world", 0, 5, ClaimKind.RHETORIC),),
        (), (), 0.0,
    )
    checks = ("check:role-binding", "check:source-grant", "check:dispatch-budget")
    segments = (
        SegmentGrant("segment:1", "effect:1", 0,
                     segment_payload_digest(first.body, (), first.claim_uses),
                     200, (), None, checks, 100.0, 2),
        SegmentGrant("segment:2", "effect:2", 1,
                     segment_payload_digest(second.body, (), second.claim_uses),
                     200, (), "segment:1", checks, 100.0, 2),
    )
    intent = CommunicationIntentGrant(
        "communication-grant:" + "1" * 64, "communication:reply",
        "contact:alice", 1, "action:reply-1", "action:reply-1", 1,
        "entity:alice", ("entity:alice",), "expression", ("answer",),
        (ClaimKind.RHETORIC.value,), (), segments, "2" * 64,
        checks, 100.0, 2,
    )
    provider = D09ExpressionProvider()
    blueprint = provider.prepare_blueprint(
        intent, "scene:private", 4,
        (ExpressionClaim("claim:hello", "Hello", ClaimKind.RHETORIC,
                         (), ("entity:alice",), ("expression",), "disclosure:one"),
         ExpressionClaim("claim:world", "World", ClaimKind.RHETORIC,
                         (), ("entity:alice",), ("expression",), "disclosure:one")),
        now=1.0,
    ).blueprint
    assert blueprint is not None
    staged = provider.verify_and_stage(blueprint, (first, second))
    assert staged.status == "complete"
    track = ConversationTrack(
        "track:private", "scene:private", 4, (), (), (), "active",
    )
    head = GraphVersion(AtomKey(Owner("persona", "bot", "persona"),
                                "d09.conversation_track.v1", track.track_id), 2)
    observation = DeliveryObservation(
        "segment:1", "effect:1", first_status, "receipt:first", None,
    )
    return SegmentInterruptionReadV1(
        intent, staged, track, head, (observation,), cancellation_epoch,
        4, VersionedRef("cancellation:reply", cancellation_epoch),
        reason, coverage,
    )


def test_first_accepted_then_stop_blocks_only_unadmitted_remainder():
    read = _read()
    result = interrupt_remaining_segments_v1(
        read, read_verifier=lambda observed: observed is read,
    )
    assert result.status == "interrupted"
    assert result.blocked_segment_refs == ("segment:2",)
    assert result.exposed_segment_refs == ("segment:1",)
    assert result.unknown_segment_refs == ()
    assert result.track is not None
    assert result.track.status == "interrupted"
    assert result.track.exposed_segment_refs == ("segment:1",)
    assert read.track.status == "active"


def test_unknown_first_is_preserved_without_replay():
    read = _read(first_status="unknown")
    result = interrupt_remaining_segments_v1(
        read, read_verifier=lambda _: True,
    )
    assert result.blocked_segment_refs == ("segment:2",)
    assert result.exposed_segment_refs == ()
    assert result.unknown_segment_refs == ("segment:1",)


def test_source_revocation_blocks_remaining_segment_without_rewriting_first():
    read = _read(reason="source_revoked", cancellation_epoch=2)
    read = replace(read, change_ref=VersionedRef("d06:source-access-revoked", 6))
    result = interrupt_remaining_segments_v1(
        read, read_verifier=lambda observed: observed is read,
    )
    assert result.status == "interrupted"
    assert result.blocked_segment_refs == ("segment:2",)
    assert result.exposed_segment_refs == ("segment:1",)
    assert result.change_ref == read.change_ref


def test_confirmed_first_reconciles_prior_unknown_without_replaying_it():
    read = _read()
    read = replace(read, track=replace(
        read.track, unknown_segment_refs=("segment:1",)))
    result = interrupt_remaining_segments_v1(
        read, read_verifier=lambda observed: observed is read,
    )
    assert result.exposed_segment_refs == ("segment:1",)
    assert result.unknown_segment_refs == ()
    assert result.blocked_segment_refs == ("segment:2",)


def test_stale_or_untrusted_interruption_cannot_change_track():
    read = _read()
    assert interrupt_remaining_segments_v1(
        read, read_verifier=None,
    ).status == "hold"
    assert interrupt_remaining_segments_v1(
        read, read_verifier=lambda _: False,
    ).status == "hold"
    assert interrupt_remaining_segments_v1(
        replace(read, current_cancellation_epoch=2),
        read_verifier=lambda _: True,
    ).missing == ("cancellation_epoch",)
    wrong = replace(read, observations=(replace(
        read.observations[0], effect_id="effect:forged"),))
    assert interrupt_remaining_segments_v1(
        wrong, read_verifier=lambda _: True,
    ).missing == ("observation_identity",)
