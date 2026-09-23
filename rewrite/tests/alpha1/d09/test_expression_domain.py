from __future__ import annotations

from dataclasses import replace

import pytest

from rewrite.sylanne3.domains.d08 import CommunicationIntentGrant, SegmentGrant
from rewrite.sylanne3.domains.d09 import (
    AdmissionReceipt,
    ClaimKind,
    ClaimUse,
    ConversationTrack,
    D09ExpressionProvider,
    DeliveryObservation,
    ExpressionClaim,
    SegmentCandidate,
    TopicThread,
    segment_payload_digest,
)
from rewrite.sylanne3.graph_types import AtomKey, GraphVersion, GraphWrite, Owner, TypeSpec
from rewrite.sylanne3.runtime_contracts import (
    AuthorityContext,
    CommandEnvelope,
    DependencySet,
    DomainProposal,
    NamespaceId,
    OperationIdentity,
    QueryEpoch,
    SourceQualification,
    VersionGuard,
    canonical_digest,
)


def grant(*, segments: tuple[SegmentGrant, ...] | None = None) -> CommunicationIntentGrant:
    checks = (
        segments[0].required_check_refs if segments
        else ("check:role-binding", "check:source-grant", "check:dispatch-budget")
    )
    return CommunicationIntentGrant(
        grant_id="communication-grant:" + "1" * 64,
        communication_action_id="communication:reply-1",
        contact_id="contact:alice-1",
        batch_revision=1,
        intent_ref="action:reply-1",
        action_id="action:reply-1",
        intent_revision=1,
        target_ref="entity:alice",
        audiences=("entity:alice",),
        purpose="expression",
        required_slots=("answer",),
        allowed_claim_kinds=(
            ClaimKind.EXTERNAL_FACT.value,
            ClaimKind.SUBJECTIVE_JUDGMENT.value,
            ClaimKind.RHETORIC.value,
        ),
        promise_grants=(),
        segment_grants=segments or (
            SegmentGrant("segment:1", "effect:1", 0, "0" * 64, 200, (), None, checks, 100.0, 2),
        ),
        qualification_receipt_digest="2" * 64,
        required_check_refs=checks,
        valid_until=100.0,
        cancellation_epoch=2,
    )


def claim(
    claim_id: str,
    text: str,
    kind: ClaimKind,
    *,
    sources: tuple[str, ...] = ("source:1",),
) -> ExpressionClaim:
    return ExpressionClaim(
        claim_id=claim_id,
        text=text,
        kind=kind,
        source_refs=sources,
        allowed_audiences=("entity:alice",),
        eligibility=("expression",),
        disclosure_ref="disclosure:1",
    )


def d09_proposal(write: GraphWrite, *, schema_hash: str | None = None) -> DomainProposal:
    provider = D09ExpressionProvider()
    namespace = NamespaceId("bot", "persona")
    envelope = CommandEnvelope(
        "sylanne.runtime.v1",
        OperationIdentity(
            "activity:reply", "effect:expression", "attempt:1", "prepare",
            "operation:expression", canonical_digest({"input_refs": ["source:request"]}),
        ),
        AuthorityContext(
            "host:user", "d09", "capability:d09", namespace, ("persona", "activity"),
            "expression", ("entity:alice",), "policy:1", 1,
        ),
        VersionGuard(
            (GraphVersion(write.key, 0),), (QueryEpoch(namespace, "d09:dialogue", 1),),
            0, 0, "catalogue:1", "scheme:1", "operator:1", "policy:1", (), (), (),
        ),
        SourceQualification(
            ("source:request",), "reported", 1.0, 1.0, "external_report", "eligible", 1.0,
            "not_applicable",
        ),
        ("source:request",), "budget:1", 10.0, 10.0, "clock:1", (),
    )
    return DomainProposal(
        "d09", "d09.proposal.v1", schema_hash or provider.descriptor.request_schema_hash,
        envelope, (write,), DependencySet(), ("d09:expression",), (),
    )


def test_missing_d08_intent_returns_unavailable() -> None:
    result = D09ExpressionProvider().prepare_blueprint(
        None,
        scene_ref="scene:chat",
        conversation_epoch=3,
        claims=(),
        now=1.0,
    )
    assert result.status == "unavailable"
    assert result.missing == ("d08_intent",)
    assert result.blueprint is None


def test_blueprint_preserves_claim_sources_and_eligibility() -> None:
    fact = claim("claim:fact", "The file is ready", ClaimKind.EXTERNAL_FACT)
    subjective = claim("claim:feeling", "I feel uncertain", ClaimKind.SUBJECTIVE_JUDGMENT)
    result = D09ExpressionProvider().prepare_blueprint(
        grant(),
        scene_ref="scene:chat",
        conversation_epoch=3,
        claims=(fact, subjective),
        now=1.0,
    )
    assert result.status == "complete"
    assert result.blueprint is not None
    assert result.blueprint.claims == (fact, subjective)
    assert result.blueprint.intent_ref == "action:reply-1"


def test_every_assertive_span_requires_exact_claim_mapping() -> None:
    provider = D09ExpressionProvider()
    blueprint = provider.prepare_blueprint(
        grant(), "scene:chat", 3,
        (claim("claim:fact", "The file is ready", ClaimKind.EXTERNAL_FACT),),
        now=1.0,
    ).blueprint
    assert blueprint is not None
    candidate = SegmentCandidate(
        "segment:1", "effect:1", "The file is ready and sent", (ClaimUse("claim:fact", 0, 17, ClaimKind.EXTERNAL_FACT),),
        ("answer",), (), 0.0,
    )
    result = provider.verify_and_stage(blueprint, (candidate,))
    assert result.status == "rejected"
    assert "unmapped_content" in result.failures


def test_subjective_claim_cannot_be_expressed_as_external_fact() -> None:
    provider = D09ExpressionProvider()
    blueprint = provider.prepare_blueprint(
        grant(), "scene:chat", 3,
        (claim("claim:guess", "You seem distant", ClaimKind.SUBJECTIVE_JUDGMENT),),
        now=1.0,
    ).blueprint
    assert blueprint is not None
    candidate = SegmentCandidate(
        "segment:1", "effect:1", "You seem distant",
        (ClaimUse("claim:guess", 0, 16, ClaimKind.EXTERNAL_FACT),),
        ("answer",), (), 0.0,
    )
    result = provider.verify_and_stage(blueprint, (candidate,))
    assert result.status == "rejected"
    assert "eligibility_upgrade" in result.failures


def test_staging_requires_all_slots_and_obeys_segment_constraints() -> None:
    provider = D09ExpressionProvider()
    use = ClaimUse("claim:answer", 0, 3, ClaimKind.EXTERNAL_FACT)
    checks = ("check:1",)
    intent = grant(segments=(SegmentGrant(
        "segment:1", "effect:1", 0, segment_payload_digest("Yes", (), (use,)),
        200, (), None, checks, 100.0, 2,
    ),))
    blueprint = provider.prepare_blueprint(
        intent, "scene:chat", 3,
        (claim("claim:answer", "Yes", ClaimKind.EXTERNAL_FACT),),
        now=1.0,
    ).blueprint
    assert blueprint is not None
    missing_slot = SegmentCandidate(
        "segment:1", "effect:1", "Yes",
        (use,), (), (), 0.0,
    )
    assert provider.verify_and_stage(blueprint, (missing_slot,)).status == "unavailable"
    delayed = SegmentCandidate(
        "segment:1", "effect:1", "Yes",
        (use,), ("answer",), (), 2.1,
    )
    assert provider.verify_and_stage(blueprint, (delayed,)).status == "rejected"


def test_d11_admission_is_required_and_unknown_blocks_dependent_segment() -> None:
    use_one = ClaimUse("claim:one", 0, 5, ClaimKind.EXTERNAL_FACT)
    use_two = ClaimUse("claim:two", 0, 6, ClaimKind.EXTERNAL_FACT)
    checks = ("check:1",)
    grants = (
        SegmentGrant(
            "segment:1", "effect:1", 0, segment_payload_digest("First", (), (use_one,)),
            200, (), None, checks, 100.0, 2,
        ),
        SegmentGrant(
            "segment:2", "effect:2", 1, segment_payload_digest("Second", (), (use_two,)),
            200, (), "segment:1", checks, 100.0, 2,
        ),
    )
    intent = grant(segments=grants)
    provider = D09ExpressionProvider()
    claims = (
        claim("claim:one", "First", ClaimKind.EXTERNAL_FACT),
        claim("claim:two", "Second", ClaimKind.EXTERNAL_FACT),
    )
    blueprint = provider.prepare_blueprint(intent, "scene:chat", 3, claims, now=1.0).blueprint
    assert blueprint is not None
    candidates = (
        SegmentCandidate("segment:1", "effect:1", "First", (use_one,), ("answer",), (), 0.0),
        SegmentCandidate("segment:2", "effect:2", "Second", (use_two,), (), (), 0.0),
    )
    staged = provider.verify_and_stage(blueprint, candidates)
    assert staged.status == "complete"
    assert provider.prepare_delivery(staged, intent, ()).status == "unavailable"

    first_unknown = AdmissionReceipt(
        "admission:1", "segment:1", "effect:1", staged.segments[0].payload_digest, "unknown",
    )
    result = provider.prepare_delivery(staged, intent, (first_unknown,))
    assert result.status == "pending_confirmation"
    assert result.blocked_segment_refs == ("segment:2",)

    wrong_intent = replace(intent, action_id="action:other")
    assert provider.prepare_delivery(staged, wrong_intent, (first_unknown,)).status == "rejected"


def test_platform_acceptance_does_not_imply_read_or_agreement() -> None:
    provider = D09ExpressionProvider()
    accepted = provider.settle_progress(
        DeliveryObservation("segment:1", "effect:1", "accepted", "provider:receipt", None)
    )
    assert accepted.delivery_state == "accepted"
    assert accepted.read_state == "unknown"
    assert accepted.agreement_state == "unknown"

    read = provider.settle_progress(
        DeliveryObservation("segment:1", "effect:1", "accepted", "provider:receipt", "read:proof")
    )
    assert read.read_state == "confirmed"
    assert read.agreement_state == "unknown"
    with pytest.raises(ValueError, match="read proof"):
        provider.settle_progress(
            DeliveryObservation("segment:1", "effect:1", "unknown", "provider:receipt", "read:proof")
        )


def test_dialogue_continuity_preserves_unanswered_slots_through_interruption() -> None:
    provider = D09ExpressionProvider()
    track = ConversationTrack(
        "track:1", "scene:chat", 4,
        (TopicThread("topic:old", "old topic", ("old-question",), (), "when resumed", "open"),),
        ("segment:already-exposed",), (), "active",
    )
    updated = provider.update_dialogue_track(
        track,
        TopicThread("topic:new", "new topic", ("new-question",), (), "after answer", "open"),
        explicit_stop=True,
    )
    assert updated.conversation_epoch == 5
    assert updated.status == "interrupted"
    assert updated.unanswered_slots == ("old-question", "new-question")
    assert updated.exposed_segment_refs == ("segment:already-exposed",)


def test_provider_supplies_real_d09_type_specs_without_dispatch_capability() -> None:
    provider = D09ExpressionProvider()
    specs = provider.register_types()
    assert len(specs) == 6
    assert all(isinstance(spec, TypeSpec) for spec in specs)
    assert all(spec.writer_domain == "d09" for spec in specs)
    assert all(spec.schema_hash and callable(spec.validator) for spec in specs)
    assert provider.descriptor.contract_version == "sylanne.runtime.v1"
    assert not hasattr(provider, "send")
    track_spec = next(spec for spec in specs if spec.name == "d09.conversation_track.v1")
    valid_track = {
        "schema": "d09.conversation_track.v1",
        "track_id": "track:1",
        "scene_ref": "scene:chat",
        "conversation_epoch": 1,
        "thread_refs": ["topic:1"],
        "exposed_segment_refs": [],
        "unknown_segment_refs": [],
        "status": "active",
        "version": 1,
    }
    track_spec.validator(valid_track)
    with pytest.raises(ValueError, match="schema"):
        track_spec.validator({"track_id": "track:1", "conversation_epoch": 1})
    with pytest.raises(ValueError, match="unknown"):
        track_spec.validator({**valid_track, "invented_delivery": True})
    with pytest.raises(ValueError, match="status"):
        track_spec.validator({
            "schema": "d09.conversation_track.v1",
            "track_id": "track:1",
            "scene_ref": "scene:chat",
            "conversation_epoch": 1,
            "thread_refs": ["topic:1"],
            "exposed_segment_refs": [],
            "unknown_segment_refs": [],
            "status": "pretend_sent",
            "version": 1,
        })


def test_provider_validates_only_exact_d09_proposal_types_owners_and_payloads() -> None:
    provider = D09ExpressionProvider()
    value = {
        "schema": "d09.conversation_track.v1",
        "track_id": "track:1",
        "scene_ref": "scene:chat",
        "conversation_epoch": 1,
        "thread_refs": ["topic:1"],
        "exposed_segment_refs": [],
        "unknown_segment_refs": [],
        "status": "active",
        "version": 1,
    }
    valid_write = GraphWrite(
        AtomKey(Owner("persona", "bot", "persona"), "d09.conversation_track.v1", "track:1"),
        value,
    )
    proposal = d09_proposal(valid_write)
    assert provider.validate(proposal) is proposal

    with pytest.raises(ValueError, match="schema hash"):
        provider.validate(replace(proposal, proposal_schema_hash="0" * 64))

    foreign = GraphWrite(
        AtomKey(Owner("persona", "bot", "persona"), "d08.action_intent.v1", "intent:1"),
        {"schema": "d08.action_intent.v1"},
    )
    with pytest.raises(ValueError, match="type or owner"):
        provider.validate(d09_proposal(foreign))

    wrong_owner = GraphWrite(
        AtomKey(
            Owner("activity", "bot", "persona", "activity:reply"),
            "d09.conversation_track.v1", "track:1",
        ),
        value,
    )
    with pytest.raises(ValueError, match="type or owner"):
        provider.validate(d09_proposal(wrong_owner))

    invented_payload = GraphWrite(valid_write.key, {**value, "invented_delivery": True})
    with pytest.raises(ValueError, match="unknown"):
        provider.validate(d09_proposal(invented_payload))
