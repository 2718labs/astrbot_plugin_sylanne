from __future__ import annotations

from dataclasses import asdict, replace

import pytest

from rewrite.sylanne3.domains.d06 import (
    CandidateItem,
    CandidateSet,
    D06DomainAdapter,
    RecollectionContext,
    SelectionTicket,
)
from rewrite.sylanne3.domains.d07 import (
    AttentionPolicy,
    AttentionTicket,
    BeliefRevision,
    CognitiveActivity,
    Concern,
    CurrentInterpretationCandidate,
    D07DomainProvider,
    EvidenceStatus,
    FocusState,
    Hypothesis,
    ReflectionCheckpoint,
    SimulationRequest,
    Stance,
    WorkingSetItem,
    WorkingSet,
)
from rewrite.sylanne3.graph_types import AtomKey, GraphVersion, GraphWrite, Owner, TypeRegistry, TypeSpec
from rewrite.sylanne3.memory_types import access_key, source_key
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
    VersionedRef,
    canonical_digest,
    schema_hash,
)


def recollection_envelope(
    *, activity_id: str = "activity-r1", input_refs: tuple[str, ...] = ("selection-input", "set-1"),
) -> tuple[CommandEnvelope, AtomKey]:
    namespace = NamespaceId("bot", "persona")
    source = AtomKey(Owner("persona", "bot", "persona"), "memory.source", "source-1")
    envelope = CommandEnvelope(
        schema="sylanne.runtime.v1",
        identity=OperationIdentity(
            activity_id, None, "attempt-r1", "realize-recollection", "operation-r1",
            canonical_digest({"input_refs": list(input_refs)}),
        ),
        authority=AuthorityContext(
            "host:user", "d06", "cap:d06", namespace, ("activity",), "context", ("user",),
            "policy:1", 1,
        ),
        version_guard=VersionGuard(
            (GraphVersion(source, 2),), (), 1, 1,
            "catalogue:1", "scheme:1", "operator:1", "policy:1",
            (), (VersionedRef("focus:1", 4),), (),
        ),
        source_qualification=SourceQualification(
            (source.token,), "reported", 1.0, 2.0, "external_observation", "eligible", 0.8,
            "not_applicable",
        ),
        input_refs=input_refs,
        parent_budget_lease_ref="budget:1",
        deadline_utc=100.0,
        monotonic_deadline=50.0,
        character_interval_ref="character:1",
        causation=("operation:parent",),
    )
    return envelope, source


def ticket(
    ticket_id: str,
    *,
    category: str = "background",
    relevance: float = 0.5,
    urgency: float = 0.5,
    waiting: float = 0.0,
    eligible: bool = True,
    valid_until: float = 100.0,
) -> AttentionTicket:
    return AttentionTicket(
        ticket_id=ticket_id,
        question_key=f"question:{ticket_id}",
        concern_ref=None,
        causal_root=f"root:{ticket_id}",
        category=category,
        relevance=relevance,
        urgency=urgency,
        information_value=0.4,
        persona_salience=0.3,
        emotional_salience=0.2,
        waiting=waiting,
        switch_cost=0.1,
        fatigue_cost=0.1,
        served_fraction=0.0,
        enqueued_seq=1,
        valid_until=valid_until,
        eligible=eligible,
        resources_available=True,
        cancel_refs=(),
    )


def test_attention_filters_ineligible_and_expired_before_bounded_priority() -> None:
    provider = D07DomainProvider()
    policy = AttentionPolicy.default()
    ranked = provider.rank_attention(
        (
            ticket("expired", category="required", urgency=1.0, valid_until=5.0),
            ticket("denied", category="required", urgency=1.0, eligible=False),
            ticket("chat", category="interaction", relevance=0.4),
            ticket("deadline", category="required", urgency=0.1),
        ),
        policy,
        now=10.0,
    )

    assert tuple(item.ticket.ticket_id for item in ranked) == ("deadline", "chat")
    assert all(0.0 <= item.score <= 1.0 for item in ranked)


def test_focus_is_one_primary_plus_three_auxiliary_and_epoch_is_serial() -> None:
    provider = D07DomainProvider()
    initial = FocusState("persona-a", 7, "old", ("aux-old",), "previous")
    next_state = provider.allocate_focus(
        initial,
        tuple(ticket(f"t{index}", relevance=1 - index / 10) for index in range(6)),
        AttentionPolicy.default(),
        now=1.0,
    )

    assert next_state.focus_epoch == 8
    assert next_state.primary_ticket_ref == "t0"
    assert next_state.auxiliary_ticket_refs == ("t1", "t2", "t3")


def test_working_set_keeps_hard_constraints_and_counterevidence() -> None:
    provider = D07DomainProvider()
    items = (
        WorkingSetItem("constraint", "hard_constraint", 200, 1.0, "observed", ("src-c",)),
        WorkingSetItem("counter", "counterevidence", 200, 0.1, "reported", ("src-r",)),
        WorkingSetItem("support", "support", 200, 0.9, "observed", ("src-s",)),
        WorkingSetItem("low", "retrievable", 4000, 0.0, "reported", ("src-l",)),
    )
    working = provider.assemble_working_set("activity-1", "q", items)

    assert tuple(item.content_ref for item in working.items) == ("constraint", "counter", "support")
    assert working.coverage == "partial"
    assert "capacity" in working.unknowns


def test_working_set_enforces_the_separate_d06_fragment_budget() -> None:
    provider = D07DomainProvider()
    working = provider.assemble_working_set(
        "activity-memory",
        "q-memory",
        (
            WorkingSetItem("memory-a", "memory_fragment", 1500, 1.0, "reported", ("src-a",)),
            WorkingSetItem("memory-b", "memory_fragment", 1000, 0.9, "reported", ("src-b",)),
            WorkingSetItem("context", "context", 1000, 0.8, "observed", ("src-c",)),
        ),
    )

    assert tuple(item.content_ref for item in working.items) == ("memory-a", "context")
    assert working.d06_tokens == 1500
    assert working.coverage == "partial"


def test_competing_explanations_are_bounded_and_source_eligibility_is_preserved() -> None:
    provider = D07DomainProvider()
    candidates = tuple(
        Hypothesis(
            hypothesis_id=f"h{index}",
            proposition=f"meaning-{index}",
            support_refs=(f"source-{index}",),
            counter_refs=(),
            source_families=(f"family-{index}",),
            evidence_status=EvidenceStatus.SUPPORTED,
            action_eligibility=("subjective_reaction",),
            score=1.0 - index / 10,
        )
        for index in range(5)
    )
    compared = provider.compare_hypotheses("question-1", candidates)

    assert len(compared.hypotheses) == 3
    assert compared.non_exhaustive is True
    with pytest.raises(ValueError, match="cannot elevate"):
        provider.adopt_belief(
            compared,
            "h0",
            stance=Stance.SUPPORT,
            subjective_conviction=0.95,
            requested_eligibility=("external_fact",),
        )


def test_correction_invalidates_current_belief_without_erasing_history() -> None:
    provider = D07DomainProvider()
    hypothesis = Hypothesis(
        "h1", "the reply meant rejection", ("source-short-reply",), (), ("event-1",),
        EvidenceStatus.INSUFFICIENT, ("subjective_reaction",), 0.5,
    )
    compared = provider.compare_hypotheses("reply-meaning", (hypothesis,))
    adopted = provider.adopt_belief(
        compared, "h1", stance=Stance.SUPPORT, subjective_conviction=0.8,
        requested_eligibility=("subjective_reaction",),
    )
    revised = provider.invalidate_belief(adopted, "source-correction", "correction")

    assert revised.current is False
    assert revised.replaced_by is None
    assert revised.historical is True
    assert revised.invalidation_refs == ("source-correction",)


def test_recollection_is_only_a_d06_selection_handoff() -> None:
    provider = D07DomainProvider()
    candidates = CandidateSet(
        "set-1",
        (CandidateItem("m1", "memory-1", "family-1", "association", ("context",), 0.8, "reported_claim"),),
        "complete",
    )
    handoff = provider.select_recollection(
        activity_id="activity-r1",
        focus_epoch=4,
        candidates=candidates,
        selected_candidate_ids=("m1",),
    )

    assert isinstance(handoff.selection_ticket, SelectionTicket)
    assert handoff.coordinator == "d06.c04"
    assert handoff.creates_recollection is False
    assert handoff.required_bundle_parts == ("experience", "d02_settlement", "cost_settlement")


def test_reflection_stops_after_two_no_progress_segments_and_depth_is_bounded() -> None:
    provider = D07DomainProvider()
    first = ReflectionCheckpoint("reflection-1", 1, 0, ("slot-a",), (), "continue")
    second = provider.advance_reflection(first, resolved_slots=(), discriminating_refs=())
    third = provider.advance_reflection(second, resolved_slots=(), discriminating_refs=())

    assert second.no_progress_count == 1
    assert third.no_progress_count == 2
    assert third.status == "waiting_for_new_trigger"
    with pytest.raises(ValueError, match="meta depth"):
        provider.advance_reflection(replace(first, meta_depth=2), resolved_slots=("slot-a",), discriminating_refs=())


def test_simulation_is_isolated_and_cannot_claim_external_fact() -> None:
    provider = D07DomainProvider()
    result = provider.simulate(
        SimulationRequest(
            activity_id="sim-1",
            snapshot_refs=("source-1",),
            baseline="do nothing",
            alternatives=("ask once", "wait", "invent a fourth path"),
            predictions=(("no new evidence",), ("may clarify", "may remain ambiguous"), ("unknown",)),
            unknowns=("other person's intent",),
        )
    )

    assert len(result.branches) == 3
    assert all(branch.content_reality == "simulated" for branch in result.branches)
    assert all(branch.evidence_eligibility == "none" for branch in result.branches)
    assert result.truncated is True


def test_concern_requires_a_resolution_or_explicit_review_condition() -> None:
    with pytest.raises(ValueError, match="resolution"):
        Concern(
            concern_id="c1", anchor_ref="event-1", reason_refs=("source-1",),
            resolution_predicate=None, wake_conditions=(), status="open", version=1,
        )


def test_provider_exposes_frozen_runtime_contract_without_claiming_commit() -> None:
    provider = D07DomainProvider()
    assert provider.descriptor.contract_version == "sylanne.runtime.v1"
    assert provider.register_types() == (
        "d07.concern.v1",
        "d07.focus.v1",
        "d07.working_set.v1",
        "d07.belief_revision.v1",
        "d07.cognitive_activity.v1",
        "d07.simulation_branch.v1",
        "d07.selection_ticket.v1",
        "d07.current_interpretation.v1",
    )


def test_provider_builds_a_candidate_domain_proposal_only() -> None:
    provider = D07DomainProvider()
    namespace = NamespaceId("bot", "persona")
    key = AtomKey(Owner("persona", "bot", "persona"), "d07.concern.v1", "concern-1")
    input_refs = ("input:1",)
    envelope = CommandEnvelope(
        schema="sylanne.runtime.v1",
        identity=OperationIdentity(
            "activity-1", None, "attempt-1", "prepare", "operation-1",
            canonical_digest({"input_refs": list(input_refs)}),
        ),
        authority=AuthorityContext(
            "host:user", "d07", "cap:d07", namespace, ("persona",), "context", ("user",),
            "policy:1", 1,
        ),
        version_guard=VersionGuard(
            (GraphVersion(key, 0),), (QueryEpoch(namespace, "query:d07", 1),), 1, 1,
            "catalogue:1", "scheme:1", "operator:1", "policy:1",
            (VersionedRef("grant:1", 1),), (VersionedRef("focus:1", 1),),
            (VersionedRef("resource:1", 1),),
        ),
        source_qualification=SourceQualification(
            ("source:1",), "observed", 1.0, 2.0, "external_observation", "eligible", 0.8,
            "not_applicable",
        ),
        input_refs=input_refs,
        parent_budget_lease_ref="budget:1",
        deadline_utc=100.0,
        monotonic_deadline=50.0,
        character_interval_ref="character:1",
        causation=("operation:parent",),
    )

    proposal = provider.proposal_for(envelope, required_bundle_parts=("outbox",))
    assert proposal.typed_writes == ()
    assert proposal.required_bundle_parts == ("outbox",)
    assert provider.validate(proposal) is proposal


def test_provider_supplies_d11_catalogue_specs_with_writer_and_schema_validation() -> None:
    specs = D07DomainProvider().type_specs()
    assert len(specs) == 8
    assert all(isinstance(spec, TypeSpec) for spec in specs)
    assert all(spec.writer_domain == "d07" for spec in specs)
    assert all(spec.schema_hash is not None and len(spec.schema_hash) == 64 for spec in specs)
    concern = next(spec for spec in specs if spec.name == "d07.concern.v1")
    valid = {"schema": "d07.concern.v1", **asdict(Concern(
        "c1", "event-1", ("source-1",), "receipt:resolved", (), "open", 1,
    ))}
    valid["reason_refs"] = list(valid["reason_refs"])
    valid["wake_conditions"] = list(valid["wake_conditions"])
    concern.validator(valid)
    with pytest.raises(ValueError, match="schema"):
        concern.validator({key: value for key, value in valid.items() if key != "schema"})
    with pytest.raises(ValueError, match="exactly"):
        concern.validator({**valid, "unowned_claim": True})
    with pytest.raises(ValueError, match="resolution"):
        concern.validator({**valid, "resolution_predicate": None})


def test_catalogue_checks_complete_cognitive_activity_and_simulation_eligibility() -> None:
    specs = {spec.name: spec for spec in D07DomainProvider().type_specs()}
    activity = CognitiveActivity(
        "activity-1", "effect-1", "attempt-1", "reflection", 1.0, 2.0,
        "bounded_complete", ("source-1",), ("cost-1",),
    )
    payload = {"schema": "d07.cognitive_activity.v1", **asdict(activity)}
    payload["source_refs"] = list(payload["source_refs"])
    payload["cost_receipt_refs"] = list(payload["cost_receipt_refs"])
    specs["d07.cognitive_activity.v1"].validator(payload)
    with pytest.raises(ValueError, match="before"):
        specs["d07.cognitive_activity.v1"].validator({**payload, "ended_at": 0.0})
    simulation = {
        "schema": "d07.simulation_branch.v1", "branch_id": "branch-1",
        "changed_assumption": "ask once", "prediction_steps": ["may clarify"],
        "snapshot_refs": ["source-1"], "unknowns": ["response"],
        "content_reality": "simulated", "evidence_eligibility": "none",
    }
    specs["d07.simulation_branch.v1"].validator(simulation)
    with pytest.raises(ValueError, match="external evidence"):
        specs["d07.simulation_branch.v1"].validator({
            **simulation, "evidence_eligibility": "eligible",
        })


def test_catalogue_reconstructs_working_set_and_belief_without_source_upgrade() -> None:
    specs = {spec.name: spec for spec in D07DomainProvider().type_specs()}
    focus = {
        "schema": "d07.focus.v1", "persona_id": "persona-1", "focus_epoch": 1,
        "primary_ticket_ref": "ticket-1", "auxiliary_ticket_refs": [],
        "switch_reason": "selected_by_bounded_attention",
    }
    specs["d07.focus.v1"].validator(focus)
    with pytest.raises(ValueError, match="three auxiliary"):
        specs["d07.focus.v1"].validator({
            **focus, "auxiliary_ticket_refs": ["a", "b", "c", "d"],
        })
    working = {
        "schema": "d07.working_set.v1", "activity_id": "activity-1",
        "question_key": "question-1", "items": [{
            "content_ref": "memory-1", "kind": "memory_fragment", "token_cost": 12,
            "relevance": 0.5, "source_eligibility": "reported_claim", "source_refs": ["src-1"],
        }], "unknowns": [], "coverage": "complete", "d06_tokens": 12,
        "max_items": 16, "max_tokens": 4096,
    }
    specs["d07.working_set.v1"].validator(working)
    with pytest.raises(ValueError, match="accounting"):
        specs["d07.working_set.v1"].validator({**working, "d06_tokens": 0})
    belief = {
        "schema": "d07.belief_revision.v1", "belief_id": "belief-1",
        "question_key": "question-1", "hypothesis_ref": "h1",
        "proposition": "perhaps they were busy", "stance": "support",
        "subjective_conviction": 0.8, "evidence_status": "insufficient",
        "eligibility": ["subjective_reaction"], "source_refs": ["src-1"],
        "source_families": ["family-1"], "current": True, "historical": True,
        "replaced_by": None, "invalidation_refs": [], "invalidation_kind": None,
    }
    specs["d07.belief_revision.v1"].validator(belief)
    with pytest.raises(ValueError, match="eligibility"):
        specs["d07.belief_revision.v1"].validator({
            **belief, "eligibility": ["external_fact"],
        })


def test_recollection_support_builds_strict_choice_and_interpretation_writes() -> None:
    provider = D07DomainProvider()
    handoff = provider.select_recollection(
        activity_id="activity-r1",
        focus_epoch=4,
        candidates=CandidateSet(
            "set-1",
            (CandidateItem("m1", "source-1", "family-1", "association", ("context",), 0.8,
                           "reported_claim"),),
            "complete",
        ),
        selected_candidate_ids=("m1",),
    )
    envelope, source = recollection_envelope(
        input_refs=(handoff.selection_ticket.ticket_id, "set-1"),
    )
    interpretation = CurrentInterpretationCandidate(
        "interpretation-1", "activity-r1", "question:memory", "this memory still matters",
        Stance.SUPPORT, 0.7, EvidenceStatus.INSUFFICIENT, (source.token,), ("family-1",),
        ("present meaning remains uncertain",),
    )

    proposal = provider.recollection_support_proposal(
        envelope,
        handoff,
        interpretation,
        source_dependencies=(source,),
    )

    assert proposal.domain == "d07"
    assert proposal.envelope is envelope
    assert tuple(write.key.type_name for write in proposal.typed_writes) == (
        "d07.selection_ticket.v1", "d07.current_interpretation.v1",
    )
    choice, current = proposal.typed_writes
    assert choice.key.owner == Owner("activity", "bot", "persona", "activity-r1")
    assert choice.key.name == handoff.selection_ticket.ticket_id
    assert choice.value == {
        "schema": "d07.selection_ticket.v1",
        "ticket_id": handoff.selection_ticket.ticket_id,
        "activity_id": "activity-r1",
        "candidate_set_id": "set-1",
        "selected_candidate_ids": ["m1"],
        "focus_epoch": 4,
    }
    assert current.key.name == "interpretation-1"
    assert current.value["source_refs"] == [source.token]
    assert choice.dependencies == current.dependencies == ()
    assert proposal.dependencies.historical_provenance == (GraphVersion(source, 2),)
    assert "committed" not in choice.value and "commit_seq" not in current.value

    registry = TypeRegistry()
    for spec in provider.type_specs():
        registry.register(spec)
    for write in proposal.typed_writes:
        registry.validate(write.key, write.value)


def test_recollection_support_rejects_forged_choice_activity_namespace_and_missing_interpretation() -> None:
    provider = D07DomainProvider()
    handoff = provider.select_recollection(
        activity_id="activity-r1",
        focus_epoch=4,
        candidates=CandidateSet(
            "set-1",
            (CandidateItem("m1", "source-1", "family-1", "association", ("context",), 0.8,
                           "reported_claim"),),
            "complete",
        ),
        selected_candidate_ids=("m1",),
    )
    envelope, source = recollection_envelope(
        input_refs=(handoff.selection_ticket.ticket_id, "set-1"),
    )
    interpretation = CurrentInterpretationCandidate(
        "interpretation-1", "activity-r1", "question:memory", "possible present meaning",
        Stance.SUSPEND, 0.4, EvidenceStatus.INSUFFICIENT, (source.token,), ("family-1",), (),
    )
    proposal = provider.recollection_support_proposal(
        envelope, handoff, interpretation, source_dependencies=(source,),
    )
    choice, current = proposal.typed_writes
    forged = DomainProposal(
        proposal.domain,
        proposal.proposal_schema,
        proposal.proposal_schema_hash,
        envelope,
        (GraphWrite(choice.key, {**choice.value, "selected_candidate_ids": ["forged"]},
                    choice.dependencies), current),
        proposal.dependencies,
        proposal.contribution_keys,
        proposal.required_bundle_parts,
    )
    with pytest.raises(ValueError, match="SelectionTicket"):
        provider.validate(forged)

    wrong_activity, _ = recollection_envelope(
        activity_id="activity-other",
        input_refs=(handoff.selection_ticket.ticket_id, "set-1"),
    )
    with pytest.raises(ValueError, match="activity"):
        provider.recollection_support_proposal(
            wrong_activity, handoff, interpretation, source_dependencies=(source,),
        )
    foreign = AtomKey(Owner("persona", "other-bot", "persona"), "memory.source", "source-1")
    with pytest.raises(ValueError, match="namespace"):
        provider.recollection_support_proposal(
            envelope, handoff, interpretation, source_dependencies=(foreign,),
        )
    with pytest.raises(TypeError, match="interpretation"):
        provider.recollection_support_proposal(
            envelope, handoff, None, source_dependencies=(source,),
        )


def test_recollection_catalogue_rejects_extra_or_forged_candidate_fields() -> None:
    specs = {spec.name: spec for spec in D07DomainProvider().type_specs()}
    assert {"d07.selection_ticket.v1", "d07.current_interpretation.v1"}.issubset(specs)
    choice = {
        "schema": "d07.selection_ticket.v1",
        "ticket_id": "selection-1",
        "activity_id": "activity-r1",
        "candidate_set_id": "set-1",
        "selected_candidate_ids": ["m1"],
        "focus_epoch": 4,
    }
    specs["d07.selection_ticket.v1"].validator(choice)
    with pytest.raises(ValueError, match="exactly"):
        specs["d07.selection_ticket.v1"].validator({**choice, "committed": True})

    interpretation = {
        "schema": "d07.current_interpretation.v1",
        "interpretation_id": "interpretation-1",
        "activity_id": "activity-r1",
        "question_key": "question:memory",
        "proposition": "possible present meaning",
        "stance": "suspend",
        "subjective_conviction": 0.4,
        "evidence_status": "insufficient",
        "source_refs": ["source:1"],
        "source_families": ["family-1"],
        "meaningful_unknowns": [],
        "current": True,
    }
    specs["d07.current_interpretation.v1"].validator(interpretation)
    with pytest.raises(ValueError, match="external evidence|EvidenceStatus|evidence"):
        specs["d07.current_interpretation.v1"].validator({
            **interpretation, "evidence_status": "proven_external_fact",
        })


def test_recollection_support_is_consumable_by_d06_c04_without_placeholder_d07_writes() -> None:
    provider = D07DomainProvider()
    namespace = NamespaceId("bot", "persona")
    source = source_key("bot", "persona", "source-1")
    access = access_key("bot", "persona", "source-1")
    candidates = CandidateSet(
        "set-1",
        (CandidateItem("m1", "source-1", "family-1", "association", ("context",), 0.8,
                       "reported_claim"),),
        "complete",
        access_epoch=5,
        delete_epoch=6,
    )
    handoff = provider.select_recollection(
        activity_id="activity-r1", focus_epoch=4, candidates=candidates,
        selected_candidate_ids=("m1",),
    )
    input_refs = (handoff.selection_ticket.ticket_id, candidates.candidate_set_id)
    envelope = CommandEnvelope(
        "sylanne.runtime.v1",
        OperationIdentity(
            "activity-r1", None, "attempt-r1", "realize-recollection", "operation-r1",
            canonical_digest({"input_refs": list(input_refs)}),
        ),
        AuthorityContext(
            "host:user", "d06", "cap:d06", namespace, ("activity",), "context", ("user",),
            "policy:1", 1,
        ),
        VersionGuard(
            (GraphVersion(source, 2), GraphVersion(access, 3)), (), 5, 6,
            "catalogue:1", "scheme:1", "operator:1", "policy:1", (),
            (VersionedRef("focus:1", 4),), (),
        ),
        SourceQualification(
            (source.token,), "reported", 1.0, 2.0, "external_observation", "eligible", 0.8,
            "not_applicable",
        ),
        input_refs,
        "budget:1",
        100.0,
        50.0,
        "character:1",
        ("operation:parent",),
    )
    interpretation = CurrentInterpretationCandidate(
        "interpretation-1", "activity-r1", "question:memory", "possible present meaning",
        Stance.SUSPEND, 0.4, EvidenceStatus.INSUFFICIENT, (source.token,), ("family-1",), (),
    )
    d07_proposal = provider.recollection_support_proposal(
        envelope, handoff, interpretation, source_dependencies=(source,),
    )
    feeling = AtomKey(
        Owner("activity", "bot", "persona", "activity-r1"),
        "d04.recollection_feeling.v1", "feeling-1",
    )
    settlement = AtomKey(
        Owner("activity", "bot", "persona", "activity-r1"),
        "d02.settlement.v1", "settlement-1",
    )
    cost = AtomKey(
        Owner("activity", "bot", "persona", "activity-r1"),
        "runtime.cost_settlement", "cost-1",
    )
    outbox = AtomKey(
        Owner("activity", "bot", "persona", "activity-r1"), "runtime.outbox", "outbox-1",
    )

    def supporting(domain: str, writes: tuple[GraphWrite, ...]) -> DomainProposal:
        return DomainProposal(
            domain, f"{domain}.proposal.v1", schema_hash({"domain": domain, "proposal": 1}),
            envelope, writes, DependencySet(), (), (),
        )

    choice, current = d07_proposal.typed_writes
    bundle = D06DomainAdapter(namespace).assemble_recollection_bundle(
        envelope,
        handoff.selection_ticket,
        candidates,
        RecollectionContext((current.key.token,), (feeling.token,), ()),
        supporting_proposals=(
            d07_proposal,
            supporting("d04", (GraphWrite(feeling, {"candidate": "current-feeling"}),)),
            supporting("d02", (GraphWrite(settlement, {"candidate": "settlement"}),)),
            supporting("d11", (
                GraphWrite(cost, {"candidate": "cost"}),
                GraphWrite(outbox, {"candidate": "outbox"}),
            )),
        ),
        choice_ref=choice.key.token,
        d02_settlement_ref=settlement.token,
        d11_cost_settlement_ref=cost.token,
        outbox_ref=outbox.token,
    )

    assert bundle.choice_refs == (choice.key.token,)
    assert bundle.proposals[1] == d07_proposal
    assert bundle.proposals[1].typed_writes[1].key.token == current.key.token


def test_recollection_support_historical_sources_commit_through_graph_coordinator() -> None:
    """The immutable D07 records keep provenance without invalidating edges."""
    # Reuse the controlled coordinator fixture to exercise its real commit checks.
    from rewrite.tests.alpha1.runtime.graph_coordinator_test import CoordinatorTests
    from rewrite.tests.alpha1.runtime import graph_coordinator_test as coordinator_fixture
    from unittest.mock import patch
    from sylanne3.domains.d06 import CandidateItem as LiveCandidateItem, CandidateSet as LiveCandidateSet
    from sylanne3.domains.d07 import (
        CurrentInterpretationCandidate as LiveInterpretation,
        D07DomainProvider as LiveD07,
        EvidenceStatus as LiveEvidenceStatus,
        Stance as LiveStance,
    )
    from sylanne3.graph_types import AtomKey as LiveAtomKey, Owner as LiveOwner
    from sylanne3.runtime_contracts import (
        AuthorityContext as LiveAuthorityContext,
        DomainBundle as LiveDomainBundle,
        QueryEpoch as LiveQueryEpoch,
        VersionedRef as LiveVersionedRef,
        canonical_digest as live_digest,
    )

    fixture = CoordinatorTests("test_atomic_bundle_and_duplicate_after_newer_state")
    real_store = coordinator_fixture.ProductionGraphStore

    def store_with_d07(path, registry):
        for spec in LiveD07().type_specs():
            registry.register(spec)
        return real_store(path, registry)

    with patch.object(coordinator_fixture, "ProductionGraphStore", side_effect=store_with_d07):
        fixture.setUp()
    try:
        provider = LiveD07()
        fixture.coordinator.register_provider(
            fixture.bootstrap, "d07", provider, "d07.proposal.v1",
            provider.descriptor.request_schema_hash)
        fixture.coordinator.set_guard_version(
            fixture.bootstrap, fixture.namespace, "focus_lease", "focus:1", 4)
        assert fixture.coordinator.commit_domain_bundle(
            fixture.bundle(operation="seed-source"), fixture.lease).status == "committed"
        lease, ref = fixture.coordinator.grant(
            fixture.bootstrap, actor="host", issuer_domain="d11",
            namespace=fixture.namespace, domains=("d06", "d07"), activation_generation=1)
        authority = LiveAuthorityContext(
            "host", "d11", ref, fixture.namespace, ("activity", "persona"),
            "remember", ("internal",), "policy", 1)
        candidates = LiveCandidateSet(
            "set-1", (LiveCandidateItem(
                "memory-1", fixture.key.token, "family-1", "association",
                ("context",), 0.8, "reported_claim"),), "complete")
        handoff = provider.select_recollection(
            activity_id="activity", focus_epoch=4, candidates=candidates,
            selected_candidate_ids=("memory-1",))
        choice_key = LiveAtomKey(
            LiveOwner("activity", "bot", "persona", "activity"),
            "d07.selection_ticket.v1", handoff.selection_ticket.ticket_id)
        interpretation_key = LiveAtomKey(
            LiveOwner("activity", "bot", "persona", "activity"),
            "d07.current_interpretation.v1", "interpretation-1")
        snapshot = fixture.coordinator.read_snapshot(
            authority, lease, (fixture.key, choice_key, interpretation_key))
        input_refs = (handoff.selection_ticket.ticket_id, candidates.candidate_set_id)
        base = fixture.bundle(operation="d07-recollection").envelope
        envelope = replace(
            base,
            identity=replace(
                base.identity, phase="realize-recollection",
                canonical_input_digest=live_digest({"input_refs": list(input_refs)})),
            authority=authority,
            version_guard=replace(
                base.version_guard, read_versions=snapshot.versions,
                query_epochs=(LiveQueryEpoch(
                    fixture.namespace, "all", snapshot.epochs[0].revision),),
                focus_lease_versions=(LiveVersionedRef("focus:1", 4),),
                catalogue_version=fixture.registry.catalogue_hash),
            input_refs=input_refs)
        interpretation = LiveInterpretation(
            "interpretation-1", "activity", "question:memory",
            "this memory may matter now", LiveStance.SUSPEND, 0.4,
            LiveEvidenceStatus.INSUFFICIENT, (fixture.key.token,),
            ("family-1",), ("present meaning remains uncertain",))
        proposal = provider.recollection_support_proposal(
            envelope, handoff, interpretation, source_dependencies=(fixture.key,))
        assert proposal.dependencies.historical_provenance == (snapshot.versions[0],)
        assert all(write.dependencies == () for write in proposal.typed_writes)
        # This test isolates D07's graph dependency contract; C04's required
        # experience, settlement and outbox bundle is assembled elsewhere.
        isolated = replace(proposal, required_bundle_parts=())
        bundle = LiveDomainBundle(envelope, (isolated,), (), (), (), (), (), (), ())
        receipt = fixture.coordinator.commit_domain_bundle(bundle, lease)
        assert receipt.status == "committed"
        with fixture.store._lock:
            edges = fixture.store._db.execute(
                "SELECT dependent_token,dependency_token,edge_kind "
                "FROM graph_dependency_edges WHERE operation_id=? ORDER BY dependent_token",
                (envelope.identity.operation_id,)).fetchall()
        assert edges == sorted((
            (choice_key.token, fixture.key.token, "historical_provenance"),
            (interpretation_key.token, fixture.key.token, "historical_provenance"),
        ))
        assert fixture.coordinator.commit_domain_bundle(
            fixture.bundle(operation="later-source", value=2), fixture.lease).status == "committed"
        after = fixture.coordinator.read_snapshot(
            authority, lease, (choice_key, interpretation_key))
        assert all(after.get(key).valid for key in (choice_key, interpretation_key))
    finally:
        fixture.tearDown()
