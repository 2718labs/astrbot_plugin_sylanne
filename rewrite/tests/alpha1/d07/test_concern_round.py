"""D07 concern service is bounded and cannot invent work on recovery."""

from dataclasses import replace

import pytest

from sylanne3.domains.d07 import AttentionPolicy, AttentionTicket
from sylanne3.domains.d07.concern_round import (
    ConcernRoundHold, ConcernRoundV1, begin_concern_round,
    choose_concern_segment, concern_round_key, concern_round_type_spec,
    concern_round_write, park_concern_group, read_concern_round,
    settle_concern_segment,
)
from sylanne3.graph_types import GraphAtom, GraphSnapshot, NamespaceEpoch
from sylanne3.runtime_contracts import NamespaceId


POLICY = AttentionPolicy.default()


def _ticket(ticket_id, group, relevance=0.5, *, valid_until=100.0):
    return AttentionTicket(
        ticket_id, f"question:{ticket_id}", f"concern:{group}", f"root:{group}",
        "background", relevance, 0.5, 0.4, 0.3, 0.2, 0.0, 0.1, 0.1, 0.0,
        1, valid_until, True, True, (), (),
    )


def _empty():
    return ConcernRoundV1("persona", "background", 0, 0, (), (), (), ())


def _settle(state, choice, inventory, effect, *, now=10.0, prior=()):
    return settle_concern_segment(
        state, choice, inventory, POLICY, effect_id=effect,
        receipt_ref=f"receipt:{effect}", now=now,
        focus_epoch=7, previously_committed_effect_ids=prior,
    )


def test_one_group_cannot_split_tickets_to_outrun_another_group():
    a1 = _ticket("a1", "a", 0.9)
    a2 = _ticket("a2", "a", 0.8)
    b = _ticket("b", "b", 0.1)
    tickets = (a1, a2, b)
    begun = begin_concern_round(_empty(), tickets, now=10.0)
    assert begun.status == "new_round_candidate"
    state = begun.next_round
    assert state.groups == ("concern:a", "concern:b")
    first = choose_concern_segment(state, tickets, POLICY, now=10.0, focus_epoch=7)
    assert first.ticket_id == "a1"
    with pytest.raises(ConcernRoundHold, match="digest differs"):
        _settle(state, first, (a1,), "effect:forged-inventory")
    settled = _settle(state, first, tickets, "effect:a1")
    assert settled.status == "service_candidate_requires_receipt_verification"
    assert settled.receipt_ref == "receipt:effect:a1"
    assert settled.choice_digest == first.choice_digest
    state = settled.next_round
    assert _settle(state, first, tickets, "effect:a1").next_round == state
    second = choose_concern_segment(state, tickets, POLICY, now=10.0, focus_epoch=7)
    assert second.ticket_id == "b"  # unserved group before a second slice for a
    state = _settle(state, second, tickets, "effect:b").next_round
    third = choose_concern_segment(state, tickets, POLICY, now=10.0, focus_epoch=7)
    assert third.group_id == "concern:a"
    state = _settle(state, third, tickets, "effect:a2").next_round
    fourth = choose_concern_segment(state, tickets, POLICY, now=10.0, focus_epoch=7)
    assert fourth.group_id == "concern:b"
    state = _settle(state, fourth, tickets, "effect:b2").next_round
    assert choose_concern_segment(state, tickets, POLICY, now=10.0, focus_epoch=7) is None
    assert dict(state.served) == {"concern:a": 2, "concern:b": 2}


def test_expiry_pause_cooldown_resume_and_receipt_recovery_do_not_consume_twice():
    a = _ticket("a", "a", 0.8)
    b = _ticket("b", "b", 0.2, valid_until=20.0)
    tickets = (a, b)
    state = begin_concern_round(_empty(), tickets, now=10.0).next_round
    choice = choose_concern_segment(state, (b,), POLICY, now=10.0, focus_epoch=7)
    assert choice.ticket_id == "b"
    with pytest.raises(ConcernRoundHold, match="stale, paused or expired"):
        _settle(state, choice, (b,), "effect:b", now=20.0)
    parked = park_concern_group(state, group_id="concern:b", until=50.0)
    state = parked.next_round
    assert parked.status == "park_candidate"
    assert choose_concern_segment(state, tickets, POLICY, now=11.0, focus_epoch=7).ticket_id == "a"
    with pytest.raises(ConcernRoundHold, match="stale, paused or expired"):
        _settle(state, choice, (b,), "effect:b", now=11.0)
    for effect in ("effect:a1", "effect:a2"):
        current = choose_concern_segment(state, tickets, POLICY, now=11.0, focus_epoch=7)
        state = _settle(state, current, tickets, effect, now=11.0).next_round
    early = begin_concern_round(state, tickets, now=30.0).next_round
    assert early.groups == ("concern:a",)
    assert early.parked == (("concern:b", 50.0),)
    for effect in ("effect:a3", "effect:a4"):
        current = choose_concern_segment(early, tickets, POLICY, now=31.0, focus_epoch=7)
        early = _settle(early, current, tickets, effect, now=31.0).next_round
    assert begin_concern_round(early, tickets, now=40.0).next_round.groups == ("concern:a",)
    resumed = begin_concern_round(state, (a, replace(b, valid_until=100.0)), now=60.0)
    assert resumed.next_round.groups == ("concern:a", "concern:b")
    assert resumed.next_round.round_id == 2  # elapsed time did not invent ticks
    resume_choice = choose_concern_segment(
        resumed.next_round, (a, replace(b, valid_until=100.0)), POLICY,
        now=60.0, focus_epoch=7,
    )
    assert _settle(resumed.next_round, resume_choice,
                   (a, replace(b, valid_until=100.0)),
                   "effect:old", now=60.0,
                   prior=("effect:old",)).status == "receipt_exists_requires_reconciliation"
    assert resumed.next_round.served == ()


def test_no_runnable_group_keeps_revision_and_round_stable():
    state = _empty()
    ticket = _ticket("expired", "x", valid_until=5.0)
    waiting = begin_concern_round(state, (ticket,), now=10.0)
    assert waiting.status == "waiting_without_fabricated_round"
    assert waiting.next_round == state
    assert choose_concern_segment(state, (ticket,), POLICY,
                                  now=10.0, focus_epoch=7) is None


def test_graph_round_write_and_revision_read_are_typed():
    namespace = NamespaceId("bot", "persona")
    state = begin_concern_round(_empty(), (_ticket("a", "a"),), now=10.0).next_round
    write = concern_round_write(namespace, state)
    assert write.key == concern_round_key(namespace, "background")
    assert concern_round_type_spec().writer_domain == "d07"
    assert concern_round_type_spec().validator(write.value) == state
    snapshot = GraphSnapshot((GraphAtom(write.key, 1, write.value),),
                             (NamespaceEpoch("bot", "persona", 1),))
    assert read_concern_round(snapshot, namespace, "background")[0] == state
    with pytest.raises(ConcernRoundHold, match="revision or identity"):
        read_concern_round(replace(snapshot, atoms=(GraphAtom(write.key, 2, write.value),)),
                           namespace, "background")
