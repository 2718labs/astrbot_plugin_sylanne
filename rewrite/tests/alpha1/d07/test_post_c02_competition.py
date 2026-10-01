from dataclasses import replace

import pytest

from sylanne3.domains.d07 import AttentionPolicy, AttentionTicket, FocusState
from sylanne3.domains.d07.post_c02_competition import choose_post_c02_attention_v2


def _ticket(ticket_id: str, *, relevance: float, urgency: float,
            enqueued_seq: int, valid_until: float = 140.0) -> AttentionTicket:
    return AttentionTicket(
        ticket_id, f"question:{ticket_id}", None, f"source:{ticket_id}",
        "interaction", relevance, urgency, 0.5, 0.5, 0.0, 0.0, 0.0, 0.0,
        0.0, enqueued_seq, valid_until, True, True, (), (f"source:{ticket_id}",),
    )


def _policy(*, urgency: bool) -> AttentionPolicy:
    weights = [0.0625] * 9
    weights[1 if urgency else 0] = 0.5
    return AttentionPolicy(*weights)


def test_adopted_weights_change_current_vs_inbound_and_preserve_loser():
    old = _ticket("old", relevance=1.0, urgency=0.0, enqueued_seq=1, valid_until=130.0)
    inbound = _ticket("new", relevance=0.0, urgency=1.0, enqueued_seq=2)
    current = FocusState("persona", 7, "old", (), "previous")

    retained = choose_post_c02_attention_v2(current, inbound, old,
                                             _policy(urgency=False), now=100.0)
    assert retained.focus.primary_ticket_ref == "old"
    assert retained.focus.auxiliary_ticket_refs == ("new",)
    assert retained.focus.focus_epoch == 8
    assert retained.inbound_deferred and retained.wake_at == 130.0

    switched = choose_post_c02_attention_v2(current, inbound, old,
                                             _policy(urgency=True), now=100.0)
    assert switched.focus.primary_ticket_ref == "new"
    assert switched.focus.auxiliary_ticket_refs == ("old",)
    assert not switched.inbound_deferred and switched.wake_at is None


def test_expired_cancelled_or_fully_served_old_ticket_cannot_hold_inbound():
    old = _ticket("old", relevance=1.0, urgency=0.0, enqueued_seq=1, valid_until=100.0)
    inbound = _ticket("new", relevance=0.0, urgency=1.0, enqueued_seq=2)
    current = FocusState("persona", 7, "old", (), "previous")
    for previous in (
        old,
        replace(old, valid_until=140.0, cancel_refs=("cancel",)),
        replace(old, valid_until=140.0, served_fraction=1.0),
    ):
        choice = choose_post_c02_attention_v2(current, inbound, previous,
                                              _policy(urgency=False), now=100.0)
        assert choice.selected_ticket_id == "new"
        assert choice.focus.auxiliary_ticket_refs == ()


def test_missing_old_or_queued_auxiliary_does_not_silently_drop_work():
    inbound = _ticket("new", relevance=1.0, urgency=1.0, enqueued_seq=2)
    current = FocusState("persona", 7, "old", (), "previous")
    with pytest.raises(ValueError, match="current primary"):
        choose_post_c02_attention_v2(current, inbound, None, _policy(urgency=True), now=100.0)
    with pytest.raises(ValueError, match="queued auxiliaries"):
        choose_post_c02_attention_v2(replace(current, auxiliary_ticket_refs=("other",)),
                                     inbound, _ticket("old", relevance=0.0, urgency=0.0,
                                                       enqueued_seq=1),
                                     _policy(urgency=True), now=100.0)
