from __future__ import annotations

from dataclasses import replace

import pytest

from sylanne3.domains.d09 import (
    D09ExpressionProvider, complete_inbound_turn_v1, complete_outbound_turn_v1,
    observe_outbound_turn_v1,
    project_completed_turns_v1, reserve_turn_slot_v1, turn_order_key,
)
from sylanne3.graph_types import AtomKey, GraphAtom, GraphVersion, Owner
from sylanne3.memory_types import SourceRecord, access_key, source_key
from sylanne3.runtime_contracts import NamespaceId
from sylanne3.domains.d09.turn_order import (
    validate_turn_completion_v1, validate_turn_outbound_observation_v1,
)


NS = NamespaceId("bot", "persona")
SCENE = "scene:private"
CONVERSATION = "private:recipient"


def _arrival_and_source(suffix: str):
    source_id = f"source:{suffix}"
    source = SourceRecord(source_id, f"message {suffix}", "sender", "reported",
                          "reported", 10.0, 11.0, "ingress", (CONVERSATION,), ("context",))
    source_atom = GraphAtom(source_key(*NS.as_tuple, source_id), 1, source.to_dict())
    access_atom = GraphAtom(access_key(*NS.as_tuple, source_id), 1, {
        "source_id": source_id, "audiences": [CONVERSATION], "purposes": ["context"],
        "status": "active", "recorded_at": 11.0,
    })
    event_key = AtomKey(Owner("event", *NS.as_tuple, f"world:{suffix}"),
                        "d03.world_event", "current")
    arrival = GraphAtom(event_key, 1, {
        "event_id": f"world:{suffix}", "kind": "message_received",
        "participant_roles": [["entity:sender", "sender_account"]],
        "occurred_from": 10.0, "occurred_until": 10.0, "learned_at": 11.0,
        "scene_ref": SCENE, "source_refs": [source_atom.key.token],
        "reality": "host_observed",
    })
    binding_key = AtomKey(Owner("persona", *NS.as_tuple), "d03.account_binding", "account:sender")
    binding = GraphAtom(binding_key, 1, {
        "account_id": "account:sender", "platform_namespace": "platform:one",
        "platform_identifier": "sender", "entity_id": "entity:sender",
        "verification_ref": event_key.token, "valid_from": 11.0, "valid_until": None,
    })
    return arrival, binding, source_atom, access_atom


def _committed_reservation(origin_ref: str, direction: str,
                           current_order: GraphAtom | None = None):
    candidate = reserve_turn_slot_v1(NS, SCENE, CONVERSATION, direction, origin_ref,
                                     current_order=current_order)
    order, slot = candidate.writes
    return candidate, GraphAtom(order.key, 1 if current_order is None else current_order.revision + 1,
                                order.value), GraphAtom(slot.key, 1, slot.value)


def test_inbound_completion_and_pending_outbound_gap_are_ordered():
    arrival0, binding0, source0, access0 = _arrival_and_source("zero")
    first, order, slot0 = _committed_reservation(arrival0.key.token, "inbound")
    outbox_key = AtomKey(Owner("activity", *NS.as_tuple, "activity:reply"),
                        "runtime.outbox", "outbox:one")
    second, order, slot1 = _committed_reservation(outbox_key.token, "outbound", order)
    arrival2, binding2, source2, access2 = _arrival_and_source("two")
    third, order, slot2 = _committed_reservation(arrival2.key.token, "inbound", order)

    completion0 = complete_inbound_turn_v1(NS, slot0, arrival0, binding0, source0, access0,
                                         binding_evidence=arrival0)
    completion2 = complete_inbound_turn_v1(NS, slot2, arrival2, binding2, source2, access2,
                                         binding_evidence=arrival2)
    projection = project_completed_turns_v1(
        NS, order, (slot0, slot1, slot2),
        (GraphAtom(completion0.write.key, 1, completion0.write.value),
         GraphAtom(completion2.write.key, 1, completion2.write.value)),
    )
    assert (first.sequence, second.sequence, third.sequence) == (0, 1, 2)
    assert projection.high_watermark == 2
    assert tuple(item.value["sequence"] for item in projection.completed) == (0, 2)
    assert projection.missing_ranges == ((1, 1),)
    assert all(item.value["peer_read_state"] == "unknown" for item in projection.completed)
    assert len(completion0.read_versions) == 5
    assert {spec.name for spec in D09ExpressionProvider.register_types()} >= {
        "d09.turn_order.v1", "d09.turn_slot.v1", "d09.turn_completion.v1",
        "d09.turn_outbound_observation.v1"}


def test_reservation_rejects_wrong_order_and_unaccounted_sequence_hole():
    arrival, binding, source, access = _arrival_and_source("one")
    candidate, order, slot = _committed_reservation(arrival.key.token, "inbound")
    assert candidate.expected_order is None
    with pytest.raises(ValueError, match="head differs"):
        reserve_turn_slot_v1(NS, SCENE, "different", "inbound", arrival.key.token,
                             current_order=order)
    with pytest.raises(ValueError, match="unaccounted hole"):
        project_completed_turns_v1(NS, order, (), ())
    with pytest.raises(ValueError, match="turn slot closure differs"):
        project_completed_turns_v1(NS, order, (slot, slot), ())


def test_inbound_completion_rejects_stale_access_and_wrong_arrival():
    arrival, binding, source, access = _arrival_and_source("one")
    _, _, slot = _committed_reservation(arrival.key.token, "inbound")
    with pytest.raises(ValueError, match="not current"):
        complete_inbound_turn_v1(NS, slot, arrival, binding, source,
                                 GraphAtom(access.key, 2, {**access.value, "status": "withdrawn"}),
                                 binding_evidence=arrival)
    with pytest.raises(ValueError, match="D03 arrival differs"):
        complete_inbound_turn_v1(NS, slot, GraphAtom(arrival.key, 2,
                                 {**arrival.value, "reality": "candidate"}), binding, source, access,
                                 binding_evidence=arrival)
    with pytest.raises(ValueError, match="sender role"):
        complete_inbound_turn_v1(NS, slot, arrival, GraphAtom(binding.key, 2,
                                 {**binding.value, "platform_identifier": "other"}), source, access,
                                 binding_evidence=arrival)


def _later_arrival_with_original_binding():
    evidence, binding, _, _ = _arrival_and_source("original")
    arrival, _, source, access = _arrival_and_source("later")
    arrival = replace(arrival, value={**arrival.value, "learned_at": 23.0,
                                      "occurred_from": 22.0, "occurred_until": 22.0})
    source = replace(source, value={**source.value, "recorded_at": 23.0})
    access = replace(access, value={**access.value, "recorded_at": 23.0})
    _, _, slot = _committed_reservation(arrival.key.token, "inbound")
    return slot, arrival, binding, source, access, evidence


def test_later_inbound_keeps_independent_original_binding_evidence():
    slot, arrival, binding, source, access, evidence = _later_arrival_with_original_binding()
    # The historical verification can have its original scene/source; the
    # current arrival alone determines this turn's scene, text and time.
    evidence = replace(evidence, value={**evidence.value, "scene_ref": "scene:original"})
    result = complete_inbound_turn_v1(NS, slot, arrival, binding, source, access,
                                     binding_evidence=evidence)
    assert result.write.value["evidence_ref"] == arrival.key.token
    assert result.write.value["trusted_utc"] == 23.0
    assert len(result.read_versions) == 6
    assert GraphVersion(arrival.key, 1) in result.read_versions
    assert GraphVersion(evidence.key, 1) in result.read_versions


@pytest.mark.parametrize("change", [
    "missing", "invalid", "zero_revision", "wrong_token", "namespace", "owner",
    "type", "kind", "reality", "sender", "role", "extra_sender", "time",
])
def test_inbound_rejects_unqualified_original_binding_evidence(change):
    slot, arrival, binding, source, access, evidence = _later_arrival_with_original_binding()
    if change == "missing":
        evidence = None
    elif change == "invalid":
        evidence = replace(evidence, valid=False)
    elif change == "zero_revision":
        evidence = replace(evidence, revision=0)
    elif change == "wrong_token":
        evidence = arrival
    elif change in {"namespace", "owner", "type"}:
        owner = (Owner("event", "other-bot", NS.persona_id, "world:original")
                 if change == "namespace" else
                 Owner("scene", *NS.as_tuple, "scene:original")
                 if change == "owner" else evidence.key.owner)
        key = AtomKey(owner, "d03.account_binding" if change == "type"
                      else "d03.world_event", "current")
        evidence = replace(evidence, key=key)
        binding = replace(binding, value={**binding.value, "verification_ref": key.token})
    else:
        changed = {"kind": {"kind": "message_sent"},
                   "reality": {"reality": "candidate"},
                   "sender": {"participant_roles": [["entity:other", "sender_account"]]},
                   "role": {"participant_roles": [["entity:sender", "recipient_account"]]},
                   "extra_sender": {"participant_roles": [
                       ["entity:sender", "sender_account"], ["entity:other", "sender_account"]]},
                   "time": {"learned_at": 12.0}}[change]
        evidence = replace(evidence, value={**evidence.value, **changed})
    with pytest.raises(ValueError, match="binding evidence"):
        complete_inbound_turn_v1(NS, slot, arrival, binding, source, access,
                                 binding_evidence=evidence)


def test_inbound_requires_explicit_original_binding_evidence():
    slot, arrival, binding, source, access, _ = _later_arrival_with_original_binding()
    with pytest.raises(TypeError, match="binding_evidence"):
        complete_inbound_turn_v1(NS, slot, arrival, binding, source, access)


@pytest.mark.parametrize("field,value", [
    ("source_refs", []), ("scene_ref", "scene:other"),
    ("participant_roles", [["entity:other", "sender_account"]]), ("learned_at", 24.0),
])
def test_original_binding_evidence_does_not_qualify_wrong_current_arrival(field, value):
    slot, arrival, binding, source, access, evidence = _later_arrival_with_original_binding()
    arrival = replace(arrival, value={**arrival.value, field: value})
    with pytest.raises(ValueError):
        complete_inbound_turn_v1(NS, slot, arrival, binding, source, access,
                                 binding_evidence=evidence)


def test_outbound_unknown_or_uncommitted_observation_cannot_complete():
    outbox_key = AtomKey(Owner("activity", *NS.as_tuple, "activity:reply"),
                        "runtime.outbox", "outbox:one")
    _, _, slot = _committed_reservation(outbox_key.token, "outbound")
    _, _, source, access = _arrival_and_source("outbound")
    outbox = GraphAtom(outbox_key, 1, {"phase": "unknown"})
    batch_key = AtomKey(Owner("activity", *NS.as_tuple, "activity:reply"),
                        "d09.verified_segment_batch.v1", "batch:one")
    batch = GraphAtom(batch_key, 1, {"segments": [{"body": source.value["text"]}]})
    with pytest.raises(ValueError, match="persisted D11 observation"):
        observe_outbound_turn_v1(NS, slot, outbox, batch, source, access, None)
    with pytest.raises(ValueError, match="actual D11 recipient delivery"):
        complete_outbound_turn_v1(NS, slot, outbox, batch, source, access, None)
    assert turn_order_key(NS, SCENE, CONVERSATION).type_name == "d09.turn_order.v1"


def test_adapter_accepted_is_observed_but_never_a_completed_delivery():
    outbox_key = AtomKey(Owner("activity", *NS.as_tuple, "activity:reply"),
                        "runtime.outbox", "outbox:one")
    _, _, slot = _committed_reservation(outbox_key.token, "outbound")
    _, _, source, access = _arrival_and_source("outbound")
    batch_key = AtomKey(Owner("activity", *NS.as_tuple, "activity:reply"),
                        "d09.verified_segment_batch.v1", "batch:one")
    observed = {"schema": "d09.turn_outbound_observation.v1", "scene_ref": SCENE,
                "conversation_ref": CONVERSATION, "sequence": 0,
                "slot_ref": slot.key.token, "outbox_ref": outbox_key.token,
                "batch_ref": batch_key.token, "source_ref": source.key.token,
                "access_ref": access.key.token, "evidence_ref": "receipt:d11",
                "observation_state": "platform_accepted", "peer_delivery_state": "unknown",
                "peer_read_state": "unknown", "version": 1}
    validate_turn_outbound_observation_v1(observed)
    with pytest.raises(ValueError, match="platform ACK cannot prove"):
        validate_turn_outbound_observation_v1({**observed, "peer_delivery_state": "confirmed"})
    with pytest.raises(ValueError, match="turn completion fields differ"):
        validate_turn_completion_v1(observed)
    projection = project_completed_turns_v1(NS,
        GraphAtom(turn_order_key(NS, SCENE, CONVERSATION), 1, {
            "schema": "d09.turn_order.v1", "scene_ref": SCENE,
            "conversation_ref": CONVERSATION, "high_watermark": 0, "version": 1}),
        (slot,), ())
    assert projection.completed == () and projection.missing_ranges == ((0, 0),)
