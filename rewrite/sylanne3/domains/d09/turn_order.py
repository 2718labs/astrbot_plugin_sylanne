"""Non-authorizing D09 turn order candidates for D13's current read path.

The graph coordinator must read the complete scene sequence under one fenced
transaction, check the absence predicates, and commit the returned writes.
Parsing these values alone does not establish current source or D11 authority.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import math

from ...authority_service.v2_contract import MutationReceiptV2, PlatformObservationV2
from ...graph_types import AtomKey, GraphAtom, GraphVersion, GraphWrite, Owner, TypeSpec
from ...memory_types import SourceRecord, access_key, source_key, validate_access
from ...runtime.dispatch_candidate import dispatch_segment_payload_ref
from ...runtime_contracts import NamespaceId, canonical_digest, schema_hash


ORDER_TYPE = "d09.turn_order.v1"
SLOT_TYPE = "d09.turn_slot.v1"
COMPLETION_TYPE = "d09.turn_completion.v1"
OUTBOUND_OBSERVATION_TYPE = "d09.turn_outbound_observation.v1"


def _string(value: object, label: str) -> str:
    if type(value) is not str or not value:
        raise ValueError(f"{label} is required")
    return value


def _number(value: object, label: str, *, positive: bool = False) -> int:
    if type(value) is not int or value < int(positive):
        raise ValueError(f"{label} must be an exact nonnegative integer")
    return value


def _time(value: object) -> float:
    if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
        raise ValueError("trusted time must be finite and nonnegative")
    return float(value)


def _scene_owner(namespace: NamespaceId, scene_ref: str) -> Owner:
    if type(namespace) is not NamespaceId:
        raise TypeError("namespace must be NamespaceId")
    return Owner("scene", *namespace.as_tuple, _string(scene_ref, "scene_ref"))


def _conversation_name(conversation_ref: str) -> str:
    return canonical_digest({"conversation_ref": _string(conversation_ref, "conversation_ref")})


def turn_order_key(namespace: NamespaceId, scene_ref: str, conversation_ref: str) -> AtomKey:
    return AtomKey(_scene_owner(namespace, scene_ref), ORDER_TYPE, _conversation_name(conversation_ref))


def turn_slot_key(namespace: NamespaceId, scene_ref: str, conversation_ref: str,
                  sequence: int) -> AtomKey:
    return AtomKey(_scene_owner(namespace, scene_ref), SLOT_TYPE,
                   f"{_conversation_name(conversation_ref)}:{_number(sequence, 'sequence')}")


def turn_completion_key(namespace: NamespaceId, scene_ref: str, conversation_ref: str,
                        sequence: int) -> AtomKey:
    return AtomKey(_scene_owner(namespace, scene_ref), COMPLETION_TYPE,
                   f"{_conversation_name(conversation_ref)}:{_number(sequence, 'sequence')}")


def turn_outbound_observation_key(namespace: NamespaceId, scene_ref: str,
                                  conversation_ref: str, sequence: int) -> AtomKey:
    return AtomKey(_scene_owner(namespace, scene_ref), OUTBOUND_OBSERVATION_TYPE,
                   f"{_conversation_name(conversation_ref)}:{_number(sequence, 'sequence')}")


def validate_turn_order_v1(value: dict) -> None:
    if type(value) is not dict or set(value) != {"schema", "scene_ref", "conversation_ref",
                                                  "high_watermark", "version"}:
        raise ValueError("turn order fields differ")
    if value["schema"] != ORDER_TYPE:
        raise ValueError("turn order schema differs")
    _string(value["scene_ref"], "scene_ref")
    _string(value["conversation_ref"], "conversation_ref")
    _number(value["high_watermark"], "high_watermark")
    _number(value["version"], "version", positive=True)


def validate_turn_slot_v1(value: dict) -> None:
    if type(value) is not dict or set(value) != {"schema", "scene_ref", "conversation_ref",
                                                  "sequence", "direction", "origin_ref", "version"}:
        raise ValueError("turn slot fields differ")
    if value["schema"] != SLOT_TYPE:
        raise ValueError("turn slot schema differs")
    _string(value["scene_ref"], "scene_ref")
    _string(value["conversation_ref"], "conversation_ref")
    _number(value["sequence"], "sequence")
    _number(value["version"], "version", positive=True)
    if value["direction"] not in {"inbound", "outbound"}:
        raise ValueError("turn direction differs")
    origin = AtomKey.from_token(_string(value["origin_ref"], "origin_ref"))
    if (value["direction"] == "inbound" and origin.type_name != "d03.world_event"):
        raise ValueError("inbound turn needs D03 arrival")
    if (value["direction"] == "outbound" and origin.type_name != "runtime.outbox"):
        raise ValueError("outbound turn needs D11 outbox")


def validate_turn_completion_v1(value: dict) -> None:
    fields = {"schema", "scene_ref", "conversation_ref", "sequence", "direction",
              "slot_ref", "source_ref", "access_ref", "evidence_ref", "speaker_ref",
              "trusted_utc", "tool_state", "observation_state", "peer_read_state", "version"}
    if type(value) is not dict or set(value) != fields:
        raise ValueError("turn completion fields differ")
    if value["schema"] != COMPLETION_TYPE:
        raise ValueError("turn completion schema differs")
    _string(value["scene_ref"], "scene_ref")
    _string(value["conversation_ref"], "conversation_ref")
    _number(value["sequence"], "sequence")
    _number(value["version"], "version", positive=True)
    if value["direction"] not in {"inbound", "outbound"}:
        raise ValueError("turn completion direction differs")
    slot = AtomKey.from_token(_string(value["slot_ref"], "slot_ref"))
    source = AtomKey.from_token(_string(value["source_ref"], "source_ref"))
    access = AtomKey.from_token(_string(value["access_ref"], "access_ref"))
    if slot.type_name != SLOT_TYPE or source.type_name != "memory.source" or access.type_name != "memory.access":
        raise ValueError("turn completion graph refs differ")
    if (source.owner != access.owner or source.owner.kind != "event"
            or (source.owner.bot, source.owner.persona)
               != (slot.owner.bot, slot.owner.persona)):
        raise ValueError("turn source namespace differs")
    _string(value["evidence_ref"], "evidence_ref")
    _string(value["speaker_ref"], "speaker_ref")
    _time(value["trusted_utc"])
    if value["tool_state"] not in {"complete", "not_applicable"}:
        raise ValueError("unclosed tool turn cannot complete")
    if value["peer_read_state"] != "unknown":
        raise ValueError("D09 cannot assert peer read from a host receipt")
    expected = "host_observed" if value["direction"] == "inbound" else "peer_delivered"
    if value["observation_state"] != expected:
        raise ValueError("turn is not observed in its direction")


def validate_turn_outbound_observation_v1(value: dict) -> None:
    fields = {"schema", "scene_ref", "conversation_ref", "sequence", "slot_ref",
              "outbox_ref", "batch_ref", "source_ref", "access_ref", "evidence_ref",
              "observation_state", "peer_delivery_state", "peer_read_state", "version"}
    if type(value) is not dict or set(value) != fields or value["schema"] != OUTBOUND_OBSERVATION_TYPE:
        raise ValueError("outbound observation fields differ")
    _string(value["scene_ref"], "scene_ref")
    _string(value["conversation_ref"], "conversation_ref")
    _number(value["sequence"], "sequence")
    _number(value["version"], "version", positive=True)
    for name, type_name in (("slot_ref", SLOT_TYPE), ("outbox_ref", "runtime.outbox"),
                            ("batch_ref", "d09.verified_segment_batch.v1"),
                            ("source_ref", "memory.source"), ("access_ref", "memory.access")):
        actual = AtomKey.from_token(_string(value[name], name)).type_name
        allowed = ({type_name, "d09.natural_verified_segment_batch.v2"}
                   if name == "batch_ref" else {type_name})
        if actual not in allowed:
            raise ValueError(f"outbound {name} type differs")
    _string(value["evidence_ref"], "evidence_ref")
    if value["observation_state"] not in {"unknown", "platform_accepted"}:
        raise ValueError("outbound observation state differs")
    if value["peer_delivery_state"] != "unknown" or value["peer_read_state"] != "unknown":
        raise ValueError("platform ACK cannot prove peer delivery or read")


def turn_order_type_specs_v1() -> tuple[TypeSpec, ...]:
    return tuple(TypeSpec(name, ("scene",), "state", validator, immutable=immutable,
                          writer_domain="d09", schema_hash=schema_hash({
                              "domain": "d09", "type": name, "version": 1,
                              "scene_owned": True, "immutable": immutable,
                          })) for name, validator, immutable in (
                              (ORDER_TYPE, validate_turn_order_v1, False),
                              (SLOT_TYPE, validate_turn_slot_v1, True),
                              (COMPLETION_TYPE, validate_turn_completion_v1, True),
                              (OUTBOUND_OBSERVATION_TYPE, validate_turn_outbound_observation_v1, False),
                          ))


@dataclass(frozen=True)
class TurnReservationCandidateV1:
    sequence: int
    expected_order: GraphVersion | None
    writes: tuple[GraphWrite, GraphWrite]
    absent_slot: AtomKey


def reserve_turn_slot_v1(namespace: NamespaceId, scene_ref: str, conversation_ref: str,
                         direction: str, origin_ref: str, *,
                         current_order: GraphAtom | None) -> TurnReservationCandidateV1:
    """Allocate the next local slot. W01 must CAS order and prove slot/origin absence."""
    order_key = turn_order_key(namespace, scene_ref, conversation_ref)
    if current_order is None:
        previous, version, guard = -1, 1, None
    else:
        if (type(current_order) is not GraphAtom or not current_order.valid
                or current_order.key != order_key):
            raise ValueError("current order head differs")
        validate_turn_order_v1(current_order.value)
        if (current_order.value["scene_ref"], current_order.value["conversation_ref"]) != (
                scene_ref, conversation_ref):
            raise ValueError("current order scope differs")
        previous = current_order.value["high_watermark"]
        version = current_order.value["version"] + 1
        guard = GraphVersion(order_key, current_order.revision)
    sequence = previous + 1
    slot_key = turn_slot_key(namespace, scene_ref, conversation_ref, sequence)
    order = {"schema": ORDER_TYPE, "scene_ref": scene_ref, "conversation_ref": conversation_ref,
             "high_watermark": sequence, "version": version}
    slot = {"schema": SLOT_TYPE, "scene_ref": scene_ref, "conversation_ref": conversation_ref,
            "sequence": sequence, "direction": direction, "origin_ref": origin_ref, "version": 1}
    validate_turn_slot_v1(slot)
    return TurnReservationCandidateV1(sequence, guard,
                                      (GraphWrite(order_key, order), GraphWrite(slot_key, slot)), slot_key)


@dataclass(frozen=True)
class TurnCompletionCandidateV1:
    write: GraphWrite
    read_versions: tuple[GraphVersion, ...]
    absent_completion: AtomKey


def _source_guard(namespace: NamespaceId, conversation_ref: str,
                  source: GraphAtom, access: GraphAtom) -> SourceRecord:
    if type(source) is not GraphAtom or type(access) is not GraphAtom or not source.valid or not access.valid:
        raise ValueError("current D06 source and access required")
    record = SourceRecord.from_dict(source.value)
    if (source.key != source_key(*namespace.as_tuple, record.source_id)
            or access.key != access_key(*namespace.as_tuple, record.source_id)):
        raise ValueError("D06 source/access graph identity differs")
    validate_access(access.value)
    if (access.value["source_id"] != record.source_id
            or access.value["status"] != "active"
            or conversation_ref not in access.value["audiences"]
            or "context" not in access.value["purposes"]
            or conversation_ref not in record.audiences
            or "context" not in record.purposes):
        raise ValueError("D06 source is not current for this conversation")
    return record


def _completion(namespace: NamespaceId, slot: GraphAtom, source: GraphAtom,
                access: GraphAtom, *, evidence_ref: str, speaker_ref: str,
                trusted_utc: float, tool_state: str, observation_state: str) -> TurnCompletionCandidateV1:
    value = slot.value
    validate_turn_slot_v1(value)
    key = turn_slot_key(namespace, value["scene_ref"], value["conversation_ref"], value["sequence"])
    if not slot.valid or slot.key != key or slot.revision != 1:
        raise ValueError("committed immutable turn slot required")
    record = _source_guard(namespace, value["conversation_ref"], source, access)
    if record.speaker_id != speaker_ref:
        raise ValueError("turn speaker differs from D06 source")
    completion_key = turn_completion_key(namespace, value["scene_ref"],
                                         value["conversation_ref"], value["sequence"])
    completion = {"schema": COMPLETION_TYPE, "scene_ref": value["scene_ref"],
                  "conversation_ref": value["conversation_ref"], "sequence": value["sequence"],
                  "direction": value["direction"], "slot_ref": key.token,
                  "source_ref": source.key.token, "access_ref": access.key.token,
                  "evidence_ref": evidence_ref, "speaker_ref": speaker_ref,
                  "trusted_utc": _time(trusted_utc), "tool_state": tool_state,
                  "observation_state": observation_state, "peer_read_state": "unknown", "version": 1}
    validate_turn_completion_v1(completion)
    return TurnCompletionCandidateV1(
        GraphWrite(completion_key, completion, (key, source.key, access.key)),
        tuple(GraphVersion(atom.key, atom.revision) for atom in (slot, source, access)),
        completion_key,
    )


def complete_inbound_turn_v1(namespace: NamespaceId, slot: GraphAtom,
                             arrival: GraphAtom, account_binding: GraphAtom,
                             source: GraphAtom, access: GraphAtom,
                             *, binding_evidence: GraphAtom,
                             tool_state: str = "not_applicable") -> TurnCompletionCandidateV1:
    """Complete only a committed D03 host-observed arrival and matching D06 text."""
    if (type(arrival) is not GraphAtom or arrival.valid is not True
            or type(arrival.revision) is not int or arrival.revision < 1
            or arrival.key.type_name != "d03.world_event"
            or arrival.key.owner.kind != "event"
            or (arrival.key.owner.bot, arrival.key.owner.persona) != namespace.as_tuple
            or arrival.key.token != slot.value.get("origin_ref")
            or arrival.value.get("kind") != "message_received"
            or arrival.value.get("reality") != "host_observed"
            or arrival.value.get("scene_ref") != slot.value.get("scene_ref")
            or arrival.value.get("source_refs") != [source.key.token]
            or slot.value.get("direction") != "inbound"):
        raise ValueError("current D03 arrival differs from inbound slot")
    record = SourceRecord.from_dict(source.value)
    if record.source_kind != "reported" or record.assertion_status != "reported":
        raise ValueError("inbound text must remain a reported source")
    participants = arrival.value.get("participant_roles", [])
    if (len(participants) != 1 or participants[0][1] != "sender_account"
            or type(account_binding) is not GraphAtom or account_binding.valid is not True
            or type(account_binding.revision) is not int or account_binding.revision < 1
            or account_binding.key.type_name != "d03.account_binding"
            or account_binding.value.get("entity_id") != participants[0][0]
            or account_binding.value.get("platform_identifier") != record.speaker_id
            or account_binding.value.get("valid_until") is not None
            or (account_binding.key.owner.bot, account_binding.key.owner.persona)
               != namespace.as_tuple
            or record.recorded_at != arrival.value.get("learned_at")):
        raise ValueError("arrival sender role is not unique")
    if (type(binding_evidence) is not GraphAtom or binding_evidence.valid is not True
            or type(binding_evidence.revision) is not int or binding_evidence.revision < 1
            or binding_evidence.key.type_name != "d03.world_event"
            or binding_evidence.key.owner.kind != "event"
            or (binding_evidence.key.owner.bot, binding_evidence.key.owner.persona)
               != namespace.as_tuple
            or account_binding.value.get("verification_ref") != binding_evidence.key.token
            or binding_evidence.value.get("kind") != "message_received"
            or binding_evidence.value.get("reality") != "host_observed"):
        raise ValueError("original D03 binding evidence differs")
    evidence_roles = binding_evidence.value.get("participant_roles")
    if (type(evidence_roles) not in (list, tuple) or len(evidence_roles) != 1
            or type(evidence_roles[0]) not in (list, tuple)
            or tuple(evidence_roles[0]) != (account_binding.value["entity_id"], "sender_account")
            or _time(binding_evidence.value.get("learned_at"))
               != _time(account_binding.value.get("valid_from"))):
        raise ValueError("original D03 binding evidence sender or time differs")
    result = _completion(namespace, slot, source, access,
                         evidence_ref=arrival.key.token, speaker_ref=record.speaker_id,
                         trusted_utc=arrival.value["learned_at"], tool_state=tool_state,
                         observation_state="host_observed")
    return TurnCompletionCandidateV1(result.write, tuple(dict.fromkeys(
                                     result.read_versions +
                                     tuple(GraphVersion(atom.key, atom.revision) for atom in
                                           (arrival, account_binding, binding_evidence)))),
                                     result.absent_completion)


@dataclass(frozen=True)
class TurnOutboundObservationCandidateV1:
    write: GraphWrite
    read_versions: tuple[GraphVersion, ...]
    expected_observation: GraphVersion | None


def _outbound_segment(batch):
    """Explicit batch-version dispatch; never relabel a paid natural batch."""
    if type(batch) is not GraphAtom or not batch.valid:
        raise ValueError("current outbound batch required")
    if batch.key.type_name == "d09.natural_verified_segment_batch.v2":
        from .natural_batch import validate_natural_verified_batch_value_v2
        from ...runtime.dispatch_candidate import natural_dispatch_segment_payload_ref_v2
        validate_natural_verified_batch_value_v2(batch.value)
        return batch.value["segment"], natural_dispatch_segment_payload_ref_v2(batch.key.token, 0)
    if batch.key.type_name == "d09.verified_segment_batch.v1":
        segments = batch.value.get("segments")
        if type(segments) is list and len(segments) == 1 and type(segments[0]) is dict:
            return segments[0], dispatch_segment_payload_ref(batch.key.token, 0)
    raise ValueError("one explicit versioned outbound segment required")


def observe_outbound_turn_v1(namespace: NamespaceId, slot: GraphAtom,
                             outbox: GraphAtom, batch: GraphAtom,
                             source: GraphAtom, access: GraphAtom,
                             observation_receipt: MutationReceiptV2, *,
                             previous: GraphAtom | None = None) -> TurnOutboundObservationCandidateV1:
    """Record accepted/unknown transport evidence, never a completed turn.

    W01 must independently read the Authority receipt and current outbox under
    its fence. A caller-supplied receipt is structurally checked but untrusted.
    """
    pending = observation_receipt.pending if type(observation_receipt) is MutationReceiptV2 else None
    observation = pending.platform_observation if pending is not None else None
    source_record = SourceRecord.from_dict(source.value)
    segment, payload_ref = _outbound_segment(batch)
    _source_guard(namespace, slot.value.get("conversation_ref"), source, access)
    if (type(outbox) is not GraphAtom or not outbox.valid
            or outbox.key.type_name != "runtime.outbox"
            or outbox.key.token != slot.value.get("origin_ref")
            or slot.value.get("direction") != "outbound"
            or type(batch) is not GraphAtom or not batch.valid
            or type(segment) is not dict
            or outbox.value.get("payload_ref") != payload_ref
            or segment.get("body") != source_record.text
            or source_record.source_kind != "authored"
            or type(observation) is not PlatformObservationV2
            or pending.phase != "observed" or observation_receipt.durable_state != "committed"
            or observation.outcome not in {"accepted", "unknown"}
            or outbox.value.get("phase") != (
                "ack" if observation.outcome == "accepted" else "unknown")
            or outbox.value.get("effect_id") != observation.binding.origin.effect_id
            or outbox.value.get("operation_id") != observation.binding.origin.operation_id
            or "/".join(namespace.as_tuple) != observation.binding.graph_namespace):
        raise ValueError("persisted D11 observation differs from outbound slot")
    key = turn_outbound_observation_key(namespace, slot.value["scene_ref"],
                                        slot.value["conversation_ref"], slot.value["sequence"])
    if previous is None:
        version, guard = 1, None
    else:
        if type(previous) is not GraphAtom or not previous.valid or previous.key != key:
            raise ValueError("previous outbound observation differs")
        validate_turn_outbound_observation_v1(previous.value)
        if previous.value["slot_ref"] != slot.key.token:
            raise ValueError("previous outbound slot differs")
        if previous.value["observation_state"] == "platform_accepted":
            raise ValueError("accepted observation cannot regress or be rewritten")
        version = previous.value["version"] + 1
        guard = GraphVersion(key, previous.revision)
    value = {"schema": OUTBOUND_OBSERVATION_TYPE,
             "scene_ref": slot.value["scene_ref"],
             "conversation_ref": slot.value["conversation_ref"],
             "sequence": slot.value["sequence"],
             "slot_ref": slot.key.token, "outbox_ref": outbox.key.token,
             "batch_ref": batch.key.token, "source_ref": source.key.token,
             "access_ref": access.key.token,
             "evidence_ref": canonical_digest(observation_receipt),
             "observation_state": "platform_accepted" if observation.outcome == "accepted" else "unknown",
             "peer_delivery_state": "unknown", "peer_read_state": "unknown",
             "version": version}
    validate_turn_outbound_observation_v1(value)
    return TurnOutboundObservationCandidateV1(
        GraphWrite(key, value, (slot.key, outbox.key, batch.key, source.key, access.key)),
        tuple(GraphVersion(atom.key, atom.revision)
              for atom in (slot, outbox, batch, source, access)), guard)


def complete_outbound_turn_v1(namespace: NamespaceId, slot: GraphAtom,
                              outbox: GraphAtom, batch: GraphAtom,
                              source: GraphAtom, access: GraphAtom,
                              delivery_receipt: MutationReceiptV2, *,
                              tool_state: str = "not_applicable") -> TurnCompletionCandidateV1:
    """Complete only independently verified D11 recipient-delivery evidence.

    An accepted adapter ACK never passes this gate. W01 must obtain the
    receipt from current Authority state and recheck the same graph versions.
    """
    pending = delivery_receipt.pending if type(delivery_receipt) is MutationReceiptV2 else None
    observation = pending.platform_observation if pending is not None else None
    record = SourceRecord.from_dict(source.value)
    segment, payload_ref = _outbound_segment(batch)
    if (type(slot) is not GraphAtom or not slot.valid
            or slot.value.get("direction") != "outbound"
            or type(outbox) is not GraphAtom or not outbox.valid
            or outbox.key.type_name != "runtime.outbox"
            or slot.value.get("origin_ref") != outbox.key.token
            or outbox.value.get("phase") != "delivered"
            or type(batch) is not GraphAtom or not batch.valid
            or type(segment) is not dict
            or outbox.value.get("payload_ref") != payload_ref
            or segment.get("body") != record.text or record.source_kind != "authored"
            or type(observation) is not PlatformObservationV2
            or pending.phase != "observed" or delivery_receipt.durable_state != "committed"
            or observation.outcome != "delivered"
            or outbox.value.get("effect_id") != observation.binding.origin.effect_id
            or outbox.value.get("operation_id") != observation.binding.origin.operation_id
            or "/".join(namespace.as_tuple) != observation.binding.graph_namespace):
        raise ValueError("actual D11 recipient delivery evidence required")
    observed_utc = datetime.fromisoformat(
        observation.observed_at_utc.replace("Z", "+00:00")).timestamp()
    result = _completion(namespace, slot, source, access,
                         evidence_ref=canonical_digest(delivery_receipt),
                         speaker_ref=record.speaker_id, trusted_utc=observed_utc,
                         tool_state=tool_state, observation_state="peer_delivered")
    return TurnCompletionCandidateV1(
        GraphWrite(result.write.key, result.write.value,
                   result.write.dependencies + (outbox.key, batch.key)),
        result.read_versions + (GraphVersion(outbox.key, outbox.revision),
                                GraphVersion(batch.key, batch.revision)),
        result.absent_completion)


@dataclass(frozen=True)
class TurnOrderProjectionV1:
    high_watermark: int
    completed: tuple[GraphAtom, ...]
    missing_ranges: tuple[tuple[int, int], ...]


def project_completed_turns_v1(namespace: NamespaceId, order: GraphAtom,
                               slots: tuple[GraphAtom, ...],
                               completions: tuple[GraphAtom, ...]) -> TurnOrderProjectionV1:
    """Project only a full W01-read sequence closure, including pending gaps."""
    if type(order) is not GraphAtom or not order.valid or order.key.type_name != ORDER_TYPE:
        raise ValueError("current D09 order head required")
    validate_turn_order_v1(order.value)
    scene, conversation = order.value["scene_ref"], order.value["conversation_ref"]
    if order.key != turn_order_key(namespace, scene, conversation):
        raise ValueError("order key differs from scope")
    if type(slots) is not tuple or type(completions) is not tuple:
        raise TypeError("full slot and completion tuples required")
    high = order.value["high_watermark"]
    indexed: dict[int, GraphAtom] = {}
    for slot in slots:
        if type(slot) is not GraphAtom or not slot.valid:
            raise ValueError("invalid turn slot")
        validate_turn_slot_v1(slot.value)
        seq = slot.value["sequence"]
        if (seq > high or seq in indexed
                or slot.key != turn_slot_key(namespace, scene, conversation, seq)
                or (slot.value["scene_ref"], slot.value["conversation_ref"]) != (scene, conversation)):
            raise ValueError("turn slot closure differs")
        indexed[seq] = slot
    if set(indexed) != set(range(high + 1)):
        raise ValueError("turn slot sequence has an unaccounted hole")
    complete: dict[int, GraphAtom] = {}
    for item in completions:
        if type(item) is not GraphAtom or not item.valid:
            raise ValueError("invalid turn completion")
        validate_turn_completion_v1(item.value)
        seq = item.value["sequence"]
        if (seq in complete or seq not in indexed
                or item.key != turn_completion_key(namespace, scene, conversation, seq)
                or item.value["slot_ref"] != indexed[seq].key.token
                or item.value["direction"] != indexed[seq].value["direction"]):
            raise ValueError("turn completion closure differs")
        complete[seq] = item
    gaps: list[tuple[int, int]] = []
    start: int | None = None
    for seq in range(high + 1):
        if seq not in complete:
            if start is None:
                start = seq
        elif start is not None:
            gaps.append((start, seq - 1))
            start = None
    if start is not None:
        gaps.append((start, high))
    return TurnOrderProjectionV1(high, tuple(complete[seq] for seq in sorted(complete)), tuple(gaps))


__all__ = ["ORDER_TYPE", "SLOT_TYPE", "COMPLETION_TYPE", "OUTBOUND_OBSERVATION_TYPE",
           "TurnReservationCandidateV1", "TurnCompletionCandidateV1",
           "TurnOutboundObservationCandidateV1", "TurnOrderProjectionV1", "turn_order_key",
           "turn_slot_key", "turn_completion_key", "turn_outbound_observation_key",
           "turn_order_type_specs_v1", "reserve_turn_slot_v1", "complete_inbound_turn_v1",
           "observe_outbound_turn_v1", "complete_outbound_turn_v1",
           "project_completed_turns_v1"]
