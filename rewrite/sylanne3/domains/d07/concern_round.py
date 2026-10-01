"""Versioned D07 concern-round candidates for bounded, recoverable service.

This module neither commits graph writes nor settles D02/D11 costs. W01 must
authenticate tickets, effect receipts, and the current round revision before
adopting a transition. Calling a planner never creates character experience.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import math

from ...graph_types import AtomKey, GraphSnapshot, GraphVersion, GraphWrite, Owner, TypeSpec
from ...runtime_contracts import NamespaceId, canonical_digest, schema_hash
from . import AttentionPolicy, AttentionTicket, D07DomainProvider


SCHEMA = "d07.concern_round.v1"
MAX_GROUPS = 64
MAX_SEGMENTS_PER_GROUP = 2


class ConcernRoundHold(ValueError):
    """A round cannot safely consume or adopt the proposed service."""


def _group(ticket: AttentionTicket) -> str:
    return ticket.concern_ref or ticket.causal_root


def _valid(ticket: AttentionTicket, *, now: float, category: str) -> bool:
    return (ticket.category == category and ticket.eligible
            and ticket.resources_available and not ticket.cancel_refs
            and ticket.valid_until > now)


@dataclass(frozen=True, slots=True)
class ConcernRoundV1:
    persona_id: str
    category: str
    revision: int
    round_id: int
    groups: tuple[str, ...]
    served: tuple[tuple[str, int], ...]
    parked: tuple[tuple[str, float], ...]
    consumed_effect_ids: tuple[str, ...]
    schema: str = SCHEMA

    def __post_init__(self) -> None:
        if (self.schema != SCHEMA or not self.persona_id
                or self.category not in {"required", "interaction", "background"}
                or type(self.revision) is not int or self.revision < 0
                or type(self.round_id) is not int or self.round_id < 0
                or type(self.groups) is not tuple or len(self.groups) > MAX_GROUPS
                or len(set(self.groups)) != len(self.groups)
                or any(type(group) is not str or not group for group in self.groups)):
            raise ConcernRoundHold("concern round identity or groups are invalid")
        counts = dict(self.served)
        parking = dict(self.parked)
        if (len(counts) != len(self.served) or len(parking) != len(self.parked)
                or len(parking) > MAX_GROUPS
                or not set(counts) <= set(self.groups)
                or any(type(count) is not int or not 0 <= count <= MAX_SEGMENTS_PER_GROUP
                       for count in counts.values())
                or sum(counts.values()) != len(self.consumed_effect_ids)
                or any(type(group) is not str or not group for group in parking)
                or any(type(until) not in (int, float) or not math.isfinite(until)
                       for until in parking.values())
                or len(self.consumed_effect_ids) > MAX_GROUPS * MAX_SEGMENTS_PER_GROUP
                or len(set(self.consumed_effect_ids)) != len(self.consumed_effect_ids)
                or any(type(effect) is not str or not effect
                       for effect in self.consumed_effect_ids)):
            raise ConcernRoundHold("concern round service ledger is invalid")


@dataclass(frozen=True, slots=True)
class ConcernServiceChoiceV1:
    expected_revision: int
    round_id: int
    group_id: str
    ticket_id: str
    ticket_valid_until: float
    focus_epoch: int
    ticket_inventory_digest: str
    choice_digest: str
    status: str = "candidate_requires_w01_admission"


@dataclass(frozen=True, slots=True)
class ConcernRoundTransitionV1:
    expected_revision: int
    next_round: ConcernRoundV1
    effect_id: str | None
    status: str
    receipt_ref: str | None = None
    choice_digest: str | None = None


def concern_round_key(namespace: NamespaceId, category: str) -> AtomKey:
    if type(namespace) is not NamespaceId or category not in {
            "required", "interaction", "background"}:
        raise ConcernRoundHold("concern round graph identity is invalid")
    return AtomKey(Owner("persona", *namespace.as_tuple), SCHEMA, category)


def decode_concern_round(value: object) -> ConcernRoundV1:
    if (type(value) is not dict
            or set(value) != set(ConcernRoundV1.__dataclass_fields__)):
        raise ConcernRoundHold("concern round graph fields differ from v1 schema")
    return ConcernRoundV1(**{
        **value,
        "groups": tuple(value["groups"]),
        "served": tuple(tuple(item) for item in value["served"]),
        "parked": tuple(tuple(item) for item in value["parked"]),
        "consumed_effect_ids": tuple(value["consumed_effect_ids"]),
    })


def concern_round_type_spec() -> TypeSpec:
    return TypeSpec(
        SCHEMA, ("persona",), "state", decode_concern_round,
        writer_domain="d07", schema_hash=schema_hash({
            "type": SCHEMA, "fields": tuple(ConcernRoundV1.__dataclass_fields__),
            "max_groups": MAX_GROUPS, "max_segments_per_group": MAX_SEGMENTS_PER_GROUP,
        }),
    )


def concern_round_write(namespace: NamespaceId,
                        state: ConcernRoundV1) -> GraphWrite:
    if type(state) is not ConcernRoundV1 or state.persona_id != namespace.persona_id:
        raise ConcernRoundHold("concern round write crosses persona")
    value = asdict(state)
    for field in ("groups", "consumed_effect_ids"):
        value[field] = list(value[field])
    for field in ("served", "parked"):
        value[field] = [list(item) for item in value[field]]
    return GraphWrite(concern_round_key(namespace, state.category), value)


def read_concern_round(snapshot: GraphSnapshot, namespace: NamespaceId,
                       category: str) -> tuple[ConcernRoundV1, GraphVersion] | None:
    """Decode one supplied graph atom; W01 still proves currentness."""
    if type(snapshot) is not GraphSnapshot:
        raise TypeError("concern round read needs GraphSnapshot")
    if (len(snapshot.epochs) != 1
            or (snapshot.epochs[0].bot, snapshot.epochs[0].persona) != namespace.as_tuple
            or len({atom.key for atom in snapshot.atoms}) != len(snapshot.atoms)
            or any((atom.key.owner.bot, atom.key.owner.persona) != namespace.as_tuple
                   for atom in snapshot.atoms)):
        raise ConcernRoundHold("concern round graph snapshot scope differs")
    key = concern_round_key(namespace, category)
    atom = snapshot.get(key)
    if atom is None or not atom.valid or atom.revision < 1:
        return None
    state = decode_concern_round(atom.value)
    if (state.persona_id != namespace.persona_id or state.category != category
            or state.revision != atom.revision):
        raise ConcernRoundHold("concern round graph revision or identity differs")
    return state, GraphVersion(key, atom.revision)


def begin_concern_round(
    current: ConcernRoundV1, tickets: tuple[AttentionTicket, ...], *, now: float,
) -> ConcernRoundTransitionV1:
    """Freeze only runnable groups after the previous round is exhausted."""
    if type(current) is not ConcernRoundV1 or type(tickets) is not tuple:
        raise TypeError("concern round needs typed state and tickets")
    if (any(type(ticket) is not AttentionTicket for ticket in tickets)
            or len({ticket.ticket_id for ticket in tickets}) != len(tickets)):
        raise ConcernRoundHold("concern round ticket inventory is malformed")
    if type(now) not in (int, float) or not math.isfinite(now):
        raise ConcernRoundHold("round time must be finite")
    served, parked = dict(current.served), dict(current.parked)
    if any(group not in parked and served.get(group, 0) < MAX_SEGMENTS_PER_GROUP
           for group in current.groups):
        raise ConcernRoundHold("previous round still has an unserved group")
    runnable = tuple(ticket for ticket in tickets
                     if _valid(ticket, now=now, category=current.category)
                     and now >= parked.get(_group(ticket), -math.inf))
    groups = tuple(sorted({_group(ticket) for ticket in runnable}))
    if not groups:
        return ConcernRoundTransitionV1(current.revision, current, None,
                                        "waiting_without_fabricated_round")
    if len(groups) > MAX_GROUPS:
        raise ConcernRoundHold("runnable concern groups exceed bounded round")
    next_round = ConcernRoundV1(
        current.persona_id, current.category, current.revision + 1,
        current.round_id + 1, groups, (),
        tuple(sorted((group, until) for group, until in parked.items()
                     if until > now)), (),
    )
    return ConcernRoundTransitionV1(current.revision, next_round, None,
                                    "new_round_candidate")


def choose_concern_segment(
    state: ConcernRoundV1, tickets: tuple[AttentionTicket, ...],
    policy: AttentionPolicy, *, now: float, focus_epoch: int,
) -> ConcernServiceChoiceV1 | None:
    """Choose an unserved group first; selection itself consumes nothing."""
    if (type(state) is not ConcernRoundV1 or type(tickets) is not tuple
            or type(policy) is not AttentionPolicy
            or type(focus_epoch) is not int or focus_epoch < 0
            or type(now) not in (int, float) or not math.isfinite(now)):
        raise ConcernRoundHold("concern selection needs a valid round and focus epoch")
    if len({ticket.ticket_id for ticket in tickets}) != len(tickets):
        raise ConcernRoundHold("duplicate concern ticket identity")
    served, parked = dict(state.served), dict(state.parked)
    ranked = D07DomainProvider.rank_attention(tickets, policy, now=now)
    choices = [entry.ticket for entry in ranked
               if _valid(entry.ticket, now=now, category=state.category)
               and _group(entry.ticket) in state.groups
               and _group(entry.ticket) not in parked
               and served.get(_group(entry.ticket), 0) < MAX_SEGMENTS_PER_GROUP]
    if not choices:
        return None
    least_served = min(served.get(_group(ticket), 0) for ticket in choices)
    ticket = next(ticket for ticket in choices
                  if served.get(_group(ticket), 0) == least_served)
    group = _group(ticket)
    inventory_digest = canonical_digest(tuple(sorted(
        (item.ticket_id, asdict(item)) for item in tickets
    )))
    digest = canonical_digest({
        "schema": "d07.concern_service_choice.v1", "persona": state.persona_id,
        "category": state.category, "revision": state.revision,
        "round": state.round_id, "group": group, "ticket": ticket.ticket_id,
        "valid_until": ticket.valid_until, "focus_epoch": focus_epoch,
        "ticket_inventory": inventory_digest,
    })
    return ConcernServiceChoiceV1(
        state.revision, state.round_id, group, ticket.ticket_id,
        ticket.valid_until, focus_epoch, inventory_digest, digest,
    )


def park_concern_group(
    state: ConcernRoundV1, *, group_id: str, until: float,
) -> ConcernRoundTransitionV1:
    """Remove a paused/expired group from this round; it can join the next."""
    if (type(state) is not ConcernRoundV1 or group_id not in state.groups
            or type(until) not in (int, float) or not math.isfinite(until)):
        raise ConcernRoundHold("parked concern group or cooldown is invalid")
    parked = dict(state.parked)
    if group_id in parked and parked[group_id] >= until:
        return ConcernRoundTransitionV1(state.revision, state, None,
                                        "already_parked")
    parked[group_id] = float(until)
    next_round = ConcernRoundV1(
        state.persona_id, state.category, state.revision + 1, state.round_id,
        state.groups, state.served, tuple(sorted(parked.items())),
        state.consumed_effect_ids,
    )
    return ConcernRoundTransitionV1(state.revision, next_round, None,
                                    "park_candidate")


def settle_concern_segment(
    state: ConcernRoundV1, choice: ConcernServiceChoiceV1,
    tickets: tuple[AttentionTicket, ...], policy: AttentionPolicy,
    *, effect_id: str, receipt_ref: str,
    now: float, focus_epoch: int,
    previously_committed_effect_ids: tuple[str, ...],
) -> ConcernRoundTransitionV1:
    """Prepare one service increment after a real receipt; W01 verifies it."""
    if (type(state) is not ConcernRoundV1
            or type(choice) is not ConcernServiceChoiceV1
            or type(tickets) is not tuple
            or type(policy) is not AttentionPolicy
            or type(effect_id) is not str or not effect_id
            or type(receipt_ref) is not str or not receipt_ref
            or type(previously_committed_effect_ids) is not tuple
            or any(type(item) is not str or not item
                   for item in previously_committed_effect_ids)
            or type(now) not in (int, float) or not math.isfinite(now)
            or type(focus_epoch) is not int or focus_epoch < 0):
        raise ConcernRoundHold("service receipt inputs are invalid")
    if effect_id in state.consumed_effect_ids:
        return ConcernRoundTransitionV1(state.revision, state, effect_id,
                                        "already_recorded", receipt_ref,
                                        choice.choice_digest)
    if effect_id in previously_committed_effect_ids:
        return ConcernRoundTransitionV1(state.revision, state, effect_id,
                                        "receipt_exists_requires_reconciliation",
                                        receipt_ref, choice.choice_digest)
    ticket = next((item for item in tickets if item.ticket_id == choice.ticket_id), None)
    if (choice.expected_revision != state.revision
            or choice.round_id != state.round_id
            or choice.focus_epoch != focus_epoch
            or ticket is None
            or choice.group_id != _group(ticket)
            or choice.ticket_valid_until != ticket.valid_until
            or not _valid(ticket, now=now, category=state.category)
            or choice.group_id in dict(state.parked)
            or choice.group_id not in state.groups):
        raise ConcernRoundHold("service choice is stale, paused or expired")
    expected = canonical_digest({
        "schema": "d07.concern_service_choice.v1", "persona": state.persona_id,
        "category": state.category, "revision": state.revision,
        "round": state.round_id, "group": choice.group_id,
        "ticket": choice.ticket_id, "valid_until": ticket.valid_until,
        "focus_epoch": focus_epoch,
        "ticket_inventory": choice.ticket_inventory_digest,
    })
    if (choice.choice_digest != expected
            or choose_concern_segment(
                state, tickets, policy, now=now, focus_epoch=focus_epoch,
            ) != choice):
        raise ConcernRoundHold("service choice digest differs")
    counts = dict(state.served)
    if counts.get(choice.group_id, 0) >= MAX_SEGMENTS_PER_GROUP:
        raise ConcernRoundHold("concern group exhausted its round quota")
    counts[choice.group_id] = counts.get(choice.group_id, 0) + 1
    next_round = ConcernRoundV1(
        state.persona_id, state.category, state.revision + 1, state.round_id,
        state.groups, tuple(sorted(counts.items())), state.parked,
        state.consumed_effect_ids + (effect_id,),
    )
    return ConcernRoundTransitionV1(state.revision, next_round, effect_id,
                                    "service_candidate_requires_receipt_verification",
                                    receipt_ref, choice.choice_digest)


__all__ = ["ConcernRoundHold", "ConcernRoundV1", "ConcernServiceChoiceV1",
           "ConcernRoundTransitionV1", "begin_concern_round",
           "choose_concern_segment", "park_concern_group", "settle_concern_segment",
           "concern_round_key", "concern_round_type_spec", "concern_round_write",
           "decode_concern_round", "read_concern_round"]
