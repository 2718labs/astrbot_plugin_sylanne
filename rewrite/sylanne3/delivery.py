"""Local delivery protocol. No platform/network adapter is provided."""
from __future__ import annotations

import asyncio
from dataclasses import asdict, dataclass
import json
from typing import Protocol

from .contracts import Candidate, Event, Scope, Write
from .store import StaleRead


@dataclass(frozen=True)
class ActionContract:
    action_id: str
    source_event_id: str
    scope: Scope
    interpretation_ids: tuple[str, ...]
    reaction: tuple[float, float]
    error_bound: float
    expression: str
    observed_at: float
    reaction_revision: int
    interpretations_revision: int

    def to_dict(self):
        return json.loads(json.dumps(asdict(self), allow_nan=False))

    @classmethod
    def from_dict(cls, value):
        data = dict(value)
        data['scope'] = Scope(**data['scope'])
        data['reaction'] = tuple(data['reaction'])
        data['interpretation_ids'] = tuple(data['interpretation_ids'])
        return cls(**data)


class DeliveryFailed(Exception):
    """Transport guarantees that the action was NOT externally accepted."""


class Transport(Protocol):
    async def send(self, action: ActionContract) -> None: ...


class RecordingTransport:
    """In-memory test/demo sink; these records are not real sent messages."""
    def __init__(self):
        self.sent: list[ActionContract] = []

    async def send(self, action):
        self.sent.append(action)


async def _transition(store, action, expected, target, detail=''):
    """CAS lifecycle updates; no external side effect occurs inside the transaction."""
    claiming = expected == 'pending' and target == 'sending'
    names = ('reaction', 'interpretations', 'actions', 'outbox') if claiming else ('actions', 'outbox')
    for _ in range(64):
        actual_target = target
        snapshot = await asyncio.to_thread(store.snapshot, action.scope, names)
        actions = snapshot.get('actions').value
        outbox = snapshot.get('outbox').value
        current = outbox.get('items', {}).get(action.action_id)
        if current is None or current['status'] != expected:
            return False
        if actions['items'][action.action_id]['contract'] != action.to_dict():
            return False
        if claiming:
            reaction = snapshot.get('reaction').value
            source = snapshot.get('interpretations').value.get('events', {}).get(action.source_event_id)
            if (reaction.get('source_event_id') != action.source_event_id or not source
                    or source['action_id'] != action.action_id
                    or snapshot.get('reaction').revision != action.reaction_revision
                    or snapshot.get('interpretations').revision != action.interpretations_revision):
                actual_target = 'superseded'
                detail = 'newer certified state superseded pending action before claim'
        current['status'] = actual_target
        current['detail'] = detail
        actions['items'][action.action_id]['delivery_status'] = actual_target
        event = Event(action.scope, '__delivery__:' + action.action_id + ':' + actual_target,
                      action.observed_at, '_delivery_' + actual_target,
                      {'action_id': action.action_id, 'status': actual_target, 'detail': detail})
        try:
            receipt = await asyncio.to_thread(store.commit, Candidate(event, snapshot.versions,
                (Write('actions', actions), Write('outbox', outbox))))
            return receipt.status == 'committed' and actual_target == target
        except StaleRead:
            continue
    raise RuntimeError('delivery settlement contention; claimed actions must not be retried')


async def _finish(task):
    """Own and join a finite lifecycle task despite repeated caller cancellation."""
    cancellation = None
    while True:
        try:
            return await asyncio.shield(task), cancellation
        except asyncio.CancelledError as exc:
            if task.cancelled():
                raise
            cancellation = exc


async def dispatch(store, transport, action):
    # SQLite offloads cannot be cancelled once their threads enter commit. Own
    # the claim until its result is known before reacting to caller cancellation.
    claimed, cancellation = await _finish(asyncio.create_task(
        _transition(store, action, 'pending', 'sending')))
    if cancellation is not None:
        if claimed:
            await _finish(asyncio.create_task(_transition(
                store, action, 'sending', 'failed', 'cancelled_before_send')))
        raise cancellation
    if not claimed:
        return 'not_claimed'
    try:
        await transport.send(action)
    except asyncio.CancelledError:
        await _finish(asyncio.create_task(_transition(
            store, action, 'sending', 'unknown', 'send cancelled; acceptance unknown')))
        raise
    except DeliveryFailed as exc:
        status, detail = 'failed', str(exc)
    except Exception as exc:
        status, detail = 'unknown', type(exc).__name__ + ': ' + str(exc)
    else:
        status, detail = 'delivered', 'transport returned acceptance'
    # Settle a known result completely; keep a strong task reference and join it
    # even if the caller cancels more than once while SQLite is finishing.
    _, cancellation = await _finish(asyncio.create_task(
        _transition(store, action, 'sending', status, detail)))
    if cancellation is not None:
        raise cancellation
    return status


def action_id(event):
    return event.digest
