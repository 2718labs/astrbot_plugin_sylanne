"""Bounded typed semantic fixture with causal replay; semantics are not calibrated."""
from __future__ import annotations

import asyncio
from dataclasses import dataclass
import math

from .contracts import Candidate, Event, Write
from .store import EventConflict, StaleRead
from .delivery import ActionContract, _finish, action_id, dispatch

ATOM_NAMES = ('reaction', 'interpretations', 'actions', 'outbox')
TOTAL_TOLERANCE = 1e-8
MAX_EVIDENCE = 256


class SemanticConflict(ValueError):
    pass


@dataclass(frozen=True)
class TurnResult:
    status: str
    reaction: tuple[float, float] | None = None
    action: ActionContract | None = None
    delivery_status: str | None = None


def _number(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise SemanticConflict('expected finite numeric value')
    return float(value)


def expression(state, error_bound):
    """Read only certified reaction, using a conservative threshold branch."""
    x = state[0]
    if x - error_bound > 0.5:
        return 'engage'
    if x + error_bound < -0.5:
        return 'withdraw'
    if x - error_bound >= -0.5 and x + error_bound <= 0.5:
        return 'neutral'
    return 'uncertain'


class Engine:
    def __init__(self, store, scheduler, kernel, transport):
        self.store, self.scheduler, self.kernel, self.transport = store, scheduler, kernel, transport

    async def handle(self, event):
        prepared = await self.prepare(event)
        if prepared.status != 'committed':
            return prepared
        status = await dispatch(self.store, self.transport, prepared.action)
        return TurnResult('committed', prepared.reaction, prepared.action, status)

    async def prepare(self, event):
        """Commit the complete dependency chain; dispatch is a separate observation."""
        if event.kind not in ('interpretation', 'correction') or event.event_id.startswith('__delivery__:'):
            raise SemanticConflict('unsupported event kind or reserved event ID')
        now = _number(event.occurred_at)
        if now < 0:
            raise SemanticConflict('negative physical time')
        # Detach input before the first yield: callers cannot mutate a job in flight.
        import json
        event = Event(event.scope, event.event_id, now, event.kind,
                      json.loads(json.dumps(event.payload, allow_nan=False)))
        snapshot, cancellation = await _finish(asyncio.create_task(
            asyncio.to_thread(self.store.snapshot, event.scope, ATOM_NAMES)))
        if cancellation is not None:
            raise cancellation
        ledger = snapshot.get('interpretations').value or {'items': {}, 'events': {}, 'timepoints': [0.]}
        previous = snapshot.get('reaction').value or {'time': 0.}
        actions = snapshot.get('actions').value or {'items': {}}
        outbox = snapshot.get('outbox').value or {'items': {}}
        if event.event_id in ledger['events']:
            old = ledger['events'][event.event_id]
            if old['digest'] != event.digest:
                raise EventConflict('event ID reused with different content')
            contract = ActionContract.from_dict(actions['items'][old['action_id']]['contract'])
            return TurnResult('duplicate', contract.reaction, contract,
                              actions['items'][old['action_id']]['delivery_status'])
        if now < previous['time']:
            raise SemanticConflict('events must not move current physical time backwards')
        payload = event.payload
        if event.kind == 'interpretation':
            if set(payload) != {'interpretation_id', 'subject', 'proposition', 'drive', 'start_at'}:
                raise SemanticConflict('interpretation fields do not match typed fixture')
            iid = payload['interpretation_id']
            if not isinstance(iid, str) or not iid or iid in ledger['items']:
                raise SemanticConflict('interpretation ID must be new and nonempty')
            expected_scope = {'bot': event.scope.bot, 'persona': event.scope.persona, 'session': event.scope.session}
            if payload['subject'] != expected_scope:
                raise SemanticConflict('interpretation subject must match exact event scope')
            if not isinstance(payload['proposition'], str) or not payload['proposition'].strip():
                raise SemanticConflict('complete proposition is required')
            if not isinstance(payload['drive'], (list, tuple)) or len(payload['drive']) != 2:
                raise SemanticConflict('fixture requires two-component drive')
            drive = [_number(v) for v in payload['drive']]
            if max(abs(v) for v in drive) > 1000:
                raise SemanticConflict('fixture drive exceeds bounded range')
            start = _number(payload['start_at'])
            if not 0 <= start < now:
                raise SemanticConflict('require 0 <= start_at < occurred_at')
            if len(ledger['items']) >= MAX_EVIDENCE:
                raise SemanticConflict('bounded fixture evidence capacity exceeded')
            ledger['items'][iid] = {'source_event_id': event.event_id, 'subject': expected_scope,
                'proposition': payload['proposition'], 'drive': drive, 'start': start, 'end': now, 'valid': True}
            ledger['timepoints'].extend([start, now])
        else:
            if set(payload) != {'target_interpretation_id'}:
                raise SemanticConflict('correction requires exactly target_interpretation_id')
            target = payload['target_interpretation_id']
            if not isinstance(target, str) or target not in ledger['items']:
                raise SemanticConflict('correction target is absent in this exact scope')
            if not ledger['items'][target]['valid']:
                raise SemanticConflict('interpretation is already invalid')
            ledger['items'][target]['valid'] = False
            ledger['items'][target]['invalidated_by'] = event.event_id
        # Keep all observed endpoints, including prior correction times. Invalidation
        # changes drives, never the historical BE integration partition.
        ledger['timepoints'] = sorted(set(ledger['timepoints'] + [now]))
        points = ledger['timepoints']
        state = (0., 0.)
        accumulated_bound = 0.
        steps = max(1, len(points) - 1)
        for start, end in zip(points, points[1:]):
            drive = [0., 0.]
            for item in ledger['items'].values():
                if item['valid'] and item['start'] <= start and item['end'] >= end:
                    drive = [drive[j] + item['drive'][j] for j in range(2)]
            job = self.kernel.job(mass=(1., 1.), recovery=(1., 1.), edges=((0., .25), (.25, 0.)),
                                  previous=state, drive=drive, dt=end-start,
                                  tolerance=TOTAL_TOLERANCE / steps)
            result = await self.scheduler.run(event.scope, job)
            state = tuple(result.solution)
            accumulated_bound += result.error_bound
        if accumulated_bound > TOTAL_TOLERANCE:
            raise RuntimeError('replay failed cumulative error certificate')
        valid_ids = tuple(sorted(i for i, v in ledger['items'].items() if v['valid']))
        action = ActionContract(action_id(event), event.event_id, event.scope, valid_ids, state,
                                accumulated_bound, expression(state, accumulated_bound), now,
                                snapshot.get('reaction').revision + 1, snapshot.get('interpretations').revision + 1)
        ledger['events'][event.event_id] = {'digest': event.digest, 'action_id': action.action_id}
        actions['items'][action.action_id] = {'contract': action.to_dict(), 'delivery_status': 'pending'}
        outbox['items'][action.action_id] = {'status': 'pending', 'source_event_id': event.event_id, 'detail': ''}
        reaction = {'time': now, 'state': list(state), 'error_bound': accumulated_bound,
                    'interpretation_ids': list(valid_ids), 'source_event_id': event.event_id,
                    'model': 'uncalibrated-two-component-episode-fixture', 'segments': steps}
        candidate = Candidate(event, snapshot.versions, (Write('reaction', reaction), Write('interpretations', ledger),
                              Write('actions', actions), Write('outbox', outbox)))
        async def commit():
            try:
                return await asyncio.to_thread(self.store.commit, candidate), False
            except StaleRead:
                return None, True

        (receipt, stale), cancellation = await _finish(asyncio.create_task(commit()))
        if cancellation is not None:
            raise cancellation
        if stale:
            return TurnResult('stale')
        if receipt.status == 'duplicate':
            return TurnResult('duplicate', state, action)
        return TurnResult('committed', state, action, 'pending')
