"""Bounded authentication of the actual installed Control event chain.

A persisted cursor is never a proof. A cold process authenticates the immutable
chain from genesis and observes its real EOF before issuing a private view.
"""
from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path

from .contract import AuthorityUnavailable
from .c09_paged_recovery_facts_v2 import C09CanonicalSqlCellReaderV2, _read_one
from .c09_storage_control_v1 import STAGES

_TOKEN = object()
_CURRENT_COLUMNS = ('installation_id', 'pointer_version', 'current_manifest_digest',
    'active_operation_id', 'stage', 'last_event_seq', 'last_event_digest',
    'deletion_watermark', 'cumulative_tombstone_root')
_EVENT_FIELDS = frozenset(('schema', 'installation_id', 'event_seq', 'operation_id',
    'stage', 'prior_event_digest', 'pointer_version', 'current_manifest_digest',
    'deletion_watermark', 'cumulative_tombstone_root', 'details', 'event_digest',
    'key_id', 'signature'))
_EVENT_SELECT = 'event_seq,operation_id,stage,prior_event_digest,event_digest,key_id,signature'
_INTENT_PATHS = tuple(('details', name) for name in ('expected_pointer_version', 'old_manifest_digest', 'namespace', 'accepted_receipt_digest'))
_INTENT_OPTIONAL_PATHS = tuple(('details', 'quiescence_original', name) for name in ('schema', 'quiescence_digest', 'writer_peer_retirement_complete_original_digest', 'writer_peer_retirement_count', 'writer_peer_retirement_root'))


def _identity(control):
    stat = Path(control.path).stat()
    return stat.st_dev, stat.st_ino


def _current_row(control, db, meter):
    row = _read_one(db, 'SELECT ' + ','.join(_CURRENT_COLUMNS) +
        ' FROM c09_storage_current_v1 WHERE installation_id=?', (control.installation_id,), meter)
    if row is None:
        raise AuthorityUnavailable('actual installed Control pointer is absent')
    return dict(zip(_CURRENT_COLUMNS, row))


class _EventReaderV2:
    def __init__(self, control, row):
        self.control, self.row = control, row
        self.detail_starts, self.detail_spans, self.intent = {}, {}, {}
        self.cell = C09CanonicalSqlCellReaderV2('c09_storage_events_v1', 'event_json',
            'installation_id=? AND event_seq=?', (control.installation_id, row[0]), ensure_ascii=False, observe=self._observe_detail)
        self.phase = 'scan'
        self.fields = None
        self.index = self.offset = 0
        self.hasher = hashlib.sha256(b'{')
        self.header = {}

    def _observe_detail(self, event):
        if self.row[2] != 'INTENT' or event.path not in (*_INTENT_PATHS, *_INTENT_OPTIONAL_PATHS):
            return
        if event.kind == 'scalar_start':
            self.detail_starts[event.path] = event.start_offset
        elif event.kind == 'scalar_end':
            self.detail_spans[event.path] = (self.detail_starts.pop(event.path), event.end_offset)

    def advance(self, db, meter):
        actual = _read_one(db, 'SELECT ' + _EVENT_SELECT +
            ' FROM c09_storage_events_v1 WHERE installation_id=? AND event_seq=?',
            (self.control.installation_id, self.row[0]), meter)
        if actual != self.row:
            raise AuthorityUnavailable('actual immutable Control event changed during its read')
        if self.phase == 'scan':
            if not self.cell.advance(db, meter):
                return None
            if {path[0] for path in self.cell.spans} != _EVENT_FIELDS:
                raise AuthorityUnavailable('actual Control event field inventory differs')
            self.fields = tuple(sorted(_EVENT_FIELDS - {'event_digest', 'signature'}))
            self.phase = 'hash'
            return None
        if self.phase == 'hash':
            if self.index < len(self.fields):
                name = self.fields[self.index]
                start, end = self.cell.spans[(name,)]
                if self.offset == 0:
                    prefix = (b',' if self.index else b'') + json.dumps(name, ensure_ascii=False).encode() + b':'
                    meter.charge_encode(len(prefix))
                    self.hasher.update(prefix)
                size = min(16384, end - start - self.offset)
                self.hasher.update(self.cell.read(db, start + self.offset, size, meter))
                self.offset += size
                if self.offset == end - start:
                    self.index += 1
                    self.offset = 0
                return None
            meter.charge_encode(1)
            self.hasher.update(b'}')
            self.phase = 'header'
            self.index = 0
            return None
        names = tuple(sorted(_EVENT_FIELDS - {'details'}))
        if self.index < len(names):
            name = names[self.index]
            start, end = self.cell.spans[(name,)]
            meter.require_available((end - start) * 7)
            self.header[name] = self.cell.value(db, (name,), meter)
            self.index += 1
            return None
        paths = (*_INTENT_PATHS, *(path for path in _INTENT_OPTIONAL_PATHS if path in self.detail_spans))
        if self.row[2] == 'INTENT' and len(self.intent) < len(paths):
            path = paths[len(self.intent)]
            if path not in self.detail_spans:
                raise AuthorityUnavailable('actual signed INTENT omits its selected-source fields')
            start, end = self.detail_spans[path]
            meter.require_available((end - start) * 8)
            self.intent[path[-1]] = json.loads(self.cell.read(db, start, end - start, meter))
            return None
        header = self.header
        if (header['schema'] != 'sylanne3.c09.storage_event.v1'
                or header['installation_id'] != self.control.installation_id
                or tuple(header[name] for name in ('event_seq', 'operation_id', 'stage',
                    'prior_event_digest', 'event_digest', 'key_id', 'signature')) != self.row
                or header['key_id'] != self.control.key_id
                or header['event_digest'] != self.hasher.hexdigest()):
            raise AuthorityUnavailable('streamed installed Control event digest or identity differs')
        expected = hmac.new(self.control._key,
            (header['schema'] + '\n' + header['event_digest']).encode(), 'sha256').hexdigest()
        if not hmac.compare_digest(expected, header['signature']):
            raise AuthorityUnavailable('streamed installed Control event HMAC differs')
        if self.row[2] == 'INTENT':
            header['_maintenance_intent'] = dict(self.intent)
        return header


class VerifiedC09ControlChainV2:
    """Private runtime proof of a complete signed chain and its exact materialization."""
    __slots__ = ('_issuer', 'control', 'identity', 'current', 'state')

    def __init__(self, token, reader, current):
        if token is not _TOKEN or reader.event is not None:
            raise AuthorityUnavailable('actual complete Control chain issuer required')
        self._issuer, self.control = token, reader.control
        self.identity, self.current, self.state = reader.identity, dict(current), dict(reader.state)

    def require_current(self, db, meter):
        if self._issuer is not _TOKEN or _identity(self.control) != self.identity:
            raise AuthorityUnavailable('authenticated Control file identity changed')
        current = _current_row(self.control, db, meter)
        tail = _read_one(db, 'SELECT event_seq,event_digest FROM c09_storage_events_v1 '
            'WHERE installation_id=? ORDER BY event_seq DESC LIMIT 1', (self.control.installation_id,), meter)
        expected = None if self.current['last_event_seq'] == 0 else (
            self.current['last_event_seq'], self.current['last_event_digest'])
        if current != self.current or tail != expected:
            raise AuthorityUnavailable('authenticated Control tail or current selection changed')
        return dict(current)

    def observe_committed_event(self, original):
        state = _advance_state(self.state, original)
        self.state = state
        self.current = dict(installation_id=self.control.installation_id,
            pointer_version=state['pointer'], current_manifest_digest=state['selected'],
            active_operation_id=state['active'], stage=state['stage'],
            last_event_seq=state['last'], last_event_digest=state['prior'],
            deletion_watermark=state['water'], cumulative_tombstone_root=state['tomb'])


def _advance_state(state, header):
    if header['event_seq'] != state['last'] + 1 or header['prior_event_digest'] != state['prior']:
        raise AuthorityUnavailable('installed Control event chain has a gap or altered predecessor')
    stage = header['stage']
    active = state['active']
    if stage == 'INTENT':
        if state['stage'] not in {'READY', 'RELEASED'}:
            raise AuthorityUnavailable('installed Control INTENT transition differs')
        active = header['operation_id']
        intent = header.get('_maintenance_intent')
        if intent is None:
            details = header['details']
            intent = {path[1]: details[path[1]] for path in _INTENT_PATHS}
            quiescence = details.get('quiescence_original', {})
            intent.update({path[-1]: quiescence[path[-1]] for path in _INTENT_OPTIONAL_PATHS if path[-1] in quiescence})
        if (intent['expected_pointer_version'] != header['pointer_version']
                or intent['old_manifest_digest'] != header['current_manifest_digest']
                or type(intent['namespace']) is not str or not intent['namespace']
                or type(intent['accepted_receipt_digest']) is not str or len(intent['accepted_receipt_digest']) != 64):
            raise AuthorityUnavailable('actual signed INTENT selected-source relation differs')
    else:
        intent = state.get('maintenance_intent')
    if stage != 'INTENT' and (stage not in STAGES or header['operation_id'] != active
            or state['stage'] not in STAGES or STAGES.index(stage) != STAGES.index(state['stage']) + 1):
        raise AuthorityUnavailable('installed Control stage transition differs')
    pointer = state['pointer'] + (stage == 'SWITCHED')
    if (header['pointer_version'] != pointer
            or state['selected'] is not None and stage != 'SWITCHED'
                and header['current_manifest_digest'] != state['selected']):
        raise AuthorityUnavailable('installed Control pointer did not change atomically')
    if state['water'] is not None and header['deletion_watermark'] < state['water']:
        raise AuthorityUnavailable('installed Control deletion watermark regressed')
    return dict(prior=header['event_digest'], last=header['event_seq'], pointer=pointer,
        selected=header['current_manifest_digest'], active=active, stage=stage,
        water=header['deletion_watermark'], tomb=header['cumulative_tombstone_root'], maintenance_intent=intent)


class InstalledC09ControlChainReaderV2:
    def __init__(self, control):
        from .c09_storage_control_v1 import C09StorageControlV1, InstalledC09StorageReaderV1
        if type(control) not in {C09StorageControlV1, InstalledC09StorageReaderV1}:
            raise AuthorityUnavailable('actual installed Control composition required')
        control.lease.require_held()
        self.control, self.identity = control, _identity(control)
        self.state = dict(prior='genesis', last=0, pointer=0, selected=None,
            active=None, stage='READY', water=None, tomb=None)
        self.event = None
        self.result = None
        self.schema_verified = False

    def advance(self, db, meter):
        if _identity(self.control) != self.identity:
            raise AuthorityUnavailable('actual installed Control inode changed during chain read')
        if self.result is not None:
            self.result.require_current(db, meter)
            return self.result
        if not self.schema_verified:
            from .c09_paged_recovery_facts_v2 import _BoundedReadConnectionV2
            self.control._validate(_BoundedReadConnectionV2(db, meter))
            self.schema_verified = True
            return None
        if self.event is not None:
            header = self.event.advance(db, meter)
            if header is None:
                return None
            self.state = _advance_state(self.state, header)
            self.event = None
            return None
        row = _read_one(db, 'SELECT ' + _EVENT_SELECT + ' FROM c09_storage_events_v1 '
            'WHERE installation_id=? AND event_seq>? ORDER BY event_seq LIMIT 1',
            (self.control.installation_id, self.state['last']), meter)
        if row is not None:
            self.event = _EventReaderV2(self.control, row)
            return None
        current = _current_row(self.control, db, meter)
        state = self.state
        if ((state['last'], state['prior'], state['pointer'], state['stage']) !=
                (current['last_event_seq'], current['last_event_digest'], current['pointer_version'], current['stage'])
                or state['last'] and (state['selected'], state['active'], state['water'], state['tomb']) !=
                    (current['current_manifest_digest'], current['active_operation_id'],
                     current['deletion_watermark'], current['cumulative_tombstone_root'])):
            raise AuthorityUnavailable('complete installed Control chain differs from its actual materialization')
        self.result = VerifiedC09ControlChainV2(_TOKEN, self, current)
        self.result.require_current(db, meter)
        return self.result
