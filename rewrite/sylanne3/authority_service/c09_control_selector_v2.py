"""Independent, leased V1 -> V2 selector and durable retirement transaction.

This is a protected installation primitive, not business admission or a V1
fallback. Only the first conversion is supported; unfinished work is HOLD.
All deletion authority is derived from the installed Control path and the
independently authenticated complete history, never a caller's inventory.
"""
from contextlib import contextmanager
import hashlib
import hmac
import json
import os
from pathlib import Path
import stat

from ..runtime_contracts import canonical_digest, canonical_serialize
from .contract import AuthorityUnavailable
from .c09_storage_control_v1 import C09StorageControlV1, _regular_path, _directory_path
from .c09_control_inventory_export_v2 import capture_control_inventory_export_v2
from .c09_durable_unlink_v2 import unlink_inventory_member_durably_v2
from .c09_process_identity_v1 import require_process_retired_v1

SELECTOR_SCHEMA = 'sylanne3.c09.control-selector.v2'
JOURNAL_SCHEMA = 'sylanne3.c09.control-selector-event.v2'
STAGES = ('INTENT', 'SWITCHED', 'DISPOSED')
COMPANIONS = ('', '-wal', '-shm', '-journal')
MAX_BYTES = 64 * 1024 * 1024
OBSERVATION_FIELDS = {'resolved_path', 'device', 'file_id', 'prepared_size',
                      'prepared_mtime_ns', 'prepared_sha256'}
SELECTOR_FIELDS = {'schema', 'identity', 'selector_path', 'journal_identity',
    'generation', 'prior_selector_digest', 'candidate', 'candidate_path', 'source_inventory_digest',
    'history_digest', 'selector_digest', 'signature'}
EVENT_FIELDS = {'schema', 'identity', 'seq', 'stage', 'previous_event_digest',
    'selector', 'selector_observation', 'old_control_files', 'event_digest', 'signature'}


def _fail(message):
    raise AuthorityUnavailable('C09 V2 selector ' + message + '; HOLD')


def _observe(path):
    """Observe one unaliased regular named inode through a stable handle."""
    path = _regular_path(path)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            _fail('requires an unaliased regular inode')
        digest = hashlib.sha256()
        while block := os.read(fd, 1024 * 1024):
            digest.update(block)
        after = os.fstat(fd)
        named = os.stat(path, follow_symlinks=False)
        fields = ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns', 'st_ctime_ns', 'st_nlink')
        if (any(getattr(before, k) != getattr(after, k) for k in fields)
                or (named.st_dev, named.st_ino) != (after.st_dev, after.st_ino)):
            _fail('named inode changed')
        return dict(resolved_path=str(path), device=after.st_dev, file_id=after.st_ino,
            prepared_size=after.st_size, prepared_mtime_ns=after.st_mtime_ns,
            prepared_sha256=digest.hexdigest())
    finally:
        os.close(fd)


def _identity(observation):
    return {k: observation[k] for k in ('resolved_path', 'device', 'file_id')}


def _read_json(path):
    before = _observe(path)
    if before['prepared_size'] > MAX_BYTES:
        _fail('document exceeds bound')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, 'rb') as stream:
        encoded = stream.read(MAX_BYTES + 1)
    if _observe(path) != before:
        _fail('document changed during read')
    try:
        value = json.loads(encoded)
        if encoded != canonical_serialize(value).encode():
            _fail('document is not canonical closed JSON')
    except (ValueError, TypeError, UnicodeError) as exc:
        raise AuthorityUnavailable('C09 V2 selector invalid document; HOLD') from exc
    return value, before


def _fsync_parent(path):
    parent = _directory_path(Path(path).parent)
    fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        opened, named = os.fstat(fd), os.stat(parent, follow_symlinks=False)
        if (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino):
            _fail('parent inode changed')
        os.fsync(fd)
    finally:
        os.close(fd)


class InstalledC09ControlSelectorV2:
    def __init__(self, control, selector_path, journal_path):
        if type(control) is not C09StorageControlV1 or os.name != 'posix':
            _fail('requires installed Control and POSIX durability')
        control.lease.require_held()
        self._control = control
        self.selector_path = _regular_path(selector_path, exists=False)
        self.journal_path = _regular_path(journal_path, exists=False)
        if (self.selector_path != Path(str(control.path) + '.selector-v2')
                or self.journal_path != Path(str(control.path) + '.selector-v2.journal')):
            _fail('selector and journal must use the unique installed Control names')
        self._pending = Path(str(self.selector_path) + '.pending')
        paths = (self.selector_path, self.journal_path, self._pending,
                 control.path, control.key_path, control.lease.path)
        if (len(set(paths)) != len(paths)
                or any(p.is_relative_to(root) for p in paths[:3] for root in control._roots)
                or any(p in self._source_paths() for p in paths[:3])):
            _fail('protected paths overlap')
        for path in paths[:3]:
            _directory_path(path.parent)
        self._identity = dict(authority=canonical_digest(('authority', control.authority_id)),
            installation=canonical_digest(('installation', control.installation_id)),
            key=canonical_digest(('c09.key', control.key_id)),
            control=canonical_digest(('control', control.control_store_id)))

    @property
    def control(self):
        return self._control

    @contextmanager
    def _guard(self):
        with self._control._lock, self._control.lease.hold_continuation_v3():
            try:
                yield
            except OSError as exc:
                raise AuthorityUnavailable('C09 V2 selector OS operation/durability failed; HOLD') from exc

    def _source_paths(self):
        return tuple(Path(str(self._control.path) + suffix) for suffix in COMPANIONS)

    def _source_files(self):
        if not os.path.lexists(self._control.path):
            _fail('source Control is absent')
        return [_observe(p) for p in self._source_paths() if os.path.lexists(p)]

    def _sign(self, body, field):
        committed = canonical_digest(body)
        return dict(body, **{field: committed}, signature=hmac.new(self._control._key,
            (body['schema'] + '\n' + committed).encode(), hashlib.sha256).hexdigest())

    def _verify(self, value, fields, schema, field):
        if (type(value) is not dict or set(value) != fields or value['schema'] != schema
                or value['identity'] != self._identity):
            _fail('closed signed identity differs')
        body = {k: v for k, v in value.items() if k not in (field, 'signature')}
        expected = self._sign(body, field)
        if (value[field] != expected[field] or type(value['signature']) is not str
                or not hmac.compare_digest(value['signature'], expected['signature'])):
            _fail('actual signature differs')

    def _check_selector(self, value):
        self._verify(value, SELECTOR_FIELDS, SELECTOR_SCHEMA, 'selector_digest')
        if (value['selector_path'] != str(self.selector_path)
                or type(value['generation']) is not int or value['generation'] != 1
                or value['prior_selector_digest'] is not None
                or type(value['candidate']) is not dict
                or set(value['candidate']) != OBSERVATION_FIELDS
                or value['candidate_path'] != value['candidate']['resolved_path']
                or value['journal_identity'] != _identity(_observe(self.journal_path))):
            _fail('selector generation/path/journal inode differs')
        self._candidate_path(value['candidate']['resolved_path'])

    def _candidate_path(self, path):
        path = _regular_path(path)
        if (path in (*self._source_paths(), self.selector_path, self.journal_path,
                     self._pending, self._control.key_path, self._control.lease.path)
                or any(path.is_relative_to(root) for root in self._control._roots)):
            _fail('candidate overlaps protected or business file')
        return path

    def _history(self, path):
        from .c09_sanitized_history_v2 import read_sanitized_history_v2
        path = self._candidate_path(path)
        before = _observe(path)
        value = read_sanitized_history_v2(self._control, path)
        if _observe(path) != before:
            _fail('candidate changed during authenticated read')
        if (value['schema'] != 'sylanne3.c09.sanitized-control-history.v2'
                or type(value['generation']) is not int or value['generation'] != 1
                or value['prior_selector_digest'] is not None):
            _fail('only first V1 to V2 conversion is supported')
        return value, before

    def _candidate_matches(self, selector):
        history, observed = self._history(selector['candidate']['resolved_path'])
        if (observed != selector['candidate'] or history['history_digest'] != selector['history_digest']
                or history['source_inventory_digest'] != selector['source_inventory_digest']):
            _fail('candidate exact inode/history differs')
        return history

    def _events(self):
        if not os.path.lexists(self.journal_path):
            if os.path.lexists(self.selector_path):
                _fail('selected pointer without journal')
            return []
        before = _observe(self.journal_path)
        if before['prepared_size'] > MAX_BYTES:
            _fail('journal exceeds bound')
        fd = os.open(self.journal_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as stream:
            raw = stream.read(MAX_BYTES + 1)
        if _observe(self.journal_path) != before:
            _fail('journal changed during read')
        if raw and not raw.endswith(b'\n'):
            _fail('torn journal')
        events = []
        for encoded in raw.splitlines():
            try:
                event = json.loads(encoded)
            except (ValueError, UnicodeError) as exc:
                raise AuthorityUnavailable('C09 V2 selector corrupt journal; HOLD') from exc
            self._verify(event, EVENT_FIELDS, JOURNAL_SCHEMA, 'event_digest')
            if canonical_serialize(event).encode() != encoded:
                _fail('noncanonical journal')
            index = len(events)
            if (index >= len(STAGES) or type(event['seq']) is not int or event['seq'] != index + 1
                    or event['stage'] != STAGES[index]
                    or event['previous_event_digest'] != (events[-1]['event_digest'] if events else None)):
                _fail('journal transition or rollback differs')
            self._check_selector(event['selector'])
            if events and any(event[k] != events[0][k] for k in
                              ('selector', 'selector_observation', 'old_control_files')):
                _fail('journal transaction identity differs')
            old = event['old_control_files']
            allowed = list(map(str, self._source_paths()))
            if (type(old) is not list or not old or any(type(v) is not dict or set(v) != OBSERVATION_FIELDS for v in old)
                    or [v['resolved_path'] for v in old] != [p for p in allowed if p in {v['resolved_path'] for v in old}]
                    or old[0]['resolved_path'] != str(self._control.path)
                    or type(event['selector_observation']) is not dict
                    or set(event['selector_observation']) != OBSERVATION_FIELDS
                    or event['selector_observation']['resolved_path'] != str(self.selector_path)):
                _fail('derived old Control inventory differs')
            events.append(event)
        return events

    def _append(self, events, selector, observed, old):
        self._control.lease.require_held()
        if self._events() != events:
            _fail('journal concurrently changed')
        event = self._sign(dict(schema=JOURNAL_SCHEMA, identity=self._identity,
            seq=len(events) + 1, stage=STAGES[len(events)],
            previous_event_digest=events[-1]['event_digest'] if events else None,
            selector=selector, selector_observation=observed, old_control_files=old), 'event_digest')
        raw = (canonical_serialize(event) + '\n').encode()
        fd = os.open(self.journal_path, os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW)
        try:
            opened = os.fstat(fd)
            expected = selector['journal_identity']
            if (opened.st_dev, opened.st_ino) != (expected['device'], expected['file_id']):
                _fail('journal append inode differs')
            view = memoryview(raw)
            while view:
                wrote = os.write(fd, view)
                if wrote <= 0:
                    _fail('journal append incomplete')
                view = view[wrote:]
            os.fsync(fd)
        finally:
            os.close(fd)
        _fsync_parent(self.journal_path)
        return event

    def _durable_existing_journal(self):
        fd = os.open(self.journal_path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        _fsync_parent(self.journal_path)

    def _selected(self, intent):
        selector, observation = _read_json(self.selector_path)
        self._check_selector(selector)
        if selector != intent['selector'] or observation != intent['selector_observation']:
            _fail('selected pointer exact inode/content differs')
        if os.path.lexists(self._pending):
            _fail('double current/pending pointer')
        self._candidate_matches(selector)
        return selector

    def _check_old(self, old, *, absent_ok=False):
        expected = {v['resolved_path']: v for v in old}
        for path in self._source_paths():
            if os.path.lexists(path):
                if str(path) not in expected or _observe(path) != expected[str(path)]:
                    _fail('old Control changed or unregistered companion appeared')
            elif str(path) in expected and not absent_ok:
                _fail('old Control disappeared before switch')

    def prepare(self, candidate_path):
        """Authenticate entire source and candidate; persist the signed INTENT."""
        with self._guard():
            events = self._events()
            if events:
                if str(_regular_path(candidate_path)) != events[0]['selector']['candidate']['resolved_path']:
                    _fail('another candidate or unsupported successor')
                self._candidate_matches(events[0]['selector'])
                if len(events) > 1 or os.path.lexists(self.selector_path):
                    self._selected(events[0])
                self._durable_existing_journal()
                return events[0]
            if os.path.lexists(self.selector_path):
                _fail('existing selector without intent')
            history, candidate = self._history(candidate_path)
            candidate_fd = os.open(candidate['resolved_path'], os.O_RDONLY | os.O_NOFOLLOW)
            try:
                os.fsync(candidate_fd)
            finally:
                os.close(candidate_fd)
            _fsync_parent(candidate['resolved_path'])
            source = capture_control_inventory_export_v2(self._control)
            old = self._source_files()
            if (source != history['source_inventory']
                    or source['inventory_digest'] != history['source_inventory_digest']
                    or old != history['old_control_files']):
                _fail('complete source export or exact source files differ')
            if not os.path.lexists(self.journal_path):
                fd = os.open(self.journal_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                try:
                    os.fsync(fd)
                finally:
                    os.close(fd)
                _fsync_parent(self.journal_path)
            selector = self._sign(dict(schema=SELECTOR_SCHEMA, identity=self._identity,
                selector_path=str(self.selector_path), journal_identity=_identity(_observe(self.journal_path)),
                generation=1, prior_selector_digest=None, candidate=candidate, candidate_path=candidate['resolved_path'],
                source_inventory_digest=source['inventory_digest'], history_digest=history['history_digest']), 'selector_digest')
            if os.path.lexists(self._pending):
                existing, _ = _read_json(self._pending)
                if existing != selector:
                    _fail('unregistered staging pointer exists')
            else:
                fd = os.open(self._pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                with os.fdopen(fd, 'wb') as stream:
                    stream.write(canonical_serialize(selector).encode())
                    stream.flush()
                    os.fsync(stream.fileno())
                _fsync_parent(self._pending)
            observation = dict(_observe(self._pending), resolved_path=str(self.selector_path))
            self._check_old(old)
            self._candidate_matches(selector)
            return self._append([], selector, observation, old)

    def switch(self):
        """Atomically select the exact staged inode and persist SWITCHED."""
        with self._guard():
            events = self._events()
            if not events:
                _fail('durable intent absent')
            intent = events[0]
            if len(events) > 1:
                self._selected(intent)
                self._durable_existing_journal()
                return events[1]
            history = self._candidate_matches(intent['selector'])
            require_process_retired_v1(history['writer_quiescence']['authority_process_original'])
            self._durable_existing_journal()
            self._check_old(intent['old_control_files'])
            if os.path.lexists(self.selector_path):
                self._selected(intent)
            else:
                selector, observation = _read_json(self._pending)
                if (selector != intent['selector'] or dict(observation, resolved_path=str(self.selector_path))
                        != intent['selector_observation']):
                    _fail('staged pointer inode/content differs')
                self._control.lease.require_held()
                os.replace(self._pending, self.selector_path)
            fd = os.open(self.selector_path, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
            _fsync_parent(self.selector_path)
            self._selected(intent)
            return self._append(events, intent['selector'], intent['selector_observation'], intent['old_control_files'])

    def dispose(self):
        """Durably unlink only the signed retired inodes, then sign DISPOSED."""
        with self._guard():
            events = self._events()
            if len(events) < 2:
                _fail('durable switch absent')
            intent = events[0]
            self._selected(intent)
            history = self._candidate_matches(intent['selector'])
            require_process_retired_v1(history['writer_quiescence']['authority_process_original'])
            if len(events) == 3:
                if any(os.path.lexists(p) for p in self._source_paths()):
                    _fail('disposed old Control reappeared')
                self._durable_existing_journal()
                return events[2]
            self._durable_existing_journal()
            self._check_old(intent['old_control_files'], absent_ok=True)
            # Main first prevents reopening a still-live V1 Control after partial disposal.
            for before in intent['old_control_files']:
                self._control.lease.require_held()
                self._selected(intent)
                self._check_old(intent['old_control_files'], absent_ok=True)
                unlink_inventory_member_durably_v2(before)
            if any(os.path.lexists(p) for p in self._source_paths()):
                _fail('retired Control names still exist')
            self._selected(intent)
            return self._append(events, intent['selector'], intent['selector_observation'], intent['old_control_files'])

    def current(self):
        """Return the independently selected history only after physical disposal.

        This result confers no business/recovery admission or V1 open context.
        """
        with self._guard():
            events = self._events()
            if len(events) != 3:
                _fail('conversion unfinished')
            selector = self._selected(events[0])
            if any(os.path.lexists(p) for p in self._source_paths()):
                _fail('retired old Control reappeared')
            self._durable_existing_journal()
            return selector
