"""Independent signed Owner Source page/detail READ, metadata before every Body."""
from dataclasses import dataclass
from weakref import WeakKeyDictionary
import secrets
import time

from ..authority_service.contract import AuthorityUnavailable
from ..graph_types import AtomKey, GraphVersion
from ..memory_types import source_key, SourceRecord
from ..runtime_contracts import canonical_digest
from ..runtime_storage_v3 import (begin_runtime_storage_operation_v3, bind_runtime_storage_operation_v3,
    finish_runtime_storage_operation_v3, runtime_storage_quantum_v3, _runtime_bounded_fixed_row_v3,
    begin_runtime_cell_read_v3)
from .source_correction_read_v3 import PersonalEligibilityRecoverySourcesV1, _heap
from .source_inspection_metadata_read_v3 import InspectionMetadataReadV3, LegacyInspectionMetadataUnavailableV3

PAGE_ACTION = 'read_current_source_page_v1'
DETAIL_ACTION = 'read_current_source_detail_v1'
WORK_KIND = 'source_owner_read_v3'
_READERS = WeakKeyDictionary()
_RESULTS = WeakKeyDictionary()
_CURSORS = WeakKeyDictionary()


class SourceOwnerCursorStaleV3(AuthorityUnavailable):
    pass


class SourceOwnerReadIncompleteV3(AuthorityUnavailable):
    pass


class _SourceDeniedV3(AuthorityUnavailable):
    pass


@dataclass(frozen=True, slots=True)
class SourceOwnerPageRequestV1:
    cursor: str | None
    page_size: int

    def __post_init__(self):
        if (self.cursor is not None and (type(self.cursor) is not str or not 1 <= len(self.cursor) <= 4096)
                or type(self.page_size) is not int or not 1 <= self.page_size <= 100):
            raise ValueError('Source page requires its exact bounded selectors')


@dataclass(frozen=True, slots=True)
class SourceOwnerDetailRequestV1:
    source_id: str
    expected_revision: int

    def __post_init__(self):
        if (type(self.source_id) is not str or not 1 <= len(self.source_id) <= 256 or not self.source_id.strip()
                or type(self.expected_revision) is not int or self.expected_revision < 1):
            raise ValueError('Source detail requires its exact positive target version')


def decode_source_owner_request_v1(action, data):
    if action == PAGE_ACTION:
        if (type(data) is not dict or set(data) != {'cursor', 'page_size'}
                or data['cursor'] is not None and (type(data['cursor']) is not str or not 1 <= len(data['cursor']) <= 4096)
                or type(data['page_size']) is not int or not 1 <= data['page_size'] <= 100):
            raise ValueError('Source page requires its exact bounded cursor/page_size request')
        return SourceOwnerPageRequestV1(**data)
    if action == DETAIL_ACTION:
        if (type(data) is not dict or set(data) != {'source_id', 'expected_revision'}
                or type(data['source_id']) is not str or not 1 <= len(data['source_id']) <= 256 or not data['source_id'].strip()
                or type(data['expected_revision']) is not int or data['expected_revision'] < 1):
            raise ValueError('Source detail requires one exact source and positive Graph revision')
        return SourceOwnerDetailRequestV1(**data)
    raise ValueError('unregistered Source Owner READ action')


class _CursorV3:
    def __init__(self, operation, binding, after):
        self.operation, self.binding, self.after = operation, binding, after
        operation.retain(_heap((binding, after)) + 2048)

    def release_v3(self):
        self.operation.release()


def release_source_owner_cursors_v3(graph):
    for cursor in _CURSORS.pop(graph, {}).values():
        cursor.release_v3()


class _InspectionFamilyV3(PersonalEligibilityRecoverySourcesV1):
    """The existing Source ALL traversal, fed only independent inspection originals."""
    def __init__(self, owner, root):
        self.owner, self.inspection, self.inspections = owner, None, {}
        self._registered = False
        self._extra = 0
        super().__init__(owner.db, roots=(root,), namespace=owner.namespace, storage_lease=owner.operation,
            read_scope=owner.fence.scope, graph_stamp=owner.graph_stamp, purpose='context', audiences=('owner',))

    def _runtime_retained_heap_bytes_v3(self):
        return self._payload_bytes() + _heap(tuple(self.inspections)) + self._extra + 4096

    def _reserve(self, extra=0):
        if not self._registered:
            self.storage_lease.register_retained_state_v3(self)
            self._registered = True
        self._extra = extra
        self.storage_lease.refresh_retained_state_v3(self)

    def _open(self, token, kind, meter):
        if kind == 'source':
            if self._head(token, meter)[1] != 1:
                raise _SourceDeniedV3('current Source ancestor is unavailable')
            self.inspection = InspectionMetadataReadV3(self.owner, AtomKey.from_token(token))
            self.inspections[token] = self.inspection
            return
        if self._head(token, meter)[1] != 1:
            raise _SourceDeniedV3('current Source access is unavailable')
        super()._open(token, kind, meter)

    def _step(self, meter):
        if self.inspection is not None:
            task = self.inspection
            if task.advance(meter):
                original = task.result
                ref = original.key.token
                self.sources[ref] = (dict(original.metadata), original.payload_sha256)
                self.heads[task.metadata_key.token] = task.metadata_head
                self.family_keys.add(task.metadata_key.token)
                self._source_loaded(ref)
                self.inspection = None
            return
        if self.cell is None and self.phase == 'result':
            if self._epochs(meter) != self.epochs:
                raise SourceOwnerCursorStaleV3('source_cursor_stale')
            for task in self.inspections.values():
                task.require_current_v3(meter)
            self.readset = tuple(self._readset_pending)
            self.complete = True
            return
        try:
            super()._step(meter)
        except AuthorityUnavailable as error:
            if str(error) == 'current Source/access/correction qualification is denied':
                raise _SourceDeniedV3('current Source metadata qualification denied') from error
            raise

    def release_v3(self):
        for task in self.inspections.values():
            task.release_v3()
        self.inspections.clear()
        self.inspection = None
        if self._registered:
            self.storage_lease.unregister_retained_state_v3(self)
            self._registered = False
        self.sources.clear(); self.accesses.clear(); self.heads.clear(); self.families.clear()


class _SourceOwnerResultV3:
    def __init__(self, state, value):
        self.state, self.value = state, value
        _RESULTS[self] = (state, state.work, state.operation, canonical_digest(value))

    def release_payload_v3(self):
        if _RESULTS.pop(self, None) is not None:
            self.value = None
            self.state.release_v3()


def require_source_owner_terminal_v3(value, work):
    if (type(value) is not _SourceOwnerResultV3 or value.state.work is not work
            or not value.state.read_finished or _RESULTS.get(value) !=
                (value.state, work, work.operation, canonical_digest(value.value))):
        raise AuthorityUnavailable('Source READ returned no actual privately issued readonly result')
    return value.value


class _SourceOwnerReadV3:
    def __init__(self, graph, authority, lease, owner, session, operation, fence, action, request):
        self.graph, self.authority, self.lease, self.owner_binding = graph, authority, lease, owner
        self.session_proof, self.operation, self.fence, self.action, self.request = session, operation, fence, action, request
        self.store, self.db, self.namespace = graph._GraphCoordinator__store, graph._GraphCoordinator__store._db, authority.namespace
        self.graph_stamp = (fence.metadata, fence.epoch)
        self.work = None
        self.phase = 'coverage_sources' if action == PAGE_ACTION else 'detail'
        self.scan_after = self.coverage_after = self.retraction_after = None
        self.task = self.family = self.body_cell = self.body_parser = None
        self.fragment = b''; self.fragment_offset = 0
        self.body_extra = 0
        self.family_ids = ()
        self.items = []
        self.selected_key = self.selected_original = None
        self.read_finished = self.closed = False
        self.result = None
        self.coverage_kind = 'memory.source'
        self.after = None
        self.deadline_monotonic = time.monotonic() + 60.0
        operation.register_retained_state_v3(self)

    @property
    def read_scope(self):
        return self.fence.scope

    def _identity_v3(self):
        return (self.graph, self.work, self.operation, self.fence, self.authority, self.lease,
            self.owner_binding, self.session_proof, self.action, self.request, self.graph_stamp)

    def _runtime_retained_heap_bytes_v3(self):
        parser_bytes = 0 if self.body_parser is None else self.body_parser._source_heap_bytes()
        return 32768 + _heap((self.items, self.fragment, self.after, self.scan_after,
            self.coverage_after, self.retraction_after, self.family_ids)) + parser_bytes + self.body_extra

    def _cursor_binding_v3(self):
        o = self.owner_binding
        return canonical_digest((self.namespace, self.session_proof, self.authority.actor,
            o.grant_id, o.grant_revision, o.grant_digest, o.authorization_head, o.authorization_revision,
            o.revocation_epoch, o.graph_incarnation, o.access_epoch, o.delete_epoch,
            self.authority.purpose, self.authority.audience, self.authority.activation_generation,
            self.operation.selection_digest, self.graph_stamp,
            self.request.page_size if self.action == PAGE_ACTION else None))

    def _current_v3(self):
        self.work._require_invocation(self.graph)
        if _READERS.get(self) != self._identity_v3() or self.closed or self.operation.closed:
            raise AuthorityUnavailable('Source READ lost its exact current Owner/Work')
        if time.monotonic() >= self.deadline_monotonic:
            raise SourceOwnerReadIncompleteV3('source_read_incomplete')
        with bind_runtime_storage_operation_v3(self.operation, self.db):
            if self.action == PAGE_ACTION:
                with self.store._lock, runtime_storage_quantum_v3(self.db) as meter:
                    try:
                        self.operation.handle.require_current(meter)
                    except AuthorityUnavailable as error:
                        raise SourceOwnerCursorStaleV3('source_cursor_stale') from error
                    if self.graph._v2_graph_stamp(self.namespace) != self.graph_stamp:
                        raise SourceOwnerCursorStaleV3('source_cursor_stale')
            self.graph._validate_read_fence_v3(self.fence)

    def _fixed_v3(self, meter, table, columns, where, key):
        return _runtime_bounded_fixed_row_v3(self.db, meter, table, columns, where, key)

    def _next_head_v3(self, meter, kind, after):
        where, args = ('bot=? AND persona=? AND type_name=?', (*self.namespace.as_tuple, kind))
        if after is not None:
            where += ' AND token>?'
            args += (after,)
        return self._fixed_v3(meter, 'graph_atoms', ('token', 'revision', 'valid'), where + ' ORDER BY token', args)

    def _public_metadata_v3(self, original):
        return {name: original.metadata[name] for name in ('source_id', 'source_kind', 'assertion_status', 'recorded_at')} | {
            'qualification': 'not_recorded', 'revision': original.revision}

    def _release_task_v3(self):
        if self.task is not None:
            self.task.release_v3()
            self.task = None

    def _drop_family_v3(self):
        if self.family is not None:
            self.family.release_v3()
            self.family = None
        self.selected_original = self.selected_key = None
        self.family_ids = ()

    def _complete_page_v3(self):
        has_more = len(self.items) > self.request.page_size
        rows = self.items[:self.request.page_size]
        records = _CURSORS.setdefault(self.graph, {})
        # Superseded snapshots retain no Authority or Body and release their actual pool reservation.
        binding = self._cursor_binding_v3()
        for token, cursor in tuple(records.items()):
            if cursor.binding != binding or self.request.cursor is None or token == self.request.cursor:
                cursor.release_v3(); del records[token]
        token = None
        if has_more:
            token = secrets.token_urlsafe(32)
            cursor_operation = begin_runtime_storage_operation_v3(self.db, 'source-cursor:' + token, None)
            try:
                records[token] = _CursorV3(cursor_operation, binding, self.items[self.request.page_size - 1][0])
            except BaseException:
                cursor_operation.release()
                raise
        value = {'schema': 'd12.source-page.v1', 'sources': tuple(item[1] for item in rows),
            'next_cursor': token, 'has_more': has_more}
        self.result = _SourceOwnerResultV3(self, value)
        self.operation.retain(_heap(value) * 2 + 4096)
        self.phase = 'complete'

    def _step_v3(self, meter):
        if self.phase.startswith('coverage_'):
            if self.task is not None:
                if self.task.advance(meter):
                    self._release_task_v3()
                return
            row = self._next_head_v3(meter, self.coverage_kind, self.coverage_after)
            if row is None:
                if self.coverage_kind == 'memory.source':
                    self.coverage_kind, self.coverage_after = 'memory.interpretation', None
                    self.phase = 'coverage_interpretations'
                else:
                    self.scan_after = self.after
                    self.phase = 'scan'
                return
            self.coverage_after = row[0]
            if row[1] > 0 and row[2] == 1:
                self.task = InspectionMetadataReadV3(self, AtomKey.from_token(row[0]))
            return
        if self.phase == 'detail':
            self.selected_key = source_key(*self.namespace.as_tuple, self.request.source_id)
            row = self._fixed_v3(meter, 'graph_atoms', ('revision', 'valid'), 'bot=? AND persona=? AND token=?',
                (*self.namespace.as_tuple, self.selected_key.token))
            if row is None or row[1] != 1:
                raise AuthorityUnavailable('source_read_unavailable')
            if row[0] != self.request.expected_revision:
                raise SourceOwnerCursorStaleV3('source_revision_stale')
            self.family = _InspectionFamilyV3(self, self.selected_key.token)
            self.phase = 'family'
            return
        if self.phase == 'scan':
            row = self._next_head_v3(meter, 'memory.source', self.scan_after)
            if row is None:
                self._complete_page_v3()
                return
            self.scan_after = row[0]
            if row[1] > 0 and row[2] == 1:
                self.selected_key = AtomKey.from_token(row[0])
                self.family = _InspectionFamilyV3(self, row[0])
                self.phase = 'family'
            return
        if self.phase == 'retractions':
            if self.task is not None:
                if not self.task.advance(meter):
                    return
                record = self.task.result.metadata
                if record['status'] == 'retracted' and any(sid in record['source_ids'] for sid in self.family_ids):
                    self._release_task_v3()
                    if self.action == DETAIL_ACTION:
                        raise _SourceDeniedV3('source_read_unavailable')
                    self._drop_family_v3()
                    self.phase = 'scan'
                    return
                self._release_task_v3()
            row = self._next_head_v3(meter, 'memory.interpretation', self.retraction_after)
            if row is not None:
                self.retraction_after = row[0]
                if row[1] > 0 and row[2] == 1:
                    self.task = InspectionMetadataReadV3(self, AtomKey.from_token(row[0]))
                return
            if self.action == PAGE_ACTION:
                self.items.append((self.selected_key.token, self._public_metadata_v3(self.selected_original)))
                self._drop_family_v3()
                if len(self.items) > self.request.page_size:
                    self._complete_page_v3()
                else:
                    self.phase = 'scan'
            else:
                self.phase = 'body_start'
            return
        if self.phase == 'body_start':
            # The Source ALL traversal and complete retraction metadata EOF precede this first Body open.
            for task in self.family.inspections.values():
                task.require_current_v3(meter)
            self.body_cell = begin_runtime_cell_read_v3(self.db, self.selected_original.cell_id,
                erasure_owner_ref=self.selected_key.token)
            from .current_graph_source_material_v3 import _SourceTextJSONStreamV3
            state = self
            class _BodyParserV3(_SourceTextJSONStreamV3):
                def _source_require_arena(self, extra=0):
                    state.body_extra = extra + 32768
                    state.operation.refresh_retained_state_v3(state)
            self.body_parser = _BodyParserV3(ensure_ascii=self.body_cell.header[0] == 'canonical-json.ascii.v1')
            self.phase = 'body'
            return
        if self.phase == 'body':
            if self.fragment_offset < len(self.fragment):
                end = min(self.fragment_offset + 1024, len(self.fragment))
                self.body_parser.feed(self.fragment[self.fragment_offset:end], lambda event: None)
                self.fragment_offset = end
                return
            fragment = self.body_cell.read_fragment(meter=meter)
            if fragment is not None:
                self.fragment, self.fragment_offset = fragment, 0
                return
            parsed = self.body_parser.finish()
            if (parsed.sha256, parsed.byte_count) != (self.body_cell.finish(meter=meter), self.body_cell.header[3]):
                raise AuthorityUnavailable('Source detail physical canonical EOF differs')
            metadata = {k: tuple(v) if type(v) is list else v for k, v in self.body_parser._source_metadata.items()}
            if metadata != dict(self.selected_original.metadata):
                raise AuthorityUnavailable('Source detail metadata differs from its independent inspection original')
            record = SourceRecord(text=self.body_parser.text, **metadata)
            if canonical_digest(record.to_dict()) != self.selected_original.semantic_digest:
                raise AuthorityUnavailable('Source detail semantic digest differs from its producer commitment')
            value = {'schema': 'd12.source-detail.v1', 'source': self._public_metadata_v3(self.selected_original) | {'text': record.text}}
            self.operation.retain(_heap(value) * 2 + 4096)
            self.result = _SourceOwnerResultV3(self, value)
            self.phase = 'complete'

    def release_v3(self):
        if self.closed:
            return
        self.closed = True
        _READERS.pop(self, None)
        self._release_task_v3(); self._drop_family_v3()
        self.body_parser = self.body_cell = self.result = None
        self.fragment = b''; self.items.clear()
        self.operation.unregister_retained_state_v3(self)


def require_source_owner_work_v3(work, graph, *, action, request):
    from ..graph_worker import GraphStorageWorkV3
    if type(work) is not GraphStorageWorkV3 or work.coordinator is not graph or work.kind != WORK_KIND:
        raise AuthorityUnavailable('Source Owner READ requires its actual registered serial Work')
    state = work.state
    if (type(state) is not _SourceOwnerReadV3 or _READERS.get(state) != state._identity_v3()
            or state.work is not work or state.action != action or state.request != request):
        raise AuthorityUnavailable('Source Owner READ changed its exact command selectors')
    return state


def advance_source_owner_read_v3(graph, work):
    from ..graph_worker import GraphStorageStepV3
    from .c09_paged_sql_v2 import C09PagedCaptureHold
    state = require_source_owner_work_v3(work, graph, action=work.state.action, request=work.state.request)
    state._current_v3()
    with bind_runtime_storage_operation_v3(state.operation, state.db):
        try:
            with state.store._lock, runtime_storage_quantum_v3(state.db) as meter:
                if state.phase == 'family':
                    try:
                        state.family._step(meter)
                    except _SourceDeniedV3:
                        if state.action == DETAIL_ACTION:
                            raise
                        state._drop_family_v3(); state.phase = 'scan'
                    if state.family is not None and state.family.complete:
                        state.selected_original = state.family.inspections[state.selected_key.token].result
                        state.family_ids = tuple(AtomKey.from_token(ref).owner.subject for ref in state.family.inspections)
                        state.retraction_after = None
                        state.phase = 'retractions'
                else:
                    state._step_v3(meter)
                if state.family is not None:
                    state.family._reserve()
                state.operation.refresh_retained_state_v3(state)
        except C09PagedCaptureHold:
            return GraphStorageStepV3('progress')
    state._current_v3()
    return GraphStorageStepV3('complete', state.result) if state.phase == 'complete' else GraphStorageStepV3('progress')


def finish_source_owner_read_v3(graph, work, error):
    state = work.state
    try:
        try:
            if error is None:
                state._current_v3()
        finally:
            if not state.read_finished:
                try:
                    with bind_runtime_storage_operation_v3(state.operation, state.db):
                        graph._finish_read_fence_v3(state.fence)
                finally:
                    state.read_finished = True
    except BaseException:
        state.release_v3()
        finish_runtime_storage_operation_v3(state.operation)
        raise
    if error is not None:
        state.release_v3()
        finish_runtime_storage_operation_v3(state.operation)
    else:
        # Keep both the private result and its real operation charged through
        # terminal mapping, Host serialization and the actual result release.
        work.result_lease = state.operation


def prepare_source_owner_read_v3(graph, authority, lease, *, action, request):
    from ..graph_worker import require_graph_storage_work_admission_v3, create_graph_storage_work_v3
    from .first_ingress_v2 import trusted_upper
    expected = SourceOwnerPageRequestV1 if action == PAGE_ACTION else SourceOwnerDetailRequestV1 if action == DETAIL_ACTION else None
    if expected is None or type(request) is not expected or authority.purpose != 'context' or authority.audience != ('owner',):
        raise AuthorityUnavailable('Source READ requires its exact registered Owner context request')
    require_graph_storage_work_admission_v3(graph)
    graph._authorize(lease, authority, frozenset({'d06', 'd11'}), owner_read=True)
    owner = graph._GraphCoordinator__owner_leases.get(lease)
    session = graph._GraphCoordinator__owner_session_proofs.get(lease)
    if owner is None or session is None or 'workbench.read' not in owner.capabilities:
        raise AuthorityUnavailable('current signed Owner Source READ unavailable')
    now = trusted_upper(graph._GraphCoordinator__content_fence_v2.read_ingress_clock(graph._GraphCoordinator__scene_clock_policy))
    operation_id = 'source-owner-read:' + secrets.token_hex(24)
    operation = begin_runtime_storage_operation_v3(graph._GraphCoordinator__store._db, operation_id, now + 60.0)
    fence = state = None
    try:
        with bind_runtime_storage_operation_v3(operation, graph._GraphCoordinator__store._db):
            fence = graph._begin_read_fence_v3(authority, operation_id=operation_id,
                owner_binding=owner, owner_session_proof=session)
            state = _SourceOwnerReadV3(graph, authority, lease, owner, session, operation, fence, action, request)
        work = create_graph_storage_work_v3(graph, kind=WORK_KIND, operation_id=operation_id,
            selection_digest=operation.selection_digest, deadline_utc=operation.deadline_utc, state=state, operation=operation)
        state.work = work
        _READERS[state] = state._identity_v3()
        if action == PAGE_ACTION and request.cursor is not None:
            cursor = _CURSORS.get(graph, {}).get(request.cursor)
            if cursor is None or cursor.operation.closed or cursor.binding != state._cursor_binding_v3():
                raise SourceOwnerCursorStaleV3('source_cursor_stale')
            state.after = cursor.after
        return work
    except BaseException:
        if state is not None:
            state.release_v3()
        try:
            if fence is not None:
                graph._finish_read_fence_v3(fence)
        finally:
            finish_runtime_storage_operation_v3(operation)
        raise
