"""Finite Owner correction preparation; metadata discovery precedes selected Body."""
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import fields
from hashlib import sha256
from time import monotonic
from uuid import uuid4
from weakref import WeakKeyDictionary

from ..authority_service.contract import AuthorityUnavailable
from ..domains.d06 import (CorrectionRequest, D06DomainAdapter, SourceCorrectionReadSetV1,
    source_correction_head_key)
from ..domains.d07 import BeliefRevision
from ..graph_types import AtomKey, GraphAtom, GraphSnapshot, GraphVersion
from ..memory_types import SourceRecord, InterpretationRecord, source_key, access_key, interpretation_key
from ..runtime_contracts import QueryEpoch, canonical_digest
from ..runtime_storage_v3 import (runtime_storage_v3, begin_runtime_storage_operation_v3,
    bind_runtime_storage_operation_v3, finish_runtime_storage_operation_v3,
    runtime_storage_quantum_v3, begin_runtime_cell_read_v3)
from ..graph_worker import (GraphStorageStepV3, create_graph_storage_work_v3,
    require_graph_storage_work_admission_v3)
from .source_correction_read_v3 import SourceCorrectionCommitFamilyV3, _heap
from .source_inspection_metadata_read_v3 import (InspectionMetadataReadV3, _InspectionColumnV3,
    release_inspection_metadata_owner_v3)
from .d02_fixed_policy_read_v3 import _D02MetadataReadsV3
from .c09_canonical_json_stream_v2 import C09CanonicalJSONStreamV2
from .runtime_canonical_stream_v3 import RuntimeCanonicalStreamV3
from .first_ingress_v2 import trusted_upper_at_v4

KIND = 'source_correction_commit_read_v3'
_ISSUER = object()
_READERS = WeakKeyDictionary()
_PROOFS = WeakKeyDictionary()
_BOUND = ContextVar('source_correction_commit_exact_v3', default=None)


class _BeliefMetadataStreamV3(C09CanonicalJSONStreamV2):
    """Only fixed qualification fields are decoded; proposition text is skipped."""
    def __init__(self, owner, *, ensure_ascii):
        super().__init__(ensure_ascii=ensure_ascii)
        self.owner = owner
        self.seen, self.metadata, self.scalar = set(), {}, bytearray()
        self.allowed = frozenset(field.name for field in fields(BeliefRevision))

    def _emit(self, emit, kind, path, start, end, **values):
        if kind == 'key':
            if len(path) != 1 or values['key'] not in self.allowed:
                raise AuthorityUnavailable('belief metadata has an unregistered schema field')
            self.seen.add(values['key'])
        if path and path[0] in ('belief_id', 'current', 'source_refs'):
            if kind == 'object_start':
                raise AuthorityUnavailable('belief qualification metadata cannot be an object')
            if kind == 'array_start':
                if path != ('source_refs',):
                    raise AuthorityUnavailable('belief qualification array has another path')
                self.metadata['source_refs'] = []
            elif kind == 'scalar_start':
                if len(path) > 2 or len(path) == 2 and path[0] != 'source_refs':
                    raise AuthorityUnavailable('belief qualification scalar has another path')
                self.scalar.clear()
            elif kind == 'scalar_chunk':
                self.owner.reserve_v3(len(values['raw']) * 8 + 32768)
                self.scalar.extend(values['raw'])
            elif kind == 'scalar_end':
                import json
                self.owner.reserve_v3(len(self.scalar) * 8 + 32768)
                value = json.loads(self.scalar)
                if len(path) == 2:
                    self.metadata['source_refs'].append(value)
                else:
                    self.metadata[path[0]] = value
                self.scalar.clear()
        super()._emit(emit, kind, path, start, end, **values)

    def finish(self):
        result = super().finish()
        if (self.seen != self.allowed or set(self.metadata) != {'belief_id', 'current', 'source_refs'}
                or type(self.metadata['belief_id']) is not str or not self.metadata['belief_id']
                or type(self.metadata['current']) is not bool
                or type(self.metadata['source_refs']) is not list
                or any(type(ref) is not str or not ref for ref in self.metadata['source_refs'])
                or len(set(self.metadata['source_refs'])) != len(self.metadata['source_refs'])):
            raise AuthorityUnavailable('belief complete metadata EOF differs from the actual typed schema')
        self.metadata['source_refs'] = tuple(self.metadata['source_refs'])
        return result


def require_source_correction_commit_owner_v3(owner):
    if (type(owner) is not _SourceCorrectionCommitReadV3 or _READERS.get(owner) != owner.identity_v3()
            or owner.closed or owner.operation.closed or owner.work.state is not owner
            or owner.work.operation is not owner.operation or owner.work.coordinator is not owner.graph
            or owner.work.kind != KIND or runtime_storage_v3(owner.db) is not owner.operation.handle):
        raise AuthorityUnavailable('actual registered Owner correction Source Work required')
    owner.work._require_invocation(owner.graph)
    return owner


class _SourceCorrectionCommitReadV3:
    def __init__(self, graph, *, request, authority, owner_authority, owner_binding, principal,
            session_proof, deadline, clock_reading, correction_key):
        require_graph_storage_work_admission_v3(graph)
        self.graph, self.request, self.namespace = graph, request, request.namespace
        self.source_authority, self.authority = authority, owner_authority
        self.owner_binding, self.principal, self.session_proof = owner_binding, principal, session_proof
        self.deadline, self.clock_reading = deadline, clock_reading
        self.correction_key = correction_key
        self.store = graph._GraphCoordinator__store
        self.db = self.store._db
        self.operation = self.fence = self.work = self.metadata_reads = None
        self.closed = self.complete = self.read_finished = False
        self.phase, self.cursor, self.belief_count = 'targets', '', 0
        self.belief_root = sha256(b'sylanne3.source-correction-belief-metadata.v3').hexdigest()
        self.heads, self.inspections, self.belief_metadata, self.atoms, self.bodies = {}, {}, {}, {}, {}
        self.selected_beliefs, self.source_roots, self.target_queue = [], set(request.source_refs), list(request.target_refs)
        self.inspection_current = self.belief_current = self.family = self.body_current = None
        self.body_queue, self.producer_queue = [], []
        self.producer_current = None
        self.snapshot = self.reads = self.extra = self.proof = None
        self.reserved = 0
        if (request.namespace != authority.namespace or owner_authority.namespace != self.namespace
                or correction_key != D06DomainAdapter(self.namespace).correction_source_key(CorrectionRequest(
                    request.operation_id, request.target_refs, request.source_refs, request.statement,
                    request.access_epoch, request.deletion_epoch))):
            raise AuthorityUnavailable('correction Source Work crossed its exact request/authority')
        self.clock_v3()
        operation_id = KIND + ':' + uuid4().hex
        try:
            self.operation = begin_runtime_storage_operation_v3(self.db, operation_id, deadline)
            with bind_runtime_storage_operation_v3(self.operation, self.db):
                self.fence = graph._begin_read_fence_v3(owner_authority, operation_id=operation_id,
                    owner_principal=principal, owner_binding=owner_binding, owner_session_proof=session_proof)
                self.graph_stamp = self.fence.metadata, self.fence.epoch
                self.selection_digest = self.operation.selection_digest
                self.metadata_reads = _D02MetadataReadsV3(self.operation, self.db)
                self.reserve_v3()
        except BaseException:
            try:
                if self.fence is not None:
                    graph._finish_read_fence_v3(self.fence)
            finally:
                finish_runtime_storage_operation_v3(self.operation)
            raise

    def identity_v3(self):
        return (self.graph, self.request, self.source_authority, self.authority, self.owner_binding,
            self.principal, self.session_proof, self.deadline, self.operation, self.fence, self.graph_stamp)

    def clock_v3(self):
        if trusted_upper_at_v4(self.clock_reading, monotonic()) >= self.deadline:
            raise AuthorityUnavailable('original Owner correction deadline expired')

    def reserve_v3(self, extra=0):
        transient = () if self.belief_current is None else (
            self.belief_current['parser'].metadata, self.belief_current['parser'].scalar,
            self.belief_current['fragment'])
        amount = _heap((transient, self.heads, self.belief_metadata, self.atoms, self.bodies,
            self.selected_beliefs, self.source_roots, self.target_queue, self.body_queue,
            self.producer_queue, self.snapshot,
            self.reads, self.extra)) + extra + 65536
        if amount > self.reserved:
            self.operation.retain(amount - self.reserved)
            self.reserved = amount

    def point_v3(self, meter, table, columns, where, key):
        return self.metadata_reads.fixed(meter, table, columns, where, key)

    def head_v3(self, key, meter):
        if (key.owner.bot, key.owner.persona) != self.namespace.as_tuple:
            raise AuthorityUnavailable('correction metadata head crosses namespace')
        prior = self.heads.get(key.token)
        head = self.point_v3(meter, 'graph_atoms', ('revision', 'valid', 'value_cell_id'),
            'token=?', (key.token,))
        head = (0, 0, None) if head is None else head
        if prior is not None and prior != head:
            raise AuthorityUnavailable('correction current head changed')
        self.heads[key.token] = head
        if len(self.heads) > 512:
            raise AuthorityUnavailable('correction actual Graph head closure exceeds original 512 bound')
        self.reserve_v3()
        return head

    def require_current_v3(self, meter):
        require_source_correction_commit_owner_v3(self)
        self.clock_v3()
        if self.graph._v2_graph_stamp(self.namespace) != self.graph_stamp:
            raise AuthorityUnavailable('correction namespace metadata/epoch changed')
        epochs = self.point_v3(meter, 'graph_authority_epochs', ('access_epoch', 'delete_epoch'),
            'bot=? AND persona=?', self.namespace.as_tuple)
        if epochs != (self.request.access_epoch, self.request.deletion_epoch):
            raise AuthorityUnavailable('correction original Source/delete epochs changed')
        for key, expected in tuple(self.metadata_reads.fixed_rows.items()):
            if self.metadata_reads.fixed(meter, *key) != expected:
                raise AuthorityUnavailable('correction metadata point changed')
        if self.family is not None and self.family.complete:
            self.family.require_metadata_current_v3(meter)

    def _start_inspection_v3(self, token, meter):
        key = AtomKey.from_token(token)
        if key.type_name != 'memory.interpretation' or key != interpretation_key(*self.namespace.as_tuple, key.owner.subject):
            raise AuthorityUnavailable('correction supports only exact D06 Interpretation source roots')
        head = self.head_v3(key, meter)
        if head[0] < 1 or head[1] != 1:
            raise AuthorityUnavailable('correction interpretation metadata is not current')
        task = InspectionMetadataReadV3(self, key)
        self.inspections[token] = task
        self.inspection_current = token, task

    def _inspection_step_v3(self, meter):
        token, task = self.inspection_current
        task.advance(meter)
        if not task.complete:
            return
        original = task.result.require_v3(self, meter)
        if original.metadata['status'] == 'retracted':
            raise AuthorityUnavailable('correction interpretation root is already retracted')
        self.source_roots.update(source_key(*self.namespace.as_tuple, sid).token
            for sid in original.metadata['source_ids'])
        self.inspection_current = None
        self.reserve_v3()

    def _belief_start_v3(self, meter):
        row = meter.read_fixed_row(self.db, 'graph_atoms', ('token', 'revision', 'valid', 'value_cell_id'),
            "bot=? AND persona=? AND type_name='d07.belief_revision.v1' AND valid=1 AND token>? ORDER BY token",
            (*self.namespace.as_tuple, self.cursor))
        if row is None:
            self.phase = 'belief_roots'
            return
        self.cursor = row[0]
        self.belief_count += 1
        if self.belief_count > 512:
            raise AuthorityUnavailable('correction complete belief metadata census exceeds original bound')
        key = AtomKey.from_token(row[0])
        if key.type_name != 'd07.belief_revision.v1' or key.owner.kind != 'persona' or row[2] != 1:
            raise AuthorityUnavailable('correction belief head is outside its actual typed namespace')
        self.head_v3(key, meter)
        cell = begin_runtime_cell_read_v3(self.db, row[3], erasure_owner_ref=key.token)
        if cell.header[0] not in ('canonical-json.ascii.v1', 'canonical-json.utf8.v1'):
            raise AuthorityUnavailable('belief metadata requires its actual canonical codec')
        history = self.point_v3(meter, 'graph_history', ('valid', 'value_cell_id',
            'event_bot', 'event_persona', 'event_session', 'event_id'),
            'token=? AND revision=?', (key.token, row[1]))
        if history is None or history[:4] != (1, row[3], *self.namespace.as_tuple):
            raise AuthorityUnavailable('belief metadata lacks its exact producing history')
        self.belief_current = {'token': key.token, 'head': tuple(row[1:]), 'cell': cell,
            'parser': _BeliefMetadataStreamV3(self, ensure_ascii=cell.header[0] == 'canonical-json.ascii.v1'),
            'fragment': b'', 'offset': 0, 'history': history}

    def _belief_step_v3(self, meter):
        item = self.belief_current
        if item['offset'] < len(item['fragment']):
            end = min(item['offset'] + 1024, len(item['fragment']))
            item['parser'].feed(item['fragment'][item['offset']:end], lambda event: None)
            item['offset'] = end
            return
        chunk = item['cell'].read_fragment(meter=meter)
        if chunk is not None:
            item['fragment'], item['offset'] = chunk, 0
            return
        parsed = item['parser'].finish()
        digest = item['cell'].finish(meter=meter)
        if (parsed.sha256, parsed.byte_count) != (digest, item['cell'].header[3]):
            raise AuthorityUnavailable('belief metadata complete parser/header/SHA EOF differs')
        metadata = item['parser'].metadata
        key = AtomKey.from_token(item['token'])
        if metadata['belief_id'] != key.name:
            raise AuthorityUnavailable('belief metadata identity differs from current head')
        self.belief_root = canonical_digest(('sylanne3.source-correction-belief-link.v3',
            self.belief_root, item['token'], item['head'], digest))
        if metadata['current'] and set(metadata['source_refs']).intersection(
                (*self.request.source_refs, *self.request.target_refs)):
            self.heads[item['token']] = item['head']
            self.belief_metadata[item['token']] = (metadata, digest, tuple(item['cell'].header), item['history'])
            self.selected_beliefs.append(item['token'])
            for ref in metadata['source_refs']:
                dependency = AtomKey.from_token(ref)
                if (dependency.owner.bot, dependency.owner.persona) != self.namespace.as_tuple:
                    raise AuthorityUnavailable('selected belief Source reference crosses namespace')
                if dependency.type_name == 'memory.source' and dependency == source_key(*self.namespace.as_tuple, dependency.owner.subject):
                    self.source_roots.add(ref)
                elif dependency.type_name == 'memory.interpretation' and dependency == interpretation_key(*self.namespace.as_tuple, dependency.owner.subject):
                    if ref not in self.inspections and ref not in self.target_queue:
                        self.target_queue.append(ref)
                else:
                    raise AuthorityUnavailable('selected belief has an unregistered Source root type')
        self.producer_queue.append((item['token'], item['head'][0], item['history']))
        self.belief_current = None
        self.reserve_v3()


    def _family_complete_v3(self, meter):
        for token, head in self.family.heads.items():
            key = AtomKey.from_token(token)
            actual = self.head_v3(key, meter)
            if actual != ((0, 0, None) if head[0] == 0 else head):
                raise AuthorityUnavailable('correction Source family actual head differs')
        for token, task in self.family.inspection_tasks.items():
            self.inspections[token] = task
        for task in self.inspections.values():
            self.head_v3(task.metadata_key, meter)
        self.body_queue = list(dict.fromkeys((*self.request.source_refs,
            *self.request.target_refs, *self.selected_beliefs)))
        self.phase = 'bodies'

    def _body_start_v3(self, meter):
        if not self.body_queue:
            self.phase = 'guards'
            return
        token = self.body_queue.pop(0)
        key = AtomKey.from_token(token)
        head = self.head_v3(key, meter)
        if head[0] < 1 or head[1] != 1:
            raise AuthorityUnavailable('qualified correction Body is absent')
        original = self.inspections[token].result.require_v3(self, meter) if token in self.inspections else None
        if original is not None and (original.revision, original.cell_id) != (head[0], head[2]):
            raise AuthorityUnavailable('qualified correction Body inspection changed')
        column = _InspectionColumnV3(self, table='graph_history', column='value',
            key_columns=('token', 'revision'), key=(token, head[0]), cell_id=head[2])
        if original is not None and tuple(column.cell.header) != original.header:
            raise AuthorityUnavailable('correction Body physical header differs from inspection')
        if token in self.belief_metadata and tuple(column.cell.header) != self.belief_metadata[token][2]:
            raise AuthorityUnavailable('selected belief physical header changed after census')
        self.body_current = {'token': token, 'column': column, 'original': original, 'stream': None}

    def _body_step_v3(self, meter):
        item = self.body_current
        token, column = item['token'], item['column']
        if not column.complete:
            column.advance(meter)
            return
        if item['stream'] is None:
            value = column.value_v3(self)
            key = AtomKey.from_token(token)
            if key.type_name == 'memory.source':
                from ..domains.d06.inspection_metadata_v1 import SOURCE_FIELDS
                record = SourceRecord.from_dict(value)
                metadata = {name: tuple(value[name]) if type(value[name]) is list else value[name]
                    for name in SOURCE_FIELDS}
                if metadata != dict(item['original'].metadata) or record.source_id != key.owner.subject:
                    raise AuthorityUnavailable('qualified Source Body metadata differs')
            elif key.type_name == 'memory.interpretation':
                record = InterpretationRecord.from_dict(value)
                metadata = {'interpretation_id': record.interpretation_id, 'status': record.status,
                    'source_ids': record.source_ids}
                if metadata != dict(item['original'].metadata) or record.interpretation_id != key.owner.subject:
                    raise AuthorityUnavailable('qualified Interpretation Body metadata differs')
            else:
                from ..domains.d07 import D07DomainProvider
                next(spec for spec in D07DomainProvider.type_specs()
                    if spec.name == 'd07.belief_revision.v1').validator(value)
                metadata = {'belief_id': value['belief_id'], 'current': value['current'],
                    'source_refs': tuple(value['source_refs'])}
                expected, physical, _, history = self.belief_metadata[token]
                if metadata != expected or column.sha256 != physical:
                    raise AuthorityUnavailable('selected belief Body differs from complete metadata census')
            item['value'] = value
            item['stream'] = RuntimeCanonicalStreamV3(value, self.operation)
            self.reserve_v3(_heap(value) + 65536)
            return
        item['stream'].read_fragment(meter)
        if not item['stream'].complete:
            return
        if item['original'] is not None and item['stream'].hash.hexdigest() != item['original'].semantic_digest:
            raise AuthorityUnavailable('qualified correction Body complete semantic SHA differs')
        original = SourceCorrectionBodyOriginalV3(_ISSUER, self, token, item['value'],
            column.sha256, column.byte_count)
        self.bodies[token] = original
        self.atoms[AtomKey.from_token(token)] = GraphAtom(AtomKey.from_token(token),
            self.heads[token][0], item['value'], True, _canonical_original=original)
        self.body_current = None
        column.release_v3()
        self.reserve_v3()

    def _producer_step_v3(self, meter):
        if self.producer_current is None:
            if not self.producer_queue:
                self.phase = 'family_begin'
                return
            token, revision, history = self.producer_queue.pop(0)
            event = tuple(history[2:])
            receipt = self.point_v3(meter, 'graph_bundle_operations',
                ('activity_id', 'digest', 'commit_seq'),
                'bot=? AND persona=? AND operation_id=?', (*self.namespace.as_tuple, event[3]))
            event_header = self.point_v3(meter, 'graph_events', ('digest', 'epoch_revision'),
                'bot=? AND persona=? AND session=? AND event_id=?', event)
            if receipt is None or event_header is None or receipt[0] != event[2] or receipt[2] < 1:
                raise AuthorityUnavailable('selected belief has no actual producing W01/event original')
            column = _InspectionColumnV3(self, table='graph_events', column='revisions',
                key_columns=('bot', 'persona', 'session', 'event_id'), key=event)
            self.producer_current = token, revision, column
            return
        token, revision, column = self.producer_current
        column.advance(meter)
        if not column.complete:
            return
        if [token, revision] not in column.value_v3(self):
            raise AuthorityUnavailable('selected belief producing event does not write its actual revision')
        column.release_v3()
        self.producer_current = None

    def _guards_v3(self, meter):
        from .issuers import d06_source_correction_job_ref, d06_source_correction_outbox_ref
        from .source_inspection_producer_targets_v1 import inspection_producer_target_keys_v1
        from ..domains.d06.inspection_metadata_v1 import inspection_key_v1
        activity = 'source-correction-' + self.request.operation_id
        correction = CorrectionRequest(self.request.operation_id, self.request.target_refs,
            self.request.source_refs, self.request.statement, self.request.access_epoch,
            self.request.deletion_epoch)
        job_ref = d06_source_correction_job_ref(self.namespace, activity, self.request.operation_id)
        outbox_ref = d06_source_correction_outbox_ref(self.namespace, activity, self.request.operation_id)
        absent = [self.correction_key, access_key(*self.namespace.as_tuple, self.correction_key.owner.subject),
            AtomKey.from_token(job_ref), AtomKey.from_token(outbox_ref)]
        for key in inspection_producer_target_keys_v1(self.namespace, 'source-correction', correction):
            revision = self.head_v3(key, meter)[0]
            absent.append(inspection_key_v1(key, revision + 1))
        for key in absent:
            if self.head_v3(key, meter)[0] != 0:
                raise AuthorityUnavailable('correction exact output/job/outbox/projection absence changed')
        guards = {}
        for kind in ('scheme', 'operator', 'policy'):
            row = self.point_v3(meter, 'graph_guard_versions', ('version',),
                'bot=? AND persona=? AND kind=? AND ref=?', (*self.namespace.as_tuple, kind, 'current'))
            if row is None:
                raise AuthorityUnavailable('correction installed guard version unavailable')
            guards[kind] = row[0]
        # Access payloads are genuine complete qualification cells. Only the
        # request basis is passed to the unchanged Domain compiler.
        for ref in self.request.source_refs:
            key = AtomKey.from_token(ref)
            access = access_key(*self.namespace.as_tuple, key.owner.subject)
            self.atoms[access] = GraphAtom(access, self.family.heads[access.token][0],
                dict(self.family.accesses[access.token]), True)
        self.snapshot = GraphSnapshot(tuple(self.atoms.values()), (self.graph_stamp[1],))
        self.reads = SourceCorrectionReadSetV1(
            tuple(SourceRecord.from_dict(self.bodies[ref].value) for ref in self.request.source_refs),
            tuple(self.atoms[access_key(*self.namespace.as_tuple, AtomKey.from_token(ref).owner.subject)].value
                for ref in self.request.source_refs),
            tuple(InterpretationRecord.from_dict(self.bodies[ref].value) for ref in self.request.target_refs),
            tuple(self.selected_beliefs))
        self.extra = {'read_versions': tuple(GraphVersion(AtomKey.from_token(token), head[0])
                for token, head in sorted(self.heads.items())),
            'query_epochs': (QueryEpoch(self.namespace, 'all', self.graph_stamp[1].revision),),
            'access_epoch': self.request.access_epoch, 'deletion_epoch': self.request.deletion_epoch,
            'guard_versions': guards, 'job_ref': job_ref, 'outbox_ref': outbox_ref,
            'correction_key': self.correction_key, 'selected_belief_refs': tuple(self.selected_beliefs),
            'belief_census_count': self.belief_count, 'belief_census_digest': self.belief_root}
        self.phase = 'result'
        self.reserve_v3()

    def advance_v3(self, meter):
        self.require_current_v3(meter)
        if self.inspection_current is not None:
            self._inspection_step_v3(meter)
        elif self.belief_current is not None:
            self._belief_step_v3(meter)
        elif self.body_current is not None:
            self._body_step_v3(meter)
        elif self.phase == 'targets':
            if self.target_queue:
                token = self.target_queue.pop(0)
                if token not in self.inspections:
                    self._start_inspection_v3(token, meter)
            else:
                self.phase = 'beliefs'
        elif self.phase == 'beliefs':
            self._belief_start_v3(meter)
        elif self.phase == 'belief_roots':
            if self.target_queue:
                token = self.target_queue.pop(0)
                if token not in self.inspections:
                    self._start_inspection_v3(token, meter)
            else:
                self.phase = 'producers'
        elif self.phase == 'family_begin':
            self.family = SourceCorrectionCommitFamilyV3(self, tuple(sorted(self.source_roots)))
            self.phase = 'family'
        elif self.phase == 'family':
            self.family._step(meter)
            if self.family.complete:
                self._family_complete_v3(meter)
        elif self.phase == 'bodies':
            self._body_start_v3(meter)
        elif self.phase == 'guards':
            self._guards_v3(meter)
        elif self.phase == 'producers':
            self._producer_step_v3(meter)
        elif self.phase == 'result':
            self.complete = True
            self.proof = PreparedSourceCorrectionCommitReadV3(_ISSUER, self)
            self.reserve_v3()

    def release_payload_v3(self):
        if self.closed:
            return
        if self.body_current is not None:
            self.body_current['column'].release_v3()
        if self.producer_current is not None:
            self.producer_current[2].release_v3()
        release_inspection_metadata_owner_v3(self)
        for original in tuple(self.bodies.values()):
            _BODY_ORIGINALS.pop(original, None)
        if self.proof is not None:
            _PROOFS.pop(self.proof, None)
        _READERS.pop(self, None)
        self.metadata_reads.release()
        self.heads.clear(); self.inspections.clear(); self.belief_metadata.clear()
        self.atoms.clear(); self.bodies.clear()
        self.snapshot = self.reads = self.extra = self.proof = self.body_current = self.producer_current = None
        if self.family is not None:
            self.family.release_v3()
        self.family = None
        self.closed = True


_BODY_ORIGINALS = WeakKeyDictionary()


class SourceCorrectionBodyOriginalV3:
    def __init__(self, issuer, owner, token, value, digest, byte_count):
        if issuer is not _ISSUER:
            raise AuthorityUnavailable('actual correction Body complete EOF producer required')
        self.owner, self.token, self.value = owner, token, value
        self.digest, self.byte_count = digest, byte_count
        _BODY_ORIGINALS[self] = owner, token, value, digest, byte_count


def require_source_correction_graph_atom_v3(original, *, key, revision, value, valid):
    if (type(original) is not SourceCorrectionBodyOriginalV3
            or _BODY_ORIGINALS.get(original) != (original.owner, original.token, original.value,
                original.digest, original.byte_count)
            or original.owner.closed or original.owner.operation.closed
            or original.token != key.token or original.value is not value or valid is not True
            or original.owner.heads[key.token][0] != revision):
        raise AuthorityUnavailable('correction graph atom requires its actual qualified complete Body EOF')
    return value


class PreparedSourceCorrectionCommitReadV3:
    def __init__(self, issuer, reader):
        if issuer is not _ISSUER or not reader.complete:
            raise AuthorityUnavailable('actual complete correction Source Work required')
        self.reader = reader
        _PROOFS[self] = reader.identity_v3()

    def _require_v3(self, db):
        r = self.reader
        if (_PROOFS.get(self) != r.identity_v3() or r.closed or r.operation.closed
                or r.db is not db or not r.complete or not r.read_finished):
            raise AuthorityUnavailable('correction proof left its actual request/retention')
        require_source_correction_commit_owner_v3(r)
        return r

    def materialize_v3(self, callback):
        r = self._require_v3(self.reader.db)
        with bind_runtime_storage_operation_v3(r.operation, r.db), r.store._lock:
            if r.db.in_transaction:
                raise AuthorityUnavailable('correction materialization requires its own READ transaction')
            r.db.execute('BEGIN')
            try:
                with runtime_storage_quantum_v3(r.db) as meter:
                    r.require_current_v3(meter)
                    return callback(r.snapshot, r.reads, r.extra)
            finally:
                r.db.rollback()

    @contextmanager
    def bind_for_write_v3(self, db, scope, owner_binding, session):
        r = self._require_v3(db)
        if (not db.in_transaction or scope.operation != 'write' or scope.namespace != r.namespace
                or owner_binding != r.owner_binding or session is not r.session_proof
                or runtime_storage_v3(db) is not r.operation.handle
                or scope.graph_revision != r.graph_stamp[0].graph_revision
                or scope.graph_epoch != r.graph_stamp[1]):
            raise AuthorityUnavailable('correction WRITE differs from its actual prepared Owner/readset')
        with runtime_storage_quantum_v3(db) as meter:
            r.require_current_v3(meter)
        token = _BOUND.set((self, db, scope))
        try:
            yield self
        finally:
            _BOUND.reset(token)

    def require_current_v3(self, db, *, meter):
        r = self._require_v3(db)
        binding = _BOUND.get()
        if binding is None or binding[:2] != (self, db) or binding[2].operation != 'write':
            raise AuthorityUnavailable('actual correction WRITE proof binding required')
        r.require_current_v3(meter)
        return r.extra

    def source_head_v3(self, source_ref):
        from ..domains.d04.source_head import D04SourceHead
        r = self._require_v3(self.reader.db)
        versions = current_source_correction_family_v3(r.db, namespace=r.namespace,
            roots=(source_ref,), purpose='context', audiences=('owner',))
        if versions is None:
            raise AuthorityUnavailable('actual correction WRITE metadata family binding required')
        sources = sorted((v.key.token, v.revision) for v in versions if v.key.type_name == 'memory.source')
        accesses = sorted((v.key.token, v.revision) for v in versions if v.key.type_name == 'memory.access')
        return D04SourceHead('sha256:' + canonical_digest(sources),
            'sha256:' + canonical_digest(accesses), True)

    def release_payload_v3(self):
        self.reader.release_payload_v3()



def current_source_correction_guard_snapshot_v3(db, *, bundle):
    """Only the actual correction WRITE may reuse its qualified sparse Body set."""
    binding = _BOUND.get()
    if binding is None:
        return None
    from ..runtime_contracts import DomainBundle
    proof, actual_db, scope = binding
    r = proof._require_v3(db)
    if (type(bundle) is not DomainBundle or actual_db is not db or not db.in_transaction
            or scope.operation != 'write' or scope.operation_id != r.request.operation_id
            or scope.namespace != r.namespace or bundle.envelope.authority is not r.source_authority
            or bundle.envelope.authority.namespace != r.namespace
            or bundle.envelope.authority.purpose != 'context'
            or bundle.envelope.authority.audience != ('owner',)
            or bundle.envelope.identity.operation_id != r.request.operation_id
            or bundle.envelope.identity.phase != 'source-correction'
            or bundle.envelope.version_guard.read_versions != r.extra['read_versions']
            or bundle.envelope.version_guard.query_epochs != r.extra['query_epochs']):
        raise AuthorityUnavailable('correction sparse snapshot differs from its actual WRITE/request/full CAS')
    with runtime_storage_quantum_v3(db) as meter:
        proof.require_current_v3(db, meter=meter)
    return r.snapshot


def current_source_correction_family_v3(db, *, namespace, roots, purpose, audiences):
    binding = _BOUND.get()
    if binding is None:
        return None
    proof, actual_db, scope = binding
    r = proof._require_v3(db)
    if (db is not actual_db or namespace != r.namespace or purpose != 'context'
            or tuple(audiences) != ('owner',) or not db.in_transaction or scope.operation != 'write'):
        raise AuthorityUnavailable('correction metadata family crossed its exact WRITE authority')
    with runtime_storage_quantum_v3(db) as meter:
        r.require_current_v3(meter)
    pending, seen, versions = list(roots), set(), {}
    while pending:
        ref = pending.pop()
        if ref in seen:
            continue
        if ref not in r.family.sources:
            raise AuthorityUnavailable('correction WRITE asks for an unqualified Source root')
        seen.add(ref)
        source = r.family.sources[ref][0]
        for key in (AtomKey.from_token(ref), access_key(*namespace.as_tuple, source['source_id']),
                source_correction_head_key(namespace, source['source_id'])):
            versions[key.token] = GraphVersion(key, r.family.heads[key.token][0])
        pending.extend(source_key(*namespace.as_tuple, sid).token for sid in source['parent_source_ids'])
    return tuple(versions[token] for token in sorted(versions))


def begin_source_correction_commit_read_v3(graph, *, request, authority, owner_authority,
        owner_binding, principal, session_proof, deadline, clock_reading, correction_key):
    r = _SourceCorrectionCommitReadV3(graph, request=request, authority=authority,
        owner_authority=owner_authority, owner_binding=owner_binding, principal=principal,
        session_proof=session_proof, deadline=deadline, clock_reading=clock_reading,
        correction_key=correction_key)
    try:
        r.work = create_graph_storage_work_v3(graph, kind=KIND, operation_id=r.operation.operation_id,
            selection_digest=r.selection_digest, deadline_utc=deadline, state=r, operation=r.operation)
        _READERS[r] = r.identity_v3()
        return r.work
    except BaseException:
        try:
            graph._finish_read_fence_v3(r.fence)
        finally:
            r.release_payload_v3()
            finish_runtime_storage_operation_v3(r.operation)
        raise


def advance_source_correction_commit_read_v3(graph, work):
    r = work.state
    if type(r) is not _SourceCorrectionCommitReadV3 or r.graph is not graph:
        raise AuthorityUnavailable('actual correction Source Work required')
    with bind_runtime_storage_operation_v3(r.operation, r.db):
        with runtime_storage_quantum_v3(r.db):
            graph._validate_read_fence_v3(r.fence)
        with r.store._lock:
            if r.db.in_transaction:
                raise AuthorityUnavailable('correction Work requires its own READ quantum')
            r.db.execute('BEGIN')
            try:
                with runtime_storage_quantum_v3(r.db) as meter:
                    r.advance_v3(meter)
            finally:
                r.db.rollback()
    return GraphStorageStepV3('complete', r.proof) if r.complete else GraphStorageStepV3('progress')


def finish_source_correction_commit_read_v3(graph, work, error):
    r = work.state
    if type(r) is not _SourceCorrectionCommitReadV3 or r.graph is not graph:
        raise AuthorityUnavailable('correction finish crossed its actual Work')
    failure = error
    try:
        graph._finish_read_fence_v3(r.fence)
        r.read_finished = True
        if failure is None and not r.complete:
            raise AuthorityUnavailable('incomplete correction Source preparation')
    except BaseException as exc:
        if failure is None:
            failure = exc
    finally:
        if failure is None:
            work.result_lease = r.operation
        else:
            r.release_payload_v3()
            finish_runtime_storage_operation_v3(r.operation)
    if failure is not None:
        raise failure
