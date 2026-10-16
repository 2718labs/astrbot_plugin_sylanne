"""Incremental Source correction context under an already admitted read fence.

The caller owns the actual fence and persistent storage lease. This reader never
acquires authority or substitutes a partial cell for a Source/Interpretation.
"""
from __future__ import annotations

import json
import sys
from hashlib import sha256

from ..graph_types import AtomKey, GraphVersion, Owner
from ..runtime_contracts import FenceScope, canonical_digest
from ..memory_types import (
    InterpretationRecord, _INTERPRETATION_FIELDS, source_key, access_key,
    interpretation_key,
)
from ..domains.d06 import source_correction_head_key
from ..runtime_storage_v3 import (
    RuntimeStorageOperationV3, runtime_storage_v3,
    bind_runtime_storage_operation_v3, runtime_storage_quantum_v3,
    begin_runtime_cell_read_v3,
)
from ..authority_service.contract import AuthorityUnavailable
from .c09_canonical_json_stream_v2 import C09CanonicalJSONStreamV2
from .c09_graph_row_codec_v2 import (
    C09MemorySourceJSONStreamV3, C09MemoryAccessJSONStreamV3,
)

_QUALIFIED = object()


def _heap(value, seen=None):
    """Count the retained payload containers, excluding installed capabilities."""
    if seen is None:
        seen = set()
    if id(value) in seen:
        return 0
    seen.add(id(value))
    size = sys.getsizeof(value)
    if type(value) is dict:
        return size + sum(_heap(k, seen) + _heap(v, seen) for k, v in value.items())
    if type(value) in (list, tuple, set):
        return size + sum(_heap(v, seen) for v in value)
    if type(value) in (GraphVersion, AtomKey, Owner, InterpretationRecord):
        return size + _heap(value.__dict__, seen)
    return size


class _InterpretationJSONStreamV3(C09CanonicalJSONStreamV2):
    """Registered interpretation metadata, including its bounded claim."""
    def __init__(self, owner):
        super().__init__(ensure_ascii=True)
        self.owner = owner
        self.fields, self.metadata, self.scalar = set(), {}, bytearray()

    def _emit(self, emit, kind, path, start, end, **values):
        if kind == 'key':
            if len(path) != 1 or values['key'] not in _INTERPRETATION_FIELDS:
                raise ValueError('interpretation fields must match exactly')
            self.fields.add(values['key'])
        elif kind == 'object_start' and path:
            raise ValueError('interpretation field cannot be an object')
        elif kind == 'array_start':
            if path != ('source_ids',):
                raise ValueError('interpretation array must be source_ids')
            self.metadata['source_ids'] = []
        elif kind == 'scalar_start':
            if (not path or len(path) > 2 or path[0] not in _INTERPRETATION_FIELDS
                    or path == ('source_ids',)
                    or len(path) == 2 and path[0] != 'source_ids'):
                raise ValueError('interpretation scalar has another registered path')
            self.scalar.clear()
        elif kind == 'scalar_chunk':
            self.owner._reserve(len(values['raw']) * 4 + 16384)
            self.scalar.extend(values['raw'])
        elif kind == 'scalar_end':
            self.owner._reserve(len(self.scalar) * 4 + 16384)
            value = json.loads(self.scalar)
            if len(path) == 1:
                self.metadata[path[0]] = value
            else:
                self.metadata['source_ids'].append(value)
            self.scalar.clear()
        super()._emit(emit, kind, path, start, end, **values)

    def finish(self):
        result = super().finish()
        if self.fields != _INTERPRETATION_FIELDS:
            raise ValueError('interpretation fields must match exactly')
        self.owner._reserve(_heap(self.metadata) + 16384)
        self.record = InterpretationRecord.from_dict(self.metadata)
        return result


class _SourceFamilyQualificationV3:
    def __init__(self, issuer, reader):
        if issuer is not _QUALIFIED:
            raise AuthorityUnavailable('actual completed Source family reader required')
        self.reader = reader

    def require_for(self, db, *, namespace, roots, purpose, audiences, read_scope, graph_stamp):
        reader = self.reader
        roots = tuple(roots)
        if (not reader.complete or reader.db is not db or reader.namespace != namespace
                or reader.purpose != purpose or reader.audiences != tuple(audiences)
                or reader.storage_lease.closed or roots not in reader.families
                or read_scope is not reader.read_scope or graph_stamp != reader.graph_stamp
                or read_scope.operation_id != reader.storage_lease.operation_id
                or reader.storage_lease.selection_digest != reader.selection_digest):
            raise AuthorityUnavailable('completed same-operation Source family qualification differs')
        return reader.families[roots]


class SourceCorrectionContextReadV3:
    """One real storage quantum per advance; FINAL still belongs to the caller."""
    def __init__(self, db, *, namespace, source_id, storage_lease, read_scope, graph_stamp,
                 purpose='context', audiences=('owner',)):
        handle = runtime_storage_v3(db)
        if (handle is None or type(storage_lease) is not RuntimeStorageOperationV3
                or storage_lease.closed or storage_lease.handle is not handle
                or type(read_scope) is not FenceScope or read_scope.namespace != namespace
                or read_scope.operation != 'read' or read_scope.operation_id != storage_lease.operation_id
                or type(graph_stamp) is not tuple or len(graph_stamp) != 2
                or graph_stamp[1] != read_scope.graph_epoch
                or graph_stamp[0].graph_revision != read_scope.graph_revision):
            raise AuthorityUnavailable('Source correction streaming requires actual selected storage operation')
        self.db, self.namespace, self.storage_lease = db, namespace, storage_lease
        self.read_scope, self.graph_stamp = read_scope, graph_stamp
        self.selection_digest = storage_lease.selection_digest
        self.purpose, self.audiences = purpose, tuple(audiences)
        self.source_id = source_id
        self.source_ref = source_key(*namespace.as_tuple, source_id).token
        self.complete = False
        self.context = None
        self.qualification = None
        self.readset = ()
        self.phase = 'epochs'
        self.epochs = None
        self.heads, self.sources, self.accesses, self.families = {}, {}, {}, {}
        self.targets = []
        self.jobs, self.active, self.done, self.family_keys = [], set(), set(), set()
        self.family_roots, self.family_after = (), None
        self.cursor, self.pending_target = '', None
        self.scan_count, self.scan_complete = 0, False
        self.scan_root = sha256(b'd12.source-correction-interpretation-scan.v3').hexdigest()
        self._readset_pending = []
        self.cell, self.parser, self.cell_kind, self.cell_token = None, None, None, None
        self.fragment, self.fragment_offset = b'', 0
        self.final_tokens, self.final_index = (), 0
        self._reserved = 0
        self._reserve(32768)

    def _payload_bytes(self):
        payload = (self.heads, self.sources, self.accesses, self.families,
                   self.targets, self.jobs, self.active, self.done, self.family_keys,
                   self.family_roots, self.pending_target, self.fragment,
                   self.final_tokens, self._readset_pending, self.readset, self.context)
        seen = set()
        size = _heap(payload, seen)
        if self.parser is not None:
            size += _heap(self.parser.__dict__, seen)
            size += _heap((self.parser._stack, self.parser._string,
                           self.parser._literal, self.parser._number, self.parser._active_scalar), seen)
        return size + 32768

    def _reserve(self, extra=0):
        required = self._payload_bytes() + extra
        if required > self._reserved:
            self.storage_lease.retain(required - self._reserved)
            self._reserved = required

    def _head(self, token, meter):
        meter.require_available(32768)
        row = meter.read_fixed_row(self.db, 'graph_atoms',
            ('revision', 'valid', 'value_cell_id'),
            'bot=? AND persona=? AND token=?', (*self.namespace.as_tuple, token))
        value = (0, None, None) if row is None else tuple(row)
        prior = self.heads.get(token)
        if prior is not None and prior != value:
            raise AuthorityUnavailable('Source correction head changed during streaming read')
        self._reserve(len(token) * 4 + 1024)
        self.heads[token] = value
        return value

    def _open(self, token, kind, meter):
        head = self._head(token, meter)
        if head[1] != 1 or head[2] is None:
            raise AuthorityUnavailable('current Source correction member is absent')
        self._reserve(32768)
        self.cell = begin_runtime_cell_read_v3(self.db, head[2])
        if self.cell.header[0] != 'canonical-json.ascii.v1':
            raise AuthorityUnavailable('Source correction requires its actual canonical ASCII JSON codec')
        self.cell_kind, self.cell_token = kind, token
        if kind == 'source':
            self.parser = C09MemorySourceJSONStreamV3(ensure_ascii=True)
        elif kind == 'access':
            self.parser = C09MemoryAccessJSONStreamV3(ensure_ascii=True)
        else:
            self.parser = _InterpretationJSONStreamV3(self)
        self.fragment, self.fragment_offset = b'', 0

    def _family(self, roots, after):
        self.family_roots, self.family_after = tuple(roots), after
        self.active, self.done, self.family_keys = set(), set(), set()
        self._reserve(_heap(roots) * 2 + 4096)
        self.jobs = [('enter', ref) for ref in reversed(self.family_roots)]
        self.phase = 'family'

    def _source_loaded(self, token):
        data = self.sources[token][0]
        self.jobs.append(('exit', token))
        for parent in reversed(data['parent_source_ids']):
            self.jobs.append(('enter', source_key(*self.namespace.as_tuple, parent).token))
        self.jobs.append(('correct', token))
        self.jobs.append(('access', token))

    def _cell_complete(self, digest):
        kind, token, parser = self.cell_kind, self.cell_token, self.parser
        if kind == 'source':
            data = parser._source_metadata
            if source_key(*self.namespace.as_tuple, data['source_id']).token != token:
                raise AuthorityUnavailable('Source canonical key/payload identity differs')
            self.sources[token] = (data, digest)
            self._source_loaded(token)
        elif kind == 'access':
            self.accesses[token] = parser.metadata
        else:
            self.scan_root = canonical_digest(('d12.source-correction-interpretation-scan.v3',
                self.scan_root, token, self.heads[token][0], digest))
            self.scan_count += 1
            record = parser.record
            if interpretation_key(*self.namespace.as_tuple, record.interpretation_id).token != token:
                raise AuthorityUnavailable('interpretation canonical key/payload identity differs')
            if self.source_id in record.source_ids:
                if len(self.targets) >= 100:
                    raise AuthorityUnavailable('correction target page exceeds its bounded contract')
                self.pending_target = {'target_ref': token, 'revision': self.heads[token][0],
                                       'digest': digest, 'claim': record.claim}
                self._reserve(sum(len(sid) * 12 + 512 for sid in record.source_ids) + 16384)
                roots = tuple(source_key(*self.namespace.as_tuple, sid).token for sid in record.source_ids)
                self._family(roots, 'target')
            else:
                # Unselected rows have complete canonical/origin proof but no
                # target dependency. The caller's original graph epoch closes
                # scan phantoms; keep only the keyset cursor across rows.
                del self.heads[token]
                self.phase = 'scan'
        self.cell, self.parser = None, None
        self.fragment, self.fragment_offset = b'', 0
        self._reserve()

    def _cell_step(self, meter):
        if self.fragment_offset < len(self.fragment):
            end = min(self.fragment_offset + 1024, len(self.fragment))
            self._reserve((end - self.fragment_offset) * 12 + 32768)
            self.parser.feed(self.fragment[self.fragment_offset:end], lambda event: None)
            self.fragment_offset = end
            return
        self._reserve(16384 + 32768)
        fragment = self.cell.read_fragment(meter=meter)
        if fragment is not None:
            self.fragment, self.fragment_offset = fragment, 0
            return
        self._reserve(32768)
        parsed = self.parser.finish()
        digest = self.cell.finish(meter=meter)
        if parsed.byte_count != self.cell.header[3] or parsed.sha256 != digest:
            raise AuthorityUnavailable('Source correction parser and sealed cell EOF differ')
        self._cell_complete(digest)

    def _family_step(self, meter):
        if not self.jobs:
            versions = tuple(GraphVersion(AtomKey.from_token(token), self.heads[token][0])
                             for token in sorted(self.family_keys))
            self._reserve(_heap(versions) + 16384)
            self.families[self.family_roots] = versions
            if self.family_after == 'target':
                self.targets.append(self.pending_target)
                self.pending_target = None
            self.phase = 'scan'
            return
        kind, token = self.jobs.pop()
        key = AtomKey.from_token(token)
        if key.owner.bot != self.namespace.bot_id or key.owner.persona != self.namespace.persona_id:
            raise AuthorityUnavailable('Source ancestry crossed namespace')
        if kind == 'enter':
            if token in self.active:
                raise AuthorityUnavailable('Source ancestry is cyclic')
            if token in self.done:
                return
            if len(self.done) + len(self.active) >= 32:
                raise AuthorityUnavailable('Source closure exceeds its bounded window')
            self.active.add(token)
            self.family_keys.add(token)
            if token in self.sources:
                self._source_loaded(token)
            else:
                self._open(token, 'source', meter)
        elif kind == 'exit':
            self.active.remove(token)
            self.done.add(token)
        elif kind == 'access':
            sid = self.sources[token][0]['source_id']
            ref = access_key(*self.namespace.as_tuple, sid).token
            self.family_keys.add(ref)
            if ref not in self.accesses:
                self._open(ref, 'access', meter)
        else:
            data = self.sources[token][0]
            sid = data['source_id']
            ref = source_correction_head_key(self.namespace, sid).token
            self.family_keys.add(ref)
            head = self._head(ref, meter)
            access = self.accesses[access_key(*self.namespace.as_tuple, sid).token]
            if (head[0] or access['source_id'] != sid or access['status'] != 'active'
                    or self.purpose not in data['purposes'] or self.purpose not in access['purposes']
                    or not set(self.audiences) <= set(data['audiences'])
                    or not set(self.audiences) <= set(access['audiences'])):
                raise AuthorityUnavailable('current Source/access/correction qualification is denied')
        self._reserve()

    def _epochs(self, meter):
        meter.require_available(1024)
        row = meter.read_fixed_row(self.db, 'graph_authority_epochs',
            ('access_epoch', 'delete_epoch'), 'bot=? AND persona=?', self.namespace.as_tuple)
        if row is None:
            raise AuthorityUnavailable('Source correction authority epochs are absent')
        return tuple(row)

    def _step(self, meter):
        if self.cell is not None:
            self._cell_step(meter)
        elif self.phase == 'epochs':
            self.epochs = self._epochs(meter)
            self._family((self.source_ref,), 'source')
        elif self.phase == 'family':
            self._family_step(meter)
        elif self.phase == 'scan':
            meter.require_available(32768)
            row = meter.read_fixed_row(self.db, 'graph_atoms', ('token',),
                "bot=? AND persona=? AND type_name='memory.interpretation' AND valid=1 AND token>? ORDER BY token",
                (*self.namespace.as_tuple, self.cursor))
            if row is None:
                self.scan_complete = True
                self._reserve(_heap(tuple(self.heads)) + 16384)
                self.final_tokens = tuple(sorted(self.heads))
                self.phase = 'recheck'
            else:
                self.cursor = row[0]
                self._open(self.cursor, 'interpretation', meter)
        elif self.phase == 'recheck':
            if self.final_index < len(self.final_tokens):
                token = self.final_tokens[self.final_index]
                self._head(token, meter)
                self._reserve(len(token) * 4 + 2048)
                self._readset_pending.append(GraphVersion(AtomKey.from_token(token), self.heads[token][0]))
                self.final_index += 1
            else:
                self.phase = 'result'
        elif self.phase == 'result':
            if self._epochs(meter) != self.epochs:
                raise AuthorityUnavailable('Source correction access/deletion epochs changed')
            self._reserve(_heap(self.heads) * 2 + 32768)
            self.readset = tuple(self._readset_pending)
            self.context = {'schema': 'd12.source-correction-context.v1',
                'namespace': {'bot_id': self.namespace.bot_id, 'persona_id': self.namespace.persona_id},
                'source_refs': [self.source_ref], 'source_revision': self.heads[self.source_ref][0],
                'source_digest': self.sources[self.source_ref][1], 'targets': self.targets,
                'access_epoch': self.epochs[0], 'deletion_epoch': self.epochs[1]}
            self.complete = True
            self.qualification = _SourceFamilyQualificationV3(_QUALIFIED, self)
            self._reserve()

    def advance(self):
        if self.complete:
            raise AuthorityUnavailable('Source correction read already completed')
        with bind_runtime_storage_operation_v3(self.storage_lease, self.db):
            with runtime_storage_quantum_v3(self.db) as meter:
                self._step(meter)
        return self


class PersonalEligibilityRecoverySourcesV1(SourceCorrectionContextReadV3):
    """Exact family-only front door; it never scans Interpretation claim bodies."""
    def __init__(self,db,*,roots,namespace,storage_lease,read_scope,graph_stamp,purpose,audiences):
        roots=tuple(roots)
        if not roots or len(roots)>32:raise AuthorityUnavailable("finite saved eligibility Source roots required")
        super().__init__(db,namespace=namespace,source_id=AtomKey.from_token(roots[0]).owner.subject,
            storage_lease=storage_lease,read_scope=read_scope,graph_stamp=graph_stamp,
            purpose=purpose,audiences=audiences)
        self.saved_roots=roots
    def _step(self,meter):
        if self.cell is None and self.phase=="epochs":
            self.epochs=self._epochs(meter);self._family(self.saved_roots,"eligibility");return
        if self.cell is None and self.phase=="scan":
            self.scan_complete=True;self.final_tokens=tuple(sorted(self.heads));self.phase="recheck";return
        super()._step(meter)
