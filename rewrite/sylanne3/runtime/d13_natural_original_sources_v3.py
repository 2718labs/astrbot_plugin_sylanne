"""Independent same-Work Source ALL before an ordinary saved natural Body."""
from weakref import WeakKeyDictionary, WeakSet
import codecs
from hashlib import sha256

from ..authority_service.contract import AuthorityUnavailable
from ..graph_types import AtomKey, GraphVersion
from ..memory_types import access_key, source_key
from ..runtime_contracts import NamespaceId, QueryEpoch
from ..runtime_storage_v3 import RuntimeCellReadV3, _runtime_bounded_fixed_row_v3
from .c09_graph_row_codec_v2 import C09MemorySourceJSONStreamV3
from .source_correction_read_v3 import _heap

_ISSUER = object()
_TASKS = WeakKeyDictionary()
_READERS = WeakSet()
_PROOFS = WeakKeyDictionary()


def _actual_owner_v3(task, meter=None):
    from .current_graph_full_read_v3 import _OrdinaryFullReadV3
    from .dispatch_initial_source_read_v3 import HostNaturalSavedOriginalReadV3
    owner = task.owner
    if (type(task) is not HostNaturalSavedOriginalReadV3
            or type(owner) is not _OrdinaryFullReadV3
            or owner.work.state is not owner
            or owner.work.operation is not owner.operation
            or owner.operation.closed or not owner.graph_eof
            or owner.prefinal is None
            or task.parent_original_id != task.natural_meta[0]):
        raise AuthorityUnavailable('actual originating ordinary saved-original Source Work required')
    owner.work._require_invocation(owner.graph)
    owner.prefinal.require_current(meter=meter)
    return owner


class _NaturalOriginalSourceAllProofV3:
    def __init__(self, issuer, source):
        if issuer is not _ISSUER or source not in _READERS or not source.complete:
            raise TypeError('actual complete ordinary natural Source ALL issuer required')
        self.task, self.owner = source.task, source.owner
        self.operation, self.work = source.owner.operation, source.owner.work
        self.seal_column = source.task.natural_json['seal_json']
        self.columns = tuple(source.columns.items())
        self.audience, self.roots = source.audience, source.roots
        self.witnesses = tuple(sorted(source.witnesses.items()))
        self.rights_versions = tuple(source.rights_versions)
        self.eofs = tuple(source.eofs)
        _PROOFS[self] = self._identity()

    def _identity(self):
        return (self.task, self.owner, self.operation, self.work, self.seal_column,
                self.seal_column.sha256, self.seal_column.byte_count,
                tuple((name, column, column.sha256, column.byte_count)
                      for name, column in self.columns), self.audience, self.roots,
                self.witnesses, self.rights_versions, self.eofs)

    def require_v3(self, task, meter=None):
        if (_PROOFS.get(self) != self._identity() or self.task is not task
                or _TASKS.get(task) is None or _TASKS[task].proof is not self
                or task.natural_json.get('seal_json') is not self.seal_column):
            raise AuthorityUnavailable('actual same-Work natural Source ALL proof required')
        owner = _actual_owner_v3(task, meter)
        if owner is not self.owner or owner.operation is not self.operation or owner.work is not self.work:
            raise AuthorityUnavailable('natural Source ALL original receiver changed')
        # The unchanged census stamp, access/deletion epochs and actual headers
        # keep these individually qualified, fully streamed members current.
        from .dispatch_current_inventory_v3 import _SOURCE_ISSUED
        for ref, witness in self.witnesses:
            expected = (owner.db, witness.source_key, witness.revision,
                        witness.valid, witness.cell_id, witness.header,
                        witness.payload_sha256, witness.metadata, witness.scope,
                        witness.graph_stamp, witness.query, witness.operation_id,
                        witness.selection_digest)
            if (_SOURCE_ISSUED.get(witness) != expected
                    or owner.sources.get(ref) is not witness
                    or owner.heads.get(ref) != (witness.revision, int(witness.valid), witness.cell_id)):
                raise AuthorityUnavailable('natural Source ALL current member identity changed')
        return self


class _NaturalOriginalSourceAllReadV3:
    def __init__(self, task):
        self.task, self.owner = task, _actual_owner_v3(task)
        self.phase, self.position = 'scope_header', 0
        self.columns, self.column = {}, None
        self.specs = ('read_versions_json', 'query_epochs_json', 'proof_json')
        self.scope_digest = self.seal = self.scope = None
        self.versions, self.roots, self.audience = {}, (), None
        self.pending, self.witnesses, self.metadata_records = [], {}, {}
        self.rights_versions, self.eofs = [], []
        self.cell = self.parser = self.witness = None
        self.semantic_decoder=self.semantic_hash=None
        self.fragment, self.offset = b'', 0
        self.complete, self.proof, self.reserved = False, None, 0
        _READERS.add(self)
        self._reserve()

    def _reserve(self):
        size = 65536 + _heap((self.columns, self.versions, self.roots, self.pending,
                             self.metadata_records, self.rights_versions, self.eofs, self.fragment))
        size += sum(_heap(dict(record.metadata)) + 1024 for record in self.metadata_records.values())
        if self.parser is not None:
            size += self.parser._source_heap_bytes()
        if size > self.reserved:
            self.owner.operation.retain(size - self.reserved)
            self.reserved = size

    def advance(self, meter):
        _actual_owner_v3(self.task, meter)
        if self.complete:
            return True
        self._reserve()
        self._advance(meter)
        self._reserve()
        return self.complete

    def _advance(self, meter):
        owner, ns = self.owner, self.owner.namespace
        db, prefinal = owner.db, owner.prefinal
        key = (*ns.as_tuple, self.task.parent_original_id)
        if self.phase == 'scope_header':
            row = _runtime_bounded_fixed_row_v3(db, meter,
                'graph_natural_generation_scopes_v2', ('original_seal_digest',),
                'bot=? AND persona=? AND parent_original_id=?', key)
            if row is None:
                raise AuthorityUnavailable('natural Source ALL original scoped metadata is absent')
            self.scope_digest = row[0]
            self.phase = 'metadata'
            return
        if self.phase == 'metadata':
            if self.position == len(self.specs):
                self.phase = 'bind'
                return
            name = self.specs[self.position]
            if self.column is None:
                from .dispatch_initial_source_read_v3 import DispatchOriginalJSONReadV3
                self.column = DispatchOriginalJSONReadV3(owner,
                    table=('graph_natural_generation_scopes_v2' if name == 'proof_json'
                           else 'graph_natural_generation_preparations_v2'),
                    column=name, key_columns=('bot', 'persona', 'parent_original_id'), key=key)
                return
            if self.column.advance(meter):
                self.columns[name] = self.column
                self.column = None
                self.position += 1
            return
        if self.phase == 'bind':
            from .natural_reply_job_v2 import _seal, natural_graph_guard_digest_v2
            from .natural_scoped_query_proof_v2 import natural_scoped_query_proof_from_wire_v2
            seal_column = self.task.natural_json.get('seal_json')
            if seal_column is None:
                raise AuthorityUnavailable('natural Source ALL actual seal metadata EOF is absent')
            self.seal = _seal('generation', seal_column.require_v3(owner))
            self.scope = natural_scoped_query_proof_from_wire_v2(self.columns['proof_json'].require_v3(owner))
            raw = self.columns['read_versions_json'].require_v3(owner)
            reads = tuple(GraphVersion(AtomKey.from_token(row['key']), row['revision']) for row in raw)
            queries = tuple(QueryEpoch(NamespaceId(**row['namespace']), row['scope_ref'], row['revision'])
                            for row in self.columns['query_epochs_json'].require_v3(owner))
            epochs = self.task.natural_meta[1:4]
            guard = natural_graph_guard_digest_v2(ns, reads, queries,
                graph_epoch=epochs[0], access_epoch=epochs[1], deletion_epoch=epochs[2])
            if (self.scope_digest != seal_column.sha256
                    or self.seal.namespace != ns or self.scope.scope.namespace != ns
                    or self.seal.c02_operation_id != self.task.parent_original_id
                    or self.seal.original_graph_guard_digest != guard):
                raise AuthorityUnavailable('natural Source ALL original seal/scope/readset metadata differs')
            self.versions = {row.key.token: row.revision for row in reads}
            # W01's actual original readset joins every qualified unit, producer
            # context and history selection before seal/guard and scope are saved
            # together. Its complete Source union is selected before any Body.
            self.roots = tuple(sorted(row.key.token for row in reads if row.key.type_name == 'memory.source'))
            required = {*self.scope.scope.source_roots, self.seal.source_ref}
            if not self.roots or not required.issubset(self.roots):
                raise AuthorityUnavailable('natural Source ALL complete original Source union is absent')
            for item in self.scope.d06_closure:
                if self.versions.get(item.token) != item.revision:
                    raise AuthorityUnavailable('natural Source ALL scoped original is outside its complete readset')
            self.audience = self.scope.scope.audience_id
            self.pending = list(self.roots)
            self.phase = 'rights'
            return
        if self.phase == 'rights':
            if not self.pending:
                self._require_acyclic_v3()
                self.position, self.phase = 0, 'cell'
                return
            ref = self.pending.pop()
            if ref in self.witnesses:
                return
            from ..domains.d06 import source_correction_head_key
            from ..domains.d07.qualified_attention_read import _qualify_source_rights_values_v3
            source = AtomKey.from_token(ref)
            if source != source_key(*ns.as_tuple, source.owner.subject or ''):
                raise AuthorityUnavailable('natural Source ALL source selector crosses its actual namespace')
            access = access_key(*ns.as_tuple, source.owner.subject)
            correction = source_correction_head_key(ns, source.owner.subject)
            witness = prefinal.source_metadata(db, ns, prefinal.query, source, require_grant=False, meter=meter)
            head = prefinal.correction_head(db, ns, prefinal.query, correction, meter=meter)
            access_atom = prefinal.projection.get(access)
            record = _qualify_source_rights_values_v3(ns, ref, witness, access_atom, head,
                audience=self.audience, purpose='expression', metadata_only=True)
            if record is None:
                raise AuthorityUnavailable('natural Source ALL current Source/Access/correction/purpose/audience is unavailable')
            versions = (GraphVersion(source, witness.revision), GraphVersion(access, access_atom.revision),
                        GraphVersion(correction, 0))
            if any(self.versions.get(row.key.token) != row.revision for row in versions):
                raise AuthorityUnavailable('natural Source ALL current ancestry differs from original readset')
            self.witnesses[ref], self.metadata_records[ref] = witness, record
            self.rights_versions.extend(versions)
            self.pending.extend(source_key(*ns.as_tuple, parent).token for parent in record.parent_source_ids)
            return
        if self.phase == 'cell':
            refs = tuple(sorted(self.witnesses))
            if self.position == len(refs):
                self.complete = True
                self.proof = _NaturalOriginalSourceAllProofV3(_ISSUER, self)
                return
            self.witness = self.witnesses[refs[self.position]]
            self.cell = RuntimeCellReadV3(owner.operation.handle, self.witness.cell_id,
                erasure_owner_ref=refs[self.position], meter=meter)
            if (tuple(self.cell.header) != tuple(self.witness.header)
                    or self.cell.header[0] not in ('canonical-json.ascii.v1', 'canonical-json.utf8.v1')):
                raise AuthorityUnavailable('natural Source ALL actual canonical Source cell differs')
            self.parser = C09MemorySourceJSONStreamV3(ensure_ascii=self.cell.header[0] == 'canonical-json.ascii.v1')
            self.semantic_decoder=(codecs.getincrementaldecoder('utf-8')('strict')
                if self.cell.header[0]=='canonical-json.utf8.v1'else None)
            self.semantic_hash=sha256()if self.semantic_decoder is not None else None
            self.phase = 'body'
            return
        if self.phase == 'body':
            if self.offset < len(self.fragment):
                end = min(self.offset + 1024, len(self.fragment))
                fragment=self.fragment[self.offset:end]
                self.parser.feed(fragment, lambda event: None)
                self._semantic_body_fragment_v3(fragment,meter)
                self.offset = end
                return
            fragment = self.cell.read_fragment(meter=meter)
            if fragment is not None:
                self.fragment, self.offset = fragment, 0
                return
            self.phase = 'eof'
            return
        if self.phase == 'eof':
            parsed, digest = self.parser.finish(), self.cell.finish(meter=meter)
            self._semantic_body_fragment_v3(b'',meter,final=True)
            original=owner.source_inspections[self.witness.source_key.token]
            original.require_v3(owner,meter)
            semantic=digest if self.semantic_hash is None else self.semantic_hash.hexdigest()
            if semantic!=original.semantic_digest:
                raise AuthorityUnavailable('qualified natural Source semantic digest differs from inspection original')
            metadata = {name: tuple(value) if type(value) is list else value
                        for name, value in self.parser._source_metadata.items()}
            if ((parsed.sha256, parsed.byte_count) != (digest, self.witness.header[3])
                    or digest != self.witness.payload_sha256 or metadata != dict(self.witness.metadata)):
                raise AuthorityUnavailable('natural Source ALL complete canonical EOF/SHA/metadata differs')
            self.eofs.append((self.witness.source_key.token, digest, parsed.byte_count))
            self.cell = self.parser = self.witness = None
            self.semantic_decoder=self.semantic_hash=None
            self.fragment, self.offset = b'', 0
            self.position += 1
            self.phase = 'cell'
            return
        raise AuthorityUnavailable('natural Source ALL actual Work phase differs')

    def _semantic_body_fragment_v3(self,fragment,meter,*,final=False):
        if self.semantic_decoder is None:return
        text=self.semantic_decoder.decode(fragment,final=final)
        parts=[]
        for char in text:
            point=ord(char)
            if point<127:parts.append(char)
            elif point<=65535:parts.append('\\u'+format(point,'04x'))
            else:
                point-=65536
                parts.append('\\u'+format(55296+(point>>10),'04x')+'\\u'+format(56320+(point&1023),'04x'))
        encoded=''.join(parts).encode('ascii')
        meter.charge_encode(len(encoded));self.semantic_hash.update(encoded)

    def _require_acyclic_v3(self):
        active, settled = set(), set()
        ns = self.owner.namespace
        pending = [(ref, False) for ref in self.roots]
        reserved = 0
        while pending:
            size = _heap((active, settled, pending))
            if size > reserved:
                self.owner.operation.retain(size - reserved)
                reserved = size
            ref, closing = pending.pop()
            if closing:
                active.remove(ref)
                settled.add(ref)
                continue
            if ref in settled:
                continue
            if ref in active:
                raise AuthorityUnavailable('natural Source ALL ancestry contains a cycle')
            active.add(ref)
            pending.append((ref, True))
            pending.extend((source_key(*ns.as_tuple, parent).token, False)
                           for parent in self.metadata_records[ref].parent_source_ids)


def advance_host_natural_original_source_all_v3(task, *, meter):
    """False keeps frozen_json queued; only this actual Source ALL can return True."""
    from .current_graph_full_read_v3 import _OrdinaryFullReadV3
    from .dispatch_initial_source_read_v3 import HostNaturalSavedOriginalReadV3
    if type(task) is not HostNaturalSavedOriginalReadV3 or type(task.owner) is not _OrdinaryFullReadV3:
        return True
    source = _TASKS.get(task)
    if source is None:
        source = _NaturalOriginalSourceAllReadV3(task)
        _TASKS[task] = source
    return source.advance(meter)


def require_host_natural_original_source_all_v3(task, *, meter=None):
    """Require the private proof for this exact saved-original receiver, before Body."""
    source = _TASKS.get(task)
    if source is None or source.proof is None:
        raise AuthorityUnavailable('independent before-frozen natural Source ALL is incomplete')
    return source.proof.require_v3(task, meter)


def release_host_natural_original_source_all_v3(owner):
    """Drop only this receiver's private retained streams at the existing Work release."""
    for task, source in tuple(_TASKS.items()):
        if source.owner is owner:
            _TASKS.pop(task, None)
            _READERS.discard(source)
            if source.proof is not None:
                _PROOFS.pop(source.proof, None)
            source.columns.clear()
            source.witnesses.clear()
            source.metadata_records.clear()
            source.cell = source.parser = source.proof = None
