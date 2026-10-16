"""Private full-EOF inventory prepared on the ordinary worker before P1/P2."""
from __future__ import annotations

from contextlib import asynccontextmanager, contextmanager
from dataclasses import dataclass, replace
from datetime import datetime
from hashlib import sha256
import json
import sys
from types import MappingProxyType
from weakref import WeakKeyDictionary, WeakSet

from ..authority_service.contract import AuthorityUnavailable
from ..graph_types import AtomKey, GraphAtom, OWNER_GRANT_TYPE, owner_grant_key
from ..runtime_contracts import QueryEpoch, canonical_digest
from ..graph_worker import GraphStorageStepV3, OwnedGraphStorageResultV3, create_graph_storage_work_v3, require_graph_storage_work_admission_v3
from ..runtime_storage_v3 import (begin_runtime_storage_operation_v3, bind_runtime_storage_operation_v3,
    finish_runtime_storage_operation_v3, runtime_storage_quantum_v3, runtime_storage_v3, begin_runtime_cell_read_v3)
from .c09_canonical_json_stream_v2 import C09CanonicalJSONStreamV2
from .c09_graph_row_codec_v2 import C09MemorySourceJSONStreamV3
from .source_correction_read_v3 import _heap
from .d11_types import _VALUE_TYPES,RuntimeJobValue

_RUNTIME_JOB_TYPE_V3=next(name for name,value_type in _VALUE_TYPES.items()if value_type is RuntimeJobValue)

_ISSUER = object()
_ISSUED = WeakKeyDictionary()
_SOURCE_ISSUED = WeakKeyDictionary()
_SUCCESSOR_ISSUED = WeakKeyDictionary()
_DISPATCH_TYPES = frozenset({'d03.role_binding','d05.boundary_rule','d08.goal.v1','d08.action_schema.v1',
    'd08.commitment.v1','d08.action_intent.v1','d08.action_outcome.v1','d08.action_cancellation.v1',
    'd10.contact_policy.v1','d10.proactive_opportunity.v1','d10.contact_claim.v1','d10.contact_claim.v2',
    'memory.access','d06.source_correction_head.v1',OWNER_GRANT_TYPE,'d03.account_binding','d03.entity_anchor',
    'd08.contact_expression_plan.v2','d08.contact_expression_plan_provenance.v2','d08.contact_expression_plan_eligibility.v2',
    'd03.world_event','d07.focus.v1','d07.attention_ticket.v1',_RUNTIME_JOB_TYPE_V3})


@dataclass(frozen=True)
class _FrozenObjectV3:
    items: tuple


@dataclass(frozen=True)
class _FrozenArrayV3:
    items: tuple


def _freeze_value_v3(value):
    if type(value) is dict:return _FrozenObjectV3(tuple((k,_freeze_value_v3(v))for k,v in value.items()))
    if type(value) is list:return _FrozenArrayV3(tuple(_freeze_value_v3(v)for v in value))
    return value


def _detach_value_v3(value):
    if type(value) is _FrozenObjectV3:return {k:_detach_value_v3(v)for k,v in value.items}
    if type(value) is _FrozenArrayV3:return [_detach_value_v3(v)for v in value.items]
    return value


@dataclass(frozen=True)
class _FrozenDispatchAtomV3:
    key: object
    revision: int
    value: object
    valid: bool
    retained_bytes: int


@dataclass(frozen=True)
class CurrentDispatchTypedProjectionV3:
    """Immutable evidence with reserved detached views; never a GraphSnapshot."""
    _atoms: tuple
    epochs: tuple
    _operation: object

    def _view(self,atom):
        self._operation.retain(atom.retained_bytes*4+512)
        return GraphAtom(atom.key,atom.revision,_detach_value_v3(atom.value),atom.valid)

    @property
    def atoms(self):
        self._operation.retain(256+len(self._atoms)*16)
        return tuple(self._view(atom)for atom in self._atoms)

    def get(self,key):
        atom=next((atom for atom in self._atoms if atom.key==key),None)
        return None if atom is None else self._view(atom)

    def atoms_for_types_v3(self,type_names):
        self._operation.retain(256+len(self._atoms)*16)
        return tuple(self._view(atom)for atom in self._atoms if atom.key.type_name in type_names)


class _DispatchSourceStreamV3(C09MemorySourceJSONStreamV3):
    """Real Source semantics or the exact valid=0 C09 erased marker, both EOF."""
    def __init__(self,reader,key,valid,**profile):
        self._inventory_reader,self._inventory_key,self._inventory_valid=reader,key,valid
        self.erased=None;self._marker_fields=set();self._marker_value={};self._marker_scalar=bytearray()
        super().__init__(**profile)

    def _source_heap_bytes(self):
        return super()._source_heap_bytes()+_heap((self._marker_fields,self._marker_value,self._marker_scalar))

    def _source_require_arena(self,extra=0):
        self._inventory_reader._reserve(extra if self._inventory_reader.parser is self else self._source_heap_bytes()+extra)
        super()._source_require_arena(extra)

    def _emit(self,emit,kind,path,start,end,**values):
        if kind=='key' and len(path)==1 and self.erased is None:
            self.erased=values['key']=='key_digest'
        if not self.erased:return super()._emit(emit,kind,path,start,end,**values)
        if kind=='key':
            if len(path)!=1 or values['key'] not in {'key_digest','schema'}:
                raise ValueError('erased Source marker fields differ')
            self._marker_fields.add(values['key'])
        elif kind in {'object_start','array_start'} and path:
            raise ValueError('erased Source marker cannot contain nested values')
        elif kind=='scalar_start':
            if len(path)!=1 or path[0] not in {'key_digest','schema'} or values.get('scalar_kind')!='string':
                raise ValueError('erased Source marker requires exact strings')
            self._marker_scalar.clear()
        elif kind=='scalar_chunk':
            self._source_require_arena(len(values['raw'])+1024)
            if len(self._marker_scalar)+len(values['raw'])>256:raise ValueError('erased Source marker scalar bound differs')
            self._marker_scalar.extend(values['raw'])
        elif kind=='scalar_end':
            self._marker_value[path[0]]=json.loads(self._marker_scalar)
            self._marker_scalar.clear()
        return C09CanonicalJSONStreamV2._emit(self,emit,kind,path,start,end,**values)

    def finish(self):
        if not self.erased:return super().finish()
        result=C09CanonicalJSONStreamV2.finish(self)
        if (self._inventory_valid!=0 or self._marker_fields!={'key_digest','schema'} or self._marker_value!={
                'schema':'sylanne3.graph.erased_value.v1','key_digest':canonical_digest(self._inventory_key.token)}):
            raise ValueError('actual bodyless erased Source marker is invalid')
        return result


class VerifiedDispatchSourceMetadataV3:
    @property
    def key(self):return self.source_key

    @property
    def source_id(self):return self.metadata['source_id']

    @property
    def speaker_id(self):return self.metadata['speaker_id']

    @property
    def source_kind(self):return self.metadata['source_kind']

    @property
    def assertion_status(self):return self.metadata['assertion_status']

    @property
    def audiences(self):return self.metadata['audiences']

    @property
    def recorded_at(self):return self.metadata['recorded_at']


    def __init__(self, issuer, reader, key, revision, valid, cell, header, digest, metadata):
        if issuer is not _ISSUER:
            raise TypeError('actual full-EOF dispatch Source reader required')
        self.source_key, self.revision, self.valid = key, revision, valid
        self.cell_id, self.header, self.payload_sha256 = cell, tuple(header), digest
        self.byte_count = header[3]
        self.metadata = MappingProxyType({name:tuple(value) if type(value) is list else value
            for name,value in metadata.items()})
        self.scope, self.graph_stamp, self.query = reader.fence.scope, reader.graph_stamp, reader.query
        self.operation_id, self.selection_digest = reader.operation.operation_id, reader.selection_digest
        _SOURCE_ISSUED[self] = (reader.db, self.source_key, self.revision, self.valid, self.cell_id,
            self.header, self.payload_sha256, self.metadata, self.scope, self.graph_stamp, self.query,
            self.operation_id, self.selection_digest)


class PreparedCurrentDispatchInventoryV3:
    def __init__(self, issuer, reader):
        if issuer is not _ISSUER or not reader.complete:
            raise TypeError('actual complete ordinary-worker dispatch inventory required')
        self.graph, self.db, self.namespace = reader.graph, reader.db, reader.namespace
        self.binding, self.admission, self.request = reader.binding, reader.admission, reader.request
        self.operation, self.selection_digest = reader.operation, reader.selection_digest
        self.scope, self.graph_stamp = reader.fence.scope, reader.graph_stamp
        self.query, self.authority_epochs, self.catalogue_hash = reader.query, reader.authority_epochs, reader.catalogue_hash
        self.leaf_count, self.ordered_root, self.full_eof = reader.count, reader.root, True
        self.projection = CurrentDispatchTypedProjectionV3(tuple(_FrozenDispatchAtomV3(atom.key,atom.revision,
            _freeze_value_v3(atom.value),atom.valid,_heap(atom.value))for atom in reader.atoms),
            (reader.graph_stamp[1],),reader.operation)
        self.sources, self.heads = MappingProxyType(dict(reader.sources)), MappingProxyType(dict(reader.heads))
        self.qualified_sources = frozenset(reader.qualified_sources)
        self.family=reader.family
        self.source_descriptors=reader.auxiliary.descriptors
        self.contact_birth=getattr(reader.auxiliary,'prepared_birth',None)
        self.natural_originals=getattr(reader.auxiliary,'natural_values',None)
        self.natural_history=getattr(reader.auxiliary,'natural_history',None)
        self._successors = WeakSet()
        _ISSUED[self] = (self.graph,self.db,self.namespace,self.binding,self.admission,self.request,self.operation,
            self.selection_digest,self.scope,self.graph_stamp,self.query,self.authority_epochs,self.catalogue_hash,
            self.leaf_count,self.ordered_root,self.projection,self.sources,self.heads,self.qualified_sources,
            self.family,self.source_descriptors,self.contact_birth,self.natural_originals,self.natural_history)

    def release_payload_v3(self):
        """Invalidate the ephemeral proof and detach payloads after real dispatch ends."""
        for successor in tuple(self._successors):successor.release_payload_v3()
        self._successors.clear()
        _ISSUED.pop(self,None)
        self.projection = self.sources = self.heads = None
        self.contact_birth=self.natural_originals=self.natural_history=None
        self.qualified_sources = frozenset()

    def _actual(self):
        expected = _ISSUED.get(self)
        actual = (self.graph,self.db,self.namespace,self.binding,self.admission,self.request,self.operation,
            self.selection_digest,self.scope,self.graph_stamp,self.query,self.authority_epochs,self.catalogue_hash,
            self.leaf_count,self.ordered_root,self.projection,self.sources,self.heads,self.qualified_sources,
            self.family,self.source_descriptors,self.contact_birth,self.natural_originals,self.natural_history)
        if expected is None or actual != expected or not self.full_eof or self.operation.closed:
            raise AuthorityUnavailable('actual dispatch inventory issuer/retention/EOF differs')

    def require_current(self, db, namespace, query, projection=None):
        self._actual()
        store = self.graph._GraphCoordinator__store
        if (db is not self.db or not db.in_transaction or not store._lock._is_owned()
                or namespace != self.namespace or query != self.query
                or projection is not None and projection is not self.projection
                or runtime_storage_v3(db) is not self.operation.handle
                or self.operation.selection_digest != self.selection_digest
                or self.graph._v2_graph_stamp(namespace) != self.graph_stamp
                or store._registry.catalogue_hash != self.catalogue_hash):
            raise AuthorityUnavailable('prepared dispatch graph/selection/query/catalogue changed')
        row = db.execute('SELECT access_epoch,delete_epoch FROM graph_authority_epochs WHERE bot=? AND persona=?',
            namespace.as_tuple).fetchone()
        if row is None or tuple(row) != self.authority_epochs:
            raise AuthorityUnavailable('prepared dispatch Source access/deletion epoch changed')
        owner_key = owner_grant_key(*namespace.as_tuple)
        expected_owner = self.heads.get(owner_key.token)
        owner = db.execute('SELECT revision,valid,value_cell_id FROM graph_atoms WHERE bot=? AND persona=? AND token=?',
            (*namespace.as_tuple,owner_key.token)).fetchone()
        if expected_owner is None or owner is None or tuple(owner) != expected_owner:
            raise AuthorityUnavailable('prepared dispatch current Owner head changed')
        return self.projection

    def require_for(self, context, binding, claimed, db, *, authority_snapshot):
        from ..authority_service.reverse_handoff import require_exact_reverse_handoff_identity
        from .dispatch_current_commitment_check import _require_prepared_claimed_delta
        require_exact_reverse_handoff_identity(context.permit.namespace,context,binding,claimed)
        if binding != self.binding or claimed.pending.binding != self.binding:
            raise AuthorityUnavailable('prepared dispatch actual execution binding changed')
        initial = _require_prepared_claimed_delta(claimed,context,authority_snapshot)
        if (initial != self.scope.pinned_anchor.execution_seq
                or claimed.pending.prepared_receipt.pending.before_anchor != self.scope.pinned_anchor):
            raise AuthorityUnavailable('dispatch inventory permits only its actual P1/P2 anchor delta')
        projection=self.require_current(db,self.namespace,self.query,self.projection)
        from .dispatch_initial_source_read_v3 import require_dispatch_source_originals_current_v3
        require_dispatch_source_originals_current_v3(self,db)
        from .current_graph_full_read_v3 import _qualify_bound_dispatch_full_read_v3
        _qualify_bound_dispatch_full_read_v3(self,db,context,binding,claimed,authority_snapshot)
        return projection

    def atoms_for(self, db, namespace, query, type_names, *, valid_only=True):
        self.require_current(db,namespace,query)
        self.operation.retain(128+len(self.projection._atoms)*16)
        return tuple(self.projection._view(atom)for atom in self.projection._atoms
            if atom.key.type_name in type_names and (atom.valid or not valid_only))

    def atom_rows(self, db, namespace, query, type_names, columns, *, valid_only=True, name=None):
        atoms = self.atoms_for(db,namespace,query,type_names,valid_only=valid_only)
        self.operation.retain(128+len(atoms)*(128+len(columns)*16))
        return tuple(tuple({'token':atom.key.token,'revision':atom.revision,'valid':int(atom.valid),
            'type_name':atom.key.type_name,'value':atom.value}[column] for column in columns)
            for atom in atoms if name is None or atom.key.name == name)

    def source_metadata(self, db, namespace, query, key, *, revision=None, require_grant=True):
        self.require_current(db,namespace,query)
        if require_grant and key.token not in self.qualified_sources:
            raise AuthorityUnavailable('dispatch Source has no original expression grant qualification')
        source = self.sources.get(key.token)
        issued = None if source is None else _SOURCE_ISSUED.get(source)
        actual = None if source is None else (db,source.source_key,source.revision,source.valid,source.cell_id,
            source.header,source.payload_sha256,source.metadata,source.scope,source.graph_stamp,source.query,
            source.operation_id,source.selection_digest)
        if (source is None or issued is None or issued != actual or issued[0] is not db or source.source_key != key
                or not source.valid or revision is not None and source.revision != revision
                or source.scope is not self.scope or source.graph_stamp != self.graph_stamp
                or source.query != query or source.operation_id != self.operation.operation_id
                or source.selection_digest != self.selection_digest):
            raise AuthorityUnavailable('current fulltyped Source metadata identity differs')
        head = db.execute('SELECT revision,valid,value_cell_id FROM graph_atoms WHERE bot=? AND persona=? AND token=?',
            (*namespace.as_tuple,key.token)).fetchone()
        if head is None or tuple(head) != (source.revision,int(source.valid),source.cell_id):
            raise AuthorityUnavailable('current Source head differs from its full-EOF witness')
        return source

    def source_family(self,db,roots,*,purpose,audiences,allow_corrected=False,max_roots=32,max_heads=96):
        from ..domains.d06 import source_correction_head_key
        from ..memory_types import source_key,access_key,validate_access
        self.require_current(db,self.namespace,self.query)
        if type(roots) is not tuple or not roots or len(roots)>max_roots:
            raise AuthorityUnavailable('actual bounded Source roots required')
        self.operation.retain(65536)
        active,done,records=set(),set(),{}
        def visit(ref):
            key=AtomKey.from_token(ref)
            if key!=source_key(*self.namespace.as_tuple,key.owner.subject or ''):
                raise AuthorityUnavailable('actual Source family is outside its canonical namespace')
            if ref in active:raise AuthorityUnavailable('actual Source family is cyclic')
            if ref in done:return
            if 3*(len(active)+len(done)+1)>max_heads:
                raise AuthorityUnavailable('actual Source family exceeds its original bounded head count')
            source=self.source_metadata(db,self.namespace,self.query,key,require_grant=False)
            access=self.projection.get(access_key(*self.namespace.as_tuple,key.owner.subject))
            correction=self.correction_head(db,self.namespace,self.query,source_correction_head_key(self.namespace,key.owner.subject))
            if access is None or not access.valid:raise AuthorityUnavailable('actual Source access is unavailable')
            validate_access(access.value);metadata=source.metadata
            if (metadata['source_id']!=key.owner.subject or access.value['source_id']!=metadata['source_id']
                    or access.value['status']!='active' or purpose not in metadata['purposes']
                    or purpose not in access.value['purposes'] or not set(audiences)<=set(metadata['audiences'])
                    or not set(audiences)<=set(access.value['audiences'])
                    or not allow_corrected and correction is not None):
                raise AuthorityUnavailable('actual Source family purpose/audience/correction permission differs')
            active.add(ref)
            for parent in metadata['parent_source_ids']:visit(source_key(*self.namespace.as_tuple,parent).token)
            active.remove(ref);done.add(ref);records[ref]=source
        for root in roots:visit(root)
        return records

    def correction_head(self, db, namespace, query, key):
        self.require_current(db,namespace,query)
        return self.projection.get(key)


class _CurrentNamespaceInventoryKernelV3:
    """Shared actual namespace keyset and cell EOF; projections never claim census coverage."""
    def __init__(self,graph,operation,fence,*,projection_types,selected_tokens,census_schema,leaf_schema):
        self.graph=graph
        self.store,self.db=graph._GraphCoordinator__store,graph._GraphCoordinator__store._db
        self._initialize_storage_kernel_v3(operation,fence,namespace=fence.scope.namespace,
            graph_stamp=(fence.metadata,fence.epoch),catalogue_hash=self.store._registry.catalogue_hash,
            projection_types=projection_types,selected_tokens=selected_tokens,
            census_schema=census_schema,leaf_schema=leaf_schema)

    def _initialize_storage_kernel_v3(self,operation,fence,*,namespace,graph_stamp,catalogue_hash,
            projection_types,selected_tokens,census_schema,leaf_schema):
        self.namespace=namespace
        self.operation,self.fence=operation,fence
        self.selection_digest=operation.selection_digest
        self.graph_stamp=graph_stamp
        self.query=QueryEpoch(namespace,'all',graph_stamp[1].revision)
        self.catalogue_hash=catalogue_hash
        self.projection_types,self.selected_tokens=projection_types,selected_tokens
        self.census_schema,self.leaf_schema=census_schema,leaf_schema
        self.authority_epochs=None
        self.atoms,self.sources,self.heads=[],{},{}
        self.cursor,self.count='',0
        self.root=canonical_digest((census_schema,namespace,self.query,self.selection_digest))
        self.cell,self.parser,self.pending=None,None,None
        self.fragment,self.offset,self.body=b'',0,None
        self.complete,self.result,self.graph_eof=False,None,False
        self.reserved=0
        self._reserve(65536)

    def _reserve(self, extra=0):
        seen = set()
        size = _heap((self.heads,self.body,self.fragment),seen) + sys.getsizeof(self.atoms) + sys.getsizeof(self.sources)
        for atom in self.atoms:
            size += sys.getsizeof(atom) + _heap(atom.key,seen) + _heap(atom.value,seen)
        for token,source in self.sources.items():
            size += _heap(token,seen) + sys.getsizeof(source) + sys.getsizeof(source.__dict__)
            size += sys.getsizeof(source.metadata) + sum(_heap(k,seen)+_heap(v,seen) for k,v in source.metadata.items())
        if self.parser is not None and isinstance(self.parser,C09MemorySourceJSONStreamV3):
            size += self.parser._source_heap_bytes()
        size += extra + 65536
        if size > self.reserved:
            self.operation.retain(size-self.reserved)
            self.reserved = size


    def _epochs(self, meter):
        meter.require_available(32768)
        row = meter.read_fixed_row(self.db,'graph_authority_epochs',('access_epoch','delete_epoch'),
            'bot=? AND persona=?',self.namespace.as_tuple)
        if row is None:raise AuthorityUnavailable('actual Source authority epochs absent')
        return tuple(row)


    def _next(self, meter):
        meter.require_available(32768)
        row = meter.read_fixed_row(self.db,'graph_atoms',('token','revision','valid','type_name','value_cell_id'),
            'bot=? AND persona=? AND token>? ORDER BY token',(*self.namespace.as_tuple,self.cursor))
        if row is None:
            if self._epochs(meter) != self.authority_epochs:
                raise AuthorityUnavailable('dispatch inventory Source epochs changed before EOF')
            self.graph_eof=True
            self._graph_eof_v3()
            return
        token,revision,valid,type_name,cell = row
        key = AtomKey.from_token(token)
        if ((key.owner.bot,key.owner.persona) != self.namespace.as_tuple or key.type_name != type_name
                or type(revision) is not int or revision < 1 or valid not in (0,1) or cell is None):
            raise AuthorityUnavailable('full dispatch inventory contains an invalid graph head')
        self.store._validate_key(key)
        self.cursor = token
        self.pending = (key,revision,valid,type_name,cell)
        self.cell = begin_runtime_cell_read_v3(self.db,cell,erasure_owner_ref=token)
        codec = self.cell.header[0]
        if codec not in ('canonical-json.ascii.v1','canonical-json.utf8.v1'):
            raise AuthorityUnavailable('dispatch graph value is not actual canonical JSON')
        self.parser = (_DispatchSourceStreamV3(self,key,valid,ensure_ascii=codec=='canonical-json.ascii.v1')
            if type_name=='memory.source' else C09CanonicalJSONStreamV2(ensure_ascii=codec=='canonical-json.ascii.v1'))
        retain = type_name != 'memory.source' and (type_name in self.projection_types or token in self.selected_tokens)
        self._reserve(self.cell.header[3]*8+32768 if retain else 32768)
        self.body = bytearray() if retain else None


    def _cell(self, meter):
        if self.offset < len(self.fragment):
            end = min(self.offset+1024,len(self.fragment))
            self._reserve(65536)
            part = self.fragment[self.offset:end]
            self.parser.feed(part,lambda event:None)
            if self.body is not None:self.body.extend(part)
            self.offset = end
            return
        fragment = self.cell.read_fragment(meter=meter)
        if fragment is not None:
            self.fragment,self.offset = fragment,0
            return
        parsed = self.parser.finish()
        digest = self.cell.finish(meter=meter)
        if parsed.byte_count != self.cell.header[3] or parsed.sha256 != digest:
            raise AuthorityUnavailable('dispatch inventory logical digest/header/fullEOF differ')
        key,revision,valid,type_name,cell = self.pending
        self.root = canonical_digest((self.leaf_schema,self.root,key.token,
            revision,valid,type_name,digest,cell,tuple(self.cell.header)))
        self.count += 1
        if type_name=='memory.source' and not self.parser.erased:
            metadata = self.parser._source_metadata
            if metadata['source_id'] != key.owner.subject or key.name != 'record':
                raise AuthorityUnavailable('fulltyped Source canonical identity changed')
            self._reserve(_heap(metadata)*4+32768)
            self.sources[key.token] = VerifiedDispatchSourceMetadataV3(_ISSUER,self,key,revision,bool(valid),
                cell,self.cell.header,digest,metadata)
            self.heads[key.token] = (revision,valid,cell)
        elif self.body is not None:
            self._reserve(len(self.body)*8+32768)
            value = json.loads(self.body)
            self.atoms.append(GraphAtom(key,revision,value,bool(valid)))
            self.heads[key.token] = (revision,valid,cell)
        self.cell,self.parser,self.pending = None,None,None
        self.fragment,self.offset,self.body = b'',0,None
        self._reserve()


    def _graph_eof_v3(self):
        raise NotImplementedError("actual registered producer EOF disposition required")


class _DispatchInventoryReadV3(_CurrentNamespaceInventoryKernelV3):
    def __init__(self,graph,authority,lease,binding,admission,request,operation,fence,family,now_utc):
        self.authority,self.lease,self.binding,self.admission,self.request=authority,lease,binding,admission,request
        self.family,self.now_utc,self.auxiliary=family,now_utc,None
        self.qualified_sources=set()
        selected=frozenset({ref for ref,_ in admission.admission.graph_reads}
            | {item.ref for check in admission.admission.check_receipts for item in check.input_versions})
        super().__init__(graph,operation,fence,projection_types=_DISPATCH_TYPES,selected_tokens=selected,
            census_schema='sylanne.dispatch-full-inventory.v3',leaf_schema='sylanne.dispatch-full-inventory-leaf.v3')

    def _graph_eof_v3(self):
        from .dispatch_initial_source_read_v3 import DispatchInitialSourceReadsV3
        self.auxiliary=DispatchInitialSourceReadsV3(self,self.family,self.now_utc)

    def _qualify_sources(self):
        from ..domains.d08 import GoalExecutionProvider
        from ..domains.d06 import source_correction_head_key
        from ..memory_types import source_key,access_key,validate_access
        self._reserve(65536)
        spec = next(spec for spec in GoalExecutionProvider().register_types() if spec.name=='d08.action_intent.v1')
        selected = [spec.validator(atom.value) for atom in self.atoms if atom.valid
            and atom.key.type_name=='d08.action_intent.v1' and atom.key.name==self.admission.admission.action_ref]
        if (len(selected)!=1 or selected[0].identity.operation_id!=self.binding.operation_id
                or selected[0].identity.effect_id!=self.binding.origin.effect_id
                or canonical_digest(selected[0])!=self.admission.admission.action_intent_digest):
            raise AuthorityUnavailable('inventory Source roots lack the actual selected admitted action')
        self.qualified_sources=self._require_source_roots_v3(tuple(selected[0].source_refs),'expression',self.admission.admission.audience)


    def _require_source_roots_v3(self,roots,purpose,audiences):
        from ..domains.d06 import source_correction_head_key
        from ..memory_types import source_key,access_key,validate_access
        active,done = set(),set()
        by_token = {atom.key.token:atom for atom in self.atoms}
        def visit(ref):
            if ref in active:raise AuthorityUnavailable('dispatch Source ancestry is cyclic')
            if ref in done:return
            if len(done)+len(active)>=32:raise AuthorityUnavailable('dispatch Source closure exceeds original parent bound')
            key = AtomKey.from_token(ref)
            source = self.sources.get(ref)
            if (source is None or not source.valid or key!=source_key(*self.namespace.as_tuple,source.metadata['source_id'])):
                raise AuthorityUnavailable('dispatch actual current Source is unavailable')
            access = by_token.get(access_key(*self.namespace.as_tuple,source.metadata['source_id']).token)
            correction = source_correction_head_key(self.namespace,source.metadata['source_id'])
            if correction.token in by_token or access is None or not access.valid:
                raise AuthorityUnavailable('dispatch Source correction/access closure is unavailable')
            validate_access(access.value)
            if (access.value['source_id']!=source.metadata['source_id'] or access.value['status']!='active'
                    or purpose not in source.metadata['purposes'] or purpose not in access.value['purposes']
                    or not set(audiences)<=set(source.metadata['audiences'])
                    or not set(audiences)<=set(access.value['audiences'])):
                raise AuthorityUnavailable('dispatch Source lacks its actual expression/audience grant')
            active.add(ref)
            for parent in source.metadata['parent_source_ids']:
                visit(source_key(*self.namespace.as_tuple,parent).token)
            active.remove(ref);done.add(ref)
        for ref in dict.fromkeys(roots):visit(ref)
        return done


    def advance(self):
        with bind_runtime_storage_operation_v3(self.operation,self.db):
            with runtime_storage_quantum_v3(self.db) as meter:
                if self.authority_epochs is None:self.authority_epochs = self._epochs(meter)
                elif self.graph_eof:
                    self.db.execute('BEGIN')
                    try:
                        if self.auxiliary.advance(meter):
                            self._qualify_sources();self.complete=True;self._reserve(self.reserved+65536)
                            self.result=PreparedCurrentDispatchInventoryV3(_ISSUER,self)
                    finally:self.db.rollback()
                elif self.cell is None:self._next(meter)
                else:self._cell(meter)
        return self


def prepare_current_dispatch_inventory_v3(graph, authority, lease, *, binding, admission, request, permit, now_utc, dispatch_family):
    from ..authority_service.v2_contract import ExecutionBindingV2
    from .dispatch_admission import load_admission
    from .dispatch_binding_v2 import build_non_authorizing_execution_binding_v2
    require_graph_storage_work_admission_v3(graph)
    graph._authorize(lease,authority,frozenset({'d08','d09','d11'}))
    if type(binding) is not ExecutionBindingV2 or binding.origin.permit != permit:
        raise AuthorityUnavailable('actual initial execution binding and original dispatch permit required')
    exact = build_non_authorizing_execution_binding_v2(namespace=authority.namespace,admission_receipt=admission,
        recovered_request=request,original_dispatch_permit=permit,adapter_ref=binding.origin.adapter_ref,now_utc=now_utc)
    if exact != binding:raise AuthorityUnavailable('initial admitted dispatch request/binding changed')
    store,db = graph._GraphCoordinator__store,graph._GraphCoordinator__store._db
    deadline = datetime.fromisoformat(binding.utc_deadline.replace('Z','+00:00')).timestamp()
    operation = begin_runtime_storage_operation_v3(db,'dispatch-inventory:'+binding.operation_id,deadline)
    fence = None
    try:
        with bind_runtime_storage_operation_v3(operation,db):
            fence = graph._begin_read_fence_v3(authority,operation_id=operation.operation_id)
            with store._lock,runtime_storage_quantum_v3(db):
                if db.in_transaction:raise AuthorityUnavailable('inventory preparation cannot inherit a transaction')
                db.execute('BEGIN')
                try:
                    if load_admission(db,authority.namespace,binding.origin.admission_ref) != admission:
                        raise AuthorityUnavailable('initial actual durable dispatch admission differs')
                finally:db.rollback()
            reader = _DispatchInventoryReadV3(graph,authority,lease,binding,admission,request,operation,fence,dispatch_family,now_utc)
        return create_graph_storage_work_v3(graph,kind='dispatch_inventory_prepare_v3',operation_id=operation.operation_id,
            selection_digest=operation.selection_digest,deadline_utc=deadline,state=reader,operation=operation)
    except BaseException:
        try:
            if fence is not None:graph._finish_read_fence_v3(fence)
        finally:finish_runtime_storage_operation_v3(operation)
        raise


def advance_current_dispatch_inventory_v3(graph,work):
    reader = work.state
    if type(reader) is not _DispatchInventoryReadV3 or reader.graph is not graph or reader.operation is not work.operation:
        raise AuthorityUnavailable('actual same-operation dispatch inventory work required')
    with bind_runtime_storage_operation_v3(work.operation,reader.db):
        graph._authorize(reader.lease,reader.authority,frozenset({'d08','d09','d11'}))
        graph._validate_read_fence_v3(reader.fence)
        with reader.store._lock:
            if reader.db.in_transaction:raise AuthorityUnavailable('dispatch inventory continuation retained a transaction')
            if graph._v2_graph_stamp(reader.namespace) != reader.graph_stamp:
                raise AuthorityUnavailable('dispatch inventory original graph stamp changed')
            reader.advance()
        graph._validate_read_fence_v3(reader.fence)
    return GraphStorageStepV3('complete',reader.result) if reader.complete else GraphStorageStepV3('progress')


def finish_current_dispatch_inventory_v3(graph,work,error):
    from .dispatch_initial_source_read_v3 import detach_dispatch_preparation_workspace_v3
    reader=work.state
    try:
        graph._finish_read_fence_v3(reader.fence)
        if error is None:work.result_lease=work.operation
    except BaseException:
        detach_dispatch_preparation_workspace_v3(reader)
        finish_runtime_storage_operation_v3(work.operation)
        raise
    finally:
        detach_dispatch_preparation_workspace_v3(reader)
        reader.cell=reader.parser=reader.pending=reader.body=reader.fragment=reader.result=None
        reader.atoms=reader.sources=reader.heads=None
    if error is not None:finish_runtime_storage_operation_v3(work.operation)


@asynccontextmanager
async def prepare_dispatch_inventory_on_worker_v3(worker,authority,lease,*,binding,admission,request,permit,now_utc,dispatch_family):
    owned = await worker.call(lambda graph: graph._prepare_current_dispatch_inventory_v3(authority,lease,
        binding=binding,admission=admission,request=request,permit=permit,now_utc=now_utc,dispatch_family=dispatch_family))
    if owned is None:
        yield None
        return
    if type(owned) is not OwnedGraphStorageResultV3:
        raise AuthorityUnavailable('actual worker retained dispatch inventory required')
    value,retention = owned.take_value_v3()
    try:
        if type(value) is not PreparedCurrentDispatchInventoryV3:
            raise AuthorityUnavailable('actual private prepared dispatch inventory required')
        value._actual()
        yield value
    finally:
        if type(value) is PreparedCurrentDispatchInventoryV3:value.release_payload_v3()
        value = None
        retention.release()


@contextmanager
def bind_prepared_dispatch_inventory_v3(proof,db):
    if proof is None:
        yield None
        return
    proof._actual()
    if proof.db is not db:raise AuthorityUnavailable('prepared dispatch retention belongs to another database')
    from .current_graph_full_read_v3 import _bind_prepared_dispatch_full_read_v3
    with _bind_prepared_dispatch_full_read_v3(proof,proof.graph,db):
        yield proof


class _DispatchCommittedDeltaCaptureV3:
    """An actual final transaction capture; it cannot issue coverage before COMMIT."""
    def __init__(self,issuer,base,writer,context,binding,claimed):
        if issuer is not _ISSUER:raise TypeError('actual Contact final transaction capture required')
        base._actual()
        self.base,self.writer,self.context,self.binding,self.claimed=base,writer,context,binding,claimed
        self.pending=None

    def capture(self,graph,db,candidate,receipt,before_stamp,after_stamp):
        from ..graph_types import GraphCandidate,GraphReceipt
        from .dispatch_graph_claim import dispatch_claim_key
        from .contact_p2_qualification_v1 import contact_p2_graph_proof_key_v1
        if (graph is not self.base.graph or db is not self.base.db or not db.in_transaction
                or type(candidate) is not GraphCandidate or type(receipt) is not GraphReceipt
                or receipt.status!='committed' or before_stamp!=self.base.graph_stamp
                or candidate.epochs!=(before_stamp[1],) or receipt.epoch!=after_stamp[1]
                or self.pending is not None):
            raise AuthorityUnavailable('actual committed Contact delta capture identity changed')
        ns=self.base.namespace
        proof_key=contact_p2_graph_proof_key_v1(ns,self.binding.origin.effect_id,self.binding.origin.activity_id)
        if self.binding.origin.segment_index>0:
            from .contact_continuation_p2_v1 import contact_continuation_p2_graph_proof_key_v1
            proof_key=contact_continuation_p2_graph_proof_key_v1(ns,self.binding.origin.effect_id,self.binding.origin.activity_id)
        expected={dispatch_claim_key(ns,self.binding.origin.effect_id),proof_key}
        if ({write.key for write in candidate.writes}!=expected
                or {version.key for version in receipt.revisions}!=expected
                or candidate.event.scope.bot!=ns.bot_id or candidate.event.scope.persona!=ns.persona_id
                or candidate.event.scope.session!=self.binding.origin.activity_id
                or candidate.event.event_id!='dispatch-claim:'+self.binding.origin.effect_id):
            raise AuthorityUnavailable('Contact successor contains an unexpected actual write footprint')
        dangerous={'memory.source','memory.access','d06.source_correction_head.v1',OWNER_GRANT_TYPE}
        if any(version.key.type_name in dangerous or version.key.token not in self.base.heads
                for version in receipt.invalidated):
            raise AuthorityUnavailable('Contact claim affected rights or an unprojected head; reprepare required')
        anchor=self.claimed.after_anchor
        replacement=replace(before_stamp[0].requirements,deletion_seq=anchor.deletion_seq,
            deletion_digest=anchor.deletion_digest,execution_seq=anchor.execution_seq,
            execution_digest=anchor.execution_digest,revocation_epoch=anchor.revocation_epoch)
        if (after_stamp[0]!=replace(before_stamp[0],requirements=replacement,graph_revision=before_stamp[0].graph_revision+1)
                or after_stamp[1]!=replace(before_stamp[1],revision=before_stamp[1].revision+1)):
            raise AuthorityUnavailable('Contact successor recovery CAS is outside its actual P2 footprint')
        self.base.operation.retain(sum(_heap(write.value)*4+32768 for write in candidate.writes)+
            len(receipt.invalidated)*32768+65536)
        changed={};seals={}
        for version in (*receipt.revisions,*receipt.invalidated):
            row=db.execute('SELECT revision,valid,value_cell_id FROM graph_atoms WHERE token=? AND bot=? AND persona=?',
                (version.key.token,*ns.as_tuple)).fetchone()
            if row is None or row[0]!=version.revision:
                raise AuthorityUnavailable('committed Contact actual revision/invalidation head differs')
            cell=begin_runtime_cell_read_v3(db,row[2],erasure_owner_ref=version.key.token)
            write=next((item for item in candidate.writes if item.key==version.key),None)
            if write is not None:
                if (row[1]!=1 or cell.header[0]!='canonical-json.ascii.v1'
                        or cell.header[2]!=candidate.event.event_id or cell.header[5]!=canonical_digest(write.value)):
                    raise AuthorityUnavailable('Contact actual write/cell logical SHA or producer differs')
            else:
                prior=self.base.heads[version.key.token]
                if row[1]!=0 or version.revision!=prior[0]+1 or row[2]!=prior[2]:
                    raise AuthorityUnavailable('Contact actual invalidation is outside its original retained head')
            changed[version.key.token]=tuple(row)
            seals[version.key.token]=(row[2],tuple(cell.header))
        if graph._v2_graph_stamp(ns)!=after_stamp or graph._GraphCoordinator__store._registry.catalogue_hash!=self.base.catalogue_hash:
            raise AuthorityUnavailable('Contact committed delta metadata CAS/catalogue changed')
        frozen_writes=tuple(_FrozenDispatchAtomV3(write.key,changed[write.key.token][0],_freeze_value_v3(write.value),
            bool(changed[write.key.token][1]),_heap(write.value))for write in candidate.writes)
        self.pending=(candidate,receipt,before_stamp,after_stamp,MappingProxyType(changed),MappingProxyType(seals),frozen_writes)

    def committed(self,actual_receipt):
        if self.pending is None or self.base.db.in_transaction:
            raise AuthorityUnavailable('unknown Contact transaction cannot mint successor coverage')
        candidate,receipt,before_stamp,after_stamp,heads,seals,writes=self.pending
        if (self.base.graph._v2_graph_stamp(self.base.namespace)!=after_stamp
                or actual_receipt.graph_epoch!=receipt.epoch.revision
                or self.writer.prepared_inventory is not self.base):
            raise AuthorityUnavailable('actual committed Contact receipt/stamp/writer changed')
        self.pending=None
        return PreparedCurrentDispatchSuccessorInventoryV3(_ISSUER,self.base,self.writer,self.context,self.binding,
            self.claimed,actual_receipt,candidate,receipt,before_stamp,after_stamp,heads,seals,writes)


class PreparedCurrentDispatchSuccessorInventoryV3(PreparedCurrentDispatchInventoryV3):
    """Original ALL EOF certificate plus one independent actual committed delta."""
    def __init__(self,issuer,base,writer,context,binding,claimed,actual_receipt,candidate,receipt,before_stamp,
            after_stamp,changed_heads,seals,writes):
        if issuer is not _ISSUER:raise TypeError('actual committed Contact successor issuer required')
        self.base,self.writer,self.actual_receipt=base,writer,actual_receipt
        self._successors=WeakSet();base._successors.add(self)
        self.context,self.claimed=context,claimed
        self.delta_candidate=(candidate.event.scope,candidate.event.event_id,candidate.event.occurred_at,
            candidate.event.kind,_freeze_value_v3(candidate.event.payload),candidate.reads,
            tuple((write.key,write.dependencies,_freeze_value_v3(write.value))for write in candidate.writes),candidate.epochs)
        self.delta_receipt,self.delta_before,self.delta_after=receipt,before_stamp,after_stamp
        self.delta_heads,self.delta_seals=changed_heads,seals
        for name in ('graph','db','namespace','binding','admission','request','operation','selection_digest','scope',
                'authority_epochs','catalogue_hash','leaf_count','ordered_root','full_eof','sources','qualified_sources',
                'family','source_descriptors','contact_birth','natural_originals','natural_history'):
            setattr(self,name,getattr(base,name))
        self.base_leaf_count,self.base_ordered_root=base.leaf_count,base.ordered_root
        self.coverage_kind='actual_base_eof_plus_committed_delta'
        self.graph_stamp=after_stamp
        self.query=QueryEpoch(self.namespace,'all',after_stamp[1].revision)
        frozen={atom.key.token:atom for atom in base.projection._atoms}
        for atom in writes:frozen[atom.key.token]=atom
        for invalidated in receipt.invalidated:
            atom=frozen.get(invalidated.key.token)
            if atom is not None:
                frozen[invalidated.key.token]=_FrozenDispatchAtomV3(atom.key,invalidated.revision,atom.value,False,atom.retained_bytes)
        self.projection=CurrentDispatchTypedProjectionV3(tuple(frozen[key]for key in sorted(frozen)),
            (after_stamp[1],),base.operation)
        self.heads=MappingProxyType(dict(base.heads)|dict(changed_heads))
        _ISSUED[self]=(self.graph,self.db,self.namespace,self.binding,self.admission,self.request,self.operation,
            self.selection_digest,self.scope,self.graph_stamp,self.query,self.authority_epochs,self.catalogue_hash,
            self.leaf_count,self.ordered_root,self.projection,self.sources,self.heads,self.qualified_sources,
            self.family,self.source_descriptors,self.contact_birth,self.natural_originals,self.natural_history)
        _SUCCESSOR_ISSUED[self]=self._successor_identity_v3()

    def _successor_identity_v3(self):
        return (self.base,self.writer,self.actual_receipt,self.context,self.claimed,self.delta_candidate,
            self.delta_receipt,self.delta_before,self.delta_after,self.delta_heads,self.delta_seals,
            self.base_leaf_count,self.base_ordered_root,self.coverage_kind)

    def _actual(self):
        super()._actual()
        expected=_SUCCESSOR_ISSUED.get(self)
        if expected is None or expected!=self._successor_identity_v3():
            raise AuthorityUnavailable('actual committed Contact successor issuer/delta changed')
        self.base._actual()

    def release_payload_v3(self):
        super().release_payload_v3()
        _SUCCESSOR_ISSUED.pop(self,None)
        self.delta_candidate=self.delta_heads=self.delta_seals=None

    def require_for(self,context,binding,claimed,db,*,authority_snapshot):
        if (binding!=self.binding or claimed!=self.claimed or context!=self.context
                or self.writer.prepared_inventory is not self or self.actual_receipt is None):
            raise AuthorityUnavailable('Contact successor original callback identity changed')
        return super().require_for(context,binding,claimed,db,authority_snapshot=authority_snapshot)

    def source_metadata(self,db,namespace,query,key,*,revision=None,require_grant=True):
        self.require_current(db,namespace,query)
        if key.token in self.delta_heads:
            raise AuthorityUnavailable('Contact successor cannot reuse an affected Source witness')
        source=self.base.sources.get(key.token)
        issued=None if source is None else _SOURCE_ISSUED.get(source)
        if (source is None or issued is None or source.source_key!=key or not source.valid or source.scope is not self.base.scope
                or source.graph_stamp!=self.base.graph_stamp or source.query!=self.base.query
                or source.operation_id!=self.operation.operation_id or source.selection_digest!=self.selection_digest
                or revision is not None and source.revision!=revision
                or require_grant and key.token not in self.qualified_sources):
            raise AuthorityUnavailable('original base Source witness cannot qualify this successor')
        actual=(db,source.source_key,source.revision,source.valid,source.cell_id,source.header,source.payload_sha256,
            source.metadata,source.scope,source.graph_stamp,source.query,source.operation_id,source.selection_digest)
        if issued!=actual:raise AuthorityUnavailable('original immutable Source witness changed')
        head=db.execute('SELECT revision,valid,value_cell_id FROM graph_atoms WHERE token=? AND bot=? AND persona=?',
            (key.token,*namespace.as_tuple)).fetchone()
        if head is None or tuple(head)!=(source.revision,int(source.valid),source.cell_id):
            raise AuthorityUnavailable('successor current Source head changed')
        return source


def begin_contact_dispatch_delta_capture_v3(base,writer,context,binding,claimed):
    return _DispatchCommittedDeltaCaptureV3(_ISSUER,base,writer,context,binding,claimed)
