"""Same-Work C09 proof for physical-only changes in immutable role manifests."""
from dataclasses import asdict, fields, is_dataclass
from weakref import WeakKeyDictionary
from sys import getsizeof

from ..authority_service.contract import AuthorityUnavailable
from ..runtime_storage_v3 import runtime_storage_v3
from .c09_paged_sql_v2 import canonical_digest, canonical_serialize
from .source_correction_read_v3 import _heap

_KEY = object()
_TASKS = WeakKeyDictionary()
_BY_OWNER = WeakKeyDictionary()
_PROOFS = WeakKeyDictionary()
def _metadata_heap(value):
    if is_dataclass(value):
        return _heap(value)+sum(_metadata_heap(getattr(value,f.name))for f in fields(value))
    if type(value)is dict:
        return getsizeof(value)+sum(_metadata_heap(k)+_metadata_heap(v)for k,v in value.items())
    if type(value)in (tuple,list,set):
        return getsizeof(value)+sum(_metadata_heap(v)for v in value)
    return _heap(value)


_HEADER = ('cell_id','codec_id','erasure_owner_ref','producer_operation_id','total_bytes',
    'segment_count','payload_sha256','ordered_segment_root','origin_scope_digest')
_ATOM = ('token','bot','persona','owner_kind','subject','type_name','name','revision','value_cell_id','valid')


class RoleManifestLogicalPreservationNeededV1(Exception):
    def __init__(self, task):
        self.task = task
        super().__init__('actual role manifest physical preservation needs its next metadata quantum')


def _owner(owner, meter=None):
    from .d06_ordinary_readout_v3 import (
        require_life_ordinary_origin_owner_v3, _HOST, _AUTHORITY)
    value = require_life_ordinary_origin_owner_v3(owner)
    registry = _AUTHORITY if value.is_authority else _HOST
    selector = value.work if value.is_authority else value.consumer
    if registry.get(selector) is not value:
        raise AuthorityUnavailable('role physical preservation requires its actual registered Numeric Work')
    handle = runtime_storage_v3(value.db)
    if (handle is not value.operation.handle or value.operation.closed
            or handle.selection_digest != value.work.selection_digest):
        raise AuthorityUnavailable('role preservation left its installed operation/selection')
    if meter is not None:
        handle.require_current(meter)
    return value


def _identity(owner):
    return (owner,owner.consumer,owner.work,owner.operation,owner.db,
        owner.work.selection_digest,owner.namespace,owner.is_authority,owner.authority_epochs)


def _manifests(owner, old, current):
    from .d06_ordinary_readout_v3 import (
        LifeOrdinaryReadoutManifestV3, LifeOrdinaryReadoutManifestV4,
        validate_life_role_manifest_wire_v3, life_role_manifest_wire_v3)
    def typed(value):
        if type(value) in (LifeOrdinaryReadoutManifestV3,LifeOrdinaryReadoutManifestV4):
            value = life_role_manifest_wire_v3(value)
        return validate_life_role_manifest_wire_v3(value,owner.namespace)
    old, current = typed(old), typed(current)
    left,right = asdict(old),asdict(current)
    left.pop('support_heads');right.pop('support_heads')
    if left != right or tuple(h.ref for h in old.support_heads) != tuple(h.ref for h in current.support_heads):
        raise AuthorityUnavailable('role manifests changed semantic fields, controls or support coverage')
    for a,b in zip(old.support_heads,current.support_heads):
        if (a.ref,a.revision,a.valid) != (b.ref,b.revision,b.valid):
            raise AuthorityUnavailable('role logical proof cannot change Source/access/correction versions')
    return old,current


def _row(table, columns, where, key):
    return ('row',table,tuple(columns),where,tuple(key))


def _column(table, column, key_columns, key):
    return ('column',table,column,tuple(key_columns),tuple(key))


class _MetadataColumnV1:
    """Only certificate JSON: no business value or Source text column."""
    def __init__(self, task, request):
        from .c09_canonical_json_stream_v2 import C09CanonicalJSONStreamV2,_CanonicalJSONValueBuilderV3
        from .dispatch_current_inventory_v3 import _FrozenObjectV3,_FrozenArrayV3
        self.task,self.request=task,request
        self.total=None;self.position=0;self.fragment=b'';self.offset=0
        self.complete=False;self.value=None
        self.parser=C09CanonicalJSONStreamV2()
        self.builder=_CanonicalJSONValueBuilderV3()
        self.builder.operation=task.owner.operation
        self.builder._initialize_json_value_v3(incremental_retention=True,
            frozen_object_type=_FrozenObjectV3,frozen_array_type=_FrozenArrayV3)

    def advance(self,meter):
        from .c09_paged_sql_v2 import read_legacy_sql_cell_fragment_v2,legacy_cell_read_transaction_v2,_quote
        from .dispatch_current_inventory_v3 import _detach_value_v3
        _,table,column,columns,key=self.request
        where=' AND '.join(_quote(c)+'=?'for c in columns)
        if self.total is None:
            row=self.task.owner.db.execute('SELECT length(CAST('+_quote(column)+' AS BLOB)) FROM '+
                _quote(table)+' WHERE '+where,key).fetchone()
            meter.charge_read(8)
            if row is None or row[0] is None:
                raise AuthorityUnavailable('actual role certificate column disappeared')
            self.total=row[0]
            return False
        if self.offset<len(self.fragment):
            end=min(self.offset+1024,len(self.fragment))
            self.parser.feed(self.fragment[self.offset:end],self.builder._emit)
            self.offset=end
            return False
        if self.position<self.total:
            with legacy_cell_read_transaction_v2(self.task.owner.db):
                raw,total,kind=read_legacy_sql_cell_fragment_v2(self.task.owner.db,
                    table=table,column=column,where=where,parameters=key,start=self.position,
                    length=min(16384,self.total-self.position),meter=meter)
            if total!=self.total or kind!='text':
                raise AuthorityUnavailable('actual role certificate bytes changed during metadata EOF')
            self.builder._reserve(len(raw)*4+1024)
            self.fragment=raw;self.offset=0;self.position+=len(raw)
            return False
        result=self.parser.finish()
        if result.byte_count!=self.total:
            raise AuthorityUnavailable('actual role certificate metadata EOF differs')
        self.builder._reserve(_heap(self.builder.value)*3+4096)
        self.value=_detach_value_v3(self.builder.value)
        self.parser=self.builder=None;self.fragment=b''
        self.complete=True
        return True


class RoleManifestLogicalPreservationTaskV1:
    def __init__(self, issuer, owner, old, current):
        if issuer is not _KEY:raise TypeError('private role preservation task issuer required')
        self.owner=owner
        self.old_manifest,self.current_manifest=_manifests(owner,old,current)
        self.identity=_identity(owner)
        self.manifest_digests=(self.old_manifest.digest,self.current_manifest.digest)
        self.complete=False;self.proof=None;self.pending=None;self.column=None
        self.headers={};self.verified_streams={};self.certificates={}
        self.basis_identity=None
        self.generator=self._run()
        _TASKS[self]=(self.identity,self.manifest_digests)
        owner.operation.register_retained_state_v3(self)

    def _runtime_retained_heap_bytes_v3(self):
        state=(asdict(self.old_manifest),asdict(self.current_manifest),self.headers,
            tuple(asdict(v)for v in self.verified_streams.values()),
            tuple(asdict(v)for v in self.certificates.values()),self.pending)
        local=()if self.generator is None or self.generator.gi_frame is None else tuple(
            v for k,v in self.generator.gi_frame.f_locals.items()if k!='self')
        return _metadata_heap(state)+_metadata_heap(local)+4096

    def _actual(self,meter=None):
        owner=_owner(self.owner,meter)
        if (_TASKS.get(self)!=(self.identity,self.manifest_digests)
                or self.identity!=_identity(owner)
                or self.manifest_digests!=(self.old_manifest.digest,self.current_manifest.digest)):
            raise AuthorityUnavailable('role physical proof lost its same-Work immutable input binding')
        return owner

    def advance(self,meter):
        from .c09_paged_sql_v2 import read_capture_page_v2
        self._actual(meter)
        if self.complete:
            self.proof.require_current_v1(self.owner,meter=meter)
            return True
        if self.pending is None:
            try:self.pending=next(self.generator)
            except StopIteration:
                self.complete=True
                self.proof=RoleManifestLogicalPreservationV1(_KEY,self)
                return True
        request=self.pending
        if request[0]=='column':
            if self.column is None:self.column=_MetadataColumnV1(self,request)
            if not self.column.advance(meter):
                self.owner.operation.refresh_retained_state_v3(self)
                return False
            value=self.column.value;self.column=None
        elif request[0]=='row':
            _,table,columns,where,key=request
            value=meter.read_fixed_row(self.owner.db,table,columns,where,key)
        elif request[0]=='page':
            value=read_capture_page_v2(self.owner.db,request[1],request[2])
        elif request[0]=='member':
            from .c09_historical_proof_row_codec_v2 import _require_exact_structural_member
            _require_exact_structural_member(self.owner.db,request[1],request[2],request[3],meter)
            value=True
        elif request[0]=='descriptor':
            from .c09_paged_sql_v2 import require_c09_logical_source_row_member_v3
            value=require_c09_logical_source_row_member_v3(self.owner.db,request[1],
                role='graph',table_name='graph_atoms',key=request[2],record_ordinal=request[3],meter=meter)
        elif request[0]=='disposition':
            from .c09_graph_rebase_candidate_v2 import _read_graph_disposition_original_row_v3
            value=_read_graph_disposition_original_row_v3(self.owner.db,request[1],'graph_atoms',request[2],meter)
        else:raise AuthorityUnavailable('unregistered role preservation metadata continuation')
        self.owner.operation.reserve_retained_state_growth_v3(self,_metadata_heap(value)*3+4096)
        try:self.pending=self.generator.send(value)
        except StopIteration:
            self.pending=None;self.complete=True
            self.proof=RoleManifestLogicalPreservationV1(_KEY,self)
        self.owner.operation.finish_retained_state_growth_v3(self)
        return self.complete

    def _certificate(self,digest):
        from .c09_paged_capture_contract_v2 import GraphErasureRebaseCertificateV2,c09_paged_value_from_wire_v2
        if digest in self.certificates:return self.certificates[digest]
        after='';found=None
        while True:
            row=yield _row('graph_c09_rebase_certificates_v2',('operation_id',),
                'bot=? AND persona=? AND operation_id>? ORDER BY operation_id',(*self.owner.namespace.as_tuple,after))
            if row is None:break
            after=row[0]
            wire=yield _column('graph_c09_rebase_certificates_v2','certificate_json',
                ('bot','persona','operation_id'),(*self.owner.namespace.as_tuple,after))
            value=c09_paged_value_from_wire_v2(wire,GraphErasureRebaseCertificateV2)
            if value.candidate.scope.operation_id!=after:
                raise AuthorityUnavailable('role certificate mirror has another actual operation')
            if value.certificate_digest==digest:
                if found is not None:raise AuthorityUnavailable('role certificate digest repeats in mirror')
                found=value
        if found is None:raise AuthorityUnavailable('authenticated role certificate mirror is absent')
        scope=found.candidate.scope
        if scope.graph_namespace!=canonical_serialize(self.owner.namespace.as_tuple):
            raise AuthorityUnavailable('role certificate namespace differs from actual Work')
        self.certificates[digest]=found
        return found

    def _stream(self,locator):
        import json
        from .c09_paged_capture_contract_v2 import (
            C09CompleteStreamV2,c09_paged_value_from_wire_v2,begin_c09_stream_v2,verify_c09_page_v2)
        identity,seal=locator.identity,locator.complete
        prior=self.verified_streams.get(identity.stream_id)
        if prior is not None:
            if prior!=locator:raise AuthorityUnavailable('role proof stream identity changed')
            return
        saved=yield _row('c09_capture_streams_v2',('status','seal_json'),'stream_id=?',(identity.stream_id,))
        if saved is None or saved[0]!='sealed' or c09_paged_value_from_wire_v2(json.loads(saved[1]),C09CompleteStreamV2)!=seal:
            raise AuthorityUnavailable('role proof stream has no identical committed complete seal')
        cursor=begin_c09_stream_v2(identity)
        while cursor.page_index<seal.page_count:
            page,records=yield ('page',identity,cursor.page_index)
            cursor=verify_c09_page_v2(identity,cursor,page,records)
        if (cursor.record_offset,cursor.encoded_bytes,cursor.page_index,cursor.record_chain,cursor.previous_page_digest)!=(
                seal.record_count,seal.encoded_bytes,seal.page_count,seal.record_root,seal.page_root):
            raise AuthorityUnavailable('role proof page chain does not reach the signed complete root')
        extra=yield _row('c09_capture_pages_v2',('page_index',),'stream_id=? AND page_index>=?',
            (identity.stream_id,seal.page_count))
        if extra is not None:raise AuthorityUnavailable('role proof stream has unsealed extra pages')
        extra=yield _row('c09_capture_members_v2',('record_ordinal',),'stream_id=? AND record_ordinal>?',
            (identity.stream_id,seal.record_count))
        if extra is not None:raise AuthorityUnavailable('role proof stream has unsealed extra members')
        self.verified_streams[identity.stream_id]=locator

    def _family(self,certificate):
        import json
        from .c09_paged_capture_contract_v2 import (
            C09StreamIdentityV2,C09CompleteStreamV2,C09SealedStreamLocatorV2,c09_paged_value_from_wire_v2)
        outer=certificate.candidate.disposition_directory
        if outer.identity.family!='c09_graph_disposition_directory_v2':
            raise AuthorityUnavailable('role proof has another disposition directory family')
        yield from self._stream(outer)
        row=yield _row(outer.identity.family,('scope_digest','family','identity_json','complete_json'),
            'scope_digest=? AND family=?',(certificate.candidate.scope.scope_digest,'graph_atoms'))
        if row is None:raise AuthorityUnavailable('role graph_atoms signed disposition directory absent')
        yield ('member',outer,(row[0],row[1]),row)
        identity=c09_paged_value_from_wire_v2(json.loads(row[2]),C09StreamIdentityV2)
        complete=c09_paged_value_from_wire_v2(json.loads(row[3]),C09CompleteStreamV2)
        if (identity.scope_digest!=row[0] or identity.role_source_digest!=certificate.candidate.source.role_source_digest
                or identity.family!='graph_atoms' or identity.stream_kind!='row_dispositions'):
            raise AuthorityUnavailable('role graph_atoms disposition escaped signed Source namespace/family')
        locator=C09SealedStreamLocatorV2('graph',identity,complete)
        yield from self._stream(locator)
        return locator

    def _basis(self):
        handle=runtime_storage_v3(self.owner.db)
        if handle.host_binding is not None:
            from ..host.c09_storage_admission_v1 import VerifiedHostGraphStorageBindingV4
            binding=handle.host_binding
            if type(binding)is not VerifiedHostGraphStorageBindingV4:
                raise AuthorityUnavailable('role physical proof requires actual installed Host storage binding')
            binding.require_business_v4()
            return (binding.certificate_digest,binding.capture_scope_digest,binding.authority_id,
                binding.authority_namespace,binding.installation_id)
        if handle.selected is None:
            raise AuthorityUnavailable('initial Graph has no prior logical migration certificate')
        basis=handle.selected.basis
        manifest=basis.manifest
        return (manifest['certificate_digest'],basis.prepared['capture_scope_digest'],basis.control.authority_id,
            basis.prepared['namespace'],basis.control.installation_id)

    def _run(self):
        import json
        from .c09_paged_capture_contract_v2 import (
            C09StreamIdentityV2,C09CompleteStreamV2,C09SealedStreamLocatorV2,c09_paged_value_from_wire_v2)
        from .c09_graph_rebase_candidate_v2 import _graph_logical_preservation_original_v3
        changed=[(a,b)for a,b in zip(self.old_manifest.support_heads,self.current_manifest.support_heads)
            if a.cell_id!=b.cell_id]
        if not changed:return
        self.basis_identity=self._basis()
        digest,scope_digest,authority,authority_namespace,installation=self.basis_identity
        if digest is None:raise AuthorityUnavailable('role physical difference has no authenticated current certificate')
        current=yield from self._certificate(digest)
        scope=current.candidate.scope
        if current.candidate.new_incarnation!=runtime_storage_v3(self.owner.db).member['incarnation_or_journal_id']:
            raise AuthorityUnavailable('role current certificate has another actual Graph incarnation')
        if (scope.scope_digest,scope.authority_id,scope.authority_namespace,scope.installation_id)!=(
                scope_digest,authority,authority_namespace,installation):
            raise AuthorityUnavailable('role current certificate differs from actual installed binding')
        for old,new in changed:
            row=yield _row('graph_atoms',_ATOM,'token=? AND bot=? AND persona=?',
                (new.ref,*self.owner.namespace.as_tuple))
            if row is None or (row[7],row[9],row[8])!=(new.revision,int(new.valid),new.cell_id):
                raise AuthorityUnavailable('role physical proof target current GraphVersion changed')
            header=yield _row('segmented_cells_v1',_HEADER,'cell_id=?',(new.cell_id,))
            if header is None or header[2]!=new.ref:
                raise AuthorityUnavailable('role actual current target cell owner differs')
            self.headers[new.ref]=(tuple(row),tuple(header))
            physical=canonical_digest(tuple(row))
            certificate=current;seen=set()
            while header[0]!=old.cell_id:
                if certificate.certificate_digest in seen:raise AuthorityUnavailable('role prior certificate chain is cyclic')
                seen.add(certificate.certificate_digest)
                family=yield from self._family(certificate)
                proof=yield ('disposition',certificate.candidate.scope.scope_digest,(new.ref,))
                if proof is None or proof[:3]!=(certificate.candidate.scope.scope_digest,'graph_atoms',canonical_digest(('graph_atoms',(new.ref,)))):
                    raise AuthorityUnavailable('role migration lacks its exact authoritative row disposition')
                yield ('member',family,(new.ref,),proof)
                if proof[5]=='preserved_exact':
                    if proof[4]!=proof[6] or proof[6]!=physical:
                        raise AuthorityUnavailable('preserved_exact role row physical commitment differs')
                elif len(proof)==13 and proof[5]=='logical_preserved_v3':
                    source=yield _row('c09_capture_streams_v2',('identity_json','status','seal_json'),
                        'stream_id=?',(proof[7],))
                    if source is None or source[1]!='sealed':raise AuthorityUnavailable('role actual Source stream absent')
                    identity=c09_paged_value_from_wire_v2(json.loads(source[0]),C09StreamIdentityV2)
                    complete=c09_paged_value_from_wire_v2(json.loads(source[2]),C09CompleteStreamV2)
                    if (identity.scope_digest!=certificate.candidate.scope.scope_digest
                            or identity.role_source_digest!=certificate.candidate.source.role_source_digest
                            or identity.stream_kind!='graph_facts' or identity.family!='graph_atoms'
                            or complete.record_count!=family.complete.record_count):
                        raise AuthorityUnavailable('role original Source stream crossed signed capture')
                    yield from self._stream(C09SealedStreamLocatorV2('graph',identity,complete))
                    descriptor=yield ('descriptor',identity,(new.ref,),proof[8])
                    raw=json.loads(proof[12])
                    if type(raw)is not dict or set(raw)!={'target_cell_seal','logical_equivalence_original'}:
                        raise AuthorityUnavailable('role logical preservation original grammar differs')
                    source_header=tuple(raw['logical_equivalence_original']['source_cell_header'])
                    if len(source_header)!=9 or (source_header[1],source_header[4],source_header[6])!=(header[1],header[4],header[6]):
                        raise AuthorityUnavailable('role logical migration changed codec or complete payload bytes/SHA')
                    expected=_graph_logical_preservation_original_v3(certificate.candidate.scope.scope_digest,
                        'graph_atoms',(new.ref,),descriptor,source_header,header,physical)
                    if proof[9:]!=expected or proof[4]!=expected[0] or proof[6]!=physical:
                        raise AuthorityUnavailable('role Source/target cell and signed logical equivalence differ')
                    header=source_header;physical=descriptor['physical_row_commitment']
                else:raise AuthorityUnavailable('role payload was erased, derived, rebuilt or has unknown disposition')
                if header[0]==old.cell_id:break
                prior=certificate.prior_certificate_digest_or_none
                if prior is None or certificate.prior_certificate_schema_or_none!='sylanne3.graph.c09_erasure_rebase.v2':
                    raise AuthorityUnavailable('role immutable old cell has no complete prior certificate chain')
                previous=yield from self._certificate(prior)
                if (previous.candidate.scope.authority_id,previous.candidate.scope.authority_namespace,
                        previous.candidate.scope.installation_id)!=(authority,authority_namespace,installation):
                    raise AuthorityUnavailable('role prior certificate changed installation identity')
                if (previous.candidate.new_incarnation!=certificate.candidate.old_incarnation
                        or previous.candidate.scope.maintenance_generation>=certificate.candidate.scope.maintenance_generation):
                    raise AuthorityUnavailable('role prior certificate is not the actual predecessor incarnation')
                certificate=previous
            if header[0]!=old.cell_id or header[2]!=old.ref:
                raise AuthorityUnavailable('role physical chain did not reach the immutable original cell')

    def release_v1(self):
        if _TASKS.pop(self,None) is None:return
        owner=self.owner
        owner.operation.unregister_retained_state_v3(self)
        if self.proof is not None:_PROOFS.pop(self.proof,None)
        if self.generator is not None:self.generator.close()
        self.generator=self.pending=self.column=self.proof=None
        self.headers.clear();self.verified_streams.clear();self.certificates.clear()
        tasks=_BY_OWNER.get(self.owner)
        if tasks is not None:
            tasks.pop(self.manifest_digests,None)
            if not tasks:_BY_OWNER.pop(self.owner,None)
        self.old_manifest=self.current_manifest=None
        self.owner=self.identity=self.basis_identity=None


class RoleManifestLogicalPreservationV1:
    def __init__(self,issuer,task):
        if issuer is not _KEY:raise TypeError('actual complete role preservation issuer required')
        self.task=task
        _PROOFS[self]=(task,task.identity,task.manifest_digests)

    def require_current_v1(self,owner,*,meter=None):
        task=self.task
        if (_PROOFS.get(self)!=(task,task.identity,task.manifest_digests)
                or task.owner is not owner or not task.complete):
            raise AuthorityUnavailable('role physical proof is not this actual completed Work')
        task._actual(meter)
        if task.basis_identity is not None and task._basis()!=task.basis_identity:
            raise AuthorityUnavailable('role preservation current certificate selection changed')
        if meter is None:
            with owner.quantum_v3()as actual:return self.require_current_v1(owner,meter=actual)
        for head in task.current_manifest.support_heads:
            row=meter.read_fixed_row(owner.db,'graph_atoms',('revision','valid','value_cell_id'),
                'token=? AND bot=? AND persona=?',(head.ref,*owner.namespace.as_tuple))
            if row!=(None if head.revision==0 else(head.revision,int(head.valid),head.cell_id)):
                raise AuthorityUnavailable('role physical proof current Source head changed')
            saved=task.headers.get(head.ref)
            if saved is not None:
                actual=meter.read_fixed_row(owner.db,'segmented_cells_v1',_HEADER,'cell_id=?',(head.cell_id,))
                if actual!=saved[1]:raise AuthorityUnavailable('role physical proof current cell seal changed')
        return self

    def release_v1(self):
        self.task.release_v1()


def prepare_role_manifest_logical_preservation_v1(owner,old_manifest,current_manifest):
    owner=_owner(owner)
    old,current=_manifests(owner,old_manifest,current_manifest)
    key=(old.digest,current.digest)
    tasks=_BY_OWNER.setdefault(owner,{})
    task=tasks.get(key)
    if task is None:
        task=RoleManifestLogicalPreservationTaskV1(_KEY,owner,old,current)
        tasks[key]=task
    task._actual()
    return task


def require_role_manifest_logical_preservation_v1(task,owner,old_manifest,current_manifest,*,meter=None):
    if type(task)is not RoleManifestLogicalPreservationTaskV1:
        raise AuthorityUnavailable('actual same-Work role preservation metadata task required')
    task._actual()
    old,current=_manifests(owner,old_manifest,current_manifest)
    if task.owner is not owner or task.manifest_digests!=(old.digest,current.digest):
        raise AuthorityUnavailable('role physical proof crossed immutable/current manifest inputs')
    if not task.complete:raise RoleManifestLogicalPreservationNeededV1(task)
    return task.proof.require_current_v1(owner,meter=meter)


def release_role_manifest_logical_preservation_v1(owner):
    for task in tuple(_BY_OWNER.get(owner,{}).values()):task.release_v1()
