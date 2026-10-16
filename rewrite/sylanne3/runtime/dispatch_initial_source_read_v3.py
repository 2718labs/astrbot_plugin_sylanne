"""Private original JSON and Source witnesses retained by one dispatch prepare work."""
from dataclasses import fields
from hashlib import sha256
import json
from types import MappingProxyType
from typing import get_type_hints
from weakref import WeakKeyDictionary, WeakSet, ref

from ..authority_service.contract import AuthorityUnavailable
from ..graph_types import AtomKey
from ..runtime_storage_v3 import begin_runtime_cell_read_v3, runtime_storage_v3
from .c09_canonical_json_stream_v2 import C09CanonicalJSONStreamV2
from .c09_graph_row_codec_v2 import C09MemorySourceJSONStreamV3
from .c09_paged_sql_v2 import read_legacy_sql_cell_fragment_v2, legacy_cell_read_transaction_v2, _quote
from .source_correction_read_v3 import _heap

_ISSUER=object()
_MEMBERS=WeakKeyDictionary()
_SOURCES=WeakKeyDictionary()
_EVIDENCE=WeakKeyDictionary()
_COLUMNS=WeakKeyDictionary()
_PAYLOAD_EOF=WeakSet()
_BIRTH_ORIGINALS=WeakKeyDictionary()
_HISTORIES=WeakKeyDictionary()
_ABSENCES=WeakKeyDictionary()
_MEMBER_PREFIX=('provenance','qualification_evidence','members')

def _container_bytes_v3(value):
    from .dispatch_current_inventory_v3 import _FrozenObjectV3,_FrozenArrayV3
    if type(value)is dict:return 256+len(value)*72+sum(_container_bytes_v3(v)for v in value.values())
    if type(value)is list:return 64+len(value)*16+sum(_container_bytes_v3(v)for v in value)
    if type(value)is _FrozenObjectV3:return 256+len(value.items)*72+sum(_container_bytes_v3(v)for _,v in value.items)
    if type(value)is _FrozenArrayV3:return 64+len(value.items)*16+sum(_container_bytes_v3(v)for v in value.items)
    return 0


class _SourceMetadataRecordV3:
    def __init__(self,metadata):self.metadata=MappingProxyType({k:tuple(v)if type(v)is list else v for k,v in metadata.items()})
    def __getattr__(self,name):return self.metadata[name]

class PreparedContactSourceMemberV3:
    def __init__(self,issuer,outer,member,parsed,metadata):
        if issuer is not _ISSUER:raise TypeError('actual complete Source-member stream required')
        self.ref,self.revision,self.valid=member['ref'],member['revision'],member['valid']
        key=AtomKey.from_token(self.ref)
        if ((key.owner.bot,key.owner.persona)!=outer.owner.namespace.as_tuple or key.type_name!='memory.source'
                or type(self.revision)is not int or self.revision<0 or type(self.valid)is not bool
                or metadata is not None and metadata['source_id']!=key.owner.subject):
            raise AuthorityUnavailable('actual streamed Source fullPK/revision/namespace differs')
        self.value_digest,self.value_bytes=parsed.sha256,parsed.byte_count
        self.record=None if metadata is None else _SourceMetadataRecordV3(metadata)
        self._outer_ref=ref(outer);self.scope,self.operation=outer.owner.fence.scope,outer.owner.operation
        self.history=None
        _MEMBERS[self]=(self.ref,self.revision,self.valid,self.value_digest,self.value_bytes,self.record,None if self.record is None else self.record.metadata,self._outer_ref,self.scope,self.operation)
    @property
    def outer(self):return self._outer_ref()
    @property
    def value_json(self):
        if self.revision==0 and self.value_digest==sha256(b'{}').hexdigest()and self.value_bytes==2:return '{}'
        raise AuthorityUnavailable('Source member is a fulltyped metadata witness, not a text-bearing GraphAtom')
    def _actual(self):
        expected=_MEMBERS.get(self)
        actual=(self.ref,self.revision,self.valid,self.value_digest,self.value_bytes,self.record,None if self.record is None else self.record.metadata,self._outer_ref,self.scope,self.operation)
        if expected is None or actual!=expected or self.outer is None or not self.outer.complete or self.operation.closed:
            raise AuthorityUnavailable('actual streamed Contact Source member identity differs')
        return self

class _OriginalJSONStreamV3(C09CanonicalJSONStreamV2):
    def __init__(self,reader):
        self.reader=reader;self.source_inner=None;self.source_path=None
        super().__init__(ensure_ascii=True)
    def _append_decoded_codepoint(self,codepoint):
        state=self._string
        if self.source_inner is not None and state is not None and state['path']==self.source_path:
            if codepoint>127:raise ValueError('historical member value_json is not its canonical ASCII wire')
            self.source_inner.feed(bytes((codepoint,)),lambda event:None)
            return
        return super()._append_decoded_codepoint(codepoint)
    def _emit(self,emit,kind,path,start,end,**values):
        reader=self.reader
        if kind=='scalar_start' and len(path)==5 and path[:3]==_MEMBER_PREFIX and path[-1]=='value_json':
            member=reader.nodes[path[:-1]];key=AtomKey.from_token(member['ref'])
            if key.type_name=='memory.source':
                self.source_path=path
                self.source_inner=(C09MemorySourceJSONStreamV3(ensure_ascii=True)if member['revision']and member['valid']
                    else C09CanonicalJSONStreamV2(ensure_ascii=True))
        if self.source_inner is not None and path==self.source_path:
            if kind=='scalar_end':
                parsed=self.source_inner.finish();metadata=(self.source_inner._source_metadata
                    if isinstance(self.source_inner,C09MemorySourceJSONStreamV3)else None)
                member=reader.nodes[path[:-1]]
                witness=PreparedContactSourceMemberV3(_ISSUER,reader,member,parsed,metadata)
                reader._put(path,witness);reader.source_members.append(witness)
                self.source_inner=self.source_path=None
            return
        return super()._emit(emit,kind,path,start,end,**values)

class DispatchOriginalJSONReadV3:
    """One fragment per ordinary quantum; no SQLite transaction survives advance."""
    def __init__(self,owner,*,table,column,key_columns,key,cell_id=None,contact_sources=False,authority_blob_original=None,authority_signature_original=None):
        self.owner,self.db,self.operation=owner,owner.db,owner.operation
        self.table,self.column,self.key_columns,self.key=table,column,key_columns,key
        self.where=' AND '.join(_quote(name)+'=?'for name in key_columns)
        self.authority_blob_original=authority_blob_original
        self.authority_signature_original=authority_signature_original
        if authority_signature_original is not None:
            from ..authority_service.current_authority_graph_read_v3 import AuthoritySignedJSONColumnV3
            if(type(authority_signature_original)is not AuthoritySignedJSONColumnV3
                    or authority_signature_original.owner is not owner
                    or(table,column,tuple(key_columns),tuple(key))!=('runtime_resource_quotes','quote_json',
                        ('quote_id','version'),authority_signature_original.key)):
                raise AuthorityUnavailable('actual fixed Authority signed quote column required')
            authority_signature_original._actual_v3()
        if authority_blob_original is not None:
            from ..authority_service.current_authority_graph_read_v3 import _AuthorityDerivedBlobOriginalV6
            if type(authority_blob_original)is not _AuthorityDerivedBlobOriginalV6 or cell_id is not None or contact_sources:
                raise AuthorityUnavailable('actual fixed Authority derived BLOB column original required')
            authority_blob_original.require_current_v6(owner,table=table,column=column,key_columns=key_columns,key=key)
        self.cell=begin_runtime_cell_read_v3(self.db,cell_id,erasure_owner_ref=key[0]if table=='graph_history'else None)if cell_id else None
        self.parser=_OriginalJSONStreamV3(self)if contact_sources else C09CanonicalJSONStreamV2(ensure_ascii=True)
        self.nodes={};self.scalar=bytearray();self.value=None;self.source_members=[]
        self.offset=0;self.total=None;self.fragment=b'';self.fragment_offset=0;self.complete=False;self.reserved=0
        self._reserve(65536)
    def _reserve(self,extra=0):
        size=_heap((self.nodes,self.scalar,self.fragment))+extra+65536
        for source in self.source_members:
            if source.record is not None:size+=sum(_heap(k)+_heap(v)for k,v in source.record.metadata.items())+1024
        inner=getattr(self.parser,'source_inner',None)
        if isinstance(inner,C09MemorySourceJSONStreamV3):size+=inner._source_heap_bytes()
        if size>self.reserved:self.operation.retain(size-self.reserved);self.reserved=size
    def _put(self,path,value):
        if not path:self.value=value
        else:
            parent=self.nodes[path[:-1]]
            if type(parent)is list:parent.append(value)
            else:parent[path[-1]]=value
    def _emit(self,event):
        if event.kind in ('object_start','array_start'):
            self._reserve(1024);value={}if event.kind=='object_start'else[];self.nodes[event.path]=value;self._put(event.path,value)
        elif event.kind=='scalar_start':self.scalar=bytearray()
        elif event.kind=='scalar_chunk':self._reserve(len(event.raw)*4+1024);self.scalar.extend(event.raw)
        elif event.kind=='scalar_end':
            self._reserve(len(self.scalar)*4+1024);value=json.loads(self.scalar);self.scalar=bytearray();self._put(event.path,value)
    def advance(self,meter):
        if self.complete:return True
        if self.authority_blob_original is not None:
            self.authority_blob_original.require_current_v6(self.owner,table=self.table,column=self.column,
                key_columns=self.key_columns,key=self.key)
        if self.fragment_offset<len(self.fragment):
            end=min(self.fragment_offset+1024,len(self.fragment));self._reserve(65536)
            fragment=self.fragment[self.fragment_offset:end]
            self.parser.feed(fragment,self._emit)
            if self.authority_signature_original is not None:self.authority_signature_original.feed_signature_v3(fragment)
            self.fragment_offset=end;return False
        if self.cell is not None:
            chunk=self.cell.read_fragment(meter=meter)
            if chunk is not None:self.fragment,self.fragment_offset=chunk,0;return False
        else:
            with legacy_cell_read_transaction_v2(self.db):
                if self.total is None:
                    row=self.db.execute('SELECT length(CAST('+_quote(self.column)+' AS BLOB)) FROM '+_quote(self.table)+' WHERE '+self.where,self.key).fetchone()
                    if row is None:raise AuthorityUnavailable('actual original JSON column absent')
                    meter.charge_read(8);self.total=row[0]
                    if self.authority_blob_original is not None and self.total!=self.authority_blob_original.byte_count:
                        raise AuthorityUnavailable('actual Authority derived BLOB length differs from metadata original')
                if self.offset<self.total:
                    chunk,total,kind=read_legacy_sql_cell_fragment_v2(self.db,table=self.table,column=self.column,where=self.where,
                        parameters=self.key,start=self.offset,length=min(16384,self.total-self.offset),meter=meter)
                    expected_kind='blob'if self.authority_blob_original is not None else'text'
                    if total!=self.total or kind!=expected_kind:raise AuthorityUnavailable('original JSON cell kind/length changed')
                    self.offset+=len(chunk);self.fragment,self.fragment_offset=chunk,0;return False
        parsed=self.parser.finish()
        if self.cell is not None:
            digest=self.cell.finish(meter=meter)
            if (parsed.sha256,parsed.byte_count)!=(digest,self.cell.header[3]):raise AuthorityUnavailable('original JSON header/SHA/EOF differs')
        elif parsed.byte_count!=self.total:raise AuthorityUnavailable('legacy original JSON EOF differs')
        if self.authority_blob_original is not None and(parsed.sha256,parsed.byte_count)!=(
                self.authority_blob_original.sha256,self.authority_blob_original.byte_count):
            raise AuthorityUnavailable('Authority derived BLOB actual full SHA/byte EOF differs from original metadata')
        from .dispatch_current_inventory_v3 import _freeze_value_v3
        self.operation.retain(_container_bytes_v3(self.value)+1024)
        self._frozen_value=_freeze_value_v3(self.value)
        self.sha256,self.byte_count=parsed.sha256,parsed.byte_count;self.complete=True
        self.value=None;self.nodes={};self.scalar=bytearray();self.fragment=b'';self.parser=None
        _COLUMNS[self]=(self.owner,self.table,self.column,self.key,self.sha256,self.byte_count,self._frozen_value)
        return True
    def require_v3(self,owner):
        expected=_COLUMNS.get(self)
        if (expected is None or expected!=(self.owner,self.table,self.column,self.key,self.sha256,self.byte_count,self._frozen_value)
                or self.owner is not owner or not self.complete or self.operation.closed):
            raise AuthorityUnavailable('actual same-work complete original JSON required')
        from .dispatch_current_inventory_v3 import _detach_value_v3
        self.operation.retain(_container_bytes_v3(self._frozen_value)+1024)
        return _detach_value_v3(self._frozen_value)

class PreparedContactSourcesV3:
    def __init__(self,issuer,owner,original,members):
        if issuer is not _ISSUER:raise TypeError('actual complete Contact historical Source provider required')
        original.require_v3(owner)
        self.owner,self.original,self.members=owner,original,tuple(members)
        for member in self.members:
            member._actual()
            if type(member.history)not in (_ContactHistoryCellReadV3,_ContactHistoryAbsenceV3):raise AuthorityUnavailable('Contact Source member has no independent historical EOF')
            member.history.require_member_v3(member)
        _SOURCES[self]=(owner,original,original.sha256,self.members)
    def require_member_v3(self,row):
        expected=_SOURCES.get(self)
        if expected!=(self.owner,self.original,self.original.sha256,self.members)or type(row)is not PreparedContactSourceMemberV3 or row not in self.members:
            raise AuthorityUnavailable('actual private Contact Source provider/member required')
        row._actual();row.history.require_member_v3(row)
        if row.record is None:raise AuthorityUnavailable('Contact Source body has no complete typed semantic stream')
        return row.record

class PreparedContactEvidenceV3:
    def __init__(self,issuer,raw,sources,expected_digest):
        from .contact_qualification_evidence_v3 import ContactQualificationEvidenceV3
        from .domain_production_erasure_v1 import decode_typed_production_value_v1
        from .d10_offline_tick_execution_v1 import OfflineTickGraphReadV1
        if issuer is not _ISSUER or type(sources)is not PreparedContactSourcesV3:raise TypeError('actual Contact historical issuer required')
        annotations=get_type_hints(ContactQualificationEvidenceV3);names={field.name for field in fields(ContactQualificationEvidenceV3)}
        if type(raw)is not dict or set(raw)!=names:raise ValueError('Contact historical metadata exact fieldset differs')
        for name in names-{'members'}:setattr(self,name,decode_typed_production_value_v1(raw[name],annotations[name]))
        members=[]
        for row in raw['members']:
            if type(row)is not dict or set(row)!={'ref','revision','value_json','valid'}:raise ValueError('Contact original member shape differs')
            member=row['value_json']
            if type(member)is PreparedContactSourceMemberV3:
                member._actual()
                if (row['ref'],row['revision'],row['valid'])!=(member.ref,member.revision,member.valid):raise ValueError('Contact streamed Source member identity differs')
                members.append(member)
            else:members.append(decode_typed_production_value_v1(row,OfflineTickGraphReadV1))
        self.members=tuple(members);self.sources=sources
        ContactQualificationEvidenceV3.__post_init__(self,prepared_sources=sources)
        if self.qualification.digest!=expected_digest:raise ValueError('original Contact six-provider digest differs')
        _EVIDENCE[self]=(sources,tuple((name,getattr(self,name))for name in sorted(names)))

def require_prepared_contact_sources_v3(provider):
    if type(provider)is not PreparedContactSourcesV3 or provider not in _SOURCES:
        raise AuthorityUnavailable('actual private issued Contact Source evidence provider required')
    return provider


class _ContactHistoryCellReadV3:
    def __init__(self,owner,key,revision,valid,cell_id):
        self.owner,self.key,self.revision,self.valid=owner,key,revision,valid
        self.cell=begin_runtime_cell_read_v3(owner.db,cell_id,erasure_owner_ref=key.token)
        self.parser=(C09MemorySourceJSONStreamV3(ensure_ascii=True)if key.type_name=='memory.source'and valid
            else C09CanonicalJSONStreamV2(ensure_ascii=True))
        self.fragment=b'';self.offset=0;self.complete=False
        self.reserved=0;self._reserve(65536)
    def _reserve(self,extra=0):
        size=_heap(self.fragment)+extra+65536
        if isinstance(self.parser,C09MemorySourceJSONStreamV3):size+=self.parser._source_heap_bytes()
        if size>self.reserved:self.owner.operation.retain(size-self.reserved);self.reserved=size
    def advance(self,meter):
        if self.offset<len(self.fragment):
            self._reserve(65536)
            end=min(self.offset+1024,len(self.fragment));self.parser.feed(self.fragment[self.offset:end],lambda event:None);self.offset=end;return False
        fragment=self.cell.read_fragment(meter=meter)
        if fragment is not None:self.fragment,self.offset=fragment,0;return False
        parsed=self.parser.finish();digest=self.cell.finish(meter=meter)
        if (parsed.sha256,parsed.byte_count)!=(digest,self.cell.header[3]):raise AuthorityUnavailable('Contact historical cell complete SHA/EOF differs')
        self.sha256=digest;self.complete=True;self.parser=None;self.fragment=b''
        _HISTORIES[self]=(self.owner,self.key,self.revision,self.valid,self.cell.cell_id,tuple(self.cell.header),self.sha256)
        return True
    def require_member_v3(self,member):
        actual=(self.owner,self.key,self.revision,self.valid,self.cell.cell_id,tuple(self.cell.header),self.sha256)
        if (_HISTORIES.get(self)!=actual or not self.complete or not self.cell.complete
                or (self.key.token,self.revision,bool(self.valid),self.sha256)!=(member.ref,member.revision,member.valid,member.value_digest)
                or self.owner is not member.outer.owner):
            raise AuthorityUnavailable('actual independent historical Source header/fullPK/SHA/EOF required')
        return self

class DispatchInitialSourceReadsV3:
    """Actual auxiliary producer originals; selected by the fixed trusted Host caller."""
    def __init__(self,owner,family,now_utc):
        if family not in {'private_reply','natural_reply','contact'}:raise ValueError('fixed dispatch family required')
        self.owner,self.family,self.now_utc=owner,family,now_utc
        self.phase='initial';self.complete=False;self.descriptors=();self.birth=None;self.natural=None
        self.original=None;self.history=None;self.history_cursor='';self.history_heads={};self.written_heads={};self.meta=None
        self.owner.operation.retain(65536)
    def _contact_initial(self,meter):
        from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3
        from .domain_production_originals_v1 import TABLE
        owner=self.owner;ns=owner.namespace;operation=owner.binding.operation_id
        if owner.request.proactive_contact is not True:raise AuthorityUnavailable('Contact original lacks proactive identity')
        columns=('domain','operation_kind','request_digest','original_digest','read_versions_json','bundle_digest','receipt_json','receipt_digest')
        self.meta=_runtime_bounded_fixed_row_v3(owner.db,meter,TABLE,columns,'bot=? AND persona=? AND operation_id=?',(*ns.as_tuple,operation))
        if self.meta is None or self.meta[:2]!=('d08','prepare_contact_dispatch_v3'):
            raise AuthorityUnavailable('actual Contact adopted producer is absent')
        self.original=DispatchOriginalJSONReadV3(owner,table=TABLE,column='original_payload_json',key_columns=('bot','persona','operation_id'),
            key=(*ns.as_tuple,operation),contact_sources=True)
        self.phase='contact_original'
    def _contact_outer(self):
        from dataclasses import asdict
        from .domain_production_originals_v1 import _receipt
        from ..graph_types import GraphVersion
        raw=self.original.require_v3(self.owner);meta=self.meta;owner=self.owner
        if (self.original.sha256!=meta[3]or raw['namespace']!=asdict(owner.namespace)
                or raw['identity']['operation_id']!=owner.binding.operation_id):
            raise AuthorityUnavailable('Contact complete original canonical identity differs')
        receipt=_receipt(json.loads(meta[6]));reads=tuple(GraphVersion(AtomKey.from_token(ref),rev)for ref,rev in json.loads(meta[4]))
        if canonical_digest_small_v3(receipt)!=meta[7]or receipt.operation_id!=owner.binding.operation_id or receipt.operation_digest!=meta[5]:
            raise AuthorityUnavailable('Contact actual original receipt identity differs')
        self.adopted=dict(domain=meta[0],operation_kind=meta[1],request_digest=meta[2],original_digest=meta[3],payload=raw,read_versions=reads,receipt=receipt)
        self.raw_evidence=raw['provenance']['qualification_evidence'];self.member_rows={v['ref']:v for v in self.raw_evidence['members']}
        if len(self.member_rows)!=len(self.raw_evidence['members']):raise AuthorityUnavailable('Contact original repeats historical members')
        self.phase='contact_history'
    def _next_contact_history(self,meter):
        owner=self.owner;ns=owner.namespace;raw=self.raw_evidence
        from .contact_qualification_evidence_v3 import CONTACT_FINAL_QUERY_TYPES_V3
        refs=tuple(dict.fromkeys((*self.member_rows,*(v['ref']for v in self.adopted['payload']['provenance']['write_commitments']))));kinds=CONTACT_FINAL_QUERY_TYPES_V3
        sql=('WITH latest AS (SELECT h.token,MAX(h.revision) AS revision FROM graph_history h JOIN graph_events e '
            'ON (h.event_bot,h.event_persona,h.event_session,h.event_id)=(e.bot,e.persona,e.session,e.event_id) '
            'WHERE e.bot=? AND e.persona=? AND e.epoch_revision<=? '
            f"AND (h.token IN ({','.join('?'for _ in refs)}) OR json_extract(h.token,'$[4]')IN ({','.join('?'for _ in kinds)}))GROUP BY h.token) "
            'SELECT h.token,h.revision,h.value_cell_id,h.valid,h.event_id FROM latest l JOIN graph_history h '
            'ON h.token=l.token AND h.revision=l.revision WHERE h.token>? ORDER BY h.token LIMIT 1')
        meter.require_available(32768);row=owner.db.execute(sql,(*ns.as_tuple,raw['graph_epoch'],*refs,*kinds,self.history_cursor)).fetchone()
        if row is None:
            self.history_complete=True;self._complete_contact();return
        meter.charge_read(sum(len(v.encode())if type(v)is str else 8 for v in row))
        if len(self.history_heads)>=1024:raise AuthorityUnavailable('Contact original historical query exceeds its original bound')
        token,revision,cell_id,valid,event_id=row;key=AtomKey.from_token(token)
        if (key.owner.bot,key.owner.persona)!=ns.as_tuple:raise AuthorityUnavailable('Contact historical member namespace differs')
        self.history_cursor=token;self.history=_ContactHistoryCellReadV3(owner,key,revision,valid,cell_id);self.history.event_id=event_id
    def _finish_contact_history(self):
        history=self.history;token=history.key.token
        row=self.member_rows.get(token)
        if row is not None:
            witness=row['value_json']
            digest=witness.value_digest if type(witness)is PreparedContactSourceMemberV3 else sha256(witness.encode('utf-8')).hexdigest()
            if (row['revision'],int(row['valid']),digest)!=(history.revision,history.valid,history.sha256):
                raise AuthorityUnavailable('Contact actual historical fullPK/revision/valid/logical SHA differs')
            if type(witness)is PreparedContactSourceMemberV3:
                history.require_member_v3(witness)
                witness.history=history
        self.history_heads[token]=(history.revision,history.valid,history.sha256)
        self.written_heads[token]=(history.revision,history.valid,history.sha256,history.event_id)
        self.history=None
    def _complete_contact(self):
        from .contact_p2_birth_v1 import read_contact_p2_birth_v1
        for member in self.original.source_members:
            if member.revision==0 and member.history is None:
                member.history=_ContactHistoryAbsenceV3(_ISSUER,self,member)
        sources=PreparedContactSourcesV3(_ISSUER,self.owner,self.original,self.original.source_members)
        proof=self.adopted['payload']['provenance']
        evidence=PreparedContactEvidenceV3(_ISSUER,self.raw_evidence,sources,proof['qualification_digest'])
        for member in self.adopted['payload']['provenance']['write_commitments']:
            if self.written_heads.get(member['ref'])!=(member['revision'],1,member['digest'],self.owner.binding.operation_id):
                raise AuthorityUnavailable('Contact original eleven producing members lost their actual COMMIT cell')
        self.prepared_birth=PreparedContactBirthOriginalsV3(_ISSUER,self,evidence)
        self.birth=read_contact_p2_birth_v1(self.owner.db,namespace=self.owner.namespace,operation_id=self.owner.binding.operation_id,
            prepared_original=self.prepared_birth)
        self.phase='contact_route'
    def _contact_route(self):
        from ..domains.d03.context import AccountBinding,WorldEvent
        from .first_ingress_v2 import scene_ref_for_conversation
        from .ingress_observation import read_committed_ingress_identity
        owner=self.owner;admission=owner.admission.admission;by_token={atom.key.token:atom for atom in owner.atoms}
        original=self.birth.qualification.route;account=by_token.get(original.account_version.key.token)
        if account is None or not account.valid:raise AuthorityUnavailable('initial Contact actual selected account is absent')
        binding=AccountBinding(**account.value)
        event_atom=by_token.get(binding.verification_ref)
        if event_atom is None or not event_atom.valid or event_atom.key.type_name!='d03.world_event':
            raise AuthorityUnavailable('initial Contact actual account evidence is absent')
        event=WorldEvent(**{**event_atom.value,'participant_roles':tuple(tuple(v)for v in event_atom.value['participant_roles']),
            'source_refs':tuple(event_atom.value['source_refs'])})
        if (binding.entity_id!=admission.object_ref or binding.platform_namespace!=admission.account_ref
                or event.event_id!=event_atom.key.owner.subject or event.kind!='message_received'or event.reality!='host_observed'
                or len(event.source_refs)!=1 or event.participant_roles!=((binding.entity_id,'sender_account'),)
                or event.learned_at!=binding.valid_from or admission.audience!=(self.birth.qualification.audience,)):
            raise AuthorityUnavailable('initial Contact account/WorldEvent selected descriptor differs')
        ingress=read_committed_ingress_identity(owner.db,owner.namespace,AtomKey.from_token(event.source_refs[0]).owner.subject)
        if ingress is None:raise AuthorityUnavailable('initial Contact ingress original is absent')
        identity=json.loads(ingress.identity_json)
        if (identity['platform_ref'],identity['sender_ref'],identity['conversation_ref'],identity['visibility'])!=(
                binding.platform_namespace,binding.platform_identifier,self.birth.qualification.audience,'private'):
            raise AuthorityUnavailable('initial Contact descriptor is outside its actual private ingress')
        if scene_ref_for_conversation(owner.namespace,binding.platform_namespace,identity['conversation_ref'])!=event.scene_ref:
            raise AuthorityUnavailable('initial Contact descriptor scene differs')
        self.descriptors=((event.source_refs,'context',admission.audience,('d03.world_event',event_atom.key.token,event_atom.revision)),)
        owner._require_source_roots_v3(event.source_refs,'context',admission.audience)
        self.complete=True
    def _private_route(self,meter):
        from .first_ingress_v2 import scene_ref_for_conversation
        owner=self.owner;admission=owner.admission.admission;ns=owner.namespace
        rows=owner.db.execute('SELECT ingress_operation_id,c02_operation_id,source_ref,target_entity_ref,account_ref,destination_ref,'
            'admission_digest,state,ack_digest FROM graph_post_c02_reply_ownership_v1 WHERE bot=? AND persona=? AND admission_ref=? LIMIT 2',
            (*ns.as_tuple,admission.admission_ref)).fetchmany(2)
        meter.charge_read(sum(sum(len(v.encode())if type(v)is str else 8 for v in row)for row in rows))
        if len(rows)!=1:raise AuthorityUnavailable('actual unique private ownership original required')
        row=rows[0];ingress,c02,source,target,account,destination,digest,state,ack=row
        identity=owner.graph._reply_ingress_identity_locked(ns,ingress);scene=scene_ref_for_conversation(ns,account,destination)
        source_key=AtomKey.from_token(source)
        source_identity=owner.db.execute('SELECT source_ref FROM graph_first_ingress_identity_v1 WHERE bot=? AND persona=? AND operation_id=?',
            (*ns.as_tuple,ingress)).fetchall()
        c02_identity=owner.db.execute('SELECT schema,bundle_digest FROM graph_first_ingress_c02_committed_seals_v2 WHERE bot=? AND persona=? AND operation_id=?',
            (*ns.as_tuple,c02)).fetchone()
        c02_commit=owner.db.execute('SELECT digest FROM graph_bundle_operations WHERE bot=? AND persona=? AND operation_id=?',(*ns.as_tuple,c02)).fetchone()
        if (source_identity!=[(source_key.owner.subject,)] or identity['source_ref']!=source_key.owner.subject
                or c02_identity is None or c02_commit is None or c02_identity!=('sylanne.first-ingress-c02-candidate.v2',c02_commit[0])
                or state!='sylanne_owned'or not ack or digest!=admission.digest
                or (identity['platform_ref'],identity['conversation_ref'])!=(account,destination)
                or (admission.account_ref,admission.destination_ref,admission.scene_ref,admission.object_ref,admission.audience)!=(
                    account,destination,scene,target,(destination,))):
            raise AuthorityUnavailable('initial private ownership/source descriptor identity differs')
        self.descriptors=(((source,),'context',admission.audience,('graph_post_c02_reply_ownership_v1',*ns.as_tuple,admission.admission_ref,tuple(row))),)
        owner._require_source_roots_v3((source,),'context',admission.audience)
        self.complete=True
    def _natural_initial(self,meter):
        from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3
        owner=self.owner;ns=owner.namespace
        if owner.request.proactive_contact:raise AuthorityUnavailable('natural original cannot use Contact scope')
        self.natural_bundle=_runtime_bounded_fixed_row_v3(owner.db,meter,'graph_bundle_operations',
            ('digest','activity_id','effect_id','commit_seq'),'bot=? AND persona=? AND operation_id=?',(*ns.as_tuple,owner.binding.operation_id))
        if self.natural_bundle is None:raise AuthorityUnavailable('actual natural producer COMMIT absent')
        self.original=DispatchOriginalJSONReadV3(owner,table='graph_bundle_operations',column='receipt_json',
            key_columns=('bot','persona','operation_id'),key=(*ns.as_tuple,owner.binding.operation_id))
        self.phase='natural_bundle'
    def _natural_columns_initial(self,meter):
        from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3
        owner=self.owner;data=self.original.require_v3(owner).get('natural_dispatch_candidate')
        if (type(data)is not dict or data.get('schema')!='sylanne.d11.natural_dispatch_candidate.v2'
                or data.get('status')!='natural_paid_review_current_hold' or len(data.get('refs',()))!=4):
            raise AuthorityUnavailable('actual natural candidate original schema/footprint differs')
        self.natural_candidate=data;self.natural_refs=list(data['refs']);self.natural_cells={};self.natural_cell_rows={};self.column=None
        self.phase='natural_candidate_cells'
    def _natural_candidate_cells(self,meter):
        from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3
        owner=self.owner
        if self.column is not None:
            if self.column.advance(meter):self.natural_cells[self.column.key]=self.column;self.column=None
            return
        if self.natural_refs:
            token,revision=self.natural_refs.pop(0);key=AtomKey.from_token(token)
            if (key.owner.bot,key.owner.persona)!=owner.namespace.as_tuple:raise AuthorityUnavailable('natural producing member crosses namespace')
            row=owner.db.execute('SELECT value_cell_id,valid,event_bot,event_persona,event_session,event_id FROM graph_history WHERE token=? AND revision=?',
                (token,revision)).fetchone()
            meter.charge_read(1024)
            if row is None or row[1]!=1 or tuple(row[2:])!=(*owner.namespace.as_tuple,owner.binding.origin.activity_id,owner.binding.operation_id):
                raise AuthorityUnavailable('actual natural member producing event/COMMIT differs')
            self.natural_cell_rows[(token,revision)]=row
            self.column=DispatchOriginalJSONReadV3(owner,table='graph_history',column='value',key_columns=('token','revision'),key=(token,revision),cell_id=row[0]);return
        from .natural_dispatch_current_read_v2 import recover_natural_dispatch_candidate_in_transaction_v2
        self.natural_history=PreparedNaturalHistoryV3(_ISSUER,self)
        recovered=recover_natural_dispatch_candidate_in_transaction_v2(owner.db,owner.namespace,owner.binding.operation_id,prepared_history=self.natural_history)
        if recovered is None:raise AuthorityUnavailable('actual natural candidate full typed qualification absent')
        self.natural_evidence=recovered.evidence
        table='graph_natural_generation_preparations_v2'
        row=_runtime_bounded_fixed_row_v3(owner.db,meter,table,('parent_original_id','graph_epoch','access_epoch','deletion_epoch',
            'state','typed_request_digest','worker_fence','terminal_receipt_digest','terminal_output_digest'),
            'bot=? AND persona=? AND original_operation_id=?',(*owner.namespace.as_tuple,self.natural_evidence.generation_original_operation_id))
        if row is None or row[4]!='terminal':raise AuthorityUnavailable('actual natural generation is not completed')
        self.natural_meta=row;self.natural_json={};self.natural_column_queue=['seal_json','frozen_json','read_versions_json','query_epochs_json','typed_request_wire']
        self.column=None;self.phase='natural_columns'
    def _natural_columns(self,meter):
        return _advance_host_saved_natural_columns_v3(self,meter)
    def _natural_frozen_step(self,meter):
        return _advance_host_saved_natural_frozen_step_v3(self,meter)
    def _natural_digest_step(self,meter):
        return _advance_host_saved_natural_digest_step_v3(self,meter)
    def _advance_natural(self,meter):
        if self.phase=='natural_bundle':
            if self.original.advance(meter):self.phase='natural_columns_initial'
        elif self.phase=='natural_columns_initial':self._natural_columns_initial(meter)
        elif self.phase=='natural_candidate_cells':self._natural_candidate_cells(meter)
        elif self.phase=='natural_columns':self._natural_columns(meter)
        elif self.phase=='natural_frozen':self._natural_frozen_step(meter)
        elif self.phase=='natural_digests':self._natural_digest_step(meter)
        else:raise AuthorityUnavailable('actual initial Source original phase differs')
    def advance(self,meter):
        if self.phase=='initial':
            if self.family=='contact':self._contact_initial(meter)
            elif self.family=='private_reply':self._private_route(meter)
            else:self._natural_initial(meter)
        elif self.phase=='contact_original':
            if self.original.advance(meter):self._contact_outer()
        elif self.phase=='contact_history':
            if self.history is None:self._next_contact_history(meter)
            elif self.history.advance(meter):self._finish_contact_history()
        elif self.phase=='contact_route':self._contact_route()
        else:self._advance_natural(meter)
        return self.complete


def canonical_digest_small_v3(value):
    from ..runtime_contracts import canonical_digest
    return canonical_digest(value)


class PreparedContactBirthOriginalsV3:
    def __init__(self,issuer,producer,evidence):
        if issuer is not _ISSUER or type(evidence)is not PreparedContactEvidenceV3 or evidence not in _EVIDENCE:
            raise TypeError('actual complete Contact original and typed history qualification required')
        self.owner,self.original,self.evidence=producer.owner,producer.original,evidence
        from .dispatch_current_inventory_v3 import _freeze_value_v3
        producer.owner.operation.retain(_container_bytes_v3(producer.adopted)+1024)
        self.adopted,self.heads=_freeze_value_v3(producer.adopted),MappingProxyType(dict(producer.history_heads))
        self.metadata=producer.meta
        _BIRTH_ORIGINALS[self]=(self.owner,self.original,self.evidence,self.adopted,self.heads,self.metadata)
    def require_for_v3(self,db,namespace,operation_id):
        from ..runtime_storage_v3 import _operation
        if (_BIRTH_ORIGINALS.get(self)!=(self.owner,self.original,self.evidence,self.adopted,self.heads,self.metadata)
                or db is not self.owner.db or namespace!=self.owner.namespace or operation_id!=self.owner.binding.operation_id
                or not db.in_transaction or _operation(runtime_storage_v3(db))is not self.owner.operation):
            raise AuthorityUnavailable('actual same-work Contact historical original required')
        self.original.require_v3(self.owner)
        row=db.execute('SELECT original_digest,bundle_digest,receipt_digest FROM graph_domain_production_originals_v1 '
            'WHERE bot=? AND persona=? AND operation_id=?',(*namespace.as_tuple,operation_id)).fetchone()
        if row!=(self.metadata[3],self.metadata[5],self.metadata[7]):
            raise AuthorityUnavailable('Contact original durable identity changed after ordinary preparation')
        from .dispatch_current_inventory_v3 import _detach_value_v3
        self.owner.operation.retain(_container_bytes_v3(self.adopted)+1024)
        require_prepared_contact_evidence_v3(self.evidence)
        return _detach_value_v3(self.adopted),self.evidence,self.heads


def require_prepared_contact_evidence_v3(evidence):
    from .contact_qualification_evidence_v3 import ContactQualificationEvidenceV3
    names=sorted(field.name for field in fields(ContactQualificationEvidenceV3))
    if type(evidence)is not PreparedContactEvidenceV3 or _EVIDENCE.get(evidence)!=(evidence.sources,
            tuple((name,getattr(evidence,name))for name in names)):
        raise AuthorityUnavailable('actual private complete Contact metadata evidence required')
    require_prepared_contact_sources_v3(evidence.sources)
    return evidence


class _ContactHistoryAbsenceV3:
    def __init__(self,issuer,producer,member):
        if (issuer is not _ISSUER or not producer.history_complete or member.ref in producer.history_heads
                or member.revision!=0 or member.valid or member.value_digest!=sha256(b'{}').hexdigest()):
            raise AuthorityUnavailable('actual complete historical absence required')
        self.owner,self.original_ref=producer.owner,ref(producer.original)
        self.token,self.original_sha,self.graph_epoch=member.ref,producer.original.sha256,producer.raw_evidence['graph_epoch']
        _ABSENCES[self]=(self.owner,self.original_ref,self.token,self.original_sha,self.graph_epoch)
    def require_member_v3(self,member):
        if (_ABSENCES.get(self)!=(self.owner,self.original_ref,self.token,self.original_sha,self.graph_epoch)
                or member.ref!=self.token or member.outer is not self.original_ref()or member.outer is None
                or member.outer.sha256!=self.original_sha or member.revision!=0 or member.valid):
            raise AuthorityUnavailable('actual historical absence member/query changed')
        row=self.owner.db.execute('SELECT h.revision FROM graph_history h JOIN graph_events e ON e.bot=h.event_bot '
            'AND e.persona=h.event_persona AND e.session=h.event_session AND e.event_id=h.event_id '
            'WHERE h.token=? AND e.bot=? AND e.persona=? AND e.epoch_revision<=? LIMIT 1',
            (self.token,*self.owner.namespace.as_tuple,self.graph_epoch)).fetchone()
        if row is not None:raise AuthorityUnavailable('historical Source absence changed')
        return self

_NATURAL_ORIGINALS=WeakKeyDictionary()
class _PreparedNaturalPayloadEOFV3:
    def __init__(self,issuer,columns,raw,envelope):
        from .dispatch_current_inventory_v3 import _freeze_value_v3,_SOURCE_ISSUED
        if issuer is not _ISSUER or type(columns)is not PreparedNaturalOriginalsV3:
            raise AuthorityUnavailable('actual natural original payload EOF issuer required')
        original=columns.columns['typed_request_wire'];original.require_v3(columns.owner)
        if (_freeze_value_v3(raw)!=original._frozen_value or envelope.authority.namespace!=columns.owner.namespace
                or original.owner is not columns.owner or not columns.owner.sources):
            raise AuthorityUnavailable('actual natural request fields/namespace/Source EOF differ')
        for source in columns.owner.sources.values():
            if (source not in _SOURCE_ISSUED or source.scope is not columns.owner.fence.scope
                    or source.operation_id!=columns.owner.operation.operation_id):
                raise AuthorityUnavailable('actual same-work full Source EOF qualification required')
        self.columns,self.original,self.raw,self.envelope=columns,original,raw,envelope
        _PAYLOAD_EOF.add(self)
    def require_for_v3(self,request):
        from .dispatch_current_inventory_v3 import _freeze_value_v3
        from .reply_model_job import reply_request_wire_v1
        if (self not in _PAYLOAD_EOF or self.columns.owner.operation.closed or request.envelope!=self.envelope
                or request.payload is not self.raw['payload']
                or _freeze_value_v3(reply_request_wire_v1(request.envelope,request))!=self.original._frozen_value):
            raise AuthorityUnavailable('actual immutable full request/payload EOF differs')
        self.original.require_v3(self.columns.owner)
        _PAYLOAD_EOF.discard(self)


def require_prepared_model_payload_eof_v3(witness,request):
    if type(witness)is not _PreparedNaturalPayloadEOFV3:
        from ..authority_service.current_authority_graph_read_v3 import require_prepared_authority_model_payload_eof_v3
        require_prepared_authority_model_payload_eof_v3(witness,request)
        return
    witness.require_for_v3(request)


class PreparedNaturalOriginalsV3:
    def __init__(self,issuer,producer):
        if issuer is not _ISSUER:raise TypeError('actual complete natural original columns required')
        self.owner,self.meta,self.columns=producer.owner,producer.natural_meta,MappingProxyType(dict(producer.natural_json))
        for value in self.columns.values():value.require_v3(self.owner)
        self.digests=MappingProxyType(dict(producer.natural_digests));self.saved=None
        self.frozen_eof=producer.natural_frozen_read
        _NATURAL_ORIGINALS[self]=(self.owner,self.meta,self.columns,self.digests,self.saved,self.frozen_eof)
    def require_for_v3(self,db,namespace,parent,stage):
        if (_NATURAL_ORIGINALS.get(self)!=(self.owner,self.meta,self.columns,self.digests,self.saved,self.frozen_eof)or db is not self.owner.db
                or namespace!=self.owner.namespace or parent!=self.meta[0]or stage!='generation' or not db.in_transaction):
            raise AuthorityUnavailable('actual same-work natural original required')
        row=db.execute('SELECT parent_original_id,graph_epoch,access_epoch,deletion_epoch,state,typed_request_digest,worker_fence,'
            'terminal_receipt_digest,terminal_output_digest FROM graph_natural_generation_preparations_v2 '
            'WHERE bot=? AND persona=? AND parent_original_id=?',(*namespace.as_tuple,parent)).fetchone()
        if row!=self.meta:raise AuthorityUnavailable('natural original mutable state changed after prepare')
        return (None,None,None,None,self.meta[1],self.meta[2],self.meta[3],self.meta[4],self.meta[5],self.meta[6],None,self.meta[7],self.meta[8])
    def json_v3(self,name):return self.columns[name].require_v3(self.owner)
    def frozen_v3(self,raw):
        if _NATURAL_ORIGINALS.get(self)!=(self.owner,self.meta,self.columns,self.digests,self.saved,self.frozen_eof):
            raise AuthorityUnavailable("actual original frozen EOF issuer changed")
        return self.frozen_eof.require_for_v3(raw)
    def payload_eof_v3(self,raw,envelope):return _PreparedNaturalPayloadEOFV3(_ISSUER,self,raw,envelope)
    def require_payload_v3(self,payload):
        from .dispatch_current_inventory_v3 import _freeze_value_v3
        if (_NATURAL_ORIGINALS.get(self)!=(self.owner,self.meta,self.columns,self.digests,self.saved,self.frozen_eof)
                or self.digests.get('payload')!=self.frozen_eof.result.model_request_digest):
            raise AuthorityUnavailable('actual complete provider payload EOF witness required')
        value=dict(self.columns['typed_request_wire']._frozen_value.items)['payload']
        if _freeze_value_v3(dict(payload))!=value:
            raise AuthorityUnavailable('actual typed provider payload changed after complete EOF')
        return True
    def digest_v3(self,name):
        if _NATURAL_ORIGINALS.get(self)!=(self.owner,self.meta,self.columns,self.digests,self.saved,self.frozen_eof):
            raise AuthorityUnavailable('actual original complete digest witness changed')
        return self.digests[name]
    def qualify_saved_v3(self,issuer,saved):
        from .natural_reply_job_v2 import SavedNaturalPreparationV2
        if (issuer is not _ISSUER or self.saved is not None or type(saved)is not SavedNaturalPreparationV2
                or saved.stage!='generation' or saved.parent_original_id!=self.meta[0]or saved.seal.namespace!=self.owner.namespace):
            raise AuthorityUnavailable('actual fully typed natural original issuer required')
        self.saved=saved
        _NATURAL_ORIGINALS[self]=(self.owner,self.meta,self.columns,self.digests,self.saved,self.frozen_eof)
    def saved_v3(self,db,namespace,parent,stage):
        self.require_for_v3(db,namespace,parent,stage)
        if self.saved is not None:
            from .jobs import get_job
            job=get_job(db,self.saved.seal.job_id)
            if job is None or job.work_kind!='natural_generation' or job.operation_id!=self.saved.seal.original_operation_id:
                raise AuthorityUnavailable('actual saved natural current job identity changed')
        return self.saved



_NATURAL_HISTORIES=WeakKeyDictionary()
class PreparedNaturalHistoryV3:
    def __init__(self,issuer,producer):
        if issuer is not _ISSUER or len(producer.natural_cells)!=4:raise TypeError('actual natural four-member cell EOF required')
        self.owner,self.cells,self.rows=producer.owner,MappingProxyType(dict(producer.natural_cells)),MappingProxyType(dict(producer.natural_cell_rows))
        self.original=producer.original
        for value in self.cells.values():value.require_v3(self.owner)
        _NATURAL_HISTORIES[self]=(self.owner,self.cells,self.rows,self.original)
    def receipt_v3(self,db,namespace,operation):
        if (_NATURAL_HISTORIES.get(self)!=(self.owner,self.cells,self.rows,self.original)
                or db is not self.owner.db or namespace!=self.owner.namespace or operation!=self.owner.binding.operation_id):
            raise AuthorityUnavailable('natural receipt belongs to another actual work')
        return self.original.require_v3(self.owner)
    def read_history_json_v3(self,db,namespace,token,revision,activity,operation):
        key=(token,revision)
        if (_NATURAL_HISTORIES.get(self)!=(self.owner,self.cells,self.rows,self.original)or db is not self.owner.db or namespace!=self.owner.namespace
                or operation!=self.owner.binding.operation_id or activity!=self.owner.binding.origin.activity_id or key not in self.cells):
            raise AuthorityUnavailable('actual same-work natural producing history required')
        row=db.execute('SELECT value_cell_id,valid,event_bot,event_persona,event_session,event_id FROM graph_history WHERE token=? AND revision=?',key).fetchone()
        if row!=self.rows[key]:raise AuthorityUnavailable('natural actual producing cell/event identity changed')
        return self.cells[key].require_v3(self.owner),row[1]


def detach_dispatch_preparation_workspace_v3(reader):
    """Drop only volatile preparation work after its actual issued result is handed off."""
    auxiliary=reader.auxiliary
    reader.auxiliary=None
    if auxiliary is not None:
        for name in tuple(vars(auxiliary)):
            if name!='owner':setattr(auxiliary,name,None)
        auxiliary.owner=None


def require_dispatch_source_originals_current_v3(inventory,db):
    """Independent mutable originals are checked at the real final transaction."""
    if inventory.family=='private_reply':
        for roots,purpose,audiences,origin in inventory.source_descriptors:
            if origin[0]!='graph_post_c02_reply_ownership_v1':
                raise AuthorityUnavailable('actual private route original descriptor required')
            namespace=inventory.namespace
            row=db.execute('SELECT ingress_operation_id,c02_operation_id,source_ref,target_entity_ref,account_ref,destination_ref,'
                'admission_digest,state,ack_digest FROM graph_post_c02_reply_ownership_v1 WHERE bot=? AND persona=? AND admission_ref=?',
                (*namespace.as_tuple,origin[3])).fetchone()
            if row!=origin[4]:raise AuthorityUnavailable('actual private route ownership original changed after preparation')
            identity=inventory.graph._reply_ingress_identity_locked(namespace,row[0])
            if (identity['source_ref']!=AtomKey.from_token(roots[0]).owner.subject
                    or (identity['platform_ref'],identity['conversation_ref'])!=(row[4],row[5])):
                raise AuthorityUnavailable('actual private route ingress original changed after preparation')
    elif inventory.family=='contact':
        inventory.contact_birth.require_for_v3(db,inventory.namespace,inventory.binding.operation_id)
    elif inventory.family=='natural_reply':
        original=inventory.natural_originals
        original.require_for_v3(db,inventory.namespace,original.meta[0],'generation')
    else:raise AuthorityUnavailable('actual fixed dispatch family changed')

def _advance_host_saved_natural_columns_v3(self,meter):
    table='graph_natural_generation_preparations_v2';owner=self.owner
    if self.column is None:
        if self.natural_column_queue:
            name=self.natural_column_queue.pop(0)
            self.column=DispatchOriginalJSONReadV3(owner,table=table,column=name,key_columns=('bot','persona','parent_original_id'),
                key=(*owner.namespace.as_tuple,self.natural_meta[0]));return
        from .natural_frozen_original_read_v3 import begin_natural_frozen_original_read_v3,begin_authority_natural_frozen_original_read_v3
        if type(self)is AuthorityNaturalSavedOriginalReadV3:
            self.natural_frozen_read=begin_authority_natural_frozen_original_read_v3(owner,self.natural_json['frozen_json'])
        else:self.natural_frozen_read=begin_natural_frozen_original_read_v3(owner,self.natural_json['frozen_json'])
        self.phase='natural_frozen';return
    if self.column.advance(meter):self.natural_json[self.column.column]=self.column;self.column=None

def _advance_host_saved_natural_frozen_step_v3(self,meter):
    owner=self.owner
    if not self.natural_frozen_read.advance(meter):return
    if self.natural_meta[4]=='queued':
        frozen=self.natural_json['frozen_json'].require_v3(owner)
        self.natural_digests={};self.natural_frozen_wire=frozen['canonical_wire']
        self.natural_frozen_offset=0;self.natural_frozen_hash=sha256()
        self.phase='natural_digests';return
    raw=self.natural_json['typed_request_wire'].require_v3(owner)
    frozen=self.natural_json['frozen_json'].require_v3(owner)
    from .owner_material_source_storage_v3 import CanonicalValueStreamV3
    self.natural_digests={};self.natural_request_raw=raw
    from .natural_reply_job_v2 import _envelope_from_wire_v3
    from ..runtime_contracts import _canonical_value
    value={'envelope':_envelope_from_wire_v3(raw),'call_id':raw['call_id'],'provider_id':raw['provider_id'],'model_id':raw['model_id'],
        'purpose':raw['envelope']['authority']['purpose'],'required_capabilities':sorted(raw['required_capabilities']),
        'privacy_tier':raw['privacy_tier'],'template':raw['prompt_template_digest'],'payload':raw['payload'],
        'timeout_seconds':float(raw['timeout_seconds']),'max_output_tokens':raw['max_output_tokens']}
    owner.operation.retain(_container_bytes_v3(value)+65536)
    self.natural_digest_stream=CanonicalValueStreamV3(_canonical_value(value,set()))
    self.natural_frozen_wire=frozen['canonical_wire'];self.natural_frozen_offset=0;self.natural_frozen_hash=sha256()
    self.phase='natural_digests';return

def _advance_host_saved_natural_digest_step_v3(self,meter):
    table="graph_natural_generation_preparations_v2"
    owner=self.owner
    if self.natural_meta[4]!='queued' and not self.natural_digest_stream.complete:
        self.natural_digest_stream.read_fragment(meter)
        return
    if self.natural_meta[4]!='queued' and 'typed_request' not in self.natural_digests:
        self.natural_digests['typed_request']=self.natural_digest_stream.hash.hexdigest()
    if self.natural_meta[4]!='queued' and 'payload' not in self.natural_digests:
        from .owner_material_source_storage_v3 import CanonicalValueStreamV3
        from ..runtime_contracts import _canonical_value
        if not hasattr(self,'natural_payload_stream'):
            self.owner.operation.retain(_container_bytes_v3(self.natural_request_raw['payload'])+65536)
            self.natural_payload_stream=CanonicalValueStreamV3(_canonical_value(self.natural_request_raw['payload'],set()))
        if not self.natural_payload_stream.complete:
            self.natural_payload_stream.read_fragment(meter);return
        digest=self.natural_payload_stream.hash.hexdigest()
        if digest!=self.natural_frozen_read.result.model_request_digest:
            raise AuthorityUnavailable('actual complete typed request payload differs from frozen provider wire')
        self.natural_digests['payload']=digest
    if self.natural_frozen_offset<len(self.natural_frozen_wire):
        end=min(self.natural_frozen_offset+1024,len(self.natural_frozen_wire))
        meter.require_available(16384)
        encoded=self.natural_frozen_wire[self.natural_frozen_offset:end].encode('utf-8')
        meter.charge_encode(len(encoded));self.natural_frozen_hash.update(encoded);self.natural_frozen_offset=end;return
    self.natural_digests['frozen_wire']=self.natural_frozen_hash.hexdigest()
    self.natural_values=(PreparedAuthorityNaturalOriginalsV3(_AUTHORITY_NATURAL_ISSUER_V3,self)
        if type(self)is AuthorityNaturalSavedOriginalReadV3 else PreparedNaturalOriginalsV3(_ISSUER,self))
    from .natural_reply_job_v2 import read_original_preparation
    self.natural=read_original_preparation(owner.db,owner.namespace,self.natural_meta[0],'generation',prepared_originals=self.natural_values)
    if type(self)in(HostNaturalSavedOriginalReadV3,AuthorityNaturalSavedOriginalReadV3):
        if self.natural is None:raise AuthorityUnavailable('actual saved natural original disappeared')
        self.natural_values.qualify_saved_v3(_ISSUER,self.natural)
        self.complete=True;return
    if self.natural is None or self.natural.state!='terminal' or self.natural.seal.original_operation_id!=self.natural_evidence.generation_original_operation_id:
        raise AuthorityUnavailable('actual complete natural generation seal identity differs')
    self.natural_values.qualify_saved_v3(_ISSUER,self.natural)
    self.descriptors=(((self.natural.seal.source_ref,),'context',owner.admission.admission.audience,
        (table,*owner.namespace.as_tuple,self.natural.parent_original_id,self.natural_json['seal_json'].sha256)),)
    owner._require_source_roots_v3((self.natural.seal.source_ref,),'context',owner.admission.admission.audience)
    self.complete=True;return

class HostNaturalSavedOriginalReadV3:
    """Saved-generation originals in the sole originating ordinary FULL Work."""
    def __init__(self,issuer,owner,parent_original_id):
        if issuer is not _ISSUER:raise TypeError('installed same-Work saved-original reader required')
        from .current_graph_full_read_v3 import _OrdinaryFullReadV3
        if (type(owner)is not _OrdinaryFullReadV3 or owner.prefinal is None
                or owner.work.state is not owner or owner.work.operation is not owner.operation
                or type(parent_original_id)is not str or not parent_original_id):
            raise AuthorityUnavailable('actual ordinary natural saved-original reader required')
        owner.prefinal._actual()
        self.owner,self.parent_original_id=owner,parent_original_id
        self.complete=False;self.natural=None;self.natural_values=None
        self.phase='locate';self.column=None
    def advance(self,meter):
        self.owner.prefinal.require_current(meter=meter)
        if self.complete:return True
        if self.phase=='locate':
            from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3
            self.natural_meta=_runtime_bounded_fixed_row_v3(self.owner.db,meter,
                'graph_natural_generation_preparations_v2',
                ('parent_original_id','graph_epoch','access_epoch','deletion_epoch','state',
                 'typed_request_digest','worker_fence','terminal_receipt_digest','terminal_output_digest'),
                'bot=? AND persona=? AND parent_original_id=?',
                (*self.owner.namespace.as_tuple,self.parent_original_id))
            if self.natural_meta is None:self.complete=True;return True
            self.natural_json={};self.natural_column_queue=['seal_json','frozen_json','read_versions_json','query_epochs_json']
            if self.natural_meta[4]!='queued':self.natural_column_queue.append('typed_request_wire')
            self.phase='natural_columns'
        elif self.phase=='natural_columns':_advance_host_saved_natural_columns_v3(self,meter)
        elif self.phase=='natural_frozen':_advance_host_saved_natural_frozen_step_v3(self,meter)
        elif self.phase=='natural_digests':_advance_host_saved_natural_digest_step_v3(self,meter)
        else:raise AuthorityUnavailable('saved-original production phase differs')
        return self.complete
    def require_v3(self,owner):
        if self.owner is not owner or not self.complete or owner.operation.closed:
            raise AuthorityUnavailable('saved-original complete same-Work reader required')
        owner.prefinal._actual()
        return self.natural


def begin_host_natural_saved_original_read_v3(owner,*,parent_original_id):
    return HostNaturalSavedOriginalReadV3(_ISSUER,owner,parent_original_id)


_AUTHORITY_NATURAL_ISSUER_V3=object()
_AUTHORITY_NATURAL_ORIGINALS_V3=WeakKeyDictionary()
_AUTHORITY_SAVED_READERS_V3=WeakSet()


class PreparedAuthorityNaturalOriginalsV3(PreparedNaturalOriginalsV3):
    """Independent Authority saved-value issuer; not an ordinary Host original."""
    def __init__(self,issuer,producer):
        from ..authority_service.current_authority_graph_read_v3 import require_actual_authority_graph_attachment_owner_v3
        if issuer is not _AUTHORITY_NATURAL_ISSUER_V3 or producer not in _AUTHORITY_SAVED_READERS_V3:
            raise TypeError('actual Authority saved-value producer required')
        require_actual_authority_graph_attachment_owner_v3(producer.owner,db=producer.owner.db)
        super().__init__(_ISSUER,producer)
        self.stage=producer.stage
        self.request=None
        _AUTHORITY_NATURAL_ORIGINALS_V3[self]=(producer,producer.owner,producer.owner.operation,producer.owner.scope)
    def require_for_v3(self,db,namespace,parent,stage):
        require_actual_authority_natural_original_v3(self)
        if stage!=self.stage:raise AuthorityUnavailable('Authority natural original crossed its actual stage')
        if stage=='generation':return super().require_for_v3(db,namespace,parent,stage)
        if (db is not self.owner.db or namespace!=self.owner.namespace or parent!=self.meta[0]or not db.in_transaction):
            raise AuthorityUnavailable('actual same-Work Authority review original required')
        from ..runtime_storage_v3 import runtime_storage_quantum_v3,_runtime_bounded_fixed_row_v3
        with runtime_storage_quantum_v3(db)as meter:
            row=_runtime_bounded_fixed_row_v3(db,meter,'graph_natural_review_preparations_v2',
                ('parent_original_id','graph_epoch','access_epoch','deletion_epoch','state','typed_request_digest',
                 'worker_fence','terminal_receipt_digest','terminal_output_digest'),
                'bot=? AND persona=? AND parent_original_id=?',(*namespace.as_tuple,parent))
        if row!=self.meta:raise AuthorityUnavailable('Authority review mutable original state changed')
        return(None,None,None,None,*self.meta[1:7],None,*self.meta[7:])
    def require_payload_v3(self,payload):
        require_actual_authority_natural_original_v3(self)
        if self.stage=='generation':return super().require_payload_v3(payload)
        from .dispatch_current_inventory_v3 import _freeze_value_v3
        value=dict(self.columns['typed_request_wire']._frozen_value.items)['payload']
        if (self.digests.get('payload')!=self.frozen_eof.expected_payload_digest
                or _freeze_value_v3(payload)!=value):
            raise AuthorityUnavailable('Authority review full provider payload differs')
        return True
    def qualify_saved_v3(self,issuer,saved):
        if self.stage=='generation':return super().qualify_saved_v3(issuer,saved)
        from .natural_reply_job_v2 import SavedNaturalPreparationV2
        if (issuer is not _ISSUER or self.saved is not None or type(saved)is not SavedNaturalPreparationV2
                or saved.stage!='review' or saved.parent_original_id!=self.meta[0]
                or saved.seal.namespace!=self.owner.namespace):
            raise AuthorityUnavailable('actual fully typed Authority review original issuer required')
        self.saved=saved
        _NATURAL_ORIGINALS[self]=(self.owner,self.meta,self.columns,self.digests,self.saved,self.frozen_eof)
    def saved_v3(self,db,namespace,parent,stage):
        if self.stage=='generation':return super().saved_v3(db,namespace,parent,stage)
        self.require_for_v3(db,namespace,parent,stage)
        return self.saved
    def qualify_call_binding_v3(self,request):
        require_actual_authority_natural_original_v3(self)
        from ..model_broker.broker import ModelCallRequest
        if type(request)is not ModelCallRequest or self.request is not None:
            raise AuthorityUnavailable('Authority original typed request can be qualified only once')
        self.request=request
    def call_binding_v3(self,db,namespace,parent,stage):
        self.require_for_v3(db,namespace,parent,stage)
        if self.request is None:raise AuthorityUnavailable('Authority paid call has no qualified original request')
        return self.request
    def payload_eof_v3(self,raw,envelope):
        require_actual_authority_natural_original_v3(self)
        from ..authority_service.current_authority_graph_read_v3 import prepare_authority_natural_payload_eof_v3
        return prepare_authority_natural_payload_eof_v3(self,raw,envelope)


def require_actual_authority_natural_original_v3(original):
    from ..authority_service.current_authority_graph_read_v3 import require_actual_authority_graph_attachment_owner_v3
    if type(original)is not PreparedAuthorityNaturalOriginalsV3:
        raise TypeError('exact independently issued Authority natural original required')
    issuance=_AUTHORITY_NATURAL_ORIGINALS_V3.get(original)
    if issuance is None or issuance[1:]!=(original.owner,original.owner.operation,original.owner.scope):
        raise AuthorityUnavailable('Authority natural original lost its actual producer/lease/scope')
    require_actual_authority_graph_attachment_owner_v3(original.owner,db=original.owner.db)
    return original


class AuthorityNaturalSavedOriginalReadV3(HostNaturalSavedOriginalReadV3):
    """Canonical generation values in the originating Authority Work only."""
    def __init__(self,issuer,owner,parent_original_id):
        from ..authority_service.current_authority_graph_read_v3 import require_actual_authority_graph_attachment_owner_v3
        if issuer is not _AUTHORITY_NATURAL_ISSUER_V3:
            raise TypeError('actual Authority saved-generation reader required')
        require_actual_authority_graph_attachment_owner_v3(owner,db=owner.db)
        if type(parent_original_id)is not str or not parent_original_id:
            raise AuthorityUnavailable('Authority saved-generation needs its actual parent locator')
        self.owner,self.parent_original_id=owner,parent_original_id
        self.stage='generation'
        self.complete=False;self.natural=None;self.natural_values=None
        self.phase='locate';self.column=None
        _AUTHORITY_SAVED_READERS_V3.add(self)
    def require_v3(self,owner):
        from ..authority_service.current_authority_graph_read_v3 import require_actual_authority_graph_attachment_owner_v3
        require_actual_authority_graph_attachment_owner_v3(owner,db=owner.db)
        if self not in _AUTHORITY_SAVED_READERS_V3 or self.owner is not owner or not self.complete:
            raise AuthorityUnavailable('actual Authority generation original has not completed EOF')
        return self.natural


def begin_authority_natural_saved_original_read_v3(owner,*,parent_original_id):
    return AuthorityNaturalSavedOriginalReadV3(_AUTHORITY_NATURAL_ISSUER_V3,owner,parent_original_id)


class AuthorityNaturalReviewOriginalReadV3:
    def __init__(self,issuer,owner,parent_original_id,generation_original):
        from ..authority_service.current_authority_graph_read_v3 import require_actual_authority_graph_attachment_owner_v3
        if issuer is not _AUTHORITY_NATURAL_ISSUER_V3:raise TypeError('actual Authority review original issuer required')
        require_actual_authority_graph_attachment_owner_v3(owner,db=owner.db)
        require_actual_authority_natural_original_v3(generation_original)
        if (generation_original.owner is not owner or generation_original.stage!='generation'
                or generation_original.meta[0]!=parent_original_id or generation_original.saved is None):
            raise AuthorityUnavailable('Authority review needs its actual completed generation original')
        self.owner,self.parent_original_id,self.generation_original=owner,parent_original_id,generation_original
        self.stage='review';self.phase='locate';self.complete=False
        self.column=None;self.natural=None;self.natural_values=None;self.natural_frozen_read=None
        _AUTHORITY_SAVED_READERS_V3.add(self)
    def advance(self,meter):
        self.owner.require_current(meter=meter)
        table='graph_natural_review_preparations_v2';owner=self.owner
        if self.complete:return True
        if self.phase=='locate':
            from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3
            self.natural_meta=_runtime_bounded_fixed_row_v3(owner.db,meter,table,
                ('parent_original_id','graph_epoch','access_epoch','deletion_epoch','state',
                 'typed_request_digest','worker_fence','terminal_receipt_digest','terminal_output_digest'),
                'bot=? AND persona=? AND parent_original_id=?',(*owner.namespace.as_tuple,self.parent_original_id))
            if self.natural_meta is None:self.complete=True;return True
            self.natural_json={};self.queue=['seal_json','frozen_json','read_versions_json','query_epochs_json']
            if self.natural_meta[4]!='queued':self.queue.append('typed_request_wire')
            self.phase='columns';return False
        if self.phase=='columns':
            if self.column is not None:
                if self.column.advance(meter):self.natural_json[self.column.column]=self.column;self.column=None
                return False
            if self.queue:
                name=self.queue.pop(0)
                self.column=DispatchOriginalJSONReadV3(owner,table=table,column=name,
                    key_columns=('bot','persona','parent_original_id'),key=(*owner.namespace.as_tuple,self.parent_original_id))
                return False
            from ..authority_service.current_authority_graph_read_v3 import begin_authority_review_canonical_read_v3
            self.natural_frozen_read=begin_authority_review_canonical_read_v3(owner,self.natural_json['frozen_json'],
                generation=self.generation_original.saved.seal)
            self.phase='canonical';return False
        if self.phase=='canonical':
            if not self.natural_frozen_read.advance(meter):return False
            self.natural_digests={'frozen_wire':self.natural_frozen_read.wire_digest}
            if self.natural_meta[4]=='queued':self.phase='publish';return False
            raw=self.natural_json['typed_request_wire'].require_v3(owner)
            self.request_raw=raw
            from .natural_reply_job_v2 import _envelope_from_wire_v3
            from .natural_frozen_original_read_v3 import _CanonicalComparisonV3
            value={'envelope':_envelope_from_wire_v3(raw),'call_id':raw['call_id'],'provider_id':raw['provider_id'],
                'model_id':raw['model_id'],'purpose':raw['envelope']['authority']['purpose'],
                'required_capabilities':sorted(raw['required_capabilities']),'privacy_tier':raw['privacy_tier'],
                'template':raw['prompt_template_digest'],'payload':raw['payload'],
                'timeout_seconds':float(raw['timeout_seconds']),'max_output_tokens':raw['max_output_tokens']}
            self.comparison=_CanonicalComparisonV3(value,operation=owner.operation)
            self.phase='request';return False
        if self.phase=='request':
            if not self.comparison.advance(meter):return False
            self.natural_digests['typed_request']=self.comparison.digest
            from .natural_frozen_original_read_v3 import _CanonicalComparisonV3
            self.comparison=_CanonicalComparisonV3(self.request_raw['payload'],operation=owner.operation)
            self.phase='payload';return False
        if self.phase=='payload':
            if not self.comparison.advance(meter):return False
            self.natural_digests['payload']=self.comparison.digest
            if self.comparison.digest!=self.natural_frozen_read.expected_payload_digest:
                raise AuthorityUnavailable('Authority review actual paid payload differs from frozen provider wire')
            self.phase='publish';return False
        if self.phase=='publish':
            self.natural_values=PreparedAuthorityNaturalOriginalsV3(_AUTHORITY_NATURAL_ISSUER_V3,self)
            from .natural_reply_job_v2 import read_original_preparation
            self.natural=read_original_preparation(owner.db,owner.namespace,self.parent_original_id,'review',
                prepared_originals=self.natural_values)
            if self.natural is None:raise AuthorityUnavailable('actual Authority review original disappeared')
            self.natural_values.qualify_saved_v3(_ISSUER,self.natural)
            self.complete=True;return True
        raise AuthorityUnavailable('unregistered Authority review original phase')
    def require_v3(self,owner):
        from ..authority_service.current_authority_graph_read_v3 import require_actual_authority_graph_attachment_owner_v3
        require_actual_authority_graph_attachment_owner_v3(owner,db=owner.db)
        if self not in _AUTHORITY_SAVED_READERS_V3 or self.owner is not owner or not self.complete:
            raise AuthorityUnavailable('Authority review original requires actual completed EOF')
        return self.natural


def begin_authority_natural_review_original_read_v3(owner,*,parent_original_id,generation_original):
    return AuthorityNaturalReviewOriginalReadV3(_AUTHORITY_NATURAL_ISSUER_V3,owner,parent_original_id,generation_original)
