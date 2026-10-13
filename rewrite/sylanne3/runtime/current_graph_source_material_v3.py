"""Root Source material prepared by the originating ordinary FULL Work."""
from copy import copy
import hmac
from hashlib import sha256
from types import MappingProxyType
from weakref import WeakKeyDictionary,WeakSet

from ..authority_service.contract import AuthorityUnavailable
from ..graph_types import AtomKey,NamespaceEpoch,GraphVersion
from ..memory_types import SourceRecord,source_key,access_key
from ..runtime_contracts import CommitReceipt
from ..runtime_storage_v3 import RuntimeCellReadV3
from .c09_graph_row_codec_v2 import C09MemorySourceJSONStreamV3
from .source_correction_read_v3 import _heap

_ISSUER=object()
_READERS=WeakSet()
_MATERIALS=WeakKeyDictionary()
_C02_ORIGINALS=WeakKeyDictionary()


class _SourceTextJSONStreamV3(C09MemorySourceJSONStreamV3):
    """The same complete Source semantics, retaining only this required root text."""
    def __init__(self,**profile):
        self.text_chunks=[];self.text_pending=[];self.text=None
        super().__init__(**profile)
    def _source_heap_bytes(self):
        return super()._source_heap_bytes()+_heap((self.text_chunks,self.text_pending,self.text))
    def _source_character(self,codepoint):
        super()._source_character(codepoint)
        self._source_require_arena(4096)
        self.text_pending.append(chr(codepoint))
        if len(self.text_pending)==256:
            self.text_chunks.append(''.join(self.text_pending));self.text_pending.clear()
    def finish(self):
        result=super().finish()
        self._source_require_arena(self._source_text_characters*4+8192)
        self.text=''.join((*self.text_chunks,''.join(self.text_pending)))
        self.text_chunks=[];self.text_pending=[]
        return result


def _require_prefinal(prefinal,entry,meter=None):
    from .current_graph_full_read_v3 import _PrefinalSourceInventoryV3,_CurrentSourceEntryLocatorV3
    if (type(prefinal) is not _PrefinalSourceInventoryV3 or type(entry) is not _CurrentSourceEntryLocatorV3
            or entry is not prefinal.actual_entry):
        raise AuthorityUnavailable('actual originating prefinal Source inventory/entry locator required')
    prefinal.require_current(meter=meter)
    return prefinal


class PreparedCurrentC02OriginalsV3:
    """Fixed C02 original columns, each complete under the originating Work."""
    def __init__(self,token,reader):
        if token is not _ISSUER or reader not in _READERS or reader.entry_column_position!=len(reader.entry_specs):
            raise AuthorityUnavailable('actual complete C02 original streams required')
        if not hmac.compare_digest(reader.quote_hmac.hexdigest(),reader.quote_signature):
            raise AuthorityUnavailable('original resource-quote.v1 signature is invalid')
        self.prefinal,self.entry=reader.prefinal,reader.entry
        self.issuer,self.quote_id=reader.entry_issuer,reader.quote_id
        self.columns=MappingProxyType(dict(reader.entry_columns))
        self.business,self.archive,self.event_epoch=reader.entry_business,reader.entry_archive,reader.entry_event_epoch
        self.quote_signature=reader.quote_signature
        quote_value=self.value_v3('signed_quote')
        from .issuers import ResourceQuote
        quote_value['outbox_refs']=tuple(quote_value['outbox_refs'])
        quote_value['d02_settlement_refs']=tuple(quote_value['d02_settlement_refs'])
        self.quote=ResourceQuote(**quote_value)
        _C02_ORIGINALS[self]=self._identity()
        self.require_archive_quote_v3()
    def _identity(self):
        return(self.prefinal,self.entry,self.issuer,self.quote_id,self.columns,self.business,self.archive,
            self.event_epoch,self.quote_signature,self.quote,tuple((name,column.sha256,column.byte_count)for name,column in self.columns.items()))
    def require_for_v3(self,prefinal,entry):
        if(type(self)is not PreparedCurrentC02OriginalsV3 or _C02_ORIGINALS.get(self)!=self._identity()
                or self.prefinal is not prefinal or self.entry is not entry or self.prefinal.operation.closed):
            raise AuthorityUnavailable('actual issued same-Work C02 originals required')
        prefinal._actual()
        return self
    def value_v3(self,name):
        return self.columns[name].require_v3(self.prefinal.reader)
    def require_quote_for_v3(self,issuer,db,quote_id,version):
        self.require_for_v3(self.prefinal,self.entry)
        if issuer is not self.issuer or db is not self.prefinal.db or quote_id!=self.quote_id or version!=1:
            raise AuthorityUnavailable('complete signed quote belongs to another actual issuer/PK/Work')
        if(self.quote.quote_id,self.quote.version)!=(quote_id,version):
            raise AuthorityUnavailable('original signed quote identity differs')
        return self.quote
    def require_archive_quote_v3(self):
        signed,archived=self.columns['signed_quote'],self.columns['archive_quote']
        if(signed.sha256,signed.byte_count)!=(archived.sha256,archived.byte_count):
            raise AuthorityUnavailable('C02 archived quote differs from its actual signed canonical EOF')


def _read_entry(prefinal,entry,meter,originals):
    """Resolve the locator through complete C02 originals and its unchanged leaf checks."""
    from ..domains.d07 import _qualify_focus_attention_values_v3
    from .reply_model_job import read_current_reply_model_inputs_v1
    originals.require_for_v3(prefinal,entry)
    db=prefinal.db;ns=prefinal.namespace;op=entry.c02_operation_id
    evidence=originals.value_v3('evidence');ref=source_key(*ns.as_tuple,evidence['source_ref']).token
    if entry.source_ref is not None and entry.source_ref!=ref:
        raise AuthorityUnavailable('Source material locator differs from the actual C02 Source original')
    row=originals.business;detail=originals.value_v3('business')
    reads=tuple(GraphVersion(AtomKey.from_token(token),revision)for token,revision in originals.value_v3('event_reads'))
    writes=tuple(GraphVersion(AtomKey.from_token(token),revision)for token,revision in originals.value_v3('event_writes'))
    receipt=CommitReceipt('committed',op,row[0],row[1],row[2],row[3],reads,writes,
        (NamespaceEpoch(*ns.as_tuple,originals.event_epoch),),tuple(detail['ledger_refs']),tuple(detail['outbox_refs']))
    source_reader=lambda key:prefinal.source_metadata(db,ns,prefinal.query,key,require_grant=False,meter=meter)
    attention=_qualify_focus_attention_values_v3(prefinal.projection,ns,now=None,source_reader=source_reader)
    if attention is None:raise AuthorityUnavailable('Source material current D07 focus/ticket is unavailable')
    inputs=read_current_reply_model_inputs_v1(db,originals.issuer,ns,receipt,ref,prefinal.projection,attention,
        _prefinal_source_inventory=prefinal,_prepared_c02_originals=originals)
    return ref,inputs


def _record_heap(record):
    return 0 if record is None else _heap(record.__dict__)


def _family_from_nodes(reader):
    from ..domains.d07.qualified_attention_read import QualifiedPreparedAttentionReadV3
    active=set();settled=set()
    def visit(ref):
        if ref in active:raise AuthorityUnavailable('Source material ancestry contains a cycle')
        if ref in settled:return
        active.add(ref)
        for parent in reader.metadata_records[ref].parent_source_ids:
            visit(source_key(*reader.prefinal.namespace.as_tuple,parent).token)
        active.remove(ref);settled.add(ref)
    for ref in reader.witnesses:visit(ref)
    versions=[]
    from ..domains.d06 import source_correction_head_key
    ns=reader.prefinal.namespace
    pending=list(reader.inputs.attention.ticket.source_refs);visited=set()
    while pending:
        ref=pending.pop()
        if ref in visited:continue
        visited.add(ref)
        key=AtomKey.from_token(ref);witness=reader.witnesses[ref]
        access=access_key(*ns.as_tuple,key.owner.subject)
        versions.extend((GraphVersion(key,witness.revision),GraphVersion(access,reader.prefinal.projection.get(access).revision),
            GraphVersion(source_correction_head_key(ns,key.owner.subject),0)))
        pending.extend(source_key(*ns.as_tuple,parent).token for parent in reader.metadata_records[ref].parent_source_ids)
    return QualifiedPreparedAttentionReadV3(reader.inputs.attention,
        tuple(reader.witnesses[ref]for ref in sorted(reader.attention_refs)),
        tuple(dict.fromkeys((reader.inputs.attention.focus_version,reader.inputs.attention.ticket_version,*versions))),
        reader.inputs.conversation_ref,'expression')


class PreparedCurrentSourceMaterialV3:
    """Actual required root texts with complete cells and separate metadata ancestry."""
    def __init__(self,token,reader):
        if token is not _ISSUER or reader not in _READERS or not reader.complete:
            raise AuthorityUnavailable('actual complete same-Work Source material issuer required')
        self.prefinal_inventory,self.actual_entry=reader.prefinal,reader.entry
        self.namespace,self.operation,self.work=reader.prefinal.namespace,reader.prefinal.operation,reader.prefinal.work
        self.source_ref,self.inputs,self.family=reader.source_ref,reader.inputs,reader.family
        self.c02_originals=reader.c02_originals
        self.roots=reader.roots
        self.audiences=(reader.inputs.conversation_ref,)
        self.producer_members=reader.producer_members
        self.rights_versions=tuple(sorted(reader.versions,key=lambda version:version.key.token))
        self.source_records=MappingProxyType(dict(reader.records))
        self.source_record=self.source_records[self.source_ref]
        self.witnesses=MappingProxyType(dict(reader.witnesses))
        self.metadata_records=MappingProxyType({ref:witness.metadata for ref,witness in reader.witnesses.items()})
        self.witness=self.witnesses[self.source_ref]
        self.header=tuple(self.witness.header)
        self.payload_sha256,self.payload_bytes=self.header[5],self.header[3]
        self.scope,self.selection_digest=reader.prefinal.scope,reader.prefinal.selection_digest
        _MATERIALS[self]=self._identity()
    def _identity(self):
        return(self.prefinal_inventory,self.actual_entry,self.namespace,self.operation,self.work,self.source_ref,
            self.inputs,self.family,self.c02_originals,self.roots,self.audiences,self.producer_members,self.rights_versions,self.source_records,self.source_record,self.witnesses,
            self.metadata_records,self.witness,self.payload_sha256,self.payload_bytes,self.header,self.scope,self.selection_digest)
    def require_current(self,*,db,prepared_full_read,namespace,source_ref,audiences,purpose='expression'):
        from .current_graph_full_read_v3 import(PreparedCurrentGraphFullReadV3,PreparedCurrentGraphFullWriteViewV3,
            require_bound_graph_full_read_proof_for_db_v3,CURRENT_DISPATCH_FAMILY_V3,SOURCE_METADATA_FAMILY_V3)
        require_prepared_current_source_material_v3(self,prefinal_inventory=self.prefinal_inventory,actual_entry=self.actual_entry)
        if(type(prepared_full_read)not in(PreparedCurrentGraphFullReadV3,PreparedCurrentGraphFullWriteViewV3)or prepared_full_read.source_material is not self
                or prepared_full_read.prefinal is not self.prefinal_inventory or db is not self.prefinal_inventory.db
                or namespace!=self.namespace or source_ref not in self.source_records
                or tuple(audiences)!=self.audiences or purpose!='expression'or not db.in_transaction):
            raise AuthorityUnavailable('Source material belongs to another actual FULL entry or rights scope')
        actual=require_bound_graph_full_read_proof_for_db_v3(db,namespace,
            required_families=frozenset({CURRENT_DISPATCH_FAMILY_V3,SOURCE_METADATA_FAMILY_V3}))
        if actual is not prepared_full_read:raise AuthorityUnavailable('Source material actual Binder changed')
        if type(actual)is PreparedCurrentGraphFullReadV3:self.prefinal_inventory.require_current()
        else:self.prefinal_inventory._actual()
        # FULL's unchanged graph stamp and epochs cover these complete same-Work heads.
        # The retained originals are still exact members, never purpose/audience grants themselves.
        from .dispatch_current_inventory_v3 import _SOURCE_ISSUED
        for ref,witness in self.witnesses.items():
            expected=(db,witness.source_key,witness.revision,witness.valid,witness.cell_id,witness.header,
                witness.payload_sha256,witness.metadata,witness.scope,witness.graph_stamp,witness.query,
                witness.operation_id,witness.selection_digest)
            if(_SOURCE_ISSUED.get(witness)!=expected or actual.sources.get(ref)is not witness
                    or actual.heads.get(ref)!=(witness.revision,int(witness.valid),witness.cell_id)):
                raise AuthorityUnavailable('Source material ancestor/head original changed')
        return self
    def source_record_for_v3(self,*,db,prepared_full_read,namespace,source_ref,audiences,purpose='expression'):
        self.require_current(db=db,prepared_full_read=prepared_full_read,namespace=namespace,source_ref=source_ref,
            audiences=audiences,purpose=purpose)
        return self.source_records[source_ref]
    def source_family_for_v3(self,*,db,prepared_full_read,namespace,source_ref,audiences):
        self.require_current(db=db,prepared_full_read=prepared_full_read,namespace=namespace,source_ref=source_ref,audiences=audiences)
        pending=[source_ref];visited=set();lineage=[];versions=[]
        while pending:
            ref=pending.pop()
            if ref in visited:continue
            visited.add(ref);lineage.append(ref)
            key=AtomKey.from_token(ref);witness=self.witnesses[ref]
            access=access_key(*namespace.as_tuple,key.owner.subject)
            from ..domains.d06 import source_correction_head_key
            correction=source_correction_head_key(namespace,key.owner.subject)
            atom=prepared_full_read.projection.get(access)
            versions.extend((GraphVersion(key,witness.revision),GraphVersion(access,atom.revision),GraphVersion(correction,0)))
            pending.extend(source_key(*namespace.as_tuple,parent).token for parent in self.metadata_records[ref]['parent_source_ids'])
        return tuple(lineage),tuple(sorted(versions,key=lambda version:version.key.token))


class CurrentGraphSourceMaterialReadV3:
    def __init__(self,token,prefinal,entry):
        if token is not _ISSUER:raise AuthorityUnavailable('actual Source material factory required')
        self.prefinal,self.entry=prefinal,entry
        self.phase='entry_setup';self.inputs=self.source_ref=self.witness=self.family=None
        self.entry_specs=();self.entry_column_position=0;self.entry_column=None;self.entry_columns={}
        self.entry_business=self.entry_archive=self.entry_event_epoch=self.entry_issuer=self.quote_id=self.quote_signature=None
        self.quote_hmac=None;self.c02_originals=None
        self.producer_members=None;self.roots=();self.pending=[];self.versions=[];self.attention_refs=set()
        self.witnesses={};self.metadata_records={};self.records={};self.root_position=0
        self.cell=self.parser=None;self.fragment=b'';self.offset=0;self.record=None
        self.complete=False;self.proof=None;self.reserved=0
        _READERS.add(self);self._reserve(65536)
    def _reserve(self,extra=0):
        size=_heap((self.fragment,self.pending,self.versions))+extra+65536
        size+=sum(_record_heap(record)for record in self.records.values())
        size+=sum(_heap(dict(witness.metadata))+1024 for witness in self.witnesses.values())
        if self.parser is not None:size+=self.parser._source_heap_bytes()
        if size>self.reserved:self.prefinal.operation.retain(size-self.reserved);self.reserved=size
    def advance(self,*,meter):
        if self not in _READERS or self.complete:raise AuthorityUnavailable('actual incomplete Source material Work required')
        _require_prefinal(self.prefinal,self.entry,meter)
        result=copy(self)
        result.entry_columns=dict(self.entry_columns)
        if self.quote_hmac is not None:result.quote_hmac=self.quote_hmac.copy()
        result.pending=list(self.pending);result.versions=list(self.versions);result.attention_refs=set(self.attention_refs)
        result.witnesses=dict(self.witnesses);result.metadata_records=dict(self.metadata_records);result.records=dict(self.records)
        if self.cell is not None:
            result.cell=copy(self.cell);result.cell.hash=self.cell.hash.copy()
        if self.parser is not None:result.parser=self.parser.copy()
        _READERS.add(result)
        result._reserve(32768+(0 if self.parser is None else self.parser._source_heap_bytes()))
        result._advance(meter)
        _require_prefinal(self.prefinal,self.entry,meter);result._reserve()
        return result
    def _advance(self,meter):
        db=self.prefinal.db;ns=self.prefinal.namespace
        if self.phase=='entry_setup':
            from .issuers import d06_first_ingress_c02_quote_id
            op=self.entry.c02_operation_id
            self.entry_business=meter.read_fixed_row(db,'graph_bundle_operations',('digest','activity_id','effect_id','commit_seq'),
                'bot=? AND persona=? AND operation_id=?',(*ns.as_tuple,op))
            self.entry_archive=meter.read_fixed_row(db,'graph_first_ingress_c02_committed_seals_v2',('schema','bundle_digest'),
                'bot=? AND persona=? AND operation_id=?',(*ns.as_tuple,op))
            if self.entry_business is None or self.entry_archive is None:
                raise AuthorityUnavailable('Source entry lacks its actual committed C02 original')
            event=meter.read_fixed_row(db,'graph_events',('epoch_revision',),
                'bot=? AND persona=? AND session=? AND event_id=?',(*ns.as_tuple,self.entry_business[1],op))
            if event is None:raise AuthorityUnavailable('Source entry lacks its actual C02 W01 event')
            self.entry_event_epoch=event[0]
            self.entry_issuer=self.prefinal.graph._GraphCoordinator__d02_issuer
            self.quote_id=d06_first_ingress_c02_quote_id(ns,op)
            signature=meter.read_fixed_row(db,'runtime_resource_quotes',('signature',),'quote_id=? AND version=?',(self.quote_id,1))
            if signature is None:raise AuthorityUnavailable('original signed C02 resource quote is absent')
            self.quote_signature=signature[0]
            self.quote_hmac=hmac.new(self.entry_issuer._signer._Signer__key,b'resource-quote.v1\n',sha256)
            from ..runtime_contracts import canonical_digest
            cost='c02-cost-'+canonical_digest({'namespace':list(ns.as_tuple),'operation_id':op})[:48]
            nskey=(*ns.as_tuple,op);eventkey=(*ns.as_tuple,self.entry_business[1],op)
            self.entry_specs=(
                ('evidence','graph_first_ingress_c02_committed_seals_v2','evidence_json',('bot','persona','operation_id'),nskey),
                ('archive_quote','graph_first_ingress_c02_committed_seals_v2','quote_json',('bot','persona','operation_id'),nskey),
                ('business','graph_bundle_operations','receipt_json',('bot','persona','operation_id'),nskey),
                ('cost','graph_bundle_operations','receipt_json',('bot','persona','operation_id'),(*ns.as_tuple,cost)),
                ('event_reads','graph_events','reads',('bot','persona','session','event_id'),eventkey),
                ('event_writes','graph_events','revisions',('bot','persona','session','event_id'),eventkey),
                ('signed_quote','runtime_resource_quotes','quote_json',('quote_id','version'),(self.quote_id,1)))
            self.phase='entry_columns';return
        if self.phase=='entry_columns':
            if self.entry_column_position==len(self.entry_specs):
                self.c02_originals=PreparedCurrentC02OriginalsV3(_ISSUER,self);self.phase='entry';return
            if self.entry_column is None:
                from .dispatch_initial_source_read_v3 import DispatchOriginalJSONReadV3
                name,table,column,key_columns,key=self.entry_specs[self.entry_column_position]
                self.entry_column=DispatchOriginalJSONReadV3(self.prefinal.reader,table=table,column=column,key_columns=key_columns,key=key)
                return
            name=self.entry_specs[self.entry_column_position][0]
            before=self.entry_column.offset
            finished=self.entry_column.advance(meter)
            if name=='signed_quote'and self.entry_column.offset>before:self.quote_hmac.update(self.entry_column.fragment)
            if finished:
                self.entry_columns[name]=self.entry_column;self.entry_column=None;self.entry_column_position+=1
            return
        if self.phase=='entry':
            from .c09_paged_sql_v2 import legacy_cell_read_transaction_v2
            with legacy_cell_read_transaction_v2(db):
                self.source_ref,self.inputs=_read_entry(self.prefinal,self.entry,meter,self.c02_originals)
            self.producer_members=self.prefinal.reader.prepared_producer_members
            roots=()
            if self.producer_members is not None:
                from .natural_producer_qualification_v1 import require_prepared_host_natural_producers_v3
                proof=require_prepared_host_natural_producers_v3(self.producer_members,prefinal=self.prefinal,scope=self.prefinal.scope)
                roots=proof.require_for(self.prefinal,self.entry)
            self.roots=tuple(dict.fromkeys((self.source_ref,*roots)))
            self.pending=[(ref,False)for ref in self.roots]+[(ref,True)for ref in self.inputs.attention.ticket.source_refs]
            self.phase='rights';return
        if self.phase=='rights':
            if not self.pending:self.family=_family_from_nodes(self);self.phase='cell';return
            ref,attention_required=self.pending.pop()
            if ref in self.witnesses:
                if attention_required and ref not in self.attention_refs:
                    record=self.metadata_records[ref]
                    if record.assertion_status not in {'confirmed','reported'}:
                        raise AuthorityUnavailable('D07 ticket Source assertion status differs')
                    self.attention_refs.add(ref)
                    self.pending.extend((source_key(*ns.as_tuple,parent).token,True)for parent in record.parent_source_ids)
                return
            if len(self.witnesses)>=256:raise AuthorityUnavailable('Source material ancestry exceeds its original bound')
            from ..domains.d06 import source_correction_head_key
            from ..domains.d07.qualified_attention_read import _qualify_source_node_values_v3,_qualify_source_rights_values_v3
            key=AtomKey.from_token(ref)
            witness=self.prefinal.source_metadata(db,ns,self.prefinal.query,key,require_grant=False,meter=meter)
            access=access_key(*ns.as_tuple,key.owner.subject);head=source_correction_head_key(ns,key.owner.subject)
            correction=self.prefinal.correction_head(db,ns,self.prefinal.query,head,meter=meter)
            atom=self.prefinal.projection.get(access)
            qualifier=_qualify_source_node_values_v3 if attention_required else _qualify_source_rights_values_v3
            record=qualifier(ns,ref,witness,atom,correction,
                audience=self.inputs.conversation_ref,purpose='expression',metadata_only=True)
            if record is None:raise AuthorityUnavailable('Source material ancestry/access/correction/purpose/audience differs')
            self.witnesses[ref]=witness;self.metadata_records[ref]=record
            if attention_required:self.attention_refs.add(ref)
            self.versions.extend((GraphVersion(key,witness.revision),GraphVersion(access,atom.revision),GraphVersion(head,0)))
            self.pending.extend((source_key(*ns.as_tuple,parent).token,attention_required)for parent in record.parent_source_ids)
            return
        if self.phase=='cell':
            if self.root_position==len(self.roots):self.phase='seal';return
            ref=self.roots[self.root_position];self.witness=self.witnesses[ref]
            self.cell=RuntimeCellReadV3(self.prefinal.operation.handle,self.witness.cell_id,erasure_owner_ref=ref,meter=meter)
            if tuple(self.cell.header)!=tuple(self.witness.header)or self.cell.header[0]not in('canonical-json.ascii.v1','canonical-json.utf8.v1'):
                raise AuthorityUnavailable('Source material requires its actual whole canonical Source cell')
            self.parser=_SourceTextJSONStreamV3(ensure_ascii=self.cell.header[0]=='canonical-json.ascii.v1');self.phase='body';return
        if self.phase=='body':
            if self.offset<len(self.fragment):
                end=min(self.offset+1024,len(self.fragment));self._reserve(65536)
                self.parser.feed(self.fragment[self.offset:end],lambda event:None);self.offset=end;return
            fragment=self.cell.read_fragment(meter=meter)
            if fragment is not None:self.fragment,self.offset=fragment,0;return
            self.phase='eof';return
        if self.phase=='eof':
            self._reserve(self.parser._source_text_characters*4+8192)
            parsed=self.parser.finish();digest=self.cell.finish(meter=meter)
            metadata={key:tuple(value)if type(value)is list else value for key,value in self.parser._source_metadata.items()}
            if(parsed.byte_count!=self.cell.header[3]or parsed.sha256!=digest or digest!=self.witness.payload_sha256
                    or metadata!=dict(self.witness.metadata)):
                raise AuthorityUnavailable('Source material full codec/SHA/EOF or original metadata differs')
            self.records[self.roots[self.root_position]]=SourceRecord.from_dict(dict(self.parser._source_metadata,text=self.parser.text))
            self.fragment=b'';self.offset=0;self.parser=self.cell=None;self.root_position+=1;self.phase='cell';return
        if self.phase=='seal':
            if self.producer_members is not None:self.producer_members.require_for(self.prefinal,self.entry)
            self.complete=True;self.proof=PreparedCurrentSourceMaterialV3(_ISSUER,self);return
        raise AuthorityUnavailable('Source material Work phase differs')


def begin_current_graph_source_material_v3(prefinal_inventory,*,actual_entry):
    _require_prefinal(prefinal_inventory,actual_entry)
    return CurrentGraphSourceMaterialReadV3(_ISSUER,prefinal_inventory,actual_entry)


def require_prepared_current_source_material_v3(material,*,prefinal_inventory,actual_entry):
    if (type(material) is not PreparedCurrentSourceMaterialV3 or _MATERIALS.get(material)!=material._identity()
            or material.prefinal_inventory is not prefinal_inventory or material.actual_entry is not actual_entry
            or material.operation is not prefinal_inventory.operation or material.work is not prefinal_inventory.work
            or material.operation.closed or material.selection_digest!=prefinal_inventory.selection_digest):
        raise AuthorityUnavailable('actual issued complete same-Work Source material required')
    prefinal_inventory._actual()
    material.c02_originals.require_for_v3(prefinal_inventory,actual_entry)
    return material
