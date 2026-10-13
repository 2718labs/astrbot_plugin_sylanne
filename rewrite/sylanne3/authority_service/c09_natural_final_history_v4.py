"""Natural final permissions from the actual frozen Source history keyset."""
from copy import copy
from weakref import WeakSet
from dataclasses import asdict,fields,is_dataclass
from hashlib import sha256
import json
import sys
from .c09_authority_storage_rebase_v2 import C09PagedCaptureHold,_D13PaidRowStreamV3,C09CanonicalJSONStreamV2
from ..runtime.c09_paged_sql_v2 import (legacy_cell_read_transaction_v2,read_c09_table_shape_v2,
    read_legacy_sql_cell_fragment_v2,c09_canonical_json_size_v3)
from ..runtime_contracts import canonical_serialize,meter_canonical_outputs

_HISTORY=('token','revision','value','valid','dependencies','event_bot','event_persona','event_session','event_id')
_EVENTS=('bot','persona','session','event_id','digest','reads','epoch_reads','revisions','invalidated','epoch_revision')
_RETAIN_TYPES=frozenset({'d11.owner_grant.v1','d03.entity_anchor','d03.account_binding','d03.world_event',
    'd03.role_binding','d05.boundary_rule','d08.goal.v1','d08.action_intent.v1','d08.action_schema.v1',
    'd08.action_cancellation.v1','d08.commitment.v1','d08.action_outcome.v1','d08.communication_intent_grant.v1','memory.access'})

def _heap(value):
    result=sys.getsizeof(value)
    if type(value) is dict:result+=sum(_heap(k)+_heap(v) for k,v in value.items())
    elif type(value) in (list,tuple,set,frozenset):result+=sum(_heap(v) for v in value)
    elif is_dataclass(value) and not isinstance(value,type):result+=sum(_heap(getattr(value,f.name)) for f in fields(value))
    return result

def _encode(source,value,meter):
    bound=c09_canonical_json_size_v3(value,typed=True)*2;source.require_arena(bound*32+16384);meter.require_available(bound*2)
    with meter_canonical_outputs(meter):raw=canonical_serialize(value).encode('ascii')
    meter.charge_encode(len(raw));return raw

class NaturalFinalPayloadArrayCursorV4:
    """Bounded original array elements; no complete array allocation."""
    def __init__(self,owner,path,*,column='receipt_json'):
        self.parent=owner.parent;self.source=owner.source;self.graph=owner.graph
        original=owner.parent.natural_final_original;self.column=column
        if column=='receipt_json':
            self.left,self.right=original.receipt_parser.ranges[path];self.total=original.bundle_total
            self.table='graph_bundle_operations';self.where='bot=? AND persona=? AND operation_id=?'
            self.row_key=(*self.parent.namespace.as_tuple,self.parent.handoff.observation.binding.origin.operation_id)
        elif column=='admission_json':
            self.left,self.right=original.admission_ranges[path];self.total=original.admission_total
            self.table='graph_dispatch_admissions';self.where='bot=? AND persona=? AND admission_ref=?'
            self.row_key=(*self.parent.namespace.as_tuple,self.parent.handoff.observation.binding.origin.admission_ref)
        else:raise C09PagedCaptureHold('closed actual final array source column required')
        self.offset=0;self.base=0;self.buffer=bytearray();self.queue=[];self.starts={};self.completed=[]
        self.parser=C09CanonicalJSONStreamV2(ensure_ascii=True);self.index=0;self.complete=False;self.source.arena.add(self)
    def _source_heap_bytes(self):
        return _heap((self.buffer,self.queue,self.starts,self.completed))+sum(_heap(getattr(self.parser,n)) for n in C09CanonicalJSONStreamV2.__slots__ if n!='_emit_callback')+8192
    def copy(self):
        self.source.require_arena(self._source_heap_bytes());result=copy(self)
        result.buffer=bytearray(self.buffer);result.queue=list(self.queue);result.starts=dict(self.starts)
        result.completed=[];result.parser=self.parser.copy();self.source.arena.add(result);return result
    def _event(self,event):
        if not event.path and event.kind in {'object_start','array_start','scalar_start'} and event.kind!='array_start':
            raise C09PagedCaptureHold('actual original final array has another root codec')
        if len(event.path)!=1:return
        if event.kind in {'array_start','object_start','scalar_start'}:self.starts[event.path]=event.start_offset
        elif event.kind in {'array_end','object_end','scalar_end'}:self.completed.append((event.path[0],self.starts.pop(event.path),event.end_offset))
    def advance(self,meter):
        result=self.copy()
        if result.queue or result.complete:return result
        amount=min(1024,result.right-result.left-result.offset);result.source.require_arena((len(result.buffer)+amount)*32+32768)
        if amount:
            with legacy_cell_read_transaction_v2(result.graph.pair.source):
                raw,total,kind=read_legacy_sql_cell_fragment_v2(result.graph.pair.source,table=result.table,
                    column=result.column,where=result.where,parameters=result.row_key,
                    start=result.left+result.offset,length=amount,meter=meter)
            if kind!='text' or total!=result.total or len(raw)!=amount:
                raise C09PagedCaptureHold('historical array lost its complete original range')
            result.buffer.extend(raw);result.parser.feed(raw,result._event);result.parser._emit_callback=None;result.offset+=amount
            for ordinal,left,right in result.completed:
                if ordinal!=result.index:raise C09PagedCaptureHold('historical array element inventory/order differs')
                result.queue.append(json.loads(result.buffer[left-result.base:right-result.base]));result.index+=1
            result.completed=[];keep=min(result.starts.values()) if result.starts else result.offset
            del result.buffer[:keep-result.base];result.base=keep
        if result.offset==result.right-result.left:
            if result.parser.finish().byte_count!=result.offset or result.starts:raise C09PagedCaptureHold('historical array canonical EOF differs')
            result.complete=True
        result.source.require_arena();return result
    def pop(self):return self.queue.pop(0)

class _HistoricalGraphRowReadV4(_D13PaidRowStreamV3):
    """Full actual Source/target bytes against the existing sealed member roots."""
    def __init__(self,owner,table,key,*,decode=(),typed_hash=None,source_metadata=False):
        self.capture=owner.capture;self.graph=owner.graph;self.source=owner.source
        self.table=table;self.row_key=key;self.decode_names=tuple(decode);self.typed_hash=None if typed_hash is None else typed_hash.copy()
        self.source_metadata=source_metadata;self.semantic=None;self.complete=False;self.phase='source'
        self.shape=None;self.small=None;self.disposition=None;self.target_small=None
        self.json_columns=({'graph_history':('value','dependencies'),'graph_events':('reads','epoch_reads','revisions','invalidated'),
            'graph_first_ingress_identity_v1':('identity_json',),'graph_first_ingress_intents_v2':('identity_json',),'graph_bundle_operations':('receipt_json',),'runtime_budget_grants':('grant_json',),'runtime_resource_quotes':('quote_json',),'runtime_budget_operations':('receipt_json','resolution_binding_json')}).get(table,())
        self.row_where=None;self.source_hash=sha256();self.target_hash=sha256();self.column=0;self.offset=0;self.total=None
        self.parser=None;self.buffer=bytearray();self.values={};self.json_source_bytes={};self.source.arena.add(self)
    def owned_values(self):return (self.semantic,self.typed_hash)
    def copy(self):
        result=super().copy();result.typed_hash=None if self.typed_hash is None else self.typed_hash.copy()
        result.semantic=None if self.semantic is None else self.semantic.copy();return result
    def _source_heap_bytes(self):return super()._source_heap_bytes()+(0 if self.semantic is None else self.semantic._source_heap_bytes())+(self.parser._source_heap_bytes() if self.source_metadata and self.parser is not None and self.shape.columns[self.column]=='value' else 0)
    def _new_source_parser(self,name):
        if self.source_metadata and name=='value':
            from ..runtime.c09_graph_row_codec_v2 import C09MemorySourceJSONStreamV3
            return C09MemorySourceJSONStreamV3(ensure_ascii=True,source_arena=self.source.arena)
        return C09CanonicalJSONStreamV2(ensure_ascii=True)
    def _feed_source_json(self,raw):
        super()._feed_source_json(raw)
        if self.table=='graph_history' and self.shape.columns[self.column]=='value' and self.typed_hash is not None:self.typed_hash.update(raw)
    def _source_json_complete(self,name,parser,eof):
        if self.source_metadata and name=='value':self.semantic=parser
    def advance(self,meter):
        from .c09_paged_recovery_facts_v2 import _C09ReadonlyPointMeterV3
        self.source.require_current();self.graph.require_current();result=self.copy()
        if result.phase=='source':
            with legacy_cell_read_transaction_v2(result.graph.pair.source):
                result.shape=read_c09_table_shape_v2(result.graph.pair.source,result.table,meter=meter)
                if result.table=='graph_history' and (result.shape.columns!=_HISTORY or result.shape.primary_key_columns!=('token','revision')):
                    raise C09PagedCaptureHold('historical Source history schema/key differs')
                if result.table=='graph_events' and (result.shape.columns!=_EVENTS or result.shape.primary_key_columns!=('bot','persona','session','event_id')):
                    raise C09PagedCaptureHold('historical Source event schema/key differs')
                result.row_where=' AND '.join(name+'=?' for name in result.shape.primary_key_columns)
                if result.table=='runtime_budget_operations':
                    nullable=meter.read_fixed_row(result.graph.pair.source,result.table,('resolution_binding_json',),result.row_where,result.row_key)
                    if nullable==(None,):
                        result.json_columns=('receipt_json',);result.decode_names=tuple(n for n in result.decode_names if n!='resolution_binding_json');result.values['resolution_binding_json']=None
                names=tuple(name for name in result.shape.columns if name not in result.json_columns)
                row=meter.read_fixed_row(result.graph.pair.source,result.table,names,result.row_where,result.row_key)
                if row is None:raise C09PagedCaptureHold('actual historical original row absent')
                result.small=dict(zip(names,row,strict=True));result.disposition=result.capture.builder.basis._graph_disposition_original_v3(
                    result.graph,result.shape,result.row_key,_C09ReadonlyPointMeterV3(meter))
            result.phase='source_row'
        elif result.phase=='source_row':result._row_advance(False,meter)
        elif result.phase=='target':
            with legacy_cell_read_transaction_v2(result.graph._read_db):
                shape=read_c09_table_shape_v2(result.graph._read_db,result.table,meter=meter)
                if shape!=result.shape:raise C09PagedCaptureHold('historical Source/target logical schema differs')
                names=tuple(name for name in shape.columns if name not in result.json_columns)
                row=meter.read_fixed_row(result.graph._read_db,result.table,names,result.row_where,result.row_key)
            if result.disposition.disposition=='derived_removed':
                if row is not None:raise C09PagedCaptureHold('removed historical row remains in candidate')
                result.phase='fields'
            else:
                if row is None:raise C09PagedCaptureHold('retained historical row absent in candidate')
                result.target_small=dict(zip(names,row,strict=True));result.phase='target_row'
        elif result.phase=='target_row':result._row_advance(True,meter)
        elif result.phase=='fields':result._read_fields(meter)
        elif result.phase=='identity':result.complete=True
        else:raise C09PagedCaptureHold('unknown historical row phase')
        self.source.require_arena();return result

class NaturalFinalHistoricalPermissionsReadV4:
    """Complete E+1 historical directory and pure business authorization checks."""
    def __init__(self,parent):
        from .c09_authority_storage_rebase_v2 import _D13OutboundAdoptionReadV3
        if (type(parent) is not _D13OutboundAdoptionReadV3 or parent.phase!='natural_final_historical_permissions'
                or parent.natural_final_authority_original is None or not parent.natural_final_authority_original.complete):
            raise C09PagedCaptureHold('historical permissions require actual Graph/Core/Owner original closure')
        self.parent=parent;self.capture=parent.capture;self.graph=parent.graph;self.source=parent.natural_reference_facts.source
        self.payload=parent.natural_final_original.payload_values;self.scope=parent.natural_final_authority_original.scope
        self.epoch=self.payload['query']['revision'];self.phase='version';self.complete=False
        self.business_operation_id=parent.handoff.observation.binding.origin.operation_id;self.required_core_rows=();self.source_qualified_complete=False
        self.last_key=None;self.current_token=None;self.last_revision=0;self.last_epoch=-1;self.selected=None
        self.pending=None;self.row=None;self.event=None;self.eof=False;self.snapshot_hash=sha256();self.snapshot_count=0;self.versions=None;self.admission_reads=None
        self.atoms={};self.sources={};self.source_versions={};self.history_count=0;self.route_rows={};self.route_index=0;self.checks=[]
        self.semantic_phase=0;self.core_reader=None;self.budget=None;self.present_tokens=set();self.now=None
        refs=parent.natural_reference_facts.parser.references
        self.qualification_pins=tuple(sorted({(v.ref,v.version) for path,v in refs.items() if path[:3]==('input','plan','units')
            and (len(path)==6 and path[4] in {'source_refs','access_refs','correction_refs'} or len(path)==5 and path[4]=='qualification_ref')}))
        self.qualification_tokens={v[0] for v in self.qualification_pins};self.qualification_headers={};self.qualification_pin_index=0
        self.d11_issuer=parent.natural_installed_authority.model.d11_issuer;self.d02_issuer=self.d11_issuer.resource_issuer
        self.source.arena.add(self);self.source.require_arena()
    def _source_heap_bytes(self):
        excluded={'parent','capture','graph','source','payload','scope','d11_issuer','d02_issuer','versions','row','event','core_reader','budget','scan_cursor','projection_cursor','admission_reads','check_cursor','execution_pair'}
        context=0 if 'context' not in self.__dict__ else _heap(self.context.__dict__)
        return sys.getsizeof(self.__dict__)+sum(_heap(value) for name,value in self.__dict__.items() if name not in excluded)+context+16384
    def copy(self):
        self.source.require_arena(self._source_heap_bytes());result=copy(self);result.snapshot_hash=self.snapshot_hash.copy()
        result.atoms=dict(self.atoms);result.sources=dict(self.sources);result.source_versions=dict(self.source_versions)
        result.route_rows=dict(self.route_rows);result.checks=list(self.checks);result.versions=None if self.versions is None else self.versions.copy();result.present_tokens=set(self.present_tokens)
        for name,value in self.__dict__.items():
            if type(value) in (dict,list,set,bytearray):setattr(result,name,copy(value))
        for name in ('route_scan_hash','projection_hash','execution_blob_hash','checks_hash'):
            if name in self.__dict__ and getattr(self,name) is not None:setattr(result,name,getattr(self,name).copy())
        for name in ('scan_cursor','projection_cursor','admission_reads','check_cursor'):
            if name in self.__dict__ and getattr(self,name) is not None:setattr(result,name,getattr(self,name).copy())
        self.source.arena.add(result);return result
    def _scan(self,meter):
        names=('token','revision','valid','event_bot','event_persona','event_session','event_id')
        with legacy_cell_read_transaction_v2(self.graph.pair.source):
            row=meter.read_fixed_row(self.graph.pair.source,'graph_history',names,'1 ORDER BY token,revision',()) if self.last_key is None else meter.read_fixed_row(
                self.graph.pair.source,'graph_history',names,'(token,revision)>(?,?) ORDER BY token,revision',self.last_key)
        if row is None:self.eof=True;self.phase='selected' if self.selected is not None else 'snapshot_eof';return
        self.pending=row
        self.phase='selected' if self.current_token is not None and row[0]!=self.current_token and self.selected is not None else 'history_row'
    def _history_begin(self,meter):
        from ..graph_types import AtomKey
        row=self.pending;key=AtomKey.from_token(row[0]);meter.charge_encode(len(row[0]))
        if (key.owner.bot,key.owner.persona)!=row[3:5] or type(row[1]) is not int or row[2] not in (0,1):raise C09PagedCaptureHold('historical key/event namespace or revision differs')
        if row[0]!=self.current_token:self.current_token=row[0];self.last_revision=0;self.last_epoch=-1;self.selected=None
        if row[1]!=self.last_revision+1:raise C09PagedCaptureHold('complete Source history has a revision gap')
        self.row=_HistoricalGraphRowReadV4(self,'graph_history',row[:2]);self.phase='history_bytes'
    def _history_event(self,meter):
        if self.event is None:self.event=_HistoricalGraphRowReadV4(self,'graph_events',self.pending[3:])
        elif not self.event.complete:self.event=self.event.advance(meter)
        else:
            epoch=self.event.small['epoch_revision'];row=self.pending
            if type(epoch) is not int or epoch<=self.last_epoch:raise C09PagedCaptureHold('history revisions have incoherent actual event epochs')
            self.last_epoch=epoch;self.last_revision=row[1];self.last_key=row[:2];self.history_count+=1
            if row[3:5]==self.parent.namespace.as_tuple and epoch<=self.epoch:self.selected=row
            self.pending=None;self.row=None;self.event=None;self.phase='scan'
    def _selected(self,meter):
        from ..graph_types import AtomKey,GraphAtom
        if not self.versions.queue and not self.versions.complete:self.versions=self.versions.advance(meter);return
        if not self.versions.queue:raise C09PagedCaptureHold('complete E+1 namespace omitted from snapshot_versions')
        if not self.admission_reads.queue and not self.admission_reads.complete:self.admission_reads=self.admission_reads.advance(meter);return
        if not self.admission_reads.queue:raise C09PagedCaptureHold('actual admission graph_reads omits complete E+1 member')
        row=self.selected;version=self.versions.pop();admission=self.admission_reads.pop()
        if (type(version) is not list or len(version)!=3 or type(version[1]) is not int or type(version[2]) is not bool
                or type(admission) is not list or len(admission)!=2 or type(admission[1]) is not int
                or admission!=list(row[:2]) or version!=[row[0],row[1],bool(row[2])]):raise C09PagedCaptureHold('snapshot_versions differs from E+1 history including invalid rows')
        key=AtomKey.from_token(row[0]);meter.charge_encode(len(row[0]))
        raw=_encode(self.source,{'$type':GraphAtom.__module__+'.'+GraphAtom.__qualname__,'key':key,'revision':row[1],'valid':bool(row[2])},meter)
        self.snapshot_hash.update((b',' if self.snapshot_count else b'')+raw[:-1]+b',"value":')
        self.row=_HistoricalGraphRowReadV4(self,'graph_history',row[:2],decode=('value',) if key.type_name in _RETAIN_TYPES or 'criteria' in key.type_name else (),
            typed_hash=self.snapshot_hash,source_metadata=key.type_name=='memory.source');self.phase='selected_bytes'
    def _selected_finish(self,meter):
        from ..graph_types import AtomKey,GraphAtom
        row=self.selected;key=AtomKey.from_token(row[0]);meter.charge_encode(len(row[0]))
        self.snapshot_hash=self.row.typed_hash.copy();self.snapshot_hash.update(b'}');meter.charge_encode(1);self.snapshot_count+=1
        if key.type_name=='d06.source_correction_head.v1':self.present_tokens.add(key.token)
        if key.token in self.qualification_tokens:self.qualification_headers[key.token]=(row[1],bool(row[2]))
        if self.row.semantic is not None:self.sources[row[0]]=dict(self.row.semantic._source_metadata);self.source_versions[row[0]]=(row[1],bool(row[2]))
        elif 'value' in self.row.values:
            bound=c09_canonical_json_size_v3(self.row.values['value']);meter.require_available(bound*2);self.source.require_arena(bound*32+32768)
            with meter_canonical_outputs(meter):self.atoms[row[0]]=GraphAtom(key,row[1],self.row.values['value'],bool(row[2]))
            meter.charge_encode(c09_canonical_json_size_v3(self.row.values['value'],exact=True))
        self.selected=None;self.row=None;self.phase='snapshot_eof' if self.eof else 'history_row' if self.pending is not None else 'scan'
    def _snapshot_eof(self,meter):
        from ..graph_types import NamespaceEpoch
        if not self.versions.queue and not self.versions.complete:self.versions=self.versions.advance(meter);return
        if self.versions.queue or not self.versions.complete:raise C09PagedCaptureHold('snapshot_versions has extra members or incomplete EOF')
        if not self.admission_reads.queue and not self.admission_reads.complete:self.admission_reads=self.admission_reads.advance(meter);return
        if self.admission_reads.queue or not self.admission_reads.complete:raise C09PagedCaptureHold('actual admission graph_reads has extras or incomplete EOF')
        suffix=b'],"epochs":'+_encode(self.source,(NamespaceEpoch(*self.parent.namespace.as_tuple,self.epoch),),meter)+b',"ingress_receipts":[],"scene_proofs":[]}'
        meter.charge_encode(len(suffix));self.snapshot_hash.update(suffix)
        if (self.snapshot_hash.hexdigest()!=self.payload['snapshot_commitment'] or self.scope.graph_epoch.revision+1!=self.epoch
                or self.payload['snapshot_epochs']!=[{'bot':self.parent.namespace.bot_id,'persona':self.parent.namespace.persona_id,'revision':self.epoch}]):
            raise C09PagedCaptureHold('complete typed historical GraphSnapshot commitment differs')
        self.phase='barrier'
    def advance(self,meter):
        self.source.require_current();self.capture.builder.require_current();self.graph.require_current();result=self.copy()
        if result.phase=='version':
            if result.payload['schema']!='sylanne.natural_final_authorization_original.v4':raise C09PagedCaptureHold('actual final v4 originals required; legacy cannot be backfilled')
            result.versions=NaturalFinalPayloadArrayCursorV4(result,('natural_final_authorization_original','payload','snapshot_versions'))
            result.admission_reads=NaturalFinalPayloadArrayCursorV4(result,('graph_reads',),column='admission_json')
            from ..graph_types import GraphSnapshot
            raw=_encode(result.source,{'$type':GraphSnapshot.__module__+'.'+GraphSnapshot.__qualname__,'atoms':[]},meter)[:-2]
            result.snapshot_hash.update(raw);result.phase='clock'
        elif result.phase=='scan':result._scan(meter)
        elif result.phase=='history_row':result._history_begin(meter)
        elif result.phase=='history_bytes':
            if not result.row.complete:result.row=self.row.advance(meter)
            else:result.phase='history_event'
        elif result.phase=='history_event':result._history_event(meter)
        elif result.phase=='selected':result._selected(meter)
        elif result.phase=='selected_bytes':
            if not result.row.complete:result.row=self.row.advance(meter)
            else:result._selected_finish(meter)
        elif result.phase=='snapshot_eof':result._snapshot_eof(meter)
        else:result._semantics(meter)
        self.source.require_current();self.source.require_arena();return result
    def _atom(self,token,kind=None):
        atom=self.atoms.get(token)
        if atom is None or not atom.valid or atom.revision<1 or kind is not None and atom.key.type_name!=kind:
            raise C09PagedCaptureHold('actual E+1 typed authorization member absent or invalid')
        return atom
    def _digest(self,value,meter):return sha256(_encode(self.source,value,meter)).hexdigest()
    def _barrier(self,meter):
        original=self.parent.natural_final_original;admission=original.admission_values['admission_json'];barrier=self.payload['graph_barrier']
        expected={'graph_incarnation','access_epoch','delete_epoch','graph_revision','graph_epoch'}
        proof=self.parent.natural_final_authority_original.proof
        if (type(barrier) is not dict or set(barrier)!=expected or barrier['graph_incarnation']!=proof.graph_incarnation
                or any(type(barrier[n]) is not int or barrier[n]<0 for n in ('access_epoch','delete_epoch','graph_revision','graph_epoch'))
                or barrier['graph_epoch']!=self.epoch or barrier['graph_revision']!=self.scope.graph_revision
                or barrier['access_epoch']!=admission['access_epoch'] or barrier['delete_epoch']!=admission['delete_epoch']
                or barrier['graph_incarnation']!=admission['graph_incarnation'] or proof.graph_access_epoch>barrier['access_epoch']):
            raise C09PagedCaptureHold('actual historical graph access/deletion barrier differs')
        self.phase='owner'
    def _owner(self,meter):
        from ..graph_types import owner_grant_key,validate_owner_grant_v1
        from .v2_owner_contract import canonical_digest as owner_digest
        original=self.parent.natural_final_authority_original;proof=original.proof;guard=original.guard
        atom=self._atom(owner_grant_key(*self.parent.namespace.as_tuple).token,'d11.owner_grant.v1');grant=atom.value
        validate_owner_grant_v1(grant);anchor=self.scope.pinned_anchor;route=self.payload['route']
        if (atom.revision!=1 or grant['grant_revision']!=1 or 'sha256:'+self._digest(grant,meter)!=proof.grant_digest
                or grant['grant_id']!=proof.grant_id or grant['issue_operation_id']!=proof.operation_id
                or grant['graph_incarnation']!=proof.graph_incarnation or grant['authority_id']!=anchor.authority_id
                or grant['authority_id']!=guard.authority_id or grant['installation_id']!=guard.installation_id
                or 'expression' not in grant['purposes'] or route['conversation_ref'] not in grant['audiences']
                or proof.graph_epoch>self.scope.graph_epoch.revision or guard.authorization_revision!=grant['grant_revision']
                or guard.minimum_revocation_revision!=0 or guard.minimum_revocation_epoch!=0
                or guard.pending_revoke_operation_id is not None or anchor.revocation_epoch!=0):
            raise C09PagedCaptureHold('actual historical Owner grant policy/value differs from committed original')
        upper=c09_canonical_json_size_v3(proof,typed=True);meter.require_available(upper*2)
        with meter_canonical_outputs(meter):head=owner_digest(proof)
        if guard.authorization_head!=head:raise C09PagedCaptureHold('historical Owner issue proof head differs')
        self.phase='route_rows'
    def _route_originals(self,meter):
        from ..runtime.first_ingress_v2 import ingress_ids
        from ..runtime.reply_model_job import source_key_from_ref
        route=self.payload['route'];ns=self.parent.namespace;source=source_key_from_ref(route['source_ref'],ns)
        ingress=ingress_ids(source)[2]
        arrival='d03-arrival-'+self._digest({'namespace':list(ns.as_tuple),'source_ref':source},meter)[:40]
        specs=(('identity','graph_first_ingress_identity_v1',(*ns.as_tuple,ingress),('identity_json',)),
            ('observed','ingress_first_observations',(*ns.as_tuple,ingress),()),
            ('intent','graph_first_ingress_intents_v2',(*ns.as_tuple,ingress),('identity_json',)),
            ('ingress_bundle','graph_bundle_operations',(*ns.as_tuple,ingress),()),
            ('c02','graph_first_ingress_c02_committed_seals_v2',(*ns.as_tuple,route['c02_operation_id']),()),
            ('c02_bundle','graph_bundle_operations',(*ns.as_tuple,route['c02_operation_id']),()),
            ('arrival','graph_d03_arrival_issuance_v2',(*ns.as_tuple,arrival),()),
            ('arrival_bundle','graph_bundle_operations',(*ns.as_tuple,arrival),()))
        if self.route_index==len(specs):self.phase='route_identity';return
        name,table,key,decode=specs[self.route_index]
        if self.row is None:self.row=_HistoricalGraphRowReadV4(self,table,key,decode=decode)
        elif not self.row.complete:self.row=self.row.advance(meter)
        else:
            self.route_rows[name]=(dict(self.row.small),dict(self.row.values));self.row=None;self.route_index+=1
    def _route_identity(self,meter):
        from ..runtime.first_ingress_v2 import scene_ref_for_conversation,ingress_ids
        from ..runtime.reply_model_job import source_key_from_ref
        from ..graph_types import AtomKey,Owner
        from ..memory_types import source_key,access_key,validate_access
        from ..domains.d03.context import EntityAnchor,AccountBinding,WorldEvent
        ns=self.parent.namespace;route=self.payload['route'];source_id=source_key_from_ref(route['source_ref'],ns)
        small,values=self.route_rows['identity'];identity=values['identity_json'];observed=self.route_rows['observed'][0]
        intent=self.route_rows['intent'][1]['identity_json'];ingress_digest=self.route_rows['ingress_bundle'][0]['digest']
        if (set(identity)!={'schema','namespace','operation_id','source_ref','platform_ref','conversation_ref','sender_ref','message_id','visibility','lineage'}
                or identity['schema']!='sylanne3.ingress.identity.v1' or identity['namespace']!=list(ns.as_tuple)
                or identity['operation_id']!=ingress_ids(source_id)[2] or identity['source_ref']!=source_id
                or identity['visibility']!='private' or identity['platform_ref']!=route['platform_ref']
                or identity['sender_ref']!=route['sender_ref'] or identity['conversation_ref']!=route['conversation_ref']
                or tuple(identity[n] for n in ('source_ref','platform_ref','conversation_ref','sender_ref','message_id','visibility'))
                   !=tuple(small[n] for n in ('source_ref','platform_ref','conversation_ref','sender_ref','message_id','visibility'))
                or any(observed[n]!=small[n] for n in ('content_fingerprint','learned_at','bundle_digest'))
                or ingress_digest!=small['bundle_digest'] or intent['fingerprint']!=small['content_fingerprint']
                or self.route_rows['c02'][0]['bundle_digest']!=self.route_rows['c02_bundle'][0]['digest']
                or self.route_rows['arrival'][0]['source_ref']!=source_id
                or self.route_rows['arrival'][0]['bundle_digest']!=self.route_rows['arrival_bundle'][0]['digest']):
            raise C09PagedCaptureHold('actual original ingress/C02/D03 route seals or identity differ')
        with meter_canonical_outputs(meter):scene=scene_ref_for_conversation(ns,route['platform_ref'],route['conversation_ref'])
        suffix=self._digest({'namespace':ns.as_tuple,'platform_ref':route['platform_ref'],'sender_ref':route['sender_ref']},meter)
        entity='entity:account-v1:'+suffix;account='account:v1:'+suffix
        if (route['namespace']!={'bot_id':ns.bot_id,'persona_id':ns.persona_id} or route['scene_ref']!=scene
                or route['target_entity_ref']!=entity or route['account_id']!=account or route['query']!=self.payload['query']):
            raise C09PagedCaptureHold('historical route scope or deterministic account identity differs')
        source_token=source_key(*ns.as_tuple,source_id).token;access=self._atom(access_key(*ns.as_tuple,source_id).token,'memory.access')
        source=self.sources.get(source_token);validate_access(access.value)
        if (source is None or self.source_versions[source_token][1] is not True or source['source_id']!=source_id
                or source['speaker_id']!=route['sender_ref'] or source['source_kind']!='reported'
                or source['assertion_status']!='reported' or tuple(source['audiences'])!=(route['conversation_ref'],)
                or access.value['source_id']!=source_id or access.value['status']!='active'
                or route['conversation_ref'] not in access.value['audiences'] or 'expression' not in access.value['purposes']):
            raise C09PagedCaptureHold('actual E+1 reply Source or Access differs')
        anchor_atom=self._atom(AtomKey(Owner('persona',*ns.as_tuple),'d03.entity_anchor',entity).token)
        binding_atom=self._atom(AtomKey(Owner('persona',*ns.as_tuple),'d03.account_binding',account).token)
        anchor=EntityAnchor(**{**anchor_atom.value,'creation_evidence_refs':tuple(anchor_atom.value['creation_evidence_refs'])})
        binding=AccountBinding(**binding_atom.value);now=self.now
        if (anchor.entity_id!=entity or anchor.kind!='account' or anchor.owner_scope!='persona:'+ns.persona_id or anchor.status!='active'
                or binding.account_id!=account or binding.platform_namespace!=route['platform_ref'] or binding.platform_identifier!=route['sender_ref']
                or binding.entity_id!=entity or binding.valid_from>now or binding.valid_until is not None and now>=binding.valid_until):
            raise C09PagedCaptureHold('actual historical entity anchor/account binding differs')
        event_id='world:message-arrival-v1:'+self._digest({'namespace':ns.as_tuple,'platform_ref':route['platform_ref'],
            'conversation_ref':route['conversation_ref'],'message_id':identity['message_id'],'source_id':source_id},meter)
        arrival_atom=self._atom(AtomKey(Owner('event',*ns.as_tuple,event_id),'d03.world_event','current').token)
        def world(atom):return WorldEvent(**{**atom.value,'participant_roles':tuple(tuple(role) for role in atom.value['participant_roles']),
            'source_refs':tuple(atom.value['source_refs'])})
        arrival=world(arrival_atom);evidence_key=AtomKey.from_token(binding.verification_ref)
        if evidence_key.type_name!='d03.world_event' or evidence_key.owner.kind!='event' or (evidence_key.owner.bot,evidence_key.owner.persona)!=ns.as_tuple:
            raise C09PagedCaptureHold('historical binding verification crossed namespace/family')
        evidence_atom=self._atom(evidence_key.token);evidence=world(evidence_atom)
        if (arrival.event_id!=event_id or arrival.kind!='message_received' or arrival.reality!='host_observed' or arrival.scene_ref!=scene
                or arrival.participant_roles!=((entity,'sender_account'),) or arrival.source_refs!=(route['source_ref'],)
                or arrival.learned_at!=source['recorded_at'] or evidence.kind!='message_received' or evidence.reality!='host_observed'
                or evidence.participant_roles!=((entity,'sender_account'),) or evidence.learned_at!=binding.valid_from):
            raise C09PagedCaptureHold('actual historical arrival/evidence event differs')
        selected=(anchor_atom,binding_atom,arrival_atom,evidence_atom)
        names=('anchor_version','binding_version','arrival_event_version','binding_evidence_event_version')
        for name,atom in zip(names,selected,strict=True):
            value=route[name]
            if (value['revision']!=atom.revision or AtomKey.from_token(atom.key.token)!=atom.key
                    or value['key']!={'owner':{'kind':atom.key.owner.kind,'bot':atom.key.owner.bot,'persona':atom.key.owner.persona,'subject':atom.key.owner.subject},
                        'type_name':atom.key.type_name,'name':atom.key.name}):raise C09PagedCaptureHold('historical route positive read differs')
        for name,token,revision in (('source_version',source_token,self.source_versions[source_token][0]),('access_version',access.key.token,access.revision)):
            raw=route[name];key=AtomKey.from_token(token)
            if raw['revision']!=revision or raw['key']!={'owner':{'kind':key.owner.kind,'bot':key.owner.bot,'persona':key.owner.persona,'subject':key.owner.subject},
                    'type_name':key.type_name,'name':key.name}:raise C09PagedCaptureHold('historical route Source/Access read differs')
        if route['valid_until_utc']!=binding.valid_until:raise C09PagedCaptureHold('historical route lifetime differs')
        self.route_identity=identity;self.route_binding=binding;self.route_selected=selected
        from ..graph_types import GraphVersion
        semantic={'schema':'sylanne.d08.natural-route-semantic.v2','namespace':ns,
            **{name:route[name] for name in ('c02_operation_id','source_ref','platform_ref','sender_ref','conversation_ref','scene_ref','target_entity_ref','account_id','valid_until_utc')},
            **dict(zip(names,(GraphVersion(a.key,a.revision) for a in selected),strict=True)),
            'source_version':GraphVersion(AtomKey.from_token(source_token),self.source_versions[source_token][0]),
            'access_version':GraphVersion(access.key,access.revision)}
        self.route_semantic_digest=self._digest(semantic,meter)
        self.account_tokens=tuple(sorted(token for token,atom in self.atoms.items() if atom.valid and atom.key.type_name=='d03.account_binding'))
        self.account_index=0;self.account_matches=[]
        self.scan_cursor=NaturalFinalPayloadArrayCursorV4(self,('natural_final_authorization_original','payload','route','binding_scan_versions'))
        self.route_scan_hash=sha256()
        proof={'schema':'sylanne3.current-reply-entity-route-binding.v2','namespace':list(ns.as_tuple),'c02_operation_id':route['c02_operation_id'],
            'source_ref':route['source_ref'],'platform_ref':route['platform_ref'],'sender_ref':route['sender_ref'],'conversation_ref':route['conversation_ref'],
            'scene_ref':scene,'target_entity_ref':entity,'account_id':account,'versions':[(a.key.token,a.revision) for a in selected]+[(source_token,self.source_versions[source_token][0]),(access.key.token,access.revision)],
            'binding_scan_versions':None,'query':(ns.as_tuple,'all',self.epoch),'valid_until_utc':binding.valid_until,
            'route_digest':self._digest({'account_ref':route['platform_ref'],'destination_ref':route['conversation_ref'],'scene_ref':scene},meter),
            'ingress_identity_digest':self._digest(identity,meter),'arrival_operation_digest':self.route_rows['arrival_bundle'][0]['digest']}
        head,tail=_encode(self.source,proof,meter).split(b'"binding_scan_versions":null',1)
        self.route_scan_hash.update(head+b'"binding_scan_versions":[');self.route_scan_suffix=b']'+tail;self.phase='route_scan'
    def _route_scan(self,meter):
        from ..domains.d03.context import AccountBinding
        from ..graph_types import GraphVersion
        if not self.scan_cursor.queue and not self.scan_cursor.complete:self.scan_cursor=self.scan_cursor.advance(meter);return
        if self.account_index==len(self.account_tokens):
            if self.scan_cursor.queue or not self.scan_cursor.complete:raise C09PagedCaptureHold('historical account inventory has extra rows or lacks EOF')
            if self.account_matches!=[self.route_selected[1].key.token]:raise C09PagedCaptureHold('historical reply account binding is ambiguous')
            self.route_scan_hash.update(self.route_scan_suffix)
            if self.route_scan_hash.hexdigest()!=self.payload['route']['binding_digest']:raise C09PagedCaptureHold('actual complete historical account route digest differs')
            self.phase='projection_begin';return
        if not self.scan_cursor.queue:raise C09PagedCaptureHold('historical route omits valid account inventory')
        atom=self._atom(self.account_tokens[self.account_index]);binding=AccountBinding(**atom.value)
        raw=self.scan_cursor.pop();version=GraphVersion(atom.key,atom.revision)
        from dataclasses import asdict
        if raw!=asdict(version):raise C09PagedCaptureHold('historical account inventory complete version differs')
        if (binding.platform_namespace==self.payload['route']['platform_ref'] and binding.platform_identifier==self.payload['route']['sender_ref']
                and binding.valid_from<=self.now and (binding.valid_until is None or self.now<binding.valid_until)):
            self.account_matches.append(atom.key.token)
        self.route_scan_hash.update((b',' if self.account_index else b'')+_encode(self.source,(atom.key.token,atom.revision),meter));self.account_index+=1
    def _action_begin(self,meter):
        from ..domains.d08.execution import GoalExecutionProvider,ActionSchema
        self.d08_types={spec.name:spec for spec in GoalExecutionProvider().register_types()}
        matches=[atom for atom in self.atoms.values() if atom.valid and atom.key.type_name=='d08.action_intent.v1'
            and atom.value['identity']['operation_id']==self.business_operation_id]
        if len(matches)!=1:raise C09PagedCaptureHold('historical final action identity is not unique')
        atom=matches[0];self.action_atom_revision=atom.revision
        with meter_canonical_outputs(meter):self.action=self.d08_types[atom.key.type_name].validator(atom.value)
        schemas=[a for a in self.atoms.values() if a.valid and a.key.type_name=='d08.action_schema.v1' and a.value['action_ref']==self.action.action_id]
        if len(schemas)!=1:raise C09PagedCaptureHold('historical final action schema is not unique')
        self.schema_atom_revision=schemas[0].revision
        with meter_canonical_outputs(meter):self.schema_record=self.d08_types['d08.action_schema.v1'].validator(schemas[0].value)
        self.schema=ActionSchema(self.schema_record.schema_id,self.schema_record.action_kind,self.schema_record.proactive,self.schema_record.required_checks)
        if (self.action.action_kind!='communication' or self.action.purpose!='expression' or self.schema.proactive
                or self.action.identity.effect_id!=self.payload['identity']['effect_id'] or self.action.target_ref!=self.payload['route']['target_entity_ref']
                or self.action.required_checks!=self.schema.required_checks):raise C09PagedCaptureHold('historical final action scope differs')
        self.expected_checks=self.parent.natural_final_original.admission_values['admission_json']['check_receipts']
        if (len(self.expected_checks)!=5 or len({check['valid_until'] for check in self.expected_checks[:4]})!=1
                or self.expected_checks[4]['valid_until']<self.expected_checks[0]['valid_until']):
            raise C09PagedCaptureHold('historical final five check lifetime/inventory differs')
        self.expiry=self.expected_checks[0]['valid_until']
        if not self.now<self.expiry:raise C09PagedCaptureHold('historical final checks were expired')
        self.roles=tuple(self.atoms[t] for t in sorted(self.atoms) if self.atoms[t].valid and self.atoms[t].key.type_name=='d03.role_binding')
        self.boundaries=tuple(self.atoms[t] for t in sorted(self.atoms) if self.atoms[t].valid and self.atoms[t].key.type_name=='d05.boundary_rule')
        self.projection_hash=sha256();self.projection_group='boundary_rules';self.projection_index=0
        self.projection_cursor=NaturalFinalPayloadArrayCursorV4(self,('natural_final_authorization_original','payload','projection','boundary_rules'))
        raw=b'{"boundary_rules":[';meter.charge_encode(len(raw));self.projection_hash.update(raw);self.phase='projection_members'
    def _projection_member(self,meter):
        group=self.boundaries if self.projection_group=='boundary_rules' else self.roles
        if not self.projection_cursor.queue and not self.projection_cursor.complete:self.projection_cursor=self.projection_cursor.advance(meter);return
        if self.projection_index==len(group):
            if self.projection_cursor.queue or not self.projection_cursor.complete:raise C09PagedCaptureHold('historical projection has extra inventory or incomplete EOF')
            if self.projection_group=='boundary_rules':
                raw=b'],"graph_epoch":'+_encode(self.source,self.epoch,meter)+b',"namespace":'+_encode(self.source,self.parent.namespace,meter)+b',"role_bindings":['
                meter.charge_encode(len(raw));self.projection_hash.update(raw);self.projection_group='role_bindings';self.projection_index=0
                self.projection_cursor=NaturalFinalPayloadArrayCursorV4(self,('natural_final_authorization_original','payload','projection','role_bindings'));return
            self.projection_hash.update(b']}');meter.charge_encode(2);projection=self.payload['projection']
            if (projection['digest']!=self.projection_hash.hexdigest() or projection['coverage']!='full' or projection['missing_sources']!=[]
                    or projection['graph_epoch']!=self.epoch or projection['namespace']!=self.payload['namespace']):
                raise C09PagedCaptureHold('actual full historical D03/D05 projection differs')
            self.phase='social';return
        atom=group[self.projection_index]
        if self.projection_cursor.pop()!=[atom.key.token,atom.revision]:raise C09PagedCaptureHold('historical projection omits or changes domain inventory')
        self.projection_hash.update((b',' if self.projection_index else b'')+_encode(self.source,atom,meter));self.projection_index+=1
    def _social(self,meter):
        from ..domains.d03.context import ContextProvider,RoleBinding,RoleBindingRequest,RoleBindingResolution
        from ..domains.d05.relationship import BoundaryRule,BoundaryRuleReadSet,RelationshipProvider
        from ..domains.d05.prebatch_boundary import issue_prebatch_boundary_check_v1
        from ..graph_types import AtomKey,GraphVersion
        from ..runtime_contracts import QueryEpoch,VersionedRef
        ns=self.parent.namespace;context=ContextProvider();catalogue=self.payload['context_catalogue']
        if set(catalogue)!={'roles','norms'} or any(type(catalogue[n]) is not list or catalogue[n]!=sorted(set(catalogue[n])) for n in catalogue):
            raise C09PagedCaptureHold('actual final D03 catalogue original differs')
        context._roles=frozenset(catalogue['roles']);context._norms=frozenset(catalogue['norms'])
        request=RoleBindingRequest('persona:'+ns.persona_id,self.action.target_ref,None,self.payload['route']['scene_ref'],self.action.action_kind,self.action.purpose,self.now,True)
        role_spec=next(spec for spec in context.type_specs() if spec.name=='d03.role_binding')
        boundary_spec=next(spec for spec in RelationshipProvider().type_specs() if spec.name=='d05.boundary_rule')
        self.context=context;self.role_request=request;self.role_spec=role_spec;self.boundary_spec=boundary_spec
        self.social_index=0;self.bindings=[];self.rules=[];self.structural=set();self.social_ids=set();self.phase='social_rows';return
    def _social_row(self,meter):
        from ..domains.d03.context import RoleBinding
        from ..domains.d05.relationship import BoundaryRule
        from ..runtime_contracts import VersionedRef
        group=self.roles+self.boundaries;ns=self.parent.namespace
        if self.social_index==len(group):self.phase='social_result';return
        atom=group[self.social_index]
        if self.social_index<len(self.roles):
            self.role_spec.validator(atom.value);binding=RoleBinding(**{**atom.value,'norm_refs':tuple(atom.value['norm_refs']),'source_refs':tuple(atom.value['source_refs'])})
            if (atom.key.owner.kind not in self.role_spec.owner_kinds or atom.key.name!=binding.role_binding_id or atom.revision!=binding.binding_version
                    or binding.subject_persona_ref!='persona:'+ns.persona_id or atom.key.owner.kind=='scene' and atom.key.owner.subject!=binding.scene_ref
                    or ('role',binding.role_binding_id) in self.social_ids):raise C09PagedCaptureHold('historical role identity/version/inventory repeats or differs')
            self.social_ids.add(('role',binding.role_binding_id));self.bindings.append(binding);self.structural.update(binding.source_refs)
        else:
            self.boundary_spec.validator(atom.value);rule=BoundaryRule(**{**atom.value,**{n:tuple(atom.value[n]) for n in ('source_refs','communicated_refs','acknowledged_refs','exception_refs')}})
            if (atom.key.owner.kind not in self.boundary_spec.owner_kinds or atom.key.name!=rule.rule_id or atom.revision!=rule.scope_version
                    or atom.key.owner.subject!=rule.target_entity_ref or rule.subject_persona_ref!='persona:'+ns.persona_id
                    or ('boundary',rule.rule_id) in self.social_ids):raise C09PagedCaptureHold('historical boundary identity/version/inventory repeats or differs')
            self.social_ids.add(('boundary',rule.rule_id));self.rules.append(rule);self.structural.update(rule.source_refs)
        self.social_index+=1
    def _social_result(self,meter):
        from ..domains.d03.context import RoleBindingResolution,_resolve_role_binding_catalogue_v4
        from ..domains.d05.relationship import BoundaryRuleReadSet
        from ..domains.d05.prebatch_boundary import issue_prebatch_boundary_check_v1
        from ..graph_types import AtomKey,GraphVersion
        from ..runtime_contracts import QueryEpoch,VersionedRef
        context=self.context;request=self.role_request;ns=self.parent.namespace;bindings=self.bindings;rules=self.rules;structural=self.structural
        for spec in self.action.required_checks[:2]:
            criteria=[v for v in spec.required_input_versions if v.ref==spec.criteria_version]
            if len(criteria)!=1:raise C09PagedCaptureHold('historical social criterion absent')
            key=AtomKey.from_token(criteria[0].ref);atom=self._atom(key.token)
            if atom.revision!=criteria[0].version:raise C09PagedCaptureHold('historical social criterion changed')
        resolved=_resolve_role_binding_catalogue_v4(request,tuple(bindings),roles=context._roles,norms=context._norms)
        role_read=RoleBindingResolution(resolved.status,resolved.matched_bindings,resolved.applicable_norm_refs,resolved.missing_items,
            tuple(GraphVersion(a.key,a.revision) for a in self.roles),QueryEpoch(ns,'d03.role_binding',self.epoch),resolved.valid_until,request)
        boundary_read=BoundaryRuleReadSet(ns,QueryEpoch(ns,'d05.boundary',self.epoch),tuple(rules),
            (VersionedRef('d05.boundary',self.epoch),)+tuple(VersionedRef(v.rule_id,v.scope_version) for v in rules),'full',())
        with meter_canonical_outputs(meter):
            role_receipt=context.provide_required_check(self.action,role_read,valid_until=self.expiry)
            boundary=issue_prebatch_boundary_check_v1(self.action,self.schema,boundary_read,audience_scope=self.payload['route']['conversation_ref'],
                scene_ref=self.payload['route']['scene_ref'],now_utc=self.now,valid_until_utc=self.expiry)
        concrete=[b for b in bindings if b.scene_ref==self.payload['route']['scene_ref'] and b.applies_to(request)]
        if len(concrete)!=1 or role_receipt.result!='pass' or boundary.status!='check_pass' or boundary.receipt is None:
            raise C09PagedCaptureHold('historical D03/D05 provider predicates did not pass')
        self.selected_role=concrete[0];self.checks=[role_receipt,boundary.receipt]
        plan=self.parent.natural_plan_budget.plan
        role_atom=next(a for a in self.roles if a.key.name==self.selected_role.role_binding_id)
        binding_atom=self.route_selected[1]
        if (plan.scene_ref.ref!=role_atom.key.token or plan.scene_ref.version!=role_atom.revision
                or plan.audience_ref.ref!=binding_atom.key.token or plan.audience_ref.version!=binding_atom.revision
                or plan.route_binding_digest!=self.route_semantic_digest):raise C09PagedCaptureHold('historical final selected role/account route differs from paid plan')
        expression=set(self.action.source_refs)
        expression.update(v.ref for p,v in self.parent.natural_reference_facts.parser.references.items() if len(p)==6 and p[:3]==('input','plan','units') and p[4]=='source_refs')
        self.closure_pending=[(ref,'expression') for ref in sorted(expression)]+[(ref,'structural') for ref in sorted(structural-expression)]
        self.closure_seen=set();self.phase='source_closure'
    def _source_closure(self,meter):
        from ..graph_types import AtomKey
        from ..memory_types import source_key,access_key,validate_access
        from ..domains.d06 import source_correction_head_key
        if not self.closure_pending:self.phase='qualification_pins';return
        token,mode=self.closure_pending.pop();key=AtomKey.from_token(token);ns=self.parent.namespace
        if key!=source_key(*ns.as_tuple,key.owner.subject):raise C09PagedCaptureHold('historical Source closure root is noncanonical or crosses namespace')
        if (token,mode) in self.closure_seen:return
        self.closure_seen.add((token,mode))
        if len(self.closure_seen)>512:raise C09PagedCaptureHold('actual formal Source ancestry exceeds domain bound')
        record=self.sources.get(token);version=self.source_versions.get(token);access=self._atom(access_key(*ns.as_tuple,key.owner.subject).token,'memory.access')
        if record is None or version is None or version[0]<1 or not version[1]:raise C09PagedCaptureHold('historical source ancestry member absent/invalid')
        validate_access(access.value);head=source_correction_head_key(ns,key.owner.subject)
        if head.token in self.present_tokens:raise C09PagedCaptureHold('actual historical Source correction head was present')
        if record['source_id']!=key.owner.subject or access.value['source_id']!=key.owner.subject or access.value['status']!='active':
            raise C09PagedCaptureHold('actual historical Source/Access identity or state differs')
        if mode=='expression':
            audience=self.payload['route']['conversation_ref']
            if 'expression' not in record['purposes'] or 'expression' not in access.value['purposes'] or audience not in record['audiences'] or audience not in access.value['audiences']:
                raise C09PagedCaptureHold('historical final Source closure lacks expression/audience permissions')
        elif ('owner' not in record['audiences'] or 'owner' not in access.value['audiences']
                or not set(record['purposes']).intersection(access.value['purposes']).intersection({'context','audit'})):
            raise C09PagedCaptureHold('historical structural source lacks Owner context/audit permissions')
        self.closure_pending.extend((source_key(*ns.as_tuple,parent).token,mode) for parent in record['parent_source_ids'])
    def _qualification_pin(self,meter):
        if self.qualification_pin_index==len(self.qualification_pins):self.phase='source_check';return
        token,revision=self.qualification_pins[self.qualification_pin_index]
        if revision==0:
            if token in self.qualification_headers:raise C09PagedCaptureHold('original qualification negative member was present at final E+1')
        elif self.qualification_headers.get(token)!=(revision,True):
            raise C09PagedCaptureHold('actual producer/Source qualification member changed by final E+1')
        self.qualification_pin_index+=1
    def _source_check(self,meter):
        from ..graph_types import AtomKey
        from ..runtime_contracts import CheckReceipt
        specs=[v for v in self.action.required_checks if v.check_kind=='source_grant']
        if len(specs)!=1 or specs[0].provider_id!='d06.source_grant':raise C09PagedCaptureHold('actual final Source check specification absent')
        spec=specs[0];pinned={v.ref:v.version for v in spec.required_input_versions}
        if len(pinned)!=len(spec.required_input_versions) or spec.action_ref!=self.action.action_id or spec.purpose!=self.action.purpose:
            raise C09PagedCaptureHold('actual final Source check version/scope repeats or differs')
        self.source_spec=spec;self.source_pinned=pinned;self.source_pin_items=tuple(pinned.items());self.source_pin_index=0
        self.source_pending=list(self.action.source_refs);self.source_seen=set();self.phase='source_pins';return
    def _source_pin(self,meter):
        from ..graph_types import AtomKey
        if self.source_pin_index==len(self.source_pin_items):self.phase='source_pin_closure';return
        token,revision=self.source_pin_items[self.source_pin_index];key=AtomKey.from_token(token);meter.charge_encode(len(token))
        if (key.owner.bot,key.owner.persona)!=self.parent.namespace.as_tuple:raise C09PagedCaptureHold('historical Source pin crosses namespace')
        if key.type_name=='memory.source':
            if self.source_versions.get(token)!=(revision,True):raise C09PagedCaptureHold('historical Source pin changed')
        elif self._atom(token).revision!=revision:raise C09PagedCaptureHold('historical final Source criterion or Access pin changed')
        self.source_pin_index+=1
    def _source_pin_closure(self,meter):
        from ..memory_types import access_key,source_key
        if not self.source_pending:self.phase='source_receipt';return
        token=self.source_pending.pop()
        if token in self.source_seen:return
        self.source_seen.add(token);record=self.sources[token];access=access_key(*self.parent.namespace.as_tuple,record['source_id']).token
        if token not in self.source_pinned or access not in self.source_pinned:raise C09PagedCaptureHold('historical Source/ancestor Access missing from action pins')
        self.source_pending.extend(source_key(*self.parent.namespace.as_tuple,parent).token for parent in record['parent_source_ids'])
    def _source_receipt(self,meter):
        from ..runtime_contracts import CheckReceipt
        spec=self.source_spec
        self.checks.append(CheckReceipt(spec.check_kind,spec.subject_ref,spec.action_ref,spec.purpose,spec.required_input_versions,'full','pass',float(self.expiry),spec.provider_id))
        self.phase='d08_inventory'
    def _d08(self,meter):
        from ..graph_types import AtomKey,Owner
        from ..domains.d08.execution import ActionSchemaRecord,CommitmentConflictSnapshot,GoalExecutionProvider
        from ..domains.d08.dispatch_check import D08_CRITERIA_REF_V1,D08_CRITERIA_VERSION_V1
        action=self.action;ns=self.parent.namespace;owner=Owner('activity',*ns.as_tuple,action.identity.activity_id)
        goal_atom=self._atom(AtomKey(owner,'d08.goal.v1',action.goal_ref).token)
        cancel_atom=self._atom(AtomKey(owner,'d08.action_cancellation.v1',action.action_id).token)
        with meter_canonical_outputs(meter):
            goal=self.d08_types['d08.goal.v1'].validator(goal_atom.value)
            cancel=self.d08_types['d08.action_cancellation.v1'].validator(cancel_atom.value)
            schema=ActionSchemaRecord.bind(action,self.schema)
        if (self.action_atom_revision!=1 or self.schema_atom_revision!=1 or goal_atom.revision!=1 or goal.goal_id!=action.goal_ref or goal.revision!=1 or goal.state!='active'
                or goal.satisfaction_predicate!=action.success_predicate or len(action.source_refs)!=1 or action.source_refs[0] not in goal.reason_refs
                or self.schema_record!=schema or cancel_atom.revision!=1 or cancel.action_id!=action.action_id or cancel.action_revision!=1
                or cancel.action_digest!=self._digest(action,meter) or cancel.activity_id!=action.identity.activity_id
                or cancel.attempt_id!=action.identity.attempt_id or cancel.effect_id!=action.identity.effect_id or cancel.operation_id!=action.identity.operation_id
                or cancel.state!='active' or cancel.cancel_epoch!=0 or action.commitment_refs):
            raise C09PagedCaptureHold('actual historical D08 goal/schema/cancellation differs')
        self.d08_inventory_tokens=tuple(sorted(t for t,a in self.atoms.items() if a.valid and a.key.type_name in {'d08.commitment.v1','d08.action_intent.v1','d08.action_outcome.v1'}))
        self.d08_index=0;self.d08_ids=set();self.applicable_commitments=[];self.other_actions=[];self.completed_outcomes={};self.current_action_count=0
        self.phase='d08_rows';return
    def _d08_row(self,meter):
        if self.d08_index==len(self.d08_inventory_tokens):
            if self.current_action_count!=1:raise C09PagedCaptureHold('historical action not uniquely present')
            self.d08_other_index=0;self.phase='d08_conflicts';return
        atom=self.atoms[self.d08_inventory_tokens[self.d08_index]];kind=atom.key.type_name;spec=self.d08_types[kind]
        if atom.key.owner.kind not in spec.owner_kinds:raise C09PagedCaptureHold('historical D08 inventory owner differs')
        with meter_canonical_outputs(meter):value=spec.validator(atom.value)
        if kind=='d08.commitment.v1':
            identity=value.commitment_id
            if atom.key.name!=identity or atom.revision!=value.revision or value.subject_ref!='persona:'+self.parent.namespace.persona_id:
                raise C09PagedCaptureHold('historical commitment identity/revision differs')
            if value.counterparty_ref==self.action.target_ref:
                if value.fulfillment_state not in {'fulfilled','withdrawn'}:raise C09PagedCaptureHold('historical same-target commitment was unfinished')
                self.applicable_commitments.append(value)
        elif kind=='d08.action_intent.v1':
            identity=value.action_id
            if atom.key.name!=identity or atom.revision!=value.revision or atom.key.owner.subject!=value.identity.activity_id:
                raise C09PagedCaptureHold('historical action identity/revision differs')
            for token in value.source_refs:self._correction_clear(token)
            if value.action_id==self.action.action_id:
                if value!=self.action:raise C09PagedCaptureHold('historical action differs from actual final intent')
                self.current_action_count+=1
            else:
                if value.identity.effect_id==self.action.identity.effect_id:raise C09PagedCaptureHold('historical effect shared by another action')
                if value.target_ref==self.action.target_ref:self.other_actions.append(value)
        else:
            identity=value.outcome_id
            if atom.key.name!=identity:raise C09PagedCaptureHold('historical outcome identity differs')
            if value.result_level=='completed_verified' and not value.unknown_effects:
                key=(value.action_id,value.effect_id,value.attempt_id);self.completed_outcomes[key]=self.completed_outcomes.get(key,0)+1
        if (kind,identity) in self.d08_ids:raise C09PagedCaptureHold('historical D08 inventory repeats identity')
        self.d08_ids.add((kind,identity));self.d08_index+=1
    def _d08_conflict(self,meter):
        if self.d08_other_index==len(self.other_actions):self.phase='d08_receipt';return
        other=self.other_actions[self.d08_other_index]
        if self.completed_outcomes.get((other.action_id,other.identity.effect_id,other.identity.attempt_id))!=1:
            raise C09PagedCaptureHold('historical same-target action was unfinished')
        self.d08_other_index+=1
    def _d08_receipt(self,meter):
        from ..domains.d08.execution import CommitmentConflictSnapshot,GoalExecutionProvider
        from ..domains.d08.dispatch_check import D08_CRITERIA_REF_V1,D08_CRITERIA_VERSION_V1
        from ..graph_types import AtomKey,Owner
        action=self.action;ns=self.parent.namespace;owner=Owner('activity',*ns.as_tuple,action.identity.activity_id)
        goal_atom=self._atom(AtomKey(owner,'d08.goal.v1',action.goal_ref).token);cancel_atom=self._atom(AtomKey(owner,'d08.action_cancellation.v1',action.action_id).token)
        applicable=self.applicable_commitments
        specs=[v for v in action.required_checks if v.check_kind=='commitment_conflict']
        if len(specs)!=1 or specs[0].provider_id!='d08.commitment_conflict':raise C09PagedCaptureHold('historical D08 fixed check absent')
        spec=specs[0];anchor=self.scope.pinned_anchor
        expected={D08_CRITERIA_REF_V1:D08_CRITERIA_VERSION_V1,action.goal_ref:goal_atom.revision,
            'commitments-query:persona:'+ns.persona_id:self.epoch,'execution-epoch:'+action.action_id:anchor.execution_seq,
            'cancellation-epoch:'+action.action_id:cancel_atom.revision}
        if (spec.criteria_version!=D08_CRITERIA_REF_V1 or spec.subject_ref!='persona:'+ns.persona_id or spec.action_ref!=action.action_id
                or spec.purpose!='expression' or len(spec.required_input_versions)!=len(expected)
                or {v.ref:v.version for v in spec.required_input_versions}!=expected):raise C09PagedCaptureHold('historical D08 criteria/version mapping differs')
        current=CommitmentConflictSnapshot(spec.required_input_versions,'full',tuple(v.commitment_id for v in applicable),(),(),
            action_ref=action.action_id,action_revision=action.revision,intent_digest=self._digest(action,meter),schema_id=action.schema_id,
            goal_ref=action.goal_ref,target_ref=action.target_ref,action_kind=action.action_kind,purpose=action.purpose,
            commitment_query_epoch_ref='commitments-query:persona:'+ns.persona_id,commitment_query_epoch=self.epoch,
            execution_epoch_ref='execution-epoch:'+action.action_id,execution_epoch=anchor.execution_seq,
            cancellation_epoch_ref='cancellation-epoch:'+action.action_id,cancellation_epoch=cancel_atom.revision,current_read_confirmed=True)
        with meter_canonical_outputs(meter):receipt=GoalExecutionProvider().provide_required_check(action,self.schema,current,valid_until=float(self.expiry))
        if receipt.result!='pass' or receipt.coverage!='full':raise C09PagedCaptureHold('actual historical D08 provider did not pass')
        self.checks.append(receipt);self.phase='budget'
    def _correction_clear(self,token):
        from ..graph_types import AtomKey
        from ..memory_types import source_key
        from ..domains.d06 import source_correction_head_key
        key=AtomKey.from_token(token);ns=self.parent.namespace
        if key!=source_key(*ns.as_tuple,key.owner.subject) or self.source_versions.get(token,(0,False))[1] is not True:
            raise C09PagedCaptureHold('historical conflict Source unavailable/noncanonical')
        if source_correction_head_key(ns,key.owner.subject).token in self.present_tokens:raise C09PagedCaptureHold('historical conflict Source correction present')
    def _checks_compare(self,meter):
        from ..runtime_contracts import CheckReceipt
        if self.check_index==len(self.checks):
            self.checks_hash.update(b']');meter.charge_encode(1)
            if self.checks_hash.hexdigest()!=self.payload['checks_digest']:raise C09PagedCaptureHold('actual typed five-check commitment differs')
            self.phase='checks_result';return
        check=self.checks[self.check_index];spec=self.action.required_checks[self.check_index]
        if self.check_cursor is None:
            raw=self.expected_checks[self.check_index]
            expected={f.name:getattr(check,f.name) for f in fields(CheckReceipt) if f.name!='input_versions'}
            if (set(raw)!=set(expected)|{'input_versions'} or {k:v for k,v in raw.items() if k!='input_versions'}!=expected
                    or (check.check_kind,check.issuer,check.subject_ref,check.action_ref,check.purpose)!=(spec.check_kind,spec.provider_id,spec.subject_ref,spec.action_ref,spec.purpose)
                    or check.result!='pass' or check.coverage!='full' or check.valid_until<self.now
                    or check.input_versions!=spec.required_input_versions):
                raise C09PagedCaptureHold('actual recomputed five-check scope/status/metadata differs')
            typed={'$type':CheckReceipt.__module__+'.'+CheckReceipt.__qualname__,**expected,'input_versions':None}
            head,tail=_encode(self.source,typed,meter).split(b'"input_versions":null',1)
            prefix=(b',' if self.check_index else b'')+head+b'"input_versions":[';meter.charge_encode(len(prefix))
            self.checks_hash.update(prefix);self.check_suffix=b']'+tail;self.check_version_index=0
            self.check_cursor=NaturalFinalPayloadArrayCursorV4(self,('check_receipts',self.check_index,'input_versions'),column='admission_json');return
        if not self.check_cursor.queue and not self.check_cursor.complete:self.check_cursor=self.check_cursor.advance(meter);return
        if self.check_version_index==len(check.input_versions):
            if self.check_cursor.queue or not self.check_cursor.complete:raise C09PagedCaptureHold('actual check versions have extra members or incomplete EOF')
            self.checks_hash.update(self.check_suffix);meter.charge_encode(len(self.check_suffix));self.check_index+=1;self.check_cursor=None;return
        if not self.check_cursor.queue:raise C09PagedCaptureHold('actual check input versions omit frozen original')
        raw=self.check_cursor.pop();version=check.input_versions[self.check_version_index]
        if type(raw) is not dict or set(raw)!={'ref','version'} or type(raw['version']) is not int or raw!={'ref':version.ref,'version':version.version}:
            raise C09PagedCaptureHold('actual full historical check input version differs')
        self.checks_hash.update((b',' if self.check_version_index else b'')+_encode(self.source,version,meter));self.check_version_index+=1
    def _checks_result(self,meter):
        # The actual fresh RequiredCheckRegistry qualification has no prior
        # invalidation epochs. Its PASS predicate is exactly the complete,
        # unexpired, scope/spec/receipt equality just proved element by element;
        # its receipt_digest is this complete typed receipt-array commitment.
        grant_atoms=[v for v in self.atoms.values() if v.valid and v.key.type_name=='d08.communication_intent_grant.v1' and v.value['action_id']==self.action.action_id]
        if len(grant_atoms)!=1:raise C09PagedCaptureHold('historical final communication grant is not unique')
        with meter_canonical_outputs(meter):self.communication_grant=self.d08_types['d08.communication_intent_grant.v1'].validator(grant_atoms[0].value)
        if (len(self.checks)!=5 or len(self.action.required_checks)!=5 or self.action.required_checks!=self.schema.required_checks
                or tuple(c.check_kind for c in self.checks)!=('role_binding','boundary','source_grant','commitment_conflict','dispatch_budget')
                or self.checks_hash.hexdigest()!=self.communication_grant.qualification_receipt_digest
                or self.communication_grant.route_binding_digest!=self.route_semantic_digest):
            raise C09PagedCaptureHold('historical qualification predicate/digest differs from actual communication grant')
        self.phase='final_links'
    def _final_links(self,meter):
        from ..runtime.dispatch_admission import _decode_request
        from ..runtime_contracts import canonical_digest
        original=self.parent.natural_final_original;admission=original.admission_values['admission_json']
        request_raw=original.admission_values['request_json']
        fee=c09_canonical_json_size_v3(request_raw,spaced=True)+c09_canonical_json_size_v3(request_raw)
        meter.require_available(fee*2);self.source.require_arena(fee*32+65536)
        raw=json.dumps(request_raw,sort_keys=True,separators=(',',':'),ensure_ascii=True)
        meter.charge_encode(len(raw));self.source.require_arena(len(raw)*32+32768)
        with meter_canonical_outputs(meter):request=_decode_request(raw)
        meter.charge_encode(c09_canonical_json_size_v3(request_raw,spaced=True,exact=True)+c09_canonical_json_size_v3(request_raw,exact=True))
        grant=self.communication_grant;scope=self.scope;action=self.action
        command={'operation_id':self.business_operation_id,'outbox_ref':self.parent.outbox_ref,'idempotency_key':request.footprint.external_idempotency_ref,
            'batch_ref':self.parent.small['batch_ref'],'segment_index':request.segment_index,'payload_digest':request.payload_digest,'fence_token':scope.permit.token}
        if (request.command_digest!=self._digest(command,meter) or self._digest(request,meter)!=self.payload['request_digest']
                or admission['request_digest']!=self.payload['request_digest'] or admission['operation_id']!=self.business_operation_id
                or admission['effect_id']!=action.identity.effect_id or admission['attempt_id']!=action.identity.attempt_id
                or admission['action_ref']!=action.action_id or admission['purpose']!=action.purpose or admission['object_ref']!=action.target_ref
                or admission['account_ref']!=self.payload['route']['platform_ref'] or admission['destination_ref']!=self.payload['route']['conversation_ref']
                or admission['scene_ref']!=self.payload['route']['scene_ref'] or admission['binding_ref']!=self.selected_role.role_binding_id
                or admission['role_ref']!=self.selected_role.social_role or admission['owner_head_ref']!=self.parent.natural_final_authority_original.proof.grant_id
                or admission['action_intent_digest']!=self._digest(action,meter) or admission['action_schema_digest']!=self._digest(self.schema_record,meter)
                or admission['required_checks_digest']!=self._digest(action.required_checks,meter) or admission['grant_digest']!=self._digest(grant,meter)
                or request.content_fence!=scope.permit.token or request.activation_generation!=scope.generation
                or request.required_check_refs!=grant.required_check_refs):
            raise C09PagedCaptureHold('historical final admission/request business links differ')
        if (admission['budget_lease_ref']!=self.budget.lease.lease_id or admission['budget_ceiling']!=self.budget.ceiling
                or admission['budget_reservation_digest']!=self.budget.reservation_digest):
            raise C09PagedCaptureHold('historical final admission differs from actual immutable budget observation')
        receipt_digest=self._digest({'admission_digest':self.payload['admission_digest'],'graph_revision':scope.graph_revision+1,'graph_epoch':self.epoch},meter)
        if original.admission_wire_sha!=self.payload['admission_digest'] or receipt_digest!=self.payload['admission_receipt_digest']:
            raise C09PagedCaptureHold('actual complete admission canonical digest or receipt digest differs')
        self.complete=True;self.source_qualified_complete=True
    def _semantics(self,meter):
        if self.phase=='clock':self._clock(meter)
        elif self.phase=='core_effect':self._core_effect(meter)
        elif self.phase=='execution_prefix':self._execution_prefix(meter)
        elif self.phase=='barrier':self._barrier(meter)
        elif self.phase=='owner':self._owner(meter)
        elif self.phase=='route_rows':self._route_originals(meter)
        elif self.phase=='route_identity':self._route_identity(meter)
        elif self.phase=='route_scan':self._route_scan(meter)
        elif self.phase=='projection_begin':self._action_begin(meter)
        elif self.phase=='projection_members':self._projection_member(meter)
        elif self.phase=='social':self._social(meter)
        elif self.phase=='social_rows':self._social_row(meter)
        elif self.phase=='social_result':self._social_result(meter)
        elif self.phase=='source_closure':self._source_closure(meter)
        elif self.phase=='qualification_pins':self._qualification_pin(meter)
        elif self.phase=='source_check':self._source_check(meter)
        elif self.phase=='source_pins':self._source_pin(meter)
        elif self.phase=='source_pin_closure':self._source_pin_closure(meter)
        elif self.phase=='source_receipt':self._source_receipt(meter)
        elif self.phase=='d08_inventory':self._d08(meter)
        elif self.phase=='d08_rows':self._d08_row(meter)
        elif self.phase=='d08_conflicts':self._d08_conflict(meter)
        elif self.phase=='d08_receipt':self._d08_receipt(meter)
        elif self.phase=='budget':
            from .c09_natural_final_budget_v4 import NaturalFinalBudgetOriginalReadV4
            if self.budget is None:self.budget=NaturalFinalBudgetOriginalReadV4(self)
            elif not self.budget.complete:self.budget=self.budget.advance(meter)
            else:
                self.checks.append(self.budget.recomputed_receipt);self.check_index=0;self.check_cursor=None;self.checks_hash=sha256();self.checks_hash.update(b'[');meter.charge_encode(1);self.phase='checks_compare'
        elif self.phase=='checks_compare':self._checks_compare(meter)
        elif self.phase=='checks_result':self._checks_result(meter)
        elif self.phase=='final_links':self._final_links(meter)
        else:raise C09PagedCaptureHold('unknown actual final historical permission phase')
    def _clock(self,meter):
        import math
        from dataclasses import asdict
        from .v2_clock import IngressClockSampleV2
        from ..host.authority_profile import AdminIngressClockPolicy
        from ..host.v2_fence_port import VerifiedIngressClockV2
        from ..runtime.first_ingress_v2 import trusted_upper_at_v4
        value=self.payload['clock_validation'];uses=self.payload['clock_uses'];raw=self.payload['clock_reading']
        expected={'schema','authority_id','installation_id','sample','policy','monotonic_before','monotonic_after','prior_watermark','next_watermark','utc_upper'}
        if set(value)!=expected or value['schema']!='sylanne.natural-clock-validation.v4':raise C09PagedCaptureHold('actual original paired clock schema differs')
        sample=IngressClockSampleV2(**value['sample']);policy=AdminIngressClockPolicy(**value['policy'])
        before=value['monotonic_before'];after=value['monotonic_after']
        if (any(type(v) not in (int,float) or not math.isfinite(v) for v in (before,after,value['utc_upper']))
                or sample.authority_id!=self.scope.permit.authority_id or sample.installation_id!=self.parent.natural_final_authority_original.guard.installation_id
                or value['authority_id']!=sample.authority_id or value['installation_id']!=sample.installation_id
                or sample.source_id!=policy.source_id or sample.utc_error_seconds>policy.max_utc_error_seconds
                or after<before or after-before>policy.max_round_trip_seconds or value['policy']!=self.payload['clock_policy']):
            raise C09PagedCaptureHold('actual historical paired clock installation/policy/roundtrip differs')
        upper=math.nextafter(math.fsum((sample.utc_seconds,sample.utc_error_seconds,after-before)),math.inf)
        lower=math.fsum((sample.utc_seconds,-sample.utc_error_seconds));prior=value['prior_watermark']
        names={'source_id','epoch','source_monotonic','local_after','lower'}
        if prior is not None:
            if (type(prior) is not dict or set(prior)!=names or prior['source_id']!=sample.source_id or prior['epoch']!=sample.epoch
                    or any(type(prior[n]) not in (int,float) or not math.isfinite(prior[n]) for n in ('source_monotonic','local_after','lower'))
                    or sample.monotonic_seconds<prior['source_monotonic'] or before<prior['local_after']):
                raise C09PagedCaptureHold('historical paired clock prior watermark differs')
            elapsed=max(sample.monotonic_seconds-prior['source_monotonic'],before-prior['local_after'])
            projected=math.fsum((prior['lower'],elapsed));sample_upper=math.fsum((sample.utc_seconds,sample.utc_error_seconds))
            if not math.isfinite(projected) or math.nextafter(sample_upper,math.inf)<projected:raise C09PagedCaptureHold('historical paired clock rolled back')
            lower=max(lower,projected)
        next_watermark={'source_id':sample.source_id,'epoch':sample.epoch,'source_monotonic':sample.monotonic_seconds,'local_after':after,'lower':lower}
        reading=VerifiedIngressClockV2(sample,before,after,upper)
        if (not math.isfinite(upper) or value['utc_upper']!=upper or value['next_watermark']!=next_watermark
                or raw!=asdict(reading) or type(uses) not in (tuple,list) or not uses):raise C09PagedCaptureHold('historical paired clock next/reading original differs')
        previous=after
        for index,use in enumerate(uses):
            if (type(use) is not dict or set(use)!={'purpose','monotonic_now','utc_upper'}
                    or use['purpose']!=('natural_basis' if index==0 else 'natural_dispatch')
                    or type(use['monotonic_now']) not in (int,float) or not math.isfinite(use['monotonic_now'])
                    or use['monotonic_now']<previous or trusted_upper_at_v4(reading,use['monotonic_now'])!=use['utc_upper']):
                raise C09PagedCaptureHold('historical actual clock consumer arithmetic or order differs')
            previous=use['monotonic_now']
        if uses[0]['utc_upper']!=self.payload['now_utc'] or len(uses)<2:raise C09PagedCaptureHold('historical basis/final dispatch clock consumption absent')
        self.now=self.payload['now_utc'];self.dispatch_now=uses[-1]['utc_upper'];self.phase='core_effect'
    def _core_effect(self,meter):
        if self.core_reader is None:self.core_reader=_NaturalFinalCoreObservationReadV4(self)
        elif not self.core_reader.complete:self.core_reader=self.core_reader.advance(meter)
        else:
            value=self.core_reader.observation;self.observation=value
            self.required_core_rows=(self.core_reader.obligation,)
            self.capture.builder.basis.record_source_qualified_natural_final_core_rows_v4(self,meter=meter)
            if value.effect_snapshot.coverage!='complete' or value.effect_snapshot.unresolved_effects or value.current_effect.state!='absent':
                raise C09PagedCaptureHold('actual historical D08 complete effect inventory was not clear')
            self.execution_pair=self.parent.dispatch_mutation.journal.pair
            self.execution_pair.require_current();self.execution_seq=0;self.execution_digest='genesis'
            self.execution_small=None;self.execution_buffer=bytearray();self.execution_offset=0;self.execution_total=None
            self.execution_blob_hash=sha256();self.phase='execution_prefix'
    def _execution_prefix(self,meter):
        from .v2_contract import decode_bytes,canonical_bytes,PendingMutationV2
        from .v2_execution_journal import AuthorityV2ExecutionJournal
        pair=self.execution_pair;pair.require_current();anchor=self.scope.pinned_anchor
        if self.execution_small is None:
            if self.execution_seq==anchor.execution_seq:
                if self.execution_digest!=anchor.execution_digest:raise C09PagedCaptureHold('historical execution prefix head differs from actual final observation')
                self.phase='scan';return
            columns=('seq','mutation_id','request_digest','append_id','previous_digest','chain_digest')
            with legacy_cell_read_transaction_v2(pair.source):
                small=meter.read_fixed_row(pair.source,'authority_v2_execution_entries',columns,'seq=?',(self.execution_seq+1,))
            if small is None or small[0]!=self.execution_seq+1 or small[4]!=self.execution_digest:raise C09PagedCaptureHold('actual final historical execution prefix has a gap')
            self.execution_small=small;self.execution_offset=0;self.execution_total=None;self.execution_buffer=bytearray();self.execution_blob_hash=sha256();return
        small=self.execution_small
        with legacy_cell_read_transaction_v2(pair.source):
            if self.execution_total is None:
                _,total,kind=read_legacy_sql_cell_fragment_v2(pair.source,table='authority_v2_execution_entries',column='pending',
                    where='seq=?',parameters=(small[0],),start=0,length=0,meter=meter)
                if kind!='blob' or total<=0:raise C09PagedCaptureHold('actual historical journal pending BLOB absent')
                self.source.require_arena(total*32+65536);self.execution_total=total;return
            if self.execution_offset<self.execution_total:
                amount=min(8192,self.execution_total-self.execution_offset);self.source.require_arena(amount*16+32768)
                raw,total,kind=read_legacy_sql_cell_fragment_v2(pair.source,table='authority_v2_execution_entries',column='pending',
                    where='seq=?',parameters=(small[0],),start=self.execution_offset,length=amount,meter=meter)
                if kind!='blob' or total!=self.execution_total or len(raw)!=amount:raise C09PagedCaptureHold('actual historical prefix pending BLOB changed')
                self.execution_buffer.extend(raw);self.execution_blob_hash.update(raw);self.execution_offset+=amount;return
        facts=self.capture.builder.transform.facts
        columns=('seq','mutation_id','request_digest','append_id','pending','previous_digest','chain_digest')
        facts.require_execution_journal_stream_v3(pair.source_original,columns,small,self.execution_blob_hash.hexdigest(),meter=meter)
        # The sealed recovery index was produced by the real complete journal
        # and authenticated Core mutation walk. Recompute the exact pending
        # codec/chain too; domain journals remain authenticated by that index.
        encoded=bytes(self.execution_buffer);meter.charge_encode(len(encoded));self.source.require_arena(len(encoded)*32+65536)
        if not encoded.startswith((b'{"binding":',b'D04',b'D11')):
            parsed=json.loads(encoded);kind=parsed.get('kind') if type(parsed) is dict else None
            if kind=='pending_mutation':
                fee=self.parent._constructor_encoding_bound(parsed);meter.require_available(fee+len(encoded)*4)
                pending=decode_bytes(encoded);meter.charge_encode(self.parent._constructor_encoding_bound(parsed,exact=True))
                wire=canonical_bytes(pending);meter.charge_encode(len(wire))
                material=AuthorityV2ExecutionJournal._material(pending,pending.expected_execution_seq,pending.before_anchor.execution_digest,pending.expected_execution_journal_id)
                meter.charge_encode(len(material));digest='sha256:'+sha256(material).hexdigest()
                if (type(pending) is not PendingMutationV2 or wire!=encoded or pending.permit.namespace!=self.scope.authority_namespace
                        or pending.expected_execution_journal_id!=anchor.execution_journal_id or pending.before_anchor.execution_seq!=small[0]-1
                        or pending.before_anchor.execution_digest!=small[4] or pending.expected_append_digest!=small[5] or digest!=small[5]
                        or (pending.mutation_id,pending.request_digest,pending.expected_append_id)!=small[1:4]):
                    raise C09PagedCaptureHold('historical execution mutation codec/chain identity differs')
        self.execution_seq=small[0];self.execution_digest=small[5];self.execution_small=None;self.execution_buffer.clear();self.execution_total=None

class _NaturalFinalCoreObservationReadV4:
    """One actual frozen Core original with bounded complete BLOB decoding."""
    _columns=('authority_namespace','operation_id','observation_kind','permit_digest','original_bytes','original_digest')
    def __init__(self,owner):
        self.owner=owner;self.source=owner.source;self.builder=owner.capture.builder;self.pair=self.builder.pair
        self.scope=owner.scope;self.key=(self.scope.authority_namespace,self.scope.operation_id,'effect_inventory')
        self.phase='row';self.small=None;self.buffer=bytearray();self.offset=0;self.total=None;self.complete=False;self.observation=None
        self.source.arena.add(self)
    def _source_heap_bytes(self):
        return sys.getsizeof(self.__dict__)+sum(_heap(v) for n,v in self.__dict__.items() if n not in {'owner','source','builder','pair','scope'})+8192
    def copy(self):
        self.source.require_arena(self._source_heap_bytes());result=copy(self);result.buffer=bytearray(self.buffer);self.source.arena.add(result);return result
    def advance(self,meter):
        from dataclasses import asdict
        from .v2_contract import (decode_bytes,canonical_bytes,to_wire,AuthorityNaturalFinalEffectObservationV4,
            canonical_digest as authority_digest,_reject_duplicate_pairs,_reject_constant)
        self.builder.require_current();self.pair.require_current();result=self.copy();db=self.pair.source
        if result.phase=='row':
            if self.pair.source_original!=self.owner.parent.natural_final_authority_original.source_original:raise C09PagedCaptureHold('Core final observation lost actual frozen role source')
            with legacy_cell_read_transaction_v2(db):
                shape=read_c09_table_shape_v2(db,'authority_natural_final_observations_v4',meter=meter)
                if shape.columns!=result._columns or shape.primary_key_columns!=result._columns[:3] or shape.primary_key_types!=('text','text','text'):
                    raise C09PagedCaptureHold('actual final Core observation schema/key differs')
                names=result._columns[:4]+result._columns[5:]
                row=meter.read_fixed_row(db,shape.table,names,'authority_namespace=? AND operation_id=? AND observation_kind=?',result.key)
            if row is None or row[:3]!=result.key:raise C09PagedCaptureHold('actual final Core observation original absent')
            result.small=dict(zip(names,row,strict=True));result.shape=shape;result.phase='blob'
        elif result.phase=='blob':
            with legacy_cell_read_transaction_v2(db):
                if result.total is None:
                    _,total,kind=read_legacy_sql_cell_fragment_v2(db,table='authority_natural_final_observations_v4',column='original_bytes',
                        where='authority_namespace=? AND operation_id=? AND observation_kind=?',parameters=result.key,start=0,length=0,meter=meter)
                    if kind!='blob' or total<=0:raise C09PagedCaptureHold('actual final Core observation BLOB absent')
                    result.source.require_arena(total*32+65536);result.total=total
                elif result.offset<result.total:
                    amount=min(8192,result.total-result.offset);result.source.require_arena(amount*16+32768)
                    raw,total,kind=read_legacy_sql_cell_fragment_v2(db,table='authority_natural_final_observations_v4',column='original_bytes',
                        where='authority_namespace=? AND operation_id=? AND observation_kind=?',parameters=result.key,start=result.offset,length=amount,meter=meter)
                    if kind!='blob' or total!=result.total or len(raw)!=amount:raise C09PagedCaptureHold('actual final Core observation BLOB changed')
                    result.buffer.extend(raw);result.offset+=amount
                else:result.phase='decode'
        elif result.phase=='decode':
            encoded=bytes(result.buffer);meter.require_available(len(encoded)*8);result.source.require_arena(len(encoded)*32+65536)
            wire=json.loads(encoded,object_pairs_hook=_reject_duplicate_pairs,parse_constant=_reject_constant)
            if type(wire) is not dict or wire.get('kind')!='authority_natural_final_effect_observation_v4':raise C09PagedCaptureHold('actual final Core observation closed codec kind differs')
            value=decode_bytes(encoded);roundtrip=canonical_bytes(value);meter.charge_encode(len(roundtrip))
            permit_bytes=canonical_bytes(value.permit);meter.charge_encode(len(permit_bytes)*2)
            reference=value.original_ref;ref_bytes=json.dumps(result.key,separators=(',',':'),ensure_ascii=False).encode('utf-8');meter.charge_encode(len(ref_bytes))
            locator=result.owner.payload['effect_observation'];digest='sha256:'+sha256(encoded).hexdigest()
            if (type(value) is not AuthorityNaturalFinalEffectObservationV4 or roundtrip!=encoded or digest!=result.small['original_digest']
                    or result.small['permit_digest']!='sha256:'+sha256(permit_bytes).hexdigest() or value.permit!=result.scope.permit
                    or value.anchor!=result.scope.pinned_anchor or value.target_effect_id!=result.owner.payload['identity']['effect_id']
                    or value.installation_id!=result.owner.parent.natural_final_authority_original.guard.installation_id
                    or locator!={'original_ref':reference,'original_digest':digest,'authority_namespace':result.key[0],'operation_id':result.key[1],'observation_kind':result.key[2]}
                    or asdict(value.current_effect)!=result.owner.payload['current_effect'] or to_wire(value.effect_snapshot)!=result.owner.payload['effect_snapshot']):
                raise C09PagedCaptureHold('actual frozen Core final effect/fence/Owner/Graph original semantics differ')
            from . import c09_authority_storage_rebase as legacy
            row=(*result.key,result.small['permit_digest'],encoded,digest)
            row_commitment=legacy._row_commitment('authority_natural_final_observations_v4',result._columns,row)
            meter.charge_encode(len(legacy._canonical(('authority_natural_final_observations_v4',result._columns,tuple(legacy._cell(v) for v in row)))))
            key_json=_encode(result.source,result.key,meter)
            result.obligation={'scope_digest':result.builder.scope.scope_digest,
                'core_source_original_digest':result.pair.source_original.role_source_digest,
                'table':result.shape.table,'schema_digest':result.shape.schema_digest,'primary_key':list(result.key),
                'key_digest':sha256(key_json).hexdigest(),'source_row_commitment':row_commitment,
                'required_disposition':'preserved_exact','expected_target_row_commitment':row_commitment,
                'operation_id':result.scope.operation_id,'fence_token':result.scope.permit.token}
            result.observation=value;result.buffer.clear();result.complete=True
        else:raise C09PagedCaptureHold('unknown actual final Core observation phase')
        self.source.require_arena();return result

def emit_natural_final_core_row_obligation_v4(builder,*,source,table,key,operation_id,fence_token,meter,row_reader):
    """Qualify one actual Source row; the closing stream owns its persistence."""
    from .c09_authority_storage_rebase_v2 import _InstalledAuthorityRoleBuilderV2
    if type(builder) is not _InstalledAuthorityRoleBuilderV2 or builder.transform.role!='core':
        raise C09PagedCaptureHold('actual Core role builder required for final target obligation')
    builder.require_current();pair=builder.pair;pair.require_current()
    if (type(row_reader) is not _NaturalFinalCoreRowCommitmentReadV4 or not row_reader.complete
            or row_reader.target or row_reader.builder is not builder or row_reader.table!=table or row_reader.key!=tuple(key)):
        raise C09PagedCaptureHold('actual complete streamed Core Source row required')
    shape=row_reader.shape;commitment=row_reader.commitment
    key_json=_encode(source,key,meter)
    value={'scope_digest':builder.scope.scope_digest,'core_source_original_digest':pair.source_original.role_source_digest,
        'table':table,'schema_digest':shape.schema_digest,'primary_key':list(key),'key_digest':sha256(key_json).hexdigest(),
        'source_row_commitment':commitment,'required_disposition':'preserved_exact','expected_target_row_commitment':commitment,
        'operation_id':operation_id,'fence_token':fence_token}
    builder.require_current();return value

class _NaturalFinalCoreRowCommitmentReadV4:
    """Exact legacy full-row commitment, one column or bounded fragment per step."""
    def __init__(self,token,builder,table,key,arena,*,target=False):
        from .c09_authority_storage_rebase_v2 import _InstalledAuthorityRoleBuilderV2
        if token is not _CORE_OBLIGATION_TOKEN_V4 or type(builder) is not _InstalledAuthorityRoleBuilderV2 or builder.transform.role!='core':raise TypeError('actual private Core row commitment issuer required')
        self._issuer=token;self.builder=builder;self.table=table;self.key=tuple(key);self.target=target;self.arena=arena
        self.shape=None;self.column=0;self.kind=None;self.total=None;self.offset=0;self.decoder=None
        self.digest=sha256();self.complete=False;self.commitment=None;arena.add(self)
    def _source_heap_bytes(self):return _heap((self.shape,self.key,self.kind,self.total,self.offset))+8192
    def require_arena(self,extra=0):
        _require_core_obligation_arena_v4(self.arena,extra)
    def copy(self):
        self.require_arena(self._source_heap_bytes());result=copy(self);result.digest=self.digest.copy()
        if self.decoder is not None:
            import codecs
            result.decoder=codecs.getincrementaldecoder('utf-8')('strict');result.decoder.setstate(self.decoder.getstate())
        self.arena.add(result);return result
    def advance(self,meter):
        if self._issuer is not _CORE_OBLIGATION_TOKEN_V4:raise C09PagedCaptureHold('actual Core row commitment issuer differs')
        self.builder.require_current()
        db=self.builder.cold.reader if self.target else self.builder.pair.source
        return self._advance_database(db,meter)
    def _advance_database(self,db,meter):
        import codecs
        from .c09_paged_recovery_facts_v2 import _read_one
        from . import c09_authority_storage_rebase as legacy
        from ..runtime.c09_paged_sql_v2 import _quote
        result=self.copy()
        with legacy_cell_read_transaction_v2(db):
            if result.shape is None:
                result.shape=read_c09_table_shape_v2(db,result.table,meter=meter)
                prefix=legacy._canonical((result.table,result.shape.columns))[:-1]+b',['
                meter.charge_encode(len(prefix));result.digest.update(prefix);return result
            if result.column==len(result.shape.columns):
                meter.charge_encode(2);result.digest.update(b']]');result.commitment=result.digest.hexdigest();result.complete=True;return result
            name=result.shape.columns[result.column];where=' AND '.join(_quote(n)+'=?' for n in result.shape.primary_key_columns)
            if result.kind is None:
                found=_read_one(db,'SELECT typeof('+_quote(name)+'),length(CAST('+_quote(name)+' AS BLOB)) FROM '+_quote(result.table)+' WHERE '+where,result.key,meter)
                if found is None:raise C09PagedCaptureHold('required actual Core row absent')
                result.kind,result.total=found
                comma=b',' if result.column else b''
                if result.kind in {'text','blob'}:
                    prefix=comma+b'["'+result.kind.encode('ascii')+b'","'
                    result.decoder=codecs.getincrementaldecoder('utf-8')('strict') if result.kind=='text' else None
                    meter.charge_encode(len(prefix));result.digest.update(prefix);return result
                scalar=_read_one(db,'SELECT '+_quote(name)+' FROM '+_quote(result.table)+' WHERE '+where,result.key,meter)
                raw=comma+legacy._canonical(legacy._cell(scalar[0]));meter.charge_encode(len(raw));result.digest.update(raw)
                result.column+=1;result.kind=None;result.total=None;return result
            amount=min(8192,result.total-result.offset);result.require_arena(amount*16+32768);meter.require_available(amount*8+4096)
            raw,total,kind=read_legacy_sql_cell_fragment_v2(db,table=result.table,column=name,where=where,parameters=result.key,start=result.offset,length=amount,meter=meter)
            if kind!=result.kind or total!=result.total or len(raw)!=amount:raise C09PagedCaptureHold('required actual Core row fragment changed')
            if kind=='blob':encoded=raw.hex().encode('ascii')
            else:encoded=legacy._canonical(result.decoder.decode(raw,final=result.offset+amount==total))[1:-1]
            meter.charge_encode(len(encoded));result.digest.update(encoded);result.offset+=amount
            if result.offset==result.total:
                meter.charge_encode(2);result.digest.update(b'"]');result.column+=1;result.kind=None;result.total=None;result.offset=0;result.decoder=None
        return result

def _verify_core_obligation_disposition_v4(db,obligation,shape,target,scope_digest,source_digest,meter):
    from ..runtime.c09_paged_capture_contract_v2 import C09StreamIdentityV2,C09CompleteStreamV2,c09_paged_value_from_wire_v2
    from ..runtime.c09_paged_sql_v2 import require_c09_capture_member_v2
    table=obligation['table'];key=tuple(obligation['primary_key'])
    proof=meter.read_fixed_row(db,'authority_c09_role_rows_v2',('old_commitment','disposition','new_commitment'),
        'scope_digest=? AND role=? AND table_name=? AND key_digest=?',(scope_digest,'core',table,obligation['key_digest']))
    if proof!=(obligation['source_row_commitment'],'preserved_exact',target) or target!=obligation['expected_target_row_commitment']:
        raise C09PagedCaptureHold('required Core target disposition/full commitment differs')
    stream=C09StreamIdentityV2(scope_digest,source_digest,'row_dispositions',table,shape.schema_digest,shape.primary_key_columns,shape.primary_key_types)
    seal=meter.read_fixed_row(db,'c09_capture_streams_v2',('status','seal_json'),'stream_id=?',(stream.stream_id,))
    if seal is None or seal[0]!='sealed':raise C09PagedCaptureHold('required Core disposition stream is not sealed')
    complete=c09_paged_value_from_wire_v2(json.loads(seal[1]),C09CompleteStreamV2)
    member=meter.read_fixed_row(db,'c09_capture_members_v2',('record_ordinal','commitment'),
        'stream_id=? AND key_digest=?',(stream.stream_id,obligation['key_digest']))
    values=(scope_digest,'core',table,obligation['key_digest'],canonical_serialize(key),*proof)
    with meter_canonical_outputs(meter):expected=sha256(canonical_serialize(('sylanne3.c09.authority-row-disposition.v2',values)).encode('ascii')).hexdigest()
    if member is None or not 1<=member[0]<=complete.record_count or member[1]!=expected:
        raise C09PagedCaptureHold('required Core target disposition lacks sealed membership')
    require_c09_capture_member_v2(db,stream,member[0],key,expected,meter=meter)
    return stream,complete

def fulfil_natural_final_core_row_obligation_v4(builder,obligation,*,meter,row_reader):
    """Closing-only actual cold target/member proof for one Source obligation."""
    from .c09_authority_storage_rebase_v2 import _InstalledAuthorityRoleBuilderV2
    if (type(builder) is not _InstalledAuthorityRoleBuilderV2 or builder.transform.role!='core' or builder.cold is None
            or not builder.cold.directory_checked or builder.cold.active is not None
            or (builder.cold_position_v3 or builder._pending_cold_position_v3) is None
            or (builder.cold_position_v3 or builder._pending_cold_position_v3)['cold_digest']!=builder.cold.root):
        raise C09PagedCaptureHold('required Core target obligations need actual completed cold sweep')
    builder.require_current();pair=builder.pair;pair.require_current();table=obligation['table'];key=tuple(obligation['primary_key'])
    if (obligation['scope_digest']!=builder.scope.scope_digest or obligation['core_source_original_digest']!=pair.source_original.role_source_digest
            or obligation['required_disposition']!='preserved_exact'):raise C09PagedCaptureHold('Core target obligation crossed actual scope/source')
    with legacy_cell_read_transaction_v2(builder.cold.reader):
        shape=read_c09_table_shape_v2(builder.cold.reader,table,meter=meter)
        if shape.schema_digest!=obligation['schema_digest']:raise C09PagedCaptureHold('required Core target logical schema differs')
        if (type(row_reader) is not _NaturalFinalCoreRowCommitmentReadV4 or not row_reader.complete
                or not row_reader.target or row_reader.builder is not builder or row_reader.table!=table or row_reader.key!=key
                or row_reader.shape!=shape):raise C09PagedCaptureHold('actual complete streamed Core target row required')
        target=row_reader.commitment
        _verify_core_obligation_disposition_v4(builder.cold.reader,obligation,shape,target,builder.scope.scope_digest,pair.source_original.role_source_digest,meter)
    builder.require_current();return {**obligation,'fulfilled_target_commitment':target,'cold_digest':builder.cold.root}

_CORE_OBLIGATION_TABLES_V4={
 'c09_natural_final_core_required_v4':"CREATE TABLE c09_natural_final_core_required_v4(scope_digest TEXT NOT NULL,table_name TEXT NOT NULL,key_digest TEXT NOT NULL,source_json TEXT NOT NULL,source_commitment TEXT NOT NULL,PRIMARY KEY(scope_digest,table_name,key_digest)) STRICT",
 'c09_natural_final_core_consumers_v4':"CREATE TABLE c09_natural_final_core_consumers_v4(scope_digest TEXT NOT NULL,table_name TEXT NOT NULL,key_digest TEXT NOT NULL,operation_id TEXT NOT NULL,fence_token TEXT NOT NULL,PRIMARY KEY(scope_digest,table_name,key_digest,operation_id,fence_token),FOREIGN KEY(scope_digest,table_name,key_digest) REFERENCES c09_natural_final_core_required_v4(scope_digest,table_name,key_digest)) STRICT",
 'c09_natural_final_core_fulfilled_v4':"CREATE TABLE c09_natural_final_core_fulfilled_v4(scope_digest TEXT NOT NULL,table_name TEXT NOT NULL,key_digest TEXT NOT NULL,source_commitment TEXT NOT NULL,target_commitment TEXT NOT NULL,cold_digest TEXT NOT NULL,PRIMARY KEY(scope_digest,table_name,key_digest),FOREIGN KEY(scope_digest,table_name,key_digest) REFERENCES c09_natural_final_core_required_v4(scope_digest,table_name,key_digest)) STRICT",
 'c09_natural_final_core_progress_v4':"CREATE TABLE c09_natural_final_core_progress_v4(scope_digest TEXT NOT NULL,family TEXT NOT NULL,progress_json TEXT NOT NULL,PRIMARY KEY(scope_digest,family)) STRICT",
 'c09_natural_final_core_seals_v4':"CREATE TABLE c09_natural_final_core_seals_v4(scope_digest TEXT NOT NULL,family TEXT NOT NULL,stream_json TEXT NOT NULL,seal_json TEXT NOT NULL,matching_root TEXT NOT NULL,record_count INTEGER NOT NULL,PRIMARY KEY(scope_digest,family)) STRICT",
}
_CORE_OBLIGATION_TOKEN_V4=object()
_CORE_OBLIGATION_PROOFS_V4=WeakSet()

def _write(db,sql,parameters,meter):
    from .c09_paged_recovery_facts_v2 import _write as fact_write
    return fact_write(db,sql,parameters,meter)

def require_natural_final_core_obligation_schema_v4(db,*,meter,install=False):
    from ..runtime.c09_paged_sql_v2 import CAPTURE_DDLS_V2,CAPTURE_TRIGGERS_V2
    from .c09_paged_recovery_facts_v2 import _read_one
    for name,ddl in _CORE_OBLIGATION_TABLES_V4.items():
        row=_read_one(db,"SELECT sql FROM sqlite_master WHERE type='table' AND name=?",(name,),meter)
        if row is None and install:_write(db,ddl,(),meter)
        elif row!=(ddl,):raise C09PagedCaptureHold('actual natural Core obligation schema differs')
        if name!='c09_natural_final_core_progress_v4':
            for action in ('UPDATE','DELETE'):
                trigger=name+'_no_'+action.lower()
                sql="CREATE TRIGGER "+trigger+" BEFORE "+action+" ON "+name+" BEGIN SELECT RAISE(ABORT,'immutable natural Core obligation'); END"
                saved=_read_one(db,"SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?",(trigger,),meter)
                if saved is None and install:_write(db,sql,(),meter)
                elif saved!=(sql,):raise C09PagedCaptureHold('actual natural Core obligation immutable trigger differs')
    for table,family in (('c09_natural_final_core_required_v4','required'),('c09_natural_final_core_consumers_v4','consumers'),('c09_natural_final_core_fulfilled_v4','fulfilled')):
        trigger=table+'_closed_insert'
        sql="CREATE TRIGGER "+trigger+" BEFORE INSERT ON "+table+" WHEN EXISTS(SELECT 1 FROM c09_natural_final_core_seals_v4 WHERE scope_digest=NEW.scope_digest AND family='"+family+"') BEGIN SELECT RAISE(ABORT,'sealed natural Core obligation inventory'); END"
        saved=_read_one(db,"SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?",(trigger,),meter)
        if saved is None and install:_write(db,sql,(),meter)
        elif saved!=(sql,):raise C09PagedCaptureHold('actual natural Core obligation EOF insert fence differs')
    for kind,definitions in (('table',CAPTURE_DDLS_V2.items()),('trigger',CAPTURE_TRIGGERS_V2)):
        for name,ddl in definitions:
            row=_read_one(db,"SELECT sql FROM sqlite_master WHERE type=? AND name=?",(kind,name),meter)
            if row is None and install:
                _write(db,ddl,(),meter)
            elif row!=(ddl,):raise C09PagedCaptureHold('actual sparse obligation capture schema differs')

def _obligation_control_v4(session,builder):
    from .c09_paged_capture_control_v2 import C09PagedCaptureSessionV2
    from .c09_authority_storage_rebase_v2 import _InstalledAuthorityRoleBuilderV2
    if (type(session) is not C09PagedCaptureSessionV2 or type(builder) is not _InstalledAuthorityRoleBuilderV2
            or builder.session is not session or builder.transform.role!='core' or builder.basis.pair is not builder.pair):
        raise C09PagedCaptureHold('actual installed same-session Core obligation producer required')
    session.require_current();builder.require_current()
    return session._control.maintenance.control

def record_source_qualified_natural_final_core_row_v4(reader,*,meter):
    """Only an actual completed semantic reader supplies its just-qualified row."""
    from .c09_natural_final_authority_v3 import NaturalFinalAuthorityOriginalReadV3
    from .c09_paged_recovery_facts_v2 import _read_one
    if type(reader) is NaturalFinalAuthorityOriginalReadV3:
        if reader.phase!='obligations' or not reader.required_core_rows:raise C09PagedCaptureHold('actual Owner/fence Source qualification required')
        builder=reader.builder;value=reader.required_core_rows[-1];source=reader.source
    elif type(reader) is NaturalFinalHistoricalPermissionsReadV4:
        if reader.phase!='core_effect' or reader.core_reader is None or not reader.core_reader.complete:raise C09PagedCaptureHold('actual Core effect Source qualification required')
        builder=reader.capture.builder;value=reader.core_reader.obligation;source=reader.source
    else:raise C09PagedCaptureHold('actual final Source semantic reader required')
    control=_obligation_control_v4(builder.session,builder)
    if value['core_source_original_digest']!=builder.pair.source_original.role_source_digest or value['scope_digest']!=builder.scope.scope_digest:
        raise C09PagedCaptureHold('natural Core obligation Source identity changed')
    normalized={key:item for key,item in value.items() if key not in {'operation_id','fence_token'}}
    raw=_encode(source,normalized,meter).decode('ascii');digest=sha256(raw.encode('ascii')).hexdigest();meter.charge_encode(len(raw))
    key=(builder.scope.scope_digest,value['table'],value['key_digest']);edge=(*key,value['operation_id'],value['fence_token'])
    with control._db(write=True) as db:
        require_natural_final_core_obligation_schema_v4(db,meter=meter,install=True)
        closed=_read_one(db,'SELECT progress_json FROM c09_natural_final_core_progress_v4 WHERE scope_digest=? AND family=?',(builder.scope.scope_digest,'source_closed'),meter)
        if closed is not None:raise C09PagedCaptureHold('actual canonical Source EOF already froze natural Core obligations')
        old=_read_one(db,'SELECT source_json,source_commitment FROM c09_natural_final_core_required_v4 WHERE scope_digest=? AND table_name=? AND key_digest=?',key,meter)
        if old is None:_write(db,'INSERT INTO c09_natural_final_core_required_v4 VALUES(?,?,?,?,?)',(*key,raw,digest),meter)
        elif old!=(raw,digest):raise C09PagedCaptureHold('natural Core Source obligation replay changed')
        prior=_read_one(db,'SELECT operation_id FROM c09_natural_final_core_consumers_v4 WHERE scope_digest=? AND table_name=? AND key_digest=? AND operation_id=? AND fence_token=?',edge,meter)
        if prior is None:_write(db,'INSERT INTO c09_natural_final_core_consumers_v4 VALUES(?,?,?,?,?)',edge,meter)
    builder.require_current()

def _require_core_obligation_arena_v4(arena,extra=0):
    from ..runtime.c09_paged_sql_v2 import current_c09_sql_meter_v2
    meter=current_c09_sql_meter_v2()
    if sum(v._source_heap_bytes() for v in arena)+extra>meter.budget.reserved_arena_bytes:
        raise C09PagedCaptureHold('actual Core obligation reader/copy exceeds shared reserved arena')

class _NaturalCoreObligationStateV4:
    def _source_heap_bytes(self):
        return sys.getsizeof(self.__dict__)+sum(_heap(v) for k,v in self.__dict__.items() if k not in {'session','builder','control','arena','proof','basis'})+8192
    def require_arena(self,extra=0):_require_core_obligation_arena_v4(self.arena,extra)
    def copy(self):
        self.require_arena(self._source_heap_bytes());result=copy(self)
        for name,value in self.__dict__.items():
            if type(value) in (dict,list,set,bytearray):setattr(result,name,copy(value))
        self.arena.add(result);return result
    def _encoded(self,value,meter):return _encode(self,value,meter).decode('ascii')

def _next_core_obligation_row_v4(owner,db,scope,family,last,meter,*,cold_digest):
    from .c09_paged_recovery_facts_v2 import _read_one
    if family=='consumers':
        args=(scope,*(last or ('','','','')))
        row=_read_one(db,'SELECT table_name,key_digest,operation_id,fence_token FROM c09_natural_final_core_consumers_v4 WHERE scope_digest=? AND (table_name,key_digest,operation_id,fence_token)>(?,?,?,?) ORDER BY table_name,key_digest,operation_id,fence_token LIMIT 1',args,meter)
        if row is None:return None
        raw=owner._encoded(row,meter);return tuple(row),sha256(raw.encode('ascii')).hexdigest()
    table='c09_natural_final_core_'+family+'_v4'
    row=_read_one(db,'SELECT table_name,key_digest,source_commitment FROM '+table+' WHERE scope_digest=? AND (table_name,key_digest)>(?,?) ORDER BY table_name,key_digest LIMIT 1',(scope,*(last or ('',''))),meter)
    if row is not None and family=='fulfilled':
        original=_read_one(db,'SELECT source_json,source_commitment FROM c09_natural_final_core_required_v4 WHERE scope_digest=? AND table_name=? AND key_digest=?',(scope,*row[:2]),meter)
        target=_read_one(db,'SELECT target_commitment,cold_digest FROM c09_natural_final_core_fulfilled_v4 WHERE scope_digest=? AND table_name=? AND key_digest=?',(scope,*row[:2]),meter)
        if (original is None or original[1]!=row[2] or sha256(original[0].encode('ascii')).hexdigest()!=row[2]
                or target!=(json.loads(original[0])['expected_target_row_commitment'],cold_digest)):
            raise C09PagedCaptureHold('actual full fulfilled Core row/source/cold binding differs')
    return None if row is None else (row[:2],row[2])

def _core_obligation_stream_identity_v4(owner,scope,source_digest,family,meter):
    from ..runtime.c09_paged_capture_contract_v2 import C09StreamIdentityV2
    keys=('table_name','key_digest','operation_id','fence_token') if family=='consumers' else ('table_name','key_digest')
    return C09StreamIdentityV2(scope,source_digest,'control_metadata','natural_final_core_'+family+'_v4',
        sha256(owner._encoded((family,_CORE_OBLIGATION_TABLES_V4['c09_natural_final_core_'+family+'_v4'],keys),meter).encode('ascii')).hexdigest(),keys,('text',)*len(keys))

class NaturalFinalCoreObligationStreamSealReadV4(_NaturalCoreObligationStateV4):
    """Independent real keyset census and data EOF over one sparse Control family."""
    def __init__(self,token,session,builder,family):
        if token is not _CORE_OBLIGATION_TOKEN_V4 or family not in {'required','consumers','fulfilled'}:raise TypeError('installed natural Core stream issuer required')
        self.session=session;self.builder=builder;self.control=_obligation_control_v4(session,builder);self.family=family
        self.arena=session._source_parser_arena_v3;self.arena.add(self);self.complete=False;self.summary=None
    def _next(self,db,last,meter):
        cold_digest=self.builder.cold.root if self.family=='fulfilled' else None
        return _next_core_obligation_row_v4(self,db,self.builder.scope.scope_digest,self.family,last,meter,cold_digest=cold_digest)
    def _stream(self,meter):
        return _core_obligation_stream_identity_v4(self,self.builder.scope.scope_digest,self.builder.pair.source_original.role_source_digest,self.family,meter)
    def advance(self,meter):
        from .c09_paged_recovery_facts_v2 import _read_one
        from ..runtime.c09_paged_capture_contract_v2 import (C09CountOriginalV2,C09PageCursorV2,C09CaptureRecordV2,
            C09CompleteStreamV2,append_c09_page_v2,seal_c09_stream_v2,c09_paged_value_from_wire_v2)
        from ..runtime.c09_paged_sql_v2 import begin_capture_stream_v2
        self.builder.require_current();result=self.copy();stream=result._stream(meter)
        scope=result.builder.scope.scope_digest
        with result.control._db(write=True) as db:
            require_natural_final_core_obligation_schema_v4(db,meter=meter,install=True);begin_capture_stream_v2(db,stream)
            sealed=_read_one(db,'SELECT seal_json,matching_root,record_count FROM c09_natural_final_core_seals_v4 WHERE scope_digest=? AND family=?',(scope,result.family),meter)
            if sealed is not None:
                result.summary={'family':result.family,'stream':json.loads(result._encoded(asdict(stream),meter)),'seal':json.loads(sealed[0]),'matching_root':sealed[1],'record_count':sealed[2]};result.complete=True;return result
            saved=_read_one(db,'SELECT progress_json FROM c09_natural_final_core_progress_v4 WHERE scope_digest=? AND family=?',(scope,result.family),meter)
            seed=sha256(result._encoded(('natural-final-core-matching.v4',scope,result.builder.pair.source_original.role_source_digest),meter).encode('ascii')).hexdigest()
            state={'phase':'census','count':0,'last':None,'matching_root':seed,'census':None,'data_eof':None} if saved is None else json.loads(saved[0])
            if state['phase']=='census':
                found=result._next(db,None if state['last'] is None else tuple(state['last']),meter)
                if found is None:
                    eof=sha256(result._encoded(('natural-core-census-eof.v4',stream.stream_id,state['count'],state['last'],state['matching_root']),meter).encode('ascii')).hexdigest()
                    census=C09CountOriginalV2(stream.stream_id,state['count'],None if state['last'] is None else tuple(state['last']),eof,
                        'natural-core-count:'+stream.stream_id,sha256(result._encoded((stream.stream_id,state['count'],state['last'],state['matching_root'],eof),meter).encode('ascii')).hexdigest())
                    state['census']=asdict(census);state['phase']='data'
                else:
                    key,commitment=found;state['count']+=1;state['last']=key
                    state['matching_root']=sha256(result._encoded(('natural-final-core-matching.v4',state['matching_root'],state['count'],key,commitment),meter).encode('ascii')).hexdigest()
            else:
                raw=_read_one(db,"SELECT progress_json FROM c09_capture_progress_v2 WHERE stream_id=? AND phase='data'",(stream.stream_id,),meter)
                data=json.loads(raw[0]);cursor=c09_paged_value_from_wire_v2(data['cursor'],C09PageCursorV2)
                found=result._next(db,cursor.last_key,meter)
                if found is None:
                    state['data_eof']=sha256(result._encoded(('natural-core-data-eof.v4',stream.stream_id,cursor.record_offset,cursor.last_key),meter).encode('ascii')).hexdigest()
                    census=c09_paged_value_from_wire_v2(state['census'],C09CountOriginalV2)
                    seal=seal_c09_stream_v2(stream,cursor,census,data_eof_observation_digest=state['data_eof'])
                    _write(db,"UPDATE c09_capture_streams_v2 SET status='sealed',seal_json=? WHERE stream_id=?",(result._encoded(asdict(seal),meter),stream.stream_id),meter)
                    _write(db,'INSERT INTO c09_natural_final_core_seals_v4 VALUES(?,?,?,?,?,?)',(scope,result.family,result._encoded(asdict(stream),meter),result._encoded(asdict(seal),meter),state['matching_root'],state['count']),meter)
                    state['phase']='sealed';result.summary={'family':result.family,'stream':json.loads(result._encoded(asdict(stream),meter)),'seal':json.loads(result._encoded(asdict(seal),meter)),'matching_root':state['matching_root'],'record_count':state['count']};result.complete=True
                else:
                    key,commitment=found;record=C09CaptureRecordV2(key,commitment);page=append_c09_page_v2(stream,cursor,(record,))
                    _write(db,'INSERT INTO c09_capture_pages_v2 VALUES(?,?,?,?)',(stream.stream_id,page.page_index,result._encoded(asdict(page),meter),result._encoded((asdict(record),),meter)),meter)
                    _write(db,'INSERT INTO c09_capture_members_v2 VALUES(?,?,?,?,?,?)',(stream.stream_id,cursor.record_offset+1,sha256(result._encoded(key,meter).encode('ascii')).hexdigest(),result._encoded(key,meter),commitment,page.page_index),meter)
                    cursor=page.next_cursor
                data.update(cursor=asdict(cursor),eof=state['data_eof'])
                _write(db,"UPDATE c09_capture_progress_v2 SET progress_json=? WHERE stream_id=? AND phase='data'",(result._encoded(data,meter),stream.stream_id),meter)
            if saved is None:_write(db,'INSERT INTO c09_natural_final_core_progress_v4 VALUES(?,?,?)',(scope,result.family,result._encoded(state,meter)),meter)
            else:_write(db,'UPDATE c09_natural_final_core_progress_v4 SET progress_json=? WHERE scope_digest=? AND family=?',(result._encoded(state,meter),scope,result.family),meter)
        result.builder.require_current();result.require_arena();return result

class NaturalFinalCoreRequiredSealReadV4(_NaturalCoreObligationStateV4):
    def __init__(self,token,session,builder):
        if token is not _CORE_OBLIGATION_TOKEN_V4:raise TypeError('actual natural Core source seal factory required')
        self.session=session;self.builder=builder;self.control=_obligation_control_v4(session,builder);self.index=0;self.reader=None;self.complete=False;self.required_summary={}
        self.arena=session._source_parser_arena_v3;self.arena.add(self)
    def advance(self,meter):
        result=self.copy()
        if result.index==2:
            result.control.record_build_original_v1(operation_id=result.builder.scope.operation_id,kind='natural_final_core_required_complete_v4',details=result.required_summary)
            result.complete=True;return result
        family=('required','consumers')[result.index]
        if result.reader is None:result.reader=NaturalFinalCoreObligationStreamSealReadV4(_CORE_OBLIGATION_TOKEN_V4,result.session,result.builder,family)
        elif not result.reader.complete:result.reader=result.reader.advance(meter)
        else:result.required_summary[family]=result.reader.summary;result.reader=None;result.index+=1
        return result

def begin_natural_final_core_required_seal_v4(session,core_builder,*,meter):
    control=_obligation_control_v4(session,core_builder)
    from .c09_paged_recovery_facts_v2 import _read_one
    row=_read_one(core_builder.pair.candidate,'SELECT phase FROM authority_c09_role_build_v2 WHERE scope_digest=? AND role=?',(core_builder.scope.scope_digest,'core'),meter)
    post_source={'suffix_begin','suffix_census','suffix_rows','suffix_seal','finish_execution_facts','finish_unknown','generated','next_target','target_census','target_rows','target_seal','integrity','cold','file_hash','complete','stream_directory_begin','stream_directory_census','stream_directory_rows','stream_directory_seal','deferred_schema'}
    if row is None or row[0] not in post_source:raise C09PagedCaptureHold('natural Core required seal needs actual complete canonical Source table scan')
    with control._db(write=True) as db:
        require_natural_final_core_obligation_schema_v4(db,meter=meter,install=True)
        saved=_read_one(db,'SELECT progress_json FROM c09_natural_final_core_progress_v4 WHERE scope_digest=? AND family=?',(core_builder.scope.scope_digest,'source_closed'),meter)
        if saved is None:_write(db,'INSERT INTO c09_natural_final_core_progress_v4 VALUES(?,?,?)',(core_builder.scope.scope_digest,'source_closed',canonical_serialize({'core_source_original_digest':core_builder.pair.source_original.role_source_digest})),meter)
    return NaturalFinalCoreRequiredSealReadV4(_CORE_OBLIGATION_TOKEN_V4,session,core_builder)

class _NaturalFinalCoreObligationStreamReadV4(_NaturalCoreObligationStateV4):
    def __init__(self,token,session,builder,summary):
        if token is not _CORE_OBLIGATION_TOKEN_V4:raise TypeError('actual sparse Core obligation verifier required')
        from ..runtime.c09_paged_capture_contract_v2 import C09StreamIdentityV2,C09CompleteStreamV2,c09_paged_value_from_wire_v2,begin_c09_stream_v2
        self.session=session;self.builder=builder;self.control=_obligation_control_v4(session,builder)
        self.scope_digest=builder.scope.scope_digest;self.source_digest=builder.pair.source_original.role_source_digest;self.cold_digest=builder.cold.root
        self.summary=summary;self.family=summary['family'];self.stream=c09_paged_value_from_wire_v2(summary['stream'],C09StreamIdentityV2)
        self.seal=c09_paged_value_from_wire_v2(summary['seal'],C09CompleteStreamV2);self.cursor=begin_c09_stream_v2(self.stream)
        if (self.stream.scope_digest!=builder.scope.scope_digest or self.stream.role_source_digest!=builder.pair.source_original.role_source_digest
                or self.stream.family!='natural_final_core_'+self.family+'_v4' or self.seal.stream_id!=self.stream.stream_id):
            raise C09PagedCaptureHold('actual sparse Core obligation stream crossed source/scope')
        self.page=None;self.records=();self.index=0;self.last=None;self.count=0;self.matching_root=None;self.complete=False
        self.arena=session._source_parser_arena_v3;self.arena.add(self)
    def advance(self,meter):
        self.builder.require_current()
        with self.control._db() as db:result=self._advance_database(db,meter)
        self.builder.require_current();return result
    def _advance_database(self,db,meter):
        from .c09_paged_recovery_facts_v2 import _read_one
        from ..runtime.c09_paged_sql_v2 import read_capture_page_v2,require_c09_capture_member_v2
        from ..runtime.c09_paged_capture_contract_v2 import verify_c09_page_v2,verify_c09_complete_stream_v2,C09CountOriginalV2,c09_paged_value_from_wire_v2
        result=self.copy()
        if result.matching_root is None:
            result.matching_root=sha256(result._encoded(('natural-final-core-matching.v4',result.scope_digest,result.source_digest),meter).encode('ascii')).hexdigest()
        require_natural_final_core_obligation_schema_v4(db,meter=meter)
        sealed=_read_one(db,'SELECT identity_json,status,seal_json FROM c09_capture_streams_v2 WHERE stream_id=?',(result.stream.stream_id,),meter)
        actual=_read_one(db,'SELECT stream_json,seal_json,matching_root,record_count FROM c09_natural_final_core_seals_v4 WHERE scope_digest=? AND family=?',(result.scope_digest,result.family),meter)
        if (sealed is None or actual is None or sealed[1]!='sealed' or json.loads(sealed[0])!=result.summary['stream']
                or json.loads(sealed[2])!=result.summary['seal'] or json.loads(actual[0])!=result.summary['stream']
                or json.loads(actual[1])!=result.summary['seal'] or actual[2:]!=(result.summary['matching_root'],result.summary['record_count'])
                or _core_obligation_stream_identity_v4(result,result.scope_digest,result.source_digest,result.family,meter)!=result.stream):
            raise C09PagedCaptureHold('actual sparse Core sealed stream/index/schema original differs')
        found=_next_core_obligation_row_v4(result,db,result.scope_digest,result.family,result.last,meter,cold_digest=result.cold_digest)
        if result.cursor.page_index==result.seal.page_count:
            if found is not None or result.count!=result.summary['record_count'] or result.matching_root!=result.summary['matching_root']:
                raise C09PagedCaptureHold('actual sparse Core obligation keyset/EOF/root/count differs')
            saved=_read_one(db,'SELECT progress_json FROM c09_natural_final_core_progress_v4 WHERE scope_digest=? AND family=?',(result.scope_digest,result.family),meter)
            state=json.loads(saved[0]);census=c09_paged_value_from_wire_v2(state['census'],C09CountOriginalV2)
            verify_c09_complete_stream_v2(result.stream,result.cursor,census,result.seal,data_eof_observation_digest=state['data_eof'])
            for sql,args in (("SELECT 1 FROM c09_capture_pages_v2 WHERE stream_id=? AND page_index>=? LIMIT 1",(result.stream.stream_id,result.seal.page_count)),
                ("SELECT 1 FROM c09_capture_members_v2 WHERE stream_id=? AND record_ordinal>? LIMIT 1",(result.stream.stream_id,result.seal.record_count))):
                if _read_one(db,sql,args,meter) is not None:raise C09PagedCaptureHold('sparse Core obligation has unsealed extra capture members')
            result.complete=True;return result
        if result.page is None:
            result.page,result.records=read_capture_page_v2(db,result.stream,result.cursor.page_index);result.index=0;return result
        record=result.records[result.index]
        if found!=(record.primary_key,record.commitment):raise C09PagedCaptureHold('sparse Core obligation page omitted/reordered/changed actual row')
        ordinal=result.cursor.record_offset+result.index+1
        require_c09_capture_member_v2(db,result.stream,ordinal,record.primary_key,record.commitment,meter=meter)
        result.count+=1;result.last=record.primary_key
        result.matching_root=sha256(result._encoded(('natural-final-core-matching.v4',result.matching_root,result.count,record.primary_key,record.commitment),meter).encode('ascii')).hexdigest()
        result.index+=1
        if result.index==len(result.records):
            result.cursor=verify_c09_page_v2(result.stream,result.cursor,result.page,result.records);result.page=None;result.records=();result.index=0
        result.require_arena();return result

class VerifiedNaturalFinalCoreObligationsV4:
    """Private proof issued only by current Source/target/EOF verification."""
    def __init__(self,token,*,reader,summary,completion_original_digest):
        if token is not _CORE_OBLIGATION_TOKEN_V4 or type(reader) is not NaturalFinalCoreObligationsVerificationReadV4 or reader.phase!='issue':
            raise TypeError('actual complete natural Core obligation verification issuer required')
        from pathlib import Path
        self.session=reader.session;self.builder=reader.builder;self.control=reader.control;self.summary=summary;self.completion_original_digest=completion_original_digest;self.consumed_prepared_digest=None
        self.target_path=reader.builder.pair.target_path
        stat=Path(self.target_path).stat();self.target_file_identity=(stat.st_dev,stat.st_ino)
        self.cold_digest=reader.builder.cold.root
        _CORE_OBLIGATION_PROOFS_V4.add(self)
    def require_for(self,session):
        if self not in _CORE_OBLIGATION_PROOFS_V4 or self.session is not session:raise C09PagedCaptureHold('private actual natural Core obligation proof required')
        session.require_current()
        from pathlib import Path
        stat=Path(self.target_path).stat()
        if ((stat.st_dev,stat.st_ino)!=self.target_file_identity
                or self.summary['cold_digest']!=self.cold_digest):raise C09PagedCaptureHold('actual Core obligation target identity/cold root changed')
        original=self.control.read_build_original_v1(operation_id=session.scope.operation_id,kind='natural_final_core_obligations_complete_v4')
        if original is None or original['details']!=self.summary or original['original_digest']!=self.completion_original_digest or self.summary['scope_digest']!=session.scope.scope_digest:
            raise C09PagedCaptureHold('actual signed natural Core obligation completion changed')
        return self
    def consume_committed_for(self,session,*,prepared_digest):
        """Acknowledge only this actual committed V3 PREPARED; mint no permission."""
        from pathlib import Path
        from .c09_paged_capture_control_v2 import C09PagedCaptureSessionV2
        from .c09_control_chain_read_v2 import VerifiedC09ControlChainV2
        from .c09_paged_recovery_facts_v2 import _read_one
        from ..runtime.c09_paged_sql_v2 import require_c09_reserved_meter_v3,current_c09_sql_meter_v2
        if self not in _CORE_OBLIGATION_PROOFS_V4 or type(session) is not C09PagedCaptureSessionV2 or self.session is not session:
            raise C09PagedCaptureHold('actual same-session committed Core obligations proof required')
        current_meter=current_c09_sql_meter_v2();meter=require_c09_reserved_meter_v3(current_meter.budget);control=self.control;control.lease.require_held();scope=session.scope
        chain=control._c09_control_chain_proof_v2
        if type(chain) is not VerifiedC09ControlChainV2 or chain.control is not control:
            raise C09PagedCaptureHold('actual complete private Control chain required for committed consumption')
        stat=Path(self.target_path).stat()
        if (stat.st_dev,stat.st_ino)!=self.target_file_identity:raise C09PagedCaptureHold('actual Core obligation target inode changed')
        with control._db() as db:
            current=chain.require_current(db,meter)
            if (current['stage']!='PREPARED' or current['active_operation_id']!=scope.operation_id
                    or current['pointer_version']!=scope.expected_pointer_version or current['current_manifest_digest']!=scope.old_manifest_digest):
                raise C09PagedCaptureHold('Core proof consumption requires this actual committed PREPARED predecessor')
            row=_read_one(db,'SELECT installation_id,namespace,generation,expected_pointer_version,old_manifest_digest,new_manifest_digest,prepared_digest,prepared_original_json FROM c09_storage_operations_v3 WHERE operation_id=?',(scope.operation_id,),meter)
            if (row is None or row[:5]!=(scope.installation_id,scope.authority_namespace,scope.maintenance_generation,scope.expected_pointer_version,scope.old_manifest_digest)
                    or row[6]!=prepared_digest):raise C09PagedCaptureHold('actual V3 PREPARED row/scope/digest differs')
            _require_core_obligation_arena_v4(session._source_parser_arena_v3,len(row[7].encode('utf-8'))*16+32768)
            prepared=json.loads(row[7]);control.verify_original_v1(prepared,'prepared_digest')
            if (prepared['prepared_digest']!=prepared_digest or prepared['operation_id']!=scope.operation_id
                    or prepared['authority_id']!=scope.authority_id or prepared['installation_id']!=scope.installation_id
                    or prepared['namespace']!=scope.authority_namespace or prepared['maintenance_generation']!=scope.maintenance_generation
                    or prepared['capture_scope_digest']!=scope.scope_digest or prepared['old_manifest_digest']!=scope.old_manifest_digest
                    or prepared['expected_pointer_version']!=scope.expected_pointer_version or prepared['new_manifest_digest']!=row[5]
                    or prepared['natural_core_obligations_complete_original_digest']!=self.completion_original_digest):
                raise C09PagedCaptureHold('signed PREPARED does not bind this actual Core obligation completion')
            completion=control._build_original_locked(db,scope.operation_id,'natural_final_core_obligations_complete_v4')
            core=control._build_original_locked(db,scope.operation_id,'capture_role_complete_v2_core')
            if (completion is None or completion['original_digest']!=self.completion_original_digest or completion['details']!=self.summary
                    or core is None or core['original_digest']!=prepared['four_role_complete_original_digests']['core']
                    or core['details']['scope_digest']!=scope.scope_digest
                    or core['details']['cold_digest']!=self.cold_digest or self.summary['cold_digest']!=self.cold_digest
                    or core['details']['source_original']['role_source_digest']!=self.summary['core_source_original_digest']
                    or core['details']['target_path']!=self.target_path or tuple(core['details']['target_file_identity'])[:2]!=self.target_file_identity
                    or self.summary['scope_digest']!=scope.scope_digest or self.summary['pending_count']!=0):
                raise C09PagedCaptureHold('committed PREPARED Core source/cold/target/signed completion differs')
            manifest=_read_one(db,'SELECT installation_id,generation FROM c09_storage_manifests_v1 WHERE manifest_digest=?',(row[5],),meter)
            if manifest!=(scope.installation_id,scope.maintenance_generation):raise C09PagedCaptureHold('actual committed new manifest storage generation differs')
        if self.consumed_prepared_digest is not None and self.consumed_prepared_digest!=prepared_digest:
            raise C09PagedCaptureHold('Core obligation proof belongs to another committed PREPARED')
        self.consumed_prepared_digest=prepared_digest
        return dict(self.summary)

class NaturalFinalCoreObligationsVerificationReadV4(_NaturalCoreObligationStateV4):
    def __init__(self,token,session,builder):
        if token is not _CORE_OBLIGATION_TOKEN_V4:raise TypeError('actual Core target verification factory required')
        self.session=session;self.builder=builder;self.control=_obligation_control_v4(session,builder)
        original=self.control.read_build_original_v1(operation_id=builder.scope.operation_id,kind='natural_final_core_required_complete_v4')
        if original is None:raise C09PagedCaptureHold('actual sealed natural Core required Source inventory absent')
        self.required=original['details'];self.phase='required';self.reader=None;self.last=None;self.fulfilled=None;self.complete=False;self.proof=None;self.target_reader=None;self.target_row=None
        self.arena=session._source_parser_arena_v3;self.arena.add(self)
    def advance(self,meter):
        from .c09_paged_recovery_facts_v2 import _read_one
        result=self.copy();result.builder.require_current();scope=result.builder.scope.scope_digest
        if result.phase in {'required','consumers','fulfilled'}:
            summary=result.required[result.phase] if result.phase!='fulfilled' else result.fulfilled
            if result.reader is None:result.reader=_NaturalFinalCoreObligationStreamReadV4(_CORE_OBLIGATION_TOKEN_V4,result.session,result.builder,summary)
            elif not result.reader.complete:result.reader=result.reader.advance(meter)
            else:result.reader=None;result.phase={'required':'consumers','consumers':'targets','fulfilled':'issue'}[result.phase]
            return result
        if result.phase=='targets':
            if result.target_row is not None:
                row=result.target_row;value=json.loads(row[2])
                if result.target_reader is None:
                    result.target_reader=_NaturalFinalCoreRowCommitmentReadV4(_CORE_OBLIGATION_TOKEN_V4,result.builder,value['table'],value['primary_key'],result.arena,target=True);return result
                if not result.target_reader.complete:
                    result.target_reader=result.target_reader.advance(meter);result.require_arena();return result
                target=fulfil_natural_final_core_row_obligation_v4(result.builder,value,meter=meter,row_reader=result.target_reader)
                saved=(scope,*row[:2],row[3],target['fulfilled_target_commitment'],target['cold_digest'])
                with result.control._db(write=True) as db:
                    old=_read_one(db,'SELECT source_commitment,target_commitment,cold_digest FROM c09_natural_final_core_fulfilled_v4 WHERE scope_digest=? AND table_name=? AND key_digest=?',saved[:3],meter)
                    if old is None:_write(db,'INSERT INTO c09_natural_final_core_fulfilled_v4 VALUES(?,?,?,?,?,?)',saved,meter)
                    elif old!=saved[3:]:raise C09PagedCaptureHold('required Core target fulfil replay changed')
                result.last=row[:2];result.target_reader=None;result.target_row=None;return result
            with result.control._db() as db:
                row=_read_one(db,'SELECT table_name,key_digest,source_json,source_commitment FROM c09_natural_final_core_required_v4 WHERE scope_digest=? AND (table_name,key_digest)>(?,?) ORDER BY table_name,key_digest LIMIT 1',(scope,*(result.last or ('',''))),meter)
                if row is not None:
                    if sha256(row[2].encode('ascii')).hexdigest()!=row[3]:raise C09PagedCaptureHold('actual required Core row descriptor differs')
                    consumer=_read_one(db,'SELECT operation_id FROM c09_natural_final_core_consumers_v4 WHERE scope_digest=? AND table_name=? AND key_digest=? LIMIT 1',(scope,*row[:2]),meter)
                    if consumer is None:raise C09PagedCaptureHold('required Core row lacks actual final consumer')
            if row is None:result.phase='seal_fulfilled';result.reader=None;return result
            result.target_row=row;return result
        if result.phase=='seal_fulfilled':
            if result.reader is None:result.reader=NaturalFinalCoreObligationStreamSealReadV4(_CORE_OBLIGATION_TOKEN_V4,result.session,result.builder,'fulfilled')
            elif not result.reader.complete:result.reader=result.reader.advance(meter)
            else:
                result.fulfilled=result.reader.summary;result.reader=None
                if (result.fulfilled['matching_root'],result.fulfilled['record_count'])!=(result.required['required']['matching_root'],result.required['required']['record_count']):
                    raise C09PagedCaptureHold('natural Core required/fulfilled roots or counts differ')
                result.phase='fulfilled'
            return result
        if result.phase=='issue':
            summary={'scope_digest':scope,'core_source_original_digest':result.builder.pair.source_original.role_source_digest,
                'required':result.required['required'],'consumers':result.required['consumers'],'fulfilled':result.fulfilled,
                'cold_digest':result.builder.cold.root,'pending_count':0}
            # Both complete real EOF walks proved identical keysets. A pending
            # count of zero is their consequence, never caller input or COUNT.
            original=result.control.record_build_original_v1(operation_id=result.builder.scope.operation_id,kind='natural_final_core_obligations_complete_v4',details=summary)
            if original['details']!=summary:raise C09PagedCaptureHold('natural Core signed completed obligations differ')
            result.proof=VerifiedNaturalFinalCoreObligationsV4(_CORE_OBLIGATION_TOKEN_V4,reader=result,summary=summary,completion_original_digest=original['original_digest']);result.complete=True;return result
        raise C09PagedCaptureHold('unknown actual natural Core obligation verification phase')

def begin_natural_final_core_obligations_verification_v4(session,core_builder,*,meter):
    _obligation_control_v4(session,core_builder)
    if (core_builder.cold is None or not core_builder.cold.directory_checked or core_builder.cold.active is not None
            or (core_builder.cold_position_v3 or core_builder._pending_cold_position_v3) is None
            or (core_builder.cold_position_v3 or core_builder._pending_cold_position_v3)['cold_digest']!=core_builder.cold.root):
        raise C09PagedCaptureHold('actual Core completed cold sweep required before natural target obligations')
    return NaturalFinalCoreObligationsVerificationReadV4(_CORE_OBLIGATION_TOKEN_V4,session,core_builder)
_SELECTED_CORE_OBLIGATION_PROOFS_V4=WeakSet()
_NATURAL_CORE_REQUIRED_TABLES_V4=frozenset(('authority_v2_fences','authority_owner_issue_committed_v1',
    'authority_owner_issue_pending_v1','authority_owner_claim_tickets_v1','authority_natural_final_observations_v4'))

class _SelectedNaturalCoreRowReadV4(_NaturalFinalCoreRowCommitmentReadV4):
    def __init__(self,token,owner,table,key):
        if token is not _CORE_OBLIGATION_TOKEN_V4 or type(owner) is not _SelectedNaturalCoreObligationsReadV4:
            raise TypeError('actual selected natural Core row issuer required')
        self._issuer=token;self.basis=owner.basis;self.table=table;self.key=tuple(key);self.target=True;self.arena=owner.arena
        self.shape=None;self.column=0;self.kind=None;self.total=None;self.offset=0;self.decoder=None
        self.digest=sha256();self.complete=False;self.commitment=None;self.arena.add(self)
    def advance(self,meter):
        self.basis.require_current(meter=meter)
        with self.basis.read_database('core',meter=meter) as db:result=self._advance_database(db,meter)
        result.require_arena();return result

class _SelectedNaturalCoreControlStreamReadV4(_NaturalFinalCoreObligationStreamReadV4):
    def __init__(self,token,owner,summary):
        if token is not _CORE_OBLIGATION_TOKEN_V4 or type(owner) is not _SelectedNaturalCoreObligationsReadV4:
            raise TypeError('actual selected sparse Control stream issuer required')
        from ..runtime.c09_paged_capture_contract_v2 import C09StreamIdentityV2,C09CompleteStreamV2,c09_paged_value_from_wire_v2,begin_c09_stream_v2
        self.basis=owner.basis;self.control=owner.control;self.arena=owner.arena
        self.scope_digest=owner.scope.scope_digest;self.source_digest=owner.source_digest;self.cold_digest=owner.summary['cold_digest']
        self.summary=summary;self.family=summary['family'];self.stream=c09_paged_value_from_wire_v2(summary['stream'],C09StreamIdentityV2)
        self.seal=c09_paged_value_from_wire_v2(summary['seal'],C09CompleteStreamV2);self.cursor=begin_c09_stream_v2(self.stream)
        if (self.stream.scope_digest!=self.scope_digest or self.stream.role_source_digest!=self.source_digest
                or self.stream.family!='natural_final_core_'+self.family+'_v4' or self.seal.stream_id!=self.stream.stream_id):
            raise C09PagedCaptureHold('actual selected sparse Core stream crossed signed Source/scope')
        self.page=None;self.records=();self.index=0;self.last=None;self.count=0;self.matching_root=None;self.complete=False;self.arena.add(self)
    def advance(self,meter):
        self.basis.require_current(meter=meter)
        with self.control._db() as db:result=self._advance_database(db,meter)
        self.basis.require_current(meter=meter);result.require_arena();return result

class _SelectedNaturalCoreSealedMetadataReadV4(_NaturalCoreObligationStateV4):
    """A signed Core directory or disposition stream plus independent actual PK EOF."""
    def __init__(self,token,owner,locator,*,table=None):
        if token is not _CORE_OBLIGATION_TOKEN_V4 or type(owner) is not _SelectedNaturalCoreObligationsReadV4:
            raise TypeError('actual selected sealed Core metadata issuer required')
        from .c09_paged_recovery_facts_v2 import C09HistoricalSealedStreamReaderV2
        self.basis=owner.basis;self.control=owner.control;self.arena=owner.arena;self.scope_digest=owner.scope.scope_digest
        self.locator=locator;self.table=table;self.shape=None;self.last=None;self.count=0;self.phase='census' if table else 'directory'
        if (locator.storage_role!='core' or locator.identity.scope_digest!=self.scope_digest
                or locator.identity.role_source_digest!=owner.source_digest
                or locator.identity.family!=(table or 'authority_c09_role_streams_v2')
                or locator.identity.stream_kind!=('row_dispositions' if table else 'control_metadata')):
            raise C09PagedCaptureHold('selected signed Core metadata stream crossed its exact scope/source/kind')
        self.reader=C09HistoricalSealedStreamReaderV2(locator);self.complete=False;self.arena.add(self)
    def _source_heap_bytes(self):
        return super()._source_heap_bytes()+_heap(self.reader.__dict__)
    def copy(self):
        result=super().copy();result.reader=copy(self.reader);return result
    def _row(self,db,key,meter):
        if self.table is None:
            columns=('scope_digest','role','table_name','stream_kind','stream_json','seal_json')
            row=meter.read_fixed_row(db,'authority_c09_role_streams_v2',columns,'scope_digest=? AND role=? AND table_name=? AND stream_kind=?',key)
            return row
        columns=('scope_digest','role','table_name','key_digest','key_json','old_commitment','disposition','new_commitment')
        return meter.read_fixed_row(db,'authority_c09_role_rows_v2',columns,'scope_digest=? AND role=? AND table_name=? AND key_digest=?',
            (self.scope_digest,'core',self.table,sha256(self._encoded(key,meter).encode('ascii')).hexdigest()))
    def advance(self,meter):
        from .c09_paged_recovery_facts_v2 import _read_one
        result=self.copy();result.basis.require_current(meter=meter)
        with result.basis.read_database('core',meter=meter) as db:
            actual_stream=_read_one(db,'SELECT identity_json,status,seal_json FROM c09_capture_streams_v2 WHERE stream_id=?',(result.locator.identity.stream_id,),meter)
            if (actual_stream is None or actual_stream[1]!='sealed'
                    or json.loads(actual_stream[0])!=json.loads(result._encoded(asdict(result.locator.identity),meter))
                    or json.loads(actual_stream[2])!=json.loads(result._encoded(asdict(result.locator.complete),meter))):
                raise C09PagedCaptureHold('selected actual Core metadata sealed stream/index original differs')
            if result.shape is None:
                if result.table is None:
                    result.shape=read_c09_table_shape_v2(db,'authority_c09_role_streams_v2',meter=meter)
                    if result.shape.schema_digest!=result.locator.identity.schema_digest:raise C09PagedCaptureHold('selected actual Core directory schema differs')
                else:
                    result.shape=read_c09_table_shape_v2(db,result.table,meter=meter)
                    if result.shape.schema_digest!=result.locator.identity.schema_digest:raise C09PagedCaptureHold('selected actual disposition table schema differs')
                return result
            if result.phase=='census':
                row=_read_one(db,'SELECT key_digest,key_json,old_commitment,disposition,new_commitment FROM authority_c09_role_rows_v2 WHERE scope_digest=? AND role=? AND table_name=? AND key_digest>? ORDER BY key_digest LIMIT 1',
                    (result.scope_digest,'core',result.table,result.last or ''),meter)
                if row is None:
                    if result.count!=result.locator.complete.record_count:raise C09PagedCaptureHold('selected actual disposition PK EOF/count differs')
                    result.phase='pages';result.last=None;return result
                key=tuple(json.loads(row[1]));values=(result.scope_digest,'core',result.table,*row)
                expected=sha256(result._encoded(('sylanne3.c09.authority-row-disposition.v2',values),meter).encode('ascii')).hexdigest()
                from ..runtime.c09_paged_sql_v2 import require_c09_capture_member_v2
                member=_read_one(db,'SELECT record_ordinal FROM c09_capture_members_v2 WHERE stream_id=? AND key_digest=?',(result.locator.identity.stream_id,row[0]),meter)
                if member is None or not 1<=member[0]<=result.locator.complete.record_count:raise C09PagedCaptureHold('selected actual disposition index has unsealed row')
                require_c09_capture_member_v2(db,result.locator.identity,member[0],key,expected,meter=meter)
                result.count+=1;result.last=row[0];return result
            def observe(record):
                row=result._row(db,record.primary_key,meter)
                if row is None:raise C09PagedCaptureHold('selected signed Core metadata actual row disappeared')
                if result.table is None:
                    key=tuple(row[:4]);after=result.last or ('','','','')
                    actual=_read_one(db,'SELECT scope_digest,role,table_name,stream_kind FROM authority_c09_role_streams_v2 WHERE (scope_digest,role,table_name,stream_kind)>(?,?,?,?) ORDER BY scope_digest,role,table_name,stream_kind LIMIT 1',after,meter)
                    if actual!=key or record.primary_key!=key or sha256(result._encoded(('sylanne3.c09.authority-directory-row.v2',result.locator.identity.stream_kind,result.shape.table,key,tuple(row)),meter).encode('ascii')).hexdigest()!=record.commitment:
                        raise C09PagedCaptureHold('selected actual Core directory omits/reorders/changes row')
                    result.last=key;result.count+=1
                else:
                    if tuple(json.loads(row[4]))!=record.primary_key or sha256(result._encoded(('sylanne3.c09.authority-row-disposition.v2',tuple(row)),meter).encode('ascii')).hexdigest()!=record.commitment:
                        raise C09PagedCaptureHold('selected actual complete Core disposition record differs')
            if result.reader.advance(db,meter,observe):
                if result.table is None:
                    after=result.last or ('','','','')
                    if (_read_one(db,'SELECT 1 FROM authority_c09_role_streams_v2 WHERE (scope_digest,role,table_name,stream_kind)>(?,?,?,?) LIMIT 1',after,meter) is not None
                            or result.count!=result.locator.complete.record_count):raise C09PagedCaptureHold('selected actual Core directory has unsealed EOF suffix')
                result.complete=True
        result.require_arena();return result

class SelectedNaturalCoreObligationsV4:
    """Private cold proof of persistent actual selected Source/target obligations."""
    def __init__(self,token,reader):
        if token is not _CORE_OBLIGATION_TOKEN_V4 or type(reader) is not _SelectedNaturalCoreObligationsReadV4 or reader.phase!='issue':
            raise TypeError('actual selected complete Core obligation issuer required')
        self.basis=reader.basis;self.preparedref=reader.preparedref;self.summary=reader.summary
        self.selection_digest=reader.basis.selection_digest;self.target_path=reader.core_header['target_path']
        self.target_inode=tuple(reader.core_header['target_file_identity'])[:2];self.core_original_digest=reader.basis.prepared['four_role_complete_original_digests']['core']
        _SELECTED_CORE_OBLIGATION_PROOFS_V4.add(self)
    def require_current(self,*,meter):
        from .c09_prepared_storage_v3 import _read_original
        if self not in _SELECTED_CORE_OBLIGATION_PROOFS_V4 or self.selection_digest!=self.basis.selection_digest:
            raise C09PagedCaptureHold('actual private selected Core obligation proof required')
        self.basis.require_current(meter=meter);member=self.basis.member('core')
        if (member['resolved_path']!=self.target_path or (member['device'],member['file_id'])!=self.target_inode
                or member['cold_read_digest']!=self.summary['cold_digest']
                or self.basis.prepared['natural_core_obligations_complete_original_digest']!=self.preparedref):
            raise C09PagedCaptureHold('selected actual Core source/cold/target binding changed')
        with self.basis.control._db() as db:
            summary=_read_original(self.basis.control,db,self.basis.prepared['operation_id'],'natural_final_core_obligations_complete_v4',self.preparedref,meter)
            if summary!=self.summary:raise C09PagedCaptureHold('selected signed Core obligation original changed')
        return self

class _SelectedNaturalCoreObligationsReadV4(_NaturalCoreObligationStateV4):
    def __init__(self,token,basis,preparedref):
        if token is not _CORE_OBLIGATION_TOKEN_V4:raise TypeError('actual selected natural Core obligation factory required')
        self.basis=basis;self.control=basis.control;self.preparedref=preparedref;self.phase='summary';self.summary=None;self.scope=None
        self.core_header=None;self.source_digest=None;self.reader=None;self.complete=False;self.proof=None;self.last=None;self.row=None;self.target=None
        self.checked_tables=set();self.count=0;self.arena=getattr(basis,'_natural_core_arena_v4',None)
        if self.arena is None:self.arena=WeakSet();basis._natural_core_arena_v4=self.arena
        self.arena.add(self);self.require_arena()
    def advance(self,meter):
        from .c09_paged_recovery_facts_v2 import _read_one
        from .c09_prepared_storage_v3 import _read_original
        from ..runtime.c09_paged_capture_contract_v2 import C09CaptureScopeV2,C09FrozenRoleSourceV2,C09SealedStreamLocatorV2,C09StreamIdentityV2,C09CompleteStreamV2,c09_paged_value_from_wire_v2
        result=self.copy();result.basis.require_current(meter=meter);prepared=result.basis.prepared;operation=prepared['operation_id']
        if result.phase in {'summary','scope','header','required_original'}:
            with result.control._db() as db:
                if result.phase=='summary':
                    result.summary=_read_original(result.control,db,operation,'natural_final_core_obligations_complete_v4',result.preparedref,meter);result.phase='scope'
                elif result.phase=='scope':
                    result.scope=C09CaptureScopeV2(**_read_original(result.control,db,operation,'capture_scope_v2',None,meter))
                    if result.scope.scope_digest!=prepared['capture_scope_digest'] or result.summary['scope_digest']!=result.scope.scope_digest or result.summary['pending_count']!=0:raise C09PagedCaptureHold('selected signed Core obligations have another scope or pending rows')
                    result.phase='header'
                elif result.phase=='header':
                    result.core_header=_read_original(result.control,db,operation,'capture_role_complete_v2_core',prepared['four_role_complete_original_digests']['core'],meter)
                    source=c09_paged_value_from_wire_v2(result.core_header['source_original'],C09FrozenRoleSourceV2);member=result.basis.member('core')
                    if (source.scope_digest!=result.scope.scope_digest or source.role!='core' or result.core_header['scope_digest']!=result.scope.scope_digest
                            or source.role_source_digest!=result.summary['core_source_original_digest'] or result.core_header['cold_digest']!=result.summary['cold_digest']
                            or member['cold_read_digest']!=result.summary['cold_digest'] or result.core_header['target_path']!=member['resolved_path']
                            or tuple(result.core_header['target_file_identity'])[:2]!=(member['device'],member['file_id'])):raise C09PagedCaptureHold('selected signed Core Source/cold/target path/inode differs')
                    result.source_digest=source.role_source_digest;result.phase='required_original'
                else:
                    required=_read_original(result.control,db,operation,'natural_final_core_required_complete_v4',None,meter)
                    if required!={key:result.summary[key] for key in ('required','consumers')}:raise C09PagedCaptureHold('selected Source-qualified complete required inventory differs')
                    if (result.summary['required']['matching_root'],result.summary['required']['record_count'])!=(result.summary['fulfilled']['matching_root'],result.summary['fulfilled']['record_count']):raise C09PagedCaptureHold('selected natural Core required/fulfilled root/count differs')
                    result.phase='directory'
            return result
        if result.phase=='directory':
            if result.reader is None:
                locator=c09_paged_value_from_wire_v2(result.core_header['stream_directory'],C09SealedStreamLocatorV2)
                result.reader=_SelectedNaturalCoreSealedMetadataReadV4(_CORE_OBLIGATION_TOKEN_V4,result,locator)
            elif not result.reader.complete:result.reader=result.reader.advance(meter)
            else:result.reader=None;result.phase='required'
            return result
        if result.phase in {'required','consumers','fulfilled'}:
            if result.reader is None:result.reader=_SelectedNaturalCoreControlStreamReadV4(_CORE_OBLIGATION_TOKEN_V4,result,result.summary[result.phase])
            elif not result.reader.complete:result.reader=result.reader.advance(meter)
            else:result.reader=None;result.phase={'required':'consumers','consumers':'fulfilled','fulfilled':'targets'}[result.phase]
            return result
        if result.phase=='targets':
            if result.row is None:
                with result.control._db() as db:
                    row=_read_one(db,'SELECT table_name,key_digest,source_json,source_commitment FROM c09_natural_final_core_required_v4 WHERE scope_digest=? AND (table_name,key_digest)>(?,?) ORDER BY table_name,key_digest LIMIT 1',(result.scope.scope_digest,*(result.last or ('',''))),meter)
                    if row is None:
                        if result.count!=result.summary['required']['record_count']:raise C09PagedCaptureHold('selected actual required target EOF/count differs')
                        result.phase='issue';return result
                    if row[0] not in _NATURAL_CORE_REQUIRED_TABLES_V4 or sha256(row[2].encode('ascii')).hexdigest()!=row[3]:raise C09PagedCaptureHold('selected required Core original kind/descriptor differs')
                    result.row=row;return result
            value=json.loads(result.row[2]);table=value['table'];key=tuple(value['primary_key'])
            if (set(value)!={'scope_digest','core_source_original_digest','table','schema_digest','primary_key','key_digest','source_row_commitment','required_disposition','expected_target_row_commitment'}
                    or table!=result.row[0] or value['key_digest']!=result.row[1]
                    or value['scope_digest']!=result.scope.scope_digest or value['core_source_original_digest']!=result.source_digest
                    or value['required_disposition']!='preserved_exact' or value['source_row_commitment']!=value['expected_target_row_commitment']
                    or value['key_digest']!=sha256(result._encoded(key,meter).encode('ascii')).hexdigest()):raise C09PagedCaptureHold('selected actual required Core Source identity/full commitment differs')
            if table not in result.checked_tables:
                if result.reader is None:
                    with result.basis.read_database('core',meter=meter) as db:
                        entry=meter.read_fixed_row(db,'authority_c09_role_streams_v2',('stream_json','seal_json'),'scope_digest=? AND role=? AND table_name=? AND stream_kind=?',(result.scope.scope_digest,'core',table,'row_dispositions'))
                        if entry is None or entry[1] is None:raise C09PagedCaptureHold('selected actual required disposition stream absent')
                        identity=c09_paged_value_from_wire_v2(json.loads(entry[0]),C09StreamIdentityV2);seal=c09_paged_value_from_wire_v2(json.loads(entry[1]),C09CompleteStreamV2)
                        if identity.scope_digest!=result.scope.scope_digest or identity.role_source_digest!=result.source_digest or identity.family!=table or identity.stream_kind!='row_dispositions':raise C09PagedCaptureHold('selected actual required disposition stream identity differs')
                    result.reader=_SelectedNaturalCoreSealedMetadataReadV4(_CORE_OBLIGATION_TOKEN_V4,result,C09SealedStreamLocatorV2('core',identity,seal),table=table)
                elif not result.reader.complete:result.reader=result.reader.advance(meter)
                else:result.checked_tables.add(table);result.reader=None
                return result
            if result.target is None:result.target=_SelectedNaturalCoreRowReadV4(_CORE_OBLIGATION_TOKEN_V4,result,table,key);return result
            if not result.target.complete:result.target=result.target.advance(meter);return result
            if result.target.shape.schema_digest!=value['schema_digest']:raise C09PagedCaptureHold('selected actual required Core row logical schema differs')
            with result.basis.read_database('core',meter=meter) as db:
                _verify_core_obligation_disposition_v4(db,value,result.target.shape,result.target.commitment,result.scope.scope_digest,result.source_digest,meter)
            result.count+=1;result.last=result.row[:2];result.row=None;result.target=None;return result
        if result.phase=='issue':
            result.proof=SelectedNaturalCoreObligationsV4(_CORE_OBLIGATION_TOKEN_V4,result);result.complete=True;return result
        raise C09PagedCaptureHold('unknown actual selected natural Core obligation phase')

def begin_selected_natural_core_obligations_read_v4(actualselectedbasis,*,preparedref,meter):
    from .c09_selected_history_v3 import _InstalledSelectedStorageBasisV3
    from ..runtime.c09_paged_sql_v2 import current_c09_sql_meter_v2
    if type(actualselectedbasis) is not _InstalledSelectedStorageBasisV3 or meter is not current_c09_sql_meter_v2():
        raise TypeError('actual selected storage basis and same reserved root required')
    actualselectedbasis.require_current(meter=meter)
    if (type(preparedref) is not str or actualselectedbasis.prepared.get('natural_core_obligations_complete_original_digest')!=preparedref):
        raise C09PagedCaptureHold('selected signed PREPARED lacks its actual natural Core completion original')
    return _SelectedNaturalCoreObligationsReadV4(_CORE_OBLIGATION_TOKEN_V4,actualselectedbasis,preparedref)
