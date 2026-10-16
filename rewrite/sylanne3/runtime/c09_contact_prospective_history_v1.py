"""Frozen Graph-role Contact prospective birth/final joins.

The installed C09 build drains each cell in a separate reserved quantum. This
history proof issues no current Source or execution authority.
"""
import json
from weakref import WeakKeyDictionary
from ..runtime_contracts import NamespaceId,canonical_digest,canonical_serialize
from ..graph_types import AtomKey
from .c09_paged_sql_v2 import (C09PagedCaptureHold,require_c09_reserved_meter_v3,c09_sql_meter_quantum_v2,
    read_c09_table_shape_v2,read_c09_next_row_metadata_v2,begin_c09_row_commitment_v2,
    advance_c09_row_commitment_v2,require_c09_capture_member_v2,read_legacy_sql_cell_fragment_v2)
from .c09_graph_row_codec_v2 import _C09RegisteredGraphValueV3
from .contact_prospective_v1 import (TABLE,COLUMNS,SUCCESSOR_TABLE,SUCCESSOR_COLUMNS,
    read_c09_contact_prospective_row_v1,read_c09_contact_successor_row_v1,
    contact_prospective_barrier_key_v1,contact_prospective_attempt_id_v1,_receipt,_receipt_wire)

_ISSUER=object()
_PROOFS=WeakKeyDictionary()

class _FrozenJSONV1:
    def __init__(self,reader,table,column,key_columns,key,*,cell_id=None,source_metadata=False):
        self.reader,self.table,self.column,self.key_columns,self.key=reader,table,column,tuple(key_columns),tuple(key)
        self.cell_id,self.offset,self.complete=cell_id,0,False
        self.where=' AND '.join(name+'=?'for name in self.key_columns)
        from .c09_graph_row_codec_v2 import C09MemorySourceJSONStreamV3
        self.source_metadata=source_metadata
        self.parser=(C09MemorySourceJSONStreamV3(source_arena=reader.scope.arena,ensure_ascii=True)if source_metadata else
            _C09RegisteredGraphValueV3(source_arena=reader.scope.arena,ensure_ascii=True))
        self.header=None;self.total=None
    def advance(self,meter):
        self.reader.require_current(meter)
        if self.total is None:
            if self.cell_id is None:
                row=self.reader.scope.source.execute('SELECT typeof('+self.column+'),length(CAST('+self.column+
                    ' AS BLOB)) FROM '+self.table+' WHERE '+self.where,self.key).fetchone()
                meter.charge_read(16)
                if row is None or row[0]!='text':raise C09PagedCaptureHold('Contact frozen original actual TEXT absent')
                self.total=row[1]
            else:
                self.header=self.reader.scope.read_cell_header_v3(self.cell_id,meter=meter)
                if self.header[1]!='canonical-json.ascii.v1':
                    raise C09PagedCaptureHold('Contact frozen original canonical physical codec differs')
                self.total=self.header[4]
            return
        if self.offset<self.total:
            if self.cell_id is None:
                block,total,kind=read_legacy_sql_cell_fragment_v2(self.reader.scope.source,table=self.table,
                    column=self.column,where=self.where,parameters=self.key,start=self.offset,
                    length=min(1024,self.total-self.offset),meter=meter)
                if kind!='text':raise C09PagedCaptureHold('Contact frozen original TEXT storage differs')
            else:
                block,total=self.reader.scope.read_cell_fragment_v3(self.cell_id,start=self.offset,
                    length=min(1024,self.total-self.offset),meter=meter)
            if total!=self.total or not block:raise C09PagedCaptureHold('Contact frozen original EOF span differs')
            self.parser.feed(block,lambda event:None);self.offset+=len(block);return
        result=self.parser.finish()
        if result.byte_count!=self.total:raise C09PagedCaptureHold('Contact frozen canonical EOF length differs')
        if self.header is not None:
            if result.sha256!=self.header[6]:raise C09PagedCaptureHold('Contact frozen physical EOF digest differs')
            self.reader.scope.require_cell_eof_v3(self.cell_id,self.header[5],meter=meter)
        self.value,self.digest,self.complete=(dict(self.parser._source_metadata)if self.source_metadata else self.parser.value),result.sha256,True

class ContactProspectiveHistoryReadV1:
    def __init__(self,issuer,build,shape,key,metadata,scope,meter):
        from .c09_graph_rebase_candidate_v2 import InstalledGraphRebaseBuildV2
        from ..authority_service.c09_source_physical_read_v3 import SourcePhysicalReadScopeV3
        if (issuer is not _ISSUER or type(build)is not InstalledGraphRebaseBuildV2
                or type(scope)is not SourcePhysicalReadScopeV3 or scope.session is not build.session
                or scope.pair is not build.pair or scope.role!='graph'
                or scope.source_original is not build.pair.source_original
                or shape.table not in (TABLE,SUCCESSOR_TABLE)):
            raise C09PagedCaptureHold('Contact prospective history requires actual installed captured Graph-role identity')
        self.build,self.scope,self.shape,self.key,self.metadata=build,scope,shape,tuple(key),tuple(metadata)
        self.namespace=NamespaceId(key[0],key[1])
        if self.namespace.as_tuple!=tuple(json.loads(build.scope.graph_namespace)):
            raise C09PagedCaptureHold('Contact prospective history crossed selected namespace')
        columns=COLUMNS if shape.table==TABLE else SUCCESSOR_COLUMNS
        pk=('bot','persona','contact_id')if shape.table==TABLE else ('bot','persona','final_operation_id')
        if shape.columns!=columns or shape.primary_key_columns!=pk:
            raise C09PagedCaptureHold('Contact prospective actual frozen row shape differs')
        self.row_cursor=begin_c09_row_commitment_v2(scope.source,shape,key,metadata)
        self.phase,self.pending,self.complete='row',None,False
        self.values={};self.index=0;self.issuer=build.session.get_c09_domain_original_issuer_v2()
        self.scope.arena.add(self)
    def _source_heap_bytes(self):
        from .source_correction_read_v3 import _heap
        return 65536+_heap((self.values,getattr(self,'raw',None),getattr(self,'domain',None),
            getattr(self,'born',None),getattr(self,'descriptor',None)))
    def require_current(self,meter):
        self.build.require_current();self.scope.require_current(meter=meter)
        if self.scope.source_original is not self.build.pair.source_original:
            raise C09PagedCaptureHold('Contact prospective actual capture Source changed')
    def point(self,meter,table,columns,where,key):
        return meter.read_fixed_row(self.scope.source,table,columns,where,key)
    def advance(self,budget,meter):
        self.require_current(meter)
        if self.phase=='row':
            advance_c09_row_commitment_v2(self.scope.source,self.shape,budget,cursor=self.row_cursor)
            if not self.row_cursor.complete:return
            from .c09_graph_rebase_candidate_v2 import _actual_source_locator_v2
            locator=_actual_source_locator_v2(self.build,self.shape,meter)
            member=meter.read_fixed_row(self.build.pair.candidate,'c09_capture_members_v2',('record_ordinal','commitment'),
                'stream_id=? AND primary_key_json=?',(locator.identity.stream_id,canonical_serialize(self.key)))
            if member is None or member[1]!=self.row_cursor.commitment:
                raise C09PagedCaptureHold('Contact prospective actual independent full row differs from captured member')
            require_c09_capture_member_v2(self.build.pair.candidate,locator.identity,member[0],self.key,member[1],meter=meter)
            self.origin=(locator.identity.stream_id,*member)
            body='payload_json';self.pending=_FrozenJSONV1(self,self.shape.table,body,self.shape.primary_key_columns,self.key)
            self.phase='payload';return
        if self.pending is not None:
            self.pending.advance(meter)
            if not self.pending.complete:return
            task=self.pending;self.pending=None
            if self.phase=='payload':
                self.raw=task.value;self.payload_digest=task.digest;self.phase='decode'
            elif self.phase=='domain_payload':
                self.domain=task.value;self.phase='domain_check'
            elif self.phase=='attempt_permit':
                self.permit=task.value;self.phase='attempt_receipt'
            elif self.phase=='attempt_receipt':
                self.attempt_receipt=task.value;self.phase='attempt_check'
            elif self.phase=='barrier':
                self.barrier=task.value;self.phase='barrier_check'
            elif self.phase=='quote':
                self.quote_payload=task.value;self.phase='quote_check'
            elif self.phase=='reservation':
                self.ceiling=task.value;self.phase='reservation_check'
            elif self.phase=='born_read':
                token,revision=self.reads[self.index]
                self.values[token]=(revision,task.value,task.digest)
                self.index+=1;self.phase='born_read_prepare'
            elif self.phase=='final_member':
                name,key,revision=self.member_expected[self.member_index]
                if task.value!=self.raw['final_candidate'][name]:
                    raise C09PagedCaptureHold('Contact successor actual final physical Goal/Action/Schema differs from saved restricted successor')
                self.member_index+=1;self.phase='final_member_prepare'
            elif self.phase=='domain_receipt':
                self.receipt=_receipt(task.value);self.phase='domain_commit_check'
            elif self.phase=='birth_payload':
                self.born=task.value;self.phase='successor_check'
            else:raise C09PagedCaptureHold('Contact prospective pending original phase differs')
            return
        if self.phase=='decode':
            small=tuple(name for name in self.shape.columns if name!='payload_json')
            row=self.point(meter,self.shape.table,small,' AND '.join(name+'=?'for name in self.shape.primary_key_columns),self.key)
            if row is None:raise C09PagedCaptureHold('Contact prospective actual immutable SQL original disappeared')
            values=dict(zip(small,row));values['payload_json']=canonical_serialize(self.raw)
            physical=tuple(values[name]for name in self.shape.columns)
            codec=read_c09_contact_prospective_row_v1 if self.shape.table==TABLE else read_c09_contact_successor_row_v1
            self.original=codec(self.shape.columns,physical,authority_namespace=self.build.scope.authority_namespace,issuer=self.issuer)
            self.operation_id=self.raw['birth_operation_id']if self.shape.table==TABLE else values['final_operation_id']
            self.receipt_digest=None if self.shape.table==TABLE else values['final_receipt_digest']
            self.phase='domain';return
        if self.phase=='domain':
            self.domain_meta=self.point(meter,'graph_domain_production_originals_v1',
                ('domain','operation_kind','request_digest','original_digest','bundle_digest','receipt_digest'),
                'bot=? AND persona=? AND operation_id=?',(*self.namespace.as_tuple,self.operation_id))
            if self.domain_meta is None:raise C09PagedCaptureHold('Contact prospective actual producing Domain COMMIT absent')
            self.pending=_FrozenJSONV1(self,'graph_domain_production_originals_v1','original_payload_json',
                ('bot','persona','operation_id'),(*self.namespace.as_tuple,self.operation_id))
            self.phase='domain_payload';return
        if self.phase=='domain_check':
            if canonical_digest(self.domain)!=self.domain_meta[3]:
                raise C09PagedCaptureHold('Contact prospective actual whole Domain original digest differs')
            if self.shape.table==TABLE:
                before={name:value for name,value in self.raw.items()if name!='receipt'}
                if (self.domain_meta[:2]!=('d08','prepare_contact_prospective_v1')
                        or self.domain['request']!={'contact_id':self.raw['contact_id']}
                        or self.domain['authority']['actor']!=self.raw['observation']['owner_actor']
                        or self.domain['identity']['operation_id']!=self.operation_id
                        or self.domain['provenance']['prospective']!=before
                        or self.domain['provenance']['precommit_digest']!=canonical_digest(before)):
                    raise C09PagedCaptureHold('Contact prospective actual Domain producer/provenance differs')
                self.receipt=_receipt(self.raw['receipt']);self.receipt_digest=canonical_digest(self.receipt)
            else:
                if self.domain_meta[:2]!=('d08','prepare_contact_dispatch_v3'):
                    raise C09PagedCaptureHold('Contact successor actual final Domain producer differs')
                self.pending=_FrozenJSONV1(self,'graph_domain_production_originals_v1','receipt_json',
                    ('bot','persona','operation_id'),(*self.namespace.as_tuple,self.operation_id))
                self.phase='domain_receipt';return
            self.phase='domain_commit_check';return
        if self.phase=='domain_commit_check':
            if (self.receipt.operation_id!=self.operation_id or self.receipt.status!='committed'
                    or canonical_digest(self.receipt)!=self.receipt_digest or self.domain_meta[4:]!=
                        (self.receipt.operation_digest,self.receipt_digest)):
                raise C09PagedCaptureHold('Contact prospective actual same-CAS receipt/digest differs')
            bundle=self.point(meter,'graph_bundle_operations',('digest','activity_id','effect_id','commit_seq'),
                'bot=? AND persona=? AND operation_id=?',(*self.namespace.as_tuple,self.operation_id))
            if bundle!=(self.receipt.operation_digest,self.receipt.activity_id,self.receipt.effect_id,self.receipt.commit_seq):
                raise C09PagedCaptureHold('Contact prospective actual W01 original ledger differs')
            self.phase='event';return
        if self.phase=='event':
            event=self.point(meter,'graph_events',('digest','reads','revisions','epoch_revision'),
                'bot=? AND persona=? AND session=? AND event_id=?',
                (*self.namespace.as_tuple,self.receipt.activity_id,self.operation_id))
            if (event is None or json.loads(event[1])!=[[v.key.token,v.revision]for v in self.receipt.read_versions]
                    or json.loads(event[2])!=[[v.key.token,v.revision]for v in self.receipt.write_versions]
                    or len(self.receipt.invalidated_epochs)!=1 or event[3]!=self.receipt.invalidated_epochs[0].revision):
                raise C09PagedCaptureHold('Contact prospective real Graph event read/write/epoch differs')
            from ..contracts import Event,Scope
            expected=Event(Scope(*self.namespace.as_tuple,self.receipt.activity_id),self.operation_id,
                self.domain['now_utc'],'domain_bundle',{'bundle_digest':self.receipt.operation_digest})
            if event[0]!=expected.digest:raise C09PagedCaptureHold('Contact prospective actual producing Event commitment differs')
            self.birth_epoch=event[3]-1
            if self.shape.table==SUCCESSOR_TABLE:
                self.pending=_FrozenJSONV1(self,TABLE,'payload_json',('bot','persona','original_ref'),
                    (*self.namespace.as_tuple,self.raw['birth_ref']))
                self.phase='birth_payload';return
            if (self.raw['prospective_facts']['graph_epoch']!=self.birth_epoch
                    or self.raw['terms']['graph_epoch']!=self.birth_epoch):
                raise C09PagedCaptureHold('Contact prospective actual born fact cut differs')
            self.phase='attempt';return
        if self.phase=='attempt':
            self.attempt=self.point(meter,'graph_owner_domain_attempts_v3',
                ('request_digest','attempt_id','graph_revision','graph_epoch'),
                'bot=? AND persona=? AND operation_id=?',(*self.namespace.as_tuple,self.operation_id))
            observed=self.raw['observation']
            if (self.attempt!=(self.raw['birth_request_digest'],observed['attempt_id'],
                    self.raw['terms']['graph_revision'],self.raw['terms']['graph_epoch'])
                    or observed['attempt_id']!=contact_prospective_attempt_id_v1(self.namespace,self.operation_id,self.attempt[0])):
                raise C09PagedCaptureHold('Contact prospective original real WRITE attempt differs')
            self.pending=_FrozenJSONV1(self,'graph_owner_domain_attempts_v3','permit_json',('bot','persona','operation_id'),
                (*self.namespace.as_tuple,self.operation_id));self.phase='attempt_permit';return
        if self.phase=='attempt_receipt':
            self.pending=_FrozenJSONV1(self,'graph_owner_domain_attempts_v3','receipt_json',('bot','persona','operation_id'),
                (*self.namespace.as_tuple,self.operation_id));return
        if self.phase=='attempt_check':
            from ..authority_service.v2_contract import from_wire,canonical_digest as authority_digest
            if (authority_digest(from_wire(self.permit)).removeprefix('sha256:')!=self.raw['observation']['permit_digest']
                    or self.attempt_receipt['receipt']!=self.raw['receipt']):
                raise C09PagedCaptureHold('Contact prospective actual permit/receipt original differs')
            barrier=contact_prospective_barrier_key_v1(self.namespace,self.receipt.activity_id,self.raw['contact_id'])
            if tuple((v.key.token,v.revision)for v in self.receipt.write_versions)!=((barrier.token,1),):
                raise C09PagedCaptureHold('Contact prospective birth wrote a dispatch/job/claim instead of only barrier')
            history=self.point(meter,'graph_history',('value_cell_id','valid','event_bot','event_persona','event_session','event_id'),
                'token=? AND revision=?',(barrier.token,1))
            if history is None or history[1:]!=(1,*self.namespace.as_tuple,self.receipt.activity_id,self.operation_id):
                raise C09PagedCaptureHold('Contact prospective birth barrier physical history differs')
            self.pending=_FrozenJSONV1(self,'graph_history','value',('token','revision'),(barrier.token,1),cell_id=history[0])
            self.phase='barrier';return
        if self.phase=='barrier_check':
            before={name:value for name,value in self.raw.items()if name!='receipt'}
            if (self.barrier['precommit_digest']!=canonical_digest(before)
                    or self.barrier['joint_preparation']!=self.raw['joint_preparation']
                    or self.barrier['original_ref']!=self.original[1]
                    or self.barrier['old_contact_dedupe']!=self.raw['terms']['dedupe_key']):
                raise C09PagedCaptureHold('Contact prospective independently read born barrier differs')
            self.pending=_FrozenJSONV1(self,'runtime_resource_quotes','quote_json',('quote_id','version'),
                (self.raw['quote']['id'],self.raw['quote']['version']));self.phase='quote';return
        if self.phase=='quote_check':
            from .issuers import _decode_quote
            quote_raw=canonical_serialize(self.quote_payload)
            signature=self.point(meter,'runtime_resource_quotes',('signature',),'quote_id=? AND version=?',
                (self.raw['quote']['id'],self.raw['quote']['version']))
            if signature is None:raise C09PagedCaptureHold('Contact prospective original quote signature absent')
            self.issuer._signer.verify('resource-quote.v1',quote_raw,signature[0]);quote=_decode_quote(quote_raw)
            if (canonical_digest(quote)!=self.raw['quote']['digest']
                    or (quote.bot_id,quote.persona_id,quote.operation_id,quote.effect_id,quote.parent_budget_lease_ref)!=
                        (*self.namespace.as_tuple,self.raw['final_operation_id'],self.raw['effect_id'],self.raw['reservation']['lease_ref'])
                    or quote.deadline_utc!=self.raw['deadline_utc']):
                raise C09PagedCaptureHold('Contact prospective historical actual signed quote fixed identity differs')
            self.pending=_FrozenJSONV1(self,'runtime_budget_reservations','ceiling_json',('lease_id','operation_id'),
                (self.raw['reservation']['lease_ref'],self.raw['final_operation_id']));self.phase='reservation';return
        if self.phase=='reservation_check':
            row=self.point(meter,'runtime_budget_reservations',('digest',),'lease_id=? AND operation_id=?',
                (self.raw['reservation']['lease_ref'],self.raw['final_operation_id']))
            if row!=(self.raw['reservation']['digest'],) or self.ceiling!=self.raw['reservation']['ceiling']:
                raise C09PagedCaptureHold('Contact prospective historical once reservation changed')
            self.reads=tuple((v.key.token,v.revision)for v in self.receipt.read_versions)
            if self.domain['read_versions']!=[{'key':ref,'revision':revision}for ref,revision in self.reads]:
                raise C09PagedCaptureHold('Contact prospective actual complete born readset differs')
            self.index=0;self.phase='born_read_prepare';return
        if self.phase=='born_read_prepare':
            if self.index==len(self.reads):
                queries={}
                for page in self.domain['query_coverage']:
                    if page['epoch']['revision']!=self.birth_epoch:
                        raise C09PagedCaptureHold('Contact prospective birth query page selected a different historical cut')
                    rows,complete=queries.get(page['type_id'],((),False))
                    if complete:raise C09PagedCaptureHold('Contact prospective query pages continued after actual EOF')
                    addition=tuple((r['key'],r['revision'])for r in page['row_versions'])
                    if addition and rows and addition[0][0]<=rows[-1][0]:
                        raise C09PagedCaptureHold('Contact prospective query page order/repeated key differs')
                    queries[page['type_id']]=(rows+addition,page['complete'])
                if any(not complete for rows,complete in queries.values()):
                    raise C09PagedCaptureHold('Contact prospective birth query family never reached complete EOF')
                self.queries=tuple((kind,rows)for kind,(rows,complete)in sorted(queries.items()))
                self.query_index=0;self.after='';self.query_rows=[]
                self.phase='born_queries';return
            token,revision=self.reads[self.index]
            current=self.scope.source.execute('SELECT MAX(h.revision) FROM graph_history h JOIN graph_events e ON '
                '(h.event_bot,h.event_persona,h.event_session,h.event_id)=(e.bot,e.persona,e.session,e.event_id) '
                'WHERE e.bot=? AND e.persona=? AND e.epoch_revision<=? AND h.token=?',
                (*self.namespace.as_tuple,self.birth_epoch,token)).fetchone()[0]
            meter.charge_read(8)
            if current!=(revision if revision else None):
                raise C09PagedCaptureHold('Contact prospective historical selected read revision differs from actual cut')
            if not revision:self.index+=1;return
            history=self.point(meter,'graph_history',('value_cell_id','valid'),'token=? AND revision=?',(token,revision))
            if history is None:raise C09PagedCaptureHold('Contact prospective historical physical read absent')
            self.pending=_FrozenJSONV1(self,'graph_history','value',('token','revision'),(token,revision),
                cell_id=history[0],source_metadata=AtomKey.from_token(token).type_name=='memory.source')
            self.phase='born_read';return
        if self.phase=='born_queries':
            if self.query_index==len(self.queries):self.phase='finish';return
            kind,expected=self.queries[self.query_index]
            row=self.scope.source.execute('WITH latest AS (SELECT h.token,MAX(h.revision) AS revision '
                'FROM graph_history h JOIN graph_events e ON '
                '(h.event_bot,h.event_persona,h.event_session,h.event_id)=(e.bot,e.persona,e.session,e.event_id) '
                "WHERE e.bot=? AND e.persona=? AND e.epoch_revision<=? AND h.token>? AND json_extract(h.token,'$[4]')=? GROUP BY h.token) "
                'SELECT token,revision FROM latest ORDER BY token LIMIT 1',
                (*self.namespace.as_tuple,self.birth_epoch,self.after,kind)).fetchone()
            meter.charge_read(8 if row is None else len(row[0].encode())+32)
            if row is not None:self.query_rows.append(row);self.after=row[0];return
            if tuple(self.query_rows)!=expected:
                raise C09PagedCaptureHold('Contact prospective historical complete positive/negative keyset differs')
            self.query_index+=1;self.after='';self.query_rows=[];return
        if self.phase=='successor_check':
            from .contact_prospective_v1 import ContactProspectiveOriginalV1
            born=ContactProspectiveOriginalV1(canonical_serialize(self.born))
            birth=self.build.contact_prospective_proofs_v1.get((TABLE,(*self.namespace.as_tuple,self.born['contact_id'])))
            if birth is None:raise C09PagedCaptureHold('Contact successor has no independent actual completed birth proof')
            birth.require_complete(self.build,meter)
            if (born.digest!=self.raw['birth_digest'] or self.born['final_operation_id']!=self.operation_id
                    or self.born['quote']['digest']!=self.raw['quote_digest']
                    or self.born['reservation']['digest']!=self.raw['reservation_digest']
                    or self.born['deadline_utc']!=self.raw['deadline_utc']
                    or self.raw['final_candidate']['goal']!=self.born['candidate']['goal']):
                raise C09PagedCaptureHold('Contact successor actual fixed born Goal/quote/reservation/deadline differs')
            for name in ('action','schema'):
                before=self.born['candidate'][name];after=self.raw['final_candidate'][name]
                if {k:v for k,v in before.items()if k!='required_checks'}!={k:v for k,v in after.items()if k!='required_checks'}:
                    raise C09PagedCaptureHold('Contact successor changed fixed action/schema semantics')
                for old,new in zip(before['required_checks'],after['required_checks'],strict=True):
                    if {k:v for k,v in old.items()if k!='required_input_versions'}!={k:v for k,v in new.items()if k!='required_input_versions'}:
                        raise C09PagedCaptureHold('Contact successor changed exact provider/check parameters')
            provenance=self.domain['provenance']
            from .contact_final_stage_v3 import validate_contact_final_provenance_v3
            validate_contact_final_provenance_v3(provenance)
            if provenance['qualification_digest']!=self.raw['final_qualification_digest']:
                raise C09PagedCaptureHold('Contact successor actual final six-provider qualified original differs')
            kinds={'d08.goal.v1':'goal','d08.action_intent.v1':'action','d08.action_schema.v1':'schema'}
            self.member_expected=tuple((kinds[v.key.type_name],v.key,v.revision)for v in self.receipt.write_versions
                if v.key.type_name in kinds)
            if len(self.member_expected)!=3:
                raise C09PagedCaptureHold('Contact successor final lacks its actual Goal/Action/Schema writers')
            self.member_index=0;self.phase='final_member_prepare';return
        if self.phase=='final_member_prepare':
            if self.member_index==len(self.member_expected):self.phase='finish';return
            name,key,revision=self.member_expected[self.member_index]
            row=self.point(meter,'graph_history',('value_cell_id','valid','event_bot','event_persona','event_session','event_id'),
                'token=? AND revision=?',(key.token,revision))
            if row is None or row[1:]!=(1,*self.namespace.as_tuple,self.receipt.activity_id,self.operation_id):
                raise C09PagedCaptureHold('Contact successor actual producing final member history differs')
            self.pending=_FrozenJSONV1(self,'graph_history','value',('token','revision'),(key.token,revision),cell_id=row[0])
            self.phase='final_member';return
        if self.phase=='finish':
            self.descriptor={'schema':'d10.contact-prospective-c09-history.v1','scope_digest':self.build.scope.scope_digest,
                'source_role_digest':self.scope.source_original.role_source_digest,'table':self.shape.table,'key':self.key,
                'original_digest':self.original[3],'operation_id':self.operation_id,
                'receipt_digest':self.receipt_digest,'origin':self.origin}
            self.complete=True;_PROOFS[self]=(self.build,self.scope,self.key,canonical_digest(self.descriptor));return
        raise C09PagedCaptureHold('Contact prospective history unknown closed phase')
    def require_complete(self,build,meter):
        self.require_current(meter)
        if (not self.complete or build is not self.build or _PROOFS.get(self)!=(self.build,self.scope,self.key,canonical_digest(self.descriptor))):
            raise C09PagedCaptureHold('Contact prospective actual full frozen birth/final proof required')
        return self.descriptor


def advance_contact_prospective_history_v1(build):
    from .c09_graph_rebase_candidate_v2 import InstalledGraphRebaseBuildV2
    if type(build)is not InstalledGraphRebaseBuildV2:raise C09PagedCaptureHold('actual installed Graph build required')
    build.require_current()
    if build.contact_prospective_complete_v1:return False
    with build.session.reserve_batch()as budget:
        meter=require_c09_reserved_meter_v3(budget)
        with c09_sql_meter_quantum_v2(meter):
            scope=build.session.begin_source_physical_read_v3(build.pair,meter=meter)
            with scope.read_database_v3(meter=meter):
                table=(TABLE,SUCCESSOR_TABLE)[build.contact_prospective_table_v1]
                exists=meter.read_fixed_row(scope.source,'sqlite_master',('name',),'type=? AND name=?',('table',table))
                reader=build.contact_prospective_reader_v1
                if reader is None:
                    shape=None if exists is None else read_c09_table_shape_v2(scope.source,table,meter=meter)
                    found=None if shape is None else read_c09_next_row_metadata_v2(scope.source,shape,build.contact_prospective_after_v1)
                    if found is None:
                        if table==TABLE:build.contact_prospective_table_v1=1;build.contact_prospective_after_v1=None
                        else:build.contact_prospective_complete_v1=True
                        return True
                    key,metadata=found
                    reader=ContactProspectiveHistoryReadV1(_ISSUER,build,shape,key,metadata,scope,meter)
                    build.contact_prospective_reader_v1=reader
                reader.advance(budget,meter)
                if reader.complete:
                    reader.require_complete(build,meter)
                    build.contact_prospective_proofs_v1[(reader.shape.table,reader.key)]=reader
                    build.contact_prospective_after_v1=reader.key;build.contact_prospective_reader_v1=None
    build.require_current();return True


def require_contact_prospective_c09_join_v1(build,shape,row,original,meter):
    values=dict(zip(shape.columns,row,strict=True))
    key=tuple(values[name]for name in shape.primary_key_columns)
    reader=build.contact_prospective_proofs_v1.get((shape.table,key))
    if reader is None:raise C09PagedCaptureHold('Contact prospective target/cold requires independent actual frozen history proof')
    proof=reader.require_complete(build,meter)
    if original.original_commitment!=proof['original_digest']:
        raise C09PagedCaptureHold('Contact prospective target/cold original differs from actual frozen Source EOF')
    return proof
