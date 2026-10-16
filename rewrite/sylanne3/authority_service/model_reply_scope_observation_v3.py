"""Independent model parentage observation; no Source or model admission grant."""
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import asdict
from pathlib import Path
from threading import get_ident
from weakref import WeakSet
import sqlite3

from .contract import AuthorityUnavailable
from .v2_model_egress_contract import ModelEgressDraftV1,ModelEgressIntentV1
from ..runtime_contracts import NamespaceId
from ..runtime_storage_v3 import (bind_runtime_database_from_control_v3,runtime_storage_v3,
    begin_runtime_storage_operation_v3,bind_runtime_storage_operation_v3,
    finish_runtime_storage_operation_v3,runtime_storage_quantum_v3)

_BOUND=ContextVar('sylanne_model_reply_scope_observation_v3',default=None)
_OBSERVATIONS=WeakSet()

_POINT_KEYS={
    'runtime_jobs':('job_id',),
    'runtime_job_operations':('bot_id','persona_id','operation_id','phase'),
    'runtime_budget_leases':('lease_id',),
    'runtime_budget_reservations':('lease_id','operation_id'),
    'runtime_budget_operations':('bot_id','persona_id','operation_id','phase'),
    'runtime_resource_quotes':('quote_id','version'),
    'runtime_budget_grants':('lease_id','version'),
    'graph_first_ingress_c02_committed_seals_v2':('bot','persona','operation_id'),
    'graph_domain_production_outbox_v1':('bot','persona','dedupe_key'),
    'graph_first_ingress_identity_v1':('bot','persona','operation_id'),
    'graph_first_ingress_intents_v2':('bot','persona','operation_id'),
    'ingress_first_observations':('bot','persona','operation_id'),
    'graph_bundle_operations':('bot','persona','operation_id'),
    'graph_domain_production_originals_v1':('bot','persona','operation_id'),
    'graph_recovery_metadata_v2':('bot','persona'),
    'graph_epochs':('bot','persona'),
    'graph_atoms':('token',),
    'graph_history':('token','revision'),
    'graph_events':('bot','persona','session','event_id'),
    'graph_d11_life_originals_v1':('bot','persona','kind','original_ref'),
    'graph_d07_execution_originals_v1':('bot','persona','kind','original_ref'),
    'graph_d04_originals_v3':('bot','persona','kind','original_ref'),
    'graph_d05_production_policies_v1':('bot','persona','policy_ref','revision'),
    'graph_natural_generation_preparations_v2':('bot','persona','parent_original_id'),
    'graph_natural_review_preparations_v2':('bot','persona','parent_original_id'),
    'graph_d13_outbound_observations_v1':('bot','persona','final_operation_id','observation_digest'),
}

_POINT_COLUMNS={
    'runtime_jobs':frozenset(('job_id', 'operation_id', 'activity_id', 'effect_id', 'bot_id', 'persona_id', 'snapshot_ref', 'phase', 'work_kind', 'continuation_json', 'wake_condition_json', 'deadline_utc', 'budget_ref', 'resource_ref', 'operator_versions_json', 'lease_holder', 'lease_expires_utc', 'fence', 'cancel_epoch', 'usage_json', 'result_ref')),
    'runtime_job_operations':frozenset(('bot_id', 'persona_id', 'operation_id', 'phase', 'digest', 'job_id', 'job_json')),
    'runtime_budget_leases':frozenset(('lease_id', 'parent_id', 'bot_id', 'persona_id', 'currency', 'limits_json', 'used_json', 'reserved_json', 'unconfirmed_json', 'version', 'state')),
    'runtime_budget_reservations':frozenset(('state', 'digest')),
    'runtime_budget_operations':frozenset(('digest', 'receipt_json')),
    'runtime_resource_quotes':frozenset(('quote_json', 'signature')),
    'runtime_budget_grants':frozenset(('grant_json', 'signature')),
    'graph_bundle_operations':frozenset(('digest', 'activity_id', 'effect_id', 'commit_seq', 'receipt_json')),
    'graph_domain_production_originals_v1':frozenset(('domain', 'operation_kind', 'request_digest', 'original_digest', 'original_payload_json', 'read_versions_json', 'bundle_digest', 'receipt_json', 'receipt_digest')),
    'graph_recovery_metadata_v2':frozenset(('graph_revision', 'requirements_json')),
    'graph_epochs':frozenset(('revision',)),
    'graph_events':frozenset(('digest', 'epoch_revision', 'revisions')),
    'graph_d11_life_originals_v1':frozenset(('bot', 'persona', 'kind', 'original_ref', 'producing_operation_id', 'payload_json', 'payload_digest', 'signature')),
    'graph_d07_execution_originals_v1':frozenset(('payload_json', 'payload_digest', 'signature')),
    'graph_d04_originals_v3':frozenset(('payload_json', 'payload_digest')),
    'graph_d05_production_policies_v1':frozenset(('revision', 'payload_json', 'payload_digest', 'signature')),
    'graph_natural_generation_preparations_v2':frozenset(('parent_original_id', 'original_operation_id', 'job_id', 'seal_json', 'state', 'terminal_receipt_digest')),
    'graph_natural_review_preparations_v2':frozenset(('parent_original_id', 'original_operation_id', 'job_id', 'seal_json', 'state', 'terminal_receipt_digest')),
    'graph_d13_outbound_observations_v1':frozenset(('observation_digest',)),
    'graph_first_ingress_c02_committed_seals_v2':frozenset(('schema', 'bundle_digest', 'bundle_json')),
    'graph_domain_production_outbox_v1':frozenset(('causal_operation_id', 'receiver_domain', 'event_kind', 'original_ref', 'original_digest', 'state')),
    'graph_first_ingress_identity_v1':frozenset(('source_ref', 'platform_ref', 'conversation_ref', 'sender_ref', 'message_id', 'visibility', 'identity_json', 'content_fingerprint', 'learned_at', 'bundle_digest')),
    'graph_first_ingress_intents_v2':frozenset(('identity_json',)),
    'ingress_first_observations':frozenset(('content_fingerprint', 'learned_at', 'bundle_digest')),
}

class ModelReplyScopeObservationNeededV3(Exception):
    def __init__(self,request):self.request=request


def _active_observation_v3(db=None):
    observation=_BOUND.get()
    if observation is None or db is not None and observation.db is not db:return None
    observation.require_actual_v3()
    return observation


def require_actual_model_reply_scope_column_owner_v3(owner,*,db):
    if type(owner)is not _ModelReplyScopeObservationV3 or owner not in _OBSERVATIONS or owner.db is not db:
        raise AuthorityUnavailable('actual independent model reply observer required')
    return owner.require_actual_v3()


class _ReplyScopeMetadataScanV3:
    def __init__(self,owner,kind,parameters):
        self.owner,self.kind,self.parameters=owner,kind,parameters
        self.after=None;self.rows=[];self.pending=None;self.complete=False;self.candidate=None
    def advance(self,meter):
        from ..runtime.domain_background_read_v3 import _BackgroundPointReadV3,background_json_loads_v3
        owner=self.owner;owner.require_data_current_v3(meter);ns=owner.namespace.as_tuple
        if self.pending is not None:
            if not self.pending.complete:self.pending.advance(meter);return
            row=self.pending.require_row_v3(meter)
            if self.kind in('life_c4','life_c4_call','life_c4_call_original','life_binding'):
                value=background_json_loads_v3(row[0])
                expected=self.parameters[0]
                match=(value.get('call_id')==expected if self.kind in('life_c4_call','life_c4_call_original') else
                    value.get('selector',{}).get('cycle_job_ref')==expected if self.kind=='life_c4'
                    else value.get('binding',{}).get('activity_id')==expected)
                if match:self.rows.append(self.candidate if self.kind=='life_c4_call_original' else (self.candidate[0],))
            elif self.kind=='message_history':
                value=background_json_loads_v3(row[0]);paid=value.get('paid_review',{})
                if(paid.get('generation_original_operation_id'),paid.get('review_original_operation_id'))==self.parameters:
                    token,revision,event=self.candidate
                    self.rows.append((token,revision,event,value.get('schema'),value.get('activity_id'),
                        value.get('operation_id'),value.get('effect_id'),value.get('batch_id'),
                        paid.get('generation_call_id'),paid.get('review_call_id')))
            else:self.rows.append(row)
            self.pending=None;return
        if self.kind=='life_c4_call_original':
            table='graph_d11_life_originals_v1'
            where="bot=? AND persona=? AND kind IN ('c4_prepared','c4_phase_prepared')"
            args=ns
            if self.after is not None:where+=' AND (kind,original_ref)>(?,?)';args=(*args,*self.after)
            row=meter.read_fixed_row(owner.db,table,('kind','original_ref'),
                where+' ORDER BY kind,original_ref LIMIT 1',args)
            if row is None:self.complete=True;return
            self.after=row;self.candidate=row
            request=(table,('payload_json',),('bot','persona','kind','original_ref'),(*ns,*row))
            self.pending=_BackgroundPointReadV3(owner,request);return
        if self.kind in('life_c4','life_c4_call','life_binding'):
            table='graph_d11_life_originals_v1';where='bot=? AND persona=? AND kind=?';args=(*ns,'c4_prepared'if self.kind in('life_c4','life_c4_call')else'prepared')
            if self.after is not None:where+=' AND original_ref>?';args=(*args,self.after)
            row=meter.read_fixed_row(owner.db,table,('original_ref',),where+' ORDER BY original_ref LIMIT 1',args)
            if row is None:self.complete=True;return
            self.after=row[0];self.candidate=row
            request=(table,('payload_json',),('bot','persona','kind','original_ref'),(*ns,args[2],row[0]))
            self.pending=_BackgroundPointReadV3(owner,request);return
        if self.kind=='message_history':
            where='event_bot=? AND event_persona=? AND valid=1';args=ns
            if self.after is not None:where+=' AND (event_id,token,revision)>(?,?,?)';args=(*args,*self.after)
            row=meter.read_fixed_row(owner.db,'graph_history',('event_id','token','revision'),
                where+' ORDER BY event_id,token,revision LIMIT 1',args)
            if row is None:self.complete=True;return
            self.after=row
            from ..graph_types import AtomKey
            atom=AtomKey.from_token(row[1])
            if(atom.type_name not in('d09.natural_verified_segment_batch.v2','d09.natural_verified_segment_batch.v3')
                    or NamespaceId.from_key(atom)!=owner.namespace):return
            self.candidate=(row[1],row[2],row[0])
            self.pending=_BackgroundPointReadV3(owner,('graph_history',('value',),('token','revision'),(row[1],row[2])));return
        specs={
            'foreground_parents':('runtime_jobs',('job_id',),'bot_id=? AND persona_id=? AND work_kind=?',(*ns,'d11.foreground_cycle.v1'),'job_id',129),
            'children':('runtime_jobs',('job_id',),"bot_id=? AND persona_id=? AND activity_id=? AND work_kind IN ('artifact_draft_v1','d10.life.source_note.v1','d10.life.artifact_draft.v1','d07.recall_need')",(*ns,*self.parameters),'job_id',257),
            'message_jobs':('runtime_jobs',('job_id',),"bot_id=? AND persona_id=? AND operation_id=? AND work_kind='message'",(*ns,*self.parameters),'job_id',2),
            'outbound':('graph_d13_outbound_observations_v1',('observation_digest',),'bot=? AND persona=? AND final_operation_id=?',(*ns,*self.parameters),'observation_digest',2),
        }
        if self.kind not in specs:raise AuthorityUnavailable('unregistered model reply metadata selector')
        table,columns,where,args,order,limit=specs[self.kind]
        if len(self.rows)>=limit:self.complete=True;return
        if self.after is not None:where+=' AND '+order+'>?';args=(*args,self.after)
        row=meter.read_fixed_row(owner.db,table,columns,where+' ORDER BY '+order+' LIMIT 1',args)
        if row is None:self.complete=True;return
        self.after=row[0];self.rows.append(row)
    def require_rows_v3(self,meter):
        self.owner.require_data_current_v3(meter)
        if not self.complete:raise AuthorityUnavailable('model reply metadata selector requires actual complete EOF')
        return tuple(self.rows)


class _ModelReplyScopeObservationV3:
    def __init__(self,verifier,*,model_service,credential,subject,holder,intent,expected_anchor,permit):
        from .current_authority_graph_read_v3 import require_authority_graph_read_controller_v3
        controller=require_authority_graph_read_controller_v3(verifier)
        if(controller.kind!='model'or controller.service is not model_service
                or model_service._graph_verifier is not verifier
                or type(intent)not in(ModelEgressDraftV1,ModelEgressIntentV1)
                or permit is None and type(intent)is not ModelEgressDraftV1
                or permit is not None and type(intent)is not ModelEgressIntentV1
                or intent.subject!=subject or intent.namespace!=controller.fences.namespace
                or expected_anchor.namespace!=intent.namespace):
            raise AuthorityUnavailable('actual model service/intent/original prepare-or-dispatch observation required')
        self.verifier,self.model_service,self.controller=verifier,model_service,controller
        self.credential,self.subject,self.holder=credential,subject,holder
        self.intent,self.expected_anchor,self.permit=intent,expected_anchor,permit
        self.thread=get_ident();self.closed=False;self.points={};self.scans={};self.columns=set();self.column_kinds={};self.inner_readers={};self.inner_headers={};self.growth_heads={};self.history_commitments={};self.c02_readers={};self.source_readers={};self.source_headers={};self.cause_history={};self.cause_headers={};self.reserved=0;self.issued_scope=None
        self.service=verifier._owner_stop_reply_service_v1
        self.control=controller.location._control
        self.namespace=controller.location.namespace_id
        if (controller.location.namespace != intent.namespace
                or controller.location.core is not controller.fences.core):
            raise AuthorityUnavailable('model observation crossed its actual namespace/Core location')
        self.context=self.control.read_verified_current_storage_v1()
        self.context.require_current('business')
        members={member['role']:member for member in self.context.manifest['members']}
        self.member=members['graph']
        if Path(members['core']['resolved_path']) != controller.fences.core.path.resolve(strict=True):
            raise AuthorityUnavailable('model observation selected another actual Core')
        self.storage={'pointer_version':self.context.pointer_version,'manifest_digest':self.context.manifest_digest,
            'storage_generation':self.context.storage_generation,'graph_path':self.member['resolved_path'],
            'core_path':members['core']['resolved_path'],'graph_device':self.member['device'],
            'graph_file_id':self.member['file_id'],'graph_incarnation':self.member['incarnation_or_journal_id']}
        self._authorize_v3()
        self.db=self.handle=self.operation=None
        try:
            self.db=sqlite3.connect(Path(self.storage['graph_path']).as_uri()+'?mode=ro',uri=True)
            self.db.execute('PRAGMA query_only=ON')
            self.handle=bind_runtime_database_from_control_v3(self.db,control=self.control,role='graph')
            self.legacy=self.handle is None
            core_handle=runtime_storage_v3(controller.fences.core._db)
            if self.legacy and core_handle is not None:
                raise AuthorityUnavailable('selected Core lost its matching selected Graph observer handle')
            self.operation=begin_runtime_storage_operation_v3(self.db,intent.operation_id,None)
            if not self.legacy:
                if(core_handle is None or core_handle.role!='core'
                        or core_handle.pool is not self.handle.pool
                        or core_handle.selection_digest!=self.handle.selection_digest):
                    raise AuthorityUnavailable('independent model observation lost selected same Core/Graph pool')
                with bind_runtime_storage_operation_v3(self.operation,self.db):
                    self.db.execute('BEGIN')
                    try:
                        with runtime_storage_quantum_v3(self.db)as meter:
                            self.handle.require_current(meter)
                            self.job_metadata=meter.read_fixed_row(self.db,'runtime_jobs',
                                ('bot_id','persona_id','work_kind','operation_id','activity_id','budget_ref'),
                                'job_id=?',(intent.job_id,))
                            if self.job_metadata is None:
                                from ..runtime.jobs import JobConflict
                                raise JobConflict('job does not exist')
                            if NamespaceId(*self.job_metadata[:2]) != self.namespace:
                                raise AuthorityUnavailable('model observation job crossed its actual namespace')
                            self.stamp=self._stamp_v3(meter)
                    finally:self.db.rollback()
            else:
                self.job_metadata=None;self.stamp=None
            _OBSERVATIONS.add(self)
        except BaseException:
            self.close_v3();raise

    def require_reply_service_v3(self):
        self.require_actual_v3()
        service=self.verifier._owner_stop_reply_service_v1
        if service is None:
            raise AuthorityUnavailable('foreground model admission lacks its actual Core reply barrier service/namespace')
        if (service is not self.service or service.control is not self.control
                or service.core is not self.controller.fences.core or service.namespace!=self.intent.namespace
                or service.namespace_id!=self.namespace):
            raise AuthorityUnavailable('model parentage crossed installed Core/OwnerStop/Graph')
        context,storage,member=service._storage()
        if storage!=self.storage or member!=self.member or context.manifest_digest!=self.context.manifest_digest:
            raise AuthorityUnavailable('model reply service changed its actual selected storage')
        return service

    def _authorize_v3(self):
        controller=self.controller.require_installed_v3()
        if controller.fences.core._db.in_transaction:
            raise AuthorityUnavailable('model parentage permission observation must precede Graph SQL')
        controller.fences.core._require(self.credential,'model_egress',controller.fences.namespace,self.holder)
        if self.permit is not None:
            controller.fences.validate_fence(credential=self.credential,subject=self.subject,permit=self.permit)
        with controller.fences._frozen()as(db,deletion,execution,_):
            anchor=controller.fences._current_locked(db,deletion,execution,holder=self.holder,
                generation=self.expected_anchor.activation_generation)
        if anchor!=self.expected_anchor:raise AuthorityUnavailable('model parentage original Authority anchor changed')
    def require_actual_v3(self):
        if(self not in _OBSERVATIONS or self.closed or get_ident()!=self.thread
                or _BOUND.get()is not self or self.controller.service is not self.model_service
                or self.model_service._graph_verifier is not self.verifier
                or self.operation is not None and self.operation.closed):
            raise AuthorityUnavailable('model parentage observation lost its actual call lifetime')
        return self
    def _stamp_v3(self,meter):
        self.handle.require_current(meter)
        recovery=meter.read_fixed_row(self.db,'graph_recovery_metadata_v2',('graph_revision',),
            'bot=? AND persona=?',self.namespace.as_tuple)
        epoch=meter.read_fixed_row(self.db,'graph_epochs',('revision',),'bot=? AND persona=?',self.namespace.as_tuple)
        if recovery is None or epoch is None:raise AuthorityUnavailable('model parentage Graph metadata is absent')
        return recovery,epoch,self.handle.selection_digest,self.context.pointer_version,self.context.manifest_digest
    def require_data_current_v3(self,meter):
        self.require_actual_v3()
        if self.legacy:raise AuthorityUnavailable('legacy observation has no segmented column capability')
        if runtime_storage_v3(self.db)is not self.handle or self._stamp_v3(meter)!=self.stamp:
            raise AuthorityUnavailable('model parentage actual selected Graph changed during observation')
        return self
    def reserve_heap_v3(self,*,extra=0):
        from ..runtime.source_correction_read_v3 import _heap
        amount=_heap((tuple((column.nodes,column.scalar,column.text_parts,column.text_chars,column.frozen,column.fragment)
            for column in self.columns), tuple((task.metadata,task.small,task.row) for task in self.points.values()),
            tuple((task.rows,task.after,task.candidate) for task in self.scans.values()), self.column_kinds,self.inner_headers,self.growth_heads,self.history_commitments,self.cause_history,self.source_headers,self.cause_headers,tuple(self.source_readers.values()),tuple(self.c02_readers.values()),tuple((reader.nodes,reader.value,reader.scalar,reader.chars,reader.buffer)for reader in self.inner_readers.values())))+sum(parser._source_heap_bytes()for parser in self.source_readers.values())+extra+65536
        if amount>self.reserved:self.operation.retain(amount-self.reserved);self.reserved=amount
    def life_binding_column_v3(self,column):
        return (column.table=='graph_d11_life_originals_v1' and column.column=='payload_json'
            and dict(zip(column.key_columns,column.key)).get('kind')=='prepared')
    def d07_parentage_column_v3(self,column):
        return (column.table=='graph_d07_execution_originals_v1'and column.column=='payload_json'
            and dict(zip(column.key_columns,column.key)).get('kind')=='prepared')
    def appraisal_parentage_column_v3(self,column):
        return (column.table=='graph_d04_originals_v3'and column.column=='payload_json'
            and dict(zip(column.key_columns,column.key)).get('kind')=='appraisal')
    def c02_column_v3(self,column):
        return column.table=='graph_first_ingress_c02_committed_seals_v2'and column.column=='bundle_json'
    def source_history_column_v3(self,column):
        if column.table!='graph_history'or column.column!='value':return False
        key=(column.key[0],column.key[1])
        existing=self.history_commitments.get(key)
        cause=self.cause_history.get(key)
        return bool(existing is not None and existing[3]or cause is not None and cause[3]=='source')
    def observe_column_fragment_v3(self,column,fragment,meter):
        if self.source_history_column_v3(column):
            parser=self.source_readers.get(column)
            if parser is None:
                from ..runtime.c09_graph_row_codec_v2 import C09MemorySourceJSONStreamV3
                codec=None if column.cell is None else column.cell.header[0]
                parser=C09MemorySourceJSONStreamV3(ensure_ascii=codec!='canonical-json.utf8.v1')
                self.source_readers[column]=parser
            parser.feed(fragment,lambda event:None)
        if self.c02_column_v3(column):
            operation_id=dict(zip(column.key_columns,column.key))['operation_id']
            self.c02_readers[operation_id].feed_v3(fragment,meter)
    def observe_column_finish_v3(self,column):
        if self.source_history_column_v3(column):
            parser=self.source_readers.pop(column)
            parsed=parser.finish()
            if((parsed.sha256,parsed.byte_count)!=(column.sha256,column.byte_count)
                    or column.byte_count>4_194_304):
                raise AuthorityUnavailable('foreground Source semantic validation changed actual raw EOF/limit')
            self.source_headers[column]=dict(parser._source_metadata)
        if column.table=='graph_history'and column.column=='value':
            material=self.cause_history.get((column.key[0],column.key[1]))
            if material is not None and material[3]in('episode','trace'):
                from ..runtime.domain_background_read_v3 import _freeze_value_v3
                from ..memory_types import validate_episode,validate_subjective_trace_v2
                if column.byte_count>4_194_304:
                    raise AuthorityUnavailable('foreground episode/trace exceeds its original JSON limit')
                value=column.json_v3()
                if material[3]=='episode':
                    validate_episode(value);header=tuple(value['source_refs'])
                else:
                    validate_subjective_trace_v2(value);header=value['episode_ref']
                self.cause_headers[column]=header
                column.frozen=_freeze_value_v3({})
        if self.c02_column_v3(column):
            operation_id=dict(zip(column.key_columns,column.key))['operation_id']
            self.c02_readers[operation_id].finish_v3(sha256=column.sha256,byte_count=column.byte_count)
    def observe_column_event_v3(self,column,event):
        if self.appraisal_parentage_column_v3(column)and event.path==('frozen_json',):
            if event.kind=='scalar_start'and event.scalar_kind=='string':
                from .model_reply_parentage_v3 import _HeaderStreamV3
                self.inner_readers[column]=_HeaderStreamV3()
            elif event.kind=='scalar_end'and event.scalar_kind=='string':
                self.inner_headers[column]=self.inner_readers.pop(column).finish_header()
        if len(event.path)!=1:
            return
        parentage=self.d07_parentage_column_v3(column)or self.appraisal_parentage_column_v3(column)
        if not parentage and(not self.life_binding_column_v3(column)or event.path[0]not in(
                'requirements_json','graph_revision','graph_epoch','job_projection_json','job_projection_revision')):
            return
        kinds=self.column_kinds.setdefault(column,{})
        if event.kind=='key':
            kinds[event.path[0]]=None
        elif event.kind=='scalar_start':
            kinds[event.path[0]]=event.scalar_kind
        elif event.kind in('object_start','array_start'):
            kinds[event.path[0]]=event.kind
    def observe_column_codepoint_v3(self,column,path,codepoint):
        if self.appraisal_parentage_column_v3(column)and path==('frozen_json',):
            self.inner_readers[column].codepoint(codepoint)
    def metadata_only_column_v3(self,column):
        if column.table=='graph_history'and column.column=='value':
            if (column.key[0],column.key[1])in self.cause_history:return True
        if(self.c02_column_v3(column)or self.life_binding_column_v3(column)or self.d07_parentage_column_v3(column)
                or self.appraisal_parentage_column_v3(column)):
            return True
        if column.table=='graph_atoms'and column.column=='value':
            material=self.growth_heads.get(column.key[0])
            if material is not None and material[3]=='source':
                return True
        if column.table=='graph_history'and column.column=='value':
            material=self.history_commitments.get((column.key[0],column.key[1]))
            if material is not None and material[3]:
                return True
            from ..graph_types import AtomKey
            return AtomKey.from_token(column.key[0]).type_name in(
                'd09.natural_verified_segment_batch.v2','d09.natural_verified_segment_batch.v3')
        return False
    def retain_column_path_v3(self,column,path):
        if not self.metadata_only_column_v3(column):return True
        if self.c02_column_v3(column):return not path
        if column.table=='graph_history'and column.column=='value':
            material=self.cause_history.get((column.key[0],column.key[1]))
            if material is not None:return not path if material[3]=='source'else True
        if column.table=='graph_atoms'and column.column=='value':
            material=self.growth_heads.get(column.key[0])
            if material is not None and material[3]=='source':
                return not path
        if column.table=='graph_history'and column.column=='value':
            material=self.history_commitments.get((column.key[0],column.key[1]))
            if material is not None and material[3]:
                return not path
        if self.d07_parentage_column_v3(column):
            fields=('schema','namespace','operation_id','activity_id','effect_id','attempt_id','job_id','call_id',
                'execution_id','work_kind','semantic_question_ref','semantic_question_digest','cycle_ref',
                'cycle_digest','call_plan_digest','c02_operation_id','cancel_generation','proposal_head',
                'proposal_digest','source_head','source_digest','parent_budget_lease_ref','original_deadline_utc',
                'need_ref','need_digest','cycle_job_ref','responsibility_ref','responsibility_digest',
                'recall_policy_digest','adoption_operation_id','self_authority_json','owner_guard_json',
                'reflection_request_ref','reflection_request_digest','reflection_continuation_ref',
                'reflection_continuation_digest','parent_prepared_ref','parent_prepared_digest',
                'parent_execution_ref','parent_execution_digest','checkpoint_ref','checkpoint_digest',
                'parent_grant_digest','source_refs','ticket_id')
            selected=tuple((name,)for name in fields)
        elif self.appraisal_parentage_column_v3(column):
            selected=tuple((name,)for name in('schema','namespace','operation_id','job_id','call_id','model_request_digest'))
        elif self.life_binding_column_v3(column):
            selected=(('binding',),('prepare_operation_id',),('plan','activity_id'),('plan','effect_id'),('plan','operation_id'))
        else:
            selected=(('schema',),('activity_id',),('operation_id',),('effect_id',),('batch_id',),
                ('paid_review','generation_original_operation_id'),('paid_review','review_original_operation_id'),
                ('paid_review','generation_call_id'),('paid_review','review_call_id'))
        return not path or any(path[:len(prefix)]==prefix or prefix[:len(path)]==path for prefix in selected)
    def signer_v3(self,table):
        return (self.verifier._issuer.resource_issuer._signer if table=='runtime_resource_quotes'
            else self.verifier._issuer._signer)
    def require_request_v3(self,request):
        table,columns,key_columns,key=request
        if table not in _POINT_KEYS or not columns or len(key_columns)!=len(key):
            raise AuthorityUnavailable('unregistered model parentage fixed original')
        if table not in('graph_atoms','graph_history')and not set(columns)<=_POINT_COLUMNS.get(table,frozenset()):
            raise AuthorityUnavailable('unregistered model parentage original columns')
        keys=dict(zip(key_columns,key))
        if any(name in keys and keys[name]!=value for name,value in
                (('bot',self.namespace.bot),('persona',self.namespace.persona),
                 ('bot_id',self.namespace.bot),('persona_id',self.namespace.persona))):
            raise AuthorityUnavailable('model parentage fixed original crossed namespace')
        if table in('graph_atoms','graph_history'):
            from ..graph_types import AtomKey
            atom=AtomKey.from_token(keys['token'])
            if NamespaceId.from_key(atom)!=self.namespace:
                raise AuthorityUnavailable('model parentage fixed head crossed namespace')
            from ..graph_types import OWNER_GRANT_TYPE
            requested=set(columns)
            if atom.type_name==OWNER_GRANT_TYPE:
                allowed={'revision','value','valid'}if table=='graph_atoms'else set()
            elif atom.type_name=='runtime.job':
                allowed=({'revision','value','valid'}if table=='graph_atoms'else
                    {'token','value','valid','event_id','event_bot','event_persona'})
            elif atom.type_name=='runtime.cost_settlement':
                allowed={'revision','value','valid','event_id'}
            elif atom.type_name in('d09.natural_verified_segment_batch.v2','d09.natural_verified_segment_batch.v3'):
                allowed={'value'}if table=='graph_history'else set()
            elif table=='graph_history'and (atom.token,keys.get('revision'))in self.cause_history:
                column,digest,cause,kind=self.cause_history[(atom.token,keys['revision'])]
                column._actual_v3()
                if not column.complete or column.sha256!=digest:
                    raise AuthorityUnavailable('foreground history lost its actual signed cause EOF')
                allowed={'event_id','value','valid'}
            elif table=='graph_history'and (atom.token,keys.get('revision'))in self.history_commitments:
                column,version,digest,source=self.history_commitments[(atom.token,keys['revision'])]
                column._actual_v3()
                if not column.complete:
                    raise AuthorityUnavailable('historical commitment lost its actual create EOF')
                allowed={'value','valid'}
            elif atom.token in self.growth_heads:
                proof,version,digest,kind=self.growth_heads[atom.token]
                proof[1]._actual_v3()
                if not proof[1].complete or proof[1].sha256!=proof[2]:
                    raise AuthorityUnavailable('growth commitment lost its signed semantic EOF')
                if table=='graph_history':
                    if keys.get('revision')!=version.revision:
                        raise AuthorityUnavailable('growth history changed its actual signed head')
                    allowed={'event_id'}
                else:
                    allowed={'revision','value','valid'}if kind=='source'else{'revision','value','valid'}
            else:
                raise AuthorityUnavailable('unregistered model parentage Graph family')
            if not requested or not requested<=allowed:
                raise AuthorityUnavailable('unregistered model parentage Graph columns')
        if table in('graph_natural_generation_preparations_v2','graph_natural_review_preparations_v2') and tuple(key_columns)==('job_id',):
            if tuple(columns)!=('parent_original_id','original_operation_id','job_id') or key!=(self.intent.job_id,):
                raise AuthorityUnavailable('natural parent locator needs its actual unique model job')
            return request
        required=_POINT_KEYS[table]
        if table=='graph_events'and tuple(key_columns)!=required:
            raise AuthorityUnavailable('model parentage event needs complete original PK')
        if any(name not in keys for name in required):
            raise AuthorityUnavailable('model parentage fixed point requires complete original PK')
        return request
    def prepare_point_v3(self,request):
        from ..runtime.domain_background_read_v3 import _BackgroundPointReadV3
        if request[0]=='scan':
            _,kind,parameters=request
            task=self.scans.get(request)
            if task is None:task=_ReplyScopeMetadataScanV3(self,kind,parameters);self.scans[request]=task
        else:
            self.require_request_v3(request)
            task=self.points.get(request)
            if task is None:task=_BackgroundPointReadV3(self,request);self.points[request]=task
        self._authorize_v3()
        with bind_runtime_storage_operation_v3(self.operation,self.db):
            self.db.execute('BEGIN')
            try:
                with runtime_storage_quantum_v3(self.db)as meter:
                    task.advance(meter)
                    self.reserve_heap_v3()
            finally:self.db.rollback()
        self._authorize_v3()
    def evaluate_v3(self,callback):
        while True:
            self._authorize_v3()
            with bind_runtime_storage_operation_v3(self.operation,self.db):
                self.db.execute('BEGIN')
                try:
                    with runtime_storage_quantum_v3(self.db)as meter:
                        self.require_data_current_v3(meter)
                        result=callback(self.db)
                        self.require_data_current_v3(meter)
                except ModelReplyScopeObservationNeededV3 as needed:
                    request=needed.request
                else:return result
                finally:self.db.rollback()
            tasks=self.scans if request[0]=='scan'else self.points
            task=tasks.get(request)
            while task is None or not task.complete:
                self.prepare_point_v3(request);task=tasks[request]
    def close_v3(self):
        if self.closed:return
        self.closed=True;_OBSERVATIONS.discard(self)
        from ..runtime.domain_background_read_v3 import _COLUMNS
        for column in self.columns:
            _COLUMNS.pop(column,None)
            column.value=column.frozen=column.parser=column.cell=column.signature_state=None
            column.semantic_state=column.semantic_decoder=column.semantic_sha256=None
            column.nodes={};column.scalar=bytearray();column.text_parts=[];column.text_chars=[];column.fragment=b''
        self.columns.clear();self.points.clear();self.scans.clear()
        self.column_kinds.clear();self.inner_readers.clear();self.inner_headers.clear()
        self.growth_heads.clear();self.history_commitments.clear();self.c02_readers.clear();self.source_readers.clear();self.source_headers.clear();self.cause_history.clear();self.cause_headers.clear()
        if self.issued_scope is not None:self.service._scopes.pop(id(self.issued_scope),None)
        self.issued_scope=None
        try:
            if self.handle is not None:self.handle.close()
            if self.db is not None:self.db.close()
        finally:finish_runtime_storage_operation_v3(self.operation)
        self.db=self.operation=self.handle=None


@contextmanager
def retain_authority_model_reply_scope_observation_v3(verifier,*,model_service,credential,subject,holder,
        intent,expected_anchor,permit=None):
    observation=_ModelReplyScopeObservationV3(verifier,model_service=model_service,credential=credential,
        subject=subject,holder=holder,intent=intent,expected_anchor=expected_anchor,permit=permit)
    token=_BOUND.set(observation)
    try:
        yield observation
    finally:
        _BOUND.reset(token);observation.close_v3()


def read_bound_model_reply_scope_point_v3(db,*,table,columns,key_columns,key):
    observation=_active_observation_v3(db)
    if observation is None or observation.legacy:return False,None
    request=(table,tuple(columns),tuple(key_columns),tuple(key));observation.require_request_v3(request)
    task=observation.points.get(request)
    if task is None or not task.complete:raise ModelReplyScopeObservationNeededV3(request)
    with runtime_storage_quantum_v3(db)as meter:
        observation.require_data_current_v3(meter);return True,task.require_row_v3(meter)


def model_reply_scope_point_v3(db,*,table,columns,key_columns,key,legacy_reader):
    from .named_joint_binding_body_v1 import named_joint_core_point_v1
    named,row=named_joint_core_point_v1(db,table=table,columns=columns,key_columns=key_columns,key=key)
    if named:return row
    handled,row=read_bound_model_reply_scope_point_v3(db,table=table,columns=columns,key_columns=key_columns,key=key)
    if handled:
        return row
    from ..runtime.domain_background_read_v3 import read_bound_d07_mutable_runtime_row_v3
    current,row=read_bound_d07_mutable_runtime_row_v3(db,table=table,columns=columns,key_columns=key_columns,key=key)
    return row if current else legacy_reader()


def model_reply_scope_rows_v3(db,*,kind,parameters,legacy_reader):
    owner=_active_observation_v3(db)
    if owner is None or owner.legacy:return legacy_reader()
    if kind not in('life_c4','life_c4_call','life_c4_call_original','life_binding','message_history','foreground_parents','children','message_jobs','outbound'):
        raise AuthorityUnavailable('unregistered model reply parentage metadata selector')
    request=('scan',kind,tuple(parameters));task=owner.scans.get(request)
    if task is None or not task.complete:raise ModelReplyScopeObservationNeededV3(request)
    with runtime_storage_quantum_v3(db)as meter:return task.require_rows_v3(meter)



def model_reply_scope_canonical_digest_v3(encoded,value):
    from ..runtime.domain_background_read_v3 import BackgroundJSONColumnV3
    if type(encoded)is BackgroundJSONColumnV3:
        encoded._actual_v3()
        owner=require_actual_model_reply_scope_column_owner_v3(encoded.owner,db=encoded.db)
        if not encoded.complete or owner.metadata_only_column_v3(encoded) or not encoded.matches_v3(value):
            raise AuthorityUnavailable('model parentage canonical digest needs actual full-value EOF')
        return encoded.semantic_sha256
    from ..runtime_contracts import canonical_digest
    return canonical_digest(value)



def read_model_reply_latest_d05_policy_revision_v3(db,namespace,policy_ref):
    owner=_active_observation_v3(db)
    if owner is None or owner.legacy:
        return False,None
    if namespace!=owner.namespace:
        raise AuthorityUnavailable('named C3 policy selector crossed its actual namespace')
    with runtime_storage_quantum_v3(db)as meter:
        owner.require_data_current_v3(meter)
        row=meter.read_fixed_row(db,'graph_d05_production_policies_v1',('revision',),
            'bot=? AND persona=? AND policy_ref=? ORDER BY revision DESC LIMIT 1',
            (*namespace.as_tuple,policy_ref))
        return True,None if row is None else row[0]

def require_model_reply_d07_parentage_descriptor_v3(parentage,*,db,namespace,issuer):
    from .model_reply_parentage_v3 import require_d07_descriptor_v3
    return require_d07_descriptor_v3(parentage,db=db,namespace=namespace,issuer=issuer)


_GROWTH_BOUND=ContextVar('sylanne_model_reply_growth_parentage_v3',default=None)

@contextmanager
def bind_model_reply_growth_question_v3(db,*,namespace,question,original_ref,original_digest):
    owner=_active_observation_v3(db)
    if owner is None or owner.legacy:
        yield
        return
    from dataclasses import asdict
    from ..runtime.d07_method_growth_semantic_v2 import D07MethodGrowthSemanticQuestionV2
    from ..runtime.domain_background_read_v3 import background_json_loads_v3,background_json_matches_v3
    if type(question)is not D07MethodGrowthSemanticQuestionV2 or namespace!=owner.namespace:
        raise AuthorityUnavailable('actual signed growth semantic parentage required')
    row=model_reply_scope_point_v3(db,table='graph_d07_execution_originals_v1',
        columns=('payload_json','payload_digest','signature'),key_columns=('bot','persona','kind','original_ref'),
        key=(*namespace.as_tuple,'semantic_question',original_ref),legacy_reader=lambda:None)
    if(row is None or row[1]!=original_digest or not row[0].complete or row[0].sha256!=original_digest
            or not background_json_matches_v3(row[0],asdict(question))):
        raise AuthorityUnavailable('growth parentage lost its actual signed semantic original')
    from ..runtime_contracts import canonical_serialize
    owner.verifier._issuer._signer.verify('d07.execution-original.v1',
        canonical_serialize(
            (namespace,'semantic_question',original_ref,original_digest)),row[2])
    proof=(question,row[0],original_digest)
    owner.growth_heads[question.source_head.key.token]=(proof,question.source_head,question.source_digest,'source')
    owner.growth_heads[question.proposal_head.key.token]=(proof,question.proposal_head,question.proposal_digest,'proposal')
    token=_GROWTH_BOUND.set((owner,question))
    try:
        yield
    finally:
        _GROWTH_BOUND.reset(token)

def read_model_reply_growth_head_commitment_v3(db,*,namespace,version):
    owner=_active_observation_v3(db)
    if owner is None or owner.legacy:
        return False,None
    bound=_GROWTH_BOUND.get()
    if(bound is None or bound[0]is not owner or namespace!=owner.namespace
            or version not in(bound[1].proposal_head,bound[1].source_head)):
        raise AuthorityUnavailable('growth commitment needs its actual signed semantic head')
    row=model_reply_scope_point_v3(db,table='graph_atoms',columns=('revision','value','valid'),
        key_columns=('token',),key=(version.key.token,),legacy_reader=lambda:None)
    if row is None:return True,None
    column=row[1]
    if not column.complete:raise AuthorityUnavailable('growth head lacks actual raw/semantic EOF')
    return True,(row[0],row[2],column.semantic_sha256)

def read_model_reply_growth_proposal_v3(db,*,namespace,version):
    owner=_active_observation_v3(db)
    if owner is None or owner.legacy:return False,None
    bound=_GROWTH_BOUND.get()
    if bound is None or bound[0]is not owner or namespace!=owner.namespace or version!=bound[1].proposal_head:
        raise AuthorityUnavailable('growth proposal needs its actual signed semantic head')
    row=model_reply_scope_point_v3(db,table='graph_atoms',columns=('value',),key_columns=('token',),
        key=(version.key.token,),legacy_reader=lambda:None)
    from ..runtime.domain_background_read_v3 import background_json_loads_v3
    return True,None if row is None else background_json_loads_v3(row[0])


def read_model_reply_responsibility_history_v3(db,*,namespace,responsibility,original,version,expected_digest):
    owner=_active_observation_v3(db)
    if owner is None or owner.legacy:
        return False,None
    from ..runtime.foreground_cycle_v1 import ForegroundResponsibilityV1
    from ..domains.d01.production_operations_v1 import plain_v1
    from ..runtime.domain_background_read_v3 import background_json_matches_v3,background_json_loads_v3
    if type(responsibility)is not ForegroundResponsibilityV1 or namespace!=owner.namespace:
        raise AuthorityUnavailable('actual foreground responsibility original required')
    create_id=original['receipt'].operation_id
    payload=model_reply_scope_point_v3(db,table='graph_domain_production_originals_v1',
        columns=('original_payload_json','original_digest','read_versions_json'),
        key_columns=('bot','persona','operation_id'),key=(*namespace.as_tuple,create_id),legacy_reader=lambda:None)
    if(payload is None or not payload[0].complete or payload[0].sha256!=payload[1]
            or not background_json_matches_v3(payload[0],original['payload'])
            or original['payload']['provenance']['foreground_responsibility']!=plain_v1(responsibility)
            or tuple(v for v in original['read_versions']if v.key==version.key)!=(version,)):
        raise AuthorityUnavailable('foreground historical commitment lost its actual create/read member')
    pairs={(responsibility.source_ref,responsibility.source_digest),
        (responsibility.self_mapping_ref,responsibility.self_mapping_digest),
        (responsibility.owner_guard.grant_ref,responsibility.owner_guard.grant_digest)}
    if(version.key.token,expected_digest)not in pairs:
        raise AuthorityUnavailable('foreground historical commitment is not its actual responsibility member')
    owner.history_commitments[(version.key.token,version.revision)]=(payload[0],version,expected_digest,
        version.key.token==responsibility.source_ref)
    row=model_reply_scope_point_v3(db,table='graph_history',columns=('value','valid'),
        key_columns=('token','revision'),key=(version.key.token,version.revision),legacy_reader=lambda:None)
    if row is None:return True,None
    column=row[0]
    if not column.complete:raise AuthorityUnavailable('foreground historical commitment lacks actual cell EOF')
    value=None if version.key.token==responsibility.source_ref else background_json_loads_v3(column)
    return True,(row[1],column.semantic_sha256,value)

def observe_authority_model_reply_scope_v3(verifier,*,model_service,credential,subject,holder,
        intent,expected_anchor,permit=None):
    observation=_active_observation_v3()
    if(observation is None or observation.verifier is not verifier or observation.model_service is not model_service
            or observation.credential is not credential or observation.subject!=subject or observation.holder!=holder
            or observation.intent is not intent or observation.expected_anchor is not expected_anchor or observation.permit is not permit):
        raise AuthorityUnavailable('model reply observation requires its actual outer service lifetime')
    return observation


def require_model_reply_scope_c02_envelope_v3(db,namespace,operation_id):
    owner=_active_observation_v3(db)
    if owner is None or owner.legacy:return None
    bound=_GROWTH_BOUND.get()
    if(bound is None or bound[0]is not owner or namespace!=owner.namespace
            or bound[1].c02_operation_id!=operation_id):
        raise AuthorityUnavailable('C02 parentage needs its actual signed growth question')
    archive=model_reply_scope_point_v3(db,table='graph_first_ingress_c02_committed_seals_v2',
        columns=('schema','bundle_digest'),key_columns=('bot','persona','operation_id'),
        key=(*namespace.as_tuple,operation_id),legacy_reader=lambda:None)
    business=model_reply_scope_point_v3(db,table='graph_bundle_operations',
        columns=('digest','activity_id','effect_id','commit_seq'),key_columns=('bot','persona','operation_id'),
        key=(*namespace.as_tuple,operation_id),legacy_reader=lambda:None)
    if archive is None or business is None:
        raise AuthorityUnavailable('actual committed C02 parentage archive/business is absent')
    event=model_reply_scope_point_v3(db,table='graph_events',columns=('digest','epoch_revision'),
        key_columns=('bot','persona','session','event_id'),
        key=(*namespace.as_tuple,business[1],operation_id),legacy_reader=lambda:None)
    if event is None:raise AuthorityUnavailable('actual committed C02 parentage event is absent')
    kernel=owner.c02_readers.get(operation_id)
    if kernel is None:
        from ..runtime.c02_bundle_mechanical_read_v3 import C02BundleMechanicalReadV3
        kernel=C02BundleMechanicalReadV3(namespace=namespace,operation_id=operation_id,
            archive_schema=archive[0],archive_digest=archive[1],business=business,event=event,operation=owner.operation)
        owner.c02_readers[operation_id]=kernel
    row=model_reply_scope_point_v3(db,table='graph_first_ingress_c02_committed_seals_v2',
        columns=('bundle_json',),key_columns=('bot','persona','operation_id'),
        key=(*namespace.as_tuple,operation_id),legacy_reader=lambda:None)
    if row is None or not row[0].complete or not kernel.complete:
        raise AuthorityUnavailable('C02 parentage requires actual full column/typed semantic EOF')
    if (kernel.sha256,kernel.byte_count)!=(row[0].sha256,row[0].byte_count):
        raise AuthorityUnavailable('C02 parentage kernel changed its actual column EOF')
    return kernel.envelope


def read_model_reply_foreground_cause_history_v3(db,*,cause,receipt):
    owner=_active_observation_v3(db)
    if owner is None or owner.legacy:return False,None
    from ..runtime.foreground_cycle_v1 import ForegroundPostC02CauseV1,foreground_post_c02_cause_ref_v1
    from ..runtime.c09_life_originals_v1 import FOREGROUND_CAUSE_KIND
    from ..runtime.d11_life_preparation_v1 import _read
    from ..runtime.domain_background_read_v3 import background_json_matches_v3,background_json_loads_v3
    from ..memory_types import source_key
    if type(cause)is not ForegroundPostC02CauseV1 or cause.namespace!=owner.namespace:
        raise AuthorityUnavailable('actual signed foreground cause namespace required')
    ref=foreground_post_c02_cause_ref_v1(owner.namespace,cause.c02_operation_id)
    original=_read(db,issuer=owner.verifier._issuer,namespace=owner.namespace,kind=FOREGROUND_CAUSE_KIND,ref=ref)
    if(original is None or original[1]!=cause.c02_operation_id or original[0]!=asdict(cause)):
        raise AuthorityUnavailable('foreground history lost its actual signed cause')
    proof=model_reply_scope_point_v3(db,table='graph_d11_life_originals_v1',
        columns=('payload_json','payload_digest','signature'),key_columns=('bot','persona','kind','original_ref'),
        key=(*owner.namespace.as_tuple,FOREGROUND_CAUSE_KIND,ref),legacy_reader=lambda:None)
    if not proof[0].complete or proof[0].sha256!=proof[1]:
        raise AuthorityUnavailable('foreground cause lacks actual complete raw EOF')
    envelope=require_model_reply_scope_c02_envelope_v3(db,owner.namespace,cause.c02_operation_id)
    if (receipt.operation_id!=cause.c02_operation_id or receipt.status!='committed'
            or receipt.commit_seq!=cause.commit_seq):
        raise AuthorityUnavailable('foreground cause changed its actual committed C02')
    from ..runtime_contracts import canonical_digest
    if canonical_digest(receipt)!=cause.c02_receipt_digest:
        raise AuthorityUnavailable('foreground cause C02 receipt commitment differs')
    from ..graph_types import AtomKey
    source=AtomKey.from_token(cause.source_ref)
    version=next((v for v in receipt.read_versions if v.key==source and v.revision==cause.source_revision),None)
    if(version is None or version not in envelope.version_guard.read_versions
            or cause.source_ref not in envelope.source_qualification.source_refs):
        raise AuthorityUnavailable('foreground cause lost its actual C02 Source member')
    episodes=tuple(v for v in receipt.write_versions if v.key.type_name=='memory.episode.v1')
    traces=tuple(v for v in receipt.write_versions if v.key.type_name=='memory.subjective_trace.v2')
    if len(episodes)!=1 or len(traces)!=1:
        raise AuthorityUnavailable('foreground cause needs its exact committed episode/trace members')
    for member,kind in ((version,'source'),(episodes[0],'episode'),(traces[0],'trace')):
        if NamespaceId.from_key(member.key)!=owner.namespace:
            raise AuthorityUnavailable('foreground cause history member crossed namespace')
        owner.cause_history[(member.key.token,member.revision)]=(proof[0],proof[1],cause,kind)
    source_row=model_reply_scope_point_v3(db,table='graph_history',columns=('value','valid'),
        key_columns=('token','revision'),key=(source.token,version.revision),legacy_reader=lambda:None)
    if(source_row is None or source_row[1]!=1 or source_row[0].semantic_sha256!=cause.source_digest
            or source_row[0]not in owner.source_headers):
        raise AuthorityUnavailable('foreground cause lost its original immutable validated Source')
    source_id=owner.source_headers[source_row[0]]['source_id']
    if source_key(*owner.namespace.as_tuple,source_id)!=source:
        raise AuthorityUnavailable('foreground cause Source metadata changed its actual key')
    from ..runtime.ingress_observation import read_committed_ingress_identity
    ingress=read_committed_ingress_identity(db,owner.namespace,source_id)
    if ingress is None:raise AuthorityUnavailable('foreground cause has no actual committed ingress identity')
    import json
    ingress_operation=json.loads(ingress.identity_json)['operation_id']
    event=model_reply_scope_point_v3(db,table='graph_events',columns=('revisions',),
        key_columns=('bot','persona','session','event_id'),
        key=(*owner.namespace.as_tuple,receipt.activity_id,cause.c02_operation_id),legacy_reader=lambda:None)
    if event is None:raise AuthorityUnavailable('foreground cause lost actual C02 Graph event')
    from ..runtime.foreground_cycle_v1 import _reply_event_version_rows_v3
    versions=_reply_event_version_rows_v3(event[0])
    metadata=[]
    for member in (episodes[0],traces[0]):
        row=model_reply_scope_point_v3(db,table='graph_history',columns=('event_id','value','valid'),
            key_columns=('token','revision'),key=(member.key.token,member.revision),legacy_reader=lambda:None)
        if(row is None or row[0]!=cause.c02_operation_id or row[2]!=1 or row[1]not in owner.cause_headers):
            raise AuthorityUnavailable('foreground cause lost its exact validated episode/trace history')
        metadata.append(owner.cause_headers[row[1]])
    return True,(source_id,ingress_operation,versions,metadata[0],metadata[1])


def read_model_reply_latest_budget_grant_metadata_v3(db,lease_id):
    owner=_active_observation_v3(db)
    if owner is None or owner.legacy:return False,None
    with runtime_storage_quantum_v3(db)as meter:
        owner.require_data_current_v3(meter)
        row=meter.read_fixed_row(db,'runtime_budget_grants',('version','status'),
            'lease_id=? ORDER BY version DESC LIMIT 1',(lease_id,))
        return True,row
