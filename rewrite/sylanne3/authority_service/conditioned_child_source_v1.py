"""Independent Core Source lifetime for the fixed conditioned-child recipe.

The paired Host's retained inputs never constitute Core permission.
"""
from contextlib import contextmanager
from pathlib import Path
from threading import get_ident
from weakref import WeakKeyDictionary,WeakSet
import codecs
import hashlib
import json
import sqlite3

from .contract import AuthorityUnavailable
from .conditioned_child_contract_v1 import ConditionedChildSelectorV1,ROOT_WORK_KIND
from ..runtime_contracts import NamespaceId,canonical_digest,canonical_serialize
from ..runtime_storage_v3 import (bind_runtime_database_from_control_v3,begin_runtime_storage_operation_v3,
    bind_runtime_storage_operation_v3,finish_runtime_storage_operation_v3,runtime_storage_quantum_v3,
    begin_runtime_cell_read_v3,_runtime_bounded_fixed_row_v3)
from ..runtime.current_method_learning_read_v3 import MethodJSONColumnV3,_MethodJSONStreamV3
from ..runtime.dispatch_current_inventory_v3 import _heap,_freeze_value_v3,_detach_value_v3

_ISSUER=object()
_WORKS=WeakSet()
_COLUMNS=WeakKeyDictionary()


class _ConditionedCoreColumnV1(MethodJSONColumnV3):
    def __init__(self,issuer,owner,*,table,column,key_columns,key,profile,cell=None):
        if issuer is not _ISSUER:raise TypeError('conditioned Core column has no public issuer')
        require_conditioned_core_source_work_v1(owner)
        self.owner,self.db,self.operation=owner,owner.db,owner.operation
        self.table,self.column,self.key_columns,self.key=table,column,tuple(key_columns),tuple(key)
        self.cell,self.profile,self.source=cell,profile,profile=='source_metadata'
        owner._require_column_recipe(table,column,self.key_columns,self.key,profile)
        self.general_metadata_profile=None
        self.general_metadata_fields_seen=set()
        self.nodes,self.value,self.scalar={},None,bytearray()
        self.text_parts,self.text_chars,self.text_high=[],[],None
        self.fragment,self.fragment_offset,self.offset,self.total=b'',0,0,None
        self.complete,self.frozen,self.sha256,self.byte_count=False,None,None,None
        self.reserved,self.wire_parts,self.wire=0,[],None
        self.canonical_digest=None
        self.semantic_decoder=self.semantic_hash=None
        if cell is not None and cell.header[0]=='canonical-json.utf8.v1':
            self.semantic_decoder=codecs.getincrementaldecoder('utf8')('strict');self.semantic_hash=hashlib.sha256()
        if self.source:
            from ..runtime.c09_graph_row_codec_v2 import C09MemorySourceJSONStreamV3
            self.parser=C09MemorySourceJSONStreamV3(ensure_ascii=cell is None or cell.header[0]!='canonical-json.utf8.v1')
        else:
            from ..runtime.conditioned_producer_source_metadata_v3 import ConditionedMetadataJSONStreamV3
            from ..runtime.conditioned_producer_source_metadata_v3 import ConditionedClaimCaptureV3
            from types import SimpleNamespace
            self.nested_locators=[];self.reader=owner
            capture=SimpleNamespace(column=self,reader=owner)
            self.claim_capture=ConditionedClaimCaptureV3(capture)if(profile=='graph_metadata'and owner._is_persona_plan_key(self.key[0]))else None
            self.parser=ConditionedMetadataJSONStreamV3(self,ensure_ascii=cell is None or cell.header[0]!='canonical-json.utf8.v1',wire_metadata=self.claim_capture)
        _COLUMNS[self]=(owner,table,column,self.key_columns,self.key,profile,cell,self.source)

    def _actual(self):
        require_conditioned_core_source_work_v1(self.owner)
        if _COLUMNS.get(self)!=(self.owner,self.table,self.column,self.key_columns,self.key,self.profile,self.cell,self.source):
            raise AuthorityUnavailable('conditioned Core column changed its private actual recipe')
        return self

    def retain_path_v3(self,path):
        from ..runtime.conditioned_producer_source_metadata_v3 import retain_conditioned_business_locator_path_v3,retain_conditioned_producer_locator_path_v3
        if self.profile=='life_prepared_metadata':
            from ..runtime.life_prepared_source_metadata_v3 import retain_life_prepared_locator_path_v3
            return retain_life_prepared_locator_path_v3(path)
        if self.profile=='signed_metadata':
            if not path:return True
            if path[0]=='read_rows':return len(path)<3 or path[2]in {'ref','revision','valid'}
            if path[0]=='terminal':return len(path)<2 or path[1]=='binding'
            return path[0]in {'schema','namespace','binding','source_head','owner_guard','registration_operation_id',
                'goal_ref','project_ref','original_ref','prepared_original_ref','audience','purpose','operation_id',
                'execution_id','job_id','work_kind','parent_budget_ref','stage_input_digest','prepare_operation_id',
                'source_refs','source_read_versions','selector','content_selector','frozen_ref','frozen_digest',
                'ordered_phase_originals','full_check_original_ref','full_check_original_digest','terminal','write_commitments',
                'producing_operation_id','prepared_digest','result_ref'}
        if self.profile=='producer_metadata':
            if len(path)>=2 and path[:2]==('provenance','prepared_candidates'):
                if len(path)<=2:return True
                if path[2]=='candidates':return len(path)<5 or path[4]in {'quote_ref','quote_digest','future_identity'}
                return path[2]in {'schema','namespace','read_versions','query_coverage','source_refs','preparation_operation_id',
                    'selection_operation_id','future_decision_ref','value_evaluation_operation_id','value_evaluation_digest','parent_budget_lease_ref'}
            if path and path[0]=='query_coverage':return True
            if len(path)>=2 and path[:2]==('provenance','artifact_task_milestone'):
                return len(path)<=2 or path[2]in {'selector','source_head','original_deadline_utc'}
            if len(path)>=2 and path[:2]==('provenance','actual_progress'):
                return len(path)<=2 or path[2]in {'artifact_ref','terminal_ref','source_refs','project_ref','recipe_ref'}
            return(retain_conditioned_producer_locator_path_v3(path)
            or retain_conditioned_business_locator_path_v3(('producer',self.key[-1]),path))
        if self.profile=='graph_metadata':return retain_conditioned_business_locator_path_v3(('head',self.key[0]),path)
        return True

    def _reserve_v3(self,extra=0):
        size=_heap((self.nodes,self.value,self.scalar,self.text_parts,self.text_chars,self.fragment,self.general_metadata_fields_seen))+extra+65536
        if self.source:size+=self.parser._source_heap_bytes()
        if size>self.reserved:self.operation.retain(size-self.reserved);self.reserved=size

    def _emit_v3(self,event):
        if event.kind=='key'and len(event.path)==1:self.general_metadata_fields_seen.add(event.key)
        if self.retain_path_v3(event.path):MethodJSONColumnV3._emit_v3(self,event)

    def advance(self,meter):
        from ..runtime.c09_paged_sql_v2 import legacy_cell_read_transaction_v2,read_legacy_sql_cell_fragment_v2,_quote
        self._actual();self.owner.require_current(meter=meter)
        if self.complete:return True
        if self.fragment_offset<len(self.fragment):
            end=min(self.fragment_offset+1024,len(self.fragment));chunk=self.fragment[self.fragment_offset:end]
            self._reserve_v3(131072)
            self.parser.feed(chunk,(lambda event:None)if self.source else self._emit_v3)
            if self.semantic_decoder is not None:
                from .d07_authority_model_source_read_v3 import _D07AuthorityGraphMetadataColumnV3
                _D07AuthorityGraphMetadataColumnV3._semantic_v3(self,chunk,meter)
            self.fragment_offset=end;self._flush_text_v3();return False
        if self.cell is not None:chunk=self.cell.read_fragment(meter=meter)
        else:
            where=' AND '.join(_quote(name)+'=?'for name in self.key_columns)
            with legacy_cell_read_transaction_v2(self.db):
                if self.total is None:
                    header=self.db.execute('SELECT typeof('+_quote(self.column)+'),length(CAST('+_quote(self.column)
                        +' AS BLOB)) FROM '+_quote(self.table)+' WHERE '+where,self.key).fetchone();meter.charge_read(16)
                    if header is None or header[0]!='text':raise AuthorityUnavailable('conditioned Core column disappeared or changed kind')
                    self.total=header[1]
                if self.offset<self.total:
                    chunk,total,kind=read_legacy_sql_cell_fragment_v2(self.db,table=self.table,column=self.column,
                        where=where,parameters=self.key,start=self.offset,length=min(16384,self.total-self.offset),meter=meter)
                    if(total,kind)!=(self.total,'text'):raise AuthorityUnavailable('conditioned Core column changed while reading')
                    self.offset+=len(chunk)
                else:chunk=None
        if chunk is not None:self.fragment,self.fragment_offset=chunk,0;return False
        parsed=self.parser.finish()
        if self.cell is not None:
            if(parsed.sha256,parsed.byte_count)!=(self.cell.finish(meter=meter),self.cell.header[3]):
                raise AuthorityUnavailable('conditioned Core complete cell EOF changed')
        elif parsed.byte_count!=self.total:raise AuthorityUnavailable('conditioned Core complete original EOF changed')
        if self.semantic_decoder is not None:
            from .d07_authority_model_source_read_v3 import _D07AuthorityGraphMetadataColumnV3
            _D07AuthorityGraphMetadataColumnV3._semantic_v3(self,b'',meter,final=True)
            self.canonical_digest=self.semantic_hash.hexdigest()
        else:self.canonical_digest=parsed.sha256
        if self.source:
            self.value=dict(self.parser._source_metadata)
            for key in('audiences','purposes','parent_source_ids'):self.value[key]=tuple(self.value[key])
        self._reserve_v3(_heap(self.value)*2+1024)
        self.frozen=_freeze_value_v3(self.value);self.sha256,self.byte_count=parsed.sha256,parsed.byte_count
        if not self.source and self.claim_capture is not None:
            self.claim_capture.finish_v3();self.nested_locators=tuple(self.claim_capture.locators)
        self.value,self.nodes,self.scalar,self.fragment,self.parser=None,{},bytearray(),b'',None
        self.semantic_decoder=self.semantic_hash=None;self.complete=True;return True

    def json_v3(self):
        self._actual()
        if not self.complete or self.source:raise AuthorityUnavailable('only complete selected Core body or metadata may be detached')
        self.operation.retain(_heap(self.frozen)+1024)
        return _detach_value_v3(self.frozen)


class _ConditionedCoreSourceWorkV1:
    def __init__(self,issuer,service,*,credential,subject,permit,selector,current_self,owner_entry):
        if issuer is not _ISSUER or type(selector)is not ConditionedChildSelectorV1:
            raise TypeError('conditioned Core Source requires its private installed factory')
        self.service,self.credential,self.subject,self.permit,self.selector=service,credential,subject,permit,selector
        self.namespace,self.current_self,self.owner_entry=selector.namespace,current_self,owner_entry
        self.thread,self.closed,self.operation=get_ident(),False,None
        self.db=self.handle=None;self.selection_digest=None;self.stamp=None
        self.phase='metadata';self.read_versions={};self.graph_metadata={};self.graph_bodies={}
        self.producers={};self.producer_bodies={};self.sources={};self.source_commitments={};self.columns=[]
        self.column_recipes=set();self.selected_graph_keys=set();self.selected_producer_ids={selector.producer_operation_id}
        self.signed_metadata={};self.signed_bodies={};self.producer_fences={};self.producer_bundles={};self.producer_fence_candidates={};self.finished_proofs={};self.extra_source_groups=[];self.quotes={}
        self.metadata_locators=[];self.history_metadata={};self.query_pages={};self.selected_history=set();self.frozen_history={}
        from ..graph_types import owner_grant_key
        from ..runtime.domain_production_contracts_v1 import ProductionOwnerGuardV1
        head=owner_entry[1].head
        self.owner_guard=ProductionOwnerGuardV1(owner_grant_key(*self.namespace.as_tuple).token,head.grant_revision,
            head.grant_digest.removeprefix('sha256:'),head.guard.authorization_head.removeprefix('sha256:'))
        self._observe()
        control=service._source_location._control
        from .daemon import _bootstrap_control_quantum_v3
        with _bootstrap_control_quantum_v3(control):
            context=control.read_verified_current_storage_v3();context.require_current('business')
            actual=service._core._runtime_storage_v3
            if(actual is None or actual.context._reader is not control or
                    (actual.context.manifest_digest,actual.context.pointer_version)!=(context.manifest_digest,context.pointer_version)):
                raise AuthorityUnavailable('conditioned Core Source changed selected actual storage')
            path=Path(next(item for item in context.manifest['members']if item['role']=='graph')['resolved_path']).resolve(strict=True)
            if path!=service._owner_storage.graph_path:raise AuthorityUnavailable('conditioned Core Source crossed its selected Graph')
            self.db=sqlite3.connect(path.as_uri()+'?mode=ro',uri=True);self.db.execute('PRAGMA query_only=ON')
            try:self.handle=bind_runtime_database_from_control_v3(self.db,control=control,role='graph')
            except BaseException:self.db.close();self.db=None;raise
        try:
            self.operation=begin_runtime_storage_operation_v3(self.db,permit.operation_id,selector.original_deadline_utc)
            self.selection_digest=self.operation.selection_digest;_WORKS.add(self)
        except BaseException:self.handle.close();self.db.close();self.db=None;raise

    def _observe(self):
        from .current_conditioned_child_v1 import require_current_conditioned_core_call_v1
        from .owner_location_read_v3 import require_owner_location_caller_proof_v3
        require_current_conditioned_core_call_v1(self.service,credential=self.credential,subject=self.subject,
            permit=self.permit,selector=self.selector)
        location,call,proof,lineage=self.owner_entry
        call._check_permission_v3();require_owner_location_caller_proof_v3(proof,phase='before')
        if(call.service is not self.service or call.permit!=self.permit or call.location is not location or not lineage.complete):
            raise AuthorityUnavailable('conditioned Core Source lost its independently completed Owner EOF')

    def require_current(self,*,meter):
        require_conditioned_core_source_work_v1(self)
        self.handle.require_current(meter)
        epoch=meter.read_fixed_row(self.db,'graph_epochs',('revision',),'bot=? AND persona=?',self.namespace.as_tuple)
        rights=meter.read_fixed_row(self.db,'graph_authority_epochs',('access_epoch','delete_epoch'),'bot=? AND persona=?',self.namespace.as_tuple)
        if epoch is None or rights is None:raise AuthorityUnavailable('conditioned Core Graph epochs are absent')
        stamp=(*epoch,*rights)
        if self.stamp is None:self.stamp=stamp
        elif self.stamp!=stamp:raise AuthorityUnavailable('conditioned Core Source or rights epoch changed')
        return self

    @contextmanager
    def quantum(self):
        self._observe()
        if self.db.in_transaction:raise AuthorityUnavailable('conditioned Core Source cannot inherit Graph SQL')
        with bind_runtime_storage_operation_v3(self.operation,self.db):
            with runtime_storage_quantum_v3(self.db)as meter:
                self.db.execute('BEGIN')
                try:self.require_current(meter=meter);yield meter;self.require_current(meter=meter)
                finally:self.db.execute('ROLLBACK')
        self._observe()

    def _fixed(self,table,columns,key_columns,key):
        from ..runtime.c09_paged_sql_v2 import _quote
        with self.quantum()as meter:
            return _runtime_bounded_fixed_row_v3(self.db,meter,table,columns,
                ' AND '.join(_quote(name)+'=?'for name in key_columns),tuple(key))




    @staticmethod
    def _is_persona_plan_key(ref):
        from ..graph_types import AtomKey
        return AtomKey.from_token(ref).type_name=='d01.persona_plan.v1'



    def _graph_body(self,ref,*,revision=None):
        from ..graph_types import AtomKey,GraphAtom,owner_grant_key
        if self.phase!='body':raise AuthorityUnavailable('conditioned Core protected graph body requires independent ALL Source')
        key=AtomKey.from_token(ref)
        if key==owner_grant_key(*self.namespace.as_tuple):
            return GraphAtom(key,self.owner_guard.grant_revision,self.owner_entry[0][1],True)
        cache=(ref,revision)
        if cache in self.graph_bodies:return self.graph_bodies[cache]
        if revision is None:
            if ref not in self.graph_metadata:raise AuthorityUnavailable('conditioned Core body was not selected by complete metadata')
            metadata=self.graph_metadata[ref]
            if metadata is None:return GraphAtom(key,0,{},False)
            header,locator,digest=metadata;table='graph_atoms';key_columns=('token','bot','persona');selected=(ref,*self.namespace.as_tuple)
            rev,valid,cell_id=header
        else:
            if cache not in self.frozen_history:raise AuthorityUnavailable('conditioned Core historical body lacks its exact frozen metadata EOF')
            header,locator,digest=self.frozen_history[cache];table='graph_history';key_columns=('token','revision');selected=cache
            rev,valid,cell_id=revision,header[3],header[4]
        if not valid:return GraphAtom(key,rev,{},False)
        if key.type_name in{'memory.source','memory.access','d06.source_correction_head.v1'}:
            raise AuthorityUnavailable('Source metadata qualification never grants an arbitrary Source text read')
        recipe=self._register_column(table,'value',key_columns,selected,'body')
        column=self._column(*recipe[:4],profile=recipe[4],cell_id=cell_id)
        if column.canonical_digest!=digest:raise AuthorityUnavailable('conditioned Core actual body changed after its metadata EOF')
        body=column.json_v3()
        from ..runtime.domain_production_erasure_v1 import _production_value_type_registry_v1
        registry=_production_value_type_registry_v1();registry.validate(key,body)
        atom=GraphAtom(key,rev,body,bool(valid));self.graph_bodies[cache]=atom
        return atom

    def _producer_body(self,operation_id):
        from ..runtime.domain_production_original_codec_v1 import ORIGINAL_COLUMNS,decode_domain_production_original_row_v1
        from ..runtime.domain_production_erasure_v1 import _production_value_type_registry_v1,decode_typed_production_value_v1
        from ..runtime.domain_production_registry_v1 import installed_operation_v1
        from ..runtime_contracts import canonical_serialize
        if self.phase!='body'or operation_id not in self.producers:
            raise AuthorityUnavailable('conditioned Core actual producing body lacks independent Source qualification')
        if operation_id in self.producer_bodies:return self.producer_bodies[operation_id]
        selected=(*self.namespace.as_tuple,operation_id);key_columns=('bot','persona','operation_id')
        metadata=self._fixed('graph_domain_production_originals_v1',
            tuple(name for name in ORIGINAL_COLUMNS if not name.endswith('_json')),key_columns,selected)
        if metadata is None:raise AuthorityUnavailable('conditioned Core actual producer body disappeared')
        row=dict(zip((name for name in ORIGINAL_COLUMNS if not name.endswith('_json')),metadata,strict=True))
        for name in('original_payload_json','read_versions_json','receipt_json'):
            recipe=self._register_column('graph_domain_production_originals_v1',name,key_columns,selected,'body')
            column=self._column(*recipe[:4],profile=recipe[4]);value=column.json_v3()
            self.operation.retain(_heap(value)*3+column.byte_count*4+4096)
            row[name]=canonical_serialize(value)
        closed=decode_domain_production_original_row_v1(tuple(row[name]for name in ORIGINAL_COLUMNS),self.namespace,
            registry=_production_value_type_registry_v1())
        import json
        payload=json.loads(row['original_payload_json']);header,locator,bundle,cause=self.producers[operation_id]
        if(row['domain'],row['operation_kind'],row['request_digest'],row['original_digest'],row['receipt_digest'],row['bundle_digest'])!=header:
            raise AuthorityUnavailable('conditioned Core producer changed after its complete locator EOF')
        operation=installed_operation_v1(row['operation_kind'])
        request=decode_typed_production_value_v1(payload['request'],operation.request_type)
        if canonical_digest(request)!=row['request_digest']:
            raise AuthorityUnavailable('conditioned Core actual producer request commitment differs')
        actual_bundle=self._fixed('graph_bundle_operations',('digest','commit_seq'),key_columns,selected)
        if actual_bundle!=bundle:raise AuthorityUnavailable('conditioned Core actual producer W01 COMMIT changed')
        execution=payload['provenance'].get('conditioned_child_execution_v1')
        if execution is not None:
            from .conditioned_child_contract_v1 import (conditioned_child_from_wire_v1,
                conditioned_child_fence_operation_id_v1,conditioned_child_finish_digest_v1)
            selector=conditioned_child_from_wire_v1(execution,ConditionedChildSelectorV1)
            fence,permit=self.producer_fences[operation_id]
            if(selector.operation_id!=operation_id or selector.operation_kind!=row['operation_kind']
                    or selector.typed_request_digest!=row['request_digest']or selector.typed_request_json!=canonical_serialize(payload['request'])
                    or permit.operation_id!=conditioned_child_fence_operation_id_v1(selector)
                    or fence[6]!=conditioned_child_finish_digest_v1(selector,permit)):
                raise AuthorityUnavailable('conditioned producer selector is not its actual exact finished semantic WRITE original')
        result=(payload,row,closed,request);self.producer_bodies[operation_id]=result
        return result

    def _require_actual_graph_origin(self,atom,kind=None):
        from ..domains.d01.production_operations_v1 import plain_v1
        key=atom.key;selected=(key.token,atom.revision)
        header=self.history_metadata.get(selected)
        if header is None:
            historical=self.frozen_history.get(selected)
            if historical is None:raise AuthorityUnavailable('conditioned Core graph body lacks its actual historical producer origin')
            header=historical[0]
        payload,row,_,_=self._producer_body(header[2])
        members=tuple(write for write in payload['writes']if write['key']==key.token)
        if(len(members)!=1 or members[0]['value']!=plain_v1(atom.value)
                or kind is not None and row['operation_kind']!=kind):
            raise AuthorityUnavailable('conditioned Core graph body is not the exact actual W01 producer member')
        return payload,row

    def _life_prepared_metadata(self,original_ref):
        from ..runtime.life_prepared_source_metadata_v3 import life_prepared_locator_spec_v3,finish_life_prepared_locator_v3
        if original_ref in self.life_prepared:return self.life_prepared[original_ref]
        spec=life_prepared_locator_spec_v3(self.namespace,original_ref)
        table,column,key_columns,key,headers,_,_=spec
        header=self._fixed(table,headers,key_columns,key)
        if header is None:raise AuthorityUnavailable('conditioned Core Life prepared original is absent')
        recipe=self._register_column(table,column,key_columns,key,'life_prepared_metadata')
        value=self._column(*recipe[:4],profile=recipe[4])
        facts=finish_life_prepared_locator_v3(namespace=self.namespace,original_ref=original_ref,header=header,
            projection=value.json_v3(),fields_seen=value.general_metadata_fields_seen,
            whole_digest=value.canonical_digest,signer=self.service.issuer._signer)
        self.life_prepared[original_ref]=facts
        self.signed_metadata[(table,'prepared',original_ref)]=(header,value.json_v3(),value.canonical_digest)
        self.selected_producer_ids.add(facts.producing_operation_id)
        for version in facts.read_versions:self.selected_graph_keys.add(version.key)
        return facts

    def _prepare_metadata_closure(self):
        import json
        from ..graph_types import AtomKey,owner_grant_key
        from ..runtime.conditioned_self_operations_v1 import conditioned_request_from_wire_v1
        selector=self.selector
        self.request=conditioned_request_from_wire_v1(selector.operation_kind,json.loads(selector.typed_request_json))
        base=('d01.persona_activation.v1','d01.persona_plan.v1')
        families={
            'register_current_prediction_v1':(*base,'d07.current_interpretation.v1','d07.simulation_branch.v1'),
            'record_current_simulation_v1':(*base,'d07.simulation_branch.v1'),
            'resolve_current_prediction_v1':base,
            'review_current_conditioned_self_v1':(*base,'d01.conditioned_capability_revision.v1','d01.conditioned_strategy_revision.v1',
                'd01.condition_predicate.v1','d01.calibration_policy.v1','d01.conditioned_self_review.v1',
                'd07.prediction_record.v1','d07.prediction_resolution.v1','d08.commitment.v1','d02.body_state.v1'),
            'match_current_conditioned_strategy_v1':(*base,'d07.current_interpretation.v1'),
            'select_current_conditioned_personal_step_v1':(*base,'d07.current_interpretation.v1'),
            'project_current_conditioned_life_strategy_v1':(*base,'d07.current_interpretation.v1')}
        complete=set(families[selector.operation_kind])
        event_families={
            'conditioned_simulation_committed_v1':('d07.simulation_branch.v1',),
            'conditioned_observed_outcome_committed_v1':('d07.prediction_record.v1',),
            'conditioned_calibration_resolution_committed_v1':('d01.condition_predicate.v1','d07.prediction_record.v1','d07.prediction_resolution.v1','d08.goal.v1'),
            'conditioned_method_review_committed_v1':('d01.condition_predicate.v1','d07.prediction_record.v1','d07.prediction_resolution.v1'),
            'conditioned_conditions_committed_v1':('d08.personal_plan.v1','d07.current_interpretation.v1'),
            'conditioned_life_phase_committed_v1':('d07.current_interpretation.v1',)}
        complete.update(event_families.get(selector.event_kind,()))
        if selector.phase=='child':
            census_types=(*base,'d01.conditioned_capability_revision.v1','d01.conditioned_strategy_revision.v1',
                'd01.condition_predicate.v1','d01.calibration_policy.v1','d01.conditioned_self_review.v1',
                'd07.prediction_record.v1','d07.prediction_resolution.v1','d08.commitment.v1','d02.body_state.v1',
                'd07.current_interpretation.v1','d07.simulation_forecast_plan.v1','d07.simulation_branch.v1',
                'd07.simulation_record.v1','d07.condition_match.v1','d07.self_discrepancy.v1',
                'd08.goal.v1','d08.personal_plan.v1','d10.life_project.v1','d10.project_checkpoint.v1',
                'd10.conditioned_strategy_projection.v1','d10.activity_recipe.v1')
            declared=tuple(page['type_id']for page in json.loads(selector.frozen_targets_json)['target_census']['query_coverage'])
            if len(set(declared))!=len(declared)or set(declared)!=set(census_types):
                raise AuthorityUnavailable('conditioned first-child target census changed its exact installed fixed producer families')
            complete.update(census_types)
        complete.update(('d08.commitment.v1','d02.body_state.v1')if selector.operation_kind=='review_current_conditioned_self_v1'else())
        for type_name in sorted(complete):self._metadata_inventory(type_name)
        if selector.phase=='child':
            frozen=json.loads(selector.frozen_targets_json)
            for version in frozen['target_census']['read_versions']:
                self.selected_graph_keys.add(AtomKey.from_token(version['key']))
            if selector.frozen_targets_original_ref is not None:
                row=self._fixed('graph_domain_production_originals_v1',('operation_id','domain','original_digest'),
                    ('bot','persona','original_digest'),(*self.namespace.as_tuple,selector.frozen_targets_original_digest))
                if row is None or row[1]+'-current:'+row[2][:48]!=selector.frozen_targets_original_ref:
                    raise AuthorityUnavailable('conditioned frozen first child has no exact retained actual original')
                self.frozen_producer_id=row[0];self.selected_producer_ids.add(row[0])
        self.selected_graph_keys.update(selector.allowed_write_keys)
        self.selected_graph_keys.add(owner_grant_key(*self.namespace.as_tuple))
        self.roots=set();self.life_prepared={};self.observed_at_utc=self.service._clock()
        def locators(value):
            if type(value)is str:
                try:key=AtomKey.from_token(value)
                except(ValueError,TypeError):return
                if NamespaceId.from_key(key)!=self.namespace:raise AuthorityUnavailable('conditioned Core locator crossed its original namespace')
                if key.type_name=='memory.source':self.roots.add(key.token)
                else:self.selected_graph_keys.add(key)
            elif type(value)is dict:
                ref=value.get('key',value.get('ref'));revision=value.get('revision')
                if type(ref)is str and type(revision)is int and revision>0:
                    try:version_key=AtomKey.from_token(ref)
                    except(ValueError,TypeError):version_key=None
                    if version_key is not None:
                        if NamespaceId.from_key(version_key)!=self.namespace:raise AuthorityUnavailable('conditioned frozen version crossed namespace')
                        self.selected_history.add((ref,revision))
                for item in value.values():locators(item)
            elif type(value)in(list,tuple):
                for item in value:locators(item)
        from ..domains.d01.production_operations_v1 import plain_v1
        locators(plain_v1(self.request))
        trigger=self._producer_metadata(selector.producer_operation_id,trigger=True)
        locators(trigger[1].get('read_versions',()))
        self.roots.update(trigger[3].source_refs if trigger[3]is not None else selector.source_refs)
        self._select_signed_metadata(trigger[1])
        processed=set();producer_done={selector.producer_operation_id}
        while True:
            pending=sorted(self.selected_graph_keys-processed,key=lambda key:key.token)
            historical_pending=self.selected_history-set(self.frozen_history)
            if not pending and self.selected_producer_ids<=producer_done and not historical_pending:break
            for ref,revision in sorted(historical_pending):locators(self._history_locator(ref,revision)[1])
            for key in pending:
                processed.add(key)
                if key.type_name=='memory.source':self.roots.add(key.token);continue
                if key.type_name in{'memory.access','d06.source_correction_head.v1'}:continue
                result=self._head_metadata(key.token)
                if result is None:continue
                locator=result[1]
                if locator is None:continue
                locators(locator)
                if key.type_name=='d10.life_progress.v1':
                    self._signed_locator('graph_d11_life_originals_v1','adopted_life',locator['artifact_ref'])
                terminal=locator.get('terminal_provenance')
                if type(terminal)is dict and type(terminal.get('binding'))is dict:
                    binding=terminal['binding']
                    if binding.get('namespace')!={'bot_id':self.namespace.bot_id,'persona_id':self.namespace.persona_id}:
                        raise AuthorityUnavailable('conditioned Core Life binding crossed its namespace')
                    facts=self._life_prepared_metadata(binding['prepared_original_ref']);self.roots.update(facts.source_roots)
                while self.metadata_locators:locators(self.metadata_locators.pop())
            for operation_id in sorted(self.selected_producer_ids-producer_done):
                original=self._producer_metadata(operation_id);producer_done.add(operation_id)
                locators(original[1].get('read_versions',()))
                locators(original[1].get('provenance',{}))
                self._select_signed_metadata(original[1])
            if len(self.selected_graph_keys)>1024 or len(producer_done)>128:
                raise AuthorityUnavailable('conditioned Core complete signed locator family exceeds installed bounds')
        if not self.roots<=set(selector.source_refs):
            raise AuthorityUnavailable('conditioned Core actual producer/request roots exceed the selected immutable Source scope')
        grant=self.owner_entry[0][1]
        if(selector.purpose not in grant['purposes']or not set(selector.audiences)<=set(grant['audiences'])
                or 'workbench.create'not in grant['capabilities']):
            raise AuthorityUnavailable('conditioned Core current Owner does not cover the fixed child purpose and audiences')
        self._source_family(tuple(sorted(self.roots)),purposes=(selector.purpose,),audiences=selector.audiences)
        for roots,purposes,audiences in self.extra_source_groups:
            self._source_family(roots,purposes=purposes,audiences=audiences)
        from ..runtime.life_prepared_source_metadata_v3 import life_prepared_source_groups_v3
        for facts in self.life_prepared.values():
            for purpose,audiences,roots in life_prepared_source_groups_v3(facts):
                self._source_family(roots,purposes=(purpose,),audiences=audiences)
            for version in facts.read_versions:
                if version.key.type_name=='memory.source'and self.read_versions.get(version.key)!=version:
                    raise AuthorityUnavailable('conditioned Core Life original Source revision changed')
        if set(self.sources)!=set(selector.source_refs):
            raise AuthorityUnavailable('conditioned Core complete actual Source and parent closure differs from its immutable selector')
        self.phase='body'

    def _producer_fence_metadata(self,operation_id,bundle):
        from .v2_contract import FencePermitV2,from_wire,canonical_bytes
        from .v2_fence_store import AuthorityV2FenceStore
        selected=(*self.namespace.as_tuple,operation_id)
        header=self._fixed('graph_bundle_fences_v2',('digest','pre_graph_revision','pre_graph_epoch',
            'post_graph_revision','post_graph_epoch','finish_request_id','finish_request_digest'),
            ('bot','persona','operation_id'),selected)
        if(header is None or header[0]!=bundle[0]or header[3:5]!=(header[1]+1,header[2]+1)):
            raise AuthorityUnavailable('conditioned producer lost its exact real W01 WRITE fence')
        recipe=self._register_column('graph_bundle_fences_v2','permit_json',('bot','persona','operation_id'),selected,'permit_metadata')
        column=self._column(*recipe[:4],profile=recipe[4]);permit=from_wire(column.json_v3())
        policy=self.service.installed_bundle.installation_policy
        if(type(permit)is not FencePermitV2 or permit.operation!='write'or permit.operation_id==self.permit.operation_id
                or(permit.authority_id,permit.namespace,permit.subject,permit.holder)!=(self.permit.authority_id,
                    policy.authority_namespace,self.subject,policy.administrator_holder)
                or header[5]!='finish:'+permit.operation_id):
            raise AuthorityUnavailable('conditioned producer historical WRITE belongs to another actual installation or caller')
        self.producer_fence_candidates[operation_id]=(header,permit,bundle)
        fences=self.service._fences
        with fences._frozen()as(db,deletion,execution,_):
            self.service._core.require_current_storage_generation_locked(db,namespace=policy.authority_namespace,action='business')
            fences._current_locked(db,deletion,execution,holder=self.permit.holder,generation=self.permit.generation)
            actual=AuthorityV2FenceStore._row(db,permit.operation_id)
            if actual is not None and(AuthorityV2FenceStore._permit(actual)!=permit or actual[7]!=canonical_bytes(permit)
                    or actual[6]!='finished'or actual[8:11]!=(header[5],header[6],None)):
                raise AuthorityUnavailable('conditioned actual producing Core WRITE has another durable original state')
        if actual is None:
            from .conditioned_child_c09_finished_v1 import require_accepted_conditioned_producer_fence_v1
            actual=require_accepted_conditioned_producer_fence_v1(self,operation_id=operation_id,header=header,permit=permit,bundle=bundle)
        proof=canonical_digest((actual[:7],hashlib.sha256(bytes(actual[7])).hexdigest(),actual[8:]))
        prior=self.finished_proofs.get(operation_id)
        if prior is not None and prior!=proof:raise AuthorityUnavailable('conditioned producing Core finished original changed')
        self.finished_proofs[operation_id]=proof;self.producer_fences[operation_id]=(header,permit);self.producer_bundles[operation_id]=bundle
        return proof

    def _signed_locator(self,table,kind,ref):
        identity=(table,kind,ref)
        if identity in self.signed_metadata:return self.signed_metadata[identity]
        if table=='graph_d07_execution_originals_v1':
            if kind!='prepared':raise AuthorityUnavailable('conditioned Core signed D07 locator escaped its actual prepared recipe')
            columns=('payload_digest','signature')
        elif table=='graph_d11_life_originals_v1':
            if kind not in {'artifact_task_milestone_v2','adopted_life','prepared','c4_phase_verified','c4_phase_prepared','c4_phase_frozen'}:
                raise AuthorityUnavailable('conditioned Core signed Life locator escaped its actual fact recipe')
            columns=('producing_operation_id','payload_digest','signature')
        else:raise AuthorityUnavailable('conditioned Core unregistered signed Original table')
        selected=(*self.namespace.as_tuple,kind,ref);key_columns=('bot','persona','kind','original_ref')
        header=self._fixed(table,columns,key_columns,selected)
        if header is None:raise AuthorityUnavailable('conditioned Core actual signed prerequisite is absent')
        recipe=self._register_column(table,'payload_json',key_columns,selected,'signed_metadata')
        column=self._column(*recipe[:4],profile=recipe[4]);locator=column.json_v3()
        if column.canonical_digest!=header[-2]:raise AuthorityUnavailable('conditioned signed metadata lacks exact canonical EOF')
        sign_kind='d07.execution-original.v1'if table=='graph_d07_execution_originals_v1'else'd11.life-original.v1'
        self.service.issuer._signer.verify(sign_kind,canonical_serialize((self.namespace,kind,ref,header[-2])),header[-1])
        self.signed_metadata[identity]=(header,locator,column.canonical_digest)
        self.roots.update(locator.get('source_refs',()))
        if len(header)==3:self.selected_producer_ids.add(header[0])
        rows=locator.get('read_rows',())
        roots=[]
        from ..graph_types import AtomKey,GraphVersion
        from ..runtime.domain_production_erasure_v1 import decode_typed_production_value_v1
        for row in rows:
            key=AtomKey.from_token(row['ref'])
            if NamespaceId.from_key(key)!=self.namespace:raise AuthorityUnavailable('conditioned signed metadata read crossed its namespace')
            self.selected_graph_keys.add(key)
            if row['revision']>0:self.selected_history.add((key.token,row['revision']))
            if key.type_name=='memory.source':roots.append(key.token)
        if table=='graph_d07_execution_originals_v1':
            audiences=tuple(locator['audience']);purpose=locator['purpose']
            self.extra_source_groups.append((tuple(roots),(purpose,'consolidation'),audiences))
        self.roots.update(roots)
        if kind=='artifact_task_milestone_v2':
            for phase_ref,phase_digest in locator['ordered_phase_originals']:
                phase=self._signed_locator(table,'c4_phase_verified',phase_ref)
                if phase[2]!=phase_digest:raise AuthorityUnavailable('conditioned milestone changed its actual ordered phase digest')
        elif kind=='c4_phase_verified':
            from ..model_broker.artifact_draft_v1 import ArtifactDraftPhaseSelectorV2
            from ..runtime.d11_artifact_draft_model_v1 import artifact_draft_model_ids_v2
            from ..runtime.domain_production_erasure_v1 import decode_typed_production_value_v1
            selector=decode_typed_production_value_v1(locator['content_selector'],ArtifactDraftPhaseSelectorV2)
            self._signed_locator(table,'c4_phase_prepared',artifact_draft_model_ids_v2(selector)['job'])
        elif kind=='c4_phase_prepared':
            frozen=self._signed_locator(table,'c4_phase_frozen',locator['frozen_ref'])
            if frozen[2]!=locator['frozen_digest']:raise AuthorityUnavailable('conditioned phase preparation changed its actual frozen input digest')
        elif kind=='c4_phase_frozen':
            for raw in locator['source_read_versions']:
                version=decode_typed_production_value_v1(raw,GraphVersion)
                self.selected_graph_keys.add(version.key)
                if version.revision:self.selected_history.add((version.key.token,version.revision))
                if version.key.type_name=='memory.source':self.roots.add(version.key.token)
        elif kind=='adopted_life':
            binding=locator['terminal']['binding']
            facts=self._life_prepared_metadata(binding['prepared_original_ref']);self.roots.update(facts.source_roots)
            for row in locator['write_commitments']:
                key=AtomKey.from_token(row['ref']);self.selected_graph_keys.add(key)
                self.selected_history.add((key.token,row['revision']))
        return self.signed_metadata[identity]

    def _select_signed_metadata(self,locator):
        provenance=locator.get('provenance',{})
        execution=provenance.get('execution')
        if type(execution)is dict and execution.get('work_kind')=='simulation':
            from ..runtime.d07_execution_v1 import d07_execution_ids_v1
            job=d07_execution_ids_v1(self.namespace,execution['operation_id'],'simulation')['job']
            self._signed_locator('graph_d07_execution_originals_v1','prepared',job)
        milestone=provenance.get('artifact_task_milestone')
        if type(milestone)is dict:
            ref=locator['identity']['operation_id'].removesuffix(':register')
            if ref is not None:
                self._signed_locator('graph_d11_life_originals_v1','artifact_task_milestone_v2',ref)
        prepared=provenance.get('prepared_candidates')
        if type(prepared)is dict:
            self.selected_producer_ids.add(prepared['value_evaluation_operation_id'])
            for candidate in prepared['candidates']:
                if candidate.get('quote_ref')is not None:self._personal_quote(candidate['quote_ref'],candidate['quote_digest'])
        progress=provenance.get('actual_progress')
        if type(progress)is dict:
            self._signed_locator('graph_d11_life_originals_v1','adopted_life',progress['artifact_ref'])
        for page in locator.get('query_coverage',()):
            if page['complete']:self._metadata_inventory(page['type_id'])

    def _personal_quote(self,quote_ref,digest):
        from ..runtime.issuers import _decode_quote
        header=self._fixed('runtime_resource_quotes',('signature','status'),('quote_id','version'),(quote_ref,1))
        if header is None or header[1]!='active':raise AuthorityUnavailable('conditioned Core actual candidate quote is inactive or absent')
        recipe=self._register_column('runtime_resource_quotes','quote_json',('quote_id','version'),(quote_ref,1),'quote_metadata')
        column=self._column(*recipe[:4],profile=recipe[4]);raw=column.json_v3();wire=canonical_serialize(raw)
        self.service.issuer._d02._signer.verify('resource-quote.v1',wire,header[0])
        quote=_decode_quote(wire)
        if(quote.quote_id!=quote_ref or quote.version!=1 or canonical_digest(quote)!=digest
                or(quote.bot_id,quote.persona_id)!=self.namespace.as_tuple or self.service._clock()>=quote.valid_until_utc):
            raise AuthorityUnavailable('conditioned Core candidate quote changed exact signed identity, namespace or original expiry')
        self.quotes[quote_ref]=(digest,header,quote)
        return quote

    def _signed_body(self,table,kind,ref):
        identity=(table,kind,ref)
        if self.phase!='body'or identity not in self.signed_metadata:
            raise AuthorityUnavailable('conditioned signed protected body lacks prior actual metadata and ALL Source')
        if identity in self.signed_bodies:return self.signed_bodies[identity]
        header,locator,digest=self.signed_metadata[identity]
        recipe=self._register_column(table,'payload_json',('bot','persona','kind','original_ref'),
            (*self.namespace.as_tuple,kind,ref),'body')
        column=self._column(*recipe[:4],profile=recipe[4])
        if column.canonical_digest!=digest:raise AuthorityUnavailable('conditioned signed body changed after its complete metadata EOF')
        raw=column.json_v3();self.signed_bodies[identity]=raw
        return raw

    def _adopted(self,operation_id):
        from ..runtime.domain_production_originals_v1 import _receipt
        from ..runtime.domain_production_erasure_v1 import decode_typed_production_value_v1
        from ..graph_types import GraphVersion
        payload,row,closed,request=self._producer_body(operation_id)
        receipt=_receipt(json.loads(row['receipt_json']))
        if receipt.status!='committed':raise AuthorityUnavailable('conditioned Core producer is not actually committed')
        self._producer_fence_metadata(operation_id,self.producers[operation_id][2])
        return dict(domain=row['domain'],operation_kind=row['operation_kind'],request_digest=row['request_digest'],
            original_digest=row['original_digest'],payload=payload,receipt=receipt,
            read_versions=decode_typed_production_value_v1(payload['read_versions'],tuple[GraphVersion,...]))

    def _before_outcome(self,prediction):
        if prediction.target_observable.startswith('artifact_'):
            row=self._fixed('graph_d11_life_originals_v1',('producing_operation_id','payload_digest'),
                ('bot','persona','kind','original_ref'),(*self.namespace.as_tuple,'artifact_task_milestone_v2',prediction.resolution_target_ref))
            if row is not None:raise AuthorityUnavailable('conditioned forecast cannot follow its actual artifact outcome')
        elif self._graph_body(prediction.resolution_target_ref).revision:
            raise AuthorityUnavailable('conditioned forecast cannot follow its actual Action/Life outcome')

    def _sequence(self,first,second):
        if self.producers[first][2][1]>=self.producers[second][2][1]:
            raise AuthorityUnavailable('conditioned frozen declaration was not committed before its actual outcome/execution')

    def _forecast_execution(self,plan_atom,original):
        import json
        from ..runtime.d07_execution_v1 import d07_execution_ids_v1,D07PreparedExecutionV1
        from ..runtime.domain_production_erasure_v1 import decode_typed_production_value_v1
        from ..model_broker.d07_cognition_v1 import thaw_d07_cognition_request_v1
        from ..graph_types import GraphVersion,AtomKey
        history=self.history_metadata[(plan_atom.key.token,plan_atom.revision)]
        self._sequence(history[2],original['receipt'].operation_id)
        execution=original['payload']['provenance']['execution']
        job=d07_execution_ids_v1(self.namespace,execution['operation_id'],'simulation')['job']
        raw=self._signed_body('graph_d07_execution_originals_v1','prepared',job)
        prepared=decode_typed_production_value_v1(raw,D07PreparedExecutionV1)
        if(prepared.namespace!=self.namespace or prepared.job_id!=job or prepared.operation_id!=execution['operation_id']
                or prepared.work_kind!='simulation'or prepared.execution_id!=execution['execution_id']
                or prepared.stage_input_digest!=execution['input_digest']
                or execution['parent_budget_ref']!=self.selector.parent_budget_lease_ref
                or GraphVersion(plan_atom.key,plan_atom.revision)not in tuple(GraphVersion(AtomKey.from_token(row.ref),row.revision)for row in prepared.read_rows)):
            raise AuthorityUnavailable('conditioned forecast changed its actual signed model preparation, frozen plan or original Root')
        item=thaw_d07_cognition_request_v1(json.loads(prepared.frozen_json)).input
        context=json.loads(item.target_original_json)
        if(item.work_kind!='simulation'or item.target_original_kind!='simulation_forecast_context_v1'
                or context['schema']!='d07.simulation-forecast-context.v1'or context['plan_ref']!=plan_atom.key.token
                or context['plan_revision']!=plan_atom.revision or context['plan_digest']!=canonical_digest(plan_atom.value)
                or item.target_original_digest!=canonical_digest(context)):
            raise AuthorityUnavailable('conditioned actual model input lost its complete declared forecast context')
        return prepared

    def read_current_evidence_v1(self):
        from .conditioned_child_contract_v1 import ConditionedChildEvidenceV1,CHILD_DOMAINS
        from ..runtime_contracts import QueryEpoch
        self._prepare_metadata_closure();self._root_budget()
        read=_ConditionedCoreSemanticReadV1(self)
        membership=self._qualify_frozen_targets(read)
        keys=self._qualify_semantics(read,self.selector.operation_kind,self.request)
        if tuple(keys)!=self.selector.allowed_write_keys:
            raise AuthorityUnavailable('conditioned Core independently derived semantic output keys differ from the exact selected command')
        self._root_budget();self._observe()
        for operation_id,bundle in tuple(self.producer_bundles.items()):self._producer_fence_metadata(operation_id,bundle)
        with self.quantum():pass
        if self.stamp[0]!=self.current_self.graph_epoch:
            raise AuthorityUnavailable('conditioned Core graph epoch differs from actual independently completed Self')
        provider=self.parent_grant.policy_ref
        return ConditionedChildEvidenceV1(selector=self.selector,current_self=self.current_self,owner_guard=self.owner_guard,
            read_versions=tuple(sorted(self.read_versions.values(),key=lambda v:v.key.token)),query_epoch=QueryEpoch(self.namespace,'namespace',self.stamp[0]),
            access_epoch=self.stamp[1],delete_epoch=self.stamp[2],allowed_write_domains=(CHILD_DOMAINS[self.selector.operation_kind],),
            allowed_owner_kinds=tuple(sorted({key.owner.kind for key in keys})),provider_policy_ref=provider,
            root_grant_digest=self.selector.root_grant_digest,valid_until_utc=self.valid_until_utc,
            source_commitment=canonical_digest(tuple(sorted(self.source_commitments.items()))),
            target_membership_digest=membership,observed_at_utc=self.observed_at_utc)

    def _qualify_semantics(self,read,kind,request):
        from ..runtime.conditioned_self_operations_v1 import OPERATIONS
        from ..graph_types import GraphVersion
        if kind not in OPERATIONS or type(request)is not OPERATIONS[kind][1]:
            raise AuthorityUnavailable('conditioned Core semantic request changed its closed registered type')
        db=self.db;readers=None;ns=self.namespace
        if kind=='register_current_prediction_v1':
            value=request.value
            _,plan,_,actual=_actual_forecast_parent(db,read,readers,request.forecast_plan_ref,request.simulation_operation_id)
            if type(request.forecast_index)is not int or not 0<=request.forecast_index<len(plan.forecasts):
                raise AuthorityUnavailable('conditioned actual declared forecast index differs')
            declared=plan.forecasts[request.forecast_index]
            if(replace(value,registered_at=declared.registered_at)!=declared or value.branch_ref!=request.branch_ref
                    or not any(branch['branch_id']==AtomKey.from_token(request.branch_ref).name for branch in actual['branches'])):
                raise AuthorityUnavailable('conditioned Core forecast changed its actual declared simulation branch membership')
            _,predicate=_typed(db,read,value.condition_predicate_ref,ConditionPredicateV1)
            _,policy=_calibration_policy(db,read,predicate)
            target=read.head(db,value.target_head.key,required=True)
            expected_type={'action_result_level':'d08.action_intent.v1','artifact_content_length':'d08.goal.v1',
                'artifact_content_digest':'d08.goal.v1','life_postcondition':'d10.life_project.v1'}[value.target_observable]
            if((value.target_observable,value.resolution_rule)!=(policy.target_observable,policy.resolution_rule)
                    or target.key.type_name!=expected_type or target.revision!=value.target_head.revision
                    or value.task_class!=predicate.task_class or value.target_head.key.token not in predicate.scope_refs
                    or not predicate.valid_from<=self.observed_at_utc<value.expires_at<=predicate.valid_until):
                raise AuthorityUnavailable('conditioned Core forecast changed its actual immutable target, policy or validity')
            key=conditioned_key_v1(ns,PREDICTION_TYPE,value.prediction_id);prior=read.head(db,key)
            if prior.revision:
                _,saved=_typed(db,read,key.token,PredictionRecordV1)
                if replace(value,registered_at=saved.registered_at)!=saved:raise AuthorityUnavailable('conditioned forecast replay changed its original declaration')
            else:self._before_outcome(value)
            for ref in value.assumption_refs:_typed(db,read,ref,ConditionPredicateV1)
            _prediction_assumptions_v1(db,read,value)
            keys=(key,)
        elif kind=='record_current_simulation_v1':
            value=request.value;_,plan,_,actual=_actual_forecast_parent(db,read,readers,request.forecast_plan_ref,request.simulation_operation_id)
            branches=(value.baseline,*value.alternatives)
            if(value.namespace!=ns or value.baseline_snapshot!=plan.baseline_snapshot
                    or len(branches)!=1+len(plan.alternative_assumption_refs)
                    or tuple(b.changed_assumption_refs for b in branches)!=((),*((ref,)for ref in plan.alternative_assumption_refs))):
                raise AuthorityUnavailable('conditioned Core simulation changed its exact frozen baseline/alternative assumptions')
            for index,branch in enumerate(branches):
                member=actual['branches'][index]
                expected=tuple(conditioned_key_v1(ns,PREDICTION_TYPE,p.prediction_id).token for p in plan.forecasts if p.branch_ref==branch.branch_ref)
                if(member['branch_id']!=AtomKey.from_token(branch.branch_ref).name or member['content_reality']!='simulated'
                        or member['evidence_eligibility']!='none'or branch.prediction_refs!=expected):
                    raise AuthorityUnavailable('conditioned Core simulation branch differs from its actual hypothetical COMMIT member')
                for ref in branch.changed_assumption_refs:_typed(db,read,ref,ConditionPredicateV1)
            for version in value.baseline_snapshot:
                if read.head(db,version.key,required=True).revision!=version.revision:
                    raise AuthorityUnavailable('conditioned Core simulation baseline is no longer the exact frozen current head')
            keys=(conditioned_key_v1(ns,SIMULATION_TYPE,value.simulation_id),)
        elif kind=='resolve_current_prediction_v1':
            value,discrepancy=_prediction_resolution_material_v1(db,read,request,readers)
            keys=(conditioned_key_v1(ns,RESOLUTION_TYPE,value.resolution_id),
                *((conditioned_key_v1(ns,DISCREPANCY_TYPE,discrepancy.discrepancy_id),)if discrepancy is not None else()))
        elif kind=='review_current_conditioned_self_v1':
            review,candidate,type_name,identity=_conditioned_review_material_v1(db,read,request,readers)
            if request.previous_ref is None and request.revision!=1:
                raise AuthorityUnavailable('conditioned Core first semantic revision must retain its actual initial revision')
            keys=(conditioned_key_v1(ns,type_name,identity),conditioned_key_v1(ns,REVIEW_TYPE,review.review_id))
        elif kind=='match_current_conditioned_strategy_v1':
            if not request.semantic_question_ref:raise AuthorityUnavailable('conditioned Core matching requires its actual D07 semantic question')
            value=read_current_conditioned_match_v1(db,read,request,readers)
            keys=(conditioned_key_v1(ns,MATCH_TYPE,value.match_id),)
        elif kind=='project_current_conditioned_life_strategy_v1':
            value=_conditioned_life_projection_material_v1(db,read,request,readers)
            keys=(conditioned_key_v1(ns,'d10.conditioned_strategy_projection.v1',value.projection_id),)
        elif kind=='select_current_conditioned_personal_step_v1':
            keys=self._qualify_personal_selection(read,request)
        else:raise AuthorityUnavailable('conditioned Core operation is not one of its seven semantic child recipes')
        if len(set(keys))!=len(keys):raise AuthorityUnavailable('conditioned Core exact output recipe repeated a write key')
        return keys

    def _qualify_personal_selection(self,read,request):
        from ..domains.d08.personal_candidate_v1 import PreparedPersonalCandidateSetV1
        from ..domains.d08.personal_plan_v1 import decode_personal_plan_type_v1,PLAN_TYPE
        from ..runtime.d08_personal_plan_v1 import personal_decision_key_v1
        from ..runtime.conditioned_self_operations_v1 import MatchCurrentConditionedStrategyRequestV1
        original=self._adopted(request.prepared_candidates_operation_id)
        if(original['domain'],original['operation_kind'])!=('d08','prepare_personal_candidates_v1'):
            raise AuthorityUnavailable('conditioned Core personal choice lacks its exact real prepared-candidate producer')
        prepared=decode_typed_production_value_v1(original['payload']['provenance']['prepared_candidates'],PreparedPersonalCandidateSetV1)
        if(prepared.namespace!=self.namespace or prepared.selection_operation_id!=self.selector.operation_id
                or prepared.plan_head.key.token!=request.plan_ref or prepared.goal_head.key.token!=request.goal_ref
                or(prepared.owner_grant_ref,prepared.owner_grant_revision,prepared.owner_grant_digest)!=(
                    self.owner_guard.grant_ref,self.owner_guard.grant_revision,self.owner_guard.grant_digest)
                or(prepared.access_epoch,prepared.delete_epoch)!=self.stamp[1:]
                or prepared.parent_budget_lease_ref!=self.selector.parent_budget_lease_ref):
            raise AuthorityUnavailable('conditioned Core personal choice substituted its actual Owner, Root or immutable selection identity')
        if(self.selector.targets_digest!=canonical_digest((self.selector.operation_kind,request,prepared.future_decision_ref))
                or self.selector.target_census_digest!=canonical_digest((prepared.read_versions,prepared.query_coverage,prepared.source_refs))
                or self.selector.original_deadline_utc>min(row.future_identity.deadline_utc for row in prepared.candidates)):
            raise AuthorityUnavailable('conditioned Core inline choice changed its exact prepared target/census or original candidate window')
        for version in prepared.read_versions:
            if read.head(self.db,version.key).revision!=version.revision:
                raise AuthorityUnavailable('conditioned Core current hard-eligibility input differs from the actual prepared set')
        for page in prepared.query_coverage:
            actual=tuple(GraphVersion(a.key,a.revision)for a in read.complete_inventory(self.db,page.type_id))
            if not page.complete or page.row_versions!=actual:
                raise AuthorityUnavailable('conditioned Core personal eligibility lost complete current negative-query coverage')
        plan=decode_personal_plan_type_v1(PLAN_TYPE,read.head(self.db,request.plan_ref,required=True).value)
        if len(request.condition_match_refs)>6 or len(set(request.condition_match_refs))!=len(request.condition_match_refs):
            raise AuthorityUnavailable('conditioned Core personal match set changed its original six-candidate bound')
        for candidate in prepared.candidates:
            if candidate.quote_ref is not None:
                quote=self._personal_quote(candidate.quote_ref,candidate.quote_digest)
                if quote.parent_budget_lease_ref!=self.selector.parent_budget_lease_ref:
                    raise AuthorityUnavailable('conditioned Core candidate quote crossed its actual original parent lease')
        for ref in request.condition_match_refs:
            _,saved=_typed(self.db,read,ref,ConditionMatchProjectionV1)
            current=read_current_conditioned_match_v1(self.db,read,MatchCurrentConditionedStrategyRequestV1(
                saved.strategy_ref,saved.semantic_question_ref,request.goal_ref,plan.goal_revision,plan.method_candidates,saved.scope_project_ref),None)
            if replace(current,coverage_epoch=saved.coverage_epoch)!=saved:
                raise AuthorityUnavailable('conditioned Core personal preference lost its exact current D07 match')
            if saved.scope_project_ref is not None:
                _condition_project_scope_v1(self.db,read,saved.scope_project_ref,read.head(self.db,request.goal_ref,required=True),selected_plan_ref=request.plan_ref)
        from types import SimpleNamespace
        frame=SimpleNamespace(envelope=SimpleNamespace(authority=SimpleNamespace(namespace=self.namespace),
            identity=SimpleNamespace(activity_id=self.selector.activity_id,operation_id=self.selector.operation_id)))
        key=personal_decision_key_v1(frame,request.plan_ref)
        if key.token!=prepared.future_decision_ref or read.head(self.db,key).revision:
            raise AuthorityUnavailable('conditioned Core personal choice cannot replace its actual immutable Decision')
        return(key,)

    def _qualify_frozen_targets(self,read):
        import json
        from .conditioned_child_contract_v1 import validate_conditioned_frozen_targets_v1
        from ..runtime.conditioned_self_operations_v1 import conditioned_request_from_wire_v1
        if self.selector.phase=='personal_choice':
            original=self._adopted(self.selector.producer_operation_id)
            if original['payload']['parent_budget']!=self.selector.parent_budget_lease_ref:
                raise AuthorityUnavailable('conditioned inline choice changed actual prepared-candidate parent Root')
            if self.selector.producer_operation_id!=self.request.prepared_candidates_operation_id:
                raise AuthorityUnavailable('conditioned Core inline choice crossed its actual prepared-candidate producer')
            return canonical_digest((self.selector.phase,self.selector.producer_operation_id,self.selector.typed_request_digest))
        frozen=validate_conditioned_frozen_targets_v1(json.loads(self.selector.frozen_targets_json),namespace=self.namespace)
        original=self._adopted(self.selector.producer_operation_id)
        if self.selector.frozen_targets_original_ref is not None:
            first=self._adopted(self.frozen_producer_id)
            if(first['original_digest']!=self.selector.frozen_targets_original_digest
                    or first['payload']['provenance']['conditioned_frozen_targets']!=frozen):
                raise AuthorityUnavailable('conditioned frozen target set differs from its actual finished first child COMMIT')
            for item in self.frozen_disposition['completed_commands']:
                completed=self._adopted(item['operation_id'])
                targets=tuple(t for t in frozen['targets']if t['child_id']==item['operation_id'])
                if(len(targets)!=1 or item['command_digest']!=canonical_digest(targets[0])
                        or item['receipt_digest']!=canonical_digest(completed['receipt'])
                        or completed['operation_kind']!=targets[0]['operation_kind']
                        or completed['payload']['request']!=targets[0]['request']
                        or completed['payload']['provenance']['conditioned_frozen_targets']!=frozen):
                    raise AuthorityUnavailable('conditioned durable target progress differs from its real actual finished child originals')
            members=tuple(t for t in frozen['targets']if t['child_id']==first['receipt'].operation_id)
            if(len(members)!=1 or members[0]['operation_kind']!=first['operation_kind']or members[0]['request']!=first['payload']['request']):
                raise AuthorityUnavailable('conditioned frozen first actual producer is not a full target member')
        else:
            from types import SimpleNamespace
            event=SimpleNamespace(event_kind=self.selector.event_kind,causal_operation_id=self.selector.producer_operation_id)
            commands=resolve_current_conditioned_followup_command_v1(self.db,frame=read.frame,event=event,producer_original=original,readers=None)
            expected=[]
            for kind,request in commands:
                matching=tuple(t for t in frozen['targets']if t['operation_kind']==kind and canonical_digest(t['request'])==canonical_digest(plain_v1(request)))
                if len(matching)!=1:raise AuthorityUnavailable('conditioned frozen full target census omitted or changed an actual independently derived semantic child')
                expected.append(matching[0]['child_id'])
            if set(expected)!={t['child_id']for t in frozen['targets']}:
                raise AuthorityUnavailable('conditioned frozen full target tuple contains an unauthorized extra semantic child')
            for raw in frozen['target_census']['read_versions']:
                key=AtomKey.from_token(raw['key'])
                if key.type_name in {'memory.source','memory.access','d06.source_correction_head.v1'}:
                    actual=self.read_versions.get(key)
                    if actual is None or actual.revision!=raw['revision']:raise AuthorityUnavailable('conditioned first-child frozen Source census changed')
                elif read.head(self.db,key).revision!=raw['revision']:
                    raise AuthorityUnavailable('conditioned first-child actual frozen target census version changed')
            for page in frozen['target_census']['query_coverage']:
                actual=tuple(GraphVersion(a.key,a.revision)for a in read.complete_inventory(self.db,page['type_id']))
                if not page['complete']or plain_v1(actual)!=page['row_versions']:
                    raise AuthorityUnavailable('conditioned first-child actual frozen target query census changed')
        return canonical_digest((frozen,self.finished_proofs[self.selector.producer_operation_id],
            self.selector.operation_id,self.selector.typed_request_digest))

    def _artifact_milestone_from_producer(self,original):
        ref=original['receipt'].operation_id.removesuffix(':register')
        return self._artifact_milestone(ref)

    def _artifact_milestone(self,ref):
        from ..runtime.artifact_task_observer_v1 import decode_artifact_task_milestone_v2,RegisterCurrentArtifactTaskMilestoneRequestV2
        from ..runtime.d11_artifact_draft_content_v1 import ArtifactDraftPhaseVerifiedOriginalV2,artifact_draft_phase_verification_from_wire_v2
        from ..model_broker.artifact_draft_v1 import artifact_draft_phase_sequence_v2
        raw=self._signed_body('graph_d11_life_originals_v1','artifact_task_milestone_v2',ref)
        value=decode_artifact_task_milestone_v2(raw)
        original=self._adopted(value.registration_operation_id)
        if(value.namespace!=self.namespace or value.original_ref!=ref or value.owner_guard!=self.owner_guard
                or(original['domain'],original['operation_kind'])!=('d08','register_artifact_task_milestone_v2')
                or original['receipt'].write_versions or original['payload']['coverage']!='complete'
                or original['payload']['request']!=plain_v1(RegisterCurrentArtifactTaskMilestoneRequestV2(value.selector))
                or original['payload']['provenance']['artifact_task_milestone']!=raw
                or original['payload']['now_utc']!=value.registered_at_utc):
            raise AuthorityUnavailable('conditioned Core artifact outcome is not its exact real signed empty-write W01 milestone')
        source=self.sources.get(value.source_head.key.token)
        groups=tuple(v for key,v in self.source_commitments.items()if key[2]==value.source_head.key.token)
        if(source is None or source.revision!=value.source_head.revision
                or not groups or any(group[1]!=value.source_value_digest for group in groups)):
            raise AuthorityUnavailable('conditioned Core artifact outcome Source no longer matches its exact registered milestone')
        phases=artifact_draft_phase_sequence_v2(value.selector.method_ref)
        for index,(phase_ref,digest)in enumerate(value.ordered_phase_originals):
            phase_raw=self._signed_body('graph_d11_life_originals_v1','c4_phase_verified',phase_ref)
            verified=artifact_draft_phase_verification_from_wire_v2(phase_raw,ArtifactDraftPhaseVerifiedOriginalV2)
            producer=self._adopted(verified.producing_operation_id)
            prior=value.ordered_phase_originals[index-1]if index else(None,None)
            expected=replace(value.selector,phase_index=index,phase_kind=phases[index],prev_phase_original_ref=prior[0],prev_phase_original_digest=prior[1])
            if(canonical_digest(phase_raw)!=digest or verified.selector!=expected
                    or producer['operation_kind']!='verify_artifact_draft_phase_v2'
                    or producer['payload']['provenance']!={'phase_verified':phase_raw}):
                raise AuthorityUnavailable('conditioned Core milestone lost its complete exact actual method-phase prefix')
            if index==len(phases)-1 and(verified.method_qualified is not True or verified.content_selector.phase_kind!='full'or verified.readback!=value.readback):
                raise AuthorityUnavailable('conditioned Core milestone lacks an actual independently verified full-file readback')
        return value

    def _life_progress(self,progress):
        from ..runtime.d11_life_contract_v1 import D11LifeTerminalV1,life_from_wire_v1
        from ..runtime.d11_life_preparation_v1 import life_prepared_from_wire_v1
        from ..runtime.d10_life_progress_provenance_v1 import life_progress_qualified_writes_v1
        from ..runtime.domain_production_originals_v1 import _receipt
        from ..graph_types import GraphVersion
        import json
        raw=self._signed_body('graph_d11_life_originals_v1','adopted_life',progress.artifact_ref)
        terminal=life_from_wire_v1(raw['terminal'],D11LifeTerminalV1)
        prepared=life_prepared_from_wire_v1(self._signed_body('graph_d11_life_originals_v1','prepared',terminal.binding.prepared_original_ref))
        if(raw['schema']!='d11.adopted-life-original.v4'or terminal.binding!=prepared.binding
                or prepared.digest!=raw['prepared_digest']or prepared.binding.parent_budget_lease_ref!=self.selector.parent_budget_lease_ref):
            raise AuthorityUnavailable('conditioned Core Life outcome lost its signed actual prepared/terminal/Root lineage')
        operation=raw['producing_operation_id'];receipt=_receipt(json.loads(raw['graph_receipt_json']))
        actual=self._fixed('graph_bundle_operations',('digest','commit_seq'),('bot','persona','operation_id'),(*self.namespace.as_tuple,operation))
        if receipt.status!='committed'or receipt.operation_id!=operation or actual!=(receipt.operation_digest,receipt.commit_seq):
            raise AuthorityUnavailable('conditioned Core Life terminal lacks its exact real W01 COMMIT')
        self._producer_fence_metadata(operation,actual)
        for member in raw['write_commitments']:
            atom=self._graph_body(member['ref'],revision=member['revision'])
            header=self.frozen_history[(member['ref'],member['revision'])][0]
            if(header[2]!=operation or not atom.valid or canonical_digest(atom.value)!=member['digest']
                    or GraphVersion(atom.key,atom.revision)not in receipt.write_versions):
                raise AuthorityUnavailable('conditioned Core signed Life terminal member differs from actual immutable history')
        matches=tuple(self._graph_body(ref)for ref in self.graph_metadata if AtomKey.from_token(ref).type_name=='d10.life_progress.v1'
            and self.graph_metadata[ref]is not None and self.graph_metadata[ref][1]is not None)
        matches=tuple(atom for atom in matches if atom.valid and atom.value==plain_v1(progress))
        if len(matches)!=1:raise AuthorityUnavailable('conditioned Core Life progress lacks its exact current adopted head')
        atom=matches[0]
        production=_origin(self.db,_ConditionedCoreSemanticReadV1(self),atom,'advance_life')
        if production['payload']['provenance']['actual_progress']!=plain_v1(progress):
            raise AuthorityUnavailable('conditioned Core Life progress changed its actual composite producer')
        from ..runtime.d11_life_fact_provenance_v1 import life_current_fact_reads_v1
        from ..runtime.d11_life_preparation_v1 import life_read_digest_v1
        for frozen in life_current_fact_reads_v1(prepared):
            key=AtomKey.from_token(frozen.ref)
            version=self.read_versions.get(key)
            if version is None or version.revision!=frozen.revision:
                raise AuthorityUnavailable('conditioned Core Life current Source/Access/Correction/Owner/plan input changed')
            expected_digest=life_read_digest_v1(frozen)
            if key.type_name=='memory.source':
                values=tuple(value[1]for group,value in self.source_commitments.items()if group[2]==key.token)
                if not values or any(value!=expected_digest for value in values):raise AuthorityUnavailable('conditioned Core Life Source original changed')
            elif key.type_name=='memory.access':
                from ..memory_types import source_key
                ref=source_key(*self.namespace.as_tuple,key.owner.subject).token
                values=tuple(value[3]for group,value in self.source_commitments.items()if group[2]==ref)
                if not values or any(value!=expected_digest for value in values):raise AuthorityUnavailable('conditioned Core Life Access original changed')
            elif key.type_name!='d06.source_correction_head.v1':
                current=self._graph_body(key.token)
                if current.valid!=frozen.valid or canonical_digest(current.value)!=expected_digest:
                    raise AuthorityUnavailable('conditioned Core Life actual permission or plan original changed')
        writes=life_progress_qualified_writes_v1(prepared,terminal,progress,production['receipt'].operation_id)
        for write in writes:
            current=self._graph_body(write.key.token)
            if(current.revision!=1 or not current.valid or current.value!=write.value
                    or GraphVersion(current.key,1)not in production['receipt'].write_versions):
                raise AuthorityUnavailable('conditioned Core current Life fact/proof/eligibility differs from its actual original')
        return prepared,terminal,production

    def _execution_assumptions(self,prediction,outcome):
        if prediction.target_observable.startswith('artifact_'):
            from ..runtime.d11_artifact_draft_content_v1 import ArtifactDraftPhaseVerifiedOriginalV2,artifact_draft_phase_verification_from_wire_v2
            from ..runtime.d11_artifact_draft_model_v1 import artifact_draft_model_ids_v2,ArtifactDraftModelPreparedV2,artifact_draft_model_from_wire_v2,artifact_draft_input_from_wire_v2
            milestone=self._artifact_milestone(outcome.original_ref)
            verified=artifact_draft_phase_verification_from_wire_v2(self._signed_body('graph_d11_life_originals_v1','c4_phase_verified',milestone.full_check_original_ref),ArtifactDraftPhaseVerifiedOriginalV2)
            prepared=artifact_draft_model_from_wire_v2(self._signed_body('graph_d11_life_originals_v1','c4_phase_prepared',artifact_draft_model_ids_v2(verified.content_selector)['job']),ArtifactDraftModelPreparedV2)
            frozen=artifact_draft_input_from_wire_v2(self._signed_body('graph_d11_life_originals_v1','c4_phase_frozen',prepared.frozen_ref))
            if frozen.digest!=prepared.frozen_digest or frozen.selector!=verified.content_selector:
                raise AuthorityUnavailable('conditioned Core actual artifact execution changed its frozen input')
            versions=frozen.source_read_versions
        elif prediction.target_observable=='life_postcondition':
            from ..domains.d10.production_operations_v1 import LifeProgressHeadV1
            progress=decode_typed_production_value_v1(self._graph_body(prediction.resolution_target_ref).value,LifeProgressHeadV1)
            prepared,_,_=self._life_progress(progress)
            versions=tuple(GraphVersion(AtomKey.from_token(row.ref),row.revision)for row in prepared.read_rows)
        else:
            frozen=self._graph_body(prediction.target_head.key.token,revision=prediction.target_head.revision)
            header=self.frozen_history[(frozen.key.token,frozen.revision)][0]
            planning=self._adopted(header[2])
            if prediction.target_head not in planning['receipt'].write_versions:return None
            versions=planning['read_versions']
        if not set((*prediction.assumption_heads,prediction.condition_goal_head,prediction.target_head))<=set(versions):return None
        facts=[]
        for version in prediction.assumption_heads:
            atom=self._graph_body(version.key.token,revision=version.revision)
            header=self.frozen_history[(version.key.token,version.revision)][0]
            producer=self._adopted(header[2])
            if(not atom.valid or producer['operation_kind']!='adopt_current_c1_method_conditions_v1'
                    or version not in producer['receipt'].write_versions):return None
            facts.append((version,atom.value,header[2]))
        return tuple(facts)

    def _register_column(self,table,column,key_columns,key,profile):
        recipe=(table,column,tuple(key_columns),tuple(key),profile)
        self.column_recipes.add(recipe)
        return recipe


    def _history_locator(self,ref,revision):
        from ..graph_types import AtomKey
        key=AtomKey.from_token(ref)
        if NamespaceId.from_key(key)!=self.namespace or type(revision)is not int or revision<1:
            raise AuthorityUnavailable('conditioned frozen historical locator changed namespace or revision')
        selected=(ref,revision)
        if selected in self.frozen_history:return self.frozen_history[selected]
        if selected not in self.selected_history:
            raise AuthorityUnavailable('conditioned historical body has no actual frozen upstream locator')
        header=self._fixed('graph_history',('event_bot','event_persona','event_id','valid','value_cell_id'),('token','revision'),selected)
        if header is None or header[:2]!=self.namespace.as_tuple:
            raise AuthorityUnavailable('conditioned frozen historical origin is absent')
        recipe=self._register_column('graph_history','value',('token','revision'),selected,'graph_metadata')
        column=self._column(*recipe[:4],profile=recipe[4],cell_id=header[4])
        locator=column.json_v3();self.selected_producer_ids.add(header[2])
        result=(header,locator,column.canonical_digest);self.frozen_history[selected]=result
        return result

    def _head_metadata(self,ref):
        from ..graph_types import AtomKey,GraphVersion,owner_grant_key
        key=AtomKey.from_token(ref)
        if key.token!=ref or NamespaceId.from_key(key)!=self.namespace:
            raise AuthorityUnavailable('conditioned Core graph locator crossed its namespace')
        if ref in self.graph_metadata:return self.graph_metadata[ref]
        if len(self.graph_metadata)>=1024:raise AuthorityUnavailable('conditioned Core complete locator closure exceeds installed read bound')
        row=self._fixed('graph_atoms',('revision','valid','value_cell_id'),('token','bot','persona'),(ref,*self.namespace.as_tuple))
        revision=0 if row is None else row[0];self.read_versions[key]=GraphVersion(key,revision)
        if row is None:self.graph_metadata[ref]=None;return None
        if key==owner_grant_key(*self.namespace.as_tuple):
            grant=self.owner_entry[0][1]
            if(row[0],canonical_digest(grant))!=(self.owner_guard.grant_revision,self.owner_guard.grant_digest):
                raise AuthorityUnavailable('conditioned Core completed Owner grant head changed')
            result=(row,grant,canonical_digest(grant));self.graph_metadata[ref]=result;return result
        if not row[1]:
            result=(row,{},None);self.graph_metadata[ref]=result;return result
        if key.type_name in{'memory.source','memory.access','d06.source_correction_head.v1'}:
            self.graph_metadata[ref]=(row,None,None);return self.graph_metadata[ref]
        recipe=self._register_column('graph_atoms','value',('token','bot','persona'),(ref,*self.namespace.as_tuple),'graph_metadata')
        column=self._column(*recipe[:4],profile=recipe[4],cell_id=row[2]);locator=column.json_v3()
        from ..runtime.conditioned_self_operations_v1 import VALUE_TYPES
        if key.type_name in VALUE_TYPES:
            from ..domains.d01.conditioned_self_v1 import require_conditioned_record_locator_v1
            require_conditioned_record_locator_v1(locator,column.general_metadata_fields_seen,
                namespace=self.namespace,type_name=key.type_name)
        result=(row,locator,column.canonical_digest);self.graph_metadata[ref]=result
        if key.type_name=='d01.persona_plan.v1':
            self.metadata_locators.extend(column.nested_locators)
        history=self._fixed('graph_history',('event_bot','event_persona','event_id','valid','value_cell_id'),
            ('token','revision'),(ref,row[0]))
        if history is None or history[:2]!=self.namespace.as_tuple or history[3]!=row[1]:
            raise AuthorityUnavailable('conditioned Core current value lost its exact actual history origin')
        if key.type_name not in {'d01.persona_activation.v1','d01.persona_plan.v1'}:
            self.selected_producer_ids.add(history[2])
        self.history_metadata[(ref,row[0])]=history
        return result

    def _outbox_frozen_pointer(self,cause):
        key=(*self.namespace.as_tuple,self.selector.dedupe_key)
        consumer=self._fixed('graph_domain_production_outbox_v1',('consumer_operation_id',),('bot','persona','dedupe_key'),key)
        with self.quantum()as meter:
            info=self.db.execute('SELECT typeof(receipt_json),length(CAST(receipt_json AS BLOB)) FROM graph_domain_production_outbox_v1 WHERE bot=? AND persona=? AND dedupe_key=?',key).fetchone()
            meter.charge_read(32)
        if cause.header[5]=='pending':
            if consumer!=(None,)or info!=('null',None)or self.selector.frozen_targets_original_ref is not None:
                raise AuthorityUnavailable('conditioned first-child selector differs from the actual virgin producer event')
            return
        if cause.header[5]!='waiting'or consumer is None or consumer[0]is None or info is None or info[0]!='text':
            raise AuthorityUnavailable('conditioned current child has no actual complete frozen-first-child event pointer')
        recipe=self._register_column('graph_domain_production_outbox_v1','receipt_json',('bot','persona','dedupe_key'),key,'disposition_metadata')
        value=self._column(*recipe[:4],profile=recipe[4]).json_v3()
        fields={'schema','resolver_version','namespace','dedupe_key','causal_operation_id','causal_original_digest',
            'trigger_original_digest','producer_receipt_digest','manifest_digest','state','observed_epoch','completed_commands',
            'missing_originals','continuation_ref','consumer_operation_id','first_child_operation_id','first_child_original_ref',
            'first_child_original_digest','targets_digest','target_census_digest'}
        if(type(value)is not dict or set(value)!=fields or value['schema']!='d01.conditioned-followup-disposition.v1'
                or value['resolver_version']!='conditioned-fixed-targets.v1'or value['namespace']!=plain_v1(self.namespace)
                or(value['dedupe_key'],value['causal_operation_id'],value['causal_original_digest'],value['trigger_original_digest'],value['producer_receipt_digest'])!=(
                    cause.dedupe_key,cause.causal_operation_id,cause.original_digest,cause.trigger_digest,cause.receipt_digest)
                or value['state']!='waiting'or value['consumer_operation_id']!=consumer[0]
                or(value['first_child_original_ref'],value['first_child_original_digest'],value['targets_digest'],value['target_census_digest'])!=(
                    self.selector.frozen_targets_original_ref,self.selector.frozen_targets_original_digest,self.selector.targets_digest,self.selector.target_census_digest)
                or value['manifest_digest']!=canonical_digest(json.loads(self.selector.frozen_targets_json))
                or value['missing_originals']!=[]or value['continuation_ref']is not None
                or not 1<=len(value['completed_commands'])<=16):
            raise AuthorityUnavailable('conditioned selector replaced its actual durable frozen complete target-set pointer')
        if value['first_child_operation_id']!=self.frozen_producer_id:
            raise AuthorityUnavailable('conditioned actual frozen event pointer differs from its real first producer')
        self.selected_producer_ids.add(value['first_child_operation_id'])
        for item in value['completed_commands']:
            if type(item)is not dict or set(item)!={'command_digest','operation_id','receipt_digest'}:
                raise AuthorityUnavailable('conditioned actual frozen progress contains another child receipt schema')
            self.selected_producer_ids.add(item['operation_id'])
        self.frozen_disposition=value

    def _producer_metadata(self,operation_id,*,trigger=False):
        from ..runtime.conditioned_producer_source_metadata_v3 import (PRODUCER_HEADER_COLUMNS_V3,
            OUTBOX_HEADER_COLUMNS_V3,finish_conditioned_producer_locator_v3)
        from ..runtime.conditioned_self_operations_v1 import CONDITIONED_PRODUCER_EVENTS_V1
        if operation_id in self.producers:return self.producers[operation_id]
        if operation_id not in self.selected_producer_ids:
            raise AuthorityUnavailable('conditioned Core original is outside its actual producing history')
        key=(*self.namespace.as_tuple,operation_id)
        header=self._fixed('graph_domain_production_originals_v1',PRODUCER_HEADER_COLUMNS_V3,
            ('bot','persona','operation_id'),key)
        if header is None:
            signed=tuple(value for identity,value in self.signed_metadata.items()if len(value[0])==3 and value[0][0]==operation_id)
            if not signed:raise AuthorityUnavailable('conditioned Core selected producer original is absent')
            bundle=self._fixed('graph_bundle_operations',('digest','commit_seq'),('bot','persona','operation_id'),key)
            if bundle is None or bundle[1]<1:raise AuthorityUnavailable('conditioned signed fact has no actual producing COMMIT')
            self._producer_fence_metadata(operation_id,bundle)
            versions=tuple({'key':row['ref'],'revision':row['revision']}for value in signed for row in value[1].get('read_rows',()))
            return(None,{'read_versions':versions},bundle,None)
        recipe=self._register_column('graph_domain_production_originals_v1','original_payload_json',
            ('bot','persona','operation_id'),key,'producer_metadata')
        column=self._column(*recipe[:4],profile=recipe[4]);locator=column.json_v3()
        if column.canonical_digest!=header[3]:raise AuthorityUnavailable('conditioned Core producing original metadata EOF digest changed')
        bundle=self._fixed('graph_bundle_operations',('digest','commit_seq'),('bot','persona','operation_id'),key)
        if bundle is None or bundle[0]!=header[5]or type(bundle[1])is not int or bundle[1]<1:
            raise AuthorityUnavailable('conditioned Core selected producer has no actual complete positive W01 COMMIT')
        if(locator.get('namespace')!={'bot_id':self.namespace.bot_id,'persona_id':self.namespace.persona_id}
                or locator.get('identity',{}).get('operation_id')!=operation_id
                or locator.get('schema')!=header[0]+'.current-'+header[1]+'.v1'):
            raise AuthorityUnavailable('conditioned Core producing original changed its immutable namespace or identity')
        cause=None
        if trigger and self.selector.phase=='child':
            outbox=self._fixed('graph_domain_production_outbox_v1',OUTBOX_HEADER_COLUMNS_V3,
                ('bot','persona','dedupe_key'),(*self.namespace.as_tuple,self.selector.dedupe_key))
            cause=finish_conditioned_producer_locator_v3(namespace=self.namespace,dedupe_key=self.selector.dedupe_key,
                outbox_header=outbox,header=header,bundle_metadata=bundle,projection=locator,
                whole_digest=column.canonical_digest,producer_events=CONDITIONED_PRODUCER_EVENTS_V1)
            self._outbox_frozen_pointer(cause)
            if(cause.domain,cause.operation_kind,cause.causal_operation_id,cause.original_digest,cause.receipt_digest,
                    cause.parent_budget_lease_ref,cause.event_kind)!=(self.selector.producer_domain,self.selector.producer_kind,
                    operation_id,self.selector.producer_original_digest,self.selector.producer_receipt_digest,
                    self.selector.parent_budget_lease_ref,self.selector.event_kind):
                raise AuthorityUnavailable('conditioned Core trigger changed its actual selected producer, Root or outbox identity')
        if trigger:
            if(header[0],header[1],header[3],header[4],header[0]+'-current:'+header[3][:48],locator['parent_budget'])!=(
                    self.selector.producer_domain,self.selector.producer_kind,self.selector.producer_original_digest,
                    self.selector.producer_receipt_digest,self.selector.producer_original_ref,self.selector.parent_budget_lease_ref):
                raise AuthorityUnavailable('conditioned trigger changed its actual original, receipt or parent Root')
            if not set(self.selector.audiences)<=set(locator['authority']['audience']):
                raise AuthorityUnavailable('conditioned trigger cannot expand its original audience scope')
            if cause is not None and self.selector.original_deadline_utc>cause.original_deadline_utc:
                raise AuthorityUnavailable('conditioned trigger cannot extend its original actual producer deadline')
        self._producer_fence_metadata(operation_id,bundle)
        result=(header,locator,bundle,cause);self.producers[operation_id]=result
        return result

    def _metadata_inventory(self,type_name):
        from ..graph_types import AtomKey,GraphVersion
        versions=[];after=''
        while True:
            with self.quantum()as meter:
                meter.require_available(65536)
                rows=self.db.execute('SELECT token,revision,valid FROM graph_atoms WHERE bot=? AND persona=? AND type_name=? AND token>? ORDER BY token LIMIT 64',
                    (*self.namespace.as_tuple,type_name,after)).fetchall()
                meter.charge_read(sum(len(row[0].encode())+24 for row in rows))
                self.operation.retain(_heap(rows)+1024)
            if not rows:break
            for token,revision,valid in rows:
                key=AtomKey.from_token(token)
                if key.type_name!=type_name or NamespaceId.from_key(key)!=self.namespace:
                    raise AuthorityUnavailable('conditioned Core metadata census crossed its fixed type')
                versions.append(GraphVersion(key,revision))
                if len(versions)>128:raise AuthorityUnavailable('conditioned Core complete fixed metadata census exceeds installed bound')
                self.selected_graph_keys.add(key)
            after=rows[-1][0]
        self.query_pages[type_name]=tuple(versions)
        return self.query_pages[type_name]

    def _source_family(self,roots,*,purposes,audiences):
        from ..graph_types import AtomKey,GraphAtom,GraphVersion
        from ..memory_types import source_key,access_key
        from ..domains.d06 import source_correction_head_key
        from ..domains.d07.qualified_attention_read import _qualify_source_rights_values_v3
        from types import SimpleNamespace
        pending=[(ref,())for ref in roots];seen=set()
        while pending:
            ref,ancestors=pending.pop()
            if ref in ancestors:raise AuthorityUnavailable('conditioned Core Source ancestry is cyclic')
            if ref in seen:continue
            key=AtomKey.from_token(ref)
            if key!=source_key(*self.namespace.as_tuple,key.owner.subject or''):
                raise AuthorityUnavailable('conditioned Core Source is not an exact current namespace locator')
            columns=('revision','valid','value_cell_id')
            row=self._fixed('graph_atoms',columns,('token','bot','persona'),(ref,*self.namespace.as_tuple))
            if row is None or row[0]<1 or not row[1]:raise AuthorityUnavailable('conditioned Core Source is no longer current')
            recipe=('graph_atoms','value',('token','bot','persona'),(ref,*self.namespace.as_tuple),'source_metadata')
            self.column_recipes.add(recipe)
            column=self._column(*recipe[:4],profile=recipe[4],cell_id=row[2])
            metadata=_detach_value_v3(column.frozen)
            source=SimpleNamespace(metadata=metadata,revision=row[0],valid=True)
            acl_key=access_key(*self.namespace.as_tuple,key.owner.subject)
            acl_row=self._fixed('graph_atoms',columns,('token','bot','persona'),(acl_key.token,*self.namespace.as_tuple))
            if acl_row is None or not acl_row[1]:raise AuthorityUnavailable('conditioned Core Source Access is unavailable')
            acl_recipe=('graph_atoms','value',('token','bot','persona'),(acl_key.token,*self.namespace.as_tuple),'access_metadata')
            self.column_recipes.add(acl_recipe)
            acl=self._column(*acl_recipe[:4],profile=acl_recipe[4],cell_id=acl_row[2]).json_v3()
            correction_key=source_correction_head_key(self.namespace,key.owner.subject)
            correction=self._fixed('graph_atoms',('revision','valid'),('token','bot','persona'),(correction_key.token,*self.namespace.as_tuple))
            head=GraphAtom(correction_key,0,{},False)if correction is None else GraphAtom(correction_key,correction[0],{},bool(correction[1]))
            access=GraphAtom(acl_key,acl_row[0],acl,True)
            for purpose in purposes:
                for audience in audiences:
                    if _qualify_source_rights_values_v3(self.namespace,ref,source,access,head,
                            purpose=purpose,audience=audience,metadata_only=True)is None:
                        raise AuthorityUnavailable('conditioned Core Source/Access/Correction no longer permits its actual consumer')
            self.sources[ref]=source
            for version in(GraphVersion(key,row[0]),GraphVersion(acl_key,acl_row[0]),GraphVersion(correction_key,head.revision)):
                prior=self.read_versions.get(version.key)
                if prior is not None and prior!=version:raise AuthorityUnavailable('conditioned Source group revision changed')
                self.read_versions[version.key]=version
            group=(tuple(purposes),tuple(audiences),ref)
            self.source_commitments[group]=(row[0],column.canonical_digest,acl_row[0],canonical_digest(acl),head.revision)
            seen.add(ref)
            pending.extend((source_key(*self.namespace.as_tuple,parent).token,(*ancestors,ref))for parent in metadata['parent_source_ids'])
        return tuple(sorted(seen))

    def _root_budget(self):
        from ..runtime.issuers import BudgetLeaseGrant
        from ..runtime_contracts import canonical_serialize
        from ..runtime.domain_production_erasure_v1 import decode_typed_production_value_v1
        policy=self.service.installed_bundle.installation_policy;selector=self.selector
        expected=policy.root_grant
        if(selector.root_budget_lease_ref,selector.root_grant_id,selector.root_grant_version,selector.root_grant_digest)!=(
                policy.root_lease.lease_id,expected.grant_id,expected.version,canonical_digest(expected)):
            raise AuthorityUnavailable('conditioned child substituted the actual original installed Root grant')
        seen=set();current=selector.parent_budget_lease_ref;grants=[];chain=[]
        while current is not None:
            if current in seen or len(seen)>=32:raise AuthorityUnavailable('conditioned child parent budget ancestry is cyclic or exceeds its bound')
            seen.add(current)
            lease=self._fixed('runtime_budget_leases',('lease_id','parent_id','bot_id','persona_id','currency','state'),('lease_id',),(current,))
            if lease is None or lease[:1]!=(current,)or lease[2:4]!=self.namespace.as_tuple or lease[5]!='active':
                raise AuthorityUnavailable('conditioned child original parent budget is absent, foreign or inactive')
            with self.quantum()as meter:
                latest=_runtime_bounded_fixed_row_v3(self.db,meter,'runtime_budget_grants',('version','signature','status'),
                    'lease_id=? ORDER BY version DESC',(current,))
                debt=meter.read_fixed_row(self.db,'runtime_budget_debt_blocks',('lease_id',),'lease_id=?',(current,))
            if latest is None or latest[2]!='active'or debt is not None:
                raise AuthorityUnavailable('conditioned child original budget grant is inactive or blocked by actual ancestor debt')
            key=(current,latest[0]);recipe=('runtime_budget_grants','grant_json',('lease_id','version'),key,'budget_grant')
            self.column_recipes.add(recipe)
            column=self._column(recipe[0],recipe[1],recipe[2],recipe[3],profile=recipe[4])
            raw=column.json_v3();grant=decode_typed_production_value_v1(raw,BudgetLeaseGrant)
            payload=canonical_serialize(raw)
            if hashlib.sha256(payload.encode()).hexdigest()!=column.canonical_digest:
                raise AuthorityUnavailable('conditioned child grant is not the original complete canonical metadata')
            self.service.issuer._signer.verify('budget-grant.v1',payload,latest[1])
            if(grant.lease_id,grant.version,grant.bot_id,grant.persona_id,grant.currency)!=(current,latest[0],*self.namespace.as_tuple,lease[4]):
                raise AuthorityUnavailable('conditioned child signed grant changed its actual durable lease identity')
            grants.append(grant);chain.append((lease,grant,latest[1]));current=lease[1]
        if not chain or chain[-1][0][0]!=policy.root_lease.lease_id or grants[-1]!=expected or ROOT_WORK_KIND not in expected.allowed_work_kinds:
            raise AuthorityUnavailable('conditioned semantic child recipe was never explicitly allowed by this original Root')
        now=self.service._clock();deadline=min(selector.original_deadline_utc,*(grant.valid_until_utc for grant in grants))
        if now>=deadline:raise AuthorityUnavailable('conditioned child original Root or parent grant has expired')
        if ROOT_WORK_KIND not in grants[0].allowed_work_kinds:
            raise AuthorityUnavailable('conditioned current parent grant never explicitly allowed this semantic child work')
        self.valid_until_utc=deadline;self.parent_grant=grants[0];self.budget_chain=tuple(chain)
        return self.budget_chain

    def _require_column_recipe(self,table,column,key_columns,key,profile):
        require_conditioned_core_source_work_v1(self)
        if(table,column,tuple(key_columns),tuple(key),profile)not in self.column_recipes:
            raise AuthorityUnavailable('conditioned Core column escaped its actual fixed preplanned locator')
        if profile=='body'and self.phase!='body':raise AuthorityUnavailable('conditioned protected body requires independent ALL Source first')

    def _column(self,table,column,key_columns,key,*,profile,cell_id=None):
        self._require_column_recipe(table,column,key_columns,key,profile)
        with self.quantum()as meter:
            cell=None if cell_id is None else begin_runtime_cell_read_v3(self.db,cell_id)
            value=_ConditionedCoreColumnV1(_ISSUER,self,table=table,column=column,key_columns=key_columns,key=key,
                profile=profile,cell=cell)
            self.columns.append(value)
        while not value.complete:
            with self.quantum()as meter:value.advance(meter)
        return value

    def release_v1(self):
        if self.closed:return
        self.closed=True
        try:
            from .conditioned_child_c09_finished_v1 import release_accepted_conditioned_producer_reads_v1
            release_accepted_conditioned_producer_reads_v1(self)
            for column in self.columns:_COLUMNS.pop(column,None)
            if self.operation is not None:finish_runtime_storage_operation_v3(self.operation)
        finally:
            _WORKS.discard(self)
            if self.handle is not None:self.handle.close()
            if self.db is not None:self.db.close()


def require_conditioned_core_source_work_v1(work):
    if(type(work)is not _ConditionedCoreSourceWorkV1 or work not in _WORKS or work.closed
            or work.thread!=get_ident()or work.operation is None or work.operation.closed
            or work.operation.selection_digest!=work.selection_digest
            or work.operation.deadline_utc!=work.selector.original_deadline_utc):
        raise AuthorityUnavailable('conditioned Core Source has no actual same private Work or selection')
    return work


def prepare_conditioned_child_core_read_v1(service,*,credential,subject,permit,selector,current_self,owner_entry):
    from .current_conditioned_child_v1 import InstalledCurrentConditionedChildV1
    if type(service)is not InstalledCurrentConditionedChildV1:raise TypeError('actual installed conditioned Core child service required')
    service.require_installed_v1()
    return _ConditionedCoreSourceWorkV1(_ISSUER,service,credential=credential,subject=subject,permit=permit,
        selector=selector,current_self=current_self,owner_entry=owner_entry)

from dataclasses import dataclass,replace
from ..domains.d01.conditioned_self_v1 import (CalibrationPolicyV1,ConditionPredicateV1,ConditionedCapabilityRevisionV1,
    ConditionedStrategyRevisionV1,ConditionedSelfReviewV1,CALIBRATION_POLICY_TYPE,CONDITION_TYPE,CAPABILITY_TYPE,STRATEGY_TYPE,REVIEW_TYPE,conditioned_revision_record_name_v1)
from ..domains.d01.identity_v3 import RuntimeIdentityRef
from ..domains.d01.production_operations_v1 import plain_v1
from ..domains.d07.prediction_v1 import (PredictionRecordV1,PredictionResolutionV1,SimulationRecordV1,SimulationForecastPlanV1,
    ConditionMatchProjectionV1,SelfDiscrepancyV1,PREDICTION_TYPE,RESOLUTION_TYPE,SIMULATION_TYPE,MATCH_TYPE,DISCREPANCY_TYPE)
from ..graph_types import AtomKey,Owner,GraphVersion
from ..runtime.domain_production_erasure_v1 import decode_typed_production_value_v1
from ..runtime.d01_production_operations_v1 import MissingProductionOriginalV1
from ..runtime.conditioned_self_operations_v1 import (VALUE_TYPES,PRODUCERS,CONDITIONED_PRODUCER_EVENTS_V1,conditioned_key_v1,
    RegisterCurrentPredictionRequestV1,RecordCurrentSimulationRequestV1,ResolveCurrentPredictionRequestV1,
    ReviewCurrentConditionedSelfRequestV1,MatchCurrentConditionedStrategyRequestV1,ProjectCurrentConditionedLifeStrategyRequestV1)


def _calibration_policy(db,read,predicate):
    atom,policy=_typed(db,read,predicate.calibration_policy_ref,CalibrationPolicyV1)
    
    if (policy.runtime_identity!=RuntimeIdentityRef.from_owner_guard(read.work.namespace,read.work.owner_guard)or policy.runtime_identity.namespace!=predicate.namespace or policy.task_class!=predicate.task_class
            or not set(predicate.scope_refs)<=set(policy.population_scope_refs)
            or predicate.valid_from<policy.valid_from or predicate.valid_until>policy.valid_until
            or policy.minimum_verified_outcomes>read.frame.limits.max_query_rows):
        raise ValueError('conditioned calibration changed its immutable Owner policy or installed population bound')
    return atom,policy


def _actual_prediction_outcome(db,read,readers,prediction,outcome_ref):
    if outcome_ref!=prediction.resolution_target_ref:raise ValueError('prediction resolution substituted its frozen observer target')
    target=read.head(db,prediction.target_head.key,required=True)
    if prediction.target_observable.startswith('artifact_'):
        actual=read.work._artifact_milestone(outcome_ref)
        if actual.goal_ref!=target.key.token:raise ValueError('artifact resolution belongs to another frozen Goal')
        digest=actual.digest
        original=read.original(outcome_ref,digest=digest)
        read.source_family(db,(actual.source_head.key.token,),purpose='consolidation')
        if prediction.target_observable=='artifact_content_length':category=None;interval=(actual.readback.content_length,actual.readback.content_length)
        else:category=actual.readback.content_digest;interval=None
        from datetime import datetime
        observed=datetime.fromisoformat(actual.readback.verified_at_utc.replace('Z','+00:00')).timestamp()
        return original,digest,category,interval,observed,(actual.source_head.key.token,),False,'artifact-observation:'+canonical_digest((prediction.namespace,actual.readback.execution_call_id,actual.readback.effect_id))
    outcome=read.head(db,outcome_ref,required=True)
    _origin(db,read,outcome)
    original=read.original(outcome_ref,digest=canonical_digest(outcome.value))
    if prediction.target_observable=='action_result_level':
        from ..domains.d08.execution import _decode,_decode_intent
        if outcome.key.type_name!='d08.action_outcome.v1':raise ValueError('action resolver requires its actual Action outcome')
        actual=_decode('d08.action_outcome.v1',outcome.value);planned=_decode_intent(target.value)
        if (actual.action_id,actual.effect_id,actual.attempt_id)!=(planned.action_id,planned.identity.effect_id,planned.identity.attempt_id):
            raise ValueError('Action resolver crossed frozen Action/effect/attempt')
        for ref in actual.observation_refs:read.original(ref)
        roots=tuple(planned.source_refs)
        if roots:read.source_family(db,roots,purpose='consolidation')
        return original,canonical_digest(outcome.value),actual.result_level,None,actual.observed_at,roots,bool(actual.unknown_effects),'action-observation:'+canonical_digest((prediction.namespace,actual.effect_id,actual.attempt_id))
    from ..domains.d10.production_operations_v1 import LifeProgressHeadV1
    if outcome.key.type_name!='d10.life_progress.v1':raise ValueError('Life resolver requires its actual adopted progress')
    actual=decode_typed_production_value_v1(outcome.value,LifeProgressHeadV1)
    prepared,terminal,_=read.work._life_progress(actual)
    if actual.project_ref!=target.key.token or prepared.plan.project.ref!=target.key.token:
        raise ValueError('Life resolver crossed frozen actual project')
    read.original(terminal.original_ref);read.original(terminal.binding.artifact_ref)
    from datetime import datetime
    observed=datetime.fromisoformat(terminal.payload.completed_at_utc.replace('Z','+00:00')).timestamp()
    return original,canonical_digest(outcome.value),actual.step,None,observed,actual.source_refs,terminal.status!='completed','life-observation:'+canonical_digest((prediction.namespace,terminal.binding.execution_id,terminal.binding.effect_id,terminal.binding.attempt_id))


def _prediction_resolution_material_v1(db,read,request,readers):
    atom,prediction=_typed(db,read,request.prediction_ref,PredictionRecordV1)
    original=_origin(db,read,atom,'register_current_prediction_v1')
    now=read.frame.now_utc
    outcome=None;digest=category=interval=observed=observation_unit=None;roots=prediction.source_refs
    if request.outcome_ref is None:
        
        read.work._before_outcome(prediction)
        status='expired_unknown' if now>=prediction.expires_at else 'unknown'
    else:
        outcome,digest,category,interval,observed,actual_roots,unresolved,observation_unit=_actual_prediction_outcome(db,read,readers,prediction,request.outcome_ref)
        roots=tuple(sorted(set((*roots,*actual_roots))))
        if observed<prediction.registered_at:raise ValueError('prediction was not durably registered before its actual observed outcome')
        
        read.work._sequence(original['receipt'].operation_id,read.producing_operation(outcome.original_ref))
        assumptions_witnessed=_prediction_assumptions_v1(db,read,prediction,outcome=outcome)
        if unresolved or not assumptions_witnessed or observed>prediction.expires_at:status='expired_unknown' if observed>prediction.expires_at else 'unknown'
        elif interval is not None:
            low,high=prediction.predicted_range
            status='matched' if low<=interval[0]<=interval[1]<=high else 'counterexample' if interval[1]<low or interval[0]>high else 'unknown'
        else:status='matched' if category==prediction.predicted_category else 'counterexample'
    identity='prediction-resolution:'+canonical_digest((request.prediction_ref,None if outcome is None else(outcome.original_ref,digest),status))[:48]
    value=PredictionResolutionV1(prediction.namespace,identity,request.prediction_ref,canonical_digest(atom.value),
        None if outcome is None else outcome.original_ref,digest,observation_unit,category,interval,observed,now,status,roots)
    discrepancy=None
    if status=='counterexample':
        _,predicate=_typed(db,read,prediction.condition_predicate_ref,ConditionPredicateV1)
        did='self-discrepancy:'+canonical_digest((request.prediction_ref,identity))[:48]
        resolution_ref=conditioned_key_v1(prediction.namespace,RESOLUTION_TYPE,identity).token
        discrepancy=SelfDiscrepancyV1(prediction.namespace,did,request.prediction_ref,resolution_ref,
            prediction.condition_predicate_ref,predicate.scope_refs,roots)
    return value,discrepancy


def _conditioned_review_id_v1(persona_head,target_block,predicate_ref,record_id,revision,resolution_refs,trigger_ref,method_review_ref):
    return 'conditioned-review:'+canonical_digest((persona_head,target_block,predicate_ref,record_id,revision,
        tuple(resolution_refs),trigger_ref,method_review_ref))[:48]


def _conditioned_review_material_v1(db,read,request,readers):
    active=_active(read,readers);ns=read.frame.envelope.authority.namespace
    runtime_identity=RuntimeIdentityRef.from_owner_guard(ns,readers.owner_guard)
    block=next((block for block in active.plan.blocks if block.block_id==request.target_block),None)
    if block is None or block.kind not in {'self_knowledge','strategy'}:
        raise ValueError('conditional review targets only Self knowledge or strategy')
    _,predicate=_typed(db,read,request.predicate_ref,ConditionPredicateV1)
    _,policy=_calibration_policy(db,read,predicate)
    if request.target_block!=policy.review_target_block:
        raise ValueError('review cannot replace its actual Owner-configured target block')
    trigger=read.head(db,request.trigger_ref,required=True);trigger_counter=None
    if trigger.key.type_name==RESOLUTION_TYPE:
        _,resolution=_typed(db,read,request.trigger_ref,PredictionResolutionV1)
        _,trigger_prediction=_typed(db,read,resolution.prediction_ref,PredictionRecordV1)
        trigger_predicate_ref=trigger_prediction.condition_predicate_ref
        if resolution.calibration_status=='counterexample':trigger_counter=(request.trigger_ref,resolution)
    elif trigger.key.type_name==DISCREPANCY_TYPE:
        _,discrepancy=_typed(db,read,request.trigger_ref,SelfDiscrepancyV1)
        trigger_predicate_ref=discrepancy.condition_predicate_ref
        _,resolution=_typed(db,read,discrepancy.resolution_ref,PredictionResolutionV1)
        if resolution.calibration_status!='counterexample':raise ValueError('discrepancy lacks its actual counterexample resolution')
        trigger_counter=(discrepancy.resolution_ref,resolution)
    else:raise ValueError('conditional review requires its true resolution or D07 discrepancy precursor')
    calibration=_current_prediction_calibration_v1(db,read,request.predicate_ref,predicate)
    actual_predictions,resolution_refs,counterexamples,counts,unknown,roots,support=(calibration.prediction_refs,
        calibration.resolution_refs,calibration.counterexamples,dict(calibration.counts),calibration.unknown_count,
        calibration.source_refs,calibration.support_families)
    if tuple(sorted(request.prediction_refs))!=actual_predictions:
        raise MissingProductionOriginalV1('complete_actual_conditional_prediction_denominator')
    heads=tuple(v for v in active.read_versions if v.key.type_name=='d01.persona_plan.v1')
    if len(heads)!=1:raise ValueError('conditional review requires its exact active persona CAS head')
    review_id=_conditioned_review_id_v1(heads[0],request.target_block,request.predicate_ref,request.capability_id,request.revision,
        resolution_refs,request.trigger_ref,None if request.strategy is None else request.strategy.method_outcome_review_ref)
    review_ref=conditioned_key_v1(ns,REVIEW_TYPE,review_id).token
    qualification='qualified'if calibration.threshold_met else'unknown'if not sum(counts.values())else'limited'
    if request.previous_ref is not None:
        cls=ConditionedStrategyRevisionV1 if block.kind=='strategy'else ConditionedCapabilityRevisionV1
        _,previous=_typed(db,read,request.previous_ref,cls)
        identity=previous.strategy_id if cls is ConditionedStrategyRevisionV1 else previous.capability_id
        if previous.runtime_identity!=runtime_identity or request.revision!=previous.revision+1 or request.capability_id!=identity:
            raise ValueError('conditional revision did not retain its actual predecessor/runtime identity')
    if trigger_predicate_ref!=request.predicate_ref:
        if (block.kind!='strategy'or request.previous_ref is None or trigger_counter is None
                or previous.condition_predicate_ref!=trigger_predicate_ref
                or block.claim!=canonical_serialize(plain_v1(previous))):
            raise ValueError('condition review substituted its true trigger instead of narrowing the actual current strategy')
        resolution_refs=tuple(dict.fromkeys((*resolution_refs,trigger_counter[0])))
        counterexamples=tuple(dict.fromkeys((*counterexamples,trigger_counter[0])))
        roots=tuple(sorted(set((*roots,*trigger_counter[1].source_refs))))
    if block.kind=='self_knowledge':
        candidate=ConditionedCapabilityRevisionV1(runtime_identity,request.capability_id,request.revision,request.previous_ref,
            predicate.task_class,request.predicate_ref,predicate.scope_refs,tuple(sorted(support)),tuple(counterexamples),actual_predictions,
            tuple(resolution_refs),tuple(counts.items()),unknown,calibration.observation_unit_count,calibration.policy_ref,
            calibration.policy_digest,calibration.minimum_verified_outcomes,calibration.coverage,review_ref,predicate.valid_from,
            predicate.valid_until,'sample_threshold_met'if calibration.threshold_met else qualification,roots)
        candidate_type=CAPABILITY_TYPE
    else:
        candidate=request.strategy
        if (type(candidate)is not ConditionedStrategyRevisionV1 or candidate.runtime_identity!=runtime_identity
                or (candidate.strategy_id,candidate.revision,candidate.previous_ref)!=(request.capability_id,request.revision,request.previous_ref)
                or candidate.review_ref!=review_ref or candidate.condition_predicate_ref!=request.predicate_ref
                or predicate.rollback_predicate_ref is None or candidate.rollback_predicate_ref!=predicate.rollback_predicate_ref
                or candidate.applicable_scope!=predicate.scope_refs or candidate.support_families!=tuple(sorted(support))
                or candidate.counterexamples!=tuple(counterexamples) or candidate.source_refs!=roots
                or not predicate.valid_from<=candidate.valid_from<=read.frame.now_utc<candidate.valid_until<=predicate.valid_until):
            raise ValueError('strategy candidate differs from actual calibrated conditional review')
        rollback_candidate=candidate.qualification=='rolled_back'
        if rollback_candidate:
            if(request.previous_ref is None or trigger_counter is None or block.claim!=canonical_serialize(plain_v1(previous))
                    or candidate.preferred_method!=previous.alternative_method or candidate.alternative_method!=previous.preferred_method
                    or not set(candidate.applicable_scope)<=set(previous.applicable_scope)
                    or not set(previous.exclusions)<=set(candidate.exclusions)
                    or candidate.method_outcome_review_ref!=previous.method_outcome_review_ref):
                raise ValueError('rollback candidate must withdraw the actual adopted method within its existing scope')
            qualification='rollback_evidence_qualified'
            candidate=replace(candidate,qualification='rolled_back')
        elif counterexamples:
            if request.previous_ref is None:raise MissingProductionOriginalV1('actual_previous_strategy_for_counterexample_narrowing')
            _,old_predicate=_typed(db,read,previous.condition_predicate_ref,ConditionPredicateV1)
            if (not set(old_predicate.conditions)<set(predicate.conditions)
                    or not set(predicate.scope_refs)<=set(old_predicate.scope_refs)
                    or not set(previous.exclusions)<=set(candidate.exclusions)):
                raise ValueError('actual counterexample must narrow a candidate and preserve prior exclusions')
            candidate=replace(candidate,qualification='narrowed')
        else:candidate=replace(candidate,qualification='candidate'if qualification!='qualified'else'qualified')
        _,rollback_predicate=_typed(db,read,candidate.rollback_predicate_ref,ConditionPredicateV1)
        if not set(candidate.applicable_scope)<=set(rollback_predicate.scope_refs):
            raise ValueError('strategy rollback predicate does not cover its actual candidate scope')
        candidate_type=STRATEGY_TYPE
    candidate_id=conditioned_revision_record_name_v1(namespace=ns,type_name=candidate_type,record_id=request.capability_id,
        revision=request.revision,review_ref=review_ref)
    candidate_ref=conditioned_key_v1(ns,candidate_type,candidate_id).token
    review=ConditionedSelfReviewV1(runtime_identity,review_id,request.target_block,heads[0],request.predicate_ref,
        actual_predictions,tuple(resolution_refs),candidate_ref,roots,qualification,('unresolved_actual_outcomes',)if unknown else())
    return review,candidate,candidate_type,candidate_id


def _condition_facts_v1(db,read,goal,predicate):
    from ..domains.d07 import decode_method_condition_question_v1
    inventory=read.complete_inventory(db,'d07.current_interpretation.v1')
    pages=tuple(page for page in read.frame.query_coverage if page.type_id=='d07.current_interpretation.v1')
    if len(pages)!=1 or not pages[0].complete:raise MissingProductionOriginalV1('complete_actual_D07_condition_match_coverage')
    values={};heads=[];roots=set(predicate.source_refs)
    for atom in inventory:
        if not atom.valid or atom.value.get('current')is not True:continue
        scope=decode_method_condition_question_v1(atom.value.get('question_key'))
        if scope is None or(scope['goal_ref'],scope['goal_revision'])!=(goal.key.token,goal.value['revision']):continue
        _origin(db,read,atom,'adopt_current_c1_method_conditions_v1')
        condition=scope['condition_id']
        if condition not in dict(predicate.conditions):continue
        if condition in values:raise MissingProductionOriginalV1('unique_actual_current_condition_interpretation')
        roots.update(atom.value['source_refs']);heads.append(GraphVersion(atom.key,atom.revision))
        values[condition]=(atom.value['proposition']=='true')if(atom.value['stance']=='support'
            and atom.value['evidence_status']=='supported'and not atom.value['meaningful_unknowns']
            and atom.value['proposition']in {'true','false'})else None
    if roots:read.source_family(db,tuple(sorted(roots)),purpose='consolidation')
    return values,tuple(heads),tuple(sorted(roots)),pages[0]


def _forecast_goal_v1(db,read,prediction):
    target=read.head(db,prediction.target_head.key,required=True)
    if target.key.type_name=='d08.goal.v1':return target
    if target.key.type_name=='d08.action_intent.v1':
        from ..domains.d08.execution import _decode_intent
        intent=_decode_intent(target.value)
        goals=tuple(atom for atom in read.complete_inventory(db,'d08.goal.v1')
            if atom.valid and atom.value['goal_id']==intent.goal_ref)
        if len(goals)!=1:raise MissingProductionOriginalV1('exact_actual_forecast_Action_Goal')
        return goals[0]
    if target.key.type_name=='d10.life_project.v1':
        from ..domains.d10.project_checkpoint_v1 import project_checkpoint_key_v1,decode_project_checkpoint_type_v1,CHECKPOINT_TYPE
        from ..domains.d08.personal_plan_v1 import decode_personal_plan_type_v1,PLAN_TYPE
        checkpoint=decode_project_checkpoint_type_v1(CHECKPOINT_TYPE,read.head(db,
            project_checkpoint_key_v1(prediction.namespace,target.key.token),required=True).value)
        plan=decode_personal_plan_type_v1(PLAN_TYPE,read.head(db,checkpoint.plan_ref,required=True).value)
        if checkpoint.plan_revision!=plan.revision:raise MissingProductionOriginalV1('actual_forecast_Life_plan_revision')
        return read.head(db,plan.goal_ref,required=True)
    raise ValueError('forecast has no registered actual Goal target')


def _prediction_assumptions_v1(db,read,prediction,*,outcome=None):
    _,predicate=_typed(db,read,prediction.condition_predicate_ref,ConditionPredicateV1)
    if outcome is None:
        goal=_forecast_goal_v1(db,read,prediction)
        if (GraphVersion(goal.key,goal.revision),goal.value['revision'])!=(prediction.condition_goal_head,prediction.condition_goal_revision):
            raise ValueError('forecast plan changed its frozen actual Goal condition scope')
        values,heads,roots,_=_condition_facts_v1(db,read,goal,predicate)
        if heads!=prediction.assumption_heads:raise ValueError('forecast plan substituted its original current D07 assumption versions')
        if not set(roots)<=set(prediction.source_refs):raise ValueError('forecast omitted its actual assumption Source roots')
    else:
        
        facts=read.work._execution_assumptions(prediction,outcome)
        if facts is None:return False
        from ..domains.d07 import decode_method_condition_question_v1
        if tuple(version for version,_,_ in facts)!=prediction.assumption_heads:
            raise ValueError('actual execution assumption EOF changed its frozen exact versions')
        values={}
        for version,raw,producer in facts:
            scope=decode_method_condition_question_v1(raw.get('question_key'))
            if (scope is None or(scope['goal_ref'],scope['goal_revision'])!=
                    (prediction.condition_goal_head.key.token,prediction.condition_goal_revision)
                    or scope['condition_id']not in dict(predicate.conditions)or scope['condition_id']in values):
                raise ValueError('actual historical execution condition crossed its frozen typed Goal scope')
            values[scope['condition_id']]=(raw['proposition']=='true')if(raw['stance']=='support'
                and raw['evidence_status']=='supported'and not raw['meaningful_unknowns']
                and raw['proposition']in {'true','false'})else None
    return all(key in values and values[key]is not None and values[key]==value for key,value in predicate.conditions)


def _condition_project_scope_v1(db,read,project_ref,goal,*,selected_plan_ref=None):
    from ..domains.d10.project_checkpoint_v1 import project_checkpoint_key_v1,decode_project_checkpoint_type_v1,CHECKPOINT_TYPE
    from ..domains.d08.personal_plan_v1 import decode_personal_plan_type_v1,PLAN_TYPE
    project=read.head(db,project_ref,required=True)
    if project.key.type_name!='d10.life_project.v1':raise ValueError('conditional scope has another actual project type')
    atom=read.head(db,project_checkpoint_key_v1(read.frame.envelope.authority.namespace,project_ref),required=True)
    checkpoint=decode_project_checkpoint_type_v1(CHECKPOINT_TYPE,atom.value)
    plan=decode_personal_plan_type_v1(PLAN_TYPE,read.head(db,checkpoint.plan_ref,required=True).value)
    if (checkpoint.plan_revision!=plan.revision or plan.goal_ref!=goal.key.token or plan.goal_revision!=goal.value['revision']
            or selected_plan_ref is not None and checkpoint.plan_ref!=selected_plan_ref):
        raise MissingProductionOriginalV1('actual_conditional_Project_checkpoint_plan_Goal_scope')
    return project


def read_current_conditioned_match_v1(db,read,request,readers):
    from ..domains.d07 import decode_method_condition_question_v1
    strategy_atom,strategy=_typed(db,read,request.strategy_ref,ConditionedStrategyRevisionV1)
    active=_active(read,readers)
    adopted=tuple(block for block in active.plan.blocks if block.kind=='strategy'
        and block.claim==canonical_serialize(plain_v1(strategy)))
    if len(adopted)!=1:raise MissingProductionOriginalV1('actual_adopted_conditional_strategy_persona_member')
    _,predicate=_typed(db,read,strategy.condition_predicate_ref,ConditionPredicateV1)
    goal=read.head(db,request.goal_ref,required=True)
    if goal.key.type_name!='d08.goal.v1'or goal.value['revision']!=request.goal_revision:
        raise MissingProductionOriginalV1('current_actual_conditional_strategy_Goal')
    if request.semantic_question_ref is not None:
        question=read.head(db,request.semantic_question_ref,required=True)
        if question.key.type_name!='d07.current_interpretation.v1':raise ValueError('matching requires its actual current D07 semantic question')
        scope=decode_method_condition_question_v1(question.value.get('question_key'))
        if scope is None or(scope['goal_ref'],scope['goal_revision'])!=(goal.key.token,request.goal_revision):
            raise ValueError('condition matching question crossed its actual Goal scope')
        _origin(db,read,question,'adopt_current_c1_method_conditions_v1')
    values,heads,predicate_roots,page=_condition_facts_v1(db,read,goal,predicate)
    roots=set((*strategy.source_refs,*predicate_roots));gaps=[]
    scope_refs={goal.key.token}
    if request.scope_project_ref is not None:
        _condition_project_scope_v1(db,read,request.scope_project_ref,goal)
        scope_refs.add(request.scope_project_ref)
    project_scope_required=any(AtomKey.from_token(ref).type_name=='d10.life_project.v1'for ref in strategy.applicable_scope)
    _,rollback=_typed(db,read,strategy.rollback_predicate_ref,ConditionPredicateV1)
    rollback_values,rollback_heads,rollback_roots,_=_condition_facts_v1(db,read,goal,rollback)
    roots.update(rollback_roots);heads=tuple(dict.fromkeys((*heads,*rollback_heads)))
    rollback_covered=(bool(scope_refs.intersection(rollback.scope_refs))and rollback.valid_from<=read.frame.now_utc<rollback.valid_until
        and all(key in rollback_values and rollback_values[key]is not None for key,_ in rollback.conditions))
    rollback_triggered=rollback_covered and all(rollback_values[key]==value for key,value in rollback.conditions)
    matching='matched'
    if (strategy.qualification=='rolled_back'or rollback_triggered or scope_refs.intersection(strategy.exclusions)
            or not strategy.valid_from<=read.frame.now_utc<strategy.valid_until
            or not predicate.valid_from<=read.frame.now_utc<predicate.valid_until):matching='excluded'
    elif not rollback_covered:
        matching='unknown';gaps.append('current_rollback_predicate_not_covered')
    elif project_scope_required and request.scope_project_ref is None:
        matching='unknown';gaps.append('project_scope_not_covered')
    elif not scope_refs.intersection(strategy.applicable_scope):matching='excluded'
    elif request.semantic_question_ref is None or any(key not in values or values[key]is None for key,_ in predicate.conditions):
        matching='unknown';gaps.append('incomplete_actual_condition_evidence')
    elif any(values[key]!=value for key,value in predicate.conditions):matching='excluded'
    roots=tuple(sorted(roots))
    if roots:read.source_family(db,roots,purpose='consolidation')
    pairs=request.method_candidates
    if len(pairs)>6 or len({ref for ref,_ in pairs})!=len(pairs):raise ValueError('bounded exact conditional method candidates required')
    preferred=tuple(ref for ref,method in pairs if method==strategy.preferred_method)
    alternatives=tuple(ref for ref,method in pairs if method==strategy.alternative_method)
    edges=tuple((a,b)for a in preferred for b in alternatives if a!=b)if matching=='matched'else()
    identity='condition-match:'+canonical_digest((request,strategy_atom.revision,tuple(heads)))[:48]
    return ConditionMatchProjectionV1(active.plan.namespace,identity,request.strategy_ref,canonical_digest(strategy_atom.value),
        strategy.condition_predicate_ref,predicate.scope_refs,request.semantic_question_ref,request.scope_project_ref,tuple(heads),page.epoch.revision,True,matching,edges,roots,tuple(gaps))


def _conditioned_life_projection_material_v1(db,read,request,readers):
    from ..domains.d10.production_operations_v1 import ConditionedLifeStrategyProjectionV1
    from ..domains.d10.project_checkpoint_v1 import project_checkpoint_key_v1,decode_project_checkpoint_type_v1,CHECKPOINT_TYPE
    from ..domains.d08.personal_plan_v1 import decode_personal_plan_type_v1,PLAN_TYPE
    project=read.head(db,request.project_ref,required=True);recipe=read.head(db,request.recipe_ref,required=True)
    if (project.key.type_name!='d10.life_project.v1'or recipe.key.type_name!='d10.activity_recipe.v1'
            or project.value['next_step']not in recipe.value['allowed_steps']):
        raise ValueError('conditioned Life projection changed actual project/recipe current step')
    checkpoint_atom=read.head(db,project_checkpoint_key_v1(read.frame.envelope.authority.namespace,request.project_ref),required=True)
    checkpoint=decode_project_checkpoint_type_v1(CHECKPOINT_TYPE,checkpoint_atom.value)
    plan_atom=read.head(db,checkpoint.plan_ref,required=True);plan=decode_personal_plan_type_v1(PLAN_TYPE,plan_atom.value)
    if checkpoint.plan_revision!=plan.revision:raise MissingProductionOriginalV1('current_actual_Life_project_plan_revision')
    goal=read.head(db,plan.goal_ref,required=True)
    _,strategy=_typed(db,read,request.strategy_ref,ConditionedStrategyRevisionV1)
    matching=read_current_conditioned_match_v1(db,read,MatchCurrentConditionedStrategyRequestV1(request.strategy_ref,_condition_question_locator_v1(db,read,goal.key.token,plan.goal_revision),
        goal.key.token,plan.goal_revision,plan.method_candidates,request.project_ref),readers)
    identity='life-strategy-projection:'+canonical_digest((request,GraphVersion(project.key,project.revision),
        GraphVersion(recipe.key,recipe.revision),GraphVersion(plan_atom.key,plan_atom.revision),matching.match_id))[:48]
    value=ConditionedLifeStrategyProjectionV1(read.frame.envelope.authority.namespace,identity,
        GraphVersion(project.key,project.revision),GraphVersion(recipe.key,recipe.revision),GraphVersion(plan_atom.key,plan_atom.revision),
        GraphVersion(goal.key,goal.revision),request.strategy_ref,canonical_digest(plain_v1(strategy)),matching,
        strategy.preferred_method,strategy.alternative_method,strategy.support_families,strategy.exclusions,
        strategy.counterexamples,strategy.rollback_predicate_ref,matching.source_refs)
    return value


@dataclass(frozen=True,slots=True)
class _CalibrationReadoutV1:
    prediction_refs: tuple[str,...]
    resolution_refs: tuple[str,...]
    counterexamples: tuple[str,...]
    counts: tuple[tuple[str,int],...]
    unknown_count: int
    source_refs: tuple[str,...]
    support_families: tuple[str,...]
    observation_unit_count: int
    policy_ref: str
    policy_digest: str
    minimum_verified_outcomes: int
    coverage: float
    threshold_met: bool


def _current_prediction_calibration_v1(db,read,predicate_ref,predicate):
    policy_atom,policy=_calibration_policy(db,read,predicate)
    inventory=read.complete_inventory(db,PREDICTION_TYPE)
    actual_predictions=tuple(sorted(atom.key.token for atom in inventory if atom.valid
        and atom.value['condition_predicate_ref']==predicate_ref))
    resolution_inventory=read.complete_inventory(db,RESOLUTION_TYPE)
    resolutions=[];counterexamples=[];roots=set((*predicate.source_refs,*policy.source_refs));support=set();items=[]
    for ref in actual_predictions:
        atom,prediction=_typed(db,read,ref,PredictionRecordV1)
        if (prediction.task_class!=policy.task_class or prediction.target_observable!=policy.target_observable
                or prediction.resolution_rule!=policy.resolution_rule or prediction.target_head.key.token not in policy.population_scope_refs):
            raise ValueError('prediction calibration crossed its actual registered population, observable or rule')
        roots.update(prediction.source_refs)
        choices=[]
        for item in resolution_inventory:
            if not item.valid or item.value['prediction_ref']!=ref:continue
            _,value=_typed(db,read,item.key.token,PredictionResolutionV1)
            if value.prediction_digest!=canonical_digest(atom.value):raise ValueError('resolution substituted its frozen prediction')
            choices.append((value.resolved_at,item.key.token,value))
        observed=[item for item in choices if item[2].observation_unit_ref is not None]
        if len({(item[2].observation_unit_ref,item[2].outcome_ref,item[2].outcome_digest)for item in observed})>1:
            raise ValueError('one prediction cannot claim different independent actual outcomes')
        chosen=max(observed or choices,default=None)
        value=None if chosen is None else chosen[2]
        if chosen is not None:
            resolution_ref=chosen[1];resolutions.append(resolution_ref);roots.update(value.source_refs)
            if value.calibration_status=='counterexample':counterexamples.append(resolution_ref)
        items.append((prediction.resolution_target_ref,None if value is None else value.observation_unit_ref,value))
    target_units={}
    for target,unit,_ in items:
        if unit is None:continue
        if target in target_units and target_units[target]!=unit:raise ValueError('one frozen observer target claimed different physical observation units')
        target_units[target]=unit
    units={}
    for target,unit,value in items:
        key=unit or target_units.get(target)or('unobserved-target:'+target)
        units.setdefault(key,[]).append(value)
    counts={'matched':0,'counterexample':0};unknown=0
    for values in units.values():
        statuses={None if value is None else value.calibration_status for value in values}
        if len(statuses)!=1 or next(iter(statuses))not in counts:unknown+=1;continue
        status=next(iter(statuses));counts[status]+=1
        if status=='matched':
            for value in values:
                records=read.source_family(db,value.source_refs,purpose='consolidation')if value.source_refs else{}
                support.update(record.provenance_root for record in records.values())
    known=sum(counts.values());total=len(units)
    threshold=(known>=policy.minimum_verified_outcomes
        and(policy.missing_outcome_policy=='report_known_and_unknown'or unknown==0)
        and policy.valid_from<=read.frame.now_utc<policy.valid_until)
    return _CalibrationReadoutV1(actual_predictions,tuple(resolutions),tuple(counterexamples),tuple(counts.items()),unknown,
        tuple(sorted(roots)),tuple(sorted(support)),total,predicate.calibration_policy_ref,canonical_digest(policy_atom.value),
        policy.minimum_verified_outcomes,known/total if total else 0.0,threshold)


def _actual_forecast_parent(db,read,readers,plan_ref,simulation_operation_id):
    atom,plan=_typed(db,read,plan_ref,SimulationForecastPlanV1)
    original=read.work._adopted(simulation_operation_id)
    if original is None or(original['domain'],original['operation_kind'])!=('d07','run_simulation'):
        raise MissingProductionOriginalV1('actual_adopted_simulation_producer_COMMIT')
    provenance=original['payload']['provenance'];behavior=provenance['behavior'];execution=provenance['execution']
    if (provenance['status']not in {'staged','already_recorded'}or execution is None
            or(behavior['forecast_plan_ref'],behavior['forecast_plan_digest'],behavior['forecast_mode'])!=
                (plan_ref,canonical_digest(atom.value),'declared_forecast')
            or behavior['registered_request_ref']!=plan.simulation_request_ref
            or plan.declared_at>execution['started_at']or execution['work_kind']!='simulation'
            or behavior['content_reality']!='hypothetical'or behavior['external_evidence_eligibility']!='none'):
        raise ValueError('forecast plan was not durably bound before its actual simulation execution')
    
    read.work._forecast_execution(atom,original)
    return atom,plan,original,behavior['simulation_result']


def _current_conditioned_strategies_v1(db,read,readers):
    from ..domains.d01.conditioned_self_v1 import decode_conditioned_self_claim_v1
    active=_active(read,readers);result=[]
    for block in active.plan.blocks:
        if block.kind!='strategy':continue
        value=decode_conditioned_self_claim_v1(block.claim)
        if type(value)is not ConditionedStrategyRevisionV1 or value.qualification=='rolled_back':continue
        ref=conditioned_key_v1(active.plan.namespace,STRATEGY_TYPE,conditioned_revision_record_name_v1(
            namespace=active.plan.namespace,type_name=STRATEGY_TYPE,record_id=value.strategy_id,revision=value.revision,review_ref=value.review_ref)).token
        _,actual=_typed(db,read,ref,ConditionedStrategyRevisionV1)
        if actual!=value:raise ValueError('current strategy claim lost its actual immutable revision')
        result.append((ref,value))
    return tuple(result)


def _review_request_from_actual_trigger_v1(db,read,readers,*,predicate_ref,trigger_ref,method_review_ref=None,origin_utc=None):
    from ..domains.d01.conditioned_self_v1 import decode_conditioned_self_claim_v1
    _,predicate=_typed(db,read,predicate_ref,ConditionPredicateV1);_,policy=_calibration_policy(db,read,predicate)
    active=_active(read,readers)
    block=next((b for b in active.plan.blocks if b.block_id==policy.review_target_block),None)
    if block is None or block.kind not in {'self_knowledge','strategy'}:
        raise MissingProductionOriginalV1('actual_Owner_configured_conditional_review_target')
    previous=decode_conditioned_self_claim_v1(block.claim)
    expected=ConditionedCapabilityRevisionV1 if block.kind=='self_knowledge'else ConditionedStrategyRevisionV1
    if previous is not None and type(previous)is not expected:raise ValueError('configured review target changed its semantic kind')
    ns=active.plan.namespace;identity=RuntimeIdentityRef.from_owner_guard(ns,readers.owner_guard)
    name=(previous.capability_id if expected is ConditionedCapabilityRevisionV1 else previous.strategy_id)if previous is not None else 'conditioned-self:'+canonical_digest((identity,block.block_id))[:40]
    revision=1 if previous is None else previous.revision+1
    previous_type=CAPABILITY_TYPE if expected is ConditionedCapabilityRevisionV1 else STRATEGY_TYPE
    previous_ref=None if previous is None else conditioned_key_v1(ns,previous_type,conditioned_revision_record_name_v1(
        namespace=ns,type_name=previous_type,record_id=name,revision=previous.revision,
        review_ref=previous.last_review_ref if previous_type==CAPABILITY_TYPE else previous.review_ref)).token
    calibration=_current_prediction_calibration_v1(db,read,predicate_ref,predicate)
    counterexamples=calibration.counterexamples;source_refs=calibration.source_refs
    trigger_atom=read.head(db,trigger_ref,required=True)
    if trigger_atom.key.type_name==RESOLUTION_TYPE:
        _,trigger_resolution=_typed(db,read,trigger_ref,PredictionResolutionV1)
        _,trigger_prediction=_typed(db,read,trigger_resolution.prediction_ref,PredictionRecordV1)
        if trigger_prediction.condition_predicate_ref!=predicate_ref:
            if(previous is None or expected is not ConditionedStrategyRevisionV1
                    or previous.condition_predicate_ref!=trigger_prediction.condition_predicate_ref
                    or trigger_resolution.calibration_status!='counterexample'):
                raise ValueError('narrow review changed its actual adopted strategy counterexample')
            counterexamples=tuple(dict.fromkeys((*counterexamples,trigger_ref)))
            source_refs=tuple(sorted(set((*source_refs,*trigger_resolution.source_refs))))
    strategy=None
    if expected is ConditionedStrategyRevisionV1:
        from ..domains.d01.method_learning_v1 import MethodOutcomeReviewV1,TRIAL_METHOD,BASELINE_METHOD
        
        review_ref=method_review_ref or(None if previous is None else previous.method_outcome_review_ref)
        if review_ref is None:raise MissingProductionOriginalV1('actual_method_review_before_strategy_candidate')
        atom,method=_typed(db,read,review_ref,MethodOutcomeReviewV1);_origin(db,read,atom,'review_current_method_growth_v1')
        if method.qualification!='qualified'or method.target_block!=block.block_id:
            raise MissingProductionOriginalV1('actual_qualified_method_review_for_configured_strategy_target')
        head=next(v for v in active.read_versions if v.key.type_name=='d01.persona_plan.v1')
        review_id=_conditioned_review_id_v1(head,block.block_id,predicate_ref,name,revision,calibration.resolution_refs,trigger_ref,review_ref)
        rollback_ref=predicate.rollback_predicate_ref
        if rollback_ref is None:raise MissingProductionOriginalV1('actual_registered_strategy_rollback_predicate')
        strategy=ConditionedStrategyRevisionV1(identity,name,revision,previous_ref,predicate_ref,TRIAL_METHOD,BASELINE_METHOD,
            predicate.scope_refs,calibration.support_families,counterexamples,(method.trial_ref,),
            predicate.exclusions,rollback_ref,conditioned_key_v1(ns,REVIEW_TYPE,review_id).token,review_ref,
            max(predicate.valid_from,read.frame.now_utc if origin_utc is None else origin_utc),predicate.valid_until,'candidate',source_refs)
    return ReviewCurrentConditionedSelfRequestV1(trigger_ref,block.block_id,predicate_ref,calibration.prediction_refs,
        name,revision,previous_ref,strategy)


def _review_requests_for_actual_resolution_v1(db,read,readers,ref,resolution,prediction,*,origin_utc=None):
    _,predicate=_typed(db,read,prediction.condition_predicate_ref,ConditionPredicateV1)
    _,policy=_calibration_policy(db,read,predicate);active=_active(read,readers)
    block=next((b for b in active.plan.blocks if b.block_id==policy.review_target_block),None)
    if block is None or block.kind not in {'self_knowledge','strategy'}:
        raise MissingProductionOriginalV1('actual_configured_counterexample_review_target')
    if block.kind!='strategy'or resolution.calibration_status!='counterexample':
        return(_review_request_from_actual_trigger_v1(db,read,readers,predicate_ref=prediction.condition_predicate_ref,trigger_ref=ref,origin_utc=origin_utc),)
    from ..domains.d01.conditioned_self_v1 import decode_conditioned_self_claim_v1
    previous=decode_conditioned_self_claim_v1(block.claim)
    if(type(previous)is not ConditionedStrategyRevisionV1 or previous.condition_predicate_ref!=prediction.condition_predicate_ref):
        raise MissingProductionOriginalV1('actual_adopted_strategy_for_counterexample_narrowing')
    goal=_forecast_goal_v1(db,read,prediction);requests=[]
    for atom in read.complete_inventory(db,CONDITION_TYPE):
        if not atom.valid:continue
        _,narrow=_typed(db,read,atom.key.token,ConditionPredicateV1)
        if(narrow.calibration_policy_ref!=predicate.calibration_policy_ref
                or narrow.calibration_policy_digest!=predicate.calibration_policy_digest
                or not set(narrow.scope_refs)<=set(previous.applicable_scope)
                or not set(predicate.conditions)<set(narrow.conditions)
                or not set(previous.exclusions)<=set(narrow.exclusions)
                or narrow.rollback_predicate_ref is None
                or not narrow.valid_from<=read.frame.now_utc<narrow.valid_until):continue
        values,_,_,_=_condition_facts_v1(db,read,goal,narrow)
        if not all(values.get(key)is value for key,value in narrow.conditions):continue
        requests.append(_review_request_from_actual_trigger_v1(db,read,readers,predicate_ref=atom.key.token,trigger_ref=ref,origin_utc=origin_utc))
    if not requests:raise MissingProductionOriginalV1('actual_current_Owner_registered_strict_narrow_condition')
    return tuple(requests)


def resolve_current_conditioned_followup_command_v1(db,*,frame,event,producer_original,readers):
    
    if(event.event_kind not in CONDITIONED_PRODUCER_EVENTS_V1 or producer_original is None
            or(producer_original['domain'],producer_original['operation_kind'])not in CONDITIONED_PRODUCER_EVENTS_V1[event.event_kind]
            or producer_original['receipt'].operation_id!=event.causal_operation_id):
        raise ValueError('conditional followup has another exact fully committed producer')
    read=frame.core_read;read.check(db);p=producer_original['payload']['provenance'];commands=[]
    if not set(p['conditioned_source_roots'])<=set(frame.envelope.source_qualification.source_refs):
        raise ValueError('conditional followup changed its actual signed producer Source roots')
    kind=event.event_kind
    if kind=='conditioned_simulation_committed_v1':
        ref=p['behavior']['forecast_plan_ref'];_,plan,_,actual=_actual_forecast_parent(db,read,readers,ref,event.causal_operation_id)
        from ..domains.d07.prediction_v1 import SimulationBranchV1
        branches=[]
        for index,row in enumerate(actual['branches']):
            members=tuple(v.key for v in producer_original['receipt'].write_versions if v.key.type_name=='d07.simulation_branch.v1'and v.key.name==row['branch_id'])
            if len(members)!=1:raise ValueError('simulation branch is not its real producer COMMIT member')
            branch_ref=members[0].token
            forecasts=tuple(conditioned_key_v1(plan.namespace,PREDICTION_TYPE,item.prediction_id).token for item in plan.forecasts if item.branch_ref==branch_ref)
            branches.append(SimulationBranchV1(branch_ref,()if index==0 else(plan.alternative_assumption_refs[index-1],),forecasts))
        record=SimulationRecordV1(plan.namespace,'simulation-record:'+canonical_digest((event.causal_operation_id,ref))[:40],
            plan.baseline_snapshot,branches[0],tuple(branches[1:]),(), 'frozen_baseline_two_alternatives_two_steps',plan.source_refs)
        commands.append(('record_current_simulation_v1',RecordCurrentSimulationRequestV1(record,ref,event.causal_operation_id)))
        commands.extend(('register_current_prediction_v1',RegisterCurrentPredictionRequestV1(value,ref,event.causal_operation_id,value.branch_ref,index))for index,value in enumerate(plan.forecasts))
    elif kind=='conditioned_observed_outcome_committed_v1':
        if producer_original['operation_kind']=='register_artifact_task_milestone_v2':
            outcomes=(read.work._artifact_milestone_from_producer(producer_original).original_ref,)
        else:outcomes=tuple(v.key.token for v in producer_original['receipt'].write_versions if v.key.type_name in {'d08.action_outcome.v1','d10.life_progress.v1'})
        for atom in read.complete_inventory(db,PREDICTION_TYPE):
            if atom.valid and atom.value['resolution_target_ref']in outcomes:
                _,prediction=_typed(db,read,atom.key.token,PredictionRecordV1)
                commands.append(('resolve_current_prediction_v1',ResolveCurrentPredictionRequestV1(atom.key.token,prediction.resolution_target_ref)))
    elif kind=='conditioned_calibration_resolution_committed_v1':
        refs=tuple(v.key.token for v in producer_original['receipt'].write_versions if v.key.type_name==RESOLUTION_TYPE)
        for ref in refs:
            _,resolution=_typed(db,read,ref,PredictionResolutionV1);_,prediction=_typed(db,read,resolution.prediction_ref,PredictionRecordV1)
            commands.extend(('review_current_conditioned_self_v1',request)for request in
                _review_requests_for_actual_resolution_v1(db,read,readers,ref,resolution,prediction,origin_utc=producer_original['payload']['now_utc']))
    elif kind=='conditioned_method_review_committed_v1':
        method_refs=tuple(v.key.token for v in producer_original['receipt'].write_versions if v.key.type_name=='d01.method_outcome_review.v1')
        for method_ref in method_refs:
            from ..domains.d01.method_learning_v1 import MethodOutcomeReviewV1
            
            _,method=_typed(db,read,method_ref,MethodOutcomeReviewV1)
            for atom in read.complete_inventory(db,CONDITION_TYPE):
                if not atom.valid:continue
                _,predicate=_typed(db,read,atom.key.token,ConditionPredicateV1);_,policy=_calibration_policy(db,read,predicate)
                if policy.review_target_block!=method.target_block:continue
                calibration=_current_prediction_calibration_v1(db,read,atom.key.token,predicate)
                if not calibration.resolution_refs:raise MissingProductionOriginalV1('actual_calibration_resolution_before_method_strategy_review')
                commands.append(('review_current_conditioned_self_v1',_review_request_from_actual_trigger_v1(db,read,readers,
                    predicate_ref=atom.key.token,trigger_ref=calibration.resolution_refs[-1],method_review_ref=method_ref,origin_utc=producer_original['payload']['now_utc'])))
    elif kind=='conditioned_conditions_committed_v1':
        goal_ref=p['goal_ref'];goal=read.head(db,goal_ref,required=True)
        questions=tuple(v.key.token for v in producer_original['receipt'].write_versions if v.key.type_name=='d07.current_interpretation.v1')
        if not questions:return ()
        plans=tuple(atom for atom in read.complete_inventory(db,'d08.personal_plan.v1')if atom.valid and atom.value['goal_ref']==goal_ref)
        for plan in plans:
            for ref,strategy in _current_conditioned_strategies_v1(db,read,readers):
                commands.append(('match_current_conditioned_strategy_v1',MatchCurrentConditionedStrategyRequestV1(ref,questions[0],
                    goal_ref,goal.value['revision'],tuple(tuple(pair)for pair in plan.value['method_candidates']))))
    elif kind=='conditioned_life_phase_committed_v1':
        progress=p['actual_progress']
        for ref,strategy in _current_conditioned_strategies_v1(db,read,readers):
            commands.append(('project_current_conditioned_life_strategy_v1',ProjectCurrentConditionedLifeStrategyRequestV1(
                progress['project_ref'],progress['recipe_ref'],ref)))
    distinct={canonical_digest((operation,request)):(operation,request)for operation,request in commands}
    if len(distinct)>frame.limits.max_followup_jobs:
        raise MissingProductionOriginalV1('complete_conditioned_child_set_exceeds_original_followup_bound')
    return tuple(distinct[key]for key in sorted(distinct))



def _typed(db,read,ref,cls):
    atom=read.head(db,ref,required=True)
    from ..domains.d01.method_learning_v1 import MethodOutcomeReviewV1
    expected=VALUE_TYPES.get(atom.key.type_name)
    if cls is MethodOutcomeReviewV1:expected=MethodOutcomeReviewV1 if atom.key.type_name=='d01.method_outcome_review.v1'else None
    if expected is not cls:raise AuthorityUnavailable('conditioned Core body has another exact registered semantic type')
    value=decode_typed_production_value_v1(atom.value,cls)
    _origin(db,read,atom,'review_current_method_growth_v1'if cls is MethodOutcomeReviewV1 else PRODUCERS[atom.key.type_name])
    if value.source_refs:read.source_family(db,value.source_refs,purpose='consolidation')
    return atom,value


def _origin(db,read,atom,operation_kind=None):
    payload,row=read.work._require_actual_graph_origin(atom,operation_kind)
    original=read.work._adopted(row['operation_id'])
    if GraphVersion(atom.key,atom.revision)not in original['receipt'].write_versions:
        raise AuthorityUnavailable('conditioned Core semantic body lost its actual COMMIT member revision')
    return original


def _active(read,readers):
    from ..domains.d01 import PersonaDomain
    return PersonaDomain().resolve_active_role(read.frame.snapshot,namespace=read.work.namespace,
        current_guard=read.work.owner_entry[1].head.guard)


class _ConditionedCoreSemanticReadV1:
    def __init__(self,work):
        from types import SimpleNamespace
        from ..graph_types import GraphSnapshot,NamespaceEpoch
        from ..runtime_contracts import QueryEpoch
        from ..runtime.domain_production_contracts_v1 import ProductionQueryCoverageV1
        require_conditioned_core_source_work_v1(work)
        if work.phase!='body':raise AuthorityUnavailable('conditioned Core semantic reader requires its completed ALL Source closure')
        self.work=work
        atoms=tuple(work._graph_body(ref)for ref in sorted(work.graph_metadata)
            if AtomKey.from_token(ref).type_name not in {'memory.source','memory.access','d06.source_correction_head.v1'})
        epoch=QueryEpoch(work.namespace,'namespace',work.stamp[0])
        pages=tuple(ProductionQueryCoverageV1(epoch,name,versions,True,None)for name,versions in sorted(work.query_pages.items()))
        self.frame=SimpleNamespace(snapshot=GraphSnapshot(atoms,(NamespaceEpoch(*work.namespace.as_tuple,work.stamp[0]),)),
            query_coverage=pages,now_utc=work.observed_at_utc,owner_guard=work.owner_guard,core_read=self,
            limits=SimpleNamespace(max_query_rows=128,max_followup_jobs=16),
            envelope=SimpleNamespace(authority=SimpleNamespace(namespace=work.namespace),
                source_qualification=SimpleNamespace(source_refs=tuple(work.sources)),
                parent_budget_lease_ref=work.selector.parent_budget_lease_ref))

    def check(self,db):
        if db is not self.work.db:raise AuthorityUnavailable('conditioned Core semantic reader crossed its actual database')
        require_conditioned_core_source_work_v1(self.work)
        self.work._observe()
        return self.frame.snapshot

    def head(self,db,ref,*,required=False):
        self.check(db);token=ref.token if type(ref)is AtomKey else ref
        atom=self.work._graph_body(token)
        if required and(not atom.valid or atom.revision<1):raise MissingProductionOriginalV1('actual_current_conditioned_'+atom.key.type_name)
        return atom

    def complete_inventory(self,db,type_name):
        self.check(db)
        if type_name not in self.work.query_pages:raise AuthorityUnavailable('conditioned Core semantic inventory lacks its exact complete metadata census')
        return tuple(self.head(db,version.key)for version in self.work.query_pages[type_name])

    def source_family(self,db,roots,*,purpose=None,audience=None):
        from types import SimpleNamespace
        self.check(db);purpose=purpose or self.work.selector.purpose
        audiences=(audience,)if audience is not None else self.work.selector.audiences
        pending=list(roots);seen=set();records={}
        while pending:
            ref=pending.pop()
            if ref in seen:continue
            source=self.work.sources.get(ref)
            group=((purpose,),tuple(audiences),ref)
            if source is None or group not in self.work.source_commitments:
                raise AuthorityUnavailable('conditioned Core semantic consumer has no exact independently qualified Source purpose/audience group')
            seen.add(ref);records[ref]=SimpleNamespace(**source.metadata)
            from ..memory_types import source_key
            pending.extend(source_key(*self.work.namespace.as_tuple,parent).token for parent in source.metadata['parent_source_ids'])
        return records

    def producing_operation(self,ref):
        try:key=AtomKey.from_token(ref)
        except(ValueError,TypeError):
            for identity,(header,locator,digest)in self.work.signed_metadata.items():
                if identity[2]==ref and len(header)==3:return header[0]
            for operation_id,(header,locator,bundle,cause)in self.work.producers.items():
                if header[0]+'-current:'+header[3][:48]==ref:return operation_id
            raise AuthorityUnavailable('conditioned Core Original is outside its independently selected actual producers')
        atom=self.head(self.work.db,key,required=True)
        return self.work.history_metadata[(key.token,atom.revision)][2]

    def original(self,ref,*,kind=None,digest=None):
        from ..runtime.domain_production_contracts_v1 import ProductionOriginalRefV1
        for identity,raw in self.work.signed_bodies.items():
            if identity[1]=='adopted_life':
                from ..runtime.d11_life_contract_v1 import life_from_wire_v1,D11LifeTerminalV1
                terminal=life_from_wire_v1(raw['terminal'],D11LifeTerminalV1)
                if terminal.original_ref==ref:
                    operation=raw['producing_operation_id']
                    if operation not in self.work.finished_proofs:raise AuthorityUnavailable('conditioned nested Life terminal lost its actual Core finished producer')
                    actual=terminal.terminal_digest
                    if digest is not None and digest!=actual:raise AuthorityUnavailable('conditioned actual terminal digest differs')
                    return ProductionOriginalRefV1(kind or 'd11.life_terminal',ref,actual,())
        try:key=AtomKey.from_token(ref)
        except(ValueError,TypeError):key=None
        if key is not None:
            atom=self.head(self.work.db,key,required=True);_origin(self.work.db,self,atom)
            actual=canonical_digest(atom.value);versions=(GraphVersion(key,atom.revision),)
        else:
            operation=self.producing_operation(ref);original=self.work._adopted(operation)
            actual=next((metadata[0][-2]for identity,metadata in self.work.signed_metadata.items()if identity[2]==ref),original['original_digest'])
            versions=original['read_versions']
        if digest is not None and digest!=actual:raise AuthorityUnavailable('conditioned Core actual Original digest differs')
        return ProductionOriginalRefV1(kind or 'conditioned.actual-original.v1',ref,actual,versions)


def _condition_question_locator_v1(db,read,goal_ref,goal_revision):
    from ..domains.d07 import decode_method_condition_question_v1
    for atom in read.complete_inventory(db,'d07.current_interpretation.v1'):
        if not atom.valid or not atom.value.get('current'):continue
        scope=decode_method_condition_question_v1(atom.value.get('question_key'))
        if scope is not None and(scope['goal_ref'],scope['goal_revision'])==(goal_ref,goal_revision):return atom.key.token
    raise MissingProductionOriginalV1('actual_current_D07_condition_question')
