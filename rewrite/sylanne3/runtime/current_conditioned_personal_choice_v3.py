"""Actual D08 prepared-choice locator for the conditioned Self Source Work.

The private locator grants only declared metadata reads. Owner EOF precedes its
Match census; the final immutable request then enters the independent Self READ.
"""
from __future__ import annotations
from dataclasses import dataclass,replace
from weakref import WeakKeyDictionary
import time
from ..authority_service.contract import AuthorityUnavailable
from ..graph_types import AtomKey,GraphVersion
from ..runtime_contracts import NamespaceId,AuthorityContext,canonical_digest,canonical_serialize
from ..runtime_storage_v3 import runtime_storage_quantum_v3

_ISSUER=object()
_LOCATORS=WeakKeyDictionary()
_C1_BODIES=WeakKeyDictionary()
_KIND='select_current_conditioned_personal_step_v1'
_MATCH='d07.condition_match.v1'
_QUESTION='d07.current_interpretation.v1'
_HEADER=('domain','operation_kind','request_digest','original_digest','receipt_digest','bundle_digest')


@dataclass(frozen=True,slots=True)
class _ChoiceCauseV3:
    namespace: NamespaceId
    causal_operation_id: str
    original_digest: str
    receipt_digest: str
    parent_budget_lease_ref: str
    original_deadline_utc: float
    source_refs: tuple[str,...]
    authority: AuthorityContext


class _ChoiceColumnV3:
    """One exact PK; physical EOF and semantic canonical SHA cover skipped fields."""
    def __init__(self,owner,table,column,keys,key,headers,retain):
        from .conditioned_producer_source_metadata_v3 import ConditionedLocatorJSONV3
        self.owner,self.operation=owner,owner.operation
        self.table,self.column,self.keys,self.key,self.headers=table,column,keys,key,headers
        self.where=' AND '.join(name+'=?'for name in keys)
        self.header=None;self.total=None;self.offset=0;self.cell=None
        self.fragment=b'';self.fragment_offset=0;self.complete=False;self.result=None;self.digest=None
        self.capture=ConditionedLocatorJSONV3(self);self.capture.retain_path_v3=retain
        self.semantic_decoder=self.semantic_hash=None
    def _actual(self):
        require_personal_choice_locator_v3(self.owner)
        return self
    def _header(self,meter):
        row=meter.read_fixed_row(self.owner.db,self.table,self.headers,self.where,self.key)
        if self.header is not None and row!=self.header:
            raise AuthorityUnavailable('personal choice metadata changed during full EOF')
        return row
    def advance(self,meter):
        from .c09_paged_sql_v2 import legacy_cell_read_transaction_v2,read_legacy_sql_cell_fragment_v2
        self._actual();self.owner.require_current_v3()
        if self.complete:self._header(meter);return True
        if self.header is None:
            self.header=self._header(meter)
            if self.header is None:self.complete=True;return True
            if 'value_cell_id'in self.headers:
                from ..runtime_storage_v3 import begin_runtime_cell_read_v3
                from .conditioned_producer_source_metadata_v3 import ConditionedMetadataJSONStreamV3
                cell_id=self.header[self.headers.index('value_cell_id')]
                if cell_id is None:raise AuthorityUnavailable('personal choice Graph metadata has no physical cell')
                self.cell=begin_runtime_cell_read_v3(self.owner.db,cell_id,erasure_owner_ref=self.key[0])
                codec=self.cell.header[0]
                if codec not in {'canonical-json.ascii.v1','canonical-json.utf8.v1'}:
                    raise AuthorityUnavailable('personal choice metadata uses an unknown actual Graph codec')
                self.capture.parser=ConditionedMetadataJSONStreamV3(self.capture,ensure_ascii=codec!='canonical-json.utf8.v1')
                if codec=='canonical-json.utf8.v1':
                    import codecs,hashlib
                    self.semantic_decoder=codecs.getincrementaldecoder('utf8')('strict');self.semantic_hash=hashlib.sha256()
            return False
        self._header(meter)
        if self.fragment_offset<len(self.fragment):
            end=min(self.fragment_offset+1024,len(self.fragment));chunk=self.fragment[self.fragment_offset:end]
            self.capture._reserve_v3(131072);self.capture.parser.feed(chunk,self.capture._emit_v3)
            if self.semantic_decoder is not None:
                from ..authority_service.d07_authority_model_source_read_v3 import _D07AuthorityGraphMetadataColumnV3
                _D07AuthorityGraphMetadataColumnV3._semantic_v3(self,chunk,meter)
            self.fragment_offset=end;self.capture._flush_text_v3();return False
        if self.cell is not None:chunk=self.cell.read_fragment(meter=meter)
        else:
            with legacy_cell_read_transaction_v2(self.owner.db):
                if self.total is None:
                    row=self.owner.db.execute('SELECT typeof('+self.column+'),length(CAST('+self.column+' AS BLOB)) FROM '+self.table+' WHERE '+self.where,self.key).fetchone()
                    meter.charge_read(16)
                    if row is None or row[0]!='text':raise AuthorityUnavailable('personal choice original metadata column disappeared')
                    self.total=row[1];return False
                chunk,total,kind=read_legacy_sql_cell_fragment_v2(self.owner.db,table=self.table,column=self.column,
                    where=self.where,parameters=self.key,start=self.offset,length=min(1024,self.total-self.offset),meter=meter)if self.offset<self.total else(None,self.total,'text')
                if(total,kind)!=(self.total,'text'):raise AuthorityUnavailable('personal choice metadata EOF changed physical length')
                if chunk:self.offset+=len(chunk)
        if chunk:self.fragment=chunk;self.fragment_offset=0;return False
        parsed=self.capture.parser.finish();self.capture._flush_text_v3()
        if self.cell is not None:
            if(parsed.byte_count,parsed.sha256)!=(self.cell.header[3],self.cell.finish(meter=meter)):
                raise AuthorityUnavailable('personal choice physical Graph cell EOF/root differs')
        elif parsed.byte_count!=self.total:raise AuthorityUnavailable('personal choice original full EOF is incomplete')
        if self.semantic_decoder is not None:
            from ..authority_service.d07_authority_model_source_read_v3 import _D07AuthorityGraphMetadataColumnV3
            _D07AuthorityGraphMetadataColumnV3._semantic_v3(self,b'',meter,final=True)
            self.digest=self.semantic_hash.hexdigest()
        else:self.digest=parsed.sha256
        self.result=self.capture.value;self.complete=True;self.fragment=b''
        return True


def _prepared_path_v3(path):
    if not path:return True
    if path[0]in {'schema','namespace','identity','authority','parent_budget','owner_guard','request','read_versions','query_coverage','coverage'}:return True
    return path[0]=='provenance'and(len(path)==1 or path[1]=='prepared_candidates')


def _graph_path_v3(path):
    from .conditioned_producer_source_metadata_v3 import CONDITIONED_LOCATOR_FIELDS_V3
    return not path or path[0]in CONDITIONED_LOCATOR_FIELDS_V3 or path[0]=='business_revision'


class _PreparedChoiceLocatorV3:
    def __init__(self,issuer,graph,bootstrap,bundle,operation,*,c02_operation_id,source_ref,preparation,plan_ref,goal_ref):
        from uuid import uuid4
        if issuer is not _ISSUER:raise AuthorityUnavailable('personal choice locator requires its actual installed factory')
        self.graph,self.bootstrap,self.bundle,self.operation=graph,bootstrap,bundle,operation
        self.store=graph._GraphCoordinator__store;self.db=self.store._db
        self.runtime=graph._GraphCoordinator__domain_production_runtime_v1
        self.namespace=bundle.installation_policy.namespace;self.operation_id=operation.operation_id
        self.c02_operation_id,self.source_ref,self.preparation_operation_id=c02_operation_id,source_ref,preparation
        self.plan_ref,self.goal_ref=plan_ref,goal_ref
        self.work=self.fence=self.authority=None;self.session_proof=None;self.read_finished=False
        self.owner_binding=self.owner_guard=self.material_owner_guard=None
        self.general_owner_entry=None;self.cause_complete=False;self.cause_metadata=None
        self.read_scope_nonce=uuid4().hex;self.graph_stamp=graph._v2_graph_stamp(self.namespace)
        self.selection_digest=operation.selection_digest;self.initial_monotonic_deadline=time.monotonic()+60.0
        self.phase='producer';self.columns={};self.prepared=None;self.prepared_request=None
        self.match_after=None;self.match_rows=[];self.match_metadata={};self.question_metadata={}
        self.match_pending=None;self.match_refs=None;self.match_commitment=None
        self.request=None;self.operation_kind=_KIND;self.evidence_plan=None;self.personal_signed={};self.personal_policies={}
        self.replay_selector=None
        _LOCATORS[self]=(graph,bootstrap,bundle,operation,c02_operation_id,source_ref,preparation,plan_ref,goal_ref)
        from .current_conditioned_self_read_v3 import _CONDITIONED_LOCATOR_READERS_V3
        _CONDITIONED_LOCATOR_READERS_V3[self]=_LOCATORS[self]
    def require_current_v3(self):
        require_personal_choice_locator_v3(self)
        if self.graph._v2_graph_stamp(self.namespace)!=self.graph_stamp:
            raise AuthorityUnavailable('personal choice locator Graph/authority stamp changed')
        if time.monotonic()>=self.initial_monotonic_deadline:
            raise AuthorityUnavailable('personal choice metadata original monotonic deadline expired')
        if self.general_owner_entry is not None:self.general_owner_entry.require_for_v3(self)
    def column_v3(self,label,table,column,keys,key,headers,retain,meter):
        task=self.columns.get(label)
        if task is None:
            task=_ChoiceColumnV3(self,table,column,keys,key,headers,retain);self.columns[label]=task
        return task if task.advance(meter)else None
    def producer_v3(self,meter):
        from .domain_production_originals_v1 import TABLE,_receipt
        from .natural_frozen_original_read_v3 import _CanonicalComparisonV3
        from .domain_production_erasure_v1 import decode_typed_production_value_v1 as typed
        from ..domains.d08.personal_candidate_v1 import PreparedPersonalCandidateSetV1,PrepareCurrentPersonalCandidatesRequestV1
        key=(*self.namespace.as_tuple,self.preparation_operation_id)
        payload=self.column_v3('producer',TABLE,'original_payload_json',('bot','persona','operation_id'),key,_HEADER,_prepared_path_v3,meter)
        if payload is None:return False
        if payload.header is None or payload.header[:2]!=('d08','prepare_personal_candidates_v1')or payload.digest!=payload.header[3]:
            raise AuthorityUnavailable('personal choice requires actual complete D08 preparation original')
        raw=payload.result
        if raw['schema']!='d08.current-prepare_personal_candidates_v1.v1'or raw['namespace']!={'bot_id':self.namespace.bot_id,'persona_id':self.namespace.persona_id}or raw['identity']['operation_id']!=self.preparation_operation_id:
            raise AuthorityUnavailable('personal choice producer namespace/operation differs')
        if self.prepared is None:
            self.prepared=typed(raw['provenance']['prepared_candidates'],PreparedPersonalCandidateSetV1)
            self.prepared_request=typed(raw['request'],PrepareCurrentPersonalCandidatesRequestV1)
            from .natural_frozen_original_read_v3 import _canonical_container_bytes_v3
            self.operation.retain(_canonical_container_bytes_v3((self.prepared,self.prepared_request))*2+65536)
            self._validate_prepared_v3(raw,payload.header)
        receipt=self.column_v3('receipt',TABLE,'receipt_json',('bot','persona','operation_id'),key,_HEADER,lambda path:True,meter)
        if receipt is None:return False
        if not hasattr(self,'receipt'):
            self.receipt=_receipt(receipt.result);self.receipt_hash=_CanonicalComparisonV3(self.receipt,operation=self.operation)
        if not self.receipt_hash.complete and not self.receipt_hash.advance(meter):return False
        bundle=meter.read_fixed_row(self.db,'graph_bundle_operations',('digest','activity_id','effect_id','commit_seq'),
            'bot=? AND persona=? AND operation_id=?',key)
        if(self.receipt_hash.digest!=payload.header[4]or self.receipt.status!='committed'
                or self.receipt.operation_id!=self.preparation_operation_id or self.receipt.operation_digest!=payload.header[5]
                or bundle!=(self.receipt.operation_digest,self.receipt.activity_id,self.receipt.effect_id,self.receipt.commit_seq)
                or self.receipt.commit_seq<1):
            raise AuthorityUnavailable('personal choice preparation lacks its actual original W01 receipt/bundle')
        reads=self.column_v3('reads',TABLE,'read_versions_json',('bot','persona','operation_id'),key,_HEADER,lambda path:True,meter)
        if reads is None:return False
        from .current_conditioned_self_read_v3 import _metadata_versions_v3
        if receipt.header!=payload.header or reads.header!=payload.header or reads.result!=[[v.key.token,v.revision]for v in _metadata_versions_v3(raw['read_versions'])]:
            raise AuthorityUnavailable('personal choice actual producer readset differs')
        self.cause_complete=True;self.phase='owner';return True
    def _validate_prepared_v3(self,raw,header):
        from .d08_personal_candidate_v1 import artifact_task_choice_ids_v2
        from ..domains.d08.personal_candidate_v1 import ArtifactPhaseCandidateBindingV1,ArtifactPhaseCandidateBindingV2,ArtifactPhaseCandidateBindingV3
        p=self.prepared;q=self.prepared_request
        if(not p.candidates or any(type(row.binding)not in {ArtifactPhaseCandidateBindingV1,ArtifactPhaseCandidateBindingV2,ArtifactPhaseCandidateBindingV3}for row in p.candidates)):
            raise AuthorityUnavailable('installed Artifact choice requires its actual finite Artifact bindings')
        tasks={row.binding.task for row in p.candidates}
        if len(tasks)!=1:raise AuthorityUnavailable('prepared Artifact candidates crossed task/C02 identities')
        self.task=next(iter(tasks));ids=artifact_task_choice_ids_v2(self.task,p.plan_head)
        from .d08_personal_candidate_v1 import prospective_personal_decision_key_v1
        future=AtomKey.from_token(p.future_decision_ref)
        if future.owner.kind!='activity'or NamespaceId.from_key(future)!=self.namespace:
            raise AuthorityUnavailable('personal choice future Decision has no actual preparation activity')
        self.activity_id=future.owner.subject
        if future!=prospective_personal_decision_key_v1(self.namespace,self.activity_id,self.operation_id,self.plan_ref):
            raise AuthorityUnavailable('personal choice future Decision changed its canonical selection/activity/Plan derivation')
        if(self.task.namespace!=self.namespace or self.task.c02_operation_id!=self.c02_operation_id
                or self.source_ref not in p.source_refs or ids['prepare']!=self.preparation_operation_id
                or ids['select']!=p.selection_operation_id or p.selection_operation_id!=self.operation_id
                or p.preparation_operation_id!=self.preparation_operation_id or p.namespace!=self.namespace
                or NamespaceId.from_key(p.goal_head.key)!=self.namespace or raw['identity']['activity_id']!=self.activity_id
                or any(NamespaceId.from_key(AtomKey.from_token(ref))!=self.namespace for ref in p.source_refs)
                or GraphVersion(future,0)not in p.read_versions
                or any(page.epoch.namespace!=self.namespace for page in p.query_coverage)
                or(p.plan_head.key.token,p.goal_head.key.token)!=(self.plan_ref,self.goal_ref)
                or(q.plan_ref,q.goal_ref,q.expected_plan_revision,q.expected_goal_revision,q.selection_operation_id)!=
                    (self.plan_ref,self.goal_ref,p.plan_head.revision,p.goal_head.revision,self.operation_id)
                or {row.binding.candidate_ref:row.binding for row in p.candidates}!={binding.candidate_ref:binding for binding in q.bindings}
                or raw['parent_budget']!=p.parent_budget_lease_ref or raw['coverage']!='complete'
                ):
            raise AuthorityUnavailable('personal choice changed actual prepared request, heads, Root or stable selection identity')
        from .current_conditioned_self_read_v3 import _metadata_versions_v3
        if any(NamespaceId.from_key(v.key)!=self.namespace for v in _metadata_versions_v3(raw['read_versions'])):
            raise AuthorityUnavailable('personal choice producer readset crossed namespace')
        authority=raw['authority'];authority=AuthorityContext(**{**authority,'namespace':NamespaceId(**authority['namespace']),
            'owner_scope':tuple(authority['owner_scope']),'audience':tuple(authority['audience'])})
        if authority.namespace!=self.namespace:raise AuthorityUnavailable('personal choice producer authority crossed namespace')
        deadline=min(row.future_identity.deadline_utc for row in p.candidates)
        deadline=min(deadline,p.need.original_deadline_utc,self.bundle.installation_policy.root_grant.valid_until_utc)
        from .artifact_recipe_metadata_v3 import artifact_candidate_evidence_plan_from_metadata_v3
        self.evidence_plan=artifact_candidate_evidence_plan_from_metadata_v3(raw['provenance']['prepared_candidates'],preparation_original_digest=header[3])
        self.cause_metadata=_ChoiceCauseV3(self.namespace,self.preparation_operation_id,header[3],header[4],
            p.parent_budget_lease_ref,deadline,p.source_refs,authority)


def require_personal_choice_locator_v3(locator):
    record=_LOCATORS.get(locator)
    if(type(locator)is not _PreparedChoiceLocatorV3 or record is None or record!=(locator.graph,locator.bootstrap,locator.bundle,
            locator.operation,locator.c02_operation_id,locator.source_ref,locator.preparation_operation_id,locator.plan_ref,locator.goal_ref)
            or locator.operation.closed or locator.work is None or locator.work.operation is not locator.operation
            or locator.work.state is not locator):
        raise AuthorityUnavailable('personal choice metadata escaped its exact private locator Work')
    locator.work._require_invocation(locator.graph)
    return locator


def _choice_head_v3(locator,ref,meter):
    key=AtomKey.from_token(ref)
    if NamespaceId.from_key(key)!=locator.namespace:raise AuthorityUnavailable('personal choice declared Graph locator crossed namespace')
    return locator.column_v3(('head',ref),'graph_atoms','value',('token','bot','persona'),(ref,*locator.namespace.as_tuple),
        ('revision','valid','value_cell_id'),_graph_path_v3,meter)


def _advance_choice_owner_metadata_v3(locator,meter):
    from .ingress_artifact_task_scope_v1 import task_scope_ref_v1
    from .d11_life_preparation_v1 import TABLE,SIGN_KIND
    from ..domains.d01.production_operations_v1 import plain_v1
    p=locator.prepared
    for ref,revision in((locator.plan_ref,p.plan_head.revision),(locator.goal_ref,p.goal_head.revision)):
        column=_choice_head_v3(locator,ref,meter)
        if column is None:return False
        if column.header is None or column.header[:2]!=(revision,1):raise AuthorityUnavailable('personal choice prepared Plan/Goal is no longer current')
    owner=locator.general_owner_entry.require_for_v3(locator)
    if(p.owner_grant_revision!=owner.grant_revision or p.owner_grant_digest!=owner.grant_digest.removeprefix('sha256:')):
        raise AuthorityUnavailable('personal choice prepared Owner generation is no longer actual')
    ref=task_scope_ref_v1(locator.task.root_registration_ref)
    scope=locator.column_v3('task_scope',TABLE,'payload_json',('bot','persona','kind','original_ref'),
        (*locator.namespace.as_tuple,'artifact_task_scope',ref),('producing_operation_id','payload_digest','signature'),
        lambda path:not path or path[0]in {'schema','namespace','c02_operation_id','source_ref','root'},meter)
    if scope is None:return False
    if scope.header is None or scope.digest!=scope.header[1]:raise AuthorityUnavailable('personal choice lacks complete signed actual task scope')
    locator.graph._GraphCoordinator__d11_issuer._signer.verify(SIGN_KIND,
        canonical_serialize((locator.namespace,'artifact_task_scope',ref,scope.header[1])),scope.header[2])
    wire=scope.result;root=wire['root']
    if(wire['namespace']!=plain_v1(locator.namespace)or wire['c02_operation_id']!=locator.c02_operation_id
            or wire['source_ref']!=locator.source_ref or root['registration_ref']!=locator.task.root_registration_ref
            or root['installation_id']!=locator.bundle.installation_policy.installation_id):
        raise AuthorityUnavailable('personal choice task/Source/C02/installed Root association changed')
    from datetime import datetime
    root_deadline=datetime.fromisoformat(root['valid_until_utc'].replace('Z','+00:00')).timestamp()
    locator.draft_root_deadline=root_deadline
    c02key=(*locator.namespace.as_tuple,locator.c02_operation_id)
    c02=meter.read_fixed_row(locator.db,'graph_bundle_operations',('digest','activity_id','effect_id','commit_seq'),
        'bot=? AND persona=? AND operation_id=?',c02key)
    if c02 is None or c02[3]<1:raise AuthorityUnavailable('personal choice has no real first-ingress C02 W01')
    c02receipt=locator.column_v3('c02receipt','graph_bundle_operations','receipt_json',('bot','persona','operation_id'),c02key,
        ('digest','activity_id','effect_id','commit_seq'),lambda path:not path or path[0]in {'first_ingress_c02','commit_seq','ledger_refs','outbox_refs'},meter)
    if c02receipt is None:return False
    if c02receipt.header!=c02 or 'first_ingress_c02'not in c02receipt.result:
        raise AuthorityUnavailable('personal choice C02 is not its actual ingress receipt')
    if not _advance_choice_c02_receipt_v3(locator,c02,c02receipt,meter):return False
    return _advance_choice_selected_metadata_v3(locator,meter)


def _advance_choice_match_census_v3(locator,meter):
    """Complete keyset census under the actual Owner READ, including no-match EOF."""
    from ..domains.d07 import decode_method_condition_question_v1
    goal=locator.columns[('head',locator.goal_ref)].result
    if locator.match_pending is not None:
        ref=locator.match_pending
        column=_choice_head_v3(locator,ref,meter)
        if column is None:return False
        if column.header is None:raise AuthorityUnavailable('personal choice Match census row vanished')
        if column.header[1]:
            value=column.result;question=value.get('semantic_question_ref')
            if question is not None:
                q=_choice_head_v3(locator,question,meter)
                if q is None:return False
                if q.header is None:raise AuthorityUnavailable('personal choice Match lost its actual semantic question')
                locator.question_metadata[question]=(q.header,q.digest,q.result)
                scope=decode_method_condition_question_v1(q.result.get('question_key'))
                if q.header[1]and q.result.get('current')is True and scope is not None and(scope['goal_ref'],scope['goal_revision'])==(locator.goal_ref,goal['revision']):
                    locator.match_metadata[ref]=(column.header,column.digest,value)
        locator.match_pending=None;return False
    where='bot=? AND persona=? AND type_name=?';args=(*locator.namespace.as_tuple,_MATCH)
    if locator.match_after is not None:where+=' AND token>?';args+=(locator.match_after,)
    row=meter.read_fixed_row(locator.db,'graph_atoms',('token','revision','valid','value_cell_id'),where+' ORDER BY token',args)
    if row is not None:
        key=AtomKey.from_token(row[0])
        if NamespaceId.from_key(key)!=locator.namespace or key.type_name!=_MATCH:raise AuthorityUnavailable('personal choice Match census crossed declared family')
        locator.match_after=row[0];locator.match_rows.append(row);locator.match_pending=row[0]
        if len(locator.match_rows)>128:raise AuthorityUnavailable('personal choice Match inventory exceeds original 128-row bound')
        locator.operation.retain(1024);return False
    locator.match_refs=tuple(sorted(locator.match_metadata))
    if len(locator.match_refs)>6:raise AuthorityUnavailable('personal choice relevant Match set exceeds original six-candidate bound')
    if locator.replay_selector is not None and locator.replay_request.condition_match_refs!=locator.match_refs:
        raise AuthorityUnavailable('personal choice replay current Match census differs from its immutable original request')
    if not hasattr(locator,'match_hash'):
        from .natural_frozen_original_read_v3 import _CanonicalComparisonV3
        locator.match_hash=_CanonicalComparisonV3((locator.graph_stamp,tuple(locator.match_rows),
            tuple((ref,*locator.match_metadata[ref][:2])for ref in sorted(locator.match_metadata)),
            tuple((ref,*locator.question_metadata[ref][:2])for ref in sorted(locator.question_metadata))),operation=locator.operation)
    if not locator.match_hash.complete and not locator.match_hash.advance(meter):return False
    locator.match_commitment=locator.match_hash.digest
    return True


def personal_choice_owner_identity_v3(locator):
    require_personal_choice_locator_v3(locator)
    if not locator.cause_complete or locator.fence is None or locator.phase not in {'owner','metadata','matches'}:
        raise AuthorityUnavailable('personal choice Owner caller lacks actual preparation EOF and original READ')
    return locator,canonical_digest(locator.cause_metadata)


def is_personal_choice_locator_v3(value):
    return type(value)is _PreparedChoiceLocatorV3 and value in _LOCATORS


def personal_choice_locator_for_reader_v3(reader):
    locator=getattr(reader,'conditioned_cause_locator',None)
    if not is_personal_choice_locator_v3(locator):return None
    from .current_conditioned_self_read_v3 import require_conditioned_self_work_v3
    require_conditioned_self_work_v3(reader)
    if(locator.graph is not reader.graph or locator.operation is not reader.operation or locator.work is not reader.work
            or reader.session_proof is not None or reader.request!=locator.request or reader.operation_id!=locator.prepared.selection_operation_id
            or reader.operation_kind!=_KIND or not locator.cause_complete or locator.match_commitment is None):
        raise AuthorityUnavailable('personal choice reader lost its exact private immutable prepared locator')
    return locator


def prepare_current_conditioned_personal_choice_v3(graph,bootstrap,bundle,*,c02_operation_id,source_ref,
        prepared_candidates_operation_id,plan_ref,goal_ref):
    from ..graph_worker import require_graph_storage_work_admission_v3,create_graph_storage_work_v3
    from ..runtime_storage_v3 import begin_runtime_storage_operation_v3,finish_runtime_storage_operation_v3,bind_runtime_storage_operation_v3
    from .current_conditioned_self_read_v3 import CONDITIONED_SELF_WORK_KIND_V3
    from .first_ingress_v2 import trusted_upper
    graph._admin(bootstrap);require_graph_storage_work_admission_v3(graph)
    assembly=graph._GraphCoordinator__d04_installed_joint_assembly
    if assembly is None or assembly.admin_bundle is not bundle:raise AuthorityUnavailable('personal choice requires actual installed assembly')
    prefix='artifact-task-candidates-prepare:'
    if type(prepared_candidates_operation_id)is not str or not prepared_candidates_operation_id.startswith(prefix):
        raise ValueError('personal choice requires its existing Artifact D08 preparation locator')
    marker=prepared_candidates_operation_id[len(prefix):]
    if len(marker)!=48 or any(c not in '0123456789abcdef'for c in marker):raise ValueError('personal choice preparation marker differs')
    namespace=bundle.installation_policy.namespace
    for ref,type_name in((source_ref,'memory.source'),(plan_ref,'d08.personal_plan.v1'),(goal_ref,'d08.goal.v1')):
        key=AtomKey.from_token(ref)
        if key.type_name!=type_name or NamespaceId.from_key(key)!=namespace:raise ValueError('personal choice locator family/namespace differs')
    now=trusted_upper(graph._GraphCoordinator__content_fence_v2.read_ingress_clock(graph._GraphCoordinator__scene_clock_policy))
    deadline=min(now+60.0,bundle.installation_policy.root_grant.valid_until_utc)
    if now>=deadline:raise AuthorityUnavailable('personal choice installed Root original deadline expired')
    operation_id='artifact-task-method-select:'+marker
    operation=begin_runtime_storage_operation_v3(graph._GraphCoordinator__store._db,operation_id,deadline)
    locator=None
    try:
        with bind_runtime_storage_operation_v3(operation,graph._GraphCoordinator__store._db),graph._GraphCoordinator__store._lock,runtime_storage_quantum_v3(graph._GraphCoordinator__store._db):
            locator=_PreparedChoiceLocatorV3(_ISSUER,graph,bootstrap,bundle,operation,c02_operation_id=c02_operation_id,
                source_ref=source_ref,preparation=prepared_candidates_operation_id,plan_ref=plan_ref,goal_ref=goal_ref)
        work=create_graph_storage_work_v3(graph,kind=CONDITIONED_SELF_WORK_KIND_V3,operation_id=operation_id,
            selection_digest=operation.selection_digest,deadline_utc=deadline,state=locator,operation=operation)
        work._require_invocation(graph,initial=True);locator.work=work
        work.phase='conditioned_personal_prepared_eof';return work
    except BaseException:
        if locator is not None:release_personal_choice_locator_v3(locator)
        finish_runtime_storage_operation_v3(operation);raise


def advance_personal_choice_locator_v3(graph,work):
    from ..graph_worker import GraphStorageStepV3
    from ..runtime_storage_v3 import bind_runtime_storage_operation_v3
    from .first_ingress_v2 import trusted_upper
    locator=require_personal_choice_locator_v3(work.state)
    if locator.graph is not graph:raise AuthorityUnavailable('personal choice advanced on another Graph')
    with bind_runtime_storage_operation_v3(work.operation,locator.db):
        if locator.phase=='producer':
            with locator.store._lock,runtime_storage_quantum_v3(locator.db)as meter:
                if not locator.producer_v3(meter):return GraphStorageStepV3('progress')
        now=trusted_upper(graph._GraphCoordinator__content_fence_v2.read_ingress_clock(graph._GraphCoordinator__scene_clock_policy))
        deadline=min(work.operation.deadline_utc,locator.cause_metadata.original_deadline_utc)
        if now>=deadline:raise AuthorityUnavailable('personal choice original preparation/Root deadline expired')
        work.operation.deadline_utc=work.deadline_utc=deadline
        locator.initial_monotonic_deadline=min(locator.initial_monotonic_deadline,time.monotonic()+deadline-now)
        if locator.fence is None:
            locator.authority=replace(locator.cause_metadata.authority,issuer_domain='d12',purpose='consolidation',
                capability_ref='conditioned-choice:'+locator.preparation_operation_id)
            locator.fence=graph._begin_read_fence_v3(locator.authority,operation_id=work.operation_id+':owner:'+locator.read_scope_nonce)
        graph._validate_read_fence_v3(locator.fence)
        from ..authority_service.owner_location_read_v3 import prepare_current_host_semantic_background_owner_read_entry_v3
        if locator.general_owner_entry is None:locator.general_owner_entry=prepare_current_host_semantic_background_owner_read_entry_v3(locator)
        locator.general_owner_entry.require_permission_v3(locator);locator.phase='metadata'
        with locator.store._lock,runtime_storage_quantum_v3(locator.db)as meter:
            locator.require_current_v3()
            if not _advance_choice_owner_metadata_v3(locator,meter):return GraphStorageStepV3('progress')
            locator.phase='matches'
            if not _advance_choice_match_census_v3(locator,meter):return GraphStorageStepV3('progress')
        now=trusted_upper(graph._GraphCoordinator__content_fence_v2.read_ingress_clock(graph._GraphCoordinator__scene_clock_policy))
        if now>=min(work.operation.deadline_utc,locator.draft_root_deadline):raise AuthorityUnavailable('personal choice expired after Owner-qualified metadata EOF')
        locator.general_owner_entry.require_permission_v3(locator)
        _handoff_personal_choice_v3(locator,now)
    return GraphStorageStepV3('progress')


def _handoff_personal_choice_v3(locator,now):
    from .conditioned_self_operations_v1 import SelectCurrentConditionedPersonalStepRequestV1
    from .current_method_learning_read_v3 import begin_current_method_learning_read_v3
    from .current_beta1_source_read_v3 import register_current_beta1_source_work_v3
    from . import current_conditioned_self_read_v3 as own
    locator.general_owner_entry.release_v3();locator.general_owner_entry=None
    deadline=min(locator.operation.deadline_utc,locator.draft_root_deadline)
    locator.operation.deadline_utc=locator.work.deadline_utc=deadline
    locator.initial_monotonic_deadline=min(locator.initial_monotonic_deadline,time.monotonic()+deadline-now)
    locator.cause_metadata=replace(locator.cause_metadata,original_deadline_utc=min(locator.cause_metadata.original_deadline_utc,locator.draft_root_deadline))
    locator.request=(locator.replay_request if locator.replay_selector is not None else
        SelectCurrentConditionedPersonalStepRequestV1(locator.plan_ref,locator.goal_ref,locator.preparation_operation_id,locator.match_refs))
    capsule=own._ConditionedPendingOwnerV3(own._ISSUER,locator,authority=locator.authority,fence=locator.fence,
        operation_kind=_KIND,request=locator.request)
    reader=begin_current_method_learning_read_v3(locator.graph,locator.operation,locator.fence,runtime=locator.runtime,
        authority=locator.authority,lease=None,operation_kind=_KIND,request=locator.request,operation_id=locator.operation_id,
        activity_id=locator.activity_id,audience_ref=locator.authority.audience[0],
        parent_budget_lease_ref=locator.prepared.parent_budget_lease_ref,
        request_digest=canonical_digest((_KIND,locator.request,locator.cause_metadata.original_digest)),
        owner_binding=None,owner_guard=None,session_proof=None,initial_now_utc=now,source_pending_owner=capsule)
    reader.work=locator.work;reader.conditioned_cause_locator=locator
    reader.initial_monotonic_deadline=locator.initial_monotonic_deadline
    reader.background_followup=reader.background_host_lifecycle=reader.background_offline=None
    own._SELF_VIEW_CLOCKS_V4[reader]=(now,time.monotonic())
    locator.work.state=reader;register_current_beta1_source_work_v3(reader,locator.work)
    own.bind_pending_conditioned_reader_v3(reader,capsule)
    state=own._STATES[reader];state.read_stage='metadata_owner'
    state.adoption_operations.add(locator.preparation_operation_id);state.required_domain_producers.add(locator.preparation_operation_id)
    state.source_roots.update(locator.prepared.source_refs)
    locator.phase='bound';locator.work.phase='conditioned_personal_owner_eof'


def release_personal_choice_locator_v3(locator):
    if not is_personal_choice_locator_v3(locator):return
    if locator.general_owner_entry is not None:locator.general_owner_entry.release_v3();locator.general_owner_entry=None
    _LOCATORS.pop(locator,None)
    from .current_conditioned_self_read_v3 import _CONDITIONED_LOCATOR_READERS_V3
    _CONDITIONED_LOCATOR_READERS_V3.pop(locator,None)
    locator.columns.clear()


def finish_personal_choice_locator_v3(graph,work,error):
    from ..runtime_storage_v3 import finish_runtime_storage_operation_v3
    locator=work.state
    try:
        if locator.fence is not None and not locator.read_finished:
            graph._finish_read_fence_v3(locator.fence);locator.read_finished=True
    finally:
        release_personal_choice_locator_v3(locator);finish_runtime_storage_operation_v3(work.operation)


_LIFE_KINDS=frozenset({'artifact_task_scope','draft_root_capability','artifact_task_text_extent',
    'artifact_phase_postcondition_policy','artifact_candidate_preparation_parent','artifact_task_objective',
    'c1_task_intent','artifact_standing_predecision_approval','artifact_task_continuation_authorization_v2',
    'activity_scope','c4_phase_verified','c4_phase_adopted','c4_phase_paid','c4_phase_result','c4_phase_prepared',
    'c4_verified','c4_adopted','c4_paid','c4_result','c4_prepared'})
_LIFE_FIELDS=frozenset({'schema','namespace','source_refs','source_ref','source_head','task_source_head','heads',
    'read_versions','query_coverage','root','task','selector','binding','request','root_registration_ref',
    'activity_scope_ref','activity_scope_digest','c1_intent_ref','c1_intent_digest','objective_ref','objective_digest',
    'approval_original_ref','approval_original_digest','continuation_authorization','extent_original_ref',
    'extent_original_digest','postcondition_policy_ref','postcondition_policy_digest','prev_phase_original_ref',
    'prev_phase_original_digest','prior_content','verified_original_ref','verified_original_digest',
    'prepared_original_ref','paid_original_ref','result_original_ref','operation_id','acquire_operation_id',
    'registration_operation_id','authorization_operation_id','task_producer_ref','c02_operation_id',
    'plan_head','goal_head','original_deadline_utc','deadline_utc','valid_until_utc','owner_guard','owner_grant_ref',
    'owner_grant_revision','owner_grant_digest','actor_ref','installation_id','manifest_digest','job_id','activity_id',
    'producer_operation_id','original_ref','original_digest','source_digest','source_revision','task_kind'})
_LIFE_LINKS={'c1_intent_ref':'c1_task_intent','objective_ref':'artifact_task_objective',
    'approval_original_ref':'artifact_standing_predecision_approval','extent_original_ref':'artifact_task_text_extent',
    'postcondition_policy_ref':'artifact_phase_postcondition_policy','activity_scope_ref':'activity_scope',
    'prev_phase_original_ref':'c4_phase_verified','verified_original_ref':'c4_phase_verified',
    'prepared_original_ref':'c4_phase_prepared','paid_original_ref':'c4_phase_paid','result_original_ref':'c4_phase_result'}


def _register_choice_signed_v3(locator,kind,ref,digest=None):
    if ref is None:return
    if kind not in _LIFE_KINDS or type(ref)is not str:raise AuthorityUnavailable('personal choice signed dependency escaped its closed actual family')
    old=locator.personal_signed.get(ref)
    if old is not None and(old[0]!=kind or old[1]is not None and digest is not None and old[1]!=digest):
        raise AuthorityUnavailable('personal choice signed dependency has conflicting original identities')
    locator.personal_signed[ref]=(kind,digest if digest is not None else old[1]if old is not None else None)


def _seed_choice_signed_v3(locator):
    if hasattr(locator,'signed_seeded'):return
    from ..domains.d08.personal_candidate_v1 import ArtifactPhaseCandidateBindingV2,ArtifactPhaseCandidateBindingV3
    from .ingress_artifact_task_scope_v1 import task_scope_ref_v1
    from .artifact_phase_postconditions_v1 import artifact_candidate_preparation_parent_ref_v1
    for row in locator.prepared.candidates:
        binding=row.binding
        _register_choice_signed_v3(locator,'artifact_task_scope',task_scope_ref_v1(binding.task.root_registration_ref))
        _register_choice_signed_v3(locator,'draft_root_capability',binding.task.root_registration_ref)
        if type(binding)in{ArtifactPhaseCandidateBindingV2,ArtifactPhaseCandidateBindingV3}:
            _register_choice_signed_v3(locator,'artifact_task_text_extent',binding.extent_original_ref,binding.extent_original_digest)
        if type(binding)is ArtifactPhaseCandidateBindingV3:
            _register_choice_signed_v3(locator,'artifact_phase_postcondition_policy',binding.postcondition_policy_ref,binding.postcondition_policy_digest)
        _register_choice_signed_v3(locator,'c4_phase_verified',binding.prev_phase_original_ref,binding.prev_phase_original_digest)
        if binding.prior_content is not None:
            _register_choice_signed_v3(locator,'c4_phase_verified',binding.prior_content.verified_original_ref)
    _register_choice_signed_v3(locator,'artifact_candidate_preparation_parent',
        artifact_candidate_preparation_parent_ref_v1(locator.task,locator.prepared.plan_head))
    locator.signed_seeded=True


def choice_signed_metadata_spec_v3(reader,identity):
    locator=personal_choice_locator_for_reader_v3(reader)
    if locator is None:return None
    if identity[0]=='personal_choice_policy':
        from .d02_artifact_phase_price_v1 import TABLE,SIGN_KIND
        ref,revision,digest=identity[1]
        if locator.personal_policies.get(ref)!=(revision,digest):raise AuthorityUnavailable('personal choice price policy was not selected from actual candidate evidence')
        return(TABLE,'payload_json',('bot','persona','policy_ref','revision'),(*reader.namespace.as_tuple,ref,revision),
            ('revision','kind','payload_digest','signature'),(),SIGN_KIND)
    if identity[0]!='personal_choice_life':return None
    kind,ref=identity[1]
    if locator.personal_signed.get(ref,(None,))[0]!=kind or kind not in _LIFE_KINDS:
        raise AuthorityUnavailable('personal choice Life metadata was not derived from actual authenticated candidate closure')
    return('graph_d11_life_originals_v1','payload_json',('bot','persona','kind','original_ref'),
        (*reader.namespace.as_tuple,kind,ref),('producing_operation_id','payload_digest','signature'),(),None)


def choice_metadata_retain_v3(task,path):
    locator=personal_choice_locator_for_reader_v3(task.reader)
    if locator is not None and task.identity==('producer',locator.operation_id):
        if not path:return True
        if path[0]=='request':return True
        if path[0]=='provenance'and(len(path)==1 or path[1]=='conditioned_child_execution_v1'):return True
        return None
    if task.identity[0]=='personal_choice_policy':
        if locator is None:raise AuthorityUnavailable('personal choice policy lacks its actual private Source reader')
        return True
    if task.identity[0]!='personal_choice_life':return None
    if locator is None:raise AuthorityUnavailable('personal choice metadata reader is not privately registered')
    if not path:return True
    kind,ref=task.identity[1]
    if kind in {'artifact_task_scope','draft_root_capability','artifact_task_text_extent','artifact_phase_postcondition_policy','artifact_candidate_preparation_parent','c4_phase_prepared','c4_prepared'}:
        from .artifact_recipe_metadata_v3 import ArtifactMetadataLocatorV3,artifact_recipe_metadata_retain_path_v3
        return artifact_recipe_metadata_retain_path_v3(ArtifactMetadataLocatorV3('life',kind,ref),path)
    if kind=='c1_task_intent':
        return path[0]in {'schema','namespace','c02_operation_id','source_ref','source_revision','source_digest',
            'installation_id','manifest_digest','c02_bundle_digest','c02_receipt_digest','c02_commit_seq'}
    if path[0]not in _LIFE_FIELDS:return False
    nested=_LIFE_FIELDS|{'bot_id','persona_id','key','revision','ref','digest','phase_index','phase_kind','method_ref','decision_ref','decision_revision','plan_ref','plan_revision','goal_ref','goal_revision','business_revision','condition_heads','condition_match_refs'}
    return all(type(part)is int or part in nested for part in path)


def finish_choice_signed_metadata_v3(task,value):
    from .current_conditioned_self_read_v3 import require_conditioned_self_work_v3,_source_tokens,_graph_tokens,_metadata_versions_v3
    from .d11_life_preparation_v1 import SIGN_KIND
    from .dispatch_current_inventory_v3 import _freeze_value_v3
    from .domain_production_contracts_v1 import ProductionOriginalRefV1
    reader=task.reader;locator=personal_choice_locator_for_reader_v3(reader)
    if task.identity[0]=='personal_choice_policy':return _finish_choice_policy_v3(task,value,locator)
    kind,ref=task.identity[1]
    if locator is None:raise AuthorityUnavailable('personal choice signed metadata lacks exact same-Work locator')
    state=require_conditioned_self_work_v3(reader);op,digest,signature=task.metadata
    expected=locator.personal_signed[ref][1]
    if task.column.canonical_digest!=digest or expected is not None and digest!=expected:
        raise AuthorityUnavailable('personal choice signed original full canonical EOF/digest differs')
    reader.graph._GraphCoordinator__d11_issuer._signer.verify(SIGN_KIND,canonical_serialize((reader.namespace,kind,ref,digest)),signature)
    if value.get('namespace')is not None and value['namespace']!={'bot_id':reader.namespace.bot_id,'persona_id':reader.namespace.persona_id}:
        raise AuthorityUnavailable('personal choice signed metadata namespace differs')
    state.signed_originals.add(('graph_d11_life_originals_v1',(*reader.namespace.as_tuple,kind,ref)))
    state.observed_originals[ref]=ProductionOriginalRefV1('d11.life_'+kind,ref,digest)
    if kind=='c1_task_intent':
        _bind_choice_c1_producer_v3(reader,locator,ref,value,op,state)
    else:
        state.adoption_operations.add(op);state.required_domain_producers.add(op)
    state.source_roots.update(_source_tokens(value));state.selected_keys.update(_graph_tokens(value))
    for version in _metadata_versions_v3(value):
        if NamespaceId.from_key(version.key)!=reader.namespace:raise AuthorityUnavailable('personal choice signed frozen version crossed namespace')
        if version.revision:state.allowed_history.add((version.key.token,version.revision))
    def links(raw):
        if type(raw)is dict:
            for name,target in _LIFE_LINKS.items():
                if name in raw and raw[name]is not None:
                    actual_kind='artifact_task_scope'if name=='activity_scope_ref'and raw[name].startswith('artifact-task-scope:')else target
                    _register_choice_signed_v3(locator,actual_kind,raw[name],raw.get(name.removesuffix('_ref')+'_digest'))
            if type(raw.get('continuation_authorization'))is dict:
                auth=raw['continuation_authorization'];_register_choice_signed_v3(locator,'artifact_task_continuation_authorization_v2',auth['original_ref'],auth.get('original_digest'))
            for child in raw.values():links(child)
        elif type(raw)in(tuple,list):
            for child in raw:links(child)
    links(value)
    return _freeze_value_v3({'kind':kind,'ref':ref,'digest':digest,'locator':value})


def seed_personal_choice_plan_v3(reader,types):
    from . import current_conditioned_self_read_v3 as own
    locator=personal_choice_locator_for_reader_v3(reader)
    if locator is None:return types
    state=own.require_conditioned_owner_ready_v3(reader);p=locator.prepared
    current_rows=tuple((token,*reader.heads[token])for token in sorted(reader.heads)if AtomKey.from_token(token).type_name==_MATCH)
    if current_rows!=tuple(locator.match_rows):raise AuthorityUnavailable('personal choice Match negative census changed between actual Owner and Self READ')
    for ref,(header,digest,_)in {**locator.match_metadata,**locator.question_metadata}.items():
        meta=own.conditioned_metadata_v3(reader.db,reader.namespace,('head',ref))
        task=state.tasks[('head',ref)]
        if meta is None or task.metadata!=header or task.column.canonical_digest!=digest:
            raise AuthorityUnavailable('personal choice current Match/Question EOF changed before Source request consumption')
    from .artifact_task_choice_lookup_v3 import seed_conditioned_task_choice_catalogue_v3
    seed_conditioned_task_choice_catalogue_v3(reader,locator,state)
    state.adoption_operations.add(reader.operation_id)
    selected=own.conditioned_metadata_v3(reader.db,reader.namespace,('producer',reader.operation_id))
    if locator.replay_selector is not None:
        if selected is None or selected['original_digest']!=locator.replay_original_digest or selected['operation_kind']!=_KIND:
            raise AuthorityUnavailable('personal choice replay producer metadata changed from actual Owner EOF')
        state.required_domain_producers.add(reader.operation_id)
    elif selected is not None:raise AuthorityUnavailable('personal choice selection appeared after original negative metadata census')
    state.adoption_operations.add(p.value_evaluation_operation_id);state.required_domain_producers.add(p.value_evaluation_operation_id)
    state.source_roots.update(p.source_refs)
    for key in locator.evidence_plan.exact_keys:state.selected_keys.add(key)
    for version in p.read_versions:
        if version.revision:state.allowed_history.add((version.key.token,version.revision))
    _seed_choice_signed_v3(locator)
    while True:
        before=tuple(sorted(locator.personal_signed))
        for ref in before:
            kind,_=locator.personal_signed[ref]
            value=own.conditioned_metadata_v3(reader.db,reader.namespace,('personal_choice_life',(kind,ref)))
            if value is None:
                if kind=='artifact_candidate_preparation_parent':continue
                raise AuthorityUnavailable('personal choice actual signed candidate dependency is absent')
        if tuple(sorted(locator.personal_signed))==before:break
    references=[p.need.original]
    for row in p.candidates:
        references.extend(row.eligibility.originals)
        if row.price is not None:references.append(row.price.original)
    with runtime_storage_quantum_v3(reader.db)as meter:
        for original in references:
            ref=original.original_ref
            if '-current:'in ref:
                domain,prefix=ref.split('-current:',1)
                row=meter.read_fixed_row(reader.db,'graph_domain_production_originals_v1',('operation_id','domain','original_digest'),
                    'bot=? AND persona=? AND original_digest=?',(*reader.namespace.as_tuple,original.original_digest))
                if row is None or row[1]!=domain or row[2][:48]!=prefix:
                    raise AuthorityUnavailable('personal choice candidate evidence has no exact actual Domain Original locator')
                state.adoption_operations.add(row[0]);state.required_domain_producers.add(row[0])
            elif original.kind=='d02.installed_policy':
                from .d02_artifact_phase_price_v1 import TABLE,POLICY_KIND
                header=meter.read_fixed_row(reader.db,TABLE,('revision','kind','payload_digest'),
                    'bot=? AND persona=? AND policy_ref=? ORDER BY revision DESC',(*reader.namespace.as_tuple,ref))
                if header is None or header[1:]!=(POLICY_KIND,original.original_digest):
                    raise AuthorityUnavailable('personal choice candidate price policy is no longer the actual latest signed original')
                locator.personal_policies[ref]=(header[0],header[2])
            elif original.kind.startswith('d11.life_'):
                _register_choice_signed_v3(locator,original.kind.removeprefix('d11.life_'),ref,original.original_digest)
            elif ref not in state.observed_originals:
                raise AuthorityUnavailable('personal choice evidence uses an unregistered actual Original family')
    for ref,(revision,digest)in tuple(locator.personal_policies.items()):
        own.conditioned_metadata_v3(reader.db,reader.namespace,('personal_choice_policy',(ref,revision,digest)))
    # The callback is retried only by MethodInputNeeded; all selected dependencies
    # receive their own bounded EOF tasks before any Source/body permission.
    for ref,(kind,_)in tuple(locator.personal_signed.items()):
        own.conditioned_metadata_v3(reader.db,reader.namespace,('personal_choice_life',(kind,ref)))
    return tuple(dict.fromkeys((*types,*locator.evidence_plan.fixed_type_ids,_MATCH,_QUESTION)))


def require_personal_choice_original_v3(reader,original,prepared):
    locator=personal_choice_locator_for_reader_v3(reader)
    if locator is None:return
    if(original['original_digest']!=locator.cause_metadata.original_digest or original['receipt']!=locator.receipt
            or prepared!=locator.prepared or reader.request.condition_match_refs!=locator.match_refs):
        raise AuthorityUnavailable('personal choice body differs from complete actual metadata/receipt/request commitment')


def _selected_path_v3(path):
    if not path:return True
    if path[0]in {'schema','namespace','identity','request','parent_budget','read_versions','coverage'}:return True
    return path[0]=='provenance'and(len(path)==1 or path[1]=='conditioned_child_execution_v1')


def _advance_choice_selected_metadata_v3(locator,meter):
    from .domain_production_originals_v1 import TABLE,_receipt
    from .natural_frozen_original_read_v3 import _CanonicalComparisonV3
    from ..authority_service.conditioned_child_contract_v1 import ConditionedChildSelectorV1,conditioned_child_from_wire_v1
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    from .conditioned_self_operations_v1 import SelectCurrentConditionedPersonalStepRequestV1
    from ..domains.d01.production_operations_v1 import plain_v1
    key=(*locator.namespace.as_tuple,locator.operation_id)
    payload=locator.column_v3('selected',TABLE,'original_payload_json',('bot','persona','operation_id'),key,_HEADER,_selected_path_v3,meter)
    if payload is None:return False
    if payload.header is None:
        return True
    if payload.header[:2]!=('d08',_KIND)or payload.digest!=payload.header[3]:
        raise AuthorityUnavailable('personal choice existing selection is not its actual complete conditioned original')
    raw=payload.result
    selector=conditioned_child_from_wire_v1(raw['provenance']['conditioned_child_execution_v1'],ConditionedChildSelectorV1)
    request=decode_typed_production_value_v1(raw['request'],SelectCurrentConditionedPersonalStepRequestV1)
    cause=locator.cause_metadata
    if(raw['namespace']!=plain_v1(locator.namespace)or raw['identity']['operation_id']!=locator.operation_id
            or raw['coverage']!='complete'or selector.phase!='personal_choice'or selector.namespace!=locator.namespace
            or selector.operation_id!=locator.operation_id or selector.activity_id!=locator.activity_id or selector.operation_kind!=_KIND
            or selector.typed_request_json!=canonical_serialize(raw['request'])or selector.typed_request_digest!=canonical_digest(request)
            or(request.plan_ref,request.goal_ref,request.prepared_candidates_operation_id)!=(locator.plan_ref,locator.goal_ref,locator.preparation_operation_id)
            or selector.producer_operation_id!=locator.preparation_operation_id or selector.producer_original_digest!=cause.original_digest
            or selector.producer_receipt_digest!=cause.receipt_digest or selector.parent_budget_lease_ref!=cause.parent_budget_lease_ref
            or selector.original_deadline_utc>cause.original_deadline_utc):
        raise AuthorityUnavailable('personal choice replay lost actual immutable prepared selector/Root/request identity')
    receipt=locator.column_v3('selected_receipt',TABLE,'receipt_json',('bot','persona','operation_id'),key,_HEADER,lambda path:True,meter)
    if receipt is None:return False
    if not hasattr(locator,'selected_receipt'):
        locator.selected_receipt=_receipt(receipt.result)
        locator.selected_receipt_hash=_CanonicalComparisonV3(locator.selected_receipt,operation=locator.operation)
    if not locator.selected_receipt_hash.complete and not locator.selected_receipt_hash.advance(meter):return False
    actual=locator.selected_receipt
    bundle=meter.read_fixed_row(locator.db,'graph_bundle_operations',('digest','activity_id','effect_id','commit_seq'),
        'bot=? AND persona=? AND operation_id=?',key)
    if(receipt.header!=payload.header or raw['schema']!='d08.current-'+_KIND+'.v1'
            or actual.status!='committed'or actual.operation_id!=locator.operation_id or actual.operation_digest!=payload.header[5]
            or locator.selected_receipt_hash.digest!=payload.header[4]or actual.commit_seq<1
            or bundle!=(actual.operation_digest,actual.activity_id,actual.effect_id,actual.commit_seq)):
        raise AuthorityUnavailable('personal choice replay lacks actual same original W01 receipt/bundle')
    decision=_choice_head_v3(locator,locator.prepared.future_decision_ref,meter)
    if decision is None:return False
    if decision.header is None or decision.header[1]!=1:
        raise AuthorityUnavailable('personal choice completed original has no current valid Decision')
    version=GraphVersion(AtomKey.from_token(locator.prepared.future_decision_ref),decision.header[0])
    history=meter.read_fixed_row(locator.db,'graph_history',('event_bot','event_persona','event_id','valid','value_cell_id'),
        'token=? AND revision=?',(version.key.token,version.revision))
    if(version not in actual.write_versions or history!=(*locator.namespace.as_tuple,locator.operation_id,1,decision.header[2])
            or tuple(selector.allowed_write_keys)!=(version.key,)):
        raise AuthorityUnavailable('personal choice replay Decision is not its actual sole W01 write/history')
    locator.replay_selector=selector;locator.replay_request=request
    locator.replay_original_digest=payload.digest;locator.replay_receipt_digest=payload.header[4]
    return True


def personal_choice_selected_replay_v3(reader):
    """Exact installed Source-qualified replay gate; caller keeps all D08 current checks."""
    from . import current_conditioned_self_read_v3 as own
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    from ..authority_service.conditioned_child_contract_v1 import ConditionedChildSelectorV1,conditioned_child_from_wire_v1
    from ..domains.d01.production_operations_v1 import plain_v1
    locator=personal_choice_locator_for_reader_v3(reader)
    if locator is None or locator.replay_selector is None:return False
    own.require_conditioned_owner_ready_v3(reader);own.require_conditioned_sources_v3(reader,reader.selected_plan.source_roots)
    original=read_adopted_domain_operation_v1(reader.db,reader.namespace,reader.operation_id)
    if(original is None or original['domain']!='d08'or original['operation_kind']!=_KIND
            or original['original_digest']!=locator.replay_original_digest
            or original['receipt']!=locator.selected_receipt
            or original['payload']['request']!=plain_v1(reader.request)
            or conditioned_child_from_wire_v1(original['payload']['provenance']['conditioned_child_execution_v1'],ConditionedChildSelectorV1)!=locator.replay_selector):
        raise AuthorityUnavailable('personal choice Source-qualified replay original/receipt/selector differs')
    from .domain_production_contracts_v1 import CurrentOperationFrameV1
    from .d01_production_operations_v1 import CurrentDomainReadV1
    read=CurrentDomainReadV1(CurrentOperationFrameV1(*reader.frame_fields))
    atom=read.head(reader.db,locator.prepared.future_decision_ref,required=True)
    meta=own.conditioned_metadata_v3(reader.db,reader.namespace,('history',(atom.key.token,atom.revision)))
    task=own.require_conditioned_self_work_v3(reader).tasks[('history',(atom.key.token,atom.revision))]
    if meta is None or task.metadata[2]!=reader.operation_id or GraphVersion(atom.key,atom.revision)not in original['receipt'].write_versions:
        raise AuthorityUnavailable('personal choice replay changed current actual Decision adoption')
    return True


def restore_personal_choice_selector_v3(reader):
    from . import current_conditioned_self_read_v3 as own
    locator=personal_choice_locator_for_reader_v3(reader)
    if locator is None or locator.replay_selector is None:return False
    if not personal_choice_selected_replay_v3(reader):raise AuthorityUnavailable('personal choice replay lost actual completed original')
    own.conditioned_current_root_locator_v3(reader)
    own.bind_current_conditioned_child_selector_v3(reader,locator.replay_selector)
    own.prepare_current_conditioned_attempt_metadata_v3(reader)
    return True


def _finish_choice_policy_v3(task,value,locator):
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    from .d02_artifact_phase_price_v1 import ArtifactPhasePricePolicyV1,POLICY_KIND,TABLE
    from .domain_production_contracts_v1 import ProductionOriginalRefV1,ProductionPolicyRefV1
    from .dispatch_current_inventory_v3 import _freeze_value_v3
    from . import current_conditioned_self_read_v3 as own
    if locator is None:raise AuthorityUnavailable('personal choice policy lacks its actual private reader')
    reader=task.reader;ref,revision,digest=task.identity[1]
    policy=decode_typed_production_value_v1(value,ArtifactPhasePricePolicyV1)
    owner=reader.material_owner_guard;installation=locator.bundle.installation_policy
    if(task.metadata[:3]!=(revision,POLICY_KIND,digest)or task.column.canonical_digest!=digest
            or task.column.signature_verified is not True or policy.namespace!=reader.namespace
            or(policy.policy_ref,policy.revision,policy.installation_id,policy.manifest_digest,policy.profile_id)!=
                (ref,revision,installation.installation_id,installation.manifest_digest,locator.bundle.tls_profile.profile_id)
            or(policy.owner_grant_ref,policy.owner_grant_revision,policy.owner_grant_digest)!=
                (owner.grant_ref,owner.grant_revision,owner.grant_digest)):
        raise AuthorityUnavailable('personal choice actual signed price policy changed installed namespace/Owner/manifest')
    with runtime_storage_quantum_v3(reader.db)as meter:
        latest=meter.read_fixed_row(reader.db,TABLE,('revision','kind','payload_digest','signature'),
            'bot=? AND persona=? AND policy_ref=? ORDER BY revision DESC',(*reader.namespace.as_tuple,ref))
    if latest!=task.metadata:raise AuthorityUnavailable('personal choice actual signed price policy was superseded')
    state=own.require_conditioned_owner_ready_v3(reader)
    state.signed_originals.add((TABLE,(*reader.namespace.as_tuple,ref,revision)))
    state.observed_originals[ref]=ProductionOriginalRefV1('d02.installed_policy',ref,digest)
    state.adoption_operations.add(policy.producing_operation_id);state.required_domain_producers.add(policy.producing_operation_id)
    pins={pin.policy_ref:pin for pin in reader.installed_policy_refs};pin=ProductionPolicyRefV1(ref,revision,digest)
    if ref in pins and pins[ref]!=pin:raise AuthorityUnavailable('personal choice installed policy pin changed')
    pins[ref]=pin;reader.installed_policy_refs=tuple(pins[name]for name in sorted(pins))
    return _freeze_value_v3(value)


def advance_personal_choice_source_v3(graph,work):
    """Exact prepared-choice adapter; no generic plan may replace its sealed stock."""
    from dataclasses import fields
    from . import current_conditioned_self_read_v3 as own
    from .current_method_learning_read_v3 import (_READING,MethodInputNeededV3,bind_prepared_method_learning_read_v3,
        _MethodPointReadV3,_MethodInventoryReadV3,_MethodBudgetGrantReadV3,_ISSUER,PreparedMethodDomainInputsV3)
    from .current_beta1_source_read_v3 import create_current_beta1_source_metadata_task_v3
    from .domain_production_contracts_v1 import CurrentOperationFrameV1
    from ..graph_worker import GraphStorageStepV3
    reader=work.state
    if personal_choice_locator_for_reader_v3(reader)is None:raise AuthorityUnavailable('personal choice Source adapter requires exact private prepared provenance')
    if reader.inputs_sealed:
        graph._finish_read_fence_v3(reader.fence);reader.read_finished=True;work.phase='conditioned_personal_core_write'
        return GraphStorageStepV3('progress')
    if not reader.inventory_sealed:
        with reader.store._lock:reader.advance()
        return GraphStorageStepV3('progress')
    if reader.pending_input is not None:
        with reader.store._lock,runtime_storage_quantum_v3(reader.db)as meter:
            reader.require_current(meter=meter);reader.pending_input.advance(meter)
            if reader.pending_input.complete:reader.pending_input=None
        return GraphStorageStepV3('progress')
    token=_READING.set(reader)
    try:
        with bind_prepared_method_learning_read_v3(reader.inventory,graph,reader.db),reader.store._lock:
            reader.db.execute('BEGIN')
            try:
                if reader.selected_envelope is None:reader.selected_envelope=own._self_view_envelope_v4(reader)
                if reader.installed_readers is None:
                    reader.installed_readers=own.install_conditioned_self_readers_v1(graph,scope=reader.fence.scope,
                        owner_guard=reader.owner_guard,operation_kind=reader.operation_kind,owner_binding=reader.owner_binding)
                plan=own.read_plan_current_conditioned_self_v1(reader.db,reader.namespace,reader.activity_id,
                    reader.operation_kind,reader.request,reader.installed_readers)
                reader.selected_plan=plan;own.require_conditioned_sources_v3(reader,plan.source_roots)
                prepare_personal_choice_c1_body_v3(reader)
                frame=own.freeze_current_conditioned_source_read_frame_v3(reader,plan)
                reader.frame_fields=tuple(getattr(frame,item.name)for item in fields(CurrentOperationFrameV1))
                if own.augment_current_conditioned_output_plan_v3(reader):return GraphStorageStepV3('progress')
                own.finalize_current_conditioned_source_inputs_v3(reader)
                reader.inputs_sealed=reader.complete=True
                reader.result=PreparedMethodDomainInputsV3(_ISSUER,reader,reader.selected_plan,reader.selected_envelope)
                work.phase='conditioned_personal_inputs_sealed'
            finally:reader.db.rollback()
        own._self_view_now_v4(reader);graph._validate_read_fence_v3(reader.fence)
        return GraphStorageStepV3('progress')
    except MethodInputNeededV3 as needed:
        kind,actual=needed.request
        with reader.store._lock,runtime_storage_quantum_v3(reader.db):
            if kind=='conditioned_owner_metadata':task=own.create_current_conditioned_metadata_task_v3(reader,actual)
            elif kind=='beta1_source_metadata':task=create_current_beta1_source_metadata_task_v3(reader,actual)
            elif kind=='task_choice_catalogue':
                from .artifact_task_choice_lookup_v3 import start_task_choice_catalogue_v3
                task=start_task_choice_catalogue_v3(reader,actual)
            elif kind=='point':
                own.require_conditioned_point_v3(reader,actual)
                task=reader.points.get(actual)
                if task is None:task=_MethodPointReadV3(reader,actual);reader.points[actual]=task
            elif kind=='inventory':
                if reader.selected_plan is None or actual not in reader.selected_plan.fixed_type_ids:
                    raise AuthorityUnavailable('personal choice body inventory escaped actual complete Source plan')
                task=reader.inventories.get(actual)
                if task is None:task=_MethodInventoryReadV3(reader,actual);reader.inventories[actual]=task
            elif kind=='budget_grant':
                if actual!=reader.parent_budget_lease_ref:raise AuthorityUnavailable('personal choice budget metadata crossed original parent')
                if reader.budget_task is None:reader.budget_task=_MethodBudgetGrantReadV3(reader,actual)
                task=reader.budget_task
            else:raise AuthorityUnavailable('personal choice requested an unregistered actual Source dependency')
            reader.pending_input=task
        return GraphStorageStepV3('progress')
    finally:_READING.reset(token)


def _advance_choice_c02_receipt_v3(locator,bundle,original,meter):
    """Rebuild the actual C02 receipt from its bundle/event metadata EOF.

    C02 is a direct W01 producer, not a domain_production original. The typed
    shape is the same as reconstruct_graph_bundle_commit_receipt_v1; its JSON
    columns are supplied here only after their exact physical EOF.
    """
    from ..runtime_contracts import CommitReceipt
    from ..graph_types import NamespaceEpoch
    from .domain_production_originals_v1 import _receipt,_receipt_wire
    from .natural_frozen_original_read_v3 import _CanonicalComparisonV3
    raw=original.result
    if original.header!=bundle or raw.get('commit_seq')!=bundle[3]:
        raise AuthorityUnavailable('personal choice actual C02 receipt sequence/header differs')
    key=(*locator.namespace.as_tuple,bundle[1],locator.c02_operation_id)
    columns=[]
    for name in ('reads','revisions'):
        column=locator.column_v3(('c02_event',name),'graph_events',name,('bot','persona','session','event_id'),
            key,('epoch_revision',),lambda path:True,meter)
        if column is None:return False
        if column.header is None:raise AuthorityUnavailable('personal choice C02 has no actual adopted Graph event metadata')
        columns.append(column)
    if columns[0].header!=columns[1].header:raise AuthorityUnavailable('personal choice C02 event epoch changed between metadata columns')
    if not hasattr(locator,'c02_receipt'):
        versions=[]
        for column in columns:
            rows=column.result
            if type(rows)is not list or len(rows)>1024:
                raise AuthorityUnavailable('personal choice C02 event read/write rows exceed the original bounded contract')
            values=tuple(GraphVersion(AtomKey.from_token(token),revision)for token,revision in rows)
            if len({v.key for v in values})!=len(values)or any(NamespaceId.from_key(v.key)!=locator.namespace for v in values):
                raise AuthorityUnavailable('personal choice C02 event metadata repeats/crosses namespace')
            versions.append(values)
        receipt=CommitReceipt('committed',locator.c02_operation_id,bundle[0],bundle[1],bundle[2],bundle[3],
            versions[0],versions[1],(NamespaceEpoch(*locator.namespace.as_tuple,columns[0].header[0]),),
            tuple(raw['ledger_refs']),tuple(raw['outbox_refs']))
        locator.c02_receipt=_receipt(_receipt_wire(receipt))
        locator.c02_receipt_hash=_CanonicalComparisonV3(locator.c02_receipt,operation=locator.operation)
    if not locator.c02_receipt_hash.complete and not locator.c02_receipt_hash.advance(meter):return False
    return True


def _bind_choice_c1_producer_v3(reader,locator,ref,value,operation_id,state):
    from .c1_artifact_task_intent_v1 import c1_task_intent_ref_v1
    from ..domains.d01.production_operations_v1 import plain_v1
    receipt=locator.c02_receipt
    scope=locator.columns['task_scope'].result
    source=GraphVersion(AtomKey.from_token(value['source_ref']),value['source_revision'])
    if(value.get('schema')!='d11.c1-artifact-task-intent-original.v1'
            or value.get('namespace')!=plain_v1(reader.namespace)
            or operation_id!=locator.c02_operation_id or value['c02_operation_id']!=operation_id
            or ref!=c1_task_intent_ref_v1(reader.namespace,operation_id)
            or value['source_ref']!=scope['source_ref']or value['source_ref']!=locator.source_ref
            or value['installation_id']!=locator.bundle.installation_policy.installation_id
            or value['manifest_digest']!=locator.bundle.installation_policy.manifest_digest
            or(value['c02_bundle_digest'],value['c02_receipt_digest'],value['c02_commit_seq'])!=
                (receipt.operation_digest,locator.c02_receipt_hash.digest,receipt.commit_seq)
            or source not in (*receipt.read_versions,*receipt.write_versions)):
        raise AuthorityUnavailable('personal choice signed C1 is not its actual direct C02 Source/bundle/receipt original')
    state.source_roots.add(source.key.token)
    for version in (*receipt.read_versions,*receipt.write_versions):
        state.selected_keys.add(version.key)
        if version.revision:state.allowed_history.add((version.key.token,version.revision))
    # C02 has no Domain Original. The ordinary bounded plan loop consumes
    # these historical locators after this signature task completes.


_C1_BODY_COLUMNS=('producing_operation_id','payload_json','payload_digest','signature')
_ENCODING_BINDING_COLUMNS=('source_id','source_revision','access_revision','budget_lease_id',
    'budget_reservation_operation_id','binding_digest','model_request_digest','call_id','request_json')


def prepare_personal_choice_c1_body_v3(reader):
    """Bind only the request in the actual signed C1 body's protected EOF.

    This runs after current all-parent Source qualification. Neither an external
    request DTO nor a metadata projection can issue the body-point membership.
    """
    from . import current_conditioned_self_read_v3 as own
    from .c1_artifact_task_intent_v1 import c1_task_intent_ref_v1
    from .current_method_learning_read_v3 import read_bound_method_learning_attachment_v3,_MethodPointReadV3,MethodJSONColumnV3
    from ..authority_service.v2_worker_model_result_contract import from_wire,WorkerModelResultReadV1
    from .domain_production_contracts_v1 import ProductionOriginalRefV1
    from .natural_frozen_original_read_v3 import _canonical_container_bytes_v3
    import json
    locator=personal_choice_locator_for_reader_v3(reader)
    if locator is None:raise AuthorityUnavailable('personal choice C1 body requires the actual private preparation locator')
    own.require_conditioned_sources_v3(reader,reader.selected_plan.source_roots)
    ref=c1_task_intent_ref_v1(reader.namespace,locator.c02_operation_id)
    state=own.require_conditioned_owner_ready_v3(reader)
    original=state.observed_originals.get(ref)
    if type(original)is not ProductionOriginalRefV1 or original.kind!='d11.life_c1_task_intent':
        raise AuthorityUnavailable('personal choice C1 body was not selected by actual signed metadata EOF')
    request=('graph_d11_life_originals_v1',_C1_BODY_COLUMNS,('bot','persona','kind','original_ref'),
        (*reader.namespace.as_tuple,'c1_task_intent',ref))
    handled,row=read_bound_method_learning_attachment_v3(reader.db,table=request[0],columns=request[1],key_columns=request[2],key=request[3])
    point=reader.points.get(request)
    if(not handled or row is None or type(point)is not _MethodPointReadV3 or point.owner is not reader
            or point.request!=request or not point.complete or row[0]!=locator.c02_operation_id or row[2]!=original.original_digest):
        raise AuthorityUnavailable('personal choice C1 body lacks its actual same-Work protected point EOF')
    column=point.values.get('payload_json')
    if type(column)is not MethodJSONColumnV3 or not column.complete or column.sha256!=original.original_digest:
        raise AuthorityUnavailable('personal choice protected C1 full-body SHA differs from its signed original')
    column._actual()
    saved=_C1_BODIES.get(reader)
    if saved is not None:
        if saved[:5]!=(locator,own._identity(reader),point,column,original):raise AuthorityUnavailable('personal choice C1 body binding changed')
        return saved
    raw=column.json_v3()
    signer=reader.graph._GraphCoordinator__d11_issuer._signer
    from .d11_life_preparation_v1 import SIGN_KIND
    signer.verify(SIGN_KIND,canonical_serialize((reader.namespace,'c1_task_intent',ref,original.original_digest)),row[3])
    from ..domains.d01.production_operations_v1 import plain_v1
    if(raw['namespace']!=plain_v1(reader.namespace)or raw['c02_operation_id']!=locator.c02_operation_id
            or raw['source_ref']!=locator.source_ref or raw['installation_id']!=locator.bundle.installation_policy.installation_id
            or raw['manifest_digest']!=locator.bundle.installation_policy.manifest_digest):
        raise AuthorityUnavailable('personal choice C1 protected body changed Source/C02/installation metadata')
    wire=json.loads(raw['worker_read_json']);reader.operation.retain(_canonical_container_bytes_v3(wire)*2+131072)
    read=from_wire(wire,WorkerModelResultReadV1);actual=read.request
    if(actual.namespace!=reader.namespace or actual.consumer_operation_id!=locator.c02_operation_id
            or actual.installation_id!=locator.bundle.installation_policy.installation_id or actual.purpose!='first_ingress_c02'):
        raise AuthorityUnavailable('personal choice actual C1 result request belongs to another consumer/namespace')
    source=GraphVersion(AtomKey.from_token(raw['source_ref']),raw['source_revision'])
    saved=(locator,own._identity(reader),point,column,original,actual,source)
    _C1_BODIES[reader]=saved
    return saved


def _personal_choice_c1_requests_v3(reader):
    from . import current_conditioned_self_read_v3 as own
    locator=personal_choice_locator_for_reader_v3(reader)
    saved=_C1_BODIES.get(reader)
    if locator is None or saved is None:return None
    if saved[0]is not locator or saved[1]!=own._identity(reader):raise AuthorityUnavailable('personal choice C1 points left their actual Source Work')
    state=own.require_conditioned_owner_ready_v3(reader)
    if state.source_permission is None:raise AuthorityUnavailable('personal choice C1 body points require full current Source qualification')
    state.source_permission.require_for_v3(reader)
    _,_,point,column,original,actual,source=saved
    column._actual()
    if(not point.complete or column.sha256!=original.original_digest or point.values.get('payload_json')is not column
            or actual.namespace!=reader.namespace or actual.consumer_operation_id!=locator.c02_operation_id):
        raise AuthorityUnavailable('personal choice C1 point origin no longer matches its protected actual EOF')
    c02=('graph_first_ingress_c02_committed_seals_v2',('evidence_json','bundle_digest'),
        ('bot','persona','operation_id'),(*reader.namespace.as_tuple,locator.c02_operation_id))
    binding=('runtime_encoding_call_bindings_v1',_ENCODING_BINDING_COLUMNS,
        ('bot','persona','job_id'),(*reader.namespace.as_tuple,actual.job_id))
    return saved,(c02,binding)


def require_personal_choice_c1_point_v3(reader,request):
    if request[0]not in {'graph_first_ingress_c02_committed_seals_v2','runtime_encoding_call_bindings_v1'}:return False
    current=_personal_choice_c1_requests_v3(reader)
    if current is None:return False
    saved,allowed=current
    if request not in allowed:return False
    locator,_,_,_,_,actual,source=saved
    point=reader.points.get(request)
    if point is not None and point.complete:
        with runtime_storage_quantum_v3(reader.db)as meter:row=point.require_row_v3(meter)
        if row is None:raise AuthorityUnavailable('personal choice actual C1/C02 body dependency disappeared')
        if request==allowed[0]:
            if row[1]!=locator.c02_receipt.operation_digest:raise AuthorityUnavailable('personal choice C02 evidence points at another committed bundle')
        else:
            from ..memory_types import source_key
            if(source_key(*reader.namespace.as_tuple,row[0])!=source.key or row[1]!=source.revision
                    or(row[4],row[5],row[6],row[7])!=(actual.original_operation_id,actual.binding_digest,actual.model_request_digest,actual.call_id)
                    or point.values['request_json'].sha256!=actual.binding_digest):
                raise AuthorityUnavailable('personal choice encoding binding changed actual Source/budget/call/request identity')
    return True


def require_personal_choice_c1_body_v3(reader,table,key):
    if table not in {'graph_first_ingress_c02_committed_seals_v2','runtime_encoding_call_bindings_v1'}:return False
    current=_personal_choice_c1_requests_v3(reader)
    if current is None:return False
    _,allowed=current
    for request in allowed:
        if table==request[0]and tuple(key)==request[3]:
            point=reader.points.get(request)
            if point is None or point.owner is not reader or point.request!=request:
                raise AuthorityUnavailable('personal choice C1 body has no actual exact-shape point task')
            return require_personal_choice_c1_point_v3(reader,request)
    return False


def release_personal_choice_reader_v3(reader):
    _C1_BODIES.pop(reader,None)
