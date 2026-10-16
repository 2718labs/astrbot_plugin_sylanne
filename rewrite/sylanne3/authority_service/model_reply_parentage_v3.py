"""Private, same-observation parentage originals; no prepared-body capability."""
from dataclasses import dataclass, fields
from weakref import WeakKeyDictionary
import json

from .contract import AuthorityUnavailable
from ..runtime_contracts import NamespaceId, canonical_serialize
from ..graph_types import AtomKey, Owner, GraphVersion
from ..runtime.c09_canonical_json_stream_v2 import C09CanonicalJSONStreamV2

_PROOFS=WeakKeyDictionary()
_DESCRIPTORS=WeakKeyDictionary()

def _active(db):
    from .model_reply_scope_observation_v3 import _active_observation_v3
    owner=_active_observation_v3(db)
    if owner is None or owner.legacy:
        raise AuthorityUnavailable('actual selected parentage observation required')
    return owner

def _point(db,table,columns,key_columns,key):
    from .model_reply_scope_observation_v3 import model_reply_scope_point_v3
    return model_reply_scope_point_v3(db,table=table,columns=columns,key_columns=key_columns,key=key,
        legacy_reader=lambda:None)

def _digest(value):
    if type(value)is not str or len(value)!=64 or any(c not in '0123456789abcdef'for c in value):
        raise ValueError('parentage original commitment differs')
    return value

def _head(raw):
    return GraphVersion(AtomKey(Owner(**raw['key']['owner']),raw['key']['type_name'],raw['key']['name']),raw['revision'])

@dataclass(frozen=True,slots=True,eq=False,weakref_slot=True)
class _D07ParentageEOFV3:
    schema:str
    namespace:NamespaceId
    c02_operation_id:str|None
    digest:str

def require_d07_parentage_v3(db,*,intent,issuer):
    owner=_active(db)
    row=_point(db,'graph_d07_execution_originals_v1',('payload_json','payload_digest','signature'),
        ('bot','persona','kind','original_ref'),(*owner.namespace.as_tuple,'prepared',intent.job_id))
    if row is None:
        return None
    column=row[0]
    if not column.complete or column.sha256!=row[1]:
        raise AuthorityUnavailable('D07 parentage original raw canonical EOF differs')
    issuer._signer.verify('d07.execution-original.v1',
        canonical_serialize((owner.namespace,'prepared',intent.job_id,row[1])),row[2])
    from ..runtime.domain_background_read_v3 import background_json_loads_v3
    raw=background_json_loads_v3(column)
    from ..runtime.d07_execution_v1 import D07PreparedExecutionV1,D07RelationshipPreparedV2,D07IngressRecallPreparedV1,D07ReflectionPreparedV3
    from ..runtime.d07_method_growth_semantic_v2 import D07MethodGrowthPreparedV2,PREPARED_SCHEMA,_head as growth_head,_deadline
    variants={'d07.prepared-execution.v1':D07PreparedExecutionV1,
        'd07.relationship-prepared.v2':D07RelationshipPreparedV2,
        'd07.ingress-recall-prepared.v1':D07IngressRecallPreparedV1,
        'd07.reflection-prepared.v3':D07ReflectionPreparedV3,PREPARED_SCHEMA:D07MethodGrowthPreparedV2}
    variant=variants.get(raw.get('schema'))
    if variant is None or set(owner.column_kinds[column])!={field.name for field in fields(variant)}:
        raise AuthorityUnavailable('D07 parentage original closed field set differs')
    if NamespaceId(**raw['namespace'])!=owner.namespace or raw['job_id']!=intent.job_id:
        raise AuthorityUnavailable('D07 parentage crossed its actual namespace/job')
    if variant is D07ReflectionPreparedV3 and raw["cycle_ref"] is None and any(
            raw[name] is not None for name in ("cycle_digest","call_plan_digest","c02_operation_id","cancel_generation")):
        raise AuthorityUnavailable("ordinary reflection cannot carry partial Self parentage")
    if variant is D07PreparedExecutionV1 or (variant is D07ReflectionPreparedV3 and raw["cycle_ref"] is None):
        proof=_D07ParentageEOFV3(raw['schema'],owner.namespace,None,row[1])
        _PROOFS[proof]=(owner,column,raw,issuer,None)
        return proof
    if raw['call_id']!=intent.call_id or row[1]!=intent.binding_digest:
        raise AuthorityUnavailable('model barrier signed C3 call/binding identity differs')
    if variant is D07ReflectionPreparedV3:
        from ..runtime.foreground_call_plan_v1 import NamedC3ParentageDescriptorV3
        if raw["work_kind"]!="reflection":
            raise ValueError("reflection parentage changed its exact work kind")
        def canonical_head(value):
            if type(value) is not dict or set(value)!={"key","revision"} or type(value["key"]) is not str:
                raise ValueError("reflection v3 retains its distinct canonical GraphVersion wire")
            return GraphVersion(AtomKey.from_token(value["key"]),value["revision"])
        names=("reflection_request_ref","reflection_request_digest","reflection_continuation_ref",
            "reflection_continuation_digest","parent_prepared_ref","parent_prepared_digest",
            "parent_execution_ref","parent_execution_digest","checkpoint_digest","parent_grant_digest")
        descriptor=NamedC3ParentageDescriptorV3(namespace=owner.namespace,kind="reflection",
            operation_id=raw["operation_id"],job_id=raw["job_id"],call_id=raw["call_id"],
            semantic_question_ref=None,semantic_question_digest=None,cycle_ref=canonical_head(raw["cycle_ref"]),
            cycle_digest=raw["cycle_digest"],call_plan_digest=raw["call_plan_digest"],
            c02_operation_id=raw["c02_operation_id"],cancel_generation=raw["cancel_generation"],prepared_digest=row[1],
            parent_budget_lease_ref=raw["parent_budget_lease_ref"],original_deadline_utc=raw["original_deadline_utc"],
            checkpoint_ref=canonical_head(raw["checkpoint_ref"]),**{name:raw[name] for name in names})
    elif variant is D07IngressRecallPreparedV1:
        if(raw['work_kind']!='recall_need' or type(raw['cancel_generation'])is not int
                or raw['cancel_generation']<0 or raw['adoption_operation_id']==raw['operation_id']):
            raise ValueError('exact Self recall preparation/adoption identities required')
        cycle=AtomKey.from_token(raw['cycle_job_ref'])
        if cycle.type_name!='runtime.job' or NamespaceId.from_key(cycle)!=owner.namespace:
            raise ValueError('Self recall preparation crosses its parent cycle')
        for name in('need_ref','c02_operation_id','responsibility_ref','adoption_operation_id'):
            if type(raw[name])is not str or not raw[name]:
                raise ValueError('Self recall preparation lost its actual parent original')
        for name in('need_digest','responsibility_digest','recall_policy_digest'):
            _digest(raw[name])
        for name in('self_authority_json','owner_guard_json'):
            value=raw[name]
            if type(value)is not str or canonical_serialize(json.loads(value))!=value:
                raise ValueError('Self and upstream Owner provenance must remain exact and separate')
        descriptor=None
    else:
        from ..runtime.foreground_call_plan_v1 import NamedC3ParentageDescriptorV3
        growth=variant is D07MethodGrowthPreparedV2
        from ..runtime.d07_execution_v1 import decode_native_named_d07_head_v2
        cycle_head=decode_native_named_d07_head_v2(raw["cycle_ref"],namespace=owner.namespace,
            c02_operation_id=raw["c02_operation_id"],head_kind="cycle_ref")
        if raw['work_kind']!='concern':
            raise ValueError('named C3 changed its actual concern work kind')
        extras={}
        if growth:
            from ..domains.d01.method_learning_v1 import TRIAL_PROPOSAL_TYPE_V2
            proposal=decode_native_named_d07_head_v2(raw['proposal_head'],namespace=owner.namespace,
                c02_operation_id=raw['c02_operation_id'],head_kind='proposal_head')
            source=decode_native_named_d07_head_v2(raw['source_head'],namespace=owner.namespace,
                c02_operation_id=raw['c02_operation_id'],head_kind='source_head')
            growth_head(proposal,TRIAL_PROPOSAL_TYPE_V2,owner.namespace)
            growth_head(source,'memory.source',owner.namespace)
            _deadline(raw['original_deadline_utc'])
            extras={'proposal_head':proposal,'proposal_digest':raw['proposal_digest'],'source_head':source,
                'source_digest':raw['source_digest'],'parent_budget_lease_ref':raw['parent_budget_lease_ref'],
                'original_deadline_utc':raw['original_deadline_utc']}
        descriptor=NamedC3ParentageDescriptorV3(namespace=owner.namespace,kind='growth'if growth else'relationship',
            operation_id=raw['operation_id'],job_id=raw['job_id'],call_id=raw['call_id'],
            semantic_question_ref=raw['semantic_question_ref'],semantic_question_digest=raw['semantic_question_digest'],
            cycle_ref=cycle_head,cycle_digest=raw['cycle_digest'],call_plan_digest=raw['call_plan_digest'],
            c02_operation_id=raw['c02_operation_id'],cancel_generation=raw['cancel_generation'],
            prepared_digest=row[1],**extras)
    proof=_D07ParentageEOFV3(raw['schema'],owner.namespace,raw['c02_operation_id'],row[1])
    _PROOFS[proof]=(owner,column,raw,issuer,descriptor)
    if descriptor is not None:
        _DESCRIPTORS[descriptor]=proof
    return proof

def require_d07_descriptor_v3(proof,*,db,namespace,issuer):
    record=_PROOFS.get(proof)
    if type(proof)is not _D07ParentageEOFV3 or record is None:
        raise AuthorityUnavailable('actual issued D07 parentage EOF proof required')
    owner,column,raw,actual_issuer,descriptor=record
    owner.require_actual_v3();column._actual_v3()
    if(owner is not _active(db) or namespace!=owner.namespace or issuer is not actual_issuer
            or not column.complete or column.sha256!=proof.digest or descriptor is None):
        raise AuthorityUnavailable('D07 parentage proof changed its actual observer/original')
    return descriptor

class _HeaderStreamV3(C09CanonicalJSONStreamV2):
    """Inner frozen JSON grammar, retaining only fixed header paths."""
    def __init__(self):
        super().__init__(ensure_ascii=True)
        self.nodes={};self.value=None;self.scalar=bytearray();self.chars=[];self.high=None;self.buffer=bytearray()
    def keep(self,path):
        prefixes=(('input','namespace'),('input','source_qualification','source_refs'),
            ('frozen_input_digest',),('model_request_digest',))
        return not path or any(path[:len(p)]==p or p[:len(path)]==path for p in prefixes)
    def _append_decoded_codepoint(self,codepoint):
        state=self._string
        if state is None or state['mode']!='value':
            return super()._append_decoded_codepoint(codepoint)
        if not self.keep(state['path']):
            return
        if self.high is not None:
            previous=self.high;self.high=None
            if 0xdc00<=codepoint<=0xdfff:
                self.chars.append(chr(0x10000+((previous-0xd800)<<10)+codepoint-0xdc00));return
            self.chars.append(chr(previous))
        if 0xd800<=codepoint<=0xdbff:self.high=codepoint
        else:self.chars.append(chr(codepoint))
    def put(self,path,value):
        if not path:self.value=value
        else:
            parent=self.nodes[path[:-1]]
            if type(parent)is list:
                if path[-1]!=len(parent):raise ValueError('parentage inner header array changed')
                parent.append(value)
            else:parent[path[-1]]=value
    def emit(self,event):
        if not self.keep(event.path):return
        if event.kind in('object_start','array_start'):
            value={}if event.kind=='object_start'else[]
            self.nodes[event.path]=value;self.put(event.path,value)
        elif event.kind=='scalar_start':
            self.scalar=bytearray();self.chars=[];self.high=None
        elif event.kind=='scalar_chunk'and event.scalar_kind!='string':
            self.scalar.extend(event.raw)
        elif event.kind=='scalar_end':
            if event.scalar_kind=='string':
                if self.high is not None:self.chars.append(chr(self.high));self.high=None
                value=''.join(self.chars);self.chars=[]
            else:value=json.loads(self.scalar)
            self.scalar=bytearray();self.put(event.path,value)
    def codepoint(self,codepoint):
        self.buffer.extend(chr(codepoint).encode('utf-8'))
        if len(self.buffer)>=1024:
            self.feed(bytes(self.buffer),self.emit);self.buffer.clear()
    def finish_header(self):
        if self.buffer:self.feed(bytes(self.buffer),self.emit);self.buffer.clear()
        self.finish()
        return self.value

def _require_appraisal_job_identity_v3(owner,job):
    continuation=job.continuation
    if(set(continuation)!={'schema','c02_operation_id','source_ref','frozen_input_digest'}
            or continuation['schema']!='d04.post-c02-appraisal.v3'):
        raise AuthorityUnavailable('model barrier lacks its actual appraisal continuation')
    from ..runtime.d04_product_pipeline_v3 import ids
    parent=continuation['c02_operation_id'];identity=ids(owner.namespace,parent)
    if((job.bot_id,job.persona_id)!=owner.namespace.as_tuple
            or (job.job_id,job.operation_id,job.activity_id)!=(identity['job'],identity['operation'],identity['activity'])):
        raise AuthorityUnavailable('model barrier appraisal job/origin/activity/call differs')
    return parent,identity


def _appraisal_original_row_v3(db,owner,job_id):
    return _point(db,'graph_d04_originals_v3',('payload_json','payload_digest'),
        ('bot','persona','kind','original_ref'),(*owner.namespace.as_tuple,'appraisal',job_id))


def _require_appraisal_original_metadata_v3(db,owner,job,identity,row):
    from ..runtime.domain_background_read_v3 import background_json_loads_v3
    from ..runtime.d04_appraisal_driver_v3 import D04AppraisalOriginalV3
    column=row[0];raw=background_json_loads_v3(column)
    if(not column.complete or column.sha256!=row[1]
            or set(owner.column_kinds[column])!={field.name for field in fields(D04AppraisalOriginalV3)}
            or raw['schema']!='d04.paid_appraisal_original.v3'
            or NamespaceId(**raw['namespace'])!=owner.namespace
            or (raw['job_id'],raw['operation_id'],raw['call_id'])!=(job.job_id,job.operation_id,identity['call'])):
        raise AuthorityUnavailable('appraisal parentage original raw EOF/identity differs')
    header=owner.inner_headers[column];continuation=job.continuation
    if(NamespaceId(**header['input']['namespace'])!=owner.namespace
            or continuation['source_ref']not in header['input']['source_qualification']['source_refs']
            or header['frozen_input_digest']!=continuation['frozen_input_digest']
            or header['model_request_digest']!=raw['model_request_digest']):
        raise AuthorityUnavailable('appraisal parentage frozen header differs from its actual job')
    business=_point(db,'graph_bundle_operations',('activity_id','effect_id','receipt_json','commit_seq'),
        ('bot','persona','operation_id'),(*owner.namespace.as_tuple,job.operation_id))
    receipt=None if business is None else background_json_loads_v3(business[2])
    if(business is None or business[:2]!=(job.activity_id,None)
            or business[3]<1 or receipt.get('commit_seq')!=business[3]
            or receipt['schema']!='d04.installed_graph_stage.v3' or receipt['stage']!='d04.appraisal_prepared.v3'):
        raise AuthorityUnavailable('appraisal parentage has no actual initial Graph producer')
    event=_point(db,'graph_events',('revisions',),('bot','persona','session','event_id'),
        (*owner.namespace.as_tuple,job.activity_id,job.operation_id))
    from ..runtime.foreground_cycle_v1 import _reply_event_version_rows_v3
    from ..runtime.d11_types import job_graph_write
    versions=()if event is None else tuple(v for v in _reply_event_version_rows_v3(event[0])if v.key==job_graph_write(job).key)
    if len(versions)!=1:
        raise AuthorityUnavailable('appraisal parentage lost its actual initial job CAS')
    history=_point(db,'graph_history',('valid','event_id','event_bot','event_persona'),('token','revision'),
        (versions[0].key.token,versions[0].revision))
    if history!=(1,job.operation_id,*owner.namespace.as_tuple):
        raise AuthorityUnavailable('appraisal parentage initial job history changed')
    return job.operation_id,job.job_id,row[1]


def require_appraisal_parent_v3(db,*,intent,job,issuer):
    owner=_active(db)
    parent,identity=_require_appraisal_job_identity_v3(owner,job)
    if intent.call_id!=identity['call']:
        raise AuthorityUnavailable('model barrier appraisal job/origin/activity/call differs')
    row=_appraisal_original_row_v3(db,owner,job.job_id)
    if row is None:
        raise AuthorityUnavailable('model barrier appraisal original is absent')
    _require_appraisal_original_metadata_v3(db,owner,job,identity,row)
    return parent


def read_appraisal_child_metadata_v3(db,*,namespace,job_id,issuer):
    """Read one actual C2 child original identity without a prepared-body DTO."""
    owner=_active(db)
    if(type(namespace)is not NamespaceId or namespace!=owner.namespace
            or issuer is not owner.verifier._issuer or type(job_id)is not str or not job_id):
        raise AuthorityUnavailable('appraisal child metadata crossed its installed observer namespace/issuer/PK')
    row=_appraisal_original_row_v3(db,owner,job_id)
    if row is None:return None
    from ..runtime.jobs import get_job
    job=get_job(db,job_id)
    _,identity=_require_appraisal_job_identity_v3(owner,job)
    return _require_appraisal_original_metadata_v3(db,owner,job,identity,row)
