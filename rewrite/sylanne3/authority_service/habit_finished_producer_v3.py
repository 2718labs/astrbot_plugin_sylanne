"""Exact finished old Habit producer tuple in the current selected Core lineage."""
from weakref import WeakKeyDictionary
import hashlib
from .contract import AuthorityUnavailable
from .v2_contract import FencePermitV2,canonical_bytes,from_wire
from .v2_fence_store import AuthorityV2FenceStore
from ..runtime_contracts import canonical_digest

_KEY=object()
_BINDINGS=WeakKeyDictionary()

class _HabitFinishedProducerWorkV3:
    def __init__(self,key,inputs,operation_id,header,permit,bundle,origin):
        if key is not _KEY:raise AuthorityUnavailable('Habit finished read requires its actual private producer recipe')
        self.inputs,self.actual_work,self.service=inputs,inputs.work,inputs.service
        self.namespace,self.subject,self.permit=inputs.work.namespace,inputs.work.subject,inputs.work.permit
        self.producer_fence_candidates={operation_id:(header,permit,bundle)}
        self.origin=origin;self.failed=False
    def require_v3(self):
        from .habit_authority_source_read_v3 import require_habit_authority_work_v3
        state=require_habit_authority_work_v3(self.actual_work)
        if(state is not self.inputs or not state.complete or state.closed or self.failed
                or self.service is not state.service or self.permit!=self.actual_work.permit
                or self.subject!=self.actual_work.subject or self not in _BINDINGS.get(self.actual_work,())):
            raise AuthorityUnavailable('Habit finished producer reader lost actual Source EOF/current private Work')
        self.inputs.require_for_v3(service=self.service,permit=self.permit)
        return self
    def _observe(self):self.require_v3();return self

def require_habit_finished_work_v3(work):
    if type(work)is not _HabitFinishedProducerWorkV3:raise AuthorityUnavailable('exact Habit private finished reader required')
    return work.require_v3()

def _finished(inputs,operation_id,header,permit,bundle,origin):
    from .habit_authority_source_read_v3 import require_habit_authority_work_v3
    state=require_habit_authority_work_v3(inputs.work)
    if state is not inputs or not state.complete:raise AuthorityUnavailable('Habit producer metadata requires actual complete Source EOF')
    candidates=_BINDINGS.setdefault(inputs.work,[])
    match=next((w for w in candidates if w.origin==origin and operation_id in w.producer_fence_candidates),None)
    if match is None:
        match=_HabitFinishedProducerWorkV3(_KEY,inputs,operation_id,header,permit,bundle,origin);candidates.append(match)
    elif match.producer_fence_candidates[operation_id]!=(header,permit,bundle):
        raise AuthorityUnavailable('Habit producing Core original changed in one actual Source Work')
    match.require_v3()
    fences=inputs.service.policy_service.fences;core=inputs.service.policy_service.core
    try:
        with fences._frozen()as(db,deletion,execution,_):
            core.require_current_storage_generation_locked(db,namespace=fences.namespace,action='business')
            fences._current_locked(db,deletion,execution,holder=inputs.work.permit.holder,generation=inputs.work.permit.generation)
            row=AuthorityV2FenceStore._row(db,permit.operation_id)
            if row is not None and(AuthorityV2FenceStore._permit(row)!=permit or row[7]!=canonical_bytes(permit)
                    or row[6]!='finished'or row[8:11]!=(header[5],header[6],None)):
                raise AuthorityUnavailable('Habit actual producer Core row is not its exact ended original tuple')
        if row is None:
            from .conditioned_child_c09_finished_v1 import require_accepted_conditioned_producer_fence_v1
            row=require_accepted_conditioned_producer_fence_v1(match,operation_id=operation_id,header=header,permit=permit,bundle=bundle)
        return canonical_digest((row[:7],hashlib.sha256(bytes(row[7])).hexdigest(),row[8:]))
    except BaseException:match.failed=True;raise

def require_habit_producer_finished_v3(inputs,*,operation_id,expected_kind,original_digest,receipt_digest):
    from .habit_authority_source_read_v3 import _fixed_row_v3,_run_column_v3
    from ..runtime.dispatch_initial_source_read_v3 import DispatchOriginalJSONReadV3
    from ..runtime.habit_activity_history_v1 import validate_habit_activity_provenance_v1
    w=inputs.work;key=(*w.namespace.as_tuple,operation_id)
    header=_fixed_row_v3(w,'graph_bundle_fences_v2',('digest','pre_graph_revision','pre_graph_epoch',
        'post_graph_revision','post_graph_epoch','finish_request_id','finish_request_digest'),
        'bot=? AND persona=? AND operation_id=?',key)
    bundle=_fixed_row_v3(w,'graph_bundle_operations',('digest','commit_seq'),'bot=? AND persona=? AND operation_id=?',key)
    original=_fixed_row_v3(w,'graph_domain_production_originals_v1',('domain','operation_kind','original_digest','receipt_digest'),
        'bot=? AND persona=? AND operation_id=?',key)
    if(header is None or bundle is None or bundle[0]!=header[0]or bundle[1]<1
            or header[3:5]!=(header[1]+1,header[2]+1)
            or original is None or original[1:]!=(expected_kind,original_digest,receipt_digest)):
        raise AuthorityUnavailable('Habit producer lacks exact actual Graph COMMIT/fence/original')
    p=DispatchOriginalJSONReadV3(w,table='graph_bundle_fences_v2',column='permit_json',
        key_columns=('bot','persona','operation_id'),key=key)
    permit=from_wire(_run_column_v3(w,p))
    payload=DispatchOriginalJSONReadV3(w,table='graph_domain_production_originals_v1',column='original_payload_json',
        key_columns=('bot','persona','operation_id'),key=key)
    raw=_run_column_v3(w,payload)
    historical=raw['provenance']['habit_activity_execution_v1']
    selector,_=validate_habit_activity_provenance_v1(original[0],expected_kind,historical)
    from ..runtime.habit_activity_history_v1 import habit_activity_scope_binding_v1
    if historical['scope_binding_digest']!=habit_activity_scope_binding_v1(selector,permit=permit,graph_revision=header[1],graph_epoch=header[2]):
        raise AuthorityUnavailable('Habit actual producer permit/stamp differs from its signed historical binding')
    finish='sha256:'+canonical_digest({'schema':'w01.habit-domain-write.v1','operation_id':operation_id,
        'request_digest':canonical_digest(selector),'permit_token':permit.token})
    if(type(permit)is not FencePermitV2 or permit.operation!='write'or permit.operation_id!=operation_id
            or(selector.namespace,selector.operation_id)!=(w.namespace,operation_id)
            or(permit.authority_id,permit.namespace,permit.subject,permit.holder)!=(w.permit.authority_id,
                w.permit.namespace,w.subject,w.permit.holder)or header[5:]!=('finish:'+operation_id,finish)):
        raise AuthorityUnavailable('Habit producer finished tuple differs from actual installation/subject/holder/phase')
    return _finished(inputs,operation_id,header,permit,bundle,'actual_habit_write_producer')

def require_habit_preparation_read_finished_v3(inputs,preparation):
    permit=preparation.read_permit;current=inputs.work.permit
    if(permit.authority_id,permit.namespace,permit.subject,permit.holder)!=(current.authority_id,current.namespace,inputs.work.subject,current.holder):
        raise AuthorityUnavailable('Habit Body preparation READ belongs to another actual caller/installation')
    finish='sha256:'+canonical_digest({'operation_id':permit.operation_id,'permit_token':permit.token,'action':'finish_read'})
    header=(preparation.digest,None,None,None,None,'finish:'+permit.operation_id,finish)
    return _finished(inputs,permit.operation_id,header,permit,('body_cpu_preparation_read',preparation.digest),
        'actual_habit_body_preparation_read')


def require_habit_life_progress_producer_finished_v3(inputs,*,operation_id,original_digest,receipt_digest):
    """Only the actual advance_life COMMIT/attempt tuple, read in this Habit Source Work."""
    from .habit_authority_source_read_v3 import _fixed_row_v3,_run_column_v3
    from ..runtime.dispatch_initial_source_read_v3 import DispatchOriginalJSONReadV3
    w=inputs.work;key=(*w.namespace.as_tuple,operation_id)
    original=_fixed_row_v3(w,"graph_domain_production_originals_v1",
        ("domain","operation_kind","original_digest","receipt_digest"),"bot=? AND persona=? AND operation_id=?",key)
    bundle=_fixed_row_v3(w,"graph_bundle_operations",("digest","commit_seq"),"bot=? AND persona=? AND operation_id=?",key)
    header=_fixed_row_v3(w,"graph_bundle_fences_v2",("digest","pre_graph_revision","pre_graph_epoch",
        "post_graph_revision","post_graph_epoch","finish_request_id","finish_request_digest"),
        "bot=? AND persona=? AND operation_id=?",key)
    attempt=_fixed_row_v3(w,"graph_owner_domain_attempts_v3",("request_digest","attempt_id","graph_revision","graph_epoch"),
        "bot=? AND persona=? AND operation_id=?",key)
    if(original!=("d10","advance_life",original_digest,receipt_digest)or bundle is None or type(bundle[1])is not int or bundle[1]<1
            or header is None or header[0]!=bundle[0]or header[3:5]!=(header[1]+1,header[2]+1)
            or attempt is None or attempt[2:]!=header[1:3]):
        raise AuthorityUnavailable("Habit Life result lacks its actual positive COMMIT/attempt/fence original")
    column=DispatchOriginalJSONReadV3(w,table="graph_bundle_fences_v2",column="permit_json",
        key_columns=("bot","persona","operation_id"),key=key)
    permit=from_wire(_run_column_v3(w,column))
    saved=DispatchOriginalJSONReadV3(w,table="graph_owner_domain_attempts_v3",column="permit_json",
        key_columns=("bot","persona","operation_id"),key=key)
    saved_permit=from_wire(_run_column_v3(w,saved))
    if(type(permit)is not FencePermitV2 or permit!=saved_permit or permit.operation!="write"
            or permit.operation_id!=attempt[1]or header[5]!="finish:"+permit.operation_id
            or(permit.authority_id,permit.namespace,permit.subject,permit.holder)!=(w.permit.authority_id,
                w.permit.namespace,w.subject,w.permit.holder)):
        raise AuthorityUnavailable("Habit Life result old scope differs from actual namespace/subject/holder/phase/attempt")
    return _finished(inputs,operation_id,header,permit,bundle,"actual_advance_life_producer")

def release_habit_finished_reads_v3(work):
    from .conditioned_child_c09_finished_v1 import release_accepted_conditioned_producer_reads_v1
    for value in _BINDINGS.pop(work,()):release_accepted_conditioned_producer_reads_v1(value)
