"""Private metadata-only D07 dispatch, followed by a fresh formal command."""
from contextvars import ContextVar
from dataclasses import fields
from weakref import WeakKeyDictionary
import time

from ..authority_service.contract import AuthorityUnavailable
from ..graph_types import AtomKey
from ..runtime_contracts import NamespaceId,canonical_serialize
from ..runtime_storage_v3 import bind_runtime_storage_operation_v3,runtime_storage_quantum_v3,finish_runtime_storage_operation_v3
from ..graph_worker import GraphStorageStepV3,GraphStorageWorkV3

D07_DISPATCH_WORK_KIND_V3="current_d07_dispatch_read_v3"
_READS=WeakKeyDictionary()
_HANDOFFS=WeakKeyDictionary()
_BOUND=ContextVar("sylanne_d07_classified_actual_dispatch_v3",default=None)

def register_d07_dispatch_read_v3(r):
    if r.work.kind!=D07_DISPATCH_WORK_KIND_V3 or r.operation_kind!="serve_concern"or r in _READS:
        raise AuthorityUnavailable("D07 classifier requires its actual once-issued current concern")
    _READS[r]={"identity":(r.work,r.operation,r.fence,r.request,r.operation_id,r.activity_id,r.namespace,r.authority,r.lease),
        "tasks":{},"phase":"semantic_question","owner":None}

def require_d07_dispatch_read_v3(r):
    from .current_beta1_source_read_v3 import require_current_beta1_source_work_v3
    require_current_beta1_source_work_v3(r)
    record=_READS.get(r)
    if(record is None or record["identity"]!=(r.work,r.operation,r.fence,r.request,r.operation_id,r.activity_id,r.namespace,r.authority,r.lease)
            or r.work.kind!=D07_DISPATCH_WORK_KIND_V3):
        raise AuthorityUnavailable("D07 classifier lost its actual original command/READ")
    return record

def pin_d07_dispatch_owner_v3(r):
    value=require_d07_dispatch_read_v3(r)
    if value["owner"]is not None and value["owner"]!=r.owner_binding:
        raise AuthorityUnavailable("D07 classifier changed its complete current Owner")
    value["owner"]=r.owner_binding

def d07_dispatch_metadata_spec_v3(r,identity):
    record=require_d07_dispatch_read_v3(r)
    if identity[0]=="d07_classify_graph":
        if len(identity)!=2 or identity[1]!=r.request.trigger_original_ref:
            raise AuthorityUnavailable("D07 Graph trigger metadata escaped actual current concern")
        key=AtomKey.from_token(identity[1])
        if NamespaceId.from_key(key)!=r.namespace:raise AuthorityUnavailable("D07 Graph trigger crossed namespace")
        r.store._registry.spec(key.type_name)
        return("graph_atoms","value",("token","bot","persona"),(key.token,*r.namespace.as_tuple),
            ("revision","valid","value_cell_id"),(("schema",),),None)
    if(identity[0]!="d07_classify"or len(identity)!=3 or identity[1]not in{"semantic_question","reflection_request"}
            or identity[2]!=r.request.trigger_original_ref):
        raise AuthorityUnavailable("D07 classifier metadata escaped its exact signed current trigger")
    return("graph_d07_execution_originals_v1","payload_json",("bot","persona","kind","original_ref"),
        (*r.namespace.as_tuple,identity[1],identity[2]),("payload_digest","signature"),
        (("schema",),("target_ref",)),None)

def finish_d07_dispatch_metadata_v3(task,value):
    from .d07_execution_v1 import SIGN_KIND,D07SemanticQuestionV1,D07RelationshipSemanticQuestionV2
    from .d07_method_growth_semantic_v2 import D07MethodGrowthSemanticQuestionV2,QUESTION_SCHEMA as METHOD_SCHEMA
    from .d07_general_growth_attention_v1 import D07GeneralGrowthQuestionV1
    from .d07_reflection_execution_v1 import D07ReflectionExecutionRequestV1
    r=task.reader;require_d07_dispatch_read_v3(r)
    if task.identity[0]=="d07_classify_graph":
        if task.metadata[0]<1 or task.metadata[1]!=1:
            raise AuthorityUnavailable("D07 ordinary Graph trigger has no actual positive current original")
        key=AtomKey.from_token(task.identity[1])
        return("graph_original",key.token,task.column.canonical_digest,task.metadata,key.type_name,"registered_graph")
    kind,original=task.identity[1:]
    r.graph._GraphCoordinator__d11_issuer._signer.verify(SIGN_KIND,
        canonical_serialize((r.namespace,kind,original,task.metadata[0])),task.metadata[1])
    schema=value["schema"]
    known={"d07.registered-semantic-question.v1":D07SemanticQuestionV1,
        "d07.relationship-semantic-question.v2":D07RelationshipSemanticQuestionV2,
        METHOD_SCHEMA:D07MethodGrowthSemanticQuestionV2,
        "d07.general-growth-semantic-question.v1":D07GeneralGrowthQuestionV1,
        "d07.actual-reflection-request.v1":D07ReflectionExecutionRequestV1}
    cls=known.get(schema)
    if(cls is None or task.column.beta1_metadata_fields_seen!={f.name for f in fields(cls)}
            or(kind=="reflection_request")!=(cls is D07ReflectionExecutionRequestV1)):
        raise AuthorityUnavailable("D07 classifier rejects an unknown or misshaped registered signed original")
    route="registered_native"
    if cls is not D07ReflectionExecutionRequestV1:
        from ..domains.d03.world_history_v1 import VIEW_TYPE
        target=value["target_ref"]
        if set(target)!={"ref","version"}or type(target["version"])is not int or target["version"]<1:
            raise AuthorityUnavailable("D07 classifier target has no exact current signed revision")
        try:key=AtomKey.from_token(target["ref"])
        except (ValueError,TypeError):
            if cls is not D07SemanticQuestionV1:
                raise AuthorityUnavailable("named D07 semantic question lost its canonical registered Graph target")
            route="registered_joint_plan"
        else:
            if NamespaceId.from_key(key)!=r.namespace:
                raise AuthorityUnavailable("D07 classifier target crossed actual namespace")
            r.store._registry.spec(key.type_name)
            if key.type_name==VIEW_TYPE:
                if cls is not D07SemanticQuestionV1:
                    raise AuthorityUnavailable("named D07 question cannot substitute a World target")
                route="world"
    else:route="registered_reflection"
    return(kind,original,task.metadata[0],task.metadata[1],schema,route)

class _D07DispatchHandoffV3:
    pass

def advance_current_d07_dispatch_read_v3(graph,work):
    from .current_beta1_source_read_v3 import prepare_current_beta1_owner_entry_v3,create_current_beta1_metadata_task_v3
    from .current_method_learning_read_v3 import PreparedCurrentMethodLearningReadV3,_ISSUER
    r=work.state;record=require_d07_dispatch_read_v3(r)
    with bind_runtime_storage_operation_v3(work.operation,r.db):
        prepare_current_beta1_owner_entry_v3(r);graph._validate_read_fence_v3(r.fence)
        if not r.graph_eof:
            with r.store._lock:r.advance()
            return GraphStorageStepV3("progress")
        if not r.inventory_sealed:
            r.inventory_sealed=True;r.inventory=PreparedCurrentMethodLearningReadV3(_ISSUER,r)
            return GraphStorageStepV3("progress")
        identity=(("d07_classify_graph",r.request.trigger_original_ref)if record["phase"]=="graph_original"else
            ("d07_classify",record["phase"],r.request.trigger_original_ref))
        with r.store._lock,runtime_storage_quantum_v3(r.db)as meter:
            task=record["tasks"].get(identity)
            if task is None:
                task=create_current_beta1_metadata_task_v3(r,identity);record["tasks"][identity]=task
            if not task.complete:
                task.advance(meter);return GraphStorageStepV3("progress")
            task.require_header_v3(meter)
            if task.result is None:
                if record["phase"]=="semantic_question":
                    record["phase"]="reflection_request";return GraphStorageStepV3("progress")
                if record["phase"]=="reflection_request":
                    try:key=AtomKey.from_token(r.request.trigger_original_ref)
                    except (ValueError,TypeError):
                        raise AuthorityUnavailable("D07 concern has no authenticated named original family")
                    if NamespaceId.from_key(key)!=r.namespace:
                        raise AuthorityUnavailable("D07 actual Graph trigger crossed namespace")
                    r.store._registry.spec(key.type_name)
                    record["phase"]="graph_original";return GraphStorageStepV3("progress")
                raise AuthorityUnavailable("D07 concern has no authenticated positive registered original")
            if record["owner"]!=r.owner_binding:
                raise AuthorityUnavailable("D07 classifier lost its completed independent current Owner")
            r.operation.retain(32768)
            proof=_D07DispatchHandoffV3()
            _HANDOFFS[proof]={"graph":graph,"work":work,"operation":work.operation,
                "authority":r.authority,"lease":r.lease,"runtime":r.runtime,"namespace":r.namespace,
                "request":r.request,"operation_id":r.operation_id,"activity_id":r.activity_id,
                "audience_ref":r.audience_ref,"parent_budget_lease_ref":r.parent_budget_lease_ref,
                "request_digest":r.request_digest,"owner":r.owner_binding,
                "deadline":r.operation.deadline_utc,"monotonic_deadline":r.initial_monotonic_deadline,
                "locator":task.result,"status":"classified"}
        graph._finish_read_fence_v3(r.fence);r.read_finished=True
        return GraphStorageStepV3("complete",proof)

def require_d07_dispatch_handoff_v3(proof,work):
    value=_HANDOFFS.get(proof)
    if(type(proof)is not _D07DispatchHandoffV3 or value is None or value["work"]is not work
            or work.kind!=D07_DISPATCH_WORK_KIND_V3 or value["operation"]is not work.operation
            or value["graph"]is not work.coordinator or value["status"]!="classified"
            or work.state not in _READS or not work.state.read_finished):
        raise AuthorityUnavailable("D07 dispatch is not its actual complete private metadata READ handoff")
    work._require_invocation(work.coordinator)
    return value

def detach_current_d07_dispatch_read_v3(proof,work):
    value=require_d07_dispatch_handoff_v3(proof,work);r=work.state
    from .current_method_learning_read_v3 import _release_method_registered_payloads_v3,_READERS
    _release_method_registered_payloads_v3(r)
    if r.inventory is not None:r.inventory.release_payload_v3()
    _READERS.discard(r)
    r.points.clear();r.inventories.clear();r.input_heads.clear();r.attachments.clear();r.wires.clear()
    r.heads=r.atoms=r.sources=r.inventory=None
    work.state=proof;value["status"]="ready"
    return value

def current_d07_classified_command_v3(graph,*,authority,lease,request,operation_id,activity_id,audience_ref,parent_budget_lease_ref):
    proof=_BOUND.get()
    if proof is None:return None
    value=_HANDOFFS.get(proof)
    if(value is None or value["status"]!="resuming"or value["graph"]is not graph
            or value["authority"]is not authority or value["lease"]is not lease or value["request"]!=request
            or(value["operation_id"],value["activity_id"],value["audience_ref"],value["parent_budget_lease_ref"])!=(
                operation_id,activity_id,audience_ref,parent_budget_lease_ref)):
        raise AuthorityUnavailable("D07 classified command crossed its private fresh formal entry")
    if time.monotonic()>=value["monotonic_deadline"]:
        raise AuthorityUnavailable("D07 original dispatch Root deadline expired")
    from .current_method_learning_read_v3 import _method_active
    if _method_active(graph._GraphCoordinator__store._db)is not None:
        raise AuthorityUnavailable("D07 fresh dispatch may not inherit a Source/Method reader or Binder")
    return value

def require_d07_classified_write_v3(graph,db,scope,owner,request):
    proof=_BOUND.get()
    if proof is None:return None
    value=_HANDOFFS.get(proof)
    if(value is None or value["status"]!="resuming"or value["graph"]is not graph
            or value["request"]!=request or owner!=value["owner"]or scope.operation!="write"
            or scope.namespace!=value["namespace"]or db is not graph._GraphCoordinator__store._db):
        raise AuthorityUnavailable("D07 classified command lacks its fresh exact current Owner WRITE")
    kind,original,digest,signature,_,_=value["locator"]
    with runtime_storage_quantum_v3(db)as meter:
        from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3
        if kind=="graph_original":
            actual=_runtime_bounded_fixed_row_v3(db,meter,"graph_atoms",("revision","valid","value_cell_id"),
                "token=? AND bot=? AND persona=?",(original,*value["namespace"].as_tuple))
            expected=signature
        else:
            actual=_runtime_bounded_fixed_row_v3(db,meter,"graph_d07_execution_originals_v1",
                ("payload_digest","signature"),"bot=? AND persona=? AND kind=? AND original_ref=?",
                (*value["namespace"].as_tuple,kind,original))
            expected=(digest,signature)
    if actual!=expected:
        raise AuthorityUnavailable("D07 actual signed trigger changed between classification and fresh WRITE")
    value["write_scope"]=scope
    return value

def finish_d07_dispatch_handoff_v3(proof,work):
    from ..graph_worker import OwnedGraphStorageResultV3,_RESULT_ISSUER_V3
    value=detach_current_d07_dispatch_read_v3(proof,work)
    value["first_ticket"]=work.ticket
    value["mappers"],work._mappers=work._mappers,[]
    value["lifetime"],work._request_lifetime=work._request_lifetime,None
    value.pop("work")
    work.state=None;work.terminal=True;work.phase="classified"
    def abandon():release_current_d07_dispatch_handoff_v3(proof)
    value["abandon_release"]=abandon
    return OwnedGraphStorageResultV3(_RESULT_ISSUER_V3,proof,value["operation"],abandon)

def take_current_d07_dispatch_handoff_v3(result):
    from ..graph_worker import OwnedGraphStorageResultV3
    if type(result)is not OwnedGraphStorageResultV3:return None
    with result._lock:
        proof=result._value
        if type(proof)is not _D07DispatchHandoffV3:return None
        value=_HANDOFFS.get(proof)
        if(value is None or value["status"]!="ready"or result._lease is not value["operation"]
                or result._release_payload is not value["abandon_release"]):
            raise AuthorityUnavailable("D07 async consumer received another operation's dispatch retention")
        root=result._lease
        result._value=result._lease=result._release_payload=None
        value["status"]="enqueued"
    return proof,root

def release_current_d07_dispatch_handoff_v3(proof):
    value=_HANDOFFS.pop(proof,None)
    if value is None:return
    lifetime=value.pop("lifetime",None)
    if lifetime is not None:lifetime.close()

def abandon_unaccepted_d07_dispatch_v3(proof,root):
    value=_HANDOFFS.get(proof)
    if value is None:return
    if value["status"]!="enqueued"or root is not value["operation"]:
        raise AuthorityUnavailable("D07 cleanup cannot abandon an already accepted formal command")
    try:release_current_d07_dispatch_handoff_v3(proof)
    finally:root.release()

def _finish_classified_response_v3(proof,value,result,error=None):
    from ..graph_worker import OwnedGraphStorageResultV3,_RESULT_ISSUER_V3
    had_error=error is not None
    mappers=value.pop("mappers")
    try:
        for _,success,failed in mappers:
            try:result=success(result)if error is None else failed(error);error=None
            except BaseException as mapped:result,error=None,mapped
    finally:
        mappers.clear()
        try:release_current_d07_dispatch_handoff_v3(proof)
        except BaseException as closed:
            if error is not None:closed.__cause__=error
            result,error=None,closed
    if error is not None:
        finish_runtime_storage_operation_v3(value["operation"]);raise error
    if had_error:
        finish_runtime_storage_operation_v3(value["operation"]);return result
    return OwnedGraphStorageResultV3(_RESULT_ISSUER_V3,result,value["operation"])

def resume_current_d07_classified_command_v3(graph,proof):
    from ..graph_worker import require_graph_storage_work_admission_v3
    value=_HANDOFFS.get(proof)
    if(value is None or value["status"]!="enqueued"or value["graph"]is not graph
            or require_graph_storage_work_admission_v3(graph)==value["first_ticket"]):
        raise AuthorityUnavailable("D07 dispatch requires its actual second ordinary worker call")
    value["status"]="resuming";token=_BOUND.set(proof)
    try:
        try:
            with bind_runtime_storage_operation_v3(value["operation"],graph._GraphCoordinator__store._db):
                result=value["runtime"].run_current(value["authority"],value["lease"],operation_kind="serve_concern",
                    request=value["request"],operation_id=value["operation_id"],activity_id=value["activity_id"],
                    audience_ref=value["audience_ref"],parent_budget_lease_ref=value["parent_budget_lease_ref"])
            if value["locator"][-1]=="world":
                if(type(result)is not GraphStorageWorkV3 or result.kind!="current_d07_source_read_v3"
                        or result.operation is not value["operation"]):
                    raise AuthorityUnavailable("World classifier did not re-enter its actual independent Source Work")
                for stage,success,failed in value["mappers"]:result.map_terminal_v3(stage,success,failed)
                result.adopt_request_lifetime_v3(value["lifetime"])
                value["mappers"]=[];value["lifetime"]=None
                _HANDOFFS.pop(proof)
                return result
            if type(result)is GraphStorageWorkV3:
                raise AuthorityUnavailable("registered native D07 dispatch returned an unregistered continuation")
            value["status"]="completed"
        except BaseException as failure:
            return _finish_classified_response_v3(proof,value,None,failure)
        return _finish_classified_response_v3(proof,value,result)
    finally:_BOUND.reset(token)

def finish_current_d07_dispatch_read_v3(graph,work,error):
    state=work.state
    if state in _READS:
        from .current_method_learning_read_v3 import _release_method_registered_payloads_v3,_READERS
        if not state.read_finished:
            graph._finish_read_fence_v3(state.fence);state.read_finished=True
        _release_method_registered_payloads_v3(state)
        if state.inventory is not None:state.inventory.release_payload_v3()
        _READERS.discard(state)
    elif _HANDOFFS.get(state,{}).get("work")is not work:
        raise AuthorityUnavailable("D07 classifier finalization changed its private handoff")
    if error is None:work.result_lease=work.operation
    else:
        _HANDOFFS.pop(state,None);finish_runtime_storage_operation_v3(work.operation)

def release_d07_dispatch_read_v3(r):
    _READS.pop(r,None)
