"""C4 terminal Body Source on its actual existing once READ permit."""
from weakref import WeakKeyDictionary
from .contract import AuthorityUnavailable

_BRIDGES=WeakKeyDictionary()

def require_artifact_result_source_bridge_v3(work,*,observe=False):
    bridge=_BRIDGES.get(work)
    if bridge is None:return None
    from .owner_location_read_v3 import _OWNER_LIFE_RESULT_ENTRIES_V3,_OWNER_LIFE_RESULT_INVOCATIONS_V3,_OWNER_MODEL_LOCATION_ENTRIES_V3
    service,request,intent,terminal,entry,state=bridge
    call=state[5]
    if(_OWNER_LIFE_RESULT_ENTRIES_V3.get(entry)is not state or _OWNER_MODEL_LOCATION_ENTRIES_V3.get(work)is not state
            or _OWNER_LIFE_RESULT_INVOCATIONS_V3.get(service,{}).get(request.read_attempt_id)!=(work.credential,request,work.permit)
            or service._inflight_deliveries.get(request.read_attempt_id)is not work.permit
            or service._graph_reader is not state[0]or service._graph_reader.result_service is not service
            or work.request is not intent or work.permit.operation!="read"or work.permit.operation_id!=request.read_attempt_id
            or call.permit is not work.permit or call.request is not intent or call.closed
            or call.operation.closed or call.subject!=work.subject
            or work.controller.verifier._artifact_model_reader_v3 is not service._graph_reader
            or work.service is not service._graph_reader.model_service
            or work.controller.fences is not service._fences or work.controller.location is not service._location
            or work.operation.pool is not call.operation.pool or work.controller.control is not call.control
            or(intent.job_id,intent.call_id,intent.request_digest,intent.binding_digest)!=(request.job_id,request.call_id,
                request.model_request_digest,request.binding_digest)
            or terminal.call_id!=intent.call_id or terminal.request_digest!=intent.request_digest):
        raise AuthorityUnavailable("Artifact result Source lost actual once READ/Owner/terminal/installed model bridge")
    state[2].require_for_v3(state[1])
    if observe:
        if work.db.in_transaction:raise AuthorityUnavailable("Artifact READ current permission must precede Graph SQL")
        call._check_permission_v3()
    return bridge

def prepare_artifact_result_source_work_v3(service,*,request,intent,terminal,entry):
    from .d11_artifact_draft_model_v1 import AuthorityArtifactDraftModelResultServiceV1
    from .owner_location_read_v3 import _OWNER_LIFE_RESULT_ENTRIES_V3,_OWNER_LIFE_RESULT_INVOCATIONS_V3,_OWNER_MODEL_LOCATION_ENTRIES_V3
    if type(service)is not AuthorityArtifactDraftModelResultServiceV1:
        raise AuthorityUnavailable("Artifact result Source requires exact installed terminal service")
    registered=_OWNER_LIFE_RESULT_INVOCATIONS_V3.get(service,{}).get(request.read_attempt_id)
    state=_OWNER_LIFE_RESULT_ENTRIES_V3.get(entry)
    if registered is None or registered[1]is not request or state is None or state[0]is not service._graph_reader:
        raise AuthorityUnavailable("Artifact result Source has no actual active once READ and Owner EOF")
    from .current_authority_graph_read_v3 import begin_authority_artifact_result_read_work_v3
    work=begin_authority_artifact_result_read_work_v3(service,credential=registered[0],permit=registered[2],intent=intent)
    _BRIDGES[work]=(service,request,intent,terminal,entry,state);_OWNER_MODEL_LOCATION_ENTRIES_V3[work]=state
    try:
        require_artifact_result_source_bridge_v3(work,observe=True)
        from .artifact_model_source_read_v3 import require_artifact_model_phase_v3
        require_artifact_model_phase_v3(work,service._graph_reader)
        work.phase="catalogue"
        return work
    except BaseException:
        from .current_authority_graph_read_v3 import finish_authority_graph_read_work_v3
        finish_authority_graph_read_work_v3(work);raise

def read_artifact_result_material_v3(work,*,location):
    bridge=require_artifact_result_source_bridge_v3(work)
    if bridge is None:raise AuthorityUnavailable("Artifact result has no actual independent Source Work")
    service,request,intent,terminal,entry,state=bridge
    from .current_authority_graph_read_v3 import read_authority_graph_current_v3
    def read(db):
        service._location.require_graph_snapshot_v1(db,location,graph_db_path=service._path)
        current=service._graph_reader.read(db,intent,work.now_utc,allow_accounted_result=True)
        p=current.prepared
        if(request.selector,request.binding_digest,request.model_request_digest,request.original_operation_id)!=(
                p.selector,p.digest,current.request.digest,p.operation_id):
            raise AuthorityUnavailable("Artifact result selector differs from actual current original")
        return p,current.job,current.frozen
    return read_authority_graph_current_v3(work,read)

def release_artifact_result_source_v3(work):
    _BRIDGES.pop(work,None)
