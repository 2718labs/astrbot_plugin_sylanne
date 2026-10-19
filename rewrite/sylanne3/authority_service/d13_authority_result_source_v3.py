"""Private Source bridge for the existing D13 worker-result READ attempt."""
from contextvars import ContextVar
from weakref import WeakKeyDictionary
from .contract import AuthorityUnavailable
from ..runtime_contracts import canonical_digest
from dataclasses import asdict

_BRIDGES=WeakKeyDictionary()
_ACTIVE=ContextVar("actual_d13_authority_result_source_v3",default=None)


def require_d13_result_bridge_v3(work,*,observe=False):
    saved=_BRIDGES.get(work)
    if saved is None:return None
    service,credential,request,intent,permit,installed,terminal,operation,scope,selection=saved
    from .v2_worker_model_result_read_service import AuthorityV2WorkerModelResultReadService
    if (type(service)is not AuthorityV2WorkerModelResultReadService
            or service._graph is not installed.worker_service._graph or service is not installed.worker_service
            or service._store is not installed.model_service._store or service._fences is not work.controller.fences
            or service._inflight_deliveries.get(request.read_attempt_id)!=permit
            or work.credential is not credential or work.request is not intent or work.permit is not permit
            or work.operation is not operation or work.scope is not scope or work.selection_digest!=selection
            or permit.operation!="read"or permit.operation_id!=request.read_attempt_id
            or service._graph._path!=work.controller.location._graph_db_path
            or work.operation.pool is not service._fences.core._runtime_storage_v3.pool):
        raise AuthorityUnavailable("D13 result Source lost its same actual READ/model/selected pool")
    work._actual();installed.require_v3(work)
    if observe:
        if work.db.in_transaction:raise AuthorityUnavailable("D13 result Core observation must precede Graph SQL")
        service._require(credential,request)
        fences=service._fences
        with fences._frozen()as(db,deletion,execution,_):
            anchor=fences._current_locked(db,deletion,execution,holder=service._holder,generation=permit.generation)
            if anchor!=permit.pinned_anchor:raise AuthorityUnavailable("D13 result actual READ anchor changed")
            fences.fences.validate_fence_locked(db,permit,subject=service._read_subject,current_anchor=anchor)
            attempt=service._attempts._read_locked(db,request.read_attempt_id)
            actual_intent,actual_terminal,_=service._terminal_locked(db,request,anchor,content=False)
            if (attempt is None or attempt.request!=request or attempt.state!="active"
                    or attempt.permit_digest!=canonical_digest(asdict(permit))
                    or actual_intent!=intent or actual_terminal!=terminal):
                raise AuthorityUnavailable("D13 result actual Core attempt/terminal changed")
    return saved


def prepare_d13_worker_result_source_v3(service,*,credential,request,intent,permit):
    from .v2_worker_model_result_read_service import AuthorityV2WorkerModelResultReadService
    from .v2_worker_model_result_contract import WorkerModelResultReadRequestV1
    from .current_authority_graph_read_v3 import (
        require_authority_graph_read_controller_v3,AuthorityGraphReadWorkV3,_ISSUER,
        _AuthorityCatalogueReadV3,finish_authority_graph_read_work_v3)
    from .d13_authority_model_source_v3 import _PHASES,InstalledD13AuthorityModelReaderV3
    if (type(service)is not AuthorityV2WorkerModelResultReadService
            or type(request)is not WorkerModelResultReadRequestV1 or request.purpose!="d13_precompress_paid"
            or service._inflight_deliveries.get(request.read_attempt_id)!=permit
            or permit.operation!="read"or permit.operation_id!=request.read_attempt_id):
        raise AuthorityUnavailable("D13 result Source must be issued by its actual begun service READ")
    installed=getattr(service._graph,"_d13_paid_reader_v3",None)
    if type(installed)is not InstalledD13AuthorityModelReaderV3 or installed.worker_service is not service:
        raise AuthorityUnavailable("D13 result independent Source reader is not installed")
    controller=require_authority_graph_read_controller_v3(installed.model_service._graph_verifier)
    if (controller.service is not installed.model_service or controller.fences is not service._fences
            or service._store is not controller.service._store):
        raise AuthorityUnavailable("D13 result Source crossed installed Core/model controller")
    with service._fences._frozen()as(db,deletion,execution,_):
        anchor=service._fences._current_locked(db,deletion,execution,holder=service._holder,generation=permit.generation)
        service._fences.fences.validate_fence_locked(db,permit,subject=service._read_subject,current_anchor=anchor)
        actual,terminal,_=service._terminal_locked(db,request,anchor,content=False)
        attempt=service._attempts._read_locked(db,request.read_attempt_id)
        if (actual!=intent or attempt is None or attempt.request!=request or attempt.state!="active"
                or attempt.permit_digest!=canonical_digest(asdict(permit))):
            raise AuthorityUnavailable("D13 result Source has no actual durable READ/attempt pair")
    work=AuthorityGraphReadWorkV3(_ISSUER,controller,credential=credential,subject=permit.subject,
        permit=permit,namespace=request.namespace,request=intent,deadline_utc=None)
    try:
        work.now_utc=float(controller.clock());work.catalogue_reader=_AuthorityCatalogueReadV3(work)
        work.model_natural=work.model_reply=False;work.phase="d13_paid_source"
        _BRIDGES[work]=(service,credential,request,intent,permit,installed,terminal,
            work.operation,work.scope,work.selection_digest)
        _PHASES[work]=(installed,intent,permit,work.operation,work.scope,"d13_result_read")
        require_d13_result_bridge_v3(work,observe=True)
        return work
    except BaseException:
        finish_authority_graph_read_work_v3(work)
        _BRIDGES.pop(work,None)
        raise


def read_d13_worker_result_source_v3(work):
    saved=require_d13_result_bridge_v3(work,observe=True)
    if saved is None:raise AuthorityUnavailable("D13 result has no actual independent Source READ")
    service,_,request,intent,permit=saved[:5]
    from .current_authority_graph_read_v3 import read_authority_graph_current_v3
    def current(db):
        token=_ACTIVE.set(work)
        try:return service._graph.current(request,intent,permit)
        finally:_ACTIVE.reset(token)
    return read_authority_graph_current_v3(work,current)


def d13_result_current_on_bound_source_v3(verifier,request,intent,permit):
    installed=getattr(verifier,"_d13_paid_reader_v3",None)
    if installed is None:return None
    work=_ACTIVE.get()
    if work is None:return False
    saved=require_d13_result_bridge_v3(work)
    if (saved is None or saved[0]._graph is not verifier or saved[2]is not request
            or saved[3]is not intent or saved[4]is not permit or not work.db.in_transaction):
        raise AuthorityUnavailable("D13 result graph qualification crossed its original active Source read")
    from .d13_authority_model_source_v3 import d13_authority_source_reader_v3
    reader=d13_authority_source_reader_v3(work)
    if reader is None:raise AuthorityUnavailable("D13 result actual Source EOF is absent")
    return verifier._check_d13_paid(work.db,request,intent,permit,reader.now_utc)


def finish_d13_worker_result_source_v3(work):
    from .current_authority_graph_read_v3 import finish_authority_graph_read_work_v3
    try:finish_authority_graph_read_work_v3(work)
    finally:_BRIDGES.pop(work,None)
