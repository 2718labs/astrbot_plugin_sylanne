"""Once-only scheduling handoff after a real Graph Work terminal.

Only detached command bytes cross this boundary. The child factory must obtain
its own current business permissions; the scheduler conveys no Source proof.
"""
from contextvars import ContextVar
from math import isfinite
from time import monotonic
from types import FunctionType
from weakref import WeakKeyDictionary

_ISSUER=object()
_PENDING=WeakKeyDictionary()
_TERMINAL_RETENTION=ContextVar("sylanne_graph_handoff_terminal_retention_v3",default=None)


class _GraphStorageHandoffV3:
    def __init__(self,issuer,parent,factory,command,deadline_utc,observed_utc):
        if issuer is not _ISSUER:raise TypeError('actual terminal Work handoff required')
        self.parent,self.factory,self.command=parent,factory,command
        self.deadline_utc=deadline_utc
        self.start_before=monotonic()+min(parent.deadline_utc,deadline_utc)-observed_utc
        self.mappers=[];self.lifetime=None
        _PENDING[self]=(parent,parent.coordinator,parent.ticket,factory,command,deadline_utc)


def issue_graph_storage_handoff_v3(parent,*,factory,command,deadline_utc,observed_utc):
    from .graph_worker import GraphStorageWorkV3
    if type(parent)is not GraphStorageWorkV3:raise TypeError('actual parent Graph Work required')
    parent._require_invocation(parent.coordinator)
    if(not parent.terminal or not parent._finish_called or parent.phase!='complete'
            or type(factory)is not FunctionType or factory.__closure__ is not None
            or type(command)is not bytes or not command or len(command)>262144
            or type(deadline_utc)not in(int,float)or not isfinite(deadline_utc)
            or type(observed_utc)not in(int,float)or not isfinite(observed_utc)
            or observed_utc>=min(parent.deadline_utc,deadline_utc)):
        raise RuntimeError('handoff requires completed current parent and bounded detached command')
    actual=_TERMINAL_RETENTION.get()
    retention=actual[1]if actual is not None and actual[0]is parent else parent.operation
    retention.retain(len(command)*2+65536)
    return _GraphStorageHandoffV3(_ISSUER,parent,factory,command,float(deadline_utc),float(observed_utc))


def is_graph_storage_handoff_v3(value):
    return type(value)is _GraphStorageHandoffV3


def suspend_graph_storage_mappers_v3(value,parent,remaining):
    if not is_graph_storage_handoff_v3(value):return False
    expected=_PENDING.get(value)
    if expected is None or expected[:3]!=(parent,parent.coordinator,parent.ticket):
        raise RuntimeError('terminal mapper returned another or consumed parent handoff')
    value.mappers.extend(remaining)
    return True


def transfer_graph_storage_lifetime_v3(value,parent):
    if not is_graph_storage_handoff_v3(value):return False
    if value.parent is not parent or value.lifetime is not None:
        raise RuntimeError('request lifetime handoff was already transferred')
    value.lifetime,parent._request_lifetime=parent._request_lifetime,None
    return True


def _close_secondary_v3(error,action):
    try:action()
    except BaseException as secondary:
        error.add_note('handoff cleanup also failed: '+type(secondary).__name__)



def _retain_immediate_result_v3(parent,value,deadline_utc):
    """Own a completed formal producer result; this memory lease grants no rights."""
    from .graph_worker import OwnedGraphStorageResultV3,_RESULT_ISSUER_V3
    if type(value)is OwnedGraphStorageResultV3:
        actual,lease=value.take_value_v3()
        return OwnedGraphStorageResultV3(_RESULT_ISSUER_V3,actual,lease)
    from .runtime_storage_v3 import RuntimeStorageOperationV3,_INSTALLED
    from .runtime.dispatch_current_inventory_v3 import _heap
    import json
    operation=parent.operation
    if type(operation)is not RuntimeStorageOperationV3:
        raise TypeError('synchronous Graph receipt requires its actual installed retention owner')
    lease=RuntimeStorageOperationV3(_INSTALLED,operation.handle,operation.operation_id+':terminal',
        min(operation.deadline_utc,deadline_utc))
    try:
        lease.retain(_heap(value)*8+65536)
        # Formal synchronous domain methods return JSON receipts. A deep JSON
        # detach rejects readers, proof objects, cursors and arbitrary DTOs.
        encoded=json.dumps(value,ensure_ascii=True,allow_nan=False,sort_keys=True,separators=(',',':'))
        actual=json.loads(encoded)
        return OwnedGraphStorageResultV3(_RESULT_ISSUER_V3,actual,lease)
    except BaseException:
        lease.release();raise

def advance_graph_storage_handoff_v3(worker,call,coordinator,value):
    from .graph_worker import (GraphStorageWorkV3,OwnedGraphStorageResultV3,
        _STORAGE_INVOCATION_V3,_GraphStorageInvocationV3)
    holder=None
    candidate=value._value if type(value)is OwnedGraphStorageResultV3 else value
    if not is_graph_storage_handoff_v3(candidate):return False,value
    handoff=candidate;record=_PENDING.pop(handoff,None)
    if(record is None or record!=(handoff.parent,coordinator,call.ticket,handoff.factory,handoff.command,handoff.deadline_utc)
            or call.work is not handoff.parent or not handoff.parent.terminal
            or call.is_callback or monotonic()>=handoff.start_before):
        error=RuntimeError('Graph handoff changed its parent/ticket/original deadline')
        if type(value)is OwnedGraphStorageResultV3:_close_secondary_v3(error,value.release_v3)
        if handoff.lifetime is not None:_close_secondary_v3(error,handoff.lifetime.close)
        raise error
    if type(value)is OwnedGraphStorageResultV3:_,holder=value.take_value_v3()
    call.handoff_deadline=(handoff.deadline_utc if call.handoff_deadline is None
        else min(call.handoff_deadline,handoff.deadline_utc))
    child=None;immediate=None;token=_STORAGE_INVOCATION_V3.set(_GraphStorageInvocationV3(coordinator,call.ticket,'ordinary',True))
    try:
        child=handoff.factory(coordinator,handoff.command)
        if type(child)is GraphStorageWorkV3:
            if(child is handoff.parent or child.coordinator is not coordinator or child.ticket!=call.ticket
                    or child.terminal or child._handed_to_worker
                    or child.deadline_utc is None or child.deadline_utc>call.handoff_deadline):
                raise RuntimeError('Graph child changed its actual ticket or original business deadline')
            child.operation.retain(len(handoff.command)*2+65536)
            if handoff.lifetime is not None:
                if child._request_lifetime is None:child.adopt_request_lifetime_v3(handoff.lifetime)
                else:child._request_lifetime.callback(handoff.lifetime.close)
                handoff.lifetime=None
            if holder is not None:
                retired,holder=holder,None;retired.release()
            child._accept(coordinator,call.ticket)
            call.final_mappers=handoff.mappers+call.final_mappers
            call.work=child;worker._queue.put_nowait(call)
            return True,None
        import inspect
        if inspect.isawaitable(child):
            if inspect.iscoroutine(child):child.close()
            raise TypeError('Graph handoff factory must be synchronous')
        if is_graph_storage_handoff_v3(child):raise RuntimeError('child factory must construct its actual Work or terminal result')
        immediate=_retain_immediate_result_v3(handoff.parent,child,call.handoff_deadline)
        if handoff.lifetime is not None:
            lifetime,handoff.lifetime=handoff.lifetime,None;lifetime.close()
        if holder is not None:
            retired,holder=holder,None;retired.release()
        call.final_mappers=handoff.mappers+call.final_mappers
        call.pending_handoff_result,immediate=immediate,None
        worker._queue.put_nowait(call)
        return True,None
    except BaseException as error:
        if immediate is not None:_close_secondary_v3(error,immediate.release_v3)
        if type(child)is OwnedGraphStorageResultV3:_close_secondary_v3(error,child.release_v3)
        if type(child)is GraphStorageWorkV3 and not child.terminal:
            def close_child():
                discarded=child._finish_and_map(coordinator,None,error)
                if type(discarded)is OwnedGraphStorageResultV3:discarded.release_v3()
            _close_secondary_v3(error,close_child)
        if holder is not None:_close_secondary_v3(error,holder.release)
        if handoff.lifetime is not None:_close_secondary_v3(error,handoff.lifetime.close)
        raise
    finally:
        handoff.factory=handoff.command=handoff.parent=None
        handoff.mappers=[];handoff.lifetime=None
        _STORAGE_INVOCATION_V3.reset(token)


def apply_graph_storage_final_mappers_v3(call,value,error):
    from .graph_worker import OwnedGraphStorageResultV3,_RESULT_ISSUER_V3
    lease=None
    if error is None and type(value)is OwnedGraphStorageResultV3:value,lease=value.take_value_v3()
    pending,call.final_mappers=call.final_mappers,[]
    token=_TERMINAL_RETENTION.set(None if lease is None else(call.work,lease))
    try:
        for index,(_,success,failed)in enumerate(pending):
            try:
                value=success(value)if error is None else failed(error);error=None
                if is_graph_storage_handoff_v3(value):
                    value.mappers.extend(pending[index+1:]);break
            except BaseException as mapped_error:value,error=None,mapped_error
        if error is not None:
            if lease is not None:_close_secondary_v3(error,lease.release);lease=None
        elif lease is not None:
            value=OwnedGraphStorageResultV3(_RESULT_ISSUER_V3,value,lease);lease=None
        return value,error
    finally:
        _TERMINAL_RETENTION.reset(token)
        pending.clear()
