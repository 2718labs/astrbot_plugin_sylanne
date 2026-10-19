"""Scheduler/retention regressions; synthetic work conveys no domain authority."""
import asyncio
from contextlib import ExitStack
import time
import pytest
from sylanne3.graph_worker import (GraphWorker,GraphStorageStepV3,OwnedGraphStorageResultV3,
    create_graph_storage_work_v3,require_graph_storage_work_admission_v3)
from sylanne3.graph_storage_handoff_v3 import issue_graph_storage_handoff_v3

class _Operation:
    def __init__(self,trace,label):self.trace,self.label,self.releases,self.callback=trace,label,0,None
    def retain(self,size):self.trace.append((self.label,'retain',size))
    def transfer_payload_release_v3(self,callback):self.callback=callback
    def release(self):
        self.releases+=1
        assert self.releases==1
        if self.callback is not None:self.callback()
        self.trace.append((self.label,'release'))
        if self.label=='parent'and ('mode','release_failure')in self.trace:
            raise OSError('first parent payload release failure')

class _Coordinator:
    def __init__(self):self.trace=[];self.operations=[]
    def close(self):self.trace.append(('store','close'))
    def _advance_runtime_storage_work_v3(self,work):
        self.trace.append((work.operation_id,'advance',require_graph_storage_work_admission_v3(self)))
        return GraphStorageStepV3('complete',{'completed':work.operation_id})
    def _finish_runtime_storage_work_v3(self,work,error):
        self.trace.append((work.operation_id,'finish',type(error).__name__ if error else None))
        if error is None:work.result_lease=work.operation
        else:work.operation.release()

def _child(coordinator,command):
    coordinator.trace.append(('child','factory',require_graph_storage_work_admission_v3(coordinator)))
    operation=_Operation(coordinator.trace,'child');coordinator.operations.append(operation)
    return create_graph_storage_work_v3(coordinator,kind='contact_cost_metadata_v3',operation_id='child',
        selection_digest='child-selected',deadline_utc=float(command),state=None,operation=operation)

def _failed_child(coordinator,command):
    coordinator.trace.append(('child','factory_failed'))
    raise ValueError('first child construction failure')

def _parent(coordinator,factory,*,outer_failure=False):
    deadline=time.time()+30.0
    operation=_Operation(coordinator.trace,'parent');coordinator.operations.append(operation)
    work=create_graph_storage_work_v3(coordinator,kind='contact_cost_metadata_v3',operation_id='parent',
        selection_digest='parent-selected',deadline_utc=deadline,state=None,operation=operation)
    lifetime=ExitStack();lifetime.callback(lambda:coordinator.trace.append(('lifetime','closed')))
    work.adopt_request_lifetime_v3(lifetime)
    def issue(_value):
        coordinator.trace.append(('parent','mapper'))
        return issue_graph_storage_handoff_v3(work,factory=factory,command=str(deadline).encode(),
            deadline_utc=deadline,observed_utc=time.time())
    def failed(error):raise error
    def complete(value):
        assert value=={'completed':'child'}
        coordinator.trace.append(('outer','mapper'))
        if outer_failure:raise LookupError('final mapper failure')
        return {'actual_child':value}
    work.map_terminal_v3('issuer',issue,failed);work.map_terminal_v3('service',complete,failed)
    return work

def test_actual_handoff_keeps_ticket_and_moves_retention_and_lifetime():
    async def run():
        graph=_Coordinator();worker=await GraphWorker.start(lambda:graph,lambda store:store,capacity=1)
        try:
            owned=await worker.call(lambda actual:_parent(actual,_child))
            assert type(owned)is OwnedGraphStorageResultV3
            value,retention=owned.take_value_v3();assert value=={'actual_child':{'completed':'child'}}
            assert [op.releases for op in graph.operations]==[1,0]
            retention.release();assert [op.releases for op in graph.operations]==[1,1]
            trace=graph.trace;labels=[item[:2]for item in trace]
            tickets=[item[2]for item in trace if item[1]=='advance'];assert len(set(tickets))==1
            assert labels.index(('parent','finish'))<labels.index(('child','factory'))
            assert labels.index(('child','factory'))<labels.index(('parent','release'))<labels.index(('child','advance'))
            assert labels.index(('child','finish'))<labels.index(('lifetime','closed'))<labels.index(('outer','mapper'))
            assert labels.count(('lifetime','closed'))==1
        finally:await worker.close()
    asyncio.run(run())

@pytest.mark.parametrize('failure',('factory','expired','outer','parent_release'))
def test_handoff_failures_preserve_error_and_release_each_owned_resource_once(monkeypatch,failure):
    if failure=='expired':
        import sylanne3.graph_storage_handoff_v3 as handoff
        clock=iter((0.0,1000.0));monkeypatch.setattr(handoff,'monotonic',lambda:next(clock))
    async def run():
        graph=_Coordinator();worker=await GraphWorker.start(lambda:graph,lambda store:store)
        expected={'factory':(ValueError,'first child construction failure'),
            'expired':(RuntimeError,'original deadline'),'outer':(LookupError,'final mapper failure'),
            'parent_release':(OSError,'first parent payload release failure')}[failure]
        if failure=='parent_release':graph.trace.append(('mode','release_failure'))
        try:
            with pytest.raises(expected[0],match=expected[1]):
                await worker.call(lambda actual:_parent(actual,_failed_child if failure=='factory'else _child,
                    outer_failure=failure=='outer'))
            assert [op.releases for op in graph.operations]==([1,1]if failure in {'outer','parent_release'}else[1])
            assert graph.trace.count(('lifetime','closed'))==1
            if failure=='expired':assert not any(item[:2]==('child','factory')for item in graph.trace)
        finally:await worker.close()
    asyncio.run(run())


def _synchronous_receipt(coordinator,command):
    coordinator.trace.append(('sync','write_once',require_graph_storage_work_admission_v3(coordinator)))
    return {'receipt':{'status':'committed','operation_id':'synthetic-local-only'}}


def _owned_synchronous_receipt(coordinator,command):
    from sylanne3.graph_worker import _RESULT_ISSUER_V3
    from sylanne3.runtime_storage_v3 import RuntimeStorageOperationV3,_INSTALLED
    coordinator.trace.append(('sync','write_once',require_graph_storage_work_admission_v3(coordinator)))
    lease=RuntimeStorageOperationV3(_INSTALLED,coordinator.handle,'synthetic-owned',float(command))
    lease.retain(1024)
    return OwnedGraphStorageResultV3(_RESULT_ISSUER_V3,{'receipt':{'status':'committed','operation_id':'synthetic-local-only'}},lease)


def _receipt_parent(coordinator,mode):
    from sylanne3.runtime_storage_v3 import RuntimeStorageOperationV3,_INSTALLED
    deadline=time.time()+30.0
    operation=RuntimeStorageOperationV3(_INSTALLED,coordinator.handle,'parent',deadline)
    operation.retain(1024)
    work=create_graph_storage_work_v3(coordinator,kind='contact_cost_metadata_v3',operation_id='parent',
        selection_digest=operation.selection_digest,deadline_utc=deadline,state=None,operation=operation)
    def first(_value):
        return issue_graph_storage_handoff_v3(work,factory=_owned_synchronous_receipt if mode=='owned'else _synchronous_receipt,
            command=str(deadline).encode(),deadline_utc=deadline,observed_utc=time.time())
    def after(receipt):
        assert operation.closed
        coordinator.trace.append(('sync','consume_receipt',require_graph_storage_work_admission_v3(coordinator)))
        assert receipt['receipt']['status']=='committed'
        if mode=='suffix_failure':raise ValueError('committed receipt suffix first failure')
        if mode=='post_read':
            return issue_graph_storage_handoff_v3(work,factory=_child,command=str(deadline).encode(),
                deadline_utc=deadline,observed_utc=time.time())
        return receipt
    def failed(error):raise error
    return work.map_terminal_v3('issuer',first,failed).map_terminal_v3('service',after,failed)


@pytest.mark.parametrize('mode',['plain','owned','post_read','suffix_failure'])
def test_synchronous_receipt_once_retained_and_followed_without_rewrite(mode):
    from types import SimpleNamespace
    from sylanne3.runtime_storage_v3 import _RuntimeResourcePoolV3
    async def scenario():
        coordinator=_Coordinator();pool=_RuntimeResourcePoolV3();baseline=pool.used
        coordinator.handle=SimpleNamespace(pool=pool,selection_digest='synthetic-retention-only')
        worker=await GraphWorker.start(lambda:coordinator,lambda store:store,capacity=1)
        try:
            if mode=='suffix_failure':
                with pytest.raises(ValueError,match='committed receipt suffix first failure'):
                    await worker.call(lambda graph:_receipt_parent(graph,mode))
            else:
                result=await worker.call(lambda graph:_receipt_parent(graph,mode))
                assert type(result)is OwnedGraphStorageResultV3
                actual,lease=result.take_value_v3()
                try:
                    assert actual==({'completed':'child'}if mode=='post_read'else
                        {'receipt':{'status':'committed','operation_id':'synthetic-local-only'}})
                finally:lease.release()
            calls=[item for item in coordinator.trace if len(item)>1 and item[1]=='write_once']
            assert len(calls)==1
            consumption=[item for item in coordinator.trace if len(item)>1 and item[1]=='consume_receipt']
            assert len(consumption)==1 and calls[0][2]==consumption[0][2]
            assert pool.used==baseline
        finally:await worker.close()
    asyncio.run(scenario())
