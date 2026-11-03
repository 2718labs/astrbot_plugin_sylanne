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
        assert ('lifetime','closed')not in coordinator.trace
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
            assert labels.index(('child','finish'))<labels.index(('outer','mapper'))<labels.index(('lifetime','closed'))
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


@pytest.mark.parametrize('cleanup_failure',(False,True))
def test_worker_abort_releases_inherited_final_lifetime_without_replacing_first_failure(monkeypatch,cleanup_failure):
    original=GraphWorker._step_call
    def fail_child(self,call,coordinator):
        if call.work is not None and call.work.operation_id=='child':
            raise RuntimeError('first worker abort before child advance')
        return original(self,call,coordinator)
    monkeypatch.setattr(GraphWorker,'_step_call',fail_child)
    def parent(graph):
        work=_parent(graph,_child)
        if cleanup_failure:
            def fail_cleanup():raise OSError('secondary outer lifetime release')
            work._request_lifetime.callback(fail_cleanup)
        return work
    async def scenario():
        graph=_Coordinator();worker=await GraphWorker.start(lambda:graph,lambda store:store)
        try:
            with pytest.raises(RuntimeError,match='first worker abort before child advance')as caught:
                await worker.call(parent)
            assert [op.releases for op in graph.operations]==[1,1]
            assert graph.trace.count(('lifetime','closed'))==1
            assert ('outer','mapper')not in graph.trace
            if cleanup_failure:
                assert any('final request lifetime cleanup' in note for note in caught.value.__notes__)
        finally:
            with pytest.raises(RuntimeError,match='first worker abort before child advance'):
                await worker.close()
    asyncio.run(scenario())



@pytest.mark.parametrize('read_failure',(False,True))
def test_d13_storage_finish_and_request_cleanup_preserve_first_failure(read_failure):
    from types import SimpleNamespace
    first=ValueError('first diagnostic read refusal') if read_failure else OSError('first diagnostic finish failure')
    class Graph(_Coordinator):
        def _advance_runtime_storage_work_v3(self,work):
            if read_failure:raise first
            return GraphStorageStepV3('complete',SimpleNamespace(release_payload_v3=lambda:None))
        def _finish_runtime_storage_work_v3(self,work,error):
            work.operation.release()
            if read_failure:raise OSError('secondary diagnostic finish failure')
            raise first
    def begin(graph):
        operation=_Operation(graph.trace,'diagnostic');graph.operations.append(operation)
        work=create_graph_storage_work_v3(graph,kind='d13_accounting_diagnostic_v3',operation_id='diagnostic',
            selection_digest='diagnostic-selected',deadline_utc=time.time()+30,state=None,operation=operation)
        def cleanup():
            graph.trace.append(('diagnostic','request_closed'))
            raise LookupError('secondary diagnostic request cleanup')
        lifetime=ExitStack();lifetime.callback(cleanup);work.adopt_request_lifetime_v3(lifetime)
        return work
    async def scenario():
        graph=Graph();worker=await GraphWorker.start(lambda:graph,lambda store:store)
        try:
            with pytest.raises(type(first),match=str(first))as caught:await worker.call(begin)
            assert caught.value is first
            assert first.__cause__ is not first
            assert any('request lifetime cleanup failed' in note for note in first.__notes__)
            if read_failure:assert any('producer finish failed' in note for note in first.__notes__)
            assert [op.releases for op in graph.operations]==[1]
            assert graph.trace.count(('diagnostic','request_closed'))==1
        finally:await worker.close()
    asyncio.run(scenario())


def test_abandoned_storage_result_keeps_payload_failure_and_releases_retention_once():
    from sylanne3.graph_worker import _RESULT_ISSUER_V3
    trace=[]
    first=ValueError('first abandoned payload failure')
    class Lease:
        def release(self):
            trace.append('lease')
            raise OSError('secondary retention release failure')
    def release_payload():
        trace.append('payload')
        raise first
    owned=OwnedGraphStorageResultV3(_RESULT_ISSUER_V3,object(),Lease(),release_payload)
    with pytest.raises(ValueError,match=str(first))as caught:owned.release_v3()
    assert caught.value is first
    assert trace==['payload','lease']
    assert any('retention release failed' in note for note in first.__notes__)
    owned.release_v3()
    assert trace==['payload','lease']


def _full_retention_case_v3(*, finish_error=None):
    """Synthetic storage seam; no namespace grant, Source rights or model authority."""
    from types import SimpleNamespace
    import sqlite3
    from sylanne3.graph_types import NamespaceEpoch
    from sylanne3.runtime_contracts import NamespaceId
    from sylanne3.runtime_storage_v3 import RuntimeStorageOperationV3, _RuntimeResourcePoolV3, _INSTALLED
    from sylanne3.runtime.current_graph_full_read_v3 import (
        _OrdinaryFullReadV3, _PrefinalSourceInventoryV3, _FixedTypedProjectionV3,
        PreparedCurrentGraphFullReadV3, NATURAL_MODEL_FULL_READ_V3, _ISSUER)

    class Work:
        pass

    class Rights:
        def __init__(self):
            self.reads = 0
        def require_v3(self):
            self.reads += 1
            return self

    class Material:
        proof = None
        def __init__(self):
            self.rights = Rights()
        def require_rights_seal_v3(self):
            return self.rights.require_v3()

    db = sqlite3.connect(':memory:')
    pool = _RuntimeResourcePoolV3()
    baseline = pool.used
    handle = SimpleNamespace(pool=pool, selection_digest='synthetic-full-retention')
    operation = RuntimeStorageOperationV3(_INSTALLED, handle, 'synthetic-full', 1000.0)
    ns = NamespaceId('retention-bot', 'retention-persona')
    scope = SimpleNamespace(namespace=ns)
    fence = SimpleNamespace(scope=scope, metadata=object(), epoch=NamespaceEpoch(*ns.as_tuple, 1))
    finishes = []
    def finish(actual):
        assert actual is fence
        finishes.append(actual)
        if finish_error is not None:
            raise finish_error
    graph = SimpleNamespace(_GraphCoordinator__store=SimpleNamespace(_db=db,
        _registry=SimpleNamespace(catalogue_hash='synthetic-catalogue')),
        _finish_read_fence_v3=finish)
    reader = _OrdinaryFullReadV3(graph, operation, fence, NATURAL_MODEL_FULL_READ_V3)
    work = Work()
    work.state, work.coordinator, work.operation = reader, graph, operation
    work.ticket, work.result_lease = 1, None
    reader.work = work
    reader.graph_eof = True
    reader.sources['original-source'] = object()
    reader.heads['original-source'] = (1, 1, 'original-cell')
    reader.prefinal = _PrefinalSourceInventoryV3(_ISSUER, reader)
    reader.source_material = Material()
    reader.projection = _FixedTypedProjectionV3(_ISSUER, reader)
    reader.body_eof = reader.complete = True
    proof = PreparedCurrentGraphFullReadV3(_ISSUER, reader)
    reader.result = proof
    return graph, work, reader, proof, operation, pool, db, finishes, baseline


def test_full_terminal_keeps_original_source_consumable_until_owned_result_release():
    from sylanne3.graph_worker import _RESULT_ISSUER_V3
    from sylanne3.authority_service.contract import AuthorityUnavailable
    from sylanne3.runtime.current_graph_full_read_v3 import (
        finish_current_graph_full_read_v3, release_current_graph_full_result_v3, _ORDINARY_READERS_V3)
    graph, work, reader, proof, operation, pool, db, finishes, baseline = _full_retention_case_v3()
    original_sources, original_heads, material, prefinal = (
        reader.sources, reader.heads, reader.source_material, reader.prefinal)
    try:
        finish_current_graph_full_read_v3(graph, work, None)
        # The actual retained consumer used by the Natural producer must still work.
        assert prefinal.require_body_projection_v3() is proof.projection
        proof._actual()
        assert reader.sources is original_sources and reader.heads is original_heads
        assert reader.sources['original-source'] is prefinal.sources['original-source']
        assert reader.heads['original-source'] == prefinal.heads['original-source']
        assert reader.source_material is material and material.rights.reads > 0
        assert reader.cell is reader.parser is reader.body is reader.atoms is None
        assert work.result_lease is operation and not operation.closed and pool.used > baseline
        owned = OwnedGraphStorageResultV3(_RESULT_ISSUER_V3, proof, work.result_lease,
            lambda: release_current_graph_full_result_v3(work, proof))
        work.result_lease = None
        value, retention = owned.take_value_v3()
        assert value is proof
        retention.release()
        assert operation.closed and pool.used == baseline and reader not in _ORDINARY_READERS_V3
        assert reader.sources is reader.heads is reader.source_material is None
        with pytest.raises(AuthorityUnavailable):
            prefinal.require_body_projection_v3()
        with pytest.raises(AuthorityUnavailable):
            proof._actual()
        retention.release()
        assert pool.used == baseline and finishes == [reader.fence]
    finally:
        operation.release()
        db.close()


@pytest.mark.parametrize('failure_stage', ('read', 'fence_finish'))
def test_full_early_failure_closes_retention_without_missing_selection_cleanup(failure_stage):
    from sylanne3.authority_service.contract import AuthorityUnavailable
    from sylanne3.runtime.current_graph_full_read_v3 import (
        finish_current_graph_full_read_v3, _ORDINARY_READERS_V3)
    first = ValueError('first actual read refusal') if failure_stage == 'read' else OSError('first actual finish refusal')
    graph, work, reader, proof, operation, pool, db, finishes, baseline = _full_retention_case_v3(
        finish_error=first if failure_stage == 'fence_finish' else None)
    try:
        if failure_stage == 'fence_finish':
            with pytest.raises(OSError, match=str(first)) as caught:
                finish_current_graph_full_read_v3(graph, work, None)
            assert caught.value is first
        else:
            finish_current_graph_full_read_v3(graph, work, first)
        assert work.result_lease is None and operation.closed and pool.used == baseline
        assert reader.sources is reader.heads is reader.source_material is None
        assert reader not in _ORDINARY_READERS_V3 and reader.metadata_selection is None
        assert finishes == [reader.fence]
        with pytest.raises(AuthorityUnavailable):
            proof._actual()
    finally:
        operation.release()
        db.close()
