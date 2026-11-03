"""Actual worker/handoff/retention lifecycle with synthetic business readers.

These cases issue no domain authority, model call, or installed acceptance.
"""
import asyncio
from contextlib import ExitStack
from dataclasses import replace
from datetime import datetime, timezone
from threading import Event, get_ident
from types import SimpleNamespace
import sqlite3
import time

import pytest

from sylanne3.graph_worker import (GraphWorker, GraphStorageStepV3,
    OwnedGraphStorageResultV3, create_graph_storage_work_v3)
from sylanne3.runtime import natural_stage_egress_work_v3 as natural
from sylanne3.runtime.natural_reply_job_v2 import SavedNaturalPreparationV2
from sylanne3.runtime_contracts import (NamespaceId, NaturalReplyGenerationOriginalSealV2,
    NaturalReplyReviewOriginalSealV2)
from sylanne3.runtime_storage_v3 import RuntimeStorageOperationV3, _RuntimeResourcePoolV3, _INSTALLED


def originals(stage, deadline):
    namespace = NamespaceId("bot", "persona")
    generation_seal = NaturalReplyGenerationOriginalSealV2(namespace, "parent", "source",
        "installation", "1" * 64, "generation-job", "generation-original",
        "generation-acquire", "generation-call", *("2" * 64 for _ in range(4)),
        "budget", "reservation")
    plan = SimpleNamespace(audience_id="audience", valid_until_utc=deadline)
    generation = SavedNaturalPreparationV2("generation", "parent", generation_seal,
        SimpleNamespace(input=SimpleNamespace(plan=plan, expires_at_utc=deadline)),
        (), (), 0, 0, 0, "queued" if stage == "generation" else "terminal", None, None, None, None)
    if stage == "generation":
        return generation, generation
    review_seal = NaturalReplyReviewOriginalSealV2(namespace, "installation", "1" * 64,
        "review-job", "review-original", "review-acquire", "review-call",
        "generation-original", "generation-call", *("2" * 64 for _ in range(6)),
        "budget", "reservation", "review-policy")
    review = SavedNaturalPreparationV2("review", "parent", review_seal, SimpleNamespace(),
        (), (), 0, 0, 0, "queued", None, None, None, None)
    return review, generation


class LifecycleGraph:
    """Only the new producer boundary is real; business reads are explicit doubles."""
    def __init__(self, saved, generation, mode):
        self.saved, self.generation, self.mode = saved, generation, mode
        self.epoch = 0
        self.producer_open = False
        self.leases = set()
        self.release_threads = []
        self.operations = []
        self.child_entered, self.child_continue = Event(), Event()
        self.pool = _RuntimeResourcePoolV3()
        self.baseline = self.pool.used
        self.handle = SimpleNamespace(pool=self.pool, selection_digest="natural-lifecycle-unit")
        ns = saved.seal.namespace
        workflow = SimpleNamespace(work_kind="natural_" + saved.stage, purpose="proposal",
            audiences=("audience",), provider_config_ref="provider-policy")
        workflows = SimpleNamespace(**{"natural_" + saved.stage: workflow})
        policy = SimpleNamespace(namespace=ns, installation_id="installation", authority_namespace="authority")
        self.bundle = SimpleNamespace(installation_policy=policy, model_workflows=workflows, ingress_clock=None)
        self.bootstrap = object()
        self.port = SimpleNamespace(installation_grant=SimpleNamespace(subject="host"),
            current_anchor=lambda **kw: SimpleNamespace(activation_generation=1),
            read_ingress_clock=lambda policy: time.time())
        self._GraphCoordinator__bootstrap = self.bootstrap
        self._GraphCoordinator__content_fence_v2 = self.port
        self._GraphCoordinator__d04_installed_joint_assembly = SimpleNamespace(admin_bundle=self.bundle)
        db = sqlite3.connect(":memory:", check_same_thread=False)
        db.execute("CREATE TABLE runtime_jobs(bot_id,persona_id,job_id,operation_id,work_kind,deadline_utc)")
        db.execute("INSERT INTO runtime_jobs VALUES(?,?,?,?,?,?)", (*ns.as_tuple,
            saved.seal.job_id, saved.seal.original_operation_id, "natural_" + saved.stage,
            datetime.fromtimestamp(generation.frozen.input.expires_at_utc, timezone.utc).isoformat()))
        from threading import RLock
        self._GraphCoordinator__store = SimpleNamespace(_db=db, _lock=RLock())

    def _admin(self, bootstrap):
        assert bootstrap is self.bootstrap

    def grant(self, bootstrap, **kw):
        self._admin(bootstrap)
        assert not self.producer_open
        lease = object()
        self.leases.add(lease)
        return lease, "same-original-operation-capability"

    def release_authority_lease(self, bootstrap, lease):
        self._admin(bootstrap)
        self.leases.remove(lease)
        self.release_threads.append(get_ident())

    def close(self):
        self._GraphCoordinator__store._db.close()

    def _prepare_full_read_then_call_v3(self, authority, lease, contract, callback,
            *, deadline_utc, c02_operation_id):
        assert not self.producer_open and lease in self.leases
        operation = RuntimeStorageOperationV3(_INSTALLED, self.handle,
            "natural-read-" + str(len(self.operations)), deadline_utc)
        operation.retain(1024)
        self.operations.append(operation)
        state = SimpleNamespace(callback=callback, expected_epoch=self.epoch)
        work = create_graph_storage_work_v3(self, kind="contact_cost_metadata_v3",
            operation_id=operation.operation_id, selection_digest=operation.selection_digest,
            deadline_utc=deadline_utc, state=state, operation=operation)
        lifetime = ExitStack()
        lifetime.callback(lambda: setattr(self, "producer_open", False))
        work.adopt_request_lifetime_v3(lifetime)

        def completed(proof):
            assert proof.epoch == state.expected_epoch
            return callback(proof)

        def failed(error):
            raise error

        return work.map_terminal_v3("issuer", completed, failed)

    def _advance_runtime_storage_work_v3(self, work):
        self.producer_open = True
        return GraphStorageStepV3("complete", SimpleNamespace(epoch=work.state.expected_epoch))

    def _finish_runtime_storage_work_v3(self, work, error):
        if error is None:
            work.result_lease = work.operation
        else:
            work.operation.release()

    def read_natural_original_stage_preparation_v2(self, authority, lease, parent, stage, bundle):
        assert self.producer_open and lease in self.leases and bundle is self.bundle
        return self.saved if stage == self.saved.stage else self.generation

    def _acquire_post_c02_natural_stage_v2(self, authority, lease, parent, bundle,
            *, stage, lease_seconds, _prepared_full_read):
        assert _prepared_full_read.epoch == self.epoch == 0
        self.saved = replace(self.saved, state="acquired")
        self.epoch += 1
        self.job = SimpleNamespace(job_id=self.saved.seal.job_id,
            operation_id=self.saved.seal.original_operation_id, fence=1)
        self.call = SimpleNamespace(call_id=self.saved.seal.call_id, digest="a" * 64,
            identity=SimpleNamespace(operation_id=self.saved.seal.acquire_operation_id),
            envelope=SimpleNamespace(authority=replace(authority, worker_fence=1)))
        return self.job, self.call

    def read_natural_model_egress_preparation_v2(self, authority, lease, parent, stage, bundle,
            *, _prepared_full_read, _include_job_v3):
        assert _prepared_full_read.epoch == self.epoch == 1
        assert self.call.envelope.authority == authority
        assert _include_job_v3 and len(self.leases) == 1
        self.child_entered.set()
        if self.mode == "cancel":
            assert self.child_continue.wait(2)
        if self.mode == "child_failure":
            raise ValueError("first fresh egress failure")
        return self.call, "draft", "fresh-anchor", self.job


@pytest.mark.parametrize("stage", ("generation", "review"))
@pytest.mark.parametrize("mode", ("complete", "child_failure", "cancel"))
def test_natural_actual_worker_handoff_closes_graph_authority_before_owned_delivery(monkeypatch, stage, mode):
    monkeypatch.setattr(natural, "runtime_storage_v3", lambda db: True)
    monkeypatch.setattr(natural, "trusted_upper", lambda reading: reading)

    async def scenario():
        saved, generation = originals(stage, time.time() + 30)
        graph = LifecycleGraph(saved, generation, mode)
        worker = await GraphWorker.start(lambda: graph, lambda store: store, capacity=1)
        loop_thread = get_ident()
        try:
            task = asyncio.create_task(worker.call(lambda current:
                natural.start_installed_natural_stage_v3(current, graph.bootstrap, graph.bundle,
                    saved=saved, generation_saved=generation, lease_seconds=30)))
            if mode == "cancel":
                assert await asyncio.to_thread(graph.child_entered.wait, 2)
                task.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await task
                graph.child_continue.set()
            elif mode == "child_failure":
                with pytest.raises(ValueError, match="first fresh egress failure"):
                    await task
            else:
                owned = await task
                assert type(owned) is OwnedGraphStorageResultV3 and graph.leases == set()
                value, retention = owned.take_value_v3()
                try:
                    assert type(value) is natural.NaturalStageEgressV3
                    assert value.prepared == (graph.call, "draft", "fresh-anchor")
                    assert value.authority == graph.call.envelope.authority
                    assert graph.operations[0].closed and not graph.operations[1].closed
                finally:
                    value = None
                    retention.release()
        finally:
            graph.child_continue.set()
            await worker.close()
        assert len(graph.operations) == 2
        assert graph.leases == set() and not graph.producer_open
        assert graph.pool.used == graph.baseline
        assert all(op.closed for op in graph.operations)
        assert len(graph.release_threads) == 2
        assert all(thread != loop_thread for thread in graph.release_threads)

    asyncio.run(scenario())


@pytest.mark.parametrize('delivery',('consumed','abandoned','cancel_before_delivery'))
def test_actual_dispatch_inventory_owned_cleanup_survives_abandoned_delivery(delivery):
    """Actual worker/result/operation ownership; business Source is synthetic."""
    class Payload:
        releases=0
        def release_payload_v3(self):self.releases+=1
    class Graph:
        def __init__(self):
            self.pool=_RuntimeResourcePoolV3();self.baseline=self.pool.used
            self.handle=SimpleNamespace(pool=self.pool,selection_digest='inventory-lifecycle')
            self.payload=Payload();self.entered=Event();self.proceed=Event();self.operation=None
        def close(self):pass
        def start(self):
            self.operation=RuntimeStorageOperationV3(_INSTALLED,self.handle,'inventory-lifecycle',time.time()+30)
            self.operation.retain(4096)
            return create_graph_storage_work_v3(self,kind='dispatch_inventory_prepare_v3',
                operation_id=self.operation.operation_id,selection_digest=self.operation.selection_digest,
                deadline_utc=self.operation.deadline_utc,state=self.payload,operation=self.operation)
        def _advance_runtime_storage_work_v3(self,work):
            if delivery=='cancel_before_delivery':
                self.entered.set();assert self.proceed.wait(2)
            return GraphStorageStepV3('complete',self.payload)
        def _finish_runtime_storage_work_v3(self,work,error):
            if error is None:work.result_lease=work.operation
            else:
                self.payload.release_payload_v3();work.operation.release()
    async def scenario():
        graph=Graph();worker=await GraphWorker.start(lambda:graph,lambda value:value,capacity=1)
        try:
            task=asyncio.create_task(worker.call(lambda current:current.start()))
            if delivery=='cancel_before_delivery':
                assert await asyncio.to_thread(graph.entered.wait,2)
                task.cancel()
                with pytest.raises(asyncio.CancelledError):await task
                graph.proceed.set()
            else:
                owned=await task
                assert type(owned)is OwnedGraphStorageResultV3 and not graph.operation.closed
                if delivery=='abandoned':owned.release_v3()
                else:
                    value,lease=owned.take_value_v3()
                    assert value is graph.payload and value.releases==0
                    value=None;lease.release()
                owned.release_v3()  # Moved/released wrapper no longer owns a payload.
        finally:
            graph.proceed.set();await worker.close()
        assert graph.payload.releases==1
        assert graph.operation.closed and graph.pool.used==graph.baseline
    asyncio.run(scenario())
