"""One bounded thread owns graph calls and their explicit storage continuations."""
from __future__ import annotations

import asyncio
from concurrent.futures import Future
from contextlib import ExitStack
from contextvars import ContextVar, copy_context
from dataclasses import dataclass
import inspect
import traceback
from queue import Queue
from threading import BoundedSemaphore, Lock, Thread
from typing import Callable

from .contracts import CapacityExceeded

_STOP = object()
_WINDOW_READY = object()
_WINDOW_END = object()
_WORK_ISSUER_V3 = object()
_RESULT_ISSUER_V3 = object()
_STORAGE_INVOCATION_V3 = ContextVar("sylanne_graph_storage_invocation_v3", default=None)
_STORAGE_KINDS_V3 = frozenset({"current_d07_dispatch_read_v3","current_world_source_read_v3","current_d07_source_read_v3","current_d07_simulation_source_read_v3","current_life_numeric_accounting_v3","current_life_numeric_paid_write_v3", "current_life_numeric_model_seal_v3", "current_owner_job_cancel_v3", "source_correction_context_v3", "owner_material_source_write_v3", "dispatch_inventory_prepare_v3", "current_graph_full_read_v3", "d13_standby_read_v3","d13_paid_original_read_v3","d13_derived_retirement_read_v3", "current_method_learning_read_v3", "current_life_numeric_read_v3", "domain_background_read_v3", "contact_host_stage_read_v3", "contact_cost_metadata_v3", "contact_effect_accounting_v1", "host_beta1_fixture_evidence_read"})


def _clear_storage_error_frames_v3(error):
    """Preserve the actual traceback locations while detaching completed locals."""
    pending,seen = [error],set()
    while pending:
        current=pending.pop()
        if current is None or id(current) in seen:continue
        seen.add(id(current))
        traceback.clear_frames(current.__traceback__)
        pending.extend((current.__cause__,current.__context__))
        if isinstance(current,BaseExceptionGroup):pending.extend(current.exceptions)


class GraphStorageContinuationRequiredV3(RuntimeError):
    """The actual installed storage operation requires its owning async worker."""


@dataclass(frozen=True, slots=True)
class _GraphStorageInvocationV3:
    coordinator: object
    ticket: int | None
    mode: str
    initial: bool


def require_graph_storage_work_admission_v3(coordinator):
    """Require an actual ordinary worker invocation before opening a fence."""
    invocation = _STORAGE_INVOCATION_V3.get()
    if (invocation is None or invocation.coordinator is not coordinator
            or invocation.mode != "ordinary" or invocation.ticket is None):
        raise GraphStorageContinuationRequiredV3("async_graph_worker_required")
    return invocation.ticket


@dataclass(frozen=True, slots=True)
class GraphStorageStepV3:
    status: str
    result: object = None

    def __post_init__(self):
        if self.status not in {"progress", "complete"}:
            raise ValueError("graph storage step has an unknown status")
        if self.status == "progress" and self.result is not None:
            raise ValueError("unfinished graph storage step cannot publish a result")


class OwnedGraphStorageResultV3:
    """Private DTO retention ownership, moved to the actual response encoder."""
    __slots__ = ("_value", "_lease", "_lock", "_release_payload")

    def __init__(self, issuer, value, lease, release_payload=None):
        if issuer is not _RESULT_ISSUER_V3:
            raise TypeError("actual graph worker result ownership required")
        self._value, self._lease, self._lock = value, lease, Lock()
        self._release_payload = release_payload

    def take_value_v3(self):
        """Move the actual value and the same lease together, exactly once."""
        with self._lock:
            if self._lease is None:
                raise RuntimeError("graph storage result ownership already moved")
            value, lease = self._value, self._lease
            if self._release_payload is not None:
                lease.transfer_payload_release_v3(self._release_payload)
            self._value = self._lease = self._release_payload = None
        return value, lease

    def release_v3(self):
        """Drop an abandoned value; an already moved wrapper owns nothing."""
        with self._lock:
            lease, release_payload = self._lease, self._release_payload
            self._value = self._lease = self._release_payload = None
        if lease is not None:
            try:
                if release_payload is not None:release_payload()
            finally:
                lease.release()


class GraphStorageWorkV3:
    """Private scheduling state; actual permissions remain with the producer.

    ``state`` is the registered kind's actual state, retaining the original
    job/input references and readset. A read operation does not invent a job.
    ``operation`` is the original physical retention lease, never a new grant.
    """
    __slots__ = ("coordinator", "kind", "operation_id", "selection_digest",
        "deadline_utc", "state", "operation", "phase", "terminal", "ticket",
        "result_lease", "_handed_to_worker", "_finish_called", "_mappers",
        "_request_lifetime")

    def __init__(self, issuer, coordinator, *, kind, operation_id,
                 selection_digest, deadline_utc, state, operation):
        if issuer is not _WORK_ISSUER_V3:
            raise TypeError("actual graph storage work producer required")
        ticket = require_graph_storage_work_admission_v3(coordinator)
        invocation = _STORAGE_INVOCATION_V3.get()
        if not invocation.initial or kind not in _STORAGE_KINDS_V3:
            raise GraphStorageContinuationRequiredV3("registered initial graph storage producer required")
        self.coordinator, self.kind, self.ticket = coordinator, kind, ticket
        self.operation_id, self.selection_digest = operation_id, selection_digest
        self.deadline_utc, self.state, self.operation = deadline_utc, state, operation
        self.phase, self.terminal, self.result_lease = "prepared", False, None
        self._handed_to_worker = self._finish_called = False
        self._mappers = []
        self._request_lifetime = None

    def _require_invocation(self, coordinator, *, initial=False):
        if coordinator is not self.coordinator:
            raise RuntimeError("graph storage work belongs to another coordinator")
        ticket = require_graph_storage_work_admission_v3(coordinator)
        invocation = _STORAGE_INVOCATION_V3.get()
        if ticket != self.ticket or (initial and (not invocation.initial or self._handed_to_worker)):
            raise RuntimeError("graph storage work belongs to another invocation")

    def map_terminal_v3(self, stage, success_mapper, failure_mapper):
        self._require_invocation(self.coordinator, initial=True)
        if len(self._mappers) == 2 or stage not in {"issuer", "service"} or stage != ("issuer", "service")[len(self._mappers)]:
            raise RuntimeError("graph storage terminal mapper stage is repeated or out of order")
        if not callable(success_mapper) or not callable(failure_mapper):
            raise TypeError("graph storage terminal mappers must be actual functions")
        self._mappers.append((stage, success_mapper, failure_mapper))
        return self

    def adopt_request_lifetime_v3(self, lifetime):
        self._require_invocation(self.coordinator, initial=True)
        if type(lifetime) is not ExitStack or self._request_lifetime is not None:
            raise RuntimeError("graph storage request lifetime must be transferred once")
        self._request_lifetime = lifetime
        return self

    def _accept(self, coordinator, ticket):
        self._require_invocation(coordinator, initial=True)
        if ticket != self.ticket or self.terminal:
            raise RuntimeError("graph storage work identity changed before worker ownership")
        self._handed_to_worker = True

    def advance(self, coordinator):
        self._require_invocation(coordinator)
        if not self._handed_to_worker or self.terminal:
            raise RuntimeError("graph storage work is not owned and unfinished")
        if self.kind == "current_graph_full_read_v3":
            from .runtime.current_graph_full_read_v3 import advance_current_graph_full_read_v3
            step = advance_current_graph_full_read_v3(coordinator,self)
        else:
            step = coordinator._advance_runtime_storage_work_v3(self)
        if type(step) is not GraphStorageStepV3:
            raise TypeError("actual graph storage producer step required")
        return step

    def _finish_and_map(self, coordinator, value, error):
        self._require_invocation(coordinator)
        if self._finish_called:
            raise RuntimeError("graph storage work was already finalized")
        self._finish_called = True
        if error is None and self.kind=="current_d07_dispatch_read_v3":
            from .runtime.d07_source_dispatch_read_v3 import _D07DispatchHandoffV3,finish_d07_dispatch_handoff_v3
            if type(value)is _D07DispatchHandoffV3:
                return finish_d07_dispatch_handoff_v3(value,self)
        storage_payload = self.kind in {"current_d07_dispatch_read_v3","current_world_source_read_v3","current_d07_source_read_v3","current_d07_simulation_source_read_v3","current_life_numeric_accounting_v3","current_life_numeric_paid_write_v3","current_life_numeric_model_seal_v3","current_owner_job_cancel_v3","owner_material_source_write_v3","dispatch_inventory_prepare_v3","current_graph_full_read_v3","d13_standby_read_v3","d13_paid_original_read_v3","d13_derived_retirement_read_v3","current_method_learning_read_v3","current_life_numeric_read_v3","domain_background_read_v3", "host_beta1_fixture_evidence_read"}
        release_payload = (value.release_payload_v3
            if self.kind in {"current_d07_dispatch_read_v3","current_world_source_read_v3","current_d07_source_read_v3","current_d07_simulation_source_read_v3","current_life_numeric_paid_write_v3","current_graph_full_read_v3","d13_standby_read_v3","d13_paid_original_read_v3","d13_derived_retirement_read_v3","current_method_learning_read_v3","current_life_numeric_read_v3","domain_background_read_v3", "host_beta1_fixture_evidence_read"} and error is None else None)
        if storage_payload and error is not None:_clear_storage_error_frames_v3(error)
        try:
            if self.kind == "current_graph_full_read_v3":
                from .runtime.current_graph_full_read_v3 import finish_current_graph_full_read_v3
                finish_current_graph_full_read_v3(coordinator,self,error)
            else:
                coordinator._finish_runtime_storage_work_v3(self, error)
        except BaseException as finish_error:
            if error is not None:
                finish_error.__cause__ = error
            value, error = None, finish_error
            if storage_payload:_clear_storage_error_frames_v3(error)
        self.terminal = True
        self.phase = "failed" if error is not None else "complete"
        if error is None and self.kind in {"current_world_source_read_v3","current_d07_source_read_v3","current_d07_simulation_source_read_v3"}:
            try:
                from .runtime.current_beta1_source_read_v3 import require_beta1_source_terminal_value_v3
                value=require_beta1_source_terminal_value_v3(value,self)
            except BaseException as result_error:
                value,error=None,result_error;self.phase="failed"
                _clear_storage_error_frames_v3(error)
        if error is None and self.kind == "current_method_learning_read_v3":
            try:
                value = value.require_business_result_v3(self)
            except BaseException as result_error:
                value, error = None, result_error
                self.phase = "failed"
                _clear_storage_error_frames_v3(error)
        if error is None and self.kind=="current_life_numeric_paid_write_v3":
            try:value=value.require_result_v3(self)
            except BaseException as result_error:
                value,error=None,result_error;self.phase="failed"
                _clear_storage_error_frames_v3(error)
        if error is None and self.kind=="current_life_numeric_read_v3":
            try:value=value.require_result_v3(self)
            except BaseException as result_error:
                value,error=None,result_error;self.phase="failed"
                _clear_storage_error_frames_v3(error)
        if (error is None and self.kind == 'domain_background_read_v3'
                and self.state.kind == 'semantic_recovery'):
            try:
                from .runtime.semantic_recovery_source_v3 import require_semantic_recovery_terminal_value_v3
                value = require_semantic_recovery_terminal_value_v3(value, self)
            except BaseException as result_error:
                value, error = None, result_error
                self.phase = 'failed'
                _clear_storage_error_frames_v3(error)
        mappers, self._mappers = self._mappers, []
        try:
            for _, success, failed in mappers:
                try:
                    value = success(value) if error is None else failed(error)
                    error = None
                except BaseException as mapped_error:
                    value, error = None, mapped_error
                    if storage_payload:_clear_storage_error_frames_v3(error)
        finally:
            mappers.clear()
            if self.kind == "owner_material_source_write_v3":
                self.state.input_witness = None
        if self._request_lifetime is not None:
            lifetime, self._request_lifetime = self._request_lifetime, None
            try:
                lifetime.close()
            except BaseException as close_error:
                if error is not None:
                    close_error.__cause__ = error
                value, error = None, close_error
                if storage_payload:_clear_storage_error_frames_v3(error)
        lease, self.result_lease = self.result_lease, None
        if error is not None:
            if lease is not None:
                try:
                    if release_payload is not None:release_payload()
                finally:
                    lease.release()
            raise error
        if lease is not None:
            return OwnedGraphStorageResultV3(_RESULT_ISSUER_V3, value, lease, release_payload)
        return value


def create_graph_storage_work_v3(coordinator, *, kind, operation_id,
                                 selection_digest, deadline_utc, state, operation):
    """Store an actual producer's fenced state without minting authority."""
    return GraphStorageWorkV3(_WORK_ISSUER_V3, coordinator, kind=kind,
        operation_id=operation_id, selection_digest=selection_digest,
        deadline_utc=deadline_utc, state=state, operation=operation)


class _GraphCallV3:
    __slots__ = ("function", "args", "outcome", "is_callback", "ticket", "context",
                 "started", "deliver", "work", "terminal", "delivery_abandoned",
                 "delivered_result")

    def __init__(self, function, args, outcome, *, is_callback, ticket):
        self.function, self.args, self.outcome = function, args, outcome
        self.is_callback, self.ticket, self.context = is_callback, ticket, copy_context()
        self.started = self.deliver = self.terminal = self.delivery_abandoned = False
        self.work = self.delivered_result = None


class _ExclusiveCallbackWindow:
    """A dispatcher-held lease spanning Authority handoff and its reverse call."""

    def __init__(self, worker: GraphWorker) -> None:
        self._worker = worker
        self._ready: Future = Future()
        self._ended: Future = Future()
        self._entered = self._ending = self._called = False
        self._watermark = 0

    async def __aenter__(self) -> _ExclusiveCallbackWindow:
        worker = self._worker
        with worker._lock:
            if self._entered or self._ending:
                raise RuntimeError("graph worker callback window lease already used")
            if worker._closed:
                raise RuntimeError("graph worker is closed")
            if worker._callback_window is not None:
                raise RuntimeError("graph worker callback window is active")
            self._watermark = worker._accepted_ticket
            worker._callback_window = self
            worker._queue.put_nowait((_WINDOW_READY, self))
        try:
            await asyncio.shield(asyncio.wrap_future(self._ready))
        except BaseException:
            self._end()
            raise
        self._entered = True
        return self

    async def call(self, function: Callable, *args):
        """One synchronous callback; it cannot create storage continuation work."""
        if not callable(function):
            raise TypeError("graph worker callback requires a callable")
        worker = self._worker
        with worker._lock:
            if worker._callback_window is not self or not self._entered or self._ending:
                raise RuntimeError("graph worker callback window is not open")
            if self._called:
                raise RuntimeError("graph worker callback already submitted")
            self._called = True
            call = _GraphCallV3(function, args, Future(), is_callback=True, ticket=None)
            worker._queue.put_nowait(call)
        return await worker._await_call(call)

    def _end(self) -> None:
        worker = self._worker
        with worker._lock:
            if not self._ending:
                if worker._callback_window is not self:
                    if self._ended.done():
                        return
                    raise RuntimeError("graph worker callback window is not open")
                self._ending = True
                worker._queue.put_nowait((_WINDOW_END, self))

    async def __aexit__(self, _exc_type, _exc, _tb) -> None:
        self._end()
        await asyncio.shield(asyncio.wrap_future(self._ended))


class GraphWorker:
    """One thread and bounded ordinary tickets own complete graph lifetimes.

    An ordinary function executes once. Its exact private GraphStorageWorkV3
    may advance one quantum per queue turn while retaining the same ticket,
    capacity slot, Future, request Context and actual producer retention lease.
    """

    def __init__(self, store_factory: Callable, coordinator_factory: Callable,
                 *, fence_port_factory: Callable | None = None, capacity: int = 8) -> None:
        if not callable(store_factory) or not callable(coordinator_factory):
            raise TypeError("graph worker requires store and coordinator factories")
        if fence_port_factory is not None and not callable(fence_port_factory):
            raise TypeError("graph worker fence port factory must be callable")
        if type(capacity) is not int or capacity < 1:
            raise ValueError("graph worker capacity must be a positive integer")
        self._store_factory, self._coordinator_factory = store_factory, coordinator_factory
        self._fence_port_factory = fence_port_factory
        self._slots = BoundedSemaphore(capacity)
        self._queue: Queue = Queue(maxsize=capacity + 2)
        self._lock = Lock()
        self._closed = self._stop_requested = False
        self._accepted_ticket = 0
        self._ordinary_calls = {}
        self._callback_call = None
        self._callback_window: _ExclusiveCallbackWindow | None = None
        self._pending_window = self._pending_window_end = None
        self._started: Future = Future()
        self._stopped: Future = Future()
        self._thread = Thread(target=self._run, name="sylanne-graph", daemon=True)

    @classmethod
    async def start(cls, store_factory: Callable, coordinator_factory: Callable,
                    *, fence_port_factory: Callable | None = None,
                    capacity: int = 8) -> GraphWorker:
        worker = cls(store_factory, coordinator_factory,
                     fence_port_factory=fence_port_factory, capacity=capacity)
        worker._thread.start()
        try:
            await asyncio.shield(asyncio.wrap_future(worker._started))
        except BaseException:
            try:
                await worker.close()
            except BaseException:
                pass
            raise
        return worker

    def _complete_call(self, call, value, error):
        abandoned = None
        with self._lock:
            call.terminal = True
            if not call.is_callback:
                del self._ordinary_calls[call.ticket]
                self._slots.release()
            else:
                self._callback_call = None
            if type(value) is OwnedGraphStorageResultV3:
                if call.delivery_abandoned or not call.deliver:
                    abandoned, value = value, None
                else:
                    call.delivered_result = value
        if abandoned is not None:
            try:
                abandoned.release_v3()
            except BaseException as release_error:
                error = release_error
        # No completed queue cell may cache request Context or producer state.
        call.function, call.args, call.context, call.work = None, (), None, None
        if call.deliver:
            if error is None:
                call.outcome.set_result(value)
            else:
                call.outcome.set_exception(error)

    def _step_call(self, call, coordinator):
        initial = not call.started
        if initial:
            call.started = True
            call.deliver = call.outcome.set_running_or_notify_cancel()
        token = _STORAGE_INVOCATION_V3.set(_GraphStorageInvocationV3(
            coordinator, call.ticket, "callback" if call.is_callback else "ordinary", initial))
        value = error = None
        try:
            try:
                if call.work is None:
                    value = call.function(coordinator, *call.args)
                    if type(value) is GraphStorageWorkV3:
                        if call.is_callback:
                            raise GraphStorageContinuationRequiredV3("callback cannot return graph storage work")
                        value._accept(coordinator, call.ticket)
                        call.work, value = value, None
                        self._queue.put_nowait(call)
                        return
                    if inspect.isawaitable(value):
                        if inspect.iscoroutine(value):
                            value.close()
                        raise TypeError("graph worker call must be synchronous")
                else:
                    step = call.work.advance(coordinator)
                    if step.status == "progress":
                        self._queue.put_nowait(call)
                        return
                    value = step.result

            except BaseException as call_error:
                value, error = None, call_error
            if call.work is not None:
                try:
                    value = call.work._finish_and_map(coordinator, value, error)
                    error = None
                except BaseException as terminal_error:
                    value, error = None, terminal_error
            self._complete_call(call, value, error)
        finally:
            _STORAGE_INVOCATION_V3.reset(token)

    def _pump_barriers(self):
        ready = ended = None
        with self._lock:
            window = self._pending_window
            if window is not None and not any(ticket <= window._watermark for ticket in self._ordinary_calls):
                ready, self._pending_window = window._ready, None
            window = self._pending_window_end
            if (window is not None and self._pending_window is None
                    and not any(ticket <= window._watermark for ticket in self._ordinary_calls)):
                self._pending_window_end = self._callback_window = None
                ended = window._ended
                if self._closed:
                    self._stop_requested = True
            stop = (self._stop_requested and not self._ordinary_calls
                    and self._callback_window is None and self._callback_call is None)
        if ready is not None:
            ready.set_result(None)
        if ended is not None:
            ended.set_result(None)
        return stop

    def _abort_calls(self, coordinator, failure):
        with self._lock:
            calls = list(self._ordinary_calls.values())
            if self._callback_call is not None:
                calls.append(self._callback_call)
        for call in calls:
            def abort():
                if not call.started:
                    call.started = True
                    call.deliver = call.outcome.set_running_or_notify_cancel()
                token = _STORAGE_INVOCATION_V3.set(_GraphStorageInvocationV3(
                    coordinator, call.ticket, "callback" if call.is_callback else "ordinary", False))
                error = failure
                try:
                    if call.work is not None and not call.work.terminal:
                        try:
                            discarded = call.work._finish_and_map(coordinator, None, failure)
                            if type(discarded) is OwnedGraphStorageResultV3:
                                discarded.release_v3()
                        except BaseException as terminal_error:
                            error = terminal_error
                    self._complete_call(call, None, error)
                finally:
                    _STORAGE_INVOCATION_V3.reset(token)
            call.context.run(abort)
        with self._lock:
            self._closed = True
            window = self._callback_window
            self._callback_window = self._pending_window = self._pending_window_end = None
        if window is not None:
            for outcome in (window._ready, window._ended):
                if not outcome.done():
                    outcome.set_exception(failure)

    def _run(self) -> None:
        store = fence_port = coordinator = None
        failure = None
        try:
            store = self._store_factory()
            if self._fence_port_factory is None:
                coordinator = self._coordinator_factory(store)
            else:
                fence_port = self._fence_port_factory()
                coordinator = self._coordinator_factory(store, fence_port)
            self._started.set_result(None)
            while True:
                item = self._queue.get()
                if item is _STOP:
                    self._stop_requested = True
                elif type(item) is _GraphCallV3:
                    if item.is_callback:
                        self._callback_call = item
                    item.context.run(self._step_call, item, coordinator)
                elif item[0] is _WINDOW_READY:
                    self._pending_window = item[1]
                elif item[0] is _WINDOW_END:
                    self._pending_window_end = item[1]
                if self._pump_barriers():
                    break
        except BaseException as exc:
            failure = exc
            self._abort_calls(coordinator, failure)
        finally:
            if fence_port is not None:
                try:
                    fence_port.close()
                except BaseException as exc:
                    if failure is None:
                        failure = exc
            if store is not None:
                try:
                    store.close()
                except BaseException as exc:
                    if failure is None:
                        failure = exc
            if not self._started.done():
                self._started.set_exception(failure)
            if failure is None:
                self._stopped.set_result(None)
            else:
                self._stopped.set_exception(failure)

    def _abandon_delivery(self, call):
        with self._lock:
            call.delivery_abandoned = True
            owned, call.delivered_result = call.delivered_result, None
        if owned is not None:
            owned.release_v3()

    async def _await_call(self, call):
        wrapped = asyncio.wrap_future(call.outcome)
        wrapped.add_done_callback(lambda done: done.exception() if not done.cancelled() else None)
        try:
            value = await asyncio.shield(wrapped)
        except asyncio.CancelledError:
            self._abandon_delivery(call)
            raise
        with self._lock:
            call.delivered_result = None
        return value

    async def call(self, function: Callable, *args):
        """Cancellation abandons delivery, never the accepted operation itself."""
        if not callable(function):
            raise TypeError("graph worker call requires a callable")
        with self._lock:
            if self._closed:
                raise RuntimeError("graph worker is closed")
            if self._callback_window is not None:
                raise RuntimeError("graph worker callback window is active")
            if not self._slots.acquire(blocking=False):
                raise CapacityExceeded("graph worker capacity exhausted")
            self._accepted_ticket += 1
            call = _GraphCallV3(function, args, Future(), is_callback=False, ticket=self._accepted_ticket)
            self._ordinary_calls[call.ticket] = call
            self._queue.put_nowait(call)
        return await self._await_call(call)

    def exclusive_callback_window(self) -> _ExclusiveCallbackWindow:
        """Wait for all tickets before the captured watermark to terminate."""
        return _ExclusiveCallbackWindow(self)

    async def close(self) -> None:
        """Stop admission and drain accepted continuations before closing stores."""
        with self._lock:
            if not self._closed:
                self._closed = True
                if self._callback_window is None:
                    self._queue.put_nowait(_STOP)
        try:
            await asyncio.shield(asyncio.wrap_future(self._stopped))
        finally:
            await asyncio.to_thread(self._thread.join)


__all__ = ("GraphWorker", "GraphStorageWorkV3", "GraphStorageStepV3",
    "GraphStorageContinuationRequiredV3", "OwnedGraphStorageResultV3",
    "require_graph_storage_work_admission_v3", "create_graph_storage_work_v3")


# A single engineering provider is bound to an actual protected fixture process.
# Ordinary runtime installations have no registration and cannot activate it.
from weakref import WeakKeyDictionary as _Beta1ProviderRegistryV3
_BETA1_ENGINEERING_METADATA_PROVIDERS_V3 = _Beta1ProviderRegistryV3()
_BETA1_ENGINEERING_METADATA_MODULE_V3 = "beta1_fixture_evidence_read_v3"
_BETA1_ENGINEERING_METADATA_PATH_V3 = "rewrite/tests/alpha1/integration/beta1_fixture_evidence_read_v3.py"


def _beta1_engineering_fixture_components_v3(graph,worker):
    from .authority_service.contract import AuthorityUnavailable
    from .host.authority_profile import (require_artifact_phase_fixture_qualification_v1,
        _require_beta1_fixture_bundle_identity_v3)
    from .runtime.d11_artifact_draft_model_v1 import InstalledArtifactDraftModelRuntimeV1
    runtime=graph._GraphCoordinator__artifact_draft_model_runtime_v1
    if type(runtime)is not InstalledArtifactDraftModelRuntimeV1 or type(worker)is not GraphWorker or worker._closed:
        raise AuthorityUnavailable("protected Beta1 engineering metadata provider is unavailable")
    qualification=require_artifact_phase_fixture_qualification_v1(runtime.bundle,client_grant=runtime.client_grant)
    _require_beta1_fixture_bundle_identity_v3(qualification)
    if (qualification.graph is not graph or qualification.worker is not worker
            or qualification.model_runtime is not runtime or runtime.worker is not worker):
        raise AuthorityUnavailable("Beta1 engineering metadata changed actual fixture components")
    return qualification


def _register_beta1_engineering_metadata_provider_v3(graph,worker,*,engineering_root,
        engineering_inventory_sha256,guard_sha256):
    import hashlib,importlib,json,os,stat,sys
    import importlib.util
    from pathlib import Path
    from .authority_service.contract import AuthorityUnavailable
    require_graph_storage_work_admission_v3(graph)
    qualification=_beta1_engineering_fixture_components_v3(graph,worker)
    root=Path(engineering_root).resolve(strict=True)
    if root!=Path(os.environ["SYLANNE_C09_TEST_ROOT"]).resolve(strict=True):
        raise AuthorityUnavailable("engineering metadata is outside the Root-approved frozen tree")
    inventory_path=root.parent/"frozen-engineering-inventory.json"
    origin=root/_BETA1_ENGINEERING_METADATA_PATH_V3
    guard=sys.modules.get("sitecustomize")
    guard_path=Path(os.environ["SYLANNE_C09_IMPORT_EVIDENCE"]).resolve(strict=True)/"sitecustomize.py"
    for target in (inventory_path,origin,guard_path):
        for entry in (target,*target.parents):
            info=entry.lstat()
            if entry.is_symlink()or info.st_uid!=0 or info.st_mode&0o022:
                raise AuthorityUnavailable("engineering metadata source/guard is not Root protected")
        if not stat.S_ISREG(target.stat().st_mode):
            raise AuthorityUnavailable("engineering metadata source/guard is not an actual file")
    inventory=json.loads(inventory_path.read_bytes())
    digest=hashlib.sha256(json.dumps(inventory["files"],sort_keys=True,separators=(",",":"),
        ensure_ascii=True,allow_nan=False).encode()).hexdigest()
    if (inventory["schema"]!="sylanne.engineering-source-inventory.v1"
            or inventory["sha256"]!=digest or digest!=engineering_inventory_sha256
            or digest!=os.environ["SYLANNE_C09_ENGINEERING_INVENTORY_SHA256"]
            or guard is None or Path(guard.__file__).resolve(strict=True)!=guard_path
            or hashlib.sha256(guard_path.read_bytes()).hexdigest()!=guard_sha256
            or guard_sha256!=os.environ["SYLANNE_C09_GUARD_SHA256"]):
        raise AuthorityUnavailable("Root engineering inventory/loaded guard identity differs")
    pins=[row for row in inventory["files"]if row["path"]==_BETA1_ENGINEERING_METADATA_PATH_V3]
    source=origin.read_bytes()
    if (len(pins)!=1 or pins[0]["sha256"]!=hashlib.sha256(source).hexdigest()
            or pins[0]["bytes"]!=len(source)):
        raise AuthorityUnavailable("fixed engineering metadata provider source differs")
    existing=sys.modules.get(_BETA1_ENGINEERING_METADATA_MODULE_V3)
    if existing is not None and Path(existing.__file__).resolve(strict=True)!=origin:
        raise AuthorityUnavailable("fixed engineering provider already loaded from another origin")
    spec=importlib.util.find_spec(_BETA1_ENGINEERING_METADATA_MODULE_V3)
    if spec is None or Path(spec.origin).resolve(strict=True)!=origin:
        raise AuthorityUnavailable("fixed engineering provider import origin differs before loading")
    module=importlib.import_module(_BETA1_ENGINEERING_METADATA_MODULE_V3)
    symbols=(module._Beta1FixtureEvidenceReadV3,module.prepare_current_beta1_fixture_evidence_read_v3,
        module.advance_current_beta1_fixture_evidence_read_v3,module.finish_current_beta1_fixture_evidence_read_v3)
    if (Path(module.__file__).resolve(strict=True)!=origin
            or any(symbol.__module__!=_BETA1_ENGINEERING_METADATA_MODULE_V3 for symbol in symbols)
            or any(Path(symbol.__code__.co_filename).resolve(strict=True)!=origin for symbol in symbols[1:])):
        raise AuthorityUnavailable("loaded fixed engineering metadata provider identity differs")
    record=(worker,qualification,module,origin,symbols,tuple(v.__code__ for v in symbols[1:]),digest,guard_sha256)
    previous=_BETA1_ENGINEERING_METADATA_PROVIDERS_V3.get(graph)
    if previous is not None and previous!=record:
        raise AuthorityUnavailable("this Graph already has another engineering metadata provider")
    _BETA1_ENGINEERING_METADATA_PROVIDERS_V3[graph]=record
    return None


def _require_beta1_engineering_metadata_provider_v3(graph,*,cleanup_only=False):
    import sys
    from pathlib import Path
    from .authority_service.contract import AuthorityUnavailable
    record=_BETA1_ENGINEERING_METADATA_PROVIDERS_V3.get(graph)
    if record is None:
        raise AuthorityUnavailable("Beta1 engineering metadata provider is not registered")
    worker,qualification,module,origin,symbols,codes,_,_=record
    if ((not cleanup_only and _beta1_engineering_fixture_components_v3(graph,worker)is not qualification)
            or sys.modules.get(_BETA1_ENGINEERING_METADATA_MODULE_V3)is not module
            or Path(module.__file__).resolve(strict=True)!=origin
            or (module._Beta1FixtureEvidenceReadV3,module.prepare_current_beta1_fixture_evidence_read_v3,
                module.advance_current_beta1_fixture_evidence_read_v3,module.finish_current_beta1_fixture_evidence_read_v3)!=symbols
            or tuple(v.__code__ for v in symbols[1:])!=codes):
        raise AuthorityUnavailable("registered engineering metadata provider identity changed")
    return module


def _unregister_beta1_engineering_metadata_provider_v3(graph,worker):
    record=_BETA1_ENGINEERING_METADATA_PROVIDERS_V3.get(graph)
    if record is not None:
        if record[0]is not worker:
            raise ValueError("engineering metadata unregister changed its actual worker")
        _BETA1_ENGINEERING_METADATA_PROVIDERS_V3.pop(graph)


def _advance_beta1_engineering_metadata_work_v3(graph,work):
    from .authority_service.contract import AuthorityUnavailable
    module=_require_beta1_engineering_metadata_provider_v3(graph)
    if work.kind!="host_beta1_fixture_evidence_read"or type(work.state)is not module._Beta1FixtureEvidenceReadV3:
        raise AuthorityUnavailable("unregistered engineering metadata Work type")
    return module.advance_current_beta1_fixture_evidence_read_v3(graph,work)


def _finish_beta1_engineering_metadata_work_v3(graph,work,error):
    from .authority_service.contract import AuthorityUnavailable
    def cleanup(original):
        module=_require_beta1_engineering_metadata_provider_v3(graph,cleanup_only=True)
        state=work.state
        if (work.kind!="host_beta1_fixture_evidence_read"or type(state)is not module._Beta1FixtureEvidenceReadV3
                or state.work is not work or state.graph is not graph or state.operation is not work.operation
                or module._READERS.get(state)!=state.identity_v3()or state.read_scope is not state.fence.scope):
            raise AuthorityUnavailable("engineering metadata cleanup changed original Work/fence")
        return module.finish_current_beta1_fixture_evidence_read_v3(graph,work,original)
    if error is not None:
        try:return cleanup(error)
        except BaseException as failure:
            raise BaseExceptionGroup("engineering metadata original failure and cleanup failure",[error,failure])
    try:
        _require_beta1_engineering_metadata_provider_v3(graph)
    except BaseException as failure:
        try:cleanup(failure)
        except BaseException as cleanup_failure:
            raise BaseExceptionGroup("engineering metadata final qualification and cleanup failure",[failure,cleanup_failure])
        raise
    return cleanup(None)
