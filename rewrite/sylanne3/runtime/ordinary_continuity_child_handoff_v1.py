"""One actual ordinary-continuity child and its retained parent ownership."""
from contextlib import ExitStack
from secrets import token_bytes
from threading import Lock, get_ident

_LIVE = {}
_BY_ISSUED = {}


def _prepared_payload_v1(callback, prepared):
    from .domain_background_read_v3 import PreparedBackgroundOperationV3
    return (getattr(callback, '__self__', None) is prepared
        and getattr(callback, '__func__', None) is PreparedBackgroundOperationV3.release_payload_v3)


class _OrdinaryChildHandoffV1:
    def __init__(self, graph, parent, prepared, issued, deadline):
        self.graph, self.parent, self.prepared, self.issued = graph, parent, prepared, issued
        self.command, self.request, self.authority = issued.command, issued.command.request, issued.authority
        self.deadline, self.ticket, self.selection = deadline, parent.ticket, parent.selection_digest
        self.locator, self.thread, self.lock = token_bytes(32), get_ident(), Lock()
        self.handoff = self.child = self.holder = self.original_lifetime = None
        self.started = self.closed = self.lifetime_installed = False
        self.first_error = None
        parent.operation.register_retained_state_v3(self)
        _LIVE[self.locator] = self
        _BY_ISSUED[id(issued)] = self

    def _runtime_retained_heap_bytes_v3(self):
        # The retained actual parent already accounts for prepared/command material.
        return len(self.locator) * 2 + 8192

    def require_identity_v1(self, graph):
        if (_LIVE.get(self.locator) is not self or self.closed or self.graph is not graph
                or self.thread != get_ident() or self.parent.coordinator is not graph
                or self.parent.ticket != self.ticket or self.parent.selection_digest != self.selection
                or self.parent.operation is not self.prepared.operation
                or self.parent.state is not self.prepared.owner
                or self.parent.operation.closed or self.issued.command is not self.command
                or self.command.request is not self.request or self.issued.authority is not self.authority):
            raise RuntimeError('ordinary child lost its actual retained parent/issuer identity')
        self.prepared.require_v3(graph)
        return self

    def remember_error_v1(self, error):
        with self.lock:
            if self.first_error is None:
                self.first_error = error

    def complete_v1(self, result):
        try:
            from ..runtime_contracts import canonical_digest
            from .domain_production_originals_v1 import _receipt
            from .domain_background_read_v3 import background_followup_progress_v3
            self.require_identity_v1(self.graph)
            self.child._require_invocation(self.graph)
            if (not self.child.terminal or not self.child._finish_called or self.child.phase != 'complete'
                    or type(result) is not dict or result.get('schema') != 'sylanne.domain-production-receipt.v1'
                    or result.get('operation_id') != self.issued.operation_id
                    or result.get('operation_kind') != self.command.operation_kind):
                raise RuntimeError('ordinary child did not return its actual completed formal business result')
            receipt = _receipt(result['receipt'])
            if receipt.status != 'committed' or canonical_digest(receipt) != result['receipt_digest']:
                raise RuntimeError('ordinary child result has no actual committed receipt')
            if self.command.operation_kind == 'serve_concern':
                service = self.graph._GraphCoordinator__d07_execution_service_v1
                for job_id, phase in result.get('job_states', ()):
                    if phase == 'queued':
                        service.wake_committed_job_v1(job_id)
            return background_followup_progress_v3('child_completed', result, None)

        except BaseException as first:
            self.remember_error_v1(first)
            raise

    def failed_v1(self, error):
        self.remember_error_v1(error)
        raise error

    def close_v1(self):
        with self.lock:
            if self.closed:
                return
            self.closed = True
            first = self.first_error
            issued, holder, lifetime = self.issued, self.holder, self.original_lifetime
            parent = self.parent
            self.holder = self.original_lifetime = None
            _LIVE.pop(self.locator, None)
            _BY_ISSUED.pop(id(issued), None)
        from .domain_followup_consumer_v1 import release_actual_ordinary_continuity_child_v1
        actions = [('issuer', lambda: release_actual_ordinary_continuity_child_v1(issued)),
            ('handoff metadata', lambda: parent.operation.unregister_retained_state_v3(self))]
        if holder is not None:
            actions.append(('parent payload and lease', holder.release))
        if lifetime is not None:
            actions.append(('original request lifetime', lifetime.close))
        try:
            for label, action in actions:
                try:
                    action()
                except BaseException as later:
                    if first is None:
                        first = later
                    else:
                        first.add_note('ordinary child cleanup ' + label + ' failed: ' + type(later).__name__)
        finally:
            self.graph = self.parent = self.prepared = self.issued = self.command = None
            self.request = self.authority = self.handoff = self.child = None
        if first is not None and first is not self.first_error:
            raise first


def issue_ordinary_continuity_child_handoff_v1(graph, *, parent, prepared, issued):
    from ..graph_worker import GraphStorageWorkV3
    from ..graph_storage_handoff_v3 import issue_graph_storage_handoff_v3
    from .domain_background_read_v3 import PreparedBackgroundOperationV3
    from .domain_followup_consumer_v1 import (require_actual_ordinary_continuity_child_origin_v1,
        actual_ordinary_continuity_child_deadline_v1)
    from .first_ingress_v2 import trusted_upper
    if type(parent) is not GraphStorageWorkV3 or type(prepared) is not PreparedBackgroundOperationV3:
        raise TypeError('actual terminal ordinary Background preparation and Work required')
    parent._require_invocation(graph)
    if (prepared.owner.work is not parent or prepared.operation is not parent.operation
            or prepared.owner.kind != 'followup_child' or prepared.owner.fence is not None
            or not parent.terminal or not parent._finish_called or parent.phase != 'complete'
            or prepared.db.in_transaction or prepared.owner.store._lock._is_owned()
            or require_actual_ordinary_continuity_child_origin_v1(issued, graph) is not prepared):
        raise RuntimeError('ordinary handoff must follow actual child issuance outside Graph SQL')
    deadline = min(parent.deadline_utc, actual_ordinary_continuity_child_deadline_v1(issued, graph))
    now = trusted_upper(graph._GraphCoordinator__content_fence_v2.read_ingress_clock(
        graph._GraphCoordinator__scene_clock_policy))
    if id(issued) in _BY_ISSUED:
        raise RuntimeError('actual ordinary child issuer already has its once-only handoff')
    record = _OrdinaryChildHandoffV1(graph, parent, prepared, issued, deadline)
    try:
        handoff = issue_graph_storage_handoff_v3(parent, factory=_start_ordinary_continuity_child_v1,
            command=record.locator, deadline_utc=deadline, observed_utc=now)
        record.handoff = handoff
        return handoff
    except BaseException as first:
        record.remember_error_v1(first)
        record.close_v1()
        raise


def actual_ordinary_continuity_child_handoff_deadline_v1(issued, graph):
    from ..graph_worker import _STORAGE_INVOCATION_V3
    record = _BY_ISSUED.get(id(issued))
    if record is None or record.issued is not issued:
        raise RuntimeError('ordinary child has no actual retained handoff deadline')
    record.require_identity_v1(graph)
    invocation = _STORAGE_INVOCATION_V3.get()
    if (not record.started or invocation is None or not invocation.initial or invocation.mode != 'ordinary'
            or invocation.coordinator is not graph or invocation.ticket != record.ticket):
        raise RuntimeError('ordinary child deadline left its actual initial factory invocation')
    return record.deadline


def _start_ordinary_continuity_child_v1(graph, locator):
    from ..graph_worker import (GraphStorageWorkV3, OwnedGraphStorageResultV3,
        _STORAGE_INVOCATION_V3)
    record = _LIVE.get(locator)
    if record is None or type(locator) is not bytes or record.locator is not locator:
        raise RuntimeError('ordinary child locator is absent or already consumed')
    record.require_identity_v1(graph)
    invocation = _STORAGE_INVOCATION_V3.get()
    if (invocation is None or not invocation.initial or invocation.mode != 'ordinary' or invocation.coordinator is not graph
            or invocation.ticket != record.ticket or not record.lifetime_installed):
        raise RuntimeError('ordinary child requires its actual initial handoff invocation')
    with record.lock:
        if record.started:
            raise RuntimeError('ordinary child locator was already consumed')
        record.started = True
    child = None
    try:
        runtime = graph._GraphCoordinator__domain_production_runtime_v1
        command = record.command
        child = runtime.run_current(record.authority, None, operation_kind=command.operation_kind,
            request=record.request, operation_id=record.issued.operation_id,
            activity_id=command.activity_id, audience_ref=command.audience_ref,
            parent_budget_lease_ref=record.issued.parent_budget, _background_followup=record.issued)
        if (type(child) is not GraphStorageWorkV3 or child.kind != 'current_method_learning_read_v3'
                or child.coordinator is not graph or child.ticket != record.ticket or child.terminal
                or child.operation is record.parent.operation or child.deadline_utc > record.deadline
                or child.state.background_followup is not record.issued
                or child.state.request is not record.request or child.state.authority is not record.authority):
            raise RuntimeError('ordinary child is not its actual independent current Method Work')
        record.child = child
        return child.map_terminal_v3('issuer', record.complete_v1, record.failed_v1)
    except BaseException as first:
        record.remember_error_v1(first)
        if (type(child) is GraphStorageWorkV3 and child.coordinator is graph
                and child.ticket == record.ticket and not child.terminal):
            try:
                discarded = child._finish_and_map(graph, None, first)
                if type(discarded) is OwnedGraphStorageResultV3:
                    discarded.release_v3()
            except BaseException as later:
                if later is not first:
                    first.add_note('ordinary child factory cleanup failed: ' + type(later).__name__)
        raise


def _record_v1(handoff):
    record = _LIVE.get(handoff.command)
    return record if record is not None and record.handoff is handoff else None


def install_ordinary_continuity_child_lifetime_v1(handoff, parent):
    record = _record_v1(handoff)
    if record is None:
        return False
    record.require_identity_v1(parent.coordinator)
    if record.parent is not parent or record.lifetime_installed or handoff.lifetime is not None:
        raise RuntimeError('ordinary parent lifetime was already transferred')
    lifetime = ExitStack()
    record.original_lifetime, parent._request_lifetime = parent._request_lifetime, None
    record.lifetime_installed = True
    lifetime.callback(record.close_v1)
    handoff.lifetime = lifetime
    return True


def retain_ordinary_continuity_parent_holder_v1(handoff, holder, *, child=None, error=None):
    record = _record_v1(handoff)
    if record is None:
        return False
    own = (holder is record.parent.operation and not holder.closed
        and _prepared_payload_v1(holder._payload_release, record.prepared))
    if not own:
        if error is None:
            raise RuntimeError('ordinary handoff cannot transfer another result payload/lease')
        record.remember_error_v1(error)
        return False
    if error is None and (child is not record.child or child.coordinator is not record.graph
            or child.ticket != record.ticket or child.kind != 'current_method_learning_read_v3'):
        raise RuntimeError('ordinary parent retention has no exact independent child')
    if error is not None:
        record.remember_error_v1(error)
    with record.lock:
        if record.holder is not None or record.closed:
            raise RuntimeError('ordinary parent result ownership was already transferred')
        record.holder = holder
    return True


def retain_invalid_ordinary_continuity_parent_v1(handoff, coordinator, call, value, error):
    from ..graph_worker import OwnedGraphStorageResultV3
    record = _record_v1(handoff)
    if record is None:
        return False
    record.remember_error_v1(error)
    if (record.graph is not coordinator or record.parent is not call.work or record.ticket != call.ticket
            or type(value) is not OwnedGraphStorageResultV3 or value._value is not handoff
            or value._lease is not record.parent.operation
            or not (_prepared_payload_v1(value._release_payload, record.prepared)
                or value._release_payload is None and
                    _prepared_payload_v1(value._lease._payload_release, record.prepared))):
        return False
    actual, holder = value.take_value_v3()
    if actual is not handoff:
        raise RuntimeError('ordinary invalid result ownership changed during its actual transfer')
    return retain_ordinary_continuity_parent_holder_v1(handoff, holder, error=error)
