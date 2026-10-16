"""Private lifetime of a real Owner WRITE for Habit policy and LongWindow Source."""
from contextlib import contextmanager
from dataclasses import dataclass
from weakref import WeakKeyDictionary

from ..authority_service.contract import AuthorityUnavailable

_OWNER_WRITES_V3 = WeakKeyDictionary()


def _owner_habit_operations_v3():
    from .d10_habit_v1 import POLICY_OPERATIONS
    from .d08_long_term_plan_v1 import OPERATIONS
    return frozenset(POLICY_OPERATIONS) | frozenset(OPERATIONS)


@dataclass(frozen=True, slots=True)
class _FreshHabitOwnerWriteV3:
    graph: object
    reader: object
    inputs: object
    authority: object
    lease: object
    scope: object
    guard: object
    current_owner: object
    original_owner: object
    session_proof: object
    metadata: object
    epoch: object
    operation_id: str
    request_digest: str
    attempt_id: str

    @property
    def prepared(self): return self.inputs
    @property
    def issued(self): return self
    @property
    def owner_binding(self): return self.current_owner
    @property
    def owner_entry(self): return self
    def require_for_v3(self, reader):
        if reader is not self.reader:
            raise AuthorityUnavailable('Habit Owner WRITE belongs to another Source reader')
        require_current_habit_owner_write_v3(self.inputs, self.graph, self.scope, self.current_owner)
        return self.current_owner


@contextmanager
def observe_current_habit_owner_write_v3(graph, issuer, *, authority, lease, scope, guard,
        current_owner, original_owner, session_proof, metadata, epoch, operation_id,
        request_digest, attempt_id, background_original):
    from ..graph_coordinator import GraphCoordinator
    from .current_method_learning_read_v3 import (_method_active, PreparedMethodDomainInputsV3,
        _INPUTS)
    from .current_habit_source_read_v3 import HABIT_SOURCE_WORK_KIND_V3, is_habit_prepared_inputs_v3
    if type(graph) is not GraphCoordinator or issuer is not graph._GraphCoordinator__habit_owner_write_issuer_v3:
        raise AuthorityUnavailable('Habit Owner WRITE observer belongs to the actual W01 coordinator')
    db = graph._GraphCoordinator__store._db
    reader = _method_active(db)
    if reader is None or reader.work.kind != HABIT_SOURCE_WORK_KIND_V3:
        yield None
        return
    inputs = reader.result
    if (reader.operation_kind not in _owner_habit_operations_v3() or background_original is not None
            or type(inputs) is not PreparedMethodDomainInputsV3 or not is_habit_prepared_inputs_v3(inputs)
            or inputs not in _INPUTS or inputs.owner is not reader
            or reader.graph is not graph or reader.authority is not authority or reader.lease is not lease
            or reader.operation_id != operation_id or reader.request_digest != request_digest
            or not reader.read_finished or not reader.inputs_sealed or not reader.business_started
            or reader.business_completed or reader.operation.closed or reader in _OWNER_WRITES_V3
            or session_proof is None or inputs is not reader.result
            or scope.operation != 'write' or scope is inputs.read_scope
            or scope.operation_id != attempt_id or scope.permit.operation_id != attempt_id
            or graph._GraphCoordinator__owner_leases.get(lease) is not original_owner
            or graph._GraphCoordinator__owner_session_proofs.get(lease) != session_proof
            or reader.session_proof != session_proof
            or scope.namespace != reader.namespace or current_owner.namespace != reader.namespace
            or scope.graph_revision != metadata.graph_revision or scope.graph_epoch != epoch
            or inputs.graph_stamp != (metadata, epoch)
            or current_owner.actor != authority.actor or guard.authorization_head != current_owner.authorization_head):
        raise AuthorityUnavailable('Habit Owner Source did not enter its actual independent fresh WRITE')
    inputs._actual_v3()
    reader.work._require_invocation(graph)
    if db.in_transaction:
        raise AuthorityUnavailable('Habit Owner WRITE observation must precede W01 SQL')
    if graph._GraphCoordinator__content_fence_v2.validate_fence(scope) != scope.permit:
        raise AuthorityUnavailable('Habit Owner WRITE original permit changed')
    fact = _FreshHabitOwnerWriteV3(graph, reader, inputs, authority, lease, scope, guard,
        current_owner, original_owner, session_proof, metadata, epoch, operation_id, request_digest, attempt_id)
    _OWNER_WRITES_V3[reader] = fact
    try:
        yield fact
    finally:
        _OWNER_WRITES_V3.pop(reader, None)
        from .current_habit_source_read_v3 import release_habit_owner_write_phase_v3
        release_habit_owner_write_phase_v3(reader)


def require_current_habit_owner_write_v3(inputs, graph, scope, current_owner):
    from .current_method_learning_read_v3 import PreparedMethodDomainInputsV3, _INPUTS, _method_active
    if type(inputs) is not PreparedMethodDomainInputsV3 or inputs not in _INPUTS:
        raise AuthorityUnavailable('Habit Owner WRITE requires actual private Source inputs')
    reader = inputs.owner
    fact = _OWNER_WRITES_V3.get(reader)
    if (type(fact) is not _FreshHabitOwnerWriteV3 or fact.graph is not graph
            or fact.inputs is not inputs or fact.reader is not reader or fact.scope is not scope
            or fact.current_owner != current_owner or _method_active(reader.db) is not reader
            or graph._GraphCoordinator__owner_leases.get(fact.lease) is not fact.original_owner
            or graph._GraphCoordinator__owner_session_proofs.get(fact.lease) != fact.session_proof
            or reader.authority is not fact.authority or reader.lease is not fact.lease
            or reader.operation_id != fact.operation_id or reader.request_digest != fact.request_digest
            or reader.operation.closed or reader.work.state is not reader
            or reader.work.operation is not reader.operation or reader.work.coordinator is not graph
            or not reader.read_finished or not reader.inputs_sealed or not reader.business_started):
        raise AuthorityUnavailable('Habit Owner WRITE private Source/Scope lifetime ended or changed')
    inputs._actual_v3()
    reader.work._require_invocation(graph)
    return fact


def require_current_habit_owner_write_for_reader_v3(reader):
    fact = _OWNER_WRITES_V3.get(reader)
    if type(fact) is not _FreshHabitOwnerWriteV3:
        raise AuthorityUnavailable('Habit Owner Source has no actual active WRITE observer')
    return require_current_habit_owner_write_v3(fact.inputs, fact.graph, fact.scope, fact.current_owner)
