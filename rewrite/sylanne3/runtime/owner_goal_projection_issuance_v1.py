"""Private paired Goal metadata projection observation under the actual WRITE."""
from contextlib import contextmanager
from dataclasses import dataclass
from weakref import WeakKeyDictionary
from ..runtime_contracts import FenceScope
from ..authority_service.owner_goal_projection_contract_v1 import (
    OwnerGoalProjectionObservedV1,goal_projection_operation_id_v1)
from ..authority_service.contract import AuthorityUnavailable

_KEY=object()
_ACTIVE=WeakKeyDictionary()
_SUCCESSORS=WeakKeyDictionary()


@dataclass(frozen=True,slots=True,eq=False,weakref_slot=True)
class GoalProjectionReceiptSuccessorViewV1:
    issued: object
    graph_stamp: tuple
    bridge: object
    _issuer: object
    def require_current_v1(self,issued):
        from dataclasses import asdict
        from ..runtime_contracts import canonical_serialize
        if (_SUCCESSORS.get(self)!=(issued,self.graph_stamp,self.bridge) or self.issued is not issued
                or self._issuer is not _KEY or issued not in _ACTIVE):
            raise AuthorityUnavailable("Goal receipt view is not its actual privately verified original successor")
        with issued.graph._GraphCoordinator__store._lock:
            stamp=issued.graph._v2_graph_stamp(issued.scope.namespace)
        if stamp!=self.graph_stamp or (canonical_serialize(asdict(stamp[0])),canonical_serialize(asdict(stamp[1])))!=(
                self.bridge.after_metadata_json,self.bridge.after_epoch_json):
            raise AuthorityUnavailable("Goal receipt successor metadata changed")
        if issued.retained_operation.closed:raise AuthorityUnavailable("Goal receipt successor original operation ended")
        return self



@dataclass(frozen=True,slots=True,eq=False,weakref_slot=True)
class IssuedOwnerGoalProjectionV1:
    graph: object
    scope: FenceScope
    observation: OwnerGoalProjectionObservedV1
    _issuer: object
    retained_operation: object

    @property
    def successor_view(self):
        entry=_ACTIVE.get(self)
        return None if entry is True else entry

    def _runtime_retained_heap_bytes_v3(self):
        import sys
        from .artifact_no_dispatch_metadata_invocation_v1 import _actual_metadata_heap_v1
        seen={id(self)}
        amount=sys.getsizeof(self)+_actual_metadata_heap_v1(self.observation,seen)
        view=self.successor_view
        if view is not None:
            amount+=sys.getsizeof(view)+_actual_metadata_heap_v1(view.graph_stamp,seen)
            amount+=_actual_metadata_heap_v1(view.bridge,seen)
        return amount


@contextmanager
def owner_goal_projection_for_fence_v1(graph,*,scope,cancel_operation_id,original_ref):
    from ..graph_coordinator import GraphCoordinator
    from ..host.v2_fence_port import V2FencePort
    if type(graph) is not GraphCoordinator or type(scope) is not FenceScope or scope.operation not in {"read","write"}:
        raise TypeError("actual installed Graph independent Goal WRITE scope required")
    db=graph._GraphCoordinator__store._db;port=graph._GraphCoordinator__content_fence_v2
    if db.in_transaction or type(port) is not V2FencePort:
        raise AuthorityUnavailable("Goal projection observation must precede Graph SQL")
    observed=port.observe_current_owner_goal_cancellation_projection_v1(scope=scope,
        cancel_operation_id=cancel_operation_id,original_ref=original_ref)
    observed.require_signature_v1(graph._GraphCoordinator__d11_issuer)
    bridge=observed.committed_bridge
    if (observed.permit!=scope.permit or scope.operation!={"projection_write":"write","projection_lookup":"read"}[observed.scope_kind]):
        raise AuthorityUnavailable("Goal metadata observation changed its original actual permit")
    with graph._GraphCoordinator__store._lock:
        metadata,epoch=graph._v2_graph_stamp(scope.namespace)
    if not graph._anchor_matches(metadata.requirements,scope.pinned_anchor):
        raise AuthorityUnavailable("Goal metadata requires actual current Graph/Core recovery")
    if bridge is None:
        if (metadata.graph_revision!=scope.graph_revision or epoch!=scope.graph_epoch
                or observed.scope_kind=="projection_write" and (observed.metadata.graph_revision!=scope.graph_revision
                    or observed.metadata.graph_epoch!=scope.graph_epoch.revision)):
            raise AuthorityUnavailable("Goal metadata changed before its actual current snapshot")
    else:
        from dataclasses import asdict
        from ..runtime_contracts import canonical_serialize,canonical_digest
        from ..authority_service.v2_contract import to_wire
        bridge.require_local_signature_v1(graph._GraphCoordinator__d11_issuer,observed.original)
        if (scope.operation!="write" or bridge.operation_id!=scope.operation_id
                or bridge.permit_digest!=canonical_digest(to_wire(scope.permit))
                or (scope.graph_revision,scope.graph_epoch.revision)!=(bridge.before_graph_revision,bridge.before_graph_epoch)
                or (canonical_serialize(asdict(metadata)),canonical_serialize(asdict(epoch)))!=(
                    bridge.after_metadata_json,bridge.after_epoch_json)
                or bridge.current_owner_observation_digest!=canonical_digest((asdict(observed.owner_head),
                    observed.owner_grant_ref,observed.owner_grant_revision,observed.owner_grant_digest))
                or bridge.selection_digest!=observed.metadata.selection_digest):
            raise AuthorityUnavailable("Goal receipt has no exact held original WRITE committed successor")
        permit,state=port.get_fence_operation(namespace=scope.namespace,authority_namespace=scope.authority_namespace,
            operation_id=scope.operation_id)
        if state!="active" or permit!=scope.permit:
            raise AuthorityUnavailable("Goal receipt successor requires the actual still-active original WRITE")
    from ..runtime_storage_v3 import _operation
    operation=_operation(db)
    if operation is None or operation.closed or operation.operation_id!=scope.operation_id:
        raise AuthorityUnavailable("Goal projection needs its actual retained metadata operation")
    issued=IssuedOwnerGoalProjectionV1(graph,scope,observed,_KEY,operation)
    operation.register_retained_state_v3(issued)
    _ACTIVE[issued]=True
    if bridge is not None:
        view=GoalProjectionReceiptSuccessorViewV1(issued,(metadata,epoch),bridge,_KEY)
        _SUCCESSORS[view]=(issued,(metadata,epoch),bridge)
        _ACTIVE[issued]=view
    try:yield issued
    finally:
        view=issued.successor_view
        if view is not None:_SUCCESSORS.pop(view,None)
        _ACTIVE.pop(issued,None)
        operation.unregister_retained_state_v3(issued)


def require_owner_goal_projection_v1(issued,graph,scope):
    if (type(issued) is not IssuedOwnerGoalProjectionV1 or issued._issuer is not _KEY
            or issued not in _ACTIVE or issued.graph is not graph or issued.scope is not scope):
        raise AuthorityUnavailable("actual paired live Goal metadata projection handle required")
    return issued.observation


def reobserve_owner_goal_projection_v1(issued):
    observed=require_owner_goal_projection_v1(issued,issued.graph,issued.scope)
    if issued.graph._GraphCoordinator__store._db.in_transaction:
        raise AuthorityUnavailable("Goal projection reobservation must precede Graph SQL")
    current=issued.graph._GraphCoordinator__content_fence_v2.observe_current_owner_goal_cancellation_projection_v1(
        scope=issued.scope,cancel_operation_id=observed.original.request.cancel_operation_id,
        original_ref=observed.original.original_ref)
    current.require_signature_v1(issued.graph._GraphCoordinator__d11_issuer)
    if current!=observed:
        raise AuthorityUnavailable("Goal projection key/Owner/metadata/WRITE changed")
    return current
