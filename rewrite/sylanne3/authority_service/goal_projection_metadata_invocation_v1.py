"""Private Goal projection WRITE or duplicate lookup READ call."""
from dataclasses import dataclass
from threading import get_ident
from weakref import WeakSet,WeakKeyDictionary
from .contract import AuthorityUnavailable
from .v2_contract import FencePermitV2
from .owner_goal_cancellation_contract_v1 import OwnerGoalCancellationOriginalV1
from ..runtime_storage_v3 import runtime_storage_v3,RuntimeStorageOperationV3

_ISSUER=object()
_LIVE=WeakSet()
_COMMITTED_BRIDGES=WeakKeyDictionary()


@dataclass(frozen=True,slots=True,eq=False,weakref_slot=True)
class GoalProjectionMetadataInvocationV1:
    service: object
    original: OwnerGoalCancellationOriginalV1
    credential: object
    subject: str
    original_permit: FencePermitV2
    session_request: object
    principal: object
    current_owner_guard: object
    current_owner_head: object
    current_anchor: object
    active_originals_commitment: str
    storage_context: object
    selected_graph_member: object
    selection_digest: str
    actual_db: object
    retained_operation: object
    thread_id: int
    _issuer: object

    def __post_init__(self):
        if self._issuer is not _ISSUER:raise AuthorityUnavailable("actual independent Goal projection issuer required")
        _LIVE.add(self)
        self.retained_operation.register_retained_state_v3(self)

    def _runtime_retained_heap_bytes_v3(self):
        import sys
        from ..runtime.artifact_no_dispatch_metadata_invocation_v1 import _actual_metadata_heap_v1
        seen={id(self)}
        amount=sys.getsizeof(self)
        for name in ("original","subject","original_permit","session_request","principal","current_owner_guard",
                "current_owner_head","current_anchor","active_originals_commitment","selected_graph_member",
                "selection_digest","thread_id"):
            amount+=_actual_metadata_heap_v1(getattr(self,name),seen)
        return amount

    @property
    def committed_bridge(self):
        entry=_COMMITTED_BRIDGES.get(self)
        return None if entry is None else entry[0]
    @property
    def scope_kind(self):
        from .owner_goal_projection_contract_v1 import require_goal_projection_operation_v1
        return require_goal_projection_operation_v1(self.original,self.original_permit)
    @property
    def scope(self):return self.original_permit
    @property
    def current_owner_authority(self):return None
    @property
    def original_request(self):return self.original.request
    @property
    def request_digest(self):return self.original.request.digest
    @property
    def namespace(self):return self.original.request.namespace
    @property
    def authority_namespace(self):return self.original.request.authority_namespace
    @property
    def installation_id(self):return self.original.request.installation_id
    @property
    def holder(self):return self.original_permit.holder
    @property
    def owner_service(self):return self.service.owner_service
    @property
    def status_service(self):return self.service.status_service
    @property
    def core(self):return self.service.core
    @property
    def fences(self):return self.service.fences
    @property
    def control(self):return self.service.control
    @property
    def issuer(self):return self.service.issuer
    @property
    def bundle(self):return self.service.bundle
    @property
    def manifest_digest(self):return self.service.manifest_digest
    @property
    def actor(self):return self.original.actor_id
    @property
    def operation_id(self):return self.original_permit.operation_id
    @property
    def metadata_operation_id(self):return self.operation_id
    @property
    def registered_deadline_utc(self):return self.retained_operation.deadline_utc
    @property
    def graph_path(self):return self.selected_graph_member["resolved_path"]
    @property
    def kind(self):return "goal_projection_metadata"

    def require_current_v1(self,*,phase,graph_stamp=None):
        from .owner_goal_cancellation_v1 import InstalledOwnerGoalCancellationServiceV1
        if (self not in _LIVE or self._issuer is not _ISSUER or phase not in {"before","after"}
                or type(self.service) is not InstalledOwnerGoalCancellationServiceV1
                or type(self.original) is not OwnerGoalCancellationOriginalV1
                or self.original.state!="cancel_requested" or type(self.original_permit) is not FencePermitV2
                or self.original_permit.operation not in {"read","write"} or self.original_permit.subject!=self.subject
                or self.original_permit.namespace!=self.authority_namespace
                or self.thread_id!=get_ident() or type(self.retained_operation) is not RuntimeStorageOperationV3
                or self.retained_operation.closed or self.retained_operation.operation_id!=self.operation_id
                or runtime_storage_v3(self.actual_db).selection_digest!=self.selection_digest):
            raise AuthorityUnavailable("cold Goal projection lost its actual independent WRITE call")
        if self.original_permit.operation!={"projection_write":"write","projection_lookup":"read"}[self.scope_kind]:
            raise AuthorityUnavailable("Goal metadata private scope kind changed its original permit")
        if self.actual_db.in_transaction:
            if graph_stamp is not None:self.service.require_current_goal_metadata_stamp_v1(self,graph_stamp)
            return self
        self.storage_context.require_current("business")
        self.service.require_projection_metadata_permission_v1(self)
        if graph_stamp is not None:self.service.require_current_goal_metadata_stamp_v1(self,graph_stamp)
        return self

    def release_v1(self):
        self.retained_operation.unregister_retained_state_v3(self)
        _LIVE.discard(self)
        _COMMITTED_BRIDGES.pop(self,None)


def issue_goal_projection_metadata_invocation_v1(issuer,**fields):
    if issuer is not _ISSUER:raise AuthorityUnavailable("actual Goal projection issuer required")
    return GoalProjectionMetadataInvocationV1(**fields,_issuer=issuer)


def require_goal_projection_metadata_invocation_v1(invocation,*,phase,graph_stamp=None):
    if type(invocation) is not GoalProjectionMetadataInvocationV1:
        raise AuthorityUnavailable("actual private Goal projection metadata invocation required")
    return invocation.require_current_v1(phase=phase,graph_stamp=graph_stamp)


def issue_goal_projection_committed_bridge_v1(invocation,work):
    from ..runtime.owner_goal_projection_receipt_read_v1 import GoalProjectionReceiptReadWorkV1
    from .owner_goal_projection_contract_v1 import GoalProjectionCommittedBridgeV1
    require_goal_projection_metadata_invocation_v1(invocation,phase="after")
    if (type(work) is not GoalProjectionReceiptReadWorkV1 or work.core_invocation is not invocation
            or not work.complete or work.closed or type(work.result) is not GoalProjectionCommittedBridgeV1):
        raise AuthorityUnavailable("actual same-Invocation complete W01 bridge EOF required")
    bridge=work.require_result()
    bridge.require_local_signature_v1(invocation.issuer,invocation.original)
    _COMMITTED_BRIDGES[invocation]=(bridge,work)
    return bridge

def require_goal_projection_committed_bridge_v1(invocation,*,graph_stamp=None):
    require_goal_projection_metadata_invocation_v1(invocation,phase="after")
    entry=_COMMITTED_BRIDGES.get(invocation)
    if entry is None:return None
    bridge,work=entry
    if work.core_invocation is not invocation or work.closed or work.require_result() is not bridge:
        raise AuthorityUnavailable("Goal W01 bridge lost its actual private complete same-call Work")
    if graph_stamp is not None:
        from dataclasses import asdict
        from ..runtime_contracts import canonical_serialize
        metadata,epoch=graph_stamp
        if (canonical_serialize(asdict(metadata)),canonical_serialize(asdict(epoch)))!=(
                bridge.after_metadata_json,bridge.after_epoch_json):
            raise AuthorityUnavailable("Goal W01 successor differs from its actual complete after metadata stamp")
    return bridge
