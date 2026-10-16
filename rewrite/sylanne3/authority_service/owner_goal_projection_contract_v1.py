"""Signed metadata observation for a fixed cold Goal cancellation projection."""
from dataclasses import dataclass,asdict,fields
from .contract import AuthorityUnavailable
from .owner_goal_cancellation_contract_v1 import OwnerGoalCancellationOriginalV1,GoalCancellationMetadataV1,owner_goal_cancellation_from_wire_v1
from .v2_contract import FencePermitV2
from .v2_owner_contract import OwnerMigrationHeadV1
from ..runtime_contracts import canonical_digest,canonical_serialize
from ..runtime.restore_anchor import RestoreAnchor

SIGN_KIND="authority.owner-goal-projection-observed.v1"


@dataclass(frozen=True,slots=True)
class GoalProjectionCommittedBridgeV1:
    operation_id: str
    request_digest: str
    permit_digest: str
    before_graph_revision: int
    before_graph_epoch: int
    after_graph_revision: int
    after_graph_epoch: int
    observation_digest: str
    before_metadata_json: str
    before_epoch_json: str
    after_metadata_json: str
    after_epoch_json: str
    receipt_json: str
    receipt_digest: str
    receipt_signature: str
    event_digest: str
    row_digest: str
    attempt_digest: str
    selection_digest: str
    current_owner_observation_digest: str
    schema: str="d08.owner-goal-projection-committed-bridge.v1"
    def __post_init__(self):
        import json
        from ..runtime.owner_goal_projection_v1 import decode_goal_projection_receipt_v1
        receipt=decode_goal_projection_receipt_v1(json.loads(self.receipt_json))
        if (self.schema!="d08.owner-goal-projection-committed-bridge.v1"
                or canonical_serialize(asdict(receipt))!=self.receipt_json
                or (receipt.operation_id,receipt.request_digest,receipt.permit_digest,receipt.digest,
                    receipt.before_graph_revision,receipt.before_graph_epoch,receipt.after_graph_revision,
                    receipt.after_graph_epoch,receipt.observation_digest,receipt.event_digest)!=(
                    self.operation_id,self.request_digest,self.permit_digest,self.receipt_digest,
                    self.before_graph_revision,self.before_graph_epoch,self.after_graph_revision,
                    self.after_graph_epoch,self.observation_digest,self.event_digest)):
            raise ValueError("exact same-operation W01 committed Goal bridge differs")
        if (receipt.before_metadata_json,receipt.before_epoch_json,receipt.after_metadata_json,receipt.after_epoch_json)!=(
                self.before_metadata_json,self.before_epoch_json,self.after_metadata_json,self.after_epoch_json):
            raise ValueError("Goal bridge changed its actual complete before/after metadata stamp")
    def require_local_signature_v1(self,issuer,original):
        from ..runtime.owner_goal_projection_v1 import SIGN_KIND as receipt_kind
        if self.operation_id!=goal_projection_operation_id_v1(original):
            raise AuthorityUnavailable("Goal committed bridge retargeted the original metadata operation")
        issuer._signer.verify(receipt_kind,canonical_serialize((original.request.namespace,
            self.operation_id,self.observation_digest,self.receipt_digest)),self.receipt_signature)
        return self

@dataclass(frozen=True,slots=True)
class OwnerGoalProjectionObservedV1:
    scope_kind: str
    committed_bridge: GoalProjectionCommittedBridgeV1 | None
    original: OwnerGoalCancellationOriginalV1
    metadata: GoalCancellationMetadataV1
    permit: FencePermitV2
    owner_head: OwnerMigrationHeadV1
    owner_grant_ref: str
    owner_grant_revision: int
    owner_grant_digest: str
    current_anchor: RestoreAnchor
    storage_manifest_digest: str
    storage_pointer_version: int
    storage_generation: int
    graph_incarnation: str
    registered_deadline_utc: float | None
    signature: str
    schema: str="d08.owner-goal-projection-observed.v1"

    def __post_init__(self):
        if (type(self.original) is not OwnerGoalCancellationOriginalV1
                or type(self.metadata) is not GoalCancellationMetadataV1
                or type(self.permit) is not FencePermitV2
                or self.scope_kind not in {"projection_write","projection_lookup"}
                or self.permit.operation!={"projection_write":"write","projection_lookup":"read"}[self.scope_kind]
                or type(self.owner_head) is not OwnerMigrationHeadV1
                or self.schema!="d08.owner-goal-projection-observed.v1"
                or self.permit.namespace!=self.original.request.authority_namespace
                or self.current_anchor!=self.permit.pinned_anchor
                or self.owner_head.guard.namespace!=self.original.request.namespace
                or self.owner_grant_ref!=self.original.owner_grant_ref or self.owner_grant_revision<1):
            raise ValueError("actual fixed Goal projection WRITE/current Owner metadata tuple required")
        self.metadata.require_request_v1(self.original.request)
        if self.committed_bridge is not None:
            if self.scope_kind!="projection_write" or type(self.committed_bridge) is not GoalProjectionCommittedBridgeV1:
                raise ValueError("only the held original WRITE can carry a committed W01 bridge")
    @property
    def unsigned_wire(self):
        from .v2_contract import to_wire as fence_to_wire
        from .v2_owner_contract import to_wire as owner_to_wire
        value=asdict(self);value.pop("signature")
        value["permit"]=fence_to_wire(self.permit)
        value["owner_head"]=owner_to_wire(self.owner_head)
        return value
    @property
    def digest(self):return canonical_digest(self.unsigned_wire)
    def require_signature_v1(self,issuer):
        issuer._signer.verify(SIGN_KIND,canonical_serialize(self.unsigned_wire),self.signature);return self


def goal_projection_to_wire_v1(value):
    if type(value) is not OwnerGoalProjectionObservedV1:raise TypeError("exact Goal projection observation required")
    return {**value.unsigned_wire,"signature":value.signature}


def goal_projection_from_wire_v1(raw):
    from .v2_contract import from_wire as fence_from_wire
    from .v2_owner_contract import from_wire as owner_from_wire
    if type(raw) is not dict or set(raw)!={f.name for f in fields(OwnerGoalProjectionObservedV1)}:
        raise ValueError("closed Goal projection observation fields differ")
    value=dict(raw)
    if value["committed_bridge"] is not None:
        bridge=value["committed_bridge"]
        if type(bridge) is not dict or set(bridge)!={f.name for f in fields(GoalProjectionCommittedBridgeV1)}:
            raise ValueError("closed committed Goal bridge wire differs")
        value["committed_bridge"]=GoalProjectionCommittedBridgeV1(**bridge)
    value["original"]=owner_goal_cancellation_from_wire_v1(value["original"],OwnerGoalCancellationOriginalV1)
    value["metadata"]=owner_goal_cancellation_from_wire_v1(value["metadata"],GoalCancellationMetadataV1)
    value["permit"]=fence_from_wire(value["permit"])
    value["owner_head"]=owner_from_wire(value["owner_head"])
    value["current_anchor"]=RestoreAnchor(**value["current_anchor"])
    result=OwnerGoalProjectionObservedV1(**value)
    from ..domains.d01.production_operations_v1 import plain_v1
    if plain_v1(goal_projection_to_wire_v1(result))!=raw:
        raise ValueError("Goal projection observation exact wire roundtrip differs")
    return result

def goal_projection_operation_id_v1(original):
    if type(original) is not OwnerGoalCancellationOriginalV1:
        raise TypeError("actual signed Goal cancellation cause required")
    return "goal-cancel-projection:"+canonical_digest((original.request.namespace,original.original_ref,original.digest))[:48]


def require_goal_projection_operation_v1(original,permit):
    if permit.operation=="write" and permit.operation_id==goal_projection_operation_id_v1(original):
        return "projection_write"
    prefix="goal-projection-lookup:"+canonical_digest((original.request.namespace,original.original_ref,original.digest))[:32]+":"
    if (permit.operation=="read" and permit.operation_id.startswith(prefix)
            and len(permit.operation_id)==len(prefix)+32
            and all(ch in "0123456789abcdef" for ch in permit.operation_id[len(prefix):])):
        return "projection_lookup"
    raise AuthorityUnavailable("Goal metadata call changed its actual fixed projection/lookup operation")


def goal_projection_lookup_operation_id_v1(original):
    from uuid import uuid4
    if type(original) is not OwnerGoalCancellationOriginalV1:
        raise TypeError("actual signed stable Goal cancellation cause required")
    return "goal-projection-lookup:"+canonical_digest((original.request.namespace,original.original_ref,original.digest))[:32]+":"+uuid4().hex
