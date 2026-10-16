"""Closed Core financial metadata grant; no model, Goal or Source body permission."""
from dataclasses import dataclass, fields, asdict
from uuid import UUID
from .contract import AuthorityUnavailable, identifier
from .v2_model_egress_contract import ModelEgressIntentV1
from .v2_owner_contract import OwnerMigrationHeadV1
from ..runtime.restore_anchor import RestoreAnchor
from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize

SIGN_KIND = "authority.artifact-no-dispatch-metadata.v1"
FINANCIAL_KINDS = ("c4_prepared","c4_phase_prepared","c4_call","c4_phase_call",
    "c4_no_dispatch","c4_phase_no_dispatch","original_model_quote","original_model_reservation",
    "original_model_budget_lease","original_model_cost","original_model_job","owner_goal_cancel_requested")


@dataclass(frozen=True, slots=True)
class ModelNoDispatchMetadataRequestV1:
    namespace: NamespaceId
    authority_namespace: str
    installation_id: str
    read_operation_id: str
    job_id: str | None
    after_call_id: str | None
    schema: str = "d11.artifact-no-dispatch-metadata-request.v1"

    def __post_init__(self):
        if type(self.namespace) is not NamespaceId or self.schema!="d11.artifact-no-dispatch-metadata-request.v1":
            raise ValueError("actual financial metadata request namespace/schema required")
        operation=UUID(self.read_operation_id)
        if operation.version!=4 or str(operation)!=self.read_operation_id or (self.job_id is None)==(self.after_call_id is None):
            raise ValueError("fixed point or cold cursor metadata request with original UUID4 required")
        identifier(self.authority_namespace,"authority_namespace");identifier(self.installation_id,"installation_id")
        if self.job_id is not None:identifier(self.job_id,"job_id")
        if self.after_call_id is not None and (type(self.after_call_id) is not str or len(self.after_call_id)>256):
            raise ValueError("bounded original call cursor required")

    @property
    def digest(self): return canonical_digest(asdict(self))


@dataclass(frozen=True, slots=True, eq=False, weakref_slot=True)
class ModelNoDispatchMetadataGrantV1:
    request: ModelNoDispatchMetadataRequestV1
    intent: ModelEgressIntentV1
    subject: str
    holder: str
    original_identity_digest: str
    current_anchor: RestoreAnchor
    current_owner_head: OwnerMigrationHeadV1
    selection_digest: str
    storage_manifest_digest: str
    storage_pointer_version: int
    storage_generation: int
    graph_incarnation: str
    core_registered_deadline_utc: float | None
    allowed_kinds: tuple[str, ...]
    signature: str
    schema: str = "d11.artifact-no-dispatch-metadata-grant.v1"

    def __post_init__(self):
        if (self.schema!="d11.artifact-no-dispatch-metadata-grant.v1"
                or type(self.request) is not ModelNoDispatchMetadataRequestV1
                or type(self.intent) is not ModelEgressIntentV1 or type(self.current_anchor) is not RestoreAnchor
                or type(self.current_owner_head) is not OwnerMigrationHeadV1
                or self.allowed_kinds!=FINANCIAL_KINDS or self.intent.subject!=self.subject
                or self.intent.namespace!=self.request.authority_namespace
                or self.current_anchor.namespace!=self.intent.namespace
                or self.current_anchor.authority_id!=self.intent.authority_id
                or self.current_owner_head.authority_namespace!=self.intent.namespace
                or self.current_owner_head.guard.namespace!=self.request.namespace
                or self.request.job_id is not None and self.request.job_id!=self.intent.job_id
                or self.request.after_call_id is not None and self.intent.call_id<=self.request.after_call_id):
            raise ValueError("actual original model financial metadata grant tuple differs")
        import math
        if self.core_registered_deadline_utc is not None and (
                type(self.core_registered_deadline_utc) not in (int,float)
                or not math.isfinite(self.core_registered_deadline_utc)):
            raise ValueError("actual registered metadata operation deadline required")
        for name in ("original_identity_digest","selection_digest","storage_manifest_digest"):
            value=getattr(self,name)
            if type(value) is not str or len(value)!=64 or any(c not in "0123456789abcdef" for c in value):
                raise ValueError("actual metadata original commitment required")
        if any(type(getattr(self,name)) is not int or getattr(self,name)<0 for name in
                ("storage_pointer_version","storage_generation")) or not self.signature:
            raise ValueError("actual selected storage metadata/producer signature required")

    @property
    def unsigned_wire(self):
        from .v2_model_egress_wire import to_wire as model_to_wire
        from .v2_owner_contract import to_wire as owner_to_wire
        raw=asdict(self);raw.pop("signature")
        raw["intent"]=model_to_wire(self.intent);raw["current_owner_head"]=owner_to_wire(self.current_owner_head)
        return raw

    @property
    def digest(self): return canonical_digest(self.unsigned_wire)

    def require_signature_v1(self, signer):
        signer.verify(SIGN_KIND,canonical_serialize(self.unsigned_wire),self.signature);return self


def to_wire_v1(value):
    if type(value) is ModelNoDispatchMetadataRequestV1:return asdict(value)
    if type(value) is ModelNoDispatchMetadataGrantV1:return {**value.unsigned_wire,"signature":value.signature}
    raise TypeError("closed Artifact financial metadata wire type required")


def from_wire_v1(raw, kind):
    from .v2_model_egress_wire import from_wire as model_from_wire
    from .v2_owner_contract import from_wire as owner_from_wire
    if kind not in {ModelNoDispatchMetadataRequestV1,ModelNoDispatchMetadataGrantV1} or type(raw) is not dict or set(raw)!={f.name for f in fields(kind)}:
        raise ValueError("closed Artifact metadata fields differ")
    data=dict(raw)
    if kind is ModelNoDispatchMetadataRequestV1:data["namespace"]=NamespaceId(**data["namespace"])
    else:
        data["request"]=from_wire_v1(data["request"],ModelNoDispatchMetadataRequestV1)
        data["intent"]=model_from_wire(data["intent"],ModelEgressIntentV1)
        data["current_anchor"]=RestoreAnchor(**data["current_anchor"])
        data["current_owner_head"]=owner_from_wire(data["current_owner_head"])
        data["allowed_kinds"]=tuple(data["allowed_kinds"])
    result=kind(**data)
    from ..domains.d01.production_operations_v1 import plain_v1
    if plain_v1(to_wire_v1(result))!=raw:raise ValueError("Artifact metadata exact wire roundtrip differs")
    return result
