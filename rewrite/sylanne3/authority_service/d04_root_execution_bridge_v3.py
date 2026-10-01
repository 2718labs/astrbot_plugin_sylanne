"""Dedicated authored-root gates; parsed DTOs are never authority evidence."""
from dataclasses import dataclass,asdict
import json
from ..runtime.restore_anchor import RestoreAnchor
from ..runtime_contracts import NamespaceId,SnapshotRequirementsV2,canonical_serialize
from .d04_root_execution_contract_v3 import (D04RootExecutionBindingV3,D04RootExecutionClaimV3,
    D04RootExecutionMeasurementV3,D04RootExecutionTerminalV3,root_execution_to_wire_v3,root_execution_from_wire_v3)
from .d12_target_owner_admission_v1 import D12CurrentOwnerAuthorityV1,target_admission_from_wire_v1
from .v2_owner_contract import to_wire as owner_to_wire,from_wire as owner_from_wire
from .v2_contract import FencePermitV2,to_wire as fence_to_wire,from_wire as fence_from_wire


def _common(value):
    for item in (value.prepared_digest,value.qualification_digest):
        if type(item) is not str or len(item)!=64 or any(c not in "0123456789abcdef" for c in item):raise ValueError("root bridge commitment differs")
    if type(value.before_graph_revision) is not int or value.before_graph_revision<0:raise ValueError("root old revision differs")
    raw=json.loads(value.before_requirements_json)
    if canonical_serialize(raw)!=value.before_requirements_json:raise ValueError("root old requirements noncanonical")
    raw["namespace"]=NamespaceId(**raw["namespace"]);requirements=SnapshotRequirementsV2(**raw)
    if (requirements.namespace!=value.binding.namespace or requirements.authority_id!=value.binding.authority_id
            or requirements.authority_namespace!=value.binding.authority_namespace
            or requirements.activation_generation!=value.binding.activation_generation
            or value.permit.namespace!=value.binding.authority_namespace or value.permit.generation!=value.binding.activation_generation):
        raise ValueError("root bridge namespace/generation differs")
    return requirements


@dataclass(frozen=True,slots=True)
class D04RootOriginalAppendV3:
    binding: D04RootExecutionBindingV3
    claim: D04RootExecutionClaimV3
    prepared_digest: str
    before_requirements_json: str
    before_graph_revision: int
    source_anchor: RestoreAnchor
    permit: FencePermitV2
    content_artifact_permitted: bool
    qualification_digest: str
    schema: str = "d04.authored-root-original-append.v3"

    def __post_init__(self):
        if (type(self.binding) is not D04RootExecutionBindingV3 or type(self.claim) is not D04RootExecutionClaimV3
                or self.claim.binding_digest!=self.binding.digest or type(self.permit) is not FencePermitV2
                or self.permit.operation!="accounting" or type(self.source_anchor) is not RestoreAnchor
                or type(self.content_artifact_permitted) is not bool or self.schema!="d04.authored-root-original-append.v3"):
            raise ValueError("dedicated actual root technical gate required")
        _common(self)


@dataclass(frozen=True,slots=True)
class D04RootAdoptionBridgeV3:
    binding: D04RootExecutionBindingV3
    terminal: D04RootExecutionTerminalV3
    owner_authority: D12CurrentOwnerAuthorityV1
    prepared_digest: str
    before_requirements_json: str
    before_graph_revision: int
    before_anchor: RestoreAnchor
    after_anchor: RestoreAnchor
    permit: FencePermitV2
    qualification_digest: str
    schema: str = "d04.authored-root-adoption-bridge.v3"

    def __post_init__(self):
        if (type(self.binding) is not D04RootExecutionBindingV3 or type(self.terminal) is not D04RootExecutionTerminalV3
                or self.terminal.binding!=self.binding or type(self.owner_authority) is not D12CurrentOwnerAuthorityV1
                or type(self.permit) is not FencePermitV2 or self.permit.operation!="write"
                or self.permit.pinned_anchor!=self.after_anchor or self.schema!="d04.authored-root-adoption-bridge.v3"
                or self.terminal.claim.claim_sequence!=self.before_anchor.execution_seq+1
                or self.terminal.terminal_sequence!=self.terminal.claim.claim_sequence+1
                or self.after_anchor.execution_seq!=self.terminal.terminal_sequence
                or self.after_anchor.execution_digest!="sha256:"+self.terminal.journal_head_digest):
            raise ValueError("root exact two-row current bridge required")
        _common(self)


@dataclass(frozen=True,slots=True)
class D04RootRestoreOriginalV3:
    prepared: object
    claim: D04RootExecutionClaimV3
    measurement: D04RootExecutionMeasurementV3
    artifact_payload: dict
    terminal: D04RootExecutionTerminalV3
    qualification_digest: str

    def __post_init__(self):
        from ..runtime.d04_root_execution_v3 import D04RootPreparedExecutionV3
        if (type(self.prepared) is not D04RootPreparedExecutionV3 or type(self.terminal) is not D04RootExecutionTerminalV3
                or self.prepared.binding!=self.terminal.binding or self.claim!=self.terminal.claim
                or self.measurement!=self.terminal.measurement or type(self.artifact_payload) is not dict):
            raise ValueError("root actual restore original identity differs")


def root_bridge_to_wire_v3(value):
    if type(value) not in {D04RootOriginalAppendV3,D04RootAdoptionBridgeV3}:raise TypeError("root typed gate required")
    raw=json.loads(canonical_serialize(asdict(value)));raw["permit"]=fence_to_wire(value.permit)
    if type(value) is D04RootAdoptionBridgeV3:
        from .d12_target_owner_admission_v1 import current_owner_authority_to_wire_v1
        raw["owner_authority"]=current_owner_authority_to_wire_v1(value.owner_authority)
    return raw


def root_bridge_from_wire_v3(raw,kind):
    if kind not in {D04RootOriginalAppendV3,D04RootAdoptionBridgeV3} or type(raw) is not dict or set(raw)!=set(kind.__dataclass_fields__):raise ValueError("root gate wire differs")
    value=dict(raw);value["binding"]=root_execution_from_wire_v3(value["binding"],D04RootExecutionBindingV3)
    value["permit"]=fence_from_wire(value["permit"])
    if kind is D04RootOriginalAppendV3:
        value["claim"]=root_execution_from_wire_v3(value["claim"],D04RootExecutionClaimV3);value["source_anchor"]=RestoreAnchor(**value["source_anchor"])
    else:
        value["terminal"]=root_execution_from_wire_v3(value["terminal"],D04RootExecutionTerminalV3)
        for name in ("before_anchor","after_anchor"):value[name]=RestoreAnchor(**value[name])
        from .d12_target_owner_admission_v1 import current_owner_authority_from_wire_v1
        value["owner_authority"]=current_owner_authority_from_wire_v1(value["owner_authority"])
    result=kind(**value)
    if root_bridge_to_wire_v3(result)!=raw:raise ValueError("noncanonical root gate")
    return result


def root_restore_to_wire_v3(value):
    if type(value) is not D04RootRestoreOriginalV3:raise TypeError("root actual restoration required")
    return json.loads(canonical_serialize(asdict(value)))


def root_restore_from_wire_v3(raw):
    from ..runtime.d04_root_execution_v3 import D04RootPreparedExecutionV3
    if type(raw) is not dict or set(raw)!=set(D04RootRestoreOriginalV3.__dataclass_fields__):raise ValueError("root restore wire differs")
    value=dict(raw);prepared=dict(value["prepared"]);prepared["binding"]=root_execution_from_wire_v3(prepared["binding"],D04RootExecutionBindingV3)
    value["prepared"]=D04RootPreparedExecutionV3(**prepared)
    for name,kind in (("claim",D04RootExecutionClaimV3),("measurement",D04RootExecutionMeasurementV3),("terminal",D04RootExecutionTerminalV3)):
        value[name]=root_execution_from_wire_v3(value[name],kind)
    result=D04RootRestoreOriginalV3(**value)
    if root_restore_to_wire_v3(result)!=raw:raise ValueError("noncanonical root restore")
    return result
