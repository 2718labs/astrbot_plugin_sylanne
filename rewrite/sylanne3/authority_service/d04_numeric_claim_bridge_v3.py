"""Typed installed numeric journal transitions; DTO parsing grants no authority."""
from dataclasses import asdict, dataclass
import json

from ..runtime.restore_anchor import RestoreAnchor
from ..runtime_contracts import canonical_digest, canonical_serialize, NamespaceId, SnapshotRequirementsV2
from .d04_numeric_contract_v3 import D04NumericBindingV3, D04NumericClaimV3, D04NumericTerminalV3, from_wire, to_wire
from .d12_target_owner_admission_v1 import D12CurrentOwnerAuthorityV1, target_admission_from_wire_v1
from .v2_owner_contract import from_wire as owner_from_wire, to_wire as owner_to_wire
from .v2_contract import FencePermitV2, from_wire as fence_from_wire, to_wire as fence_to_wire


def _common_bridge(value):
    for item in (value.prepared_digest,value.qualification_digest):
        if type(item) is not str or len(item)!=64 or any(c not in "0123456789abcdef" for c in item):
            raise ValueError("numeric bridge commitment must be exact SHA256")
    if type(value.before_graph_revision) is not int or value.before_graph_revision<0:
        raise ValueError("numeric bridge old Graph revision must be exact nonnegative integer")
    raw=json.loads(value.before_requirements_json)
    if canonical_serialize(raw)!=value.before_requirements_json:
        raise ValueError("numeric bridge Graph requirements must be canonical")
    raw["namespace"]=NamespaceId(**raw["namespace"])
    before=SnapshotRequirementsV2(**raw)
    if (before.namespace!=value.binding.namespace or before.authority_id!=value.binding.authority_id
            or before.authority_namespace!=value.binding.authority_namespace
            or before.activation_generation!=value.binding.activation_generation
            or value.permit.authority_id!=value.binding.authority_id
            or value.permit.namespace!=value.binding.authority_namespace
            or value.permit.generation!=value.binding.activation_generation):
        raise ValueError("numeric bridge Graph/Authority installation differs")
    return before


@dataclass(frozen=True, slots=True)
class D04NumericOriginalAppendV3:
    binding: D04NumericBindingV3
    claim: D04NumericClaimV3
    prepared_digest: str
    before_requirements_json: str
    before_graph_revision: int
    source_anchor: RestoreAnchor
    permit: FencePermitV2
    content_artifact_permitted: bool
    qualification_digest: str
    schema: str = "d04.numeric-original-append.v3"

    def __post_init__(self):
        if (type(self.binding) is not D04NumericBindingV3 or type(self.claim) is not D04NumericClaimV3
                or type(self.source_anchor) is not RestoreAnchor or type(self.permit) is not FencePermitV2
                or self.schema != "d04.numeric-original-append.v3" or self.permit.operation != "accounting"
                or self.claim.binding_digest != self.binding.digest or type(self.content_artifact_permitted) is not bool):
            raise ValueError("typed numeric technical-original gate differs")
        _common_bridge(self)


@dataclass(frozen=True, slots=True)
class D04NumericAdoptionBridgeV3:
    binding: D04NumericBindingV3
    terminal: D04NumericTerminalV3
    owner_authority: D12CurrentOwnerAuthorityV1
    prepared_digest: str
    before_requirements_json: str
    before_graph_revision: int
    before_anchor: RestoreAnchor
    after_anchor: RestoreAnchor
    permit: FencePermitV2
    qualification_digest: str
    schema: str = "d04.numeric-adoption-bridge.v3"

    def __post_init__(self):
        if (type(self.binding) is not D04NumericBindingV3 or type(self.terminal) is not D04NumericTerminalV3
                or self.terminal.binding != self.binding or type(self.owner_authority) is not D12CurrentOwnerAuthorityV1
                or type(self.before_anchor) is not RestoreAnchor
                or type(self.after_anchor) is not RestoreAnchor or type(self.permit) is not FencePermitV2
                or self.permit.operation != "write" or self.permit.pinned_anchor != self.after_anchor
                or self.schema != "d04.numeric-adoption-bridge.v3"
                or self.terminal.claim.claim_sequence != self.before_anchor.execution_seq+1
                or self.terminal.terminal_sequence != self.terminal.claim.claim_sequence+1
                or self.after_anchor.execution_seq != self.terminal.terminal_sequence):
            raise ValueError("exact own two-row numeric bridge differs")
        before=_common_bridge(self)
        if (self.owner_authority.guard.namespace!=self.binding.namespace
                or self.after_anchor.execution_digest!="sha256:"+self.terminal.journal_head_digest
                or any(getattr(before,key)!=getattr(self.before_anchor,key) for key in (
                    "authority_id","activation_generation","revocation_epoch","deletion_journal_id",
                    "deletion_seq","deletion_digest","execution_journal_id","execution_seq","execution_digest"))):
            raise ValueError("numeric bridge exact source/target journal heads differ")


@dataclass(frozen=True, slots=True)
class D04NumericRestoreOriginalV3:
    terminal: D04NumericTerminalV3
    prepared: object
    artifact_payload: dict
    artifact_json: str
    qualification_digest: str

    def __post_init__(self):
        from ..runtime.d04_numeric_cost_v3 import D04NumericPreparedV3
        if (type(self.terminal) is not D04NumericTerminalV3 or type(self.prepared) is not D04NumericPreparedV3
                or self.prepared.binding!=self.terminal.binding or type(self.artifact_payload) is not dict
                or canonical_serialize(self.artifact_payload)!=self.artifact_json
                or type(self.qualification_digest) is not str or len(self.qualification_digest)!=64
                or any(c not in "0123456789abcdef" for c in self.qualification_digest)):
            raise ValueError("numeric restored original shape/identity differs")


def numeric_bridge_to_wire_v3(value):
    if type(value) not in {D04NumericOriginalAppendV3,D04NumericAdoptionBridgeV3}:
        raise TypeError("typed numeric bridge required")
    raw=json.loads(canonical_serialize(asdict(value)))
    raw["binding"]=to_wire(value.binding)
    raw["permit"]=fence_to_wire(value.permit)
    if type(value) is D04NumericOriginalAppendV3:raw["claim"]=to_wire(value.claim)
    else:
        raw["terminal"]=to_wire(value.terminal)
        from .d12_target_owner_admission_v1 import current_owner_authority_to_wire_v1
        raw["owner_authority"]=current_owner_authority_to_wire_v1(value.owner_authority)
    return raw


def numeric_bridge_from_wire_v3(raw, kind):
    if kind not in {D04NumericOriginalAppendV3,D04NumericAdoptionBridgeV3} or type(raw) is not dict or set(raw)!=set(kind.__dataclass_fields__):
        raise ValueError("numeric bridge wire fields differ")
    values=dict(raw);values["binding"]=from_wire(values["binding"],D04NumericBindingV3)
    values["permit"]=fence_from_wire(values["permit"])
    if kind is D04NumericOriginalAppendV3:
        values["claim"]=from_wire(values["claim"],D04NumericClaimV3)
        values["source_anchor"]=RestoreAnchor(**values["source_anchor"])
    else:
        values["terminal"]=from_wire(values["terminal"],D04NumericTerminalV3)
        from .d12_target_owner_admission_v1 import current_owner_authority_from_wire_v1
        values["owner_authority"]=current_owner_authority_from_wire_v1(values["owner_authority"])
        for name in ("before_anchor","after_anchor"):values[name]=RestoreAnchor(**values[name])
    value=kind(**values)
    if numeric_bridge_to_wire_v3(value)!=raw:raise ValueError("noncanonical numeric bridge")
    return value


def numeric_gate_operation_id_v3(binding, phase):
    if phase not in {"claim","original","adoption","restore"}:raise ValueError("unknown numeric gate phase")
    return "d04-numeric-gate:"+phase+":"+canonical_digest((binding.authority_namespace,binding.installation_id,binding.execution_id))


def numeric_restore_to_wire_v3(value):
    if type(value) is not D04NumericRestoreOriginalV3:raise TypeError("numeric restore original required")
    return {"terminal":to_wire(value.terminal),"prepared":json.loads(canonical_serialize(asdict(value.prepared))),
        "artifact_payload":value.artifact_payload,"artifact_json":value.artifact_json,"qualification_digest":value.qualification_digest}


def numeric_restore_from_wire_v3(raw):
    from ..runtime.d04_numeric_cost_v3 import D04NumericPreparedV3
    if type(raw) is not dict or set(raw)!=set(D04NumericRestoreOriginalV3.__dataclass_fields__):raise ValueError("numeric restore fields differ")
    prepared=dict(raw["prepared"]);prepared["binding"]=from_wire(prepared["binding"],D04NumericBindingV3)
    value=D04NumericRestoreOriginalV3(from_wire(raw["terminal"],D04NumericTerminalV3),D04NumericPreparedV3(**prepared),
        raw["artifact_payload"],raw["artifact_json"],raw["qualification_digest"])
    if numeric_restore_to_wire_v3(value)!=raw or canonical_serialize(value.artifact_payload)!=value.artifact_json:
        raise ValueError("numeric restore original is noncanonical")
    return value
