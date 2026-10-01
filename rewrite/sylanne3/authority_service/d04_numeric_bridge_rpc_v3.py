"""Narrow paired installed numeric original/bridge/restore methods."""
from .contract import AuthorityUnavailable, identifier
from .d04_numeric_contract_v3 import D04NumericBindingV3,D04NumericClaimV3,D04NumericMeasurementV3,from_wire,to_wire
from .d04_numeric_claim_bridge_v3 import (D04NumericOriginalAppendV3,D04NumericAdoptionBridgeV3,
    numeric_bridge_from_wire_v3,numeric_bridge_to_wire_v3,numeric_restore_to_wire_v3)

METHODS=frozenset({"d04_numeric_original_append_v3","d04_numeric_adoption_bridge_v3",
    "d04_numeric_validate_gate_v3","d04_numeric_finish_adoption_v3","d04_numeric_restore_original_v3",
    "d04_numeric_cost_only_v3","d04_numeric_cost_inspect_v3","d04_numeric_gate_status_v3","d04_numeric_accounting_v3",
    "d04_numeric_restore_manifest_v3","d04_numeric_restore_chunk_v3"})


def dispatch_d04_numeric_bridge_v3(server,method,credential,profile_id,manifest_digest,command):
    if method not in METHODS:return None
    if type(command) is not dict:raise AuthorityUnavailable("numeric bridge command shape differs")
    expected={"namespace","binding"}
    if method=="d04_numeric_original_append_v3":expected.add("claim")
    if method=="d04_numeric_cost_only_v3":expected.update({"claim","measurement"})
    if method in {"d04_numeric_validate_gate_v3","d04_numeric_finish_adoption_v3","d04_numeric_gate_status_v3"}:expected.add("gate")
    if method=="d04_numeric_finish_adoption_v3":expected.add("outcome")
    if method=="d04_numeric_accounting_v3":expected.update({"action","gate"})
    if method=="d04_numeric_restore_chunk_v3":expected.update({"packet_digest","offset"})
    if set(command)!=expected:raise AuthorityUnavailable("numeric bridge command fields differ")
    namespace=identifier(command["namespace"],"namespace")
    server._bound_v2_service(credential,profile_id,manifest_digest,namespace)
    installation=server._installations_v2[(credential.certificate_sha256,profile_id)]
    service=server._d04_numeric_services_v3.get(namespace)
    binding=from_wire(command["binding"],D04NumericBindingV3)
    if (service is None or service.installation_id!=installation.installation_id
            or binding.installation_id!=installation.installation_id or binding.authority_namespace!=namespace):
        raise AuthorityUnavailable("numeric bridge paired installation differs")
    if method=="d04_numeric_restore_manifest_v3":
        from .d04_numeric_restore_stream_v3 import read_numeric_restore_manifest_v3
        return read_numeric_restore_manifest_v3(service,binding)
    if method=="d04_numeric_restore_chunk_v3":
        from .d04_numeric_restore_stream_v3 import read_numeric_restore_chunk_v3
        return read_numeric_restore_chunk_v3(service,binding,packet_digest=command["packet_digest"],offset=command["offset"])
    if method=="d04_numeric_accounting_v3":
        from .d04_numeric_accounting_v3 import operate_d04_numeric_accounting_v3,numeric_accounting_from_wire_v3,numeric_accounting_to_wire_v3
        gate=None if command["gate"] is None else numeric_accounting_from_wire_v3(command["gate"])
        result=operate_d04_numeric_accounting_v3(service,binding,command["action"],gate)
        return {"gate":numeric_accounting_to_wire_v3(result)} if command["action"]=="begin" else {"ok":result}
    if method=="d04_numeric_cost_inspect_v3":
        value=service.read_d04_numeric_measured_cost_closure_v3(binding)
        return {"cost_closure":None if value is None else to_wire(value)}
    if method=="d04_numeric_cost_only_v3":
        value=service.record_d04_numeric_measured_cost_closure_v3(binding,
            from_wire(command["claim"],D04NumericClaimV3),from_wire(command["measurement"],D04NumericMeasurementV3))
        return {"cost_closure":to_wire(value)}
    if method=="d04_numeric_original_append_v3":
        return {"gate":numeric_bridge_to_wire_v3(service.begin_d04_numeric_original_append_v3(binding,from_wire(command["claim"],D04NumericClaimV3)))}
    if method=="d04_numeric_adoption_bridge_v3":
        return {"gate":numeric_bridge_to_wire_v3(service.begin_d04_numeric_adoption_bridge_v3(binding))}
    if method=="d04_numeric_restore_original_v3":
        value=numeric_restore_to_wire_v3(service.read_d04_numeric_restore_original_v3(binding))
        from ..runtime_contracts import canonical_serialize
        if len(canonical_serialize(value).encode())>48*1024:
            raise AuthorityUnavailable("numeric restore requires bounded manifest/chunk transfer")
        return {"restore_original":value}
    raw=command["gate"]
    kind={"d04.numeric-original-append.v3":D04NumericOriginalAppendV3,
          "d04.numeric-adoption-bridge.v3":D04NumericAdoptionBridgeV3}.get(raw.get("schema") if type(raw) is dict else None)
    gate=numeric_bridge_from_wire_v3(raw,kind)
    if method=="d04_numeric_gate_status_v3":
        return {"state":service.read_d04_numeric_gate_state_v3(binding,gate)}
    if method=="d04_numeric_validate_gate_v3":
        return {"gate":numeric_bridge_to_wire_v3(service.validate_d04_numeric_gate_v3(binding,gate))}
    service.finish_d04_numeric_adoption_bridge_v3(binding,gate,outcome=command["outcome"])
    return {"finished":True}
