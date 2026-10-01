"""Paired D04 series RPC; native transcripts use bounded packet transfer."""
import base64
import hashlib
from .contract import AuthorityUnavailable, identifier
from .d04_series_contract_v1 import (D04SeriesChunkBindingV1, D04SeriesClaimV1,
    D04SeriesMeasurementV1, D04SeriesGateV1, from_wire, to_wire)

METHODS = frozenset("d04_series_" + name + "_v1" for name in (
    "claim", "inspect", "terminal", "gate", "validate", "finish", "abandon", "restore_manifest", "restore_chunk", "prefix_manifest"))


def dispatch_d04_series_rpc_v1(server, method, credential, profile_id, manifest_digest, command):
    if method not in METHODS:
        return None
    fields = {"namespace", "binding"}
    if method == "d04_series_claim_v1": fields.add("executor_incarnation")
    if method == "d04_series_terminal_v1": fields.update({"claim", "measurement"})
    if method == "d04_series_gate_v1": fields.add("phase")
    if method in {"d04_series_validate_v1", "d04_series_finish_v1", "d04_series_abandon_v1"}: fields.add("gate")
    if method == "d04_series_restore_chunk_v1": fields.update({"packet_digest", "offset"})
    if type(command) is not dict or set(command) != fields:
        raise AuthorityUnavailable("series RPC closed fields differ")
    namespace = identifier(command["namespace"], "namespace")
    server._bound_v2_service(credential, profile_id, manifest_digest, namespace)
    installation = server._installations_v2[(credential.certificate_sha256, profile_id)]
    service = server._d04_series_services_v1.get(namespace)
    binding = from_wire(command["binding"], D04SeriesChunkBindingV1)
    if (service is None or service.installation_id != installation.installation_id
            or binding.numeric.installation_id != installation.installation_id or binding.numeric.authority_namespace != namespace):
        raise AuthorityUnavailable("series paired installation differs")
    if method == "d04_series_claim_v1":
        return {"claim": to_wire(service.claim(binding, command["executor_incarnation"]))}
    if method == "d04_series_inspect_v1":
        claim, terminal = service.inspect(binding)
        return {"claim": None if claim is None else to_wire(claim), "terminal": None if terminal is None else to_wire(terminal)}
    if method == "d04_series_terminal_v1":
        return {"terminal": to_wire(service.terminal(binding, from_wire(command["claim"], D04SeriesClaimV1),
            from_wire(command["measurement"], D04SeriesMeasurementV1)))}
    if method == "d04_series_gate_v1":
        return {"gate": to_wire(service.gate(binding, command["phase"]))}
    if method in {"d04_series_validate_v1", "d04_series_finish_v1", "d04_series_abandon_v1"}:
        gate = from_wire(command["gate"], D04SeriesGateV1)
        if gate.binding != binding:
            raise AuthorityUnavailable("series gate binding differs")
        if method.endswith("validate_v1"):
            return {"gate": to_wire(service.validate_gate(gate))}
        return {"finished": service.abandon(gate) if method.endswith("abandon_v1") else service.finish(gate)}
    if method == "d04_series_prefix_manifest_v1":
        from ..runtime.d04_series_prefix_manifest_v1 import prefix_manifest_to_wire_v1
        return {"manifest": prefix_manifest_to_wire_v1(service.restore_prefix_manifest(binding))}
    packet = service.restore_bytes(binding)
    digest = hashlib.sha256(packet).hexdigest()
    if method == "d04_series_restore_manifest_v1":
        return {"manifest": {"sha256": digest, "length": len(packet), "chunk_bytes": 24576}}
    offset = command["offset"]
    if command["packet_digest"] != digest or type(offset) is not int or not 0 <= offset < len(packet) or offset % 24576:
        raise AuthorityUnavailable("series restore packet/absolute offset differs")
    return {"chunk": {"sha256": digest, "offset": offset, "data": base64.b64encode(packet[offset:offset + 24576]).decode()}}
