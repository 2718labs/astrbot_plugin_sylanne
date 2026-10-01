"""Closed mTLS DTOs and bounded cold terminal restore, without native calls."""
import base64
import hashlib
import json
from ..authority_service.d04_series_contract_v1 import (D04SeriesChunkBindingV1,
    D04SeriesClaimV1, D04SeriesTerminalV1, D04SeriesGateV1, from_wire, to_wire)
from ..authority_service.v2_contract import SCHEMA as AUTHORITY_V2_PROTOCOL


async def transport_d04_series_v1(transport, request, handshake, grant, *, namespace, binding, method, **values):
    if (type(binding) is not D04SeriesChunkBindingV1 or binding.numeric.authority_namespace != namespace
            or binding.numeric.installation_id != grant.installation_id or binding.numeric.authority_id != grant.authority_id):
        raise ValueError("series installed transport binding differs")
    async def rpc(name, extra):
        command = {"namespace": namespace, "binding": to_wire(binding), **extra}
        raw = await transport._content_rpc(request, handshake, name, command, protocol=AUTHORITY_V2_PROTOCOL)
        if type(raw) is not dict or raw.pop("channel_binding_sha256", None) != handshake.channel_binding_sha256:
            raise RuntimeError("series response channel differs")
        return raw
    if method == "d04_series_restore_v1":
        manifest = (await rpc("d04_series_restore_manifest_v1", {}))["manifest"]
        local_packet = values.get("local_packet")
        if local_packet is not None:
            if (type(local_packet) is not bytes or len(local_packet) != manifest["length"]
                    or hashlib.sha256(local_packet).hexdigest() != manifest["sha256"]):
                raise ValueError("series local packet differs from the current Authority manifest")
            packet = local_packet
        else:
            packet = bytearray()
            for offset in range(0, manifest["length"], manifest["chunk_bytes"]):
                part = (await rpc("d04_series_restore_chunk_v1", {"packet_digest": manifest["sha256"], "offset": offset}))["chunk"]
                data = base64.b64decode(part["data"], validate=True)
                if (part["offset"] != offset or part["sha256"] != manifest["sha256"]
                        or len(data) != min(manifest["chunk_bytes"], manifest["length"] - offset)):
                    raise ValueError("series restored packet range differs")
                packet.extend(data)
        if hashlib.sha256(packet).hexdigest() != manifest["sha256"]:
            raise ValueError("series restored packet commitment differs")
        raw = json.loads(packet)
        terminal = from_wire(raw["terminal"], D04SeriesTerminalV1)
        if terminal.binding != binding:
            raise ValueError("series restored terminal binding differs")
        return terminal, raw["math"]
    encoded = {name: to_wire(value) if name in {"claim", "measurement", "gate"} else value for name, value in values.items()}
    raw = await rpc(method, encoded)
    if method == "d04_series_prefix_manifest_v1":
        from ..runtime.d04_series_prefix_manifest_v1 import prefix_manifest_from_wire_v1
        if set(raw) != {"manifest"}:
            raise ValueError("series prefix response closed fields differ")
        return prefix_manifest_from_wire_v1(raw["manifest"], final_binding=binding)
    if method == "d04_series_inspect_v1":
        return tuple(None if raw[name] is None else from_wire(raw[name], kind)
            for name, kind in (("claim", D04SeriesClaimV1), ("terminal", D04SeriesTerminalV1)))
    if method in {"d04_series_finish_v1", "d04_series_abandon_v1"}:
        return raw["finished"] is True
    field, kind = (("claim", D04SeriesClaimV1) if method == "d04_series_claim_v1" else
        ("terminal", D04SeriesTerminalV1) if method == "d04_series_terminal_v1" else ("gate", D04SeriesGateV1))
    value = from_wire(raw[field], kind)
    if (value.binding_digest if field == "claim" else value.binding.digest) != binding.digest:
        raise ValueError("series actual returned original differs")
    return value
