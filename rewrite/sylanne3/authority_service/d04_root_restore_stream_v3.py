"""Bounded stateless restoration frames over the existing 64 KiB mTLS profile.

Each frame repeats actual current content qualification. No partial packet is a
trusted result, and no retained server payload cache adds a C09 erasure surface.
"""
import base64
from hashlib import sha256
import json

from ..runtime_contracts import canonical_serialize,canonical_digest
from .contract import AuthorityUnavailable
from .d04_root_execution_bridge_v3 import D04RootRestoreOriginalV3,root_restore_to_wire_v3,root_restore_from_wire_v3

RESTORE_PACKET_MAX_BYTES_V3=32*1024*1024
RESTORE_CHUNK_BYTES_V3=24*1024
MANIFEST_METHOD="d04_root_restore_manifest_v3"
CHUNK_METHOD="d04_root_restore_chunk_v3"


def _qualified_packet(service,binding,*,light=False):
    from .d04_root_execution_service_v3 import AuthorityD04RootExecutionServiceV3
    if type(service) is not AuthorityD04RootExecutionServiceV3:raise AuthorityUnavailable("actual root restoration service required")
    original=service.read_d04_root_restore_original_v3(binding)
    if type(original) is not D04RootRestoreOriginalV3:raise AuthorityUnavailable("actual qualified restore original absent")
    wire=root_restore_to_wire_v3(original)
    # The artifact canonical JSON duplicates the complete payload; the Host
    # reconstructs it only after complete authenticated packet assembly. The
    # per-read current qualification changes with each real transient permit.
    packet=canonical_serialize({key:wire[key] for key in ("terminal","prepared","claim","measurement","artifact_payload")}).encode()
    if len(packet)>RESTORE_PACKET_MAX_BYTES_V3:raise AuthorityUnavailable("root restore packet exceeds installed 32 MiB bound")
    return original.qualification_digest,packet,sha256(packet).hexdigest()


def read_root_restore_manifest_v3(service,binding):
    qualification,packet,commitment=_qualified_packet(service,binding)
    return {"packet_digest":commitment,"packet_bytes":len(packet),"chunk_bytes":RESTORE_CHUNK_BYTES_V3,
        "qualification_digest":qualification}


def read_root_restore_chunk_v3(service,binding,*,packet_digest,offset):
    if (type(packet_digest) is not str or len(packet_digest)!=64 or any(c not in "0123456789abcdef" for c in packet_digest)
            or type(offset) is not int or offset<0 or offset%RESTORE_CHUNK_BYTES_V3 or offset>=RESTORE_PACKET_MAX_BYTES_V3):
        raise AuthorityUnavailable("exact bounded root restore packet offset required")
    qualification,packet,commitment=_qualified_packet(service,binding,light=True)
    if commitment!=packet_digest or offset>=len(packet):raise AuthorityUnavailable("root restore packet changed or offset is absent")
    chunk=packet[offset:offset+RESTORE_CHUNK_BYTES_V3]
    return {"packet_digest":commitment,"offset":offset,"chunk_base64":base64.b64encode(chunk).decode("ascii"),
        "chunk_digest":sha256(chunk).hexdigest(),"end":offset+len(chunk)==len(packet),
        "qualification_digest":qualification}


async def read_root_restore_stream_v3(transport,request,handshake,*,namespace,binding,installation_grant):
    from .d04_root_execution_contract_v3 import root_execution_to_wire_v3 as to_wire
    from .v2_contract import SCHEMA
    command={"namespace":namespace,"binding":to_wire(binding)}
    from dataclasses import asdict
    import time
    paired_at=time.monotonic()
    expected_identity=asdict(installation_grant);expected_identity.pop("channel_binding_sha256")
    async def rpc(method,command):
        nonlocal handshake,paired_at
        # Authority sessions have a fixed 30-second lifetime. Long bounded
        # packets renew real pairing before expiry; every frame still rechecks
        # current source/Owner rights and the immutable full-packet commitment.
        if time.monotonic()-paired_at>=10:
            renewed=await transport.handshake(request,protocol=SCHEMA)
            current=await transport.installation_grant_v2(request,renewed)
            stable=asdict(current);stable.pop("channel_binding_sha256")
            if stable!=expected_identity:raise RuntimeError("restoration re-pairing changed installed identity")
            handshake=renewed;paired_at=time.monotonic()
        return await transport._content_rpc(request,handshake,method,command,protocol=SCHEMA)
    response=await rpc(MANIFEST_METHOD,command)
    if (type(response) is not dict or set(response)!={"packet_digest","packet_bytes","chunk_bytes","qualification_digest","channel_binding_sha256"}
            or response["channel_binding_sha256"]!=handshake.channel_binding_sha256
            or type(response["packet_bytes"]) is not int or not 0<response["packet_bytes"]<=RESTORE_PACKET_MAX_BYTES_V3
            or response["chunk_bytes"]!=RESTORE_CHUNK_BYTES_V3
            or type(response["packet_digest"]) is not str or len(response["packet_digest"])!=64):
        raise RuntimeError("root restoration manifest is not a bounded current original")
    packet_digest,total=response["packet_digest"],response["packet_bytes"]
    pieces=[];qualifications=[response["qualification_digest"]];offset=0
    while offset<total:
        part=await rpc(CHUNK_METHOD,{**command,"packet_digest":packet_digest,"offset":offset})
        if (type(part) is not dict or set(part)!={"packet_digest","offset","chunk_base64","chunk_digest","end","qualification_digest","channel_binding_sha256"}
                or part["channel_binding_sha256"]!=handshake.channel_binding_sha256
                or part["packet_digest"]!=packet_digest or part["offset"]!=offset or type(part["chunk_base64"]) is not str
                or len(part["chunk_base64"])>4*((RESTORE_CHUNK_BYTES_V3+2)//3)):
            raise RuntimeError("root restoration chunk identity/bound differs")
        chunk=base64.b64decode(part["chunk_base64"],validate=True)
        expected=min(RESTORE_CHUNK_BYTES_V3,total-offset)
        if len(chunk)!=expected or sha256(chunk).hexdigest()!=part["chunk_digest"] or part["end"] is not (offset+expected==total):
            raise RuntimeError("root restoration chunk bytes/termination differ")
        pieces.append(chunk);qualifications.append(part["qualification_digest"]);offset+=len(chunk)
    packet=b"".join(pieces)
    if sha256(packet).hexdigest()!=packet_digest:raise RuntimeError("root restoration packet hash differs")
    raw=json.loads(packet)
    if type(raw) is not dict or set(raw)!={"terminal","prepared","claim","measurement","artifact_payload"} or canonical_serialize(raw).encode()!=packet:
        raise RuntimeError("root restoration packet is noncanonical")
    value=root_restore_from_wire_v3({**raw,"qualification_digest":canonical_digest((packet_digest,total,tuple(qualifications)))})
    if value.terminal.binding!=binding or value.prepared.binding!=binding:raise RuntimeError("root restored packet binding differs")
    return value
