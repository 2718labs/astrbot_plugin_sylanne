#!/opt/sylanne-runtime/bin/python3.12
"""Protected finite-Mock complete HTTP byte-token upper bound, never a real tokenizer."""
import base64,hashlib,json,sys
from pathlib import Path

SCHEMA="sylanne.sdk-d13-v6-http-byte-bound.v1"

def complete_http_token_upper_v1(wire):
    value=json.loads(wire) if type(wire) is str else wire
    body={"model":value["model"],"messages":value["messages"],"stream":False,
        "max_completion_tokens":value["max_output_tokens"],"metadata":{"sylanne_call_id":"x"*128,
        "sylanne_request_digest":"x"*64,"sylanne_billing_contract":"x"*64}}
    return (len(json.dumps(body,ensure_ascii=True).encode())+3)//4

def require_actual_http_bound_v1(raw,content):
    if set(raw)!={"model","messages","stream","max_completion_tokens","metadata"} or raw["stream"] is not False:
        raise ValueError("finite SDK HTTP serializer fields differ from signed bound")
    metadata=raw["metadata"]
    if len(metadata["sylanne_call_id"])>128 or any(len(metadata[k])!=64 for k in ("sylanne_request_digest","sylanne_billing_contract")):
        raise ValueError("finite SDK HTTP identity exceeds signed bound")
    upper=complete_http_token_upper_v1({"model":raw["model"],"messages":raw["messages"],"max_output_tokens":raw["max_completion_tokens"]})
    if (len(content)+3)//4>upper:raise ValueError("actual SDK HTTP bytes exceed protected conservative bound")
    return upper

def main():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    request=json.load(sys.stdin)
    if request["schema"]!="sylanne3.d13.full-wire-count-request.v6":raise ValueError("finite V6 count request required")
    for key,digest in (("raw_wire","raw_request_digest"),("compressed_wire","compressed_request_digest")):
        if hashlib.sha256(request[key].encode()).hexdigest()!=request["original"][digest]:raise ValueError("actual whole-wire digest differs")
    key=Ed25519PrivateKey.from_private_bytes(bytes.fromhex(Path('/etc/sylanne-b04-fixture/d13-counter-private.hex').read_text().strip()))
    from cryptography.hazmat.primitives import serialization
    if key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw).hex()!=request["policy"]["counter_public_key_hex"]:
        raise ValueError("protected independent counter key differs")
    payload={**request["original"],"schema":"sylanne3.d13.signed-full-wire-evidence.v6","token_evidence":"bounded_full_wire",
        "raw_lower_tokens":0,"raw_upper_tokens":complete_http_token_upper_v1(request["raw_wire"]),
        "compressed_lower_tokens":0,"compressed_upper_tokens":complete_http_token_upper_v1(request["compressed_wire"])}
    encoded=json.dumps(payload,sort_keys=True,separators=(',',':'),ensure_ascii=False)
    signature=key.sign(b'sylanne3.d13.signed-full-wire-evidence.v6\0'+encoded.encode())
    print(json.dumps({"payload":payload,"signature":base64.b64encode(signature).decode()}))

if __name__=='__main__':main()
