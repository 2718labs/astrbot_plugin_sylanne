#!/opt/sylanne-runtime/bin/python
"""Permanent LOCAL_FIXTURE counter program; no SDK model or provider call.

The public fixture key is deliberately reproducible. It authenticates only the
separate finite ASCII fixture model and must never enter a production profile.
"""
import hashlib
import json
import math
import os
import sys
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

PROVIDER = "sylanne.local.phase-counter-fixture.v1"
MODEL = "finite-ascii-char-v1"
RULE_ID = "sylanne.fixture.ascii-char-chat.two-message.v1"
TEMPLATE = "sylanne.artifact_draft_phase_template.v2"
RULE = {"schema": RULE_ID, "characters": "ASCII U+0009,U+000A,U+000D,U+0020..U+007E",
    "character_tokens": 1, "message_overhead_tokens": 3, "assistant_priming_tokens": 3,
    "roles": ["system", "user"], "metadata_is_input": False, "model": MODEL, "model_revision": "1"}
PRIVATE_KEY = hashlib.sha256(b"sylanne.LOCAL_FIXTURE.phase-count-only.v1").digest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def require(condition, message):
    if not condition:
        raise ValueError(message)


def main():
    raw = sys.stdin.buffer.read(262145)
    require(len(raw) <= 262144, "fixture counter request exceeds bound")
    outer = json.loads(raw)
    require(set(outer) == {"schema", "policy", "request", "tokenizer_fd", "applicability_fd"}
        and outer["schema"] == "sylanne.artifact-phase-counter-program.v1", "unknown fixture counter purpose")
    policy, request = outer["policy"], outer["request"]
    require((policy["source_scope"], policy["provider_id"], policy["model_id"], policy["model_revision"],
        policy["encoding_rule_id"], policy["encoding_rule_sha256"], policy["template_version"]) == (
        "LOCAL_FIXTURE", PROVIDER, MODEL, "1", RULE_ID, digest(RULE), TEMPLATE), "fixture cannot count another model")
    public_key = Ed25519PrivateKey.from_private_bytes(PRIVATE_KEY).public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw).hex()
    require(policy["counter_public_key_hex"] == public_key, "fixture public key differs")
    require(hashlib.sha256(open(sys.argv[0], "rb").read()).hexdigest() == policy["program_sha256"],
        "fixture program bytes differ")
    tokenizer = os.pread(outer["tokenizer_fd"], 65537, 0)
    applicability = os.pread(outer["applicability_fd"], 65537, 0)
    require(len(tokenizer) <= 65536 and hashlib.sha256(tokenizer).hexdigest() == policy["tokenizer_sha256"]
        and json.loads(tokenizer) == RULE, "fixture finite vocabulary changed")
    require(len(applicability) <= 65536 and hashlib.sha256(applicability).hexdigest() == policy["applicability_sha256"],
        "fixture applicability asset changed")
    expected_applicability = {"schema": "sylanne.artifact-phase-count-applicability.v1", "purpose": "artifact_phase_count",
        **{name: policy[name] for name in ("source_scope", "provider_id", "model_id", "model_revision",
            "provider_config_digest", "template_version", "counter_policy_id", "counter_policy_version",
            "program_sha256", "tokenizer_sha256", "encoding_rule_id", "encoding_rule_sha256")}}
    require(json.loads(applicability) == expected_applicability, "fixture applicability model or purpose differs")
    require(request["schema"] == "sylanne.artifact-phase-count-request.v1"
        and request["input_kind"] in {"prospective", "actual"} and request["policy_digest"] == digest(policy),
        "fixture request schema, kind or installed policy differs")
    for name in ("namespace", "installation_id", "manifest_digest", "profile_id", "provider_id", "model_id",
            "model_revision", "provider_config_digest", "template_version"):
        require(request[name] == policy[name], "fixture request selected another installed identity")
    wire = request["provider_request_json"]
    require(hashlib.sha256(wire.encode()).hexdigest() == request["provider_wire_digest"], "fixture wire digest differs")
    provider = json.loads(wire)
    require(canonical(provider) == wire and provider["model"] == MODEL and provider["stream"] is False
        and set(provider) in ({"model", "messages", "stream", "max_completion_tokens"},
            {"model", "messages", "stream", "max_completion_tokens", "metadata"}), "fixture provider shape differs")
    require(type(provider["max_completion_tokens"]) is int and 1 <= provider["max_completion_tokens"] <= 2000,
        "fixture output limit differs")
    messages = provider["messages"]
    require(type(messages) is list and len(messages) == 2
        and [m["role"] for m in messages] == ["system", "user"], "fixture message roles differ")
    tokens = RULE["assistant_priming_tokens"]
    for message in messages:
        require(set(message) == {"role", "content"} and type(message["content"]) is str,
            "fixture message content differs")
        require(all(ord(c) in (9, 10, 13) or 32 <= ord(c) <= 126 for c in message["content"]),
            "fixture input is outside its finite ASCII vocabulary")
        tokens += len(message["content"]) + RULE["message_overhead_tokens"]
    nonce = request["nonce"]
    require(type(nonce) is str and len(nonce) == 32 and all(c in "0123456789abcdef" for c in nonce),
        "fixture nonce differs")
    now = time.time()
    require(math.isfinite(request["frozen_at_utc"]) and math.isfinite(request["original_deadline_utc"])
        and request["frozen_at_utc"] <= now < request["original_deadline_utc"], "fixture original deadline expired")
    scope = {name: request[name] for name in ("namespace", "owner_grant_ref", "owner_grant_revision",
        "owner_grant_digest", "source_versions", "read_versions", "query_coverage_digest", "budget_scope_digest", "access_epoch",
        "delete_epoch", "activation_generation")}
    payload = {"schema": "sylanne.artifact-phase-count-evidence.v1", "source_scope": "LOCAL_FIXTURE",
        "input_kind": request["input_kind"], "request_digest": digest(request), "policy_digest": digest(policy),
        "provider_wire_digest": request["provider_wire_digest"], "candidate_parameter_digest": request["candidate_parameter_digest"],
        "frozen_material_digest": request["frozen_material_digest"], "scope_digest": digest(scope),
        "original_deadline_utc": request["original_deadline_utc"], "nonce": nonce, "counted_at_utc": now,
        "token_evidence": "exact_model_input", "lower_tokens": tokens, "upper_tokens": tokens,
        **{name: policy[name] for name in ("program_sha256", "tokenizer_sha256", "applicability_sha256", "encoding_rule_sha256")}}
    signature = Ed25519PrivateKey.from_private_bytes(PRIVATE_KEY).sign(
        b"sylanne.artifact-phase-count-evidence.v1\0" + canonical(payload).encode()).hex()
    sys.stdout.write(canonical({"payload": payload, "signature_hex": signature}))


if __name__ == "__main__":
    main()