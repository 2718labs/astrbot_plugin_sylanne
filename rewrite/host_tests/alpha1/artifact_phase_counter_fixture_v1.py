#!/opt/sylanne-runtime/bin/python3.12
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
    if outer["policy"]["provider_id"] == MOCK_V3_PROVIDER:
        sys.stdout.write(canonical(mock_v3_counter_response(outer)))
        return
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




# A separate declared Mock model, never a tokenizer claim about a vendor model.
MOCK_V3_PROVIDER = "sylanne.test.mock.artifact-v3"
MOCK_V3_MODEL = "mock-utf8-eight-octets-v1"
MOCK_V3_RULE_ID = "sylanne.test.mock.utf8-eight-octets-chat.v1"
MOCK_V3_RULE = {"schema": MOCK_V3_RULE_ID, "model": MOCK_V3_MODEL, "model_revision": "mock-only-v1",
    "unit": "ceil(UTF8 message content octets / 8)", "message_overhead_tokens": 3,
    "assistant_priming_tokens": 3, "roles": ["system", "user"], "metadata_is_input": False,
    "claim": "exact only for this deterministic Mock model; no vendor equivalence"}
MOCK_V3_PRIVATE_KEY = hashlib.sha256(b"sylanne.test.mock.artifact-v3.counter-only.NOT_VENDOR").digest()


def mock_v3_input_tokens(messages):
    require(type(messages) is list and [m.get("role") for m in messages] == ["system", "user"],
        "Mock V3 model counts its exact two-message body")
    return 3 + sum(3 + (len(m["content"].encode("utf-8")) + 7) // 8 for m in messages)


def mock_v3_counter_response(outer):
    policy, request = outer["policy"], outer["request"]
    require((policy["source_scope"], policy["provider_id"], policy["model_id"], policy["model_revision"],
        policy["encoding_rule_id"], policy["encoding_rule_sha256"]) == (
        "production", MOCK_V3_PROVIDER, MOCK_V3_MODEL, "mock-only-v1", MOCK_V3_RULE_ID, digest(MOCK_V3_RULE)),
        "Mock meter cannot impersonate another model, rule or old LOCAL_FIXTURE")
    key = Ed25519PrivateKey.from_private_bytes(MOCK_V3_PRIVATE_KEY)
    require(key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex() == policy["counter_public_key_hex"],
        "Mock meter key differs")
    require(hashlib.sha256(open(sys.argv[0], "rb").read()).hexdigest() == policy["program_sha256"],
        "Mock meter installed program bytes differ")
    tokenizer = os.pread(outer["tokenizer_fd"], 65537, 0)
    applicability = os.pread(outer["applicability_fd"], 65537, 0)
    require(hashlib.sha256(tokenizer).hexdigest() == policy["tokenizer_sha256"] and json.loads(tokenizer) == MOCK_V3_RULE,
        "Mock tokenizer bytes differ")
    expected = {"schema": "sylanne.artifact-phase-count-applicability.v1", "purpose": "artifact_phase_count",
        **{n: policy[n] for n in ("source_scope", "provider_id", "model_id", "model_revision",
            "provider_config_digest", "template_version", "counter_policy_id", "counter_policy_version",
            "program_sha256", "tokenizer_sha256", "encoding_rule_id", "encoding_rule_sha256")}}
    require(hashlib.sha256(applicability).hexdigest() == policy["applicability_sha256"]
        and json.loads(applicability) == expected, "Mock applicability differs")
    require(request["policy_digest"] == digest(policy), "Mock request policy digest differs")
    for n in ("namespace", "installation_id", "manifest_digest", "profile_id", "provider_id",
            "model_id", "model_revision", "provider_config_digest", "template_version"):
        require(request[n] == policy[n], "Mock request changed installed identity")
    wire = request["provider_request_json"]
    require(hashlib.sha256(wire.encode()).hexdigest() == request["provider_wire_digest"], "Mock provider wire differs")
    provider = json.loads(wire)
    require(provider["model"] == MOCK_V3_MODEL and provider["stream"] is False, "Mock model/stream differs")
    tokens = mock_v3_input_tokens(provider["messages"])
    now = time.time()
    require(request["frozen_at_utc"] <= now < request["original_deadline_utc"], "Mock original deadline ended or is future")
    scope = {n: request[n] for n in ("namespace", "owner_grant_ref", "owner_grant_revision", "owner_grant_digest",
        "source_versions", "read_versions", "query_coverage_digest", "budget_scope_digest", "access_epoch",
        "delete_epoch", "activation_generation")}
    payload = {"schema": "sylanne.artifact-phase-count-evidence.v1", "source_scope": "production",
        "input_kind": request["input_kind"], "request_digest": digest(request), "policy_digest": digest(policy),
        "provider_wire_digest": request["provider_wire_digest"], "candidate_parameter_digest": request["candidate_parameter_digest"],
        "frozen_material_digest": request["frozen_material_digest"], "scope_digest": digest(scope),
        "original_deadline_utc": request["original_deadline_utc"], "nonce": request["nonce"], "counted_at_utc": now,
        "token_evidence": "exact_model_input", "lower_tokens": tokens, "upper_tokens": tokens,
        **{n: policy[n] for n in ("program_sha256", "tokenizer_sha256", "applicability_sha256", "encoding_rule_sha256")}}
    return {"payload": payload, "signature_hex": key.sign(
        b"sylanne.artifact-phase-count-evidence.v1\0" + canonical(payload).encode()).hex()}


def prepare_mock_v3_installer_inputs_v1(request_path, provider_path, model_script_path, output_request_path, assets_directory):
    """Root tool produces a fresh unsigned request proposal; it never installs or executes."""
    if os.name != "posix" or os.geteuid() != 0:
        raise PermissionError("fixture asset preparation requires its isolated Root controller")
    from pathlib import Path
    from cryptography.hazmat.primitives.serialization import PrivateFormat, NoEncryption
    request = json.loads(Path(request_path).read_bytes())
    provider = json.loads(Path(provider_path).read_bytes())
    script = json.loads(Path(model_script_path).read_bytes())
    require(request["schema"] == "sylanne3.linux-install-request.v6"
        and (request["provider_id"], request["model_id"], provider["id"], provider["model"]) ==
        (MOCK_V3_PROVIDER, MOCK_V3_MODEL, MOCK_V3_PROVIDER, MOCK_V3_MODEL),
        "Mock fixture needs an explicitly proposed new V6 request, never an old Root/vendor")
    original_budget = {n: request[n] for n in ("budget_limits", "budget_max_ceiling", "budget_valid_until_utc")}
    require(script["schema"] == "sylanne.sdk-artifact-v3-mock-model.v1"
        and script["unknown_observation"] in (True, False) and len(script["episodes"]) == 1,
        "one explicit Mock model script required")
    config_digest = digest(provider)
    for workflow in (request["artifact_draft"]["model_workflow"], request["artifact_draft"]["phase_model_workflow"],
            request["artifact_observation_cognition"]):
        require((workflow["provider_id"], workflow["model_id"], workflow["provider_config_digest"]) ==
            (MOCK_V3_PROVIDER, MOCK_V3_MODEL, config_digest), "explicit proposed workflow changed actual Mock selection")
    directory = Path(assets_directory)
    directory.mkdir(mode=0o755, parents=False, exist_ok=False)
    def create(path, value, mode):
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
        with os.fdopen(fd, "wb") as stream:
            stream.write(value);stream.flush();os.fsync(stream.fileno())
    program = Path(__file__).read_bytes()
    create(directory/"counter", program, 0o755)
    tokenizer = canonical(MOCK_V3_RULE).encode()
    create(directory/"tokenizer", tokenizer, 0o644)
    counter = {"schema": "sylanne3.initial-artifact-phase-counter.v1", "source_scope": "production",
        "model_revision": "mock-only-v1", "counter_policy_id": "test:artifact-v3-external-mock-only", "counter_policy_version": 1,
        "executable": str(directory/"counter"), "program_sha256": hashlib.sha256(program).hexdigest(),
        "counter_public_key_hex": Ed25519PrivateKey.from_private_bytes(MOCK_V3_PRIVATE_KEY).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex(),
        "tokenizer_path": str(directory/"tokenizer"), "tokenizer_sha256": hashlib.sha256(tokenizer).hexdigest(),
        "applicability_path": str(directory/"applicability.json"), "encoding_rule_id": MOCK_V3_RULE_ID,
        "encoding_rule_sha256": digest(MOCK_V3_RULE), "timeout_seconds": 60}
    applicability = {"schema": "sylanne.artifact-phase-count-applicability.v1", "purpose": "artifact_phase_count",
        "provider_id": MOCK_V3_PROVIDER, "model_id": MOCK_V3_MODEL, "provider_config_digest": config_digest,
        "template_version": "sylanne.artifact_draft_phase_template.v2",
        **{n: counter[n] for n in ("source_scope", "model_revision", "counter_policy_id", "counter_policy_version",
            "program_sha256", "tokenizer_sha256", "encoding_rule_id", "encoding_rule_sha256")}}
    encoded = canonical(applicability).encode()
    counter["applicability_sha256"] = hashlib.sha256(encoded).hexdigest()
    create(directory/"applicability.json", encoded, 0o644)
    observer = {"schema": "sylanne.artifact-phase-observer-policy.v2",
        "observer_id": "test:artifact-v3-independent-observer", "observer_version": 1,
        "workflow_digest": digest(request["artifact_observation_cognition"]), "condition_kinds": ["tone", "task_semantics"],
        "producer": "d07.independent-artifact-observation.v1", "call_plan_schema": "d11.foreground-call-plan.v3",
        "question_template": "d07.artifact-phase-independent-question.v1", "completion_mode": "artifact_receipt_only"}
    encoded = canonical(observer).encode()
    create(directory/"observer.json", encoded, 0o644)
    request["artifact_phase_counter"] = counter
    request["artifact_phase_observer"] = {"schema": "sylanne.artifact-phase-observer-installation.v2",
        "observer_id": observer["observer_id"], "observer_version": 1, "asset_ref": str(directory/"observer.json"),
        "asset_sha256": hashlib.sha256(encoded).hexdigest()}
    key = Ed25519PrivateKey.generate()
    script.update(provider_id=MOCK_V3_PROVIDER, model_id=MOCK_V3_MODEL, provider_config_digest=config_digest,
        billing_private_key_hex=key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex(),
        max_episode_calls=6, max_auxiliary_calls=0, max_total_calls=6)
    request["provider_billing_contract_v1"] = {"contract_id": "test:artifact-v3-zero-simulated-charge",
        "contract_version": 1, "provider_ed25519_public_key_hex": key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex(),
        "evidence_kind": "fixture_simulated_charge", "currency": "USD", "unit": "model_microusd"}
    require({n: request[n] for n in original_budget} == original_budget, "fixture proposal changed original budget/deadline")
    create(directory/"model-private-config.json", canonical(script).encode(), 0o600)
    create(Path(output_request_path), canonical(request).encode(), 0o600)
    return {"status": "UNSIGNED_FRESH_REQUEST_PROPOSAL_REQUIRES_ROOT_APPROVAL",
        "request_sha256": hashlib.sha256(canonical(request).encode()).hexdigest(),
        "model_script_sha256": hashlib.sha256(canonical(script).encode()).hexdigest(),
        "model_calls": 0, "database_access": False, "installation_performed": False}


def write_mock_v3_installed_setup_v1(profile_id, model_config_path, evidence_directory, output_path):
    """Capture a new installed Mock fixture descriptor without opening any business DB."""
    from pathlib import Path
    if os.name != "posix" or os.geteuid() != 0:
        raise PermissionError("isolated fixture Root controller required")
    sys.path.insert(0, "/opt/sylanne/code")
    from _runtime_bootstrap import load_canonical_runtime_v1
    load_canonical_runtime_v1(Path("/opt/sylanne/code"))
    from sylanne3.authority_service.linux_installation_security_v1 import read_installed_bytes_v1
    from sylanne3.host.authority_profile import _policy_from_payload
    from sylanne3.runtime_contracts import canonical_digest
    profile = json.loads(read_installed_bytes_v1(Path("/etc/sylanne/client/profiles")/profile_id/"profile.json"))
    policy = _policy_from_payload(profile)
    require(profile["model_workflows"]["version"] == 9
        and (profile["artifact_phase_counter"]["provider_id"], profile["artifact_phase_counter"]["model_id"]) ==
        (MOCK_V3_PROVIDER, MOCK_V3_MODEL), "setup capture requires the actual installed V9 Mock model")
    assets = json.loads(read_installed_bytes_v1("/etc/sylanne/authority/assets.json"))
    script = json.loads(Path(model_config_path).read_bytes())
    episode = script["episodes"][0]
    setup = {"schema": "sylanne.test.artifact-v3-installed-snapshot-setup.v1", "profile_id": profile_id,
        "installation_id": policy.installation_id, "manifest_digest": policy.manifest_digest,
        "root_grant_digest": canonical_digest(policy.root_grant), "original_deadline_utc": policy.root_grant.valid_until_utc,
        "approved_root_limits": dict(policy.root_lease.limits), "approved_root_max_ceiling": dict(policy.root_grant.max_ceiling),
        "graph_path": assets["graph_db"], "evidence_directory": str(Path(evidence_directory)),
        "message_id": episode["message_id"], "task_text": episode["task_text"],
        "unknown_observation": script["unknown_observation"]}
    fd = os.open(output_path, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as stream:
        stream.write(canonical(setup));stream.flush();os.fsync(stream.fileno())
    return {"status": "INSTALLED_FIXTURE_DESCRIPTOR_ONLY_NOT_ACCEPTANCE", "setup_sha256": digest(setup),
        "model_calls": 0, "database_access": False}




def stage_mock_v3_sdk_helpers_v1(model_source, counter_source, pins_path, input_settings, output_settings):
    """Copy the two pinned engineering modules before SDK startup; never edit product code."""
    from pathlib import Path
    import stat
    if os.name != "posix" or os.geteuid() != 0:
        raise PermissionError("isolated fixture Root controller required")
    def read_root(path):
        path = Path(path)
        require(path.is_absolute() and path.resolve(strict=True) == path, "canonical Root helper input required")
        for entry in (path, *path.parents):
            st = entry.lstat()
            require(not entry.is_symlink() and st.st_uid == 0 and not st.st_mode & 0o022,
                "fixture helper input/ancestor is not Root protected")
        require(stat.S_ISREG(path.stat().st_mode), "Root helper input must be a regular file")
        return path.read_bytes()
    expected = json.loads(read_root(pins_path))
    names = {"sdk_m1_model_fixture_v1.py": Path(model_source), "artifact_phase_counter_fixture_v1.py": Path(counter_source)}
    require(type(expected) is dict and set(expected) == set(names), "exact published helper hash map required")
    content = {name: read_root(path) for name, path in names.items()}
    require(all(hashlib.sha256(body).hexdigest() == expected[name] for name, body in content.items()),
        "engineering helper source differs from its externally supplied SHA256")
    directory = Path("/opt/sylanne-b04-fixture")
    require(directory.is_dir() and directory.stat().st_uid == 0 and not directory.stat().st_mode & 0o022,
        "actual fixed Root SDK fixture directory required")
    for name, body in content.items():
        target = directory/name
        if target.exists():
            require(hashlib.sha256(read_root(target)).hexdigest() == expected[name], "refuse helper overwrite")
            continue
        fd = os.open(target, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o644)
        with os.fdopen(fd, "wb") as stream:
            stream.write(body);stream.flush();os.fsync(stream.fileno())
    settings = json.loads(read_root(input_settings))
    require(settings.get("scenario") in {"sdk_artifact_v3_tone_sample_v1", "sdk_artifact_v3_unknown_v1"},
        "new Artifact V3 SDK scenario required")
    settings["artifact_v3_helper_sha256"] = expected
    fd = os.open(output_settings, os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW, 0o640)
    os.fchown(fd, 0, 1000)
    with os.fdopen(fd, "w") as stream:
        stream.write(canonical(settings));stream.flush();os.fsync(stream.fileno())
    return {"status": "SDK_HELPERS_STAGED_NOT_RUNTIME_ACCEPTANCE", "helpers": expected,
        "settings_sha256": digest(settings), "model_calls": 0, "database_access": False}

if __name__ == "__main__":
    if len(sys.argv) == 7 and sys.argv[1] == "--prepare-v3":
        result = prepare_mock_v3_installer_inputs_v1(*sys.argv[2:])
        sys.stdout.write(canonical(result))
    elif len(sys.argv) == 7 and sys.argv[1] == "--stage-v3-sdk-helpers":
        result = stage_mock_v3_sdk_helpers_v1(*sys.argv[2:])
        sys.stdout.write(canonical(result))
    elif len(sys.argv) == 6 and sys.argv[1] == "--installed-setup-v3":
        result = write_mock_v3_installed_setup_v1(*sys.argv[2:])
        sys.stdout.write(canonical(result))
    else:
        main()
