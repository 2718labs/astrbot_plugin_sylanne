"""Fixed detached old-package proof operations; never an Authority endpoint.

The parent qualifies protected registration and the actual originals. This
process imports only the specified retained package and cannot call native,
open a network connection, spawn children, or write files. Its public JSON
answer has no admission or trusted-witness meaning.
"""
from __future__ import annotations

import hashlib
import json
import os
import ctypes  # Initializes only CPython's own handle before the audit fence.
from pathlib import Path
import resource
import sys

SCHEMA = "d12.historical-d04-recipe.v1"
LIMIT = 32 * 1024 * 1024


def _json(raw):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("duplicate historical input")
            value[key] = item
        return value
    return json.loads(raw, object_pairs_hook=unique,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite historical input")))


def _readonly_audit(event, args):
    if (event.startswith(("socket.", "subprocess.", "os.exec", "os.spawn"))
            or event in {"os.system", "os.fork", "os.forkpty", "ctypes.dlopen",
                "os.remove", "os.rename", "os.mkdir", "os.rmdir", "os.chmod", "os.chown",
                "os.link", "os.symlink", "os.truncate", "os.utime", "os.putenv", "os.unsetenv"}):
        raise RuntimeError("historical verifier prohibited operation")
    if event == "open":
        _path, mode, flags = args
        if (type(mode) is str and any(c in mode for c in "wax+")
                or type(flags) is int and flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND)):
            raise RuntimeError("historical verifier is read-only")
    if event.startswith("sqlite3.connect"):
        raise RuntimeError("historical mathematical worker does not open databases")


def _identity(root, manifest):
    from sylanne3.host.installed_d04_numeric_build_v3 import read_installed_d04_numeric_identity_v3
    from sylanne3.host.installed_d04_root_build_v3 import read_installed_d04_root_identity_v3
    return {"numeric": read_installed_d04_numeric_identity_v3(root, manifest),
        "authored_root": read_installed_d04_root_identity_v3(root, manifest)}


def _numeric(root, manifest, payload):
    from sylanne3.authority_service.d04_numeric_contract_v3 import D04NumericBindingV3, D04NumericTerminalV3, from_wire
    from sylanne3.runtime.d04_numeric_cost_v3 import D04NumericPreparedV3
    from sylanne3.native_runtime.d04_joint_replay_validation_v3 import D04PinnedReplayAssetsV3, revalidate_d04_numeric_artifact_v3
    from sylanne3.domains.d04.trusted_joint_replay import is_package_bound_joint_numeric_replay_v1
    if type(payload) is not dict or set(payload) != {"prepared", "terminal", "artifact"}:
        raise ValueError("complete fixed historical numeric packet required")
    raw = payload["prepared"]
    if type(raw) is not dict or set(raw) != set(D04NumericPreparedV3.__dataclass_fields__):
        raise ValueError("historical numeric preparation fields differ")
    prepared = D04NumericPreparedV3(**{**raw, "binding": from_wire(raw["binding"], D04NumericBindingV3)})
    terminal = from_wire(payload["terminal"], D04NumericTerminalV3)
    assets = D04PinnedReplayAssetsV3(root, prepared.binding.namespace, prepared.binding.installation_id, manifest)
    product = revalidate_d04_numeric_artifact_v3(prepared, terminal, payload["artifact"], assets)
    if is_package_bound_joint_numeric_replay_v1(product.replay):
        raise ValueError("detached historical verifier minted a trusted witness")
    return dict(binding_digest=prepared.binding.digest, prepared_digest=prepared.digest,
        terminal_digest=terminal.digest, artifact_digest=payload["artifact"]["artifact_digest"],
        full_transcript_digest=product.replay.math_result.full_transcript_sha256,
        family_transcripts=product.replay.math_result.family_transcripts,
        output_original_digest=product.output.original_digest, trusted=False)


def _root(root, manifest, payload):
    from sylanne3.authority_service.d04_root_execution_contract_v3 import D04RootExecutionBindingV3, D04RootExecutionTerminalV3, root_execution_from_wire_v3
    from sylanne3.runtime.d04_root_execution_v3 import D04RootPreparedExecutionV3
    from sylanne3.domains.d04.authored_lineage_v3 import decode_authored_root_candidate_v3
    from sylanne3.domains.d04.authored_root_recovery_v3 import decode_authored_root_math_artifact_v3, verify_authored_root_math_artifact_v3
    from sylanne3.host.installed_d04_root_build_v3 import read_installed_d04_root_identity_v3
    from sylanne3.host.installed_d04_root_resources import load_installed_d04_root_preset_v3
    from sylanne3.host.installed_d04_output_policy import load_installed_d04_output_policy_v1
    from sylanne3.host.installed_tanh_readout_asset import load_installed_tanh_readout_candidate
    from sylanne3.native_runtime.loader import NativeLoadBinding
    from sylanne3.runtime_contracts import canonical_digest, canonical_serialize
    if type(payload) is not dict or set(payload) != {"prepared", "terminal", "artifact"}:
        raise ValueError("complete fixed historical root packet required")
    raw = payload["prepared"]
    if type(raw) is not dict or set(raw) != set(D04RootPreparedExecutionV3.__dataclass_fields__):
        raise ValueError("historical root preparation fields differ")
    binding = root_execution_from_wire_v3(raw["binding"], D04RootExecutionBindingV3)
    prepared = D04RootPreparedExecutionV3(**{**raw, "binding": binding})
    terminal = root_execution_from_wire_v3(payload["terminal"], D04RootExecutionTerminalV3)
    identity = read_installed_d04_root_identity_v3(root, manifest)
    if (terminal.binding != binding or terminal.measurement.status != "completed"
            or prepared.schema != "d04.authored-root-prepared.v3"
            or any(getattr(binding, key) != value for key, value in identity.items())):
        raise ValueError("historical root recipe/terminal differs")
    for value in (prepared.input_payload_json, prepared.quote_payload_json, prepared.reserve_receipt_json,
                  prepared.parent_budget_original_json, prepared.signed_grant_payload_json):
        if canonical_serialize(_json(value)) != value:
            raise ValueError("historical root original is noncanonical")
    inputs = _json(prepared.input_payload_json)
    if canonical_digest(inputs) != binding.input_digest:
        raise ValueError("historical root frozen input changed")
    candidate = decode_authored_root_candidate_v3(inputs["candidate"])
    artifact = decode_authored_root_math_artifact_v3(payload["artifact"])
    preset = load_installed_d04_root_preset_v3(root, manifest)
    policy = load_installed_d04_output_policy_v1(root, manifest, require_formal=False, require_backend_runtime=True)
    readout = load_installed_tanh_readout_candidate(root, manifest, preset.assets,
        expected_readout_id=policy.policy.readout_id)
    if (candidate.digest != binding.candidate_digest or candidate.preset != preset
            or artifact.artifact_digest != terminal.measurement.artifact_digest
            or artifact.initial_box_proof.proof_digest != terminal.measurement.initial_box_proof_digest
            or artifact.output.issuance_digest != terminal.measurement.output_issuance_digest
            or artifact.output.write_set_digest != terminal.measurement.output_write_set_digest):
        raise ValueError("historical root measured commitments differ")
    platform = _json((root / "release-manifest.json").read_bytes())["platform"]
    output = verify_authored_root_math_artifact_v3(candidate, artifact,
        NativeLoadBinding(manifest, binding.native_sha256, platform["os"], platform["arch"],
            platform.get("libc"), 2), readout.asset, policy.policy, binding.operation_id)
    return dict(binding_digest=binding.digest, prepared_digest=prepared.digest, terminal_digest=terminal.digest,
        artifact_digest=artifact.artifact_digest, output_issuance_digest=output.issuance_digest,
        output_write_set_digest=output.write_set_digest, trusted=False)


def main():
    raw = sys.stdin.buffer.read(LIMIT + 1)
    if len(raw) > LIMIT:
        raise ValueError("historical worker input exceeds bound")
    packet = _json(raw)
    if (type(packet) is not dict or set(packet) != {"schema", "package_root", "manifest_sha256", "operation", "payload"}
            or packet["schema"] != SCHEMA or packet["operation"] not in {"identity", "numeric_math", "authored_root_math"}):
        raise ValueError("fixed historical worker request required")
    root = Path(packet["package_root"])
    if not root.is_absolute() or root.resolve(strict=True) != root or ".." in root.parts:
        raise ValueError("canonical retained package root required")
    if hashlib.sha256((root / "release-manifest.json").read_bytes()).hexdigest() != packet["manifest_sha256"]:
        raise ValueError("retained package manifest changed")
    # No inherited caller path, environment credentials, imported current
    # Sylanne classes, writable bytecode, native library, or Authority handle.
    sys.path.insert(0, str(root / "rewrite"))
    sys.dont_write_bytecode = True
    if ctypes.pythonapi._name is not None:
        raise RuntimeError("unexpected interpreter native handle")
    resource.setrlimit(resource.RLIMIT_CPU, (150, 150))
    resource.setrlimit(resource.RLIMIT_AS, (1024 ** 3, 1024 ** 3))
    resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))
    sys.addaudithook(_readonly_audit)
    operation = packet["operation"]
    if operation == "identity":
        if packet["payload"] is not None:
            raise ValueError("identity operation takes no caller recipe")
        result = _identity(root, packet["manifest_sha256"])
    elif operation == "numeric_math":
        result = _numeric(root, packet["manifest_sha256"], packet["payload"])
    else:
        result = _root(root, packet["manifest_sha256"], packet["payload"])
    sys.stdout.write(json.dumps(dict(schema=SCHEMA, request_sha256=hashlib.sha256(raw).hexdigest(),
        operation=operation, result=result), sort_keys=True, separators=(",", ":"), allow_nan=False))


if __name__ == "__main__":
    main()
