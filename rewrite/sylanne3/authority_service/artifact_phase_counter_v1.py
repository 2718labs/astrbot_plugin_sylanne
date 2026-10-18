"""Protected artifact-phase counter transport and its distinct signed evidence.

The configured program counts outside Graph transactions. Verification grants
no source access, quote reservation, model job or provider admission.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
import selectors
import signal
import subprocess
import tempfile
import time

from ..model_broker.artifact_phase_count_v1 import (
    ArtifactPhaseCountPolicyV1,
    SIGNING_DOMAIN, artifact_phase_count_evidence_from_wire_v1, require_phase_count_request_policy_v1,
)
from ..runtime_contracts import canonical_serialize
from .linux_installation_security_v1 import opened_installed_file_v1

APPLICABILITY_SCHEMA = "sylanne.artifact-phase-count-applicability.v1"


def artifact_phase_applicability_wire_v1(policy):
    return {"schema": APPLICABILITY_SCHEMA, "purpose": "artifact_phase_count",
        "source_scope": policy.source_scope, "provider_id": policy.provider_id, "model_id": policy.model_id,
        "model_revision": policy.model_revision, "provider_config_digest": policy.provider_config_digest,
        "template_version": policy.template_version, "counter_policy_id": policy.counter_policy_id,
        "counter_policy_version": policy.counter_policy_version, "program_sha256": policy.program_sha256,
        "tokenizer_sha256": policy.tokenizer_sha256, "encoding_rule_id": policy.encoding_rule_id,
        "encoding_rule_sha256": policy.encoding_rule_sha256}


def verify_artifact_phase_count_envelope_v1(policy, request, envelope, *, now_utc):
    require_phase_count_request_policy_v1(policy, request)
    if type(envelope) is not dict or set(envelope) != {"payload", "signature_hex"}:
        raise ValueError("phase counter requires its distinct signed envelope")
    evidence = artifact_phase_count_evidence_from_wire_v1(envelope["payload"])
    if (evidence.source_scope, evidence.input_kind, evidence.request_digest, evidence.policy_digest,
            evidence.provider_wire_digest, evidence.candidate_parameter_digest, evidence.frozen_material_digest,
            evidence.scope_digest, evidence.original_deadline_utc, evidence.nonce, evidence.program_sha256,
            evidence.tokenizer_sha256, evidence.applicability_sha256, evidence.encoding_rule_sha256) != (
            policy.source_scope, request.input_kind, request.digest, policy.digest, request.provider_wire_digest,
            request.candidate_parameter_digest, request.frozen_material_digest, request.scope_digest,
            request.original_deadline_utc, request.nonce, policy.program_sha256, policy.tokenizer_sha256,
            policy.applicability_sha256, policy.encoding_rule_sha256):
        raise ValueError("phase counter signed a different kind, nonce, scope, model or provider input")
    if (type(now_utc) not in (int, float) or not request.frozen_at_utc <= evidence.counted_at_utc <= now_utc
            or not now_utc < request.original_deadline_utc):
        raise ValueError("phase counter evidence cannot refresh the original trusted deadline")
    signature = envelope["signature_hex"]
    if (type(signature) is not str or len(signature) != 128
            or any(character not in "0123456789abcdef" for character in signature)):
        raise ValueError("phase counter signature shape differs")
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    Ed25519PublicKey.from_public_bytes(bytes.fromhex(policy.counter_public_key_hex)).verify(
        bytes.fromhex(signature), SIGNING_DOMAIN + canonical_serialize(envelope["payload"]).encode())
    return evidence


def require_independent_actual_phase_counts_v1(policy, *, initial_request, initial_envelope,
        final_request, final_envelope, now_utc):
    """Both counts must be over independently reconstructed actual input."""
    initial = verify_artifact_phase_count_envelope_v1(policy, initial_request, initial_envelope,
        now_utc=now_utc)
    final = verify_artifact_phase_count_envelope_v1(policy, final_request, final_envelope,
        now_utc=now_utc)
    if (initial_request.input_kind != "actual" or final_request.input_kind != "actual"
            or initial_request.nonce == final_request.nonce
            or initial_request.provider_request_json != final_request.provider_request_json
            or initial_request.provider_wire_digest != final_request.provider_wire_digest
            or initial_request.frozen_material_digest != final_request.frozen_material_digest
            or initial_request.candidate_parameter_digest != final_request.candidate_parameter_digest
            or initial_request.scope_digest != final_request.scope_digest
            or initial_request.original_deadline_utc != final_request.original_deadline_utc
            or final_request.frozen_at_utc < initial_request.frozen_at_utc
            or final.counted_at_utc < initial.counted_at_utc
            or (initial.token_evidence, initial.lower_tokens, initial.upper_tokens) !=
                (final.token_evidence, final.lower_tokens, final.upper_tokens)):
        raise ValueError("phase final count is not an independent nonce over the same actual current input")
    return initial, final


def _unique_json(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("phase counter response repeats a field")
        result[key] = value
    return result


@dataclass(frozen=True, slots=True)
class InstalledArtifactPhaseCounterCommandV1:
    policy: ArtifactPhaseCountPolicyV1

    def __post_init__(self):
        if type(self.policy) is not ArtifactPhaseCountPolicyV1:
            raise TypeError("protected phase counter requires its exact installed policy")

    def count_outside_graph_transaction_v1(self, *, db, request, now_utc):
        if db.in_transaction:
            raise ValueError("artifact phase counting is forbidden inside a Graph transaction")
        policy = self.policy
        require_phase_count_request_policy_v1(policy, request)
        if not request.frozen_at_utc <= now_utc < request.original_deadline_utc:
            raise ValueError("phase counter request expired under its original deadline")
        started = time.monotonic()
        assets = ((policy.tokenizer_path, policy.tokenizer_sha256),
            (policy.applicability_path, policy.applicability_sha256))
        asset_descriptors = []
        with opened_installed_file_v1(policy.executable) as program_fd:
            try:
                with os.fdopen(os.dup(program_fd), "rb") as stream:
                    if hashlib.file_digest(stream, "sha256").hexdigest() != policy.program_sha256:
                        raise ValueError("installed phase counter program changed")
                for path, digest in assets:
                    context = opened_installed_file_v1(path)
                    fd = context.__enter__()
                    asset_descriptors.append((context, fd))
                    with os.fdopen(os.dup(fd), "rb") as stream:
                        if hashlib.file_digest(stream, "sha256").hexdigest() != digest:
                            raise ValueError("installed phase counter tokenizer or applicability asset changed")
                # The consumed applicability object carries no Source content.
                applicability_fd = asset_descriptors[1][1]
                raw_applicability = os.pread(applicability_fd, 65537, 0)
                if (len(raw_applicability) > 65536 or json.loads(raw_applicability, object_pairs_hook=_unique_json)
                        != artifact_phase_applicability_wire_v1(policy)):
                    raise ValueError("phase counter applicability purpose, model or pinned encoding differs")
                encoded = canonical_serialize({"schema": "sylanne.artifact-phase-counter-program.v1",
                    "policy": policy, "request": request,
                    "tokenizer_fd": asset_descriptors[0][1], "applicability_fd": applicability_fd}).encode()
                if len(encoded) > 262144:
                    raise ValueError("phase count program request exceeds the original bounded material")
                with tempfile.TemporaryFile() as source:
                    source.write(encoded); source.seek(0)
                    process = subprocess.Popen([f"/proc/self/fd/{program_fd}"], stdin=source,
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                        pass_fds=(program_fd, *(fd for _, fd in asset_descriptors)), start_new_session=True,
                        env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}, cwd="/")
                    output, error = bytearray(), bytearray()
                    deadline = started + min(policy.timeout_seconds,
                        request.original_deadline_utc - now_utc)
                    try:
                        with selectors.DefaultSelector() as selector:
                            selector.register(process.stdout, selectors.EVENT_READ, output)
                            selector.register(process.stderr, selectors.EVENT_READ, error)
                            while selector.get_map():
                                remaining = deadline - time.monotonic()
                                if remaining <= 0:
                                    raise ValueError("installed phase counter exceeded its original deadline")
                                for key, _mask in selector.select(min(remaining, 0.5)):
                                    chunk = os.read(key.fileobj.fileno(), 8192)
                                    if not chunk:
                                        selector.unregister(key.fileobj); continue
                                    key.data.extend(chunk)
                                    if len(key.data) > 65536:
                                        raise ValueError("installed phase counter response exceeds its bound")
                            if process.wait(timeout=max(0.001, deadline - time.monotonic())) != 0:
                                raise ValueError("installed phase counter failed")
                        value = bytes(output)
                    finally:
                        try:
                            os.killpg(process.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                        process.wait()
                        process.stdout.close(); process.stderr.close()
            finally:
                for context, _fd in reversed(asset_descriptors):
                    context.__exit__(None, None, None)
        envelope = json.loads(value, object_pairs_hook=_unique_json)
        # The caller supplies trusted now again at the short acceptance tx.
        # Elapsed monotonic time here cannot extend the signed original deadline.
        verified_now = now_utc + max(0, time.monotonic() - started)
        verify_artifact_phase_count_envelope_v1(policy, request, envelope, now_utc=verified_now)
        return envelope

def verify_installed_artifact_phase_counter_assets_v1(policy):
    """Reopen installed code and model assets; never execute a counter here."""
    if type(policy) is not ArtifactPhaseCountPolicyV1:
        raise TypeError("actual pinned phase counter policy required")
    for path, digest in ((policy.executable, policy.program_sha256),
            (policy.tokenizer_path, policy.tokenizer_sha256), (policy.applicability_path, policy.applicability_sha256)):
        with opened_installed_file_v1(path) as fd:
            with os.fdopen(os.dup(fd), "rb") as stream:
                if hashlib.file_digest(stream, "sha256").hexdigest() != digest:
                    raise ValueError("current installed phase counter program or model asset changed")
            if path == policy.applicability_path:
                raw = os.pread(fd, 65537, 0)
                if len(raw) > 65536 or json.loads(raw, object_pairs_hook=_unique_json) != artifact_phase_applicability_wire_v1(policy):
                    raise ValueError("current counter asset purpose or model applicability differs")