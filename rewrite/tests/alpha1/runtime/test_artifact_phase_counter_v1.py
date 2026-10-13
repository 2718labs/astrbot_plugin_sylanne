"""Permanent protocol acceptance for a genuinely executed finite local counter.

This fixture establishes only LOCAL_FIXTURE protocol behavior. It does not
qualify any production provider, tokenizer asset or source scope.
"""
from dataclasses import asdict, replace
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import time

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from sylanne3.model_broker.artifact_phase_count_v1 import (
    ArtifactPhaseCountPolicyV1, ArtifactPhaseCountRequestV1, FIXTURE_MODEL, FIXTURE_PROVIDER,
    FIXTURE_RULE, FIXTURE_RULE_ID, FIXTURE_RULE_DIGEST, artifact_phase_counter_policy_from_payload_v1,
    phase_provider_wire_digest_v1,
)
from sylanne3.authority_service.artifact_phase_counter_v1 import (
    InstalledArtifactPhaseCounterCommandV1, artifact_phase_applicability_wire_v1,
    require_independent_actual_phase_counts_v1, verify_artifact_phase_count_envelope_v1,
)
from sylanne3.runtime_contracts import NamespaceId, canonical_serialize


@pytest.mark.skipif(sys.platform != "linux" or os.geteuid() != 0,
    reason="actual protected FD counter fixture requires its Linux administrator-owned installation")
def test_actual_phase_counter_program_signs_finite_input_and_rejects_replay_scope():
    fixture_source = Path(__file__).resolve().parents[3] / "host_tests/alpha1/artifact_phase_counter_fixture_v1.py"
    private = hashlib.sha256(b"sylanne.LOCAL_FIXTURE.phase-count-only.v1").digest()
    public = Ed25519PrivateKey.from_private_bytes(private).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    with tempfile.TemporaryDirectory(prefix="sylanne-phase-counter-fixture-", dir="/opt") as directory:
        root = Path(directory)
        program, tokenizer, applicability = (root / name for name in ("counter", "tokenizer.json", "applicability.json"))
        script = fixture_source.read_text(encoding="utf-8")
        script = "#!" + sys.executable + "\n" + script.split("\n", 1)[1]
        program.write_text(script, encoding="utf-8"); program.chmod(0o700)
        tokenizer.write_text(canonical_serialize(FIXTURE_RULE), encoding="utf-8"); tokenizer.chmod(0o600)
        policy = ArtifactPhaseCountPolicyV1("LOCAL_FIXTURE", NamespaceId("fixture-bot", "fixture-persona"),
            "fixture-installation", "a" * 64, "fixture-profile", FIXTURE_PROVIDER, FIXTURE_MODEL, "1",
            "b" * 64, "sylanne.artifact_draft_phase_template.v2", "fixture-counter", 1,
            str(program), hashlib.sha256(program.read_bytes()).hexdigest(), public,
            str(tokenizer), hashlib.sha256(tokenizer.read_bytes()).hexdigest(), str(applicability), "c" * 64,
            FIXTURE_RULE_ID, FIXTURE_RULE_DIGEST, 10)
        applicability.write_text(canonical_serialize(artifact_phase_applicability_wire_v1(policy)), encoding="utf-8")
        applicability.chmod(0o600)
        policy = replace(policy, applicability_sha256=hashlib.sha256(applicability.read_bytes()).hexdigest())
        body = {"model": FIXTURE_MODEL, "messages": [{"role": "system", "content": "A"},
            {"role": "user", "content": "B"}], "stream": False, "max_completion_tokens": 1}
        wire = canonical_serialize(body)
        now = time.time()
        request = ArtifactPhaseCountRequestV1("actual", policy.digest, policy.namespace, policy.installation_id,
            policy.manifest_digest, policy.profile_id, policy.provider_id, policy.model_id, policy.model_revision,
            policy.provider_config_digest, policy.template_version, "d" * 64, "e" * 64, wire,
            phase_provider_wire_digest_v1(wire), "fixture-owner", 1, "f" * 64,
            (("fixture-source", 1, "1" * 64),), (("fixture-head", 1),), "2" * 64, "5" * 64,
            0, 0, 1, now + 20, "3" * 32, now)
        class OutsideTransaction:
            in_transaction = False
        command = InstalledArtifactPhaseCounterCommandV1(policy)
        initial = command.count_outside_graph_transaction_v1(db=OutsideTransaction(), request=request,
            now_utc=time.time(), allow_local_fixture=True)
        evidence = verify_artifact_phase_count_envelope_v1(policy, request, initial,
            now_utc=time.time(), allow_local_fixture=True)
        assert evidence.source_scope == "LOCAL_FIXTURE"
        # Two one-character messages plus two three-token headers and three
        # assistant-priming tokens. Serialized HTTP JSON bytes do not enter.
        assert (evidence.lower_tokens, evidence.upper_tokens) == (11, 11)
        final_request = replace(request, nonce="4" * 32, frozen_at_utc=time.time())
        final = command.count_outside_graph_transaction_v1(db=OutsideTransaction(), request=final_request,
            now_utc=time.time(), allow_local_fixture=True)
        require_independent_actual_phase_counts_v1(policy, initial_request=request, initial_envelope=initial,
            final_request=final_request, final_envelope=final, now_utc=time.time(), allow_local_fixture=True)
        with pytest.raises(ValueError, match="independent nonce"):
            require_independent_actual_phase_counts_v1(policy, initial_request=request, initial_envelope=initial,
                final_request=request, final_envelope=initial, now_utc=time.time(), allow_local_fixture=True)
        with pytest.raises(ValueError, match="different kind, nonce"):
            verify_artifact_phase_count_envelope_v1(policy, replace(request, input_kind="prospective"), initial,
                now_utc=time.time(), allow_local_fixture=True)
        with pytest.raises(ValueError, match="original trusted deadline"):
            verify_artifact_phase_count_envelope_v1(policy, request, initial,
                now_utc=request.original_deadline_utc, allow_local_fixture=True)
        tampered = json.loads(canonical_serialize(initial))
        tampered["payload"]["lower_tokens"] = tampered["payload"]["upper_tokens"] = 1
        with pytest.raises(InvalidSignature):
            verify_artifact_phase_count_envelope_v1(policy, request, tampered,
                now_utc=time.time(), allow_local_fixture=True)
        with pytest.raises(ValueError, match="production profile"):
            artifact_phase_counter_policy_from_payload_v1(asdict(policy))
        with pytest.raises(ValueError, match="production phase counter"):
            command.count_outside_graph_transaction_v1(db=OutsideTransaction(), request=request, now_utc=time.time())
        class InsideTransaction:
            in_transaction = True
        with pytest.raises(ValueError, match="forbidden inside"):
            command.count_outside_graph_transaction_v1(db=InsideTransaction(), request=request,
                now_utc=time.time(), allow_local_fixture=True)
        tokenizer.write_text("changed", encoding="utf-8")
        with pytest.raises(ValueError, match="asset changed"):
            command.count_outside_graph_transaction_v1(db=OutsideTransaction(), request=request,
                now_utc=time.time(), allow_local_fixture=True)