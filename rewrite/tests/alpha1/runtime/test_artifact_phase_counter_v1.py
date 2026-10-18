"""Permanent protocol acceptance for a genuinely executed finite local counter.

This fixture establishes only the declared external Mock model protocol. It
qualifies no vendor model or production deployment.
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

from rewrite.host_tests.alpha1.artifact_phase_counter_fixture_v1 import (
    MOCK_V3_RULE as FIXTURE_RULE, MOCK_V3_PROVIDER as FIXTURE_PROVIDER,
    MOCK_V3_MODEL as FIXTURE_MODEL, MOCK_V3_RULE_ID as FIXTURE_RULE_ID,
    MOCK_V3_PRIVATE_KEY,
)
from sylanne3.model_broker.artifact_phase_count_v1 import (
    ArtifactPhaseCountPolicyV1, ArtifactPhaseCountRequestV1, artifact_phase_counter_policy_from_payload_v1,
    phase_provider_wire_digest_v1,
)
from sylanne3.authority_service.artifact_phase_counter_v1 import (
    InstalledArtifactPhaseCounterCommandV1, artifact_phase_applicability_wire_v1,
    require_independent_actual_phase_counts_v1, verify_artifact_phase_count_envelope_v1,
)
from sylanne3.runtime_contracts import NamespaceId, canonical_digest, canonical_serialize


@pytest.mark.skipif(sys.platform != "linux" or os.geteuid() != 0,
    reason="actual protected FD counter fixture requires its Linux administrator-owned installation")
def test_actual_phase_counter_program_signs_finite_input_and_rejects_replay_scope():
    fixture_source = Path(__file__).resolve().parents[3] / "host_tests/alpha1/artifact_phase_counter_fixture_v1.py"
    private = MOCK_V3_PRIVATE_KEY
    public = Ed25519PrivateKey.from_private_bytes(private).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    with tempfile.TemporaryDirectory(prefix="sylanne-phase-counter-fixture-", dir="/opt") as directory:
        root = Path(directory)
        program, tokenizer, applicability = (root / name for name in ("counter", "tokenizer.json", "applicability.json"))
        script = fixture_source.read_text(encoding="utf-8")
        script = "#!" + sys.executable + "\n" + script.split("\n", 1)[1]
        program.write_text(script, encoding="utf-8"); program.chmod(0o700)
        tokenizer.write_text(canonical_serialize(FIXTURE_RULE), encoding="utf-8"); tokenizer.chmod(0o600)
        policy = ArtifactPhaseCountPolicyV1("production", NamespaceId("fixture-bot", "fixture-persona"),
            "fixture-installation", "a" * 64, "fixture-profile", FIXTURE_PROVIDER, FIXTURE_MODEL, "mock-only-v1",
            "b" * 64, "sylanne.artifact_draft_phase_template.v2", "fixture-counter", 1,
            str(program), hashlib.sha256(program.read_bytes()).hexdigest(), public,
            str(tokenizer), hashlib.sha256(tokenizer.read_bytes()).hexdigest(), str(applicability), "c" * 64,
            FIXTURE_RULE_ID, canonical_digest(FIXTURE_RULE), 10)
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
            now_utc=time.time())
        evidence = verify_artifact_phase_count_envelope_v1(policy, request, initial,
            now_utc=time.time())
        assert evidence.source_scope == "production"
        # Two one-character messages plus two three-token headers and three
        # assistant-priming tokens. Serialized HTTP JSON bytes do not enter.
        assert (evidence.lower_tokens, evidence.upper_tokens) == (11, 11)
        final_request = replace(request, nonce="4" * 32, frozen_at_utc=time.time())
        final = command.count_outside_graph_transaction_v1(db=OutsideTransaction(), request=final_request,
            now_utc=time.time())
        require_independent_actual_phase_counts_v1(policy, initial_request=request, initial_envelope=initial,
            final_request=final_request, final_envelope=final, now_utc=time.time())
        with pytest.raises(ValueError, match="independent nonce"):
            require_independent_actual_phase_counts_v1(policy, initial_request=request, initial_envelope=initial,
                final_request=request, final_envelope=initial, now_utc=time.time())
        with pytest.raises(ValueError, match="different kind, nonce"):
            verify_artifact_phase_count_envelope_v1(policy, replace(request, input_kind="prospective"), initial,
                now_utc=time.time())
        with pytest.raises(ValueError, match="original trusted deadline"):
            verify_artifact_phase_count_envelope_v1(policy, request, initial,
                now_utc=request.original_deadline_utc)
        tampered = json.loads(canonical_serialize(initial))
        tampered["payload"]["lower_tokens"] = tampered["payload"]["upper_tokens"] = 1
        with pytest.raises(InvalidSignature):
            verify_artifact_phase_count_envelope_v1(policy, request, tampered,
                now_utc=time.time())
        assert artifact_phase_counter_policy_from_payload_v1(asdict(policy)) == policy
        with pytest.raises(ValueError, match="closed installed"):
            replace(policy, source_scope="LOCAL_FIXTURE")
        class InsideTransaction:
            in_transaction = True
        with pytest.raises(ValueError, match="forbidden inside"):
            command.count_outside_graph_transaction_v1(db=InsideTransaction(), request=request,
                now_utc=time.time())
        tokenizer.write_text("changed", encoding="utf-8")
        with pytest.raises(ValueError, match="asset changed"):
            command.count_outside_graph_transaction_v1(db=OutsideTransaction(), request=request,
                now_utc=time.time())