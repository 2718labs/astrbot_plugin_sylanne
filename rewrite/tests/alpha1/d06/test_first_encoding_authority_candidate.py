"""D06 boundary tests: original result bytes may only produce held candidates."""

import json
from dataclasses import replace

import pytest

from sylanne3.authority_service.v2_model_egress_contract import (
    ModelEgressObservationV1, ModelTerminalReceiptV2,
)
from sylanne3.authority_service.v2_model_result_read_contract import ModelResultReadV1
from sylanne3.authority_service.v2_worker_model_result_contract import (
    WorkerModelResultReadRequestV1, WorkerModelResultReadV1,
)
from sylanne3.model_broker.first_ingress_encoding import build_first_ingress_encoding_payload
from sylanne3.runtime_contracts import NamespaceId


def test_authority_result_boundary_rejects_changed_original_source():
    """The pure boundary must not accept a response for different source bytes."""
    from sylanne3.domains.d06.pipeline import validate_first_encoding_authority_result
    from sylanne3.memory_types import SourceRecord

    original = SourceRecord("source-1", "A reported promise", "alice", "reported",
                            "reported", None, 2.0, "family-1", ("owner",), ("context",))
    changed = replace(original, text="A different promise")
    payload, template_digest = build_first_ingress_encoding_payload(original)
    frozen_request = {
        "schema": "sylanne.first-ingress-encoding-call.v2",
        "source_id": original.source_id,
        "source_revision": 1,
        "access_revision": 1,
        "call_id": "call-1",
        "model_request_digest": "a" * 64,
        "prompt_template_digest": template_digest,
        "payload": payload,
        "worker_fence": 1,
        "work_kind": "d06.encode_source",
        "envelope": {"identity": {"operation_id": "operation-1"}},
    }
    observation = ModelEgressObservationV1(
        "authority-1", "namespace-1", "worker-1", "operation-1", "call-1",
        "a" * 64, "completed", json.dumps({"text": json.dumps({
            "event_summary": "A promise was reported", "quoted_details": [
                {"quote": "promise", "salience": 0.8}],
            "possible_meanings": ["trust"], "possible_feelings": ["relief"],
        })}, sort_keys=True, separators=(",", ":")), (), (), None,
    )
    terminal = ModelTerminalReceiptV2(
        "b" * 64, "call-1", "a" * 64, "c" * 64,
        observation.digest, "sha256:" + "d" * 64, "installation-1", "e" * 64,
    )
    read = ModelResultReadV1("call-1", observation, terminal)
    assert validate_first_encoding_authority_result(
        read, frozen_request, original, source_revision=1, access_revision=1,
    ) == observation.result
    with pytest.raises(ValueError, match="original source"):
        validate_first_encoding_authority_result(
            read, frozen_request, changed, source_revision=1, access_revision=1,
        )
    with pytest.raises(ValueError, match="request digest"):
        validate_first_encoding_authority_result(
            read, {**frozen_request, "model_request_digest": "f" * 64},
            original, source_revision=1, access_revision=1,
        )
    with pytest.raises(ValueError, match="worker fence"):
        validate_first_encoding_authority_result(
            read, {**frozen_request, "worker_fence": 0}, original,
            source_revision=1, access_revision=1,
        )
    with pytest.raises(ValueError, match="access revisions"):
        validate_first_encoding_authority_result(
            read, frozen_request, original, source_revision=1, access_revision=2,
        )
    with pytest.raises(ValueError, match="call identity"):
        validate_first_encoding_authority_result(
            read, {**frozen_request, "call_id": "another-call"}, original,
            source_revision=1, access_revision=1,
        )

    worker_request = WorkerModelResultReadRequestV1(
        "authority-1", "namespace-1", NamespaceId("bot", "persona"),
        "installation-1", "job-1", "operation-1", "ingress-1", "call-1",
        "b" * 64, "a" * 64, "consumer-1", "read-attempt-1",
    )
    worker_read = WorkerModelResultReadV1(worker_request, observation, terminal)
    assert validate_first_encoding_authority_result(
        worker_read, frozen_request, original, source_revision=1, access_revision=1,
    ) == observation.result
    with pytest.raises(ValueError, match="request digest"):
        validate_first_encoding_authority_result(
            worker_read, {**frozen_request, "model_request_digest": "f" * 64},
            original, source_revision=1, access_revision=1,
        )


def test_authority_result_boundary_accepts_v3_only_with_committed_baseline_proof():
    from sylanne3.domains.d06.pipeline import validate_first_encoding_authority_result
    from sylanne3.graph_types import AtomKey, Owner
    from sylanne3.memory_types import SourceRecord, access_key, source_key
    from sylanne3.runtime_contracts import NamespaceId, canonical_digest, canonical_serialize
    from sylanne3.runtime.encoding_call_binding import EncodingCallBinding

    original = SourceRecord("source-v3", "A reported promise", "alice", "reported",
                            "reported", None, 2.0, "family-1", ("owner",), ("context",))
    payload, template_digest = build_first_ingress_encoding_payload(original)
    namespace = NamespaceId("bot", "persona")
    baseline_key = AtomKey(Owner("persona", "bot", "persona"),
                           "d04.encoding_baseline.v1", "baseline-1")
    baseline = {
        "baseline_ref": baseline_key.token,
        "baseline_revision": 3,
        "operation_id": "baseline-operation",
        "bundle_digest": "b" * 64,
        "graph_incarnation": "incarnation-1",
        "graph_epoch": 7,
    }
    read_versions = [
        {"key": json.loads(canonical_serialize(source_key("bot", "persona", original.source_id))),
         "revision": 1},
        {"key": json.loads(canonical_serialize(access_key("bot", "persona", original.source_id))),
         "revision": 1},
        {"key": json.loads(canonical_serialize(baseline_key)), "revision": 3},
    ]
    envelope = {
        "identity": {"operation_id": "acquire-1"},
        "authority": {"purpose": "consolidation"},
        "version_guard": {"read_versions": read_versions},
    }
    request = {
        "schema": "sylanne.first-ingress-encoding-call.v3",
        "namespace": list(namespace.as_tuple), "job_id": "job-1",
        "source_id": original.source_id, "source_revision": 1, "access_revision": 1,
        "budget_lease_id": "lease-1", "budget_reservation_operation_id": "operation-1",
        "acquire_operation_id": "acquire-1", "original_operation_id": "operation-1",
        "worker_fence": 2, "worker_lease_expires_utc": "2030-01-01T00:00:00Z",
        "work_kind": "d06.encode_source", "clock_epoch": "clock-1", "envelope": envelope,
        "baseline": baseline, "call_id": "call-1", "provider_id": "provider-1",
        "model_id": "model-1", "required_capabilities": [], "privacy_tier": "private",
        "prompt_template_digest": template_digest, "payload": payload,
        "timeout_seconds": 10, "max_output_tokens": 100,
    }
    request["model_request_digest"] = canonical_digest({
        "envelope": envelope, "call_id": request["call_id"],
        "provider_id": request["provider_id"], "model_id": request["model_id"],
        "purpose": envelope["authority"]["purpose"],
        "required_capabilities": request["required_capabilities"],
        "privacy_tier": request["privacy_tier"], "template": template_digest,
        "payload": payload, "timeout_seconds": 10, "max_output_tokens": 100,
    })
    binding = EncodingCallBinding(
        namespace, "job-1", original.source_id, 1, 1, "lease-1", "operation-1",
        canonical_digest(request), request["model_request_digest"], "call-1",
        canonical_serialize(request),
    )
    observation = ModelEgressObservationV1(
        "authority-1", "namespace-1", "worker-1", "operation-1", "call-1",
        request["model_request_digest"], "completed", json.dumps({"text": json.dumps({
            "event_summary": "A promise was reported", "quoted_details": [
                {"quote": "promise", "salience": 0.8}],
            "possible_meanings": ["trust"], "possible_feelings": ["relief"],
        })}, sort_keys=True, separators=(",", ":")), (), (), None,
    )
    terminal = ModelTerminalReceiptV2(
        "b" * 64, "call-1", request["model_request_digest"], "c" * 64,
        observation.digest, "sha256:" + "d" * 64, "installation-1", "e" * 64,
    )
    read = ModelResultReadV1("call-1", observation, terminal)
    assert validate_first_encoding_authority_result(
        read, request, original, source_revision=1, access_revision=1,
        binding=binding,
    ) == observation.result

    bad_baseline = {**request, "baseline": {**baseline, "bundle_digest": "f" * 64}}
    with pytest.raises(ValueError, match="baseline"):
        validate_first_encoding_authority_result(
            read, bad_baseline, original, source_revision=1, access_revision=1,
            binding=binding,
        )
    bad_proof = {**request, "envelope": {**envelope, "version_guard": {
        "read_versions": [*read_versions[:-1], {**read_versions[-1], "revision": 4}],
    }}}
    with pytest.raises(ValueError, match="baseline"):
        validate_first_encoding_authority_result(
            read, bad_proof, original, source_revision=1, access_revision=1,
            binding=binding,
        )
    with pytest.raises(ValueError, match="binding differs"):
        validate_first_encoding_authority_result(
            read, {**request, "model_request_digest": "f" * 64}, original,
            source_revision=1, access_revision=1,
            binding=binding,
        )
