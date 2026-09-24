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
