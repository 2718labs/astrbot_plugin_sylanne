"""A paid DTO normalizes provider JSON without losing terminal identity."""

from dataclasses import replace
import json
import sqlite3

import pytest

from rewrite.tests.alpha1.authority.test_context_reply_original_verifier import (
    _prepared_graph,
)
from sylanne3.authority_service.v2_context_reply_result_contract import (
    ContextReplyPaidResultReadV2, ContextReplyResultReadRequestV1,
    from_wire, to_wire,
)
from sylanne3.authority_service.v2_model_egress_contract import (
    ModelEgressObservationV1, ModelTerminalReceiptV2,
)
from sylanne3.model_broker.context_reply import (
    OUTPUT_SCHEMA, parse_context_reply_output_v1,
)
from sylanne3.runtime.context_reply_job_v2 import (
    read_original_context_reply_preparation_v2,
)
from sylanne3.runtime_contracts import canonical_serialize


def test_paid_result_normalizes_provider_json_and_rejects_content_tamper(tmp_path):
    path = tmp_path / "graph.sqlite"
    request = _prepared_graph(path)
    with sqlite3.connect(path) as db:
        db.execute("BEGIN")
        saved = read_original_context_reply_preparation_v2(
            db, request.namespace, request.c02_operation_id, request.source_ref)
    assert saved is not None
    payload = {
        "spans": [{
            "source_quote": "ok", "access_revision": 1,
            "access_ref": saved.frozen_request.input.evidence[0].access_ref.ref,
            "source_revision": 1, "source_ref": request.source_ref,
            "end": 2, "start": 0,
        }],
        "body": "ok", "schema": OUTPUT_SCHEMA,
    }
    provider_json = json.dumps(payload, indent=2)
    normalized = canonical_serialize(json.loads(provider_json))
    assert normalized != provider_json
    parsed = parse_context_reply_output_v1(provider_json, saved.frozen_request)
    observation = ModelEgressObservationV1(
        request.authority_id, request.authority_namespace, "worker-a",
        request.acquire_operation_id, request.call_id, "b" * 64,
        "completed", canonical_serialize({"text": provider_json}), (), (), None)
    receipt = ModelTerminalReceiptV2(
        "a" * 64, request.call_id, "b" * 64, "c" * 64,
        observation.digest, "sha256:" + "d" * 64,
        request.installation_id, "e" * 64)
    paid = ContextReplyPaidResultReadV2(
        saved.seal, saved.frozen_request, request.read_attempt_id, 1,
        request.read_attempt_id, "f" * 64, "b" * 64, receipt,
        observation, saved.read_versions, saved.seal.graph_guard_digest,
        parsed.canonical_output, parsed.output_digest,
        "paid_current_source_verified_hold")
    assert paid.body == "ok"
    assert from_wire(to_wire(paid), ContextReplyPaidResultReadV2) == paid
    assert from_wire(to_wire(request), ContextReplyResultReadRequestV1) == request
    with pytest.raises(ValueError, match="state or digest"):
        replace(paid, canonical_output=parsed.canonical_output.replace("ok", "no"))
    changed = replace(observation, result_json=canonical_serialize({
        "text": json.dumps(payload | {"body": "no"})}))
    with pytest.raises(ValueError, match="identity differs"):
        replace(paid, provider_observation=changed)
    refusal_json = json.dumps({"schema": OUTPUT_SCHEMA, "body": "", "spans": []})
    refusal = replace(observation, result_json=canonical_serialize({
        "text": refusal_json}))
    refusal_parsed = parse_context_reply_output_v1(
        refusal_json, saved.frozen_request)
    no_reply = replace(
        paid, provider_observation=refusal,
        terminal_receipt=replace(receipt, observation_digest=refusal.digest),
        canonical_output=refusal_parsed.canonical_output,
        output_digest=refusal_parsed.output_digest, status="no_reply_hold")
    assert no_reply.body == "" and no_reply.status == "no_reply_hold"
