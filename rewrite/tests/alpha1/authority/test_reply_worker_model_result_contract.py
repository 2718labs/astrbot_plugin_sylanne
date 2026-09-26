"""Reply result read identity remains distinct from first-ingress scope."""

from dataclasses import replace

import pytest

from sylanne3.authority_service.v2_reply_worker_model_result_contract import (
    ReplyWorkerModelResultReadRequestV1, from_wire,
    reply_worker_read_attempt_id_v1, to_wire,
)
from sylanne3.memory_types import source_key
from sylanne3.runtime_contracts import NamespaceId
from rewrite.tests.alpha1.authority.test_v2_worker_result_read_service import _case


def test_reply_read_identity_round_trip_and_first_ingress_scope_rejected():
    consumer = "post-c02-reply-a"
    request = ReplyWorkerModelResultReadRequestV1(
        authority_id="authority-a", authority_namespace="ns-a",
        namespace=NamespaceId("bot-a", "persona-a"),
        installation_id="installation-a", job_id="reply-job-a",
        acquire_operation_id="reply-model-a",
        original_operation_id="reply-budget-a", call_id="reply-call-a",
        binding_digest="a" * 64, model_request_digest="b" * 64,
        consumer_operation_id=consumer,
        read_attempt_id=reply_worker_read_attempt_id_v1(consumer, 1),
        c02_operation_id="c02-a",
        source_ref=source_key("bot-a", "persona-a", "source-a").token,
        source_revision=2, access_revision=3,
        attention_ticket_id="ticket-a", focus_revision=4,
        audience=("user-a",))
    assert from_wire(to_wire(request), ReplyWorkerModelResultReadRequestV1) == request
    with pytest.raises(ValueError, match="scope"):
        replace(request, purpose="first_ingress_c02")
    with pytest.raises(ValueError, match="source"):
        replace(request, source_ref=source_key("other-bot", "persona-a", "source-a").token)


def test_reply_attempt_identity_is_durable_and_conflicting_replay_denied(tmp_path, monkeypatch):
    service, first, core, deletion, guard, execution = _case(tmp_path, monkeypatch)
    try:
        request = ReplyWorkerModelResultReadRequestV1(
            first.authority_id, first.authority_namespace, first.namespace,
            first.installation_id, first.job_id, first.acquire_operation_id,
            first.original_operation_id, first.call_id, first.binding_digest,
            first.model_request_digest, "reply-consumer-a",
            reply_worker_read_attempt_id_v1("reply-consumer-a", 1), "c02-a",
            source_key("bot-a", "persona-a", "source-a").token,
            2, 3, "ticket-a", 4, ("user-a",))
        fences = service._fences
        permit = fences.begin_fence(
            credential="ok", subject="worker-a", holder="holder-a",
            operation="read", operation_id=request.read_attempt_id,
            expected_anchor=fences.current_anchor(
                credential="ok", subject="worker-a"))
        ledger = service._attempts
        assert ledger.begin(request, permit=permit).state == "active"
        assert ledger.read(request).request == request
        assert ledger.begin(request, permit=permit).request == request
        with pytest.raises(Exception, match="identity conflict"):
            ledger.read(replace(request, attention_ticket_id="ticket-b"))
    finally:
        core.close(); deletion.close(); guard.close(); execution.close()
