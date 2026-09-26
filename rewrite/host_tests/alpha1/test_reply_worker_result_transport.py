"""The installed reply read uses the reply-scoped Authority RPC and DTO."""

from types import SimpleNamespace

import pytest

from sylanne3.authority_service.v2_reply_worker_model_result_contract import (
    ReplyWorkerModelResultReadRequestV1, reply_worker_read_attempt_id_v1,
    to_wire,
)
from sylanne3.host.mtls_transport import MtlsAuthorityTransport
from sylanne3.memory_types import source_key
from sylanne3.runtime_contracts import NamespaceId


@pytest.mark.asyncio
async def test_reply_selection_uses_exact_installed_scope():
    request = ReplyWorkerModelResultReadRequestV1(
        "authority-a", "namespace-a", NamespaceId("bot-a", "persona-a"),
        "installation-a", "job-a", "acquire-a", "original-a", "call-a",
        "a" * 64, "b" * 64, "consumer-a",
        reply_worker_read_attempt_id_v1("consumer-a", 1), "c02-a",
        source_key("bot-a", "persona-a", "source-a").token,
        1, 1, "ticket-a", 1, ("conversation-a",),
    )
    calls = []

    async def rpc(*args, **kwargs):
        calls.append((args, kwargs))
        return {"selected_request": to_wire(request),
                "channel_binding_sha256": "c" * 64}

    transport = object.__new__(MtlsAuthorityTransport)
    transport._content_rpc = rpc
    grant = SimpleNamespace(authority_id="authority-a",
                            installation_id="installation-a")
    assert await transport.reply_worker_model_result_select_attempt_v1(
        object(), object(), grant, namespace="namespace-a",
        first_request=request) == request
    assert calls[0][0][2] == "reply_worker_model_result_select_attempt_v1"
    assert calls[0][0][3] == {
        "namespace": "namespace-a", "read_request": to_wire(request)}
    with pytest.raises(RuntimeError, match="identity"):
        await transport.reply_worker_model_result_select_attempt_v1(
            object(), object(), grant, namespace="different",
            first_request=request)
    assert len(calls) == 1
