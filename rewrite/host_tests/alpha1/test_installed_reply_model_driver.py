"""Reply host handoff remains source-bound and never retries an unknown call."""

from dataclasses import asdict, replace
import json
from types import MethodType, SimpleNamespace

import pytest

from rewrite.host_tests.alpha1 import test_astrbot_model_call as model_fixture
from rewrite.tests.alpha1.authority.test_v2_model_egress_store import intent as model_intent
from rewrite.tests.alpha1.model.test_reply_language import _inputs
from sylanne3.authority_service.v2_model_egress_contract import (
    ModelEgressDraftV1, ModelEgressObservationV1, ModelEgressRecoveryV1,
    ModelTerminalReceiptV2,
)
from sylanne3.authority_service.v2_contract import FencePermitV2
from sylanne3.authority_service.v2_reply_worker_model_result_contract import (
    ReplyWorkerModelResultReadRequestV1, ReplyWorkerModelResultReadV1,
    reply_worker_read_attempt_id_v1,
)
from sylanne3.domains.d07 import AttentionTicket
from sylanne3.graph_types import AtomKey, GraphVersion, Owner
from sylanne3.host.installed_reply_model_driver import (
    execute_or_recover_reply_model_v1, freeze_reply_model_preparation_v1,
    prepare_and_run_installed_reply_model_v1,
    parse_authority_reply_observation_v1, reply_model_operation_id_v1,
    read_and_parse_installed_reply_with_receipt_v1,
)
from sylanne3.host.post_c02_reply_driver import post_c02_reply_operation_id
from sylanne3.host.model_egress_executor import HostModelEgressExecutor
from sylanne3.model_broker.reply_language import REPLY_TEMPLATE_VERSION
from sylanne3.runtime.restore_anchor import RestoreAnchor
from sylanne3.runtime_contracts import CommitReceipt, canonical_digest, canonical_serialize


def _attention(source_ref):
    return AttentionTicket(
        "attention-1", "inbound", None, source_ref, "interaction",
        0.5, 0.5, 0.5, 0.5, 0.5, 0.0, 0.0, 0.0, 0.0,
        1, 10.0, True, True, ())


def _preparation(bundle):
    source, base = _inputs()
    c02_op = "c02-operation"
    owner = Owner("event", "bot", "persona", source.source.source_id)
    c02 = CommitReceipt(
        "committed", c02_op, "a" * 64, "activity", None, 1, (),
        (GraphVersion(AtomKey(owner, "memory.episode.v1", "episode"), 1),
         GraphVersion(AtomKey(owner, "memory.subjective_trace.v2", "trace"), 1)),
        (), (), ())
    operation_id = reply_model_operation_id_v1(c02_op, source.source_ref)
    envelope = replace(
        base.envelope,
        identity=replace(base.identity, operation_id=operation_id),
        authority=replace(base.envelope.authority, actor="worker", worker_fence=7),
        causation=(c02_op,))
    anchor = RestoreAnchor(
        "authority", "bot/persona", 1, "deletion", 0, "genesis",
        "execution", 0, "genesis", 0, "proof")
    frozen = bundle.model_workflows.reply
    request_digest = None
    from sylanne3.model_broker.reply_language import freeze_installed_reply_request_v1
    installed = freeze_installed_reply_request_v1(envelope, source, bundle=bundle)
    request_digest = installed.request.digest
    intent = model_intent(
        namespace="bot/persona",
        operation_id=operation_id, call_id=installed.request.call_id,
        request_digest=request_digest, subject="worker", worker_fence=7,
        anchor_digest=canonical_digest(asdict(anchor)),
        source_refs=(source.source.source_id,),
        source_revisions=((source.source.source_id, source.source_revision),),
        access_revisions=((source.source.source_id, source.access_revision),),
        access_epoch=envelope.version_guard.access_epoch,
        delete_epoch=envelope.version_guard.delete_epoch,
        budget_lease_id=envelope.parent_budget_lease_ref,
        budget_ceiling=(("output_tokens", frozen.max_output_tokens),),
        provider_id=frozen.provider_id, model_id=frozen.model_id,
        provider_config_digest=frozen.provider_config_digest,
        max_output_tokens=frozen.max_output_tokens)
    intent = replace(intent, acquire_operation_id=operation_id,
                     binding_digest="f" * 64)
    prepared = freeze_reply_model_preparation_v1(
        c02_receipt=c02, envelope=envelope, source=source,
        attention=_attention(source.source_ref), focus_revision=1, intent=intent,
        expected_anchor=anchor, bundle=bundle)
    return prepared


@pytest.mark.asyncio
async def test_reply_host_recovers_original_before_any_new_send():
    host = model_fixture.AstrBotModelCallTests(
        methodName="test_one_http_request_on_host_loop_with_usage")
    await host.asyncSetUp()
    try:
        bundle, _, _ = host.v2_adapters()
        prepared = _preparation(bundle)
        executor = object.__new__(HostModelEgressExecutor)
        executor._bundle = bundle
        executor._grant = object()
        executor._adapter = SimpleNamespace(_admin_model=bundle.model_workflows.reply)
        events = []
        intent = prepared.intent
        permit = FencePermitV2(
            intent.authority_id, intent.namespace, intent.subject, "holder",
            1, "model_egress", intent.operation_id, intent.fence_token,
            intent.fence_epoch, intent.fence_revision, prepared.expected_anchor)

        async def recover_fence(_self, _bundle, _grant, *, intent):
            events.append(("fence", intent.call_id))
            return ModelEgressRecoveryV1(intent, "prepared"), permit

        executor._authority = SimpleNamespace(
            model_recover_fenced_v1=MethodType(recover_fence, object()))

        async def recover(_self, intent):
            events.append(("recover", intent.call_id))
            return None

        async def execute(_self, *, intent, expected_anchor, request):
            events.append(("execute", request.call_id))
            assert request.digest == intent.request_digest
            return None

        executor.recover_original_terminal = MethodType(recover, executor)
        executor.execute_once = MethodType(execute, executor)
        hold = await execute_or_recover_reply_model_v1(prepared, executor=executor)
        assert hold.status == "unresolved" and hold.terminal is None
        assert events == [("recover", prepared.intent.call_id),
                          ("fence", prepared.intent.call_id),
                          ("execute", prepared.intent.call_id)]
        events.clear()
        async def started_fence(_self, _bundle, _grant, *, intent):
            events.append(("fence", intent.call_id))
            return ModelEgressRecoveryV1(intent, "dispatch_started"), permit

        executor._authority.model_recover_fenced_v1 = MethodType(
            started_fence, object())
        hold = await execute_or_recover_reply_model_v1(prepared, executor=executor)
        assert hold.status == "unresolved"
        assert events == [("recover", intent.call_id), ("fence", intent.call_id)]
        events.clear()
        terminal = ModelTerminalReceiptV2(
            "a" * 64, prepared.intent.call_id, prepared.intent.request_digest,
            "b" * 64, "c" * 64, "sha256:" + "d" * 64,
            "install", "e" * 64)

        async def recovered(_self, intent):
            events.append(("recover", intent.call_id))
            return terminal

        executor.recover_original_terminal = MethodType(recovered, executor)
        result = await execute_or_recover_reply_model_v1(prepared, executor=executor)
        assert result.status == "observed_pending_result_read"
        assert result.terminal == terminal
        assert events == [("recover", prepared.intent.call_id)]
    finally:
        await host.asyncTearDown()


@pytest.mark.asyncio
async def test_completed_authority_observation_yields_only_source_claim_candidate():
    host = model_fixture.AstrBotModelCallTests(
        methodName="test_one_http_request_on_host_loop_with_usage")
    await host.asyncSetUp()
    try:
        bundle, _, replier = host.v2_adapters()
        prepared = _preparation(bundle)
        assert bundle.model_workflows.reply.template_version == REPLY_TEMPLATE_VERSION
        host.completion["choices"][0]["message"]["content"] = json.dumps({
            "schema": "sylanne.d09.source_reply_output.v1",
            "body": "你好", "spans": [
                {"start": 0, "end": 2, "source_quote": "你好"}],
        }, ensure_ascii=False)
        response = await replier._invoke_on_host(prepared.installed.request)
        assert response.status == "completed" and len(host.requests) == 1
        result = response.result
        intent = prepared.intent
        observation = ModelEgressObservationV1(
            intent.authority_id, intent.namespace, intent.subject,
            intent.operation_id, intent.call_id, intent.request_digest,
            "completed", canonical_serialize(result), (), (), "provider-call")
        terminal = ModelTerminalReceiptV2(
            "a" * 64, intent.call_id, intent.request_digest,
            "b" * 64, observation.digest, "sha256:" + "d" * 64,
            "install", "e" * 64)
        candidate = parse_authority_reply_observation_v1(
            prepared, observation=observation, terminal=terminal)
        assert candidate.status == "candidate"
        assert candidate.claims[0].source_refs == (prepared.source.source_ref,)
        with pytest.raises(ValueError):
            parse_authority_reply_observation_v1(
                prepared, observation=observation,
                terminal=replace(terminal, observation_digest="f" * 64))
    finally:
        await host.asyncTearDown()


@pytest.mark.asyncio
async def test_reply_result_read_keeps_the_verified_authority_receipt():
    host = model_fixture.AstrBotModelCallTests(
        methodName="test_one_http_request_on_host_loop_with_usage")
    await host.asyncSetUp()
    try:
        bundle, _, _ = host.v2_adapters()
        prepared = _preparation(bundle)
        intent = prepared.intent
        consumer_id = post_c02_reply_operation_id(
            prepared.c02_receipt.operation_id, prepared.source.source_ref)
        request = ReplyWorkerModelResultReadRequestV1(
            intent.authority_id, intent.namespace,
            prepared.envelope.authority.namespace,
            bundle.installation_policy.installation_id, intent.job_id,
            intent.operation_id, intent.budget_reservation_operation_id,
            intent.call_id, intent.binding_digest, intent.request_digest,
            consumer_id, reply_worker_read_attempt_id_v1(consumer_id, 1),
            prepared.c02_receipt.operation_id, prepared.source.source_ref,
            prepared.source.source_revision, prepared.source.access_revision,
            prepared.attention.ticket_id, prepared.focus_revision,
            prepared.envelope.authority.audience)
        observation = ModelEgressObservationV1(
            intent.authority_id, intent.namespace, intent.subject,
            intent.operation_id, intent.call_id, intent.request_digest,
            "completed", canonical_serialize({"text": json.dumps({
                "schema": "sylanne.d09.source_reply_output.v1",
                "body": "你好", "spans": [
                    {"start": 0, "end": 2, "source_quote": "你好"}],
            }, ensure_ascii=False)}), (), (), "provider-call")
        terminal = ModelTerminalReceiptV2(
            "a" * 64, intent.call_id, intent.request_digest,
            "b" * 64, observation.digest, "sha256:" + "d" * 64,
            request.installation_id, "e" * 64)
        response = ReplyWorkerModelResultReadV1(request, observation, terminal)
        calls = []

        class Authority:
            async def reply_worker_model_result_select_attempt_v1(
                self, _bundle, _grant, *, first_request,
            ):
                calls.append("select")
                assert first_request == request
                return request

            async def reply_worker_model_result_read_v1(
                self, _bundle, _grant, *, read_request,
            ):
                calls.append("read")
                assert read_request == request
                return response

        executor = object.__new__(HostModelEgressExecutor)
        executor._bundle = bundle
        executor._grant = SimpleNamespace(installation_id=request.installation_id)
        executor._authority = Authority()
        read = await read_and_parse_installed_reply_with_receipt_v1(
            prepared, executor=executor, read_request=request, terminal=terminal)
        assert read is not None and read.result_read is response
        assert read.candidate.body == "你好"
        assert calls == ["select", "read"]
    finally:
        await host.asyncTearDown()


@pytest.mark.asyncio
async def test_graph_draft_requires_authority_model_permit_before_reply_attempt():
    host = model_fixture.AstrBotModelCallTests(
        methodName="test_one_http_request_on_host_loop_with_usage")
    await host.asyncSetUp()
    try:
        bundle, _, _ = host.v2_adapters()
        prepared = _preparation(bundle)
        intent = prepared.intent
        draft = ModelEgressDraftV1.from_intent(intent)
        executor = object.__new__(HostModelEgressExecutor)
        executor._bundle = bundle
        executor._grant = SimpleNamespace(
            authority_id=intent.authority_id,
            installation_id=bundle.installation_policy.installation_id)
        executor._adapter = SimpleNamespace(_admin_model=bundle.model_workflows.reply)
        permit = FencePermitV2(
            intent.authority_id, intent.namespace, intent.subject, "holder", 1,
            "model_egress", intent.operation_id, intent.fence_token,
            intent.fence_epoch, intent.fence_revision, prepared.expected_anchor)
        calls = []

        async def prepare(_self, _bundle, _grant, *, draft, expected_anchor):
            calls.append("prepare")
            return ModelEgressRecoveryV1(intent, "prepared"), permit

        async def recover(_self, intent):
            calls.append("recover")
            return None

        async def recover_fence(_self, _bundle, _grant, *, intent):
            calls.append("recover_fence")
            return ModelEgressRecoveryV1(intent, "prepared"), permit

        async def execute(_self, *, intent, expected_anchor, request):
            calls.append("execute")
            assert request.digest == intent.request_digest
            return None

        executor._authority = SimpleNamespace(
            model_prepare_fenced_v1=MethodType(prepare, object()),
            model_recover_fenced_v1=MethodType(recover_fence, object()))
        executor.recover_original_terminal = MethodType(recover, executor)
        executor.execute_once = MethodType(execute, executor)
        run = await prepare_and_run_installed_reply_model_v1(
            c02_receipt=prepared.c02_receipt,
            envelope=prepared.envelope, source=prepared.source,
            attention=prepared.attention, focus_revision=prepared.focus_revision,
            draft=draft, expected_anchor=prepared.expected_anchor,
            executor=executor)
        assert run is not None and run.terminal.status == "unresolved"
        assert calls == ["prepare", "recover", "recover_fence", "execute"]
        calls.clear()
        assert await prepare_and_run_installed_reply_model_v1(
            c02_receipt=prepared.c02_receipt,
            envelope=prepared.envelope, source=prepared.source,
            attention=prepared.attention, focus_revision=prepared.focus_revision,
            draft=replace(draft, request_digest="0" * 64),
            expected_anchor=prepared.expected_anchor,
            executor=executor) is None
        assert calls == []
    finally:
        await host.asyncTearDown()
