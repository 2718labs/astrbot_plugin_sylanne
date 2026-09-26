"""Executor control-flow fixture; the paired RPC has a separate real TLS test."""

import hashlib
from dataclasses import asdict, replace
from pathlib import Path
from types import MethodType

import pytest

from rewrite.host_tests.alpha1 import test_astrbot_model_call as model_fixture
from rewrite.tests.alpha1.authority.test_v2_model_egress_store import intent as model_intent
from sylanne3.authority_service.v2_contract import FencePermitV2
from sylanne3.authority_service.v2_model_egress_contract import (
    ModelAdmissionV2, ModelEgressRecoveryV1, ModelTerminalReceiptV2,
)
from sylanne3.host.authority_client import AuthorityClient, AuthoritySelection
from sylanne3.host.model_egress_executor import HostModelEgressExecutor
from sylanne3.model_broker.first_ingress_encoding import (
    FIRST_INGRESS_ENCODING_TEMPLATE_DIGEST,
)
from sylanne3.runtime.restore_anchor import RestoreAnchor
from sylanne3.runtime.first_ingress_c02_identity import (
    first_ingress_c02_consumer_operation_id_v1,
)
from sylanne3.runtime.first_ingress_recovery import FirstIngressRecoveryItemV1
from sylanne3.runtime.original_model_result_context import OriginalModelResultContextV1
from sylanne3.runtime_contracts import InstallationGrantV2, canonical_digest


def fixture_values(host, request):
    original = model_intent(
        call_id=request.call_id, operation_id=request.identity.operation_id,
        request_digest=request.digest,
        provider_config_digest=host.admin_model.provider_config_digest,
        max_output_tokens=request.max_output_tokens,
        budget_ceiling=(("output_tokens", 128),))
    anchor = RestoreAnchor(
        "authority", original.namespace, 1, "deletion", 0, "genesis",
        "execution", 0, "genesis", 0, "proof")
    permit = FencePermitV2(
        "authority", original.namespace, "worker", "holder", 1,
        "model_egress", original.operation_id, original.fence_token,
        original.fence_epoch, original.fence_revision, anchor)
    admission = ModelAdmissionV2(
        hashlib.sha256(request.call_id.encode()).hexdigest(),
        original.authority_id, original.namespace, original.subject,
        original.operation_id, original.call_id, original.request_digest,
        original.provider_config_digest, "install", "a" * 64,
        "default", "a" * 64, host.adapter.host_incarnation)
    grant = InstallationGrantV2(
        "authority", "mtls:sha256:" + "a" * 64, "holder", "install",
        "a" * 64, "policy", "v2", "b" * 64)
    authority = AuthorityClient(
        AuthoritySelection(), package_root=Path.cwd(), data_dir=Path.cwd())
    return original, anchor, permit, admission, grant, authority


@pytest.mark.asyncio
async def test_executor_reports_only_actual_completed_response():
    host = model_fixture.AstrBotModelCallTests(methodName="test_one_http_request_on_host_loop_with_usage")
    await host.asyncSetUp()
    try:
        request = model_fixture.call_request()
        intent, anchor, permit, admission, grant, authority = fixture_values(host, request)
        observed = []

        async def admit(self, *args, **kwargs):
            observed.append("admit")
            return ModelEgressRecoveryV1(intent, "dispatch_started"), permit, admission

        async def complete(self, *args, **kwargs):
            report = kwargs["report"]
            observed.append(report)
            observation = report.observation_for(intent)
            receipt = ModelTerminalReceiptV2(
                admission.admission_id, intent.call_id, intent.request_digest,
                report.digest, observation.digest, "sha256:" + "c" * 64,
                admission.installation_id, admission.host_incarnation)
            return (ModelEgressRecoveryV1(
                intent, "observed", observation.digest,
                report.usage, report.cost), permit, receipt)

        authority.model_admit_dispatch_once_v2 = MethodType(admit, authority)
        authority.model_complete_observed_v2 = MethodType(complete, authority)
        executor = HostModelEgressExecutor(
            authority=authority, bundle=host.bundle, grant=grant, adapter=host.adapter)
        receipt = await executor.execute_once(
            intent=intent, expected_anchor=anchor, request=request)
        assert receipt is not None and receipt.report_digest == observed[1].digest
        assert observed[0] == "admit"
        assert observed[1].result_json == '{"text":"hello"}'
        assert len(host.requests) == 1
    finally:
        await host.asyncTearDown()


@pytest.mark.asyncio
async def test_v2_executor_rejects_borrowed_workflow_quote_before_authority():
    host = model_fixture.AstrBotModelCallTests(
        methodName="test_one_http_request_on_host_loop_with_usage")
    await host.asyncSetUp()
    try:
        bundle, encoder, replier = host.v2_adapters()
        request = model_fixture.call_request()
        request = replace(request, envelope=replace(
            request.envelope, authority=replace(
                request.envelope.authority, purpose="consolidation")),
            prompt_template_digest=FIRST_INGRESS_ENCODING_TEMPLATE_DIGEST)
        intent, anchor, _permit, _admission, grant, authority = fixture_values(
            host, request)
        called = []

        async def forbidden_admit(self, *args, **kwargs):
            called.append(True)
            raise AssertionError("borrowed quote must not reach Authority")

        authority.model_admit_dispatch_once_v2 = MethodType(
            forbidden_admit, authority)
        encoder_executor = HostModelEgressExecutor(
            authority=authority, bundle=bundle, grant=grant, adapter=encoder)
        assert encoder._request_allowed(request)
        assert await encoder_executor.execute_once(
            intent=intent, expected_anchor=anchor, request=request) is None
        assert not called and not host.requests
        replier_executor = HostModelEgressExecutor(
            authority=authority, bundle=bundle, grant=grant, adapter=replier)
        assert await replier_executor.execute_once(
            intent=intent, expected_anchor=anchor, request=request) is None
        assert not called and not host.requests
    finally:
        await host.asyncTearDown()


@pytest.mark.asyncio
async def test_executor_holds_on_uncertain_admit_or_incomplete_http():
    host = model_fixture.AstrBotModelCallTests(methodName="test_one_http_request_on_host_loop_with_usage")
    await host.asyncSetUp()
    try:
        request = model_fixture.call_request()
        intent, anchor, permit, admission, grant, authority = fixture_values(host, request)
        async def lost_admit(self, *args, **kwargs):
            raise RuntimeError("admit response lost")
        authority.model_admit_dispatch_once_v2 = MethodType(lost_admit, authority)
        executor = HostModelEgressExecutor(
            authority=authority, bundle=host.bundle, grant=grant, adapter=host.adapter)
        assert await executor.execute_once(
            intent=intent, expected_anchor=anchor, request=request) is None
        assert host.requests == []

        async def admitted(self, *args, **kwargs):
            return ModelEgressRecoveryV1(intent, "dispatch_started"), permit, admission
        async def forbidden_complete(self, *args, **kwargs):
            raise AssertionError("incomplete response cannot be reported")
        authority.model_admit_dispatch_once_v2 = MethodType(admitted, authority)
        authority.model_complete_observed_v2 = MethodType(forbidden_complete, authority)
        host.status = 500
        assert await executor.execute_once(
            intent=intent, expected_anchor=anchor, request=request) is None
        assert len(host.requests) == 1
        assert await executor.execute_once(
            intent=intent, expected_anchor=anchor, request=request) is None
        assert len(host.requests) == 1
    finally:
        await host.asyncTearDown()


@pytest.mark.asyncio
async def test_lost_terminal_reply_holds_without_second_http():
    host = model_fixture.AstrBotModelCallTests(methodName="test_one_http_request_on_host_loop_with_usage")
    await host.asyncSetUp()
    try:
        request = model_fixture.call_request()
        intent, anchor, permit, admission, grant, authority = fixture_values(host, request)
        admits = 0
        reports = 0

        async def admit(self, *args, **kwargs):
            nonlocal admits
            admits += 1
            if admits > 1:
                raise RuntimeError("admission already consumed")
            return ModelEgressRecoveryV1(intent, "dispatch_started"), permit, admission

        async def lost_complete(self, *args, **kwargs):
            nonlocal reports
            reports += 1
            raise RuntimeError("terminal reply lost")

        authority.model_admit_dispatch_once_v2 = MethodType(admit, authority)
        authority.model_complete_observed_v2 = MethodType(lost_complete, authority)
        executor = HostModelEgressExecutor(
            authority=authority, bundle=host.bundle, grant=grant, adapter=host.adapter)
        assert await executor.execute_once(
            intent=intent, expected_anchor=anchor, request=request) is None
        assert len(host.requests) == 1 and reports == 1
        assert await executor.execute_once(
            intent=intent, expected_anchor=anchor, request=request) is None
        assert len(host.requests) == 1 and reports == 1 and admits == 2
    finally:
        await host.asyncTearDown()


@pytest.mark.asyncio
@pytest.mark.parametrize("observed", [True, False])
async def test_acquired_recovery_reads_observed_terminal_without_model_admission(
        observed):
    host = model_fixture.AstrBotModelCallTests(
        methodName="test_one_http_request_on_host_loop_with_usage")
    await host.asyncSetUp()
    try:
        bundle, encoder, _ = host.v2_adapters()
        request = model_fixture.call_request()
        original, anchor, permit, admission, grant, authority = fixture_values(
            host, request)
        anchor = replace(
            anchor, namespace=bundle.installation_policy.authority_namespace)
        original = replace(
            original, namespace=anchor.namespace, subject=grant.subject,
            anchor_digest=canonical_digest(asdict(anchor)),
            access_revisions=((original.source_refs[0], 3),),
            acquire_operation_id=original.operation_id,
            binding_digest="e" * 64)
        context = OriginalModelResultContextV1(
            bundle.installation_policy.namespace, original.authority_id,
            original.namespace, grant.installation_id, "incarnation-1",
            original.graph_revision + 7, original.graph_epoch + 2,
            original.access_epoch, original.delete_epoch,
            original.job_id, original.operation_id,
            original.budget_reservation_operation_id,
            original.call_id, original.binding_digest, original.request_digest,
            original.source_refs[0], original.source_revisions[0][1],
            original.access_revisions[0][1], original.subject,
            original.worker_fence, "2030-01-01T00:00:00Z", anchor)
        consumer_id = first_ingress_c02_consumer_operation_id_v1(
            namespace=context.namespace, authority_id=context.authority_id,
            authority_namespace=context.authority_namespace,
            installation_id=context.installation_id, job_id=context.job_id,
            acquire_operation_id=context.acquire_operation_id,
            original_operation_id=context.original_operation_id,
            call_id=context.call_id, binding_digest=context.binding_digest,
            model_request_digest=context.model_request_digest)
        item = FirstIngressRecoveryItemV1(
            bundle.installation_policy.namespace, grant.installation_id,
            original.job_id, original.operation_id,
            original.budget_reservation_operation_id, original.call_id,
            original.binding_digest, original.request_digest, consumer_id,
            "running", original.subject, original.worker_fence,
            "2030-01-01T00:00:00Z", "original_fence", None, None)
        terminal = ModelTerminalReceiptV2(
            admission.admission_id, original.call_id,
            original.request_digest, "a" * 64, "b" * 64,
            "sha256:" + "c" * 64, grant.installation_id,
            admission.host_incarnation)
        calls = []

        async def lookup(self, *args, **kwargs):
            calls.append("lookup")
            assert kwargs["lookup"].acquire_operation_id == item.acquire_operation_id
            return original

        async def terminal_fact(self, *args, **kwargs):
            calls.append("terminal")
            assert kwargs["intent"] == original
            if observed:
                return (ModelEgressRecoveryV1(original, "observed", "b" * 64),
                        permit, admission, terminal)
            return (ModelEgressRecoveryV1(original, "dispatch_started"),
                    permit, admission, None)

        async def forbidden_admit(self, *args, **kwargs):
            raise AssertionError("recovery must not admit a second model call")

        authority.model_original_intent_lookup_v1 = MethodType(lookup, authority)
        authority.model_terminal_fact_v2 = MethodType(terminal_fact, authority)
        authority.model_admit_dispatch_once_v2 = MethodType(
            forbidden_admit, authority)
        executor = HostModelEgressExecutor(
            authority=authority, bundle=bundle, grant=grant, adapter=encoder)
        result = await executor.recover_observed_frozen_encoding(
            context=context, original=item)
        assert calls == ["lookup", "terminal"]
        assert result is not None
        assert result.terminal == (terminal if observed else None)
        assert host.requests == []
    finally:
        await host.asyncTearDown()
