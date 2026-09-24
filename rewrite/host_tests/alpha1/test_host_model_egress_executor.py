"""Executor control-flow fixture; the paired RPC has a separate real TLS test."""

import hashlib
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
from sylanne3.runtime.restore_anchor import RestoreAnchor
from sylanne3.runtime_contracts import InstallationGrantV2


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
