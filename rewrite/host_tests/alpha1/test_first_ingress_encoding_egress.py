"""Frozen V2 encoding request reaches the admitted host call once."""

import asyncio
from dataclasses import replace
from types import MethodType, SimpleNamespace

import pytest

from rewrite.host_tests.alpha1 import test_astrbot_model_call as model_fixture
from rewrite.host_tests.alpha1.test_host_model_egress_executor import fixture_values
from sylanne3.authority_service.v2_model_egress_contract import (
    ModelEgressDraftV1, ModelEgressRecoveryV1,
)
from sylanne3.authority_service.v2_contract import FencePermitV2
from sylanne3.host.model_egress_executor import HostModelEgressExecutor
from sylanne3.host.model_terminal_cost_port import InstalledModelTerminalCostPort
from sylanne3.memory_types import SourceRecord, access_key, source_key
from sylanne3.model_broker.first_ingress_encoding import (
    FIRST_INGRESS_ENCODING_TEMPLATE_DIGEST,
    FIRST_INGRESS_ENCODING_TEMPLATE_VERSION,
    build_first_ingress_encoding_payload,
)
from sylanne3.runtime.encoding_call_binding import prepare_binding
from sylanne3.runtime.restore_anchor import RestoreAnchor
from sylanne3.runtime_contracts import canonical_digest


def frozen_case(host, bundle):
    namespace = bundle.installation_policy.namespace
    source = SourceRecord(
        "source-1", "a remembered sentence", "speaker-1", "reported",
        "reported", None, 1.0, "source-1", ("owner",), ("consolidation",),
    )
    source_token = source_key(*namespace.as_tuple, source.source_id).token
    payload, _ = build_first_ingress_encoding_payload(source)
    base = model_fixture.call_request()
    identity = replace(
        base.identity, operation_id="acquire-1", phase="encode",
        canonical_input_digest=canonical_digest({"input_refs": [source_token]}),
    )
    authority_context = replace(
        base.envelope.authority, actor="worker", issuer_domain="d11",
        owner_scope=("activity",), purpose="consolidation",
        worker_fence=1,
    )
    guard = replace(
        base.envelope.version_guard,
        read_versions=(
            replace(base.envelope.version_guard.read_versions[0],
                    key=source_key(*namespace.as_tuple, source.source_id), revision=1),
            replace(base.envelope.version_guard.read_versions[0],
                    key=access_key(*namespace.as_tuple, source.source_id), revision=1),
        ), query_epochs=(),
    )
    envelope = replace(
        base.envelope, identity=identity, authority=authority_context,
        version_guard=guard, input_refs=(source_token,),
        source_qualification=replace(base.envelope.source_qualification,
                                     source_refs=(source_token,)),
        parent_budget_lease_ref="budget-1", causation=("reserve-1",),
    )
    request = replace(
        base, envelope=envelope, required_capabilities=frozenset({"text"}),
        prompt_template_digest=FIRST_INGRESS_ENCODING_TEMPLATE_DIGEST,
        payload=payload,
    )
    context = SimpleNamespace(
        acquire_operation_id="acquire-1",
        job=SimpleNamespace(
            work_kind="d06.encode_source", operation_id="reserve-1",
            budget_ref="budget-1", fence=1,
            lease_expires_utc="2099-01-01T00:00:00Z",
        ), monotonic_deadline=envelope.monotonic_deadline,
        character_interval_ref=envelope.character_interval_ref,
        deadline_utc=envelope.deadline_utc, clock_epoch="clock-1",
    )
    model = bundle.model_workflows.encode
    binding = prepare_binding(
        namespace, "job-1", source, 1, 1, "budget-1", "reserve-1",
        request, prompt_template_version=FIRST_INGRESS_ENCODING_TEMPLATE_VERSION,
        provider_config_ref=model.provider_config_ref,
        provider_config_digest=model.provider_config_digest,
        production_context=context,
    )
    draft = ModelEgressDraftV1(
        authority_id="authority", namespace=bundle.installation_policy.authority_namespace,
        subject="worker", operation_id="acquire-1", call_id=request.call_id,
        request_digest=request.digest, job_id="job-1", worker_fence=1,
        source_refs=(source.source_id,), source_revisions=((source.source_id, 1),),
        access_revisions=((source.source_id, 1),), access_epoch=0, delete_epoch=0,
        graph_epoch=1, graph_revision=1, authority_activation_generation=1,
        authority_revocation_epoch=0, authority_deletion_seq=0,
        authority_execution_seq=0, budget_lease_id="budget-1",
        budget_reservation_operation_id="reserve-1",
        budget_reservation_digest="a" * 64,
        budget_ceiling=(("output_tokens", 64),),
        provider_id=model.provider_id, model_id=model.model_id,
        provider_config_digest=model.provider_config_digest,
        max_output_tokens=request.max_output_tokens,
    )
    anchor = RestoreAnchor(
        "authority", draft.namespace, 1, "deletion", 0, "genesis",
        "execution", 0, "genesis", 0, "proof")
    return binding, draft, anchor, request


@pytest.mark.asyncio
async def test_frozen_v2_binding_prepares_then_dispatches_once():
    host = model_fixture.AstrBotModelCallTests(
        methodName="test_one_http_request_on_host_loop_with_usage")
    await host.asyncSetUp()
    try:
        bundle, adapter, _ = host.v2_adapters()
        binding, draft, anchor, request = frozen_case(host, bundle)
        _old, _old_anchor, _old_permit, _old_admission, grant, authority = (
            fixture_values(host, request))
        executor = HostModelEgressExecutor(
            authority=authority, bundle=bundle, grant=grant, adapter=adapter)
        assert executor._frozen_encoding_request(binding, draft, anchor).digest == request.digest
        prepared = []

        async def prepare(self, *args, **kwargs):
            prepared.append(kwargs["draft"])
            intent = replace(
                _old, **{name: getattr(draft, name)
                         for name in draft.__dataclass_fields__},
                anchor_digest=canonical_digest(anchor),
            )
            permit = FencePermitV2(
                "authority", draft.namespace, "worker", "holder", 1,
                "model_egress", draft.operation_id, intent.fence_token,
                intent.fence_epoch, intent.fence_revision, anchor)
            return ModelEgressRecoveryV1(intent, "prepared"), permit

        authority.model_prepare_fenced_v1 = MethodType(prepare, authority)
        # The existing executor fixture exercises the admitted HTTP exchange.
        # Here the returned terminal is a content-free marker for orchestration.
        calls = []

        async def execute(*, intent, expected_anchor, request):
            calls.append((intent, request))
            return None

        executor.execute_once = execute
        first = await executor.execute_frozen_encoding_once(
            binding=binding, draft=draft, expected_anchor=anchor)
        assert first is not None and first.intent.operation_id == "acquire-1"
        assert first.terminal is None
        assert len(prepared) == len(calls) == 1
        assert calls[0][1].digest == binding.model_request_digest
        assert await executor.execute_frozen_encoding_once(
            binding=binding, draft=draft, expected_anchor=anchor) is None
        assert len(prepared) == len(calls) == 1
    finally:
        await host.asyncTearDown()


@pytest.mark.asyncio
async def test_frozen_v2_binding_rejects_changed_original_without_prepare():
    host = model_fixture.AstrBotModelCallTests(
        methodName="test_one_http_request_on_host_loop_with_usage")
    await host.asyncSetUp()
    try:
        bundle, adapter, _ = host.v2_adapters()
        binding, draft, anchor, request = frozen_case(host, bundle)
        _old, _old_anchor, _old_permit, _old_admission, grant, authority = (
            fixture_values(host, request))
        executor = HostModelEgressExecutor(
            authority=authority, bundle=bundle, grant=grant, adapter=adapter)
        assert await executor.execute_frozen_encoding_once(
            binding=binding, draft=replace(draft, request_digest="b" * 64),
            expected_anchor=anchor) is None
        assert host.requests == []
    finally:
        await host.asyncTearDown()


@pytest.mark.asyncio
async def test_original_terminal_cost_port_preserves_fence_permit():
    host = model_fixture.AstrBotModelCallTests(
        methodName="test_one_http_request_on_host_loop_with_usage")
    await host.asyncSetUp()
    try:
        bundle, _adapter, _ = host.v2_adapters()
        bundle = replace(bundle, tls_profile=SimpleNamespace(timeout_seconds=1.0))
        request = model_fixture.call_request()
        intent, _anchor, permit, admission, grant, authority = fixture_values(
            host, request)
        receipt = object()
        observed = ModelEgressRecoveryV1(intent, "observed", "f" * 64)

        async def terminal(self, *args, **kwargs):
            assert kwargs["intent"] is intent
            return observed, permit, admission, receipt

        authority.model_terminal_fact_v2 = MethodType(terminal, authority)
        port = InstalledModelTerminalCostPort(
            client=authority, bundle=bundle, grant=grant,
            owner_loop=asyncio.get_running_loop())
        assert await asyncio.to_thread(port, intent) == (
            observed, permit, admission, receipt)
        with pytest.raises(RuntimeError, match="graph worker"):
            port(intent)
    finally:
        await host.asyncTearDown()
