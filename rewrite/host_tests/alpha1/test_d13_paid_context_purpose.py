"""Installed-purpose gates only; no fabricated local model admission or I/O."""
from dataclasses import replace

import pytest

from rewrite.tests.alpha1.model_broker.test_d13_precompression import _planned, _envelope
from sylanne3.host.astrbot_model_call import AstrBotModelProvider
from sylanne3.host.authority_profile import (
    AdminInstallationBundle, AdminModelWorkflowV2, AdminModelWorkflowsV2,
    installed_model_config_ref,
)
from sylanne3.installation_policy import AdminInstallationPolicy
from sylanne3.model_broker.broker import ModelProviderDescriptor
from sylanne3.model_broker.d13_precompression import (
    freeze_d13_precompression_request_v1, issue_unadmitted_d13_model_request_v1,
)
from sylanne3.model_broker.reply_language import REPLY_TEMPLATE_VERSION
from sylanne3.runtime.budget import BudgetLease
from sylanne3.runtime.issuers import BudgetLeaseGrant
from sylanne3.runtime.d13_technical_policy import AdminD13PaidPrecompressionPolicyV1
from sylanne3.runtime.d13_installed_paid_purpose_v1 import (
    installed_d13_paid_context_model_v1, installed_d13_paid_context_request_v1,
)
from sylanne3.runtime_contracts import NamespaceId


def _case():
    window, plan, main = _planned()
    limits = {"input_tokens": 8192, "output_tokens": 2048}
    lease = BudgetLease("root", None, *window.namespace.as_tuple, "USD", limits,
                        {}, {}, {}, 1, "active")
    grant = BudgetLeaseGrant("grant", 1, *window.namespace.as_tuple, "root", "USD", limits,
        ("reply", "d06.encode_source", "d13.precompress.paid.v1"), 4102444800.0, "budget-policy")
    installation = AdminInstallationPolicy(
        window.namespace, "authority-ns", main.installation_id, "b" * 64, "holder", "authority",
        "c" * 64, "scheme", "operator", "policy", lease, grant)
    model = AdminModelWorkflowV2(
        "reply", main.provider_id, main.model_id,
        installed_model_config_ref(main.provider_id, main.model_id, main.provider_config_digest),
        main.provider_config_digest, "proposal", ("owner",), "private", REPLY_TEMPLATE_VERSION,
        ("text",), 10.0, main.max_output_tokens, {"output_tokens": main.max_output_tokens})
    workflows = AdminModelWorkflowsV2(
        2, replace(model, work_kind="d06.encode_source", purpose="consolidation"), model)
    d13 = AdminD13PaidPrecompressionPolicyV1(
        window.namespace, main.installation_id, "grant", 1, "root", 1000,
        {"input_tokens": 8192, "output_tokens": main.max_output_tokens}, 300, 8, "d13-resource", main)
    bundle = AdminInstallationBundle(None, installation, b"test-d11", b"test-d02",
        model_workflows=workflows, d13_paid_precompression=d13)
    original = _envelope(window, plan)
    envelope = replace(original, authority=replace(original.authority, purpose="context"),
                       parent_budget_lease_ref="root")
    request = issue_unadmitted_d13_model_request_v1(
        envelope, freeze_d13_precompression_request_v1(window, plan, main),
        call_id="call:d13", timeout_seconds=10.0, privacy_tier="private")
    adapter = object.__new__(AstrBotModelProvider)
    adapter._installation_bundle, adapter._admin_model = bundle, model
    adapter._descriptor = ModelProviderDescriptor(
        model.provider_id, "astrbot-openai-official-v1", model.model_id,
        frozenset({"text"}), frozenset({"context"}), frozenset({"private"}),
        model.provider_config_ref, "unknown", False, False)
    return bundle, model, request, adapter


def test_real_d13_context_is_distinct_from_main_reply_purpose():
    bundle, model, request, adapter = _case()
    assert model.purpose == "proposal" and request.envelope.authority.purpose == "context"
    assert installed_d13_paid_context_model_v1(bundle, model)
    assert installed_d13_paid_context_request_v1(bundle, model, request)
    assert adapter._request_allowed(request)
    adapter._descriptor = replace(adapter._descriptor, purposes=frozenset({"proposal"}))
    assert not adapter._request_allowed(request)


@pytest.mark.parametrize("mutation", (
    "absent_policy", "root_kind", "root_ceiling", "grant_id", "lease_id",
    "installation", "provider", "model", "config", "namespace", "purpose",
    "output", "deadline", "phase", "worker", "template", "payload",
))
def test_d13_context_cannot_be_selected_by_caller_phase(mutation):
    bundle, model, request, adapter = _case()
    d13, policy = bundle.d13_paid_precompression, bundle.installation_policy
    if mutation == "absent_policy":
        bundle = replace(bundle, d13_paid_precompression=None)
    elif mutation == "root_kind":
        bundle = replace(bundle, installation_policy=replace(policy, root_grant=replace(
            policy.root_grant, allowed_work_kinds=("reply", "d06.encode_source"))))
    elif mutation == "root_ceiling":
        bundle = replace(bundle, installation_policy=replace(policy, root_grant=replace(
            policy.root_grant, max_ceiling={"output_tokens": 2048, "input_tokens": 1})))
    elif mutation in {"grant_id", "lease_id"}:
        bundle = replace(bundle, d13_paid_precompression=replace(
            d13, quote_ceiling=dict(d13.quote_ceiling), **{mutation: "wrong"}))
    elif mutation in {"installation", "provider", "model", "config"}:
        field = {"installation": "installation_id", "provider": "provider_id",
                 "model": "model_id", "config": "provider_config_digest"}[mutation]
        main = replace(d13.selected_main, **{field: "d" * 64 if mutation == "config" else "other"})
        kwargs = {"selected_main": main, "quote_ceiling": dict(d13.quote_ceiling)}
        if mutation == "installation":
            kwargs["installation_id"] = main.installation_id
        bundle = replace(bundle, d13_paid_precompression=replace(d13, **kwargs))
    elif mutation in {"namespace", "purpose", "worker"}:
        field, value = {"namespace": ("namespace", NamespaceId("other", "persona")),
                        "purpose": ("purpose", "proposal"), "worker": ("worker_fence", None)}[mutation]
        request = replace(request, envelope=replace(request.envelope,
            authority=replace(request.envelope.authority, **{field: value})))
    elif mutation == "output":
        request = replace(request, max_output_tokens=request.max_output_tokens - 1)
    elif mutation == "deadline":
        request = replace(request, envelope=replace(request.envelope,
            deadline_utc=policy.root_grant.valid_until_utc + 1))
    elif mutation == "phase":
        request = replace(request, envelope=replace(request.envelope,
            identity=replace(request.identity, phase="reply")))
    elif mutation == "template":
        request = replace(request, prompt_template_digest="e" * 64)
    else:
        request = replace(request, payload={"system_prompt": "wrong", "prompt": "{}"})
    adapter._installation_bundle = bundle
    assert not adapter._request_allowed(request)


def test_equal_but_distinct_main_workflow_is_not_installed_identity():
    bundle, model, _request, _adapter = _case()
    assert not installed_d13_paid_context_model_v1(bundle, replace(model))


@pytest.mark.asyncio
@pytest.mark.parametrize('mutation', ('authorized', 'input_over', 'output_over', 'unknown_dimension', 'cross_grant', 'cross_lease', 'root_bound', 'module_disabled'))
async def test_executor_checks_the_same_finite_d13_authorization(mutation, tmp_path, monkeypatch):
    import asyncio
    from astrbot.api.star import Context
    from sylanne3.host.authority_client import AuthorityClient, AuthoritySelection
    from sylanne3.runtime_contracts import InstallationGrantV2
    from rewrite.tests.alpha1.authority.test_v2_model_egress_store import intent as model_intent
    from sylanne3.host.model_egress_executor import HostModelEgressExecutor
    from sylanne3.runtime.restore_anchor import RestoreAnchor
    bundle, model, request, adapter = _case()
    bound = dict(bundle.d13_paid_precompression.quote_ceiling)
    if mutation == 'input_over':
        bound['input_tokens'] += 1
    elif mutation == 'output_over':
        bound['output_tokens'] += 1
    elif mutation == 'unknown_dimension':
        bound['USD'] = 1
    elif mutation in {'cross_grant', 'cross_lease'}:
        field = 'grant_id' if mutation == 'cross_grant' else 'lease_id'
        bundle = replace(bundle, d13_paid_precompression=replace(bundle.d13_paid_precompression,
            quote_ceiling=dict(bound), **{field: 'other'}))
    elif mutation == 'root_bound':
        policy = bundle.installation_policy
        bundle = replace(bundle, installation_policy=replace(policy, root_grant=replace(policy.root_grant,
            max_ceiling={'input_tokens': bound['input_tokens'] - 1, 'output_tokens': bound['output_tokens']})))
    context = Context(asyncio.Queue(), {}, None, None, None, None, None, None, None, None, None)
    adapter = AstrBotModelProvider(context=context, host_loop=asyncio.get_running_loop(),
        trusted_umo="d13-authorization-boundary", descriptor=adapter._descriptor,
        admin_model=model, installation_bundle=bundle)
    original = model_intent(call_id=request.call_id, operation_id=request.identity.operation_id,
        request_digest=request.digest, provider_id=model.provider_id, model_id=model.model_id,
        provider_config_digest=model.provider_config_digest, max_output_tokens=request.max_output_tokens,
        budget_lease_id=request.envelope.parent_budget_lease_ref, budget_ceiling=tuple(sorted(bound.items())))
    anchor = RestoreAnchor('authority', original.namespace, 1, 'deletion', 0, 'genesis', 'execution', 0, 'genesis', 0, 'proof')
    attempts = []
    async def unavailable(*args, **kwargs):
        attempts.append(kwargs['intent'])
        raise RuntimeError('isolated Authority boundary; no admission or provider')
    client = AuthorityClient(AuthoritySelection(), package_root=tmp_path, data_dir=tmp_path)
    monkeypatch.setattr(client, "model_admit_dispatch_once_v2", unavailable)
    policy = bundle.installation_policy
    grant = InstallationGrantV2(policy.expected_authority_id, 'mtls:sha256:' + 'a' * 64,
        policy.administrator_holder, policy.installation_id, policy.manifest_digest, 'policy', 'v2', 'b' * 64)
    from sylanne3.runtime.local_module_admission_v1 import LocalModuleAdmissionV1, LocalModuleAdmissionDeniedV1
    executor = HostModelEgressExecutor(authority=client, bundle=bundle, grant=grant, adapter=adapter,
        local_module_admission=LocalModuleAdmissionV1((True,) * 12 + (mutation != 'module_disabled',)))
    if mutation == 'module_disabled':
        assert installed_d13_paid_context_request_v1(bundle, model, request)
        assert adapter._request_allowed(request)
        with pytest.raises(LocalModuleAdmissionDeniedV1, match='local_module_disabled:d13') as refused:
            executor._require_new_model_attempt_v1(request)
        assert refused.value.reason_code == 'local_module_disabled'
    # The public executor catches this precise refusal and returns its existing
    # no-terminal result; neither denied modules nor unavailable Authority send.
    assert await executor.execute_once(intent=original, expected_anchor=anchor, request=request) is None
    assert attempts == ([original] if mutation == 'authorized' else [])


@pytest.mark.parametrize('version', (2, 3))
def test_d13_executor_retains_exact_installed_main_slot(version, tmp_path):
    from sylanne3.host.authority_client import AuthorityClient, AuthoritySelection
    from sylanne3.host.model_egress_executor import HostModelEgressExecutor
    from sylanne3.host.model_workflows_v3 import AdminModelWorkflowsV3
    from sylanne3.runtime_contracts import InstallationGrantV2
    bundle, model, _request, adapter = _case()
    if version == 3:
        bundle = replace(bundle, model_workflows=AdminModelWorkflowsV3(3, bundle.model_workflows.encode, model))
        adapter._installation_bundle = bundle
    policy = bundle.installation_policy
    grant = InstallationGrantV2(policy.expected_authority_id, 'mtls:sha256:' + 'a' * 64,
        policy.administrator_holder, policy.installation_id, policy.manifest_digest, 'policy', 'v2', 'b' * 64)
    client = AuthorityClient(AuthoritySelection(), package_root=tmp_path, data_dir=tmp_path)
    executor = HostModelEgressExecutor(authority=client, bundle=bundle, grant=grant, adapter=adapter)
    assert executor._adapter._admin_model is bundle.model_workflows.reply
    adapter._admin_model = replace(model)
    with pytest.raises(ValueError):
        HostModelEgressExecutor(authority=client, bundle=bundle, grant=grant, adapter=adapter)
