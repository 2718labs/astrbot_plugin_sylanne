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
