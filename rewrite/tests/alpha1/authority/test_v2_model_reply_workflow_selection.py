"""Authority selects the installed reply workflow only for its exact scope."""

from dataclasses import replace

import pytest

from rewrite.tests.alpha1.authority.test_v2_model_egress_store import intent
from rewrite.tests.alpha1.model_broker.test_broker import request as broker_request
from sylanne3.authority_service.v2_model_egress_service import AuthorityV2ModelEgressService
from sylanne3.host.authority_profile import (
    AdminModelWorkflowV2, AdminModelWorkflowsV2, installed_model_config_ref,
)
from sylanne3.model_broker.first_ingress_encoding import (
    FIRST_INGRESS_ENCODING_TEMPLATE_VERSION,
)
from sylanne3.model_broker.reply_language import (
    REPLY_TEMPLATE_DIGEST, REPLY_TEMPLATE_VERSION,
)
from sylanne3.model_broker.context_reply import (
    CONTEXT_REPLY_TEMPLATE_DIGEST, CONTEXT_REPLY_TEMPLATE_VERSION,
)
from sylanne3.model_broker.natural_reply import (
    TEMPLATE_DIGEST as NATURAL_GENERATION_TEMPLATE_DIGEST,
    TEMPLATE_VERSION as NATURAL_GENERATION_TEMPLATE_VERSION,
)
from sylanne3.model_broker.natural_review import (
    REVIEW_TEMPLATE_DIGEST, REVIEW_TEMPLATE_VERSION,
)


def _case():
    def workflow(kind, purpose, version, provider, model, digest, tokens, timeout):
        return AdminModelWorkflowV2(
            work_kind=kind, purpose=purpose, template_version=version,
            provider_id=provider, model_id=model,
            provider_config_ref=installed_model_config_ref(provider, model, digest),
            provider_config_digest=digest, audiences=("owner",),
            privacy_tier="private", required_capabilities=("text",),
            timeout_seconds=timeout, max_output_tokens=tokens,
            quote_ceiling={"output_tokens": tokens, "USD": 3})

    workflows = AdminModelWorkflowsV2(
        2,
        workflow("d06.encode_source", "consolidation",
                 FIRST_INGRESS_ENCODING_TEMPLATE_VERSION,
                 "encode-provider", "encode-model", "c" * 64, 64, 10.0),
        workflow("reply", "proposal", REPLY_TEMPLATE_VERSION,
                 "reply-provider", "reply-model", "d" * 64, 32, 20.0),
    )
    base = broker_request()
    envelope = replace(
        base.envelope,
        identity=replace(base.identity, phase="post_c02_reply_model",
                         operation_id="job-operation"),
        authority=replace(base.envelope.authority, actor="worker",
                          issuer_domain="d11", purpose="proposal",
                          worker_fence=7),
    )
    request = replace(
        base, envelope=envelope, call_id="call-1",
        provider_id="reply-provider", model_id="reply-model",
        required_capabilities=frozenset({"text"}),
        prompt_template_digest=REPLY_TEMPLATE_DIGEST,
        timeout_seconds=20.0, max_output_tokens=32)
    original = intent(
        request_digest=request.digest, provider_id="reply-provider",
        model_id="reply-model", provider_config_digest="d" * 64,
        max_output_tokens=32,
        budget_ceiling=(("output_tokens", 32), ("USD", 2)))
    service = object.__new__(AuthorityV2ModelEgressService)
    service._admin_model_policy = workflows
    return service, original, request


def test_exact_reply_workflow_matches_same_installed_profile_snapshot():
    service, original, request = _case()
    assert service._admin_model_matches(original, request)


@pytest.mark.parametrize("change", (
    lambda r: replace(r, envelope=replace(
        r.envelope, identity=replace(r.identity, phase="encode"))),
    lambda r: replace(r, envelope=replace(
        r.envelope, authority=replace(r.envelope.authority,
                                      purpose="consolidation"))),
    lambda r: replace(r, prompt_template_digest="0" * 64),
    lambda r: replace(r, provider_id="encode-provider", model_id="encode-model"),
    lambda r: replace(r, required_capabilities=frozenset({"structured"})),
    lambda r: replace(r, timeout_seconds=19.0),
    lambda r: replace(r, max_output_tokens=33),
    lambda r: replace(r, privacy_tier="public"),
))
def test_reply_scope_and_workflow_mismatches_fail_even_with_updated_request_digest(change):
    service, original, request = _case()
    changed = change(request)
    matching_intent = replace(original, request_digest=changed.digest,
                              provider_id=changed.provider_id,
                              model_id=changed.model_id,
                              max_output_tokens=changed.max_output_tokens)
    assert not service._admin_model_matches(matching_intent, changed)


def test_reply_quote_and_installed_config_mismatch_fail():
    service, original, request = _case()
    assert not service._admin_model_matches(
        replace(original, budget_ceiling=(("output_tokens", 32), ("USD", 4))),
        request)
    assert not service._admin_model_matches(
        replace(original, provider_config_digest="e" * 64), request)


def test_context_reply_uses_only_its_installed_workflow():
    service, original, request = _case()
    workflow = replace(
        service._admin_model_policy.reply,
        work_kind="context_reply",
        template_version=CONTEXT_REPLY_TEMPLATE_VERSION,
        provider_id="context-provider", model_id="context-model",
        provider_config_ref=installed_model_config_ref(
            "context-provider", "context-model", "e" * 64),
        provider_config_digest="e" * 64,
    )
    context_request = replace(
        request,
        envelope=replace(request.envelope,
                         identity=replace(request.identity,
                                          phase="context_reply")),
        provider_id=workflow.provider_id, model_id=workflow.model_id,
        prompt_template_digest=CONTEXT_REPLY_TEMPLATE_DIGEST,
    )
    context_intent = replace(
        original, request_digest=context_request.digest,
        provider_id=workflow.provider_id, model_id=workflow.model_id,
        provider_config_digest=workflow.provider_config_digest,
    )
    assert not service._admin_model_matches(context_intent, context_request)
    service._admin_model_policy = replace(
        service._admin_model_policy, context_reply=workflow)
    assert service._admin_model_matches(context_intent, context_request)
    assert not service._admin_model_matches(
        replace(context_intent, provider_config_digest="f" * 64),
        context_request)
    assert not service._admin_model_matches(
        context_intent,
        replace(context_request, prompt_template_digest=REPLY_TEMPLATE_DIGEST))


@pytest.mark.parametrize("field,version,digest", (
    ("natural_generation", NATURAL_GENERATION_TEMPLATE_VERSION,
     NATURAL_GENERATION_TEMPLATE_DIGEST),
    ("natural_review", REVIEW_TEMPLATE_VERSION, REVIEW_TEMPLATE_DIGEST),
))
def test_natural_workflow_uses_only_its_own_installed_identity(field, version, digest):
    service, original, request = _case()
    workflow = replace(
        service._admin_model_policy.reply,
        work_kind=field, template_version=version,
        provider_id=field + "-provider", model_id=field + "-model",
        provider_config_ref=installed_model_config_ref(
            field + "-provider", field + "-model", "e" * 64),
        provider_config_digest="e" * 64,
    )
    model_request = replace(
        request,
        envelope=replace(request.envelope,
                         identity=replace(request.identity, phase=field)),
        provider_id=workflow.provider_id, model_id=workflow.model_id,
        prompt_template_digest=digest,
    )
    model_intent = replace(
        original, request_digest=model_request.digest,
        provider_id=workflow.provider_id, model_id=workflow.model_id,
        provider_config_digest=workflow.provider_config_digest,
    )
    assert not service._admin_model_matches(model_intent, model_request)
    service._admin_model_policy = replace(
        service._admin_model_policy, **{field: workflow})
    assert service._admin_model_matches(model_intent, model_request)
    assert not service._admin_model_matches(
        model_intent, replace(model_request, prompt_template_digest=REPLY_TEMPLATE_DIGEST))
