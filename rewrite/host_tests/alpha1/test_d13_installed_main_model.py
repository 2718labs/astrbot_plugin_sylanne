"""D13 copies the installed conversation model, not optional natural stages."""

from dataclasses import replace

from rewrite.host_tests.alpha1.test_authority_profile import (
    _workflow_profile_payload,
)

from sylanne3.host.authority_profile import (
    AdminInstallationBundle, AdminModelWorkflowsV2,
    _model_workflows_from_payload, _policy_from_payload,
    installed_model_config_ref,
)
from sylanne3.runtime_contracts import NATURAL_REPLY_GENERATION_WORKFLOW_V2
from sylanne3.runtime_context import RuntimeContext


def test_d13_installation_uses_reply_main_identity() -> None:
    payload = _workflow_profile_payload()
    policy = _policy_from_payload(payload)
    workflows = _model_workflows_from_payload(payload)
    assert workflows is not None
    natural = replace(
        workflows.reply, work_kind="natural_generation",
        template_version=NATURAL_REPLY_GENERATION_WORKFLOW_V2,
        provider_id="other-provider", model_id="other-model",
        provider_config_digest="d" * 64,
        provider_config_ref=installed_model_config_ref(
            "other-provider", "other-model", "d" * 64),
    )
    workflows = AdminModelWorkflowsV2(
        2, workflows.encode, workflows.reply, natural_generation=natural)
    runtime = object.__new__(RuntimeContext)
    runtime._v2_policy = policy
    runtime._v2_model_bundle = AdminInstallationBundle(
        None, policy, b"signing", b"resource", model_workflows=workflows)

    installed = runtime.installed_d13_main_model_v1()
    assert installed is not None
    assert (installed.installation_id, installed.provider_id,
            installed.model_id, installed.provider_config_digest,
            installed.max_output_tokens) == (
                policy.installation_id, workflows.reply.provider_id,
                workflows.reply.model_id,
                workflows.reply.provider_config_digest,
                workflows.reply.max_output_tokens)
    assert installed.provider_id != natural.provider_id
    runtime._v2_model_bundle = replace(runtime._v2_model_bundle,
                                       model_workflows=None)
    assert runtime.installed_d13_main_model_v1() is None
