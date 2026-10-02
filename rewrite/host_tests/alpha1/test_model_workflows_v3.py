"""Installed profile parsing/budget closure; no provider or paid execution."""
from copy import deepcopy
from dataclasses import fields

import pytest

from test_authority_profile import (
    authority_profile, _workflow_profile_payload, _model_workflow_payload,
)
from sylanne3.host.model_workflows_v3 import (
    AdminModelWorkflowsV3, LIFE_CONTENT_WORK_KIND, LIFE_CONTENT_TEMPLATE_VERSION,
)
from sylanne3.model_broker.contact_expression_v2 import (
    GENERATION_TEMPLATE_VERSION, REVIEW_TEMPLATE_VERSION,
)
from sylanne3.domains.d01.production_operations_v1 import plain_v1


def profile():
    raw = _workflow_profile_payload()
    raw["model_workflows"]["version"] = 3
    for name, template in (("contact_generation", GENERATION_TEMPLATE_VERSION),
                           ("contact_review", REVIEW_TEMPLATE_VERSION)):
        raw["model_workflows"][name] = _model_workflow_payload(name, "proposal", template)
        raw["installation_policy"]["root_grant"]["allowed_work_kinds"].append(name)
    return raw


def test_profile_v3_contact_pair_and_independent_life_slot():
    raw = profile()
    authority_profile._policy_from_payload(raw)
    parsed = authority_profile._model_workflows_from_payload(raw)
    assert type(parsed) is AdminModelWorkflowsV3
    assert parsed.life_content is None
    raw["model_workflows"]["life_content"] = _model_workflow_payload(
        LIFE_CONTENT_WORK_KIND, "consolidation", LIFE_CONTENT_TEMPLATE_VERSION)
    life = raw["model_workflows"]["life_content"]
    # Contact's conversation-model restriction is not borrowed for Life.
    life["model_id"] = "independent-content-model"
    life["provider_config_ref"] = authority_profile.installed_model_config_ref(
        life["provider_id"], life["model_id"], life["provider_config_digest"])
    raw["installation_policy"]["root_grant"]["allowed_work_kinds"].append(LIFE_CONTENT_WORK_KIND)
    authority_profile._policy_from_payload(raw)
    assert authority_profile._model_workflows_from_payload(raw).life_content.model_id == life["model_id"]


@pytest.mark.parametrize("change", (
    lambda p: p["model_workflows"].update(version=True),
    lambda p: p["model_workflows"].update(version=4),
    lambda p: p["model_workflows"].pop("contact_review"),
    lambda p: p["model_workflows"].update(unregistered_worker={}),
    lambda p: p["model_workflows"]["contact_generation"].update(template_version="sylanne.d09.contact_generation.v1"),
    lambda p: p["model_workflows"]["contact_review"].update(purpose="consolidation"),
    lambda p: p["model_workflows"]["contact_generation"].update(quote_ceiling={"output_tokens": True}),
    lambda p: p["installation_policy"]["root_grant"]["allowed_work_kinds"].remove("contact_generation"),
    lambda p: p["installation_policy"]["root_grant"].update(max_ceiling={"output_tokens": 1}),
))
def test_profile_v3_rejects_changed_or_ungranted_phase(change):
    raw = profile()
    change(raw)
    with pytest.raises(ValueError):
        authority_profile._policy_from_payload(raw)


def test_profile_v3_rejects_other_contact_provider_identity():
    raw = profile()
    item = raw["model_workflows"]["contact_review"]
    item["model_id"] = "other"
    item["provider_config_ref"] = authority_profile.installed_model_config_ref(
        item["provider_id"], item["model_id"], item["provider_config_digest"])
    with pytest.raises(ValueError, match="exact installed workflow"):
        authority_profile._policy_from_payload(raw)


def test_disabled_life_slot_does_not_inherit_contact_grant():
    raw = profile()
    raw["model_workflows"]["life_content"] = _model_workflow_payload(
        LIFE_CONTENT_WORK_KIND, "consolidation", LIFE_CONTENT_TEMPLATE_VERSION)
    with pytest.raises(ValueError, match="own root grant"):
        authority_profile._policy_from_payload(raw)


def test_version2_wire_fields_stay_independent():
    raw = _workflow_profile_payload()
    saved = deepcopy(raw)
    old = authority_profile._model_workflows_from_payload(raw)
    assert type(old) is authority_profile.AdminModelWorkflowsV2
    assert tuple(f.name for f in fields(old)) == (
        "version", "encode", "reply", "context_reply", "natural_generation",
        "natural_review", "appraisal", "d07_cognition", "contact_generation", "contact_review")
    before = plain_v1(old)
    authority_profile._model_workflows_from_payload(profile())
    assert plain_v1(authority_profile._model_workflows_from_payload(saved)) == before
    assert "life_content" not in before
