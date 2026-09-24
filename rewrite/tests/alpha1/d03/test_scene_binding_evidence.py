"""The two binding sources keep Owner configuration separate from host fact."""

import json
from dataclasses import replace

import pytest

from sylanne3.host.current_scene import CurrentHostScene
from sylanne3.memory_types import validate_access
from sylanne3.runtime.first_ingress_v2 import scene_ref_for_conversation
from sylanne3.runtime_contracts import NamespaceId
from sylanne3.workbench_api.scene_binding_evidence import build_scene_binding_evidence


def _inputs():
    namespace = NamespaceId("bot", "persona")
    platform_ref = '["platform","aiocqhttp","10001"]'
    conversation_ref = '["umo:friend:10002","conversation"]'
    scene = CurrentHostScene(
        namespace, platform_ref, conversation_ref, "private",
        scene_ref_for_conversation(namespace, platform_ref, conversation_ref),
    )
    return {
        "namespace": namespace, "scene": scene, "owner_actor": "owner:one",
        "operation_id": "operation:one", "request_digest": "sha256:" + "a" * 64,
        "authorization_head": "sha256:" + "b" * 64, "observed_at": 1234.5,
    }


def test_two_sources_are_deterministic_and_keep_distinct_qualifications():
    evidence = build_scene_binding_evidence(**_inputs())
    assert evidence == build_scene_binding_evidence(**_inputs())
    config, identity = evidence.owner_config, evidence.host_identity
    assert (config.admission.source_kind, config.admission.content_reality,
            config.admission.evidence_eligibility) == ("authored", "authored", "none")
    assert (config.proposal.qualification.source_family,
            config.proposal.qualification.content_reality,
            config.proposal.qualification.evidence_eligibility) == (
                "authored", "authored_content", "ineligible",
            )
    assert (identity.admission.source_kind, identity.admission.content_reality,
            identity.admission.evidence_eligibility) == (
                "observed", "observed", "external_fact",
            )
    assert (identity.proposal.qualification.source_family,
            identity.proposal.qualification.content_reality,
            identity.proposal.qualification.evidence_eligibility) == (
                "observed", "external_observation", "eligible",
            )
    for item in (config, identity):
        assert item.proposal.qualification.source_refs == (item.source_key.token,)
        assert NamespaceId.from_key(item.source_key) == evidence.namespace
        assert NamespaceId.from_key(item.access_key) == evidence.namespace
        assert item.source_key.owner.subject == item.access_key.owner.subject
        assert item.source_value == item.proposal.source.to_dict()
        validate_access(item.access_value)
        assert item.access_value["source_id"] == item.source_value["source_id"]
        assert item.access_value["recorded_at"] == evidence.observed_at
    assert config.source_key != identity.source_key
    assert json.loads(config.admission.text) == {
        "schema": "sylanne.scene-binding.owner-config.v1",
        "namespace": ["bot", "persona"], "scene_ref": evidence.scene.scene_ref,
        "visibility": "private", "owner_actor": "owner:one",
        "operation_id": "operation:one", "request_digest": "sha256:" + "a" * 64,
        "authorization_head": "sha256:" + "b" * 64,
    }
    assert json.loads(identity.admission.text) == {
        "schema": "sylanne.scene-binding.host-identity.v1",
        "namespace": ["bot", "persona"], "scene_ref": evidence.scene.scene_ref,
        "visibility": "private", "platform_ref": evidence.scene.platform_ref,
        "conversation_ref": evidence.scene.conversation_ref,
    }


def test_rejects_cross_namespace_or_mismatched_scene_identity():
    inputs = _inputs()
    with pytest.raises(ValueError, match="cross namespace"):
        build_scene_binding_evidence(**{**inputs, "namespace": NamespaceId("bot", "other")})
    with pytest.raises(ValueError, match="identity mismatch"):
        build_scene_binding_evidence(**{**inputs, "scene": replace(inputs["scene"], scene_ref="scene:wrong")})


@pytest.mark.parametrize("observed_at", [None, -1, float("nan"), float("inf"), "1234"])
def test_rejects_invalid_observation_time(observed_at):
    with pytest.raises(ValueError, match="observed_at"):
        build_scene_binding_evidence(**{**_inputs(), "observed_at": observed_at})
