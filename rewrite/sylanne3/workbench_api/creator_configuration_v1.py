"""Finite WebUI creator draft inputs; W01 owns authorization and persistence."""
import json
import re
from uuid import UUID

from ..runtime.d12_creator_configuration_v1 import EDITABLE_FIELDS


READ_ACTION = "read_configuration_draft"
SAVE_ACTION = "save_creator_draft"
SAVE_FIELDS = frozenset({
    "draft_ref", "expected_draft_revision", "expected_draft_digest",
    "expected_graph_revision", "expected_access_epoch", "expected_delete_epoch", "fields",
})
STAMP_FIELDS = SAVE_FIELDS - {"draft_ref", "expected_draft_digest", "fields"}


def validate_creator_configuration_input_v1(action, payload, *, purpose, audience, operation_id):
    if purpose != "workbench_user_action" or audience != "owner":
        raise ValueError("creator configuration requires the registered Owner purpose")
    if action == READ_ACTION:
        if type(payload) is not dict or payload:
            raise ValueError("creator discovery requires empty input")
        return
    if action != SAVE_ACTION or type(payload) is not dict or set(payload) != SAVE_FIELDS:
        raise ValueError("creator save input fields differ")
    operation = UUID(operation_id)
    if operation.version != 4 or str(operation) != operation_id:
        raise ValueError("creator save requires canonical UUID4")
    if (type(payload["draft_ref"]) is not str or not 1 <= len(payload["draft_ref"]) <= 4096
            or any(type(payload[name]) is not int or payload[name] < 0 for name in STAMP_FIELDS)):
        raise ValueError("creator save requires exact current locators and epochs")
    digest = payload["expected_draft_digest"]
    if ((payload["expected_draft_revision"] == 0 and digest is not None)
            or (payload["expected_draft_revision"] > 0
                and (type(digest) is not str or re.fullmatch(r"[0-9a-f]{64}", digest) is None))):
        raise ValueError("creator save requires the current draft digest")
    if type(payload["fields"]) is not dict or not set(payload["fields"]) <= EDITABLE_FIELDS:
        raise ValueError("creator save includes an unsupported field")
    if len(json.dumps(payload, ensure_ascii=False, allow_nan=False).encode()) > 65536:
        raise ValueError("creator configuration exceeds its request bound")


def valid_creator_save_receipt_v1(receipt, operation_id, payload):
    return (type(receipt) is dict
        and set(receipt) == {"schema", "operation_id", "draft_ref", "draft_revision", "draft_digest",
                           "graph_revision", "access_epoch", "delete_epoch", "changed_fields", "status"}
        and receipt["schema"] == "d12.creator-draft-save.v1"
        and receipt["operation_id"] == operation_id
        and receipt["draft_ref"] == payload["draft_ref"]
        and type(receipt["draft_revision"]) is int
        and receipt["draft_revision"] == payload["expected_draft_revision"] + 1
        and type(receipt["graph_revision"]) is int
        and receipt["graph_revision"] == payload["expected_graph_revision"] + 1
        and receipt["access_epoch"] == payload["expected_access_epoch"]
        and receipt["delete_epoch"] == payload["expected_delete_epoch"]
        and type(receipt["draft_digest"]) is str
        and re.fullmatch(r"[0-9a-f]{64}", receipt["draft_digest"]) is not None
        and type(receipt["changed_fields"]) is list
        and all(field in EDITABLE_FIELDS for field in receipt["changed_fields"])
        and receipt["status"] == "draft_saved_not_adopted")


def creator_field_templates_v1(namespace):
    """Editable structural examples; never substitute them for current values."""
    from dataclasses import asdict
    from ..domains.d07 import AttentionPolicy
    from ..domains.d08 import BASE_REQUIRED_PROVIDERS
    scope = {"bot_id": namespace.bot_id, "persona_id": namespace.persona_id}
    return {
        "d01.persona_plan": {
            "plan_id": "persona:authored", "namespace": scope, "version": 1, "authored": True,
            "blocks": [{"block_id": "identity", "kind": "semantic_identity",
                        "claim": "请填写角色身份与行为立场", "plasticity": "read_only"}],
            "values": [{"rule_id": "truth", "label": "如实表达", "applies_to": ["reply"],
                        "supports_candidates": ["honest"], "rejects_candidates": ["fabricated"]}],
        },
        "d02.body_profile": {
            "profile_id": "body:authored", "namespace": scope, "version": 1,
            "applicable_axes": ["energy", "load"], "work_kinds": ["thinking"],
        },
        "d03.context_scheme": {"schema": "d03.context.scheme.v1", "roles": ["scene_participant"], "norms": []},
        "d04.affect_scheme": {
            "schema": "d04.affect.scheme.v1", "scheme_version": "scheme:authored",
            "operator_version": "operator:authored", "parameter_version": "parameters:authored",
            "coupling_version": "coupling:authored",
            "axes": [{"axis_id": "gain_engagement:fast", "unit": "normalized", "meaning": "参与倾向"}],
            "parameter_bounds": [["recovery_rate", 0.0, 1.0]],
        },
        "d05.relationship_scheme": {"schema": "d05.relationship.scheme.v1", "dimensions": ["trust", "care"],
                                    "contribution_semantics": ["external_observation", "recollection"]},
        "d06.encoding_projection_policy": {
            "schema": "d06.encoding_projection_policy.v1", "policy_ref": "encoding:authored", "policy_version": "v1",
            "salience_gain": 0.4, "tone_magnitude_gain": 0.3, "neutral_salience": 0.5,
        },
        "d07.attention_policy": asdict(AttentionPolicy.default()),
        "d08.action_schemas": [{
            "schema_id": "action:reply", "action_kind": "reply", "proactive": False,
            "required_checks": [{
                "check_kind": kind, "provider_id": provider,
                "subject_ref": "persona:" + namespace.persona_id, "action_ref": "action:reply",
                "purpose": "reply", "criteria_version": "criteria:" + kind,
                "required_input_versions": [{"ref": "criteria:" + kind, "version": 1}],
            } for kind, provider in BASE_REQUIRED_PROVIDERS],
        }],
        "d09.expression_policy": {"schema": "d09.expression_policy.v1", "policy_ref": "expression:authored",
                                  "policy_version": "v1", "max_visible_chars": 160},
        "d10.activity_recipe": {"recipe_id": "activity:authored", "version": 1, "reality": "role_simulation",
                                "allowed_steps": ["draft", "review"], "preemptible": True},
    }
