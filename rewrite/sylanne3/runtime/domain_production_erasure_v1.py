"""Closed C09 codecs for the installed domain-production input inventory.

These codecs classify real persisted schema fields and dependencies. They do
not authenticate a caller, authorize execution, or manufacture cost facts.
Only the two strictly decoded source-independent policy tables are retained
without a source closure. Every other row is content-bearing derived input.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import asdict, fields, is_dataclass, replace
from decimal import Decimal
from enum import Enum
from functools import lru_cache
import json
import math
import re
import sqlite3
import types
from typing import Any, Union, get_args, get_origin, get_type_hints

from ..graph_types import AtomKey, GraphVersion, GraphWrite
from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize


TABLE_COLUMNS = {
    "graph_world_revision_erasure_barriers_v1":("bot","persona","assertion_commitment","known_sequence","revision_commitment",
        "deletion_generation","deletion_knowledge_sequence","delete_original_commitment","payload_json","payload_digest","signature"),
    "graph_world_revision_index_v1":("bot","persona","original_ref","kind","producing_operation_id","payload_json","payload_digest","signature","source_refs_json","assertion_id","assertion_commitment","known_sequence","supersedes_ref"),
    'graph_contact_segment_originals_v1':('bot','persona','contact_id','segment_index','operation_id','effect_id','payload_json','payload_digest','signature'),
    'graph_contact_prospective_successors_v1':('bot','persona','final_operation_id','birth_ref','birth_digest','payload_json','payload_digest','signature','final_receipt_digest'),
    'graph_contact_prospective_originals_v1':('bot','persona','contact_id','birth_operation_id','payload_json','payload_digest','signature','original_ref'),
    "graph_owner_goal_cancellation_projections_v1": ("bot","persona","operation_id","goal_ref","root_registration_ref","core_original_ref","core_original_digest","observation_json","observation_digest","receipt_json","receipt_digest","signature"),
    "graph_d08_joint_node_originals_v1": ("bot", "persona", "original_ref", "kind", "producing_operation_id", "payload_json", "payload_digest", "signature", "source_refs_json"),
    "graph_d01_production_inputs_v1": ("bot", "persona", "original_ref", "kind", "producing_operation_id", "payload_json", "payload_digest", "signature", "source_refs_json"),
    "graph_d02_production_policies_v1": ("bot", "persona", "policy_ref", "revision", "kind", "profile_id", "from_role_cursor", "to_role_cursor", "payload_json", "payload_digest", "signature"),
    "graph_d02_action_components_v1": ("bot", "persona", "original_ref", "producing_operation_id", "payload_json", "payload_digest", "signature", "source_refs_json"),
    "graph_d05_production_policies_v1": ("bot", "persona", "policy_ref", "revision", "payload_json", "payload_digest", "signature"),
    "graph_d05_boundary_intents_v1": ("bot", "persona", "original_ref", "producing_operation_id", "payload_json", "payload_digest", "signature", "source_refs_json"),
    "graph_d08_joint_plan_intents_v1": ("bot", "persona", "original_ref", "producing_operation_id", "payload_json", "payload_digest", "signature", "source_refs_json"),
    "graph_d08_party_consents_v1": ("bot", "persona", "original_ref", "producing_operation_id", "plan_proposal_ref", "participant_ref", "terms_digest", "payload_json", "payload_digest", "signature", "source_refs_json"),
    "graph_d10_production_inputs_v1": ("bot", "persona", "original_ref", "kind", "producing_operation_id", "payload_json", "payload_digest", "signature", "source_refs_json"),
    "graph_d10_observed_ticks_v1": ("bot", "persona", "interval_ref", "scheduled_at_utc", "job_id", "payload_json", "payload_digest", "signature", "source_refs_json"),
    "graph_d11_offline_originals_v1": ("bot", "persona", "kind", "original_ref", "producing_operation_id", "payload_json", "payload_digest", "signature"),
    "graph_d11_life_originals_v1": ("bot", "persona", "kind", "original_ref", "producing_operation_id", "payload_json", "payload_digest", "signature"),
    "graph_d11_life_artifact_stage_v1": ("bot", "persona", "execution_id", "binding_digest", "artifact_ref", "artifact_bytes", "artifact_digest", "artifact_length", "adopted_operation_id"),
    "graph_d11_derived_cache_payloads_v1": ("bot", "persona", "block_ref", "payload_digest", "payload_bytes"),
    "graph_d13_derived_activations_v6": ("bot", "persona", "block_ref", "before_revision", "after_revision", "before_digest", "after_digest", "payload_digest", "operation_id", "receipt_digest"),
    "graph_d13_wire_evidence_v6": ("bot", "persona", "evidence_digest", "policy_digest", "raw_request_digest", "compressed_request_digest", "envelope_json"),
    "graph_d13_core_wire_evidence_v1": ("bot", "persona", "frame_intent_id", "evidence_digest", "policy_digest", "c02_operation_id", "selector_json", "envelope_json"),
}
TABLE_SCHEMAS = {name: {"columns": columns, "indexes": (), "triggers": ()}
                 for name, columns in TABLE_COLUMNS.items()}
SOURCE_INDEPENDENT_POLICY_TABLES = frozenset({"graph_d02_production_policies_v1"})
SOURCE_INDEPENDENT_METADATA_TABLES=frozenset({'graph_owner_goal_cancellation_projections_v1','graph_world_revision_erasure_barriers_v1'})
CONTENT_TABLES = frozenset(TABLE_COLUMNS) - SOURCE_INDEPENDENT_POLICY_TABLES - SOURCE_INDEPENDENT_METADATA_TABLES


def validate_domain_production_schema_v1(db):
    """Compare actual SQL/constraints with the five fixed schema installers.

    The private memory database contains schema only, never proof or content
    rows. An empty production table is still checked against its real DDL.
    """
    from .d01_production_operations_v1 import install_d01_production_schema_v1
    from .d02_production_operations_v1 import install_d02_production_schema_v1
    from .d05_production_operations_v1 import install_d05_production_schema_v1
    from .d08_production_operations_v1 import install_d08_production_schema_v1
    from .d10_production_operations_v1 import install_d10_production_schema_v1
    from .d11_offline_originals_v1 import install_d11_offline_schema_v1
    from .d11_life_preparation_v1 import install_d11_life_schema_v1
    from .d11_derived_cache_payload_v1 import install_derived_payload_schema_v1
    from ..authority_service.d13_wire_evidence_v6 import install_d13_wire_evidence_schema_v6
    from ..authority_service.d13_wire_evidence_v7 import install_d13_core_wire_evidence_schema_v1
    from .d03_world_history_v1 import install_world_history_schema_v1
    expected = sqlite3.connect(":memory:")
    try:
        for installer in (install_derived_payload_schema_v1, install_d13_wire_evidence_schema_v6, install_d13_core_wire_evidence_schema_v1, install_d01_production_schema_v1, install_d02_production_schema_v1,
                          install_d05_production_schema_v1, install_d08_production_schema_v1,
                          install_d10_production_schema_v1, install_d11_offline_schema_v1, install_d11_life_schema_v1):
            installer(expected)
        install_world_history_schema_v1(expected)
        from .owner_goal_projection_v1 import install_owner_goal_projection_schema_v1
        install_owner_goal_projection_schema_v1(expected)
        from .contact_prospective_v1 import (DDL as PROSPECTIVE_DDL,TRIGGERS as PROSPECTIVE_TRIGGERS,
            SUCCESSOR_DDL,SUCCESSOR_TRIGGERS)
        expected.execute(SUCCESSOR_DDL)
        for trigger in SUCCESSOR_TRIGGERS:expected.execute(trigger)
        expected.execute(PROSPECTIVE_DDL)
        for trigger in PROSPECTIVE_TRIGGERS:expected.execute(trigger)
        from .contact_continuation_v1 import DDL as SEGMENT_DDL,TRIGGERS as SEGMENT_TRIGGERS
        expected.execute(SEGMENT_DDL)
        for trigger in SEGMENT_TRIGGERS:expected.execute(trigger)
        for table in TABLE_COLUMNS:
            actual_table = db.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone()
            if actual_table is None:
                continue
            wanted = expected.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone()
            if actual_table != wanted:
                raise DomainProductionErasureHold("production table SQL/constraints differ: " + table)
            actual_objects = db.execute("SELECT type,name,sql FROM sqlite_master WHERE tbl_name=? AND type IN ('index','trigger') ORDER BY type,name", (table,)).fetchall()
            expected_objects = expected.execute("SELECT type,name,sql FROM sqlite_master WHERE tbl_name=? AND type IN ('index','trigger') ORDER BY type,name", (table,)).fetchall()
            if actual_objects != expected_objects:
                raise DomainProductionErasureHold("production index/trigger definitions differ: " + table)
    finally:
        expected.close()
    validate_offline_original_joins_v1(db)
    from .c09_life_originals_v1 import validate_life_original_joins_v1
    validate_life_original_joins_v1(db)
    from .d11_artifact_draft_content_v1 import validate_artifact_method_settlement_joins_v2
    validate_artifact_method_settlement_joins_v2(db)
    from .d08_personal_plan_v1 import validate_artifact_task_control_joins_v2
    validate_artifact_task_control_joins_v2(db)
    validate_artifact_phase_price_policy_joins_v1(db)
    if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='graph_domain_production_originals_v1'").fetchone():
        from .d06_association_formation_v1 import validate_association_formation_original_joins_v1
        validate_association_formation_original_joins_v1(db)
    return True


class DomainProductionErasureHold(ValueError):
    pass


def _exact(raw, names):
    if type(raw) is not dict or set(raw) != set(names):
        raise DomainProductionErasureHold("domain production fields differ from the installed exact schema")
    return raw


def _json(encoded):
    if type(encoded) is not str or len(encoded.encode("utf-8")) > 4_194_304:
        raise DomainProductionErasureHold("domain production canonical JSON must be bounded")
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise DomainProductionErasureHold("duplicate domain production JSON field")
            value[key] = item
        return value
    try:
        raw = json.loads(encoded, object_pairs_hook=unique,
            parse_constant=lambda _: (_ for _ in ()).throw(DomainProductionErasureHold("nonfinite domain production JSON")))
    except (TypeError, json.JSONDecodeError) as exc:
        raise DomainProductionErasureHold("domain production JSON is invalid") from exc
    if canonical_serialize(raw) != encoded:
        raise DomainProductionErasureHold("domain production JSON is noncanonical")
    return raw


@lru_cache(maxsize=1)
def _production_value_type_registry_v1():
    """Frozen code schemas only; contains no caller or current SQL authority."""
    from ..domain_registry import discover_domain_registry
    return discover_domain_registry().type_registry


def decode_typed_production_value_v1(raw, expected, *, depth=0):
    """Strict decoder for the fixed dataclass types named by this module."""
    from .joint_node_execution_v1 import RegisterJointNodeExecutionBindingRequestV1,decode_joint_binding_v1
    if expected is RegisterJointNodeExecutionBindingRequestV1:
        if type(raw) is not dict or set(raw)!={"binding"}:
            raise DomainProductionErasureHold("closed Joint binding request fields differ")
        return RegisterJointNodeExecutionBindingRequestV1(decode_joint_binding_v1(raw["binding"]))
    if depth > 64:
        raise DomainProductionErasureHold("domain production nesting exceeds its installed bound")
    from ..domains.d08.personal_candidate_v1 import (
        PrepareCurrentPersonalCandidatesRequestV1, SelectCurrentPersonalStepRequestV2,
    )
    candidate_requests = {PrepareCurrentPersonalCandidatesRequestV1: "prepare_personal_candidates_v1",
        SelectCurrentPersonalStepRequestV2: "select_personal_step_v2"}
    if expected in candidate_requests:
        return decode_personal_candidate_request_v1(candidate_requests[expected], raw, depth=depth)
    from ..model_broker.artifact_draft_v1 import (
        ArtifactDraftPhaseSelectorV2, ArtifactDraftTextExtentV2, ArtifactDraftPriorContentCommitmentV2,
        ArtifactDraftInputV2, ArtifactDraftInputV3, ArtifactDraftOutputV2, artifact_draft_from_wire_v2,
    )
    if expected in {ArtifactDraftPhaseSelectorV2, ArtifactDraftTextExtentV2, ArtifactDraftPriorContentCommitmentV2,
            ArtifactDraftInputV2, ArtifactDraftInputV3, ArtifactDraftOutputV2}:
        return artifact_draft_from_wire_v2(raw, expected)
    from ..domains.d10.offline_interval import OfflineTickRecipeV1, decode_offline_tick_recipe_v1
    if expected is OfflineTickRecipeV1:
        return decode_offline_tick_recipe_v1(raw)
    from .d11_life_contract_v1 import (
        RegisteredLifePlanV2, D11LifeExecutionBindingV1, RoleSegmentStartV1,
        LifeTerminalPayloadV1, D11LifeClaimV1, D11LifeTerminalV1,
        life_from_wire_v1)
    if expected in {RegisteredLifePlanV2, D11LifeExecutionBindingV1, RoleSegmentStartV1,
            LifeTerminalPayloadV1, D11LifeClaimV1, D11LifeTerminalV1}:
        return life_from_wire_v1(raw, expected)
    from ..domains.d01.production_operations_v1 import MethodStrategyProjectionV1, MethodStrategyProjectionV2
    if expected is MethodStrategyProjectionV1 and type(raw) is dict and raw.get("schema") == "d01.method-strategy-projection.v2":
        return decode_typed_production_value_v1(raw, MethodStrategyProjectionV2, depth=depth)
    origin, args = get_origin(expected), get_args(expected)
    if expected is Any or expected is object:
        raise DomainProductionErasureHold("untyped content cannot be a closed production original")
    if expected is type(None):
        if raw is not None:
            raise DomainProductionErasureHold("expected null production field")
        return None
    if origin in {Union, types.UnionType}:
        for option in args:
            try:
                return decode_typed_production_value_v1(raw, option, depth=depth + 1)
            except (DomainProductionErasureHold, ValueError, TypeError):
                pass
        raise DomainProductionErasureHold("production union field does not match an installed variant")
    if expected is AtomKey:
        if type(raw) is not str:
            raise DomainProductionErasureHold("production graph key must be canonical token")
        return AtomKey.from_token(raw)
    if expected is GraphWrite:
        _exact(raw, ("key", "value", "dependencies"))
        key = AtomKey.from_token(raw["key"])
        if type(raw["dependencies"]) is not list or len(raw["dependencies"]) > 1024:
            raise DomainProductionErasureHold("production write dependencies are unbounded")
        write = GraphWrite(key, raw["value"], tuple(AtomKey.from_token(ref) for ref in raw["dependencies"]))
        registry = _production_value_type_registry_v1()
        if key.type_name == "d05.contribution":
            from ..domains.d05.relationship import decode_relationship_contribution_payload_v1
            decode_relationship_contribution_payload_v1(raw["value"])
        elif key.type_name == "d05.relationship_projection":
            from ..domains.d05.relationship import decode_relationship_projection_payload_v1
            decode_relationship_projection_payload_v1(raw["value"])
        else:
            registry.validate(key, raw["value"])
        return write
    if expected is Decimal:
        if type(raw) is not str:
            raise DomainProductionErasureHold("production exact decimal must be text")
        result = Decimal(raw)
        if not result.is_finite():
            raise DomainProductionErasureHold("nonfinite production decimal")
        return result
    if expected in (str, bool, int, float):
        if expected is float:
            if type(raw) not in (int, float) or not math.isfinite(raw):
                raise DomainProductionErasureHold("production numeric field is not finite")
        elif type(raw) is not expected:
            raise DomainProductionErasureHold("production scalar has the wrong exact type")
        if expected is str and len(raw) > 262_144:
            raise DomainProductionErasureHold("production string exceeds bound")
        return raw
    if isinstance(expected, type) and issubclass(expected, Enum):
        return expected(raw)
    if origin in (tuple, list):
        if type(raw) is not list or len(raw) > 1024:
            raise DomainProductionErasureHold("production sequence is not a bounded JSON array")
        if len(args) == 2 and args[1] is Ellipsis:
            values = tuple(decode_typed_production_value_v1(item, args[0], depth=depth + 1) for item in raw)
        elif args:
            if len(raw) != len(args):
                raise DomainProductionErasureHold("production tuple arity differs")
            values = tuple(decode_typed_production_value_v1(item, typ, depth=depth + 1) for item, typ in zip(raw, args))
        elif raw:
            raise DomainProductionErasureHold("untyped production sequence is forbidden")
        else:
            values = ()
        return list(values) if origin is list else values
    if origin in (dict, Mapping):
        if type(raw) is not dict or len(raw) > 1024 or len(args) != 2:
            raise DomainProductionErasureHold("production map is not a bounded typed object")
        return {decode_typed_production_value_v1(key, args[0], depth=depth + 1):
                decode_typed_production_value_v1(value, args[1], depth=depth + 1) for key, value in raw.items()}
    if isinstance(expected, type) and is_dataclass(expected):
        from ..domains.d08.personal_plan_v1 import PersonalPlanV1
        from .d01_production_operations_v1 import FrozenValuesCandidateSetV1, FrozenValuesContextV1
        legacy_defaults = {PersonalPlanV1: {"method_candidates": []},
            FrozenValuesCandidateSetV1: {"plan_head": None},
            FrozenValuesContextV1: {"condition_heads": [], "condition_query_epoch": None}}
        defaults = legacy_defaults.get(expected)
        names = {field.name for field in fields(expected)}
        if defaults is not None and type(raw) is dict and set(raw) == names - set(defaults):
            raw = {**raw, **defaults}
        _exact(raw, names)
        hints = get_type_hints(expected)
        value = {field.name: decode_typed_production_value_v1(raw[field.name], hints[field.name], depth=depth + 1)
                 for field in fields(expected)}
        return expected(**value)
    raise DomainProductionErasureHold("production original has an unregistered nested type")


def _input_types():
    from .joint_window_command_v1 import JointWindowNodeCommandOriginalV1
    from .joint_external_observation_v1 import ORIGINAL_TYPES as JOINT_D08_ORIGINAL_TYPES
    from .joint_node_execution_v1 import JointNodeExecutionBindingV1, JointPlanQualificationV1, JointExecutorIndexV1
    from .joint_artifact_execution_v1 import JointArtifactProspectiveBindingV1
    from .joint_node_execution_v1 import JointContactProspectiveBindingV1
    from .joint_node_execution_v1 import JointContactProspectiveBindingV1
    from .d07_general_growth_attention_v1 import D10GeneralGrowthOutcomeTriggerV1
    from .d01_production_operations_v1 import _ORIGINAL_TYPES
    from .d01_general_growth_v1 import (GeneralGrowthIntentOriginalV1,GeneralGrowthTrialStartV1,GeneralGrowthTrialOriginalV1)
    from .d02_production_operations_v1 import CompletedActionBodyComponentV1, PassiveBodyPolicyV1, SettledBodyEffectPolicyV1
    from .d05_production_operations_v1 import BoundaryIntentOriginalV1, InstalledRelationshipPolicyV1
    from .d08_production_operations_v1 import JointPlanIntentOriginalV1, PartyConsentEvidenceV1
    from .d10_production_operations_v1 import RegisteredLifePlanV1, RegisteredLifeOutcomeV1, RegisteredOfflineIntervalV1
    from ..domains.d10.offline_interval import OfflineTickRecipeV1, OfflineObservedTickV1
    from .d02_artifact_phase_price_v1 import ArtifactPhasePricePolicyV1
    return {
        "graph_d08_joint_node_originals_v1": JOINT_D08_ORIGINAL_TYPES,
        "graph_d01_production_inputs_v1": {**_ORIGINAL_TYPES,
            "general_growth_intent_v1":GeneralGrowthIntentOriginalV1,
            "general_growth_trial_start_v1":GeneralGrowthTrialStartV1,
            "general_growth_trial_v1":GeneralGrowthTrialOriginalV1},
        "graph_d02_production_policies_v1": {"passive": PassiveBodyPolicyV1, "effect": SettledBodyEffectPolicyV1,
            "artifact_phase_price": ArtifactPhasePricePolicyV1},
        "graph_d02_action_components_v1": {"completed_action_component": CompletedActionBodyComponentV1},
        "graph_d05_production_policies_v1": {"policy": InstalledRelationshipPolicyV1},
        "graph_d05_boundary_intents_v1": {"boundary_intent": BoundaryIntentOriginalV1},
        "graph_d08_joint_plan_intents_v1": {"joint_plan_intent": JointPlanIntentOriginalV1},
        "graph_d08_party_consents_v1": {"party_consent": PartyConsentEvidenceV1},
        "graph_d10_production_inputs_v1": {"joint_window_node_command_v1":JointWindowNodeCommandOriginalV1,"joint_contact_prospective_binding_v1":JointContactProspectiveBindingV1, "joint_artifact_prospective_binding_v1": JointArtifactProspectiveBindingV1, "joint_node_execution_binding_v1": JointNodeExecutionBindingV1,
            "joint_plan_qualification_v1": JointPlanQualificationV1, "joint_executor_index_v1": JointExecutorIndexV1, "life_plan": RegisteredLifePlanV1, "life_outcome": RegisteredLifeOutcomeV1,
            "offline_recipe": OfflineTickRecipeV1, "offline_interval": RegisteredOfflineIntervalV1,
            "general_growth_outcome_trigger_v1": D10GeneralGrowthOutcomeTriggerV1},
        "graph_d10_observed_ticks_v1": {"observed_tick": OfflineObservedTickV1},
    }


_FIXED_KINDS = {'graph_contact_segment_originals_v1':'segment_original','graph_contact_prospective_successors_v1':'prospective_successor','graph_contact_prospective_originals_v1':'prospective_birth',"graph_d02_action_components_v1": "completed_action_component", "graph_d05_production_policies_v1": "policy",
    "graph_d05_boundary_intents_v1": "boundary_intent", "graph_d08_joint_plan_intents_v1": "joint_plan_intent",
    "graph_d08_party_consents_v1": "party_consent", "graph_d10_observed_ticks_v1": "observed_tick"}


def decode_domain_production_content_v1(table, kind, payload_json):
    if table=="graph_world_revision_erasure_barriers_v1" and kind=="world_erasure_barrier":
        from ..domains.d03.world_history_v1 import WorldErasureBarrierV1,decode_world_value_v1
        return decode_world_value_v1(_json(payload_json),WorldErasureBarrierV1)
    if table=="graph_world_revision_index_v1" and kind=="world_revision_index":
        from .d03_world_history_v1 import WorldRevisionIndexV1
        return decode_typed_production_value_v1(_json(payload_json),WorldRevisionIndexV1)
    if table=='graph_contact_segment_originals_v1':
        from .contact_continuation_v1 import contact_segment_original_from_wire_v1
        if kind!='segment_original':raise DomainProductionErasureHold('Contact segment registered kind differs')
        return contact_segment_original_from_wire_v1(json.loads(payload_json))
    if table=='graph_contact_prospective_successors_v1':
        from .contact_prospective_v1 import ContactProspectiveSuccessorV1
        if kind!='prospective_successor':raise DomainProductionErasureHold('Contact successor registered kind differs')
        return ContactProspectiveSuccessorV1(payload_json)
    if table=='graph_contact_prospective_originals_v1':
        from .contact_prospective_v1 import ContactProspectiveOriginalV1
        if kind!='prospective_birth':raise DomainProductionErasureHold('Contact prospective registered birth kind differs')
        return ContactProspectiveOriginalV1(payload_json)
    types_by_table = _input_types()
    if table == "graph_d11_life_originals_v1":
        from .c09_life_originals_v1 import decode_life_original_content_v1
        return decode_life_original_content_v1(kind, payload_json)
    if table == "graph_d11_offline_originals_v1":
        from .d11_offline_originals_v1 import D11OfflineScheduleOriginalV1, D11HostLifecycleOriginalV1
        from .d10_offline_tick_execution_v1 import D10OfflineTickPreparedV1
        from .d10_offline_tick_terminal_v1 import AdoptedOfflineTickOriginalV1
        from .d11_offline_accounting_v1 import D11OfflineAccountingPreparedV1
        from .d11_offline_adoption_v1 import D11OfflineTickAdoptionReceiptV1
        if kind == "adoption_bridge":
            from ..authority_service.d11_offline_tick_bridge_v1 import offline_bridge_from_wire_v1
            return offline_bridge_from_wire_v1(_json(payload_json))
        if kind == "historical_accounting_gate":
            from ..authority_service.d11_offline_historical_accounting_v1 import historical_accounting_from_wire_v1
            return historical_accounting_from_wire_v1(_json(payload_json))
        if kind == "historical_accounting_receipt":
            from .d11_offline_historical_accounting_v1 import historical_accounting_receipt_from_wire_v1
            return historical_accounting_receipt_from_wire_v1(_json(payload_json))
        if kind == "cancellation_gate":
            from ..authority_service.d11_offline_unstarted_cancellation_v1 import unstarted_cancellation_from_wire_v1
            return unstarted_cancellation_from_wire_v1(_json(payload_json))
        if kind == "cancellation_receipt":
            from .d11_offline_unstarted_cancellation_v1 import unstarted_cancellation_receipt_from_wire_v1
            return unstarted_cancellation_receipt_from_wire_v1(_json(payload_json))
        types_by_table[table] = {"registered_schedule": D11OfflineScheduleOriginalV1,
            "host_disconnect": D11HostLifecycleOriginalV1, "host_reconnect": D11HostLifecycleOriginalV1,
            "prepared_tick": D10OfflineTickPreparedV1, "adopted_tick": AdoptedOfflineTickOriginalV1,
            "accounting_prepared": D11OfflineAccountingPreparedV1,
            "adoption_receipt": D11OfflineTickAdoptionReceiptV1}
    if table not in types_by_table or kind not in types_by_table[table]:
        raise DomainProductionErasureHold("unknown installed domain production table/kind")
    raw = _json(payload_json)
    expected = types_by_table[table][kind]
    if table == "graph_d05_production_policies_v1" and raw.get("schema_version") == 2:
        from ..domains.d05.relationship_revision_v2 import InstalledRelationshipPolicyV2
        expected = InstalledRelationshipPolicyV2
    value = decode_typed_production_value_v1(raw, expected)
    from ..domains.d01.production_operations_v1 import plain_v1
    from ..domains.d10.offline_interval import OfflineTickRecipeV1, offline_tick_recipe_to_wire_v1
    projection = offline_tick_recipe_to_wire_v1(value) if type(value) is OfflineTickRecipeV1 else plain_v1(value)
    # Preserve the exact old stored wire after in-memory defaults. No bytes,
    # digest or signature are rewritten by compatibility decoding.
    from .d01_production_operations_v1 import FrozenValuesCandidateSetV1, FrozenValuesContextV1
    legacy_fields = {FrozenValuesCandidateSetV1: {"plan_head"},
        FrozenValuesContextV1: {"condition_heads", "condition_query_epoch"}}
    added = legacy_fields.get(type(value))
    if added is not None and set(raw) == set(projection) - added:
        projection = {name: item for name, item in projection.items() if name not in added}
    if projection != raw:
        raise DomainProductionErasureHold("production typed content does not round-trip exactly")
    return value


def _references(raw, *, depth=0):
    if depth > 64:
        raise DomainProductionErasureHold("production reference closure exceeds nesting bound")
    if type(raw) is str:
        try:
            key = AtomKey.from_token(raw)
        except (TypeError, ValueError):
            from ..domains.d01.identity_v3 import SEMANTIC_SCHEMA_V3, decode_semantic_identity_v3, identity_payload_v3
            if raw.startswith("{") and SEMANTIC_SCHEMA_V3 in raw:
                value=decode_semantic_identity_v3(raw)
                if value is not None:
                    yield from _references(identity_payload_v3(value),depth=depth+1)
            return
        yield key.token
    elif type(raw) is dict:
        for value in raw.values():
            yield from _references(value, depth=depth + 1)
    elif type(raw) is list:
        for value in raw:
            yield from _references(value, depth=depth + 1)


def domain_production_source_closure_v1(table, kind, payload_json):
    value = decode_domain_production_content_v1(table, kind, payload_json)
    if table == "graph_d11_life_originals_v1":
        from .c09_life_originals_v1 import C4_KINDS, C4_PHASE_KINDS, life_original_content_projection_v1
        if kind in C4_KINDS | C4_PHASE_KINDS:
            raw = life_original_content_projection_v1(kind, _json(payload_json))
            return tuple(sorted({ref for ref in _references(raw) if AtomKey.from_token(ref).type_name == "memory.source"}))
    if (table == "graph_d11_offline_originals_v1" and kind == "prepared_tick"
            or table == "graph_d11_life_originals_v1" and kind == "prepared"):
        raw = _json(payload_json)
        for item in raw["read_rows"]:
            item["value_json"] = _json(item["value_json"])
        return tuple(sorted({ref for ref in _references(raw) if AtomKey.from_token(ref).type_name == "memory.source"}))
    return tuple(sorted({ref for ref in _references(_json(payload_json)) if AtomKey.from_token(ref).type_name == "memory.source"}))


def validate_domain_production_row_v1(table, columns, row, *, authority_namespace=None):
    if table=="graph_world_revision_erasure_barriers_v1":
        from .d03_world_history_v1 import decode_world_erasure_barrier_row_v1
        from ..runtime_contracts import namespace_ref
        value=decode_world_erasure_barrier_row_v1(columns,row)
        if authority_namespace is not None and namespace_ref(value.namespace)!=authority_namespace:
            raise DomainProductionErasureHold("World barrier namespace differs")
        return ("world_erasure_barrier",canonical_digest(tuple(row[:4])),asdict(value),row[9])
    if table=="graph_owner_goal_cancellation_projections_v1":
        from .owner_goal_projection_v1 import validate_goal_projection_row_v1
        observed,receipt=validate_goal_projection_row_v1(columns,row)
        from ..runtime_contracts import namespace_ref
        if authority_namespace is not None and namespace_ref(receipt.namespace)!=authority_namespace:
            raise DomainProductionErasureHold("Goal projection namespace differs")
        return ("goal_metadata_projection",receipt.operation_id,asdict(receipt),receipt.digest)
    if table in DERIVED_STORE_TABLES_V6:
        return _validate_derived_store_row_v6(table, columns, row, authority_namespace=authority_namespace)
    if table == "graph_d11_life_artifact_stage_v1":
        from .c09_life_originals_v1 import validate_life_stage_row_v1
        return validate_life_stage_row_v1(columns, row, authority_namespace=authority_namespace)
    if table not in TABLE_COLUMNS or tuple(columns) != TABLE_COLUMNS[table] or len(row) != len(columns):
        raise DomainProductionErasureHold("production table columns differ from exact installed layout")
    data = dict(zip(columns, row))
    ns = NamespaceId(data["bot"], data["persona"])
    if authority_namespace is not None:
        from ..graph_coordinator import namespace_ref
        if namespace_ref(ns) != authority_namespace:
            raise DomainProductionErasureHold("production row differs from Authority namespace")
    kind = data.get("kind", _FIXED_KINDS.get(table))
    decoded = decode_domain_production_content_v1(table, kind, data["payload_json"])
    raw = _json(data["payload_json"])
    if canonical_digest(raw) != data["payload_digest"]:
        raise DomainProductionErasureHold("production original commitment differs")
    for name in ("payload_digest", "signature"):
        value = data[name]
        if type(value) is not str or len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
            raise DomainProductionErasureHold("production signature/commitment field differs")
    if "producing_operation_id" in data and (type(data["producing_operation_id"]) is not str or not data["producing_operation_id"]):
        raise DomainProductionErasureHold("production input lacks its real producing-operation locator")
    if table=='graph_contact_prospective_originals_v1':
        from .contact_prospective_v1 import contact_prospective_original_ref_v1
        if (raw['namespace']!={'bot_id':ns.bot_id,'persona_id':ns.persona_id}
                or (raw['contact_id'],raw['birth_operation_id'])!=(data['contact_id'],data['birth_operation_id'])
                or data['original_ref']!=contact_prospective_original_ref_v1(ns,data['contact_id'],data['birth_operation_id'])):
            raise DomainProductionErasureHold('Contact prospective actual C09 indexed birth identity differs')
    if table=='graph_contact_prospective_successors_v1':
        candidate=raw['final_candidate'];action=candidate['action']
        if (raw['birth_ref']!=data['birth_ref'] or raw['birth_digest']!=data['birth_digest']
                or action['identity']['operation_id']!=data['final_operation_id']
                or action['namespace']!={'bot_id':ns.bot_id,'persona_id':ns.persona_id}):
            raise DomainProductionErasureHold('Contact prospective successor indexed birth/final namespace differs')
    if table=='graph_contact_segment_originals_v1':
        if (raw['namespace']!={'bot_id':ns.bot_id,'persona_id':ns.persona_id}
                or (raw['contact_id'],raw['segment_index'],raw['operation_id'],raw['effect_id'])!=(
                    data['contact_id'],data['segment_index'],data['operation_id'],data['effect_id'])):
            raise DomainProductionErasureHold('Contact segment actual C09 indexed original identity differs')
    if table=="graph_world_revision_index_v1":
        if (decoded.input_version.key.token!=data["original_ref"] or decoded.adoption_operation_id!=data["producing_operation_id"]
                or (decoded.assertion_id,decoded.assertion_commitment,decoded.known_from_sequence,decoded.supersedes_ref)!=(data["assertion_id"],data["assertion_commitment"],data["known_sequence"],data["supersedes_ref"])):
            raise DomainProductionErasureHold("World derived index differs from its typed actual adoption locator")
    direct = domain_production_source_closure_v1(table, kind, data["payload_json"])
    roots = ()
    if "source_refs_json" in data:
        roots_raw = _json(data["source_refs_json"])
        if type(roots_raw) is not list or len(roots_raw) > 1024 or len(set(roots_raw)) != len(roots_raw):
            raise DomainProductionErasureHold("production source closure field differs")
        roots = tuple(roots_raw)
    for ref in set(direct) | set(roots):
        key = AtomKey.from_token(ref)
        if key.type_name != "memory.source" or NamespaceId.from_key(key) != ns:
            raise DomainProductionErasureHold("production source closure crossed namespace/type")
    d05_legacy_independent = table == "graph_d05_production_policies_v1" and raw.get("schema_version") is None
    if table in SOURCE_INDEPENDENT_POLICY_TABLES or d05_legacy_independent:
        if direct or roots or raw.get("namespace") != {"bot_id": ns.bot_id, "persona_id": ns.persona_id}:
            raise DomainProductionErasureHold("source-independent policy contains a source or another namespace")
        if data["policy_ref"] != decoded.policy_ref or data["revision"] != decoded.revision:
            raise DomainProductionErasureHold("production policy locator/revision differs")
        if table == "graph_d02_production_policies_v1":
            if data["profile_id"] != decoded.profile_id:
                raise DomainProductionErasureHold("body policy SQL profile differs")
            interval = (decoded.from_role_cursor, decoded.to_role_cursor) if kind == "passive" else (None, None)
            if (data["from_role_cursor"], data["to_role_cursor"]) != interval:
                raise DomainProductionErasureHold("body policy SQL interval differs")
    if table == "graph_d05_production_policies_v1" and not d05_legacy_independent:
        if (raw["namespace"] != {"bot_id": ns.bot_id, "persona_id": ns.persona_id}
                or data["policy_ref"] != decoded.policy_ref or data["revision"] != decoded.revision or not direct):
            raise DomainProductionErasureHold("sourced relationship numeric policy identity/closure differs")
    if table=='graph_d01_production_inputs_v1' and kind=='general_growth_trial_start_v1':
        if (decoded.namespace!=ns or decoded.start_ref!=data['original_ref']
                or decoded.producing_operation_id!=data['producing_operation_id']):
            raise DomainProductionErasureHold('General trial start indexed identity differs from its actual original')
    if table == "graph_d08_party_consents_v1" and any(data[name] != raw[field] for name, field in (
            ("plan_proposal_ref", "plan_proposal_ref"), ("participant_ref", "participant_ref"), ("terms_digest", "terms_digest"))):
        raise DomainProductionErasureHold("party consent indexed identity differs")
    if table == "graph_d10_observed_ticks_v1" and data["scheduled_at_utc"] != decoded.scheduled_at_utc:
        raise DomainProductionErasureHold("observed tick schedule SQL identity differs")
    if table == "graph_d11_life_originals_v1":
        from .c09_life_originals_v1 import (C4_KINDS, C4_PHASE_KINDS, POSTCONDITION_KINDS, validate_c4_life_original_row_v1,
            validate_c4_phase_life_original_row_v2,
            FOREGROUND_CAUSE_KIND, validate_foreground_post_c02_cause_row_v1)
        if kind == "c1_task_intent":
            from .c1_artifact_task_intent_v1 import validate_c1_task_original_row_v1
            validate_c1_task_original_row_v1(namespace=ns,original_ref=data["original_ref"],
                producing_operation_id=data["producing_operation_id"],raw=raw)
        if kind == FOREGROUND_CAUSE_KIND:
            validate_foreground_post_c02_cause_row_v1(namespace=ns, original_ref=data["original_ref"],
                producing_operation_id=data["producing_operation_id"], raw=raw)
        if kind == "artifact_task_continuation_authorization_v2":
            if decoded.namespace!=ns or decoded.original_ref!=data["original_ref"]:
                raise DomainProductionErasureHold("continuation authorization SQL namespace/original locator changed")
        if kind == 'artifact_task_milestone_v2':
            if (decoded.namespace!=ns or decoded.registration_operation_id!=data['producing_operation_id']
                    or decoded.original_ref!=data['original_ref']):
                raise DomainProductionErasureHold('task milestone SQL original changed its exact namespace/producer/locator')
        if kind in POSTCONDITION_KINDS:
            if (decoded.namespace != ns or decoded.registration_operation_id != data["producing_operation_id"]
                    or decoded.original_ref != data["original_ref"]):
                raise DomainProductionErasureHold("postcondition SQL original changed exact namespace/producer/locator")
        if kind == "artifact_task_text_extent":
            from .artifact_task_text_extent_v1 import artifact_task_text_extent_ref_v1
            if (decoded.namespace != ns or decoded.registration_operation_id != data["producing_operation_id"]
                    or artifact_task_text_extent_ref_v1(decoded) != data["original_ref"]):
                raise DomainProductionErasureHold("task extent SQL original lost exact namespace/producer/locator")
        if kind in C4_PHASE_KINDS:
            validate_c4_phase_life_original_row_v2(kind, namespace=ns, original_ref=data["original_ref"],
                producing_operation_id=data["producing_operation_id"], raw=raw)
        if kind in C4_KINDS:
            validate_c4_life_original_row_v1(kind, namespace=ns, original_ref=data["original_ref"],
                producing_operation_id=data["producing_operation_id"], raw=raw)
        from .d11_life_contract_v1 import D11LifeTerminalV1, life_from_wire_v1
        binding = (decoded.binding if kind in {"prepared","accounting_prepared","adoption_bridge","historical_accounting_gate"}
            else life_from_wire_v1(raw["terminal"],D11LifeTerminalV1).binding if kind in {"adopted_life","experience"} else None)
        if binding is not None and binding.namespace != ns:
            raise DomainProductionErasureHold("Life SQL original crossed namespace")
        if kind == "prepared" and (decoded.requirements_json is None or data["original_ref"] != binding.prepared_original_ref or data["producing_operation_id"] != decoded.prepare_operation_id):
            raise DomainProductionErasureHold("Life prepared SQL row lacks exact actual CAS stamp")
        if kind == "accounting_prepared" and (data["original_ref"] != decoded.accounting_original_ref or data["producing_operation_id"] != decoded.prepare_operation_id):
            raise DomainProductionErasureHold("Life accounting SQL row identity differs")
        if kind in {"adoption_bridge","historical_accounting_gate"} and data["original_ref"] != binding.execution_id:
            raise DomainProductionErasureHold("Life gate SQL row identity differs")
        if kind == "adopted_life" and (data["original_ref"] != binding.artifact_ref or data["producing_operation_id"] != raw["producing_operation_id"]):
            raise DomainProductionErasureHold("Life adopted SQL row identity differs")
        if kind == "experience" and data["original_ref"] != raw["experience"]["actual_provenance_ref"]:
            raise DomainProductionErasureHold("Life experience SQL provenance identity differs")
    if table == "graph_d11_offline_originals_v1":
        original_ns = (None if kind in {"adoption_receipt", "historical_accounting_receipt", "cancellation_receipt"} else decoded.binding.namespace
            if kind in {"prepared_tick", "accounting_prepared", "adoption_bridge", "historical_accounting_gate", "cancellation_gate"} else decoded.namespace)
        if original_ns is not None and original_ns != ns:
            raise DomainProductionErasureHold("offline original namespace differs")
        ref = (decoded.schedule_ref if kind == "registered_schedule" else decoded.binding.prepared_original_ref if kind == "prepared_tick"
            else decoded.accounting_original_ref if kind == "accounting_prepared" else decoded.result_ref if kind == "adopted_tick"
            else decoded.binding.execution_id if kind in {"adoption_bridge", "historical_accounting_gate", "cancellation_gate"}
            else data["original_ref"] if kind in {"adoption_receipt", "historical_accounting_receipt", "cancellation_receipt"}
            else decoded.lifecycle_ref)
        if data["original_ref"] != ref or kind in {"host_disconnect", "host_reconnect"} and decoded.kind != kind:
            raise DomainProductionErasureHold("offline SQL original locator/kind differs")
        if kind == "prepared_tick" and (decoded.requirements_json is None or data["producing_operation_id"] != decoded.prepare_operation_id):
            raise DomainProductionErasureHold("offline prepared row lacks actual final stamp/producing operation")
        if kind in {"adoption_bridge", "adoption_receipt"}:
            from .d10_offline_tick_terminal_v1 import offline_tick_adoption_operation_id_v1
            operation_id = offline_tick_adoption_operation_id_v1(decoded.binding) if kind == "adoption_bridge" else decoded.operation_id
            if data["producing_operation_id"] != operation_id:
                raise DomainProductionErasureHold("offline adoption indexed operation differs")
        if kind in {"historical_accounting_gate", "historical_accounting_receipt"}:
            from ..authority_service.d11_offline_historical_accounting_v1 import historical_accounting_operation_id_v1
            operation_id = (historical_accounting_operation_id_v1(decoded.binding) if kind == "historical_accounting_gate"
                else decoded["operation_id"])
            if data["producing_operation_id"] != operation_id:
                raise DomainProductionErasureHold("offline historical accounting indexed operation differs")
        if kind in {"cancellation_gate", "cancellation_receipt"}:
            from ..authority_service.d11_offline_unstarted_cancellation_v1 import unstarted_cancellation_operation_id_v1
            operation_id = (unstarted_cancellation_operation_id_v1(decoded.binding) if kind == "cancellation_gate"
                else decoded["operation_id"])
            if data["producing_operation_id"] != operation_id:
                raise DomainProductionErasureHold("offline unstarted cancellation indexed operation differs")
    return kind, (data["operation_id"] if table=="graph_contact_segment_originals_v1" else data["final_operation_id"] if table=="graph_contact_prospective_successors_v1" else data.get("original_ref", data.get("policy_ref", data.get("interval_ref")))), raw, data["payload_digest"]


def validate_artifact_phase_price_policy_joins_v1(db):
    from .d02_artifact_phase_price_v1 import (TABLE, POLICY_KIND, OPERATION_KIND,
        RegisterCurrentArtifactPhasePricePolicyRequestV1)
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    from .domain_production_contracts_v1 import ProductionOwnerGuardV1
    from ..domains.d01.production_operations_v1 import plain_v1
    if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (TABLE,)).fetchone() is None:
        return
    columns = TABLE_COLUMNS[TABLE]
    for row in db.execute("SELECT " + ",".join(columns) + " FROM " + TABLE + " WHERE kind=?", (POLICY_KIND,)):
        kind, ref, raw, digest = validate_domain_production_row_v1(TABLE, columns, row)
        value = decode_domain_production_content_v1(TABLE, kind, row[columns.index("payload_json")])
        adopted = read_adopted_domain_operation_v1(db, value.namespace, value.producing_operation_id)
        expected_request = RegisterCurrentArtifactPhasePricePolicyRequestV1(value.policy_ref, value.revision - 1,
            value.installation_id, value.manifest_digest, value.profile_id, value.provider_config_digest, value.template_version)
        if (adopted is None or (adopted["domain"], adopted["operation_kind"]) != ("d02", OPERATION_KIND)
                or adopted["payload"]["coverage"] != "complete"
                or adopted["payload"]["provenance"] != {"artifact_phase_price_policy": raw}
                or adopted["payload"]["request"] != plain_v1(expected_request)):
            raise DomainProductionErasureHold("phase price has no exact actual adopted Owner registration")
        guard = decode_typed_production_value_v1(adopted["payload"]["owner_guard"], ProductionOwnerGuardV1)
        if (guard.grant_ref, guard.grant_revision, guard.grant_digest) != (
                value.owner_grant_ref, value.owner_grant_revision, value.owner_grant_digest):
            raise DomainProductionErasureHold("phase price changed its actual registered Owner grant")


def validate_offline_original_joins_v1(db):
    """Validate immutable same-operation joins before C09 or migration copying.

    This classifies persisted originals; installed Authority readers still own
    signature authentication and all execution/accounting admission.
    """
    from .joint_node_execution_v1 import validate_joint_original_joins_v1
    validate_joint_original_joins_v1(db)
    from .d11_offline_originals_v1 import TABLE
    if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (TABLE,)).fetchone() is None:
        return
    from .d11_offline_adoption_v1 import validate_offline_adoption_composite_v1
    from .d11_offline_historical_accounting_v1 import validate_offline_historical_accounting_composite_v1
    from .d11_offline_accounting_v1 import offline_accounting_original_ref_v1
    from .d10_offline_tick_execution_v1 import offline_tick_ids_v1
    originals = {}
    for row in db.execute("SELECT bot,persona,kind,original_ref,producing_operation_id,payload_json,payload_digest,signature FROM " + TABLE):
        kind, ref, raw, digest = validate_domain_production_row_v1(TABLE, TABLE_COLUMNS[TABLE], row)
        originals[(NamespaceId(row[0], row[1]), kind, ref)] = (row[4],
            decode_domain_production_content_v1(TABLE, kind, row[5]), raw, digest)
    for (ns, kind, ref), (operation_id, value, raw, digest) in originals.items():
        if kind in {"cancellation_gate", "cancellation_receipt"}:
            gate = originals.get((ns, "cancellation_gate", ref))
            receipt = originals.get((ns, "cancellation_receipt", ref))
            if gate is None or receipt is None or gate[0] != operation_id or receipt[0] != operation_id:
                raise DomainProductionErasureHold("offline cancellation gate/receipt lost its same-operation join")
            if kind == "cancellation_receipt":
                continue
            from .d11_offline_unstarted_cancellation_v1 import validate_offline_unstarted_cancellation_composite_v1
            accounting = originals.get((ns, "accounting_prepared", offline_accounting_original_ref_v1(value.binding)))
            if (accounting is None or accounting[1].binding != value.binding
                    or accounting[1].prepared_digest != value.prepared_digest
                    or accounting[3] != value.accounting_original_digest):
                raise DomainProductionErasureHold("offline cancellation lost its actual content-free preparation")
            validate_offline_unstarted_cancellation_composite_v1(db, gate=value, result=receipt[2])
            continue
        if kind in {"historical_accounting_gate", "historical_accounting_receipt"}:
            gate = originals.get((ns, "historical_accounting_gate", ref))
            receipt = originals.get((ns, "historical_accounting_receipt", ref))
            if gate is None or receipt is None or gate[0] != operation_id or receipt[0] != operation_id:
                raise DomainProductionErasureHold("offline historical gate/receipt lost its same-operation join")
            if kind == "historical_accounting_receipt":
                continue
            binding = value.binding
            accounting = originals.get((ns, "accounting_prepared", offline_accounting_original_ref_v1(binding)))
            if (accounting is None or accounting[1].binding != binding
                    or accounting[1].prepared_digest != value.prepared_digest
                    or accounting[3] != value.accounting_original_digest):
                raise DomainProductionErasureHold("offline historical accounting lost its signed cost original")
            validate_offline_historical_accounting_composite_v1(db, gate=value, result=receipt[2])
            continue
        if kind not in {"adoption_bridge", "adoption_receipt"}:
            continue
        bridge = originals.get((ns, "adoption_bridge", ref))
        receipt = originals.get((ns, "adoption_receipt", ref))
        if bridge is None or receipt is None or bridge[0] != operation_id or receipt[0] != operation_id:
            raise DomainProductionErasureHold("offline adoption bridge/receipt lost the same-operation join")
        if kind == "adoption_receipt":
            continue
        binding = value.binding
        accounting = originals.get((ns, "accounting_prepared", offline_accounting_original_ref_v1(binding)))
        ids = offline_tick_ids_v1(ns, binding.schedule_ref, binding.scheduled_at_utc)
        adopted = originals.get((ns, "adopted_tick", ids["result"]))
        if (accounting is None or accounting[1].binding != binding
                or accounting[1].prepared_digest != value.prepared_digest
                or adopted is None or adopted[0] != operation_id):
            raise DomainProductionErasureHold("offline adoption lost its accounting or adopted original")
        validate_offline_adoption_composite_v1(db, gate=value, result=receipt[2], adopted=adopted[1])


def _linked_identities(raw):
    if type(raw) is dict:
        for name, value in raw.items():
            if type(value) is str and (name.endswith(("_ref", "_digest")) or name in {"original_ref", "job_id", "operation_id", "activity_id", "effect_id"}):
                yield value
            elif type(value) in (dict, list):
                yield from _linked_identities(value)
    elif type(raw) is list:
        for value in raw:
            yield from _linked_identities(value)


def domain_production_original_dispositions_v1(table, columns, rows, *, affected, affected_operations,
        nested_hits, source_ids, authority_namespace=None, db=None, qualified_retention_manifests=None, qualified_retention_operation_id=None):
    if table in DERIVED_STORE_TABLES_V6:
        if db is None:
            raise DomainProductionErasureHold("derived inventory requires its actual Graph/paid-original database")
        return _derived_store_dispositions_v6(db, table, columns, rows, affected=affected,
            affected_operations=affected_operations, authority_namespace=authority_namespace,
            qualified_retention_manifests=qualified_retention_manifests, qualified_retention_operation_id=qualified_retention_operation_id)
    if table == "graph_d11_life_artifact_stage_v1":
        from .c09_life_originals_v1 import life_stage_dispositions_v1
        return life_stage_dispositions_v1(columns, rows, affected=affected, affected_operations=affected_operations,
            nested_hits=nested_hits, source_ids=source_ids, authority_namespace=authority_namespace)
    originals = [validate_domain_production_row_v1(table, columns, row, authority_namespace=authority_namespace) for row in rows]
    if table in SOURCE_INDEPENDENT_POLICY_TABLES or table in SOURCE_INDEPENDENT_METADATA_TABLES:
        return tuple("preserved_exact" for _ in originals)
    links, removed = set(affected) | set(affected_operations), set()
    while True:
        count = len(removed)
        for index, (kind, ref, raw, digest) in enumerate(originals):
            if index in removed:
                continue
            if table == "graph_d05_production_policies_v1" and raw.get("schema_version") is None:
                continue  # Exact historical v1 has no content/source closure.
            if table == "graph_d11_offline_originals_v1" and kind in {
                    "accounting_prepared", "historical_accounting_gate", "historical_accounting_receipt",
                    "cancellation_gate", "cancellation_receipt"}:
                # This fixed contract has no Graph body/content fields; its
                # exact signed quote/grant/reserve joins remain real accounting.
                if domain_production_source_closure_v1(table, kind, rows[index][columns.index("payload_json")]):
                    raise DomainProductionErasureHold("offline accounting fact unexpectedly contains source content")
                continue
            if table == "graph_d11_life_originals_v1":
                from .c09_life_originals_v1 import FACT_KINDS
                if kind in FACT_KINDS:
                    if domain_production_source_closure_v1(table, kind, rows[index][columns.index("payload_json")]):
                        raise DomainProductionErasureHold("Life accounting original contains source body references")
                    continue
            row = dict(zip(columns, rows[index]))
            if table == "graph_d11_life_originals_v1":
                from .c09_life_originals_v1 import life_original_content_projection_v1
                raw = life_original_content_projection_v1(kind, raw)
            roots = _json(row["source_refs_json"]) if "source_refs_json" in row else []
            if (ref in links or row.get("producing_operation_id") in links or row.get("job_id") in links
                    or nested_hits(raw, affected, source_ids) or nested_hits(roots, affected, source_ids)
                    or set(domain_production_source_closure_v1(table, kind, row["payload_json"])) & set(affected)
                    or set(_linked_identities(raw)) & links):
                removed.add(index)
                links.update((ref, digest, *_linked_identities(raw)))
        if len(removed) == count:
            break
    return tuple("derived_removed" if index in removed else "preserved_exact" for index in range(len(originals)))


def decode_personal_candidate_request_v1(operation_kind, raw, *, depth=0):
    """Only the two exact registered request variants; no generic dictionary."""
    from ..domains.d08.personal_candidate_v1 import (
        PREPARE_OPERATION_V1, SELECT_OPERATION_V2,
        PrepareCurrentPersonalCandidatesRequestV1, SelectCurrentPersonalStepRequestV2,
    )
    variants = {PREPARE_OPERATION_V1: PrepareCurrentPersonalCandidatesRequestV1,
        SELECT_OPERATION_V2: SelectCurrentPersonalStepRequestV2}
    if operation_kind not in variants:
        raise DomainProductionErasureHold("unknown personal candidate request operation")
    expected = variants[operation_kind]
    _exact(raw, (field.name for field in fields(expected)))
    hints = get_type_hints(expected)
    decoded = {field.name: decode_typed_production_value_v1(raw[field.name], hints[field.name], depth=depth + 1)
        for field in fields(expected)}
    value = expected(**decoded)
    from ..domains.d01.production_operations_v1 import plain_v1
    if plain_v1(value) != raw:
        raise DomainProductionErasureHold("personal candidate request wire does not round-trip exactly")
    return value


def personal_candidate_reference_closure_v1(raw, expected):
    """Validate content before exposing Graph references to C09/migration."""
    from ..domains.d08.personal_candidate_v1 import (
        PrepareCurrentPersonalCandidatesRequestV1, SelectCurrentPersonalStepRequestV2,
        PreparedPersonalCandidateSetV1, CurrentPersonalNeedQualificationV1,
        CurrentPersonalCandidateEligibilityV1, CurrentPersonalCandidatePriceV1,
        ArtifactPhaseCandidateBindingV1, ArtifactPhaseCandidateBindingV2, ArtifactPhaseCandidateBindingV3, SourceNoteCandidateBindingV1,
    )
    from ..model_broker.artifact_draft_v1 import ArtifactDraftInputV2, ArtifactDraftInputV3, ArtifactDraftPriorContentCommitmentV2
    allowed = {PrepareCurrentPersonalCandidatesRequestV1, SelectCurrentPersonalStepRequestV2,
        PreparedPersonalCandidateSetV1, CurrentPersonalNeedQualificationV1, CurrentPersonalCandidateEligibilityV1,
        CurrentPersonalCandidatePriceV1, ArtifactPhaseCandidateBindingV1, ArtifactPhaseCandidateBindingV2, ArtifactPhaseCandidateBindingV3, SourceNoteCandidateBindingV1,
        ArtifactDraftInputV2, ArtifactDraftInputV3, ArtifactDraftPriorContentCommitmentV2}
    if expected not in allowed:
        raise DomainProductionErasureHold("unregistered personal candidate reference-closure type")
    value = decode_typed_production_value_v1(raw, expected)
    from ..domains.d01.production_operations_v1 import plain_v1
    if plain_v1(value) != raw:
        raise DomainProductionErasureHold("candidate reference content changed its canonical wire")
    return tuple(sorted(set(_references(raw))))


def _validate_prepared_candidate_scope_v1(prepared):
    from ..domains.d08.personal_candidate_v1 import ArtifactPhaseCandidateBindingV1, ArtifactPhaseCandidateBindingV2, ArtifactPhaseCandidateBindingV3
    ns, activity = prepared.namespace, prepared.plan_head.key.owner.subject
    if (not prepared.need.complete or prepared.need.new_c3_required or prepared.need.meaningful_gaps
            or not prepared.need.query_coverage
            or any(not page.complete for page in prepared.need.query_coverage)
            or prepared.plan_head.key.owner.kind != "activity" or prepared.goal_head.key.owner.kind != "activity"
            or prepared.goal_head.key.owner.subject != activity
            or NamespaceId.from_key(prepared.plan_head.key) != ns or NamespaceId.from_key(prepared.goal_head.key) != ns
            or prepared.need.plan_head != prepared.plan_head or prepared.need.goal_head != prepared.goal_head):
        raise DomainProductionErasureHold("prepared candidate Plan/Goal/Need scope differs")
    decision = AtomKey.from_token(prepared.future_decision_ref)
    expected_id = "decision:" + canonical_digest((ns, activity, prepared.selection_operation_id, prepared.plan_head.key.token))[:48]
    if decision != AtomKey(prepared.plan_head.key.owner, "d08.decision_record.v2", expected_id):
        raise DomainProductionErasureHold("candidate preparation changed its stable future Decision")
    for ref in prepared.source_refs:
        if NamespaceId.from_key(AtomKey.from_token(ref)) != ns:
            raise DomainProductionErasureHold("candidate source closure crossed namespace")
    for row in prepared.candidates:
        if (row.eligibility.hard_status == "eligible" and row.price is None
                or row.future_identity.activity_id != activity or row.future_identity.parent_budget_lease_ref != prepared.parent_budget_lease_ref
                or row.price is not None and (row.price.candidate_ref, row.price.parameter_digest) != (row.binding.candidate_ref, row.binding.digest)):
            raise DomainProductionErasureHold("candidate future identity/price differs from its bound input")
        if type(row.binding) in {ArtifactPhaseCandidateBindingV1, ArtifactPhaseCandidateBindingV2, ArtifactPhaseCandidateBindingV3} and row.binding.task.namespace != ns:
            raise DomainProductionErasureHold("artifact candidate task crossed namespace")


def _validate_personal_candidate_provenance_v1(domain, operation_kind, provenance):
    from ..domains.d08.personal_candidate_v1 import PREPARE_OPERATION_V1, SELECT_OPERATION_V2, PreparedPersonalCandidateSetV1
    from ..domains.d08.personal_plan_v1 import DecisionRecordV2, QualifiedPersonalCandidateV1
    from ..domains.d01.production_operations_v1 import MethodStrategyProjectionV1
    if domain != "d08":
        raise DomainProductionErasureHold("personal candidate operation has another writer")
    if provenance == {}:
        return ()  # Exact missing-input stage; cannot confer candidate eligibility.
    if operation_kind == PREPARE_OPERATION_V1:
        if (type(provenance) is not dict or "prepared_candidates" not in provenance
                or not set(provenance) <= {"prepared_candidates", "artifact_phase_counts", "relationship_preference"}):
            raise DomainProductionErasureHold("candidate preparation differs from its exact installed provenance")
        prepared = decode_typed_production_value_v1(provenance["prepared_candidates"], PreparedPersonalCandidateSetV1)
        _validate_prepared_candidate_scope_v1(prepared)
        refs = set(personal_candidate_reference_closure_v1(provenance["prepared_candidates"], PreparedPersonalCandidateSetV1))
        if "relationship_preference" in provenance:
            from ..domains.d05.relationship_revision_v2 import RelationshipPreferenceProjectionV2
            relation = decode_typed_production_value_v1(provenance["relationship_preference"], RelationshipPreferenceProjectionV2)
            if (relation.namespace != prepared.namespace or set(relation.candidate_refs) != {row.binding.candidate_ref for row in prepared.candidates}
                    or not set(relation.read_versions) <= set(prepared.read_versions)):
                raise DomainProductionErasureHold("relationship preparation differs from its actual frozen scope/read set")
            refs.update(_references(provenance["relationship_preference"]))
        if "artifact_phase_counts" in provenance:
            from ..model_broker.artifact_phase_count_v1 import artifact_phase_count_request_from_wire_v1, artifact_phase_count_evidence_from_wire_v1
            counts = provenance["artifact_phase_counts"]
            if type(counts) is not list or len(counts) > 6:
                raise DomainProductionErasureHold("candidate count provenance exceeds its actual finite candidates")
            for row in counts:
                _exact(row, {"count_request", "signed_envelope"})
                _exact(row["signed_envelope"], {"payload", "signature_hex"})
                count = artifact_phase_count_request_from_wire_v1(row["count_request"])
                evidence = artifact_phase_count_evidence_from_wire_v1(row["signed_envelope"]["payload"])
                candidates = tuple(candidate for candidate in prepared.candidates if candidate.binding.digest == count.candidate_parameter_digest)
                signature = row["signed_envelope"]["signature_hex"]
                if (len(candidates) != 1 or count.namespace != prepared.namespace or count.input_kind != "prospective"
                        or count.frozen_material_digest != candidates[0].prospective_input_digest
                        or evidence.request_digest != count.digest or type(signature) is not str
                        or re.fullmatch(r"[0-9a-f]{128}", signature) is None):
                    raise DomainProductionErasureHold("candidate signed count retained bytes changed their actual input")
                refs.update(_references(row))
        return tuple(sorted(refs))
    if operation_kind != SELECT_OPERATION_V2:
        raise DomainProductionErasureHold("unregistered personal candidate stage operation")
    required = {"decision", "candidate_evidence", "prepared_candidates_operation_id", "prepared_candidates_digest", "value_evaluation"}
    if (type(provenance) is not dict or not required <= set(provenance)
            or not set(provenance) <= required | {"method_strategy", "relationship_preference"}):
        raise DomainProductionErasureHold("prepared selection provenance differs from its exact producer")
    decision = decode_typed_production_value_v1(provenance["decision"], DecisionRecordV2)
    candidates = decode_typed_production_value_v1(provenance["candidate_evidence"], tuple[QualifiedPersonalCandidateV1, ...])
    preparation = decode_typed_production_value_v1(provenance["prepared_candidates_operation_id"], str)
    if not preparation or len(preparation.encode()) > 4096:
        raise DomainProductionErasureHold("selection preparation locator differs")
    for name in ("prepared_candidates_digest", "value_evaluation"):
        if type(provenance[name]) is not str or re.fullmatch(r"[0-9a-f]{64}", provenance[name]) is None:
            raise DomainProductionErasureHold("selection actual original commitment differs")
    if (not 1 <= len(candidates) <= 6 or len({row.candidate_ref for row in candidates}) != len(candidates)
            or len({row.action_ref for row in candidates}) != len(candidates)
            or set(decision.eligible_action_refs) != {row.action_ref for row in candidates if row.hard_status == "eligible"}):
        raise DomainProductionErasureHold("Decision eligibility differs from its actual bounded candidate evidence")
    if "relationship_preference" in provenance:
        from ..domains.d05.relationship_revision_v2 import RelationshipPreferenceProjectionV2
        relation = decode_typed_production_value_v1(provenance["relationship_preference"], RelationshipPreferenceProjectionV2)
        eligible = {row.candidate_ref for row in candidates if row.hard_status == "eligible"}
        if (set(relation.candidate_refs) != {row.candidate_ref for row in candidates}
                or any(a not in eligible or b not in eligible for a, b in relation.preference_edges)):
            raise DomainProductionErasureHold("relationship preference cannot create hard candidate eligibility")
    if "method_strategy" in provenance:
        strategy = decode_typed_production_value_v1(provenance["method_strategy"], MethodStrategyProjectionV1)
        if set(strategy.candidate_refs) != {row.candidate_ref for row in candidates}:
            raise DomainProductionErasureHold("method projection differs from selected candidate scope")
    return tuple(sorted(set(_references(provenance))))


def _general_growth_provenance_types_v1(operation_kind):
    from .d01_general_growth_v1 import (GeneralGrowthIntentOriginalV1,
        GeneralGrowthTrialAdmissionV1,GeneralGrowthTrialOriginalV1)
    from .d01_production_operations_v1 import GrowthIntentOriginalV1,GrowthCounterevidenceOriginalV1
    from .domain_production_contracts_v1 import ProductionOriginalRefV1
    return {
        'freeze_general_growth_intent_v1':{'general_growth_intent':GeneralGrowthIntentOriginalV1,
            'growth_proposal':GrowthIntentOriginalV1,'growth_counterevidence':GrowthCounterevidenceOriginalV1,
            'semantic_interpretation':ProductionOriginalRefV1},
        'register_general_growth_trial_start_v1':{'general_growth_trial_admission':GeneralGrowthTrialAdmissionV1},
        'derive_general_growth_trial_v1':{'general_growth_trial':GeneralGrowthTrialOriginalV1,
            'trial_start_original':ProductionOriginalRefV1},
        'adopt_general_growth_v1':{'general_growth_intent':GeneralGrowthIntentOriginalV1,
            'trial_start_originals':tuple[ProductionOriginalRefV1,...],
            'trial_originals':tuple[ProductionOriginalRefV1,...],'growth':None}}[operation_kind]


def validate_domain_stage_provenance_v1(domain, operation_kind, provenance):
    from .named_joint_binding_provenance_v1 import KEY as NAMED_JOINT_KEY,validate_named_joint_provenance_v1
    if type(provenance)is dict and NAMED_JOINT_KEY in provenance:
        selector,current,scope,refs=validate_named_joint_provenance_v1(domain,operation_kind,provenance[NAMED_JOINT_KEY])
        business={name:value for name,value in provenance.items()if name!=NAMED_JOINT_KEY}
        if business.get('managed_window_argument')!=json.loads(canonical_serialize(selector.argument)):
            raise ValueError('Named Joint provenance changed its actual managed argument')
        return tuple(sorted(set((*refs,*validate_domain_stage_provenance_v1(domain,operation_kind,business)))))
    from .artifact_model_control_contract_v1 import validate_artifact_model_control_provenance_v1
    artifact=validate_artifact_model_control_provenance_v1(domain,operation_kind,provenance)
    if artifact is not None:
        business,refs=artifact
        return tuple(sorted(set((*refs,*validate_domain_stage_provenance_v1(domain,operation_kind,business)))))
    from .habit_maintenance_followup_v3 import validate_habit_maintenance_followup_provenance_v3
    maintenance=validate_habit_maintenance_followup_provenance_v3(domain,operation_kind,provenance)
    if maintenance is not None:return validate_domain_stage_provenance_v1(domain,operation_kind,maintenance)
    from .habit_followup_source_v3 import validate_body_preparation_provenance_v3
    body=validate_body_preparation_provenance_v3(domain,operation_kind,provenance)
    if body is not None:
        business,refs=body
        return tuple(sorted(set((*refs,*validate_domain_stage_provenance_v1(domain,operation_kind,business)))))
    from .habit_followup_source_v3 import PROVENANCE as HABIT_FOLLOWUP,validate_followup_target_v3
    if type(provenance)is dict and HABIT_FOLLOWUP in provenance:
        from .habit_activity_history_v1 import HABIT_ACTIVITY_PROVENANCE_V1,validate_habit_activity_provenance_v1
        if HABIT_ACTIVITY_PROVENANCE_V1 not in provenance:
            raise ValueError('Habit followup target requires its actual ordinary execution provenance')
        selected=validate_followup_target_v3(domain,operation_kind,provenance[HABIT_FOLLOWUP])
        actual,refs=validate_habit_activity_provenance_v1(domain,operation_kind,provenance[HABIT_ACTIVITY_PROVENANCE_V1])
        if selected!=actual:raise ValueError('Habit followup target belongs to another signed actual phase')
        business={name:value for name,value in provenance.items()if name!=HABIT_FOLLOWUP}
        return tuple(sorted(set((*refs,*validate_domain_stage_provenance_v1(domain,operation_kind,business)))))
    if type(provenance)is dict and 'managed_metadata_retirements_v1'in provenance:
        from .b3_managed_metadata_v1 import decode_managed_metadata_retirement_shape_v1
        decode_managed_metadata_retirement_shape_v1(domain,operation_kind,provenance['managed_metadata_retirements_v1'])
        business={name:value for name,value in provenance.items()if name!='managed_metadata_retirements_v1'}
        return validate_domain_stage_provenance_v1(domain,operation_kind,business)
    from .habit_maintenance_provenance_v1 import MAINTENANCE_PROVENANCE_V1,validate_habit_maintenance_provenance_v1
    if type(provenance)is dict and MAINTENANCE_PROVENANCE_V1 in provenance:
        from .habit_census_provenance_v1 import OWNER_CENSUS_V1
        from .habit_activity_history_v1 import HABIT_ACTIVITY_PROVENANCE_V1
        if any(name in provenance for name in (OWNER_CENSUS_V1,HABIT_ACTIVITY_PROVENANCE_V1)):
            raise ValueError('Habit maintenance cannot borrow Owner or execution provenance')
        selector,current,owner,metadata=validate_habit_maintenance_provenance_v1(domain,operation_kind,provenance[MAINTENANCE_PROVENANCE_V1])
        business={name:value for name,value in provenance.items()if name!=MAINTENANCE_PROVENANCE_V1}
        refs=validate_domain_stage_provenance_v1(domain,operation_kind,business)
        return tuple(sorted(set((*refs,selector.policy_ref,selector.occurrence_ref,*(row.key.token for row in metadata)))))
    from .habit_census_provenance_v1 import OWNER_CENSUS_V1,validate_habit_owner_census_v1
    if type(provenance)is dict and OWNER_CENSUS_V1 in provenance:
        metadata=validate_habit_owner_census_v1(domain,operation_kind,provenance[OWNER_CENSUS_V1])
        business={name:value for name,value in provenance.items()if name!=OWNER_CENSUS_V1}
        from .habit_activity_history_v1 import HABIT_ACTIVITY_PROVENANCE_V1
        if HABIT_ACTIVITY_PROVENANCE_V1 in business:
            raise ValueError('Owner census and background execution carriers cannot coexist')
        refs=validate_domain_stage_provenance_v1(domain,operation_kind,business)
        return tuple(sorted(set((*refs,*(version.key.token for version in metadata)))))
    from .habit_activity_history_v1 import (HABIT_ACTIVITY_PROVENANCE_V1,
        validate_habit_activity_provenance_v1)
    if type(provenance) is dict and HABIT_ACTIVITY_PROVENANCE_V1 in provenance:
        selector, refs = validate_habit_activity_provenance_v1(domain, operation_kind,
            provenance[HABIT_ACTIVITY_PROVENANCE_V1])
        business = {key: value for key, value in provenance.items() if key != HABIT_ACTIVITY_PROVENANCE_V1}
        return tuple(sorted(set((*refs, *validate_domain_stage_provenance_v1(domain, operation_kind, business)))))
    from .conditioned_self_operations_v1 import OPERATIONS as CONDITIONED_OPERATIONS,validate_conditioned_business_provenance_v1
    if operation_kind in CONDITIONED_OPERATIONS:
        return validate_conditioned_business_provenance_v1(domain,operation_kind,provenance)
    from .joint_habit_provenance_v1 import JOINT_HABIT_BUSINESS_KINDS_V1,validate_joint_habit_business_provenance_v1
    if(operation_kind in JOINT_HABIT_BUSINESS_KINDS_V1
            or (domain,operation_kind)==('d10','prepare_life')and 'habit_life_occurrence_transition'in provenance
            or 'managed_window_argument'in provenance):
        return validate_joint_habit_business_provenance_v1(domain,operation_kind,provenance)
    from ..domains.d03.world_history_v1 import WORLD_OPERATIONS,WorldAssertionInputV1,WorldViewResultV1,WorldPerspectiveExpressionInputV1
    if operation_kind in WORLD_OPERATIONS:
        expected_domain="d09" if operation_kind=="project_world_perspective_v1" else "d03"
        field_name,cls={"adopt_world_assertion_v1":("world_assertion",WorldAssertionInputV1),
            "relearn_world_assertion_v1":("world_assertion",WorldAssertionInputV1),
            "query_world_view_v1":("world_view",WorldViewResultV1),
            "project_world_perspective_v1":("world_expression",WorldPerspectiveExpressionInputV1)}[operation_kind]
        if domain!=expected_domain:
            raise DomainProductionErasureHold("World provenance changed its actual writer")
        _exact(provenance,(field_name,) if operation_kind=="query_world_view_v1" else
            (field_name,"world_source_roots","semantic_mesh") if operation_kind in {"adopt_world_assertion_v1","relearn_world_assertion_v1"}
            else (field_name,"semantic_mesh"))
        decode_typed_production_value_v1(provenance[field_name],cls)
        if operation_kind in {"adopt_world_assertion_v1","relearn_world_assertion_v1"}:
            roots=decode_typed_production_value_v1(provenance["world_source_roots"],tuple[str,...])
            if roots!=tuple(sorted(set(roots))) or not 1<=len(roots)<=16:
                raise DomainProductionErasureHold("World producer Source root set exceeds its actual bound")
            if any(AtomKey.from_token(ref).type_name!="memory.source" for ref in roots):
                raise DomainProductionErasureHold("World producer Source closure has another type")
        if operation_kind!="query_world_view_v1":
            from .domain_mesh_tick_v1 import validate_semantic_mesh_trace_v1
            validate_semantic_mesh_trace_v1(provenance["semantic_mesh"])
        return tuple(sorted(set(_references(provenance))))
    if type(provenance) is dict and 'semantic_mesh' in provenance:
        from .domain_mesh_tick_v1 import validate_semantic_mesh_trace_v1
        from .domain_mesh_catalog_v1 import require_semantic_recipe_operation_v1
        trace = validate_semantic_mesh_trace_v1(provenance['semantic_mesh'])
        profile = require_semantic_recipe_operation_v1(trace.after_tick.recipe_version,operation_kind)
        if profile.domain != domain or trace.operation_kind != operation_kind:
            raise DomainProductionErasureHold('semantic companion crossed its exact installed domain producer')
        body = {key:value for key,value in provenance.items() if key != 'semantic_mesh'}
        refs = validate_domain_stage_provenance_v1(domain,operation_kind,body)
        return tuple(sorted(set((*refs,*_references(provenance['semantic_mesh'])))))
    if operation_kind in {'freeze_general_growth_intent_v1','register_general_growth_trial_start_v1',
            'derive_general_growth_trial_v1','adopt_general_growth_v1'}:
        if domain!='d01':
            raise DomainProductionErasureHold('General growth has another actual domain writer')
        if provenance=={}:return ()
        shape=_general_growth_provenance_types_v1(operation_kind)
        _exact(provenance,shape)
        for name,cls in shape.items():
            if cls is not None:decode_typed_production_value_v1(provenance[name],cls)
        if operation_kind=='adopt_general_growth_v1':
            validate_domain_stage_provenance_v1('d01','adopt_growth',provenance['growth'])
        return tuple(sorted(set(_references(provenance))))
    if operation_kind in {"prepare_personal_candidate_eligibility_v1", "adopt_personal_candidate_eligibility_v1"}:
        if domain != "d08": raise DomainProductionErasureHold("personal eligibility has another writer")
        from .personal_candidate_eligibility_v1 import PreparedPersonalEligibilityWaveV1, CompletedPersonalEligibilityWaveV1
        from ..domains.d08.personal_candidate_v1 import CurrentPersonalCandidateEligibilityV1
        if operation_kind == "prepare_personal_candidate_eligibility_v1":
            _exact(provenance, {"personal_eligibility_inputs"})
            decode_typed_production_value_v1(provenance["personal_eligibility_inputs"], PreparedPersonalEligibilityWaveV1)
        else:
            _exact(provenance, {"prepared_eligibility_digest", "projection_wave", "eligibilities"})
            decode_typed_production_value_v1(provenance["projection_wave"], CompletedPersonalEligibilityWaveV1)
            rows = provenance["eligibilities"]
            if type(rows) is not list or not 1 <= len(rows) <= 6:
                raise DomainProductionErasureHold("personal eligibility exceeds the exact candidate bound")
            for row in rows: decode_typed_production_value_v1(row, CurrentPersonalCandidateEligibilityV1)
        return tuple(sorted(set(_references(provenance))))
    if operation_kind in {"pause_project_v1", "resume_project_v1"}:
        if domain != "d08":
            raise DomainProductionErasureHold("project control has another domain writer")
        if provenance == {}:
            return ()
        _exact(provenance, {"project_control"})
        from .d08_project_control_v1 import decode_project_control_original_v1
        control = decode_project_control_original_v1(provenance["project_control"])
        if control.control != ("pause" if operation_kind == "pause_project_v1" else "resume"):
            raise DomainProductionErasureHold("project control original differs from its actual operation")
        return tuple(sorted(set(_references(provenance["project_control"]))))
    if operation_kind == "initialize_relationship_prior_v2":
        if domain != "d05":
            raise DomainProductionErasureHold("relationship authored prior has another writer")
        _exact(provenance, {"policy", "initial_origin", "initialization"})
        from .domain_production_contracts_v1 import ProductionOriginalRefV1
        from ..domains.d05.relationship_revision_v2 import RelationshipCheckpointV2
        policy = decode_typed_production_value_v1(provenance["policy"], ProductionOriginalRefV1)
        origin = decode_typed_production_value_v1(provenance["initial_origin"], ProductionOriginalRefV1)
        value = decode_typed_production_value_v1(provenance["initialization"], RelationshipCheckpointV2)
        if (policy.kind != "d05.installed_policy" or value.initialization_kind != "authored_prior"
                or origin.original_ref != value.initial_origin_ref or policy.original_digest != value.policy_digest):
            raise DomainProductionErasureHold("relationship authored prior lost its actual independent source/policy")
        return tuple(sorted(set(_references(provenance))))
    from .d01_method_learning_v1 import OPERATIONS as METHOD_OPERATIONS
    if operation_kind in METHOD_OPERATIONS:
        if domain != "d01":
            raise DomainProductionErasureHold("method-learning original has another writer")
        if provenance == {}:
            return ()
        from ..domains.d01.method_learning_v1 import (MethodEvaluationProtocolV1, MethodScopedTrialV1,
            MethodExperimentPlanV1, MethodEvaluationV1, MethodOutcomeReviewV1, MethodTrialProposalV2, MethodBlindReviewRequestV2)
        from .domain_production_contracts_v1 import ProductionOriginalRefV1
        from ..domains.d01 import GrowthProposal
        from .method_pair_shared_input_v1 import MethodPairSharedInputOriginalV1
        shapes = {
            "register_method_trial_proposal_v2": {"method_trial_proposal": MethodTrialProposalV2, "active_strategy": str},
            "register_scoped_method_trial_v2": {"trial": MethodScopedTrialV1, "GP1": ProductionOriginalRefV1,
                "proposal_original": ProductionOriginalRefV1, "proposal_ref": str, "proposal_digest": str,
                "active_strategy": str, "selection_basis": str},
            "register_method_blind_review_request_v2": {"method_blind_review_request": MethodBlindReviewRequestV2},
            "register_method_evaluation_protocol_v1": {"protocol": MethodEvaluationProtocolV1},
            "register_scoped_method_trial_v1": {"trial": MethodScopedTrialV1, "GP1": ProductionOriginalRefV1,
                "active_strategy": str, "selection_basis": str},
            "register_method_experiment_v1": {"experiment": MethodExperimentPlanV1, "real_experience_increment": int},
            "register_method_experiment_v2": {"experiment": MethodExperimentPlanV1, "real_experience_increment": int, "shared_input": MethodPairSharedInputOriginalV1},
            "evaluate_current_method_outcome_v1": {"method_evaluation": MethodEvaluationV1, "actual_observer_operation": str},
            "review_current_method_growth_v1": {"method_outcome_review": MethodOutcomeReviewV1},
            "adopt_current_method_strategy_v1": {"method_outcome_review_ref": str, "method_outcome_review_digest": str,
                "growth_proposal": GrowthProposal, "semantic_identity_changed": bool},
        }
        shape = shapes[operation_kind]
        if operation_kind=='review_current_method_growth_v1' and type(provenance)is dict and set(provenance)==set(shape)|{'conditioned_source_roots','conditioned_original_deadline_utc'}:
            from .conditioned_self_operations_v1 import _validate_conditioned_source_provenance_v1
            review=decode_typed_production_value_v1(provenance['method_outcome_review'],MethodOutcomeReviewV1)
            _validate_conditioned_source_provenance_v1(provenance,review.namespace,review.source_refs)
            return tuple(sorted(set(_references(provenance))))
        _exact(provenance, shape)
        for field, cls in shape.items():
            decode_typed_production_value_v1(provenance[field], cls)
        if (operation_kind in {"register_scoped_method_trial_v1", "register_scoped_method_trial_v2"}
                and (provenance["active_strategy"], provenance["selection_basis"]) != ("ST0", "scoped_trial")
                or operation_kind == "register_method_trial_proposal_v2" and provenance["active_strategy"] != "ST0"
                or operation_kind in {"register_method_experiment_v1", "register_method_experiment_v2"} and provenance["real_experience_increment"] != 0
                or operation_kind == "adopt_current_method_strategy_v1" and provenance["semantic_identity_changed"] is not False):
            raise DomainProductionErasureHold("method-learning registration cannot manufacture experience or semantic identity")
        return tuple(sorted(set(_references(provenance))))
    if operation_kind == "quote_current_method_choices_v1":
        if domain != "d02":
            raise DomainProductionErasureHold("method readiness has another writer")
        if provenance == {}:
            return ()
        _exact(provenance, {"method_readiness", "method_quote_evidence", "artifact_phase_counts"})
        from ..domains.d02.method_readiness_v1 import MethodReadinessOriginalV1, MethodReadinessEvidenceV1
        summary = decode_typed_production_value_v1(provenance["method_readiness"], MethodReadinessOriginalV1)
        evidence = decode_typed_production_value_v1(provenance["method_quote_evidence"], MethodReadinessEvidenceV1)
        from ..model_broker.artifact_phase_count_v1 import artifact_phase_count_request_from_wire_v1, artifact_phase_count_evidence_from_wire_v1
        counts = provenance["artifact_phase_counts"]
        if type(counts) is not list or len(counts) != 2:
            raise DomainProductionErasureHold("method readiness requires two actual bounded phase counts")
        for row in counts:
            _exact(row, {"count_request", "signed_envelope"})
            _exact(row["signed_envelope"], {"payload", "signature_hex"})
            count = artifact_phase_count_request_from_wire_v1(row["count_request"])
            measured = artifact_phase_count_evidence_from_wire_v1(row["signed_envelope"]["payload"])
            if (count.namespace != evidence.namespace or count.input_kind != "prospective"
                    or count.candidate_parameter_digest not in {choice.binding_digest for choice in evidence.choices}
                    or measured.request_digest != count.digest
                    or re.fullmatch(r"[0-9a-f]{128}", row["signed_envelope"]["signature_hex"]) is None):
                raise DomainProductionErasureHold("method readiness actual signed count identity differs")
        if set(summary.quote_original_refs) != {choice.quote_original_ref for choice in evidence.choices}:
            raise DomainProductionErasureHold("method readiness original quote membership differs")
        return tuple(sorted(set(_references(provenance))))
    if operation_kind == "observe_method_comparison_v1":
        if domain not in {"d11", "d06"}:
            raise DomainProductionErasureHold("method measurement has another composite writer")
        if provenance == {}:
            return ()
        _exact(provenance, {"method_comparison_observation", "measurement_source", "measurement_source_access",
            "measurement_parent_source_refs", "treatment_phase_billing", "baseline_phase_billing"})
        from ..domains.d01.method_learning_v1 import MethodComparisonObservationV2
        from ..memory_types import SourceRecord, validate_access
        observed = decode_typed_production_value_v1(provenance["method_comparison_observation"], MethodComparisonObservationV2)
        source = SourceRecord.from_dict(provenance["measurement_source"])
        validate_access(provenance["measurement_source_access"])
        parents = decode_typed_production_value_v1(provenance["measurement_parent_source_refs"], tuple[str, ...])
        if (source.source_kind, source.assertion_status, source.independence) != ("internal", "confirmed", "same_root") or not parents:
            raise DomainProductionErasureHold("method measured Source cannot manufacture independent external experience")
        fields = {"call_ref": str, "paid_ref": str, "paid_digest": str, "result_ref": str, "result_digest": str,
            "provider_receipt_digest": str, "evidence_kind": str, "input_tokens": int, "output_tokens": int,
            "lease_ref": str, "reservation_operation_id": str, "settlement_receipt_digest": str,
            "authorization_basis": str, "budget_lineage": list}
        lineage_fields = {"lease_ref": str, "parent_lease_ref": str | None, "currency": str,
            "creation_operation_id": str, "creation_request_digest": str, "creation_receipt_digest": str,
            "associated_grant_ref": str, "associated_grant_version": int, "associated_grant_digest": str}
        for name, calls in (("treatment_phase_billing", observed.treatment_call_refs), ("baseline_phase_billing", observed.baseline_call_refs)):
            rows = provenance[name]
            if type(rows) is not list or not 1 <= len(rows) <= 8 or tuple(row["call_ref"] for row in rows) != tuple(sorted(calls)):
                raise DomainProductionErasureHold("method measurement actual settled-call membership differs")
            for row in rows:
                _exact(row, fields)
                for field, cls in fields.items():
                    if field != "budget_lineage":
                        decode_typed_production_value_v1(row[field], cls)
                if type(row["budget_lineage"]) is not list:
                    raise DomainProductionErasureHold("method budget ancestry must be its closed actual row list")
                if any(row[field] < 0 for field in ("input_tokens", "output_tokens")):
                    raise DomainProductionErasureHold("method measured phase token quantities must remain actual and finite")
                if row["authorization_basis"] != "actual_prepared_producer" or len(row["budget_lineage"]) > 128:
                    raise DomainProductionErasureHold("method measurement requires actual prepared authorization and bounded budget ancestry")
                for ancestor in row["budget_lineage"]:
                    _exact(ancestor, lineage_fields)
                    for field, cls in lineage_fields.items():
                        decode_typed_production_value_v1(ancestor[field], cls)
                    if ancestor["associated_grant_version"] < 1:
                        raise DomainProductionErasureHold("method budget ancestry associated signed grant requires an actual positive version")
        return tuple(sorted(set(_references(provenance))))
    if operation_kind == 'input:freeze_owner_source_note_values_parent_v1':
        if domain != 'd08': raise DomainProductionErasureHold('Owner Values parent has another writer')
        _exact(provenance, {'owner_task_values_parent'})
        from .owner_source_note_values_v1 import OwnerTaskValuesParentV1
        decode_typed_production_value_v1(provenance['owner_task_values_parent'],OwnerTaskValuesParentV1)
        return tuple(sorted(set(_references(provenance))))
    if operation_kind in {"register_owner_source_note_life_plan_v1", "register_owner_source_note_life_outcome_v1"}:
        if domain != "d10":
            raise DomainProductionErasureHold("Owner Life selector has another writer")
        from .d11_life_contract_v1 import RegisteredLifePlanV2, RegisteredLifeOutcomeV2, life_from_wire_v1
        plan = operation_kind == "register_owner_source_note_life_plan_v1"
        fields = {"owner_task_authorization_ref", "owner_task_authorization_digest", "life_plan" if plan else "life_outcome"}
        if plan:
            fields |= {"action_original_ref", "action_original_digest", "body_original_ref", "body_original_digest"}
        _exact(provenance, fields)
        if not provenance["owner_task_authorization_ref"].startswith("owner-source-note-authorization:"):
            raise DomainProductionErasureHold("Owner Life selector lost its signed authorization locator")
        for key in fields:
            if key.endswith("_digest"):
                value = provenance[key]
                if type(value) is not str or len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
                    raise DomainProductionErasureHold("Owner Life original commitment must be an exact SHA256")
        life_from_wire_v1(provenance["life_plan" if plan else "life_outcome"], RegisteredLifePlanV2 if plan else RegisteredLifeOutcomeV2)
        return tuple(sorted(set(_references(provenance))))
    if operation_kind in {"create_owner_source_note_task_v1","acquire_owner_source_note_task_v1","checkpoint_owner_source_note_task_v1","cancel_owner_source_note_task_v1"}:
        if domain != 'd11': raise DomainProductionErasureHold('Owner task execution has another writer')
        fields = {'before_job','after_job','owner_task_responsibility'}
        if operation_kind == 'cancel_owner_source_note_task_v1':
            fields |= {'owner_task_authorization_ref','noop'}
        _exact(provenance, fields)
        from .owner_source_note_task_execution_v1 import decode_owner_source_note_task_job_v1
        from .owner_source_note_task_contract_v1 import OwnerSourceNoteTaskResponsibilityV2, OwnerSourceNoteTaskContinuationV2, owner_source_note_task_ids_v1
        responsibility = decode_typed_production_value_v1(provenance['owner_task_responsibility'],OwnerSourceNoteTaskResponsibilityV2)
        after = decode_owner_source_note_task_job_v1(provenance['after_job'],namespace=responsibility.namespace)
        continuation = decode_typed_production_value_v1(dict(after.continuation),OwnerSourceNoteTaskContinuationV2)
        ids = owner_source_note_task_ids_v1(responsibility.namespace,responsibility.owner_operation_id)
        if (after.job_id != ids['job_id'] or after.activity_id != ids['activity_id'] or after.operation_id != ids['create_operation_id']
                or after.budget_ref != responsibility.parent_budget_lease_ref
                or continuation.responsibility_ref != ids['responsibility_ref'] or continuation.responsibility_digest != responsibility.digest
                or continuation.authorization_original_ref != responsibility.authorization_original_ref
                or continuation.authorization_original_digest != responsibility.authorization_original_digest):
            raise DomainProductionErasureHold('Owner task execution changed its actual immutable job/cause/authorization/root')
        if operation_kind == 'create_owner_source_note_task_v1':
            if provenance['before_job'] is not None or after.phase != 'queued' or after.cancel_epoch:
                raise DomainProductionErasureHold('Owner task creation must be an actual initial queued job')
        else:
            before = decode_owner_source_note_task_job_v1(provenance['before_job'],namespace=responsibility.namespace)
            if (before.job_id,before.operation_id,before.activity_id,before.budget_ref,before.deadline_utc) != (
                    after.job_id,after.operation_id,after.activity_id,after.budget_ref,after.deadline_utc):
                raise DomainProductionErasureHold('Owner task transition substituted its actual initial identity/deadline')
            if operation_kind == 'cancel_owner_source_note_task_v1':
                from .cancel_owner_source_note_task_v1 import _plan_cancel
                if (type(provenance['noop']) is not bool or provenance['noop'] != (before == after)
                        or provenance['owner_task_authorization_ref'] != responsibility.authorization_original_ref
                        or after != _plan_cancel(before)):
                    raise DomainProductionErasureHold('Owner task cancellation changed its actual deterministic transition')
        return tuple(sorted(set(_references(provenance))))
    if operation_kind == "admit_owner_material_source_v1":
        if domain != "d06": raise DomainProductionErasureHold("Owner material has another writer")
        _exact(provenance, {"source_ref", "source", "source_access"})
        from ..memory_types import SourceRecord, validate_access
        source = SourceRecord.from_dict(provenance['source'])
        key = AtomKey.from_token(provenance['source_ref']); access = provenance['source_access']
        validate_access(access)
        if (key.type_name != 'memory.source' or key.owner.subject != source.source_id
                or (source.source_kind,source.assertion_status,source.independence,source.occurred_at,source.parent_source_ids) != ('authored','unknown','unknown',None,())
                or source.audiences != ('owner',) or source.purposes != ('context','consolidation')
                or source.provenance_root != 'owner-material:' + source.source_id
                or access != {'source_id':source.source_id,'audiences':['owner'],'purposes':['context','consolidation'],
                    'status':'active','recorded_at':source.recorded_at}):
            raise DomainProductionErasureHold('Owner material cannot manufacture an observation, experience, or another source right')
        return (key.token,)
    if (domain,operation_kind) == ("d07","focus_owner_source_note_task_v1"):
        _exact(provenance, {"owner_project_ref","owner_project_source_ref","owner_focus_selection",
            "authorization_original_ref","authorization_original_digest","task_job_ref","original_valid_until"})
        if (AtomKey.from_token(provenance["owner_project_ref"]).type_name != "d10.life_project.v1"
                or AtomKey.from_token(provenance["owner_project_source_ref"]).type_name != "memory.source"
                or AtomKey.from_token(provenance["task_job_ref"]).type_name != "runtime.job"
                or provenance["owner_focus_selection"] != "owner_task_project"
                or not provenance["authorization_original_ref"].startswith("owner-source-note-authorization:")
                or type(provenance["authorization_original_digest"]) is not str
                or len(provenance["authorization_original_digest"]) != 64
                or type(provenance["original_valid_until"]) not in (int,float)
                or not math.isfinite(provenance["original_valid_until"])):
            raise DomainProductionErasureHold("Owner task Focus has another exact task recipe")
        return tuple(sorted(set(_references(provenance))))
    if operation_kind == "prepare_owner_source_note_need_v1":
        if domain != "d07":
            raise DomainProductionErasureHold("Owner fixed-recipe Need has another writer")
        _exact(provenance, {"owner_source_note_need"})
        from .owner_source_note_need_v1 import OwnerSourceNoteNeedOriginalV2
        decode_typed_production_value_v1(provenance["owner_source_note_need"],OwnerSourceNoteNeedOriginalV2)
        return tuple(sorted(set(_references(provenance))))
    if operation_kind == "submit_owner_source_note_task_v1":
        if domain != "d08":
            raise DomainProductionErasureHold("Owner task submission has another domain writer")
        _exact(provenance, {"owner_task_cause", "owner_task_authorization"})
        from .owner_source_note_task_contract_v1 import OwnerTaskCauseV1, OwnerSourceNoteTaskAuthorizationV2
        cause = decode_typed_production_value_v1(provenance['owner_task_cause'], OwnerTaskCauseV1)
        auth = decode_typed_production_value_v1(provenance['owner_task_authorization'], OwnerSourceNoteTaskAuthorizationV2)
        if auth.cause != cause:
            raise DomainProductionErasureHold("Owner task authorization changed its actual management cause")
        return tuple(sorted(set(_references(provenance))))
    if operation_kind == "authorize_source_note_task_v1":
        if domain != "d11":
            raise DomainProductionErasureHold("SourceNote authorization has another writer")
        _exact(provenance, {"source_note_task_authorization"})
        from .source_note_task_authorization_v1 import SourceNoteTaskAuthorizationV1
        decode_typed_production_value_v1(provenance["source_note_task_authorization"], SourceNoteTaskAuthorizationV1)
        return tuple(sorted(set(_references(provenance))))
    if operation_kind == "create_source_note_foreground_cycle_v1":
        if domain != "d11":
            raise DomainProductionErasureHold("SourceNote initial responsibility has another writer")
        _exact(provenance, {"before_job", "after_job", "reply_allocation", "responsibility", "source_note_authorization"})
        from .source_note_foreground_v1 import ForegroundSourceNoteResponsibilityV1, ForegroundSourceNoteContinuationV1
        from .source_note_task_authorization_v1 import SourceNoteTaskAuthorizationV1
        from .foreground_call_plan_v1 import ForegroundReplyAllocationV1
        from .foreground_cycle_v1 import decode_foreground_job_v1, foreground_cycle_from_wire_v1
        responsibility = decode_typed_production_value_v1(provenance["responsibility"], ForegroundSourceNoteResponsibilityV1)
        authorization = decode_typed_production_value_v1(provenance["source_note_authorization"], SourceNoteTaskAuthorizationV1)
        job = decode_foreground_job_v1(provenance["after_job"], namespace=authorization.namespace)
        current = foreground_cycle_from_wire_v1(job.continuation)
        allocation = decode_typed_production_value_v1(provenance["reply_allocation"], ForegroundReplyAllocationV1)
        if (provenance["before_job"] is not None or type(current) is not ForegroundSourceNoteContinuationV1
                or current.responsibility_digest != responsibility.digest or current.authorization_original_digest != authorization.digest
                or responsibility.authorization_original_digest != authorization.digest
                or allocation.parent_lease_ref != authorization.parent_budget_lease_ref
                or allocation.child_lease_id != current.call_plan.protected_reply_lease_ref):
            raise DomainProductionErasureHold("SourceNote initial creation changed its actual Owner/task/root binding")
        return tuple(sorted(set(_references(provenance))))
    if operation_kind == "adopt_current_task_no_search_v1":
        if domain != "d07":
            raise DomainProductionErasureHold("current-task no-search has another writer")
        if provenance == {}:
            return ()
        from .d07_task_history_v1 import CurrentTaskNoSearchOriginalV1, CurrentTaskNoSearchDecisionV1
        if set(provenance) == {"task_no_search"}:
            decode_typed_production_value_v1(provenance["task_no_search"], CurrentTaskNoSearchOriginalV1)
        elif set(provenance) == {"task_no_search_decision"}:
            decode_typed_production_value_v1(provenance["task_no_search_decision"], CurrentTaskNoSearchDecisionV1)
        else:
            raise DomainProductionErasureHold("current-task no-search has no closed actual adopted decision variant")
        return tuple(sorted(set(_references(provenance))))
    if operation_kind == "adopt_current_c1_method_conditions_v1":
        if domain != "d07":
            raise DomainProductionErasureHold("actual C1 method condition has another writer")
        if provenance == {}:
            return ()
        shape = {"c1_original_ref": str, "c1_original_digest": str, "task_scope_ref": str,
            "task_scope_digest": str, "goal_ref": str, "goal_revision": int,
            "conditions": tuple[tuple[str, str, str], ...], "readiness_original_digest": str | None,
            "additional_model_calls": int, "subjective_confidence_origin": str}
        _exact(provenance, shape)
        for field, cls in shape.items():
            decode_typed_production_value_v1(provenance[field], cls)
        from ..domains.d07 import METHOD_CONDITION_IDS_V1
        if (provenance["additional_model_calls"] != 0 or provenance["subjective_confidence_origin"] != "not_requested_by_C1_schema"
                or len(provenance["conditions"]) != len(METHOD_CONDITION_IDS_V1)
                or {row[1] for row in provenance["conditions"]} != set(METHOD_CONDITION_IDS_V1)
                or any(AtomKey.from_token(row[0]).type_name != "d07.current_interpretation.v1"
                    or row[2] not in {"true", "false", "unknown"} for row in provenance["conditions"])):
            raise DomainProductionErasureHold("C1 method-condition original differs from its closed actual member set")
        return tuple(sorted(set(_references(provenance))))
    if operation_kind == "adopt_relationship_revision_v2":
        if domain != "d05":
            raise DomainProductionErasureHold("relationship revision has another writer")
        if provenance == {}:
            return ()
        _exact(provenance, {"evaluation", "policy", "duplicate", "held_reason"})
        from .domain_production_contracts_v1 import ProductionOriginalRefV1
        evaluation = decode_typed_production_value_v1(provenance["evaluation"], ProductionOriginalRefV1)
        policy = decode_typed_production_value_v1(provenance["policy"], ProductionOriginalRefV1)
        if type(provenance["duplicate"]) is not bool or policy.kind != "d05.installed_policy":
            raise DomainProductionErasureHold("relationship revision actual original provenance differs")
        decode_typed_production_value_v1(provenance["held_reason"], str | None)
        if AtomKey.from_token(evaluation.original_ref).type_name != "d07.current_interpretation.v1":
            raise DomainProductionErasureHold("relationship revision lost its actual adopted D07 evaluation")
        return tuple(sorted(set(_references(provenance))))
    if operation_kind in {"prepare_personal_candidates_v1", "select_personal_step_v2"}:
        return _validate_personal_candidate_provenance_v1(domain, operation_kind, provenance)
    if operation_kind == "await_existing_artifact_revision_v1":
        from .artifact_wait_checkpoint_v1 import (
            WAIT_SCHEMA, ExistingArtifactWaitOriginalV1, validate_artifact_wait_original_v1,
        )
        if domain != "d10":
            raise DomainProductionErasureHold("artifact waiting bridge has another writer")
        _exact(provenance, {"schema", "wait"})
        if provenance["schema"] != WAIT_SCHEMA:
            raise DomainProductionErasureHold("artifact wait original schema differs")
        validate_artifact_wait_original_v1(decode_typed_production_value_v1(
            provenance["wait"], ExistingArtifactWaitOriginalV1))
        return tuple(sorted(ref for ref in _references(provenance)
            if AtomKey.from_token(ref).type_name == "memory.source"))
    if operation_kind in {"select_existing_artifact_continuation_v1", "revise_existing_artifact_v1"}:
        from .artifact_continuation_v1 import ExistingArtifactRevisionBasisV1, ArtifactRevisionCandidateV1
        from ..domains.d01.production_operations_v1 import plain_v1
        from .d11_artifact_draft_contract_v1 import DraftFileTargetV1
        from .d11_artifact_draft_content_v1 import ArtifactDraftContentAdoptionV1
        from ..model_broker.artifact_draft_v1 import ArtifactDraftTaskSelectorV1
        if domain != "d08":
            raise DomainProductionErasureHold("artifact continuation has another exact writer")
        if operation_kind == "select_existing_artifact_continuation_v1":
            _exact(provenance, {"schema", "selector", "basis", "replacement_target"})
            if provenance["schema"] != "d08.existing-artifact-continuation-original.v1":
                raise DomainProductionErasureHold("artifact continuation original schema differs")
            selector = decode_typed_production_value_v1(provenance["selector"], ArtifactDraftTaskSelectorV1)
            basis = decode_typed_production_value_v1(provenance["basis"], ExistingArtifactRevisionBasisV1)
            target = decode_typed_production_value_v1(provenance["replacement_target"], DraftFileTargetV1)
            if (target.mode != "replace" or target.root_registration_ref != selector.root_registration_ref
                    or (target.root_resource_id, target.root_identity, target.filename) != (
                        basis.predecessor_target.root_resource_id, basis.predecessor_target.root_identity,
                        basis.predecessor_target.filename)
                    or (target.expected_prior_version, target.expected_prior_digest, target.expected_prior_identity,
                        target.expected_prior_effect_marker) != (basis.prior_version, basis.prior_content_digest,
                        basis.prior_file_identity, basis.prior_effect_marker)):
                raise DomainProductionErasureHold("artifact selection changed actual predecessor lineage")
        else:
            _exact(provenance, {"schema", "selection_original_digest", "basis", "content_adoption", "candidate"})
            if provenance["schema"] != "d08.existing-artifact-revision-original.v1":
                raise DomainProductionErasureHold("artifact amendment original schema differs")
            basis = decode_typed_production_value_v1(provenance["basis"], ExistingArtifactRevisionBasisV1)
            adoption = decode_typed_production_value_v1(provenance["content_adoption"], ArtifactDraftContentAdoptionV1)
            candidate = decode_typed_production_value_v1(provenance["candidate"], ArtifactRevisionCandidateV1)
            if (type(provenance["selection_original_digest"]) is not str
                    or re.fullmatch(r"[0-9a-f]{64}", provenance["selection_original_digest"]) is None
                    or candidate.basis_digest != basis.digest
                    or candidate.content_adoption_digest != canonical_digest(plain_v1(adoption))
                    or candidate.old_effect_id != basis.predecessor_effect_id
                    or candidate.expected_versions != basis.current_versions
                    or candidate.new_effect_id == candidate.old_effect_id):
                raise DomainProductionErasureHold("artifact amendment lost actual basis/content/effect commitments")
        return tuple(sorted(ref for ref in _references(provenance)
            if AtomKey.from_token(ref).type_name == "memory.source"))
    if operation_kind in {"prepare_ingress_c04_v1", "adopt_ingress_c04_v1"}:
        from .c04_ingress_preparation_v4 import validate_self_c04_provenance_v4
        return validate_self_c04_provenance_v4(domain, operation_kind, provenance)
    if operation_kind == "select_ingress_recall_seed_v1":
        from .d06_ingress_c03_selection_v1 import C03DirectSelectionOriginalV1
        _exact(provenance, {"selection"})
        if domain != "d06":
            raise DomainProductionErasureHold("C03 selection metadata has another domain writer")
        return decode_typed_production_value_v1(provenance["selection"], C03DirectSelectionOriginalV1)
    if operation_kind == "prepare_ingress_recall_result_read_v1":
        from ..authority_service.d07_current_execution_v1 import D07CognitionResultReadRequestV1
        _exact(provenance, {"prepared_digest", "result_request"})
        if domain != "d07":
            raise DomainProductionErasureHold("Self C3 result read has another writer")
        decode_typed_production_value_v1(provenance["result_request"], D07CognitionResultReadRequestV1)
        return
    if operation_kind == "finish_ingress_recall_model_v1":
        from .d07_execution_v1 import D07IngressRecallExecutionOriginalV1
        _exact(provenance, {"prepared_digest", "terminal", "result_digest"})
        terminal = decode_typed_production_value_v1(provenance["terminal"], D07IngressRecallExecutionOriginalV1)
        if domain != "d11" or terminal.prepared_digest != provenance["prepared_digest"]:
            raise DomainProductionErasureHold("Self C3 terminal has another writer/preparation")
        return
    if operation_kind == "adopt_ingress_recall_model_v1":
        from .d07_ingress_recall_result_v1 import validate_ingress_recall_adoption_v1
        from .foreground_cycle_v1 import decode_foreground_job_v1, foreground_cycle_from_wire_v1
        _exact(provenance, {"prepared_digest", "adoption", "before_cycle", "after_cycle"})
        raw = validate_ingress_recall_adoption_v1(provenance["adoption"], committed=False)
        before = decode_foreground_job_v1(provenance["before_cycle"])
        after = decode_foreground_job_v1(provenance["after_cycle"])
        old, current = (foreground_cycle_from_wire_v1(job.continuation) for job in (before, after))
        expected = tuple(replace(attempt, state="completed", terminal_ref=raw["execution_ref"])
            if attempt.slot == "C3" else attempt for attempt in old.call_plan.attempts)
        if (domain != "d07" or raw["prepared_digest"] != provenance["prepared_digest"]
                or before.job_id != after.job_id or before.phase not in {"waiting", "deferred"}
                or after.phase != "queued" or after.lease_holder is not None or after.lease_expires_utc is not None
                or (before.bot_id, before.persona_id, before.activity_id, before.budget_ref, before.deadline_utc, before.cancel_epoch)
                    != (after.bot_id, after.persona_id, after.activity_id, after.budget_ref, after.deadline_utc, after.cancel_epoch)
                or current.call_plan != replace(old.call_plan, attempts=expected)
                or current != replace(old, call_plan=current.call_plan, wait=None)):
            raise DomainProductionErasureHold("Self C3 adoption changed its actual parent/finite CallPlan")
        return
    if operation_kind == "acquire_ingress_recall_model_v1":
        _exact(provenance, {"prepared_digest", "request_digest", "job_id", "worker_holder", "worker_fence"})
        if domain != "d11" or provenance["worker_fence"] != 1 or type(provenance["worker_fence"]) is not int:
            raise DomainProductionErasureHold("Self C3 acquisition writer/fence differs")
        for name in ("prepared_digest", "request_digest"):
            value = provenance[name]
            if type(value) is not str or re.fullmatch(r"[0-9a-f]{64}", value) is None:
                raise DomainProductionErasureHold("Self C3 acquisition digest differs")
        for name in ("job_id", "worker_holder"):
            decode_typed_production_value_v1(provenance[name], str)
        return
    if operation_kind == "prepare_ingress_recall_model_v1":
        from .foreground_cycle_v1 import foreground_cycle_from_wire_v1, decode_foreground_job_v1
        if domain != "d07":
            raise DomainProductionErasureHold("Self C3 preparation changed its actual writer")
        _exact(provenance, {"prepared_job_id", "prepared_digest", "need_ref", "need_digest", "before_cycle", "after_cycle"})
        before = decode_foreground_job_v1(provenance["before_cycle"])
        after = decode_foreground_job_v1(provenance["after_cycle"])
        old = foreground_cycle_from_wire_v1(before.continuation)
        current = foreground_cycle_from_wire_v1(after.continuation)
        for name in ("prepared_digest", "need_digest"):
            value = provenance[name]
            if type(value) is not str or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
                raise DomainProductionErasureHold("Self C3 commitment is not exact")
        if (any(type(provenance[name]) is not str or not provenance[name] for name in ("prepared_job_id", "need_ref"))
                or (before.job_id, before.operation_id, before.activity_id, before.budget_ref, before.deadline_utc, before.cancel_epoch)
                    != (after.job_id, after.operation_id, after.activity_id, after.budget_ref, after.deadline_utc, after.cancel_epoch)
                or before.phase != "running" or after.phase != "waiting" or after.lease_holder is not None
                or after.lease_expires_utc is not None or current.stage != "recall"
                or len(current.call_plan.attempts) != len(old.call_plan.attempts) + 1
                or current.call_plan.attempts[:-1] != old.call_plan.attempts
                or current.call_plan.attempts[-1].slot != "C3"
                or current.call_plan.attempts[-1].state != "reserved"
                or current.call_plan.protected_reply_lease_ref != old.call_plan.protected_reply_lease_ref
                or current.call_plan.parent_budget_lease_ref != old.call_plan.parent_budget_lease_ref):
            raise DomainProductionErasureHold("Self C3 changed its original finite parent/CallPlan")
        return
    if operation_kind == "prepare_ingress_recall_need_v1":
        from ..domains.d07 import IngressRecallNeedV1
        from .domain_production_contracts_v1 import ProductionQueryCoverageV1
        if domain != "d07":
            raise DomainProductionErasureHold("ingress recall need has another actual writer")
        _exact(provenance, ("need", "ledger_coverage"))
        need = decode_typed_production_value_v1(provenance["need"], IngressRecallNeedV1)
        coverage = decode_typed_production_value_v1(provenance["ledger_coverage"], tuple[ProductionQueryCoverageV1, ...])
        if len(coverage) > 6 or any(len(page.row_versions) > 64 for page in coverage):
            raise DomainProductionErasureHold("ingress recall need exceeds its finite ledger page bounds")
        return (need.source_ref,)
    if operation_kind == "adopt_owner_artifact_project_context_v1":
        if domain != "d03":
            raise DomainProductionErasureHold("Owner project role adoption has another domain writer")
        _exact(provenance, ("artifact_project_ref", "artifact_recipe_ref", "artifact_context_source_refs", "self_mapping_ref",
            "self_certification_ref", "self_certification_digest", "owner_actor_ref"))
        for name in ("artifact_project_ref", "artifact_recipe_ref", "self_mapping_ref", "self_certification_ref", "self_certification_digest", "owner_actor_ref"):
            decode_typed_production_value_v1(provenance[name], str)
        return decode_typed_production_value_v1(provenance["artifact_context_source_refs"], tuple[str, ...])
    if operation_kind == "owner_stop_reply_v1":
        from .owner_stop_reply_v1 import OwnerReplyCycleIdentityV1
        from .foreground_cycle_v1 import decode_foreground_job_v1
        from .jobs import PersistentJob, _job_from_dict
        from .d11_types import job_graph_write
        from ..domains.d01.production_operations_v1 import plain_v1
        if domain != "d11":
            raise DomainProductionErasureHold("Stop projection has another metadata writer")
        _exact(provenance, ("stop_original_ref", "stop_original_digest", "cycle_identity", "before_jobs", "after_jobs", "child_originals"))
        identity = decode_typed_production_value_v1(provenance["cycle_identity"], OwnerReplyCycleIdentityV1)
        for name in ("stop_original_ref", "stop_original_digest"):
            decode_typed_production_value_v1(provenance[name], str)
        def decode_job(raw):
            _exact(raw, PersistentJob.__dataclass_fields__)
            job = _job_from_dict(raw)
            if (plain_v1(job) != raw or (job.bot_id, job.persona_id) != identity.namespace.as_tuple):
                raise DomainProductionErasureHold("Stop projection child metadata differs from exact job schema")
            return job
        before = tuple(decode_job(raw) for raw in provenance["before_jobs"])
        after = tuple(decode_job(raw) for raw in provenance["after_jobs"])
        if (not before or len(before) != len(after) or job_graph_write(before[0]).key.token != identity.cycle_job_ref
                or len({job.job_id for job in before}) != len(before)):
            raise DomainProductionErasureHold("Stop projection actual metadata inventory differs")
        decode_foreground_job_v1(provenance["before_jobs"][0], namespace=identity.namespace)
        decode_foreground_job_v1(provenance["after_jobs"][0], namespace=identity.namespace)
        for prior, updated in zip(before, after, strict=True):
            if (prior.job_id, prior.operation_id, prior.activity_id, prior.budget_ref, prior.deadline_utc) != (
                    updated.job_id, updated.operation_id, updated.activity_id, updated.budget_ref, updated.deadline_utc):
                raise DomainProductionErasureHold("Stop projection changed original work identity")
        decode_typed_production_value_v1(provenance["child_originals"], tuple[tuple[str, str, str], ...])
        return ()
    if operation_kind == "derive_ingress_artifact_task_scope_v1":
        from .ingress_artifact_task_scope_v1 import IngressArtifactTaskScopeOriginalV1,ArtifactTaskObjectiveV1,_decode as decode_task_scope
        from .d11_artifact_draft_contract_v1 import DraftRootCapabilityV1
        if domain!="d10":raise DomainProductionErasureHold("task scope has another actual writer")
        _exact(provenance,("draft_root_capability","artifact_task_scope","artifact_task_objective","cause_frozen_at_utc","clock_sample_digest"))
        root=decode_typed_production_value_v1(provenance["draft_root_capability"],DraftRootCapabilityV1)
        task=decode_task_scope(provenance["artifact_task_scope"],IngressArtifactTaskScopeOriginalV1)
        objective=decode_typed_production_value_v1(provenance["artifact_task_objective"],ArtifactTaskObjectiveV1|None)
        if (root!=task.root or task.cause_frozen_at_utc!=provenance["cause_frozen_at_utc"]
                or type(provenance["clock_sample_digest"]) is not str or len(provenance["clock_sample_digest"])!=64
                or (objective is None)!=(task.objective_ref is None)):
            raise DomainProductionErasureHold("task scope lost its exact original source/objective/clock binding")
        refs={task.source_ref}
        if objective is not None:refs.add(objective.source_ref)
        from .ingress_artifact_task_scope_v1 import IngressArtifactTaskScopeOriginalV3
        if type(task) is IngressArtifactTaskScopeOriginalV3:
            from ..domains.d01.production_operations_v1 import plain_v1
            refs.update(ref for ref in _references(plain_v1(task.continuation_authorization))
                if AtomKey.from_token(ref).type_name=="memory.source")
        return tuple(sorted(refs))
    if operation_kind == "register_artifact_draft_root":
        from ..authority_service.current_foreground_activity_v1 import DraftRootRegistrationRequestV1
        from .d11_artifact_draft_contract_v1 import DraftRootCapabilityV1
        if domain != "d10":
            raise DomainProductionErasureHold("draft root setup has another Owner writer domain")
        _exact(provenance, ("draft_root_request", "draft_root_capability", "cause_frozen_at_utc", "clock_sample_digest"))
        request = decode_typed_production_value_v1(provenance["draft_root_request"], DraftRootRegistrationRequestV1)
        capability = decode_typed_production_value_v1(provenance["draft_root_capability"], DraftRootCapabilityV1)
        if (capability.source_ref != request.source_ref or capability.resource_id != request.resource_id
                or type(provenance["cause_frozen_at_utc"]) is not float or not math.isfinite(provenance["cause_frozen_at_utc"])):
            raise DomainProductionErasureHold("draft root setup lost its actual Source/resource/clock binding")
        decode_typed_production_value_v1(provenance["clock_sample_digest"], str)
        return (request.source_ref,)
    if operation_kind in {"prepare_artifact_draft_model_v2", "acquire_artifact_draft_model_v2"}:
        from .d11_artifact_draft_model_v1 import ArtifactDraftModelPreparedV2, artifact_draft_model_from_wire_v2
        from .foreground_cycle_v1 import decode_foreground_job_v1, foreground_cycle_from_wire_v1
        from .foreground_call_plan_v1 import ForegroundCallPlanV2
        from ..model_broker.artifact_draft_v1 import (ArtifactDraftPhaseSelectorV2,
            artifact_draft_from_wire_v2, artifact_draft_model_ids_v2)
        if domain != "d11":
            raise DomainProductionErasureHold("C4 phase model provenance has another writer")
        if operation_kind == "prepare_artifact_draft_model_v2":
            _exact(provenance, {"prepared", "frozen_ref", "frozen_digest", "before_cycle", "after_cycle"})
            prepared = artifact_draft_model_from_wire_v2(provenance["prepared"], ArtifactDraftModelPreparedV2)
            before = decode_foreground_job_v1(provenance["before_cycle"], namespace=prepared.namespace)
            after = decode_foreground_job_v1(provenance["after_cycle"], namespace=prepared.namespace)
            plan = foreground_cycle_from_wire_v1(after.continuation).call_plan
            if ((before.job_id, before.activity_id, before.deadline_utc, before.budget_ref) != (
                    after.job_id, after.activity_id, after.deadline_utc, after.budget_ref)
                    or before.phase != "running" or after.phase != "waiting"
                    or (provenance["frozen_ref"], provenance["frozen_digest"]) != (prepared.frozen_ref, prepared.frozen_digest)
                    or type(plan) is not ForegroundCallPlanV2 or plan.phase_group.selector != prepared.selector):
                raise DomainProductionErasureHold("C4 phase preparation changed actual cycle/group/frozen seal")
        else:
            from .jobs import _job_from_dict
            from ..domains.d01.production_operations_v1 import plain_v1
            _exact(provenance, {"prepared_digest", "request_digest", "job", "actual_count_proof"})
            from .d11_artifact_draft_model_v1 import artifact_draft_phase_count_proof_from_wire_v2
            artifact_draft_phase_count_proof_from_wire_v2(provenance["actual_count_proof"])
            job = _job_from_dict(provenance["job"])
            _exact(job.continuation, {"schema", "selector", "prepared_digest"})
            selector = artifact_draft_from_wire_v2(job.continuation["selector"], ArtifactDraftPhaseSelectorV2)
            if (plain_v1(job) != provenance["job"] or job.work_kind != "artifact_draft_v1"
                    or job.continuation["schema"] != "d11.artifact-draft-phase-model-job.v2"
                    or job.continuation["prepared_digest"] != provenance["prepared_digest"]
                    or job.job_id != artifact_draft_model_ids_v2(selector)["job"]
                    or job.phase != "running" or job.fence != 1 or job.cancel_epoch):
                raise DomainProductionErasureHold("C4 phase acquisition changed its actual once worker")
            for name in ("prepared_digest", "request_digest"):
                if type(provenance[name]) is not str or re.fullmatch(r"[0-9a-f]{64}", provenance[name]) is None:
                    raise DomainProductionErasureHold("C4 phase acquisition lost exact original commitment")
        return tuple(sorted(ref for ref in _references(provenance) if AtomKey.from_token(ref).type_name == "memory.source"))
    if operation_kind == "adopt_artifact_draft_content_v2":
        if domain != "d06":
            raise DomainProductionErasureHold("C4 phase content provenance has another Source writer")
        _exact(provenance, {"schema", "prepared_digest", "result_original_ref", "paid_original_ref", "parent_source_refs", "content_digest"})
        if provenance["schema"] != "d06.artifact-draft-phase-authored-source.v2":
            raise DomainProductionErasureHold("C4 phase content provenance has another schema")
        for name in ("prepared_digest", "content_digest"):
            if type(provenance[name]) is not str or re.fullmatch(r"[0-9a-f]{64}", provenance[name]) is None:
                raise DomainProductionErasureHold("C4 phase content lost original prepared/content commitment")
        for name, prefix in (("result_original_ref", "artifact-draft-v2-result:"), ("paid_original_ref", "artifact-draft-v2-paid:")):
            if type(provenance[name]) is not str or re.fullmatch(re.escape(prefix) + r"[0-9a-f]{40}", provenance[name]) is None:
                raise DomainProductionErasureHold("C4 phase content changed exact paid/result original family")
        roots = decode_typed_production_value_v1(provenance["parent_source_refs"], tuple[str, ...])
        if not roots or len(set(roots)) != len(roots) or any(AtomKey.from_token(ref).type_name != "memory.source" for ref in roots):
            raise DomainProductionErasureHold("C4 phase content lost complete Source parent closure")
        return roots
    if operation_kind == "propose_artifact_draft_phase_action_v2":
        from .d11_artifact_draft_content_v1 import ArtifactDraftContentAdoptionV2, artifact_draft_content_from_wire_v2
        if domain != "d08":
            raise DomainProductionErasureHold("phase Action provenance has another real writer")
        _exact(provenance, {"artifact_phase_content_adoption", "artifact_goal_ref", "artifact_plan_ref",
            "artifact_project_ref", "artifact_recipe_ref", "selected_preparation_original_ref",
            "selected_preparation_original_digest", "final_admission"})
        adoption = artifact_draft_content_from_wire_v2(provenance["artifact_phase_content_adoption"], ArtifactDraftContentAdoptionV2)
        if provenance["final_admission"] is not False:
            raise DomainProductionErasureHold("phase Action proposal cannot assert final execution admission")
        digest = provenance["selected_preparation_original_digest"]
        if (type(digest) is not str or re.fullmatch(r"[0-9a-f]{64}", digest) is None
                or provenance["selected_preparation_original_ref"] != "d08-current:" + digest[:48]):
            raise DomainProductionErasureHold("phase Action lost its actual adopted selection identity")
        for field in ("artifact_goal_ref", "artifact_plan_ref", "artifact_project_ref", "artifact_recipe_ref"):
            ref = provenance[field]
            if type(ref) is not str or NamespaceId.from_key(AtomKey.from_token(ref)) != adoption.selector.task.namespace:
                raise DomainProductionErasureHold("phase Action control crossed task namespace")
        return tuple(sorted(ref for ref in _references(provenance) if AtomKey.from_token(ref).type_name == "memory.source"))
    if operation_kind == "verify_artifact_draft_phase_v2":
        from .d11_artifact_draft_content_v1 import ArtifactDraftPhaseVerifiedOriginalV2, artifact_draft_phase_verification_from_wire_v2
        if domain != "d11":
            raise DomainProductionErasureHold("C4 phase verification provenance has another actual writer")
        _exact(provenance, {"phase_verified"})
        value = artifact_draft_phase_verification_from_wire_v2(provenance["phase_verified"], ArtifactDraftPhaseVerifiedOriginalV2)
        if not value.selector.generation:
            raise DomainProductionErasureHold("C4 method check has no installed semantic original decoder")
        return tuple(sorted(ref for ref in _references(provenance) if AtomKey.from_token(ref).type_name == "memory.source"))
    from .domain_production_registry_v1 import _ARTIFACT_OPERATIONS
    if operation_kind in _ARTIFACT_OPERATIONS:
        from .d11_artifact_draft_model_v1 import ArtifactDraftModelPreparedV1
        from .d11_artifact_draft_content_v1 import ArtifactDraftContentAdoptionV1
        from ..runtime_contracts import VersionedRef
        maps = {
            "prepare_artifact_draft_model": {"prepared": ArtifactDraftModelPreparedV1,
                "frozen_ref": str, "frozen_digest": str, "before_cycle": None, "after_cycle": None},
            "acquire_artifact_draft_model": {"prepared_digest": str, "request_digest": str, "job": None},
            "adopt_artifact_draft_content": {"schema": str, "prepared_digest": str,
                "result_original_ref": str, "paid_original_ref": str, "parent_source_refs": tuple[str, ...], "content_digest": str},
            "compose_artifact_goal_plan": {"artifact_content_adoption": ArtifactDraftContentAdoptionV1,
                "actual_fact_versions": tuple[VersionedRef, ...], "artifact_project_ref": str, "artifact_recipe_ref": str},
            "create_artifact_project": {"artifact_goal_ref": str, "artifact_plan_ref": str, "artifact_project_ref": str,
                "artifact_recipe_ref": str, "draft_task_source_ref": str, "draft_content_ref": str,
                "artifact_content_adoption": ArtifactDraftContentAdoptionV1},
            "prepare_artifact_draft_project_context": {"artifact_project_ref": str, "artifact_recipe_ref": str,
                "artifact_context_source_refs": tuple[str, ...], "self_mapping_ref": str},
            "propose_artifact_draft_action": {"artifact_content_adoption": ArtifactDraftContentAdoptionV1,
                "artifact_goal_ref": str, "artifact_plan_ref": str, "artifact_project_ref": str,
                "artifact_recipe_ref": str, "final_admission": bool},
        }
        expected = maps[operation_kind]
        if domain != _ARTIFACT_OPERATIONS[operation_kind][0] or type(provenance) is not dict or set(provenance) != set(expected):
            raise DomainProductionErasureHold("artifact stage provenance differs from its closed operation variant")
        for name, value_type in expected.items():
            if value_type is not None:
                decode_typed_production_value_v1(provenance[name], value_type)
        if operation_kind == "prepare_artifact_draft_model":
            from .foreground_cycle_v1 import decode_foreground_job_v1
            before = decode_foreground_job_v1(provenance["before_cycle"])
            after = decode_foreground_job_v1(provenance["after_cycle"], namespace=NamespaceId(before.bot_id, before.persona_id))
            if (before.job_id, before.activity_id, before.deadline_utc, before.budget_ref) != (
                    after.job_id, after.activity_id, after.deadline_utc, after.budget_ref) or before.phase != "running" or after.phase != "waiting":
                raise DomainProductionErasureHold("C4 preparation changed its original cycle identity/deadline or wait transition")
        elif operation_kind == "acquire_artifact_draft_model":
            from .jobs import _job_from_dict
            from ..model_broker.artifact_draft_v1 import ArtifactDraftTaskSelectorV1, artifact_draft_from_wire_v1, artifact_draft_model_ids_v1
            job = _job_from_dict(provenance["job"])
            selector = artifact_draft_from_wire_v1(job.continuation["selector"], ArtifactDraftTaskSelectorV1)
            if (job.work_kind != "artifact_draft_v1" or job.job_id != artifact_draft_model_ids_v1(selector)["job"]
                    or job.phase != "running" or job.fence != 1 or job.cancel_epoch):
                raise DomainProductionErasureHold("C4 acquired provenance lost its exact once worker job")
        elif operation_kind == "adopt_artifact_draft_content" and provenance["schema"] != "d06.artifact-draft-authored-source.v1":
            raise DomainProductionErasureHold("C4 adopted source provenance has another schema")
        elif operation_kind == "propose_artifact_draft_action" and provenance["final_admission"] is not False:
            raise DomainProductionErasureHold("artifact proposal original cannot assert final admission")
        return tuple(sorted(ref for ref in _references(provenance) if AtomKey.from_token(ref).type_name == "memory.source"))
    from .domain_production_registry_v1 import _FOREGROUND_OPERATIONS
    if operation_kind == "wake_artifact_draft_cycle_v1":
        if domain != "d11":
            raise DomainProductionErasureHold("artifact wake has another writer")
        _exact(provenance, ("before_job", "after_job", "queued_dedupe_key", "prepared_digest",
            "paid_ref", "paid_digest", "result_ref", "result_digest"))
        from .foreground_cycle_v1 import decode_foreground_job_v1, foreground_job_source_refs_v1
        before = decode_foreground_job_v1(provenance["before_job"])
        after = decode_foreground_job_v1(provenance["after_job"], namespace=NamespaceId(before.bot_id, before.persona_id))
        if (before.phase != "waiting" or after != replace(before, phase="queued", wake_condition=None)):
            raise DomainProductionErasureHold("artifact wake changed more than its exact waiting-to-queued job transition")
        for name in ("queued_dedupe_key", "prepared_digest", "paid_digest", "result_digest"):
            if type(provenance[name]) is not str or len(provenance[name]) != 64:
                raise DomainProductionErasureHold("artifact wake terminal commitment differs")
        for name in ("paid_ref", "result_ref"):
            decode_typed_production_value_v1(provenance[name], str)
        return foreground_job_source_refs_v1(before)
    if operation_kind in _FOREGROUND_OPERATIONS or operation_kind == "checkpoint_source_note_foreground_cycle_v1":
        if domain != "d11":
            raise DomainProductionErasureHold("foreground cycle provenance has another writer domain")
        old_fields = {"before_job", "after_job"}
        new_fields = old_fields | {"reply_allocation"}
        fields_v2 = new_fields | {"foreground_responsibility"}
        allowed = (fields_v2,) if operation_kind == "create_foreground_cycle_v2" else (
            (old_fields, new_fields) if operation_kind == "create_foreground_cycle" else (old_fields,))
        if type(provenance) is not dict or set(provenance) not in allowed:
            raise DomainProductionErasureHold("foreground provenance differs from its exact historical/current allocation variant")
        from .foreground_cycle_v1 import decode_foreground_job_v1, foreground_job_source_refs_v1, foreground_cycle_from_wire_v1
        after = decode_foreground_job_v1(provenance["after_job"])
        ns = NamespaceId(after.bot_id, after.persona_id)
        before = None if provenance["before_job"] is None else decode_foreground_job_v1(provenance["before_job"], namespace=ns)
        if "foreground_responsibility" in provenance:
            from .jobs import _utc
            from .foreground_cycle_v1 import ForegroundResponsibilityV1, ForegroundCycleContinuationV2, foreground_responsibility_ref_v1
            responsibility = decode_typed_production_value_v1(provenance["foreground_responsibility"], ForegroundResponsibilityV1)
            current = foreground_cycle_from_wire_v1(after.continuation)
            if (type(current) is not ForegroundCycleContinuationV2 or responsibility.namespace != ns
                    or current.responsibility_ref != foreground_responsibility_ref_v1(ns, current.c02_operation_id)
                    or current.responsibility_digest != responsibility.digest
                    or _utc(after.deadline_utc, "deadline_utc").timestamp() != responsibility.deadline_utc):
                raise DomainProductionErasureHold("new foreground provenance lost its exact responsibility/job deadline binding")
        if "reply_allocation" in provenance:
            from .foreground_call_plan_v1 import ForegroundReplyAllocationV1
            allocation = decode_typed_production_value_v1(provenance["reply_allocation"], ForegroundReplyAllocationV1)
            current = foreground_cycle_from_wire_v1(after.continuation)
            from .jobs import _utc
            if (allocation.namespace != ns or allocation.c02_operation_id != current.c02_operation_id
                    or allocation.parent_lease_ref != after.budget_ref
                    or allocation.child_lease_id != current.call_plan.protected_reply_lease_ref
                    or allocation.valid_until_utc != _utc(after.deadline_utc, "deadline_utc").timestamp()):
                raise DomainProductionErasureHold("foreground protected allocation original differs from its actual created cycle")
        if (operation_kind in {"create_foreground_cycle", "create_foreground_cycle_v2"}) != (before is None):
            raise DomainProductionErasureHold("foreground creation/transition provenance lost its exact observed precondition")
        if before is not None:
            old = foreground_cycle_from_wire_v1(before.continuation)
            current = foreground_cycle_from_wire_v1(after.continuation)
            if (before.job_id, before.operation_id, before.activity_id, before.budget_ref, before.deadline_utc) != (
                    after.job_id, after.operation_id, after.activity_id, after.budget_ref, after.deadline_utc):
                raise DomainProductionErasureHold("foreground retained transition changed its original job/budget/deadline")
            if (old.ingress_operation_id, old.c02_operation_id, old.source_ref, old.source_revision, old.source_barrier_epoch) != (
                    current.ingress_operation_id, current.c02_operation_id, current.source_ref, current.source_revision, current.source_barrier_epoch):
                raise DomainProductionErasureHold("foreground transition changed its actual ingress/C02/Source origin")
            if (old.call_plan.parent_budget_lease_ref, old.call_plan.protected_reply_lease_ref) != (
                    current.call_plan.parent_budget_lease_ref, current.call_plan.protected_reply_lease_ref):
                raise DomainProductionErasureHold("foreground transition changed its actual protected reply family")
            if (after.cancel_epoch != before.cancel_epoch or after.usage != before.usage
                    or not set(old.completed_operation_refs) <= set(current.completed_operation_refs)):
                raise DomainProductionErasureHold("foreground retained transition changed cancellation/usage or forgot an actual original")
            if operation_kind == "acquire_foreground_cycle":
                if before.phase != "queued" or after.phase != "running" or after.fence != before.fence + 1 or before.continuation != after.continuation:
                    raise DomainProductionErasureHold("foreground acquire provenance differs from its real once-acquire producer")
            elif operation_kind == "wake_foreground_cycle":
                if before.phase not in {"waiting", "deferred"} or after.phase != "queued" or before.continuation != after.continuation or before.fence != after.fence:
                    raise DomainProductionErasureHold("foreground wake provenance differs from its original registered waiting job")
            elif (before.phase != "running" or after.fence != before.fence
                    or after.phase not in {"running", "waiting", "queued", "completed"}
                    or not old.stage_cursor <= current.stage_cursor <= old.stage_cursor + 1):
                raise DomainProductionErasureHold("foreground checkpoint provenance differs from its actual fenced producer")
        elif after.phase != "queued" or after.fence or after.cancel_epoch:
            raise DomainProductionErasureHold("foreground creation retained an invented live worker/control state")
        return tuple(sorted(set(foreground_job_source_refs_v1(after)) |
            (set() if before is None else set(foreground_job_source_refs_v1(before)))))
    if operation_kind in {'create_artifact_task_project_v1','initialize_artifact_task_project_checkpoint_v1','activate_artifact_task_project_checkpoint_v1'}:
        if domain!='d10':raise DomainProductionErasureHold('task Project checkpoint has another actual writer')
        if provenance=={}:return ()
        from ..model_broker.artifact_draft_v1 import ArtifactDraftTaskSelectorV1
        from ..domains.d10.project_checkpoint_v1 import ProjectCheckpointV1
        from ..domains.d10 import LifeProject,ActivityRecipe
        fields=({'task_project_basis'} if operation_kind=='create_artifact_task_project_v1' else
            {'checkpoint','task_project_basis'} if operation_kind=='initialize_artifact_task_project_checkpoint_v1' else
            {'checkpoint','task_project_basis','selected_candidates_original_ref','selected_candidates_original_digest',
                'selected_binding_digest','decision_ref','decision_digest'})
        _exact(provenance,fields)
        basis=provenance['task_project_basis']
        string_fields=('objective_ref','objective_digest','task_scope_ref','task_scope_digest','task_scope_producer_ref','task_scope_producer_digest',
            'c1_intent_ref','c1_intent_digest','goal_digest','plan_digest','plan_producer_ref','plan_producer_digest','source_digest',
            'root_digest','project_ref')
        _exact(basis,{'task','goal_head','plan_head','source_head','project_value','recipe_ref','recipe_value',*string_fields})
        task=decode_typed_production_value_v1(basis['task'],ArtifactDraftTaskSelectorV1)
        for name in string_fields:decode_typed_production_value_v1(basis[name],str)
        for name,kind in (('goal_head','d08.goal.v1'),('plan_head','d08.personal_plan.v1'),('source_head','memory.source')):
            head=decode_typed_production_value_v1(basis[name],GraphVersion)
            if head.key.type_name!=kind or NamespaceId.from_key(head.key)!=task.namespace:
                raise DomainProductionErasureHold('task Project basis changed actual typed namespace heads')
        _exact(basis['project_value'],{'project_id','topic','reality','next_step'})
        LifeProject(namespace=task.namespace,**basis['project_value'])
        decode_typed_production_value_v1(basis['recipe_value'],ActivityRecipe)
        if operation_kind!='create_artifact_task_project_v1':decode_typed_production_value_v1(provenance['checkpoint'],ProjectCheckpointV1)
        for name in fields-{'checkpoint','task_project_basis'}:decode_typed_production_value_v1(provenance[name],str)
        return (basis['source_head']['key'],)
    if operation_kind=='activate_artifact_task_project_checkpoint_v2':
        if domain!='d10':raise DomainProductionErasureHold('amended activation has another actual writer')
        if provenance=={}:return ()
        from ..domains.d10.project_checkpoint_v1 import ProjectCheckpointV1
        fields={'checkpoint','task_plan_revision_operation_id','task_plan_revision_original_digest',
            'selected_candidates_original_ref','selected_candidates_original_digest','selected_binding_digest','decision_ref','decision_digest'}
        _exact(provenance,fields)
        decode_typed_production_value_v1(provenance['checkpoint'],ProjectCheckpointV1)
        for name in fields-{'checkpoint'}:decode_typed_production_value_v1(provenance[name],str)
        return tuple(sorted(ref for ref in _references(provenance) if AtomKey.from_token(ref).type_name=='memory.source'))
    from .domain_production_registry_v1 import _PERSONAL_OPERATIONS
    if operation_kind in _PERSONAL_OPERATIONS:
        if operation_kind == "create_artifact_task_plan_v1" and domain != "d08":
            raise DomainProductionErasureHold("initial artifact task Plan belongs to its exact d08 writer")
        if domain != _PERSONAL_OPERATIONS[operation_kind][0]:
            raise DomainProductionErasureHold("personal stage belongs to a different writer")
        if provenance == {}:
            return ()
        from ..domains.d08.personal_plan_v1 import DecisionRecordV2, QualifiedPersonalCandidateV1
        from ..domains.d10.project_checkpoint_v1 import ProjectCheckpointV1, ProjectWorkVersionV1
        from .d10_project_checkpoint_v1 import VerifiedProjectEffectV1
        from ..runtime_contracts import VersionedRef
        from .artifact_task_observer_v1 import ArtifactTaskObservationV1,ArtifactTaskObservationV2
        from .d11_artifact_draft_content_v1 import ArtifactDraftMethodSettlementHistoryV2
        from .domain_production_contracts_v1 import ProductionOriginalRefV1
        shapes = {
            "create_personal_plan": ({"actual_fact_versions"},),
            "create_artifact_task_plan_v1": ({"actual_fact_versions"},),
            "revise_artifact_task_plan_v2": ({"actual_fact_versions","amendment_original_ref","amendment_original_digest",
                "previous_milestone_ref","previous_milestone_digest","previous_settlement_operation_id","previous_settlement_original_digest",
                "task_scope_ref","task_scope_digest","checkpoint"},),
            "revise_personal_plan": ({"actual_fact_versions", "carried_effects", "pending_effects", "retained_commitment_versions"},),
            "select_personal_step": ({"decision", "candidate_evidence", "value_evaluation"},
                {"decision", "candidate_evidence", "value_evaluation", "method_strategy"},
                {"decision", "candidate_evidence", "value_evaluation", "candidate_discriminator_contracts"},
                {"decision", "candidate_evidence", "value_evaluation", "method_strategy", "candidate_discriminator_contracts"}),
            "settle_personal_goal": ({"actual_effect"}, {"duplicate"}, {"actual_effect","task_observation"},
                {"actual_effect","task_observation","artifact_method_completion"}),
            "initialize_project_checkpoint": ({"checkpoint"},),
            "refresh_project_checkpoint": ({"checkpoint"}, {"duplicate"}),
            "settle_project_checkpoint": ({"checkpoint", "work_version", "actual_effect"}, {"duplicate", "actual_effect"},
                {"checkpoint", "work_version", "actual_effect", "artifact_task_milestone"}),
        }
        if type(provenance) is not dict or set(provenance) not in shapes[operation_kind]:
            raise DomainProductionErasureHold("personal stage provenance differs from its exact operation")
        from ..domains.d01.production_operations_v1 import MethodStrategyProjectionV1
        from .personal_candidate_eligibility_v1 import PersonalCandidateDiscriminatorContractV1
        types = {
            "method_strategy": MethodStrategyProjectionV1,
            "candidate_discriminator_contracts": tuple[tuple[str,PersonalCandidateDiscriminatorContractV1],...],
            "actual_fact_versions": tuple[VersionedRef, ...],
            "carried_effects": tuple[str, ...], "pending_effects": tuple[str, ...],
            "retained_commitment_versions": tuple[tuple[str, int], ...],
            "decision": DecisionRecordV2,
            "candidate_evidence": tuple[QualifiedPersonalCandidateV1, ...],
            "value_evaluation": str, "actual_effect": VerifiedProjectEffectV1,
            "duplicate": bool, "checkpoint": ProjectCheckpointV1,
            "work_version": ProjectWorkVersionV1, "task_observation": ArtifactTaskObservationV1,
            "artifact_task_milestone": ProductionOriginalRefV1,
            "artifact_method_completion": ArtifactDraftMethodSettlementHistoryV2,
            "amendment_original_ref":str,"amendment_original_digest":str,"previous_milestone_ref":str,"previous_milestone_digest":str,
            "previous_settlement_operation_id":str,"previous_settlement_original_digest":str,"task_scope_ref":str,"task_scope_digest":str,
        }
        for name, value in provenance.items():
            expected_type=types[name]
            if name=='task_observation' and type(value) is dict and value.get('schema')=='d08.artifact-task-observation.v2':
                expected_type=ArtifactTaskObservationV2
            decode_typed_production_value_v1(value, expected_type)
        if "candidate_discriminator_contracts" in provenance:
            contracts=decode_typed_production_value_v1(provenance["candidate_discriminator_contracts"],
                tuple[tuple[str,PersonalCandidateDiscriminatorContractV1],...])
            candidates=decode_typed_production_value_v1(provenance["candidate_evidence"],tuple[QualifiedPersonalCandidateV1,...])
            if (len(contracts)!=len(candidates) or len({ref for ref,_ in contracts})!=len(contracts)
                    or {ref for ref,_ in contracts}!={row.candidate_ref for row in candidates}
                    or any(row.numeric_discriminator_unresolved for row in candidates)):
                raise DomainProductionErasureHold("legacy selection numeric flags differ from its exact closed recipe contracts")
        if "value_evaluation" in provenance and not re.fullmatch(r"[0-9a-f]{64}", provenance["value_evaluation"]):
            raise DomainProductionErasureHold("personal value evaluation original digest differs")
        return tuple(sorted(set(_references(provenance))))
    if (domain, operation_kind) == ('d06', 'encode_internal_life'):
        _exact(provenance, ('schema', 'cause'))
        from .d06_internal_life_encoding_v1 import CAUSE_SCHEMA, decode_internal_life_encoding_cause_v1
        if provenance['schema'] != CAUSE_SCHEMA:
            raise DomainProductionErasureHold('Life encoding causal original schema differs')
        cause = decode_internal_life_encoding_cause_v1(provenance['cause'])
        return tuple(sorted(row.ref for row in cause.occurrence.historical_reads
            if AtomKey.from_token(row.ref).type_name == 'memory.source'))
    if ((domain, operation_kind) == ('d06', 'encode_structured_experience')
            and type(provenance) is dict and provenance.get('schema') == 'd06.internal-life-episode-original.v2'):
        _exact(provenance, ('schema', 'proof', 'encoding_status'))
        from .d06_internal_life_episode_v2 import PROVENANCE, decode_internal_life_value_v2
        proof = decode_internal_life_value_v2(PROVENANCE, provenance['proof'])
        if provenance['encoding_status'] != 'encoding_pending':
            raise DomainProductionErasureHold('Life episode does not certify a subjective trace')
        return tuple(sorted(row.ref for row in proof.historical_reads if AtomKey.from_token(row.ref).type_name == 'memory.source'))
    """Closed top-level variants; nested content is checked by typed codecs."""
    if type(provenance) is not dict:
        raise DomainProductionErasureHold("stage provenance must be an exact registered object")
    if (domain, operation_kind) == ('d08', 'prepare_contact_dispatch_v3'):
        from .contact_final_stage_v3 import validate_contact_final_provenance_v3
        try:
            return validate_contact_final_provenance_v3(provenance)
        except (ValueError, TypeError, KeyError) as error:
            raise DomainProductionErasureHold('Contact3 closed final provenance differs') from error
    if (domain, operation_kind) == ('d08', 'prepare_contact_dispatch'):
        from .contact_final_stage_v1 import validate_contact_final_provenance_v1
        from .contact_final_stage_v2 import validate_contact_final_provenance_v2
        try:
            validate = validate_contact_final_provenance_v2 if provenance.get("schema") == "d08.contact-final-original.v2" else validate_contact_final_provenance_v1
            return validate(provenance)
        except (ValueError, TypeError, KeyError) as error:
            raise DomainProductionErasureHold('Contact final provenance differs from its closed actual join') from error
    if not provenance:
        return ()
    if (domain, operation_kind) == ('d11','acquire_internal_life_content_v2'):
        _exact(provenance,('schema','binding','binding_digest','request_digest','job_ref'))
        from .internal_life_worker_binding_v2 import decode_internal_life_worker_binding_v2
        binding=decode_internal_life_worker_binding_v2(provenance['binding'])
        job=AtomKey.from_token(provenance['job_ref'])
        if (provenance['schema']!='d06.internal-life-worker-acquisition.v2'
                or provenance['binding_digest']!=binding.digest or job.type_name!='runtime.job'
                or job.name!=binding.job_id or NamespaceId.from_key(job)!=binding.namespace
                or type(provenance['request_digest']) is not str
                or not re.fullmatch(r'[0-9a-f]{64}',provenance['request_digest'])):
            raise DomainProductionErasureHold('Life worker dual-role original scope differs')
        return (binding.episode_ref,job.token,binding.owner_guard.grant_ref)
    if (domain, operation_kind) == ('d11', 'acquire_internal_life_content'):
        _exact(provenance, ('schema','prepared_digest','episode_ref','request_digest','job_ref'))
        from .d06_internal_life_episode_v2 import EPISODE
        episode = AtomKey.from_token(provenance['episode_ref'])
        job = AtomKey.from_token(provenance['job_ref'])
        if (provenance['schema'] != 'd06.internal-life-content-acquisition.v1'
                or episode.type_name != EPISODE or job.type_name != 'runtime.job'
                or NamespaceId.from_key(episode) != NamespaceId.from_key(job)
                or not job.name.startswith('life-content-job:')
                or any(type(provenance[name]) is not str or not re.fullmatch(r'[0-9a-f]{64}', provenance[name])
                    for name in ('prepared_digest','request_digest'))):
            raise DomainProductionErasureHold('Life acquired input provenance closed scope differs')
        return (episode.token, job.token)
    if (domain, operation_kind) == ('d11', 'prepare_internal_life_content'):
        _exact(provenance, ('prepared_digest', 'episode_ref', 'occurrence_digest', 'job_ref'))
        from .d06_internal_life_episode_v2 import EPISODE
        episode = AtomKey.from_token(provenance['episode_ref'])
        job = AtomKey.from_token(provenance['job_ref'])
        if (episode.type_name != EPISODE or job.type_name != 'runtime.job'
                or NamespaceId.from_key(episode) != NamespaceId.from_key(job)
                or not job.name.startswith('life-content-job:')
                or any(type(provenance[name]) is not str or not re.fullmatch(r'[0-9a-f]{64}', provenance[name])
                    for name in ('prepared_digest', 'occurrence_digest'))):
            raise DomainProductionErasureHold('Life content preparation provenance scope/closed type differs')
        return (episode.token, job.token)
    if (domain, operation_kind) == ("d11", "prepare_contact_model_v2"):
        from .c09_contact_originals_v2 import decode_contact_preparation_provenance_v2
        return decode_contact_preparation_provenance_v2(provenance)
    if (domain, operation_kind) == ("d11", "prepare_contact_model"):
        from .c09_contact_originals_v1 import decode_contact_preparation_provenance_v1
        return decode_contact_preparation_provenance_v1(provenance)
    if (domain,operation_kind)==('d08','adopt_contact_expression_plan_v2'):
        _exact(provenance,('schema','contact_plan','expression','proof'))
        from ..domains.d08.contact_plan_v2 import PROVENANCE,PLAN,decode_contact_plan_member_v2
        from .contact_plan_adoption_v2 import SIGN_KIND
        from ..domains.d09.natural_reply import NaturalExpressionPlanV2
        proof=decode_contact_plan_member_v2(PROVENANCE,provenance['proof'])
        plan=decode_contact_plan_member_v2(PLAN,provenance['contact_plan'])
        expression=decode_typed_production_value_v1(provenance['expression'],NaturalExpressionPlanV2)
        if (provenance['schema']!=SIGN_KIND or canonical_serialize(proof.plan)!=canonical_serialize(plan)
                or canonical_digest(expression.units)!=plan.qualified_units_digest):
            raise DomainProductionErasureHold('Contact Plan v2 actual expression/proof differs')
        return tuple(sorted(set(_references(provenance))))
    if (domain, operation_kind) == ("d08", "adopt_contact_expression_plan"):
        _exact(provenance, ("contact_plan", "expression", "owner_policy_original", "owner_policy_digest"))
        from ..domains.d08.contact_plan_v1 import decode_contact_plan_v1
        from ..domains.d09.natural_reply import NaturalExpressionPlanV2
        plan = decode_contact_plan_v1(provenance["contact_plan"])
        expression = decode_typed_production_value_v1(provenance["expression"], NaturalExpressionPlanV2)
        if (canonical_digest(expression.units) != plan.qualified_units_digest
                or provenance["owner_policy_original"] != plan.policy_original_ref
                or provenance["owner_policy_digest"] != plan.policy_original_digest):
            raise DomainProductionErasureHold("contact full expression and current Owner policy differ")
        return tuple(sorted(set(_references(provenance))))
    if (domain, operation_kind) == ("d07", "focus_life_project"):
        _exact(provenance, ("owner_project_ref", "owner_project_source_ref", "owner_focus_selection"))
        if (AtomKey.from_token(provenance["owner_project_ref"]).type_name != "d10.life_project.v1"
                or AtomKey.from_token(provenance["owner_project_source_ref"]).type_name != "memory.source"
                or provenance["owner_focus_selection"] != "owner_directed_project"):
            raise DomainProductionErasureHold("Owner project focus provenance differs from its fixed operation")
        return tuple(sorted(set(_references(provenance))))
    if (domain, operation_kind) == ("d03", "prepare_life_project_context"):
        _exact(provenance, ("life_project_ref", "life_context_source_ref"))
        if (AtomKey.from_token(provenance["life_project_ref"]).type_name != "d10.life_project.v1"
                or AtomKey.from_token(provenance["life_context_source_ref"]).type_name != "memory.source"):
            raise DomainProductionErasureHold("project context provenance has another actual type")
        return tuple(sorted(set(_references(provenance))))
    if (domain, operation_kind) == ("d08", "prepare_selected_source_note_action_v2"):
        from .d08_source_note_action_v1 import PrepareSourceNoteActionRequestV1
        from ..domains.d08.personal_candidate_v1 import PreparedPersonalCandidateV1, SourceNoteCandidateBindingV1
        _exact(provenance, {"source_note_target_entity_ref", "source_note_role_binding_ref", "source_note_project_ref",
            "source_note_recipe_ref", "source_note_goal_ref", "derived_request", "selected_decision_ref", "selected_decision_digest",
            "preparation_original_ref", "preparation_original_digest", "selected_candidate"})
        derived = decode_typed_production_value_v1(provenance["derived_request"], PrepareSourceNoteActionRequestV1)
        chosen = decode_typed_production_value_v1(provenance["selected_candidate"], PreparedPersonalCandidateV1)
        if type(chosen.binding) is not SourceNoteCandidateBindingV1 or chosen.eligibility.hard_status != "eligible":
            raise DomainProductionErasureHold("selected SourceNote action must retain its actual eligible SourceNote candidate")
        binding = chosen.binding
        if (derived.project_ref, derived.recipe_ref, derived.source_ref, derived.goal_ref, derived.target_entity_ref, derived.role_binding_ref) != (
                binding.project_ref, binding.recipe_ref, binding.source_ref, binding.goal_ref, binding.target_entity_ref, binding.role_binding_ref):
            raise DomainProductionErasureHold("selected SourceNote action parameters differ from its actual selected binding")
        if AtomKey.from_token(provenance["selected_decision_ref"]).type_name != "d08.decision_record.v2":
            raise DomainProductionErasureHold("selected SourceNote action has another Decision type")
        for name in ("selected_decision_digest", "preparation_original_digest"):
            value = decode_typed_production_value_v1(provenance[name], str)
            if len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
                raise DomainProductionErasureHold("selected SourceNote action original commitment differs")
        return tuple(sorted(set(_references(provenance))))
    if (domain, operation_kind) == ("d08", "prepare_source_note_action"):
        _exact(provenance, ("source_note_target_entity_ref", "source_note_role_binding_ref", "source_note_project_ref", "source_note_recipe_ref", "source_note_goal_ref"))
        if any(AtomKey.from_token(provenance[name]).type_name != kind for name, kind in (
                ("source_note_target_entity_ref", "d03.entity_anchor"), ("source_note_role_binding_ref", "d03.role_binding"),
                ("source_note_project_ref", "d10.life_project.v1"), ("source_note_recipe_ref", "d10.activity_recipe.v1"),
                ("source_note_goal_ref", "d08.goal.v1"))):
            raise DomainProductionErasureHold("source-note root context has another installed type")
        return tuple(sorted(set(_references(provenance))))
    if domain == "d02" and operation_kind in {"prepare_source_note_body", "prepare_artifact_draft_body"}:
        _exact(provenance, ("life_body_root_action_ref", "life_body_root_action_digest", "life_body_resource_quote", "life_body_quote", "life_body_effect_policy"))
        from .issuers import ResourceQuote
        from ..domains.d02 import BodyQuote
        from .d02_production_operations_v1 import SettledBodyEffectPolicyV1
        decode_typed_production_value_v1(provenance["life_body_resource_quote"], ResourceQuote)
        decode_typed_production_value_v1(provenance["life_body_quote"], BodyQuote)
        decode_typed_production_value_v1(provenance["life_body_effect_policy"], SettledBodyEffectPolicyV1)
        return tuple(sorted(set(_references(provenance))))
    if (domain, operation_kind) == ("d06", "form_association"):
        _exact(provenance, ("formation",))
        from .d06_association_formation_v1 import decode_association_formation_evidence_v1
        formation = decode_association_formation_evidence_v1(provenance["formation"])
        return formation.basis_source_refs
    if operation_kind == 'register_artifact_task_milestone_v2':
        if domain != 'd08': raise DomainProductionErasureHold('task milestone requires its registered d08 writer')
        if provenance == {}: return ()
        _exact(provenance, {'artifact_task_milestone'})
        from .artifact_task_observer_v1 import decode_artifact_task_milestone_v2
        decode_artifact_task_milestone_v2(provenance['artifact_task_milestone'])
        return tuple(sorted(ref for ref in _references(provenance) if AtomKey.from_token(ref).type_name == 'memory.source'))
    if operation_kind in {"input:register_artifact_phase_postcondition_policy_v1", "register_artifact_phase_postcondition_contract_v1", "observe_artifact_phase_postconditions_v1", "input:approve_artifact_standing_predecision_v2", "input:freeze_artifact_candidate_preparation_v1"}:
        from .artifact_phase_postconditions_v1 import (POLICY_KIND, CONTRACT_KIND, ASSESSMENT_KIND, APPROVAL_KIND_V2, PREPARATION_PARENT_KIND_V1,
            decode_artifact_phase_postcondition_original_v1)
        expected_domain, field, kind = {
            "input:register_artifact_phase_postcondition_policy_v1": ("d08", "postcondition_policy", POLICY_KIND),
            "input:approve_artifact_standing_predecision_v2": ("d08", "standing_predecision_approval", APPROVAL_KIND_V2),
            "input:freeze_artifact_candidate_preparation_v1": ("d08", "candidate_preparation_parent", PREPARATION_PARENT_KIND_V1),
            "register_artifact_phase_postcondition_contract_v1": ("d08", "postcondition_contract", CONTRACT_KIND),
            "observe_artifact_phase_postconditions_v1": ("d11", "phase_assessment", ASSESSMENT_KIND),
        }[operation_kind]
        if domain != expected_domain:
            raise DomainProductionErasureHold("postcondition operation changed its registered exact writer")
        if provenance == {}:
            return ()
        _exact(provenance, {field})
        decode_artifact_phase_postcondition_original_v1(kind, provenance[field])
        return tuple(sorted(ref for ref in _references(provenance) if AtomKey.from_token(ref).type_name == "memory.source"))
    if operation_kind in {"input:register_artifact_task_text_extent", "input:register_artifact_phase_price_policy"}:
        from .artifact_task_text_extent_v1 import decode_artifact_task_text_extent_original_v1
        from .d02_artifact_phase_price_v1 import ArtifactPhasePricePolicyV1
        expected_domain, field = ("d08", "artifact_task_text_extent") if (
            operation_kind == "input:register_artifact_task_text_extent") else (
            "d02", "artifact_phase_price_policy")
        if domain != expected_domain:
            raise DomainProductionErasureHold("artifact registration has another exact Owner writer")
        if provenance == {}:
            return ()
        _exact(provenance, {field})
        value = (decode_artifact_task_text_extent_original_v1(provenance[field]) if
            operation_kind == "input:register_artifact_task_text_extent" else
            decode_typed_production_value_v1(provenance[field], ArtifactPhasePricePolicyV1))
        from ..domains.d01.production_operations_v1 import plain_v1
        if plain_v1(value) != provenance[field]:
            raise DomainProductionErasureHold("artifact registration changed its closed typed original")
        roots = tuple(sorted(ref for ref in _references(provenance) if AtomKey.from_token(ref).type_name == "memory.source"))
        if value_type is ArtifactPhasePricePolicyV1 and roots:
            raise DomainProductionErasureHold("source-independent phase price cannot carry task content")
        return roots
    if type(operation_kind) is str and operation_kind.startswith("input:"):
        from .domain_production_inputs_v1 import input_operation_for_request_v1
        kind = operation_kind.removeprefix("input:")
        try:
            registration = input_operation_for_request_v1(kind)
        except (ValueError, TypeError) as error:
            raise DomainProductionErasureHold("unknown Owner input provenance kind") from error
        if (domain != registration.domain or set(provenance) != {"producer_kind", "input_request_digest"}
                or provenance["producer_kind"] != kind or type(provenance["input_request_digest"]) is not str
                or not re.fullmatch(r"[0-9a-f]{64}", provenance["input_request_digest"])):
            raise DomainProductionErasureHold("Owner input provenance differs from its exact registered producer")
        return ()
    shapes = {
        ("d01", "evaluate_values"): [{"persona_view", "candidate_original", "context_original", "evaluation"},
            {"persona_view", "candidate_original", "context_original", "evaluation", "method_strategy"}],
        ("d01", "adopt_growth"): [{"proposal", "originals"}, {"candidate", "originals"}],
        ("d01", "migrate_semantic_identity_v3"): [{"candidate", "originals"}, {}],
        ("d01", "project_self_model_v3"): [{"self_model"}, {}],
        ("d02", "advance_body"): [{"state", "unresolved_reservations"}, {"state", "duplicate_interval", "clock"},
            {"prior_state", "segments", "clock", "trigger", "processed_until", "requested_until"}],
        ("d02", "apply_body_effect"): [{"settlement", "terminal", "effect_policy", "body_quote", "component_id", "component_receipt"}],
        ("d05", "adopt_relationship_contribution"): [{"contribution", "duplicate", "trigger", "policy", "entity"}],
        ("d05", "revise_boundary"): [{"prior_rule", "intent", "policy", "consents"}],
        ("d05", "reevaluate_relationship"): [{"reevaluation", "historical_contributions_preserved"}],
        ("d06", "encode_structured_experience"): [{"source", "world_event", "causal_original", "self_identity_original",
            "self_mapping_ref", "perspective_ref", "episode_ref", "encoding_status", "duplicate"}],
        ("d08", "acknowledge_bilateral"): [{"acknowledgement", "read", "acceptance", "outbound", "actor"}],
        ("d08", "adopt_joint_plan"): [{"plan", "proposal", "consents", "terms_digest", "current_goals", "current_boundaries", "execution"}],
        ("d08", "recheck_action"): [{"action_recovery", "commitment_check", "boundary_check", "required_specs", "actual_originals", "admission"}],
        ("d08", "settle_observed_action"): [{"action_outcome", "outcome_settlement", "observation_original", "cost_original"}],
        ("d10", "advance_life"): [{"life_progress", "actual_progress", "terminal", "adopted_plan", "duplicate"}],
        ("d10", "advance_offline"): [{"interval"}, {"observed_prefix", "interval_original"},
            {"observed_prefix", "interval", "interval_original", "checkpoint", "content_reality", "actuality"}],
        ("d10", "prepare_contact"): [{"contact_candidate", "target_route", "boundaries", "source", "required_check", "claim_phase"},
            {"contact_candidate", "target_route", "boundaries", "source", "required_check", "claim_phase", "policy_approval"}],
        ("d10", "prepare_life"): [{"prepared_binding", "execution"}],
        ("d11", "adopt_life"): [{"actual_terminal", "actual_cost", "actual_job"}],
        ("d08", "adopt_life"): [{"action_outcome", "actual_terminal", "actual_cost", "postcondition_build_digest"}],
        ("d10", "prepare_offline_tick"): [{"prepared_binding", "actual_schedule_original", "actual_clock_original", "execution"}],
        ("d11", "record_host_lifecycle"): [{"actual_lifecycle_original", "trusted_clock_original"}],
        ("d06", "adopt_offline_tick"): [{"prepared_original", "actual_terminal", "source_refs", "terminal_status"}],
        ("d11", "adopt_offline_tick"): [{"actual_terminal", "actual_cost", "actual_job"}],
    }
    if (domain, operation_kind) not in shapes or set(provenance) not in shapes[(domain, operation_kind)]:
        raise DomainProductionErasureHold("unknown current domain stage provenance variant")
    from .domain_production_contracts_v1 import ProductionOriginalRefV1
    from ..domains.d01 import PersonaView, ValueEvaluation, GrowthAdoptionCandidate, GrowthProposal
    from ..domains.d01.identity_v3 import SelfModelProjectionV3
    from ..domains.d02 import BodyState, BodyQuote, SettlementResult
    from ..domains.d05.relationship import RelationshipContribution, BoundaryRule
    from ..domains.d08.commitment_acknowledgement import BilateralAcknowledgementCandidateV1, BilateralAcknowledgementReadV1
    from ..domains.d08.execution import ActionOutcome, JointPlan, OutcomeSettlement
    from ..domains.d08.execution import RequiredCheckSpec
    from ..domains.d08.action_recovery import CurrentActionRecoveryCandidateV1
    from ..domains.d05.relationship import BoundaryCheck
    from ..domains.d10 import LifeProgress
    from ..domains.d10.production_operations_v1 import LifeProgressHeadV1, OfflineCheckpointV1
    from ..domains.d10.offline_interval import OfflineSimulationSliceCandidate, OfflineTickAdvanceCandidateV1
    from ..domains.d02.production_operations_v1 import PassiveBodySegmentV1
    from ..domains.d10.current_contact import CurrentContactCandidateV1
    from ..domains.d05.source_correction import D05SourceReevaluationCandidate
    from ..runtime_contracts import CheckReceipt
    from ..memory_types import SourceRecord
    from ..domains.d03.context import WorldEvent
    from ..domains.d01.production_operations_v1 import MethodStrategyProjectionV1
    types_by_name = {"persona_view": PersonaView, "evaluation": ValueEvaluation,
        "method_strategy": MethodStrategyProjectionV1,
        "action_outcome": ActionOutcome, "outcome_settlement": OutcomeSettlement,
        "observation_original": ProductionOriginalRefV1, "cost_original": ProductionOriginalRefV1,
        "policy_approval": ProductionOriginalRefV1 | None,
        "self_model": SelfModelProjectionV3, "candidate": GrowthAdoptionCandidate, "state": BodyState, "prior_state": BodyState,
        "settlement": SettlementResult, "body_quote": BodyQuote, "contribution": RelationshipContribution,
        "prior_rule": BoundaryRule | None, "reevaluation": D05SourceReevaluationCandidate,
        "acknowledgement": BilateralAcknowledgementCandidateV1, "read": BilateralAcknowledgementReadV1,
        "plan": JointPlan, "life_progress": LifeProgress, "actual_progress": LifeProgressHeadV1,
        "checkpoint": OfflineCheckpointV1, "contact_candidate": CurrentContactCandidateV1,
        "required_check": CheckReceipt | None, "segments": tuple[PassiveBodySegmentV1, ...],
        "action_recovery": CurrentActionRecoveryCandidateV1, "commitment_check": CheckReceipt,
        "boundary_check": BoundaryCheck, "required_specs": tuple[RequiredCheckSpec, ...],
        "actual_originals": tuple[ProductionOriginalRefV1, ...], "admission": str,
        "interval": OfflineSimulationSliceCandidate, "observed_prefix": OfflineTickAdvanceCandidateV1,
        "unresolved_reservations": tuple[str, ...], "historical_contributions_preserved": tuple[str, ...],
        "current_goals": tuple[str, ...], "component_id": str, "component_receipt": str,
        "terms_digest": str, "execution": str, "content_reality": str, "actuality": str,
        "claim_phase": str, "processed_until": float, "requested_until": float,
        "duplicate": bool, "duplicate_interval": bool}
    if domain == "d06":
        types_by_name.update({"source": SourceRecord, "world_event": WorldEvent,
            "causal_original": ProductionOriginalRefV1, "self_identity_original": ProductionOriginalRefV1,
            "self_mapping_ref": str, "perspective_ref": str, "episode_ref": str, "encoding_status": str})
    if operation_kind in {"prepare_life", "adopt_life"}:
        from .d11_life_contract_v1 import D11LifeExecutionBindingV1, D11LifeTerminalV1
        from .d11_types import RuntimeCostSettlement
        types_by_name.update({"prepared_binding":D11LifeExecutionBindingV1,"actual_terminal":D11LifeTerminalV1,
            "actual_cost":RuntimeCostSettlement,"postcondition_build_digest":str})
        if "actual_job" in provenance:
            from .jobs import PersistentJob
            from .d10_offline_tick_execution_v1 import _decode_json
            job=_decode_json(canonical_serialize(provenance["actual_job"]),PersistentJob)
            from .d11_life_contract_v1 import life_from_wire_v1, life_work_kind_v1
            binding = (life_from_wire_v1(provenance["actual_terminal"], D11LifeTerminalV1).binding
                if "actual_terminal" in provenance else life_from_wire_v1(provenance["prepared_binding"], D11LifeExecutionBindingV1))
            if job.work_kind != life_work_kind_v1(binding):
                raise DomainProductionErasureHold("Life actual job differs from its closed actual binding family")
            types_by_name["actual_job"]=None
    if operation_kind == "prepare_offline_tick":
        from .d11_offline_originals_v1 import D11OfflineTickBindingV1
        types_by_name.update({"prepared_binding": D11OfflineTickBindingV1,
            "actual_schedule_original": ProductionOriginalRefV1, "actual_clock_original": ProductionOriginalRefV1})
    if operation_kind == "record_host_lifecycle":
        from .d11_offline_originals_v1 import D11HostLifecycleOriginalV1
        types_by_name.update({"actual_lifecycle_original": D11HostLifecycleOriginalV1, "trusted_clock_original": ProductionOriginalRefV1})
    if operation_kind == "adopt_offline_tick":
        from ..authority_service.d11_offline_tick_contract_v1 import D11OfflineTickTerminalV1
        from .d11_types import RuntimeCostSettlement
        from .jobs import PersistentJob
        types_by_name.update({"prepared_original": ProductionOriginalRefV1, "actual_terminal": D11OfflineTickTerminalV1,
            "source_refs": tuple[str, ...], "terminal_status": str, "actual_cost": RuntimeCostSettlement})
        # PersistentJob's continuation/operator maps are intentionally not
        # generic content schemas. This exact fixed worker kind is closed here.
        if "actual_job" in provenance:
            _validate_offline_job_wire_v1(provenance["actual_job"])
            types_by_name["actual_job"] = None
    original_fields = {"candidate_original", "context_original", "clock", "trigger", "terminal", "effect_policy", "policy",
        "entity", "intent", "acceptance", "outbound", "actor", "adopted_plan", "target_route", "source", "interval_original"}
    for name, value in provenance.items():
        if name == "proposal":
            decode_typed_production_value_v1(value, GrowthProposal if domain == "d01" else ProductionOriginalRefV1)
        elif name == "contribution" and domain == "d05":
            from ..domains.d05.relationship import decode_relationship_contribution_payload_v1
            decode_relationship_contribution_payload_v1(value)
        elif name in types_by_name:
            if types_by_name[name] is not None:
                decode_typed_production_value_v1(value, types_by_name[name])
        elif name in original_fields:
            decode_typed_production_value_v1(value, ProductionOriginalRefV1)
        elif name in {"originals", "consents", "current_boundaries", "boundaries"}:
            decode_typed_production_value_v1(value, tuple[ProductionOriginalRefV1, ...])
        else:
            raise DomainProductionErasureHold("production provenance field has no installed typed decoder")
    constants = {"admission": "requires_fresh_d11_dispatch_admission", "execution": "each_effect_requires_separate_current_action_and_required_checks",
        "content_reality": "simulation", "actuality": "computed_at_recovery", "claim_phase": "final_dispatch_admission"}
    if domain == "d06":
        constants["encoding_status"] = "encoding_pending"
    if operation_kind == "prepare_life":
        constants["execution"] = "requires_actual_d11_once_claim_and_durable_artifact_postcondition"
    if operation_kind == "prepare_offline_tick":
        constants["execution"] = "requires_independent_d11_once_claim_and_actual_terminal"
    for name, expected in constants.items():
        if name in provenance and provenance[name] != expected:
            raise DomainProductionErasureHold("production semantic/actuality marker differs")
    if "terms_digest" in provenance and (len(provenance["terms_digest"]) != 64
            or any(char not in "0123456789abcdef" for char in provenance["terms_digest"])):
        raise DomainProductionErasureHold("joint plan terms commitment differs")
    for name, type_name in (("current_goals", "d08.goal.v1"), ("historical_contributions_preserved", "d05.contribution")):
        for ref in provenance.get(name, ()):
            if AtomKey.from_token(ref).type_name != type_name:
                raise DomainProductionErasureHold("production provenance reference has another registered type")
    return tuple(sorted({ref for ref in _references(provenance) if AtomKey.from_token(ref).type_name == "memory.source"}))

def _validate_offline_job_wire_v1(raw):
    from .jobs import PersistentJob
    _exact(raw, (field.name for field in fields(PersistentJob)))
    _exact(raw["continuation"], ("schema", "prepared_original_ref", "schedule_ref", "scheduled_at_utc", "source_ref", "input_digest", "execution_id"))
    _exact(raw["operator_versions"], ("algorithm", "resource_quote"))
    if (raw["work_kind"] != "d10.offline_observed_tick.v1" or raw["continuation"]["schema"] != "d11.actual-offline-tick-job.v1"
            or raw["operator_versions"]["algorithm"] != "d11.signed_role_clock_tick.v1"
            or not set(raw["usage"]) <= {"thread_cpu_ms"} or raw["wake_condition"] is not None):
        raise DomainProductionErasureHold("offline job continuation/operator/cost kinds differ")
    value = PersistentJob(**raw)
    from .d11_offline_originals_v1 import _utc
    _utc(value.continuation["scheduled_at_utc"])
    if AtomKey.from_token(value.continuation["source_ref"]).type_name != "memory.source":
        raise DomainProductionErasureHold("offline job source locator differs")
    for key, item in value.continuation.items():
        if type(item) is not str or not item:
            raise DomainProductionErasureHold("offline job continuation field is not closed text")
    return value


DERIVED_STORE_TABLES_V6 = frozenset({"graph_d11_derived_cache_payloads_v1",
    "graph_d13_derived_activations_v6", "graph_d13_wire_evidence_v6", "graph_d13_core_wire_evidence_v1"})
DERIVED_WIRE_FACT_TABLES_V6 = frozenset({"graph_d13_wire_evidence_v6", "graph_d13_core_wire_evidence_v1"})



def _validate_core_wire_evidence_row_v7(data, namespace):
    """Closed imported counter metadata; crypto origin remains the cross-Core historical gate."""
    from ..authority_service.d13_core_counter_contract_v1 import (
        D13CurrentWireCountSelectorV1, D13CoreFullWireEnvelopeV1, d13_core_counter_from_wire_v1)
    from ..graph_coordinator import namespace_ref
    selector = d13_core_counter_from_wire_v1(_json(data["selector_json"]), D13CurrentWireCountSelectorV1)
    envelope = d13_core_counter_from_wire_v1(_json(data["envelope_json"]), D13CoreFullWireEnvelopeV1)
    payload = envelope.payload
    frame = payload.frame
    if (canonical_serialize(asdict(selector)) != data["selector_json"]
            or canonical_serialize(asdict(envelope)) != data["envelope_json"]
            or data["evidence_digest"] != envelope.evidence_digest
            or frame.namespace != namespace or frame.authority_namespace != namespace_ref(namespace)
            or (data["frame_intent_id"], data["policy_digest"], data["c02_operation_id"])
                != (frame.frame_intent_id, frame.policy_digest, frame.c02_operation_id)
            or payload.selector_digest != selector.selector_digest
            or (selector.install_id, selector.authority_namespace, selector.frame_intent_id,
                selector.frame_intent_digest, selector.counter_operation_id)
                != (frame.install_id, frame.authority_namespace, frame.frame_intent_id,
                    frame.frame_intent_digest, frame.counter_operation_id)):
        raise DomainProductionErasureHold("V7 imported counter row lost its exact original frame/selector identity")
    for name, expected_name in (("raw_authority_digest", "expected_raw_authority_digest"),
            ("compressed_authority_digest", "expected_compressed_authority_digest"),
            ("raw_http_template_digest", "expected_raw_http_template_digest"),
            ("compressed_http_template_digest", "expected_compressed_http_template_digest")):
        if getattr(selector, expected_name) != getattr(frame, name) or getattr(payload, name) != getattr(frame, name):
            raise DomainProductionErasureHold("V7 imported counter pair differs from its exact signed frame")
    plan = AtomKey.from_token(frame.plan_ref.ref)
    if (frame.plan_ref.version < 1 or plan.type_name != "d08.natural_expression_plan.v2"
            or NamespaceId.from_key(plan) != namespace):
        raise DomainProductionErasureHold("V7 imported counter plan crossed its actual namespace/type")
    for binding in frame.block_bindings:
        key = AtomKey.from_token(binding.metadata_ref)
        if (key.owner.kind != "persona" or key.type_name not in (
                "d13.derived_block_metadata.v1", "d13.derived_block_metadata.v2")
                or NamespaceId.from_key(key) != namespace or binding.metadata_revision < 1
                or binding.turn_last >= binding.turn_first + 64):
            raise DomainProductionErasureHold("V7 imported counter metadata member crossed its finite original scope")
    return "derived_core_wire_evidence", frame.frame_intent_id, _json(data["envelope_json"]), data["evidence_digest"]


def _derived_wire_metadata_members_v6(table, raw):
    payload = raw["payload"]
    bindings = payload["frame"]["block_bindings"] if table == "graph_d13_core_wire_evidence_v1" else payload["block_bindings"]
    return tuple((AtomKey.from_token(binding["metadata_ref"]), binding["metadata_revision"], binding["metadata_digest"])
                 for binding in bindings)


def _derived_fact_primary_key_v6(table):
    return {
        "graph_d13_derived_activations_v6": ("bot", "persona", "block_ref", "before_revision"),
        "graph_d13_wire_evidence_v6": ("bot", "persona", "evidence_digest"),
        "graph_d13_core_wire_evidence_v1": ("bot", "persona", "frame_intent_id"),
    }[table]


def _validate_derived_store_row_v6(table, columns, row, *, authority_namespace=None):
    from hashlib import sha256
    if tuple(columns) != TABLE_COLUMNS[table] or len(row) != len(columns):
        raise DomainProductionErasureHold("derived store has another exact row layout")
    data = dict(zip(columns, row))
    ns = NamespaceId(data["bot"], data["persona"])
    for name in columns:
        if name.endswith("digest") and (type(data[name]) is not str or re.fullmatch('[0-9a-f]{64}', data[name]) is None):
            raise DomainProductionErasureHold("derived store commitment differs")
    if table == "graph_d13_core_wire_evidence_v1":
        return _validate_core_wire_evidence_row_v7(data, ns)
    if table == "graph_d11_derived_cache_payloads_v1":
        from ..domains.d13.provider import _block_from_graph_value, block_graph_value
        payload = data["payload_bytes"]
        if type(payload) is not bytes or not 1 <= len(payload) <= 524288 or sha256(payload).hexdigest() != data["payload_digest"]:
            raise DomainProductionErasureHold("derived body bytes differ from the exact bounded commitment")
        raw = _json(payload.decode("utf-8"))
        block = _block_from_graph_value(raw)
        if block.block_ref != data["block_ref"] or block.status != "standby" or canonical_serialize(block_graph_value(block)).encode('utf-8') != payload:
            raise DomainProductionErasureHold("derived body is another canonical cache member")
        return 'derived_payload', data['block_ref'], raw, data['payload_digest']
    if table == "graph_d13_derived_activations_v6":
        if (type(data['before_revision']) is not int or data['before_revision'] < 1
                or type(data['after_revision']) is not int or data['after_revision'] != data['before_revision'] + 1
                or type(data['block_ref']) is not str or not data['block_ref']
                or type(data['operation_id']) is not str or not data['operation_id']):
            raise DomainProductionErasureHold("derived activation lacks its exact finite transition")
        return 'derived_activation', data['block_ref'], data, data['receipt_digest']
    from ..authority_service.d13_wire_evidence_v6 import _FIELDS, _BINDING_FIELDS, EVIDENCE_SCHEMA
    raw = _json(data['envelope_json'])
    _exact(raw, {'payload', 'signature'})
    payload = _exact(raw['payload'], _FIELDS)
    if (payload['schema'] != EVIDENCE_SCHEMA or payload['namespace'] != {'bot_id':ns.bot_id,'persona_id':ns.persona_id}
            or canonical_serialize(raw) != data['envelope_json'] or canonical_digest(raw) != data['evidence_digest']
            or any(payload[name] != data[name] for name in ('policy_digest','raw_request_digest','compressed_request_digest'))
            or type(raw['signature']) is not str or re.fullmatch('[0-9a-f]{128}', raw['signature']) is None
            or type(payload['block_bindings']) is not list or not 1 <= len(payload['block_bindings']) <= 4):
        raise DomainProductionErasureHold("derived full-wire evidence is another closed signed envelope")
    if payload['token_evidence'] not in {'exact_full_wire','bounded_full_wire'}:
        raise DomainProductionErasureHold('derived full-wire count mode is not contracted')
    for name in ('policy_digest','raw_request_digest','compressed_request_digest','raw_frozen_digest',
            'compressed_frozen_digest','collection_digest','blockset_digest'):
        if type(payload[name]) is not str or re.fullmatch('[0-9a-f]{64}',payload[name]) is None:
            raise DomainProductionErasureHold('derived full-wire exact digest field differs')
    for name in ('raw_lower_tokens','raw_upper_tokens','compressed_lower_tokens','compressed_upper_tokens'):
        if type(payload[name]) is not int or payload[name] < 0:
            raise DomainProductionErasureHold('derived full-wire token bound differs')
    if payload['raw_lower_tokens'] > payload['raw_upper_tokens'] or payload['compressed_lower_tokens'] > payload['compressed_upper_tokens']:
        raise DomainProductionErasureHold('derived full-wire lower bound exceeds upper bound')
    for name in ('frozen_at_utc','expires_at_utc'):
        if type(payload[name]) not in (int,float) or not math.isfinite(payload[name]):
            raise DomainProductionErasureHold('derived full-wire timestamp differs')
    if payload['expires_at_utc'] <= payload['frozen_at_utc']:
        raise DomainProductionErasureHold('derived full-wire evidence has no original valid interval')
    if canonical_digest(payload['block_bindings']) != payload['blockset_digest']:
        raise DomainProductionErasureHold('derived full-wire ordered block commitment differs')
    for binding in payload['block_bindings']:
        _exact(binding, _BINDING_FIELDS)
        for name in ('metadata_digest','payload_digest','plan_digest','paid_original_digest'):
            if type(binding[name]) is not str or re.fullmatch('[0-9a-f]{64}',binding[name]) is None:
                raise DomainProductionErasureHold('derived full-wire block commitment differs')
        for name in ('plan_ref','paid_original_ref'):
            if type(binding[name]) is not str or not binding[name] or len(binding[name]) > 4096:
                raise DomainProductionErasureHold('derived full-wire original locator differs')
        if (type(binding['turn_first']) is not int or binding['turn_first'] < 0
                or type(binding['turn_last']) is not int or not binding['turn_first'] <= binding['turn_last'] < binding['turn_first'] + 64
                or type(binding['expires_at_utc']) not in (int,float) or not math.isfinite(binding['expires_at_utc'])):
            raise DomainProductionErasureHold('derived full-wire finite block interval differs')
        key = AtomKey.from_token(binding['metadata_ref'])
        if key.type_name not in ('d13.derived_block_metadata.v1','d13.derived_block_metadata.v2') or NamespaceId.from_key(key) != ns:
            raise DomainProductionErasureHold("derived full-wire metadata binding crossed namespace/type")
        if type(binding['metadata_revision']) is not int or binding['metadata_revision'] < 1:
            raise DomainProductionErasureHold("derived full-wire binding lacks its real metadata revision")
    return 'derived_wire_evidence', data['evidence_digest'], raw, data['evidence_digest']


def _require_derived_payload_metadata_closure_v6(metadata,block):
    """The actual historical metadata version determines its claimed turn closure."""
    from ..domains.d13.derived_block_metadata_v2 import DerivedBlockMetadataV2,require_derived_turn_dependencies_v2
    if type(metadata)is DerivedBlockMetadataV2:
        scene=AtomKey.from_token(metadata.scene_ref.ref)
        require_derived_turn_dependencies_v2(metadata.namespace,scene.owner.subject,metadata.conversation_ref,
            block.turns,block.source_dependencies)


def _derived_store_metadata_history_key_v6(db,namespace,block_ref,revision=None,*,meter=None):
    """Resolve a block-only historical locator across exactly two registered versions."""
    from ..graph_types import Owner
    matches=[]
    for kind in('d13.derived_block_metadata.v1','d13.derived_block_metadata.v2'):
        key=AtomKey(Owner('persona',*namespace.as_tuple),kind,block_ref)
        where='token=? ORDER BY revision DESC'if revision is None else'token=? AND revision=?'
        args=(key.token,)if revision is None else(key.token,revision)
        if meter is None:row=db.execute('SELECT revision FROM graph_history WHERE '+where+' LIMIT 1',args).fetchone()
        else:row=meter.read_fixed_row(db,'graph_history',('revision',),where,args)
        if row is not None:matches.append(key)
    if len(matches)!=1:
        raise DomainProductionErasureHold('derived block-only history has zero or ambiguous metadata versions')
    return matches[0]


def _derived_store_dispositions_v6(db, table, columns, rows, *, affected, affected_operations, authority_namespace, qualified_retention_manifests=None, qualified_retention_operation_id=None):
    from ..domains.d13.derived_block_metadata_v2 import decode_derived_block_metadata_history_v2
    from ..graph_coordinator import namespace_ref
    result = []
    for row in rows:
        kind, ref, raw, digest = _validate_derived_store_row_v6(table, columns, row)
        data = dict(zip(columns, row)); ns = NamespaceId(data['bot'], data['persona'])
        if authority_namespace is not None and namespace_ref(ns) != authority_namespace:
            result.append('preserved_exact'); continue
        if table in DERIVED_WIRE_FACT_TABLES_V6:
            members = _derived_wire_metadata_members_v6(table, raw)
        else:
            key = _derived_store_metadata_history_key_v6(db,ns,data['block_ref'],data.get('after_revision'))
            members = [(key, data.get('after_revision'), data.get('after_digest'))]
        removed = False
        for key, revision, expected_digest in members:
            if revision is None:
                archived = db.execute('SELECT revision,value,valid,event_id,event_bot,event_persona,event_session FROM graph_history WHERE token=? ORDER BY revision DESC LIMIT 1', (key.token,)).fetchone()
            else:
                archived = db.execute('SELECT revision,value,valid,event_id,event_bot,event_persona,event_session FROM graph_history WHERE token=? AND revision=?', (key.token,revision)).fetchone()
            if archived is None:
                raise DomainProductionErasureHold('derived evidence has no exact historical metadata member')
            if archived[2] != 1:
                if table == 'graph_d11_derived_cache_payloads_v1':
                    raise DomainProductionErasureHold('erased metadata cannot preserve its derived body BLOB')
                _require_qualified_erased_derived_fact_v6(db,table,columns,row,namespace=ns,key=key,revision=archived[0],
                    qualified_retention_manifests=qualified_retention_manifests,
                    qualified_retention_operation_id=qualified_retention_operation_id)
                continue
            metadata = decode_derived_block_metadata_history_v2(key,_json(archived[1]))
            if (expected_digest is not None and canonical_digest(metadata) != expected_digest
                    or table not in DERIVED_WIRE_FACT_TABLES_V6 and metadata.payload_digest != data['payload_digest']):
                raise DomainProductionErasureHold('derived metadata differs from actual cache/evidence commitments')
            if table == 'graph_d11_derived_cache_payloads_v1':
                from ..domains.d13.provider import _block_from_graph_value
                block = _block_from_graph_value(raw)
                _require_derived_payload_metadata_closure_v6(metadata,block)
                if (len(data['payload_bytes']) != metadata.payload_length_bytes or block.source_dependencies != metadata.source_dependencies
                        or block.job_ref != metadata.job_ref or block.candidate_ref != metadata.candidate_ref):
                    raise DomainProductionErasureHold('derived payload lost actual metadata Source/paid-family ownership')
                paid = db.execute('SELECT operation_id,original_digest FROM graph_d13_paid_intent_originals_v1 WHERE bot=? AND persona=? AND job_ref=?', (*ns.as_tuple,metadata.job_ref)).fetchone()
                if paid != (metadata.paid_original_operation_id, metadata.paid_original_digest):
                    raise DomainProductionErasureHold('derived payload lacks its actual paid original identity')
                removed = bool({key.token, *(source.ref for source in metadata.source_dependencies)} & set(affected)) or metadata.paid_original_operation_id in affected_operations
            elif table == 'graph_d13_derived_activations_v6':
                previous = db.execute('SELECT value,valid FROM graph_history WHERE token=? AND revision=?',(key.token,data['before_revision'])).fetchone()
                if (previous is None or previous[1] != 1 or canonical_digest(_json(previous[0])) != data['before_digest']
                        or archived[3] != data['operation_id'] or metadata.status != 'active'):
                    raise DomainProductionErasureHold('derived activation lost its actual before/after Graph receipt transition')
                from ..graph_types import GraphReceipt, NamespaceEpoch
                from ..graph_store import GraphStore
                event = db.execute('SELECT revisions,invalidated,epoch_revision FROM graph_events WHERE bot=? AND persona=? AND session=? AND event_id=?',
                    (*ns.as_tuple,archived[6],data['operation_id'])).fetchone()
                if event is None or archived[4:6] != ns.as_tuple:
                    raise DomainProductionErasureHold('derived activation has no actual same-namespace Graph event receipt')
                receipt = GraphReceipt('committed',GraphStore._version_rows(event[0]),GraphStore._version_rows(event[1]),
                    NamespaceEpoch(*ns.as_tuple,event[2]))
                if (canonical_digest(receipt) != data['receipt_digest']
                        or GraphVersion(key,data['after_revision']) not in receipt.revisions):
                    raise DomainProductionErasureHold('derived activation receipt digest differs from its actual original Graph event')
        result.append('derived_removed' if removed else 'preserved_exact')
    return tuple(result)


def _require_qualified_erased_derived_fact_v6(db, table, columns, row, *, namespace, key, revision,
        qualified_retention_manifests, qualified_retention_operation_id):
    from .c09_graph_rebase_candidate_v1 import _row_digest
    from .c09_graph_originals_read_v4 import read_graph_rebase_certificate_v1
    from .c09_storage_rebase_contract_v1 import GraphTableDispositionManifestV1
    key_digest = canonical_digest(key.token)
    erased = db.execute('SELECT maintenance_generation,operation_id FROM graph_c09_erased_keys_v1 WHERE bot=? AND persona=? AND key_digest=?',
        (*namespace.as_tuple,key_digest)).fetchone()
    if erased is None:
        raise DomainProductionErasureHold('derived erased metadata has no exact namespace tombstone generation')
    history_columns = tuple(row[1] for row in db.execute('PRAGMA table_info(graph_history)'))
    history = db.execute('SELECT * FROM graph_history WHERE token=? AND revision=?',(key.token,revision)).fetchone()
    if history is None:
        raise DomainProductionErasureHold('derived retained fact has no exact metadata history revision')
    data = dict(zip(history_columns,history))
    marker = _json(data['value'])
    if (data['valid'] != 0 or data['dependencies'] != '[]' or marker != {
            'schema':'sylanne3.graph.erased_value.v1','key_digest':key_digest}):
        raise DomainProductionErasureHold('derived retained fact metadata is not the exact content-free erased history')
    if qualified_retention_manifests is not None and erased[1] == qualified_retention_operation_id:
        if (type(qualified_retention_manifests) is not tuple or not qualified_retention_manifests
                or any(type(item) is not GraphTableDispositionManifestV1 for item in qualified_retention_manifests)):
            raise DomainProductionErasureHold('candidate derived fact retention needs the actual frozen-source typed manifests')
        manifests = qualified_retention_manifests
    else:
        certificate = read_graph_rebase_certificate_v1(db,namespace,erased[1])
        if (certificate is None or certificate.maintenance_generation != erased[0]
                or key_digest not in certificate.cumulative_erased_key_digests):
            raise DomainProductionErasureHold('derived erased fact has no exact actual mirrored erasure certificate lineage')
        manifests = certificate.table_manifests
    values = dict(zip(columns,row))
    pk = _derived_fact_primary_key_v6(table)
    fact_key = canonical_digest((table,tuple(values[name] for name in pk)))
    history_key = canonical_digest(('graph_history',(key.token,revision)))
    fact_entries = [entry for manifest in manifests if manifest.table_name == table for entry in manifest.rows if entry.row_key_digest == fact_key]
    history_entries = [entry for manifest in manifests if manifest.table_name == 'graph_history' for entry in manifest.rows if entry.row_key_digest == history_key]
    if (len(fact_entries) != 1 or fact_entries[0].disposition != 'preserved_exact'
            or fact_entries[0].old_commitment != _row_digest(tuple(row)) or fact_entries[0].new_commitment != _row_digest(tuple(row))
            or len(history_entries) != 1 or history_entries[0].disposition != 'payload_erased_retained_facts'
            or history_entries[0].new_commitment != _row_digest(tuple(history))):
        raise DomainProductionErasureHold('derived retained fact/history differs from its exact pre-erasure validated row manifests')
    return True
