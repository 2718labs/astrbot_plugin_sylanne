"""Closed C09 codecs for the installed domain-production input inventory.

These codecs classify real persisted schema fields and dependencies. They do
not authenticate a caller, authorize execution, or manufacture cost facts.
Only the two strictly decoded source-independent policy tables are retained
without a source closure. Every other row is content-bearing derived input.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import fields, is_dataclass
from decimal import Decimal
from enum import Enum
import json
import math
import re
import sqlite3
import types
from typing import Any, Union, get_args, get_origin, get_type_hints

from ..graph_types import AtomKey, GraphVersion, GraphWrite
from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize


TABLE_COLUMNS = {
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
}
TABLE_SCHEMAS = {name: {"columns": columns, "indexes": (), "triggers": ()}
                 for name, columns in TABLE_COLUMNS.items()}
SOURCE_INDEPENDENT_POLICY_TABLES = frozenset({"graph_d02_production_policies_v1", "graph_d05_production_policies_v1"})
CONTENT_TABLES = frozenset(TABLE_COLUMNS) - SOURCE_INDEPENDENT_POLICY_TABLES


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
    expected = sqlite3.connect(":memory:")
    try:
        for installer in (install_d01_production_schema_v1, install_d02_production_schema_v1,
                          install_d05_production_schema_v1, install_d08_production_schema_v1,
                          install_d10_production_schema_v1, install_d11_offline_schema_v1, install_d11_life_schema_v1):
            installer(expected)
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


def decode_typed_production_value_v1(raw, expected, *, depth=0):
    """Strict decoder for the fixed dataclass types named by this module."""
    if depth > 64:
        raise DomainProductionErasureHold("domain production nesting exceeds its installed bound")
    from ..domains.d10.offline_interval import OfflineTickRecipeV1, decode_offline_tick_recipe_v1
    if expected is OfflineTickRecipeV1:
        return decode_offline_tick_recipe_v1(raw)
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
        from ..domain_registry import discover_domain_registry
        registry = discover_domain_registry().type_registry
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
        _exact(raw, (field.name for field in fields(expected)))
        hints = get_type_hints(expected)
        value = {field.name: decode_typed_production_value_v1(raw[field.name], hints[field.name], depth=depth + 1)
                 for field in fields(expected)}
        return expected(**value)
    raise DomainProductionErasureHold("production original has an unregistered nested type")


def _input_types():
    from .d01_production_operations_v1 import _ORIGINAL_TYPES
    from .d02_production_operations_v1 import CompletedActionBodyComponentV1, PassiveBodyPolicyV1, SettledBodyEffectPolicyV1
    from .d05_production_operations_v1 import BoundaryIntentOriginalV1, InstalledRelationshipPolicyV1
    from .d08_production_operations_v1 import JointPlanIntentOriginalV1, PartyConsentEvidenceV1
    from .d10_production_operations_v1 import RegisteredLifePlanV1, RegisteredLifeOutcomeV1, RegisteredOfflineIntervalV1
    from ..domains.d10.offline_interval import OfflineTickRecipeV1, OfflineObservedTickV1
    return {
        "graph_d01_production_inputs_v1": _ORIGINAL_TYPES,
        "graph_d02_production_policies_v1": {"passive": PassiveBodyPolicyV1, "effect": SettledBodyEffectPolicyV1},
        "graph_d02_action_components_v1": {"completed_action_component": CompletedActionBodyComponentV1},
        "graph_d05_production_policies_v1": {"policy": InstalledRelationshipPolicyV1},
        "graph_d05_boundary_intents_v1": {"boundary_intent": BoundaryIntentOriginalV1},
        "graph_d08_joint_plan_intents_v1": {"joint_plan_intent": JointPlanIntentOriginalV1},
        "graph_d08_party_consents_v1": {"party_consent": PartyConsentEvidenceV1},
        "graph_d10_production_inputs_v1": {"life_plan": RegisteredLifePlanV1, "life_outcome": RegisteredLifeOutcomeV1,
            "offline_recipe": OfflineTickRecipeV1, "offline_interval": RegisteredOfflineIntervalV1},
        "graph_d10_observed_ticks_v1": {"observed_tick": OfflineObservedTickV1},
    }


_FIXED_KINDS = {"graph_d02_action_components_v1": "completed_action_component", "graph_d05_production_policies_v1": "policy",
    "graph_d05_boundary_intents_v1": "boundary_intent", "graph_d08_joint_plan_intents_v1": "joint_plan_intent",
    "graph_d08_party_consents_v1": "party_consent", "graph_d10_observed_ticks_v1": "observed_tick"}


def decode_domain_production_content_v1(table, kind, payload_json):
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
    value = decode_typed_production_value_v1(raw, types_by_table[table][kind])
    from ..domains.d01.production_operations_v1 import plain_v1
    from ..domains.d10.offline_interval import OfflineTickRecipeV1, offline_tick_recipe_to_wire_v1
    projection = offline_tick_recipe_to_wire_v1(value) if type(value) is OfflineTickRecipeV1 else plain_v1(value)
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
    if (table == "graph_d11_offline_originals_v1" and kind == "prepared_tick"
            or table == "graph_d11_life_originals_v1" and kind == "prepared"):
        raw = _json(payload_json)
        for item in raw["read_rows"]:
            item["value_json"] = _json(item["value_json"])
        return tuple(sorted({ref for ref in _references(raw) if AtomKey.from_token(ref).type_name == "memory.source"}))
    return tuple(sorted({ref for ref in _references(_json(payload_json)) if AtomKey.from_token(ref).type_name == "memory.source"}))


def validate_domain_production_row_v1(table, columns, row, *, authority_namespace=None):
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
    if table in SOURCE_INDEPENDENT_POLICY_TABLES:
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
    if table == "graph_d08_party_consents_v1" and any(data[name] != raw[field] for name, field in (
            ("plan_proposal_ref", "plan_proposal_ref"), ("participant_ref", "participant_ref"), ("terms_digest", "terms_digest"))):
        raise DomainProductionErasureHold("party consent indexed identity differs")
    if table == "graph_d10_observed_ticks_v1" and data["scheduled_at_utc"] != decoded.scheduled_at_utc:
        raise DomainProductionErasureHold("observed tick schedule SQL identity differs")
    if table == "graph_d11_life_originals_v1":
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
    return kind, data.get("original_ref", data.get("policy_ref", data.get("interval_ref"))), raw, data["payload_digest"]


def validate_offline_original_joins_v1(db):
    """Validate immutable same-operation joins before C09 or migration copying.

    This classifies persisted originals; installed Authority readers still own
    signature authentication and all execution/accounting admission.
    """
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
        nested_hits, source_ids, authority_namespace=None):
    if table == "graph_d11_life_artifact_stage_v1":
        from .c09_life_originals_v1 import life_stage_dispositions_v1
        return life_stage_dispositions_v1(columns, rows, affected=affected, affected_operations=affected_operations,
            nested_hits=nested_hits, source_ids=source_ids, authority_namespace=authority_namespace)
    originals = [validate_domain_production_row_v1(table, columns, row, authority_namespace=authority_namespace) for row in rows]
    if table in SOURCE_INDEPENDENT_POLICY_TABLES:
        return tuple("preserved_exact" for _ in originals)
    links, removed = set(affected) | set(affected_operations), set()
    while True:
        count = len(removed)
        for index, (kind, ref, raw, digest) in enumerate(originals):
            if index in removed:
                continue
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


def validate_domain_stage_provenance_v1(domain, operation_kind, provenance):
    """Closed top-level variants; nested content is checked by typed codecs."""
    if type(provenance) is not dict:
        raise DomainProductionErasureHold("stage provenance must be an exact registered object")
    if not provenance:
        return ()
    if (domain, operation_kind) == ("d11", "prepare_contact_model"):
        from .c09_contact_originals_v1 import decode_contact_preparation_provenance_v1
        return decode_contact_preparation_provenance_v1(provenance)
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
    if (domain, operation_kind) == ("d08", "prepare_source_note_action"):
        _exact(provenance, ("source_note_target_entity_ref", "source_note_role_binding_ref", "source_note_project_ref", "source_note_recipe_ref", "source_note_goal_ref"))
        if any(AtomKey.from_token(provenance[name]).type_name != kind for name, kind in (
                ("source_note_target_entity_ref", "d03.entity_anchor"), ("source_note_role_binding_ref", "d03.role_binding"),
                ("source_note_project_ref", "d10.life_project.v1"), ("source_note_recipe_ref", "d10.activity_recipe.v1"),
                ("source_note_goal_ref", "d08.goal.v1"))):
            raise DomainProductionErasureHold("source-note root context has another installed type")
        return tuple(sorted(set(_references(provenance))))
    if (domain, operation_kind) == ("d02", "prepare_source_note_body"):
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
        ("d01", "evaluate_values"): [{"persona_view", "candidate_original", "context_original", "evaluation"}],
        ("d01", "adopt_growth"): [{"proposal", "originals"}, {"candidate", "originals"}],
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
    types_by_name = {"persona_view": PersonaView, "evaluation": ValueEvaluation,
        "action_outcome": ActionOutcome, "outcome_settlement": OutcomeSettlement,
        "observation_original": ProductionOriginalRefV1, "cost_original": ProductionOriginalRefV1,
        "policy_approval": ProductionOriginalRefV1 | None,
        "candidate": GrowthAdoptionCandidate, "state": BodyState, "prior_state": BodyState,
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
            if job.work_kind != "d10.life.source_note.v1":
                raise DomainProductionErasureHold("Life actual job has another installed family")
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
