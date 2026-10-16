"""Closed C09 inventory for actual D07 work, bodies and accounting originals."""
from __future__ import annotations

from dataclasses import asdict, fields
import json
import re
import sqlite3
import math

from ..graph_types import AtomKey
from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize, VersionedRef, AuthorityContext
from .d07_execution_v1 import (TABLE, SIGN_KIND, KINDS, D07PreparedExecutionV1, D07ExecutionReadV1,
    D07AccountingPreparedV1, D07IngressRecallPreparedV1, D07SemanticQuestionV1, decode_d07_execution_original_v1)
from .d07_graph_stages_v1 import TABLE as STAGE_TABLE
from .d07_accounting_v1 import TABLE as ACCOUNTING_TABLE
from .domain_production_erasure_v1 import decode_typed_production_value_v1

COLUMNS = ("bot", "persona", "kind", "original_ref", "payload_json", "payload_digest", "signature")
STAGE_COLUMNS = ("bot", "persona", "stage_operation_id", "job_id", "phase", "request_digest", "attempt_id", "anchor_json",
    "graph_revision", "graph_epoch", "permit_json", "receipt_json")
ACCOUNTING_COLUMNS = ("bot", "persona", "call_id", "intent_digest", "attempt_id", "anchor_json", "state", "grant_json", "result_json")
TIMING_TABLE = "authority_d07_model_timings_v1"
TIMING_COLUMNS = ("call_id", "admission_id", "request_digest", "binding_digest", "started_at", "ended_at", "terminal_digest")
BODY_KINDS = frozenset({"prepared", "prepare_commit", "request", "result", "execution", "adopted", "simulation_request", "semantic_question", "reflection_request","reflection_continuation","general_growth_attention_v1"})
BODY_KINDS = BODY_KINDS | frozenset({'joint_external_semantic_basis_v1'})
FACT_KINDS = KINDS - BODY_KINDS


def _json(encoded):
    def unique(pairs):
        raw = {}
        for key, value in pairs:
            if key in raw:
                raise ValueError("D07 original repeats a field")
            raw[key] = value
        return raw
    if type(encoded) is not str:
        raise ValueError("D07 exact encoded original required")
    raw = json.loads(encoded, object_pairs_hook=unique)
    if canonical_serialize(raw) != encoded:
        raise ValueError("D07 original is noncanonical")
    return raw


def _fields(raw, names, schema=None):
    if type(raw) is not dict or set(raw) != set(names) or schema is not None and raw.get("schema") != schema:
        raise ValueError("D07 installed original fields/schema differ")
    return raw


def _digest(value):
    if type(value) is not str or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise ValueError("D07 original commitment differs")


def _cost(raw):
    from .budget import BudgetReceipt
    from .d11_types import RuntimeCostSettlement
    _fields(raw, {"schema", "prepared_digest", "result_ref", "result_digest", "cost_ref", "cost_value", "budget_receipt",
        "unknown_dimensions", "paid", "terminal_digest"}, "d07.paid-model-result.v1")
    decode_typed_production_value_v1(raw["budget_receipt"], BudgetReceipt)
    cost = decode_typed_production_value_v1(raw["cost_value"], RuntimeCostSettlement)
    key = AtomKey.from_token(raw["cost_ref"])
    if key.type_name != "runtime.cost_settlement" or type(raw["paid"]) is not bool:
        raise ValueError("D07 preserved cost is not an actual D11 cost contract")
    for name in ("prepared_digest", "terminal_digest"):
        _digest(raw[name])
    if raw["result_digest"] is not None:
        _digest(raw["result_digest"])
    if type(raw["unknown_dimensions"]) is not list or any(type(v) is not str or not v for v in raw["unknown_dimensions"]):
        raise ValueError("D07 preserved unknown cost dimensions differ")
    return cost


def validate_d07_original_payload_v1(kind, raw):
    if kind not in KINDS or kind not in BODY_KINDS | FACT_KINDS:
        raise ValueError("D07 unclassified installed original kind")
    from ..model_broker.d07_cognition_v1 import thaw_d07_cognition_request_v1, d07_cognition_messages_v1
    from ..authority_service.d07_current_execution_v1 import D07CognitionResultReadRequestV1, D07CognitionResultReadV1, from_wire
    if kind == "prepared":
        if raw.get("schema") == "d07.ingress-recall-prepared.v1":
            from ..model_broker.d07_cognition_v1 import thaw_d07_ingress_recall_request_v1
            _fields(raw, (f.name for f in fields(D07IngressRecallPreparedV1)), "d07.ingress-recall-prepared.v1")
            prepared = decode_typed_production_value_v1(raw, D07IngressRecallPreparedV1)
            frozen = thaw_d07_ingress_recall_request_v1(_json(prepared.frozen_json))
            if (frozen.input.namespace != prepared.namespace
                    or frozen.input.c02_operation_id != prepared.c02_operation_id
                    or frozen.input.cycle_job_ref != prepared.cycle_job_ref
                    or frozen.input.need_ref != prepared.need_ref
                    or frozen.input.need_digest != prepared.need_digest):
                raise ValueError("D07 Self prepared input crosses its exact parent/Need original")
            authority_field = "self_authority_json"
        elif raw.get("schema") == "d07.relationship-prepared.v2":
            from .d07_execution_v1 import D07RelationshipPreparedV2
            _fields(raw, (f.name for f in fields(D07RelationshipPreparedV2)), "d07.relationship-prepared.v2")
            from .d07_execution_v1 import decode_native_named_d07_value_v2
            prepared = decode_native_named_d07_value_v2(raw, D07RelationshipPreparedV2)
            thaw_d07_cognition_request_v1(_json(prepared.frozen_json))
            authority_field = "owner_authority_json"

        elif raw.get("schema") == "d07.reflection-prepared.v3":
            from .d07_execution_v1 import D07ReflectionPreparedV3
            _fields(raw,(f.name for f in fields(D07ReflectionPreparedV3)),"d07.reflection-prepared.v3")
            prepared=decode_typed_production_value_v1(raw,D07ReflectionPreparedV3)
            thaw_d07_cognition_request_v1(_json(prepared.frozen_json))
            authority_field="owner_authority_json"
        elif raw.get("schema")=="d07.general-growth-prepared.v1":
            from .d07_general_growth_execution_v1 import D07GeneralGrowthPreparedV1
            _fields(raw,(f.name for f in fields(D07GeneralGrowthPreparedV1)),"d07.general-growth-prepared.v1")
            prepared=decode_typed_production_value_v1(raw,D07GeneralGrowthPreparedV1)
            authority_field="owner_authority_json"
        elif raw.get("schema") == "d07.method-growth-prepared.v2":
            from .d07_method_growth_semantic_v2 import D07MethodGrowthPreparedV2, method_growth_value_from_wire_v2
            _fields(raw, (f.name for f in fields(D07MethodGrowthPreparedV2)), "d07.method-growth-prepared.v2")
            prepared = method_growth_value_from_wire_v2(raw, D07MethodGrowthPreparedV2)
            thaw_d07_cognition_request_v1(_json(prepared.frozen_json))
            authority_field = "owner_authority_json"
        else:
            _fields(raw, (f.name for f in fields(D07PreparedExecutionV1)), "d07.prepared-execution.v1")
            thaw_d07_cognition_request_v1(_json(raw["frozen_json"]))
            authority_field = "owner_authority_json"
        if type(raw["read_rows"]) is not list or len(raw["read_rows"]) > 1024:
            raise ValueError("D07 prepared read closure exceeds installed bounds")
        for row in raw["read_rows"]:
            _fields(row, (f.name for f in fields(D07ExecutionReadV1)))
            D07ExecutionReadV1(**row)
        from .domain_production_contracts_v1 import ProductionOwnerGuardV1
        decode_typed_production_value_v1(_json(raw["owner_guard_json"]), ProductionOwnerGuardV1)
        decode_typed_production_value_v1(_json(raw[authority_field]), AuthorityContext)
        _json(raw["query_inventory_json"])
        external = _json(raw["external_content_originals_json"])
        if type(external) is not list or len(external) > 1:
            raise ValueError("D07 external target closure exceeds installed bound")
        for target in external:
            _fields(target, ("kind", "ref", "revision", "digest"))
            if target["kind"] != "d08_joint_plan_intent" or type(target["revision"]) is not int or target["revision"] < 1:
                raise ValueError("D07 external target kind/revision differs")
            _digest(target["digest"])
    elif kind == "prepare_commit":
        _fields(raw, ("schema", "prepared_digest", "prepare_operation_id", "graph_receipt_digest", "writes_digest", "post_read_rows", "post_query_inventory_json"),
            "d07.preparation-commit.v1")
        for row in raw["post_read_rows"]:
            D07ExecutionReadV1(**_fields(row, (f.name for f in fields(D07ExecutionReadV1))))
        _json(raw["post_query_inventory_json"])
        for name in ("prepared_digest", "graph_receipt_digest", "writes_digest"):
            _digest(raw[name])
    elif kind == "request":
        from .natural_reply_job_v2 import _request_from_wire
        request = _request_from_wire(canonical_serialize(raw))
        from ..model_broker.general_growth_cognition_v1 import (TEMPLATE_DIGEST as GENERAL_TEMPLATE_DIGEST,
            general_growth_cognition_messages_v1)
        messages=(general_growth_cognition_messages_v1(request)if request.prompt_template_digest==GENERAL_TEMPLATE_DIGEST
            else d07_cognition_messages_v1(request))
        if request.identity.phase != "d07.cognition" or messages is None:
            raise ValueError("D07 body request is not the installed exact provider wire")
    elif kind == "call":
        from ..authority_service.v2_model_egress_contract import ModelEgressIntentV1
        from ..authority_service.v2_model_egress_wire import from_wire as model_from_wire
        model_from_wire(raw, ModelEgressIntentV1)
    elif kind == "result_attempt":
        from_wire(raw, D07CognitionResultReadRequestV1)
    elif kind == "result":
        from_wire(raw, D07CognitionResultReadV1)
    elif kind in {"paid_cost", "partial_cost"}:
        _cost(raw)
        if kind == "paid_cost" and (not raw["paid"] or raw["unknown_dimensions"]):
            raise ValueError("D07 paid cost cannot conceal unresolved actual dimensions")
    elif kind == "accounting_prepared":
        actual = D07AccountingPreparedV1(raw)
        from .d07_execution_v1 import _clock_from_json
        _clock_from_json(actual.clock_mapping_json)
        for name in ("prepared_digest", "stage_input_digest", "quote_digest", "reservation_digest", "body_quote_digest", "clock_original_digest"):
            _digest(raw[name])
        for name in ("body_reservation_ref", "body_state_ref", "body_profile_ref"):
            AtomKey.from_token(raw[name])
    elif kind == "body_cost":
        _fields(raw, ("schema", "prepared_digest", "terminal_digest", "result_digest", "component_ref", "settlement_ref", "writes_digest",
            "fixed_cost", "overrun", "unpaid_cost"), "d07.fixed-body-cost.v1")
        if AtomKey.from_token(raw["settlement_ref"]).type_name != "d02.settlement.v1":
            raise ValueError("D07 fixed body cost references another domain")
        for name in ("prepared_digest", "terminal_digest", "writes_digest"):
            _digest(raw[name])
        for name in ("fixed_cost", "overrun", "unpaid_cost"):
            if type(raw[name]) not in (int, float) or raw[name] < 0:
                raise ValueError("D07 body cost amount differs")
    elif kind == "execution":
        decode_d07_execution_original_v1(raw)
    elif kind == "adopted" and raw.get("schema") == "d07.ingress-recall-adoption.v1":
        from .d07_ingress_recall_result_v1 import validate_ingress_recall_adoption_v1
        validate_ingress_recall_adoption_v1(raw, committed=True)
    elif kind == "adopted":
        _fields(raw, ("schema", "interpretation_ref", "interpretation_revision", "interpretation_value_digest", "adoption_operation_id",
            "graph_receipt_digest", "prepared_digest", "actual_result_digest", "question_scope", "supporting_refs", "meaningful_unknowns"),
            "d07.actual-cognition-adoption.v1")
        if AtomKey.from_token(raw["interpretation_ref"]).type_name != "d07.current_interpretation.v1":
            raise ValueError("D07 adopted interpretation domain differs")
        for name in ("interpretation_value_digest", "graph_receipt_digest", "prepared_digest", "actual_result_digest"):
            _digest(raw[name])
        for ref in raw["supporting_refs"]:
            if AtomKey.from_token(ref).type_name != "memory.source":
                raise ValueError("D07 adopted interpretation has unqualified source kind")
    elif kind == "simulation_request":
        from ..domains.d07 import SimulationRequest
        _fields(raw, ("schema", "request", "request_digest", "dedicated_budget_ref", "owner_guard"), "d07.registered-simulation-original.v1")
        request = decode_typed_production_value_v1(raw["request"], SimulationRequest)
        if request.predictions or len(request.alternatives) > 2 or canonical_digest(request) != raw["request_digest"]:
            raise ValueError("D07 registered hypothetical request contains fabricated predictions")
    elif kind == "simulation_budget":
        from .issuers import BudgetLeaseGrant
        _fields(raw, ("schema", "namespace", "lease_id", "parent_id", "grant", "grant_digest", "owner_guard"), "d07.dedicated-simulation-budget.v1")
        grant = decode_typed_production_value_v1(raw["grant"], BudgetLeaseGrant)
        if not raw["parent_id"] or grant.lease_id != raw["lease_id"] or canonical_digest(grant) != raw["grant_digest"]:
            raise ValueError("D07 preserved simulation child grant original differs")
    elif kind == "joint_external_semantic_basis_v1":
        from .joint_external_observation_v1 import JointExternalSemanticBasisV1
        decode_typed_production_value_v1(raw, JointExternalSemanticBasisV1)
    elif kind == "reflection_continuation":
        from .d07_reflection_execution_v1 import D07ReflectionContinuationOriginalV3
        decode_typed_production_value_v1(raw,D07ReflectionContinuationOriginalV3)
    elif kind=="general_growth_attention_v1":
        from .d07_general_growth_attention_v1 import D07GeneralGrowthAttentionOriginalV1
        _fields(raw,(f.name for f in fields(D07GeneralGrowthAttentionOriginalV1)),"d07.general-growth-attention.v1")
        decode_typed_production_value_v1(raw,D07GeneralGrowthAttentionOriginalV1)
    elif kind == "semantic_question":
        from .d07_execution_v1 import D07RelationshipSemanticQuestionV2
        from .d07_method_growth_semantic_v2 import D07MethodGrowthSemanticQuestionV2
        from .d07_general_growth_attention_v1 import D07GeneralGrowthQuestionV1
        question_type = (D07GeneralGrowthQuestionV1 if raw.get("schema")=="d07.general-growth-semantic-question.v1" else
            D07MethodGrowthSemanticQuestionV2 if raw.get("schema") == "d07.method-growth-semantic-question.v2" else
            D07RelationshipSemanticQuestionV2 if raw.get("schema") == "d07.relationship-semantic-question.v2" else D07SemanticQuestionV1)
        if question_type in (D07SemanticQuestionV1,D07GeneralGrowthQuestionV1):
            decode_typed_production_value_v1(raw, question_type)
        else:
            from .d07_execution_v1 import decode_native_named_d07_value_v2
            decode_native_named_d07_value_v2(raw,question_type)
    elif kind == "budget_allocation":
        from .issuers import BudgetLeaseGrant
        from .budget import BudgetReceipt
        _fields(raw, ("schema", "namespace", "operation_id", "lease_id", "parent_id", "grant", "grant_digest", "signature_digest", "creation_receipt"),
            "d07.actual-child-budget.v1")
        grant = decode_typed_production_value_v1(raw["grant"], BudgetLeaseGrant)
        receipt = decode_typed_production_value_v1(raw["creation_receipt"], BudgetReceipt)
        if (grant.lease_id != raw["lease_id"] or canonical_digest(grant) != raw["grant_digest"]
                or grant.allowed_work_kinds != ("d07.cognition",) or receipt.lease_id != raw["lease_id"] or not raw["parent_id"]):
            raise ValueError("D07 child allocation original differs from actual signed grant/receipt")
        _digest(raw["signature_digest"])
    elif kind == "budget_closed":
        from .budget import BudgetReceipt
        _fields(raw, ("schema", "namespace", "lease_id", "parent_id", "operation_id", "prepared_digest", "execution_original_digest", "close_receipt"),
            "d07.actual-child-budget-close.v1")
        receipt = decode_typed_production_value_v1(raw["close_receipt"], BudgetReceipt)
        if receipt.lease_id != raw["lease_id"] or not raw["parent_id"] or receipt.status != "closed":
            raise ValueError("D07 child close lacks its actual receipt")
        _digest(raw["prepared_digest"]); _digest(raw["execution_original_digest"])
    else:
        # No reflection request can enter retention until its concrete producer
        # and closed schema have been installed below. Unknown never means safe.
        from .d07_reflection_execution_v1 import D07ReflectionExecutionRequestV1
        decode_typed_production_value_v1(raw, D07ReflectionExecutionRequestV1)
    return raw


def decoded_nested_d07_original_v1(raw, *, name="", depth=0):
    if depth > 96:
        raise ValueError("D07 original nesting exceeds bound")
    if type(raw) is str and name.endswith("_json"):
        return decoded_nested_d07_original_v1(_json(raw), depth=depth + 1)
    if type(raw) is dict:
        return {k: decoded_nested_d07_original_v1(v, name=k, depth=depth + 1) for k, v in raw.items()}
    if type(raw) is list:
        return [decoded_nested_d07_original_v1(v, depth=depth + 1) for v in raw]
    return raw


def read_d07_inventory_row_v1(columns, row, *, authority_namespace=None, issuer=None):
    if tuple(columns) != COLUMNS or len(row) != len(COLUMNS):
        raise ValueError("D07 installed execution table columns differ")
    bot, persona, kind, ref, wire, digest, signature = row
    ns = NamespaceId(bot, persona)
    raw = _json(wire)
    _digest(digest); _digest(signature)
    if canonical_digest(raw) != digest:
        raise ValueError("D07 actual original byte commitment differs")
    validate_d07_original_payload_v1(kind, raw)
    if issuer is not None:
        issuer._signer.verify(SIGN_KIND, canonical_serialize((ns, kind, ref, digest)), signature)
    if "namespace" in raw:
        expected = authority_namespace if type(raw["namespace"]) is str else asdict(ns)
        if raw["namespace"] != expected:
            raise ValueError("D07 original row namespace differs")
    return kind, ref, raw, digest


def d07_original_dispositions_v1(columns, rows, *, affected, affected_operations, nested_hits, source_ids,
        authority_namespace=None, issuer=None):
    originals = [read_d07_inventory_row_v1(columns, r, authority_namespace=authority_namespace, issuer=issuer) for r in rows]
    links = set(affected) | set(affected_operations)
    removed = set()
    def identities(value):
        if type(value) is dict:
            for name, item in value.items():
                if type(item) is str and name in {"operation_id", "job_id", "call_id", "execution_id", "prepared_digest", "binding_digest", "result_digest",
                        "actual_result_digest", "interpretation_ref", "input_digest", "original_operation_id", "stage_input_digest"}:
                    yield item
                elif type(item) in (dict, list):
                    yield from identities(item)
        elif type(value) is list:
            for item in value:
                yield from identities(item)
    while True:
        before = len(removed)
        for index, (kind, ref, raw, digest) in enumerate(originals):
            if index in removed or kind not in BODY_KINDS:
                continue
            body = decoded_nested_d07_original_v1(raw)
            if ref in links or nested_hits(body, affected, source_ids) or set(identities(body)) & links:
                removed.add(index)
                links.update((ref, digest, *identities(body)))
        if len(removed) == before:
            break
    # Retained accounting identities must join their real originals even when
    # the source body is removed. A paid row cannot attest a different call.
    accounting = {ref: raw for kind, ref, raw, _ in originals if kind == "accounting_prepared"}
    calls = {ref: raw for kind, ref, raw, _ in originals if kind == "call"}
    for kind, ref, raw, _ in originals:
        if kind in {"paid_cost", "partial_cost", "body_cost", "call"}:
            prepared = accounting.get(ref)
            if prepared is None:
                raise ValueError("D07 retained execution fact lacks actual accounting-prepared identity")
            if kind == "call":
                if ((raw["job_id"], raw["call_id"], raw["binding_digest"], raw["budget_reservation_operation_id"], raw["budget_reservation_digest"]) !=
                        (prepared["job_id"], prepared["call_id"], prepared["prepared_digest"], prepared["operation_id"], prepared["reservation_digest"])):
                    raise ValueError("D07 retained once-only call differs from original preparation")
            elif raw["prepared_digest"] != prepared["prepared_digest"] or ref not in calls:
                raise ValueError("D07 retained actual cost differs from original once-only call")
    return tuple("derived_removed" if i in removed else "preserved_exact" for i in range(len(originals)))


def validate_d07_schema_v1(db):
    from .d07_execution_v1 import install_d07_execution_schema_v1
    from .d07_graph_stages_v1 import install_d07_graph_stage_schema_v1
    from .d07_accounting_v1 import install_d07_accounting_schema_v1
    from ..authority_service.d07_model_timing_v1 import install_d07_model_timing_schema_v1
    reference = sqlite3.connect(":memory:")
    try:
        for installer in (install_d07_execution_schema_v1, install_d07_graph_stage_schema_v1,
                install_d07_accounting_schema_v1, install_d07_model_timing_schema_v1):
            installer(reference)
        for table in (TABLE, STAGE_TABLE, ACCOUNTING_TABLE, TIMING_TABLE):
            actual = db.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone()
            if actual is None:
                continue
            expected = reference.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone()
            objects = db.execute("SELECT type,name,sql FROM sqlite_master WHERE tbl_name=? AND type IN ('index','trigger') ORDER BY type,name", (table,)).fetchall()
            wanted = reference.execute("SELECT type,name,sql FROM sqlite_master WHERE tbl_name=? AND type IN ('index','trigger') ORDER BY type,name", (table,)).fetchall()
            if actual != expected or objects != wanted:
                raise ValueError("D07 installed table SQL/constraints differ: " + table)
    finally:
        reference.close()
    return True


def validate_d07_stage_attempt_row_v1(columns, row):
    if tuple(columns) != STAGE_COLUMNS or len(row) != len(STAGE_COLUMNS):
        raise ValueError("D07 fixed stage table columns differ")
    raw = dict(zip(columns, row, strict=True))
    NamespaceId(raw["bot"], raw["persona"])
    reflection_prepare=type(raw["phase"]) is str and re.fullmatch(r"reflection_prepare:[0-9a-f]{48}",raw["phase"]) is not None
    if raw["phase"] not in {"acquire", "result_read", "complete", "adopt"} and not reflection_prepare:
        raise ValueError("D07 unregistered installed stage phase")
    from .restore_anchor import RestoreAnchor
    RestoreAnchor(**_json(raw["anchor_json"]))
    _digest(raw["request_digest"])
    if raw["permit_json"] is not None:
        from ..authority_service.v2_contract import from_wire
        permit = from_wire(_json(raw["permit_json"]))
        if permit.operation != "write" or permit.operation_id != raw["attempt_id"]:
            raise ValueError("D07 exact stage write permit differs")
    if raw["receipt_json"] is not None:
        receipt = _json(raw["receipt_json"])
        allowed = {"status", "job_id", "phase", "reason", "attempt_id", "prepared_digest", "permit_digest", "graph_revision", "graph_epoch"}
        if receipt.get("status") == "held":
            _fields(receipt, allowed)
        elif reflection_prepare:
            if set(receipt) not in ({"status","original_ref"},{"status","job_id","original_ref","prepared_digest"}):
                raise ValueError("reflection preparation receipt hides undeclared content")
            if receipt["status"] not in {"prepared","waiting_for_fair_concern","waiting_for_original_fair_ticket"}:
                raise ValueError("reflection preparation receipt has another actual state")
        elif raw["phase"] == "result_read":
            from ..authority_service.d07_current_execution_v1 import D07CognitionResultReadRequestV1, from_wire
            from_wire(receipt, D07CognitionResultReadRequestV1)
        elif raw["phase"] in {"acquire", "complete"}:
            if set(receipt) not in ({"status", "job_id"}, {"status", "job_id", "terminal_ref"}):
                raise ValueError("D07 stage receipt hides undeclared content")
        elif raw["phase"] == "adopt":
            if set(receipt) not in ({"status", "job_id", "terminal_ref"},
                    {"status", "job_id", "operation_id", "terminal_ref", "interpretation_refs", "reflection_request_ref", "graph_receipt_digest"},
                    {"status", "job_id", "operation_id", "terminal_ref", "receipt"}):
                raise ValueError("D07 adoption stage receipt hides undeclared content")
    return raw


def validate_d07_accounting_attempt_row_v1(columns, row):
    if tuple(columns) != ACCOUNTING_COLUMNS or len(row) != len(ACCOUNTING_COLUMNS):
        raise ValueError("D07 accounting table columns differ")
    raw = dict(zip(columns, row, strict=True))
    NamespaceId(raw["bot"], raw["persona"])
    _digest(raw["intent_digest"])
    from .restore_anchor import RestoreAnchor
    RestoreAnchor(**_json(raw["anchor_json"]))
    if raw["state"] not in {"open", "closed", "committed"}:
        raise ValueError("D07 original accounting state differs")
    if raw["grant_json"] is not None:
        from ..authority_service.v2_accounting_contract import AccountingMaintenanceGrantV1
        decode_typed_production_value_v1(_json(raw["grant_json"]), AccountingMaintenanceGrantV1)
    if raw["result_json"] is not None:
        _cost(_json(raw["result_json"]))
    if raw["state"] == "committed" and (raw["grant_json"] is None or raw["result_json"] is None):
        raise ValueError("D07 accounting commit lacks actual grant/result")
    return raw


def validate_d07_timing_row_v1(columns, row):
    if tuple(columns) != TIMING_COLUMNS or len(row) != len(TIMING_COLUMNS):
        raise ValueError("D07 independent timing table columns differ")
    if row[5] is None:
        if row[6] is not None:
            raise ValueError("D07 unknown interval may not invent a terminal")
        _digest(row[1]); _digest(row[2]); _digest(row[3])
        if type(row[4]) not in (int, float) or not math.isfinite(row[4]) or row[4] < 0:
            raise ValueError("D07 original admission start time differs")
        return dict(zip(columns, row, strict=True))
    from ..authority_service.d07_model_timing_v1 import D07ModelTimingOriginalV1
    return asdict(D07ModelTimingOriginalV1(*row))
