"""Closed C09 inventory for D04 immutable originals in the business database.

This codec does not grant execution, validate an adoption, or invent receipts.
It authenticates original bytes and classifies the real installed kinds. Only
fixed content-free accounting contracts survive an affected body closure.
"""
from __future__ import annotations

from dataclasses import fields
import json

from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize

TABLE = "graph_d04_originals_v3"
COLUMNS = ("bot", "persona", "kind", "original_ref", "payload_json", "payload_digest")

# The disposition is part of the installed inventory, never inferred from an
# arbitrary caller's schema, a lack of references, or an empty table.
BODY_KINDS = frozenset({
    "appraisal", "appraisal_request", "appraisal_result", "appraisal_acceptance",
    "semantic_mapping", "numeric_prepared", "numeric_artifact", "joint_evidence_payloads",
    "root_prepared", "root_artifact",
})
FACT_KINDS = frozenset({
    "c02_interpretation", "appraisal_scope", "appraisal_call", "appraisal_result_attempt",
    "appraisal_cost", "appraisal_cost_partial", "appraisal_no_supported_meaning", "stage_refusal",
    "numeric_claim", "numeric_measurement", "numeric_terminal", "numeric_cost",
    "numeric_accounting_prepared", "numeric_accounting_gate", "numeric_execution_closure",
    "numeric_historical_cost", "numeric_adoption_bridge", "numeric_adoption",
    "root_accounting_prepared", "root_claim", "root_measurement", "root_terminal", "root_cost",
    "root_adoption_bridge", "root_execution_link",
    "root_accounting_gate", "root_historical_cost",
})

# Explicit new codec; the old wire schemas and decoders stay closed.
SERIES_BODY_KINDS = frozenset({"series_root", "series_chunk_prepared", "series_chunk_math", "series_final_native_prefix"})
SERIES_FACT_KINDS = frozenset({"series_chunk_accounting", "series_chunk_measurement", "series_chunk_terminal",
    "series_chunk_cost_pending", "series_chunk_cost_commit", "series_chunk_cost", "series_chunk_cost_gate", "series_chunk_measurement_gate", "series_progress",
    "series_adoption", "series_adoption_gate", "series_adoption_rejected"})
BODY_KINDS = BODY_KINDS | SERIES_BODY_KINDS
FACT_KINDS = FACT_KINDS | SERIES_FACT_KINDS


class D04ErasureInventoryHold(ValueError):
    """An installed original has no explicit, content-safe classification."""


def _fields(raw, names, schema=None):
    if type(raw) is not dict or set(raw) != set(names):
        raise D04ErasureInventoryHold("D04 original fields differ from its installed kind")
    if schema is not None and raw.get("schema") != schema:
        raise D04ErasureInventoryHold("D04 original schema differs from its installed kind")
    return raw


def _dto_fields(raw, cls, schema=None):
    return _fields(raw, (f.name for f in fields(cls)), schema)


def _json(raw):
    if type(raw) is not str:
        raise D04ErasureInventoryHold("D04 original JSON text required")
    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise D04ErasureInventoryHold("D04 original has duplicate fields")
            value[key] = item
        return value
    value = json.loads(raw, object_pairs_hook=unique,
        parse_constant=lambda _: (_ for _ in ()).throw(D04ErasureInventoryHold("nonfinite D04 original")))
    if canonical_serialize(value) != raw:
        raise D04ErasureInventoryHold("D04 original JSON is noncanonical")
    return value


def decoded_nested_original_v3(value, *, field="", depth=0):
    """Decode each explicitly serialized nested original, never raw prose."""
    if depth > 96:
        raise D04ErasureInventoryHold("D04 original nesting exceeds installed bound")
    if type(value) is str and field.endswith("_json"):
        return decoded_nested_original_v3(_json(value), depth=depth + 1)
    if type(value) is dict:
        return {name: decoded_nested_original_v3(item, field=name, depth=depth + 1)
                for name, item in value.items()}
    if type(value) is list:
        # Root preparation uses the actual SQL tuple wire rather than the
        # appraisal/numeric D04GraphReadV3 object wire.
        if (field == "read_rows" and len(value) == 4 and type(value[0]) is str
                and type(value[1]) is int and type(value[2]) is str and type(value[3]) is int):
            from ..graph_types import AtomKey
            AtomKey.from_token(value[0])
            if value[1] < 0 or value[3] not in (0, 1):
                raise D04ErasureInventoryHold("root frozen SQL read identity differs")
            return {"ref": value[0], "revision": value[1], "value": _json(value[2]), "valid": bool(value[3])}
        return [decoded_nested_original_v3(item, field=field, depth=depth + 1) for item in value]
    return value


def _budget(raw):
    from .budget import BudgetReceipt
    _dto_fields(raw, BudgetReceipt)
    return BudgetReceipt(**raw)


def _cost(raw):
    from .d11_types import RuntimeCostSettlement, _strict_payload
    return _strict_payload(raw, RuntimeCostSettlement)


def _cost_write(raw):
    _fields(raw, ("key", "value", "dependencies"))
    _cost(raw["value"])
    if raw["dependencies"] != []:
        raise D04ErasureInventoryHold("retained D04 CPU cost must have no source dependencies")
    from ..graph_types import AtomKey, Owner
    key = raw["key"]
    _fields(key, ("owner", "type_name", "name"))
    AtomKey(Owner(**key["owner"]), key["type_name"], key["name"])
    if key["type_name"] != "runtime.cost_settlement":
        raise D04ErasureInventoryHold("D04 retained cost write is not an accounting fact")


def _reads(raw):
    from .d04_appraisal_driver_v3 import D04GraphReadV3
    if type(raw) is not list or not raw:
        raise D04ErasureInventoryHold("D04 body original has no frozen read closure")
    refs = set()
    for item in raw:
        _dto_fields(item, D04GraphReadV3)
        read = D04GraphReadV3(**item)
        if read.ref in refs:
            raise D04ErasureInventoryHold("D04 body original has duplicate frozen reads")
        refs.add(read.ref)


def _accounting_prepared(raw, *, root=False):
    if root:
        from .d04_root_accounting_prepared_v3 import decode_root_accounting_prepared_payload_v3
        return decode_root_accounting_prepared_payload_v3(raw)[0]
    from .d04_numeric_accounting_prepared_v3 import decode_numeric_accounting_prepared_payload_v3
    return decode_numeric_accounting_prepared_payload_v3(raw).binding


def validate_d04_original_payload_v3(kind, raw):
    """Validate fixed fields before the caller may preserve or erase any row."""
    if kind not in BODY_KINDS | FACT_KINDS:
        raise D04ErasureInventoryHold("unclassified installed D04 original kind: " + str(kind))
    if kind in SERIES_BODY_KINDS | SERIES_FACT_KINDS:
        from .c09_d04_series_originals_v1 import validate_d04_series_original_payload_v1
        return validate_d04_series_original_payload_v1(kind, raw)
    from .d04_appraisal_driver_v3 import D04AppraisalOriginalV3, D04AppraisalAcceptanceV3
    from .d04_numeric_cost_v3 import D04NumericPreparedV3, D04NumericCostOriginalV3
    from ..authority_service.d04_numeric_contract_v3 import (
        D04NumericBindingV3, D04NumericClaimV3, D04NumericMeasurementV3, D04NumericTerminalV3, from_wire,
    )
    if kind == "appraisal":
        names=set(D04AppraisalOriginalV3.__dataclass_fields__)
        if 'role_support_manifest' not in raw:names.remove('role_support_manifest')
        _fields(raw,names,'d04.paid_appraisal_original.v3')
        if raw.get('role_support_manifest') is not None:
            from .d04_ordinary_readout_v3 import validate_d04_role_manifest_wire_v3
            validate_d04_role_manifest_wire_v3(raw['role_support_manifest'],NamespaceId(**raw['namespace']))
        from ..model_broker.d04_appraisal import thaw_appraisal_request_v1
        thaw_appraisal_request_v1(_json(raw["frozen_json"]))
        _reads(raw["read_rows"])
    elif kind == "appraisal_acceptance":
        names=set(D04AppraisalAcceptanceV3.__dataclass_fields__)
        if 'role_support_manifest' not in raw:names.remove('role_support_manifest')
        _fields(raw,names,'d04.appraisal_acceptance_original.v3')
        if raw.get('role_support_manifest') is not None:
            from .d04_ordinary_readout_v3 import validate_d04_role_manifest_wire_v3
            validate_d04_role_manifest_wire_v3(raw['role_support_manifest'],NamespaceId(**raw['namespace']))
        _reads(raw["read_rows"])
    elif kind == "appraisal_request":
        from .natural_reply_job_v2 import _request_from_wire
        _fields(raw, ("envelope", "call_id", "provider_id", "model_id", "required_capabilities",
            "privacy_tier", "prompt_template_digest", "payload", "timeout_seconds", "max_output_tokens"))
        _request_from_wire(canonical_serialize(raw))
    elif kind == "appraisal_result":
        from ..authority_service.current_d04_appraisal_v3 import D04AppraisalResultReadV3, from_wire as result_from_wire
        result_from_wire(raw, D04AppraisalResultReadV3)
    elif kind == "appraisal_result_attempt":
        from ..authority_service.current_d04_appraisal_v3 import D04AppraisalResultReadRequestV3, from_wire as result_from_wire
        result_from_wire(raw, D04AppraisalResultReadRequestV3)
    elif kind == "appraisal_call":
        from ..authority_service.v2_model_egress_contract import ModelEgressIntentV1
        from ..authority_service.v2_model_egress_wire import from_wire as model_from_wire
        _dto_fields(raw, ModelEgressIntentV1); model_from_wire(raw, ModelEgressIntentV1)
    elif kind in {"appraisal_cost", "appraisal_cost_partial"}:
        _fields(raw, ("schema", "prepared_digest", "result_original_ref", "result_original_digest", "cost_ref",
            "cost_value", "budget_receipt", "paid", "unknown_dimensions"), "d04.appraisal-paid-result.v3")
        _budget(raw["budget_receipt"]); _cost(raw["cost_value"])
    elif kind == "semantic_mapping":
        _fields(raw, ("schema", "namespace", "dose_policy", "signed_budget_grant", "dose_policy_authority",
            "appraisal_acceptance_ref", "appraisal_acceptance_digest", "mapping_installation", "mapping_installation_digest",
            "role", "condition", "clock", "interpretation_level", "mapping_candidate", "family_candidates",
            "read_rows", "source_family_by_ref", "unknown_fields", "output_writes",
            *(("role_support_manifest",)if "role_support_manifest"in raw else())), "d04.semantic_mapping_acceptance.v3")
        _reads(raw["read_rows"])
        if raw.get('role_support_manifest') is not None:
            manifest=raw['role_support_manifest']
            if manifest.get('purpose')=='consolidation' and manifest.get('schema')in {'d06.ordinary-role-support-manifest.v3','d06.ordinary-role-support-manifest.v4'}:
                        c09_life_role_manifest_metadata_v4(manifest,NamespaceId(**raw['namespace']))
            else:
                from .d04_ordinary_readout_v3 import validate_d04_role_manifest_wire_v3
                validate_d04_role_manifest_wire_v3(manifest,NamespaceId(**raw['namespace']))
    elif kind == "joint_evidence_payloads":
        from .d04_semantic_mapping_v3 import D04ProductEvidencePayloadsV3
        _dto_fields(raw, D04ProductEvidencePayloadsV3, "d04.product-evidence-payloads.v3")
        _reads(raw["inputs"]["read_rows"])
    elif kind == "numeric_prepared":
        _dto_fields(raw, D04NumericPreparedV3, "d04.numeric_prepared_original.v3")
        binding = from_wire(raw["binding"], D04NumericBindingV3)
        if canonical_digest(_json(raw["input_payload_json"])) != binding.input_digest:
            raise D04ErasureInventoryHold("numeric preparation input commitment differs")
        _reads(_json(raw["input_payload_json"])["read_rows"])
    elif kind == "numeric_artifact":
        from .d04_numeric_artifact_v3 import decode_d04_numeric_artifact_v3
        decode_d04_numeric_artifact_v3(raw)
    elif kind == "numeric_claim":
        from_wire(raw, D04NumericClaimV3)
    elif kind == "numeric_measurement":
        _fields(raw, ("binding", "claim", "measurement"))
        binding = from_wire(raw["binding"], D04NumericBindingV3)
        claim = from_wire(raw["claim"], D04NumericClaimV3)
        measured = from_wire(raw["measurement"], D04NumericMeasurementV3)
        if measured.binding_digest != binding.digest or claim.binding_digest != binding.digest or measured.claim_id != claim.claim_id:
            raise D04ErasureInventoryHold("numeric measurement binding/claim differs")
    elif kind == "numeric_terminal":
        from_wire(raw, D04NumericTerminalV3)
    elif kind == "numeric_cost":
        _dto_fields(raw, D04NumericCostOriginalV3, "d04.numeric_paid_original.v3")
        NamespaceId(**raw["namespace"]); _budget(_json(raw["budget_receipt_json"])); _cost_write(_json(raw["cost_write_json"]))
    elif kind in {"numeric_accounting_prepared", "root_accounting_prepared"}:
        _accounting_prepared(raw, root=kind.startswith("root"))
    elif kind == "numeric_accounting_gate":
        from ..authority_service.d04_numeric_accounting_v3 import numeric_accounting_from_wire_v3
        numeric_accounting_from_wire_v3(raw)
    elif kind == "numeric_adoption_bridge":
        from ..authority_service.d04_numeric_claim_bridge_v3 import D04NumericAdoptionBridgeV3, numeric_bridge_from_wire_v3
        numeric_bridge_from_wire_v3(raw, D04NumericAdoptionBridgeV3)
    elif kind == "numeric_adoption":
        _fields(raw, ("schema", "status", "operation_id", "binding_digest", "terminal_digest", "output_original_digest",
            "bundle_digest", "graph_receipt_digest", "graph_epoch", "actual_cpu_ns", "actual_cpu_ms"), "d04.numeric-adoption-receipt.v3")
    elif kind == "numeric_execution_closure":
        _fields(raw, ("schema", "operation_id", "binding_digest", "terminal_digest", "execution_status", "adoption_status",
            "actual_cpu_ns", "actual_cpu_ms", "job_status"), "d04.numeric-execution-closure.v3")
    elif kind == "numeric_historical_cost":
        _fields(raw, ("schema", "status", "operation_id", "binding_digest", "terminal_digest", "cost_original_digest",
            "event_id", "graph_receipt_digest", "adoption_status", "job_closure", "actual_cpu_ns", "actual_cpu_ms"),
            "d04.numeric-historical-cost-receipt.v3")
        validate_d04_original_payload_v3("numeric_execution_closure", raw["job_closure"])
    elif kind == "c02_interpretation":
        _fields(raw, ("schema", "policy", "c02_operation_id", "c02_receipt_digest", "source_ref", "source_revision",
            "perspective_ref", "proposal_digest", "graph_receipt_digest"), "d07.c02_presence_original.v1")
    elif kind == "appraisal_scope":
        _fields(raw, ("scope_digest",))
    elif kind == "appraisal_no_supported_meaning":
        _fields(raw, ("prepared_digest", "result_digest", "suggestion_digest"))
    elif kind == "stage_refusal":
        _fields(raw, ("schema", "status", "operation_id", "attempt_id", "stage", "request_digest", "reason",
            "permit_digest", "anchor_digest", "graph_revision", "graph_epoch"), "d04.installed-stage-refusal.v3")
        if (raw["status"] != "held" or raw["reason"] not in {"ValueError", "TypeError", "StaleRead"}
                or raw["stage"] not in {"interpretation", "prepare", "acquire", "settle", "adopt", "drive", "numeric_prepare", "c04_encoding"}):
            raise D04ErasureInventoryHold("D04 refusal is not a fixed content-free failure fact")
    elif kind == "root_prepared":
        from .d04_root_execution_v3 import D04RootPreparedExecutionV3
        from ..authority_service.d04_root_execution_contract_v3 import D04RootExecutionBindingV3, root_execution_from_wire_v3
        _dto_fields(raw, D04RootPreparedExecutionV3, "d04.authored-root-prepared.v3")
        binding = root_execution_from_wire_v3(raw["binding"], D04RootExecutionBindingV3)
        if canonical_digest(_json(raw["input_payload_json"])) != binding.input_digest:
            raise D04ErasureInventoryHold("root preparation input commitment differs")
    elif kind == "root_artifact":
        from ..domains.d04.authored_root_recovery_v3 import decode_authored_root_math_artifact_v3
        decode_authored_root_math_artifact_v3(raw)
    elif kind in {"root_claim", "root_measurement", "root_terminal"}:
        from ..authority_service.d04_root_execution_contract_v3 import (
            D04RootExecutionClaimV3, D04RootExecutionMeasurementV3, D04RootExecutionTerminalV3, root_execution_from_wire_v3,
        )
        root_execution_from_wire_v3(raw, {"root_claim": D04RootExecutionClaimV3,
            "root_measurement": D04RootExecutionMeasurementV3, "root_terminal": D04RootExecutionTerminalV3}[kind])
    elif kind == "root_adoption_bridge":
        from ..authority_service.d04_root_execution_bridge_v3 import D04RootAdoptionBridgeV3, root_bridge_from_wire_v3
        root_bridge_from_wire_v3(raw, D04RootAdoptionBridgeV3)
    elif kind == "root_cost":
        _fields(raw, ("schema", "binding_digest", "prepared_digest", "terminal_digest", "operation_id", "status",
            "actual_cpu_ns", "actual_cpu_ms", "settlement_json", "graph_write_json"), "d04.authored-root-cost.v3")
        _budget(_json(raw["settlement_json"])); _cost_write(_json(raw["graph_write_json"]))
        if (raw["status"] not in {"completed", "failed"} or type(raw["actual_cpu_ns"]) is not int
                or raw["actual_cpu_ns"] < 0 or raw["actual_cpu_ms"] != (raw["actual_cpu_ns"] + 999999) // 1000000):
            raise D04ErasureInventoryHold("root actual CPU fact has invalid units/status")
    elif kind == "root_execution_link":
        from ..domains.d12.scheme_command import D12SchemeAdoptionReceiptV1
        _fields(raw, ("schema", "operation_id", "binding_digest", "prepared_digest", "terminal_digest", "artifact_digest",
            "cost_original_digest", "freeze_digest", "root_original_digest", "head_event_session", "root_event_session",
            "head_receipt_digest", "root_receipt_digest", "adoption_receipt", "graph_revision", "graph_epoch"),
            "d04.authored-root-execution-link.v3")
        _dto_fields(raw["adoption_receipt"], D12SchemeAdoptionReceiptV1)
        if (raw["head_event_session"] != "d12.scheme_adoption.v1" or raw["root_event_session"] != "d04.authored_root.v3"
                or raw["adoption_receipt"]["status"] != "coordinator_committed_scheme"):
            raise D04ErasureInventoryHold("root exact two-event adoption fact differs")
    elif kind == "root_accounting_gate":
        from ..authority_service.d04_root_accounting_v3 import root_accounting_from_wire_v3
        root_accounting_from_wire_v3(raw)
    elif kind == "root_historical_cost":
        _fields(raw, ("schema", "operation_id", "binding_digest", "original_digest", "cost_original_digest", "event_id",
            "graph_receipt_digest", "adoption_status", "execution_status", "actual_cpu_ns", "actual_cpu_ms"),
            "d04.authored-root-historical-cost.v3")
        if raw["adoption_status"] != "not_adopted" or raw["execution_status"] not in {"completed", "failed"}:
            raise D04ErasureInventoryHold("root historical CPU cannot claim mathematical adoption")
    else:
        # New root artifact/cost wire formats must be installed explicitly when
        # their writer is integrated. Naming a kind is not an empty proof.
        raise D04ErasureInventoryHold("D04 kind has no installed wire codec: " + kind)
    decoded_nested_original_v3(raw)
    return raw


def read_d04_inventory_row_v3(columns, row, *, authority_namespace=None):
    if tuple(columns) != COLUMNS:
        raise D04ErasureInventoryHold("installed D04 original table columns differ")
    bot, persona, kind, ref, payload, committed = row
    NamespaceId(bot, persona)
    raw = _json(payload)
    if canonical_digest(raw) != committed:
        raise D04ErasureInventoryHold("D04 original payload commitment differs")
    try:
        validate_d04_original_payload_v3(kind, raw)
    except D04ErasureInventoryHold:
        raise
    except (ValueError, TypeError, KeyError, AttributeError) as exc:
        # Installed fixed codecs expose their own strict validation errors.
        # The inventory boundary always reports a HOLD, never leaks a codec
        # error into a caller that could misclassify the row as an absence.
        raise D04ErasureInventoryHold(str(exc)) from exc
    namespace = {"bot_id": bot, "persona_id": persona}
    for body in (raw, raw.get("binding", {}), raw.get("binding", {}).get("numeric", {}),
                 raw.get("request", {}), raw.get("inputs", {})):
        if type(body) is dict and "namespace" in body:
            expected = authority_namespace if type(body["namespace"]) is str else namespace
            if expected is None or body["namespace"] != expected:
                raise D04ErasureInventoryHold("D04 original payload crosses its authenticated row scope")
    return kind, ref, raw, committed


def d04_original_dispositions_v3(columns, rows, *, affected, affected_operations, nested_hits, source_ids, authority_namespace=None):
    """Close body linkage across job/call/preparation/result/artifact originals."""
    originals = [read_d04_inventory_row_v3(columns, row, authority_namespace=authority_namespace) for row in rows]
    links = set(affected) | set(affected_operations)
    removed = set()
    def identities(value):
        if type(value) is dict:
            for name, item in value.items():
                if type(item) is str and (name in {"operation_id", "job_id", "call_id", "original_ref", "appraisal_ref",
                        "root_ref", "root_digest", "predecessor_ref", "predecessor_digest", "numeric_operation_id", "numeric_prepared_digest"}
                        or name.endswith(("_original_ref", "_original_digest", "_prepared_digest", "_binding_digest"))
                        or name in {"prepared_digest", "binding_digest", "input_digest", "result_digest"}):
                    yield item
                elif type(item) in {dict, list}:
                    yield from identities(item)
        elif type(value) is list:
            for item in value:
                yield from identities(item)
    def ordinary_support_hit(raw):
        manifest=raw.get('role_support_manifest')
        if manifest is None:return False
        from ..graph_types import AtomKey
        for head in manifest['support_heads']:
            key=AtomKey.from_token(head['ref'])
            if head['ref'] in affected or key.owner.subject in source_ids:return True
        return False
    while True:
        before = len(removed)
        for index, (kind, ref, raw, committed) in enumerate(originals):
            if kind not in BODY_KINDS or index in removed:
                continue
            body = decoded_nested_original_v3(raw)
            if (ref in links or ordinary_support_hit(raw) or nested_hits(body, affected, source_ids)
                    or set(identities(body)) & links):
                removed.add(index)
                links.update((ref, committed, *identities(body)))
        if len(removed) == before:
            break
    return tuple("derived_removed" if index in removed else "preserved_exact"
                 for index in range(len(originals)))


def c09_life_role_manifest_metadata_v4(raw,namespace):
    """Closed metadata only: ordinary blocks carry claim commitments, never claim text."""
    from .d06_ordinary_readout_v3 import validate_life_role_manifest_wire_v3,LifeOrdinaryReadoutManifestV4
    from .d01_single_event_readout_v4 import single_event_control_versions_v4
    from ..graph_types import AtomKey,GraphVersion
    manifest=validate_life_role_manifest_wire_v3(raw,namespace)
    versions=[GraphVersion(AtomKey.from_token(ref),revision)for ref,revision in
        (manifest.plan_ref,manifest.activation_ref)]
    versions.extend(GraphVersion(AtomKey.from_token(head.ref),head.revision)for head in manifest.support_heads)
    if type(manifest)is LifeOrdinaryReadoutManifestV4:
        versions.extend(single_event_control_versions_v4(manifest.single_event_controls))
        support={head.ref for head in manifest.support_heads if head.valid and head.revision>0
            and AtomKey.from_token(head.ref).type_name=='memory.source'}
        for control in manifest.single_event_controls:
            selector=control.consumer_selector
            if (len(selector)!=3 or NamespaceId.from_key(AtomKey.from_token(selector[0]))!=namespace
                    or AtomKey.from_token(selector[0]).type_name!='memory.episode.v1'
                    or type(selector[1])is not int or selector[1]<1):
                raise D04ErasureInventoryHold('Life V4 actual consumer episode selector differs')
            for digest in (selector[2],control.policy_digest,control.input_digest,control.adoption_digest,
                    control.review_digest,control.scope_digest,control.counter_census_digest):
                if type(digest)is not str or len(digest)!=64 or any(c not in '0123456789abcdef'for c in digest):
                    raise D04ErasureInventoryHold('Life V4 original metadata commitment differs')
            if (not control.policy_ref or not control.input_ref or len(set(control.source_refs))!=len(control.source_refs)
                    or not set(control.source_refs)<=support or len(control.counter_census)>128):
                raise D04ErasureInventoryHold('Life V4 control Source ALL/counter census differs from its actual support')
            for source in control.source_refs:
                key=AtomKey.from_token(source)
                if NamespaceId.from_key(key)!=namespace or key.type_name!='memory.source':
                    raise D04ErasureInventoryHold('Life V4 control Source crossed its registered namespace/type')
            for values,census in ((control.guard_heads,False),(control.counter_census,True)):
                if len({head.ref for head in values})!=len(values):
                    raise D04ErasureInventoryHold('Life V4 historical metadata repeats a guard')
                for head in values:
                    if head.revision==0 and (head.valid or head.cell_id is not None):
                        raise D04ErasureInventoryHold('Life V4 absence guard has a physical member')
                    if census and (head.revision<1 or AtomKey.from_token(head.ref).type_name!='d07.current_interpretation.v1'
                            or (head.semantic_digest is None)!= (not head.valid)):
                        raise D04ErasureInventoryHold('Life V4 counter row differs from its actual metadata census')
    unique={}
    for version in versions:
        if version.key in unique and unique[version.key]!=version.revision:
            raise D04ErasureInventoryHold('Life role manifest repeats a conflicting original version')
        unique[version.key]=version.revision
    return manifest,tuple(GraphVersion(key,revision)for key,revision in sorted(unique.items(),key=lambda item:item[0].token))


def iter_c09_life_role_manifest_links_v4(raw,namespace):
    manifest,versions=c09_life_role_manifest_metadata_v4(raw,namespace)
    yield from (version.key.token for version in versions)
    for origin in manifest.origins:
        yield origin['producing_operation_id']
        for related in origin['related_originals']:
            yield related['original_ref']
            yield related['original_digest']
    from .d06_ordinary_readout_v3 import LifeOrdinaryReadoutManifestV4
    if type(manifest)is LifeOrdinaryReadoutManifestV4:
        for control in manifest.single_event_controls:
            yield control.policy_ref
            yield control.input_ref
            yield control.consumer_selector[0]
            yield from control.source_refs


def verify_c09_life_mapping_manifest_history_v4(build,original,*,meter):
    """The real historical mapping event carries metadata CAS omitted from Body read_rows."""
    if original.family!=TABLE or original.kind!='semantic_mapping':return
    raw=original.payload;manifest=raw.get('role_support_manifest')
    if type(manifest)is not dict or manifest.get('schema')!='d06.ordinary-role-support-manifest.v4':return
    from ..graph_types import AtomKey,Owner
    from ..runtime.c09_paged_sql_v2 import legacy_cell_read_transaction_v2,read_legacy_sql_cell_fragment_v2,read_c09_table_shape_v2
    from hashlib import sha256
    namespace=NamespaceId(**raw['namespace'])
    value,versions=c09_life_role_manifest_metadata_v4(manifest,namespace)
    build.require_current()
    if namespace.as_tuple!=tuple(json.loads(build.scope.graph_namespace)):
        raise D04ErasureInventoryHold('Life V4 mapping historical proof crossed its actual capture namespace')
    expected={(v.key.token,v.revision)for v in versions}
    if not raw['output_writes']:
        raise D04ErasureInventoryHold('Life V4 mapping has no actual immutable drive producer')
    origin=None
    writes=set()
    for write in raw['output_writes']:
        _fields(write,('key','value','dependencies'))
        key_raw=write['key'];_fields(key_raw,('owner','type_name','name'))
        key=AtomKey(Owner(**key_raw['owner']),key_raw['type_name'],key_raw['name'])
        if NamespaceId.from_key(key)!=namespace or key.token in writes:
            raise D04ErasureInventoryHold('Life V4 mapping output repeats or crosses its original namespace')
        spec=build.session._control.maintenance.graph._registry.spec(key.type_name)
        if spec.writer_domain!='d04' or not spec.immutable:
            raise D04ErasureInventoryHold('Life V4 mapping output is not its registered immutable D04 drive')
        spec.validator(write['value'])
        history=meter.read_fixed_row(build.pair.source,'graph_history',
            ('valid','event_bot','event_persona','event_session','event_id'),'token=? AND revision=?',(key.token,1))
        if history is None or history[:3]!=(1,*namespace.as_tuple) or origin is not None and history[3:]!=origin:
            raise D04ErasureInventoryHold('Life V4 mapping writes lost their same-W01 historical producer')
        origin=history[3:];writes.add(key.token)
        shape=read_c09_table_shape_v2(build.pair.source,'graph_history',meter=meter)
        digest=sha256()
        if 'value_cell_id'in shape.columns:
            scope=build.session.begin_source_physical_read_v3(build.pair,meter=meter)
            cell=meter.read_fixed_row(build.pair.source,'graph_history',('value_cell_id',),'token=? AND revision=?',(key.token,1))
            header=scope.read_cell_header_v3(cell[0],meter=meter)
            if header[1]!='canonical-json.ascii.v1' or header[2]!=key.token:
                raise D04ErasureInventoryHold('Life V4 drive physical codec/owner differs')
            meter.require_available(header[4]*2+header[5]*1024+8192)
            root=canonical_digest(('sylanne3.segmented-cell-genesis.v1',cell[0]));offset=0
            for ordinal in range(header[5]):
                segment=scope.read_cell_segment_v3(cell[0],ordinal,meter=meter)
                if segment is None or segment[0]!=offset:
                    raise D04ErasureInventoryHold('Life V4 drive physical Source order differs')
                digest.update(segment[1]);root=canonical_digest(('sylanne3.segmented-cell-link.v1',
                    root,cell[0],ordinal,offset,len(segment[1]),segment[2]));offset+=len(segment[1])
            scope.require_cell_eof_v3(cell[0],header[5],meter=meter)
            if (offset,root,digest.hexdigest())!=(header[4],header[7],header[6]):
                raise D04ErasureInventoryHold('Life V4 drive physical Source SHA/root/EOF differs')
        else:
            with legacy_cell_read_transaction_v2(build.pair.source):
                _,total,kind=read_legacy_sql_cell_fragment_v2(build.pair.source,table='graph_history',column='value',
                    where='token=? AND revision=?',parameters=(key.token,1),start=0,length=0,meter=meter)
                if kind!='text':raise D04ErasureInventoryHold('Life V4 drive native Source codec differs')
                meter.require_available(total*2+8192);offset=0
                while offset<total:
                    block,size,kind=read_legacy_sql_cell_fragment_v2(build.pair.source,table='graph_history',column='value',
                        where='token=? AND revision=?',parameters=(key.token,1),start=offset,length=min(4096,total-offset),meter=meter)
                    if kind!='text' or size!=total or not block:raise D04ErasureInventoryHold('Life V4 drive native Source EOF changed')
                    digest.update(block);offset+=len(block)
        if digest.hexdigest()!=canonical_digest(write['value']):
            raise D04ErasureInventoryHold('Life V4 drive historical value differs from its complete mapping original')
    event=meter.read_fixed_row(build.pair.source,'graph_events',('reads','revisions','digest','epoch_revision'),
        'bot=? AND persona=? AND session=? AND event_id=?',(*namespace.as_tuple,*origin))
    bundle=meter.read_fixed_row(build.pair.source,'graph_bundle_operations',('digest','activity_id','effect_id','commit_seq'),
        'bot=? AND persona=? AND operation_id=?',(*namespace.as_tuple,origin[1]))
    if event is None or bundle is None or bundle[1]!=origin[0] or bundle[3]<1 or event[3]<1:
        raise D04ErasureInventoryHold('Life V4 mapping actual W01 event/bundle is absent')
    _require_life_mapping_event_identity_v4(build,original,namespace,origin,event,bundle,meter)
    reads=_json(event[0]);revisions=_json(event[1])
    if (type(reads)is not list or type(revisions)is not list
            or any(type(item)is not list or len(item)!=2 for item in (*reads,*revisions))
            or len({item[0]for item in reads})!=len(reads)
            or not expected<=set(tuple(item)for item in reads)
            or not {(token,1)for token in writes}<=set(tuple(item)for item in revisions)):
        raise D04ErasureInventoryHold('Life V4 original support/control versions are absent from their real historical metadata CAS')
    build.require_current()


def _require_life_mapping_event_identity_v4(build,original,namespace,origin,event,bundle,meter):
    # The actual selected Drive producer uses initial_now_utc for both
    # Frame.now_utc and envelope.source_qualification.learned_at. Graph events
    # persist the digest, not an occurred_at column.
    from .domain_production_original_codec_v1 import ORIGINAL_COLUMNS,decode_domain_production_original_row_v1
    from .domain_production_originals_v1 import _receipt
    from .d06_life_numeric_drive_v1 import OPERATION,decode_life_numeric_drive_original_v1
    from ..contracts import Event,Scope
    from ..domains.d01.production_operations_v1 import plain_v1
    from .c09_paged_sql_v2 import _quote,c09_row_commitment_v2
    db=build.pair.source;key=(*namespace.as_tuple,origin[1])
    header=meter.read_fixed_row(db,'graph_domain_production_originals_v1',
        ('domain','operation_kind'),'bot=? AND persona=? AND operation_id=?',key)
    if header is None:
        if build.prior_view is None:
            raise D04ErasureInventoryHold('Life V4 mapping lacks its exact original producer or authenticated prior certificate')
        # Only this exact already-qualified V4 mapping row can use the existing
        # preservation certificate. A retired Domain Body is never reopened.
        source_key=(*namespace.as_tuple,'semantic_mapping',original.original_ref)
        lengths=db.execute('SELECT '+','.join('length(CAST('+_quote(c)+' AS BLOB))'for c in COLUMNS)
            +' FROM '+TABLE+' WHERE bot=? AND persona=? AND kind=? AND original_ref=?',source_key).fetchone()
        meter.charge_read(8*len(COLUMNS))
        if lengths is None:raise D04ErasureInventoryHold('Life V4 mapping source row disappeared')
        build.session._control.require_c09_retained_arena_v3(meter=meter,
            additional_bytes=sum(n or 0 for n in lengths)*12+32768)
        row=meter.read_fixed_row(db,TABLE,COLUMNS,
            'bot=? AND persona=? AND kind=? AND original_ref=?',source_key)
        if (row[4]!=canonical_serialize(original.payload)or row[5]!=original.original_commitment):
            raise D04ErasureInventoryHold('Life V4 prior mapping changed its complete current source bytes')
        commitment=c09_row_commitment_v2(row)
        proof=build.prior_view.require_target_row_disposition(TABLE,source_key,commitment,meter=meter)
        if proof.disposition!='preserved_exact' or (proof.old_commitment,proof.new_commitment)!=(commitment,commitment):
            raise D04ErasureInventoryHold('Life V4 mapping has no exact previously qualified preservation')
        return
    if header!=('d04',OPERATION):
        raise D04ErasureInventoryHold('Life V4 mapping was not produced by the actual registered Drive operation')
    lengths=db.execute('SELECT '+','.join('length(CAST('+_quote(c)+' AS BLOB))'for c in ORIGINAL_COLUMNS)
        +' FROM graph_domain_production_originals_v1 WHERE bot=? AND persona=? AND operation_id=?',key).fetchone()
    meter.charge_read(8*len(ORIGINAL_COLUMNS))
    if lengths is None:raise D04ErasureInventoryHold('Life V4 actual Drive producer disappeared')
    build.session._control.require_c09_retained_arena_v3(meter=meter,
        additional_bytes=sum(n or 0 for n in lengths)*12+32768)
    row=meter.read_fixed_row(db,'graph_domain_production_originals_v1',ORIGINAL_COLUMNS,
        'bot=? AND persona=? AND operation_id=?',key)
    actual=decode_domain_production_original_row_v1(row,namespace,
        registry=build.session._control.maintenance.graph._registry)
    payload=_json(row[7]);receipt=_receipt(_json(row[10]))
    drive=decode_life_numeric_drive_original_v1(payload['provenance']['life_numeric_drive_original'])
    from ..graph_types import AtomKey
    expected_writes={(AtomKey.from_token(token),revision)for token,revision in drive.drive_versions}
    if (actual['operation_id']!=origin[1]or actual['operation_kind']!=OPERATION
            or (drive.namespace,drive.operation_id,drive.mapping_ref,drive.mapping_digest)!=(
                namespace,origin[1],original.original_ref,original.original_commitment)
            or plain_v1(drive.clock)!=original.payload['clock']
            or payload['writes']!=original.payload['output_writes']
            or (receipt.status,receipt.operation_id,receipt.activity_id,receipt.operation_digest,receipt.effect_id,receipt.commit_seq)!=(
                'committed',origin[1],origin[0],bundle[0],bundle[2],bundle[3])
            or canonical_digest(receipt)!=row[11]or { (v.key,v.revision)for v in receipt.write_versions}!=expected_writes
            or { (v.key.token,v.revision)for v in receipt.read_versions}!=set(tuple(v)for v in _json(event[0]))
            or len(receipt.invalidated_epochs)!=1 or receipt.invalidated_epochs[0].revision!=event[3]
            or event[2]!=Event(Scope(*namespace.as_tuple,origin[0]),origin[1],payload['now_utc'],
                'domain_bundle',{'bundle_digest':bundle[0]}).digest):
        raise D04ErasureInventoryHold('Life V4 mapping changed its actual Drive clock/receipt/event/full write membership')
