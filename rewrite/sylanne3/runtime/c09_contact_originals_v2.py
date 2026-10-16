"""Exact C09 body/fact closure for the installed proactive paid model pair."""
from dataclasses import fields
import json
import sqlite3
from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize
from ..domains.d01.production_operations_v1 import plain_v1
from .contact_paid_original_v2 import TABLE, SIGN_KIND, KINDS, install_contact_original_schema_v2
from .c09_d07_execution_v1 import _json, _fields, _digest, decoded_nested_d07_original_v1

COLUMNS = ("bot", "persona", "kind", "original_ref", "payload_json", "payload_digest", "signature")
BODY_KINDS = frozenset({"prepared", "request", "result", "read_attempt", "stage_receipt"})
FACT_KINDS = KINDS - BODY_KINDS


def validate_contact_payload_v2(kind, raw):
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    from .contact_model_job_v2 import decode_contact_prepared_v2, thaw_contact_request_v2
    from ..domains.d08.contact_plan_v2 import decode_contact_plan_v2
    from ..domains.d09.natural_reply import NaturalExpressionPlanV2
    from ..authority_service.contact_model_result_contract_v2 import ContactModelResultReadRequestV2, ContactModelResultReadV2, contact_result_from_wire_v2
    if kind not in KINDS:
        raise ValueError("unregistered contact original C09 kind")
    if kind == "prepared":
        from dataclasses import asdict
        prepared = decode_contact_prepared_v2(raw)
        frozen = thaw_contact_request_v2(_json(prepared.frozen_json))
        if canonical_digest(plain_v1(frozen)) != prepared.frozen_digest or frozen.phase != prepared.phase:
            raise ValueError("contact body preparation frozen commitment differs")
    elif kind == "accounting_prepared":
        _fields(raw, ("schema", "namespace", "contact_id", "job_id", "call_id", "prepared_digest", "prepare_operation_id", "acquire_operation_id",
            "quote_id", "quote_version", "quote_digest", "reservation_digest", "work_kind", "activity_id", "parent_budget_lease_id"),
            "d10.contact-model-accounting-prepared.v2")
        NamespaceId(**raw["namespace"])
        from ..authority_service.contract import identifier
        for name in ('contact_id','job_id','call_id','prepare_operation_id','acquire_operation_id','quote_id','activity_id','parent_budget_lease_id'):
            identifier(raw[name],name)
        if not raw['contact_id'].startswith('contact:') or not raw['job_id'].startswith('contact-model-job-v2:'):
            raise ValueError('Contact V2 accounting locators differ')
        if raw["work_kind"] not in {"contact_generation", "contact_review"} or type(raw["quote_version"]) is not int or raw["quote_version"] < 1:
            raise ValueError("contact retained accounting identity differs")
        for name in ("prepared_digest", "quote_digest", "reservation_digest"):
            _digest(raw[name])
    elif kind == "prepare_commit":
        _fields(raw, ("schema", "prepared_digest", "receipt_digest", "operation_id"), "d10.contact-model-prepare-commit.v2")
        _digest(raw["prepared_digest"]); _digest(raw["receipt_digest"])
    elif kind == "request":
        _fields(raw, ("schema", "prepared_digest", "request_digest", "worker_fence", "wire"), "d10.contact-model-request.v2")
        from .natural_reply_job_v2 import _request_from_wire
        request = _request_from_wire(raw["wire"])
        if request.identity.phase not in {"contact_generation", "contact_review"} or request.digest != raw["request_digest"]:
            raise ValueError("contact request has another installed model phase")
        _digest(raw["prepared_digest"])
    elif kind == "call":
        from ..authority_service.v2_model_egress_contract import ModelEgressIntentV1
        from ..authority_service.v2_model_egress_wire import from_wire
        from_wire(raw, ModelEgressIntentV1)
    elif kind == "read_attempt":
        contact_result_from_wire_v2(raw, ContactModelResultReadRequestV2)
    elif kind == "result":
        contact_result_from_wire_v2(raw, ContactModelResultReadV2)
    elif kind == "terminal":
        _fields(raw, ("schema", "prepared_digest", "terminal_digest", "output_digest", "result_digest", "cost_ref"), "d10.contact-model-terminal.v2")
        for name in ("prepared_digest", "terminal_digest", "output_digest", "result_digest"):
            _digest(raw[name])
    elif kind == "paid_cost":
        from .budget import BudgetReceipt
        from .d11_types import RuntimeCostSettlement
        _fields(raw, ("schema", "prepared_digest", "terminal_digest", "cost_ref", "cost_value", "budget_receipt", "unknown_dimensions", "cost_operation_id"), "d10.contact-paid-cost-original.v2")
        decode_typed_production_value_v1(raw["budget_receipt"], BudgetReceipt)
        cost = decode_typed_production_value_v1(raw["cost_value"], RuntimeCostSettlement)
        if cost.bundle_operation_id != raw["cost_operation_id"]:
            raise ValueError("contact retained cost actual operation differs")
        for name in ("prepared_digest", "terminal_digest"):
            _digest(raw[name])
    elif kind == "stage_attempt":
        from .restore_anchor import RestoreAnchor
        _fields(raw, ("schema", "job_id", "phase", "request_digest", "attempt_id", "anchor", "graph_revision", "graph_epoch", "prepared_digest"), "d10.contact-stage-attempt.v2")
        RestoreAnchor(**raw["anchor"])
        if raw["phase"] not in {"acquire", "paid_cost", "result_read", "terminal", "seal"}:
            raise ValueError("contact retained stage has another operation")
        _digest(raw["request_digest"]); _digest(raw["prepared_digest"])
    elif kind == "stage_permit":
        from ..authority_service.v2_contract import from_wire
        _fields(raw, ("schema", "attempt_id", "permit"), "d10.contact-stage-permit.v2")
        permit = from_wire(raw["permit"])
        if permit.operation != "write" or permit.operation_id != raw["attempt_id"]:
            raise ValueError("contact retained stage permit identity differs")
    else:
        _fields(raw, ("schema", "prepared_digest", "operation_id", "attempt_id", "result"), "d10.contact-stage-receipt.v2")
        _digest(raw["prepared_digest"])
        result = raw["result"]
        if result.get("schema") == "d10.contact-model-result-read.v2":
            contact_result_from_wire_v2(result, ContactModelResultReadRequestV2)
        elif result.get("schema") == "d10.contact-paid-cost-original.v2":
            validate_contact_payload_v2("paid_cost", result)
        elif result.get("status") == "acquired":
            _fields(result, ("status", "job_id", "request_digest")); _digest(result["request_digest"])
        elif result.get('status') == 'sealed':
            _fields(result,('status','job_id','intent_digest')); _digest(result['intent_digest'])
        elif result.get("status") == "completed":
            _fields(result, ("status", "job_id", "output_digest", "graph_receipt_digest"))
            _digest(result["output_digest"]); _digest(result["graph_receipt_digest"])
        else:
            raise ValueError("contact retained stage result has unclassified content")
    return raw


def read_contact_inventory_row_v2(columns, row, *, authority_namespace=None, issuer=None):
    if tuple(columns) != COLUMNS or len(row) != len(COLUMNS):
        raise ValueError("contact original table installed columns differ")
    bot, persona, kind, ref, encoded, digest, signature = row
    namespace = NamespaceId(bot, persona)
    raw = _json(encoded)
    _digest(digest); _digest(signature)
    if canonical_digest(raw) != digest:
        raise ValueError("contact original exact byte commitment differs")
    validate_contact_payload_v2(kind, raw)
    if issuer is not None:
        issuer._signer.verify(SIGN_KIND, canonical_serialize((namespace, kind, ref, digest)), signature)
    if kind == "prepared" and raw["namespace"] != plain_v1(namespace):
        raise ValueError("contact actual prepared row crossed namespace")
    return kind, ref, raw, digest


def contact_original_dispositions_v2(columns, rows, *, affected, affected_operations, nested_hits, source_ids, authority_namespace=None, issuer=None):
    originals = [read_contact_inventory_row_v2(columns, row, authority_namespace=authority_namespace, issuer=issuer) for row in rows]
    links, removed = set(affected) | set(affected_operations), set()
    def identities(raw):
        if type(raw) is dict:
            for name, value in raw.items():
                if name in {"job_id", "call_id", "prepared_digest", "binding_digest", "producing_operation_id", "plan_original_digest", "contact_id", "model_request_digest"} and type(value) is str:
                    yield value
                elif type(value) in (list, dict):
                    yield from identities(value)
        elif type(raw) is list:
            for value in raw:
                yield from identities(value)
    while True:
        before = len(removed)
        for index, (kind, ref, raw, digest) in enumerate(originals):
            if index in removed or kind not in BODY_KINDS:
                continue
            body = decoded_nested_d07_original_v1(raw)
            if ref in links or nested_hits(body, affected, source_ids) or set(identities(body)) & links:
                removed.add(index); links.update((ref, digest, *identities(body)))
        if len(removed) == before:
            break
    accounts = {ref: raw for kind, ref, raw, _ in originals if kind == "accounting_prepared"}
    calls = {ref: raw for kind, ref, raw, _ in originals if kind == "call"}
    account_digests = {raw["prepared_digest"]: raw for raw in accounts.values()}
    attempts = {ref: raw for kind, ref, raw, _ in originals if kind == "stage_attempt"}
    for kind, ref, raw, _ in originals:
        if kind in {"call", "paid_cost", "terminal", "prepare_commit"}:
            account = accounts.get(ref)
            if account is None:
                raise ValueError("contact retained actual fact lost its accounting preparation")
            if kind == "call":
                if (raw["job_id"], raw["call_id"], raw["binding_digest"], raw["budget_reservation_operation_id"], raw["budget_reservation_digest"]) != (
                        account["job_id"], account["call_id"], account["prepared_digest"], account["prepare_operation_id"], account["reservation_digest"]):
                    raise ValueError("contact retained call differs from its actual once reservation")
            elif raw["prepared_digest"] != account["prepared_digest"] or kind in {"paid_cost", "terminal"} and ref not in calls:
                raise ValueError("contact retained paid fact differs from actual call binding")
        elif kind == "stage_attempt":
            account = account_digests.get(raw["prepared_digest"])
            if account is None or account["job_id"] != raw["job_id"]:
                raise ValueError("contact stage lost its actual accounting preparation")
        elif kind in {"stage_permit", "stage_receipt"}:
            attempt = attempts.get(ref)
            if attempt is None or raw["attempt_id"] != attempt["attempt_id"]:
                raise ValueError("contact stage completion lost its exact durable attempt")
            if kind == "stage_receipt" and (raw["prepared_digest"] != attempt["prepared_digest"] or raw["operation_id"] != ref):
                raise ValueError("contact stage receipt identity differs from its actual attempt")
    return tuple("derived_removed" if index in removed else "preserved_exact" for index in range(len(rows)))


def decode_contact_preparation_provenance_v2(raw):
    """Decode the one real queued-job preparation variant before erasure walks it."""
    from dataclasses import asdict
    from .contact_model_job_v2 import decode_contact_prepared_v2, thaw_contact_request_v2, contact_model_ids_v2
    from .jobs import PersistentJob
    from datetime import datetime, timezone
    from .domain_production_erasure_v1 import _references
    _fields(raw, ("prepared", "frozen", "job"))
    prepared = decode_contact_prepared_v2(raw["prepared"])
    frozen = thaw_contact_request_v2(raw["frozen"])
    _fields(raw["job"], tuple(field.name for field in fields(PersistentJob)))
    job = PersistentJob(**raw["job"])
    plan = frozen.input.adopted_plan
    ids = contact_model_ids_v2(plan, prepared.phase)
    if (plain_v1(job) != raw["job"] or canonical_serialize(raw["frozen"]) != prepared.frozen_json
            or canonical_digest(plain_v1(frozen)) != prepared.frozen_digest
            or frozen.phase != prepared.phase or plan.namespace != prepared.namespace
            or (plan.contact_id, plan.activity_id) != (prepared.contact_id, prepared.activity_id)
            or (job.job_id, job.operation_id, job.activity_id, job.bot_id, job.persona_id, job.work_kind, job.phase) !=
               (ids["job"], ids["prepare"], plan.activity_id, *prepared.namespace.as_tuple, prepared.phase, "queued")
            or (prepared.job_id, prepared.prepare_operation_id, prepared.acquire_operation_id, prepared.call_id) !=
               (ids["job"], ids["prepare"], ids["acquire"], ids["call"])
            or job.continuation != {"contact_id": plan.contact_id, "plan_id": plan.plan_id}
            or job.operator_versions != {"resource_quote": prepared.quote_id + ":" + str(prepared.quote_version)}
            or job.wake_condition is not None or job.usage or job.lease_holder is not None or job.lease_expires_utc is not None
            or job.fence != 0 or job.budget_ref != plan.parent_budget_lease_id or job.effect_id is not None
            or job.result_ref is not None or job.cancel_epoch != plan.cancellation_epoch
            or job.snapshot_ref != ids["snapshot"] or job.resource_ref != prepared.provider_config_ref
            or job.deadline_utc != datetime.fromtimestamp(plan.valid_until_utc, timezone.utc).isoformat().replace("+00:00", "Z")):
        raise ValueError("contact preparation provenance differs from the actual fixed queued model job")
    return tuple(sorted(set(_references(raw)) | {row.key.token for row in plan.qualified_read_versions}))


def validate_contact_schema_v2(db):
    with sqlite3.connect(":memory:") as expected:
        install_contact_original_schema_v2(expected)
        actual = tuple(db.execute("SELECT type,name,sql FROM sqlite_master WHERE tbl_name=? AND sql IS NOT NULL ORDER BY type,name", (TABLE,)))
        wanted = tuple(expected.execute("SELECT type,name,sql FROM sqlite_master WHERE tbl_name=? AND sql IS NOT NULL ORDER BY type,name", (TABLE,)))
        if actual and actual != wanted:
            raise ValueError("contact original exact installed DDL/index/triggers differ")
    return True
