"""Contact acquire, exact call seal, actual result import and independent cost."""
from .contact_original_read_v3 import contact_original_point_v3
from dataclasses import replace, asdict
from datetime import datetime, timezone
import json
from ..domains.d01.production_operations_v1 import plain_v1
from ..model_broker.broker import ModelCallRequest
from ..model_broker.contact_expression_v2 import (GENERATION_TEMPLATE_DIGEST, REVIEW_TEMPLATE_DIGEST,
    parse_contact_generation_output_v2, parse_contact_review_output_v2)
from ..runtime_contracts import VersionedRef, canonical_digest, canonical_serialize
from ..authority_service.v2_model_egress_wire import to_wire as model_wire, from_wire as model_unwire
from ..authority_service.v2_model_egress_contract import ModelEgressIntentV1, ModelTerminalReceiptV2
from .contact_model_job_v2 import read_contact_prepared_v2, contact_model_ids_v2
from .contact_plan_adoption_v2 import read_adopted_contact_plan_v2
from .contact_paid_original_v2 import record_contact_original_v2, require_contact_original_v2, read_contact_original_v2
from .jobs import get_job, acquire_job, transition_job
from .d11_types import job_graph_write, cost_settlement_from_runtime, cost_settlement_graph_write
from .model_cost_settlement import (OriginalModelCostFactV1, original_model_cost_operation_id_v1,
    original_model_budget_measurement, prepare_original_model_cost_plan, apply_original_model_budget_in_transaction)
from .reply_model_job import reply_request_wire_v1


def acquire_contact_model_in_transaction_v2(db, *, envelope, prepared, issuer, installed_bundle, now_utc, lease_seconds):
    from ..authority_service.contact_model_graph_v2 import require_contact_scope_current_v2
    if not db.in_transaction:
        raise ValueError("contact acquire requires actual W01 business transaction")
    actual, frozen = read_contact_prepared_v2(db, namespace=prepared.namespace, job_id=prepared.job_id, issuer=issuer)
    if actual != prepared or envelope.identity.operation_id != prepared.acquire_operation_id or envelope.identity.phase != prepared.phase:
        raise ValueError("contact acquire cannot change its frozen once identity")
    plan, expression, _, _ = read_adopted_contact_plan_v2(db, namespace=prepared.namespace, contact_id=prepared.contact_id, issuer=issuer)
    require_contact_scope_current_v2(db, plan, expression, now=now_utc)
    workflow = getattr(installed_bundle.model_workflows, prepared.phase)
    if (envelope.authority.namespace != prepared.namespace or envelope.identity.activity_id != prepared.activity_id
            or envelope.authority.audience != (plan.audience_id,) or envelope.authority.purpose != "proposal"
            or envelope.parent_budget_lease_ref != plan.parent_budget_lease_id
            or workflow.provider_config_digest != frozen.installation.provider_config_digest
            or workflow.provider_config_ref != prepared.provider_config_ref):
        raise ValueError("contact actual acquire scope differs from its installed original")
    prior = read_contact_original_v2(db, issuer, prepared.namespace, "request", prepared.job_id)
    if prior is not None:
        from .natural_reply_job_v2 import _request_from_wire
        request = _request_from_wire(prior[0]["wire"])
        job = get_job(db, prepared.job_id)
        if job.phase != "running" or job.fence != request.envelope.authority.worker_fence or job.lease_holder != envelope.authority.actor:
            raise ValueError("contact prior once worker cannot be reacquired after retirement")
        return job, request, ()
    job = acquire_job(db, prepared.job_id, envelope.authority.actor,
        now_utc=datetime.fromtimestamp(now_utc, timezone.utc).isoformat().replace("+00:00", "Z"), lease_seconds=lease_seconds)
    guard = replace(envelope.version_guard, resource_lease_versions=(VersionedRef(prepared.quote_id, prepared.quote_version),))
    actual_envelope = replace(envelope, authority=replace(envelope.authority, worker_fence=job.fence),
        version_guard=guard, deadline_utc=min(envelope.deadline_utc, plan.valid_until_utc))
    request = ModelCallRequest(actual_envelope, prepared.call_id, workflow.provider_id, workflow.model_id,
        frozenset(workflow.required_capabilities), workflow.privacy_tier,
        GENERATION_TEMPLATE_DIGEST if prepared.phase == "contact_generation" else REVIEW_TEMPLATE_DIGEST,
        json.loads(frozen.wire_json), workflow.timeout_seconds, workflow.max_output_tokens)
    record_contact_original_v2(db, issuer, prepared.namespace, "request", prepared.job_id,
        {"schema": "d10.contact-model-request.v2", "prepared_digest": prepared.digest,
         "request_digest": request.digest, "worker_fence": job.fence,
         "wire": canonical_serialize(reply_request_wire_v1(actual_envelope, request))})
    return job, request, (job_graph_write(job),)


def seal_contact_call_in_transaction_v2(db, *, prepared, issuer, intent):
    request, _ = require_contact_original_v2(db, issuer, prepared.namespace, "request", prepared.job_id)
    if (type(intent) is not ModelEgressIntentV1 or intent.job_id != prepared.job_id
            or intent.call_id != prepared.call_id or intent.binding_digest != prepared.digest
            or intent.acquire_operation_id != prepared.acquire_operation_id or intent.operation_id != prepared.acquire_operation_id
            or intent.request_digest != request["request_digest"] or intent.worker_fence != request["worker_fence"]
            or intent.budget_reservation_operation_id != prepared.prepare_operation_id
            or intent.budget_reservation_digest != prepared.reservation_digest):
        raise ValueError("contact Authority original differs from actual prepared request and reservation")
    return record_contact_original_v2(db, issuer, prepared.namespace, "call", prepared.job_id, model_wire(intent))


def settle_contact_model_cost_in_transaction_v2(db, *, prepared, fact, issuer, resource_issuer):
    if not db.in_transaction or type(fact) is not OriginalModelCostFactV1:
        raise ValueError("contact settlement requires actual authenticated terminal facts")
    call, _ = require_contact_original_v2(db, issuer, prepared.namespace, "call", prepared.job_id)
    if call != model_wire(fact.intent) or fact.intent.binding_digest != prepared.digest:
        raise ValueError("contact settlement cannot use another model's terminal")
    prior = read_contact_original_v2(db, issuer, prepared.namespace, "paid_cost", prepared.job_id)
    if prior is not None:
        if prior[0]["terminal_digest"] != canonical_digest(asdict(fact.receipt)):
            raise ValueError("contact cost replay changed original terminal")
        return prior[0], ()
    plan = prepare_original_model_cost_plan(db, resource_issuer, prepared.namespace, fact,
        quote_id=prepared.quote_id, quote_version=prepared.quote_version, work_kind=prepared.phase)
    application = apply_original_model_budget_in_transaction(db, resource_issuer, plan, fact)
    known, unknown = original_model_budget_measurement(fact, plan.quote, work_kind=prepared.phase)
    value = {"schema": "d10.contact-paid-cost-original.v2", "prepared_digest": prepared.digest,
        "terminal_digest": canonical_digest(asdict(fact.receipt)), "cost_ref": application.cost_write.key.token,
        "cost_value": application.cost_write.value, "budget_receipt": plain_v1(application.receipt),
        "unknown_dimensions": list(unknown), "cost_operation_id": plan.bundle_operation_id}
    # Unknown actual dimensions are retained by the original D11 settlement.
    # They never authorize review or become a paid whole-batch pass.
    record_contact_original_v2(db, issuer, prepared.namespace, "paid_cost", prepared.job_id, value)
    return value, (application.cost_write,)


def import_contact_result_in_transaction_v2(db, *, prepared, result_read, fact, issuer, resource_issuer, holder, fence, now_utc):
    from ..authority_service.contact_model_result_contract_v2 import ContactModelResultReadV2, contact_result_to_wire_v2
    if type(result_read) is not ContactModelResultReadV2 or type(fact) is not OriginalModelCostFactV1:
        raise TypeError("actual current Authority contact delivery and independent terminal fact required")
    result_read.require_original(fact.intent, prepared)
    if result_read.terminal_receipt != fact.receipt or result_read.observation.digest != fact.receipt.observation_digest:
        raise ValueError("contact delivered body differs from actual terminal accounting")
    paid, cost_writes = settle_contact_model_cost_in_transaction_v2(db, prepared=prepared, fact=fact, issuer=issuer, resource_issuer=resource_issuer)
    if paid["unknown_dimensions"]:
        return paid, cost_writes
    plan, expression, _, _ = read_adopted_contact_plan_v2(db, namespace=prepared.namespace, contact_id=prepared.contact_id, issuer=issuer)
    from ..authority_service.contact_model_graph_v2 import require_contact_scope_current_v2
    from .contact_plan_adoption_v2 import require_contact_inventory_current_v2
    _, _, plan_raw, _ = read_adopted_contact_plan_v2(db, namespace=prepared.namespace, contact_id=prepared.contact_id, issuer=issuer)
    require_contact_inventory_current_v2(db, prepared.namespace, plan_raw)
    require_contact_scope_current_v2(db, plan, expression, now=now_utc)
    if now_utc < result_read.read_at_utc:
        raise ValueError("contact result read time exceeds current trusted adoption clock")
    saved_attempt, _ = require_contact_original_v2(db, issuer, prepared.namespace, "read_attempt", result_read.request.read_attempt_id)
    from ..authority_service.contact_model_result_contract_v2 import contact_result_to_wire_v2
    if saved_attempt != contact_result_to_wire_v2(result_read.request):
        raise ValueError("contact delivered body lacks its actual W01 saved read selector")
    _, frozen = read_contact_prepared_v2(db, namespace=prepared.namespace, job_id=prepared.job_id, issuer=issuer)
    observation = result_read.observation.result
    if type(observation) is not dict or set(observation) != {"text"}:
        raise ValueError("contact provider response is not the installed text result")
    if prepared.phase == "contact_generation":
        candidate = parse_contact_generation_output_v2(observation["text"], frozen)
    else:
        _, _, generation, _ = read_paid_contact_result_v2(db, namespace=prepared.namespace, contact_id=prepared.contact_id,
            phase="contact_generation", issuer=issuer, resource_issuer=resource_issuer)
        candidate = parse_contact_review_output_v2(observation["text"], frozen, generation)
    raw = contact_result_to_wire_v2(result_read)
    record_contact_original_v2(db, issuer, prepared.namespace, "result", prepared.job_id, raw)
    record_contact_original_v2(db, issuer, prepared.namespace, "terminal", prepared.job_id,
        {"schema": "d10.contact-model-terminal.v2", "prepared_digest": prepared.digest,
         "terminal_digest": canonical_digest(asdict(fact.receipt)), "output_digest": candidate.output_digest,
         "result_digest": canonical_digest(raw), "cost_ref": paid["cost_ref"]})
    job = transition_job(db, prepared.job_id, holder, fence, target_phase="completed", result_ref=prepared.call_id)
    return candidate, (*cost_writes, job_graph_write(job))


def read_paid_contact_result_v2(db, *, namespace, contact_id, phase, issuer, resource_issuer):
    from ..authority_service.contact_model_result_contract_v2 import ContactModelResultReadV2, contact_result_from_wire_v2
    plan, expression, _, plan_digest = read_adopted_contact_plan_v2(db, namespace=namespace, contact_id=contact_id, issuer=issuer)
    ids = contact_model_ids_v2(plan, phase)
    prepared, frozen = read_contact_prepared_v2(db, namespace=namespace, job_id=ids["job"], issuer=issuer)
    from .d04_root_original_store_v1 import _receipt
    prepare_commit, _ = require_contact_original_v2(db, issuer, namespace, "prepare_commit", prepared.job_id)
    prepare_receipt = _receipt(db, namespace, prepared.prepare_operation_id)
    raw, _ = require_contact_original_v2(db, issuer, namespace, "result", prepared.job_id)
    result = contact_result_from_wire_v2(raw, ContactModelResultReadV2)
    terminal, _ = require_contact_original_v2(db, issuer, namespace, "terminal", prepared.job_id)
    paid, _ = require_contact_original_v2(db, issuer, namespace, "paid_cost", prepared.job_id)
    original_intent, _ = require_contact_original_v2(db, issuer, namespace, "call", prepared.job_id)
    intent = model_unwire(original_intent, ModelEgressIntentV1)
    result.require_original(intent, prepared)
    job = get_job(db, prepared.job_id)
    quote = resource_issuer.original_signed_quote(db, prepared.quote_id, prepared.quote_version)
    reservation = contact_original_point_v3(db,table='runtime_budget_reservations',columns=('digest', 'ceiling_json', 'state'),key_columns=('lease_id', 'operation_id'),key=(lambda _contact_values: (_contact_values[0],_contact_values[1]))((quote.parent_budget_lease_ref, prepared.prepare_operation_id)),legacy_reader=lambda: db.execute("SELECT digest,ceiling_json,state FROM runtime_budget_reservations WHERE lease_id=? AND operation_id=?",
        (quote.parent_budget_lease_ref, prepared.prepare_operation_id)).fetchone())
    cost = contact_original_point_v3(db,table='graph_atoms',columns=('value', 'valid'),key_columns=('token',),key=(lambda _contact_values: (_contact_values[0],))((paid["cost_ref"],)),legacy_reader=lambda: db.execute("SELECT value,valid FROM graph_atoms WHERE token=?", (paid["cost_ref"],)).fetchone())
    cost_operation = contact_original_point_v3(db,table='graph_bundle_operations',columns=('receipt_json', 'activity_id', 'commit_seq'),key_columns=('bot', 'persona', 'operation_id'),key=(lambda _contact_values: (_contact_values[0],_contact_values[1],_contact_values[2]))((*namespace.as_tuple, paid["cost_operation_id"])),legacy_reader=lambda: db.execute("SELECT receipt_json,activity_id,commit_seq FROM graph_bundle_operations WHERE bot=? AND persona=? AND operation_id=?",
        (*namespace.as_tuple, paid["cost_operation_id"])).fetchone())
    from .budget import _receipt_from_json
    original_budget = contact_original_point_v3(db,table='runtime_budget_operations',columns=('receipt_json',),key_columns=('bot_id', 'persona_id', 'operation_id', 'phase'),key=(lambda _contact_values: (_contact_values[0],_contact_values[1],_contact_values[2],'settle'))((*namespace.as_tuple, prepared.prepare_operation_id)),legacy_reader=lambda: db.execute("SELECT receipt_json FROM runtime_budget_operations WHERE bot_id=? AND persona_id=? AND operation_id=? AND phase='settle'",
        (*namespace.as_tuple, prepared.prepare_operation_id)).fetchone())
    actual_cost_commit = None if cost_operation is None else json.loads(cost_operation[0])
    stored_cost = None if actual_cost_commit is None else actual_cost_commit.get("original_model_cost")
    job_write = job_graph_write(job)
    job_head = contact_original_point_v3(db,table='graph_atoms',columns=('value', 'valid'),key_columns=('token',),key=(lambda _contact_values: (_contact_values[0],))((job_write.key.token,)),legacy_reader=lambda: db.execute("SELECT value,valid FROM graph_atoms WHERE token=?", (job_write.key.token,)).fetchone())
    cost_event = None if cost_operation is None else contact_original_point_v3(db,table='graph_events',columns=('1',),key_columns=('bot', 'persona', 'session', 'event_id'),key=(lambda _contact_values: (_contact_values[0],_contact_values[1],_contact_values[2],_contact_values[3]))((*namespace.as_tuple, cost_operation[1], paid["cost_operation_id"])),legacy_reader=lambda: db.execute("SELECT 1 FROM graph_events WHERE bot=? AND persona=? AND session=? AND event_id=?",
        (*namespace.as_tuple, cost_operation[1], paid["cost_operation_id"])).fetchone())
    if (prepared.plan_original_digest != plan_digest or frozen.input.adopted_plan != plan or frozen.input.expression_plan != expression
            or prepare_commit != {"schema": "d10.contact-model-prepare-commit.v2", "prepared_digest": prepared.digest,
                "receipt_digest": canonical_digest(prepare_receipt), "operation_id": prepared.prepare_operation_id}
            or job_write.key not in {row.key for row in prepare_receipt.write_versions}
            or job_head is None or job_head[1] != 1 or json.loads(job_head[0]) != job_write.value
            or terminal["prepared_digest"] != prepared.digest or paid["prepared_digest"] != prepared.digest
            or terminal["terminal_digest"] != canonical_digest(asdict(result.terminal_receipt))
            or paid["terminal_digest"] != terminal["terminal_digest"] or paid["unknown_dimensions"]
            or terminal["result_digest"] != canonical_digest(raw) or terminal["cost_ref"] != paid["cost_ref"]
            or job.phase != "completed" or job.result_ref != prepared.call_id or job.operation_id != prepared.prepare_operation_id
            or canonical_digest(quote) != prepared.quote_digest or reservation is None
            or reservation[0] != prepared.reservation_digest or json.loads(reservation[1]) != dict(quote.ceiling)
            or reservation[2] != "settled" or cost is None or cost[1] != 1
            or json.loads(cost[0]) != paid["cost_value"] or stored_cost is None or original_budget is None
            or stored_cost["terminal_receipt_digest"] != terminal["terminal_digest"]
            or (stored_cost["call_id"], stored_cost["quote_id"], stored_cost["quote_version"], stored_cost["cost_ref"]) !=
                (prepared.call_id, prepared.quote_id, prepared.quote_version, paid["cost_ref"])
            or plain_v1(_receipt_from_json(original_budget[0])) != paid["budget_receipt"]
            or stored_cost["budget_receipt_digest"] != canonical_digest(asdict(_receipt_from_json(original_budget[0])))
            or actual_cost_commit["original_intent_digest"] != canonical_digest(asdict(intent))
            or stored_cost["status"] != "committed" or stored_cost["commit_seq"] != cost_operation[2] or cost_event is None
            or stored_cost["operation_id"] != paid["cost_operation_id"]
            or paid["cost_operation_id"] != original_model_cost_operation_id_v1(namespace, prepared.call_id)):
        raise ValueError("contact result lacks its actual completed job and independently settled cost")
    if phase == "contact_generation":
        candidate = parse_contact_generation_output_v2(result.observation.result["text"], frozen)
    else:
        _, _, generation, _ = read_paid_contact_result_v2(db, namespace=namespace, contact_id=contact_id,
            phase="contact_generation", issuer=issuer, resource_issuer=resource_issuer)
        candidate = parse_contact_review_output_v2(result.observation.result["text"], frozen, generation)
    if candidate.output_digest != terminal["output_digest"]:
        raise ValueError("contact paid complete output commitment changed")
    _require_contact_completion_graph_original_v2(db, namespace, prepared, candidate, issuer, job_write)
    return prepared, frozen, candidate, paid


def _require_contact_completion_graph_original_v2(db, namespace, prepared, candidate, issuer, job_write):
    from ..graph_types import GraphReceipt, NamespaceEpoch
    from ..graph_store import GraphStore
    operation = "contact-terminal:" + canonical_digest((namespace, prepared.job_id, "terminal"))[:48]
    completed, _ = require_contact_original_v2(db, issuer, namespace, "stage_receipt", operation)
    event = contact_original_point_v3(db,table='graph_events',columns=('revisions', 'invalidated', 'epoch_revision'),key_columns=('bot', 'persona', 'session', 'event_id'),key=(lambda _contact_values: (_contact_values[0],_contact_values[1],_contact_values[2],_contact_values[3]))((*namespace.as_tuple, prepared.activity_id, operation)),legacy_reader=lambda: db.execute("SELECT revisions,invalidated,epoch_revision FROM graph_events WHERE bot=? AND persona=? AND session=? AND event_id=?",
        (*namespace.as_tuple, prepared.activity_id, operation)).fetchone())
    bundle = contact_original_point_v3(db,table='graph_bundle_operations',columns=('receipt_json',),key_columns=('bot', 'persona', 'operation_id'),key=(lambda _contact_values: (_contact_values[0],_contact_values[1],_contact_values[2]))((*namespace.as_tuple, operation)),legacy_reader=lambda: db.execute("SELECT receipt_json FROM graph_bundle_operations WHERE bot=? AND persona=? AND operation_id=?",
        (*namespace.as_tuple, operation)).fetchone())
    if event is None or bundle is None:
        raise ValueError("contact completed job lost its actual Graph operation")
    receipt = GraphReceipt("committed", GraphStore._version_rows(event[0]), GraphStore._version_rows(event[1]),
        NamespaceEpoch(*namespace.as_tuple, event[2]))
    if (completed["operation_id"] != operation or completed["prepared_digest"] != prepared.digest
            or completed["result"] != {"status": "completed", "job_id": prepared.job_id,
                "output_digest": candidate.output_digest, "graph_receipt_digest": canonical_digest(receipt)}
            or json.loads(bundle[0])["graph_receipt_digest"] != canonical_digest(receipt)
            or len(receipt.revisions) != 1 or receipt.revisions[0].key != job_write.key):
        raise ValueError("contact completed signed output differs from its actual Graph receipt")
    history = contact_original_point_v3(db,table='graph_history',columns=('value', 'valid'),key_columns=('token', 'revision', 'event_bot', 'event_persona', 'event_session', 'event_id'),key=(lambda _contact_values: (_contact_values[0],_contact_values[1],_contact_values[2],_contact_values[3],_contact_values[4],_contact_values[5]))((job_write.key.token, receipt.revisions[0].revision, *namespace.as_tuple, prepared.activity_id, operation)),legacy_reader=lambda: db.execute("SELECT value,valid FROM graph_history WHERE token=? AND revision=? AND event_bot=? AND event_persona=? AND event_session=? AND event_id=?",
        (job_write.key.token, receipt.revisions[0].revision, *namespace.as_tuple, prepared.activity_id, operation)).fetchone())
    if history is None or history[1] != 1 or json.loads(history[0]) != job_write.value:
        raise ValueError("contact actual completed job history differs")


def prepare_contact_result_read_in_transaction_v2(db, *, prepared, issuer, intent, attempt):
    from ..authority_service.contact_model_result_contract_v2 import ContactModelResultReadRequestV2, contact_result_to_wire_v2
    if not db.in_transaction or type(attempt) is not int or not 1 <= attempt <= 128:
        raise ValueError("contact result selection requires an actual bounded W01 transaction")
    actual, frozen = read_contact_prepared_v2(db, namespace=prepared.namespace, job_id=prepared.job_id, issuer=issuer)
    call, _ = require_contact_original_v2(db, issuer, prepared.namespace, "call", prepared.job_id)
    request, _ = require_contact_original_v2(db, issuer, prepared.namespace, "request", prepared.job_id)
    paid, _ = require_contact_original_v2(db, issuer, prepared.namespace, "paid_cost", prepared.job_id)
    if actual != prepared or call != model_wire(intent) or paid["unknown_dimensions"] or paid["prepared_digest"] != prepared.digest:
        raise ValueError("contact result selector lacks its exact paid actual once call")
    consumer = "contact-terminal:" + canonical_digest((prepared.namespace, prepared.job_id))[:48]
    read_id = "contact-result-read:" + canonical_digest((consumer, attempt))[:48]
    result = ContactModelResultReadRequestV2(intent.authority_id, intent.namespace, prepared.namespace,
        prepared.installation_id, prepared.contact_id, prepared.phase, prepared.job_id, prepared.acquire_operation_id,
        prepared.prepare_operation_id, prepared.call_id, prepared.digest, request["request_digest"], consumer, read_id)
    if attempt > 1:
        previous_id = "contact-result-read:" + canonical_digest((consumer, attempt - 1))[:48]
        require_contact_original_v2(db, issuer, prepared.namespace, "read_attempt", previous_id)
    record_contact_original_v2(db, issuer, prepared.namespace, "read_attempt", read_id, contact_result_to_wire_v2(result))
    return result


def contact_model_draft_v2(*, prepared, frozen, request, job, metadata, epoch):
    from ..authority_service.v2_model_egress_contract import ModelEgressDraftV1
    plan = frozen.input.adopted_plan
    target = metadata.requirements
    sources = tuple(sorted((row.key.owner.subject, row.revision) for row in plan.qualified_read_versions
        if row.key.type_name == "memory.source" and row.revision > 0))
    access = tuple(sorted((row.key.owner.subject, row.revision) for row in plan.qualified_read_versions
        if row.key.type_name == "memory.access" and row.revision > 0))
    if (job.phase != "running" or job.job_id != prepared.job_id or job.fence != request.envelope.authority.worker_fence
            or request.identity.operation_id != prepared.acquire_operation_id or job.lease_holder != request.envelope.authority.actor):
        raise ValueError("contact egress draft lacks actual acquired original worker")
    ceiling = plan.generation_ceiling if prepared.phase == "contact_generation" else plan.review_ceiling
    return ModelEgressDraftV1(target.authority_id, target.authority_namespace, request.envelope.authority.actor,
        request.identity.operation_id, request.call_id, request.digest, job.job_id, job.fence,
        tuple(ref for ref, _ in sources), sources, access, request.envelope.version_guard.access_epoch,
        request.envelope.version_guard.delete_epoch, epoch.revision, metadata.graph_revision,
        target.activation_generation, target.revocation_epoch, target.deletion_seq, target.execution_seq,
        job.budget_ref, prepared.prepare_operation_id, prepared.reservation_digest, ceiling,
        request.provider_id, request.model_id, frozen.installation.provider_config_digest, request.max_output_tokens,
        acquire_operation_id=prepared.acquire_operation_id, binding_digest=prepared.digest)


def read_paid_contact_batch_original_v2(db, *, namespace, contact_id, issuer, resource_issuer):
    """Authenticate the adopted paid pair; current adoption rights are checked by its installed consumer."""
    if not db.in_transaction:
        raise ValueError("contact paid pair requires one pinned original read transaction")
    plan, expression, _, digest = read_adopted_contact_plan_v2(db, namespace=namespace, contact_id=contact_id, issuer=issuer)
    generation = read_paid_contact_result_v2(db, namespace=namespace, contact_id=contact_id,
        phase="contact_generation", issuer=issuer, resource_issuer=resource_issuer)
    if generation[2].status != "untrusted_content_candidate":
        return None
    review = read_paid_contact_result_v2(db, namespace=namespace, contact_id=contact_id,
        phase="contact_review", issuer=issuer, resource_issuer=resource_issuer)
    generation_prepared, generation_frozen, generated, generation_paid = generation
    review_prepared, review_frozen, reviewed, review_paid = review
    if (generation_prepared.plan_original_digest != digest or review_prepared.plan_original_digest != digest
            or generation_frozen.input != review_frozen.input
            or review_prepared.generation_terminal_digest != generation_paid["terminal_digest"]
            or review_prepared.generation_output_digest != generated.output_digest
            or review_prepared.generation_cost_ref != generation_paid["cost_ref"]
            or review_frozen.generation_output_digest != generated.output_digest
            or generation_prepared.job_id == review_prepared.job_id or generation_prepared.call_id == review_prepared.call_id
            or generation_prepared.prepare_operation_id == review_prepared.prepare_operation_id):
        raise ValueError("contact independent paid review does not bind its exact whole paid generation")
    if review[2].verdict != "pass" or review[2].generation_output_digest != generation[2].output_digest:
        return None
    return plan, expression, generation, review


def read_paid_contact_batch_v2(db, *, namespace, contact_id, issuer, resource_issuer, now_utc):
    from .contact_plan_adoption_v2 import require_contact_inventory_current_v2
    from ..authority_service.contact_model_graph_v2 import require_contact_scope_current_v2
    original = read_paid_contact_batch_original_v2(db, namespace=namespace, contact_id=contact_id,
        issuer=issuer, resource_issuer=resource_issuer)
    plan, expression, raw, _ = read_adopted_contact_plan_v2(db, namespace=namespace, contact_id=contact_id, issuer=issuer)
    require_contact_inventory_current_v2(db, namespace, raw)
    require_contact_scope_current_v2(db, plan, expression, now=now_utc)
    return original
