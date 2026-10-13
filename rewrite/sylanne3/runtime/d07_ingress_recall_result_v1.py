"""Actual scoped Self C3 result and routing adoption through foreground W01."""
from dataclasses import dataclass, replace, asdict
import json

from ..domains.d01.production_operations_v1 import plain_v1, stage_result_v1
from ..runtime_contracts import canonical_digest, canonical_serialize, DomainProposal, DependencySet
from ..graph_types import AtomKey
from .d01_production_operations_v1 import CurrentDomainReadV1, MissingProductionOriginalV1
from .d07_ingress_recall_preparation_v1 import PrepareIngressRecallModelRequestV1, InstalledIngressRecallModelReadersV1, ingress_recall_model_ids_v1
from .d07_ingress_recall_acquisition_v1 import _prepared, read_plan_ingress_recall_acquire_v1
from .d07_execution_v1 import (
    read_d07_original_v1, read_original_d07_request_v1, record_d07_original_in_transaction_v1,
    require_current_d07_content_reads_v1, build_actual_ingress_recall_execution_v1,
    settle_d07_paid_result_in_transaction_v1, stage_d07_execution_original_in_transaction_v1,
)
from .foreground_activity_issuance_v1 import require_foreground_activity_issuance_v1
from .foreground_cycle_v1 import foreground_cycle_from_wire_v1
from .d11_types import job_graph_write
from .jobs import get_job, _save_job, _record_operation
from ..authority_service.d07_current_execution_v1 import (
    D07CognitionResultReadRequestV1, D07CognitionResultReadV1,
    read_current_d07_execution_graph_v1, _require_current_ingress_recall_parent_v1, from_wire,
)
from ..authority_service.v2_model_egress_wire import from_wire as model_from_wire
from ..authority_service.v2_model_egress_contract import ModelEgressIntentV1
from ..model_broker.d07_cognition_v1 import thaw_d07_ingress_recall_request_v1

RESULT_OPERATION = "prepare_ingress_recall_result_read_v1"
FINISH_OPERATION = "finish_ingress_recall_model_v1"
ADOPT_OPERATION = "adopt_ingress_recall_model_v1"
OPERATIONS = (RESULT_OPERATION, FINISH_OPERATION, ADOPT_OPERATION)


def ingress_recall_result_operation_id_v1(namespace, c02_operation_id, operation_kind):
    ids = ingress_recall_model_ids_v1(namespace, c02_operation_id)
    if operation_kind == ADOPT_OPERATION:
        return ids["adopt"]
    if operation_kind == RESULT_OPERATION:
        return "d07-result-prepare:" + canonical_digest((namespace, ids["prepare"]))[:48]
    if operation_kind == FINISH_OPERATION:
        return "d07-complete:" + canonical_digest((namespace, ids["call"]))[:48]
    raise ValueError("unregistered Self C3 result operation")


@dataclass(frozen=True, slots=True)
class D07IngressRecallResultStageV1:
    frame: object
    stage: object
    operation_kind: str
    prepared: object
    before_job: object
    after_job: object
    result_request: object = None
    result_read: object = None
    execution: object = None
    adoption: object = None


def read_plan_ingress_recall_result_v1(db, *, namespace, request, service):
    return read_plan_ingress_recall_acquire_v1(db, namespace=namespace, request=request, service=service)


def stage_current_ingress_recall_result_v1(db, *, frame, request, installed_readers, operation_kind):
    from .domain_production_registry_v1 import installed_operation_v1
    from ..authority_service.current_foreground_activity_v1 import foreground_typed_command_digest_v1
    if (operation_kind not in OPERATIONS or type(request) is not PrepareIngressRecallModelRequestV1
            or type(installed_readers) is not InstalledIngressRecallModelReadersV1):
        raise TypeError("exact Self C3 result operation and installed private readers required")
    readers, ns, env = installed_readers, frame.envelope.authority.namespace, frame.envelope
    evidence = require_foreground_activity_issuance_v1(readers.issued, readers.graph, readers.scope)
    if (evidence.request.operation_kind != operation_kind
            or evidence.request.request_digest != foreground_typed_command_digest_v1(installed_operation_v1(operation_kind), request)
            or env.identity.operation_id != ingress_recall_result_operation_id_v1(ns, request.c02_operation_id, operation_kind)
            or env.authority.actor != evidence.current_self.self_entity_ref
            or frame.owner_guard != evidence.owner_guard
            or (evidence.request.c02_operation_id, evidence.request.cue_source_ref, evidence.request.cycle_job_ref) !=
               (request.c02_operation_id, request.source_ref, request.job_ref)):
        raise ValueError("Self C3 result phase changed its actual private issuance")
    read = CurrentDomainReadV1(frame)
    read.check(db)
    p = _prepared(db, ns, request, readers.execution_reader)
    require_current_d07_content_reads_v1(db, p, issuer=readers.issuer)
    call = read_original_d07_request_v1(db, readers.issuer, p)
    sealed = read_d07_original_v1(db, readers.issuer, ns, "call", p.job_id)
    if sealed is None:
        raise MissingProductionOriginalV1("actual_original_self_c3_call")
    intent = model_from_wire(sealed[0], ModelEgressIntentV1)
    child = get_job(db, p.job_id)
    frozen = thaw_d07_ingress_recall_request_v1(json.loads(p.frozen_json))
    if operation_kind == ADOPT_OPERATION:
        _require_current_ingress_recall_parent_v1(db, prepared=p, frozen=frozen, request=call,
            issuer=readers.issuer, installed_bundle=readers.installed_bundle, now=frame.now_utc)
    else:
        checked, checked_job, _ = read_current_d07_execution_graph_v1(db, intent, readers.issuer, frame.now_utc,
            allow_accounted_result=True, installed_bundle=readers.installed_bundle)
        if checked != p or checked_job != child:
            raise ValueError("Self C3 current result worker differs")
    paid = read_d07_original_v1(db, readers.issuer, ns, "paid_cost", p.job_id)
    body = read_d07_original_v1(db, readers.issuer, ns, "body_cost", p.job_id)
    if (paid is None or paid[0]["paid"] is not True or paid[0]["unknown_dimensions"]
            or paid[0]["prepared_digest"] != p.digest or body is None
            or body[0]["prepared_digest"] != p.digest or body[0]["unpaid_cost"]):
        raise MissingProductionOriginalV1("actual_self_c3_paid_model_and_body")
    before, after, result_request, actual_read, execution, adoption = child, None, None, None, None, None
    if operation_kind == RESULT_OPERATION:
        attempt = "d07-result-read:" + canonical_digest((ns, p.job_id, p.digest, intent.request_digest))[:48]
        result_request = D07CognitionResultReadRequestV1(intent.authority_id, intent.namespace, ns,
            readers.installed_bundle.installation_policy.installation_id, p.job_id,
            intent.acquire_operation_id, p.operation_id, p.call_id, p.digest,
            intent.request_digest, p.adoption_operation_id, attempt)
        provenance = {"prepared_digest": p.digest, "result_request": result_request}
        domain, writes = "d07", ()
    else:
        if operation_kind == FINISH_OPERATION:
            actual_read = readers.execution_reader.pre_read_result_v1(p.job_id)
            fact = readers.execution_reader.pre_read_cost_fact_v1(p.job_id)
            if type(actual_read) is not D07CognitionResultReadV1:
                raise ValueError("Self C3 finish lacks the actual authenticated scoped read")
            actual_read.require_original(fact.intent, p)
            result_attempt = read_d07_original_v1(db, readers.issuer, ns, "result_attempt", p.job_id)
            if (result_attempt is None or result_attempt[0] != plain_v1(actual_read.request)
                    or actual_read.terminal_receipt != fact.receipt
                    or actual_read.observation.digest != fact.recovery.observation_digest
                    or actual_read.request.consumer_operation_id != p.adoption_operation_id):
                raise ValueError("Self C3 finish changed its original read attempt/terminal")
        else:
            saved = read_d07_original_v1(db, readers.issuer, ns, "result", "d07-result:" + p.call_id)
            if saved is None:
                raise MissingProductionOriginalV1("actual_self_c3_durable_scoped_result")
            actual_read = from_wire(saved[0], D07CognitionResultReadV1)
            actual_read.require_original(intent, p)
        execution, suggestion = build_actual_ingress_recall_execution_v1(db, prepared=p,
            result_read=actual_read, paid=paid[0], issuer=readers.issuer)
        if (paid[0]["terminal_digest"] != canonical_digest(asdict(actual_read.terminal_receipt))
                or body[0]["terminal_digest"] != paid[0]["terminal_digest"]):
            raise ValueError("Self C3 actual paid/body terminal join differs")
        if operation_kind == FINISH_OPERATION:
            after = replace(child, phase="completed", result_ref=execution.terminal_ref,
                wake_condition=None, lease_holder=None, lease_expires_utc=None)
            domain, writes = "d11", (job_graph_write(after),)
            provenance = {"prepared_digest": p.digest, "terminal": execution,
                "result_digest": actual_read.observation.digest}
        else:
            from .d07_execution_v1 import decode_d07_execution_original_v1
            terminal = read_d07_original_v1(db, readers.issuer, ns, "execution", execution.terminal_ref)
            if (terminal is None or decode_d07_execution_original_v1(terminal[0]) != execution
                    or child.phase != "completed" or child.result_ref != execution.terminal_ref):
                raise MissingProductionOriginalV1("actual_self_c3_completed_execution")
            parent = get_job(db, AtomKey.from_token(p.cycle_job_ref).name)
            continuation = foreground_cycle_from_wire_v1(parent.continuation)
            if parent.phase not in {"waiting", "deferred"} or parent.cancel_epoch:
                raise ValueError("Self C3 adoption needs its unretired waiting parent")
            from .d06_ingress_recall_v1 import read_adopted_ingress_recall_need_v1
            from .d07_ingress_recall_preparation_v1 import read_current_ingress_recall_attempt_v1
            need = read_adopted_ingress_recall_need_v1(db, namespace=ns, c02_operation_id=p.c02_operation_id)
            previous = next(attempt for attempt in continuation.call_plan.attempts if attempt.slot == "C3")
            completed = read_current_ingress_recall_attempt_v1(db, namespace=ns, continuation=continuation,
                attempt=previous, issuer=readers.issuer)
            plan = replace(continuation.call_plan, attempts=tuple(completed if attempt.slot == "C3" else attempt
                for attempt in continuation.call_plan.attempts))
            next_continuation = replace(continuation, call_plan=plan, wait=None)
            before = parent
            after = replace(parent, phase="queued", continuation=plain_v1(next_continuation),
                wake_condition=None, lease_holder=None, lease_expires_utc=None)
            adoption = {"schema": "d07.ingress-recall-adoption.v1", "namespace": plain_v1(ns),
                "prepared_digest": p.digest, "need_ref": p.need_ref, "need_digest": p.need_digest,
                "c02_operation_id": p.c02_operation_id, "cycle_job_ref": p.cycle_job_ref,
                "adoption_operation_id": p.adoption_operation_id, "execution_ref": execution.terminal_ref,
                "execution_digest": terminal[1], "actual_result_digest": actual_read.observation.digest,
                "mode": suggestion.mode, "query_terms": list(suggestion.query_terms),
                "selected_source_refs": list(suggestion.selected_source_refs),
                "triggers": list(dict.fromkeys((*need.triggers, *suggestion.triggers))),
                "required_checks": list(need.required_checks), "missing_items": list(need.missing_items),
                "meaningful_unknowns": list(dict.fromkeys((*need.missing_items, *suggestion.unknowns))),
                "stop_reason": suggestion.stop_reason}
            domain, writes = "d07", (job_graph_write(after),)
            provenance = {"prepared_digest": p.digest, "adoption": adoption,
                "before_cycle": parent, "after_cycle": after}
    registration = readers.graph._GraphCoordinator__providers[domain]
    stage = stage_result_v1(frame, domain, operation_kind, request,
        writes=() if domain == "d07" else writes, provenance=provenance,
        proposal_schema=registration[1], proposal_hash=registration[2])
    if domain == "d07" and writes:
        registration = readers.graph._GraphCoordinator__providers["d11"]
        proposal = DomainProposal("d11", registration[1], registration[2], env, writes, DependencySet(), (), ())
        payload = json.loads(stage.original_payload_json)
        payload["writes"] = plain_v1(writes)
        stage = replace(stage, proposals=(*stage.proposals, proposal),
            original_payload_json=canonical_serialize(payload), original_digest=canonical_digest(payload))
    return D07IngressRecallResultStageV1(frame, stage, operation_kind, p, before, after,
        result_request, actual_read, execution, adoption)


def apply_ingress_recall_result_once_v1(witness, graph, db):
    from .domain_production_commit_v1 import _ACTIVE, _FOREGROUND_VALIDATED, _FOREGROUND_APPLIED, _require_foreground_witness_v1
    from .domain_production_registry_v1 import installed_readers_for_operation_v1
    if (type(witness.stage) is not D07IngressRecallResultStageV1
            or _ACTIVE.get(id(witness)) is not witness
            or _FOREGROUND_VALIDATED.get(id(witness)) is not witness
            or id(witness) in _FOREGROUND_APPLIED):
        raise ValueError("Self C3 result requires its privately verified once W01 witness")
    issued, evidence = _require_foreground_witness_v1(witness, graph, db, witness.bundle)
    readers = installed_readers_for_operation_v1(graph, witness.operation, scope=witness.scope,
        owner_guard=evidence.owner_guard, foreground_issuance=issued)
    s = witness.stage
    if stage_current_ingress_recall_result_v1(db, frame=s.frame, request=witness.request,
            installed_readers=readers, operation_kind=s.operation_kind) != s:
        raise ValueError("Self C3 result changed before final once application")
    p = s.prepared
    if s.operation_kind == RESULT_OPERATION:
        record_d07_original_in_transaction_v1(db, readers.issuer, p.namespace, "result_attempt", p.job_id, asdict(s.result_request))
    elif s.operation_kind == FINISH_OPERATION:
        _, extra_writes = settle_d07_paid_result_in_transaction_v1(db, prepared=p,
            result_read=s.result_read, fact=readers.execution_reader.pre_read_cost_fact_v1(p.job_id),
            issuer=readers.issuer, resource_issuer=readers.execution_reader.resource_issuer,
            holder=s.before_job.lease_holder, fence=s.before_job.fence)
        if extra_writes:
            raise ValueError("Self C3 finish cannot settle model cost a second time")
        actual, writes = stage_d07_execution_original_in_transaction_v1(db, prepared=p,
            issuer=readers.issuer, holder=s.before_job.lease_holder, fence=s.before_job.fence)
        if actual != s.execution or writes != (job_graph_write(s.after_job),):
            raise ValueError("Self C3 actual terminal differs from its pure current projection")
    else:
        _save_job(db, s.after_job)
        _record_operation(db, s.after_job, p.adoption_operation_id, "checkpoint", canonical_digest(plain_v1(s.after_job)))
    _FOREGROUND_APPLIED[id(witness)] = witness
    return True


def validate_ingress_recall_adoption_v1(raw, *, committed):
    from ..runtime_contracts import NamespaceId
    from ..domains.d06 import TriggerKind
    names = {"schema", "namespace", "prepared_digest", "need_ref", "need_digest", "c02_operation_id",
        "cycle_job_ref", "adoption_operation_id", "execution_ref", "execution_digest", "actual_result_digest",
        "mode", "query_terms", "selected_source_refs", "triggers", "required_checks", "missing_items",
        "meaningful_unknowns", "stop_reason"}
    if committed:
        names.add("graph_receipt_digest")
    if type(raw) is not dict or set(raw) != names or raw["schema"] != "d07.ingress-recall-adoption.v1":
        raise ValueError("Self C3 adoption differs from its exact installed schema")
    ns = NamespaceId(**raw["namespace"])
    ids = ingress_recall_model_ids_v1(ns, raw["c02_operation_id"])
    cycle = AtomKey.from_token(raw["cycle_job_ref"])
    if (cycle.type_name != "runtime.job" or NamespaceId.from_key(cycle) != ns
            or raw["adoption_operation_id"] != ids["adopt"]
            or raw["execution_ref"] != "d07-terminal:" + ids["call"]
            or raw["mode"] not in {"light", "normal", "deep"}
            or raw["stop_reason"] not in {"search_required", "clarification_required", "no_history_needed"}):
        raise ValueError("Self C3 adoption changed its actual parent or finite routing")
    for name in ("prepared_digest", "need_digest", "execution_digest", "actual_result_digest",
            *(("graph_receipt_digest",) if committed else ())):
        value = raw[name]
        if type(value) is not str or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
            raise ValueError("Self C3 adoption commitment differs")
    if type(raw["need_ref"]) is not str or not raw["need_ref"].startswith("d07-current:"):
        raise ValueError("Self C3 adoption lacks its actual Need original")
    caps = {"query_terms": (5, 256), "selected_source_refs": (1, 1024), "triggers": (6, 1024),
        "required_checks": (64, 1024), "missing_items": (64, 1024), "meaningful_unknowns": (80, 1024)}
    for name, (count, length) in caps.items():
        values = raw[name]
        if (type(values) is not list or len(values) > count or len(set(values)) != len(values)
                or any(type(value) is not str or not value.strip() or len(value) > length for value in values)):
            raise ValueError("Self C3 adoption exceeds its finite routing data")
    allowed = {kind.value for kind in TriggerKind if kind is not TriggerKind.OPTIONAL_ASSOCIATION}
    if not set(raw["triggers"]) <= allowed:
        raise ValueError("Self C3 adoption invented an unregistered trigger")
    for ref in raw["selected_source_refs"]:
        key = AtomKey.from_token(ref)
        if key.type_name != "memory.source" or NamespaceId.from_key(key) != ns:
            raise ValueError("Self C3 routing source crosses its namespace")
    if raw["stop_reason"] == "no_history_needed" and (raw["required_checks"] or raw["missing_items"]):
        raise ValueError("Self C3 routing cannot clear mandatory facts or coverage gaps")
    return raw


def read_adopted_ingress_recall_routing_v1(db, *, namespace, c02_operation_id, issuer):
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    ids = ingress_recall_model_ids_v1(namespace, c02_operation_id)
    row = read_d07_original_v1(db, issuer, namespace, "adopted", ids["adopt"])
    if row is None:
        return None
    raw = validate_ingress_recall_adoption_v1(row[0], committed=True)
    original = read_adopted_domain_operation_v1(db, namespace, ids["adopt"])
    if (original is None or original["domain"] != "d07" or original["operation_kind"] != ADOPT_OPERATION
            or original["payload"]["provenance"]["adoption"] != {k: v for k, v in raw.items() if k != "graph_receipt_digest"}
            or raw["graph_receipt_digest"] != canonical_digest(original["receipt"])):
        raise ValueError("Self C3 routing lacks its actual W01 adoption receipt")
    return raw


def record_ingress_recall_result_after_cas_v1(db, *, stage, receipt, issuer):
    if stage.operation_kind != ADOPT_OPERATION:
        return None
    if receipt.status != "committed" or receipt.operation_id != stage.prepared.adoption_operation_id:
        raise ValueError("Self C3 adoption requires its actual Graph receipt")
    row = db.execute("SELECT value,valid FROM graph_atoms WHERE token=?", (job_graph_write(stage.after_job).key.token,)).fetchone()
    if row != (canonical_serialize(job_graph_write(stage.after_job).value), 1):
        raise ValueError("Self C3 adoption parent checkpoint was not actually adopted")
    value = {**stage.adoption, "graph_receipt_digest": canonical_digest(receipt)}
    validate_ingress_recall_adoption_v1(value, committed=True)
    digest = record_d07_original_in_transaction_v1(db, issuer, stage.prepared.namespace,
        "adopted", stage.prepared.adoption_operation_id, value)
    return {"kind": "d07.ingress-recall-adoption", "original_ref": stage.prepared.adoption_operation_id, "original_digest": digest}
