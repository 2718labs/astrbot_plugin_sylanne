"""Ingress-derived recall need through the actual private Foreground W01 path.

The committed original records exact attention, responsibility and bounded
ledger coverage. It is routing provenance, never a RequiredCheck PASS receipt.
"""
from dataclasses import dataclass
import json

from ..domains.d01.production_operations_v1 import plain_v1, stage_result_v1
from ..domains.d03 import ContextProvider
from ..domains.d05.relationship import RelationshipProvider
from ..domains.d07 import D07DomainProvider, IngressRecallNeedV1
from ..domains.d08.execution import GoalExecutionProvider
from ..graph_types import AtomKey, Owner
from ..memory_types import SourceRecord
from ..runtime_contracts import canonical_digest
from .d01_production_operations_v1 import CurrentDomainReadV1, MissingProductionOriginalV1, production_read_plan_v1
from .domain_production_originals_v1 import read_adopted_domain_operation_v1
from .foreground_cycle_v1 import require_current_foreground_responsibility_v1, foreground_responsibility_ref_v1, foreground_cycle_from_wire_v1
from .ingress_observation import read_committed_ingress_identity
from .jobs import get_job


NEED_OPERATION = "prepare_ingress_recall_need_v1"
LEDGER_TYPES = ("d03.account_binding", "d03.entity_anchor", "d08.commitment.v1",
    "d08.action_intent.v1", "d08.action_outcome.v1", "d05.boundary_rule")
_GREETINGS = frozenset({"你好", "您好", "嗨", "哈喽", "hello", "hi", "hey", "早上好", "晚上好"})


@dataclass(frozen=True, slots=True)
class PrepareIngressRecallNeedRequestV1:
    c02_operation_id: str
    source_ref: str
    job_ref: str
    policy_digest: str

    def __post_init__(self):
        if (type(self.c02_operation_id) is not str or not self.c02_operation_id
                or AtomKey.from_token(self.source_ref).type_name != "memory.source"
                or AtomKey.from_token(self.job_ref).type_name != "runtime.job"
                or type(self.policy_digest) is not str or len(self.policy_digest) != 64
                or any(c not in "0123456789abcdef" for c in self.policy_digest)):
            raise ValueError("recall need requires actual C02, cycle, Source and installed policy selectors")


@dataclass(frozen=True, slots=True)
class InstalledIngressRecallReadersV1:
    issuer: object
    installed_bundle: object


def ingress_recall_need_operation_id_v1(namespace, c02_operation_id):
    return "ingress-recall-need:" + canonical_digest((namespace, c02_operation_id))[:40]


def read_plan_ingress_recall_need_v1(db, *, namespace, request, policy):
    from ..host.authority_profile import AdminD06RecallPolicyV1
    if type(policy) is not AdminD06RecallPolicyV1 or policy.policy_digest != request.policy_digest:
        raise MissingProductionOriginalV1("actual_installed_recall_policy")
    focus = AtomKey(Owner("persona", *namespace.as_tuple), "d07.focus.v1", namespace.persona_id)
    keys = [AtomKey.from_token(request.job_ref), focus]
    row = db.execute("SELECT value,valid FROM graph_atoms WHERE token=? AND bot=? AND persona=?",
        (focus.token, *namespace.as_tuple)).fetchone()
    if row is not None and row[1] == 1:
        value = json.loads(row[0])
        next(spec for spec in D07DomainProvider.type_specs() if spec.name == "d07.focus.v1").validator(value)
        if value["primary_ticket_ref"] is not None:
            ticket = AtomKey.from_token(value["primary_ticket_ref"])
            keys.append(ticket)
            current = db.execute("SELECT value,valid FROM graph_atoms WHERE token=? AND bot=? AND persona=?",
                (ticket.token, *namespace.as_tuple)).fetchone()
            if current is not None and current[1] == 1:
                ticket_value = json.loads(current[0])
                next(spec for spec in D07DomainProvider.type_specs() if spec.name == "d07.attention_ticket.v1").validator(ticket_value)
                if ticket_value["concern_ref"] is not None:
                    keys.append(AtomKey.from_token(ticket_value["concern_ref"]))
    pages = min(len(LEDGER_TYPES), policy.max_ledger_pages, policy.max_ledger_nodes)
    return production_read_plan_v1(LEDGER_TYPES[:pages], tuple(keys), (request.source_ref,), ())


def _ledger_page(db, read, type_name, specs):
    pages = tuple(page for page in read.frame.query_coverage if page.type_id == type_name)
    if not pages:
        return (), "unavailable"
    if len(pages) != 1:
        raise ValueError("recall ledger needs one exact registered current page")
    page = pages[0]
    atoms = tuple(read.head(db, version.key) for version in page.row_versions)
    for atom in atoms:
        if atom.valid:
            specs[type_name].validator(atom.value)
    return tuple(atom for atom in atoms if atom.valid), "complete" if page.complete else "partial"


def stage_ingress_recall_need_in_transaction_v1(db, *, frame, request, installed_readers):
    from ..host.authority_profile import AdminD06RecallPolicyV1
    from .issuers import D11BudgetJobIssuer
    if (type(installed_readers) is not InstalledIngressRecallReadersV1
            or type(installed_readers.issuer) is not D11BudgetJobIssuer):
        raise TypeError("recall need requires its actual installed readers")
    ns, bundle = frame.envelope.authority.namespace, installed_readers.installed_bundle
    policy = bundle.d06_recall
    if type(policy) is not AdminD06RecallPolicyV1 or policy.policy_digest != request.policy_digest:
        raise MissingProductionOriginalV1("actual_installed_recall_policy")
    read = CurrentDomainReadV1(frame)
    read.check(db)
    cycle = get_job(db, AtomKey.from_token(request.job_ref).name)
    from .foreground_call_plan_v1 import require_protected_reply_budget_v1
    require_protected_reply_budget_v1(db, namespace=ns, plan=foreground_cycle_from_wire_v1(cycle.continuation).call_plan,
        issuer=installed_readers.issuer, now_utc=frame.now_utc)
    responsibility = require_current_foreground_responsibility_v1(db, namespace=ns, job=cycle,
        installed_bundle=bundle, issuer=installed_readers.issuer, owner_guard=frame.owner_guard,
        purpose=frame.envelope.authority.purpose, audiences=frame.envelope.authority.audience, now_utc=frame.now_utc)
    if (responsibility is None or responsibility.c02_operation_id != request.c02_operation_id
            or responsibility.source_ref != request.source_ref or cycle.activity_id != frame.envelope.identity.activity_id
            or cycle.phase != "running" or cycle.lease_holder != frame.envelope.authority.actor
            or frame.now_utc >= responsibility.deadline_utc):
        raise MissingProductionOriginalV1("actual_running_self_foreground_responsibility")
    source = read.head(db, request.source_ref, required=True)
    read.source_family(db, (request.source_ref,))
    record = SourceRecord.from_dict(source.value)
    ingress = read_committed_ingress_identity(db, ns, record.source_id)
    if ingress is None:
        raise MissingProductionOriginalV1("actual_recall_ingress")
    ingress_identity = json.loads(ingress.identity_json)
    focus_key = AtomKey(Owner("persona", *ns.as_tuple), "d07.focus.v1", ns.persona_id)
    focus = read.head(db, focus_key, required=True)
    specs = {spec.name: spec for spec in D07DomainProvider.type_specs()}
    specs[focus_key.type_name].validator(focus.value)
    if focus.value["primary_ticket_ref"] is None:
        raise MissingProductionOriginalV1("actual_current_recall_attention")
    ticket = read.head(db, focus.value["primary_ticket_ref"], required=True)
    specs[ticket.key.type_name].validator(ticket.value)
    from ..graph_coordinator import post_c02_attention_operation_id
    attention_operation = post_c02_attention_operation_id(request.c02_operation_id, request.source_ref)
    issuance = db.execute("SELECT operation_id,c02_operation_id FROM graph_d07_attention_issuance_v1 "
        "WHERE bot=? AND persona=? AND source_ref=?", (*ns.as_tuple, request.source_ref)).fetchall()
    if (request.source_ref not in ticket.value["source_refs"] or ticket.value["valid_until"] <= frame.now_utc
            or not ticket.value["eligible"] or not ticket.value["resources_available"] or ticket.value["cancel_refs"]
            or ticket.value["causal_root"] != request.source_ref
            or (attention_operation, request.c02_operation_id) not in issuance
            or ticket.value["ticket_id"] != "attention:" + canonical_digest({"operation_id": attention_operation})[:48]):
        raise MissingProductionOriginalV1("actual_current_ingress_attention_ticket")
    specs.update({spec.name: spec for spec in ContextProvider().type_specs()})
    specs.update({spec.name: spec for spec in GoalExecutionProvider().register_types()})
    specs.update({spec.name: spec for spec in RelationshipProvider().type_specs()})
    inventories, missing = {}, []
    for type_name in LEDGER_TYPES:
        atoms, coverage = _ledger_page(db, read, type_name, specs)
        inventories[type_name] = atoms
        if coverage != "complete":
            missing.append("ledger_" + coverage + ":" + type_name)
    bindings = tuple(atom for atom in inventories["d03.account_binding"]
        if atom.value["platform_identifier"] == ingress_identity["sender_ref"]
        and atom.value["platform_namespace"] == ingress_identity["platform_ref"]
        and atom.value["valid_from"] <= frame.now_utc
        and (atom.value["valid_until"] is None or frame.now_utc <= atom.value["valid_until"]))
    entity = None
    if not any(item.endswith(":d03.account_binding") or item.endswith(":d03.entity_anchor") for item in missing):
        if len(bindings) == 1:
            anchors = tuple(atom for atom in inventories["d03.entity_anchor"]
                if atom.value["entity_id"] == bindings[0].value["entity_id"] and atom.value["status"] == "active")
            if len(anchors) == 1:
                entity = anchors[0].value["entity_id"]
        elif len(bindings) > 1:
            missing.append("ambiguous_current_inbound_entity")
    triggers, checks = [], []
    if ticket.value["concern_ref"] is not None:
        concern = read.head(db, ticket.value["concern_ref"], required=True)
        specs[concern.key.type_name].validator(concern.value)
        if concern.value["status"] in {"open", "waiting", "parked"}:
            triggers.append("unresolved_reference")
            checks.append("current_concern_resolution")
    obligations = tuple(atom for atom in inventories["d08.commitment.v1"]
        if atom.value["subject_ref"] == "persona:" + ns.persona_id
        and atom.value["fulfillment_state"] not in {"fulfilled", "withdrawn"}
        and (entity is None or atom.value["counterparty_ref"] == entity))
    if obligations:
        if entity is None:
            missing.append("unresolved_commitment_counterparty")
        else:
            triggers.append("commitment_execution")
            checks.extend(("current_commitment_conflict", "current_action_cancellation", "atomic_execution_effect"))
            if any(atom.value["deadline_ref"] is not None for atom in obligations):
                triggers.append("time_or_activity_status")
    if entity is not None:
        actions = tuple(atom for atom in inventories["d08.action_intent.v1"] if atom.value["target_ref"] == entity)
        if actions:
            triggers.append("commitment_execution")
            checks.extend(("current_action_cancellation", "atomic_execution_effect"))
            action_ids = {atom.value["action_id"] for atom in actions}
            if any(atom.value["action_id"] in action_ids and (atom.value["result_level"] == "unknown"
                    or atom.value["unknown_effects"]) for atom in inventories["d08.action_outcome.v1"]):
                missing.append("actual_action_outcome_unknown")
    boundaries = tuple(atom for atom in inventories["d05.boundary_rule"]
        if atom.value["subject_persona_ref"] == "persona:" + ns.persona_id and atom.value["status"] == "active"
        and atom.value["valid_from"] <= frame.now_utc
        and (atom.value["valid_until"] is None or frame.now_utc <= atom.value["valid_until"])
        and (entity is None or atom.value["target_entity_ref"] == entity))
    if boundaries:
        checks.append("current_applicable_boundary")
        if entity is None:
            missing.append("unresolved_boundary_target")
    # Whole-message recognition chooses zero historical work only after real
    # ledger/Concern observations. It never supplies a trigger or permission.
    greeting = record.text.strip().casefold().rstrip("!！。.").strip() in _GREETINGS
    routing = "partial" if missing else "required_checks" if checks else "no_search" if greeting else "semantic_route_required"
    need = IngressRecallNeedV1(request.c02_operation_id, request.source_ref, source.revision, canonical_digest(source.value),
        focus_key.token, focus.revision, ticket.key.token, ticket.revision, request.job_ref, cycle.cancel_epoch,
        foreground_responsibility_ref_v1(ns, request.c02_operation_id), responsibility.digest, policy.policy_ref, policy.policy_version,
        policy.policy_digest, responsibility.deadline_utc, tuple(dict.fromkeys(triggers)), tuple(dict.fromkeys(checks)),
        tuple(dict.fromkeys(missing)), entity, routing)
    return stage_result_v1(frame, "d07", NEED_OPERATION, request,
        provenance={"need": need, "ledger_coverage": frame.query_coverage},
        coverage="partial" if missing else "complete", missing=need.missing_items,
        continuation=next((page.continuation_ref for page in frame.query_coverage if not page.complete), None))


def read_adopted_ingress_recall_need_v1(db, *, namespace, c02_operation_id):
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    original = read_adopted_domain_operation_v1(db, namespace, ingress_recall_need_operation_id_v1(namespace, c02_operation_id))
    if original is None:
        return None
    if original["domain"] != "d07" or original["operation_kind"] != NEED_OPERATION:
        raise ValueError("recall need locator names another adopted operation")
    return decode_typed_production_value_v1(original["payload"]["provenance"]["need"], IngressRecallNeedV1)
