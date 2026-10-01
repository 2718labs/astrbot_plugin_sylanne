"""Closed receiver resolution from an adopted event and current W01 heads.

Ready commands remain ordinary current operations under a fresh Owner fence.
Missing execution, encoding or consent originals yield a durable precise wait.
This reader never acknowledges an effect, retries a dispatch or grants CPU.
"""
from dataclasses import dataclass
import json

from ..graph_types import AtomKey
from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize
from ..domains.d10 import decode_contact_policy, decode_proactive_opportunity
from ..domains.d10.production_operations_v1 import PrepareCurrentContactRequestV1
from .d01_production_operations_v1 import CurrentDomainReadV1, MissingProductionOriginalV1, production_read_plan_v1
from .domain_production_contracts_v1 import ProductionOutboxStageV1
from .domain_production_original_codec_v1 import _EVENTS
from .domain_production_originals_v1 import read_adopted_domain_operation_v1


def verify_current_followup_trigger_v1(db, namespace, event, causal_original, issuer):
    """Authenticate the one fixed trigger emitted by each actual causal issuer."""
    if (not db.in_transaction or type(namespace) is not NamespaceId
            or type(event) is not ProductionOutboxStageV1 or event.namespace != namespace
            or causal_original is None or causal_original["receipt"].operation_id != event.causal_operation_id):
        raise ValueError("followup trigger requires its actual causal W01 adoption")
    if event.event_kind == "actual_internal_experience_requires_encoding":
        if (causal_original["domain"], causal_original["operation_kind"]) != ("d10", "advance_life"):
            raise ValueError("internal experience has another actual causal operation")
        key = AtomKey.from_token(event.trigger_original.original_ref)
        versions = tuple(version for version in causal_original["receipt"].write_versions if version.key == key)
        if len(versions) != 1 or key.type_name != "memory.source" or not key.owner.subject.startswith("d10-life-experience:"):
            raise ValueError("experience source is not an actual member of the causal composite receipt")
        row = db.execute("SELECT event_bot,event_persona,event_id,value,valid FROM graph_history WHERE token=? AND revision=?",
            (key.token, versions[0].revision)).fetchone()
        if row is None or row[:3] != (*namespace.as_tuple, event.causal_operation_id) or row[4] != 1:
            raise ValueError("experience source lost its actual causal Graph history")
        from ..memory_types import SourceRecord
        from ..domains.d06 import D06DomainAdapter, SourceAdmission
        from ..domains.d01.production_operations_v1 import plain_v1
        source = SourceRecord.from_dict(json.loads(row[3]))
        progress = causal_original["payload"]["provenance"]["actual_progress"]
        expected_id = "d10-life-experience:" + canonical_digest((progress["activity_id"], progress["effect_id"]))[:48]
        expected_text = canonical_serialize({
            "kind": "life_step_completed", "project_ref": progress["project_ref"], "recipe_ref": progress["recipe_ref"],
            "step": progress["step"], "role_start": progress["role_start"], "role_end": progress["role_end"],
            "artifact_ref": progress["artifact_ref"], "terminal_ref": progress["terminal_ref"], "reality": progress["reality"]})
        root_ref = progress["source_refs"][-1]
        roots = tuple(version for version in causal_original["read_versions"] if version.key.token == root_ref)
        if len(roots) != 1:
            raise ValueError("experience admission lost its actual causal parent read")
        root = db.execute("SELECT value,valid FROM graph_history WHERE token=? AND revision=?", (root_ref, roots[0].revision)).fetchone()
        if root is None or root[1] != 1:
            raise ValueError("experience admission lost its actual parent source history")
        actual_parent = SourceRecord.from_dict(json.loads(root[0]))
        family = actual_parent.provenance_root
        from ..graph_types import GraphAtom, GraphSnapshot
        from .d10_production_operations_v1 import experience_allowed_purposes_v1
        historical = []
        for version in causal_original["read_versions"]:
            if version.revision < 1 or version.key.type_name not in {"memory.source", "memory.access", "d11.owner_grant.v1"}:
                continue
            value = db.execute("SELECT value,valid FROM graph_history WHERE token=? AND revision=?",
                (version.key.token, version.revision)).fetchone()
            if value is None:
                raise ValueError("experience admission lost its actual parent/Owner permission history")
            historical.append(GraphAtom(version.key, version.revision, json.loads(value[0]), bool(value[1])))
        purposes = experience_allowed_purposes_v1(GraphSnapshot(tuple(historical), ()), namespace, tuple(progress["source_refs"]))
        simulated = progress["reality"] == "role_simulation"
        admission = SourceAdmission(expected_id, expected_text, "persona:" + namespace.persona_id,
            "simulated" if simulated else "internal", "simulated" if simulated else "observed",
            "none" if simulated else "subjective_only", "committed",
            actual_parent.occurred_at, causal_original["payload"]["now_utc"], family,
            tuple(causal_original["payload"]["authority"]["audience"]),
            purposes,
            tuple(AtomKey.from_token(ref).owner.subject for ref in progress["source_refs"]))
        if (source.source_id != expected_id or source.text != expected_text
                or source.recorded_at != causal_original["payload"]["now_utc"]
                or tuple(source.parent_source_ids) != tuple(AtomKey.from_token(ref).owner.subject for ref in progress["source_refs"])
                or D06DomainAdapter(namespace).admit_source(admission).source != source
                or canonical_digest(plain_v1(admission)) != event.trigger_original.original_digest):
            raise ValueError("actual internal-experience trigger differs from its original admission bytes")
        return event.trigger_original
    if event.event_kind == "actual_offline_simulation_experiences_require_encoding":
        if (causal_original["domain"], causal_original["operation_kind"]) != ("d10", "advance_offline"):
            raise ValueError("offline experience has another actual causal operation")
        if event.trigger_original.original_ref != causal_original["payload"]["request"]["offline_interval_ref"]:
            raise ValueError("offline trigger names another registered interval")
        from .domain_production_read_plans_v1 import _signed_input
        actual = _signed_input(db, namespace, event.trigger_original.original_ref, issuer)
        if (actual is None or actual.kind != "d10.offline_interval"
                or actual.original_digest != event.trigger_original.original_digest):
            raise ValueError("offline trigger is not the actual signed interval original")
        return actual
    if (event.trigger_original.original_digest != causal_original["original_digest"]
            or event.trigger_original.original_ref != causal_original["domain"] + "-current:" + causal_original["original_digest"][:48]):
        raise ValueError("domain followup trigger differs from its actually adopted stage original")
    return event.trigger_original


@dataclass(frozen=True, slots=True)
class DomainFollowupCommandV1:
    receiver_domain: str
    operation_kind: str
    request: object
    activity_id: str
    audience_ref: str
    audience_refs: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class DomainFollowupResolutionV1:
    status: str
    commands: tuple[DomainFollowupCommandV1, ...]
    target_refs: tuple[str, ...]
    missing_originals: tuple[str, ...]
    continuation_ref: str | None = None

    def __post_init__(self):
        if (self.status not in {"ready", "waiting_for_original", "partial"}
                or type(self.commands) is not tuple or len(self.commands) > 16
                or any(type(command) is not DomainFollowupCommandV1 for command in self.commands)
                or type(self.target_refs) is not tuple or len(self.target_refs) > 128
                or type(self.missing_originals) is not tuple or len(self.missing_originals) > 128
                or self.status == "ready" and (not self.commands or self.missing_originals or self.continuation_ref)):
            raise ValueError("domain followup resolution is not a bounded concrete result")


def _adopted_event(db, namespace, event):
    if (type(event) is not ProductionOutboxStageV1 or event.namespace != namespace
            or _EVENTS.get(event.event_kind) != event.receiver_domain):
        raise ValueError("followup requires the exact installed event kind/receiver")
    row = db.execute("SELECT causal_operation_id,receiver_domain,event_kind,original_ref,original_digest,state "
        "FROM graph_domain_production_outbox_v1 WHERE bot=? AND persona=? AND dedupe_key=?",
        (*namespace.as_tuple, event.dedupe_key)).fetchone()
    if (row is None or row[:5] != (event.causal_operation_id, event.receiver_domain, event.event_kind,
            event.trigger_original.original_ref, event.trigger_original.original_digest)
            or row[5] not in {"pending", "waiting"}):
        raise ValueError("followup has no matching current unconsumed durable outbox original")
    original = read_adopted_domain_operation_v1(db, namespace, event.causal_operation_id)
    if original is None:
        raise ValueError("followup lost its real causal W01 adoption")
    return original


def read_plan_current_domain_followup_v1(db, *, namespace, event):
    if not db.in_transaction or type(namespace) is not NamespaceId:
        raise ValueError("followup plan needs the actual current W01 SQL transaction")
    original = _adopted_event(db, namespace, event)
    fixed = {
        "d01": ("d01.persona_activation.v1", "d01.persona_plan.v1", "d07.current_interpretation.v1"),
        "d08": ("d08.action_intent.v1", "d08.action_outcome.v1", "d08.commitment.v1", "d08.goal.v1", "d08.joint_plan.v1",
            "d08.action_schema.v1", "d05.boundary_rule", "d05.relationship_projection"),
        "d10": ("d10.contact_policy.v1", "d10.proactive_opportunity.v1", "d10.contact_claim.v1", "d10.contact_claim.v2", "d10.life_project.v1",
            "d10.activity_recipe.v1", "d03.account_binding", "d03.entity_anchor", "d05.boundary_rule"),
        "d06": (), "d07": ("d07.concern_round.v1", "d07.reflection_checkpoint.v1", "d07.attention_ticket.v1"),
    }[event.receiver_domain]
    keys = [version.key for version in original["receipt"].write_versions]
    keys += [version.key for version in original["read_versions"]]
    roots = [key.token for key in keys if key.type_name == "memory.source"]
    for type_id in fixed:
        rows = db.execute("SELECT value FROM graph_atoms WHERE bot=? AND persona=? AND type_name=? AND valid=1 "
            "ORDER BY token LIMIT 129", (*namespace.as_tuple, type_id)).fetchall()
        if len(rows) > 128:
            raise MissingProductionOriginalV1("complete_followup_inventory:" + type_id,
                continuation="followup-query:" + canonical_digest((namespace, event.dedupe_key, type_id))[:48])
        for (encoded,) in rows:
            raw = json.loads(encoded)
            roots += list(raw.get("source_refs", raw.get("creation_evidence_refs", ())))
            if type_id == "d10.proactive_opportunity.v1":
                roots.append(raw["source_ref"])
            if event.receiver_domain == "d10" and type_id == "d03.account_binding":
                from .d01_production_operations_v1 import raw_head_value_v1
                evidence_key = AtomKey.from_token(raw["verification_ref"])
                keys.append(evidence_key)
                evidence = raw_head_value_v1(db, namespace, evidence_key)
                if evidence is not None:
                    roots.extend(evidence["source_refs"])
    return production_read_plan_v1(fixed, keys, roots, (event.trigger_original.original_ref,))


def resolve_domain_followup_v1(db, current_frame, event):
    read = CurrentDomainReadV1(current_frame)
    read.check(db)
    ns = current_frame.envelope.authority.namespace
    original = _adopted_event(db, ns, event)
    epoch = current_frame.snapshot.epochs[0].revision
    continuation = "domain-followup:" + canonical_digest((ns, event.dedupe_key, epoch))[:48]
    def wait(reason, targets=()):
        return DomainFollowupResolutionV1("waiting_for_original", (), tuple(targets), (reason,), continuation)
    if event.receiver_domain == "d10" and event.event_kind in {
            "boundary_changed_requires_contact_recheck", "source_correction_requires_contact_recheck"}:
        policies = tuple(atom for atom in read.complete_inventory(db, "d10.contact_policy.v1") if atom.valid)
        opportunities = tuple(atom for atom in read.complete_inventory(db, "d10.proactive_opportunity.v1") if atom.valid)
        read.complete_inventory(db, "d03.account_binding")
        read.complete_inventory(db, "d03.entity_anchor")
        commands, missing, targets = [], [], []
        from .contact_route_binding_v1 import contact_route_audience_v1, read_current_contact_route_binding_v1
        for atom in opportunities:
            opportunity = decode_proactive_opportunity(atom.value, ns)
            if opportunity.expires_at < current_frame.now_utc:
                continue
            targets.append(atom.key.token)
            matching = tuple(policy for policy in policies if
                (policy.value["subject_ref"], policy.value["channel"], policy.value["category"]) ==
                (opportunity.subject_ref, opportunity.channel, opportunity.category))
            if len(matching) != 1:
                missing.append("unique_current_contact_policy:" + atom.key.token)
                continue
            decode_contact_policy(matching[0].value, ns)
            accounts = tuple(value for value in read.complete_inventory(db, "d03.account_binding")
                if value.valid and value.value["entity_id"] == opportunity.subject_ref
                and value.value["valid_from"] <= current_frame.now_utc
                and (value.value["valid_until"] is None or current_frame.now_utc < value.value["valid_until"]))
            if len(accounts) != 1:
                missing.append("unique_current_contact_target_account:" + atom.key.token)
                continue
            account = accounts[0]
            try:
                audience = contact_route_audience_v1(db, ns, account.value)
                read_current_contact_route_binding_v1(db, read, account_ref=account.key.token,
                    target_entity_ref=opportunity.subject_ref, audience=audience)
            except MissingProductionOriginalV1 as error:
                missing.extend(error.missing_inputs)
                continue
            if len(commands) >= current_frame.limits.max_followup_jobs:
                missing.append("bounded_contact_followup_tail")
                break
            commands.append(DomainFollowupCommandV1("d10", "prepare_contact",
                PrepareCurrentContactRequestV1(atom.key.token, matching[0].key.token, account.key.token),
                "contact-followup:" + canonical_digest((event.dedupe_key, atom.key.token))[:48], audience))
        if not targets:
            return wait("current_contact_opportunity_from_actual_source")
        status = "partial" if missing and commands else "ready" if commands else "waiting_for_original"
        return DomainFollowupResolutionV1(status, tuple(commands), tuple(targets), tuple(dict.fromkeys(missing)),
            continuation if status != "ready" else None)
    if event.receiver_domain == "d06":
        # Actual experience keys must occur in the causal composite receipt,
        # and their original history must be the same adopted commit.
        targets = tuple(version.key.token for version in original["receipt"].write_versions
            if version.key.type_name == "memory.source" and version.key.owner.subject.startswith(
                ("d10-life-experience:", "d10-offline-experience:")))
        if not targets:
            return wait("actual_adopted_d10_experience_sources")
        for ref in targets:
            atom = read.head(db, ref, required=True)
            history = db.execute("SELECT event_bot,event_persona,event_id,value,valid FROM graph_history WHERE token=? AND revision=?",
                (ref, atom.revision)).fetchone()
            adopted_revision = next(version.revision for version in original["receipt"].write_versions if version.key.token == ref)
            if (history is None or history[:3] != (*ns.as_tuple, event.causal_operation_id)
                    or atom.revision != adopted_revision or history[4] != 1 or json.loads(history[3]) != atom.value):
                raise ValueError("experience original is not from the actual causal D10 bundle")
        read.source_family(db, targets, purpose="consolidation")
        from ..domains.d06.structured_experience_v1 import EncodeCurrentStructuredExperienceRequestV1
        audience = original["payload"]["authority"]["audience"]
        commands = tuple(DomainFollowupCommandV1("d06", "encode_structured_experience",
            EncodeCurrentStructuredExperienceRequestV1(event.causal_operation_id, ref),
            "structured-experience:" + canonical_digest((event.dedupe_key, ref))[:48],
            audience[0], tuple(audience))
            for ref in targets[:current_frame.limits.max_followup_jobs])
        missing = ("actual_d04_then_feeling_and_d06_subjective_trace_encoding",)
        if len(commands) < len(targets):
            missing += ("bounded_structured_experience_tail",)
        return DomainFollowupResolutionV1("partial", commands, targets, missing, continuation)
    if event.receiver_domain == "d08":
        actions = tuple(atom.key.token for atom in read.complete_inventory(db, "d08.action_intent.v1") if atom.valid)
        goals = tuple(atom.key.token for atom in read.complete_inventory(db, "d08.goal.v1") if atom.valid)
        plans = tuple(atom.key.token for atom in read.complete_inventory(db, "d08.joint_plan.v1") if atom.valid)
        if event.event_kind in {"relationship_changed_requires_action_recheck", "boundary_changed_requires_action_recheck",
                "source_correction_requires_boundary_recheck", "persona_growth_requires_commitment_reevaluation"}:
            if not actions:
                return wait("actual_current_d08_action_intents")
            from ..domains.d08.production_operations_v1 import RecheckCurrentActionRequestV1
            from ..domains.d08.execution import _decode_intent
            commands = []
            for ref in actions[:current_frame.limits.max_followup_jobs]:
                intent = _decode_intent(read.head(db, ref, required=True).value)
                commands.append(DomainFollowupCommandV1("d08", "recheck_action", RecheckCurrentActionRequestV1(ref),
                    intent.identity.activity_id, current_frame.envelope.authority.audience[0]))
            partial = len(commands) < len(actions)
            return DomainFollowupResolutionV1("partial" if partial else "ready", tuple(commands), actions,
                ("bounded_current_action_recheck_tail",) if partial else (), continuation if partial else None)
        if event.event_kind == "qualified_contact_opportunity_requires_action":
            target = original["payload"]["request"]["opportunity_ref"]
            read.head(db, target, required=True)
            return wait("adopted_d08_contact_action_intent_with_current_required_checks", (target,))
        if event.event_kind == "joint_plan_adopted_requires_next_node_action":
            return wait("actual_d08_joint_node_action_intent_and_independent_party_scope", plans)
        return wait("actual_d08_value_ranked_action_candidates_and_required_checks", actions or goals)
    if event.receiver_domain == "d01":
        return wait("adopted_d07_growth_interpretation_and_actual_completed_trials", tuple(
            version.key.token for version in original["receipt"].write_versions if version.key.type_name == "d10.life_progress.v1"))
    if event.receiver_domain == "d10":
        projects = tuple(atom.key.token for atom in read.complete_inventory(db, "d10.life_project.v1") if atom.valid)
        return wait("actual_d08_life_action_outcome_with_settled_body_component_and_clock_originals", projects)
    if event.receiver_domain == "d07":
        return wait("actual_d07_execution_terminal_and_registered_resume_request", (event.trigger_original.original_ref,))
    raise ValueError("registered followup receiver has no concrete installed semantics")
