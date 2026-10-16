"""Current D08 reads and fixed producers for actual bilateral evidence."""
from __future__ import annotations

from dataclasses import dataclass
import json

from ..domains.d01.production_operations_v1 import plain_v1
from ..domains.d05.relationship import BoundaryRule, RelationshipProvider, _tuple_payload as boundary_tuple
from ..domains.d08.commitment_acknowledgement import BilateralAcknowledgementReadV1
from ..domains.d08.execution import (
    Commitment, CommitmentConflictSnapshot, ActionSchema, ActionSchemaRecord, GoalExecutionProvider, JointPlan, JointPlanAcceptance, PlanNode,
    _decode, _decode_intent, _decode_joint_plan, _tuple_fields,
)
from ..domains.d08.production_operations_v1 import (
    AcknowledgeCurrentBilateralRequestV1, AdoptCurrentJointPlanRequestV1, CurrentBilateralInputsV1,
    CurrentJointPlanInputsV1, compile_acknowledge_current_bilateral_v1, compile_adopt_current_joint_plan_v1,
    RecheckCurrentActionRequestV1, CurrentActionRecheckInputsV1, compile_recheck_current_action_v1,
    SettleCurrentObservedActionRequestV1, observed_action_outcome_key_v1,
    compile_settle_current_observed_action_v1,
    verify_d08_production_stage_v1,
)
from ..graph_types import AtomKey, GraphVersion
from ..memory_types import access_key
from ..runtime_contracts import NamespaceId, QueryEpoch, VersionedRef, canonical_digest, canonical_serialize
from .d01_production_operations_v1 import CurrentDomainReadV1, MissingProductionOriginalV1, table_exists_v1, waiting_stage_v1
from .domain_production_contracts_v1 import ProductionOriginalRefV1
from .issuers import D11BudgetJobIssuer


@dataclass(frozen=True, slots=True)
class JointPlanIntentOriginalV1:
    plan_id: str
    revision: int
    nodes: tuple[PlanNode, ...]
    exit_rules: tuple[str, ...]
    source_refs: tuple[str, ...]
    current_goal_refs: tuple[str, ...]

    def __post_init__(self):
        if (type(self.plan_id) is not str or not self.plan_id.startswith("plan:")
                or type(self.revision) is not int or self.revision < 1
                or type(self.nodes) is not tuple or not 1 <= len(self.nodes) <= 8
                or any(type(node) is not PlanNode for node in self.nodes)
                or type(self.exit_rules) is not tuple or not self.exit_rules
                or type(self.source_refs) is not tuple or not self.source_refs
                or type(self.current_goal_refs) is not tuple or not self.current_goal_refs):
            raise ValueError("joint plan intent requires bounded actual tasks, sources and goals")
        if len({node.node_id for node in self.nodes}) != len(self.nodes):
            raise ValueError("joint plan node identities repeat")
        JointPlan._assert_acyclic(self.nodes)


@dataclass(frozen=True, slots=True)
class PartyConsentEvidenceV1:
    plan_proposal_ref: str
    participant_ref: str
    plan_revision: int
    terms_digest: str
    accepted_scope: tuple[str, ...]
    acceptance_interpretation_ref: str
    inbound_source_ref: str
    outbound_receipt_refs: tuple[str, ...] = ()


def joint_plan_terms_digest_v1(intent):
    return canonical_digest(plain_v1(intent))


def joint_plan_consent_scope_v1(intent, participant, scope):
    return "d08.joint-plan-consent:" + canonical_digest((joint_plan_terms_digest_v1(intent),
        participant, tuple(scope)))


def bilateral_acceptance_scope_v1(commitment):
    return "d08.commitment-acceptance:" + canonical_digest((commitment.commitment_id,
        commitment.revision, commitment.counterparty_ref, commitment.semantic_scope))


def install_d08_production_schema_v1(db):
    if db.in_transaction:
        raise ValueError("install D08 production schema before runtime transactions")
    from .joint_external_observation_v1 import install_joint_external_schema_v1
    install_joint_external_schema_v1(db)
    db.execute("CREATE TABLE IF NOT EXISTS graph_d08_joint_plan_intents_v1 ("
        "bot TEXT NOT NULL,persona TEXT NOT NULL,original_ref TEXT NOT NULL,producing_operation_id TEXT NOT NULL,"
        "payload_json TEXT NOT NULL,payload_digest TEXT NOT NULL,signature TEXT NOT NULL,source_refs_json TEXT NOT NULL,"
        "PRIMARY KEY(bot,persona,original_ref))")
    db.execute("CREATE TABLE IF NOT EXISTS graph_d08_party_consents_v1 ("
        "bot TEXT NOT NULL,persona TEXT NOT NULL,original_ref TEXT NOT NULL,producing_operation_id TEXT NOT NULL,"
        "plan_proposal_ref TEXT NOT NULL,participant_ref TEXT NOT NULL,terms_digest TEXT NOT NULL,"
        "payload_json TEXT NOT NULL,payload_digest TEXT NOT NULL,signature TEXT NOT NULL,source_refs_json TEXT NOT NULL,"
        "PRIMARY KEY(bot,persona,original_ref),UNIQUE(bot,persona,plan_proposal_ref,participant_ref,terms_digest))")


class InstalledD08ProductionReadersV1:
    def __init__(self, *, issuer):
        if type(issuer) is not D11BudgetJobIssuer:
            raise TypeError("D08 needs the installed D11 original issuer")
        self.issuer = issuer

    def read_bilateral(self, db, frame, request):
        read = CurrentDomainReadV1(frame)
        read.check(db)
        atom = read.head(db, request.commitment_ref, required=True)
        commitment = _decode("d08.commitment.v1", atom.value)
        source = read.head(db, request.inbound_source_ref, required=True)
        read.source_family(db, (request.inbound_source_ref,))
        access = read.head(db, access_key(*frame.envelope.authority.namespace.as_tuple, source.key.owner.subject), required=True)
        account, entity = read.actor_entity(db, request.inbound_source_ref, expected_entity=commitment.counterparty_ref)
        semantic, acceptance, records = read.adopted_interpretation(db, request.acceptance_interpretation_ref,
            question_scope=bilateral_acceptance_scope_v1(commitment))
        if (semantic.value["proposition"] != "accepted" or request.inbound_source_ref not in semantic.value["source_refs"]
                or request.inbound_source_ref not in records):
            raise MissingProductionOriginalV1("explicit_current_bilateral_acceptance")
        observed, outbound = read.adopted_outbound_observation(db, request.outbound_receipt_ref)
        platform = observed.pending.platform_observation
        origin = getattr(platform.binding, "origin", platform.binding)
        from .natural_dispatch_current_read_v2 import recover_natural_dispatch_candidate_in_transaction_v2
        recovered = recover_natural_dispatch_candidate_in_transaction_v2(db, frame.envelope.authority.namespace, origin.operation_id)
        if recovered is None:
            raise MissingProductionOriginalV1("original_outbound_commitment_communication_action")
        action_heads = tuple((read.head(db, token, required=True), revision)
            for token, revision in recovered.write_versions
            if AtomKey.from_token(token).type_name == "d08.action_intent.v1")
        if any(atom.revision != revision for atom, revision in action_heads):
            raise ValueError("original commitment communication action changed")
        actions = tuple(_decode_intent(atom.value) for atom, _ in action_heads)
        if (len(actions) != 1 or commitment.commitment_id not in actions[0].commitment_refs
                or actions[0].target_ref != commitment.counterparty_ref
                or request.outbound_receipt_ref not in commitment.communicated_refs):
            raise ValueError("bilateral outbound receipt does not communicate this exact commitment")
        outcome = platform.outcome
        status = "accepted" if outcome in {"accepted", "delivered"} else "known_not_accepted" if outcome == "known_not_accepted" else "unknown"
        current = BilateralAcknowledgementReadV1(frame.envelope.authority.namespace, commitment,
            GraphVersion(atom.key, atom.revision), VersionedRef(request.outbound_receipt_ref, 1), status,
            GraphVersion(source.key, source.revision), GraphVersion(access.key, access.revision),
            commitment.counterparty_ref, commitment.commitment_id, commitment.semantic_scope, "accepted", "full")
        actor = ProductionOriginalRefV1("d03.inbound_actor", entity.key.token,
            canonical_digest((account.value, entity.value)), (GraphVersion(account.key, account.revision), GraphVersion(entity.key, entity.revision)))
        return CurrentBilateralInputsV1(current, acceptance, outbound, actor)

    def _read_intent(self, db, read, ref):
        if not table_exists_v1(db, "graph_d08_joint_plan_intents_v1"):
            raise MissingProductionOriginalV1("joint_plan_intent_original")
        row = db.execute("SELECT producing_operation_id,payload_json,payload_digest,signature FROM graph_d08_joint_plan_intents_v1 "
            "WHERE bot=? AND persona=? AND original_ref=?", (*read.frame.envelope.authority.namespace.as_tuple, ref)).fetchone()
        if row is None:
            raise MissingProductionOriginalV1("joint_plan_intent_original:" + ref)
        self.issuer._signer.verify("d11.d08-joint-plan-intent.v1", row[1], row[3])
        raw = json.loads(row[1])
        if canonical_digest(raw) != row[2] or canonical_serialize(raw) != row[1]:
            raise ValueError("joint plan intent original changed")
        read.committed_operation(db, row[0])
        # Recover nodes through D08's strict typed predicate decoder.
        nodes = []
        from ..domains.d08.execution import _predicate
        for value in raw["nodes"]:
            node = dict(value)
            node["depends_on"] = tuple(node["depends_on"])
            node["success_predicate"] = _predicate(node["success_predicate"])
            nodes.append(PlanNode(**node))
        intent = JointPlanIntentOriginalV1(raw["plan_id"], raw["revision"], tuple(nodes),
            tuple(raw["exit_rules"]), tuple(raw["source_refs"]), tuple(raw["current_goal_refs"]))
        return intent, read.original(ref, kind="d08.joint_plan_intent", digest=row[2])

    def record_joint_plan_intent(self, db, *, frame, original_ref, producing_operation_id, intent):
        """Produce an explicit Owner/D12 plan intent after its admitted command.

        No participant consent or action execution is inferred by this writer.
        """
        if type(intent) is not JointPlanIntentOriginalV1:
            raise TypeError("exact typed Owner/D12 joint plan intent required")
        read = CurrentDomainReadV1(frame)
        read.check(db)
        read.committed_operation(db, producing_operation_id)
        read.source_family(db, intent.source_refs)
        for ref in intent.current_goal_refs:
            goal = read.head(db, ref, required=True)
            if goal.key.type_name != "d08.goal.v1" or goal.value["state"] != "active":
                raise ValueError("joint plan depends on a noncurrent active goal")
        participants = {node.owner_ref for node in intent.nodes}
        if len(participants) < 2:
            raise ValueError("joint plan requires at least two distinct actual parties")
        entities = tuple(atom for atom in read.complete_inventory(db, "d03.entity_anchor") if atom.valid)
        for participant in participants - {"persona:" + frame.envelope.authority.namespace.persona_id}:
            matches = tuple(atom for atom in entities if atom.value.get("entity_id") == participant and atom.value.get("status") == "active")
            if len(matches) != 1:
                raise MissingProductionOriginalV1("exact_joint_plan_participant:" + participant)
        raw = plain_v1(intent)
        encoded, digest = canonical_serialize(raw), canonical_digest(raw)
        expected = (producing_operation_id, encoded, digest,
            self.issuer._signer.sign("d11.d08-joint-plan-intent.v1", encoded), canonical_serialize(intent.source_refs))
        row = db.execute("SELECT producing_operation_id,payload_json,payload_digest,signature,source_refs_json "
            "FROM graph_d08_joint_plan_intents_v1 WHERE bot=? AND persona=? AND original_ref=?",
            (*frame.envelope.authority.namespace.as_tuple, original_ref)).fetchone()
        if row is not None and row != expected:
            raise ValueError("joint plan intent replay conflicts")
        if row is None:
            db.execute("INSERT INTO graph_d08_joint_plan_intents_v1 VALUES(?,?,?,?,?,?,?,?)",
                (*frame.envelope.authority.namespace.as_tuple, original_ref, *expected))
        return ProductionOriginalRefV1("d08.joint_plan_intent", original_ref, digest)

    def _qualify_consent(self, db, read, intent, evidence):
        if (type(evidence) is not PartyConsentEvidenceV1 or evidence.plan_revision != intent.revision
                or evidence.terms_digest != joint_plan_terms_digest_v1(intent)
                or not evidence.accepted_scope or not set(evidence.accepted_scope) <= {node.node_id for node in intent.nodes}
                or evidence.participant_ref not in {node.owner_ref for node in intent.nodes}):
            raise ValueError("party consent terms/revision/responsibility differ")
        interpretation, original, _ = read.adopted_interpretation(db, evidence.acceptance_interpretation_ref,
            question_scope=joint_plan_consent_scope_v1(intent, evidence.participant_ref, evidence.accepted_scope))
        if interpretation.value["proposition"] != "accepted" or evidence.inbound_source_ref not in interpretation.value["source_refs"]:
            raise MissingProductionOriginalV1("explicit_exact_joint_plan_acceptance")
        read.source_family(db, (evidence.inbound_source_ref,))
        if evidence.participant_ref.startswith("entity:"):
            read.actor_entity(db, evidence.inbound_source_ref, expected_entity=evidence.participant_ref)
        elif evidence.participant_ref == "persona:" + read.frame.envelope.authority.namespace.persona_id:
            if not evidence.outbound_receipt_refs:
                raise MissingProductionOriginalV1("actual_persona_joint_plan_acceptance_communication")
            for ref in evidence.outbound_receipt_refs:
                observation, _ = read.adopted_outbound_observation(db, ref)
                if observation.pending.platform_observation.outcome not in {"accepted", "delivered"}:
                    raise MissingProductionOriginalV1("persona_consent_outbound_confirmation")
        else:
            raise ValueError("joint plan party is not current persona or D03 entity")
        return interpretation, original

    def record_party_consent(self, db, *, frame, original_ref, producing_operation_id, evidence):
        """Issue only from an actual current D07 acceptance and D03 actor."""
        read = CurrentDomainReadV1(frame)
        read.check(db)
        read.committed_operation(db, producing_operation_id)
        intent, _ = self._read_intent(db, read, evidence.plan_proposal_ref)
        self._qualify_consent(db, read, intent, evidence)
        encoded, digest = canonical_serialize(plain_v1(evidence)), canonical_digest(plain_v1(evidence))
        expected = (producing_operation_id, evidence.plan_proposal_ref, evidence.participant_ref, evidence.terms_digest,
            encoded, digest, self.issuer._signer.sign("d11.d08-party-consent.v1", encoded),
            canonical_serialize((evidence.inbound_source_ref,)))
        row = db.execute("SELECT producing_operation_id,plan_proposal_ref,participant_ref,terms_digest,payload_json,payload_digest,signature,source_refs_json "
            "FROM graph_d08_party_consents_v1 WHERE bot=? AND persona=? AND original_ref=?",
            (*frame.envelope.authority.namespace.as_tuple, original_ref)).fetchone()
        if row is not None and row != expected:
            raise ValueError("party consent original replay conflicts")
        if row is None:
            db.execute("INSERT INTO graph_d08_party_consents_v1 VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (*frame.envelope.authority.namespace.as_tuple, original_ref, *expected))
        return ProductionOriginalRefV1("d08.party_consent", original_ref, digest)

    def read_joint_plan(self, db, frame, request, *, for_execution=False):
        read = CurrentDomainReadV1(frame)
        read.check(db)
        intent, proposal_original = self._read_intent(db, read, request.joint_plan_proposal_ref)
        read.source_family(db, intent.source_refs)
        goals = tuple(read.head(db, ref, required=True) for ref in intent.current_goal_refs)
        allowed_goal_states = {"active", "satisfied"} if for_execution else {"active"}
        if any(goal.key.type_name != "d08.goal.v1" or goal.value["state"] not in allowed_goal_states for goal in goals):
            raise ValueError("joint plan current goal is no longer active")
        acceptances, originals = [], []
        for ref in request.party_consent_original_refs:
            if not table_exists_v1(db, "graph_d08_party_consents_v1"):
                raise MissingProductionOriginalV1("actual_party_consent_original")
            row = db.execute("SELECT producing_operation_id,plan_proposal_ref,participant_ref,terms_digest,payload_json,payload_digest,signature "
                "FROM graph_d08_party_consents_v1 WHERE bot=? AND persona=? AND original_ref=?", (*frame.envelope.authority.namespace.as_tuple, ref)).fetchone()
            if row is None:
                raise MissingProductionOriginalV1("actual_party_consent_original:" + ref)
            self.issuer._signer.verify("d11.d08-party-consent.v1", row[4], row[6])
            raw = json.loads(row[4])
            if canonical_digest(raw) != row[5] or row[1] != request.joint_plan_proposal_ref or row[3] != joint_plan_terms_digest_v1(intent):
                raise ValueError("party consent does not cover current exact plan terms")
            read.committed_operation(db, row[0])
            raw["accepted_scope"], raw["outbound_receipt_refs"] = tuple(raw["accepted_scope"]), tuple(raw["outbound_receipt_refs"])
            evidence = PartyConsentEvidenceV1(**raw)
            self._qualify_consent(db, read, intent, evidence)
            acceptances.append(JointPlanAcceptance(evidence.participant_ref, intent.revision, evidence.accepted_scope,
                tuple(dict.fromkeys((evidence.inbound_source_ref, *evidence.outbound_receipt_refs)))))
            originals.append(read.original(ref, kind="d08.party_consent", digest=row[5]))
        boundaries = []
        for atom in read.complete_inventory(db, "d05.boundary_rule"):
            if not atom.valid:
                continue
            rule = BoundaryRule(**boundary_tuple(atom.value, "source_refs", "communicated_refs", "acknowledged_refs", "exception_refs"))
            if rule.target_entity_ref in {node.owner_ref for node in intent.nodes}:
                read.source_family(db, rule.source_refs)
                if (rule.effect == "deny" and rule.status == "active" and rule.valid_from <= frame.now_utc
                        and (rule.valid_until is None or frame.now_utc <= rule.valid_until)
                        and rule.action_kind in {node.action_kind for node in intent.nodes}):
                    raise MissingProductionOriginalV1("joint_plan_current_boundary_denies_responsibility")
                boundaries.append(ProductionOriginalRefV1("d05.current_boundary", atom.key.token,
                    canonical_digest(atom.value), (GraphVersion(atom.key, atom.revision),)))
        plan = JointPlan(intent.plan_id, intent.revision, tuple(acceptances), intent.nodes, intent.exit_rules, intent.source_refs)
        return CurrentJointPlanInputsV1(plan, proposal_original, tuple(originals), joint_plan_terms_digest_v1(intent),
                                      intent.current_goal_refs, tuple(boundaries))


def stage_settle_current_observed_action_in_transaction_v1(db, *, frame, request, installed_readers):
    """Record the independently observed effect, without claiming a postcondition."""
    from datetime import datetime
    from ..domains.d08.execution import ActionOutcome
    from .natural_dispatch_current_read_v2 import recover_natural_dispatch_candidate_in_transaction_v2
    if type(installed_readers) is not InstalledD08ProductionReadersV1 or type(request) is not SettleCurrentObservedActionRequestV1:
        raise TypeError("observed outcome needs its installed D08 reader and exact request")
    read = CurrentDomainReadV1(frame)
    try:
        read.check(db)
        action = read.head(db, request.action_intent_ref, required=True)
        intent = _decode_intent(action.value)
        read.source_family(db, intent.source_refs)
        observed, original = read.adopted_outbound_observation(db, request.outbound_receipt_ref)
        platform = observed.pending.platform_observation
        origin = getattr(platform.binding, "origin", platform.binding)
        recovered = recover_natural_dispatch_candidate_in_transaction_v2(db,
            frame.envelope.authority.namespace, origin.operation_id)
        if (recovered is None or (action.key.token, action.revision) not in recovered.write_versions
                or (origin.activity_id, origin.effect_id, origin.attempt_id, origin.operation_id) !=
                   (intent.identity.activity_id, intent.identity.effect_id, intent.identity.attempt_id, intent.identity.operation_id)
                or frame.envelope.identity.activity_id != intent.identity.activity_id
                or frame.envelope.identity.effect_id != intent.identity.effect_id):
            raise ValueError("observed terminal does not belong to the exact adopted action attempt")
        cost = read.head(db, request.cost_settlement_ref, required=True)
        cost_original = read.original(request.cost_settlement_ref)
        if (cost_original.kind != "d11.cost_settlement"
                or (cost.value["activity_id"], cost.value["effect_id"]) !=
                   (intent.identity.activity_id, intent.identity.effect_id)
                or not cost.value["execution_revoked"]):
            raise ValueError("observed effect lacks its actual revoked execution cost settlement")
        level = {"accepted": "accepted", "delivered": "partially_observed", "unknown": "unknown"}[platform.outcome]
        key = observed_action_outcome_key_v1(action.key, intent)
        previous = read.head(db, key)
        outcome = ActionOutcome(key.name, intent.action_id, intent.identity.effect_id,
            intent.identity.attempt_id, level, "platform_observation",
            (request.outbound_receipt_ref, request.cost_settlement_ref), (),
            (intent.identity.effect_id,) if level == "unknown" else (),
            "d08-effect-settlement:" + canonical_digest((intent.action_id,
                intent.identity.effect_id, intent.identity.attempt_id)),
            datetime.fromisoformat(platform.observed_at_utc.replace("Z", "+00:00")).timestamp())
        if previous.revision:
            prior = _decode("d08.action_outcome.v1", previous.value)
            progression = {"unknown": {"unknown", "accepted", "partially_observed"},
                "accepted": {"accepted", "partially_observed"}, "partially_observed": {"partially_observed"}}
            if (not previous.valid or prior.settlement_key != outcome.settlement_key
                    or outcome.observed_at < prior.observed_at
                    or level not in progression.get(prior.result_level, set())):
                raise ValueError("observed action outcome would regress or replace another settlement")
        return compile_settle_current_observed_action_v1(frame, request, intent=intent,
            outcome_key=key, outcome=outcome, observation_original=original, cost_original=cost_original)
    except MissingProductionOriginalV1 as missing:
        return waiting_stage_v1(frame, "d08", "settle_observed_action", request, missing)


def stage_acknowledge_current_bilateral_in_transaction_v1(db, *, frame, request, installed_readers):
    if type(installed_readers) is not InstalledD08ProductionReadersV1:
        raise TypeError("installed D08 readers required")
    try:
        stage = compile_acknowledge_current_bilateral_v1(frame, request, installed_readers.read_bilateral(db, frame, request))
    except MissingProductionOriginalV1 as missing:
        return waiting_stage_v1(frame, "d08", "acknowledge_bilateral", request, missing)
    return verify_d08_production_stage_v1(stage)


def stage_adopt_current_joint_plan_in_transaction_v1(db, *, frame, request, installed_readers):
    if type(installed_readers) is not InstalledD08ProductionReadersV1:
        raise TypeError("installed D08 readers required")
    try:
        stage = compile_adopt_current_joint_plan_v1(frame, request, installed_readers.read_joint_plan(db, frame, request))
    except MissingProductionOriginalV1 as missing:
        return waiting_stage_v1(frame, "d08", "adopt_joint_plan", request, missing)
    return verify_d08_production_stage_v1(stage)


def stage_recheck_current_action_in_transaction_v1(db, *, frame, request, installed_readers):
    if type(installed_readers) is not InstalledD08ProductionReadersV1 or type(request) is not RecheckCurrentActionRequestV1:
        raise TypeError("D08 current recheck needs the installed exact readers/request")
    try:
        read = CurrentDomainReadV1(frame)
        read.check(db)
        ns = frame.envelope.authority.namespace
        action_atom = read.head(db, request.action_intent_ref, required=True)
        intent = _decode_intent(action_atom.value)
        if intent.identity.activity_id != frame.envelope.identity.activity_id:
            raise ValueError("current action recheck activity differs from the actual intent")
        read.source_family(db, intent.source_refs, purpose=intent.purpose)
        inventories = {name: read.complete_inventory(db, name) for name in (
            "d08.action_intent.v1", "d08.action_outcome.v1", "d08.commitment.v1", "d08.action_schema.v1",
            "d08.action_cancellation.v1", "d05.boundary_rule", "d03.role_binding", "d05.relationship_projection")}
        schema_atoms = tuple(atom for atom in inventories["d08.action_schema.v1"] if atom.valid
            and atom.value["action_id"] == intent.action_id and atom.key.owner.subject == intent.identity.activity_id)
        if len(schema_atoms) != 1:
            raise MissingProductionOriginalV1("exact_original_frozen_action_schema")
        record = _decode("d08.action_schema.v1", schema_atoms[0].value)
        schema = ActionSchema(record.schema_id, record.action_kind, record.proactive, record.required_checks)
        if record != ActionSchemaRecord.bind(intent, schema):
            raise ValueError("D08 recheck frozen action/schema identity changed")
        query = QueryEpoch(ns, "all", frame.snapshot.epochs[0].revision)
        from ..domains.d08.action_recovery import project_current_action_recovery_v1
        from .dispatch_current_commitments import read_current_d08_conflict_facts
        recovery = project_current_action_recovery_v1(frame.snapshot, query, intent, namespace=ns)
        facts = read_current_d08_conflict_facts(db, ns, frame.snapshot, query)
        applicable = tuple(item for item in facts.commitments if item.counterparty_ref == intent.target_ref)
        cancellations = tuple(_decode("d08.action_cancellation.v1", atom.value)
            for atom in inventories["d08.action_cancellation.v1"] if atom.valid and atom.value["action_id"] == intent.action_id)
        specs = tuple(item for item in intent.required_checks if item.check_kind == "commitment_conflict"
            and item.provider_id == "d08.commitment_conflict")
        if len(specs) != 1:
            raise ValueError("D08 action lost its unique original commitment-conflict check")
        from .dispatch_current_commitment_check import CRITERIA_REF, CRITERIA_VERSION
        responsive = (not schema.proactive and intent.action_kind in {"message", "communication"}
            and specs[0].criteria_version == CRITERIA_REF
            and any(version.ref == CRITERIA_REF and version.version == CRITERIA_VERSION
                for version in specs[0].required_input_versions))
        missing = tuple(dict.fromkeys((*facts.missing_sources,
            "actual_responsive_p0_p1_p2_admission_and_current_criteria_read" if responsive else
            "registered_d08_criterion_policy_for_exact_general_action_kind_and_scope")))
        observed = CommitmentConflictSnapshot(specs[0].required_input_versions, "partial",
            tuple(item.commitment_id for item in applicable),
            tuple(item.commitment_id for item in applicable if item.fulfillment_state not in {"fulfilled", "withdrawn"}),
            tuple(outcome.effect_id for outcome in facts.action_outcomes if outcome.unknown_effects or outcome.result_level == "unknown"),
            action_ref=intent.action_id, action_revision=intent.revision, intent_digest=canonical_digest(intent),
            schema_id=schema.schema_id, goal_ref=intent.goal_ref, target_ref=intent.target_ref,
            action_kind=intent.action_kind, purpose=intent.purpose, current_read_confirmed=False,
            action_cancelled=any(item.state == "cancelled" for item in cancellations))
        check = GoalExecutionProvider().provide_required_check(intent, schema, observed,
            valid_until=min(frame.envelope.deadline_utc, frame.now_utc + 1.0))
        # `unknown` is an actual provider result from incomplete independent
        # evidence. The current Graph epoch cannot stand in for an Authority
        # effect inventory or a registered semantic conflict criterion.
        if check.result != "unknown" or check.coverage != "partial":
            raise ValueError("D08 incomplete effect/criterion read unexpectedly became a passing check")
        boundaries = tuple(BoundaryRule(**boundary_tuple(atom.value, "source_refs", "communicated_refs",
            "acknowledged_refs", "exception_refs")) for atom in inventories["d05.boundary_rule"] if atom.valid)
        for rule in boundaries:
            read.source_family(db, rule.source_refs, purpose=intent.purpose)
        boundary_check = RelationshipProvider().provide_required_check(subject_persona_ref="persona:" + ns.persona_id,
            target_entity_ref=intent.target_ref, action_kind=intent.action_kind,
            audience_scope=frame.envelope.authority.audience[0], scene_ref=None,
            at_time=frame.now_utc, rules=boundaries, coverage_complete=True)
        originals = tuple(read.original(atom.key.token) for atom in (action_atom, schema_atoms[0]))
        inputs = CurrentActionRecheckInputsV1(recovery, check, boundary_check, intent.required_checks, originals, missing)
        return verify_d08_production_stage_v1(compile_recheck_current_action_v1(frame, request, inputs))
    except MissingProductionOriginalV1 as error:
        return waiting_stage_v1(frame, "d08", "recheck_action", request, error)


prepare_current_bilateral_plan_v1 = stage_adopt_current_joint_plan_in_transaction_v1
adopt_current_bilateral_plan_v1 = stage_adopt_current_joint_plan_in_transaction_v1
D08_PRODUCTION_STORAGE_INVENTORY_V1 = {table: {"namespace_columns": ("bot", "persona"),
    "content_columns": ("payload_json",), "source_closure_column": "source_refs_json",
    "operation_column": "producing_operation_id", "recovery": "revalidate_actual_plan_terms_and_bilateral_evidence"}
    for table in ("graph_d08_joint_plan_intents_v1", "graph_d08_party_consents_v1", "graph_d08_joint_node_originals_v1")}


def read_plan_current_d08_operation_v1(db, *, namespace, activity_id, operation_kind, request):
    from .d01_production_operations_v1 import production_read_plan_v1, raw_registered_input_v1, raw_head_value_v1
    from ..graph_types import Owner, owner_grant_key
    if not db.in_transaction or type(namespace) is not NamespaceId:
        raise ValueError("D08 fixed read planning requires current W01 transaction")
    types = ["d03.entity_anchor", "d03.account_binding", "d05.boundary_rule"]
    keys, roots, originals = [owner_grant_key(*namespace.as_tuple)], [], []
    if operation_kind == "settle_observed_action" and type(request) is SettleCurrentObservedActionRequestV1:
        action_key = AtomKey.from_token(request.action_intent_ref)
        keys.extend((action_key, AtomKey.from_token(request.cost_settlement_ref)))
        originals.extend((request.action_intent_ref, request.cost_settlement_ref, request.outbound_receipt_ref))
        action = raw_head_value_v1(db, namespace, action_key)
        if action:
            intent = _decode_intent(action)
            roots.extend(intent.source_refs)
            keys.append(observed_action_outcome_key_v1(action_key, intent))
        types += ["d08.action_intent.v1", "d08.action_outcome.v1", "runtime.cost_settlement"]
        if table_exists_v1(db, "graph_d13_outbound_observations_v1"):
            roots.extend(row[0] for row in db.execute("SELECT source_ref FROM graph_d13_outbound_observations_v1 "
                "WHERE bot=? AND persona=? AND (source_ref=? OR observation_digest=? OR final_operation_id=?) LIMIT 3",
                (*namespace.as_tuple, request.outbound_receipt_ref, request.outbound_receipt_ref, request.outbound_receipt_ref)))
    elif operation_kind == "recheck_action" and type(request) is RecheckCurrentActionRequestV1:
        keys.append(AtomKey.from_token(request.action_intent_ref))
        types += ["d08.action_intent.v1", "d08.action_outcome.v1", "d08.action_schema.v1", "d08.action_cancellation.v1",
            "d08.commitment.v1", "d08.goal.v1", "d03.role_binding", "d05.relationship_projection", "runtime.cost_settlement"]
        action = raw_head_value_v1(db, namespace, keys[-1])
        originals.append(request.action_intent_ref)
        if action:
            intent = _decode_intent(action)
            roots += list(intent.source_refs)
            from .domain_background_read_v3 import background_inventory_v3
            for schema_atom in background_inventory_v3(db,namespace,'d08.action_schema.v1',valid_only=True):
                if schema_atom.value["action_id"] == intent.action_id:
                    originals.append(schema_atom.key.token)
            for spec in intent.required_checks:
                for version in spec.required_input_versions:
                    try:
                        key = AtomKey.from_token(version.ref)
                    except (ValueError, TypeError):
                        continue
                    keys.append(key)
    elif operation_kind == "acknowledge_bilateral" and type(request) is AcknowledgeCurrentBilateralRequestV1:
        keys.extend(AtomKey.from_token(ref) for ref in (request.commitment_ref, request.inbound_source_ref, request.acceptance_interpretation_ref))
        roots.append(request.inbound_source_ref)
        originals.extend((request.acceptance_interpretation_ref, request.outbound_receipt_ref))
        semantic = raw_head_value_v1(db, namespace, AtomKey.from_token(request.acceptance_interpretation_ref))
        if semantic:
            roots.extend(semantic["source_refs"])
        if table_exists_v1(db, "graph_d13_outbound_observations_v1"):
            rows = db.execute("SELECT final_operation_id,source_ref FROM graph_d13_outbound_observations_v1 "
                "WHERE bot=? AND persona=? AND (source_ref=? OR observation_digest=? OR final_operation_id=?) LIMIT 3",
                (*namespace.as_tuple, request.outbound_receipt_ref, request.outbound_receipt_ref, request.outbound_receipt_ref)).fetchall()
            for operation, source in rows:
                roots.append(source)
                if table_exists_v1(db, "graph_bundle_operations"):
                    row = db.execute("SELECT receipt_json FROM graph_bundle_operations WHERE bot=? AND persona=? AND operation_id=?",
                                     (*namespace.as_tuple, operation)).fetchone()
                    if row:
                        candidate = json.loads(row[0]).get("natural_dispatch_candidate", {})
                        keys.extend(AtomKey.from_token(ref) for ref, _ in candidate.get("refs", ()))
    elif operation_kind == "adopt_joint_plan" and type(request) is AdoptCurrentJointPlanRequestV1:
        originals.extend((request.joint_plan_proposal_ref, *request.party_consent_original_refs))
        intent = raw_registered_input_v1(db, "graph_d08_joint_plan_intents_v1", namespace, request.joint_plan_proposal_ref)
        if intent:
            roots.extend(intent["source_refs"])
            keys.extend(AtomKey.from_token(ref) for ref in intent["current_goal_refs"])
            keys.append(AtomKey(Owner("activity", *namespace.as_tuple, activity_id), "d08.joint_plan.v1", intent["plan_id"]))
            for node in intent["nodes"]:
                participant = node["owner_ref"]
                if participant.startswith("entity:"):
                    key = AtomKey(Owner("persona", *namespace.as_tuple), "d03.entity_anchor", participant)
                    keys.append(key)
                    entity = raw_head_value_v1(db, namespace, key)
                    if entity:
                        roots.extend(entity["creation_evidence_refs"])
        for ref in request.party_consent_original_refs:
            consent = raw_registered_input_v1(db, "graph_d08_party_consents_v1", namespace, ref)
            if consent:
                roots.append(consent["inbound_source_ref"])
                keys.append(AtomKey.from_token(consent["acceptance_interpretation_ref"]))
                originals.extend((consent["acceptance_interpretation_ref"], *consent["outbound_receipt_refs"]))
                semantic = raw_head_value_v1(db, namespace, AtomKey.from_token(consent["acceptance_interpretation_ref"]))
                if semantic:
                    roots.extend(semantic["source_refs"])
    else:
        raise ValueError("unregistered exact D08 production request")
    return production_read_plan_v1(types, keys, roots, originals)
