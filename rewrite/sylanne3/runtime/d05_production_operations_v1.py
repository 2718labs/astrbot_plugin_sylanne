"""Installed D05 readers, with exact object, family and bilateral evidence."""
from __future__ import annotations

from dataclasses import dataclass
import json

from ..domains.d01.production_operations_v1 import plain_v1
from ..domains.d03.context import ContextProvider, EntityAnchor, WorldEvent, _tuple_payload as d03_tuple
from ..domains.d05.production_operations_v1 import (
    AdoptCurrentRelationshipContributionRequestV1, CurrentBoundaryInputsV1,
    CurrentRelationshipContributionInputsV1, ReevaluateCurrentRelationshipRequestV1,
    ReviseCurrentBoundaryRequestV1, compile_adopt_current_relationship_contribution_v1,
    compile_reevaluate_current_relationship_v1, compile_revise_current_boundary_v1,
    verify_d05_production_stage_v1,
)
from ..domains.d05.relationship import BoundaryRule, RelationshipContribution, _tuple_payload
from ..graph_types import AtomKey, Owner
from ..memory_types import SourceRecord
from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize
from .d01_production_operations_v1 import CurrentDomainReadV1, MissingProductionOriginalV1, table_exists_v1, waiting_stage_v1
from .domain_production_contracts_v1 import ProductionOriginalRefV1
from .issuers import D11BudgetJobIssuer


@dataclass(frozen=True, slots=True)
class InstalledRelationshipPolicyV1:
    policy_ref: str
    revision: int
    namespace: NamespaceId
    dimensions: tuple[str, ...]
    semantics: tuple[str, ...]
    boundary_bases: tuple[str, ...]

    def __post_init__(self):
        if (type(self.namespace) is not NamespaceId or not self.policy_ref
                or type(self.revision) is not int or self.revision < 1
                or type(self.dimensions) is not tuple or not self.dimensions
                or len(set(self.dimensions)) != len(self.dimensions)
                or any(type(item) is not str or not item for item in self.dimensions)
                or type(self.semantics) is not tuple or not self.semantics
                or not set(self.semantics) <= {"external_observation", "recollection", "simulation"}
                or type(self.boundary_bases) is not tuple or not self.boundary_bases
                or not set(self.boundary_bases) <= {"runtime_policy", "counterparty_explicit", "self_internal", "mutual_agreement", "inferred_preference"}):
            raise ValueError("relationship policy requires explicitly installed dimensions and semantics")


@dataclass(frozen=True, slots=True)
class BoundaryIntentOriginalV1:
    boundary_ref: str
    expected_scope_version: int
    next_rule: BoundaryRule
    acceptance_interpretation_refs: tuple[str, ...]
    outbound_receipt_refs: tuple[str, ...]

    def __post_init__(self):
        if (type(self.next_rule) is not BoundaryRule or type(self.expected_scope_version) is not int
                or self.expected_scope_version < 0
                or type(self.acceptance_interpretation_refs) is not tuple
                or type(self.outbound_receipt_refs) is not tuple):
            raise ValueError("boundary intent requires typed next rule and exact evidence locators")
        AtomKey.from_token(self.boundary_ref)


def boundary_consent_scope_v1(rule):
    return "d05.boundary-consent:" + canonical_digest({name: getattr(rule, name) for name in (
        "rule_id", "subject_persona_ref", "target_entity_ref", "action_kind", "audience_scope",
        "scene_ref", "effect", "valid_from", "valid_until", "scope_version")})


def install_d05_production_schema_v1(db):
    if db.in_transaction:
        raise ValueError("install D05 production schemas before runtime transactions")
    db.execute("CREATE TABLE IF NOT EXISTS graph_d05_production_policies_v1 ("
        "bot TEXT NOT NULL,persona TEXT NOT NULL,policy_ref TEXT NOT NULL,revision INTEGER NOT NULL,"
        "payload_json TEXT NOT NULL,payload_digest TEXT NOT NULL,signature TEXT NOT NULL,"
        "PRIMARY KEY(bot,persona,policy_ref,revision))")
    db.execute("CREATE TABLE IF NOT EXISTS graph_d05_boundary_intents_v1 ("
        "bot TEXT NOT NULL,persona TEXT NOT NULL,original_ref TEXT NOT NULL,producing_operation_id TEXT NOT NULL,"
        "payload_json TEXT NOT NULL,payload_digest TEXT NOT NULL,signature TEXT NOT NULL,source_refs_json TEXT NOT NULL,"
        "PRIMARY KEY(bot,persona,original_ref))")


class InstalledD05ProductionReadersV1:
    def __init__(self, *, issuer):
        if type(issuer) is not D11BudgetJobIssuer:
            raise TypeError("D05 requires the installed D11 input/policy issuer")
        self.issuer = issuer

    def install_policy(self, db, *, frame, policy):
        if type(policy) is not InstalledRelationshipPolicyV1 or policy.namespace != frame.envelope.authority.namespace:
            raise TypeError("exact namespace D05 policy required")
        CurrentDomainReadV1(frame).check(db)
        raw = plain_v1(policy)
        encoded, digest = canonical_serialize(raw), canonical_digest(raw)
        pin = tuple(item for item in frame.installed_policy_refs if item.policy_ref == policy.policy_ref and item.revision == policy.revision)
        if len(pin) != 1 or (pin[0].revision, pin[0].policy_digest) != (policy.revision, digest):
            raise ValueError("D05 policy lacks current installation selection")
        expected = (encoded, digest, self.issuer._signer.sign("d11.d05-production-policy.v1", encoded))
        row = db.execute("SELECT payload_json,payload_digest,signature FROM graph_d05_production_policies_v1 "
            "WHERE bot=? AND persona=? AND policy_ref=? AND revision=?",
            (*policy.namespace.as_tuple, policy.policy_ref, policy.revision)).fetchone()
        if row is not None and row != expected:
            raise ValueError("D05 policy replay conflicts")
        if row is None:
            maximum = db.execute("SELECT max(revision) FROM graph_d05_production_policies_v1 WHERE bot=? AND persona=? AND policy_ref=?",
                (*policy.namespace.as_tuple, policy.policy_ref)).fetchone()[0]
            if policy.revision != (maximum or 0) + 1:
                raise ValueError("D05 installed policy revision must advance its actual predecessor")
            db.execute("INSERT INTO graph_d05_production_policies_v1 VALUES(?,?,?,?,?,?,?)",
                (*policy.namespace.as_tuple, policy.policy_ref, policy.revision, *expected))

    def _policy(self, db, read, policy_ref):
        pin = tuple(item for item in read.frame.installed_policy_refs if item.policy_ref == policy_ref)
        if len(pin) != 1 or not table_exists_v1(db, "graph_d05_production_policies_v1"):
            raise MissingProductionOriginalV1("installed_relationship_policy:" + policy_ref)
        row = db.execute("SELECT payload_json,payload_digest,signature FROM graph_d05_production_policies_v1 "
            "WHERE bot=? AND persona=? AND policy_ref=? AND revision=?",
            (*read.frame.envelope.authority.namespace.as_tuple, policy_ref, pin[0].revision)).fetchone()
        if row is None:
            raise MissingProductionOriginalV1("signed_relationship_policy:" + policy_ref)
        self.issuer._signer.verify("d11.d05-production-policy.v1", row[0], row[2])
        raw = json.loads(row[0])
        if canonical_digest(raw) != row[1] or row[1] != pin[0].policy_digest or canonical_serialize(raw) != row[0]:
            raise ValueError("D05 installed policy changed")
        raw["namespace"] = NamespaceId(**raw["namespace"])
        for name in ("dimensions", "semantics", "boundary_bases"):
            raw[name] = tuple(raw[name])
        policy = InstalledRelationshipPolicyV1(**raw)
        return policy, ProductionOriginalRefV1("d05.installed_policy", policy_ref, row[1])

    def _entity(self, db, read, entity):
        entities = tuple(atom for atom in read.complete_inventory(db, "d03.entity_anchor")
            if atom.valid and atom.value.get("entity_id") == entity and atom.value.get("status") == "active")
        if len(entities) != 1:
            raise MissingProductionOriginalV1("unique_current_d03_relationship_entity")
        atom = entities[0]
        anchor = EntityAnchor(**d03_tuple(atom.value, "creation_evidence_refs"))
        read.source_family(db, anchor.creation_evidence_refs)
        return ProductionOriginalRefV1("d03.entity", atom.key.token, canonical_digest(atom.value),
                                      (next(version for version in read.frame.snapshot.versions if version.key == atom.key),))

    def read_contribution(self, db, frame, request):
        read = CurrentDomainReadV1(frame)
        read.check(db)
        policy, policy_original = self._policy(db, read, request.policy_ref)
        entity = self._entity(db, read, request.subject_entity_ref)
        trigger = read.original(request.trigger_original_ref)
        key = AtomKey.from_token(request.trigger_original_ref)
        atom = read.head(db, key, required=True)
        actual_host_event = False
        if key.type_name == "memory.source":
            roots = (key.token,)
            records = read.source_family(db, roots)
            source = records[key.token]
            read.actor_entity(db, key.token, expected_entity=request.subject_entity_ref)
        elif key.type_name == "d03.world_event":
            event = WorldEvent(**d03_tuple(atom.value, "participant_roles", "source_refs"))
            if request.subject_entity_ref not in {entity for entity, _ in event.participant_roles}:
                raise ValueError("relationship event does not involve the target entity")
            roots = event.source_refs
            records = read.source_family(db, roots)
            source = records[roots[0]]
            actual_host_event = event.kind == "message_received" and event.reality == "host_observed"
        elif key.type_name == "d06.recollection.v1":
            if trigger.kind != "d06.adopted_recollection":
                raise MissingProductionOriginalV1("actual_adopted_recollection_trigger")
            roots = tuple(atom.value.get("source_refs", ()))
            records = read.source_family(db, roots)
            source = records[roots[0]]
        elif key.type_name == "d07.simulation_branch.v1":
            if trigger.kind != "d07.adopted_simulation":
                raise MissingProductionOriginalV1("actual_adopted_simulation_trigger")
            roots = tuple(atom.value.get("snapshot_refs", ()))
            records = read.source_family(db, roots)
            source = records[roots[0]]
        else:
            raise ValueError("relationship trigger is not a registered real event/activity original")
        if request.semantics == "external_observation" and not (
                (source.source_kind == "observed" and source.assertion_status == "confirmed")
                or (actual_host_event and source.source_kind in {"observed", "reported"}
                    and source.assertion_status in {"confirmed", "reported"})):
            raise ValueError("authored/recalled/simulated sources cannot become external relationship observation")
        if request.semantics == "recollection" and key.type_name != "d06.recollection.v1":
            raise ValueError("recollection semantics need actual adopted recollection")
        if request.semantics == "simulation" and key.type_name != "d07.simulation_branch.v1":
            raise ValueError("simulation semantics need actual adopted hypothetical branch")
        item = RelationshipContribution("persona:" + frame.envelope.authority.namespace.persona_id,
            source.provenance_root, request.subject_entity_ref, request.dimension, request.semantics, 1, roots)
        read.complete_inventory(db, "d05.contribution")
        read.complete_inventory(db, "d05.relationship_projection")
        item_key = AtomKey(Owner("relation", *frame.envelope.authority.namespace.as_tuple, request.subject_entity_ref),
                           "d05.contribution", item.key)
        prior_atom = read.head(db, item_key)
        prior = RelationshipContribution(**_tuple_payload(prior_atom.value, "source_refs")) if prior_atom.valid else None
        if prior is not None:
            item = item.with_revision(prior.contribution_revision)
            if item != prior:
                item = item.with_revision(prior.contribution_revision + 1)
        return CurrentRelationshipContributionInputsV1(item, policy.dimensions, policy.semantics,
            trigger, policy_original, entity, prior)

    def record_boundary_intent(self, db, *, frame, original_ref, producing_operation_id, intent):
        if type(intent) is not BoundaryIntentOriginalV1:
            raise TypeError("exact typed boundary intent required")
        read = CurrentDomainReadV1(frame)
        read.check(db)
        read.committed_operation(db, producing_operation_id)
        read.source_family(db, intent.next_rule.source_refs)
        raw = plain_v1(intent)
        encoded, digest = canonical_serialize(raw), canonical_digest(raw)
        expected = (producing_operation_id, encoded, digest, self.issuer._signer.sign("d11.d05-boundary-intent.v1", encoded),
                    canonical_serialize(intent.next_rule.source_refs))
        row = db.execute("SELECT producing_operation_id,payload_json,payload_digest,signature,source_refs_json "
            "FROM graph_d05_boundary_intents_v1 WHERE bot=? AND persona=? AND original_ref=?",
            (*frame.envelope.authority.namespace.as_tuple, original_ref)).fetchone()
        if row is not None and row != expected:
            raise ValueError("D05 boundary intent original replay conflicts")
        if row is None:
            db.execute("INSERT INTO graph_d05_boundary_intents_v1 VALUES(?,?,?,?,?,?,?,?)",
                (*frame.envelope.authority.namespace.as_tuple, original_ref, *expected))
        return ProductionOriginalRefV1("d05.boundary_intent", original_ref, digest)

    def read_boundary(self, db, frame, request):
        read = CurrentDomainReadV1(frame)
        read.check(db)
        policy, policy_original = self._policy(db, read, request.policy_ref)
        if not table_exists_v1(db, "graph_d05_boundary_intents_v1"):
            raise MissingProductionOriginalV1("actual_boundary_intent_original")
        row = db.execute("SELECT producing_operation_id,payload_json,payload_digest,signature "
            "FROM graph_d05_boundary_intents_v1 WHERE bot=? AND persona=? AND original_ref=?",
            (*frame.envelope.authority.namespace.as_tuple, request.intent_original_ref)).fetchone()
        if row is None:
            raise MissingProductionOriginalV1("actual_boundary_intent_original:" + request.intent_original_ref)
        self.issuer._signer.verify("d11.d05-boundary-intent.v1", row[1], row[3])
        raw = json.loads(row[1])
        if canonical_digest(raw) != row[2] or canonical_serialize(raw) != row[1]:
            raise ValueError("D05 boundary intent bytes changed")
        read.committed_operation(db, row[0])
        original = read.original(request.intent_original_ref, kind="d05.boundary_intent", digest=row[2])
        if raw["boundary_ref"] != request.boundary_ref:
            raise ValueError("boundary intent targets another key")
        rule = BoundaryRule(**_tuple_payload(raw["next_rule"], "source_refs", "communicated_refs", "acknowledged_refs", "exception_refs"))
        if rule.basis not in policy.boundary_bases:
            raise ValueError("boundary basis is not in current installed policy")
        self._entity(db, read, rule.target_entity_ref)
        read.complete_inventory(db, "d05.boundary_rule")
        prior_atom = read.head(db, request.boundary_ref)
        prior = BoundaryRule(**_tuple_payload(prior_atom.value, "source_refs", "communicated_refs", "acknowledged_refs", "exception_refs")) if prior_atom.valid else None
        if (raw["expected_scope_version"] != (prior.scope_version if prior else 0)
                or rule.scope_version != prior_atom.revision + 1):
            raise ValueError("boundary intent is stale")
        records = read.source_family(db, rule.source_refs)
        consent_originals = []
        if rule.basis in {"counterparty_explicit", "mutual_agreement"}:
            refs = tuple(raw["acceptance_interpretation_refs"])
            if not refs:
                raise MissingProductionOriginalV1("explicit_current_boundary_acceptance")
            accepted_sources = set()
            for ref in refs:
                interpretation, acceptance, _ = read.adopted_interpretation(db, ref,
                    question_scope=boundary_consent_scope_v1(rule))
                if interpretation.value["proposition"] != "accepted":
                    raise MissingProductionOriginalV1("explicit_boundary_acceptance_result")
                accepted_sources.update(interpretation.value["source_refs"])
                consent_originals.append(acceptance)
            if not set(rule.acknowledged_refs) <= accepted_sources or not rule.acknowledged_refs:
                raise ValueError("boundary acknowledgement source differs from actual accepted scope")
            for ref in rule.acknowledged_refs:
                read.actor_entity(db, ref, expected_entity=rule.target_entity_ref)
            if rule.basis == "mutual_agreement":
                if set(raw["outbound_receipt_refs"]) != set(rule.communicated_refs) or not rule.communicated_refs:
                    raise MissingProductionOriginalV1("actual_bilateral_boundary_outbound_receipt")
                for ref in rule.communicated_refs:
                    observation, outward = read.adopted_outbound_observation(db, ref)
                    if observation.pending.platform_observation.outcome not in {"accepted", "delivered"}:
                        raise MissingProductionOriginalV1("boundary_outbound_handoff_confirmation")
                    consent_originals.append(outward)
        return CurrentBoundaryInputsV1(rule, prior, original, policy_original, tuple(consent_originals),
                                       policy.dimensions, policy.semantics)


def stage_adopt_current_relationship_contribution_in_transaction_v1(db, *, frame, request, installed_readers):
    if type(installed_readers) is not InstalledD05ProductionReadersV1:
        raise TypeError("installed D05 readers required")
    try:
        stage = compile_adopt_current_relationship_contribution_v1(frame, request,
            installed_readers.read_contribution(db, frame, request))
    except MissingProductionOriginalV1 as missing:
        return waiting_stage_v1(frame, "d05", "adopt_relationship_contribution", request, missing)
    return verify_d05_production_stage_v1(stage)


def stage_revise_current_boundary_in_transaction_v1(db, *, frame, request, installed_readers):
    if type(installed_readers) is not InstalledD05ProductionReadersV1:
        raise TypeError("installed D05 readers required")
    try:
        stage = compile_revise_current_boundary_v1(frame, request, installed_readers.read_boundary(db, frame, request))
    except MissingProductionOriginalV1 as missing:
        return waiting_stage_v1(frame, "d05", "revise_boundary", request, missing)
    return verify_d05_production_stage_v1(stage)


def stage_reevaluate_current_relationship_in_transaction_v1(db, *, frame, request, installed_readers):
    if type(installed_readers) is not InstalledD05ProductionReadersV1:
        raise TypeError("installed D05 readers required")
    read = CurrentDomainReadV1(frame)
    try:
        read.check(db)
        correction = read.head(db, request.correction_head_ref, required=True)
        read.source_family(db, (correction.value["correction_source_ref"],), allow_corrected=True)
        for type_name in ("d05.boundary_rule", "d05.contribution", "d05.relationship_projection"):
            read.complete_inventory(db, type_name)
        stage = compile_reevaluate_current_relationship_v1(frame, request)
    except MissingProductionOriginalV1 as missing:
        return waiting_stage_v1(frame, "d05", "reevaluate_relationship", request, missing)
    return verify_d05_production_stage_v1(stage)


D05_PRODUCTION_STORAGE_INVENTORY_V1 = {
    "graph_d05_production_policies_v1": {"namespace_columns": ("bot", "persona"), "content_columns": ("payload_json",),
        "recovery": "revalidate_signed_installed_policy"},
    "graph_d05_boundary_intents_v1": {"namespace_columns": ("bot", "persona"), "content_columns": ("payload_json",),
        "source_closure_column": "source_refs_json", "operation_column": "producing_operation_id",
        "recovery": "revalidate_producing_operation_and_actual_bilateral_scope"}}


def read_plan_current_d05_operation_v1(db, *, namespace, activity_id, operation_kind, request):
    from .d01_production_operations_v1 import production_read_plan_v1, raw_registered_input_v1, raw_head_value_v1
    from ..graph_types import owner_grant_key
    if not db.in_transaction or type(namespace) is not NamespaceId:
        raise ValueError("D05 fixed read plan requires current W01 transaction")
    keys, roots, originals = [owner_grant_key(*namespace.as_tuple)], [], []
    types = ["d03.entity_anchor", "d03.account_binding", "d05.contribution", "d05.boundary_rule", "d05.relationship_projection"]
    if operation_kind == "adopt_relationship_contribution" and type(request) is AdoptCurrentRelationshipContributionRequestV1:
        originals.extend((request.trigger_original_ref, request.policy_ref))
        trigger_key = AtomKey.from_token(request.trigger_original_ref)
        keys.append(trigger_key)
        trigger = raw_head_value_v1(db, namespace, trigger_key)
        if trigger:
            refs = (trigger_key.token,) if trigger_key.type_name == "memory.source" else tuple(trigger.get("source_refs", trigger.get("snapshot_refs", ())))
            roots.extend(refs)
            source = raw_head_value_v1(db, namespace, AtomKey.from_token(refs[0])) if refs else None
            if source:
                contribution = RelationshipContribution("persona:" + namespace.persona_id, source["provenance_root"],
                    request.subject_entity_ref, request.dimension, request.semantics, 1, refs)
                owner = Owner("relation", *namespace.as_tuple, request.subject_entity_ref)
                keys.extend((AtomKey(owner, "d05.contribution", contribution.key),
                             AtomKey(owner, "d05.relationship_projection", request.dimension)))
        entity_key = AtomKey(Owner("persona", *namespace.as_tuple), "d03.entity_anchor", request.subject_entity_ref)
        keys.append(entity_key)
        entity = raw_head_value_v1(db, namespace, entity_key)
        if entity:
            roots.extend(entity["creation_evidence_refs"])
    elif operation_kind == "revise_boundary" and type(request) is ReviseCurrentBoundaryRequestV1:
        keys.append(AtomKey.from_token(request.boundary_ref))
        originals.extend((request.intent_original_ref, request.policy_ref))
        intent = raw_registered_input_v1(db, "graph_d05_boundary_intents_v1", namespace, request.intent_original_ref)
        if intent:
            roots.extend(intent["next_rule"]["source_refs"])
            originals.extend((*intent["acceptance_interpretation_refs"], *intent["outbound_receipt_refs"]))
            keys.extend(AtomKey.from_token(ref) for ref in intent["acceptance_interpretation_refs"])
            for ref in intent["acceptance_interpretation_refs"]:
                semantic = raw_head_value_v1(db, namespace, AtomKey.from_token(ref))
                if semantic:
                    roots.extend(semantic["source_refs"])
    elif operation_kind == "reevaluate_relationship" and type(request) is ReevaluateCurrentRelationshipRequestV1:
        key = AtomKey.from_token(request.correction_head_ref)
        keys.append(key)
        head = raw_head_value_v1(db, namespace, key)
        if head:
            keys.extend(AtomKey.from_token(head[name]) for name in ("source_ref", "correction_source_ref"))
            # The correction compiler preserves old history; the current
            # correction source and every parent still need their access read.
            roots.append(head["correction_source_ref"])
    else:
        raise ValueError("unregistered exact D05 production request")
    return production_read_plan_v1(types, keys, roots, originals)
