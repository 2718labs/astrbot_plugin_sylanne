"""Installed D05 readers, with exact object, family and bilateral evidence."""
from __future__ import annotations

from dataclasses import dataclass, replace
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
from ..domains.d05.relationship import (BoundaryRule, RelationshipContribution, _tuple_payload,
    CONTRIBUTION_KINDS_V2, decode_relationship_contribution_payload_v1)
from ..domains.d05.relationship_revision_v2 import InstalledRelationshipPolicyV2
from ..graph_types import AtomKey, Owner, GraphAtom, GraphSnapshot, GraphVersion, NamespaceEpoch
from ..memory_types import SourceRecord, access_key, source_key
from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize
from .d01_production_operations_v1 import CurrentDomainReadV1, MissingProductionOriginalV1, table_exists_v1, waiting_stage_v1
from .domain_production_contracts_v1 import ProductionOriginalRefV1
from .issuers import D11BudgetJobIssuer


@dataclass(frozen=True, slots=True)
class D05CatalogueMigrationReadV2:
    snapshot: GraphSnapshot
    batch_tokens: tuple[str, ...]
    authenticated_recollections: tuple
    legacy_consumed_keys: tuple[str, ...]
    source_catalogue_hash: str
    next_after: str | None


def collect_d05_catalogue_migration_batch_v2(db, namespace, after_token=None, limit=16):
    """Read real heads/receipts in maintenance's transaction; no writes or grant."""
    import hashlib
    from ..contracts import canonical_json
    from ..domains.d06 import source_correction_head_key
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    from .domain_production_read_plans_v1 import read_d05_recollection_migration_material_v2
    if not db.in_transaction or type(namespace) is not NamespaceId or type(limit) is not int or not 1 <= limit <= 32:
        raise ValueError("D05 migration collector needs one bounded maintenance transaction")
    catalogue_rows = db.execute("SELECT c.name,c.owner_kinds,c.storage_role,c.immutable,c.schema_version,a.writer_domain,a.schema_hash "
        "FROM graph_type_catalog c JOIN graph_type_authority a ON a.name=c.name ORDER BY c.name").fetchall()
    catalogue_hash = hashlib.sha256(canonical_json([[name, json.loads(owners), storage, bool(immutable), version,
        writer or None, digest or None] for name, owners, storage, immutable, version, writer, digest in catalogue_rows]).encode()).hexdigest()
    if catalogue_hash not in {"6a05fc901a3c45696faaab63746a6bf795db79282c6be7fdc8bffb6c228a71d1",
            "fb3c44ee4ce9bf85325bb445b891144929aea14d6d7d722f6004d4df817f4f8f"}:
        raise ValueError("D05 migration collector source catalogue is not registered")
    rows = db.execute("SELECT token FROM graph_atoms WHERE bot=? AND persona=? "
        "AND type_name IN ('d05.contribution','d05.relationship_projection') AND token>? ORDER BY token LIMIT ?",
        (*namespace.as_tuple, after_token or "", limit + 1)).fetchall()
    batch_tokens = tuple(row[0] for row in rows[:limit])
    atoms, materials, consumed = {}, [], set()

    def head(key):
        if NamespaceId.from_key(key) != namespace:
            raise ValueError("D05 migration closure crossed namespace")
        if key not in atoms:
            if len(atoms) >= 1024:
                raise MissingProductionOriginalV1("bounded_d05_catalogue_migration_closure")
            row = db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=? AND bot=? AND persona=?",
                (key.token, *namespace.as_tuple)).fetchone()
            atoms[key] = GraphAtom(key, row[0], json.loads(row[1]), bool(row[2])) if row else GraphAtom(key, 0, {}, False)
        return atoms[key]

    groups = set()
    for token in batch_tokens:
        atom = head(AtomKey.from_token(token))
        dimension = atom.value["target_dimension"] if atom.key.type_name == "d05.contribution" else atom.value["dimension"]
        groups.add((atom.key.owner.subject, dimension))
    # A projection's complete current dimension inventory is a negative-read
    # guard. It must not qualify only the first family's convenient row.
    contribution_keys = set()
    for subject, dimension in sorted(groups):
        current = db.execute("SELECT token FROM graph_atoms WHERE bot=? AND persona=? AND type_name='d05.contribution' "
            "AND subject=? AND json_extract(value,'$.target_dimension')=? ORDER BY token LIMIT 129",
            (*namespace.as_tuple, subject, dimension)).fetchall()
        if len(current) > 128:
            raise MissingProductionOriginalV1("bounded_d05_catalogue_dimension_inventory")
        contribution_keys.update(AtomKey.from_token(row[0]) for row in current)
    contributions = tuple(head(key) for key in sorted(contribution_keys, key=lambda item: item.token))
    roots = tuple(dict.fromkeys(ref for atom in contributions for ref in atom.value["source_refs"]))
    seen, pending = set(), list(roots)
    while pending:
        ref = pending.pop()
        if ref in seen:
            continue
        seen.add(ref)
        key = AtomKey.from_token(ref)
        if key != source_key(*namespace.as_tuple, key.owner.subject):
            raise ValueError("D05 migration closure contains another source type")
        source = head(key)
        head(access_key(*namespace.as_tuple, key.owner.subject))
        head(source_correction_head_key(namespace, key.owner.subject))
        if source.revision:
            record = SourceRecord.from_dict(source.value)
            pending.extend(source_key(*namespace.as_tuple, parent).token for parent in record.parent_source_ids)
    for atom in contributions:
        if atom.value.get("schema_version", 1) != 1:
            continue
        old = decode_relationship_contribution_payload_v1(atom.value)
        if not table_exists_v1(db, "graph_domain_production_originals_v1"):
            continue
        operations = db.execute("SELECT operation_id FROM graph_domain_production_originals_v1 WHERE bot=? AND persona=? "
            "AND domain='d05' AND operation_kind='adopt_relationship_contribution' "
            "AND json_extract(original_payload_json,'$.provenance.contribution.canonical_event_or_family_ref')=? "
            "AND json_extract(original_payload_json,'$.provenance.contribution.subject_entity_ref')=? "
            "AND json_extract(original_payload_json,'$.provenance.contribution.target_dimension')=? "
            "AND json_extract(original_payload_json,'$.provenance.contribution.semantics')=? LIMIT 129",
            (*namespace.as_tuple, old.canonical_event_or_family_ref, old.subject_entity_ref, old.target_dimension, old.semantics)).fetchall()
        if len(operations) > 128:
            raise MissingProductionOriginalV1("bounded_d05_catalogue_original_history")
        for (operation,) in operations:
            saved = read_adopted_domain_operation_v1(db, namespace, operation)
            provenance = saved["payload"]["provenance"]
            observed = decode_relationship_contribution_payload_v1(provenance["contribution"])
            if observed.key != atom.key.name:
                raise ValueError("D05 migration actual original targets another contribution")
            if not provenance["duplicate"] and any(version.key == atom.key for version in saved["receipt"].write_versions):
                consumed.add(atom.key.token)
            if old.semantics == "recollection":
                try:
                    material = read_d05_recollection_migration_material_v2(db, namespace,
                        provenance["trigger"]["original_ref"], legacy_source_token=atom.key.token)
                except MissingProductionOriginalV1:
                    continue
                if set(material.content_source_refs) != set(observed.source_refs):
                    raise ValueError("D05 legacy original differs from actual recollection content sources")
                materials.append(material)
                head(material.write_version.key)
                rebuilt = replace(old, canonical_event_or_family_ref=material.canonical_activity_identity)
                head(AtomKey(atom.key.owner, atom.key.type_name, rebuilt.key))
    epoch = db.execute("SELECT revision FROM graph_epochs WHERE bot=? AND persona=?", namespace.as_tuple).fetchone()
    snapshot = GraphSnapshot(tuple(atoms[key] for key in sorted(atoms, key=lambda item: item.token)),
        (NamespaceEpoch(*namespace.as_tuple, epoch[0] if epoch else 0),))
    return D05CatalogueMigrationReadV2(snapshot, batch_tokens, tuple(materials), tuple(sorted(consumed)), catalogue_hash,
        batch_tokens[-1] if len(rows) > limit else None)


def _relationship_trigger_sources_v1(namespace, key, value):
    if key.type_name == "memory.source":
        return (key.token,)
    if key.type_name == "d06.recollection.v1":
        # D06 content_refs are source IDs, while activity_basis_refs name the
        # selection ticket/candidate set. The latter are not external sources.
        return tuple(source_key(*namespace.as_tuple, ref).token for ref in value["content_refs"])
    return tuple(value.get("source_refs", value.get("snapshot_refs", ())))


def _relationship_canonical_identity_v1(db, namespace, request, roots, source):
    if request.semantics != "recollection":
        return source.provenance_root, ()
    from .domain_production_read_plans_v1 import read_committed_recollection_original_v1
    _, identity = read_committed_recollection_original_v1(db, namespace, request.trigger_original_ref)
    legacy = RelationshipContribution("persona:" + namespace.persona_id, source.provenance_root,
        request.subject_entity_ref, request.dimension, request.semantics, 1, roots)
    legacy_key = AtomKey(Owner("relation", *namespace.as_tuple, request.subject_entity_ref), "d05.contribution", legacy.key)
    row = db.execute("SELECT revision FROM graph_atoms WHERE token=?", (legacy_key.token,)).fetchone()
    if row is None:
        return identity, ()
    # Preserve the consumed legacy key as an authenticated identity alias;
    # signed originals and graph history are never rewritten. Multiple old
    # activities collapsed into this key require an explicit scoped migration.
    if not table_exists_v1(db, "graph_domain_production_originals_v1"):
        return identity, ()
    rows = db.execute("SELECT operation_id FROM graph_domain_production_originals_v1 WHERE bot=? AND persona=? "
        "AND domain='d05' AND operation_kind='adopt_relationship_contribution' "
        "AND json_extract(original_payload_json,'$.provenance.contribution.canonical_event_or_family_ref')=? "
        "AND json_extract(original_payload_json,'$.provenance.contribution.subject_entity_ref')=? "
        "AND json_extract(original_payload_json,'$.provenance.contribution.target_dimension')=? "
        "AND json_extract(original_payload_json,'$.provenance.contribution.semantics')='recollection' LIMIT 129",
        (*namespace.as_tuple, source.provenance_root, request.subject_entity_ref, request.dimension)).fetchall()
    if len(rows) > 128:
        raise MissingProductionOriginalV1("legacy_recollection_identity_migration:" + legacy_key.token)
    if not rows:
        return identity, ()
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    identities = set()
    for (operation,) in rows:
        saved = read_adopted_domain_operation_v1(db, namespace, operation)
        original_ref = saved["payload"]["provenance"]["trigger"]["original_ref"]
        _, old_identity = read_committed_recollection_original_v1(db, namespace, original_ref)
        identities.add(old_identity)
    if identity in identities:
        return (source.provenance_root if len(identities) == 1 else identity), (legacy_key.token,)
    return identity, ()


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
        if type(policy) not in {InstalledRelationshipPolicyV1, InstalledRelationshipPolicyV2} or policy.namespace != frame.envelope.authority.namespace:
            raise TypeError("exact namespace D05 policy required")
        read = CurrentDomainReadV1(frame)
        read.check(db)
        if type(policy) is InstalledRelationshipPolicyV2:
            prior_roots = tuple(rule.authored_prior_source_ref for rule in policy.dimension_rules if rule.authored_prior_source_ref is not None)
            read.source_family(db, tuple(dict.fromkeys((*policy.policy_source_refs, *prior_roots))))
        raw = plain_v1(policy)
        encoded, digest = canonical_serialize(raw), canonical_digest(raw)
        pin = tuple(item for item in frame.installed_policy_refs if item.policy_ref == policy.policy_ref and item.revision == policy.revision)
        if len(pin) != 1 or (pin[0].revision, pin[0].policy_digest) != (policy.revision, digest):
            raise ValueError("D05 policy lacks current installation selection")
        expected = (encoded, digest, self.issuer._signer.sign("d11.d05-production-policy.v2" if type(policy) is InstalledRelationshipPolicyV2 else "d11.d05-production-policy.v1", encoded))
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
        raw = json.loads(row[0])
        self.issuer._signer.verify("d11.d05-production-policy.v2" if raw.get("schema_version") == 2 else "d11.d05-production-policy.v1", row[0], row[2])
        if canonical_digest(raw) != row[1] or row[1] != pin[0].policy_digest or canonical_serialize(raw) != row[0]:
            raise ValueError("D05 installed policy changed")
        if raw.get("schema_version") == 2:
            from .domain_production_erasure_v1 import decode_typed_production_value_v1
            policy = decode_typed_production_value_v1(raw, InstalledRelationshipPolicyV2)
            read.source_family(db, policy.policy_source_refs)
            return policy, ProductionOriginalRefV1("d05.installed_policy", policy_ref, row[1])
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
            from .domain_production_read_plans_v1 import read_committed_recollection_original_v1
            actual_original, _ = read_committed_recollection_original_v1(db, frame.envelope.authority.namespace, key.token)
            if actual_original != trigger:
                raise ValueError("recollection production original differs from its actual C04 commit")
            roots = _relationship_trigger_sources_v1(frame.envelope.authority.namespace, key, atom.value)
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
                (key.type_name == "memory.source" and source.source_kind == "observed" and source.assertion_status == "confirmed")
                or (actual_host_event and source.source_kind in {"observed", "reported"}
                    and source.assertion_status in {"confirmed", "reported"})):
            raise ValueError("authored/recalled/simulated sources cannot become external relationship observation")
        if request.semantics == "recollection" and key.type_name != "d06.recollection.v1":
            raise ValueError("recollection semantics need actual adopted recollection")
        if request.semantics == "simulation" and key.type_name != "d07.simulation_branch.v1":
            raise ValueError("simulation semantics need actual adopted hypothetical branch")
        ns = frame.envelope.authority.namespace
        identity, aliases = _relationship_canonical_identity_v1(db, ns, request, roots, source)
        item = RelationshipContribution("persona:" + ns.persona_id,
            identity, request.subject_entity_ref, request.dimension, request.semantics, 1, roots,
            schema_version=2, kind=CONTRIBUTION_KINDS_V2[request.semantics],
            recollection_activity_ref=key.token if request.semantics == "recollection" else None,
            identity_status="resolved", legacy_alias_keys=aliases)
        read.complete_inventory(db, "d05.contribution")
        read.complete_inventory(db, "d05.relationship_projection")
        item_key = AtomKey(Owner("relation", *frame.envelope.authority.namespace.as_tuple, request.subject_entity_ref),
                           "d05.contribution", item.key)
        prior_atom = read.head(db, item_key)
        prior = decode_relationship_contribution_payload_v1(prior_atom.value) if prior_atom.revision else None
        if prior is not None:
            item = item.with_revision(prior.contribution_revision)
            if item != prior or not prior_atom.valid:
                item = item.with_revision(prior.contribution_revision + 1)
        from ..domains.d06 import source_correction_head_key
        qualification_keys = tuple(dict.fromkeys(key for ref, record in records.items()
            for key in (AtomKey.from_token(ref), access_key(*ns.as_tuple, record.source_id),
                        source_correction_head_key(ns, record.source_id))))
        return CurrentRelationshipContributionInputsV1(item, policy.dimensions, policy.semantics,
            trigger, policy_original, entity, prior, qualification_keys, prior_atom.valid)

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
            refs = _relationship_trigger_sources_v1(namespace, trigger_key, trigger)
            roots.extend(refs)
            source = raw_head_value_v1(db, namespace, AtomKey.from_token(refs[0])) if refs else None
            if source:
                identity, aliases = _relationship_canonical_identity_v1(db, namespace, request, refs, SourceRecord.from_dict(source))
                contribution = RelationshipContribution("persona:" + namespace.persona_id, identity,
                    request.subject_entity_ref, request.dimension, request.semantics, 1, refs,
                    schema_version=2, kind=CONTRIBUTION_KINDS_V2[request.semantics],
                    recollection_activity_ref=trigger_key.token if request.semantics == "recollection" else None,
                    identity_status="resolved", legacy_alias_keys=aliases)
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
