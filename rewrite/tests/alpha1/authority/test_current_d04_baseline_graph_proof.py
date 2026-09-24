"""A V3 baseline claim needs real original graph rows, not only a frozen DTO."""

from dataclasses import asdict
import json

import pytest

from sylanne3.authority_service.current_d04_baseline_graph_proof import (
    committed_baseline_current,
)
from sylanne3.authority_service.v2_contract import FencePermitV2, to_wire
from sylanne3.contracts import canonical_json
from sylanne3.domains.d04.encoding_baseline import EncodingBaseline
from sylanne3.domains.d03.context import WorldEvent
from sylanne3.domains.d03.self_perspective import (
    SelfIdentityMapping, SelfPerspective, self_mapping_key,
    self_perspective_id, self_perspective_key,
)
from sylanne3.graph_store import GraphStore
from sylanne3.graph_types import AtomKey, Owner, TypeRegistry
from sylanne3.memory_types import source_key
from sylanne3.runtime.encoding_call_binding import CommittedEncodingBaselineV1
from sylanne3.runtime.d03_self_identity_projection_identity import (
    d03_self_identity_projection_activity_id_v1,
    d03_self_identity_projection_operation_id_v1,
)
from sylanne3.runtime.restore_anchor import RestoreAnchor
from sylanne3.runtime_contracts import (
    NamespaceId, SnapshotRequirementsV2, canonical_digest, canonical_serialize,
)


def _seed_d03_stage(db, ns, source, requirements, anchor, *,
                    pre_revision, pre_epoch, source_revision=1):
    event_value = WorldEvent(
        "world:v3-arrival", "message_received",
        (("entity:sender-account", "sender_account"),), None, None,
        1.0, "scene:v3-arrival", (source.token,), "host_observed")
    event = AtomKey(Owner("event", *ns.as_tuple, event_value.event_id),
                    "d03.world_event", "current")
    mapping_value = SelfIdentityMapping(
        "self-map:v3-fixture", f"persona:{ns.persona_id}",
        "entity:fixture-self", "authority:self-identity:fixture",
        "role-head:v3", requirements.graph_incarnation, "active")
    mapping = self_mapping_key(ns)
    perspective_value = SelfPerspective(
        self_perspective_id(ns, event_value.scene_ref, event.token),
        mapping_value.persona_ref, mapping_value.self_entity_ref,
        event_value.scene_ref, mapping.token, event.token,
        mapping_value.role_head_id)
    perspective = self_perspective_key(ns, perspective_value.perspective_id)
    operation_id = d03_self_identity_projection_operation_id_v1(
        ns, source.token, mapping_value.certification_ref)
    activity_id = d03_self_identity_projection_activity_id_v1(ns, source.token)
    bundle_digest = "b" * 64
    attempt = "graph-write-" + canonical_digest({
        "namespace": list(ns.as_tuple), "operation_id": operation_id,
        "bundle_digest": bundle_digest})[:48]
    permit = FencePermitV2(
        anchor.authority_id, anchor.namespace, "writer", "administrator", 1,
        "write", attempt, "d" * 32, 1, 0, anchor)
    for atom_key, atom_value in ((event, event_value),
                                 (mapping, mapping_value),
                                 (perspective, perspective_value)):
        db.execute("INSERT INTO graph_atoms VALUES(?,?,?,?,?,?,?,?,?,1)",
                   (atom_key.token, *ns.as_tuple, atom_key.owner.kind,
                    atom_key.owner.subject, atom_key.type_name, atom_key.name,
                    1, canonical_serialize(asdict(atom_value))))
    seq = db.execute("SELECT COALESCE(MAX(commit_seq),0)+1 "
                     "FROM graph_bundle_operations").fetchone()[0]
    db.execute("""CREATE TABLE IF NOT EXISTS graph_d03_self_projection_issuance_v1(
        bot TEXT,persona TEXT,operation_id TEXT,source_ref TEXT,
        certification_ref TEXT,quote_id TEXT,bundle_digest TEXT)""")
    db.execute("INSERT INTO graph_d03_self_projection_issuance_v1 "
               "VALUES(?,?,?,?,?,?,?)",
               (*ns.as_tuple, operation_id, source.token,
                mapping_value.certification_ref, "signed-d03-quote", bundle_digest))
    db.execute("INSERT INTO graph_bundle_operations VALUES(?,?,?,?,?,?,?,?)",
               (*ns.as_tuple, operation_id, bundle_digest, activity_id,
                None, seq, canonical_json({
                    "commit_seq": seq, "ledger_refs": [], "outbox_refs": []})))
    db.execute("INSERT INTO graph_bundle_intents_v2 VALUES(?,?,?,?,?,?,?,?,?)",
               (*ns.as_tuple, operation_id, bundle_digest, attempt,
                canonical_json(asdict(requirements)), canonical_json(asdict(anchor)),
                pre_revision-1, pre_epoch))
    db.execute("INSERT INTO graph_bundle_fences_v2 VALUES(?,?,?,?,?,?,?,?,?,?,?)",
               (*ns.as_tuple, operation_id, bundle_digest,
                canonical_json(to_wire(permit)), pre_revision-1, pre_epoch,
                pre_revision, pre_epoch, "finish:" + attempt,
                "sha256:" + canonical_digest({
                    "operation_id": attempt, "permit_token": permit.token,
                    "action": "finish_domain_bundle",
                    "business_operation_id": operation_id,
                    "bundle_digest": bundle_digest})))
    db.execute("INSERT INTO graph_events VALUES(?,?,?,?,?,?,?,?,?,?)",
               (*ns.as_tuple, activity_id, operation_id, "d03-event-digest",
                canonical_json([[source.token, source_revision],
                                [event.token, 1], [mapping.token, 0],
                                [perspective.token, 0]]), "[]",
                canonical_json([[mapping.token, 1], [perspective.token, 1]]),
                "[]", pre_epoch))
    for atom_key, atom_value in ((mapping, mapping_value),
                                 (perspective, perspective_value)):
        db.execute("INSERT INTO graph_history VALUES(?,?,?,?,?,?,?,?,?)",
                   (atom_key.token, 1, canonical_serialize(asdict(atom_value)), 1,
                    "[]", *ns.as_tuple, activity_id, operation_id))
    return perspective, event, mapping


def _case(tmp_path):
    ns = NamespaceId("bot", "persona")
    source = source_key(*ns.as_tuple, "arrival")
    op, digest, activity = "d04-original-op", "a" * 64, "arrival-activity"
    anchor = RestoreAnchor(
        "authority", "bot:persona", 1, "deletion-journal", 0, "genesis",
        "execution-journal", 0, "genesis", 0, "proof")
    requirements = SnapshotRequirementsV2(
        ns, anchor.authority_id, anchor.namespace, anchor.activation_generation,
        anchor.deletion_journal_id, anchor.deletion_seq, anchor.deletion_digest,
        anchor.execution_journal_id, anchor.execution_seq,
        anchor.execution_digest, anchor.revocation_epoch, "incarnation-1")
    attempt = "graph-write-" + canonical_digest({
        "namespace": list(ns.as_tuple), "operation_id": op,
        "bundle_digest": digest})[:48]
    permit = FencePermitV2(
        anchor.authority_id, anchor.namespace, "writer", "administrator", 1,
        "write", attempt, "w" * 32, 1, 0, anchor)
    store = GraphStore(tmp_path / "graph.db", TypeRegistry())
    db = store._db
    db.execute("INSERT INTO graph_atoms VALUES(?,?,?,?,?,?,?,?,?,1)",
               (source.token, *ns.as_tuple, source.owner.kind,
                source.owner.subject, source.type_name, source.name,
                1, canonical_json({})))
    perspective, event, mapping = _seed_d03_stage(
        db, ns, source, requirements, anchor, pre_revision=1, pre_epoch=2)
    value = EncodingBaseline(
        "baseline:fixture", (source.token,), perspective.token, (), (), 1.0,
        "projection-policy", "1", "1", "1", None, None,
        ("salience_interval:unknown", "tone_interval:unknown"))
    key = AtomKey(source.owner, "d04.encoding_baseline.v1", value.baseline_id)
    baseline = CommittedEncodingBaselineV1(
        key.token, 1, op, digest, "incarnation-1", 3)
    db.execute("""CREATE TABLE graph_d04_baseline_issuance_v1(
        bot TEXT,persona TEXT,operation_id TEXT,source_ref TEXT,event_ref TEXT,
        quote_id TEXT,bundle_digest TEXT)""")
    db.execute("INSERT INTO graph_d04_baseline_issuance_v1 VALUES(?,?,?,?,?,?,?)",
               (*ns.as_tuple, op, source.token, event.token, "signed-quote", digest))
    db.execute("INSERT INTO graph_bundle_operations VALUES(?,?,?,?,?,?,?,?)",
               (*ns.as_tuple, op, digest, activity, None, 2,
                canonical_json({"commit_seq": 2, "ledger_refs": [],
                                "outbox_refs": []})))
    db.execute("INSERT INTO graph_bundle_intents_v2 VALUES(?,?,?,?,?,?,?,?,?)",
               (*ns.as_tuple, op, digest, attempt,
                canonical_json(asdict(requirements)), canonical_json(asdict(anchor)),
                1, 2))
    db.execute("INSERT INTO graph_bundle_fences_v2 VALUES(?,?,?,?,?,?,?,?,?,?,?)",
               (*ns.as_tuple, op, digest, canonical_json(to_wire(permit)),
                1, 2, 2, 3, "finish:" + attempt,
                "sha256:" + canonical_digest({
                    "operation_id": attempt, "permit_token": permit.token,
                    "action": "finish_domain_bundle", "business_operation_id": op,
                    "bundle_digest": digest})))
    reads = [[source.token, 1], [perspective.token, 1], [key.token, 0]]
    db.execute("INSERT INTO graph_events VALUES(?,?,?,?,?,?,?,?,?,?)",
               (*ns.as_tuple, activity, op, "graph-event-digest",
                canonical_json(reads), "[]", canonical_json([[key.token, 1]]),
                "[]", 3))
    baseline_json = canonical_json({
        **asdict(value), "source_refs": [source.token],
        "then_feeling_versions": [], "interpretation_versions": [],
        "unknown_reasons": list(value.unknown_reasons)})
    for atom_key, atom_value in ((key, baseline_json),):
        text_value = (atom_value if type(atom_value) is str
                      else canonical_json(atom_value))
        db.execute("INSERT INTO graph_atoms VALUES(?,?,?,?,?,?,?,?,?,1)",
                   (atom_key.token, *ns.as_tuple, atom_key.owner.kind,
                    atom_key.owner.subject, atom_key.type_name, atom_key.name,
                    1, text_value))
    db.execute("INSERT INTO graph_history VALUES(?,?,?,?,?,?,?,?,?)",
               (key.token, 1, baseline_json, 1, "[]", *ns.as_tuple,
                activity, op))
    for ref in (source.token, perspective.token):
        db.execute("INSERT INTO graph_dependency_edges VALUES(?,?,?,?,?)",
                   (key.token, ref, 1, "historical_provenance", op))
    return store, ns, baseline, requirements, source, perspective, key


@pytest.mark.parametrize("damage", [
    "none", "fence", "history", "operation", "provenance", "atom",
    "perspective", "issuance", "guard", "d03_stage", "d03_history",
    "mapping", "arrival", "legacy_ref",
])
def test_real_d04_commit_proof_requires_fence_history_guard_and_current_refs(
        tmp_path, damage):
    store, ns, baseline, requirements, source, perspective, key = _case(tmp_path)
    db = store._db

    def current():
        db.execute("BEGIN")
        try:
            return committed_baseline_current(
                db, namespace=ns, baseline=baseline, source_id="arrival",
                requirements=requirements, current_graph_revision=4,
                current_graph_epoch=5,
                acquire_graph_revision=1 if damage == "guard" else 2,
                acquire_graph_epoch=3)
        finally:
            db.execute("ROLLBACK")

    try:
        if damage == "fence":
            db.execute("DELETE FROM graph_bundle_fences_v2")
        elif damage == "history":
            db.execute("DELETE FROM graph_history WHERE token=?", (key.token,))
        elif damage == "operation":
            db.execute("DELETE FROM graph_bundle_operations")
        elif damage == "provenance":
            db.execute("DELETE FROM graph_dependency_edges WHERE dependency_token=?",
                       (source.token,))
        elif damage == "atom":
            db.execute("UPDATE graph_atoms SET revision=2 WHERE token=?", (key.token,))
        elif damage == "perspective":
            db.execute("UPDATE graph_atoms SET valid=0 WHERE token=?",
                       (perspective.token,))
        elif damage == "issuance":
            db.execute("DELETE FROM graph_d04_baseline_issuance_v1")
        elif damage == "d03_stage":
            db.execute("DELETE FROM graph_d03_self_projection_issuance_v1")
        elif damage == "d03_history":
            db.execute("DELETE FROM graph_history WHERE token=?",
                       (perspective.token,))
        elif damage == "mapping":
            db.execute("UPDATE graph_atoms SET valid=0 "
                       "WHERE type_name='d03.self_identity_mapping.v1'")
        elif damage == "arrival":
            db.execute("UPDATE graph_atoms SET valid=0 "
                       "WHERE type_name='d03.world_event'")
        elif damage == "legacy_ref":
            old = AtomKey(Owner("persona", *ns.as_tuple), "d03.entity_anchor", "self")
            db.execute("INSERT INTO graph_atoms VALUES(?,?,?,?,?,?,?,?,?,1)",
                       (old.token, *ns.as_tuple, old.owner.kind,
                        old.owner.subject, old.type_name, old.name, 1, "{}"))
            prior = json.loads(db.execute(
                "SELECT value FROM graph_history WHERE token=?", (key.token,),
            ).fetchone()[0])
            prior["perspective_ref"] = old.token
            db.execute("UPDATE graph_history SET value=? WHERE token=?",
                       (canonical_json(prior), key.token))
            db.execute("UPDATE graph_atoms SET value=? WHERE token=?",
                       (canonical_json(prior), key.token))
            db.execute("UPDATE graph_events SET reads=? WHERE event_id=?",
                       (canonical_json([[source.token, 1], [old.token, 1],
                                        [key.token, 0]]), baseline.operation_id))
            db.execute("UPDATE graph_dependency_edges SET dependency_token=? "
                       "WHERE dependent_token=? AND dependency_token=?",
                       (old.token, key.token, perspective.token))
        assert current() is (damage == "none")
    finally:
        store.close()
