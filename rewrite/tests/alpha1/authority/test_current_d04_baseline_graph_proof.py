"""A V3 baseline claim needs real original graph rows, not only a frozen DTO."""

from dataclasses import asdict, replace
import json

import pytest

from sylanne3.authority_service.current_d04_baseline_graph_proof import (
    committed_baseline_current,
)
from sylanne3.authority_service.v2_contract import (
    FencePermitV2, from_wire, to_wire,
)
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
    d03_self_identity_projection_retry_operation_id_v2,
)
from sylanne3.runtime.d04_baseline_retry_identity import (
    d04_baseline_retry_operation_id_v2,
)
from sylanne3.runtime.issuers import (
    D03_SELF_IDENTITY_PROJECTION_WORK_KIND, D04_BASELINE_WORK_KIND,
    ResourceQuote, build_runtime_issuers,
    d03_self_identity_projection_quote_id, d04_baseline_quote_id,
    install_schema as install_issuer_schema,
)
from sylanne3.runtime.restore_anchor import RestoreAnchor
from sylanne3.runtime_contracts import (
    NamespaceId, SnapshotRequirementsV2, canonical_digest, canonical_serialize,
)


def _stage_quote(db, issuer, ns, operation_id, activity_id, stage, *,
                 lease_id="root-lease"):
    quote_id = (d03_self_identity_projection_quote_id(ns, operation_id)
                if stage == "d03" else d04_baseline_quote_id(ns, operation_id))
    quote = ResourceQuote(
        quote_id, 1, *ns.as_tuple, activity_id, operation_id, None,
        lease_id, D03_SELF_IDENTITY_PROJECTION_WORK_KIND if stage == "d03"
        else D04_BASELINE_WORK_KIND, "stage-snapshot", 1000.0,
        "stage-resource", None, (), (), {"cpu_ms": 10}, None, 1000.0)
    issuer.resource_issuer.issue_quote(db, quote)
    db.execute("INSERT INTO runtime_budget_reservations VALUES(?,?,?,?,?,?)",
               (lease_id, operation_id, "reservation-digest",
                canonical_json({"cpu_ms": 10}), "settled", None))
    return quote_id


def _seed_d03_stage(db, ns, source, requirements, anchor, *, issuer,
                    pre_revision, pre_epoch, source_revision=1,
                    original_operation_id="c01-original", lease_id="root-lease"):
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
    quote_id = _stage_quote(db, issuer, ns, operation_id, activity_id, "d03",
                            lease_id=lease_id)
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
                 mapping_value.certification_ref, quote_id, bundle_digest))
    db.execute("""CREATE TABLE IF NOT EXISTS graph_d03_self_projection_intents_v1(
        bot TEXT,persona TEXT,source_ref TEXT,original_operation_id TEXT,
        operation_id TEXT,bundle_digest TEXT)""")
    db.execute("INSERT INTO graph_d03_self_projection_intents_v1 VALUES(?,?,?,?,?,?)",
               (*ns.as_tuple, source.token, original_operation_id, operation_id,
                bundle_digest))
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
    digest, activity = "a" * 64, "arrival-activity"
    anchor = RestoreAnchor(
        "authority", "bot:persona", 1, "deletion-journal", 0, "genesis",
        "execution-journal", 0, "genesis", 0, "proof")
    requirements = SnapshotRequirementsV2(
        ns, anchor.authority_id, anchor.namespace, anchor.activation_generation,
        anchor.deletion_journal_id, anchor.deletion_seq, anchor.deletion_digest,
        anchor.execution_journal_id, anchor.execution_seq,
        anchor.execution_digest, anchor.revocation_epoch, "incarnation-1")
    store = GraphStore(tmp_path / "graph.db", TypeRegistry())
    db = store._db
    _, issuer = build_runtime_issuers(b"v3-baseline-test-signing-key-00000000")
    install_issuer_schema(db)
    db.execute("""CREATE TABLE IF NOT EXISTS runtime_budget_reservations(
        lease_id TEXT,operation_id TEXT,digest TEXT,ceiling_json TEXT,
        state TEXT,actual_json TEXT)""")
    db.execute("INSERT INTO graph_atoms VALUES(?,?,?,?,?,?,?,?,?,1)",
               (source.token, *ns.as_tuple, source.owner.kind,
                source.owner.subject, source.type_name, source.name,
                1, canonical_json({})))
    perspective, event, mapping = _seed_d03_stage(
        db, ns, source, requirements, anchor, issuer=issuer,
        pre_revision=1, pre_epoch=2)
    op = "d04-baseline-" + canonical_digest({
        "namespace": ns.as_tuple, "source": source.token,
        "event": event.token, "perspective": perspective.token,
        "perspective_revision": 1,
    })[:40]
    attempt = "graph-write-" + canonical_digest({
        "namespace": list(ns.as_tuple), "operation_id": op,
        "bundle_digest": digest})[:48]
    permit = FencePermitV2(
        anchor.authority_id, anchor.namespace, "writer", "administrator", 1,
        "write", attempt, "w" * 32, 1, 0, anchor)
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
    quote_id = _stage_quote(db, issuer, ns, op, activity, "d04")
    db.execute("INSERT INTO graph_d04_baseline_issuance_v1 VALUES(?,?,?,?,?,?,?)",
               (*ns.as_tuple, op, source.token, event.token, quote_id, digest))
    db.execute("""CREATE TABLE graph_d04_baseline_intents_v1(
        bot TEXT,persona TEXT,source_ref TEXT,original_operation_id TEXT,
        operation_id TEXT,bundle_digest TEXT)""")
    db.execute("INSERT INTO graph_d04_baseline_intents_v1 VALUES(?,?,?,?,?,?)",
               (*ns.as_tuple, source.token, "c01-original", op, digest))
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
    return store, ns, baseline, requirements, source, perspective, key, issuer


def _retry_d04(db, ns, baseline, requirements, source, perspective, issuer):
    old_op, digest = baseline.operation_id, baseline.bundle_digest
    old_intent = db.execute(
        "SELECT digest,fence_attempt_id,requirements_json,anchor_json,"
        "graph_revision,graph_epoch FROM graph_bundle_intents_v2 "
        "WHERE operation_id=?", (old_op,),
    ).fetchone()
    old_fence = db.execute(
        "SELECT permit_json FROM graph_bundle_fences_v2 WHERE operation_id=?",
        (old_op,),
    ).fetchone()[0]
    old_permit = from_wire(json.loads(old_fence))
    rejection = (
        digest, "rejected_no_commit", old_fence,
        old_intent[4], old_intent[5], "abort:" + old_intent[1],
        "sha256:" + canonical_digest({
            "operation_id": old_intent[1], "permit_token": old_permit.token,
            "action": "rejected_no_commit", "business_operation_id": old_op,
            "bundle_digest": digest,
        }),
    )
    db.execute("""CREATE TABLE IF NOT EXISTS graph_bundle_rejections_v2(
        bot TEXT,persona TEXT,operation_id TEXT,digest TEXT,status TEXT,
        permit_json TEXT,graph_revision INTEGER,graph_epoch INTEGER,
        finish_request_id TEXT,finish_request_digest TEXT)""")
    db.execute("INSERT INTO graph_bundle_rejections_v2 VALUES(?,?,?,?,?,?,?,?,?,?)",
               (*ns.as_tuple, old_op, *rejection))
    db.execute("""CREATE TABLE IF NOT EXISTS graph_stage_retry_lineage_v1(
        bot TEXT,persona TEXT,stage TEXT,source_ref TEXT,
        original_operation_id TEXT,operation_id TEXT,
        previous_operation_id TEXT,retry_index INTEGER,
        previous_bundle_digest TEXT,previous_attempt_id TEXT,
        previous_rejection_digest TEXT)""")
    event_ref = db.execute(
        "SELECT event_ref FROM graph_d04_baseline_issuance_v1 "
        "WHERE operation_id=?", (old_op,),
    ).fetchone()[0]
    new_op = d04_baseline_retry_operation_id_v2(
        ns, source.token, event_ref, perspective.token, 1, old_op, 1)
    activity = db.execute(
        "SELECT activity_id FROM graph_bundle_operations WHERE operation_id=?",
        (old_op,),
    ).fetchone()[0]
    new_quote = _stage_quote(db, issuer, ns, new_op, activity, "d04")
    new_attempt = "graph-write-" + canonical_digest({
        "namespace": list(ns.as_tuple), "operation_id": new_op,
        "bundle_digest": digest,
    })[:48]
    new_permit = replace(old_permit, operation_id=new_attempt, token="n" * 32)
    db.execute("DELETE FROM graph_bundle_fences_v2 WHERE operation_id=?",
               (old_op,))
    db.execute("INSERT INTO graph_bundle_intents_v2 VALUES(?,?,?,?,?,?,?,?,?)",
               (*ns.as_tuple, new_op, digest, new_attempt, *old_intent[2:]))
    db.execute("INSERT INTO graph_bundle_fences_v2 VALUES(?,?,?,?,?,?,?,?,?,?,?)",
               (*ns.as_tuple, new_op, digest, canonical_json(to_wire(new_permit)),
                1, 2, 2, 3, "finish:" + new_attempt,
                "sha256:" + canonical_digest({
                    "operation_id": new_attempt, "permit_token": new_permit.token,
                    "action": "finish_domain_bundle", "business_operation_id": new_op,
                    "bundle_digest": digest,
                })))
    db.execute("UPDATE graph_bundle_operations SET operation_id=? "
               "WHERE operation_id=?", (new_op, old_op))
    db.execute("UPDATE graph_events SET event_id=? WHERE event_id=?",
               (new_op, old_op))
    db.execute("UPDATE graph_history SET event_id=? WHERE event_id=?",
               (new_op, old_op))
    db.execute("UPDATE graph_dependency_edges SET operation_id=? "
               "WHERE operation_id=?", (new_op, old_op))
    db.execute("UPDATE graph_d04_baseline_issuance_v1 "
               "SET operation_id=?,quote_id=? WHERE operation_id=?",
               (new_op, new_quote, old_op))
    db.execute("UPDATE graph_d04_baseline_intents_v1 SET operation_id=? "
               "WHERE operation_id=?", (new_op, old_op))
    db.execute("INSERT INTO graph_stage_retry_lineage_v1 VALUES(?,?,?,?,?,?,?,?,?,?,?)",
               (*ns.as_tuple, "d04", source.token, "c01-original", new_op,
                old_op, 1, digest, old_intent[1], canonical_digest(list(rejection))))
    return replace(baseline, operation_id=new_op), old_op, new_op


def _retry_d03(db, ns, source, issuer):
    old_op, digest, certification = db.execute(
        "SELECT operation_id,bundle_digest,certification_ref "
        "FROM graph_d03_self_projection_issuance_v1",
    ).fetchone()
    old_intent = db.execute(
        "SELECT digest,fence_attempt_id,requirements_json,anchor_json,"
        "graph_revision,graph_epoch FROM graph_bundle_intents_v2 "
        "WHERE operation_id=?", (old_op,),
    ).fetchone()
    old_fence = db.execute(
        "SELECT permit_json FROM graph_bundle_fences_v2 WHERE operation_id=?",
        (old_op,),
    ).fetchone()[0]
    old_permit = from_wire(json.loads(old_fence))
    rejection = (
        digest, "rejected_no_commit", old_fence,
        old_intent[4], old_intent[5], "abort:" + old_intent[1],
        "sha256:" + canonical_digest({
            "operation_id": old_intent[1], "permit_token": old_permit.token,
            "action": "rejected_no_commit", "business_operation_id": old_op,
            "bundle_digest": digest,
        }),
    )
    db.execute("INSERT INTO graph_bundle_rejections_v2 VALUES(?,?,?,?,?,?,?,?,?,?)",
               (*ns.as_tuple, old_op, *rejection))
    db.execute("""CREATE TABLE IF NOT EXISTS graph_stage_retry_lineage_v1(
        bot TEXT,persona TEXT,stage TEXT,source_ref TEXT,
        original_operation_id TEXT,operation_id TEXT,
        previous_operation_id TEXT,retry_index INTEGER,
        previous_bundle_digest TEXT,previous_attempt_id TEXT,
        previous_rejection_digest TEXT)""")
    new_op = d03_self_identity_projection_retry_operation_id_v2(
        ns, source.token, certification, old_op, 1)
    activity = db.execute(
        "SELECT activity_id FROM graph_bundle_operations WHERE operation_id=?",
        (old_op,),
    ).fetchone()[0]
    new_quote = _stage_quote(db, issuer, ns, new_op, activity, "d03")
    new_attempt = "graph-write-" + canonical_digest({
        "namespace": list(ns.as_tuple), "operation_id": new_op,
        "bundle_digest": digest,
    })[:48]
    new_permit = replace(old_permit, operation_id=new_attempt, token="s" * 32)
    db.execute("DELETE FROM graph_bundle_fences_v2 WHERE operation_id=?",
               (old_op,))
    db.execute("INSERT INTO graph_bundle_intents_v2 VALUES(?,?,?,?,?,?,?,?,?)",
               (*ns.as_tuple, new_op, digest, new_attempt, *old_intent[2:]))
    db.execute("INSERT INTO graph_bundle_fences_v2 VALUES(?,?,?,?,?,?,?,?,?,?,?)",
               (*ns.as_tuple, new_op, digest, canonical_json(to_wire(new_permit)),
                *old_intent[4:], old_intent[4]+1, old_intent[5],
                "finish:" + new_attempt,
                "sha256:" + canonical_digest({
                    "operation_id": new_attempt, "permit_token": new_permit.token,
                    "action": "finish_domain_bundle", "business_operation_id": new_op,
                    "bundle_digest": digest,
                })))
    db.execute("UPDATE graph_bundle_operations SET operation_id=? "
               "WHERE operation_id=?", (new_op, old_op))
    db.execute("UPDATE graph_events SET event_id=? WHERE event_id=?",
               (new_op, old_op))
    db.execute("UPDATE graph_history SET event_id=? WHERE event_id=?",
               (new_op, old_op))
    db.execute("UPDATE graph_d03_self_projection_issuance_v1 "
               "SET operation_id=?,quote_id=? WHERE operation_id=?",
               (new_op, new_quote, old_op))
    db.execute("UPDATE graph_d03_self_projection_intents_v1 SET operation_id=? "
               "WHERE operation_id=?", (new_op, old_op))
    db.execute("INSERT INTO graph_stage_retry_lineage_v1 VALUES(?,?,?,?,?,?,?,?,?,?,?)",
               (*ns.as_tuple, "d03", source.token, "c01-original", new_op,
                old_op, 1, digest, old_intent[1], canonical_digest(list(rejection))))
    return old_op, new_op


@pytest.mark.parametrize("damage", [
    "none", "fence", "history", "operation", "provenance", "atom",
    "perspective", "issuance", "guard", "d03_stage", "d03_history",
    "mapping", "arrival", "legacy_ref",
])
def test_real_d04_commit_proof_requires_fence_history_guard_and_current_refs(
        tmp_path, damage):
    store, ns, baseline, requirements, source, perspective, key, issuer = _case(tmp_path)
    db = store._db

    def current():
        db.execute("BEGIN")
        try:
            return committed_baseline_current(
                db, namespace=ns, baseline=baseline, source_id="arrival",
                requirements=requirements, current_graph_revision=4,
                current_graph_epoch=5,
                acquire_graph_revision=1 if damage == "guard" else 2,
                acquire_graph_epoch=3, issuer=issuer)
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


@pytest.mark.parametrize("damage", [
    "none", "missing_rejection", "wrong_rejection", "old_receipt",
    "old_fence", "broken_link", "wrong_quote", "wrong_quote_signature",
    "wrong_ceiling", "wrong_lease", "missing_head",
])
def test_d04_retry_requires_immutable_rejection_and_signed_final_quote(
        tmp_path, damage):
    store, ns, baseline, requirements, source, perspective, _, issuer = _case(
        tmp_path)
    db = store._db
    try:
        baseline, old_op, new_op = _retry_d04(
            db, ns, baseline, requirements, source, perspective, issuer)
        if damage != "none":
            table = ("graph_bundle_rejections_v2" if damage in {
                "missing_rejection", "wrong_rejection"} else
                "graph_stage_retry_lineage_v1" if damage == "broken_link" else
                "graph_d04_baseline_issuance_v1" if damage == "wrong_quote" else
                "graph_d04_baseline_intents_v1")
            for (trigger,) in db.execute(
                    "SELECT name FROM sqlite_master WHERE type='trigger' "
                    "AND tbl_name=?", (table,)).fetchall():
                db.execute('DROP TRIGGER "' + trigger.replace('"', '""') + '"')
        if damage == "missing_rejection":
            db.execute("DELETE FROM graph_bundle_rejections_v2")
        elif damage == "wrong_rejection":
            db.execute("UPDATE graph_bundle_rejections_v2 SET digest='wrong'")
        elif damage == "old_receipt":
            db.execute("INSERT INTO graph_bundle_operations VALUES(?,?,?,?,?,?,?,?)",
                       (*ns.as_tuple, old_op, baseline.bundle_digest,
                        "arrival-activity", None, 99, "{}"))
        elif damage == "old_fence":
            db.execute("INSERT INTO graph_bundle_fences_v2 VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                       (*ns.as_tuple, old_op, baseline.bundle_digest,
                        "{}", 0, 0, 0, 0, "old", "old"))
        elif damage == "broken_link":
            db.execute("UPDATE graph_stage_retry_lineage_v1 SET retry_index=2")
        elif damage == "wrong_quote":
            db.execute("UPDATE graph_d04_baseline_issuance_v1 "
                       "SET quote_id='untrusted' WHERE operation_id=?", (new_op,))
        elif damage == "wrong_quote_signature":
            quote_id = db.execute(
                "SELECT quote_id FROM graph_d04_baseline_issuance_v1 "
                "WHERE operation_id=?", (new_op,),
            ).fetchone()[0]
            db.execute("UPDATE runtime_resource_quotes SET signature='wrong' "
                       "WHERE quote_id=?", (quote_id,))
        elif damage == "wrong_ceiling":
            db.execute("UPDATE runtime_budget_reservations SET ceiling_json=? "
                       "WHERE operation_id=?",
                       (canonical_json({"cpu_ms": 11}), new_op))
        elif damage == "wrong_lease":
            db.execute("UPDATE runtime_budget_reservations SET lease_id='other' "
                       "WHERE operation_id=?", (new_op,))
        elif damage == "missing_head":
            db.execute("DELETE FROM graph_d04_baseline_intents_v1")
        db.execute("BEGIN")
        try:
            result = committed_baseline_current(
                db, namespace=ns, baseline=baseline, source_id="arrival",
                requirements=requirements, current_graph_revision=4,
                current_graph_epoch=5, acquire_graph_revision=2,
                acquire_graph_epoch=3, issuer=issuer)
        finally:
            db.execute("ROLLBACK")
        assert result is (damage == "none")
    finally:
        store.close()


@pytest.mark.parametrize("damage", [
    "none", "missing_rejection", "wrong_predecessor", "old_receipt",
    "wrong_quote_signature",
])
def test_d03_retry_predecessor_is_the_actual_perspective_stage(
        tmp_path, damage):
    store, ns, baseline, requirements, source, _, _, issuer = _case(tmp_path)
    db = store._db
    try:
        old_op, new_op = _retry_d03(db, ns, source, issuer)
        if damage == "missing_rejection":
            for (trigger,) in db.execute(
                    "SELECT name FROM sqlite_master WHERE type='trigger' "
                    "AND tbl_name='graph_bundle_rejections_v2'").fetchall():
                db.execute('DROP TRIGGER "' + trigger + '"')
            db.execute("DELETE FROM graph_bundle_rejections_v2")
        elif damage == "wrong_predecessor":
            db.execute("UPDATE graph_stage_retry_lineage_v1 "
                       "SET previous_operation_id='unrelated'")
        elif damage == "old_receipt":
            db.execute("INSERT INTO graph_bundle_operations VALUES(?,?,?,?,?,?,?,?)",
                       (*ns.as_tuple, old_op, "b" * 64,
                        "arrival-activity", None, 99, "{}"))
        elif damage == "wrong_quote_signature":
            quote_id = db.execute(
                "SELECT quote_id FROM graph_d03_self_projection_issuance_v1 "
                "WHERE operation_id=?", (new_op,),
            ).fetchone()[0]
            db.execute("UPDATE runtime_resource_quotes SET signature='wrong' "
                       "WHERE quote_id=?", (quote_id,))
        db.execute("BEGIN")
        try:
            result = committed_baseline_current(
                db, namespace=ns, baseline=baseline, source_id="arrival",
                requirements=requirements, current_graph_revision=4,
                current_graph_epoch=5, acquire_graph_revision=2,
                acquire_graph_epoch=3, issuer=issuer)
        finally:
            db.execute("ROLLBACK")
        assert result is (damage == "none")
    finally:
        store.close()
