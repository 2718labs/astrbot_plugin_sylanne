"""The installed issuer reads current graph rows and never invents PASS."""

from dataclasses import asdict, replace
import json
import sqlite3

import pytest

from sylanne3.graph_types import AtomKey, Owner
from sylanne3.domains.d03 import ContextProvider, RoleBinding
from sylanne3.domains.d05 import BoundaryRule
from sylanne3.domains.d08 import ActionSchema, ActionSchemaRecord
from sylanne3.memory_types import access_key, source_key
from sylanne3.runtime.dispatch_candidate import DispatchCandidateEvidenceV1
from sylanne3.runtime.installed_dispatch_admission_issuer import (
    DispatchAdmissionHold, InstalledDispatchAdmissionIssuer,
    inspect_current_d06_source_grant,
    inspect_current_d03_d05,
)
from sylanne3.runtime_contracts import VersionedRef, canonical_digest

from test_dispatch_admission_preflight import _candidates


def _social_case(*, effect="allow", rule_audience="entity:user"):
    from sylanne3.contracts import canonical_json
    db = sqlite3.connect(":memory:", isolation_level=None)
    db.executescript("""
        CREATE TABLE graph_epochs(bot TEXT,persona TEXT,revision INTEGER);
        CREATE TABLE graph_atoms(token TEXT,bot TEXT,persona TEXT,
            type_name TEXT,revision INTEGER,value TEXT,valid INTEGER);
    """)
    source = source_key("bot", "persona", "source-one")
    _, intent, batch, _, _ = _candidates(source_ref=source.token)
    role = RoleBinding(
        "binding:one", "persona:persona", "friend", "entity:user", None,
        "scene:one", "direct", "private", (), 0.0, None, 1,
        (source.token,), 2, "active",
    )
    boundary = BoundaryRule(
        "boundary:one", "persona:persona", "entity:user", "message",
        rule_audience, "scene:one", effect, "self_internal",
        (source.token,), (), (), 0.0, None, 1, "actor", (), "active",
    )
    versions = (
        (VersionedRef(source.token, 1), VersionedRef("d03.role_binding", 5),
         VersionedRef("binding:one", 2)),
        (VersionedRef(source.token, 1), VersionedRef("d05.boundary", 5),
         VersionedRef("boundary:one", 1)),
    )
    specs = list(intent.required_checks)
    for index in (0, 1):
        specs[index] = replace(specs[index], criteria_version=source.token,
                               required_input_versions=versions[index])
    intent = replace(intent, required_checks=tuple(specs))
    schema = ActionSchemaRecord.bind(
        intent, ActionSchema(intent.schema_id, intent.action_kind, False,
                             intent.required_checks),
    )
    owner = Owner("activity", "bot", "persona", intent.identity.activity_id)
    keys = (
        AtomKey(owner, "d08.action_intent.v1", intent.action_id),
        AtomKey(owner, "d08.action_schema.v1", schema.schema_ref),
        AtomKey(owner, "d09.verified_segment_batch.v1", batch["batch_id"]),
    )
    role_key = AtomKey(Owner("scene", "bot", "persona", "scene:one"),
                       "d03.role_binding", role.role_binding_id)
    boundary_key = AtomKey(Owner("relation", "bot", "persona", "entity:user"),
                           "d05.boundary_rule", boundary.rule_id)
    db.execute("INSERT INTO graph_epochs VALUES(?,?,?)", ("bot", "persona", 5))
    for key, revision, value in (
        (source, 1, {"source_id": "source-one"}),
        (keys[0], 1, asdict(intent)), (keys[1], 1, asdict(schema)),
        (keys[2], 1, batch), (role_key, 2, asdict(role)),
        (boundary_key, 1, asdict(boundary)),
    ):
        db.execute("INSERT INTO graph_atoms VALUES(?,?,?,?,?,?,?)", (
            key.token, "bot", "persona", key.type_name, revision,
            canonical_json(json.loads(json.dumps(value))), 1,
        ))
    candidate = DispatchCandidateEvidenceV1(
        intent.identity.operation_id, keys[0].token, keys[1].token,
        "grant:one", keys[2].token, canonical_digest(intent),
        canonical_digest(schema), "1" * 64, batch["batch_digest"],
        intent.source_refs, (), (), 0, 0, 5, "source_qualified",
        tuple(batch["audiences"]), (), None,
    )
    context = ContextProvider()
    context.compile_scheme({
        "schema": "d03.context.scheme.v1", "roles": ("friend",), "norms": (),
    }, None)
    db.execute("BEGIN IMMEDIATE")
    return db, candidate, context, boundary_key


def _case():
    db = sqlite3.connect(":memory:")
    db.execute("CREATE TABLE graph_epochs(bot TEXT,persona TEXT,revision INTEGER)")
    db.execute("CREATE TABLE graph_authority_epochs("
               "bot TEXT,persona TEXT,access_epoch INTEGER,delete_epoch INTEGER)")
    db.execute("CREATE TABLE graph_atoms("
               "token TEXT,bot TEXT,persona TEXT,revision INTEGER,"
               "value TEXT,valid INTEGER)")
    source = source_key("bot", "persona", "source-one")
    access = access_key("bot", "persona", "source-one")
    _schema, intent, *_ = _candidates(source_ref=source.token)
    pinned = (VersionedRef(source.token, 1), VersionedRef(access.token, 1))
    specs = tuple(replace(item, criteria_version=source.token,
                          required_input_versions=pinned)
                  if item.check_kind == "source_grant" else item
                  for item in intent.required_checks)
    intent = replace(intent, required_checks=specs)
    action_ref = AtomKey(
        Owner("activity", "bot", "persona", intent.identity.activity_id),
        "d08.action_intent.v1", intent.action_id,
    ).token
    values = ((source.token, {"source_id": "source-one"}),
              (access.token, {"source_id": "source-one", "status": "active"}))
    proof = tuple((ref, 1, canonical_digest(value)) for ref, value in values)
    candidate = DispatchCandidateEvidenceV1(
        intent.identity.operation_id, action_ref, "schema:one", "grant:one",
        "batch:one", canonical_digest(intent), "0" * 64, "1" * 64,
        "2" * 64, intent.source_refs, ((source.token, 1),),
        ((access.token, 1),), 3, 4, 7, "source_qualified",
        ("entity:user",), tuple((ref, version) for ref, version, _ in proof),
        canonical_digest(proof),
    )
    db.execute("INSERT INTO graph_epochs VALUES(?,?,?)", ("bot", "persona", 7))
    db.execute("INSERT INTO graph_authority_epochs VALUES(?,?,?,?)",
               ("bot", "persona", 3, 4))
    for ref, value in values:
        db.execute("INSERT INTO graph_atoms VALUES(?,?,?,?,?,?)",
                   (ref, "bot", "persona", 1, json.dumps(value), 1))
    db.execute("INSERT INTO graph_atoms VALUES(?,?,?,?,?,?)",
               (action_ref, "bot", "persona", 1, json.dumps(asdict(intent)), 1))
    db.commit()
    db.execute("BEGIN IMMEDIATE")
    return db, intent, specs[2], candidate


def test_d06_reads_current_rows_but_holds_without_independent_barrier():
    db, intent, spec, candidate = _case()
    try:
        inspection = inspect_current_d06_source_grant(
            db, intent, spec, candidate, audience=("entity:user",),
        )
        assert inspection.status == "hold"
        assert inspection.provider_result == "unknown"
        assert inspection.observed_versions == candidate.source_proof_versions
        assert inspection.missing == ("d06.independent_deletion_authority_barrier",)
        issuer = InstalledDispatchAdmissionIssuer()
        with pytest.raises(DispatchAdmissionHold) as error:
            issuer.issue_dispatch_admission(None, None, candidate, db,
                                            graph_incarnation="incarnation:one",
                                            now_utc=1.0)
        assert "d03.d05.installed_context_provider" in error.value.missing
        assert "d11.dispatch_budget.current_grant_and_journal" in error.value.missing
        assert issuer.verify_required_check(spec, None, None, db) is False
    finally:
        db.close()


def test_changed_row_or_epoch_cannot_reuse_qualified_candidate():
    db, intent, spec, candidate = _case()
    try:
        db.execute("UPDATE graph_atoms SET value=? WHERE token=?",
                   (json.dumps({"source_id": "replaced"}), intent.source_refs[0]))
        with pytest.raises(DispatchAdmissionHold) as error:
            inspect_current_d06_source_grant(
                db, intent, spec, candidate, audience=("entity:user",),
            )
        assert error.value.missing == ("d06.current_source_access_content",)
        db.execute("UPDATE graph_epochs SET revision=8")
        with pytest.raises(DispatchAdmissionHold) as error:
            inspect_current_d06_source_grant(
                db, intent, spec, candidate, audience=("entity:user",),
            )
        assert error.value.missing == ("d06.current_graph_epoch",)
    finally:
        db.close()


def test_no_graph_transaction_holds_before_reading():
    db, intent, spec, candidate = _case()
    try:
        db.rollback()
        with pytest.raises(DispatchAdmissionHold) as error:
            inspect_current_d06_source_grant(
                db, intent, spec, candidate, audience=("entity:user",),
            )
        assert error.value.missing == ("graph.current_write_transaction",)
    finally:
        db.close()


def test_d03_d05_scoped_receipts_come_from_complete_graph_rows():
    db, candidate, context, _ = _social_case()
    try:
        result = inspect_current_d03_d05(
            db, candidate, context=context, now_utc=2.0,
        )
        assert result.status == "checks_pass"
        assert result.missing == ()
        assert (result.role_receipt.result, result.boundary_receipt.result) == (
            "pass", "pass",
        )
        assert result.graph_epoch == 5
    finally:
        db.close()


@pytest.mark.parametrize("effect,scope,expected", [
    ("deny", "entity:user", "d05.current_boundary_not_pass"),
    ("allow", "conversation", "d05.audience_scope_mapping_unavailable"),
])
def test_d05_deny_and_unmapped_scope_hold(effect, scope, expected):
    db, candidate, context, _ = _social_case(
        effect=effect, rule_audience=scope,
    )
    try:
        result = inspect_current_d03_d05(
            db, candidate, context=context, now_utc=2.0,
        )
        assert result.status == "hold"
        assert expected in result.missing
    finally:
        db.close()


def test_current_boundary_row_change_recomputes_and_fails():
    db, candidate, context, key = _social_case()
    try:
        db.execute("UPDATE graph_atoms SET value=json_set(value,'$.effect','deny') "
                   "WHERE token=?", (key.token,))
        result = inspect_current_d03_d05(
            db, candidate, context=context, now_utc=2.0,
        )
        assert result.status == "hold"
        assert result.boundary_receipt.result == "fail"
    finally:
        db.close()


def test_new_boundary_rule_cannot_be_omitted_from_complete_read():
    db, candidate, context, key = _social_case()
    try:
        row = db.execute("SELECT value FROM graph_atoms WHERE token=?",
                         (key.token,)).fetchone()
        new_rule = {**json.loads(row[0]), "rule_id": "boundary:new",
                    "effect": "deny"}
        new_key = AtomKey(key.owner, key.type_name, "boundary:new")
        db.execute("INSERT INTO graph_atoms VALUES(?,?,?,?,?,?,?)", (
            new_key.token, "bot", "persona", key.type_name, 1,
            json.dumps(new_rule), 1,
        ))
        result = inspect_current_d03_d05(
            db, candidate, context=context, now_utc=2.0,
        )
        assert result.status == "hold"
        assert "d05.current_boundary_not_pass" in result.missing
    finally:
        db.close()
