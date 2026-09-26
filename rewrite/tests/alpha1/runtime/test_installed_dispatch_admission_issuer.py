"""The installed issuer reads current graph rows and never invents PASS."""

from dataclasses import asdict, replace
import json
import sqlite3

import pytest

from sylanne3.graph_types import AtomKey, Owner
from sylanne3.memory_types import access_key, source_key
from sylanne3.runtime.dispatch_candidate import DispatchCandidateEvidenceV1
from sylanne3.runtime.installed_dispatch_admission_issuer import (
    DispatchAdmissionHold, InstalledDispatchAdmissionIssuer,
    inspect_current_d06_source_grant,
)
from sylanne3.runtime_contracts import VersionedRef, canonical_digest

from test_dispatch_admission_preflight import _candidates


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
        assert "d05.boundary.current_provider" in error.value.missing
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
