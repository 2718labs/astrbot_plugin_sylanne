"""W01 reads current durable facts and keeps the unresolved barrier closed."""

import json
import sqlite3
from dataclasses import asdict

import pytest

from rewrite.tests.alpha1.d06.test_source_correction_candidate import (
    ADAPTER, NAMESPACE, setup,
)
from sylanne3.runtime.source_correction_resolution import (
    SourceCorrectionResolutionHold,
    plan_source_correction_resolution_v1,
    read_source_correction_resolution_preflight,
)
from sylanne3.graph_types import AtomKey
from sylanne3.memory_types import access_key, source_key


def _database():
    db = sqlite3.connect(":memory:")
    db.execute("CREATE TABLE graph_atoms (token TEXT, bot TEXT, persona TEXT, "
               "revision INTEGER, value TEXT, valid INTEGER)")
    db.execute("CREATE TABLE graph_authority_epochs (bot TEXT, persona TEXT, "
               "access_epoch INTEGER, delete_epoch INTEGER)")
    request, reads, envelope = setup()
    proposal = ADAPTER.compile_source_correction(
        envelope, request, reads, recorded_at=5.0).proposal
    source = reads.sources[0]
    originals = (
        (source_key(*NAMESPACE.as_tuple, source.source_id), asdict(source)),
        (access_key(*NAMESPACE.as_tuple, source.source_id), reads.accesses[0]),
    )
    for key, value in originals:
        db.execute("INSERT INTO graph_atoms VALUES (?,?,?,?,?,1)",
                   (key.token, *NAMESPACE.as_tuple, 1, json.dumps(value)))
    for write in proposal.typed_writes[:3]:
        db.execute("INSERT INTO graph_atoms VALUES (?,?,?,?,?,1)",
                   (write.key.token, *NAMESPACE.as_tuple, 1,
                    json.dumps(write.value)))
    db.execute("INSERT INTO graph_authority_epochs VALUES (?,?,?,?)",
               (*NAMESPACE.as_tuple, 3, 2))
    db.commit()
    return db, proposal.typed_writes[2].key


def test_current_preflight_still_holds_without_trusted_issuers():
    db, head_key = _database()
    db.execute("BEGIN")
    snapshot = read_source_correction_resolution_preflight(
        db, NAMESPACE, head_key.owner.subject)
    assert snapshot.pending_head["state"] == "pending_reevaluation"
    assert snapshot.head.revision == 1
    assert snapshot.current.source_access_status == "active"
    assert snapshot.status == "HOLD"
    with pytest.raises(SourceCorrectionResolutionHold, match="issuers absent"):
        plan_source_correction_resolution_v1(snapshot)
    assert json.loads(db.execute(
        "SELECT value FROM graph_atoms WHERE token=?",
        (head_key.token,)).fetchone()[0])["state"] == "pending_reevaluation"
    db.rollback()


def test_withdrawn_access_and_stale_head_fail_closed():
    db, head_key = _database()
    correction_id = json.loads(db.execute(
        "SELECT value FROM graph_atoms WHERE token=?",
        (head_key.token,)).fetchone()[0])["correction_source_ref"]
    correction_key = AtomKey.from_token(correction_id)
    access = access_key(*NAMESPACE.as_tuple, correction_key.owner.subject)
    db.execute("UPDATE graph_atoms SET value=? WHERE token=?",
               (json.dumps({"source_id": correction_key.owner.subject,
                            "status": "withdrawn"}), access.token))
    db.commit()
    db.execute("BEGIN")
    with pytest.raises(SourceCorrectionResolutionHold, match="source access"):
        read_source_correction_resolution_preflight(
            db, NAMESPACE, head_key.owner.subject)
    db.rollback()
    db.execute("UPDATE graph_atoms SET value=? WHERE token=?",
               (json.dumps({"state": "resolved_reevaluation"}), head_key.token))
    db.commit()
    db.execute("BEGIN")
    with pytest.raises(SourceCorrectionResolutionHold, match="head invalid"):
        read_source_correction_resolution_preflight(
            db, NAMESPACE, head_key.owner.subject)
    db.rollback()
