"""A dispatch admission can bind only one committed D08 action to one D11 job."""

from dataclasses import asdict, replace
import json
import sqlite3

import pytest

from sylanne3.contracts import canonical_json
from sylanne3.graph_types import AtomKey, Owner
from sylanne3.runtime.d11_types import job_graph_write
from sylanne3.runtime.dispatch_admission import (
    DispatchAdmissionReceiptV1, DispatchAdmissionV1,
)
from sylanne3.runtime.jobs import PersistentJob, create_job, install_schema as install_jobs
from sylanne3.runtime_contracts import NamespaceId, canonical_digest

from test_dispatch_admission_preflight import _candidates


def _case(path=":memory:"):
    from sylanne3.runtime.dispatch_action_job_binding import (
        bind_action_job, load_action_job_binding,
    )

    db = sqlite3.connect(path)
    db.execute("PRAGMA foreign_keys=ON")
    install_jobs(db)
    db.execute("""CREATE TABLE graph_atoms (
        token TEXT PRIMARY KEY, bot TEXT NOT NULL, persona TEXT NOT NULL,
        type_name TEXT NOT NULL, revision INTEGER NOT NULL,
        value TEXT NOT NULL, valid INTEGER NOT NULL)""")
    db.execute("""CREATE TABLE graph_dispatch_admissions (
        bot TEXT NOT NULL, persona TEXT NOT NULL, admission_ref TEXT NOT NULL,
        operation_id TEXT NOT NULL, effect_id TEXT NOT NULL,
        admission_digest TEXT NOT NULL, admission_json TEXT NOT NULL,
        graph_revision INTEGER NOT NULL, graph_epoch INTEGER NOT NULL,
        receipt_digest TEXT NOT NULL, request_json TEXT,
        PRIMARY KEY(bot,persona,admission_ref))""")
    namespace = NamespaceId("bot", "persona")
    _, intent, _, _, checks = _candidates()
    admission = DispatchAdmissionV1(
        namespace="bot/persona", graph_incarnation="incarnation:one",
        activity_id="activity:one", effect_id="effect:one",
        attempt_id="attempt:one", operation_id="operation:one",
        dispatch_generation=1, admission_ref="admission:one",
        candidate_digest="0" * 64, request_digest="1" * 64,
        action_intent_digest=canonical_digest(intent),
        action_intent_schema_version="d08.action_intent.v1",
        action_schema_digest="3" * 64,
        action_schema_version="d08.action_schema.v1",
        required_checks_digest="4" * 64,
        required_checks_schema_version="d08.required_check_spec.v1",
        grant_digest="5" * 64, batch_digest="6" * 64,
        segment_index=0, payload_digest="7" * 64,
        account_ref="account:one", destination_ref="destination:one",
        scene_ref="scene:one", owner_head_ref="owner:one",
        role_ref="role:one", binding_ref="binding:one",
        object_ref="entity:user", action_ref="action:one",
        purpose="expression", audience=("entity:user",),
        graph_reads=(("source:one", 1),), query_epoch=1,
        access_epoch=0, delete_epoch=0, check_receipts=checks,
        budget_parent_lease_ref="parent:one", budget_lease_ref="parent:one",
        budget_reservation_operation_id="operation:one",
        budget_reservation_digest="8" * 64,
        budget_ceiling={"cpu_ms": 1}, budget_currency="USD",
        budget_version=1, contact_reservation_ref=None,
        utc_deadline="2099-01-01T00:00:00Z", clock_policy_ref="clock:one",
        clock_policy_digest="9" * 64,
    )
    receipt = DispatchAdmissionReceiptV1(
        admission, 2, 3, canonical_digest({
            "admission_digest": admission.digest, "graph_revision": 2,
            "graph_epoch": 3,
        }),
    )
    db.execute(
        "INSERT INTO graph_dispatch_admissions VALUES(?,?,?,?,?,?,?,?,?,?,?)",
        ("bot", "persona", admission.admission_ref, admission.operation_id,
         admission.effect_id, admission.digest,
         canonical_json(json.loads(json.dumps(asdict(admission)))),
         receipt.graph_revision, receipt.graph_epoch, receipt.receipt_digest, None),
    )
    action_key = AtomKey(Owner("activity", "bot", "persona", "activity:one"),
                         "d08.action_intent.v1", intent.action_id)
    db.execute("INSERT INTO graph_atoms VALUES(?,?,?,?,?,?,?)", (
        action_key.token, "bot", "persona", action_key.type_name,
        intent.revision, canonical_json(json.loads(json.dumps(asdict(intent)))), 1,
    ))
    job = PersistentJob(
        "job:one", "operation:one", "activity:one", "effect:one",
        "bot", "persona", "snapshot:one", "queued", "dispatch", {}, None,
        "2099-01-01T00:00:00Z", "parent:one", "resource:one", {},
        None, None, 0, 0, {}, None,
    )
    create_job(db, job, "create:one", "a" * 64)
    graph_job = job_graph_write(job)
    db.execute("INSERT INTO graph_atoms VALUES(?,?,?,?,?,?,?)", (
        graph_job.key.token, "bot", "persona", graph_job.key.type_name,
        1, canonical_json(graph_job.value), 1,
    ))
    db.commit()
    return db, namespace, intent, receipt, job, bind_action_job, load_action_job_binding


def test_exact_action_attempt_admission_and_job_bind_once_and_survive_reopen(tmp_path):
    path = tmp_path / "binding.db"
    db, namespace, intent, receipt, job, bind, load = _case(path)
    try:
        db.execute("BEGIN IMMEDIATE")
        binding = bind(db, intent, receipt)
        assert binding.job_id == job.job_id
        assert binding.action_id == intent.action_id
        assert binding.attempt_id == intent.identity.attempt_id
        assert binding.job_fence == binding.job_cancel_epoch == 0
        assert bind(db, intent, receipt) == binding
        db.commit()
        db.execute("UPDATE runtime_jobs SET cancel_epoch=1 WHERE job_id=?",
                   (job.job_id,))
        assert bind(db, intent, receipt) == binding
        db.commit()
    finally:
        db.close()
    reopened = sqlite3.connect(path)
    try:
        assert load(reopened, namespace, receipt.admission.admission_ref) == binding
    finally:
        reopened.close()


def test_missing_ambiguous_or_stale_job_never_binds():
    db, _, intent, receipt, job, bind, _ = _case()
    try:
        db.execute("BEGIN IMMEDIATE")
        db.execute("DELETE FROM graph_atoms WHERE type_name='runtime.job'")
        with pytest.raises(ValueError, match="job graph"):
            bind(db, intent, receipt)
        graph_job = job_graph_write(job)
        db.execute("INSERT INTO graph_atoms VALUES(?,?,?,?,?,?,?)", (
            graph_job.key.token, "bot", "persona", "runtime.job", 1,
            canonical_json(graph_job.value), 1,
        ))
        other = replace(job, job_id="job:two")
        create_job(db, other, "create:two", "b" * 64)
        with pytest.raises(ValueError, match="unique job"):
            bind(db, intent, receipt)
        db.execute("DELETE FROM runtime_jobs WHERE job_id=?", (other.job_id,))
        db.execute("UPDATE runtime_jobs SET cancel_epoch=1 WHERE job_id=?",
                   (job.job_id,))
        with pytest.raises(ValueError, match="cancel|job graph"):
            bind(db, intent, receipt)
    finally:
        db.close()


def test_absent_job_and_stale_action_graph_never_bind():
    db, _, intent, receipt, job, bind, _ = _case()
    try:
        db.execute("BEGIN IMMEDIATE")
        db.execute("DELETE FROM runtime_jobs WHERE job_id=?", (job.job_id,))
        with pytest.raises(ValueError, match="unique job"):
            bind(db, intent, receipt)
        db.execute("UPDATE graph_atoms SET value='{}' "
                   "WHERE type_name='d08.action_intent.v1'")
        with pytest.raises(ValueError, match="action graph"):
            bind(db, intent, receipt)
    finally:
        db.close()


def test_conflicting_action_or_reused_admission_rejected():
    db, _, intent, receipt, _, bind, _ = _case()
    try:
        db.execute("BEGIN IMMEDIATE")
        bind(db, intent, receipt)
        with pytest.raises(ValueError, match="action|admission"):
            bind(db, replace(intent, action_id="action:other"), receipt)
        db.execute("UPDATE graph_dispatch_admissions SET receipt_digest=?",
                   ("f" * 64,))
        with pytest.raises(ValueError, match="receipt digest"):
            bind(db, intent, receipt)
    finally:
        db.close()


def test_stored_binding_columns_must_match_its_digest():
    db, namespace, intent, receipt, _, bind, load = _case()
    try:
        db.execute("BEGIN IMMEDIATE")
        bind(db, intent, receipt)
        db.execute("UPDATE graph_dispatch_action_job_bindings_v1 "
                   "SET action_id='action:other'")
        with pytest.raises(ValueError, match="binding digest differs"):
            load(db, namespace, receipt.admission.admission_ref)
    finally:
        db.close()
