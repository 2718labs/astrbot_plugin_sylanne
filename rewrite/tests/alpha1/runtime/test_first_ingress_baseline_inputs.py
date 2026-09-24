"""Queued C01 baseline inputs remain a narrow read, never a D04 issuance."""

from dataclasses import asdict
import json

import pytest

from sylanne3.graph_coordinator import AuthorityDenied, UnavailableGuard
from sylanne3.runtime.jobs import get_job
from sylanne3.runtime_contracts import AuthorityContext

from test_current_model_egress_graph_verifier import token_ingress_system  # noqa: F401


def _queued(token_ingress_system):
    store, coordinator, bootstrap, _, policy, clock, encoding, host = token_ingress_system
    coordinator._GraphCoordinator__scene_clock_policy = clock
    coordinator.commit_first_ingress_v2(bootstrap, host, policy, clock, encoding)
    db = store._db
    job_id, operation_id = db.execute(
        "SELECT job_id,operation_id FROM runtime_jobs").fetchone()
    lease, capability = coordinator.grant(
        bootstrap, actor="administrator", issuer_domain="d11",
        namespace=policy.namespace, domains=("d11",),
        activation_generation=1, operation_id=operation_id)
    authority = AuthorityContext(
        "administrator", "d11", capability, policy.namespace,
        ("activity",), "context", (host.conversation_ref,),
        policy.root_grant.policy_ref, 1)
    return db, coordinator, authority, lease, get_job(db, job_id), operation_id


def test_queued_first_ingress_read_has_original_source_and_no_new_work(
        token_ingress_system):
    db, coordinator, authority, lease, job, operation_id = _queued(token_ingress_system)
    def business_state():
        return (
            db.execute("SELECT * FROM runtime_jobs WHERE job_id=?",
                       (job.job_id,)).fetchone(),
            tuple(db.execute(
                "SELECT token,revision,value,valid FROM graph_atoms "
                "WHERE type_name IN ('memory.source','memory.access','runtime.job') "
                "ORDER BY token")),
            db.execute("SELECT * FROM runtime_budget_leases WHERE lease_id=?",
                       (job.budget_ref,)).fetchone(),
            db.execute("SELECT COUNT(*) FROM graph_events").fetchone(),
            db.execute("SELECT COUNT(*) FROM graph_bundle_operations").fetchone(),
            db.execute("SELECT revision FROM graph_epochs WHERE bot=? AND persona=?",
                       (job.bot_id, job.persona_id)).fetchone(),
        )

    before = business_state()
    inputs = coordinator.read_first_ingress_baseline_inputs_v1(
        authority, lease, job.job_id, operation_id)
    assert business_state() == before
    assert db.execute(
        "SELECT state FROM graph_stage_candidate_reads_v1 "
        "WHERE bot=? AND persona=? AND read_key=?",
        (job.bot_id, job.persona_id, "d04-baseline:" + operation_id),
    ).fetchall() == [("closed",)]
    assert (inputs.job_id, inputs.original_operation_id) == (
        job.job_id, operation_id)
    assert inputs.qualification.source_refs == (inputs.source_ref,)
    assert inputs.source_revision == inputs.access_revision == 1
    assert "text" not in asdict(inputs)
    assert "perspective_ref" not in asdict(inputs)
    assert db.execute("SELECT COUNT(*) FROM graph_job_acquire_receipts_v2").fetchone()[0] == 0
    assert db.execute(
        "SELECT COUNT(*) FROM graph_atoms WHERE type_name='d04.encoding_baseline.v1'"
    ).fetchone()[0] == 0


@pytest.mark.parametrize("mutation", ["cancel", "acquire", "source", "access"])
def test_queued_baseline_read_holds_on_current_change(token_ingress_system, mutation):
    db, coordinator, authority, lease, job, operation_id = _queued(token_ingress_system)
    if mutation == "cancel":
        db.execute("UPDATE runtime_jobs SET cancel_epoch=1 WHERE job_id=?", (job.job_id,))
    elif mutation == "acquire":
        db.execute("UPDATE runtime_jobs SET phase='running' WHERE job_id=?", (job.job_id,))
    else:
        db.execute("UPDATE graph_atoms SET valid=0 WHERE type_name=?", (
            "memory.source" if mutation == "source" else "memory.access",))
    db.commit()
    with pytest.raises(UnavailableGuard):
        coordinator.read_first_ingress_baseline_inputs_v1(
            authority, lease, job.job_id, operation_id)


def test_queued_baseline_read_rejects_other_operation_or_incarnation(
        token_ingress_system):
    db, coordinator, authority, lease, job, operation_id = _queued(token_ingress_system)
    with pytest.raises(AuthorityDenied):
        coordinator.read_first_ingress_baseline_inputs_v1(
            authority, lease, job.job_id, operation_id + "-other")
    row = db.execute("SELECT requirements_json FROM graph_recovery_metadata_v2").fetchone()
    changed = json.loads(row[0])
    changed["graph_incarnation"] = "another-incarnation"
    db.execute("UPDATE graph_recovery_metadata_v2 SET requirements_json=?", (
        json.dumps(changed, sort_keys=True, separators=(",", ":")),))
    db.commit()
    with pytest.raises(UnavailableGuard):
        coordinator.read_first_ingress_baseline_inputs_v1(
            authority, lease, job.job_id, operation_id)
