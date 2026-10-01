"""Isolated storage contract for signed paid originals, not live model egress."""

from dataclasses import replace
from datetime import datetime, timezone
from hashlib import sha256
import sqlite3

import pytest

from sylanne3.domains.d13.paid_lifecycle import bind_paid_original_v1
from sylanne3.model_broker.d13_precompression import (
    D13ExactTokenCountV1, D13PrecompressionInstallationV1,
    freeze_d13_precompression_request_v1,
)
from sylanne3.runtime.budget import (
    BudgetLease, create_budget_lease, install_schema as install_budget,
    reserve_budget,
)
from sylanne3.runtime.d11_types import runtime_job_key
from sylanne3.runtime.d13_paid_intent_original_v1 import (
    PAID_WORK_KIND, install_d13_paid_intent_original_v1,
    read_current_d13_paid_intent_original_v1, record_d13_paid_intent_original_v1,
)
from sylanne3.runtime.issuers import (
    BudgetLeaseGrant, D02ResourceIssuer, D11BudgetGrantIssuer, ResourceQuote,
    install_schema as install_issuers,
)
from sylanne3.runtime.jobs import (
    PersistentJob, create_job, acquire_job, install_schema as install_jobs,
)
from sylanne3.runtime_contracts import canonical_digest
from test_precompression import extractive_fixture


def _case(db):
    window, plan, _ = extractive_fixture()
    installation = D13PrecompressionInstallationV1(
        "main-install", "provider", "main-model", "a" * 64, 512)
    frozen = freeze_d13_precompression_request_v1(window, plan, installation)
    binding = bind_paid_original_v1(
        frozen, original_operation_id="paid-original:1", call_id="paid-call:1")
    count = D13ExactTokenCountV1(
        installation.provider_id, installation.model_id,
        installation.provider_config_digest,
        sha256(frozen.messages_wire.encode()).hexdigest(), frozen.wire_digest,
        130, "installed-exact-tokenizer")
    d02 = D02ResourceIssuer(b"q" * 32)
    d11 = D11BudgetGrantIssuer(b"b" * 32)
    ceiling = {"input_tokens": 300, "output_tokens": 512,
               "model_microusd": 5000}
    lease_id = "paid-lease:1"
    create_budget_lease(db, BudgetLease(
        lease_id, None, *window.namespace.as_tuple, "USD", ceiling,
        {}, {}, {}, 1, "active"), "create-paid-lease", "1" * 64)
    d11.issue_budget_grant(db, BudgetLeaseGrant(
        "paid-grant:1", 1, *window.namespace.as_tuple, lease_id, "USD",
        ceiling, (PAID_WORK_KIND,), window.trusted_utc + 5000, "paid-policy:1"))
    job = PersistentJob(
        plan.job_ref, binding.original_operation_id, "paid-activity:1", None,
        *window.namespace.as_tuple, "paid-snapshot:1", "queued", PAID_WORK_KIND,
        {"binding_digest": binding.binding_digest,
         "frozen_input_digest": frozen.digest, "wire_digest": frozen.wire_digest,
         "read_closure_digest": frozen.read_closure_digest}, None,
        datetime.fromtimestamp(window.trusted_utc + 1000, timezone.utc).isoformat(),
        lease_id, "paid-provider:1", {}, None, None, 0, 0, {}, None)
    create_job(db, job, "create-paid-job", "2" * 64)
    quote = ResourceQuote(
        "paid-quote:1", 1, *window.namespace.as_tuple, job.activity_id,
        job.operation_id, None, lease_id, PAID_WORK_KIND, job.snapshot_ref,
        window.trusted_utc + 1000, job.resource_ref,
        runtime_job_key(*window.namespace.as_tuple, job.activity_id,
                        job.job_id).token, (), (), ceiling, None,
        window.trusted_utc + 2000, job_continuation=dict(job.continuation))
    d02.issue_quote(db, quote)
    reserve_budget(db, lease_id, job.operation_id, canonical_digest({
        "binding": binding.binding_digest, "quote": quote.quote_id,
    }), ceiling)
    params = dict(quote_id=quote.quote_id, quote_version=1,
                  budget_operation_id=job.operation_id,
                  resource_issuer=d02, budget_issuer=d11)
    return window.namespace, frozen, binding, count, installation, params


def test_paid_intent_requires_separate_signed_job_and_cold_read_identity():
    db = sqlite3.connect(":memory:")
    install_budget(db)
    install_jobs(db)
    install_issuers(db)
    install_d13_paid_intent_original_v1(db)
    db.execute("CREATE TABLE graph_authority_epochs (bot TEXT, persona TEXT, "
               "access_epoch INTEGER, delete_epoch INTEGER)")
    db.commit()
    db.execute("BEGIN IMMEDIATE")
    ns, frozen, binding, count, selected, params = _case(db)
    db.execute("INSERT INTO graph_authority_epochs VALUES(?,?,?,?)",
               ns.as_tuple + (frozen.window.access_epoch,
                              frozen.window.delete_epoch))
    original = record_d13_paid_intent_original_v1(
        db, ns, frozen, binding, count, selected, frozen.window, **params)
    assert original.ceiling["input_tokens"] == 300
    assert record_d13_paid_intent_original_v1(
        db, ns, frozen, binding, count, selected, frozen.window,
        **params) == original
    with pytest.raises(ValueError, match="worker is not current"):
        read_current_d13_paid_intent_original_v1(
            db, ns, frozen, binding, count, selected, frozen.window, **params)
    acquired = acquire_job(db, binding.job_ref, "worker:test",
        now_utc=datetime.fromtimestamp(frozen.window.trusted_utc, timezone.utc).isoformat(),
        lease_seconds=60)
    assert acquired.phase == "running" and acquired.fence == 1
    db.commit()
    db.execute("BEGIN")
    assert read_current_d13_paid_intent_original_v1(
        db, ns, frozen, binding, count, selected, frozen.window,
        **params) == original
    with pytest.raises(ValueError, match="frozen model or source"):
        read_current_d13_paid_intent_original_v1(
            db, ns, frozen, binding, count,
            replace(selected, provider_config_digest="f" * 64),
            frozen.window, **params)
    with pytest.raises(ValueError, match="original identity"):
        read_current_d13_paid_intent_original_v1(
            db, ns, frozen, binding, replace(count, wire_digest="f" * 64),
            selected, frozen.window, **params)
    with pytest.raises(ValueError, match="rights epochs"):
        db.execute("UPDATE graph_authority_epochs SET delete_epoch=delete_epoch+1")
        read_current_d13_paid_intent_original_v1(
            db, ns, frozen, binding, count, selected, frozen.window, **params)
    db.execute("UPDATE graph_authority_epochs SET delete_epoch=delete_epoch-1")
    with pytest.raises(sqlite3.IntegrityError, match="immutable"):
        db.execute("UPDATE graph_d13_paid_intent_originals_v1 "
                   "SET original_digest=?", ("0" * 64,))
    db.rollback()


def test_deterministic_d13_job_cannot_be_recorded_as_paid():
    db = sqlite3.connect(":memory:")
    install_budget(db)
    install_jobs(db)
    install_issuers(db)
    install_d13_paid_intent_original_v1(db)
    db.execute("CREATE TABLE graph_authority_epochs (bot TEXT, persona TEXT, "
               "access_epoch INTEGER, delete_epoch INTEGER)")
    db.commit()
    db.execute("BEGIN IMMEDIATE")
    ns, frozen, binding, count, selected, params = _case(db)
    db.execute("INSERT INTO graph_authority_epochs VALUES(?,?,?,?)",
               ns.as_tuple + (frozen.window.access_epoch,
                              frozen.window.delete_epoch))
    db.execute("UPDATE runtime_jobs SET work_kind='d13.precompress' "
               "WHERE job_id=?", (binding.job_ref,))
    with pytest.raises(ValueError, match="independent paid job"):
        record_d13_paid_intent_original_v1(
            db, ns, frozen, binding, count, selected, frozen.window, **params)
    assert db.execute("SELECT count(*) FROM graph_d13_paid_intent_originals_v1"
                      ).fetchone() == (0,)
    db.rollback()
