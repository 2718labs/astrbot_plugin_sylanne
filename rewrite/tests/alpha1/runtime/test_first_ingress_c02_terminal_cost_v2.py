"""A finished v2 C02 terminal leaves one conservative historical charge."""

import asyncio
from dataclasses import replace
import json
from unittest.mock import patch

import pytest

from sylanne3.host.terminal_c02_recovery_query import (
    PinnedTerminalC02RecoveryQueryV1,
)
from sylanne3.runtime.c02_cost_settlement import (
    C02CostUnavailable, apply_c02_terminal_unknown_budget_in_transaction,
    prepare_c02_terminal_unknown_cost_plan,
)
from sylanne3.runtime.c02_terminal_job import pin_finished_terminal_read_from_host

from test_first_ingress_c02_commit import c02_case
from test_first_ingress_c02_terminal_recovery_v2 import _sealed_case


def _committed_case(c02_case, monkeypatch):
    (store, coordinator, bootstrap, namespace, installation, clock, admin,
     read, _, seal, fact, adapter) = _sealed_case(c02_case, monkeypatch)
    request = coordinator.read_pending_first_ingress_c02_terminal_request_v2(
        bootstrap, namespace, read.request.consumer_operation_id)
    adapter._request = request
    fact = replace(fact, request=request)
    coordinator.claim_pending_first_ingress_c02_terminal_read_v2(
        bootstrap, namespace, read.request.consumer_operation_id, request)

    async def query(_self):
        assert not store._lock._is_owned()
        return fact

    with patch.object(PinnedTerminalC02RecoveryQueryV1, "query_finished", query):
        pinned = asyncio.run(pin_finished_terminal_read_from_host(adapter))
        receipt = coordinator.recover_pending_first_ingress_c02_v2_pinned(
            bootstrap, namespace, read.request.consumer_operation_id,
            installation, admin, clock, adapter, pinned)
    return (store, coordinator, namespace, c02_case[6], seal, pinned,
            replace(receipt, status="duplicate"))


def test_v2_terminal_cost_settles_original_reservation_once(c02_case, monkeypatch):
    store, coordinator, namespace, intent, seal, pinned, verified = (
        _committed_case(c02_case, monkeypatch))
    db = store._db
    issuer = coordinator._GraphCoordinator__d02_issuer
    plan = prepare_c02_terminal_unknown_cost_plan(
        db, issuer, namespace, intent, seal, pinned, verified)
    assert db.execute(
        "SELECT state FROM runtime_budget_reservations WHERE operation_id=?",
        (seal.consumer_operation_id,),
    ).fetchone() == ("reserved",)
    db.execute("BEGIN IMMEDIATE")
    try:
        applied = apply_c02_terminal_unknown_budget_in_transaction(
            db, issuer, plan, namespace, intent, seal, pinned, verified)
        assert applied.receipt.status == "pending_confirmation"
        assert applied.cost_write.key.type_name == "runtime.cost_settlement"
        assert db.execute(
            "SELECT state FROM runtime_budget_reservations WHERE operation_id=?",
            (seal.consumer_operation_id,),
        ).fetchone() == ("unknown",)
        assert issuer.original_c02_unknown_outcome(db, plan.quote) == plan.outcome
    finally:
        db.rollback()


def test_v2_terminal_cost_rejects_bare_fact_and_changed_receipt(
        c02_case, monkeypatch):
    store, coordinator, namespace, intent, seal, pinned, verified = (
        _committed_case(c02_case, monkeypatch))
    db = store._db
    issuer = coordinator._GraphCoordinator__d02_issuer
    with pytest.raises(C02CostUnavailable):
        prepare_c02_terminal_unknown_cost_plan(
            db, issuer, namespace, intent, seal, pinned.fact, verified)
    row = db.execute(
        "SELECT receipt_json FROM graph_bundle_operations WHERE bot=? "
        "AND persona=? AND operation_id=?",
        namespace.as_tuple + (seal.consumer_operation_id,),
    ).fetchone()
    receipt = json.loads(row[0])
    receipt["first_ingress_c02"]["terminal_read_fact_digest"] = "0" * 64
    db.execute("BEGIN IMMEDIATE")
    try:
        db.execute(
            "UPDATE graph_bundle_operations SET receipt_json=? WHERE bot=? "
            "AND persona=? AND operation_id=?",
            (json.dumps(receipt, sort_keys=True, separators=(",", ":")),
             *namespace.as_tuple, seal.consumer_operation_id),
        )
        with pytest.raises(C02CostUnavailable):
            prepare_c02_terminal_unknown_cost_plan(
                db, issuer, namespace, intent, seal, pinned, verified)
    finally:
        db.rollback()
