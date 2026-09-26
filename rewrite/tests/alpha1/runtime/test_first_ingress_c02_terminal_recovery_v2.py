"""A first-sealed C02 result commits with one pinned post-expiry read."""

import asyncio
from dataclasses import replace
import json
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from sylanne3.authority_service.v2_terminal_c02_recovery_contract import (
    OriginalC02ResultKeyV1, TerminalRecoveryReadFactV1,
    TerminalRecoveryReadRequestV1, from_wire,
)
from sylanne3.graph_coordinator import UnavailableGuard
from sylanne3.host.authority_profile import AdminD06FirstIngressC02Policy
from sylanne3.host.terminal_c02_recovery_query import (
    PinnedTerminalC02RecoveryQueryV1,
)
from sylanne3.domains.d06 import source_key
from sylanne3.runtime.c02_terminal_job import TerminalC02JobHold
from sylanne3.runtime.issuers import IssuerAuthorityDenied
from sylanne3.runtime.terminal_c02_recovery_candidate_v2 import (
    FrozenTerminalC02CandidateV2,
)

from test_first_ingress_c02_commit import c02_case


def _sealed_case(c02_case, monkeypatch):
    store, coordinator, bootstrap, namespace, installation, clock, intent, read, fact_port = c02_case
    port = coordinator._GraphCoordinator__content_fence_v2
    original_begin = port.begin_fence

    def stop_after_seal(**kwargs):
        if kwargs["operation"] == "write":
            raise RuntimeError("stop after first seal")
        return original_begin(**kwargs)

    monkeypatch.setattr(port, "begin_fence", stop_after_seal)
    admin = AdminD06FirstIngressC02Policy(
        120.0, {"cpu_ms": 3}, "c02-snapshot", "c02-resource")
    with pytest.raises(RuntimeError, match="stop after first seal"):
        coordinator.commit_first_ingress_c02_v2(
            bootstrap, intent, read, installation, admin, clock)
    monkeypatch.setattr(port, "begin_fence", original_begin)
    row = store._db.execute(
        "SELECT seal_json FROM graph_first_ingress_c02_candidates_v2 "
        "WHERE bot=? AND persona=? AND operation_id=?",
        namespace.as_tuple + (read.request.consumer_operation_id,),
    ).fetchone()
    raw = json.loads(row[0])
    raw["original_key"] = from_wire(
        raw["original_key"], OriginalC02ResultKeyV1)
    seal = FrozenTerminalC02CandidateV2(**raw)
    expired_now = seal.original_worker_lease_expires_utc + 1.0
    assert expired_now < seal.business_deadline_utc

    def expired_clock(_policy):
        return SimpleNamespace(
            utc_upper_bound_seconds=expired_now,
            monotonic_after_seconds=time.monotonic())

    monkeypatch.setattr(port, "read_ingress_clock", expired_clock)
    request = TerminalRecoveryReadRequestV1(
        seal.original_key, read.request.consumer_operation_id,
        "terminal-c02-read-1")
    fact = TerminalRecoveryReadFactV1(
        request, "8" * 64, seal.original_key.stable_result_digest, "9" * 64)
    adapter = object.__new__(PinnedTerminalC02RecoveryQueryV1)
    adapter._request = request
    return (store, coordinator, bootstrap, namespace, installation, clock,
            admin, read, fact_port, seal, fact, adapter)


def test_expired_c02_uses_original_quote_and_job_in_one_graph_commit(
        c02_case, monkeypatch):
    (store, coordinator, bootstrap, namespace, installation, clock, admin,
     read, fact_port, seal, fact, adapter) = _sealed_case(c02_case, monkeypatch)
    quote_count = store._db.execute(
        "SELECT COUNT(*) FROM runtime_resource_quotes WHERE quote_id=?",
        (seal.quote_id,),
    ).fetchone()[0]

    async def pinned_query(_self):
        assert not store._lock._is_owned()
        return fact

    with patch.object(PinnedTerminalC02RecoveryQueryV1, "query_finished",
                      pinned_query):
        receipt = asyncio.run(coordinator.recover_pending_first_ingress_c02_v2(
            bootstrap, namespace, read.request.consumer_operation_id,
            installation, admin, clock, adapter))
    assert receipt.status == "committed"
    assert fact_port.calls == 0
    assert store._db.execute(
        "SELECT COUNT(*) FROM runtime_resource_quotes WHERE quote_id=?",
        (seal.quote_id,),
    ).fetchone()[0] == quote_count
    assert store._db.execute(
        "SELECT phase,result_ref FROM runtime_jobs WHERE job_id=?",
        (read.request.job_id,),
    ).fetchone()[0] == "completed"
    assert store._db.execute(
        "SELECT 1 FROM graph_first_ingress_c02_candidates_v2 WHERE bot=? "
        "AND persona=? AND operation_id=?",
        namespace.as_tuple + (read.request.consumer_operation_id,),
    ).fetchone() is None


def test_terminal_c02_rejects_mismatched_pinned_fact_before_write(
        c02_case, monkeypatch):
    (store, coordinator, bootstrap, namespace, installation, clock, admin,
     read, _, seal, fact, adapter) = _sealed_case(c02_case, monkeypatch)
    other_request = replace(fact.request, read_attempt_id="other-attempt")
    with patch.object(PinnedTerminalC02RecoveryQueryV1, "query_finished",
                      AsyncMock(return_value=replace(fact, request=other_request))):
        with pytest.raises(TerminalC02JobHold):
            asyncio.run(coordinator.recover_pending_first_ingress_c02_v2(
                bootstrap, namespace, read.request.consumer_operation_id,
                installation, admin, clock, adapter))
    assert store._db.execute(
        "SELECT phase FROM runtime_jobs WHERE job_id=?",
        (read.request.job_id,),
    ).fetchone() == ("running",)
    assert store._db.execute(
        "SELECT 1 FROM graph_first_ingress_c02_candidates_v2 WHERE bot=? "
        "AND persona=? AND operation_id=?",
        namespace.as_tuple + (read.request.consumer_operation_id,),
    ).fetchone() is not None


@pytest.mark.parametrize("lost_authority", ["source", "budget_grant"])
def test_terminal_c02_rechecks_current_source_and_budget_before_job_cas(
        c02_case, monkeypatch, lost_authority):
    (store, coordinator, bootstrap, namespace, installation, clock, admin,
     read, _, seal, fact, adapter) = _sealed_case(c02_case, monkeypatch)
    if lost_authority == "source":
        evidence = json.loads(store._db.execute(
            "SELECT evidence_json FROM graph_first_ingress_c02_candidates_v2 "
            "WHERE bot=? AND persona=? AND operation_id=?",
            namespace.as_tuple + (read.request.consumer_operation_id,),
        ).fetchone()[0])
        store._db.execute(
            "UPDATE graph_atoms SET valid=0 WHERE token=?",
            (source_key(*namespace.as_tuple, evidence["source_ref"]).token,),
        )
    else:
        store._db.execute(
            "UPDATE runtime_budget_grants SET status='revoked' "
            "WHERE lease_id=(SELECT budget_ref FROM runtime_jobs WHERE job_id=?)",
            (read.request.job_id,),
        )
    with patch.object(PinnedTerminalC02RecoveryQueryV1, "query_finished",
                      AsyncMock(return_value=fact)):
        with pytest.raises((UnavailableGuard, IssuerAuthorityDenied)):
            asyncio.run(coordinator.recover_pending_first_ingress_c02_v2(
                bootstrap, namespace, read.request.consumer_operation_id,
                installation, admin, clock, adapter))
    assert store._db.execute(
        "SELECT phase FROM runtime_jobs WHERE job_id=?",
        (read.request.job_id,),
    ).fetchone() == ("running",)
    assert store._db.execute(
        "SELECT 1 FROM graph_bundle_operations WHERE bot=? AND persona=? "
        "AND operation_id=?",
        namespace.as_tuple + (read.request.consumer_operation_id,),
    ).fetchone() is None
