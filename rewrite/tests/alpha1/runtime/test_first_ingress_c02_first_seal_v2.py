"""Production C02 v2 first seal is atomic with its graph intent."""

from dataclasses import asdict
import json

import pytest

from sylanne3.authority_service.v2_terminal_c02_recovery_contract import (
    OriginalC02ResultKeyV1, from_wire as original_key_from_wire,
)
from sylanne3.host.authority_profile import AdminD06FirstIngressC02Policy
from sylanne3.runtime.terminal_c02_recovery_candidate_v2 import (
    FrozenTerminalC02CandidateV2, inspect_frozen_terminal_c02_candidate_v2,
)
from sylanne3.runtime_contracts import canonical_serialize

from test_first_ingress_c02_commit import c02_case


def test_first_seal_v2_persists_exact_quote_and_bundle_before_write_fence(
        c02_case, monkeypatch):
    store, coordinator, bootstrap, namespace, installation, clock, intent, read, _ = c02_case
    port = coordinator._GraphCoordinator__content_fence_v2
    original_begin = port.begin_fence

    def stop_before_write(**kwargs):
        if kwargs["operation"] == "write":
            raise RuntimeError("stop after durable first seal")
        return original_begin(**kwargs)

    monkeypatch.setattr(port, "begin_fence", stop_before_write)
    with pytest.raises(RuntimeError, match="stop after durable first seal"):
        coordinator.commit_first_ingress_c02_v2(
            bootstrap, intent, read, installation,
            AdminD06FirstIngressC02Policy(
                120.0, {"cpu_ms": 3}, "c02-snapshot", "c02-resource"),
            clock)
    db = store._db
    operation = read.request.consumer_operation_id
    intent_row = db.execute(
        "SELECT digest,fence_attempt_id FROM graph_bundle_intents_v2 "
        "WHERE bot=? AND persona=? AND operation_id=?",
        namespace.as_tuple + (operation,),
    ).fetchone()
    saved = db.execute(
        "SELECT schema,bundle_digest,fence_attempt_id,bundle_json,"
        "evidence_json,quote_json,seal_json "
        "FROM graph_first_ingress_c02_candidates_v2 "
        "WHERE bot=? AND persona=? AND operation_id=?",
        namespace.as_tuple + (operation,),
    ).fetchone()
    assert saved is not None
    assert saved[:3] == ("sylanne.first-ingress-c02-candidate.v2", *intent_row)
    assert db.execute(
        "SELECT 1 FROM graph_first_ingress_c02_candidates_v1 "
        "WHERE bot=? AND persona=? AND operation_id=?",
        namespace.as_tuple + (operation,),
    ).fetchone() is None
    raw_seal = json.loads(saved[6])
    raw_seal["original_key"] = original_key_from_wire(
        raw_seal["original_key"], OriginalC02ResultKeyV1)
    seal = FrozenTerminalC02CandidateV2(**raw_seal)
    inspected = inspect_frozen_terminal_c02_candidate_v2(
        namespace=namespace, operation_id=operation, seal=seal,
        bundle_json=saved[3], quote_json=saved[5])
    assert inspected.bundle.digest == saved[1]
    assert seal.original_worker_lease_expires_utc < seal.business_deadline_utc
    quote = coordinator._GraphCoordinator__d02_issuer.original_signed_quote(
        db, seal.quote_id, seal.quote_version)
    assert canonical_serialize(asdict(quote)) == saved[5]
    assert db.execute(
        "SELECT COUNT(*) FROM runtime_resource_quotes WHERE quote_id=?",
        (seal.quote_id,)).fetchone() == (1,)


def test_first_ingress_c02_v2_commits_with_presealed_quote(c02_case):
    store, coordinator, bootstrap, namespace, installation, clock, intent, read, _ = c02_case
    receipt = coordinator.commit_first_ingress_c02_v2(
        bootstrap, intent, read, installation,
        AdminD06FirstIngressC02Policy(
            120.0, {"cpu_ms": 3}, "c02-snapshot", "c02-resource"),
        clock)
    assert receipt.status == "committed"
    quote_id = store._db.execute(
        "SELECT quote_id FROM runtime_resource_quotes WHERE quote_json "
        "LIKE '%d06.first_ingress_c02%'"
    ).fetchone()[0]
    assert store._db.execute(
        "SELECT COUNT(*) FROM runtime_resource_quotes WHERE quote_id=?",
        (quote_id,)).fetchone() == (1,)


def test_first_seal_v2_rolls_back_quote_and_intent_together(c02_case, monkeypatch):
    store, coordinator, bootstrap, namespace, installation, clock, intent, read, _ = c02_case
    d11 = coordinator._GraphCoordinator__d11_issuer
    original_issue = d11.issue_d06_first_ingress_c02_quote_at_first_seal_v2

    def fail_after_signing(*args, **kwargs):
        original_issue(*args, **kwargs)
        raise RuntimeError("first seal interrupted")

    monkeypatch.setattr(d11, "issue_d06_first_ingress_c02_quote_at_first_seal_v2",
                        fail_after_signing)
    with pytest.raises(RuntimeError, match="first seal interrupted"):
        coordinator.commit_first_ingress_c02_v2(
            bootstrap, intent, read, installation,
            AdminD06FirstIngressC02Policy(
                120.0, {"cpu_ms": 3}, "c02-snapshot", "c02-resource"),
            clock)
    operation = read.request.consumer_operation_id
    assert store._db.execute(
        "SELECT 1 FROM graph_bundle_intents_v2 WHERE bot=? AND persona=? "
        "AND operation_id=?",
        namespace.as_tuple + (operation,),
    ).fetchone() is None
    assert store._db.execute(
        "SELECT 1 FROM runtime_resource_quotes WHERE quote_id LIKE 'd06-c02-q-%'"
    ).fetchone() is None
