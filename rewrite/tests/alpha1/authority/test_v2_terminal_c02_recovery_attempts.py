"""Terminal C02 read attempts persist exact identities without provider bodies."""

from dataclasses import asdict, replace
import sqlite3

import pytest

from sylanne3.authority_service.contract import AuthorityUnavailable
from sylanne3.authority_service.v2_contract import FencePermitV2
from sylanne3.authority_service.v2_terminal_c02_recovery_attempts import (
    AuthorityV2TerminalC02RecoveryAttempts,
)
from sylanne3.authority_service.v2_terminal_c02_recovery_contract import (
    OriginalC02ResultKeyV1, TerminalRecoveryReadFactV1,
    TerminalRecoveryReadRequestV1, from_wire, to_wire,
)
from sylanne3.runtime.first_ingress_c02_identity import first_ingress_c02_consumer_operation_id_v1
from sylanne3.runtime.restore_anchor import RestoreAnchor
from sylanne3.runtime_contracts import NamespaceId, canonical_digest


def identity():
    namespace = NamespaceId("bot", "persona")
    key = OriginalC02ResultKeyV1(
        "authority", "authority-ns", namespace, "installation",
        "job", "original-operation", "acquire", "acquire", "call",
        "a" * 64, "b" * 64, "c" * 64, "d" * 64, "e" * 64,
    )
    operation = first_ingress_c02_consumer_operation_id_v1(
        namespace=namespace, authority_id=key.authority_id,
        authority_namespace=key.authority_namespace,
        installation_id=key.installation_id, job_id=key.job_id,
        acquire_operation_id=key.acquire_operation_id,
        original_operation_id=key.original_operation_id, call_id=key.call_id,
        binding_digest=key.binding_digest,
        model_request_digest=key.model_request_digest,
    )
    request = TerminalRecoveryReadRequestV1(key, operation, "recovery-read-1")
    anchor = RestoreAnchor(
        key.authority_id, key.authority_namespace, 2,
        "deletion-journal", 0, "genesis", "execution-journal", 0,
        "genesis", 0, "proof",
    )
    permit = FencePermitV2(
        key.authority_id, key.authority_namespace, "recovery-observer",
        "installation-holder", 2, "read", request.read_attempt_id,
        "p" * 32, 1, 0, anchor,
    )
    return request, permit


def connection(path):
    db = sqlite3.connect(path, isolation_level=None)
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA synchronous=FULL")
    return db


def test_terminal_attempt_fact_roundtrip_and_restart_query(tmp_path):
    request, permit = identity()
    path = tmp_path / "authority.db"
    db = connection(path)
    ledger = AuthorityV2TerminalC02RecoveryAttempts(db, create=True)
    with ledger._tx() as tx:
        begun = ledger.begin_locked(tx, request, permit=permit)
        assert ledger.begin_locked(tx, request, permit=permit) == begun
    assert begun.state == "active"
    assert ledger.read(request) == (begun, None)
    handoff = "f" * 64
    with ledger._tx() as tx:
        fact = ledger.finish_locked(tx, request, permit=permit,
                                    handoff_digest=handoff)
        assert ledger.finish_locked(tx, request, permit=permit,
                                    handoff_digest=handoff) == fact
    assert fact.result_digest == request.original_key.stable_result_digest
    assert from_wire(to_wire(fact), TerminalRecoveryReadFactV1) == fact
    assert "result_json" not in str(to_wire(fact))
    db.close()

    reopened = connection(path)
    try:
        persisted = AuthorityV2TerminalC02RecoveryAttempts(reopened)
        attempt, recovered_fact = persisted.read(request)
        assert attempt.state == "finished"
        assert recovered_fact == fact
        with persisted._tx() as tx:
            with pytest.raises(AuthorityUnavailable, match="cannot reopen"):
                persisted.begin_locked(tx, request, permit=permit)
        columns = {row[1] for row in reopened.execute(
            "PRAGMA table_info(authority_terminal_c02_read_attempts_v1)"
        )}
        assert "result_json" not in columns
        assert "observation_json" not in columns
    finally:
        reopened.close()


def test_terminal_attempt_conflicts_on_changed_request_permit_or_handoff(tmp_path):
    request, permit = identity()
    db = connection(tmp_path / "authority.db")
    try:
        ledger = AuthorityV2TerminalC02RecoveryAttempts(db, create=True)
        with ledger._tx() as tx:
            ledger.begin_locked(tx, request, permit=permit)
            with pytest.raises(AuthorityUnavailable, match="identity conflict"):
                ledger.begin_locked(tx, request, permit=replace(permit, token="q" * 32))
            with pytest.raises(AuthorityUnavailable, match="already has a read attempt"):
                ledger.begin_locked(tx, replace(request, read_attempt_id="other-read"),
                                    permit=replace(permit, operation_id="other-read"))
            ledger.finish_locked(tx, request, permit=permit,
                                 handoff_digest="f" * 64)
            with pytest.raises(AuthorityUnavailable, match="handoff digest conflict"):
                ledger.finish_locked(tx, request, permit=permit,
                                     handoff_digest="0" * 64)
        changed_key = replace(request.original_key, observation_digest="0" * 64)
        with pytest.raises(AuthorityUnavailable, match="identity conflict"):
            ledger.read(replace(request, original_key=changed_key))
    finally:
        db.close()


def test_terminal_attempt_rejects_wrong_operation_fence_and_transaction(tmp_path):
    request, permit = identity()
    db = connection(tmp_path / "authority.db")
    try:
        ledger = AuthorityV2TerminalC02RecoveryAttempts(db, create=True)
        with pytest.raises(AuthorityUnavailable, match="same Authority transaction"):
            ledger.begin_locked(db, request, permit=permit)
        with ledger._tx() as tx:
            with pytest.raises(AuthorityUnavailable, match="business operation differs"):
                ledger.begin_locked(tx, replace(request, consumer_operation_id="other"),
                                    permit=permit)
            with pytest.raises(AuthorityUnavailable, match="current read fence"):
                ledger.begin_locked(tx, request, permit=replace(permit, operation_id="other"))
            ledger.begin_locked(tx, request, permit=permit)
            with pytest.raises(ValueError, match="handoff_digest"):
                ledger.finish_locked(tx, request, permit=permit, handoff_digest="bad")
    finally:
        db.close()


def test_terminal_attempt_rolls_back_finish_and_detects_record_tampering(tmp_path):
    request, permit = identity()
    db = connection(tmp_path / "authority.db")
    try:
        ledger = AuthorityV2TerminalC02RecoveryAttempts(db, create=True)
        with ledger._tx() as tx:
            ledger.begin_locked(tx, request, permit=permit)
        with pytest.raises(RuntimeError, match="transport failed"):
            with ledger._tx() as tx:
                ledger.finish_locked(tx, request, permit=permit,
                                     handoff_digest="f" * 64)
                raise RuntimeError("transport failed")
        assert ledger.read(request)[0].state == "active"
        assert ledger.read(request)[1] is None
        with ledger._tx() as tx:
            tx.execute("UPDATE authority_terminal_c02_read_attempts_v1 "
                       "SET request_digest=? WHERE read_attempt_id=?",
                       (canonical_digest({"different": asdict(request)}),
                        request.read_attempt_id))
        with pytest.raises(AuthorityUnavailable, match="record differs"):
            ledger.read(request)
    finally:
        db.close()
