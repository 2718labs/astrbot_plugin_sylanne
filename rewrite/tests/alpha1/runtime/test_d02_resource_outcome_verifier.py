"""Original resource execution evidence is required before D02 signs C04 use."""

from dataclasses import asdict, replace
import hashlib
import sqlite3
import time

import pytest

from sylanne3.domains.d02.resource_outcome_verifier import (
    candidate_outcome_from_terminal, candidate_outcome_from_verified_terminal,
    execute_local_cpu_action,
    install_resource_outcome_evidence_schema, outcome_verifier,
)
from sylanne3.authority_service.contract import JournalHead
from sylanne3.authority_service.internal_work_contract import (
    InternalWorkBindingV1, InternalWorkTerminalProofV1,
    claim_internal_work_v1, terminal_internal_work_v1,
)
from sylanne3.domains.d02.body_quote_original import BodyQuoteUnavailable
from sylanne3.domains.d02.measured_settlement import (
    build_measured_fixed_component_settlement,
)
from sylanne3.graph_types import AtomKey, Owner
from sylanne3.runtime.issuers import (
    D02ResourceIssuer, IssuerAuthorityDenied, ResourceOutcome, ResourceQuote,
    install_schema,
)
from sylanne3.runtime_contracts import (
    AuthorityContext, CommandEnvelope, NamespaceId, OperationIdentity,
    RUNTIME_SCHEMA, SourceQualification, VersionGuard, VersionedRef,
    canonical_digest, canonical_serialize,
)


@pytest.fixture
def original():
    db = sqlite3.connect(":memory:")
    install_schema(db)
    install_resource_outcome_evidence_schema(db)
    issuer = D02ResourceIssuer(b"d02-resource-verifier" * 2,
                               outcome_verifier=outcome_verifier)
    quote = ResourceQuote(
        "quote-1", 1, "bot", "persona", "activity-1", "operation-1", None,
        "lease-1", "work", "snapshot-1", 100.0, "resource-1", None,
        (), (), {"cpu_ms": 20}, None, 110.0,
    )
    outcome = ResourceOutcome(
        "outcome-1", 1, quote.quote_id, quote.bot_id, quote.persona_id,
        quote.activity_id, quote.operation_id, {"cpu_ms": 12}, True,
        "execution-1",
    )
    issuer.issue_quote(db, quote)
    yield db, issuer, quote, outcome
    db.close()


def _record(db, quote, outcome, *, operation_id=None, actual_json=None,
            receipt_ref=None, state="completed", revoked=1):
    operation_id = operation_id or quote.operation_id
    receipt_ref = receipt_ref or outcome.provider_receipt_ref
    actual_json = (canonical_serialize(outcome.actual)
                   if actual_json is None else actual_json)
    digest = hashlib.sha256(canonical_serialize(asdict(quote)).encode()).hexdigest()
    db.execute(
        "INSERT INTO d02_resource_actuals_v1 VALUES(?,?,?,?,?,?,?,?)",
        (quote.quote_id, operation_id, receipt_ref, quote.bot_id,
         quote.persona_id, quote.activity_id, digest, actual_json),
    )
    db.execute(
        "INSERT INTO d02_resource_execution_receipts_v1 VALUES(?,?,?,?,?,?,?,?,?,?)",
        (quote.quote_id, operation_id, receipt_ref, quote.bot_id,
         quote.persona_id, quote.activity_id, digest,
         hashlib.sha256(actual_json.encode()).hexdigest(), state, revoked),
    )


def test_signed_outcome_rejects_missing_execution(original):
    db, issuer, quote, outcome = original
    assert outcome_verifier(outcome, quote, db) is False
    with pytest.raises(IssuerAuthorityDenied):
        issuer.issue_outcome(db, outcome)


@pytest.mark.parametrize("change", [
    {"operation_id": "another-operation"},
    {"receipt_ref": "another-receipt"},
    {"actual_json": '{"cpu_ms":11}'},
    {"state": "running"},
    {"revoked": 0},
])
def test_mismatched_or_unfinished_evidence_fails_closed(original, change):
    db, issuer, quote, outcome = original
    _record(db, quote, outcome, **change)
    assert outcome_verifier(outcome, quote, db) is False
    with pytest.raises(IssuerAuthorityDenied):
        issuer.issue_outcome(db, outcome)


def test_quote_identity_and_complete_measurement_required(original):
    db, _issuer, quote, outcome = original
    _record(db, quote, outcome)
    assert outcome_verifier(outcome, replace(quote, resource_ref="other"), db) is False
    assert outcome_verifier(replace(outcome, actual={}), quote, db) is False


def test_no_execution_schema_is_not_a_receipt():
    db = sqlite3.connect(":memory:")
    install_schema(db)
    quote = ResourceQuote(
        "q", 1, "bot", "persona", "a", "op", None, "lease", "work",
        "snapshot", 100.0, "resource", None, (), (), {"cpu_ms": 1}, None,
        110.0,
    )
    outcome = ResourceOutcome("o", 1, "q", "bot", "persona", "a", "op",
                              {"cpu_ms": 1}, False, "receipt")
    assert outcome_verifier(outcome, quote, db) is False
    db.close()


def test_local_cpu_action_only_measures_real_work():
    run = execute_local_cpu_action(
        lambda: sum(i * i for i in range(1_000_000)),
    )
    assert run.status == "completed"
    assert run.result == 1_000_000 * 999_999 * 1_999_999 // 6
    assert run.actual_cpu_ms > 0
    assert run.error is None


def test_local_cpu_failure_is_measured_but_not_signed():
    def failing_action():
        sum(i * i for i in range(100_000))
        raise RuntimeError("action failed")

    run = execute_local_cpu_action(failing_action)
    assert run.status == "failed"
    assert run.result is None
    assert isinstance(run.error, RuntimeError)
    assert run.actual_cpu_ms >= 0


def test_measurement_cannot_authorize_an_unobserved_quote():
    db = sqlite3.connect(":memory:")
    install_schema(db)
    install_resource_outcome_evidence_schema(db)
    issuer = D02ResourceIssuer(b"d02-resource-verifier" * 2,
                               outcome_verifier=outcome_verifier)
    deadline = time.time() + 60
    quote = ResourceQuote(
        "quote-mixed", 1, "bot", "persona", "activity-mixed",
        "operation-mixed", None, "lease-mixed", "work", "snapshot-mixed",
        deadline, "resource-mixed", None, (), (),
        {"cpu_ms": 1000, "model_microusd": 1000}, None, deadline + 60,
    )
    issuer.issue_quote(db, quote)
    run = execute_local_cpu_action(lambda: 1 + 1)
    assert run.status == "completed"
    assert db.execute("SELECT COUNT(*) FROM d02_resource_actuals_v1").fetchone()[0] == 0
    assert db.execute("SELECT COUNT(*) FROM runtime_resource_outcomes").fetchone()[0] == 0
    db.close()


def test_unknown_authority_terminal_cannot_become_a_resource_outcome():
    namespace = NamespaceId("bot", "persona")
    quote = ResourceQuote(
        "quote-unknown", 1, "bot", "persona", "activity", "operation",
        None, "lease", "work", "snapshot", 4_102_444_800.0,
        "resource", None, (), (), {"cpu_ms": 100}, None, 4_102_444_900.0,
    )
    input_digest = canonical_digest({"input_refs": []})
    envelope = CommandEnvelope(
        RUNTIME_SCHEMA,
        OperationIdentity("activity", None, "attempt", "work", "operation",
                          input_digest),
        AuthorityContext("owner", "d02", "capability", namespace,
                         ("activity",), "consolidation", ("internal",),
                         "policy", 1),
        VersionGuard((), (), 0, 0, "catalogue", "scheme", "operator",
                     "policy", (), (), (VersionedRef(quote.quote_id, 1),)),
        SourceQualification((), "reported", 1.0, 1.0, "external_report",
                            "qualified", 0.5, "not_applicable"),
        (), "lease", quote.deadline_utc, 100.0, "character", (),
    )
    binding = InternalWorkBindingV1(
        "ns:sha256:" + canonical_digest(list(namespace.as_tuple)),
        "activity", "operation", "execution", input_digest,
        quote.quote_id, quote.version, canonical_digest(quote),
        "body-quote", 1, "a" * 64,
        AtomKey(Owner("activity", "bot", "persona", "activity"),
                "d02.reservation.v1", "reservation").token,
        "think", "lease", 1,
        "algorithm", "policy",
    )
    claim = claim_internal_work_v1(binding)
    terminal = terminal_internal_work_v1(binding, claim, status="unknown")
    proof = InternalWorkTerminalProofV1(
        binding, claim, terminal, "claim-ref", "b" * 64,
        "terminal-ref", "c" * 64,
        JournalHead("journal", 2, "sha256:" + "d" * 64),
    )
    with pytest.raises(ValueError, match="completed internal work"):
        candidate_outcome_from_terminal(proof, quote, envelope)
    with pytest.raises(ValueError, match="typed Authority terminal"):
        candidate_outcome_from_verified_terminal(
            object(), proof, object(), quote, envelope,
        )
    failed = terminal_internal_work_v1(
        binding, claim, status="failed", actual_cpu_ms=7,
    )
    failed_proof = InternalWorkTerminalProofV1(
        binding, claim, failed, "claim-ref", "b" * 64,
        "terminal-ref", "c" * 64,
        JournalHead("journal", 2, "sha256:" + "d" * 64),
    )
    with pytest.raises(ValueError, match="completed internal work"):
        candidate_outcome_from_terminal(failed_proof, quote, envelope)
    with pytest.raises(BodyQuoteUnavailable, match="completion receipt"):
        build_measured_fixed_component_settlement()
