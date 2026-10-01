"""Verify a D02 outcome against original resource execution evidence.

The execution adapter must persist the actual measurement and terminal receipt
before asking D02 to sign an outcome. This module deliberately does not write
either fact: a quote, D11 budget entry, or model-cost record cannot attest that
resource work ran.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
import math
import sqlite3
import time
from typing import Callable, Generic, TypeVar

from ...authority_service.internal_work_contract import (
    InternalWorkTerminalProofV1, validate_internal_work_terminal_proof_v1,
)
from ...authority_service.internal_work_service import (
    AuthorityInternalWorkVerifiedReceiptV1,
)
from ...runtime.issuers import ResourceOutcome, ResourceQuote
from ...runtime.c04_internal_work_original_v1 import C04InternalWorkPreparedV1
from ...runtime_contracts import CommandEnvelope, canonical_digest, canonical_serialize


T = TypeVar("T")
C04_INTERNAL_CPU_WORK_KIND = "d06.c04_internal_cpu.v1"


def install_resource_outcome_evidence_schema(db: sqlite3.Connection) -> None:
    """Install the evidence contract for a trusted execution adapter."""
    db.execute("""
        CREATE TABLE IF NOT EXISTS d02_resource_actuals_v1 (
            quote_id TEXT NOT NULL,
            operation_id TEXT NOT NULL,
            provider_receipt_ref TEXT NOT NULL,
            bot_id TEXT NOT NULL,
            persona_id TEXT NOT NULL,
            activity_id TEXT NOT NULL,
            quote_digest TEXT NOT NULL,
            actual_json TEXT,
            PRIMARY KEY (quote_id, operation_id, provider_receipt_ref)
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS d02_resource_execution_receipts_v1 (
            quote_id TEXT NOT NULL,
            operation_id TEXT NOT NULL,
            provider_receipt_ref TEXT NOT NULL,
            bot_id TEXT NOT NULL,
            persona_id TEXT NOT NULL,
            activity_id TEXT NOT NULL,
            quote_digest TEXT NOT NULL,
            actual_digest TEXT NOT NULL,
            state TEXT NOT NULL,
            execution_revoked INTEGER NOT NULL,
            PRIMARY KEY (quote_id, operation_id, provider_receipt_ref)
        )
    """)


def outcome_verifier(
    outcome: ResourceOutcome, quote: ResourceQuote, db: sqlite3.Connection,
) -> bool:
    """Accept only an original signed quote and matching durable execution facts.

    The caller (D02ResourceIssuer) authenticates the quote signature. No
    execution producer is wired today, so an absent table or row returns False.
    """
    if (type(outcome) is not ResourceOutcome or type(quote) is not ResourceQuote
            or not isinstance(db, sqlite3.Connection)):
        return False
    identity = (quote.quote_id, quote.operation_id, outcome.provider_receipt_ref)
    if ((outcome.quote_id, outcome.operation_id) != identity[:2]
            or (outcome.bot_id, outcome.persona_id, outcome.activity_id)
            != (quote.bot_id, quote.persona_id, quote.activity_id)):
        return False
    try:
        quote_json = canonical_serialize(asdict(quote))
        durable_quote = db.execute(
            "SELECT quote_json,status FROM runtime_resource_quotes "
            "WHERE quote_id=? AND version=?", (quote.quote_id, quote.version),
        ).fetchone()
        if durable_quote != (quote_json, "active"):
            return False
        quote_digest = hashlib.sha256(quote_json.encode("utf-8")).hexdigest()
        actual = db.execute(
            "SELECT bot_id,persona_id,activity_id,quote_digest,actual_json "
            "FROM d02_resource_actuals_v1 WHERE quote_id=? AND operation_id=? "
            "AND provider_receipt_ref=?", identity,
        ).fetchone()
        receipt = db.execute(
            "SELECT bot_id,persona_id,activity_id,quote_digest,actual_digest,"
            "state,execution_revoked FROM d02_resource_execution_receipts_v1 "
            "WHERE quote_id=? AND operation_id=? AND provider_receipt_ref=?",
            identity,
        ).fetchone()
        if actual is None or receipt is None:
            return False
        owner = (quote.bot_id, quote.persona_id, quote.activity_id, quote_digest)
        if actual[:4] != owner or receipt[:4] != owner:
            return False
        measured_json = actual[4]
        measurement = json.loads(measured_json)
        if measurement is None:
            if outcome.actual is not None:
                return False
        elif (type(measurement) is not dict
              or set(measurement) != set(quote.ceiling)
              or any(type(value) is not int or value < 0
                     for value in measurement.values())
              or {name: value for name, value in measurement.items() if value}
              != outcome.actual):
            return False
        if canonical_serialize(measurement) != measured_json:
            return False
        return (receipt[4] == hashlib.sha256(measured_json.encode("utf-8")).hexdigest()
                and receipt[5] == "completed"
                and type(receipt[6]) is int
                and receipt[6] == int(outcome.execution_revoked))
    except (sqlite3.Error, TypeError, ValueError, json.JSONDecodeError):
        return False


@dataclass(frozen=True)
class LocalCpuRunV1(Generic[T]):
    """Volatile observation; Authority must persist its own terminal."""

    status: str
    actual_cpu_ms: int
    result: T | None
    error: Exception | None


def execute_local_cpu_action(action: Callable[[], T]) -> LocalCpuRunV1[T]:
    """Measure one synchronous action; perform no database or signing work.

    Only the current thread's CPU is covered. The returned value cannot be
    used as a durable terminal or a D02 outcome. A crash before Authority
    records the terminal leaves the original claim unknown.
    """
    if not callable(action):
        raise TypeError("local CPU action must be callable")
    clock = getattr(time, "thread_time_ns", None)
    if not callable(clock):
        raise RuntimeError("thread CPU clock is unavailable")
    start = clock()
    result: T | None = None
    error: Exception | None = None
    try:
        result = action()
    except Exception as exc:
        error = exc
    elapsed_ns = clock() - start
    if elapsed_ns < 0:
        raise RuntimeError("thread CPU clock moved backwards")
    return LocalCpuRunV1(
        "completed" if error is None else "failed",
        math.ceil(elapsed_ns / 1_000_000), result, error,
    )


def candidate_outcome_from_terminal(
    proof: InternalWorkTerminalProofV1,
    quote: ResourceQuote,
    envelope: CommandEnvelope,
) -> ResourceOutcome:
    """Check the typed terminal's C04 identity; never authenticate or sign it.

    The installed W09 port must independently reread its claim and terminal
    before this candidate may enter the business SQLite evidence transaction.
    """
    if (type(proof) is not InternalWorkTerminalProofV1
            or type(quote) is not ResourceQuote
            or type(envelope) is not CommandEnvelope):
        raise ValueError("typed internal work terminal, quote and envelope required")
    binding, terminal = proof.binding, proof.terminal
    validate_internal_work_terminal_proof_v1(proof, expected_binding=binding)
    namespace = envelope.authority.namespace
    if (terminal.status != "completed" or not terminal.component_completed
            or terminal.actual_cpu_ms is None
            or binding.namespace != "ns:sha256:" + canonical_digest(
                list(namespace.as_tuple))
            or (quote.bot_id, quote.persona_id) != namespace.as_tuple
            or (binding.activity_id, binding.operation_id,
                binding.input_digest) != (
                    envelope.identity.activity_id,
                    envelope.identity.operation_id,
                    envelope.identity.canonical_input_digest)
            or (binding.resource_quote_ref, binding.resource_quote_version,
                binding.resource_quote_digest) != (
                    quote.quote_id, quote.version, canonical_digest(quote))
            or binding.parent_budget_lease_ref != quote.parent_budget_lease_ref
            or binding.activation_generation != envelope.authority.activation_generation
            or quote.operation_id != envelope.identity.operation_id
            or quote.activity_id != envelope.identity.activity_id
            or quote.work_kind != C04_INTERNAL_CPU_WORK_KIND
            or set(quote.ceiling) != {"cpu_ms"}
            or quote.required_worker_fence is not None):
        raise ValueError("completed internal work differs from original C04 quote")
    return ResourceOutcome(
        "internal-work-outcome:" + binding.execution_id, 1,
        quote.quote_id, quote.bot_id, quote.persona_id,
        quote.activity_id, quote.operation_id,
        {"cpu_ms": terminal.actual_cpu_ms}, True,
        terminal.component_receipt_ref,
    )


def candidate_outcome_from_verified_terminal(
    verified: AuthorityInternalWorkVerifiedReceiptV1,
    proof: InternalWorkTerminalProofV1,
    prepared: C04InternalWorkPreparedV1,
    quote: ResourceQuote,
    envelope: CommandEnvelope,
) -> ResourceOutcome:
    """Join typed Authority reread with W01's prepared identity only.

    This does not establish the receipt's provenance: the installed Authority
    reader and current Owner/head check must run outside the accounting graph
    transaction. D02 must not sign solely from a caller-built DTO.
    """
    if (type(verified) is not AuthorityInternalWorkVerifiedReceiptV1
            or type(proof) is not InternalWorkTerminalProofV1
            or type(prepared) is not C04InternalWorkPreparedV1):
        raise ValueError("typed Authority terminal and W01 original required")
    binding, terminal = proof.binding, proof.terminal
    if (prepared.binding != binding
            or verified.proof_digest != canonical_digest(proof)
            or (verified.namespace, verified.activity_id,
                verified.operation_id, verified.execution_id,
                verified.input_digest) != (
                    binding.namespace, binding.activity_id,
                    binding.operation_id, binding.execution_id,
                    binding.input_digest)
            or (verified.resource_quote_ref,
                verified.resource_quote_version,
                verified.resource_quote_digest) != (
                    binding.resource_quote_ref,
                    binding.resource_quote_version,
                    binding.resource_quote_digest)
            or (verified.terminal_receipt_ref,
                verified.terminal_receipt_digest) != (
                    proof.terminal_receipt_ref,
                    proof.terminal_receipt_digest)
            or verified.journal_head != proof.journal_head
            or type(verified.terminal_sequence) is not int
            or verified.terminal_sequence < 2
            or (verified.status, verified.actual_cpu_ms,
                verified.component_completed) != (
                    terminal.status, terminal.actual_cpu_ms,
                    terminal.component_completed)):
        raise ValueError("Authority verified terminal differs from C04 original")
    return candidate_outcome_from_terminal(proof, quote, envelope)
