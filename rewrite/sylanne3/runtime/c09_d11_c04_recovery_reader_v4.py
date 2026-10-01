"""Read one C04 CPU D11 recovery fact from current signed originals.

This is a narrow C09 recovery reader. The installed Authority service must
still attest the current journal/Core head, and W01 must call it inside its
current business SQLite read transaction. Other budget paths remain HOLD.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3

from ..authority_service.internal_work_contract import InternalWorkTerminalProofV1
from ..authority_service.internal_work_service import AuthorityInternalWorkService
from ..authority_service.contract import JournalHead
from ..domains.d02.resource_outcome_verifier import C04_INTERNAL_CPU_WORK_KIND
from ..runtime_contracts import NamespaceId, canonical_digest
from .budget import BudgetReceipt, _receipt_json, get_budget_lease
from .c04_internal_work_original_v1 import read_c04_internal_work_prepared_v1
from .c09_storage_rebase_contract_v1 import SanitizedD11FactV4
from .d11_c04_internal_cost import read_c04_cpu_cost_original_v1
from .issuers import D02ResourceIssuer


class C09D11RecoveryHold(ValueError):
    """A signed C04 budget fact cannot be proven from current originals."""


def _operation(db: sqlite3.Connection, namespace: NamespaceId,
               operation_id: str, phase: str, lease_id: str,
               digest: str) -> BudgetReceipt:
    row = db.execute(
        "SELECT digest,lease_id,receipt_json,resolution_binding_json "
        "FROM runtime_budget_operations WHERE bot_id=? AND persona_id=? "
        "AND operation_id=? AND phase=?",
        (*namespace.as_tuple, operation_id, phase),
    ).fetchone()
    if row is None or row[0] != digest or row[1] != lease_id:
        raise C09D11RecoveryHold(f"D11 {phase} original is absent or differs")
    try:
        receipt = BudgetReceipt(**json.loads(row[2]))
    except (TypeError, ValueError, KeyError) as exc:
        raise C09D11RecoveryHold(f"D11 {phase} receipt is malformed") from exc
    if (row[2] != _receipt_json(receipt)
            or receipt.operation_id != operation_id
            or receipt.lease_id != lease_id or receipt.digest != digest
            or (phase == "reserve" and row[3] is not None)):
        raise C09D11RecoveryHold(f"D11 {phase} receipt identity differs")
    return receipt


def read_current_c04_d11_recovery_fact_v4(
    db: sqlite3.Connection, *, namespace: NamespaceId, operation_id: str,
    issuer: D02ResourceIssuer, authority: AuthorityInternalWorkService,
    prepared_proof: InternalWorkTerminalProofV1 | None = None,
) -> SanitizedD11FactV4:
    """Issue a known CPU fact only after signed quote/terminal and budget replay.

    No amount, quote, proof, or budget identifier is accepted from the caller.
    The current installed Authority reader and D02 signer are required.
    Unknown/partial budget states never become a zero-cost fact.
    """
    if (type(db) is not sqlite3.Connection or not db.in_transaction
            or type(namespace) is not NamespaceId
            or type(operation_id) is not str or not operation_id
            or type(issuer) is not D02ResourceIssuer
            or type(authority) is not AuthorityInternalWorkService
            or not authority.installed_runtime_verified):
        raise C09D11RecoveryHold("current installed D11 recovery readers unavailable")
    return read_c04_d11_recovery_fact_connection_v4(
        db, namespace=namespace, operation_id=operation_id, issuer=issuer, authority=authority, prepared_proof=prepared_proof)


__all__ = ["C09D11RecoveryHold", "read_current_c04_d11_recovery_fact_v4"]


def read_c04_d11_recovery_fact_connection_v4(db, *, namespace, operation_id, issuer, authority, prepared_proof=None):
    from ..authority_service.c09_installed_original_verifiers_v1 import InstalledC09OriginalVerifierV1
    if (not db.in_transaction or type(authority) not in {AuthorityInternalWorkService, InstalledC09OriginalVerifierV1}
            or (type(authority) is InstalledC09OriginalVerifierV1 and (authority.kind != "internal" or prepared_proof is None))):
        raise C09D11RecoveryHold("actual installed original verifier and pinned snapshot required")
    try:
        prepared = read_c04_internal_work_prepared_v1(db, namespace, operation_id)
        original = read_c04_cpu_cost_original_v1(db, namespace, operation_id)
        if prepared is None or original is None:
            raise C09D11RecoveryHold("C04 preparation or D11 cost original absent")
        binding = prepared.binding
        if (original.binding_digest != binding.binding_digest
                or original.prepared_digest != prepared.prepared_digest
                or original.budget_operation_id != prepared.budget_reservation_operation_id
                or original.budget_lease_id != binding.parent_budget_lease_ref
                or original.budget_reservation_digest != prepared.budget_reservation_digest
                or prepared.budget_reservation_operation_id
                   != "c04-internal-budget:" + binding.binding_digest):
            raise C09D11RecoveryHold("C04 and D11 original binding differs")
        quote = issuer.original_signed_quote(
            db, binding.resource_quote_ref, binding.resource_quote_version)
        if (canonical_digest(quote) != binding.resource_quote_digest
                or (quote.bot_id, quote.persona_id, quote.activity_id,
                    quote.operation_id, quote.parent_budget_lease_ref)
                   != (*namespace.as_tuple, binding.activity_id, operation_id,
                       binding.parent_budget_lease_ref)
                or quote.work_kind != C04_INTERNAL_CPU_WORK_KIND
                or quote.required_worker_fence is not None
                or set(quote.ceiling) != {"cpu_ms"}):
            raise C09D11RecoveryHold("original signed D02 quote differs")
        if prepared_proof is None:
            observation = authority.inspect(binding)
            if (observation.claim is None or observation.terminal is None
                    or observation.claim_append is None
                    or observation.terminal_append is None):
                raise C09D11RecoveryHold("current Authority terminal is absent")
            proof = InternalWorkTerminalProofV1(
                binding, observation.claim, observation.terminal,
                observation.claim_append.receipt_ref,
                observation.claim_append.content_digest,
                observation.terminal_append.receipt_ref,
                observation.terminal_append.content_digest,
                JournalHead(observation.verified_head.journal_id,
                            observation.terminal_append.sequence,
                            observation.terminal_append.chain_digest),
            )
            verified = authority.verify_original_internal_work_terminal(proof)
            status, actual, completed = (verified.status,
                                         verified.actual_cpu_ms,
                                         verified.component_completed)
            proof_digest = verified.proof_digest
            terminal_ref = verified.terminal_receipt_ref
            terminal_digest = verified.terminal_receipt_digest
        else:
            # Core has already scanned the sealed PREPARED chain and joined
            # this proof to its exact rows. The installed signer still checks
            # the V2/V3 terminal; normal inspection is blocked by PREPARED.
            proof = prepared_proof
            if (proof.binding != binding
                    or proof.journal_head.journal_id != authority.journal.journal_id
                    or authority.verify_installed_terminal(
                        binding, proof.claim, proof.terminal) is not True):
                raise C09D11RecoveryHold("prepared terminal signature differs")
            status = proof.terminal.status
            actual = proof.terminal.actual_cpu_ms
            completed = (status == "completed"
                         and proof.terminal.component_receipt_ref is not None)
            proof_digest = canonical_digest(proof)
            terminal_ref = proof.terminal_receipt_ref
            terminal_digest = proof.terminal_receipt_digest
        if (proof_digest != original.proof_digest
                or terminal_ref != original.terminal_receipt_ref
                or terminal_digest != original.terminal_receipt_digest
                or status != original.status
                or actual != original.actual_cpu_ms
                or completed != original.component_completed
                or original.status not in {"completed", "failed"}):
            raise C09D11RecoveryHold("signed Authority terminal differs from D11 cost")
        lease = get_budget_lease(db, binding.parent_budget_lease_ref)
        if (lease.bot_id, lease.persona_id) != namespace.as_tuple:
            raise C09D11RecoveryHold("parent budget belongs to another namespace")
        reserve = _operation(db, namespace, original.budget_operation_id,
                             "reserve", lease.lease_id, binding.binding_digest)
        settle = _operation(db, namespace, original.budget_operation_id,
                            "settle", lease.lease_id, binding.binding_digest)
        reserve_row = db.execute(
            "SELECT digest,ceiling_json,state,actual_json "
            "FROM runtime_budget_reservations WHERE lease_id=? AND operation_id=?",
            (lease.lease_id, original.budget_operation_id),
        ).fetchone()
        ceiling = int(quote.ceiling["cpu_ms"])
        actual = original.actual_cpu_ms
        if (hashlib.sha256(_receipt_json(reserve).encode("utf-8")).hexdigest()
                != prepared.budget_reservation_digest
                or reserve.status != "reserved"
                or reserve_row != (
                    binding.binding_digest, json.dumps({"cpu_ms": ceiling},
                                                       separators=(",", ":")),
                    "overrun" if actual > ceiling else "settled",
                    json.dumps({"cpu_ms": actual}, separators=(",", ":")),
                )
                or settle.status != original.budget_receipt_status
                or settle.status != ("overrun" if actual > ceiling else "settled")
                or settle.version <= reserve.version):
            raise C09D11RecoveryHold("D11 reserve, actual, or settle original differs")
        settle_row = db.execute(
            "SELECT resolution_binding_json FROM runtime_budget_operations "
            "WHERE bot_id=? AND persona_id=? AND operation_id=? AND phase='settle'",
            (*namespace.as_tuple, original.budget_operation_id),
        ).fetchone()
        if settle_row != (json.dumps({
                "actual": {"cpu_ms": actual}, "execution_revoked": True,
        }, sort_keys=True, separators=(",", ":")),):
            raise C09D11RecoveryHold("D11 original settlement call differs")
        debt = max(0, actual - ceiling)
        debt_row = db.execute(
            "SELECT 1 FROM runtime_budget_debt_blocks WHERE lease_id=? "
            "AND cause_lease_id=? AND cause_operation_id=?",
            (lease.lease_id, lease.lease_id, original.budget_operation_id),
        ).fetchone()
        if (debt > 0 and debt_row != (1,)) or (debt == 0 and debt_row is not None):
            raise C09D11RecoveryHold("D11 overrun debt block differs")
        return SanitizedD11FactV4(
            settlement_id=original.budget_operation_id,
            parent_budget_id=lease.lease_id,
            idempotency_id=binding.binding_digest,
            upper_bound=ceiling, actual_cost=actual,
            settled=actual, pending=0, debt=debt,
        )
    except C09D11RecoveryHold:
        raise
    except Exception as exc:
        raise C09D11RecoveryHold("current C04 D11 originals failed verification") from exc
