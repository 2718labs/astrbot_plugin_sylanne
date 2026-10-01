"""Import a historical, signed C04 CPU terminal into the D11 budget ledger.

The Authority reread finishes before this module opens the business transaction.
An observed failure is still a measured bill. A claim without a signed terminal
remains reserved and cannot be converted into a zero-cost outcome here.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
import sqlite3

from ..authority_service.internal_work_contract import (
    InternalWorkTerminalProofV1, InternalWorkTerminalV2,
)
from ..authority_service.internal_work_service import (
    AuthorityInternalWorkService, AuthorityInternalWorkVerifiedReceiptV1,
)
from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize
from .budget import BudgetUnavailable, get_budget_lease, settle_budget
from .c04_internal_work_original_v1 import read_c04_internal_work_prepared_v1
from ..domains.d02.resource_outcome_verifier import C04_INTERNAL_CPU_WORK_KIND
from .issuers import D02ResourceIssuer


class C04CostHold(RuntimeError):
    """A historical effect exists, but its cost cannot be adopted safely."""


@dataclass(frozen=True, slots=True)
class C04CpuCostOriginalV1:
    namespace: NamespaceId
    operation_id: str
    binding_digest: str
    prepared_digest: str
    proof_digest: str
    terminal_receipt_ref: str
    terminal_receipt_digest: str
    status: str
    actual_cpu_ms: int
    budget_lease_id: str
    budget_operation_id: str
    budget_reservation_digest: str
    budget_receipt_status: str
    component_completed: bool


def install_d11_c04_cost_schema(db: sqlite3.Connection) -> None:
    db.execute("""CREATE TABLE IF NOT EXISTS d11_c04_cpu_cost_originals_v1 (
        bot TEXT NOT NULL, persona TEXT NOT NULL, operation_id TEXT NOT NULL,
        original_json TEXT NOT NULL, original_digest TEXT NOT NULL,
        PRIMARY KEY(bot,persona,operation_id))""")
    for operation in ("UPDATE", "DELETE"):
        db.execute(f"""CREATE TRIGGER IF NOT EXISTS
            d11_c04_cpu_cost_originals_v1_{operation.lower()}_immutable
            BEFORE {operation} ON d11_c04_cpu_cost_originals_v1
            BEGIN SELECT RAISE(ABORT, 'C04 CPU cost original is immutable'); END""")


def read_c04_cpu_cost_original_v1(
    db: sqlite3.Connection, namespace: NamespaceId, operation_id: str,
) -> C04CpuCostOriginalV1 | None:
    if db.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' "
        "AND name='d11_c04_cpu_cost_originals_v1'",
    ).fetchone() is None:
        return None
    row = db.execute(
        "SELECT original_json,original_digest FROM d11_c04_cpu_cost_originals_v1 "
        "WHERE bot=? AND persona=? AND operation_id=?",
        (*namespace.as_tuple, operation_id),
    ).fetchone()
    if row is None:
        return None
    raw = json.loads(row[0])
    if (type(raw) is not dict or set(raw) != set(C04CpuCostOriginalV1.__dataclass_fields__)
            or canonical_serialize(raw) != row[0]
            or type(raw.get("namespace")) is not dict
            or set(raw["namespace"]) != {"bot_id", "persona_id"}):
        raise C04CostHold("C04 cost original fields changed")
    raw["namespace"] = NamespaceId(**raw["namespace"])
    original = C04CpuCostOriginalV1(**raw)
    # Two existing concrete importers issued these exact commitments: the
    # legacy local importer used the plain wire, and historical accounting
    # used the fixed DTO tag while retaining the same plain JSON payload.
    # Preserve both original hashes; never rewrite an already-issued cost.
    if row[1] not in {canonical_digest(asdict(original)), canonical_digest(original)}:
        raise C04CostHold("C04 cost original changed")
    if original.namespace != namespace or original.operation_id != operation_id:
        raise C04CostHold("C04 cost original identity changed")
    return original


def import_c04_cpu_terminal_v1(
    db: sqlite3.Connection, namespace: NamespaceId, operation_id: str,
    proof: InternalWorkTerminalProofV1,
    authority: AuthorityInternalWorkService,
    issuer: D02ResourceIssuer,
) -> C04CpuCostOriginalV1:
    """Reread Authority, then atomically settle the exact prepared reservation.

    The caller supplies a connection outside any graph transaction. This
    function owns one short accounting transaction and never runs the work.
    """
    if (type(db) is not sqlite3.Connection or db.in_transaction
            or type(namespace) is not NamespaceId
            or type(proof) is not InternalWorkTerminalProofV1
            or type(authority) is not AuthorityInternalWorkService
            or not authority.installed_runtime_verified
            or type(issuer) is not D02ResourceIssuer):
        raise C04CostHold("typed historical import outside transaction required")
    terminal = proof.terminal
    if (type(terminal) is not InternalWorkTerminalV2
            or terminal.status not in {"completed", "failed"}
            or not authority.verify_installed_terminal(
                proof.binding, proof.claim, terminal)):
        raise C04CostHold("signed installed terminal required")
    verified = authority.verify_original_internal_work_terminal(proof)
    return _settle_verified_c04_cpu_terminal_v1(
        db, namespace, operation_id, proof, verified, issuer)


async def import_c04_cpu_terminal_remote_v1(
    db: sqlite3.Connection, namespace: NamespaceId, operation_id: str,
    proof: InternalWorkTerminalProofV1, client: object,
    bundle: object, grant: object, issuer: D02ResourceIssuer,
) -> C04CpuCostOriginalV1:
    """Read the original over paired mTLS before opening the D11 transaction."""
    from ..host.authority_client import AuthorityClient
    from ..host.mtls_transport import MtlsAuthorityTransport

    if (type(db) is not sqlite3.Connection or db.in_transaction
            or type(namespace) is not NamespaceId
            or type(proof) is not InternalWorkTerminalProofV1
            or type(proof.terminal) is not InternalWorkTerminalV2
            or proof.terminal.status not in {"completed", "failed"}
            or type(client) is not AuthorityClient
            or type(client._transport) is not MtlsAuthorityTransport
            or type(issuer) is not D02ResourceIssuer):
        raise C04CostHold("paired C04 Authority read outside transaction required")
    try:
        verified = await client.c04_terminal_verify_v1(
            bundle, grant, proof=proof)
    except (RuntimeError, TypeError, ValueError) as exc:
        raise C04CostHold("current C04 Authority terminal is unavailable") from exc
    return _settle_verified_c04_cpu_terminal_v1(
        db, namespace, operation_id, proof, verified, issuer)


def _settle_verified_c04_cpu_terminal_v1(
    db: sqlite3.Connection, namespace: NamespaceId, operation_id: str,
    proof: InternalWorkTerminalProofV1,
    verified: AuthorityInternalWorkVerifiedReceiptV1,
    issuer: D02ResourceIssuer,
) -> C04CpuCostOriginalV1:
    terminal = proof.terminal
    binding = proof.binding
    if (db.in_transaction or type(verified) is not AuthorityInternalWorkVerifiedReceiptV1
            or verified.proof_digest != canonical_digest(proof)
            or verified.namespace != binding.namespace
            or (verified.activity_id, verified.operation_id,
                verified.execution_id, verified.input_digest,
                verified.resource_quote_ref, verified.resource_quote_version,
                verified.resource_quote_digest) !=
               (binding.activity_id, binding.operation_id,
                binding.execution_id, binding.input_digest,
                binding.resource_quote_ref, binding.resource_quote_version,
                binding.resource_quote_digest)
            or verified.status != terminal.status
            or verified.actual_cpu_ms != terminal.actual_cpu_ms
            or verified.terminal_receipt_ref != proof.terminal_receipt_ref
            or verified.terminal_receipt_digest != proof.terminal_receipt_digest
            or verified.terminal_sequence < 2
            or verified.journal_head.seq < verified.terminal_sequence
            or (terminal.status == "completed") != verified.component_completed):
        raise C04CostHold("Authority terminal reread differs")
    db.execute("BEGIN IMMEDIATE")
    try:
        install_d11_c04_cost_schema(db)
        prepared = read_c04_internal_work_prepared_v1(db, namespace, operation_id)
        if prepared is None or prepared.binding != proof.binding:
            raise C04CostHold("original W01 preparation differs")
        binding = prepared.binding
        quote = issuer.original_signed_quote(
            db, binding.resource_quote_ref, binding.resource_quote_version)
        if (canonical_digest(quote) != binding.resource_quote_digest
                or quote.ceiling.keys() != {"cpu_ms"}
                or quote.work_kind != C04_INTERNAL_CPU_WORK_KIND
                or quote.required_worker_fence is not None
                or quote.parent_budget_lease_ref != binding.parent_budget_lease_ref
                or (quote.bot_id, quote.persona_id, quote.activity_id,
                    quote.operation_id) != (*namespace.as_tuple,
                                            binding.activity_id, operation_id)
                or prepared.budget_reservation_operation_id !=
                "c04-internal-budget:" + binding.binding_digest):
            raise C04CostHold("signed quote and prepared budget differ")
        lease = get_budget_lease(db, binding.parent_budget_lease_ref)
        if (lease.bot_id, lease.persona_id) != namespace.as_tuple:
            raise C04CostHold("budget owner differs")
        reserved = db.execute(
            "SELECT digest,ceiling_json FROM runtime_budget_reservations "
            "WHERE lease_id=? AND operation_id=?",
            (lease.lease_id, prepared.budget_reservation_operation_id),
        ).fetchone()
        reserve_receipt = db.execute(
            "SELECT digest,lease_id,receipt_json FROM runtime_budget_operations "
            "WHERE bot_id=? AND persona_id=? AND operation_id=? AND phase='reserve'",
            (*namespace.as_tuple, prepared.budget_reservation_operation_id),
        ).fetchone()
        if (reserved is None or reserved[0] != binding.binding_digest
                or json.loads(reserved[1]) != dict(quote.ceiling)):
            raise C04CostHold("original CPU reservation differs")
        if (reserve_receipt is None
                or reserve_receipt[0] != binding.binding_digest
                or reserve_receipt[1] != lease.lease_id
                or hashlib.sha256(reserve_receipt[2].encode()).hexdigest()
                   != prepared.budget_reservation_digest):
            raise C04CostHold("prepared D11 reserve receipt differs")
        receipt_shape = json.loads(reserve_receipt[2])
        if (receipt_shape.get("status") != "reserved"
                or receipt_shape.get("operation_id") !=
                prepared.budget_reservation_operation_id
                or receipt_shape.get("digest") != binding.binding_digest
                or receipt_shape.get("lease_id") != lease.lease_id):
            raise C04CostHold("D11 reserve receipt identity differs")
        receipt = settle_budget(
            db, lease.lease_id, prepared.budget_reservation_operation_id,
            binding.binding_digest,
            {"cpu_ms": terminal.actual_cpu_ms}, execution_revoked=True,
        )
        if receipt.status not in {"settled", "overrun"}:
            raise C04CostHold("CPU settlement is not final")
        original = C04CpuCostOriginalV1(
            namespace, operation_id, binding.binding_digest,
            prepared.prepared_digest, verified.proof_digest,
            proof.terminal_receipt_ref, proof.terminal_receipt_digest,
            terminal.status, terminal.actual_cpu_ms, lease.lease_id,
            prepared.budget_reservation_operation_id,
            prepared.budget_reservation_digest,
            receipt.status, verified.component_completed,
        )
        encoded = canonical_serialize(asdict(original))
        prior = read_c04_cpu_cost_original_v1(db, namespace, operation_id)
        if prior is not None and prior != original:
            raise C04CostHold("replayed CPU terminal differs")
        if prior is None:
            db.execute("INSERT INTO d11_c04_cpu_cost_originals_v1 VALUES(?,?,?,?,?)",
                       (*namespace.as_tuple, operation_id, encoded,
                        canonical_digest(asdict(original))))
        db.commit()
        return original
    except (BudgetUnavailable, sqlite3.Error, ValueError, C04CostHold):
        db.rollback()
        raise
