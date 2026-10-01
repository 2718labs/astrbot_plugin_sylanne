"""Read-only gate for C09 execution journal physical cleanup.

The V3 identity switch is a prerequisite, not proof that old SQLite pages or
managed backup copies have been cleared. This probe deliberately issues no
cleanup receipt and never mutates the journal.
"""

from __future__ import annotations

from dataclasses import dataclass
from dataclasses import asdict
from contextlib import closing
import hashlib
from pathlib import Path
import sqlite3
from urllib.parse import quote

from ..runtime_contracts import canonical_digest
from .contract import AuthorityUnavailable
from .erasure_closure_inventory import (
    AuthorityErasureClosureInventory, CleanupRunV2, SURFACES_V1, _TABLES,
)
from .erasure_closure_sidecar_v3 import read_execution_sidecar_recovery_v3


@dataclass(frozen=True, slots=True)
class ExecutionPhysicalCleanupGateV3:
    operation_id: str
    old_journal_path: str
    old_row_count: int
    switch_digest: str
    blockers: tuple[str, ...]
    status: str = "hold"


def inspect_execution_physical_cleanup_v3(
        closure: AuthorityErasureClosureInventory, *, credential,
        subject: str, operation_id: str) -> ExecutionPhysicalCleanupGateV3:
    """Verify switched originals and enumerate unresolved physical obligations.

    This gate must stay read-only until an installed maintainer can prove
    stopped writers, an exclusive file generation and complete managed-copy
    inventory. A request argument alone cannot attest those facts.
    """
    if type(closure) is not AuthorityErasureClosureInventory:
        raise AuthorityUnavailable("paired C09 closure service required")
    core = closure.core
    namespace = closure.namespace
    core._require(credential, "execution_redaction_install", namespace)
    location=closure.qualify_current_registry_location_v1(
        credential=credential,subject=subject,operation_id=operation_id)
    with core._tx() as db:
        registry = closure._registry_locked(db)
        run = closure._read_record(db, _TABLES[1], operation_id, CleanupRunV2)
        if run is None:
            raise AuthorityUnavailable("accepted cleanup run absent")
        if run.registry_digest != registry.registry_digest:
            raise AuthorityUnavailable("cleanup registry changed")
    old_path = closure.execution.path.resolve()
    recovery = read_execution_sidecar_recovery_v3(
        core=core, credential=credential, namespace=namespace,
        operation_id=operation_id, old_journal_path=old_path)
    if recovery.stage != "identity_switched_hold":
        raise AuthorityUnavailable("V3 identity switch required before physical cleanup")
    seal, switch = recovery.seal, recovery.switch
    with core._tx() as db:
        state = closure.scoped.state_locked(db)
        original = closure.scoped.fences.mutation_locked(
            db, run.accepted_mutation_id)
        if original is None or original[1:3] != (namespace, subject):
            raise AuthorityUnavailable("accepted deletion original absent")
        kind, pending, receipt, _ = closure.scoped.fences._decode_mutation_row(
            original)
        if (kind != "deletion" or pending.deletion_operation_id != operation_id
                or (pending.source_phase, pending.target_phase) !=
                   ("pending", "accepted")
                or canonical_digest(receipt) != run.accepted_receipt_digest
                or canonical_digest(asdict(receipt.after_anchor)) !=
                   switch.before_anchor_digest
                or state.active_operation_id != operation_id
                or state.aggregate_phase != "accepted"
                or state.closed_seq is not None
                or core._row(db, namespace)[9] != "accepted"):
            raise AuthorityUnavailable("accepted cleanup original differs after switch")
    if (seal.cleanup_run_digest != run.run_digest
            or seal.registry_digest != registry.registry_digest
            or seal.installation_id != registry.installation_id
            or old_path != Path(closure.execution.path).resolve()):
        raise AuthorityUnavailable("execution cleanup installation differs")
    execution = registry.targets[SURFACES_V1.index("execution_journal_payloads")]
    if execution.inventory_state != "installed":
        raise AuthorityUnavailable("installed execution target differs")
    if (execution.target_ref,execution.generation_ref)!=(str(old_path),seal.execution_journal_id):
        qualifier=closure.current_source_location
        if qualifier is None or location is None:
            raise AuthorityUnavailable("actual current execution successor observation absent")
        with core._tx() as db:
            qualifier.require_registry_target_in_tx_v1(db,location,
                target_ref=execution.target_ref,generation_ref=execution.generation_ref)
        if location.execution_locations[-1]!=(str(old_path),seal.execution_journal_id):
            raise AuthorityUnavailable("sealed execution file is not the exact selected successor")
    if not old_path.is_file():
        raise AuthorityUnavailable("old execution journal absent before cleanup")
    uri = "file:" + quote(old_path.as_posix(), safe="/:") + "?mode=ro"
    try:
        with closing(sqlite3.connect(uri, uri=True, timeout=5)) as db:
            db.execute("PRAGMA query_only=ON")
            if db.execute("PRAGMA integrity_check").fetchone() != ("ok",):
                raise AuthorityUnavailable("old execution SQLite integrity differs")
            rows = tuple(db.execute(
                "SELECT seq,mutation_id,request_digest,append_id,pending,"
                "previous_digest,chain_digest FROM authority_v2_execution_entries "
                "ORDER BY seq"))
            if len(rows) != seal.execution_seq:
                raise AuthorityUnavailable("old execution row count differs")
            for row, committed in zip(rows, seal.rows):
                if ((row[0], row[1], row[2], row[3], row[5], row[6]) !=
                    (committed.seq, committed.mutation_id,
                     committed.request_digest, committed.append_id,
                     committed.previous_digest, committed.chain_digest)
                        or len(row[4]) != committed.body_bytes
                        or "sha256:" + hashlib.sha256(row[4]).hexdigest()
                        != committed.body_digest):
                    raise AuthorityUnavailable("old execution body differs from Core seal")
    except sqlite3.Error as exc:
        raise AuthorityUnavailable("old execution SQLite unavailable") from exc
    backups = registry.targets[SURFACES_V1.index("controlled_backups")]
    pages = registry.targets[SURFACES_V1.index("sqlite_wal_free_pages")]
    blockers = ["writer_quiescence_and_exclusive_generation_unproven",
                "physical_scrubber_and_cold_reread_unimplemented"]
    if backups.inventory_state != "installed":
        blockers.append("controlled_backup_inventory_unresolved")
    if pages.inventory_state != "installed":
        blockers.append("sqlite_file_inventory_unresolved")
    return ExecutionPhysicalCleanupGateV3(
        operation_id, str(old_path), len(rows), switch.switch_digest,
        tuple(blockers))


__all__ = ["ExecutionPhysicalCleanupGateV3", "inspect_execution_physical_cleanup_v3"]
