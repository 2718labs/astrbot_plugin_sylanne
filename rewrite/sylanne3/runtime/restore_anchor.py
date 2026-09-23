"""Recovery gate against *known* deletion/execution-log rollback.

The authority is injected and must be outside the ordinary business backup.
It must return its CURRENT signed/attested head, not a value copied from the
snapshot being restored. This cannot prove freshness if a whole machine and
every external authority are rolled back together.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import sqlite3
from typing import Protocol

from .deletion import DeletionHead, DeletionJournal


class RestoreQuarantined(RuntimeError):
    pass


@dataclass(frozen=True)
class SnapshotRequirements:
    namespace: str
    activation_generation: int
    deletion_seq: int
    execution_seq: int
    revocation_epoch: int

    def __post_init__(self):
        if not self.namespace:
            raise ValueError("namespace required")
        for field in ("activation_generation", "deletion_seq", "execution_seq",
                      "revocation_epoch"):
            value = getattr(self, field)
            if type(value) is not int or value < 0:
                raise ValueError(f"{field} must be a nonnegative exact integer")


@dataclass(frozen=True)
class RestoreAnchor:
    authority_id: str
    namespace: str
    activation_generation: int
    deletion_journal_id: str
    deletion_seq: int
    deletion_digest: str
    execution_journal_id: str
    execution_seq: int
    execution_digest: str
    revocation_epoch: int
    proof: str

    def __post_init__(self):
        for field in ("authority_id", "namespace", "deletion_journal_id",
                      "deletion_digest", "execution_journal_id", "execution_digest", "proof"):
            if not isinstance(getattr(self, field), str) or not getattr(self, field):
                raise ValueError(f"{field} required")
        for field in ("activation_generation", "deletion_seq", "execution_seq",
                      "revocation_epoch"):
            value = getattr(self, field)
            if type(value) is not int or value < 0:
                raise ValueError(f"{field} must be a nonnegative exact integer")


class RestoreAuthority(Protocol):
    """Installer/external trust root; never implemented by a business snapshot."""

    def current_anchor(self, namespace: str) -> RestoreAnchor: ...
    def verify_current(self, anchor: RestoreAnchor) -> bool: ...


class ExecutionJournalPort(Protocol):
    """Trusted service boundary for the CURRENT execution chain.

    The implementation must inspect the service-owned journal for ``namespace``
    and compare its complete, continuous chain with ``expected_head``. The
    caller-supplied head is only a comparison target, never evidence. A local
    plugin journal or the business snapshot cannot implement this production
    trust boundary.
    """

    def verify_current_chain(self, namespace: str,
                             expected_head: tuple[str, int, str]) -> bool: ...


def _execution_head_and_continuity(path) -> tuple[str, int, str]:
    """Legacy local-path verifier for explicit tests and historical recovery only."""
    uri = f"file:{path}?mode=ro"
    try:
        db = sqlite3.connect(uri, uri=True)
        try:
            jid_row = db.execute(
                "SELECT value FROM execution_metadata WHERE name='journal_id'"
            ).fetchone()
            if not jid_row:
                raise RestoreQuarantined("execution journal identity absent")
            previous = None
            expected_seq = 1
            for row in db.execute("""
                SELECT e.execution_seq,e.effect_id,x.command_digest,
                       x.dispatch_generation,x.activation_generation,x.admission_ref,
                       e.phase,e.observation_ref,e.chain_digest
                FROM execution_entries e JOIN execution_effects x USING(effect_id)
                ORDER BY e.execution_seq
            """):
                seq, effect, digest, dispatch_gen, activation_gen, admission, phase, observation, chain = row
                if seq != expected_seq:
                    raise RestoreQuarantined("execution journal sequence gap")
                material = json.dumps({
                    "previous": previous, "effect_id": effect,
                    "command_digest": digest, "dispatch_generation": dispatch_gen,
                    "activation_generation": activation_gen, "admission_ref": admission,
                    "phase": phase, "observation_ref": observation,
                }, sort_keys=True, separators=(",", ":"))
                candidate = "sha256:" + hashlib.sha256(material.encode()).hexdigest()
                if candidate != chain:
                    raise RestoreQuarantined("execution journal chain invalid")
                previous, expected_seq = chain, expected_seq + 1
            return jid_row[0], expected_seq - 1, previous or "genesis"
        finally:
            db.close()
    except (sqlite3.Error, OSError) as exc:
        raise RestoreQuarantined("execution journal unavailable") from exc


def validate_restore(*, snapshot: SnapshotRequirements, authority: RestoreAuthority,
                     deletion_journal: DeletionJournal, active_generation: int,
                     execution_journal_port: ExecutionJournalPort | None = None,
                     execution_journal_path=None,
                     allow_local_execution_journal: bool = False) -> RestoreAnchor:
    """Fail closed before opening any content path after restore/migration.

    The coordinator must hold the activation/read barrier across this check and
    service opening. A later journal append requires a refreshed authority head.
    Production callers must inject a trusted service port. The local SQLite path
    is disabled unless explicitly selected for tests or historical recovery.
    """
    if not isinstance(snapshot, SnapshotRequirements):
        raise TypeError("snapshot must be SnapshotRequirements")
    try:
        if execution_journal_port is None:
            if not allow_local_execution_journal or execution_journal_path is None:
                raise RestoreQuarantined("trusted execution journal port unavailable")
        elif execution_journal_path is not None or allow_local_execution_journal:
            raise RestoreQuarantined("ambiguous execution journal verification source")
        current = authority.current_anchor(snapshot.namespace)
        if (not isinstance(current, RestoreAnchor)
                or authority.verify_current(current) is not True
                or current.namespace != snapshot.namespace
                or current.activation_generation != active_generation
                or current.activation_generation < snapshot.activation_generation
                or current.deletion_seq < snapshot.deletion_seq
                or current.execution_seq < snapshot.execution_seq
                or current.revocation_epoch < snapshot.revocation_epoch):
            raise RestoreQuarantined("current independent restore authority unavailable or stale")
        deletion_head = DeletionHead(current.deletion_journal_id,
                                    current.deletion_seq, current.deletion_digest)
        if not deletion_journal.verify_chain(deletion_head):
            raise RestoreQuarantined("deletion journal does not match current authority")
        expected_head = (current.execution_journal_id,
                         current.execution_seq, current.execution_digest)
        if execution_journal_port is not None:
            if execution_journal_port.verify_current_chain(
                    snapshot.namespace, expected_head) is not True:
                raise RestoreQuarantined("execution journal does not match current authority")
        elif _execution_head_and_continuity(execution_journal_path) != expected_head:
            raise RestoreQuarantined("execution journal does not match current authority")
        return current
    except RestoreQuarantined:
        raise
    except Exception as exc:
        raise RestoreQuarantined("restore authority could not be verified") from exc
