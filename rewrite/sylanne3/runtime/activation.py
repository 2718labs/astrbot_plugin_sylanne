"""One-authority activation and transfer fencing for every content-capable path.

The SQLite implementation is an installer-level, single-host reference. The
host must keep this database outside ordinary business restore and guard its
file permissions. Cross-host transfer requires a shared external authority
implementing the same protocol; copied local files cannot grant activation.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import sqlite3
import threading
from typing import Protocol
import uuid

from .restore_anchor import RestoreAnchor


CONTENT_OPERATIONS = frozenset({
    "startup", "read", "subscribe", "download", "model_egress",
    "adopt", "write", "dispatch",
})


class ActivationDenied(RuntimeError):
    pass


@dataclass(frozen=True)
class ActivationProof:
    authority_id: str
    namespace: str
    holder: str | None
    generation: int
    phase: str
    operation_id: str | None = None


@dataclass(frozen=True)
class TransferPlan:
    namespace: str
    source: str
    target: str
    operation_id: str

    def __post_init__(self):
        if not all(isinstance(value, str) and value for value in
                   (self.namespace, self.source, self.target, self.operation_id)):
            raise ValueError("transfer identities required")
        if self.source == self.target:
            raise ValueError("target must differ from source")


class MigrationAuthority(Protocol):
    def current(self, namespace: str) -> ActivationProof: ...
    def begin_transfer(self, plan: TransferPlan) -> ActivationProof: ...
    def revoke_source(self, proof: ActivationProof, *, credential=None) -> ActivationProof: ...
    def activate_target(self, proof: ActivationProof,
                        anchors: RestoreAnchor, *, credential=None) -> ActivationProof: ...
    def recover_transfer(self, operation_id: str) -> ActivationProof: ...
    def check(self, *, namespace: str, holder: str, generation: int,
              operation: str) -> ActivationProof: ...


class SqliteMigrationAuthority:
    """Persistent local reference authority; no timeout grants resurrection.

    ``anchor_verifier`` must consult the independently trusted current restore
    anchor. It cannot be inferred from a copied business or migration file.
    """

    def __init__(self, path, *, anchor_verifier=None, installer_verifier=None,
                 transfer_verifier=None, create: bool = False):
        self.path = Path(path)
        if not self.path.exists() and not create:
            raise ActivationDenied("missing installer migration authority")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._anchor_verifier = anchor_verifier
        self._installer_verifier = installer_verifier
        self._transfer_verifier = transfer_verifier
        self._db = sqlite3.connect(self.path, isolation_level=None, check_same_thread=False)
        self._db.execute("PRAGMA busy_timeout=5000")
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=FULL")
        self._db.executescript("""
            CREATE TABLE IF NOT EXISTS activation_meta(key TEXT PRIMARY KEY,value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS activation_state(
                namespace TEXT PRIMARY KEY, holder TEXT, generation INTEGER NOT NULL,
                phase TEXT NOT NULL, operation_id TEXT, target TEXT);
            CREATE TABLE IF NOT EXISTS activation_events(
                seq INTEGER PRIMARY KEY AUTOINCREMENT, namespace TEXT NOT NULL,
                generation INTEGER NOT NULL, holder TEXT, phase TEXT NOT NULL,
                operation_id TEXT);
            CREATE TRIGGER IF NOT EXISTS activation_events_no_update
                BEFORE UPDATE ON activation_events BEGIN SELECT RAISE(ABORT,'append-only'); END;
            CREATE TRIGGER IF NOT EXISTS activation_events_no_delete
                BEFORE DELETE ON activation_events BEGIN SELECT RAISE(ABORT,'append-only'); END;
        """)
        self._db.execute("INSERT OR IGNORE INTO activation_meta VALUES('authority_id',?)",
                         (str(uuid.uuid4()),))

    def _ensure_open(self):
        if self._db is None:
            raise ActivationDenied("migration authority unavailable")

    def _authority_id(self):
        return self._db.execute(
            "SELECT value FROM activation_meta WHERE key='authority_id'").fetchone()[0]

    def _state(self, namespace):
        return self._db.execute(
            "SELECT holder,generation,phase,operation_id,target FROM activation_state "
            "WHERE namespace=?", (namespace,)).fetchone()

    def _proof(self, namespace, row):
        if row is None:
            raise ActivationDenied("namespace is not registered")
        return ActivationProof(self._authority_id(), namespace, row[0], row[1], row[2], row[3])

    def _event(self, namespace, row):
        self._db.execute(
            "INSERT INTO activation_events(namespace,generation,holder,phase,operation_id) "
            "VALUES(?,?,?,?,?)", (namespace, row[1], row[0], row[2], row[3]))

    def _require_transfer_authority(self, credential, value):
        if (self._transfer_verifier is None
                or self._transfer_verifier(credential, value) is not True):
            raise ActivationDenied("transfer authority required")

    def bootstrap(self, namespace: str, holder: str, *, installer_credential=None):
        """Installer-only registration. The host must guard this call boundary."""
        if (self._installer_verifier is None
                or self._installer_verifier(installer_credential, namespace, holder) is not True
                or not namespace or not holder):
            raise ActivationDenied("installer authorization required")
        with self._lock:
            self._ensure_open()
            self._db.execute("BEGIN IMMEDIATE")
            try:
                if self._state(namespace) is not None:
                    raise ActivationDenied("namespace already registered")
                self._db.execute("INSERT INTO activation_state VALUES(?,?,?,?,?,?)",
                                 (namespace, holder, 1, "active", None, None))
                row = self._state(namespace)
                self._event(namespace, row)
                self._db.execute("COMMIT")
                return self._proof(namespace, row)
            except BaseException:
                self._db.execute("ROLLBACK")
                raise

    def current(self, namespace: str) -> ActivationProof:
        with self._lock:
            self._ensure_open()
            return self._proof(namespace, self._state(namespace))

    def check(self, *, namespace: str, holder: str, generation: int,
              operation: str) -> ActivationProof:
        if operation not in CONTENT_OPERATIONS:
            raise ValueError("operation must be a registered content path")
        with self._lock:
            self._ensure_open()
            proof = self._proof(namespace, self._state(namespace))
            if (proof.phase != "active" or proof.holder != holder
                    or type(generation) is not int or proof.generation != generation):
                raise ActivationDenied("stale or inactive activation generation")
            return proof

    def begin_transfer(self, plan: TransferPlan, *, credential=None) -> ActivationProof:
        if not isinstance(plan, TransferPlan):
            raise TypeError("plan must be TransferPlan")
        self._require_transfer_authority(credential, plan)
        with self._lock:
            self._ensure_open()
            self._db.execute("BEGIN IMMEDIATE")
            try:
                row = self._state(plan.namespace)
                if row is None:
                    raise ActivationDenied("source namespace not registered")
                if (row[2] == "planned" and row[3] == plan.operation_id
                        and row[4] == plan.target and row[0] == plan.source):
                    self._db.execute("COMMIT")
                    return self._proof(plan.namespace, row)
                if self._db.execute(
                    "SELECT 1 FROM activation_events WHERE operation_id=? LIMIT 1",
                    (plan.operation_id,)).fetchone():
                    raise ActivationDenied("transfer operation_id was already consumed")
                if row[2] != "active" or row[0] != plan.source:
                    raise ActivationDenied("source is not current active holder")
                self._db.execute(
                    "UPDATE activation_state SET phase='planned',operation_id=?,target=? "
                    "WHERE namespace=?", (plan.operation_id, plan.target, plan.namespace))
                result = self._state(plan.namespace)
                self._event(plan.namespace, result)
                self._db.execute("COMMIT")
                return self._proof(plan.namespace, result)
            except BaseException:
                self._db.execute("ROLLBACK")
                raise

    def revoke_source(self, proof: ActivationProof, *, credential=None) -> ActivationProof:
        if not isinstance(proof, ActivationProof):
            raise TypeError("proof must be ActivationProof")
        self._require_transfer_authority(credential, proof)
        with self._lock:
            self._ensure_open()
            self._db.execute("BEGIN IMMEDIATE")
            try:
                row = self._state(proof.namespace)
                if (row is None or self._authority_id() != proof.authority_id
                        or row[:4] != (proof.holder, proof.generation, "planned",
                                       proof.operation_id)):
                    raise ActivationDenied("transfer plan changed")
                self._db.execute(
                    "UPDATE activation_state SET holder=NULL,generation=?,phase='revoked' "
                    "WHERE namespace=?", (row[1] + 1, proof.namespace))
                result = self._state(proof.namespace)
                self._event(proof.namespace, result)
                self._db.execute("COMMIT")
                return self._proof(proof.namespace, result)
            except BaseException:
                self._db.execute("ROLLBACK")
                raise

    def activate_target(self, proof: ActivationProof,
                        anchors: RestoreAnchor, *, credential=None) -> ActivationProof:
        if not isinstance(proof, ActivationProof):
            raise TypeError("proof must be ActivationProof")
        self._require_transfer_authority(credential, proof)
        with self._lock:
            self._ensure_open()
            self._db.execute("BEGIN IMMEDIATE")
            try:
                row = self._state(proof.namespace)
                if (row is None or self._authority_id() != proof.authority_id
                        or row[:4] != (None, proof.generation, "revoked",
                                       proof.operation_id)):
                    raise ActivationDenied("source revocation is not current")
                if (not isinstance(anchors, RestoreAnchor)
                        or anchors.namespace != proof.namespace
                        or anchors.activation_generation != proof.generation
                        or self._anchor_verifier is None
                        or self._anchor_verifier(anchors) is not True):
                    raise ActivationDenied("current independent recovery anchor required")
                self._db.execute(
                    "UPDATE activation_state SET holder=target,phase='active',target=NULL "
                    "WHERE namespace=?", (proof.namespace,))
                result = self._state(proof.namespace)
                self._event(proof.namespace, result)
                self._db.execute("COMMIT")
                return self._proof(proof.namespace, result)
            except BaseException:
                self._db.execute("ROLLBACK")
                raise

    def recover_transfer(self, operation_id: str) -> ActivationProof:
        with self._lock:
            self._ensure_open()
            rows = self._db.execute(
                "SELECT namespace FROM activation_state WHERE operation_id=?",
                (operation_id,)).fetchall()
            if len(rows) == 1:
                return self._proof(rows[0][0], self._state(rows[0][0]))
            if rows:
                raise ActivationDenied("transfer operation ambiguous")
            historical = self._db.execute(
                "SELECT namespace,holder,generation,phase,operation_id "
                "FROM activation_events WHERE operation_id=? ORDER BY seq DESC LIMIT 1",
                (operation_id,)).fetchone()
            if historical is None:
                raise ActivationDenied("transfer operation unavailable")
            return ActivationProof(self._authority_id(), historical[0], historical[1],
                                   historical[2], historical[3], historical[4])

    def close(self):
        with self._lock:
            if self._db is not None:
                self._db.close()
                self._db = None
