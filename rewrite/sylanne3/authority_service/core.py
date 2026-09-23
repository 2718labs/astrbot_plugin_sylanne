"""Durable, content-free authority kernel for a separate trusted service.

The SQLite path must be outside business backup and owned by a separately
installed service. A copied local DB, in-process plugin, or loopback socket is
not a trust root. All calls require server-side authentication and independent
journal verification supplied by the deployment. Open permits never expire:
an uncertain/crashed holder blocks transfer until independently recovered.
"""

from __future__ import annotations

from contextlib import contextmanager
import json
from pathlib import Path
import secrets
import sqlite3
import threading
import uuid

from ..runtime.activation import ActivationProof, TransferPlan
from ..runtime.restore_anchor import RestoreAnchor
from .contract import (
    AuthorityUnavailable, CONTENT_OPERATIONS, ContentPermit, JournalHead,
    identifier,
)


class AuthorityServiceCore:
    """Transactional authority state; no role content and no network listener."""

    def __init__(self, path, *, authorizer, deletion_verifier,
                 execution_verifier, effect_verifier, dispatch_verifier,
                 create: bool = False):
        for name, value in (
            ("authorizer", authorizer), ("deletion_verifier", deletion_verifier),
            ("execution_verifier", execution_verifier),
            ("effect_verifier", effect_verifier),
            ("dispatch_verifier", dispatch_verifier),
        ):
            if not callable(value):
                raise AuthorityUnavailable(f"server-side {name} is required")
        self.path = Path(path)
        if not self.path.exists() and not create:
            raise AuthorityUnavailable("independent authority store is absent")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._authorize_callback = authorizer
        self._deletion_verifier = deletion_verifier
        self._execution_verifier = execution_verifier
        self._effect_verifier = effect_verifier
        self._dispatch_verifier = dispatch_verifier
        self._lock = threading.RLock()
        self._db = sqlite3.connect(self.path, isolation_level=None,
                                   check_same_thread=False)
        self._db.execute("PRAGMA busy_timeout=5000")
        self._db.execute("PRAGMA foreign_keys=ON")
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=FULL")
        self._install_schema()

    def _install_schema(self) -> None:
        self._db.executescript("""
            CREATE TABLE IF NOT EXISTS authority_meta(
                key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS authority_namespaces(
                namespace TEXT PRIMARY KEY, holder TEXT, generation INTEGER NOT NULL,
                phase TEXT NOT NULL, transfer_id TEXT, target TEXT,
                revocation_epoch INTEGER NOT NULL, deletion_journal_id TEXT NOT NULL,
                deletion_seq INTEGER NOT NULL, deletion_digest TEXT NOT NULL,
                deletion_phase TEXT NOT NULL, execution_journal_id TEXT NOT NULL,
                execution_seq INTEGER NOT NULL, execution_digest TEXT NOT NULL,
                anchor_nonce TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS authority_transfers(
                operation_id TEXT PRIMARY KEY, namespace TEXT NOT NULL,
                source TEXT NOT NULL, target TEXT NOT NULL,
                base_generation INTEGER NOT NULL, phase TEXT NOT NULL,
                FOREIGN KEY(namespace) REFERENCES authority_namespaces(namespace));
            CREATE TABLE IF NOT EXISTS authority_permits(
                token TEXT PRIMARY KEY, namespace TEXT NOT NULL,
                holder TEXT NOT NULL, generation INTEGER NOT NULL,
                operation TEXT NOT NULL,
                FOREIGN KEY(namespace) REFERENCES authority_namespaces(namespace));
            CREATE TABLE IF NOT EXISTS authority_effects(
                namespace TEXT NOT NULL, effect_id TEXT NOT NULL,
                state TEXT NOT NULL, conflict_keys_json TEXT NOT NULL,
                execution_seq INTEGER NOT NULL,
                PRIMARY KEY(namespace,effect_id),
                FOREIGN KEY(namespace) REFERENCES authority_namespaces(namespace));
            CREATE TABLE IF NOT EXISTS authority_events(
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                namespace TEXT NOT NULL, kind TEXT NOT NULL,
                generation INTEGER NOT NULL, detail_digest TEXT NOT NULL);
            CREATE TRIGGER IF NOT EXISTS authority_events_no_update
                BEFORE UPDATE ON authority_events
                BEGIN SELECT RAISE(ABORT,'append-only'); END;
            CREATE TRIGGER IF NOT EXISTS authority_events_no_delete
                BEFORE DELETE ON authority_events
                BEGIN SELECT RAISE(ABORT,'append-only'); END;
        """)
        self._db.execute(
            "INSERT OR IGNORE INTO authority_meta(key,value) VALUES('authority_id',?)",
            (str(uuid.uuid4()),))

    def _require(self, credential, action: str, namespace: str,
                 holder: str | None = None) -> None:
        identifier(namespace, "namespace")
        if holder is not None:
            identifier(holder, "holder")
        try:
            granted = self._authorize_callback(credential, action, namespace, holder)
        except Exception as exc:
            raise AuthorityUnavailable("server authentication failed") from exc
        if granted is not True:
            raise AuthorityUnavailable("server authentication denied")

    @contextmanager
    def _tx(self):
        with self._lock:
            if self._db is None:
                raise AuthorityUnavailable("authority service is unavailable")
            self._db.execute("BEGIN IMMEDIATE")
            try:
                yield self._db
                self._db.execute("COMMIT")
            except BaseException:
                self._db.execute("ROLLBACK")
                raise

    @staticmethod
    def _require_legacy_mode(db) -> None:
        row = db.execute(
            "SELECT value FROM authority_meta WHERE key='service_mode'").fetchone()
        if row is None:
            return
        if row == ("v2-only",):
            raise AuthorityUnavailable("legacy authority entry disabled by v2-only seal")
        raise AuthorityUnavailable("unknown authority service mode")

    @staticmethod
    def _require_no_deletion_migration(db) -> None:
        """All v2 entrances fail while the cross-file migration is incomplete."""
        row = db.execute(
            "SELECT value FROM authority_meta WHERE key='deletion_v2_migration'").fetchone()
        if row is None:
            return  # Pre-migration service prototype; never a deployment claim.
        try:
            marker = json.loads(row[0])
        except (TypeError, ValueError) as exc:
            raise AuthorityUnavailable("malformed deletion migration blocker") from exc
        if (type(marker) is not dict
                or marker.get("schema") != "sylanne3.deletion-migration.v1"
                or marker.get("stage") != "complete"):
            raise AuthorityUnavailable("deletion migration blocks v2 service entry")

    @contextmanager
    def _legacy_tx(self):
        """Cross-process seal barrier before any legacy journal access."""
        with self._tx() as db:
            self._require_legacy_mode(db)
            yield db

    def seal_v2_only(self, credential) -> None:
        """Installer transition for this whole Authority DB; never clears state."""
        with self._lock:
            if self._db is None:
                raise AuthorityUnavailable("authority service is unavailable")
            namespaces = tuple(row[0] for row in self._db.execute(
                "SELECT namespace FROM authority_namespaces ORDER BY namespace"))
        if not namespaces:
            raise AuthorityUnavailable("cannot seal an uninstalled authority")
        for namespace in namespaces:
            self._require(credential, "seal_v2_only", namespace)
        with self._tx() as db:
            current = tuple(row[0] for row in db.execute(
                "SELECT namespace FROM authority_namespaces ORDER BY namespace"))
            if current != namespaces:
                raise AuthorityUnavailable("authority namespace set changed during seal")
            mode = db.execute(
                "SELECT value FROM authority_meta WHERE key='service_mode'").fetchone()
            if mode == ("v2-only",):
                return
            if mode is not None:
                raise AuthorityUnavailable("unknown authority service mode")
            if db.execute("SELECT 1 FROM authority_permits LIMIT 1").fetchone():
                raise AuthorityUnavailable("legacy content permit blocks v2-only seal")
            if db.execute("SELECT 1 FROM authority_transfers LIMIT 1").fetchone():
                raise AuthorityUnavailable("legacy transfer history requires explicit migration")
            if db.execute("SELECT 1 FROM authority_effects WHERE state!='resolved' LIMIT 1").fetchone():
                raise AuthorityUnavailable("unresolved legacy effect blocks v2-only seal")
            if db.execute("SELECT 1 FROM authority_namespaces WHERE holder IS NULL OR phase!='active' OR transfer_id IS NOT NULL OR target IS NOT NULL OR deletion_phase!='clear' LIMIT 1").fetchone():
                raise AuthorityUnavailable("unsettled authority namespace blocks v2-only seal")
            for namespace in namespaces:
                self._verify_current_heads(namespace, self._row(db, namespace))
            table = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='authority_v2_fences'").fetchone()
            if table and db.execute("SELECT 1 FROM authority_v2_fences WHERE state='active' LIMIT 1").fetchone():
                raise AuthorityUnavailable("active v2 fence blocks mode transition")
            table = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='authority_v2_mutations'").fetchone()
            if table and db.execute("SELECT 1 FROM authority_v2_mutations WHERE state='pending' LIMIT 1").fetchone():
                raise AuthorityUnavailable("pending v2 mutation blocks mode transition")
            db.execute("INSERT INTO authority_meta(key,value) VALUES('service_mode','v2-only')")

    def _row(self, db, namespace: str):
        row = db.execute(
            "SELECT holder,generation,phase,transfer_id,target,revocation_epoch,"
            "deletion_journal_id,deletion_seq,deletion_digest,deletion_phase,"
            "execution_journal_id,execution_seq,execution_digest,anchor_nonce "
            "FROM authority_namespaces WHERE namespace=?", (namespace,),
        ).fetchone()
        if row is None:
            raise AuthorityUnavailable("namespace is not registered")
        return row

    def _id(self, db) -> str:
        return db.execute(
            "SELECT value FROM authority_meta WHERE key='authority_id'"
        ).fetchone()[0]

    @staticmethod
    def _head(row, kind: str) -> JournalHead:
        index = 6 if kind == "deletion" else 10
        return JournalHead(row[index], row[index + 1], row[index + 2])

    def _proof(self, db, namespace: str, row) -> ActivationProof:
        return ActivationProof(self._id(db), namespace, row[0], row[1], row[2], row[3])

    def _anchor(self, db, namespace: str, row) -> RestoreAnchor:
        return RestoreAnchor(
            self._id(db), namespace, row[1], row[6], row[7], row[8],
            row[10], row[11], row[12], row[5], row[13],
        )

    @staticmethod
    def _event(db, namespace: str, kind: str, generation: int,
               detail: object) -> None:
        import hashlib
        payload = json.dumps(detail, sort_keys=True, separators=(",", ":"))
        digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        db.execute(
            "INSERT INTO authority_events(namespace,kind,generation,detail_digest) "
            "VALUES(?,?,?,?)", (namespace, kind, generation, digest),
        )

    @staticmethod
    def _new_nonce() -> str:
        return secrets.token_hex(32)

    @staticmethod
    def _no_permits(db, namespace: str) -> None:
        if db.execute(
            "SELECT 1 FROM authority_permits WHERE namespace=? LIMIT 1",
            (namespace,),
        ).fetchone():
            raise AuthorityUnavailable("in-flight content permit blocks transfer or deletion")

    def _verify_head(self, kind: str, namespace: str,
                     previous: JournalHead | None, current: JournalHead,
                     phase: str | None) -> None:
        verifier = (self._deletion_verifier if kind == "deletion"
                    else self._execution_verifier)
        if not isinstance(current, JournalHead):
            raise TypeError("current journal head must be JournalHead")
        if previous is not None:
            if (current.journal_id != previous.journal_id
                    or current.seq <= previous.seq):
                raise AuthorityUnavailable("journal head must advance on one journal")
        try:
            verified = verifier(namespace, previous, current, phase)
        except Exception as exc:
            raise AuthorityUnavailable("independent journal verification failed") from exc
        if verified is not True:
            raise AuthorityUnavailable("independent journal head was not verified")

    def _verify_current_heads(self, namespace: str, row) -> None:
        """A journal append not yet reflected here closes every content path."""
        for kind, phase in (("deletion", row[9]), ("execution", None)):
            head = self._head(row, kind)
            verifier = (self._deletion_verifier if kind == "deletion"
                        else self._execution_verifier)
            try:
                current = verifier(namespace, head, head, phase)
            except Exception as exc:
                raise AuthorityUnavailable("current independent journal is unavailable") from exc
            if current is not True:
                raise AuthorityUnavailable("authority head is behind independent journal")

    def register_namespace(self, credential, namespace: str, holder: str,
                           deletion: JournalHead, execution: JournalHead) -> ActivationProof:
        """Installer-only genesis after both independent journals are verified."""
        self._require(credential, "install", namespace, holder)
        with self._legacy_tx() as db:
            return self._register_namespace_locked(db, namespace, holder,
                                                   deletion, execution)

    def _register_namespace_locked(self, db, namespace: str, holder: str,
                                   deletion: JournalHead,
                                   execution: JournalHead) -> ActivationProof:
        self._verify_head("deletion", namespace, None, deletion, "clear")
        self._verify_head("execution", namespace, None, execution, None)
        if db.execute("SELECT 1 FROM authority_namespaces WHERE namespace=?",
                      (namespace,)).fetchone():
            raise AuthorityUnavailable("namespace already registered")
        db.execute(
            "INSERT INTO authority_namespaces VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (namespace, holder, 1, "active", None, None, 0,
             deletion.journal_id, deletion.seq, deletion.digest, "clear",
             execution.journal_id, execution.seq, execution.digest,
             self._new_nonce()),
        )
        self._event(db, namespace, "install", 1, (holder, deletion.seq, execution.seq))
        return self._proof(db, namespace, self._row(db, namespace))

    def current(self, credential, namespace: str) -> ActivationProof:
        self._require(credential, "current", namespace)
        with self._legacy_tx() as db:
            row = self._row(db, namespace)
            self._verify_current_heads(namespace, row)
            return self._proof(db, namespace, row)

    def current_anchor(self, credential, namespace: str) -> RestoreAnchor:
        self._require(credential, "anchor", namespace)
        with self._legacy_tx() as db:
            row = self._row(db, namespace)
            self._verify_current_heads(namespace, row)
            return self._anchor(db, namespace, row)

    def verify_current(self, credential, anchor: RestoreAnchor) -> bool:
        if not isinstance(anchor, RestoreAnchor):
            return False
        self._require(credential, "anchor", anchor.namespace)
        with self._legacy_tx() as db:
            try:
                row = self._row(db, anchor.namespace)
                self._verify_current_heads(anchor.namespace, row)
                return self._anchor(db, anchor.namespace, row) == anchor
            except AuthorityUnavailable:
                return False

    def check(self, credential, *, namespace: str, holder: str,
              generation: int, operation: str) -> ActivationProof:
        if operation not in CONTENT_OPERATIONS or type(generation) is not int:
            raise AuthorityUnavailable("invalid content operation or generation")
        self._require(credential, operation, namespace, holder)
        with self._legacy_tx() as db:
            row = self._row(db, namespace)
            self._verify_current_heads(namespace, row)
            if (row[0] != holder or row[1] != generation or row[2] != "active"
                    or row[9] != "clear"):
                raise AuthorityUnavailable("holder, generation or deletion barrier is stale")
            return self._proof(db, namespace, row)

    def begin_content_operation(self, credential, *, namespace: str, holder: str,
                                generation: int, operation: str) -> ContentPermit:
        if operation not in CONTENT_OPERATIONS or type(generation) is not int:
            raise AuthorityUnavailable("invalid content operation or generation")
        self._require(credential, operation, namespace, holder)
        with self._legacy_tx() as db:
            row = self._row(db, namespace)
            self._verify_current_heads(namespace, row)
            if (row[0] != holder or row[1] != generation or row[2] != "active"
                    or row[9] != "clear"):
                raise AuthorityUnavailable("holder, generation or deletion barrier is stale")
            permit = ContentPermit(secrets.token_hex(32), namespace, holder,
                                   generation, operation)
            db.execute("INSERT INTO authority_permits VALUES(?,?,?,?,?)",
                       (permit.token, namespace, holder, generation, operation))
            return permit

    def end_content_operation(self, credential, permit: ContentPermit) -> None:
        if not isinstance(permit, ContentPermit):
            raise TypeError("permit must be ContentPermit")
        self._require(credential, "release", permit.namespace, permit.holder)
        with self._legacy_tx() as db:
            changed = db.execute(
                "DELETE FROM authority_permits WHERE token=? AND namespace=? "
                "AND holder=? AND generation=? AND operation=?",
                (permit.token, permit.namespace, permit.holder,
                 permit.generation, permit.operation),
            ).rowcount
            if changed != 1:
                raise AuthorityUnavailable("permit is absent or already released")

    def observe_deletion_head(self, credential, namespace: str,
                              expected: JournalHead, current: JournalHead,
                              phase: str) -> RestoreAnchor:
        if phase not in {"pending", "accepted", "clear"}:
            raise ValueError("invalid deletion barrier phase")
        self._require(credential, "deletion", namespace)
        with self._legacy_tx() as db:
            row = self._row(db, namespace)
            if self._head(row, "deletion") != expected:
                raise AuthorityUnavailable("deletion head CAS failed")
            self._no_permits(db, namespace)
            self._verify_head("deletion", namespace, expected, current, phase)
            db.execute(
                "UPDATE authority_namespaces SET deletion_seq=?,deletion_digest=?,"
                "deletion_phase=?,revocation_epoch=revocation_epoch+1,anchor_nonce=? "
                "WHERE namespace=?",
                (current.seq, current.digest, phase, self._new_nonce(), namespace),
            )
            self._event(db, namespace, "deletion", row[1],
                        (current.seq, current.digest, phase))
            return self._anchor(db, namespace, self._row(db, namespace))

    def observe_execution_head(self, credential, namespace: str,
                               expected: JournalHead, current: JournalHead,
                               *, effect_id: str, state: str,
                               conflict_keys: tuple[str, ...]) -> RestoreAnchor:
        """Advance only after verifying the journal and its exact effect footprint."""
        identifier(effect_id, "effect_id")
        if state not in {"unresolved", "resolved"}:
            raise ValueError("effect state must be unresolved or resolved")
        keys = self._keys(conflict_keys)
        self._require(credential, "execution", namespace)
        with self._legacy_tx() as db:
            row = self._row(db, namespace)
            if self._head(row, "execution") != expected:
                raise AuthorityUnavailable("execution head CAS failed")
            self._verify_head("execution", namespace, expected, current, None)
            try:
                verified = self._effect_verifier(namespace, effect_id, state,
                                                 keys, current)
            except Exception as exc:
                raise AuthorityUnavailable("execution footprint verification failed") from exc
            if verified is not True:
                raise AuthorityUnavailable("execution footprint is not verified")
            prior = db.execute(
                "SELECT state,conflict_keys_json FROM authority_effects WHERE "
                "namespace=? AND effect_id=?", (namespace, effect_id),
            ).fetchone()
            if prior is None:
                if state != "unresolved":
                    raise AuthorityUnavailable("effect cannot begin resolved")
                db.execute(
                    "INSERT INTO authority_effects VALUES(?,?,?,?,?)",
                    (namespace, effect_id, state, json.dumps(keys), current.seq),
                )
            else:
                if tuple(json.loads(prior[1])) != keys or prior[0] == "resolved":
                    raise AuthorityUnavailable("effect footprint changed or was resolved")
                db.execute(
                    "UPDATE authority_effects SET state=?,execution_seq=? "
                    "WHERE namespace=? AND effect_id=?",
                    (state, current.seq, namespace, effect_id),
                )
            db.execute(
                "UPDATE authority_namespaces SET execution_seq=?,execution_digest=?,"
                "anchor_nonce=? WHERE namespace=?",
                (current.seq, current.digest, self._new_nonce(), namespace),
            )
            self._event(db, namespace, "execution", row[1],
                        (effect_id, state, current.seq, current.digest))
            return self._anchor(db, namespace, self._row(db, namespace))

    @staticmethod
    def _keys(keys: tuple[str, ...]) -> tuple[str, ...]:
        if not isinstance(keys, tuple) or len(keys) > 64:
            raise ValueError("conflict keys must be a bounded tuple")
        for key in keys:
            identifier(key, "conflict key")
        if len(set(keys)) != len(keys):
            raise ValueError("duplicate conflict keys")
        return tuple(sorted(keys))

    def admit_dispatch(self, credential, *, namespace: str, holder: str,
                       generation: int, effect_id: str,
                       conflict_keys: tuple[str, ...],
                       permit: ContentPermit) -> None:
        """Read-only eligibility under a durable dispatch permit.

        This is still not a send token: business claim, journal preparation,
        current policy and platform handoff require their own receipts.
        """
        with self._legacy_tx() as db:
            self._admit_dispatch_locked(
                db, credential, namespace=namespace, holder=holder,
                generation=generation, effect_id=effect_id,
                conflict_keys=conflict_keys, permit=permit)

    def _admit_dispatch_locked(self, db, credential, *, namespace: str,
                               holder: str, generation: int, effect_id: str,
                               conflict_keys: tuple[str, ...],
                               permit: ContentPermit) -> None:
        self._require(credential, "dispatch", namespace, holder)
        identifier(effect_id, "effect_id")
        keys = self._keys(conflict_keys)
        if (not isinstance(permit, ContentPermit)
                or (permit.namespace, permit.holder, permit.generation,
                    permit.operation) != (namespace, holder, generation, "dispatch")):
            raise AuthorityUnavailable("current dispatch permit required")
        try:
            verified = self._dispatch_verifier(namespace, effect_id, keys)
        except Exception as exc:
            raise AuthorityUnavailable("dispatch constraint verification failed") from exc
        if verified is not True:
            raise AuthorityUnavailable("dispatch constraint set is not verified")
        row = self._row(db, namespace)
        self._verify_current_heads(namespace, row)
        if (row[0] != holder or row[1] != generation or row[2] != "active"
                or row[9] != "clear"):
            raise AuthorityUnavailable("dispatch holder or deletion barrier is stale")
        if not db.execute(
            "SELECT 1 FROM authority_permits WHERE token=? AND namespace=? "
            "AND holder=? AND generation=? AND operation='dispatch'",
            (permit.token, namespace, holder, generation),
        ).fetchone():
            raise AuthorityUnavailable("dispatch permit is no longer current")
        if db.execute(
            "SELECT 1 FROM authority_effects WHERE namespace=? AND effect_id=?",
            (namespace, effect_id),
        ).fetchone():
            raise AuthorityUnavailable("effect already has execution history; query original")
        for state, encoded in db.execute(
            "SELECT state,conflict_keys_json FROM authority_effects WHERE namespace=?",
            (namespace,),
        ):
            if state == "unresolved":
                prior = set(json.loads(encoded))
                if not prior or not keys or prior.intersection(keys):
                    raise AuthorityUnavailable("unresolved execution constraint blocks dispatch")

    def begin_transfer(self, credential, plan: TransferPlan,
                       *, expected_generation: int) -> ActivationProof:
        if not isinstance(plan, TransferPlan) or type(expected_generation) is not int:
            raise TypeError("typed transfer plan and expected generation required")
        self._require(credential, "transfer", plan.namespace, plan.source)
        with self._legacy_tx() as db:
            row = self._row(db, plan.namespace)
            self._verify_current_heads(plan.namespace, row)
            prior = db.execute(
                "SELECT namespace,source,target,base_generation,phase "
                "FROM authority_transfers WHERE operation_id=?",
                (plan.operation_id,),
            ).fetchone()
            if prior is not None:
                if prior[:4] != (plan.namespace, plan.source, plan.target,
                                 expected_generation):
                    raise AuthorityUnavailable("transfer ID reused with different plan")
                return self._proof(db, plan.namespace, row)
            if (row[0] != plan.source or row[1] != expected_generation
                    or row[2] != "active" or row[3] is not None):
                raise AuthorityUnavailable("source is not uniquely active at expected generation")
            db.execute(
                "INSERT INTO authority_transfers VALUES(?,?,?,?,?,?)",
                (plan.operation_id, plan.namespace, plan.source, plan.target,
                 expected_generation, "planned"),
            )
            db.execute(
                "UPDATE authority_namespaces SET transfer_id=?,target=?,anchor_nonce=? "
                "WHERE namespace=?",
                (plan.operation_id, plan.target, self._new_nonce(), plan.namespace),
            )
            self._event(db, plan.namespace, "transfer_planned", row[1],
                        (plan.operation_id, plan.source, plan.target))
            return self._proof(db, plan.namespace, self._row(db, plan.namespace))

    def revoke_source(self, credential, operation_id: str,
                      *, expected_generation: int) -> ActivationProof:
        identifier(operation_id, "operation_id")
        if type(expected_generation) is not int:
            raise TypeError("expected generation must be exact integer")
        with self._legacy_tx() as db:
            transfer = db.execute(
                "SELECT namespace,source,target,base_generation,phase "
                "FROM authority_transfers WHERE operation_id=?",
                (operation_id,),
            ).fetchone()
            if transfer is None:
                raise AuthorityUnavailable("transfer is absent")
            namespace, source, _, base, phase = transfer
            self._require(credential, "revoke", namespace, source)
            row = self._row(db, namespace)
            self._verify_current_heads(namespace, row)
            if phase == "revoked":
                if (base != expected_generation or row[0] is not None
                        or row[1] != expected_generation + 1
                        or row[2] != "revoked" or row[3] != operation_id):
                    raise AuthorityUnavailable("revoked transfer replay differs from current state")
                return self._proof(db, namespace, row)
            if (phase != "planned" or base != expected_generation
                    or row[1] != expected_generation or row[0] != source
                    or row[3] != operation_id or row[2] != "active"):
                raise AuthorityUnavailable("source transfer CAS failed")
            self._no_permits(db, namespace)
            db.execute(
                "UPDATE authority_namespaces SET holder=NULL,generation=generation+1,"
                "phase='revoked',revocation_epoch=revocation_epoch+1,anchor_nonce=? "
                "WHERE namespace=?", (self._new_nonce(), namespace),
            )
            db.execute(
                "UPDATE authority_transfers SET phase='revoked' WHERE operation_id=?",
                (operation_id,),
            )
            self._event(db, namespace, "source_revoked", row[1] + 1, operation_id)
            return self._proof(db, namespace, self._row(db, namespace))

    def activate_target(self, credential, operation_id: str, *,
                        expected_revoked_generation: int,
                        deletion: JournalHead, execution: JournalHead) -> ActivationProof:
        identifier(operation_id, "operation_id")
        if type(expected_revoked_generation) is not int:
            raise TypeError("expected revoked generation must be exact integer")
        with self._legacy_tx() as db:
            transfer = db.execute(
                "SELECT namespace,source,target,base_generation,phase "
                "FROM authority_transfers WHERE operation_id=?",
                (operation_id,),
            ).fetchone()
            if transfer is None:
                raise AuthorityUnavailable("transfer is absent")
            namespace, _, target, _, phase = transfer
            self._require(credential, "activate", namespace, target)
            row = self._row(db, namespace)
            self._verify_current_heads(namespace, row)
            if phase == "activated":
                if (row[0] != target or row[1] != expected_revoked_generation + 1
                        or row[2] != "active"
                        or self._head(row, "deletion") != deletion
                        or self._head(row, "execution") != execution):
                    raise AuthorityUnavailable("activated transfer replay differs from current state")
                return self._proof(db, namespace, row)
            if (phase != "revoked" or row[2] != "revoked" or row[0] is not None
                    or row[1] != expected_revoked_generation
                    or row[3] != operation_id
                    or self._head(row, "deletion") != deletion
                    or self._head(row, "execution") != execution
                    or row[9] != "clear"):
                raise AuthorityUnavailable("target activation requires current revoked heads")
            self._no_permits(db, namespace)
            db.execute(
                "UPDATE authority_namespaces SET holder=?,generation=generation+1,"
                "phase='active',transfer_id=NULL,target=NULL,anchor_nonce=? "
                "WHERE namespace=?", (target, self._new_nonce(), namespace),
            )
            db.execute(
                "UPDATE authority_transfers SET phase='activated' WHERE operation_id=?",
                (operation_id,),
            )
            self._event(db, namespace, "target_activated", row[1] + 1,
                        (operation_id, target))
            return self._proof(db, namespace, self._row(db, namespace))

    def recover_transfer(self, credential, operation_id: str) -> ActivationProof:
        identifier(operation_id, "operation_id")
        with self._legacy_tx() as db:
            row = db.execute(
                "SELECT namespace FROM authority_transfers WHERE operation_id=?",
                (operation_id,),
            ).fetchone()
            if row is None:
                raise AuthorityUnavailable("transfer is absent")
            namespace = row[0]
            self._require(credential, "recover", namespace)
            current = self._row(db, namespace)
            self._verify_current_heads(namespace, current)
            return self._proof(db, namespace, current)

    def close(self) -> None:
        with self._lock:
            if self._db is not None:
                self._db.close()
                self._db = None


__all__ = ["AuthorityServiceCore"]
