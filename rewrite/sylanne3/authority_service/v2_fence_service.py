"""Internal v2-only protected anchor reads and exclusive fence issuance.

The installed service supplies an authenticated subject and owns both journal
files. Fixed nesting is deletion writer guard, execution writer guard, then a
short transaction on Core's Authority DB. No graph or business callback runs
inside those guards. This has no RPC or production RuntimeDependency wiring.
"""

from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json

from ..runtime.restore_anchor import RestoreAnchor
from ..runtime_contracts import NamespaceBootstrapV2, NamespaceId, NamespaceRuntimeState
from ..runtime_journal import RecoveryConstraintFootprint
from .contract import AuthorityUnavailable, identifier
from .core import AuthorityServiceCore
from .local_bridge import constraint_keys_from_footprint
from .v2_contract import FencePermitV2
from .v2_deletion_guard import AuthorityV2DeletionGuard
from .v2_execution_journal import AuthorityV2ExecutionJournal
from .v2_fence_store import AuthorityV2FenceStore


class AuthorityV2FenceService:
    def __init__(self, *, core: AuthorityServiceCore,
                 fences: AuthorityV2FenceStore,
                 deletion: AuthorityV2DeletionGuard,
                 execution: AuthorityV2ExecutionJournal,
                 namespace: str):
        identifier(namespace, "namespace")
        if (type(core) is not AuthorityServiceCore
                or type(fences) is not AuthorityV2FenceStore
                or type(deletion) is not AuthorityV2DeletionGuard
                or type(execution) is not AuthorityV2ExecutionJournal
                or core._db is not fences._db or core._lock is not fences._lock
                or execution.namespace != namespace):
            raise AuthorityUnavailable("v2 protected fence requires one service DB/lock and namespace")
        self.core, self.fences = core, fences
        self.deletion, self.execution = deletion, execution
        self.namespace = namespace
        # Pre-seal Core still verifies journals while holding its DB lock.
        # Reject here before this service can take journal guards and invert it.
        with core._tx() as db:
            self._require_mode(db)

    @staticmethod
    def _require_mode(db):
        if db.execute("SELECT value FROM authority_meta WHERE key='service_mode'").fetchone() != ("v2-only",):
            raise AuthorityUnavailable("v2 protected read requires persistent v2-only mode")
        AuthorityServiceCore._require_no_deletion_migration(db)

    def _current_locked(self, db, deletion_head, execution_head, *, holder: str | None = None,
                        generation: int | None = None,
                        require_clear: bool = True) -> RestoreAnchor:
        self._require_mode(db)
        self.fences._check_schema(db)
        row = self.core._row(db, self.namespace)
        if (row[2] != "active" or row[3] is not None or row[4] is not None
                or row[0] is None or (require_clear and row[9] != "clear")
                or (holder is not None and row[0] != holder)
                or (generation is not None and row[1] != generation)):
            raise AuthorityUnavailable("v2 namespace is not settled under expected owner")
        if (row[6:9] != (deletion_head.journal_id, deletion_head.seq, deletion_head.digest)
                or row[10:13] != (execution_head.journal_id, execution_head.seq,
                                   execution_head.digest)):
            raise AuthorityUnavailable("Authority is behind or differs from an independent journal")
        if db.execute("SELECT 1 FROM authority_v2_fences WHERE namespace=? AND pending IS NOT NULL LIMIT 1",
                      (self.namespace,)).fetchone():
            raise AuthorityUnavailable("namespace has a pending v2 mutation")
        return self.core._anchor(db, self.namespace, row)

    @contextmanager
    def _frozen(self):
        with self.deletion.freeze_writes():
            with self.execution.freeze_writes():
                deletion_head = self.deletion.verified_head()
                deletion_history = self.deletion.has_deletion_history(self.namespace)
                execution_head = self.execution.verified_head()
                with self.core._tx() as db:
                    yield db, deletion_head, execution_head, deletion_history

    def current_anchor(self, *, credential, subject: str) -> RestoreAnchor:
        """Protected, fully verified read; subject is authenticated by the host."""
        identifier(subject, "subject")
        self.core._require(credential, "current", self.namespace)
        with self._frozen() as (db, deletion_head, execution_head, _):
            return self._current_locked(db, deletion_head, execution_head)

    def namespace_bootstrap(self, *, credential, subject: str,
                            namespace_id: NamespaceId) -> NamespaceBootstrapV2:
        """Observe one administrator-bound namespace; this is no content permit.

        The RPC caller supplies NamespaceId from its administrator-owned mapping,
        never from an untrusted authority namespace claim.
        """
        identifier(subject, "subject")
        if type(namespace_id) is not NamespaceId:
            raise TypeError("namespace_id must be NamespaceId")
        self.core._require(credential, "current", self.namespace)
        with self._frozen() as (db, deletion_head, execution_head, deletion_history):
            self._require_mode(db)
            self.fences._check_schema(db)
            authority_id = self.core._id(db)
            if not db.execute(
                    "SELECT 1 FROM authority_namespaces WHERE namespace=?",
                    (self.namespace,)).fetchone():
                return NamespaceBootstrapV2(
                    authority_id, namespace_id, self.namespace, None, 0, "unbound",
                    NamespaceRuntimeState.UNBOUND, None, ("not_registered",))

            row = self.core._row(db, self.namespace)
            heads_match = (
                row[6:9] == (deletion_head.journal_id, deletion_head.seq,
                             deletion_head.digest)
                and row[10:13] == (execution_head.journal_id, execution_head.seq,
                                   execution_head.digest)
            )
            blockers = []
            if row[2] != "active" or row[0] is None or row[1] == 0 or row[3] is not None or row[4] is not None:
                blockers.append("activation_unsettled")
            if not heads_match:
                blockers.append("journal_head_mismatch")
            if row[9] != "clear":
                blockers.append("deletion_barrier")
            if deletion_history:
                blockers.append("deletion_history")
            if db.execute(
                    "SELECT 1 FROM authority_v2_fences WHERE namespace=? "
                    "AND pending IS NOT NULL LIMIT 1",
                    (self.namespace,)).fetchone():
                blockers.append("pending_fence")
            if db.execute(
                    "SELECT 1 FROM authority_v2_mutations WHERE namespace=? "
                    "AND state='pending' LIMIT 1", (self.namespace,)).fetchone():
                blockers.append("pending_mutation")
            anchor = self.core._anchor(db, self.namespace, row) if heads_match else None
            state = (NamespaceRuntimeState.QUARANTINED
                     if "deletion_barrier" in blockers or "deletion_history" in blockers
                     else NamespaceRuntimeState.RECOVERING if blockers
                     else NamespaceRuntimeState.ACTIVE)
            return NamespaceBootstrapV2(
                authority_id, namespace_id, self.namespace, row[0], row[1], row[2],
                state, anchor, tuple(blockers))

    def activate_namespace(self, *, credential, subject: str, holder: str,
                           namespace_id: NamespaceId, request_id: str) -> NamespaceBootstrapV2:
        """Administrator-authorized, idempotent genesis for an empty namespace."""
        identifier(subject, "subject")
        identifier(holder, "holder")
        identifier(request_id, "request_id")
        if type(namespace_id) is not NamespaceId:
            raise TypeError("namespace_id must be NamespaceId")
        self.core._require(credential, "namespace_genesis", self.namespace, holder)
        request_key = f"v2_namespace_genesis_request:{request_id}"
        request = json.dumps(
            (self.namespace, namespace_id.bot_id, namespace_id.persona_id, subject, holder),
            separators=(",", ":"), ensure_ascii=True)
        with self._frozen() as (db, deletion_head, execution_head, deletion_history):
            self._require_mode(db)
            self.fences._check_schema(db)
            deletion_kind, _, deletion_meta = self.deletion._check_schema()
            if deletion_kind == "v2" and deletion_meta["namespace"] != self.namespace:
                raise AuthorityUnavailable("v2 deletion journal belongs to another namespace")
            saved = db.execute(
                "SELECT value FROM authority_meta WHERE key=?", (request_key,)).fetchone()
            if saved is not None and saved[0] != request:
                raise AuthorityUnavailable("namespace genesis request ID reused with different parameters")
            if db.execute(
                    "SELECT 1 FROM authority_v2_fences WHERE namespace=? AND state='active' LIMIT 1",
                    (self.namespace,)).fetchone():
                raise AuthorityUnavailable("active v2 fence blocks namespace genesis")
            if db.execute(
                    "SELECT 1 FROM authority_v2_mutations WHERE namespace=? AND state='pending' LIMIT 1",
                    (self.namespace,)).fetchone():
                raise AuthorityUnavailable("pending v2 mutation blocks namespace genesis")

            existing = db.execute(
                "SELECT 1 FROM authority_namespaces WHERE namespace=?", (self.namespace,)).fetchone()
            if saved is None:
                if (deletion_head.seq != 0 or execution_head.seq != 0 or deletion_history):
                    raise AuthorityUnavailable("namespace genesis requires empty independent journals")
                if existing or db.execute(
                        "SELECT 1 FROM authority_events WHERE namespace=? LIMIT 1",
                        (self.namespace,)).fetchone():
                    raise AuthorityUnavailable("namespace already has Authority history")
                if db.execute(
                        "SELECT 1 FROM authority_v2_fences WHERE namespace=? LIMIT 1",
                        (self.namespace,)).fetchone():
                    raise AuthorityUnavailable("namespace already has v2 fence history")
                if db.execute(
                        "SELECT 1 FROM authority_v2_mutations WHERE namespace=? LIMIT 1",
                        (self.namespace,)).fetchone():
                    raise AuthorityUnavailable("namespace already has v2 mutation history")
                if db.execute(
                        "SELECT 1 FROM authority_v2_epochs WHERE namespace=? LIMIT 1",
                        (self.namespace,)).fetchone():
                    raise AuthorityUnavailable("namespace already has v2 fence epoch")
                if db.execute(
                        "SELECT 1 FROM authority_namespaces WHERE namespace!=? "
                        "AND deletion_journal_id=? LIMIT 1",
                        (self.namespace, deletion_head.journal_id)).fetchone():
                    raise AuthorityUnavailable("deletion journal already belongs to another namespace")
                if db.execute(
                        "SELECT 1 FROM authority_namespaces WHERE namespace!=? "
                        "AND execution_journal_id=? LIMIT 1",
                        (self.namespace, execution_head.journal_id)).fetchone():
                    raise AuthorityUnavailable("execution journal already belongs to another namespace")
                db.execute(
                    "INSERT INTO authority_namespaces VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (self.namespace, holder, 1, "active", None, None, 0,
                     deletion_head.journal_id, 0, deletion_head.digest, "clear",
                     execution_head.journal_id, 0, execution_head.digest,
                     self.core._new_nonce()))
                self.core._event(db, self.namespace, "v2_namespace_genesis", 1, request)
                db.execute("INSERT INTO authority_meta(key,value) VALUES(?,?)", (request_key, request))
            elif not existing or deletion_history:
                raise AuthorityUnavailable("namespace genesis no longer has a clear activation")

            anchor = self._current_locked(
                db, deletion_head, execution_head, holder=holder, generation=1)
            return NamespaceBootstrapV2(
                anchor.authority_id, namespace_id, self.namespace, holder, 1, "active",
                NamespaceRuntimeState.ACTIVE, anchor, ())

    def begin_fence(self, *, credential, subject: str, holder: str,
                    operation: str, operation_id: str,
                    expected_anchor: RestoreAnchor,
                    effect_id: str | None = None,
                    command_digest: str | None = None,
                    footprint: RecoveryConstraintFootprint | None = None) -> FencePermitV2:
        """Issue only against the exact caller-seen full anchor and live owner."""
        identifier(subject, "subject")
        identifier(holder, "holder")
        identifier(operation_id, "operation_id")
        if type(expected_anchor) is not RestoreAnchor or expected_anchor.namespace != self.namespace:
            raise AuthorityUnavailable("expected full v2 anchor is required")
        self.core._require(credential, operation, self.namespace, holder)
        footprint_digest = None
        if operation == "dispatch":
            if (type(footprint) is not RecoveryConstraintFootprint
                    or footprint.namespace != self.namespace
                    or footprint.effect_id != effect_id):
                raise AuthorityUnavailable("dispatch requires exact service-verified footprint")
            keys = constraint_keys_from_footprint(footprint)
            try:
                verified = self.core._dispatch_verifier(self.namespace, effect_id, keys)
            except Exception as exc:
                raise AuthorityUnavailable("D08 dispatch verification unavailable") from exc
            if verified is not True:
                raise AuthorityUnavailable("D08 dispatch verification denied")
            footprint_digest = "sha256:" + hashlib.sha256(footprint._json().encode()).hexdigest()
        elif any(value is not None for value in (effect_id, command_digest, footprint)):
            raise AuthorityUnavailable("effect binding requires dispatch")
        with self._frozen() as (db, deletion_head, execution_head, deletion_history):
            anchor = self._current_locked(
                db, deletion_head, execution_head, holder=holder,
                generation=expected_anchor.activation_generation)
            if anchor != expected_anchor:
                raise AuthorityUnavailable("full v2 anchor changed before fence issuance")
            if deletion_history:
                raise AuthorityUnavailable("historical deletion closure blocks content fence")
            if operation == "dispatch":
                if db.execute("SELECT 1 FROM authority_effects WHERE namespace=? AND effect_id=?",
                              (self.namespace, effect_id)).fetchone():
                    raise AuthorityUnavailable("dispatch effect already has history")
            return self.fences.begin_fence_locked(
                db, subject=subject, holder=holder, operation=operation,
                current_anchor=anchor, operation_id=operation_id,
                effect_id=effect_id, command_digest=command_digest,
                footprint_digest=footprint_digest)

    def _require_permit(self, *, credential, subject: str,
                        permit: FencePermitV2) -> None:
        """Authenticate before taking journal guards; the host supplies subject."""
        identifier(subject, "subject")
        if (type(permit) is not FencePermitV2
                or permit.namespace != self.namespace or permit.subject != subject):
            raise AuthorityUnavailable("v2 fence subject or namespace mismatch")
        self.core._require(credential, permit.operation, self.namespace, permit.holder)

    def validate_fence(self, *, credential, subject: str,
                       permit: FencePermitV2) -> FencePermitV2:
        """Validate a live permit against both frozen journals and Authority."""
        self._require_permit(credential=credential, subject=subject, permit=permit)
        with self._frozen() as (db, deletion_head, execution_head, deletion_history):
            anchor = self._current_locked(
                db, deletion_head, execution_head, holder=permit.holder,
                generation=permit.generation)
            if deletion_history:
                raise AuthorityUnavailable("historical deletion closure blocks content fence")
            if anchor != permit.pinned_anchor:
                raise AuthorityUnavailable("v2 fence pinned anchor changed")
            return self.fences.validate_fence_locked(
                db, permit, subject=subject, current_anchor=anchor)

    def finish_fence(self, *, credential, subject: str,
                     permit: FencePermitV2, request_id: str,
                     request_digest: str) -> None:
        """Finish under both writer guards; exact completed retries return no permit."""
        self._require_permit(credential=credential, subject=subject, permit=permit)
        with self._frozen() as (db, deletion_head, execution_head, deletion_history):
            anchor = self._current_locked(
                db, deletion_head, execution_head, holder=permit.holder,
                generation=permit.generation)
            if deletion_history:
                raise AuthorityUnavailable("historical deletion closure blocks content fence")
            self.fences.finish_fence_locked(
                db, permit, subject=subject, current_anchor=anchor,
                request_id=request_id, request_digest=request_digest)


__all__ = ["AuthorityV2FenceService"]
