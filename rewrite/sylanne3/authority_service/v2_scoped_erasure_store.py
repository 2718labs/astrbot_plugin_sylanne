"""Authority-local scoped deletion state, separate from per-operation journal phases.

This is a storage primitive. The controlled application receipt used by tests
is not a Graph proof; no public route may call ``apply_verified_head`` until a
pinned W01 verifier supplies the original cumulative application receipt.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re

from .contract import AuthorityUnavailable, identifier
from .core import AuthorityServiceCore
from .v2_contract import DeletionPendingV1, DeletionMutationReceiptV1
from .v2_deletion_guard import AuthorityV2DeletionGuard
from .v2_execution_journal import AuthorityV2ExecutionJournal
from .v2_fence_store import AuthorityV2FenceStore


_SCHEMA = "sylanne3.authority.scoped-erasure.v2"
_MARKER = "scoped_erasure_v2_migration"
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_DDL = """CREATE TABLE authority_scoped_erasure_v2(
    namespace TEXT PRIMARY KEY, schema TEXT NOT NULL,
    active_operation_id TEXT, aggregate_phase TEXT NOT NULL,
    active_epoch INTEGER, closed_seq INTEGER, closed_digest TEXT,
    applied_seq INTEGER NOT NULL, applied_digest TEXT NOT NULL,
    applied_epoch INTEGER NOT NULL, cut_seq INTEGER NOT NULL,
    cut_digest TEXT NOT NULL,
    CHECK(schema='sylanne3.authority.scoped-erasure.v2'),
    CHECK(aggregate_phase IN ('clear','pending','accepted')),
    CHECK((active_operation_id IS NULL AND aggregate_phase='clear'
           AND active_epoch IS NULL AND closed_seq IS NULL AND closed_digest IS NULL)
       OR (active_operation_id IS NOT NULL AND aggregate_phase!='clear'
           AND active_epoch IS NOT NULL)),
    CHECK((closed_seq IS NULL)=(closed_digest IS NULL))
) STRICT"""


@dataclass(frozen=True, slots=True)
class ScopedErasureStateV2:
    namespace: str
    active_operation_id: str | None
    aggregate_phase: str
    active_epoch: int | None
    closed_seq: int | None
    closed_digest: str | None
    applied_seq: int
    applied_digest: str
    applied_epoch: int
    cut_seq: int
    cut_digest: str


@dataclass(frozen=True, slots=True)
class VerifiedGraphAppliedHeadV2:
    """Internal verifier output; constructing this DTO does not verify Graph."""

    namespace: str
    deletion_operation_id: str
    deletion_seq: int
    deletion_digest: str
    deletion_epoch: int
    graph_receipt_digest: str

    def __post_init__(self) -> None:
        identifier(self.namespace, "namespace")
        identifier(self.deletion_operation_id, "deletion_operation_id")
        if (type(self.deletion_seq) is not int or self.deletion_seq < 1
                or type(self.deletion_epoch) is not int or self.deletion_epoch < 1
                or any(type(value) is not str or _DIGEST.fullmatch(value) is None
                       for value in (
                           self.deletion_digest, self.graph_receipt_digest))):
            raise ValueError("invalid cumulative graph application claim")


class AuthorityV2ScopedErasureStore:
    def __init__(self, *, core: AuthorityServiceCore,
                 fences: AuthorityV2FenceStore,
                 deletion: AuthorityV2DeletionGuard,
                 execution: AuthorityV2ExecutionJournal, namespace: str):
        identifier(namespace, "namespace")
        if (type(core) is not AuthorityServiceCore
                or type(fences) is not AuthorityV2FenceStore
                or type(deletion) is not AuthorityV2DeletionGuard
                or type(execution) is not AuthorityV2ExecutionJournal
                or core._db is not fences._db or core._lock is not fences._lock
                or execution.namespace != namespace):
            raise AuthorityUnavailable("one installed scoped deletion Authority required")
        self.core, self.fences = core, fences
        self.deletion, self.execution = deletion, execution
        self.namespace = namespace
        self._current_graph_application_v1 = None

    @staticmethod
    def _marker(db):
        row = db.execute("SELECT value FROM authority_meta WHERE key=?",
                         (_MARKER,)).fetchone()
        if row is None:
            return None
        try:
            value = json.loads(row[0])
        except (TypeError, ValueError) as exc:
            raise AuthorityUnavailable("scoped deletion migration marker malformed") from exc
        if (type(value) is not dict or set(value) != {
                "schema", "namespace", "authority_id", "cut_seq", "cut_digest",
                "stage"} or value["schema"] != _SCHEMA
                or value["stage"] not in {"complete", "hold_legacy_history"}
                or type(value["cut_seq"]) is not int or value["cut_seq"] < 0):
            raise AuthorityUnavailable("scoped deletion migration marker differs")
        return value

    @staticmethod
    def _table(db) -> bool:
        row = db.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' "
            "AND name='authority_scoped_erasure_v2'").fetchone()
        if row is None:
            return False
        if row[0] != _DDL:
            raise AuthorityUnavailable("scoped deletion schema differs")
        return True

    def migrate_zero_history(self, *, credential) -> ScopedErasureStateV2:
        """Explicit only: historical operations remain unchanged and HOLD."""
        self.core._require(credential, "migrate_deletion", self.namespace)
        blocked = False
        result = None
        with self.deletion.freeze_writes():
            with self.execution.freeze_writes():
                deletion_head = self.deletion.verified_head()
                execution_head = self.execution.verified_head()
                history = self.deletion.has_deletion_history(self.namespace)
                with self.core._tx() as db:
                    if db.execute("SELECT value FROM authority_meta WHERE key='service_mode'").fetchone() != ("v2-only",):
                        raise AuthorityUnavailable("scoped deletion needs v2-only Authority")
                    self.core._require_no_deletion_migration(db)
                    self.fences._check_schema(db)
                    self.deletion.require_target_schema_locked(
                        db, authority_id=self.core._id(db),
                        namespace=self.namespace, journal_id=deletion_head.journal_id)
                    if self.deletion.schema_version() != 2:
                        raise AuthorityUnavailable("scoped deletion needs schema-2 journal")
                    row = self.core._row(db, self.namespace)
                    if (row[0] is None or row[2] != "active" or row[3:5] != (None, None)
                            or row[6:9] != (deletion_head.journal_id,
                                              deletion_head.seq,
                                              deletion_head.digest)
                            or row[10:13] != (execution_head.journal_id,
                                               execution_head.seq,
                                               execution_head.digest)):
                        raise AuthorityUnavailable("scoped deletion migration needs settled heads")
                    marker = self._marker(db)
                    if marker is not None:
                        if marker["stage"] != "complete":
                            blocked = True
                        else:
                            result = self.state_locked(db, allow_reserved=True)
                    else:
                        blocked = history
                        if not blocked and (
                                row[9] != "clear" or db.execute(
                                    "SELECT 1 FROM authority_v2_fences "
                                    "WHERE namespace=? AND state='active' LIMIT 1",
                                    (self.namespace,)).fetchone()):
                            raise AuthorityUnavailable(
                                "scoped deletion migration needs idle clear namespace")
                        stage = "hold_legacy_history" if blocked else "complete"
                        marker = dict(schema=_SCHEMA, namespace=self.namespace,
                                      authority_id=self.core._id(db),
                                      cut_seq=deletion_head.seq,
                                      cut_digest=deletion_head.digest, stage=stage)
                        db.execute("INSERT INTO authority_meta(key,value) VALUES(?,?)",
                                   (_MARKER, json.dumps(marker, sort_keys=True,
                                                        separators=(",", ":"))))
                        if not blocked:
                            if not self._table(db):
                                db.execute(_DDL)
                            db.execute("INSERT INTO authority_scoped_erasure_v2 VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                                       (self.namespace, _SCHEMA, None, "clear", None,
                                        None, None, deletion_head.seq,
                                        deletion_head.digest, 0,
                                        deletion_head.seq, deletion_head.digest))
                            result = self.state_locked(db)
        if blocked:
            raise AuthorityUnavailable("legacy deletion history requires verified migration")
        if result is None:
            raise AuthorityUnavailable("scoped deletion migration produced no state")
        return result

    def state_locked(self, db, *, allow_reserved: bool = False) -> ScopedErasureStateV2:
        if db is not self.core._db or not db.in_transaction:
            raise AuthorityUnavailable("scoped deletion state needs Core transaction")
        return read_scoped_erasure_state_in_tx_v1(db, namespace=self.namespace, allow_reserved=allow_reserved)

    def reserve_locked(self, db, pending: DeletionPendingV1) -> None:
        """Reserve one operation in the same transaction as typed pending."""
        state = self.state_locked(db)
        before = pending.before_anchor
        if (pending.permit.namespace != self.namespace
                or (pending.source_phase, pending.target_phase) != ("absent", "pending")
                or state.aggregate_phase != "clear"
                or state.active_operation_id is not None
                or (state.applied_seq, state.applied_digest) != (
                    before.deletion_seq, before.deletion_digest)
                or pending.deletion_epoch != state.applied_epoch + 1):
            raise AuthorityUnavailable("scoped deletion overlap or epoch mismatch")
        changed = db.execute(
            "UPDATE authority_scoped_erasure_v2 SET active_operation_id=?,"
            "aggregate_phase='pending',active_epoch=? WHERE namespace=? "
            "AND active_operation_id IS NULL AND aggregate_phase='clear' "
            "AND applied_seq=? AND applied_digest=? AND applied_epoch=?",
            (pending.deletion_operation_id, pending.deletion_epoch, self.namespace,
             before.deletion_seq, before.deletion_digest,
             state.applied_epoch)).rowcount
        if changed != 1:
            raise AuthorityUnavailable("scoped deletion reservation CAS failed")
        # Core aggregate still reads clear until the journal append and CAS.
        # The reservation and typed pending share this transaction; consumers
        # already block on the pending fence while recovery completes.

    def require_pending_locked(self, db, pending: DeletionPendingV1) -> None:
        state = self.state_locked(db, allow_reserved=True)
        if (state.active_operation_id != pending.deletion_operation_id
                or state.active_epoch != pending.deletion_epoch
                or state.aggregate_phase != (
                    "pending" if pending.source_phase in {"absent", "pending"}
                    else "accepted")):
            raise AuthorityUnavailable("scoped deletion operation is not active")

    def transition_locked(self, db, pending: DeletionPendingV1) -> str:
        """Advance the aggregate inside the journal-to-Core CAS transaction."""
        self.require_pending_locked(db, pending)
        if pending.target_phase == "pending":
            return "pending"
        if pending.target_phase == "accepted":
            changed = db.execute(
                "UPDATE authority_scoped_erasure_v2 SET aggregate_phase='accepted' "
                "WHERE namespace=? AND active_operation_id=? "
                "AND aggregate_phase='pending' AND active_epoch=? AND closed_seq IS NULL",
                (self.namespace, pending.deletion_operation_id,
                 pending.deletion_epoch)).rowcount
            result = "accepted"
        elif pending.target_phase == "closed":
            changed = db.execute(
                "UPDATE authority_scoped_erasure_v2 SET closed_seq=?,closed_digest=? "
                "WHERE namespace=? AND active_operation_id=? "
                "AND aggregate_phase='accepted' AND active_epoch=? "
                "AND closed_seq IS NULL",
                (pending.expected_deletion_seq,
                 pending.expected_append_digest, self.namespace,
                 pending.deletion_operation_id, pending.deletion_epoch)).rowcount
            result = "accepted"
        else:
            raise AuthorityUnavailable("unknown scoped deletion transition")
        if changed != 1:
            raise AuthorityUnavailable("scoped deletion aggregate CAS failed")
        return result

    def install_current_graph_application_v1(self, reader):
        from .c09_graph_application_v1 import InstalledC09GraphApplicationV1
        if (type(reader) is not InstalledC09GraphApplicationV1 or reader.scoped is not self
                or reader.core is not self.core or self._current_graph_application_v1 is not None):
            raise AuthorityUnavailable("installed cumulative Graph verifier differs")
        self._current_graph_application_v1 = reader

    def apply_verified_head(self, *, credential, subject: str, operation_id: str):
        """Consume the cumulative ACK under journals, Core, then Graph locks."""
        reader = self._current_graph_application_v1
        if reader is None:
            raise AuthorityUnavailable("pinned cumulative Graph application verifier unavailable")
        if subject != reader.subject:
            raise AuthorityUnavailable("C09 installed application subject differs")
        self.core._require(credential, "deletion", self.namespace)
        with self.deletion.freeze_writes():
            with self.execution.freeze_writes():
                head = self.deletion.verified_head()
                execution_head = self.execution.verified_head()
                with self.core._tx() as db:
                    with reader.read_verified_applied_original_v1(operation_id=operation_id) as (receipt, ack):
                        if (head.seq, head.digest) != (receipt.deletion_seq, receipt.deletion_digest):
                            raise AuthorityUnavailable("Graph application is not at latest deletion head")
                        state = self.state_locked(db)
                        if ((state.applied_seq, state.applied_digest, state.applied_epoch)
                                == (receipt.deletion_seq, receipt.deletion_digest, receipt.deletion_epoch)):
                            if state.aggregate_phase != "clear" or state.active_operation_id is not None:
                                raise AuthorityUnavailable("C09 recovered applied watermark is not clear")
                            return state
                        return self._apply_verified_head_locked_v1(db, head, execution_head, subject, receipt)

    def _apply_controlled_head_for_storage_test(
            self, *, credential, subject: str,
            receipt: VerifiedGraphAppliedHeadV2):
        """Exercise the storage CAS only; this is no product Graph attestation."""
        return self._apply_current_graph_head_original_v1(credential=credential, subject=subject, receipt=receipt)

    def _apply_current_graph_head_original_v1(
            self, *, credential, subject: str, receipt: VerifiedGraphAppliedHeadV2):
        if type(receipt) is not VerifiedGraphAppliedHeadV2:
            raise AuthorityUnavailable("typed cumulative Graph original required")
        identifier(subject, "subject")
        if receipt.namespace != self.namespace:
            raise AuthorityUnavailable("Graph application crosses namespace")
        self.core._require(credential, "deletion", self.namespace)
        with self.deletion.freeze_writes():
            with self.execution.freeze_writes():
                head = self.deletion.verified_head()
                execution_head = self.execution.verified_head()
                with self.core._tx() as db:
                    return self._apply_verified_head_locked_v1(db, head, execution_head, subject, receipt)

    def _apply_verified_head_locked_v1(self, db, head, execution_head, subject, receipt):
        if (head.seq, head.digest) != (receipt.deletion_seq, receipt.deletion_digest):
            raise AuthorityUnavailable("Graph application is not at latest deletion head")
        if self.deletion.latest_phases().get((self.namespace, receipt.deletion_operation_id)) != "closed":
            raise AuthorityUnavailable("scoped deletion is not closed")
        tail = self.deletion._db.execute(
            "SELECT mutation_id,operation_id,phase FROM authority_deletion_v2_tail WHERE seq=?",
            (head.seq,)).fetchone()
        if tail is None or tail[1:] != (receipt.deletion_operation_id, "closed"):
            raise AuthorityUnavailable("latest deletion close original differs")
        state = self.state_locked(db)
        row = self.core._row(db, self.namespace)
        if (state.active_operation_id != receipt.deletion_operation_id
                or state.aggregate_phase != "accepted"
                or state.active_epoch != receipt.deletion_epoch
                or (state.closed_seq, state.closed_digest) != (
                    head.seq, head.digest)
                or row[0] is None or row[2] != "active"
                or row[3:5] != (None, None)
                or row[6:10] != (head.journal_id, head.seq,
                                  head.digest, "accepted")
                or row[10:13] != (
                    execution_head.journal_id, execution_head.seq,
                    execution_head.digest)):
            raise AuthorityUnavailable("scoped deletion application CAS precondition differs")
        mutation = self.fences.mutation_locked(db, tail[0])
        if mutation is None:
            raise AuthorityUnavailable("closed deletion mutation is absent")
        kind, closed, close_receipt, permit = self.fences._decode_mutation_row(mutation)
        if (kind != "deletion" or type(close_receipt) is not DeletionMutationReceiptV1
                or close_receipt.pending != closed
                or closed.target_phase != "closed"
                or closed.deletion_operation_id != receipt.deletion_operation_id
                or closed.deletion_epoch != receipt.deletion_epoch
                or close_receipt.after_anchor != self.core._anchor(
                    db, self.namespace, row)
                or permit is None or permit.subject != subject):
            raise AuthorityUnavailable("closed Authority original differs")
        self.fences.finish_fence_locked(
            db, permit, subject=subject,
            current_anchor=close_receipt.after_anchor,
            request_id="c09-apply-" + receipt.deletion_operation_id,
            request_digest="sha256:" + hashlib.sha256(json.dumps(
                dict(namespace=receipt.namespace,
                     operation_id=receipt.deletion_operation_id,
                     deletion_seq=receipt.deletion_seq,
                     deletion_digest=receipt.deletion_digest,
                     deletion_epoch=receipt.deletion_epoch,
                     graph_receipt_digest=receipt.graph_receipt_digest),
                sort_keys=True, separators=(",", ":")).encode()).hexdigest())
        changed = db.execute(
            "UPDATE authority_namespaces SET deletion_phase='clear',"
            "revocation_epoch=revocation_epoch+1,anchor_nonce=? "
            "WHERE namespace=? AND deletion_phase='accepted' "
            "AND deletion_seq=? AND deletion_digest=?",
            (self.core._new_nonce(), self.namespace,
             head.seq, head.digest)).rowcount
        if changed != 1:
            raise AuthorityUnavailable("scoped deletion clear CAS failed")
        changed = db.execute(
            "UPDATE authority_scoped_erasure_v2 SET "
            "active_operation_id=NULL,aggregate_phase='clear',"
            "active_epoch=NULL,closed_seq=NULL,closed_digest=NULL,"
            "applied_seq=?,applied_digest=?,applied_epoch=? "
            "WHERE namespace=? AND active_operation_id=? "
            "AND aggregate_phase='accepted' AND closed_seq=? "
            "AND closed_digest=?",
            (head.seq, head.digest, receipt.deletion_epoch,
             self.namespace, receipt.deletion_operation_id,
             head.seq, head.digest)).rowcount
        if changed != 1:
            raise AuthorityUnavailable("scoped applied watermark CAS failed")
        self.core._event(db, self.namespace, "scoped_erasure_applied",
                         row[1], (receipt.deletion_operation_id,
                                  head.seq, head.digest,
                                  receipt.graph_receipt_digest))
        return self.state_locked(db)

    def read_ancestor_receipt(self, *, credential, subject: str,
                              mutation_id: str) -> DeletionMutationReceiptV1:
        """Read an exact committed operation ancestor without minting a permit."""
        identifier(subject, "subject")
        identifier(mutation_id, "mutation_id")
        self.core._require(credential, "deletion", self.namespace)
        with self.deletion.freeze_writes():
            with self.execution.freeze_writes():
                head = self.deletion.verified_head()
                execution_head = self.execution.verified_head()
                with self.core._tx() as db:
                    self.state_locked(db, allow_reserved=True)
                    current = self.core._row(db, self.namespace)
                    if (current[6:9] != (head.journal_id, head.seq, head.digest)
                            or current[10:13] != (
                                execution_head.journal_id, execution_head.seq,
                                execution_head.digest)):
                        raise AuthorityUnavailable("Core differs from cumulative deletion head")
                    mutation = self.fences.mutation_locked(db, mutation_id)
                    if mutation is None or mutation[1:3] != (self.namespace, subject):
                        raise AuthorityUnavailable("historical deletion mutation is absent")
                    kind, pending, receipt, updated = self.fences._decode_mutation_row(mutation)
                    if (kind != "deletion" or mutation[4] != "committed"
                            or type(pending) is not DeletionPendingV1
                            or type(receipt) is not DeletionMutationReceiptV1
                            or receipt.pending != pending or updated is None
                            or receipt.after_anchor.deletion_seq > head.seq
                            or receipt.after_anchor.deletion_digest
                               != pending.expected_append_digest):
                        raise AuthorityUnavailable("historical deletion receipt differs")
                    journal = self.deletion._db.execute(
                        "SELECT append_id,mutation_id,operation_id,phase,chain_digest "
                        "FROM authority_deletion_v2_tail WHERE seq=?",
                        (pending.expected_deletion_seq,)).fetchone()
                    if (journal != (pending.expected_append_id, pending.mutation_id,
                                    pending.deletion_operation_id,
                                    pending.target_phase,
                                    pending.expected_append_digest)
                            or self.deletion.expected_digest(pending)
                               != pending.expected_append_digest):
                        raise AuthorityUnavailable("historical deletion append differs")
                    return receipt


__all__ = ["AuthorityV2ScopedErasureStore", "ScopedErasureStateV2",
           "VerifiedGraphAppliedHeadV2"]


def read_scoped_erasure_state_in_tx_v1(db, *, namespace, allow_reserved=False):
    from .c09_connection_state_v1 import authority_id_in_tx_v1, namespace_row_in_tx_v1
    if not db.in_transaction:
        raise AuthorityUnavailable("scoped deletion state needs pinned Authority transaction")
    marker = AuthorityV2ScopedErasureStore._marker(db)
    if (marker is None or marker["stage"] != "complete"
            or marker["namespace"] != namespace
            or marker["authority_id"] != authority_id_in_tx_v1(db)
            or not AuthorityV2ScopedErasureStore._table(db)):
        raise AuthorityUnavailable("scoped deletion migration is not complete")
    row = db.execute("SELECT * FROM authority_scoped_erasure_v2 WHERE namespace=?",
                     (namespace,)).fetchone()
    if (row is None or row[1] != _SCHEMA or row[10:12] != (
            marker["cut_seq"], marker["cut_digest"])):
        raise AuthorityUnavailable("scoped deletion state differs from migration")
    state = ScopedErasureStateV2(row[0], row[2], row[3], row[4], row[5],
                                 row[6], row[7], row[8], row[9], row[10], row[11])
    current = namespace_row_in_tx_v1(db, namespace)
    core_phase = current[9]
    if (state.applied_seq < state.cut_seq or state.applied_epoch < 0
            or state.active_operation_id is not None
            and state.active_epoch != state.applied_epoch + 1
            or state.closed_seq is not None
            and (state.aggregate_phase != "accepted"
                 or state.closed_seq <= state.applied_seq)
            or state.aggregate_phase == "clear"
            and current[7:9] != (state.applied_seq, state.applied_digest)):
        raise AuthorityUnavailable("scoped deletion watermark or epoch differs")
    if core_phase != state.aggregate_phase:
        if not (allow_reserved and state.aggregate_phase == "pending"
                and core_phase == "clear"):
            raise AuthorityUnavailable("scoped deletion aggregate phase differs from Core")
        rows = tuple(db.execute(
            "SELECT operation_id,namespace,subject,request_digest,state,"
            "conflict_keys_json,pending,receipt,updated_permit,mutation_kind,"
            "deletion_evidence,footprint FROM authority_v2_mutations "
            "WHERE namespace=? AND mutation_kind='deletion' AND state='pending'",
            (namespace,)))
        if len(rows) != 1:
            raise AuthorityUnavailable("scoped reserved pending original is absent")
        kind, pending, receipt, updated = AuthorityV2FenceStore._decode_mutation_row(rows[0])
        fence = AuthorityV2FenceStore._row(db, pending.permit.operation_id)
        if (kind != "deletion" or receipt is not None or updated is not None
                or pending.source_phase != "absent"
                or pending.target_phase != "pending"
                or pending.deletion_operation_id != state.active_operation_id
                or pending.deletion_epoch != state.active_epoch
                or fence is None or fence[6] != "active"
                or AuthorityV2FenceStore._permit(fence) != pending.permit):
            raise AuthorityUnavailable("scoped reserved pending original differs")
    return state
