"""Installed cumulative Graph application and independent C09 ACK reader."""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict, replace
import json
from pathlib import Path
import time

from .contract import AuthorityUnavailable
from .v2_scoped_erasure_store import VerifiedGraphAppliedHeadV2
from ..contracts import Event, Scope, canonical_json
from ..graph_store import GraphStore, ProductionGraphStore
from ..graph_types import GraphCandidate
from ..runtime_contracts import canonical_digest
from ..runtime.c09_graph_originals_read_v4 import read_graph_rebase_certificate_v1

_TABLE = "graph_c09_cumulative_applications_v1"
_DDL = """CREATE TABLE graph_c09_cumulative_applications_v1(
 bot TEXT NOT NULL, persona TEXT NOT NULL, operation_id TEXT NOT NULL,
 original_json TEXT NOT NULL, original_digest TEXT NOT NULL UNIQUE,
 PRIMARY KEY(bot,persona,operation_id)) STRICT"""


def install_c09_graph_application_schema_v1(db):
    row = db.execute("SELECT sql FROM sqlite_master WHERE name=?", (_TABLE,)).fetchone()
    if row is None:
        db.execute(_DDL)
        for action in ("UPDATE", "DELETE"):
            db.execute(f"CREATE TRIGGER {_TABLE}_no_{action.lower()} BEFORE {action} ON {_TABLE} "
                "BEGIN SELECT RAISE(ABORT,'immutable C09 cumulative application'); END")
    elif row[0] != _DDL:
        raise AuthorityUnavailable("C09 Graph application schema differs")


class InstalledC09GraphApplicationV1:
    def __init__(self, *, control, core, scoped, coordinator, bootstrap, namespace, subject, credential):
        from .c09_storage_control_v1 import C09StorageControlV1
        from .core import AuthorityServiceCore
        from .v2_scoped_erasure_store import AuthorityV2ScopedErasureStore
        from ..graph_coordinator import GraphCoordinator
        if (type(control) is not C09StorageControlV1 or type(core) is not AuthorityServiceCore
                or type(scoped) is not AuthorityV2ScopedErasureStore or scoped.core is not core
                or type(coordinator) is not GraphCoordinator):
            raise AuthorityUnavailable("complete installed C09 Graph application required")
        coordinator._admin(bootstrap)
        store = coordinator._GraphCoordinator__store
        if not isinstance(store, ProductionGraphStore):
            raise AuthorityUnavailable("C09 cumulative application needs actual production Graph")
        self.control, self.core, self.scoped, self.coordinator = control, core, scoped, coordinator
        self.store, self.bootstrap, self.namespace = store, bootstrap, namespace
        self.subject, self.credential = subject, credential
        self.capability = coordinator._GraphCoordinator__graph_capability

    def _certificate_locked(self, db, context, operation_id):
        member = next(m for m in context.manifest["members"] if m["role"] == "graph")
        path = db.execute("PRAGMA database_list").fetchone()
        if path is None or str(Path(path[2]).resolve()) != member["resolved_path"]:
            raise AuthorityUnavailable("C09 Graph application outside current manifest")
        certificate = read_graph_rebase_certificate_v1(db, self.namespace, operation_id)
        if (certificate is None or certificate.certificate_digest != context.manifest["certificate_digest"]
                or certificate.new_incarnation != member["incarnation_or_journal_id"]
                or certificate.maintenance_generation != context.storage_generation
                or certificate.tombstone_root != context.manifest["cumulative_tombstone_root"]):
            raise AuthorityUnavailable("current C09 cumulative certificate differs")
        keys = tuple(sorted(row[0] for row in db.execute("SELECT key_digest FROM graph_c09_erased_keys_v1 "
            "WHERE bot=? AND persona=?", self.namespace.as_tuple)))
        if keys != certificate.cumulative_erased_key_digests:
            raise AuthorityUnavailable("C09 permanent erased-key set differs")
        prior = certificate
        while prior.prior_certificate_digest is not None:
            candidates = [read_graph_rebase_certificate_v1(db, self.namespace, row[0])
                for row in db.execute("SELECT operation_id FROM graph_c09_rebase_certificates_v1 "
                    "WHERE bot=? AND persona=?", self.namespace.as_tuple)]
            older = next((c for c in candidates if c.certificate_digest == prior.prior_certificate_digest), None)
            if (older is None or older.new_incarnation != prior.old_incarnation
                    or older.maintenance_generation + 1 != prior.maintenance_generation
                    or older.cumulative_erased_key_digests != prior.prior_erased_key_digests):
                raise AuthorityUnavailable("C09 cumulative certificate ancestry differs")
            prior = older
        return certificate

    def _read_ack_locked(self, db, operation_id):
        row = db.execute(f"SELECT original_json,original_digest FROM {_TABLE} "
            "WHERE bot=? AND persona=? AND operation_id=?", (*self.namespace.as_tuple, operation_id)).fetchone()
        if row is None:
            return None
        original = json.loads(row[0])
        if (original.get("operation_id") != operation_id or original.get("namespace") != list(self.namespace.as_tuple)
                or original.get("ack_digest") != row[1]
                or canonical_digest({k: v for k, v in original.items() if k != "ack_digest"}) != row[1]):
            raise AuthorityUnavailable("C09 cumulative Graph ACK commitment differs")
        return original

    def apply_current_graph_head_v1(self, *, operation_id, closed_receipt):
        self.coordinator._admin(self.bootstrap)
        context = self.control.read_verified_current_storage_v1()
        context.require_current("maintenance")
        if context.stage != "CLEANED" or context.prepared_original["operation_id"] != operation_id:
            raise AuthorityUnavailable("C09 Graph ACK requires this CLEANED")
        with self.scoped.deletion.freeze_writes(), self.scoped.execution.freeze_writes():
            deletion = self.scoped.deletion.verified_head()
            execution = self.scoped.execution.verified_head()
            with self.core._tx() as core_db:
                anchor = self.core._anchor(core_db, self.scoped.namespace, self.core._row(core_db, self.scoped.namespace))
                tail_row = self.scoped.deletion._db.execute("SELECT mutation_id,operation_id,phase "
                    "FROM authority_deletion_v2_tail WHERE seq=?", (deletion.seq,)).fetchone()
                saved = None if tail_row is None else self.scoped.fences.mutation_locked(core_db, tail_row[0])
                stored = None if saved is None else self.scoped.fences._decode_mutation_row(saved)
                if (closed_receipt.after_anchor.deletion_seq != deletion.seq
                        or closed_receipt.after_anchor.deletion_digest != deletion.digest
                        or closed_receipt.pending.target_phase != "closed"
                        or closed_receipt.pending.deletion_operation_id != operation_id
                        or tail_row is None or tail_row[1:] != (operation_id, "closed") or stored is None
                        or stored[0] != "deletion" or stored[2] != closed_receipt
                        or saved[1:3] != (self.scoped.namespace, self.subject)):
                    raise AuthorityUnavailable("actual closed original differs from latest journal")
                state = self.scoped.state_locked(core_db)
                if (state.applied_seq < deletion.seq and (state.closed_seq, state.closed_digest) != (deletion.seq, deletion.digest)):
                    raise AuthorityUnavailable("C09 latest closed obligation differs")
                with self.store._lock:
                    db = self.store._db
                    db.execute("BEGIN IMMEDIATE")
                    try:
                        certificate = self._certificate_locked(db, context, operation_id)
                        prior = self._read_ack_locked(db, operation_id)
                        if prior is not None:
                            db.rollback()
                            return prior
                        metadata, epoch = self.coordinator._v2_graph_stamp(self.namespace)
                        if metadata.requirements.graph_incarnation != certificate.new_incarnation:
                            raise AuthorityUnavailable("C09 current Graph incarnation differs")
                        tail = tuple(self.scoped.deletion._db.execute(
                            "SELECT seq,operation_id,phase,chain_digest FROM authority_deletion_v2_tail "
                            "WHERE seq>? AND seq<=? ORDER BY seq", (state.applied_seq, deletion.seq)))
                        if not tail or tail[-1] != (deletion.seq, operation_id, "closed", deletion.digest):
                            raise AuthorityUnavailable("C09 cumulative deletion suffix differs")
                        certificate_operations = {row[0] for row in db.execute(
                            "SELECT operation_id FROM graph_c09_rebase_certificates_v1 WHERE bot=? AND persona=?",
                            self.namespace.as_tuple)}
                        if any(op not in certificate_operations for _, op, _, _ in tail):
                            raise AuthorityUnavailable("C09 cumulative operation lacks erasure certificate")
                        candidate = GraphCandidate(Event(Scope(*self.namespace.as_tuple, "c09-maintenance"),
                            "c09-ack-" + canonical_digest((self.namespace, operation_id))[:48], time.time(),
                            "c09.cumulative-erasure-application.v1", {"certificate_digest": certificate.certificate_digest}),
                            (), (), (epoch,))
                        result = None
                        def record(_db, receipt):
                            nonlocal result
                            target = replace(metadata.requirements, deletion_seq=deletion.seq,
                                deletion_digest=deletion.digest, execution_seq=execution.seq,
                                execution_digest=execution.digest, revocation_epoch=anchor.revocation_epoch,
                                execution_journal_id=execution.journal_id, deletion_journal_id=deletion.journal_id)
                            if target.execution_journal_id != metadata.requirements.execution_journal_id:
                                self.store.cas_c09_recovery_identity_v1(metadata, target, storage_reader=self.control,
                                    core=self.core, credential=self.credential, _capability=self.capability)
                            else:
                                self.store.cas_graph_recovery_metadata(metadata, target, _capability=self.capability)
                            result = {"schema": "sylanne3.c09.cumulative-graph-ack.v1",
                                "namespace": list(self.namespace.as_tuple), "operation_id": operation_id,
                                "manifest_digest": context.manifest_digest, "storage_generation": context.storage_generation,
                                "certificate_digest": certificate.certificate_digest,
                                "cumulative_tombstone_root": certificate.tombstone_root,
                                "new_incarnation": certificate.new_incarnation, "deletion_seq": deletion.seq,
                                "deletion_digest": deletion.digest, "deletion_epoch": closed_receipt.pending.deletion_epoch,
                                "closed_digest": canonical_digest(closed_receipt), "cumulative_suffix_digest": canonical_digest(tail),
                                "prior_applied_seq": state.applied_seq, "graph_receipt_digest": canonical_digest(receipt),
                                "graph_revision": metadata.graph_revision + 1}
                            result["ack_digest"] = canonical_digest(result)
                            _db.execute(f"INSERT INTO {_TABLE} VALUES(?,?,?,?,?)",
                                (*self.namespace.as_tuple, operation_id, canonical_json(result), result["ack_digest"]))
                        GraphStore._graph_commit_in_transaction(self.store, candidate,
                            _receipt_hook=record, _capability=self.capability)
                        if result is None:
                            raise AuthorityUnavailable("C09 Graph ACK event was not committed")
                        db.commit()
                        return result
                    except BaseException:
                        if db.in_transaction:
                            db.rollback()
                        raise

    @contextmanager
    def read_verified_applied_original_v1(self, *, operation_id):
        context = self.control.read_verified_current_storage_v1()
        context.require_current("maintenance")
        with self.store._lock:
            db = self.store._db
            db.execute("BEGIN")
            try:
                certificate = self._certificate_locked(db, context, operation_id)
                ack = self._read_ack_locked(db, operation_id)
                metadata, _epoch = self.coordinator._v2_graph_stamp(self.namespace)
                if (ack is None or ack["manifest_digest"] != context.manifest_digest
                        or ack["certificate_digest"] != certificate.certificate_digest
                        or ack["cumulative_tombstone_root"] != certificate.tombstone_root
                        or metadata.requirements.graph_incarnation != ack["new_incarnation"]
                        or metadata.graph_revision < ack["graph_revision"]):
                    raise AuthorityUnavailable("C09 installed cumulative Graph application differs")
                with self.core._lock:
                    saved = self.scoped.fences.mutation_locked(self.core._db,
                        "c09-closed-mutation-" + canonical_digest((self.scoped.namespace, operation_id))[:48])
                    stored = None if saved is None else self.scoped.fences._decode_mutation_row(saved)
                    if (stored is None or stored[0] != "deletion" or stored[2] is None
                            or saved[1:3] != (self.scoped.namespace, self.subject)
                            or canonical_digest(stored[2]) != ack["closed_digest"]):
                        raise AuthorityUnavailable("C09 Graph ACK lacks actual closed Authority original")
                original = VerifiedGraphAppliedHeadV2(self.scoped.namespace, operation_id,
                    ack["deletion_seq"], ack["deletion_digest"], ack["deletion_epoch"],
                    "sha256:" + ack["graph_receipt_digest"])
                yield original, ack
                context.require_current("maintenance")
            finally:
                db.rollback()
