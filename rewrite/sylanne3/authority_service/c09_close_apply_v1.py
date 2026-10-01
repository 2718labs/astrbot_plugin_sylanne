"""Installed CLEANED -> closed -> cumulative ACK -> scoped applied -> release."""
from __future__ import annotations

from dataclasses import replace, fields, asdict
from contextlib import closing, nullcontext
import json
from pathlib import Path
import sqlite3
import threading

from .contract import AuthorityUnavailable
from .c09_storage_control_v1 import C09StorageControlV1, SURFACES, digest
from .c09_graph_application_v1 import InstalledC09GraphApplicationV1
from .v2_contract import (
    DeletionEvidenceV1, DeletionPendingV1, DeletionMutationReceiptV1,
    from_wire, deletion_scope_digest,
)
from .v2_fence_service import AuthorityV2FenceService
from .v2_deletion_recovery_service import AuthorityV2DeletionPendingRecovery
from ..runtime_contracts import canonical_digest


def _prepared_deletion_receipt_original_v1(raw):
    """Decode the exact retained asdict original, not the tagged RPC wire."""
    from .v2_contract import FencePermitV2
    from ..runtime.restore_anchor import RestoreAnchor
    def exact(value, cls):
        if type(value) is not dict or set(value) != {item.name for item in fields(cls)}:
            raise AuthorityUnavailable("C09 retained deletion original fields differ")
        return dict(value)
    receipt = exact(raw, DeletionMutationReceiptV1)
    pending = exact(receipt["pending"], DeletionPendingV1)
    permit = exact(pending["permit"], FencePermitV2)
    permit["pinned_anchor"] = RestoreAnchor(**exact(permit["pinned_anchor"], RestoreAnchor))
    pending["permit"] = FencePermitV2(**permit)
    pending["before_anchor"] = RestoreAnchor(**exact(pending["before_anchor"], RestoreAnchor))
    evidence = exact(pending["evidence"], DeletionEvidenceV1)
    evidence["bound_anchor"] = RestoreAnchor(**exact(evidence["bound_anchor"], RestoreAnchor))
    pending["evidence"] = DeletionEvidenceV1(**evidence)
    pending["closure_roots"] = tuple(pending["closure_roots"])
    receipt["pending"] = DeletionPendingV1(**pending)
    receipt["after_anchor"] = RestoreAnchor(**exact(receipt["after_anchor"], RestoreAnchor))
    value = DeletionMutationReceiptV1(**receipt)
    from ..runtime_contracts import canonical_serialize
    if canonical_serialize(asdict(value)) != canonical_serialize(raw):
        raise AuthorityUnavailable("C09 retained deletion original wire differs")
    return value


class InstalledC09CloseApplyV1:
    def __init__(self, *, control, service, recovery, graph_application, subject, credential):
        if (type(control) is not C09StorageControlV1 or type(service) is not AuthorityV2FenceService
                or type(recovery) is not AuthorityV2DeletionPendingRecovery
                or type(graph_application) is not InstalledC09GraphApplicationV1
                or recovery.core is not service.core or recovery.fences is not service.fences
                or recovery.deletion is not service.deletion or recovery.execution is not service.execution
                or recovery.scoped_store is not graph_application.scoped
                or graph_application.core is not service.core or graph_application.control is not control
                or graph_application.subject != subject):
            raise AuthorityUnavailable("complete installed C09 close/application composition required")
        self.control, self.service, self.recovery = control, service, recovery
        self.graph_application, self.subject, self.credential = graph_application, subject, credential
        self.scoped, self.namespace = graph_application.scoped, service.namespace
        self._lock = threading.RLock()
        self.scoped.install_current_graph_application_v1(graph_application)

    def _id(self, operation_id, phase):
        return "c09-" + phase + "-" + canonical_digest((self.namespace, operation_id))[:48]

    def _closed_original(self, operation_id):
        self.service.core._require(self.credential, "deletion", self.namespace)
        with self.service.deletion.freeze_writes():
            head = self.service.deletion.verified_head()
            with self.service.core._tx() as db:
                row = self.service.fences.mutation_locked(db, self._id(operation_id, "closed-mutation"))
                if row is None:
                    return None
                kind, pending, receipt, permit = self.service.fences._decode_mutation_row(row)
                if (kind != "deletion" or row[1:3] != (self.namespace, self.subject)
                        or type(pending) is not DeletionPendingV1 or pending.target_phase != "closed"
                        or pending.deletion_operation_id != operation_id):
                    raise AuthorityUnavailable("C09 closed original identity differs")
                if receipt is None:
                    return None
                journal = self.service.deletion._db.execute("SELECT append_id,mutation_id,operation_id,phase,chain_digest "
                    "FROM authority_deletion_v2_tail WHERE seq=?", (pending.expected_deletion_seq,)).fetchone()
                if (type(receipt) is not DeletionMutationReceiptV1 or receipt.pending != pending
                        or journal != (pending.expected_append_id, pending.mutation_id, operation_id,
                            "closed", pending.expected_append_digest)
                        or head.seq < pending.expected_deletion_seq
                        or self.service.deletion.expected_digest(pending) != pending.expected_append_digest):
                    raise AuthorityUnavailable("C09 closed append/receipt independent read differs")
                return receipt

    def _cleaned(self, operation_id):
        context = self.control.read_verified_current_storage_v1()
        context.require_current("maintenance")
        if context.stage not in {"CLEANED", "RELEASED"} or context.prepared_original["operation_id"] != operation_id:
            raise AuthorityUnavailable("C09 actual current CLEANED operation required")
        surfaces = self.control.read_surface_evidence_v1(operation_id)
        cleaned = self.control.read_operation_event_v1(operation_id, "CLEANED")
        if ({item["surface"] for item in surfaces} != SURFACES
                or digest([item["evidence_digest"] for item in surfaces]) != cleaned["details"]["surface_receipt_root"]
                or any(item.get("manifest_digest") != context.manifest_digest
                    or item.get("installation_id") != self.control.installation_id
                    or item.get("issuer_id") != self.control.authority_id
                    or "after_observations" not in item for item in surfaces)):
            raise AuthorityUnavailable("C09 actual twelve-surface CLEANED original differs")
        return context, cleaned, surfaces

    def close_verified_cleanup_v1(self, *, operation_id):
        with self._lock:
            context, cleaned, surfaces = self._cleaned(operation_id)
            prior = self._closed_original(operation_id)
            if prior is not None:
                return prior
            if context.stage != "CLEANED":
                raise AuthorityUnavailable("C09 RELEASED lacks actual closed original")
            service = self.service
            mutation_id = self._id(operation_id, "closed-mutation")
            with service._frozen() as (db, deletion_head, execution_head, _):
                saved = service.fences.mutation_locked(db, mutation_id)
                if saved is None:
                    transition = service.core.read_current_deletion_continuation_v1(
                        credential=self.credential, namespace=self.namespace, operation_id=operation_id, db=db)
                    accepted = _prepared_deletion_receipt_original_v1(context.prepared_original["accepted_receipt_original"])
                    original_row = service.fences.mutation_locked(db, accepted.pending.mutation_id)
                    original = None if original_row is None else service.fences._decode_mutation_row(original_row)
                    if (original is None or original[0] != "deletion" or original[2] != accepted
                            or original_row[1:3] != (self.namespace, self.subject)):
                        raise AuthorityUnavailable("C09 detached accepted original differs from Core")
                    fence = service.fences._row(db, accepted.pending.permit.operation_id)
                    permit = None if fence is None else service.fences._permit(fence)
                    current = service._current_locked(db, deletion_head, execution_head,
                        holder=accepted.pending.permit.holder, require_clear=False)
                    if permit is None or permit.pinned_anchor != current:
                        raise AuthorityUnavailable("C09 close continuation permit is not current")
                    service.fences.validate_fence_locked(db, permit, subject=self.subject, current_anchor=current)
                    graph = self.graph_application
                    with graph.store._lock:
                        metadata, epoch = graph.coordinator._v2_graph_stamp(graph.namespace)
                        authority_epoch = graph.store._db.execute("SELECT access_epoch,delete_epoch "
                            "FROM graph_authority_epochs WHERE bot=? AND persona=?", graph.namespace.as_tuple).fetchone()
                        if authority_epoch is None or authority_epoch[1] != accepted.pending.deletion_epoch:
                            raise AuthorityUnavailable("C09 actual Graph authority epochs differ")
                    certificate = context.prepared_original["graph_certificate_original"]
                    if (metadata.graph_revision != certificate["old_revision"]
                            or epoch.revision != certificate["old_graph_epoch"]
                            or authority_epoch[0] != certificate["old_access_epoch"]):
                        raise AuthorityUnavailable("C09 selected Graph changed before original barrier cleanup")
                    scope = deletion_scope_digest(accepted.pending.closure_roots,
                        accepted.pending.deletion_epoch, accepted.pending.policy_ref)
                    proof = canonical_digest({"prepared_digest": context.prepared_original["prepared_digest"],
                        "cleaned_digest": cleaned["event_digest"], "transition_digest": transition["transition_digest"],
                        "surface_receipts": [item["evidence_digest"] for item in surfaces]})
                    evidence = DeletionEvidenceV1(permit.authority_id, self.namespace, operation_id,
                        "cleanup_complete", "authority-installed-c09-cleanup-v1",
                        self._id(operation_id, "closed-evidence"), current, accepted.pending.request_digest,
                        scope, "sha256:" + proof, graph_version="graph-epoch-" + str(epoch.revision),
                        incarnation=metadata.requirements.graph_incarnation,
                        access_epoch=authority_epoch[0], deletion_epoch=accepted.pending.deletion_epoch,
                        barrier_scope_digest="sha256:" + certificate["source_closure_digest"],
                        cleanup_digest="sha256:" + cleaned["details"]["surface_receipt_root"])
                    draft = DeletionPendingV1(permit, mutation_id, accepted.pending.request_digest, operation_id,
                        "accepted", "closed", accepted.pending.closure_roots, accepted.pending.deletion_epoch,
                        accepted.pending.policy_ref, current, evidence, self._id(operation_id, "closed-append"),
                        "sha256:" + "0" * 64)
                    pending = replace(draft, expected_append_digest=service.deletion.expected_digest(draft))
                    service.fences.record_deletion_pending_locked(db, pending, subject=self.subject,
                        current_anchor=current, core=service.core)
                else:
                    kind, pending, receipt, permit = service.fences._decode_mutation_row(saved)
                    if kind != "deletion" or pending.deletion_operation_id != operation_id:
                        raise AuthorityUnavailable("C09 closed mutation replay differs")
            receipt = self.recovery.recover(credential=self.credential, subject=self.subject, mutation_id=mutation_id)
            if receipt is None:
                service.deletion.append_transition(pending, core=service.core, fences=service.fences)
                receipt = self.recovery.recover(credential=self.credential, subject=self.subject, mutation_id=mutation_id)
            independently_read = self._closed_original(operation_id)
            if receipt is None or receipt != independently_read:
                raise AuthorityUnavailable("C09 actual closed receipt remains unresolved")
            return receipt

    def apply_current_graph_head_v1(self, *, operation_id):
        with self._lock:
            closed = self.close_verified_cleanup_v1(operation_id=operation_id)
            ack = self.graph_application.apply_current_graph_head_v1(operation_id=operation_id, closed_receipt=closed)
            self.scoped.apply_verified_head(credential=self.credential, subject=self.subject, operation_id=operation_id)
            self._sync_current_graph_anchor()
            return ack

    def _sync_current_graph_anchor(self):
        graph = self.graph_application
        with self.service.deletion.freeze_writes(), self.service.execution.freeze_writes():
            with self.service.core._tx() as db:
                anchor = self.service.core._anchor(db, self.namespace, self.service.core._row(db, self.namespace))
                with graph.store._lock:
                    business = graph.store._db
                    business.execute("BEGIN IMMEDIATE")
                    try:
                        metadata, _epoch = graph.coordinator._v2_graph_stamp(graph.namespace)
                        target = replace(metadata.requirements, deletion_seq=anchor.deletion_seq,
                            deletion_digest=anchor.deletion_digest, execution_seq=anchor.execution_seq,
                            execution_digest=anchor.execution_digest, revocation_epoch=anchor.revocation_epoch)
                        if target != metadata.requirements:
                            graph.store.cas_graph_recovery_metadata(metadata, target, _capability=graph.capability)
                        business.commit()
                    except BaseException:
                        business.rollback()
                        raise

    def read_release_original_v1(self, *, operation_id, storage_reader):
        with self._lock:
            if storage_reader is not self.control:
                raise AuthorityUnavailable("C09 release reader installation differs")
            context, cleaned, surfaces = self._cleaned(operation_id)
            closed = self._closed_original(operation_id)
            with self.graph_application.read_verified_applied_original_v1(operation_id=operation_id) as (proof, ack):
                with self.service.core._tx() as db:
                    state = self.scoped.state_locked(db)
                    live = self.service.core._row(db, self.namespace)
                    if (closed is None or live[9] != "clear" or state.aggregate_phase != "clear"
                            or state.active_operation_id is not None
                            or (state.applied_seq, state.applied_digest, state.applied_epoch)
                                != (proof.deletion_seq, proof.deletion_digest, proof.deletion_epoch)
                            or canonical_digest(closed) != ack["closed_digest"]):
                        raise AuthorityUnavailable("C09 actual closed/scoped applied state differs")
            return self.control.sign_original_v1("sylanne3.c09.storage-release-original.v1", {
                "schema": "sylanne3.c09.storage-release-original.v1", "operation_id": operation_id,
                "installation_id": self.control.installation_id, "manifest_digest": context.manifest_digest,
                "storage_generation": context.storage_generation, "state": "applied",
                "closed_digest": canonical_digest(closed), "graph_ack_digest": ack["ack_digest"],
                "applied_seq": proof.deletion_seq, "applied_digest": proof.deletion_digest,
                "applied_epoch": proof.deletion_epoch, "cleaned_digest": cleaned["event_digest"]}, "release_digest")

    def read_storage_applied_original_v1(self, *, context):
        if context._reader is not self.control or context.stage != "RELEASED":
            raise AuthorityUnavailable("C09 business requires current RELEASED context")
        # This guard also runs inside Core transactions. Read immutable Graph
        # originals through a separate WAL snapshot and never reacquire journals.
        operation_id = context.prepared_original["operation_id"]
        event = self.control.read_operation_event_v1(operation_id, "RELEASED")
        release = event["details"]["release_original"]
        self.control.verify_original_v1(release, "release_digest")
        if release["manifest_digest"] != context.manifest_digest or release["state"] != "applied":
            raise AuthorityUnavailable("C09 signed current release differs")
        member = next(m for m in context.manifest["members"] if m["role"] == "graph")
        with closing(sqlite3.connect(Path(member["resolved_path"]).as_uri() + "?mode=ro", uri=True)) as db:
            db.execute("BEGIN")
            certificate = self.graph_application._certificate_locked(db, context, operation_id)
            ack = self.graph_application._read_ack_locked(db, operation_id)
            row = db.execute("SELECT requirements_json,graph_revision FROM graph_recovery_metadata_v2 "
                "WHERE bot=? AND persona=?", self.graph_application.namespace.as_tuple).fetchone()
            if (ack is None or ack["ack_digest"] != release["graph_ack_digest"] or row is None
                    or row[1] < ack["graph_revision"]
                    or json.loads(row[0])["graph_incarnation"] != certificate.new_incarnation):
                raise AuthorityUnavailable("C09 current cold Graph application differs")
        with self.service.core._lock:
            db = self.service.core._db
            if db is None:
                raise AuthorityUnavailable("C09 current Core unavailable")
            # Reuse only the actual caller-owned transaction. An ordinary
            # outside-SQL admission must take its own real Core snapshot.
            manager = nullcontext(db) if db.in_transaction else self.service.core._tx()
            with manager as locked:
                state = self.scoped.state_locked(locked)
                live = self.service.core._row(locked, self.namespace)
                saved = self.service.fences.mutation_locked(locked, self._id(operation_id, "closed-mutation"))
                stored = None if saved is None else self.service.fences._decode_mutation_row(saved)
                if (live[9] != "clear" or state.aggregate_phase != "clear" or state.active_operation_id is not None
                        or (state.applied_seq, state.applied_digest, state.applied_epoch)
                            != (release["applied_seq"], release["applied_digest"], release["applied_epoch"])
                        or stored is None or stored[2] is None
                        or saved[1:3] != (self.namespace, self.subject)
                        or canonical_digest(stored[2]) != release["closed_digest"]):
                    raise AuthorityUnavailable("C09 current Core closed/applied originals differ")
        return release
