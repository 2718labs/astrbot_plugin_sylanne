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

    def _closed_original(self, operation_id, *, selected_proof=None, meter=None):
        self.service.core._require(self.credential, "deletion", self.namespace)
        with self.service.deletion.freeze_writes():
            if selected_proof is None:
                head = self.service.deletion.verified_head()
            else:
                head = selected_proof.deletion_head_locked(self.service.deletion,meter=meter)
            with self.service.core._tx() as db:
                if selected_proof is not None:
                    from .c09_selected_history_v3 import _bounded
                    db = _bounded(db,meter)
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
                journal_db = self.service.deletion._db
                if selected_proof is not None:
                    journal_db = _bounded(journal_db,meter)
                journal = journal_db.execute("SELECT append_id,mutation_id,operation_id,phase,chain_digest "
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

    def _selected_close_originals_v3(self, db, context, transition):
        from .erasure_closure_inventory import CleanupRunV2, _TABLES
        from .c09_graph_rebase_issue_v2 import _read_issue, _verify_signature, _wire
        from .c09_selected_history_v3 import _bounded
        from .c09_prepared_storage_v3 import _read_original
        from ..runtime.c09_paged_sql_v2 import current_c09_sql_meter_v2
        meter = current_c09_sql_meter_v2()
        maintenance = self._maintenance_v3
        bounded = _bounded(db, meter)
        run = maintenance.closure._read_record(bounded, _TABLES[1], context.prepared_original['operation_id'], CleanupRunV2)
        if run is None or run.namespace != self.namespace:
            raise AuthorityUnavailable('actual selected accepted cleanup run absent')
        # Preread the exact immutable mutation through the decoder reservation;
        # the existing bridge verifier then sees its real caller-owned Core db.
        self.service.fences.mutation_locked(bounded, run.accepted_mutation_id)
        accepted = maintenance.closure._accepted_locked(db, run, self.subject)
        if (canonical_digest(accepted) != context.prepared_original['accepted_receipt_digest']
                or transition['accepted_receipt_digest'] != context.prepared_original['accepted_receipt_digest']
                or run.graph_barrier_receipt_digest != context.prepared_original['barrier_receipt_digest']
                or accepted.pending.evidence.barrier_scope_digest is None
                or accepted.pending.evidence.barrier_scope_digest.removeprefix('sha256:') != run.barrier_scope_digest):
            raise AuthorityUnavailable('actual selected accepted receipt, barrier or continuation differs')
        issued = _read_issue(bounded, self.namespace, run.operation_id)
        if issued is None:
            raise AuthorityUnavailable('actual selected signed Core Graph issue absent')
        _verify_signature(issued, self.control._key)
        with self.control._db() as control_db:
            original = _read_original(self.control, control_db, run.operation_id, 'graph_issued_v2',
                context.prepared_original['graph_issue_original_digest'], meter)
        if (original != _wire(issued) or issued.issue_digest != context.manifest['graph_issue_digest']
                or issued.certificate.certificate_digest != context.manifest['certificate_digest']):
            raise AuthorityUnavailable('actual selected Core issue differs from signed Control PREPARED')
        return accepted, issued.certificate.candidate

    def close_verified_cleanup_v1(self, *, operation_id, selected_proof=None, meter=None):
        with self._lock:
            context, cleaned, surfaces = self._cleaned(operation_id)
            if context.manifest['schema'] == 'sylanne3.c09.storage_manifest.v3' and selected_proof is None:
                raise AuthorityUnavailable('actual V3 close requires its complete selected journal producer')
            prior = self._closed_original(operation_id,selected_proof=selected_proof,meter=meter)
            if prior is not None:
                return prior
            if context.stage != "CLEANED":
                raise AuthorityUnavailable("C09 RELEASED lacks actual closed original")
            service = self.service
            mutation_id = self._id(operation_id, "closed-mutation")
            with service._frozen(selected_proof=selected_proof) as (db, deletion_head, execution_head, _):
                saved = service.fences.mutation_locked(db, mutation_id)
                if saved is None:
                    transition = service.core.read_current_deletion_continuation_v1(
                        credential=self.credential, namespace=self.namespace, operation_id=operation_id, db=db)
                    v3 = context.manifest['schema'] == 'sylanne3.c09.storage_manifest.v3'
                    if v3:
                        accepted, selected_candidate = self._selected_close_originals_v3(db, context, transition)
                    else:
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
                        from .c09_graph_application_v1 import c09_actual_root_read_v3
                        authority_epoch = c09_actual_root_read_v3(graph.store._db).execute("SELECT access_epoch,delete_epoch "
                            "FROM graph_authority_epochs WHERE bot=? AND persona=?", graph.namespace.as_tuple).fetchone()
                        if authority_epoch is None or authority_epoch[1] != accepted.pending.deletion_epoch:
                            raise AuthorityUnavailable("C09 actual Graph authority epochs differ")
                    if v3:
                        if (metadata.graph_revision != selected_candidate.old_revision
                                or metadata.requirements.graph_incarnation != selected_candidate.new_incarnation
                                or epoch.revision != selected_candidate.new_graph_epoch
                                or authority_epoch != (selected_candidate.new_access_epoch, selected_candidate.new_delete_epoch)):
                            raise AuthorityUnavailable('actual selected Graph differs from the signed candidate before cleanup closure')
                        barrier_scope = accepted.pending.evidence.barrier_scope_digest
                    else:
                        certificate = context.prepared_original["graph_certificate_original"]
                        if (metadata.graph_revision != certificate["old_revision"]
                                or epoch.revision != certificate["old_graph_epoch"]
                                or authority_epoch[0] != certificate["old_access_epoch"]):
                            raise AuthorityUnavailable("C09 selected Graph changed before original barrier cleanup")
                        barrier_scope = "sha256:" + certificate["source_closure_digest"]
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
                        barrier_scope_digest=barrier_scope,
                        cleanup_digest="sha256:" + cleaned["details"]["surface_receipt_root"])
                    draft = DeletionPendingV1(permit, mutation_id, accepted.pending.request_digest, operation_id,
                        "accepted", "closed", accepted.pending.closure_roots, accepted.pending.deletion_epoch,
                        accepted.pending.policy_ref, current, evidence, self._id(operation_id, "closed-append"),
                        "sha256:" + "0" * 64)
                    pending = replace(draft, expected_append_digest=service.deletion.expected_digest(draft))
                    service.fences.record_deletion_pending_locked(db, pending, subject=self.subject,
                        current_anchor=current, core=service.core,selected_proof=selected_proof)
                else:
                    kind, pending, receipt, permit = service.fences._decode_mutation_row(saved)
                    if kind != "deletion" or pending.deletion_operation_id != operation_id:
                        raise AuthorityUnavailable("C09 closed mutation replay differs")
            receipt = self.recovery.recover(credential=self.credential, subject=self.subject, mutation_id=mutation_id,selected_proof=selected_proof)
            if receipt is None:
                service.deletion.append_transition(pending, core=service.core, fences=service.fences,selected_proof=selected_proof)
                receipt = self.recovery.recover(credential=self.credential, subject=self.subject, mutation_id=mutation_id,selected_proof=selected_proof)
            independently_read = self._closed_original(operation_id,selected_proof=selected_proof,meter=meter)
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

    def advance_selected_close_v3(self, *, operation_id, view, meter):
        from .c09_graph_application_v1 import advance_selected_journal_proof_v3, SelectedC09JournalProofV3
        if view.scope.operation_id != operation_id or view.basis.control is not self.control:
            raise AuthorityUnavailable('actual selected cleanup operation differs')
        result = advance_selected_journal_proof_v3(self.graph_application,view=view,meter=meter)
        if type(result) is not SelectedC09JournalProofV3:
            return result
        closed = self.close_verified_cleanup_v1(operation_id=operation_id,selected_proof=result,meter=meter)
        self._selected_closed_receipt_v3 = closed
        return dict(status='complete',phase='actual_closed',original=closed)

    def advance_selected_graph_application_v3(self, *, operation_id, view, meter):
        from .c09_graph_application_v1 import advance_selected_graph_application_v2
        from .c09_graph_application_v1 import SelectedC09JournalProofV3, _selected_meter_v3
        _selected_meter_v3(meter)
        journal_proof = getattr(self.graph_application,'_selected_journal_proof_v3',None)
        if type(journal_proof) is not SelectedC09JournalProofV3 or journal_proof.view is not view:
            raise AuthorityUnavailable('actual complete selected close journal proof required before application')
        phase = getattr(self, '_selected_apply_phase_v3', 'graph')
        if phase == 'graph':
            closed = getattr(self, '_selected_closed_receipt_v3', None)
            if closed is None:
                closed = self._closed_original(operation_id,selected_proof=journal_proof,meter=meter)
                if closed is None:
                    raise AuthorityUnavailable('actual selected closed receipt absent before Graph application')
                self._selected_closed_receipt_v3 = closed
            progress = advance_selected_graph_application_v2(self.graph_application, view=view, closed_receipt=closed, meter=meter)
            if progress['status'] == 'complete':
                self._selected_graph_ack_v3 = progress['original']
                self._selected_apply_phase_v3 = 'scoped'
            return dict(progress, status='progress')
        if phase == 'scoped':
            from .c09_graph_application_v1 import SelectedC09GraphApplicationReadV3
            proof = getattr(self.graph_application,'_selected_graph_application_read_v3',None)
            if type(proof) is not SelectedC09GraphApplicationReadV3 or proof.view is not view:
                raise AuthorityUnavailable('actual complete selected Graph ACK proof required for scoped application')
            self.service.core._require(self.credential,'deletion',self.namespace)
            with self.service.deletion.freeze_writes(), self.service.execution.freeze_writes():
                with self.service.core._tx() as db:
                    head, execution = journal_proof.require_current_locked(deletion=self.service.deletion,
                        execution=self.service.execution,core=self.service.core,db=db,meter=meter)
                    receipt, ack = proof.require_current_locked(db=db,meter=meter)
                    state = self.scoped.state_locked(db)
                    if (state.applied_seq,state.applied_digest,state.applied_epoch) == (receipt.deletion_seq,receipt.deletion_digest,receipt.deletion_epoch):
                        if state.aggregate_phase != 'clear' or state.active_operation_id is not None:
                            raise AuthorityUnavailable('actual recovered selected applied watermark is not clear')
                    else:
                        self.scoped._apply_verified_head_locked_v1(db,head,execution,self.subject,receipt,selected_proof=journal_proof)
            self._selected_apply_phase_v3 = 'anchor'
            return dict(status='progress', phase='actual_scoped_applied')
        if phase == 'anchor':
            self._sync_current_graph_anchor()
            self._selected_apply_phase_v3 = 'complete'
            return dict(status='progress', phase='actual_graph_anchor')
        view.require_current(meter=meter)
        return dict(status='complete', phase='actual_applied', original=self._selected_graph_ack_v3)

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
            selected = getattr(self.graph_application,'_selected_journal_proof_v3',None)
            if selected is None:
                closed = self._closed_original(operation_id)
            else:
                from ..runtime.c09_paged_sql_v2 import current_c09_sql_meter_v2
                closed = self._closed_original(operation_id,selected_proof=selected,meter=current_c09_sql_meter_v2())
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
        if context.manifest['schema'] == 'sylanne3.c09.storage_manifest.v3':
            from ..runtime.c09_paged_sql_v2 import current_c09_sql_meter_v2
            view = self.control._selected_history_read_v3
            if view.basis.manifest['manifest_digest'] != context.manifest_digest:
                raise AuthorityUnavailable('actual complete selected applied read has another current manifest')
            return read_selected_storage_applied_original_v3(self.control,view=view,meter=current_c09_sql_meter_v2())
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



_SELECTED_APPLIED_V3 = object()


def _selected_applied_mutable_state_v3(view, release, ack, *, meter):
    from .c09_selected_history_v3 import _read_one, _bounded
    namespace = view.basis.prepared['namespace']
    with view.basis.read_database('core', meter=meter) as core:
        state = _read_one(core, 'SELECT active_operation_id,aggregate_phase,applied_seq,applied_digest,applied_epoch '
            'FROM authority_scoped_erasure_v2 WHERE namespace=?', (namespace,), meter)
        live = _read_one(core, 'SELECT deletion_phase,deletion_journal_id,deletion_seq,deletion_digest,execution_journal_id '
            'FROM authority_namespaces WHERE namespace=?', (namespace,), meter)
    if (state != (None, 'clear', release['applied_seq'], release['applied_digest'], release['applied_epoch'])
            or live is None or live[0] != 'clear' or live[2] < release['applied_seq']):
        raise AuthorityUnavailable('actual selected scoped applied state or Core applied prefix differs')
    with view.basis.read_database('graph', meter=meter) as graph:
        metadata = _bounded(graph, meter).execute('SELECT requirements_json,graph_revision FROM graph_recovery_metadata_v2 '
            'WHERE bot=? AND persona=?', tuple(json.loads(view.scope.graph_namespace))).fetchone()
    requirements = None if metadata is None else json.loads(metadata[0])
    if (metadata is None or metadata[1] < ack['graph_revision']
            or requirements['graph_incarnation'] != ack['new_incarnation']
            or requirements['deletion_journal_id'] != live[1] or requirements['execution_journal_id'] != live[4]
            or requirements['deletion_seq'] < release['applied_seq']
            or requirements['deletion_seq'] == release['applied_seq'] and requirements['deletion_digest'] != release['applied_digest']):
        raise AuthorityUnavailable('actual selected Graph applied prefix or current journal identity differs')


class SelectedAppliedReadV3:
    """Private RELEASE/closed/ACK qualification, independent of business composition."""
    def __init__(self, token, reader):
        if token is not _SELECTED_APPLIED_V3 or reader.phase != 'complete':
            raise AuthorityUnavailable('actual complete selected applied proof required')
        self._issuer, self.view, self.release, self.ack = token, reader.view, reader.release, reader.ack

    def require_current(self, *, meter):
        if self._issuer is not _SELECTED_APPLIED_V3:
            raise AuthorityUnavailable('actual selected applied issuer differs')
        current = self.view.basis.require_current(meter=meter)
        if current['stage'] != 'RELEASED':
            raise AuthorityUnavailable('actual selected applied proof has no business admission')
        _selected_applied_mutable_state_v3(self.view, self.release, self.ack, meter=meter)
        self.view.require_current(meter=meter)
        return self


class InstalledSelectedAppliedReadV3:
    def __init__(self, control, view):
        from .c09_selected_history_v3 import VerifiedSelectedHistoryReadV3
        if type(view) is not VerifiedSelectedHistoryReadV3 or view.basis.control is not control:
            raise AuthorityUnavailable('actual full private selected history required for applied qualification')
        self.control, self.view, self.phase = control, view, 'release'
        self.release = self.issue = self.ack = self.result = self.closed = None
        self.suffix_seq = self.suffix_root = None
        self.suffix_count = 0
        self.failed = None

    def advance(self, *, meter):
        if self.failed is not None:
            raise AuthorityUnavailable(self.failed)
        try:
            from .c09_graph_application_v1 import _selected_meter_v3
            return self._advance(_selected_meter_v3(meter))
        except BaseException as exc:
            self.failed = str(exc)
            raise

    def _advance(self, meter):
        from .c09_selected_history_v3 import _bounded, _read_one
        from .v2_fence_store import AuthorityV2FenceStore
        from .v2_scoped_erasure_store import _DDL as SCOPED_DDL
        from .c09_graph_rebase_issue_v2 import _read_issue, _verify_signature
        view, control = self.view, self.control
        current = view.basis.require_current(meter=meter)
        if current['stage'] != 'RELEASED':
            raise AuthorityUnavailable('actual applied bootstrap requires selected RELEASED')
        namespace, operation_id = view.basis.prepared['namespace'], view.basis.prepared['operation_id']
        if self.result is not None:
            return self.result.require_current(meter=meter)
        if self.phase == 'release':
            with control._db() as db:
                row = _bounded(db, meter).execute("SELECT event_json FROM c09_storage_events_v1 WHERE operation_id=? AND stage='RELEASED'", (operation_id,)).fetchone()
            if row is None:
                raise AuthorityUnavailable('actual selected signed release event absent')
            event = json.loads(row[0]);control.verify_original_v1(event, 'event_digest')
            release = event['details']['release_original'];control.verify_original_v1(release, 'release_digest')
            if (release['operation_id'] != operation_id or release['manifest_digest'] != view.basis.manifest['manifest_digest']
                    or release['storage_generation'] != view.basis.manifest['generation'] or release['state'] != 'applied'
                    or release['installation_id'] != control.installation_id):
                raise AuthorityUnavailable('actual selected release scope differs')
            self.release, self.phase = release, 'issue'
        elif self.phase == 'issue':
            with view.basis.read_database('core', meter=meter) as core:
                issue = _read_issue(_bounded(core, meter), namespace, operation_id)
            if issue is None:
                raise AuthorityUnavailable('actual selected Core signed Graph issue absent')
            _verify_signature(issue, control._key)
            if issue.issue_digest != view.basis.manifest['graph_issue_digest'] or issue.certificate.certificate_digest != view.basis.manifest['certificate_digest']:
                raise AuthorityUnavailable('actual selected Core issue differs from signed manifest')
            self.issue, self.phase = issue, 'closed'
        elif self.phase == 'closed':
            with view.basis.read_database('core', meter=meter) as core:
                if _read_one(core, "SELECT sql FROM sqlite_master WHERE type='table' AND name='authority_scoped_erasure_v2'", (), meter) != (SCOPED_DDL,):
                    raise AuthorityUnavailable('actual selected scoped erasure schema differs')
                mutation = 'c09-closed-mutation-' + canonical_digest((namespace, operation_id))[:48]
                saved = AuthorityV2FenceStore.mutation_locked(_bounded(core, meter), mutation)
                stored = None if saved is None else AuthorityV2FenceStore._decode_mutation_row(saved)
                if (stored is None or stored[0] != 'deletion' or stored[2] is None
                        or saved[1:3] != (namespace, stored[1].permit.subject)
                        or stored[1].deletion_operation_id != operation_id or stored[1].target_phase != 'closed'
                        or canonical_digest(stored[2]) != self.release['closed_digest']):
                    raise AuthorityUnavailable('actual selected Core closed original differs from signed release')
            self.closed = stored[2]
            with view.basis.read_database('deletion',meter=meter) as deletion:
                pending = self.closed.pending
                journal = _bounded(deletion,meter).execute('SELECT append_id,mutation_id,operation_id,phase,chain_digest '
                    'FROM authority_deletion_v2_tail WHERE seq=?',(pending.expected_deletion_seq,)).fetchone()
            from .v2_deletion_guard import AuthorityV2DeletionGuard
            if (journal != (pending.expected_append_id,pending.mutation_id,operation_id,'closed',pending.expected_append_digest)
                    or AuthorityV2DeletionGuard.expected_digest(pending) != pending.expected_append_digest
                    or (self.closed.after_anchor.deletion_seq,self.closed.after_anchor.deletion_digest) !=
                        (self.release['applied_seq'],self.release['applied_digest'])):
                raise AuthorityUnavailable('actual selected closed journal append differs from release')
            self.phase = 'ack'
        elif self.phase == 'ack':
            graph_namespace = tuple(json.loads(view.scope.graph_namespace))
            with view.basis.read_database('graph', meter=meter) as graph:
                row = _bounded(graph, meter).execute('SELECT original_json,original_digest FROM graph_c09_cumulative_applications_v1 '
                    'WHERE bot=? AND persona=? AND operation_id=?', (*graph_namespace, operation_id)).fetchone()
            if row is None:
                raise AuthorityUnavailable('actual selected cumulative Graph ACK absent')
            ack = json.loads(row[0])
            if (ack['ack_digest'] != row[1] or canonical_digest({key: value for key, value in ack.items() if key != 'ack_digest'}) != row[1]
                    or row[1] != self.release['graph_ack_digest'] or ack['manifest_digest'] != view.basis.manifest['manifest_digest']
                    or ack['namespace'] != list(graph_namespace) or ack['operation_id'] != operation_id
                    or ack['storage_generation'] != view.basis.manifest['generation']
                    or ack['cumulative_tombstone_root'] != view.basis.manifest['cumulative_tombstone_root']
                    or ack['certificate_digest'] != self.issue.certificate.certificate_digest
                    or ack['closed_digest'] != self.release['closed_digest']
                    or ack['new_incarnation'] != self.issue.certificate.candidate.new_incarnation
                    or (ack['deletion_seq'], ack['deletion_digest'], ack['deletion_epoch']) !=
                        (self.release['applied_seq'], self.release['applied_digest'], self.release['applied_epoch'])):
                raise AuthorityUnavailable('actual selected signed release does not bind the retained Graph ACK')
            if (ack['schema'] != 'sylanne3.c09.cumulative-graph-ack.v2'
                    or ack['suffix_algorithm'] != 'sylanne3.c09.applied-deletion-suffix.v2'
                    or ack['selection_digest'] != view.basis.selection_digest
                    or ack['selected_history_root'] != view.history_root or ack['selected_history_count'] != view.history_count
                    or type(ack['prior_applied_seq']) is not int or not 0 <= ack['prior_applied_seq'] < ack['deletion_seq']):
                raise AuthorityUnavailable('actual selected release ACK lineage domain differs')
            self.suffix_seq = ack['prior_applied_seq']
            self.suffix_root = canonical_digest(('sylanne3.c09.applied-deletion-suffix.v2',view.basis.selection_digest))
            self.ack,self.phase = ack,'suffix'
        elif self.phase == 'suffix':
            from .contract import JournalHead
            with view.basis.read_database('deletion',meter=meter) as deletion:
                row = _read_one(deletion,'SELECT seq,operation_id,phase,chain_digest FROM authority_deletion_v2_tail '
                    'WHERE seq>? AND seq<=? ORDER BY seq LIMIT 1',(self.suffix_seq,self.ack['deletion_seq']),meter)
            if row is None:
                head = JournalHead(self.closed.after_anchor.deletion_journal_id,self.ack['deletion_seq'],self.ack['deletion_digest'])
                if (self.suffix_seq != head.seq or not self.suffix_count or self.suffix_count != self.ack['suffix_count']
                        or self.suffix_root != self.ack['suffix_root']
                        or canonical_digest((self.suffix_seq,head,self.suffix_root)) != self.ack['suffix_eof_digest']):
                    raise AuthorityUnavailable('actual selected release ACK suffix count, root or EOF differs')
                self.phase = 'effect'
            else:
                if row[0] != self.suffix_seq + 1 or row[0] == self.ack['deletion_seq'] and row[1:] != (operation_id,'closed',self.ack['deletion_digest']):
                    raise AuthorityUnavailable('actual selected release ACK suffix has a gap or differs at closed EOF')
                self.suffix_seq = row[0]
                self.suffix_count += 1
                self.suffix_root = canonical_digest((self.suffix_root,self.suffix_count,row))
        elif self.phase == 'effect':
            from .c09_graph_application_v1 import _read_selected_graph_ack_event_v3
            from ..runtime_contracts import NamespaceId
            namespace = NamespaceId(*tuple(json.loads(view.scope.graph_namespace)))
            with view.basis.read_database('graph',meter=meter) as graph:
                _read_selected_graph_ack_event_v3(graph,namespace,self.ack,meter=meter)
            self.phase = 'mutable'
        elif self.phase == 'mutable':
            _selected_applied_mutable_state_v3(view, self.release, self.ack, meter=meter)
            self.phase = 'complete'
            self.result = SelectedAppliedReadV3(_SELECTED_APPLIED_V3, self)
            return self.result
        else:
            raise AuthorityUnavailable('actual selected applied private phase differs')
        return dict(status='progress', phase='selected_applied_' + self.phase)


def advance_selected_storage_applied_read_v3(control, *, view, meter):
    reader = getattr(control, '_selected_applied_reader_v3', None)
    if reader is None:
        reader = InstalledSelectedAppliedReadV3(control, view)
        control._selected_applied_reader_v3 = reader
    elif reader.view is not view:
        raise AuthorityUnavailable('actual selected applied reader has another selected basis')
    result = reader.advance(meter=meter)
    if type(result) is SelectedAppliedReadV3:
        control._selected_applied_read_v3 = result
    return result


def read_selected_storage_applied_original_v3(control, *, view, meter):
    proof = getattr(control, '_selected_applied_read_v3', None)
    if type(proof) is not SelectedAppliedReadV3 or proof.view is not view:
        raise AuthorityUnavailable('actual selected applied bootstrap proof is not complete')
    proof.require_current(meter=meter)
    return proof.release
