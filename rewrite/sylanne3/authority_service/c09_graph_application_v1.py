"""Installed cumulative Graph application and independent C09 ACK reader."""
from __future__ import annotations

from contextlib import closing, contextmanager
from dataclasses import asdict, replace
import json
import sqlite3
from pathlib import Path
import time

from .contract import AuthorityUnavailable
from .v2_scoped_erasure_store import VerifiedGraphAppliedHeadV2
from ..contracts import Event, Scope, canonical_json
from ..graph_store import GraphStore, ProductionGraphStore
from ..graph_types import GraphCandidate
from ..runtime_contracts import canonical_digest
from ..runtime.c09_graph_originals_read_v4 import read_graph_rebase_certificate_v1

_GRAPH_APPLICATION_PROGRESS_V2 = object()
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
        if context.manifest['schema']=='sylanne3.c09.storage_manifest.v2':
            from .c09_graph_rebase_issue_v2 import _read_issue,_verify_signature
            from .c09_paged_recovery_facts_v2 import _BoundedReadConnectionV2
            from ..runtime.c09_paged_sql_v2 import peek_current_c09_sql_meter_v3,require_c09_reserved_meter_v3
            from ..runtime.c09_paged_capture_contract_v2 import (
                GraphErasureRebaseCertificateV2,c09_paged_value_from_wire_v2,c09_paged_value_to_wire_v2)
            from ..runtime_contracts import canonical_serialize
            from contextlib import nullcontext
            active=peek_current_c09_sql_meter_v3()
            manager=self.control.reserve_control_read_v3()if active is None else nullcontext(active.budget)
            with manager as budget:
                meter=require_c09_reserved_meter_v3(budget)
                # Immutable issue reads use the actual selected Core member independently
                # of caller-owned Core/Graph transactions; no V3 basis or lock inversion.
                core_member=next(item for item in context.manifest['members']if item['role']=='core')
                self.control.verify_member_v1(core_member,prepared=False)
                with closing(sqlite3.connect(Path(core_member['resolved_path']).as_uri()+'?mode=ro',
                        uri=True,isolation_level=None))as source:
                    source.execute('PRAGMA query_only=ON');source.execute('BEGIN')
                    try:issue=_read_issue(_BoundedReadConnectionV2(source,meter),self.scoped.namespace,operation_id)
                    finally:source.rollback()
                self.control.verify_member_v1(core_member,prepared=False)
                if issue is None:raise AuthorityUnavailable('actual current V2 Core signed Graph issue absent')
                _verify_signature(issue,self.control._key)
                row=meter.read_fixed_row(db,'graph_c09_rebase_certificates_v2',
                    ('certificate_json','issue_digest'),'bot=? AND persona=? AND operation_id=?',
                    (*self.namespace.as_tuple,operation_id))
                if row is None:raise AuthorityUnavailable('actual current V2 Graph certificate mirror absent')
                certificate=c09_paged_value_from_wire_v2(json.loads(row[0]),GraphErasureRebaseCertificateV2)
                candidate=certificate.candidate;scope=candidate.scope
                if (issue.certificate!=certificate or row[1]!=issue.issue_digest
                        or canonical_serialize(c09_paged_value_to_wire_v2(certificate))!=row[0]
                        or (scope.authority_id,scope.installation_id,scope.authority_namespace,
                            scope.operation_id,scope.maintenance_generation)!=
                           (self.control.authority_id,self.control.installation_id,self.scoped.namespace,
                            operation_id,context.storage_generation)
                        or scope.graph_namespace!=json.dumps(list(self.namespace.as_tuple),separators=(',',':'))
                        or scope.old_manifest_digest!=context.manifest['prior_manifest_digest']
                        or certificate.certificate_digest!=context.manifest['certificate_digest']
                        or issue.issue_digest!=context.manifest['graph_issue_digest']
                        or certificate.facts_pin_digest!=context.manifest['recovery_pin_digest']
                        or candidate.new_incarnation!=member['incarnation_or_journal_id']
                        or canonical_digest(candidate.tombstones)!=context.manifest['cumulative_tombstone_root']):
                    raise AuthorityUnavailable('actual current V2 Core issue/Graph mirror/manifest original differs')
                return certificate
        if context.manifest['schema'] == 'sylanne3.c09.storage_manifest.v3':
            from .c09_selected_history_v3 import _bounded
            from .c09_graph_rebase_issue_v2 import _read_issue, _verify_signature
            from ..runtime.c09_paged_sql_v2 import current_c09_sql_meter_v2
            meter = current_c09_sql_meter_v2()
            view = self.control._selected_history_read_v3
            view.require_current(meter=meter)
            with view.basis.read_database('core', meter=meter) as core:
                issue = _read_issue(_bounded(core, meter), self.scoped.namespace, operation_id)
            if issue is None:
                raise AuthorityUnavailable('actual selected Core Graph application issue absent')
            _verify_signature(issue, self.control._key)
            certificate = issue.certificate
            if (certificate.certificate_digest != context.manifest['certificate_digest']
                    or certificate.candidate.new_incarnation != member['incarnation_or_journal_id']
                    or canonical_digest(certificate.candidate.tombstones) != context.manifest['cumulative_tombstone_root']):
                raise AuthorityUnavailable('actual current selected paged Graph certificate differs')
            return certificate
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
        if context.manifest['schema'] == 'sylanne3.c09.storage_manifest.v3':
            raise AuthorityUnavailable('actual V3 Graph application requires its progressive selected consumer')
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
                        from ..runtime.c09_paged_capture_contract_v2 import GraphErasureRebaseCertificateV2
                        if type(certificate)is GraphErasureRebaseCertificateV2:
                            new_incarnation=certificate.candidate.new_incarnation
                            tombstone_root=canonical_digest(certificate.candidate.tombstones)
                        else:
                            new_incarnation=certificate.new_incarnation;tombstone_root=certificate.tombstone_root
                        prior = self._read_ack_locked(db, operation_id)
                        if prior is not None:
                            db.rollback()
                            return prior
                        metadata, epoch = self.coordinator._v2_graph_stamp(self.namespace)
                        if metadata.requirements.graph_incarnation != new_incarnation:
                            raise AuthorityUnavailable("C09 current Graph incarnation differs")
                        tail = tuple(self.scoped.deletion._db.execute(
                            "SELECT seq,operation_id,phase,chain_digest FROM authority_deletion_v2_tail "
                            "WHERE seq>? AND seq<=? ORDER BY seq", (state.applied_seq, deletion.seq)))
                        if not tail or tail[-1] != (deletion.seq, operation_id, "closed", deletion.digest):
                            raise AuthorityUnavailable("C09 cumulative deletion suffix differs")
                        certificate_operations = {row[0] for row in db.execute(
                            "SELECT operation_id FROM graph_c09_rebase_certificates_v1 WHERE bot=? AND persona=?",
                            self.namespace.as_tuple)}
                        present_v2=db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='graph_c09_rebase_certificates_v2'").fetchone()
                        if present_v2 is not None:
                            certificate_operations.update(row[0]for row in db.execute(
                                'SELECT operation_id FROM graph_c09_rebase_certificates_v2 WHERE bot=? AND persona=?',
                                self.namespace.as_tuple))
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
                                "cumulative_tombstone_root": tombstone_root,
                                "new_incarnation": new_incarnation, "deletion_seq": deletion.seq,
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

    def _read_selected_ack_effect_locked(self, db, ack, *, meter):
        from .c09_selected_history_v3 import _bounded
        self._selected_journal_proof_v3._require_connection(db,'graph',meter)
        bounded = _bounded(db,meter)
        receipt = _read_selected_graph_ack_event_v3(db,self.namespace,ack,meter=meter)
        metadata = bounded.execute('SELECT requirements_json,graph_revision FROM graph_recovery_metadata_v2 '
            'WHERE bot=? AND persona=?',self.namespace.as_tuple).fetchone()
        requirements = None if metadata is None else json.loads(metadata[0])
        if (canonical_digest(receipt) != ack['graph_receipt_digest'] or metadata is None or metadata[1] < ack['graph_revision']
                or requirements['graph_incarnation'] != ack['new_incarnation']
                or (requirements['deletion_seq'],requirements['deletion_digest']) != (ack['deletion_seq'],ack['deletion_digest'])):
            raise AuthorityUnavailable('actual Graph effect receipt or recovery metadata differs from ACK')
        return receipt

    @contextmanager
    def read_verified_applied_original_v1(self, *, operation_id):
        context = self.control.read_verified_current_storage_v1()
        context.require_current("maintenance")
        if context.manifest['schema'] == 'sylanne3.c09.storage_manifest.v3':
            from ..runtime.c09_paged_sql_v2 import current_c09_sql_meter_v2
            proof = getattr(self,'_selected_graph_application_read_v3',None)
            if type(proof) is not SelectedC09GraphApplicationReadV3 or proof.view.scope.operation_id != operation_id:
                raise AuthorityUnavailable('actual complete selected Graph application proof required')
            with self.core._lock:
                original, ack = proof.require_current_locked(db=self.core._db,meter=current_c09_sql_meter_v2())
            yield original, ack
            proof.view.require_current(meter=current_c09_sql_meter_v2())
            return
        with self.store._lock:
            db = self.store._db
            db.execute("BEGIN")
            try:
                certificate = self._certificate_locked(db, context, operation_id)
                ack = self._read_ack_locked(db, operation_id)
                metadata, _epoch = self.coordinator._v2_graph_stamp(self.namespace)
                tombstone_root = (context.manifest['cumulative_tombstone_root'] if context.manifest['schema'] == 'sylanne3.c09.storage_manifest.v3' else certificate.tombstone_root)
                if (ack is None or ack["manifest_digest"] != context.manifest_digest
                        or ack["certificate_digest"] != certificate.certificate_digest
                        or ack["cumulative_tombstone_root"] != tombstone_root
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


    def _commit_selected_graph_application_v2(self, progress, *, meter):
        from .c09_selected_history_v3 import _bounded
        if type(progress) is not InstalledC09GraphApplicationProgressV2 or progress._issuer is not _GRAPH_APPLICATION_PROGRESS_V2 or progress.application is not self or progress.phase != 'commit':
            raise AuthorityUnavailable('actual fully verified selected Graph application progress required')
        view, certificate = progress.view, progress.certificate
        operation_id = view.basis.prepared['operation_id']
        self.coordinator._admin(self.bootstrap)
        with self.scoped.deletion.freeze_writes(), self.scoped.execution.freeze_writes():
            journals = self._selected_journal_proof_v3
            deletion = journals.deletion_head_locked(self.scoped.deletion,meter=meter)
            execution = journals.execution_head_locked(self.scoped.execution,meter=meter)
            if (deletion, execution) != (progress.deletion_head, progress.execution_head):
                raise AuthorityUnavailable('actual journals changed after cumulative suffix EOF')
            with self.core._tx() as core:
                state = self.scoped.state_locked(core)
                anchor = self.core._anchor(core, self.scoped.namespace, self.core._row(core, self.scoped.namespace))
                if (state.applied_seq != progress.prior_applied_seq and
                        (state.applied_seq,state.applied_digest,state.applied_epoch) !=
                            (deletion.seq,deletion.digest,progress.closed.pending.deletion_epoch)):
                    raise AuthorityUnavailable('actual scoped applied predecessor changed before ACK')
                with self.store._lock:
                    db = self.store._db
                    db.execute('BEGIN IMMEDIATE')
                    try:
                        view.require_current(meter=meter)
                        journals._require_connection(db,'graph',meter)
                        prior = self._read_ack_locked(_bounded(db, meter), operation_id)
                        if prior is not None:
                            progress.require_ack(prior)
                            self._read_selected_ack_effect_locked(db,prior,meter=meter)
                            db.rollback();return prior
                        if state.applied_seq != progress.prior_applied_seq:
                            raise AuthorityUnavailable('actual scoped applied state advanced without its retained ACK')
                        metadata, epoch = self.coordinator._v2_graph_stamp(self.namespace)
                        if metadata.requirements.graph_incarnation != certificate.candidate.new_incarnation:
                            raise AuthorityUnavailable('actual selected Graph incarnation changed before ACK')
                        candidate = GraphCandidate(Event(Scope(*self.namespace.as_tuple, 'c09-maintenance'),
                            'c09-ack-' + canonical_digest((self.namespace, operation_id))[:48], time.time(),
                            'c09.cumulative-erasure-application.v2', {'certificate_digest': certificate.certificate_digest}), (), (), (epoch,))
                        result = None
                        def record(_db, receipt):
                            nonlocal result
                            target = replace(metadata.requirements, deletion_seq=deletion.seq, deletion_digest=deletion.digest,
                                execution_seq=execution.seq, execution_digest=execution.digest, revocation_epoch=anchor.revocation_epoch,
                                execution_journal_id=execution.journal_id, deletion_journal_id=deletion.journal_id)
                            if target.execution_journal_id != metadata.requirements.execution_journal_id:
                                self.store.cas_c09_recovery_identity_v1(metadata, target, storage_reader=self.control,
                                    core=self.core, credential=self.credential, _capability=self.capability)
                            else:
                                self.store.cas_graph_recovery_metadata(metadata, target, _capability=self.capability)
                            result = dict(schema='sylanne3.c09.cumulative-graph-ack.v2', namespace=list(self.namespace.as_tuple),
                                operation_id=operation_id, manifest_digest=view.basis.manifest['manifest_digest'],
                                storage_generation=view.basis.manifest['generation'], certificate_digest=certificate.certificate_digest,
                                cumulative_tombstone_root=view.basis.manifest['cumulative_tombstone_root'],
                                new_incarnation=certificate.candidate.new_incarnation, deletion_seq=deletion.seq, deletion_digest=deletion.digest,
                                deletion_epoch=progress.closed.pending.deletion_epoch, closed_digest=canonical_digest(progress.closed),
                                suffix_algorithm='sylanne3.c09.applied-deletion-suffix.v2', suffix_count=progress.suffix_count,
                                suffix_root=progress.suffix_root, suffix_eof_digest=canonical_digest((progress.last_seq, deletion, progress.suffix_root)),
                                selection_digest=view.basis.selection_digest, selected_history_root=view.history_root,
                                selected_history_count=view.history_count, prior_applied_seq=state.applied_seq,
                                graph_receipt_digest=canonical_digest(receipt), graph_revision=metadata.graph_revision + 1)
                            result['ack_digest'] = canonical_digest(result)
                            meter.write_row(_db, _TABLE, ('bot', 'persona', 'operation_id', 'original_json', 'original_digest'),
                                (*self.namespace.as_tuple, operation_id, canonical_json(result), result['ack_digest']))
                        GraphStore._graph_commit_in_transaction(self.store, candidate, _receipt_hook=record, _capability=self.capability)
                        if result is None:
                            raise AuthorityUnavailable('actual Graph ACK event was not committed')
                        db.commit();return result
                    except BaseException:
                        if db.in_transaction:db.rollback()
                        raise




class InstalledC09GraphApplicationProgressV2:
    """Authenticate finite erasure streams and the actual unapplied journal suffix."""
    def __init__(self, token, application, view, closed):
        if token is not _GRAPH_APPLICATION_PROGRESS_V2:
            raise AuthorityUnavailable('actual installed Graph application progress issuer required')
        self._issuer = token
        from .c09_selected_history_v3 import VerifiedSelectedHistoryReadV3
        if type(application) is not InstalledC09GraphApplicationV1 or type(view) is not VerifiedSelectedHistoryReadV3:
            raise AuthorityUnavailable('actual installed Graph application and complete selected history required')
        self.application, self.view, self.closed = application, view, closed
        self.phase, self.certificate, self.stream = 'issue', None, None
        self.family_index, self.last_seq, self.suffix_count = 0, None, 0
        self.nested_stream = self.nested_shape = None
        self.suffix_root = canonical_digest(('sylanne3.c09.applied-deletion-suffix.v2', view.basis.selection_digest))
        self.suffix_first = self.prior_applied_seq = self.deletion_head = self.execution_head = None
        self.failed, self.result, self.replay_ack = None, None, None

    def require_ack(self, ack):
        view = self.view
        expected = dict(schema='sylanne3.c09.cumulative-graph-ack.v2',namespace=list(self.application.namespace.as_tuple),
            operation_id=view.scope.operation_id,manifest_digest=view.basis.manifest['manifest_digest'],
            storage_generation=view.basis.manifest['generation'],certificate_digest=self.certificate.certificate_digest,
            cumulative_tombstone_root=view.basis.manifest['cumulative_tombstone_root'],new_incarnation=self.certificate.candidate.new_incarnation,
            deletion_seq=self.deletion_head.seq,deletion_digest=self.deletion_head.digest,deletion_epoch=self.closed.pending.deletion_epoch,
            closed_digest=canonical_digest(self.closed),suffix_algorithm='sylanne3.c09.applied-deletion-suffix.v2',
            suffix_count=self.suffix_count,suffix_root=self.suffix_root,
            suffix_eof_digest=canonical_digest((self.last_seq,self.deletion_head,self.suffix_root)),
            selection_digest=view.basis.selection_digest,selected_history_root=view.history_root,selected_history_count=view.history_count,
            prior_applied_seq=self.prior_applied_seq)
        if any(ack.get(name) != value for name,value in expected.items()):
            raise AuthorityUnavailable('actual cumulative Graph ACK signed ancestry or reconstructed suffix differs')
        if self.replay_ack is not None and ack != self.replay_ack:
            raise AuthorityUnavailable('actual retained Graph ACK changed during independent recovery')
        return ack

    def advance(self, *, meter):
        if self._issuer is not _GRAPH_APPLICATION_PROGRESS_V2:
            raise AuthorityUnavailable('actual Graph application progress issuer differs')
        if self.failed is not None:
            raise AuthorityUnavailable(self.failed)
        try:
            return self._advance(_selected_meter_v3(meter))
        except BaseException as exc:
            self.failed = str(exc)
            raise

    def _advance(self, meter):
        from .c09_selected_history_v3 import _bounded, _read_one
        from .c09_graph_rebase_issue_v2 import _read_issue, _verify_signature
        from .c09_paged_recovery_facts_v2 import C09HistoricalSealedStreamReaderV2
        from ..runtime.c09_paged_sql_v2 import read_c09_table_shape_v2, c09_row_commitment_v2
        view, graph = self.view, self.application
        current = view.basis.require_current(meter=meter)
        operation_id, namespace = view.basis.prepared['operation_id'], view.basis.prepared['namespace']
        if current['stage'] != 'CLEANED' or namespace != graph.scoped.namespace:
            raise AuthorityUnavailable('actual CLEANED selected Graph application scope required')
        if self.result is not None:
            return dict(status='complete', phase='graph_applied', original=self.result)
        if self.phase == 'issue':
            with view.basis.read_database('core', meter=meter) as core:
                issued = _read_issue(_bounded(core, meter), namespace, operation_id)
            if issued is None:
                raise AuthorityUnavailable('actual selected Core Graph issue absent before ACK')
            _verify_signature(issued, graph.control._key)
            self.certificate = issued.certificate
            if (issued.issue_digest != view.basis.manifest['graph_issue_digest']
                    or issued.certificate.certificate_digest != view.basis.manifest['certificate_digest']
                    or issued.certificate.candidate.scope != view.scope):
                raise AuthorityUnavailable('actual selected Graph issue and PREPARED differ')
            with view.basis.read_database('graph', meter=meter) as db:
                from ..runtime.c09_paged_capture_contract_v2 import c09_paged_value_to_wire_v2
                from ..runtime_contracts import canonical_serialize
                mirrored = _bounded(db, meter).execute('SELECT certificate_json,issue_digest FROM graph_c09_rebase_certificates_v2 '
                    'WHERE bot=? AND persona=? AND operation_id=?', (*graph.namespace.as_tuple, operation_id)).fetchone()
            if mirrored != (canonical_serialize(c09_paged_value_to_wire_v2(self.certificate)), issued.issue_digest):
                raise AuthorityUnavailable('actual selected Graph mirror differs from Core signed issue')
            self.phase = 'streams'
        elif self.phase == 'streams':
            families = (('closure', 'c09_graph_closure_directory_v2'), ('tombstones', 'graph_c09_erased_keys_v1'))
            if self.family_index == len(families):
                self.phase = 'suffix_begin'
            else:
                field, table = families[self.family_index]
                if self.stream is None:
                    self.stream = C09HistoricalSealedStreamReaderV2(getattr(self.certificate.candidate, field))
                with view.basis.read_database('graph', meter=meter) as db:
                    if self.nested_stream is not None:
                        nested = self.nested_stream
                        shape = read_c09_table_shape_v2(db, nested.locator.identity.family, meter=meter)
                        def nested_observe(record):
                            actual = meter.read_row(db, shape, record.primary_key)
                            if actual is None or c09_row_commitment_v2(tuple(actual)) != record.commitment:
                                raise AuthorityUnavailable('actual selected closure family changed before ACK')
                        if nested.advance(db, meter, nested_observe):
                            self.nested_stream = None
                        return dict(status='progress', phase='graph_application_closure_family')
                    shape = read_c09_table_shape_v2(db, table, meter=meter)
                    def observe(record):
                        actual = meter.read_row(db, shape, record.primary_key)
                        if actual is None or c09_row_commitment_v2(tuple(actual)) != record.commitment:
                            raise AuthorityUnavailable('actual selected erasure stream member changed before ACK')
                        if field == 'closure':
                            from ..runtime.c09_paged_capture_contract_v2 import C09StreamIdentityV2, C09CompleteStreamV2, C09SealedStreamLocatorV2, c09_paged_value_from_wire_v2
                            from ..runtime.c09_closure_index_v2 import CLOSURE_TABLES_V2
                            identity = c09_paged_value_from_wire_v2(json.loads(actual[2]), C09StreamIdentityV2)
                            complete = c09_paged_value_from_wire_v2(json.loads(actual[3]), C09CompleteStreamV2)
                            if (identity.family not in CLOSURE_TABLES_V2 or identity.scope_digest != view.scope.scope_digest
                                    or identity.role_source_digest != self.certificate.candidate.source.role_source_digest):
                                raise AuthorityUnavailable('actual closure family locator crosses its signed scope')
                            self.nested_stream = C09HistoricalSealedStreamReaderV2(C09SealedStreamLocatorV2('graph', identity, complete))
                    if self.stream.advance(db, meter, observe):
                        self.stream = None
                        self.family_index += 1
        elif self.phase == 'suffix_begin':
            with graph.scoped.deletion.freeze_writes(), graph.scoped.execution.freeze_writes():
                journals = graph._selected_journal_proof_v3
                deletion = journals.deletion_head_locked(graph.scoped.deletion,meter=meter)
                execution = journals.execution_head_locked(graph.scoped.execution,meter=meter)
                with graph.core._tx() as db:
                    state = graph.scoped.state_locked(db)
                    saved = graph.scoped.fences.mutation_locked(_bounded(db, meter),
                        'c09-closed-mutation-' + canonical_digest((namespace, operation_id))[:48])
                    stored = None if saved is None else graph.scoped.fences._decode_mutation_row(saved)
                    if (stored is None or stored[2] != self.closed or self.closed.pending.target_phase != 'closed'
                            or self.closed.pending.deletion_operation_id != operation_id
                            or self.closed.after_anchor.deletion_seq != deletion.seq
                            or self.closed.after_anchor.deletion_digest != deletion.digest
                            or state.applied_seq < deletion.seq and (state.closed_seq, state.closed_digest) != (deletion.seq, deletion.digest)):
                        raise AuthorityUnavailable('actual closed Core receipt and latest deletion obligation differ')
            self.deletion_head, self.execution_head = deletion, execution
            with view.basis.read_database('graph',meter=meter) as db:
                self.replay_ack = graph._read_ack_locked(_bounded(db,meter),operation_id)
            predecessor = state.applied_seq if self.replay_ack is None else self.replay_ack['prior_applied_seq']
            if (type(predecessor) is not int or not 0 <= predecessor < deletion.seq
                    or self.replay_ack is None and state.applied_seq >= deletion.seq
                    or self.replay_ack is not None and state.applied_seq not in (predecessor,deletion.seq)):
                raise AuthorityUnavailable('actual retained ACK applied predecessor differs from Core')
            self.prior_applied_seq = self.last_seq = predecessor
            self.phase = 'suffix'
        elif self.phase == 'suffix':
            with graph.scoped.deletion.freeze_writes():
                head = graph._selected_journal_proof_v3.deletion_head_locked(graph.scoped.deletion,meter=meter)
                if head != self.deletion_head:
                    raise AuthorityUnavailable('actual deletion suffix changed before cumulative ACK')
                row = _read_one(graph.scoped.deletion._db, 'SELECT seq,operation_id,phase,chain_digest FROM authority_deletion_v2_tail '
                    'WHERE seq>? AND seq<=? ORDER BY seq LIMIT 1', (self.last_seq, head.seq), meter)
            if row is None:
                if self.last_seq != head.seq or not self.suffix_count:
                    raise AuthorityUnavailable('actual unapplied deletion suffix did not reach closed EOF')
                self.phase = 'commit'
            else:
                if row[0] != self.last_seq + 1:
                    raise AuthorityUnavailable('actual unapplied deletion suffix has a gap')
                # The authenticated storage history pins each corresponding certificate;
                # only indexed operation metadata is needed for suffix coverage.
                with graph.control._db() as control_db:
                    found = []
                    for version in (1, 2, 3):
                        table = 'c09_storage_operations_v' + str(version)
                        if _read_one(control_db, "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,), meter) is not None:
                            retained = _read_one(control_db, 'SELECT generation,new_manifest_digest FROM ' + table + ' WHERE operation_id=?', (row[1],), meter)
                            if retained is not None:
                                found.append(retained)
                    if len(found) != 1 or not 1 <= found[0][0] <= view.history_count:
                        raise AuthorityUnavailable('actual cumulative suffix operation lacks unique authenticated storage history')
                self.last_seq = row[0]
                self.suffix_count += 1
                self.suffix_root = canonical_digest((self.suffix_root, self.suffix_count, row))
                if row[0] == head.seq and row[1:] != (operation_id, 'closed', head.digest):
                    raise AuthorityUnavailable('actual unapplied deletion suffix ends outside this closed operation')
        elif self.phase == 'commit':
            self.result = graph._commit_selected_graph_application_v2(self, meter=meter)
            self.require_ack(self.result)
            graph._selected_graph_application_read_v3 = SelectedC09GraphApplicationReadV3(_GRAPH_APPLICATION_PROGRESS_V2,self)
            return dict(status='complete', phase='graph_applied', original=self.result)
        else:
            raise AuthorityUnavailable('actual cumulative Graph application private phase differs')
        return dict(status='progress', phase='graph_application_' + self.phase, suffix_count=self.suffix_count)




def advance_selected_graph_application_v2(application, *, view, closed_receipt, meter):
    progress = getattr(application, '_selected_application_progress_v2', None)
    if progress is None:
        progress = InstalledC09GraphApplicationProgressV2(_GRAPH_APPLICATION_PROGRESS_V2, application, view, closed_receipt)
        application._selected_application_progress_v2 = progress
    elif progress.view is not view or progress.closed != closed_receipt:
        raise AuthorityUnavailable('actual cumulative application has another selected scope or closed receipt')
    return progress.advance(meter=meter)


_SELECTED_JOURNALS_V3 = object()


def _selected_meter_v3(meter):
    from ..runtime.c09_paged_sql_v2 import require_c09_reserved_meter_v3
    if require_c09_reserved_meter_v3(meter.budget) is not meter:
        raise AuthorityUnavailable('actual same reserved C09 root required')
    return meter


class SelectedC09JournalProofV3:
    """Signed finite journal prefixes plus the one actual closed continuation."""
    def __init__(self, token, reader):
        if token is not _SELECTED_JOURNALS_V3 or not reader.complete:
            raise AuthorityUnavailable('actual journal directory, members and EOF issuer required')
        self._issuer, self.application, self.view = token, reader.application, reader.view
        self.base_anchor, self.accepted = reader.base_anchor, reader.accepted
        self.seals = tuple(reader.seals)
        self.metadata = tuple(reader.metadata)
        self.schema_stamps = dict(reader.schema_stamps)

    def require_identity(self, *, deletion, execution=None, core=None):
        graph = self.application
        if (self._issuer is not _SELECTED_JOURNALS_V3 or deletion is not graph.scoped.deletion
                or execution is not None and execution is not graph.scoped.execution
                or core is not None and core is not graph.core):
            raise AuthorityUnavailable('actual selected journal proof composition differs')
        return self

    def _require_connection(self, db, role, meter):
        from .c09_selected_history_v3 import _bounded
        row = _bounded(db,meter).execute('PRAGMA database_list').fetchone()
        member = self.view.basis.member(role)
        if row is None or row[1] != 'main' or Path(row[2]).resolve() != Path(member['resolved_path']).resolve():
            raise AuthorityUnavailable('actual selected journal/Core connection differs from signed role path')

    def _require_metadata(self, db, role, meter):
        for captured_role,table,columns,key,row in self.metadata:
            if captured_role == role:
                actual = meter.read_fixed_row(db,table,columns,'"'+columns[0]+'"=?',key)
                if actual != row:
                    raise AuthorityUnavailable('actual selected journal metadata differs from its signed prefix')

    def require_schema_locked(self, journal, role, *, meter):
        from .c09_selected_history_v3 import _read_one
        self.require_identity(deletion=self.application.scoped.deletion,
            execution=journal if role == 'execution' else None,core=self.application.core)
        if (role == 'deletion' and journal is not self.application.scoped.deletion
                or journal._db is None or not journal._db.in_transaction):
            raise AuthorityUnavailable('actual selected guarded journal schema required')
        _selected_meter_v3(meter)
        self.view.require_current(meter=meter)
        self._require_connection(journal._db,role,meter)
        if _read_one(journal._db,'SELECT schema_version FROM pragma_schema_version',(),meter) != self.schema_stamps[role]:
            raise AuthorityUnavailable('actual selected journal schema changed after signed full EOF')
        self._require_metadata(journal._db,role,meter)
        if role == 'execution':
            version = next(row[1] for captured_role,table,columns,key,row in self.metadata
                if captured_role == 'execution' and table == 'authority_v2_execution_meta' and row[0] == 'schema_version')
            if version != '4':
                raise AuthorityUnavailable('actual signed selected execution prefix schema differs')
            journal._schema_version = version
            return None
        values = {row[0]:row[1] for captured_role,table,columns,key,row in self.metadata
            if captured_role == 'deletion' and table == 'authority_deletion_v2_meta'}
        if (values['namespace'] != self.application.scoped.namespace or values['schema_version'] != '2'
                or values['journal_id'] != self.base_anchor.deletion_journal_id):
            raise AuthorityUnavailable('actual signed selected deletion schema metadata differs')
        return 'v2',self.base_anchor.deletion_journal_id,values

    def deletion_head_locked(self, deletion, *, meter):
        from .contract import JournalHead
        from .c09_selected_history_v3 import _bounded, _read_one
        self.require_identity(deletion=deletion)
        _selected_meter_v3(meter)
        self.view.require_current(meter=meter)
        if deletion._db is None or not deletion._db.in_transaction:
            raise AuthorityUnavailable('actual selected deletion writer guard required')
        self._require_connection(deletion._db,'deletion',meter)
        self._require_metadata(deletion._db,'deletion',meter)
        base = self.base_anchor
        graph = self.application
        with graph.core._lock:
            core = graph.core._db
            self._require_connection(core,'core',meter)
            saved = graph.scoped.fences.mutation_locked(_bounded(core, meter),
                'c09-closed-mutation-' + canonical_digest((graph.scoped.namespace, self.view.scope.operation_id))[:48])
            stored = None if saved is None else graph.scoped.fences._decode_mutation_row(saved)
        after = _read_one(deletion._db, 'SELECT seq FROM authority_deletion_v2_tail WHERE seq>? ORDER BY seq LIMIT 1',
            (base.deletion_seq,), meter)
        if after is None:
            return JournalHead(base.deletion_journal_id, base.deletion_seq, base.deletion_digest)
        if (stored is None or stored[0] != 'deletion' or saved[1:3] != (graph.scoped.namespace, graph.subject)
                or stored[1].source_phase != 'accepted' or stored[1].target_phase != 'closed'
                or stored[1].deletion_operation_id != self.view.scope.operation_id
                or stored[1].before_anchor.deletion_journal_id != base.deletion_journal_id
                or (stored[1].before_anchor.deletion_seq, stored[1].before_anchor.deletion_digest) !=
                    (base.deletion_seq, base.deletion_digest)
                or after != (base.deletion_seq + 1,)):
            raise AuthorityUnavailable('actual selected deletion has an unowned continuation')
        pending = stored[1]
        body = deletion._pending_body(pending)
        columns = ('seq','schema','kind','append_id','mutation_id','request_digest','namespace','operation_id',
            'phase','subject','holder','token_digest','fence_epoch','revision','before_seq','before_digest',
            'evidence_digest','roots_json','epoch','policy_ref','prev_digest','chain_digest')
        actual = meter.read_fixed_row(deletion._db, 'authority_deletion_v2_tail', columns, 'seq=?', after)
        expected = (body['seq'],body['schema'],body['kind'],body['append_id'],body['mutation_id'],body['request_digest'],
            body['namespace'],body['operation_id'],body['phase'],body['subject'],body['holder'],body['token_digest'],
            body['fence_epoch'],body['revision'],body['before_seq'],body['before_digest'],body['evidence_digest'],
            json.dumps(body['roots'],separators=(',', ':'),ensure_ascii=True),body['epoch'],body['policy_ref'],
            body['previous'],pending.expected_append_digest)
        if (actual != expected or deletion.expected_digest(pending) != pending.expected_append_digest
                or _read_one(deletion._db,'SELECT 1 FROM authority_deletion_v2_tail WHERE seq>? LIMIT 1',after,meter) is not None):
            raise AuthorityUnavailable('actual closed continuation fields, hash or EOF differ')
        return JournalHead(base.deletion_journal_id, pending.expected_deletion_seq, pending.expected_append_digest)

    def execution_head_locked(self, execution, *, meter):
        from .contract import JournalHead
        from .c09_selected_history_v3 import _read_one
        self.require_identity(deletion=self.application.scoped.deletion, execution=execution)
        _selected_meter_v3(meter)
        self.view.require_current(meter=meter)
        base = self.base_anchor
        if (execution._db is None or not execution._db.in_transaction
                or _read_one(execution._db, 'SELECT 1 FROM authority_v2_execution_entries LIMIT 1', (), meter) is not None
                or (base.execution_seq, base.execution_digest) != (0, 'genesis')):
            raise AuthorityUnavailable('actual selected maintenance execution prefix is not unchanged genesis')
        self._require_connection(execution._db,'execution',meter)
        self._require_metadata(execution._db,'execution',meter)
        return JournalHead(base.execution_journal_id, 0, 'genesis')

    def require_current_locked(self, *, deletion, execution, core, db, meter):
        self.require_identity(deletion=deletion, execution=execution, core=core)
        if db is not core._db or not db.in_transaction:
            raise AuthorityUnavailable('actual caller-owned Core transaction required for selected journals')
        return self.deletion_head_locked(deletion, meter=meter), self.execution_head_locked(execution, meter=meter)

    def inspect_pending_locked(self, deletion, pending, *, meter):
        from .v2_deletion_guard import VerifiedDeletionAppendV2
        head = self.deletion_head_locked(deletion, meter=meter)
        if (pending.permit.namespace != self.application.scoped.namespace
                or pending.deletion_operation_id != self.view.scope.operation_id
                or pending.source_phase != 'accepted' or pending.target_phase != 'closed'
                or (pending.before_anchor.deletion_journal_id, pending.before_anchor.deletion_seq, pending.before_anchor.deletion_digest) !=
                    (self.base_anchor.deletion_journal_id, self.base_anchor.deletion_seq, self.base_anchor.deletion_digest)):
            raise AuthorityUnavailable('actual selected closed pending differs from signed accepted predecessor')
        if (head.seq, head.digest) == (self.base_anchor.deletion_seq, self.base_anchor.deletion_digest):
            return None
        if (head.seq, head.digest) != (pending.expected_deletion_seq, pending.expected_append_digest):
            raise AuthorityUnavailable('actual selected pending append differs')
        return VerifiedDeletionAppendV2(head.seq, pending.expected_append_id, pending.mutation_id, head.digest)


class _SelectedC09JournalReaderV3:
    """Consume the signed role directory and actual original journal rows in quanta."""
    def __init__(self, application, view):
        from .c09_selected_history_v3 import VerifiedSelectedHistoryReadV3
        if type(application) is not InstalledC09GraphApplicationV1 or type(view) is not VerifiedSelectedHistoryReadV3:
            raise AuthorityUnavailable('actual installed selected journal producer required')
        self.application, self.view = application, view
        self.role_index, self.directory, self.stream, self.shape = 0, None, None, None
        self.directory_after = self.actual_after = None
        self.seen, self.seals, self.metadata = set(), [], []
        self.accepted = self.base_anchor = None
        self.complete, self.result, self.failed = False, None, None
        self.schema_stamps, self.schema_after, self.schema_chain, self.schema_count = {}, None, None, 0

    def advance(self, *, meter):
        if self.failed is not None:
            raise AuthorityUnavailable(self.failed)
        try:
            return self._advance(_selected_meter_v3(meter))
        except BaseException as exc:
            self.failed = str(exc)
            raise

    def _advance(self, meter):
        from .c09_selected_history_v3 import _bounded, _read_one
        from .v2_fence_store import AuthorityV2FenceStore
        from .v2_contract import DeletionMutationReceiptV1
        from ..runtime.restore_anchor import RestoreAnchor
        from .c09_paged_recovery_facts_v2 import C09HistoricalSealedStreamReaderV2
        from ..runtime.c09_paged_capture_contract_v2 import C09SealedStreamLocatorV2, C09StreamIdentityV2, C09CompleteStreamV2, c09_paged_value_from_wire_v2
        from ..runtime.c09_paged_sql_v2 import read_c09_table_shape_v2
        from .c09_authority_storage_rebase import _row_commitment
        view, graph = self.view, self.application
        current = view.require_current(meter=meter).basis.require_current(meter=meter)
        if current['stage'] != 'CLEANED':
            raise AuthorityUnavailable('actual selected cleanup journal window required')
        if self.result is not None:
            return self.result
        if self.base_anchor is None:
            transition = view.basis.prepared['anchor_transition_original']
            self.base_anchor = RestoreAnchor(**transition['after_anchor'])
            with view.basis.read_database('deletion', meter=meter) as deletion:
                original = _read_one(deletion,'SELECT mutation_id,operation_id,phase,chain_digest FROM authority_deletion_v2_tail WHERE seq=?',
                    (self.base_anchor.deletion_seq,),meter)
            if original is None or original[1:] != (view.scope.operation_id, 'accepted', self.base_anchor.deletion_digest):
                raise AuthorityUnavailable('actual signed selected accepted journal predecessor differs')
            with view.basis.read_database('core', meter=meter) as core:
                saved = AuthorityV2FenceStore.mutation_locked(_bounded(core,meter),original[0])
                stored = None if saved is None else AuthorityV2FenceStore._decode_mutation_row(saved)
            if (stored is None or stored[0] != 'deletion' or type(stored[2]) is not DeletionMutationReceiptV1
                    or saved[1:3] != (graph.scoped.namespace,graph.subject)
                    or canonical_digest(stored[2]) != view.scope.accepted_receipt_digest
                    or transition['accepted_receipt_digest'] != view.scope.accepted_receipt_digest
                    or (stored[2].after_anchor.deletion_journal_id,stored[2].after_anchor.deletion_seq,stored[2].after_anchor.deletion_digest) !=
                        (self.base_anchor.deletion_journal_id,self.base_anchor.deletion_seq,self.base_anchor.deletion_digest)
                    or self.base_anchor.execution_journal_id != view.basis.member('execution')['incarnation_or_journal_id']
                    or self.base_anchor.deletion_journal_id != view.basis.member('deletion')['incarnation_or_journal_id']):
                raise AuthorityUnavailable('actual signed accepted Core original and journal transition differ')
            self.accepted = stored[2]
            return dict(status='progress',phase='selected_journal_accepted')
        if self.role_index == 2:
            required = {'deletion_meta','deletion_events','authority_deletion_v2_tail','authority_deletion_v2_meta',
                'authority_v2_execution_entries','authority_v2_execution_meta','authority_v2_execution_redacted_prefix_v4'}
            if self.seen != required:
                raise AuthorityUnavailable('signed role directory omits a required journal family')
            self.complete = True
            self.result = SelectedC09JournalProofV3(_SELECTED_JOURNALS_V3,self)
            return self.result
        role = ('deletion','execution')[self.role_index]
        proof = next(value for value in view.verified_roles if value.role == role)
        proof.require_current(control=graph.control,scope=view.scope,meter=meter)
        with view.basis.read_database(role,meter=meter) as db:
            if role not in self.schema_stamps:
                from ..runtime.c09_paged_sql_v2 import read_c09_next_schema_object_v2
                if self.schema_chain is None:
                    self.schema_chain = canonical_digest(('sylanne3.c09.actual-target-schema-catalogue.v2',view.scope.scope_digest,role))
                original = read_c09_next_schema_object_v2(_bounded(db,meter),self.schema_after,max_bytes=meter.remaining_bytes)
                if original is None:
                    digest = canonical_digest(('sylanne3.c09.actual-target-schema-eof.v2',view.scope.scope_digest,role,
                        self.schema_count,self.schema_after,self.schema_chain))
                    if digest != proof.base_header['target_schema_digest']:
                        raise AuthorityUnavailable('actual selected journal target schema count/root/full EOF differs from signed role')
                    self.schema_stamps[role] = _read_one(db,'SELECT schema_version FROM pragma_schema_version',(),meter)
                    self.schema_after,self.schema_chain,self.schema_count = None,None,0
                else:
                    self.schema_count += 1
                    self.schema_chain = canonical_digest(('sylanne3.c09.actual-target-schema-object.v2',self.schema_chain,
                        self.schema_count,original.object_type,original.name,original.table_name,original.sql))
                    self.schema_after = original.primary_key
                return dict(status='progress',phase='selected_journal_schema_eof',role=role)
            if self.stream is not None:
                shape, stream = self.shape, self.stream
                def observe(record):
                    actual = meter.read_row(db,shape,record.primary_key)
                    commitment = None if actual is None else canonical_digest(('sylanne3.c09.authority-target-row.v2',shape.table,
                        record.primary_key,_row_commitment(shape.table,shape.columns,actual)))
                    if commitment != record.commitment or self._next_key(db,shape,self.actual_after,meter) != record.primary_key:
                        raise AuthorityUnavailable('actual selected journal row differs from signed target prefix')
                    if shape.table in {'deletion_meta','authority_deletion_v2_meta','authority_v2_execution_meta','authority_v2_execution_redacted_prefix_v4'}:
                        self.metadata.append((role,shape.table,shape.columns,record.primary_key,tuple(actual)))
                    self.actual_after = record.primary_key
                if stream.advance(db,meter,observe):
                    if self._next_key(db,shape,self.actual_after,meter) is not None:
                        raise AuthorityUnavailable('actual selected journal contains an unsealed prefix row')
                    self.seals.append(stream.locator.complete.digest)
                    self.seen.add(shape.table)
                    self.stream = self.shape = self.actual_after = None
                return dict(status='progress',phase='selected_journal_members',role=role)
            if self.directory is None:
                locator = c09_paged_value_from_wire_v2(proof.base_header['stream_directory'],C09SealedStreamLocatorV2)
                self.directory = C09HistoricalSealedStreamReaderV2(locator)
            shape = read_c09_table_shape_v2(db,'authority_c09_role_streams_v2',meter=meter)
            def observe_directory(record):
                actual = meter.read_row(db,shape,record.primary_key)
                if (actual is None or canonical_digest(('sylanne3.c09.authority-directory-row.v2','control_metadata',
                        shape.table,record.primary_key,actual)) != record.commitment):
                    raise AuthorityUnavailable('actual selected journal role directory differs from signed seal')
                names = ','.join('"'+name+'"' for name in shape.primary_key_columns)
                where,params = ('',()) if self.directory_after is None else (' WHERE ('+names+')>('+','.join('?' for _ in self.directory_after)+')',self.directory_after)
                next_key = _read_one(db,'SELECT '+names+' FROM authority_c09_role_streams_v2'+where+' ORDER BY '+names+' LIMIT 1',params,meter)
                if next_key != record.primary_key:
                    raise AuthorityUnavailable('actual selected journal directory omits a retained original')
                self.directory_after = record.primary_key
                values = dict(zip(shape.columns,actual))
                needed = {'deletion_meta','deletion_events','authority_deletion_v2_tail','authority_deletion_v2_meta'} if role == 'deletion' else {
                    'authority_v2_execution_entries','authority_v2_execution_meta','authority_v2_execution_redacted_prefix_v4'}
                if (values['scope_digest'] == view.scope.scope_digest and values['role'] == role
                        and values['stream_kind'] == 'target_rows' and values['table_name'] in needed):
                    identity = c09_paged_value_from_wire_v2(json.loads(values['stream_json']),C09StreamIdentityV2)
                    complete = c09_paged_value_from_wire_v2(json.loads(values['seal_json']),C09CompleteStreamV2)
                    self.shape = read_c09_table_shape_v2(db,values['table_name'],meter=meter)
                    if (identity.scope_digest != view.scope.scope_digest or identity.role_source_digest != self.directory.locator.identity.role_source_digest
                            or identity.family != self.shape.table or identity.schema_digest != self.shape.schema_digest
                            or self.shape.table in self.seen):
                        raise AuthorityUnavailable('actual journal locator crosses its signed role, schema or scope')
                    self.stream = C09HistoricalSealedStreamReaderV2(C09SealedStreamLocatorV2(role,identity,complete))
            if self.directory.advance(db,meter,observe_directory):
                names = ','.join('"'+name+'"' for name in shape.primary_key_columns)
                where,params = ('',()) if self.directory_after is None else (' WHERE ('+names+')>('+','.join('?' for _ in self.directory_after)+')',self.directory_after)
                if _read_one(db,'SELECT '+names+' FROM authority_c09_role_streams_v2'+where+' ORDER BY '+names+' LIMIT 1',params,meter) is not None:
                    raise AuthorityUnavailable('actual selected journal directory has an unsealed suffix')
                self.seals.append(self.directory.locator.complete.digest)
                self.role_index += 1
                self.directory = self.directory_after = None
        return dict(status='progress',phase='selected_journal_directory',role=role)

    def _next_key(self, db, shape, after, meter):
        from .c09_selected_history_v3 import _read_one
        key = shape.primary_key_columns
        if len(key) != 1:
            raise AuthorityUnavailable('actual journal scalar primary key required')
        name = key[0]
        where, params = ('',()) if after is None else (' WHERE "'+name+'">?',after)
        if shape.table == 'authority_deletion_v2_tail':
            where += (' AND ' if where else ' WHERE ') + 'seq<=?'
            params = (*params,self.base_anchor.deletion_seq)
        return _read_one(db,'SELECT "'+name+'" FROM "'+shape.table+'"'+where+' ORDER BY "'+name+'" LIMIT 1',params,meter)


def advance_selected_journal_proof_v3(application, *, view, meter):
    reader = getattr(application,'_selected_journal_reader_v3',None)
    if reader is None:
        reader = _SelectedC09JournalReaderV3(application,view)
        application._selected_journal_reader_v3 = reader
    elif reader.view is not view:
        raise AuthorityUnavailable('actual selected journals have another complete read basis')
    result = reader.advance(meter=meter)
    if type(result) is SelectedC09JournalProofV3:
        application._selected_journal_proof_v3 = result
        application.scoped.deletion._c09_selected_journal_proof_v3 = result
        application.scoped.execution._c09_selected_journal_proof_v3 = result
    return result


class SelectedC09GraphApplicationReadV3:
    def __init__(self, token, progress):
        if (token is not _GRAPH_APPLICATION_PROGRESS_V2 or progress._issuer is not token
                or progress.phase != 'commit' or progress.result is None):
            raise AuthorityUnavailable('actual complete selected Graph ACK issuer required')
        progress.require_ack(progress.result)
        self._issuer,self.application,self.view = token,progress.application,progress.view
        self.ack,self.closed = dict(progress.result),progress.closed

    def require_current_locked(self, *, db, meter):
        from .c09_selected_history_v3 import _bounded
        graph = self.application
        _selected_meter_v3(meter)
        if self._issuer is not _GRAPH_APPLICATION_PROGRESS_V2 or db is not graph.core._db:
            raise AuthorityUnavailable('actual selected Graph ACK and caller Core connection required')
        self.view.require_current(meter=meter)
        saved = graph.scoped.fences.mutation_locked(_bounded(db,meter),
            'c09-closed-mutation-' + canonical_digest((graph.scoped.namespace,self.view.scope.operation_id))[:48])
        stored = None if saved is None else graph.scoped.fences._decode_mutation_row(saved)
        if stored is None or saved[1:3] != (graph.scoped.namespace,graph.subject) or stored[2] != self.closed:
            raise AuthorityUnavailable('actual selected Graph ACK closed Core original differs')
        with graph.store._lock:
            actual = graph._read_ack_locked(_bounded(graph.store._db,meter),self.view.scope.operation_id)
            if actual != self.ack:
                raise AuthorityUnavailable('actual selected Graph ACK changed after complete independent read')
            graph._read_selected_ack_effect_locked(graph.store._db,actual,meter=meter)
        original = VerifiedGraphAppliedHeadV2(graph.scoped.namespace,actual['operation_id'],actual['deletion_seq'],
            actual['deletion_digest'],actual['deletion_epoch'],'sha256:'+actual['graph_receipt_digest'])
        return original,actual


def _read_selected_graph_ack_event_v3(db, namespace, ack, *, meter):
    from .c09_selected_history_v3 import _bounded
    from ..graph_types import GraphReceipt, NamespaceEpoch
    _selected_meter_v3(meter)
    values = namespace.as_tuple
    row = _bounded(db,meter).execute('SELECT revisions,invalidated,epoch_revision FROM graph_events '
        'WHERE bot=? AND persona=? AND session=? AND event_id=?',
        (*values,'c09-maintenance','c09-ack-'+canonical_digest((namespace,ack['operation_id']))[:48])).fetchone()
    if row is None or row[:2] != ('[]','[]'):
        raise AuthorityUnavailable('actual retained ACK lacks its exact committed Graph event')
    receipt = GraphReceipt('committed',(),(),NamespaceEpoch(*values,row[2]))
    if canonical_digest(receipt) != ack['graph_receipt_digest']:
        raise AuthorityUnavailable('actual retained Graph event receipt differs from ACK')
    return receipt


def c09_actual_root_read_v3(db):
    """Meter an installed exact read without changing its actual caller connection."""
    from ..runtime.c09_paged_sql_v2 import peek_current_c09_sql_meter_v3
    from .c09_paged_recovery_facts_v2 import _BoundedReadConnectionV2
    from .c09_selected_history_v3 import _bounded
    meter = peek_current_c09_sql_meter_v3()
    if meter is None or type(db) is _BoundedReadConnectionV2:
        return db
    return _bounded(db,_selected_meter_v3(meter))
