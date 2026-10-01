"""Installed C09 maintenance gate and four-store prepare/switch/resume flow."""
from __future__ import annotations

from contextlib import contextmanager, closing
from dataclasses import asdict, fields
import json
from pathlib import Path
import sqlite3
import threading

from ..runtime_contracts import canonical_digest, canonical_serialize
from ..runtime.c09_storage_transition_v1 import C09ExecutionBindingV1,C09RecoveryBindingsV1
from .contract import AuthorityUnavailable
from .c09_storage_control_v1 import C09StorageControlV1,SURFACES,ROLES,canonical,digest,file_observation_v1,_regular_path
from .c09_recovery_resolver_v4 import InstalledSanitizedRecoveryResolverV4,read_recovery_bindings_v1_locked


class InstalledC09WriterGateV1:
    """Installation-wide admission epoch; real writers hold this shared gate."""
    def __init__(self, *, control):
        if type(control) is not C09StorageControlV1:
            raise AuthorityUnavailable("installed C09 gate requires control authority")
        self.control = control
        self._condition = threading.Condition(threading.RLock())
        self._active = 0
        self._operation = None
        self._epoch = 0
        self._workers = {}
        self._peers = {}
        self._retired_peers = []
        self._peer_retirement_handler = None
        self._closing_continuation=None

    def install_peer_retirement_handler_v1(self, handler):
        with self._condition:
            if self._peer_retirement_handler is not None or not callable(handler) or self._operation is not None:
                raise AuthorityUnavailable("C09 installed peer supervisor already bound or invalid")
            self._peer_retirement_handler = handler

    def register_peer_process_v1(self, *, peer, process_id, process_incarnation,
                                 pointer_version, storage_generation):
        """Installer-only admission of a real local Host/cache-holder process.

        A TLS handshake cannot create or refresh this generation grant. The
        supervisor registers a newly started process after RELEASED instead.
        """
        from .c09_process_identity_v1 import read_process_identity_v1, require_process_retired_v1
        if (type(peer) is not tuple or len(peer) != 2
                or not all(type(part) is str and part for part in peer)
                or type(process_incarnation) is not str or not process_incarnation):
            raise AuthorityUnavailable("C09 installed peer process identity required")
        with self._condition:
            context = self.control.read_verified_current_storage_v1()
            context.require_current("business")
            identity = read_process_identity_v1(process_id)
            if (identity is None or self._operation is not None
                    or (pointer_version, storage_generation) !=
                       (context.pointer_version, context.storage_generation)):
                raise AuthorityUnavailable("C09 peer is not live in the current generation")
            admission = (pointer_version, storage_generation, self._epoch,
                         process_incarnation, identity)
            prior = self._peers.get(peer)
            if prior is not None and prior != admission:
                if self._active:
                    raise AuthorityUnavailable("C09 prior peer requests have not drained")
                retired = require_process_retired_v1(prior[4])
                self._retired_peers.append(retired)
            self._peers[peer] = admission

    @contextmanager
    def admit_peer_v1(self, *, peer):
        from .c09_process_identity_v1 import read_process_identity_v1
        with self._condition:
            admission = self._peers.get(peer)
            if (admission is None or admission[2] != self._epoch
                    or read_process_identity_v1(admission[4]["pid"]) != admission[4]):
                raise AuthorityUnavailable("C09 installed current peer admission unavailable")
        with self.admit_writer_v1(pointer_version=admission[0],
                storage_generation=admission[1], process_incarnation=admission[3],
                peer=peer, expected_admission=admission):
            yield admission

    @contextmanager
    def admit_writer_v1(self, *, pointer_version, storage_generation, process_incarnation,
                        peer=None, expected_admission=None):
        with self._condition:
            context = self.control.read_verified_current_storage_v1()
            context.require_current("business")
            if self._operation is not None or (pointer_version,storage_generation) != (context.pointer_version,context.storage_generation):
                raise AuthorityUnavailable("C09 writer admission generation revoked")
            if not process_incarnation:
                raise AuthorityUnavailable("C09 process incarnation required")
            if peer is not None and self._peers.get(peer) != expected_admission:
                raise AuthorityUnavailable("C09 peer process admission was replaced")
            admission = (context.pointer_version,context.storage_generation,self._epoch,process_incarnation)
            self._active += 1
        try:
            yield admission
            with self._condition:
                if self._operation is not None or admission[2] != self._epoch:
                    raise AuthorityUnavailable("C09 in-flight writer epoch revoked")
        finally:
            with self._condition:
                self._active -= 1
                self._condition.notify_all()

    def register_worker_v1(self, *, process, process_incarnation, pointer_version, storage_generation):
        if not callable(getattr(process,"poll",None)) or not callable(getattr(process,"terminate",None)) or not callable(getattr(process,"wait",None)):
            raise AuthorityUnavailable("C09 actual installed worker process handle required")
        with self._condition:
            context = self.control.read_verified_current_storage_v1()
            context.require_current("business")
            if self._operation is not None or (pointer_version,storage_generation) != (context.pointer_version,context.storage_generation) or process_incarnation in self._workers:
                raise AuthorityUnavailable("C09 worker admission conflict")
            from .c09_process_identity_v1 import read_process_identity_v1
            identity = read_process_identity_v1(process.pid)
            if identity is None or process.poll() is not None:
                raise AuthorityUnavailable("C09 actual worker process is not live")
            self._workers[process_incarnation] = (process,pointer_version,storage_generation,identity)

    def revoke_and_drain_v1(self, *, operation_id):
        import time
        with self._condition:
            self.control.lease.require_held()
            if self._operation not in {None, operation_id}:
                raise AuthorityUnavailable("C09 other maintenance gate active")
            if self._operation is None:
                self._epoch += 1
                self._operation = operation_id
            peers = tuple(admission[4] for admission in self._peers.values())
        # The supervisor may wait on real process exit. Do not hold the gate
        # lock while active RPC finally blocks need it to decrement readers.
        if self._peer_retirement_handler is not None:
            self._peer_retirement_handler(peers)
        with self._condition:
            for process, _version, _generation, _identity in self._workers.values():
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except Exception as exc:
                        raise AuthorityUnavailable("C09 old worker did not exit") from exc
            deadline = time.monotonic() + 10
            while self._active and time.monotonic() < deadline:
                self._condition.wait(timeout=max(0, deadline - time.monotonic()))
            if self._active:
                raise AuthorityUnavailable("C09 active writer handles have not drained")
            return self.read_quiescence_original_v1(operation_id=operation_id)

    def read_quiescence_original_v1(self, *, operation_id):
        with self._condition:
            self.control.lease.require_held()
            from .c09_process_identity_v1 import read_process_identity_v1, require_process_retired_v1
            if self._operation != operation_id or self._active:
                raise AuthorityUnavailable("C09 real writer quiescence unavailable")
            retired = [require_process_retired_v1(identity) for _p,_v,_g,identity in self._workers.values()]
            retired_peers = list(self._retired_peers) + [require_process_retired_v1(admission[4])
                for _, admission in sorted(self._peers.items())]
            context = self.control.read_verified_current_storage_v1(verify_files=False)
            return self.control.sign_original_v1("sylanne3.c09.writer_quiescence.v1",dict(
                schema="sylanne3.c09.writer_quiescence.v1",installation_id=self.control.installation_id,
                operation_id=operation_id,pointer_version=context.pointer_version,
                storage_generation=context.storage_generation,revoked_admission_epoch=self._epoch,
                active_writers=0,exited_workers=sorted((name,p.pid,version,generation,p.poll()) for name,(p,version,generation,_identity) in self._workers.items()),
                retired_worker_originals=retired, retired_peer_originals=retired_peers,
                authority_process_original=read_process_identity_v1(__import__('os').getpid()),
                lock_path=str(self.control.lease.path),lock_process_id=__import__('os').getpid()),"quiescence_digest")

    def verify_frozen_candidate_v1(self,candidate):
        original = self.read_quiescence_original_v1(operation_id=candidate.operation_id)
        self.control.verify_original_v1(original,"quiescence_digest")
        return True

    @contextmanager
    def hold_final_continuation_v3(self,*,operation_id):
        # This lock blocks every admission/reset/release path until PREPARED
        # commits; the lease guard also prevents close/reacquire in that span.
        with self.control.lease.hold_continuation_v3():
            with self._condition:
                self.read_quiescence_original_v1(operation_id=operation_id)
                if self._closing_continuation is not None:
                    raise AuthorityUnavailable("C09 final continuation already active")
                token=(object(),operation_id,self._epoch,threading.get_ident())
                self._closing_continuation=token
                try:yield token
                finally:self._closing_continuation=None

    def require_final_continuation_v3(self,token,*,operation_id,observe=True):
        with self._condition:
            if (self._closing_continuation is not token or token[1:]!=(operation_id,self._epoch,threading.get_ident())
                    or self._operation!=operation_id or self._active
                    or self.control.lease._continuation_thread!=threading.get_ident()):
                raise AuthorityUnavailable("C09 continuous final exclusion expired")
            self.control.lease.require_held()
            return self.read_quiescence_original_v1(operation_id=operation_id) if observe else None

    def release_v1(self, *, operation_id):
        with self._condition:
            if self._closing_continuation is not None:
                raise AuthorityUnavailable("C09 cannot release during final continuation")
            context = self.control.read_verified_current_storage_v1()
            if context.stage != "RELEASED" or self._operation != operation_id:
                raise AuthorityUnavailable("C09 gate release needs current RELEASED")
            context.require_current("business")
            self._workers.clear(); self._peers.clear(); self._retired_peers.clear(); self._operation = None


class InstalledC09MaintenanceV1:
    """Installation object. Public maintenance calls accept only operation ID."""
    def __init__(self, *, control, gate, core, closure, graph, namespace_id,
                 accepted_service, inventory_manifest, target_directory,
                 subject, credential, service_handles,
                 surface_services, close_apply_service, current_bundle_factory=None):
        from .core import AuthorityServiceCore
        from .erasure_closure_inventory import AuthorityErasureClosureInventory
        from ..graph_store import ProductionGraphStore
        if (type(control) is not C09StorageControlV1 or type(gate) is not InstalledC09WriterGateV1
                or gate.control is not control or type(core) is not AuthorityServiceCore
                or type(closure) is not AuthorityErasureClosureInventory or closure.core is not core
                or not isinstance(graph, ProductionGraphStore) or set(surface_services) != SURFACES
                or current_bundle_factory is not None and not callable(current_bundle_factory)):
            raise AuthorityUnavailable("complete installed C09 maintenance binding required")
        for service in surface_services.values():
            if any(not callable(getattr(service,name,None)) for name in (
                    "clean_installed_surface_v1","reread_installed_surface_v1")):
                raise AuthorityUnavailable("C09 installed cleaner and independent reader required")
        for method in ("close_verified_cleanup_v1","apply_current_graph_head_v1","read_release_original_v1"):
            if not callable(getattr(close_apply_service,method,None)):
                raise AuthorityUnavailable("C09 actual close/ACK/applied service required")
        if getattr(control,'_final_gate_v3',gate) is not gate:
            raise AuthorityUnavailable("C09 final exclusion gate changed")
        control._final_gate_v3=gate
        self.control,self.gate,self.core,self.closure,self.graph = control,gate,core,closure,graph
        self.namespace_id,self.accepted_service = namespace_id,accepted_service
        self.inventory_manifest = inventory_manifest
        self.target_directory = Path(target_directory).resolve(strict=True)
        if not any(self.target_directory.is_relative_to(root) for root in control._roots):
            raise AuthorityUnavailable("C09 rebuild directory outside registered inventory")
        self.subject,self.credential = subject,credential
        self.service_handles = tuple(service_handles)
        self.current_bundle_factory = current_bundle_factory
        self.surface_services = dict(surface_services)
        self.close_apply_service = close_apply_service
        self._candidate_originals = {}
        self._closed_connection_originals_v3={}
        self._maintenance_lock = threading.RLock()
        self.restart_required = False
        control.install_build_originals_schema_v1()
        core.install_current_c09_storage_reader_v1(reader=control)
        from .current_source_location_v1 import InstalledCurrentSourceLocationQualifierV1
        self.current_source_location = InstalledCurrentSourceLocationQualifierV1(
            fences=close_apply_service.service, scoped=closure.scoped, control=control,
            graph_db_path=graph._db.execute("PRAGMA database_list").fetchone()[2],
            namespace_id=namespace_id, installation_id=control.installation_id)
        closure.install_current_source_location_v1(self.current_source_location)
        if core._c09_maintenance_authority_v1 is None:
            core.install_c09_maintenance_authority_v1(signing_key=control._key,
                inventory_manifest=inventory_manifest,
                writer_freeze_verifier=gate.verify_frozen_candidate_v1)

    def _targets(self,operation_id,generation):
        from .contract import identifier
        identifier(operation_id,"operation_id")
        stem = digest((self.control.installation_id,operation_id,generation))
        targets = {}
        for role in ROLES:
            directory = self.target_directory / role
            directory.mkdir(mode=0o700, exist_ok=True)
            if directory.is_symlink() or directory.resolve(strict=True) != directory:
                raise AuthorityUnavailable("C09 installed role target directory is unsafe")
            targets[role] = str(directory / (stem + ".sqlite"))
        return targets

    def _require_historical_provider_cache_coverage_v1(self, *, operation_id=None):
        """One signed provider absence cannot clear another provider's history."""
        from .v2_model_egress_store import _decoded
        provider = getattr(self.surface_services["model_prompt_caches"], "provider_id", None)
        with self.core._tx() as db:
            present = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='authority_model_egress_v1'").fetchone()
            rows = () if present is None else tuple(db.execute(
                "SELECT call_id,operation_id,namespace,subject,identity_json FROM authority_model_egress_v1 WHERE namespace=?",
                (self.closure.namespace,)))
        providers = set()
        scopes = set()
        commitments = []
        for call, operation, namespace, subject, payload in rows:
            try:
                intent = _decoded(payload)
            except (TypeError, ValueError, KeyError) as exc:
                raise AuthorityUnavailable("C09 historical model provider inventory is unreadable") from exc
            if (intent.call_id, intent.operation_id, intent.namespace, intent.subject) != (call, operation, namespace, subject):
                raise AuthorityUnavailable("C09 historical model provider identity differs")
            providers.add(intent.provider_id)
            scopes.add((intent.provider_id, intent.provider_config_digest))
            commitments.append(canonical_digest((call, operation, namespace, subject, payload)))
        if providers and (type(provider) is not str or providers != {provider}):
            raise AuthorityUnavailable("C09 installed cache cleaner does not cover all historical model providers")
        cleaner = self.surface_services["model_prompt_caches"]
        if scopes:
            check = getattr(cleaner, "require_historical_provider_scopes_v2", None)
            if not callable(check):
                raise AuthorityUnavailable("C09 provider adapter cannot attest historical account/configuration scopes")
            check(tuple(sorted(scopes)))
        if operation_id is not None:
            self.control.record_build_original_v1(operation_id=operation_id, kind="provider_scope_inventory",
                details={"schema": "sylanne3.c09.historical-provider-scopes.v2", "namespace": self.closure.namespace,
                    "installation_id": self.control.installation_id, "provider_config_scopes": sorted(scopes),
                    "source_row_commitments": sorted(commitments)})

    def _checkpoint(self,handle,*,close=False):
        lock = getattr(handle,"_lock",None)
        if lock is None:
            raise AuthorityUnavailable("C09 installed SQLite handle lacks writer lock")
        with lock:
            if getattr(handle, "_closed", False):
                if close and id(handle) not in self._closed_connection_originals_v3:
                    raise AuthorityUnavailable("C09 close flag has no actual local close completion")
                return
            db = getattr(handle,"_db",None)
            if db is not None:
                if db.in_transaction:
                    raise AuthorityUnavailable("C09 SQLite writer still active")
                result = db.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
                if result is not None and result[0] != 0:
                    raise AuthorityUnavailable("C09 SQLite WAL checkpoint blocked")
            if close:
                if db is None:
                    if id(handle) not in self._closed_connection_originals_v3:
                        raise AuthorityUnavailable("C09 handle has no actual close completion")
                    return
                # PRAGMA executes on the connection's permitted thread. A
                # successful exact close call is the evidence, not an error.
                path=db.execute("PRAGMA database_list").fetchone()[2]
                original=dict(handle_type=type(handle).__module__+'.'+type(handle).__qualname__,
                    connection_id=id(db),path=path,process_id=__import__('os').getpid(),thread_id=threading.get_ident())
                handle.close()
                self._closed_connection_originals_v3[id(handle)]=(handle,db,original)

    def _close_old_bundle_v1(self, *, operation_id):
        """Same drain/close boundary for fresh PREPARED and cold recovery."""
        self.gate.revoke_and_drain_v1(operation_id=operation_id)
        seen = set()
        for handle in (*self.service_handles, self.graph, self.closure.execution,
                       self.closure.deletion, self.core):
            if id(handle) not in seen:
                self._checkpoint(handle, close=True)
                seen.add(id(handle))
        return tuple(self._closed_connection_originals_v3[key][2] for key in sorted(seen))

    def read_current_recovery_bindings_v1(self,*,bundle):
        with self.core._tx() as db:
            return read_recovery_bindings_connection_v1(control=self.control, core_db=db,
                execution_reader=self.closure.execution, namespace=self.closure.namespace, bundle=bundle)

    def read_rebased_file_original_v1(self, *, operation_id, role):
        return read_rebased_file_from_control_v1(self.control, operation_id=operation_id, role=role)

    def retain_rebased_file_original_v1(self, *, operation_id, role, file, rows, transition=None):
        return retain_rebased_file_in_control_v1(self.control, operation_id=operation_id, role=role, file=file, rows=rows, transition=transition)

    def retain_candidate_originals_v1(self,*,operation_id,**originals):
        self._candidate_originals[operation_id] = originals
        candidate = originals["candidate"]
        self.control.record_build_original_v1(operation_id=operation_id, kind="storage_candidate",
            details={"candidate": asdict(candidate), "transition": originals["transition"],
                "bindings_digest": originals["bindings"].bindings_digest, "issue_digest": originals["issue"].issue_digest})

    def _seal_prepared(self,*,operation_id,graph_candidate,graph_mirror,candidate):
        with self.gate.hold_final_continuation_v3(operation_id=operation_id) as continuation:
            return self._seal_prepared_under_continuation_v3(operation_id=operation_id,
                graph_candidate=graph_candidate,graph_mirror=graph_mirror,candidate=candidate,continuation=continuation)

    def _seal_prepared_under_continuation_v3(self,*,operation_id,graph_candidate,graph_mirror,candidate,continuation):
        from .c09_authority_storage_rebase import _root,_objects
        from ..runtime.c09_erasure_barrier_store_v1 import read_c09_erasure_barrier_v1
        current = self.control.read_verified_current_storage_v1()
        originals = self._candidate_originals[operation_id]
        bundle = originals["bundle"]
        # The builder drained and closed this exact source before hashing it.
        # A WAL-mode read-only connection can still create sidecars; immutable
        # reads are permitted only while the actual writer gate remains held.
        source_path = Path(graph_candidate.source_path)
        from .d12_sqlite_backup_v2 import sqlite_companions_present_v2
        if sqlite_companions_present_v2(source_path):
            raise AuthorityUnavailable("C09 closed Graph source still has sidecars")
        with closing(sqlite3.connect(source_path.as_uri()+"?mode=ro&immutable=1",uri=True)) as db:
            db.execute("BEGIN")
            barrier = read_c09_erasure_barrier_v1(db,self.namespace_id,operation_id)
        with self.core._tx() as db:
            old_anchor = self.core._anchor(db,self.closure.namespace,self.core._row(db,self.closure.namespace))
        transition = originals["transition"]
        if transition is None:
            raise AuthorityUnavailable("C09 accepted deletion anchor transition absent")
        from .c09_retired_prepared_marker_v1 import verify_retired_prepared_marker_v1
        verify_retired_prepared_marker_v1(core_path=Path(candidate.core.target_path), execution_path=Path(candidate.execution.target_path),
            source_core_path=Path(candidate.core.source_path),
            namespace=self.closure.namespace, operation_id=operation_id, expected_pin_digest=bundle["pin"].pin_digest,
            expected_issue_digest=graph_mirror.core_issue_digest, expected_new_journal_id=candidate.new_execution_journal_id,
            maintenance_generation=current.storage_generation + 1)
        checkpoint = dict(schema="sylanne3.c09.prepared_checkpoint_inputs.v1",
            namespace=self.closure.namespace, operation_id=operation_id,
            old_anchor=asdict(old_anchor), transition=transition,
            accepted_receipt=asdict(bundle["accepted_receipt"]),
            accepted_receipt_digest=canonical_digest(bundle["accepted_receipt"]),
            barrier=asdict(barrier), barrier_digest=canonical_digest(barrier),
            facts_pin=asdict(bundle["pin"]), facts_digest=bundle["facts"].facts_digest,
            bindings_digest=originals["bindings"].bindings_digest, issue=asdict(originals["issue"]),
            inventory=asdict(self.inventory_manifest), graph_mirror=asdict(graph_mirror),
            candidate_digest=candidate.candidate_digest, graph_candidate_digest=graph_candidate.candidate_digest)
        self.control.record_build_original_v1(operation_id=operation_id,
            kind="prepared_checkpoint_inputs_v1", details=checkpoint)
        from .c09_final_inventory_v3 import close_and_scan_current_inventory_v3
        scan = close_and_scan_current_inventory_v3(self,operation_id=operation_id,continuation=continuation,
            graph_candidate=graph_candidate,candidate=candidate)
        from .c09_prepared_assembly_v1 import assemble_prepared_storage_v1
        manifest, prepared = assemble_prepared_storage_v1(control=self.control, current=current,
            operation_id=operation_id, graph_candidate=graph_candidate, graph_mirror=graph_mirror,
            candidate=candidate, checkpoint=checkpoint, scan=scan,
            quiescence=self.gate.read_quiescence_original_v1(operation_id=operation_id))
        self.control.record_prepared_storage_v1(manifest=manifest, prepared_original=prepared,
            closing_continuation=continuation)
        return prepared

    def prepare_storage_rebase_v1(self, *, operation_id):
        with self._maintenance_lock:
            return self._prepare_storage_rebase_v1(operation_id=operation_id)

    def _prepare_storage_rebase_v1(self, *, operation_id):
        from .erasure_closure_inventory import CleanupRunV2,_TABLES
        from ..runtime.c09_graph_rebase_candidate_v1 import build_installed_graph_rebase_candidate_v1,install_verified_graph_rebase_certificate_v1
        from .c09_authority_storage_rebase import build_installed_authority_storage_rebase_candidate_v1
        current = self.control.read_verified_current_storage_v1()
        self._require_historical_provider_cache_coverage_v1()
        with self.core._tx() as db:
            run = self.closure._read_record(db,_TABLES[1],operation_id,CleanupRunV2)
            if run is None:
                raise AuthorityUnavailable("C09 accepted run required before INTENT")
            accepted = self.closure._accepted_locked(db,run,self.subject)
            fence = db.execute("SELECT permit FROM authority_v2_fences WHERE operation_id=?",(accepted.pending.permit.operation_id,)).fetchone()
            from .v2_contract import decode_bytes
            permit = decode_bytes(fence[0])
        quiescence = self.gate.revoke_and_drain_v1(operation_id=operation_id)
        if current.stage in {"READY","RELEASED"}:
            targets = self._targets(operation_id,current.storage_generation+1)
            self.control.record_maintenance_intent_v1(operation_id=operation_id,namespace=self.closure.namespace,
                installed_intent=dict(expected_pointer_version=current.pointer_version,old_manifest_digest=current.manifest_digest,
                    targets=targets,accepted_receipt_digest=canonical_digest(accepted),quiescence_original=quiescence))
        else:
            intent = self.control.read_operation_event_v1(operation_id,"INTENT")
            targets = intent["details"]["targets"]
        # Recompute the complete historical scope after the actual writer drain,
        # then pin it in protected control before any source/candidate sealing.
        self._require_historical_provider_cache_coverage_v1(operation_id=operation_id)
        self.core.prepare_c09_execution_source_v4(credential=self.credential,closure=self.closure,subject=self.subject,operation_id=operation_id)
        self._checkpoint(self.graph,close=True)
        self._checkpoint(self.core)
        self._checkpoint(self.closure.execution)
        self._checkpoint(self.closure.deletion)
        from .c09_build_originals_v1 import decode_installed_build_original_v1
        from ..runtime.c09_graph_rebase_candidate_v1 import GraphRebaseCandidateV1, graph_source_files_fingerprint_v1
        saved = self.control.read_build_original_v1(operation_id=operation_id, kind="graph_candidate")
        if saved is None:
            inventory_view=self.current_source_location.observe_installation_inventory_v1(self.inventory_manifest,
                credential=self.credential,subject=self.subject,accepted_mutation_id=run.accepted_mutation_id)
            graph_candidate = build_installed_graph_rebase_candidate_v1(
                next(Path(m["resolved_path"]) for m in current.manifest["members"] if m["role"] == "graph"),Path(targets["graph"]),
                accepted_service=self.accepted_service,credential=self.credential,subject=self.subject,
                installation_id=self.control.installation_id,namespace=self.namespace_id,operation_id=operation_id,
                permit=permit,inventory_manifest=self.inventory_manifest,pinned_manifest_digest=self.inventory_manifest.manifest_digest,
                writer_freeze_digest=self.control.read_operation_event_v1(operation_id, "INTENT")["details"]["quiescence_original"]["quiescence_digest"],
                completion_control=self.control, registry=self.graph._registry,
                current_inventory_qualifier=self.current_source_location,current_inventory_view=inventory_view)
        else:
            graph_candidate = decode_installed_build_original_v1(saved["details"]["candidate"], GraphRebaseCandidateV1)
            if (graph_candidate.namespace != self.namespace_id or graph_candidate.operation_id != operation_id
                    or graph_candidate.target_path != targets["graph"]
                    or graph_source_files_fingerprint_v1(Path(graph_candidate.source_path)) != graph_candidate.source_files_fingerprint):
                raise AuthorityUnavailable("C09 registered Graph candidate source identity differs")
        from .c09_graph_rebase_issue_v1 import read_graph_rebase_issue_v1_locked
        with self.core._tx() as db:
            issued = read_graph_rebase_issue_v1_locked(db, self.closure.namespace, operation_id=operation_id)
        if issued is None:
            issued = self.core.issue_graph_rebase_certificate_v1(credential=self.credential,closure=self.closure,subject=self.subject,candidate=graph_candidate)
        graph_mirror = install_verified_graph_rebase_certificate_v1(graph_candidate,core=self.core,credential=self.credential,issued=issued, registry=self.graph._registry)
        candidate = build_installed_authority_storage_rebase_candidate_v1(core=self.core,closure=self.closure,maintenance=self,
            operation_id=operation_id,subject=self.subject,credential=self.credential,graph_mirror=graph_mirror,targets=targets)
        return self._seal_prepared(operation_id=operation_id,graph_candidate=graph_candidate,graph_mirror=graph_mirror,candidate=candidate)

    def switch_prepared_storage_v1(self, *, operation_id):
        self._close_old_bundle_v1(operation_id=operation_id)
        original = self.gate.read_quiescence_original_v1(operation_id=operation_id)
        event = self.control.switch_prepared_storage_v1(operation_id=operation_id,quiescence_original=original)
        # Never hot-swap a subset of the daemon's objects: TLS handlers, Owner
        # stores and cached readers still own the old bundle. Only a new OS
        # process may open the switched files and prove cache retirement.
        self.restart_required = True
        return event

    def cleanup_and_release_v1(self, *, operation_id):
        context = self.control.read_verified_current_storage_v1()
        if context.stage not in {"SWITCHED","CLEANED"}:
            raise AuthorityUnavailable("C09 cleanup requires switched current files")
        from .c09_process_identity_v1 import require_process_retired_v1
        intent = self.control.read_operation_event_v1(operation_id, "INTENT")
        switched = self.control.read_operation_event_v1(operation_id, "SWITCHED")
        switch_quiescence = switched["details"].get("quiescence_original")
        if switch_quiescence is None:
            raise AuthorityUnavailable("C09 switching process original unavailable")
        self.control.verify_original_v1(switch_quiescence, "quiescence_digest")
        for original in (intent["details"]["quiescence_original"], switch_quiescence):
            require_process_retired_v1(original["authority_process_original"])
            for key in ("retired_worker_originals", "retired_peer_originals"):
                for retired in original.get(key, []):
                    require_process_retired_v1(retired["original_process"])
        if context.stage == "SWITCHED":
            existing = {o["surface"]:o for o in self.control.read_surface_evidence_v1(operation_id)}
            for surface in sorted(SURFACES):
                service = self.surface_services[surface]
                original = existing.get(surface)
                if original is None:
                    original = service.clean_installed_surface_v1(operation_id=operation_id,storage_reader=self.control)
                    self.control.record_surface_evidence_v1(original)
                reread = service.reread_installed_surface_v1(operation_id=operation_id,storage_reader=self.control,original=original)
                if type(reread) is not dict or reread.get("evidence_digest") != original["evidence_digest"] or reread.get("after_observations") != original["after_observations"]:
                    raise AuthorityUnavailable("C09 independent cleanup reread differs: " + surface)
            originals = self.control.read_surface_evidence_v1(operation_id)
            self.control.record_cleaned_storage_v1(operation_id=operation_id,independently_verified_root=digest([o["evidence_digest"] for o in originals]))
        self.close_apply_service.close_verified_cleanup_v1(operation_id=operation_id)
        self.close_apply_service.apply_current_graph_head_v1(operation_id=operation_id)
        from .c09_model_budget_original_v1 import require_model_budget_release_safe_v1
        with self.core._tx() as db:
            require_model_budget_release_safe_v1(db, namespace=self.closure.namespace)
        release = self.close_apply_service.read_release_original_v1(operation_id=operation_id,storage_reader=self.control)
        self.control.release_cleaned_storage_v1(operation_id=operation_id,release_original=release)
        self.gate.release_v1(operation_id=operation_id)
        return self.control.read_verified_current_storage_v1()

    def resume_storage_maintenance_v1(self, *, operation_id):
        with self._maintenance_lock:
            return self._resume_storage_maintenance_v1(operation_id=operation_id)

    def _resume_storage_maintenance_v1(self, *, operation_id):
        context = self.control.read_verified_current_storage_v1()
        with self.control._db() as db:
            current = self.control._current(db)
            active_operation = current["active_operation_id"]
        if context.stage == "RELEASED" and active_operation == operation_id:
            context.require_current("business")
            return context
        if context.stage not in {"READY", "RELEASED"} and active_operation != operation_id:
            raise AuthorityUnavailable("C09 other maintenance operation is active")
        if self.restart_required:
            return context
        self.gate.revoke_and_drain_v1(operation_id=operation_id)
        if context.stage in {"READY","RELEASED","INTENT"}:
            self.prepare_storage_rebase_v1(operation_id=operation_id)
            context = self.control.read_verified_current_storage_v1()
        if context.stage == "PREPARED":
            self.switch_prepared_storage_v1(operation_id=operation_id)
            return self.control.read_verified_current_storage_v1()
        return self.cleanup_and_release_v1(operation_id=operation_id)


def read_rebased_file_from_control_v1(control, *, operation_id, role):
    from .c09_authority_storage_rebase import RebasedFileV1, RowDispositionV1
    from .c09_build_originals_v1 import decode_installed_build_original_v1, verify_rebased_file_original_v1
    original = control.read_build_original_v1(operation_id=operation_id, kind="file_" + role)
    if original is None:
        return None
    details = original["details"]
    file = decode_installed_build_original_v1(details["file"], RebasedFileV1)
    targets = control.read_operation_event_v1(operation_id, "INTENT")["details"]["targets"]
    if file.target_path != targets[role]:
        raise AuthorityUnavailable("C09 registered rebuilt role/path differs")
    verify_rebased_file_original_v1(file)
    rows = decode_installed_build_original_v1(details["rows"], tuple[RowDispositionV1, ...])
    return file, rows, details["transition"]


def retain_rebased_file_in_control_v1(control, *, operation_id, role, file, rows, transition=None):
    return control.record_build_original_v1(operation_id=operation_id, kind="file_" + role,
        details={"file": asdict(file), "rows": [asdict(row) for row in rows], "transition": transition})


def read_recovery_bindings_connection_v1(*, control, core_db, execution_reader, namespace, bundle):
    if not core_db.in_transaction:
        raise AuthorityUnavailable("C09 bindings need pinned source Core transaction")
    context,frames = InstalledSanitizedRecoveryResolverV4(storage_reader=control).read_verified_frames_v4()
    prior = {}
    for _,_,bindings in frames:
        for binding in bindings.execution_bindings:
            if binding.execution_id in prior and prior[binding.execution_id] != binding:
                raise AuthorityUnavailable("C09 prior typed binding conflict")
            prior[binding.execution_id] = binding
    rows_by_execution = {}
    originals = {}
    for row in bundle["rows"]:
        from .d04_root_execution_contract_v3 import D04RootExecutionBindingV3, root_execution_from_wire_v3
        from .d04_root_execution_journal_v3 import ROOT_ENTRY_PREFIX_V3
        from .d04_numeric_contract_v3 import D04NumericBindingV3, from_wire as numeric_from_wire
        from .d04_numeric_journal_v3 import ENTRY_PREFIX
        from .d04_series_journal_v1 import ENTRY_PREFIX as SERIES_ENTRY_PREFIX, decode_series_row_v1
        from .d11_offline_tick_journal_v1 import ENTRY_PREFIX as OFFLINE_ENTRY_PREFIX, decode_offline_tick_row_v1
        from .d11_life_journal_v1 import ENTRY_PREFIX as LIFE_ENTRY_PREFIX, decode_life_row_v1
        if row[4].startswith(LIFE_ENTRY_PREFIX):
            binding, _claim, _terminal = decode_life_row_v1(execution_reader, row)
            execution, operation, kind = binding.execution_id, binding.operation_id, "life"
            generation = binding.activation_generation
        elif row[4].startswith(OFFLINE_ENTRY_PREFIX):
            binding, _claim, _terminal = decode_offline_tick_row_v1(execution_reader, row)
            execution, operation, kind = binding.execution_id, binding.operation_id, "offline_tick"
            generation = binding.activation_generation
        elif row[4].startswith(SERIES_ENTRY_PREFIX):
            series, _claim, _measurement = decode_series_row_v1(execution_reader, row)
            binding = series.numeric
            execution,operation,kind = binding.execution_id,binding.operation_id,"series"
            generation = binding.activation_generation
        elif row[4].startswith(ROOT_ENTRY_PREFIX_V3):
            binding = root_execution_from_wire_v3(json.loads(row[4])["d04_root_execution_original"]["binding"], D04RootExecutionBindingV3)
            execution,operation,kind = binding.execution_id,binding.operation_id,"authored_root"
            generation = binding.activation_generation
        elif row[4].startswith(ENTRY_PREFIX):
            binding = numeric_from_wire(json.loads(row[4])["d04_numeric_original"]["binding"], D04NumericBindingV3)
            execution,operation,kind = binding.execution_id,binding.operation_id,"numeric"
            generation = binding.activation_generation
        elif row[4].startswith(b'{"binding":'):
            from .internal_work_contract import InternalWorkBindingV1
            binding = InternalWorkBindingV1(**json.loads(row[4])["binding"])
            execution,operation,kind = binding.execution_id,binding.operation_id,"internal"
            generation = binding.activation_generation
        else:
            from .v2_contract import decode_bytes
            pending = decode_bytes(row[4]); binding = pending
            execution,operation,kind = pending.permit.effect_id,pending.permit.operation_id,"dispatch"
            generation = pending.permit.generation
        commitment = canonical_digest((row[0],row[1],row[2],row[3],row[5],row[6],__import__('hashlib').sha256(row[4]).hexdigest()))
        rows_by_execution.setdefault(execution,[]).append(commitment)
        if execution in originals and originals[execution][:3] != (operation,kind,generation):
            raise AuthorityUnavailable("C09 original business execution binding differs")
        originals[execution] = (operation,kind,generation,binding)
    from .c09_model_budget_original_v1 import read_model_budget_originals_v1, model_unit_fact_v4
    model_originals = read_model_budget_originals_v1(core_db, namespace=namespace, operation_id=bundle["seal"].operation_id)
    for original in model_originals:
        if original.call_id in originals:
            raise AuthorityUnavailable("C09 model call collides with an independent execution identity")
        originals[original.call_id] = (original.model_operation_id, "model", original.dispatch_generation, original)
        rows_by_execution[original.call_id] = [*original.source_row_commitments, original.original_digest]
    for fact in bundle["facts"].executions:
        if fact.execution_id in prior:
            raise AuthorityUnavailable("C09 suffix reused prior execution identity")
        found = originals.get(fact.execution_id)
        if found is None:
            raise AuthorityUnavailable("C09 original business operation absent")
        operation,kind,generation,original = found
        d02_quotes,d02_components,d11_settlements = (),(),()
        if kind == "internal":
            d02_quotes = tuple(sorted(f.quote_id for f in bundle["facts"].d02_facts if f.quote_id == original.resource_quote_ref))
            d02_components = tuple(sorted(f.component_id for f in bundle["facts"].d02_facts if f.component_id == original.component_id))
            d11_settlements = tuple(sorted(f.settlement_id for f in bundle["facts"].d11_facts
                if f.parent_budget_id == original.parent_budget_lease_ref
                and f.idempotency_id == "c04-internal-budget:" + original.binding_digest))
        elif kind in {"numeric", "series", "authored_root", "offline_tick", "life"}:
            d11_settlements = tuple(sorted(f.settlement_id for f in bundle["facts"].d11_facts
                if f.parent_budget_id == original.parent_budget_lease_ref
                and f.idempotency_id == original.reservation_operation_id))
        elif kind == "model":
            d11_settlements = tuple(sorted(model_unit_fact_v4(original, unit).settlement_id
                for unit in original.units if unit.actual_or_none is not None))
        prior[fact.execution_id] = C09ExecutionBindingV1(fact.execution_id,operation,kind,
            fact.input_commitment,operation,bundle["seal"].execution_journal_id,
            tuple(sorted(rows_by_execution[fact.execution_id])),d02_quotes,d02_components,
            d11_settlements,generation,None)
    body = dict(authority_id=control.authority_id,installation_id=control.installation_id,
        namespace=namespace,operation_id=bundle["seal"].operation_id,
        prior_transition_digest_or_none=None if context.prepared_original is None else context.prepared_original["prepared_digest"],
        prior_fact_frame_digests=tuple(facts.facts_digest for _,facts,_ in frames),
        execution_bindings=tuple(item for _,item in sorted(prior.items())),facts_digest=bundle["facts"].facts_digest)
    committed = canonical_digest(tuple(body[f.name] for f in fields(C09RecoveryBindingsV1) if f.name != "bindings_digest"))
    return C09RecoveryBindingsV1(**body,bindings_digest=committed)
