"""Installed C09 maintenance gate and four-store prepare/switch/resume flow."""
from __future__ import annotations

from ..runtime.c09_paged_sql_v2 import current_c09_sql_meter_v2

from contextlib import contextmanager, closing
from dataclasses import asdict, fields
import json
from pathlib import Path
import sqlite3
import threading
from weakref import WeakSet

from ..runtime_contracts import canonical_digest, canonical_serialize
from ..runtime.c09_storage_transition_v1 import C09ExecutionBindingV1,C09RecoveryBindingsV1
from .contract import AuthorityUnavailable
from .c09_storage_control_v1 import C09StorageControlV1,SURFACES,ROLES,canonical,digest,file_observation_v1,_regular_path
from .c09_recovery_resolver_v4 import InstalledSanitizedRecoveryResolverV4,read_recovery_bindings_v1_locked


_PEER_REGISTRY_ACTIVATIONS_V3=WeakSet()
_PEER_REGISTRY_ACTIVATION_ISSUER_V3=object()


class VerifiedInstalledPeerRegistryActivationV3:
    """Exact installed process census and continuous Gate exclusion, never wire permission."""
    def __init__(self,issuer,*,control,gate,qualification,hold_token,meter):
        if issuer is not _PEER_REGISTRY_ACTIVATION_ISSUER_V3:
            raise AuthorityUnavailable('actual installed registry activation issuer required')
        from .c09_writer_peer_activation_v3 import InstalledPeerRegistryCensusV3
        if type(qualification) is InstalledPeerRegistryCensusV3:
            qualification.require_current(control=control,gate=gate,meter=meter)
        else:
            from ..host.c09_controlled_sdk_bootstrap_v3 import VerifiedControlledSDKInstallerOriginalV3
            if type(qualification) is not VerifiedControlledSDKInstallerOriginalV3:
                raise AuthorityUnavailable('actual Root or controlled SDK installer process census required')
            qualification.require_current(gate=gate,control=control,config=gate._installed_config_v3,meter=meter)
        gate.require_peer_registry_activation_hold_v3(hold_token)
        self.control,self.gate,self.qualification,self.hold_token=control,gate,qualification,hold_token
        self.summary=qualification.activation_summary_v3(control=control,gate=gate,meter=meter)
        _PEER_REGISTRY_ACTIVATIONS_V3.add(self)

    def require_current(self,*,control,gate,meter):
        if self not in _PEER_REGISTRY_ACTIVATIONS_V3 or self.control is not control or self.gate is not gate:
            raise AuthorityUnavailable('actual installed registry activation changed its issuer or Gate')
        gate.require_peer_registry_activation_hold_v3(self.hold_token)
        if self.summary['mode']=='controlled_sdk_genesis':
            self.qualification.require_current(gate=gate,control=control,config=gate._installed_config_v3,meter=meter)
        else:self.qualification.require_current(control=control,gate=gate,meter=meter)
        return self

    def require_activation_original_for_gate_v3(self,original,*,control,gate,meter):
        if (self not in _PEER_REGISTRY_ACTIVATIONS_V3 or self.control is not control or self.gate is not gate
                or self.summary['mode']!='controlled_sdk_genesis'):
            raise AuthorityUnavailable('actual same-installation controlled SDK qualification required')
        self.qualification.require_activation_original_for_gate_v3(original,control=control,gate=gate,meter=meter)


class InstalledC09WriterGateV1:
    """Installation-wide admission epoch; real writers hold this shared gate."""
    def __init__(self, *, control, installed_config=None):
        if type(control) is not C09StorageControlV1:
            raise AuthorityUnavailable("installed C09 gate requires control authority")
        self.control = control
        from .deployment_config import AuthorityDeploymentConfig
        if installed_config is not None and type(installed_config) is not AuthorityDeploymentConfig:
            raise AuthorityUnavailable("actual installed deployment config required for durable peer admission")
        self._installed_config_v3=installed_config
        self._installed_maintenance_v3=None
        self._peer_admission_originals_v3={}
        self._peer_retirement_coverage_v3=None
        self._condition = threading.Condition(threading.RLock())
        self._active = 0
        self._operation = None
        self._epoch = 0
        self._workers = {}
        self._peers = {}
        self._retired_peers = []
        self._peer_retirement_handler = None
        self._closing_continuation=None
        self._peer_registry_activation_hold_v3=None
        self._controlled_sdk_activation_v3=None

    @contextmanager
    def hold_peer_registry_activation_v3(self):
        """Keep actual Gate admissions excluded through registry activation commit."""
        with self.control.lease.hold_continuation_v3():
            with self._condition:
                if (self._peer_registry_activation_hold_v3 is not None
                        or self._operation is not None or self._active):
                    raise AuthorityUnavailable("installed peer registry activation exclusion unavailable")
                token=(object(),self,threading.get_ident(),self._epoch)
                self._peer_registry_activation_hold_v3=token
                try:
                    yield token
                finally:
                    self._peer_registry_activation_hold_v3=None

    def require_peer_registry_activation_hold_v3(self, token):
        if (self._peer_registry_activation_hold_v3 is not token
                or token[1:]!=(self,threading.get_ident(),self._epoch)
                or self._operation is not None or self._active):
            raise AuthorityUnavailable("actual continuous peer registry Gate exclusion ended")
        self.control.lease.require_held()

    def require_registry_activation_domain_v3(self, original, *, meter):
        schema=original.get('schema')
        if schema=='sylanne3.c09.writer-peer-registry-activation.v3':
            from .c09_writer_peer_activation_v3 import InstalledPeerRegistryCensusV3
            census=self._installed_config_v3.c09_maintenance_factory._peer_registry_census_v3
            if (type(census) is not InstalledPeerRegistryCensusV3
                    or census.supervisor.config.spec_digest!=original['activation_basis']['supervisor_spec_digest']):
                raise AuthorityUnavailable('production registry activation lacks its actual installed Root startup exclusion')
            return
        if schema!='sylanne3.c09.writer-peer-registry-activation.controlled-sdk.v3':
            raise AuthorityUnavailable("unknown installed peer registry activation domain")
        qualification=self._controlled_sdk_activation_v3
        if (type(qualification) is not VerifiedInstalledPeerRegistryActivationV3
                or qualification not in _PEER_REGISTRY_ACTIVATIONS_V3):
            raise AuthorityUnavailable("controlled SDK activation has no installed private SDK qualification")
        qualification.require_activation_original_for_gate_v3(original,
            control=self.control,gate=self,meter=meter)

    def install_pending_start_supervisor_v3(self,supervisor):
        from .installed_process_supervisor_v1 import InstalledRootProcessSupervisorV1
        if (type(supervisor) is not InstalledRootProcessSupervisorV1 or supervisor._peer_registry_gate_v3 is not self
                or supervisor._peer_registry_control_v3 is not self.control
                or getattr(self,'_pending_start_supervisor_v3',None) is not None):
            raise AuthorityUnavailable('one actual installed Root pending-start supervisor required')
        self._pending_start_supervisor_v3=supervisor

    def require_pending_start_bootstrap_scope_v3(self,*,meter):
        from .installed_process_supervisor_v1 import RootPeerStartCoverageHoldV3
        from ..host.c09_controlled_sdk_bootstrap_v3 import VerifiedControlledSDKProcessCensusV3
        hold=self._pending_start_bootstrap_hold_v3
        if type(hold) is RootPeerStartCoverageHoldV3:
            hold.require_current(control=self.control,gate=self,meter=meter)
        elif type(hold) is VerifiedControlledSDKProcessCensusV3:
            hold.require_current()
            scope=hold.original['selection_scope']
            if (scope['authority_id']!=self.control.authority_id or scope['installation_id']!=self.control.installation_id
                    or scope['control_store_id']!=self.control.control_store_id):
                raise AuthorityUnavailable('actual SDK bootstrap pending EOF belongs to another installation')
        else:raise AuthorityUnavailable('actual continuous Root pending EOF bootstrap scope required')
        return hold

    def resolve_pending_start_coverage_v3(self,pending):
        from .installed_process_supervisor_v1 import RootPeerStartCoverageHoldV3
        from .c09_process_identity_v1 import read_process_identity_v1
        hold=getattr(self,'_pending_start_bootstrap_hold_v3',None)
        if pending['root_process_original']!=read_process_identity_v1(1):
            from .installed_root_lifetime_observer_v3 import (read_installed_old_root_retirement_v3,
                VerifiedInstalledRootCohortRetirementV3)
            retirement=read_installed_old_root_retirement_v3(control=self.control,gate=self,pending=pending)
            if type(retirement) is not VerifiedInstalledRootCohortRetirementV3:return retirement
            try:
                physical=self.control.retain_writer_peer_old_root_retirement_v3(self,retirement=retirement)
                completion=self.control.read_writer_peer_pending_start_completion_v3(self,pending_start_original=pending)
                if completion is None:
                    completion=self.control.complete_writer_peer_pending_start_old_cohort_v3(self,retirement=retirement)
                if type(hold) is RootPeerStartCoverageHoldV3:
                    hold.ack_old_root_pending_v3(pending,physical,completion)
                return completion
            finally:retirement.close()
        if type(hold) is RootPeerStartCoverageHoldV3:cap=hold.resolve_pending_v3(pending)
        else:
            supervisor=self._pending_start_supervisor_v3
            cap=supervisor.resolve_pending_peer_start_v3(pending)
        completion=self.control.read_writer_peer_pending_start_completion_v3(self,pending_start_original=pending)
        if completion is None:completion=self.control.complete_writer_peer_pending_start_v3(self,observed_start=cap)
        if type(hold) is RootPeerStartCoverageHoldV3:hold.ack_pending_v3(completion)
        else:cap.baseline.close(completion)
        return completion

    def install_current_maintenance_v3(self, maintenance):
        if (type(maintenance) is not InstalledC09MaintenanceV1 or maintenance.gate is not self
                or maintenance.control is not self.control
                or maintenance._installed_deployment_config_v2 is not self._installed_config_v3
                or self._installed_maintenance_v3 is not None):
            raise AuthorityUnavailable("actual same-config maintenance composition required for durable peer retirement")
        self._installed_maintenance_v3=maintenance

    def _current_context_v3(self, *, action, verify_files=True):
        from .daemon import _bootstrap_control_quantum_v3
        with _bootstrap_control_quantum_v3(self.control) as meter:
            context=self.control.read_verified_current_storage_v2(meter=meter,verify_files=verify_files)
            context.require_current(action)
            return context

    def install_peer_retirement_handler_v1(self, handler):
        with self._condition:
            if self._peer_retirement_handler is not None or not callable(handler) or self._operation is not None:
                raise AuthorityUnavailable("C09 installed peer supervisor already bound or invalid")
            self._peer_retirement_handler = handler

    def retire_previous_peer_before_host_start_v3(self, *, peer):
        from .c09_process_identity_v1 import require_process_retired_v1
        with self._condition:
            if self._operation is not None or self._active or self._peer_registry_activation_hold_v3 is not None:
                raise AuthorityUnavailable('prior Host requests must drain before actual process replacement')
            prior=self._peers.get(peer)
            if prior is not None:
                retired=require_process_retired_v1(prior[4])
                self._retired_peers.append(retired)
                del self._peers[peer]
                self._peer_admission_originals_v3.pop(peer,None)

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
            if self._peer_registry_activation_hold_v3 is not None:
                raise AuthorityUnavailable("actual peer registry activation excludes Host and writer admission")
            context=self._current_context_v3(action="business")
            config=self._installed_config_v3
            if config is None or peer not in config.installations_v2:
                raise AuthorityUnavailable("actual installed peer registry is required for admission")
            namespace=context.manifest["cohort_namespaces"][0]
            if (config.installations_v2[peer].installation_id!=self.control.installation_id
                    or not any(key[:2]==peer and value==namespace for key,value in config.namespace_bindings_v2.items())):
                raise AuthorityUnavailable("peer profile is outside the installed selected namespace")
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
            original=self.control.retain_writer_peer_admission_v3(self,peer=peer,
                process_incarnation=process_incarnation,process_original=identity,context=context)
            # The durable original commits before this process receives its live capability.
            self._peer_admission_originals_v3[peer]=original
            self._peers[peer]=admission
            return original

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
            if self._peer_registry_activation_hold_v3 is not None:
                raise AuthorityUnavailable("actual peer registry activation excludes Host and writer admission")
            context=self._current_context_v3(action="business")
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
            if self._peer_registry_activation_hold_v3 is not None:
                raise AuthorityUnavailable("actual peer registry activation excludes Host and writer admission")
            context=self._current_context_v3(action="business")
            if self._operation is not None or (pointer_version,storage_generation) != (context.pointer_version,context.storage_generation) or process_incarnation in self._workers:
                raise AuthorityUnavailable("C09 worker admission conflict")
            from .c09_process_identity_v1 import read_process_identity_v1
            identity = read_process_identity_v1(process.pid)
            if identity is None or process.poll() is not None:
                raise AuthorityUnavailable("C09 actual worker process is not live")
            self._workers[process_incarnation] = (process,pointer_version,storage_generation,identity)

    def advance_peer_retirement_coverage_v3(self, *, operation_id):
        """Revoke actual admission and advance one durable OS-retirement obligation."""
        from .c09_writer_peer_originals_v3 import VerifiedPeerRetirementCoverageV3
        with self._condition:
            self.control.lease.require_held()
            if self._operation not in {None,operation_id}:
                raise AuthorityUnavailable("another actual maintenance gate is active")
            if self._operation is None:
                self._epoch+=1
                self._operation=operation_id
        result=self.control.advance_writer_peer_retirement_coverage_v3(self,operation_id=operation_id)
        if type(result) is VerifiedPeerRetirementCoverageV3:
            self._peer_retirement_coverage_v3=result
            return result
        if result["phase"]=="writer_peer_pending_start":
            self.resolve_pending_start_coverage_v3(result['pending_start_original'])
            return result
        if result["phase"]=="writer_peer_waiting_retirement":
            handler=self._peer_retirement_handler
            if handler is None:
                raise AuthorityUnavailable("actual recorded peer remains live; installed retirement supervisor required")
            # The process observation came from the HMAC-verified durable admission.
            # Its real installed supervisor runs outside the Gate's condition lock.
            handler((result["process_original"],))
        return result

    def restore_prepared_peer_retirement_v3(self, *, operation_id, context):
        """Bind signed old-selection retirement EOF after the actual pointer switch."""
        from .c09_writer_peer_originals_v3 import VerifiedPreparedPeerRetirementCoverageV3
        proof=self.control.read_writer_peer_retirement_coverage_for_prepared_v3(
            self,operation_id=operation_id,context=context)
        if type(proof) is not VerifiedPreparedPeerRetirementCoverageV3:
            raise AuthorityUnavailable("actual prepared peer retirement coverage required")
        with self._condition:
            if self._operation not in {None,operation_id} or self._active or self._peers:
                raise AuthorityUnavailable("prepared peer retirement cannot replace current live admission")
            if self._operation is None:
                self._epoch+=1
                self._operation=operation_id
            self._peer_retirement_coverage_v3=proof
        return proof

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
            from .c09_writer_peer_originals_v3 import (
                VerifiedPeerRetirementCoverageV3,VerifiedPreparedPeerRetirementCoverageV3)
            from .daemon import _bootstrap_control_quantum_v3
            coverage=self._peer_retirement_coverage_v3
            if (type(coverage) not in {VerifiedPeerRetirementCoverageV3,VerifiedPreparedPeerRetirementCoverageV3}
                    or coverage.operation_id!=operation_id):
                raise AuthorityUnavailable("complete durable peer retirement EOF required before writer freeze")
            with _bootstrap_control_quantum_v3(self.control) as meter:
                coverage.require_current(meter=meter)
            peer_completion=coverage.original
            retired = [require_process_retired_v1(identity) for _p,_v,_g,identity in self._workers.values()]
            retired_peers = list(self._retired_peers) + [require_process_retired_v1(admission[4])
                for _, admission in sorted(self._peers.items())]
            context=self._current_context_v3(action="maintenance",verify_files=False)
            return self.control.sign_original_v1("sylanne3.c09.writer_quiescence.v3",dict(
                schema="sylanne3.c09.writer_quiescence.v3",installation_id=self.control.installation_id,
                operation_id=operation_id,pointer_version=context.pointer_version,
                storage_generation=context.storage_generation,revoked_admission_epoch=self._epoch,
                active_writers=0,exited_workers=sorted((name,p.pid,version,generation,p.poll()) for name,(p,version,generation,_identity) in self._workers.items()),
                retired_worker_originals=retired, retired_peer_originals=retired_peers,
                writer_peer_retirement_complete_original_digest=peer_completion["completion_digest"],
                writer_peer_retirement_count=peer_completion["admission_count"],
                writer_peer_retirement_root=peer_completion["retirement_root"],
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
            context=self._current_context_v3(action="maintenance")
            if context.stage != "RELEASED" or self._operation != operation_id:
                raise AuthorityUnavailable("C09 gate release needs current RELEASED")
            context.require_current("business")
            self._workers.clear();self._peers.clear();self._retired_peers.clear()
            self._peer_admission_originals_v3.clear()
            self._peer_retirement_coverage_v3=None
            self._operation=None


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
        close_apply_service._maintenance_v3 = self
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

    def advance_current_c09_prepared_preflight_v2(self):
        from .c09_paged_capture_control_v2 import InstalledC09PagedCaptureControlV2
        control = getattr(self, "_paged_capture_control_v2", None)
        if control is None:
            control = InstalledC09PagedCaptureControlV2(self)
            self._paged_capture_control_v2 = control
        return control.advance_selected_prepared_preflight_v2()

    def begin_current_c09_capture_v2(self, *, operation_id):
        from .c09_paged_capture_control_v2 import begin_current_c09_capture_v2
        return begin_current_c09_capture_v2(self, operation_id)

    def prepare_storage_rebase_v1(self, *, operation_id):
        """Actual progressive V3 capture; the legacy whole-frame prepare is retired."""
        from .c09_maintenance_actor_v3 import prepare_current_storage_v3
        return prepare_current_storage_v3(self, operation_id=operation_id)

    def switch_prepared_storage_v1(self, *, operation_id):
        """Progress the actual V3 switch; request cold restart only after its CAS."""
        self._close_old_bundle_v1(operation_id=operation_id)
        original = self.gate.read_quiescence_original_v1(operation_id=operation_id)
        from .c09_prepared_storage_v3 import advance_prepared_switch_v3
        progress = advance_prepared_switch_v3(self.control, operation_id=operation_id,
            quiescence_original=original)
        progress["operation_id"] = operation_id
        if progress["status"] == "complete":
            self.restart_required = True
        return progress

    def cleanup_and_release_v1(self, *, operation_id):
        from .c09_selected_history_v3 import advance_selected_obligation_coverage_v3, VerifiedSelectedHistoryReadV3
        view = getattr(self.control, '_selected_history_read_v3', None)
        if type(view) is VerifiedSelectedHistoryReadV3:
            for consumer in ('execution_cleanup', 'model_release'):
                progress = advance_selected_obligation_coverage_v3(self, view=view, consumer=consumer)
                if progress['status'] != 'complete':
                    return progress
                setattr(self.control, '_selected_' + consumer + '_certificate_v3', progress['certificate'])
            return self._advance_selected_cleanup_v3(operation_id=operation_id, view=view)
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
            require_model_budget_release_safe_v1(db, namespace=self.closure.namespace, meter=current_c09_sql_meter_v2())
        release = self.close_apply_service.read_release_original_v1(operation_id=operation_id,storage_reader=self.control)
        self.control.release_cleaned_storage_v1(operation_id=operation_id,release_original=release)
        self.gate.release_v1(operation_id=operation_id)
        return self.control.read_verified_current_storage_v1()

    def _advance_selected_cleanup_v3(self, *, operation_id, view):
        # All source obligations are qualified before any managed bytes disappear.
        control = self._paged_capture_control_v2
        with control.reserve_selected_history_quantum_v2(view) as meter:
            context = self.control.read_verified_current_storage_v3(meter=meter)
            if context.prepared_original['operation_id'] != operation_id:
                raise AuthorityUnavailable('actual selected cleanup operation differs')
            phase = getattr(self, '_selected_cleanup_phase_v3', 'surfaces')
            if phase == 'surfaces':
                existing = {item['surface']: item for item in self.control.read_surface_evidence_v1(operation_id)}
                verified = getattr(self, '_selected_verified_surfaces_v3', None)
                if verified is None:
                    verified = {};self._selected_verified_surfaces_v3 = verified
                for surface in sorted(SURFACES):
                    original = existing.get(surface)
                    if original is not None and verified.get(surface) == original['evidence_digest']:
                        continue
                    service = self.surface_services[surface]
                    if original is None:
                        if hasattr(service, 'advance_installed_surface_v3'):
                            progress = service.advance_installed_surface_v3(operation_id=operation_id, storage_reader=self.control,
                                view=view, meter=meter)
                            if progress['status'] != 'complete':return progress
                            original = progress['original']
                        else:
                            original = service.clean_installed_surface_v1(operation_id=operation_id, storage_reader=self.control)
                        self.control.record_surface_evidence_v1(original)
                        return dict(status='progress', phase='surface_evidence_recorded', surface=surface)
                    if hasattr(service, 'advance_installed_surface_reread_v3'):
                        progress = service.advance_installed_surface_reread_v3(operation_id=operation_id, storage_reader=self.control,
                            view=view, meter=meter, original=original)
                        if progress['status'] != 'complete':return progress
                        if progress['original'] != original:
                            raise AuthorityUnavailable('actual independent selected surface original differs: ' + surface)
                    else:
                        reread = service.reread_installed_surface_v1(operation_id=operation_id, storage_reader=self.control, original=original)
                        if reread.get('evidence_digest') != original['evidence_digest'] or reread.get('after_observations') != original['after_observations']:
                            raise AuthorityUnavailable('actual independent selected cleanup surface differs: ' + surface)
                    verified[surface] = original['evidence_digest']
                    return dict(status='progress', phase='surface_independently_verified', surface=surface)
                self.control.record_cleaned_storage_v1(operation_id=operation_id,
                    independently_verified_root=digest([existing[name]['evidence_digest'] for name in sorted(SURFACES)]))
                self._selected_cleanup_phase_v3 = 'close'
                return dict(status='progress', phase='CLEANED')
            if phase == 'close':
                progress = self.close_apply_service.advance_selected_close_v3(operation_id=operation_id, view=view, meter=meter)
                if progress['status'] == 'complete':
                    self._selected_cleanup_phase_v3 = 'apply'
                return dict(progress, status='progress')
            if phase == 'apply':
                progress = self.close_apply_service.advance_selected_graph_application_v3(operation_id=operation_id, view=view, meter=meter)
                if progress['status'] == 'complete':
                    self._selected_cleanup_phase_v3 = 'release'
                return dict(progress, status='progress')
            certificate = self.control._selected_model_release_certificate_v3
            self.control.verify_original_v1(certificate, 'checkpoint_digest')
            if certificate['details']['eof'] is not True or certificate['details']['unknown_present']:
                raise AuthorityUnavailable('actual complete model coverage retains pending or unknown debt')
            release = self.close_apply_service.read_release_original_v1(operation_id=operation_id, storage_reader=self.control)
            self.control.release_cleaned_storage_v1(operation_id=operation_id, release_original=release)
            self.gate.release_v1(operation_id=operation_id)
            return dict(status='complete', phase='RELEASED', stage='RELEASED', restart_required=False,
                current_manifest_digest=context.manifest_digest, pointer_version=context.pointer_version,
                storage_generation=context.storage_generation)

    def bind_current_thread_actor_v3(self, *, operation_id):
        """Register the actual installed actor before activating physical maintenance readers."""
        from .c09_maintenance_actor_v3 import InstalledC09MaintenanceActorV3
        from .c09_paged_capture_control_v2 import InstalledC09PagedCaptureControlV2
        self.core._require(self.credential, 'delete', self.closure.namespace)
        owner = threading.get_ident()
        with self._maintenance_lock:
            existing_owner = getattr(self, '_c09_actor_host_thread_v3', None)
            if existing_owner is not None and existing_owner != owner:
                raise AuthorityUnavailable('actual installed C09 host thread changed')
            self._c09_actor_host_thread_v3 = owner
            capture_control = getattr(self, '_paged_capture_control_v2', None)
            if capture_control is None:
                capture_control = InstalledC09PagedCaptureControlV2(self)
                self._paged_capture_control_v2 = capture_control
            capture_control._registered()
            actor = getattr(self, '_maintenance_actor_v3', None)
            if actor is None:
                actor = InstalledC09MaintenanceActorV3(self, operation_id)
                actor.owner_thread = owner
                self._maintenance_actor_v3 = actor
            elif actor.operation_id != operation_id or actor.thread is not None or actor.owner_thread != owner:
                raise AuthorityUnavailable('actual installed actor is owned by another operation or thread')
            return actor

    def advance_storage_maintenance_current_thread_v3(self, *, operation_id):
        """The installed bounded queue host owns all continuation calls on one thread."""
        owner = threading.get_ident()
        existing = getattr(self, '_c09_actor_host_thread_v3', None)
        if existing is None:
            if getattr(self, '_maintenance_actor_v3', None) is not None:
                raise AuthorityUnavailable('actual C09 actor already has another thread owner')
            self._c09_actor_host_thread_v3 = owner
        elif existing != owner:
            raise AuthorityUnavailable('actual C09 maintenance host thread changed')
        return self.resume_storage_maintenance_v1(operation_id=operation_id)

    def resume_storage_maintenance_v1(self, *, operation_id):
        with self._maintenance_lock:
            return self._resume_storage_maintenance_v1(operation_id=operation_id)

    def _resume_storage_maintenance_v1(self, *, operation_id):
        actor = getattr(self, '_maintenance_actor_v3', None)
        if actor is not None and actor.operation_id == operation_id:
            snapshot = actor.snapshot()
            if snapshot['status'] in {'progress', 'failed'}:
                if snapshot['status'] == 'progress' and getattr(self, '_c09_actor_host_thread_v3', None) is not None:
                    return actor.advance_one_quantum_v3()
                return snapshot
        status = self.control.read_verified_control_status_v3()
        status["operation_id"] = operation_id
        if status["status"] != "complete":
            return status
        stage, active = status["stage"], status["active_operation_id"]
        if stage not in {"READY", "RELEASED"} and active != operation_id:
            raise AuthorityUnavailable("C09 other maintenance operation is active")
        if self.restart_required:
            return dict(status, status="complete", phase="SWITCHED", restart_required=True)
        is_v3 = status["manifest_schema"] == "sylanne3.c09.storage_manifest.v3"
        if is_v3 and stage in {"INTENT", "PREPARED", "SWITCHED", "CLEANED", "RELEASED"}:
            from .c09_selected_history_v3 import VerifiedSelectedHistoryReadV3
            selected = self.control.advance_selected_history_read_v3()
            if type(selected) is not VerifiedSelectedHistoryReadV3:
                progress = dict(status)
                progress.update(selected)
                progress['operation_id'] = operation_id
                return progress
            status["storage_generation"] = selected.basis.manifest["generation"]
        if stage == "RELEASED" and active == operation_id:
            if is_v3:
                from .c09_close_apply_v1 import SelectedAppliedReadV3
                applied = self.control.advance_selected_storage_applied_read_v3()
                if type(applied) is not SelectedAppliedReadV3:
                    progress = dict(status)
                    progress.update(applied)
                    return progress
            context = self.control.read_verified_current_storage_v3() if is_v3 else self.control.read_verified_current_storage_v1()
            context.require_current("business")
            return dict(status, status="complete", phase="RELEASED", restart_required=False)
        if stage in {"READY", "RELEASED", "INTENT"}:
            progress = self.prepare_storage_rebase_v1(operation_id=operation_id)
            result = dict(status, **progress)
            if progress["status"] != "complete":
                return result
            # The actor has retained the actual PREPARED event. Read its CAS status
            # in the next request; its old selected source is not a new opener.
            return dict(result, status="progress", phase="PREPARED")
        self.gate.revoke_and_drain_v1(operation_id=operation_id)
        if stage == "PREPARED":
            return dict(status, **self.switch_prepared_storage_v1(operation_id=operation_id),
                restart_required=self.restart_required)
        progress = self.cleanup_and_release_v1(operation_id=operation_id)
        if type(progress) is dict:
            return dict(status, **progress)
        return dict(status, status="complete", phase="RELEASED", storage_generation=progress.storage_generation,
            pointer_version=progress.pointer_version, current_manifest_digest=progress.manifest_digest,
            stage=progress.stage, restart_required=False)


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
    model_originals = read_model_budget_originals_v1(core_db, namespace=namespace, operation_id=bundle["seal"].operation_id, meter=current_c09_sql_meter_v2())
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
