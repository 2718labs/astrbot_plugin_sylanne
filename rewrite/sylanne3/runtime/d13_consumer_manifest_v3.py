"""Private fresh-install D13 consumer composition and actual empty inventory EOF.

Only the original Root genesis hold can issue this manifest. An old cohort,
nonempty durable original or missing consumer remains HOLD; this module never
classifies history as audit-only and never opens another database connection.
"""
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import asdict,replace
from pathlib import Path
from threading import get_ident
import json
from weakref import WeakKeyDictionary,ref

from ..authority_service.contract import AuthorityUnavailable
from ..runtime_contracts import canonical_digest,canonical_serialize

_ISSUER = object()
_MANIFESTS = WeakKeyDictionary()
_KINDS = (
    ('authority_source_receiver', 3), ('graph_source_receiver', 3),
    ('counter_frame_draft', 3), ('natural_generation_original', 3),
    ('natural_review_original', 3), ('graph_natural_original_receiver', 3),
)
_GRAPH_TABLES = (
    'graph_natural_generation_preparations_v2', 'graph_natural_review_preparations_v2',
    'graph_d11_derived_cache_payloads_v1', 'graph_d13_derived_activations_v6',
)
_CORE_TABLES = (
    'authority_d13_counter_originals_v1', 'authority_model_egress_v1',
    'authority_model_egress_bindings_v1', 'authority_model_egress_observations_v1',
    'authority_model_egress_observation_status_v1', 'authority_model_admissions_v2',
    'authority_model_original_identity_v2', 'authority_model_no_dispatch_witnesses_v1',
    'authority_d13_cache_use_pins_v2', 'authority_d13_cache_use_operations_v2',
    'authority_d13_cache_reclaim_seals_v2', 'authority_d13_cache_use_totals_v2',
)


def installed_d13_consumer_cohort_digest_v3():
    """Stable cohort names/versions, independent of either policy signature."""
    return canonical_digest(('sylanne3.d13.actual-consumer-cohort.v3',_KINDS,
        ('production-runtime-context-consumer-ready.v3','controlled-sdk-worker-ready-and-drain.v3',
         'authority-core-incarnation-birth.v4','production-root-authority-observation-held.v4',
         'current-bootstrap-core-birth-and-receiver-retirement.v4','controlled-sdk-actual-root-phase-retirement.v4',
         'explicit-initial-segmented-genesis-and-counter-empty-prefix.v4','controlled-sdk-never-started-initial-creation.v4','exact-current-installation-core-birth-inventory.v4','independent-host-graph-live-storage-custody.v4','installed-d13-accounting-metadata-producer.v3')))


def _actual_components_v3():
    # Capture actual installed code objects, never caller-supplied paths/methods.
    from ..authority_service.current_authority_graph_read_v3 import (
        AuthorityGraphReadWorkV3, advance_authority_graph_read_work_v3)
    from ..authority_service.d13_cache_use_control_v2 import (
        InstalledD13CacheUseControlServiceV2, InstalledD13CacheUseControlPortV2)
    from ..authority_service.d13_core_counter_service_v1 import InstalledD13CoreCounterServiceV1
    from ..authority_service.d13_original_owner_v3 import (
        prepare_d13_counter_frame_owner_v3, prepare_d13_counter_original_use_v3,
        prepare_d13_natural_stage_owner_v3, require_d13_natural_model_execution_in_tx_v3)
    from .d13_natural_original_use_v3 import (
        require_actual_graph_natural_owner_v3, require_actual_graph_natural_release_v3)
    from .current_graph_full_read_v3 import advance_current_graph_full_read_v3, release_current_graph_full_result_v3
    from .graph_d13_cache_use_collection_v2 import GraphFullReadD13CollectionV2
    from .d13_cache_use_admission_v2 import (
        prepare_authority_d13_cache_use_v2, require_authority_d13_payload_pin_v2,
        require_d13_graph_payload_pin_v2, release_authority_d13_cache_use_v2,
        release_graph_d13_cache_use_v2, bind_authority_d13_source_successor_v3)
    return (AuthorityGraphReadWorkV3, advance_authority_graph_read_work_v3,
        InstalledD13CacheUseControlServiceV2, InstalledD13CacheUseControlPortV2,
        InstalledD13CoreCounterServiceV1, prepare_d13_counter_frame_owner_v3,
        prepare_d13_counter_original_use_v3, prepare_d13_natural_stage_owner_v3,
        require_d13_natural_model_execution_in_tx_v3, require_actual_graph_natural_owner_v3,
        require_actual_graph_natural_release_v3, advance_current_graph_full_read_v3,
        release_current_graph_full_result_v3, GraphFullReadD13CollectionV2,
        prepare_authority_d13_cache_use_v2, require_authority_d13_payload_pin_v2,
        require_d13_graph_payload_pin_v2, release_authority_d13_cache_use_v2,
        release_graph_d13_cache_use_v2, bind_authority_d13_source_successor_v3)


def _role_v3(db, role, manifest, meter):
    member = next(item for item in manifest['members'] if item['role'] == role)
    count, size = db.execute('SELECT count(*),coalesce(sum(length(CAST(name AS BLOB))+'
        'length(CAST(file AS BLOB))),0) FROM pragma_database_list').fetchone()
    meter.charge_read(16)
    if count != 1:
        raise AuthorityUnavailable('D13 genesis role has an attached database outside its actual selection')
    meter.require_available(size * 8 + 256)
    rows = db.execute('PRAGMA database_list').fetchmany(2)
    meter.charge_read(size)
    if len(rows) != 1 or rows[0][1] != 'main':
        raise AuthorityUnavailable('D13 genesis requires one actual selected SQLite role')
    selected = Path(member['resolved_path']).resolve(strict=True)
    if Path(rows[0][2]).resolve(strict=True) != selected:
        raise AuthorityUnavailable('D13 genesis role is not the actual selected file')
    stat = selected.stat()
    if (stat.st_dev, stat.st_ino) != (member['device'], member['file_id']):
        raise AuthorityUnavailable('D13 genesis selected role fingerprint changed')
    return (role, member['device'], member['file_id'], member['incarnation_or_journal_id'])


def _empty_inventory_v3(db, role, tables, meter):
    if not db.in_transaction:
        raise AuthorityUnavailable('D13 actual empty inventory requires its held role READ transaction')
    evidence = []
    for table in tables:
        meter.require_available(1024)
        present = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone()
        meter.charge_read(8)
        if present is not None:
            row = db.execute('SELECT 1 FROM ' + table + ' LIMIT 1').fetchone()
            meter.charge_read(8)
            if row is not None:
                raise AuthorityUnavailable('D13 historical durable inventory is nonempty; disposition census remains HOLD: ' + table)
        # Prepare records absence; final installation separately requires every actual schema.
        evidence.append((role, table, 0,
            canonical_digest(('d13.actual-empty-durable-inventory-eof.v3', role, table, 0))))
    return tuple(evidence)



def _require_final_birth_operation_inventory_v4(db,expected,meter):
    if not db.in_transaction:
        raise AuthorityUnavailable('final installation birth census requires its actual Core transaction')
    count,size=db.execute('SELECT count(*),coalesce(sum(length(CAST(namespace AS BLOB))+'
        'length(CAST(operation_id AS BLOB))+length(CAST(action AS BLOB))+'
        'length(CAST(request_digest AS BLOB))+length(CAST(result_json AS BLOB))),0) '
        'FROM authority_d13_cache_use_operations_v2').fetchone()
    meter.charge_read(16)
    if count!=1:
        raise AuthorityUnavailable('final installation operation census is not its one actual Core birth')
    meter.require_available(size*2+1024)
    rows=db.execute('SELECT namespace,operation_id,action,request_digest,result_json '
        'FROM authority_d13_cache_use_operations_v2 ORDER BY namespace,operation_id LIMIT 2').fetchmany(2)
    meter.charge_read(sum(sum(len(str(value).encode('utf8')) for value in row) for row in rows))
    if len(rows)!=1 or tuple(rows[0])!=expected:
        raise AuthorityUnavailable('final installation contains an operation beyond its actual own Core birth')
    return expected


_FINALIZED = WeakKeyDictionary()
_FRESH_REQUESTS = WeakKeyDictionary()
_DORMANT = ContextVar('d13_exact_fresh_dormant_composition_v3',default=None)
_HOST_READY = WeakKeyDictionary()


class _FreshD13InstallationRequestV3:
    def __init__(self,issuer,config,mode,profile_bytes,assets_bytes,expected,consumer_mode,consumer_closures):
        if issuer is not _ISSUER or mode not in ('prepare','finalize'):
            raise AuthorityUnavailable('actual explicit fresh installer request required')
        self.config,self.mode,self.profile_bytes,self.assets_bytes,self.expected=config,mode,profile_bytes,assets_bytes,expected
        self.consumer_mode,self.consumer_closures=consumer_mode,consumer_closures
        self.sdk_startup_worker=self.sdk_consumers=self.dormant=None
        self.selected_composition=self.composition=self.activation=self.registry_original=self.daemon=self.manifest=None
        self.closed=False
        _FRESH_REQUESTS[self]=(config,mode,profile_bytes,assets_bytes,canonical_digest(expected),consumer_mode,consumer_closures)
    def require_v3(self,config=None):
        if (_FRESH_REQUESTS.get(self)!=(self.config,self.mode,self.profile_bytes,self.assets_bytes,canonical_digest(self.expected),self.consumer_mode,self.consumer_closures)
                or self.closed or config is not None and config is not self.config
                    and (self.selected_composition is None or config is not self.selected_composition.config)):
            raise AuthorityUnavailable('fresh D13 installer lost its exact request/config lifetime')
        return self
    def bind_selected_composition_v3(self,composition):
        from ..authority_service.daemon import _ResolvedStorageCompositionV3,_selected_config_v3
        self.require_v3()
        if (type(composition)is not _ResolvedStorageCompositionV3 or self.selected_composition is not None
                or composition.config!=_selected_config_v3(self.config,composition.context)):
            raise AuthorityUnavailable('fresh D13 selected composition differs from its actual protected config')
        self.selected_composition=composition
    def bind_composition_v3(self,composition,activation,registry_original):
        self.require_v3()
        if (self.composition is not None or (activation.summary['mode'],activation.summary['process_count'])!=
                (('genesis',0)if self.consumer_mode=='production_root'else('controlled_sdk_genesis',1))):
            raise AuthorityUnavailable('fresh D13 requires its exact actual production or controlled SDK census')
        self.composition,self.activation,self.registry_original=composition,activation,registry_original
    def close_v3(self):
        if self.manifest is not None:
            _MANIFESTS.pop(self.manifest,None)
            if self.manifest.finalized is not None:_FINALIZED.pop(self.manifest.finalized,None)
            control=self.manifest.activation.control
            if getattr(control,'_d13_cache_use_consumer_manifest_v2',None)is self.manifest:
                control._d13_cache_use_consumer_manifest_v2=None
        self.closed=True
        _FRESH_REQUESTS.pop(self,None)


def _issue_fresh_d13_installation_request_v3(config,*,mode,profile_bytes,assets_bytes,expected=None,
        consumer_mode='production_root',consumer_closures=()):
    from ..authority_service.deployment_config import AuthorityDeploymentConfig
    if type(config)is not AuthorityDeploymentConfig or type(profile_bytes)is not bytes or type(assets_bytes)is not bytes:
        raise AuthorityUnavailable('fresh D13 needs the exact protected configuration/file cohort')
    config.require_d13_fresh_installation_scope_v3(consumer_mode=consumer_mode)
    return _FreshD13InstallationRequestV3(_ISSUER,config,mode,profile_bytes,assets_bytes,expected,consumer_mode,consumer_closures)


def _require_fresh_d13_request_v3(request,*,config):
    if type(request)is not _FreshD13InstallationRequestV3:
        raise AuthorityUnavailable('ordinary open cannot sign or upgrade D13 policies')
    return request.require_v3(config)


@contextmanager
def bind_fresh_d13_dormant_composition_v3(request):
    request.require_v3()
    token=_DORMANT.set(request)
    try:yield
    finally:_DORMANT.reset(token)


def defer_fresh_d13_control_composition_v3(config,core):
    request=_DORMANT.get()
    if request is None:return False
    request.require_v3(config)
    if request.composition is None or request.composition.control is None:
        raise AuthorityUnavailable('fresh D13 dormant composition has no selected physical owner')
    with core._tx()as db:
        present=db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='authority_d13_cache_use_policies_v2'").fetchone()
        if present is not None and db.execute('SELECT 1 FROM authority_d13_cache_use_policies_v2 LIMIT 1').fetchone()is not None:
            raise AuthorityUnavailable('existing D13 signed/legacy policy needs explicit new-cohort migration census; HOLD')
    return True


def _empty_memory_v3():
    from .d13_cache_use_admission_v2 import _RETAINED
    from .d13_natural_original_use_v3 import _RETAINED as natural_receivers
    from ..authority_service.d13_original_owner_v3 import _PROOFS
    from ..authority_service.current_authority_graph_read_v3 import _WORKS
    if _RETAINED or natural_receivers or _PROOFS or any(not work.closed for work in _WORKS):
        raise AuthorityUnavailable('fresh D13 has an actual in-memory original/receiver; migration census HOLD')


class InstalledD13ConsumerManifestV3:
    """Actual dormant Authority receivers plus the installed future Host admission contract."""
    def __init__(self,issuer,*,composition,core,graph_store,activation,bundle,daemon,fresh_request):
        if issuer is not _ISSUER:raise AuthorityUnavailable('actual fresh D13 composition producer required')
        self.composition,self.core,self.graph_store,self.activation=composition,core,graph_store,activation
        self.bundle,self.installation,self.daemon,self.request=bundle,bundle.installation_policy,daemon,fresh_request
        self.components,self.original,self.finalized=_actual_components_v3(),None,None
        _MANIFESTS[self]=(composition,core,graph_store,activation,bundle,daemon,fresh_request,self.components)
    def _bindings_v3(self,*,require_control):
        from ..authority_service.daemon import AuthorityDaemon
        from ..authority_service.mtls_server import AuthorityRpcServer
        from ..authority_service.d13_core_counter_service_v1 import InstalledD13CoreCounterServiceV1
        from ..authority_service.current_authority_graph_read_v3 import require_authority_graph_read_controller_v3
        from ..authority_service.d13_cache_use_control_v2 import InstalledD13CacheUseControlServiceV2
        daemon=self.daemon;server=daemon.server;ns=self.installation.authority_namespace
        if (type(daemon)is not AuthorityDaemon or type(server)is not AuthorityRpcServer
                or daemon.core is not self.core or server._core is not self.core
                or daemon._resolved_storage_composition_v3 is not self.composition
                or daemon.c09_maintenance.graph is not self.graph_store):
            raise AuthorityUnavailable('D13 manifest lost its actual dormant Authority/Graph objects')
        model=server._v2_model_egress.get(ns);generation=server._v2_natural_generation_content_reads.get(ns)
        review=server._v2_natural_paid_review_reads.get(ns);counter=server._d13_core_counters_v1.get(ns)
        if (model is None or generation is None or review is None
                or type(counter)is not InstalledD13CoreCounterServiceV1 or counter.core is not self.core
                or counter.bridge is not server._v2_execution.get(ns)
                or counter.source.observer.installed_bundle is not self.bundle
                or counter._active_claim is not None or counter._pending_owner_draft_v3 is not None):
            raise AuthorityUnavailable('D13 actual model/Counter/generation/review consumers are incomplete')
        controllers=tuple(require_authority_graph_read_controller_v3(verifier)for verifier in
            (model._graph_verifier,generation._graph,review._graph,counter.source))
        if any(c.fences is not server._v2_fences[ns] or c.location._control is not self.composition.control for c in controllers):
            raise AuthorityUnavailable('D13 consumers crossed their actual Source/fence/storage registry')
        history=model._graph_verifier._natural_history
        if history is None or history._bundle is not self.bundle or history._execution is not counter.bridge:
            raise AuthorityUnavailable('D13 generation/review original ownership lacks its actual execution bridge')
        if self.request.consumer_mode=='production_root':
            supervisor=self.activation.qualification.supervisor
            from ..authority_service.installed_process_supervisor_v1 import InstalledRootProcessSupervisorV1
            from ..host.v2_installation import V2InstallationAssembly
            if (type(supervisor)is not InstalledRootProcessSupervisorV1
                    or supervisor.config.installation_id!=self.installation.installation_id
                    or supervisor.config.namespace_cohort!=(ns,)
                    or V2InstallationAssembly.__dataclass_fields__['fence_port_factory']is None):
                raise AuthorityUnavailable('D13 future Host requires its actual Root startup gate and factory contract')
            future=supervisor
        else:
            future=self.request.sdk_consumers
            if (type(future)is not _ControlledSDKD13ConsumersV3 or future.daemon is not daemon
                    or future.control is not self.composition.control or future.gate is not self.activation.gate
                    or future.phase!='dormant'):
                raise AuthorityUnavailable('SDK fresh coverage requires its actual dormant GraphWorker/factory capture')
            future._actual_v3()
        control=birth=initial_counter_seal=accounting_producer=None
        if require_control:
            control=self.core._d13_cache_use_controls_v2.get(ns)
            if (type(control)is not InstalledD13CacheUseControlServiceV2 or control.core is not self.core
                    or control.bundle is not self.bundle or control.fences is not server._v2_fences[ns]
                    or server._d13_cache_use_controls_v2.get((ns,self.installation.installation_id))is not control):
                raise AuthorityUnavailable('D13 final consumer manifest has no actual installed control/RPC object')
            from ..authority_service.d13_original_owner_v3 import require_actual_d13_core_birth_v4
            birth=require_actual_d13_core_birth_v4(control)
            from ..authority_service.v2_model_egress_service import require_installed_d13_accounting_metadata_producer_v3
            accounting_producer=require_installed_d13_accounting_metadata_producer_v3(model,server=server,bundle=self.bundle)
            if self.core._runtime_storage_v3.source_kind=='initial_segmented_v4':
                from ..authority_service.d13_provider_http_admission_v1 import require_actual_initial_runtime_counter_index_v4
                initial_counter_seal=require_actual_initial_runtime_counter_index_v4(counter,db=self.core._db)
            context=self.composition.context
            if (birth.birth_profile!=self.request.consumer_mode
                    or birth.namespace!=self.installation.namespace or birth.authority_namespace!=ns
                    or birth.installation_id!=self.installation.installation_id
                    or birth.authority_id!=self.composition.control.authority_id
                    or birth.control_store_id!=self.composition.control.control_store_id
                    or birth.consumer_cohort_digest!=installed_d13_consumer_cohort_digest_v3()
                    or (birth.selected_manifest_digest,birth.pointer_version,birth.storage_generation)!=
                        (context.manifest_digest,context.pointer_version,context.storage_generation)):
                raise AuthorityUnavailable('final local-v4 consumer lacks its exact actual current Core birth ACK')
        return (server,model,generation,review,counter,*controllers,history,future,control,birth,initial_counter_seal,accounting_producer)
    def _identity_v3(self):
        return (self.composition,self.core,self.graph_store,self.activation,self.bundle,self.daemon,self.request,self.components)
    def _require_identity_v3(self,*,control,gate,meter):
        if _MANIFESTS.get(self)!=self._identity_v3() or self.components!=_actual_components_v3():
            raise AuthorityUnavailable('D13 actual consumer manifest issuer changed')
        self.request.require_v3(self.composition.config)
        if (self.composition.control is not control or self.activation.control is not control
                or self.activation.gate is not gate or gate._installed_config_v3 is not self.composition.config):
            raise AuthorityUnavailable('D13 actual fresh composition/Gate changed')
        self.activation.require_current(control=control,gate=gate,meter=meter)
        gate.require_pending_start_bootstrap_scope_v3(meter=meter)
        context=self.composition.context
        context.require_current('maintenance')
        if (context.stage!='READY' or context.pointer_version!=0 or context.storage_generation!=0
                or context.manifest['installation_id']!=self.installation.installation_id
                or context.manifest['authority_id']!=control.authority_id):
            raise AuthorityUnavailable('D13 historical storage requires explicit new-cohort migration census; HOLD')
        from ..runtime_storage_v3 import InstalledRuntimeStorageV3
        graph_handle=self.graph_store._runtime_storage_v3;core_handle=self.core._runtime_storage_v3
        if (type(graph_handle)is not InstalledRuntimeStorageV3 or type(core_handle)is not InstalledRuntimeStorageV3
                or graph_handle.role!='graph' or core_handle.role!='core'
                or graph_handle.selection_digest!=core_handle.selection_digest):
            raise AuthorityUnavailable('fresh D13 consumers require actual selected Graph/Core runtime storage')
        _empty_memory_v3()
        self._bindings_v3(require_control=False)
        return context
    def _require_v3(self,*,control,gate,meter):
        context=self._require_identity_v3(control=control,gate=gate,meter=meter)
        graph,core=self.graph_store,self.core
        with graph._lock,core._lock:
            if graph._db.in_transaction or core._db.in_transaction:
                raise AuthorityUnavailable('fresh D13 inventory must precede the final policy transaction')
            graph._db.execute('BEGIN')
            try:
                core._db.execute('BEGIN')
                try:
                    roles=(_role_v3(graph._db,'graph',context.manifest,meter),
                        _role_v3(core._db,'core',context.manifest,meter))
                    inventory=(_empty_inventory_v3(graph._db,'graph',_GRAPH_TABLES,meter)
                        +_empty_inventory_v3(core._db,'core',_CORE_TABLES,meter))
                    initial_counter_seal=None
                    if core._runtime_storage_v3.source_kind=='initial_segmented_v4':
                        from ..authority_service.d13_provider_http_admission_v1 import require_actual_initial_runtime_counter_index_v4
                        initial_counter_seal=require_actual_initial_runtime_counter_index_v4(self.daemon.server._d13_core_counters_v1[self.installation.authority_namespace],db=core._db)
                finally:core._db.rollback()
            finally:graph._db.rollback()
        material=dict(schema='sylanne3.d13.installed-consumer-manifest.v3',
            installation_id=self.installation.installation_id,namespace=self.installation.namespace,
            consumer_cohort_digest=installed_d13_consumer_cohort_digest_v3(),members=_KINDS,
            selected_manifest_digest=context.manifest_digest,pointer_version=0,storage_generation=0,
            selected_roles=roles,durable_inventory=inventory,initial_counter_empty_prefix_seal=initial_counter_seal,
            actual_authority_bindings=('model_source','counter_source','generation_source','review_source','natural_execution',
                'authority_core_incarnation_v4'),
            future_consumer_admission=(
                dict(schema='sylanne3.d13.actual-host-consumer-ready-contract.v3',mode='production_root',
                    supervisor_spec_digest=self.activation.qualification.supervisor.config.spec_digest,
                    authority_spec_digest=self.activation.qualification.authority_spec_v4.spec_digest,
                    authority_birth_contract='sylanne3.d13.core-incarnation-authority-observation.v4',
                    factory='sylanne3.host.v2_installation.V2InstallationAssembly',
                    readiness='sylanne3.runtime.d13_consumer_manifest_v3.install_actual_d13_host_consumer_ready_v3')
                if self.request.consumer_mode=='production_root'else
                dict(schema='sylanne3.d13.controlled-sdk-consumer-contract.v3',mode='controlled_sdk',
                    descriptor_digest=self.request.registry_original['activation_basis']['controlled_sdk_root_census_original']['selection_scope']['descriptor_digest'],
                    closed_service_original_root=self.request.registry_original['activation_basis']['closed_service_original_root'],
                    resource_operation_id=self.request.registry_original['activation_basis']['controlled_sdk_root_census_original']['resource_operation_id'],
                    factory='sylanne3.runtime.d13_consumer_manifest_v3.prepare_controlled_sdk_d13_consumers_v3',
                    readiness='actual_graph_worker_capture_signed_peer_core_ready_and_drain.v3')))
        if self.original is not None and material!=self.original:
            raise AuthorityUnavailable('fresh D13 actual empty EOF or consumer bindings changed; needs_reprepare')
        self.original=material
        return material
    def require_actual_fresh_qualification_v3(self,proof,*,control,gate,meter):
        from ..authority_service.c09_storage_maintenance_v1 import VerifiedInstalledPeerRegistryActivationV3
        from ..authority_service.c09_writer_peer_activation_v3 import InstalledPeerRegistryCensusV3
        from ..host.c09_controlled_sdk_bootstrap_v3 import VerifiedControlledSDKInstallerOriginalV3
        if type(proof)is not VerifiedInstalledPeerRegistryActivationV3 or proof is not self.activation:
            raise AuthorityUnavailable('fresh D13 coverage requires its exact current private activation')
        self._require_identity_v3(control=control,gate=gate,meter=meter)
        qualification=proof.qualification
        if self.request.consumer_mode=='production_root':
            if type(qualification)is not InstalledPeerRegistryCensusV3 or (proof.summary['mode'],proof.summary['process_count'])!=('genesis',0):
                raise AuthorityUnavailable('production fresh coverage requires actual Root prehost census zero')
        elif self.request.consumer_mode=='controlled_sdk':
            if (type(qualification)is not VerifiedControlledSDKInstallerOriginalV3
                    or (proof.summary['mode'],proof.summary['process_count'])!=('controlled_sdk_genesis',1)
                    or self.request.sdk_consumers.census is not qualification.process_census
                    or self.request.sdk_consumers.descriptor is not qualification.descriptor):
                raise AuthorityUnavailable('SDK fresh coverage requires actual sole-process installer and dormant worker')
        else:raise AuthorityUnavailable('unregistered fresh D13 consumer qualification')
        return proof
    def require_d13_pin_only_consumers_v2(self,*,control,gate,policy,meter):
        if (policy.namespace,policy.installation_id,policy.authority_namespace,policy.consumer_cohort_digest)!=(
                self.installation.namespace,self.installation.installation_id,self.installation.authority_namespace,
                installed_d13_consumer_cohort_digest_v3()):
            raise AuthorityUnavailable('D13 final policy differs from its actual fresh consumer cohort')
        return self._require_v3(control=control,gate=gate,meter=meter)
    def coverage_original_v3(self):
        control,gate=self.activation.control,self.activation.gate
        with control._resource_sql_quantum_v3()as meter:
            material=self._require_v3(control=control,gate=gate,meter=meter)
        return dict(schema='sylanne3.d13.cache-use-complete-coverage.v3',
            installation_id=self.installation.installation_id,namespace=self.installation.namespace,
            consumer_cohort_digest=installed_d13_consumer_cohort_digest_v3(),
            basis=self.request.registry_original,future_consumers=material)
    def coverage_digest_v3(self):return canonical_digest(self.coverage_original_v3())
    def finalize_actual_consumers_v3(self,*,server,daemon):
        control,gate=self.activation.control,self.activation.gate
        if (daemon is not self.daemon or server is not daemon.server or not self.core._db.in_transaction
                or not self.graph_store._db.in_transaction or self.original is None):
            raise AuthorityUnavailable('D13 final manifest requires actual outer Core install and pinned Graph snapshot')
        with control._resource_sql_quantum_v3()as meter:
            self._require_identity_v3(control=control,gate=gate,meter=meter)
            for db,tables in ((self.graph_store._db,_GRAPH_TABLES),(self.core._db,_CORE_TABLES)):
                for table in tables:
                    if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",(table,)).fetchone()is None:
                        raise AuthorityUnavailable('D13 final actual consumer schema is missing: '+table)
            _empty_inventory_v3(self.graph_store._db,'graph',_GRAPH_TABLES,meter)
            _empty_inventory_v3(self.core._db,'core',tuple(t for t in _CORE_TABLES
                if t!='authority_d13_cache_use_operations_v2'),meter)
            from ..authority_service.d13_original_owner_v3 import require_actual_fresh_d13_core_birth_operation_v4
            service=self.core._d13_cache_use_controls_v2[self.installation.authority_namespace]
            birth_operation=require_actual_fresh_d13_core_birth_operation_v4(service,daemon=daemon,db=self.core._db)
            _require_final_birth_operation_inventory_v4(self.core._db,birth_operation,meter)
        bindings=self._bindings_v3(require_control=True)
        proof=_FinalizedD13ConsumerInstallationV3(_ISSUER,self,bindings,birth_operation)
        self.finalized=proof
        return proof


class _FinalizedD13ConsumerInstallationV3:
    def __init__(self,issuer,manifest,bindings,birth_operation):
        if issuer is not _ISSUER:raise AuthorityUnavailable('actual finalized D13 installation producer required')
        self.manifest,self.bindings,self.birth_operation=manifest,bindings,birth_operation
        _FINALIZED[self]=(manifest,bindings,birth_operation,manifest.core._db,canonical_digest(manifest.original),get_ident())


def _actual_core_birth_binding_material_v4(*,service,daemon,control,context,profile,authority,
        observation_digest,census_digest,spec_digest,root_original):
    import os
    from ..authority_service.c09_storage_control_v1 import InstalledC09InstanceLeaseV1
    from ..runtime_storage_v3 import InstalledRuntimeStorageV3
    lease=daemon._lock_handle
    if (type(lease)is not InstalledC09InstanceLeaseV1 or lease is not control.lease
            or Path(lease.path).resolve()!=Path(daemon.config.instance_lock).resolve()):
        raise AuthorityUnavailable('Core birth has no actual same-daemon held instance lease')
    lease.require_held();info=os.fstat(lease._stream.fileno());path_info=Path(lease.path).stat()
    if (info.st_dev,info.st_ino)!=(path_info.st_dev,path_info.st_ino):
        raise AuthorityUnavailable('Core birth instance-lock incarnation changed')
    handle=service.core._runtime_storage_v3;graph_handle=daemon.c09_maintenance.graph._runtime_storage_v3
    if (type(handle)is not InstalledRuntimeStorageV3 or handle.role!='core' or handle._closed
            or type(graph_handle)is not InstalledRuntimeStorageV3 or graph_handle.role!='graph'
            or graph_handle._closed or handle.selection_digest!=graph_handle.selection_digest):
        raise AuthorityUnavailable('Core birth crossed its actual selected Core/Graph storage handles')
    lock_ref='instance-lock-v4:sha256:'+canonical_digest((str(Path(lease.path).resolve()),info.st_dev,info.st_ino))
    material=dict(authority_process_original=authority,root_observation_original=root_original,
        root_authority_observation_digest=observation_digest,
        root_process_census_digest=census_digest,authority_spec_digest=spec_digest,instance_lock_ref=lock_ref,
        selected_manifest_digest=context.manifest_digest,pointer_version=context.pointer_version,
        storage_generation=context.storage_generation)
    material['producer_binding_digest']=canonical_digest(('sylanne3.d13.actual-core-incarnation-producer.v4',
        profile,material,control.authority_id,control.installation_id,control.control_store_id,
        service.namespace,service.use_policy.policy_ref,service.use_policy.digest,
        service.use_policy.consumer_cohort_digest,handle.selection_digest))
    return control,material


def require_actual_d13_core_birth_material_v4(qualification,*,service,daemon,installation):
    """Only the exact fresh installer may consume its actual Root Authority-role witness."""
    from ..authority_service.d13_cache_use_control_v2 import (
        _FreshD13PolicyInstallationV3,InstalledD13CacheUseControlServiceV2)
    from ..authority_service.daemon import AuthorityDaemon
    from ..authority_service.c09_writer_peer_activation_v3 import InstalledPeerRegistryCensusV3
    from ..host.c09_controlled_sdk_bootstrap_v3 import VerifiedControlledSDKInstallerOriginalV3
    if type(installation)is not _FreshD13PolicyInstallationV3:
        raise AuthorityUnavailable('actual private fresh Core installer required for local incarnation birth')
    installation.require_v3();manifest=installation.manifest
    if (type(manifest)is not InstalledD13ConsumerManifestV3 or _MANIFESTS.get(manifest)!=manifest._identity_v3()
            or type(service)is not InstalledD13CacheUseControlServiceV2 or installation.service is not service
            or type(daemon)is not AuthorityDaemon or manifest.daemon is not daemon or manifest.core is not service.core
            or installation.core is not service.core or installation.db is not service.core._db
            or installation.bundle is not manifest.bundle or service.bundle is not manifest.bundle
            or manifest.request.activation.qualification is not qualification
            or manifest.activation.qualification is not qualification
            or manifest.composition is not daemon._resolved_storage_composition_v3
            or manifest.composition.control is not daemon.c09_control or installation.gate is not daemon.c09_gate
            or daemon.core is not service.core or daemon.server._core is not service.core
            or daemon.server._d13_cache_use_controls_v2.get((service.authority_namespace,service.installation_id))is not service):
        raise AuthorityUnavailable('Core birth crossed its exact actual fresh service/daemon/manifest/qualification')
    manifest.request.require_v3(daemon.config)
    control,gate=daemon.c09_control,daemon.c09_gate
    with control._resource_sql_quantum_v3()as meter:
        if manifest.request.consumer_mode=='production_root':
            if type(qualification)is not InstalledPeerRegistryCensusV3:
                raise AuthorityUnavailable('production Core birth requires its actual independent Root process qualification')
            qualification.require_current(control=control,gate=gate,meter=meter)
            observed=qualification.hold.require_authority_birth_observation_v4()
            if (qualification.hold.authority_spec is not qualification.authority_spec_v4
                    or observed.selected_manifest_digest!=manifest.installation.manifest_digest
                    or qualification.hold.original['registry_scope']!=qualification.scope):
                raise AuthorityUnavailable('production Core birth package observation or storage registry scope changed')
            authority=observed.main_process_original
            observation_digest=observed.observation_digest
            root_original=asdict(observed)
            census_digest=canonical_digest(root_original)
            spec_digest=qualification.authority_spec_v4.spec_digest
        elif manifest.request.consumer_mode=='controlled_sdk':
            if type(qualification)is not VerifiedControlledSDKInstallerOriginalV3:
                raise AuthorityUnavailable('controlled SDK Core birth requires its independent actual Root census')
            qualification.require_current(gate=gate,control=control,config=daemon.config,meter=meter)
            census=qualification.process_census;census.require_current()
            authority=qualification.current_authority_original
            if (census.authority_process_original!=authority or census.original['authority_process']['pid']!=authority['pid']
                    or census.original['authority_process']['birth']!=authority['birth']
                    or qualification.descriptor.payload['manifest_digest']!=manifest.installation.manifest_digest):
                raise AuthorityUnavailable('controlled SDK Core birth differs from its actual Root Authority process/package')
            observation_digest=canonical_digest(census.original['authority_process'])
            census_digest=census.digest;spec_digest=qualification.descriptor.payload['descriptor_digest']
            root_original=census.original
        else:raise AuthorityUnavailable('unknown explicit fresh Core birth process profile')
        context=manifest.composition.context;context.require_current('maintenance')
    result=_actual_core_birth_binding_material_v4(service=service,daemon=daemon,control=control,context=context,
        profile=manifest.request.consumer_mode,authority=authority,observation_digest=observation_digest,
        census_digest=census_digest,spec_digest=spec_digest,root_original=root_original)
    installation.require_v3()
    return result


def require_finalized_d13_consumer_installation_v3(proof,*,manifest,core,bundle,db):
    if (type(proof)is not _FinalizedD13ConsumerInstallationV3 or proof.manifest is not manifest
            or _FINALIZED.get(proof)!=(manifest,proof.bindings,proof.birth_operation,db,canonical_digest(manifest.original),get_ident())
            or manifest.finalized is not proof or manifest.core is not core or core._db is not db
            or manifest.bundle is not bundle or not db.in_transaction or not manifest.graph_store._db.in_transaction
            or proof.bindings!=manifest._bindings_v3(require_control=True)):
        raise AuthorityUnavailable('D13 actual final consumer installation proof differs')
    with manifest.activation.control._resource_sql_quantum_v3()as meter:
        manifest._require_identity_v3(control=manifest.activation.control,gate=manifest.activation.gate,meter=meter)
        _require_final_birth_operation_inventory_v4(db,proof.birth_operation,meter)
    return proof


def prepare_installed_d13_consumer_manifest_v3(*,composition,core,graph_store,activation,bundle,daemon,fresh_request):
    fresh_request.require_v3(composition.config)
    proof=InstalledD13ConsumerManifestV3(_ISSUER,composition=composition,core=core,graph_store=graph_store,
        activation=activation,bundle=bundle,daemon=daemon,fresh_request=fresh_request)
    proof.coverage_original_v3()
    control=activation.control
    if getattr(control,'_d13_cache_use_consumer_manifest_v2',None)is not None:
        raise AuthorityUnavailable('D13 actual fresh consumer manifest cannot be replaced')
    control._d13_cache_use_consumer_manifest_v2=proof
    return proof


_PREPARED_FRESH=WeakKeyDictionary()


class _PreparedFreshD13InstallationV3:
    def __init__(self,issuer,profile_bytes,assets_bytes,receipt,request):
        if issuer is not _ISSUER:raise AuthorityUnavailable('actual fresh preparation producer required')
        self.status='prepared_unpublished'
        self.profile_bytes,self.assets_bytes,self.publication_receipt=profile_bytes,assets_bytes,receipt
        self.source_profile_bytes,self.source_assets_bytes=request.profile_bytes,request.assets_bytes
        self.consumer=request.sdk_consumers
        self.activation_original=request.registry_original
        _PREPARED_FRESH[self]=(profile_bytes,assets_bytes,canonical_digest(receipt),self.consumer,canonical_digest(self.activation_original))


_CURRENT_CORE_BIRTH_QUALIFICATIONS_V4=WeakKeyDictionary()


def requires_current_core_birth_v4(config):
    from ..authority_service.deployment_config import AuthorityDeploymentConfig
    if type(config)is not AuthorityDeploymentConfig:
        raise AuthorityUnavailable('actual protected current installation config required')
    installed=config.natural_model_authorities_v2 or {}
    return any(item.installation_bundle is not None and item.installation_bundle.d13_cache_use_control_v2 is not None
        and item.installation_bundle.d13_cache_use_control_v2.enabled
        and item.installation_bundle.d13_cache_use_control_v2.consumer_cohort_digest==installed_d13_consumer_cohort_digest_v3()
        for item in installed.values())


class CurrentCoreBirthQualificationV4:
    def __init__(self,issuer,*,control,gate,config,context,state):
        if issuer is not _ISSUER:raise AuthorityUnavailable('actual current bootstrap Core qualification issuer required')
        self.control,self.gate,self.config,self.context,self.state=control,gate,config,context,state
        self.hold=gate._pending_start_bootstrap_hold_v3
        self.factory=config.c09_maintenance_factory
        self.profile='controlled_sdk'if self.factory._controlled_sdk_registry_assets_v3 is not None else'production_root'
        self.daemon=self.core=self.birth=None;self.closed=False
        _CURRENT_CORE_BIRTH_QUALIFICATIONS_V4[self]=self._identity_v4()
    @property
    def consumer_mode(self):return self.profile
    def _identity_v4(self):
        return (self.control,self.gate,self.config,self.context,self.state,self.hold,self.factory,self.profile,
            self.daemon,self.core,canonical_digest(self.birth),self.closed)
    def require_v4(self):
        from ..authority_service.installed_process_supervisor_v1 import RootPeerStartCoverageHoldV3
        from ..host.c09_controlled_sdk_bootstrap_v3 import VerifiedControlledSDKProcessCensusV3
        if (_CURRENT_CORE_BIRTH_QUALIFICATIONS_V4.get(self)!=self._identity_v4() or self.closed
                or self.factory._peer_registry_preparations_v3.get(self.control)is not self.state
                or self.state.get('current_core_birth_qualification_v4')is not self or self.state['fresh']is not None
                or self.state['phase']!='complete' or self.state['gate']is not self.gate
                or self.gate._installed_config_v3 is not self.config or self.gate.control is not self.control
                or self.gate._pending_start_bootstrap_hold_v3 is not self.hold
                or not requires_current_core_birth_v4(self.config)):
            raise AuthorityUnavailable('current Core qualification lost its exact bootstrap/Control/Gate/selection/hold')
        with self.control._resource_sql_quantum_v3()as meter:
            self.gate.require_pending_start_bootstrap_scope_v3(meter=meter)
            if self.profile=='production_root':
                if type(self.hold)is not RootPeerStartCoverageHoldV3:
                    raise AuthorityUnavailable('production current Core requires its actual independent Root coverage hold')
                self.hold.require_authority_birth_observation_v4()
            else:
                if type(self.hold)is not VerifiedControlledSDKProcessCensusV3 or self.state.get('sdk_census')is not self.hold:
                    raise AuthorityUnavailable('SDK current Core requires its actual independent Root phase census')
                self.hold.require_current()
            stored=self.state['original']
            if self.state['existing']:stored.require_current(meter=meter)
            else:self.control.verify_original_v1(stored,'activation_digest')
            original=stored.original if self.state['existing']else stored
            self.gate.require_registry_activation_domain_v3(original,meter=meter)
            self.context.require_current('maintenance')
        self.control.lease.require_held()
        return self
    def bind_daemon_v4(self,daemon):
        from ..authority_service.daemon import AuthorityDaemon
        self.require_v4()
        if (type(daemon)is not AuthorityDaemon or daemon.c09_control is not self.control or daemon.c09_gate is not self.gate
                or daemon.config is not self.config or daemon._resolved_storage_composition_v3.context is not self.context
                or self.daemon is not None or self.core is not None):
            raise AuthorityUnavailable('current Core qualification binds its actual newly composed daemon only once')
        self.daemon,self.core=daemon,daemon.core
        _CURRENT_CORE_BIRTH_QUALIFICATIONS_V4[self]=self._identity_v4()
        return self
    def record_birth_v4(self,service,birth):
        from ..authority_service.d13_original_owner_v3 import require_actual_d13_core_birth_v4
        self.require_v4()
        if service.core is not self.core or require_actual_d13_core_birth_v4(service)!=birth or birth.birth_profile!=self.profile:
            raise AuthorityUnavailable('current Core qualification did not consume its exact actual typed birth ACK')
        self.birth=birth;_CURRENT_CORE_BIRTH_QUALIFICATIONS_V4[self]=self._identity_v4()
    def close_v4(self):
        _CURRENT_CORE_BIRTH_QUALIFICATIONS_V4.pop(self,None);self.closed=True


def issue_current_core_birth_qualification_v4(*,control,gate,config,context,state):
    from ..authority_service.c09_installed_factory_v1 import InstalledC09MaintenanceFactoryV1
    factory=config.c09_maintenance_factory
    if (type(factory)is not InstalledC09MaintenanceFactoryV1 or factory._peer_registry_preparations_v3.get(control)is not state
            or state['fresh']is not None or state['phase']!='complete' or state['gate']is not gate
            or not requires_current_core_birth_v4(config)or state.get('current_core_birth_qualification_v4')is not None):
        raise AuthorityUnavailable('current Core qualification must follow this actual completed pending metadata EOF')
    proof=CurrentCoreBirthQualificationV4(_ISSUER,control=control,gate=gate,config=config,context=context,state=state)
    state['current_core_birth_qualification_v4']=proof
    return proof.require_v4()


def require_current_core_birth_qualification_v4(qualification,*,service,daemon,db):
    from ..authority_service.d13_cache_use_control_v2 import InstalledD13CacheUseControlServiceV2
    if type(qualification)is not CurrentCoreBirthQualificationV4:
        raise AuthorityUnavailable('unknown current Core birth qualification kind')
    qualification.require_v4()
    ns=service.authority_namespace
    installed=qualification.config.natural_model_authorities_v2.get(ns)
    if (type(service)is not InstalledD13CacheUseControlServiceV2 or qualification.daemon is not daemon
            or qualification.core is not service.core or daemon.core is not service.core
            or db is not service.core._db or not db.in_transaction or daemon._closed
            or daemon._lock_handle is not qualification.control.lease
            or daemon.server._d13_cache_use_controls_v2.get((ns,service.installation_id))is not service
            or installed is None or installed.installation_bundle is not service.bundle
            or service.use_policy.consumer_cohort_digest!=installed_d13_consumer_cohort_digest_v3()):
        raise AuthorityUnavailable('current Core birth crossed its exact actual Core/db/daemon/lease/service/policy')
    return qualification


def require_actual_current_d13_core_birth_material_v4(qualification,*,service,daemon,db):
    q=require_current_core_birth_qualification_v4(qualification,service=service,daemon=daemon,db=db)
    if q.profile=='production_root':
        observed=q.hold.require_authority_birth_observation_v4()
        authority=observed.main_process_original;observation_digest=observed.observation_digest
        root_original=asdict(observed);spec_digest=q.hold.authority_spec.spec_digest
        if observed.selected_manifest_digest!=service.bundle.installation_policy.manifest_digest:
            raise AuthorityUnavailable('current production Core uses another actual selected package invocation')
    else:
        census=q.hold;census.require_current();root_original=census.original
        authority=census.authority_process_original;observation_digest=canonical_digest(root_original['authority_process'])
        spec_digest=census.descriptor.payload['descriptor_digest']
        if census.descriptor.payload['manifest_digest']!=service.bundle.installation_policy.manifest_digest:
            raise AuthorityUnavailable('current SDK Core uses another actual protected package')
    return _actual_core_birth_binding_material_v4(service=service,daemon=daemon,control=q.control,context=q.context,
        profile=q.profile,authority=authority,observation_digest=observation_digest,
        census_digest=canonical_digest(root_original),spec_digest=spec_digest,root_original=root_original)


def require_actual_d13_current_core_receiver_cleanup_v4(qualification,daemon,hold,meter,*,db=None):
    """Independent actual current-bootstrap boundary; never a borrowed C09 scope."""
    from ..authority_service.daemon import AuthorityDaemon
    from ..authority_service.d13_original_owner_v3 import require_actual_d13_core_birth_v4
    if type(qualification)is not CurrentCoreBirthQualificationV4 or type(daemon)is not AuthorityDaemon:
        raise AuthorityUnavailable('actual independent current Core cleanup qualification required')
    q=qualification.require_v4()
    if (q.daemon is not daemon or q.core is not daemon.core or hold is not q.hold or q.birth is None
            or daemon._closed or daemon.is_listening
            or (db is None and daemon.core._db.in_transaction)
            or (db is not None and (db is not daemon.core._db or not db.in_transaction or not daemon.core._lock._is_owned()))
            or daemon.c09_maintenance.graph._db.in_transaction or q.gate._operation is not None or q.gate._active
            or q.control.lease is not daemon._lock_handle):
        raise AuthorityUnavailable('current Core cleanup crossed its actual closed-entry bootstrap/hold/Core boundary')
    if q.gate.require_pending_start_bootstrap_scope_v3(meter=meter)is not hold:
        raise AuthorityUnavailable('current Core cleanup lost its continuous actual Root hold')
    services=tuple(s for s in daemon.core._d13_cache_use_controls_v2.values()
        if s.use_policy.consumer_cohort_digest==installed_d13_consumer_cohort_digest_v3())
    if len(services)!=1 or require_actual_d13_core_birth_v4(services[0])!=q.birth:
        raise AuthorityUnavailable('current Core cleanup lacks its actual same-installed-service birth ACK')
    q.context.require_current('maintenance')
    return q


def begin_actual_current_core_birth_v4(daemon):
    from ..authority_service.d13_original_owner_v3 import install_actual_current_d13_core_incarnation_v4
    factory=daemon.config.c09_maintenance_factory
    q=factory.current_core_birth_qualification_v4(control=daemon.c09_control,config=daemon.config)
    if q.daemon is None:q.bind_daemon_v4(daemon)
    for service in daemon.core._d13_cache_use_controls_v2.values():
        if service.use_policy.consumer_cohort_digest!=installed_d13_consumer_cohort_digest_v3():continue
        birth=install_actual_current_d13_core_incarnation_v4(service,qualification=q,daemon=daemon)
        q.record_birth_v4(service,birth)
    return q


def complete_fresh_d13_composition_v3(request,daemon):
    from hashlib import sha256
    from ..authority_service.d13_cache_use_contract_v2 import cache_policy_pair_digest_v2
    from .d13_technical_policy import InstalledD13CacheUseAssetsV2
    request.require_v3(daemon.config)
    config=daemon.config;ns=next(iter(config.d13_cache_use_assets_v2))
    installed=config.natural_model_authorities_v2[ns];bundle=installed.installation_bundle
    manifest=prepare_installed_d13_consumer_manifest_v3(composition=request.composition,core=daemon.core,
        graph_store=daemon.c09_maintenance.graph,activation=request.activation,bundle=bundle,
        daemon=daemon,fresh_request=request)
    request.daemon,request.manifest=daemon,manifest
    public=manifest.coverage_original_v3();digest=canonical_digest(public)
    if request.mode=='prepare':
        use=replace(bundle.d13_cache_use_control_v2,consumer_cohort_digest=installed_d13_consumer_cohort_digest_v3())
        maintenance=replace(bundle.d13_derived_cache_maintenance_v2,
            consumer_cohort_digest=use.consumer_cohort_digest,coverage_digest=digest)
        pair=cache_policy_pair_digest_v2(use,maintenance)
        use=replace(use,policy_pair_digest=pair);maintenance=replace(maintenance,policy_pair_digest=pair)
        final_bundle=replace(bundle,d13_cache_use_control_v2=use,d13_derived_cache_maintenance_v2=maintenance)
        asset=InstalledD13CacheUseAssetsV2(use.namespace,use.authority_namespace,use.installation_id,
            bundle.installation_policy.manifest_digest,use.policy_ref,use.digest,maintenance.link_ref,
            maintenance.digest,use.consumer_cohort_digest,pair)
        asset.require_installation_v2(final_bundle)
        profile=json.loads(request.profile_bytes)
        profile['d13_cache_use_control_v2']=asdict(use)
        profile['d13_derived_cache_maintenance_v2']=asdict(maintenance)
        assets=json.loads(request.assets_bytes)
        rows=assets['d13_cache_use_assets_v2']
        if len(rows)!=1 or rows[0]['authority_namespace']!=ns:
            raise AuthorityUnavailable('fresh D13 protected asset cohort is not the exact single installation')
        assets['d13_cache_use_assets_v2']=[asdict(asset)]
        def encoded(value):return (json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False)+'\n').encode('utf8')
        profile_bytes,assets_bytes=encoded(profile),encoded(assets)
        from ..host.authority_profile import _MAX_PROFILE_BYTES
        if len(profile_bytes)>_MAX_PROFILE_BYTES or len(assets_bytes)>65536:
            raise AuthorityUnavailable('fresh D13 final protected files exceed their existing exact codecs')
        receipt=dict(schema='sylanne3.d13.fresh-policy-publication.v3',
            profile_sha256=sha256(profile_bytes).hexdigest(),assets_sha256=sha256(assets_bytes).hexdigest(),
            coverage_original=json.loads(canonical_serialize(public)),
            policy_refs=(use.policy_ref,maintenance.link_ref),policy_pair_digest=pair)
        return _PreparedFreshD13InstallationV3(_ISSUER,profile_bytes,assets_bytes,receipt,request)
    expected=request.expected
    if (type(expected)is not dict or set(expected)!={'schema','profile_sha256','assets_sha256','coverage_original','policy_refs','policy_pair_digest'}
            or expected['schema']!='sylanne3.d13.fresh-policy-publication.v3'
            or sha256(request.profile_bytes).hexdigest()!=expected['profile_sha256']
            or sha256(request.assets_bytes).hexdigest()!=expected['assets_sha256']
            or canonical_digest(public)!=canonical_digest(expected['coverage_original'])
            or tuple(expected['policy_refs'])!=(bundle.d13_cache_use_control_v2.policy_ref,bundle.d13_derived_cache_maintenance_v2.link_ref)
            or expected['policy_pair_digest']!=bundle.d13_cache_use_control_v2.policy_pair_digest
            or digest!=bundle.d13_derived_cache_maintenance_v2.coverage_digest):
        raise AuthorityUnavailable('fresh D13 final protected cohort/actual census changed; needs_reprepare')
    from .d13_cache_use_admission_v2 import prepare_d13_cache_use_coverage_installation_v2
    from ..authority_service.d13_cache_use_control_v2 import (
        fresh_d13_policy_installation_v3,install_d13_cache_use_rpc_service_v2)
    from types import MappingProxyType
    coverage=prepare_d13_cache_use_coverage_installation_v2(qualification=request.activation,
        control=request.composition.control,gate=request.composition.peer_gate,
        policy=bundle.d13_cache_use_control_v2,maintenance_policy=bundle.d13_derived_cache_maintenance_v2,
        consumer_manifest=manifest)
    # No Body can start under this continuous actual Root/Gate hold.
    graph=manifest.graph_store
    with graph._lock:
        try:
            with fresh_d13_policy_installation_v3(core=daemon.core,
                    credential=config.local_administrator_credential('d13_cache_use_install',ns),
                    bundle=bundle,budget_issuer=installed.d11_issuer,coverage_installation=coverage)as installation:
                graph._db.execute('BEGIN')
                service=installation.create_service_v3(fences=daemon.server._v2_fences[ns],
                    clock=daemon.server._v2_model_egress[ns]._graph_verifier._clock)
                daemon.core._d13_cache_use_controls_v2=MappingProxyType({ns:service})
                install_d13_cache_use_rpc_service_v2(daemon.server,ns,service)
                from ..authority_service.d13_original_owner_v3 import install_actual_d13_core_incarnation_v4
                install_actual_d13_core_incarnation_v4(service,qualification=request.activation.qualification,daemon=daemon)
                installation.finalize_actual_consumers_v3(server=daemon.server,daemon=daemon)
        finally:graph._db.rollback()
    return daemon


class _ActualD13HostReleaseWakeV3:
    def __init__(self,runtime,graph,worker,owner_loop):
        self.runtime,self.graph,self.worker=ref(runtime),ref(graph),ref(worker)
        self.owner_loop=owner_loop
    def __call__(self):
        graph=self.graph();runtime=self.runtime()
        if graph is None or runtime is None:return
        require_actual_d13_host_consumer_ready_v3(graph)
        self.owner_loop.call_soon_threadsafe(runtime.resume_d13_cache_use_release_v3)


def install_actual_d13_host_consumer_ready_v3(*,runtime,graph,worker,port,bundle,owner_loop):
    import asyncio
    from ..runtime_context import RuntimeContext
    from ..graph_coordinator import GraphCoordinator
    from ..graph_worker import GraphWorker
    from ..authority_service.d13_cache_use_control_v2 import InstalledD13CacheUseControlPortV2
    from ..runtime_storage_v3 import runtime_storage_v3
    if (type(runtime)is not RuntimeContext or type(graph)is not GraphCoordinator or type(worker)is not GraphWorker
            or runtime._worker is not worker or runtime._v2_model_bundle is not bundle
            or runtime._v2_policy is not bundle.installation_policy or runtime._v2_authority_loop is not owner_loop
            or worker._thread.ident!=get_ident()
            or not isinstance(owner_loop,asyncio.AbstractEventLoop)or owner_loop.is_closed()
            or not owner_loop.is_running()or graph in _HOST_READY):
        raise AuthorityUnavailable('D13 consumer ready requires its actual production RuntimeContext/worker/owner loop')
    use=graph._GraphCoordinator__d13_cache_use_control_v2
    if (type(use)is not InstalledD13CacheUseControlPortV2 or use.fence_port is not port or use.bundle is not bundle
            or use.use_policy.consumer_cohort_digest!=installed_d13_consumer_cohort_digest_v3()
            or graph._GraphCoordinator__content_fence_v2 is not port):
        raise AuthorityUnavailable('D13 Host consumer changed its actual installed ports/cohort')
    use._actual()
    store=graph._GraphCoordinator__store;handle=runtime_storage_v3(store._db)
    if handle is None or handle.role!='graph':
        raise AuthorityUnavailable('D13 Host Body requires actual selected storage consumer admission')
    wake=_ActualD13HostReleaseWakeV3(runtime,graph,worker,owner_loop)
    _HOST_READY[graph]=(ref(runtime),ref(worker),port,bundle,use,handle,handle.selection_digest,wake)
    graph._GraphCoordinator__d13_cache_use_release_wake_v3=wake
    return wake


def require_actual_d13_host_consumer_ready_v3(graph):
    state=_HOST_READY.get(graph)
    if state is None:
        sdk_ref=_SDK_READY.get(graph);sdk=None if sdk_ref is None else sdk_ref()
        if sdk is None or sdk.phase!='ready':
            raise AuthorityUnavailable('D13 actual Host/controlled SDK consumer-ready protocol is absent')
        sdk._actual_v3()
        return sdk
    runtime_ref,worker_ref,port,bundle,use,handle,selection,wake=state
    runtime,worker=runtime_ref(),worker_ref()
    if (runtime is None or worker is None or runtime._worker is not worker or runtime._v2_model_bundle is not bundle
            or use is not graph._GraphCoordinator__d13_cache_use_control_v2 or use.fence_port is not port
            or use.bundle is not bundle or handle._closed or handle.selection_digest!=selection
            or graph._GraphCoordinator__store._runtime_storage_v3 is not handle
            or graph._GraphCoordinator__d13_cache_use_release_wake_v3 is not wake
            or wake.runtime()is not runtime or wake.worker()is not worker or wake.graph()is not graph):
        raise AuthorityUnavailable('D13 actual Host consumer readiness/retention owner changed')
    use._actual()
    return state


def release_actual_d13_host_consumer_ready_v3(graph):
    state=_HOST_READY.pop(graph,None)
    if state is not None and graph._GraphCoordinator__d13_cache_use_release_wake_v3 is state[-1]:
        graph._GraphCoordinator__d13_cache_use_release_wake_v3=None


_SDK_CONSUMERS=WeakKeyDictionary()
_SDK_STATES=WeakKeyDictionary()
_SDK_READY=WeakKeyDictionary()
_SDK_CLOSURES=WeakKeyDictionary()
_SDK_METADATA_LISTENERS=WeakKeyDictionary()


class _ControlledSDKD13ConsumersV3:
    def __init__(self,issuer,*,worker,graph,bootstrap,daemon,descriptor,closed,census):
        from threading import Event
        if issuer is not _ISSUER:raise AuthorityUnavailable('actual controlled SDK worker capture issuer required')
        self.worker,self.graph,self.bootstrap,self.daemon=worker,graph,bootstrap,daemon
        self.descriptor,self.closed_services,self.census=descriptor,closed,census
        self.control,self.gate=daemon.c09_control,daemon.c09_gate
        self.store=graph._GraphCoordinator__store;self.handle=self.store._runtime_storage_v3
        self.port=graph._GraphCoordinator__content_fence_v2
        self.use=graph._GraphCoordinator__d13_cache_use_control_v2
        self.bundle=self.use.bundle
        self.namespace=self.bundle.installation_policy.namespace
        self.authority_namespace=self.bundle.installation_policy.authority_namespace
        self.final_mark=Event();self.phase='dormant';self.admission=self.receipt=self.closure=None
        self.capture_thread=get_ident()
        self.selection_digest=self.handle.selection_digest
        _SDK_CONSUMERS[self]=self._identity_v3()
        self._record_state_v3()
    def _record_state_v3(self):
        _SDK_STATES[self]=(self.phase,canonical_digest(self.admission),canonical_digest(self.receipt),self.closure)
    def _identity_v3(self):
        return (self.worker,self.graph,self.bootstrap,self.daemon,self.descriptor,self.closed_services,self.census,
            self.control,self.gate,self.store,self.handle,self.port,self.use,self.bundle,self.namespace,
            self.authority_namespace,self.final_mark,self.capture_thread,self.selection_digest)
    def _actual_v3(self):
        from ..host.c09_controlled_sdk_bootstrap_v3 import VerifiedControlledSDKInstallerOriginalV3
        from ..authority_service.d13_cache_use_control_v2 import InstalledD13CacheUseControlPortV2
        if (_SDK_CONSUMERS.get(self)!=self._identity_v3()
                or _SDK_STATES.get(self)!=(self.phase,canonical_digest(self.admission),canonical_digest(self.receipt),self.closure)
                or self.phase=='closed'
                or self.graph._GraphCoordinator__store is not self.store or self.store._runtime_storage_v3 is not self.handle
                or self.handle._closed or self.handle.selection_digest!=self.selection_digest
                or self.graph._GraphCoordinator__bootstrap is not self.bootstrap
                or type(self.use)is not InstalledD13CacheUseControlPortV2
                or self.graph._GraphCoordinator__d13_cache_use_control_v2 is not self.use
                or self.graph._GraphCoordinator__content_fence_v2 is not self.port
                or self.use.fence_port is not self.port or self.use.bundle is not self.bundle
                or self.phase!='dormant'and self.use.use_policy.consumer_cohort_digest!=installed_d13_consumer_cohort_digest_v3()
                or self.worker._closed or self.worker._thread.ident!=self.capture_thread):
            raise AuthorityUnavailable('actual SDK consumer lost its originating worker/Graph/ports/selection')
        self.use._actual();self.census.require_installed_cohort_v3()
        core_handle=self.daemon.core._runtime_storage_v3
        if (core_handle._closed or core_handle.selection_digest!=self.selection_digest
                or self.daemon._resolved_storage_composition_v3.control is not self.control):
            raise AuthorityUnavailable('SDK consumer differs from its actual selected Core/Graph cohort')
        self.descriptor.require_current(config=self.gate._installed_config_v3,
            inventory=self.daemon.config.c09_maintenance_factory.inventory,
            peer=self.daemon.config.c09_maintenance_factory.peer)
        qualification=self.gate._controlled_sdk_activation_v3
        if (qualification is None or type(qualification.qualification)is not VerifiedControlledSDKInstallerOriginalV3
                or qualification.summary['mode']!='controlled_sdk_genesis' or qualification.summary['process_count']!=1
                or qualification.qualification.descriptor is not self.descriptor
                or qualification.qualification.process_census is not self.census):
            raise AuthorityUnavailable('actual SDK consumer has no exact independent Root SDK installation contract')
        qualification.qualification.require_consumer_disposition_root_v4(closed=self.closed_services)
        core_handle.context.require_current('business')
        if self.handle.source_kind=='host_graph_v4':self.handle.host_binding._require_custody_v4()
        return self
    def _require_service_v3(self,service,db):
        self._actual_v3()
        if (self.phase!='marking' or service is not self.daemon.core._d13_cache_use_controls_v2.get(self.authority_namespace)
                or service.core is not self.daemon.core or db is not service.core._db or not db.in_transaction
                or service.use_policy!=self.use.use_policy or service.maintenance_policy!=self.use.maintenance_policy
                or self.admission is None):
            raise AuthorityUnavailable('SDK ready Core record requires its exact final installed service and peer admission')
        peer=self.daemon.config.c09_maintenance_factory.peer
        if self.gate._peer_admission_originals_v3.get(peer)!=self.admission:
            raise AuthorityUnavailable('actual SDK signed peer admission changed before its ready record')
        return service
    async def mark_ready_v3(self,*,peer_admission):
        import asyncio
        from ..authority_service.d13_cache_use_control_v2 import retain_controlled_sdk_d13_consumer_ready_v3
        from ..authority_service.d13_cache_use_contract_v2 import D13ControlledSDKConsumerReadyReceiptV3
        def capture(graph):
            self._actual_v3()
            if graph is not self.graph or self.phase!='dormant':
                raise AuthorityUnavailable('SDK consumer ready marker is one original actual worker step')
            peer=self.daemon.config.c09_maintenance_factory.peer
            if self.gate._peer_admission_originals_v3.get(peer)!=peer_admission:
                raise AuthorityUnavailable('SDK ready needs its actual durable registered peer admission')
            self.control.verify_original_v1(peer_admission,'admission_digest')
            self.admission=peer_admission;self.phase='marking';self._record_state_v3()
        await self.worker.call(capture)
        if self.handle.source_kind=='host_graph_v4':
            self.handle.host_binding.custody.promote_business_v4(self.handle.host_binding,peer_admission)
        service=self.daemon.core._d13_cache_use_controls_v2[self.authority_namespace]
        credential=self.daemon.config.local_administrator_credential('d13_cache_use_install',self.authority_namespace)
        receipt=await asyncio.to_thread(retain_controlled_sdk_d13_consumer_ready_v3,service,
            credential=credential,proof=self)
        def finish(graph):
            self._actual_v3()
            if (graph is not self.graph or type(receipt)is not D13ControlledSDKConsumerReadyReceiptV3
                    or receipt.namespace!=self.namespace or receipt.peer_admission_digest!=self.admission['admission_digest']
                    or receipt.consumer_cohort_digest!=self.use.use_policy.consumer_cohort_digest
                    or receipt.use_policy_digest!=self.use.use_policy.digest):
                raise AuthorityUnavailable('SDK ready acknowledgement differs from its actual Core original')
            self.receipt=receipt;self.phase='ready';self._record_state_v3()
            _SDK_READY[graph]=ref(self)
            _SDK_METADATA_LISTENERS.pop(self.daemon.server,None)
            graph._GraphCoordinator__d13_cache_use_release_wake_v3=_ControlledSDKD13ReleaseWakeV3(self)
        await self.worker.call(finish)
        return receipt
    async def drain_v3(self):
        def drain(graph):
            self._actual_v3()
            if graph is not self.graph:raise AuthorityUnavailable('SDK drain crossed its actual worker')
            self.phase='draining';self._record_state_v3();self.final_mark.clear()
            from .d13_cache_use_admission_v2 import reconcile_graph_d13_cache_use_cleanup_v2,_RETAINED,_GraphConsumerOwnerV2
            from .d13_natural_original_use_v3 import _RETAINED as originals
            reconcile_graph_d13_cache_use_cleanup_v2(graph)
            pending=sum(type(owner)is _GraphConsumerOwnerV2 and owner.graph is graph for owner in _RETAINED.values())
            pending+=sum(owner.work.coordinator is graph for owner in originals.values())
            if pending:return dict(status='pending',retained_original_receivers=pending)
            _SDK_READY.pop(graph,None)
            wake=graph._GraphCoordinator__d13_cache_use_release_wake_v3
            if type(wake)is _ControlledSDKD13ReleaseWakeV3 and wake.owner()is self:
                graph._GraphCoordinator__d13_cache_use_release_wake_v3=None
            self.phase='drained';self._record_state_v3()
            return dict(status='complete',retained_original_receivers=0)
        return await self.worker.call(drain)
    async def close_v3(self):
        import asyncio
        if self.phase=='closed':
            require_actual_controlled_sdk_consumers_stopped_v3(self,daemon=self.daemon)
            return dict(status='complete',closure=self.closure)
        if self.phase!='drained':
            result=await self.drain_v3()
            if result['status']!='complete':return result
        await self.worker.close()
        if not self.port._closed:await asyncio.to_thread(self.port.close)
        if (not self.worker._stopped.done()or self.worker._thread.is_alive()
                or not self.store._closed or not self.port._closed):
            raise AuthorityUnavailable('SDK final consumer closure lacks actual worker/store/port stop')
        closure=_ControlledSDKD13ConsumerClosureV3(_ISSUER,self)
        self.closure=closure;self.phase='closed';_SDK_CONSUMERS.pop(self,None);_SDK_STATES.pop(self,None)
        return dict(status='complete',closure=closure)


class _ControlledSDKD13ReleaseWakeV3:
    def __init__(self,owner):self.owner=ref(owner)
    def __call__(self):
        owner=self.owner()
        if owner is not None:owner.final_mark.set()


class _ControlledSDKD13ConsumerClosureV3:
    def __init__(self,issuer,owner):
        if issuer is not _ISSUER or owner.phase!='drained':
            raise AuthorityUnavailable('actual drained SDK worker closure producer required')
        self.worker,self.store,self.port=owner.worker,owner.store,owner.port
        self.connection=self.store._db
        self.descriptor,self.census,self.selected_digest=owner.descriptor,owner.census,owner.selection_digest
        self.original=dict(schema='sylanne3.d13.controlled-sdk-consumer-closed.v3',
            descriptor_digest=owner.descriptor.payload['descriptor_digest'],
            process_census_digest=owner.census.digest,selected_digest=owner.selection_digest,
            authority_process_original=owner.census.authority_process_original,
            resource_operation_id=owner.census.original['resource_operation_id'])
        _SDK_CLOSURES[self]=(self.worker,self.store,self.port,self.descriptor,self.census,canonical_digest(self.original))
    def require_current_v3(self,*,descriptor):
        if (_SDK_CLOSURES.get(self)!=(self.worker,self.store,self.port,self.descriptor,self.census,canonical_digest(self.original))
                or (self.descriptor.source_digest,self.descriptor.payload['descriptor_digest'])!=
                    (descriptor.source_digest,descriptor.payload['descriptor_digest'])or not self.worker._stopped.done()
                or self.worker._thread.is_alive()or not self.store._closed or not self.port._closed):
            raise AuthorityUnavailable('SDK closure lost its actual final worker/store/port disposition')
        self.census.require_installed_cohort_v3()
        import sqlite3
        try:self.connection.execute('SELECT 1')
        except sqlite3.ProgrammingError:pass
        else:raise AuthorityUnavailable('actual SDK Graph connection remains open after worker stop')
        return self


async def prepare_controlled_sdk_d13_consumers_v3(*,worker,dormant,bootstrap):
    if type(dormant)is not _FreshD13DormantCompositionV3:raise AuthorityUnavailable('actual fresh SDK dormant handle required')
    dormant.require_v3();daemon=dormant.daemon
    qualification=dormant.request.activation.qualification
    root_descriptor,closed_services,process_census=qualification.descriptor,qualification.closed,qualification.process_census
    from ..graph_worker import GraphWorker
    from ..graph_coordinator import GraphCoordinator
    from ..host.c09_controlled_sdk_bootstrap_v3 import (
        VerifiedControlledSDKRootDescriptorV3,VerifiedControlledSDKClosedServicesOriginalV3,VerifiedControlledSDKProcessCensusV3)
    from ..authority_service.c09_initial_segmented_genesis_v4 import VerifiedControlledSDKInitialGenesisOriginalV4
    if (type(worker)is not GraphWorker or type(root_descriptor)is not VerifiedControlledSDKRootDescriptorV3
            or type(closed_services)not in {VerifiedControlledSDKClosedServicesOriginalV3,VerifiedControlledSDKInitialGenesisOriginalV4}
            or type(process_census)is not VerifiedControlledSDKProcessCensusV3):
        raise AuthorityUnavailable('actual independent controlled SDK factory/cohort originals required')
    closed_services.require_current();process_census.require_installed_cohort_v3()
    def capture(graph):
        if (type(graph)is not GraphCoordinator or worker._thread.ident!=get_ident()
                or graph._GraphCoordinator__bootstrap is not bootstrap):
            raise AuthorityUnavailable('SDK dormant consumer must be captured on its actual GraphWorker.call')
        from ..authority_service.d13_cache_use_control_v2 import InstalledD13CacheUseControlPortV2
        from ..runtime_storage_v3 import InstalledRuntimeStorageV3
        if (type(graph._GraphCoordinator__d13_cache_use_control_v2)is not InstalledD13CacheUseControlPortV2
                or type(graph._GraphCoordinator__store._runtime_storage_v3)is not InstalledRuntimeStorageV3):
            raise AuthorityUnavailable('SDK dormant consumer has no real installed Source port/selected Graph')
        host_handle=graph._GraphCoordinator__store._runtime_storage_v3
        if host_handle.source_kind=='host_graph_v4':
            host_handle.host_binding.custody.bind_worker_v4(worker,host_handle.host_binding)
        proof=_ControlledSDKD13ConsumersV3(_ISSUER,worker=worker,graph=graph,bootstrap=bootstrap,daemon=daemon,
            descriptor=root_descriptor,closed=closed_services,census=process_census)
        return proof._actual_v3()
    if dormant.bound_consumers is not None:raise AuthorityUnavailable('one exact SDK dormant worker capture required')
    dormant.request.sdk_startup_worker=worker
    try:proof=await worker.call(capture)
    except BaseException:
        await worker.close()
        dormant.request.sdk_startup_worker=None
        raise
    dormant.request.sdk_startup_worker=None
    dormant.request.sdk_consumers=proof;dormant.bound_consumers=proof
    daemon._d13_controlled_sdk_consumers_v3=proof
    return proof


async def prepare_current_controlled_sdk_d13_consumers_v3(*,worker,daemon,bootstrap):
    """Capture the real cold SDK worker after its original process retirement proof."""
    from ..authority_service.daemon import AuthorityDaemon,_bootstrap_control_quantum_v3
    from ..host.c09_controlled_sdk_bootstrap_v3 import VerifiedControlledSDKInstallerOriginalV3
    from ..authority_service.c09_process_identity_v1 import require_process_retired_v1
    from ..graph_worker import GraphWorker
    from ..graph_coordinator import GraphCoordinator
    if type(daemon)is not AuthorityDaemon or type(worker)is not GraphWorker or daemon._closed:
        raise AuthorityUnavailable('actual current cold SDK daemon/worker required')
    activation=daemon.c09_gate._controlled_sdk_activation_v3
    qualification=None if activation is None else activation.qualification
    if (type(qualification)is not VerifiedControlledSDKInstallerOriginalV3
            or qualification.original is None or qualification.fresh_finalization is not None
            or qualification.control is not daemon.c09_control or qualification.gate is not daemon.c09_gate
            or daemon._d13_controlled_sdk_consumers_v3 is not None):
        raise AuthorityUnavailable('cold SDK capture requires the actual independent cold registry qualification')
    require_process_retired_v1(qualification.original['authority_process_original'])
    qualification.process_census.require_installed_cohort_v3()
    with _bootstrap_control_quantum_v3(daemon.c09_control)as meter:
        stored=daemon.c09_control.read_writer_peer_registry_activation_v3()
        original=stored.original
        qualification.require_activation_original_for_gate_v3(original,control=daemon.c09_control,
            gate=daemon.c09_gate,meter=meter)
    def capture(graph):
        if (type(graph)is not GraphCoordinator or worker._thread.ident!=get_ident()
                or graph._GraphCoordinator__bootstrap is not bootstrap):
            raise AuthorityUnavailable('cold SDK consumer must be captured on its actual GraphWorker.call')
        handle=graph._GraphCoordinator__store._runtime_storage_v3
        if handle.source_kind=='host_graph_v4':handle.host_binding.custody.bind_worker_v4(worker,handle.host_binding)
        proof=_ControlledSDKD13ConsumersV3(_ISSUER,worker=worker,graph=graph,bootstrap=bootstrap,
            daemon=daemon,descriptor=qualification.descriptor,closed=None,census=qualification.process_census)
        return proof._actual_v3()
    proof=await worker.call(capture)
    if proof.handle.source_kind=='host_graph_v4':proof.handle.host_binding.custody.census.close()
    daemon._d13_controlled_sdk_consumers_v3=proof
    return proof



def require_controlled_sdk_fresh_publication_material_v3(prepared,*,closed_services,consumer_closure):
    """Attest actual local RAM closure; Root separately rechecks its durable/OS census."""
    from hashlib import sha256
    from ..host.c09_controlled_sdk_bootstrap_v3 import VerifiedControlledSDKClosedServicesOriginalV3
    if (type(prepared)is not _PreparedFreshD13InstallationV3 or type(closed_services)is not VerifiedControlledSDKClosedServicesOriginalV3
            or _PREPARED_FRESH.get(prepared)!=(prepared.profile_bytes,prepared.assets_bytes,
                canonical_digest(prepared.publication_receipt),prepared.consumer,canonical_digest(prepared.activation_original))):
        raise AuthorityUnavailable('actual unpublished preparation and closed SDK Authority originals required')
    consumer=prepared.consumer
    if (type(consumer)is not _ControlledSDKD13ConsumersV3 or consumer.phase!='closed'
            or consumer.closure is not consumer_closure or closed_services.control is not consumer.control):
        raise AuthorityUnavailable('publication requires the preparation originating actual drained/stopped worker')
    closed_services.require_current()
    consumer_closure.require_current_v3(descriptor=consumer.descriptor)
    consumer.census.require_installed_cohort_v3()
    if closed_services.authority!=consumer.census.authority_process_original:
        raise AuthorityUnavailable('publication closure crossed its original SDK process')
    context=consumer.daemon._resolved_storage_composition_v3.context
    body=dict(schema='sylanne3.d13.controlled-sdk-fresh-publication-witness.v3',
        authority_id=consumer.control.authority_id,installation_id=consumer.control.installation_id,
        control_store_id=consumer.control.control_store_id,namespace=consumer.authority_namespace,
        authority_process_original=closed_services.authority,
        resource_operation_id=consumer.census.original['resource_operation_id'],
        root_census_original=consumer.census.original,descriptor_digest=consumer.descriptor.payload['descriptor_digest'],
        closed_services_originals=closed_services.originals,closed_services_root=closed_services.root,
        consumer_closures=(consumer_closure.original,),consumer_closure_root=canonical_digest((consumer_closure.original,)),
        selected_manifest=context.manifest,selected_manifest_digest=context.manifest_digest,
        pointer_version=context.pointer_version,storage_generation=context.storage_generation,
        selection_digest=consumer.selection_digest,activation_original=prepared.activation_original,
        consumer_cohort_digest=installed_d13_consumer_cohort_digest_v3(),
        source_profile_sha256=sha256(prepared.source_profile_bytes).hexdigest(),
        source_assets_sha256=sha256(prepared.source_assets_bytes).hexdigest(),
        prepared_receipt=prepared.publication_receipt,prepared_receipt_digest=canonical_digest(prepared.publication_receipt))
    original=consumer.control.sign_original_v1(body['schema'],body,'publication_witness_digest')
    return original,prepared.profile_bytes,prepared.assets_bytes


def require_actual_controlled_sdk_consumer_ready_control_v3(proof,*,service,db):
    if type(proof)is not _ControlledSDKD13ConsumersV3:
        raise AuthorityUnavailable('actual same-worker controlled SDK ready issuer required')
    proof._require_service_v3(service,db)
    return proof.control


def require_actual_controlled_sdk_consumer_ready_material_v3(proof,*,service,db):
    if type(proof)is not _ControlledSDKD13ConsumersV3:
        raise AuthorityUnavailable('actual controlled SDK ready material issuer required')
    proof._require_service_v3(service,db)
    from ..authority_service.c09_process_identity_v1 import read_process_identity_v1
    import os
    config=proof.daemon.config;peer=config.c09_maintenance_factory.peer
    admission=proof.admission;context=proof.daemon._resolved_storage_composition_v3.context
    if admission['process_original']!=read_process_identity_v1(os.getpid()):
        raise AuthorityUnavailable('SDK ready crossed its actual sole Authority process')
    original=proof.census.original
    resource_selection=canonical_digest((original['resource_operation_id'],original['selection_scope'],
        original['run_cgroup'],original['app_cgroup'],original['run_deadline_monotonic_ns']))
    qualification=proof.gate._controlled_sdk_activation_v3.qualification
    disposition_root=qualification.require_consumer_disposition_root_v4(closed=proof.closed_services)
    producer=canonical_digest((proof.namespace,proof.selection_digest,proof.descriptor.source_digest,
        disposition_root,proof.census.digest,admission['admission_digest'],
        context.manifest_digest,proof.use.use_policy.digest,resource_selection,
        proof.handle.host_binding.original['binding_digest']if proof.handle.source_kind=='host_graph_v4'else None))
    return dict(namespace=proof.namespace,authority_namespace=proof.authority_namespace,
        installation_id=service.installation_id,authority_id=proof.control.authority_id,
        control_store_id=proof.control.control_store_id,use_policy_ref=proof.use.use_policy.policy_ref,
        use_policy_digest=proof.use.use_policy.digest,consumer_cohort_digest=proof.use.use_policy.consumer_cohort_digest,
        peer_certificate_sha256=peer[0],profile_id=peer[1],peer_admission_digest=admission['admission_digest'],
        process_incarnation=admission['process_incarnation'],process_original_digest=canonical_digest(admission['process_original']),
        selected_manifest_digest=context.manifest_digest,pointer_version=context.pointer_version,
        storage_generation=context.storage_generation,descriptor_digest=proof.descriptor.payload['descriptor_digest'],
        process_census_digest=proof.census.digest,producer_binding_digest=producer,
        resource_operation_id=original['resource_operation_id'],resource_selection_digest=resource_selection,resource_deadline_utc=None)


class _FreshD13DormantCompositionV3:
    def __init__(self,issuer,request,daemon):
        if issuer is not _ISSUER:raise AuthorityUnavailable('actual dormant fresh SDK composition issuer required')
        self.request,self.daemon=request,daemon
        self.control,self.gate=daemon.c09_control,daemon.c09_gate
        self.bound_consumers=None
        self.listener=None
        self.listener_loop=None
    def require_v3(self):
        self.request.require_v3(self.daemon.config)
        if (self.request.consumer_mode!='controlled_sdk' or self.request.daemon is not self.daemon
                or self.daemon.core._d13_cache_use_controls_v2 or self.bound_consumers is not self.request.sdk_consumers):
            raise AuthorityUnavailable('actual SDK dormant composition changed or already admitted')
        return self


    async def start_metadata_listener_v3(self):
        import asyncio
        self.require_v3()
        if self.listener is not None or self.daemon._listener is not None:
            raise AuthorityUnavailable('one actual SDK dormant metadata listener required')
        server=self.daemon.server
        _SDK_METADATA_LISTENERS[server]=self
        try:
            self.listener=await server.start(self.daemon.config.bind_host,self.daemon.config.bind_port,self.daemon.config.tls)
        except BaseException:
            _SDK_METADATA_LISTENERS.pop(server,None)
            raise
        self.listener_loop=asyncio.get_running_loop()
        self.daemon._listener=self.listener
        return self.listener
    async def close_metadata_listener_v3(self):
        import asyncio
        if self.listener is None:return
        if asyncio.get_running_loop()is not self.listener_loop:
            future=asyncio.run_coroutine_threadsafe(self.close_metadata_listener_v3(),self.listener_loop)
            await asyncio.wrap_future(future)
            return
        self.listener.close()
        await self.listener.wait_closed()
        self.daemon._listener=None
        self.listener=None
        _SDK_METADATA_LISTENERS.pop(self.daemon.server,None)


def require_controlled_sdk_dormant_rpc_v3(server,method):
    """Closed startup transport gate, checked before any business command decoding."""
    dormant=_SDK_METADATA_LISTENERS.get(server)
    if dormant is None:return
    if (type(dormant)is not _FreshD13DormantCompositionV3 or dormant.daemon.server is not server
            or dormant.daemon._closed or method not in ('handshake','installation_grant_v2')):
        raise AuthorityUnavailable('SDK dormant transport admits only actual handshake/installation metadata')
    if dormant.bound_consumers is None:dormant.require_v3()
    else:dormant.bound_consumers._actual_v3()


def require_actual_controlled_sdk_consumer_closure_v3(closure,*,descriptor,resource_operation_id):
    if type(closure)is not _ControlledSDKD13ConsumerClosureV3:
        raise AuthorityUnavailable('actual stopped/drained SDK consumer closure required')
    closure.require_current_v3(descriptor=descriptor)
    if closure.original['resource_operation_id']!=resource_operation_id:
        raise AuthorityUnavailable('SDK closed consumer belongs to another original Root resource window')
    return closure


def issue_fresh_d13_dormant_composition_v3(request,daemon):
    request.require_v3(daemon.config)
    if request.consumer_mode!='controlled_sdk' or request.daemon is not daemon:
        raise AuthorityUnavailable('actual SDK fresh daemon owner required')
    return _FreshD13DormantCompositionV3(_ISSUER,request,daemon)


def require_no_live_controlled_sdk_consumers_v3(*,resource_operation_id):
    if any(owner.census.original['resource_operation_id']==resource_operation_id for owner in _SDK_CONSUMERS):
        raise AuthorityUnavailable('actual previous SDK consumer remains live; drain/stop required')


def require_actual_controlled_sdk_consumers_stopped_v3(proof,*,daemon):
    if (type(proof)is not _ControlledSDKD13ConsumersV3 or proof.daemon is not daemon
            or proof.phase!='closed' or type(proof.closure)is not _ControlledSDKD13ConsumerClosureV3):
        raise AuthorityUnavailable('SDK Authority still owns actual consumers; drain remains pending')
    closure=proof.closure
    if (_SDK_CLOSURES.get(closure)!=(closure.worker,closure.store,closure.port,closure.descriptor,
            closure.census,canonical_digest(closure.original))
            or not closure.worker._stopped.done()or closure.worker._thread.is_alive()
            or not closure.store._closed or not closure.port._closed):
        raise AuthorityUnavailable('SDK Authority close lacks its actual worker/store/port stop')
    return closure
