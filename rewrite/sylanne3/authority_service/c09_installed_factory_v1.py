"""Concrete cold-process C09 assembly over the daemon's exact current bundle.

The administrator supplies typed installation assets, never per-request
callbacks or caller-created cleanup receipts. No old process hot-swap exists.
"""
from __future__ import annotations

from pathlib import Path
from dataclasses import dataclass

from .contract import AuthorityUnavailable
from .c09_storage_control_v1 import SURFACES
from .c09_storage_maintenance_v1 import InstalledC09MaintenanceV1
from .c09_surface_cleanup_v1 import InstalledC09SurfaceCleanupV1
from .c09_close_apply_v1 import InstalledC09CloseApplyV1
from .c09_graph_application_v1 import InstalledC09GraphApplicationV1
from .erasure_closure_inventory import AuthorityErasureClosureInventory
from ..graph_coordinator import GraphCoordinator, namespace_ref
from ..graph_store import ProductionGraphStore
from ..graph_types import TypeRegistry
from ..runtime.c09_installation_inventory_v2 import InstallationFilesystemManifestV2
from ..runtime_contracts import NamespaceId
from ..domains.d02.body_quote_original import D02BodyQuoteAuthority
from ..runtime.issuers import D02ResourceIssuer


class _LocalInstalledFencePortV1:
    """Actual local Authority service calls; no synthesized permits or ACKs."""
    def __init__(self, service, credential, subject, namespace):
        self.service, self.credential, self.subject, self.namespace = service, credential, subject, namespace

    def _scope(self, namespace, authority_namespace):
        if namespace != self.namespace or authority_namespace != self.service.namespace:
            raise AuthorityUnavailable("installed maintenance graph namespace differs")

    def current_anchor(self, *, namespace, authority_namespace):
        self._scope(namespace, authority_namespace)
        return self.service.current_anchor(credential=self.credential, subject=self.subject)

    def begin_fence(self, *, namespace, authority_namespace, holder, generation,
                    operation, operation_id, expected_anchor, **effect):
        self._scope(namespace, authority_namespace)
        if generation != expected_anchor.activation_generation:
            raise AuthorityUnavailable("installed local fence generation differs")
        return self.service.begin_fence(credential=self.credential, subject=self.subject,
            holder=holder, operation=operation, operation_id=operation_id,
            expected_anchor=expected_anchor, **effect)

    def validate_fence(self, scope):
        self._scope(scope.namespace, scope.authority_namespace)
        return self.service.validate_fence(credential=self.credential,
            subject=self.subject, permit=scope.permit)

    def finish_fence(self, scope, *, request_id, request_digest):
        self._scope(scope.namespace, scope.authority_namespace)
        return self.service.finish_fence(credential=self.credential, subject=self.subject,
            permit=scope.permit, request_id=request_id, request_digest=request_digest)


@dataclass(frozen=True, slots=True)
class InstalledAuthorityMaintenanceServicesV3:
    """Actual locally authenticated Core, journal, Owner and erasure components."""
    config: object
    core: object
    deletion: object
    execution: object
    fence_service: object
    pairings: object
    sessions: object
    owner_tickets: object
    scoped: object
    recovery: object
    erasure: object
    accepted: object


class InstalledC09MaintenanceFactoryV1:
    """Bind all four current stores, recovery readers and twelve actual cleaners.

    Provider prompt caches and nonempty backups require their independently
    installed provider/backup cleaner. A sanitized Graph hash cannot prove
    those external surfaces empty. Missing support remains a specific HOLD.
    """
    def __init__(self, *, namespace, peer, registry, resource_issuer,
            body_authority, inventory_manifest, target_directory,
            provider_cache_cleanup, controlled_backup_cleanup=None, controlled_backup_registry=None,
            budget_job_issuer=None):
        if (type(namespace) is not NamespaceId or type(registry) is not TypeRegistry
                or type(resource_issuer) is not D02ResourceIssuer
                or type(body_authority) is not D02BodyQuoteAuthority
                or type(inventory_manifest) is not InstallationFilesystemManifestV2
                or inventory_manifest.namespace != namespace_ref(namespace)
                or type(peer) is not tuple or len(peer) != 2):
            raise AuthorityUnavailable("typed installed C09 factory assets required")
        from ..runtime.issuers import D11BudgetJobIssuer
        if budget_job_issuer is not None and (type(budget_job_issuer) is not D11BudgetJobIssuer
                or budget_job_issuer.resource_issuer is not resource_issuer):
            raise AuthorityUnavailable("C09 Life requires the actual same-installation D11/D02 issuers")
        for service in (provider_cache_cleanup, controlled_backup_cleanup):
            if service is not None and any(not callable(getattr(service, name, None))
                    for name in ("clean_installed_surface_v1", "reread_installed_surface_v1")):
                raise AuthorityUnavailable("installed surface cleaner and independent reader required")
        if provider_cache_cleanup is None:
            raise AuthorityUnavailable("installed provider cache disposition service required")
        if controlled_backup_registry is not None:
            from .d12_package_supervisor_journal_v2 import InstalledPackageSupervisorJournalV2
            if (type(controlled_backup_registry) is not InstalledPackageSupervisorJournalV2
                    or controlled_backup_cleanup is not None):
                raise AuthorityUnavailable("one exact installed managed-backup registry is required")
        self.namespace, self.peer, self.registry = namespace, peer, registry
        self.resource_issuer, self.body_authority = resource_issuer, body_authority
        self.budget_job_issuer = budget_job_issuer
        self.inventory, self.target_directory = inventory_manifest, Path(target_directory)
        self.provider_cache_cleanup = provider_cache_cleanup
        self.controlled_backup_cleanup = controlled_backup_cleanup
        self.controlled_backup_registry = controlled_backup_registry
        self._peer_registry_census_v3=None
        self._controlled_sdk_registry_assets_v3=None
        self._peer_registry_preparations_v3={}

    def install_peer_registry_census_v3(self, census):
        from .c09_writer_peer_activation_v3 import InstalledPeerRegistryCensusV3
        if (type(census) is not InstalledPeerRegistryCensusV3 or census.inventory is not self.inventory
                or census.peer!=self.peer or self._peer_registry_census_v3 is not None
                or self._controlled_sdk_registry_assets_v3 is not None):
            raise AuthorityUnavailable('actual same-installation Root peer census must install once')
        self._peer_registry_census_v3=census

    def install_controlled_sdk_peer_registry_v3(self, *, root_descriptor, closed_services=None):
        from ..host.c09_controlled_sdk_bootstrap_v3 import require_controlled_sdk_registry_assets_v3
        require_controlled_sdk_registry_assets_v3(root_descriptor=root_descriptor,closed_services=closed_services,
            inventory=self.inventory,peer=self.peer)
        if self._peer_registry_census_v3 is not None or self._controlled_sdk_registry_assets_v3 is not None:
            raise AuthorityUnavailable('one exact installed peer registry initializer required')
        self._controlled_sdk_registry_assets_v3=(root_descriptor,closed_services)

    def advance_peer_registry_preparation_v3(self, *, control, config, context):
        from .c09_storage_maintenance_v1 import (InstalledC09WriterGateV1,
            VerifiedInstalledPeerRegistryActivationV3,_PEER_REGISTRY_ACTIVATION_ISSUER_V3)
        from .daemon import _bootstrap_control_quantum_v3
        state=self._peer_registry_preparations_v3.get(control)
        if state is None:
            gate=InstalledC09WriterGateV1(control=control,installed_config=config)
            original=control.read_writer_peer_registry_activation_v3()
            state={'gate':gate,'original':original,'phase':'qualify','existing':original is not None}
            self._peer_registry_preparations_v3[control]=state
            if original is None and self._peer_registry_census_v3 is not None:
                self._peer_registry_census_v3.begin(control=control,config=config,context=context)
            return dict(status='progress',phase='writer_peer_registry_qualification')
        gate=state['gate']
        if gate._installed_config_v3 is not config:
            raise AuthorityUnavailable('peer registry preparation changed selected installed config')
        if state['phase']=='complete':return gate
        if state['phase']=='pending_coverage':
            from .c09_writer_peer_originals_v3 import VerifiedWriterPeerPendingStartCoverageV3
            if self._controlled_sdk_registry_assets_v3 is not None:
                hold=state['sdk_census']
            else:
                if 'pending_hold' not in state:
                    supervisor=self._peer_registry_census_v3.supervisor
                    supervisor.install_peer_registry_start_v3(control=control,gate=gate)
                    state['pending_hold']=supervisor.hold_pending_peer_start_coverage_v3()
                hold=state['pending_hold']
            gate._pending_start_bootstrap_hold_v3=hold
            result=control.advance_writer_peer_pending_start_coverage_v3(gate,operation_id=None,context=context)
            if type(result) is not VerifiedWriterPeerPendingStartCoverageV3:
                if result['phase']=='writer_peer_pending_start':
                    gate.resolve_pending_start_coverage_v3(result['pending_start_original'])
                return result
            gate._bootstrap_pending_start_coverage_v3=result
            if self._controlled_sdk_registry_assets_v3 is not None:hold.close()
            else:hold.close(result.original)
            gate._pending_start_bootstrap_hold_v3=None
            state['phase']='complete'
            return gate
        if state['original'] is None and self._peer_registry_census_v3 is not None:
            self._peer_registry_census_v3.advance()
        elif self._controlled_sdk_registry_assets_v3 is None and state['original'] is None:
            raise AuthorityUnavailable('missing peer registry has no actual installed process census activation; HOLD')
        if self._controlled_sdk_registry_assets_v3 is not None and 'sdk_census' not in state:
            from ..host.c09_controlled_sdk_bootstrap_v3 import hold_controlled_sdk_process_census_v3
            descriptor,_=self._controlled_sdk_registry_assets_v3
            state['sdk_census']=hold_controlled_sdk_process_census_v3(root_descriptor=descriptor,config=config,
                inventory=self.inventory,peer=self.peer)
        with gate.hold_peer_registry_activation_v3() as token:
            with _bootstrap_control_quantum_v3(control) as meter:
                if self._controlled_sdk_registry_assets_v3 is not None:
                    descriptor,closed=self._controlled_sdk_registry_assets_v3
                    from ..host.c09_controlled_sdk_bootstrap_v3 import (
                        issue_controlled_sdk_genesis_v3,read_controlled_sdk_activation_original_v3)
                    if state['original'] is None:
                        qualification=issue_controlled_sdk_genesis_v3(gate=gate,control=control,config=config,
                            closed_services=closed,root_descriptor=descriptor,process_census=state['sdk_census'],meter=meter)
                    else:
                        qualification=read_controlled_sdk_activation_original_v3(gate=gate,control=control,config=config,
                            root_descriptor=descriptor,process_census=state['sdk_census'],original=state['original'].original,meter=meter)
                    activation=VerifiedInstalledPeerRegistryActivationV3(_PEER_REGISTRY_ACTIVATION_ISSUER_V3,
                        control=control,gate=gate,qualification=qualification,hold_token=token,meter=meter)
                    gate._controlled_sdk_activation_v3=activation
                elif state['original'] is None:
                    activation=VerifiedInstalledPeerRegistryActivationV3(_PEER_REGISTRY_ACTIVATION_ISSUER_V3,
                        control=control,gate=gate,qualification=self._peer_registry_census_v3,hold_token=token,meter=meter)
                if state['original'] is None:
                    state['original']=control.retain_writer_peer_registry_activation_v3(gate,activation=activation)
                else:
                    state['original'].require_current(meter=meter)
                actual_original=state['original'].original if state['existing'] else state['original']
                gate.require_registry_activation_domain_v3(actual_original,meter=meter)
                control.install_writer_peer_gate_v3(gate)
        if self._peer_registry_census_v3 is not None:self._peer_registry_census_v3.close()
        state['phase']='pending_coverage'
        return dict(status='progress',phase='writer_peer_pending_start_coverage')

    def take_prepared_peer_registry_gate_v3(self, *, control, config):
        state=self._peer_registry_preparations_v3.pop(control,None)
        if state is None or state['phase']!='complete' or state['gate']._installed_config_v3 is not config:
            raise AuthorityUnavailable('actual complete selected peer registry Gate required before composition')
        return state['gate']

    def close_peer_registry_preparation_v3(self, control):
        state=self._peer_registry_preparations_v3.pop(control,None)
        if state is not None and 'sdk_census' in state:state['sdk_census'].close()
        if state is not None and 'pending_hold' in state:state['pending_hold'].close()
        if self._peer_registry_census_v3 is not None:self._peer_registry_census_v3.close()

    def __call__(self, *, daemon, control, gate):
        namespace = namespace_ref(self.namespace)
        return self._compose_existing_components_v3(config=daemon.config, core=daemon.core,
            service=daemon.server._v2_fences[namespace],
            erasure=daemon.server._current_erasure_prepares[(namespace,control.installation_id)],
            accepted=daemon.server._current_accepted_erasure_reads[(namespace,control.installation_id)],
            control=control, gate=gate, selected_composition=daemon._resolved_storage_composition_v3)

    def compose_for_cold_maintenance_v3(self, services, selected_composition):
        if type(services) is not InstalledAuthorityMaintenanceServicesV3:
            raise AuthorityUnavailable("actual installed maintenance service composition required")
        from .c09_storage_maintenance_v1 import InstalledC09WriterGateV1
        control=selected_composition.control
        gate=selected_composition.peer_gate
        if type(gate) is not InstalledC09WriterGateV1 or gate._installed_config_v3 is not services.config:
            raise AuthorityUnavailable('actual qualified selected registry Gate required for cold maintenance')
        return self._compose_existing_components_v3(config=services.config, core=services.core,
            service=services.fence_service, erasure=services.erasure, accepted=services.accepted,
            control=control, gate=gate, selected_composition=selected_composition)

    def _compose_existing_components_v3(self, *, config, core, service, erasure, accepted,
            control, gate, selected_composition):
        selected_composition.require_current()
        namespace=namespace_ref(self.namespace)
        installed=config.installations_v2.get(self.peer)
        if (installed is None or installed.installation_id!=control.installation_id
                or self.inventory.installation_id!=control.installation_id
                or self.inventory.authority_id!=control.authority_id
                or config.namespace_bindings_v2.get((*self.peer,self.namespace))!=namespace
                or service.core is not core or service.namespace!=namespace
                or erasure._recovery.core is not core):
            raise AuthorityUnavailable("C09 factory differs from actual installed component identity")
        credential=config.local_administrator_credential("c09_maintenance",namespace)
        core._require(credential,"execution_redaction_install",namespace)
        recovery = erasure._recovery
        scoped = recovery.scoped_store
        closure = AuthorityErasureClosureInventory(scoped=scoped, installation_id=control.installation_id)
        subject = "mtls:sha256:" + self.peer[0]
        graph = selected_composition.open_graph(self.registry)
        try:
            bootstrap = object()
            coordinator = GraphCoordinator(graph, bootstrap,
                holder=installed.administrator_holder,
                content_fence_v2=_LocalInstalledFencePortV1(service, credential, subject, self.namespace))
            application = InstalledC09GraphApplicationV1(control=control, core=core,
                scoped=scoped, coordinator=coordinator, bootstrap=bootstrap,
                namespace=self.namespace, subject=subject, credential=credential)
            close_apply = InstalledC09CloseApplyV1(control=control, service=service,
                recovery=recovery, graph_application=application, subject=subject, credential=credential)
            cleaners = {surface: InstalledC09SurfaceCleanupV1(control=control, gate=gate,
                inventory_manifest=self.inventory, surface=surface, registry=self.registry)
                for surface in SURFACES - {"model_prompt_caches"}}
            cleaners["model_prompt_caches"] = self.provider_cache_cleanup
            if self.controlled_backup_cleanup is not None:
                cleaners["controlled_backups"] = self.controlled_backup_cleanup
            elif self.controlled_backup_registry is not None:
                from .d12_managed_backup_cleanup_v2 import InstalledD12ManagedBackupCleanupV2
                cleaners["controlled_backups"] = InstalledD12ManagedBackupCleanupV2(control=control, gate=gate,
                    inventory_manifest=self.inventory, supervisor_journal=self.controlled_backup_registry)
            internal = dict(core._execution_redaction_c04_services.get(namespace, {}))
            core.install_current_c09_recovery_readers_v4(closure=closure, graph=graph,
                namespace_id=self.namespace, resource_issuer=self.resource_issuer,
                body_authority=self.body_authority, internal_services=internal,
                budget_job_issuer=self.budget_job_issuer)
            result = InstalledC09MaintenanceV1(control=control, gate=gate, core=core,
                closure=closure, graph=graph, namespace_id=self.namespace,
                accepted_service=accepted, inventory_manifest=self.inventory,
                target_directory=self.target_directory, subject=subject, credential=credential,
                service_handles=(graph,), surface_services=cleaners, close_apply_service=close_apply)
            result._installed_deployment_config_v2 = config
            from .c09_lifecycle_clock_v3 import InstalledC09LifecycleClockV3
            result._installed_lifecycle_clock_v3 = InstalledC09LifecycleClockV3(
                config=config,maintenance=result,namespace=namespace)
            gate.install_current_maintenance_v3(result)
            result._installed_d02_resource_issuer_v2 = self.resource_issuer
            result._installed_d11_budget_job_issuer_v2 = self.budget_job_issuer
            from .c09_paged_capture_control_v2 import InstalledC09PagedCaptureControlV2
            result._paged_capture_control_v2 = InstalledC09PagedCaptureControlV2(result)
            coordinator.install_current_c09_source_plan_resources_v2(
                bootstrap, result._paged_capture_control_v2)
            erasure._plan_graph_verifier.install_source_plan_control_v2(result._paged_capture_control_v2)
            return result
        except BaseException:
            graph.close()
            raise
