"""Paired independent control/status/bootstrap routes, usable while Host is down."""
from dataclasses import asdict

from .contract import AuthorityUnavailable, identifier
from .d12_installation_lifecycle_v1 import InstalledD12InstallationLifecycleV1

CONTROL_METHOD="d12_installation_control_v1"
BOOTSTRAP_METHOD="d12_lifecycle_host_bootstrap_v1"


def install_d12_installation_lifecycle_v1(server, service):
    if (type(service) is not InstalledD12InstallationLifecycleV1
            or service.core is not server._core or server._v2_fences.get(service.namespace) is not service.fences):
        raise AuthorityUnavailable("installed lifecycle Authority differs")
    services=getattr(server,"_d12_installation_lifecycle_services_v1",None)
    if services is None:
        services={};server._d12_installation_lifecycle_services_v1=services
    key=(service.namespace,service.installation_id)
    if key in services and services[key] is not service:
        raise AuthorityUnavailable("installation lifecycle already bound")
    services[key]=service


def install_d12_source_inspection_migration_v1(server, migration):
    from .source_inspection_migration_v1 import InstalledSourceInspectionMigrationV1
    if type(migration) is not InstalledSourceInspectionMigrationV1:
        raise AuthorityUnavailable("actual installed inspection migration service required")
    lifecycle=migration.lifecycle
    key=(lifecycle.namespace,lifecycle.installation_id)
    if (lifecycle.core is not server._core
            or getattr(server,"_d12_installation_lifecycle_services_v1",{}).get(key) is not lifecycle
            or server._v2_fences.get(lifecycle.namespace) is not lifecycle.fences):
        raise AuthorityUnavailable("inspection migration belongs to another installed Authority/lifecycle")
    services=getattr(server,"_d12_source_inspection_migration_services_v1",None)
    if services is None:
        services={}
        server._d12_source_inspection_migration_services_v1=services
    if key in services and services[key] is not migration:
        raise AuthorityUnavailable("installed inspection migration is already bound")
    services[key]=migration
    from ..runtime.source_inspection_member_admission_v1 import install_source_inspection_member_verifier_v1
    install_source_inspection_member_verifier_v1(server,migration)


def dispatch_d12_installation_lifecycle_v1(server,method,credential,profile_id,manifest_digest,command):
    if method not in {CONTROL_METHOD,BOOTSTRAP_METHOD}:
        return None
    if type(command) is not dict or "namespace" not in command:
        raise AuthorityUnavailable("lifecycle command shape differs")
    namespace=identifier(command["namespace"],"namespace")
    fence=server._bound_v2_service(credential,profile_id,manifest_digest,namespace)
    installed=server._installations_v2[(credential.certificate_sha256,profile_id)]
    service=getattr(server,"_d12_installation_lifecycle_services_v1",{}).get((namespace,installed.installation_id))
    if service is None or service.fences is not fence:
        raise AuthorityUnavailable("whole-Host lifecycle service unavailable")
    if method==BOOTSTRAP_METHOD:
        expected={"namespace","operation_id","expected_epoch","process_id","invocation_id","catalogue_hash","ready_domains"}
        if set(command)!=expected or type(command["ready_domains"]) is not list:
            raise AuthorityUnavailable("Host bootstrap fields differ")
        fields={key:value for key,value in command.items() if key!="namespace"}
        fields["ready_domains"]=tuple(fields["ready_domains"])
        ref=service.register_current_host_bootstrap_v1(credential=credential,
            peer_certificate_sha256=credential.certificate_sha256,peer_profile_id=profile_id,**fields)
        return service.read_current_host_bootstrap_progress_v1(ref)
    common={"namespace","action","owner_actor_id","owner_session_token","owner_session_request"}
    extra={"reconcile_held_inspection_v1":{"operation_id","input_data"},"inspection_reconciliation_status":{"operation_id"},"read_inspection_recovery_options_v1":{"parent_workflow_operation_id"},"resume_completed_inspection_v1":{"operation_id","input_data"},"inspection_recovery_status":{"operation_id"},"inspection_workflow_accept":{"operation_id","input_data"},"inspection_workflow_status":{"operation_id"},"inspection_access":set(),"inspection_status":{"operation_id"},"inspect":set(),"submit":{"original_ref"},"status":{"operation_id"},"continue":{"operation_id"},
           "resume":{"pause_operation_id","operation_id","expected_lifecycle_epoch"},
           "upgrade_catalogue":{"operation_id","pause_operation_id","target_cohort_ref","source_catalogue_hash"},
           "migrate_source_inspection":{"operation_id","pause_operation_id","scope_kind","target_refs",
               "deadline_utc","interpretation_status_discovery"}}
    action=command.get("action")
    if action not in extra or set(command)!=common|extra[action]:
        raise AuthorityUnavailable("whole-Host lifecycle action fields differ")
    kwargs=server._owner_session_kwargs(command,namespace,installed.installation_id)
    kwargs.update(credential=credential,actor=identifier(command["owner_actor_id"],"owner_actor_id"))
    if action in {"reconcile_held_inspection_v1","inspection_reconciliation_status","read_inspection_recovery_options_v1"}:
        from .source_inspection_migration_v1 import InstalledSourceInspectionMigrationV1
        migration=getattr(server,"_d12_source_inspection_migration_services_v1",{}).get((namespace,installed.installation_id))
        if type(migration) is not InstalledSourceInspectionMigrationV1 or migration.lifecycle is not service:
            raise AuthorityUnavailable("actual installed held reconciliation service unavailable")
        if action=="read_inspection_recovery_options_v1":
            return {"inspection_recovery_options":migration.workflow.recovery.read_options_current_v1(
                parent_workflow_operation_id=command["parent_workflow_operation_id"],**kwargs)}
        if action=="reconcile_held_inspection_v1":
            result=migration.workflow.held_reconciliation.accept_v1(operation_id=command["operation_id"],
                input_data=command["input_data"],**kwargs)
        else:
            result=migration.workflow.read_current_v1(operation_id=command["operation_id"],**kwargs)
            if result["schema"]!="d12.source-inspection-held-reconciliation-view.v1":
                raise AuthorityUnavailable("requested operation is not a held inspection reconciliation")
        return {"inspection_reconciliation":result}
    if action in {"resume_completed_inspection_v1","inspection_recovery_status"}:
        from .source_inspection_migration_v1 import InstalledSourceInspectionMigrationV1
        migration=getattr(server,"_d12_source_inspection_migration_services_v1",{}).get((namespace,installed.installation_id))
        if type(migration) is not InstalledSourceInspectionMigrationV1 or migration.lifecycle is not service:
            raise AuthorityUnavailable("actual installed inspection recovery service unavailable")
        if action=="resume_completed_inspection_v1":
            result=migration.workflow.recovery.accept_completed_v1(operation_id=command["operation_id"],
                input_data=command["input_data"],**kwargs)
        else:
            result=migration.workflow.read_current_v1(operation_id=command["operation_id"],**kwargs)
            if result["schema"]!="d12.source-inspection-recovery-view.v1":
                raise AuthorityUnavailable("requested operation is not a fresh inspection recovery")
        return {"inspection_recovery":result}
    if action in {"inspection_workflow_accept","inspection_workflow_status"}:
        from .source_inspection_migration_v1 import InstalledSourceInspectionMigrationV1
        migration=getattr(server,"_d12_source_inspection_migration_services_v1",{}).get((namespace,installed.installation_id))
        if type(migration) is not InstalledSourceInspectionMigrationV1 or migration.lifecycle is not service:
            raise AuthorityUnavailable("registered inspection workflow service unavailable")
        if action=="inspection_workflow_accept":
            result=migration.workflow.accept_current_v1(operation_id=command["operation_id"],input_data=command["input_data"],**kwargs)
        else:
            result=migration.workflow.read_current_v1(operation_id=command["operation_id"],**kwargs)
        return {"inspection_workflow":result}
    if action in {"inspection_access","inspection_status"}:
        from .source_inspection_migration_v1 import InstalledSourceInspectionMigrationV1
        migration=getattr(server,"_d12_source_inspection_migration_services_v1",{}).get((namespace,installed.installation_id))
        if type(migration) is not InstalledSourceInspectionMigrationV1 or migration.lifecycle is not service:
            raise AuthorityUnavailable("registered inspection maintenance service unavailable")
        if action=="inspection_access":
            return {"inspection_access":migration.read_current_access_v1(**kwargs)}
        return {"inspection_migration":migration.read_current_status_v1(operation_id=command["operation_id"],**kwargs)}
    if action=="migrate_source_inspection":
        from .source_inspection_migration_v1 import InstalledSourceInspectionMigrationV1
        migration=getattr(server,"_d12_source_inspection_migration_services_v1",{}).get((namespace,installed.installation_id))
        if (type(migration) is not InstalledSourceInspectionMigrationV1 or migration.lifecycle is not service
                or type(command["target_refs"]) is not list):
            raise AuthorityUnavailable("registered inspection migration service/target scope unavailable")
        return {"inspection_migration":migration.advance_current_migration_v1(
            **{key:command[key] for key in extra[action]},**kwargs)}
    if action=="upgrade_catalogue":
        from .graph_catalogue_upgrade_v1 import InstalledGraphCatalogueUpgradeV1
        catalogue=getattr(server,"_d12_graph_catalogue_upgrade_services_v1",{}).get((namespace,installed.installation_id))
        if type(catalogue) is not InstalledGraphCatalogueUpgradeV1 or catalogue.lifecycle is not service:
            raise AuthorityUnavailable("registered catalogue maintenance service unavailable")
        return {"catalogue_upgrade":catalogue.advance_current_upgrade_v1(
            **{key:command[key] for key in extra[action]},**kwargs)}
    if action=="inspect":
        return {"lifecycle_head":asdict(service.inspect_current_lifecycle_v1(**kwargs))}
    if action=="submit":
        original=service.submit_current_control_v1(original_ref=command["original_ref"],**kwargs)
    elif action=="resume":
        original=service.resume_paused_installation_v1(**{key:command[key] for key in extra[action]},**kwargs)
    else:
        original=service.read_current_control_v1(operation_id=command["operation_id"],continue_original=action=="continue",**kwargs)
    return {"original":original.to_wire()}


__all__=("CONTROL_METHOD","BOOTSTRAP_METHOD","install_d12_installation_lifecycle_v1","install_d12_source_inspection_migration_v1","dispatch_d12_installation_lifecycle_v1")
