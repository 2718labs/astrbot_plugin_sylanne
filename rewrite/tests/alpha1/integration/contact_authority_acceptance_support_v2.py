"""Compose real initial Owner/current storage/contact services for acceptance.

The same installed classes are assembled in the daemon. No policy, permission,
claim, result, quota or current-location DTO is inserted by this fixture.
"""
from pathlib import Path
import functools
import hashlib
import hmac
import time
import traceback


def install_actual_contact_authority_case_v2(case):
    from sylanne3.authority_service.v2_scoped_erasure_store import AuthorityV2ScopedErasureStore
    from sylanne3.authority_service.v2_deletion_recovery_service import AuthorityV2DeletionPendingRecovery
    from sylanne3.authority_service.c09_close_apply_v1 import InstalledC09CloseApplyV1
    from sylanne3.authority_service.c09_graph_application_v1 import InstalledC09GraphApplicationV1
    from sylanne3.authority_service.d12_owner_storage_admission_v1 import InstalledD12OwnerStorageAdmissionServiceV1
    from sylanne3.authority_service.d10_contact_policy_service_v1 import InstalledD10ContactPolicyServiceV1
    from sylanne3.authority_service.current_source_location_v1 import InstalledCurrentSourceLocationQualifierV1
    graph,store,core,server=case['graph'],case['store'],case['core'],case['server']
    authority_namespace=case['authority_namespace'];fences=server._v2_fences[authority_namespace]
    bridge=server._v2_execution[authority_namespace]
    control=graph._actual_d04_authority_acceptance_v3.storage_control
    context=control.read_verified_current_storage_v1();context.require_current('business')
    assert context.stage=='READY'
    graph_path=Path(store._db.execute('PRAGMA database_list').fetchone()[2]).resolve()
    assert graph_path==Path(next(m['resolved_path'] for m in context.manifest['members'] if m['role']=='graph'))
    assert bridge.core is core and fences.core is core
    scoped=AuthorityV2ScopedErasureStore(core=core,fences=fences.fences,deletion=bridge.deletion,
        execution=bridge.journal,namespace=authority_namespace)
    recovery=AuthorityV2DeletionPendingRecovery(core=core,fences=fences.fences,deletion=bridge.deletion,
        execution=bridge.journal,namespace=authority_namespace,scoped_store=scoped)
    subject='mtls:sha256:'+case['peer'].certificate_sha256
    application=InstalledC09GraphApplicationV1(control=control,core=core,scoped=scoped,coordinator=graph,
        bootstrap=case['bootstrap'],namespace=case['namespace'],subject=subject,credential=case['peer'])
    close=InstalledC09CloseApplyV1(control=control,service=fences,recovery=recovery,
        graph_application=application,subject=subject,credential=case['peer'])
    control.install_applied_reader_v1(close)
    owner=InstalledD12OwnerStorageAdmissionServiceV1(fences=fences,owner_tickets=server._v2_owner_tickets,
        graph_db_path=graph_path,namespace_id=case['namespace'],installation_id=case['policy'].installation_id,
        holder=case['policy'].administrator_holder,control=control,close_apply=close)
    bundle=graph._GraphCoordinator__d04_installed_joint_assembly.admin_bundle
    policy=InstalledD10ContactPolicyServiceV1(fences=fences,owner_tickets=server._v2_owner_tickets,
        owner_service=owner,namespace=case['namespace'],installation_id=case['policy'].installation_id,
        signing_key=hmac.new(bundle.d11_signing_key,b'sylanne.authority.d10-contact-policy-signing.v1',hashlib.sha256).digest(),
        trusted_now_utc=time.time,create=True)
    # Keep the actual RPC gate, exposing only its exception chain in test logs.
    def diagnosed(method):
        @functools.wraps(method)
        def call(*args,**kwargs):
            try:return method(*args,**kwargs)
            except Exception:
                traceback.print_exc()
                raise
        return call
    for name in ('change','read_current'):
        setattr(policy,name,diagnosed(getattr(policy,name)))
    if not hasattr(server,'_d10_contact_policy_services_v1'):server._d10_contact_policy_services_v1={}
    server._d10_contact_policy_services_v1[(authority_namespace,case['policy'].installation_id)]=policy
    location=InstalledCurrentSourceLocationQualifierV1(fences=fences,scoped=scoped,control=control,
        graph_db_path=graph_path,namespace_id=case['namespace'],installation_id=case['policy'].installation_id)
    model=server._v2_model_egress[authority_namespace]
    model.install_current_source_location_v1(location)
    model._graph_verifier.install_contact_policy_service_v1(policy)
    from sylanne3.host.model_workflows_v3 import AdminModelWorkflowsV3
    if type(bundle.model_workflows) is AdminModelWorkflowsV3:
        from sylanne3.authority_service.contact_model_result_service_v2 import InstalledContactModelResultServiceV2
        server.install_contact_model_result_reader_v2(authority_namespace,
            InstalledContactModelResultServiceV2(store=model._store,fences=fences,
                graph_db_path=graph_path,d11_issuer=case['d11_issuer'],
                installation_id=case['policy'].installation_id,read_subject=subject,
                holder=case['policy'].administrator_holder,trusted_now_utc=time.time,
                source_location=location,contact_policy_service=policy))
        graph.install_contact_model_runtime_v2(case['bootstrap'],bundle)
    return policy,location
