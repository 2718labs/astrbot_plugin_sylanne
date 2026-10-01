"""Real pinned native/13-domain Host readiness over paired Authority mTLS.

Systemd is an explicit subprocess boundary fixture. OS birth/retirement,
package/catalogue/native mapping, Owner, journals and four-file selection are real.
This does not assert a privileged installed service deployment.
"""
import asyncio
import json
import os
import subprocess
import sys
import time
from uuid import uuid4
import pytest

from test_d04_owner_semantic_initialization_v3 import (installed_d04_root,real_owner_case,current_owner,install_d04_test_composition)
from d04_numeric_authority_acceptance_support_v3 import install_actual_root_authority_case_v3
from sylanne3.authority_service.contract import AuthorityUnavailable
from sylanne3.authority_service.d12_installed_supervisor_v1 import InstalledD12SystemdSupervisorV1,D12SupervisorObservationV1
from sylanne3.authority_service.d12_installation_lifecycle_v1 import InstalledD12InstallationLifecycleV1
from sylanne3.authority_service.d12_installation_lifecycle_rpc_v1 import install_d12_installation_lifecycle_v1,BOOTSTRAP_METHOD
from sylanne3.authority_service.d12_operation_status_v1 import InstalledD12OperationStatusServiceV1
from sylanne3.authority_service.d12_operation_status_rpc_v1 import install_d12_operation_status_service_v1
from sylanne3.authority_service.v2_contract import SCHEMA
from sylanne3.host.d12_operation_status_port_v1 import InstalledD12OperationStatusPortV1
from sylanne3.host.d12_installation_control_port_v1 import InstalledD12InstallationControlPortV1
from sylanne3.runtime.d12_installed_services_v1 import install_d12_services_v1
from sylanne3.runtime.lifecycle_operations_v1 import digest


def eventually(function,timeout=25):
    until=time.monotonic()+timeout
    while time.monotonic()<until:
        result=function()
        if result:return result
        time.sleep(.05)
    raise AssertionError('actual lifecycle stage did not complete')


@pytest.mark.asyncio
async def test_actual_pinned_host_bootstrap_active_and_exact_replay(tmp_path,installed_d04_root):
    resources=[];controllers=[];processes=[]
    async def after_role(case):
        await asyncio.to_thread(install_d04_test_composition,case)
        support=await asyncio.to_thread(install_actual_root_authority_case_v3,case,owner_loop=asyncio.get_running_loop())
        resources.append(support)
        def run():
            core,graph,store=case['core'],case['graph'],case['store'];namespace=case['authority_namespace']
            prior=core._authorize_callback
            core._authorize_callback=lambda credential,action,ns,holder: (ns==namespace and (
                credential==case['admin_peer'] and action in {'d12_operation_install','d12_lifecycle_install'}
                or credential==case['peer'] and action in {'d12_operation_status','d12_lifecycle_control','d12_lifecycle_bootstrap'})) or prior(credential,action,ns,holder)
            service=InstalledD12OperationStatusServiceV1(fences=case['server']._v2_fences[namespace],
                owner_tickets=case['server']._v2_owner_tickets,source_graph_db=tmp_path/'business.db',
                namespace_id=case['namespace'],installation_id=case['policy'].installation_id)
            service.install_schema(case['admin_peer']);install_d12_operation_status_service_v1(case['server'],service)
            first=subprocess.Popen([sys.executable,'-c','import time; time.sleep(120)']);processes.append(first)
            current=[first,'1'*32];starts=[];stops=[];ready={}
            supervisor=object.__new__(InstalledD12SystemdSupervisorV1)
            def observe():
                process,invocation=current;live=process.poll() is None
                body=dict(unit_name='fixture-host.service',load_state='loaded',active_state='active' if live else 'inactive',
                    sub_state='running' if live else 'dead',main_pid=process.pid if live else 0,invocation_id=invocation,
                    control_group='/fixture-host',process_ids=(process.pid,) if live else (),unit_fragment_sha256='f'*64)
                return D12SupervisorObservationV1(**body,observation_digest=digest(body))
            def stop(*,expected_invocation_id):
                assert current[1]==expected_invocation_id
                stops.append(expected_invocation_id);current[0].terminate();current[0].wait(timeout=5)
                return observe()
            def start(*,expected_prior_invocation_id):
                assert observe().stopped_and_drained and current[1]==expected_prior_invocation_id
                starts.append(expected_prior_invocation_id)
                code="""import json,sys,time
from pathlib import Path
from sylanne3.host.affect_scheme_asset import load_verified_affect_scheme
from sylanne3.native_runtime.loader import load_production_native
root=Path(sys.argv[1]);pin=sys.argv[2]
native=load_production_native(root,trusted_manifest_sha256=pin)
registry=load_verified_affect_scheme(root,pin).registry
assert registry.complete
print(json.dumps({'catalogue_hash':registry.type_registry.catalogue_hash,'ready_domains':sorted(registry.registrations)}),flush=True)
time.sleep(120)
"""
                environment=dict(os.environ,PYTHONPATH=str(case['package_root']/'rewrite'))
                process=subprocess.Popen([sys.executable,'-c',code,str(case['package_root']),case['manifest_digest']],
                    env=environment,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
                processes.append(process);current[:]=[process,'2'*32]
                line=process.stdout.readline()
                if not line:raise AssertionError('actual qualified Host failed to initialize: '+process.stderr.read())
                ready.update(json.loads(line));return observe()
            supervisor.read_current_host_state_v1=observe;supervisor.stop_original_host_v1=stop;supervisor.start_stopped_host_v1=start
            controller=InstalledD12InstallationLifecycleV1(status_service=service,control=support.storage_control,
                supervisor=supervisor,package_root=case['package_root'],expected_manifest_digest=case['manifest_digest'],
                peer_certificate_sha256=case['peer'].certificate_sha256,peer_profile_id=case['installed_bundle'].tls_profile.profile_id,
                drain_timeout_seconds=30)
            import functools,traceback
            def diagnosed(method):
                @functools.wraps(method)
                def call(*args,**kwargs):
                    try:return method(*args,**kwargs)
                    except Exception:
                        traceback.print_exc();raise
                return call
            for name in ('_constraints_in_tx','_owner_still_current','_storage','_operation'):
                setattr(controller,name,diagnosed(getattr(controller,name)))
            original_run=controller._run
            def traced_run(operation):
                def trace(frame,event,arg):
                    if frame.f_code is original_run.__func__.__code__ and event=='exception':
                        traceback.print_exception(*arg)
                    return trace
                sys.settrace(trace)
                try:return original_run(operation)
                finally:sys.settrace(None)
            controller._run=traced_run
            controllers.append(controller);controller.install_schema(case['admin_peer']);install_d12_installation_lifecycle_v1(case['server'],controller)
            status=InstalledD12OperationStatusPortV1(coordinator=graph,bootstrap=case['bootstrap'],authority_port=case['port'])
            control=InstalledD12InstallationControlPortV1(coordinator=graph,bootstrap=case['bootstrap'],authority_port=case['port'])
            product=install_d12_services_v1(graph,bootstrap=case['bootstrap'],operation_status_port=status,lifecycle_control_port=control)
            with current_owner(case) as (authority,lease):
                pause=str(uuid4());intent={'object_ref':'installation:'+case['policy'].installation_id,'control':'pause','test_intent':None,
                    'config_diff':{'schema':'d12.installation_control.v1','scope':'whole_host','expected_lifecycle_epoch':0,'prior_pause_operation_id':None}}
                result=product.commit_current_control_v1(authority,lease,operation_id=pause,request_digest=digest(intent),input_data=intent)
                assert result.operation_id==pause
                paused=eventually(lambda:(value if (value:=control._rpc(authority,lease,action='status',operation_id=pause)).state=='completed' else None))
                assert 'stage:paused' in paused.coverage and stops==['1'*32] and first.poll() is not None
                resume=str(uuid4())
                control._rpc(authority,lease,action='resume',pause_operation_id=pause,operation_id=resume,expected_lifecycle_epoch=1)
                eventually(lambda:ready)
                from sylanne3.authority_service.d12_lifecycle_gate_v1 import require_lifecycle_admission_in_tx_v1
                with core._tx() as db:
                    with pytest.raises(AuthorityUnavailable):require_lifecycle_admission_in_tx_v1(db,namespace,action='graph_write')
                command={'namespace':namespace,'operation_id':resume,'expected_epoch':2,'process_id':current[0].pid,
                    'invocation_id':'2'*32,**ready}
                def bootstrap(body):
                    async def call():
                        handshake,_=case['port']._identity()
                        return await case['port']._transport._content_rpc(case['port']._request,handshake,BOOTSTRAP_METHOD,body,protocol=SCHEMA)
                    return case['port']._submit(case['port']._with_session_repair(call))
                response=bootstrap(command);original=response['bootstrap_original_ref']
                active=eventually(lambda:(value if (value:=bootstrap(command))['lifecycle_state']=='active' else None))
                assert active['bootstrap_original_ref']==original and active['lifecycle_epoch']==2
                assert bootstrap(command)['bootstrap_original_ref']==original
                assert starts==['1'*32]
                assert core._db.execute('SELECT COUNT(*) FROM authority_d12_lifecycle_bootstraps_v1 WHERE namespace=? AND epoch=2',(namespace,)).fetchone()==(1,)
                with pytest.raises(RuntimeError):bootstrap({**command,'invocation_id':'3'*32})
                with core._tx() as db:require_lifecycle_admission_in_tx_v1(db,namespace,action='graph_write')
                assert control._rpc(authority,lease,action='inspect').state=='active'
                # A real ordinary content fence opens only after the active CAS.
                view=graph.read_current_owner_view(case['bootstrap'],actor=authority.actor,namespace=case['namespace'],
                    purpose='workbench_user_action',audience='owner',expected_principal=case['principal'],
                    owner_session_token=case['owner_session_token'],owner_session_request=case['owner_session_request'])
                assert view.graph_binding.principal==case['principal']
                assert 'stage:active' in control._rpc(authority,lease,action='status',operation_id=resume).coverage
        await asyncio.to_thread(run)
    try:
        await real_owner_case(tmp_path,'owned',installed_package_root=installed_d04_root,
            after_role_initialization=after_role,enable_d09_workbench=True,
            extra_owner_capabilities=('workbench.control','workbench.maintain'))
    finally:
        for controller in controllers:controller.close()
        for process in processes:
            if process.poll() is None:process.terminate()
            process.wait(timeout=5)
        for resource in resources:resource.close()
