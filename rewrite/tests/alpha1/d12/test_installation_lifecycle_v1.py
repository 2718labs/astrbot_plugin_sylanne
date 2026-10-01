"""Durable installed control against real Owner/Core/journals/Graph and OS PIDs.

The systemd command boundary is a local process supervisor fixture, deliberately
not a claim that a privileged systemd deployment or native Host resume ran.
An unqualified restart must remain bootstrap-only, never report active.
"""
import os
import subprocess
import sys
import time
from uuid import uuid4

import pytest

from rewrite.tests.alpha1.integration import test_owner_signed_chain as owner_fixture
from rewrite.tests.alpha1.authority.test_local_owner_round_trip import ADMIN, AUTH_NS, PEER, ROLE
from rewrite.tests.alpha1.d12.test_installed_lifecycle_services_v1 import _current_owner, _clock
from sylanne3.authority_service.contract import AuthorityUnavailable
from sylanne3.authority_service.c09_storage_control_v1 import C09StorageControlV1, InstalledC09InstanceLeaseV1
from sylanne3.authority_service.linux_bootstrap_v1 import build_initial_inventory_v1, bootstrap_current_storage_v1
from sylanne3.authority_service.d12_installed_supervisor_v1 import InstalledD12SystemdSupervisorV1, D12SupervisorObservationV1
from sylanne3.authority_service.d12_installation_lifecycle_v1 import InstalledD12InstallationLifecycleV1
from sylanne3.authority_service.d12_installation_lifecycle_rpc_v1 import install_d12_installation_lifecycle_v1, dispatch_d12_installation_lifecycle_v1, CONTROL_METHOD
from sylanne3.authority_service.d12_operation_status_v1 import InstalledD12OperationStatusServiceV1
from sylanne3.authority_service.d12_operation_status_rpc_v1 import install_d12_operation_status_service_v1, dispatch_d12_operation_status_v1
from sylanne3.authority_service.d12_lifecycle_gate_v1 import require_lifecycle_admission_in_tx_v1, require_lifecycle_exclusion_in_tx_v1, D12LifecycleAdmissionV1
from sylanne3.authority_service.v2_contract import to_wire as fence_wire
from sylanne3.authority_service.v2_owner_session import to_wire as session_wire
from sylanne3.host.d12_operation_status_port_v1 import InstalledD12OperationStatusPortV1
from sylanne3.host.d12_installation_control_port_v1 import InstalledD12InstallationControlPortV1
from sylanne3.runtime.d11_types import graph_type_specs
from sylanne3.runtime.d12_installed_services_v1 import install_d12_services_v1
from sylanne3.runtime.lifecycle_operations_v1 import decode_original, digest


def _until(predicate, timeout=5):
    deadline=time.monotonic()+timeout
    while time.monotonic()<deadline:
        value=predicate()
        if value:
            return value
        time.sleep(0.02)
    raise AssertionError("actual original stage did not become observable")


def test_signed_pause_drains_real_pid_and_independent_resume_stays_bootstrap_only(tmp_path, monkeypatch):
    # Configure intended capabilities before the real signed issuance. No grant
    # row or current admission is edited after issuance.
    issue=owner_fixture._owner_issue
    def control_issue(*args):
        ticket,operation,value=issue(*args)
        return ticket,operation,{**value,"capabilities":[*value["capabilities"],"workbench.control"]}
    monkeypatch.setattr(owner_fixture,"_owner_issue",control_issue)
    state=tmp_path/"state";state.mkdir()
    chain=owner_fixture._real_owner_chain(state,extra_purpose="audit",extra_capability="workbench.maintain",extra_specs=graph_type_specs())
    graph,core=chain.resources[:2]
    prior_authorizer=core._authorize_callback
    core._authorize_callback=lambda credential,action,namespace,holder: (namespace==AUTH_NS and (
        credential==ADMIN and action in {"d12_operation_install","d12_lifecycle_install"}
        or credential==PEER and action in {"d12_operation_status","d12_lifecycle_control","d12_lifecycle_bootstrap"})) or prior_authorizer(credential,action,namespace,holder)
    chain.port.read_ingress_clock=lambda _: _clock(chain)
    control_lock=InstalledC09InstanceLeaseV1(tmp_path/"control.lock")
    processes=[];controller=None
    try:
        status_service=InstalledD12OperationStatusServiceV1(fences=chain.service,owner_tickets=chain.server._v2_owner_tickets,
            source_graph_db=state/"business.db",namespace_id=ROLE,installation_id="installation")
        status_service.install_schema(ADMIN);install_d12_operation_status_service_v1(chain.server,status_service)
        class LocalStatus(InstalledD12OperationStatusPortV1):
            def _call(self,*,method,namespace,actor,token,request,original_ref,permit=None,refresh=False):
                command={"namespace":AUTH_NS,"owner_actor_id":actor,"owner_session_token":token,
                    "owner_session_request":session_wire(request),"original_ref":original_ref}
                command.update({"permit":fence_wire(permit)} if permit is not None else {"refresh":refresh})
                result=dispatch_d12_operation_status_v1(chain.server,method,PEER,"installed","c"*64,command)
                return None if result["original"] is None else decode_original(result["original"])
        class LocalControl(InstalledD12InstallationControlPortV1):
            def _rpc(self,authority,lease,*,action,**extra):
                token,request=self.coordinator._GraphCoordinator__owner_session_proofs[lease]
                result=dispatch_d12_installation_lifecycle_v1(chain.server,CONTROL_METHOD,PEER,"installed","c"*64,
                    {"namespace":AUTH_NS,"action":action,"owner_actor_id":authority.actor,"owner_session_token":token,
                     "owner_session_request":session_wire(request),**extra})
                return D12LifecycleAdmissionV1(**result["lifecycle_head"]) if action=="inspect" else decode_original(result["original"])
        status=LocalStatus(coordinator=chain.coordinator,bootstrap=chain.bootstrap,authority_port=chain.port)
        command_port=LocalControl(coordinator=chain.coordinator,bootstrap=chain.bootstrap,authority_port=chain.port)
        port=install_d12_services_v1(chain.coordinator,bootstrap=chain.bootstrap,operation_status_port=status,lifecycle_control_port=command_port)
        authority,lease,_=_current_owner(chain)
        token,request=chain.coordinator._GraphCoordinator__owner_session_proofs[lease]
        key=tmp_path/"control.key";key.write_bytes(os.urandom(32))
        files={"graph":state/"business.db","core":state/"authority.db","deletion":state/"deletion.db","execution":state/"execution.db"}
        directories={name:state/name for name in ("controlled_backup","export","rebuild_temp","cache")}
        for path in directories.values():path.mkdir()
        inventory=build_initial_inventory_v1(authority_id=chain.authority_id,installation_id="installation",namespace=AUTH_NS,files=files,directories=directories)
        control=C09StorageControlV1(control_path=tmp_path/"control.db",key_path=key,installation_id="installation",
            authority_id=chain.authority_id,control_store_id="control",key_id="control-key",lease=control_lock,resource_roots=(state,))
        # Real SQLite identities and authenticated four-file pointer, no DTO
        # current-authority substitute. There are no concurrent writers here.
        for resource in chain.resources:
            db=getattr(resource,"_db",None)
            if db is not None:db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        metadata,_=chain.coordinator._v2_graph_stamp(ROLE)
        bootstrap_current_storage_v1(control=control,files=files,inventory=inventory,
            identities={"core":chain.authority_id,"deletion":metadata.requirements.deletion_journal_id,
                        "execution":metadata.requirements.execution_journal_id,"graph":metadata.requirements.graph_incarnation})
        first=subprocess.Popen([sys.executable,"-c","import time; time.sleep(60)"]);processes.append(first)
        current=[first,"1"*32];starts=[];stops=[]
        # Boundary fixture replaces systemd only. Birth/liveness and retirement
        # are still read by the product from real /proc, and no readiness is faked.
        supervisor=object.__new__(InstalledD12SystemdSupervisorV1)
        def observation():
            process,invocation=current;live=process.poll() is None
            material=dict(unit_name="fixture.service",load_state="loaded",active_state="active" if live else "inactive",
                sub_state="running" if live else "dead",main_pid=process.pid if live else 0,invocation_id=invocation,
                control_group="/fixture",process_ids=(process.pid,) if live else (),unit_fragment_sha256="f"*64)
            return D12SupervisorObservationV1(**material,observation_digest=digest(material))
        def stop(*,expected_invocation_id):
            assert current[1]==expected_invocation_id
            stops.append(expected_invocation_id);current[0].terminate();current[0].wait(timeout=5)
            return observation()
        def start(*,expected_prior_invocation_id):
            assert observation().stopped_and_drained and current[1]==expected_prior_invocation_id
            starts.append(expected_prior_invocation_id)
            process=subprocess.Popen([sys.executable,"-c","import time; time.sleep(60)"]);processes.append(process)
            current[:]=[process,"2"*32]
            return observation()
        supervisor.read_current_host_state_v1=observation;supervisor.stop_original_host_v1=stop;supervisor.start_stopped_host_v1=start
        controller=InstalledD12InstallationLifecycleV1(status_service=status_service,control=control,supervisor=supervisor,
            package_root=tmp_path,expected_manifest_digest="f"*64,peer_certificate_sha256="a"*64,peer_profile_id="installed",drain_timeout_seconds=2)
        controller.install_schema(ADMIN);install_d12_installation_lifecycle_v1(chain.server,controller)
        credentials=dict(credential=PEER,actor="owner-actor",session_token=token,session_request=request)
        view=port.read_current_installation_lifecycle_v1(authority,lease)
        assert view["schema"]=="d12.installation_lifecycle_view.v1" and view["lifecycle_epoch"]==0 and view["state"]=="active"
        operation=str(uuid4());intent={"object_ref":"installation:installation","control":"pause","test_intent":None,
            "config_diff":{"schema":"d12.installation_control.v1","scope":"whole_host","expected_lifecycle_epoch":0,"prior_pause_operation_id":None}}
        with controller.rpc_activity_v1():
            accepted=port.commit_current_control_v1(authority,lease,operation_id=operation,request_digest=digest(intent),input_data=intent)
            assert accepted.kind=="control" and accepted.state=="running"
            with core._tx() as db:
                for action in ("graph_write","job","model_claim","dispatch_claim","handoff"):
                    with pytest.raises(AuthorityUnavailable):require_lifecycle_admission_in_tx_v1(db,AUTH_NS,action=action)
                require_lifecycle_admission_in_tx_v1(db,AUTH_NS,action="accounting",original_claimed=True)
                with pytest.raises(AuthorityUnavailable):require_lifecycle_admission_in_tx_v1(db,AUTH_NS,action="accounting")
                with pytest.raises(AuthorityUnavailable):require_lifecycle_exclusion_in_tx_v1(db,AUTH_NS,operation="migration")
            assert first.poll() is None and stops==[]
        paused=_until(lambda:(result if (result:=controller.read_current_control_v1(**credentials,operation_id=operation)).state=="completed" else None))
        assert first.poll() is not None and stops==["1"*32]
        assert paused.activation_generation==1 and paused.result.effective_version==1
        assert {"stage:paused","unknown_constraints_preserved"}<=set(paused.coverage)
        head=controller.inspect_current_lifecycle_v1(**credentials)
        assert (head.state,head.epoch)==("paused",1)
        assert controller.read_current_control_v1(**credentials,operation_id=operation)==paused
        assert port.commit_current_control_v1(authority,lease,operation_id=operation,request_digest=digest(intent),input_data=intent)==paused
        from sylanne3.contracts import StaleRead
        with pytest.raises(StaleRead):
            port.commit_current_control_v1(authority,lease,operation_id=operation,request_digest=digest({"changed":True}),input_data=intent)
        # Re-enrol the same principal/actor using the actual administrator
        # pairing flow. The old initiating bytes stay immutable, while a new
        # signed current session may inspect and resume the exact pause.
        from dataclasses import replace
        from datetime import datetime,timedelta,timezone
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives import serialization
        from sylanne3.authority_service.v2_owner_proof import OwnerCredentialRegistrationV1
        from sylanne3.authority_service.v2_owner_contract import OwnerActorBindingV1
        original_request_bytes=core._db.execute("SELECT session_request_json FROM authority_d12_operation_originals_v1 WHERE operation_id=?",(operation,)).fetchone()[0]
        old_credentials=dict(credentials)
        chain.source.revoke_credential(administrator_credential=ADMIN,authority_namespace=AUTH_NS,principal=chain.principal)
        with pytest.raises(AuthorityUnavailable):controller.read_current_control_v1(**old_credentials,operation_id=operation)
        replacement=Ed25519PrivateKey.generate()
        registration=OwnerCredentialRegistrationV1(chain.authority_id,AUTH_NS,"installation",chain.principal,
            "owner-key-after-pause",1,replacement.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw),"reenrol-after-pause")
        chain.source.pair_credential(administrator_credential=ADMIN,registration=registration,
            client_certificate_sha256="a"*64,valid_until_utc=(datetime.now(timezone.utc)+timedelta(hours=1)).replace(microsecond=0))
        chain.source.pair_actor(administrator_credential=ADMIN,binding=OwnerActorBindingV1(chain.authority_id,
            "installation",ROLE,"owner-actor",chain.principal,3))
        chain.server._v2_owner_proofs.register_credential(transport_credential=PEER,registration=registration)
        request=replace(request,credential_id=registration.credential_id,credential_epoch=registration.credential_epoch)
        challenge=chain.sessions.begin_login(transport_credential=PEER,request=request)
        token=chain.sessions.accept_login(transport_credential=PEER,challenge=challenge,signature=replacement.sign(challenge.signed_bytes()))
        credentials.update(session_token=token,session_request=request)
        assert controller.read_current_control_v1(**credentials,operation_id=operation)==paused
        assert core._db.execute("SELECT session_request_json FROM authority_d12_operation_originals_v1 WHERE operation_id=?",(operation,)).fetchone()==(original_request_bytes,)
        resume=str(uuid4())
        controller.resume_paused_installation_v1(**credentials,pause_operation_id=operation,operation_id=resume,expected_lifecycle_epoch=1)
        _until(lambda:starts)
        controller.resume_paused_installation_v1(**credentials,pause_operation_id=operation,operation_id=resume,expected_lifecycle_epoch=1)
        assert starts==["1"*32]
        from sylanne3.authority_service.v2_owner_session import _canonical
        assert core._db.execute("SELECT session_request_json FROM authority_d12_operation_originals_v1 WHERE operation_id=?",(resume,)).fetchone()==(_canonical(request),)
        with pytest.raises(AuthorityUnavailable):
            controller.register_current_host_bootstrap_v1(credential=PEER,peer_certificate_sha256="a"*64,peer_profile_id="installed",
                operation_id=resume,expected_epoch=2,process_id=current[0].pid,invocation_id="2"*32,
                catalogue_hash="unqualified",ready_domains=tuple(f"d{i:02}" for i in range(1,14)))
        pending=_until(lambda:(result if (result:=controller.read_current_control_v1(**credentials,operation_id=resume)).state=="pending_confirmation" else None))
        assert pending.activation_generation==1 and "stage:start_intent" in pending.coverage
        assert controller.inspect_current_lifecycle_v1(**credentials).state=="resuming"
        chain.sessions.logout(transport_credential=PEER,token=token,request=request)
        with pytest.raises(AuthorityUnavailable):controller.read_current_control_v1(**credentials,operation_id=resume)
        # All seven actual Core table families must be cold-codec-valid. The
        # target-only tables aren't installed in this source fixture.
        from sylanne3.authority_service.d12_c09_core_rows_v1 import COLUMNS,validate_d12_core_row_v1
        for table,columns in COLUMNS.items():
            if core._db.execute("SELECT 1 FROM sqlite_master WHERE name=?",(table,)).fetchone():
                for row in core._db.execute("SELECT * FROM "+table):validate_d12_core_row_v1(table,columns,row)
    finally:
        if controller is not None:controller.close()
        for process in processes:
            if process.poll() is None:process.terminate()
            process.wait(timeout=5)
        control_lock.close()
        for resource in chain.resources:resource.close()
