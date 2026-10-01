"""Real fresh Core/Graph/Owner and reverse-mTLS first issue.

Only root systemd/Unix installation is a controlled boundary here. Both TLS
legs and the Graph worker's nested V2 fence RPCs use the real serialized
Authority. Four stores, actual PID admission, Ed25519 session, pending claim,
Graph proof, replay and revocation are real.
This is not privileged Linux deployment acceptance.
"""
import asyncio
from dataclasses import replace
import hashlib
import os
import ssl
from types import SimpleNamespace

import pytest
from rewrite.tests.alpha1.integration.test_owner_signed_chain import _real_owner_chain
from rewrite.tests.alpha1.integration.c09_four_store_process_acceptance_support_v1 import _fresh_installed_factory
from rewrite.tests.alpha1.authority.test_local_owner_round_trip import ROLE,AUTH_NS,PEER
from rewrite.host_tests.alpha1 import test_authority_mtls_loopback as cert_donor
from sylanne3.authority_service.contract import AuthorityUnavailable
from sylanne3.authority_service.c09_storage_maintenance_v1 import InstalledC09WriterGateV1
from sylanne3.authority_service.c09_process_identity_v1 import read_process_identity_v1
from sylanne3.authority_service.first_owner_reverse_v1 import dispatch_first_owner_issue_v1,METHOD
from sylanne3.authority_service.v2_owner_contract import to_wire,from_wire
from sylanne3.authority_service.v2_owner_session import to_wire as session_wire
from sylanne3.authority_service.reverse_handoff import AdministratorReverseHandoffProfile,ReverseGraphClaimClient
from sylanne3.host.reverse_handoff import AdministratorHostReverseProfile,HostReverseGraphClaimServer
from sylanne3.host.first_owner_reverse_v1 import InstalledFirstOwnerGraphCommitV1
from sylanne3.host.c09_storage_admission_v1 import InstalledHostStorageAdmissionV1
from sylanne3.host.mtls_transport import AuthorityTlsProfile,MtlsAuthorityTransport
from sylanne3.host.authority_client import AuthorityProvisioningRequest,PublisherPackageIdentity,AUTHORITY_PROTOCOL,AUTHORITY_V2_PROTOCOL
from sylanne3.host.v2_fence_port import V2FencePort
from sylanne3.authority_service.mtls_server import AuthorityServerTlsConfig,MtlsPeerCredential
from sylanne3.graph_coordinator import GraphCoordinator
from sylanne3.host.authority_profile import AdminInstallationBundle
from sylanne3.host.v2_installation import V2InstallationAssembly
from sylanne3.graph_worker import GraphWorker
from sylanne3.graph_store import ProductionGraphStore


@pytest.mark.parametrize('lose_first_ack',(False,True))
def test_real_first_owner_reverse_replay_and_logout(tmp_path,monkeypatch,lose_first_ack):
    state=tmp_path/'state';state.mkdir()
    protected=tmp_path/'protected';protected.mkdir()
    (protected/'control.key').write_bytes(os.urandom(32));(protected/'instance.lock').write_bytes(b'\0')
    certdir=tmp_path/'certs';certdir.mkdir();files=cert_donor.AuthorityMtlsLoopbackTests._certificates(certdir)
    fingerprint=lambda name:hashlib.sha256(ssl.PEM_cert_to_DER_cert(files[name].read_text('ascii'))).hexdigest()
    peer=MtlsPeerCredential(fingerprint('client.pem'))
    from rewrite.tests.alpha1.authority import test_local_owner_round_trip as local_fixture
    from rewrite.tests.alpha1.integration import test_owner_signed_chain as signed_fixture
    from rewrite.tests.alpha1.integration import c09_four_store_process_acceptance_support_v1 as fresh_fixture
    for target in (local_fixture,signed_fixture,fresh_fixture):
        monkeypatch.setattr(target,'PEER',peer)
    monkeypatch.setattr(local_fixture,'SUBJECT','mtls:sha256:'+peer.certificate_sha256)
    packets=[]
    exchange=ReverseGraphClaimClient._exchange
    def captured(self,message):
        packets.append(message)
        assert 'owner_session_token' not in message and 'owner_session_request' not in message
        result=exchange(self,message)
        if lose_first_ack and len(packets)==1:
            raise RuntimeError('controlled ACK loss after real graph commit')
        return result
    monkeypatch.setattr(ReverseGraphClaimClient,'_exchange',captured)
    resources={}
    def runner(case):
        async def run():
            server=case['server'];port=case['port'];control=port.c09_control
            resources['lease']=port.c09_lease
            gate=InstalledC09WriterGateV1(control=control)
            context=control.read_verified_current_storage_v1()
            process=read_process_identity_v1(os.getpid())
            gate.register_peer_process_v1(peer=(peer.certificate_sha256,'installed'),process_id=os.getpid(),
                process_incarnation='real-test-host:'+process['birth'],pointer_version=context.pointer_version,storage_generation=context.storage_generation)
            server._c09_maintenance_v1=SimpleNamespace(gate=gate,restart_required=False)
            policy=case['policy']
            server._installations_v2[(peer.certificate_sha256,'installed')]=replace(
                server._installations_v2[(peer.certificate_sha256,'installed')],manifest_digest=policy.manifest_digest)
            authority_listener=await server.start('127.0.0.1',0,AuthorityServerTlsConfig(
                str(files['server.pem']),str(files['server.key']),str(files['ca.pem']),timeout_seconds=10))
            profile=AuthorityTlsProfile('installed','127.0.0.1',authority_listener.sockets[0].getsockname()[1],'localhost',case['authority_id'],
                files['ca.pem'],files['client.pem'],files['client.key'])
            bundle=AdminInstallationBundle(profile,policy,b'd11'*11,b'd02'*11)
            admission=InstalledHostStorageAdmissionV1('installation',case['authority_id'],context.pointer_version,
                context.storage_generation,context.manifest_digest,state/'business.db',process)
            installation=V2InstallationAssembly(policy,port.installation_grant,bundle.d11_signing_key,bundle.d02_signing_key,
                lambda:port,tmp_path,state,admin_bundle=bundle,storage_admission=admission)
            request=AuthorityProvisioningRequest(AUTHORITY_PROTOCOL,'installed','astrbot_plugin_sylanne','4.28.1',
                tmp_path,tmp_path,PublisherPackageIdentity(policy.manifest_digest))
            provision_transport=MtlsAuthorityTransport({'installed':profile})
            handshake=await provision_transport.handshake(request,protocol=AUTHORITY_V2_PROTOCOL)
            actual_grant=await provision_transport.installation_grant_v2(request,handshake)
            await provision_transport.close()
            registry=case['graph']._registry
            case['graph'].close()
            worker=await GraphWorker.start(lambda:ProductionGraphStore(state/'business.db',registry),
                lambda store,actual_port:GraphCoordinator(store,case['bootstrap'],holder=policy.administrator_holder,content_fence_v2=actual_port),
                fence_port_factory=lambda:V2FencePort(request,{'installed':profile},actual_grant))
            host=HostReverseGraphClaimServer(AdministratorHostReverseProfile('installed','installation',AUTH_NS,
                fingerprint('client.pem'),files['server.pem'],files['server.key'],files['ca.pem']))
            host.install_first_owner_v1(InstalledFirstOwnerGraphCommitV1(namespace=ROLE,worker=worker,
                bootstrap=case['bootstrap'],installation=installation))
            listener=await host.start('127.0.0.1',0)
            reverse=ReverseGraphClaimClient(AdministratorReverseHandoffProfile(AUTH_NS,'installed','installation',
                '127.0.0.1',listener.sockets[0].getsockname()[1],'localhost',fingerprint('server.pem'),
                files['ca.pem'],files['client.pem'],files['client.key']))
            server._final_handoff_reverse_v2[AUTH_NS]=reverse
            command=dict(namespace=AUTH_NS,ticket=to_wire(case['ticket']),operation=to_wire(case['operation']),
                grant_value=case['value'],owner_session_token=case['issue_token'],owner_session_request=session_wire(case['issue_request']))
            async def issue(value):
                client=MtlsAuthorityTransport({'installed':profile})
                try:
                    handshake=await client.handshake(request,protocol=AUTHORITY_V2_PROTOCOL)
                    await client.installation_grant_v2(request,handshake)
                    reply=await client._content_rpc(request,handshake,METHOD,value,protocol=AUTHORITY_V2_PROTOCOL)
                    return {k:v for k,v in reply.items() if k!='channel_binding_sha256'}
                finally:await client.close()
            try:
                if lose_first_ack:
                    with pytest.raises(RuntimeError):
                        await issue(command)
                    pending=case['tickets'].get_pending(credential=peer,authority_namespace=AUTH_NS,
                        operation_id=case['operation'].operation_id,session_token=case['issue_token'],session_request=case['issue_request'])
                    assert pending.phase=='pending'
                result=await issue(command)
                assert from_wire(result['receipt']).phase=='committed'
                assert await issue(command)==result
                assert len(packets)==1+int(lose_first_ack)
                bad=dict(packets[-1],process_original={**process,'birth':'not-current'})
                with pytest.raises(AuthorityUnavailable,match='incarnation'):
                    await host._first_owner.commit(bad)
                case['sessions'].logout(transport_credential=peer,request=case['issue_request'],token=case['issue_token'])
                with pytest.raises(RuntimeError):await issue(command)
                assert len(packets)==1+int(lose_first_ack)
                return from_wire(result['receipt'])
            finally:
                listener.close();authority_listener.close();await listener.wait_closed();await authority_listener.wait_closed();await worker.close();await server.aclose()
        return asyncio.run(run())
    def consistent_factory(state,**kwargs):
        result=_fresh_installed_factory(state,**kwargs)
        port=result[0]._GraphCoordinator__content_fence_v2
        installed=next(iter(port.c09_config.installations_v2.values()))
        port.installation_grant=replace(port.installation_grant,manifest_digest=installed.manifest_digest)
        return result
    chain=None
    try:
        chain=_real_owner_chain(state,installation_factory=consistent_factory,issue_runner=runner)
    finally:
        if chain is not None:
            for resource in chain.resources:resource.close()
        if 'lease' in resources:resources['lease'].close()
