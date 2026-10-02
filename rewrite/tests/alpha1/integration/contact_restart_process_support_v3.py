"""Linux child-process Contact recovery with a new Graph/runtime and TLS port.

Only test-owned installation configuration and ephemeral test Owner key cross
fork; no existing Graph lease/session dictionary is used in the child. The
parent closes its GraphWorker/store before fork. Authority stays independently
running in the parent. This is not full Host startup or Authority reboot.
"""
import asyncio
import json
import multiprocessing
import os
import traceback
from dataclasses import replace


def _restart_child(config,pipe):
    store=port=client=None
    try:
        from sylanne3.graph_store import ProductionGraphStore
        from sylanne3.graph_coordinator import GraphCoordinator
        from sylanne3.host.v2_fence_port import V2FencePort
        from sylanne3.host.authority_client import AuthorityClient,AuthoritySelection
        from sylanne3.host.mtls_transport import MtlsAuthorityTransport
        from sylanne3.runtime.c04_authority_port_v3 import InstalledC04AuthorityPortV3
        from sylanne3.runtime.contact_owner_invocation_v3 import read_contact_owner_invocation_v3
        from sylanne3.authority_service.contact_owner_session_v3 import from_wire,OwnerContactRecoveryUseV3
        from sylanne3.authority_service.v2_owner_session import _verifier
        from sylanne3.runtime_contracts import canonical_digest
        # Fork inherits the parent's event-loop thread-local marker, never use it.
        asyncio.events._set_running_loop(None)
        from sylanne3.runtime.contact_final_ack_v1 import _CALLS,_SAVED
        from sylanne3.runtime.contact_owner_invocation_v3 import _CAPTURES,_RECOVERIES
        assert not _CALLS and not _SAVED and not _CAPTURES and not _RECOVERIES
        bundle=config['bundle'];profile=bundle.tls_profile
        port=V2FencePort(config['request'],{config['request'].profile_id:profile},config['grant'])
        client=AuthorityClient(AuthoritySelection(config['request'].profile_id),
            package_root=config['package_root'],data_dir=config['data_dir'],
            transport=MtlsAuthorityTransport({config['request'].profile_id:profile}))
        assert port._submit(client.status_v2()).state=='paired'
        grant=port._submit(client.installation_grant_v2())
        c04=InstalledC04AuthorityPortV3(client=client,bundle=bundle,grant=grant,owner_loop=port._loop)
        ns=config['namespace'];ans=config['authority_namespace']
        def principal(actor,namespace):
            binding=port.current_owner_actor_binding(namespace=namespace,authority_namespace=ans,actor_id=actor)
            return None if binding is None else binding.principal
        store=ProductionGraphStore(config['path'],config['registry'].type_registry)
        bootstrap=object()
        graph=GraphCoordinator(store,bootstrap,holder=bundle.installation_policy.administrator_holder,
            content_fence_v2=port,d02_issuer=config['d02'],d11_issuer=config['d11'],
            owner_principal_resolver=principal,scene_clock_policy=config['clock_policy'],
            c04_authority_port_v3=c04,d04_installed_joint_assembly=replace(config['assembly'],
                fence_port_factory=lambda:port,installation_grant=grant),
            d04_installed_joint_output_policy=config['output_policy'],
            body_quote_authority=config['body_quote'],c04_cpu_quote_authority=config['cpu_quote'])
        from sylanne3.host.installed_d04_semantic_mapping_v3 import InstalledD04SemanticMappingReaderV3
        graph._GraphCoordinator__d04_semantic_mapping_reader=InstalledD04SemanticMappingReaderV3(
            graph,config['package_root'],bundle.installation_policy.manifest_digest)
        for domain in config['domains']:
            item=config['registry'].registrations[domain]
            graph.register_provider(bootstrap,domain,item.provider,item.proposal_schema,item.proposal_schema_hash)
        assert not graph._GraphCoordinator__owner_leases
        assert not graph._GraphCoordinator__owner_session_proofs
        assert not graph._GraphCoordinator__contact_recovery_leases_v3
        assert not graph._GraphCoordinator__leases
        request=config['session_request']
        challenge=port.begin_owner_session(namespace=ns,authority_namespace=ans,request=request)
        new_token=port.accept_owner_session(namespace=ns,authority_namespace=ans,challenge=challenge,
            signature=config['owner_key'].sign(challenge.signed_bytes()))
        store._db.execute('BEGIN')
        try:
            original=read_contact_owner_invocation_v3(store._db,config['d11'],ns,config['operation_id'],config['request_digest'])
        finally:store._db.rollback()
        raw=json.loads(original.payload_json);old=from_wire(raw['session_observation'])
        assert 'sha256:'+_verifier(new_token)!=old.verifier_commitment
        use=OwnerContactRecoveryUseV3(original.digest,old.commitment,'sha256:'+_verifier(new_token),
            old.principal,old.actor,config['operation_id'],old.permit_digest,raw['deadline_utc'])
        tables=('runtime_budget_reservations','runtime_budget_operations','graph_domain_production_originals_v1',
            'graph_dispatch_admissions','runtime_jobs','graph_bundle_outbox')
        def counts():return tuple((t,store._db.execute('SELECT COUNT(*) FROM '+t).fetchone()[0]) for t in tables)
        before=counts()
        result=graph.recover_contact_owner_dispatch_v3(bootstrap,namespace=ns,operation_id=config['operation_id'],
            request_digest=config['request_digest'],owner_session_token=new_token,owner_session_request=request,
            use=use,signature=config['owner_key'].sign(use.signed_bytes()))
        assert result==raw['result'] and len(result['receipt']['write_versions'])==11
        assert before==counts()
        assert not graph._GraphCoordinator__leases and not graph._GraphCoordinator__owner_leases
        assert not graph._GraphCoordinator__owner_session_proofs and not graph._GraphCoordinator__contact_recovery_leases_v3
        from sylanne3.authority_service.v2_contract import from_wire as permit_from_wire
        permit=permit_from_wire(raw['scope']['permit'])
        observed,state=port.get_fence_operation(namespace=ns,authority_namespace=ans,operation_id=permit.operation_id)
        assert observed==permit and state=='finished'
        pipe.send({'ok':True,'pid':os.getpid(),'result_digest':canonical_digest(result),'count_unchanged':True})
    except BaseException:
        pipe.send({'ok':False,'pid':os.getpid(),'traceback':traceback.format_exc()})
    finally:
        if store is not None:store.close()
        if client is not None and port is not None:port._submit(client._transport.close())
        if port is not None:port.close()
        pipe.close()


async def run_contact_restart_process_v3(case,worker,retained_owner,*,operation_id,expected_digest):
    graph=case['graph'];store=case['store'];bundle=graph._GraphCoordinator__d04_installed_joint_assembly.admin_bundle
    def configuration(_graph):
        row=store._db.execute('SELECT request_digest FROM graph_owner_domain_attempts_v3 WHERE bot=? AND persona=? AND operation_id=?',
            (*case['namespace'].as_tuple,operation_id)).fetchone()
        path=store._db.execute('PRAGMA database_list').fetchone()[2]
        return dict(path=path,request_digest=row[0],operation_id=operation_id,bundle=bundle,
            request=case['port']._request,grant=case['port'].installation_grant,
            package_root=case['package_root'],data_dir=case['authority_client']._data_dir,
            namespace=case['namespace'],authority_namespace=case['authority_namespace'],
            registry=case['domain_registry'],d02=case['d02_issuer'],d11=case['d11_issuer'],
            clock_policy=graph._GraphCoordinator__scene_clock_policy,
            assembly=graph._GraphCoordinator__d04_installed_joint_assembly,
            output_policy=graph._GraphCoordinator__d04_installed_joint_output_policy,
            body_quote=graph._GraphCoordinator__body_quote_authority,cpu_quote=graph._GraphCoordinator__c04_cpu_quote_authority,
            domains=tuple(graph._GraphCoordinator__providers),session_request=case['owner_session_request'],owner_key=case['owner_key'])
    config=await worker.call(configuration)
    await worker.call(lambda _:retained_owner['manager'].__exit__(None,None,None))
    retained_owner.clear()
    await worker.close()
    context=multiprocessing.get_context('fork')
    parent,child=context.Pipe(duplex=False)
    process=context.Process(target=_restart_child,args=(config,child))
    process.start();child.close()
    try:
        available=await asyncio.to_thread(parent.poll,45)
        assert available,'independent Contact recovery process timed out'
        outcome=parent.recv()
        await asyncio.to_thread(process.join,5)
        assert not process.is_alive() and process.exitcode==0
        assert outcome['pid']!=os.getpid()
        assert outcome['ok'],outcome.get('traceback')
        assert outcome['result_digest']==expected_digest and outcome['count_unchanged']
    finally:
        if process.is_alive():process.terminate();await asyncio.to_thread(process.join,5)
        parent.close()
