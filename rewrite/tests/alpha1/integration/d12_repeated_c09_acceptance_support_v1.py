"""Two real C09 rebases and unchanged source Owner across both generations."""
from __future__ import annotations
from dataclasses import replace
from datetime import datetime,timezone
import json
import os
from pathlib import Path
import sqlite3
import sys
from uuid import uuid4

import c09_four_store_process_acceptance_support_v1 as base
from c09_four_store_process_acceptance_support_v1 import (
    ROLE,AUTH_NS,WORKER,SUBJECT,PEER,ADMIN,AuthorityV2DeletionGuard,AuthorityV2ExecutionJournal,
    installed_core_verifier_factory,AuthorityServiceCore,AuthorityV2FenceStore,AuthorityV2FenceService,
    AuthorityV2ScopedErasureStore,AuthorityV2DeletionPendingRecovery,ProductionGraphStore,
    AuthorityOwnerPairingSource,OwnerDeploymentVerifier,AuthorityV2OwnerProofStore,AuthorityV2OwnerSessionStore,
    GraphCoordinator,LocalFencePort,D06DomainProvider,CurrentAcceptedErasureReadService,
    AuthorityV2DeletionGraphReadService,CurrentErasureAuthority,canonical_serialize,
)

SECOND_PRIVATE='C09_SECOND_GENERATION_PRIVATE_SENTINEL_20260930'


def prepare_second(root):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from sylanne3.authority_service.local_composition import compose_local_owner_authority
    from sylanne3.authority_service.mtls_server import AdministratorInstallationV2
    from sylanne3.authority_service.v2_owner_session import from_wire
    from sylanne3.authority_service.d12_owner_storage_admission_v1 import InstalledD12OwnerStorageAdmissionServiceV1
    from sylanne3.graph_types import AtomKey,owner_grant_key
    packet=json.loads((root/'packet.json').read_text());control,lease=base._control(root,packet)
    context=control.read_verified_current_storage_v1()
    assert context.storage_generation==1
    if context.stage!='RELEASED':
        # Resume only the already accepted second operation's durable INTENT.
        # The selected source generation and original request stay unchanged.
        assert context.stage=='INTENT' and packet.get('next_operation_id')==packet['operation_id']
        intent=control.read_operation_event_v1(packet['operation_id'],'INTENT')
        with control._db() as db:current=control._current(db)
        assert current['active_operation_id']==packet['operation_id']
        assert intent['pointer_version']==context.pointer_version
        assert intent['details']['old_manifest_digest']==context.manifest_digest
    paths={m['role']:Path(m['resolved_path']) for m in context.manifest['members']}
    deletion=AuthorityV2DeletionGuard(paths['deletion']);execution=AuthorityV2ExecutionJournal(paths['execution'],namespace=AUTH_NS,
        journal_id=next(m['incarnation_or_journal_id'] for m in context.manifest['members'] if m['role']=='execution'),installed_storage_reader=control)
    verifiers=installed_core_verifier_factory(deletion,{AUTH_NS:execution})
    core=AuthorityServiceCore(paths['core'],authorizer=base._authorize,deletion_verifier=verifiers.deletion,
        execution_verifier=verifiers.execution,effect_verifier=verifiers.effect,dispatch_verifier=verifiers.dispatch)
    core.install_current_c09_storage_reader_v1(reader=control)
    fences=AuthorityV2FenceStore(core._db,lock=core._lock);service=AuthorityV2FenceService(core=core,fences=fences,deletion=deletion,execution=execution,namespace=AUTH_NS)
    scoped=AuthorityV2ScopedErasureStore(core=core,fences=fences,deletion=deletion,execution=execution,namespace=AUTH_NS)
    recovery=AuthorityV2DeletionPendingRecovery(core=core,fences=fences,deletion=deletion,execution=execution,namespace=AUTH_NS,scoped_store=scoped)
    now=lambda:datetime.now(timezone.utc).replace(microsecond=0)
    pairings=AuthorityOwnerPairingSource(core,utc_clock=now,create=False);deployment=OwnerDeploymentVerifier(pairings,now)
    proofs=AuthorityV2OwnerProofStore(core,utc_clock=now,pairing_verifier=deployment.pair_credential,current_pairing_source=pairings,create=False)
    sessions=AuthorityV2OwnerSessionStore(core,utc_clock=now,current_pairing_source=pairings,create=False)
    server=compose_local_owner_authority(core=core,v2_fences={AUTH_NS:service},graph_db_path=paths['graph'],utc_clock=now,
        first_claim_verifier=lambda *_:False,claimant_verifier=None,owner_proofs=proofs,owner_sessions=sessions,
        creation_pairing_source=pairings,create_owner_schema=False,administrator_authorizer=lambda credential,*_:credential==PEER,
        publisher_manifest_verifier=lambda *_:True,installations_v2={(PEER.certificate_sha256,'installed'):AdministratorInstallationV2(
            'installation','administrator','controlled-installation-policy','2','b'*64)},
        namespace_bindings_v2={(PEER.certificate_sha256,'installed',ROLE):AUTH_NS})
    tickets=server._v2_owner_tickets;graph=ProductionGraphStore(paths['graph'],base._registry());bootstrap=object()
    port=LocalFencePort(graph,service,tickets,packet['authority_id'])
    def principal(actor,namespace):
        actual=pairings.current_actor_binding(authority_namespace=AUTH_NS,installation_id='installation',actor_id=actor)
        return actual.principal if actual is not None and namespace==ROLE else None
    coordinator=GraphCoordinator(graph,bootstrap,holder='administrator',content_fence_v2=port,owner_principal_resolver=principal)
    provider=D06DomainProvider();coordinator.register_provider(bootstrap,'d06',provider,'d06.contract.v1',provider.descriptor.request_schema_hash)
    accepted_reader=CurrentAcceptedErasureReadService(fence_service=service,owner_tickets=tickets,scoped_store=scoped)
    maintenance,closure=base._compose(control,graph,coordinator,bootstrap,service,scoped,recovery,accepted_reader,base._inventory(packet['inventory']),root)
    from current_inventory_acceptance_support_v3 import instrument_actual_inventory_negatives_v3
    instrument_actual_inventory_negatives_v3(maintenance)
    owner_service=InstalledD12OwnerStorageAdmissionServiceV1(fences=service,owner_tickets=tickets,graph_db_path=paths['graph'],
        namespace_id=ROLE,installation_id='installation',holder='administrator',control=control,close_apply=maintenance.close_apply_service)
    def guard(**kw):
        return tickets.get_current_guard(credential=WORKER,authority_namespace=AUTH_NS,installation_id='installation',
            subject=SUBJECT,permit=kw['permit'],owner_actor_id=kw.get('owner_actor_id'),owner_session_token=kw.get('owner_session_token'),
            owner_session_request=kw.get('owner_session_request')),kw['permit']
    port.get_current_owner_guard_for_fence=guard
    port.get_current_owner_authority_for_fence_v1=lambda **kw:owner_service.get_current_owner_authority_for_fence_v1(
        credential=WORKER,subject=SUBJECT,permit=kw['permit'],actor=kw['owner_actor_id'],session_token=kw['owner_session_token'],session_request=kw['owner_session_request'])
    pending_reader=AuthorityV2DeletionGraphReadService(fence_service=service,owner_tickets=tickets)
    port.get_pending_deletion_for_graph_write=lambda **kw:pending_reader.get_pending_deletion_for_graph_write(
        credential=WORKER,subject=SUBJECT,installation_id='installation',deletion_operation_id=kw['deletion_operation_id'],permit=kw['permit'])
    request=replace(from_wire(packet['owner_login_request']),audience='owner');key=Ed25519PrivateKey.from_private_bytes((root/'protected/test-owner.key').read_bytes())
    token=None
    immutable=graph._db.execute('SELECT revision,value,valid FROM graph_atoms WHERE token=?',(owner_grant_key(*ROLE.as_tuple).token,)).fetchone()
    operation=packet.get('next_operation_id') or str(uuid4());packet['next_operation_id']=operation
    base._json_write(root/'packet.json',packet)
    source_ref=packet['next_erased_refs'][0];owner_lease=None;did_read=False
    with core._tx() as db:
        existing=fences.mutation_locked(db,CurrentErasureAuthority._protocol_id(AUTH_NS,operation,'mutation'))
        active_state=scoped.state_locked(db)
    if existing is None:
        challenge=sessions.begin_login(transport_credential=PEER,request=request)
        token=sessions.accept_login(transport_credential=PEER,challenge=challenge,signature=key.sign(challenge.signed_bytes()))
        authority,owner_lease,binding=coordinator.grant_current_owner(bootstrap,actor='owner-actor',namespace=ROLE,domains=('d06',),
            purpose='context',audience='owner',activation_generation=1,owner_session_token=token,owner_session_request=request)
        assert binding.storage_admission is not None and binding.storage_admission.storage_generation==1
        assert coordinator.read_snapshot(authority,owner_lease,(AtomKey.from_token(packet['survivor_ref']),)).atoms[0].value['text']==base.SURVIVOR
        did_read=True
        plan=coordinator.issue_current_c09_erasure_plan_v1(authority,owner_lease,operation_id=operation,source_ref=source_ref)
    else:
        # Recovery uses the exact actual plan and the durable pending request;
        # it creates no new content lease or deletion operation while pending.
        from sylanne3.runtime.c09_erasure_plan_original_v1 import read_c09_erasure_plan_original_v1
        plan=read_c09_erasure_plan_original_v1(graph._db,ROLE,operation)
        assert plan is not None and plan.source_ref==source_ref
    erasure=CurrentErasureAuthority(recovery,graph_coordinator=coordinator,graph_bootstrap=bootstrap,namespace_id=ROLE,
        pending_graph_reader=pending_reader,installation_id='installation',fence_service=service,owner_sessions=sessions,
        owner_tickets=tickets,scoped_store=scoped,plan_graph_coordinator=coordinator,graph_db_path=paths['graph'])
    # The concrete current-storage reader is installed through the product hook
    # once the independently verified plan entrance exposes it.
    erasure.install_current_owner_storage_reader_v1(owner_service)
    if active_state.aggregate_phase=='accepted' and active_state.active_operation_id==operation:
        with core._tx() as db:
            mutation_ids=tuple(row[0] for row in db.execute("SELECT mutation_id FROM authority_v2_mutations WHERE namespace=? AND mutation_kind='deletion'",(AUTH_NS,)))
        matches=[]
        for mutation_id in mutation_ids:
            original=scoped.read_ancestor_receipt(credential=WORKER,subject=SUBJECT,mutation_id=mutation_id)
            if original.pending.deletion_operation_id==operation and original.pending.target_phase=='accepted':matches.append(original)
        assert len(matches)==1
        accepted=matches[0]
    else:
        if existing is None:
            receipt,permit=erasure.prepare_request(credential=WORKER,subject=SUBJECT,holder='administrator',installation_id='installation',
                owner_actor_id='owner-actor',owner_session_token=token,owner_session_request=request,deletion_operation_id=operation,source_id=plan.source_id)
        else:
            mutation=CurrentErasureAuthority._protocol_id(AUTH_NS,operation,'mutation')
            receipt=erasure.recover_prepared_pending(credential=WORKER,subject=SUBJECT,mutation_id=mutation)
            actual=fences.get_mutation(mutation,subject=SUBJECT,namespace=AUTH_NS)
            assert receipt is not None and actual[2]==receipt
            permit=actual[3]
        coordinator.commit_current_c09_source_barrier_v1(bootstrap,namespace=ROLE,deletion_operation_id=operation,permit=permit)
        accepted,_=erasure.accept_verified_graph_barrier(credential=WORKER,subject=SUBJECT,pending_mutation_id=receipt.pending.mutation_id)
    if owner_lease is not None:coordinator.release_current_owner_lease(bootstrap,owner_lease)
    assert graph._db.execute('SELECT revision,value,valid FROM graph_atoms WHERE token=?',(owner_grant_key(*ROLE.as_tuple).token,)).fetchone()==immutable
    packet.setdefault('first_operation_id',packet['operation_id']);packet['operation_id']=operation
    if source_ref not in packet['erased_refs']:packet['erased_refs'].append(source_ref)
    base._json_write(root/'packet.json',packet)
    closure.begin_run(credential=WORKER,subject=SUBJECT,accepted_mutation_id=accepted.pending.mutation_id)
    try:
        original=maintenance.prepare_storage_rebase_v1(operation_id=operation)
        assert original['maintenance_generation']==2
        return dict(stage='PREPARED',generation=2,process_id=os.getpid(),first_fresh_owner_read=did_read)
    finally:lease.close()


if __name__=='__main__':
    phase,root=sys.argv[1],Path(sys.argv[2])
    if phase=='prepare':result=base.initialize_and_prepare(root,additional_sources=(('erase-second',SECOND_PRIVATE,()),))
    elif phase=='prepare_second':result=prepare_second(root)
    else:
        result=base.resume(root,phase)
        if phase=='verify':
            from current_inventory_acceptance_support_v3 import assert_actual_current_inventory_v3
            packet=json.loads((root/'packet.json').read_text());control,lease=base._control(root,packet)
            try:result['actual_mapped_inventory']=assert_actual_current_inventory_v3(control)
            finally:lease.close()
    print(canonical_serialize(result))
