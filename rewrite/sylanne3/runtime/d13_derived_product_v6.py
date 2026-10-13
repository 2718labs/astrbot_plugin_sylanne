"""Finite actual v6 paid adoption and named derived-cache retirement via retained W01 writes."""
from dataclasses import asdict,replace
import json

from ..contracts import Event,Scope
from ..graph_types import AtomKey,GraphCandidate,GraphVersion,GraphWrite
from ..domains.d13.derived_block_metadata_v2 import (METADATA_TYPE,decode_derived_block_metadata_v2,
    derived_block_metadata_key_v2,derived_block_metadata_value_v2)
from ..runtime_contracts import canonical_digest,canonical_serialize
from .d11_derived_cache_payload_v1 import (prepare_derived_payload_v1,insert_derived_payload_v1,
    reclaim_derived_payload_v1)
from .d13_paid_product_v1 import _authorize,_read_original_locked
from .d13_current_window import read_current_d13_frozen_window_for_authority_v1
from .d13_paid_coordinator_v1 import (D13PaidStandbyPreparationV1,prepare_paid_d13_standby_in_transaction_v1,
    finalize_paid_d13_in_transaction_v1)
from .jobs import get_job


def _commit_derived_graph(graph,db,metadata,epoch,authority,operation_id,now,writes,reads=(),*,stages=(),retired=()):
    from ..graph_store import GraphStore
    store=graph._GraphCoordinator__store
    if not db.in_transaction or not store._lock._is_owned():
        raise ValueError('derived cache changes require the actual held W01 current transaction')
    versions=list(reads)
    for write in writes:
        row=db.execute('SELECT revision FROM graph_atoms WHERE token=?',(write.key.token,)).fetchone()
        version=GraphVersion(write.key,0 if row is None else row[0])
        if all(prior.key!=write.key for prior in versions):
            versions.append(version)
    event=Event(Scope(*authority.namespace.as_tuple,'d13-derived-cache-v6'),operation_id,now,
        'd13.derived-cache-lifecycle.v6',{'operation_id':operation_id})
    candidate=GraphCandidate(event,tuple(versions),tuple(writes),(epoch,))
    reclaimed=[]
    def seal(hook_db,receipt):
        if receipt.status!='committed':
            raise ValueError('derived lifecycle must bind an actual committed W01 receipt')
        store.cas_graph_recovery_metadata(metadata,metadata.requirements,_capability=graph._GraphCoordinator__graph_capability)
        for stage in stages:
            insert_derived_payload_v1(hook_db,stage)
        for item in retired:
            result=reclaim_derived_payload_v1(hook_db,item)
            if not result.payload_absent:
                raise ValueError('named derived payload still exists after its exact delete')
            reclaimed.append(result)
    receipt=GraphStore._graph_commit_in_transaction(store,candidate,_receipt_hook=seal,
        _capability=graph._GraphCoordinator__graph_capability)
    return receipt,tuple(reclaimed)


def complete_d13_paid_derived_graph_v6(graph, authority, lease, *, job_id, selected_main):
    _store, _port, policy, resource, budget = _authorize(graph, authority, lease)
    saved = _read_original_locked(graph, authority.namespace, job_id)
    if saved is None or saved.settlement is None:
        raise ValueError("D13 completion requires settled original evidence")
    operation_id = "d13-paid-derived-complete:" + saved.original.binding.binding_digest[:48]
    digest = canonical_digest({"evidence": saved.evidence.evidence_digest,
                               "receipt": saved.settlement.receipt,
                               "selected_main": selected_main})

    def commit(db, metadata, epoch, now):
        from ..graph_coordinator import UnavailableGuard
        from .local_module_admission_v1 import LocalModuleAdmissionDeniedV1
        current = None
        try:
            graph.local_module_admission.require_v1(("d13", "d11"), "d13:paid_standby")
            current = read_current_d13_frozen_window_for_authority_v1(
                db, saved.frozen.window, now, max_slots=policy.max_slots)
            prepared = prepare_paid_d13_standby_in_transaction_v1(
                db, saved.original, saved.call_original, saved.frozen, current, selected_main,
                resource_issuer=resource, budget_issuer=budget, holder=authority.actor,
                fence=saved.call_original.worker_fence, now_utc=now)
        except (ValueError, UnavailableGuard) as refusal:
            job = get_job(db, job_id)
            if (job.phase != "running" or job.lease_holder != authority.actor or
                    job.fence != saved.call_original.worker_fence or job.cancel_epoch != 0):
                raise ValueError("D13 paid original worker cannot close stale result")
            prepared = D13PaidStandbyPreparationV1(
                saved.original, saved.evidence.evidence_digest, saved.settlement,
                None, "local_module_disabled" if isinstance(refusal, LocalModuleAdmissionDeniedV1)
                else "paid_current_source_model_or_lifetime_invalid", job)
        completed, writes = finalize_paid_d13_in_transaction_v1(
            db, prepared, holder=authority.actor, fence=saved.call_original.worker_fence)
        stage=None
        if prepared.block is not None:
            stage=prepare_derived_payload_v1(prepared,scene_ref=current.scene_ref)
            new_key=derived_block_metadata_key_v2(stage.metadata)
            from ..graph_types import Owner
            legacy_key=AtomKey(Owner('persona',*authority.namespace.as_tuple),'d13.derived_block_metadata.v1',stage.metadata.block_ref)
            if db.execute('SELECT token FROM graph_atoms WHERE token IN (?,?) LIMIT 1',(new_key.token,legacy_key.token)).fetchone() is not None:
                raise ValueError('new derived metadata identity already exists')
            writes=tuple(write for write in writes if write.key.type_name!='d13.compressed_turn_block.v2')+(
                GraphWrite(new_key,derived_block_metadata_value_v2(stage.metadata),
                    tuple(AtomKey.from_token(ref.ref) for ref in stage.metadata.source_dependencies)),)
        _commit_derived_graph(graph,db,metadata,epoch,authority,operation_id,now,writes,
            tuple(GraphVersion(AtomKey.from_token(ref.ref),ref.version) for ref in current.read_set)
                if prepared.block is not None else (),stages=() if stage is None else (stage,))
        return {"job_id": job_id, "reason": prepared.reason, "job": asdict(completed)}

    result = graph._d13_worker_write_v2(authority, operation_id, digest, commit)
    return result



def retire_due_d13_derived_graph_v6(graph,authority,lease,*,block_ref,expected_revision):
    """One finite original; no model call, budget release or old-history reclamation."""
    store,_port,_policy,_resource,_budget=_authorize(graph,authority,lease)
    from ..graph_types import Owner
    key=AtomKey(Owner('persona',*authority.namespace.as_tuple),METADATA_TYPE,block_ref)
    if type(expected_revision) is not int or expected_revision<1:
        raise ValueError('derived retirement requires the original exact positive CAS revision')
    with store._lock:
        row=store._db.execute('SELECT revision,value,valid FROM graph_atoms WHERE token=?',(key.token,)).fetchone()
        if row is None or row[2]!=1:
            raise ValueError('derived retirement current head unavailable')
        if row[0]==expected_revision:
            original=decode_derived_block_metadata_v2(json.loads(row[1]))
        else:
            history=store._db.execute('SELECT value,valid FROM graph_history WHERE token=? AND revision=? '
                'AND event_bot=? AND event_persona=?',(key.token,expected_revision,*authority.namespace.as_tuple)).fetchone()
            if history is None or history[1]!=1:
                raise ValueError('derived retirement original CAS history unavailable')
            original=decode_derived_block_metadata_v2(json.loads(history[0]))
            if original.status not in {'standby','active'} or row!=(expected_revision+1,canonical_serialize(replace(original,status='retired')),1):
                raise ValueError('derived retirement selector changed beyond its one actual retirement')
    if original.namespace!=authority.namespace or original.conversation_ref!=authority.audience[0]:
        raise ValueError('derived retirement crossed its actual namespace/audience')
    digest=canonical_digest({'schema':'d13.derived-retirement.v6','namespace':authority.namespace,
        'block_ref':block_ref,'revision':expected_revision,'metadata_digest':canonical_digest(original)})
    operation_id='d13-derived-retire:'+digest[:48]
    if row[0]!=expected_revision:
        with store._lock:
            adopted=store._db.execute('SELECT value,valid,event_id FROM graph_history WHERE token=? AND revision=? '
                'AND event_bot=? AND event_persona=?',(key.token,expected_revision+1,*authority.namespace.as_tuple)).fetchone()
            if adopted!=(row[1],1,operation_id):
                raise ValueError('derived retirement head is not this actual original operation')
        recovered=graph._d13_worker_replay_v2(authority,operation_id,digest)
        if recovered is None:
            raise ValueError('derived retirement committed result has not been observed; retain original operation')
        return recovered
    def commit(db,metadata,epoch,now):
        current=db.execute('SELECT revision,value,valid FROM graph_atoms WHERE token=?',(key.token,)).fetchone()
        if current!=(expected_revision,canonical_serialize(original),1):
            raise ValueError('derived retirement current metadata CAS changed')
        if now<original.expires_at_utc:
            raise ValueError('derived retirement cannot shorten a still-live original without actual invalidation')
        retired=replace(original,status='retired')
        receipt,reclaims=_commit_derived_graph(graph,db,metadata,epoch,authority,operation_id,now,
            (GraphWrite(key,derived_block_metadata_value_v2(retired)),),retired=(retired,))
        # This mutable scene exclusion index is derived scheduling state, not immutable paid cost evidence.
        db.execute("UPDATE graph_d13_paid_scene_jobs_v1 SET state='retired' WHERE bot=? AND persona=? AND job_ref=? "
            "AND state IN ('standby','active')",(*authority.namespace.as_tuple,original.job_ref))
        return {'schema':'d13.derived-retirement-result.v6','operation_id':operation_id,'metadata_ref':key.token,
            'metadata_revision':expected_revision+1,'graph_receipt':asdict(receipt),'reclaim':asdict(reclaims[0]),
            'legacy_v2_history_and_paid_originals':'preserved_legacy_only','secure_erasure':'unsupported'}
    return graph._d13_worker_write_v2(authority,operation_id,digest,commit)


def due_d13_derived_refs_v6(db,namespace,*,conversation_ref,now_utc):
    """At most 16 current candidates per invocation; callers do not auto-loop."""
    if not db.in_transaction:
        raise ValueError('derived cleanup discovery requires the current fenced read transaction')
    return tuple(db.execute("SELECT token,revision FROM graph_atoms WHERE bot=? AND persona=? AND type_name=? "
        "AND valid=1 AND json_extract(value,'$.conversation_ref')=? AND json_extract(value,'$.expires_at_utc')<=? "
        "AND json_extract(value,'$.status') IN ('standby','active') ORDER BY token LIMIT 16",
        (*namespace.as_tuple,METADATA_TYPE,conversation_ref,now_utc)).fetchall())


def discover_due_d13_derived_graph_v6(graph,authority,lease):
    _store,port,_policy,_resource,_budget=_authorize(graph,authority,lease)
    from .first_ingress_v2 import trusted_upper
    assembly=graph._GraphCoordinator__d04_installed_joint_assembly
    if assembly is None or assembly.admin_bundle is None:
        raise ValueError('derived cleanup requires the actual installed current Source/clock context')
    now=trusted_upper(port.read_ingress_clock(assembly.admin_bundle.ingress_clock))
    def read():
        db=graph._GraphCoordinator__store._db
        db.execute('BEGIN')
        try:
            return due_d13_derived_refs_v6(db,authority.namespace,conversation_ref=authority.audience[0],now_utc=now)
        finally:
            db.rollback()
    return graph._read_v2(authority,read)
