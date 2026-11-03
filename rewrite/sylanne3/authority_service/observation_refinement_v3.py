"""Installed observation refinement; the original dispatch fence stays finished."""
from __future__ import annotations
from dataclasses import replace
import hashlib
import json
import threading
from .contract import AuthorityUnavailable,JournalHead,identifier
from .v2_contract import (MutationReceiptV2,PlatformObservationV1,PlatformObservationV2,
    CurrentEffectReadV2,canonical_bytes as v2_bytes,decode_bytes as v2_decode)
from .observation_refinement_contract_v3 import (PlatformObservationRefinementPendingV3,
    PlatformObservationRefinementReceiptV3,ENTRY_PREFIX,canonical_digest,canonical_bytes,decode_bytes,
    decode_fact_row_v3,encode_fact_entry_v3,expected_fact_digest_v3,fact_operation_id_v3,fact_request_digest_v3,
    observation_platform_observation_v3)

from .c09_platform_observation_fact_storage_v3 import COLUMNS

TABLE='authority_platform_observation_facts_v3'
DDL="""CREATE TABLE authority_platform_observation_facts_v3(
    namespace TEXT NOT NULL, fact_operation_id TEXT PRIMARY KEY,
    mutation_id TEXT NOT NULL UNIQUE, subject TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('pending','committed')),
    pending BLOB NOT NULL, receipt BLOB, updated_fact_permit BLOB,
    CHECK((state='pending' AND receipt IS NULL AND updated_fact_permit IS NULL)
       OR (state='committed' AND receipt IS NOT NULL AND updated_fact_permit IS NOT NULL))
) STRICT"""

def require_observation_refinement_schema_v3(db):
    from .c09_platform_observation_fact_storage_v3 import fact_storage_schema_v3
    return fact_storage_schema_v3(db)


def require_no_pending_fact_v3(db,namespace):
    require_observation_refinement_schema_v3(db)
    if db.execute('SELECT 1 FROM '+TABLE+" WHERE namespace=? AND state='pending' LIMIT 1",(namespace,)).fetchone():
        raise AuthorityUnavailable('pending observation fact blocks current observation read')

def install_observation_refinement_schema_v3(db):
    if not db.in_transaction:raise AuthorityUnavailable('actual Core installation transaction required')
    row=db.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?",(TABLE,)).fetchone()
    from .c09_platform_observation_fact_storage_v3 import PHYSICAL_DDL
    from ..runtime_storage_v3 import runtime_storage_v3
    layout=db.execute("SELECT role FROM segmented_storage_layout_v1 WHERE singleton=1").fetchone() if db.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='segmented_storage_layout_v1'").fetchone() else None
    if row is None:db.execute(PHYSICAL_DDL if runtime_storage_v3(db) is not None or layout==('core',) else DDL)
    elif row not in ((DDL,),(PHYSICAL_DDL,)):raise AuthorityUnavailable('observation fact schema differs')
    require_observation_refinement_schema_v3(db)

def require_fact_unconsumed_v3(db,namespace,fact_operation_id):
    from .c09_graph_application_v1 import c09_actual_root_read_v3
    if not db.in_transaction:raise AuthorityUnavailable('fact consumed check requires actual Core transaction')
    actual=c09_actual_root_read_v3(db)
    if actual.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='authority_c09_consumed_execution_v1'").fetchone():
        for kind in ('platform_observation_fact_v3','fence'):
            if actual.execute('SELECT 1 FROM authority_c09_consumed_execution_v1 WHERE namespace=? AND kind=? AND item_id=?',(namespace,kind,fact_operation_id)).fetchone():
                raise AuthorityUnavailable('already_consumed:'+kind+':'+fact_operation_id)

def fact_row_locked_v3(db,mutation_id):
    from .c09_graph_application_v1 import c09_actual_root_read_v3
    from .c09_platform_observation_fact_storage_v3 import PHYSICAL_DDL,fact_row_runtime_v3
    if require_observation_refinement_schema_v3(db)==PHYSICAL_DDL:return fact_row_runtime_v3(db,mutation_id)
    return c09_actual_root_read_v3(db).execute('SELECT namespace,fact_operation_id,mutation_id,subject,request_digest,state,pending,receipt,updated_fact_permit FROM '+TABLE+' WHERE mutation_id=?',(mutation_id,)).fetchone()

def decode_fact_record_v3(row):
    if row is None:raise AuthorityUnavailable('observation fact original is absent')
    p=decode_bytes(row[6]) if type(row[6])is bytes else row[6]
    r=None if row[7] is None else decode_bytes(row[7]) if type(row[7])is bytes else row[7]
    u=None if row[8] is None else v2_decode(row[8]) if type(row[8])is bytes else row[8]
    if type(p) is not PlatformObservationRefinementPendingV3 or row[:5]!=(p.fact_write_permit.namespace,p.fact_write_permit.operation_id,p.mutation_id,p.fact_write_permit.subject,p.request_digest):
        raise AuthorityUnavailable('observation fact row identity differs')
    if row[5]=='pending':
        if r is not None or u is not None:raise AuthorityUnavailable('pending observation fact has a result')
    elif row[5]!='committed' or type(r) is not PlatformObservationRefinementReceiptV3 or r.pending!=p or u!=replace(p.fact_write_permit,revision=r.updated_revision,pinned_anchor=r.after_anchor):
        raise AuthorityUnavailable('observation fact result differs')
    return p,r,u

def load_observation_receipt_locked_v3(bridge,db,mutation_id):
    row=bridge.fences.mutation_locked(db,mutation_id)
    if row is not None:
        result=bridge._completed_result(row)
        if result is None or result[0].pending.phase!='observed':raise AuthorityUnavailable('observed predecessor is not committed')
        return result[0]
    require_observation_refinement_schema_v3(db)
    require_fact_unconsumed_v3(db,bridge.namespace,mutation_id)
    _,r,_=decode_fact_record_v3(fact_row_locked_v3(db,mutation_id))
    if r is None:raise AuthorityUnavailable('observation fact predecessor is not committed')
    return r

def _current_owner_v3(bridge,db,origin,subject):
    owner=bridge.core._row(db,bridge.namespace)
    if (origin.subject!=subject or origin.namespace!=bridge.namespace or origin.authority_id!=bridge.core._id(db)
        or (owner[0],owner[1],owner[2],owner[3],owner[4],owner[9],owner[10])!=(origin.holder,origin.generation,'active',None,None,'clear',bridge.journal.journal_id)):
        raise AuthorityUnavailable('observation fact current Owner/activation differs')
    return owner

def _claim_v3(bridge,db,claim,subject,observation):
    if type(claim) is not MutationReceiptV2 or claim.pending.phase!='claimed' or claim.durable_state!='committed' or type(observation) not in (PlatformObservationV1,PlatformObservationV2) or observation.binding!=claim.pending.binding:
        raise AuthorityUnavailable('fact needs exact original committed claim')
    owner=_current_owner_v3(bridge,db,claim.pending.permit,subject)
    cr=bridge._load_mutation_locked(db,claim.pending,subject)
    updated=replace(claim.pending.permit,revision=claim.updated_revision,pinned_anchor=claim.after_anchor)
    if bridge._completed_result(cr)!=(claim,updated):raise AuthorityUnavailable('fact original claimed receipt differs')
    prep=claim.pending.prepared_receipt
    pr=bridge._load_mutation_locked(db,prep.pending,subject)
    if bridge._completed_result(pr)!=(prep,claim.pending.permit) or bridge.fences._decode_footprint(prep.pending,pr[11])!=observation.binding.footprint or bridge.fences._decode_footprint(claim.pending,cr[11])!=observation.binding.footprint:
        raise AuthorityUnavailable('fact lost original prepared footprint')
    if type(observation) is PlatformObservationV2:bridge._check_v2_observation_start_locked(db,observation,claim,subject)
    return owner

def _initial_dispatch_finished_v3(bridge,db,previous):
    if type(previous) is not MutationReceiptV2:return
    origin=previous.pending.permit
    row=bridge.fences._row(db,origin.operation_id)
    updated=replace(origin,revision=previous.updated_revision,pinned_anchor=previous.after_anchor)
    finish='observed-'+hashlib.sha256(previous.pending.mutation_id.encode('utf-8')).hexdigest()
    if (previous.pending.phase!='observed' or row is None or row[6]!='finished'
            or row[10] is not None or bridge.fences._permit(row)!=updated
            or row[8:10]!=(finish,canonical_digest(previous))):
        raise AuthorityUnavailable('fact lacks the actual first-observation finished dispatch original')

def _refinement_v3(previous,new):
    if type(previous) is not type(new) or previous.binding!=new.binding or (previous.adapter_ref,previous.account_ref,previous.destination_ref)!=(new.adapter_ref,new.account_ref,new.destination_ref):
        raise AuthorityUnavailable('observation fact route/binding differs')
    if type(new) is PlatformObservationV2:
        if (previous.handoff_id,previous.start_digest)!=(new.handoff_id,new.start_digest):raise AuthorityUnavailable('observation fact handoff differs')
    elif previous.handoff_start_ref!=new.handoff_start_ref:raise AuthorityUnavailable('observation fact handoff differs')
    for field in ('platform_request_id','platform_message_id'):
        old=getattr(previous,field);value=getattr(new,field)
        if old is not None and value is not None and value!=old:raise AuthorityUnavailable('observation fact platform identity conflicts')
    if previous.observation_id==new.observation_id or (previous.outcome,new.outcome)!=('accepted','delivered'):
        raise AuthorityUnavailable('unsupported platform fact refinement')

def read_current_effect_with_facts_locked_v3(bridge,db,*,effect_id,execution_head,execution_rows,owner):
    matches=[]
    for row in bridge._verified_dispatch_rows(execution_rows,execution_head.journal_id):
        p=decode_fact_row_v3(bridge.journal,row) if row[4].startswith(ENTRY_PREFIX) else v2_decode(row[4])
        key=(p.original_claimed_receipt.pending.permit.effect_id if type(p) is PlatformObservationRefinementPendingV3 else p.permit.effect_id)
        if key==effect_id:matches.append((row,p))
    effect=db.execute('SELECT state,conflict_keys_json,execution_seq FROM authority_effects WHERE namespace=? AND effect_id=?',(bridge.namespace,effect_id)).fetchone()
    common=dict(authority_id=bridge.core._id(db),namespace=bridge.namespace,effect_id=effect_id,activation_generation=owner[1],execution_head_seq=execution_head.seq,execution_head_digest=execution_head.digest)
    if not matches or effect is None or effect[0]!='unresolved' or effect[2]!=matches[-1][0][0] or type(matches[0][1]) is PlatformObservationRefinementPendingV3 or matches[0][1].phase!='prepared':
        raise AuthorityUnavailable('observation fact effect index/history differs')
    op=matches[0][1].permit.operation_id;previous=None;phase=None;claim=None;conflicts=None;first_observed=None
    for entry,p in matches:
        if type(p) is PlatformObservationRefinementPendingV3:
            if previous is None or phase!='observed' or p.original_claimed_receipt!=claim or p.predecessor_mutation_id!=previous.pending.mutation_id or p.predecessor_receipt_digest!=canonical_digest(previous):
                raise AuthorityUnavailable('observation fact predecessor/claim chain differs')
            _claim_v3(bridge,db,claim,p.fact_write_permit.subject,p.platform_observation)
            _refinement_v3(observation_platform_observation_v3(previous),p.platform_observation)
            require_fact_unconsumed_v3(db,bridge.namespace,p.fact_write_permit.operation_id)
            saved,r,updated=decode_fact_record_v3(fact_row_locked_v3(db,p.mutation_id))
            fr=bridge.fences._row(db,p.fact_write_permit.operation_id)
            if saved!=p or r is None or fr is None or fr[6]!='finished' or bridge.fences._permit(fr)!=updated or fr[10] is not None or fr[8:10]!=('finish:'+p.mutation_id,canonical_digest(r)):
                raise AuthorityUnavailable('observation fact lacks actual finished fact fence')
        else:
            permit=p.permit
            if (permit.authority_id,permit.namespace,permit.generation,permit.operation_id)!=(common['authority_id'],bridge.namespace,owner[1],op) or (phase is not None and p.phase not in {'prepared':{'claimed'},'claimed':{'observed'},'observed':{'observed'}}[phase]):
                raise AuthorityUnavailable('dispatch phase chain differs')
            mr=bridge._load_mutation_locked(db,p,permit.subject);result=bridge._completed_result(mr)
            if result is None or result[0].durable_state!='committed':raise AuthorityUnavailable('dispatch chain lacks actual committed receipt')
            r=result[0];conflicts=mr[5]
            if p.phase=='claimed':claim=r
            if p.phase=='observed':
                bridge._check_observed_source_locked(db,p,permit.subject)
                if first_observed is None:first_observed=r
            phase=p.phase
        if (r.after_anchor.execution_seq,r.after_anchor.execution_digest)!=(entry[0],entry[6]):raise AuthorityUnavailable('observation receipt differs from actual journal')
        previous=r
    if first_observed is None or effect[1]!=conflicts:raise AuthorityUnavailable('observation fact lost initial observed/conflict original')
    dispatch=bridge.fences._row(db,op)
    first_updated=replace(first_observed.pending.permit,revision=first_observed.updated_revision,pinned_anchor=first_observed.after_anchor)
    finish='observed-'+hashlib.sha256(first_observed.pending.mutation_id.encode('utf-8')).hexdigest()
    if dispatch is None or dispatch[6]!='finished' or bridge.fences._permit(dispatch)!=first_updated or dispatch[10] is not None or dispatch[8:10]!=(finish,canonical_digest(first_observed)):
        raise AuthorityUnavailable('historical dispatch fence changed after first observation')
    entry,p=matches[-1];obs=observation_platform_observation_v3(previous)
    return CurrentEffectReadV2(state='observed',effect_seq=entry[0],append_id=entry[3],append_digest=entry[6],mutation_id=entry[1],observation_id=obs.observation_id,observation_outcome=obs.outcome,**common)

def _locked_environment_v3(bridge,db,deletion_head,execution_head,origin,subject):
    bridge._require_v2_mode_locked(db);bridge.fences._check_schema(db);require_observation_refinement_schema_v3(db)
    bridge._check_deletion_locked(db,deletion_head);bridge._check_execution_head_locked(db,execution_head)
    if bridge.deletion.has_deletion_history(bridge.namespace):bridge.core.require_current_content_ready_locked(db,namespace=bridge.namespace)
    return _current_owner_v3(bridge,db,origin,subject)

def _existing_v3(bridge,db,fact_id,claim,observation,subject):
    require_fact_unconsumed_v3(db,bridge.namespace,fact_id)
    row=fact_row_locked_v3(db,fact_id)
    if row is None:return None
    p,r,u=decode_fact_record_v3(row)
    if p.original_claimed_receipt!=claim or p.platform_observation!=observation or p.fact_write_permit.subject!=subject:
        raise AuthorityUnavailable('observation fact ID reused with different evidence')
    return p,r

def prepare_observation_refinement_v3(bridge,*,credential,subject,claimed_receipt,observation):
    identifier(subject,'subject')
    if type(claimed_receipt) is not MutationReceiptV2 or claimed_receipt.pending.phase!='claimed' or type(observation) not in (PlatformObservationV1,PlatformObservationV2):raise AuthorityUnavailable('exact dispatch claim and observation required')
    origin=claimed_receipt.pending.permit
    bridge.core._require(credential,'execution',bridge.namespace,origin.holder)
    fact_id=fact_operation_id_v3(bridge.namespace,claimed_receipt,observation)
    with bridge.deletion.freeze_writes(),bridge.journal.freeze_writes():
        dh=bridge.deletion.verified_head();head,rows=bridge.journal._scan_locked()
        with bridge.core._tx() as db:
            require_observation_refinement_schema_v3(db)
            existing=_existing_v3(bridge,db,fact_id,claimed_receipt,observation,subject)
            if existing is not None:
                _claim_v3(bridge,db,claimed_receipt,subject,observation)
                bridge._check_deletion_locked(db,dh)
                if existing[1] is not None:
                    bridge._check_execution_head_locked(db,head)
                    bridge._read_current_effect_locked_v4(db,effect_id=origin.effect_id,execution_head=head,execution_rows=rows,owner=bridge.core._row(db,bridge.namespace))
                return existing[0]
    verifier=bridge._observation_verifier
    if verifier is None:raise AuthorityUnavailable('installed platform observation verifier required')
    verified=verifier(bridge.namespace,claimed_receipt,observation)
    if type(verified) is not type(observation) or verified!=observation:raise AuthorityUnavailable('platform fact was not verified')
    bridge.core._require(credential,'execution',bridge.namespace,origin.holder)
    with bridge.deletion.freeze_writes(),bridge.journal.freeze_writes():
        dh=bridge.deletion.verified_head();head,rows=bridge.journal._scan_locked()
        with bridge.core._tx() as db:
            owner=_locked_environment_v3(bridge,db,dh,head,origin,subject)
            _claim_v3(bridge,db,claimed_receipt,subject,observation)
            existing=_existing_v3(bridge,db,fact_id,claimed_receipt,observation,subject)
            if existing is not None:return existing[0]
            current=bridge._read_current_effect_locked_v4(db,effect_id=origin.effect_id,execution_head=head,execution_rows=rows,owner=owner)
            if current.state!='observed':raise AuthorityUnavailable('refinement requires actual prior observation')
            previous=load_observation_receipt_locked_v3(bridge,db,current.mutation_id)
            if (previous.pending.claimed_receipt if type(previous) is MutationReceiptV2 else previous.pending.original_claimed_receipt)!=claimed_receipt:raise AuthorityUnavailable('predecessor belongs to a different claim')
            _initial_dispatch_finished_v3(bridge,db,previous)
            _refinement_v3(observation_platform_observation_v3(previous),observation)
            if db.execute("SELECT 1 FROM authority_v2_mutations WHERE namespace=? AND state='pending' LIMIT 1",(bridge.namespace,)).fetchone() or db.execute('SELECT 1 FROM '+TABLE+" WHERE namespace=? AND state='pending' LIMIT 1",(bridge.namespace,)).fetchone():raise AuthorityUnavailable('namespace has an unresolved pending original')
            before=bridge.core._anchor(db,bridge.namespace,owner)
            request=fact_request_digest_v3(fact_id,claimed_receipt,current.mutation_id,canonical_digest(previous),observation,before)
            permit=bridge.fences.begin_fence_locked(db,subject=subject,holder=origin.holder,operation='write',current_anchor=before,operation_id=fact_id)
            draft=PlatformObservationRefinementPendingV3(permit,fact_id,request,before,head.journal_id,head.seq+1,fact_id,'sha256:'+'0'*64,claimed_receipt,current.mutation_id,canonical_digest(previous),observation)
            pending=replace(draft,expected_append_digest=expected_fact_digest_v3(draft))
            bridge.fences.record_observation_fact_pending_locked_v3(db,pending,subject=subject,current_anchor=before)
            return pending

def _fact_fence_bytes_v3(db,pending):
    from .c09_platform_observation_fact_storage_v3 import fact_fence_bytes_v3
    return fact_fence_bytes_v3(db,pending)


def _pending_owner_v3(bridge,db,pending,subject):
    require_fact_unconsumed_v3(db,bridge.namespace,pending.fact_write_permit.operation_id)
    p,r,_=decode_fact_record_v3(fact_row_locked_v3(db,pending.mutation_id))
    if p!=pending or pending.fact_write_permit.subject!=subject:raise AuthorityUnavailable('fact pending ownership differs')
    fr=bridge.fences._row(db,pending.fact_write_permit.operation_id)
    if r is None and (fr is None or fr[6]!='active' or bridge.fences._permit(fr)!=pending.fact_write_permit or fr[10]!=_fact_fence_bytes_v3(db,pending)):
        raise AuthorityUnavailable('new fact fence does not own typed pending')
    return r

def _inspect_fact_rows_v3(journal,pending,head,rows):
    if journal._guard_owner!=threading.get_ident():raise AuthorityUnavailable('frozen actual execution writer required')
    b=pending.before_anchor
    if b.execution_seq>head.seq or (b.execution_seq and rows[b.execution_seq-1][6]!=b.execution_digest) or (not b.execution_seq and b.execution_digest!='genesis'):raise AuthorityUnavailable('fact before head is absent')
    following=head.seq-b.execution_seq
    if following and (rows[b.execution_seq][4]!=encode_fact_entry_v3(pending) or decode_fact_row_v3(journal,rows[b.execution_seq])!=pending):raise AuthorityUnavailable('fact expected append differs')
    return following,head,rows

def inspect_fact_append_locked_v3(journal,pending):
    if journal._guard_owner!=threading.get_ident():raise AuthorityUnavailable('frozen actual execution writer required')
    head,rows=journal._scan_locked()
    return _inspect_fact_rows_v3(journal,pending,head,rows)

def append_observation_refinement_v3(bridge,*,credential,subject,pending):
    if type(pending) is not PlatformObservationRefinementPendingV3:raise AuthorityUnavailable('exact fact pending required')
    origin=pending.original_claimed_receipt.pending.permit
    bridge.core._require(credential,'execution',bridge.namespace,origin.holder)
    with bridge.deletion.freeze_writes(),bridge.journal.freeze_writes():
        dh=bridge.deletion.verified_head();count,head,rows=inspect_fact_append_locked_v3(bridge.journal,pending)
        with bridge.core._tx() as db:
            require_observation_refinement_schema_v3(db);bridge._check_deletion_locked(db,dh)
            result=_pending_owner_v3(bridge,db,pending,subject)
            _claim_v3(bridge,db,pending.original_claimed_receipt,subject,pending.platform_observation)
            if result is not None:return
            if count>1:raise AuthorityUnavailable('extra append quarantines fact pending')
            if count==1:return
            bridge._check_core_owner(db,pending.fact_write_permit);bridge._check_execution_head_locked(db,head)
            current=bridge._read_current_effect_locked_v4(db,effect_id=origin.effect_id,execution_head=head,execution_rows=rows,owner=bridge.core._row(db,bridge.namespace))
            previous=load_observation_receipt_locked_v3(bridge,db,current.mutation_id)
            if current.mutation_id!=pending.predecessor_mutation_id or canonical_digest(previous)!=pending.predecessor_receipt_digest:raise AuthorityUnavailable('fact predecessor changed before append')
        bridge.journal.append_observation_fact_once_guarded_v3(pending)

def reconcile_observation_refinement_v3(bridge,*,credential,subject,pending):
    if type(pending) is not PlatformObservationRefinementPendingV3:raise AuthorityUnavailable('exact fact pending required')
    origin=pending.original_claimed_receipt.pending.permit
    bridge.core._require(credential,'execution',bridge.namespace,origin.holder)
    with bridge.deletion.freeze_writes(),bridge.journal.freeze_writes():
        dh=bridge.deletion.verified_head();count,head,rows=inspect_fact_append_locked_v3(bridge.journal,pending)
        with bridge.core._tx() as db:
            require_observation_refinement_schema_v3(db);bridge._require_v2_mode_locked(db);bridge.fences._check_schema(db);bridge._check_deletion_locked(db,dh)
            if bridge.deletion.has_deletion_history(bridge.namespace):bridge.core.require_current_content_ready_locked(db,namespace=bridge.namespace)
            result=_pending_owner_v3(bridge,db,pending,subject)
            owner=_claim_v3(bridge,db,pending.original_claimed_receipt,subject,pending.platform_observation)
            if result is not None:
                bridge._check_execution_head_locked(db,head)
                bridge._read_current_effect_locked_v4(db,effect_id=origin.effect_id,execution_head=head,execution_rows=rows,owner=owner)
                return result
            if count!=1:raise AuthorityUnavailable('fact recovery requires exactly its one durable append; zero remains pending')
            bridge._check_core_owner(db,pending.fact_write_permit)
            previous=load_observation_receipt_locked_v3(bridge,db,pending.predecessor_mutation_id)
            if canonical_digest(previous)!=pending.predecessor_receipt_digest:raise AuthorityUnavailable('fact predecessor receipt changed')
            _initial_dispatch_finished_v3(bridge,db,previous)
            _refinement_v3(observation_platform_observation_v3(previous),pending.platform_observation)
            beforehead=JournalHead(head.journal_id,pending.before_anchor.execution_seq,pending.before_anchor.execution_digest)
            current=bridge._read_current_effect_locked_v4(db,effect_id=origin.effect_id,execution_head=beforehead,execution_rows=rows[:beforehead.seq],owner=owner)
            if current.mutation_id!=pending.predecessor_mutation_id:raise AuthorityUnavailable('fact no longer extends actual effect tail')
            changed=db.execute("UPDATE authority_effects SET execution_seq=? WHERE namespace=? AND effect_id=? AND state='unresolved' AND execution_seq=?",(pending.expected_execution_seq,bridge.namespace,origin.effect_id,current.effect_seq)).rowcount
            if changed!=1:raise AuthorityUnavailable('fact effect tail CAS failed')
            changed=db.execute('UPDATE authority_namespaces SET execution_seq=?,execution_digest=?,anchor_nonce=? WHERE namespace=? AND execution_seq=? AND execution_digest=?',(pending.expected_execution_seq,pending.expected_append_digest,bridge.core._new_nonce(),bridge.namespace,pending.before_anchor.execution_seq,pending.before_anchor.execution_digest)).rowcount
            if changed!=1:raise AuthorityUnavailable('fact execution head CAS failed')
            bridge.core._event(db,bridge.namespace,'platform_observation_refinement_v3',origin.generation,(pending.mutation_id,pending.request_digest,pending.expected_append_digest))
            after=bridge.core._anchor(db,bridge.namespace,bridge.core._row(db,bridge.namespace))
            receipt=PlatformObservationRefinementReceiptV3(pending,after,pending.fact_write_permit.revision+1)
            bridge.fences.finish_observation_fact_locked_v3(db,receipt,subject=subject)
            return receipt

def read_observation_refinement_v3(bridge,*,credential,subject,fact_operation_id):
    """Authenticate one persisted fact by stable ID, without replaying any append."""
    identifier(subject,'subject');identifier(fact_operation_id,'fact_operation_id')
    if not fact_operation_id.startswith('observation-fact-v3:'):
        raise AuthorityUnavailable('exact observation fact operation locator required')
    bridge.core._require(credential,'execution',bridge.namespace)
    with bridge.deletion.freeze_writes(),bridge.journal.freeze_writes():
        dh=bridge.deletion.verified_head();head,rows=bridge.journal._scan_locked()
        with bridge.core._tx() as db:
            bridge._require_v2_mode_locked(db);bridge.fences._check_schema(db)
            require_observation_refinement_schema_v3(db)
            from .observation_fact_history_v3 import read_runtime_observation_fact_history_v3
            historical=read_runtime_observation_fact_history_v3(bridge,db,fact_operation_id)
            if historical is not None:
                if historical.pending.fact_write_permit.subject!=subject:
                    raise AuthorityUnavailable('historical Fact subject differs from current authenticated reader')
                bridge._check_deletion_locked(db,dh)
                if bridge.deletion.has_deletion_history(bridge.namespace):
                    bridge.core.require_current_content_ready_locked(db,namespace=bridge.namespace)
                return historical.receipt
            require_fact_unconsumed_v3(db,bridge.namespace,fact_operation_id)
            row=fact_row_locked_v3(db,fact_operation_id)
            if row is None:return None
            p,r,_=decode_fact_record_v3(row)
            if p.fact_write_permit.subject!=subject or p.fact_write_permit.namespace!=bridge.namespace:
                raise AuthorityUnavailable('observation fact locator subject/namespace differs')
            bridge._check_deletion_locked(db,dh)
            if bridge.deletion.has_deletion_history(bridge.namespace):bridge.core.require_current_content_ready_locked(db,namespace=bridge.namespace)
            owner=_claim_v3(bridge,db,p.original_claimed_receipt,subject,p.platform_observation)
            if _pending_owner_v3(bridge,db,p,subject)!=r:
                raise AuthorityUnavailable('observation fact lookup ownership differs')
            count,_,_=_inspect_fact_rows_v3(bridge.journal,p,head,rows)
            effect_id=p.original_claimed_receipt.pending.permit.effect_id
            if r is not None:
                bridge._check_execution_head_locked(db,head)
                bridge._read_current_effect_locked_v4(db,effect_id=effect_id,execution_head=head,execution_rows=rows,owner=owner)
                return r
            if count>1:raise AuthorityUnavailable('extra append quarantines cold observation fact')
            bridge._check_core_owner(db,p.fact_write_permit)
            before=JournalHead(head.journal_id,p.before_anchor.execution_seq,p.before_anchor.execution_digest)
            current=bridge._read_current_effect_locked_v4(db,effect_id=effect_id,execution_head=before,
                execution_rows=rows[:before.seq],owner=owner)
            previous=load_observation_receipt_locked_v3(bridge,db,current.mutation_id)
            if current.mutation_id!=p.predecessor_mutation_id or canonical_digest(previous)!=p.predecessor_receipt_digest:
                raise AuthorityUnavailable('cold observation fact predecessor differs')
            _initial_dispatch_finished_v3(bridge,db,previous)
            _refinement_v3(observation_platform_observation_v3(previous),p.platform_observation)
            return p

def recover_observation_refinement_v3(bridge,*,credential,subject,fact_operation_id):
    """Adopt exactly one existing append; an unappended original remains pending."""
    original=read_observation_refinement_v3(bridge,credential=credential,subject=subject,fact_operation_id=fact_operation_id)
    if original is None or type(original) is PlatformObservationRefinementReceiptV3:return original
    with bridge.deletion.freeze_writes(),bridge.journal.freeze_writes():
        count,_,_=inspect_fact_append_locked_v3(bridge.journal,original)
        if count==0:return original
        if count!=1:raise AuthorityUnavailable('cold observation fact requires its unique durable append')
    return reconcile_observation_refinement_v3(bridge,credential=credential,subject=subject,pending=original)

def current_observation_refinement_operation_v3(bridge,*,credential,subject):
    """Select the one actual subject-owned pending ID for a named recovery wake."""
    identifier(subject,'subject')
    bridge.core._require(credential,'execution',bridge.namespace)
    with bridge.core._tx() as db:
        bridge._require_v2_mode_locked(db);bridge.fences._check_schema(db)
        require_observation_refinement_schema_v3(db)
        from .c09_graph_application_v1 import c09_actual_root_read_v3
        rows=c09_actual_root_read_v3(db).execute('SELECT fact_operation_id FROM '+TABLE+" WHERE namespace=? AND subject=? AND state='pending' ORDER BY fact_operation_id LIMIT 2",(bridge.namespace,subject)).fetchall()
        if len(rows)>1:raise AuthorityUnavailable('multiple observation fact pending originals quarantine namespace')
        if not rows:return None
        # The authenticated Core columns locate the recovery responsibility.
        # Its original/fence/consumed/chain checks belong to the named recovery,
        # so a malformed original is latched against this actual persisted ID.
        return rows[0][0]


def execution_refine_observation_v3(bridge,*,credential,subject,claimed_receipt,observation):
    pending=prepare_observation_refinement_v3(bridge,credential=credential,subject=subject,claimed_receipt=claimed_receipt,observation=observation)
    append_observation_refinement_v3(bridge,credential=credential,subject=subject,pending=pending)
    return reconcile_observation_refinement_v3(bridge,credential=credential,subject=subject,pending=pending)
