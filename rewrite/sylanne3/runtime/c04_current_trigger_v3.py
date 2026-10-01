"""Current source/focus/Mood trigger for the installed bounded C04 executor."""
from dataclasses import dataclass
import json
import time

from ..graph_types import AtomKey, GraphVersion, Owner, owner_grant_key
from ..runtime_contracts import CommandEnvelope, OperationIdentity, QueryEpoch, RUNTIME_SCHEMA, SourceQualification, VersionGuard, canonical_digest
from .c04_v3_contracts import AssociationBudgetV3
from .first_ingress_v2 import trusted_upper


@dataclass(frozen=True, slots=True)
class CurrentC04TriggerV3:
    cue_source_ref: str
    body_policy_id: str
    body_policy_version: int
    cpu_policy_id: str
    cpu_policy_version: int
    parent_budget_lease_ref: str
    budget: AssociationBudgetV3
    context_tags: tuple[str, ...] = ()

    def __post_init__(self):
        if (AtomKey.from_token(self.cue_source_ref).type_name != 'memory.source'
                or type(self.budget) is not AssociationBudgetV3
                or any(type(v) is not str or not 1 <= len(v) <= 128 for v in (
                    self.body_policy_id,self.cpu_policy_id,self.parent_budget_lease_ref))
                or any(type(v) is not int or v < 1 for v in (self.body_policy_version,self.cpu_policy_version))
                or type(self.context_tags) is not tuple or tuple(sorted(set(self.context_tags))) != self.context_tags
                or len(self.context_tags)>32 or any(type(v) is not str or not v or len(v)>128 for v in self.context_tags)):
            raise ValueError('C04 trigger requires explicit installed policies, budget and current source')


def prepare_current_c04_trigger_v3(graph, authority, lease, *, operation_id, request):
    from ..graph_coordinator import UnavailableGuard
    from ..memory_types import SourceRecord, access_key
    if type(request) is not CurrentC04TriggerV3 or authority.purpose not in {'context','consolidation'}:
        raise ValueError('C04 current-source operation requires its actual qualified purpose')
    graph._authorize(lease,authority,frozenset({'d02','d04','d06','d07','d11'}),owner_read=True)
    owner=graph._GraphCoordinator__owner_leases.get(lease)
    proof=graph._GraphCoordinator__owner_session_proofs.get(lease)
    if owner is None or proof is None or 'c04.internal_work.prepare' not in owner.capabilities:
        raise UnavailableGuard('actual C04 Owner capability is unavailable')
    ns,store=authority.namespace,graph._GraphCoordinator__store
    cue=AtomKey.from_token(request.cue_source_ref)
    if (cue.owner.bot,cue.owner.persona)!=ns.as_tuple:raise ValueError('C04 cue namespace differs')
    clock=graph._GraphCoordinator__content_fence_v2.read_ingress_clock(graph._GraphCoordinator__scene_clock_policy)
    now=trusted_upper(clock)
    def read():
        db=store._db;db.execute('BEGIN')
        try:
            from .c04_product_original_v3 import read_c04_product_request_v3
            from .c04_internal_work_original_v1 import read_c04_internal_work_prepared_v1
            from .c04_frozen_association_original_v3 import read_c04_frozen_association_original_v3, verify_current_association_input_heads_v3
            saved = read_c04_product_request_v3(db, ns, operation_id)
            if saved is not None:
                prepared = read_c04_internal_work_prepared_v1(db, ns, operation_id)
                work = read_c04_frozen_association_original_v3(db, ns, prepared.binding)
                cpu, quote = graph._GraphCoordinator__c04_cpu_quote_authority.read_original_request_quote(db, ns, operation_id)
                body_policy = db.execute("SELECT policy_id,policy_version FROM d02_body_quotes_v1 "
                    "WHERE bot=? AND persona=? AND quote_id=?", (*ns.as_tuple, prepared.binding.body_quote_ref)).fetchone()
                if (body_policy != (request.body_policy_id, request.body_policy_version)
                        or (cpu.policy_id, cpu.version) != (request.cpu_policy_id, request.cpu_policy_version)
                        or (work.cue_source_ref, work.budget, work.context_tags) != (cue.token, request.budget, request.context_tags)
                        or prepared.binding.parent_budget_lease_ref != request.parent_budget_lease_ref
                        or prepared.owner_grant_revision != owner.grant_revision
                        or prepared.owner_grant_digest != owner.grant_digest.removeprefix('sha256:')
                        or (saved.envelope.authority.purpose, saved.envelope.authority.audience,
                            saved.envelope.authority.activation_generation) !=
                            (authority.purpose, authority.audience, authority.activation_generation)
                        or canonical_digest(quote) != prepared.binding.resource_quote_digest):
                    raise ValueError('same C04 trigger changed its original intent or Owner')
                verify_current_association_input_heads_v3(db, work)
                return prepared
            metadata,epoch=graph._v2_graph_stamp(ns)
            focus=AtomKey(Owner('persona',*ns.as_tuple),'d07.focus.v1',ns.persona_id)
            row=db.execute('SELECT revision,value,valid FROM graph_atoms WHERE token=?',(focus.token,)).fetchone()
            source=db.execute('SELECT revision,value,valid FROM graph_atoms WHERE token=?',(cue.token,)).fetchone()
            if row is None or row[2]!=1 or source is None or source[2]!=1:
                raise UnavailableGuard('current C04 focus/source is unavailable')
            focus_value=json.loads(row[1]);ticket_ref=focus_value.get('primary_ticket_ref')
            if type(ticket_ref) is not str:raise UnavailableGuard('C04 current focus has no selected attention ticket')
            ticket=AtomKey.from_token(ticket_ref)
            ticket_row=db.execute('SELECT revision,value,valid FROM graph_atoms WHERE token=?',(ticket_ref,)).fetchone()
            if ticket_row is None or ticket_row[2]!=1:raise UnavailableGuard('C04 current attention ticket is unavailable')
            ticket_value=json.loads(ticket_row[1])
            moods=db.execute("SELECT token,revision,value FROM graph_atoms WHERE bot=? AND persona=? AND valid=1 "
                "AND type_name IN ('d04.mood_field.v1','d04.authored_mood_state.v1') ORDER BY token LIMIT 2",ns.as_tuple).fetchall()
            if len(moods)!=1:raise UnavailableGuard('C04 requires one actual current Mood component')
            from .c04_association_graph_collector_v2 import collect_c04_association_graph_originals_v2
            from ..domains.d06.current_association_candidates import CurrentAssociationBudgetV1
            bounded = request.budget
            observed = collect_c04_association_graph_originals_v2(db, ns,
                cue_source_ref=cue.token, focus_ref=focus.token, attention_ticket_ref=ticket_ref,
                mood_ref=moods[0][0], budget=CurrentAssociationBudgetV1(bounded.max_hops,bounded.max_edges,
                    bounded.max_nodes,bounded.max_iterations,bounded.max_candidates),context_tags=request.context_tags)
            baseline_rows=[]
            for source_ref in sorted({head.key.token for head in observed.reads
                    if head.key.type_name=='memory.source' and head.revision>0 and head.valid}):
                selected=db.execute('SELECT source_ref,encoding_operation_id FROM graph_c04_encoding_baselines_v3 '
                    'WHERE bot=? AND persona=? AND source_ref=? ORDER BY encoding_operation_id LIMIT 2',
                    (*ns.as_tuple,source_ref)).fetchall()
                if len(selected)!=1:
                    raise UnavailableGuard('C04 reachable source has no unique actual encoding baseline')
                baseline_rows.extend(selected)
            if not baseline_rows:raise UnavailableGuard('bounded actual C04 encoding baselines unavailable')
            cpu=graph._GraphCoordinator__c04_cpu_quote_authority.read_policy(db,ns,request.cpu_policy_id,request.cpu_policy_version)
            body=graph._GraphCoordinator__body_quote_authority.policy(db,ns,request.body_policy_id,request.body_policy_version)
            grant=graph._GraphCoordinator__d11_issuer.current_budget_grant(db,request.parent_budget_lease_ref)
            deadline=min(now+300.0,cpu.valid_until_utc,body.valid_until,grant.valid_until_utc,ticket_value['valid_until'])
            if deadline<=now:raise UnavailableGuard('C04 current original deadline expired')
            record=SourceRecord.from_dict(json.loads(source[1]));access=access_key(*ns.as_tuple,record.source_id)
            access_row=db.execute('SELECT revision,valid FROM graph_atoms WHERE token=?',(access.token,)).fetchone()
            if access_row is None or access_row[1]!=1:raise UnavailableGuard('C04 current source access unavailable')
            revisions=(GraphVersion(cue,source[0]),GraphVersion(access,access_row[0]),GraphVersion(focus,row[0]),
                GraphVersion(ticket,ticket_row[0]),GraphVersion(AtomKey.from_token(moods[0][0]),moods[0][1]),
                GraphVersion(owner_grant_key(*ns.as_tuple),owner.grant_revision))
            inputs=(request.cue_source_ref,focus.token,ticket_ref,moods[0][0])
            activity='c04-activity:'+canonical_digest((ns,operation_id))[:48]
            effect='c04-effect:'+canonical_digest((ns,operation_id))[:48]
            envelope=CommandEnvelope(RUNTIME_SCHEMA,OperationIdentity(activity,effect,operation_id,'realize-recollection',
                operation_id,canonical_digest({'input_refs':list(inputs)})),authority,
                VersionGuard(revisions,(QueryEpoch(ns,'all',epoch.revision),),owner.access_epoch,owner.delete_epoch,
                    store._registry.catalogue_hash,graph._version(db,ns,'scheme','current'),
                    graph._version(db,ns,'operator','current'),graph._version(db,ns,'policy','current'),(),(),()),
                SourceQualification((cue.token,),'derived',record.occurred_at,record.recorded_at,
                    'inference','ineligible',None,'not_applicable'),inputs,request.parent_budget_lease_ref,
                deadline,time.monotonic()+deadline-now,'c04-snapshot:'+operation_id,())
            return envelope,focus.token,ticket_ref,moods[0][0],tuple(baseline_rows)
        finally:db.rollback()
    observed=graph._read_v2(authority,read,owner_binding=owner,owner_session_proof=proof)
    from .c04_internal_work_original_v1 import C04InternalWorkPreparedV1
    if type(observed) is C04InternalWorkPreparedV1:
        return observed
    envelope,focus,ticket,mood,baselines=observed
    return graph.prepare_internal_work_v3(authority,lease,envelope=envelope,
        body_policy_id=request.body_policy_id,body_policy_version=request.body_policy_version,
        cpu_policy_id=request.cpu_policy_id,cpu_policy_version=request.cpu_policy_version,
        reservation_id='c04-body:'+canonical_digest((ns,operation_id))[:48],
        execution_id='c04-execution:'+canonical_digest((ns,operation_id))[:48],
        cue_source_ref=request.cue_source_ref,focus_ref=focus,attention_ticket_ref=ticket,mood_ref=mood,
        encoding_operations=baselines,budget=request.budget,context_tags=request.context_tags)


def _with_current_owner_scope_v3(graph, authority, lease, read_scope, execute):
    """Derive content scope from actual originals under the signed Owner login."""
    owner=graph._GraphCoordinator__owner_leases.get(lease)
    proof=graph._GraphCoordinator__owner_session_proofs.get(lease)
    if owner is None or proof is None or 'c04.internal_work.prepare' not in owner.capabilities:
        raise ValueError('C04 signed Owner scope is unavailable')
    purpose,audience=graph._read_v2(authority,read_scope,owner_binding=owner,owner_session_proof=proof)
    if purpose not in {'context','consolidation'} or purpose not in owner.purposes or audience not in owner.audiences:
        raise ValueError('C04 actual original scope is not granted by current Owner')
    current,token,_=graph.grant_current_owner(graph._GraphCoordinator__bootstrap,actor=authority.actor,
        namespace=authority.namespace,domains=('d02','d04','d06','d07','d11','d12'),purpose=purpose,audience=audience,
        activation_generation=authority.activation_generation,owner_session_token=proof[0],owner_session_request=proof[1])
    try:return execute(current,token)
    finally:graph.release_current_owner_lease(graph._GraphCoordinator__bootstrap,token)


def prepare_owner_c04_trigger_v3(graph, authority, lease, *, operation_id, request):
    if type(request) is not CurrentC04TriggerV3:raise ValueError('exact C04 trigger required')
    def scope():
        from .ingress_observation import read_committed_ingress_identity
        source=AtomKey.from_token(request.cue_source_ref)
        if (source.owner.bot,source.owner.persona)!=authority.namespace.as_tuple:raise ValueError('C04 cue namespace differs')
        original=read_committed_ingress_identity(graph._GraphCoordinator__store._db,authority.namespace,source.owner.subject)
        if original is None:raise ValueError('C04 actual current source route is absent')
        return 'consolidation',json.loads(original.identity_json)['conversation_ref']
    def execute(current,token):
        prepared=prepare_current_c04_trigger_v3(graph,current,token,operation_id=operation_id,request=request)
        return {'status':'prepared','operation_id':operation_id,'prepared_digest':prepared.prepared_digest,
            'binding_digest':prepared.binding.binding_digest,'execution_id':prepared.binding.execution_id}
    return _with_current_owner_scope_v3(graph,authority,lease,scope,execute)


def advance_owner_c04_work_v3(graph,authority,lease,*,original_operation_id):
    def scope():
        from .c04_product_original_v3 import read_c04_product_request_v3
        db=graph._GraphCoordinator__store._db;db.execute('BEGIN')
        try:
            original=read_c04_product_request_v3(db,authority.namespace,original_operation_id)
            if original is None:raise ValueError('C04 actual prepared request is absent')
            return original.envelope.authority.purpose,original.envelope.authority.audience[0]
        finally:db.rollback()
    return _with_current_owner_scope_v3(graph,authority,lease,scope,lambda current,token:
        graph.advance_current_c04_product_v3(current,token,original_operation_id,holder=graph._GraphCoordinator__holder))
