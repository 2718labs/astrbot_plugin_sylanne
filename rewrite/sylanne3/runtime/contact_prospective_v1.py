"""Prospective Contact birth under a separate current WRITE operation.

Only the paid-content locator enters the public request. The installed writer
will derive the future first identity and reserve its original quote once.
"""
from dataclasses import dataclass
from ..authority_service.contract import identifier
from ..runtime_contracts import NamespaceId,canonical_digest,canonical_serialize

@dataclass(frozen=True,slots=True)
class PrepareCurrentContactProspectiveRequestV1:
    contact_id:str
    def __post_init__(self):
        identifier(self.contact_id,'contact_id')
        if not self.contact_id.startswith('contact:'):
            raise ValueError('Contact prospective requires the exact paid Contact identity')


def contact_prospective_command_digest_v1(namespace,actor,request,birth_operation_id,activity_id,audience,parent_budget_lease_ref):
    if type(namespace)is not NamespaceId or type(request)is not PrepareCurrentContactProspectiveRequestV1:
        raise TypeError('Contact prospective command requires its actual namespace and typed locator')
    return canonical_digest(('sylanne.domain-production-command.v1',namespace,actor,
        'prepare_contact_prospective_v1',request,birth_operation_id,activity_id,audience,parent_budget_lease_ref))


def contact_prospective_attempt_id_v1(namespace,birth_operation_id,request_digest):
    return 'owner-domain-'+canonical_digest((namespace,birth_operation_id,request_digest))[:48]

from ..authority_service.contact_prospective_contract_v1 import (
    ContactProspectiveObservationV1, contact_prospective_from_wire_v1)
from .contact_background_inputs_v1 import validate_background_inputs_v1
from .contact_original_read_v3 import contact_original_point_v3
from .domain_production_originals_v1 import _receipt, _receipt_wire
import json

TABLE = 'graph_contact_prospective_originals_v1'
SIGN_KIND = 'd10.contact-prospective-original.v1'
REFRESH_RULE = 'd10.contact-prospective-successor.v1'
COLUMNS = ('bot','persona','contact_id','birth_operation_id','payload_json','payload_digest','signature','original_ref')
DDL = ('CREATE TABLE '+TABLE+'(bot TEXT NOT NULL,persona TEXT NOT NULL,contact_id TEXT NOT NULL,'
    'birth_operation_id TEXT NOT NULL,payload_json TEXT NOT NULL,payload_digest TEXT NOT NULL,'
    'signature TEXT NOT NULL,original_ref TEXT NOT NULL,PRIMARY KEY(bot,persona,contact_id),UNIQUE(bot,persona,birth_operation_id),UNIQUE(bot,persona,original_ref))')
TRIGGERS = tuple('CREATE TRIGGER '+TABLE+'_no_'+action.lower()+' BEFORE '+action+' ON '+TABLE+
    " BEGIN SELECT RAISE(ABORT,'Contact prospective original immutable'); END" for action in ('UPDATE','DELETE'))
_FIELDS = {'schema','namespace','contact_id','birth_operation_id','birth_request_digest',
    'final_operation_id','effect_id','observation','terms','candidate','prospective_facts',
    'quote','reservation','deadline_utc','refresh_rule','receipt','joint_preparation'}


def validate_contact_prospective_original_v1(raw):
    if type(raw) is not dict or set(raw) != _FIELDS or raw['schema'] != SIGN_KIND:
        raise ValueError('Contact prospective immutable closed schema differs')
    namespace = NamespaceId(**raw['namespace'])
    observation = contact_prospective_from_wire_v1(raw['observation'],ContactProspectiveObservationV1)
    terms = validate_background_inputs_v1(raw['terms'])
    receipt = _receipt(raw['receipt'])
    selector = observation.selector
    quote,reservation,candidate = raw['quote'],raw['reservation'],raw['candidate']
    preparation=raw['joint_preparation']
    if (type(preparation) is not dict or set(preparation)!={'ref','digest','operation_id','receipt_digest','dedupe_key'}
            or (preparation['ref'],preparation['digest'],preparation['operation_id'],preparation['receipt_digest'])!=
                (observation.joint_preparation_ref,observation.joint_preparation_digest,
                 observation.joint_preparation_operation_id,observation.joint_preparation_receipt_digest)
            or preparation['dedupe_key']!=selector.causal_dedupe_key
            or preparation['dedupe_key']==terms['dedupe_key']):
        raise ValueError('Contact prospective must preserve exact independent Joint preparation and old Contact causes')
    if (raw['refresh_rule'] != REFRESH_RULE or raw['namespace'] != terms['namespace']
            or selector.namespace != namespace or selector.contact_id != raw['contact_id']
            or selector.birth_operation_id != raw['birth_operation_id']
            or selector.birth_request_digest != raw['birth_request_digest']
            or selector.final_operation_id != raw['final_operation_id'] or selector.effect_id != raw['effect_id']
            or observation.observed_operation_id != raw['birth_operation_id']
            or observation.observed_request_digest != raw['birth_request_digest']
            or observation.attempt_id != contact_prospective_attempt_id_v1(namespace,raw['birth_operation_id'],raw['birth_request_digest'])
            or observation.inputs_json != canonical_serialize(terms)
            or (terms['contact_id'],terms['operation_id'],terms['first_effect_id']) !=
                (raw['contact_id'],raw['final_operation_id'],raw['effect_id'])
            or receipt.status != 'committed' or receipt.operation_id != raw['birth_operation_id']
            or not observation.observed_at_utc < raw['deadline_utc'] <= min(observation.deadline_utc,terms['deadline_utc'])
            or type(quote) is not dict or set(quote) != {'id','version','digest','operation_id','effect_id','lease_ref'}
            or (quote['operation_id'],quote['effect_id'],quote['lease_ref']) !=
                (raw['final_operation_id'],raw['effect_id'],terms['budget_lease_ref'])
            or type(reservation) is not dict or set(reservation) != {'lease_ref','operation_id','digest','ceiling'}
            or (reservation['lease_ref'],reservation['operation_id']) != (quote['lease_ref'],quote['operation_id'])
            or type(candidate) is not dict or set(candidate) != {'goal','action','schema','digest'}
            or canonical_digest({key:candidate[key] for key in ('goal','action','schema')}) != candidate['digest']):
        raise ValueError('Contact prospective original birth/future/actual observation binding differs')
    facts = raw['prospective_facts']
    if (type(facts) is not dict or set(facts) != {'schema','namespace','graph_revision','graph_epoch',
            'future_operation_id','effect_id','quote_digest','reservation_digest','owner_policy_digest',
            'source_closure_digest','facts','digest'} or facts['schema'] != 'd10.contact-prospective-facts.v1'
            or facts['namespace'] != raw['namespace'] or facts['future_operation_id'] != raw['final_operation_id']
            or facts['effect_id'] != raw['effect_id'] or facts['quote_digest'] != quote['digest']
            or facts['reservation_digest'] != reservation['digest']
            or facts['owner_policy_digest'] != observation.policy_original_digest
            or (facts['graph_revision'],facts['graph_epoch']) != (terms['graph_revision'],terms['graph_epoch'])
            or type(facts['facts']) is not list or len(facts['facts']) != 6
            or {fact['kind'] for fact in facts['facts']} != {'role_binding','boundary','source_grant',
                'commitment_conflict','dispatch_budget','contact_policy'}
            or canonical_digest({key:value for key,value in facts.items() if key != 'digest'}) != facts['digest']):
        raise ValueError('Contact prospective requires six actual birth facts and its exact reservation')
    for fact in facts['facts']:
        if (set(fact) != {'kind','provider','input_versions','evidence','evidence_digest','valid_until_utc'}
                or not fact['input_versions'] or canonical_digest(fact['evidence'])!=fact['evidence_digest']
                or fact['valid_until_utc'] < raw['deadline_utc']):
            raise ValueError('Contact prospective fact lacks its actual provider/version/deadline evidence')
    action,goal,schema = candidate['action'],candidate['goal'],candidate['schema']
    if (action['goal_ref'] != goal['goal_id'] or action['schema_id'] != schema['schema_id']
            or action['success_predicate'] != goal['satisfaction_predicate']
            or action['identity']['operation_id'] != raw['final_operation_id']
            or action['identity']['effect_id'] != raw['effect_id']):
        raise ValueError('Contact future Action/Schema/Goal candidate differs from original fixed identity')
    return raw


@dataclass(frozen=True,slots=True)
class ContactProspectiveOriginalV1:
    payload_json:str
    def __post_init__(self):
        raw = validate_contact_prospective_original_v1(json.loads(self.payload_json))
        if canonical_serialize(raw) != self.payload_json:
            raise ValueError('Contact prospective original canonical bytes differ')
    @property
    def digest(self):
        return canonical_digest(json.loads(self.payload_json))


def read_contact_prospective_original_v1(db,issuer,namespace,contact_id):
    if not db.in_transaction or type(namespace) is not NamespaceId:
        raise ValueError('Contact prospective original requires its actual pinned Source snapshot')
    row = contact_original_point_v3(db,table=TABLE,columns=COLUMNS,key_columns=('bot','persona','contact_id'),
        key=(*namespace.as_tuple,contact_id),legacy_reader=lambda:None)
    if row is None:
        return None
    original = ContactProspectiveOriginalV1(row[4])
    raw = json.loads(original.payload_json)
    if (row[:3] != (*namespace.as_tuple,contact_id) or row[3] != raw['birth_operation_id'] or row[5] != original.digest
            or row[7]!=contact_prospective_original_ref_v1(namespace,contact_id,row[3])):
        raise ValueError('Contact prospective signed original exact locator/digest differs')
    issuer._signer.verify(SIGN_KIND,canonical_serialize((namespace,contact_id,row[3],original.digest)),row[6])
    attempt = contact_original_point_v3(db,table='graph_owner_domain_attempts_v3',
        columns=('request_digest','attempt_id','graph_revision','graph_epoch','permit_json','receipt_json'),
        key_columns=('bot','persona','operation_id'),key=(*namespace.as_tuple,row[3]),legacy_reader=lambda:None)
    observed = contact_prospective_from_wire_v1(raw['observation'],ContactProspectiveObservationV1)
    from ..authority_service.v2_contract import from_wire,canonical_digest as authority_digest
    if (attempt is None or attempt[:2] != (raw['birth_request_digest'],observed.attempt_id)
            or attempt[2:4] != (raw['terms']['graph_revision'],raw['terms']['graph_epoch'])
            or attempt[4] is None or authority_digest(from_wire(json.loads(attempt[4]))).removeprefix('sha256:') != observed.permit_digest
            or attempt[5] is None or json.loads(attempt[5])['receipt'] != raw['receipt']):
        raise ValueError('Contact prospective birth has no matching actual original WRITE attempt/COMMIT')
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    domain = read_adopted_domain_operation_v1(db,namespace,row[3])
    if (domain is None or domain['operation_kind'] != 'prepare_contact_prospective_v1'
            or domain['payload']['request'] != {'contact_id':raw['contact_id']}
            or domain['payload']['identity']['operation_id'] != raw['birth_operation_id']
            or domain['payload']['authority']['actor'] != observed.owner_actor
            or domain['payload']['provenance']['prospective'] != {name:value for name,value in raw.items()if name!='receipt'}
            or _receipt_wire(domain['receipt']) != raw['receipt']):
        raise ValueError('Contact prospective birth receipt has no exact adopted domain original')
    quote = issuer._d02.original_signed_quote(db,raw['quote']['id'],raw['quote']['version'])
    saved_quote = raw['quote']
    if (canonical_digest(quote) != saved_quote['digest']
            or (quote.bot_id,quote.persona_id,quote.operation_id,quote.effect_id,quote.parent_budget_lease_ref) !=
                (*namespace.as_tuple,raw['final_operation_id'],raw['effect_id'],saved_quote['lease_ref'])
            or dict(quote.ceiling) != raw['reservation']['ceiling']
            or raw['deadline_utc'] != quote.deadline_utc or raw['deadline_utc'] > quote.valid_until_utc):
        raise ValueError('Contact prospective actual original signed quote/ceiling/deadline differs')
    reservation = contact_original_point_v3(db,table='runtime_budget_reservations',
        columns=('digest','ceiling_json','state'),key_columns=('lease_id','operation_id'),
        key=(saved_quote['lease_ref'],raw['final_operation_id']),legacy_reader=lambda:None)
    if (reservation is None or reservation[0] != raw['reservation']['digest']
            or json.loads(reservation[1]) != raw['reservation']['ceiling']):
        raise ValueError('Contact prospective lost its actual once reserved original obligation')
    return original

from contextlib import contextmanager
from dataclasses import asdict
from .d01_production_operations_v1 import CurrentDomainReadV1

_CALLS = {}
_READS = {}

@dataclass(frozen=True,slots=True)
class _ContactProspectiveCallV1:
    runtime:object
    work:object
    request:PrepareCurrentContactProspectiveRequestV1
    operation_id:str
    request_digest:str
    scope:object
    owner:object
    observation:object
    terms:dict
    clock_reading:object


def capture_contact_prospective_call_v1(runtime,*,request,operation_id,request_digest,scope,owner):
    from .domain_background_read_v3 import _active_v3,require_actual_background_attachment_owner_v3
    from .contact_domain_source_v3 import require_contact_domain_work_v3,require_contact_domain_fresh_write_v3
    from .contact_plan_adoption_v2 import read_adopted_contact_plan_v2
    from .contact_reviewed_content_v2 import read_contact_reviewed_content_original_v2
    from .contact_background_inputs_v1 import read_contact_background_inputs_v1
    from ..authority_service.contact_prospective_contract_v1 import ContactProspectiveSelectorV1
    from ..host.contact_prospective_port_v1 import install_contact_prospective_port_v1
    from ..graph_types import AtomKey
    from ..runtime_storage_v3 import runtime_storage_quantum_v3
    from .first_ingress_v2 import trusted_upper
    from .contact_final_stage_v3 import PrepareCurrentContactDispatchRequestV3
    graph,store = runtime.graph,runtime.graph._GraphCoordinator__store
    parent = _active_v3(store._db)
    if parent is None:
        raise ValueError('Contact prospective requires its actual Joint-selected retained Source child Work')
    require_actual_background_attachment_owner_v3(parent,db=store._db)
    work = require_contact_domain_work_v3(parent.contact_active_component,db=store._db)
    if (type(request) is not PrepareCurrentContactProspectiveRequestV1 or work.selector.phase != 'contact_prospective'
            or parent.kind != 'followup_child' or not parent.sealed or not work.complete
            or request.contact_id != work.selector.contact_id or store._db.in_transaction
            or store._lock._is_owned() or runtime is not graph._GraphCoordinator__domain_production_runtime_v1
            or getattr(runtime,'_active_contact_prospective_call_v1',None) is not None):
        raise ValueError('Contact prospective cannot borrow another command/phase/Source operation')
    clock_reading=work.service.port.read_ingress_clock(work.service.bundle.ingress_clock)
    now = trusted_upper(clock_reading)
    with store._lock,runtime_storage_quantum_v3(store._db):
        store._db.execute('BEGIN')
        try:
            binding = require_contact_domain_fresh_write_v3(work,store._db)
            if binding.scope is not scope or binding.owner is not owner or binding.command.operation_kind != 'prepare_contact_prospective_v1':
                raise ValueError('Contact prospective original Source READ has no exact separate current WRITE')
            plan,_,raw,_ = read_adopted_contact_plan_v2(store._db,namespace=scope.namespace,
                contact_id=request.contact_id,issuer=work.service.issuer)
            content = read_contact_reviewed_content_original_v2(store._db,namespace=scope.namespace,
                contact_id=request.contact_id,issuer=work.service.issuer,resource_issuer=work.service.resource_issuer)
            first = content.segments[0]
            expected = contact_prospective_command_digest_v1(scope.namespace,owner.actor,request,operation_id,
                plan.activity_id,plan.audience_id,plan.parent_budget_lease_id)
            final_digest = canonical_digest(('sylanne.domain-production-command.v1',scope.namespace,owner.actor,
                'prepare_contact_dispatch_v3',PrepareCurrentContactDispatchRequestV3(request.contact_id),
                first.operation_id,plan.activity_id,plan.audience_id,plan.parent_budget_lease_id))
            if expected != request_digest or operation_id == first.operation_id:
                raise ValueError('Contact prospective birth cannot reuse its future final operation')
            preparation,joint_cause=read_joint_contact_prospective_cause_v1(store._db,namespace=scope.namespace,
                dedupe_key=work.selector.causal_dedupe,contact_id=request.contact_id,issuer=work.service.issuer)
            terms,_,_,_ = read_contact_background_inputs_v1(store._db,namespace=scope.namespace,contact_id=request.contact_id,
                operation_id=first.operation_id,request_digest=final_digest,dedupe_key=preparation.request.qualified_contact_dedupe_key,
                issuer=work.service.issuer,now=now,owner_actor=owner.actor)
            selector = ContactProspectiveSelectorV1(scope.namespace,request.contact_id,operation_id,request_digest,
                first.operation_id,first.segment.effect_id,AtomKey.from_token(raw['policy_ref']).name,work.selector.causal_dedupe)
        finally:
            store._db.rollback()
    observation,_ = install_contact_prospective_port_v1(work.service.port,work.service.bundle).capture(scope.permit,selector)
    if ((observation.joint_preparation_ref,observation.joint_preparation_digest,
            observation.joint_preparation_operation_id,observation.joint_preparation_receipt_digest)!=
            (joint_cause['ref'],joint_cause['digest'],joint_cause['operation_id'],joint_cause['receipt_digest'])
            or observation.inputs_json != canonical_serialize(terms) or observation.observed_operation_id != operation_id
            or observation.observed_request_digest != request_digest or observation.owner_actor != owner.actor
            or observation.owner_head_digest != owner.authorization_head or observation.owner_revision != owner.authorization_revision
            or not now < observation.deadline_utc):
        raise ValueError('Contact prospective actual independent Core and Graph original/current inputs differ')
    call = _ContactProspectiveCallV1(runtime,work,request,operation_id,request_digest,scope,owner,observation,terms,clock_reading)
    _CALLS[id(call)] = call
    runtime._active_contact_prospective_call_v1 = call
    return call


def require_contact_prospective_call_v1(call,db=None):
    if (type(call) is not _ContactProspectiveCallV1 or _CALLS.get(id(call)) is not call
            or getattr(call.runtime,'_active_contact_prospective_call_v1',None) is not call):
        raise ValueError('Contact prospective has no active actual independently observed WRITE invocation')
    call.runtime._current()
    if db is not None:
        from .contact_domain_source_v3 import require_contact_domain_fresh_write_v3
        binding = require_contact_domain_fresh_write_v3(call.work,db)
        if binding.scope is not call.scope or binding.owner is not call.owner:
            raise ValueError('Contact prospective Source changed its current WRITE Owner/permit')
    return call


def revoke_contact_prospective_call_v1(runtime):
    call = getattr(runtime,'_active_contact_prospective_call_v1',None)
    if call is not None:
        _CALLS.pop(id(call),None)
    runtime._active_contact_prospective_call_v1 = None
    for key,issued in tuple(_PROSPECTIVE_STAGES.items()):
        if issued[1].runtime is runtime:_PROSPECTIVE_STAGES.pop(key,None)


class _CurrentContactProspectiveReadV1(CurrentDomainReadV1):
    def __init__(self,call,frame,db):
        require_contact_prospective_call_v1(call,db)
        super().__init__(frame)
        self.call,self.db,self.phase = call,db,'prospective_birth'
    def check(self,db):
        require_contact_prospective_read_v1(self,db)
        return super().check(db)
    def source_family(self,db,roots,*,purpose=None,audience=None,allow_corrected=False):
        require_contact_prospective_read_v1(self,db)
        actual_purpose = purpose or self.frame.envelope.authority.purpose
        result = super().source_family(db,roots,purpose=actual_purpose,audience=audience,allow_corrected=allow_corrected)
        for ref in result:
            if actual_purpose not in self.call.work.source_material.purposes.get(ref,()):
                raise ValueError('Contact prospective Source family lacks its actual separately qualified purpose')
        return result


def require_contact_prospective_read_v1(read,db):
    if type(read) is not _CurrentContactProspectiveReadV1 or _READS.get(id(read)) is not read or read.db is not db:
        raise ValueError('Contact prospective facts require the actual private current birth reader')
    call = require_contact_prospective_call_v1(read.call,db)
    if (read.frame.envelope.identity.operation_id != call.operation_id or read.frame.envelope.authority.namespace != call.scope.namespace
            or read.frame.snapshot.epochs != (call.scope.graph_epoch,) or not db.in_transaction
            or not call.runtime.graph._GraphCoordinator__store._lock._is_owned()):
        raise ValueError('Contact prospective reader changed its actual birth frame/SQL/epoch')
    return read


@contextmanager
def contact_prospective_read_v1(call,frame,db):
    read = _CurrentContactProspectiveReadV1(call,frame,db)
    _READS[id(read)] = read
    try:
        read.check(db)
        yield read
    finally:
        _READS.pop(id(read),None)


def read_contact_prospective_social_facts_v1(db,read,content,route,context,now):
    require_contact_prospective_read_v1(read,db)
    from .dispatch_current_projection import CurrentDispatchProjectionV1,_derive_verified_current_domain_reads_v1
    from ..domains.d03.context import RoleBindingRequest
    roles = tuple(atom for atom in read.complete_inventory(db,'d03.role_binding') if atom.valid)
    boundaries = tuple(atom for atom in read.complete_inventory(db,'d05.boundary_rule') if atom.valid)
    material = {'namespace':content.namespace,'graph_epoch':read.call.scope.graph_epoch.revision,
        'role_bindings':roles,'boundary_rules':boundaries}
    projection = CurrentDispatchProjectionV1(content.namespace,material['graph_epoch'],roles,boundaries,
        canonical_digest(material))
    request = RoleBindingRequest('persona:'+content.namespace.persona_id,route.target_entity_ref,None,
        content.scene_id,'message','expression',now,True)
    role,boundary = _derive_verified_current_domain_reads_v1(db,projection,request,context)
    if role.status != 'complete' or boundary.coverage != 'full':
        raise ValueError('Contact prospective actual role or boundary birth facts are incomplete')
    return projection,role,boundary


def read_contact_prospective_conflict_facts_v1(db,read,*,target_ref,action_id,effect_id):
    require_contact_prospective_read_v1(read,db)
    from ..domains.d08.execution import GoalExecutionProvider
    from ..authority_service.v2_contract import canonical_digest as authority_digest
    call,scope = read.call,read.call.scope
    effect,snapshot = call.observation.current_effect,call.observation.effect_snapshot
    if (snapshot.anchor != scope.pinned_anchor or snapshot.permit_digest != authority_digest(scope.permit)
            or snapshot.coverage != 'complete' or snapshot.unresolved_effects or effect.state != 'absent'
            or effect.effect_id != effect_id or effect.authority_id != scope.pinned_anchor.authority_id
            or effect.namespace != scope.authority_namespace or effect.execution_head_seq != scope.pinned_anchor.execution_seq
            or effect.execution_head_digest != scope.pinned_anchor.execution_digest):
        raise ValueError('Contact prospective future effect has no exact clear current Core inventory')
    specs = {spec.name:spec for spec in GoalExecutionProvider().register_types()}
    atoms = tuple(atom for kind in ('d08.commitment.v1','d08.action_intent.v1','d08.action_outcome.v1')
        for atom in read.complete_inventory(db,kind) if atom.valid)
    decoded = [(atom,specs[atom.key.type_name].validator(atom.value)) for atom in atoms]
    commitments = [value for atom,value in decoded if atom.key.type_name=='d08.commitment.v1']
    actions = [value for atom,value in decoded if atom.key.type_name=='d08.action_intent.v1']
    outcomes = [value for atom,value in decoded if atom.key.type_name=='d08.action_outcome.v1']
    if any(value.counterparty_ref==target_ref and value.fulfillment_state not in {'fulfilled','withdrawn'} for value in commitments):
        raise ValueError('Contact prospective has an actual unfinished same-target commitment')
    for action in actions:
        if action.action_id==action_id or action.identity.effect_id==effect_id:
            raise ValueError('Contact prospective cannot retrofit an existing Action or future effect')
        if action.target_ref==target_ref:
            completed = [outcome for outcome in outcomes if (outcome.action_id,outcome.effect_id,outcome.attempt_id)==
                (action.action_id,action.identity.effect_id,action.identity.attempt_id)
                and outcome.result_level=='completed_verified' and not outcome.unknown_effects]
            if len(completed)!=1:
                raise ValueError('Contact prospective has an actual unfinished same-target Action')
    return {'schema':'d08.contact-prospective-conflict-facts.v1','query_epoch':scope.graph_epoch.revision,
        'scanned_versions':[[atom.key.token,atom.revision] for atom in atoms],
        'execution_head_seq':scope.pinned_anchor.execution_seq,'execution_head_digest':scope.pinned_anchor.execution_digest,
        'effect_digest':authority_digest(effect),'effect_snapshot_digest':authority_digest(snapshot),
        'future_action_id':action_id,'future_effect_id':effect_id,'target_ref':target_ref}


def read_joint_contact_prospective_cause_v1(db,*,namespace,dedupe_key,contact_id,issuer):
    from .joint_contact_preparation_v1 import read_current_joint_contact_preparation_v1,EVENT,KIND
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    event=contact_original_point_v3(db,table='graph_domain_production_outbox_v1',
        columns=('causal_operation_id','event_kind','original_ref','original_digest','state'),
        key_columns=('bot','persona','dedupe_key'),key=(*namespace.as_tuple,dedupe_key),legacy_reader=lambda:None)
    if event is None or event[1]!=EVENT or event[4] not in {'pending','waiting','completed'}:
        raise ValueError('Contact prospective requires its actual registered Joint preparation outbox')
    preparation=read_current_joint_contact_preparation_v1(db,namespace=namespace,original_ref=event[2],issuer=issuer)
    original=read_adopted_domain_operation_v1(db,namespace,event[0])
    if (preparation.request.contact_id!=contact_id or preparation.namespace!=namespace
            or preparation.producer_operation_id!=event[0] or preparation.digest!=event[3]
            or original is None or original['operation_kind']!='input:register_joint_contact_preparation_v1'
            or original['receipt'].operation_id!=event[0] or original['receipt'].status!='committed'):
        raise ValueError('Contact Joint intent differs from actual signed input/same-CAS receipt')
    return preparation,{'ref':preparation.original_ref,'digest':preparation.digest,'operation_id':event[0],
        'receipt_digest':canonical_digest(original['receipt']),'dedupe_key':dedupe_key}


def derive_contact_prospective_facts_v1(db,read,*,content,plan,route,quote,grant,future_envelope):
    """Six birth facts; this never issues final-job or dispatch qualification."""
    require_contact_prospective_read_v1(read,db)
    from .contact_domain_source_v3 import require_contact_domain_fresh_write_v3
    from ..domains.d01.production_operations_v1 import plain_v1
    from ..domains.d03.context import ContextProvider
    from ..domains.d05.prebatch_boundary import issue_prebatch_boundary_check_v1
    from ..domains.d06.source_grant import SourceGrantRead,provide_source_grant_check
    from ..domains.d10 import LifeDomain,ContactClaim,decode_contact_policy,decode_proactive_opportunity
    from ..domains.d10.contact_claim_v2 import decode_contact_claim_v2,contact_claim_key_v2
    from ..domains.d08.dispatch_check import D08_CRITERIA_REF_V1,D08_CRITERIA_VERSION_V1
    from ..runtime_contracts import VersionedRef,GraphVersion,canonical_serialize
    from ..graph_types import AtomKey
    from ..memory_types import access_key
    from .contact_final_action_v1 import ContactCheckVersionSetV1,CurrentContactCheckVersionsV1,contact_final_action_ids_v1
    from .contact_final_action_v3 import prepare_contact_action_stage_v3,CONTACT_REQUIRED_PROVIDERS_V1
    from .contact_route_binding_v1 import contact_route_semantic_digest_v1
    from .budget import get_budget_lease,require_budget_family_admissible
    from .dispatch_budget_check import _observed_versions
    call,frame=read.call,read.frame
    runtime,ns=call.runtime,call.scope.namespace
    now,deadline=frame.now_utc,quote.deadline_utc
    binding=require_contact_domain_fresh_write_v3(call.work,db)
    issuer=runtime.graph._GraphCoordinator__d11_issuer
    current_policy=binding.policy
    if (now>=deadline or deadline>min(call.observation.deadline_utc,content.valid_until,grant.valid_until_utc)
            or current_policy.original.digest!=call.observation.policy_original_digest
            or current_policy.original.original_ref!=plan.policy_original_ref
            or (quote.operation_id,quote.effect_id,quote.parent_budget_lease_ref)!=(
                call.terms['operation_id'],call.terms['first_effect_id'],call.terms['budget_lease_ref'])
            or canonical_digest(grant)!=call.terms['grant_digest']
            or contact_route_semantic_digest_v1(route)!=content.route_semantic_digest):
        raise ValueError('Contact prospective actual Owner/policy/paid content/quote/root binding changed')
    registration=runtime.graph._GraphCoordinator__providers.get('d03')
    if (type(registration)is not tuple or len(registration)!=3 or type(registration[0])is not ContextProvider
            or registration[1]!='d03.proposal.v1' or registration[2]!=registration[0].descriptor.request_schema_hash):
        raise ValueError('Contact prospective requires its actual installed D03 catalogue provider')
    context=registration[0]
    projection,role,boundary=read_contact_prospective_social_facts_v1(db,read,content,route,context,now)
    roots=future_envelope.source_qualification.source_refs
    expression=read.source_family(db,roots,purpose='expression',audience=content.audience_id)
    context_refs=tuple(ref for ref,purposes in call.work.source_selection.purpose_groups if 'context' in purposes)
    if context_refs:read.source_family(db,context_refs,purpose='context',audience=content.audience_id)
    structural={ref for atom in (*projection.role_bindings,*projection.boundary_rules) for ref in atom.value['source_refs']}
    if not structural<=set(expression)|set(context_refs):
        raise ValueError('Contact prospective new structural Source escapes its signed per-purpose selection')
    read.source_family(db,(route.source_ref,),purpose='context',audience=content.audience_id)
    criterion=read.head(db,AtomKey.from_token(plan.source_ref.ref),required=True)
    criteria=VersionedRef(criterion.key.token,criterion.revision)
    source_versions=[]
    for ref in sorted(expression):
        key=AtomKey.from_token(ref)
        for dependency in (key,access_key(*ns.as_tuple,key.owner.subject)):
            atom=read.head(db,dependency,required=True);source_versions.append(VersionedRef(dependency.token,atom.revision))
    if criteria not in source_versions:source_versions.append(criteria)
    policies=tuple(atom for atom in read.complete_inventory(db,'d10.contact_policy.v1')
        if atom.valid and atom.value['approval_ref']==plan.policy_original_ref)
    if len(policies)!=1:raise ValueError('Contact prospective current adopted standing policy is not unique')
    policy_atom=policies[0];policy=decode_contact_policy(policy_atom.value,ns)
    opportunity_atom=read.head(db,AtomKey.from_token(plan.opportunity_ref.ref),required=True)
    opportunity=decode_proactive_opportunity(opportunity_atom.value,ns)
    if policy!=current_policy.original.policy:
        raise ValueError('Contact prospective adopted policy differs from actual independently current Core policy')
    claims=[];claim_versions=[]
    for kind in ('d10.contact_claim.v1','d10.contact_claim.v2'):
        for atom in read.complete_inventory(db,kind):
            if not atom.valid:continue
            raw=atom.value
            if kind=='d10.contact_claim.v2':claim=decode_contact_claim_v2(raw)
            else:
                validator=next(spec.validator for spec in LifeDomain.type_specs() if spec.name==kind)
                validator(raw)
                claim=ContactClaim(**{**raw,'segment_effects':tuple(raw['segment_effects']),
                    'observations':tuple(tuple(pair) for pair in raw['observations'])})
            claims.append(claim)
            if (claim.subject_ref,claim.channel,claim.category)==(opportunity.subject_ref,opportunity.channel,opportunity.category):
                claim_versions.append(VersionedRef(claim.contact_id,atom.revision))
    own=read.head(db,contact_claim_key_v2(ns,content.contact_id))
    if own.revision!=0 or own.valid or any(claim.contact_id==content.contact_id for claim in claims):
        raise ValueError('Contact prospective cannot retrofit an already consumed whole Contact quota')
    native_policy=LifeDomain.contact_policy_check(policy,opportunity,tuple(claims),now=now)
    if native_policy.result!='pass' or native_policy.reasons or native_policy.dispatch_authorized is not False:
        raise ValueError('Contact prospective actual unconsumed quota/window/consent does not pass')
    if deadline>native_policy.valid_until:raise ValueError('Contact prospective original quote exceeds the native policy/opportunity deadline')
    budget=get_budget_lease(db,grant.lease_id);require_budget_family_admissible(db,grant.lease_id)
    reserve=db.execute('SELECT digest,ceiling_json,state FROM runtime_budget_reservations WHERE lease_id=? AND operation_id=?',
        (grant.lease_id,quote.operation_id)).fetchone()
    if (reserve is None or reserve[2]!='reserved' or json.loads(reserve[1])!=dict(quote.ceiling)
            or (budget.bot_id,budget.persona_id,budget.state)!=(*ns.as_tuple,'active')):
        raise ValueError('Contact prospective D11 fact lacks its actual once reserved future obligation/current active parent')
    budget_versions=(VersionedRef('d02.resource_quote:'+quote.quote_id,quote.version),
        *_observed_versions(db,budget,quote.operation_id,reserve[0]),VersionedRef('d11.budget.grant:'+grant.lease_id,grant.version))
    ids=contact_final_action_ids_v1(content.contact_id,0);epoch=call.scope.graph_epoch.revision
    conflict=read_contact_prospective_conflict_facts_v1(db,read,target_ref=route.target_entity_ref,
        action_id=ids['action'],effect_id=quote.effect_id)
    sets=(
        ContactCheckVersionSetV1('role_binding',criteria.ref,(criteria,VersionedRef('d03.role_binding',epoch),
            *sorted((VersionedRef(v.key.name,v.revision) for v in role.read_versions if v.key.name in role.matched_bindings),key=lambda v:v.ref))),
        ContactCheckVersionSetV1('boundary',criteria.ref,(criteria,VersionedRef('d05.boundary',epoch),
            *(VersionedRef(rule.rule_id,rule.scope_version)for rule in boundary.rules))),
        ContactCheckVersionSetV1('source_grant',criteria.ref,tuple(source_versions)),
        ContactCheckVersionSetV1('commitment_conflict',D08_CRITERIA_REF_V1,(VersionedRef(D08_CRITERIA_REF_V1,D08_CRITERIA_VERSION_V1),
            VersionedRef('commitments-query:persona:'+ns.persona_id,epoch),
            VersionedRef('execution-epoch:'+ids['action'],call.scope.pinned_anchor.execution_seq))),
        ContactCheckVersionSetV1('dispatch_budget',budget_versions[0].ref,budget_versions),
        ContactCheckVersionSetV1('contact_policy',criteria.ref,(criteria,VersionedRef(policy.policy_id,policy_atom.revision),
            VersionedRef(opportunity.opportunity_id,opportunity_atom.revision),
            VersionedRef('d10.contact_policy:'+opportunity.subject_ref+':'+opportunity.channel+':'+opportunity.category,epoch),
            *sorted(claim_versions,key=lambda v:v.ref))))
    versions=CurrentContactCheckVersionsV1(ns,epoch+1,frame.snapshot.versions,sets,quote.quote_id,quote.version,
        grant.grant_id,grant.version,reserve[0],current_policy.original.original_ref,current_policy.original.digest)
    action=prepare_contact_action_stage_v3(envelope=future_envelope,content=content,index=0,current_checks=versions,
        route=route,quote=quote,grant=grant,now_utc=now)
    role_check=context.provide_required_check(action.intent,role,valid_until=deadline)
    boundary_check=issue_prebatch_boundary_check_v1(action.intent,action.schema,boundary,
        audience_scope=content.audience_id,scene_ref=content.scene_id,now_utc=now,valid_until_utc=deadline)
    source_check=provide_source_grant_check(action.intent,SourceGrantRead(frame.snapshot,(content.audience_id,),
        'expression',True,True),valid_until=deadline)
    if (role_check.result,role_check.coverage)!=('pass','full') or boundary_check.status!='check_pass' or (
            source_check.result,source_check.coverage)!=('pass','full'):
        raise ValueError('Contact prospective actual D03/D05/D06 birth facts did not pass')
    future_job=read.head(db,AtomKey.from_token(quote.graph_job_ref))
    future_outboxes=tuple(read.head(db,AtomKey.from_token(ref))for ref in quote.outbox_refs)
    if future_job.revision!=0 or future_job.valid or any(row.revision!=0 or row.valid for row in future_outboxes):
        raise ValueError('Contact prospective cannot retrofit an existing final job/outbox')
    budget_fact={'schema':'d11.contact-prospective-budget-fact.v1','namespace':plain_v1(ns),
        'future_operation_id':quote.operation_id,'effect_id':quote.effect_id,'grant':plain_v1(grant),
        'quote_digest':canonical_digest(quote),'reservation_digest':reserve[0],'ceiling':dict(quote.ceiling),
        'reservation_state':reserve[2],'budget':plain_v1(budget),'deadline_utc':deadline,
        'future_job_absence':[future_job.key.token,future_job.revision,future_job.valid],
        'future_outbox_absences':[[row.key.token,row.revision,row.valid]for row in future_outboxes],
        'dispatch_authorized':False}
    facts=[]
    evidences=(role_check,boundary_check.receipt,source_check,conflict,budget_fact,
        {'schema':'d10.contact-prospective-policy-fact.v1','policy':plain_v1(policy),'opportunity':plain_v1(opportunity),
         'claims':plain_v1(tuple(claims)),'check':plain_v1(native_policy),'owner_original_digest':current_policy.original.digest})
    for (kind,provider),version_set,evidence in zip(CONTACT_REQUIRED_PROVIDERS_V1,sets,evidences):
        facts.append({'kind':kind,'provider':provider,'input_versions':plain_v1(version_set.versions),
            'evidence':plain_v1(evidence),'evidence_digest':canonical_digest(plain_v1(evidence)),'valid_until_utc':deadline})
    raw={'schema':'d10.contact-prospective-facts.v1','namespace':plain_v1(ns),
        'graph_revision':call.terms['graph_revision'],'graph_epoch':epoch,'future_operation_id':quote.operation_id,
        'effect_id':quote.effect_id,'quote_digest':canonical_digest(quote),'reservation_digest':reserve[0],
        'owner_policy_digest':current_policy.original.digest,
        'source_closure_digest':canonical_digest((call.work.source_selection.purpose_groups,material_versions_v1(call.work))),
        'facts':facts}
    raw['digest']=canonical_digest(raw)
    return action,versions,raw


def material_versions_v1(work):
    return tuple((ref,work.source_material.witnesses[ref].revision,tuple(sorted(work.source_material.purposes[ref])))
        for ref in sorted(work.source_material.metadata_records))


BARRIER_TYPE='d08.contact_prospective_barrier.v1'
_PROSPECTIVE_STAGES={}


def contact_prospective_original_ref_v1(namespace,contact_id,birth_operation_id):
    return 'contact-prospective-original:'+canonical_digest((namespace,contact_id,birth_operation_id))


def contact_prospective_barrier_key_v1(namespace,activity_id,contact_id):
    from ..graph_types import Owner,AtomKey
    return AtomKey(Owner('activity',*namespace.as_tuple,activity_id),BARRIER_TYPE,contact_id)


def validate_contact_prospective_barrier_v1(raw):
    expected={'schema','namespace','contact_id','birth_operation_id','birth_request_digest','final_operation_id',
        'effect_id','precommit_digest','original_ref','joint_preparation','old_contact_dedupe','deadline_utc'}
    if type(raw)is not dict or set(raw)!=expected or raw['schema']!=BARRIER_TYPE:
        raise ValueError('Contact prospective barrier closed schema differs')
    ns=NamespaceId(**raw['namespace'])
    if (raw['original_ref']!=contact_prospective_original_ref_v1(ns,raw['contact_id'],raw['birth_operation_id'])
            or raw['birth_operation_id']==raw['final_operation_id']
            or raw['joint_preparation']['dedupe_key']==raw['old_contact_dedupe']):
        raise ValueError('Contact prospective barrier future identity or its two causes differ')
    for name in ('birth_request_digest','precommit_digest'):
        if type(raw[name])is not str or len(raw[name])!=64:raise ValueError('Contact prospective barrier commitment differs')
    return raw


def stage_prepare_contact_prospective_in_transaction_v1(db,*,frame,request,installed_readers):
    from dataclasses import replace
    from ..runtime_contracts import OperationIdentity,VersionedRef
    from ..graph_types import GraphWrite
    from ..domains.d01.production_operations_v1 import stage_result_v1,plain_v1
    from ..domains.d08.execution import GoalExecutionProvider
    from .contact_domain_source_v3 import require_contact_domain_fresh_write_v3
    from .contact_plan_adoption_v2 import read_adopted_contact_plan_v2
    from .contact_reviewed_content_v2 import read_contact_reviewed_content_original_v2
    from .contact_route_binding_v1 import read_current_contact_route_binding_v1
    from .contact_final_stage_v3 import contact_final_runtime_ids_v3,_contact_expression_frame_v3
    from .budget import reserve_budget
    from ..graph_coordinator import budget_operation_digest
    from .first_ingress_v2 import trusted_upper
    graph=installed_readers.role_clock_reader.graph
    runtime=graph._GraphCoordinator__domain_production_runtime_v1
    call=require_contact_prospective_call_v1(runtime._active_contact_prospective_call_v1,db)
    if (type(request)is not PrepareCurrentContactProspectiveRequestV1 or request!=call.request
            or frame.envelope.identity.operation_id!=call.operation_id
            or frame.envelope.authority.actor!=call.owner.actor):
        raise ValueError('Contact prospective birth stage changed its actual independently observed command')
    binding=require_contact_domain_fresh_write_v3(call.work,db)
    issuer=graph._GraphCoordinator__d11_issuer
    assembly=graph._GraphCoordinator__d04_installed_joint_assembly
    if assembly is None or assembly.admin_bundle.private_reply_dispatch is None or assembly.admin_bundle.contact_effect_accounting is None:
        raise ValueError('Contact prospective requires its actual installed message pricing policies')
    pricing=assembly.admin_bundle.private_reply_dispatch
    if set(dict(assembly.admin_bundle.contact_effect_accounting.unit_cost))!=set(pricing.quote_ceiling):
        raise ValueError('Contact prospective requires all original effect-price dimensions before reservation')
    plan,_,_,_=read_adopted_contact_plan_v2(db,namespace=call.scope.namespace,contact_id=request.contact_id,issuer=issuer)
    content=read_contact_reviewed_content_original_v2(db,namespace=call.scope.namespace,contact_id=request.contact_id,
        issuer=issuer,resource_issuer=issuer._d02)
    preparation,joint_cause=read_joint_contact_prospective_cause_v1(db,namespace=call.scope.namespace,
        dedupe_key=call.observation.selector.causal_dedupe_key,contact_id=request.contact_id,issuer=issuer)
    if (preparation.contact_plan_original_digest!=call.terms['plan_original_digest']
            or preparation.reviewed_content_digest!=content.digest or preparation.parent_grant_digest!=call.terms['grant_digest']
            or preparation.request.qualified_contact_dedupe_key!=call.terms['dedupe_key']
            or preparation.source_purpose_groups!=tuple(call.work.source_selection.purpose_groups)
            or preparation.owner_acl_actor!=call.owner.actor):
        raise ValueError('Contact prospective cannot change its actual Owner preparation paid/Source/parent tuple')
    frame=_contact_expression_frame_v3(frame,content)
    barrier_key=contact_prospective_barrier_key_v1(call.scope.namespace,plan.activity_id,plan.contact_id)
    with contact_prospective_read_v1(call,frame,db)as read:
        old=read.head(db,barrier_key)
        if old.revision!=0 or old.valid:raise ValueError('Contact prospective birth barrier already exists')
        actual_birth=contact_original_point_v3(db,table=TABLE,columns=COLUMNS,
            key_columns=('bot','persona','contact_id'),key=(*call.scope.namespace.as_tuple,request.contact_id),legacy_reader=lambda:None)
        if actual_birth is not None:raise ValueError('Contact prospective immutable birth already exists')
        route=read_current_contact_route_binding_v1(db,read,account_ref=plan.route_account_ref.ref,
            target_entity_ref=plan.target_entity_ref,audience=content.audience_id)
        grant=issuer.current_budget_grant(db,plan.parent_budget_lease_id)
        if grant!=assembly.installation_policy.root_grant or any(len(item.segment.body)>pricing.segment_max_chars for item in content.segments):
            raise ValueError('Contact prospective paid payload or parent differs from actual installed price scope')
        deadline=min(frame.envelope.deadline_utc,call.observation.deadline_utc,content.valid_until,
            preparation.absolute_deadline_utc,frame.now_utc+pricing.deadline_after_seconds,grant.valid_until_utc)
        upper=trusted_upper(call.clock_reading)
        if upper>=deadline:raise ValueError('Contact prospective original finite deadline expired')
        first=content.segments[0]
        job_key,outbox_key=contact_final_runtime_ids_v3(call.scope.namespace,content.contact_id,content.activity_id)
        future_inputs=tuple(sorted(set(call.work.source_selection.roots+(plan.source_ref.ref,
            joint_cause['ref'],contact_prospective_original_ref_v1(call.scope.namespace,request.contact_id,call.operation_id)))))
        identity=OperationIdentity(content.activity_id,first.segment.effect_id,first.operation_id,
            'prepare_contact_dispatch_v3',first.operation_id,canonical_digest({'input_refs':list(future_inputs)}))
        future=replace(frame.envelope,identity=identity,input_refs=future_inputs,deadline_utc=deadline,
            monotonic_deadline=min(frame.envelope.monotonic_deadline,__import__('time').monotonic()+deadline-upper))
        quote=issuer.issue_private_reply_dispatch_quote_v2(db,policy=pricing,namespace=call.scope.namespace,
            identity=identity,parent_grant=grant,deadline_utc=deadline,graph_job_ref=job_key.token,
            outbox_refs=(outbox_key.token,),now_utc=frame.now_utc)
        future=replace(future,version_guard=replace(future.version_guard,
            resource_lease_versions=(VersionedRef(quote.quote_id,quote.version),)))
        reserve_digest=budget_operation_digest(future,grant.lease_id,dict(quote.ceiling))
        reserve_budget(db,grant.lease_id,first.operation_id,reserve_digest,dict(quote.ceiling))
        action,versions,facts=derive_contact_prospective_facts_v1(db,read,content=content,plan=plan,route=route,
            quote=quote,grant=grant,future_envelope=future)
    candidate={'goal':plain_v1(action.goal),'action':plain_v1(action.intent),'schema':plain_v1(action.schema)}
    candidate['digest']=canonical_digest(candidate)
    from ..authority_service.contact_prospective_contract_v1 import contact_prospective_to_wire_v1
    prepared={'schema':SIGN_KIND,'namespace':plain_v1(call.scope.namespace),'contact_id':request.contact_id,
        'birth_operation_id':call.operation_id,'birth_request_digest':call.request_digest,
        'final_operation_id':first.operation_id,'effect_id':first.segment.effect_id,
        'observation':contact_prospective_to_wire_v1(call.observation),'terms':call.terms,'candidate':candidate,
        'prospective_facts':facts,'quote':{'id':quote.quote_id,'version':quote.version,'digest':canonical_digest(quote),
            'operation_id':first.operation_id,'effect_id':first.segment.effect_id,'lease_ref':grant.lease_id},
        'reservation':{'lease_ref':grant.lease_id,'operation_id':first.operation_id,'digest':reserve_digest,'ceiling':dict(quote.ceiling)},
        'deadline_utc':deadline,'refresh_rule':REFRESH_RULE,'joint_preparation':joint_cause}
    precommit_digest=canonical_digest(prepared)
    barrier={'schema':BARRIER_TYPE,'namespace':plain_v1(call.scope.namespace),'contact_id':request.contact_id,
        'birth_operation_id':call.operation_id,'birth_request_digest':call.request_digest,
        'final_operation_id':first.operation_id,'effect_id':first.segment.effect_id,'precommit_digest':precommit_digest,
        'original_ref':contact_prospective_original_ref_v1(call.scope.namespace,request.contact_id,call.operation_id),
        'joint_preparation':joint_cause,'old_contact_dedupe':call.terms['dedupe_key'],'deadline_utc':deadline}
    validate_contact_prospective_barrier_v1(barrier)
    provider=GoalExecutionProvider()
    frame=replace(frame,envelope=replace(frame.envelope,deadline_utc=deadline,
        monotonic_deadline=min(frame.envelope.monotonic_deadline,future.monotonic_deadline),
        version_guard=replace(frame.envelope.version_guard,resource_lease_versions=(VersionedRef(quote.quote_id,quote.version),))))
    stage=stage_result_v1(frame,'d08','prepare_contact_prospective_v1',request,
        writes=(GraphWrite(barrier_key,barrier,dependencies=tuple(version.key for version in frame.snapshot.versions)),),
        provenance={'prospective':prepared,'precommit_digest':precommit_digest},
        proposal_schema='d08.proposal.v1',proposal_hash=provider.descriptor.request_schema_hash)
    _PROSPECTIVE_STAGES[id(stage)]=(stage,call,prepared,barrier_key,barrier,
        {'frame':frame,'content':content,'plan':plan,'route':route,'quote':quote,'grant':grant,'future':future})
    return stage


def record_contact_prospective_after_commit_v1(db,*,graph,stage,receipt):
    from ..runtime_contracts import CommitReceipt,canonical_serialize
    issued=_PROSPECTIVE_STAGES.get(id(stage))
    if issued is None or issued[0]is not stage or type(receipt)is not CommitReceipt or not db.in_transaction:
        raise ValueError('Contact prospective original requires its actual installed prevalidated stage and same-CAS receipt')
    _,call,prepared,barrier_key,barrier,_=issued
    require_contact_prospective_call_v1(call)
    if graph is not call.runtime.graph or not graph._GraphCoordinator__store._lock._is_owned():
        raise ValueError('Contact prospective original crossed its actual Graph writer')
    versions=tuple((version.key.token,version.revision)for version in receipt.write_versions)
    if (receipt.status!='committed' or receipt.operation_id!=call.operation_id
            or versions!=((barrier_key.token,1),) or stage.original_digest!=canonical_digest(json.loads(stage.original_payload_json))):
        raise ValueError('Contact prospective original has no exact committed barrier-only birth receipt')
    original=db.execute('SELECT domain,operation_kind,request_digest,original_digest,bundle_digest,receipt_digest '
        'FROM graph_domain_production_originals_v1 WHERE bot=? AND persona=? AND operation_id=?',
        (*call.scope.namespace.as_tuple,call.operation_id)).fetchone()
    bundle=db.execute('SELECT digest,activity_id,effect_id,commit_seq FROM graph_bundle_operations '
        'WHERE bot=? AND persona=? AND operation_id=?',(*call.scope.namespace.as_tuple,call.operation_id)).fetchone()
    if (original!=('d08','prepare_contact_prospective_v1',stage.request_digest,stage.original_digest,
            receipt.operation_digest,canonical_digest(receipt)) or bundle!=(receipt.operation_digest,
            receipt.activity_id,receipt.effect_id,receipt.commit_seq)):
        raise ValueError('Contact prospective original is not inside its actual adopted domain COMMIT')
    payload={**prepared,'receipt':_receipt_wire(receipt)}
    validate_contact_prospective_original_v1(payload)
    encoded=canonical_serialize(payload);digest=canonical_digest(payload)
    issuer=graph._GraphCoordinator__d11_issuer
    row=(*call.scope.namespace.as_tuple,call.request.contact_id,call.operation_id,encoded,digest,
        issuer._signer.sign(SIGN_KIND,canonical_serialize((call.scope.namespace,call.request.contact_id,call.operation_id,digest))),
        contact_prospective_original_ref_v1(call.scope.namespace,call.request.contact_id,call.operation_id))
    old=db.execute('SELECT '+','.join(COLUMNS)+' FROM '+TABLE+' WHERE bot=? AND persona=? AND contact_id=?',
        row[:3]).fetchone()
    if old is None:db.execute('INSERT INTO '+TABLE+' VALUES(?,?,?,?,?,?,?,?)',row)
    elif old!=row:raise ValueError('Contact prospective immutable birth replay changed its original')
    return ContactProspectiveOriginalV1(encoded)


def read_plan_contact_prospective_v1(db,*,namespace,activity_id,operation_kind,request):
    from .domain_background_read_v3 import require_background_contact_source_component_v3
    from .d01_production_operations_v1 import production_read_plan_v1
    from .contact_final_stage_v3 import _raw_plan,contact_final_runtime_ids_v3
    from .contact_qualification_evidence_v3 import CONTACT_FINAL_QUERY_TYPES_V3
    from ..domains.d08.contact_plan_v2 import contact_plan_keys_v2
    from ..domains.d08.contact_plan_v3 import contact_plan_keys_v3
    from ..domains.d10.contact_claim_v2 import contact_claim_key_v2
    from ..domains.d06 import source_correction_head_key
    from ..memory_types import access_key
    from ..graph_types import owner_grant_key,Owner,AtomKey
    from .contact_final_action_v1 import contact_final_action_ids_v1
    if type(request)is not PrepareCurrentContactProspectiveRequestV1 or operation_kind!='prepare_contact_prospective_v1':
        raise ValueError('Contact prospective read recipe needs its exact typed locator command')
    work=require_background_contact_source_component_v3(db,namespace,request.contact_id,'contact_prospective')
    plan=_raw_plan(db,namespace,request.contact_id)
    if plan.activity_id!=activity_id:raise ValueError('Contact prospective read recipe changed its actual Contact activity')
    preparation,cause=read_joint_contact_prospective_cause_v1(db,namespace=namespace,
        dedupe_key=work.selector.causal_dedupe,contact_id=request.contact_id,issuer=work.service.issuer)
    keys={owner_grant_key(*namespace.as_tuple),*contact_plan_keys_v2(plan),*contact_plan_keys_v3(plan)[1:],
        contact_prospective_barrier_key_v1(namespace,plan.activity_id,request.contact_id),contact_claim_key_v2(namespace,request.contact_id),
        *contact_final_runtime_ids_v3(namespace,request.contact_id,activity_id)}
    keys.update(version.key for version in plan.qualified_read_versions)
    ids=contact_final_action_ids_v1(request.contact_id,0);owner=Owner('activity',*namespace.as_tuple,activity_id)
    keys.update(AtomKey(owner,kind,ids[name])for kind,name in (
        ('d08.goal.v1','goal'),('d08.action_intent.v1','action'),('d08.action_schema.v1','schema'),('d08.action_cancellation.v1','action')))
    for ref in work.source_material.metadata_records:
        key=AtomKey.from_token(ref)
        keys.update((key,access_key(*namespace.as_tuple,key.owner.subject),source_correction_head_key(namespace,key.owner.subject)))
    return production_read_plan_v1(CONTACT_FINAL_QUERY_TYPES_V3,keys,work.source_selection.roots,
        (cause['ref'],plan.cause_original_ref))


def command_identity_contact_prospective_v1(db,*,namespace,request,operation_id,issuer):
    from .contact_final_stage_v3 import _raw_plan
    plan=_raw_plan(db,namespace,request.contact_id)
    if operation_id.startswith('contact-dispatch:'):
        raise ValueError('Contact prospective birth cannot consume its future final operation')
    return plan.activity_id,None,plan.audience_id


def verify_contact_prospective_stage_v1(db,*,frame,request,installed_readers,stage):
    from ..domains.d01.production_operations_v1 import plain_v1
    issued=_PROSPECTIVE_STAGES.get(id(stage))
    if issued is None or issued[0]is not stage or issued[1].request!=request or issued[5]['frame']!=frame:
        raise ValueError('Contact prospective verification requires its actual private once-reserved birth stage')
    _,call,prepared,barrier_key,barrier,inputs=issued
    require_contact_prospective_call_v1(call,db)
    issuer=call.runtime.graph._GraphCoordinator__d11_issuer
    actual_quote=issuer._d02.original_signed_quote(db,inputs['quote'].quote_id,inputs['quote'].version)
    if actual_quote!=inputs['quote'] or issuer.current_budget_grant(db,actual_quote.parent_budget_lease_ref)!=inputs['grant']:
        raise ValueError('Contact prospective original quote/root changed before actual birth CAS')
    with contact_prospective_read_v1(call,frame,db)as read:
        current=read.head(db,barrier_key)
        if current.revision!=0 or current.valid:raise ValueError('Contact prospective barrier appeared before its actual birth CAS')
        action,versions,facts=derive_contact_prospective_facts_v1(db,read,content=inputs['content'],plan=inputs['plan'],
            route=inputs['route'],quote=actual_quote,grant=inputs['grant'],future_envelope=inputs['future'])
    candidate={'goal':plain_v1(action.goal),'action':plain_v1(action.intent),'schema':plain_v1(action.schema)}
    candidate['digest']=canonical_digest(candidate)
    if candidate!=prepared['candidate'] or facts!=prepared['prospective_facts'] or canonical_digest(prepared)!=barrier['precommit_digest']:
        raise ValueError('Contact prospective six original birth facts/candidate changed before CAS')
    return stage


def require_contact_prospective_barrier_write_v1(db,*,graph,write,envelope):
    expected=tuple(value for value in _PROSPECTIVE_STAGES.values()
        if value[1].runtime.graph is graph and value[5]['frame'].envelope==envelope)
    if len(expected)!=1:raise ValueError('Contact prospective barrier has no actual current installed birth writer')
    stage,call,prepared,key,barrier,_=expected[0]
    require_contact_prospective_call_v1(call,db)
    if write.key!=key or write.value!=barrier or canonical_digest(prepared)!=barrier['precommit_digest']:
        raise ValueError('Contact prospective barrier differs from its exact six-fact once-reserved birth')
    return stage


def contact_prospective_stage_frame_v1(stage):
    value=_PROSPECTIVE_STAGES.get(id(stage))
    if value is None or value[0]is not stage:raise ValueError('actual issued Contact prospective stage required')
    return value[5]['frame']


def install_contact_prospective_schema_v1(db):
    if not db.in_transaction:raise ValueError('Contact prospective schema installs in its actual Graph installation transaction')
    from .contact_continuation_v1 import install_contact_segment_schema_v1
    install_contact_segment_schema_v1(db)
    db.execute(DDL.replace('CREATE TABLE ','CREATE TABLE IF NOT EXISTS ',1))
    for trigger in TRIGGERS:db.execute(trigger.replace('CREATE TRIGGER ','CREATE TRIGGER IF NOT EXISTS ',1))
    db.execute(SUCCESSOR_DDL.replace('CREATE TABLE ','CREATE TABLE IF NOT EXISTS ',1))
    for trigger in SUCCESSOR_TRIGGERS:db.execute(trigger.replace('CREATE TRIGGER ','CREATE TRIGGER IF NOT EXISTS ',1))


def read_contact_prospective_original_ref_v1(db,*,namespace,original_ref,issuer):
    from .domain_production_contracts_v1 import ProductionOriginalRefV1
    row=contact_original_point_v3(db,table=TABLE,columns=COLUMNS,key_columns=('bot','persona','original_ref'),
        key=(*namespace.as_tuple,original_ref),legacy_reader=lambda:None)
    # External references bind stable namespace/contact/birth identity, not a
    # caller-selected hash or an unbounded family scan.
    if row is None:return None
    saved=read_contact_prospective_original_v1(db,issuer,namespace,row[2])
    if contact_prospective_original_ref_v1(namespace,row[2],row[3])!=original_ref:
        raise ValueError('Contact prospective original reference differs from actual immutable identity')
    return ProductionOriginalRefV1(SIGN_KIND,original_ref,saved.digest)


def contact_prospective_birth_operation_v1(namespace,preparation_ref):
    return 'contact-prospective-birth:'+canonical_digest((namespace,preparation_ref))[:48]


def resolve_joint_contact_prospective_followup_v1(db,frame,event,*,graph,continuation):
    from .domain_background_read_v3 import require_background_contact_source_component_v3
    from .contact_followup_v1 import ContactFollowupCommandV1
    from .domain_production_followups_v1 import DomainFollowupResolutionV1
    from .contact_plan_adoption_v2 import read_adopted_contact_plan_v2
    from .joint_contact_preparation_v1 import read_current_joint_contact_preparation_v1
    preparation=read_current_joint_contact_preparation_v1(db,namespace=frame.envelope.authority.namespace,
        original_ref=event.trigger_original.original_ref,issuer=graph._GraphCoordinator__d11_issuer)
    require_background_contact_source_component_v3(db,preparation.namespace,preparation.request.contact_id,'contact_prospective')
    current,cause=read_joint_contact_prospective_cause_v1(db,namespace=preparation.namespace,
        dedupe_key=event.dedupe_key,contact_id=preparation.request.contact_id,issuer=graph._GraphCoordinator__d11_issuer)
    if current!=preparation or cause['digest']!=event.trigger_original.original_digest:
        raise ValueError('Contact prospective resolver changed its actual explicit Joint preparation event')
    plan=read_adopted_contact_plan_v2(db,namespace=preparation.namespace,contact_id=preparation.request.contact_id,
        issuer=graph._GraphCoordinator__d11_issuer)[0]
    saved=read_contact_prospective_original_v1(db,graph._GraphCoordinator__d11_issuer,
        preparation.namespace,preparation.request.contact_id)
    if saved is not None:
        raw=json.loads(saved.payload_json)
        if raw['joint_preparation']!=cause:raise ValueError('Contact prospective birth belongs to another explicit Joint preparation')
        return DomainFollowupResolutionV1('waiting_for_original',(),(raw['joint_preparation']['ref'],),
            ('actual_matching_joint_binding_and_current_predecessor_consent',),continuation)
    if frame.now_utc>=preparation.absolute_deadline_utc:
        return DomainFollowupResolutionV1('waiting_for_original',(),(preparation.original_ref,),
            ('original_joint_contact_preparation_expired',),continuation)
    command=ContactFollowupCommandV1('d08','prepare_contact_prospective_v1',
        PrepareCurrentContactProspectiveRequestV1(preparation.request.contact_id),plan.activity_id,plan.audience_id,
        operation_id=contact_prospective_birth_operation_v1(preparation.namespace,preparation.original_ref))
    return DomainFollowupResolutionV1('ready',(command,),(preparation.original_ref,),(),None)


def read_plan_joint_contact_prospective_followup_v1(db,*,namespace,event,issuer):
    from .joint_contact_preparation_v1 import read_current_joint_contact_preparation_v1
    from .d01_production_operations_v1 import production_read_plan_v1
    from .domain_background_read_v3 import require_background_contact_source_component_v3
    from .contact_final_stage_v3 import _raw_plan
    preparation=read_current_joint_contact_preparation_v1(db,namespace=namespace,
        original_ref=event.trigger_original.original_ref,issuer=issuer)
    work=require_background_contact_source_component_v3(db,namespace,preparation.request.contact_id,'contact_prospective')
    plan=_raw_plan(db,namespace,preparation.request.contact_id)
    # The command recipe and receiver recipe use the same actual fixed Source
    # roots and complete Contact inventories under separate operation frames.
    recipe=read_plan_contact_prospective_v1(db,namespace=namespace,activity_id=plan.activity_id,
        operation_kind='prepare_contact_prospective_v1',request=PrepareCurrentContactProspectiveRequestV1(plan.contact_id))
    return recipe


def read_c09_contact_prospective_row_v1(columns,row,*,authority_namespace,issuer):
    from ..runtime_contracts import namespace_ref
    from .c09_paged_sql_v2 import C09PagedCaptureHold
    if tuple(columns)!=COLUMNS or len(row)!=len(COLUMNS):raise C09PagedCaptureHold('Contact prospective exact C09 physical row differs')
    ns=NamespaceId(row[0],row[1]);original=ContactProspectiveOriginalV1(row[4]);raw=json.loads(original.payload_json)
    if (namespace_ref(ns)!=authority_namespace or (raw['contact_id'],raw['birth_operation_id'])!=row[2:4]
            or original.digest!=row[5] or row[7]!=contact_prospective_original_ref_v1(ns,row[2],row[3])):
        raise C09PagedCaptureHold('Contact prospective C09 original locator/namespace/whole commitment differs')
    issuer._signer.verify(SIGN_KIND,canonical_serialize((ns,row[2],row[3],original.digest)),row[6])
    return 'prospective_birth',row[7],raw,original.digest


@dataclass(frozen=True,slots=True)
class ContactProspectiveSuccessorV1:
    payload_json:str
    def __post_init__(self):
        raw=json.loads(self.payload_json)
        fields={'schema','birth_ref','birth_digest','refresh_rule','final_candidate','final_qualification_digest',
            'quote_digest','reservation_digest','joint_gate_digest','deadline_utc'}
        if (type(raw)is not dict or set(raw)!=fields or raw['schema']!='d10.contact-prospective-successor-original.v1'
                or raw['refresh_rule']!=REFRESH_RULE or canonical_serialize(raw)!=self.payload_json):
            raise ValueError('Contact prospective successor closed original schema differs')
    @property
    def digest(self):return canonical_digest(json.loads(self.payload_json))


def derive_contact_prospective_successor_v1(birth,*,action,qualification,quote,reservation_digest,joint_gate_digest,deadline_utc):
    """Pure restricted birth/final comparison; callers retain real final gates."""
    from ..domains.d01.production_operations_v1 import plain_v1
    from .contact_final_action_v3 import ContactActionStageV3
    from .contact_qualification_v3 import CurrentContactQualificationV3
    if (type(birth)is not ContactProspectiveOriginalV1 or type(action)is not ContactActionStageV3
            or type(qualification)is not CurrentContactQualificationV3):
        raise TypeError('Contact prospective successor needs actual typed birth/final originals')
    raw=json.loads(birth.payload_json);current={'goal':plain_v1(action.goal),'action':plain_v1(action.intent),'schema':plain_v1(action.schema)}
    old=raw['candidate']
    if (current['goal']!=old['goal'] or {key:value for key,value in current['action'].items()if key!='required_checks'}!=
            {key:value for key,value in old['action'].items()if key!='required_checks'}
            or {key:value for key,value in current['schema'].items()if key!='required_checks'}!=
                {key:value for key,value in old['schema'].items()if key!='required_checks'}
            or canonical_digest(quote)!=raw['quote']['digest'] or reservation_digest!=raw['reservation']['digest']
            or deadline_utc!=raw['deadline_utc'] or qualification.owner_policy_digest!=raw['observation']['policy_original_digest']):
        raise ValueError('Contact prospective successor changed fixed Goal/action/Source/Owner policy/quote/reservation/deadline')
    for name in ('action','schema'):
        old_specs=old[name]['required_checks'];new_specs=current[name]['required_checks']
        if len(old_specs)!=6 or len(new_specs)!=6:
            raise ValueError('Contact prospective successor requires all six original/final providers')
        for before,after in zip(old_specs,new_specs):
            if {key:value for key,value in before.items()if key!='required_input_versions'}!={
                    key:value for key,value in after.items()if key!='required_input_versions'}:
                raise ValueError('Contact prospective successor changed provider semantic parameters')
    current['digest']=canonical_digest(current)
    value={'schema':'d10.contact-prospective-successor-original.v1',
        'birth_ref':contact_prospective_original_ref_v1(NamespaceId(**raw['namespace']),raw['contact_id'],raw['birth_operation_id']),
        'birth_digest':birth.digest,'refresh_rule':REFRESH_RULE,'final_candidate':current,
        'final_qualification_digest':qualification.digest,'quote_digest':canonical_digest(quote),
        'reservation_digest':reservation_digest,'joint_gate_digest':joint_gate_digest,'deadline_utc':deadline_utc}
    return ContactProspectiveSuccessorV1(canonical_serialize(value))


def require_contact_prospective_final_gate_v1(db,*,material,read):
    from .contact_final_stage_v3 import require_installed_contact_material_v3
    from .contact_final_projection_v3 import require_contact_projection_read_v3
    from .joint_node_execution_v1 import read_joint_executor_index_v1,require_current_joint_binding_gate_v1
    require_installed_contact_material_v3(material)
    require_contact_projection_read_v3(read,db,phases=('pre_e','provisional_e_plus_1','post_cas_e_plus_1'))
    birth=material.prospective_birth
    if birth is None:return None
    raw=json.loads(birth.payload_json)
    key=contact_prospective_barrier_key_v1(material.scope.namespace,material.content.activity_id,material.content.contact_id)
    barrier=read.head(db,key,required=True)
    before={name:value for name,value in raw.items()if name!='receipt'}
    if (barrier.value['precommit_digest']!=canonical_digest(before)
            or barrier.value['birth_operation_id']!=raw['birth_operation_id']
            or barrier.value['joint_preparation']!=raw['joint_preparation']
            or raw['effect_id']!=material.frame.envelope.identity.effect_id
            or raw['final_operation_id']!=material.frame.envelope.identity.operation_id
            or material.current_policy.original.digest!=raw['observation']['policy_original_digest']):
        raise ValueError('Contact born final lost its immutable same-CAS barrier/current Owner policy')
    binding=read_joint_executor_index_v1(db,namespace=material.scope.namespace,selector_kind='contact',
        selector_key=(raw['terms']['causal_operation_id'],raw['terms']['dedupe_key']),
        issuer=material.runtime.graph._GraphCoordinator__d11_issuer)
    if binding is None:raise ValueError('Contact born final is waiting for its actual matching current Joint binding')
    gate=require_current_joint_binding_gate_v1(db,frame=read.frame,binding=binding,
        issuer=material.runtime.graph._GraphCoordinator__d11_issuer)
    return gate


SUCCESSOR_TABLE='graph_contact_prospective_successors_v1'
SUCCESSOR_COLUMNS=('bot','persona','final_operation_id','birth_ref','birth_digest','payload_json','payload_digest',
    'signature','final_receipt_digest')
SUCCESSOR_DDL=('CREATE TABLE '+SUCCESSOR_TABLE+'(bot TEXT NOT NULL,persona TEXT NOT NULL,final_operation_id TEXT NOT NULL,'
    'birth_ref TEXT NOT NULL,birth_digest TEXT NOT NULL,payload_json TEXT NOT NULL,payload_digest TEXT NOT NULL,'
    'signature TEXT NOT NULL,final_receipt_digest TEXT NOT NULL,PRIMARY KEY(bot,persona,final_operation_id))')
SUCCESSOR_SIGN='d10.contact-prospective-successor-original.v1'
SUCCESSOR_TRIGGERS=tuple('CREATE TRIGGER '+SUCCESSOR_TABLE+'_no_'+action.lower()+' BEFORE '+action+' ON '+SUCCESSOR_TABLE+
    " BEGIN SELECT RAISE(ABORT,'Contact prospective successor immutable'); END" for action in ('UPDATE','DELETE'))


def record_contact_prospective_successor_after_commit_v1(db,*,material,receipt,final_original_digest):
    from .contact_final_stage_v3 import require_installed_contact_material_v3
    require_installed_contact_material_v3(material)
    successor=material.prospective_successor
    if material.prospective_birth is None:
        if successor is not None:raise ValueError('Unborn Contact cannot manufacture a prospective successor')
        return None
    if type(successor)is not ContactProspectiveSuccessorV1 or receipt.status!='committed':
        raise ValueError('Contact prospective successor requires its actual final same-CAS receipt')
    raw=json.loads(successor.payload_json);ns=material.scope.namespace
    actual=db.execute('SELECT original_digest,receipt_digest FROM graph_domain_production_originals_v1 '
        'WHERE bot=? AND persona=? AND operation_id=?',(*ns.as_tuple,receipt.operation_id)).fetchone()
    if actual!=(final_original_digest,canonical_digest(receipt)) or raw['birth_digest']!=material.prospective_birth.digest:
        raise ValueError('Contact prospective successor lost its actual final/original birth COMMIT')
    issuer=material.runtime.graph._GraphCoordinator__d11_issuer
    final_digest=canonical_digest(receipt)
    signature=issuer._signer.sign(SUCCESSOR_SIGN,canonical_serialize((ns,receipt.operation_id,successor.digest,final_digest)))
    row=(*ns.as_tuple,receipt.operation_id,raw['birth_ref'],raw['birth_digest'],successor.payload_json,
        successor.digest,signature,final_digest)
    old=db.execute('SELECT '+','.join(SUCCESSOR_COLUMNS)+' FROM '+SUCCESSOR_TABLE+
        ' WHERE bot=? AND persona=? AND final_operation_id=?',row[:3]).fetchone()
    if old is None:db.execute('INSERT INTO '+SUCCESSOR_TABLE+' VALUES(?,?,?,?,?,?,?,?,?)',row)
    elif old!=row:raise ValueError('Contact prospective successor replay changed its actual original')
    return successor


def read_c09_contact_successor_row_v1(columns,row,*,authority_namespace,issuer):
    from ..runtime_contracts import namespace_ref
    from .c09_paged_sql_v2 import C09PagedCaptureHold
    if tuple(columns)!=SUCCESSOR_COLUMNS or len(row)!=len(SUCCESSOR_COLUMNS):
        raise C09PagedCaptureHold('Contact prospective successor exact physical C09 columns differ')
    ns=NamespaceId(row[0],row[1]);original=ContactProspectiveSuccessorV1(row[5]);raw=json.loads(original.payload_json)
    if (namespace_ref(ns)!=authority_namespace or raw['birth_ref']!=row[3] or raw['birth_digest']!=row[4]
            or original.digest!=row[6] or raw['final_candidate']['action']['identity']['operation_id']!=row[2]):
        raise C09PagedCaptureHold('Contact successor actual namespace/birth/final locator/digest differs')
    issuer._signer.verify(SUCCESSOR_SIGN,canonical_serialize((ns,row[2],original.digest,row[8])),row[7])
    return 'prospective_successor',row[2],raw,original.digest
