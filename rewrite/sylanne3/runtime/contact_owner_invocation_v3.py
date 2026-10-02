"""Immutable, signed Contact invocation original in the eleven-member transaction.

A decoded original is evidence only. It cannot mint a lease or authorize recovery.
"""
from dataclasses import asdict, dataclass, fields
from datetime import datetime, timezone
import json
import sqlite3
from ..runtime_contracts import canonical_digest, canonical_serialize, NamespaceId
from ..authority_service.contact_owner_session_v3 import ContactOwnerSessionObservationV3, from_wire as session_from_wire, digest

TABLE='graph_contact_owner_invocations_v3'
SCHEMA='sylanne3.contact-owner-invocation-original.v3'
SIGN_KIND='d08.contact-owner-invocation-original.v3'
DDL=f'''CREATE TABLE {TABLE} (
    bot TEXT NOT NULL, persona TEXT NOT NULL, operation_id TEXT NOT NULL,
    request_digest TEXT NOT NULL, payload_json TEXT NOT NULL, payload_digest TEXT NOT NULL,
    signature TEXT NOT NULL, PRIMARY KEY(bot,persona,operation_id))'''
TRIGGERS=tuple(f"CREATE TRIGGER {TABLE}_no_{action.lower()} BEFORE {action} ON {TABLE} "
    "BEGIN SELECT RAISE(ABORT,'contact owner invocation is immutable'); END" for action in ('UPDATE','DELETE'))
_FIELDS={'schema','namespace','operation_id','request_digest','request','command','owner','session_observation',
    'authority','lease_domains','scope','post_graph_revision','post_graph_epoch','result','provenance','deadline_utc'}


def install_contact_owner_invocation_schema_v3(db):
    db.execute(DDL.replace('CREATE TABLE ','CREATE TABLE IF NOT EXISTS ',1))
    for ddl in TRIGGERS:db.execute(ddl.replace('CREATE TRIGGER ','CREATE TRIGGER IF NOT EXISTS ',1))
    require_contact_owner_invocation_schema_v3(db)


def require_contact_owner_invocation_schema_v3(db):
    with sqlite3.connect(':memory:') as expected:
        expected.execute(DDL)
        for ddl in TRIGGERS:expected.execute(ddl)
        sql='SELECT type,name,sql FROM sqlite_master WHERE tbl_name=? AND sql IS NOT NULL ORDER BY type,name'
        if tuple(db.execute(sql,(TABLE,)))!=tuple(expected.execute(sql,(TABLE,))):
            raise ValueError('Contact Owner invocation exact schema differs; HOLD')


def owner_binding_from_wire_v3(raw):
    from ..graph_coordinator import OwnerLeaseBindingV1
    from ..authority_service.v2_owner_contract import OwnerPrincipalV1
    from ..authority_service.d12_target_owner_admission_v1 import target_admission_from_wire_v1
    from ..authority_service.d12_owner_storage_admission_v1 import owner_storage_admission_from_wire_v1
    if type(raw) is not dict or set(raw)!={f.name for f in fields(OwnerLeaseBindingV1)}:
        raise ValueError('Contact Owner full lease fields differ')
    value=dict(raw)
    for name,cls in (('principal',OwnerPrincipalV1),('namespace',NamespaceId)):
        if type(value[name]) is not dict or set(value[name])!={f.name for f in fields(cls)}:
            raise ValueError('Contact Owner identity fields differ')
        value[name]=cls(**value[name])
    for name in ('capabilities','purposes','audiences'):
        items=value[name]
        if type(items) is not list or any(type(x) is not str for x in items) or items!=sorted(set(items)):
            raise ValueError('Contact Owner finite grant set differs')
        value[name]=frozenset(items)
    if value['target_admission'] is not None:value['target_admission']=target_admission_from_wire_v1(value['target_admission'])
    if value['storage_admission'] is not None:value['storage_admission']=owner_storage_admission_from_wire_v1(value['storage_admission'])
    for name in ('actor','purpose','audience','grant_id','scope','issuer_ref','grant_digest','graph_incarnation','authorization_head'):
        if type(value[name]) is not str or not value[name]:raise ValueError('Contact Owner lease string fields differ')
    for name in ('grant_revision','access_epoch','delete_epoch','authorization_revision','revocation_epoch'):
        if type(value[name]) is not int or value[name]<0:raise ValueError('Contact Owner lease integer fields differ')
    owner=OwnerLeaseBindingV1(**value)
    if _owner_storage_wire_v3(owner)!=raw:raise ValueError('Contact Owner lease is not canonical')
    return owner


def validate_contact_owner_invocation_v3(raw):
    from .contact_final_stage_v3 import PrepareCurrentContactDispatchRequestV3, validate_contact_final_provenance_v3
    from ..authority_service.v2_contract import from_wire, to_wire, FencePermitV2
    from .restore_anchor import RestoreAnchor
    from ..authority_service.v2_owner_proof import _time
    if type(raw) is not dict or set(raw)!=_FIELDS or raw['schema']!=SCHEMA:
        raise ValueError('Contact Owner invocation closed fields differ')
    owner=owner_binding_from_wire_v3(raw['owner'])
    session=session_from_wire(raw['session_observation'])
    if type(session) is not ContactOwnerSessionObservationV3:raise ValueError('Contact session observation required')
    if type(raw['request']) is not dict or set(raw['request'])!={'contact_id','segment_index'}:
        raise ValueError('Contact invocation request fields differ')
    typed_request=PrepareCurrentContactDispatchRequestV3(**raw['request'])
    command=raw['command']
    if (type(command) is not dict or set(command)!={'activity_id','audience_ref','parent_budget_lease_ref'}
            or any(type(v) is not str or not v or len(v)>4096 for v in command.values())
            or canonical_digest(('sylanne.domain-production-command.v1',owner.namespace,owner.actor,
                'prepare_contact_dispatch_v3',typed_request,raw['operation_id'],command['activity_id'],
                command['audience_ref'],command['parent_budget_lease_ref']))!=raw['request_digest']):
        raise ValueError('Contact invocation original complete command digest differs')
    scope=raw['scope']
    if type(scope) is not dict or set(scope)!={'namespace','authority_namespace','generation','operation','operation_id','permit','pinned_anchor','graph_epoch','graph_revision'}:
        raise ValueError('Contact original scope fields differ')
    permit=from_wire(scope['permit']);anchor=RestoreAnchor(**scope['pinned_anchor'])
    if type(permit) is not FencePermitV2 or to_wire(permit)!=scope['permit']:
        raise ValueError('Contact original permit differs')
    if (scope['operation']!='write' or permit.operation!='write' or scope['operation_id']!=permit.operation_id
            or scope['namespace']!=raw['namespace'] or raw['namespace']!=asdict(owner.namespace)
            or scope['authority_namespace']!=permit.namespace or scope['generation']!=permit.generation
            or anchor!=permit.pinned_anchor or session.permit_digest!=digest(scope['permit'])
            or session.principal!=owner.principal or session.actor!=owner.actor
            or session.authority_namespace!=permit.namespace or session.authority_id!=anchor.authority_id
            or type(scope['graph_revision']) is not int or scope['graph_revision']<0
            or type(scope['graph_epoch']) is not dict or set(scope['graph_epoch'])!={'bot','persona','revision'}
            or (scope['graph_epoch']['bot'],scope['graph_epoch']['persona'])!=owner.namespace.as_tuple
            or type(scope['graph_epoch']['revision']) is not int or scope['graph_epoch']['revision']<0
            or type(raw['post_graph_revision']) is not int or raw['post_graph_revision']!=scope['graph_revision']+1
            or type(raw['post_graph_epoch']) is not int or raw['post_graph_epoch']!=scope['graph_epoch']['revision']+1):
        raise ValueError('Contact invocation original Owner/session/scope/pre-post identity differs')
    authority=authority_from_wire_v3(raw['authority'])
    domains=raw['lease_domains']
    if (authority.actor!=owner.actor or authority.purpose!=owner.purpose or authority.audience!=(owner.audience,)
            or authority.namespace!=owner.namespace or authority.activation_generation!=scope['generation']
            or authority.issuer_domain!='d12' or authority.provider_policy_ref!='owner-grant-v1'
            or type(domains) is not list or not domains or any(type(x) is not str for x in domains)
            or domains!=sorted(set(domains))):
        raise ValueError('Contact original call authority/finite domains differs')
    validate_contact_final_provenance_v3(raw['provenance'])
    result=raw['result']
    from .domain_production_originals_v1 import _receipt
    from .contact_final_stage_v3 import _contact_final_result_v3
    from ..graph_types import AtomKey
    if type(result) is not dict:raise ValueError('Contact result object required')
    receipt=_receipt(result['receipt']);proof=raw['provenance']
    expected=_contact_final_result_v3(receipt=receipt,original_digest=result['original_digest'],
        job_id=AtomKey.from_token(proof['job_ref']).name,admission_ref=proof['admission_ref'],
        dispatch_request_digest=proof['request_digest'])
    if (result!=expected or result['operation_id']!=raw['operation_id'] or len(receipt.write_versions)!=11
            or type(raw['request_digest']) is not str or len(raw['request_digest'])!=64
            or any(c not in '0123456789abcdef' for c in raw['request_digest'])):
        raise ValueError('Contact invocation result/request/eleven-member receipt differs')
    deadline=_time(raw['deadline_utc']).timestamp()
    if deadline>proof['qualification_evidence']['deadline_utc']:
        raise ValueError('Contact invocation deadline extends original')
    return raw


@dataclass(frozen=True, slots=True)
class ContactOwnerInvocationOriginalV3:
    payload_json: str
    def __post_init__(self):
        raw=json.loads(self.payload_json)
        validate_contact_owner_invocation_v3(raw)
        if canonical_serialize(raw)!=self.payload_json:raise ValueError('Contact invocation noncanonical bytes')
    @property
    def digest(self):return digest(json.loads(self.payload_json))


def record_contact_owner_invocation_v3(db,call,scope,result,owner,session_observation):
    """Called after receipt_json update and before the actual SQL COMMIT."""
    from .contact_final_ack_v1 import require_contact_owner_call_v1
    from .contact_final_stage_v3 import verify_contact_final_committed_v3
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    from .contact_saved_owner_projection_v3 import _owner_binding_wire_v3
    from ..authority_service.v2_contract import to_wire
    from ..authority_service.contact_owner_session_v3 import to_wire as session_to_wire
    require_contact_owner_call_v1(call)
    graph=call.runtime.graph;store=graph._GraphCoordinator__store
    if db is not store._db or not db.in_transaction or not store._lock._is_owned():
        raise ValueError('Contact invocation requires the actual producing SQL transaction')
    captured=_CAPTURES.get(id(call))
    if (captured is None or captured[0] is not call or captured[1] is not scope
            or captured[2]!=_owner_binding_wire_v3(owner) or captured[3] is not session_observation):
        raise ValueError('Contact invocation has no actual authenticated pretransaction capture')
    require_contact_owner_invocation_schema_v3(db)
    verify_contact_final_committed_v3(db,namespace=scope.namespace,result=result,issuer=graph._GraphCoordinator__d11_issuer,graph=graph)
    original=read_adopted_domain_operation_v1(db,scope.namespace,call.operation_id)
    proof=original['payload']['provenance'];metadata,epoch=graph._v2_graph_stamp(scope.namespace)
    scope_raw=asdict(scope);scope_raw['permit']=to_wire(scope.permit)
    raw=dict(schema=SCHEMA,namespace=asdict(scope.namespace),operation_id=call.operation_id,
        request_digest=call.request_digest,request=asdict(call.request),command=_command_from_adopted(original),owner=_owner_storage_wire_v3(owner),
        session_observation=session_to_wire(session_observation),authority=json.loads(canonical_serialize(asdict(call.authority))),
        lease_domains=sorted(graph._GraphCoordinator__leases[call.lease][4]),
        scope=scope_raw,post_graph_revision=metadata.graph_revision,post_graph_epoch=epoch.revision,result=result,
        provenance=proof,deadline_utc=datetime.fromtimestamp(proof['qualification_evidence']['deadline_utc'],timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ'))
    value=ContactOwnerInvocationOriginalV3(canonical_serialize(raw))
    issuer=graph._GraphCoordinator__d11_issuer
    signature=issuer._signer.sign(SIGN_KIND,canonical_serialize((scope.namespace,call.operation_id,call.request_digest,value.digest)))
    db.execute(f'INSERT INTO {TABLE} VALUES(?,?,?,?,?,?,?)',(*scope.namespace.as_tuple,call.operation_id,call.request_digest,value.payload_json,value.digest,signature))
    return value


def read_contact_owner_invocation_v3(db,issuer,namespace,operation_id,request_digest):
    if not db.in_transaction:raise ValueError('Contact invocation read requires pinned SQL transaction')
    require_contact_owner_invocation_schema_v3(db)
    row=db.execute(f'SELECT request_digest,payload_json,payload_digest,signature FROM {TABLE} WHERE bot=? AND persona=? AND operation_id=?',(*namespace.as_tuple,operation_id)).fetchone()
    if row is None:raise ValueError('Contact original invocation absent; no legacy backfill; HOLD')
    value=ContactOwnerInvocationOriginalV3(row[1]);raw=json.loads(value.payload_json)
    if row[0]!=request_digest or value.digest!=row[2] or raw['namespace']!=asdict(namespace) or raw['operation_id']!=operation_id or raw['request_digest']!=request_digest:
        raise ValueError('Contact invocation locator/digest differs')
    issuer._signer.verify(SIGN_KIND,canonical_serialize((namespace,operation_id,request_digest,value.digest)),row[3])
    return value


_CAPTURES={}


def capture_contact_owner_invocation_v3(call,scope,owner,session):
    """Installed GCP entry before the producing transaction; no Graph lock held."""
    from .contact_final_ack_v1 import require_contact_owner_call_v1
    from .contact_saved_owner_projection_v3 import _owner_binding_wire_v3
    from ..authority_service.v2_contract import to_wire
    require_contact_owner_call_v1(call)
    graph=call.runtime.graph;store=graph._GraphCoordinator__store
    if store._db.in_transaction or store._lock._is_owned():
        raise ValueError('Contact Owner observation RPC must be outside Graph lock')
    if (graph._GraphCoordinator__owner_session_proofs.get(call.lease)!=session
            or graph._GraphCoordinator__owner_leases.get(call.lease) is not owner):
        raise ValueError('Contact original capture differs from actual active lease/session')
    port=graph._GraphCoordinator__content_fence_v2
    response=port.capture_current_contact_owner_session_v3(namespace=scope.namespace,
        authority_namespace=scope.authority_namespace,permit=scope.permit,
        owner_actor_id=call.authority.actor,owner_session_token=session[0],owner_session_request=session[1])
    if type(response) is not dict or set(response)!={'observation','authority'}:
        raise ValueError('Contact authenticated session capture response differs')
    observed=session_from_wire(response['observation'])
    if (type(observed) is not ContactOwnerSessionObservationV3 or observed.principal!=owner.principal
            or observed.actor!=owner.actor or observed.permit_digest!=digest(to_wire(scope.permit))
            or observed.authority_observation_digest!=digest(response['authority'])):
        raise ValueError('Contact authenticated capture Owner/permit differs')
    _CAPTURES[id(call)]=(call,scope,_owner_binding_wire_v3(owner),observed)
    return observed


def release_contact_owner_invocation_v3(call):
    _CAPTURES.pop(id(call),None)


def _read_bound_invocation(call,scope,result,owner):
    from .contact_final_ack_v1 import require_contact_owner_call_v1
    from .contact_final_stage_v3 import verify_contact_final_committed_v3
    from .contact_saved_owner_projection_v3 import _owner_binding_wire_v3
    from ..authority_service.v2_contract import to_wire
    require_contact_owner_call_v1(call)
    graph=call.runtime.graph;store=graph._GraphCoordinator__store
    with store._lock:
        if store._db.in_transaction:raise ValueError('Contact recovered original requires independent durable snapshot')
        store._db.execute('BEGIN')
        try:
            value=read_contact_owner_invocation_v3(store._db,graph._GraphCoordinator__d11_issuer,
                scope.namespace,call.operation_id,call.request_digest)
            raw=json.loads(value.payload_json)
            expected_scope=asdict(scope);expected_scope['permit']=to_wire(scope.permit)
            if (raw['scope']!=expected_scope or raw['result']!=result
                    or raw['request']!=asdict(call.request) or raw['owner']!=_owner_storage_wire_v3(owner)
                    or raw['authority']!=json.loads(canonical_serialize(asdict(call.authority)))):
                raise ValueError('Contact recovered invocation full original identity differs; HOLD')
            verify_contact_final_committed_v3(store._db,namespace=scope.namespace,result=result,
                issuer=graph._GraphCoordinator__d11_issuer,graph=graph)
            return value
        finally:store._db.rollback()


def associate_saved_contact_owner_invocation_v3(call,scope,result,owner,session,*,use,signature):
    """Authenticate an explicit Owner-signed new-session use; issue no new rights.

    The installed entrant supplies a real authenticated current lease/session.
    It must retain its normal current grant/provider checks around this method.
    """
    from ..authority_service.contact_owner_session_v3 import OwnerContactRecoveryUseV3, to_wire
    from ..authority_service.v2_owner_session import _verifier
    from .contact_saved_owner_projection_v3 import _require_active
    graph=call.runtime.graph;port=graph._GraphCoordinator__content_fence_v2
    original=_read_bound_invocation(call,scope,result,owner);raw=json.loads(original.payload_json)
    old=session_from_wire(raw['session_observation'])
    if (type(use) is not OwnerContactRecoveryUseV3 or use.invocation_digest!=original.digest
            or use.operation_id!=call.operation_id or use.deadline_utc!=raw['deadline_utc']
            or use.original_session_commitment!=old.commitment
            or use.new_verifier_commitment!='sha256:'+_verifier(session[0])
            or use.principal!=owner.principal or use.actor!=owner.actor
            or use.permit_digest!=old.permit_digest):
        raise ValueError('Contact recovery-use differs from exact saved invocation/new session; HOLD')
    _require_active(graph,scope)
    response=port.associate_contact_owner_recovery_v3(namespace=scope.namespace,
        authority_namespace=scope.authority_namespace,permit=scope.permit,
        owner_actor_id=call.authority.actor,owner_session_token=session[0],owner_session_request=session[1],
        original=old,use=use,signature=signature)
    if type(response) is not dict or set(response)!={'observation','authority'}:
        raise ValueError('Contact authenticated recovery response differs')
    association=response['observation']
    if type(association) is not dict or set(association)!={'schema','kind','original','current','use','association_digest'}:
        raise ValueError('Contact authenticated association fields differ')
    current=session_from_wire(association['current'])
    from ..authority_service.contact_owner_session_v3 import SCHEMA as SESSION_SCHEMA
    if (association['schema']!=SESSION_SCHEMA or association['kind']!='contact_owner_session_association_v3'
            or association['original']!=to_wire(old) or association['use']!=to_wire(use)
            or type(current) is not ContactOwnerSessionObservationV3
            or current.verifier_commitment!=use.new_verifier_commitment
            or current.authority_observation_digest!=digest(response['authority'])
            or association['association_digest']!=digest({'original':old.commitment,'current':current.commitment,'use':to_wire(use)})):
        raise ValueError('Contact authenticated association invocation/session differs')
    _require_active(graph,scope)
    if _read_bound_invocation(call,scope,result,owner)!=original:
        raise ValueError('Contact invocation changed across association RPC')
    return association


def authority_from_wire_v3(raw):
    from ..runtime_contracts import AuthorityContext
    if type(raw) is not dict or set(raw)!={f.name for f in fields(AuthorityContext)}:
        raise ValueError('Contact original Authority context fields differ')
    parts=dict(raw)
    if type(parts['namespace']) is not dict or set(parts['namespace'])!={'bot_id','persona_id'}:
        raise ValueError('Contact Authority namespace fields differ')
    parts['namespace']=NamespaceId(**parts['namespace'])
    for key in ('owner_scope','audience'):
        if type(parts[key]) is not list:raise ValueError('Contact Authority tuple fields differ')
        parts[key]=tuple(parts[key])
    value=AuthorityContext(**parts)
    if json.loads(canonical_serialize(asdict(value)))!=raw:raise ValueError('Contact Authority context noncanonical')
    return value


@dataclass(frozen=True, slots=True)
class _AuthenticatedContactRecoveryV3:
    graph: object
    runtime: object
    authority: object
    owner: object
    scope: object
    request: object
    operation_id: str
    request_digest: str
    original: ContactOwnerInvocationOriginalV3
    session: tuple
    association: dict

    @property
    def activity_id(self):return json.loads(self.original.payload_json)['command']['activity_id']
    @property
    def audience_ref(self):return json.loads(self.original.payload_json)['command']['audience_ref']
    @property
    def parent_budget_lease_ref(self):return json.loads(self.original.payload_json)['command']['parent_budget_lease_ref']


_RECOVERIES={}


def authenticate_contact_restart_v3(graph,bootstrap,*,namespace,operation_id,request_digest,
        owner_session_token,owner_session_request,use,signature):
    """Explicit installed restart entrant, before minting any process rights.

    Authenticates original SQL and current Authority under the saved permit.
    The resulting private marker authorizes only resuming this exact invocation;
    the shared GCP entrant must not turn it into an unrestricted Owner lease.
    """
    from ..graph_coordinator import GraphCoordinator
    from ..runtime_contracts import FenceScope
    from ..graph_types import NamespaceEpoch
    from .restore_anchor import RestoreAnchor
    from .contact_final_stage_v3 import PrepareCurrentContactDispatchRequestV3,verify_contact_final_committed_v3
    from .contact_saved_owner_projection_v3 import _require_active,_owner_binding_wire_v3,_require_live,_live_terms
    from .contact_qualification_evidence_v3 import decode_contact_qualification_evidence_v3
    from .first_ingress_v2 import trusted_upper
    from ..authority_service.v2_contract import from_wire as permit_from_wire
    from ..authority_service.contact_owner_session_v3 import OwnerContactRecoveryUseV3,validate_association_v3
    from ..authority_service.d12_target_owner_admission_v1 import current_owner_authority_from_wire_v1
    from ..authority_service.v2_owner_session import _verifier
    if type(graph) is not GraphCoordinator:raise TypeError('installed GraphCoordinator required')
    graph._admin(bootstrap)
    runtime=graph._GraphCoordinator__domain_production_runtime_v1
    if runtime is None:raise ValueError('Contact installed runtime unavailable')
    runtime._current()
    store=graph._GraphCoordinator__store;port=graph._GraphCoordinator__content_fence_v2
    with store._lock:
        if store._db.in_transaction:raise ValueError('Contact restart needs independent durable SQL')
        store._db.execute('BEGIN')
        try:value=read_contact_owner_invocation_v3(store._db,graph._GraphCoordinator__d11_issuer,namespace,operation_id,request_digest)
        finally:store._db.rollback()
    raw=json.loads(value.payload_json);owner=owner_binding_from_wire_v3(raw['owner']);authority=authority_from_wire_v3(raw['authority'])
    parts=dict(raw['scope']);parts['namespace']=NamespaceId(**parts['namespace'])
    parts['graph_epoch']=NamespaceEpoch(**parts['graph_epoch']);parts['pinned_anchor']=RestoreAnchor(**parts['pinned_anchor'])
    parts['permit']=permit_from_wire(parts['permit']);scope=FenceScope(**parts)
    request=PrepareCurrentContactDispatchRequestV3(**raw['request']);old=session_from_wire(raw['session_observation'])
    if (type(use) is not OwnerContactRecoveryUseV3 or use.invocation_digest!=value.digest
            or use.operation_id!=operation_id or use.deadline_utc!=raw['deadline_utc']
            or use.original_session_commitment!=old.commitment
            or use.new_verifier_commitment!='sha256:'+_verifier(owner_session_token)
            or use.principal!=owner.principal or use.actor!=owner.actor or use.permit_digest!=old.permit_digest
            or owner_session_request.principal!=owner.principal
            or type(signature) is not bytes or len(signature)!=64):
        raise ValueError('Contact restart explicit scoped Owner proof differs; HOLD')
    marker=_AuthenticatedContactRecoveryV3(graph,runtime,authority,owner,scope,request,operation_id,
        request_digest,value,(owner_session_token,owner_session_request),{})
    def snapshot(guarded=None):
        clock=port.read_ingress_clock(graph._GraphCoordinator__scene_clock_policy)
        with store._lock:
            if store._db.in_transaction:raise ValueError('Contact restart SQL snapshot unexpectedly active')
            store._db.execute('BEGIN')
            try:
                actual=read_contact_owner_invocation_v3(store._db,graph._GraphCoordinator__d11_issuer,namespace,operation_id,request_digest)
                if actual!=value:raise ValueError('Contact restart original changed')
                verify_contact_final_committed_v3(store._db,namespace=namespace,result=raw['result'],issuer=graph._GraphCoordinator__d11_issuer,graph=graph)
                from .domain_production_originals_v1 import read_adopted_domain_operation_v1
                if _command_from_adopted(read_adopted_domain_operation_v1(store._db,namespace,operation_id))!=raw['command']:
                    raise ValueError('Contact restart actual adopted command differs')
                evidence=decode_contact_qualification_evidence_v3(raw['provenance']['qualification_evidence'],expected_digest=raw['provenance']['qualification_digest'])
                _require_live(evidence,trusted_upper(clock),*_live_terms(store._db,marker))
                if guarded is not None:
                    current=graph._owner_graph_binding_locked(authority,owner.principal,current_guard=guarded.guard,
                        target_admission=guarded.target_admission,storage_admission=guarded.storage_admission)
                    if _owner_binding_wire_v3(current)!=_owner_binding_wire_v3(owner):
                        raise ValueError('Contact restart current full Owner lease differs; HOLD')
            finally:store._db.rollback()
    _require_active(graph,scope);snapshot()
    response=port.associate_contact_owner_recovery_v3(namespace=namespace,authority_namespace=scope.authority_namespace,
        permit=scope.permit,owner_actor_id=owner.actor,owner_session_token=owner_session_token,
        owner_session_request=owner_session_request,original=old,use=use,signature=signature)
    if type(response) is not dict or set(response)!={'observation','authority'}:
        raise ValueError('Contact restart authenticated association response differs')
    validate_association_v3(response['observation'],original=old,use=use,authority_observation_digest=digest(response['authority']))
    auth=response['authority']
    if type(auth) is not dict or permit_from_wire(auth['permit'])!=scope.permit:
        raise ValueError('Contact restart authenticated original permit differs')
    guarded=current_owner_authority_from_wire_v1({k:v for k,v in auth.items() if k!='permit'})
    _require_active(graph,scope);snapshot(guarded)
    if graph._current_owner_principal(owner.actor,namespace)!=owner.principal:
        raise ValueError('Contact restart current actor pairing differs')
    marker=_AuthenticatedContactRecoveryV3(graph,runtime,authority,owner,scope,request,operation_id,
        request_digest,value,(owner_session_token,owner_session_request),response['observation'])
    _RECOVERIES[id(marker)]=marker
    return marker


def require_authenticated_contact_restart_v3(marker,graph,*,operation_id,request_digest):
    if (type(marker) is not _AuthenticatedContactRecoveryV3 or _RECOVERIES.get(id(marker)) is not marker
            or marker.graph is not graph or marker.operation_id!=operation_id or marker.request_digest!=request_digest):
        raise ValueError('Contact restart marker has no exact authenticated invocation')
    return marker


def release_authenticated_contact_restart_v3(marker):
    _RECOVERIES.pop(id(marker),None)


def _command_from_adopted(original):
    if original is None:raise ValueError('Contact actual adopted operation unavailable')
    payload=original['payload'];audiences=payload['authority']['audience']
    if type(audiences) is not list or len(audiences)!=1:
        raise ValueError('Contact original command requires one concrete audience')
    return {'activity_id':payload['identity']['activity_id'],'audience_ref':audiences[0],
        'parent_budget_lease_ref':payload['parent_budget']}


def require_saved_contact_owner_session_binding_v3(call,scope,result,owner,session):
    """Ordinary retry preserves original session; new session needs scoped marker."""
    from ..authority_service.v2_owner_session import _verifier,_canonical
    import hashlib
    value=_read_bound_invocation(call,scope,result,owner)
    old=session_from_wire(json.loads(value.payload_json)['session_observation'])
    verifier='sha256:'+_verifier(session[0])
    if verifier==old.verifier_commitment:
        if 'sha256:'+hashlib.sha256(_canonical(session[1])).hexdigest()!=old.request_digest:
            raise ValueError('Contact original Owner session request differs')
        return value
    graph=call.runtime.graph
    marker=getattr(graph,'_GraphCoordinator__contact_recovery_leases_v3',{}).get(call.lease)
    require_authenticated_contact_restart_v3(marker,graph,operation_id=call.operation_id,request_digest=call.request_digest)
    if (marker.original!=value or marker.authority is not call.authority or marker.owner is not owner
            or marker.scope!=scope or marker.session!=session or marker.request!=call.request):
        raise ValueError('Contact new-session recovery has no exact authenticated invocation marker')
    from ..authority_service.contact_owner_session_v3 import validate_association_v3
    use=session_from_wire(marker.association['use'])
    current=validate_association_v3(marker.association,original=old,use=use,
        authority_observation_digest=old.authority_observation_digest)
    if current.verifier_commitment!=verifier:raise ValueError('Contact recovery marker new session differs')
    return value


def _owner_storage_wire_v3(owner):
    """New carrier's plain wire; existing typed comparison wire stays unchanged."""
    from .contact_saved_owner_projection_v3 import _owner_binding_wire_v3
    _owner_binding_wire_v3(owner)  # Exact concrete type and finite frozen sets.
    raw=asdict(owner)
    for name in ('capabilities','purposes','audiences'):raw[name]=sorted(raw[name])
    return json.loads(canonical_serialize(raw))
