"""Independent immutable background Contact invocation; no Owner session is minted."""
from dataclasses import asdict, dataclass
import json
import sqlite3

from ..runtime_contracts import canonical_digest, canonical_serialize
from .contact_owner_invocation_v3 import owner_binding_from_wire_v3, _owner_storage_wire_v3
from ..authority_service.contact_background_rpc_v1 import validate_background_observation_v1

TABLE = 'graph_contact_background_invocations_v1'
SIGN_KIND = 'd08.contact-background-invocation-original.v1'
DDL = f'''CREATE TABLE {TABLE}(bot TEXT NOT NULL,persona TEXT NOT NULL,operation_id TEXT NOT NULL,
request_digest TEXT NOT NULL,payload_json TEXT NOT NULL,payload_digest TEXT NOT NULL,
signature TEXT NOT NULL,PRIMARY KEY(bot,persona,operation_id))'''
TRIGGERS = tuple(f"CREATE TRIGGER {TABLE}_no_{a.lower()} BEFORE {a} ON {TABLE} "
    "BEGIN SELECT RAISE(ABORT,'Contact background invocation immutable'); END" for a in ('UPDATE','DELETE'))
_FIELDS = {'schema','namespace','operation_id','request_digest','request','command','scope','owner',
    'observation','result','provenance_digest','post_graph_revision','post_graph_epoch','deadline_utc'}
_ACTIVE = {}
_CAPTURES = {}


def install_contact_background_schema_v1(db):
    db.execute(DDL.replace('CREATE TABLE ','CREATE TABLE IF NOT EXISTS ',1))
    for sql in TRIGGERS:
        db.execute(sql.replace('CREATE TRIGGER ','CREATE TRIGGER IF NOT EXISTS ',1))
    require_contact_background_schema_v1(db)


def require_contact_background_schema_v1(db):
    with sqlite3.connect(':memory:') as expected:
        expected.execute(DDL)
        for sql in TRIGGERS:
            expected.execute(sql)
        query='SELECT type,name,sql FROM sqlite_master WHERE tbl_name=? AND sql IS NOT NULL ORDER BY type,name'
        if tuple(db.execute(query,(TABLE,))) != tuple(expected.execute(query,(TABLE,))):
            raise ValueError('Contact background Graph original schema differs; HOLD')


def validate_contact_background_invocation_v1(raw):
    from .contact_final_stage_v3 import PrepareCurrentContactDispatchRequestV3
    from .domain_production_originals_v1 import _receipt
    from ..authority_service.v2_contract import from_wire
    owner = owner_binding_from_wire_v3(raw['owner']) if type(raw) is dict and 'owner' in raw else None
    if type(raw) is not dict or set(raw) != _FIELDS or raw['schema'] != SIGN_KIND:
        raise ValueError('Contact background invocation closed schema differs')
    observation = validate_background_observation_v1(raw['observation'])
    request = PrepareCurrentContactDispatchRequestV3(**raw['request'])
    scope = raw['scope']
    permit = from_wire(scope['permit'])
    inputs = observation['inputs']
    receipt = _receipt(raw['result']['receipt'])
    if (raw['namespace'] != asdict(owner.namespace) or raw['namespace'] != inputs['namespace']
            or (raw['operation_id'],raw['request_digest']) != (inputs['operation_id'],inputs['request_digest'])
            or request.contact_id != inputs['contact_id'] or request.segment_index != 0
            or receipt.operation_id != raw['operation_id'] or len(receipt.write_versions) != 11
            or raw['post_graph_revision'] != scope['graph_revision'] + 1
            or raw['post_graph_epoch'] != scope['graph_epoch']['revision'] + 1
            or (scope['graph_revision'],scope['graph_epoch']['revision']) != (inputs['graph_revision'],inputs['graph_epoch'])
            or canonical_digest(scope['permit']) != observation['permit_digest']
            or canonical_digest(scope['pinned_anchor']) != observation['anchor_digest']
            or scope['operation_id'] != permit.operation_id or permit.operation != 'write'
            or owner.actor != observation['owner_actor'] or owner.authorization_head != observation['owner_head_digest']
            or owner.authorization_revision != observation['owner_revision']
            or owner.graph_incarnation != inputs['graph_incarnation']
            or not raw['deadline_utc'] <= observation['deadline_utc']):
        raise ValueError('Contact background invocation exact original Owner/input/pre-post scope differs')
    return raw


@dataclass(frozen=True, slots=True)
class ContactBackgroundInvocationOriginalV1:
    payload_json: str
    def __post_init__(self):
        raw = validate_contact_background_invocation_v1(json.loads(self.payload_json))
        if canonical_serialize(raw) != self.payload_json:
            raise ValueError('Contact background original canonical bytes differ')
    @property
    def digest(self):
        return canonical_digest(json.loads(self.payload_json))


@dataclass(frozen=True, slots=True)
class _ContactBackgroundCallV1:
    runtime: object
    authority: object
    lease: object
    request: object
    operation_id: str
    request_digest: str
    issued: object


def issue_contact_background_call_v1(runtime, *, authority, lease, request, operation_id, request_digest, issued):
    from .domain_followup_consumer_v1 import require_background_followup_v1
    from .contact_final_stage_v3 import PrepareCurrentContactDispatchRequestV3
    if type(issued) is _BackgroundContactRecoveryV1:
        require_background_contact_recovery_v1(issued,runtime.graph,authority,operation_id)
    else:
        require_background_followup_v1(issued,runtime.graph,authority,operation_id)
    if (type(request) is not PrepareCurrentContactDispatchRequestV3 or not 0<=request.segment_index<3
            or issued.command.operation_kind != 'prepare_contact_dispatch_v3' or issued.command.request != request
            or getattr(runtime,'_active_contact_background_call_v1',None) is not None):
        raise ValueError('Contact background call requires its exact actual derived final command')
    call = _ContactBackgroundCallV1(runtime,authority,lease,request,operation_id,request_digest,issued)
    _ACTIVE[id(call)] = call
    runtime._active_contact_background_call_v1 = call
    return call


def require_contact_background_call_v1(call):
    if (type(call) is not _ContactBackgroundCallV1 or _ACTIVE.get(id(call)) is not call
            or call.runtime._active_contact_background_call_v1 is not call
            or call.runtime.graph._GraphCoordinator__domain_production_runtime_v1 is not call.runtime):
        raise ValueError('Contact background has no exact installed active invocation')
    call.runtime._current()
    return call


def contact_background_call_v1(graph, authority, lease, operation_id, request_digest):
    runtime = graph._GraphCoordinator__domain_production_runtime_v1
    call = None if runtime is None else getattr(runtime,'_active_contact_background_call_v1',None)
    if call is not None:
        require_contact_background_call_v1(call)
        if (call.authority is not authority or call.lease != lease
                or (call.operation_id,call.request_digest) != (operation_id,request_digest)):
            raise ValueError('Contact background call crossed its exact command')
    return call


def revoke_contact_background_call_v1(runtime):
    call = getattr(runtime,'_active_contact_background_call_v1',None)
    if call is not None:
        _CAPTURES.pop(id(call),None)
        _ACTIVE.pop(id(call),None)
    runtime._active_contact_background_call_v1 = None


def capture_contact_background_invocation_v1(call, scope, owner):
    require_contact_background_call_v1(call)
    if call.request.segment_index>0:
        from .contact_continuation_stage_v1 import capture_contact_continuation_call_v1
        return capture_contact_continuation_call_v1(call,scope,owner)
    graph = call.runtime.graph
    store = graph._GraphCoordinator__store
    if store._db.in_transaction or store._lock._is_owned():
        raise ValueError('Contact background capture must finish outside Graph SQL lock')
    from .contact_background_inputs_v1 import read_contact_background_inputs_v1
    from .first_ingress_v2 import trusted_upper
    port = graph._GraphCoordinator__content_fence_v2
    now = trusted_upper(port.read_ingress_clock(graph._GraphCoordinator__scene_clock_policy))
    with store._lock:
        store._db.execute('BEGIN')
        try:
            terms, _, _, _ = read_contact_background_inputs_v1(store._db,namespace=scope.namespace,
                contact_id=call.request.contact_id,operation_id=call.operation_id,request_digest=call.request_digest,
                dedupe_key=call.issued.event.dedupe_key,issuer=graph._GraphCoordinator__d11_issuer,now=now,owner_actor=owner.actor)
        finally:
            store._db.rollback()
    from ..graph_types import AtomKey
    from .contact_plan_adoption_v2 import read_adopted_contact_plan_v2
    with store._lock:
        store._db.execute('BEGIN')
        try:
            policy_ref = read_adopted_contact_plan_v2(store._db,namespace=scope.namespace,
                contact_id=call.request.contact_id,issuer=graph._GraphCoordinator__d11_issuer)[2]['policy_ref']
        finally:
            store._db.rollback()
    observed = port.capture_contact_background_invocation_v1(namespace=scope.namespace,
        authority_namespace=scope.authority_namespace,permit=scope.permit,selector={
            'namespace':asdict(scope.namespace),'contact_id':call.request.contact_id,'operation_id':call.operation_id,
            'request_digest':call.request_digest,'policy_id':AtomKey.from_token(policy_ref).name,'dedupe_key':call.issued.event.dedupe_key})
    observation = validate_background_observation_v1(observed['observation'])
    if (observation['inputs'] != terms or observation['owner_actor'] != owner.actor
            or observation['owner_head_digest'] != owner.authorization_head
            or observation['owner_revision'] != owner.authorization_revision
            or observation['owner_authority_digest'] != canonical_digest(observed['authority'])):
        raise ValueError('Contact background Core exact original inputs/Owner differ')
    _CAPTURES[id(call)] = (call,scope,_owner_storage_wire_v3(owner),observation)
    return observation


def record_contact_background_invocation_v1(db,call,scope,result,owner,observation):
    require_contact_background_call_v1(call)
    if result.get('schema') != 'sylanne.domain-production-receipt.v1':
        return
    if call.request.segment_index>0:
        from .contact_continuation_readback_v1 import record_contact_continuation_background_after_commit_v1
        return record_contact_continuation_background_after_commit_v1(db,call,scope,result,owner,observation)
    graph = call.runtime.graph
    store = graph._GraphCoordinator__store
    if not db.in_transaction or db is not store._db or not store._lock._is_owned():
        raise ValueError('Contact background original requires the actual eleven-member SQL COMMIT')
    if _CAPTURES.get(id(call)) != (call,scope,_owner_storage_wire_v3(owner),observation):
        raise ValueError('Contact background original lost its actual pretransaction capture')
    from .contact_final_stage_v3 import verify_contact_final_committed_v3
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    from ..authority_service.v2_contract import to_wire
    verify_contact_final_committed_v3(db,namespace=scope.namespace,result=result,issuer=graph._GraphCoordinator__d11_issuer,graph=graph)
    original = read_adopted_domain_operation_v1(db,scope.namespace,call.operation_id)
    proof = original['payload']['provenance']
    raw_scope = asdict(scope)
    raw_scope['permit'] = to_wire(scope.permit)
    metadata, epoch = graph._v2_graph_stamp(scope.namespace)
    raw = dict(schema=SIGN_KIND,namespace=asdict(scope.namespace),operation_id=call.operation_id,
        request_digest=call.request_digest,request=asdict(call.request),command={
            'activity_id':original['payload']['identity']['activity_id'],'audience_ref':original['payload']['authority']['audience'][0],
            'parent_budget_lease_ref':original['payload']['parent_budget']},scope=raw_scope,owner=_owner_storage_wire_v3(owner),
        observation=observation,result=result,provenance_digest=canonical_digest(proof),
        post_graph_revision=metadata.graph_revision,post_graph_epoch=epoch.revision,
        deadline_utc=min(observation['deadline_utc'],proof['qualification_evidence']['deadline_utc']))
    value = ContactBackgroundInvocationOriginalV1(canonical_serialize(raw))
    issuer = graph._GraphCoordinator__d11_issuer
    signature = issuer._signer.sign(SIGN_KIND,canonical_serialize((scope.namespace,call.operation_id,call.request_digest,value.digest)))
    db.execute(f'INSERT INTO {TABLE} VALUES(?,?,?,?,?,?,?)',(*scope.namespace.as_tuple,call.operation_id,
        call.request_digest,value.payload_json,value.digest,signature))


def read_contact_background_invocation_v1(db,issuer,namespace,operation_id,request_digest):
    if not db.in_transaction:
        raise ValueError('Contact background original needs a pinned snapshot')
    require_contact_background_schema_v1(db)
    row = db.execute(f'SELECT request_digest,payload_json,payload_digest,signature FROM {TABLE} '
        'WHERE bot=? AND persona=? AND operation_id=?',(*namespace.as_tuple,operation_id)).fetchone()
    if row is None:
        raise ValueError('Contact background original absent; no session or legacy backfill; HOLD')
    value = ContactBackgroundInvocationOriginalV1(row[1])
    raw = json.loads(value.payload_json)
    if (row[0] != request_digest or value.digest != row[2]
            or raw['namespace'] != asdict(namespace) or raw['operation_id'] != operation_id or raw['request_digest'] != request_digest):
        raise ValueError('Contact background original exact locator differs')
    issuer._signer.verify(SIGN_KIND,canonical_serialize((namespace,operation_id,request_digest,value.digest)),row[3])
    return value


def require_contact_background_deadline_v1(call, scope, result):
    require_contact_background_call_v1(call)
    if call.request.segment_index>0:
        from .contact_continuation_readback_v1 import require_contact_continuation_deadline_v1
        return require_contact_continuation_deadline_v1(call,scope,result)
    from .first_ingress_v2 import trusted_upper
    graph = call.runtime.graph
    now = trusted_upper(graph._GraphCoordinator__content_fence_v2.read_ingress_clock(graph._GraphCoordinator__scene_clock_policy))
    raw = _require_contact_background_live_sql_v1(call,scope,result,now)
    require_core_contact_background_original_v1(call,scope,result,raw)


def _require_contact_background_live_sql_v1(call, scope, result, now):
    require_contact_background_call_v1(call)
    from .contact_final_ack_v1 import _readonly
    from .contact_saved_owner_projection_v3 import _require_live, _live_terms
    graph = call.runtime.graph
    store = graph._GraphCoordinator__store
    evidence = _readonly(call,result)
    with store._lock:
        store._db.execute('BEGIN')
        try:
            raw = json.loads(read_contact_background_invocation_v1(store._db,graph._GraphCoordinator__d11_issuer,
                scope.namespace,call.operation_id,call.request_digest).payload_json)
            if not now < raw['deadline_utc']:
                raise ValueError('Contact background original deadline expired; HOLD')
            _require_live(evidence,now,*_live_terms(store._db,call))
            return raw
        finally:
            store._db.rollback()


def recover_contact_background_saved_v1(call, scope, result, state):
    require_contact_background_call_v1(call)
    if call.request.segment_index>0:
        from .contact_continuation_readback_v1 import recover_contact_continuation_background_saved_v1
        return recover_contact_continuation_background_saved_v1(call,scope,result,state)
    from .contact_final_ack_v1 import _readonly, require_contact_finish_ack_v1
    from .domain_followup_consumer_v1 import _observe_owner
    from .contact_saved_owner_projection_v3 import _owner_binding_wire_v3
    graph = call.runtime.graph
    port = graph._GraphCoordinator__content_fence_v2
    store = graph._GraphCoordinator__store
    def snapshot():
        evidence = _readonly(call,result)
        with store._lock:
            store._db.execute('BEGIN')
            try:
                original = read_contact_background_invocation_v1(store._db,graph._GraphCoordinator__d11_issuer,
                    scope.namespace,call.operation_id,call.request_digest)
                raw = json.loads(original.payload_json)
                from ..authority_service.v2_contract import to_wire
                expected = asdict(scope)
                expected['permit'] = to_wire(scope.permit)
                if raw['scope'] != expected or raw['result'] != result or raw['request'] != asdict(call.request):
                    raise ValueError('Contact background saved invocation original scope/result differs')
                from .domain_production_originals_v1 import read_adopted_domain_operation_v1
                if canonical_digest(read_adopted_domain_operation_v1(store._db,scope.namespace,
                        call.operation_id)['payload']['provenance']) != raw['provenance_digest']:
                    raise ValueError('Contact background saved eleven-member provenance changed')
                return evidence, raw
            finally:
                store._db.rollback()
    evidence, raw = snapshot()
    if state == 'active':
        guard, owner = _observe_owner(graph,call.authority,scope)
        policy = graph._GraphCoordinator__c04_authority_port_v3.contact_policy(scope.permit,'read_current',
            policy_id=evidence.owner_policy.policy.policy_id)
        if policy != evidence.owner_policy or _owner_binding_wire_v3(owner) != _owner_binding_wire_v3(owner_binding_from_wire_v3(raw['owner'])):
            raise ValueError('Contact background saved current Owner/standing policy differs')
        require_contact_background_deadline_v1(call,scope,result)
        if snapshot() != (evidence,raw):
            raise ValueError('Contact background saved originals changed across current observation')
        finish = 'sha256:' + canonical_digest({'schema':'w01.owner-domain-write.v3','operation_id':call.operation_id,
            'request_digest':call.request_digest,'permit_token':scope.permit.token})
        port.finish_fence(scope,request_id='finish:'+scope.operation_id,request_digest=finish)
    require_contact_finish_ack_v1(call,scope)
    captured = []
    observed_now = []
    def observe(current_scope):
        guard, owner = _observe_owner(graph,call.authority,current_scope)
        policy = graph._GraphCoordinator__c04_authority_port_v3.contact_policy(current_scope.permit,'read_current',
            policy_id=evidence.owner_policy.policy.policy_id)
        if (policy != evidence.owner_policy or owner.authorization_head != raw['observation']['owner_head_digest']
                or owner.authorization_revision != raw['observation']['owner_revision']
                or current_scope.pinned_anchor != scope.pinned_anchor):
            raise ValueError('Contact background finished original has no current standing authorization')
        require_core_contact_background_original_v1(call,current_scope,result,raw)
        from .first_ingress_v2 import trusted_upper
        observed_now.append(trusted_upper(port.read_ingress_clock(graph._GraphCoordinator__scene_clock_policy)))
        captured.append(owner)
        return guard, owner
    def read():
        if not captured or snapshot() != (evidence,raw):
            raise ValueError('Contact background finished read lost its exact current authorization')
        _require_contact_background_live_sql_v1(call,scope,result,observed_now[0])
        return result
    return graph._read_v2(call.authority,read,fence_observer=observe)


@dataclass(frozen=True, slots=True)
class _BackgroundContactRecoveryV1:
    graph: object
    authority: object
    owner: object
    operation_id: str
    command: object
    original_digest: str

_RECOVERY = {}


def require_background_contact_recovery_v1(value, graph, authority, operation_id):
    if (type(value) is not _BackgroundContactRecoveryV1 or _RECOVERY.get(id(value)) is not value
            or value.graph is not graph or value.authority is not authority or value.operation_id != operation_id):
        raise ValueError('Contact background recovery lacks its exact durable invocation')
    return value.owner


def recover_contact_background_dispatch_v1(graph, bootstrap, bundle, *, operation_id):
    from .contact_continuation_readback_v1 import recover_contact_continuation_background_dispatch_v1
    handled,value=recover_contact_continuation_background_dispatch_v1(graph,bootstrap,bundle,operation_id=operation_id)
    if handled:return value
    from .domain_followup_consumer_v1 import _observe_owner
    from .contact_followup_v1 import ContactFollowupCommandV1
    from .contact_final_stage_v3 import PrepareCurrentContactDispatchRequestV3
    from ..runtime_contracts import AuthorityContext
    graph._admin(bootstrap)
    assembly = graph._GraphCoordinator__d04_installed_joint_assembly
    if assembly is None or assembly.admin_bundle is not bundle:
        raise ValueError('Contact background recovery requires its actual installed assembly')
    runtime = graph._GraphCoordinator__domain_production_runtime_v1
    runtime._current()
    ns = bundle.installation_policy.namespace
    store = graph._GraphCoordinator__store
    with store._lock:
        store._db.execute('BEGIN')
        try:
            row = store._db.execute(f'SELECT request_digest FROM {TABLE} WHERE bot=? AND persona=? AND operation_id=?',
                (*ns.as_tuple,operation_id)).fetchone()
            if row is None:
                raise ValueError('Contact background recovery immutable original absent; HOLD')
            original = read_contact_background_invocation_v1(store._db,graph._GraphCoordinator__d11_issuer,ns,operation_id,row[0])
            raw = json.loads(original.payload_json)
            owner = owner_binding_from_wire_v3(raw['owner'])
            attempt = store._db.execute('SELECT receipt_json FROM graph_owner_domain_attempts_v3 '
                'WHERE bot=? AND persona=? AND operation_id=?',(*ns.as_tuple,operation_id)).fetchone()
            if attempt != (canonical_serialize(raw['result']),):
                raise ValueError('Contact background recovery actual durable attempt differs')
        finally:
            store._db.rollback()
    authority = AuthorityContext(owner.actor,'d12','installed-contact-recovery:'+operation_id,ns,(owner.scope,),
        'expression',(raw['command']['audience_ref'],),'owner-grant-v1',raw['scope']['generation'])
    captured = []
    def observe(scope):
        current = _observe_owner(graph,authority,scope)
        captured.append(current[1])
        return current
    graph._read_v2(authority,lambda:None,fence_observer=observe)
    request = PrepareCurrentContactDispatchRequestV3(**raw['request'])
    command = ContactFollowupCommandV1('d08','prepare_contact_dispatch_v3',request,
        raw['command']['activity_id'],raw['command']['audience_ref'],operation_id=operation_id)
    issued = _BackgroundContactRecoveryV1(graph,authority,captured[0],operation_id,command,original.digest)
    _RECOVERY[id(issued)] = issued
    try:
        return runtime.run_current(authority,None,operation_kind='prepare_contact_dispatch_v3',request=request,
            operation_id=operation_id,activity_id=command.activity_id,audience_ref=command.audience_ref,
            parent_budget_lease_ref=raw['command']['parent_budget_lease_ref'],_background_contact_recovery=issued)
    finally:
        _RECOVERY.pop(id(issued),None)



def validate_contact_background_inventory_row_v1(columns, row):
    if tuple(columns) != ('bot','persona','operation_id','request_digest','payload_json','payload_digest','signature'):
        raise ValueError('C09 Contact background Graph inventory exact columns differ')
    value = ContactBackgroundInvocationOriginalV1(row[4])
    raw = json.loads(value.payload_json)
    if (row[:4] != (raw['namespace']['bot_id'],raw['namespace']['persona_id'],raw['operation_id'],raw['request_digest'])
            or value.digest != row[5] or type(row[6]) is not str or not row[6]):
        raise ValueError('C09 Contact background Graph exact original row differs')
    return value



def require_core_contact_background_original_v1(call, current_scope, result, raw):
    require_contact_background_call_v1(call)
    graph = call.runtime.graph
    store = graph._GraphCoordinator__store
    if store._db.in_transaction or store._lock._is_owned():
        raise ValueError('Contact background Core original read must be outside Graph SQL lock')
    from .contact_final_ack_v1 import _readonly
    evidence = _readonly(call,result)
    observed = graph._GraphCoordinator__content_fence_v2.read_contact_background_observation_v1(
        namespace=current_scope.namespace,authority_namespace=current_scope.authority_namespace,permit=current_scope.permit,
        selector={'namespace':raw['namespace'],'contact_id':raw['request']['contact_id'],
            'operation_id':call.operation_id,'request_digest':call.request_digest,
            'policy_id':evidence.owner_policy.policy.policy_id,'dedupe_key':raw['observation']['inputs']['dedupe_key']})
    if observed['observation'] != raw['observation']:
        raise ValueError('Contact background authenticated Core durable original differs')
    return observed
