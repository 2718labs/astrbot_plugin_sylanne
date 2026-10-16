"""Core derives and records an exact standing-policy background observation."""
from dataclasses import asdict
import hmac
import json
import sqlite3

from .contract import AuthorityUnavailable
from .v2_contract import from_wire
from .d12_target_owner_rpc_v1 import dispatch_d12_target_owner_v1, BACKGROUND_METHOD
from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize

METHOD = 'capture_contact_background_invocation_v1'
READ_METHOD = 'read_contact_background_observation_v1'
TABLE = 'authority_contact_background_observations_v1'
DDL = f'''CREATE TABLE {TABLE}(authority_namespace TEXT NOT NULL,installation_id TEXT NOT NULL,
operation_id TEXT NOT NULL,request_digest TEXT NOT NULL,payload_json TEXT NOT NULL,
payload_digest TEXT NOT NULL,signature TEXT NOT NULL,PRIMARY KEY(authority_namespace,installation_id,operation_id))'''
TRIGGERS = tuple(f"CREATE TRIGGER {TABLE}_no_{a.lower()} BEFORE {a} ON {TABLE} "
    "BEGIN SELECT RAISE(ABORT,'Contact background observation immutable'); END" for a in ('UPDATE','DELETE'))
SELECTOR_FIELDS = {'namespace','contact_id','operation_id','request_digest','policy_id','dedupe_key'}
OBSERVATION_FIELDS = {'schema','authority_id','authority_namespace','installation_id','permit_digest',
    'anchor_digest','owner_authority_digest','owner_actor','principal_epoch','owner_head_digest',
    'owner_revision','policy_original_ref','policy_original_digest','window_id','inputs','deadline_utc',
    'observation_ref','signature'}


def require_background_observation_schema_v1(db):
    with sqlite3.connect(':memory:') as expected:
        expected.execute(DDL)
        for sql in TRIGGERS:
            expected.execute(sql)
        query = 'SELECT type,name,sql FROM sqlite_master WHERE tbl_name=? AND sql IS NOT NULL ORDER BY type,name'
        if tuple(db.execute(query,(TABLE,))) != tuple(expected.execute(query,(TABLE,))):
            raise ValueError('Contact background Core original schema differs; HOLD')


def install_background_observation_schema_v1(db, *, create):
    if create:
        db.execute(DDL.replace('CREATE TABLE ', 'CREATE TABLE IF NOT EXISTS ', 1))
        for sql in TRIGGERS:
            db.execute(sql.replace('CREATE TRIGGER ', 'CREATE TRIGGER IF NOT EXISTS ', 1))
    require_background_observation_schema_v1(db)


def validate_background_observation_v1(raw):
    from ..runtime.contact_background_inputs_v1 import validate_background_inputs_v1
    if type(raw) is not dict or set(raw) != OBSERVATION_FIELDS or raw['schema'] != 'd10.contact-background-observation.v1':
        raise ValueError('Contact background observation closed fields differ')
    validate_background_inputs_v1(raw['inputs'])
    if (raw['observation_ref'] != 'contact-background-observation:' + canonical_digest({k:v for k,v in raw.items()
            if k not in {'observation_ref','signature'}})
            or type(raw['signature']) is not str or len(raw['signature']) != 64
            or not raw['deadline_utc'] <= raw['inputs']['deadline_utc']):
        raise ValueError('Contact background observation original commitment/deadline differs')
    return raw


def validate_background_observation_row_v1(columns, row):
    if tuple(columns) != ('authority_namespace','installation_id','operation_id','request_digest','payload_json','payload_digest','signature'):
        raise ValueError('Contact background Core columns differ')
    raw = validate_background_observation_v1(json.loads(row[4]))
    if (row[:4] != (raw['authority_namespace'],raw['installation_id'],raw['inputs']['operation_id'],raw['inputs']['request_digest'])
            or canonical_serialize(raw) != row[4] or canonical_digest(raw) != row[5] or raw['signature'] != row[6]):
        raise ValueError('Contact background Core exact row differs')
    return raw


def dispatch_contact_background_v1(server, method, credential, profile_id, manifest_digest, command):
    if method not in {METHOD,READ_METHOD}:
        return None
    if type(command) is not dict or set(command) != {'namespace','permit','selector'}:
        raise AuthorityUnavailable('Contact background RPC closed fields differ')
    selector = command['selector']
    if type(selector) is not dict or set(selector) != SELECTOR_FIELDS:
        raise AuthorityUnavailable('Contact background selector closed fields differ')
    namespace = command['namespace']
    fences = server._bound_v2_service(credential,profile_id,manifest_digest,namespace)
    installation = server._installations_v2[(credential.certificate_sha256,profile_id)]
    service = server._contact_model_reads_v2.get(namespace)
    permit = from_wire(command['permit'])
    if (service is None or service._fences is not fences
            or permit.operation not in ({'write'} if method == METHOD else {'read','write'})
            or permit.holder != installation.administrator_holder):
        raise AuthorityUnavailable('Contact background actual installed paid reader unavailable')
    policy_service = service._policy
    subject = 'mtls:sha256:' + credential.certificate_sha256
    observed = dispatch_d12_target_owner_v1(server,BACKGROUND_METHOD,credential,profile_id,manifest_digest,
        {'namespace':namespace,'permit':command['permit']})
    policy = policy_service.read_current(credential=credential,subject=subject,permit=permit,policy_id=selector['policy_id'])
    if policy is None:
        raise AuthorityUnavailable('Contact standing consent was withdrawn or expired')
    ns = NamespaceId(**selector['namespace'])
    if ns != policy.namespace or service._installation_id != installation.installation_id:
        raise AuthorityUnavailable('Contact background namespace/policy installation differs')
    location = service._location.observe_business_for_fence_v1(credential=credential,subject=subject,permit=permit)
    from .contact_background_graph_v3 import ContactBackgroundSelectorV3, begin_contact_authority_graph_read_v3
    from .current_authority_graph_read_v3 import read_authority_graph_current_v3, finish_authority_graph_read_work_v3
    from ..runtime.contact_background_inputs_v1 import read_contact_background_inputs_v1
    selected = ContactBackgroundSelectorV3(ns,selector['contact_id'],selector['operation_id'],
        selector['request_digest'],selector['policy_id'],selector['dedupe_key'])
    work = begin_contact_authority_graph_read_v3(service,credential=credential,subject=subject,permit=permit,
        selector=selected,policy=policy,location=location)
    def graph_read(db):
        values = read_contact_background_inputs_v1(db,namespace=ns,contact_id=selected.contact_id,
            operation_id=selected.operation_id,request_digest=selected.request_digest,dedupe_key=selected.dedupe_key,
            issuer=service._issuer,now=service._clock(),owner_actor=policy.owner_actor_id)
        terms, results, plan, content = values
        if (plan.policy_original_ref,plan.policy_original_digest) != (policy.original_ref,policy.digest):
            raise AuthorityUnavailable('Contact actual signed plan policy changed')
        return terms,results
    try:
        inputs,results = read_authority_graph_current_v3(work,graph_read)
        # Core terminal IO is outside every Graph storage quantum and SQL transaction.
        for result in results:
            intent,terminal,actual = service._read_original(result.request,permit.pinned_anchor,content=True)
            if terminal != result.terminal_receipt or actual != result.observation:
                raise AuthorityUnavailable('Contact Core actual paid terminal differs from Graph original')
        if read_authority_graph_current_v3(work,graph_read) != (inputs,results):
            raise AuthorityUnavailable('Contact Core exact same-Work input snapshot drifted')
    finally:
        finish_authority_graph_read_work_v3(work)
    after = dispatch_d12_target_owner_v1(server,BACKGROUND_METHOD,credential,profile_id,manifest_digest,
        {'namespace':namespace,'permit':command['permit']})
    if after != observed or policy_service.read_current(credential=credential,subject=subject,permit=permit,
            policy_id=selector['policy_id']) != policy:
        raise AuthorityUnavailable('Contact background Owner/standing policy changed across capture')
    material = dict(schema='d10.contact-background-observation.v1',authority_id=permit.authority_id,
        authority_namespace=namespace,installation_id=installation.installation_id,permit_digest=canonical_digest(command['permit']),
        anchor_digest=canonical_digest(asdict(permit.pinned_anchor)),owner_authority_digest=canonical_digest(observed),
        owner_actor=policy.owner_actor_id,principal_epoch=policy.owner_principal_epoch,owner_head_digest=policy.owner_head_digest,
        owner_revision=policy.owner_authorization_revision,policy_original_ref=policy.original_ref,
        policy_original_digest=policy.digest,window_id=policy.window_id,inputs=inputs,
        deadline_utc=min(inputs['deadline_utc'],policy.policy.window_end))
    material['observation_ref'] = 'contact-background-observation:' + canonical_digest(material)
    material['signature'] = policy_service._sign(material)
    validate_background_observation_v1(material)
    with fences.core._tx() as db:
        require_background_observation_schema_v1(db)
        service._location.require_current_in_tx_v1(db,location)
        row = db.execute(f'SELECT * FROM {TABLE} WHERE authority_namespace=? AND installation_id=? AND operation_id=?',
            (namespace,installation.installation_id,selector['operation_id'])).fetchone()
        if row is not None:
            original = validate_background_observation_row_v1(('authority_namespace','installation_id','operation_id','request_digest',
                'payload_json','payload_digest','signature'),row)
            signature = original['signature']
            if not hmac.compare_digest(signature,policy_service._sign({k:v for k,v in original.items() if k != 'signature'})):
                raise AuthorityUnavailable('Contact background saved Core signature differs')
            if method == READ_METHOD:
                old = original['inputs']
                current = material['inputs']
                stable_fields = set(old) - {'graph_revision','graph_epoch'}
                if (any(old[key] != current[key] for key in stable_fields)
                        or current['graph_revision'] != old['graph_revision'] + 1
                        or current['graph_epoch'] != old['graph_epoch'] + 1
                        or not service._clock() < original['deadline_utc']
                        or any(original[key] != material[key] for key in ('authority_id','authority_namespace','installation_id',
                            'owner_actor','principal_epoch','owner_head_digest','owner_revision','policy_original_ref','policy_original_digest','window_id'))):
                    raise AuthorityUnavailable('Contact background current original recovery scope/deadline differs')
                material = original
            elif original != material:
                raise AuthorityUnavailable('Contact background original invocation cannot be replaced')
        else:
            if method == READ_METHOD:
                raise AuthorityUnavailable('Contact background Core original absent; no backfill; HOLD')
            db.execute(f'INSERT INTO {TABLE} VALUES(?,?,?,?,?,?,?)',(namespace,installation.installation_id,
                selector['operation_id'],selector['request_digest'],canonical_serialize(material),canonical_digest(material),material['signature']))
    fences.validate_fence(credential=credential,subject=subject,permit=permit)
    return {'observation':material,'authority':observed}
