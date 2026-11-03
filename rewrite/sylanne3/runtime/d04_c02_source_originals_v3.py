"""Independent installed D04 C02 originals and current D03 account route.

The three validators preserve the actual existing product joins. Their original
columns come only from this module's finite selected C02 recipes and full EOF.
No Natural/P2/FULL identity or generic Host attachment permission is issued.
"""
from dataclasses import asdict
import json
import math
from ..contracts import canonical_json, EventConflict
from ..domains.d03.context import AccountBinding, EntityAnchor, WorldEvent
from ..graph_types import AtomKey, GraphVersion, GraphSnapshot, Owner
from ..memory_types import SourceRecord, access_key, source_key, validate_access
from ..runtime_contracts import NamespaceId, QueryEpoch, CommitReceipt, canonical_digest, canonical_serialize
from .reply_model_job import (D02ResourceIssuer, ReplyModelJobHold, ReplySourceSnapshot,
    SettledC02ReplySourceV1, CurrentReplyRouteManifestV2, CurrentReplyModelInputsV1,
    _PreparedCurrentReplyModelInputsV3, _PreparedFullReplyModelInputsV3,
    _PreparedAuthorityReplyModelInputsV3, source_key_from_ref)
from .reply_entity_route_v2 import CurrentReplyEntityRouteBindingV2, ReplyEntityRouteHold
from .first_ingress_v2 import scene_ref_for_conversation
from .ingress_observation import IngressIdentityReceipt, ingress_ids
from .dispatch_initial_source_read_v3 import DispatchOriginalJSONReadV3

_JSON_COLUMNS = frozenset({'bundle_json','quote_json','receipt_json','identity_json','reads','revisions'})


def _actual(owner):
    from .d04_source_work_v3 import require_installed_d04_source_reader_v3
    return require_installed_d04_source_reader_v3(owner)


def _point(owner, table, columns, key_columns, key):
    _actual(owner)
    where = ' AND '.join(name+'=?' for name in key_columns)
    plain = tuple(name for name in columns if name not in _JSON_COLUMNS)
    # The selected key is resolved first without loading a text column.
    locator = plain or (key_columns[0],)
    with owner.quantum_v3() as meter:
        row = meter.read_fixed_row(owner.db,table,locator,where,key)
    if row is None:
        return None
    found = dict(zip(locator,row))
    for name in columns:
        if name not in _JSON_COLUMNS:
            continue
        cache = (table,name,key_columns,key)
        if cache not in owner.c02_columns:
            column = DispatchOriginalJSONReadV3(owner,table=table,column=name,
                key_columns=key_columns,key=key)
            while not column.complete:
                with owner.quantum_v3() as meter:
                    column.advance(meter)
            value = column.require_v3(owner)
            wire = canonical_serialize(value)
            if canonical_digest(value) != column.sha256:
                raise ReplyModelJobHold('D04 original JSON full canonical EOF differs')
            owner.c02_columns[cache] = (column,value,wire)
        found[name] = owner.c02_columns[cache][2]
    return tuple(found[name] for name in columns)


class _Rows:
    def __init__(self, rows):
        self.rows = rows
    def fetchone(self):
        return self.rows[0] if self.rows else None
    def fetchall(self):
        return list(self.rows)


def _load_sql(owner, db, sql, args=()):
    _actual(owner)
    if db is not owner.db:
        raise ReplyModelJobHold('D04 C02 originals crossed the actual selected storage')
    sql = ' '.join(sql.split())
    if sql not in _RECIPES:
        raise ReplyModelJobHold('D04 C02 original query is outside the finite actual validator')
    label = _RECIPES[sql]
    ns, op, source_ref = owner.namespace,owner.selector.c02_operation_id,owner.selector.source_ref
    source_id = AtomKey.from_token(source_ref).owner.subject
    if label == 'accounts':
        if args != ns.as_tuple:
            raise ReplyModelJobHold('D04 account census namespace changed')
        return _Rows(tuple((a.key.token,a.revision,canonical_serialize(a.value))
            for a in owner.snapshot.atoms if a.valid and a.key.type_name == 'd03.account_binding'))
    if label == 'epoch':
        if args != ns.as_tuple:
            raise ReplyModelJobHold('D04 actual query epoch namespace changed')
        return _Rows(((owner.graph_stamp[1].revision,),))
    if label in {'atom_exists','atom_revision'}:
        key = AtomKey.from_token(args[0])
        head = owner.namespace_reader.heads.get(key.token)
        rows = () if head is None or label == 'atom_exists' and not head[1] else (
            (1,) if label == 'atom_exists' else (head[0],int(head[1])),)
        return _Rows(rows)
    if label == 'ingress':
        if args != (*ns.as_tuple,source_id):
            raise ReplyModelJobHold('D04 ingress source differs from the actual selected C02')
        first = _point(owner,'graph_first_ingress_identity_v1',
            ('operation_id','conversation_ref','visibility'),('bot','persona','source_ref'),args)
        if first is None:
            return _Rows(())
        with owner.quantum_v3() as meter:
            second = meter.read_fixed_row(db,'graph_first_ingress_identity_v1',('operation_id',),
                'bot=? AND persona=? AND source_ref=? AND operation_id!=?',
                (*args,first[0]))
        if second is not None:
            raise ReplyModelJobHold('D04 ingress source has multiple actual originals')
        return _Rows((first,))
    if label == 'dependency':
        expected = (access_key(*ns.as_tuple,source_id).token,source_ref)
        if args != expected:
            raise ReplyModelJobHold('D04 event Source/access dependency selection changed')
        value = _point(owner,'graph_dependencies',('dependency_revision',),
            ('dependent_token','dependency_token'),args)
    elif label == 'reservation':
        if args != (owner.c02_quote.parent_budget_lease_ref,op):
            raise ReplyModelJobHold('D04 C02 reservation selection changed')
        value = _point(owner,'runtime_budget_reservations',('state',),('lease_id','operation_id'),args)
    elif label == 'budget_settle':
        if args != (*ns.as_tuple,op):
            raise ReplyModelJobHold('D04 original C02 budget settlement identity changed')
        value = _point(owner,'runtime_budget_operations',('operation_id',),
            ('bot_id','persona_id','operation_id','phase'),(*args,'settle'))
        value = None if value is None else (1,)
    else:
        recipes = {
            'archive':('graph_first_ingress_c02_committed_seals_v2',
                ('schema','bundle_digest','bundle_json','quote_json')),
            'seal_digest':('graph_first_ingress_c02_committed_seals_v2',('bundle_digest',)),
            'business':('graph_bundle_operations',('digest','activity_id','receipt_json')),
            'cost':('graph_bundle_operations',('activity_id','receipt_json')),
            'operation_digest':('graph_bundle_operations',('digest',)),
            'cost_state':('graph_c02_cost_attempts_v1',('state',)),
            'arrival':('graph_d03_arrival_issuance_v2',('source_ref','bundle_digest')),
        }
        table,columns = recipes[label]
        allowed = {op, 'c02-cost-'+canonical_digest({'namespace':list(ns.as_tuple),'operation_id':op})[:48],
            'd03-arrival-'+canonical_digest({'namespace':list(ns.as_tuple),'source_ref':source_id})[:40],
            ingress_ids(source_id)[2]}
        if args[:2] != ns.as_tuple or args[2] not in allowed:
            raise ReplyModelJobHold('D04 C02 selected original operation changed')
        value = _point(owner,table,columns,('bot','persona','operation_id'),args)
    return _Rows(() if value is None else (value,))


def _sql(owner,db,sql,args=()):
    _actual(owner)
    sql = ' '.join(sql.split())
    key = (sql,tuple(args))
    if key in owner.c02_points:
        return _Rows(owner.c02_points[key])
    label = _RECIPES.get(sql)
    if db.in_transaction and label not in {'atom_exists','atom_revision','accounts','epoch'}:
        raise ReplyModelJobHold('D04 C02 validator has no complete prepared original for this exact point')
    result = _load_sql(owner,db,sql,args)
    owner.c02_points[key] = tuple(result.rows)
    return result


def _quote_original(owner, issuer, quote_id, version):
    from .issuers import d06_first_ingress_c02_quote_id, _decode_quote
    _actual(owner)
    if (issuer is not owner.graph._GraphCoordinator__d02_issuer or version != 1
            or quote_id != d06_first_ingress_c02_quote_id(owner.namespace,owner.selector.c02_operation_id)):
        raise ReplyModelJobHold('D04 actual original C02 quote identity differs')
    if owner.c02_quote is not None:
        return owner.c02_quote
    row = _point(owner,'runtime_resource_quotes',('quote_json','signature'),
        ('quote_id','version'),(quote_id,version))
    if row is None:
        raise ReplyModelJobHold('D04 actual C02 quote original absent')
    issuer._signer.verify('resource-quote.v1',row[0],row[1])
    quote = _decode_quote(row[0])
    if (quote.quote_id,quote.version) != (quote_id,version):
        raise ReplyModelJobHold('D04 original signed quote changed its actual identity')
    owner.c02_quote = quote
    return quote


def _ingress(owner,db,namespace,source_id):
    _actual(owner)
    if db is not owner.db or namespace != owner.namespace or source_id != AtomKey.from_token(owner.selector.source_ref).owner.subject:
        raise ReplyEntityRouteHold('D04 original ingress crossed its selected Source')
    if owner.ingress_receipt is not None:
        return owner.ingress_receipt
    operation = ingress_ids(source_id)[2]
    key = (*namespace.as_tuple,operation)
    row = _point(owner,'graph_first_ingress_identity_v1',
        ('source_ref','platform_ref','conversation_ref','sender_ref','message_id','visibility',
         'identity_json','content_fingerprint','learned_at','bundle_digest'),
        ('bot','persona','operation_id'),key)
    if row is None:
        raise ReplyEntityRouteHold('D04 actual ingress identity original absent')
    identity = json.loads(row[6])
    expected_fields = {'schema','namespace','operation_id','source_ref','platform_ref',
        'conversation_ref','sender_ref','message_id','visibility','lineage'}
    observed = _point(owner,'ingress_first_observations',
        ('content_fingerprint','learned_at','bundle_digest'),('bot','persona','operation_id'),key)
    committed = _point(owner,'graph_bundle_operations',('digest',),('bot','persona','operation_id'),key)
    intent = _point(owner,'graph_first_ingress_intents_v2',('identity_json',),
        ('bot','persona','operation_id'),key)
    if (set(identity) != expected_fields or identity['schema'] != 'sylanne3.ingress.identity.v1'
            or identity['namespace'] != list(namespace.as_tuple) or identity['operation_id'] != operation
            or tuple(identity[name] for name in ('source_ref','platform_ref','conversation_ref',
                'sender_ref','message_id','visibility')) != row[:6]
            or identity['source_ref'] != source_id or canonical_json(identity) != row[6]
            or observed != row[7:10] or committed != (row[9],)
            or intent is None or json.loads(intent[0])['fingerprint'] != row[7]):
        raise EventConflict('D04 committed ingress identity differs from its actual original')
    owner.ingress_receipt = IngressIdentityReceipt(row[6],row[7],row[8],row[9])
    return owner.ingress_receipt


def _current_atom(owner,db,key,*,prepared_inventory=None):
    _actual(owner)
    if db is not owner.db or prepared_inventory is not None:
        raise ReplyEntityRouteHold('D04 current atom cannot borrow another prepared inventory')
    atom = owner.snapshot.get(key)
    if atom is None or atom.revision < 1 or not atom.valid:
        raise ReplyEntityRouteHold('D04 actual complete current atom unavailable')
    return GraphVersion(key,atom.revision),atom.value


def read_d04_route_metadata_v3(owner):
    source_id = AtomKey.from_token(owner.selector.source_ref).owner.subject
    original = _ingress(owner,owner.db,owner.namespace,source_id)
    return json.loads(original.identity_json)


def read_d04_c02_inputs_v3(owner):
    _actual(owner)
    ns,op = owner.namespace,owner.selector.c02_operation_id
    row = _point(owner,'graph_bundle_operations',
        ('digest','activity_id','effect_id','commit_seq','receipt_json'),
        ('bot','persona','operation_id'),(*ns.as_tuple,op))
    if row is None:
        raise ReplyModelJobHold('D04 selected C02 actual bundle receipt absent')
    event = _point(owner,'graph_events',('reads','revisions','epoch_revision'),
        ('bot','persona','session','event_id'),(*ns.as_tuple,row[1],op))
    if event is None:
        raise ReplyModelJobHold('D04 C02 original Graph event absent')
    detail = json.loads(row[4])
    reads = tuple(GraphVersion(AtomKey.from_token(ref),rev) for ref,rev in json.loads(event[0]))
    writes = tuple(GraphVersion(AtomKey.from_token(ref),rev) for ref,rev in json.loads(event[1]))
    from ..graph_types import NamespaceEpoch
    receipt = CommitReceipt('committed',op,row[0],row[1],row[2],row[3],reads,writes,
        (NamespaceEpoch(*ns.as_tuple,event[2]),),tuple(detail['ledger_refs']),tuple(detail['outbox_refs']))
    from .issuers import d06_first_ingress_c02_quote_id
    _quote_original(owner,owner.graph._GraphCoordinator__d02_issuer,d06_first_ingress_c02_quote_id(ns,op),1)
    source_id = AtomKey.from_token(owner.selector.source_ref).owner.subject
    cost_op = 'c02-cost-'+canonical_digest({'namespace':list(ns.as_tuple),'operation_id':op})[:48]
    arrival = 'd03-arrival-'+canonical_digest({'namespace':list(ns.as_tuple),'source_ref':source_id})[:40]
    for sql,label in _RECIPES.items():
        if label in {'archive','seal_digest','business','cost_state','budget_settle'}:
            args = (*ns.as_tuple,op)
        elif label == 'cost':
            args = (*ns.as_tuple,cost_op)
        elif label == 'operation_digest':
            for selected in (op,arrival):
                _sql(owner,owner.db,sql,(*ns.as_tuple,selected))
            continue
        elif label == 'arrival':
            args = (*ns.as_tuple,arrival)
        elif label == 'ingress':
            args = (*ns.as_tuple,source_id)
        elif label == 'dependency':
            args = (access_key(*ns.as_tuple,source_id).token,owner.selector.source_ref)
        elif label == 'reservation':
            args = (owner.c02_quote.parent_budget_lease_ref,op)
        else:
            continue
        _sql(owner,owner.db,sql,args)
    with owner.quantum_v3():
        inputs = _settled(owner,owner.db,owner.graph._GraphCoordinator__d02_issuer,
            ns,receipt,owner.selector.source_ref,owner.snapshot)
        route = _route(owner,owner.db,ns,inputs,owner.selector.source_ref)
        binding = _entity(owner,owner.db,ns,route,owner.query,now_utc=owner.now_utc)
    return inputs,route,binding

_RECIPES = {
  "SELECT 1 FROM graph_atoms WHERE token=? AND valid=1": "atom_exists",
  "SELECT 1 FROM runtime_budget_operations WHERE bot_id=? AND persona_id=? AND operation_id=? AND phase='settle'": "budget_settle",
  "SELECT activity_id,receipt_json FROM graph_bundle_operations WHERE bot=? AND persona=? AND operation_id=?": "cost",
  "SELECT bundle_digest FROM graph_first_ingress_c02_committed_seals_v2 WHERE bot=? AND persona=? AND operation_id=?": "seal_digest",
  "SELECT dependency_revision FROM graph_dependencies WHERE dependent_token=? AND dependency_token=?": "dependency",
  "SELECT digest FROM graph_bundle_operations WHERE bot=? AND persona=? AND operation_id=?": "operation_digest",
  "SELECT digest,activity_id,receipt_json FROM graph_bundle_operations WHERE bot=? AND persona=? AND operation_id=?": "business",
  "SELECT operation_id,conversation_ref,visibility FROM graph_first_ingress_identity_v1 WHERE bot=? AND persona=? AND source_ref=?": "ingress",
  "SELECT revision FROM graph_epochs WHERE bot=? AND persona=?": "epoch",
  "SELECT revision,valid FROM graph_atoms WHERE token=?": "atom_revision",
  "SELECT schema,bundle_digest,bundle_json,quote_json FROM graph_first_ingress_c02_committed_seals_v2 WHERE bot=? AND persona=? AND operation_id=?": "archive",
  "SELECT source_ref,bundle_digest FROM graph_d03_arrival_issuance_v2 WHERE bot=? AND persona=? AND operation_id=?": "arrival",
  "SELECT state FROM graph_c02_cost_attempts_v1 WHERE bot=? AND persona=? AND operation_id=?": "cost_state",
  "SELECT state FROM runtime_budget_reservations WHERE lease_id=? AND operation_id=?": "reservation",
  "SELECT token,revision,value FROM graph_atoms WHERE bot=? AND persona=? AND type_name='d03.account_binding' AND valid=1 ORDER BY token": "accounts"
}

def _settled(
    owner, db, issuer: D02ResourceIssuer, namespace: NamespaceId,
    c02_receipt: CommitReceipt, source_ref: str,
    snapshot: GraphSnapshot,
) -> SettledC02ReplySourceV1:
    """Read current D06 source/access and the original settled v2 C02."""
    from .c02_bundle_codec import c02_bundle_from_wire
    from .issuers import d06_first_ingress_c02_quote_id

    if (not db.in_transaction or type(issuer) is not D02ResourceIssuer
            or type(c02_receipt) is not CommitReceipt
            or c02_receipt.status != "committed"
            or type(snapshot) is not GraphSnapshot
            or len(snapshot.epochs) != 1
            or snapshot.epochs[0].bot != namespace.bot_id
            or snapshot.epochs[0].persona != namespace.persona_id):
        raise ReplyModelJobHold("transactional current C02 source read required")
    op = c02_receipt.operation_id
    archived = _sql(owner, db,
        "SELECT schema,bundle_digest,bundle_json,quote_json "
        "FROM graph_first_ingress_c02_committed_seals_v2 "
        "WHERE bot=? AND persona=? AND operation_id=?",
        namespace.as_tuple + (op,),
    ).fetchone()
    business = _sql(owner, db,
        "SELECT digest,activity_id,receipt_json FROM graph_bundle_operations "
        "WHERE bot=? AND persona=? AND operation_id=?",
        namespace.as_tuple + (op,),
    ).fetchone()
    cost_state = _sql(owner, db,
        "SELECT state FROM graph_c02_cost_attempts_v1 WHERE bot=? "
        "AND persona=? AND operation_id=?",
        namespace.as_tuple + (op,),
    ).fetchone()
    cost_op = "c02-cost-" + canonical_digest({
        "namespace": list(namespace.as_tuple), "operation_id": op})[:48]
    cost = _sql(owner, db,
        "SELECT activity_id,receipt_json FROM graph_bundle_operations "
        "WHERE bot=? AND persona=? AND operation_id=?",
        namespace.as_tuple + (cost_op,),
    ).fetchone()
    if (archived is None or business is None or cost_state != ("committed",)
            or cost is None
            or archived[0] != "sylanne.first-ingress-c02-candidate.v2"
            or archived[1] != c02_receipt.operation_digest
            or business[:2] != (c02_receipt.operation_digest,
                                c02_receipt.activity_id)
            or cost[0] != c02_receipt.activity_id):
        raise ReplyModelJobHold("original v2 C02 or cost is not committed")
    try:
        bundle = c02_bundle_from_wire(archived[2])
        source_id = source_key_from_ref(source_ref, namespace)
        source_key_value = source_key(*namespace.as_tuple, source_id)
        access_key_value = access_key(*namespace.as_tuple, source_id)
        source_atom = snapshot.get(source_key_value)
        access_atom = snapshot.get(access_key_value)
        source = SourceRecord.from_dict(source_atom.value)
        validate_access(access_atom.value)
        quote = _quote_original(owner, issuer, d06_first_ingress_c02_quote_id(namespace, op), 1)
        cost_detail = json.loads(cost[1])
        business_detail = json.loads(business[2])["first_ingress_c02"]
    except (TypeError, ValueError, KeyError, AttributeError,
            json.JSONDecodeError) as exc:
        raise ReplyModelJobHold("original C02 or current source is invalid") from exc
    source_receipt_versions = tuple(
        version for version in c02_receipt.write_versions
        if version.key.type_name in {
            "memory.episode.v1", "memory.subjective_trace.v2"})
    ingress = _sql(owner, db,
        "SELECT operation_id,conversation_ref,visibility FROM "
        "graph_first_ingress_identity_v1 WHERE bot=? AND persona=? "
        "AND source_ref=?", namespace.as_tuple + (source_id,),
    ).fetchall()
    dependency = _sql(owner, db,
        "SELECT dependency_revision FROM graph_dependencies "
        "WHERE dependent_token=? AND dependency_token=?",
        (access_key_value.token, source_ref),
    ).fetchone()
    reservation = _sql(owner, db,
        "SELECT state FROM runtime_budget_reservations "
        "WHERE lease_id=? AND operation_id=?",
        (quote.parent_budget_lease_ref, op),
    ).fetchone()
    if (bundle.envelope.identity.operation_id != op
            or bundle.envelope.source_qualification.source_refs != (source_ref,)
            or business_detail.get("seal_schema") != archived[0]
            or archived[3] != canonical_serialize(asdict(quote))
            or cost_detail.get("original_operation_id") != op
            or _sql(owner, db,
                "SELECT 1 FROM graph_atoms WHERE token=? AND valid=1",
                (cost_detail.get("cost_ref"),),
            ).fetchone() is None
            or _sql(owner, db,
                "SELECT 1 FROM runtime_budget_operations WHERE bot_id=? "
                "AND persona_id=? AND operation_id=? AND phase='settle'",
                namespace.as_tuple + (op,),
            ).fetchone() is None
            or reservation is None
            or reservation[0] not in {"unknown", "settled", "overrun"}
            or len(source_receipt_versions) != 2
            or any(_sql(owner, db,
                "SELECT revision,valid FROM graph_atoms WHERE token=?",
                (version.key.token,),
            ).fetchone() != (version.revision, 1)
                   for version in source_receipt_versions)
            or source_atom is None or access_atom is None
            or not source_atom.valid or not access_atom.valid
            or dependency != (source_atom.revision,)
            or source.source_id != access_atom.value["source_id"]
            or access_atom.value["status"] != "active"
            or "expression" not in source.purposes
            or "expression" not in access_atom.value["purposes"]
            or not set(access_atom.value["audiences"]).issubset(source.audiences)
            or len(ingress) != 1 or ingress[0][2] != "private"
            or ingress[0][1] not in access_atom.value["audiences"]):
        raise ReplyModelJobHold("settled C02 source, access or private audience differs")
    return SettledC02ReplySourceV1(
        c02_receipt, ReplySourceSnapshot(
            source, source_ref, source_atom.revision, access_atom.revision),
        ingress[0][1], bundle.envelope.source_qualification)


def _route(
    owner, db, namespace: NamespaceId, inputs: CurrentReplyModelInputsV1,
    source_ref: str,
) -> CurrentReplyRouteManifestV2:
    """Derive a reply route from the sealed ingress identity in this graph tx."""
    from .first_ingress_v2 import scene_ref_for_conversation

    if (not db.in_transaction or type(namespace) is not NamespaceId
            or type(inputs) not in {CurrentReplyModelInputsV1, SettledC02ReplySourceV1, _PreparedCurrentReplyModelInputsV3, _PreparedFullReplyModelInputsV3, _PreparedAuthorityReplyModelInputsV3}
            or inputs.c02_receipt.status != "committed"
            or inputs.source.source_ref != source_ref):
        raise ReplyModelJobHold("transactional original reply route required")
    if type(inputs) in (_PreparedCurrentReplyModelInputsV3,_PreparedFullReplyModelInputsV3,_PreparedAuthorityReplyModelInputsV3):
        inputs.require_for_v3(db,namespace,source_ref)
    source_id = source_key_from_ref(source_ref, namespace)
    natural_originals=None
    if type(inputs)is _PreparedCurrentReplyModelInputsV3 and inputs.prepared_inventory.family=="natural_reply":
        from .natural_dispatch_p2_c02_originals_v1 import require_prepared_natural_p2_c02_originals_v1
        natural_originals=require_prepared_natural_p2_c02_originals_v1(inputs.prepared_inventory,db,
            c02_operation_id=inputs.c02_receipt.operation_id,source_ref=source_ref)
    if natural_originals is None:
        original = _ingress(owner, db, namespace, source_id)
        if original is None:
            raise ReplyModelJobHold("original private ingress route is absent")
    try:
        identity = (json.loads(original.identity_json)if natural_originals is None
            else natural_originals.ingress_identity_v1(db,namespace,source_ref))
        platform_ref = identity["platform_ref"]
        conversation_ref = identity["conversation_ref"]
        visibility = identity["visibility"]
        platform = json.loads(platform_ref)
        conversation = json.loads(conversation_ref)
        if (visibility != "private"
                or conversation_ref != inputs.conversation_ref
                or type(platform) is not list or len(platform) != 3
                or type(conversation) is not list or len(conversation) != 2
                or any(type(item) is not str or not item
                       for item in (*platform, *conversation))
                or json.dumps(platform, ensure_ascii=True, separators=(",", ":"))
                   != platform_ref
                or json.dumps(conversation, ensure_ascii=True, separators=(",", ":"))
                   != conversation_ref):
            raise ReplyModelJobHold("original private reply route differs")
        scene_ref = scene_ref_for_conversation(
            namespace, platform_ref, conversation_ref)
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise ReplyModelJobHold("original private reply route is invalid") from exc
    return CurrentReplyRouteManifestV2(
        namespace, inputs.c02_receipt.operation_id, source_ref,
        platform_ref, conversation_ref, scene_ref,
        canonical_digest({
            "account_ref": platform_ref,
            "destination_ref": conversation_ref,
            "scene_ref": scene_ref,
        }),
    )


def _entity(
    owner, db, namespace: NamespaceId, route: CurrentReplyRouteManifestV2,
    query: QueryEpoch, *, now_utc: float, prepared_inventory=None,
) -> CurrentReplyEntityRouteBindingV2:
    """Join a settled C02 route to one current D03 account, with full scan."""
    from .domain_background_read_v3 import background_json_loads_v3
    if (not db.in_transaction or type(namespace) is not NamespaceId
            or type(route) is not CurrentReplyRouteManifestV2
            or type(query) is not QueryEpoch or query.namespace != namespace
            or query.scope_ref != "all" or route.namespace != namespace
            or type(now_utc) not in (int, float) or not math.isfinite(now_utc)):
        raise ReplyEntityRouteHold("current transactional reply route is required")
    natural_originals=None
    if prepared_inventory is not None and prepared_inventory.family=="natural_reply":
        from .natural_dispatch_p2_c02_originals_v1 import require_prepared_natural_p2_c02_originals_v1
        natural_originals=require_prepared_natural_p2_c02_originals_v1(prepared_inventory,db,
            c02_operation_id=route.c02_operation_id,source_ref=route.source_ref)
    epoch = _sql(owner, db,
        "SELECT revision FROM graph_epochs WHERE bot=? AND persona=?",
        namespace.as_tuple,
    ).fetchone()
    if epoch != (query.revision,):
        raise ReplyEntityRouteHold("reply account graph query epoch changed")
    try:
        source_id = source_key_from_ref(route.source_ref, namespace)
        if natural_originals is None:
            original = _ingress(owner, db, namespace, source_id)
            if original is None:
                raise ReplyEntityRouteHold("original reply ingress identity is absent")
            identity = background_json_loads_v3(original.identity_json)
        else:
            identity=natural_originals.ingress_identity_v1(db,namespace,route.source_ref)
        platform_ref = identity["platform_ref"]
        sender_ref = identity["sender_ref"]
        conversation_ref = identity["conversation_ref"]
        message_id = identity["message_id"]
        if (identity["visibility"] != "private"
                or identity["source_ref"] != source_id
                or platform_ref != route.platform_ref
                or conversation_ref != route.conversation_ref
                or scene_ref_for_conversation(namespace, platform_ref,
                                              conversation_ref) != route.scene_ref):
            raise ReplyEntityRouteHold("original reply ingress route changed")
        if natural_originals is not None:
            c02=natural_originals.read_point_v1('graph_first_ingress_c02_committed_seals_v2',('bundle_digest',),
                'bot=? AND persona=? AND operation_id=?',(*namespace.as_tuple,route.c02_operation_id))
        else:
            c02 = _sql(owner, db,
                "SELECT bundle_digest FROM graph_first_ingress_c02_committed_seals_v2 "
                "WHERE bot=? AND persona=? AND operation_id=?",
                namespace.as_tuple + (route.c02_operation_id,),
            ).fetchone()
        if natural_originals is not None:
            c02_operation=natural_originals.read_point_v1('graph_bundle_operations',('digest',),
                'bot=? AND persona=? AND operation_id=?',(*namespace.as_tuple,route.c02_operation_id))
        else:
            c02_operation = _sql(owner, db,
                "SELECT digest FROM graph_bundle_operations WHERE bot=? AND persona=? "
                "AND operation_id=?", namespace.as_tuple + (route.c02_operation_id,),
            ).fetchone()
        if c02 is None or c02 != c02_operation:
            raise ReplyEntityRouteHold("original C02 seal is absent")
        arrival_operation_id = "d03-arrival-" + canonical_digest({
            "namespace": list(namespace.as_tuple), "source_ref": source_id,
        })[:40]
        if natural_originals is not None:
            arrival=natural_originals.read_point_v1('graph_d03_arrival_issuance_v2',('source_ref', 'bundle_digest'),
                'bot=? AND persona=? AND operation_id=?',(*namespace.as_tuple,arrival_operation_id))
        else:
            arrival = _sql(owner, db,
                "SELECT source_ref,bundle_digest FROM graph_d03_arrival_issuance_v2 "
                "WHERE bot=? AND persona=? AND operation_id=?",
                namespace.as_tuple + (arrival_operation_id,),
            ).fetchone()
        if natural_originals is not None:
            arrival_operation=natural_originals.read_point_v1('graph_bundle_operations',('digest',),
                'bot=? AND persona=? AND operation_id=?',(*namespace.as_tuple,arrival_operation_id))
        else:
            arrival_operation = _sql(owner, db,
                "SELECT digest FROM graph_bundle_operations WHERE bot=? AND persona=? "
                "AND operation_id=?", namespace.as_tuple + (arrival_operation_id,),
            ).fetchone()
        if (arrival is None or arrival_operation is None
                or arrival != (source_id, arrival_operation[0])):
            raise ReplyEntityRouteHold("original D03 arrival seal is absent")
        source_version, source_value = _current_atom(
            owner, db, source_key(*namespace.as_tuple, source_id), prepared_inventory=prepared_inventory)
        access_version, access_value = _current_atom(
            owner, db, access_key(*namespace.as_tuple, source_id), prepared_inventory=prepared_inventory)
        source = (SourceRecord.from_dict(source_value)if prepared_inventory is None else
            prepared_inventory.source_metadata(db,namespace,query,source_key(*namespace.as_tuple,source_id),require_grant=False))
        validate_access(access_value)
        if (source.source_id != source_id or source.speaker_id != sender_ref
                or source.source_kind != "reported"
                or source.assertion_status != "reported"
                or source.audiences != (conversation_ref,)
                or access_value["source_id"] != source_id
                or access_value["status"] != "active"
                or conversation_ref not in access_value["audiences"]
                or "expression" not in access_value["purposes"]):
            raise ReplyEntityRouteHold("original reply source or access changed")
        account_identity = {
            "namespace": namespace.as_tuple,
            "platform_ref": platform_ref,
            "sender_ref": sender_ref,
        }
        suffix = canonical_digest(account_identity)
        target_entity_ref = "entity:account-v1:" + suffix
        account_id = "account:v1:" + suffix
        anchor_version, anchor_value = _current_atom(
            owner, db, AtomKey(Owner("persona", *namespace.as_tuple),
                        "d03.entity_anchor", target_entity_ref), prepared_inventory=prepared_inventory)
        binding_version, binding_value = _current_atom(
            owner, db, AtomKey(Owner("persona", *namespace.as_tuple),
                        "d03.account_binding", account_id), prepared_inventory=prepared_inventory)
        anchor = EntityAnchor(**{
            **anchor_value,
            "creation_evidence_refs": tuple(anchor_value["creation_evidence_refs"]),
        })
        binding = AccountBinding(**binding_value)
        if (anchor.entity_id != target_entity_ref or anchor.kind != "account"
                or anchor.owner_scope != f"persona:{namespace.persona_id}"
                or anchor.status != "active"
                or binding.account_id != account_id
                or binding.platform_namespace != platform_ref
                or binding.platform_identifier != sender_ref
                or binding.entity_id != target_entity_ref
                or binding.valid_from > now_utc
                or (binding.valid_until is not None
                    and now_utc >= binding.valid_until)):
            raise ReplyEntityRouteHold("current D03 account binding differs")
        event_id = "world:message-arrival-v1:" + canonical_digest({
            "namespace": namespace.as_tuple,
            "platform_ref": platform_ref,
            "conversation_ref": conversation_ref,
            "message_id": message_id,
            "source_id": source_id,
        })
        arrival_event_key = AtomKey(
            Owner("event", *namespace.as_tuple, event_id),
            "d03.world_event", "current",
        )
        arrival_event_version, arrival_event_value = _current_atom(
            owner, db, arrival_event_key, prepared_inventory=prepared_inventory)
        arrival_event = WorldEvent(**{
            **arrival_event_value,
            "participant_roles": tuple(tuple(role) for role in
                                       arrival_event_value["participant_roles"]),
            "source_refs": tuple(arrival_event_value["source_refs"]),
        })
        if (arrival_event.event_id != event_id
                or arrival_event.kind != "message_received"
                or arrival_event.reality != "host_observed"
                or arrival_event.scene_ref != route.scene_ref
                or arrival_event.participant_roles != (
                    (target_entity_ref, "sender_account"),)
                or arrival_event.source_refs != (route.source_ref,)
                or arrival_event.learned_at != source.recorded_at):
            raise ReplyEntityRouteHold("original D03 arrival event differs")
        evidence_key = AtomKey.from_token(binding.verification_ref)
        if (evidence_key.type_name != "d03.world_event"
                or evidence_key.owner.kind != "event"
                or (evidence_key.owner.bot, evidence_key.owner.persona)
                   != namespace.as_tuple):
            raise ReplyEntityRouteHold("D03 binding evidence crosses namespace")
        evidence_version, evidence_value = _current_atom(owner, db, evidence_key, prepared_inventory=prepared_inventory)
        evidence = WorldEvent(**{
            **evidence_value,
            "participant_roles": tuple(tuple(role) for role in
                                       evidence_value["participant_roles"]),
            "source_refs": tuple(evidence_value["source_refs"]),
        })
        if (evidence.kind != "message_received"
                or evidence.reality != "host_observed"
                or evidence.participant_roles != (
                    (target_entity_ref, "sender_account"),)
                or evidence.learned_at != binding.valid_from):
            raise ReplyEntityRouteHold("D03 binding verification event differs")
        rows = (_sql(owner, db,
            "SELECT token,revision,value FROM graph_atoms WHERE bot=? AND persona=? "
            "AND type_name='d03.account_binding' AND valid=1 ORDER BY token",
            namespace.as_tuple,
        ).fetchall()
            if prepared_inventory is None else prepared_inventory.atom_rows(db,namespace,query,('d03.account_binding',),('token','revision','value')))
        scan = []
        matches = []
        for token, revision, raw in rows:
            key = AtomKey.from_token(token)
            value = AccountBinding(**(background_json_loads_v3(raw)if prepared_inventory is None else raw))
            scan.append(GraphVersion(key, revision))
            if (value.platform_namespace == platform_ref
                    and value.platform_identifier == sender_ref
                    and value.valid_from <= now_utc
                    and (value.valid_until is None
                         or now_utc < value.valid_until)):
                matches.append(key)
        if matches != [binding_version.key]:
            raise ReplyEntityRouteHold("reply sender has ambiguous account binding")
        versions = tuple(scan)
        proof = {
            "schema": "sylanne3.current-reply-entity-route-binding.v2",
            "namespace": list(namespace.as_tuple),
            "c02_operation_id": route.c02_operation_id,
            "source_ref": route.source_ref,
            "platform_ref": platform_ref,
            "sender_ref": sender_ref,
            "conversation_ref": conversation_ref,
            "scene_ref": route.scene_ref,
            "target_entity_ref": target_entity_ref,
            "account_id": account_id,
            "versions": [(v.key.token, v.revision) for v in (
                anchor_version, binding_version, arrival_event_version,
                evidence_version, source_version, access_version)],
            "binding_scan_versions": [(v.key.token, v.revision) for v in versions],
            "query": (query.namespace.as_tuple, query.scope_ref, query.revision),
            "valid_until_utc": binding.valid_until,
            "route_digest": route.route_digest,
            "ingress_identity_digest": canonical_digest(identity),
            "arrival_operation_digest": arrival_operation[0],
        }
        return CurrentReplyEntityRouteBindingV2(
            namespace, route.c02_operation_id, route.source_ref, platform_ref,
            sender_ref, conversation_ref, route.scene_ref,
            target_entity_ref, account_id, anchor_version, binding_version,
            arrival_event_version, evidence_version, source_version,
            access_version, versions, query, binding.valid_until,
            canonical_digest(proof),
        )
    except ReplyEntityRouteHold:
        raise
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise ReplyEntityRouteHold("reply account route evidence is invalid") from exc
