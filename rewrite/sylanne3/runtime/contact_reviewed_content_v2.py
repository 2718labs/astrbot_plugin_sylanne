"""Read contact content from both real paid original calls, never caller text."""
from .contact_original_read_v3 import contact_original_point_v3
import json

from ..domains.d09.contact_content_v2 import ContactPaidModelBindingV2, prepare_contact_reviewed_content_v2
from ..graph_types import AtomKey
from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize
from .contact_paid_original_v2 import require_contact_original_v2
from .d01_production_operations_v1 import MissingProductionOriginalV1


def _read_contact_paid_cost_commit_v2(db, *, namespace, prepared, paid, issuer):
    """Authenticate the actual model-cost encoding, not a D04 root receipt.

    This read is part of the signed paired-result reader in one SQL snapshot;
    decoding a cost COMMIT never grants current Source/Owner permission.
    """
    from dataclasses import asdict
    from ..contracts import canonical_json
    from .model_cost_settlement import OriginalModelCostCommitV1, original_model_cost_operation_id_v1
    from .budget import _receipt_from_json
    if not db.in_transaction:
        raise ValueError('Contact2 paid cost requires its actual SQL snapshot')
    operation=paid['cost_operation_id']
    if operation!=original_model_cost_operation_id_v1(namespace,prepared.call_id):
        raise ValueError('Contact2 cost operation differs from its sealed once call')
    row=contact_original_point_v3(db,table='graph_bundle_operations',columns=('digest', 'activity_id', 'effect_id', 'commit_seq', 'receipt_json'),key_columns=('bot', 'persona', 'operation_id'),key=(lambda _contact_values: (_contact_values[0],_contact_values[1],_contact_values[2]))((*namespace.as_tuple,operation)),legacy_reader=lambda: db.execute('SELECT digest,activity_id,effect_id,commit_seq,receipt_json FROM graph_bundle_operations '
        'WHERE bot=? AND persona=? AND operation_id=?',(*namespace.as_tuple,operation)).fetchone())
    if row is None:raise ValueError('Contact2 actual cost COMMIT is absent')
    raw=json.loads(row[4])
    fields={'original_model_cost','original_intent_digest','terminal_receipt_digest','quote_id','quote_version','work_kind','accounting_attempt_id'}
    if type(raw) is not dict or set(raw)!=fields or canonical_json(raw)!=row[4]:
        raise ValueError('Contact2 actual cost receipt encoding differs')
    commit=raw['original_model_cost']
    if type(commit) is not dict or set(commit)!=set(OriginalModelCostCommitV1.__dataclass_fields__):
        raise ValueError('Contact2 typed model cost COMMIT fields differ')
    for name in ('quote_version','commit_seq','graph_revision','graph_epoch'):
        if type(commit[name]) is not int or commit[name]<1:
            raise ValueError('Contact2 model cost revision is not a strict positive integer')
    if type(raw['quote_version']) is not int:
        raise ValueError('Contact2 model cost quote version is not typed')
    receipt=OriginalModelCostCommitV1(**commit)
    intent_raw,_=require_contact_original_v2(db,issuer,namespace,'call',prepared.job_id)
    from ..authority_service.v2_model_egress_wire import from_wire
    from ..authority_service.v2_model_egress_contract import ModelEgressIntentV1
    intent=from_wire(intent_raw, ModelEgressIntentV1)
    quote=issuer._d02.original_signed_quote(db,prepared.quote_id,prepared.quote_version)
    budget=contact_original_point_v3(db,table='runtime_budget_operations',columns=('receipt_json',),key_columns=('bot_id', 'persona_id', 'operation_id', 'phase'),key=(lambda _contact_values: (_contact_values[0],_contact_values[1],_contact_values[2],'settle'))((*namespace.as_tuple,prepared.prepare_operation_id)),legacy_reader=lambda: db.execute('SELECT receipt_json FROM runtime_budget_operations WHERE bot_id=? AND persona_id=? '
        "AND operation_id=? AND phase='settle'",(*namespace.as_tuple,prepared.prepare_operation_id)).fetchone())
    attempt=contact_original_point_v3(db,table='graph_original_model_cost_attempts_v1',columns=('state', 'attempt_id'),key_columns=('bot', 'persona', 'call_id'),key=(lambda _contact_values: (_contact_values[0],_contact_values[1],_contact_values[2]))((*namespace.as_tuple,prepared.call_id)),legacy_reader=lambda: db.execute('SELECT state,attempt_id FROM graph_original_model_cost_attempts_v1 '
        'WHERE bot=? AND persona=? AND call_id=?',(*namespace.as_tuple,prepared.call_id)).fetchone())
    if (budget is None or attempt!=('committed',raw['accounting_attempt_id'])
            or raw['original_intent_digest']!=canonical_digest(asdict(intent))
            or raw['terminal_receipt_digest']!=paid['terminal_digest']
            or raw['work_kind']!=prepared.phase
            or (raw['quote_id'],raw['quote_version'])!=(prepared.quote_id,prepared.quote_version)
            or (receipt.schema,receipt.status,receipt.operation_id,receipt.call_id,receipt.quote_id,receipt.quote_version,
                receipt.terminal_receipt_digest,receipt.cost_ref,receipt.commit_seq)!=
                ('sylanne.d11.original-model-cost-commit.v1','committed',operation,prepared.call_id,
                 prepared.quote_id,prepared.quote_version,paid['terminal_digest'],paid['cost_ref'],row[3])
            or receipt.budget_receipt_digest!=canonical_digest(asdict(_receipt_from_json(budget[0])))
            or (row[1],row[2])!=(prepared.activity_id,quote.effect_id)):
        raise ValueError('Contact2 model cost original/call/budget/identity differs')
    event=contact_original_point_v3(db,table='graph_events',columns=('reads', 'revisions', 'epoch_revision'),key_columns=('bot', 'persona', 'session', 'event_id'),key=(lambda _contact_values: (_contact_values[0],_contact_values[1],_contact_values[2],_contact_values[3]))((*namespace.as_tuple,prepared.activity_id,operation)),legacy_reader=lambda: db.execute('SELECT reads,revisions,epoch_revision FROM graph_events WHERE bot=? AND persona=? '
        'AND session=? AND event_id=?',(*namespace.as_tuple,prepared.activity_id,operation)).fetchone())
    key=AtomKey.from_token(paid['cost_ref'])
    if key.type_name!='runtime.cost_settlement' or NamespaceId.from_key(key)!=namespace:
        raise ValueError('Contact2 cost reference type/namespace differs')
    history=contact_original_point_v3(db,table='graph_history',columns=('event_id', 'value', 'valid'),key_columns=('token', 'revision'),key=(lambda _contact_values: (_contact_values[0],1))((key.token,)),legacy_reader=lambda: db.execute('SELECT event_id,value,valid FROM graph_history WHERE token=? AND revision=1',(key.token,)).fetchone())
    def exact_member(encoded,revision):
        raw=json.loads(encoded)
        return (type(raw) is list and len(raw)==1 and type(raw[0]) is list and len(raw[0])==2
            and type(raw[0][0]) is str and raw[0][0]==key.token and type(raw[0][1]) is int
            and raw[0][1]==revision and canonical_json(raw)==encoded)
    if (event is None or not exact_member(event[0],0)
            or not exact_member(event[1],1) or event[2]!=receipt.graph_epoch
            or history!=(operation,canonical_serialize(paid['cost_value']),1)):
        raise ValueError('Contact2 model cost lacks its actual exact event/history member')
    return receipt


def _read_model_binding_v2(db, *, namespace, issuer, paid_model):
    prepared, frozen, candidate, paid = paid_model
    originals = tuple((kind, prepared.job_id,
        require_contact_original_v2(db, issuer, namespace, kind, prepared.job_id)[1])
        for kind in ("prepared", "prepare_commit", "request", "call", "result", "terminal", "paid_cost"))
    cost_key = AtomKey.from_token(paid["cost_ref"])
    row = contact_original_point_v3(db,table='graph_atoms',columns=('revision', 'value', 'valid', 'bot', 'persona'),key_columns=('token',),key=(lambda _contact_values: (_contact_values[0],))((cost_key.token,)),legacy_reader=lambda: db.execute("SELECT revision,value,valid,bot,persona FROM graph_atoms WHERE token=?", (cost_key.token,)).fetchone())
    if row is None or row[2:] != (1, *namespace.as_tuple) or row[1] != canonical_serialize(paid["cost_value"]):
        raise ValueError("contact reviewed content lost its actual immutable paid cost")
    receipt = _read_contact_paid_cost_commit_v2(db, namespace=namespace, prepared=prepared, paid=paid, issuer=issuer)
    if receipt.status != "committed" or receipt.operation_id != paid["cost_operation_id"]:
        raise ValueError("contact reviewed content lacks its real cost settlement receipt")
    return ContactPaidModelBindingV2(prepared.phase, prepared.job_id, prepared.prepare_operation_id,
        prepared.call_id, prepared.digest, prepared.frozen_digest, originals, candidate.output_digest,
        cost_key.token, row[0], canonical_digest(json.loads(row[1])), paid["cost_operation_id"], canonical_digest(receipt))


def read_contact_reviewed_content_original_v2(db, *, namespace, contact_id, issuer, resource_issuer):
    from .contact_model_preparation_v2 import read_paid_contact_batch_original_v2
    if not db.in_transaction:
        raise ValueError("contact original content requires the actual Graph read transaction")
    paid = read_paid_contact_batch_original_v2(db, namespace=namespace, contact_id=contact_id,
        issuer=issuer, resource_issuer=resource_issuer)
    if paid is None:
        raise MissingProductionOriginalV1("whole_contact_generation_and_independent_paid_review")
    plan, expression, generation, review = paid
    return prepare_contact_reviewed_content_v2(plan, expression, generation, review,
        _read_model_binding_v2(db, namespace=namespace, issuer=issuer, paid_model=generation),
        _read_model_binding_v2(db, namespace=namespace, issuer=issuer, paid_model=review))
