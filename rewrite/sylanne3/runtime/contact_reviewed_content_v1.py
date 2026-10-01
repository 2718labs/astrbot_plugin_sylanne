"""Read contact content from both real paid original calls, never caller text."""
import json

from ..domains.d09.contact_batch_v1 import ContactPaidModelBindingV1, prepare_contact_reviewed_content_v1
from ..graph_types import AtomKey
from ..runtime_contracts import canonical_digest
from .contact_paid_original_v1 import require_contact_original_v1
from .d04_root_original_store_v1 import _receipt
from .d01_production_operations_v1 import MissingProductionOriginalV1


def _read_model_binding_v1(db, *, namespace, issuer, paid_model):
    prepared, frozen, candidate, paid = paid_model
    originals = tuple((kind, prepared.job_id,
        require_contact_original_v1(db, issuer, namespace, kind, prepared.job_id)[1])
        for kind in ("prepared", "prepare_commit", "request", "call", "result", "terminal", "paid_cost"))
    cost_key = AtomKey.from_token(paid["cost_ref"])
    row = db.execute("SELECT revision,value,valid,bot,persona FROM graph_atoms WHERE token=?", (cost_key.token,)).fetchone()
    if row is None or row[2:] != (1, *namespace.as_tuple) or json.loads(row[1]) != paid["cost_value"]:
        raise ValueError("contact reviewed content lost its actual immutable paid cost")
    receipt = _receipt(db, namespace, paid["cost_operation_id"])
    if receipt.status != "committed" or receipt.operation_id != paid["cost_operation_id"]:
        raise ValueError("contact reviewed content lacks its real cost settlement receipt")
    return ContactPaidModelBindingV1(prepared.phase, prepared.job_id, prepared.prepare_operation_id,
        prepared.call_id, prepared.digest, prepared.frozen_digest, originals, candidate.output_digest,
        cost_key.token, row[0], canonical_digest(json.loads(row[1])), paid["cost_operation_id"], canonical_digest(receipt))


def read_contact_reviewed_content_original_v1(db, *, namespace, contact_id, issuer, resource_issuer):
    from .contact_model_preparation_v1 import read_paid_contact_batch_original_v1
    if not db.in_transaction:
        raise ValueError("contact original content requires the actual Graph read transaction")
    paid = read_paid_contact_batch_original_v1(db, namespace=namespace, contact_id=contact_id,
        issuer=issuer, resource_issuer=resource_issuer)
    if paid is None:
        raise MissingProductionOriginalV1("whole_contact_generation_and_independent_paid_review")
    plan, expression, generation, review = paid
    return prepare_contact_reviewed_content_v1(plan, expression, generation, review,
        _read_model_binding_v1(db, namespace=namespace, issuer=issuer, paid_model=generation),
        _read_model_binding_v1(db, namespace=namespace, issuer=issuer, paid_model=review))
