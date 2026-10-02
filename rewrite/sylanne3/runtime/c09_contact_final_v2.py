"""Contact final original joins and unresolved finish inventory for C09.

The historical pending marker never proves a current finish ACK. This offline
decoder does not have an authenticated Authority finish observation: removal
of an affected pending/unknown Contact final therefore remains HOLD.
"""
import json

from ..runtime_contracts import canonical_serialize
from .contact_final_stage_v2 import validate_contact_final_provenance_v2, validate_contact_final_result_v2
from .contact_qualification_evidence_v1 import (
    decode_contact_qualification_evidence_v1, verify_historical_contact_qualification_sql_v1,
)


def validate_contact_final_original_joins_v2(db, *, namespace, operation_id, payload, receipt, original_digest, registry):
    proof=payload['provenance']
    validate_contact_final_provenance_v2(proof)
    evidence=decode_contact_qualification_evidence_v1(proof['qualification_evidence'],expected_digest=proof['qualification_digest'])
    if (evidence.namespace != namespace or evidence.operation_id != operation_id
            or evidence.graph_epoch != receipt.invalidated_epochs[0].revision
            or evidence.activation_generation != payload['authority']['activation_generation']):
        raise ValueError('C09 Contact qualification namespace/operation/epoch/generation differs')
    verify_historical_contact_qualification_sql_v1(db,evidence,registry=registry)
    from ..domains.d09.contact_batch_v2 import PROVENANCE, decode_contact_batch_companion_v2
    from ..graph_types import AtomKey
    member=next(item for item in proof['write_commitments'] if AtomKey.from_token(item['ref']).type_name==PROVENANCE)
    row=db.execute('SELECT value FROM graph_history WHERE token=? AND revision=?',(member['ref'],member['revision'])).fetchone()
    if row is None:raise ValueError('C09 Contact v2 actual batch provenance is absent')
    batch_proof=decode_contact_batch_companion_v2(PROVENANCE,json.loads(row[0]))
    from .contact_batch_current_v2 import validate_contact_batch_history_v2
    validate_contact_batch_history_v2(db,namespace=namespace,operation_id=operation_id,receipt=receipt,qualification=evidence,proof=batch_proof)
    attempt=db.execute('SELECT permit_json,receipt_json,attempt_id FROM graph_owner_domain_attempts_v3 '
        'WHERE bot=? AND persona=? AND operation_id=?',(*namespace.as_tuple,operation_id)).fetchone()
    fence=db.execute('SELECT permit_json FROM graph_bundle_fences_v2 WHERE bot=? AND persona=? AND operation_id=?',
        (*namespace.as_tuple,operation_id)).fetchone()
    if attempt is None or fence != (attempt[0],) or attempt[1] is None:
        raise ValueError('C09 Contact intermediate COMMIT lost its actual Owner attempt/fence')
    from ..authority_service.v2_contract import FencePermitV2, from_wire, canonical_digest as authority_digest
    permit=from_wire(json.loads(attempt[0]))
    if (type(permit) is not FencePermitV2 or permit.operation!='write' or permit.operation_id!=attempt[2]
            or permit.pinned_anchor!=evidence.effect_snapshot.anchor
            or permit.generation!=evidence.activation_generation
            or (permit.authority_id,permit.namespace)!=(evidence.effect_snapshot.authority_id,evidence.effect_snapshot.namespace)
            or authority_digest(permit)!=evidence.effect_snapshot.permit_digest):
        raise ValueError('C09 Contact retained permit differs from sealed qualification evidence')
    result=json.loads(attempt[1])
    if (canonical_serialize(result) != attempt[1] or result.get('schema') != 'sylanne.domain-production-receipt.v1'
            or result.get('operation_kind') != 'prepare_contact_dispatch'
            or result.get('operation_id') != operation_id or result.get('original_digest') != original_digest
            or result.get('contact_admission_ref') != proof['admission_ref']):
        raise ValueError('C09 Contact actual intermediate COMMIT receipt differs')
    for member in proof['write_commitments']:
        from ..runtime_contracts import canonical_digest
        row=db.execute('SELECT event_id,value,valid FROM graph_history WHERE token=? AND revision=?',
            (member['ref'],member['revision'])).fetchone()
        if row is None or row[0] != operation_id or row[2] != 1 or canonical_digest(json.loads(row[1])) != member['digest']:
            raise ValueError('C09 Contact final original lacks its actual committed member')
    from ..graph_types import AtomKey
    from .d11_types import RuntimeJobValue
    job_ref=AtomKey.from_token(proof['job_ref'])
    member=next(item for item in proof['write_commitments'] if item['ref']==job_ref.token)
    job_row=db.execute('SELECT value FROM graph_history WHERE token=? AND revision=?',
        (job_ref.token,member['revision'])).fetchone()
    job=RuntimeJobValue(**json.loads(job_row[0]))
    if ((job.bot_id,job.persona_id,job.activity_id,job.effect_id,job.operation_id,job.job_id,job.phase,
            job.work_kind,job.fence,job.cancel_epoch) !=
            (*namespace.as_tuple,receipt.activity_id,receipt.effect_id,operation_id,job_ref.name,'waiting','message',0,0)):
        raise ValueError('C09 Contact historical result job differs')
    validate_contact_final_result_v2(result,original={'domain':'d08','operation_kind':'prepare_contact_dispatch',
        'receipt':receipt,'original_digest':original_digest},job_id=job.job_id,
        admission_ref=proof['admission_ref'],dispatch_request_digest=proof['request_digest'])
    return evidence


def require_contact_final_erasure_finish_v2(proof, *, db=None, namespace=None, operation_id=None):
    """No offline marker/digest is substituted for an actual finish observation."""
    validate_contact_final_provenance_v2(proof)
    if db is None:
        raise ValueError('C09 Contact final finish is pending or unauthenticated; preserve full inventory; HOLD')
    from ..authority_service.c09_contact_finish_original_v1 import require_contact_finish_graph_erasure_v1
    from ..authority_service.contract import AuthorityUnavailable
    try:
        return require_contact_finish_graph_erasure_v1(db, namespace=namespace, operation_id=operation_id, proof=proof)
    except AuthorityUnavailable as error:
        raise ValueError(str(error)) from error
