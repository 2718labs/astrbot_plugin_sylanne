"""Historical Contact W01 identity for an independent current P2 read.

This verifies the eleven members at their real birth COMMIT and the complete
historical qualification inventory. It neither requires the current epoch to
remain the birth epoch nor grants permission to read a current payload or send.
"""
from ..runtime_storage_v3 import read_graph_row_v3,read_graph_rows_v3
from dataclasses import dataclass
import json

from ..graph_types import AtomKey
from ..runtime_contracts import canonical_digest
from .contact_final_stage_v3 import validate_contact_final_provenance_v3
from .contact_qualification_evidence_v3 import (
    CONTACT_FINAL_QUERY_TYPES_V3, decode_contact_qualification_evidence_v3,
)
from .dispatch_action_job_binding import load_action_job_binding
from .dispatch_admission import load_request
from .domain_production_originals_v1 import read_adopted_domain_operation_v1


@dataclass(frozen=True, slots=True)
class ContactP2BirthV1:
    original: dict
    admission: object
    request: object
    qualification: object
    batch_ref: str
    job_ref: str
    outbox_ref: str


def read_contact_p2_birth_v1(db, *, namespace, operation_id, prepared_original=None):
    if not db.in_transaction:
        raise ValueError('Contact P2 birth requires its actual pinned SQL snapshot')
    prepared_evidence=prepared_heads=None
    if prepared_original is None:
        original = read_adopted_domain_operation_v1(db,namespace,operation_id)
    else:
        from .dispatch_initial_source_read_v3 import PreparedContactBirthOriginalsV3
        if type(prepared_original)is not PreparedContactBirthOriginalsV3:raise TypeError('actual private Contact birth original required')
        original,prepared_evidence,prepared_heads=prepared_original.require_for_v3(db,namespace,operation_id)
    if original is None or original['operation_kind'] != 'prepare_contact_dispatch_v3':
        raise ValueError('Contact P2 actual birth COMMIT is absent')
    proof = original['payload']['provenance']
    validate_contact_final_provenance_v3(proof,prepared_evidence=prepared_evidence)
    evidence = (decode_contact_qualification_evidence_v3(proof['qualification_evidence'],
        expected_digest=proof['qualification_digest'])if prepared_evidence is None else prepared_evidence)
    issued = load_request(db,namespace,proof['admission_ref'])
    if issued is None:
        raise ValueError('Contact P2 historical dispatch command is absent')
    admission, request = issued
    receipt = original['receipt']
    if (evidence.namespace != namespace or evidence.operation_id != operation_id
            or request.operation_id != operation_id or request.proactive_contact is not True
            or request.segment_index != 0 or not 1<=request.segment_count<=3
            or request.effect_id != receipt.effect_id
            or request.activation_generation != evidence.activation_generation
            or request.dispatch_generation != request.activation_generation
            or admission.receipt_digest != proof['admission_receipt_digest']
            or canonical_digest(request) != proof['request_digest']
            or canonical_digest(request.footprint) != proof['footprint_digest']
            or admission.graph_epoch != evidence.graph_epoch
            or evidence.qualification.checks != admission.admission.check_receipts
            or len(receipt.write_versions) != 11 or len(proof['write_commitments']) != 11
            or {(v.key.token,v.revision) for v in receipt.write_versions}
               != {(v['ref'],v['revision']) for v in proof['write_commitments']}
            or load_action_job_binding(db,namespace,proof['admission_ref']) is None):
        raise ValueError('Contact P2 birth eleven-member identity/qualification differs')
    if prepared_original is None:
        for member in proof['write_commitments']:
            history = read_graph_row_v3(db,columns=('event_id', 'value', 'valid'),where='token=? AND revision=?',parameters=(member['ref'],member['revision']),history=True)
            if (history is None or history[0] != operation_id or history[2] != 1
                    or canonical_digest(json.loads(history[1])) != member['digest']):
                raise ValueError('Contact P2 birth producing member commitment differs')
    fence = db.execute('SELECT digest,permit_json,pre_graph_revision,pre_graph_epoch,post_graph_revision,'
        'post_graph_epoch,finish_request_id,finish_request_digest FROM graph_bundle_fences_v2 '
        'WHERE bot=? AND persona=? AND operation_id=?',(*namespace.as_tuple,operation_id)).fetchone()
    attempt = db.execute('SELECT request_digest,attempt_id,permit_json FROM graph_owner_domain_attempts_v3 '
        'WHERE bot=? AND persona=? AND operation_id=?',(*namespace.as_tuple,operation_id)).fetchone()
    from ..authority_service.v2_contract import from_wire
    if fence is None or attempt is None:
        raise ValueError('Contact P2 historical W01 fence/Owner attempt is absent')
    permit = from_wire(json.loads(fence[1]))
    finish_digest = 'sha256:'+canonical_digest({'schema':'w01.owner-domain-write.v3',
        'operation_id':operation_id,'request_digest':attempt[0],'permit_token':permit.token})
    if (fence[0] != receipt.operation_digest or fence[1] != attempt[2]
            or permit.operation != 'write' or permit.operation_id != attempt[1]
            or permit.token != request.content_fence
            or (fence[4],fence[5]) != (fence[2]+1,fence[3]+1)
            or (admission.graph_revision,admission.graph_epoch) != (fence[4],fence[5])
            or fence[6:] != ('finish:'+attempt[1],finish_digest)):
        raise ValueError('Contact P2 historical real COMMIT/fence link differs')
    if prepared_original is None:
        refs = tuple(row.ref for row in evidence.members)
        kinds = CONTACT_FINAL_QUERY_TYPES_V3
        sql = ('WITH latest AS (SELECT h.token,MAX(h.revision) AS revision FROM graph_history h '
            'JOIN graph_events e ON (h.event_bot,h.event_persona,h.event_session,h.event_id)='
            '(e.bot,e.persona,e.session,e.event_id) WHERE e.bot=? AND e.persona=? AND e.epoch_revision<=? '
            f"AND (h.token IN ({','.join('?' for _ in refs)}) OR json_extract(h.token,'$[4]') "
            f"IN ({','.join('?' for _ in kinds)})) GROUP BY h.token) "
            'SELECT h.token,h.revision,h.value,h.valid FROM latest l JOIN graph_history h '
            'ON h.token=l.token AND h.revision=l.revision ORDER BY h.token LIMIT 1025')
        rows = db.execute(sql,(*namespace.as_tuple,evidence.graph_epoch,*refs,*kinds)).fetchall()
        if len(rows)>1024:
            raise ValueError('Contact P2 historical full inventory exceeds its existing bound')
        heads = {ref:(revision,value,valid) for ref,revision,value,valid in rows}
        for member in evidence.members:
            expected = (member.revision,member.value_json,int(member.valid)) if member.revision else None
            if heads.get(member.ref) != expected:
                raise ValueError('Contact P2 historical provider member differs from the actual birth head')
        for page in evidence.query_coverage:
            actual = tuple((ref,value[0]) for ref,value in sorted(heads.items())
                if AtomKey.from_token(ref).type_name == page.type_id)
            if actual != tuple((v.key.token,v.revision) for v in page.row_versions):
                raise ValueError('Contact P2 historical negative-query inventory differs')
    else:
        from hashlib import sha256
        from .dispatch_initial_source_read_v3 import PreparedContactSourceMemberV3
        for member in evidence.members:
            expected=(member.revision,member.valid,member.value_digest if type(member)is PreparedContactSourceMemberV3 else sha256(member.value_json.encode()).hexdigest())if member.revision else None
            if prepared_heads.get(member.ref)!=expected:raise ValueError('Contact complete historical member differs from its actual cell witness')
        for page in evidence.query_coverage:
            actual=tuple((ref,value[0])for ref,value in sorted(prepared_heads.items())if AtomKey.from_token(ref).type_name==page.type_id)
            if actual!=tuple((v.key.token,v.revision)for v in page.row_versions):raise ValueError('Contact complete historical negative-query coverage differs')
    batches = tuple(v.key.token for v in receipt.write_versions
        if v.key.type_name == 'd09.contact_verified_batch.v3')
    if len(batches) != 1 or receipt.outbox_refs != (proof['outbox_ref'],):
        raise ValueError('Contact P2 historical whole batch/outbox identity differs')
    from .contact_first_p2_source_v1 import validate_contact_first_whole_birth_v1
    validate_contact_first_whole_birth_v1(db,namespace=namespace,operation_id=operation_id,receipt=receipt,
        admission=admission,request=request,qualification=evidence)
    return ContactP2BirthV1(original,admission,request,evidence,batches[0],proof['job_ref'],proof['outbox_ref'])
