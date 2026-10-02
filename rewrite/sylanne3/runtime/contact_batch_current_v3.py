"""Actual SQL three-way Contact fact/provenance/current projection join.

This does not issue a provider check or sender. Callers must independently
authenticate the Owner/Authority fence and their own purpose and audience.
The projection authenticates frozen Source/Access/Correction, Owner, plan and
route/structural heads. It does not replace fresh complete quota, action or
WorldEvent inventories: the installed D11 entry invokes it only after the six
providers have qualified the actual private receipt-hook snapshot. New claims
cannot obtain admission by calling this standalone foundation reader.
"""
import json

from ..domains.d09.contact_batch_v3 import (
    BATCH, PROVENANCE, ELIGIBILITY, contact_batch_keys_v3,
    decode_contact_batch_companion_v3, contact_batch_writes_from_proof_v3,
)
from ..runtime_contracts import NamespaceId, canonical_serialize
from ..graph_types import AtomKey


def require_current_contact_batch_v3(db, *, namespace, batch_ref, operation_id, generation, graph_incarnation):
    if not db.in_transaction or type(namespace) is not NamespaceId or type(generation) is not int:
        raise ValueError('Contact v3 current reader requires its actual SQL transaction/scope')
    key = AtomKey.from_token(batch_ref)
    if key.type_name != BATCH or NamespaceId.from_key(key) != namespace:
        raise ValueError('Contact v3 current fact locator/type/scope differs')
    keys = tuple(AtomKey(key.owner, kind, key.name) for kind in (BATCH, PROVENANCE, ELIGIBILITY))
    current = {}
    for actual_key in keys:
        row = db.execute('SELECT revision,value,valid FROM graph_atoms WHERE bot=? AND persona=? AND token=?',
            (*namespace.as_tuple, actual_key.token)).fetchone()
        if row is None or row[0] != 1 or row[2] != 1:
            raise ValueError('Contact v3 current fact/proof/eligibility is absent or invalidated')
        history = db.execute('SELECT event_id,value,valid FROM graph_history WHERE token=? AND revision=1',
            (actual_key.token,)).fetchone()
        if history != (operation_id, row[1], 1):
            raise ValueError('Contact v3 current member lacks its actual producing history')
        current[actual_key.type_name] = decode_contact_batch_companion_v3(actual_key.type_name, json.loads(row[1]))
    batch, proof, eligible = (current[kind] for kind in (BATCH, PROVENANCE, ELIGIBILITY))
    if (contact_batch_keys_v3(namespace, batch.content.activity_id, batch.content.contact_id) != keys
            or proof.batch != batch or proof.batch.producing_operation_id != operation_id
            or eligible.producing_operation_id != operation_id
            or proof.activation_generation != generation or eligible.activation_generation != generation
            or proof.graph_incarnation != graph_incarnation or eligible.graph_incarnation != graph_incarnation
            or eligible.provenance_digest != proof.digest
            or canonical_serialize(eligible.current_reads) != canonical_serialize(proof.current_reads)):
        raise ValueError('Contact v3 current scope/operation/proof binding differs')
    expected = contact_batch_writes_from_proof_v3(proof)
    for write in expected:
        edges = tuple(db.execute('SELECT dependency_token,dependency_revision FROM graph_dependencies '
            'WHERE dependent_token=? ORDER BY dependency_token', (write.key.token,)))
        revisions = {row.ref: row.revision for row in proof.current_reads}
        revisions.update({keys[0].token:1, keys[1].token:1})
        if set(edges) != {(dependency.token,revisions[dependency.token]) for dependency in write.dependencies}:
            raise ValueError('Contact v3 current invalidation edge inventory differs')
    for row in proof.current_reads:
        head = db.execute('SELECT revision,value,valid FROM graph_atoms WHERE bot=? AND persona=? AND token=?',
            (*namespace.as_tuple,row.ref)).fetchone()
        if head != ((row.revision,row.value_json,int(row.valid)) if row.revision else None):
            raise ValueError('Contact v3 Source/Access/Correction/Owner/plan head drifted')
    return batch, proof, eligible


def validate_contact_batch_history_v3(db, *, namespace, operation_id, receipt, qualification, proof):
    """Authenticate historical proof against its actual E and E+1 SQL heads.

    Current revocation can cause deletion. This check uses the complete pinned
    historical inventory, without granting current rights or requiring validity
    after that revocation. Its latest-head SQL result is bounded before loading.
    """
    from ..domains.d09.contact_batch_v3 import ContactBatchProvenanceV3
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    from .contact_qualification_evidence_v3 import CONTACT_FINAL_QUERY_TYPES_V3
    if not db.in_transaction or type(proof) is not ContactBatchProvenanceV3:
        raise ValueError('Contact v3 historical proof lacks the actual pinned SQL snapshot')
    if (proof.batch.content.namespace != namespace or proof.batch.producing_operation_id != operation_id
            or proof.activation_generation != qualification.activation_generation
            or proof.owner_head_digest != qualification.owner_guard.owner_head_digest
            or proof.qualification.checks != qualification.qualification.checks
            or proof.qualification.owner_policy_digest != qualification.qualification.owner_policy_digest
            or proof.qualification.route_semantic_digest != qualification.qualification.route_semantic_digest):
        raise ValueError('Contact v3 historical qualification/Owner/operation binding differs')
    producing = read_adopted_domain_operation_v1(db, namespace, operation_id)
    if producing is None or producing['receipt'] != receipt:
        raise ValueError('Contact v3 historical proof has no actual adopted COMMIT receipt')
    reads = {v.key.token:v.revision for v in receipt.read_versions}
    refs = tuple(row.ref for row in proof.historical_reads)
    if any(reads.get(row.ref) != row.revision for row in proof.historical_reads):
        raise ValueError('Contact v3 proof is outside its actual COMMIT readset')
    epoch = qualification.graph_epoch - 1
    if {page.epoch.revision for page in proof.query_coverage} != {epoch}:
        raise ValueError('Contact v3 historical E scope differs from its E+1 qualification')
    kinds = CONTACT_FINAL_QUERY_TYPES_V3
    rows = db.execute('WITH latest AS (SELECT h.token,MAX(h.revision) AS revision FROM graph_history h '
        'JOIN graph_events e ON (h.event_bot,h.event_persona,h.event_session,h.event_id)='
        '(e.bot,e.persona,e.session,e.event_id) WHERE e.bot=? AND e.persona=? AND e.epoch_revision<=? '
        f"AND (h.token IN ({','.join('?' for _ in refs)}) OR json_extract(h.token,'$[4]') IN ({','.join('?' for _ in kinds)})) "
        'GROUP BY h.token) SELECT h.token,h.revision,h.value,h.valid FROM latest l '
        'JOIN graph_history h ON h.token=l.token AND h.revision=l.revision ORDER BY h.token LIMIT 1025',
        (*namespace.as_tuple,epoch,*refs,*kinds)).fetchall()
    if len(rows)>1024:
        raise ValueError('Contact v3 complete historical latest-head inventory exceeds bound; HOLD')
    heads={ref:(revision,value,valid) for ref,revision,value,valid in rows}
    for row in proof.historical_reads:
        if heads.get(row.ref) != ((row.revision,row.value_json,int(row.valid)) if row.revision else None):
            raise ValueError('Contact v3 historical Source/Access/Correction/plan frozen row differs')
    for page in proof.query_coverage:
        actual=tuple((ref,row[0]) for ref,row in sorted(heads.items()) if AtomKey.from_token(ref).type_name==page.type_id)
        if actual != tuple((v.key.token,v.revision) for v in page.row_versions):
            raise ValueError('Contact v3 historical full negative query inventory differs')
    member_refs={v.key.token:v.revision for v in receipt.write_versions}
    for write in contact_batch_writes_from_proof_v3(proof):
        if member_refs.get(write.key.token)!=1:
            raise ValueError('Contact v3 historical companion is not an actual COMMIT member')
        actual=db.execute('SELECT event_id,value,valid,dependencies FROM graph_history WHERE token=? AND revision=1',
            (write.key.token,)).fetchone()
        expected_revisions={row.ref:row.revision for row in proof.current_reads}
        expected_revisions.update({contact_batch_keys_v3(namespace,proof.batch.content.activity_id,proof.batch.content.contact_id)[i].token:1 for i in (0,1)})
        expected_edges={(key.token,expected_revisions[key.token]) for key in write.dependencies}
        recorded_edges=json.loads(actual[3]) if actual is not None else None
        if (actual is None or actual[:3]!=(operation_id,canonical_serialize(write.value),1)
                or type(recorded_edges) is not list or len(recorded_edges)!=len(expected_edges)
                or any(type(pair) is not list or len(pair)!=2 or type(pair[0]) is not str or type(pair[1]) is not int
                    for pair in recorded_edges)
                or {tuple(pair) for pair in recorded_edges}!=expected_edges):
            raise ValueError('Contact v3 historical companion bytes/invalidation originals differ')
    return proof
