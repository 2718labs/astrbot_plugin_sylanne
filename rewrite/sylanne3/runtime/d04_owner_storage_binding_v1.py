"""Compare a genuinely observed same-installation C09 Owner with Graph bytes.

This is a SQL-only comparison, never a way to authenticate a supplied DTO. The
mapping/topology observers obtain the value from their concrete current service
before entering this transaction and recheck the actual fence afterwards.
"""
from dataclasses import asdict
import json

from ..contracts import canonical_json
from ..graph_types import owner_grant_key, validate_owner_grant_v1
from ..authority_service.d12_owner_storage_admission_v1 import D12OwnerStorageAdmissionV1
from ..authority_service.d12_target_owner_admission_v1 import D12CurrentOwnerAuthorityV1
from ..authority_service.v2_owner_contract import OwnerGraphCommitProofV1, canonical_digest as owner_digest
from .c09_graph_originals_read_v4 import read_graph_rebase_certificate_v1
from .lifecycle_operations_v1 import digest


def require_d04_source_storage_binding_v1(db, *, namespace, metadata, scope,
                                        observed, installation_id, business_anchor):
    if (not db.in_transaction or type(observed) is not D12CurrentOwnerAuthorityV1
            or observed.target_admission is not None or observed.guard.namespace != namespace
            or observed.guard.installation_id != installation_id or metadata is None
            or scope.namespace != namespace or scope.permit.pinned_anchor != scope.pinned_anchor):
        raise ValueError("D04 source storage needs the actual observed Owner/fence")
    req = metadata.requirements
    if (scope.graph_revision != metadata.graph_revision or scope.authority_namespace != req.authority_namespace
            or scope.generation != req.activation_generation or scope.permit.holder == ""
            or scope.permit.authority_id != req.authority_id
            or business_anchor.namespace != req.authority_namespace
            or business_anchor.authority_id != req.authority_id
            or any(getattr(req, field) != getattr(business_anchor, field) for field in (
                "activation_generation", "revocation_epoch", "deletion_journal_id", "deletion_seq", "deletion_digest",
                "execution_journal_id", "execution_seq", "execution_digest"))
            or db.execute("SELECT revision FROM graph_epochs WHERE bot=? AND persona=?", namespace.as_tuple).fetchone()
                != (scope.graph_epoch.revision,)):
        raise ValueError("D04 source storage current snapshot and observed fence differ")
    from .domain_background_read_v3 import background_graph_head_v3,background_json_loads_v3,background_json_matches_v3
    row=background_graph_head_v3(db,namespace,owner_grant_key(*namespace.as_tuple))
    from .domain_background_read_v3 import background_point_v3
    proof_row=background_point_v3(db,table='graph_owner_issue_operations_v1',columns=(
        'operation_id','request_digest','grant_id','grant_digest','graph_incarnation','graph_access_epoch','graph_epoch','graph_receipt_digest','proof_json'),
        key_columns=('bot','persona'),key=namespace.as_tuple,legacy_reader=lambda:db.execute(
            'SELECT operation_id,request_digest,grant_id,grant_digest,graph_incarnation,graph_access_epoch,graph_epoch,graph_receipt_digest,proof_json FROM graph_owner_issue_operations_v1 WHERE bot=? AND persona=?',namespace.as_tuple).fetchone())
    if row is None or row[0] != 1 or row[2] != 1 or proof_row is None:
        raise ValueError("D04 source storage immutable Owner grant/proof absent")
    grant = background_json_loads_v3(row[1]); validate_owner_grant_v1(grant)
    proof = OwnerGraphCommitProofV1(namespace, *proof_row[:5], row[0], *proof_row[5:8])
    if (not background_json_matches_v3(proof_row[8],asdict(proof)) or not background_json_matches_v3(row[1],grant)
            or digest(grant) != proof.grant_digest or grant["installation_id"] != installation_id
            or grant["grant_id"] != proof.grant_id or grant["issue_operation_id"] != proof.operation_id
            or grant["authority_id"] != req.authority_id
            or grant["graph_incarnation"] != proof.graph_incarnation
            or grant["activation_generation"] != req.activation_generation
            or grant["scope"] != "/".join(namespace.as_tuple)
            or observed.guard.authorization_head != owner_digest(proof)
            or observed.guard.pending_revoke_operation_id is not None
            or observed.guard.minimum_revocation_revision or observed.guard.minimum_revocation_epoch):
        raise ValueError("D04 source storage retained Owner proof changed")
    admission = observed.storage_admission
    if req.graph_incarnation == proof.graph_incarnation:
        if admission is not None:
            raise ValueError("D04 source storage continuation does not change location")
        return None
    if (type(admission) is not D12OwnerStorageAdmissionV1
            or admission.namespace != namespace or admission.authority_namespace != req.authority_namespace
            or admission.installation_id != installation_id or admission.holder != scope.permit.holder
            or admission.source_owner_guard != observed.guard or asdict(admission.principal) != grant["principal"]
            or admission.source_grant_ref != owner_grant_key(*namespace.as_tuple).token
            or admission.source_grant_revision != 1 or admission.source_grant_digest != proof.grant_digest
            or admission.source_graph_incarnation != proof.graph_incarnation
            or admission.current_graph_incarnation != req.graph_incarnation
            or admission.activation_generation != req.activation_generation
            or admission.revocation_epoch != req.revocation_epoch):
        raise ValueError("D04 source storage actual RELEASED continuation differs")
    certificates = {}
    from .domain_background_read_v3 import background_rows_v3
    certificate_rows=background_rows_v3(db,table='graph_c09_rebase_certificates_v1',columns=('operation_id',),
        group_columns=('bot','persona'),group=namespace.as_tuple,order_columns=('operation_id',),limit=None,
        legacy_reader=lambda:db.execute('SELECT operation_id FROM graph_c09_rebase_certificates_v1 WHERE bot=? AND persona=?',namespace.as_tuple).fetchall())
    for (operation,) in certificate_rows:
        certificate = read_graph_rebase_certificate_v1(db, namespace, operation)
        if certificate is None or certificate.certificate_digest in certificates:
            raise ValueError("D04 source storage certificate inventory is ambiguous")
        certificates[certificate.certificate_digest] = certificate
    incarnation, previous = proof.graph_incarnation, None
    for certificate_digest, _prepared_digest, _release_digest in admission.certificate_chain:
        certificate = certificates.get(certificate_digest)
        if (certificate is None or certificate.old_incarnation != incarnation
                or previous is not None and certificate.prior_certificate_digest != previous):
            raise ValueError("D04 source storage observed certificate lineage is absent from Graph")
        incarnation, previous = certificate.new_incarnation, certificate_digest
    if incarnation != req.graph_incarnation:
        raise ValueError("D04 source storage certificate endpoint differs")
    return admission
