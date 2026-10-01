"""Actual Owner and Graph observation for installed package maintenance."""
from dataclasses import asdict,dataclass
import json
import sqlite3
from ..runtime_contracts import canonical_digest,canonical_serialize
from ..graph_types import owner_grant_key,validate_owner_grant_v1
from ..graph_store import GraphStore
from .contract import AuthorityUnavailable
from .d12_operation_status_v1 import InstalledD12OperationStatusServiceV1
from .d12_target_owner_admission_v1 import D12CurrentOwnerAuthorityV1,current_owner_authority_material_v1
from .v2_owner_session import _canonical


@dataclass(frozen=True,slots=True)
class D12PackageOwnerObservationV2:
    authority: D12CurrentOwnerAuthorityV1
    actor: str
    public_session_request_json: str
    grant_ref: str
    grant_revision: int
    grant_digest: str
    graph_requirements_json: str
    graph_revision: int
    graph_epoch: int
    observation_digest: str


def observe_current_package_owner_v2(status,*,credential,subject,permit,actor,session_token,session_request):
    """Only actual installed service reads supply the short acceptance CAS.

    The exclusive permit is issued before this helper. No Graph file is read
    while the Core SQL transaction is open. No caller-provided grant or current
    authority DTO is accepted in place of these independent observations.
    """
    if type(status) is not InstalledD12OperationStatusServiceV1 or permit.operation not in {'read','write'}:raise AuthorityUnavailable('actual package maintenance status service/current permit required')
    status.fences.validate_fence(credential=credential,subject=subject,permit=permit)
    target=(status._target_owner_readers.get(session_request.installation_id)
        or getattr(status,'_storage_owner_readers',{}).get(session_request.installation_id))
    if target is None:
        guard=status.tickets.get_current_guard(credential=credential,authority_namespace=status.namespace,
            installation_id=status.installation_id,subject=subject,permit=permit,owner_actor_id=actor,
            owner_session_token=session_token,owner_session_request=session_request)
        authority=D12CurrentOwnerAuthorityV1(guard,None)
    else:
        authority,_=target.get_current_owner_authority_for_fence_v1(credential=credential,subject=subject,
            permit=permit,actor=actor,session_token=session_token,session_request=session_request)
        guard=authority.guard
    with status.core._tx() as db:
        head=status.tickets.current_migration_head_in_tx(db,authority_namespace=status.namespace)
        if head is None or head.state!='active' or head.guard!=guard:raise AuthorityUnavailable('package current Owner head changed')
    graph_path=status._source_graphs.get(session_request.installation_id)
    if graph_path is None:raise AuthorityUnavailable('package current installation Graph absent')
    db=sqlite3.connect(graph_path.as_uri()+'?mode=ro',uri=True,isolation_level=None)
    try:
        db.execute('BEGIN')
        key=owner_grant_key(*status.namespace_id.as_tuple)
        row=db.execute('SELECT revision,value,valid FROM graph_atoms WHERE token=?',(key.token,)).fetchone()
        metadata=GraphStore._decode_recovery(db.execute('SELECT schema,requirements_json,graph_revision FROM graph_recovery_metadata_v2 WHERE bot=? AND persona=?',status.namespace_id.as_tuple).fetchone(),status.namespace_id)
        epoch=db.execute('SELECT revision FROM graph_epochs WHERE bot=? AND persona=?',status.namespace_id.as_tuple).fetchone()
        if row is None or row[2]!=1 or metadata is None or epoch is None:raise AuthorityUnavailable('package actual Owner/Graph original absent')
        grant=json.loads(row[1]);validate_owner_grant_v1(grant)
        req=metadata.requirements;anchor=permit.pinned_anchor
        if (row[0]!=head.grant_revision or 'sha256:'+canonical_digest(grant)!=head.grant_digest
                or grant['principal']!=asdict(session_request.principal) or head.issue_operation.principal!=session_request.principal
                or not {'workbench.read','workbench.maintain','workbench.control'}.issubset(grant['capabilities'])
                or 'workbench_user_action' not in grant['purposes'] or 'owner' not in grant['audiences']
                or grant['scope']!='/'.join(status.namespace_id.as_tuple) or grant['state']!='pending_authority'
                or req.authority_id!=anchor.authority_id or req.authority_namespace!=anchor.namespace
                or any(getattr(req,name)!=getattr(anchor,name) for name in ('activation_generation','revocation_epoch',
                    'deletion_journal_id','deletion_seq','deletion_digest','execution_journal_id'))):raise AuthorityUnavailable('package actual Owner rights/namespace/location differ')
        if authority.storage_admission is not None:
            admission=authority.storage_admission
            if (admission.installation_id!=session_request.installation_id or admission.current_graph_incarnation!=req.graph_incarnation
                    or admission.revocation_epoch!=req.revocation_epoch or admission.source_grant_digest!=head.grant_digest):raise AuthorityUnavailable('package actual source storage admission differs')
        elif authority.target_admission is None:
            if (grant['installation_id']!=session_request.installation_id or grant['graph_incarnation']!=req.graph_incarnation
                    or grant['activation_generation']!=req.activation_generation):raise AuthorityUnavailable('package source grant location differs')
        else:
            admission=authority.target_admission
            if admission.target_installation_id!=session_request.installation_id or admission.graph_incarnation!=req.graph_incarnation:raise AuthorityUnavailable('package actual target admission location differs')
        requirements=canonical_serialize(asdict(req));revision=metadata.graph_revision;epoch=epoch[0]
    finally:db.close()
    with status.fences._frozen() as (db,deletion,execution,_):
        current=status.fences._current_locked(db,deletion,execution,require_no_pending=False)
        status.fences.fences.validate_fence_locked(db,permit,subject=subject,current_anchor=current)
        status._current_session_in_tx(db,actor=actor,token=session_token,request=session_request,expected_head=guard.authorization_head)
        if status.tickets.current_migration_head_in_tx(db,authority_namespace=status.namespace)!=head:raise AuthorityUnavailable('package Owner head changed after Graph read')
        actual,rows=status.fences.execution._scan_locked()
        prefix='genesis' if req.execution_seq==0 else next((item[6] for item in rows if item[0]==req.execution_seq),None)
        if actual!=execution or req.execution_seq>execution.seq or req.execution_digest!=prefix:raise AuthorityUnavailable('package Graph execution prefix is not in actual independent journal')
    material=(current_owner_authority_material_v1(authority),actor,_canonical(session_request).decode(),key.token,row[0],head.grant_digest,requirements,revision,epoch)
    return D12PackageOwnerObservationV2(authority,actor,_canonical(session_request).decode(),key.token,row[0],
        head.grant_digest,requirements,revision,epoch,canonical_digest(material))
