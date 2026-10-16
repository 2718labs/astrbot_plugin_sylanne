"""Fixed independent W01 metadata projection writer."""
from ..authority_service.contract import AuthorityUnavailable
from ..runtime_contracts import canonical_digest,canonical_serialize

def commit_owner_goal_projection_in_transaction_v1(graph,db,*,issued,metadata,epoch):
    from ..graph_store import GraphStore
    from ..graph_types import AtomKey,GraphVersion,GraphCandidate
    from ..contracts import Scope,Event
    from .owner_goal_projection_issuance_v1 import require_owner_goal_projection_v1
    from .owner_goal_projection_v1 import OwnerGoalProjectionReceiptV1,TABLE,COLUMNS,SIGN_KIND
    from ..authority_service.owner_goal_projection_contract_v1 import goal_projection_to_wire_v1
    from ..authority_service.v2_contract import to_wire as fence_to_wire
    from dataclasses import asdict
    import time
    observed=require_owner_goal_projection_v1(issued,graph,issued.scope)
    if observed.scope_kind!="projection_write" or issued.scope.operation!="write" or issued.successor_view is not None:
        raise AuthorityUnavailable("Goal lookup READ observation cannot issue a W01 projection")
    scope=issued.scope;original=observed.original;target=observed.metadata
    store=graph._GraphCoordinator__store
    if db is not store._db or not db.in_transaction or graph._v2_graph_stamp(scope.namespace)!=(metadata,epoch):
        raise AuthorityUnavailable("Goal metadata projection requires its actual same W01 transaction/stamp")
    prior=db.execute("SELECT "+",".join(COLUMNS)+" FROM "+TABLE+
        " WHERE bot=? AND persona=? AND operation_id=?",(*scope.namespace.as_tuple,scope.operation_id)).fetchone()
    if prior is not None:
        from .owner_goal_projection_v1 import validate_goal_projection_row_v1
        _,receipt=validate_goal_projection_row_v1(COLUMNS,prior,issuer=graph._GraphCoordinator__d11_issuer,db=db)
        if receipt.core_original_digest!=original.digest:raise AuthorityUnavailable("Goal projection operation reused")
        return receipt
    goal=AtomKey.from_token(target.goal_ref)
    owner=AtomKey.from_token(observed.owner_grant_ref)
    reads=(GraphVersion(goal,target.goal_atom_revision),GraphVersion(owner,observed.owner_grant_revision))
    for version in reads:
        actual=db.execute("SELECT revision,valid FROM graph_atoms WHERE token=? AND bot=? AND persona=?",
            (version.key.token,*scope.namespace.as_tuple)).fetchone()
        if actual!=(version.revision,1):raise AuthorityUnavailable("Goal projection metadata version changed before W01")
    request_digest=canonical_digest(("d08.owner-goal-metadata-projection-request.v1",scope.namespace,
        original.request.cancel_operation_id,original.original_ref,original.digest))
    payload={"schema":"d08.owner-goal-metadata-projection-event.v1","operation_id":scope.operation_id,
        "request_digest":request_digest,"core_original_ref":original.original_ref,
        "core_original_digest":original.digest,"observation_digest":observed.digest}
    event=Event(Scope(*scope.namespace.as_tuple,goal.owner.subject),scope.operation_id,time.time(),
        "owner_goal_metadata_projection",payload)
    candidate=GraphCandidate(event,reads,(),(epoch,))
    result=GraphStore._graph_commit_in_transaction(store,candidate,
        _capability=graph._GraphCoordinator__graph_capability)
    if result.status!="committed":raise AuthorityUnavailable("Goal projection event has no new actual W01 CAS")
    store.cas_graph_recovery_metadata(metadata,metadata.requirements,
        _capability=graph._GraphCoordinator__graph_capability)
    after,after_epoch=graph._v2_graph_stamp(scope.namespace)
    receipt=OwnerGoalProjectionReceiptV1(scope.namespace,scope.operation_id,request_digest,target.goal_ref,
        original.request.root_registration_ref,original.request.root_registration_digest,original.original_ref,
        original.digest,original.request.cancel_operation_id,original.request.digest,observed.digest,
        canonical_digest(fence_to_wire(scope.permit)),metadata.graph_revision,epoch.revision,
        after.graph_revision,result.epoch.revision,event.digest,goal.owner.subject,target.goal_atom_revision,
        target.goal_semantic_revision,target.goal_payload_digest,target.goal_producing_operation_id,target.goal_producing_digest,
        canonical_digest((asdict(observed.owner_head),observed.owner_grant_ref,
            observed.owner_grant_revision,observed.owner_grant_digest)),
        canonical_serialize(asdict(metadata)),canonical_serialize(asdict(epoch)),
        canonical_serialize(asdict(after)),canonical_serialize(asdict(after_epoch)))
    observation_json=canonical_serialize(goal_projection_to_wire_v1(observed));receipt_json=canonical_serialize(asdict(receipt))
    signature=graph._GraphCoordinator__d11_issuer._signer.sign(SIGN_KIND,
        canonical_serialize((scope.namespace,scope.operation_id,observed.digest,receipt.digest)))
    row=(*scope.namespace.as_tuple,scope.operation_id,target.goal_ref,original.request.root_registration_ref,
        original.original_ref,original.digest,observation_json,observed.digest,receipt_json,receipt.digest,signature)
    db.execute("INSERT INTO "+TABLE+" VALUES("+",".join("?" for _ in COLUMNS)+")",row)
    return receipt
