"""Exact D08 metadata projection receipt over a real independent W01 CAS."""
from dataclasses import dataclass,asdict,fields
import json
from ..authority_service.contract import AuthorityUnavailable
from ..authority_service.owner_goal_projection_contract_v1 import goal_projection_from_wire_v1,goal_projection_operation_id_v1
from ..runtime_contracts import NamespaceId,canonical_digest,canonical_serialize

TABLE="graph_owner_goal_cancellation_projections_v1"
COLUMNS=("bot","persona","operation_id","goal_ref","root_registration_ref","core_original_ref",
    "core_original_digest","observation_json","observation_digest","receipt_json","receipt_digest","signature")
DDL="""CREATE TABLE graph_owner_goal_cancellation_projections_v1(
 bot TEXT NOT NULL,persona TEXT NOT NULL,operation_id TEXT NOT NULL,goal_ref TEXT NOT NULL,
 root_registration_ref TEXT NOT NULL,core_original_ref TEXT NOT NULL,core_original_digest TEXT NOT NULL,
 observation_json TEXT NOT NULL,observation_digest TEXT NOT NULL,receipt_json TEXT NOT NULL,
 receipt_digest TEXT NOT NULL,signature TEXT NOT NULL,PRIMARY KEY(bot,persona,operation_id),
 UNIQUE(bot,persona,goal_ref,root_registration_ref)) STRICT"""
SIGN_KIND="d08.owner-goal-metadata-projection.v1"


@dataclass(frozen=True,slots=True)
class OwnerGoalProjectionReceiptV1:
    namespace: NamespaceId
    operation_id: str
    request_digest: str
    goal_ref: str
    root_registration_ref: str
    root_registration_digest: str
    core_original_ref: str
    core_original_digest: str
    cancel_operation_id: str
    cancel_request_digest: str
    observation_digest: str
    permit_digest: str
    before_graph_revision: int
    before_graph_epoch: int
    after_graph_revision: int
    after_graph_epoch: int
    event_digest: str
    event_session: str
    goal_atom_revision: int
    goal_semantic_revision: int
    goal_payload_digest: str
    goal_producing_operation_id: str
    goal_producing_digest: str
    owner_observation_digest: str
    before_metadata_json: str
    before_epoch_json: str
    after_metadata_json: str
    after_epoch_json: str
    state: str="metadata_projected"
    schema: str="d08.owner-goal-projection-receipt.v1"

    def __post_init__(self):
        if self.schema!="d08.owner-goal-projection-receipt.v1" or self.state!="metadata_projected":
            raise ValueError("Goal projection is metadata evidence only")
        if type(self.namespace) is not NamespaceId or self.after_graph_revision!=self.before_graph_revision+1:
            raise ValueError("actual W01 Goal projection graph revision required")
        for wire in (self.before_metadata_json,self.before_epoch_json,self.after_metadata_json,self.after_epoch_json):
            if canonical_serialize(json.loads(wire))!=wire:raise ValueError("Goal projection requires actual complete canonical metadata stamps")
        if (json.loads(self.before_metadata_json)["graph_revision"],json.loads(self.before_epoch_json)["revision"],
                json.loads(self.after_metadata_json)["graph_revision"],json.loads(self.after_epoch_json)["revision"])!=(
                self.before_graph_revision,self.before_graph_epoch,self.after_graph_revision,self.after_graph_epoch):
            raise ValueError("Goal projection complete metadata stamp differs from its actual CAS revisions")
    @property
    def digest(self):return canonical_digest(asdict(self))


def decode_goal_projection_receipt_v1(raw):
    if type(raw) is not dict or set(raw)!={f.name for f in fields(OwnerGoalProjectionReceiptV1)}:
        raise ValueError("closed Goal projection receipt fields differ")
    data=dict(raw);data["namespace"]=NamespaceId(**data["namespace"])
    result=OwnerGoalProjectionReceiptV1(**data)
    if asdict(result)!=raw:raise ValueError("Goal projection receipt roundtrip differs")
    return result


def validate_goal_projection_row_v1(columns,row,*,issuer=None,db=None):
    if tuple(columns)!=COLUMNS or len(row)!=len(COLUMNS):
        raise ValueError("fixed Goal projection columns differ")
    ns=NamespaceId(row[0],row[1])
    observation=goal_projection_from_wire_v1(json.loads(row[7]))
    receipt=decode_goal_projection_receipt_v1(json.loads(row[9]))
    original=observation.original;metadata=observation.metadata
    if (row[2:7]!=(receipt.operation_id,receipt.goal_ref,receipt.root_registration_ref,
            receipt.core_original_ref,receipt.core_original_digest)
            or canonical_serialize(json.loads(row[7]))!=row[7] or observation.digest!=row[8]
            or canonical_serialize(asdict(receipt))!=row[9] or receipt.digest!=row[10]
            or receipt.namespace!=ns or receipt.observation_digest!=observation.digest
            or receipt.operation_id!=goal_projection_operation_id_v1(original)
            or (receipt.goal_ref,receipt.root_registration_ref,receipt.root_registration_digest,
                receipt.core_original_ref,receipt.core_original_digest,receipt.cancel_operation_id,receipt.cancel_request_digest)!=(
                original.request.goal_ref,original.request.root_registration_ref,original.request.root_registration_digest,
                original.original_ref,original.digest,original.request.cancel_operation_id,original.request.digest)
            or (receipt.goal_atom_revision,receipt.goal_semantic_revision,receipt.goal_payload_digest,
                receipt.goal_producing_operation_id,receipt.goal_producing_digest)!=(
                metadata.goal_atom_revision,metadata.goal_semantic_revision,metadata.goal_payload_digest,
                metadata.goal_producing_operation_id,metadata.goal_producing_digest)):
        raise ValueError("Goal projection original/observation/receipt exact joins differ")
    if issuer is not None:
        original.require_signature_v1(issuer);observation.require_signature_v1(issuer)
        issuer._signer.verify(SIGN_KIND,canonical_serialize((ns,row[2],row[8],row[10])),row[11])
    if db is not None:
        from .natural_producer_qualification_v1 import _producer_original_point_v3
        event=_producer_original_point_v3(db,table="graph_events",columns=("digest",),
            key_columns=("bot","persona","session","event_id"),
            key=(*ns.as_tuple,receipt.event_session,receipt.operation_id),
            legacy_reader=lambda:db.execute("SELECT digest FROM graph_events WHERE bot=? AND persona=? AND session=? AND event_id=?",
                (*ns.as_tuple,receipt.event_session,receipt.operation_id)).fetchone())
        if event!=(receipt.event_digest,):raise ValueError("Goal projection lost actual W01 event")
    return observation,receipt


def read_stable_goal_projection_v1(db,*,namespace,goal_ref,root_registration_ref,issuer):
    from .natural_producer_qualification_v1 import _producer_original_point_v3
    # The stable Goal/root identity, never the current Goal revision, is the barrier.
    row=_producer_original_point_v3(db,table=TABLE,columns=COLUMNS,
        key_columns=("bot","persona","goal_ref","root_registration_ref"),
        key=(*namespace.as_tuple,goal_ref,root_registration_ref),
        legacy_reader=lambda:db.execute("SELECT "+",".join(COLUMNS)+" FROM "+TABLE+
            " WHERE bot=? AND persona=? AND goal_ref=? AND root_registration_ref=?",
            (*namespace.as_tuple,goal_ref,root_registration_ref)).fetchone())
    if row is None:return None
    return validate_goal_projection_row_v1(COLUMNS,row,issuer=issuer,db=db)


def require_stable_goal_projection_not_cancelled_v1(db,*,namespace,goal_ref,root_registration_ref,issuer):
    from .artifact_host_dispatch_source_v3 import require_artifact_host_goal_projection_absent_v3
    if require_artifact_host_goal_projection_absent_v3(db,namespace=namespace,goal_ref=goal_ref,root_registration_ref=root_registration_ref,issuer=issuer):return
    projection=read_stable_goal_projection_v1(db,namespace=namespace,goal_ref=goal_ref,
        root_registration_ref=root_registration_ref,issuer=issuer)
    if projection is not None:
        raise AuthorityUnavailable("actual_goal_metadata_projection_barrier:"+projection[1].core_original_ref)

def install_owner_goal_projection_schema_v1(db):
    row=db.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?",(TABLE,)).fetchone()
    if row is None:db.execute(DDL)
    elif row!=(DDL,):raise AuthorityUnavailable("actual fixed Goal projection schema differs")


def require_joint_artifact_goal_projection_gate_v1(db,*,namespace,binding,issuer):
    from .joint_node_execution_v1 import ArtifactJointExecutorV1
    if type(binding.executor) is not ArtifactJointExecutorV1:return
    from .d08_personal_plan_v1 import artifact_goal_plan_keys_v1
    from .owner_goal_projection_v1 import require_stable_goal_projection_not_cancelled_v1
    executor=binding.executor
    goal=artifact_goal_plan_keys_v1(namespace,c02_operation_id=executor.c02_operation_id,
        root_registration_ref=executor.root_registration_ref)[0]
    require_stable_goal_projection_not_cancelled_v1(db,namespace=namespace,goal_ref=goal.token,
        root_registration_ref=executor.root_registration_ref,issuer=issuer)

