"""Finite Self task-wait disposition and post-registration original-message recheck."""
import json
from ..runtime_contracts import canonical_digest,canonical_serialize
from ..domains.d01.production_operations_v1 import plain_v1
from ..graph_types import GraphAtom
from ..domains.d10.project_checkpoint_v1 import project_checkpoint_key_v1,decode_project_checkpoint_type_v1,CHECKPOINT_TYPE
from .domain_production_originals_v1 import read_adopted_domain_operation_v1
from .d01_production_operations_v1 import MissingProductionOriginalV1
from .d11_life_preparation_v1 import TABLE,_read

WAIT_EVENT="artifact_task_wait_registered"
AMENDMENT_EVENT="artifact_task_amendment_adopted"
DISPOSITION="d11.artifact-task-wait-consumed.v1"


def current_task_wait_event_v1(db,*,namespace,objective):
    from .artifact_task_observer_v1 import require_task_observer_checkpoint_member_v1
    key=project_checkpoint_key_v1(namespace,objective.project_ref)
    row=db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=? AND bot=? AND persona=?",(key.token,*namespace.as_tuple)).fetchone()
    if row is None or row[2]!=1:raise MissingProductionOriginalV1("current_task_wait_checkpoint")
    cp=decode_project_checkpoint_type_v1(CHECKPOINT_TYPE,json.loads(row[1]))
    history=db.execute("SELECT event_id FROM graph_history WHERE token=? AND revision=?",(key.token,row[0])).fetchone()
    if history is None:raise MissingProductionOriginalV1("task_wait_actual_registration")
    producer=read_adopted_domain_operation_v1(db,namespace,history[0])
    observation=require_task_observer_checkpoint_member_v1(db,namespace=namespace,original=producer,atom=GraphAtom(key,row[0],json.loads(row[1]),True))
    if observation.phase!="partial":raise MissingProductionOriginalV1("unfinished_task_wait_registration")
    dedupe=canonical_digest((namespace,history[0],"d11",WAIT_EVENT))
    event=db.execute("SELECT causal_operation_id,original_ref,original_digest,state,consumer_operation_id,receipt_json FROM graph_domain_production_outbox_v1 WHERE bot=? AND persona=? AND dedupe_key=? AND receiver_domain='d11' AND event_kind=?",(*namespace.as_tuple,dedupe,WAIT_EVENT)).fetchone()
    if event is None or event[:3]!=(history[0],"d08-current:"+producer["original_digest"][:48],producer["original_digest"]):
        raise MissingProductionOriginalV1("actual_task_wait_outbox_registration")
    return cp,producer,dedupe,event


def require_unconsumed_task_wait_v1(db,*,namespace,objective):
    result=current_task_wait_event_v1(db,namespace=namespace,objective=objective)
    if result[3][3:]!=("pending",None,None):
        raise MissingProductionOriginalV1("task_wait_already_consumed_by_original_message")
    return result


def consume_task_wait_after_scope_cas_v1(db,*,scope,objective,receipt):
    from .artifact_task_amendment_v1 import amendment_from_scope_v1,amendment_original_ref_v1
    cp,producer,key,row=require_unconsumed_task_wait_v1(db,namespace=scope.namespace,objective=objective)
    current=read_adopted_domain_operation_v1(db,scope.namespace,receipt.operation_id)
    if current is None or current["receipt"]!=receipt:raise ValueError("task wait lacks actual continuation CAS")
    amendment=amendment_from_scope_v1(scope,objective)
    value={"schema":DISPOSITION,"dedupe_key":key,"causal_operation_id":row[0],
        "trigger_original_ref":row[1],"trigger_original_digest":row[2],"state":"completed",
        "consumer_operation_id":receipt.operation_id,"consumer_original_digest":current["original_digest"],
        "consumer_receipt_digest":canonical_digest(receipt),"objective_ref":scope.objective_ref,
        "objective_digest":scope.objective_digest,"c02_operation_id":scope.c02_operation_id,
        "root_registration_ref":scope.root.registration_ref,"amendment_ref":amendment_original_ref_v1(amendment)}
    db.execute("UPDATE graph_domain_production_outbox_v1 SET state='completed',consumer_operation_id=?,receipt_json=? WHERE bot=? AND persona=? AND dedupe_key=? AND state='pending'",
        (receipt.operation_id,canonical_serialize(value),*scope.namespace.as_tuple,key))
    if db.execute("SELECT changes()").fetchone()!=(1,):raise ValueError("task wait consumed by another original message")
    return value


def validate_task_wait_disposition_v1(db,*,namespace,row_data,value):
    from .ingress_artifact_task_scope_v1 import require_task_scope_archive_v1
    from .d11_artifact_draft_contract_v1 import draft_from_wire_v1,DraftRootCapabilityV1
    from .artifact_task_observer_v1 import ArtifactTaskObservationV1,require_task_observer_checkpoint_member_v1
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    from .artifact_task_amendment_v1 import amendment_from_scope_v1,amendment_original_ref_v1
    from .ingress_artifact_task_scope_v1 import ArtifactTaskObjectiveV1
    fields={"schema","dedupe_key","causal_operation_id","trigger_original_ref","trigger_original_digest","state",
        "consumer_operation_id","consumer_original_digest","consumer_receipt_digest","objective_ref","objective_digest",
        "c02_operation_id","root_registration_ref","amendment_ref"}
    if (db is None or set(value)!=fields or value["schema"]!=DISPOSITION
            or (row_data["receiver_domain"],row_data["event_kind"],row_data["state"])!=("d11",WAIT_EVENT,"completed")
            or any(value[k]!=row_data[k] for k in ("dedupe_key","causal_operation_id","state","consumer_operation_id"))
            or (value["trigger_original_ref"],value["trigger_original_digest"])!=(row_data["original_ref"],row_data["original_digest"])):
        raise ValueError("task wait disposition differs from its actual event")
    producer=read_adopted_domain_operation_v1(db,namespace,value["causal_operation_id"])
    consumer=read_adopted_domain_operation_v1(db,namespace,value["consumer_operation_id"])
    if producer is None or consumer is None:raise ValueError("task wait disposition lost actual producers")
    if (value["trigger_original_ref"],value["trigger_original_digest"])!=("d08-current:"+producer["original_digest"][:48],producer["original_digest"]):
        raise ValueError("task wait disposition changed its original observer digest")
    obs=decode_typed_production_value_v1(producer["payload"]["provenance"]["task_observation"],ArtifactTaskObservationV1)
    cp=obs.checkpoint
    require_task_observer_checkpoint_member_v1(db,namespace=namespace,original=producer,
        atom=GraphAtom(project_checkpoint_key_v1(namespace,cp.project_ref),cp.revision,plain_v1(cp),True))
    p=consumer["payload"]["provenance"]
    root=draft_from_wire_v1(p["draft_root_capability"],DraftRootCapabilityV1)
    scope=require_task_scope_archive_v1(db,namespace=namespace,root=root,producer=consumer)
    objective=decode_typed_production_value_v1(p["artifact_task_objective"],ArtifactTaskObjectiveV1)
    amendment=amendment_from_scope_v1(scope,objective)
    from .foreground_cycle_v1 import _adopted_c02_v1
    c02=_adopted_c02_v1(db,namespace,scope.c02_operation_id)
    if (obs.phase!="partial" or (obs.objective_ref,obs.objective_digest)!=(scope.objective_ref,scope.objective_digest)
            or c02.commit_seq<=cp.wait_condition.consume_cursor
            or (value["objective_ref"],value["objective_digest"],value["c02_operation_id"],value["root_registration_ref"],value["amendment_ref"])!=
               (scope.objective_ref,scope.objective_digest,scope.c02_operation_id,root.registration_ref,amendment_original_ref_v1(amendment))
            or value["consumer_original_digest"]!=consumer["original_digest"]
            or value["consumer_receipt_digest"]!=canonical_digest(consumer["receipt"])):
        raise ValueError("task wait consumer changed its same-objective actual new C02")


def discover_waiting_task_messages_v1(db,*,namespace,initial_c02_operation_id,issuer):
    """Read locators after registration; execution always re-enters formal current admission."""
    from .ingress_artifact_task_scope_v1 import ArtifactTaskObjectiveV1,_decode
    from .c1_artifact_task_intent_v1 import read_c1_task_intent_original_v1
    from .foreground_cycle_v1 import _adopted_c02_v1,foreground_cycle_ids_v1
    rows=db.execute("SELECT original_ref FROM "+TABLE+" WHERE bot=? AND persona=? AND kind='artifact_task_objective' AND json_extract(payload_json,'$.initial_c02_operation_id')=? LIMIT 2",(*namespace.as_tuple,initial_c02_operation_id)).fetchall()
    if not rows:return ()
    if len(rows)!=1:raise ValueError("initial task has conflicting original objectives")
    raw=_read(db,issuer=issuer,namespace=namespace,kind="artifact_task_objective",ref=rows[0][0]);objective=_decode(raw[0],ArtifactTaskObjectiveV1)
    goal=db.execute("SELECT value,valid FROM graph_atoms WHERE token=? AND bot=? AND persona=?",(objective.goal_ref,*namespace.as_tuple)).fetchone()
    if goal is None or goal[1]!=1 or json.loads(goal[0])["state"]!="active":return ()
    try:cp,producer,key,event=current_task_wait_event_v1(db,namespace=namespace,objective=objective)
    except MissingProductionOriginalV1:return ()
    rows=db.execute("SELECT json_extract(payload_json,'$.c02_operation_id') FROM "+TABLE+
        " WHERE bot=? AND persona=? AND kind='c1_task_intent' AND json_extract(payload_json,'$.intent.kind')='continue' "
        "AND json_extract(payload_json,'$.c02_commit_seq')>? "
        "AND (json_extract(payload_json,'$.intent.filename') IS NULL OR json_extract(payload_json,'$.intent.filename')=?) "
        "AND json_extract(payload_json,'$.installation_id')=? AND json_extract(payload_json,'$.manifest_digest')=? "
        "ORDER BY json_extract(payload_json,'$.c02_commit_seq'),original_ref LIMIT 129",
        (*namespace.as_tuple,cp.wait_condition.consume_cursor,objective.filename,objective.installation_id,objective.manifest_digest)).fetchall()
    if len(rows)>128:raise MissingProductionOriginalV1("bounded_complete_pending_task_message_inventory")
    candidates=[]
    for (c02_id,) in rows:
        intent=read_c1_task_intent_original_v1(db,namespace=namespace,c02_operation_id=c02_id,issuer=issuer)
        original=_adopted_c02_v1(db,namespace,c02_id)
        if original.commit_seq<=cp.wait_condition.consume_cursor or intent.intent.filename not in {None,objective.filename}:continue
        from .ingress_observation import read_committed_ingress_identity
        from ..graph_types import AtomKey
        ingress=read_committed_ingress_identity(db,namespace,AtomKey.from_token(intent.source_ref).owner.subject)
        if ingress is None or (ingress.platform_ref,ingress.sender_ref)!=(objective.platform_ref,objective.sender_ref):continue
        # A live/terminal/cancelled new parent already has its own owner; never acquire it here.
        job_id=foreground_cycle_ids_v1(namespace,c02_id)[1]
        if db.execute("SELECT 1 FROM runtime_jobs WHERE job_id=? AND bot_id=? AND persona_id=?",(job_id,*namespace.as_tuple)).fetchone():continue
        if event[3]=="completed":
            consumer=read_adopted_domain_operation_v1(db,namespace,event[4])
            if consumer is None or consumer["payload"]["provenance"]["artifact_task_scope"]["c02_operation_id"]!=c02_id:continue
        elif event[3]!="pending":continue
        candidates.append((original.commit_seq,c02_id,intent.source_ref))
    # The finite one-file task accepts its earliest actual unconsumed message.
    candidates.sort()
    return tuple({"c02_operation_id":c,"source_ref":s} for _,c,s in candidates[:1])


def discover_registered_task_waits_v1(db,*,namespace,issuer):
    from .ingress_artifact_task_scope_v1 import active_task_objectives_v1
    objectives=active_task_objectives_v1(db,namespace,issuer)
    if len(objectives)>3:raise MissingProductionOriginalV1("installed_finite_task_wait_capacity")
    result=[]
    for objective in objectives:
        try:current_task_wait_event_v1(db,namespace=namespace,objective=objective)
        except MissingProductionOriginalV1:continue
        result.append(objective.initial_c02_operation_id)
    return tuple(result)


def protected_task_reply_state_v1(db,*,namespace,c02_operation_id):
    """A scheduler observation; current formal admission still owns execution."""
    from .natural_reply_job_v2 import read_original_preparation
    generation=read_original_preparation(db,namespace,c02_operation_id,"generation")
    review=read_original_preparation(db,namespace,c02_operation_id,"review")
    if generation is None and review is None:return {"state":"not_started","job_id":None}
    if generation is None:raise ValueError("review exists without its original protected generation")
    if generation.state=="queued":return {"state":"queued","job_id":generation.seal.job_id}
    if generation.state!="terminal" or review is None or review.state!="terminal":
        return {"state":"unresolved","job_id":generation.seal.job_id}
    if (not generation.terminal_receipt_digest or not review.terminal_receipt_digest
            or review.seal.generation_original_operation_id!=generation.seal.original_operation_id):
        raise ValueError("protected task reply terminal original binding differs")
    for original in (generation,review):
        seal=original.seal
        reservation=db.execute("SELECT state,actual_json FROM runtime_budget_reservations WHERE lease_id=? AND operation_id=?",
            (seal.parent_budget_lease_id,seal.reservation_operation_id)).fetchone()
        if reservation is None or reservation[0]!="settled" or reservation[1] is None:
            return {"state":"unresolved","job_id":generation.seal.job_id}
        cost=json.loads(reservation[1])
        if type(cost.get("model_microusd")) is not int or cost["model_microusd"]<0:
            return {"state":"unresolved","job_id":generation.seal.job_id}
        settled=db.execute("SELECT count(*) FROM runtime_budget_operations WHERE lease_id=? AND operation_id=? AND phase='settle'",
            (seal.parent_budget_lease_id,seal.reservation_operation_id)).fetchone()
        if settled!=(1,):raise ValueError("protected task reply has no exact actual once settlement")
    return {"state":"settled","job_id":generation.seal.job_id}
