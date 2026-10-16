"""Reflection requests from actual adopted cognition, with preserved root depth."""
from __future__ import annotations
from .natural_producer_qualification_v1 import _producer_original_point_v3
from .domain_background_read_v3 import background_json_loads_v3,background_inventory_v3

from dataclasses import asdict, dataclass, replace
import json

from ..domains.d07 import ReflectionCheckpoint
from ..domains.d07.reflection_transition import reflection_checkpoint_key
from ..graph_types import AtomKey, GraphVersion, GraphWrite, Owner
from ..runtime_contracts import canonical_digest, canonical_serialize, NamespaceId
from ..model_broker.d07_cognition_v1 import thaw_d07_cognition_request_v1, parse_d07_cognition_output_v1
from .d07_execution_v1 import read_d07_original_v1, record_d07_original_in_transaction_v1


@dataclass(frozen=True, slots=True)
class D07ReflectionExecutionRequestV1:
    reflection_ref: str
    question_key: str
    question: str
    source_refs: tuple[str, ...]
    unresolved_slots: tuple[str, ...]
    cognition_adoption_receipt_ref: str
    causal_root_ref: str
    causal_depth_original_ref: str
    causal_depth: int
    schema: str = "d07.actual-reflection-request.v1"

    def __post_init__(self):
        if (self.schema != "d07.actual-reflection-request.v1"
                or AtomKey.from_token(self.reflection_ref).type_name != "d07.reflection_checkpoint.v1"
                or type(self.causal_depth) is not int or not 0 <= self.causal_depth < 2):
            raise ValueError("D07 exact actual reflection/root depth required")
        for name in ("question_key", "question", "cognition_adoption_receipt_ref", "causal_root_ref", "causal_depth_original_ref"):
            if type(getattr(self, name)) is not str or not getattr(self, name) or len(getattr(self, name)) > 4096:
                raise ValueError("D07 reflection original locator/question differs")
        for name in ("source_refs", "unresolved_slots"):
            values = getattr(self, name)
            if type(values) is not tuple or not 1 <= len(values) <= 16 or len(set(values)) != len(values):
                raise ValueError("D07 reflection original sources/slots exceed bound")
        for ref in self.source_refs:
            if AtomKey.from_token(ref).type_name != "memory.source":
                raise ValueError("D07 reflection scope requires actual D06 sources")


def read_actual_d07_reflection_request_v1(db, issuer, namespace, ref):
    row = read_d07_original_v1(db, issuer, namespace, "reflection_request", ref)
    if row is None:
        return None
    raw = row[0]
    result = D07ReflectionExecutionRequestV1(**{**raw, "source_refs": tuple(raw["source_refs"]), "unresolved_slots": tuple(raw["unresolved_slots"])})
    actual = read_d07_original_v1(db, issuer, namespace, "execution", result.causal_depth_original_ref)
    if actual is None or actual[0]["causal_depth"] != result.causal_depth or actual[0]["work_kind"] == "simulation":
        raise ValueError("D07 reflection request lacks its actual cognitive/root-depth original")
    checkpoint = _producer_original_point_v3(db,table='graph_atoms',columns=('value', 'valid'),key_columns=('token',),key=(result.reflection_ref,),legacy_reader=lambda:db.execute("SELECT value,valid FROM graph_atoms WHERE token=?", (result.reflection_ref,)).fetchone())
    cognition = _producer_original_point_v3(db,table='graph_atoms',columns=('revision', 'value', 'valid'),key_columns=('token',),key=(result.cognition_adoption_receipt_ref,),legacy_reader=lambda:db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=?", (result.cognition_adoption_receipt_ref,)).fetchone())
    if (checkpoint is None or checkpoint[1] != 1 or cognition is None or cognition[2] != 1
            or background_json_loads_v3(checkpoint[0])["meta_depth"] != result.causal_depth):
        raise ValueError("D07 reflection actual adopted cognition/checkpoint changed")
    history = db.execute("SELECT event_id FROM graph_history WHERE token=? AND revision=?",
        (result.cognition_adoption_receipt_ref, cognition[0])).fetchone()
    if history is None or db.execute("SELECT 1 FROM graph_bundle_operations WHERE bot=? AND persona=? AND operation_id=?",
            (*namespace.as_tuple, history[0])).fetchone() is None:
        raise ValueError("D07 reflection cognition was never adopted by W01")
    return result


def stage_reflection_from_actual_cognition_v1(db, *, prepared, issuer):
    """Actual model unknown slots may create one waiting reflection request."""
    if not db.in_transaction or prepared.work_kind != "concern":
        return None, ()
    row = read_d07_original_v1(db, issuer, prepared.namespace, "result", "d07-result:" + prepared.call_id)
    if row is None:
        raise ValueError("D07 actual cognition result missing")
    from .d07_general_growth_execution_v1 import (D07GeneralGrowthPreparedV1,
        thaw_current_general_growth_prepared_request_v1,parse_current_general_growth_output_v1,general_growth_frozen_sources_v1)
    general=type(prepared)is D07GeneralGrowthPreparedV1
    frozen=(thaw_current_general_growth_prepared_request_v1(prepared)if general
        else thaw_d07_cognition_request_v1(background_json_loads_v3(prepared.frozen_json)))
    output = background_json_loads_v3(row[0]["observation"]["result_json"])
    suggestion=(parse_current_general_growth_output_v1(prepared,output["text"],frozen)if general
        else parse_d07_cognition_output_v1(output["text"], frozen))
    causal_depth=prepared.stage_causal_depth if general else frozen.input.causal_depth
    source_inputs=general_growth_frozen_sources_v1(frozen)if general else frozen.input.sources
    if not suggestion.unknowns or causal_depth >= 2:
        return None, ()
    reflection_id = "d07-reflection:" + canonical_digest((prepared.namespace, prepared.call_id, suggestion.output_digest))[:48]
    key = reflection_checkpoint_key(prepared.namespace, reflection_id)
    if db.execute("SELECT 1 FROM graph_atoms WHERE token=?", (key.token,)).fetchone() is not None:
        raise ValueError("D07 new reflection checkpoint exists without its actual original")
    state = "waiting_for_new_trigger" if suggestion.stop_reason == "wait_for_new_information" else "continue"
    checkpoint = ReflectionCheckpoint(reflection_id, causal_depth, 0, suggestion.unknowns, (), state)
    write = GraphWrite(key, {"schema": key.type_name, **background_json_loads_v3(canonical_serialize(asdict(checkpoint)))})
    cognition_ref = AtomKey(Owner("activity", *prepared.namespace.as_tuple, prepared.activity_id),
        "d07.cognitive_activity.v1", prepared.activity_id).token
    request = D07ReflectionExecutionRequestV1(key.token, frozen.input.question_key,
        "Distinguish the unresolved meanings of the actual previous cognition", tuple(s.source_ref.ref for s in source_inputs),
        suggestion.unknowns, cognition_ref, cognition_ref, "d07-terminal:" + prepared.call_id, causal_depth)
    return request, (write,)


def record_actual_reflection_after_cas_v1(db, issuer, prepared, request, *, operation_id):
    if request is None:
        return None
    if not db.in_transaction or operation_id != prepared.operation_id:
        raise ValueError("D07 reflection request requires its actual parent cognition CAS")
    row = _producer_original_point_v3(db,table='graph_atoms',columns=('revision', 'value', 'valid'),key_columns=('token',),key=(request.reflection_ref,),legacy_reader=lambda:db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=?", (request.reflection_ref,)).fetchone())
    cognition = db.execute("SELECT revision,valid FROM graph_atoms WHERE token=?", (request.cognition_adoption_receipt_ref,)).fetchone()
    if row is None or row[2] != 1 or cognition is None or cognition[1] != 1:
        raise ValueError("D07 reflection parent/checkpoint actual graph adoption absent")
    history = db.execute("SELECT event_id FROM graph_history WHERE token=? AND revision=?", (request.reflection_ref, row[0])).fetchone()
    if history != (operation_id,):
        raise ValueError("D07 reflection request was not created by its actual cognition event")
    ref = "d07-reflection-request:" + prepared.call_id
    record_d07_original_in_transaction_v1(db, issuer, prepared.namespace, "reflection_request", ref, asdict(request))
    record_reflection_continuation_after_cas_v3(db,issuer,prepared,request,ref)
    return ref


def adopt_actual_d07_reflection_stop_v1(stage, *, actual_stop_reason):
    """Preserve a model's bounded wait without buying another reflection turn."""
    if stage.work_kind != "reflection" or stage.execution is None or stage.status != "staged":
        raise ValueError("D07 reflection wait requires actual completed reflection")
    if actual_stop_reason != "wait_for_new_information":
        return stage
    if stage.execution.resolved_slots:
        raise ValueError("D07 wait cannot claim resolved slots")
    writes = []
    checkpoint_seen = activity_seen = False
    for write in stage.proposal.typed_writes:
        value = dict(write.value)
        if write.key.type_name == "d07.reflection_checkpoint.v1":
            value["status"] = "waiting_for_new_trigger"
            checkpoint_seen = True
        elif write.key.type_name == "d07.cognitive_activity.v1":
            value["stop_reason"] = actual_stop_reason
            activity_seen = True
        writes.append(GraphWrite(write.key, value))
    if not checkpoint_seen or not activity_seen:
        raise ValueError("D07 reflection wait lacks checkpoint/activity writes")
    return replace(stage, proposal=replace(stage.proposal, typed_writes=tuple(writes)),
        provenance={**stage.provenance, "actual_stop_reason": actual_stop_reason},
        stop_reason="waiting_for_new_trigger")


def stage_actual_d07_reflection_stop_v1(db, issuer, stage):
    """Independently read the signed paid result before transforming its stage."""
    from .d07_execution_v1 import read_prepared_d07_execution_v1
    if stage.work_kind != "reflection" or stage.execution is None:
        return stage
    execution = stage.execution
    prefix = "d07-terminal:"
    if not execution.terminal_ref.startswith(prefix):
        raise ValueError("D07 actual reflection terminal locator differs")
    call_id = execution.terminal_ref[len(prefix):]
    namespace = stage.envelope.authority.namespace
    rows = db.execute("SELECT original_ref FROM graph_d07_execution_originals_v1 WHERE bot=? AND persona=? "
        "AND kind='prepared' AND json_extract(payload_json,'$.call_id')=? LIMIT 2", (*namespace.as_tuple, call_id)).fetchall()
    if len(rows) != 1:
        raise ValueError("D07 actual reflection preparation is not unique")
    prepared = read_prepared_d07_execution_v1(db, issuer, namespace, rows[0][0])
    terminal = read_d07_original_v1(db, issuer, namespace, "execution", execution.terminal_ref)
    result = read_d07_original_v1(db, issuer, namespace, "result", "d07-result:" + call_id)
    if terminal is None or terminal[0] != asdict(execution) and terminal[0] != background_json_loads_v3(canonical_serialize(asdict(execution))):
        raise ValueError("D07 reflection stage differs from its signed terminal")
    if result is None or prepared.work_kind != "reflection":
        raise ValueError("D07 actual reflection paid result missing")
    frozen = thaw_d07_cognition_request_v1(background_json_loads_v3(prepared.frozen_json))
    output = background_json_loads_v3(result[0]["observation"]["result_json"])
    suggestion = parse_d07_cognition_output_v1(output["text"], frozen)
    return adopt_actual_d07_reflection_stop_v1(stage, actual_stop_reason=suggestion.stop_reason)

@dataclass(frozen=True, slots=True)
class D07ReflectionContinuationOriginalV3:
    namespace: NamespaceId
    original_ref: str
    reflection_request_ref: str
    reflection_request_digest: str
    parent_job_id: str
    parent_prepared_digest: str
    parent_execution_ref: str
    parent_execution_digest: str
    checkpoint_ref: GraphVersion
    checkpoint_digest: str
    ticket_id: str
    category: str
    source_refs: tuple[str, ...]
    parent_budget_lease_ref: str
    parent_grant_digest: str
    original_deadline_utc: float
    cycle_job_ref: str | None
    schema: str = "d07.reflection-continuation.v3"

    def __post_init__(self):
        from ..graph_types import GraphVersion
        from ..runtime_contracts import NamespaceId
        import math
        if (self.schema != "d07.reflection-continuation.v3" or type(self.namespace) is not NamespaceId
                or type(self.checkpoint_ref) is not GraphVersion or self.checkpoint_ref.revision < 1
                or self.checkpoint_ref.key.type_name != "d07.reflection_checkpoint.v1"
                or NamespaceId.from_key(self.checkpoint_ref.key) != self.namespace
                or type(self.source_refs) is not tuple or not 1 <= len(self.source_refs) <= 16
                or len(set(self.source_refs)) != len(self.source_refs)
                or type(self.original_deadline_utc) not in (int, float) or not math.isfinite(self.original_deadline_utc)):
            raise ValueError("reflection continuation requires its original checkpoint/source/deadline")
        for name in ("original_ref", "reflection_request_ref", "parent_job_id", "parent_execution_ref",
                "ticket_id", "category", "parent_budget_lease_ref"):
            value = getattr(self, name)
            if type(value) is not str or not 1 <= len(value) <= 4096:
                raise ValueError("reflection continuation requires exact bounded locators")
        for name in ("reflection_request_digest", "parent_prepared_digest", "parent_execution_digest",
                "checkpoint_digest", "parent_grant_digest"):
            value = getattr(self, name)
            if type(value) is not str or len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value):
                raise ValueError("reflection continuation requires exact signed commitments")
        for ref in self.source_refs:
            key = AtomKey.from_token(ref)
            if key.type_name != "memory.source" or NamespaceId.from_key(key) != self.namespace:
                raise ValueError("reflection continuation crossed its source namespace")
        if self.cycle_job_ref is not None:
            key = AtomKey.from_token(self.cycle_job_ref)
            if key.type_name != "runtime.job" or NamespaceId.from_key(key) != self.namespace:
                raise ValueError("Self reflection continuation crossed its parent cycle")

    @property
    def operation_id(self):
        return "d07-reflection:" + canonical_digest(
            (self.namespace, self.reflection_request_digest, self.checkpoint_ref.revision))[:48]


def read_reflection_continuation_v3(db, issuer, namespace, original_ref):
    from ..runtime_contracts import NamespaceId
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    from ..domains.d01.production_operations_v1 import plain_v1
    row = read_d07_original_v1(db, issuer, namespace, "reflection_continuation", original_ref)
    if row is None:
        return None
    raw = dict(row[0])
    raw["namespace"] = NamespaceId(**raw["namespace"])
    raw["checkpoint_ref"] = decode_typed_production_value_v1(raw["checkpoint_ref"], GraphVersion)
    raw["source_refs"] = tuple(raw["source_refs"])
    value = D07ReflectionContinuationOriginalV3(**raw)
    if value.namespace != namespace or value.original_ref != original_ref or canonical_digest(plain_v1(value)) != row[1]:
        raise ValueError("reflection continuation differs from its signed original")
    return value, row[1]


def record_reflection_continuation_after_cas_v3(db, issuer, prepared, request, request_ref):
    from datetime import datetime
    from .jobs import get_job
    from .d07_execution_v1 import D07RelationshipPreparedV2
    from .d07_method_growth_semantic_v2 import D07MethodGrowthPreparedV2
    if not db.in_transaction or request is None:
        raise ValueError("reflection continuation requires the actual parent adoption transaction")
    row = read_d07_original_v1(db, issuer, prepared.namespace, "reflection_request", request_ref)
    terminal = read_d07_original_v1(db, issuer, prepared.namespace, "execution", request.causal_depth_original_ref)
    job = get_job(db, prepared.job_id)
    choice = job.continuation["choice"]
    checkpoint = _producer_original_point_v3(db,table='graph_atoms',columns=('revision', 'value', 'valid'),key_columns=('token',),key=(request.reflection_ref,),legacy_reader=lambda:db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=?",
        (request.reflection_ref,)).fetchone())
    if (row is None or row[0] != background_json_loads_v3(canonical_serialize(asdict(request))) or terminal is None
            or job.phase != "completed"
            or job.result_ref != request.causal_depth_original_ref or checkpoint is None or checkpoint[2] != 1):
        raise ValueError("reflection continuation lost its actual parent request/terminal/job/CAS")
    require_actual_d07_execution_prepared_relation_v3(terminal[0],prepared,parent_budget_ref=job.budget_ref)
    grant = issuer.current_budget_grant(db, job.budget_ref)
    original_ref = "d07-reflection-continuation:" + prepared.call_id
    cycle_ref = prepared.cycle_ref.key.token if type(prepared) in {
        D07RelationshipPreparedV2, D07MethodGrowthPreparedV2} else None
    continuation = D07ReflectionContinuationOriginalV3(prepared.namespace, original_ref, request_ref,
        row[1], prepared.job_id, prepared.digest, request.causal_depth_original_ref, terminal[1],
        GraphVersion(AtomKey.from_token(request.reflection_ref), checkpoint[0]),
        canonical_digest(background_json_loads_v3(checkpoint[1])), choice["ticket_id"],
        job.continuation["request"]["category"], request.source_refs, job.budget_ref, canonical_digest(grant),
        datetime.fromisoformat(job.deadline_utc.replace("Z", "+00:00")).timestamp(), cycle_ref)
    from ..domains.d01.production_operations_v1 import plain_v1
    record_d07_original_in_transaction_v1(db, issuer, prepared.namespace,
        "reflection_continuation", original_ref, plain_v1(continuation))
    return original_ref


def require_current_reflection_parent_v3(db, *, issuer, namespace, continuation, now_utc):
    from datetime import datetime
    from .budget import get_budget_lease, require_budget_family_admissible
    from .jobs import get_job
    from .d07_execution_v1 import read_prepared_d07_execution_v1
    actual = read_reflection_continuation_v3(db, issuer, namespace, continuation.original_ref)
    if actual is None or actual[0] != continuation:
        raise ValueError("reflection continuation is not its actual signed producer")
    request = read_actual_d07_reflection_request_v1(db, issuer, namespace, continuation.reflection_request_ref)
    prepared = read_prepared_d07_execution_v1(db, issuer, namespace, continuation.parent_job_id)
    terminal = read_d07_original_v1(db, issuer, namespace, "execution", continuation.parent_execution_ref)
    job = get_job(db, continuation.parent_job_id)
    grant = issuer.current_budget_grant(db, job.budget_ref)
    lease = get_budget_lease(db, job.budget_ref)
    checkpoint = _producer_original_point_v3(db,table='graph_atoms',columns=('revision', 'value', 'valid'),key_columns=('token',),key=(continuation.checkpoint_ref.key.token,),legacy_reader=lambda:db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=?",
        (continuation.checkpoint_ref.key.token,)).fetchone())
    if (request is None or prepared is None or prepared.digest != continuation.parent_prepared_digest
            or terminal is None or terminal[1] != continuation.parent_execution_digest
            or terminal[0]["source_refs"] != list(continuation.source_refs)
            or request.source_refs != continuation.source_refs or request.causal_depth >= 2
            or job.phase != "completed" or job.cancel_epoch or job.result_ref != continuation.parent_execution_ref
            or job.budget_ref != continuation.parent_budget_lease_ref or lease.state != "active"
            or canonical_digest(grant) != continuation.parent_grant_digest
            or datetime.fromisoformat(job.deadline_utc.replace("Z", "+00:00")).timestamp() != continuation.original_deadline_utc
            or not now_utc < min(continuation.original_deadline_utc, grant.valid_until_utc)
            or checkpoint is None or (checkpoint[0], checkpoint[2]) != (continuation.checkpoint_ref.revision, 1)
            or canonical_digest(background_json_loads_v3(checkpoint[1])) != continuation.checkpoint_digest
            or background_json_loads_v3(checkpoint[1])["status"] != "continue"
            or job.continuation["choice"]["ticket_id"] != continuation.ticket_id):
        raise ValueError("reflection original parent/source/control/checkpoint/grant/deadline is no longer current")
    require_actual_d07_execution_prepared_relation_v3(terminal[0],prepared,parent_budget_ref=job.budget_ref)
    require_budget_family_admissible(db, lease.lease_id)
    return request, prepared, job, grant


def reflection_self_group_v3(db, *, issuer, continuation, now_utc):
    from .jobs import get_job
    from .foreground_cycle_v1 import foreground_cycle_from_wire_v1
    from .d11_types import job_graph_write
    from datetime import datetime
    if continuation.cycle_job_ref is None:
        return {}
    key = AtomKey.from_token(continuation.cycle_job_ref)
    job = get_job(db, key.name)
    cycle = foreground_cycle_from_wire_v1(job.continuation)
    head = _producer_original_point_v3(db,table='graph_atoms',columns=('revision', 'value', 'valid'),key_columns=('token',),key=(key.token,),legacy_reader=lambda:db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=?", (key.token,)).fetchone())
    if (head is None or head[2] != 1 or background_json_loads_v3(head[1]) != job_graph_write(job).value
            or job.phase not in {"queued", "running", "waiting"} or job.cancel_epoch
            or cycle.cancel_generation != job.cancel_epoch
            or cycle.call_plan.parent_budget_lease_ref != continuation.parent_budget_lease_ref
            or cycle.stage == "completed"
            or now_utc >= datetime.fromisoformat(job.deadline_utc.replace("Z","+00:00")).timestamp()):
        raise ValueError("Self reflection cannot renew or revive its closed/cancelled cycle")
    return {"cycle_ref": GraphVersion(key, head[0]), "cycle_digest": canonical_digest(job_graph_write(job).value),
        "call_plan_digest": canonical_digest(cycle.call_plan), "c02_operation_id": cycle.c02_operation_id,
        "cancel_generation": cycle.cancel_generation}


def prepare_reflection_metadata_v3(db, *, issuer, namespace, continuation_ref, now_utc):
    from .d07_execution_v1 import read_prepared_d07_execution_v1, d07_execution_ids_v1
    actual = read_reflection_continuation_v3(db, issuer, namespace, continuation_ref)
    if actual is None:
        return None
    continuation, digest = actual
    ids = d07_execution_ids_v1(namespace, continuation.operation_id, "reflection")
    prior = read_prepared_d07_execution_v1(db, issuer, namespace, ids["job"])
    if prior is not None:
        if (prior.reflection_continuation_ref, prior.reflection_continuation_digest) != (continuation_ref, digest):
            raise ValueError("reflection stable identity names another actual continuation")
        return {"status": "prepared", "job_id": prior.job_id, "continuation": continuation,
            "continuation_digest": digest}
    require_current_reflection_parent_v3(db, issuer=issuer, namespace=namespace,
        continuation=continuation, now_utc=now_utc)
    reflection_self_group_v3(db, issuer=issuer, continuation=continuation, now_utc=now_utc)
    return {"status": "candidate", "job_id": ids["job"], "continuation": continuation,
        "continuation_digest": digest}


def reflection_preparation_fields_v3(db, *, issuer, continuation, continuation_digest, now_utc):
    request, parent, job, grant = require_current_reflection_parent_v3(db, issuer=issuer,
        namespace=continuation.namespace, continuation=continuation, now_utc=now_utc)
    return {"schema": "d07.reflection-prepared.v3",
        "reflection_request_ref": continuation.reflection_request_ref,
        "reflection_request_digest": continuation.reflection_request_digest,
        "reflection_continuation_ref": continuation.original_ref,
        "reflection_continuation_digest": continuation_digest,
        "parent_prepared_ref": continuation.parent_job_id, "parent_prepared_digest": parent.digest,
        "parent_execution_ref": continuation.parent_execution_ref,
        "parent_execution_digest": continuation.parent_execution_digest,
        "checkpoint_ref": continuation.checkpoint_ref, "checkpoint_digest": continuation.checkpoint_digest,
        "ticket_id": continuation.ticket_id, "source_refs": continuation.source_refs,
        "parent_budget_lease_ref": job.budget_ref, "parent_grant_digest": canonical_digest(grant),
        "original_deadline_utc": continuation.original_deadline_utc,
        **reflection_self_group_v3(db, issuer=issuer, continuation=continuation, now_utc=now_utc)}

def require_no_pending_self_reflection_v3(db, *, frame, job, continuation, issuer, installed_bundle):
    """The signed request is the durable obligation; no new cycle state exists."""
    from .d07_execution_v1 import TABLE, d07_execution_ids_v1, read_prepared_d07_execution_v1
    from .d01_production_operations_v1 import MissingProductionOriginalV1
    from .d11_types import job_graph_write
    from .jobs import get_job
    from .budget import get_budget_lease
    key = job_graph_write(job).key.token
    rows = db.execute("SELECT original_ref FROM " + TABLE + " WHERE bot=? AND persona=? "
        "AND kind='reflection_continuation' AND json_extract(payload_json,'$.cycle_job_ref')=? "
        "ORDER BY original_ref LIMIT 129", (*frame.envelope.authority.namespace.as_tuple,key)).fetchall()
    if len(rows)>128:
        raise MissingProductionOriginalV1("complete_self_reflection_obligation_inventory")
    attempts={value.call_id:value for value in continuation.call_plan.attempts}
    for (ref,) in rows:
        value=read_reflection_continuation_v3(db,issuer,frame.envelope.authority.namespace,ref)[0]
        ids=d07_execution_ids_v1(value.namespace,value.operation_id,"reflection")
        child=read_prepared_d07_execution_v1(db,issuer,value.namespace,ids["job"])
        if child is not None:
            current=get_job(db,child.job_id)
            if current.cancel_epoch or current.phase in {"cancelled","failed"}:
                continue
            if child.call_id in attempts:
                continue
        if frame.now_utc>=value.original_deadline_utc:
            continue
        grant=issuer.current_budget_grant(db,value.parent_budget_lease_ref)
        lease=get_budget_lease(db,value.parent_budget_lease_ref)
        if (lease.state!="active" or canonical_digest(grant)!=value.parent_grant_digest
                or frame.now_utc>=grant.valid_until_utc):
            continue
        checkpoint=frame.snapshot.get(value.checkpoint_ref.key)
        if (checkpoint is None or checkpoint.revision!=value.checkpoint_ref.revision or not checkpoint.valid
                or checkpoint.value.get("status")!="continue"):
            continue
        workflow=installed_bundle.model_workflows.d07_cognition
        if workflow is None:
            continue
        plan=continuation.call_plan
        auxiliary=sum(value.slot in {"C3","C4"} for value in plan.attempts)
        if (len(plan.attempts)>=6 or auxiliary>=2
                or sum(value.input_ceiling for value in plan.attempts)+workflow.quote_ceiling["input_tokens"]>48000
                or sum(value.output_ceiling for value in plan.attempts)+workflow.quote_ceiling["output_tokens"]>8000):
            continue
        if child is None:
            request,parent,parent_job,actual_grant=require_current_reflection_parent_v3(
                db,issuer=issuer,namespace=value.namespace,continuation=value,now_utc=frame.now_utc)
            from .d01_production_operations_v1 import CurrentDomainReadV1
            CurrentDomainReadV1(frame).source_family(db,value.source_refs,purpose="proposal")
        raise MissingProductionOriginalV1("actual_pending_reflection_acquire_and_call_plan_CAS:"+ref)

def require_reflection_c3_descriptor_v3(db, *, namespace, descriptor, issuer):
    """Authenticate only the issued metadata; prepared frozen bodies stay private."""
    from .d07_execution_v1 import read_d07_original_v1
    from .jobs import get_job
    from .natural_producer_qualification_v1 import _producer_original_point_v3, _producer_json_loads_v3
    from ..domains.d01.production_operations_v1 import plain_v1
    actual=read_reflection_continuation_v3(db,issuer,namespace,descriptor.reflection_continuation_ref)
    if actual is None or actual[1]!=descriptor.reflection_continuation_digest:
        raise ValueError("reflection C3 has no exact signed continuation")
    continuation=actual[0]
    fields=("reflection_request_ref","reflection_request_digest","parent_prepared_digest",
        "parent_execution_ref","parent_execution_digest","checkpoint_ref","checkpoint_digest",
        "parent_budget_lease_ref","parent_grant_digest","original_deadline_utc")
    if any(getattr(descriptor,name)!=getattr(continuation,name) for name in fields):
        raise ValueError("reflection C3 changed an original cause/checkpoint/budget/deadline")
    if (descriptor.parent_prepared_ref!=continuation.parent_job_id
            or descriptor.cycle_ref.key.token!=continuation.cycle_job_ref
            or descriptor.operation_id!=continuation.operation_id):
        raise ValueError("reflection C3 crossed its actual parent or stable identity")
    request=read_d07_original_v1(db,issuer,namespace,"reflection_request",continuation.reflection_request_ref)
    execution=read_d07_original_v1(db,issuer,namespace,"execution",continuation.parent_execution_ref)
    parent=read_d07_original_v1(db,issuer,namespace,"prepared",continuation.parent_job_id)
    if (request is None or request[1]!=continuation.reflection_request_digest or execution is None
            or execution[1]!=continuation.parent_execution_digest or parent is None
            or parent[1]!=continuation.parent_prepared_digest
            or execution[0]["source_refs"]!=list(continuation.source_refs)
            or request[0]["source_refs"]!=list(continuation.source_refs)
            or request[0]["causal_depth"]>=2
            or parent[0].get("schema") not in {"d07.relationship-prepared.v2","d07.method-growth-prepared.v2"}
            or parent[0]["cycle_ref"]["key"]!=asdict(descriptor.cycle_ref.key)
            or parent[0]["c02_operation_id"]!=descriptor.c02_operation_id
            or parent[0]["cancel_generation"]!=descriptor.cancel_generation):
        raise ValueError("reflection C3 lost its actual signed parent execution/preparation/source/root")
    parent_job=get_job(db,continuation.parent_job_id)
    require_actual_d07_execution_prepared_metadata_relation_v3(execution[0],parent[0],
        parent_budget_ref=parent_job.budget_ref,source_refs=continuation.source_refs)
    if (parent_job.phase!="completed" or parent_job.cancel_epoch
            or parent_job.result_ref!=continuation.parent_execution_ref
            or parent_job.budget_ref!=continuation.parent_budget_lease_ref):
        raise ValueError("reflection C3 parent execution is not actually completed")
    lineage=read_reflection_checkpoint_lineage_v3(db,issuer=issuer,continuation=continuation)
    return continuation,lineage


def reflection_obligation_read_plan_inputs_v3(db, namespace, cycle_job_ref):
    """Unsigned locators expand the plan; the final reader authenticates originals."""
    from .d07_execution_v1 import TABLE
    rows=db.execute("SELECT original_ref,payload_json FROM "+TABLE+" WHERE bot=? AND persona=? "
        "AND kind='reflection_continuation' AND json_extract(payload_json,'$.cycle_job_ref')=? "
        "ORDER BY original_ref LIMIT 129",(*namespace.as_tuple,cycle_job_ref)).fetchall()
    if len(rows)>128:
        from .d01_production_operations_v1 import MissingProductionOriginalV1
        raise MissingProductionOriginalV1("complete_reflection_obligation_read_plan")
    keys,roots,originals=[],[],[]
    for ref,encoded in rows:
        raw=background_json_loads_v3(encoded)
        keys.append(AtomKey.from_token(raw["checkpoint_ref"]["key"]))
        roots.extend(raw["source_refs"])
        originals.extend((ref,raw["reflection_request_ref"],raw["parent_job_id"],raw["parent_execution_ref"]))
    return keys,roots,originals

def read_reflection_checkpoint_lineage_v3(db, *, issuer, continuation):
    """Birth history stays immutable; one authenticated child adoption may advance it."""
    from .natural_producer_qualification_v1 import _producer_original_point_v3, _producer_json_loads_v3
    from .d07_execution_v1 import read_prepared_d07_execution_v1, d07_execution_ids_v1, D07ReflectionPreparedV3
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    from .jobs import get_job
    ns,key=continuation.namespace,continuation.checkpoint_ref.key
    parent=get_job(db,continuation.parent_job_id)
    def history_at(revision):
        return _producer_original_point_v3(db,table="graph_history",
            columns=("event_bot","event_persona","event_id","value","valid"),
            key_columns=("token","revision"),key=(key.token,revision),
            legacy_reader=lambda:db.execute("SELECT event_bot,event_persona,event_id,value,valid FROM graph_history "
                "WHERE token=? AND revision=?",(key.token,revision)).fetchone())
    born=history_at(continuation.checkpoint_ref.revision)
    if (born is None or born[:3]!=(*ns.as_tuple,parent.operation_id) or born[4]!=1
            or canonical_digest(_producer_json_loads_v3(born[3]))!=continuation.checkpoint_digest):
        raise ValueError("reflection lost its actual immutable parent checkpoint birth")
    if _producer_json_loads_v3(born[3])["status"]!="continue":
        raise ValueError("reflection parent checkpoint birth did not authorize continuation")
    head=_producer_original_point_v3(db,table="graph_atoms",columns=("revision","value","valid"),
        key_columns=("token","bot","persona"),key=(key.token,*ns.as_tuple),
        legacy_reader=lambda:db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=? AND bot=? AND persona=?",
            (key.token,*ns.as_tuple)).fetchone())
    if head is None or head[2]!=1:
        raise ValueError("reflection checkpoint is no longer a valid current head")
    value=_producer_json_loads_v3(head[1])
    if (head[0]==continuation.checkpoint_ref.revision and canonical_digest(value)==continuation.checkpoint_digest):
        return "birth",GraphVersion(key,head[0]),value
    ids=d07_execution_ids_v1(ns,continuation.operation_id,"reflection")
    prepared=read_prepared_d07_execution_v1(db,issuer,ns,ids["job"])
    if (type(prepared) is not D07ReflectionPreparedV3
            or prepared.reflection_continuation_ref!=continuation.original_ref
            or prepared.checkpoint_ref!=continuation.checkpoint_ref):
        raise ValueError("advanced reflection has no exact child prepared original")
    child=get_job(db,prepared.job_id)
    execution=read_d07_original_v1(db,issuer,ns,"execution","d07-terminal:"+prepared.call_id)
    original=read_adopted_domain_operation_v1(db,ns,prepared.operation_id)
    if (child.phase!="completed" or child.cancel_epoch or execution is None
            or child.result_ref!="d07-terminal:"+prepared.call_id
            or original is None or (original["domain"],original["operation_kind"])!=("d07","advance_reflection")):
        raise ValueError("advanced checkpoint lost its actual completed/adopted child")
    require_actual_d07_execution_prepared_relation_v3(execution[0],prepared,parent_budget_ref=child.budget_ref)
    provenance=original["payload"]["provenance"]
    behavior=provenance["behavior"]
    prior=behavior["prior_checkpoint"]
    expected={"key":key.token,"revision":continuation.checkpoint_ref.revision}
    writes=tuple(row for row in original["payload"]["writes"] if row["key"]==key.token)
    versions=tuple(version for version in original["receipt"].write_versions if version.key==key)
    history=history_at(head[0])
    if (provenance["work_kind"]!="reflection" or behavior["terminal"]!=child.result_ref or prior!=expected
            or len(writes)!=1 or writes[0]["value"]!=value or versions!=(GraphVersion(key,head[0]),)
            or head[0]!=continuation.checkpoint_ref.revision+1 or history is None
            or history[:3]!=(*ns.as_tuple,prepared.operation_id) or history[4]!=1
            or _producer_json_loads_v3(history[3])!=value
            or provenance["execution"]!=execution[0]):
        raise ValueError("current reflection checkpoint is not the unique real child adoption")
    return "adopted_child",GraphVersion(key,head[0]),value


def verify_reflection_checkpoint_member_v3(db, *, prepared, issuer):
    continuation=read_reflection_continuation_v3(db,issuer,prepared.namespace,prepared.reflection_continuation_ref)
    if continuation is None or continuation[1]!=prepared.reflection_continuation_digest:
        raise ValueError("reflection current content member lost its original continuation")
    return read_reflection_checkpoint_lineage_v3(db,issuer=issuer,continuation=continuation[0])


def require_actual_d07_execution_prepared_relation_v3(raw,parent,*,parent_budget_ref=None):
    """The existing ordinary writer relation; no new field or signed-byte revision."""
    from dataclasses import fields
    from .d07_current_behavior_v1 import D07ExecutionOriginalV1
    from .d07_execution_v1 import D07PreparedExecutionV1,D07RelationshipPreparedV2,D07ReflectionPreparedV3
    from .d07_method_growth_semantic_v2 import D07MethodGrowthPreparedV2
    from .d07_general_growth_execution_v1 import (D07GeneralGrowthPreparedV1,
        thaw_current_general_growth_prepared_request_v1,general_growth_frozen_sources_v1)
    if type(parent)not in {D07PreparedExecutionV1,D07RelationshipPreparedV2,D07MethodGrowthPreparedV2,D07ReflectionPreparedV3,D07GeneralGrowthPreparedV1}:
        raise TypeError("actual ordinary D07 prepared producer required")
    if type(raw)is not dict or set(raw)!={field.name for field in fields(D07ExecutionOriginalV1)}:
        raise ValueError("ordinary D07 execution must retain its exact existing writer schema")
    identity=("operation_id","activity_id","effect_id","attempt_id","execution_id","work_kind","activation_generation")
    if (any(raw[name]!=getattr(parent,name)for name in identity)
            or raw["terminal_ref"]!="d07-terminal:"+parent.call_id
            or raw["input_digest"]!=parent.stage_input_digest or raw["status"]!="completed"
            or parent_budget_ref is not None and raw["parent_budget_ref"]!=parent_budget_ref):
        raise ValueError("D07 actual execution lost its original prepared identity/input/paid parent")
    from .d07_execution_v1 import decode_d07_execution_original_v1
    from ..model_broker.d07_cognition_v1 import thaw_d07_cognition_request_v1
    execution=decode_d07_execution_original_v1(raw)
    general=type(parent)is D07GeneralGrowthPreparedV1
    frozen=(thaw_current_general_growth_prepared_request_v1(parent)if general
        else thaw_d07_cognition_request_v1(background_json_loads_v3(parent.frozen_json)))
    source_inputs=general_growth_frozen_sources_v1(frozen)if general else frozen.input.sources
    causal_depth=parent.stage_causal_depth if general else frozen.input.causal_depth
    if (execution.source_refs!=tuple(source.source_ref.ref for source in source_inputs)
            or execution.causal_depth!=causal_depth):
        raise ValueError("D07 actual execution changed the original source/read-depth set")
    return execution


def require_actual_d07_execution_prepared_metadata_relation_v3(raw,parent_raw,*,parent_budget_ref,source_refs):
    from dataclasses import fields
    from .d07_current_behavior_v1 import D07ExecutionOriginalV1
    from .d07_execution_v1 import D07PreparedExecutionV1,D07RelationshipPreparedV2,D07ReflectionPreparedV3
    from .d07_method_growth_semantic_v2 import D07MethodGrowthPreparedV2
    from .d07_general_growth_execution_v1 import D07GeneralGrowthPreparedV1
    classes={cls.__dataclass_fields__["schema"].default:cls for cls in (D07PreparedExecutionV1,
        D07RelationshipPreparedV2,D07ReflectionPreparedV3,D07MethodGrowthPreparedV2,D07GeneralGrowthPreparedV1)}
    cls=classes.get(parent_raw.get("schema"))
    if (cls is None or set(parent_raw)!={field.name for field in fields(cls)}
            or set(raw)!={field.name for field in fields(D07ExecutionOriginalV1)}):
        raise ValueError("reflection metadata lost its exact existing prepared/execution writer schemas")
    identity=("operation_id","activity_id","effect_id","attempt_id","execution_id","work_kind","activation_generation")
    if (any(raw[name]!=parent_raw[name]for name in identity)
            or raw["terminal_ref"]!="d07-terminal:"+parent_raw["call_id"]
            or raw["input_digest"]!=parent_raw["stage_input_digest"]
            or raw["status"]!="completed" or raw["parent_budget_ref"]!=parent_budget_ref
            or tuple(raw["source_refs"])!=tuple(source_refs) or not raw["cost_receipt_refs"]):
        raise ValueError("reflection metadata crossed the actual completed execution/prepared/cost/Source relation")
