"""Reflection requests from actual adopted cognition, with preserved root depth."""
from __future__ import annotations

from dataclasses import asdict, dataclass, replace
import json

from ..domains.d07 import ReflectionCheckpoint
from ..domains.d07.reflection_transition import reflection_checkpoint_key
from ..graph_types import AtomKey, GraphVersion, GraphWrite, Owner
from ..runtime_contracts import canonical_digest, canonical_serialize
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
    checkpoint = db.execute("SELECT value,valid FROM graph_atoms WHERE token=?", (result.reflection_ref,)).fetchone()
    cognition = db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=?", (result.cognition_adoption_receipt_ref,)).fetchone()
    if (checkpoint is None or checkpoint[1] != 1 or cognition is None or cognition[2] != 1
            or json.loads(checkpoint[0])["meta_depth"] != result.causal_depth):
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
    frozen = thaw_d07_cognition_request_v1(json.loads(prepared.frozen_json))
    output = json.loads(row[0]["observation"]["result_json"])
    suggestion = parse_d07_cognition_output_v1(output["text"], frozen)
    if not suggestion.unknowns or frozen.input.causal_depth >= 2:
        return None, ()
    reflection_id = "d07-reflection:" + canonical_digest((prepared.namespace, prepared.call_id, suggestion.output_digest))[:48]
    key = reflection_checkpoint_key(prepared.namespace, reflection_id)
    if db.execute("SELECT 1 FROM graph_atoms WHERE token=?", (key.token,)).fetchone() is not None:
        raise ValueError("D07 new reflection checkpoint exists without its actual original")
    checkpoint = ReflectionCheckpoint(reflection_id, frozen.input.causal_depth, 0, suggestion.unknowns, (), "continue")
    write = GraphWrite(key, {"schema": key.type_name, **json.loads(canonical_serialize(asdict(checkpoint)))})
    cognition_ref = AtomKey(Owner("activity", *prepared.namespace.as_tuple, prepared.activity_id),
        "d07.cognitive_activity.v1", prepared.activity_id).token
    request = D07ReflectionExecutionRequestV1(key.token, frozen.input.question_key,
        "Distinguish the unresolved meanings of the actual previous cognition", tuple(s.source_ref.ref for s in frozen.input.sources),
        suggestion.unknowns, cognition_ref, cognition_ref, "d07-terminal:" + prepared.call_id, frozen.input.causal_depth)
    return request, (write,)


def record_actual_reflection_after_cas_v1(db, issuer, prepared, request, *, operation_id):
    if request is None:
        return None
    if not db.in_transaction or operation_id != prepared.operation_id:
        raise ValueError("D07 reflection request requires its actual parent cognition CAS")
    row = db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=?", (request.reflection_ref,)).fetchone()
    cognition = db.execute("SELECT revision,valid FROM graph_atoms WHERE token=?", (request.cognition_adoption_receipt_ref,)).fetchone()
    if row is None or row[2] != 1 or cognition is None or cognition[1] != 1:
        raise ValueError("D07 reflection parent/checkpoint actual graph adoption absent")
    history = db.execute("SELECT event_id FROM graph_history WHERE token=? AND revision=?", (request.reflection_ref, row[0])).fetchone()
    if history != (operation_id,):
        raise ValueError("D07 reflection request was not created by its actual cognition event")
    ref = "d07-reflection-request:" + prepared.call_id
    record_d07_original_in_transaction_v1(db, issuer, prepared.namespace, "reflection_request", ref, asdict(request))
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
    if terminal is None or terminal[0] != asdict(execution) and terminal[0] != json.loads(canonical_serialize(asdict(execution))):
        raise ValueError("D07 reflection stage differs from its signed terminal")
    if result is None or prepared.work_kind != "reflection":
        raise ValueError("D07 actual reflection paid result missing")
    frozen = thaw_d07_cognition_request_v1(json.loads(prepared.frozen_json))
    output = json.loads(result[0]["observation"]["result_json"])
    suggestion = parse_d07_cognition_output_v1(output["text"], frozen)
    return adopt_actual_d07_reflection_stop_v1(stage, actual_stop_reason=suggestion.stop_reason)
