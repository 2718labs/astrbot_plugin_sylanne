"""Closed D07 stage payload and follow-up codecs for installed W01/C09."""
from __future__ import annotations

from dataclasses import asdict, fields

from ..domains.d01.production_operations_v1 import stage_result_v1
from ..domains.d07 import AttentionPolicy, AttentionTicket, SimulationRequest, SimulationBranch
from ..domains.d07.concern_round import ConcernRoundV1, ConcernServiceChoiceV1
from ..graph_types import AtomKey
from .d07_current_behavior_v1 import D07ExecutionOriginalV1, _json
from .d07_execution_v1 import decode_d07_execution_original_v1, D07SemanticQuestionV1, D07SemanticTargetOriginalV1
from ..runtime_contracts import VersionedRef

KINDS = {"concern": "serve_concern", "reflection": "advance_reflection", "simulation": "run_simulation"}


def _fields(raw, cls):
    if type(raw) is not dict or set(raw) != {f.name for f in fields(cls)}:
        raise ValueError("D07 stage original exact fields differ: " + cls.__name__)


def _collection(raw, name, cap=16):
    if type(raw) is not list or len(raw) > cap or len(set(raw)) != len(raw) or any(type(s) is not str or not s for s in raw):
        raise ValueError("D07 stage bounded " + name + " differs")
    return tuple(raw)


def validate_d07_behavior_provenance_v1(kind, raw):
    expected={"schema", "work_kind", "input_digest", "behavior", "execution", "status", "stop_reason"}
    if type(raw) is not dict or set(raw) not in(expected,expected|{'conditioned_source_roots','conditioned_original_deadline_utc'}):
        raise ValueError("D07 fixed behavior provenance fields differ")
    work_kind = raw["work_kind"]
    if 'conditioned_source_roots'in raw:
        if work_kind!='simulation'or raw['behavior'].get('forecast_mode')!='declared_forecast':
            raise ValueError('conditional Source metadata belongs only to its registered typed simulation')
        _collection(raw,'conditioned_source_roots',cap=32)
    if (raw["schema"] != "d07.actual-behavior-provenance.v1" or KINDS.get(work_kind) != kind
            or raw["status"] not in {"queued", "staged", "already_recorded", "deferred"}
            or type(raw["input_digest"]) is not str or len(raw["input_digest"]) != 64
            or type(raw["stop_reason"]) is not str or not raw["stop_reason"]):
        raise ValueError("D07 fixed behavior scope/state differs")
    refs = set()
    execution = None
    if raw["execution"] is not None:
        _fields(raw["execution"], D07ExecutionOriginalV1)
        execution = decode_d07_execution_original_v1(raw["execution"])
        if execution.work_kind != work_kind or execution.input_digest != raw["input_digest"]:
            raise ValueError("D07 adopted behavior differs from real execution identity")
        refs.update(execution.source_refs)
        refs.update(execution.discriminating_refs)
        refs.update(execution.cost_receipt_refs)
    behavior = raw["behavior"]
    if type(behavior) is not dict:
        raise ValueError("D07 fixed behavior input must be structured")
    if work_kind == "concern":
        expected = {"trigger", "policy", "tickets", "issuance_originals", "prior_round", "focus_epoch", "choice", "current_admission_digest"}
        if set(behavior) not in (expected, expected | {"semantic_question", "semantic_target"}):
            raise ValueError("D07 concern stage original fields differ")
        _fields(behavior["policy"], AttentionPolicy)
        AttentionPolicy(**behavior["policy"])
        _fields(behavior["prior_round"], ConcernRoundV1)
        round_raw = dict(behavior["prior_round"])
        for name in ("groups", "service_counts", "parked", "urgent_borrow_debt"):
            if name in round_raw:
                round_raw[name] = tuple(tuple(v) if type(v) is list else v for v in round_raw[name])
        # Actual field names are decoded from the fixed dataclass below.
        for f in fields(ConcernRoundV1):
            if type(round_raw[f.name]) is list:
                round_raw[f.name] = tuple(tuple(v) if type(v) is list else v for v in round_raw[f.name])
        ConcernRoundV1(**round_raw)
        if type(behavior["tickets"]) is not list or len(behavior["tickets"]) > 128:
            raise ValueError("D07 concern ticket original inventory exceeds bound")
        for ticket in behavior["tickets"]:
            _fields(ticket, AttentionTicket)
            value = AttentionTicket(**{**ticket, "cancel_refs": tuple(ticket["cancel_refs"]), "source_refs": tuple(ticket["source_refs"])})
            refs.update(value.source_refs)
            if value.concern_ref:
                refs.add(value.concern_ref)
        if behavior["choice"] is not None:
            _fields(behavior["choice"], ConcernServiceChoiceV1)
            ConcernServiceChoiceV1(**behavior["choice"])
        if "semantic_question" in behavior:
            q = behavior["semantic_question"]
            from .d07_execution_v1 import D07RelationshipSemanticQuestionV2
            from .domain_production_erasure_v1 import decode_typed_production_value_v1
            from .d07_method_growth_semantic_v2 import D07MethodGrowthSemanticQuestionV2
            kind = (D07MethodGrowthSemanticQuestionV2 if q.get("schema") == "d07.method-growth-semantic-question.v2" else
                D07RelationshipSemanticQuestionV2 if q.get("schema") == "d07.relationship-semantic-question.v2" else D07SemanticQuestionV1)
            _fields(q, kind)
            question = decode_typed_production_value_v1(q, kind)
            refs.update(question.source_refs)
            from .domain_production_erasure_v1 import decode_typed_production_value_v1
            import json
            from ..runtime_contracts import canonical_digest, canonical_serialize
            target = decode_typed_production_value_v1(behavior["semantic_target"], D07SemanticTargetOriginalV1)
            value = json.loads(target.value_json)
            if (target.original_ref != question.target_ref.ref or target.revision != question.target_ref.version
                    or canonical_serialize(value) != target.value_json or canonical_digest(value) != target.original_digest):
                raise ValueError("D07 semantic target differs from frozen exact question")
            if target.kind == "graph_head":
                refs.add(target.original_ref)
            elif target.kind == "d08_joint_plan_intent":
                from .d08_production_operations_v1 import JointPlanIntentOriginalV1
                actual = decode_typed_production_value_v1(value, JointPlanIntentOriginalV1)
                if actual.source_refs != target.source_refs or actual.revision != target.revision:
                    raise ValueError("D07 semantic target terms/source closure differs")
                refs.update(target.source_refs)
            else:
                raise ValueError("D07 semantic target kind is not installed")
            refs.update(v.key.token for v in target.read_versions)
    elif work_kind == "simulation":
        expected = {"registered_request_ref", "request", "trigger", "dedicated_budget", "dedicated_budget_original", "content_reality",
            "external_evidence_eligibility", "current_admission_digest"}
        forecast_fields={'forecast_plan_ref','forecast_plan_digest','forecast_mode'}
        if set(behavior)not in(expected,expected|{'simulation_result'},expected|forecast_fields,expected|forecast_fields|{'simulation_result'}):
            raise ValueError("D07 simulation stage original fields differ")
        if forecast_fields<=set(behavior):
            key=AtomKey.from_token(behavior['forecast_plan_ref'])
            if key.type_name!='d07.simulation_forecast_plan.v1'or behavior['forecast_mode']!='declared_forecast':
                raise ValueError('D07 simulation forecast provenance has another exact typed plan/mode')
            refs.add(key.token)
        q = behavior["request"]
        _fields(q, SimulationRequest)
        request = SimulationRequest(**{**q, "snapshot_refs": tuple(q["snapshot_refs"]), "alternatives": tuple(q["alternatives"]),
            "predictions": tuple(tuple(v) for v in q["predictions"]), "unknowns": tuple(q["unknowns"])})
        if len(request.alternatives) > 2 or behavior["content_reality"] != "hypothetical" or behavior["external_evidence_eligibility"] != "none":
            raise ValueError("D07 simulation stage cannot acquire external reality")
        refs.update(request.snapshot_refs)
        if "simulation_result" in behavior:
            result = behavior["simulation_result"]
            if type(result) is not dict or set(result) != {"activity_id", "branches", "truncated"} or type(result["truncated"]) is not bool:
                raise ValueError("D07 actual simulation result original differs")
            if type(result["branches"]) is not list or len(result["branches"]) != 1 + len(request.alternatives):
                raise ValueError("D07 actual hypothetical branch count differs")
            for row in result["branches"]:
                _fields(row, SimulationBranch)
                branch = SimulationBranch(**{**row, "prediction_steps": tuple(row["prediction_steps"]),
                    "snapshot_refs": tuple(row["snapshot_refs"]), "unknowns": tuple(row["unknowns"])})
                refs.update(branch.snapshot_refs)
    else:
        expected = {"terminal", "cognition_adoption", "causal_root", "causal_depth_original", "resolved_slots", "discriminating_refs",
                "prior_checkpoint", "causal_depth", "current_admission_digest"}
        if set(behavior) not in (expected, expected | {"actual_stop_reason"}):
            raise ValueError("D07 reflection stage original fields differ")
        if "actual_stop_reason" in behavior and (behavior["actual_stop_reason"] != "wait_for_new_information"
                or raw["stop_reason"] != "waiting_for_new_trigger" or behavior["resolved_slots"]):
            raise ValueError("D07 reflection wait differs from actual adopted result")
        if execution is None or behavior["causal_depth"] != execution.causal_depth:
            raise ValueError("D07 reflection lacks actual adopted cognition depth")
        if tuple(behavior["resolved_slots"]) != execution.resolved_slots or tuple(behavior["discriminating_refs"]) != execution.discriminating_refs:
            raise ValueError("D07 reflection result differs from actual model original")
        refs.update(execution.discriminating_refs)
    for ref in refs:
        AtomKey.from_token(ref)
    return tuple(sorted(refs))


def build_d07_staged_behavior_operation_v1(frame, behavior_stage, *, additional_writes=()):
    provenance = {"schema": "d07.actual-behavior-provenance.v1", "work_kind": behavior_stage.work_kind,
        "input_digest": behavior_stage.input_digest, "behavior": _json(behavior_stage.provenance),
        "execution": _json(behavior_stage.execution), "status": behavior_stage.status, "stop_reason": behavior_stage.stop_reason}
    kind = KINDS[behavior_stage.work_kind]
    forecast=(behavior_stage.work_kind=='simulation'and behavior_stage.provenance.get('forecast_mode')=='declared_forecast')
    if forecast:
        provenance['conditioned_source_roots']=list(frame.envelope.source_qualification.source_refs)
        provenance['conditioned_original_deadline_utc']=frame.envelope.deadline_utc
    validate_d07_behavior_provenance_v1(kind, provenance)
    costs = tuple(original for original in frame.observed_originals if behavior_stage.execution is not None
        and original.original_ref in behavior_stage.execution.cost_receipt_refs)
    return stage_result_v1(frame, "d07", kind, behavior_stage.request,
        writes=(*behavior_stage.proposal.typed_writes, *additional_writes), provenance=provenance,
        receiver_events=(('d07','conditioned_simulation_committed_v1'),)if forecast and behavior_stage.status=='staged'else(),
        costs=costs, coverage="complete" if behavior_stage.status in {"staged", "already_recorded"} else "deferred",
        missing=() if behavior_stage.status in {"staged", "already_recorded"} else (behavior_stage.stop_reason,),
        continuation=None if behavior_stage.status in {"staged", "already_recorded"} else "d07-prepared:" + frame.envelope.identity.operation_id,
        proposal_schema=behavior_stage.proposal.proposal_schema, proposal_hash=behavior_stage.proposal.proposal_schema_hash)


def decode_d07_followup_event_v1(event_kind, receiver_domain):
    # Old saved D07 stage notifications are finite state changes, never proof of
    # work completion. Only the actual paid execution wakes current adoption.
    if event_kind == "cognitive_execution_requires_current_adoption" and receiver_domain == "d07":
        return True
    allowed = {"d07." + kind + "." + status for kind in KINDS for status in ("queued", "staged", "already_recorded", "deferred")}
    if event_kind in allowed and receiver_domain == "d07":
        return True
    raise ValueError("D07 followup event is outside installed finite routing")
