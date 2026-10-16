"""D06 qualification of an actually completed installed Life activity.

This reader qualifies an internal activity for context/consolidation. It does
not qualify the processed text as an external fact or authorize expression.
"""
from dataclasses import dataclass
import json
import weakref

from ..graph_types import AtomKey, GraphVersion, Owner
from ..memory_types import SourceRecord
from ..runtime_contracts import canonical_digest, canonical_serialize
from ..domains.d01.production_operations_v1 import plain_v1
from ..domains.d08.execution import _decode
from .d01_production_operations_v1 import CurrentDomainReadV1, MissingProductionOriginalV1, raw_head_value_v1
from .d11_life_contract_v1 import D11LifeTerminalV1, life_from_wire_v1, life_to_wire_v1
from .d11_life_preparation_v1 import _read, read_prepared_life_v1
from .d11_life_adoption_v1 import _read_signed, _verify_life_adoption_commit_and_original_v1
from .d11_life_source_note_v1 import verify_durable_life_artifact_v1
from .d10_life_outcome_v2 import life_experience_source_id_v1, life_experience_provenance_ref_v1
from .d02_life_effect_v1 import require_life_body_quote_v1
from .d11_offline_originals_v1 import _utc

_QUALIFIED_INTERNAL_LIFE = {}


@dataclass(frozen=True, slots=True, weakref_slot=True)
class QualifiedLifeActivityV1:
    source_ref: str
    source_revision: int
    source_digest: str
    activity_id: str
    effect_id: str
    execution_id: str
    artifact_ref: str
    artifact_digest: str
    start_original_ref: str
    terminal_original_ref: str
    actual_cpu_ms: int
    started_at: float
    completed_at: float
    body_settlement_ref: str
    qualification_digest: str
    read_versions: tuple[GraphVersion, ...]
    reality: str = "real_execution"
    purposes: tuple[str, ...] = ("context", "consolidation")


def life_activity_read_inputs_v1(db, namespace, source_ref):
    """Plan bounded reads; these unqualified locators grant no authority."""
    value = raw_head_value_v1(db, namespace, AtomKey.from_token(source_ref))
    if value is None:
        return (), ()
    source = SourceRecord.from_dict(value)
    if source.source_kind != "internal" or source.assertion_status != "confirmed":
        return (), ()
    payload = json.loads(source.text)
    if payload.get("schema") != "d10.actual-life-activity-experience.v1":
        raise MissingProductionOriginalV1("actual_installed_life_activity_lineage")
    from .d11_life_product_adapter_v1 import raw_life_original_v1
    original = raw_life_original_v1(db, namespace, "experience", payload["actual_provenance_ref"])
    if original is None:
        raise MissingProductionOriginalV1("signed_actual_life_experience")
    terminal = life_from_wire_v1(original["terminal"], D11LifeTerminalV1)
    b = terminal.binding
    from .d10_life_progress_provenance_v1 import life_progress_read_keys_v1
    from .d11_life_graph_types_v1 import life_role_segment_key_v1
    from .jobs import get_job
    from .d11_types import job_graph_write
    job = get_job(db, b.job_id)
    keys = [AtomKey.from_token(b.artifact_ref), AtomKey.from_token(payload["action_outcome_ref"]),
        life_role_segment_key_v1(b, "start"), life_role_segment_key_v1(b, "end"),
        AtomKey(Owner("activity", *namespace.as_tuple, b.activity_id), "d10.life_progress.v1", b.effect_id),
        *(AtomKey.from_token(ref) for ref in payload["cost_refs"])]
    keys.extend(life_progress_read_keys_v1(b))
    if job is not None:
        keys.append(job_graph_write(job).key)
    from .d11_life_fact_provenance_v1 import PROVENANCE_TYPE, ELIGIBILITY_TYPE, life_fact_auxiliary_key_v1
    facts=(AtomKey.from_token(b.artifact_ref),life_role_segment_key_v1(b,'start'),life_role_segment_key_v1(b,'end'))
    keys.extend(life_fact_auxiliary_key_v1(fact,kind) for fact in facts for kind in (PROVENANCE_TYPE,ELIGIBILITY_TYPE))
    prepared = raw_life_original_v1(db, namespace, "prepared", b.prepared_original_ref)
    if prepared is not None:
        from .d11_life_outcome_provenance_v1 import life_outcome_read_keys_v1
        keys.extend(life_outcome_read_keys_v1(b,prepared['plan']['action_intent']['ref']))
        from .d10_life_progress_provenance_v1 import life_progress_current_read_inputs_v1,life_progress_key_v1
        current_keys,_,_=life_progress_current_read_inputs_v1(db,namespace,life_progress_key_v1(b).token)
        keys.extend(current_keys)
        from .d11_life_contract_v1 import LifeBodyComponentContractV1
        contract = LifeBodyComponentContractV1(**json.loads(prepared["plan"]["body_effect_request_json"]))
        keys.extend((AtomKey.from_token(contract.settlement_ref), AtomKey.from_token(contract.reservation_ref)))
    return tuple(dict.fromkeys(keys)), (payload["actual_provenance_ref"], b.prepared_original_ref,
        b.artifact_ref, terminal.original_ref, terminal.claim.original_ref, *payload["cost_refs"])


def qualify_current_life_activity_v1(db, *, frame, source_atom, adopted, progress, installed_readers):
    read = CurrentDomainReadV1(frame)
    read.check(db)
    ns, issuer = frame.envelope.authority.namespace, installed_readers.issuer
    source = SourceRecord.from_dict(source_atom.value)
    payload = json.loads(source.text)
    saved = _read(db, issuer=issuer, namespace=ns, kind="experience", ref=payload["actual_provenance_ref"])
    if saved is None:
        raise MissingProductionOriginalV1("signed_actual_life_experience")
    original, operation_id = saved
    terminal = life_from_wire_v1(original["terminal"], D11LifeTerminalV1)
    b = terminal.binding
    prepared = read_prepared_life_v1(db, binding=b, issuer=issuer)
    if prepared is None or terminal.status != "completed" or b.namespace != ns:
        raise MissingProductionOriginalV1("actual_completed_life_preparation_and_terminal")
    bridge = _read_signed(db, ns, "adoption_bridge", b.execution_id, issuer)
    if bridge is None:
        raise MissingProductionOriginalV1("actual_signed_life_adoption_bridge")
    from ..authority_service.d11_life_bridge_v1 import life_bridge_from_wire_v1
    gate = life_bridge_from_wire_v1(bridge[1])
    if gate.binding != b or gate.terminal != terminal:
        raise ValueError("Life experience differs from its signed execution bridge")
    receipt, fact_original = _verify_life_adoption_commit_and_original_v1(db,
        gate=gate, issuer=issuer, resource_issuer=installed_readers.resource_issuer,
        require_current_metadata=False)
    from .d11_life_fact_provenance_v1 import require_current_life_fact_eligibility_v1
    require_current_life_fact_eligibility_v1(db,prepared=prepared,terminal=terminal,adopted=fact_original)
    from .d10_life_progress_provenance_v1 import require_current_life_progress_v1,require_life_experience_access_edges_v1
    require_current_life_progress_v1(db,namespace=ns,progress=progress,issuer=issuer,read=read)
    access_key_actual=require_life_experience_access_edges_v1(db,prepared=prepared,source=source_atom.key)
    from .current_life_numeric_native_read_v3 import read_bound_native_numeric_history_v3
    handled,access_history=read_bound_native_numeric_history_v3(db,access_key_actual.token,1,('value', 'valid', 'event_id'))
    if not handled:
        from ..authority_service.life_model_original_family_read_v3 import read_bound_life_model_history_v3
        handled,access_history=read_bound_life_model_history_v3(db,access_key_actual.token,1,('value', 'valid', 'event_id'))
    if not handled:
        access_history=db.execute('SELECT value,valid,event_id FROM graph_history WHERE token=? AND revision=1',(access_key_actual.token,)).fetchone()
    expected_access=canonical_serialize({'source_id':source.source_id,'audiences':list(source.audiences),
        'purposes':list(source.purposes),'status':'active','recorded_at':source.recorded_at})
    from .current_life_numeric_native_read_v3 import read_bound_native_numeric_point_v3
    handled,actual_access=read_bound_native_numeric_point_v3(db,table='graph_atoms',columns=('value',),
        key_columns=('token',),key=(access_key_actual.token,))
    if not handled:
        from ..authority_service.life_model_original_family_read_v3 import read_bound_life_model_body_point_v3
        handled,actual_access=read_bound_life_model_body_point_v3(db,table='graph_atoms',columns=('value',),
        key_columns=('token',),key=(access_key_actual.token,))
    if not handled:actual_access=db.execute('SELECT value FROM graph_atoms WHERE token=?',(access_key_actual.token,)).fetchone()
    if (not any(v.key==access_key_actual and v.revision==1 for v in adopted['receipt'].write_versions)
            or access_history!=(expected_access,1,operation_id)
            or actual_access!=(expected_access,)):
        raise ValueError('Life current experience access lacks its exact actual same-composite original')
    verify_durable_life_artifact_v1(db, prepared, digest=terminal.payload.artifact_digest,
        length=terminal.payload.artifact_length)
    contract, _, body_quote = require_life_body_quote_v1(db, prepared=prepared, issuer=issuer,
        resource_issuer=installed_readers.resource_issuer, body_quote_authority=installed_readers.body_quote_authority)
    if (set(original) != {"schema", "source_ref", "source_digest", "binding", "terminal", "adopted_operation_id", "experience"}
            or original["schema"] != "d11.actual-life-experience-provenance.v1"
            or operation_id != adopted["receipt"].operation_id
            or original["source_ref"] != source_atom.key.token
            or original["source_digest"] != canonical_digest(source_atom.value)
            or original["binding"] != life_to_wire_v1(b) or original["experience"] != payload
            or original["adopted_operation_id"] != receipt["operation_id"]
            or payload["actual_provenance_ref"] != life_experience_provenance_ref_v1(b)
            or source.source_id != life_experience_source_id_v1(b)):
        raise ValueError("Life Source does not belong to the exact adopted activity")
    plan = prepared.plan
    expected = {"schema": "d10.actual-life-activity-experience.v1", "actual_provenance_ref": life_experience_provenance_ref_v1(b),
        "activity_id": b.activity_id, "effect_id": b.effect_id, "artifact_ref": b.artifact_ref,
        "artifact_digest": terminal.payload.artifact_digest, "artifact_length": terminal.payload.artifact_length,
        "start_original_ref": terminal.claim.original_ref, "terminal_original_ref": terminal.original_ref,
        "action_outcome_ref": payload["action_outcome_ref"], "cost_refs": payload["cost_refs"],
        "actual_cpu_ms": terminal.actual_cpu_ms, "started_at_utc": terminal.claim.payload.claimed_at_utc,
        "completed_at_utc": terminal.payload.completed_at_utc, "reality": "real_execution", "step": "source_note"}
    if (payload != expected or canonical_serialize(payload) != source.text
            or (source.speaker_id, source.source_kind, source.assertion_status, source.audiences, source.purposes,
                source.parent_source_ids, source.independence) !=
                ("persona:" + ns.persona_id, "internal", "confirmed", plan.audiences, ("context", "consolidation"),
                    (AtomKey.from_token(plan.input_source.ref).owner.subject,), "same_root")
            or source.provenance_root != "life-terminal:" + terminal.terminal_digest
            or source.occurred_at != _utc(terminal.payload.completed_at_utc).timestamp()):
        raise ValueError("Life internal Source promotes or changes the actual activity facts")
    outcome = _decode("d08.action_outcome.v1", read.head(db, payload["action_outcome_ref"], required=True).value)
    if (outcome.effect_id != b.effect_id or outcome.attempt_id != b.attempt_id
            or outcome.result_level != "completed_verified" or outcome.completed_effects != (b.effect_id,)
            or outcome.unknown_effects or outcome.observation_refs != (terminal.original_ref,)):
        raise ValueError("Life internal activity has no installed postcondition completion")
    for ref in payload["cost_refs"]:
        read.settled_cost_original(db, ref, activity_id=b.activity_id, effect_id=b.effect_id,
            operation_id=b.reservation_operation_id)
    if len(payload["cost_refs"]) != 1:
        raise ValueError("Life activity requires its one genuine CPU settlement")
    from .d11_types import job_graph_write
    from .d11_life_terminal_v1 import read_current_life_job_result_v1
    job, expected_result_ref = read_current_life_job_result_v1(db, job_id=b.job_id, adopted=fact_original)
    if (job.phase != "completed" or job.result_ref != expected_result_ref
            or job.operation_id != b.operation_id or job.usage != {"thread_cpu_ms": terminal.actual_cpu_ms}):
        raise ValueError("Life activity job does not preserve its actual terminal usage")
    job_write = job_graph_write(job)
    if read.head(db, job_write.key, required=True).value != job_write.value:
        raise ValueError("Life current job projection differs from its durable terminal")
    settlement = read.head(db, contract.settlement_ref, required=True)
    reservation = settlement.value["reservation"]
    component = next(part for part in body_quote.components if part.component_id == contract.component_id)
    if (reservation["quote_id"] != body_quote.quote_id or reservation["effect_id"] != b.effect_id
            or contract.component_id + "|" + terminal.original_ref not in reservation["settled_components"]
            or settlement.value["overrun"] != 0 or settlement.value["unpaid_cost"] != 0
            or reservation["remaining_cost"] != body_quote.max_energy_cost - component.fixed_cost):
        raise ValueError("Life activity Body component is not actually settled")
    version = next((v for v in adopted["receipt"].write_versions if v.key == settlement.key), None)
    historical = None
    if version is not None:
        from .current_life_numeric_native_read_v3 import read_bound_native_numeric_history_v3
        handled,historical=read_bound_native_numeric_history_v3(db,version.key.token,version.revision,('event_id','value','valid'))
        if not handled:
            from ..authority_service.life_model_original_family_read_v3 import read_bound_life_model_history_v3
            handled,historical=read_bound_life_model_history_v3(db,version.key.token,version.revision,('event_id','value','valid'))
        if not handled:
            historical=db.execute("SELECT event_id,value,valid FROM graph_history WHERE token=? AND revision=?",
                (version.key.token,version.revision)).fetchone()
    if historical != (operation_id, canonical_serialize(settlement.value), 1):
        raise ValueError("Life Body settlement is not a member of the actual D10 composite")
    if (progress.activity_id, progress.effect_id, progress.artifact_ref, progress.terminal_ref, progress.reality) != (
            b.activity_id, b.effect_id, b.artifact_ref, terminal.original_ref, "real_execution"):
        raise ValueError("Life progress differs from the authenticated actual activity")
    if (progress.role_start, progress.role_end) != (float(terminal.claim.payload.character_at), float(terminal.payload.character_at)):
        raise ValueError("Life progress role interval differs from actual start/end originals")
    start, end = _utc(terminal.claim.payload.claimed_at_utc).timestamp(), _utc(terminal.payload.completed_at_utc).timestamp()
    digest = canonical_digest((canonical_digest(original), receipt, canonical_digest(settlement.value), plain_v1(progress)))
    activity = QualifiedLifeActivityV1(source_atom.key.token, source_atom.revision, canonical_digest(source_atom.value),
        b.activity_id, b.effect_id, b.execution_id, b.artifact_ref, terminal.payload.artifact_digest,
        terminal.claim.original_ref, terminal.original_ref, terminal.actual_cpu_ms, start, end,
        settlement.key.token, digest, frame.snapshot.versions)
    identity = id(activity)
    _QUALIFIED_INTERNAL_LIFE[identity] = (weakref.ref(activity,
        lambda _: _QUALIFIED_INTERNAL_LIFE.pop(identity, None)), db, frame)
    return activity
