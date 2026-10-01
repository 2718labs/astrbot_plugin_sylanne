"""Closed C09 inventory codecs for real Life bodies and retained cost facts."""
import hashlib
import json
from dataclasses import fields

from ..graph_types import AtomKey
from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize
from .domain_production_erasure_v1 import DomainProductionErasureHold, _json, decode_typed_production_value_v1
from .d11_life_contract_v1 import RegisteredLifePlanV2, RegisteredLifeOutcomeV2, life_from_wire_v1, D11LifeTerminalV1
from .d11_life_preparation_v1 import life_prepared_from_wire_v1
from .d11_life_source_note_v1 import ARTIFACT_SCHEMA

FACT_KINDS = frozenset({"accounting_prepared", "historical_accounting_gate", "historical_accounting_receipt"})


def decode_life_original_content_v1(kind, encoded):
    raw = _json(encoded)
    if kind == "source_note_action":
        from .d08_source_note_action_v1 import source_note_action_original_from_wire_v1
        return source_note_action_original_from_wire_v1(raw)
    if kind == "life_body_preparation":
        from .d02_life_body_preparation_v1 import life_body_preparation_original_from_wire_v1
        return life_body_preparation_original_from_wire_v1(raw)
    if kind == "action_admission":
        from .d08_life_admission_v1 import LifeActionAdmissionOriginalV1
        return decode_typed_production_value_v1(raw,LifeActionAdmissionOriginalV1)
    if kind == "plan":
        return life_from_wire_v1(raw, RegisteredLifePlanV2)
    if kind == "outcome":
        return life_from_wire_v1(raw, RegisteredLifeOutcomeV2)
    if kind == "prepared":
        return life_prepared_from_wire_v1(raw)
    if kind == "accounting_prepared":
        from .d11_life_accounting_v1 import D11LifeAccountingPreparedV1
        return decode_typed_production_value_v1(raw, D11LifeAccountingPreparedV1)
    if kind == "adoption_bridge":
        from ..authority_service.d11_life_bridge_v1 import life_bridge_from_wire_v1
        return life_bridge_from_wire_v1(raw)
    if kind == "adoption_receipt":
        from .d11_life_adoption_v1 import D11LifeAdoptionReceiptV1
        return decode_typed_production_value_v1(raw, D11LifeAdoptionReceiptV1)
    if kind == "historical_accounting_gate":
        from ..authority_service.d11_life_historical_accounting_v1 import historical_accounting_from_wire_v1
        return historical_accounting_from_wire_v1(raw)
    if kind == "historical_accounting_receipt":
        from .d11_life_historical_accounting_v1 import historical_accounting_receipt_from_wire_v1
        return historical_accounting_receipt_from_wire_v1(raw)
    if kind == "experience":
        from .d11_life_contract_v1 import D11LifeExecutionBindingV1
        if set(raw) != {"schema","source_ref","source_digest","binding","terminal","adopted_operation_id","experience"} or raw["schema"] != "d11.actual-life-experience-provenance.v1":
            raise DomainProductionErasureHold("Life experience fields differ")
        binding = life_from_wire_v1(raw["binding"],D11LifeExecutionBindingV1)
        terminal = life_from_wire_v1(raw["terminal"],D11LifeTerminalV1)
        from .d10_life_outcome_v2 import life_experience_source_id_v1, life_experience_provenance_ref_v1
        from ..memory_types import source_key
        e=raw["experience"]
        expected={"schema":"d10.actual-life-activity-experience.v1","actual_provenance_ref":life_experience_provenance_ref_v1(binding),
            "activity_id":binding.activity_id,"effect_id":binding.effect_id,"artifact_ref":binding.artifact_ref,
            "artifact_digest":terminal.payload.artifact_digest,"artifact_length":terminal.payload.artifact_length,
            "start_original_ref":terminal.claim.original_ref,"terminal_original_ref":terminal.original_ref,
            "action_outcome_ref":e["action_outcome_ref"],"cost_refs":e["cost_refs"],"actual_cpu_ms":terminal.actual_cpu_ms,
            "started_at_utc":terminal.claim.payload.claimed_at_utc,"completed_at_utc":terminal.payload.completed_at_utc,
            "reality":"real_execution","step":"source_note"}
        if (terminal.binding != binding or terminal.status != "completed" or e != expected
                or raw["source_ref"] != source_key(*binding.namespace.as_tuple,life_experience_source_id_v1(binding)).token):
            raise DomainProductionErasureHold("Life internal experience lacks exact completed activity facts")
        return raw
    if kind == "adopted_life":
        if set(raw) != {"schema", "namespace", "result_ref", "producing_operation_id", "prepared_digest", "terminal", "source_refs", "graph_receipt_json", "write_commitments"}:
            raise DomainProductionErasureHold("Life adopted original fields differ")
        terminal = life_from_wire_v1(raw["terminal"], D11LifeTerminalV1)
        if (raw["schema"] != "d11.adopted-life-original.v1" or raw["prepared_digest"] != terminal.payload.prepared_digest
                or raw["result_ref"] != terminal.binding.artifact_ref or raw["namespace"] != {
                    "bot_id": terminal.binding.namespace.bot_id, "persona_id": terminal.binding.namespace.persona_id}
                or type(raw["write_commitments"]) is not list
                or any(set(r) != {"ref", "revision", "digest"} for r in raw["write_commitments"])):
            raise DomainProductionErasureHold("Life adopted original identity differs")
        return raw
    raise DomainProductionErasureHold("unregistered Life original kind")


def validate_life_stage_row_v1(columns, row, *, authority_namespace=None):
    from .domain_production_erasure_v1 import TABLE_COLUMNS
    expected = TABLE_COLUMNS["graph_d11_life_artifact_stage_v1"]
    if tuple(columns) != expected or len(row) != len(expected):
        raise DomainProductionErasureHold("Life stage columns differ")
    data = dict(zip(columns, row))
    ns = NamespaceId(data["bot"], data["persona"])
    if authority_namespace is not None:
        from ..graph_coordinator import namespace_ref
        if namespace_ref(ns) != authority_namespace:
            raise DomainProductionErasureHold("Life stage namespace differs")
    blob = data["artifact_bytes"]
    if (type(blob) is not bytes or not 1 <= len(blob) <= 262144
            or len(blob) != data["artifact_length"] or hashlib.sha256(blob).hexdigest() != data["artifact_digest"]):
        raise DomainProductionErasureHold("Life stage durable bytes/length/hash differ")
    value = _json(blob.decode("utf-8"))
    from .d11_life_contract_v1 import RECIPE_ID, life_artifact_ref_v1
    from ..memory_types import SourceRecord
    if (set(value) != {"schema", "recipe_id", "recipe_version", "activity_id", "effect_id", "attempt_id", "source_ref", "source_revision", "source_digest", "source_record"}
            or value["schema"] != ARTIFACT_SCHEMA or value["recipe_id"] != RECIPE_ID or value["recipe_version"] != 1
            or data["artifact_ref"] != life_artifact_ref_v1(ns, value["effect_id"])
            or canonical_digest(value["source_record"]) != value["source_digest"]
            or AtomKey.from_token(value["source_ref"]).type_name != "memory.source"
            or NamespaceId.from_key(AtomKey.from_token(value["source_ref"])) != ns):
        raise DomainProductionErasureHold("Life stage complete source artifact fields differ")
    SourceRecord.from_dict(value["source_record"])
    return "artifact_stage", data["artifact_ref"], value, data["artifact_digest"]


def life_stage_dispositions_v1(columns, rows, *, affected, affected_operations, nested_hits, source_ids, authority_namespace):
    result = []
    for row in rows:
        _, ref, raw, _ = validate_life_stage_row_v1(columns, row, authority_namespace=authority_namespace)
        data = dict(zip(columns, row))
        removed = (raw["source_ref"] in affected or ref in affected or data["adopted_operation_id"] in affected_operations
            or nested_hits(raw, affected, source_ids))
        result.append("derived_removed" if removed else "preserved_exact")
    return tuple(result)


def validate_life_original_joins_v1(db):
    from .d11_life_preparation_v1 import TABLE
    from .domain_production_erasure_v1 import TABLE_COLUMNS, validate_domain_production_row_v1
    from .d11_life_accounting_v1 import life_accounting_original_ref_v1
    from .d11_life_adoption_v1 import validate_life_adoption_composite_v1
    from .d11_life_historical_accounting_v1 import validate_life_historical_accounting_composite_v1
    if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",(TABLE,)).fetchone() is None:
        return
    originals={}
    for row in db.execute("SELECT bot,persona,kind,original_ref,producing_operation_id,payload_json,payload_digest,signature FROM "+TABLE):
        kind,ref,raw,digest=validate_domain_production_row_v1(TABLE,TABLE_COLUMNS[TABLE],row)
        originals[(NamespaceId(row[0],row[1]),kind,ref)]=(row[4],decode_life_original_content_v1(kind,row[5]),raw,digest)
    for (ns,kind,ref),(op,value,raw,digest) in originals.items():
        if kind == "prepared":
            admission=originals.get((ns,"action_admission",value.admission_ref))
            if admission is None or admission[0]!=value.prepare_operation_id or admission[3]!=value.admission_digest or admission[1].binding_digest!=value.binding.digest or admission[1].plan_digest!=value.binding.plan_digest:
                raise DomainProductionErasureHold("Life prepared body lost its exact signed action admission")
        if kind == "experience":
            terminal=life_from_wire_v1(raw["terminal"],D11LifeTerminalV1)
            adopted=originals.get((ns,"adopted_life",terminal.binding.artifact_ref))
            if (adopted is None or adopted[0] != raw["adopted_operation_id"]
                    or adopted[2]["terminal"] != raw["terminal"]):
                raise DomainProductionErasureHold("Life internal experience lost its genuine terminal adoption")
            history=db.execute("SELECT value,valid FROM graph_history WHERE token=? AND event_id=?",(raw["source_ref"],op)).fetchall()
            if len(history) != 1 or history[0][1] != 1 or canonical_digest(_json(history[0][0])) != raw["source_digest"]:
                raise DomainProductionErasureHold("Life internal experience lacks its real D10 source history")
            source=_json(history[0][0])
            if source["source_kind"] != "internal" or source["assertion_status"] != "confirmed" or source["text"] != canonical_serialize(raw["experience"]) or source["purposes"] != ["context","consolidation"]:
                raise DomainProductionErasureHold("Life activity Source facts or permission differ")
            continue
        if kind not in {"adoption_bridge","adoption_receipt","historical_accounting_gate","historical_accounting_receipt"}:
            continue
        adoption=kind.startswith("adoption_")
        gate=originals.get((ns,"adoption_bridge" if adoption else "historical_accounting_gate",ref))
        receipt=originals.get((ns,"adoption_receipt" if adoption else "historical_accounting_receipt",ref))
        if gate is None or receipt is None or gate[0] != op or receipt[0] != op:
            raise DomainProductionErasureHold("Life actual gate and receipt lost same-operation join")
        if kind.endswith("receipt"):
            continue
        accounting=originals.get((ns,"accounting_prepared",life_accounting_original_ref_v1(value.binding)))
        if accounting is None or accounting[1].binding != value.binding or accounting[1].prepared_digest != value.prepared_digest:
            raise DomainProductionErasureHold("Life gate lost its signed content-free preparation")
        if adoption:
            adopted=originals.get((ns,"adopted_life",value.binding.artifact_ref))
            if adopted is None or adopted[0] != op:
                raise DomainProductionErasureHold("Life adoption lost actual signed adopted original")
            validate_life_adoption_composite_v1(db,gate=value,result=receipt[2],adopted=adopted[1])
        else:
            if accounting[3] != value.accounting_original_digest:
                raise DomainProductionErasureHold("Life historical accounting cost commitment differs")
            validate_life_historical_accounting_composite_v1(db,gate=value,result=receipt[2])
