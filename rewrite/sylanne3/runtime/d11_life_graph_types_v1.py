"""Closed graph facts from an installed Life claim, terminal and digital artifact."""
import hashlib
from ..graph_types import AtomKey, Owner, TypeSpec, GraphWrite
from ..runtime_contracts import canonical_digest, canonical_serialize, schema_hash
from .d11_life_contract_v1 import (RoleSegmentStartV1, LifeTerminalPayloadV1, D11LifeExecutionBindingV1,
    life_from_wire_v1, life_to_wire_v1, ARTIFACT_SCHEMA, RECIPE_ID, life_artifact_ref_v1)

TYPES = ("d11.life_artifact.v1", "d11.role_segment_start.v1", "d11.role_segment_end.v1")


def validate_life_graph_value_v1(type_name, value):
    if type(value) is not dict:
        raise ValueError("Life graph fact requires a closed JSON object")
    if type_name == TYPES[0]:
        if set(value) != {"schema", "binding", "artifact", "artifact_digest", "artifact_length", "source_refs", "audiences", "purposes"}:
            raise ValueError("Life adopted artifact fields differ")
        binding = life_from_wire_v1(value["binding"], D11LifeExecutionBindingV1)
        artifact = value["artifact"]
        if (type(artifact) is not dict or set(artifact) != {"schema","recipe_id","recipe_version","activity_id","effect_id","attempt_id","source_ref","source_revision","source_digest","source_record"}
                or artifact["recipe_id"] != RECIPE_ID or artifact["recipe_version"] != 1
                or type(artifact["source_revision"]) is not int or artifact["source_revision"] < 1
                or canonical_digest(artifact["source_record"]) != artifact["source_digest"]
                or AtomKey.from_token(artifact["source_ref"]).type_name != "memory.source"
                or artifact["source_ref"] not in value["source_refs"]):
            raise ValueError("Life fixed artifact schema/input commitment differs")
        from ..memory_types import SourceRecord
        record=SourceRecord.from_dict(artifact["source_record"])
        if (len(record.text.encode("utf-8")) > 65536 or len(canonical_serialize(artifact["source_record"]).encode("utf-8")) > 131072
                or not set(value["audiences"]).issubset(record.audiences)):
            raise ValueError("Life artifact source/audience bounds differ")
        data = canonical_serialize(artifact).encode("utf-8")
        if (value["schema"] != "d11.adopted-life-artifact.v1" or value["artifact"]["schema"] != ARTIFACT_SCHEMA
                or len(data) != value["artifact_length"] or hashlib.sha256(data).hexdigest() != value["artifact_digest"]
                or len(data) > 262144 or not value["source_refs"] or not value["audiences"]
                or value["purposes"] != ["context", "consolidation"]
                or (value["artifact"]["activity_id"], value["artifact"]["effect_id"], value["artifact"]["attempt_id"]) !=
                    (binding.activity_id, binding.effect_id, binding.attempt_id)):
            raise ValueError("Life adopted artifact commitments differ")
    else:
        if type_name not in TYPES or set(value) != {"schema", "binding", "payload", "journal_ref", "journal_digest"}:
            raise ValueError("Life role segment fact fields differ")
        binding = life_from_wire_v1(value["binding"], D11LifeExecutionBindingV1)
        payload = life_from_wire_v1(value["payload"], RoleSegmentStartV1 if type_name == TYPES[1] else LifeTerminalPayloadV1)
        if value["schema"] != type_name or payload.binding_digest != binding.digest:
            raise ValueError("Life role segment fact crossed actual binding")
    return binding


def life_graph_type_specs_v1():
    from .d11_life_fact_provenance_v1 import life_fact_auxiliary_type_specs_v1
    from .d11_life_outcome_provenance_v1 import life_outcome_type_specs_v1
    return (tuple(TypeSpec(name, ("activity",), "state", lambda value, name=name: validate_life_graph_value_v1(name, value),
        immutable=True, schema_version=1, writer_domain="d11", schema_hash=schema_hash({"type": name, "version": 1})) for name in TYPES)
        + life_fact_auxiliary_type_specs_v1() + life_outcome_type_specs_v1())


def life_role_segment_key_v1(binding, phase):
    return AtomKey(Owner("activity", *binding.namespace.as_tuple, binding.activity_id),
        TYPES[1] if phase == "start" else TYPES[2], binding.execution_id)


def life_fact_writes_v1(prepared, claim, terminal, artifact):
    b = prepared.binding
    result = []
    for phase, original in (("start", claim), ("end", terminal)):
        key = life_role_segment_key_v1(b, phase)
        result.append(GraphWrite(key, {"schema": key.type_name, "binding": life_to_wire_v1(b),
            "payload": life_to_wire_v1(original.payload), "journal_ref": original.original_ref,
            "journal_digest": original.claim_digest if phase == "start" else original.terminal_digest}))
    if terminal.status == "completed":
        data, digest, length = artifact
        import json
        source_refs = tuple(row.ref for row in prepared.read_rows if AtomKey.from_token(row.ref).type_name == "memory.source")
        result.append(GraphWrite(AtomKey.from_token(b.artifact_ref), {"schema": "d11.adopted-life-artifact.v1",
            "binding": life_to_wire_v1(b), "artifact": json.loads(data), "artifact_digest": digest, "artifact_length": length,
            "source_refs": list(source_refs), "audiences": list(prepared.plan.audiences), "purposes": ["context", "consolidation"]}))
    from .d11_life_fact_provenance_v1 import life_fact_qualified_writes_v1
    qualified=life_fact_qualified_writes_v1(prepared,claim,terminal,tuple(result))
    from .d11_life_outcome_provenance_v1 import life_outcome_qualified_writes_v1
    return (*qualified,*life_outcome_qualified_writes_v1(prepared,terminal,qualified))
