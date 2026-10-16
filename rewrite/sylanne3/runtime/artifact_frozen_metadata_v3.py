"""Pure C4 frozen metadata projection; text remains protected Body."""
FROZEN_INPUT_FIELDS_V1=frozenset(("selector","task_source_ref","current_self_ref","current_self_digest",
    "root_registration_digest","target","sources","source_read_versions","source_query_epoch","access_epoch",
    "delete_epoch","deadline_utc","schema"))
FROZEN_INPUT_FIELDS_V2=FROZEN_INPUT_FIELDS_V1|{"extent","prior_content"}
FROZEN_INPUT_FIELDS_V3=FROZEN_INPUT_FIELDS_V2|{"postcondition_contract_ref","postcondition_contract_digest"}
FROZEN_SOURCE_FIELDS_V3=frozenset(("ref","revision","value_digest","record"))
FROZEN_SOURCE_RECORD_FIELDS_V3=frozenset(("source_id","text","speaker_id","source_kind","assertion_status",
    "occurred_at","recorded_at","provenance_root","audiences","purposes","parent_source_ids","independence"))

def artifact_frozen_metadata_path_v3(path):
    shape=_frozen_metadata_shape_v3()
    for part in path:
        if type(shape)is dict:
            if part not in shape:return False
            shape=shape[part]
        elif type(shape)is tuple and type(part)is int:shape=shape[0]
        else:return False
    return shape!="body"

def validate_artifact_frozen_metadata_fields_v3(value,*,top_fields,source_fields,record_fields,object_fields):
    from ..model_broker.artifact_draft_v1 import INPUT_SCHEMA,INPUT_SCHEMA_V2,INPUT_SCHEMA_V3
    expected={INPUT_SCHEMA:FROZEN_INPUT_FIELDS_V1,INPUT_SCHEMA_V2:FROZEN_INPUT_FIELDS_V2,INPUT_SCHEMA_V3:FROZEN_INPUT_FIELDS_V3}
    if top_fields!=expected[value["schema"]]:raise ValueError("Artifact frozen metadata has another exact registered field set")
    if set(source_fields)!=set(range(len(value["sources"])))or set(record_fields)!=set(source_fields):
        raise ValueError("Artifact frozen metadata has incomplete Source/record field census")
    for index in source_fields:
        if source_fields[index]!=FROZEN_SOURCE_FIELDS_V3 or record_fields[index]!=FROZEN_SOURCE_RECORD_FIELDS_V3:
            raise ValueError("Artifact frozen Source metadata has unknown/missing fields at complete EOF")

    def visit(item,shape,path):
        if shape=="body":return
        if type(shape)is dict:
            if item is None:return
            expected=set(shape)
            if path==("selector",):
                from ..model_broker.artifact_draft_v1 import ArtifactDraftTaskSelectorV1,ArtifactDraftPhaseSelectorV2
                from dataclasses import fields
                typ=ArtifactDraftTaskSelectorV1 if item["schema"]=="d11.artifact-draft-task-selector.v1"else ArtifactDraftPhaseSelectorV2
                expected={field.name for field in fields(typ)}
            elif not path:expected=set(top_fields)
            if object_fields.get(path)!=expected:raise ValueError("Artifact frozen nested metadata object has unknown/missing formal fields")
            for key in expected:
                if shape[key]!="body":visit(item[key],shape[key],(*path,key))
        elif type(shape)is tuple:
            for index,child in enumerate(item):visit(child,shape[0],(*path,index))
    visit(value,_frozen_metadata_shape_v3(),())
    for path in object_fields:
        shape=_frozen_metadata_shape_v3()
        for part in path:
            if type(shape)is dict and part in shape:shape=shape[part]
            elif type(shape)is tuple and type(part)is int:shape=shape[0]
            else:raise ValueError("Artifact frozen metadata has a nested object outside its exact formal codec")
        if type(shape)is not dict:raise ValueError("Artifact frozen scalar metadata contains an undeclared object")

_SHAPE_V3=None
def _frozen_metadata_shape_v3():
    global _SHAPE_V3
    if _SHAPE_V3 is not None:return _SHAPE_V3
    from dataclasses import fields
    from ..model_broker.artifact_draft_v1 import (ArtifactDraftTaskSelectorV1,ArtifactDraftPhaseSelectorV2,
        ArtifactDraftTextExtentV2,ArtifactDraftPriorContentCommitmentV2)
    from .d11_artifact_draft_contract_v1 import DraftFileTargetV1,DraftFileIdentityV1,DraftFileReadbackV1
    def flat(typ):return {field.name:"scalar"for field in fields(typ)}
    identity=flat(DraftFileIdentityV1);target=flat(DraftFileTargetV1)
    target.update(root_identity=identity,expected_prior_identity=identity)
    task=flat(ArtifactDraftTaskSelectorV1);task["namespace"]={"bot_id":"scalar","persona_id":"scalar"}
    selector={**task,**flat(ArtifactDraftPhaseSelectorV2),"task":task}
    readback=flat(DraftFileReadbackV1);readback["file_identity"]=identity
    prior=flat(ArtifactDraftPriorContentCommitmentV2);prior.update(source_head={"ref":"scalar","version":"scalar"},verified_readback=readback)
    record={field:"scalar"for field in FROZEN_SOURCE_RECORD_FIELDS_V3}
    for field in ("audiences","purposes","parent_source_ids"):record[field]=("scalar",)
    record["text"]="body"
    shape={field:"scalar"for field in FROZEN_INPUT_FIELDS_V3}
    shape.update(selector=selector,target=target,extent=flat(ArtifactDraftTextExtentV2),prior_content=prior,
        sources=({"ref":"scalar","revision":"scalar","value_digest":"scalar","record":record},),
        source_read_versions=({"key":"scalar","revision":"scalar"},))
    _SHAPE_V3=shape
    return shape
