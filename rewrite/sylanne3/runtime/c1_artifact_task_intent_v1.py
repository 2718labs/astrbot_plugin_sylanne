"""Actual C1-v2 task candidates bound to a completed C02 original, never authority."""
from dataclasses import asdict,dataclass
import json
from ..runtime_contracts import NamespaceId,canonical_digest,canonical_serialize
from ..graph_types import AtomKey
from ..memory_types import SourceRecord,source_key
from ..domains.d01.production_operations_v1 import plain_v1
from ..model_broker.first_ingress_encoding import (
    ArtifactTaskIntentCandidateV1,FIRST_INGRESS_TASK_ENCODING_TEMPLATE_VERSION,
    FIRST_INGRESS_METHOD_ENCODING_TEMPLATE_VERSION, parse_method_context_candidate_v1,
    FIRST_INGRESS_DEPENDENCY_ENCODING_TEMPLATE_VERSION, parse_historical_dependency_candidate_v1,
    parse_artifact_task_intent_v1,build_first_ingress_encoding_payload,
)
from ..authority_service.v2_worker_model_result_contract import (
    WorkerModelResultReadV1,from_wire,to_wire,
)

KIND="c1_task_intent"
EMBEDDED_FIELD="c1_task_result_v1"


def c1_task_intent_ref_v1(namespace,c02_operation_id):
    return "c1-task-intent:"+canonical_digest((namespace,c02_operation_id))[:48]


def validate_c1_task_result_evidence_v1(evidence):
    nested=evidence.get(EMBEDDED_FIELD)
    if nested is None:return None
    if (type(nested) is not dict or set(nested)!={"schema","template_version","worker_read"}
            or nested["schema"]!="d11.c1-task-result-evidence.v1"
            or nested["template_version"] not in {FIRST_INGRESS_TASK_ENCODING_TEMPLATE_VERSION, FIRST_INGRESS_METHOD_ENCODING_TEMPLATE_VERSION, FIRST_INGRESS_DEPENDENCY_ENCODING_TEMPLATE_VERSION}):
        raise ValueError("exact versioned C1 task result evidence required")
    read=from_wire(nested["worker_read"],WorkerModelResultReadV1)
    if (to_wire(read)!=nested["worker_read"] or to_wire(read.request)!=evidence["read_request"]
            or canonical_digest(asdict(read))!=evidence["read_result_digest"]
            or read.observation.digest!=evidence["observation_digest"]
            or canonical_digest(asdict(read.terminal_receipt))!=evidence["terminal_receipt_digest"]
            or canonical_digest(read.observation.result)!=evidence["result_payload_digest"]
            or read.request.call_id!=evidence["call_id"]
            or read.request.binding_digest!=evidence["binding_digest"]
            or read.request.model_request_digest!=evidence["model_request_digest"]):
        raise ValueError("task result differs from the actual pinned C02/Authority result")
    if len(canonical_serialize(nested).encode())>131072:
        raise ValueError("task result evidence exceeds its fixed descriptor bound")
    return read


@dataclass(frozen=True,slots=True)
class C1ArtifactTaskIntentOriginalV1:
    namespace:NamespaceId
    c02_operation_id:str
    source_ref:str
    source_revision:int
    source_digest:str
    installation_id:str
    manifest_digest:str
    c02_bundle_digest:str
    c02_receipt_digest:str
    c02_commit_seq:int
    worker_read_json:str
    intent:ArtifactTaskIntentCandidateV1
    schema:str="d11.c1-artifact-task-intent-original.v1"

    def __post_init__(self):
        if (self.schema!="d11.c1-artifact-task-intent-original.v1" or type(self.namespace) is not NamespaceId
                or type(self.intent) is not ArtifactTaskIntentCandidateV1
                or AtomKey.from_token(self.source_ref).type_name!="memory.source"
                or NamespaceId.from_key(AtomKey.from_token(self.source_ref))!=self.namespace
                or type(self.source_revision) is not int or self.source_revision<1
                or type(self.c02_commit_seq) is not int or self.c02_commit_seq<1):
            raise ValueError("closed C1 task original binding required")
        for value in (self.source_digest,self.manifest_digest,self.c02_bundle_digest,self.c02_receipt_digest):
            if type(value) is not str or len(value)!=64 or any(c not in '0123456789abcdef' for c in value):
                raise ValueError("C1 task original requires exact digests")
        wire=json.loads(self.worker_read_json)
        if canonical_serialize(wire)!=self.worker_read_json or len(self.worker_read_json.encode())>131072:
            raise ValueError("C1 task original result wire is not canonical/bounded")
        read=from_wire(wire,WorkerModelResultReadV1)
        if read.request.namespace!=self.namespace or read.request.consumer_operation_id!=self.c02_operation_id:
            raise ValueError("C1 task original belongs to another exact consumer")


def _c02_task_material_v1(db,namespace,c02_operation_id):
    from .encoding_call_binding import load_binding
    from .foreground_cycle_v1 import _adopted_c02_v1
    from .natural_producer_qualification_v1 import _producer_original_point_v3
    from .domain_background_read_v3 import background_json_loads_v3
    row=_producer_original_point_v3(db,table='graph_first_ingress_c02_committed_seals_v2',
        columns=('evidence_json','bundle_digest'),key_columns=('bot','persona','operation_id'),
        key=(*namespace.as_tuple,c02_operation_id),legacy_reader=lambda:db.execute(
            'SELECT evidence_json,bundle_digest FROM graph_first_ingress_c02_committed_seals_v2 WHERE bot=? AND persona=? AND operation_id=?',
            (*namespace.as_tuple,c02_operation_id)).fetchone())
    if row is None:raise ValueError("actual committed C02 task evidence is absent")
    evidence=background_json_loads_v3(row[0]);read=validate_c1_task_result_evidence_v1(evidence)
    if read is None:return None
    from ..authority_service.artifact_task_choice_catalogue_v3 import register_task_c1_binding_material_v3
    register_task_c1_binding_material_v3(db,c02_operation_id=c02_operation_id,read=read)
    binding=load_binding(db,namespace,read.request.job_id)
    if (binding is None or binding.binding_digest!=read.request.binding_digest
            or binding.model_request_digest!=read.request.model_request_digest
            or binding.call_id!=read.request.call_id
            or binding.request["prompt_template_version"] not in {FIRST_INGRESS_TASK_ENCODING_TEMPLATE_VERSION, FIRST_INGRESS_METHOD_ENCODING_TEMPLATE_VERSION, FIRST_INGRESS_DEPENDENCY_ENCODING_TEMPLATE_VERSION}
            or binding.request["prompt_template_version"] != evidence[EMBEDDED_FIELD]["template_version"]):
        raise ValueError("C1 task result lost its exact version-2 encoding binding")
    key=source_key(*namespace.as_tuple,binding.source_id)
    source_row=_producer_original_point_v3(db,table='graph_history',columns=('value',),
        key_columns=('token','revision'),key=(key.token,binding.source_revision),legacy_reader=lambda:db.execute(
            'SELECT value FROM graph_history WHERE token=? AND revision=?',(key.token,binding.source_revision)).fetchone())
    if source_row is None:raise ValueError("C1 task result lost its actual original Source version")
    source=SourceRecord.from_dict(background_json_loads_v3(source_row[0]))
    payload,digest=build_first_ingress_encoding_payload(source,
        template_version=binding.request["prompt_template_version"])
    if binding.request["payload"]!=payload or binding.request["prompt_template_digest"]!=digest:
        raise ValueError("C1 task interpretation changed its actual source-only request")
    intent=parse_artifact_task_intent_v1(read.observation.result,source)
    if binding.request["prompt_template_version"] in {FIRST_INGRESS_METHOD_ENCODING_TEMPLATE_VERSION, FIRST_INGRESS_DEPENDENCY_ENCODING_TEMPLATE_VERSION}:
        parse_method_context_candidate_v1(read.observation.result, source)
    if binding.request["prompt_template_version"] == FIRST_INGRESS_DEPENDENCY_ENCODING_TEMPLATE_VERSION:
        parse_historical_dependency_candidate_v1(read.observation.result, source)
    receipt=_adopted_c02_v1(db,namespace,c02_operation_id)
    if receipt.operation_digest!=row[1]:raise ValueError("C1 task result lost its actual committed bundle")
    return evidence,read,binding,key,source,intent,receipt


def record_c1_task_intent_after_c02_commit_v1(db,*,namespace,c02_operation_id,issuer):
    from .d11_life_preparation_v1 import _record
    if not db.in_transaction:raise ValueError("task original must follow the same actual C02 SQL commit")
    material=_c02_task_material_v1(db,namespace,c02_operation_id)
    if material is None or material[5] is None:return None
    evidence,read,binding,key,source,intent,receipt=material
    value=C1ArtifactTaskIntentOriginalV1(namespace,c02_operation_id,key.token,binding.source_revision,
        canonical_digest(source.to_dict()),read.request.installation_id,evidence["manifest_digest"],
        receipt.operation_digest,canonical_digest(receipt),receipt.commit_seq,
        canonical_serialize(to_wire(read)),intent)
    return _record(db,issuer=issuer,namespace=namespace,kind=KIND,
        ref=c1_task_intent_ref_v1(namespace,c02_operation_id),operation_id=c02_operation_id,value=value)


def validate_c1_task_original_row_v1(*,namespace,original_ref,producing_operation_id,raw):
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    value=decode_typed_production_value_v1(raw,C1ArtifactTaskIntentOriginalV1)
    if (plain_v1(value)!=raw or value.namespace!=namespace or value.c02_operation_id!=producing_operation_id
            or original_ref!=c1_task_intent_ref_v1(namespace,producing_operation_id)):
        raise ValueError("task original changed its exact producer/namespace/identity")
    return value


def require_c1_task_original_history_v1(db,value):
    material=_c02_task_material_v1(db,value.namespace,value.c02_operation_id)
    if material is None:raise ValueError("task original has no actual version-2 C02 parent")
    evidence,read,binding,key,source,intent,receipt=material
    expected=C1ArtifactTaskIntentOriginalV1(value.namespace,value.c02_operation_id,key.token,binding.source_revision,
        canonical_digest(source.to_dict()),read.request.installation_id,evidence["manifest_digest"],
        receipt.operation_digest,canonical_digest(receipt),receipt.commit_seq,
        canonical_serialize(to_wire(read)),intent)
    if value!=expected:raise ValueError("task original differs from actual committed C1/C02 history")
    return value


def read_c1_task_intent_original_v1(db,*,namespace,c02_operation_id,issuer):
    from .d11_life_preparation_v1 import _read
    ref=c1_task_intent_ref_v1(namespace,c02_operation_id)
    row=_read(db,issuer=issuer,namespace=namespace,kind=KIND,ref=ref)
    if row is None:return None
    value=validate_c1_task_original_row_v1(namespace=namespace,original_ref=ref,
        producing_operation_id=row[1],raw=row[0])
    return require_c1_task_original_history_v1(db,value)


def read_c1_method_context_original_v1(db, *, namespace, c02_operation_id, issuer):
    """Reconstruct hypotheses from the exact signed task/C02 original history."""
    value = read_c1_task_intent_original_v1(db, namespace=namespace,
        c02_operation_id=c02_operation_id, issuer=issuer)
    if value is None:
        return None
    evidence, read, binding, key, source, intent, receipt = _c02_task_material_v1(db, namespace, c02_operation_id)
    if binding.request["prompt_template_version"] not in {FIRST_INGRESS_METHOD_ENCODING_TEMPLATE_VERSION, FIRST_INGRESS_DEPENDENCY_ENCODING_TEMPLATE_VERSION}:
        return None
    candidate = parse_method_context_candidate_v1(read.observation.result, source)
    return None if candidate is None else (value, candidate, source)


def read_c1_historical_dependency_original_v1(db, *, namespace, c02_operation_id, issuer):
    """Read hypotheses from the original current-task C1-v4/C02 signed history."""
    value = read_c1_task_intent_original_v1(db, namespace=namespace,
        c02_operation_id=c02_operation_id, issuer=issuer)
    if value is None:
        return None
    evidence, read, binding, key, source, intent, receipt = _c02_task_material_v1(db, namespace, c02_operation_id)
    if binding.request["prompt_template_version"] != FIRST_INGRESS_DEPENDENCY_ENCODING_TEMPLATE_VERSION:
        return None
    candidate = parse_historical_dependency_candidate_v1(read.observation.result, source)
    return None if candidate is None else (value, candidate, source)
