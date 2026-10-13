"""Closed current-Owner artifact read selectors/results; none conveys authority."""
from dataclasses import dataclass, fields
import hashlib
import base64
import re
from ..runtime_contracts import NamespaceId, canonical_digest
from ..graph_types import AtomKey
from .d11_artifact_draft_contract_v1 import MAX_DRAFT_BYTES
from ..authority_service.v2_owner_contract import OwnerAuthorizationGuardV1, to_wire as owner_to_wire, from_wire as owner_from_wire

REQUEST_SCHEMA = "d12.owner-artifact-read.v1"
BINDING_SCHEMA = "d12.owner-artifact-read-binding.v1"
RESULT_SCHEMA = "d12.owner-artifact-read-result.v1"
OBSERVATION_SCHEMA = "d12.owner-artifact-read-observation.v1"
CONTENT_TYPE = "text/plain; charset=utf-8"
WIRE_RESULT_SCHEMA = "d12.owner-artifact-read-result.v2"
WIRE_OBSERVATION_SCHEMA = "d12.owner-artifact-read-observation.v2"
BODY_RESPONSE_MAX_BYTES = 1_048_576
METADATA_RESPONSE_MAX_BYTES = 65_536

def _text(value):
    if type(value) is not str or not 1 <= len(value) <= 4096: raise ValueError("bounded artifact locator required")

def _digest(value):
    if type(value) is not str or re.fullmatch(r"[0-9a-f]{64}", value) is None: raise ValueError("artifact commitment must be SHA256")

def _exact(value, cls):
    if type(value) is not dict or set(value) != {f.name for f in fields(cls)}: raise ValueError("closed artifact read wire required")
    return dict(value)

@dataclass(frozen=True, slots=True)
class OwnerArtifactReadRequestV1:
    namespace: NamespaceId
    installation_id: str
    project_ref: str
    progress_ref: str
    expected_artifact_version: int
    expected_content_digest: str
    schema: str = REQUEST_SCHEMA
    def __post_init__(self):
        if self.schema != REQUEST_SCHEMA or type(self.namespace) is not NamespaceId: raise ValueError("actual artifact read namespace required")
        _text(self.installation_id)
        for ref in (self.project_ref, self.progress_ref):
            _text(ref)
            if NamespaceId.from_key(AtomKey.from_token(ref)) != self.namespace: raise ValueError("artifact selector crossed namespace")
        if AtomKey.from_token(self.project_ref).type_name != "d10.life_project.v1": raise ValueError("actual registered Life project required")
        if AtomKey.from_token(self.progress_ref).type_name != "d10.life_progress.v1": raise ValueError("actual immutable Life progress required")
        if type(self.expected_artifact_version) is not int or self.expected_artifact_version < 1: raise ValueError("actual artifact version required")
        _digest(self.expected_content_digest)
    @property
    def digest(self): return canonical_digest(request_to_wire_v1(self))

@dataclass(frozen=True, slots=True)
class OwnerArtifactReadBindingV1:
    request_digest: str
    permit_digest: str
    current_owner_head: OwnerAuthorizationGuardV1
    graph_incarnation: str
    graph_revision: int
    graph_epoch: int
    source_qualification_commitment: str
    root_registration_commitment: str
    file_identity_commitment: str
    observed_at_utc: str
    schema: str = BINDING_SCHEMA
    def __post_init__(self):
        if self.schema != BINDING_SCHEMA or type(self.current_owner_head) is not OwnerAuthorizationGuardV1: raise ValueError("actual current Owner head required")
        for value in (self.request_digest, self.permit_digest, self.source_qualification_commitment, self.root_registration_commitment, self.file_identity_commitment): _digest(value)
        _text(self.graph_incarnation)
        if any(type(v) is not int or v < 0 for v in (self.graph_revision, self.graph_epoch)): raise ValueError("actual Graph stamp required")
        from .d11_offline_originals_v1 import _utc
        _utc(self.observed_at_utc)
    @property
    def current_commitment(self):
        return canonical_digest({f.name:getattr(self,f.name) for f in fields(self) if f.name != "observed_at_utc"})

@dataclass(frozen=True, slots=True)
class OwnerArtifactReadResultV1:
    namespace: NamespaceId
    installation_id: str
    project_ref: str
    progress_ref: str
    artifact_ref: str
    artifact_version: int
    content_digest: str
    content_length_bytes: int
    body: str
    read_binding: OwnerArtifactReadBindingV1
    content_type: str = CONTENT_TYPE
    schema: str = RESULT_SCHEMA
    def __post_init__(self):
        request = OwnerArtifactReadRequestV1(self.namespace,self.installation_id,self.project_ref,self.progress_ref,self.artifact_version,self.content_digest)
        if self.schema != RESULT_SCHEMA or self.content_type != CONTENT_TYPE or type(self.read_binding) is not OwnerArtifactReadBindingV1 or self.read_binding.request_digest != request.digest: raise ValueError("artifact result differs from its current read request")
        _text(self.artifact_ref)
        if NamespaceId.from_key(AtomKey.from_token(self.artifact_ref)) != self.namespace or type(self.body) is not str: raise ValueError("artifact result identity/body differs")
        data = self.body.encode("utf-8", errors="strict")
        if type(self.content_length_bytes) is not int or not 1 <= self.content_length_bytes <= MAX_DRAFT_BYTES or (len(data),hashlib.sha256(data).hexdigest()) != (self.content_length_bytes,self.content_digest): raise ValueError("artifact body differs from its verified complete bytes")
        if self.read_binding.current_owner_head.namespace != self.namespace: raise ValueError("artifact Owner head crossed namespace")

@dataclass(frozen=True, slots=True)
class OwnerArtifactReadObservationV1:
    read_binding: OwnerArtifactReadBindingV1
    result: OwnerArtifactReadResultV1 | None
    schema: str = OBSERVATION_SCHEMA
    def __post_init__(self):
        if self.schema != OBSERVATION_SCHEMA or type(self.read_binding) is not OwnerArtifactReadBindingV1 or self.result is not None and (type(self.result) is not OwnerArtifactReadResultV1 or self.result.read_binding != self.read_binding): raise ValueError("actual read observation identity differs")

def request_to_wire_v1(value):
    if type(value) is not OwnerArtifactReadRequestV1: raise TypeError("typed artifact request required")
    return {f.name: ({"bot_id":value.namespace.bot_id,"persona_id":value.namespace.persona_id} if f.name=="namespace" else getattr(value,f.name)) for f in fields(value)}

def request_from_wire_v1(raw):
    value=_exact(raw,OwnerArtifactReadRequestV1); ns=value["namespace"]
    if type(ns) is not dict or set(ns)!={"bot_id","persona_id"}: raise ValueError("exact artifact namespace wire required")
    value["namespace"]=NamespaceId(**ns); return OwnerArtifactReadRequestV1(**value)

def binding_to_wire_v1(value):
    if type(value) is not OwnerArtifactReadBindingV1: raise TypeError("typed artifact binding required")
    return {f.name:owner_to_wire(value.current_owner_head) if f.name=="current_owner_head" else getattr(value,f.name) for f in fields(value)}

def binding_from_wire_v1(raw):
    value=_exact(raw,OwnerArtifactReadBindingV1);value["current_owner_head"]=owner_from_wire(value["current_owner_head"]);return OwnerArtifactReadBindingV1(**value)

def result_to_wire_v1(value, *, public=False):
    if type(value) is not OwnerArtifactReadResultV1: raise TypeError("typed artifact result required")
    data={f.name:({"bot_id":value.namespace.bot_id,"persona_id":value.namespace.persona_id} if f.name=="namespace" else binding_to_wire_v1(value.read_binding) if f.name=="read_binding" else getattr(value,f.name)) for f in fields(value) if f.name not in {"body","schema"}}
    data.update(schema=WIRE_RESULT_SCHEMA,body_encoding="base64",body_base64=base64.b64encode(value.body.encode('utf-8')).decode('ascii'))
    if public: data.pop("read_binding")
    return data

def result_from_wire_v1(raw):
    required={f.name for f in fields(OwnerArtifactReadResultV1)}-{'body'}|{'body_encoding','body_base64'}
    if type(raw) is not dict or set(raw)!=required or raw['schema']!=WIRE_RESULT_SCHEMA or raw['body_encoding']!='base64' or type(raw['body_base64']) is not str:
        raise ValueError("exact OwnerArtifact base64 wire V2 required")
    if len(raw['body_base64'])>4*((MAX_DRAFT_BYTES+2)//3): raise ValueError("artifact encoded body exceeds registered bound")
    data=base64.b64decode(raw['body_base64'],validate=True)
    if base64.b64encode(data).decode('ascii')!=raw['body_base64'] or (len(data),hashlib.sha256(data).hexdigest())!=(raw['content_length_bytes'],raw['content_digest']):
        raise ValueError("artifact wire differs from complete original bytes")
    value={k:v for k,v in raw.items() if k not in {'body_encoding','body_base64'}};ns=value['namespace']
    if type(ns) is not dict or set(ns)!={'bot_id','persona_id'}: raise ValueError("exact artifact namespace wire required")
    value['namespace']=NamespaceId(**ns);value['read_binding']=binding_from_wire_v1(value['read_binding'])
    value['schema']=RESULT_SCHEMA;value['body']=data.decode('utf-8',errors='strict');return OwnerArtifactReadResultV1(**value)

def observation_to_wire_v1(value):
    if type(value) is not OwnerArtifactReadObservationV1: raise TypeError("typed artifact observation required")
    return {"schema":WIRE_OBSERVATION_SCHEMA,"read_binding":binding_to_wire_v1(value.read_binding),"result":None if value.result is None else result_to_wire_v1(value.result)}

def observation_from_wire_v1(raw):
    value=_exact(raw,OwnerArtifactReadObservationV1)
    if value['schema']!=WIRE_OBSERVATION_SCHEMA: raise ValueError("exact OwnerArtifact observation wire V2 required")
    value['schema']=OBSERVATION_SCHEMA;value['read_binding']=binding_from_wire_v1(value['read_binding']);value['result']=None if value['result'] is None else result_from_wire_v1(value['result']);return OwnerArtifactReadObservationV1(**value)
