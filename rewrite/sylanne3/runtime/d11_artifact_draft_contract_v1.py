"""Closed D11 Life recipe metadata for one registered draft-file effect.

These values freeze parameters; they never grant execution or observation.
Authority, current Source grants, Jobs and Budget remain their existing owners.
The content is addressed separately and is never embedded in job metadata.
"""
from dataclasses import dataclass, fields
from pathlib import PurePosixPath, PureWindowsPath

from ..graph_types import AtomKey
from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize
from ..domains.d01.production_operations_v1 import plain_v1
from .d11_life_contract_v1 import LifeInputRefV1, life_from_wire_v1
from .d11_offline_originals_v1 import _digest, _text, _utc


RECIPE_ID = "artifact_draft_v1"
WORK_KIND = "d10.life.artifact_draft.v1"
ALGORITHM_ID = "d11.life.artifact_draft.v1"
POSTCONDITION_ID = "d11.life.artifact_draft.readback.v1"
MAX_DRAFT_BYTES = 524288
CHUNK_BYTES = 65536
MAX_METADATA_BYTES = 65536
EFFECT_QUERY_PAGE = 32


def _metadata(value):
    if len(canonical_serialize(plain_v1(value)).encode("utf-8")) > MAX_METADATA_BYTES:
        raise ValueError("draft metadata exceeds its existing descriptor bound")


def _filename(value):
    _text(value)
    if (len(value.encode("utf-8")) > 255 or value in {".", ".."}
            or value[-1] in " ." or any(c in value for c in '/\\:<>"|?*')
            or any(ord(c) < 32 for c in value)
            or PurePosixPath(value).name != value or PureWindowsPath(value).name != value
            or PureWindowsPath(value).is_reserved()):
        raise ValueError("draft target must be one finite regular filename")


@dataclass(frozen=True, slots=True)
class RegisteredArtifactDraftRecipeV1:
    recipe_id: str = RECIPE_ID
    version: int = 1
    algorithm_id: str = ALGORITHM_ID
    postcondition_id: str = POSTCONDITION_ID
    parameter_schema: str = "d11.artifact-draft-target.v1"
    effect_kind: str = "bounded_local_file_write"
    idempotency: str = "original_effect_only"
    verify_capability: str = "separately_admitted_readback"
    cancel_capability: str = "best_effort_before_handoff"
    max_bytes: int = MAX_DRAFT_BYTES
    readback_chunk_bytes: int = CHUNK_BYTES
    effect_query_page: int = EFFECT_QUERY_PAGE
    metadata_bytes: int = MAX_METADATA_BYTES
    schema: str = "d11.registered-artifact-draft-recipe.v1"

    def __post_init__(self):
        expected = {f.name: f.default for f in fields(type(self))}
        if (plain_v1(self) != expected
                or any(type(getattr(self, name)) is not type(value) for name, value in expected.items())):
            raise ValueError("only the exact installed artifact_draft_v1 recipe is supported")


@dataclass(frozen=True, slots=True)
class DraftFileIdentityV1:
    device: int
    file_id: int

    def __post_init__(self):
        if any(type(v) is not int or v < 0 for v in (self.device, self.file_id)) or self.file_id == 0:
            raise ValueError("draft requires a real OS file identity")


@dataclass(frozen=True, slots=True)
class DraftRootCapabilityV1:
    installation_id: str
    manifest_digest: str
    resource_id: str
    registration_ref: str
    root_identity: DraftFileIdentityV1
    filenames: tuple[str, ...]
    max_bytes: int
    valid_until_utc: str
    source_ref: str
    owner_grant_ref: str
    owner_grant_revision: int
    owner_grant_digest: str
    schema: str = "d11.artifact-draft-root-capability.v1"

    def __post_init__(self):
        if (self.schema != "d11.artifact-draft-root-capability.v1"
                or type(self.root_identity) is not DraftFileIdentityV1
                or type(self.filenames) is not tuple or not 1 <= len(self.filenames) <= 32
                or len(set(self.filenames)) != len(self.filenames)
                or type(self.max_bytes) is not int or not 1 <= self.max_bytes <= MAX_DRAFT_BYTES
                or type(self.owner_grant_revision) is not int or self.owner_grant_revision < 1):
            raise ValueError("draft root capability requires its exact installed finite scope")
        for filename in self.filenames:
            _filename(filename)
        for value in (self.installation_id, self.resource_id, self.registration_ref, self.owner_grant_ref):
            _text(value)
        if AtomKey.from_token(self.source_ref).type_name != "memory.source":
            raise ValueError("draft capability preserves the actual permission Source")
        _digest(self.manifest_digest); _digest(self.owner_grant_digest); _utc(self.valid_until_utc)
        _metadata(self)


@dataclass(frozen=True, slots=True)
class DraftActivityScopeV1:
    activity_id: str
    actor_ref: str
    ingress_original_ref: str
    c02_original_ref: str
    source: LifeInputRefV1
    parent_budget_lease_ref: str
    root_registration_ref: str
    root_registration_digest: str
    valid_until_utc: str
    owner_grant_ref: str
    owner_grant_revision: int
    owner_grant_digest: str
    schema: str = "d11.artifact-draft-activity-scope.v1"

    def __post_init__(self):
        if (self.schema != "d11.artifact-draft-activity-scope.v1" or type(self.source) is not LifeInputRefV1
                or AtomKey.from_token(self.source.ref).type_name != "memory.source"
                or type(self.owner_grant_revision) is not int or self.owner_grant_revision < 1):
            raise ValueError("draft activity adapter requires the actual ingress/C02/source and upstream Owner")
        for name in ("activity_id", "actor_ref", "ingress_original_ref", "c02_original_ref",
                     "parent_budget_lease_ref", "root_registration_ref", "owner_grant_ref"):
            _text(getattr(self, name))
        _digest(self.root_registration_digest); _digest(self.owner_grant_digest); _utc(self.valid_until_utc)
        _metadata(self)


@dataclass(frozen=True, slots=True)
class FrozenDraftContentV1:
    content: LifeInputRefV1
    content_digest: str
    content_length: int
    source_refs: tuple[str, ...]
    schema: str = "d11.frozen-draft-content.v1"

    def __post_init__(self):
        if (self.schema != "d11.frozen-draft-content.v1" or type(self.content) is not LifeInputRefV1
                or type(self.content_length) is not int or not 1 <= self.content_length <= MAX_DRAFT_BYTES
                or type(self.source_refs) is not tuple or not 1 <= len(self.source_refs) <= 32
                or len(set(self.source_refs)) != len(self.source_refs)):
            raise ValueError("draft freezes a bounded qualified content locator, not inline bytes")
        _digest(self.content_digest)
        for ref in self.source_refs:
            if AtomKey.from_token(ref).type_name != "memory.source":
                raise ValueError("draft content lineage requires actual D06 Source references")
        _metadata(self)


@dataclass(frozen=True, slots=True)
class DraftFileTargetV1:
    root_resource_id: str
    root_registration_ref: str
    root_registration_digest: str
    root_identity: DraftFileIdentityV1
    filename: str
    mode: str
    expected_prior_version: int
    expected_prior_digest: str | None
    expected_prior_identity: DraftFileIdentityV1 | None
    expected_prior_effect_marker: str | None
    max_bytes: int
    schema: str = "d11.artifact-draft-target.v1"

    def __post_init__(self):
        if (self.schema != "d11.artifact-draft-target.v1" or type(self.root_identity) is not DraftFileIdentityV1
                or type(self.max_bytes) is not int or not 1 <= self.max_bytes <= MAX_DRAFT_BYTES
                or type(self.expected_prior_version) is not int or self.expected_prior_version < 0):
            raise ValueError("draft target needs its actual registered root and finite bound")
        for name in ("root_resource_id", "root_registration_ref"):
            _text(getattr(self, name))
        _digest(self.root_registration_digest)
        _filename(self.filename)
        prior = (self.expected_prior_digest, self.expected_prior_identity, self.expected_prior_effect_marker)
        if self.mode == "create":
            if self.expected_prior_version != 0 or any(v is not None for v in prior):
                raise ValueError("create must freeze an absent predecessor")
        elif self.mode == "replace":
            if self.expected_prior_version < 1 or type(self.expected_prior_identity) is not DraftFileIdentityV1:
                raise ValueError("replace needs the actual previous registered effect and version")
            _digest(self.expected_prior_digest)
            _digest(self.expected_prior_effect_marker)
        else:
            raise ValueError("draft supports only exact create or replace")
        _metadata(self)

    @property
    def digest(self):
        return canonical_digest(plain_v1(self))


@dataclass(frozen=True, slots=True)
class RegisteredDraftFilePlanV3:
    project: LifeInputRefV1
    recipe: LifeInputRefV1
    action_intent: LifeInputRefV1
    input_source: LifeInputRefV1
    input_access: LifeInputRefV1
    activity_id: str
    effect_id: str
    attempt_id: str
    operation_id: str
    execution_call_id: str
    activity_scope_ref: str
    activity_scope_digest: str
    audiences: tuple[str, ...]
    parent_budget_lease_ref: str
    cpu_ceiling_ms: int
    deadline_utc: str
    algorithm_build_digest: str
    postcondition_build_digest: str
    body_effect_request_json: str | None
    target: DraftFileTargetV1
    content: FrozenDraftContentV1
    observation_valid_until_utc: str | None = None
    step: str = RECIPE_ID
    recipe_id: str = RECIPE_ID
    executor_id: str = ALGORITHM_ID
    recipe_version: int = 1
    schema: str = "d10.registered-draft-file-plan.v3"

    def __post_init__(self):
        if ((self.schema, self.step, self.recipe_id, self.executor_id, self.recipe_version) !=
                ("d10.registered-draft-file-plan.v3", RECIPE_ID, RECIPE_ID, ALGORITHM_ID, 1)
                or type(self.recipe_version) is not int
                or type(self.cpu_ceiling_ms) is not int or not 1 <= self.cpu_ceiling_ms <= 60000
                or type(self.target) is not DraftFileTargetV1 or type(self.content) is not FrozenDraftContentV1
                or self.content.content_length > self.target.max_bytes
                or type(self.audiences) is not tuple or not self.audiences
                or len(set(self.audiences)) != len(self.audiences)):
            raise ValueError("exact bounded registered draft plan required")
        for name in ("project", "recipe", "action_intent", "input_source", "input_access"):
            if type(getattr(self, name)) is not LifeInputRefV1:
                raise TypeError("draft plan freezes exact current input commitments")
        if (AtomKey.from_token(self.input_source.ref).type_name != "memory.source"
                or AtomKey.from_token(self.input_access.ref).type_name != "memory.access"):
            raise ValueError("draft requires real Source/access kinds")
        for name in ("activity_id", "effect_id", "attempt_id", "operation_id", "execution_call_id",
                     "activity_scope_ref", "parent_budget_lease_ref"):
            _text(getattr(self, name))
        for value in self.audiences:
            _text(value)
        for value in (self.activity_scope_digest, self.algorithm_build_digest, self.postcondition_build_digest):
            _digest(value)
        _utc(self.deadline_utc)
        if self.observation_valid_until_utc is not None:
            _utc(self.observation_valid_until_utc)
        if self.body_effect_request_json is not None:
            import json
            from .d11_life_contract_v1 import LifeBodyComponentContractV1
            raw = json.loads(self.body_effect_request_json)
            if canonical_serialize(raw) != self.body_effect_request_json:
                raise ValueError("draft preserves canonical actual Body references")
            LifeBodyComponentContractV1(**raw)
        _metadata(self)

    @property
    def digest(self):
        return canonical_digest(plain_v1(self))

    @property
    def target_scope_digest(self):
        return self.target.digest


@dataclass(frozen=True, slots=True)
class DraftFileObservationRequestV1:
    observation_intent_ref: str
    observation_intent_digest: str
    call_id: str
    original_effect_id: str
    original_call_id: str
    original_binding_digest: str
    admission_original_ref: str
    admission_original_digest: str
    current_read_permit_ref: str
    current_read_permit_digest: str
    reservation_ref: str
    reservation_digest: str
    parent_budget_lease_ref: str
    original_deadline_utc: str
    observation_valid_until_utc: str
    cpu_ceiling_ms: int
    read_bytes_ceiling: int
    schema: str = "d11.draft-file-observation-request.v1"

    def __post_init__(self):
        if (self.schema != "d11.draft-file-observation-request.v1"
                or type(self.cpu_ceiling_ms) is not int or not 1 <= self.cpu_ceiling_ms <= 60000
                or type(self.read_bytes_ceiling) is not int or not 1 <= self.read_bytes_ceiling <= MAX_DRAFT_BYTES
                or self.call_id == self.original_call_id
                or _utc(self.observation_valid_until_utc) > _utc(self.original_deadline_utc)):
            raise ValueError("new observation requires its own finite call and unchanged applicable deadline")
        for name in ("observation_intent_digest", "original_binding_digest", "admission_original_digest",
                     "current_read_permit_digest", "reservation_digest"):
            _digest(getattr(self, name))
        for name in ("observation_intent_ref", "call_id", "original_effect_id", "original_call_id",
                     "admission_original_ref", "current_read_permit_ref", "reservation_ref", "parent_budget_lease_ref"):
            _text(getattr(self, name))
        _metadata(self)


@dataclass(frozen=True, slots=True)
class DraftObservationAdmissionV1:
    request_parameters_json: str
    original_terminal_ref: str
    original_terminal_digest: str
    root_registration_ref: str
    root_registration_digest: str
    quote_id: str
    quote_version: int
    quote_digest: str
    source_refs: tuple[str, ...]
    frame_template_json: str
    schema: str = "d11.draft-observation-admission.v1"

    def __post_init__(self):
        if (self.schema != "d11.draft-observation-admission.v1"
                or type(self.quote_version) is not int or self.quote_version < 1
                or type(self.source_refs) is not tuple or not 1 <= len(self.source_refs) <= 32
                or len(set(self.source_refs)) != len(self.source_refs)):
            raise ValueError("draft observation admission requires actual frozen read intent and quote")
        for value in (self.original_terminal_ref, self.root_registration_ref, self.quote_id):
            _text(value)
        for value in (self.original_terminal_digest, self.root_registration_digest, self.quote_digest):
            _digest(value)
        for ref in self.source_refs:
            if AtomKey.from_token(ref).type_name != "memory.source":
                raise ValueError("draft observation admission requires actual qualified Source lineage")
        import json
        parameters = json.loads(self.request_parameters_json)
        if (type(parameters) is not dict or set(parameters) != {f.name for f in fields(DraftFileObservationRequestV1)} - {"admission_original_digest"}
                or canonical_serialize(parameters) != self.request_parameters_json):
            raise ValueError("observation admission freezes parameters without a self-referential digest")
        if canonical_serialize(json.loads(self.frame_template_json)) != self.frame_template_json:
            raise ValueError("draft observation keeps its exact canonical admitted frame")
        _metadata(self)


@dataclass(frozen=True, slots=True)
class DraftObservationOutcomeV1:
    call_id: str
    original_effect_id: str
    original_binding_digest: str
    request_digest: str
    status: str
    actual_cpu_ms: int | None
    actual_read_bytes: int | None
    matched_original_identity: bool | None
    observed_at_utc: str
    signature: str
    schema: str = "d11.draft-observation-outcome.v1"

    def __post_init__(self):
        if (self.schema != "d11.draft-observation-outcome.v1" or self.status not in {"verified", "mismatch", "unknown"}
                or any(v is not None and (type(v) is not int or v < 0) for v in (self.actual_cpu_ms, self.actual_read_bytes))
                or self.status == "verified" and self.matched_original_identity is not True
                or self.status == "mismatch" and self.matched_original_identity is not False
                or self.status == "unknown" and self.matched_original_identity is not None):
            raise ValueError("draft observation distinguishes attribution, measured cost and unknown facts")
        for value in (self.call_id, self.original_effect_id):
            _text(value)
        for value in (self.original_binding_digest, self.request_digest, self.signature):
            _digest(value)
        _utc(self.observed_at_utc); _metadata(self)


@dataclass(frozen=True, slots=True)
class DraftObservationReadRequestV1:
    authority_id: str
    authority_namespace: str
    namespace: NamespaceId
    installation_id: str
    request: DraftFileObservationRequestV1
    schema: str = "d11.draft-observation-read-request.v1"

    def __post_init__(self):
        if (self.schema != "d11.draft-observation-read-request.v1" or type(self.namespace) is not NamespaceId
                or type(self.request) is not DraftFileObservationRequestV1
                or self.request.current_read_permit_ref != self.request.call_id):
            raise ValueError("draft observation requires its own exact current read fence/call identity")
        for value in (self.authority_id, self.authority_namespace, self.installation_id):
            _text(value)
        _metadata(self)

    @property
    def read_attempt_id(self):
        return self.request.call_id

    @property
    def consumer_operation_id(self):
        return self.request.observation_intent_ref

    @property
    def digest(self):
        return canonical_digest(plain_v1(self))


@dataclass(frozen=True, slots=True)
class DraftFileReadbackV1:
    effect_id: str
    execution_call_id: str
    plan_digest: str
    target_scope_digest: str
    root_registration_digest: str
    filename: str
    version: int
    content_digest: str
    content_length: int
    file_identity: DraftFileIdentityV1
    effect_marker: str
    handoff_at_utc: str
    verified_at_utc: str
    actual_cpu_ms: int
    schema: str = "d11.draft-file-readback.v1"

    def __post_init__(self):
        if (self.schema != "d11.draft-file-readback.v1" or type(self.version) is not int or self.version < 1
                or type(self.content_length) is not int or not 1 <= self.content_length <= MAX_DRAFT_BYTES
                or type(self.file_identity) is not DraftFileIdentityV1
                or type(self.actual_cpu_ms) is not int or self.actual_cpu_ms < 0
                or _utc(self.verified_at_utc) < _utc(self.handoff_at_utc)):
            raise ValueError("readback requires actual bytes, identity, version and measured execution")
        for value in (self.effect_id, self.execution_call_id):
            _text(value)
        for value in (self.plan_digest, self.target_scope_digest, self.root_registration_digest, self.content_digest, self.effect_marker):
            _digest(value)
        _filename(self.filename)
        _metadata(self)


_TYPES = {RegisteredArtifactDraftRecipeV1, DraftFileIdentityV1, FrozenDraftContentV1,
          DraftRootCapabilityV1, DraftActivityScopeV1, DraftFileTargetV1, RegisteredDraftFilePlanV3,
          DraftFileObservationRequestV1, DraftObservationAdmissionV1, DraftObservationOutcomeV1,
          DraftObservationReadRequestV1, DraftFileReadbackV1}


def draft_to_wire_v1(value):
    if type(value) not in _TYPES:
        raise TypeError("exact registered draft metadata required")
    _metadata(value)
    return plain_v1(value)


def draft_from_wire_v1(raw, kind):
    if kind not in _TYPES or type(raw) is not dict or set(raw) != {f.name for f in fields(kind)}:
        raise ValueError("closed draft metadata fields differ")
    value = dict(raw)
    if kind is DraftRootCapabilityV1:
        value["root_identity"] = draft_from_wire_v1(value["root_identity"], DraftFileIdentityV1)
        value["filenames"] = tuple(value["filenames"])
    if kind is DraftActivityScopeV1:
        value["source"] = life_from_wire_v1(value["source"], LifeInputRefV1)
    if kind is DraftObservationAdmissionV1:
        value["source_refs"] = tuple(value["source_refs"])
    if kind is DraftObservationReadRequestV1:
        value["namespace"] = NamespaceId(**value["namespace"])
        value["request"] = draft_from_wire_v1(value["request"], DraftFileObservationRequestV1)
    if kind is FrozenDraftContentV1:
        value["content"] = life_from_wire_v1(value["content"], LifeInputRefV1)
        value["source_refs"] = tuple(value["source_refs"])
    if kind is DraftFileTargetV1:
        value["root_identity"] = draft_from_wire_v1(value["root_identity"], DraftFileIdentityV1)
        if value["expected_prior_identity"] is not None:
            value["expected_prior_identity"] = draft_from_wire_v1(value["expected_prior_identity"], DraftFileIdentityV1)
    if kind is RegisteredDraftFilePlanV3:
        for name in ("project", "recipe", "action_intent", "input_source", "input_access"):
            value[name] = life_from_wire_v1(value[name], LifeInputRefV1)
        value["target"] = draft_from_wire_v1(value["target"], DraftFileTargetV1)
        value["content"] = draft_from_wire_v1(value["content"], FrozenDraftContentV1)
        value["audiences"] = tuple(value["audiences"])
    if kind is DraftFileReadbackV1:
        value["file_identity"] = draft_from_wire_v1(value["file_identity"], DraftFileIdentityV1)
    result = kind(**value)
    if draft_to_wire_v1(result) != raw:
        raise ValueError("draft metadata is not canonical")
    return result
