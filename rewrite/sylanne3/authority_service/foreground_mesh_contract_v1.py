"""Closed Personal eligibility mesh selectors on the original WRITE fence."""
from dataclasses import dataclass
from datetime import datetime
from .current_foreground_activity_v1 import ForegroundActivityRequestV1, ForegroundActivityEvidenceV1, foreground_fence_operation_id_v1
from .current_owner_source_note_task_v1 import OwnerTaskActivityRequestV1, OwnerTaskActivityEvidenceV1, owner_task_fence_operation_id_v1
from ..runtime.personal_candidate_eligibility_v1 import PersonalEligibilityRequestV1, PREPARE, ADOPT
from ..runtime.domain_production_contracts_v1 import ProductionOriginalRefV1, ProductionQueryCoverageV1
from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize
from ..graph_types import GraphVersion, AtomKey

RECIPE = "foreground-projection.v1"
OPERATIONS = frozenset((PREPARE, ADOPT))
BIRTH_OPERATOR = "d11.personal-semantic-mesh"
BIRTH_VERSION = "1"

@dataclass(frozen=True, slots=True)
class PersonalMeshCompanionSelectorV1:
    command: PersonalEligibilityRequestV1
    causal_original_ref: str
    recipe_version: str = RECIPE
    schema: str = "d11.personal-mesh-companion-selector.v1"

    def __post_init__(self):
        if (self.schema != "d11.personal-mesh-companion-selector.v1"
                or self.recipe_version != RECIPE or type(self.command) is not PersonalEligibilityRequestV1
                or self.causal_original_ref != self.command.candidates.need_qualification_original_ref):
            raise ValueError("mesh companion requires its exact actual Personal Need locator")
        if len(canonical_serialize(self).encode("utf-8")) > 65536:
            raise ValueError("Personal mesh selector exceeds the original descriptor bound")

@dataclass(frozen=True, slots=True)
class ForegroundMeshActivityRequestV1:
    original: ForegroundActivityRequestV1
    companion: PersonalMeshCompanionSelectorV1
    schema: str = "d11.foreground-mesh-activity-request.v1"

    def __post_init__(self):
        if (self.schema != "d11.foreground-mesh-activity-request.v1"
                or type(self.original) is not ForegroundActivityRequestV1
                or type(self.companion) is not PersonalMeshCompanionSelectorV1
                or self.original.operation_kind not in OPERATIONS
                or self.original.purpose != "consolidation"):
            raise ValueError("Foreground mesh supports only the original two Personal WRITE boundaries")
        _same_namespace(self.original.namespace, self.companion)

@dataclass(frozen=True, slots=True)
class OwnerTaskMeshActivityRequestV1:
    original: OwnerTaskActivityRequestV1
    companion: PersonalMeshCompanionSelectorV1
    schema: str = "d11.owner-task-mesh-activity-request.v1"

    def __post_init__(self):
        if (self.schema != "d11.owner-task-mesh-activity-request.v1"
                or type(self.original) is not OwnerTaskActivityRequestV1
                or type(self.companion) is not PersonalMeshCompanionSelectorV1
                or self.original.operation_kind not in OPERATIONS):
            raise ValueError("OwnerTask mesh supports only its original two Personal WRITE boundaries")
        _same_namespace(self.original.namespace, self.companion)

def _same_namespace(namespace, selector):
    from ..runtime_contracts import NamespaceId
    if (any(NamespaceId.from_key(AtomKey.from_token(ref)) != namespace
                for ref in (selector.command.candidates.plan_ref, selector.command.candidates.goal_ref))):
        raise ValueError("Personal mesh locators crossed the original namespace")

@dataclass(frozen=True, slots=True)
class PersonalMeshJobMetadataV1:
    namespace: NamespaceId
    job_ref: str
    job_revision: int
    work_kind: str
    continuation_schema: str
    recipe_version: str
    operator_versions_digest: str
    schema: str = "d11.personal-mesh-job-metadata.v1"

    def __post_init__(self):
        from ..runtime_contracts import NamespaceId
        if (self.schema != "d11.personal-mesh-job-metadata.v1" or type(self.namespace) is not NamespaceId
                or NamespaceId.from_key(AtomKey.from_token(self.job_ref)) != self.namespace
                or type(self.job_revision) is not int or self.job_revision < 1
                or self.recipe_version not in ("legacy.v1", RECIPE)
                or len(self.operator_versions_digest) != 64):
            raise ValueError("Personal mesh classification requires its exact registered job metadata")

@dataclass(frozen=True, slots=True)
class PersonalMeshQualifiedFactsV1:
    causal_original: ProductionOriginalRefV1
    tick_keys: tuple[AtomKey, ...]
    expected_tick: GraphVersion
    read_versions: tuple[GraphVersion, ...]
    query_coverage: tuple[ProductionQueryCoverageV1, ...]
    predecessors: tuple[ProductionOriginalRefV1, ...]
    source_closure: tuple[GraphVersion, ...]
    selector_commitment: str
    parent_budget_lease_ref: str
    original_deadline_utc: float
    storage_generation: int
    schema: str = "d11.personal-mesh-qualified-facts.v1"

    def __post_init__(self):
        if (self.schema != "d11.personal-mesh-qualified-facts.v1"
                or type(self.causal_original) is not ProductionOriginalRefV1
                or self.tick_keys != (self.expected_tick.key,)
                or type(self.read_versions) is not tuple or any(type(v) is not GraphVersion for v in self.read_versions)
                or type(self.source_closure) is not tuple or any(type(v) is not GraphVersion for v in self.source_closure)
                or type(self.predecessors) is not tuple or any(type(v) is not ProductionOriginalRefV1 for v in self.predecessors)
                or type(self.storage_generation) is not int or self.storage_generation < 0
                or not self.parent_budget_lease_ref or len(self.selector_commitment) != 64):
            raise ValueError("Personal mesh facts must contain the exact observed current readset")

    @property
    def core_qualification_readset_digest(self):
        return canonical_digest((self.read_versions,self.query_coverage,self.source_closure))

@dataclass(frozen=True, slots=True)
class ForegroundMeshActivityEvidenceV1:
    request: ForegroundMeshActivityRequestV1
    original: ForegroundActivityEvidenceV1
    mesh: PersonalMeshQualifiedFactsV1 | None
    job_metadata: PersonalMeshJobMetadataV1
    schema: str = "d11.foreground-mesh-activity-evidence.v1"

    def __post_init__(self):
        if (self.schema != "d11.foreground-mesh-activity-evidence.v1"
                or type(self.request) is not ForegroundMeshActivityRequestV1
                or type(self.original) is not ForegroundActivityEvidenceV1
                or self.original.request != self.request.original
                or self.mesh is not None and type(self.mesh) is not PersonalMeshQualifiedFactsV1
                or type(self.job_metadata) is not PersonalMeshJobMetadataV1):
            raise ValueError("Foreground mesh evidence changed its independent original issuer")
        _same_facts(self.request, self.original, self.mesh, self.job_metadata)

@dataclass(frozen=True, slots=True)
class OwnerTaskMeshActivityEvidenceV1:
    request: OwnerTaskMeshActivityRequestV1
    original: OwnerTaskActivityEvidenceV1
    mesh: PersonalMeshQualifiedFactsV1 | None
    job_metadata: PersonalMeshJobMetadataV1
    schema: str = "d11.owner-task-mesh-activity-evidence.v1"

    def __post_init__(self):
        if (self.schema != "d11.owner-task-mesh-activity-evidence.v1"
                or type(self.request) is not OwnerTaskMeshActivityRequestV1
                or type(self.original) is not OwnerTaskActivityEvidenceV1
                or self.original.request != self.request.original
                or self.mesh is not None and type(self.mesh) is not PersonalMeshQualifiedFactsV1
                or type(self.job_metadata) is not PersonalMeshJobMetadataV1):
            raise ValueError("OwnerTask mesh evidence changed its independent original issuer")
        _same_facts(self.request, self.original, self.mesh, self.job_metadata)

def _same_facts(request, original, facts, job):
    if job.namespace != request.original.namespace or job.job_ref != (request.original.cycle_job_ref if type(request) is ForegroundMeshActivityRequestV1 else request.original.task_job_ref):
        raise ValueError("Personal mesh classification changed its actual original job metadata")
    if job.recipe_version == "legacy.v1":
        if facts is not None:
            raise ValueError("Legacy job cannot acquire a new semantic tick contract")
        return
    if type(facts) is not PersonalMeshQualifiedFactsV1:
        raise ValueError("Mesh birth requires its actual independent qualification")
    deadline = datetime.fromisoformat(original.valid_until_utc.replace("Z", "+00:00")).timestamp()
    if (facts.causal_original.original_ref != request.companion.causal_original_ref
            or facts.selector_commitment != canonical_digest(request)
            or facts.original_deadline_utc > deadline
            or not set(original.read_versions) <= set(facts.read_versions)):
        raise ValueError("Mesh evidence cannot extend or substitute its original current proof")

def personal_mesh_fence_operation_id_v1(request):
    if type(request) is ForegroundMeshActivityRequestV1:
        return foreground_fence_operation_id_v1(request.original)
    if type(request) is OwnerTaskMeshActivityRequestV1:
        return owner_task_fence_operation_id_v1(request.original)
    raise TypeError("mesh fence requires one exact independently registered selector")

_WIRE = {
    "foreground_request": ForegroundMeshActivityRequestV1,
    "foreground_evidence": ForegroundMeshActivityEvidenceV1,
    "owner_task_request": OwnerTaskMeshActivityRequestV1,
    "owner_task_evidence": OwnerTaskMeshActivityEvidenceV1,
}

def personal_mesh_to_wire_v1(value):
    from ..domains.d01.production_operations_v1 import plain_v1
    kinds = {cls: kind for kind, cls in _WIRE.items()}
    if type(value) not in kinds:
        raise TypeError("unregistered Personal mesh wire type")
    return {"schema": "d11.personal-mesh-wire.v1", "kind": kinds[type(value)], "value": plain_v1(value)}

def personal_mesh_from_wire_v1(raw, expected_type):
    from ..runtime.domain_production_erasure_v1 import decode_typed_production_value_v1
    if (type(raw) is not dict or set(raw) != {"schema", "kind", "value"}
            or raw["schema"] != "d11.personal-mesh-wire.v1" or _WIRE.get(raw["kind"]) is not expected_type):
        raise ValueError("Personal mesh wire differs from its exact schema and type")
    value = decode_typed_production_value_v1(raw["value"], expected_type)
    if personal_mesh_to_wire_v1(value) != raw:
        raise ValueError("Personal mesh wire changed under its canonical codec")
    return value
