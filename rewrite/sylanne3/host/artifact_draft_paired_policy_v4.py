"""Initial paired targets in the installed export root; each capability remains one file."""
from dataclasses import dataclass, field, fields

from .authority_profile import (AdminArtifactDraftToolScopeV2, AdminArtifactDraftPolicyV3,
    AdminArtifactDraftBodyPolicyV1, AdminArtifactDraftObservationPolicyV1, AdminArtifactStandingScopeV3,
    AdminModelWorkflowV2, artifact_standing_scope_from_payload_v2, _exact_object)
from .model_workflows_v4 import model_workflow_v4_from_payload
from ..domains.d01 import FULL_DRAFT_METHOD_V1, TONE_SAMPLE_METHOD_V1


TOOL_SCHEMA = "sylanne.artifact-draft-tool-scope.v3"
POLICY_SCHEMA = "sylanne.artifact-draft-policy.v4"


class _InstalledPairScopesV3:
    __slots__ = ("_installed_tool_scopes",)


@dataclass(frozen=True, slots=True)
class AdminArtifactDraftToolScopeV3(_InstalledPairScopesV3):
    resource_id: str
    filenames: tuple[str, str]
    max_file_bytes: int
    generated_text_bytes: int
    readback_chunk_bytes: int
    execution_timeout_seconds: float
    maximum_artifact_version: int
    operations: tuple[str, ...]
    schema: str = TOOL_SCHEMA

    def __post_init__(self):
        if (self.schema != TOOL_SCHEMA or type(self.filenames) is not tuple or len(self.filenames) != 2
                or len(set(self.filenames)) != 2 or self.maximum_artifact_version != 2):
            raise ValueError("initial paired scope declares exactly two distinct files with two versions each")
        scopes = tuple(AdminArtifactDraftToolScopeV2(self.resource_id, name, self.max_file_bytes,
            self.generated_text_bytes, self.readback_chunk_bytes, self.execution_timeout_seconds,
            self.maximum_artifact_version, self.operations) for name in self.filenames)
        object.__setattr__(self, "_installed_tool_scopes", scopes)


@dataclass(frozen=True, slots=True)
class AdminArtifactDraftPairedPolicyV4:
    model_workflow: AdminModelWorkflowV2
    tool_scope: AdminArtifactDraftToolScopeV3
    body_policy: AdminArtifactDraftBodyPolicyV1
    observation_policy: AdminArtifactDraftObservationPolicyV1 | None
    standing_scope: AdminArtifactStandingScopeV3
    phase_model_workflow: AdminModelWorkflowV2 = field(kw_only=True)
    schema: str = POLICY_SCHEMA

    def __post_init__(self):
        if (self.schema != POLICY_SCHEMA or type(self.tool_scope) is not AdminArtifactDraftToolScopeV3
                or type(self.standing_scope) is not AdminArtifactStandingScopeV3
                or self.standing_scope.maximum_active_tasks != 2
                or set(self.standing_scope.method_refs) != {FULL_DRAFT_METHOD_V1, TONE_SAMPLE_METHOD_V1}):
            raise ValueError("fresh paired policy explicitly authorizes two active tasks and both legal methods")
        for scope in self.tool_scope._installed_tool_scopes:
            AdminArtifactDraftPolicyV3(self.model_workflow, scope, self.body_policy,
                self.observation_policy, self.standing_scope, phase_model_workflow=self.phase_model_workflow)


def select_paired_tool_scope_v3(policy, filename):
    if type(policy) is not AdminArtifactDraftPairedPolicyV4 or type(filename) is not str:
        raise TypeError("paired target requires the actual installed paired policy and explicit signed filename")
    matches = tuple(scope for scope in policy.tool_scope._installed_tool_scopes if scope.filename == filename)
    if len(matches) != 1:
        raise ValueError("actual C1 filename is absent from the exact installed pair")
    return matches[0]


def artifact_draft_paired_policy_v4_from_payload(raw):
    values = dict(_exact_object(raw, {field.name for field in fields(AdminArtifactDraftPairedPolicyV4)}, "paired artifact policy"))
    scope = dict(_exact_object(values["tool_scope"], {field.name for field in fields(AdminArtifactDraftToolScopeV3)}, "paired tool scope"))
    if type(scope["filenames"]) is not list or type(scope["operations"]) is not list:
        raise ValueError("paired filename and operation declarations require exact JSON arrays")
    scope["filenames"], scope["operations"] = tuple(scope["filenames"]), tuple(scope["operations"])
    values["tool_scope"] = AdminArtifactDraftToolScopeV3(**scope)
    values["model_workflow"] = model_workflow_v4_from_payload(values["model_workflow"])
    values["phase_model_workflow"] = model_workflow_v4_from_payload(values["phase_model_workflow"])
    values["standing_scope"] = artifact_standing_scope_from_payload_v2(values["standing_scope"])
    values["body_policy"] = AdminArtifactDraftBodyPolicyV1(**_exact_object(values["body_policy"],
        {field.name for field in fields(AdminArtifactDraftBodyPolicyV1)}, "paired draft Body policy"))
    if values["observation_policy"] is not None:
        values["observation_policy"] = AdminArtifactDraftObservationPolicyV1(**_exact_object(values["observation_policy"],
            {field.name for field in fields(AdminArtifactDraftObservationPolicyV1)}, "paired draft observation policy"))
    return AdminArtifactDraftPairedPolicyV4(**values)


def require_paired_phase_frozen_target_v4(policy, frozen):
    """Match the actual frozen preparation target; current signed Root verification remains mandatory."""
    from ..model_broker.artifact_draft_v1 import ArtifactDraftInputV3
    if type(policy) is not AdminArtifactDraftPairedPolicyV4 or type(frozen) is not ArtifactDraftInputV3:
        raise TypeError("paired phases require the actual named policy and contracted frozen input")
    target = frozen.target
    scope = select_paired_tool_scope_v3(policy, target.filename)
    if (target.root_resource_id != scope.resource_id or target.filename != scope.filename
            or target.max_bytes > scope.max_file_bytes or target.mode not in {"create", "replace"}
            or target.mode == "create" and target.expected_prior_version != 0
            or target.mode == "replace" and not 1 <= target.expected_prior_version < scope.maximum_artifact_version):
        raise ValueError("paired frozen target exceeds its original selected export/version boundary")
    return scope
