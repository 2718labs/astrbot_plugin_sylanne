"""Explicit C4 workflow slot; legacy containers confer no draft permission."""
from dataclasses import dataclass, fields

from .authority_profile import AdminModelWorkflowV2, _MODEL_WORKFLOW_FIELDS, _exact_object
from .model_workflows_v3 import AdminModelWorkflowsV3


@dataclass(frozen=True, slots=True)
class AdminModelWorkflowsV4:
    version: int
    encode: AdminModelWorkflowV2
    reply: AdminModelWorkflowV2
    context_reply: AdminModelWorkflowV2 | None = None
    natural_generation: AdminModelWorkflowV2 | None = None
    natural_review: AdminModelWorkflowV2 | None = None
    appraisal: AdminModelWorkflowV2 | None = None
    d07_cognition: AdminModelWorkflowV2 | None = None
    contact_generation: AdminModelWorkflowV2 | None = None
    contact_review: AdminModelWorkflowV2 | None = None
    life_content: AdminModelWorkflowV2 | None = None
    life_numeric: AdminModelWorkflowV2 | None = None
    artifact_draft: AdminModelWorkflowV2 | None = None

    def __post_init__(self):
        if type(self.version) is not int or self.version != 4:
            raise ValueError("explicit model workflow version 4 required")
        AdminModelWorkflowsV3(3, self.encode, self.reply, self.context_reply,
            self.natural_generation, self.natural_review, self.appraisal, self.d07_cognition,
            self.contact_generation, self.contact_review, self.life_content, self.life_numeric)
        workflow = self.artifact_draft
        if workflow is None:
            return
        if (type(workflow) is not AdminModelWorkflowV2
                or (workflow.work_kind, workflow.purpose, workflow.template_version)
                != ("artifact_draft_v1", "consolidation", "sylanne.artifact_draft_template.v1")
                or (workflow.provider_id, workflow.model_id, workflow.provider_config_digest)
                != (self.reply.provider_id, self.reply.model_id, self.reply.provider_config_digest)
                or set(workflow.quote_ceiling) != {"input_tokens", "output_tokens", "model_tokens", "model_microusd"}
                or workflow.quote_ceiling["input_tokens"] > 10000
                or workflow.quote_ceiling["output_tokens"] > 2000 or workflow.max_output_tokens > 2000):
            raise ValueError("C4 slot differs from its explicit installed model and quote")


def model_workflow_v4_from_payload(raw):
    item = _exact_object(raw, _MODEL_WORKFLOW_FIELDS, "explicit model workflow")
    if (type(item["audiences"]) is not list or type(item["required_capabilities"]) is not list
            or type(item["quote_ceiling"]) is not dict):
        raise ValueError("explicit model workflow arrays or quote differ")
    return AdminModelWorkflowV2(**{**item, "audiences": tuple(item["audiences"]),
        "required_capabilities": tuple(item["required_capabilities"])})


def model_workflows_v4_from_payload(raw):
    allowed = {f.name for f in fields(AdminModelWorkflowsV4)}
    if type(raw) is not dict or not {"version", "encode", "reply", "artifact_draft"} <= set(raw) <= allowed:
        raise ValueError("version-4 workflow fields differ")
    values = {name: model_workflow_v4_from_payload(item) for name, item in raw.items()
        if name != "version" and item is not None}
    return AdminModelWorkflowsV4(raw["version"], **values)
