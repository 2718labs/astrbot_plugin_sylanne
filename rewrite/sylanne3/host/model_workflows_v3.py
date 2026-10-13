"""Explicit installed Contact V2 / Life-content / Life-numeric workflow container.

V2 remains a separate wire type. Disabled slots confer no work-kind, model or
budget permission. Actual execution still requires the installed command,
current Graph verifier, quote and signed root grant.
"""
from dataclasses import dataclass

from .authority_profile import AdminModelWorkflowV2, AdminModelWorkflowsV2
from ..model_broker.contact_expression_v2 import (
    GENERATION_TEMPLATE_VERSION, REVIEW_TEMPLATE_VERSION,
)

LIFE_CONTENT_WORK_KIND = "d06.encode_internal_life_content"
LIFE_CONTENT_TEMPLATE_VERSION = "sylanne.d06.internal_life_content.v1"


@dataclass(frozen=True, slots=True)
class AdminModelWorkflowsV3:
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

    def __post_init__(self):
        if type(self.version) is not int or self.version != 3:
            raise ValueError("installed workflow container requires explicit version 3")
        # Reuse the unchanged common-workflow checks without routing V2 Contact
        # templates through the old V1 Contact authority branch.
        AdminModelWorkflowsV2(2, self.encode, self.reply, self.context_reply,
            self.natural_generation, self.natural_review, self.appraisal,
            self.d07_cognition)
        if (self.contact_generation is None) != (self.contact_review is None):
            raise ValueError("Contact V2 needs both independent installed phases")
        selected = self.natural_generation if self.natural_generation is not None else self.reply
        identity = lambda w: (w.provider_id, w.model_id, w.provider_config_digest)
        for workflow, expected in (
            (self.contact_generation, ("contact_generation", "proposal", GENERATION_TEMPLATE_VERSION)),
            (self.contact_review, ("contact_review", "proposal", REVIEW_TEMPLATE_VERSION)),
            (self.life_content, (LIFE_CONTENT_WORK_KIND, "consolidation", LIFE_CONTENT_TEMPLATE_VERSION)),
            (self.life_numeric, ("d06.encode_internal_life_numeric", "consolidation", "sylanne.d06.internal_life_numeric.v1")),
        ):
            if workflow is not None and (
                type(workflow) is not AdminModelWorkflowV2
                or (workflow.work_kind, workflow.purpose, workflow.template_version) != expected
                or (workflow is not self.life_content and workflow is not self.life_numeric
                    and identity(workflow) != identity(selected))
            ):
                raise ValueError("version-3 model slot differs from its exact installed workflow")


def model_workflows_v3_from_payload(raw):
    from dataclasses import fields
    from .authority_profile import _MODEL_WORKFLOW_FIELDS, _exact_object
    if type(raw) is not dict:
        raise ValueError("version-3 workflows must be a closed object")
    allowed = {f.name for f in fields(AdminModelWorkflowsV3)}
    if not {"version", "encode", "reply"} <= set(raw) <= allowed:
        raise ValueError("version-3 workflow fields differ")
    workflows = {}
    for name in allowed - {"version"}:
        if name not in raw:
            continue
        item = _exact_object(raw[name], _MODEL_WORKFLOW_FIELDS, f"model {name} workflow")
        if (type(item["audiences"]) is not list
                or type(item["required_capabilities"]) is not list
                or type(item["quote_ceiling"]) is not dict):
            raise ValueError("version-3 workflow arrays or price are invalid")
        workflows[name] = AdminModelWorkflowV2(**{**item,
            "audiences": tuple(item["audiences"]),
            "required_capabilities": tuple(item["required_capabilities"]),
        })
    return AdminModelWorkflowsV3(raw["version"], **workflows)
