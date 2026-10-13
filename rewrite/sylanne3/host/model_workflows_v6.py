"""Explicit preliminary growth C3 workflow; previous workflow containers stay unchanged."""
from dataclasses import dataclass, fields, replace

from .authority_profile import AdminModelWorkflowV2
from .model_workflows_v4 import model_workflow_v4_from_payload
from .model_workflows_v5 import AdminModelWorkflowsV5
from ..model_broker.d07_cognition_v1 import TEMPLATE_VERSION, WORK_KIND
from ..model_broker.natural_reply_history_v6 import TEMPLATE_VERSION as NATURAL_REPLY_GENERATION_WORKFLOW_V6
from ..runtime_contracts import NATURAL_REPLY_GENERATION_WORKFLOW_V5, NATURAL_REPLY_REVIEW_WORKFLOW_V2


@dataclass(frozen=True, slots=True)
class AdminModelWorkflowsV6(AdminModelWorkflowsV5):
    growth_cognition: AdminModelWorkflowV2 | None = None

    def __post_init__(self):
        if type(self.version) is not int or self.version != 6:
            raise ValueError("explicit model workflow version 6 required")
        values = {field.name: 5 if field.name == "version" else getattr(self, field.name)
            for field in fields(AdminModelWorkflowsV5)}
        generation = self.natural_generation
        if generation is not None and generation.template_version == NATURAL_REPLY_GENERATION_WORKFLOW_V6:
            if ((generation.work_kind, generation.purpose) != ("natural_generation", "proposal")
                    or type(self.natural_review) is not AdminModelWorkflowV2
                    or (self.natural_review.work_kind, self.natural_review.purpose, self.natural_review.template_version) !=
                        ("natural_review", "proposal", NATURAL_REPLY_REVIEW_WORKFLOW_V2)):
                raise ValueError("named natural V6 generation retains its independent review V2")
            # This view only reuses old pure structural checks. Actual self and all wire/hash/quotes retain V6.
            values["natural_generation"] = replace(generation, template_version=NATURAL_REPLY_GENERATION_WORKFLOW_V5)
        AdminModelWorkflowsV5(**values)
        workflow = self.growth_cognition
        if workflow is None:
            return
        if (type(workflow) is not AdminModelWorkflowV2
                or (workflow.work_kind, workflow.purpose, workflow.template_version) != (WORK_KIND, "proposal", TEMPLATE_VERSION)
                or set(workflow.quote_ceiling) != {"input_tokens", "output_tokens", "model_tokens", "model_microusd"}
                or workflow.quote_ceiling["input_tokens"] > 6000
                or workflow.quote_ceiling["output_tokens"] > 1000
                or workflow.quote_ceiling["model_tokens"] > 7000 or workflow.max_output_tokens > 1000):
            raise ValueError("growth cognition uses its own declared finite preliminary C3 workflow")


def model_workflows_v6_from_payload(raw):
    allowed = {field.name for field in fields(AdminModelWorkflowsV6)}
    required = {"version", "encode", "reply", "artifact_draft", "d07_relationship_cognition", "growth_cognition"}
    if type(raw) is not dict or not required <= set(raw) <= allowed:
        raise ValueError("version-6 workflow fields differ")
    values = {name: model_workflow_v4_from_payload(item) for name, item in raw.items()
        if name != "version" and item is not None}
    return AdminModelWorkflowsV6(raw["version"], **values)


def is_installed_growth_cognition_slot_v2(bundle, workflow):
    from .authority_profile import AdminInstallationBundle
    return (type(bundle) is AdminInstallationBundle and type(bundle.model_workflows) is AdminModelWorkflowsV6
        and type(workflow) is AdminModelWorkflowV2 and workflow is bundle.model_workflows.growth_cognition)
