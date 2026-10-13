"""Explicit Relationship C3 producer beside the unchanged IngressRecall slot."""
from dataclasses import dataclass, fields

from .authority_profile import AdminModelWorkflowV2
from .model_workflows_v4 import AdminModelWorkflowsV4, model_workflow_v4_from_payload
from ..model_broker.d07_cognition_v1 import TEMPLATE_VERSION, WORK_KIND


@dataclass(frozen=True, slots=True)
class AdminModelWorkflowsV5(AdminModelWorkflowsV4):
    d07_relationship_cognition: AdminModelWorkflowV2 | None = None

    def __post_init__(self):
        if type(self.version) is not int or self.version != 5:
            raise ValueError("explicit model workflow version 5 required")
        AdminModelWorkflowsV4(**{field.name: 4 if field.name == "version" else getattr(self, field.name)
            for field in fields(AdminModelWorkflowsV4)})
        workflow = self.d07_relationship_cognition
        if workflow is None:
            return
        if (type(workflow) is not AdminModelWorkflowV2
                or (workflow.work_kind, workflow.purpose, workflow.template_version) != (WORK_KIND, "proposal", TEMPLATE_VERSION)
                or set(workflow.quote_ceiling) != {"input_tokens", "output_tokens", "model_tokens", "model_microusd"}
                or workflow.quote_ceiling["input_tokens"] > 6000
                or workflow.quote_ceiling["output_tokens"] > 1000 or workflow.max_output_tokens > 1000):
            raise ValueError("Relationship cognition must use its explicit finite original C3 workflow")


def model_workflows_v5_from_payload(raw):
    allowed = {field.name for field in fields(AdminModelWorkflowsV5)}
    if type(raw) is not dict or not {"version", "encode", "reply", "artifact_draft", "d07_relationship_cognition"} <= set(raw) <= allowed:
        raise ValueError("version-5 workflow fields differ")
    values = {name: model_workflow_v4_from_payload(item) for name, item in raw.items()
        if name != "version" and item is not None}
    return AdminModelWorkflowsV5(raw["version"], **values)


def is_installed_relationship_cognition_slot_v2(bundle, workflow):
    from .authority_profile import AdminInstallationBundle
    from .model_workflows_v6 import AdminModelWorkflowsV6
    return (type(bundle) is AdminInstallationBundle and type(bundle.model_workflows) in {AdminModelWorkflowsV5, AdminModelWorkflowsV6}
        and type(workflow) is AdminModelWorkflowV2 and workflow is bundle.model_workflows.d07_relationship_cognition)
