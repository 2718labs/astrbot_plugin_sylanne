"""Explicit V8 general-growth cognition model wire; previous containers stay unchanged."""
from dataclasses import dataclass, fields

from .authority_profile import AdminModelWorkflowV2
from .model_workflows_v4 import model_workflow_v4_from_payload
from .model_workflows_v7 import AdminModelWorkflowsV7
from ..model_broker.general_growth_cognition_v1 import PURPOSE, TEMPLATE_VERSION, WORK_KIND


@dataclass(frozen=True, slots=True)
class AdminModelWorkflowsV8(AdminModelWorkflowsV7):
    general_growth_cognition: AdminModelWorkflowV2 | None = None

    def __post_init__(self):
        if type(self.version) is not int or self.version != 8:
            raise ValueError("explicit model workflow version 8 required")
        values = {field.name: getattr(self, field.name) for field in fields(AdminModelWorkflowsV7)}
        values["version"] = 7
        AdminModelWorkflowsV7(**values)
        workflow = self.general_growth_cognition
        if workflow is None:
            return
        if (type(workflow) is not AdminModelWorkflowV2
                or (workflow.work_kind, workflow.purpose, workflow.template_version)
                   != (WORK_KIND, PURPOSE, TEMPLATE_VERSION)
                or set(workflow.quote_ceiling) != {
                    "input_tokens", "output_tokens", "model_tokens", "model_microusd"}
                or workflow.quote_ceiling["input_tokens"] > 6000
                or workflow.quote_ceiling["output_tokens"] > 1000
                or workflow.quote_ceiling["model_tokens"] > 7000
                or workflow.max_output_tokens > 1000):
            raise ValueError("general growth cognition requires its exact bounded consolidation workflow")


def model_workflows_v8_from_payload(raw):
    allowed = {field.name for field in fields(AdminModelWorkflowsV8)}
    required = {
        "version", "encode", "reply", "artifact_draft", "d07_relationship_cognition",
        "growth_cognition", "natural_generation", "natural_review", "general_growth_cognition",
    }
    if type(raw) is not dict or not required <= set(raw) <= allowed:
        raise ValueError("version-8 workflow fields differ")
    values = {name: model_workflow_v4_from_payload(item) for name, item in raw.items()
              if name != "version" and item is not None}
    return AdminModelWorkflowsV8(raw["version"], **values)


def is_installed_general_growth_cognition_slot_v1(bundle, workflow):
    from .authority_profile import AdminInstallationBundle
    from .model_workflows_v9 import AdminModelWorkflowsV9
    return (type(bundle) is AdminInstallationBundle
            and type(bundle.model_workflows) in (AdminModelWorkflowsV8, AdminModelWorkflowsV9)
            and type(workflow) is AdminModelWorkflowV2
            and workflow is bundle.model_workflows.general_growth_cognition)


def is_installed_growth_cognition_slot_v4(bundle, workflow):
    from .authority_profile import AdminInstallationBundle
    from .model_workflows_v9 import AdminModelWorkflowsV9
    return (type(bundle) is AdminInstallationBundle
            and type(bundle.model_workflows) in (AdminModelWorkflowsV8, AdminModelWorkflowsV9)
            and type(workflow) is AdminModelWorkflowV2
            and workflow is bundle.model_workflows.growth_cognition)


def is_installed_relationship_cognition_slot_v4(bundle, workflow):
    from .authority_profile import AdminInstallationBundle
    from .model_workflows_v9 import AdminModelWorkflowsV9
    return (type(bundle) is AdminInstallationBundle
            and type(bundle.model_workflows) in (AdminModelWorkflowsV8, AdminModelWorkflowsV9)
            and type(workflow) is AdminModelWorkflowV2
            and workflow is bundle.model_workflows.d07_relationship_cognition)
