"""Explicitly installed C3 screen and deep slots; older workflow containers stay unchanged."""
from dataclasses import dataclass,fields
from .authority_profile import AdminModelWorkflowV2
from .model_workflows_v9 import AdminModelWorkflowsV9
from .model_workflows_v4 import model_workflow_v4_from_payload
from ..model_broker.ordinary_continuity_cognition_v1 import WORK_KIND,PURPOSE,ordinary_continuity_template_v1

@dataclass(frozen=True,slots=True)
class AdminModelWorkflowsV10(AdminModelWorkflowsV9):
    ordinary_continuity_screen:AdminModelWorkflowV2|None=None
    ordinary_continuity_deep:AdminModelWorkflowV2|None=None

    def __post_init__(self):
        if type(self.version)is not int or self.version!=10:
            raise ValueError("explicit model workflow version 10 required")
        inherited={f.name:getattr(self,f.name)for f in fields(AdminModelWorkflowsV9)}
        AdminModelWorkflowsV9(**{**inherited,"version":9})
        for phase,name in (("ordinary_screen","ordinary_continuity_screen"),("deep_review","ordinary_continuity_deep")):
            workflow=getattr(self,name)
            if workflow is None:continue
            version,_input,_output,_system=ordinary_continuity_template_v1(phase)
            if (type(workflow)is not AdminModelWorkflowV2
                    or(workflow.work_kind,workflow.purpose,workflow.template_version)!=(WORK_KIND,PURPOSE,version)
                    or set(workflow.quote_ceiling)!={"input_tokens","output_tokens","model_tokens","model_microusd"}
                    or workflow.quote_ceiling["input_tokens"]>6000 or workflow.quote_ceiling["output_tokens"]>1000
                    or workflow.quote_ceiling["model_tokens"]>7000 or workflow.max_output_tokens>1000):
                raise ValueError("ordinary continuity requires its exact explicitly installed bounded phase workflow")

def model_workflows_v10_from_payload(raw):
    allowed={f.name for f in fields(AdminModelWorkflowsV10)}
    required={"version","encode","reply","artifact_draft","d07_relationship_cognition","growth_cognition",
        "natural_generation","natural_review","general_growth_cognition","artifact_observation_cognition",
        "ordinary_continuity_screen","ordinary_continuity_deep"}
    if type(raw)is not dict or not required<=set(raw)<=allowed:
        raise ValueError("version-10 workflow fields differ")
    values={name:model_workflow_v4_from_payload(value)for name,value in raw.items()if name!="version"and value is not None}
    return AdminModelWorkflowsV10(raw["version"],**values)

def is_installed_ordinary_continuity_cognition_slot_v1(bundle,workflow,phase):
    from .authority_profile import AdminInstallationBundle
    if phase not in {"ordinary_screen","deep_review"}:
        return False
    name="ordinary_continuity_screen"if phase=="ordinary_screen"else"ordinary_continuity_deep"
    return(type(bundle)is AdminInstallationBundle and type(bundle.model_workflows)is AdminModelWorkflowsV10
        and type(workflow)is AdminModelWorkflowV2 and workflow is getattr(bundle.model_workflows,name))
