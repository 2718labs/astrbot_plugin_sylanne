"""Explicit V9 installed independent Artifact observation cognition slot."""
from dataclasses import dataclass,fields
from .authority_profile import AdminModelWorkflowV2
from .model_workflows_v8 import AdminModelWorkflowsV8
from .model_workflows_v4 import model_workflow_v4_from_payload
from ..model_broker.d07_cognition_v1 import WORK_KIND,TEMPLATE_VERSION


@dataclass(frozen=True,slots=True)
class AdminModelWorkflowsV9(AdminModelWorkflowsV8):
    artifact_observation_cognition:AdminModelWorkflowV2|None=None

    def __post_init__(self):
        if type(self.version)is not int or self.version!=9:
            raise ValueError('explicit model workflow version 9 required')
        inherited={f.name:getattr(self,f.name)for f in fields(AdminModelWorkflowsV8)}
        AdminModelWorkflowsV8(**{**inherited,'version':8})
        workflow=self.artifact_observation_cognition
        if workflow is None:return
        if (type(workflow)is not AdminModelWorkflowV2
                or(workflow.work_kind,workflow.purpose,workflow.template_version)!=(WORK_KIND,'proposal',TEMPLATE_VERSION)
                or set(workflow.quote_ceiling)!={'input_tokens','output_tokens','model_tokens','model_microusd'}
                or workflow.quote_ceiling['input_tokens']>6000 or workflow.quote_ceiling['output_tokens']>1000
                or workflow.quote_ceiling['model_tokens']>7000 or workflow.max_output_tokens>1000):
            raise ValueError('Artifact observation requires its exact independent bounded D07 workflow')


def model_workflows_v9_from_payload(raw):
    allowed={f.name for f in fields(AdminModelWorkflowsV9)}
    required={'version','encode','reply','artifact_draft','d07_relationship_cognition','growth_cognition',
        'natural_generation','natural_review','general_growth_cognition','artifact_observation_cognition'}
    if type(raw)is not dict or not required<=set(raw)<=allowed:
        raise ValueError('version-9 workflow fields differ')
    values={name:model_workflow_v4_from_payload(item)for name,item in raw.items()if name!='version'and item is not None}
    return AdminModelWorkflowsV9(raw['version'],**values)


def is_installed_artifact_observation_cognition_slot_v1(bundle,workflow):
    from .authority_profile import AdminInstallationBundle
    return(type(bundle)is AdminInstallationBundle and type(bundle.model_workflows)is AdminModelWorkflowsV9
        and type(workflow)is AdminModelWorkflowV2 and workflow is bundle.model_workflows.artifact_observation_cognition)
