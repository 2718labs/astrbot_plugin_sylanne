"""Explicit V7 semantic model wire; old workflow containers remain unchanged."""
from dataclasses import dataclass,fields,replace

from .authority_profile import AdminModelWorkflowV2
from .model_workflows_v4 import model_workflow_v4_from_payload
from .model_workflows_v6 import AdminModelWorkflowsV6
from ..model_broker.natural_reply_history_v7 import TEMPLATE_VERSION
from ..model_broker.natural_reply_history_v6 import TEMPLATE_VERSION as V6_TEMPLATE
from ..runtime_contracts import NATURAL_REPLY_REVIEW_WORKFLOW_V2

@dataclass(frozen=True,slots=True)
class AdminModelWorkflowsV7(AdminModelWorkflowsV6):
    def __post_init__(self):
        if type(self.version) is not int or self.version!=7:
            raise ValueError('explicit model workflow version7 required')
        generation=self.natural_generation
        if (type(generation) is not AdminModelWorkflowV2
                or (generation.work_kind,generation.purpose,generation.template_version)!=(
                    'natural_generation','proposal',TEMPLATE_VERSION)
                or type(self.natural_review) is not AdminModelWorkflowV2
                or (self.natural_review.work_kind,self.natural_review.purpose,self.natural_review.template_version)!=(
                    'natural_review','proposal',NATURAL_REPLY_REVIEW_WORKFLOW_V2)):
            raise ValueError('V7 explicitly selects its new natural template and independent reviewV2')
        values={field.name:6 if field.name=='version' else getattr(self,field.name) for field in fields(AdminModelWorkflowsV6)}
        # Pure structural view only; actual installed self/template/wire remain V7.
        values['natural_generation']=replace(generation,template_version=V6_TEMPLATE)
        AdminModelWorkflowsV6(**values)


def model_workflows_v7_from_payload(raw):
    allowed={field.name for field in fields(AdminModelWorkflowsV7)}
    required={'version','encode','reply','artifact_draft','d07_relationship_cognition','growth_cognition','natural_generation','natural_review'}
    if type(raw) is not dict or not required<=set(raw)<=allowed:
        raise ValueError('version7 workflow fields differ')
    values={name:model_workflow_v4_from_payload(item) for name,item in raw.items() if name!='version' and item is not None}
    return AdminModelWorkflowsV7(raw['version'],**values)


def is_installed_growth_cognition_slot_v3(bundle,workflow):
    from .authority_profile import AdminInstallationBundle
    return (type(bundle) is AdminInstallationBundle and type(bundle.model_workflows) is AdminModelWorkflowsV7
        and type(workflow) is AdminModelWorkflowV2 and workflow is bundle.model_workflows.growth_cognition)


def is_installed_relationship_cognition_slot_v3(bundle,workflow):
    from .authority_profile import AdminInstallationBundle
    return (type(bundle) is AdminInstallationBundle and type(bundle.model_workflows) is AdminModelWorkflowsV7
        and type(workflow) is AdminModelWorkflowV2 and workflow is bundle.model_workflows.d07_relationship_cognition)
