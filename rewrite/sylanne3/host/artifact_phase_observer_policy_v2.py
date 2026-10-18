"""Administrator-installed independent Artifact observation policy.

The protected asset declares a producer and a rubric, never expected answers.
Its installation identity does not replace any current Source, Owner or budget.
"""
from dataclasses import dataclass,fields
from hashlib import sha256
import json
from pathlib import Path

from ..runtime_contracts import canonical_digest,canonical_serialize

SCHEMA='sylanne.artifact-phase-observer-policy.v2'
INSTALLATION_SCHEMA='sylanne.artifact-phase-observer-installation.v2'
PRODUCER='d07.independent-artifact-observation.v1'
CALL_PLAN_SCHEMA='d11.foreground-call-plan.v3'
RUBRIC=('tone','task_semantics')
QUESTION_TEMPLATE='d07.artifact-phase-independent-question.v1'


def _sha(value):
    if type(value)is not str or len(value)!=64 or any(c not in '0123456789abcdef'for c in value):
        raise ValueError('independent observer requires exact SHA256 commitments')


@dataclass(frozen=True,slots=True)
class ArtifactPhaseObserverPolicyV2:
    observer_id:str
    observer_version:int
    asset_ref:str
    asset_digest:str
    workflow_digest:str
    condition_kinds:tuple[str,...]=RUBRIC
    producer:str=PRODUCER
    call_plan_schema:str=CALL_PLAN_SCHEMA
    question_template:str=QUESTION_TEMPLATE
    completion_mode:str='artifact_receipt_only'
    schema:str=SCHEMA

    def __post_init__(self):
        _sha(self.asset_digest);_sha(self.workflow_digest)
        if (self.schema!=SCHEMA or self.producer!=PRODUCER or self.call_plan_schema!=CALL_PLAN_SCHEMA
                or self.question_template!=QUESTION_TEMPLATE or self.completion_mode!='artifact_receipt_only' or self.condition_kinds!=RUBRIC
                or type(self.observer_id)is not str or not self.observer_id or len(self.observer_id)>1024
                or type(self.observer_version)is not int or self.observer_version<1
                or type(self.asset_ref)is not str or not Path(self.asset_ref).is_absolute()
                or '..'in Path(self.asset_ref).parts):
            raise ValueError('exact installed independent D07 observer policy required')

    @property
    def identity(self):
        return self.observer_id,self.observer_version,self.asset_digest


def artifact_phase_observer_from_asset_v2(*,asset_ref,asset_bytes,expected_digest):
    _sha(expected_digest)
    if type(asset_bytes)is not bytes or len(asset_bytes)>8192 or sha256(asset_bytes).hexdigest()!=expected_digest:
        raise ValueError('protected independent observer asset bytes differ')
    value=json.loads(asset_bytes)
    expected={f.name for f in fields(ArtifactPhaseObserverPolicyV2)}-{'asset_ref','asset_digest'}
    if type(value)is not dict or set(value)!=expected or canonical_serialize(value).encode()!=asset_bytes:
        raise ValueError('observer asset must be a closed rubric without per-content answers')
    if type(value['condition_kinds'])is not list:raise ValueError('observer rubric must be its registered ordered vocabulary')
    return ArtifactPhaseObserverPolicyV2(**{**value,'condition_kinds':tuple(value['condition_kinds']),
        'asset_ref':asset_ref,'asset_digest':expected_digest})


def load_artifact_phase_observer_policy_v2(payload):
    spec=payload.get('artifact_phase_observer')
    if spec is None:return None
    expected={'schema','observer_id','observer_version','asset_ref','asset_sha256'}
    if type(spec)is not dict or set(spec)!=expected or spec['schema']!=INSTALLATION_SCHEMA:
        raise ValueError('explicit independent observer V2 installation specification required')
    from ..authority_service.linux_installation_security_v1 import read_installed_bytes_v1
    asset=read_installed_bytes_v1(spec['asset_ref'],limit=8192)
    value=artifact_phase_observer_from_asset_v2(asset_ref=spec['asset_ref'],asset_bytes=asset,
        expected_digest=spec['asset_sha256'])
    if (value.observer_id,value.observer_version)!=(spec['observer_id'],spec['observer_version']):
        raise ValueError('protected observer identity differs from its installation declaration')
    return value


def require_current_artifact_phase_observer_v2(bundle):
    from .authority_profile import AdminInstallationBundle
    if type(bundle)is not AdminInstallationBundle or type(bundle.artifact_phase_observer)is not ArtifactPhaseObserverPolicyV2:
        from ..runtime.d01_production_operations_v1 import MissingProductionOriginalV1
        raise MissingProductionOriginalV1('explicit_installed_independent_artifact_observer')
    from ..authority_service.linux_installation_security_v1 import read_installed_bytes_v1
    installed=bundle.artifact_phase_observer
    current=artifact_phase_observer_from_asset_v2(asset_ref=installed.asset_ref,
        asset_bytes=read_installed_bytes_v1(installed.asset_ref,limit=8192),expected_digest=installed.asset_digest)
    if current!=installed:raise ValueError('independent observer protected asset changed')
    workflow=bundle.model_workflows.artifact_observation_cognition
    if workflow is None or canonical_digest(workflow)!=installed.workflow_digest:
        raise ValueError('independent observer differs from its exact installed named D07 workflow')
    return current
