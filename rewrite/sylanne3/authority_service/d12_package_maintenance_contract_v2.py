"""Typed C11 compatible package-switch audit contracts.

Parsing or hashing these contracts does not authorize filesystem changes. The
protected supervisor must retrieve the accepted original from the actual
Authority service and prove its current admission before using a package CAS.
No path, shell command, credential secret, or manufactured shadow is accepted.
"""
from dataclasses import asdict,dataclass
import json
import re
from uuid import UUID
from ..runtime_contracts import canonical_digest,canonical_serialize

INTENT_SCHEMA='d12.compatible-package-switch-intent.v2'
STAGES=frozenset(('accepted','packages_verified','quiescing','retire_intent','retired',
    'backup_ready','compatible_no_data_migration','switch_intent','package_switched',
    'authority_start_intent','authority_bootstrap_ready','host_start_intent','bootstrap_ready','active',
    'rollback_retire_intent','rollback_retired','rollback_backup_ready','rollback_compatible_current_data','rollback_switch_intent',
    'rollback_package_switched','rollback_authority_start_intent','rollback_authority_bootstrap_ready','rollback_host_start_intent',
    'rollback_bootstrap_ready','rollback_complete','abort_intent','abort_retired',
    'abort_authority_start_intent','abort_authority_bootstrap_ready','abort_host_start_intent','abort_bootstrap_ready','abort_complete','failed','unknown'))


def _sha(value):
    if type(value) is not str or re.fullmatch('[0-9a-f]{64}',value) is None:raise ValueError('package maintenance digest must be exact SHA256')


def _identifier(value):
    if type(value) is not str or not value or len(value)>256 or any(ord(c)<32 for c in value):raise ValueError('bounded package maintenance identity required')


@dataclass(frozen=True,slots=True)
class D12PackageMaintenanceIntentV2:
    operation_id: str
    request_digest: str
    authority_id: str
    installation_id: str
    namespace_cohort: tuple[str,...]
    current_storage_identity_digest: str
    current_owner_heads_digest: str
    lifecycle_operation_id: str
    lifecycle_epoch: int
    old_package_id: str
    old_manifest_sha256: str
    old_cohort_ref: str
    old_cohort_digest: str
    expected_selection_revision: int
    expected_selection_digest: str
    expected_package_epoch: int
    candidate_package_id: str
    candidate_manifest_sha256: str
    candidate_cohort_ref: str
    candidate_cohort_digest: str
    compatibility_plan_digest: str
    managed_backup_ref: str
    supervisor_policy_digest: str
    accepted_original_ref: str
    accepted_original_digest: str
    mode: str = 'compatible_package_switch'
    schema: str = INTENT_SCHEMA

    def __post_init__(self):
        operation=UUID(self.operation_id)
        if str(operation)!=self.operation_id or operation.version!=4 or self.schema!=INTENT_SCHEMA or self.mode!='compatible_package_switch':raise ValueError('exact compatible-package operation required')
        for name in ('request_digest','current_storage_identity_digest','current_owner_heads_digest',
            'old_manifest_sha256','old_cohort_digest','expected_selection_digest','candidate_manifest_sha256','candidate_cohort_digest','compatibility_plan_digest',
            'supervisor_policy_digest','accepted_original_digest'):_sha(getattr(self,name))
        for name in ('authority_id','installation_id','lifecycle_operation_id','old_package_id','old_cohort_ref','candidate_package_id','candidate_cohort_ref','managed_backup_ref','accepted_original_ref'):_identifier(getattr(self,name))
        if (type(self.namespace_cohort) is not tuple or not self.namespace_cohort
                or tuple(sorted(set(self.namespace_cohort)))!=self.namespace_cohort):raise ValueError('exact sorted nonempty maintenance cohort required')
        for namespace in self.namespace_cohort:_identifier(namespace)
        for name in ('lifecycle_epoch','expected_selection_revision','expected_package_epoch'):
            if type(getattr(self,name)) is not int or getattr(self,name)<0:raise ValueError('exact package/lifecycle epoch required')
        if self.old_package_id==self.candidate_package_id or self.old_manifest_sha256==self.candidate_manifest_sha256:raise ValueError('package switch requires a distinct registered candidate')
        body=asdict(self);body.pop('accepted_original_digest')
        if canonical_digest(body)!=self.accepted_original_digest:raise ValueError('package accepted original commitment differs')
        ref_body=dict(body);ref_body.pop('accepted_original_ref')
        if self.accepted_original_ref!='d12-package-acceptance:'+canonical_digest(ref_body):raise ValueError('package accepted original address differs')

    @property
    def digest(self):return self.accepted_original_digest


def build_d12_package_intent_v2(**actual_facts):
    """Canonicalize already-observed facts; this function grants no authority."""
    body=dict(actual_facts,mode='compatible_package_switch',schema=INTENT_SCHEMA)
    body['accepted_original_ref']='d12-package-acceptance:'+canonical_digest(body)
    return D12PackageMaintenanceIntentV2(**body,accepted_original_digest=canonical_digest(body))


def package_intent_to_wire_v2(value):
    if type(value) is not D12PackageMaintenanceIntentV2:raise TypeError('typed package acceptance required')
    return json.loads(canonical_serialize(asdict(value)))


def package_intent_from_wire_v2(raw):
    if type(raw) is not dict or set(raw)!=set(D12PackageMaintenanceIntentV2.__dataclass_fields__):raise ValueError('package acceptance fields differ')
    value=dict(raw)
    if type(value['namespace_cohort']) is not list:raise ValueError('package namespace cohort wire differs')
    value['namespace_cohort']=tuple(value['namespace_cohort']);result=D12PackageMaintenanceIntentV2(**value)
    if package_intent_to_wire_v2(result)!=raw:raise ValueError('noncanonical package acceptance')
    return result


@dataclass(frozen=True,slots=True)
class D12PackageStageReceiptV2:
    operation_id: str
    accepted_original_digest: str
    stage: str
    stage_sequence: int
    prior_receipt_digest: str | None
    observation_refs: tuple[tuple[str,str],...]
    receipt_digest: str
    schema: str = 'd12.compatible-package-stage.v2'

    def __post_init__(self):
        _identifier(self.operation_id);_sha(self.accepted_original_digest);_sha(self.receipt_digest)
        if (self.schema!='d12.compatible-package-stage.v2' or self.stage not in STAGES
                or type(self.stage_sequence) is not int or self.stage_sequence<1
                or (self.stage_sequence==1)!=(self.prior_receipt_digest is None)
                or type(self.observation_refs) is not tuple or not self.observation_refs
                or tuple(sorted(set(self.observation_refs)))!=self.observation_refs):raise ValueError('package stage chain fields differ')
        if self.prior_receipt_digest is not None:_sha(self.prior_receipt_digest)
        for reference,commitment in self.observation_refs:_identifier(reference);_sha(commitment)
        body=asdict(self);body.pop('receipt_digest')
        if canonical_digest(body)!=self.receipt_digest:raise ValueError('package stage receipt commitment differs')
