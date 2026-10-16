"""Core-owned Habit standing originals and current occurrence audit wires."""
from dataclasses import asdict,dataclass,fields
import math
from .v2_owner_contract import OwnerPrincipalV1
from ..runtime_contracts import NamespaceId,canonical_digest
from ..domains.d10.habit_policy_v1 import (HabitPolicyDefinitionV1,
    habit_policy_definition_to_wire_v1,habit_policy_definition_from_wire_v1)
from ..domains.d10.habit_occurrence_v1 import HabitOccurrenceSelectorV1,habit_value_to_wire_v1,habit_value_from_wire_v1
from ..graph_types import AtomKey,GraphVersion,Owner
from ..runtime.issuers import BudgetLeaseGrant

def _sha_v1(value):
    if type(value)is not str or len(value)!=64 or any(c not in "0123456789abcdef"for c in value):
        raise ValueError("Habit Core commitment requires exact SHA256")

@dataclass(frozen=True,slots=True)
class HabitStandingPolicyOriginalV1:
    authority_namespace:str
    authority_id:str
    installation_id:str
    namespace:NamespaceId
    definition:HabitPolicyDefinitionV1
    root_lease_id:str
    root_grant:BudgetLeaseGrant
    source_closure_versions:tuple[GraphVersion,...]
    target_commitment:str
    project_commitment:str
    owner_principal:OwnerPrincipalV1
    owner_actor_id:str
    owner_head_digest:str
    owner_authorization_revision:int
    owner_principal_epoch:int
    operation_id:str
    action:str
    issued_at_utc:float
    signature:str
    schema:str="d10.habit-standing-policy-original.v1"
    def __post_init__(self):
        if (self.schema!="d10.habit-standing-policy-original.v1"or type(self.namespace)is not NamespaceId
                or type(self.definition)is not HabitPolicyDefinitionV1 or type(self.root_grant)is not BudgetLeaseGrant
                or type(self.owner_principal)is not OwnerPrincipalV1 or self.definition.namespace!=self.namespace
                or self.root_lease_id!=self.definition.parent_root_grant_ref or self.root_grant.lease_id!=self.root_lease_id
                or (self.root_grant.bot_id,self.root_grant.persona_id)!=self.namespace.as_tuple
                or (self.root_grant.grant_id,self.root_grant.version,canonical_digest(self.root_grant))!=(
                    self.definition.parent_root_grant_id,self.definition.parent_root_grant_version,self.definition.parent_root_grant_digest)
                or self.action not in {"issue","revise","revoke"}or type(self.owner_authorization_revision)is not int
                or self.owner_authorization_revision<1 or type(self.owner_principal_epoch)is not int or self.owner_principal_epoch<0
                or type(self.issued_at_utc)not in(int,float)or not math.isfinite(self.issued_at_utc)
                or self.definition.original_valid_until_utc>self.root_grant.valid_until_utc):
            raise ValueError("Habit Core original differs from actual Definition/Owner/Root scope")
        if any(type(x)is not str or not x for x in(self.authority_namespace,self.authority_id,self.installation_id,
                self.owner_actor_id,self.owner_head_digest,self.operation_id)):
            raise ValueError("Habit Core original lacks actual issuer and Owner identity")
        if(type(self.source_closure_versions)is not tuple or not self.source_closure_versions
                or any(type(v)is not GraphVersion or v.revision<1 or v.key.type_name!="memory.source"
                    or NamespaceId.from_key(v.key)!=self.namespace for v in self.source_closure_versions)
                or tuple(v.key.token for v in self.source_closure_versions)!=tuple(sorted(set(v.key.token for v in self.source_closure_versions)))
                or not set(self.definition.source_refs)<=set(v.key.token for v in self.source_closure_versions)):
            raise ValueError("Habit standing original needs its complete actual same-namespace Source closure versions")
        for value in(self.target_commitment,self.project_commitment,self.signature):_sha_v1(value)
    @property
    def original_ref(self):
        return "habit-standing:"+canonical_digest((self.authority_namespace,self.installation_id,self.operation_id))
    @property
    def digest(self):return canonical_digest(self)

def habit_standing_policy_original_to_wire_v1(value):
    if type(value)is not HabitStandingPolicyOriginalV1:raise TypeError("exact Core Habit standing original required")
    return {**asdict(value),"definition":habit_policy_definition_to_wire_v1(value.definition)}

def habit_standing_policy_original_from_wire_v1(raw):
    if type(raw)is not dict or set(raw)!={f.name for f in fields(HabitStandingPolicyOriginalV1)}:
        raise ValueError("Core Habit standing original fields differ")
    return HabitStandingPolicyOriginalV1(**{**raw,"namespace":NamespaceId(**raw["namespace"]),
        "definition":habit_policy_definition_from_wire_v1(raw["definition"]),
        "source_closure_versions":tuple(_habit_graph_version_from_wire_v1(v)for v in raw["source_closure_versions"]),
        "root_grant":BudgetLeaseGrant(**{**raw["root_grant"],"allowed_work_kinds":tuple(raw["root_grant"]["allowed_work_kinds"])}),
        "owner_principal":OwnerPrincipalV1(**raw["owner_principal"])})

@dataclass(frozen=True,slots=True)
class HabitOccurrenceQualificationOriginalV1:
    authority_namespace:str
    authority_id:str
    installation_id:str
    namespace:NamespaceId
    selector:HabitOccurrenceSelectorV1
    standing_original_ref:str
    standing_original_digest:str
    target_commitment:str
    project_commitment:str
    effect_commitment:str
    owner_principal:OwnerPrincipalV1
    owner_head_digest:str
    owner_authorization_revision:int
    owner_principal_epoch:int
    self_entity_ref:str
    self_identity_original_ref:str
    occurrence_head:GraphVersion
    occurrence_digest:str
    read_versions:tuple[GraphVersion,...]
    window_census_digest:str
    counted_occurrence_refs:tuple[str,...]
    current_job_digest:str|None
    cancellation_generation:int
    original_deadline_utc:float
    issued_at_utc:float
    signature:str
    schema:str="d10.habit-occurrence-qualification-original.v1"
    def __post_init__(self):
        if (self.schema!="d10.habit-occurrence-qualification-original.v1"or type(self.namespace)is not NamespaceId
                or type(self.selector)is not HabitOccurrenceSelectorV1 or self.selector.namespace!=self.namespace
                or type(self.owner_principal)is not OwnerPrincipalV1 or type(self.occurrence_head)is not GraphVersion
                or NamespaceId.from_key(self.occurrence_head.key)!=self.namespace
                or type(self.read_versions)is not tuple or any(type(v)is not GraphVersion for v in self.read_versions)
                or len({v.key for v in self.read_versions})!=len(self.read_versions)
                or self.standing_original_ref!=self.selector.standing_authorization_original_ref
                or self.standing_original_digest!=self.selector.standing_authorization_original_digest
                or self.cancellation_generation!=self.selector.cancellation_generation
                or self.original_deadline_utc!=self.selector.original_deadline_utc
                or self.issued_at_utc>=self.original_deadline_utc
                or type(self.counted_occurrence_refs)is not tuple
                or tuple(sorted(set(self.counted_occurrence_refs)))!=self.counted_occurrence_refs):
            raise ValueError("Habit occurrence qualification lost actual selector/Owner/window/read scope")
        for value in(self.standing_original_digest,self.occurrence_digest,self.window_census_digest,self.target_commitment,self.project_commitment,self.effect_commitment,self.signature):
            _sha_v1(value)
        if self.current_job_digest is not None:_sha_v1(self.current_job_digest)
    @property
    def original_ref(self):
        return "habit-qualification:"+canonical_digest((self.authority_namespace,self.installation_id,
            self.selector.occurrence_original_ref,self.selector.operation_id,self.selector.request_digest))
    @property
    def digest(self):return canonical_digest(self)

def habit_occurrence_qualification_to_wire_v1(value):
    if type(value)is not HabitOccurrenceQualificationOriginalV1:raise TypeError("exact Core Habit occurrence original required")
    return {**asdict(value),"selector":habit_value_to_wire_v1(value.selector)}

def habit_occurrence_qualification_from_wire_v1(raw):
    if type(raw)is not dict or set(raw)!={f.name for f in fields(HabitOccurrenceQualificationOriginalV1)}:
        raise ValueError("Core Habit occurrence original fields differ")
    def version(value):return GraphVersion(AtomKey.from_token(value["key"])if type(value["key"])is str else
        AtomKey(**{**value["key"],"owner":Owner(**value["key"]["owner"])}),value["revision"])
    return HabitOccurrenceQualificationOriginalV1(**{**raw,"namespace":NamespaceId(**raw["namespace"]),
        "selector":habit_value_from_wire_v1("d10.habit-occurrence-selector.v1",raw["selector"]),
        "owner_principal":OwnerPrincipalV1(**raw["owner_principal"]),
        "occurrence_head":version(raw["occurrence_head"]),"read_versions":tuple(version(v)for v in raw["read_versions"]),
        "counted_occurrence_refs":tuple(raw["counted_occurrence_refs"])})

@dataclass(frozen=True,slots=True)
class HabitWindowCueSelectorV1:
    namespace:NamespaceId
    installation_id:str
    policy_ref:str
    policy_revision:int
    policy_digest:str
    standing_authorization_original_ref:str
    standing_authorization_original_digest:str
    subscription_job_ref:str
    subscription_job_revision:int
    expected_job_fence:int
    expected_job_cancel_epoch:int
    expected_lease_holder:str|None
    cancellation_generation:int
    window_id:str
    window_start_utc:float
    window_end_utc:float
    due_at_utc:float
    operation_id:str
    request_digest:str
    parent_root_grant_ref:str
    parent_root_grant_digest:str
    original_deadline_utc:float
    schema:str="d11.habit-window-cue-selector.v1"
    def __post_init__(self):
        if (self.schema!="d11.habit-window-cue-selector.v1"or type(self.namespace)is not NamespaceId
                or any(type(v)is not int or v<0 for v in(self.policy_revision,self.subscription_job_revision,self.expected_job_fence,self.expected_job_cancel_epoch,self.cancellation_generation))
                or self.policy_revision<1 or self.subscription_job_revision<1
                or not self.window_start_utc<=self.due_at_utc<self.window_end_utc
                or self.original_deadline_utc<=self.window_start_utc):
            raise ValueError("Habit timer selector needs exact existing subscription/policy/window")
        for ref,kind in ((self.policy_ref,"d10.habit_policy.v1"),(self.subscription_job_ref,"runtime.job")):
            key=AtomKey.from_token(ref)
            if NamespaceId.from_key(key)!=self.namespace or key.type_name!=kind:
                raise ValueError("Habit timer selector crossed actual namespace/type")
        for v in(self.policy_digest,self.standing_authorization_original_digest,self.request_digest,self.parent_root_grant_digest):_sha_v1(v)
        for v in(self.window_start_utc,self.window_end_utc,self.due_at_utc,self.original_deadline_utc):
            if type(v)not in(int,float)or not math.isfinite(v):raise ValueError("Habit timer retains finite original bounds")
        if any(type(v)is not str or not v for v in(self.installation_id,self.window_id,self.operation_id,
                self.standing_authorization_original_ref,self.parent_root_grant_ref)):
            raise ValueError("Habit timer selector lacks actual original identity")
    @property
    def cue_stable_key(self):
        return canonical_digest((self.namespace,AtomKey.from_token(self.policy_ref).name,self.window_id))
    @property
    def cue_original_ref(self):return "habit-window-cue:"+self.cue_stable_key

@dataclass(frozen=True,slots=True)
class HabitWindowCueOriginalV1:
    authority_namespace:str
    authority_id:str
    installation_id:str
    selector:HabitWindowCueSelectorV1
    target_commitment:str
    project_commitment:str
    owner_head_digest:str
    owner_authorization_revision:int
    owner_principal_epoch:int
    self_entity_ref:str
    read_versions:tuple[GraphVersion,...]
    clock_lower_utc:float
    clock_upper_utc:float
    execution_state:str
    signature:str
    schema:str="d11.habit-window-cue-original.v1"
    def __post_init__(self):
        if (self.schema!="d11.habit-window-cue-original.v1"or type(self.selector)is not HabitWindowCueSelectorV1
                or self.installation_id!=self.selector.installation_id or self.execution_state not in{"due","skipped","wait","reschedule-required"}
                or self.clock_lower_utc>self.clock_upper_utc or self.clock_lower_utc<self.selector.due_at_utc
                or self.clock_upper_utc>=self.selector.original_deadline_utc):
            raise ValueError("Habit time cue needs actual same-window trusted clock and original deadline")
        for value in(self.target_commitment,self.project_commitment,self.signature):_sha_v1(value)
    @property
    def original_ref(self):return self.selector.cue_original_ref
    @property
    def digest(self):return canonical_digest(self)

def habit_window_cue_selector_to_wire_v1(value):
    if type(value)is not HabitWindowCueSelectorV1:raise TypeError("exact Habit window cue selector required")
    return asdict(value)

def habit_window_cue_selector_from_wire_v1(raw):
    if type(raw)is not dict or set(raw)!={f.name for f in fields(HabitWindowCueSelectorV1)}:
        raise ValueError("Habit window cue selector fields differ")
    return HabitWindowCueSelectorV1(**{**raw,"namespace":NamespaceId(**raw["namespace"])})

def habit_window_cue_original_to_wire_v1(value):
    if type(value)is not HabitWindowCueOriginalV1:raise TypeError("exact Habit window cue original required")
    return {**asdict(value),"selector":habit_window_cue_selector_to_wire_v1(value.selector)}

def _habit_graph_version_from_wire_v1(raw):
    if type(raw)is not dict or set(raw)!={"key","revision"}:raise ValueError("Habit exact graph version fields differ")
    return GraphVersion(AtomKey(**{**raw["key"],"owner":Owner(**raw["key"]["owner"])}),raw["revision"])

def habit_window_cue_original_from_wire_v1(raw):
    if type(raw)is not dict or set(raw)!={f.name for f in fields(HabitWindowCueOriginalV1)}:
        raise ValueError("Habit window cue original fields differ")
    return HabitWindowCueOriginalV1(**{**raw,"selector":habit_window_cue_selector_from_wire_v1(raw["selector"]),
        "read_versions":tuple(_habit_graph_version_from_wire_v1(v)for v in raw["read_versions"])})


@dataclass(frozen=True,slots=True)
class HabitOccurrenceBirthSelectorV1:
    namespace:NamespaceId
    installation_id:str
    policy_ref:str
    policy_revision:int
    policy_digest:str
    standing_authorization_original_ref:str
    standing_authorization_original_digest:str
    cue_original_ref:str
    cue_original_digest:str
    cue_stable_key:str
    wake_original_ref:str|None
    wake_original_digest:str|None
    window_id:str
    window_start_utc:float
    window_end_utc:float
    operation_id:str
    request_digest:str
    parent_root_grant_ref:str
    parent_root_grant_digest:str
    original_deadline_utc:float
    cancellation_generation:int
    expected_occurrence_revision:int=0
    schema:str="d10.habit-occurrence-birth-selector.v1"
    def __post_init__(self):
        if(self.schema!="d10.habit-occurrence-birth-selector.v1"or type(self.namespace)is not NamespaceId
                or type(self.policy_revision)is not int or self.policy_revision<1 or self.expected_occurrence_revision!=0
                or type(self.cancellation_generation)is not int or self.cancellation_generation<0
                or AtomKey.from_token(self.policy_ref).type_name!="d10.habit_policy.v1"
                or NamespaceId.from_key(AtomKey.from_token(self.policy_ref))!=self.namespace
                or not self.window_start_utc<self.window_end_utc or self.original_deadline_utc<=self.window_start_utc
                or(self.wake_original_ref is None)!=(self.wake_original_digest is None)):
            raise ValueError("Habit registration selector requires actual already committed cue and absent occurrence")
        for value in(self.policy_digest,self.standing_authorization_original_digest,self.cue_original_digest,
                self.cue_stable_key,self.request_digest,self.parent_root_grant_digest):_sha_v1(value)
        if self.wake_original_digest is not None:_sha_v1(self.wake_original_digest)

def habit_occurrence_birth_to_wire_v1(value):
    if type(value)is not HabitOccurrenceBirthSelectorV1:raise TypeError("exact Habit birth selector required")
    return asdict(value)

def habit_occurrence_birth_from_wire_v1(raw):
    if type(raw)is not dict or set(raw)!={f.name for f in fields(HabitOccurrenceBirthSelectorV1)}:
        raise ValueError("Habit birth selector fields differ")
    return HabitOccurrenceBirthSelectorV1(**{**raw,"namespace":NamespaceId(**raw["namespace"])})


@dataclass(frozen=True,slots=True)
class HabitPolicyWindowCueInventoryV1:
    namespace:NamespaceId
    installation_id:str
    policy_ref:str
    definition_digest:str
    operation_id:str
    permit_token:str
    standing_original_ref:str
    standing_original_digest:str
    window_id:str
    window_start_utc:float
    window_end_utc:float
    core_cue_original_refs:tuple[str,...]
    core_cue_record_digests:tuple[str,...]
    core_cue_record_kinds:tuple[str,...]
    schema:str='d10.habit-policy-window-cue-inventory.v1'
    def __post_init__(self):
        key=AtomKey.from_token(self.policy_ref)
        if(self.schema!='d10.habit-policy-window-cue-inventory.v1'or type(self.namespace)is not NamespaceId
                or NamespaceId.from_key(key)!=self.namespace or key.type_name!='d10.habit_policy.v1'
                or not self.window_start_utc<self.window_end_utc
                or len(self.core_cue_original_refs)>1
                or not len(self.core_cue_original_refs)==len(self.core_cue_record_digests)==len(self.core_cue_record_kinds)
                or any(kind not in{'window_cue','cue_retired'}for kind in self.core_cue_record_kinds)):
            raise ValueError('Habit current-window immutable cue inventory lost actual exact shape')
        for value in(self.definition_digest,self.standing_original_digest,*self.core_cue_record_digests):_sha_v1(value)


def habit_policy_window_cue_inventory_from_wire_v1(raw):
    if type(raw)is not dict or set(raw)!={f.name for f in fields(HabitPolicyWindowCueInventoryV1)}:
        raise ValueError('Habit current-window cue inventory strict fields differ')
    return HabitPolicyWindowCueInventoryV1(**{**raw,'namespace':NamespaceId(**raw['namespace']),
        'core_cue_original_refs':tuple(raw['core_cue_original_refs']),
        'core_cue_record_digests':tuple(raw['core_cue_record_digests']),
        'core_cue_record_kinds':tuple(raw['core_cue_record_kinds'])})
