"""Explicit administrator installation for the fixed Habit Core/Host protocol."""
from dataclasses import dataclass,fields,asdict
from ..runtime_contracts import NamespaceId,canonical_digest

@dataclass(frozen=True,slots=True)
class HabitRuntimePolicyV1:
    namespace:NamespaceId
    installation_id:str
    manifest_digest:str
    root_lease_id:str
    root_grant_id:str
    root_grant_version:int
    root_grant_digest:str
    version:int=1
    schema:str="d10.habit-runtime-policy.v1"
    def __post_init__(self):
        if(self.schema!="d10.habit-runtime-policy.v1"or self.version!=1 or type(self.namespace)is not NamespaceId
                or type(self.root_grant_version)is not int or self.root_grant_version<1
                or any(type(x)is not str or not x for x in(self.installation_id,self.manifest_digest,self.root_lease_id,self.root_grant_id))):
            raise ValueError("Habit runtime installation fields differ")
        if len(self.root_grant_digest)!=64 or any(c not in"0123456789abcdef"for c in self.root_grant_digest):
            raise ValueError("Habit installed typed Root commitment differs")
    def require_installation_v1(self,policy):
        if((self.namespace,self.installation_id,self.manifest_digest,self.root_lease_id,self.root_grant_id,self.root_grant_version,self.root_grant_digest)!=(
                policy.namespace,policy.installation_id,policy.manifest_digest,policy.root_lease.lease_id,policy.root_grant.grant_id,
                policy.root_grant.version,canonical_digest(policy.root_grant))
                or "habit_subscription_v1"not in policy.root_grant.allowed_work_kinds):
            raise ValueError("Habit explicit installation differs from original Root or Root lacks declared subscription kind")
        return self

def habit_runtime_policy_from_payload_v1(raw,installation):
    if raw is None:return None
    if type(raw)is not dict or set(raw)!={f.name for f in fields(HabitRuntimePolicyV1)}:
        raise ValueError("Habit installed runtime policy wire fields differ")
    value=HabitRuntimePolicyV1(**{**raw,"namespace":NamespaceId(**raw["namespace"])})
    return value.require_installation_v1(installation)

def habit_runtime_policy_to_wire_v1(value):
    if type(value)is not HabitRuntimePolicyV1:raise TypeError("exact installed Habit runtime policy required")
    return asdict(value)
