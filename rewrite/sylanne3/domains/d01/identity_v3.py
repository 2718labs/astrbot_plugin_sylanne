"""Versioned D01 semantic claims inside existing persona blocks; no identity store."""
from dataclasses import dataclass, fields
from decimal import Decimal
import json
import math
import re

from ...graph_types import AtomKey, GraphVersion
from ...runtime_contracts import NamespaceId, canonical_digest, canonical_serialize
from ...authority_service.v2_owner_contract import OwnerAuthorizationGuardV1

SEMANTIC_SCHEMA_V3 = "d01.semantic-identity-revision.v3"
MAX_IDENTITY_BYTES_V3 = 65536

def _text(value):
    if type(value) is not str or not value or len(value.encode("utf-8")) > MAX_IDENTITY_BYTES_V3:
        raise ValueError("bounded semantic identity text required")

def _refs(value):
    if type(value) is not tuple or len(value)>128 or len(set(value))!=len(value):
        raise ValueError("identity references must be a finite unique tuple")
    for ref in value: _text(ref)

def _digest(value):
    if type(value) is not str or not re.fullmatch(r"[0-9a-f]{64}",value):
        raise ValueError("identity requires an exact digest")

def _decimal(value):
    if type(value) is not str or not Decimal(value).is_finite() or str(Decimal(value))!=value:
        raise ValueError("identity role cursor must be a canonical decimal")
    return Decimal(value)

def _time_window(start,end):
    if (type(start) not in {int,float} or not math.isfinite(start)
            or end is not None and (type(end) not in {int,float} or not math.isfinite(end) or end<=start)):
        raise ValueError("identity validity requires its original finite window")

@dataclass(frozen=True,slots=True)
class RuntimeIdentityRef:
    namespace: NamespaceId
    authority_id: str
    installation_id: str
    schema: str = "d01.runtime-identity-ref.v3"
    def __post_init__(self):
        if self.schema!="d01.runtime-identity-ref.v3" or type(self.namespace) is not NamespaceId:
            raise ValueError("runtime identity requires actual namespace")
        _text(self.authority_id);_text(self.installation_id)

    @classmethod
    def from_owner_guard(cls,namespace,guard):
        if type(guard) is not OwnerAuthorizationGuardV1 or guard.namespace!=namespace or guard.pending_revoke_operation_id:
            raise ValueError("runtime identity requires the actual qualified Owner guard")
        return cls(namespace,guard.authority_id,guard.installation_id)

@dataclass(frozen=True,slots=True)
class SemanticIdentityRevisionRefV3:
    persona_head: str
    block_id: str
    revision: int
    payload_digest: str
    def __post_init__(self):
        _text(self.persona_head);_text(self.block_id);_digest(self.payload_digest)
        if type(self.revision) is not int or self.revision<1: raise ValueError("positive semantic revision required")

@dataclass(frozen=True,slots=True)
class SemanticIdentityRevision:
    runtime_identity: RuntimeIdentityRef
    block_id: str
    revision: int
    claim: str
    previous_revision: SemanticIdentityRevisionRefV3 | None
    legacy_origin: GraphVersion | None
    continuity_anchor: GraphVersion
    changed_from_claim_digest: str
    cumulative_diff: tuple[tuple[str,str], ...]
    plasticity_policy_ref: str | None
    plasticity_policy_digest: str | None
    support_original_refs: tuple[str, ...]
    counterevidence_original_ref: str | None
    continuity_original_ref: str | None
    trial_original_refs: tuple[str, ...]
    scope_refs: tuple[str, ...]
    exclusion_refs: tuple[str, ...]
    valid_from: float
    valid_until: float | None
    revision_kind: str
    adopt_before: float | None = None
    schema: str = SEMANTIC_SCHEMA_V3
    kind: str = "semantic_identity"
    def __post_init__(self):
        if self.schema!=SEMANTIC_SCHEMA_V3 or self.kind!="semantic_identity" or type(self.runtime_identity) is not RuntimeIdentityRef:
            raise ValueError("semantic identity versioned payload differs")
        _text(self.block_id);_text(self.claim);_digest(self.changed_from_claim_digest)
        if type(self.revision) is not int or self.revision<1 or type(self.continuity_anchor) is not GraphVersion:
            raise ValueError("semantic identity revision/anchor required")
        ns=self.runtime_identity.namespace
        for head in (self.legacy_origin,self.continuity_anchor):
            if head is not None and (type(head) is not GraphVersion or head.revision<1
                    or NamespaceId.from_key(head.key)!=ns or head.key.type_name not in {"d01.persona_plan.v1","d01.persona_revision.v1"}):
                raise ValueError("semantic identity history crossed persona or domain")
        if self.previous_revision is not None and (type(self.previous_revision) is not SemanticIdentityRevisionRefV3
                or self.previous_revision.block_id!=self.block_id or self.previous_revision.revision+1!=self.revision):
            raise ValueError("semantic predecessor differs")
        if type(self.cumulative_diff) is not tuple or len(self.cumulative_diff)>128:
            raise ValueError("semantic cumulative diff exceeds its bounded history")
        for index,pair in enumerate(self.cumulative_diff):
            if type(pair) is not tuple or len(pair)!=2: raise ValueError("semantic diff must retain old/new digests")
            _digest(pair[0]);_digest(pair[1])
            if pair[0]==pair[1] or index and self.cumulative_diff[index-1][1]!=pair[0]:
                raise ValueError("semantic diff must be a continuous actual change chain")
        for refs in (self.support_original_refs,self.trial_original_refs,self.scope_refs,self.exclusion_refs):_refs(refs)
        if len(self.trial_original_refs)>3:raise ValueError("deep identity permits at most three trials")
        if (self.plasticity_policy_ref is None)!=(self.plasticity_policy_digest is None):raise ValueError("semantic policy binding incomplete")
        if self.plasticity_policy_ref is not None:_text(self.plasticity_policy_ref);_digest(self.plasticity_policy_digest)
        _time_window(self.valid_from,self.valid_until)
        if self.adopt_before is not None:_time_window(self.valid_from,self.adopt_before)
        if self.revision_kind not in {"legacy_migration","growth","administrative"}:raise ValueError("semantic revision kind differs")
        if self.revision_kind=="legacy_migration":
            if (self.revision!=1 or self.previous_revision is not None or self.legacy_origin is None or self.cumulative_diff
                    or self.support_original_refs or self.trial_original_refs or self.counterevidence_original_ref is not None or self.continuity_original_ref is not None):
                raise ValueError("schema migration cannot invent growth or trial evidence")
        if self.revision_kind=="growth":
            if (self.previous_revision is None or self.plasticity_policy_ref is None or not self.support_original_refs
                    or not self.trial_original_refs or not self.counterevidence_original_ref or not self.continuity_original_ref
                    or self.adopt_before is None or not self.cumulative_diff
                    or self.cumulative_diff[-1]!=(self.changed_from_claim_digest,canonical_digest(self.claim))):
                raise ValueError("deep semantic growth must retain its full evidence and diff")

@dataclass(frozen=True,slots=True)
class IdentityPlasticityPolicyV3:
    namespace: NamespaceId
    policy_ref: str
    revision: int
    runtime_identity: RuntimeIdentityRef
    target_block_ids: tuple[str, ...]
    mode: str
    required_independent_families: int
    required_completed_trials: int
    maximum_trials: int
    observation_role_seconds: str
    maximum_revisions_since_continuity_anchor: int
    scope_refs: tuple[str, ...]
    exclusion_refs: tuple[str, ...]
    observer_policy_ref: str
    observer_policy_digest: str
    valid_from_utc: float
    valid_until_utc: float
    readout_valid_until_utc: float | None = None
    schema: str = "d01.identity-plasticity-policy.v3"
    def __post_init__(self):
        if self.schema!="d01.identity-plasticity-policy.v3" or type(self.namespace) is not NamespaceId or self.runtime_identity.namespace!=self.namespace:
            raise ValueError("exact identity plasticity policy namespace required")
        _text(self.policy_ref);_refs(self.target_block_ids);_refs(self.scope_refs);_refs(self.exclusion_refs)
        _text(self.observer_policy_ref);_digest(self.observer_policy_digest)
        if (not self.target_block_ids or not self.scope_refs or self.mode not in {"read_only","growth"}
                or type(self.revision) is not int or self.revision<1
                or type(self.required_independent_families) is not int or self.required_independent_families<2
                or type(self.required_completed_trials) is not int or type(self.maximum_trials) is not int
                or not 1<=self.required_completed_trials<=self.maximum_trials<=3
                or type(self.maximum_revisions_since_continuity_anchor) is not int or not 1<=self.maximum_revisions_since_continuity_anchor<=128
                or not 0<_decimal(self.observation_role_seconds)<=Decimal(1209600)):
            raise ValueError("Owner must explicitly bound deep growth, families, trials and cumulative revisions")
        _time_window(self.valid_from_utc,self.valid_until_utc)
        if self.readout_valid_until_utc is not None:_time_window(self.valid_from_utc,self.readout_valid_until_utc)

def identity_payload_v3(value):
    from .production_operations_v1 import plain_v1
    return plain_v1(value)

def encode_semantic_identity_v3(value):
    if type(value) is not SemanticIdentityRevision:raise TypeError("exact semantic identity revision required")
    encoded=canonical_serialize(identity_payload_v3(value))
    if len(encoded.encode("utf-8"))>MAX_IDENTITY_BYTES_V3:raise ValueError("semantic identity exceeds 65536 bytes")
    return encoded

def decode_semantic_identity_v3(claim):
    """Plain legacy text is read-only; a declared V3 schema never falls back."""
    if type(claim) is not str:raise TypeError("semantic claim must be text")
    if len(claim.encode("utf-8"))>MAX_IDENTITY_BYTES_V3:raise ValueError("semantic identity exceeds 65536 bytes")
    try:raw=json.loads(claim)
    except ValueError:
        if SEMANTIC_SCHEMA_V3 in claim:raise ValueError("declared semantic V3 JSON is malformed") from None
        return None
    if type(raw) is not dict or raw.get("schema")!=SEMANTIC_SCHEMA_V3:return None
    if canonical_serialize(raw)!=claim:raise ValueError("semantic V3 claim must retain canonical JSON")
    from ...runtime.domain_production_erasure_v1 import decode_typed_production_value_v1
    return decode_typed_production_value_v1(raw,SemanticIdentityRevision)

@dataclass(frozen=True,slots=True)
class SemanticIdentityProjectionV3:
    runtime_identity: RuntimeIdentityRef
    block_id: str
    claim: str | None
    semantic_revision: SemanticIdentityRevisionRefV3 | None
    plasticity_policy_ref: str | None
    scope_refs: tuple[str, ...]
    availability: str
    missing_inputs: tuple[str, ...]

@dataclass(frozen=True,slots=True)
class SelfModelProjectionV3:
    runtime_identity: RuntimeIdentityRef
    persona_head: str
    semantic_identities: tuple[SemanticIdentityProjectionV3, ...]
    read_versions: tuple[GraphVersion, ...]
    schema: str = "d01.self-model-projection.v3"


@dataclass(frozen=True,slots=True)
class IdentityTrialObservationPolicyV3:
    namespace: NamespaceId
    policy_ref: str
    revision: int
    runtime_identity: RuntimeIdentityRef
    scope_refs: tuple[str, ...]
    exclusion_refs: tuple[str, ...]
    valid_from_utc: float
    valid_until_utc: float
    schema: str = "d01.identity-trial-observation-policy.v3"
    observer_kind: str = "registered_growth_trial_outcomes_v3"
    allowed_outcome_types: tuple[str, ...] = ("d08.action_outcome.v1","d10.life_progress.v1")
    def __post_init__(self):
        if (self.schema!="d01.identity-trial-observation-policy.v3"
                or self.observer_kind!="registered_growth_trial_outcomes_v3"
                or self.allowed_outcome_types!=("d08.action_outcome.v1","d10.life_progress.v1")
                or type(self.runtime_identity) is not RuntimeIdentityRef
                or self.runtime_identity.namespace!=self.namespace
                or type(self.revision) is not int or self.revision<1):
            raise ValueError("explicit deep trial observer policy differs from fixed outcome contract")
        _text(self.policy_ref);_refs(self.scope_refs);_refs(self.exclusion_refs)
        if not self.scope_refs:raise ValueError("identity trial observation scope is explicit")
        _time_window(self.valid_from_utc,self.valid_until_utc)
