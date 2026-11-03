"""Finite Owner-approved literal scope and exact segment use of one commitment."""
from __future__ import annotations
from dataclasses import dataclass
import math

from ...graph_types import AtomKey, GraphVersion, Owner, TypeSpec
from ...runtime_contracts import NamespaceId, VersionedRef, canonical_digest, schema_hash
from ...runtime.domain_production_contracts_v1 import ProductionOwnerGuardV1

SCOPE_TYPE = "d08.commitment_communication_intent.v1"
USE_TYPE = "d08.commitment_promise_use.v1"
TERMS_SCOPE_TYPE = "d08.commitment_communication_intent.v2"
TERMS_USE_TYPE = "d08.commitment_promise_use.v2"
SCOPE_TYPES = frozenset({SCOPE_TYPE, TERMS_SCOPE_TYPE})
USE_TYPES = frozenset({USE_TYPE, TERMS_USE_TYPE})


@dataclass(frozen=True, slots=True)
class RegisterCurrentCommitmentCommunicationInputRequestV1:
    commitment: VersionedRef
    source_ref: str
    approved_literal: str
    valid_until_utc: float

    def __post_init__(self):
        if (type(self.commitment) is not VersionedRef
                or AtomKey.from_token(self.commitment.ref).type_name != "d08.commitment.v1"
                or self.commitment.version < 1
                or AtomKey.from_token(self.source_ref).type_name != "memory.source"
                or type(self.approved_literal) is not str
                or not 1 <= len(self.approved_literal) <= 2048
                or any(ord(char) < 32 and char not in "\n\t" for char in self.approved_literal)
                or type(self.valid_until_utc) not in (float, int)
                or not math.isfinite(self.valid_until_utc)):
            raise ValueError("Owner communication needs one exact commitment, live Source and bounded approved literal")


@dataclass(frozen=True, slots=True)
class CommitmentCommunicationIntentV1:
    namespace: NamespaceId
    scope_id: str
    commitment: GraphVersion
    commitment_digest: str
    terms_digest: str
    subject_ref: str
    target_ref: str
    source_refs: tuple[str, ...]
    platform_ref: str
    conversation_ref: str
    scene_ref: str
    approved_literal: str
    valid_until_utc: float
    approved_at_utc: float
    approval_operation_id: str
    approving_actor_ref: str
    owner_guard: ProductionOwnerGuardV1
    graph_incarnation: str
    activation_generation: int
    persona_head_id: str
    schema: str = SCOPE_TYPE

    def __post_init__(self):
        if (self.schema != (TERMS_SCOPE_TYPE if type(self) is CommitmentTermsCommunicationIntentV2 else SCOPE_TYPE) or type(self.namespace) is not NamespaceId
                or type(self.commitment) is not GraphVersion
                or self.commitment.key.type_name != "d08.commitment.v1"
                or NamespaceId.from_key(self.commitment.key) != self.namespace
                or self.commitment.revision < 1
                or self.subject_ref != "persona:" + self.namespace.persona_id
                or not self.target_ref.startswith("entity:")
                or type(self.source_refs) is not tuple or not self.source_refs or len(self.source_refs) > (32 if type(self) is CommitmentTermsCommunicationIntentV2 else 1)
                or type(self.owner_guard) is not ProductionOwnerGuardV1
                or type(self.activation_generation) is not int or self.activation_generation < 1
                or not self.approved_at_utc < self.valid_until_utc):
            raise ValueError("finite commitment scope identity differs")
        request = RegisterCurrentCommitmentCommunicationInputRequestV1(
            VersionedRef(self.commitment.key.token, self.commitment.revision),
            self.source_refs[0], self.approved_literal, self.valid_until_utc)
        if NamespaceId.from_key(AtomKey.from_token(request.source_ref)) != self.namespace:
            raise ValueError("communication Source crossed namespace")
        for value in (self.commitment_digest, self.terms_digest):
            if type(value) is not str or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
                raise ValueError("communication scope digest differs")
        for value in (self.scope_id, self.platform_ref, self.conversation_ref, self.scene_ref,
                self.approval_operation_id, self.approving_actor_ref, self.graph_incarnation, self.persona_head_id):
            if type(value) is not str or not value:
                raise ValueError("communication scope lost actual control or route")
        if type(self) is CommitmentCommunicationIntentV1 and self.scope_id != communication_scope_id_v1(self.namespace, request):
            raise ValueError("communication scope identity differs from its actual Owner operation")

    @property
    def digest(self):
        return canonical_digest(self)


@dataclass(frozen=True, slots=True)
class CommitmentPromiseUseV1:
    namespace: NamespaceId
    scope: GraphVersion
    scope_digest: str
    commitment: GraphVersion
    terms_digest: str
    operation_id: str
    action_id: str
    effect_id: str
    segment_id: str
    payload_digest: str
    literal_digest: str
    output_digest: str
    start: int
    end: int
    target_ref: str
    audience_ref: str
    source_refs: tuple[str, ...]
    schema: str = USE_TYPE

    def __post_init__(self):
        if (self.schema != (TERMS_USE_TYPE if type(self) is CommitmentTermsPromiseUseV2 else USE_TYPE) or type(self.namespace) is not NamespaceId
                or type(self.scope) is not GraphVersion or type(self.commitment) is not GraphVersion
                or self.scope.key.type_name != (TERMS_SCOPE_TYPE if type(self) is CommitmentTermsPromiseUseV2 else SCOPE_TYPE) or self.scope.revision != 1
                or self.commitment.key.type_name != "d08.commitment.v1" or self.commitment.revision < 1
                or any(NamespaceId.from_key(value.key) != self.namespace for value in (self.scope, self.commitment))
                or type(self.start) is not int or type(self.end) is not int
                or not 0 <= self.start < self.end <= 2048
                or type(self.source_refs) is not tuple or not self.source_refs or len(self.source_refs) > (32 if type(self) is CommitmentTermsPromiseUseV2 else 1)):
            raise ValueError("promise use lost its exact scope, commitment, segment or Source")
        for value in (self.scope_digest, self.terms_digest, self.payload_digest, self.literal_digest, self.output_digest):
            if type(value) is not str or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
                raise ValueError("promise use digest differs")
        for value in (self.operation_id, self.action_id, self.effect_id, self.segment_id, self.target_ref, self.audience_ref):
            if type(value) is not str or not value:
                raise ValueError("promise use requires its actual output and route identity")



@dataclass(frozen=True, slots=True, kw_only=True)
class CommitmentTermsCommunicationIntentV2(CommitmentCommunicationIntentV1):
    fulfillment_terms: GraphVersion
    fulfillment_terms_digest: str
    role: str
    route_source_ref: str
    terms_acceptance: GraphVersion | None
    policy_source_refs: tuple[str, ...]
    policy_audiences: tuple[str, ...]
    policy_read_versions: tuple[GraphVersion, ...]
    schema: str = TERMS_SCOPE_TYPE

    def __post_init__(self):
        CommitmentCommunicationIntentV1.__post_init__(self)
        from .commitment_fulfillment_v1 import TERMS_TYPE, ACCEPTANCE_TYPE, _version, _digest
        _version(self.fulfillment_terms,TERMS_TYPE,self.namespace)
        _digest(self.fulfillment_terms_digest)
        if self.terms_acceptance is not None:_version(self.terms_acceptance,ACCEPTANCE_TYPE,self.namespace)
        if (self.fulfillment_terms.revision != 1 or self.role not in {"offer","performance"}
                or self.route_source_ref not in self.source_refs or self.terms_digest != self.fulfillment_terms_digest
                or len(set(self.source_refs)) != len(self.source_refs)):
            raise ValueError("terms scope lost its exact original terms, role, route or complete roots")
        from .commitment_fulfillment_v1 import RegisterCurrentCommitmentTermsCommunicationInputRequestV1
        request = RegisterCurrentCommitmentTermsCommunicationInputRequestV1(
            VersionedRef(self.commitment.key.token,self.commitment.revision),
            VersionedRef(self.fulfillment_terms.key.token,self.fulfillment_terms.revision),
            self.route_source_ref,self.role,self.valid_until_utc)
        if self.scope_id != communication_scope_id_v1(self.namespace,request):
            raise ValueError("V2 scope differs from its exact structured Owner command")
        if (type(self.policy_source_refs)is not tuple or len(set(self.policy_source_refs))!=len(self.policy_source_refs)
                or type(self.policy_audiences)is not tuple or not self.policy_audiences
                or len(set(self.source_refs)|set(self.policy_source_refs))>32
                or any(type(ref)is not str or not ref for ref in self.policy_audiences)
                or any(AtomKey.from_token(ref).type_name!='memory.source' or NamespaceId.from_key(AtomKey.from_token(ref))!=self.namespace for ref in self.policy_source_refs)
                or type(self.policy_read_versions)is not tuple or len({v.key for v in self.policy_read_versions})!=len(self.policy_read_versions)
                or any(type(v)is not GraphVersion or v.revision<1 or NamespaceId.from_key(v.key)!=self.namespace
                    or v.key.type_name not in {'d03.entity_anchor','d03.account_binding','d03.role_binding','d05.boundary_rule'} for v in self.policy_read_versions)):
            raise ValueError('V2 scope lost its independently authorized policy context/selected versions')


@dataclass(frozen=True, slots=True, kw_only=True)
class CommitmentTermsPromiseUseV2(CommitmentPromiseUseV1):
    fulfillment_terms: GraphVersion
    role: str
    terms_acceptance: GraphVersion | None
    schema: str = TERMS_USE_TYPE

    def __post_init__(self):
        CommitmentPromiseUseV1.__post_init__(self)
        from .commitment_fulfillment_v1 import TERMS_TYPE, ACCEPTANCE_TYPE, _version
        _version(self.fulfillment_terms,TERMS_TYPE,self.namespace)
        if self.terms_acceptance is not None:_version(self.terms_acceptance,ACCEPTANCE_TYPE,self.namespace)
        if self.fulfillment_terms.revision != 1 or self.role not in {"offer","performance"}:
            raise ValueError("V2 promise use lost its exact immutable terms or communication role")


def decode_communication_scope_v1(raw):
    schema = raw.get("schema")
    cls = CommitmentTermsCommunicationIntentV2 if schema == TERMS_SCOPE_TYPE else CommitmentCommunicationIntentV1
    return decode_commitment_communication_v1(raw,cls)


def decode_communication_use_v1(raw):
    schema = raw.get("schema")
    cls = CommitmentTermsPromiseUseV2 if schema == TERMS_USE_TYPE else CommitmentPromiseUseV1
    return decode_commitment_communication_v1(raw,cls)


def communication_scope_request_v1(scope):
    if type(scope) is CommitmentTermsCommunicationIntentV2:
        from .commitment_fulfillment_v1 import RegisterCurrentCommitmentTermsCommunicationInputRequestV1
        return RegisterCurrentCommitmentTermsCommunicationInputRequestV1(
            VersionedRef(scope.commitment.key.token,scope.commitment.revision),
            VersionedRef(scope.fulfillment_terms.key.token,scope.fulfillment_terms.revision),
            scope.route_source_ref,scope.role,scope.valid_until_utc)
    if type(scope) is CommitmentCommunicationIntentV1:
        return RegisterCurrentCommitmentCommunicationInputRequestV1(
            VersionedRef(scope.commitment.key.token,scope.commitment.revision),scope.source_refs[0],scope.approved_literal,scope.valid_until_utc)
    raise TypeError("exact registered communication scope required")


def scope_route_source_v1(scope):
    if type(scope) is CommitmentTermsCommunicationIntentV2:return scope.route_source_ref
    if type(scope) is CommitmentCommunicationIntentV1:return scope.source_refs[0]
    raise TypeError("exact registered scope required")


def scope_use_dependencies_v1(scope_version,scope):
    dependencies=(scope_version.key,scope.commitment.key)
    if type(scope) is CommitmentTermsCommunicationIntentV2:
        dependencies+=(scope.fulfillment_terms.key,)
        if scope.terms_acceptance is not None:dependencies+=(scope.terms_acceptance.key,)
    return dependencies


def scope_terms_match_v1(scope,commitment):
    if type(scope) is CommitmentTermsCommunicationIntentV2:
        return scope.terms_digest==scope.fulfillment_terms_digest
    return type(scope) is CommitmentCommunicationIntentV1 and scope.terms_digest==commitment_terms_digest_v1(commitment)


def communication_scope_version_key_v1(scope):
    return AtomKey(Owner("persona",*scope.namespace.as_tuple),scope.schema,scope.scope_id)


def commitment_communication_effect_id_v1(scope_id):
    if type(scope_id) is not str or not scope_id.startswith("commitment-communication:"):
        raise ValueError("actual deterministic communication scope identity required")
    return "effect:commitment-literal:" + scope_id.split(":",1)[1]


def communication_scope_id_v1(namespace, request):
    return "commitment-communication:" + canonical_digest((namespace, request))[:48]


def communication_scope_key_v1(namespace, scope_id):
    return AtomKey(Owner("persona", *namespace.as_tuple), SCOPE_TYPE, scope_id)


def promise_use_key_v1(namespace, activity_id, use):
    return AtomKey(Owner("activity", *namespace.as_tuple, activity_id), use.schema,
        "promise-use:" + canonical_digest(use)[:48])


def commitment_terms_digest_v1(commitment):
    return canonical_digest((commitment.commitment_id, commitment.revision, commitment.subject_ref,
        commitment.counterparty_ref, commitment.semantic_scope, commitment.establishment_kind, commitment.deadline_ref))


def decode_commitment_communication_v1(raw, expected):
    from ...runtime.domain_production_erasure_v1 import decode_typed_production_value_v1
    return decode_typed_production_value_v1(raw, expected)


def communication_type_specs_v1():
    return tuple(TypeSpec(name, owners, "state", lambda raw, cls=cls: decode_commitment_communication_v1(raw, cls),
        immutable=True, writer_domain="d08", schema_version=2 if name in {TERMS_SCOPE_TYPE,TERMS_USE_TYPE}else 1,
        schema_hash=schema_hash({"type": name, "version": 2 if name in {TERMS_SCOPE_TYPE,TERMS_USE_TYPE}else 1}))
        for name, owners, cls in ((SCOPE_TYPE, ("persona",), CommitmentCommunicationIntentV1),
            (USE_TYPE, ("activity",), CommitmentPromiseUseV1),
            (TERMS_SCOPE_TYPE, ("persona",), CommitmentTermsCommunicationIntentV2),
            (TERMS_USE_TYPE, ("activity",), CommitmentTermsPromiseUseV2)))
