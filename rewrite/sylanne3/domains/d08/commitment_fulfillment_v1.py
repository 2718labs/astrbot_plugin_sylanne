"""Immutable original terms and objective evidence for explicitly bounded commitments."""
from dataclasses import dataclass
import math
from ...graph_types import AtomKey, GraphVersion, Owner, TypeSpec
from ...runtime_contracts import NamespaceId, VersionedRef, canonical_digest, schema_hash
from ...runtime.domain_production_contracts_v1 import ProductionOwnerGuardV1

TERMS_TYPE = "d08.commitment_fulfillment_terms.v1"
ACCEPTANCE_TYPE = "d08.commitment_terms_acceptance.v1"
EVIDENCE_TYPE = "d08.commitment_fulfillment_evidence.v1"
KINDS = frozenset({"communicated", "recipient_acknowledged"})
CREATE_OPERATION = "input:create_commitment_with_fulfillment_terms"
REGISTER_OPERATION = "input:register_commitment_terms_communication"
ACK_OPERATION = "acknowledge_commitment_terms"
SETTLE_OPERATION = "settle_current_commitment_fulfillment"
OPERATIONS = frozenset({CREATE_OPERATION, REGISTER_OPERATION, ACK_OPERATION, SETTLE_OPERATION})


def _digest(value):
    if type(value) is not str or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
        raise ValueError("exact canonical SHA-256 required")


def _version(value, kind, namespace=None):
    if type(value) not in (GraphVersion, VersionedRef):
        raise TypeError("exact versioned Graph reference required")
    key = value.key if type(value) is GraphVersion else AtomKey.from_token(value.ref)
    revision = value.revision if type(value) is GraphVersion else value.version
    if key.type_name != kind or revision < 1 or namespace is not None and NamespaceId.from_key(key) != namespace:
        raise ValueError("commitment terms reference changed its exact type/namespace/version")
    return key


def _request_versions_v1(current,terms):
    if type(current)is not VersionedRef or type(terms)is not VersionedRef:
        raise TypeError("request commitment/terms must be exact VersionedRef values")
    key=_version(current,"d08.commitment.v1")
    _version(terms,TERMS_TYPE,NamespaceId.from_key(key))
    if key.token!=current.ref or AtomKey.from_token(terms.ref).token!=terms.ref:
        raise ValueError("request references must use canonical actual Graph keys")
    return key


def terms_key_v1(namespace, commitment_id):
    return AtomKey(Owner("persona", *namespace.as_tuple), TERMS_TYPE, "commitment-terms:" + canonical_digest(commitment_id)[:48])


def acceptance_key_v1(namespace, commitment_id):
    return AtomKey(Owner("persona", *namespace.as_tuple), ACCEPTANCE_TYPE, "commitment-acceptance:" + canonical_digest(commitment_id)[:48])


def evidence_key_v1(namespace, commitment_id):
    return AtomKey(Owner("persona", *namespace.as_tuple), EVIDENCE_TYPE, "commitment-fulfillment:" + canonical_digest(commitment_id)[:48])


def semantic_scope_v1(kind, target, literal, deadline):
    if kind not in KINDS:
        raise ValueError("unregistered objective commitment fulfillment kind")
    obligation = "deliver exactly this text" if kind == "communicated" else "obtain the recipient's exact receipt confirmation for this text"
    return f"To {target}: {obligation}. Deadline UTC: {deadline if deadline is not None else 'none'}. Text:\n{literal}"


def render_terms_communication_v1(*, commitment_id, target, kind, literal, deadline, terms_digest, role, effect_id=None):
    _digest(terms_digest)
    if role == "offer":
        return ("SYLANNE-COMMITMENT/1 OFFER\n" + semantic_scope_v1(kind, target, literal, deadline)
            + f"\nCommitment: {commitment_id}\nTerms: {terms_digest}\nTo accept, reply exactly:\n"
            + f"SYLANNE-COMMITMENT/1 ACCEPT {commitment_id} {terms_digest}")
    if role == "performance":
        body=f"SYLANNE-COMMITMENT/1 PERFORMANCE {commitment_id} {terms_digest}\n{literal}"
        if kind=="recipient_acknowledged":
            if type(effect_id)is not str or not effect_id:raise ValueError("receipt-confirmation performance requires its actual deterministic effect")
            body+=f"\nEffect: {effect_id}\nTo confirm receipt, reply exactly:\nSYLANNE-COMMITMENT/1 RECEIVED {commitment_id} {terms_digest} {effect_id}"
        return body
    raise ValueError("unregistered commitment communication role")


def exact_terms_command_v1(text, *, verb, commitment_id, terms_digest, effect_id=None):
    expected = f"SYLANNE-COMMITMENT/1 {verb} {commitment_id} {terms_digest}"
    if verb == "RECEIVED":
        if type(effect_id) is not str or not effect_id:
            raise ValueError("receipt confirmation requires its actual performance effect")
        expected += " " + effect_id
    elif verb != "ACCEPT":
        raise ValueError("unregistered exact terms command")
    normalized = text.replace("\r\n", "\n") if type(text) is str else None
    return normalized in (expected, expected + "\n")


@dataclass(frozen=True, slots=True)
class CreateCurrentCommitmentWithFulfillmentTermsInputRequestV1:
    commitment_id: str
    counterparty_ref: str
    establishment_kind: str
    source_refs: tuple[str, ...]
    fulfillment_kind: str
    deliverable_literal: str
    deadline_utc: float | None

    def __post_init__(self):
        if (type(self.commitment_id) is not str or not self.commitment_id.startswith("commitment:")
                or type(self.counterparty_ref) is not str or not self.counterparty_ref.startswith("entity:")
                or self.establishment_kind not in {"unilateral", "bilateral"} or self.fulfillment_kind not in KINDS
                or type(self.source_refs) is not tuple or not 1 <= len(self.source_refs) <= 30 or len(set(self.source_refs)) != len(self.source_refs)
                or type(self.deliverable_literal) is not str or not 1 <= len(self.deliverable_literal) <= 2048
                or any(ord(c) < 32 and c not in "\n\t" for c in self.deliverable_literal)
                or self.deadline_utc is not None and (type(self.deadline_utc) not in (int,float) or not math.isfinite(self.deadline_utc))):
            raise ValueError("explicit objective commitment birth requires its exact bounded original terms")
        for ref in self.source_refs:
            key = AtomKey.from_token(ref)
            if key.type_name != "memory.source" or key.token != ref:
                raise ValueError("terms birth requires canonical actual Source references")
        if self.deadline_utc is not None:object.__setattr__(self,"deadline_utc",float(self.deadline_utc))
        from .commitment_communication_v1 import commitment_communication_effect_id_v1
        for role in ("offer", "performance"):
            rendered = render_terms_communication_v1(commitment_id=self.commitment_id, target=self.counterparty_ref,
                kind=self.fulfillment_kind, literal=self.deliverable_literal, deadline=self.deadline_utc,
                terms_digest="0" * 64, role=role,effect_id=commitment_communication_effect_id_v1("commitment-communication:"+"0"*48))
            if len(rendered) > 2048:
                raise ValueError("complete rendered offer/performance exceeds the existing 2048-character route")


@dataclass(frozen=True, slots=True)
class RegisterCurrentCommitmentTermsCommunicationInputRequestV1:
    current_commitment: VersionedRef
    terms: VersionedRef
    source_ref: str
    role: str
    valid_until_utc: float

    def __post_init__(self):
        _request_versions_v1(self.current_commitment,self.terms)
        if (self.terms.version != 1 or self.role not in {"offer","performance"}
                or AtomKey.from_token(self.source_ref).type_name != "memory.source"
                or type(self.valid_until_utc) not in (int,float) or not math.isfinite(self.valid_until_utc)):
            raise ValueError("terms communication requires its exact immutable terms, role and Source")
        object.__setattr__(self,"valid_until_utc",float(self.valid_until_utc))


@dataclass(frozen=True, slots=True)
class AcknowledgeCurrentCommitmentTermsRequestV1:
    current_commitment: VersionedRef
    terms: VersionedRef
    inbound_source_ref: str
    outbound_offer_receipt_ref: str

    def __post_init__(self):
        _request_versions_v1(self.current_commitment,self.terms)
        if self.terms.version != 1 or AtomKey.from_token(self.inbound_source_ref).type_name != "memory.source" or not self.outbound_offer_receipt_ref:
            raise ValueError("terms acceptance requires actual inbound Source and outbound offer evidence")


@dataclass(frozen=True, slots=True)
class SettleCurrentCommitmentFulfillmentRequestV1:
    current_commitment: VersionedRef
    terms: VersionedRef
    performance_outbound_receipt_ref: str
    recipient_ack_source_ref: str | None

    def __post_init__(self):
        _request_versions_v1(self.current_commitment,self.terms)
        if (self.terms.version != 1 or not self.performance_outbound_receipt_ref
                or self.recipient_ack_source_ref is not None and AtomKey.from_token(self.recipient_ack_source_ref).type_name != "memory.source"):
            raise ValueError("fulfillment requires actual performance observation and optional receipt-confirmation Source")


@dataclass(frozen=True, slots=True)
class CommitmentFulfillmentTermsV1:
    namespace: NamespaceId
    commitment: GraphVersion
    semantic_scope_digest: str
    fulfillment_kind: str
    deliverable_literal: str
    counterparty_ref: str
    deadline_utc: float | None
    source_refs: tuple[str, ...]
    source_versions: tuple[GraphVersion, ...]
    create_operation_id: str
    owner_guard: ProductionOwnerGuardV1
    persona_activation: GraphVersion
    persona_head: GraphVersion
    graph_incarnation: str
    activation_generation: int
    schema: str = TERMS_TYPE

    def __post_init__(self):
        key = _version(self.commitment, "d08.commitment.v1", self.namespace)
        if self.deadline_utc is not None:object.__setattr__(self,"deadline_utc",float(self.deadline_utc))
        if self.schema != TERMS_TYPE or self.commitment.revision != 1 or type(self.owner_guard) is not ProductionOwnerGuardV1:
            raise ValueError("immutable terms require their actual same-birth commitment and Owner")
        _digest(self.semantic_scope_digest)
        CreateCurrentCommitmentWithFulfillmentTermsInputRequestV1(key.name, self.counterparty_ref, "unilateral", self.source_refs,
            self.fulfillment_kind, self.deliverable_literal, self.deadline_utc)
        if (any(type(v) is not GraphVersion or v.revision < 1 or NamespaceId.from_key(v.key) != self.namespace
                or v.key.type_name not in {"memory.source","memory.access"} for v in self.source_versions)
                or not set(self.source_refs) <= {v.key.token for v in self.source_versions if v.key.type_name == "memory.source"}
                or len(set(v.key for v in self.source_versions)) != len(self.source_versions)
                or canonical_digest(semantic_scope_v1(self.fulfillment_kind,self.counterparty_ref,self.deliverable_literal,self.deadline_utc)) != self.semantic_scope_digest
                or not self.create_operation_id or not self.graph_incarnation or self.activation_generation < 1
                or any(type(v) is not GraphVersion or v.revision < 1 or NamespaceId.from_key(v.key) != self.namespace for v in (self.persona_activation,self.persona_head))):
            raise ValueError("terms lost actual Source/Access, persona or immutable semantic binding")

    @property
    def digest(self):
        return canonical_digest(self)

    @property
    def predicate(self):
        from .execution import GoalPredicate
        return GoalPredicate(self.fulfillment_kind,"d08.commitment_fulfillment.v1",
            (("commitment",self.commitment.key.token),("target",self.counterparty_ref),("literal_digest",canonical_digest(self.deliverable_literal))),
            0.0,self.deadline_utc)

    def render(self, role, *, effect_id=None):
        return render_terms_communication_v1(commitment_id=self.commitment.key.name,target=self.counterparty_ref,
            kind=self.fulfillment_kind,literal=self.deliverable_literal,deadline=self.deadline_utc,terms_digest=self.digest,role=role,effect_id=effect_id)


@dataclass(frozen=True, slots=True)
class CommitmentTermsAcceptanceV1:
    namespace: NamespaceId
    terms: GraphVersion
    terms_digest: str
    previous_commitment: GraphVersion
    resulting_commitment: GraphVersion
    inbound_source_ref: str
    inbound_versions: tuple[GraphVersion, ...]
    actor_ref: str
    conversation_ref: str
    offer_receipt_ref: str
    offer_effect_id: str
    offer_payload_digest: str
    operation_id: str
    schema: str = ACCEPTANCE_TYPE

    def __post_init__(self):
        _version(self.terms,TERMS_TYPE,self.namespace)
        for v in (self.previous_commitment,self.resulting_commitment):_version(v,"d08.commitment.v1",self.namespace)
        if (self.schema != ACCEPTANCE_TYPE or self.terms.revision != 1 or self.previous_commitment.key != self.resulting_commitment.key
                or self.resulting_commitment.revision != self.previous_commitment.revision + 1 or not self.inbound_versions or self.inbound_source_ref not in {v.key.token for v in self.inbound_versions if v.key.type_name == "memory.source"}
                or any(v.revision < 1 or NamespaceId.from_key(v.key) != self.namespace or v.key.type_name not in {"memory.source","memory.access"} for v in self.inbound_versions)
                or not all((self.actor_ref,self.conversation_ref,self.offer_receipt_ref,self.offer_effect_id,self.operation_id))):
            raise ValueError("terms acceptance lost actual inbound actor/Source/offer/current CAS")
        _digest(self.terms_digest);_digest(self.offer_payload_digest)


@dataclass(frozen=True, slots=True)
class CommitmentFulfillmentEvidenceV1:
    namespace: NamespaceId
    terms: GraphVersion
    terms_digest: str
    previous_commitment: GraphVersion
    resulting_commitment: GraphVersion
    performance_receipt_ref: str
    performance_observation_digest: str
    performance_admission_ref: str
    performance_admission_digest: str
    performance_action: GraphVersion
    performance_effect_id: str
    performance_payload_digest: str
    terms_acceptance: GraphVersion | None
    inbound_source_ref: str | None
    inbound_versions: tuple[GraphVersion, ...]
    actor_ref: str | None
    trusted_latest_utc: float
    operation_id: str
    schema: str = EVIDENCE_TYPE

    def __post_init__(self):
        _version(self.terms,TERMS_TYPE,self.namespace)
        _version(self.performance_action,"d08.action_intent.v1",self.namespace)
        for v in (self.previous_commitment,self.resulting_commitment):_version(v,"d08.commitment.v1",self.namespace)
        if self.terms_acceptance is not None:_version(self.terms_acceptance,ACCEPTANCE_TYPE,self.namespace)
        if (self.schema != EVIDENCE_TYPE or self.terms.revision != 1 or self.previous_commitment.key != self.resulting_commitment.key
                or self.resulting_commitment.revision != self.previous_commitment.revision + 1
                or type(self.trusted_latest_utc) not in (int,float) or not math.isfinite(self.trusted_latest_utc)
                or not all((self.performance_receipt_ref,self.performance_admission_ref,self.performance_effect_id,self.operation_id))):
            raise ValueError("fulfillment evidence lost its actual delivered effect, trusted bound or current CAS")
        if (type(self.inbound_versions)is not tuple or len({v.key for v in self.inbound_versions})!=len(self.inbound_versions)
                or any(type(v)is not GraphVersion or v.revision<1 or NamespaceId.from_key(v.key)!=self.namespace
                    or v.key.type_name not in {"memory.source","memory.access"} for v in self.inbound_versions)
                or (self.inbound_source_ref is None)!=(self.actor_ref is None)
                or self.inbound_source_ref is not None and self.inbound_source_ref not in {v.key.token for v in self.inbound_versions if v.key.type_name=="memory.source"}):
            raise ValueError("fulfillment receipt confirmation lost its exact actual inbound Source/Access/actor")
        for value in (self.terms_digest,self.performance_observation_digest,self.performance_admission_digest,self.performance_payload_digest):_digest(value)


def fulfillment_type_specs_v1():
    from ...runtime.domain_production_erasure_v1 import decode_typed_production_value_v1
    return tuple(TypeSpec(name,("persona",),"state",lambda raw,cls=cls:decode_typed_production_value_v1(raw,cls),
        immutable=True,writer_domain="d08",schema_hash=schema_hash({"type":name,"version":1}))
        for name,cls in ((TERMS_TYPE,CommitmentFulfillmentTermsV1),(ACCEPTANCE_TYPE,CommitmentTermsAcceptanceV1),(EVIDENCE_TYPE,CommitmentFulfillmentEvidenceV1)))
