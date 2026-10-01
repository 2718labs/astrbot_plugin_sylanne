"""D10 life scheduling and proactive-contact semantics.

All objects are pure candidates.  D10 can describe a clock, activity, or
contact policy; it cannot execute a step, send a platform message, or claim a
D08/D11 admission.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
import math
from typing import Callable

from ...runtime_contracts import (
    CommandEnvelope,
    DependencySet,
    DomainProposal,
    NamespaceId,
    ProviderDescriptor,
    QueryEpoch,
    RUNTIME_SCHEMA,
    schema_hash,
)
from ...graph_types import AtomKey, GraphSnapshot, GraphVersion, GraphWrite, Owner, TypeSpec, owner_grant_key
from ...memory_types import access_key
from ...runtime_contracts import CheckReceipt, VersionedRef
from ..d08.execution import ActionIntent
from .offline_interval import (
    OfflineIntervalReadSet, OfflineSimulationSliceCandidate,
    plan_offline_simulation_slice, OfflineTickRecipeV1,
    OfflineObservedTickV1, OfflineTickReadSetV1,
    OfflineSimulatedOccurrenceV1, OfflineTickAdvanceCandidateV1,
    advance_observed_offline_ticks_v1,
)


def _id(value: object, name: str) -> None:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} must be a nonempty string")


def _finite(value: object, name: str) -> float:
    if type(value) not in (int, float) or not math.isfinite(value):
        raise ValueError(f"{name} must be finite")
    return float(value)


def _exact_fields(value: object, fields: frozenset[str], label: str) -> dict:
    if type(value) is not dict or frozenset(value) != fields:
        raise ValueError(f"{label} fields must match its schema exactly")
    return value


@dataclass(frozen=True)
class D10TypeSpec:
    """D10 catalogue declaration convertible to the shared graph TypeSpec."""

    name: str
    writer_domain: str
    schema_hash: str
    owner_kinds: tuple[str, ...]
    storage_role: str
    validator: object

    def to_graph_spec(self) -> TypeSpec:
        return TypeSpec(
            self.name, self.owner_kinds, self.storage_role, self.validator,
            schema_version=1, writer_domain=self.writer_domain,
            schema_hash=self.schema_hash,
        )


@dataclass(frozen=True)
class LifeProject:
    project_id: str
    namespace: NamespaceId
    topic: str
    reality: str
    next_step: str

    def __post_init__(self) -> None:
        for name in ("project_id", "topic", "next_step"):
            _id(getattr(self, name), name)
        if not isinstance(self.namespace, NamespaceId):
            raise TypeError("namespace must be NamespaceId")
        if self.reality not in {"real_execution", "role_simulation", "planned"}:
            raise ValueError("unknown project reality")


@dataclass(frozen=True)
class ActivityRecipe:
    recipe_id: str
    version: int
    reality: str
    allowed_steps: tuple[str, ...]
    preemptible: bool

    def __post_init__(self) -> None:
        _id(self.recipe_id, "recipe_id")
        if type(self.version) is not int or self.version < 1:
            raise ValueError("recipe version must be a positive exact integer")
        if self.reality not in {"real_execution", "role_simulation"}:
            raise ValueError("recipe must declare executable reality")
        steps = tuple(self.allowed_steps)
        if not steps or len(set(steps)) != len(steps) or any(not isinstance(step, str) or not step for step in steps):
            raise ValueError("allowed_steps must be nonempty and unique")
        if type(self.preemptible) is not bool:
            raise TypeError("preemptible must be bool")
        object.__setattr__(self, "allowed_steps", steps)


@dataclass(frozen=True)
class ActivityOutcome:
    activity_id: str
    effect_id: str
    status: str
    artifact_ref: str | None
    receipt_refs: tuple[str, ...]

    def __post_init__(self) -> None:
        _id(self.activity_id, "activity_id")
        _id(self.effect_id, "effect_id")
        if self.status not in {"planned", "completed", "unknown", "failed"}:
            raise ValueError("unknown activity outcome status")
        if self.artifact_ref is not None:
            _id(self.artifact_ref, "artifact_ref")
        refs = tuple(self.receipt_refs)
        if len(set(refs)) != len(refs) or any(not isinstance(ref, str) or not ref for ref in refs):
            raise ValueError("receipt_refs must be unique valid strings")
        object.__setattr__(self, "receipt_refs", refs)


@dataclass(frozen=True)
class LifeProgress:
    project_id: str
    activity_id: str
    artifact_ref: str | None
    status: str = "adoptable_candidate"


@dataclass(frozen=True)
class CharacterClockMappingProposal:
    mapping_id: str
    namespace: NamespaceId
    version: int
    wall_origin_utc: float
    character_origin: float
    rate: float
    valid_interval: tuple[float, float]
    policy_ref: str
    execution_authorized: bool = False

    def __post_init__(self) -> None:
        _id(self.mapping_id, "mapping_id")
        _id(self.policy_ref, "policy_ref")
        if not isinstance(self.namespace, NamespaceId):
            raise TypeError("namespace must be NamespaceId")
        if type(self.version) is not int or self.version < 1:
            raise ValueError("mapping version must be a positive exact integer")
        _finite(self.wall_origin_utc, "wall_origin_utc")
        _finite(self.character_origin, "character_origin")
        rate = _finite(self.rate, "rate")
        if rate <= 0:
            raise ValueError("character clock rate must be positive")
        interval = tuple(self.valid_interval)
        if len(interval) != 2 or _finite(interval[0], "valid interval start") >= _finite(interval[1], "valid interval end"):
            raise ValueError("valid_interval must be an increasing pair")
        if self.execution_authorized:
            raise ValueError("D10 clock mapping is only a proposal; D11 signs execution mappings")
        object.__setattr__(self, "valid_interval", (float(interval[0]), float(interval[1])))

    def character_time(self, wall_utc: float) -> float:
        wall_utc = _finite(wall_utc, "wall_utc")
        if not self.valid_interval[0] <= wall_utc <= self.valid_interval[1]:
            raise ValueError("wall time is outside mapping validity")
        return self.character_origin + (wall_utc - self.wall_origin_utc) * self.rate


@dataclass(frozen=True)
class ProactiveOpportunity:
    opportunity_id: str
    namespace: NamespaceId
    source_ref: str
    subject_ref: str
    channel: str
    category: str
    opens_at: float
    expires_at: float

    def __post_init__(self) -> None:
        for name in ("opportunity_id", "source_ref", "subject_ref", "channel", "category"):
            _id(getattr(self, name), name)
        if not isinstance(self.namespace, NamespaceId):
            raise TypeError("namespace must be NamespaceId")
        if _finite(self.opens_at, "opens_at") >= _finite(self.expires_at, "expires_at"):
            raise ValueError("opportunity window must increase")


@dataclass(frozen=True)
class ContactPolicy:
    policy_id: str
    namespace: NamespaceId
    version: int
    subject_ref: str
    channel: str
    category: str
    consent: bool
    quiet: bool
    quota_limit: int
    window_start: float
    window_end: float

    def __post_init__(self) -> None:
        for name in ("policy_id", "subject_ref", "channel", "category"):
            _id(getattr(self, name), name)
        if not isinstance(self.namespace, NamespaceId):
            raise TypeError("namespace must be NamespaceId")
        if type(self.version) is not int or self.version < 1:
            raise ValueError("policy version must be a positive exact integer")
        if type(self.consent) is not bool or type(self.quiet) is not bool:
            raise TypeError("consent and quiet must be bool")
        if type(self.quota_limit) is not int or self.quota_limit < 0:
            raise ValueError("quota_limit must be nonnegative exact integer")
        if _finite(self.window_start, "window_start") >= _finite(self.window_end, "window_end"):
            raise ValueError("quota window must increase")


@dataclass(frozen=True)
class ContactPolicyCheck:
    policy_id: str
    subject_ref: str
    opportunity_id: str
    result: str
    reasons: tuple[str, ...]
    policy_version: int
    valid_until: float
    dispatch_authorized: bool = False


@dataclass(frozen=True)
class ContactPolicyReadSet:
    """Graph read including the scoped negative query for contact occupancy.

    The trusted graph integration must verify this read set is complete and
    current. Its fields alone cannot authorize a passing check.
    """

    namespace: NamespaceId
    query_epoch: QueryEpoch | None
    policy: ContactPolicy
    opportunity: ProactiveOpportunity
    claims: tuple[ContactClaim, ...]
    input_versions: tuple[VersionedRef, ...]
    coverage: str
    missing_items: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.namespace, NamespaceId):
            raise TypeError("namespace must be NamespaceId")
        if self.query_epoch is not None and not isinstance(self.query_epoch, QueryEpoch):
            raise TypeError("query_epoch must be QueryEpoch or None")
        if not isinstance(self.policy, ContactPolicy) or not isinstance(self.opportunity, ProactiveOpportunity):
            raise TypeError("policy and opportunity must be D10 values")
        if type(self.claims) is not tuple or any(not isinstance(item, ContactClaim) for item in self.claims):
            raise TypeError("claims must be a tuple of ContactClaim values")
        if type(self.input_versions) is not tuple or any(type(item) is not VersionedRef
                                                       for item in self.input_versions):
            raise TypeError("input_versions must be a tuple of VersionedRef values")
        if len({item.ref for item in self.input_versions}) != len(self.input_versions):
            raise ValueError("input_versions cannot repeat a ref")
        if self.coverage not in {"full", "partial", "none"}:
            raise ValueError("coverage must be full, partial, or none")
        if type(self.missing_items) is not tuple or any(type(item) is not str or not item
                                                        for item in self.missing_items):
            raise TypeError("missing_items must be a tuple of nonempty strings")


@dataclass(frozen=True)
class ContactClaim:
    contact_id: str
    communication_action_id: str
    subject_ref: str
    channel: str
    category: str
    segment_effects: tuple[str, ...]
    observations: tuple[tuple[str, str], ...]
    status: str
    policy_id: str
    policy_version: int

    def __post_init__(self) -> None:
        for name in ("contact_id", "communication_action_id", "subject_ref", "channel", "category", "policy_id"):
            _id(getattr(self, name), name)
        effects = tuple(self.segment_effects)
        if not effects or len(set(effects)) != len(effects) or any(not isinstance(value, str) or not value for value in effects):
            raise ValueError("segment_effects must be a finite nonempty unique list")
        observations = tuple(self.observations)
        if any(effect not in effects or observation not in {"not_handed_off", "handed_off", "unknown"}
               for effect, observation in observations):
            raise ValueError("invalid segment observation")
        if len({effect for effect, _ in observations}) != len(observations):
            raise ValueError("each segment has at most one observation")
        if self.status not in {"claimed", "pending_confirmation", "handed_off", "released"}:
            raise ValueError("unknown contact claim status")
        observed_statuses = {value for _, value in observations}
        if "unknown" in observed_statuses:
            expected = "pending_confirmation"
        elif "handed_off" in observed_statuses:
            expected = "handed_off"
        else:
            expected = "claimed"
        can_release = (len(observations) == len(effects)
                       and all(value == "not_handed_off" for _, value in observations))
        if self.status != expected and not (can_release and self.status == "released"):
            raise ValueError("contact status conflicts with segment observations")
        object.__setattr__(self, "segment_effects", effects)
        object.__setattr__(self, "observations", observations)


@dataclass(frozen=True)
class ContactContinuation:
    """One segment from the original, finite contact claim; never a new quota claim."""

    contact_id: str
    communication_action_id: str
    segment_effect_id: str

    def __post_init__(self) -> None:
        for name in ("contact_id", "communication_action_id", "segment_effect_id"):
            _id(getattr(self, name), name)


def contact_policy_key(namespace: NamespaceId, policy_id: str) -> AtomKey:
    _id(policy_id, "policy_id")
    return AtomKey(Owner("persona", *namespace.as_tuple), "d10.contact_policy.v1", policy_id)


def opportunity_key(namespace: NamespaceId, opportunity_id: str) -> AtomKey:
    _id(opportunity_id, "opportunity_id")
    return AtomKey(Owner("persona", *namespace.as_tuple), "d10.proactive_opportunity.v1", opportunity_id)


def decode_contact_policy(value: object, namespace: NamespaceId, *, enforce_namespace: bool = True) -> ContactPolicy:
    fields = frozenset({"policy_id", "version", "subject_ref", "channel", "category",
                        "consent", "quiet", "quota_limit", "window_start", "window_end",
                        "owner_grant_ref", "owner_grant_revision", "approval_ref",
                        "approval_authority_id", "installation_id"})
    data = _exact_fields(value, fields, "contact policy")
    grant = AtomKey.from_token(data["owner_grant_ref"])
    if (grant.type_name != "d11.owner_grant.v1" or grant.owner.kind != "persona"
            or grant.name != "primary"
            or enforce_namespace and grant != owner_grant_key(*namespace.as_tuple)):
        raise ValueError("policy must bind this namespace's Owner grant")
    if type(data["owner_grant_revision"]) is not int or data["owner_grant_revision"] < 1:
        raise ValueError("policy Owner grant revision is required")
    for field in ("approval_ref", "approval_authority_id", "installation_id"):
        _id(data[field], field)
    return ContactPolicy(data["policy_id"], namespace, *(data[field] for field in (
        "version", "subject_ref", "channel", "category", "consent", "quiet",
        "quota_limit", "window_start", "window_end")))


def decode_proactive_opportunity(value: object, namespace: NamespaceId, *, enforce_namespace: bool = True) -> ProactiveOpportunity:
    fields = frozenset({"opportunity_id", "source_ref", "source_revision", "access_revision",
                        "subject_ref", "channel", "category", "opens_at", "expires_at"})
    data = _exact_fields(value, fields, "proactive opportunity")
    source = AtomKey.from_token(data["source_ref"])
    if (source.owner.kind != "event" or source.type_name != "memory.source"
            or source.name != "record"
            or enforce_namespace and (source.owner.bot, source.owner.persona) != namespace.as_tuple):
        raise ValueError("opportunity must bind a D06 source in this namespace")
    for field in ("source_revision", "access_revision"):
        if type(data[field]) is not int or data[field] < 1:
            raise ValueError(f"{field} must be a positive exact integer")
    return ProactiveOpportunity(data["opportunity_id"], namespace, data["source_ref"],
                                *(data[field] for field in (
                                    "subject_ref", "channel", "category", "opens_at", "expires_at")))


def contact_policy_graph_write(
    policy: ContactPolicy, *, owner_grant_revision: int, approval_ref: str,
    approval_authority_id: str, installation_id: str,
) -> GraphWrite:
    """Candidate only: W01 must authenticate the Owner/installation approval."""
    grant = owner_grant_key(*policy.namespace.as_tuple)
    value = {field: getattr(policy, field) for field in (
        "policy_id", "version", "subject_ref", "channel", "category", "consent",
        "quiet", "quota_limit", "window_start", "window_end")}
    value.update(owner_grant_ref=grant.token, owner_grant_revision=owner_grant_revision,
                 approval_ref=approval_ref, approval_authority_id=approval_authority_id,
                 installation_id=installation_id)
    decode_contact_policy(value, policy.namespace)
    return GraphWrite(contact_policy_key(policy.namespace, policy.policy_id), value, (grant,))


def proactive_opportunity_graph_write(
    opportunity: ProactiveOpportunity, *, source_revision: int, access_revision: int,
) -> GraphWrite:
    """Candidate only: source and access heads require fenced W01 adoption."""
    source = AtomKey.from_token(opportunity.source_ref)
    access = access_key(*opportunity.namespace.as_tuple, source.owner.subject)
    value = {field: getattr(opportunity, field) for field in (
        "opportunity_id", "source_ref", "subject_ref", "channel", "category",
        "opens_at", "expires_at")}
    value.update(source_revision=source_revision, access_revision=access_revision)
    decode_proactive_opportunity(value, opportunity.namespace)
    return GraphWrite(opportunity_key(opportunity.namespace, opportunity.opportunity_id),
                      value, (source, access))


class LifeDomain:
    def __init__(self, *, contact_read_verifier: Callable[[ContactPolicyReadSet], bool] | None = None) -> None:
        if contact_read_verifier is not None and not callable(contact_read_verifier):
            raise TypeError("contact_read_verifier must be callable")
        self._contact_read_verifier = contact_read_verifier

    @property
    def descriptor(self) -> ProviderDescriptor:
        return ProviderDescriptor(
            provider_id="d10.life", contract_version=RUNTIME_SCHEMA,
            request_schema_hash=schema_hash({"domain": "d10", "proposal": 1}),
            response_schema_hash=schema_hash({"domain": "d10", "projection": 1}),
            owner_capabilities=("persona",), supported_modalities=("structured",),
            supported_purposes=("context", "expression", "consolidation", "audit"),
            supported_platforms=("runtime",), timeout_mode="bounded", cancellation_mode="cooperative",
            idempotency_mode="operation_id", cost_reporting_mode="d11_only", health_capabilities=("validate",),
            recovery_capabilities=("restore_contact_gate",),
        )

    def register_types(self) -> tuple[str, ...]:
        return tuple(spec.name for spec in self.type_specs())

    @staticmethod
    def type_specs() -> tuple[D10TypeSpec, ...]:
        def project(value: object) -> None:
            data = _exact_fields(value, frozenset({"project_id", "topic", "reality", "next_step"}), "life project")
            LifeProject(data["project_id"], NamespaceId("catalogue", "validation"), data["topic"], data["reality"], data["next_step"])

        def recipe(value: object) -> None:
            data = _exact_fields(value, frozenset({"recipe_id", "version", "reality", "allowed_steps", "preemptible"}), "activity recipe")
            ActivityRecipe(data["recipe_id"], data["version"], data["reality"], tuple(data["allowed_steps"]), data["preemptible"])

        def contact(value: object) -> None:
            data = _exact_fields(value, frozenset({"contact_id", "communication_action_id", "subject_ref", "channel", "category", "segment_effects", "observations", "status", "policy_id", "policy_version"}), "contact claim")
            ContactClaim(data["contact_id"], data["communication_action_id"], data["subject_ref"], data["channel"], data["category"], tuple(data["segment_effects"]), tuple(tuple(item) for item in data["observations"]), data["status"], data["policy_id"], data["policy_version"])

        validation_namespace = NamespaceId("catalogue", "validation")

        def policy(value: object) -> None:
            decode_contact_policy(value, validation_namespace, enforce_namespace=False)

        def opportunity(value: object) -> None:
            decode_proactive_opportunity(value, validation_namespace, enforce_namespace=False)

        from .production_operations_v1 import d10_production_type_specs_v1
        from .contact_claim_v2 import contact_claim_type_spec_v2
        return (
            D10TypeSpec("d10.life_project.v1", "d10", schema_hash({"d10.life_project.v1": 1}), ("persona",), "state", project),
            D10TypeSpec("d10.activity_recipe.v1", "d10", schema_hash({"d10.activity_recipe.v1": 1}), ("persona",), "state", recipe),
            D10TypeSpec("d10.contact_claim.v1", "d10", schema_hash({"d10.contact_claim.v1": 1}), ("persona",), "state", contact),
            D10TypeSpec("d10.contact_policy.v1", "d10", schema_hash({"d10.contact_policy.v1": 1}), ("persona",), "state", policy),
            D10TypeSpec("d10.proactive_opportunity.v1", "d10", schema_hash({"d10.proactive_opportunity.v1": 1}), ("persona",), "state", opportunity),
        ) + (contact_claim_type_spec_v2(),) + d10_production_type_specs_v1()

    def proposal_for(self, envelope: CommandEnvelope, contribution_keys: tuple[str, ...] = ()) -> DomainProposal:
        if not isinstance(envelope, CommandEnvelope):
            raise TypeError("envelope must be CommandEnvelope")
        return DomainProposal("d10", "d10.proposal.v1", schema_hash({"domain": "d10", "proposal": 1}),
                              envelope, (), DependencySet(), contribution_keys, ())

    @staticmethod
    def _guarded_version(envelope: CommandEnvelope, key: AtomKey) -> GraphVersion:
        matches = tuple(item for item in envelope.version_guard.read_versions if item.key == key)
        if len(matches) != 1:
            raise ValueError("D10 proposal requires exactly one guarded graph version per input")
        return matches[0]

    def contact_policy_proposal(
        self, envelope: CommandEnvelope, policy: ContactPolicy, *, approval_ref: str,
        approval_authority_id: str, installation_id: str,
    ) -> DomainProposal:
        """Owner-approved policy candidate; W01 still authenticates the approval."""
        if not isinstance(envelope, CommandEnvelope) or not isinstance(policy, ContactPolicy):
            raise TypeError("D10 policy proposal requires typed envelope and policy")
        if envelope.authority.namespace != policy.namespace:
            raise ValueError("policy and envelope namespace differ")
        grant = owner_grant_key(*policy.namespace.as_tuple)
        grant_version = self._guarded_version(envelope, grant)
        write = contact_policy_graph_write(
            policy, owner_grant_revision=grant_version.revision, approval_ref=approval_ref,
            approval_authority_id=approval_authority_id, installation_id=installation_id,
        )
        self._guarded_version(envelope, write.key)
        if (approval_ref not in envelope.input_refs
                or policy.policy_id not in envelope.input_refs):
            raise ValueError("policy revision or approval is not bound to the command")
        proposal = DomainProposal(
            "d10", "d10.proposal.v1", self.descriptor.request_schema_hash,
            envelope, (write,), DependencySet(current_invalidation=(grant_version,)), (), (),
        )
        return self.validate(proposal)

    def proactive_opportunity_proposal(
        self, envelope: CommandEnvelope, opportunity: ProactiveOpportunity,
    ) -> DomainProposal:
        """D06-source-derived opportunity candidate; W01 checks access/correction heads."""
        if not isinstance(envelope, CommandEnvelope) or not isinstance(opportunity, ProactiveOpportunity):
            raise TypeError("D10 opportunity proposal requires typed envelope and opportunity")
        if envelope.authority.namespace != opportunity.namespace:
            raise ValueError("opportunity and envelope namespace differ")
        source = AtomKey.from_token(opportunity.source_ref)
        if (source.owner.kind != "event" or source.type_name != "memory.source"
                or source.name != "record" or
                (source.owner.bot, source.owner.persona) != opportunity.namespace.as_tuple):
            raise ValueError("opportunity must bind a same-namespace D06 source")
        access = access_key(*opportunity.namespace.as_tuple, source.owner.subject)
        source_version = self._guarded_version(envelope, source)
        access_version = self._guarded_version(envelope, access)
        write = proactive_opportunity_graph_write(
            opportunity, source_revision=source_version.revision,
            access_revision=access_version.revision,
        )
        self._guarded_version(envelope, write.key)
        if (opportunity.source_ref not in envelope.input_refs
                or opportunity.source_ref not in envelope.source_qualification.source_refs
                or opportunity.opportunity_id not in envelope.input_refs):
            raise ValueError("opportunity source or ID is not bound to the command")
        proposal = DomainProposal(
            "d10", "d10.proposal.v1", self.descriptor.request_schema_hash,
            envelope, (write,), DependencySet(
                current_invalidation=(source_version, access_version),
                historical_provenance=(source_version,),
            ), (), (),
        )
        return self.validate(proposal)

    def validate(self, proposal: DomainProposal, snapshot: object = None) -> DomainProposal:
        if not isinstance(proposal, DomainProposal):
            raise TypeError("proposal must be DomainProposal")
        if proposal.domain != "d10" or proposal.proposal_schema != "d10.proposal.v1":
            raise ValueError("proposal is not a D10 proposal")
        if proposal.proposal_schema_hash != self.descriptor.request_schema_hash:
            raise ValueError("unrecognized D10 proposal schema")
        if snapshot is not None and not isinstance(snapshot, GraphSnapshot):
            raise TypeError("D10 snapshot must be GraphSnapshot")
        if not proposal.typed_writes:
            if proposal.dependencies != DependencySet():
                raise ValueError("empty D10 proposal cannot carry graph dependencies")
            return proposal
        if len(proposal.typed_writes) != 1 or proposal.contribution_keys or proposal.required_bundle_parts:
            raise ValueError("D10 contact proposal requires one typed write only")
        write = proposal.typed_writes[0]
        namespace = proposal.envelope.authority.namespace
        if write.key.owner != Owner("persona", *namespace.as_tuple):
            raise ValueError("D10 contact write owner differs from envelope")
        current = self._guarded_version(proposal.envelope, write.key)
        if snapshot is not None:
            atom = snapshot.get(write.key)
            if (atom.revision if atom is not None else 0) != current.revision:
                raise ValueError("D10 contact write guard differs from snapshot")
        if write.key.type_name == "d10.contact_policy.v1":
            policy = decode_contact_policy(write.value, namespace)
            grant = owner_grant_key(*namespace.as_tuple)
            grant_version = self._guarded_version(proposal.envelope, grant)
            if (write.key != contact_policy_key(namespace, policy.policy_id)
                    or write.value["owner_grant_revision"] != grant_version.revision
                    or write.dependencies != (grant,)
                    or proposal.dependencies != DependencySet(current_invalidation=(grant_version,))
                    or write.value["approval_ref"] not in proposal.envelope.input_refs
                    or policy.policy_id not in proposal.envelope.input_refs):
                raise ValueError("D10 policy write, approval, or guarded dependency differs")
            if snapshot is not None:
                if atom is not None and atom.valid and atom.value["version"] >= policy.version:
                    raise ValueError("contact policy must advance its actual business version")
                grant_atom = snapshot.get(grant)
                if grant_atom is None or not grant_atom.valid or grant_atom.revision != grant_version.revision:
                    raise ValueError("D10 policy Owner grant is absent from snapshot")
        elif write.key.type_name == "d10.proactive_opportunity.v1":
            opportunity = decode_proactive_opportunity(write.value, namespace)
            source = AtomKey.from_token(opportunity.source_ref)
            access = access_key(*namespace.as_tuple, source.owner.subject)
            source_version = self._guarded_version(proposal.envelope, source)
            access_version = self._guarded_version(proposal.envelope, access)
            if (write.key != opportunity_key(namespace, opportunity.opportunity_id)
                    or write.value["source_revision"] != source_version.revision
                    or write.value["access_revision"] != access_version.revision
                    or write.dependencies != (source, access)
                    or proposal.dependencies != DependencySet(
                        current_invalidation=(source_version, access_version),
                        historical_provenance=(source_version,))
                    or opportunity.source_ref not in proposal.envelope.input_refs
                    or opportunity.source_ref not in proposal.envelope.source_qualification.source_refs
                    or opportunity.opportunity_id not in proposal.envelope.input_refs):
                raise ValueError("D10 opportunity write or guarded D06 source differs")
            if snapshot is not None and any(
                (atom := snapshot.get(ref.key)) is None or not atom.valid
                or atom.revision != ref.revision for ref in (source_version, access_version)
            ):
                raise ValueError("D10 opportunity source or access absent from snapshot")
        else:
            raise ValueError("D10 proposal contains an unregistered contact write")
        return proposal

    @staticmethod
    def compile_scheme(draft: ActivityRecipe, snapshot: object = None) -> ActivityRecipe:
        if not isinstance(draft, ActivityRecipe):
            raise TypeError("draft must be ActivityRecipe")
        return draft

    @staticmethod
    def project(query: LifeProject, snapshot: object = None) -> LifeProject:
        if not isinstance(query, LifeProject):
            raise TypeError("query must be LifeProject")
        return query

    @staticmethod
    def adopt_life_progress(project: LifeProject, recipe: ActivityRecipe, outcome: ActivityOutcome) -> LifeProgress:
        if not all(isinstance(value, expected) for value, expected in ((project, LifeProject), (recipe, ActivityRecipe), (outcome, ActivityOutcome))):
            raise TypeError("project, recipe, and outcome must be D10 values")
        if outcome.status != "completed" or not outcome.receipt_refs:
            raise ValueError("planned, failed, or unknown activity cannot become life progress")
        return LifeProgress(project.project_id, outcome.activity_id, outcome.artifact_ref)

    @staticmethod
    def contact_policy_check(policy: ContactPolicy, opportunity: ProactiveOpportunity, claims: tuple[ContactClaim, ...], *, now: float,
                             continuation: ContactContinuation | None = None) -> ContactPolicyCheck:
        if policy.namespace != opportunity.namespace:
            raise ValueError("policy and opportunity namespace differ")
        now = _finite(now, "now")
        reasons: list[str] = []
        if policy.subject_ref != opportunity.subject_ref or policy.channel != opportunity.channel or policy.category != opportunity.category:
            reasons.append("policy_scope")
        if not policy.consent:
            reasons.append("consent")
        if policy.quiet:
            reasons.append("quiet_hours")
        if not policy.window_start <= now < policy.window_end or not opportunity.opens_at <= now < opportunity.expires_at:
            reasons.append("window")
        active = tuple(claims)
        if any(not isinstance(claim, ContactClaim) for claim in active):
            raise TypeError("claims must contain ContactClaim values")
        if continuation is not None and not isinstance(continuation, ContactContinuation):
            raise TypeError("continuation must be ContactContinuation or None")
        same_subject = [claim for claim in active if claim.subject_ref == opportunity.subject_ref and claim.channel == opportunity.channel and claim.category == opportunity.category]
        original: ContactClaim | None = None
        if continuation is not None:
            matches = [claim for claim in same_subject if claim.contact_id == continuation.contact_id
                       and claim.communication_action_id == continuation.communication_action_id
                       and claim.policy_id == policy.policy_id]
            if len(matches) != 1 or matches[0].status == "released":
                reasons.append("continuation_scope")
            else:
                original = matches[0]
                if continuation.segment_effect_id not in original.segment_effects:
                    reasons.append("segment_not_granted")
                elif continuation.segment_effect_id in dict(original.observations):
                    reasons.append("segment_already_observed")
                elif "unknown" in dict(original.observations).values():
                    reasons.append("prior_segment_unknown")
        other_claims = [claim for claim in same_subject if claim is not original]
        if any(claim.status in {"pending_confirmation", "handed_off"} for claim in other_claims):
            reasons.append("no_response_gate")
        from .contact_claim_v2 import ContactClaimV2, contact_window_id_v2
        window_id = contact_window_id_v2(policy)
        if any(type(claim) is ContactClaimV2 and claim.window_id != window_id
               and claim.status == "claimed"
               and not (len(claim.observations) == len(claim.segment_effects)
                        and all(value == "not_handed_off" for _, value in claim.observations))
               for claim in other_claims):
            reasons.append("unresolved_prior_window")
        occupied = [claim for claim in same_subject if claim.status != "released"
                    and (type(claim) is not ContactClaimV2 or claim.window_id == window_id)]
        if original is not None and (original.policy_version != policy.version
                or type(original) is ContactClaimV2 and original.window_id != window_id):
            reasons.append("continuation_policy_changed")
        # The existing contact owns one quota slot; it does not claim another.
        if len(occupied) + (0 if original is not None else 1) > policy.quota_limit:
            reasons.append("quota")
        return ContactPolicyCheck(policy.policy_id, policy.subject_ref, opportunity.opportunity_id,
                                  "pass" if not reasons else "fail", tuple(reasons), policy.version,
                                  min(policy.window_end, opportunity.expires_at))

    def contact_policy_required_check(
        self,
        intent: ActionIntent,
        policy: ContactPolicy,
        opportunity: ProactiveOpportunity,
        claims: tuple[ContactClaim, ...],
        *,
        coverage: str,
        input_versions: tuple[VersionedRef, ...],
        now: float,
        read_set: ContactPolicyReadSet | None = None,
        continuation: ContactContinuation | None = None,
    ) -> CheckReceipt:
        """Adapt a complete, current graph read into D08's proactive check.

        A trusted graph integration verifies the complete read set and its
        scoped negative query at this decision point. Caller coverage and
        versions alone cannot qualify a proactive action.
        """
        if not isinstance(intent, ActionIntent):
            raise TypeError("intent must be ActionIntent")
        if not isinstance(policy, ContactPolicy) or not isinstance(opportunity, ProactiveOpportunity):
            raise TypeError("policy and opportunity must be D10 values")
        if not isinstance(claims, tuple) or any(not isinstance(item, ContactClaim) for item in claims):
            raise TypeError("claims must be a complete tuple of ContactClaim values")
        if coverage not in {"full", "partial", "none"}:
            raise ValueError("coverage must be full, partial, or none")
        if not isinstance(input_versions, tuple) or any(not isinstance(item, VersionedRef) for item in input_versions):
            raise TypeError("input_versions must be a tuple of VersionedRef values")

        matches = tuple(spec for spec in intent.required_checks
                        if spec.check_kind == "contact_policy" and spec.provider_id == "d10.contact_policy")
        if len(matches) != 1:
            raise ValueError("intent must contain exactly one D10 contact_policy check")
        spec = matches[0]
        if spec.action_ref != intent.action_id:
            raise ValueError("contact_policy check must bind to this ActionIntent")

        epoch = read_set.query_epoch if read_set is not None else None
        scope_ref = (f"d10.contact_policy:{opportunity.subject_ref}:"
                     f"{opportunity.channel}:{opportunity.category}")
        expected_refs = {spec.criteria_version, policy.policy_id, opportunity.opportunity_id,
                         scope_ref, *(claim.contact_id for claim in claims)}
        versions = {item.ref: item.version for item in input_versions}
        exact_versions = (
            len(versions) == len(input_versions)
            and set(versions) == expected_refs
            and set(input_versions) == set(spec.required_input_versions)
            and versions.get(policy.policy_id) == policy.version
            and epoch is not None and versions.get(scope_ref) == epoch.revision
        )
        scope_matches = (
            policy.namespace == opportunity.namespace
            and read_set is not None and read_set.namespace == policy.namespace
            and epoch is not None and epoch.namespace == policy.namespace
            and epoch.scope_ref == scope_ref
            and policy.subject_ref == intent.target_ref == opportunity.subject_ref
            and spec.subject_ref == f"persona:{policy.namespace.persona_id}"
            and spec.purpose == intent.purpose
            and read_set.policy == policy and read_set.opportunity == opportunity
            and read_set.claims == claims
            and read_set.input_versions == input_versions
            and read_set.coverage == coverage
        )
        trusted_current = False
        if self._contact_read_verifier is not None and read_set is not None:
            try:
                trusted_current = self._contact_read_verifier(read_set) is True
            except Exception:
                trusted_current = False
        complete_current_read = (
            trusted_current and scope_matches and coverage == "full"
            and not read_set.missing_items and exact_versions
        )
        if not complete_current_read:
            return CheckReceipt(spec.check_kind, spec.subject_ref, spec.action_ref, spec.purpose,
                                input_versions, coverage, "unknown", _finite(now, "now"), spec.provider_id)

        check = self.contact_policy_check(policy, opportunity, claims, now=now,
                                          continuation=continuation)
        if policy.namespace != opportunity.namespace:
            raise ValueError("policy and opportunity namespace differ")
        result = "pass" if check.result == "pass" else "fail"
        return CheckReceipt(spec.check_kind, spec.subject_ref, spec.action_ref, spec.purpose,
                            input_versions, "full", result, check.valid_until, spec.provider_id)

    def claim_contact_window(self, policy: ContactPolicy, opportunity: ProactiveOpportunity, contact_id: str,
                             communication_action_id: str, segment_effects: tuple[str, ...], claims: tuple[ContactClaim, ...], *, now: float) -> ContactClaim:
        check = self.contact_policy_check(policy, opportunity, claims, now=now)
        if check.result != "pass":
            raise ValueError(f"contact policy did not pass: {', '.join(check.reasons)}")
        _id(contact_id, "contact_id")
        _id(communication_action_id, "communication_action_id")
        if any(claim.contact_id == contact_id or claim.communication_action_id == communication_action_id for claim in claims):
            raise ValueError("contact/action identity was already claimed")
        return ContactClaim(contact_id, communication_action_id, policy.subject_ref, policy.channel, policy.category,
                            tuple(segment_effects), (), "claimed", policy.policy_id, policy.version)

    @staticmethod
    def observe_segment(claim: ContactClaim, effect_id: str, observation: str) -> ContactClaim:
        if not isinstance(claim, ContactClaim):
            raise TypeError("claim must be ContactClaim")
        _id(effect_id, "effect_id")
        if effect_id not in claim.segment_effects or observation not in {"not_handed_off", "handed_off", "unknown"}:
            raise ValueError("invalid effect or observation")
        observations = dict(claim.observations)
        if effect_id in observations:
            if observations[effect_id] != observation:
                raise ValueError("segment observation conflicts with durable result")
            return claim
        observations[effect_id] = observation
        # A later segment proven not handed off cannot erase an earlier
        # external handoff or an unresolved segment from this contact.
        statuses = set(observations.values())
        status = ("pending_confirmation" if "unknown" in statuses else
                  "handed_off" if "handed_off" in statuses else "claimed")
        return replace(claim, observations=tuple(sorted(observations.items())), status=status)

    @staticmethod
    def release_contact(claim: ContactClaim) -> ContactClaim:
        if not isinstance(claim, ContactClaim):
            raise TypeError("claim must be ContactClaim")
        observed = dict(claim.observations)
        if len(observed) == len(claim.segment_effects) and all(value == "not_handed_off" for value in observed.values()):
            return replace(claim, status="released")
        return claim

    @staticmethod
    def invalidate(refs: tuple[object, ...]) -> tuple[object, ...]:
        return tuple(refs)

    @staticmethod
    def cleanup(plan: object) -> tuple[str, object]:
        return "deferred_to_runtime_deletion_coordinator", plan
