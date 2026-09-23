"""D10 life scheduling and proactive-contact semantics.

All objects are pure candidates.  D10 can describe a clock, activity, or
contact policy; it cannot execute a step, send a platform message, or claim a
D08/D11 admission.
"""

from dataclasses import dataclass, replace
import math

from ...runtime_contracts import (
    CommandEnvelope,
    DependencySet,
    DomainProposal,
    NamespaceId,
    ProviderDescriptor,
    RUNTIME_SCHEMA,
    schema_hash,
)
from ...graph_types import TypeSpec


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


class LifeDomain:
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

        return (
            D10TypeSpec("d10.life_project.v1", "d10", schema_hash({"d10.life_project.v1": 1}), ("persona",), "state", project),
            D10TypeSpec("d10.activity_recipe.v1", "d10", schema_hash({"d10.activity_recipe.v1": 1}), ("persona",), "state", recipe),
            D10TypeSpec("d10.contact_claim.v1", "d10", schema_hash({"d10.contact_claim.v1": 1}), ("persona",), "state", contact),
        )

    def proposal_for(self, envelope: CommandEnvelope, contribution_keys: tuple[str, ...] = ()) -> DomainProposal:
        if not isinstance(envelope, CommandEnvelope):
            raise TypeError("envelope must be CommandEnvelope")
        return DomainProposal("d10", "d10.proposal.v1", schema_hash({"domain": "d10", "proposal": 1}),
                              envelope, (), DependencySet(), contribution_keys, ())

    def validate(self, proposal: DomainProposal, snapshot: object = None) -> DomainProposal:
        if not isinstance(proposal, DomainProposal):
            raise TypeError("proposal must be DomainProposal")
        if proposal.domain != "d10" or proposal.proposal_schema != "d10.proposal.v1":
            raise ValueError("proposal is not a D10 proposal")
        if proposal.proposal_schema_hash != self.descriptor.request_schema_hash:
            raise ValueError("unrecognized D10 proposal schema")
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
    def contact_policy_check(policy: ContactPolicy, opportunity: ProactiveOpportunity, claims: tuple[ContactClaim, ...], *, now: float) -> ContactPolicyCheck:
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
        same_subject = [claim for claim in active if claim.subject_ref == opportunity.subject_ref and claim.channel == opportunity.channel and claim.category == opportunity.category]
        if any(claim.status in {"pending_confirmation", "handed_off"} for claim in same_subject):
            reasons.append("no_response_gate")
        occupied = [claim for claim in same_subject if claim.status != "released"]
        if len(occupied) >= policy.quota_limit:
            reasons.append("quota")
        return ContactPolicyCheck(policy.policy_id, policy.subject_ref, opportunity.opportunity_id,
                                  "pass" if not reasons else "fail", tuple(reasons), policy.version,
                                  min(policy.window_end, opportunity.expires_at))

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
