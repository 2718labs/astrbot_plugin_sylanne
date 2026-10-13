"""Public, domain-neutral contracts for the Sylanne 3 alpha1 runtime.

These values describe candidates and receipts.  They do not authenticate a
caller or grant graph write authority; the runtime coordinator must resolve
opaque capability references and validate proposals at the commit boundary.
"""

from __future__ import annotations

from dataclasses import dataclass, fields, is_dataclass
from contextlib import contextmanager
from enum import Enum
import hashlib
import json
import math
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

from .authority_service.v2_contract import (
    AuthorityCurrentEffectSnapshotV2, FencePermitV2,
)
from .contracts import _CANONICAL_OUTPUT_METER, canonical_json
from .graph_types import AtomKey, GraphVersion, GraphWrite, NamespaceEpoch, Owner
from .runtime.restore_anchor import RestoreAnchor
from .runtime_journal import RecoveryConstraintFootprint

if TYPE_CHECKING:
    from .runtime.d04_joint_advance_v2 import ProductAdvanceEvidenceV2
    from .runtime.d04_root_adoption_contract_v2 import RootAdoptionEvidenceV2


RUNTIME_SCHEMA = "sylanne.runtime.v1"
AUTHORITY_BOOTSTRAP_SCHEMA_V2 = "sylanne3.authority.v2"
_HEX_DIGEST_LENGTH = 64
_OWNER_SCOPES = frozenset({"persona", "relation", "scene", "event", "activity"})
_SOURCE_FAMILIES = frozenset({"observed", "reported", "authored", "simulated", "derived"})
_CONTENT_REALITIES = frozenset({
    "external_observation", "external_report", "authored_content", "simulation", "inference", "unknown"
})
_EVIDENCE_ELIGIBILITY = frozenset({"eligible", "ineligible", "qualified"})
_ACTUALITY = frozenset({"actual", "not_actual", "unknown", "not_applicable"})
PERSISTENT_JOB_REF_KIND = "persistent_job"
_BUNDLE_PARTS = frozenset({
    "experience", "choice", "d02_settlement", "cost_settlement", PERSISTENT_JOB_REF_KIND, "outbox"
})


def _nonempty(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{label} must be a nonempty string")
    return value


def _exact_nonnegative(value: object, label: str) -> int:
    if type(value) is not int or value < 0:
        raise ValueError(f"{label} must be a nonnegative exact integer")
    return value


def _finite(value: object, label: str) -> float:
    if type(value) not in (int, float) or not math.isfinite(value):
        raise ValueError(f"{label} must be finite")
    return float(value)


def _digest(value: object, label: str) -> str:
    text = _nonempty(value, label)
    if len(text) != _HEX_DIGEST_LENGTH or any(ch not in "0123456789abcdef" for ch in text):
        raise ValueError(f"{label} must be a lowercase SHA-256 digest")
    return text


def _strings(values: object, label: str, *, allowed: frozenset[str] | None = None) -> tuple[str, ...]:
    if isinstance(values, str):
        raise TypeError(f"{label} must be a string collection, not a bare string")
    try:
        result = tuple(values)  # type: ignore[arg-type]
    except TypeError as exc:
        raise TypeError(f"{label} must be iterable") from exc
    for value in result:
        _nonempty(value, label)
        if allowed is not None and value not in allowed:
            raise ValueError(f"unknown {label}: {value!r}")
    if len(set(result)) != len(result):
        raise ValueError(f"{label} must be unique")
    return result


def _typed_tuple(values: object, expected: type, label: str) -> tuple:
    try:
        result = tuple(values)  # type: ignore[arg-type]
    except TypeError as exc:
        raise TypeError(f"{label} must be iterable") from exc
    if any(not isinstance(value, expected) for value in result):
        raise TypeError(f"{label} must contain {expected.__name__} values")
    fingerprints = tuple(canonical_serialize(value) for value in result)
    if len(set(fingerprints)) != len(fingerprints):
        raise ValueError(f"{label} must be unique")
    return result


def _canonical_value(value: object, active: set[int]) -> object:
    if value is None or type(value) in (str, bool, int):
        return value
    if type(value) is float:
        if not math.isfinite(value):
            raise ValueError("canonical numbers must be finite")
        return value
    if isinstance(value, Enum):
        return _canonical_value(value.value, active)
    if isinstance(value, AtomKey):
        return {"$type": "AtomKey", "token": value.token}
    if is_dataclass(value) and not isinstance(value, type):
        marker = id(value)
        if marker in active:
            raise ValueError("cyclic canonical value")
        active.add(marker)
        try:
            return {
                "$type": f"{type(value).__module__}.{type(value).__qualname__}",
                **{field.name: _canonical_value(getattr(value, field.name), active) for field in fields(value)},
            }
        finally:
            active.remove(marker)
    if type(value) in (list, tuple):
        marker = id(value)
        if marker in active:
            raise ValueError("cyclic canonical value")
        active.add(marker)
        try:
            return [_canonical_value(item, active) for item in value]
        finally:
            active.remove(marker)
    if type(value) is dict:
        marker = id(value)
        if marker in active:
            raise ValueError("cyclic canonical value")
        active.add(marker)
        try:
            result = {}
            for key, item in value.items():
                if not isinstance(key, str):
                    raise TypeError("canonical object keys must be strings")
                result[key] = _canonical_value(item, active)
            return result
        finally:
            active.remove(marker)
    raise TypeError(f"unsupported canonical value: {type(value).__name__}")




@contextmanager
def meter_canonical_outputs(meter):
    """Account real serializer outputs in the caller's existing reserved quantum."""
    token = _CANONICAL_OUTPUT_METER.set(meter)
    try:
        yield meter
    finally:
        _CANONICAL_OUTPUT_METER.reset(token)


def current_canonical_output_meter():
    return _CANONICAL_OUTPUT_METER.get()


def canonical_serialize(value: object) -> str:
    """Return stable UTF-8 JSON text for supported DTO and JSON values."""

    text = json.dumps(
        _canonical_value(value, set()), sort_keys=True, separators=(",", ":"),
        ensure_ascii=True, allow_nan=False,
    )
    meter = _CANONICAL_OUTPUT_METER.get()
    if meter is not None:
        meter.charge_encode(len(text))  # ensure_ascii makes characters == UTF-8 bytes.
    return text


def canonical_digest(value: object) -> str:
    return hashlib.sha256(canonical_serialize(value).encode("utf-8")).hexdigest()


def schema_hash(schema_descriptor: object) -> str:
    """Hash an explicit schema descriptor; the result is content-addressed."""

    return canonical_digest(schema_descriptor)


@dataclass(frozen=True)
class NamespaceId:
    bot_id: str
    persona_id: str

    def __post_init__(self) -> None:
        _nonempty(self.bot_id, "bot_id")
        _nonempty(self.persona_id, "persona_id")

    @property
    def as_tuple(self) -> tuple[str, str]:
        return self.bot_id, self.persona_id

    @classmethod
    def from_key(cls, key: AtomKey) -> "NamespaceId":
        if not isinstance(key, AtomKey):
            raise TypeError("key must be AtomKey")
        return cls(key.owner.bot, key.owner.persona)


def namespace_ref(namespace: NamespaceId) -> str:
    """Bounded content-free identity shared by independent authorities."""
    if not isinstance(namespace, NamespaceId):
        raise TypeError("namespace must be NamespaceId")
    return "ns:sha256:" + hashlib.sha256(
        canonical_json(list(namespace.as_tuple)).encode("utf-8")
    ).hexdigest()



class NamespaceRuntimeState(str, Enum):
    """Observed namespace availability; this is never a content permit."""

    UNBOUND = "unbound"
    RECOVERING = "recovering"
    ACTIVE = "active"
    UNAVAILABLE = "unavailable"
    QUARANTINED = "quarantined"


@dataclass(frozen=True, slots=True)
class InstallationGrantV2:
    """Installation identity facts for one authenticated TLS channel."""

    authority_id: str
    subject: str
    administrator_holder: str
    installation_id: str
    manifest_digest: str
    publisher_policy_ref: str
    service_capability_version: str
    channel_binding_sha256: str
    schema: str = AUTHORITY_BOOTSTRAP_SCHEMA_V2

    def __post_init__(self) -> None:
        if self.schema != AUTHORITY_BOOTSTRAP_SCHEMA_V2:
            raise ValueError("unknown authority bootstrap schema")
        for name in ("authority_id", "subject", "administrator_holder", "installation_id",
                     "publisher_policy_ref", "service_capability_version"):
            _nonempty(getattr(self, name), name)
        _digest(self.manifest_digest, "manifest_digest")
        _digest(self.channel_binding_sha256, "channel_binding_sha256")


@dataclass(frozen=True, slots=True)
class NamespaceBootstrapV2:
    """One namespace's observed activation and recovery facts, not authorization."""

    authority_id: str
    namespace: NamespaceId
    authority_namespace: str
    holder: str | None
    generation: int
    phase: str
    state: NamespaceRuntimeState
    anchor: RestoreAnchor | None
    blocking_reasons: tuple[str, ...]
    schema: str = AUTHORITY_BOOTSTRAP_SCHEMA_V2

    def __post_init__(self) -> None:
        if self.schema != AUTHORITY_BOOTSTRAP_SCHEMA_V2:
            raise ValueError("unknown authority bootstrap schema")
        _nonempty(self.authority_id, "authority_id")
        if type(self.namespace) is not NamespaceId:
            raise TypeError("namespace must be NamespaceId")
        _nonempty(self.authority_namespace, "authority_namespace")
        if self.holder is not None:
            _nonempty(self.holder, "holder")
        _exact_nonnegative(self.generation, "generation")
        if self.phase not in {"unbound", "active", "revoked", "recovering"}:
            raise ValueError(f"unknown activation phase: {self.phase!r}")
        if type(self.state) is not NamespaceRuntimeState:
            raise TypeError("state must be NamespaceRuntimeState")
        object.__setattr__(self, "blocking_reasons", _strings(self.blocking_reasons, "blocking_reasons"))
        if self.anchor is not None:
            if type(self.anchor) is not RestoreAnchor:
                raise TypeError("anchor must be RestoreAnchor")
            if (self.anchor.authority_id != self.authority_id
                    or self.anchor.namespace != self.authority_namespace
                    or self.anchor.activation_generation != self.generation):
                raise ValueError("anchor authority, namespace or generation mismatch")
            for journal in ("deletion", "execution"):
                _nonempty(getattr(self.anchor, f"{journal}_journal_id"), f"{journal}_journal_id")
                seq = _exact_nonnegative(getattr(self.anchor, f"{journal}_seq"), f"{journal}_seq")
                digest = getattr(self.anchor, f"{journal}_digest")
                if (seq == 0 and digest != "genesis") or (seq > 0 and
                                                          (not isinstance(digest, str) or
                                                           not digest.startswith("sha256:"))):
                    raise ValueError(f"invalid {journal} head")
                if seq > 0:
                    _digest(digest[7:], f"{journal}_digest")
            _exact_nonnegative(self.anchor.revocation_epoch, "revocation_epoch")
            _nonempty(self.anchor.proof, "proof")
        if self.state is NamespaceRuntimeState.ACTIVE:
            if (self.phase != "active" or self.holder is None or self.generation == 0
                    or self.anchor is None or self.blocking_reasons):
                raise ValueError("active namespace requires holder, generation, matching anchor and no blockers")
        elif self.state is NamespaceRuntimeState.UNBOUND:
            if self.phase != "unbound" or self.holder is not None or self.anchor is not None:
                raise ValueError("unbound namespace cannot have a holder or anchor")
        elif not self.blocking_reasons:
            raise ValueError("non-active bound state requires blocking reasons")


@dataclass(frozen=True, slots=True)
class SnapshotRequirementsV2:
    """Business snapshot comparison target, never a current Authority proof."""

    namespace: NamespaceId
    authority_id: str
    authority_namespace: str
    activation_generation: int
    deletion_journal_id: str
    deletion_seq: int
    deletion_digest: str
    execution_journal_id: str
    execution_seq: int
    execution_digest: str
    revocation_epoch: int
    graph_incarnation: str
    schema: str = AUTHORITY_BOOTSTRAP_SCHEMA_V2

    def __post_init__(self) -> None:
        if self.schema != AUTHORITY_BOOTSTRAP_SCHEMA_V2:
            raise ValueError("unknown authority bootstrap schema")
        if type(self.namespace) is not NamespaceId:
            raise TypeError("namespace must be NamespaceId")
        for name in ("authority_id", "authority_namespace", "graph_incarnation"):
            _nonempty(getattr(self, name), name)
        _exact_nonnegative(self.activation_generation, "activation_generation")
        _exact_nonnegative(self.revocation_epoch, "revocation_epoch")
        for journal in ("deletion", "execution"):
            _nonempty(getattr(self, f"{journal}_journal_id"), f"{journal}_journal_id")
            seq = _exact_nonnegative(getattr(self, f"{journal}_seq"), f"{journal}_seq")
            digest = getattr(self, f"{journal}_digest")
            if seq == 0:
                if digest != "genesis":
                    raise ValueError(f"invalid {journal} head")
            elif not isinstance(digest, str) or not digest.startswith("sha256:"):
                raise ValueError(f"invalid {journal} head")
            else:
                _digest(digest[7:], f"{journal}_digest")


@dataclass(frozen=True, slots=True)
class FenceScope:
    """One v2 permit pinned to a namespace and a graph admission stamp.

    The stamp is a comparison target for admission and commit, not proof that
    the permit remains live. Both boundaries must validate this same scope with
    the independent Authority and compare the current graph stamp.
    """

    namespace: NamespaceId
    authority_namespace: str
    generation: int
    operation: str
    operation_id: str
    permit: FencePermitV2
    pinned_anchor: RestoreAnchor
    graph_epoch: NamespaceEpoch
    graph_revision: int

    def __post_init__(self) -> None:
        if type(self.namespace) is not NamespaceId:
            raise TypeError("namespace must be NamespaceId")
        _nonempty(self.authority_namespace, "authority_namespace")
        _exact_nonnegative(self.generation, "generation")
        _nonempty(self.operation, "operation")
        _nonempty(self.operation_id, "operation_id")
        if type(self.permit) is not FencePermitV2:
            raise TypeError("permit must be FencePermitV2")
        if type(self.pinned_anchor) is not RestoreAnchor:
            raise TypeError("pinned_anchor must be RestoreAnchor")
        if (self.permit.namespace != self.authority_namespace
                or self.permit.generation != self.generation
                or self.permit.operation != self.operation
                or self.permit.operation_id != self.operation_id
                or self.permit.pinned_anchor != self.pinned_anchor):
            raise ValueError("scope does not match v2 permit")
        if type(self.graph_epoch) is not NamespaceEpoch:
            raise TypeError("graph_epoch must be NamespaceEpoch")
        if (self.graph_epoch.bot, self.graph_epoch.persona) != self.namespace.as_tuple:
            raise ValueError("graph epoch namespace mismatch")
        _exact_nonnegative(self.graph_revision, "graph_revision")


@runtime_checkable
class ContentFencePortV2(Protocol):
    """Authenticated adapter to the independent, durable v2 fence service.

    The adapter owns transport credentials; constructing a scope or satisfying
    this protocol structurally does not authenticate or activate a runtime.
    """

    def current_anchor(self, *, namespace: NamespaceId,
                       authority_namespace: str) -> RestoreAnchor: ...

    def begin_fence(self, *, namespace: NamespaceId, authority_namespace: str,
                    holder: str, generation: int, operation: str, operation_id: str,
                    expected_anchor: RestoreAnchor,
                    effect_id: str | None = None, command_digest: str | None = None,
                    footprint: RecoveryConstraintFootprint | None = None) -> FencePermitV2: ...

    def validate_fence(self, scope: FenceScope) -> FencePermitV2: ...

    def finish_fence(self, scope: FenceScope, *, request_id: str,
                     request_digest: str) -> None: ...


@runtime_checkable
class ContentEffectSnapshotPortV2(ContentFencePortV2, Protocol):
    """Optional K03 effect inventory read; the base fence port stays usable."""

    def read_current_effect_snapshot_for_write_fence(
        self, *, namespace: NamespaceId, authority_namespace: str,
        permit: FencePermitV2,
    ) -> AuthorityCurrentEffectSnapshotV2: ...


# GraphVersion is the canonical (AtomKey, revision) identity.  Re-exporting it
# avoids introducing a second atom reference type beside GraphStore.
AtomRef = GraphVersion


@dataclass(frozen=True)
class VersionedRef:
    ref: str
    version: int

    def __post_init__(self) -> None:
        _nonempty(self.ref, "ref")
        _exact_nonnegative(self.version, "version")


@dataclass(frozen=True)
class QueryEpoch:
    namespace: NamespaceId
    scope_ref: str
    revision: int

    def __post_init__(self) -> None:
        if not isinstance(self.namespace, NamespaceId):
            raise TypeError("namespace must be NamespaceId")
        _nonempty(self.scope_ref, "scope_ref")
        _exact_nonnegative(self.revision, "revision")


@dataclass(frozen=True)
class OperationIdentity:
    """Stable operation identity; canonical_input_digest covers input_refs only.

    Consumers must use ``DomainBundle.digest`` for same-operation conflict
    detection over the complete candidate bundle.
    """
    activity_id: str
    effect_id: str | None
    attempt_id: str
    phase: str
    operation_id: str
    canonical_input_digest: str

    def __post_init__(self) -> None:
        _nonempty(self.activity_id, "activity_id")
        if self.effect_id is not None:
            _nonempty(self.effect_id, "effect_id")
        _nonempty(self.attempt_id, "attempt_id")
        _nonempty(self.phase, "phase")
        _nonempty(self.operation_id, "operation_id")
        _digest(self.canonical_input_digest, "canonical_input_digest")


@dataclass(frozen=True)
class AuthorityContext:
    actor: str
    issuer_domain: str
    capability_ref: str
    namespace: NamespaceId
    owner_scope: tuple[str, ...]
    purpose: str
    audience: tuple[str, ...]
    provider_policy_ref: str
    activation_generation: int
    worker_fence: int | None = None

    def __post_init__(self) -> None:
        _nonempty(self.actor, "actor")
        _nonempty(self.issuer_domain, "issuer_domain")
        _nonempty(self.capability_ref, "capability_ref")
        if not isinstance(self.namespace, NamespaceId):
            raise TypeError("namespace must be NamespaceId")
        object.__setattr__(self, "owner_scope", _strings(self.owner_scope, "owner_scope", allowed=_OWNER_SCOPES))
        _nonempty(self.purpose, "purpose")
        object.__setattr__(self, "audience", _strings(self.audience, "audience"))
        _nonempty(self.provider_policy_ref, "provider_policy_ref")
        _exact_nonnegative(self.activation_generation, "activation_generation")
        if self.worker_fence is not None:
            _exact_nonnegative(self.worker_fence, "worker_fence")


@dataclass(frozen=True)
class VersionGuard:
    read_versions: tuple[GraphVersion, ...]
    query_epochs: tuple[QueryEpoch, ...]
    access_epoch: int
    delete_epoch: int
    catalogue_version: str
    scheme_version: str
    operator_version: str
    policy_version: str
    source_grant_refs: tuple[VersionedRef, ...]
    focus_lease_versions: tuple[VersionedRef, ...]
    resource_lease_versions: tuple[VersionedRef, ...]

    def __post_init__(self) -> None:
        reads = _typed_tuple(self.read_versions, GraphVersion, "read_versions")
        queries = _typed_tuple(self.query_epochs, QueryEpoch, "query_epochs")
        namespaces = {NamespaceId.from_key(item.key) for item in reads} | {item.namespace for item in queries}
        if len(namespaces) > 1:
            raise ValueError("version guard cannot span namespaces")
        object.__setattr__(self, "read_versions", reads)
        object.__setattr__(self, "query_epochs", queries)
        _exact_nonnegative(self.access_epoch, "access_epoch")
        _exact_nonnegative(self.delete_epoch, "delete_epoch")
        for name in ("catalogue_version", "scheme_version", "operator_version", "policy_version"):
            _nonempty(getattr(self, name), name)
        for name in ("source_grant_refs", "focus_lease_versions", "resource_lease_versions"):
            object.__setattr__(self, name, _typed_tuple(getattr(self, name), VersionedRef, name))

    @property
    def namespace(self) -> NamespaceId | None:
        if self.read_versions:
            return NamespaceId.from_key(self.read_versions[0].key)
        if self.query_epochs:
            return self.query_epochs[0].namespace
        return None


@dataclass(frozen=True)
class SourceQualification:
    source_refs: tuple[str, ...]
    source_family: str
    occurred_at: float | None
    learned_at: float
    content_reality: str
    evidence_eligibility: str
    subjective_confidence: float | None
    internal_activity_actuality: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "source_refs", _strings(self.source_refs, "source_refs"))
        if self.source_family not in _SOURCE_FAMILIES:
            raise ValueError(f"unknown source_family: {self.source_family!r}")
        if self.occurred_at is not None:
            object.__setattr__(self, "occurred_at", _finite(self.occurred_at, "occurred_at"))
        object.__setattr__(self, "learned_at", _finite(self.learned_at, "learned_at"))
        if self.content_reality not in _CONTENT_REALITIES:
            raise ValueError(f"unknown content_reality: {self.content_reality!r}")
        if self.evidence_eligibility not in _EVIDENCE_ELIGIBILITY:
            raise ValueError(f"unknown evidence_eligibility: {self.evidence_eligibility!r}")
        if self.subjective_confidence is not None:
            confidence = _finite(self.subjective_confidence, "subjective_confidence")
            if not 0.0 <= confidence <= 1.0:
                raise ValueError("subjective_confidence must be between 0 and 1")
            object.__setattr__(self, "subjective_confidence", confidence)
        if self.internal_activity_actuality not in _ACTUALITY:
            raise ValueError(f"unknown internal_activity_actuality: {self.internal_activity_actuality!r}")
        if self.source_family in {"authored", "simulated", "derived"}:
            if self.content_reality in {"external_observation", "external_report"}:
                raise ValueError("authored/simulated/derived sources cannot claim external reality")
            if self.evidence_eligibility != "ineligible":
                raise ValueError("authored/simulated/derived sources cannot qualify as external evidence")


@dataclass(frozen=True)
class DependencySet:
    current_invalidation: tuple[AtomRef, ...] = ()
    historical_provenance: tuple[AtomRef, ...] = ()
    associations: tuple[AtomRef, ...] = ()
    numeric_coupling: tuple[AtomRef, ...] = ()

    def __post_init__(self) -> None:
        for name in ("current_invalidation", "historical_provenance", "associations", "numeric_coupling"):
            object.__setattr__(self, name, _typed_tuple(getattr(self, name), GraphVersion, name))


@dataclass(frozen=True)
class CommandEnvelope:
    schema: str
    identity: OperationIdentity
    authority: AuthorityContext
    version_guard: VersionGuard
    source_qualification: SourceQualification
    input_refs: tuple[str, ...]
    parent_budget_lease_ref: str
    deadline_utc: float
    monotonic_deadline: float
    character_interval_ref: str
    causation: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.schema != RUNTIME_SCHEMA:
            raise ValueError(f"unknown runtime schema: {self.schema!r}")
        if not isinstance(self.identity, OperationIdentity):
            raise TypeError("identity must be OperationIdentity")
        if not isinstance(self.authority, AuthorityContext):
            raise TypeError("authority must be AuthorityContext")
        if not isinstance(self.version_guard, VersionGuard):
            raise TypeError("version_guard must be VersionGuard")
        if not isinstance(self.source_qualification, SourceQualification):
            raise TypeError("source_qualification must be SourceQualification")
        input_refs = _strings(self.input_refs, "input_refs")
        object.__setattr__(self, "input_refs", input_refs)
        expected_digest = canonical_digest({"input_refs": list(input_refs)})
        if self.identity.canonical_input_digest != expected_digest:
            raise ValueError("canonical_input_digest does not match input_refs")
        guard_namespace = self.version_guard.namespace
        if guard_namespace is not None and guard_namespace != self.authority.namespace:
            raise ValueError("version guard namespace differs from authority namespace")
        _nonempty(self.parent_budget_lease_ref, "parent_budget_lease_ref")
        object.__setattr__(self, "deadline_utc", _finite(self.deadline_utc, "deadline_utc"))
        object.__setattr__(self, "monotonic_deadline", _finite(self.monotonic_deadline, "monotonic_deadline"))
        _nonempty(self.character_interval_ref, "character_interval_ref")
        object.__setattr__(self, "causation", _strings(self.causation, "causation"))


@dataclass(frozen=True)
class DomainProposal:
    domain: str
    proposal_schema: str
    proposal_schema_hash: str
    envelope: CommandEnvelope
    typed_writes: tuple[GraphWrite, ...]
    dependencies: DependencySet
    contribution_keys: tuple[str, ...]
    required_bundle_parts: tuple[str, ...]

    def __post_init__(self) -> None:
        _nonempty(self.domain, "domain")
        _nonempty(self.proposal_schema, "proposal_schema")
        _digest(self.proposal_schema_hash, "proposal_schema_hash")
        if not isinstance(self.envelope, CommandEnvelope):
            raise TypeError("envelope must be CommandEnvelope")
        writes = _typed_tuple(self.typed_writes, GraphWrite, "typed_writes")
        if any(NamespaceId.from_key(write.key) != self.envelope.authority.namespace for write in writes):
            raise ValueError("proposal writes cannot cross namespace")
        from .graph_types import clone_graph_write_v3
        object.__setattr__(self, "typed_writes", tuple(clone_graph_write_v3(write) for write in writes))
        if not isinstance(self.dependencies, DependencySet):
            raise TypeError("dependencies must be DependencySet")
        refs = (self.dependencies.current_invalidation + self.dependencies.historical_provenance
                + self.dependencies.associations + self.dependencies.numeric_coupling)
        if any(NamespaceId.from_key(ref.key) != self.envelope.authority.namespace for ref in refs):
            raise ValueError("proposal dependencies cannot cross namespace")
        object.__setattr__(self, "contribution_keys", _strings(self.contribution_keys, "contribution_keys"))
        object.__setattr__(self, "required_bundle_parts",
                           _strings(self.required_bundle_parts, "required_bundle_parts", allowed=_BUNDLE_PARTS))


@dataclass(frozen=True)
class ProductAdvanceEvidenceV1:
    """Candidate-bound numeric evidence; the coordinator must verify its issuer."""

    schema: str
    feeling_ref: str
    mood_ref: str
    parent_operation_id: str
    replay_key: str
    from_cursor: float
    to_cursor: float
    candidate_digest: str
    numeric_input_digest: str
    numeric_output_digest: str
    native_manifest_sha256: str
    native_sha256: str
    previous_error_bound: float
    next_error_bound: float

    def __post_init__(self) -> None:
        if self.schema != "d11.product_advance_candidate.v1":
            raise ValueError("unknown product advance candidate schema")
        for name, type_name in (("feeling_ref", "d04.feeling_state.v1"),
                                ("mood_ref", "d04.mood_field.v1")):
            key = AtomKey.from_token(_nonempty(getattr(self, name), name))
            if key.type_name != type_name:
                raise ValueError(f"{name} has the wrong D04 graph type")
        for name in ("parent_operation_id", "replay_key"):
            _nonempty(getattr(self, name), name)
        for name in ("candidate_digest", "numeric_input_digest",
                     "numeric_output_digest", "native_manifest_sha256", "native_sha256"):
            _digest(getattr(self, name), name)
        for name in ("from_cursor", "to_cursor", "previous_error_bound", "next_error_bound"):
            object.__setattr__(self, name, _finite(getattr(self, name), name))
        if (self.to_cursor <= self.from_cursor or self.previous_error_bound < 0
                or self.next_error_bound < 0):
            raise ValueError("product advance interval and error bounds must be positive")


@dataclass(frozen=True)
class DomainBundle:
    """Complete candidate bundle; construction does not confer validation authority."""
    envelope: CommandEnvelope
    proposals: tuple[DomainProposal, ...]
    experience_refs: tuple[str, ...]
    choice_refs: tuple[str, ...]
    d02_settlement_refs: tuple[str, ...]
    d11_cost_settlement_refs: tuple[str, ...]
    idempotency_keys: tuple[str, ...]
    persistent_job_refs: tuple[str, ...]
    outbox_refs: tuple[str, ...]
    product_advance: ProductAdvanceEvidenceV1 | ProductAdvanceEvidenceV2 | None = None
    root_adoption: RootAdoptionEvidenceV2 | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.envelope, CommandEnvelope):
            raise TypeError("envelope must be CommandEnvelope")
        if self.product_advance is not None:
            from .runtime.d04_joint_advance_v2 import ProductAdvanceEvidenceV2

            if type(self.product_advance) is ProductAdvanceEvidenceV2:
                if (self.product_advance.namespace != self.envelope.authority.namespace
                        or self.product_advance.operation_id
                           != self.envelope.identity.operation_id):
                    raise ValueError("joint product evidence must match bundle scope and operation")
            elif not isinstance(self.product_advance, ProductAdvanceEvidenceV1):
                raise TypeError("product_advance must be typed product evidence")
        if self.root_adoption is not None:
            from .runtime.d04_root_adoption_contract_v2 import RootAdoptionEvidenceV2

            if type(self.root_adoption) is not RootAdoptionEvidenceV2:
                raise TypeError("root_adoption must be typed root evidence")
            if self.product_advance is not None:
                raise ValueError("root adoption cannot also advance a product")
            if (self.root_adoption.namespace != self.envelope.authority.namespace
                    or self.root_adoption.operation_id != self.envelope.identity.operation_id
                    or self.root_adoption.phase != self.envelope.identity.phase
                    or self.root_adoption.owner_actor != self.envelope.authority.actor
                    or self.root_adoption.parent_budget_lease_ref
                       != self.envelope.parent_budget_lease_ref):
                raise ValueError("root adoption evidence must match bundle scope and operation")
            if self.root_adoption.graph_read_set_digest != canonical_digest(
                    self.envelope.version_guard.read_versions):
                raise ValueError("root adoption read set differs from bundle guard")
        proposals = _typed_tuple(self.proposals, DomainProposal, "proposals")
        if any(item.envelope != self.envelope for item in proposals):
            raise ValueError("bundle proposals must share the exact bundle envelope and operation")
        object.__setattr__(self, "proposals", proposals)
        for name in ("experience_refs", "choice_refs", "d02_settlement_refs", "d11_cost_settlement_refs",
                     "idempotency_keys", "persistent_job_refs", "outbox_refs"):
            object.__setattr__(self, name, _strings(getattr(self, name), name))
        present = {
            "experience": bool(self.experience_refs), "choice": bool(self.choice_refs),
            "d02_settlement": bool(self.d02_settlement_refs),
            "cost_settlement": bool(self.d11_cost_settlement_refs),
            PERSISTENT_JOB_REF_KIND: bool(self.persistent_job_refs), "outbox": bool(self.outbox_refs),
        }
        missing = sorted(part for item in proposals for part in item.required_bundle_parts if not present[part])
        if missing:
            raise ValueError(f"bundle is missing required parts: {', '.join(sorted(set(missing)))}")
        if (self.product_advance is not None
                and type(self.product_advance) is ProductAdvanceEvidenceV2
                and self.product_advance.bundle_digest != self.digest):
            raise ValueError("joint product evidence bundle digest differs")
        if self.root_adoption is not None and self.root_adoption.bundle_digest != self.digest:
            raise ValueError("root adoption evidence bundle digest differs")

    def v2_digest_with(self, evidence: ProductAdvanceEvidenceV2) -> str:
        """Compute the V2 operation identity before binding its digest into evidence."""
        from .runtime.d04_joint_advance_v2 import ProductAdvanceEvidenceV2

        if type(evidence) is not ProductAdvanceEvidenceV2:
            raise TypeError("evidence must be ProductAdvanceEvidenceV2")
        if (evidence.namespace != self.envelope.authority.namespace
                or evidence.operation_id != self.envelope.identity.operation_id):
            raise ValueError("joint product evidence must match bundle scope and operation")
        wire = {
            "$type": f"{type(self).__module__}.{type(self).__qualname__}",
            **{field.name: getattr(self, field.name) for field in fields(self)
               if field.name not in {"product_advance", "root_adoption"}},
            "product_advance": {
                "$type": f"{type(evidence).__module__}.{type(evidence).__qualname__}",
                **{field.name: getattr(evidence, field.name) for field in fields(evidence)
                   if field.name != "bundle_digest"},
            },
        }
        return canonical_digest(wire)

    def root_digest_with(self, evidence: RootAdoptionEvidenceV2) -> str:
        """Compute root bundle identity without its back-reference digest."""
        from .runtime.d04_root_adoption_contract_v2 import RootAdoptionEvidenceV2

        if type(evidence) is not RootAdoptionEvidenceV2:
            raise TypeError("evidence must be RootAdoptionEvidenceV2")
        if (self.product_advance is not None
                or evidence.namespace != self.envelope.authority.namespace
                or evidence.operation_id != self.envelope.identity.operation_id
                or evidence.phase != self.envelope.identity.phase
                or evidence.owner_actor != self.envelope.authority.actor
                or evidence.parent_budget_lease_ref
                   != self.envelope.parent_budget_lease_ref):
            raise ValueError("root adoption evidence must match bundle scope and operation")
        wire = {
            "$type": f"{type(self).__module__}.{type(self).__qualname__}",
            **{field.name: getattr(self, field.name) for field in fields(self)
               if field.name not in {"root_adoption", "product_advance"}},
            "product_advance": None,
            "root_adoption": {
                "$type": f"{type(evidence).__module__}.{type(evidence).__qualname__}",
                **{field.name: getattr(evidence, field.name) for field in fields(evidence)
                   if field.name != "bundle_digest"},
            },
        }
        return canonical_digest(wire)

    @property
    def digest(self) -> str:
        """Digest the complete immutable bundle for idempotency/conflict checks."""
        if any(write.key.type_name == "memory.source" for proposal in self.proposals for write in proposal.typed_writes):
            from .runtime.owner_material_source_storage_v3 import issued_owner_source_bundle_digest_v3
            sealed_digest = issued_owner_source_bundle_digest_v3(self)
            if sealed_digest is not None:
                return sealed_digest
        if self.root_adoption is not None:
            return self.root_digest_with(self.root_adoption)
        if self.product_advance is None:
            # Existing operations keep their original digest across this optional
            # contract addition, so an uncertain old commit remains queryable.
            legacy = {
                "$type": f"{type(self).__module__}.{type(self).__qualname__}",
                **{field.name: getattr(self, field.name) for field in fields(self)
                   if field.name not in {"product_advance", "root_adoption"}},
            }
            return canonical_digest(legacy)
        from .runtime.d04_joint_advance_v2 import ProductAdvanceEvidenceV2

        if type(self.product_advance) is ProductAdvanceEvidenceV2:
            return self.v2_digest_with(self.product_advance)
        legacy = {
            "$type": f"{type(self).__module__}.{type(self).__qualname__}",
            **{field.name: getattr(self, field.name) for field in fields(self)
               if field.name != "root_adoption"},
        }
        return canonical_digest(legacy)


@dataclass(frozen=True)
class CommitReceipt:
    status: str
    operation_id: str
    operation_digest: str
    activity_id: str
    effect_id: str | None
    commit_seq: int | None
    read_versions: tuple[GraphVersion, ...]
    write_versions: tuple[GraphVersion, ...]
    invalidated_epochs: tuple[NamespaceEpoch, ...]
    ledger_refs: tuple[str, ...]
    outbox_refs: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.status not in {"committed", "duplicate", "rejected", "conflict", "stale", "pending_confirmation"}:
            raise ValueError(f"unknown commit status: {self.status!r}")
        _nonempty(self.operation_id, "operation_id")
        _digest(self.operation_digest, "operation_digest")
        _nonempty(self.activity_id, "activity_id")
        if self.effect_id is not None:
            _nonempty(self.effect_id, "effect_id")
        if self.status in {"committed", "duplicate"}:
            _exact_nonnegative(self.commit_seq, "commit_seq")
        elif self.commit_seq is not None:
            _exact_nonnegative(self.commit_seq, "commit_seq")
        for name, expected in (("read_versions", GraphVersion), ("write_versions", GraphVersion),
                               ("invalidated_epochs", NamespaceEpoch)):
            object.__setattr__(self, name, _typed_tuple(getattr(self, name), expected, name))
        object.__setattr__(self, "ledger_refs", _strings(self.ledger_refs, "ledger_refs"))
        object.__setattr__(self, "outbox_refs", _strings(self.outbox_refs, "outbox_refs"))


@dataclass(frozen=True)
class ProviderDescriptor:
    provider_id: str
    contract_version: str
    request_schema_hash: str
    response_schema_hash: str
    owner_capabilities: tuple[str, ...]
    supported_modalities: tuple[str, ...]
    supported_purposes: tuple[str, ...]
    supported_platforms: tuple[str, ...]
    timeout_mode: str
    cancellation_mode: str
    idempotency_mode: str
    cost_reporting_mode: str
    health_capabilities: tuple[str, ...]
    recovery_capabilities: tuple[str, ...]

    def __post_init__(self) -> None:
        _nonempty(self.provider_id, "provider_id")
        if self.contract_version != RUNTIME_SCHEMA:
            raise ValueError(f"unknown provider contract version: {self.contract_version!r}")
        _digest(self.request_schema_hash, "request_schema_hash")
        _digest(self.response_schema_hash, "response_schema_hash")
        object.__setattr__(self, "owner_capabilities",
                           _strings(self.owner_capabilities, "owner_capabilities", allowed=_OWNER_SCOPES))
        for name in ("supported_modalities", "supported_purposes", "supported_platforms",
                     "health_capabilities", "recovery_capabilities"):
            object.__setattr__(self, name, _strings(getattr(self, name), name))
        for name in ("timeout_mode", "cancellation_mode", "idempotency_mode", "cost_reporting_mode"):
            _nonempty(getattr(self, name), name)


@dataclass(frozen=True)
class CheckReceipt:
    check_kind: str
    subject_ref: str
    action_ref: str
    purpose: str
    input_versions: tuple[VersionedRef, ...]
    coverage: str
    result: str
    valid_until: float
    issuer: str

    def __post_init__(self) -> None:
        for name in ("check_kind", "subject_ref", "action_ref", "purpose", "issuer"):
            _nonempty(getattr(self, name), name)
        object.__setattr__(self, "input_versions", _typed_tuple(self.input_versions, VersionedRef, "input_versions"))
        if self.coverage not in {"full", "partial", "none"}:
            raise ValueError(f"unknown coverage: {self.coverage!r}")
        if self.result not in {"pass", "fail", "unavailable", "unknown"}:
            raise ValueError(f"unknown check result: {self.result!r}")
        if self.result == "pass" and self.coverage != "full":
            raise ValueError("only full coverage may pass")
        object.__setattr__(self, "valid_until", _finite(self.valid_until, "valid_until"))


_SHORT_CONTEXT_HOURS = 72 * 60 * 60


def _context_dependencies(turns: tuple[CompletedTurnV1 | TurnAnchorV1, ...]) -> tuple[VersionedRef, ...]:
    return tuple(dict.fromkeys(ref for turn in turns for ref in
                               (turn.raw_ref, turn.source_ref, turn.access_ref)))


def _context_ranges(values: object, label: str) -> tuple[tuple[int, int], ...]:
    if isinstance(values, (str, bytes)):
        raise TypeError(f"{label} must be a range collection")
    ranges = tuple(values)  # type: ignore[arg-type]
    result = []
    for item in ranges:
        if type(item) not in (tuple, list) or len(item) != 2:
            raise TypeError(f"{label} must contain start/end pairs")
        start, end = item
        _exact_nonnegative(start, f"{label} start")
        _exact_nonnegative(end, f"{label} end")
        if end < start:
            raise ValueError(f"{label} cannot contain reversed ranges")
        result.append((start, end))
    if any(left[1] >= right[0] for left, right in zip(result, result[1:])):
        raise ValueError(f"{label} must be ordered and disjoint")
    return tuple(result)


@dataclass(frozen=True, slots=True)
class CompletedTurnV1:
    """A committed raw turn reference, not a claim of current source validity."""

    conversation_ref: str
    audience_ref: VersionedRef
    sequence: int
    raw_ref: VersionedRef
    source_ref: VersionedRef
    access_ref: VersionedRef
    speaker_ref: str
    text: str
    trusted_utc: float
    delivery_state: str
    tool_state: str
    schema: str = "d13.completed_turn.v1"

    def __post_init__(self) -> None:
        if self.schema != "d13.completed_turn.v1":
            raise ValueError("unknown completed turn schema")
        for name in ("conversation_ref", "speaker_ref", "text"):
            _nonempty(getattr(self, name), name)
        for name in ("audience_ref", "raw_ref", "source_ref", "access_ref"):
            if type(getattr(self, name)) is not VersionedRef:
                raise TypeError(f"{name} must be VersionedRef")
        _exact_nonnegative(self.sequence, "sequence")
        object.__setattr__(self, "trusted_utc", _finite(self.trusted_utc, "trusted_utc"))
        if self.delivery_state != "confirmed" or self.tool_state not in {"complete", "not_applicable"}:
            raise ValueError("only confirmed, closed turns may enter D13")


@dataclass(frozen=True, slots=True)
class TurnAnchorV1:
    """Metadata retained by a compressed block; raw text stays in D06/projection."""

    conversation_ref: str
    audience_ref: VersionedRef
    sequence: int
    raw_ref: VersionedRef
    source_ref: VersionedRef
    access_ref: VersionedRef
    speaker_ref: str
    trusted_utc: float

    def __post_init__(self) -> None:
        _nonempty(self.conversation_ref, "conversation_ref")
        _nonempty(self.speaker_ref, "speaker_ref")
        for name in ("audience_ref", "raw_ref", "source_ref", "access_ref"):
            if type(getattr(self, name)) is not VersionedRef:
                raise TypeError(f"{name} must be VersionedRef")
        _exact_nonnegative(self.sequence, "sequence")
        object.__setattr__(self, "trusted_utc", _finite(self.trusted_utc, "trusted_utc"))

    @classmethod
    def from_turn(cls, turn: CompletedTurnV1) -> "TurnAnchorV1":
        if type(turn) is not CompletedTurnV1:
            raise TypeError("turn must be CompletedTurnV1")
        return cls(turn.conversation_ref, turn.audience_ref, turn.sequence, turn.raw_ref,
                   turn.source_ref, turn.access_ref, turn.speaker_ref, turn.trusted_utc)


@dataclass(frozen=True, slots=True)
class ConversationWindowProjectionV1:
    """D11 assembled read snapshot; issuer signatures are checked elsewhere."""

    namespace: NamespaceId
    owner_ref: str
    conversation_ref: str
    scene_ref: VersionedRef
    audience_ref: VersionedRef
    turns: tuple[CompletedTurnV1, ...]
    order_watermark: int
    trusted_utc: float
    source_dependencies: tuple[VersionedRef, ...]
    read_set: tuple[VersionedRef, ...]
    access_epoch: int
    delete_epoch: int
    activation_epoch: int
    missing_ranges: tuple[tuple[int, int], ...] = ()
    schema: str = "d13.conversation_window.v1"

    def __post_init__(self) -> None:
        if self.schema != "d13.conversation_window.v1":
            raise ValueError("unknown conversation window schema")
        if type(self.namespace) is not NamespaceId:
            raise TypeError("namespace must be NamespaceId")
        for name in ("owner_ref", "conversation_ref"):
            _nonempty(getattr(self, name), name)
        for name in ("scene_ref", "audience_ref"):
            if type(getattr(self, name)) is not VersionedRef:
                raise TypeError(f"{name} must be VersionedRef")
        turns = _typed_tuple(self.turns, CompletedTurnV1, "turns")
        object.__setattr__(self, "turns", turns)
        _exact_nonnegative(self.order_watermark, "order_watermark")
        object.__setattr__(self, "trusted_utc", _finite(self.trusted_utc, "trusted_utc"))
        for name in ("access_epoch", "delete_epoch", "activation_epoch"):
            _exact_nonnegative(getattr(self, name), name)
        if any(turn.conversation_ref != self.conversation_ref or turn.audience_ref != self.audience_ref
               for turn in turns):
            raise ValueError("window turns must share conversation and audience")
        if any(left.sequence >= right.sequence for left, right in zip(turns, turns[1:])):
            raise ValueError("window turns must be ordered")
        if turns and turns[-1].sequence > self.order_watermark:
            raise ValueError("turn exceeds order watermark")
        if any(turn.trusted_utc > self.trusted_utc for turn in turns):
            raise ValueError("turn cannot postdate window clock")
        dependencies = _typed_tuple(self.source_dependencies, VersionedRef, "source_dependencies")
        if set(dependencies) != set(_context_dependencies(turns)):
            raise ValueError("window source dependency closure is incomplete")
        object.__setattr__(self, "source_dependencies", dependencies)
        reads = _typed_tuple(self.read_set, VersionedRef, "read_set")
        if not {self.scene_ref, self.audience_ref, *dependencies}.issubset(reads):
            raise ValueError("window read set is incomplete")
        object.__setattr__(self, "read_set", reads)
        object.__setattr__(self, "missing_ranges", _context_ranges(self.missing_ranges, "missing_ranges"))


@dataclass(frozen=True, slots=True)
class ShortContextRequestV1:
    requesting_domain: str
    purpose: str
    conversation_ref: str
    scene_ref: VersionedRef
    audience_ref: VersionedRef
    query_ref: str
    committed_focus_ref: VersionedRef | None
    history_token_budget: int
    provider_id: str
    model_id: str
    template_version: str
    tool_profile_version: str
    parent_budget_lease_ref: str
    opt_in: bool
    schema: str = "d13.short_context_request.v1"

    def __post_init__(self) -> None:
        if self.schema != "d13.short_context_request.v1":
            raise ValueError("unknown short context request schema")
        for name in ("requesting_domain", "purpose", "conversation_ref", "query_ref", "provider_id",
                     "model_id", "template_version", "tool_profile_version", "parent_budget_lease_ref"):
            _nonempty(getattr(self, name), name)
        for name in ("scene_ref", "audience_ref"):
            if type(getattr(self, name)) is not VersionedRef:
                raise TypeError(f"{name} must be VersionedRef")
        if self.committed_focus_ref is not None and type(self.committed_focus_ref) is not VersionedRef:
            raise TypeError("committed_focus_ref must be VersionedRef")
        _exact_nonnegative(self.history_token_budget, "history_token_budget")
        if type(self.opt_in) is not bool:
            raise TypeError("opt_in must be bool")
        if self.opt_in and (self.requesting_domain == "d13" or self.purpose.startswith("d13.")):
            raise ValueError("D13 compression requests cannot carry D13 history")


@dataclass(frozen=True, slots=True)
class TurnTimelineItemV1:
    sequence: int
    source_ref: VersionedRef
    speaker_ref: str
    text: str

    def __post_init__(self) -> None:
        _exact_nonnegative(self.sequence, "sequence")
        if type(self.source_ref) is not VersionedRef:
            raise TypeError("source_ref must be VersionedRef")
        _nonempty(self.speaker_ref, "speaker_ref")
        _nonempty(self.text, "text")


@dataclass(frozen=True, slots=True)
class TurnDetailSlotV1:
    key: str
    sequence: int
    source_ref: VersionedRef
    text: str

    def __post_init__(self) -> None:
        _nonempty(self.key, "key")
        _exact_nonnegative(self.sequence, "sequence")
        if type(self.source_ref) is not VersionedRef:
            raise TypeError("source_ref must be VersionedRef")
        _nonempty(self.text, "text")


@dataclass(frozen=True, slots=True)
class CompressedTurnBlockV2:
    block_ref: str
    conversation_ref: str
    audience_ref: VersionedRef
    turns: tuple[TurnAnchorV1, ...]
    source_dependencies: tuple[VersionedRef, ...]
    timeline: tuple[TurnTimelineItemV1, ...]
    detail_slots: tuple[TurnDetailSlotV1, ...]
    omitted_ranges: tuple[tuple[int, int], ...]
    compiler_version: str
    job_ref: str
    candidate_ref: str
    expires_at_utc: float
    status: str
    schema: str = "d13.compressed_turn_block.v2"

    def __post_init__(self) -> None:
        if self.schema != "d13.compressed_turn_block.v2":
            raise ValueError("unknown compressed turn block schema")
        for name in ("block_ref", "conversation_ref", "compiler_version", "job_ref", "candidate_ref"):
            _nonempty(getattr(self, name), name)
        if type(self.audience_ref) is not VersionedRef:
            raise TypeError("audience_ref must be VersionedRef")
        turns = _typed_tuple(self.turns, TurnAnchorV1, "turns")
        if not turns:
            raise ValueError("block requires turn anchors")
        if any(turn.conversation_ref != self.conversation_ref or turn.audience_ref != self.audience_ref
               for turn in turns):
            raise ValueError("block turns must share conversation and audience")
        if any(right.sequence != left.sequence + 1 for left, right in zip(turns, turns[1:])):
            raise ValueError("block turns must be consecutive")
        object.__setattr__(self, "turns", turns)
        dependencies = _typed_tuple(self.source_dependencies, VersionedRef, "source_dependencies")
        if set(dependencies) != set(_context_dependencies(turns)):
            raise ValueError("block source dependency closure is incomplete")
        object.__setattr__(self, "source_dependencies", dependencies)
        by_sequence = {turn.sequence: turn for turn in turns}
        timeline = _typed_tuple(self.timeline, TurnTimelineItemV1, "timeline")
        details = _typed_tuple(self.detail_slots, TurnDetailSlotV1, "detail_slots")
        if not timeline:
            raise ValueError("block requires anchored timeline")
        if any(item.sequence not in by_sequence or
               item.source_ref != by_sequence[item.sequence].source_ref or
               item.speaker_ref != by_sequence[item.sequence].speaker_ref for item in timeline):
            raise ValueError("timeline item must anchor to its raw turn and speaker")
        if any(item.sequence not in by_sequence or
               item.source_ref != by_sequence[item.sequence].source_ref for item in details):
            raise ValueError("detail slot must anchor to its raw turn")
        if any(left.sequence >= right.sequence for left, right in zip(timeline, timeline[1:])):
            raise ValueError("timeline must follow raw turn order")
        if len({item.key for item in details}) != len(details):
            raise ValueError("detail slot keys must be unique")
        object.__setattr__(self, "timeline", timeline)
        object.__setattr__(self, "detail_slots", details)
        ranges = _context_ranges(self.omitted_ranges, "omitted_ranges")
        for start, end in ranges:
            if start < turns[0].sequence or end > turns[-1].sequence:
                raise ValueError("omitted range must lie within block")
        object.__setattr__(self, "omitted_ranges", ranges)
        expiry = _finite(self.expires_at_utc, "expires_at_utc")
        if expiry > min(turn.trusted_utc for turn in turns) + _SHORT_CONTEXT_HOURS:
            raise ValueError("block cannot outlive earliest raw turn by 72 hours")
        object.__setattr__(self, "expires_at_utc", expiry)
        if self.status not in {"candidate", "standby", "active", "retired"}:
            raise ValueError("unknown block status")

    @property
    def rendered_text(self) -> str:
        """Diagnostic view with all slots; model payload selects slice.selected_detail_slots."""
        lines = [f"[{item.sequence} {item.speaker_ref}] {item.text}" for item in self.timeline]
        lines.extend(f"[{item.sequence} {item.key}] {item.text}" for item in self.detail_slots)
        return "\n".join(lines)


@dataclass(frozen=True, slots=True)
class ShortContextSliceV1:
    conversation_ref: str
    audience_ref: VersionedRef
    blocks: tuple[CompressedTurnBlockV2, ...]
    raw_tail: tuple[CompletedTurnV1, ...]
    selected_detail_slots: tuple[str, ...]
    source_dependencies: tuple[VersionedRef, ...]
    missing_ranges: tuple[tuple[int, int], ...]
    expires_at_utc: float
    stable_prefix_digest: str
    estimated_tokens: int
    evidence_eligibility: str = "ineligible"
    schema: str = "d13.short_context_slice.v1"

    def __post_init__(self) -> None:
        if self.schema != "d13.short_context_slice.v1":
            raise ValueError("unknown short context slice schema")
        _nonempty(self.conversation_ref, "conversation_ref")
        if type(self.audience_ref) is not VersionedRef:
            raise TypeError("audience_ref must be VersionedRef")
        blocks = _typed_tuple(self.blocks, CompressedTurnBlockV2, "blocks")
        if any(block.conversation_ref != self.conversation_ref or block.audience_ref != self.audience_ref
               for block in blocks):
            raise ValueError("slice blocks must share conversation and audience")
        if any(block.status != "active" for block in blocks):
            raise ValueError("slice may select only active blocks")
        object.__setattr__(self, "blocks", blocks)
        turns = _typed_tuple(self.raw_tail, CompletedTurnV1, "raw_tail")
        if any(turn.conversation_ref != self.conversation_ref or turn.audience_ref != self.audience_ref
               for turn in turns):
            raise ValueError("slice raw tail must share conversation and audience")
        if any(left.sequence >= right.sequence for left, right in zip(turns, turns[1:])):
            raise ValueError("slice raw tail must be ordered")
        intervals = sorted((block.turns[0].sequence, block.turns[-1].sequence) for block in blocks)
        if any(left[1] >= right[0] for left, right in zip(intervals, intervals[1:])):
            raise ValueError("slice blocks cannot overlap")
        if turns and intervals and turns[0].sequence <= intervals[-1][1]:
            raise ValueError("slice raw tail must follow selected blocks")
        object.__setattr__(self, "raw_tail", turns)
        object.__setattr__(self, "selected_detail_slots", _strings(self.selected_detail_slots,
                                                                    "selected_detail_slots"))
        available_slots = {slot.key for block in blocks for slot in block.detail_slots}
        if not set(self.selected_detail_slots).issubset(available_slots):
            raise ValueError("selected detail slot has no source-anchored block item")
        dependencies = _typed_tuple(self.source_dependencies, VersionedRef, "source_dependencies")
        expected = set(_context_dependencies(turns)) | {
            dependency for block in blocks for dependency in block.source_dependencies
        }
        if set(dependencies) != expected:
            raise ValueError("slice source dependency closure is incomplete")
        object.__setattr__(self, "source_dependencies", dependencies)
        object.__setattr__(self, "missing_ranges", _context_ranges(self.missing_ranges, "missing_ranges"))
        expiry = _finite(self.expires_at_utc, "expires_at_utc")
        deadlines = [turn.trusted_utc + _SHORT_CONTEXT_HOURS for turn in turns]
        deadlines.extend(block.expires_at_utc for block in blocks)
        if deadlines and expiry > min(deadlines):
            raise ValueError("slice cannot extend selected history lifetime")
        object.__setattr__(self, "expires_at_utc", expiry)
        _digest(self.stable_prefix_digest, "stable_prefix_digest")
        _exact_nonnegative(self.estimated_tokens, "estimated_tokens")
        if self.evidence_eligibility != "ineligible":
            raise ValueError("D13 slice cannot be fact evidence")


@dataclass(frozen=True, slots=True)
class ModelInputFrameV1:
    """Frozen input description; D11 still verifies and counts before dispatch."""

    request: ShortContextRequestV1
    context_frame_ref: VersionedRef
    short_context: ShortContextSliceV1 | None
    required_evidence_refs: tuple[VersionedRef, ...]
    current_projection_refs: tuple[VersionedRef, ...]
    required_check_refs: tuple[VersionedRef, ...]
    read_set: tuple[VersionedRef, ...]
    current_input_ref: str
    available_input_tokens: int
    actual_input_tokens: int
    frozen_input_digest: str
    schema: str = "d11.model_input_frame.v1"

    def __post_init__(self) -> None:
        if self.schema != "d11.model_input_frame.v1":
            raise ValueError("unknown model input frame schema")
        if type(self.request) is not ShortContextRequestV1:
            raise TypeError("request must be ShortContextRequestV1")
        if type(self.context_frame_ref) is not VersionedRef:
            raise TypeError("context_frame_ref must be VersionedRef")
        if self.short_context is not None:
            if type(self.short_context) is not ShortContextSliceV1:
                raise TypeError("short_context must be ShortContextSliceV1")
            if not self.request.opt_in or self.request.conversation_ref != self.short_context.conversation_ref \
                    or self.request.audience_ref != self.short_context.audience_ref:
                raise ValueError("D13 slice requires matching explicit request")
        for name in ("required_evidence_refs", "current_projection_refs", "required_check_refs", "read_set"):
            object.__setattr__(self, name, _typed_tuple(getattr(self, name), VersionedRef, name))
        if any(ref.ref.startswith(("d13.", "d13:")) for ref in self.required_evidence_refs):
            raise ValueError("D13 content cannot be required fact evidence")
        dependencies = {self.context_frame_ref, self.request.scene_ref, self.request.audience_ref,
                        *self.required_evidence_refs, *self.current_projection_refs, *self.required_check_refs}
        if self.short_context is not None:
            dependencies.update(self.short_context.source_dependencies)
        if not dependencies.issubset(self.read_set):
            raise ValueError("model input read set is incomplete")
        _nonempty(self.current_input_ref, "current_input_ref")
        _exact_nonnegative(self.available_input_tokens, "available_input_tokens")
        _exact_nonnegative(self.actual_input_tokens, "actual_input_tokens")
        if self.actual_input_tokens > self.available_input_tokens:
            raise ValueError("actual input exceeds available budget")
        _digest(self.frozen_input_digest, "frozen_input_digest")


CONTEXT_REPLY_WORKFLOW_V1 = "sylanne.d09.context_reply.v1"
NATURAL_REPLY_GENERATION_WORKFLOW_V2 = "sylanne.d09.context_reply_input.v2"
NATURAL_REPLY_REVIEW_WORKFLOW_V1 = "sylanne.d09.natural_reply_review.v1"
NATURAL_REPLY_GENERATION_WORKFLOW_V3 = "sylanne.d09.context_reply_input.v3"
NATURAL_REPLY_GENERATION_WORKFLOW_V4 = "sylanne.d09.context_reply_input.v4"
NATURAL_REPLY_GENERATION_WORKFLOW_V5 = "sylanne.d09.context_reply_input.v5"
NATURAL_REPLY_REVIEW_WORKFLOW_V2 = "sylanne.d09.natural_reply_review.v2"
CONTACT_GENERATION_WORKFLOW_V1 = "sylanne.d09.contact_generation.v1"
CONTACT_REVIEW_WORKFLOW_V1 = "sylanne.d09.contact_review.v1"
D04_APPRAISAL_TEMPLATE_V1 = "sylanne.d04.appraisal_template.v1"
D04_APPRAISAL_WORK_KIND = "d04.appraisal"


def context_reply_graph_guard_digest_v2(
    read_versions: tuple[GraphVersion, ...], query_epoch: QueryEpoch, *,
    graph_epoch: int, access_epoch: int, delete_epoch: int,
    activation_generation: int,
) -> str:
    """Canonical complete-read identity for W01 and an independent Authority read.

    This hash authenticates nothing by itself. Both callers must obtain their
    own current, complete graph read under the appropriate content fence.
    """
    if (type(query_epoch) is not QueryEpoch
            or type(read_versions) is not tuple or not read_versions
            or any(type(item) is not GraphVersion for item in read_versions)):
        raise ValueError("context reply requires typed complete graph reads")
    versions = tuple(sorted((item.key.token, item.revision) for item in read_versions))
    if (len({token for token, _ in versions}) != len(versions)
            or any((item.key.owner.bot, item.key.owner.persona)
                   != query_epoch.namespace.as_tuple for item in read_versions)):
        raise ValueError("context reply graph read crosses scope or repeats a key")
    for name, value in (
        ("graph_epoch", graph_epoch), ("access_epoch", access_epoch),
        ("delete_epoch", delete_epoch),
        ("activation_generation", activation_generation),
    ):
        _exact_nonnegative(value, name)
    if query_epoch.revision != graph_epoch:
        raise ValueError("context reply query and graph epochs differ")
    return canonical_digest({
        "schema": "sylanne.context_reply.graph_guard.v2",
        "namespace": query_epoch.namespace,
        "query_scope": query_epoch.scope_ref,
        "query_epoch": query_epoch.revision,
        "graph_epoch": graph_epoch,
        "access_epoch": access_epoch,
        "delete_epoch": delete_epoch,
        "activation_generation": activation_generation,
        "read_versions": versions,
    })


@dataclass(frozen=True, slots=True)
class ContextReplyOriginalSealV2:
    """Identity of one original context-reply call, persisted before acquire.

    Only W01's sealed job and Authority's original intent can establish this
    identity. A host copy of the value is never an egress or result-read grant.
    Terminal outcome belongs to a later receipt and cannot change this seal.
    """

    namespace: NamespaceId
    c02_operation_id: str
    source_ref: str
    installation_id: str
    provider_config_digest: str
    job_id: str
    original_operation_id: str
    acquire_operation_id: str
    call_id: str
    template_version: str
    frozen_input_digest: str
    model_request_digest: str
    graph_guard_digest: str
    schema: str = "sylanne.context_reply.original_seal.v2"

    def __post_init__(self) -> None:
        if type(self.namespace) is not NamespaceId:
            raise TypeError("context reply namespace is required")
        if self.schema != "sylanne.context_reply.original_seal.v2":
            raise ValueError("unknown context reply original seal")
        if self.template_version != CONTEXT_REPLY_WORKFLOW_V1:
            raise ValueError("context reply template identity differs")
        for name in (
            "c02_operation_id", "source_ref", "installation_id", "job_id",
            "original_operation_id", "acquire_operation_id", "call_id",
        ):
            _nonempty(getattr(self, name), name)
        for name in (
            "provider_config_digest", "frozen_input_digest",
            "model_request_digest", "graph_guard_digest",
        ):
            _digest(getattr(self, name), name)


@dataclass(frozen=True, slots=True)
class NaturalReplyGenerationOriginalSealV2:
    """Pre-call generation identity; model_request_digest is frozen wire SHA-256.

    The acquired typed ModelCallRequest has its own digest and must be bound
    by the graph coordinator before an Authority-paid terminal can be read.
    """

    namespace: NamespaceId
    c02_operation_id: str
    source_ref: str
    installation_id: str
    provider_config_digest: str
    job_id: str
    original_operation_id: str
    acquire_operation_id: str
    call_id: str
    frozen_input_digest: str
    qualified_units_digest: str
    model_request_digest: str
    original_graph_guard_digest: str
    parent_budget_lease_id: str
    reservation_operation_id: str
    template_version: str = NATURAL_REPLY_GENERATION_WORKFLOW_V2
    schema: str = "sylanne.d09.natural_generation_seal.v2"

    def __post_init__(self) -> None:
        if type(self.namespace) is not NamespaceId or (
                self.schema != "sylanne.d09.natural_generation_seal.v2"
                or self.template_version != NATURAL_REPLY_GENERATION_WORKFLOW_V2):
            raise ValueError("unknown natural generation original identity")
        for name in (
            "c02_operation_id", "source_ref", "installation_id", "job_id",
            "original_operation_id", "acquire_operation_id", "call_id",
            "parent_budget_lease_id", "reservation_operation_id",
        ):
            _nonempty(getattr(self, name), name)
        for name in (
            "provider_config_digest", "frozen_input_digest",
            "qualified_units_digest", "model_request_digest",
            "original_graph_guard_digest",
        ):
            _digest(getattr(self, name), name)
        if len({self.job_id, self.original_operation_id,
                self.acquire_operation_id, self.call_id}) != 4:
            raise ValueError("natural generation identities must be distinct")


@dataclass(frozen=True, slots=True)
class NaturalReplyReviewOriginalSealV2:
    """Separate review identity bound to one observed generation output.

    model_request_digest is the frozen provider wire digest; the acquired
    typed ModelCallRequest digest is a distinct paid-call binding.
    """

    namespace: NamespaceId
    installation_id: str
    provider_config_digest: str
    job_id: str
    original_operation_id: str
    acquire_operation_id: str
    call_id: str
    generation_original_operation_id: str
    generation_call_id: str
    generation_frozen_input_digest: str
    generation_output_digest: str
    qualified_units_digest: str
    review_frozen_input_digest: str
    model_request_digest: str
    original_graph_guard_digest: str
    parent_budget_lease_id: str
    reservation_operation_id: str
    review_policy_version: str
    template_version: str = NATURAL_REPLY_REVIEW_WORKFLOW_V1
    schema: str = "sylanne.d09.natural_review_seal.v2"

    def __post_init__(self) -> None:
        if type(self.namespace) is not NamespaceId or (
                self.schema != "sylanne.d09.natural_review_seal.v2"
                or self.template_version != NATURAL_REPLY_REVIEW_WORKFLOW_V1):
            raise ValueError("unknown natural review original identity")
        for name in (
            "installation_id", "job_id", "original_operation_id",
            "acquire_operation_id", "call_id",
            "generation_original_operation_id", "generation_call_id",
            "parent_budget_lease_id", "reservation_operation_id",
            "review_policy_version",
        ):
            _nonempty(getattr(self, name), name)
        for name in (
            "provider_config_digest", "generation_frozen_input_digest",
            "generation_output_digest", "qualified_units_digest",
            "review_frozen_input_digest", "model_request_digest",
            "original_graph_guard_digest",
        ):
            _digest(getattr(self, name), name)
        if (len({self.job_id, self.original_operation_id,
                 self.acquire_operation_id, self.call_id}) != 4
                or self.original_operation_id == self.generation_original_operation_id
                or self.call_id == self.generation_call_id):
            raise ValueError("natural review and generation identities must differ")


@dataclass(frozen=True, slots=True)
class NaturalReplyPaidReviewReceiptV2:
    """Authority-issued paid-result identity; this type alone grants no send.

    The typed acquired call digests are distinct from the pre-call seals'
    frozen provider wire hashes. Current read versions and audience belong to
    the enclosing Authority result-read DTO and must be checked again by D11.
    """

    namespace: NamespaceId
    generation_original_operation_id: str
    generation_call_id: str
    generation_model_call_request_digest: str
    generation_terminal_receipt_digest: str
    generation_output_digest: str
    review_original_operation_id: str
    review_call_id: str
    review_model_call_request_digest: str
    review_terminal_receipt_digest: str
    review_output_digest: str
    parent_budget_lease_id: str
    generation_reservation_operation_id: str
    review_reservation_operation_id: str
    qualified_units_digest: str
    review_policy_version: str
    verdict: str
    current_graph_guard_digest: str
    schema: str = "sylanne.d09.natural_paid_review_receipt.v2"

    def __post_init__(self) -> None:
        if type(self.namespace) is not NamespaceId or (
                self.schema != "sylanne.d09.natural_paid_review_receipt.v2"
                or self.verdict not in {"pass", "rewrite", "hold"}):
            raise ValueError("unknown natural paid review receipt")
        for name in (
            "generation_original_operation_id", "generation_call_id",
            "review_original_operation_id", "review_call_id",
            "parent_budget_lease_id", "generation_reservation_operation_id",
            "review_reservation_operation_id", "review_policy_version",
        ):
            _nonempty(getattr(self, name), name)
        for name in (
            "generation_model_call_request_digest",
            "generation_terminal_receipt_digest", "generation_output_digest",
            "review_model_call_request_digest", "review_terminal_receipt_digest",
            "review_output_digest", "qualified_units_digest",
            "current_graph_guard_digest",
        ):
            _digest(getattr(self, name), name)
        if (self.generation_original_operation_id == self.review_original_operation_id
                or self.generation_call_id == self.review_call_id
                or self.generation_reservation_operation_id
                   == self.review_reservation_operation_id):
            raise ValueError("natural generation and review paid identities must differ")


@runtime_checkable
class DomainProvider(Protocol):
    @property
    def descriptor(self) -> ProviderDescriptor: ...

    def register_types(self) -> object: ...

    def validate(self, proposal: DomainProposal, snapshot: object) -> object: ...

    def compile_scheme(self, draft: object, snapshot: object) -> object: ...

    def project(self, query: object, snapshot: object) -> object: ...

    def invalidate(self, refs: tuple[AtomRef, ...]) -> object: ...

    def cleanup(self, plan: object) -> object: ...


__all__ = [
    "RUNTIME_SCHEMA", "AUTHORITY_BOOTSTRAP_SCHEMA_V2", "Owner", "AtomKey", "AtomRef", "NamespaceId",
    "NamespaceRuntimeState", "InstallationGrantV2", "NamespaceBootstrapV2", "SnapshotRequirementsV2",
    "FenceScope", "ContentFencePortV2", "ContentEffectSnapshotPortV2",
    "VersionedRef", "QueryEpoch",
    "OperationIdentity", "AuthorityContext", "VersionGuard", "SourceQualification", "DependencySet",
    "CommandEnvelope", "DomainProposal", "ProductAdvanceEvidenceV1", "DomainBundle",
    "CommitReceipt", "ProviderDescriptor",
    "CheckReceipt", "DomainProvider", "canonical_serialize", "canonical_digest", "schema_hash",
    "CompletedTurnV1", "TurnAnchorV1", "ConversationWindowProjectionV1", "ShortContextRequestV1",
    "TurnTimelineItemV1", "TurnDetailSlotV1",
    "CompressedTurnBlockV2", "ShortContextSliceV1", "ModelInputFrameV1",
    "CONTEXT_REPLY_WORKFLOW_V1", "ContextReplyOriginalSealV2",
    "context_reply_graph_guard_digest_v2",
    "NATURAL_REPLY_GENERATION_WORKFLOW_V2", "NATURAL_REPLY_REVIEW_WORKFLOW_V1",
    "NATURAL_REPLY_GENERATION_WORKFLOW_V3",
    "NATURAL_REPLY_GENERATION_WORKFLOW_V4",
    "NATURAL_REPLY_GENERATION_WORKFLOW_V5",
    "NATURAL_REPLY_REVIEW_WORKFLOW_V2",
    "CONTACT_GENERATION_WORKFLOW_V1",
    "CONTACT_REVIEW_WORKFLOW_V1",
    "D04_APPRAISAL_TEMPLATE_V1",
    "D04_APPRAISAL_WORK_KIND",
    "NaturalReplyGenerationOriginalSealV2", "NaturalReplyReviewOriginalSealV2",
    "NaturalReplyPaidReviewReceiptV2",
]
