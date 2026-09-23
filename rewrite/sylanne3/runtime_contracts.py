"""Public, domain-neutral contracts for the Sylanne 3 alpha1 runtime.

These values describe candidates and receipts.  They do not authenticate a
caller or grant graph write authority; the runtime coordinator must resolve
opaque capability references and validate proposals at the commit boundary.
"""

from __future__ import annotations

from dataclasses import dataclass, fields, is_dataclass
from enum import Enum
import hashlib
import json
import math
from typing import Any, Protocol, runtime_checkable

from .graph_types import AtomKey, GraphVersion, GraphWrite, NamespaceEpoch, Owner
from .runtime.restore_anchor import RestoreAnchor


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
_BUNDLE_PARTS = frozenset({
    "experience", "choice", "d02_settlement", "cost_settlement", "persistent_job", "outbox"
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


def canonical_serialize(value: object) -> str:
    """Return stable UTF-8 JSON text for supported DTO and JSON values."""

    return json.dumps(
        _canonical_value(value, set()), sort_keys=True, separators=(",", ":"),
        ensure_ascii=True, allow_nan=False,
    )


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
        if self.source_family in {"authored", "simulated"}:
            if self.content_reality in {"external_observation", "external_report"}:
                raise ValueError("authored/simulated sources cannot claim external reality")
            if self.evidence_eligibility == "eligible":
                raise ValueError("authored/simulated sources cannot be unqualified external evidence")


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
        object.__setattr__(self, "typed_writes",
                           tuple(GraphWrite(write.key, write.value, write.dependencies) for write in writes))
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

    def __post_init__(self) -> None:
        if not isinstance(self.envelope, CommandEnvelope):
            raise TypeError("envelope must be CommandEnvelope")
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
            "persistent_job": bool(self.persistent_job_refs), "outbox": bool(self.outbox_refs),
        }
        missing = sorted(part for item in proposals for part in item.required_bundle_parts if not present[part])
        if missing:
            raise ValueError(f"bundle is missing required parts: {', '.join(sorted(set(missing)))}")

    @property
    def digest(self) -> str:
        """Digest the complete immutable bundle for idempotency/conflict checks."""

        return canonical_digest(self)


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
    "NamespaceRuntimeState", "InstallationGrantV2", "NamespaceBootstrapV2", "VersionedRef", "QueryEpoch",
    "OperationIdentity", "AuthorityContext", "VersionGuard", "SourceQualification", "DependencySet",
    "CommandEnvelope", "DomainProposal", "DomainBundle", "CommitReceipt", "ProviderDescriptor",
    "CheckReceipt", "DomainProvider", "canonical_serialize", "canonical_digest", "schema_hash",
]
