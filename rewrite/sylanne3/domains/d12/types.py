"""Typed, non-authoritative D12 objects used by the workbench service."""

from __future__ import annotations

from dataclasses import dataclass, fields
from hashlib import sha256
import json
from typing import Any, Mapping

from ...graph_types import AtomKey, GraphWrite, Owner, TypeSpec
from ...runtime_contracts import (
    CommandEnvelope, DependencySet, DomainProposal, ProviderDescriptor, RUNTIME_SCHEMA,
    NamespaceId, schema_hash,
)


def _text(value: object, label: str, *, limit: int = 256) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        raise ValueError(f"{label} must be a nonempty string no longer than {limit} characters")
    return value


def _object(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise TypeError(f"{label} must be an object")
    result = dict(value)
    try:
        json.dumps(result, sort_keys=True, allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{label} must be JSON-safe") from exc
    return result


@dataclass(frozen=True)
class D12TypeSpec:
    """Versioned shape declaration; it cannot grant a domain writer capability."""

    schema: str = "d12.types.v1"
    draft_fields: tuple[str, ...] = ("fields", "field_sources", "revision", "scope")
    operation_fields: tuple[str, ...] = ("operation_id", "action", "scope", "purpose", "audience")

    def __post_init__(self) -> None:
        _text(self.schema, "schema")
        if not self.draft_fields or not self.operation_fields:
            raise ValueError("D12 type specification must list fields")

    @property
    def digest(self) -> str:
        material = json.dumps({"schema": self.schema, "draft_fields": self.draft_fields,
                               "operation_fields": self.operation_fields}, sort_keys=True,
                              separators=(",", ":"))
        return sha256(material.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class CharacterDraft:
    scope: str
    revision: int
    fields: dict[str, Any]
    field_sources: dict[str, str]

    def __post_init__(self) -> None:
        _text(self.scope, "scope")
        if type(self.revision) is not int or self.revision < 0:
            raise ValueError("revision must be a nonnegative exact integer")
        object.__setattr__(self, "fields", _object(self.fields, "fields"))
        sources = _object(self.field_sources, "field_sources")
        if set(sources) != set(self.fields):
            raise ValueError("field_sources must match exactly the draft fields")
        if any(not isinstance(value, str) or not value for value in sources.values()):
            raise ValueError("field source values must be nonempty strings")
        object.__setattr__(self, "field_sources", sources)


@dataclass(frozen=True)
class ActiveSchemeHeadV1:
    """D12's current administrative pointer; only W01 may atomically advance it."""

    scope: str
    generation: int
    compiled_digest: str
    draft_ref: str
    draft_revision: int
    draft_digest: str
    previous_compiled_digest: str | None
    adopted_operation_id: str
    adoption_kind: str

    def __post_init__(self) -> None:
        _text(self.scope, "scope")
        if type(self.generation) is not int or self.generation < 1:
            raise ValueError("active scheme generation must be positive")
        if type(self.draft_revision) is not int or self.draft_revision < 1:
            raise ValueError("active scheme draft revision must be positive")
        for name in ("compiled_digest", "draft_digest"):
            value = getattr(self, name)
            if type(value) is not str or len(value) != 64 or any(
                    ch not in "0123456789abcdef" for ch in value):
                raise ValueError(f"{name} must be a lowercase SHA-256 digest")
        if self.previous_compiled_digest is not None and (
                type(self.previous_compiled_digest) is not str
                or len(self.previous_compiled_digest) != 64
                or any(ch not in "0123456789abcdef"
                       for ch in self.previous_compiled_digest)):
            raise ValueError("previous_compiled_digest must be SHA-256")
        _text(self.draft_ref, "draft_ref", limit=4096)
        try:
            draft_key = AtomKey.from_token(self.draft_ref)
        except (TypeError, ValueError) as exc:
            raise ValueError("draft_ref must be a canonical graph key") from exc
        if (draft_key.type_name != "d12.character_draft.v1"
                or draft_key.owner.kind != "persona"
                or draft_key.owner.persona != self.scope
                or draft_key.name != "current"):
            raise ValueError("active scheme draft_ref must name the current draft")
        _text(self.adopted_operation_id, "adopted_operation_id")
        if self.adoption_kind not in ("initial", "administrative_edit"):
            raise ValueError("active scheme has unsupported adoption kind")
        if (self.generation == 1) != (self.previous_compiled_digest is None):
            raise ValueError("first scheme must have no prior digest")


def character_draft_key(namespace: NamespaceId) -> AtomKey:
    if type(namespace) is not NamespaceId:
        raise TypeError("namespace is required")
    return AtomKey(Owner("persona", namespace.bot_id, namespace.persona_id),
                   "d12.character_draft.v1", "current")


def active_scheme_head_key(namespace: NamespaceId) -> AtomKey:
    if type(namespace) is not NamespaceId:
        raise TypeError("namespace is required")
    return AtomKey(Owner("persona", namespace.bot_id, namespace.persona_id),
                   "d12.active_scheme_head.v1", "current")


@dataclass(frozen=True)
class CompiledSchemeCandidate:
    scope: str
    draft_revision: int
    candidate_ref: str
    candidate_digest: str
    domain_candidates: tuple[str, ...]
    expires_at_utc: str

    def __post_init__(self) -> None:
        _text(self.scope, "scope")
        if type(self.draft_revision) is not int or self.draft_revision < 0:
            raise ValueError("draft_revision must be a nonnegative exact integer")
        _text(self.candidate_ref, "candidate_ref")
        if len(self.candidate_digest) != 64 or any(ch not in "0123456789abcdef" for ch in self.candidate_digest):
            raise ValueError("candidate_digest must be a lowercase SHA-256 digest")
        if not self.domain_candidates or any(not isinstance(ref, str) or not ref for ref in self.domain_candidates):
            raise ValueError("domain_candidates must be nonempty references")
        _text(self.expires_at_utc, "expires_at_utc")


@dataclass(frozen=True)
class OperationPlan:
    operation_id: str
    action: str
    scope: str
    purpose: str
    audience: tuple[str, ...]
    input_digest: str

    def __post_init__(self) -> None:
        for name in ("operation_id", "action", "scope", "purpose"):
            _text(getattr(self, name), name)
        if not self.audience or any(not isinstance(item, str) or not item for item in self.audience):
            raise ValueError("audience must contain verified audience references")
        if len(self.input_digest) != 64 or any(ch not in "0123456789abcdef" for ch in self.input_digest):
            raise ValueError("input_digest must be a lowercase SHA-256 digest")


def _graph_validator(schema: str, value_type: type, tuple_fields: tuple[str, ...] = ()):
    expected = {"schema"} | {field.name for field in fields(value_type)}

    def validate(payload: dict) -> None:
        if type(payload) is not dict:
            raise TypeError("D12 graph payload must be an object")
        if payload.get("schema") != schema:
            raise ValueError("D12 graph schema mismatch")
        if set(payload) != expected:
            raise ValueError("D12 graph fields must match exactly")
        decoded = {name: value for name, value in payload.items() if name != "schema"}
        for name in tuple_fields:
            if type(decoded[name]) is not list:
                raise TypeError(f"{name} must be a JSON array")
            decoded[name] = tuple(decoded[name])
        value_type(**decoded)

    return validate


def graph_type_specs() -> tuple[TypeSpec, ...]:
    """Register D12 administrative candidates in the shared business graph.

    These types never activate a character scheme or confer a runtime write
    capability to the browser. D11 adoption remains a separate authority.
    """

    definitions = (
        ("d12.character_draft.v1", ("persona",), "state", CharacterDraft, (), False),
        ("d12.active_scheme_head.v1", ("persona",), "state", ActiveSchemeHeadV1, (), False),
        ("d12.compiled_scheme_candidate.v1", ("activity",), "cache", CompiledSchemeCandidate,
         ("domain_candidates",), True),
        ("d12.operation_plan.v1", ("activity",), "source", OperationPlan, ("audience",), True),
    )
    return tuple(
        TypeSpec(
            name=name, owner_kinds=owners, storage_role=role,
            validator=_graph_validator(name, value_type, tuple_fields),
            immutable=immutable, writer_domain="d12",
            schema_hash=schema_hash({
                "domain": "d12", "type": name, "owner_kinds": owners,
                "storage_role": role, "required": ("schema",) + tuple(
                    field.name for field in fields(value_type)), "version": 1,
            }),
        )
        for name, owners, role, value_type, tuple_fields, immutable in definitions
    )


class D12DomainProvider:
    """Validate administrative candidates without activating character state."""

    _PROPOSAL_SCHEMA = "d12.proposal.v1"
    _PROPOSAL_HASH = schema_hash({"domain": "d12", "proposal": 1, "purpose": "administrative_candidate"})

    @property
    def descriptor(self) -> ProviderDescriptor:
        return ProviderDescriptor(
            provider_id="d12.workbench", contract_version=RUNTIME_SCHEMA,
            request_schema_hash=self._PROPOSAL_HASH,
            response_schema_hash=schema_hash({"domain": "d12", "projection": 1}),
            owner_capabilities=("persona", "activity"), supported_modalities=("structured",),
            supported_purposes=("audit", "consolidation"), supported_platforms=("runtime",),
            timeout_mode="bounded", cancellation_mode="cooperative",
            idempotency_mode="operation_id", cost_reporting_mode="runtime_receipt",
            health_capabilities=("validate",), recovery_capabilities=("rebuild_candidate",),
        )

    @staticmethod
    def type_specs() -> tuple[TypeSpec, ...]:
        return graph_type_specs()

    def register_types(self) -> tuple[str, ...]:
        return tuple(spec.name for spec in self.type_specs())

    def proposal_for(self, envelope: CommandEnvelope, typed_writes: tuple[GraphWrite, ...],
                     dependencies: DependencySet | None = None) -> DomainProposal:
        if not isinstance(envelope, CommandEnvelope):
            raise TypeError("envelope must be CommandEnvelope")
        proposal = DomainProposal(
            "d12", self._PROPOSAL_SCHEMA, self._PROPOSAL_HASH, envelope,
            typed_writes, dependencies or DependencySet(), (), (),
        )
        return self.validate(proposal)

    def validate(self, proposal: DomainProposal, snapshot: object = None) -> DomainProposal:
        if not isinstance(proposal, DomainProposal):
            raise TypeError("proposal must be DomainProposal")
        if (proposal.domain, proposal.proposal_schema, proposal.proposal_schema_hash) != (
            "d12", self._PROPOSAL_SCHEMA, self._PROPOSAL_HASH,
        ):
            raise ValueError("D12 proposal schema is not registered")
        specs = {spec.name: spec for spec in self.type_specs()}
        for write in proposal.typed_writes:
            if write.key.type_name == "d12.active_scheme_head.v1":
                raise ValueError("active scheme head requires W01 atomic adoption")
            spec = specs.get(write.key.type_name)
            if spec is None or write.key.owner.kind not in spec.owner_kinds:
                raise ValueError("D12 may write only its administrative candidate types")
            spec.validator(write.value)
        return proposal
