"""Pure D05 validators and projections; no secondary relationship store."""

from dataclasses import dataclass, fields, replace
import hashlib
import json
import math

from ...graph_types import TypeSpec
from ...runtime_contracts import DomainProposal, ProviderDescriptor, schema_hash


def _id(value: str, label: str, prefix: str | None = None) -> None:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} must be a nonempty string")
    if prefix and not value.startswith(prefix):
        raise ValueError(f"{label} must start with {prefix!r}")


def _time(value: float | int, label: str) -> float:
    if type(value) not in (int, float) or not math.isfinite(value):
        raise ValueError(f"{label} must be finite")
    return float(value)


def _refs(values: tuple[str, ...], label: str) -> tuple[str, ...]:
    if not isinstance(values, tuple) or not values or len(values) != len(set(values)):
        raise ValueError(f"{label} must be a nonempty tuple without duplicates")
    for value in values:
        _id(value, label)
    return values


def _tuple_payload(payload: dict, *fields: str) -> dict:
    if not isinstance(payload, dict):
        raise TypeError("graph payload must be an object")
    decoded = dict(payload)
    for field in fields:
        if field in decoded and isinstance(decoded[field], list):
            decoded[field] = tuple(decoded[field])
    return decoded


def _strict_payload(payload: object, value_type: type, *tuple_fields: str) -> None:
    if type(payload) is not dict:
        raise TypeError("graph payload must be an object")
    expected = {field.name for field in fields(value_type)}
    actual = set(payload)
    if actual != expected:
        raise ValueError(
            f"{value_type.__name__} payload fields must match exactly; "
            f"missing={sorted(expected - actual)!r}, extra={sorted(actual - expected)!r}"
        )
    value_type(**_tuple_payload(payload, *tuple_fields))


def _validate_relationship_projection(payload: object) -> None:
    if type(payload) is not dict:
        raise TypeError("graph payload must be an object")
    expected = {"subject_entity_ref", "dimension", "status"}
    if set(payload) != expected:
        raise ValueError("relationship projection has an exact shape")
    _id(payload["subject_entity_ref"], "subject_entity_ref", "entity:")
    _id(payload["dimension"], "dimension")
    _id(payload["status"], "status")


@dataclass(frozen=True)
class RelationshipContribution:
    owner_persona_ref: str
    canonical_event_or_family_ref: str
    subject_entity_ref: str
    target_dimension: str
    semantics: str
    contribution_revision: int
    source_refs: tuple[str, ...]

    def __post_init__(self) -> None:
        _id(self.owner_persona_ref, "owner_persona_ref", "persona:")
        _id(self.canonical_event_or_family_ref, "canonical_event_or_family_ref")
        _id(self.subject_entity_ref, "subject_entity_ref", "entity:")
        _id(self.target_dimension, "target_dimension")
        if self.semantics not in {"external_observation", "recollection", "simulation"}:
            raise ValueError("unsupported contribution semantics")
        if type(self.contribution_revision) is not int or self.contribution_revision < 1:
            raise ValueError("contribution_revision must be positive")
        _refs(self.source_refs, "source_refs")

    @property
    def key(self) -> str:
        body = (self.owner_persona_ref, self.canonical_event_or_family_ref,
                self.subject_entity_ref, self.target_dimension, self.semantics)
        digest = hashlib.sha256(json.dumps(body, separators=(",", ":")).encode("utf-8")).hexdigest()
        return f"contribution:{digest}"

    def with_revision(self, revision: int) -> "RelationshipContribution":
        return replace(self, contribution_revision=revision)


@dataclass(frozen=True)
class BoundaryRule:
    rule_id: str
    subject_persona_ref: str
    target_entity_ref: str
    action_kind: str
    audience_scope: str
    scene_ref: str | None
    effect: str
    basis: str
    source_refs: tuple[str, ...]
    communicated_refs: tuple[str, ...]
    acknowledged_refs: tuple[str, ...]
    valid_from: float
    valid_until: float | None
    scope_version: int
    revision_actor: str
    exception_refs: tuple[str, ...]
    status: str

    def __post_init__(self) -> None:
        _id(self.rule_id, "rule_id", "boundary:")
        _id(self.subject_persona_ref, "subject_persona_ref", "persona:")
        _id(self.target_entity_ref, "target_entity_ref", "entity:")
        _id(self.action_kind, "action_kind")
        _id(self.audience_scope, "audience_scope")
        if self.scene_ref is not None:
            _id(self.scene_ref, "scene_ref", "scene:")
        if self.effect not in {"deny", "allow"}:
            raise ValueError("unsupported boundary effect")
        if self.basis not in {"runtime_policy", "counterparty_explicit", "self_internal", "mutual_agreement", "inferred_preference"}:
            raise ValueError("unsupported boundary basis")
        _refs(self.source_refs, "source_refs")
        if not isinstance(self.communicated_refs, tuple) or not isinstance(self.acknowledged_refs, tuple):
            raise ValueError("boundary receipt refs must be tuples")
        _time(self.valid_from, "valid_from")
        if self.valid_until is not None and _time(self.valid_until, "valid_until") < self.valid_from:
            raise ValueError("valid_until precedes valid_from")
        if type(self.scope_version) is not int or self.scope_version < 1:
            raise ValueError("scope_version must be positive")
        _id(self.revision_actor, "revision_actor")
        if not isinstance(self.exception_refs, tuple):
            raise ValueError("exception_refs must be a tuple")
        if self.status not in {"active", "superseded", "revoked"}:
            raise ValueError("unsupported boundary status")

    def applies_to(self, *, subject_persona_ref: str, target_entity_ref: str,
                   action_kind: str, audience_scope: str, scene_ref: str | None,
                   at_time: float) -> bool:
        return (
            self.status == "active"
            and self.subject_persona_ref == subject_persona_ref
            and self.target_entity_ref == target_entity_ref
            and self.action_kind == action_kind
            and self.audience_scope == audience_scope
            and (self.scene_ref is None or self.scene_ref == scene_ref)
            and self.valid_from <= at_time
            and (self.valid_until is None or at_time <= self.valid_until)
        )


@dataclass(frozen=True)
class BoundaryCheck:
    result: str
    matched_rule_ids: tuple[str, ...]
    missing_items: tuple[str, ...]


@dataclass(frozen=True)
class InvalidationResult:
    current_status: str
    historical_refs: tuple[str, ...]


class RelationshipProvider:
    """D05 projection and validation only; W01 owns adoption and epochs."""

    def __init__(self) -> None:
        self._dimensions: frozenset[str] = frozenset()
        self._semantics: frozenset[str] = frozenset()

    @property
    def descriptor(self) -> ProviderDescriptor:
        return ProviderDescriptor(
            provider_id="d05.relationship", contract_version="sylanne.runtime.v1",
            request_schema_hash=schema_hash({"domain": "d05", "request": 1}),
            response_schema_hash=schema_hash({"domain": "d05", "response": 1}),
            owner_capabilities=("persona", "relation"), supported_modalities=("text",),
            supported_purposes=("respond", "check", "project"), supported_platforms=("astrbot",),
            timeout_mode="bounded", cancellation_mode="cooperative", idempotency_mode="operation_id",
            cost_reporting_mode="actual_or_unconfirmed", health_capabilities=("probe",),
            recovery_capabilities=("query_operation",),
        )

    def type_specs(self) -> tuple[TypeSpec, ...]:
        layouts = (
            (
                "d05.contribution", ("relation",), "state",
                lambda value: _strict_payload(value, RelationshipContribution, "source_refs"),
                tuple(field.name for field in fields(RelationshipContribution)),
            ),
            (
                "d05.boundary_rule", ("relation",), "state",
                lambda value: _strict_payload(
                    value, BoundaryRule, "source_refs", "communicated_refs",
                    "acknowledged_refs", "exception_refs",
                ),
                tuple(field.name for field in fields(BoundaryRule)),
            ),
            (
                "d05.relationship_projection", ("relation",), "projection",
                _validate_relationship_projection,
                ("subject_entity_ref", "dimension", "status"),
            ),
        )
        return tuple(TypeSpec(
            name,
            owners,
            storage,
            validator,
            writer_domain="d05",
            schema_hash=schema_hash({
                "type": name,
                "schema_version": 1,
                "owner_kinds": sorted(owners),
                "storage_role": storage,
                "fields": field_names,
            }),
        ) for name, owners, storage, validator, field_names in layouts)

    def register_types(self) -> tuple[str, ...]:
        return tuple(spec.name for spec in self.type_specs())

    def validate(self, proposal: DomainProposal, snapshot: object) -> DomainProposal:
        if not isinstance(proposal, DomainProposal):
            raise TypeError("proposal must be DomainProposal")
        if proposal.domain != "d05":
            raise ValueError("D05 provider cannot validate another domain's candidate")
        if proposal.proposal_schema != "d05.proposal.v1":
            raise ValueError("unsupported D05 proposal schema")
        allowed_types = frozenset(self.register_types())
        if any(write.key.type_name not in allowed_types for write in proposal.typed_writes):
            raise ValueError("D05 candidates may only contain D05 graph writes")
        decoders = {
            "d05.contribution": lambda value: RelationshipContribution(**_tuple_payload(value, "source_refs")),
            "d05.boundary_rule": lambda value: BoundaryRule(**_tuple_payload(
                value, "source_refs", "communicated_refs", "acknowledged_refs", "exception_refs"
            )),
        }
        for write in proposal.typed_writes:
            if write.key.type_name == "d05.relationship_projection":
                if set(write.value) != {"subject_entity_ref", "dimension", "status"}:
                    raise ValueError("relationship projection has an exact shape")
                _id(write.value["subject_entity_ref"], "subject_entity_ref", "entity:")
                self.validate_dimension(write.value["dimension"])
                _id(write.value["status"], "status")
            else:
                decoders[write.key.type_name](write.value)
        return proposal

    def compile_scheme(self, draft: dict, snapshot: object) -> dict:
        if not isinstance(draft, dict) or set(draft) != {"schema", "dimensions", "contribution_semantics"}:
            raise ValueError("D05 scheme has an exact shape")
        if draft["schema"] != "d05.relationship.scheme.v1":
            raise ValueError("unsupported D05 scheme")
        dimensions = _refs(draft["dimensions"], "dimensions")
        semantics = _refs(draft["contribution_semantics"], "contribution_semantics")
        if not set(semantics) <= {"external_observation", "recollection", "simulation"}:
            raise ValueError("unsupported scheme contribution semantics")
        self._dimensions = frozenset(dimensions)
        self._semantics = frozenset(semantics)
        return {"schema": draft["schema"], "dimensions": dimensions, "contribution_semantics": semantics}

    def validate_dimension(self, dimension: str) -> None:
        _id(dimension, "dimension")
        if dimension not in self._dimensions:
            raise ValueError("dimension is not registered by the active scheme")

    def provide_required_check(
        self, *, subject_persona_ref: str, target_entity_ref: str, action_kind: str,
        audience_scope: str, scene_ref: str | None, at_time: float,
        rules: tuple[BoundaryRule, ...], coverage_complete: bool,
    ) -> BoundaryCheck:
        _id(subject_persona_ref, "subject_persona_ref", "persona:")
        _id(target_entity_ref, "target_entity_ref", "entity:")
        _id(action_kind, "action_kind")
        _id(audience_scope, "audience_scope")
        if scene_ref is not None:
            _id(scene_ref, "scene_ref", "scene:")
        _time(at_time, "at_time")
        if type(coverage_complete) is not bool:
            raise ValueError("coverage_complete must be bool")
        if not isinstance(rules, tuple) or any(not isinstance(rule, BoundaryRule) for rule in rules):
            raise TypeError("rules must be BoundaryRule values")
        if not coverage_complete:
            return BoundaryCheck("unknown", (), ("boundary_coverage",))
        matches = tuple(rule for rule in rules if rule.applies_to(
            subject_persona_ref=subject_persona_ref, target_entity_ref=target_entity_ref,
            action_kind=action_kind, audience_scope=audience_scope, scene_ref=scene_ref,
            at_time=at_time,
        ))
        denied = tuple(sorted(rule.rule_id for rule in matches if rule.effect == "deny"))
        if denied:
            return BoundaryCheck("deny", denied, ())
        allowed = tuple(sorted(rule.rule_id for rule in matches if rule.effect == "allow"))
        if len(allowed) > 1:
            return BoundaryCheck("conflict", allowed, ("multiple_allow_rules",))
        return BoundaryCheck("pass" if allowed else "pass", allowed, ())

    def invalidate(self, refs: tuple[str, ...]) -> InvalidationResult:
        if not isinstance(refs, tuple) or not refs:
            raise ValueError("refs must be a nonempty tuple")
        for ref in refs:
            _id(ref, "ref")
        return InvalidationResult("blocked_rebuild", tuple(sorted(refs)))

    def project(self, query: dict, snapshot: tuple[BoundaryRule, ...]) -> BoundaryCheck:
        if not isinstance(query, dict):
            raise TypeError("query must be a mapping")
        return self.provide_required_check(rules=snapshot, **query)

    def cleanup(self, plan: object) -> dict:
        return {"domain": "d05", "status": "delegated_to_runtime", "plan": plan}
