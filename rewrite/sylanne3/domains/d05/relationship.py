"""Pure D05 validators and projections; no secondary relationship store."""

from dataclasses import dataclass, fields, replace
import hashlib
import json
import math
import re
from collections.abc import Callable

from ...graph_types import AtomKey, TypeSpec
from ...runtime_contracts import (
    CheckReceipt,
    DomainProposal,
    NamespaceId,
    ProviderDescriptor,
    QueryEpoch,
    VersionedRef,
    schema_hash,
)
from ..d08.execution import ActionIntent, ActionSchema


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
class BoundaryRuleReadSet:
    """One D05 boundary query result, tied to a complete graph read.

    The read verifier is supplied by the trusted graph integration. A caller
    assertion such as ``coverage_complete=True`` is not sufficient evidence.
    ``input_versions`` includes the query-scope epoch and every current rule
    revision returned by that query.
    """

    namespace: NamespaceId
    query_epoch: QueryEpoch | None
    rules: tuple[BoundaryRule, ...]
    input_versions: tuple[VersionedRef, ...]
    coverage: str
    missing_items: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.namespace, NamespaceId):
            raise TypeError("namespace must be NamespaceId")
        if self.query_epoch is not None and not isinstance(self.query_epoch, QueryEpoch):
            raise TypeError("query_epoch must be QueryEpoch or None")
        if not isinstance(self.rules, tuple) or any(type(item) is not BoundaryRule for item in self.rules):
            raise TypeError("rules must be a tuple of BoundaryRule values")
        if not isinstance(self.input_versions, tuple) or any(
            type(item) is not VersionedRef for item in self.input_versions
        ):
            raise TypeError("input_versions must be a tuple of VersionedRef values")
        if len({item.ref for item in self.input_versions}) != len(self.input_versions):
            raise ValueError("input_versions cannot repeat a ref")
        if self.coverage not in {"full", "partial", "none"}:
            raise ValueError("coverage must be full, partial, or none")
        if not isinstance(self.missing_items, tuple):
            raise TypeError("missing_items must be a tuple")
        if any(not isinstance(item, str) or not item for item in self.missing_items):
            raise ValueError("missing_items must contain nonempty strings")
        if self.query_epoch is not None and self.query_epoch.namespace != self.namespace:
            raise ValueError("query epoch namespace differs from read namespace")


@dataclass(frozen=True)
class InvalidationResult:
    current_status: str
    historical_refs: tuple[str, ...]


class RelationshipProvider:
    """D05 projection and validation only; W01 owns adoption and epochs."""

    def __init__(self, *, boundary_read_verifier: Callable[[BoundaryRuleReadSet], bool] | None = None) -> None:
        self._dimensions: frozenset[str] = frozenset()
        self._semantics: frozenset[str] = frozenset()
        self._boundary_read_verifier = boundary_read_verifier

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

    @property
    def workbench_view_contract(self) -> dict[str, dict[str, object]]:
        return {"relations": {
            "types": ("d05.relationship_projection",),
            "fields": ("relations", "coverage"),
            "projection_context": "d12.projection_context.v2",
        }}

    @staticmethod
    def project_workbench(view_type: str, atoms: tuple[dict, ...], *, context: object) -> dict:
        """Show committed subjective statuses without source or boundary metadata."""
        from ...graph_coordinator import verify_complete_projection_snapshot_v1
        from ...workbench_api.domain_registry import ProjectionContextV2

        types = ("d05.relationship_projection",)
        if view_type != "relations" or type(context) is not ProjectionContextV2:
            raise ValueError("unsupported D05 workbench projection context")
        if not verify_complete_projection_snapshot_v1(
            context.snapshot_proof, authority=context.authority, view_type=view_type,
            type_names=types, owner_kind="relation", audience=context.audience,
            purpose=context.purpose,
        ):
            raise ValueError("complete fenced snapshot proof is unavailable")
        if type(atoms) is not tuple:
            raise TypeError("atoms must be a tuple")

        relations: dict[str, dict] = {}
        seen_dimensions: set[tuple[str, str]] = set()
        for atom in atoms:
            if type(atom) is not dict or set(atom) != {"key", "type", "name", "revision", "value"}:
                raise ValueError("D05 workbench atom has an invalid shape")
            key = AtomKey.from_token(atom["key"])
            atom_type = atom["type"]
            if (key.type_name != atom_type or key.name != atom["name"]
                    or atom_type not in types or key.owner.kind != "relation"
                    or (key.owner.bot, key.owner.persona) != context.authority.namespace.as_tuple
                    or type(atom["revision"]) is not int or atom["revision"] < 1):
                raise ValueError("D05 workbench atom crosses its graph scope")
            value = atom["value"]
            _validate_relationship_projection(value)
            subject = value["subject_entity_ref"]
            dimension = value["dimension"]
            if (re.fullmatch(r"entity:[A-Za-z0-9_.:-]{1,96}", subject) is None
                    or re.fullmatch(r"[A-Za-z0-9_.:-]{1,96}", dimension) is None
                    or value["status"] not in {
                        "unknown", "available", "unavailable", "stale", "blocked_rebuild",
                        "rebuilt", "sanitized", "reset",
                    }):
                raise ValueError("relationship projection has no public status token")
            if (subject, dimension) in seen_dimensions:
                raise ValueError("duplicate relationship dimension")
            seen_dimensions.add((subject, dimension))
            if key.owner.subject != subject:
                raise ValueError("relation subject differs from graph Owner")
            relation = relations.setdefault(subject, {
                "subject_entity_ref": subject, "dimensions": [],
            })
            relation["dimensions"].append({"dimension": dimension, "status": value["status"]})
        for relation in relations.values():
            relation["dimensions"].sort(key=lambda item: item["dimension"])
        return {"relations": [relations[subject] for subject in sorted(relations)],
                "coverage": "complete"}

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

    def boundary_required_check(
        self,
        intent: ActionIntent,
        schema: ActionSchema,
        read_set: BoundaryRuleReadSet,
        *,
        audience_scope: str,
        scene_ref: str | None,
        at_time: float,
        valid_until: float,
    ) -> CheckReceipt:
        """Return D05's candidate boundary check for D08.

        Passing only means the boundary query is complete/current and no
        applicable D05 rule denies this action. D11 must still revalidate the
        graph and all action qualifications before any real dispatch.
        """
        if type(intent) is not ActionIntent or type(schema) is not ActionSchema:
            raise TypeError("intent and action schema must be D08 values")
        if type(read_set) is not BoundaryRuleReadSet:
            raise TypeError("read_set must be BoundaryRuleReadSet")
        _id(audience_scope, "audience_scope")
        if scene_ref is not None:
            _id(scene_ref, "scene_ref", "scene:")
        timestamp = _time(at_time, "at_time")
        expiry = _time(valid_until, "valid_until")

        check_kind = "boundary"
        provider_id = "d05.boundary"
        schema_specs = tuple(item for item in schema.required_checks
                             if item.check_kind == check_kind and item.provider_id == provider_id)
        intent_specs = tuple(item for item in intent.required_checks
                             if item.check_kind == check_kind and item.provider_id == provider_id)
        if len(schema_specs) != 1 or len(intent_specs) != 1:
            raise ValueError("schema and intent must contain exactly one D05 boundary check")
        spec = schema_specs[0]
        if (schema.schema_id != intent.schema_id or schema.action_kind != intent.action_kind
                or spec != intent_specs[0] or spec.action_ref != intent.action_id
                or spec.purpose != intent.purpose or intent.action_kind != schema.action_kind):
            raise ValueError("D05 boundary check does not match the frozen D08 action")
        _id(spec.subject_ref, "subject_ref", "persona:")
        _id(intent.target_ref, "target_ref", "entity:")

        epoch = read_set.query_epoch
        epoch_version = (VersionedRef("d05.boundary", epoch.revision)
                         if epoch is not None and epoch.scope_ref == "d05.boundary" else None)
        rule_versions = tuple(sorted(
            (VersionedRef(rule.rule_id, rule.scope_version) for rule in read_set.rules),
            key=lambda item: item.ref,
        ))
        graph_versions = tuple(sorted(
            ((VersionedRef(spec.criteria_version,
                           next(item.version for item in spec.required_input_versions
                                if item.ref == spec.criteria_version)),)
             + ((epoch_version,) if epoch_version is not None else ()) + rule_versions),
            key=lambda item: item.ref,
        ))
        observed = read_set.input_versions
        exact_versions = (
            len({item.ref for item in graph_versions}) == len(graph_versions)
            and set(observed) == set(graph_versions)
            and set(observed) == set(spec.required_input_versions)
        )
        scope_matches = (
            read_set.namespace.persona_id == spec.subject_ref.removeprefix("persona:")
            and epoch is not None and epoch.scope_ref == "d05.boundary"
            and all(rule.subject_persona_ref == spec.subject_ref
                    and rule.target_entity_ref == intent.target_ref
                    for rule in read_set.rules)
        )
        trusted_current = False
        if self._boundary_read_verifier is not None:
            try:
                trusted_current = self._boundary_read_verifier(read_set) is True
            except Exception:
                trusted_current = False
        complete = (
            trusted_current and scope_matches and read_set.coverage == "full"
            and not read_set.missing_items and exact_versions
            and expiry >= timestamp
        )
        if not complete:
            coverage = "full" if read_set.coverage == "full" and scope_matches else read_set.coverage
            return CheckReceipt(spec.check_kind, spec.subject_ref, spec.action_ref, spec.purpose,
                                observed, coverage, "unknown", timestamp, provider_id)

        matches = tuple(rule for rule in read_set.rules if rule.applies_to(
            subject_persona_ref=spec.subject_ref,
            target_entity_ref=intent.target_ref,
            action_kind=intent.action_kind,
            audience_scope=audience_scope,
            scene_ref=scene_ref,
            at_time=timestamp,
        ))
        revoked_or_superseded = tuple(
            rule for rule in read_set.rules
            if rule.status in {"revoked", "superseded"}
            and rule.subject_persona_ref == spec.subject_ref
            and rule.target_entity_ref == intent.target_ref
            and rule.action_kind == intent.action_kind
            and rule.audience_scope == audience_scope
            and (rule.scene_ref is None or rule.scene_ref == scene_ref)
            and rule.valid_from <= timestamp
            and (rule.valid_until is None or timestamp <= rule.valid_until)
        )
        if revoked_or_superseded:
            return CheckReceipt(spec.check_kind, spec.subject_ref, spec.action_ref, spec.purpose,
                                spec.required_input_versions, "full", "unknown", timestamp, provider_id)
        denied = tuple(item for item in matches if item.effect == "deny")
        allowed = tuple(item for item in matches if item.effect == "allow")
        if denied and allowed or len(allowed) > 1:
            result = "unknown"
        elif denied:
            result = "fail"
        else:
            result = "pass"
        rule_expiries = tuple(item.valid_until for item in matches if item.valid_until is not None)
        check_expiry = min((expiry, *rule_expiries)) if rule_expiries else expiry
        return CheckReceipt(spec.check_kind, spec.subject_ref, spec.action_ref, spec.purpose,
                            spec.required_input_versions, "full", result, check_expiry, provider_id)

    def invalidate(self, refs: tuple[str, ...]) -> InvalidationResult:
        raise ValueError("D05 invalidation requires a current correction snapshot and W01 adoption")

    def project(self, query: dict, snapshot: tuple[BoundaryRule, ...]) -> BoundaryCheck:
        if not isinstance(query, dict):
            raise TypeError("query must be a mapping")
        return self.provide_required_check(rules=snapshot, **query)

    def cleanup(self, plan: object) -> dict:
        return {"domain": "d05", "status": "delegated_to_runtime", "plan": plan}
