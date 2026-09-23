"""Pure D03 candidate validation and projection.

This module owns no storage.  W01 supplies the authorised graph transaction;
D06 supplies source eligibility, and D08 consumes the resulting checks.
"""

from dataclasses import dataclass, fields
import math

from ...graph_types import TypeSpec
from ...runtime_contracts import DomainProposal, ProviderDescriptor, schema_hash


def _id(value: str, label: str, prefix: str | None = None) -> None:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} must be a nonempty string")
    if prefix is not None and not value.startswith(prefix):
        raise ValueError(f"{label} must start with {prefix!r}")


def _time(value: float | int, label: str) -> float:
    if type(value) not in (int, float) or not math.isfinite(value):
        raise ValueError(f"{label} must be finite")
    return float(value)


def _optional_time(value: float | int | None, label: str) -> float | None:
    return None if value is None else _time(value, label)


def _refs(values: tuple[str, ...], label: str, *, nonempty: bool = True) -> tuple[str, ...]:
    if not isinstance(values, tuple) or (nonempty and not values):
        raise ValueError(f"{label} must be a {'nonempty ' if nonempty else ''}tuple")
    if len(set(values)) != len(values):
        raise ValueError(f"{label} must not repeat references")
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


@dataclass(frozen=True)
class EntityAnchor:
    entity_id: str
    kind: str
    owner_scope: str
    creation_evidence_refs: tuple[str, ...]
    status: str

    def __post_init__(self) -> None:
        _id(self.entity_id, "entity_id", "entity:")
        if self.kind not in {"person", "account", "group", "place", "object", "activity"}:
            raise ValueError("unsupported entity kind")
        _id(self.owner_scope, "owner_scope")
        _refs(self.creation_evidence_refs, "creation_evidence_refs")
        if self.status not in {"active", "ambiguous", "retired"}:
            raise ValueError("unsupported entity status")


@dataclass(frozen=True)
class AccountBinding:
    account_id: str
    platform_namespace: str
    platform_identifier: str
    entity_id: str
    verification_ref: str
    valid_from: float
    valid_until: float | None

    def __post_init__(self) -> None:
        _id(self.account_id, "account_id", "account:")
        _id(self.platform_namespace, "platform_namespace")
        _id(self.platform_identifier, "platform_identifier")
        _id(self.entity_id, "entity_id", "entity:")
        _id(self.verification_ref, "verification_ref")
        start = _time(self.valid_from, "valid_from")
        if self.valid_until is not None and _time(self.valid_until, "valid_until") < start:
            raise ValueError("valid_until precedes valid_from")


@dataclass(frozen=True)
class WorldEvent:
    event_id: str
    kind: str
    participant_roles: tuple[tuple[str, str], ...]
    occurred_from: float | None
    occurred_until: float | None
    learned_at: float
    scene_ref: str
    source_refs: tuple[str, ...]
    reality: str

    def __post_init__(self) -> None:
        _id(self.event_id, "event_id", "world:")
        _id(self.kind, "kind")
        if not isinstance(self.participant_roles, tuple) or not self.participant_roles:
            raise ValueError("participant_roles must be nonempty")
        for entity_id, role in self.participant_roles:
            _id(entity_id, "participant entity", "entity:")
            _id(role, "participant role")
        start = _optional_time(self.occurred_from, "occurred_from")
        end = _optional_time(self.occurred_until, "occurred_until")
        if start is not None and end is not None and end < start:
            raise ValueError("occurred_until precedes occurred_from")
        _time(self.learned_at, "learned_at")
        _id(self.scene_ref, "scene_ref", "scene:")
        _refs(self.source_refs, "source_refs")
        if self.reality not in {"host_observed", "reported", "candidate", "simulated"}:
            raise ValueError("unsupported reality")


@dataclass(frozen=True)
class RoleBinding:
    role_binding_id: str
    subject_persona_ref: str
    social_role: str
    target_entity_ref: str | None
    group_ref: str | None
    scene_ref: str | None
    scope_selector: str
    visibility_scope: str
    norm_refs: tuple[str, ...]
    effective_from: float
    effective_until: float | None
    precedence: int
    source_refs: tuple[str, ...]
    binding_version: int
    status: str

    def __post_init__(self) -> None:
        _id(self.role_binding_id, "role_binding_id", "binding:")
        _id(self.subject_persona_ref, "subject_persona_ref", "persona:")
        _id(self.social_role, "social_role")
        if not any((self.target_entity_ref, self.group_ref, self.scene_ref)):
            raise ValueError("a role binding requires target, group, or scene scope")
        if self.target_entity_ref is not None:
            _id(self.target_entity_ref, "target_entity_ref", "entity:")
        if self.group_ref is not None:
            _id(self.group_ref, "group_ref")
        if self.scene_ref is not None:
            _id(self.scene_ref, "scene_ref", "scene:")
        _id(self.scope_selector, "scope_selector")
        _id(self.visibility_scope, "visibility_scope")
        _refs(self.norm_refs, "norm_refs")
        start = _time(self.effective_from, "effective_from")
        if self.effective_until is not None and _time(self.effective_until, "effective_until") < start:
            raise ValueError("effective_until precedes effective_from")
        if type(self.precedence) is not int:
            raise ValueError("precedence must be an integer")
        _refs(self.source_refs, "source_refs")
        if type(self.binding_version) is not int or self.binding_version < 1:
            raise ValueError("binding_version must be positive")
        if self.status not in {"active", "review", "revoked"}:
            raise ValueError("unsupported binding status")

    def applies_to(self, request: "RoleBindingRequest") -> bool:
        if self.status != "active" or not (self.effective_from <= request.at_time):
            return False
        if self.effective_until is not None and request.at_time > self.effective_until:
            return False
        return (
            self.subject_persona_ref == request.subject_persona_ref
            and (self.target_entity_ref is None or self.target_entity_ref == request.target_entity_ref)
            and (self.group_ref is None or self.group_ref == request.group_ref)
            and (self.scene_ref is None or self.scene_ref == request.scene_ref)
        )


@dataclass(frozen=True)
class RoleBindingRequest:
    subject_persona_ref: str
    target_entity_ref: str | None
    group_ref: str | None
    scene_ref: str | None
    requested_action_kind: str
    purpose: str
    at_time: float
    scope_complete: bool

    def __post_init__(self) -> None:
        _id(self.subject_persona_ref, "subject_persona_ref", "persona:")
        for value, label, prefix in ((self.target_entity_ref, "target_entity_ref", "entity:"),
                                     (self.group_ref, "group_ref", None),
                                     (self.scene_ref, "scene_ref", "scene:")):
            if value is not None:
                _id(value, label, prefix)
        _id(self.requested_action_kind, "requested_action_kind")
        _id(self.purpose, "purpose")
        _time(self.at_time, "at_time")
        if type(self.scope_complete) is not bool:
            raise ValueError("scope_complete must be bool")


@dataclass(frozen=True)
class RoleBindingResolution:
    status: str
    matched_bindings: tuple[str, ...]
    applicable_norm_refs: tuple[str, ...]
    missing_items: tuple[str, ...]


class ContextProvider:
    """D03 pure provider; graph commits and source checks remain external."""

    def __init__(self) -> None:
        self._roles: frozenset[str] = frozenset()
        self._norms: frozenset[str] = frozenset()

    @property
    def descriptor(self) -> ProviderDescriptor:
        return ProviderDescriptor(
            provider_id="d03.context", contract_version="sylanne.runtime.v1",
            request_schema_hash=schema_hash({"domain": "d03", "request": 1}),
            response_schema_hash=schema_hash({"domain": "d03", "response": 1}),
            owner_capabilities=("persona", "scene", "event"), supported_modalities=("text",),
            supported_purposes=("respond", "check", "project"), supported_platforms=("astrbot",),
            timeout_mode="bounded", cancellation_mode="cooperative", idempotency_mode="operation_id",
            cost_reporting_mode="actual_or_unconfirmed", health_capabilities=("probe",),
            recovery_capabilities=("query_operation",),
        )

    def type_specs(self) -> tuple[TypeSpec, ...]:
        layouts = (
            ("d03.entity_anchor", ("persona",), "state", EntityAnchor,
             ("creation_evidence_refs",)),
            ("d03.account_binding", ("persona",), "state", AccountBinding, ()),
            ("d03.world_event", ("event",), "state", WorldEvent,
             ("participant_roles", "source_refs")),
            ("d03.role_binding", ("persona", "scene"), "state", RoleBinding,
             ("norm_refs", "source_refs")),
        )
        result = []
        for name, owners, storage, value_type, tuple_fields in layouts:
            field_names = tuple(field.name for field in fields(value_type))
            digest = schema_hash({
                "type": name,
                "schema_version": 1,
                "owner_kinds": sorted(owners),
                "storage_role": storage,
                "fields": field_names,
            })
            validator = lambda value, cls=value_type, names=tuple_fields: _strict_payload(
                value, cls, *names
            )
            result.append(TypeSpec(
                name, owners, storage, validator,
                writer_domain="d03", schema_hash=digest,
            ))
        return tuple(result)

    def register_types(self) -> tuple[str, ...]:
        return tuple(spec.name for spec in self.type_specs())

    def validate(self, proposal: DomainProposal, snapshot: object) -> DomainProposal:
        if not isinstance(proposal, DomainProposal):
            raise TypeError("proposal must be DomainProposal")
        if proposal.domain != "d03":
            raise ValueError("D03 provider cannot validate another domain's candidate")
        if proposal.proposal_schema != "d03.proposal.v1":
            raise ValueError("unsupported D03 proposal schema")
        allowed_types = frozenset(self.register_types())
        if any(write.key.type_name not in allowed_types for write in proposal.typed_writes):
            raise ValueError("D03 candidates may only contain D03 graph writes")
        decoders = {
            "d03.entity_anchor": lambda value: EntityAnchor(**_tuple_payload(value, "creation_evidence_refs")),
            "d03.account_binding": lambda value: AccountBinding(**_tuple_payload(value)),
            "d03.world_event": lambda value: WorldEvent(**_tuple_payload(value, "participant_roles", "source_refs")),
            "d03.role_binding": lambda value: RoleBinding(**_tuple_payload(value, "norm_refs", "source_refs")),
        }
        for write in proposal.typed_writes:
            decoders[write.key.type_name](write.value)
        return proposal

    def compile_scheme(self, draft: dict, snapshot: object) -> dict:
        if not isinstance(draft, dict) or set(draft) != {"schema", "roles", "norms"}:
            raise ValueError("D03 scheme has an exact shape")
        if draft["schema"] != "d03.context.scheme.v1":
            raise ValueError("unsupported D03 scheme")
        roles = _refs(draft["roles"], "roles")
        norms = _refs(draft["norms"], "norms", nonempty=False)
        self._roles = frozenset(roles)
        self._norms = frozenset(norms)
        return {"schema": draft["schema"], "roles": roles, "norms": norms}

    def resolve_role_binding(
        self, request: RoleBindingRequest, bindings: tuple[RoleBinding, ...]
    ) -> RoleBindingResolution:
        if not isinstance(request, RoleBindingRequest):
            raise TypeError("request must be RoleBindingRequest")
        if not isinstance(bindings, tuple) or any(not isinstance(item, RoleBinding) for item in bindings):
            raise TypeError("bindings must be RoleBinding values")
        matches = tuple(sorted((item for item in bindings if item.applies_to(request)),
                               key=lambda item: (-item.precedence, item.role_binding_id)))
        if not request.scope_complete:
            return RoleBindingResolution("partial", (), (), ("scope_coverage",))
        if not matches:
            return RoleBindingResolution("no_applicable_binding", (), (), ())
        unknown_norms = tuple(sorted({ref for item in matches for ref in item.norm_refs} - self._norms))
        if unknown_norms:
            return RoleBindingResolution("partial", (), (), ("norm_catalogue",))
        return RoleBindingResolution(
            "complete",
            tuple(item.role_binding_id for item in matches),
            tuple(sorted({ref for item in matches for ref in item.norm_refs})),
            (),
        )

    def project(self, query: RoleBindingRequest, snapshot: tuple[RoleBinding, ...]) -> RoleBindingResolution:
        return self.resolve_role_binding(query, snapshot)

    def invalidate(self, refs: tuple[str, ...]) -> tuple[str, ...]:
        return _refs(refs, "refs")

    def cleanup(self, plan: object) -> dict:
        return {"domain": "d03", "status": "delegated_to_runtime", "plan": plan}
