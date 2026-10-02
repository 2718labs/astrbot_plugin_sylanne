"""Pure D03 candidate validation and projection.

This module owns no storage.  W01 supplies the authorised graph transaction;
D06 supplies source eligibility, and D08 consumes the resulting checks.
"""

from dataclasses import asdict, dataclass, fields
import math

from ...authority_service.v2_owner_contract import OwnerAuthorizationGuardV1
from ...domains.d01 import ActiveRoleQualification
from ...domains.d08 import ActionIntent
from ...graph_types import AtomKey, GraphVersion, GraphWrite, NamespaceEpoch, Owner, TypeSpec
from ...memory_types import access_key, source_key
from ...runtime_contracts import (
    AuthorityContext, CheckReceipt, CommandEnvelope, DependencySet, DomainProposal,
    ProviderDescriptor, QueryEpoch, VersionedRef, schema_hash,
)


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
        _refs(self.norm_refs, "norm_refs", nonempty=False)
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
    read_versions: tuple[GraphVersion, ...] = ()
    query_epoch: QueryEpoch | None = None
    valid_until: float | None = None
    request: RoleBindingRequest | None = None


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
        from .self_perspective import SelfIdentityMapping, SelfPerspective

        layouts = (
            ("d03.entity_anchor", ("persona",), "state", EntityAnchor,
             ("creation_evidence_refs",)),
            ("d03.account_binding", ("persona",), "state", AccountBinding, ()),
            ("d03.world_event", ("event",), "state", WorldEvent,
             ("participant_roles", "source_refs")),
            ("d03.role_binding", ("persona", "scene"), "state", RoleBinding,
             ("norm_refs", "source_refs")),
            ("d03.self_identity_mapping.v1", ("persona",), "state", SelfIdentityMapping, ()),
            ("d03.self_perspective.v1", ("persona",), "state", SelfPerspective, ()),
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
        from .self_perspective import (
            SelfIdentityMapping, SelfPerspective, validate_self_perspective_snapshot,
        )

        if not isinstance(proposal, DomainProposal):
            raise TypeError("proposal must be DomainProposal")
        if proposal.domain != "d03":
            raise ValueError("D03 provider cannot validate another domain's candidate")
        if proposal.domain == 'd03' and proposal.proposal_schema == 'd03.internal-life-context.v1':
            from ...runtime.d06_life_numeric_context_v1 import validate_life_numeric_context_proposal_v1
            return validate_life_numeric_context_proposal_v1(proposal, snapshot)
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
            "d03.self_identity_mapping.v1": lambda value: SelfIdentityMapping(**_tuple_payload(value)),
            "d03.self_perspective.v1": lambda value: SelfPerspective(**_tuple_payload(value)),
        }
        # A trusted D11 mapping issuer has not been implemented. A D03 proposal
        # must never bootstrap its own proof of who the persona is.
        if any(write.key.type_name == "d03.self_identity_mapping.v1"
               for write in proposal.typed_writes):
            raise ValueError("certified self identity mapping issuer is unavailable")
        for write in proposal.typed_writes:
            decoded = decoders[write.key.type_name](write.value)
            if write.key.type_name == "d03.role_binding":
                if (write.key.name != decoded.role_binding_id
                        or (write.key.owner.kind == "scene"
                            and write.key.owner.subject != decoded.scene_ref)):
                    raise ValueError("role binding graph identity differs from its payload")
        host_events = tuple(
            write for write in proposal.typed_writes
            if write.key.type_name == "d03.world_event"
            and (write.value.get("kind") == "message_received"
                 or write.value.get("reality") == "host_observed")
        )
        if host_events and any(write.value.get("kind") != "message_received"
                               for write in host_events):
            raise ValueError("trusted host scene evidence is unavailable for host-observed events")
        if host_events:
            from .message_arrival import validate_message_arrival_snapshot
            validate_message_arrival_snapshot(proposal, snapshot)
        if any(write.key.type_name == "d03.self_perspective.v1"
               for write in proposal.typed_writes):
            validate_self_perspective_snapshot(proposal, snapshot)
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
        unknown_roles = {item.social_role for item in matches} - self._roles
        unknown_norms = {ref for item in matches for ref in item.norm_refs} - self._norms
        if unknown_roles or unknown_norms:
            missing = tuple(name for name, absent in (
                ("role_catalogue", unknown_roles), ("norm_catalogue", unknown_norms)
            ) if absent)
            return RoleBindingResolution("partial", (), (), missing)
        return RoleBindingResolution(
            "complete",
            tuple(item.role_binding_id for item in matches),
            tuple(sorted({ref for item in matches for ref in item.norm_refs})),
            (),
            valid_until=min((item.effective_until for item in matches
                             if item.effective_until is not None), default=None),
        )

    def resolve_role_binding_from_graph(
        self, request: RoleBindingRequest, coordinator: object,
        authority: AuthorityContext, lease: object,
    ) -> RoleBindingResolution:
        """Resolve only D03's binding slot from authorised current graph pages.

        The returned query epoch and read versions must be carried into the
        eventual graph commit guard. Owner status and D01 role activation are
        separate prerequisites; this method does not infer either one.
        """
        if not isinstance(request, RoleBindingRequest):
            raise TypeError("request must be RoleBindingRequest")
        if not isinstance(authority, AuthorityContext):
            raise TypeError("authority must be AuthorityContext")
        if request.subject_persona_ref != f"persona:{authority.namespace.persona_id}":
            raise ValueError("binding subject differs from authorised persona")
        if not callable(getattr(coordinator, "query", None)):
            raise TypeError("coordinator must provide authorised graph query")
        if not request.scope_complete:
            return RoleBindingResolution("partial", (), (), ("scope_coverage",))

        epoch: NamespaceEpoch | None = None
        atoms = []
        for owner_kind in ("persona", "scene"):
            after = None
            while True:
                page = coordinator.query(
                    authority, lease, type_names=("d03.role_binding",),
                    owner_kind=owner_kind, after=after, expected_epoch=epoch,
                    limit=512,
                )
                current_epoch = page.snapshot.epochs[0]
                if epoch is None:
                    epoch = current_epoch
                elif epoch != current_epoch:
                    raise ValueError("role binding query changed between pages")
                atoms.extend(page.snapshot.atoms)
                if page.next_after is None:
                    break
                after = page.next_after

        assert epoch is not None
        bindings = []
        for atom in atoms:
            binding = RoleBinding(**_tuple_payload(atom.value, "norm_refs", "source_refs"))
            if (atom.key.name != binding.role_binding_id
                    or atom.revision != binding.binding_version
                    or (atom.key.owner.kind == "scene"
                        and atom.key.owner.subject != binding.scene_ref)):
                return RoleBindingResolution(
                    "stale", (), (), ("binding_version",),
                    tuple(GraphVersion(item.key, item.revision) for item in atoms),
                    QueryEpoch(authority.namespace, "d03.role_binding", epoch.revision),
                    request=request,
                )
            bindings.append(binding)
        if len({item.role_binding_id for item in bindings}) != len(bindings):
            return RoleBindingResolution(
                "conflict", (), (), ("binding_identity",),
                tuple(GraphVersion(item.key, item.revision) for item in atoms),
                QueryEpoch(authority.namespace, "d03.role_binding", epoch.revision),
                request=request,
            )
        result = self.resolve_role_binding(request, tuple(bindings))
        return RoleBindingResolution(
            result.status, result.matched_bindings, result.applicable_norm_refs,
            result.missing_items,
            tuple(GraphVersion(atom.key, atom.revision) for atom in atoms),
            QueryEpoch(authority.namespace, "d03.role_binding", epoch.revision),
            result.valid_until,
            request,
        )

    def provide_required_check(
        self, intent: ActionIntent, resolution: RoleBindingResolution, *, valid_until: float,
    ) -> CheckReceipt:
        """Describe a D03 binding check; D11 must revalidate its graph guards."""
        if not isinstance(intent, ActionIntent) or not isinstance(resolution, RoleBindingResolution):
            raise TypeError("action intent and D03 resolution are required")
        specs = tuple(item for item in intent.required_checks
                      if item.check_kind == "role_binding" and item.provider_id == "d03.role_binding")
        if len(specs) != 1:
            raise ValueError("action intent must contain exactly one D03 role-binding check")
        spec = specs[0]
        expiry = _time(valid_until, "valid_until")
        request = resolution.request
        epoch = resolution.query_epoch
        matched = set(resolution.matched_bindings)
        binding_versions = tuple(sorted(
            (VersionedRef(item.key.name, item.revision)
             for item in resolution.read_versions if item.key.name in matched),
            key=lambda item: item.ref,
        ))
        observed = (
            tuple(item for item in spec.required_input_versions
                  if item.ref == spec.criteria_version)
            + ((VersionedRef("d03.role_binding", epoch.revision),) if epoch is not None else ())
            + binding_versions
        )
        scope_matches = (
            request is not None and request.scope_complete
            and request.subject_persona_ref == spec.subject_ref
            and request.requested_action_kind == intent.action_kind
            and request.purpose == intent.purpose == spec.purpose
            and spec.action_ref == intent.action_id
            and intent.target_ref in (
                request.target_entity_ref, request.group_ref, request.scene_ref,
            )
            and epoch is not None and epoch.scope_ref == "d03.role_binding"
            and epoch.namespace.persona_id == request.subject_persona_ref.removeprefix("persona:")
        )
        coverage = "full" if scope_matches and resolution.status != "partial" else "partial"
        pinned = (
            len(observed) == len(spec.required_input_versions)
            and len({item.ref for item in observed}) == len(observed)
            and set(observed) == set(spec.required_input_versions)
            and len(binding_versions) == len(matched)
        )
        passed = (
            coverage == "full" and resolution.status == "complete"
            and not resolution.missing_items and bool(matched)
            and pinned and (resolution.valid_until is None or expiry <= resolution.valid_until)
            and request is not None and expiry >= request.at_time
        )
        return CheckReceipt(
            spec.check_kind, spec.subject_ref, spec.action_ref, spec.purpose,
            spec.required_input_versions if passed else observed,
            coverage, "pass" if passed else "unknown", expiry, spec.provider_id,
        )

    def build_scene_binding_proposal(
        self, envelope: CommandEnvelope, binding: RoleBinding,
        active_role: ActiveRoleQualification, owner_guard: OwnerAuthorizationGuardV1,
        prior: RoleBindingResolution,
        *, owner_config_source_ref: str | None = None,
        host_identity_source_ref: str | None = None,
    ) -> DomainProposal:
        """Build a first scene-binding candidate for D11's guarded transaction.

        D11 must freshly verify the Owner/D01 qualifications and commit the
        envelope's read/query guards; constructing this object is not authority.
        """
        if not isinstance(envelope, CommandEnvelope) or not isinstance(binding, RoleBinding):
            raise TypeError("binding and command envelope are required")
        if not isinstance(active_role, ActiveRoleQualification):
            raise TypeError("a qualified active role is required")
        if not isinstance(owner_guard, OwnerAuthorizationGuardV1):
            raise TypeError("a current Owner authorization guard is required")
        if not isinstance(prior, RoleBindingResolution):
            raise TypeError("a current negative binding query is required")
        namespace = envelope.authority.namespace
        request = prior.request
        if (prior.query_epoch is None
                or active_role.namespace != namespace
                or active_role.graph_epoch != prior.query_epoch.revision
                or owner_guard.namespace != namespace
                or owner_guard.authorization_revision != active_role.authorization_revision
                or owner_guard.pending_revoke_operation_id is not None
                or owner_guard.minimum_revocation_revision >= 1
                or owner_guard.minimum_revocation_epoch >= 1
                or envelope.authority.activation_generation < 1):
            raise ValueError("active role and binding query differ from command namespace")
        if (prior.status != "no_applicable_binding" or prior.query_epoch is None
                or prior.query_epoch.namespace != namespace
                or prior.query_epoch.scope_ref != "d03.role_binding"
                or request is None or not request.scope_complete
                or request.subject_persona_ref != binding.subject_persona_ref
                or request.subject_persona_ref != f"persona:{namespace.persona_id}"
                or request.scene_ref != binding.scene_ref
                or request.target_entity_ref is not None or request.group_ref is not None
                or request.requested_action_kind != "bind_scene"
                or request.purpose != envelope.authority.purpose):
            raise ValueError("negative query does not cover this scene-binding command")
        if (binding.scene_ref is None or binding.target_entity_ref is not None
                or binding.group_ref is not None or binding.scope_selector != "scene"
                or binding.visibility_scope not in {"private", "group"}
                or binding.binding_version != 1 or binding.status != "active"
                or not binding.applies_to(request)):
            raise ValueError("first scene binding must be active and scoped to this scene")
        if (binding.social_role not in self._roles
                or not set(binding.norm_refs).issubset(self._norms)):
            raise ValueError("scene binding role or norms are not in the active D03 scheme")
        if owner_config_source_ref is None and host_identity_source_ref is None:
            if (envelope.source_qualification.evidence_eligibility == "ineligible"
                    or not set(binding.source_refs).issubset(envelope.source_qualification.source_refs)
                    or not set(binding.source_refs).issubset(envelope.input_refs)):
                raise ValueError("scene binding lacks qualified source references")
        else:
            refs = (owner_config_source_ref, host_identity_source_ref)
            if (any(type(ref) is not str for ref in refs)
                    or owner_config_source_ref == host_identity_source_ref
                    or binding.source_refs != refs
                    or not set(refs).issubset(envelope.input_refs)
                    or envelope.source_qualification.source_refs != (host_identity_source_ref,)
                    or (envelope.source_qualification.source_family,
                        envelope.source_qualification.content_reality,
                        envelope.source_qualification.evidence_eligibility)
                    != ("observed", "external_observation", "eligible")):
                raise ValueError("scene binding needs distinct Owner and host identity sources")
            guarded = set(envelope.version_guard.read_versions)
            for ref in refs:
                try:
                    parsed = AtomKey.from_token(ref)
                    expected = source_key(*namespace.as_tuple, parsed.owner.subject or "")
                    access = access_key(*namespace.as_tuple, parsed.owner.subject or "")
                except (TypeError, ValueError) as exc:
                    raise ValueError("scene binding source key is invalid") from exc
                if (parsed != expected or GraphVersion(expected, 0) not in guarded
                        or GraphVersion(access, 0) not in guarded):
                    raise ValueError("scene binding lacks source and access revision-0 guards")

        key = AtomKey(
            Owner("scene", namespace.bot_id, namespace.persona_id, binding.scene_ref),
            "d03.role_binding", binding.role_binding_id,
        )
        guard = envelope.version_guard
        required = set(active_role.read_versions) | set(prior.read_versions) | {
            GraphVersion(key, 0)
        }
        if (prior.query_epoch not in guard.query_epochs
                or not required.issubset(set(guard.read_versions))
                or any(item.key.name == binding.role_binding_id
                       for item in prior.read_versions)):
            raise ValueError("command is missing first-binding and active-role CAS guards")
        value = asdict(binding)
        value["norm_refs"] = list(binding.norm_refs)
        value["source_refs"] = list(binding.source_refs)
        return DomainProposal(
            "d03", "d03.proposal.v1", self.descriptor.request_schema_hash,
            envelope,
            (GraphWrite(key, value, tuple(item.key for item in active_role.read_versions)),),
            DependencySet(current_invalidation=active_role.read_versions),
            (), (),
        )

    def build_owner_scene_binding_write(
        self, binding: RoleBinding, active_role: ActiveRoleQualification,
        owner_guard: OwnerAuthorizationGuardV1, prior: RoleBindingResolution,
        *, owner_config_source_key: AtomKey, host_identity_source_key: AtomKey,
    ) -> GraphWrite:
        """Prepare one first-scene Owner write; the graph owns its CAS commit."""
        if (type(binding) is not RoleBinding
                or type(active_role) is not ActiveRoleQualification
                or type(owner_guard) is not OwnerAuthorizationGuardV1
                or type(prior) is not RoleBindingResolution):
            raise TypeError("typed first-scene binding evidence is required")
        namespace = active_role.namespace
        request = prior.request
        if (owner_guard.namespace != namespace
                or owner_guard.authorization_revision != active_role.authorization_revision
                or owner_guard.pending_revoke_operation_id is not None
                or owner_guard.minimum_revocation_revision >= 1
                or owner_guard.minimum_revocation_epoch >= 1
                or prior.query_epoch is None
                or prior.query_epoch.namespace != namespace
                or active_role.graph_epoch != prior.query_epoch.revision):
            raise ValueError("active role and Owner guard differ from scene query")
        if (prior.status != "no_applicable_binding"
                or prior.query_epoch.scope_ref != "d03.role_binding"
                or any(item.key.name == binding.role_binding_id
                       for item in prior.read_versions)
                or request is None or not request.scope_complete
                or request.subject_persona_ref != binding.subject_persona_ref
                or request.subject_persona_ref != f"persona:{namespace.persona_id}"
                or request.scene_ref != binding.scene_ref
                or request.target_entity_ref is not None or request.group_ref is not None
                or request.requested_action_kind != "bind_scene"):
            raise ValueError("negative query does not cover this first scene binding")
        if (binding.scene_ref is None or binding.target_entity_ref is not None
                or binding.group_ref is not None or binding.scope_selector != "scene"
                or binding.visibility_scope not in {"private", "group"}
                or binding.binding_version != 1 or binding.status != "active"
                or not binding.applies_to(request)):
            raise ValueError("first scene binding must be active and scene scoped")
        if (binding.social_role not in self._roles
                or not set(binding.norm_refs).issubset(self._norms)):
            raise ValueError("scene binding role or norms are not in the active D03 scheme")
        sources = (owner_config_source_key, host_identity_source_key)
        if (any(type(key) is not AtomKey for key in sources)
                or owner_config_source_key == host_identity_source_key
                or binding.source_refs != tuple(key.token for key in sources)
                or any(key != source_key(
                    *namespace.as_tuple, key.owner.subject or "") for key in sources)):
            raise ValueError("first scene binding requires distinct Owner and host source keys")
        key = AtomKey(
            Owner("scene", *namespace.as_tuple, binding.scene_ref),
            "d03.role_binding", binding.role_binding_id,
        )
        value = asdict(binding)
        value["norm_refs"] = list(binding.norm_refs)
        value["source_refs"] = list(binding.source_refs)
        return GraphWrite(key, value, tuple(item.key for item in active_role.read_versions))

    def project(self, query: RoleBindingRequest, snapshot: tuple[RoleBinding, ...]) -> RoleBindingResolution:
        return self.resolve_role_binding(query, snapshot)

    def invalidate(self, refs: tuple[str, ...]) -> tuple[str, ...]:
        return _refs(refs, "refs")

    def cleanup(self, plan: object) -> dict:
        return {"domain": "d03", "status": "delegated_to_runtime", "plan": plan}
