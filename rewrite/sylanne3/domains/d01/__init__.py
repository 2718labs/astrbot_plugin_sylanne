"""D01 persona semantics.

This package validates and projects persona-domain candidates.  It deliberately
does not persist data, sign a commit, or grant action authority; those duties
remain with the shared runtime coordinator.
"""

from dataclasses import asdict, dataclass, fields, replace
from typing import Mapping

from ...graph_types import (
    AtomKey, GraphAtom, GraphSnapshot, GraphVersion, GraphWrite, Owner,
    TypeSpec, owner_grant_key, validate_owner_grant_v1,
)
from ...authority_service.v2_owner_contract import OwnerAuthorizationGuardV1
from ...memory_types import SourceRecord, access_key, source_key, validate_access
from ..d06 import source_correction_head_key

from ...runtime_contracts import (
    CommandEnvelope,
    DependencySet,
    DomainProposal,
    NamespaceId,
    ProviderDescriptor,
    RUNTIME_SCHEMA,
    schema_hash,
)


_BLOCK_KINDS = frozenset({"semantic_identity", "value", "trait", "preference", "strategy", "self_knowledge"})
_PLASTICITY = frozenset({"read_only", "growth", "authored_only"})
_CHANGE_KINDS = frozenset({"local", "core"})


def _identifier(value: object, name: str) -> None:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} must be a nonempty string")


def _unique_strings(values: object, name: str, *, minimum: int = 0) -> tuple[str, ...]:
    result = tuple(values)
    if len(result) < minimum or any(not isinstance(value, str) or not value for value in result):
        raise ValueError(f"{name} must contain valid strings")
    if len(set(result)) != len(result):
        raise ValueError(f"{name} must be unique")
    return result


def _exact_payload(value: object, expected: set[str], label: str) -> dict:
    if type(value) is not dict:
        raise TypeError(f"{label} must be an object")
    if set(value) != expected:
        raise ValueError(
            f"{label} fields must match exactly; "
            f"missing={sorted(expected - set(value))!r}, extra={sorted(set(value) - expected)!r}"
        )
    return dict(value)


def _json_value(value: object) -> object:
    if type(value) is dict:
        return {key: _json_value(item) for key, item in value.items()}
    if type(value) is tuple:
        return [_json_value(item) for item in value]
    if type(value) is list:
        return [_json_value(item) for item in value]
    return value


def _namespace(value: object) -> NamespaceId:
    data = _exact_payload(value, {"bot_id", "persona_id"}, "namespace")
    return NamespaceId(**data)


def _persona_block(value: object) -> "PersonaBlock":
    data = _exact_payload(value, {field.name for field in fields(PersonaBlock)}, "persona block")
    return PersonaBlock(**data)


def _value_rule(value: object) -> "ValueRule":
    data = _exact_payload(value, {field.name for field in fields(ValueRule)}, "value rule")
    for name in ("applies_to", "supports_candidates", "rejects_candidates"):
        if type(data[name]) is not list:
            raise TypeError(f"{name} must be a JSON array")
        data[name] = tuple(data[name])
    return ValueRule(**data)


@dataclass(frozen=True)
class PersonaBlock:
    block_id: str
    kind: str
    claim: str
    plasticity: str

    def __post_init__(self) -> None:
        _identifier(self.block_id, "block_id")
        _identifier(self.claim, "claim")
        if self.kind not in _BLOCK_KINDS:
            raise ValueError("unknown persona block kind")
        if self.plasticity not in _PLASTICITY:
            raise ValueError("unknown plasticity")
        if self.kind == "semantic_identity" and self.plasticity != "read_only":
            raise ValueError("semantic identity is a lifecycle identity and must be read_only")


@dataclass(frozen=True)
class ValueRule:
    rule_id: str
    label: str
    applies_to: tuple[str, ...]
    supports_candidates: tuple[str, ...]
    rejects_candidates: tuple[str, ...]

    def __post_init__(self) -> None:
        _identifier(self.rule_id, "rule_id")
        _identifier(self.label, "label")
        applies = _unique_strings(self.applies_to, "applies_to")
        supports = _unique_strings(self.supports_candidates, "supports_candidates")
        rejects = _unique_strings(self.rejects_candidates, "rejects_candidates")
        if set(supports) & set(rejects):
            raise ValueError("one value rule cannot both support and reject a candidate")
        object.__setattr__(self, "applies_to", applies)
        object.__setattr__(self, "supports_candidates", supports)
        object.__setattr__(self, "rejects_candidates", rejects)


@dataclass(frozen=True)
class PersonaPlan:
    plan_id: str
    namespace: NamespaceId
    version: int
    blocks: tuple[PersonaBlock, ...]
    values: tuple[ValueRule, ...]
    authored: bool

    def __post_init__(self) -> None:
        _identifier(self.plan_id, "plan_id")
        if not isinstance(self.namespace, NamespaceId):
            raise TypeError("namespace must be NamespaceId")
        if type(self.version) is not int or self.version < 1:
            raise ValueError("version must be a positive exact integer")
        blocks = tuple(self.blocks)
        values = tuple(self.values)
        if not blocks or any(not isinstance(item, PersonaBlock) for item in blocks):
            raise ValueError("blocks must contain PersonaBlock values")
        if any(not isinstance(item, ValueRule) for item in values):
            raise TypeError("values must contain ValueRule values")
        if len({item.block_id for item in blocks}) != len(blocks):
            raise ValueError("persona block IDs must be unique")
        if len({item.rule_id for item in values}) != len(values):
            raise ValueError("value rule IDs must be unique")
        if type(self.authored) is not bool:
            raise TypeError("authored must be bool")
        object.__setattr__(self, "blocks", blocks)
        object.__setattr__(self, "values", values)

    @property
    def head_id(self) -> str:
        return f"{self.plan_id}@{self.version}"


@dataclass(frozen=True)
class PersonaScheme:
    head_id: str
    namespace: NamespaceId
    blocks: tuple[PersonaBlock, ...]
    values: tuple[ValueRule, ...]
    authored: bool


@dataclass(frozen=True)
class PersonaActivation:
    """Current D01 head, committed after an independently authorized Owner issue."""

    namespace: NamespaceId
    plan_id: str
    plan_version: int
    head_id: str
    owner_grant_id: str
    owner_grant_revision: int
    graph_incarnation: str
    activation_generation: int
    authorization_revision: int
    state: str = "active"

    def __post_init__(self) -> None:
        if not isinstance(self.namespace, NamespaceId):
            raise TypeError("activation namespace must be NamespaceId")
        for name in ("plan_id", "owner_grant_id", "graph_incarnation"):
            _identifier(getattr(self, name), name)
        for name in ("plan_version", "owner_grant_revision", "activation_generation",
                     "authorization_revision"):
            value = getattr(self, name)
            if type(value) is not int or value < 1:
                raise ValueError(f"{name} must be a positive exact integer")
        if self.head_id != f"{self.plan_id}@{self.plan_version}":
            raise ValueError("activation head differs from selected plan")
        if self.state != "active":
            raise ValueError("activation state is not active")


@dataclass(frozen=True)
class ActiveRoleQualification:
    namespace: NamespaceId
    head_id: str
    plan: PersonaPlan
    read_versions: tuple[GraphVersion, ...]
    graph_epoch: int
    authorization_revision: int


@dataclass(frozen=True)
class PersonaView:
    head_id: str
    namespace: NamespaceId
    blocks: tuple[PersonaBlock, ...]
    values: tuple[ValueRule, ...]
    context_tags: tuple[str, ...]
    social_strategy_known: bool


@dataclass(frozen=True)
class ValueEvaluation:
    preferred: tuple[str, ...]
    rejected: tuple[str, ...]
    unresolved: tuple[str, ...]
    reasons: Mapping[str, tuple[str, ...]]
    action_authorized: bool = False


@dataclass(frozen=True)
class GrowthProposal:
    proposal_id: str
    base_head: str
    target_block: str
    replacement_claim: str
    source_families: tuple[str, ...]
    counterevidence_checked: bool
    change_kind: str
    evidence_reality: str = "external"

    def __post_init__(self) -> None:
        for field_name in ("proposal_id", "base_head", "target_block", "replacement_claim"):
            _identifier(getattr(self, field_name), field_name)
        source_families = _unique_strings(self.source_families, "source_families", minimum=1)
        if type(self.counterevidence_checked) is not bool:
            raise TypeError("counterevidence_checked must be bool")
        if self.change_kind not in _CHANGE_KINDS:
            raise ValueError("unknown growth change kind")
        if self.evidence_reality not in {"external", "internal", "simulated"}:
            raise ValueError("unknown evidence reality")
        object.__setattr__(self, "source_families", source_families)


@dataclass(frozen=True)
class ContinuityRecord:
    previous_head: str
    retained_blocks: tuple[str, ...]
    changed_block: str
    source_families: tuple[str, ...]

    def __post_init__(self) -> None:
        _identifier(self.previous_head, "previous_head")
        _identifier(self.changed_block, "changed_block")
        object.__setattr__(
            self, "retained_blocks", _unique_strings(self.retained_blocks, "retained_blocks")
        )
        object.__setattr__(
            self, "source_families",
            _unique_strings(self.source_families, "source_families", minimum=1),
        )


@dataclass(frozen=True)
class PersonaRevision:
    revision_id: str
    previous_head: str
    new_head: str
    blocks: tuple[PersonaBlock, ...]
    continuity: ContinuityRecord

    def __post_init__(self) -> None:
        for name in ("revision_id", "previous_head", "new_head"):
            _identifier(getattr(self, name), name)
        blocks = tuple(self.blocks)
        if not blocks or any(not isinstance(block, PersonaBlock) for block in blocks):
            raise ValueError("blocks must contain PersonaBlock values")
        if len({block.block_id for block in blocks}) != len(blocks):
            raise ValueError("persona block IDs must be unique")
        if not isinstance(self.continuity, ContinuityRecord):
            raise TypeError("continuity must be ContinuityRecord")
        if self.continuity.previous_head != self.previous_head:
            raise ValueError("continuity previous_head must match revision")
        if self.new_head == self.previous_head:
            raise ValueError("revision must advance the persona head")
        object.__setattr__(self, "blocks", blocks)


@dataclass(frozen=True)
class GrowthAdoptionCandidate:
    """D01 writes and exact graph versions for one D11 atomic adoption."""

    head_id: str
    revision: PersonaRevision
    typed_writes: tuple[GraphWrite, ...]
    read_versions: tuple[GraphVersion, ...]


def _validate_persona_plan(value: object) -> None:
    data = _exact_payload(value, {field.name for field in fields(PersonaPlan)}, "persona plan")
    data["namespace"] = _namespace(data["namespace"])
    if type(data["blocks"]) is not list or type(data["values"]) is not list:
        raise TypeError("blocks and values must be JSON arrays")
    data["blocks"] = tuple(_persona_block(item) for item in data["blocks"])
    data["values"] = tuple(_value_rule(item) for item in data["values"])
    PersonaPlan(**data)


def _validate_persona_revision(value: object) -> None:
    data = _exact_payload(value, {field.name for field in fields(PersonaRevision)}, "persona revision")
    if type(data["blocks"]) is not list:
        raise TypeError("blocks must be a JSON array")
    data["blocks"] = tuple(_persona_block(item) for item in data["blocks"])
    continuity = _exact_payload(
        data["continuity"], {field.name for field in fields(ContinuityRecord)}, "continuity"
    )
    for name in ("retained_blocks", "source_families"):
        if type(continuity[name]) is not list:
            raise TypeError(f"{name} must be a JSON array")
        continuity[name] = tuple(continuity[name])
    data["continuity"] = ContinuityRecord(**continuity)
    PersonaRevision(**data)


def _validate_growth_contribution(value: object) -> None:
    data = _exact_payload(value, {field.name for field in fields(GrowthProposal)}, "growth contribution")
    if type(data["source_families"]) is not list:
        raise TypeError("source_families must be a JSON array")
    data["source_families"] = tuple(data["source_families"])
    GrowthProposal(**data)


def _validate_persona_activation(value: object) -> None:
    data = _exact_payload(value, {field.name for field in fields(PersonaActivation)}, "persona activation")
    data["namespace"] = _namespace(data["namespace"])
    PersonaActivation(**data)


def _activation_key(namespace: NamespaceId) -> AtomKey:
    return AtomKey(Owner("persona", *namespace.as_tuple), "d01.persona_activation.v1", "current")


class PersonaDomain:
    """Pure D01 validator/projector; integration supplies graph snapshots and commits."""

    @property
    def descriptor(self) -> ProviderDescriptor:
        return ProviderDescriptor(
            provider_id="d01.persona", contract_version=RUNTIME_SCHEMA,
            request_schema_hash=schema_hash({"domain": "d01", "proposal": 1}),
            response_schema_hash=schema_hash({"domain": "d01", "projection": 1}),
            owner_capabilities=("persona",), supported_modalities=("structured",),
            supported_purposes=("context", "expression", "consolidation", "audit"),
            supported_platforms=("runtime",), timeout_mode="bounded", cancellation_mode="cooperative",
            idempotency_mode="operation_id", cost_reporting_mode="none", health_capabilities=("validate",),
            recovery_capabilities=("rebuild_projection",),
        )

    def type_specs(self) -> tuple[TypeSpec, ...]:
        layouts = (
            ("d01.persona_plan.v1", _validate_persona_plan, PersonaPlan),
            ("d01.persona_activation.v1", _validate_persona_activation, PersonaActivation),
            ("d01.persona_revision.v1", _validate_persona_revision, PersonaRevision),
            ("d01.growth_contribution.v1", _validate_growth_contribution, GrowthProposal),
        )
        return tuple(TypeSpec(
            name,
            ("persona",),
            "state",
            validator,
            writer_domain="d01",
            schema_hash=schema_hash({
                "type": name,
                "schema_version": 1,
                "owner_kinds": ["persona"],
                "storage_role": "state",
                "fields": [field.name for field in fields(value_type)],
            }),
        ) for name, validator, value_type in layouts)

    def register_types(self) -> tuple[str, ...]:
        return tuple(spec.name for spec in self.type_specs())

    @property
    def workbench_view_contract(self) -> dict[str, dict[str, tuple[str, ...]]]:
        return {"creation": {
            "types": ("d01.persona_plan.v1",),
            "fields": ("candidates",),
        }}

    def project_workbench(
        self, view_type: str, atoms: tuple[Mapping[str, object], ...]
    ) -> dict[str, object]:
        if view_type != "creation":
            raise ValueError("D01 does not project this workbench view")
        if type(atoms) is not tuple:
            raise TypeError("atoms must be a tuple")
        candidates = []
        for atom in atoms:
            data = _exact_payload(atom, {"type", "name", "revision", "value"}, "persona plan atom")
            if data["type"] != "d01.persona_plan.v1":
                raise ValueError("creation accepts only persona plan atoms")
            if type(data["revision"]) is not int or data["revision"] < 1:
                raise ValueError("persona plan atom revision must be positive")
            _validate_persona_plan(data["value"])
            plan = data["value"]
            if data["name"] != plan["plan_id"]:
                raise ValueError("persona plan atom name differs from plan ID")
            candidates.append({
                "plan_id": plan["plan_id"],
                "version": plan["version"],
                "authored": plan["authored"],
                "block_count": len(plan["blocks"]),
                "value_rule_count": len(plan["values"]),
            })
        return {"candidates": candidates}

    @staticmethod
    def plan_write(plan: PersonaPlan) -> GraphWrite:
        if not isinstance(plan, PersonaPlan):
            raise TypeError("plan must be PersonaPlan")
        key = AtomKey(
            Owner("persona", plan.namespace.bot_id, plan.namespace.persona_id),
            "d01.persona_plan.v1",
            plan.plan_id,
        )
        return GraphWrite(key, _json_value(asdict(plan)))

    @staticmethod
    def activation_write(
        plan: PersonaPlan, owner_grant: GraphAtom,
        current_guard: OwnerAuthorizationGuardV1,
    ) -> GraphWrite:
        """Prepare the head for a D11 transaction; caller supplies a fresh Authority guard."""
        if not isinstance(plan, PersonaPlan):
            raise TypeError("plan must be PersonaPlan")
        if not isinstance(owner_grant, GraphAtom) or not owner_grant.valid:
            raise ValueError("current Owner grant atom is required")
        if owner_grant.key != owner_grant_key(*plan.namespace.as_tuple):
            raise ValueError("Owner grant belongs to another role")
        validate_owner_grant_v1(owner_grant.value)
        grant = owner_grant.value
        if (owner_grant.revision != grant["grant_revision"]
                or grant["scope"] != "/".join(plan.namespace.as_tuple)
                or not isinstance(current_guard, OwnerAuthorizationGuardV1)
                or current_guard.namespace != plan.namespace
                or current_guard.authority_id != grant["authority_id"]
                or current_guard.installation_id != grant["installation_id"]
                or current_guard.authorization_revision != 1
                or current_guard.pending_revoke_operation_id is not None
                or current_guard.minimum_revocation_revision >= 1
                or current_guard.minimum_revocation_epoch >= 1):
            raise ValueError("Owner grant is not currently committed and usable")
        activation = PersonaActivation(
            plan.namespace, plan.plan_id, plan.version, plan.head_id,
            grant["grant_id"], owner_grant.revision, grant["graph_incarnation"],
            grant["activation_generation"], current_guard.authorization_revision,
        )
        return GraphWrite(
            _activation_key(plan.namespace), _json_value(asdict(activation)),
            (owner_grant.key, PersonaDomain.plan_write(plan).key),
        )

    @staticmethod
    def resolve_active_role(
        snapshot: GraphSnapshot, *, namespace: NamespaceId,
        current_guard: OwnerAuthorizationGuardV1,
    ) -> ActiveRoleQualification:
        """Qualify a graph head against a freshly read trusted Authority guard."""
        if not isinstance(snapshot, GraphSnapshot) or not isinstance(namespace, NamespaceId):
            raise TypeError("graph snapshot and namespace are required")
        if not isinstance(current_guard, OwnerAuthorizationGuardV1):
            raise TypeError("fresh Owner authorization guard is required")
        if current_guard.namespace != namespace or current_guard.pending_revoke_operation_id:
            raise ValueError("Owner authorization is unavailable")
        activation_atom = snapshot.get(_activation_key(namespace))
        grant_atom = snapshot.get(owner_grant_key(*namespace.as_tuple))
        if (activation_atom is None or grant_atom is None
                or not activation_atom.valid or not grant_atom.valid):
            raise ValueError("role activation or Owner grant is missing")
        _validate_persona_activation(activation_atom.value)
        validate_owner_grant_v1(grant_atom.value)
        activation = activation_atom.value
        grant = grant_atom.value
        if (activation["namespace"] != _json_value(asdict(namespace))
                or activation["owner_grant_id"] != grant["grant_id"]
                or activation["owner_grant_revision"] != grant_atom.revision
                or activation["graph_incarnation"] != grant["graph_incarnation"]
                or activation["activation_generation"] != grant["activation_generation"]
                or activation["authorization_revision"] != current_guard.authorization_revision
                or current_guard.authorization_revision != 1
                or current_guard.authority_id != grant["authority_id"]
                or current_guard.installation_id != grant["installation_id"]
                or current_guard.minimum_revocation_revision >= 1
                or current_guard.minimum_revocation_epoch >= 1):
            raise ValueError("role activation differs from current Owner authorization")
        plan_key = AtomKey(Owner("persona", *namespace.as_tuple),
                           "d01.persona_plan.v1", activation["plan_id"])
        plan_atom = snapshot.get(plan_key)
        if plan_atom is None or not plan_atom.valid:
            raise ValueError("active persona plan is missing")
        _validate_persona_plan(plan_atom.value)
        raw = plan_atom.value
        if (raw["namespace"] != _json_value(asdict(namespace))
                or raw["version"] != activation["plan_version"]
                or f"{raw['plan_id']}@{raw['version']}" != activation["head_id"]):
            raise ValueError("active persona head is stale")
        epochs = [item.revision for item in snapshot.epochs
                  if (item.bot, item.persona) == namespace.as_tuple]
        if len(epochs) != 1:
            raise ValueError("complete role graph epoch is required")
        plan_data = dict(raw)
        plan_data["namespace"] = namespace
        plan_data["blocks"] = tuple(_persona_block(item) for item in raw["blocks"])
        plan_data["values"] = tuple(_value_rule(item) for item in raw["values"])
        return ActiveRoleQualification(
            namespace, activation["head_id"], PersonaPlan(**plan_data),
            tuple(GraphVersion(atom.key, atom.revision)
                  for atom in (activation_atom, plan_atom, grant_atom)),
            epochs[0], current_guard.authorization_revision,
        )

    @staticmethod
    def revision_write(namespace: NamespaceId, revision: PersonaRevision) -> GraphWrite:
        if not isinstance(namespace, NamespaceId) or not isinstance(revision, PersonaRevision):
            raise TypeError("namespace and revision must be D01 values")
        return GraphWrite(
            AtomKey(Owner("persona", namespace.bot_id, namespace.persona_id),
                    "d01.persona_revision.v1", revision.revision_id),
            _json_value(asdict(revision)),
        )

    @staticmethod
    def growth_contribution_write(
        namespace: NamespaceId, proposal: GrowthProposal
    ) -> GraphWrite:
        if not isinstance(namespace, NamespaceId) or not isinstance(proposal, GrowthProposal):
            raise TypeError("namespace and proposal must be D01 values")
        return GraphWrite(
            AtomKey(Owner("persona", namespace.bot_id, namespace.persona_id),
                    "d01.growth_contribution.v1", proposal.proposal_id),
            _json_value(asdict(proposal)),
        )

    def proposal_for(
        self,
        envelope: CommandEnvelope,
        contribution_keys: tuple[str, ...] = (),
        *,
        typed_writes: tuple[GraphWrite, ...] = (),
        dependencies: DependencySet | None = None,
    ) -> DomainProposal:
        if not isinstance(envelope, CommandEnvelope):
            raise TypeError("envelope must be CommandEnvelope")
        return DomainProposal(
            domain="d01", proposal_schema="d01.proposal.v1",
            proposal_schema_hash=schema_hash({"domain": "d01", "proposal": 1}), envelope=envelope,
            typed_writes=typed_writes, dependencies=dependencies or DependencySet(), contribution_keys=contribution_keys,
            required_bundle_parts=(),
        )

    def validate(self, proposal: DomainProposal, snapshot: object = None) -> DomainProposal:
        if not isinstance(proposal, DomainProposal):
            raise TypeError("proposal must be DomainProposal")
        if proposal.domain != "d01" or proposal.proposal_schema != "d01.proposal.v1":
            raise ValueError("proposal is not a D01 persona proposal")
        if proposal.proposal_schema_hash != self.descriptor.request_schema_hash:
            raise ValueError("D01 proposal schema hash is not recognized")
        specs = {spec.name: spec for spec in self.type_specs()}
        for write in proposal.typed_writes:
            spec = specs.get(write.key.type_name)
            if spec is None or write.key.owner.kind not in spec.owner_kinds:
                raise ValueError("D01 proposal contains an unauthorized graph type or owner")
            spec.validator(write.value)
            if (write.key.type_name in {
                    "d01.persona_activation.v1", "d01.persona_revision.v1",
                    "d01.growth_contribution.v1"}
                    or (write.key.type_name == "d01.persona_plan.v1"
                        and write.value["version"] > 1)):
                raise ValueError("D01 head transition requires W01 fenced adoption")
        return proposal

    def compile_scheme(self, plan: PersonaPlan, snapshot: object = None) -> PersonaScheme:
        if not isinstance(plan, PersonaPlan):
            raise TypeError("plan must be PersonaPlan")
        return PersonaScheme(plan.head_id, plan.namespace, plan.blocks, plan.values, plan.authored)

    def project(
        self, plan: PersonaPlan, snapshot: object = None, *, context_tags: tuple[str, ...] = (),
        role_binding_complete: bool = False,
    ) -> PersonaView:
        if not isinstance(plan, PersonaPlan):
            raise TypeError("plan must be PersonaPlan")
        tags = _unique_strings(context_tags, "context_tags")
        # D03 remains the only social-role authority.  A missing resolution only
        # means social strategy is unknown; no permissive default is invented.
        return PersonaView(plan.head_id, plan.namespace, plan.blocks, plan.values, tags, role_binding_complete)

    def evaluate_values(self, view: PersonaView, candidates: Mapping[str, tuple[str, ...]]) -> ValueEvaluation:
        if not isinstance(view, PersonaView):
            raise TypeError("view must be PersonaView")
        reasons: dict[str, tuple[str, ...]] = {}
        preferred: list[str] = []
        rejected: list[str] = []
        unresolved: list[str] = []
        for candidate_id, raw_tags in candidates.items():
            _identifier(candidate_id, "candidate ID")
            tags = set(_unique_strings(raw_tags, "candidate tags"))
            applicable = [rule for rule in view.values if set(rule.applies_to) & tags]
            support = [rule.label for rule in applicable if candidate_id in rule.supports_candidates]
            reject = [rule.label for rule in applicable if candidate_id in rule.rejects_candidates]
            reasons[candidate_id] = tuple(support + reject)
            if support and not reject:
                preferred.append(candidate_id)
            elif reject and not support:
                rejected.append(candidate_id)
            else:
                unresolved.append(candidate_id)
        return ValueEvaluation(tuple(preferred), tuple(rejected), tuple(unresolved), reasons)

    def validate_growth(self, plan: PersonaPlan, proposal: GrowthProposal) -> None:
        if not isinstance(plan, PersonaPlan) or not isinstance(proposal, GrowthProposal):
            raise TypeError("plan and proposal must be D01 values")
        if proposal.base_head != plan.head_id:
            raise ValueError("growth proposal has a stale persona head")
        target = next((block for block in plan.blocks if block.block_id == proposal.target_block), None)
        if target is None:
            raise ValueError("growth target block is missing")
        if target.plasticity != "growth":
            raise ValueError("target block cannot be changed by natural growth")
        if proposal.evidence_reality != "external":
            raise ValueError("simulated or self-asserted evidence cannot settle growth")
        if proposal.change_kind == "core" and len(proposal.source_families) < 2:
            raise ValueError("core growth needs two independent evidence families")
        if not proposal.counterevidence_checked:
            raise ValueError("growth needs a completed counterevidence check")

    def activate_revision(self, plan: PersonaPlan, proposal: GrowthProposal) -> PersonaRevision:
        self.validate_growth(plan, proposal)
        blocks = tuple(
            PersonaBlock(block.block_id, block.kind, proposal.replacement_claim, block.plasticity)
            if block.block_id == proposal.target_block else block
            for block in plan.blocks
        )
        continuity = ContinuityRecord(
            previous_head=plan.head_id,
            retained_blocks=tuple(block.block_id for block in plan.blocks if block.block_id != proposal.target_block),
            changed_block=proposal.target_block,
            source_families=proposal.source_families,
        )
        return PersonaRevision(proposal.proposal_id, plan.head_id, f"{plan.plan_id}@{plan.version + 1}", blocks, continuity)

    def issue_growth_candidate(
        self, snapshot: GraphSnapshot, *, namespace: NamespaceId,
        current_guard: OwnerAuthorizationGuardV1, proposal: GrowthProposal,
        source_ids: tuple[str, ...],
    ) -> GrowthAdoptionCandidate:
        """Prepare a natural-growth write set from one current shared-graph read.

        D11 must CAS every returned read version and recheck source access and
        deletion authority at commit. This method grants no write authority.
        """
        active = self.resolve_active_role(snapshot, namespace=namespace, current_guard=current_guard)
        self.validate_growth(active.plan, proposal)
        source_ids = _unique_strings(source_ids, "source_ids", minimum=1)
        if len(source_ids) != len(proposal.source_families):
            raise ValueError("each evidence family needs one independent source")
        refs: list[GraphVersion] = []
        roots: list[str] = []
        for source_id in source_ids:
            source_atom = snapshot.get(source_key(*namespace.as_tuple, source_id))
            access_atom = snapshot.get(access_key(*namespace.as_tuple, source_id))
            head_key = source_correction_head_key(namespace, source_id)
            head_atom = snapshot.get(head_key)
            if (source_atom is None or access_atom is None or head_atom is None
                    or not source_atom.valid or not access_atom.valid or head_atom.valid
                    or source_atom.revision < 1 or access_atom.revision < 1
                    or head_atom.revision != 0):
                raise ValueError("growth evidence or access is unavailable")
            source = SourceRecord.from_dict(source_atom.value)
            validate_access(access_atom.value)
            access = access_atom.value
            if (source.source_id != source_id or access["source_id"] != source_id
                    or source.source_kind != "observed" or source.assertion_status != "confirmed"
                    or source.independence != "independent" or source.parent_source_ids
                    or "consolidation" not in source.purposes
                    or access["status"] != "active" or "consolidation" not in access["purposes"]):
                raise ValueError("source cannot support natural growth")
            roots.append(source.provenance_root)
            refs.extend((GraphVersion(source_atom.key, source_atom.revision),
                         GraphVersion(access_atom.key, access_atom.revision),
                         GraphVersion(head_key, 0)))
        if set(roots) != set(proposal.source_families) or len(set(roots)) != len(roots):
            raise ValueError("evidence provenance differs from independent families")
        revision = self.activate_revision(active.plan, proposal)
        next_plan = replace(active.plan, version=active.plan.version + 1,
                            blocks=revision.blocks, authored=False)
        grant_atom = snapshot.get(owner_grant_key(*namespace.as_tuple))
        assert grant_atom is not None  # resolve_active_role already checked it
        writes = [self.plan_write(next_plan), self.revision_write(namespace, revision),
                  self.activation_write(next_plan, grant_atom, current_guard)]
        reads = list(active.read_versions) + refs
        for source_family in proposal.source_families:
            key = AtomKey(Owner("persona", *namespace.as_tuple),
                          "d01.growth_contribution.v1",
                          self.contribution_key(proposal.target_block, source_family, proposal.change_kind))
            if snapshot.get(key) is not None:
                raise ValueError("growth contribution has already been consumed")
            writes.append(GraphWrite(key, _json_value(asdict(proposal))))
            reads.append(GraphVersion(key, 0))
        for write in writes[1:3]:
            atom = snapshot.get(write.key)
            reads.append(GraphVersion(write.key, atom.revision if atom else 0))
        return GrowthAdoptionCandidate(next_plan.head_id, revision, tuple(writes), tuple(reads))

    def validate_growth_candidate(
        self, candidate: GrowthAdoptionCandidate, snapshot: GraphSnapshot, *,
        namespace: NamespaceId, current_guard: OwnerAuthorizationGuardV1,
        proposal: GrowthProposal, source_ids: tuple[str, ...],
    ) -> GrowthAdoptionCandidate:
        """Reject modified or stale D01 write sets before D11's atomic commit."""
        if not isinstance(candidate, GrowthAdoptionCandidate):
            raise TypeError("candidate must be GrowthAdoptionCandidate")
        expected = self.issue_growth_candidate(
            snapshot, namespace=namespace, current_guard=current_guard,
            proposal=proposal, source_ids=source_ids,
        )
        if candidate != expected:
            raise ValueError("growth candidate differs from current evidence and head")
        return candidate

    @staticmethod
    def contribution_key(target_block: str, source_family: str, change_kind: str) -> str:
        _identifier(target_block, "target_block")
        _identifier(source_family, "source_family")
        if change_kind not in _CHANGE_KINDS:
            raise ValueError("unknown growth change kind")
        return f"{target_block}|{source_family}|{change_kind}"

    @staticmethod
    def consume_contribution(key: str, committed_keys: tuple[str, ...]) -> bool:
        _identifier(key, "contribution key")
        return key not in _unique_strings(committed_keys, "committed_keys")

    @staticmethod
    def invalidate(refs: tuple[object, ...]) -> tuple[object, ...]:
        return tuple(refs)

    @staticmethod
    def cleanup(plan: object) -> tuple[str, object]:
        return "deferred_to_runtime_deletion_coordinator", plan
