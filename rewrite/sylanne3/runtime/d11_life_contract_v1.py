"""Closed contracts for the installed, once-only source-note executor."""
from dataclasses import dataclass, fields
import json

from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize
from ..graph_types import AtomKey
from ..domains.d01.production_operations_v1 import plain_v1
from .d11_offline_originals_v1 import _utc, _text, _digest

RECIPE_ID = "d10.source-note.v1"
WORK_KIND = "d10.life.source_note.v1"
ALGORITHM_ID = "d11.life.source_note.v1"
POSTCONDITION_ID = "d11.life.source_note.postcondition.v1"
ARTIFACT_SCHEMA = "d10.source-note-artifact.v1"


@dataclass(frozen=True, slots=True)
class LifeBodyComponentContractV1:
    body_quote_ref: str
    body_quote_version: int
    body_quote_digest: str
    resource_quote_ref: str
    resource_quote_version: int
    resource_quote_digest: str
    reservation_ref: str
    settlement_ref: str
    component_id: str
    effect_policy_ref: str
    body_prepare_operation_id: str
    schema: str = "d02.life-body-component-contract.v1"

    def __post_init__(self):
        if (self.schema != "d02.life-body-component-contract.v1" or type(self.body_quote_version) is not int
                or self.body_quote_version < 1 or type(self.resource_quote_version) is not int or self.resource_quote_version < 1):
            raise ValueError("Life Body component requires actual signed quote versions")
        _digest(self.body_quote_digest)
        _digest(self.resource_quote_digest)
        for name in ("body_quote_ref", "resource_quote_ref", "reservation_ref", "settlement_ref", "component_id", "effect_policy_ref", "body_prepare_operation_id"):
            _text(getattr(self, name))


@dataclass(frozen=True, slots=True)
class LifeInputRefV1:
    ref: str
    revision: int
    digest: str

    def __post_init__(self):
        AtomKey.from_token(self.ref)
        if type(self.revision) is not int or self.revision < 1:
            raise ValueError("life input requires a current adopted revision")
        _digest(self.digest)


@dataclass(frozen=True, slots=True)
class RegisteredLifePlanV2:
    project: LifeInputRefV1
    recipe: LifeInputRefV1
    action_intent: LifeInputRefV1
    input_source: LifeInputRefV1
    input_access: LifeInputRefV1
    activity_id: str
    effect_id: str
    attempt_id: str
    operation_id: str
    audiences: tuple[str, ...]
    parent_budget_lease_ref: str
    cpu_ceiling_ms: int
    deadline_utc: str
    algorithm_build_digest: str
    postcondition_build_digest: str
    body_effect_request_json: str | None
    step: str = "source_note"
    recipe_id: str = RECIPE_ID
    executor_id: str = ALGORITHM_ID
    recipe_version: int = 1
    schema: str = "d10.registered-life-plan.v2"

    def __post_init__(self):
        if (self.schema != "d10.registered-life-plan.v2" or self.step != "source_note"
                or self.recipe_id != RECIPE_ID or self.executor_id != ALGORITHM_ID
                or self.recipe_version != 1 or type(self.cpu_ceiling_ms) is not int
                or not 1 <= self.cpu_ceiling_ms <= 60000
                or type(self.audiences) is not tuple or not self.audiences
                or len(set(self.audiences)) != len(self.audiences)):
            raise ValueError("exact finite installed life recipe required")
        for name in ("project", "recipe", "action_intent", "input_source", "input_access"):
            if type(getattr(self, name)) is not LifeInputRefV1:
                raise TypeError("life plan freezes actual typed input commitments")
        if (AtomKey.from_token(self.input_source.ref).type_name != "memory.source"
                or AtomKey.from_token(self.input_access.ref).type_name != "memory.access"):
            raise ValueError("life source and access kinds differ")
        for name in ("activity_id", "effect_id", "attempt_id", "operation_id", "parent_budget_lease_ref"):
            _text(getattr(self, name))
        for value in self.audiences:
            _text(value)
        _utc(self.deadline_utc)
        _digest(self.algorithm_build_digest)
        _digest(self.postcondition_build_digest)
        if self.body_effect_request_json is not None:
            if canonical_serialize(json.loads(self.body_effect_request_json)) != self.body_effect_request_json:
                raise ValueError("life Body request must preserve canonical actual component references")
            LifeBodyComponentContractV1(**json.loads(self.body_effect_request_json))


@dataclass(frozen=True, slots=True)
class D11LifeExecutionBindingV1:
    namespace: NamespaceId
    authority_namespace: str
    authority_id: str
    installation_id: str
    manifest_digest: str
    activation_generation: int
    operation_id: str
    prepare_operation_id: str
    activity_id: str
    effect_id: str
    attempt_id: str
    execution_id: str
    job_id: str
    job_holder: str
    job_fence: int
    job_lease_expires_utc: str
    job_cancel_epoch: int
    plan_original_ref: str
    plan_digest: str
    prepared_original_ref: str
    input_digest: str
    clock_original_digest: str
    owner_grant_ref: str
    owner_grant_revision: int
    owner_grant_digest: str
    parent_budget_lease_ref: str
    quote_id: str
    quote_version: int
    quote_digest: str
    reservation_operation_id: str
    reservation_digest: str
    cpu_ceiling_ms: int
    deadline_utc: str
    algorithm_build_digest: str
    postcondition_build_digest: str
    artifact_ref: str
    algorithm_id: str = ALGORITHM_ID
    recipe_id: str = RECIPE_ID
    schema: str = "d11.life-execution-binding.v1"

    def __post_init__(self):
        if (self.schema != "d11.life-execution-binding.v1" or self.algorithm_id != ALGORITHM_ID
                or self.recipe_id != RECIPE_ID or type(self.namespace) is not NamespaceId
                or type(self.job_cancel_epoch) is not int or self.job_cancel_epoch != 0):
            raise ValueError("actual installed life binding required")
        for name in ("activation_generation", "job_fence", "owner_grant_revision", "quote_version", "cpu_ceiling_ms"):
            if type(getattr(self, name)) is not int or getattr(self, name) < 1:
                raise ValueError("positive current life generation/fence/quote required")
        if self.cpu_ceiling_ms > 60000 or _utc(self.job_lease_expires_utc) > _utc(self.deadline_utc):
            raise ValueError("life frozen bounds differ")
        for name in ("manifest_digest", "plan_digest", "input_digest", "clock_original_digest", "owner_grant_digest",
                     "quote_digest", "reservation_digest", "algorithm_build_digest", "postcondition_build_digest"):
            _digest(getattr(self, name))
        for name in ("authority_namespace", "authority_id", "installation_id", "operation_id", "activity_id", "effect_id",
                     "attempt_id", "execution_id", "job_id", "job_holder", "plan_original_ref", "prepared_original_ref",
                     "owner_grant_ref", "parent_budget_lease_ref", "quote_id", "reservation_operation_id", "artifact_ref"):
            _text(getattr(self, name))
        if self.prepare_operation_id != "d11-life-prepare:" + self.operation_id or self.prepare_operation_id == self.operation_id:
            raise ValueError("Life prepare command must be distinct from adopted root action")
        if self.artifact_ref != life_artifact_ref_v1(self.namespace, self.effect_id):
            raise ValueError("life artifact reference must be derived from the stable effect")

    @property
    def digest(self):
        return canonical_digest(plain_v1(self))


def life_artifact_ref_v1(namespace, effect_id):
    from ..graph_types import Owner
    return AtomKey(Owner("activity", *namespace.as_tuple, effect_id), "d11.life_artifact.v1",
                   "source-note:" + canonical_digest((namespace, effect_id))[:48]).token


@dataclass(frozen=True, slots=True)
class RoleSegmentStartV1:
    binding_digest: str
    prepared_digest: str
    execution_id: str
    claim_id: str
    claim_sequence: int
    executor_installation_id: str
    executor_incarnation: str
    claimed_at_utc: str
    character_at: str
    clock_mapping_ref: str
    clock_mapping_version: int
    signature: str
    schema: str = "d11.life-role-segment-start.v1"

    def __post_init__(self):
        from decimal import Decimal
        if (self.schema != "d11.life-role-segment-start.v1" or type(self.claim_sequence) is not int
                or self.claim_sequence < 1 or type(self.clock_mapping_version) is not int
                or self.clock_mapping_version < 1 or not Decimal(self.character_at).is_finite()):
            raise ValueError("actual life start clock/claim required")
        for name in ("binding_digest", "prepared_digest", "signature"):
            _digest(getattr(self, name))
        for name in ("execution_id", "claim_id", "executor_installation_id", "executor_incarnation", "clock_mapping_ref"):
            _text(getattr(self, name))
        _utc(self.claimed_at_utc)


@dataclass(frozen=True, slots=True)
class LifeTerminalPayloadV1:
    binding_digest: str
    prepared_digest: str
    execution_id: str
    claim_sequence: int
    claim_digest: str
    status: str
    actual_cpu_ms: int | None
    artifact_ref: str | None
    artifact_digest: str | None
    artifact_length: int | None
    reason_code: str | None
    completed_at_utc: str
    character_at: str | None
    postcondition_build_digest: str
    signature: str
    schema: str = "d11.life-terminal-payload.v1"

    def __post_init__(self):
        if self.schema != "d11.life-terminal-payload.v1" or type(self.claim_sequence) is not int or self.claim_sequence < 1:
            raise ValueError("closed life terminal required")
        for name in ("binding_digest", "prepared_digest", "postcondition_build_digest", "signature"):
            _digest(getattr(self, name))
        if not self.claim_digest.startswith("sha256:"):
            raise ValueError("actual life claim chain commitment required")
        _digest(self.claim_digest[7:])
        _utc(self.completed_at_utc)
        if self.status == "completed":
            if (type(self.actual_cpu_ms) is not int or self.actual_cpu_ms < 0 or self.reason_code is not None
                    or type(self.artifact_length) is not int or not 1 <= self.artifact_length <= 262144
                    or self.character_at is None):
                raise ValueError("life completion needs measured work and verified durable artifact")
            _text(self.artifact_ref)
            _digest(self.artifact_digest)
        elif self.status == "failed":
            if (type(self.actual_cpu_ms) is not int or self.actual_cpu_ms < 0
                    or self.reason_code not in {"computation_failed", "artifact_stage_failed", "postcondition_failed", "cpu_ceiling_exceeded",
                                               "deadline_expired", "job_lease_expired", "clock_sample_inconsistent"}
                    or any(x is not None for x in (self.artifact_ref, self.artifact_digest, self.artifact_length))):
                raise ValueError("failed life preserves actual measured CPU without invented artifact")
        elif self.status == "unknown":
            if (self.actual_cpu_ms is not None or self.reason_code != "executor_quiesced_measurement_lost"
                    or any(x is not None for x in (self.artifact_ref, self.artifact_digest, self.artifact_length, self.character_at))):
                raise ValueError("unknown life cannot guess CPU or success")
        else:
            raise ValueError("unknown life terminal kind")


def life_mutation_id_v1(binding, phase):
    if type(binding) not in LIFE_BINDING_TYPES or phase not in {"claim", "terminal"}:
        raise ValueError("actual life binding and closed phase required")
    return "d11-life:" + phase + ":" + canonical_digest((binding.authority_namespace, binding.installation_id, binding.execution_id))


@dataclass(frozen=True, slots=True)
class D11LifeClaimV1:
    binding: D11LifeExecutionBindingV1
    payload: RoleSegmentStartV1
    journal_id: str
    claim_digest: str
    original_ref: str

    def __post_init__(self):
        if (type(self.binding) is not D11LifeExecutionBindingV1 or type(self.payload) is not RoleSegmentStartV1
                or self.payload.binding_digest != self.binding.digest or self.payload.execution_id != self.binding.execution_id
                or self.payload.claim_id != life_mutation_id_v1(self.binding, "claim") or self.original_ref != self.payload.claim_id
                or self.payload.executor_installation_id != self.binding.installation_id):
            raise ValueError("life claim identity differs")
        if not self.claim_digest.startswith("sha256:"):
            raise ValueError("life claim chain digest required")
        _digest(self.claim_digest[7:])

    @property
    def claim_sequence(self):
        return self.payload.claim_sequence


@dataclass(frozen=True, slots=True)
class D11LifeTerminalV1:
    binding: D11LifeExecutionBindingV1
    claim: D11LifeClaimV1
    payload: LifeTerminalPayloadV1
    journal_id: str
    terminal_sequence: int
    terminal_digest: str
    original_ref: str

    def __post_init__(self):
        b, p = self.binding, self.payload
        if (type(b) is not D11LifeExecutionBindingV1 or type(self.claim) is not D11LifeClaimV1
                or type(p) is not LifeTerminalPayloadV1 or self.claim.binding != b
                or p.binding_digest != b.digest or p.prepared_digest != self.claim.payload.prepared_digest
                or p.execution_id != b.execution_id or p.claim_sequence != self.claim.claim_sequence
                or p.claim_digest != self.claim.claim_digest or self.journal_id != self.claim.journal_id
                or self.terminal_sequence <= self.claim.claim_sequence
                or self.original_ref != life_mutation_id_v1(b, "terminal")
                or p.postcondition_build_digest != b.postcondition_build_digest
                or _utc(p.completed_at_utc) < _utc(self.claim.payload.claimed_at_utc)):
            raise ValueError("life terminal lacks its exact actual start")
        if type(self.terminal_sequence) is not int or not self.terminal_digest.startswith("sha256:"):
            raise ValueError("Life terminal requires actual journal sequence and chain digest")
        _digest(self.terminal_digest[7:])
        if p.status == "completed" and (p.artifact_ref != b.artifact_ref or p.actual_cpu_ms > b.cpu_ceiling_ms
                or _utc(p.completed_at_utc) >= min(_utc(b.deadline_utc), _utc(b.job_lease_expires_utc))):
            raise ValueError("life completion exceeds its frozen artifact/time/CPU bounds")

    @property
    def status(self):
        return self.payload.status

    @property
    def actual_cpu_ms(self):
        return self.payload.actual_cpu_ms


def life_adoption_operation_id_v1(binding):
    return "d11-life-adopt:" + canonical_digest((binding.namespace, binding.execution_id, binding.digest))[:48]


def life_job_result_binding_v1(terminal, *, artifact_graph_digest, artifact_revision=1):
    """Address a completed job result; only the authenticated original grants authority.

    The existing artifact name binds namespace/effect, but omits job/generation.
    This domain-separated ID commits the entire original version and execution
    scope. Its immutable Graph member must be revision one in the actual CAS.
    """
    if type(terminal) not in LIFE_TERMINAL_TYPES or terminal.status != "completed":
        raise ValueError("Life job result requires its actual completed terminal")
    if type(artifact_revision) is not int or artifact_revision != 1:
        raise ValueError("Life job result requires the first immutable artifact version")
    _digest(artifact_graph_digest)
    b = terminal.binding
    key = AtomKey.from_token(b.artifact_ref)
    value = {"schema": "d11.life-job-result-binding.v1", "namespace": plain_v1(b.namespace),
        "activation_generation": b.activation_generation, "binding_digest": b.digest,
        "job_id": b.job_id, "operation_id": b.operation_id,
        "producing_operation_id": life_adoption_operation_id_v1(b), "execution_id": b.execution_id,
        "artifact_ref": key.token, "artifact_name": key.name, "artifact_revision": artifact_revision,
        "artifact_graph_digest": artifact_graph_digest, "artifact_digest": terminal.payload.artifact_digest,
        "artifact_length": terminal.payload.artifact_length, "prepared_digest": terminal.payload.prepared_digest,
        "terminal_ref": terminal.original_ref, "terminal_digest": canonical_digest(plain_v1(terminal))}
    value["result_ref"] = "d11-life-result:" + canonical_digest(("d11.life-job-result.v1", value))
    return value


def validate_life_job_result_binding_v1(value, *, terminal):
    """Check the closed mapping; SQL/signature/member authentication is separate."""
    if type(value) is not dict:
        raise ValueError("Life job result binding requires a closed object")
    expected = life_job_result_binding_v1(terminal, artifact_graph_digest=value.get("artifact_graph_digest"),
        artifact_revision=value.get("artifact_revision"))
    if canonical_serialize(value) != canonical_serialize(expected):
        raise ValueError("Life job result original scope/version/identity differs")
    return expected["result_ref"]


@dataclass(frozen=True, slots=True)
class RegisteredLifeOutcomeV2:
    plan_original_ref: str
    action_outcome_ref: str
    start_original_ref: str
    terminal_original_ref: str
    artifact_ref: str
    artifact_digest: str
    paid_cost_refs: tuple[str, ...]
    schema: str = "d10.registered-life-outcome.v2"

    def __post_init__(self):
        if self.schema != "d10.registered-life-outcome.v2" or type(self.paid_cost_refs) is not tuple or not self.paid_cost_refs:
            raise ValueError("actual paid life outcome required")
        _digest(self.artifact_digest)


@dataclass(frozen=True, slots=True)
class D11DraftExecutionBindingV1(D11LifeExecutionBindingV1):
    execution_call_id: str = ""
    activity_scope_ref: str = ""
    activity_scope_digest: str = ""
    target_scope_digest: str = ""
    root_registration_ref: str = ""
    root_registration_digest: str = ""
    algorithm_id: str = "d11.life.artifact_draft.v1"
    recipe_id: str = "artifact_draft_v1"
    schema: str = "d11.draft-execution-binding.v1"

    def __post_init__(self):
        if (self.schema, self.algorithm_id, self.recipe_id) != (
                "d11.draft-execution-binding.v1", "d11.life.artifact_draft.v1", "artifact_draft_v1"):
            raise ValueError("exact installed draft binding required")
        # Reuse the unchanged V1 common constraints, without relabeling any
        # serialized original or weakening the old source-note constructor.
        common = {f.name: getattr(self, f.name) for f in fields(D11LifeExecutionBindingV1)}
        common.update(schema="d11.life-execution-binding.v1", algorithm_id=ALGORITHM_ID,
            recipe_id=RECIPE_ID, artifact_ref=life_artifact_ref_v1(self.namespace, self.effect_id))
        D11LifeExecutionBindingV1(**common)
        for value in (self.execution_call_id, self.activity_scope_ref, self.root_registration_ref):
            _text(value)
        for value in (self.activity_scope_digest, self.target_scope_digest, self.root_registration_digest):
            _digest(value)
        if self.artifact_ref != draft_artifact_ref_v1(self.namespace, self.effect_id):
            raise ValueError("draft artifact must bind its original stable effect")


def draft_artifact_ref_v1(namespace, effect_id):
    from ..graph_types import Owner
    return AtomKey(Owner("activity", *namespace.as_tuple, effect_id), "d11.draft_artifact.v1",
        "draft:" + canonical_digest((namespace, effect_id))[:48]).token


@dataclass(frozen=True, slots=True)
class DraftRoleSegmentStartV1(RoleSegmentStartV1):
    source_qualification_digest: str = ""
    target_scope_digest: str = ""
    schema: str = "d11.draft-role-segment-start.v1"

    def __post_init__(self):
        if self.schema != "d11.draft-role-segment-start.v1":
            raise ValueError("exact draft claim payload required")
        common = {f.name: getattr(self, f.name) for f in fields(RoleSegmentStartV1)}
        RoleSegmentStartV1(**{**common, "schema": "d11.life-role-segment-start.v1"})
        _digest(self.source_qualification_digest)
        _digest(self.target_scope_digest)


@dataclass(frozen=True, slots=True)
class DraftTerminalPayloadV1(LifeTerminalPayloadV1):
    handoff_started: bool | None = False
    readback: object = None
    schema: str = "d11.draft-terminal-payload.v1"

    def __post_init__(self):
        from .d11_artifact_draft_contract_v1 import DraftFileReadbackV1
        if (self.schema != "d11.draft-terminal-payload.v1"
                or type(self.handoff_started) is not bool and not (self.handoff_started is None and self.status == "unknown")
                or self.status not in {"completed", "failed", "unknown"}
                or type(self.claim_sequence) is not int or self.claim_sequence < 1
                or self.actual_cpu_ms is not None and (type(self.actual_cpu_ms) is not int or self.actual_cpu_ms < 0)):
            raise ValueError("draft terminal requires independent actual effect and cost facts")
        for value in (self.binding_digest, self.prepared_digest, self.postcondition_build_digest, self.signature):
            _digest(value)
        if not self.claim_digest.startswith("sha256:"):
            raise ValueError("draft terminal requires its original claim chain")
        _digest(self.claim_digest[7:]); _utc(self.completed_at_utc)
        if self.readback is not None and type(self.readback) is not DraftFileReadbackV1:
            raise ValueError("draft terminal readback is not its closed actual file witness")
        if self.status == "completed":
            if (not self.handoff_started or self.readback is None or self.reason_code is not None
                    or self.actual_cpu_ms is None or self.character_at is None
                    or (self.artifact_digest, self.artifact_length) !=
                       (self.readback.content_digest, self.readback.content_length)):
                raise ValueError("draft completion requires actual bound file readback and measured work")
            _text(self.artifact_ref)
        elif (self.artifact_ref is not None or self.artifact_digest is not None or self.artifact_length is not None
                or type(self.reason_code) is not str or not self.reason_code):
            raise ValueError("incomplete draft preserves facts without a completed artifact grant")
        if self.status == "failed" and (self.handoff_started or self.readback is not None or self.actual_cpu_ms is None):
            raise ValueError("possible file handoff cannot be labeled verified pre-handoff failure")


@dataclass(frozen=True, slots=True)
class D11DraftClaimV1(D11LifeClaimV1):
    def __post_init__(self):
        b, p = self.binding, self.payload
        if (type(b) is not D11DraftExecutionBindingV1 or type(p) is not DraftRoleSegmentStartV1
                or p.binding_digest != b.digest or p.execution_id != b.execution_id
                or p.claim_id != life_mutation_id_v1(b, "claim") or self.original_ref != p.claim_id
                or p.executor_installation_id != b.installation_id or p.target_scope_digest != b.target_scope_digest):
            raise ValueError("draft claim crossed its exact installed binding")
        if not self.claim_digest.startswith("sha256:"):
            raise ValueError("draft claim requires actual journal chain")
        _digest(self.claim_digest[7:])


@dataclass(frozen=True, slots=True)
class D11DraftTerminalV1(D11LifeTerminalV1):
    def __post_init__(self):
        b, p = self.binding, self.payload
        if (type(b) is not D11DraftExecutionBindingV1 or type(self.claim) is not D11DraftClaimV1
                or type(p) is not DraftTerminalPayloadV1 or self.claim.binding != b
                or p.binding_digest != b.digest or p.prepared_digest != self.claim.payload.prepared_digest
                or p.execution_id != b.execution_id or p.claim_sequence != self.claim.claim_sequence
                or p.claim_digest != self.claim.claim_digest or self.journal_id != self.claim.journal_id
                or type(self.terminal_sequence) is not int or self.terminal_sequence <= self.claim.claim_sequence
                or self.original_ref != life_mutation_id_v1(b, "terminal")
                or p.postcondition_build_digest != b.postcondition_build_digest
                or _utc(p.completed_at_utc) < _utc(self.claim.payload.claimed_at_utc)):
            raise ValueError("draft terminal lacks its actual earlier once claim")
        if not self.terminal_digest.startswith("sha256:"):
            raise ValueError("draft terminal requires actual journal chain")
        _digest(self.terminal_digest[7:])
        if p.readback is not None and (p.readback.effect_id != b.effect_id
                or p.readback.execution_call_id != b.execution_call_id or p.readback.plan_digest != b.plan_digest
                or p.readback.target_scope_digest != b.target_scope_digest
                or p.readback.root_registration_digest != b.root_registration_digest):
            raise ValueError("draft readback belongs to another target or effect")
        if p.status == "completed" and (p.artifact_ref != b.artifact_ref or p.actual_cpu_ms > b.cpu_ceiling_ms
                or _utc(p.completed_at_utc) >= min(_utc(b.deadline_utc), _utc(b.job_lease_expires_utc))):
            raise ValueError("draft completion exceeds original admitted bounds")


LIFE_BINDING_TYPES = frozenset({D11LifeExecutionBindingV1, D11DraftExecutionBindingV1})
LIFE_CLAIM_TYPES = frozenset({D11LifeClaimV1, D11DraftClaimV1})
LIFE_TERMINAL_TYPES = frozenset({D11LifeTerminalV1, D11DraftTerminalV1})
LIFE_START_TYPES = frozenset({RoleSegmentStartV1, DraftRoleSegmentStartV1})
LIFE_PAYLOAD_TYPES = frozenset({LifeTerminalPayloadV1, DraftTerminalPayloadV1})


def life_work_kind_v1(value):
    from .d11_artifact_draft_contract_v1 import RegisteredDraftFilePlanV3, WORK_KIND as DRAFT_WORK
    if type(value) in {RegisteredDraftFilePlanV3, D11DraftExecutionBindingV1}:
        return DRAFT_WORK
    if type(value) in {RegisteredLifePlanV2, D11LifeExecutionBindingV1}:
        return WORK_KIND
    raise TypeError("closed registered Life recipe required")


_TYPES = {LifeInputRefV1, LifeBodyComponentContractV1, RegisteredLifePlanV2, RegisteredLifeOutcomeV2, D11LifeExecutionBindingV1,
          RoleSegmentStartV1, LifeTerminalPayloadV1, D11LifeClaimV1, D11LifeTerminalV1,
          D11DraftExecutionBindingV1, DraftRoleSegmentStartV1, DraftTerminalPayloadV1, D11DraftClaimV1, D11DraftTerminalV1}


def life_to_wire_v1(value):
    from .d11_artifact_draft_contract_v1 import RegisteredDraftFilePlanV3, draft_to_wire_v1
    if type(value) is RegisteredDraftFilePlanV3:
        return draft_to_wire_v1(value)
    if type(value) not in _TYPES:
        raise TypeError("exact closed life original required")
    return plain_v1(value)


def life_from_wire_v1(raw, kind):
    from .d11_artifact_draft_contract_v1 import RegisteredDraftFilePlanV3, DraftFileReadbackV1, draft_from_wire_v1
    if kind is RegisteredDraftFilePlanV3:
        return draft_from_wire_v1(raw, kind)
    variants = {RegisteredLifePlanV2: RegisteredDraftFilePlanV3, D11LifeExecutionBindingV1: D11DraftExecutionBindingV1,
        RoleSegmentStartV1: DraftRoleSegmentStartV1, LifeTerminalPayloadV1: DraftTerminalPayloadV1,
        D11LifeClaimV1: D11DraftClaimV1, D11LifeTerminalV1: D11DraftTerminalV1}
    if type(raw) is dict and kind in variants:
        selected = variants[kind]
        if selected is RegisteredDraftFilePlanV3 and raw.get("schema") == "d10.registered-draft-file-plan.v3":
            return draft_from_wire_v1(raw, selected)
        if selected not in {RegisteredDraftFilePlanV3, D11DraftClaimV1, D11DraftTerminalV1}:
            if raw.get("schema") == selected.__dataclass_fields__["schema"].default:
                kind = selected
        elif selected in {D11DraftClaimV1, D11DraftTerminalV1} and type(raw.get("binding")) is dict:
            if raw["binding"].get("schema") == "d11.draft-execution-binding.v1":
                kind = selected
    if kind not in _TYPES or type(raw) is not dict or set(raw) != {f.name for f in fields(kind)}:
        raise ValueError("closed life original wire shape differs")
    value = dict(raw)
    if kind in LIFE_BINDING_TYPES:
        value["namespace"] = NamespaceId(**value["namespace"])
    if kind is RegisteredLifePlanV2:
        for name in ("project", "recipe", "action_intent", "input_source", "input_access"):
            value[name] = life_from_wire_v1(value[name], LifeInputRefV1)
        value["audiences"] = tuple(value["audiences"])
    if kind is RegisteredLifeOutcomeV2:
        value["paid_cost_refs"] = tuple(value["paid_cost_refs"])
    if kind in LIFE_CLAIM_TYPES | LIFE_TERMINAL_TYPES:
        value["binding"] = life_from_wire_v1(value["binding"], D11LifeExecutionBindingV1)
        value["payload"] = life_from_wire_v1(value["payload"], RoleSegmentStartV1 if kind in LIFE_CLAIM_TYPES else LifeTerminalPayloadV1)
    if kind in LIFE_TERMINAL_TYPES:
        value["claim"] = life_from_wire_v1(value["claim"], D11LifeClaimV1)
    if kind is DraftTerminalPayloadV1 and value["readback"] is not None:
        value["readback"] = draft_from_wire_v1(value["readback"], DraftFileReadbackV1)
    result = kind(**value)
    if life_to_wire_v1(result) != raw:
        raise ValueError("life original wire is not canonical")
    return result
