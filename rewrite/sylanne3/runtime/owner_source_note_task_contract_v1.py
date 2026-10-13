"""Owner management-task contracts, separate from platform/C02 foreground causes.

These values carry selectors and committed originals. They issue no Self,
Body, budget, model or execution authority. Producers use existing W01,
D11 signed originals, domain outbox and PersistentJob storage.
"""
from dataclasses import dataclass
import math

from ..graph_types import AtomKey, GraphVersion, Owner
from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize
from .domain_production_contracts_v1 import ProductionOwnerGuardV1

SUBMIT_OPERATION = "submit_owner_source_note_task_v1"
CREATE_OPERATION = "create_owner_source_note_task_v1"
CHECKPOINT_OPERATION = "checkpoint_owner_source_note_task_v1"
ACQUIRE_OPERATION = "acquire_owner_source_note_task_v1"
CAUSE_KIND = "owner_source_note_task_cause_v1"
AUTHORIZATION_KIND = "owner_source_note_task_authorization_v2"
RESPONSIBILITY_KIND = "owner_source_note_task_responsibility_v2"
VALUES_PARENT_KIND = "owner_source_note_values_parent_v1"
SUBMITTED_EVENT = "owner_source_note_task_submitted_v1"
# The existing D11 job carrier is reused; its new continuation must be decoded
# explicitly and must never enter the C02/protected-reply reconstruction path.
TASK_WORK_KIND = "d11.foreground_cycle.v1"
NOTE_WORK_KIND = "d10.life.source_note.v1"
HEAD_KINDS = {"body_source": "memory.source", "goal": "d08.goal.v1", "plan": "d08.personal_plan.v1",
    "project": "d10.life_project.v1", "recipe": "d10.activity_recipe.v1", "target": "d03.entity_anchor",
    "role": "d03.role_binding"}
TASK_STEPS = ("qualify", "values", "select", "prepare_action", "prepare_body", "register_life_plan",
    "prepare_life", "execute_life", "observe_life", "adopt_outcome", "completed")


def _text(value):
    if type(value) is not str or not 1 <= len(value) <= 4096:
        raise ValueError("bounded actual Owner task locator required")


def _digest(value):
    if type(value) is not str or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
        raise ValueError("Owner task Graph commitment must be SHA256")


def _time(value):
    if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
        raise ValueError("Owner task requires an actual finite UTC bound")


def _ref(value, kind, namespace=None):
    key = AtomKey.from_token(value)
    if key.type_name != kind or namespace is not None and NamespaceId.from_key(key) != namespace:
        raise ValueError("Owner task reference crossed its actual namespace/type")
    return key


def _sources(values, namespace):
    if type(values) is not tuple or not 1 <= len(values) <= 32 or len(set(values)) != len(values):
        raise ValueError("Owner task retains bounded distinct actual Source roots")
    for ref in values: _ref(ref, "memory.source", namespace)


@dataclass(frozen=True, slots=True)
class SubmitOwnerSourceNoteTaskRequestV1:
    body_source_ref: str
    project_ref: str
    recipe_ref: str
    target_entity_ref: str
    role_binding_ref: str
    body_policy_id: str
    body_policy_version: int
    effect_policy_ref: str
    requested_deadline_utc: float

    def __post_init__(self):
        for ref, kind in ((self.body_source_ref, "memory.source"), (self.project_ref, "d10.life_project.v1"),
                (self.recipe_ref, "d10.activity_recipe.v1"), (self.target_entity_ref, "d03.entity_anchor"),
                (self.role_binding_ref, "d03.role_binding")): _ref(ref, kind)
        _text(self.body_policy_id); _text(self.effect_policy_ref); _time(self.requested_deadline_utc)
        if type(self.body_policy_version) is not int or self.body_policy_version < 1:
            raise ValueError("Owner selects an existing registered Body policy version")


@dataclass(frozen=True, slots=True)
class OwnerTaskCauseV1:
    namespace: NamespaceId
    installation_id: str
    manifest_digest: str
    owner_operation_id: str
    owner_actor_ref: str
    owner_guard: ProductionOwnerGuardV1
    request_digest: str
    submitted_at_utc: float
    original_deadline_utc: float
    parent_budget_lease_ref: str
    parent_grant_id: str
    parent_grant_version: int
    parent_grant_digest: str
    audiences: tuple[str, ...]
    schema: str = "d11.owner-source-note-task-cause.v1"

    def __post_init__(self):
        if (self.schema != "d11.owner-source-note-task-cause.v1" or type(self.namespace) is not NamespaceId
                or type(self.owner_guard) is not ProductionOwnerGuardV1
                or type(self.parent_grant_version) is not int or self.parent_grant_version < 1):
            raise ValueError("actual Owner management cause required; platform causes are a different contract")
        for value in (self.installation_id, self.owner_operation_id, self.owner_actor_ref,
                self.parent_budget_lease_ref, self.parent_grant_id): _text(value)
        for value in (self.manifest_digest, self.request_digest, self.parent_grant_digest): _digest(value)
        _ref(self.owner_guard.grant_ref, "d11.owner_grant.v1", self.namespace)
        _time(self.submitted_at_utc); _time(self.original_deadline_utc)
        if (self.submitted_at_utc >= self.original_deadline_utc or type(self.audiences) is not tuple
                or not 1 <= len(self.audiences) <= 32 or len(set(self.audiences)) != len(self.audiences)):
            raise ValueError("Owner task needs its original finite interval and actual audience scope")
        for value in self.audiences: _text(value)

    @property
    def original_ref(self):
        return "owner-source-note-cause:" + canonical_digest((self.namespace, self.owner_operation_id))[:48]

    @property
    def digest(self):
        return canonical_digest(self)


@dataclass(frozen=True, slots=True)
class OwnerTaskBodyPolicyBindingV1:
    body_policy_id: str
    body_policy_version: int
    body_policy_digest: str
    effect_policy_ref: str
    effect_policy_revision: int
    effect_policy_digest: str
    component_id: str
    cpu_ceiling_ms: int

    def __post_init__(self):
        for value in (self.body_policy_id, self.effect_policy_ref, self.component_id): _text(value)
        for value in (self.body_policy_digest, self.effect_policy_digest): _digest(value)
        if (any(type(v) is not int or v < 1 for v in (self.body_policy_version, self.effect_policy_revision))
                or type(self.cpu_ceiling_ms) is not int or not 1 <= self.cpu_ceiling_ms <= 60000):
            raise ValueError("actual policy versions and original bounded CPU intersection required")


@dataclass(frozen=True, slots=True)
class OwnerSourceNoteTaskAuthorizationV2:
    cause: OwnerTaskCauseV1
    request: SubmitOwnerSourceNoteTaskRequestV1
    heads: tuple[tuple[str, GraphVersion, str], ...]
    body_policy: OwnerTaskBodyPolicyBindingV1
    source_refs: tuple[str, ...]
    schema: str = "d11.owner-source-note-task-authorization.v2"

    def __post_init__(self):
        if (self.schema != "d11.owner-source-note-task-authorization.v2" or type(self.cause) is not OwnerTaskCauseV1
                or type(self.request) is not SubmitOwnerSourceNoteTaskRequestV1
                or type(self.body_policy) is not OwnerTaskBodyPolicyBindingV1
                or type(self.heads) is not tuple or len(self.heads) != len(HEAD_KINDS)
                or {row[0] for row in self.heads} != set(HEAD_KINDS)
                or self.cause.request_digest != canonical_digest(self.request)
                or self.cause.original_deadline_utc > self.request.requested_deadline_utc
                or (self.body_policy.body_policy_id, self.body_policy.body_policy_version, self.body_policy.effect_policy_ref) !=
                   (self.request.body_policy_id, self.request.body_policy_version, self.request.effect_policy_ref)):
            raise ValueError("Owner task authorization must retain the exact submitted intent and actual policies")
        expected = {"body_source": self.request.body_source_ref, "project": self.request.project_ref,
            "recipe": self.request.recipe_ref, "target": self.request.target_entity_ref, "role": self.request.role_binding_ref}
        ids = owner_source_note_task_ids_v1(self.cause.namespace, self.cause.owner_operation_id)
        expected.update(goal=ids["goal_key"].token, plan=ids["plan_key"].token)
        for name, version, digest in self.heads:
            if type(version) is not GraphVersion or version.revision < 1 or version.key.token != expected[name]:
                raise ValueError("Owner task must name its exact current and newly composed heads")
            _ref(version.key.token, HEAD_KINDS[name], self.cause.namespace); _digest(digest)
            if name in {"goal", "plan"} and version.revision != 1:
                raise ValueError("Owner task submission creates its own fresh Goal and Plan")
        _sources(self.source_refs, self.cause.namespace)
        if self.request.body_source_ref not in self.source_refs:
            raise ValueError("Owner task lost its actual input Source")
        if len(canonical_serialize(self).encode()) > 65536:
            raise ValueError("Owner task original exceeds its finite metadata bound")

    @property
    def original_ref(self):
        return "owner-source-note-authorization:" + canonical_digest((self.cause.namespace, self.cause.owner_operation_id))[:48]

    @property
    def digest(self):
        return canonical_digest(self)


def owner_source_note_task_ids_v1(namespace, owner_operation_id):
    if type(namespace) is not NamespaceId: raise TypeError("actual Owner task namespace required")
    _text(owner_operation_id)
    marker = canonical_digest(("d11.owner-source-note-task.v1", namespace, owner_operation_id))[:40]
    activity = "owner-note-task:" + marker
    owner = Owner("activity", *namespace.as_tuple, activity)
    return {"activity_id": activity, "job_id": "owner-note-job:" + marker,
        "create_operation_id": "owner-note-create:" + marker,
        "goal_key": AtomKey(owner, "d08.goal.v1", "goal:owner-note:" + marker),
        "plan_key": AtomKey(owner, "d08.personal_plan.v1", "plan:owner-note:" + marker),
        "candidate_ref": "candidate:owner-note:" + marker, "node_id": "task:owner-note:" + marker,
        "selection_operation_id": "owner-note-select:" + marker,
        "responsibility_ref": "owner-note-responsibility:" + marker}


@dataclass(frozen=True, slots=True)
class CreateOwnerSourceNoteTaskRequestV1:
    authorization_original_ref: str

    def __post_init__(self):
        if not self.authorization_original_ref.startswith("owner-source-note-authorization:"):
            raise ValueError("initial Owner task Self creation needs its actual signed authorization")


@dataclass(frozen=True, slots=True)
class OwnerSourceNoteTaskResponsibilityV2:
    namespace: NamespaceId
    installation_id: str
    owner_operation_id: str
    cause_original_ref: str
    cause_original_digest: str
    authorization_original_ref: str
    authorization_original_digest: str
    owner_guard: ProductionOwnerGuardV1
    self_mapping_head: GraphVersion
    self_mapping_digest: str
    self_entity_ref: str
    parent_budget_lease_ref: str
    original_deadline_utc: float
    source_refs: tuple[str, ...]
    schema: str = "d11.owner-source-note-task-responsibility.v2"

    def __post_init__(self):
        if (self.schema != "d11.owner-source-note-task-responsibility.v2" or type(self.namespace) is not NamespaceId
                or type(self.owner_guard) is not ProductionOwnerGuardV1
                or type(self.self_mapping_head) is not GraphVersion or self.self_mapping_head.revision < 1):
            raise ValueError("independent fixed-Self task responsibility required")
        _ref(self.self_mapping_head.key.token, "d03.self_identity_mapping.v1", self.namespace)
        for value in (self.installation_id, self.owner_operation_id, self.cause_original_ref,
                self.authorization_original_ref, self.self_entity_ref, self.parent_budget_lease_ref): _text(value)
        for value in (self.cause_original_digest, self.authorization_original_digest, self.self_mapping_digest): _digest(value)
        _time(self.original_deadline_utc); _sources(self.source_refs, self.namespace)
        CreateOwnerSourceNoteTaskRequestV1(self.authorization_original_ref)

    @property
    def digest(self):
        return canonical_digest(self)


@dataclass(frozen=True, slots=True)
class OwnerSourceNoteTaskContinuationV2:
    cause_original_ref: str
    cause_original_digest: str
    authorization_original_ref: str
    authorization_original_digest: str
    responsibility_ref: str
    responsibility_digest: str
    step: str
    completed_original_refs: tuple[str, ...]
    pending_effect_refs: tuple[str, ...]
    wait_reason: str | None
    cancel_generation: int
    source_refs: tuple[str, ...]
    schema: str = "d11.owner-source-note-task-continuation.v2"

    def __post_init__(self):
        if (self.schema != "d11.owner-source-note-task-continuation.v2" or self.step not in TASK_STEPS
                or type(self.cancel_generation) is not int or self.cancel_generation < 0):
            raise ValueError("Owner SourceNote continuation has another closed task phase")
        for value in (self.cause_original_ref, self.authorization_original_ref, self.responsibility_ref): _text(value)
        for value in (self.cause_original_digest, self.authorization_original_digest, self.responsibility_digest): _digest(value)
        for refs in (self.completed_original_refs, self.pending_effect_refs, self.source_refs):
            if type(refs) is not tuple or len(refs) > 32 or len(set(refs)) != len(refs):
                raise ValueError("task originals and effects must remain bounded and distinct")
            for ref in refs: _text(ref)
        if not self.source_refs or self.pending_effect_refs and self.wait_reason is None:
            raise ValueError("actual pending effects retain a concrete wait instead of authorizing retry")
        if self.wait_reason is not None: _text(self.wait_reason)
        CreateOwnerSourceNoteTaskRequestV1(self.authorization_original_ref)


@dataclass(frozen=True, slots=True)
class AcquireOwnerSourceNoteTaskRequestV1:
    job_ref: str
    holder: str
    lease_seconds: int

    def __post_init__(self):
        _ref(self.job_ref, "runtime.job"); _text(self.holder)
        if not self.holder.startswith("entity:") or type(self.lease_seconds) is not int or not 1 <= self.lease_seconds <= 3600:
            raise ValueError("Owner task acquisition retains its actual Self and finite worker lease")


@dataclass(frozen=True, slots=True)
class CheckpointOwnerSourceNoteTaskRequestV1:
    job_ref: str
    holder: str
    fence: int
    continuation: OwnerSourceNoteTaskContinuationV2
    completion_result_ref: str | None = None

    def __post_init__(self):
        _ref(self.job_ref, "runtime.job"); _text(self.holder)
        if (not self.holder.startswith("entity:") or type(self.fence) is not int or self.fence < 1
                or type(self.continuation) is not OwnerSourceNoteTaskContinuationV2):
            raise ValueError("Owner task checkpoint needs its actual typed leased job")
        if self.completion_result_ref is not None: _text(self.completion_result_ref)
        if (self.continuation.step == "completed") != (self.completion_result_ref is not None):
            raise ValueError("only an actual terminal checkpoint carries its completed artifact original")


def owner_source_note_task_from_wire_v1(raw, cls):
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    if cls not in {SubmitOwnerSourceNoteTaskRequestV1, OwnerTaskCauseV1, OwnerTaskBodyPolicyBindingV1,
            OwnerSourceNoteTaskAuthorizationV2, CreateOwnerSourceNoteTaskRequestV1,
            OwnerSourceNoteTaskResponsibilityV2, OwnerSourceNoteTaskContinuationV2,
            AcquireOwnerSourceNoteTaskRequestV1, CheckpointOwnerSourceNoteTaskRequestV1}:
        raise TypeError("unregistered Owner task contract")
    return decode_typed_production_value_v1(raw, cls)
