"""Compose one bounded Owner SourceNote Goal/Plan from actual committed task inputs."""
from ..domains.d08.execution import Goal, GoalPredicate
from ..domains.d08.personal_plan_v1 import PersonalPlanV1, PlanNodeV2
from ..domains.d08.personal_candidate_v1 import SourceNoteCandidateBindingV1
from ..graph_types import AtomKey
from ..runtime_contracts import NamespaceId, VersionedRef, canonical_digest
from .owner_source_note_task_contract_v1 import (OwnerTaskCauseV1,
    SubmitOwnerSourceNoteTaskRequestV1, owner_source_note_task_ids_v1)
from .d08_source_note_action_v1 import source_note_effect_id_v1
from .d11_life_contract_v1 import POSTCONDITION_ID, life_artifact_ref_v1


def build_owner_source_note_goal_plan_v1(*, cause, request, source_refs, fact_versions,
        body_source_digest, postcondition_build_digest):
    """Pure construction; the Owner W01 producer supplies verified Source/build digests."""
    if type(cause) is not OwnerTaskCauseV1 or type(request) is not SubmitOwnerSourceNoteTaskRequestV1:
        raise TypeError("actual Owner management cause and submitted task required")
    if (cause.request_digest != canonical_digest(request)
            or cause.original_deadline_utc > request.requested_deadline_utc
            or request.body_source_ref not in source_refs):
        raise ValueError("Owner task construction changed its original submitted intent or lifetime")
    for digest in (body_source_digest, postcondition_build_digest):
        if type(digest) is not str or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise ValueError("actual Source and installed postcondition SHA256 commitments required")
    if (type(source_refs) is not tuple or not 1 <= len(source_refs) <= 32
            or len(set(source_refs)) != len(source_refs)
            or any(AtomKey.from_token(ref).type_name != "memory.source"
                or NamespaceId.from_key(AtomKey.from_token(ref)) != cause.namespace for ref in source_refs)):
        raise ValueError("Owner task construction requires its actual namespace Source closure")
    if (type(fact_versions) is not tuple or not 1 <= len(fact_versions) <= 128
            or any(type(ref) is not VersionedRef or ref.version < 1
                or NamespaceId.from_key(AtomKey.from_token(ref.ref)) != cause.namespace for ref in fact_versions)
            or len({ref.ref for ref in fact_versions}) != len(fact_versions)):
        raise ValueError("Owner task construction retains bounded current original fact versions")
    ids = owner_source_note_task_ids_v1(cause.namespace, cause.owner_operation_id)
    expected = {request.body_source_ref, request.project_ref, request.recipe_ref,
        request.target_entity_ref, request.role_binding_ref}
    if not expected <= {ref.ref for ref in fact_versions}:
        raise ValueError("Owner task Plan facts must include each actual submitted selector")
    binding = SourceNoteCandidateBindingV1(ids["candidate_ref"], ids["node_id"], request.project_ref,
        request.recipe_ref, request.body_source_ref, ids["goal_key"].token,
        request.target_entity_ref, request.role_binding_ref)
    action_operation = "personal-source-note-action:" + canonical_digest((cause.namespace,
        ids["selection_operation_id"], binding))[:48]
    effect = source_note_effect_id_v1(cause.namespace, request.project_ref, action_operation)
    predicate = GoalPredicate("artifact_verified", POSTCONDITION_ID, (
        ("artifact_ref", life_artifact_ref_v1(cause.namespace, effect)),
        ("input_digest", body_source_digest), ("build_digest", postcondition_build_digest)),
        cause.submitted_at_utc, cause.original_deadline_utc)
    cancellation = ("owner_authorization_revoked", "source_access_revoked", "task_cancelled", "original_deadline_expired")
    goal = Goal(ids["goal_key"].name, 1, "active", predicate, source_refs,
        (request.project_ref, request.recipe_ref), cause.original_ref, cancellation, ())
    persona = "persona:" + cause.namespace.persona_id
    node = PlanNodeV2(ids["node_id"], persona, (), "source_note", predicate, True, None,
        cause.parent_budget_lease_ref, (predicate,))
    plan = PersonalPlanV1(ids["plan_key"].name, 1, ids["goal_key"].token, 1, "active", persona,
        (node,), (ids["candidate_ref"],), ("project_paused",), ("actual_original_effect_pending",),
        cancellation, source_refs, fact_versions, None)
    return goal, plan
