"""Stage proactive actions from whole paid content and six current criteria."""
from dataclasses import dataclass

from ..domains.d08.execution import (
    ActionIntent, ActionSchema, BASE_REQUIRED_PROVIDERS, PROACTIVE_REQUIRED_PROVIDER,
    CommunicationGrantRequest, CommunicationSegmentSpec, Goal, GoalExecutionProvider,
    GoalPredicate, RequiredCheckSpec,
)
from ..domains.d09.contact_batch_v1 import ContactReviewedContentV1
from ..runtime_contracts import CommandEnvelope, DependencySet, DomainProposal, GraphVersion, NamespaceId, VersionedRef, canonical_digest
from .contact_route_binding_v1 import CurrentContactRouteBindingV1, contact_route_semantic_digest_v1
from .issuers import ResourceQuote, BudgetLeaseGrant


CONTACT_REQUIRED_PROVIDERS_V1 = (*BASE_REQUIRED_PROVIDERS, PROACTIVE_REQUIRED_PROVIDER)


@dataclass(frozen=True, slots=True)
class ContactCheckVersionSetV1:
    kind: str
    criteria_ref: str
    versions: tuple[VersionedRef, ...]


@dataclass(frozen=True, slots=True)
class CurrentContactCheckVersionsV1:
    namespace: NamespaceId
    graph_epoch: int
    read_versions: tuple[GraphVersion, ...]
    sets: tuple[ContactCheckVersionSetV1, ...]
    quote_id: str
    quote_version: int
    budget_grant_id: str
    budget_grant_version: int
    reservation_digest: str
    owner_policy_ref: str
    owner_policy_digest: str


@dataclass(frozen=True, slots=True)
class ContactActionStageV1:
    content: ContactReviewedContentV1
    segment_index: int
    goal: Goal
    intent: ActionIntent
    schema: ActionSchema
    proposal: DomainProposal


def contact_final_action_ids_v1(contact_id, index):
    if not contact_id.startswith("contact:") or type(index) is not int or not 0 <= index < 3:
        raise ValueError("contact action needs its stable finite position")
    whole = canonical_digest(("d08.contact-goal.v1", contact_id))[:48]
    segment = canonical_digest(("d08.contact-action.v1", contact_id, index))[:48]
    return {"goal": "goal:contact:" + whole, "action": "action:contact:" + segment,
        "schema": "d08.contact-message.v1"}


def contact_action_parameters_digest_v1(content, index, *, parent_grant_ref=None, parent_grant_digest=None):
    item = content.segments[index]
    if ((index == 0 and (parent_grant_ref is not None or parent_grant_digest is not None))
            or (index > 0 and (not parent_grant_ref or not parent_grant_digest))):
        raise ValueError("later contact actions must bind their actual adopted parent grant")
    return canonical_digest({"schema": "d08.contact-message-parameters.v1", "contact_id": content.contact_id,
        "whole_content_digest": content.digest, "position": index, "segment_id": item.segment.segment_id,
        "payload_digest": item.payload_digest, "parent_grant_ref": parent_grant_ref,
        "parent_grant_digest": parent_grant_digest})


def prepare_contact_action_stage_v1(*, envelope, content, index, current_checks, route, quote, grant,
        now_utc, parent_goal=None, parent_grant_ref=None, parent_grant_digest=None):
    """Produce graph material, leaving provider qualification and admission to W01."""
    if (type(envelope) is not CommandEnvelope or type(content) is not ContactReviewedContentV1
            or type(current_checks) is not CurrentContactCheckVersionsV1
            or type(route) is not CurrentContactRouteBindingV1
            or type(quote) is not ResourceQuote or type(grant) is not BudgetLeaseGrant
            or type(index) is not int or not 0 <= index < len(content.segments)):
        raise TypeError("contact action needs actual typed content, route and resource inputs")
    namespace, identity, item = content.namespace, envelope.identity, content.segments[index]
    ids = contact_final_action_ids_v1(content.contact_id, index)
    if ((namespace, content.activity_id, item.operation_id, item.segment.effect_id) !=
            (envelope.authority.namespace, identity.activity_id, identity.operation_id, identity.effect_id)
            or envelope.authority.purpose != "expression" or envelope.authority.audience != (content.audience_id,)
            or not now_utc < envelope.deadline_utc <= content.valid_until
            or current_checks.namespace != namespace or len(envelope.version_guard.query_epochs) != 1
            or current_checks.graph_epoch != envelope.version_guard.query_epochs[0].revision + 1
            or not set(content.read_versions).issubset(envelope.version_guard.read_versions)
            or (route.namespace, route.conversation_ref, route.scene_ref) !=
               (namespace, content.audience_id, content.scene_id)
            or contact_route_semantic_digest_v1(route) != content.route_semantic_digest
            or (quote.bot_id, quote.persona_id, quote.activity_id, quote.operation_id, quote.effect_id) !=
               (*namespace.as_tuple, identity.activity_id, identity.operation_id, identity.effect_id)
            or quote.work_kind != "message" or quote.work_kind not in grant.allowed_work_kinds
            or quote.deadline_utc != envelope.deadline_utc or quote.valid_until_utc <= now_utc
            or (quote.parent_budget_lease_ref, envelope.parent_budget_lease_ref) != (grant.lease_id, grant.lease_id)
            or grant.valid_until_utc <= now_utc
            or (current_checks.quote_id, current_checks.quote_version, current_checks.budget_grant_id,
                current_checks.budget_grant_version) != (quote.quote_id, quote.version, grant.grant_id, grant.version)
            or not current_checks.reservation_digest or not current_checks.owner_policy_ref
            or len(current_checks.owner_policy_digest) != 64
            or len(current_checks.sets) != 6
            or {row.kind for row in current_checks.sets} != {kind for kind, _ in CONTACT_REQUIRED_PROVIDERS_V1}):
        raise ValueError("contact action identity, current scope or real reservation changed")
    versions = {row.kind: row for row in current_checks.sets}
    specs = []
    for kind, provider in CONTACT_REQUIRED_PROVIDERS_V1:
        row = versions[kind]
        if (not row.versions or row.criteria_ref not in {value.ref for value in row.versions}
                or len({value.ref for value in row.versions}) != len(row.versions)):
            raise ValueError("contact requires six exact current criterion version sets")
        specs.append(RequiredCheckSpec(kind, provider, "persona:" + namespace.persona_id,
            ids["action"], "expression", row.criteria_ref, row.versions))
    source_refs = envelope.source_qualification.source_refs
    if not source_refs:
        raise ValueError("contact action lost its actual qualified Source family")
    if index == 0:
        if parent_goal is not None:
            raise ValueError("the first contact creates its own stable goal")
        predicate = GoalPredicate("communicated", "d11.delivery", (),
            float(envelope.source_qualification.learned_at), float(content.valid_until))
        goal = Goal(ids["goal"], 1, "active", predicate, tuple(source_refs), (), None, (), ())
    else:
        if (type(parent_goal) is not Goal or parent_goal.goal_id != ids["goal"]
                or parent_goal.state != "active"):
            raise ValueError("later contact segments require the original active goal")
        goal, predicate = parent_goal, parent_goal.satisfaction_predicate
    action = ActionIntent(ids["action"], 1, goal.goal_id, (), route.target_entity_ref,
        "message", "expression", "limited", contact_action_parameters_digest_v1(content, index,
            parent_grant_ref=parent_grant_ref, parent_grant_digest=parent_grant_digest),
        identity, ids["schema"], tuple(specs), predicate, (item.segment.effect_id,), None, tuple(source_refs))
    schema, provider = ActionSchema(ids["schema"], "message", True, tuple(specs)), GoalExecutionProvider()
    proposal = DomainProposal("d08", "d08.proposal.v1", provider.descriptor.request_schema_hash,
        envelope, (), DependencySet(), (), ())
    if index == 0:
        proposal = provider.prepare_goal_candidate(proposal, goal, source_ref=source_refs[0])
    proposal = provider.prepare_action_candidate(proposal, action, schema)
    return ContactActionStageV1(content, index, goal, action, schema, proposal)


def contact_whole_grant_request_v1(content):
    return CommunicationGrantRequest("communication:" + content.contact_id.removeprefix("contact:"),
        content.contact_id, 1, (content.audience_id,), content.required_slots,
        tuple(sorted({claim.kind.value for item in content.segments for claim in item.claims})), (),
        tuple(CommunicationSegmentSpec(item.segment.segment_id, item.segment.effect_id, item.position,
            item.payload_digest, len(item.segment.body), (), item.prerequisite_segment_ref)
            for item in content.segments), content.cancellation_epoch)
