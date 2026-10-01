"""Pure W01 candidate issuer for one private reply after a committed C02.

``check_inputs`` is a W01-private *version read*, not a check receipt or proof.
It must be assembled from the staged E+1 SQL rows and signed D02/D11 state.
The five actual providers must reissue their checks at seal; this module never
grants communication, admission, a write fence, or permission to send.
"""

from __future__ import annotations

from dataclasses import dataclass
import math

from ..domains.d07 import AttentionTicket, FocusState, read_current_focus_attention_ticket
from ..domains.d08 import (
    ActionIntent, ActionSchema, CommunicationGrantRequest,
    CommunicationSegmentSpec, Goal, GoalPredicate, RequiredCheckSpec,
)
from ..domains.d09 import ClaimKind, SourceReplyExpressionV1, segment_payload_digest
from ..graph_types import AtomKey, GraphSnapshot, GraphVersion
from ..memory_types import access_key
from ..memory_types import SourceRecord, source_key
from ..runtime_contracts import (
    CommandEnvelope, CommitReceipt, NamespaceId, QueryEpoch, VersionedRef,
    canonical_digest,
)
from .issuers import BudgetLeaseGrant, ResourceQuote
from .reply_model_job import CurrentReplyRouteManifestV2
from .reply_entity_route_v2 import CurrentReplyEntityRouteBindingV2
from .restore_anchor import RestoreAnchor
from ..host.post_c02_reply_driver import post_c02_reply_operation_id


_CHECKS = (
    ("role_binding", "d03.role_binding"),
    ("boundary", "d05.boundary"),
    ("source_grant", "d06.source_grant"),
    ("commitment_conflict", "d08.commitment_conflict"),
    ("dispatch_budget", "d11.dispatch_budget"),
)


@dataclass(frozen=True, slots=True)
class CurrentReplyCheckVersionV2:
    """One version set read by W01, before a provider issues its receipt."""

    check_kind: str
    criteria_ref: str
    versions: tuple[VersionedRef, ...]


@dataclass(frozen=True, slots=True)
class CurrentReplyCheckVersionsV2:
    """W01-owned E+1 read closure; possession alone carries no authority."""

    namespace: NamespaceId
    query: QueryEpoch
    source_ref: str
    quote_id: str
    quote_version: int
    grant_id: str
    grant_version: int
    reservation_digest: str
    sets: tuple[CurrentReplyCheckVersionV2, ...]


@dataclass(frozen=True, slots=True)
class PostC02ReplyActionCandidateV2:
    status: str
    missing: tuple[str, ...]
    goal: Goal | None = None
    intent: ActionIntent | None = None
    schema: ActionSchema | None = None
    communication: CommunicationGrantRequest | None = None
    required_input_versions: tuple[VersionedRef, ...] = ()
    graph_reads: tuple[GraphVersion, ...] = ()


def _hold(reason: str) -> PostC02ReplyActionCandidateV2:
    return PostC02ReplyActionCandidateV2("hold", (reason,))


def post_c02_reply_action_ids_v2(
    c02_operation_id: str, source_ref: str,
) -> tuple[str, str, str]:
    """Stable goal/action/schema IDs before W01 stages its E+1 rows."""
    if (type(c02_operation_id) is not str or not c02_operation_id
            or type(source_ref) is not str or not source_ref):
        raise ValueError("original C02 operation and source are required")
    operation_id = post_c02_reply_operation_id(c02_operation_id, source_ref)
    stem = {"version": 2, "operation_id": operation_id,
            "source_ref": source_ref}
    return tuple(prefix + canonical_digest(stem)
                 for prefix in ("goal:", "action:", "schema:"))


def _issue_post_c02_reply_action_v2(
    *, envelope: CommandEnvelope, c02_receipt: CommitReceipt,
    route: CurrentReplyRouteManifestV2,
    route_binding: CurrentReplyEntityRouteBindingV2, source_ref: str,
    snapshot: GraphSnapshot, query: QueryEpoch,
    attention: AttentionTicket, focus: FocusState,
    budget_grant: BudgetLeaseGrant, resource_quote: ResourceQuote,
    expression: SourceReplyExpressionV1, anchor: RestoreAnchor,
    now_utc: float,
    check_inputs: CurrentReplyCheckVersionsV2 | None = None,
    provisional: bool = False,
) -> PostC02ReplyActionCandidateV2:
    """Form a deterministic candidate; HOLD unless every input is explicit.

    W01 must obtain ``check_inputs`` within its current staged SQL transaction.
    In particular its D11 set must include the actual reservation digest and
    lease ancestry. The caller cannot provide receipts or a prebuilt bundle.
    """
    if (type(envelope) is not CommandEnvelope or type(c02_receipt) is not CommitReceipt
            or type(route) is not CurrentReplyRouteManifestV2
            or type(route_binding) is not CurrentReplyEntityRouteBindingV2
            or type(snapshot) is not GraphSnapshot or type(query) is not QueryEpoch
            or type(attention) is not AttentionTicket or type(focus) is not FocusState
            or type(budget_grant) is not BudgetLeaseGrant
            or type(resource_quote) is not ResourceQuote
            or type(expression) is not SourceReplyExpressionV1
            or type(anchor) is not RestoreAnchor
            or type(now_utc) not in (int, float) or not math.isfinite(now_utc)):
        return _hold("reply.typed_current_inputs")
    namespace = envelope.authority.namespace
    operation_id = post_c02_reply_operation_id(c02_receipt.operation_id, source_ref)
    if (c02_receipt.status not in {"committed", "duplicate"}
            or not {"memory.episode.v1", "memory.subjective_trace.v2"}
               <= {row.key.type_name for row in c02_receipt.write_versions}
            or c02_receipt.operation_id != route.c02_operation_id
            or route.namespace != namespace or route.source_ref != source_ref
            or envelope.identity.operation_id != operation_id
            or c02_receipt.operation_id not in envelope.causation
            or envelope.source_qualification.source_refs != (source_ref,)
            or source_ref not in envelope.input_refs
            or envelope.authority.purpose != "expression"
            or envelope.authority.audience != (route.conversation_ref,)
            or query.namespace != namespace or query.scope_ref != "all"
            or len(snapshot.epochs) != 1
            or (snapshot.epochs[0].bot, snapshot.epochs[0].persona,
                snapshot.epochs[0].revision)
               != (*namespace.as_tuple,
                   query.revision - 1 if provisional else query.revision)
            or not now_utc < envelope.deadline_utc):
        return _hold("reply.original_c02_route_or_epoch")
    if route.route_digest != canonical_digest({
            "account_ref": route.platform_ref,
            "destination_ref": route.conversation_ref,
            "scene_ref": route.scene_ref,
    }):
        return _hold("reply.route_digest")
    if ((route_binding.namespace, route_binding.c02_operation_id,
         route_binding.source_ref, route_binding.platform_ref,
         route_binding.conversation_ref, route_binding.scene_ref) != (
         namespace, route.c02_operation_id, source_ref, route.platform_ref,
         route.conversation_ref, route.scene_ref)
            or not route_binding.target_entity_ref.startswith("entity:account-v1:")
            or route_binding.query != QueryEpoch(namespace, "all", query.revision - 1)
            or (route_binding.valid_until_utc is not None
                and now_utc >= route_binding.valid_until_utc)):
        return _hold("reply.current_entity_route_binding")
    binding_versions = (
        route_binding.anchor_version, route_binding.binding_version,
        route_binding.arrival_event_version,
        route_binding.binding_evidence_event_version,
        route_binding.source_version, route_binding.access_version,
        *route_binding.binding_scan_versions,
    )
    if (type(route_binding.binding_scan_versions) is not tuple
            or any(type(version) is not GraphVersion
                   for version in binding_versions)
            or any((atom := snapshot.get(version.key)) is None
                   or not atom.valid or atom.revision != version.revision
                   for version in binding_versions)):
        return _hold("reply.current_entity_route_graph_versions")
    try:
        source = AtomKey.from_token(source_ref)
    except (TypeError, ValueError):
        return _hold("reply.canonical_source")
    if (source != source_key(*namespace.as_tuple, source.owner.subject or "")):
        return _hold("reply.canonical_source")
    selected = read_current_focus_attention_ticket(snapshot, namespace, now=now_utc)
    if (selected is None or selected.ticket != attention or selected.focus != focus
            or attention.causal_root != source_ref
            or attention.source_refs != (source_ref,)
            or attention.category != "interaction"):
        return _hold("reply.current_attention_focus")
    if (type(expression.segments) is not tuple or len(expression.segments) != 1
            or not expression.claims):
        return _hold("reply.one_source_segment")
    segment = expression.segments[0]
    if (not segment.body or segment.media_refs or segment.delay_seconds != 0
            or not segment.covered_slots or not segment.claim_uses
            or segment_payload_digest(segment.body, segment.media_refs,
                                      segment.claim_uses) != expression.payload_digest
            or any(claim.kind is not ClaimKind.REPORTED_CLAIM
                   or claim.source_refs != (source_ref,)
                   or claim.allowed_audiences != (route.conversation_ref,)
                   or claim.disclosure_ref != source_ref
                   for claim in expression.claims)):
        return _hold("reply.private_expression_manifest")
    identity = envelope.identity
    if (budget_grant.bot_id, budget_grant.persona_id) != namespace.as_tuple:
        return _hold("reply.budget_namespace")
    if (resource_quote.bot_id, resource_quote.persona_id,
            resource_quote.activity_id, resource_quote.operation_id,
            resource_quote.effect_id, resource_quote.parent_budget_lease_ref) != (
            *namespace.as_tuple, identity.activity_id, identity.operation_id,
            identity.effect_id, budget_grant.lease_id):
        return _hold("reply.quote_identity")
    if (resource_quote.work_kind != "message"
            or resource_quote.work_kind not in budget_grant.allowed_work_kinds
            or resource_quote.valid_until_utc <= now_utc
            or budget_grant.valid_until_utc <= now_utc
            or resource_quote.deadline_utc < envelope.deadline_utc
            or any(amount > budget_grant.max_ceiling.get(name, 0)
                   for name, amount in resource_quote.ceiling.items())):
        return _hold("reply.current_budget_quote")
    if identity.effect_id is None or anchor.execution_seq < 0:
        return _hold("reply.effect_or_execution_anchor")
    goal_id, action_id, schema_id = post_c02_reply_action_ids_v2(
        c02_receipt.operation_id, source_ref)
    if type(check_inputs) is not CurrentReplyCheckVersionsV2:
        return _hold("reply.current_e_plus_one_check_versions")
    if (type(check_inputs.sets) is not tuple
            or any(type(item) is not CurrentReplyCheckVersionV2
                   or type(item.versions) is not tuple
                   or any(type(version) is not VersionedRef
                          for version in item.versions)
                   for item in check_inputs.sets)):
        return _hold("reply.typed_current_check_versions")
    if ((check_inputs.namespace, check_inputs.query, check_inputs.source_ref,
         check_inputs.quote_id, check_inputs.quote_version,
         check_inputs.grant_id, check_inputs.grant_version) != (
         namespace, query, source_ref, resource_quote.quote_id,
         resource_quote.version, budget_grant.grant_id, budget_grant.version)
            or type(check_inputs.reservation_digest) is not str
            or len(check_inputs.reservation_digest) != 64
            or any(char not in "0123456789abcdef"
                   for char in check_inputs.reservation_digest)
            or len(check_inputs.sets) != len(_CHECKS)):
        return _hold("reply.five_current_check_sets")
    sets = {item.check_kind: item for item in check_inputs.sets}
    if len(sets) != len(_CHECKS) or set(sets) != {kind for kind, _ in _CHECKS}:
        return _hold("reply.five_current_check_sets")
    d08_expected = {
        "d08.commitment_conflict.criteria.v1": 1,
        goal_id: 1,
        f"commitments-query:persona:{namespace.persona_id}": query.revision,
        f"execution-epoch:{action_id}": anchor.execution_seq,
        f"cancellation-epoch:{action_id}": 1,
    }
    graph = {atom.key.token: atom for atom in snapshot.atoms}
    if len(graph) != len(snapshot.atoms):
        return _hold("reply.duplicate_graph_atoms")
    specs = []
    pinned = []
    for kind, provider in _CHECKS:
        item = sets[kind]
        versions = {v.ref: v.version for v in item.versions}
        if (not item.criteria_ref or not item.versions
                or len(versions) != len(item.versions)
                or item.criteria_ref not in versions
                or any(v.version < 1 for v in item.versions
                       if v.ref != f"execution-epoch:{action_id}")):
            return _hold(f"reply.{kind}_versions")
        if kind == "commitment_conflict" and (
                item.criteria_ref != "d08.commitment_conflict.criteria.v1"
                or versions != d08_expected):
            return _hold("reply.d08_fixed_versions")
        if kind in {"role_binding", "boundary", "source_grant"}:
            keys = {}
            for version in item.versions:
                if kind in {"role_binding", "boundary"} and version.ref == (
                        "d03.role_binding" if kind == "role_binding"
                        else "d05.boundary"):
                    if version.version != query.revision:
                        return _hold(f"reply.{kind}_query_epoch")
                    continue
                try:
                    key = AtomKey.from_token(version.ref)
                except (TypeError, ValueError):
                    if kind not in {"role_binding", "boundary"}:
                        return _hold(f"reply.{kind}_graph_versions")
                    type_name = ("d03.role_binding" if kind == "role_binding"
                                 else "d05.boundary_rule")
                    matches = [atom.key for atom in snapshot.atoms
                               if atom.key.type_name == type_name
                               and atom.key.name == version.ref and atom.valid]
                    if len(matches) != 1:
                        return _hold(f"reply.{kind}_named_graph_versions")
                    key = matches[0]
                if key in keys:
                    return _hold(f"reply.{kind}_duplicate_graph_version")
                keys[key] = version.version
            if (item.criteria_ref not in graph
                    or len(keys) != len(item.versions) - (
                        1 if kind in {"role_binding", "boundary"} else 0)
                    or any(key.token not in graph or not graph[key.token].valid
                           or graph[key.token].revision != revision
                           for key, revision in keys.items())):
                return _hold(f"reply.{kind}_graph_versions")
            pinned.extend(GraphVersion(key, revision) for key, revision in keys.items())
        if kind == "source_grant":
            pending = [source.owner.subject or ""]
            seen = set()
            while pending:
                source_id = pending.pop()
                if source_id in seen:
                    continue
                seen.add(source_id)
                key = source_key(*namespace.as_tuple, source_id)
                access = access_key(*namespace.as_tuple, source_id)
                if (key.token not in versions or access.token not in versions
                        or key.token not in graph or access.token not in graph):
                    return _hold("reply.d06_source_access_closure")
                try:
                    record = SourceRecord.from_dict(graph[key.token].value)
                except (TypeError, ValueError):
                    return _hold("reply.d06_source_access_closure")
                if record.source_id != source_id:
                    return _hold("reply.d06_source_access_closure")
                pending.extend(record.parent_source_ids)
        if kind == "dispatch_budget" and (
                item.criteria_ref != f"d02.resource_quote:{resource_quote.quote_id}"
                or versions.get(item.criteria_ref) != resource_quote.version
                or f"d11.budget.grant:{budget_grant.lease_id}" not in versions
                or versions[f"d11.budget.grant:{budget_grant.lease_id}"]
                   != budget_grant.version
                or versions.get(
                    f"d11.budget.reservation:{budget_grant.lease_id}:"
                    f"{operation_id}:{check_inputs.reservation_digest}") != 1
                or f"d11.budget.lease:{budget_grant.lease_id}" not in versions):
            return _hold("reply.d11_signed_reservation_versions")
        specs.append(RequiredCheckSpec(
            kind, provider, f"persona:{namespace.persona_id}", action_id,
            "expression", item.criteria_ref, item.versions))
    predicate = GoalPredicate(
        "communicated", "d11.delivery", (),
        float(envelope.source_qualification.learned_at),
        float(envelope.deadline_utc))
    goal = Goal(goal_id, 1, "active", predicate, (source_ref,), (), None, (), ())
    parameters_digest = canonical_digest({
        "route_digest": route.route_digest,
        "entity_route_binding_digest": route_binding.binding_digest,
        "target_entity_ref": route_binding.target_entity_ref,
        "source_ref": source_ref,
        "expression_provenance": expression.provenance_digest,
        "expression_payload": expression.payload_digest,
        "attention_id": attention.ticket_id,
        "focus_epoch": focus.focus_epoch,
        "quote_id": resource_quote.quote_id,
        "quote_version": resource_quote.version,
        "budget_grant_id": budget_grant.grant_id,
        "budget_grant_version": budget_grant.version,
        "anchor_proof": anchor.proof,
    })
    intent = ActionIntent(
        action_id, 1, goal_id, (), route_binding.target_entity_ref, "message",
        "expression", "limited", parameters_digest, identity, schema_id,
        tuple(specs), predicate, (identity.effect_id,), None, (source_ref,))
    schema = ActionSchema(schema_id, "message", False, tuple(specs))
    communication = CommunicationGrantRequest(
        "communication:" + canonical_digest({"action_id": action_id}),
        "contact:" + canonical_digest({"route": route.route_digest}),
        1, (route.conversation_ref,), segment.covered_slots,
        (ClaimKind.REPORTED_CLAIM.value,), (),
        (CommunicationSegmentSpec(
            segment.segment_id, segment.effect_id, 0,
            expression.payload_digest, len(segment.body), (), None),), 0)
    return PostC02ReplyActionCandidateV2(
        "provisional" if provisional else "candidate", (),
        goal, intent, schema, communication,
        tuple(v for item in check_inputs.sets for v in item.versions),
        tuple(dict.fromkeys((*selected.source_versions,
                            selected.focus_version, selected.ticket_version,
                            *binding_versions,
                            *pinned))),
    )


def issue_post_c02_reply_action_v2(
    *, envelope: CommandEnvelope, c02_receipt: CommitReceipt,
    route: CurrentReplyRouteManifestV2,
    route_binding: CurrentReplyEntityRouteBindingV2, source_ref: str,
    snapshot: GraphSnapshot, query: QueryEpoch,
    attention: AttentionTicket, focus: FocusState,
    budget_grant: BudgetLeaseGrant, resource_quote: ResourceQuote,
    expression: SourceReplyExpressionV1, anchor: RestoreAnchor,
    now_utc: float, check_inputs: CurrentReplyCheckVersionsV2 | None = None,
) -> PostC02ReplyActionCandidateV2:
    """Rebuild from the actual staged E+1 snapshot and current W01 reads."""
    return _issue_post_c02_reply_action_v2(
        envelope=envelope, c02_receipt=c02_receipt, route=route,
        route_binding=route_binding,
        source_ref=source_ref, snapshot=snapshot, query=query,
        attention=attention, focus=focus, budget_grant=budget_grant,
        resource_quote=resource_quote, expression=expression,
        anchor=anchor, now_utc=now_utc, check_inputs=check_inputs)


def prepare_post_c02_reply_action_provisional_v2(
    *, envelope: CommandEnvelope, c02_receipt: CommitReceipt,
    route: CurrentReplyRouteManifestV2,
    route_binding: CurrentReplyEntityRouteBindingV2, source_ref: str,
    snapshot: GraphSnapshot, expected_query: QueryEpoch,
    attention: AttentionTicket, focus: FocusState,
    budget_grant: BudgetLeaseGrant, resource_quote: ResourceQuote,
    expression: SourceReplyExpressionV1, anchor: RestoreAnchor,
    now_utc: float, projected_check_inputs: CurrentReplyCheckVersionsV2 | None = None,
) -> PostC02ReplyActionCandidateV2:
    """Stage-only draft from E; W01 must later compare an actual E+1 reissue."""
    return _issue_post_c02_reply_action_v2(
        envelope=envelope, c02_receipt=c02_receipt, route=route,
        route_binding=route_binding,
        source_ref=source_ref, snapshot=snapshot, query=expected_query,
        attention=attention, focus=focus, budget_grant=budget_grant,
        resource_quote=resource_quote, expression=expression,
        anchor=anchor, now_utc=now_utc,
        check_inputs=projected_check_inputs, provisional=True)


__all__ = (
    "CurrentReplyCheckVersionV2", "CurrentReplyCheckVersionsV2",
    "PostC02ReplyActionCandidateV2", "post_c02_reply_action_ids_v2",
    "issue_post_c02_reply_action_v2",
    "prepare_post_c02_reply_action_provisional_v2",
)
