"""Current six-provider qualification for an installed contact transaction."""
from dataclasses import dataclass

from ..domains.d03.context import RoleBindingRequest
from ..domains.d05.prebatch_boundary import issue_prebatch_boundary_check_v1
from ..domains.d06.source_grant import SourceGrantRead, provide_source_grant_check
from ..domains.d08.contact_dispatch_check_v1 import DispatchCheckScopeV2, read_contact_dispatch_check_scope_v1
from ..domains.d08.dispatch_check import D08_CRITERIA_REF_V1, D08_CRITERIA_VERSION_V1
from ..domains.d10 import decode_contact_policy, decode_proactive_opportunity
from ..graph_types import AtomKey, GraphVersion, Owner
from ..memory_types import access_key, source_key
from ..runtime_contracts import CheckReceipt, QueryEpoch, VersionedRef, canonical_digest
from .budget import get_budget_lease
from .contact_final_action_v1 import (
    ContactCheckVersionSetV1, CurrentContactCheckVersionsV1, contact_final_action_ids_v1,
    require_contact_segment_index_v1,
)
from .contact_route_binding_v1 import contact_route_semantic_digest_v1, read_current_contact_route_binding_v1
from .d10_contact_policy_authority_v1 import require_current_contact_policy_v1
from .dispatch_budget_check import _observed_versions
from .dispatch_current_contact import read_current_contact
from .dispatch_current_projection import derive_current_domain_reads, read_current_dispatch_projection
from .dispatch_source_correction_barrier import read_source_correction_barrier
from .installed_dispatch_admission_issuer import inspect_current_d11_dispatch_budget
from .structural_source_closure_v1 import read_current_structural_source_closure_v1


@dataclass(frozen=True, slots=True)
class CurrentContactQualificationV1:
    checks: tuple[CheckReceipt, ...]
    check_versions: CurrentContactCheckVersionsV1
    positive_reads: tuple[GraphVersion, ...]
    negative_predicates: tuple[str, ...]
    d08_scope: DispatchCheckScopeV2
    route_semantic_digest: str
    owner_policy_digest: str

    @property
    def digest(self):
        return canonical_digest(self)


def _social_reads(db, snapshot, query, content, route, context, now):
    projection = read_current_dispatch_projection(db, content.namespace, snapshot, query)
    request = RoleBindingRequest('persona:' + content.namespace.persona_id,
        route.target_entity_ref, None, content.scene_id, 'message', 'expression', now, True)
    role, boundary = derive_current_domain_reads(db, projection, request, context)
    if projection.coverage != 'full' or role.status != 'complete' or boundary.coverage != 'full':
        raise ValueError('contact social inventory is incomplete')
    return projection, role, boundary


def _plan_policy(db, read, content, current_policy, scope, now):
    from ..domains.d08.contact_plan_v1 import decode_contact_plan_v1
    atom = read.head(db, content.plan_version.key, required=True)
    plan = decode_contact_plan_v1(atom.value)
    if atom.revision != content.plan_version.revision or canonical_digest(plan) != content.plan_digest:
        raise ValueError('contact whole content plan changed')
    opportunity = read.head(db, AtomKey.from_token(plan.opportunity_ref.ref), required=True)
    parsed = decode_proactive_opportunity(opportunity.value, content.namespace)
    policies = tuple(atom for atom in read.complete_inventory(db, 'd10.contact_policy.v1')
        if atom.valid and atom.value['approval_ref'] == plan.policy_original_ref)
    if len(policies) != 1:
        raise ValueError('contact has no unique current adopted Owner policy')
    policy = require_current_contact_policy_v1(current_policy, scope, policies[0].value, now=now)
    if policy.digest != plan.policy_original_digest:
        raise ValueError('contact current Owner approval changed')
    return plan, policies[0], decode_contact_policy(policies[0].value, content.namespace), opportunity, parsed


def read_contact_check_versions_locked_v1(db, snapshot, query, scope, *, current_read,
        content, segment_index, route, context, d02_issuer, d11_issuer, quote, grant,
        current_policy, now_utc, projected=False):
    """Read raw inputs; E+1 predictions never constitute provider approval."""
    from .contact_final_projection_v1 import require_contact_projection_read_v1
    require_contact_projection_read_v1(current_read, db,
        phases=('pre_e',) if projected is True else ('provisional_e_plus_1', 'post_cas_e_plus_1'))
    if type(projected) is not bool:
        raise ValueError('Contact projection mode must match its private installed phase')
    require_contact_segment_index_v1(content, segment_index)
    current_read.check(db)
    ns = content.namespace
    if (not db.in_transaction or query != QueryEpoch(ns, 'all', snapshot.epochs[0].revision)
            or current_read.frame.snapshot != snapshot or scope.namespace != ns
            or query.revision != scope.graph_epoch.revision + int(not projected)
            or scope.operation != 'write'):
        raise ValueError('contact check versions lack their actual write projection')
    actual_route = read_current_contact_route_binding_v1(db, current_read,
        account_ref=route.account_version.key.token, target_entity_ref=route.target_entity_ref,
        audience=content.audience_id)
    if actual_route != route or contact_route_semantic_digest_v1(route) != content.route_semantic_digest:
        raise ValueError('contact route changed after paid review')
    plan, policy_atom, policy, opportunity_atom, opportunity = _plan_policy(
        db, current_read, content, current_policy, scope, now_utc)
    projection, role, boundary = _social_reads(db, snapshot, query, content, route, context, now_utc)
    roots = current_read.frame.envelope.source_qualification.source_refs
    expression = current_read.source_family(db, roots, purpose='expression', audience=content.audience_id)
    source_versions = []
    for ref in sorted(expression):
        key = AtomKey.from_token(ref)
        for item in (key, access_key(*ns.as_tuple, key.owner.subject)):
            atom = current_read.head(db, item, required=True)
            source_versions.append(VersionedRef(item.token, atom.revision))
    criterion = current_read.head(db, AtomKey.from_token(plan.source_ref.ref), required=True)
    criteria = VersionedRef(criterion.key.token, criterion.revision)
    if criteria not in source_versions:
        # D06 checks every pinned input, including this actual Graph criterion.
        # It does not make the criterion another expression root.
        source_versions.append(criteria)
    epoch = query.revision + int(projected)
    ids = contact_final_action_ids_v1(content.contact_id, segment_index)
    owner = Owner('activity', *ns.as_tuple, content.activity_id)
    goal = current_read.head(db, AtomKey(owner, 'd08.goal.v1', ids['goal']))
    cancellation = current_read.head(db, AtomKey(owner, 'd08.action_cancellation.v1', ids['action']))
    if (not projected and (not goal.valid or not cancellation.valid)):
        raise ValueError('contact action must exist in the actual E+1 projection')
    if (d02_issuer._load_quote(db, quote.quote_id, quote.version) != quote
            or d11_issuer.current_budget_grant(db, grant.lease_id) != grant):
        raise ValueError('contact signed quote or budget grant changed')
    reserve = db.execute('SELECT digest,state FROM runtime_budget_reservations '
        'WHERE lease_id=? AND operation_id=?', (grant.lease_id, quote.operation_id)).fetchone()
    if reserve is None or reserve[1] != 'reserved':
        raise ValueError('contact message reservation is not held')
    budget = (VersionedRef('d02.resource_quote:' + quote.quote_id, quote.version),
        *_observed_versions(db, get_budget_lease(db, grant.lease_id), quote.operation_id, reserve[0]),
        VersionedRef('d11.budget.grant:' + grant.lease_id, grant.version))
    claims = []
    for type_name in ('d10.contact_claim.v1', 'd10.contact_claim.v2'):
        for atom in current_read.complete_inventory(db, type_name):
            raw = atom.value
            if atom.valid and (raw['subject_ref'], raw['channel'], raw['category']) == (
                    opportunity.subject_ref, opportunity.channel, opportunity.category):
                claims.append(VersionedRef(raw['contact_id'], atom.revision))
    contact_versions = (criteria, VersionedRef(policy.policy_id, policy_atom.revision),
        VersionedRef(opportunity.opportunity_id, opportunity_atom.revision),
        VersionedRef(f'd10.contact_policy:{opportunity.subject_ref}:{opportunity.channel}:{opportunity.category}', epoch),
        *sorted(claims, key=lambda item: item.ref))
    if projected:
        from ..domains.d10.contact_claim_v2 import contact_claim_key_v2
        own = current_read.head(db, contact_claim_key_v2(ns, content.contact_id))
        if own.revision != 0 or own.valid or any(v.ref == content.contact_id for v in claims):
            raise ValueError('Contact planned whole claim is already occupied')
        contact_versions = contact_versions[:4] + tuple(sorted((*claims, VersionedRef(content.contact_id, 1)), key=lambda v:v.ref))
    sets = (
        ContactCheckVersionSetV1('role_binding', criteria.ref, (criteria,
            VersionedRef('d03.role_binding', epoch), *sorted((VersionedRef(v.key.name, v.revision)
                for v in role.read_versions if v.key.name in role.matched_bindings), key=lambda v: v.ref))),
        ContactCheckVersionSetV1('boundary', criteria.ref, (criteria,
            VersionedRef('d05.boundary', epoch), *(VersionedRef(r.rule_id, r.scope_version) for r in boundary.rules))),
        ContactCheckVersionSetV1('source_grant', criteria.ref, tuple(source_versions)),
        ContactCheckVersionSetV1('commitment_conflict', D08_CRITERIA_REF_V1, (
            VersionedRef(D08_CRITERIA_REF_V1, D08_CRITERIA_VERSION_V1),
            VersionedRef(ids['goal'], goal.revision if goal.valid else 1),
            VersionedRef('commitments-query:persona:' + ns.persona_id, epoch),
            VersionedRef('execution-epoch:' + ids['action'], scope.pinned_anchor.execution_seq),
            VersionedRef('cancellation-epoch:' + ids['action'], cancellation.revision if cancellation.valid else 1))),
        ContactCheckVersionSetV1('dispatch_budget', budget[0].ref, budget),
        ContactCheckVersionSetV1('contact_policy', criteria.ref, contact_versions),
    )
    return CurrentContactCheckVersionsV1(ns, epoch,
        tuple(GraphVersion(a.key, a.revision) for a in snapshot.atoms if a.valid), sets,
        quote.quote_id, quote.version, grant.grant_id, grant.version, reserve[0],
        current_policy.original.original_ref,
        current_policy.original.digest)


def issue_contact_checks_locked_v1(db, snapshot, query, scope, *, current_read,
        stage, route, context, d02_issuer, d11_issuer, quote, grant, current_policy,
        current_effect, effect_snapshot, now_utc, valid_until_utc):
    """Reissue all six checks from actual staged rows under the installed fence."""
    from .contact_final_projection_v1 import require_contact_projection_read_v1
    require_contact_projection_read_v1(current_read, db, phases=('provisional_e_plus_1', 'post_cas_e_plus_1'))
    content, intent, schema = stage.content, stage.intent, stage.schema
    versions = read_contact_check_versions_locked_v1(db, snapshot, query, scope,
        current_read=current_read, content=content, segment_index=stage.segment_index,
        route=route, context=context, d02_issuer=d02_issuer, d11_issuer=d11_issuer,
        quote=quote, grant=grant, current_policy=current_policy, now_utc=now_utc)
    actual = {item.kind: item for item in versions.sets}
    for spec in intent.required_checks:
        item = actual[spec.check_kind]
        if spec.criteria_version != item.criteria_ref or spec.required_input_versions != item.versions:
            raise ValueError('contact provider input versions changed before final qualification')
    projection, role_read, boundary_read = _social_reads(
        db, snapshot, query, content, route, context, now_utc)
    role = context.provide_required_check(intent, role_read, valid_until=valid_until_utc)
    boundary = issue_prebatch_boundary_check_v1(intent, schema, boundary_read,
        audience_scope=content.audience_id, scene_ref=content.scene_id, now_utc=now_utc,
        valid_until_utc=valid_until_utc)
    expression = current_read.source_family(db, intent.source_refs,
        purpose='expression', audience=content.audience_id)
    structural = tuple(sorted({ref for atom in (*projection.role_bindings, *projection.boundary_rules)
        for ref in atom.value['source_refs']} - set(expression)))
    structural_versions, heads = read_current_structural_source_closure_v1(
        db, snapshot, content.namespace, structural)
    current_read.source_family(db, (route.source_ref,), purpose='context', audience=content.audience_id)
    for ref in (*expression, *structural, route.source_ref):
        barrier = read_source_correction_barrier(db, content.namespace, query,
            (ref,), dependent_ref=intent.action_id)
        if barrier.missing_sources:
            raise ValueError('contact current Source correction barrier is incomplete')
    source = provide_source_grant_check(intent, SourceGrantRead(snapshot,
        (content.audience_id,), 'expression', True, True), valid_until=valid_until_utc)
    d08 = read_contact_dispatch_check_scope_v1(db, snapshot, query, scope,
        current_effect, effect_snapshot, intent, schema, current_read=current_read,
        route_binding=route, audience=(content.audience_id,), purpose='expression',
        now_utc=now_utc, valid_until_utc=valid_until_utc)
    budget = inspect_current_d11_dispatch_budget(db, intent, d11_issuer=d11_issuer,
        d02_issuer=d02_issuer, now_utc=now_utc, natural_communication=False)
    _, _, policy, _, opportunity = _plan_policy(db, current_read, content, current_policy, scope, now_utc)
    from .contact_claim_adoption_v1 import read_current_own_contact_continuation_v1
    continuation = read_current_own_contact_continuation_v1(db, current_read,
        content=content, segment_index=stage.segment_index, current_policy=current_policy,
        scope=scope, now_utc=now_utc)
    contact = read_current_contact(db, content.namespace, snapshot, query, intent,
        policy.policy_id, opportunity.opportunity_id, now=now_utc,
        current_policy=current_policy, scope=scope, continuation=continuation)
    checks = (role, boundary.receipt, source, d08.receipt, budget.receipt, contact.receipt)
    if any(c is None or c.result != 'pass' or c.coverage != 'full'
            or c.valid_until <= now_utc for c in checks):
        raise ValueError('contact six current provider checks did not pass')
    positives = {v.key: v for v in (*versions.read_versions, *structural_versions)}
    predicates = (*heads, 'd03.role_binding:all_valid', 'd05.boundary_rule:all_valid',
        'd10.contact_policy.v1:all', 'd10.proactive_opportunity.v1:all',
        'd10.contact_claim.v1:all', 'd10.contact_claim.v2:all')
    return CurrentContactQualificationV1(checks, versions,
        tuple(sorted(positives.values(), key=lambda v: v.key.token)), predicates, d08,
        contact_route_semantic_digest_v1(route), current_policy.original.digest)
