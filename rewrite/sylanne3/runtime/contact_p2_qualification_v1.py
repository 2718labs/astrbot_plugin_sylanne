"""Fresh six-provider Contact qualification on actual claimed P2 rows.

A provider-input ActionIntent view refreshes only RequiredCheckSpec versions.
The stored action digest remains fixed; neither this view nor a public evidence
DTO can authorize Graph writes. Issuance is tied to the active private reader.
"""
from dataclasses import dataclass, replace
import json

from ..domains.d01.production_operations_v1 import plain_v1
from ..domains.d03.context import ContextProvider
from ..domains.d05.prebatch_boundary import issue_prebatch_boundary_check_v1
from ..domains.d06.source_grant import SourceGrantRead, provide_source_grant_check
from ..domains.d08.execution import ActionSchema, ActionSchemaRecord, GoalExecutionProvider
from ..domains.d08.contact_plan_v2 import decode_contact_plan_v2
from ..domains.d08.dispatch_check import D08_CRITERIA_REF_V1, D08_CRITERIA_VERSION_V1
from ..domains.d08.contact_dispatch_check_v1 import DispatchCheckScopeV2
from ..domains.d10 import ContactContinuation, ContactClaim, LifeDomain, decode_contact_policy, decode_proactive_opportunity
from ..domains.d10.contact_claim_v2 import decode_contact_claim_v2, contact_claim_key_v2, contact_window_id_v2
from ..graph_types import AtomKey, GraphVersion, GraphWrite, Owner, TypeSpec
from ..memory_types import access_key
from ..runtime_contracts import CheckReceipt, NamespaceId, QueryEpoch, VersionedRef, canonical_digest, canonical_serialize, schema_hash
from ..authority_service.contact_p2_contract_v1 import ContactP2PolicyCapsuleV1
from .budget import get_budget_lease
from .contact_final_action_v1 import ContactCheckVersionSetV1, CurrentContactCheckVersionsV1, contact_final_action_ids_v1, require_contact_segment_index_v1
from .contact_qualification_v3 import _social_reads
from .contact_route_binding_v1 import contact_route_semantic_digest_v1, read_current_contact_route_binding_v1
from .contact_p2_current_read_v1 import require_current_contact_p2_read_v1
from .dispatch_budget_check import _observed_versions, evaluate_dispatch_budget_authority_snapshot
from .dispatch_source_correction_barrier import read_source_correction_barrier
from .installed_dispatch_admission_issuer import inspect_current_d11_dispatch_budget
from .structural_source_closure_v1 import read_current_structural_source_closure_v1
from .contact_policy_bound_v3 import ContactPolicyQualificationBoundV3


@dataclass(frozen=True, slots=True)
class ContactP2QualificationV1:
    actual_action_digest: str
    actual_schema_digest: str
    provider_input_action_digest: str
    check_versions: CurrentContactCheckVersionsV1
    checks: tuple[CheckReceipt, ...]
    positive_reads: tuple[GraphVersion, ...]
    negative_predicates: tuple[str, ...]
    d08_scope: DispatchCheckScopeV2
    contact_policy_bound: ContactPolicyQualificationBoundV3
    policy_capsule_digest: str
    authority_snapshot_digest: str
    claimed_receipt_digest: str
    graph_epoch: int
    schema: str = 'd11.contact-p2-qualification.v1'

    def __post_init__(self):
        from .contact_final_action_v1 import CONTACT_REQUIRED_PROVIDERS_V1
        if (self.schema!='d11.contact-p2-qualification.v1' or len(self.checks)!=6
                or tuple((v.check_kind,v.issuer) for v in self.checks)!=CONTACT_REQUIRED_PROVIDERS_V1
                or self.check_versions.graph_epoch!=self.graph_epoch
                or self.d08_scope.receipt!=self.checks[3]
                or self.contact_policy_bound.bounded_receipt!=self.checks[5]
                or self.d08_scope.graph_query.revision!=self.graph_epoch
                or len({v.key for v in self.positive_reads})!=len(self.positive_reads)):
            raise ValueError('Contact P2 typed six-provider metadata closure differs')
        versions={v.kind:v for v in self.check_versions.sets}
        if len(versions)!=6 or any(v.result!='pass' or v.coverage!='full'
                or v.input_versions!=versions[v.check_kind].versions for v in self.checks):
            raise ValueError('Contact P2 metadata provider receipt/version commitments differ')

    @property
    def digest(self):
        return canonical_digest(self)


@dataclass(frozen=True, slots=True)
class _IssuedContactP2QualificationV1:
    read: object
    evidence: ContactP2QualificationV1


_ISSUED = {}


def _p2_plan_policy(db, read, content, capsule, scope, now):
    require_current_contact_p2_read_v1(read,db)
    atom=read.head(db,content.plan_version.key,required=True)
    plan=decode_contact_plan_v2(atom.value)
    if (atom.revision != content.plan_version.revision or canonical_digest(plain_v1(plan)) != content.plan_digest
            or capsule is not read.capsule or capsule.plan_ref != atom.key.token
            or capsule.policy_original.original_ref != plan.policy_original_ref
            or capsule.policy_original.digest != plan.policy_original_digest):
        raise ValueError('Contact P2 actual paid plan and Core policy capsule differ')
    policies=tuple(a for a in read.complete_inventory(db,'d10.contact_policy.v1')
        if a.valid and a.value['approval_ref']==plan.policy_original_ref)
    if len(policies)!=1:
        raise ValueError('Contact P2 current adopted policy is not unique')
    raw=policies[0].value;policy=decode_contact_policy(raw,scope.namespace)
    original=capsule.policy_original
    if (policy!=original.policy or raw['approval_authority_id']!=original.authority_id
            or raw['installation_id']!=original.installation_id
            or raw['owner_grant_revision']!=original.owner_authorization_revision
            or not policy.window_start<=now<policy.window_end):
        raise ValueError('Contact P2 Graph policy no longer matches current signed Core approval')
    opportunity=read.head(db,AtomKey.from_token(plan.opportunity_ref.ref),required=True)
    return plan,policies[0],policy,opportunity,decode_proactive_opportunity(opportunity.value,scope.namespace)


def _actual_action_and_resources_v1(db, read):
    content=read.batch.content;ns=read.scope.namespace
    ids=contact_final_action_ids_v1(content.contact_id,read.birth.request.segment_index);owner=Owner('activity',*ns.as_tuple,content.activity_id)
    specs={s.name:s.validator for s in GoalExecutionProvider().register_types()}
    atom=read.head(db,AtomKey(owner,'d08.action_intent.v1',ids['action']),required=True)
    actual=specs['d08.action_intent.v1'](atom.value)
    record_key=next(v.key for v in read.birth.original['receipt'].write_versions if v.key.type_name=='d08.action_schema.v1')
    schema_atom=read.head(db,record_key,required=True)
    record=specs['d08.action_schema.v1'](schema_atom.value)
    schema=ActionSchema(record.schema_id,record.action_kind,record.proactive,record.required_checks)
    if (record!=ActionSchemaRecord.bind(actual,schema)
            or canonical_digest(actual)!=read.birth.admission.admission.action_intent_digest
            or actual.identity.operation_id!=read.binding.operation_id or actual.identity.effect_id!=read.binding.origin.effect_id
            or schema_atom.revision!=1 or atom.revision!=1):
        raise ValueError('Contact P2 immutable actual action/schema differs from admission')
    d11=read.graph._GraphCoordinator__d11_issuer
    grant=d11.current_budget_grant(db,read.birth.original['payload']['parent_budget'])
    from .jobs import get_job
    job=get_job(db,AtomKey.from_token(read.birth.job_ref).name)
    quote_id,quote_version=job.operator_versions['resource_quote'].rsplit(':',1)
    quote=d11._d02._load_quote(db,quote_id,int(quote_version))
    if (quote.operation_id!=actual.identity.operation_id or quote.effect_id!=actual.identity.effect_id
            or quote.parent_budget_lease_ref!=grant.lease_id or quote.work_kind!='message'
            or quote.graph_job_ref!=read.birth.job_ref or quote.outbox_refs!=(read.birth.outbox_ref,)):
        raise ValueError('Contact P2 actual signed message quote/reservation origin differs')
    if actual.source_refs!=read.birth.qualification.expression_roots:
        raise ValueError('Contact P2 immutable action expression roots differ from actual birth qualification')
    from .contact_reviewed_content_v2 import read_contact_reviewed_content_original_v2
    paid=read_contact_reviewed_content_original_v2(db,namespace=ns,contact_id=content.contact_id,
        issuer=d11,resource_issuer=d11._d02)
    if paid!=content or paid.digest!=read.birth.original['payload']['provenance']['reviewed_content_digest']:
        raise ValueError('Contact P2 current batch differs from actual signed generation and independent review')
    assembly=read.graph._GraphCoordinator__d04_installed_joint_assembly
    if assembly is None or assembly.installation_policy.root_grant!=grant:
        raise ValueError('Contact P2 signed parent differs from its actual installed budget root')
    return actual,schema,quote,grant


def _read_current_contact_p2_versions_v1(db, snapshot, query, scope, *, current_read,
        content, segment_index, route, context, d02_issuer, d11_issuer, quote, grant,
        current_policy, now_utc):
    """Read raw inputs; E+1 predictions never constitute provider approval."""
    require_current_contact_p2_read_v1(current_read, db)
    require_contact_segment_index_v1(content, segment_index)
    current_read.check(db)
    ns = content.namespace
    if (not db.in_transaction or query != QueryEpoch(ns, 'all', snapshot.epochs[0].revision)
            or current_read.frame.snapshot != snapshot or scope.namespace != ns
            or query.revision != scope.graph_epoch.revision
            or scope.operation != 'dispatch'):
        raise ValueError('contact check versions lack their actual current dispatch scope')
    actual_route = read_current_contact_route_binding_v1(db, current_read,
        account_ref=route.account_version.key.token, target_entity_ref=route.target_entity_ref,
        audience=content.audience_id)
    if actual_route != route or contact_route_semantic_digest_v1(route) != content.route_semantic_digest:
        raise ValueError('contact route changed after paid review')
    plan, policy_atom, policy, opportunity_atom, opportunity = _p2_plan_policy(
        db, current_read, content, current_policy, scope, now_utc)
    projection, role, boundary = _social_reads(db, snapshot, query, content, route, context, now_utc, prepared_inventory=current_read.prepared_inventory)
    roots = current_read.birth.qualification.expression_roots
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
    epoch = query.revision
    ids = contact_final_action_ids_v1(content.contact_id, segment_index)
    owner = Owner('activity', *ns.as_tuple, content.activity_id)
    goal = current_read.head(db, AtomKey(owner, 'd08.goal.v1', ids['goal']))
    cancellation = current_read.head(db, AtomKey(owner, 'd08.action_cancellation.v1', ids['action']))
    if (not goal.valid or not cancellation.valid):
        raise ValueError('contact action must exist in the actual current dispatch snapshot')
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
    sets = (
        ContactCheckVersionSetV1('role_binding', criteria.ref, (criteria,
            VersionedRef('d03.role_binding', epoch), *sorted((VersionedRef(v.key.name, v.revision)
                for v in role.read_versions if v.key.name in role.matched_bindings), key=lambda v: v.ref))),
        ContactCheckVersionSetV1('boundary', criteria.ref, (criteria,
            VersionedRef('d05.boundary', epoch), *(VersionedRef(r.rule_id, r.scope_version) for r in boundary.rules))),
        ContactCheckVersionSetV1('source_grant', criteria.ref, tuple(source_versions)),
        ContactCheckVersionSetV1('commitment_conflict', D08_CRITERIA_REF_V1, (
            VersionedRef(D08_CRITERIA_REF_V1, D08_CRITERIA_VERSION_V1),
            VersionedRef(ids['goal'], goal.revision),
            VersionedRef('commitments-query:persona:' + ns.persona_id, epoch),
            VersionedRef('execution-epoch:' + ids['action'], scope.pinned_anchor.execution_seq),
            VersionedRef('cancellation-epoch:' + ids['action'], cancellation.revision))),
        ContactCheckVersionSetV1('dispatch_budget', budget[0].ref, budget),
        ContactCheckVersionSetV1('contact_policy', criteria.ref, contact_versions),
    )
    read_versions=tuple(GraphVersion(a.key,a.revision)for a in snapshot.atoms if a.valid)
    if current_read.prepared_inventory is not None:
        versions_by_key={version.key:version for version in read_versions}
        versions_by_key.update((version.key,version)for version in current_read.source_read_versions_v3(db))
        read_versions=tuple(versions_by_key[key]for key in sorted(versions_by_key,key=lambda key:key.token))
    return CurrentContactCheckVersionsV1(ns, epoch,
        read_versions, sets,
        quote.quote_id, quote.version, grant.grant_id, grant.version, reserve[0],
        current_policy.policy_original.original_ref,
        current_policy.policy_original.digest)



def _issue_own_claimed_d08_v1(db, read, actual_intent, actual_schema, intent, schema, route, expiry):
    from ..authority_service.v2_contract import canonical_digest as authority_digest
    from ..domains.d08.contact_dispatch_check_v1 import _current_atom, DispatchCheckScopeV2, D08NegativeQueryV2
    from ..domains.d08.execution import Goal, ActionCancellationState, CommitmentConflictSnapshot
    from ..memory_types import source_key
    require_current_contact_p2_read_v1(read,db)
    scope=read.scope;snapshot=read.frame.snapshot;query=read.frame.envelope.version_guard.query_epochs[0]
    authority_snapshot=read.authority_snapshot;anchor=scope.pinned_anchor
    namespace=scope.namespace;purpose=intent.purpose
    own=tuple(v for v in authority_snapshot.unresolved_effects if v.effect_id==intent.identity.effect_id)
    claimed=read.claimed;binding=read.binding
    if (len(own)!=1 or own[0].operation_id!=binding.operation_id or own[0].phase!='claimed'
            or own[0].mutation_id!=claimed.pending.mutation_id
            or own[0].execution_seq!=anchor.execution_seq or own[0].append_digest!=anchor.execution_digest
            or claimed.pending.expected_append_digest!=anchor.execution_digest
            or own[0].footprint!=binding.footprint
            or claimed.pending.binding!=binding or claimed.pending.permit.token!=scope.permit.token
            or claimed.updated_revision!=scope.permit.revision
            or any(v.effect_id!=intent.identity.effect_id for v in authority_snapshot.unresolved_effects)):
        raise ValueError('Contact P2 own claimed exclusion lacks exact original or another effect remains')
    if (read_current_contact_route_binding_v1(db,read,account_ref=route.account_version.key.token,
            target_entity_ref=intent.target_ref,audience=read.batch.content.audience_id)!=route
            or read.now_utc>=expiry or scope.operation!='dispatch' or purpose!='expression'):
        raise ValueError('Contact P2 current route/purpose/deadline differs')
    owner = Owner("activity", *namespace.as_tuple,
                  intent.identity.activity_id)
    goal_key = AtomKey(owner, "d08.goal.v1", intent.goal_ref)
    action_key = AtomKey(owner, "d08.action_intent.v1", intent.action_id)
    cancellation_key = AtomKey(owner, "d08.action_cancellation.v1", intent.action_id)
    d08_types = {item.name: item for item in GoalExecutionProvider().register_types()}
    action_atom = (_current_atom(db, snapshot, action_key) if read.prepared_inventory is None else read.head(db, action_key, required=True))
    current_action = d08_types["d08.action_intent.v1"].validator(action_atom.value)
    if action_atom.revision != 1 or current_action != actual_intent:
        raise ValueError("D08 current action differs from frozen intent")
    binding = ActionSchemaRecord.bind(actual_intent, actual_schema)
    schema_key = AtomKey(owner, "d08.action_schema.v1", binding.schema_ref)
    goal_atom = (_current_atom(db, snapshot, goal_key) if read.prepared_inventory is None else read.head(db, goal_key, required=True))
    schema_atom = (_current_atom(db, snapshot, schema_key) if read.prepared_inventory is None else read.head(db, schema_key, required=True))
    cancellation_atom = (_current_atom(db, snapshot, cancellation_key) if read.prepared_inventory is None else read.head(db, cancellation_key, required=True))
    if not intent.source_refs:
        raise ValueError("contact expression Source closure is empty")
    source_atoms = []
    for ref in intent.source_refs:
        source = AtomKey.from_token(ref)
        if source != source_key(*namespace.as_tuple, source.owner.subject or ""):
            raise ValueError("contact expression Source is not canonical")
        source_atoms.append((_current_atom(db, snapshot, source) if read.prepared_inventory is None else read.head(db, source, required=True)))
    goal = d08_types["d08.goal.v1"].validator(goal_atom.value)
    stored_schema = d08_types["d08.action_schema.v1"].validator(schema_atom.value)
    cancellation = d08_types["d08.action_cancellation.v1"].validator(
        cancellation_atom.value)
    if (type(goal) is not Goal or goal_atom.revision != 1
            or goal.goal_id != intent.goal_ref or goal.revision != 1
            or goal.state != "active"
            or goal.satisfaction_predicate != intent.success_predicate
            or not set(intent.source_refs).issubset(goal.reason_refs)
            or schema_atom.revision != 1 or stored_schema != binding
            or type(cancellation) is not ActionCancellationState
            or cancellation_atom.revision != 1
            or cancellation.action_id != intent.action_id
            or cancellation.action_revision != 1
            or cancellation.action_digest != canonical_digest(actual_intent)
            or cancellation.activity_id != intent.identity.activity_id
            or cancellation.attempt_id != intent.identity.attempt_id
            or cancellation.effect_id != intent.identity.effect_id
            or cancellation.operation_id != intent.identity.operation_id
            or cancellation.state != "active" or cancellation.cancel_epoch != 0
            or intent.commitment_refs):
        raise ValueError("D08 goal, schema or initial cancellation is not current")

    from .dispatch_current_commitments import read_current_d08_conflict_facts

    facts = read_current_d08_conflict_facts(db, namespace, snapshot, query, prepared_inventory=read.prepared_inventory)
    if (set(facts.missing_sources) != {
            "atomic_execution_effect_read", "current_action_cancellation_read"}
            or tuple(item for item in facts.action_intents
                     if item.action_id == intent.action_id) != (actual_intent,)):
        raise ValueError("D08 full current conflict inventory is unavailable")
    # Counterparty is the only structured commitment target in v1. A
    # commitment to another conversation cannot veto this private reply; its
    # row still participates in the complete negative-query scan below.
    applicable_commitments = tuple(
        item for item in facts.commitments
        if item.counterparty_ref == intent.target_ref)
    conflicting_commitments = tuple(
        item.commitment_id for item in applicable_commitments
        if item.fulfillment_state not in {"fulfilled", "withdrawn"})
    unfinished_actions = []
    for other in facts.action_intents:
        if other.action_id == intent.action_id:
            continue
        if other.identity.effect_id == intent.identity.effect_id:
            raise ValueError("D08 effect is shared by another action")
        if other.target_ref != intent.target_ref:
            continue
        from .contact_continuation_stage_v1 import is_actual_contact_prefix_action_v1
        if is_actual_contact_prefix_action_v1(db,read,intent,other):continue
        complete = tuple(outcome for outcome in facts.action_outcomes
                         if (outcome.action_id, outcome.effect_id,
                             outcome.attempt_id) == (
                             other.action_id, other.identity.effect_id,
                             other.identity.attempt_id)
                         and outcome.result_level == "completed_verified"
                         and not outcome.unknown_effects)
        if len(complete) != 1:
            unfinished_actions.append(other.action_id)
    if conflicting_commitments or unfinished_actions:
        raise ValueError("D08 current commitment or action conflict remains")

    checks = tuple(item for item in intent.required_checks
                   if item.check_kind == "commitment_conflict")
    if len(checks) != 1 or checks[0].provider_id != "d08.commitment_conflict":
        raise ValueError("D08 fixed commitment check is absent")
    spec = checks[0]
    expected = {
        D08_CRITERIA_REF_V1: D08_CRITERIA_VERSION_V1,
        intent.goal_ref: goal_atom.revision,
        f"commitments-query:persona:{namespace.persona_id}": query.revision,
        f"execution-epoch:{intent.action_id}": anchor.execution_seq,
        f"cancellation-epoch:{intent.action_id}": cancellation_atom.revision,
    }
    frozen = {item.ref: item.version for item in spec.required_input_versions}
    if (spec.criteria_version != D08_CRITERIA_REF_V1
            or spec.subject_ref != f"persona:{namespace.persona_id}"
            or spec.action_ref != intent.action_id or spec.purpose != purpose
            or len(frozen) != len(spec.required_input_versions)
            or frozen != expected):
        raise ValueError("D08 fixed criteria or current version set differs")
    current = CommitmentConflictSnapshot(
        spec.required_input_versions, "full",
        tuple(item.commitment_id for item in applicable_commitments), (), (),
        action_ref=intent.action_id, action_revision=intent.revision,
        intent_digest=canonical_digest(intent), schema_id=intent.schema_id,
        goal_ref=intent.goal_ref, target_ref=intent.target_ref,
        action_kind=intent.action_kind, purpose=intent.purpose,
        commitment_query_epoch_ref=f"commitments-query:persona:{namespace.persona_id}",
        commitment_query_epoch=query.revision,
        execution_epoch_ref=f"execution-epoch:{intent.action_id}",
        execution_epoch=anchor.execution_seq,
        cancellation_epoch_ref=f"cancellation-epoch:{intent.action_id}",
        cancellation_epoch=cancellation_atom.revision,
        current_read_confirmed=True,
    )
    receipt = GoalExecutionProvider().provide_required_check(
        intent, schema, current, valid_until=float(expiry))
    if receipt.result != "pass" or receipt.coverage != "full":
        raise ValueError("D08 current provider did not pass")
    positive = tuple(VersionedRef(atom.key.token, atom.revision) for atom in (
        *source_atoms, goal_atom, action_atom, schema_atom, cancellation_atom))
    commitments = tuple(VersionedRef(item.key.token, item.revision)
                        for item in facts.graph_versions
                        if item.key.type_name == "d08.commitment.v1")
    action_history = tuple(VersionedRef(item.key.token, item.revision)
                           for item in facts.graph_versions
                           if item.key.type_name in {
                               "d08.action_intent.v1", "d08.action_outcome.v1"})
    return DispatchCheckScopeV2(
        intent.action_id, query, anchor, authority_digest(authority_snapshot),
        positive,
        (D08NegativeQueryV2("d08.same_target_unfinished_commitments.v1", query,
                            commitments, ()),
         D08NegativeQueryV2("d08.same_target_unfinished_actions.v1", query,
                            action_history, ())),
        receipt,
    )



def _issue_own_quota_policy_v1(db, read, intent, deadline):
    content=read.batch.content
    plan,policy_atom,policy,opportunity_atom,opportunity=_p2_plan_policy(db,read,content,
        read.capsule,read.scope,read.now_utc)
    claims=[]
    for kind in ('d10.contact_claim.v1','d10.contact_claim.v2'):
        for atom in read.complete_inventory(db,kind):
            if not atom.valid:continue
            if kind=='d10.contact_claim.v2':
                claim=decode_contact_claim_v2(atom.value)
                if atom.key!=contact_claim_key_v2(read.scope.namespace,claim.contact_id):
                    raise ValueError('Contact P2 current quota claim key differs')
            else:
                validator=next(spec.validator for spec in LifeDomain.type_specs() if spec.name==kind)
                validator(atom.value)
                claim=ContactClaim(**{**atom.value,'segment_effects':tuple(atom.value['segment_effects']),
                    'observations':tuple(tuple(v) for v in atom.value['observations'])})
            claims.append(claim)
    own_atom=read.head(db,contact_claim_key_v2(read.scope.namespace,content.contact_id),required=True)
    own=decode_contact_claim_v2(own_atom.value)
    from .contact_final_action_v1 import contact_whole_grant_request_v1
    parent=contact_whole_grant_request_v1(content)
    original=read.capsule.policy_original
    index=read.birth.request.segment_index
    if index:
        from .contact_continuation_p2_v1 import require_current_continuation_p2_prefix_v1
        require_current_continuation_p2_prefix_v1(read,db)
    if ((index==0 and own_atom.revision!=1)or own.status in {'released','pending_confirmation'}
            or dict(own.observations)!={part.segment.effect_id:'accepted'for part in content.segments[:index]}
            or own.communication_action_id!=parent.communication_action_id
            or own.segment_effects!=tuple(v.segment.effect_id for v in content.segments)
            or own.subject_ref!=plan.target_entity_ref or (own.channel,own.category)!=(policy.channel,policy.category)
            or (own.policy_id,own.policy_version,own.window_id,own.window_start,own.window_end)!=
               (policy.policy_id,policy.version,contact_window_id_v2(policy),policy.window_start,policy.window_end)
            or (own.approval_ref,own.approval_digest)!=(original.original_ref,original.digest)):
        raise ValueError('Contact P2 own quota continuation is not its original unconsumed whole claim')
    continuation=ContactContinuation(own.contact_id,own.communication_action_id,intent.identity.effect_id)
    scoped=tuple(v for v in claims if (v.subject_ref,v.channel,v.category)==
        (opportunity.subject_ref,opportunity.channel,opportunity.category))
    local=LifeDomain.contact_policy_check(policy,opportunity,scoped,now=read.now_utc,continuation=continuation)
    spec=next(v for v in intent.required_checks if v.check_kind=='contact_policy')
    native=CheckReceipt(spec.check_kind,spec.subject_ref,spec.action_ref,spec.purpose,
        spec.required_input_versions,'full',local.result,local.valid_until,spec.provider_id)
    if local.result!='pass' or local.reasons or read.now_utc>=min(local.valid_until,deadline):
        raise ValueError('Contact P2 complete current quota rule did not pass')
    return ContactPolicyQualificationBoundV3(native,local,GraphVersion(policy_atom.key,policy_atom.revision),
        GraphVersion(opportunity_atom.key,opportunity_atom.revision),continuation,deadline,
        replace(native,valid_until=min(local.valid_until,deadline)))


def _recompute_current_contact_p2_qualification_v1(db, read):
    require_current_contact_p2_read_v1(read,db)
    actual,schema,quote,grant=_actual_action_and_resources_v1(db,read)
    content=read.batch.content;snapshot=read.frame.snapshot;query=read.frame.envelope.version_guard.query_epochs[0]
    context=ContextProvider()
    route=read_current_contact_route_binding_v1(db,read,account_ref=read.birth.qualification.route.account_version.key.token,
        target_entity_ref=actual.target_ref,audience=content.audience_id)
    versions=_read_current_contact_p2_versions_v1(db,snapshot,query,read.scope,current_read=read,
        content=content,segment_index=read.birth.request.segment_index,route=route,context=context,d02_issuer=read.graph._GraphCoordinator__d11_issuer._d02,
        d11_issuer=read.graph._GraphCoordinator__d11_issuer,quote=quote,grant=grant,
        current_policy=read.capsule,now_utc=read.now_utc)
    sets={v.kind:v for v in versions.sets}
    specs=tuple(replace(spec,required_input_versions=sets[spec.check_kind].versions) for spec in actual.required_checks)
    if any(spec.criteria_version!=sets[spec.check_kind].criteria_ref for spec in actual.required_checks):
        raise ValueError('Contact P2 actual immutable action criterion changed')
    provider_input=replace(actual,required_checks=specs)
    provider_schema=replace(schema,required_checks=specs)
    # This explicitly named read-only view is consumed by pure providers only.
    if replace(provider_input,required_checks=actual.required_checks)!=actual:
        raise ValueError('Contact P2 provider view altered actual action fields')
    expiry=min(read.frame.envelope.deadline_utc,content.valid_until,quote.valid_until_utc,grant.valid_until_utc)
    projection,role_read,boundary_read=_social_reads(db,snapshot,query,content,route,context,read.now_utc,prepared_inventory=read.prepared_inventory)
    role=context.provide_required_check(provider_input,role_read,valid_until=expiry)
    boundary=issue_prebatch_boundary_check_v1(provider_input,provider_schema,boundary_read,
        audience_scope=content.audience_id,scene_ref=content.scene_id,now_utc=read.now_utc,valid_until_utc=expiry)
    expression=read.source_family(db,actual.source_refs,purpose='expression',audience=content.audience_id)
    structural=tuple(sorted({ref for atom in (*projection.role_bindings,*projection.boundary_rules)
        for ref in atom.value['source_refs']}-set(expression)))
    structural_versions,heads=read_current_structural_source_closure_v1(db,snapshot,read.scope.namespace,structural,prepared_inventory=read.prepared_inventory)
    read.source_family(db,(route.source_ref,),purpose='context',audience=content.audience_id)
    for ref in (*expression,*structural,route.source_ref):
        barrier=read_source_correction_barrier(db,read.scope.namespace,query,(ref,),dependent_ref=actual.action_id,prepared_inventory=read.prepared_inventory)
        if barrier.missing_sources:raise ValueError('Contact P2 current Source correction closure is incomplete')
    if read.prepared_inventory is None:
        source=provide_source_grant_check(provider_input,SourceGrantRead(snapshot,(content.audience_id,),
            'expression',True,True),valid_until=expiry)
    else:
        from ..domains.d06.source_grant import provide_prepared_source_grant_check_v3
        source=provide_prepared_source_grant_check_v3(provider_input,prepared_inventory=read.prepared_inventory,
            db=db,audience=(content.audience_id,),purpose='expression',valid_until=expiry)
    d08=_issue_own_claimed_d08_v1(db,read,actual,schema,provider_input,provider_schema,route,expiry)
    d11=read.graph._GraphCoordinator__d11_issuer
    budget=inspect_current_d11_dispatch_budget(db,provider_input,d11_issuer=d11,d02_issuer=d11._d02,
        now_utc=read.now_utc,natural_communication=False)
    if evaluate_dispatch_budget_authority_snapshot(read.context,read.owner_witness,read.authority_snapshot,
            namespace=read.scope.namespace,proposed_footprint=read.binding.footprint):
        raise ValueError('Contact P2 independent Authority budget/effect inventory conflicts')
    policy=_issue_own_quota_policy_v1(db,read,provider_input,expiry)
    checks=(role,boundary.receipt,source,d08.receipt,budget.receipt,policy.bounded_receipt)
    if any(v is None or v.result!='pass' or v.coverage!='full' or v.valid_until<=read.now_utc for v in checks):
        raise ValueError('Contact P2 fresh six-provider qualification did not pass')
    positives={v.key:v for v in (*versions.read_versions,*structural_versions)}
    predicates=(*heads,'d03.role_binding:all_valid','d05.boundary_rule:all_valid',
        'd10.contact_policy.v1:all','d10.proactive_opportunity.v1:all','d10.contact_claim.v1:all','d10.contact_claim.v2:all')
    from ..authority_service.v2_contract import canonical_digest as authority_digest
    return ContactP2QualificationV1(canonical_digest(actual),canonical_digest(ActionSchemaRecord.bind(actual,schema)),
        canonical_digest(provider_input),versions,checks,tuple(sorted(positives.values(),key=lambda v:v.key.token)),
        predicates,d08,policy,read.capsule.digest,authority_digest(read.authority_snapshot),
        authority_digest(read.claimed),read.scope.graph_epoch.revision)


def issue_current_contact_p2_qualification_v1(db, read):
    issued=_IssuedContactP2QualificationV1(read,_recompute_current_contact_p2_qualification_v1(db,read))
    _ISSUED[id(issued)]=issued
    return issued


def verify_current_contact_p2_sql_v1(db, read, issued):
    if (type(issued) is not _IssuedContactP2QualificationV1 or _ISSUED.get(id(issued)) is not issued
            or issued.read is not read):
        raise ValueError('Contact P2 current qualification was not issued by this actual SQL reader')
    actual=_recompute_current_contact_p2_qualification_v1(db,read)
    if actual!=issued.evidence:
        raise ValueError('Contact P2 independent SQL verifier observed a changed provider closure')
    return actual


def retire_current_contact_p2_qualification_v1(issued):
    _ISSUED.pop(id(issued),None)


CONTACT_P2_PROOF_TYPE_V1 = 'd11.contact_p2_qualification.v1'


@dataclass(frozen=True, slots=True)
class ContactP2GraphProofV1:
    namespace: NamespaceId
    installation_id: str
    operation_id: str
    effect_id: str
    activity_id: str
    admission_ref: str
    graph_incarnation: str
    context_digest: str
    policy_capsule: ContactP2PolicyCapsuleV1
    qualification: ContactP2QualificationV1
    schema: str = CONTACT_P2_PROOF_TYPE_V1

    def __post_init__(self):
        c,q=self.policy_capsule,self.qualification
        if (self.schema!=CONTACT_P2_PROOF_TYPE_V1 or type(self.namespace) is not NamespaceId
                or type(c) is not ContactP2PolicyCapsuleV1 or type(q) is not ContactP2QualificationV1
                or (c.namespace,c.installation_id,c.admission_ref,c.graph_incarnation,c.context_digest)!=
                   (self.namespace,self.installation_id,self.admission_ref,self.graph_incarnation,self.context_digest)
                or c.digest!=q.policy_capsule_digest
                or c.claimed_receipt_digest!=q.claimed_receipt_digest
                or c.authority_snapshot_digest!=q.authority_snapshot_digest
                or q.check_versions.namespace!=self.namespace
                or any(type(v) is not str or not v for v in (self.operation_id,self.effect_id,self.activity_id))):
            raise ValueError('Contact P2 immutable Graph proof scope/capsule differs')

    @property
    def digest(self):
        return canonical_digest(plain_v1(self))


def contact_p2_graph_proof_from_wire_v1(raw):
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    value=decode_typed_production_value_v1(raw,ContactP2GraphProofV1)
    if canonical_serialize(plain_v1(value))!=canonical_serialize(raw):
        raise ValueError('Contact P2 graph proof canonical wire differs')
    return value


def contact_p2_graph_proof_key_v1(namespace,effect_id,activity_id):
    return AtomKey(Owner('activity',*namespace.as_tuple,activity_id),CONTACT_P2_PROOF_TYPE_V1,effect_id)


def contact_p2_graph_proof_write_v1(value):
    if type(value) is not ContactP2GraphProofV1:
        raise ValueError('Contact P2 exact immutable companion required')
    return GraphWrite(contact_p2_graph_proof_key_v1(value.namespace,value.effect_id,value.activity_id),plain_v1(value),
        tuple(v.key for v in value.qualification.positive_reads))


def contact_p2_graph_proof_type_spec_v1():
    return TypeSpec(CONTACT_P2_PROOF_TYPE_V1,('activity',),'state',contact_p2_graph_proof_from_wire_v1,
        immutable=True,writer_domain='d11',schema_hash=schema_hash({'type':CONTACT_P2_PROOF_TYPE_V1,
            'version':1,'fields':sorted(ContactP2GraphProofV1.__dataclass_fields__),
            'qualification_fields':sorted(ContactP2QualificationV1.__dataclass_fields__),
            'capsule_fields':sorted(ContactP2PolicyCapsuleV1.__dataclass_fields__),
            'purpose':'actual Contact claimed P2 current provider metadata; no body or send grant'}))
