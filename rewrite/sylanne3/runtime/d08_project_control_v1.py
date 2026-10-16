"""Owner project controls over the current D08 Plan; no execution authority is issued."""
from dataclasses import dataclass, fields, replace
import json

from ..domains.d01.production_operations_v1 import plain_v1, stage_result_v1
from ..domains.d08.execution import GoalExecutionProvider
from ..domains.d08.personal_plan_v1 import PLAN_TYPE, PersonalPlanV1, decode_personal_plan_type_v1
from ..graph_types import AtomKey, GraphAtom, GraphWrite, owner_grant_key
from ..runtime_contracts import NamespaceId, VersionedRef, canonical_digest
from .d01_production_operations_v1 import CurrentDomainReadV1, MissingProductionOriginalV1, production_read_plan_v1
from .domain_production_originals_v1 import read_adopted_domain_operation_v1

OPERATIONS = frozenset({'pause_project_v1', 'resume_project_v1'})
_READERS_KEY = object()
_TERMINAL_PLANS = frozenset({'satisfied', 'abandoned', 'superseded'})


@dataclass(frozen=True, slots=True)
class PauseProjectRequestV1:
    project_ref: str
    plan_ref: str
    expected_plan_revision: int

    def __post_init__(self):
        if (AtomKey.from_token(self.project_ref).type_name != 'd10.life_project.v1'
                or AtomKey.from_token(self.plan_ref).type_name != PLAN_TYPE
                or type(self.expected_plan_revision) is not int or self.expected_plan_revision < 1):
            raise ValueError('project control requires its exact current project/Plan CAS selectors')


@dataclass(frozen=True, slots=True)
class ResumeProjectRequestV1(PauseProjectRequestV1):
    pause_original_ref: str

    def __post_init__(self):
        PauseProjectRequestV1.__post_init__(self)
        if type(self.pause_original_ref) is not str or not self.pause_original_ref or len(self.pause_original_ref) > 128:
            raise ValueError('resume requires its actual immutable pause operation original')


@dataclass(frozen=True, slots=True)
class ProjectExecutionSummaryV1:
    inflight: int
    unknown: int
    settlement_pending: int

    def __post_init__(self):
        if any(type(value) is not int or value < 0 for value in (self.inflight, self.unknown, self.settlement_pending)):
            raise ValueError('execution summary counts actual pending originals')


@dataclass(frozen=True, slots=True)
class ProjectControlOriginalV1:
    project_ref: str
    plan_ref: str
    control: str
    before_plan_revision: int
    after_plan_revision: int
    before_plan_state: str
    after_plan_state: str
    before_plan: PersonalPlanV1
    after_plan: PersonalPlanV1
    pause_origin: str | None
    noop: bool
    execution_summary: ProjectExecutionSummaryV1
    control_original_ref: str
    schema: str = 'd08.project-control-original.v1'

    def __post_init__(self):
        PauseProjectRequestV1(self.project_ref, self.plan_ref, self.before_plan_revision)
        if (self.schema != 'd08.project-control-original.v1' or self.control not in {'pause', 'resume'}
                or type(self.before_plan) is not PersonalPlanV1 or type(self.after_plan) is not PersonalPlanV1
                or type(self.execution_summary) is not ProjectExecutionSummaryV1 or type(self.noop) is not bool
                or self.before_plan_state != self.before_plan.state or self.after_plan_state != self.after_plan.state
                or self.after_plan_revision != self.before_plan_revision + (not self.noop)
                or not self.control_original_ref or len(self.control_original_ref) > 128):
            raise ValueError('project control original differs from actual Plan CAS')
        if self.noop:
            if self.after_plan != self.before_plan:
                raise ValueError('no-op control cannot change a Plan member')
        else:
            expected = replace(self.before_plan, state=self.after_plan_state,
                revision=self.before_plan_revision + 1,
                parent_plan_revision_ref=VersionedRef(self.plan_ref, self.before_plan_revision))
            if self.after_plan != expected or self.before_plan.state in _TERMINAL_PLANS:
                raise ValueError('project control changes only state/revision/actual parent Plan head')
        if self.control == 'pause' and self.after_plan_state != 'paused':
            raise ValueError('pause never completes, abandons or replaces a project')
        if self.control == 'resume' and (not self.pause_origin or self.after_plan_state not in {'active', 'waiting', 'paused'}):
            raise ValueError('resume must retain its actual pause origin and unresolved waits')


def decode_project_control_original_v1(raw):
    if type(raw) is not dict or set(raw) != {f.name for f in fields(ProjectControlOriginalV1)}:
        raise ValueError('project control original has another closed schema')
    values = dict(raw)
    for name in ('before_plan', 'after_plan'):
        values[name] = decode_personal_plan_type_v1(PLAN_TYPE, values[name])
    values['execution_summary'] = ProjectExecutionSummaryV1(**values['execution_summary'])
    return ProjectControlOriginalV1(**values)


class InstalledProjectControlReadersV1:
    def __init__(self, key, *, issuer, owner_guard, owner_binding, activation_generation):
        if key is not _READERS_KEY:
            raise TypeError('project controls use the actual Owner fence factory')
        self.issuer, self.owner_guard, self.owner_binding = issuer, owner_guard, owner_binding
        self.activation_generation = activation_generation


def install_project_control_readers_v1(graph, *, scope, owner_guard, owner_binding):
    from ..graph_coordinator import GraphCoordinator, OwnerLeaseBindingV1
    from ..authority_service.v2_owner_contract import OwnerAuthorizationGuardV1
    if (type(graph) is not GraphCoordinator or type(owner_guard) is not OwnerAuthorizationGuardV1
            or type(owner_binding) is not OwnerLeaseBindingV1
            or not any(binding is owner_binding for binding in graph._GraphCoordinator__owner_leases.values())
            or owner_guard.namespace != scope.namespace or owner_binding.namespace != scope.namespace
            or owner_binding.authorization_head != owner_guard.authorization_head
            or owner_binding.authorization_revision != owner_guard.authorization_revision
            or owner_guard.pending_revoke_operation_id is not None
            or 'workbench.control' not in owner_binding.capabilities):
        raise ValueError('project control requires this invocation\'s actual current Owner lease/fence')
    return InstalledProjectControlReadersV1(_READERS_KEY,
        issuer=graph._GraphCoordinator__d11_issuer, owner_guard=owner_guard,
        owner_binding=owner_binding, activation_generation=scope.generation)


def _head(db, namespace, ref):
    from ..authority_service.artifact_model_source_read_v3 import artifact_model_graph_point_v3
    key = AtomKey.from_token(ref)
    if NamespaceId.from_key(key) != namespace:
        raise ValueError('project control crossed namespace')
    row = artifact_model_graph_point_v3(db,('revision', 'value', 'valid'),token=ref)
    if row is None or row[2] != 1:
        raise MissingProductionOriginalV1('current_valid_project_control_head:' + key.type_name)
    return GraphAtom(key, row[0], json.loads(row[1]), True)


def project_control_basis_v1(db, *, namespace, project_ref):
    from .d10_project_checkpoint_v1 import _artifact_project_original_v1
    original = _artifact_project_original_v1(db, namespace=namespace, project_ref=project_ref)
    provenance = original['payload']['provenance']
    if original['operation_kind'] == 'create_artifact_task_project_v1':
        basis = provenance['task_project_basis']
        plan_ref, goal_ref = basis['plan_head']['key'], basis['goal_head']['key']
    elif original['operation_kind'] == 'revise_existing_artifact_v1':
        plan_ref, goal_ref = provenance['basis']['plan_ref'], provenance['basis']['goal_ref']
    else:
        plan_ref, goal_ref = provenance['artifact_plan_ref'], provenance['artifact_goal_ref']
    project, plan_atom, goal = (_head(db, namespace, ref) for ref in (project_ref, plan_ref, goal_ref))
    plan = decode_personal_plan_type_v1(PLAN_TYPE, plan_atom.value)
    if plan.goal_ref != goal_ref or plan.goal_revision != goal.value['revision']:
        raise MissingProductionOriginalV1('actual_current_project_Plan_Goal_binding')
    return original, project, plan_atom, plan, goal


def _project_root_ref_v1(original):
    payload = original['payload']
    if original['operation_kind'] == 'create_artifact_task_project_v1':
        return payload['provenance']['task_project_basis']['task']['root_registration_ref']
    if original['operation_kind'] == 'revise_existing_artifact_v1':
        return payload['provenance']['content_adoption']['selector']['root_registration_ref']
    return payload['request']['root_registration_ref']


def _pause_original(db, *, namespace, plan_atom):
    row = db.execute('SELECT event_id,value,valid FROM graph_history WHERE token=? AND revision=?',
        (plan_atom.key.token, plan_atom.revision)).fetchone()
    from ..runtime_contracts import canonical_serialize
    if row is None or row[1:] != (canonical_serialize(plan_atom.value), 1):
        raise MissingProductionOriginalV1('actual_project_control_Plan_producing_history')
    original = read_adopted_domain_operation_v1(db, namespace, row[0])
    if original is None or original['operation_kind'] != 'pause_project_v1':
        return None
    control = decode_project_control_original_v1(original['payload']['provenance']['project_control'])
    if (control.noop or control.after_plan_revision != plan_atom.revision
            or plain_v1(control.after_plan) != plan_atom.value
            or control.control_original_ref != original['receipt'].operation_id):
        raise ValueError('pause original changed its actual committed Plan head')
    return original, control


def _project_scope_records_v1(db, *, namespace, project_ref, plan_atom, plan):
    from .d03_life_project_context_v1 import life_project_context_keys_v1
    from .d11_types import job_graph_write
    from .jobs import get_job
    # A continued task may select the same Plan from another genuine activity.
    selected = db.execute("SELECT operation_id FROM graph_domain_production_originals_v1 "
        "WHERE bot=? AND persona=? AND domain='d08' AND operation_kind IN ('select_personal_step','select_personal_step_v2') "
        "AND json_extract(original_payload_json,'$.request.plan_ref')=? ORDER BY operation_id LIMIT 129",
        (*namespace.as_tuple, plan_atom.key.token)).fetchall()
    if len(selected) > 128:
        raise MissingProductionOriginalV1('bounded_actual_project_selections')
    activities, originals = {plan_atom.key.owner.subject}, []
    for (operation,) in selected:
        original = read_adopted_domain_operation_v1(db, namespace, operation)
        activities.add(original['payload']['identity']['activity_id'])
        originals.append(operation)
    jobs = []
    for activity in sorted(activities):
        rows = db.execute('SELECT job_id FROM runtime_jobs WHERE bot_id=? AND persona_id=? AND activity_id=? ORDER BY job_id LIMIT 129',
            (*namespace.as_tuple, activity)).fetchall()
        jobs.extend(get_job(db, job) for (job,) in rows)
        if len(jobs) > 128:
            raise MissingProductionOriginalV1('bounded_actual_project_jobs')
    # Project-bound Action targets are actual D03 entity identities, not a text search.
    target = life_project_context_keys_v1(namespace, project_ref)[0].name
    actions = db.execute("SELECT token,revision,value FROM graph_atoms WHERE bot=? AND persona=? AND type_name='d08.action_intent.v1' AND valid=1 "
        "AND json_extract(value,'$.goal_ref')=? AND json_extract(value,'$.target_ref')=? ORDER BY token LIMIT 129",
        (*namespace.as_tuple, AtomKey.from_token(plan.goal_ref).name, target)).fetchall()
    if len(actions) > 128:
        raise MissingProductionOriginalV1('bounded_actual_project_actions')
    outcomes = []
    for _, _, encoded in actions:
        action = json.loads(encoded)
        rows = db.execute("SELECT token,revision,value FROM graph_atoms WHERE bot=? AND persona=? AND type_name='d08.action_outcome.v1' AND valid=1 "
            "AND json_extract(value,'$.action_id')=? ORDER BY token LIMIT 129", (*namespace.as_tuple, action['action_id'])).fetchall()
        outcomes.extend(rows)
        if len(outcomes) > 128:
            raise MissingProductionOriginalV1('bounded_actual_project_outcomes')
    keys = tuple(job_graph_write(job).key for job in jobs) + tuple(AtomKey.from_token(row[0]) for row in (*actions, *outcomes))
    return jobs, actions, outcomes, keys, tuple(originals)


def _execution_summary(db, *, namespace, project_ref, plan_atom, plan, issuer):
    from .d11_life_preparation_v1 import _read
    jobs, _, outcomes, _, _ = _project_scope_records_v1(db, namespace=namespace,
        project_ref=project_ref, plan_atom=plan_atom, plan=plan)
    inflight = sum(job.phase in {'running', 'draining'} for job in jobs)
    unknown = {job.effect_id or 'job:' + job.job_id for job in jobs if job.phase == 'pending_confirmation'}
    reservations = set()
    for job in jobs:
        if job.continuation.get('schema') == 'd11.life-job.v1':
            saved = _read(db, issuer=issuer, namespace=namespace, kind='prepared', ref=job.continuation['prepared_original_ref'])
            if saved is None:
                raise MissingProductionOriginalV1('actual_project_prepared_reservation')
            binding = saved[0]['binding']
            if binding['job_id'] != job.job_id or binding['activity_id'] != job.activity_id:
                raise ValueError('project worker changed its signed actual reservation')
            reservations.add((binding['parent_budget_lease_ref'], binding['reservation_operation_id']))
        else:
            reservations.add((job.budget_ref, job.operation_id))
    pending = 0
    for lease, operation in reservations:
        reservation = db.execute('SELECT state FROM runtime_budget_reservations WHERE lease_id=? AND operation_id=?',
            (lease, operation)).fetchone()
        pending += reservation is not None and reservation[0] != 'settled'
    for _, _, encoded in outcomes:
        unknown.update(json.loads(encoded)['unknown_effects'])
    return ProjectExecutionSummaryV1(inflight, len(unknown), pending)


def _resume_state(db, *, namespace, plan_atom, plan, goal, issuer, root_ref, now_utc, summary):
    from .jobs import get_job
    from .budget import get_budget_lease, require_budget_family_admissible, BudgetUnavailable
    from .d11_offline_originals_v1 import _utc
    pause = _pause_original(db, namespace=namespace, plan_atom=plan_atom)
    if pause is None or goal.value['state'] != 'active':
        return None, ('actual_pause_original_and_active_Goal_required',)
    rows = db.execute("SELECT job_id FROM runtime_jobs WHERE bot_id=? AND persona_id=? AND activity_id=? AND work_kind='d11.foreground_cycle.v1' LIMIT 2",
        (*namespace.as_tuple, plan_atom.key.owner.subject)).fetchall()
    if len(rows) != 1:
        return None, ('actual_original_project_worker_required',)
    from .d11_life_preparation_v1 import _read
    from .d11_artifact_draft_contract_v1 import DraftRootCapabilityV1, draft_from_wire_v1
    saved_root = _read(db, issuer=issuer, namespace=namespace, kind='draft_root_capability', ref=root_ref)
    if saved_root is None:
        return None, ('actual_original_project_Root_required',)
    root = draft_from_wire_v1(saved_root[0], DraftRootCapabilityV1)
    if root.registration_ref != root_ref:
        raise ValueError('project resume changed its actual signed Root registration')
    if now_utc >= _utc(root.valid_until_utc).timestamp():
        return None, ('original_project_Root_deadline_expired',)
    job = get_job(db, rows[0][0])
    if now_utc >= _utc(job.deadline_utc).timestamp():
        return None, ('original_project_deadline_expired',)
    lease = get_budget_lease(db, job.budget_ref)
    while True:
        grant = issuer.current_budget_grant(db, lease.lease_id)
        if lease.state != 'active' or now_utc >= grant.valid_until_utc:
            return None, ('original_project_budget_or_grant_unavailable',)
        if lease.parent_id is None:
            break
        lease = get_budget_lease(db, lease.parent_id)
    try:
        require_budget_family_admissible(db, job.budget_ref)
        budget_wait = False
    except BudgetUnavailable:
        budget_wait = True
    before = pause[1].before_plan
    unresolved = summary.inflight or summary.unknown or summary.settlement_pending or budget_wait
    if before.state == 'waiting' or unresolved:
        if not plan.waiting_conditions:
            return None, ('actual_pending_effect_wait_condition_required',)
        return 'waiting', ('actual_original_waits_or_unsettled_effects',)
    return 'active', ()


def read_plan_project_control_v1(db, *, namespace, operation_kind, request):
    if operation_kind not in OPERATIONS or type(request) is not (PauseProjectRequestV1 if operation_kind == 'pause_project_v1' else ResumeProjectRequestV1):
        raise TypeError('exact registered project control request required')
    original, project, plan_atom, plan, goal = project_control_basis_v1(db, namespace=namespace, project_ref=request.project_ref)
    if request.plan_ref != plan_atom.key.token:
        raise ValueError('project control selected another Plan')
    _, _, _, scope_keys, selected_originals = _project_scope_records_v1(db, namespace=namespace,
        project_ref=request.project_ref, plan_atom=plan_atom, plan=plan)
    keys = (owner_grant_key(*namespace.as_tuple), project.key, plan_atom.key, goal.key, *scope_keys,
        *(AtomKey.from_token(ref.ref) for ref in plan.fact_versions))
    originals = (original['receipt'].operation_id, *selected_originals)
    if operation_kind == 'resume_project_v1':
        originals += (request.pause_original_ref, _project_root_ref_v1(original))
    # The ordinary namespace epoch catches newly appearing matching members.
    return production_read_plan_v1((), keys, plan.source_refs, originals)


def _stage(db, *, frame, request, installed_readers, control):
    if type(installed_readers) is not InstalledProjectControlReadersV1:
        raise TypeError('project controls need actual installed Owner readers')
    readers, read = installed_readers, CurrentDomainReadV1(frame)
    read.check(db)
    owner, authority = readers.owner_binding, frame.envelope.authority
    if (authority.actor != owner.actor or 'workbench.control' not in owner.capabilities
            or readers.owner_guard.authorization_head.removeprefix('sha256:') != frame.owner_guard.owner_head_digest
            or frame.owner_guard.grant_ref != owner_grant_key(*authority.namespace.as_tuple).token
            or (frame.owner_guard.grant_revision, frame.owner_guard.grant_digest) != (owner.grant_revision, owner.grant_digest)
            or authority.activation_generation != readers.activation_generation
            or frame.activation_generation != readers.activation_generation
            or not {'context', 'consolidation'} <= owner.purposes or not set(authority.audience) <= owner.audiences):
        raise ValueError('project control changed its current signed Owner purpose/audience')
    original, project, atom, plan, goal = project_control_basis_v1(db, namespace=authority.namespace, project_ref=request.project_ref)
    for head in (project, atom, goal):
        read.head(db, head.key, required=True)
    if request.plan_ref != atom.key.token or request.expected_plan_revision != atom.revision:
        from ..contracts import StaleRead
        raise StaleRead('project Plan CAS changed; read and select its current context')
    if plan.state in _TERMINAL_PLANS:
        raise ValueError('project control cannot reopen a terminal Plan')
    for purpose in ('context', 'consolidation'):
        read.source_family(db, plan.source_refs, purpose=purpose)
    _, _, _, scope_keys, selected_originals = _project_scope_records_v1(db, namespace=authority.namespace,
        project_ref=request.project_ref, plan_atom=atom, plan=plan)
    for key in scope_keys:
        read.head(db, key, required=True)
    for operation in selected_originals:
        read.original(operation)
    read.original(original['receipt'].operation_id)
    summary = _execution_summary(db, namespace=authority.namespace, project_ref=request.project_ref,
        plan_atom=atom, plan=plan, issuer=readers.issuer)
    pause = _pause_original(db, namespace=authority.namespace, plan_atom=atom) if plan.state == 'paused' else None
    if control == 'pause':
        state, reasons = 'paused', ()
        pause_origin = None if pause is None else pause[1].control_original_ref
    else:
        if pause is None or request.pause_original_ref != pause[1].control_original_ref:
            raise ValueError('resume requires this Plan head\'s actual pause original')
        read.original(request.pause_original_ref, kind='d08.current-pause_project_v1')
        read.original(_project_root_ref_v1(original), kind='d11.life_draft_root_capability')
        state, reasons = _resume_state(db, namespace=authority.namespace, plan_atom=atom, plan=plan, goal=goal,
            issuer=readers.issuer, root_ref=_project_root_ref_v1(original), now_utc=frame.now_utc, summary=summary)
        pause_origin = request.pause_original_ref
        state = 'paused' if state is None else state
    noop = state == plan.state
    after = plan if noop else replace(plan, state=state, revision=atom.revision + 1,
        parent_plan_revision_ref=VersionedRef(atom.key.token, atom.revision))
    value = ProjectControlOriginalV1(request.project_ref, request.plan_ref, control, atom.revision,
        atom.revision + (not noop), plan.state, after.state, plan, after, pause_origin, noop, summary,
        frame.envelope.identity.operation_id)
    provider = GoalExecutionProvider()
    stage = stage_result_v1(frame, 'd08', control + '_project_v1', request,
        writes=() if noop else (GraphWrite(atom.key, plain_v1(after)),),
        provenance={'project_control': value}, coverage='partial' if reasons else 'complete', missing=reasons,
        receiver_events=() if noop else (('d10', 'personal_plan_revision_available'),),
        proposal_schema='d08.proposal.v1', proposal_hash=provider.descriptor.request_schema_hash)
    return verify_project_control_stage_v1(stage)


def stage_pause_project_v1(db, *, frame, request, installed_readers):
    if type(request) is not PauseProjectRequestV1:
        raise TypeError('exact pause selectors required')
    return _stage(db, frame=frame, request=request, installed_readers=installed_readers, control='pause')


def stage_resume_project_v1(db, *, frame, request, installed_readers):
    if type(request) is not ResumeProjectRequestV1:
        raise TypeError('exact resume selectors required')
    return _stage(db, frame=frame, request=request, installed_readers=installed_readers, control='resume')


def verify_project_control_stage_v1(stage):
    if stage.domain != 'd08' or stage.operation_kind not in OPERATIONS:
        raise ValueError('unregistered project control stage')
    provider = GoalExecutionProvider()
    for proposal in stage.proposals:
        provider.validate(proposal)
        if len(proposal.typed_writes) != 1 or proposal.typed_writes[0].key.type_name != PLAN_TYPE:
            raise ValueError('project controls write only their actual D08 Plan')
    return stage


def require_current_project_plan_for_new_work_v1(db, *, namespace, plan_ref, expected_plan_revision=None):
    """Use only before new work; historical effect/cost reconciliation is independent."""
    atom = _head(db, namespace, plan_ref)
    plan = decode_personal_plan_type_v1(PLAN_TYPE, atom.value)
    goal = _head(db, namespace, plan.goal_ref)
    if (plan.state != 'active' or goal.value['state'] != 'active'
            or plan.goal_revision != goal.value['revision']
            or expected_plan_revision is not None and atom.revision != expected_plan_revision):
        raise MissingProductionOriginalV1('current_active_project_Plan_for_new_work')
    return atom, plan


def project_control_context_v1(db, *, namespace, project_ref, owner_binding, issuer, now_utc, graph_revision):
    """Called only inside Graph's current Owner read fence; no context is a permit."""
    from ..memory_types import SourceRecord
    from ..authority_service.current_foreground_activity_v1 import _source_family_current_sql_v1
    original, project, atom, plan, goal = project_control_basis_v1(db, namespace=namespace, project_ref=project_ref)
    audiences = tuple(sorted({audience for ref in plan.source_refs
        for audience in SourceRecord.from_dict(_head(db, namespace, ref).value).audiences}))
    if (owner_binding.namespace != namespace or 'workbench.control' not in owner_binding.capabilities
            or not {'context', 'consolidation'} <= owner_binding.purposes or not set(audiences) <= owner_binding.audiences):
        raise PermissionError('current Owner cannot control this project Source scope')
    for purpose in ('context', 'consolidation'):
        _source_family_current_sql_v1(db, namespace=namespace, roots=plan.source_refs, purpose=purpose, audiences=audiences)
    summary = _execution_summary(db, namespace=namespace, project_ref=project_ref, plan_atom=atom, plan=plan, issuer=issuer)
    pause = _pause_original(db, namespace=namespace, plan_atom=atom) if plan.state == 'paused' else None
    controls, resume_state, reasons = [], None, ()
    if plan.state not in _TERMINAL_PLANS:
        if plan.state != 'paused':
            controls.append('pause_project_v1')
        elif pause is not None:
            resume_state, reasons = _resume_state(db, namespace=namespace, plan_atom=atom, plan=plan, goal=goal,
                issuer=issuer, root_ref=_project_root_ref_v1(original), now_utc=now_utc, summary=summary)
            if resume_state is not None:
                controls.append('resume_project_v1')
    context = {'schema': 'd12.project-control-context.v1', 'namespace': plain_v1(namespace),
        'project_ref': project_ref, 'plan_ref': atom.key.token, 'plan_revision': atom.revision,
        'goal_ref': goal.key.token, 'goal_state': goal.value['state'], 'plan_state': plan.state,
        'pause_original_ref': None if pause is None else pause[1].control_original_ref,
        'permitted_controls': controls, 'execution_summary': plain_v1(summary),
        'resume_preview': {'state': resume_state, 'reasons': list(reasons)}, 'graph_revision': graph_revision}
    context['context_digest'] = canonical_digest(context)
    return context, audiences


def require_prepared_project_control_for_new_work_v1(db, *, prepared):
    """A new tool claim must match its actual preparation's frozen Plan head."""
    from .d11_artifact_draft_contract_v1 import RegisteredDraftFilePlanV3
    if type(prepared.plan) is not RegisteredDraftFilePlanV3:
        return
    _, _, atom, _, _ = project_control_basis_v1(db, namespace=prepared.binding.namespace,
        project_ref=prepared.plan.project.ref)
    rows = tuple(row for row in prepared.read_rows if row.ref == atom.key.token)
    if len(rows) != 1:
        raise MissingProductionOriginalV1('actual_prepared_project_Plan_read_commitment')
    require_current_project_plan_for_new_work_v1(db, namespace=prepared.binding.namespace,
        plan_ref=atom.key.token, expected_plan_revision=rows[0].revision)
