"""Current Self qualification for an explicit Owner management task.

This is independent of C02, foreground replies and model CallPlans. Its audit
DTO is not a capability; the paired Host must retain the issued handle and
recheck its exact command, Graph snapshot and write fence at W01.
"""
from contextlib import closing
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
import json
import sqlite3

from .contract import AuthorityUnavailable
from .v2_contract import FencePermitV2
from .v2_self_identity_contract import SelfIdentityCurrentRequestV1, AuthorityCurrentSelfIdentityV1
from .v2_self_identity_service import AuthorityV2SelfIdentityService
from .linux_clock_v1 import LinuxKernelClockProviderV1
from .current_foreground_activity_v1 import _source_family_current_sql_v1
from ..domains.d01.production_operations_v1 import plain_v1
from ..domains.d03.self_identity_qualification import self_identity_mapping_from_current
from ..domains.d03.self_perspective import self_mapping_key
from ..graph_types import AtomKey, GraphVersion, owner_grant_key
from ..runtime_contracts import NamespaceId, QueryEpoch, canonical_digest, canonical_serialize
from ..runtime.domain_production_contracts_v1 import ProductionOwnerGuardV1
from ..runtime.domain_production_erasure_v1 import decode_typed_production_value_v1
from ..runtime.owner_source_note_task_contract_v1 import (
    CREATE_OPERATION, CHECKPOINT_OPERATION, RESPONSIBILITY_KIND, TASK_WORK_KIND, NOTE_WORK_KIND,
    OwnerSourceNoteTaskAuthorizationV2, OwnerSourceNoteTaskContinuationV2,
    OwnerSourceNoteTaskResponsibilityV2, CreateOwnerSourceNoteTaskRequestV1,
    owner_source_note_task_ids_v1,
)
from ..runtime.owner_source_note_task_v1 import read_owner_source_note_task_authorization_v2
from ..runtime.d11_life_preparation_v1 import _read
from ..runtime.d11_types import runtime_job_key, job_graph_write
from ..runtime.jobs import get_job
from ..runtime.budget import get_budget_lease, require_budget_family_admissible
from ..runtime.issuers import D11BudgetJobIssuer

ACQUIRE_OPERATION = 'acquire_owner_source_note_task_v1'
_VALUES_CHILD_DOMAINS = {'input:freeze_values':'d01','evaluate_values':'d01'}
VALUES_PARENT_OPERATION = 'input:freeze_owner_source_note_values_parent_v1'
_DOMAINS = {
    CREATE_OPERATION:'d11', ACQUIRE_OPERATION:'d11', CHECKPOINT_OPERATION:'d11',
    'prepare_owner_source_note_need_v1':'d07', VALUES_PARENT_OPERATION:'d08',
    'prepare_personal_candidates_v1':'d08', 'select_personal_step_v2':'d08',
    'prepare_selected_source_note_action_v2':'d08', 'prepare_source_note_body':'d02',
    'register_owner_source_note_life_plan_v1':'d10', 'prepare_life':'d10',
    'register_owner_source_note_life_outcome_v1':'d10', 'advance_life':'d10', 'settle_personal_goal':'d08',
}
_STEPS = {
    'prepare_owner_source_note_need_v1':('qualify',), VALUES_PARENT_OPERATION:('values',),
    'prepare_personal_candidates_v1':('select',), 'select_personal_step_v2':('select',),
    'prepare_selected_source_note_action_v2':('prepare_action',),
    'prepare_source_note_body':('prepare_body',), 'register_owner_source_note_life_plan_v1':('register_life_plan',),
    'prepare_life':('prepare_life',), 'register_owner_source_note_life_outcome_v1':('observe_life','adopt_outcome'),
    'advance_life':('adopt_outcome',), 'settle_personal_goal':('adopt_outcome',),
    'input:freeze_values':('values',), 'evaluate_values':('values',),
}


def owner_task_allowed_write_domains_v1(operation_kind):
    if operation_kind == 'advance_life':
        return ('d02','d06','d10','d11')
    domain = {**_DOMAINS,**_VALUES_CHILD_DOMAINS}[operation_kind]
    return (domain,) if domain == 'd11' else (domain,'d11')


def owner_task_typed_command_digest_v1(operation, command):
    from ..runtime.domain_production_registry_v1 import installed_operation_v1
    if (installed_operation_v1(operation.operation_kind) != operation
            or type(command) is not operation.request_type
            or {**_DOMAINS,**_VALUES_CHILD_DOMAINS}.get(operation.operation_kind) != operation.domain):
        raise TypeError('Owner task command must be one exact registered operation and typed request')
    return canonical_digest(('sylanne.owner-task-typed-command.v1',operation.domain,operation.operation_kind,command))


@dataclass(frozen=True, slots=True)
class OwnerTaskActivityRequestV1:
    namespace: NamespaceId
    installation_id: str
    authorization_original_ref: str
    authorization_original_digest: str
    operation_id: str
    operation_kind: str
    request_digest: str
    task_job_ref: str
    expected_job_revision: int
    expected_cancel_generation: int
    schema: str = 'd11.owner-task-activity-request.v1'

    def __post_init__(self):
        child = type(self) is OwnerTaskActivityValuesChildRequestV1
        allowed = _VALUES_CHILD_DOMAINS if child else _DOMAINS if type(self) is OwnerTaskActivityRequestV1 else {}
        schema = 'd11.owner-task-values-child-request.v1' if child else 'd11.owner-task-activity-request.v1'
        if (self.schema != schema or type(self.namespace) is not NamespaceId
                or self.operation_kind not in allowed
                or not self.authorization_original_ref.startswith('owner-source-note-authorization:')
                or AtomKey.from_token(self.task_job_ref).type_name != 'runtime.job'
                or NamespaceId.from_key(AtomKey.from_token(self.task_job_ref)) != self.namespace
                or any(type(v) is not int or v < 0 for v in (self.expected_job_revision,self.expected_cancel_generation))
                or any(type(v) is not str or not v for v in (self.installation_id,self.operation_id))):
            raise ValueError('Owner task request requires exact named task and current job selectors')
        for value in (self.authorization_original_digest,self.request_digest):
            if type(value) is not str or len(value) != 64 or any(c not in '0123456789abcdef' for c in value):
                raise ValueError('Owner task request lost its exact original or command digest')
        if len(canonical_serialize(self).encode('utf-8')) > 65536:
            raise ValueError('Owner task selector exceeds its fixed metadata bound')


@dataclass(frozen=True, slots=True, kw_only=True)
class OwnerTaskActivityValuesChildRequestV1(OwnerTaskActivityRequestV1):
    values_parent_original_ref: str
    values_parent_original_digest: str
    child_slot: str
    schema: str = 'd11.owner-task-values-child-request.v1'

    def __post_init__(self):
        OwnerTaskActivityRequestV1.__post_init__(self)
        if (not self.values_parent_original_ref.startswith('owner-note-values-parent:')
                or self.child_slot not in {'freeze','evaluate'}
                or self.operation_kind != {'freeze':'input:freeze_values','evaluate':'evaluate_values'}[self.child_slot]
                or type(self.values_parent_original_digest) is not str or len(self.values_parent_original_digest)!=64
                or any(c not in '0123456789abcdef' for c in self.values_parent_original_digest)):
            raise ValueError('Owner Values child selects one exact signed parent and closed slot')


@dataclass(frozen=True, slots=True)
class OwnerTaskCompletedSettlementV1:
    authorization_original_ref: str
    authorization_original_digest: str
    settlement_operation_id: str
    goal_head: GraphVersion
    goal_digest: str
    plan_head: GraphVersion
    plan_digest: str
    progress_ref: str
    progress_operation_id: str
    native_adoption_operation_id: str
    artifact_ref: str
    terminal_original_ref: str
    actual_cpu_ms: int
    budget_receipt_digest: str
    read_versions: tuple[GraphVersion, ...]
    schema: str = 'd11.owner-task-completed-settlement.v1'


def read_completed_owner_source_note_task_v1(db, *, namespace, authorization, issuer):
    """Read only this task's exact Goal/Plan settlement and paid native result.

    This proves historical completion plus current Life eligibility. It grants
    no new task authority and does not weaken any other authorized head.
    """
    from ..runtime.domain_production_originals_v1 import read_adopted_domain_operation_v1
    from ..domains.d08.execution import _decode_goal, _decode_intent
    from ..domains.d08.personal_plan_v1 import PersonalPlanV1
    from ..runtime.d08_personal_plan_v1 import SettleCurrentPersonalGoalRequestV1
    from ..runtime_contracts import VersionedRef
    from ..runtime.d11_life_terminal_v1 import read_adopted_life_original_v1, read_current_life_job_result_v1
    from ..runtime.d11_life_contract_v1 import D11LifeTerminalV1, life_from_wire_v1, POSTCONDITION_ID
    from ..runtime.d11_life_preparation_v1 import read_prepared_life_v1
    from ..runtime.d11_life_source_note_v1 import verify_durable_life_artifact_v1
    from ..runtime.d11_life_fact_provenance_v1 import require_current_life_fact_eligibility_v1, life_current_fact_reads_v1
    from ..runtime.d10_life_progress_provenance_v1 import validate_life_progress_provenance_history_v1
    from ..domains.d10.production_operations_v1 import LifeProgressHeadV1
    from ..runtime.budget import _settlement_binding
    if (not db.in_transaction or type(authorization) is not OwnerSourceNoteTaskAuthorizationV2
            or authorization.cause.namespace != namespace or type(issuer) is not D11BudgetJobIssuer):
        raise TypeError('completed Owner task read requires its actual signed authorization and transaction')
    heads = {name:(version,digest) for name,version,digest in authorization.heads}
    versions = {}
    def current(key):
        if type(key) is str: key = AtomKey.from_token(key)
        if NamespaceId.from_key(key) != namespace:
            raise AuthorityUnavailable('completed Owner task member crossed namespace')
        row = db.execute('SELECT revision,value,valid FROM graph_atoms WHERE token=?',(key.token,)).fetchone()
        if row is None or row[2] != 1:
            raise AuthorityUnavailable('completed Owner task actual member is absent or invalidated')
        versions[key] = row[0]
        return row, json.loads(row[1])
    goal_version, goal_digest = heads['goal']; plan_version, plan_digest = heads['plan']
    goal_row, goal_raw = current(goal_version.key); plan_row, plan_raw = current(plan_version.key)
    if ((goal_row[0],canonical_digest(goal_raw),plan_row[0],canonical_digest(plan_raw)) ==
            (goal_version.revision,goal_digest,plan_version.revision,plan_digest)):
        return None
    if (goal_version.revision,plan_version.revision,goal_row[0],plan_row[0]) != (1,1,2,2):
        raise AuthorityUnavailable('completed Owner task permits only its exact first settlement')
    historical = []
    for version,digest in (heads['goal'],heads['plan']):
        old = db.execute('SELECT value,valid FROM graph_history WHERE token=? AND revision=?',
            (version.key.token,version.revision)).fetchone()
        if old is None or old[1] != 1 or canonical_digest(json.loads(old[0])) != digest:
            raise AuthorityUnavailable('completed Owner task lost its authorized original Goal/Plan')
        historical.append(json.loads(old[0]))
    latest = tuple(db.execute('SELECT event_id,value,valid FROM graph_history WHERE token=? AND revision=2',
        (version.key.token,)).fetchone() for version in (goal_version,plan_version))
    if (any(row is None for row in latest) or latest[0][0] != latest[1][0]
            or latest[0][1:] != goal_row[1:] or latest[1][1:] != plan_row[1:]):
        raise AuthorityUnavailable('completed Owner task Goal/Plan were not one actual settlement')
    original = read_adopted_domain_operation_v1(db,namespace,latest[0][0])
    if (original is None or (original['domain'],original['operation_kind']) != ('d08','settle_personal_goal')
            or set(original['receipt'].write_versions) != {GraphVersion(goal_version.key,2),GraphVersion(plan_version.key,2)}
            or not {goal_version,plan_version} <= set(original['read_versions'])):
        raise AuthorityUnavailable('completed Owner task lacks its named two-head W01 settlement')
    command = decode_typed_production_value_v1(original['payload']['request'],SettleCurrentPersonalGoalRequestV1)
    if (command.goal_ref,command.plan_ref,command.expected_goal_revision,command.expected_plan_revision) != (
            goal_version.key.token,plan_version.key.token,1,1):
        raise AuthorityUnavailable('completed Owner task settlement selected another authorized Goal/Plan')
    old_goal = _decode_goal(historical[0])
    old_plan = decode_typed_production_value_v1(historical[1],PersonalPlanV1)
    expected_goal = replace(old_goal,revision=2,state='satisfied',progress_refs=tuple(dict.fromkeys((*old_goal.progress_refs,command.progress_ref))))
    expected_plan = replace(old_plan,revision=2,goal_revision=2,state='satisfied',parent_plan_revision_ref=VersionedRef(command.plan_ref,1))
    if goal_raw != plain_v1(expected_goal) or plan_raw != plain_v1(expected_plan):
        raise AuthorityUnavailable('completed Owner task changed more than its lawful Goal/Plan settlement')
    progress_row, progress_raw = current(command.progress_ref)
    progress = decode_typed_production_value_v1(progress_raw,LifeProgressHeadV1)
    auth, cause = authorization, authorization.cause
    ids = owner_source_note_task_ids_v1(namespace,cause.owner_operation_id)
    if (progress_row[0] != 1 or progress.project_ref != auth.request.project_ref
            or progress.recipe_ref != auth.request.recipe_ref or progress.step != 'source_note'
            or progress.reality != 'real_execution' or progress.activity_id != ids['activity_id']):
        raise AuthorityUnavailable('completed Owner task progress belongs to another activity or recipe')
    adopted = read_adopted_life_original_v1(db,namespace=namespace,result_ref=progress.artifact_ref,issuer=issuer)
    if adopted is None:
        raise AuthorityUnavailable('completed Owner task lacks its actual signed native adoption')
    terminal = life_from_wire_v1(adopted['terminal'],D11LifeTerminalV1)
    prepared = read_prepared_life_v1(db,binding=terminal.binding,issuer=issuer)
    binding = terminal.binding
    if (prepared is None or type(terminal) is not D11LifeTerminalV1 or terminal.status != 'completed'
            or binding.activity_id != ids['activity_id'] or binding.parent_budget_lease_ref != cause.parent_budget_lease_ref
            or (progress.effect_id,progress.artifact_ref,progress.terminal_ref) != (binding.effect_id,binding.artifact_ref,terminal.original_ref)
            or prepared.plan.input_source.ref != auth.request.body_source_ref
            or prepared.plan.input_source.digest != heads['body_source'][1]
            or (prepared.plan.project.ref,prepared.plan.recipe.ref) != (auth.request.project_ref,auth.request.recipe_ref)):
        raise AuthorityUnavailable('completed Owner task changed its actual native execution/input/root')
    action_row, action_raw = current(prepared.plan.action_intent.ref)
    action = _decode_intent(action_raw)
    predicate = old_goal.satisfaction_predicate
    if (action_row[0] != prepared.plan.action_intent.revision
            or canonical_digest(action_raw) != prepared.plan.action_intent.digest
            or action.goal_ref != old_goal.goal_id or action.success_predicate != predicate
            or (predicate.kind,predicate.observation_provider) != ('artifact_verified',POSTCONDITION_ID)
            or dict(predicate.parameters) != {'artifact_ref':binding.artifact_ref,
                'input_digest':prepared.plan.input_source.digest,'build_digest':binding.postcondition_build_digest}):
        raise AuthorityUnavailable('completed Owner task native postcondition differs from its authorized Goal')
    for key in require_current_life_fact_eligibility_v1(db,prepared=prepared,terminal=terminal,adopted=adopted):
        current(key)
    for frozen in life_current_fact_reads_v1(prepared):
        key = AtomKey.from_token(frozen.ref)
        row = db.execute('SELECT revision FROM graph_atoms WHERE token=?',(key.token,)).fetchone()
        versions[key] = 0 if row is None else row[0]
    progress_birth = db.execute('SELECT event_id FROM graph_history WHERE token=? AND revision=1',(command.progress_ref,)).fetchone()
    progress_original = None if progress_birth is None else read_adopted_domain_operation_v1(db,namespace,progress_birth[0])
    if progress_original is None:
        raise AuthorityUnavailable('completed Owner task lacks its actual progress W01')
    writes = validate_life_progress_provenance_history_v1(db,prepared=prepared,terminal=terminal,
        progress=progress,production=progress_original)
    for write in writes:
        row, value = current(write.key)
        if row[0] != 1 or value != write.value:
            raise AuthorityUnavailable('completed Owner task progress/proof/current eligibility changed')
    native_receipt = json.loads(adopted['graph_receipt_json'])
    if not native_receipt['commit_seq'] < progress_original['receipt'].commit_seq < original['receipt'].commit_seq:
        raise AuthorityUnavailable('completed Owner task actual native/progress/Goal settlement order differs')
    verify_durable_life_artifact_v1(db,prepared,digest=terminal.payload.artifact_digest,length=terminal.payload.artifact_length)
    life_job, _ = read_current_life_job_result_v1(db,job_id=binding.job_id,adopted=adopted)
    current(job_graph_write(life_job).key)
    actual = {'thread_cpu_ms':terminal.actual_cpu_ms}
    settlement = db.execute("SELECT digest,lease_id,receipt_json,resolution_binding_json FROM runtime_budget_operations "
        "WHERE bot_id=? AND persona_id=? AND operation_id=? AND phase='settle'",
        (*namespace.as_tuple,binding.reservation_operation_id)).fetchall()
    reservation = db.execute('SELECT digest,state,actual_json FROM runtime_budget_reservations WHERE lease_id=? AND operation_id=?',
        (binding.parent_budget_lease_ref,binding.reservation_operation_id)).fetchone()
    if (len(settlement) != 1 or settlement[0][:2] != (binding.reservation_digest,binding.parent_budget_lease_ref)
            or settlement[0][3] != _settlement_binding(actual,True)
            or reservation is None or reservation[:2] != (binding.reservation_digest,'settled')
            or json.loads(reservation[2]) != actual):
        raise AuthorityUnavailable('completed Owner task lacks its exact once settled native CPU receipt')
    return OwnerTaskCompletedSettlementV1(auth.original_ref,auth.digest,original['receipt'].operation_id,
        GraphVersion(goal_version.key,2),canonical_digest(goal_raw),GraphVersion(plan_version.key,2),canonical_digest(plan_raw),
        command.progress_ref,progress_original['receipt'].operation_id,native_receipt['operation_id'],binding.artifact_ref,
        terminal.original_ref,terminal.actual_cpu_ms,canonical_digest(json.loads(settlement[0][2])),
        tuple(GraphVersion(key,revision) for key,revision in sorted(versions.items(),key=lambda row:row[0].token)))


@dataclass(frozen=True, slots=True)
class OwnerTaskActivityEvidenceV1:
    request: OwnerTaskActivityRequestV1 | OwnerTaskActivityValuesChildRequestV1
    current_self: AuthorityCurrentSelfIdentityV1
    owner_guard: ProductionOwnerGuardV1
    authorization: OwnerSourceNoteTaskAuthorizationV2
    read_versions: tuple[GraphVersion, ...]
    query_epoch: QueryEpoch
    allowed_write_domains: tuple[str, ...]
    valid_until_utc: str
    access_epoch: int
    delete_epoch: int
    observed_at_utc: float
    current_job_digest: str | None
    responsibility_ref: str | None
    responsibility_digest: str | None
    completed_settlement: OwnerTaskCompletedSettlementV1 | None = None
    schema: str = 'd11.owner-task-activity-evidence.v1'

    def __post_init__(self):
        if (self.schema != 'd11.owner-task-activity-evidence.v1' or type(self.request) not in {OwnerTaskActivityRequestV1,OwnerTaskActivityValuesChildRequestV1}
                or type(self.current_self) is not AuthorityCurrentSelfIdentityV1
                or type(self.owner_guard) is not ProductionOwnerGuardV1
                or type(self.authorization) is not OwnerSourceNoteTaskAuthorizationV2
                or self.authorization.original_ref != self.request.authorization_original_ref
                or self.authorization.digest != self.request.authorization_original_digest
                or type(self.query_epoch) is not QueryEpoch or type(self.read_versions) is not tuple
                or len(self.read_versions) > 128 or any(type(v) is not GraphVersion for v in self.read_versions)
                or self.allowed_write_domains != owner_task_allowed_write_domains_v1(self.request.operation_kind)
                or (self.responsibility_ref is None) != (self.responsibility_digest is None)
                or self.completed_settlement is not None and (type(self.completed_settlement) is not OwnerTaskCompletedSettlementV1
                    or self.request.operation_kind != CHECKPOINT_OPERATION)):
            raise ValueError('Owner task evidence must retain the actual independently read task and Self')


def owner_task_fence_operation_id_v1(request):
    if type(request) not in {OwnerTaskActivityRequestV1,OwnerTaskActivityValuesChildRequestV1}:
        raise TypeError('actual Owner task request required')
    return 'owner-task-domain-' + canonical_digest(request)[:48]


class InstalledCurrentOwnerSourceNoteTaskV1:
    def __init__(self, *, self_identity_service, budget_issuer, clock_provider, installed_bundle):
        from ..host.authority_profile import AdminInstallationBundle
        if (type(self_identity_service) is not AuthorityV2SelfIdentityService
                or type(budget_issuer) is not D11BudgetJobIssuer
                or type(clock_provider) is not LinuxKernelClockProviderV1
                or type(installed_bundle) is not AdminInstallationBundle
                or self_identity_service._source_location is None or self_identity_service._owner_storage is None
                or installed_bundle.installation_policy.namespace != self_identity_service._namespace_id
                or installed_bundle.installation_policy.installation_id != self_identity_service._installation_id
                or installed_bundle.installation_policy.manifest_digest != self_identity_service._manifest_digest):
            raise TypeError('Owner task requires the actual shared Self/C09/Owner/clock/Root composition')
        self.self_identity = self_identity_service
        self.issuer, self.clock, self.installed_bundle = budget_issuer, clock_provider, installed_bundle

    def current(self, *, credential, subject, permit, request):
        service = self.self_identity
        if (type(request) not in {OwnerTaskActivityRequestV1,OwnerTaskActivityValuesChildRequestV1} or type(permit) is not FencePermitV2
                or request.namespace != service._namespace_id or request.installation_id != service._installation_id
                or permit.operation != 'write' or subject != service._read_subject
                or permit.operation_id != owner_task_fence_operation_id_v1(request)):
            raise AuthorityUnavailable('Owner task requires its actual named Host write fence')
        from ..runtime.domain_production_registry_v1 import installed_operation_v1
        operation = installed_operation_v1(request.operation_kind)
        if operation.domain != {**_DOMAINS,**_VALUES_CHILD_DOMAINS}[request.operation_kind]:
            raise AuthorityUnavailable('Owner task operation no longer has its registered domain')
        service._fences.validate_fence(credential=credential,subject=subject,permit=permit)
        identity_request = SelfIdentityCurrentRequestV1(permit.authority_id,service._fences.namespace,
            request.namespace,service._installation_id,service._manifest_digest,request.operation_id,permit)
        current_self = service.current(credential=credential,subject=subject,request=identity_request)
        if current_self is None:
            raise AuthorityUnavailable('Owner task independently registered Self is absent')
        location = service._source_location.observe_business_for_fence_v1(credential=credential,subject=subject,permit=permit)
        current_owner, observed = service._owner_storage.get_current_background_owner_authority_for_fence_v1(
            credential=credential,subject=subject,permit=permit)
        if observed != permit or current_owner.guard.authorization_head != current_self.owner_authorization_head:
            raise AuthorityUnavailable('Owner task upstream Owner changed')
        reading = self.clock()
        now = reading.utc_seconds + reading.utc_error_seconds
        path = Path(location.graph_db_path)
        with closing(sqlite3.connect(path.as_uri()+'?mode=ro',uri=True)) as db:
            db.execute('PRAGMA query_only=ON'); db.execute('BEGIN')
            service._source_location.require_graph_snapshot_v1(db,location,graph_db_path=path)
            ns = request.namespace
            if db.execute('SELECT revision FROM graph_epochs WHERE bot=? AND persona=?',ns.as_tuple).fetchone() != (current_self.graph_epoch,):
                raise AuthorityUnavailable('Owner task Graph changed after its independent Self read')
            versions = {}
            def atom(ref, required=True):
                key = AtomKey.from_token(ref) if type(ref) is str else ref
                if NamespaceId.from_key(key) != ns:
                    raise AuthorityUnavailable('Owner task read crossed namespace')
                row = db.execute('SELECT revision,value,valid FROM graph_atoms WHERE bot=? AND persona=? AND token=?',
                    (*ns.as_tuple,key.token)).fetchone()
                versions[key] = 0 if row is None else row[0]
                if required and (row is None or row[2] != 1):
                    raise AuthorityUnavailable('Owner task current required head is absent')
                return None if row is None else json.loads(row[1])
            owner_key = owner_grant_key(*ns.as_tuple)
            owner = atom(owner_key)
            guard = ProductionOwnerGuardV1(owner_key.token,versions[owner_key],canonical_digest(owner),
                current_owner.guard.authorization_head.removeprefix('sha256:'))
            mapping_key = self_mapping_key(ns)
            mapping = atom(mapping_key)
            if mapping != plain_v1(self_identity_mapping_from_current(current_self)):
                raise AuthorityUnavailable('Owner task Graph mapping differs from current Authority Self')
            saved = read_owner_source_note_task_authorization_v2(db,namespace=ns,
                original_ref=request.authorization_original_ref,issuer=self.issuer)
            if saved is None:
                raise AuthorityUnavailable('actual signed Owner task authorization is absent')
            auth, original = saved
            cause = auth.cause
            if (auth.digest != request.authorization_original_digest or cause.owner_guard != guard
                    or cause.installation_id != service._installation_id or cause.manifest_digest != service._manifest_digest
                    or 'workbench.create' not in owner['capabilities'] or 'consolidation' not in owner['purposes']
                    or not set(cause.audiences) <= set(owner['audiences'])):
                raise AuthorityUnavailable('Owner task original identity or current upstream scope changed')
            completion = (read_completed_owner_source_note_task_v1(db,namespace=ns,authorization=auth,issuer=self.issuer)
                if request.operation_kind == CHECKPOINT_OPERATION else None)
            if completion is not None:
                versions.update((version.key,version.revision) for version in completion.read_versions)
            values = {}
            for name, head, digest in auth.heads:
                values[name] = atom(head.key)
                expected_head, expected_digest = head, digest
                if completion is not None and name in {'goal','plan'}:
                    expected_head = completion.goal_head if name == 'goal' else completion.plan_head
                    expected_digest = completion.goal_digest if name == 'goal' else completion.plan_digest
                if versions[head.key] != expected_head.revision or canonical_digest(values[name]) != expected_digest:
                    raise AuthorityUnavailable('Owner task authorized current head changed: '+name)
            role = values['role']
            if (role['status'] != 'active' or now < role['effective_from']
                    or role['effective_until'] is not None and now >= role['effective_until']
                    or values['target']['status'] != 'active'
                    or values['goal']['state'] != ('satisfied' if completion is not None else 'active')
                    or values['plan']['state'] != ('satisfied' if completion is not None else 'active')):
                raise AuthorityUnavailable('Owner task current role/target/Goal/Plan is not active')
            for purpose in ('context','consolidation'):
                for version in _source_family_current_sql_v1(db,namespace=ns,roots=auth.source_refs,
                        purpose=purpose,audiences=cause.audiences):
                    versions[version.key] = version.revision
            parent = get_budget_lease(db,cause.parent_budget_lease_ref)
            require_budget_family_admissible(db,parent.lease_id)
            grant = self.issuer.current_budget_grant(db,parent.lease_id)
            policy = self.installed_bundle.installation_policy
            if (parent.lease_id != policy.root_lease.lease_id or grant != policy.root_grant
                    or (grant.grant_id,grant.version,canonical_digest(grant)) !=
                        (cause.parent_grant_id,cause.parent_grant_version,cause.parent_grant_digest)
                    or not {TASK_WORK_KIND,NOTE_WORK_KIND} <= set(grant.allowed_work_kinds)):
                raise AuthorityUnavailable('Owner task original Root or signed grant changed')
            self._require_body_policy(db,auth,now)
            deadline = min(cause.original_deadline_utc,grant.valid_until_utc)
            if not now < deadline:
                raise AuthorityUnavailable('Owner task original absolute deadline expired')
            ids = owner_source_note_task_ids_v1(ns,cause.owner_operation_id)
            job_key = runtime_job_key(*ns.as_tuple,ids['activity_id'],ids['job_id'])
            if request.task_job_ref != job_key.token or request.expected_cancel_generation != 0:
                raise AuthorityUnavailable('Owner task selected another job or a cancelled generation')
            job_value = atom(job_key,required=request.expected_job_revision>0)
            if versions[job_key] != request.expected_job_revision:
                raise AuthorityUnavailable('Owner task expected current job revision changed')
            responsibility_ref = responsibility_digest = current_job_digest = None
            if request.operation_kind == CREATE_OPERATION:
                body = CreateOwnerSourceNoteTaskRequestV1(auth.original_ref)
                if (job_value is not None or request.expected_job_revision != 0
                        or request.operation_id != ids['create_operation_id']
                        or request.request_digest != owner_task_typed_command_digest_v1(operation,body)):
                    raise AuthorityUnavailable('Owner task creation differs from its one actual authorized cause')
            else:
                if job_value is None:
                    raise AuthorityUnavailable('Owner task continuation has no actual current job')
                job = get_job(db,job_key.name)
                cont = decode_typed_production_value_v1(job.continuation,OwnerSourceNoteTaskContinuationV2)
                if (job_graph_write(job).value != job_value or job.work_kind != TASK_WORK_KIND
                        or job.operation_id != ids['create_operation_id'] or job.activity_id != ids['activity_id']
                        or job.effect_id is not None or job.budget_ref != parent.lease_id or job.cancel_epoch
                        or cont.cancel_generation or cont.authorization_original_ref != auth.original_ref
                        or cont.authorization_original_digest != auth.digest
                        or cont.cause_original_ref != cause.original_ref or cont.cause_original_digest != cause.digest
                        or cont.source_refs != auth.source_refs
                        or job.phase in {'completed','cancelled','failed','draining','pending_confirmation'}
                        or now >= datetime.fromisoformat(job.deadline_utc.replace('Z','+00:00')).timestamp()):
                    raise AuthorityUnavailable('Owner task SQL/Graph job or immutable original scope changed')
                responsibility_ref = ids['responsibility_ref']
                saved_responsibility = _read(db,issuer=self.issuer,namespace=ns,kind=RESPONSIBILITY_KIND,ref=responsibility_ref)
                if saved_responsibility is None:
                    raise AuthorityUnavailable('Owner task actual signed Self responsibility is absent')
                responsibility = decode_typed_production_value_v1(saved_responsibility[0],OwnerSourceNoteTaskResponsibilityV2)
                expected = OwnerSourceNoteTaskResponsibilityV2(ns,service._installation_id,cause.owner_operation_id,
                    cause.original_ref,cause.digest,auth.original_ref,auth.digest,guard,GraphVersion(mapping_key,versions[mapping_key]),
                    canonical_digest(mapping),current_self.self_entity_ref,parent.lease_id,cause.original_deadline_utc,auth.source_refs)
                responsibility_digest = responsibility.digest
                if (responsibility != expected or saved_responsibility[1] != job.operation_id
                        or (cont.responsibility_ref,cont.responsibility_digest) != (responsibility_ref,responsibility_digest)):
                    raise AuthorityUnavailable('Owner task responsibility is not its actual fixed Self and Owner cause')
                if request.operation_kind == ACQUIRE_OPERATION:
                    if job.phase != 'queued' or job.lease_holder is not None:
                        raise AuthorityUnavailable('Owner task acquire requires its actual queued unleased job')
                else:
                    if (job.phase != 'running' or job.lease_holder != current_self.self_entity_ref
                            or job.lease_expires_utc is None
                            or now >= datetime.fromisoformat(job.lease_expires_utc.replace('Z','+00:00')).timestamp()):
                        raise AuthorityUnavailable('Owner task step requires its actual live Self worker')
                    if request.operation_kind != CHECKPOINT_OPERATION and (cont.pending_effect_refs
                            or cont.step not in _STEPS[request.operation_kind]):
                        raise AuthorityUnavailable('Owner task step cannot bypass an unresolved original effect or task phase')
                current_job_digest = canonical_digest(job)
                if type(request) is OwnerTaskActivityValuesChildRequestV1:
                    from ..runtime.owner_source_note_values_v1 import qualify_owner_task_values_child_in_core_v1
                    parent, _ = qualify_owner_task_values_child_in_core_v1(db,request=request,authorization=auth,
                        job=job,current_self=current_self,owner_guard=guard,now_utc=now,issuer=self.issuer)
                    versions.update((head.key,head.revision) for head,_,_ in parent.hard_heads)
                    deadline=min(deadline,parent.original_deadline_utc)
                if request.operation_kind in {'prepare_source_note_body','register_owner_source_note_life_plan_v1',
                        'prepare_life','register_owner_source_note_life_outcome_v1','advance_life','settle_personal_goal'}:
                    from ..runtime.owner_source_note_life_v1 import qualify_owner_source_note_life_command_v1
                    command_heads=qualify_owner_source_note_life_command_v1(db,authorization=auth,request=request,
                        issuer=self.issuer,now_utc=now,actor_ref=current_self.self_entity_ref)
                    versions.update((head.key,head.revision) for head in command_heads)
            epochs = db.execute('SELECT access_epoch,delete_epoch FROM graph_authority_epochs WHERE bot=? AND persona=?',ns.as_tuple).fetchone()
            result = OwnerTaskActivityEvidenceV1(request,current_self,guard,auth,
                tuple(GraphVersion(key,revision) for key,revision in sorted(versions.items(),key=lambda row:row[0].token)),
                QueryEpoch(ns,'namespace',current_self.graph_epoch),owner_task_allowed_write_domains_v1(request.operation_kind),
                datetime.fromtimestamp(deadline,timezone.utc).isoformat().replace('+00:00','Z'),
                *epochs,now,current_job_digest,responsibility_ref,responsibility_digest,completion)
        after = service.current(credential=credential,subject=subject,request=identity_request)
        if after != current_self:
            raise AuthorityUnavailable('Owner task independent Self/Owner/C09/Graph observation changed')
        service._fences.validate_fence(credential=credential,subject=subject,permit=permit)
        final_clock = self.clock()
        if final_clock.utc_seconds + final_clock.utc_error_seconds >= deadline:
            raise AuthorityUnavailable('Owner task expired during its actual current qualification')
        return result, permit

    def _require_body_policy(self, db, auth, now):
        # The signed Owner W01 original committed the verified Body policy; this
        # independent reader compares those exact bytes and current status.
        from ..domains.d02.body_quote_original import FixedBodyPolicyV1
        ns, binding = auth.cause.namespace, auth.body_policy
        row = db.execute('SELECT policy_json,status FROM d02_fixed_body_policies_v1 WHERE bot=? AND persona=? AND policy_id=? AND version=?',
            (*ns.as_tuple,binding.body_policy_id,binding.body_policy_version)).fetchone()
        if row is None or row[1] != 'active':
            raise AuthorityUnavailable('Owner task original Body policy is not active')
        body = decode_typed_production_value_v1(json.loads(row[0]),FixedBodyPolicyV1)
        if (canonical_digest(body) != binding.body_policy_digest or body.work_kind != NOTE_WORK_KIND
                or body.component.component_id != binding.component_id or now >= body.valid_until):
            raise AuthorityUnavailable('Owner task Body policy bytes or validity changed')
        effect = db.execute("SELECT revision,payload_json,payload_digest,signature FROM graph_d02_production_policies_v1 "
            "WHERE bot=? AND persona=? AND policy_ref=? AND kind='effect' ORDER BY revision DESC LIMIT 1",
            (*ns.as_tuple,binding.effect_policy_ref)).fetchone()
        if effect is None or (effect[0],effect[2]) != (binding.effect_policy_revision,binding.effect_policy_digest):
            raise AuthorityUnavailable('Owner task current effect policy changed')
        self.issuer._signer.verify('d11.d02-production-policy.v1',effect[1],effect[3])
        if canonical_digest(json.loads(effect[1])) != effect[2]:
            raise AuthorityUnavailable('Owner task current effect policy original bytes changed')


def owner_task_activity_to_wire_v1(value):
    kinds = {OwnerTaskActivityRequestV1:'request',OwnerTaskActivityValuesChildRequestV1:'values_child_request',OwnerTaskActivityEvidenceV1:'evidence'}
    if type(value) not in kinds:
        raise TypeError('unregistered Owner task activity wire type')
    return {'schema':'d11.owner-task-activity-wire.v1','kind':kinds[type(value)],'value':plain_v1(value)}


def owner_task_activity_from_wire_v1(raw, expected_type):
    kinds = {'request':OwnerTaskActivityRequestV1,'values_child_request':OwnerTaskActivityValuesChildRequestV1,'evidence':OwnerTaskActivityEvidenceV1}
    if (type(raw) is not dict or set(raw) != {'schema','kind','value'}
            or raw['schema'] != 'd11.owner-task-activity-wire.v1' or kinds.get(raw['kind']) is not expected_type):
        raise ValueError('Owner task activity exact wire type differs')
    value = decode_typed_production_value_v1(raw['value'],expected_type)
    if owner_task_activity_to_wire_v1(value) != raw:
        raise ValueError('Owner task activity original canonical wire differs')
    return value
