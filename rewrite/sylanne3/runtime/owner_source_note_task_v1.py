"""Actual Owner management submission and current authorization for a SourceNote task."""
import json

from ..domains.d01.production_operations_v1 import plain_v1, stage_result_v1
from ..domains.d08.execution import GoalExecutionProvider
from ..graph_types import AtomKey, GraphVersion, GraphWrite
from ..runtime_contracts import NamespaceId, VersionedRef, canonical_digest
from .d01_production_operations_v1 import CurrentDomainReadV1, MissingProductionOriginalV1, production_read_plan_v1
from .domain_production_originals_v1 import read_adopted_domain_operation_v1
from .domain_production_erasure_v1 import decode_typed_production_value_v1
from .owner_source_note_task_contract_v1 import (SubmitOwnerSourceNoteTaskRequestV1, OwnerTaskCauseV1,
    OwnerTaskBodyPolicyBindingV1, OwnerSourceNoteTaskAuthorizationV2, owner_source_note_task_ids_v1,
    NOTE_WORK_KIND, TASK_WORK_KIND)
from .source_note_task_authorization_v1 import install_source_note_task_authorization_readers_v1
from .d11_life_preparation_v1 import _read, _record
from .budget import get_budget_lease, require_budget_family_admissible
from ..graph_types import owner_grant_key

OPERATION = 'submit_owner_source_note_task_v1'
CAUSE_KIND = 'owner_source_note_task_cause_v1'
AUTHORIZATION_KIND = 'owner_source_note_task_authorization_v2'
_READERS_KEY = object()


class InstalledOwnerSourceNoteTaskReadersV1:
    def __init__(self, key, *, owner_readers, body_readers, package_root, manifest_digest):
        if key is not _READERS_KEY:
            raise TypeError('Owner task readers belong to the actual installed Owner factory')
        self.owner_readers, self.body_readers = owner_readers, body_readers
        self.issuer, self.installed_bundle = owner_readers.issuer, owner_readers.installed_bundle
        self.package_root, self.manifest_digest = package_root, manifest_digest

    def require_owner_frame(self, frame):
        self.owner_readers.require_owner_frame(frame)


def install_owner_source_note_task_readers_v1(graph, *, scope, owner_guard, owner_binding):
    from .d02_production_operations_v1 import InstalledD02ProductionReadersV1
    owner = install_source_note_task_authorization_readers_v1(graph, scope=scope,
        owner_guard=owner_guard, owner_binding=owner_binding)
    assembly = graph._GraphCoordinator__d04_installed_joint_assembly
    body = InstalledD02ProductionReadersV1(issuer=owner.issuer,
        body_quote_authority=graph._GraphCoordinator__body_quote_authority,
        role_clock_reader=graph._GraphCoordinator__d04_semantic_mapping_reader)
    return InstalledOwnerSourceNoteTaskReadersV1(_READERS_KEY, owner_readers=owner, body_readers=body,
        package_root=assembly.package_root, manifest_digest=assembly.installation_policy.manifest_digest)


def _scope_heads(db, read, request):
    refs = {'body_source':request.body_source_ref, 'project':request.project_ref, 'recipe':request.recipe_ref,
        'target':request.target_entity_ref, 'role':request.role_binding_ref}
    heads = {name:read.head(db, ref, required=True) for name,ref in refs.items()}
    ns = read.frame.envelope.authority.namespace
    role, target, project, recipe = (heads[name].value for name in ('role','target','project','recipe'))
    from .d11_life_contract_v1 import RECIPE_ID
    if (target['status'] != 'active' or role['status'] != 'active'
            or role['subject_persona_ref'] != 'persona:' + ns.persona_id
            or role['target_entity_ref'] != target['entity_id']
            or read.frame.now_utc < role['effective_from']
            or role['effective_until'] is not None and read.frame.now_utc >= role['effective_until']
            or project['reality'] != 'real_execution' or project['next_step'] != 'source_note'
            or recipe != {'recipe_id':RECIPE_ID,'version':1,'reality':'real_execution','allowed_steps':['source_note'],'preemptible':True}):
        raise MissingProductionOriginalV1('actual_current_Owner_SourceNote_scope')
    roots = tuple(dict.fromkeys((request.body_source_ref, *role['source_refs'])))
    for audience in read.frame.envelope.authority.audience:
        for purpose in ('context','consolidation'):
            read.source_family(db, roots, purpose=purpose, audience=audience)
    for name, head in heads.items():
        if NamespaceId.from_key(head.key) != ns:
            raise ValueError('Owner task head crossed its actual namespace')
        if name != 'body_source':
            original = db.execute('SELECT event_id FROM graph_history WHERE token=? AND revision=?',
                (head.key.token,head.revision)).fetchone()
            if original is None:
                raise MissingProductionOriginalV1('actual_Owner_task_scope_origin:' + name)
            read.committed_operation(db, original[0])
    return heads, roots


def stage_submit_owner_source_note_task_v1(db, *, frame, request, installed_readers):
    if type(request) is not SubmitOwnerSourceNoteTaskRequestV1 or type(installed_readers) is not InstalledOwnerSourceNoteTaskReadersV1:
        raise TypeError('actual installed Owner SourceNote submission required')
    readers = installed_readers; readers.require_owner_frame(frame)
    read = CurrentDomainReadV1(frame); read.check(db)
    ns = frame.envelope.authority.namespace
    bundle = readers.installed_bundle
    head = read.head(db, owner_grant_key(*ns.as_tuple), required=True)
    if (head.key.token, head.revision, canonical_digest(head.value)) != (
            frame.owner_guard.grant_ref, frame.owner_guard.grant_revision, frame.owner_guard.grant_digest):
        raise ValueError('Owner task changed the actual Owner grant head')
    heads, roots = _scope_heads(db, read, request)
    parent = get_budget_lease(db, frame.envelope.parent_budget_lease_ref)
    require_budget_family_admissible(db, parent.lease_id)
    root = readers.issuer.current_budget_grant(db, parent.lease_id)
    if (parent.lease_id != bundle.installation_policy.root_lease.lease_id or root != bundle.installation_policy.root_grant
            or not {NOTE_WORK_KIND,TASK_WORK_KIND} <= set(root.allowed_work_kinds)):
        raise MissingProductionOriginalV1('original_installed_root_allows_Owner_SourceNote_task')
    policy = readers.body_readers.body_quote_authority.policy(db, ns, request.body_policy_id, request.body_policy_version)
    profile, _, _ = readers.body_readers._current_body(db, read, policy.profile.profile_id)
    if policy.work_kind != NOTE_WORK_KIND or profile != policy.profile:
        raise ValueError('Owner task Body policy must be the actual registered SourceNote component')
    row = db.execute("SELECT policy_ref,revision,kind,payload_json,payload_digest,signature FROM graph_d02_production_policies_v1 WHERE bot=? AND persona=? AND policy_ref=? AND kind='effect' ORDER BY revision DESC LIMIT 1",
        (*ns.as_tuple,request.effect_policy_ref)).fetchone()
    if row is None: raise MissingProductionOriginalV1('actual_Owner_SourceNote_effect_policy')
    effect, _ = readers.body_readers._policy(read, row)
    if (effect.profile_id,effect.work_kind,effect.component_id) != (profile.profile_id,NOTE_WORK_KIND,policy.component.component_id):
        raise ValueError('Owner task effect policy differs from its actual Body component')
    if (any(dimension not in parent.limits or dimension not in root.max_ceiling
            or parent.limits[dimension] < 1 or root.max_ceiling[dimension] < 1
            for dimension in ('cpu_ms','thread_cpu_ms'))):
        raise MissingProductionOriginalV1('actual_Owner_SourceNote_signed_single_attempt_CPU_dimensions')
    # Body reservation and native execution retain their two distinct budget dimensions.
    cpu = min(60000, root.max_ceiling['cpu_ms'], parent.available('cpu_ms'),
        root.max_ceiling['thread_cpu_ms'], parent.available('thread_cpu_ms'))
    if cpu < 1:
        raise MissingProductionOriginalV1('actual_Owner_SourceNote_available_original_parent_CPU')
    deadline = min(request.requested_deadline_utc,frame.envelope.deadline_utc,root.valid_until_utc,policy.valid_until)
    until = heads['role'].value['effective_until']
    if until is not None: deadline = min(deadline,until)
    if deadline <= frame.now_utc: raise MissingProductionOriginalV1('actual_Owner_SourceNote_original_deadline')
    from .foreground_cycle_v1 import foreground_deadline_utc_v1
    deadline = foreground_deadline_utc_v1(deadline)
    cause = OwnerTaskCauseV1(ns,bundle.installation_policy.installation_id,bundle.installation_policy.manifest_digest,
        frame.envelope.identity.operation_id,frame.envelope.authority.actor,frame.owner_guard,canonical_digest(request),
        frame.now_utc,deadline,parent.lease_id,root.grant_id,root.version,canonical_digest(root),tuple(frame.envelope.authority.audience))
    ids = owner_source_note_task_ids_v1(ns,cause.owner_operation_id)
    if read.head(db,ids['goal_key']).revision or read.head(db,ids['plan_key']).revision:
        raise ValueError('Owner task initial Goal/Plan identities already exist')
    from ..host.installed_d11_life_build_v1 import read_installed_d11_life_build_v1
    build = read_installed_d11_life_build_v1(readers.package_root,readers.manifest_digest)
    from .owner_source_note_goal_plan_v1 import build_owner_source_note_goal_plan_v1
    facts = tuple(VersionedRef(head.key.token,head.revision) for head in heads.values())
    goal, plan = build_owner_source_note_goal_plan_v1(cause=cause,request=request,source_refs=roots,fact_versions=facts,
        body_source_digest=canonical_digest(heads['body_source'].value),postcondition_build_digest=build['postcondition_build_digest'])
    body = OwnerTaskBodyPolicyBindingV1(policy.policy_id,policy.version,canonical_digest(policy),effect.policy_ref,
        effect.revision,canonical_digest(plain_v1(effect)),effect.component_id,cpu)
    pins = [(name,GraphVersion(head.key,head.revision),canonical_digest(head.value)) for name,head in sorted(heads.items())]
    pins.extend((('goal',GraphVersion(ids['goal_key'],1),canonical_digest(plain_v1(goal))),
        ('plan',GraphVersion(ids['plan_key'],1),canonical_digest(plain_v1(plan)))))
    authorization = OwnerSourceNoteTaskAuthorizationV2(cause,request,tuple(pins),body,roots)
    dependencies = tuple(head.key for head in heads.values())
    writes = (GraphWrite(ids['goal_key'],plain_v1(goal),dependencies),GraphWrite(ids['plan_key'],plain_v1(plan),dependencies))
    provider = GoalExecutionProvider()
    return stage_result_v1(frame,'d08',OPERATION,request,writes=writes,
        provenance={'owner_task_cause':cause,'owner_task_authorization':authorization},
        receiver_events=(('d11','owner_source_note_task_submitted_v1'),),
        proposal_schema='d08.proposal.v1',proposal_hash=provider.descriptor.request_schema_hash)


def record_owner_source_note_task_after_cas_v1(db, *, frame, stage, receipt, installed_readers):
    proof = json.loads(stage.original_payload_json)['provenance']
    authorization = decode_typed_production_value_v1(proof['owner_task_authorization'],OwnerSourceNoteTaskAuthorizationV2)
    cause = authorization.cause
    ids = owner_source_note_task_ids_v1(cause.namespace,cause.owner_operation_id)
    if (receipt.operation_id != cause.owner_operation_id or receipt.status != 'committed'
            or set(receipt.write_versions) != {GraphVersion(ids['goal_key'],1),GraphVersion(ids['plan_key'],1)}
            or proof['owner_task_cause'] != plain_v1(cause)):
        raise ValueError('Owner task authorization needs its exact same-W01 Goal/Plan receipt')
    _record(db,issuer=installed_readers.issuer,namespace=cause.namespace,kind=CAUSE_KIND,
        ref=cause.original_ref,operation_id=cause.owner_operation_id,value=cause)
    return _record(db,issuer=installed_readers.issuer,namespace=cause.namespace,kind=AUTHORIZATION_KIND,
        ref=authorization.original_ref,operation_id=cause.owner_operation_id,value=authorization)


def read_owner_source_note_task_authorization_v2(db, *, namespace, original_ref, issuer):
    saved = _read(db,issuer=issuer,namespace=namespace,kind=AUTHORIZATION_KIND,ref=original_ref)
    if saved is None:return None
    auth = decode_typed_production_value_v1(saved[0],OwnerSourceNoteTaskAuthorizationV2)
    actual = read_adopted_domain_operation_v1(db,namespace,saved[1])
    cause = _read(db,issuer=issuer,namespace=namespace,kind=CAUSE_KIND,ref=auth.cause.original_ref)
    if (auth.cause.namespace != namespace or auth.original_ref != original_ref or actual is None
            or actual['operation_kind'] != OPERATION or saved[1] != auth.cause.owner_operation_id
            or actual['payload']['provenance']['owner_task_authorization'] != saved[0]
            or cause is None or cause[1] != saved[1] or cause[0] != plain_v1(auth.cause)):
        raise ValueError('Owner task lost its actual signed same-W01 cause/authorization producer')
    return auth, actual


def read_plan_owner_source_note_task_v1(db, *, namespace, request, operation_id):
    ids = owner_source_note_task_ids_v1(namespace,operation_id)
    keys = [owner_grant_key(*namespace.as_tuple),ids['goal_key'],ids['plan_key'],
        *(AtomKey.from_token(ref) for ref in (request.body_source_ref,request.project_ref,request.recipe_ref,request.target_entity_ref,request.role_binding_ref))]
    roots = [request.body_source_ref]
    row = db.execute('SELECT value FROM graph_atoms WHERE token=? AND valid=1',(request.role_binding_ref,)).fetchone()
    if row: roots.extend(json.loads(row[0])['source_refs'])
    return production_read_plan_v1(('d02.body_profile.v1','d02.body_state.v1','d02.reservation.v1'),keys,
        tuple(dict.fromkeys(roots)),(request.project_ref,request.recipe_ref,request.target_entity_ref,request.role_binding_ref,request.effect_policy_ref))


def require_current_owner_source_note_task_authorization_v2(db, *, frame, authorization, issuer,
        installed_bundle, body_quote_authority, completed_settlement=None):
    read = CurrentDomainReadV1(frame); read.check(db)
    ns = frame.envelope.authority.namespace
    if (type(authorization) is not OwnerSourceNoteTaskAuthorizationV2 or authorization.cause.namespace != ns
            or (installed_bundle.installation_policy.installation_id,installed_bundle.installation_policy.manifest_digest) != (
                authorization.cause.installation_id,authorization.cause.manifest_digest)
            or frame.owner_guard != authorization.cause.owner_guard
            or frame.envelope.parent_budget_lease_ref != authorization.cause.parent_budget_lease_ref
            or frame.now_utc >= authorization.cause.original_deadline_utc):
        raise ValueError('Owner task lost actual current Owner/root/installation/deadline qualification')
    completed = None
    if completed_settlement is not None:
        from ..authority_service.current_owner_source_note_task_v1 import OwnerTaskCompletedSettlementV1, read_completed_owner_source_note_task_v1
        from .owner_source_note_task_contract_v1 import CHECKPOINT_OPERATION
        if type(completed_settlement) is not OwnerTaskCompletedSettlementV1 or frame.envelope.identity.phase != CHECKPOINT_OPERATION:
            raise ValueError('completed settlement qualifies only this named final task checkpoint')
        completed = read_completed_owner_source_note_task_v1(db,namespace=ns,authorization=authorization,issuer=issuer)
        if completed != completed_settlement:
            raise ValueError('final checkpoint completion must match its actual Core/native settlement proof')
    values = {}
    for name, version, digest in authorization.heads:
        if completed is not None and name in {'goal','plan'}:
            version, digest = ((completed.goal_head,completed.goal_digest) if name == 'goal' else (completed.plan_head,completed.plan_digest))
        head = read.head(db,version.key,required=True)
        if head.revision != version.revision or canonical_digest(head.value) != digest:
            raise MissingProductionOriginalV1('OwnerTask_current_authorized_head:' + name)
        values[name] = head.value
    role = values['role']
    if (role['status'] != 'active' or frame.now_utc < role['effective_from']
            or role['effective_until'] is not None and frame.now_utc >= role['effective_until']
            or values['target']['status'] != 'active'
            or values['goal']['state'] != ('satisfied' if completed is not None else 'active')
            or values['plan']['state'] != ('satisfied' if completed is not None else 'active')):
        raise MissingProductionOriginalV1('OwnerTask_current_scope_time_state')
    parent = get_budget_lease(db,authorization.cause.parent_budget_lease_ref)
    require_budget_family_admissible(db,parent.lease_id)
    grant = issuer.current_budget_grant(db,parent.lease_id)
    if (grant.grant_id,grant.version,canonical_digest(grant)) != (
            authorization.cause.parent_grant_id,authorization.cause.parent_grant_version,authorization.cause.parent_grant_digest):
        raise ValueError('Owner task cannot replace its actual original parent grant')
    policy = body_quote_authority.policy(db,ns,authorization.body_policy.body_policy_id,authorization.body_policy.body_policy_version)
    if (canonical_digest(policy) != authorization.body_policy.body_policy_digest or policy.work_kind != NOTE_WORK_KIND
            or frame.now_utc >= policy.valid_until):
        raise MissingProductionOriginalV1('OwnerTask_current_actual_Body_policy')
    row = db.execute("SELECT revision,payload_json,payload_digest,signature FROM graph_d02_production_policies_v1 WHERE bot=? AND persona=? AND policy_ref=? AND kind='effect' ORDER BY revision DESC LIMIT 1",
        (*ns.as_tuple,authorization.body_policy.effect_policy_ref)).fetchone()
    if row is None or row[0] != authorization.body_policy.effect_policy_revision or row[2] != authorization.body_policy.effect_policy_digest:
        raise MissingProductionOriginalV1('OwnerTask_current_actual_effect_policy')
    issuer._signer.verify('d11.d02-production-policy.v1',row[1],row[3])
    if canonical_digest(json.loads(row[1])) != row[2]:
        raise ValueError('Owner task effect policy original commitment changed')
    for audience in frame.envelope.authority.audience:
        for purpose in ('context','consolidation'):
            read.source_family(db,authorization.source_refs,purpose=purpose,audience=audience)
    return authorization


def read_owner_source_note_task_original_ref_v1(db, *, namespace, original_ref, issuer):
    from .domain_production_contracts_v1 import ProductionOriginalRefV1
    if original_ref.startswith('owner-source-note-authorization:'):
        saved = read_owner_source_note_task_authorization_v2(db, namespace=namespace, original_ref=original_ref, issuer=issuer)
        return None if saved is None else ProductionOriginalRefV1('d11.owner_source_note_task_authorization.v2',original_ref,saved[0].digest)
    if not original_ref.startswith('owner-source-note-cause:'): return None
    saved = _read(db,issuer=issuer,namespace=namespace,kind=CAUSE_KIND,ref=original_ref)
    if saved is None:return None
    cause = decode_typed_production_value_v1(saved[0],OwnerTaskCauseV1)
    actual = read_adopted_domain_operation_v1(db,namespace,saved[1])
    if (cause.original_ref != original_ref or cause.namespace != namespace or actual is None
            or actual['operation_kind'] != OPERATION or cause.owner_operation_id != saved[1]
            or actual['payload']['provenance']['owner_task_cause'] != saved[0]):
        raise ValueError('Owner task cause has no actual signed same-W01 producer')
    return ProductionOriginalRefV1('d11.owner_source_note_task_cause.v1',original_ref,cause.digest)
