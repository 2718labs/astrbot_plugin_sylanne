"""Private Source profile for historical Habit maintenance; no execution refresh."""
from weakref import WeakKeyDictionary
from ..authority_service.contract import AuthorityUnavailable
from ..authority_service.current_habit_maintenance_v1 import HabitOriginalMaintenanceSelectorV1

_FACTORIES=WeakKeyDictionary()
_ROOTS=WeakKeyDictionary()
_LOCATORS=WeakKeyDictionary()
_GRANT_SELECTORS=WeakKeyDictionary()


def _identity(capsule):
    return (capsule.graph,capsule.context,capsule.bundle,capsule.operation,capsule.work,
        capsule.selector,capsule.operation_kind,capsule.request,capsule.initial_deadline_utc,
        capsule.initial_monotonic_deadline)


def register_habit_maintenance_source_factory_v3(capsule):
    from .current_habit_source_read_v3 import _HabitPendingSourceV3,_PENDING,_pending_identity
    from .domain_production_registry_v1 import installed_operation_v1
    from .habit_maintenance_issuance_v1 import habit_maintenance_typed_command_digest_v1
    if (type(capsule)is not _HabitPendingSourceV3 or type(capsule.selector)is not HabitOriginalMaintenanceSelectorV1
            or _PENDING.get(capsule)!=_pending_identity(capsule) or capsule in _FACTORIES
            or capsule.selector.namespace!=capsule.bundle.installation_policy.namespace
            or capsule.selector.installation_id!=capsule.bundle.installation_policy.installation_id
            or capsule.request!=capsule.selector.command or capsule.operation_kind!=capsule.selector.operation_kind
            or capsule.selector.request_digest!=habit_maintenance_typed_command_digest_v1(
                installed_operation_v1(capsule.operation_kind),capsule.request)):
        raise AuthorityUnavailable('Habit maintenance Source requires its actual once-issued closed factory')
    _FACTORIES[capsule]=_identity(capsule)


def habit_maintenance_source_reader_v3(reader):
    from .current_habit_source_read_v3 import _PENDING_READERS,require_pending_habit_factory_v3,require_habit_source_work_v3
    state=require_habit_source_work_v3(reader)
    if type(state.selector)is not HabitOriginalMaintenanceSelectorV1:return None
    capsule=_PENDING_READERS.get(reader)
    if (capsule is None or _FACTORIES.get(capsule)!=_identity(capsule)
            or capsule.reader is not reader or capsule.selector!=state.selector
            or reader.session_proof is not None):
        raise AuthorityUnavailable('Habit maintenance Source lost its independent private profile')
    require_pending_habit_factory_v3(capsule,graph=reader.graph,operation=reader.operation,fence=reader.fence,
        authority=reader.authority,operation_kind=reader.operation_kind,request=reader.request)
    return state


def maintenance_original_definition_v3(reader):
    from .current_habit_source_read_v3 import _metadata,_select_refs
    state=habit_maintenance_source_reader_v3(reader)
    selector=state.selector
    value=_metadata(reader,('head',selector.occurrence_ref))
    task=state.tasks[('head',selector.occurrence_ref)]
    if value is None or task.metadata[:2]!=(selector.expected_revision,1) or value['policy_ref']!=selector.policy_ref:
        raise AuthorityUnavailable('Habit maintenance lost its actual current occurrence metadata')
    slot=(selector.policy_ref,value['policy_revision'],value['policy_digest'])
    if slot not in state.policy_versions:
        identity=('policy_history',selector.policy_ref);state.selected.add(identity);_metadata(reader,identity)
    definition=state.policy_versions.get(slot)
    if definition is None:raise AuthorityUnavailable('Habit maintenance lacks its exact original policy revision EOF')
    _select_refs(reader,definition,body=True)
    state.original_execution_deadline=value['original_deadline_utc']
    capsule=_maintenance_capsule_v3(reader)
    locator=(definition.parent_root_grant_ref,value['activity_id'],selector.policy_ref,
        value['policy_revision'],value['policy_digest'],value['original_deadline_utc'])
    if capsule in _LOCATORS and _LOCATORS[capsule]!=locator:
        raise AuthorityUnavailable('Habit maintenance original Root/activity changed across its actual metadata Scopes')
    _LOCATORS[capsule]=locator
    return definition


def prepare_current_habit_original_maintenance_source_v3(graph,context,*,selector):
    from .current_habit_source_read_v3 import _prepare_habit_source_work_v3
    if type(selector)is not HabitOriginalMaintenanceSelectorV1:
        raise TypeError('Habit maintenance requires its exact existing-original selector')
    return _prepare_habit_source_work_v3(graph,context,selector=selector,
        operation_kind=selector.operation_kind,request=selector.command)


def require_habit_maintenance_write_owner_identity_v3(reader,scope,issued):
    from .current_habit_source_read_v3 import require_habit_write_owner_identity_v3
    from .habit_maintenance_issuance_v1 import _IssuedHabitMaintenanceV1
    if type(issued)is not _IssuedHabitMaintenanceV1 or habit_maintenance_source_reader_v3(reader)is None:
        raise AuthorityUnavailable('Habit maintenance WRITE needs its own actual Source profile')
    return require_habit_write_owner_identity_v3(reader,scope,issued)


def read_habit_maintenance_root_metadata_v3(reader,definition):
    from .current_habit_source_read_v3 import _metadata,_habit_now_v3
    from .current_beta1_source_read_v3 import _beta1_metadata_row_v3
    from ..runtime_storage_v3 import runtime_storage_quantum_v3
    from ..runtime_contracts import canonical_digest
    state=habit_maintenance_source_reader_v3(reader)
    if state is None or definition is None:
        raise AuthorityUnavailable('Habit historical Root requires its exact private maintenance Source profile')
    root=definition.parent_root_grant_ref
    if state.root_locator is None:
        if reader.inputs_sealed or reader.read_finished or state.source_permission is not None or reader.selected_envelope is not None:
            raise AuthorityUnavailable('Habit historical Root must be authenticated before Source disclosure')
    capsule=_maintenance_capsule_v3(reader)
    if capsule.phase=='source'and reader.parent_budget_lease_ref!=root:
        raise AuthorityUnavailable('Habit maintenance changed its original Source Root')
    selected=(root,definition.parent_root_grant_version)
    if reader in _GRANT_SELECTORS and _GRANT_SELECTORS[reader]!=selected:
        raise AuthorityUnavailable('Habit maintenance selected another historical grant')
    _GRANT_SELECTORS[reader]=selected
    with runtime_storage_quantum_v3(reader.db)as meter:
        lease=_beta1_metadata_row_v3(reader,meter,'runtime_budget_leases',
            ('lease_id','parent_id','bot_id','persona_id','version','state'),'lease_id=?',(root,))
        header=_beta1_metadata_row_v3(reader,meter,'runtime_budget_grants',
            ('lease_id','version','signature','status'),'lease_id=? AND version=?',(root,definition.parent_root_grant_version))
    if (lease is None or lease[0]!=root or lease[1]is not None or tuple(lease[2:4])!=reader.namespace.as_tuple
            or type(lease[4])is not int or lease[4]<1 or header is None):
        raise AuthorityUnavailable('Habit maintenance lacks its actual same-namespace historical Root lease/grant')
    grant=_metadata(reader,('budget_grant',header[:2]))
    task=state.tasks[('budget_grant',header[:2])]
    if (task.metadata!=header or (grant.lease_id,grant.grant_id,grant.version,canonical_digest(grant))!=(
            root,definition.parent_root_grant_id,definition.parent_root_grant_version,definition.parent_root_grant_digest)
            or state.original_execution_deadline is None
            or state.original_execution_deadline>min(definition.original_valid_until_utc,grant.valid_until_utc)):
        raise AuthorityUnavailable('Habit maintenance historical Root differs from its exact policy/occurrence commitment')
    original=(definition,grant,lease,header,state.original_execution_deadline)
    if reader in _ROOTS and _ROOTS[reader]!=original:
        raise AuthorityUnavailable('Habit maintenance original signed Root changed during actual metadata EOF')
    _ROOTS[reader]=original
    locator=(root,grant.grant_id,grant.version,canonical_digest(grant),reader.operation.deadline_utc)
    if state.root_locator is not None and state.root_locator!=locator:
        raise AuthorityUnavailable('Habit maintenance changed its original Root or current control lifetime')
    state.budget_ancestry=(lease,);state.root_locator=locator;state.read_deadline=reader.operation.deadline_utc
    _habit_now_v3(reader)
    return locator


def require_habit_maintenance_original_root_v3(reader,evidence):
    from ..authority_service.current_habit_maintenance_v1 import HabitOriginalMaintenanceCurrentV1
    from ..runtime_contracts import canonical_digest
    state=habit_maintenance_source_reader_v3(reader)
    original=_ROOTS.get(reader)
    if state is None or type(evidence)is not HabitOriginalMaintenanceCurrentV1 or original is None:
        raise AuthorityUnavailable('Habit maintenance lacks its actual private historical Root EOF proof')
    definition,grant,lease,header,deadline=original
    standing=evidence.standing_original
    policy=reader.graph._GraphCoordinator__d04_installed_joint_assembly.admin_bundle.installation_policy
    if (standing.definition!=definition or standing.root_grant!=grant or standing.root_lease_id!=grant.lease_id
            or standing.installation_id!=policy.installation_id or standing.namespace!=reader.namespace
            or standing.authority_namespace!=policy.authority_namespace or evidence.request!=state.selector
            or evidence.original_root_ref!=grant.lease_id or evidence.original_root_digest!=canonical_digest(grant)
            or evidence.original_deadline_utc!=deadline or reader.parent_budget_lease_ref!=grant.lease_id):
        raise AuthorityUnavailable('Habit maintenance original Root differs from its independent actual Core standing')
    return grant


def _maintenance_capsule_v3(reader):
    from .current_habit_source_read_v3 import _PENDING_READERS
    capsule=_PENDING_READERS.get(reader)
    if capsule is None or _FACTORIES.get(capsule)!=_identity(capsule):
        raise AuthorityUnavailable('Habit maintenance requires its exact private Source factory lifetime')
    return capsule


def pending_habit_maintenance_identity_v3(capsule):
    if _FACTORIES.get(capsule)!=_identity(capsule):
        raise AuthorityUnavailable('Habit maintenance pending identity lacks its actual private factory')
    if capsule.phase=='metadata':
        return capsule.bundle.installation_policy.root_lease.lease_id,capsule.operation.operation_id
    original=_LOCATORS.get(capsule)
    if capsule.phase!='source'or original is None:
        raise AuthorityUnavailable('Habit maintenance actual Source identity lacks complete prior metadata EOF')
    return original[:2]


def require_habit_maintenance_budget_selector_v3(reader,key):
    state=habit_maintenance_source_reader_v3(reader)
    selected=_GRANT_SELECTORS.get(reader)
    if state is None or selected is None or tuple(key)!=selected:
        raise AuthorityUnavailable('Habit maintenance cannot read another historical Root/grant version')
    return selected


def habit_maintenance_business_activity_v3(reader):
    if habit_maintenance_source_reader_v3(reader)is None:return reader.activity_id
    original=_LOCATORS.get(_maintenance_capsule_v3(reader))
    if original is None:raise AuthorityUnavailable('Habit maintenance output metadata lacks actual occurrence EOF')
    return original[1]


def release_habit_maintenance_source_v3(reader):
    from .current_habit_source_read_v3 import _PENDING_READERS
    _ROOTS.pop(reader,None);_GRANT_SELECTORS.pop(reader,None)
    capsule=_PENDING_READERS.get(reader)
    if capsule is not None and capsule.reader is reader:
        _FACTORIES.pop(capsule,None);_LOCATORS.pop(capsule,None)
