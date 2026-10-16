"""Exact signed provenance for original-only Habit maintenance; never execution authority."""
from ..runtime_contracts import NamespaceId,canonical_digest
from .habit_census_provenance_v1 import _versions_v1,_digest_v1

MAINTENANCE_PROVENANCE_V1='habit_original_maintenance_v1'
MAINTENANCE_PROFILE_V1='habit-original-maintenance-census.v1'
_FIELDS=frozenset(('schema','selector','selector_digest','current_self','owner_guard',
    'original_root_ref','original_root_digest','original_deadline_utc','permit_operation_id',
    'scope_binding_digest','metadata_profile','metadata_only_versions','census_digest'))


def habit_maintenance_scope_binding_v1(selector,*,permit,graph_revision,graph_epoch,root_ref,root_digest,deadline):
    return canonical_digest(('d10.habit-original-maintenance-scope-binding.v1',selector.namespace,
        canonical_digest(selector),permit.namespace,permit.operation_id,permit.token,permit.generation,
        permit.pinned_anchor,graph_revision,graph_epoch,root_ref,root_digest,deadline))


def validate_habit_maintenance_provenance_v1(domain,operation_kind,raw):
    import math
    from ..authority_service.current_habit_maintenance_v1 import habit_maintenance_selector_from_wire_v1
    from ..authority_service.v2_self_identity_contract import from_wire as self_from_wire,AuthorityCurrentSelfIdentityV1
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    from .domain_production_contracts_v1 import ProductionOwnerGuardV1
    if (domain!='d10' or operation_kind not in {'record_habit_miss_v1','adopt_habit_outcome_v1'}
            or type(raw)is not dict or set(raw)!=_FIELDS
            or raw['schema']!='d10.habit-original-maintenance-provenance.v1'
            or raw['metadata_profile']!=MAINTENANCE_PROFILE_V1):
        raise ValueError('Habit maintenance provenance has another exact domain, operation or profile')
    selector=habit_maintenance_selector_from_wire_v1(raw['selector'])
    current=self_from_wire(raw['current_self'])
    owner=decode_typed_production_value_v1(raw['owner_guard'],ProductionOwnerGuardV1)
    if (type(current)is not AuthorityCurrentSelfIdentityV1 or selector.operation_kind!=operation_kind
            or selector.namespace!=current.namespace or selector.installation_id!=current.installation_id
            or raw['selector_digest']!=canonical_digest(selector)
            or raw['permit_operation_id']!=selector.operation_id or current.permit.operation!='write'
            or current.permit.operation_id!=selector.operation_id
            or current.owner_authorization_head.removeprefix('sha256:')!=owner.owner_head_digest
            or type(raw['original_root_ref'])is not str or not raw['original_root_ref']
            or type(raw['original_deadline_utc'])not in (int,float)
            or not math.isfinite(raw['original_deadline_utc'])):
        raise ValueError('Habit maintenance provenance changed the actual selector, Owner or Self WRITE')
    for field in ('selector_digest','original_root_digest','scope_binding_digest','census_digest'):
        _digest_v1(raw[field])
    if raw['scope_binding_digest']!=habit_maintenance_scope_binding_v1(selector,permit=current.permit,
            graph_revision=current.graph_revision,graph_epoch=current.graph_epoch,
            root_ref=raw['original_root_ref'],root_digest=raw['original_root_digest'],deadline=raw['original_deadline_utc']):
        raise ValueError('Habit maintenance lost its complete actual original Scope binding')
    if selector.qualification_selector is not None:
        original=selector.qualification_selector
        if (raw['original_root_ref'],raw['original_root_digest'],raw['original_deadline_utc'])!=(
                original.parent_root_grant_ref,original.parent_root_grant_digest,original.original_deadline_utc):
            raise ValueError('Habit maintenance changed its actual historical qualification Root or deadline')
    metadata=_versions_v1(raw['metadata_only_versions'])
    if any(NamespaceId.from_key(row.key)!=selector.namespace for row in metadata):
        raise ValueError('Habit maintenance census crosses the actual namespace')
    return selector,current,owner,metadata


def append_current_habit_maintenance_provenance_v1(frame,domain,operation_kind,request,provenance):
    from .habit_maintenance_frame_v1 import CurrentHabitMaintenanceFrameV1,require_habit_maintenance_frame_v1
    from .habit_census_provenance_v1 import OWNER_CENSUS_V1
    from .habit_activity_history_v1 import HABIT_ACTIVITY_PROVENANCE_V1
    if provenance is not None and MAINTENANCE_PROVENANCE_V1 in provenance:
        raise ValueError('Habit maintenance provenance is reserved for its actual private same-Work frame')
    if type(frame)is not CurrentHabitMaintenanceFrameV1:return provenance
    from .current_habit_source_read_v3 import current_habit_frame_census_v3
    from ..authority_service.current_habit_maintenance_v1 import habit_maintenance_selector_to_wire_v1
    from ..authority_service.v2_self_identity_contract import to_wire as self_to_wire
    from ..domains.d01.production_operations_v1 import plain_v1
    evidence=require_habit_maintenance_frame_v1(frame)
    selector=evidence.request;issued=frame.issuance;scope=issued.scope
    census=current_habit_frame_census_v3(frame)
    if (census is None or domain!='d10' or operation_kind!=selector.operation_kind
            or request!=issued.command or any(key in (provenance or {})for key in (OWNER_CENSUS_V1,HABIT_ACTIVITY_PROVENANCE_V1))):
        raise ValueError('Habit maintenance lost its independent Source proof or borrowed an execution carrier')
    raw={'schema':'d10.habit-original-maintenance-provenance.v1',
        'selector':habit_maintenance_selector_to_wire_v1(selector),'selector_digest':canonical_digest(selector),
        'current_self':self_to_wire(evidence.current_self),'owner_guard':plain_v1(evidence.owner_guard),
        'original_root_ref':evidence.original_root_ref,'original_root_digest':evidence.original_root_digest,
        'original_deadline_utc':evidence.original_deadline_utc,'permit_operation_id':scope.operation_id,
        'scope_binding_digest':habit_maintenance_scope_binding_v1(selector,permit=scope.permit,
            graph_revision=scope.graph_revision,graph_epoch=scope.graph_epoch.revision,
            root_ref=evidence.original_root_ref,root_digest=evidence.original_root_digest,deadline=evidence.original_deadline_utc),
        'metadata_profile':MAINTENANCE_PROFILE_V1,'metadata_only_versions':plain_v1(census['metadata_only_versions']),
        'census_digest':census['census_digest']}
    validate_habit_maintenance_provenance_v1(domain,operation_kind,raw)
    return {**(provenance or {}),MAINTENANCE_PROVENANCE_V1:raw}


def require_habit_maintenance_attempt_payload_v1(row,*,original,permit):
    payload=original['payload'];raw=payload['provenance'][MAINTENANCE_PROVENANCE_V1]
    selector,current,owner,metadata=validate_habit_maintenance_provenance_v1(
        original['domain'],original['operation_kind'],raw)
    from .domain_production_registry_v1 import installed_operation_v1
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    operation=installed_operation_v1(original['operation_kind'])
    command=decode_typed_production_value_v1(payload['request'],operation.request_type)
    from ..domains.d01.production_operations_v1 import plain_v1
    if (selector.namespace!=NamespaceId(row[0],row[1]) or row[2]!=row[4] or row[4]!=selector.operation_id
            or row[3]!=canonical_digest(selector) or selector.command!=command or current.permit!=permit
            or (current.graph_revision,current.graph_epoch)!=(row[6],row[7])
            or payload['identity']['phase']!=selector.operation_kind
            or payload['identity']['operation_id']!=selector.operation_id
            or payload['authority']['actor']!=current.self_entity_ref
            or payload['owner_guard']!=plain_v1(owner) or payload['parent_budget']!=raw['original_root_ref']):
        raise ValueError('Habit maintenance attempt differs from its actual signed selector, Scope or historical Root')
    return selector
