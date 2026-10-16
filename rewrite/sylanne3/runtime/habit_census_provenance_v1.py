"""Signed Habit census classification. Classification never authorizes a Body read."""
from ..graph_types import AtomKey,GraphVersion
from ..runtime_contracts import NamespaceId

OWNER_CENSUS_V1='habit_owner_source_census_v1'
METADATA_PROFILE_V1='habit-current-census.v1'
METADATA_FIELDS_V1=frozenset({'metadata_profile','metadata_only_versions','census_digest'})
_OWNER_FIELDS_V1=METADATA_FIELDS_V1|{'schema'}


def _digest_v1(value):
    if type(value)is not str or len(value)!=64 or any(c not in '0123456789abcdef'for c in value):
        raise ValueError('Habit census requires the actual canonical Source proof digest')


def _versions_v1(raw):
    if type(raw)is not list or len(raw)>1024:
        raise ValueError('Habit census versions exceed the original fixed head bound')
    values=[];tokens=[]
    for item in raw:
        if(type(item)is not dict or set(item)!={'key','revision'}or type(item['key'])is not str
                or type(item['revision'])is not int or item['revision']<0):
            raise ValueError('Habit census requires exact GraphVersion wire fields')
        key=AtomKey.from_token(item['key']);values.append(GraphVersion(key,item['revision']));tokens.append(key.token)
    if tokens!=sorted(set(tokens)):
        raise ValueError('Habit census requires ordered unique full graph keys')
    return tuple(values)


def decode_habit_census_fields_v1(raw):
    if type(raw)is not dict or set(raw)!=METADATA_FIELDS_V1 or raw['metadata_profile']!=METADATA_PROFILE_V1:
        raise ValueError('Habit census has another fixed profile or a partial extension')
    _digest_v1(raw['census_digest'])
    versions=_versions_v1(raw['metadata_only_versions'])
    if len({NamespaceId.from_key(v.key)for v in versions})>1:
        raise ValueError('Habit census metadata crosses namespaces')
    return versions


def validate_habit_owner_census_v1(domain,operation_kind,raw):
    from .d10_habit_v1 import POLICY_OPERATIONS
    from .d08_long_term_plan_v1 import OPERATIONS
    expected='d10'if operation_kind in POLICY_OPERATIONS else'd08'if operation_kind in OPERATIONS else None
    if(expected is None or domain!=expected or type(raw)is not dict or set(raw)!=_OWNER_FIELDS_V1
            or raw['schema']!='habit-owner-source-census.v1'):
        raise ValueError('Owner census is outside its exact installed policy/LongWindow write')
    return decode_habit_census_fields_v1({name:raw[name]for name in METADATA_FIELDS_V1})


def split_habit_census_payload_v1(payload):
    """Call only for an independently authenticated actual DomainOriginal payload."""
    from .habit_activity_history_v1 import HABIT_ACTIVITY_PROVENANCE_V1,validate_habit_activity_provenance_v1
    provenance=payload['provenance'];kind=payload['identity']['phase']
    domain=payload['schema'].split('.current-',1)[0]
    from .habit_maintenance_provenance_v1 import MAINTENANCE_PROVENANCE_V1,validate_habit_maintenance_provenance_v1
    maintenance=MAINTENANCE_PROVENANCE_V1 in provenance
    owner=OWNER_CENSUS_V1 in provenance;activity=HABIT_ACTIVITY_PROVENANCE_V1 in provenance
    if sum((owner,activity,maintenance))>1:
        raise ValueError('Owner census cannot borrow a background Habit execution identity')
    full=_versions_v1(payload['read_versions'])
    namespace=NamespaceId(**payload['namespace'])
    if any(NamespaceId.from_key(v.key)!=namespace for v in full):
        raise ValueError('Habit signed readset crosses its actual original namespace')
    if maintenance:
        _,_,_,metadata=validate_habit_maintenance_provenance_v1(domain,kind,provenance[MAINTENANCE_PROVENANCE_V1])
    elif owner:
        metadata=validate_habit_owner_census_v1(domain,kind,provenance[OWNER_CENSUS_V1])
    elif activity:
        raw=provenance[HABIT_ACTIVITY_PROVENANCE_V1]
        validate_habit_activity_provenance_v1(domain,kind,raw)
        present=set(raw)&METADATA_FIELDS_V1
        metadata=(decode_habit_census_fields_v1({name:raw[name]for name in METADATA_FIELDS_V1})if present else())
    else:
        return full,()
    selected=set(metadata)
    if not selected<=set(full):
        raise ValueError('Habit metadata classification is outside its own actual signed complete readset')
    for page in payload['query_coverage']:
        if not set(_versions_v1(page['row_versions']))<=set(full):
            raise ValueError('Habit census query coverage is outside its complete original CAS readset')
    return tuple(v for v in full if v not in selected),metadata


def append_habit_owner_census_v1(frame,domain,operation_kind,request,provenance):
    from .current_habit_source_read_v3 import current_habit_owner_census_v3
    if provenance is not None and OWNER_CENSUS_V1 in provenance:
        raise ValueError('Owner census is reserved for the actual private same-Work Source frame')
    actual=current_habit_owner_census_v3(frame,domain,operation_kind,request)
    if actual is None:return provenance
    from .habit_activity_history_v1 import HABIT_ACTIVITY_PROVENANCE_V1
    if provenance is not None and HABIT_ACTIVITY_PROVENANCE_V1 in provenance:
        raise ValueError('Owner write cannot claim a background Habit execution identity')
    return {**(provenance or {}),OWNER_CENSUS_V1:{'schema':'habit-owner-source-census.v1',**actual}}


def require_current_habit_census_payload_v1(frame,payload):
    from .current_habit_source_read_v3 import current_habit_frame_census_v3
    from .habit_activity_history_v1 import HABIT_ACTIVITY_PROVENANCE_V1
    from ..domains.d01.production_operations_v1 import plain_v1
    from .habit_maintenance_provenance_v1 import MAINTENANCE_PROVENANCE_V1,MAINTENANCE_PROFILE_V1
    actual=current_habit_frame_census_v3(frame)
    provenance=payload['provenance']
    if actual is None:
        if(MAINTENANCE_PROVENANCE_V1 in provenance or OWNER_CENSUS_V1 in provenance or HABIT_ACTIVITY_PROVENANCE_V1 in provenance
                and set(provenance[HABIT_ACTIVITY_PROVENANCE_V1])&METADATA_FIELDS_V1):
            raise ValueError('Habit census has no actual private current Source proof')
        return
    kind=payload['identity']['phase'];domain=payload['schema'].split('.current-',1)[0]
    if MAINTENANCE_PROVENANCE_V1 in provenance:
        raw=provenance[MAINTENANCE_PROVENANCE_V1]
        actual={**actual,'metadata_profile':MAINTENANCE_PROFILE_V1}
    else:
        owner=current_habit_owner_census_v1(frame,domain,kind,payload)
        raw=provenance[OWNER_CENSUS_V1]if owner else provenance[HABIT_ACTIVITY_PROVENANCE_V1]
    if {name:raw[name]for name in METADATA_FIELDS_V1}!=plain_v1(actual):
        raise ValueError('Habit signed census differs from its actual Source proof and Body partition')
    split_habit_census_payload_v1(payload)


def current_habit_owner_census_v1(frame,domain,kind,payload):
    from .current_habit_source_read_v3 import current_habit_owner_census_v3
    from .domain_production_registry_v1 import installed_operation_v1
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    request=decode_typed_production_value_v1(payload['request'],installed_operation_v1(kind).request_type)
    return current_habit_owner_census_v3(frame,domain,kind,request)is not None


def validate_habit_census_payload_v1(payload):
    from .habit_activity_history_v1 import HABIT_ACTIVITY_PROVENANCE_V1
    provenance=payload['provenance']
    from .habit_maintenance_provenance_v1 import MAINTENANCE_PROVENANCE_V1
    if not any(name in provenance for name in (OWNER_CENSUS_V1,HABIT_ACTIVITY_PROVENANCE_V1,MAINTENANCE_PROVENANCE_V1)):return None
    return split_habit_census_payload_v1(payload)


def validate_habit_census_original_v1(original):
    payload=original['payload'];parts=validate_habit_census_payload_v1(payload)
    if parts is None:return None
    body,metadata=parts
    if(payload['schema']!=original['domain']+'.current-'+original['operation_kind']+'.v1'
            or payload['identity']['phase']!=original['operation_kind']
            or set((*body,*metadata))!=set(original['read_versions'])
            or len(body)+len(metadata)!=len(original['read_versions'])):
        raise ValueError('Habit census differs from its actual committed producer/domain/readset')
    return body,metadata
