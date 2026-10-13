"""Explicit segmented storage manifest domain; original paged roots retain V2 meaning.

Shape and signature-domain registration confer no selection or body admission.
Actual segmented completion streams and V3 PREPARED are independently required.
"""
from .contract import AuthorityUnavailable
from .c09_storage_manifest_v2 import manifest_fields_v2,_require_paged_root_values_v2

SCHEMA_V3='sylanne3.c09.storage_manifest.v3'
SIGNATURE_DOMAIN_V3='sylanne3.c09.manifest_signature.v3'
SEGMENTED_ROOT_ALGORITHM_V1='sylanne3.c09.segmented-role-roots.v1'
SEGMENTED_FIELDS_V3=frozenset({'segmented_root_algorithm','segmented_layouts',
    'segmented_role_complete_original_digests'})


def manifest_fields_v3():
    return manifest_fields_v2()|SEGMENTED_FIELDS_V3


def require_manifest_provenance_shape_v3(value):
    from .c09_storage_control_v1 import ROLES,_hex
    from ..segmented_sql_cell_v1 import LAYOUTS,LAYOUT_SCHEMA_DIGEST
    if (type(value) is not dict or set(value)!=manifest_fields_v3() or value['schema']!=SCHEMA_V3
            or value['segmented_root_algorithm']!=SEGMENTED_ROOT_ALGORITHM_V1):
        raise AuthorityUnavailable('C09 V3 manifest exact segmented-root fields differ')
    _require_paged_root_values_v2(value)
    layouts=value['segmented_layouts'];refs=value['segmented_role_complete_original_digests']
    if (type(layouts) is not dict or tuple(sorted(layouts))!=ROLES
            or type(refs) is not dict or tuple(sorted(refs))!=ROLES):
        raise AuthorityUnavailable('C09 V3 manifest requires exact four segmented roles')
    for role in ROLES:
        layout=layouts[role]
        if (type(layout) is not dict or set(layout)!={'layout_id','layout_schema_digest','storage_instance_id'}
                or layout['layout_id']!=LAYOUTS[role] or layout['layout_schema_digest']!=LAYOUT_SCHEMA_DIGEST):
            raise AuthorityUnavailable('C09 V3 selected layout differs from its registered role schema')
        _hex(layout['storage_instance_id'],'segmented_storage_instance_id')
        _hex(refs[role],'segmented_role_complete_original_digest')
