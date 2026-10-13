"""Explicit paged-root storage manifest domain; V1 tuple roots stay unchanged."""
from __future__ import annotations
from .contract import AuthorityUnavailable

SCHEMA_V2="sylanne3.c09.storage_manifest.v2"
ROOT_ALGORITHM_V2="sylanne3.c09.paged-storage-roots.v2"
PROVENANCE_FIELDS_V2=frozenset(("root_algorithm","capture_scope_digest","facts_complete_original_digest",
    "facts_pin_digest","four_role_complete_original_digests","physical_inventory_complete_original_digest",
    "physical_inventory_root","physical_inventory_eof_digest"))


def manifest_fields_v2():
    from .c09_storage_control_v1 import _MANIFEST_FIELDS
    return _MANIFEST_FIELDS|PROVENANCE_FIELDS_V2


def require_manifest_provenance_shape_v2(value):
    from .c09_storage_control_v1 import ROLES,_hex
    if set(value)!=manifest_fields_v2() or value["schema"]!=SCHEMA_V2:
        raise AuthorityUnavailable("C09 V2 manifest closed paged-root fields differ")
    _require_paged_root_values_v2(value)


def _require_paged_root_values_v2(value):
    """Unchanged V2 root meanings, also explicitly inherited by V3."""
    from .c09_storage_control_v1 import ROLES,_hex
    if value["root_algorithm"]!=ROOT_ALGORITHM_V2:
        raise AuthorityUnavailable("C09 original paged-root algorithm differs")
    for name in PROVENANCE_FIELDS_V2-{"root_algorithm","four_role_complete_original_digests"}:
        _hex(value[name],name)
    refs=value["four_role_complete_original_digests"]
    if type(refs) is not dict or tuple(sorted(refs))!=ROLES:
        raise AuthorityUnavailable("C09 V2 manifest requires exactly four completed role references")
    for value in refs.values():
        _hex(value,"completed_role_original_digest")


def manifest_signature_domain(value):
    if value["schema"]=="sylanne3.c09.storage_manifest.v3":
        from .c09_storage_manifest_v3 import require_manifest_provenance_shape_v3,SIGNATURE_DOMAIN_V3
        require_manifest_provenance_shape_v3(value)
        return SIGNATURE_DOMAIN_V3
    if value["schema"]==SCHEMA_V2:
        return "sylanne3.c09.manifest_signature.v2"
    if value["schema"]=="sylanne3.c09.storage_manifest.v1":
        return "sylanne3.c09.manifest_signature.v1"
    raise AuthorityUnavailable("unregistered C09 storage manifest version")


def require_manifest_actual_provenance_v2(control,db,manifest,prepared):
    require_manifest_provenance_shape_v2(manifest)
    return _require_manifest_actual_paged_provenance_v2(control, db, manifest, prepared)


def _require_manifest_actual_paged_provenance_v2(control, db, manifest, prepared):
    """Common signed physical roots; the caller verifies its manifest domain."""
    from .c09_prepared_storage_v2 import _build_original
    from ..runtime_contracts import canonical_digest
    for name in ("capture_scope_digest","facts_complete_original_digest","facts_pin_digest","four_role_complete_original_digests"):
        if manifest[name]!=prepared[name]:
            raise AuthorityUnavailable("C09 V2 manifest differs from its actual PREPARED "+name)
    physical=_build_original(control,db,prepared["operation_id"],"frozen_inventory_complete_v2",
        manifest["physical_inventory_complete_original_digest"])
    if (physical["record_root"]!=manifest["physical_inventory_root"]
            or physical["eof_observation_digest"]!=manifest["physical_inventory_eof_digest"]
            or physical["scope_digest"]!=manifest["capture_scope_digest"]
            or physical["four_role_complete_original_digests"]!=manifest["four_role_complete_original_digests"]
            or canonical_digest(physical)!=prepared["frozen_scan_digest"]):
        raise AuthorityUnavailable("C09 V2 manifest actual complete physical inventory differs")
