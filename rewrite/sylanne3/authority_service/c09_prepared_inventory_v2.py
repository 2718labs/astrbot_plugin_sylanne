"""C09 V2 final physical inventory admission under continuous exclusion."""
from __future__ import annotations

import os
from .contract import AuthorityUnavailable
from .c09_prepared_storage_v2 import _build_original
from ..runtime_contracts import canonical_digest


def require_prepared_inventory_v2(control, db, prepared, gate):
    """Consume the actual signed two-pass physical inventory and final gate."""
    from .c09_storage_control_v1 import ROLES
    from .c09_process_identity_v1 import read_process_identity_v1, require_process_retired_v1
    from ..runtime.c09_paged_capture_contract_v2 import C09CaptureScopeV2
    op=prepared["operation_id"]
    scope=C09CaptureScopeV2(**_build_original(control,db,op,"capture_scope_v2"))
    physical=_build_original(control,db,op,"frozen_inventory_complete_v2")
    expected_fields={"schema","scope_digest","source_domain_digest","installation_inventory_digest",
        "stream_id","record_count","page_count","record_root","page_root","eof_observation_digest",
        "four_role_complete_original_digests","accepted_receipt_digest","barrier_digest","writer_freeze_digest"}
    if (set(physical)!=expected_fields or physical["schema"]!="sylanne3.c09.frozen-physical-inventory-complete.v2"
            or physical["scope_digest"]!=scope.scope_digest or scope.scope_digest!=prepared["capture_scope_digest"]
            or physical["accepted_receipt_digest"]!=prepared["accepted_receipt_digest"]
            or physical["barrier_digest"]!=prepared["barrier_receipt_digest"]
            or physical["writer_freeze_digest"]!=prepared["writer_freeze_digest"]
            or physical["installation_inventory_digest"]!=prepared["frozen_inventory_digest"]
            or physical["four_role_complete_original_digests"]!=prepared["four_role_complete_original_digests"]
            or canonical_digest(physical)!=prepared["frozen_scan_digest"]):
        raise AuthorityUnavailable("C09 V2 PREPARED actual paged physical completion differs")
    from .c09_control_paged_schema_v2 import require_paged_control_schema_v2
    require_paged_control_schema_v2(db)
    row=db.execute("SELECT phase,source_domain_digest,result_json,first_eof,second_eof FROM c09_physical_inventory_streams_v2 WHERE stream_id=?",(physical["stream_id"],)).fetchone()
    if row is None or row[0]!="complete" or row[1]!=physical["source_domain_digest"]:
        raise AuthorityUnavailable("C09 V2 PREPARED actual physical stream completion absent")
    import json
    result=json.loads(row[2])
    if (any(result[name]!=physical[name] for name in ("record_count","page_count","record_root","page_root","eof_observation_digest"))
            or result["first_eof"]!=row[3] or result["second_eof"]!=row[4]):
        raise AuthorityUnavailable("C09 V2 PREPARED physical EOF or roots differ")
    current=control._current(db)
    intent=db.execute("SELECT event_json FROM c09_storage_events_v1 WHERE operation_id=? AND stage='INTENT'",(op,)).fetchone()
    if intent is None:
        raise AuthorityUnavailable("C09 V2 PREPARED actual INTENT absent")
    intent=json.loads(intent[0]);control.verify_original_v1(intent,"event_digest")
    frozen=intent["details"]["quiescence_original"]
    control.verify_original_v1(frozen,"quiescence_digest")
    identity=read_process_identity_v1(os.getpid())
    if (frozen["quiescence_digest"]!=scope.writer_freeze_digest
            or frozen["operation_id"]!=op or frozen["active_writers"]!=0):
        raise AuthorityUnavailable("C09 V2 PREPARED actual frozen predecessor differs")
    if frozen["authority_process_original"]!=identity:
        require_process_retired_v1(frozen["authority_process_original"])
        qualification=_build_original(control,db,op,"retired_final_qualification_v2_"+canonical_digest(identity))
        new=qualification["quiescence_original"]
        control.verify_original_v1(new,"quiescence_digest")
        if (qualification["schema"]!="sylanne3.c09.retired-final-qualification.v2"
                or qualification["operation_id"]!=op or qualification["prepared_digest"]!=prepared["prepared_digest"]
                or qualification["scan_digest"]!=prepared["frozen_scan_digest"]
                or qualification["old_quiescence_digest"]!=frozen["quiescence_digest"]
                or qualification["retired_authority_original"]!=frozen["authority_process_original"]
                or new["authority_process_original"]!=identity):
            raise AuthorityUnavailable("C09 V2 PREPARED actual retired continuation differs")
    else:
        new=frozen
    if (new["lock_process_id"]!=os.getpid() or new["lock_path"]!=str(control.lease.path)
            or new["pointer_version"]!=current["pointer_version"]
            or new["revoked_admission_epoch"]!=gate._epoch):
        raise AuthorityUnavailable("C09 V2 PREPARED actual final exclusion differs")
    sources=[]
    for role in ROLES:
        header=_build_original(control,db,op,"capture_role_complete_v2_"+role,
            prepared["four_role_complete_original_digests"][role])
        source=header["source_original"]
        identity=json.loads(source["source_identity"])
        sources.append(dict(resolved_path=source["source_path"],device=identity["device"],file_id=identity["file_id"],
            prepared_size=identity["size"],prepared_mtime_ns=identity["mtime_ns"],prepared_sha256=source["source_file_sha256"]))
    if sources!=prepared["source_final_fingerprints"]:
        raise AuthorityUnavailable("C09 V2 PREPARED signed final four source identities differ")
    return physical
