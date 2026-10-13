"""Closed D12 Core row codecs for C09 validation and namespace retirement."""
from __future__ import annotations

from dataclasses import asdict
import json

from ..runtime.lifecycle_operations_v1 import decode_original, digest
from ..runtime_contracts import NamespaceId, canonical_serialize
from .contract import AuthorityUnavailable
from .d12_target_registry_v1 import D12TargetLeaseOriginalV1
from .d12_target_owner_admission_v1 import target_admission_from_wire_v1
from .v2_owner_session import from_wire as session_from_wire, _canonical
from .graph_catalogue_upgrade_v1 import (
    TABLE as CATALOGUE_TABLE, COLUMNS as CATALOGUE_COLUMNS, validate_catalogue_upgrade_core_row_v1,
)

COLUMNS = {
    CATALOGUE_TABLE: CATALOGUE_COLUMNS,
    "authority_d12_operation_originals_v1": ("authority_namespace", "operation_id", "original_ref", "original_json",
        "actor", "session_request_json", "owner_head", "plan_json", "source_original_ref"),
    "authority_d12_target_leases_v1": ("lease_ref", "record_json", "state", "transfer_id"),
    "authority_d12_target_owner_admissions_v1": ("authority_namespace", "target_installation_id", "original_ref",
        "original_digest", "original_json"),
    "authority_d12_lifecycle_heads_v1": ("namespace", "installation_id", "state", "epoch", "operation_id", "head_digest", "current_receipt_ref"),
    "authority_d12_lifecycle_operations_v1": ("namespace", "operation_id", "request_digest", "action", "source_original_ref", "source_original_json",
        "intent_json", "actor", "session_request_json", "owner_head", "storage_json", "initial_supervisor_json", "initial_process_json", "current_stage", "current_receipt_ref", "hold_code"),
    "authority_d12_lifecycle_receipts_v1": ("namespace", "operation_id", "stage", "original_ref", "original_digest", "original_json"),
    "authority_d12_lifecycle_bootstraps_v1": ("namespace", "epoch", "operation_id", "peer_certificate_sha256", "peer_profile_id", "process_json",
        "invocation_id", "manifest_digest", "graph_head_digest", "constraint_digest", "original_ref", "original_digest"),
}


def validate_d12_core_row_v1(table, columns, row):
    """Return (namespace, consumed kind, item, original operation or None)."""
    if columns != COLUMNS.get(table) or len(row) != len(columns):
        raise AuthorityUnavailable("C09 D12 Core row schema differs")
    try:
        if table == CATALOGUE_TABLE:
            validate_catalogue_upgrade_core_row_v1(columns, row)
            if row[11] != 'completed':
                raise ValueError('C09 cannot retire pending catalogue conversion')
            return row[0], 'catalogue_upgrade_operation', row[1], row[1]
        if table == "authority_d12_operation_originals_v1":
            original = decode_original(json.loads(row[3]))
            plan = json.loads(row[7])
            request = session_from_wire({"kind": "owner_session_login_request_v1", **json.loads(row[5])})
            if ((original.operation_id, original.original_ref) != row[1:3]
                    or request.authority_namespace != row[0] or _canonical(request) != row[5]
                    or plan["owner"]["namespace"] != asdict(original.namespace)
                    or plan["owner"]["actor"] != row[4]
                    or plan["owner"]["grant_digest"] != original.owner_grant_digest
                    or plan["owner"]["authority_ref"] != "owner-authority:" + row[6]
                    or canonical_serialize(asdict(original)) != row[3]):
                raise ValueError("operation identity/Owner binding differs")
            if original.kind == "transfer_execution":
                if (original.result.authority_namespace != row[0] or plan["payload"]["authority_namespace"] != row[0]
                        or plan["migration_plan"]["transfer_id"] != original.result.transfer_id
                        or digest(plan) != original.plan_digest or not row[8].startswith("d12original:")):
                    raise ValueError("transfer plan/origin differs")
            elif original.kind == "control":
                if plan.get("schema") == "d12.registered_owner_stop_reply.v1":
                    from .owner_stop_reply_v1 import validate_owner_stop_reply_core_row_v1
                    return validate_owner_stop_reply_core_row_v1(row)
                from .d12_lifecycle_contract_v1 import D12InstallationControlIntentV1
                from ..runtime.lifecycle_operations_v1 import ControlCommandV1
                command = ControlCommandV1.from_wire(plan["input"])
                intent = D12InstallationControlIntentV1.from_command(command)
                if (plan["schema"] != "d12.registered_installation_control.v1"
                        or asdict(intent) != plan["intent"] or original.plan_ref is not None
                        or intent.installation_id != request.installation_id
                        or (original.result.object_ref,original.result.control)!=(command.object_ref,command.control)
                        or not (row[8].startswith("d12original:") or intent.action=="resume"
                            and row[8]=="d12controlrequest:"+original.request_digest[7:])):
                    raise ValueError("registered whole-Host control original differs")
            else:
                raise ValueError("unregistered D12 status original kind")
            return row[0], "d12_operation_original", original.original_ref, original.operation_id
        if table == "authority_d12_target_leases_v1":
            values = json.loads(row[1])
            values["namespace_id"] = NamespaceId(**values["namespace_id"])
            item = D12TargetLeaseOriginalV1(**values)
            if (item.lease_ref != row[0] or canonical_serialize(asdict(item)) != row[1]
                    or row[2] not in {"reserved", "active"}
                    or row[2] == "active" and not row[3]
                    or row[3] is not None and (type(row[3]) is not str or not row[3])):
                raise ValueError("target reservation identity/state differs")
            return item.authority_namespace, "d12_target_lease", item.lease_ref, row[3]
        if table == "authority_d12_lifecycle_heads_v1":
            if row[2] not in {"active","quiescing","drained","paused","resuming"} or type(row[3]) is not int or row[3]<0:
                raise ValueError("lifecycle head state/epoch differs")
            return row[0], "d12_lifecycle_head", row[1], row[4]
        if table == "authority_d12_lifecycle_operations_v1":
            from .d12_lifecycle_contract_v1 import D12InstallationControlIntentV1, STAGES
            original=decode_original(json.loads(row[5]));intent=D12InstallationControlIntentV1(**json.loads(row[6]))
            request=session_from_wire({"kind":"owner_session_login_request_v1",**json.loads(row[8])})
            if (original.kind!="control" or original.namespace!=NamespaceId(**json.loads(row[5])["namespace"])
                    or (original.operation_id,original.request_digest)!=(row[1],row[2])
                    or intent.action!=row[3] or row[13] not in STAGES or request.authority_namespace!=row[0]
                    or canonical_serialize(asdict(original))!=row[5] or _canonical(request)!=row[8]
                    or original.result.object_ref!="installation:"+intent.installation_id):
                raise ValueError("lifecycle operation original differs")
            for cell in row[10:13]:
                json.loads(cell)
            return row[0],"d12_lifecycle_operation",row[1],row[1]
        if table == "authority_d12_lifecycle_receipts_v1":
            from .d12_lifecycle_contract_v1 import lifecycle_receipt_from_wire_v1
            receipt=lifecycle_receipt_from_wire_v1(json.loads(row[5]))
            if (receipt.authority_namespace,receipt.operation_id,receipt.stage,receipt.original_ref,receipt.original_digest)!=row[:5] or canonical_serialize(asdict(receipt))!=row[5]:
                raise ValueError("lifecycle receipt row differs")
            return row[0],"d12_lifecycle_receipt",row[3],row[1]
        if table == "authority_d12_lifecycle_bootstraps_v1":
            process=json.loads(row[5])
            if (set(process)!={"pid","platform","birth"} or type(process["pid"]) is not int or process["pid"]<1
                    or row[10]!="d12bootstrap:"+digest(row[:10])[7:] or row[11]!=digest(row[:11])):
                raise ValueError("lifecycle bootstrap original differs")
            return row[0],"d12_lifecycle_bootstrap",row[10],row[2]
        original = target_admission_from_wire_v1(json.loads(row[4]))
        if ((original.authority_namespace, original.target_installation_id,
             original.original_ref, original.original_digest) != row[:4]
                or canonical_serialize(original.to_wire()) != row[4]):
            raise ValueError("target Owner admission row identity differs")
        return original.authority_namespace, "d12_target_owner_admission", original.original_ref, original.transfer_id
    except (ValueError, TypeError, KeyError, UnicodeError, AttributeError) as exc:
        raise AuthorityUnavailable("C09 D12 Core original cannot be classified: " + table) from exc


__all__ = ("COLUMNS", "validate_d12_core_row_v1")
