"""Closed C09/audit codecs for compatible-package Core records.

These readers check retained identity only. They never reopen admission or
qualify a package, supervisor receipt, backup or current Owner from copied rows.
"""
from dataclasses import asdict
import json
from ..runtime_contracts import NamespaceId,SnapshotRequirementsV2,canonical_digest,canonical_serialize
from ..runtime.restore_anchor import RestoreAnchor
from .contract import AuthorityUnavailable
from .d12_package_maintenance_contract_v2 import package_intent_from_wire_v2,STAGES
from .d12_package_files_v2 import decode_package_selection_v2
from .d12_target_owner_admission_v1 import D12CurrentOwnerAuthorityV1,target_admission_from_wire_v1,current_owner_authority_material_v1
from .v2_owner_contract import OwnerAuthorizationGuardV1
from .v2_owner_session import from_wire as session_from_wire,_canonical

COLUMNS={
'authority_d12_package_bootstraps_v2':('namespace','operation_id','service_role','package_epoch','original_ref','original_digest','original_json'),
'authority_d12_package_acceptances_v2':('namespace','operation_id','request_digest','intent_json','intent_digest','actor','session_request_json','owner_head','owner_observation_json','storage_identity_json','selection_json','acceptance_anchor_json'),
'authority_d12_package_heads_v2':('namespace','operation_id','intent_digest','lifecycle_epoch','stage','supervisor_receipt_digest','hold_code'),
'authority_d12_package_activations_v2':('namespace','operation_id','original_ref','original_digest','original_json'),
}


def _json(raw):
    value=json.loads(raw)
    if canonical_serialize(value)!=raw:raise AuthorityUnavailable('noncanonical package Core JSON')
    return value


def validate_d12_package_core_row_v2(table,columns,row):
    if table not in COLUMNS or tuple(columns)!=COLUMNS[table] or len(row)!=len(columns):raise AuthorityUnavailable('package Core row schema differs')
    if table=='authority_d12_package_acceptances_v2':
        intent=package_intent_from_wire_v2(_json(row[3]))
        request=session_from_wire({'kind':'owner_session_login_request_v1',**json.loads(row[6])})
        raw=_json(row[8]);expected={'authority','actor','public_session_request_json','grant_ref','grant_revision','grant_digest','graph_requirements_json','graph_revision','graph_epoch','observation_digest'}
        if set(raw)!=expected or set(raw['authority']) not in ({'guard','target_admission'},{'guard','target_admission','storage_admission'}):raise AuthorityUnavailable('package accepted Owner observation fields differ')
        guard=dict(raw['authority']['guard']);guard['namespace']=NamespaceId(**guard['namespace']);guard=OwnerAuthorizationGuardV1(**guard)
        admission=raw['authority']['target_admission'];storage_admission=raw['authority'].get('storage_admission')
        from .d12_owner_storage_admission_v1 import owner_storage_admission_from_wire_v1
        authority=D12CurrentOwnerAuthorityV1(guard,None if admission is None else target_admission_from_wire_v1(admission),None if storage_admission is None else owner_storage_admission_from_wire_v1(storage_admission))
        req=_json(raw['graph_requirements_json']);req['namespace']=NamespaceId(**req['namespace']);req=SnapshotRequirementsV2(**req)
        selection=decode_package_selection_v2(_json(row[10]));anchor=RestoreAnchor(**_json(row[11]));storage=_json(row[9])
        observation=canonical_digest((current_owner_authority_material_v1(authority),raw['actor'],raw['public_session_request_json'],raw['grant_ref'],raw['grant_revision'],raw['grant_digest'],raw['graph_requirements_json'],raw['graph_revision'],raw['graph_epoch']))
        if (row[:3]!=(anchor.namespace,intent.operation_id,intent.request_digest) or row[4]!=intent.digest
                or intent.namespace_cohort!=(row[0],) or intent.authority_id!=anchor.authority_id
                or request.authority_namespace!=row[0] or request.installation_id!=intent.installation_id
                or row[6]!=_canonical(request) or row[5]!=raw['actor'] or row[7]!=guard.authorization_head
                or raw['public_session_request_json']!=row[6].decode() or raw['observation_digest']!=observation
                or intent.current_owner_heads_digest!=observation or intent.current_storage_identity_digest!=canonical_digest(storage)
                or selection.selection_digest!=intent.expected_selection_digest or selection.revision!=intent.expected_selection_revision
                or selection.package_epoch!=intent.expected_package_epoch or selection.cohort_digest!=intent.old_cohort_digest
                or selection.cohort_ref!=intent.old_cohort_ref or selection.manifest_sha256!=intent.old_manifest_sha256
                or selection.release_ref!=intent.old_package_id or req.authority_namespace!=row[0]
                or req.authority_id!=anchor.authority_id or req.namespace!=guard.namespace
                or type(raw['graph_revision']) is not int or raw['graph_revision']<0
                or type(raw['graph_epoch']) is not int or raw['graph_epoch']<0):raise AuthorityUnavailable('package accepted Owner/storage/selection/namespace originals differ')
        return intent
    if table=='authority_d12_package_heads_v2':
        if (any(type(value) is not str or not value for value in row[:3]) or len(row[2])!=64
                or type(row[3]) is not int or row[3]<1 or row[4] not in STAGES
                or row[5] is not None and (type(row[5]) is not str or len(row[5])!=64)
                or row[6] is not None and (type(row[6]) is not str or not row[6])):raise AuthorityUnavailable('package durable head fields differ')
        return row
    if table=='authority_d12_package_bootstraps_v2':
        from .d12_package_bootstrap_v2 import decode_package_bootstrap_original_v2
        value=decode_package_bootstrap_original_v2(_json(row[6]))
        if row[:6]!=(value['namespace'],value['operation_id'],value['service_role'],value['package_epoch'],value['original_ref'],value['original_digest']):raise AuthorityUnavailable('package bootstrap row identity differs')
        return value
    from .d12_package_bootstrap_v2 import decode_package_activation_original_v2
    value=decode_package_activation_original_v2(_json(row[4]))
    if row[:4]!=(value['namespace'],value['operation_id'],value['original_ref'],value['original_digest']):raise AuthorityUnavailable('package activation row identity differs')
    return value
