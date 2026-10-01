"""Closed W09 views for the real compatible-package maintenance lane."""
from uuid import UUID
from ..authority_service.contract import AuthorityUnavailable
from ..authority_service.d12_package_maintenance_contract_v2 import package_intent_from_wire_v2,STAGES
from ..authority_service.d12_package_files_v2 import _sha
from ..runtime_contracts import NamespaceId
from ..graph_coordinator import namespace_ref

VIEW_SCHEMA='d12.compatible-package-operation-view.v2'


def decode_package_status_v2(raw,*,scope,operation_id=None):
    fields={'intent','stage','supervisor_receipt_digest','hold_code','lifecycle_state','executor_state'}
    if type(raw) is not dict or set(raw) not in (fields,fields|{'pending_stage'}):raise AuthorityUnavailable('exact installed package operation view required')
    intent=package_intent_from_wire_v2(raw['intent']);namespace=NamespaceId(*scope.split('/'))
    if (intent.namespace_cohort!=(namespace_ref(namespace),) or operation_id is not None and intent.operation_id!=operation_id
            or raw['stage'] not in STAGES or raw.get('pending_stage',raw['stage']) not in STAGES
            or raw['lifecycle_state'] not in {'active','quiescing','drained','resuming','paused'}
            or raw['executor_state'] not in {'awaiting_privileged_executor','original_stage_recorded','original_stage_pending'}
            or raw['supervisor_receipt_digest'] is not None and not _sha(raw['supervisor_receipt_digest'])
            or raw['hold_code'] is not None and (type(raw['hold_code']) is not str or not raw['hold_code'])):
        raise AuthorityUnavailable('package operation original scope/state differs')
    return intent,raw


def decode_package_profile_v2(raw,*,scope):
    fields={'schema','installation_id','namespace','current','lifecycle_epoch','lifecycle_state','candidates','execution_mode'}
    if (type(raw) is not dict or set(raw)!=fields or raw['schema']!='d12.package-maintenance-view.v2'
            or NamespaceId(**raw['namespace']).as_tuple!=tuple(scope.split('/'))
            or raw['lifecycle_state']!='active' or type(raw['lifecycle_epoch']) is not int or raw['lifecycle_epoch']<0
            or raw['execution_mode']!='privileged_operator_required' or type(raw['candidates']) is not list or len(raw['candidates'])>128):
        raise AuthorityUnavailable('exact installed package maintenance profile required')
    names={'cohort_ref','cohort_digest','release_ref','manifest_sha256','package_version'}
    current=raw['current']
    if type(current) is not dict or set(current)!=names|{'selection_digest','selection_revision','package_epoch'}:
        raise AuthorityUnavailable('current selected package profile differs')
    if (not _sha(current['selection_digest']) or any(type(current[k]) is not int or current[k]<0 for k in ('selection_revision','package_epoch'))):
        raise AuthorityUnavailable('current package selection revision/epoch differs')
    for row in (current,*raw['candidates']):
        if (type(row) is not dict or not names<=set(row) or any(type(row[k]) is not str or not row[k] for k in names)
                or not _sha(row['cohort_digest']) or not _sha(row['manifest_sha256'])):
            raise AuthorityUnavailable('registered package choice differs')
    if any(set(row)!=names for row in raw['candidates']) or len({r['cohort_ref'] for r in raw['candidates']})!=len(raw['candidates']):raise AuthorityUnavailable('registered package choice is ambiguous')
    return raw


def validate_package_input_v2(action,input_data,*,purpose,audience):
    if audience!='owner':raise ValueError('package maintenance requires Owner audience')
    if action=='accept_package_switch':
        if (purpose!='workbench_user_action' or set(input_data)!={'candidate_cohort_ref','expected_selection_digest','expected_lifecycle_epoch'}
                or type(input_data['candidate_cohort_ref']) is not str or not 1<=len(input_data['candidate_cohort_ref'])<=256
                or not _sha(input_data['expected_selection_digest']) or type(input_data['expected_lifecycle_epoch']) is not int or input_data['expected_lifecycle_epoch']<0):
            raise ValueError('package switch requires one registered cohort and exact current selection/lifecycle epoch')
    elif action=='read_package_operation':
        if purpose not in {'audit','workbench_view'} or set(input_data)!={'operation_id'}:raise ValueError('package status requires exact original operation')
        op=UUID(input_data['operation_id'])
        if op.version!=4 or str(op)!=input_data['operation_id']:raise ValueError('package status requires canonical original UUID4')
    elif action=='read_package_maintenance':
        if input_data or purpose not in {'audit','workbench_view'}:raise ValueError('package choices require current Owner view')
    else:raise ValueError('unknown package maintenance action')
