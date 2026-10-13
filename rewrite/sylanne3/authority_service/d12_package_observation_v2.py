"""Closed concrete supervisor observation codecs, not caller-provided readiness."""
from dataclasses import asdict, dataclass
from uuid import UUID
from .contract import AuthorityUnavailable
from .d12_installed_supervisor_v1 import D12SupervisorObservationV1
from .d12_package_files_v2 import PackageSelectionV2, decode_package_selection_v2, _digest, _sha
from ..runtime.lifecycle_operations_v1 import digest as prefixed_digest

SCHEMA='sylanne3.d12.supervisor-observation.v2'


def _validate_body(kind,body):
    if type(body) is not dict:raise AuthorityUnavailable('fixed supervisor observation body required')
    if kind=='process':
        if body.get('service_role') not in {'host','authority'}:
            raise AuthorityUnavailable('process observation scope differs')
        if set(body)=={'service_role','systemd','process_original'}:
            raw=body['systemd']
            if type(raw) is not dict or set(raw)!=set(D12SupervisorObservationV1.__dataclass_fields__):
                raise AuthorityUnavailable('actual systemd observation fields differ')
            fields=dict(raw);fields['process_ids']=tuple(fields['process_ids']);observed=D12SupervisorObservationV1(**fields)
            material=asdict(observed);material.pop('observation_digest')
            if (observed.observation_digest!=prefixed_digest(material) or type(observed.main_pid) is not int or observed.main_pid<0
                    or any(type(pid) is not int or pid<1 for pid in observed.process_ids)
                    or observed.process_ids!=tuple(sorted(set(observed.process_ids)))):
                raise AuthorityUnavailable('systemd observation commitment differs')
        elif set(body)=={'service_role','provider_kind','supervisor','process_original'}:
            from .installed_process_supervisor_v1 import KIND,decode_process_supervisor_observation_v2
            observed=decode_process_supervisor_observation_v2(body['supervisor'])
            if body['provider_kind']!=KIND or observed.service_role!=body['service_role'] or body['process_original']!=observed.main_process_original:
                raise AuthorityUnavailable('actual process provider role/birth differs')
        else:
            raise AuthorityUnavailable('closed concrete process observation fields differ')
        process=body['process_original']
        if observed.main_pid:
            if (type(process) is not dict or set(process)!={'pid','platform','birth'} or process['pid']!=observed.main_pid
                    or process['platform']!='linux' or type(process['birth']) is not str or not process['birth']
                    or observed.main_pid not in observed.process_ids):
                raise AuthorityUnavailable('process observation has no exact actual Linux birth')
        elif process is not None:
            raise AuthorityUnavailable('stopped MainPID has no current process birth')
    elif kind=='stage_failure_resolution':
        fields={'requested_stage','pending_intent_digest','failure_code','side_effect_state',
            'selection_observation_ref','selection_observation_digest','process_observation_refs'}
        if (set(body)!=fields or body['failure_code'] not in {'qualification_unavailable','process_not_qualified','source_changed'}
                or body['side_effect_state'] not in {'no_package_switch','candidate_selected_not_activated'}
                or type(body['requested_stage']) is not str or not body['requested_stage']
                or not _sha(body['pending_intent_digest']) or not _sha(body['selection_observation_digest'])
                or type(body['selection_observation_ref']) is not str
                or type(body['process_observation_refs']) not in (list,tuple) or len(body['process_observation_refs'])!=2
                or any(type(row) not in (list,tuple) or len(row)!=2 or type(row[0]) is not str or not _sha(row[1]) for row in body['process_observation_refs'])):
            raise AuthorityUnavailable('closed actual failed-stage resolution required')
    elif kind=='package_compatibility':
        from .d12_package_history_eligibility_v1 import decode_package_compatibility_original_v2
        decode_package_compatibility_original_v2(body)
    elif kind=='package_bootstrap':
        from .d12_package_bootstrap_v2 import decode_package_bootstrap_original_v2
        decode_package_bootstrap_original_v2(body)
    elif kind=='package_activation':
        from .d12_package_bootstrap_v2 import decode_package_activation_original_v2
        decode_package_activation_original_v2(body)
    elif kind=='registered_packages':
        from .d12_configuration_cohort_v2 import decode_configuration_cohort_v2
        if set(body)!={'selection','source','candidate'}:raise AuthorityUnavailable('closed package registration observation required')
        selection=decode_package_selection_v2(body['selection'])
        source=decode_configuration_cohort_v2(body['source']);candidate=decode_configuration_cohort_v2(body['candidate'])
        if (source.installation_id!=selection.installation_id or candidate.installation_id!=source.installation_id
                or source.cohort_digest!=selection.cohort_digest or source.cohort_ref!=selection.cohort_ref
                or source.package.manifest_sha256!=selection.manifest_sha256
                or source.identity_commitment!=candidate.identity_commitment
                or source.supervisor_policy_digest!=candidate.supervisor_policy_digest
                or source.compatibility_plan_ref!=candidate.compatibility_plan_ref):
            raise AuthorityUnavailable('registered package observation scopes differ')
    elif kind=='authority_admission':
        from ..runtime_contracts import canonical_digest
        fields={'schema','operation_id','accepted_original_digest','lifecycle_epoch','lifecycle_state',
            'current_storage_identity_digest','current_anchor_digest','live_fence_count','pending_mutation_count',
            'active_rpc_count','selection_digest','supervisor_policy_digest','observation_digest'}
        if set(body)!=fields or body['schema']!='d12.package-supervisor-admission.v2':
            raise AuthorityUnavailable('closed authenticated Authority admission required')
        material=dict(body);commitment=material.pop('observation_digest')
        if (canonical_digest(material)!=commitment or body['lifecycle_state'] not in {'quiescing','drained','resuming'}
                or any(not _sha(body[name]) for name in ('accepted_original_digest','current_storage_identity_digest',
                    'current_anchor_digest','selection_digest','supervisor_policy_digest','observation_digest'))
                or any(type(body[name]) is not int or body[name]<0 for name in ('lifecycle_epoch','live_fence_count','pending_mutation_count','active_rpc_count'))):
            raise AuthorityUnavailable('actual Authority admission commitment differs')
    elif kind=='backup_source':
        from .d12_managed_backup_v2 import decode_backup_source_v2
        decode_backup_source_v2(body)
    elif kind=='managed_backup':
        from .d12_managed_backup_v2 import decode_managed_backup_v2
        decode_managed_backup_v2(body)
    elif kind=='package_selection':
        decode_package_selection_v2(body)
    else:
        raise AuthorityUnavailable('unimplemented supervisor observation kind')


@dataclass(frozen=True,slots=True)
class PackageSupervisorObservationV2:
    operation_id: str
    kind: str
    body: dict
    observation_ref: str
    observation_digest: str
    schema: str = SCHEMA

    def __post_init__(self):
        operation=UUID(self.operation_id)
        if operation.version!=4 or str(operation)!=self.operation_id or self.schema!=SCHEMA:
            raise AuthorityUnavailable('exact operation-bound supervisor observation required')
        _validate_body(self.kind,self.body)
        material=asdict(self);material.pop('observation_digest');material.pop('observation_ref')
        if (not _sha(self.observation_digest) or self.observation_digest!=_digest(material)
                or self.observation_ref!='d12-supervisor-observation:'+self.observation_digest):
            raise AuthorityUnavailable('supervisor observation commitment differs')


def build_supervisor_observation_v2(*,operation_id,kind,body):
    material=dict(schema=SCHEMA,operation_id=operation_id,kind=kind,body=body)
    commitment=_digest(material)
    return PackageSupervisorObservationV2(**material,observation_digest=commitment,
        observation_ref='d12-supervisor-observation:'+commitment)


def decode_supervisor_observation_v2(raw):
    if type(raw) is not dict or set(raw)!=set(PackageSupervisorObservationV2.__dataclass_fields__):
        raise AuthorityUnavailable('closed supervisor observation original required')
    return PackageSupervisorObservationV2(**raw)
