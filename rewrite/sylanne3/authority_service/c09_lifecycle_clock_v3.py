"""Installed Authority clock originals for C09 Owner-output lifecycle decisions."""
from dataclasses import asdict
import math
from weakref import WeakSet
import threading
from .contract import AuthorityUnavailable
from .v2_clock import AuthorityClockReadingV2
from ..runtime_contracts import canonical_digest, namespace_ref
from ..runtime.c09_paged_sql_v2 import require_c09_reserved_meter_v3

_ISSUERS=WeakSet()
_OBSERVATIONS=WeakSet()
_TOKEN=object()
_SCHEMA='sylanne3.c09.owner-output-disposition-clock.v3'


def _installed_policy(config,namespace,namespace_id):
    authorities=config.natural_model_authorities_v2 or {}
    authority=authorities.get(namespace)
    if authority is None or config.clock_provider is None:
        raise AuthorityUnavailable('C09 output lifecycle requires its installed Authority clock policy')
    installation=config.installations_v2.get(authority.observer_peer)
    if (installation is None or not installation.source_id
            or config.namespace_bindings_v2.get((*authority.observer_peer,namespace_id))!=namespace):
        raise AuthorityUnavailable('C09 lifecycle clock observer/namespace installation differs')
    limits={}
    for value in authorities.values():
        installed=config.installations_v2[value.observer_peer]
        source=installed.source_id
        limits[source]=min(limits.get(source,installed.max_utc_error_seconds),installed.max_utc_error_seconds)
    limit=limits.get(installation.source_id)
    if limit is None:
        raise AuthorityUnavailable('C09 lifecycle clock has no installed source error policy')
    material={'authority_namespace':namespace,'observer_peer':list(authority.observer_peer),
        'installation_id':installation.installation_id,'source_id':installation.source_id,
        'maximum_utc_error_seconds':limit}
    return installation,limit,material


class InstalledC09LifecycleClockV3:
    def __init__(self,*,config,maintenance,namespace):
        from .deployment_config import AuthorityDeploymentConfig
        from .c09_storage_maintenance_v1 import InstalledC09MaintenanceV1
        if (type(config) is not AuthorityDeploymentConfig or type(maintenance) is not InstalledC09MaintenanceV1
                or maintenance._installed_deployment_config_v2 is not config
                or namespace_ref(maintenance.namespace_id)!=namespace):
            raise AuthorityUnavailable('actual installed C09 clock composition required')
        self.config,self.maintenance,self.namespace=config,maintenance,namespace
        _ISSUERS.add(self)

    def _binding(self,session,prepared_metadata,meter):
        from .c09_paged_capture_control_v2 import C09PagedCaptureSessionV2
        from .c09_source_physical_read_v3 import VerifiedSourceOwnerPreparedMetadataV3
        m=self.maintenance
        if (self not in _ISSUERS or type(session) is not C09PagedCaptureSessionV2
                or type(prepared_metadata) is not VerifiedSourceOwnerPreparedMetadataV3
                or session._control.maintenance is not m
                or prepared_metadata.scope.session is not session or prepared_metadata.scope.role!='graph'
                or m._installed_deployment_config_v2 is not self.config
                or require_c09_reserved_meter_v3(meter.budget) is not meter):
            raise AuthorityUnavailable('C09 clock observation crossed its actual Source/root/session')
        session._control._registered()
        session.require_current()
        prepared_metadata.require_current(meter=meter)
        actor=m._maintenance_actor_v3
        if actor.owner_thread!=threading.get_ident() or actor.operation_id!=session.scope.operation_id:
            raise AuthorityUnavailable('C09 lifecycle clock requires the actual maintenance actor/thread')
        installation,limit,policy=_installed_policy(self.config,self.namespace,m.namespace_id)
        if (installation.installation_id!=m.control.installation_id
                or session.scope.authority_id!=m.control.authority_id
                or session.scope.authority_namespace!=self.namespace):
            raise AuthorityUnavailable('C09 clock policy crossed installed Authority identity')
        return installation,limit,policy

    def issue_owner_output_disposition_clock_v3(self,*,session,prepared_metadata,meter):
        installation,limit,policy=self._binding(session,prepared_metadata,meter)
        reading=self.config.clock_provider()
        if (type(reading) is not AuthorityClockReadingV2 or not reading.healthy
                or reading.source_id!=installation.source_id or reading.utc_error_seconds>limit):
            raise AuthorityUnavailable('C09 installed Authority clock source/health/error differs')
        encoded_deadline=prepared_metadata.metadata['original_deadline_utc']
        if (type(encoded_deadline) not in (int,float) or not math.isfinite(encoded_deadline)
                or encoded_deadline<=0):
            raise AuthorityUnavailable('C09 output original deadline requires its finite UTC seconds')
        deadline=encoded_deadline
        details={'schema':_SCHEMA,'scope_digest':session.scope.scope_digest,
            'maintenance_operation_id':session.scope.operation_id,
            'prepared_digest':prepared_metadata.prepared_digest,
            'prepared_values_digest':canonical_digest(tuple(prepared_metadata.row)),
            'old_manifest_digest':session.scope.old_manifest_digest,
            'expected_pointer_version':session.scope.expected_pointer_version,
            'graph_role_source_digest':prepared_metadata.scope.source_original.role_source_digest,
            'authority_id':session.scope.authority_id,'installation_id':session.scope.installation_id,
            'authority_namespace':self.namespace,'observer_peer':policy['observer_peer'],
            'installed_policy_digest':canonical_digest(policy),'reading':asdict(reading),
            'original_deadline_utc':encoded_deadline}
        kind='capture_owner_output_clock_v3:'+canonical_digest(details)
        original=self.maintenance.control.record_build_original_v1(
            operation_id=session.scope.operation_id,kind=kind,details=details)
        self._binding(session,prepared_metadata,meter)
        return VerifiedC09OwnerOutputClockV3(_TOKEN,self,session,prepared_metadata,meter,policy,reading,deadline,kind,original)


class VerifiedC09OwnerOutputClockV3:
    def __init__(self,token,issuer,session,prepared_metadata,meter,policy,reading,deadline,kind,original):
        if token is not _TOKEN or issuer not in _ISSUERS:
            raise AuthorityUnavailable('actual installed C09 clock issuer required')
        self.issuer,self.session,self.prepared_metadata,self.meter=issuer,session,prepared_metadata,meter
        self.policy,self.reading,self.deadline,self.kind,self.original=policy,reading,deadline,kind,original
        self.provider=issuer.config.clock_provider
        details=original['details']
        if (details['reading']!=asdict(reading) or details['original_deadline_utc']!=deadline
                or details['installed_policy_digest']!=canonical_digest(policy)):
            raise AuthorityUnavailable('C09 clock capability differs from its actual signed values')
        _OBSERVATIONS.add(self)

    @property
    def lower_seconds(self):
        return self.reading.utc_seconds-self.reading.utc_error_seconds

    @property
    def upper_seconds(self):
        return self.reading.utc_seconds+self.reading.utc_error_seconds

    @property
    def deadline_seconds(self):
        return self.deadline

    @property
    def expires_status(self):
        if self.upper_seconds<self.deadline_seconds:return 'alive'
        if self.lower_seconds>=self.deadline_seconds:return 'expired'
        return 'ambiguous'

    def require_current(self,*,session,prepared_metadata,meter):
        if (self not in _OBSERVATIONS or self.session is not session
                or self.prepared_metadata is not prepared_metadata or self.meter is not meter
                or self.provider is not self.issuer.config.clock_provider):
            raise AuthorityUnavailable('C09 lifecycle clock is outside its actual issuing quantum')
        _,_,policy=self.issuer._binding(session,prepared_metadata,meter)
        if policy!=self.policy:
            raise AuthorityUnavailable('C09 installed lifecycle clock policy changed')
        actual=self.issuer.maintenance.control.read_build_original_v1(
            operation_id=session.scope.operation_id,kind=self.kind)
        if (actual!=self.original or actual['details']['reading']!=asdict(self.reading)
                or actual['details']['original_deadline_utc']!=self.deadline
                or actual['details']['installed_policy_digest']!=canonical_digest(self.policy)):
            raise AuthorityUnavailable('actual signed C09 lifecycle clock original or derived values changed')
        return self
