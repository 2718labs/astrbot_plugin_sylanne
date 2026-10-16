"""Independent Core current permission and causal qualification for semantic children."""
from weakref import WeakSet

from .contract import AuthorityUnavailable
from .v2_contract import FencePermitV2
from .v2_self_identity_contract import SelfIdentityCurrentRequestV1
from .v2_self_identity_service import AuthorityV2SelfIdentityService
from .linux_clock_v1 import LinuxKernelClockProviderV1
from .conditioned_child_contract_v1 import (ConditionedChildSelectorV1,ConditionedChildEvidenceV1,
    conditioned_child_fence_operation_id_v1)
from ..host.authority_profile import AdminInstallationBundle
from ..runtime.issuers import D11BudgetJobIssuer

_SERVICES=WeakSet()


class InstalledCurrentConditionedChildV1:
    def __init__(self,*,self_identity_service,budget_issuer,clock_provider,installed_bundle):
        if(type(self_identity_service)is not AuthorityV2SelfIdentityService or type(budget_issuer)is not D11BudgetJobIssuer
                or type(clock_provider)is not LinuxKernelClockProviderV1 or type(installed_bundle)is not AdminInstallationBundle
                or self_identity_service._source_location is None or self_identity_service._owner_storage is None):
            raise TypeError('conditioned Core child requires actual Self/Owner/Source/budget/clock installation components')
        policy=installed_bundle.installation_policy
        owner=self_identity_service._owner_storage
        if(owner.core is not self_identity_service._core or owner.fences is not self_identity_service._fences
                or owner.namespace_id!=policy.namespace or owner.installation_id!=policy.installation_id
                or owner.graph_path!=self_identity_service._graph._path):
            raise ValueError('conditioned Core child crossed its actual installation, Owner or selected Graph')
        self.self_identity=self_identity_service
        self.issuer,self.clock_provider,self.installed_bundle=budget_issuer,clock_provider,installed_bundle
        self._core,self._fences,self._owner_storage=(owner.core,owner.fences,owner)
        self._source_location=self_identity_service._source_location
        self._graph=self_identity_service._graph
        self._path=owner.graph_path
        self._calls={}
        _SERVICES.add(self)

    def _clock(self):
        reading=self.clock_provider()
        return reading.utc_seconds+reading.utc_error_seconds

    def require_installed_v1(self):
        owner=self._owner_storage;identity=self.self_identity;policy=self.installed_bundle.installation_policy
        if(self not in _SERVICES or identity._core is not self._core or identity._fences is not self._fences
                or identity._owner_storage is not owner or identity._source_location is not self._source_location
                or owner.control is not self._source_location._control or owner.core._c09_storage_reader_v1 is not owner.control
                or self._path!=owner.graph_path or self._graph is not identity._graph
                or policy.namespace!=owner.namespace_id or policy.installation_id!=owner.installation_id):
            raise AuthorityUnavailable('conditioned Core child lost its actual installed identity')
        return self

    def current(self,*,credential,subject,permit,request):
        from .owner_location_read_v3 import (_owner_location_service_invocation_v3,
            prepare_owner_location_for_conditioned_child_v1)
        from .conditioned_child_source_v1 import prepare_conditioned_child_core_read_v1
        self.require_installed_v1();identity=self.self_identity;policy=self.installed_bundle.installation_policy
        if(type(request)is not ConditionedChildSelectorV1 or type(permit)is not FencePermitV2
                or request.namespace!=policy.namespace or request.installation_id!=policy.installation_id
                or permit.operation!='write'or permit.operation_id!=conditioned_child_fence_operation_id_v1(request)
                or permit.namespace!=policy.authority_namespace or subject!=identity._read_subject
                or permit.subject!=subject or permit.holder!=policy.administrator_holder
                or permit.operation_id in self._calls):
            raise AuthorityUnavailable('conditioned Core child requires its one exact installed current WRITE invocation')
        self._core._require(credential,'write',policy.authority_namespace,policy.administrator_holder)
        self._fences.validate_fence(credential=credential,subject=subject,permit=permit)
        if self._clock()>=request.original_deadline_utc:
            raise AuthorityUnavailable('conditioned child original absolute deadline expired')
        call=(credential,subject,permit,request)
        self._calls[permit.operation_id]=call
        work=None
        try:
            current=identity.current(credential=credential,subject=subject,
                request=SelfIdentityCurrentRequestV1(permit.authority_id,policy.authority_namespace,policy.namespace,
                    policy.installation_id,policy.manifest_digest,request.operation_id,permit))
            if current is None:raise AuthorityUnavailable('conditioned child actual independently registered Self is unavailable')
            with _owner_location_service_invocation_v3(self):
                owner_entry=prepare_owner_location_for_conditioned_child_v1(self,credential=credential,
                    subject=subject,permit=permit,request=request,current_self=current)
                work=prepare_conditioned_child_core_read_v1(self,credential=credential,subject=subject,
                    permit=permit,selector=request,current_self=current,owner_entry=owner_entry)
                evidence=work.read_current_evidence_v1()
                if(type(evidence)is not ConditionedChildEvidenceV1 or evidence.selector!=request
                        or evidence.current_self!=current):
                    raise AuthorityUnavailable('conditioned Core evidence changed its original current invocation')
                self._fences.validate_fence(credential=credential,subject=subject,permit=permit)
                if self._clock()>=evidence.valid_until_utc:
                    raise AuthorityUnavailable('conditioned child actual original permission expired during qualification')
                return evidence,permit
        finally:
            try:
                if work is not None:work.release_v1()
            finally:self._calls.pop(permit.operation_id,None)


def require_current_conditioned_core_call_v1(service,*,credential,subject,permit,selector):
    if(type(service)is not InstalledCurrentConditionedChildV1 or service.require_installed_v1()is not service
            or service._calls.get(permit.operation_id)!=(credential,subject,permit,selector)):
        raise AuthorityUnavailable('conditioned Core Source read has no actual current installed invocation')
    service._fences.validate_fence(credential=credential,subject=subject,permit=permit)
    if service._clock()>=selector.original_deadline_utc:
        raise AuthorityUnavailable('conditioned Core child original deadline expired')
    return service
