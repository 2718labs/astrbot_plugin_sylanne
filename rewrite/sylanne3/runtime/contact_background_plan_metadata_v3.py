"""Exact background Contact Plan metadata EOF, with no Source body or model authority."""
from dataclasses import dataclass
from weakref import WeakKeyDictionary
from ..authority_service.contract import AuthorityUnavailable
from ..runtime_contracts import NamespaceId

_ISSUER=object()
_WORKS=WeakKeyDictionary()

@dataclass(frozen=True,slots=True)
class ContactBackgroundPlanMetadataSelectorV3:
    namespace:NamespaceId
    contact_id:str
    def __post_init__(self):
        if type(self.namespace)is not NamespaceId or type(self.contact_id)is not str or not self.contact_id.startswith('contact:'):
            raise AuthorityUnavailable('Contact background Plan metadata has another fixed namespace/identity')

class ContactBackgroundPlanMetadataWorkV3:
    def __init__(self,issuer,parent,selector):
        from .domain_background_read_v3 import require_actual_background_attachment_owner_v3
        from .contact_graph_runtime_v2 import InstalledContactModelGraphRuntimeV2
        if issuer is not _ISSUER or type(selector)is not ContactBackgroundPlanMetadataSelectorV3:
            raise AuthorityUnavailable('background Contact Plan metadata requires its installed private factory')
        require_actual_background_attachment_owner_v3(parent,db=parent.db)
        service=parent.graph._GraphCoordinator__contact_model_runtime_v2
        if (type(service)is not InstalledContactModelGraphRuntimeV2 or service.bundle is not parent.bundle
                or parent.kind not in ('followup','followup_child') or parent.fence is None or parent.sealed
                or parent.read_scope is not parent.fence.scope or selector.namespace!=parent.namespace):
            raise AuthorityUnavailable('background Contact Plan metadata cannot borrow model/Host or an unobserved Scope')
        service._current()
        self.parent,self.service,self.request,self.contact_selector=parent,service,selector,selector
        self.db,self.namespace,self.scope,self.operation=parent.db,parent.namespace,parent.read_scope,parent.operation
        self.contact_issuer,self.contact_policy=service.issuer,None
        self.issued_capabilities=[]
        self.contact_locator=None
        _WORKS[self]=(parent,service,selector,self.db,self.namespace,self.scope,self.operation,parent.graph_stamp,parent.selection_digest)
    def _actual(self):
        from .domain_background_read_v3 import require_actual_background_attachment_owner_v3
        require_actual_background_attachment_owner_v3(self.parent,db=self.db)
        self.service._current()
        if _WORKS.get(self)!=(self.parent,self.service,self.request,self.db,self.namespace,self.scope,self.operation,
                self.parent.graph_stamp,self.parent.selection_digest):
            raise AuthorityUnavailable('background Contact Plan metadata lost its actual parent/selected storage/stamp')
        return self
    def require_current(self,*,meter):
        self._actual();self.parent.require_data_current_v3(meter)
        return self
    def release_v3(self):
        for registry,original in self.issued_capabilities:registry.pop(original,None)
        self.issued_capabilities.clear();_WORKS.pop(self,None)


def require_contact_background_plan_metadata_work_v3(work):
    if type(work)is not ContactBackgroundPlanMetadataWorkV3 or work not in _WORKS:
        raise AuthorityUnavailable('Contact metadata has no exact independently registered background Work')
    return work._actual()


def track_contact_background_plan_metadata_v3(work,registry,original):
    if type(work)is not ContactBackgroundPlanMetadataWorkV3:return False
    require_contact_background_plan_metadata_work_v3(work)
    work.operation.retain(128);work.issued_capabilities.append((registry,original))
    return True
