"""Initial Contact Source closure from its authenticated causal request, before Plan birth."""
from contextlib import ExitStack,contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from types import MappingProxyType
from weakref import WeakKeyDictionary
from ..authority_service.contract import AuthorityUnavailable
from ..authority_service.current_authority_graph_read_v3 import _AuthoritySourceMaterialReadV3
from ..graph_types import AtomKey,GraphAtom,GraphVersion
from ..runtime_contracts import NamespaceId,canonical_digest
from ..runtime_storage_v3 import runtime_storage_quantum_v3
from .dispatch_current_inventory_v3 import _CurrentNamespaceInventoryKernelV3

_ISSUER=object()
_WORKS=WeakKeyDictionary()
_MATERIALS=WeakKeyDictionary()
_WRITE=ContextVar('initial_contact_source_fresh_write_v3',default=None)

@dataclass(frozen=True,slots=True)
class InitialContactPlanSelectorV3:
    namespace:NamespaceId
    dedupe_key:str
    causal_operation_id:str
    causal_original_digest:str
    opportunity_ref:str
    policy_ref:str
    route_ref:str
    audience:str
    def __post_init__(self):
        if type(self.namespace)is not NamespaceId or not all(type(x)is str and x for x in
                (self.dedupe_key,self.causal_operation_id,self.causal_original_digest,self.opportunity_ref,self.policy_ref,self.route_ref,self.audience)):
            raise AuthorityUnavailable('initial Contact requires its exact authenticated causal metadata')
        for ref,kind in ((self.opportunity_ref,'d10.proactive_opportunity.v1'),(self.policy_ref,'d10.contact_policy.v1'),(self.route_ref,'d03.account_binding')):
            key=AtomKey.from_token(ref)
            if NamespaceId.from_key(key)!=self.namespace or key.type_name!=kind:
                raise AuthorityUnavailable('initial Contact locator crossed its fixed family or namespace')


def require_initial_contact_source_work_v3(work):
    if type(work)is not InitialContactPlanSourceReadV3 or _WORKS.get(work)!=work._identity_v3():
        raise AuthorityUnavailable('initial Contact Source has no actual installed parent Work')
    work.require_actual_v3()
    return work

class InitialContactPlanProjectionV3:
    def __init__(self,issuer,work):
        if issuer is not _ISSUER or not work.graph_eof:
            raise AuthorityUnavailable('initial Contact projection requires complete metadata census EOF')
        self.work,self.epochs=work,(work.graph_stamp[1],)
    @property
    def atoms(self):
        w=require_initial_contact_source_work_v3(self.work)
        records={} if w.source_material is None else w.source_material.source_records
        return (*w.atoms,*(self.get(AtomKey.from_token(ref))for ref in sorted(records)))
    @property
    def versions(self):
        return tuple(GraphVersion(atom.key,atom.revision)for atom in self.atoms)
    def get(self,key):
        w=require_initial_contact_source_work_v3(self.work)
        if NamespaceId.from_key(key)!=w.namespace:
            raise AuthorityUnavailable('initial Contact projection crossed namespace')
        if key.type_name=='memory.source':
            material=w.source_material
            if material is None or key.token not in material.source_records:
                raise AuthorityUnavailable('initial Contact protected body is outside its qualified two-purpose closure')
            return GraphAtom(key,material.witnesses[key.token].revision,material.source_records[key.token].to_dict(),True)
        atom=next((a for a in w.atoms if a.key==key),None)
        return atom if atom is not None else GraphAtom(key,0,{},False)

class InitialContactSourceMetadataV3:
    def __init__(self,issuer,work,original):
        from .dispatch_current_inventory_v3 import VerifiedDispatchSourceMetadataV3,_SOURCE_ISSUED
        if issuer is not _ISSUER or type(original)is not VerifiedDispatchSourceMetadataV3:
            raise AuthorityUnavailable('initial Contact metadata requires actual physical full EOF')
        require_initial_contact_source_work_v3(work)
        self.work,self.original=work,original
        for name in ('source_key','revision','valid','cell_id','header','payload_sha256','metadata'):
            setattr(self,name,getattr(original,name))
        self.identity=(work.db,self.source_key,self.revision,self.valid,self.cell_id,self.header,self.payload_sha256,
            self.metadata,work.scope,work.graph_stamp,work.query,work.operation.operation_id,work.selection_digest)
        if _SOURCE_ISSUED.get(original)!=self.identity:
            raise AuthorityUnavailable('initial Contact metadata differs from the actual Source census issuer')
    def require_current_v3(self):
        from .dispatch_current_inventory_v3 import _SOURCE_ISSUED
        w=require_initial_contact_source_work_v3(self.work)
        w.require_current_v3()
        if _SOURCE_ISSUED.get(self.original)!=self.identity:
            raise AuthorityUnavailable('initial Contact Source metadata lost its complete same-Work EOF')
        return self

class _InitialContactPurposeSelectionV3:
    def __init__(self,issuer,work,purpose):
        if issuer is not _ISSUER or purpose not in ('expression','context'):
            raise AuthorityUnavailable('initial Contact accepts only its two distinct actual purpose groups')
        require_initial_contact_source_work_v3(work)
        self.work,self.purpose=work,purpose
        self.roots=work.purpose_roots[purpose]
        self.root,self.audience=self.roots[0],work.selector.audience
        self.attention,self.maximum_ancestors=None,256
        self.identity=(work,work.selector,work.scope,work.operation,purpose,self.roots,self.audience,work.metadata_commitment)
    def require_v3(self,work):
        require_initial_contact_source_work_v3(work)
        if work is not self.work or self.identity!=(work,work.selector,work.scope,work.operation,self.purpose,
                work.purpose_roots[self.purpose],self.audience,work.metadata_commitment):
            raise AuthorityUnavailable('initial Contact Source selection changed its actual causal purpose roots')
        return self

class _InitialContactPurposeReadV3(_AuthoritySourceMaterialReadV3):
    def __init__(self,work,purpose):
        self.selection=_InitialContactPurposeSelectionV3(_ISSUER,work,purpose)
        super().__init__(work,self.selection)
    def _body_refs_v3(self):
        return tuple(sorted(self.witnesses))
    def _seal_material_v3(self):
        # Both purpose closures finish independently before the union is issued.
        return self

class PreparedInitialContactPlanSourceMaterialV3:
    def __init__(self,issuer,work):
        if issuer is not _ISSUER or any(not reader.complete for reader in work.purpose_readers.values()):
            raise AuthorityUnavailable('initial Contact material requires both actual complete rights/body EOFs')
        require_initial_contact_source_work_v3(work)
        self.work,self.namespace,self.scope,self.operation=work,work.namespace,work.scope,work.operation
        records,witnesses,purposes={}, {}, {}
        for purpose,reader in work.purpose_readers.items():
            reader.selection.require_v3(work)
            for ref,record in reader.records.items():
                if ref in records and records[ref]!=record:
                    raise AuthorityUnavailable('initial Contact two-purpose body EOF differs for the same actual Source')
                records[ref],witnesses[ref]=record,reader.witnesses[ref]
                purposes.setdefault(ref,set()).add(purpose)
        self.source_records,self.witnesses=MappingProxyType(records),MappingProxyType(witnesses)
        self.purposes=MappingProxyType({ref:frozenset(values)for ref,values in purposes.items()})
        self.audiences=(work.selector.audience,)
        self.rights_versions=tuple(sorted(set(v for r in work.purpose_readers.values()for v in r.versions),key=lambda v:v.key.token))
        _MATERIALS[self]=(work,self.scope,self.operation,self.source_records,self.witnesses,self.purposes,self.rights_versions)
    def require_current(self,*,db,prepared_full_read,namespace,source_ref,audiences,purpose='expression'):
        w=require_initial_contact_source_work_v3(self.work)
        if (_MATERIALS.get(self)!=(w,self.scope,self.operation,self.source_records,self.witnesses,self.purposes,self.rights_versions)
                or db is not w.db or not db.in_transaction or namespace!=self.namespace
                or tuple(audiences)!=self.audiences or purpose not in self.purposes.get(source_ref,())
                or prepared_full_read is not None or w.source_material is not self):
            raise AuthorityUnavailable('initial Contact material cannot promote context to expression or borrow another actual Scope')
        if w.parent.sealed:
            binding=_WRITE.get()
            if binding is None or binding[0]is not w:
                raise AuthorityUnavailable('initial Contact retained Source requires its independently observed fresh WRITE')
            w.parent.require_write_data_v3(db,binding[1],binding[3])
        w.require_current_v3()
        for witness in self.witnesses.values():witness.require_current_v3()
        return self
    def source_record_for_v3(self,**kwargs):
        self.require_current(**kwargs)
        return self.source_records[kwargs['source_ref']]
    def source_family_for_v3(self,*,db,prepared_full_read,namespace,source_ref,audiences):
        self.require_current(db=db,prepared_full_read=prepared_full_read,namespace=namespace,source_ref=source_ref,audiences=audiences)
        from ..memory_types import source_key
        reader=self.work.purpose_readers['expression']
        pending,lineage,seen=[source_ref],[],set()
        while pending:
            ref=pending.pop()
            if ref in seen:continue
            if ref not in reader.records:
                raise AuthorityUnavailable('D06 expression ancestry escaped its independently qualified purpose group')
            seen.add(ref);lineage.append(ref)
            pending.extend(source_key(*namespace.as_tuple,parent).token for parent in reader.records[ref].parent_source_ids)
        keys=set(lineage)
        from ..memory_types import access_key
        from ..domains.d06 import source_correction_head_key
        for ref in lineage:
            key=AtomKey.from_token(ref)
            keys.update((access_key(*namespace.as_tuple,key.owner.subject).token,source_correction_head_key(namespace,key.owner.subject).token))
        return tuple(lineage),tuple(v for v in self.rights_versions if v.key.token in keys)

class InitialContactPlanSourceReadV3(_CurrentNamespaceInventoryKernelV3):
    def __init__(self,issuer,parent,selector):
        from .domain_background_read_v3 import require_actual_background_attachment_owner_v3
        from .contact_graph_runtime_v2 import InstalledContactModelGraphRuntimeV2
        if issuer is not _ISSUER or type(selector)is not InitialContactPlanSelectorV3:
            raise AuthorityUnavailable('initial Contact Source needs its private authenticated producer')
        require_actual_background_attachment_owner_v3(parent,db=parent.db)
        service=parent.graph._GraphCoordinator__contact_model_runtime_v2
        if (type(service)is not InstalledContactModelGraphRuntimeV2 or service.bundle is not parent.bundle
                or parent.kind not in ('followup','followup_child') or parent.sealed or parent.fence is None
                or parent.read_scope is not parent.fence.scope or parent.dedupe_key!=selector.dedupe_key
                or parent.namespace!=selector.namespace or parent.authority.purpose!='expression'
                or tuple(parent.authority.audience)!=(selector.audience,)):
            raise AuthorityUnavailable('initial Contact Source cannot borrow Plan, Model, C02 or another causal Scope')
        service._current()
        self.parent,self.selector,self.service=parent,selector,service
        self.graph,self.store,self.db,self.namespace=parent.graph,parent.store,parent.db,parent.namespace
        self.operation,self.work,self.handle=parent.operation,parent.work,parent.operation.handle
        self.fence,self.scope,self.graph_stamp,self.selection_digest=parent.fence,parent.read_scope,parent.graph_stamp,parent.selection_digest
        self.owner,self.owner_guard,self.authority=parent.owner,parent.owner_guard,parent.authority
        self.phase,self.complete,self.closed='namespace',False,False
        self.atoms,self.heads,self.sources=[],{},{}
        self.source_material,self.projection,self.policy_lifetime,self.current_policy=None,None,None,None
        self.purpose_readers,self.purpose_roots={},{}
        _WORKS[self]=self._identity_v3()
        from .contact_product_adapter_v1 import CONTACT_CURRENT_TYPES
        self._initialize_storage_kernel_v3(self.operation,self.fence,namespace=self.namespace,graph_stamp=self.graph_stamp,
            catalogue_hash=self.store._registry.catalogue_hash,projection_types=frozenset((*CONTACT_CURRENT_TYPES,'d03.world_event','memory.access','d06.source_correction_head.v1','d11.owner_grant.v1')),
            selected_tokens=frozenset(),census_schema='sylanne.contact-initial-current-census.v3',
            leaf_schema='sylanne.contact-initial-current-census-leaf.v3')
    def _identity_v3(self):
        return (self.parent,self.selector,self.service,self.operation,self.scope,self.graph_stamp,self.selection_digest)
    def require_actual_v3(self):
        from .domain_background_read_v3 import require_actual_background_attachment_owner_v3
        require_actual_background_attachment_owner_v3(self.parent,db=self.db)
        self.service._current()
        if self.closed or _WORKS.get(self)!=self._identity_v3():
            raise AuthorityUnavailable('initial Contact Source lost its actual installed operation')
        return self
    def require_current(self,*,meter):
        self.require_actual_v3();self.parent.require_data_current_v3(meter)
        return self
    def require_current_v3(self):
        if not self.db.in_transaction:
            raise AuthorityUnavailable('initial Contact Source requires its real Graph quantum')
        with runtime_storage_quantum_v3(self.db)as meter:self.require_current(meter=meter)
    def _next(self,meter):
        super()._next(meter)
        if self.pending is not None:
            key,revision,valid,kind,cell=self.pending
            self.heads[key.token]=(revision,valid,cell)
    def _graph_eof_v3(self):
        self.sources={ref:InitialContactSourceMetadataV3(_ISSUER,self,value)for ref,value in self.sources.items()}
        self.projection=InitialContactPlanProjectionV3(_ISSUER,self)
        self._derive_roots_v3()
    def _derive_roots_v3(self):
        from ..domains.d05.relationship import BoundaryRule,_tuple_payload
        selector=self.selector
        def required(ref):
            atom=self.projection.get(AtomKey.from_token(ref))
            if not atom.valid or atom.revision<1:
                raise AuthorityUnavailable('initial Contact actual metadata locator is absent or invalid')
            return atom
        opportunity=required(selector.opportunity_ref)
        policy=required(selector.policy_ref)
        account=required(selector.route_ref)
        evidence=required(account.value['verification_ref'])
        if (account.value['entity_id']!=opportunity.value['subject_ref'] or evidence.key.type_name!='d03.world_event'
                or evidence.value['kind']!='message_received' or evidence.value['reality']!='host_observed'
                or len(evidence.value['source_refs'])!=1):
            raise AuthorityUnavailable('initial Contact route metadata has no exact original private WorldEvent')
        expression={opportunity.value['source_ref']}
        for atom in self.atoms:
            if atom.key.type_name=='d05.boundary_rule' and atom.valid and atom.value['target_entity_ref']==opportunity.value['subject_ref']:
                rule=BoundaryRule(**_tuple_payload(atom.value,'source_refs','communicated_refs','acknowledged_refs','exception_refs'))
                expression.update(rule.source_refs)
        self.purpose_roots={'expression':tuple(sorted(expression)),'context':tuple(evidence.value['source_refs'])}
        if len(expression)>256:
            raise AuthorityUnavailable('initial Contact expression roots exceed their original finite closure')
        for refs in self.purpose_roots.values():
            for ref in refs:
                key=AtomKey.from_token(ref)
                if NamespaceId.from_key(key)!=self.namespace or key.type_name!='memory.source':
                    raise AuthorityUnavailable('initial Contact roots escaped authenticated metadata Source family')
        self.policy_atom,self.opportunity_atom=policy,opportunity
        self.metadata_commitment=canonical_digest((selector,tuple((atom.key.token,atom.revision,atom.valid)for atom in self.atoms),self.purpose_roots))
    def observe_current_v3(self):
        from .domain_followup_consumer_v1 import _observe_owner
        from .d10_contact_policy_authority_v1 import read_installed_current_contact_policy_v1
        from .first_ingress_v2 import trusted_upper
        if self.db.in_transaction:
            raise AuthorityUnavailable('initial Contact Owner/policy observation cannot wait inside Graph SQL')
        self.graph._validate_read_fence_v3(self.fence)
        if _observe_owner(self.graph,self.authority,self.scope)!=(self.owner_guard,self.owner):
            raise AuthorityUnavailable('initial Contact authenticated actor/Owner changed')
        if self.policy_lifetime is not None:self.policy_lifetime.close()
        lifetime=ExitStack()
        current=lifetime.enter_context(read_installed_current_contact_policy_v1(
            self.graph._GraphCoordinator__c04_authority_port_v3,self.scope,self.policy_atom.value['policy_id']))
        if (current.original.original_ref!=self.policy_atom.value['approval_ref']
                or self.current_policy is not None and current.original.digest!=self.current_policy.original.digest):
            lifetime.close()
            raise AuthorityUnavailable('initial Contact standing policy differs from its actual current Graph original')
        now=trusted_upper(self.service.port.read_ingress_clock(self.service.bundle.ingress_clock))
        deadline=min(self.operation.deadline_utc,self.opportunity_atom.value['expires_at'],current.original.policy.window_end,
            self.service.bundle.installation_policy.root_grant.valid_until_utc)
        if now>=deadline:
            lifetime.close()
            raise AuthorityUnavailable('initial Contact original grant/cause/deadline expired')
        self.operation.deadline_utc=self.work.deadline_utc=float(deadline)
        self.policy_lifetime,self.current_policy=lifetime,current
    def advance(self,meter):
        self.require_current(meter=meter)
        if self.phase=='namespace':
            if self.authority_epochs is None:self.authority_epochs=self._epochs(meter)
            if self.cell is None:self._next(meter)
            else:self._cell(meter)
            if self.graph_eof:self.phase='policy'
        elif self.phase=='source':
            for purpose in ('expression','context'):
                reader=self.purpose_readers.get(purpose)
                if reader is None:
                    reader=_InitialContactPurposeReadV3(self,purpose);self.purpose_readers[purpose]=reader
                if not reader.complete:
                    reader.advance_v3(meter);return
            self.source_material=PreparedInitialContactPlanSourceMaterialV3(_ISSUER,self)
            self.phase='protected'
        else:
            raise AuthorityUnavailable('initial Contact phase needs its actual outside-SQL observer')
    def release_payload_v3(self):
        if self.policy_lifetime is not None:self.policy_lifetime.close()
        if self.source_material is not None:_MATERIALS.pop(self.source_material,None)
        from .dispatch_current_inventory_v3 import _SOURCE_ISSUED
        for witness in self.sources.values():_SOURCE_ISSUED.pop(witness.original,None)
        self.atoms,self.heads,self.sources=[],{},{}
        self.purpose_readers.clear();self.source_material=self.projection=None
        self.closed=True;_WORKS.pop(self,None)


def require_initial_contact_plan_source_v3(parent,event,original):
    from .domain_background_read_v3 import BackgroundReadNeededV3
    if event.event_kind!='qualified_contact_opportunity_requires_action':return None
    request=original['payload']['request'];audiences=tuple(original['payload']['authority']['audience'])
    if len(audiences)!=1 or original['receipt'].operation_id!=event.causal_operation_id:
        raise AuthorityUnavailable('initial Contact Source requires its exact authenticated causal adoption/audience')
    selector=InitialContactPlanSelectorV3(parent.namespace,event.dedupe_key,event.causal_operation_id,
        original['original_digest'],request['opportunity_ref'],request['contact_policy_ref'],request['target_route_ref'],audiences[0])
    component=parent.contact_initial_component
    if component is None or not component.complete:
        if parent.sealed:raise AuthorityUnavailable('initial Contact Source was not qualified before READ sealed')
        raise BackgroundReadNeededV3(('contact_initial_source',selector))
    if component.selector!=selector:
        raise AuthorityUnavailable('initial Contact cause/request changed after complete Source EOF')
    return require_initial_contact_source_work_v3(component)


def require_initial_contact_expression_projection_v3(material,*,db,prepared,namespace,source_ref,audiences):
    if type(material)is not PreparedInitialContactPlanSourceMaterialV3:
        raise AuthorityUnavailable('D06 initial Contact needs its actual independent Source producer')
    material.require_current(db=db,prepared_full_read=prepared,namespace=namespace,source_ref=source_ref,audiences=audiences)
    return material.work.projection


def initial_contact_expression_kwargs_v3(db):
    from .domain_background_read_v3 import _active_v3
    parent=_active_v3(db)
    if parent is None or parent.contact_initial_component is None:return None
    work=require_initial_contact_source_work_v3(parent.contact_initial_component)
    if not work.complete or work.source_material is None:
        raise AuthorityUnavailable('initial Contact D06 material has not completed both actual purpose EOFs')
    return {'prepared_source_material':work.source_material,'prepared_full_read':None,'db':db}


@contextmanager
def bind_initial_contact_fresh_write_v3(runtime,*,authority,operation_kind,request,operation_id,request_digest,scope,guard,owner):
    from .domain_background_read_v3 import _active_v3
    from .domain_followup_consumer_v1 import _observe_owner
    from .d10_contact_policy_authority_v1 import read_installed_current_contact_policy_v1
    parent=_active_v3(runtime.graph._GraphCoordinator__store._db)
    if parent is None or parent.contact_initial_component is None or operation_kind!='adopt_contact_expression_plan_v2':
        yield None;return
    work=require_initial_contact_source_work_v3(parent.contact_initial_component)
    command=parent.local_result[6]
    if (not parent.sealed or parent.kind!='followup_child' or not work.complete or command is None
            or (command.operation_kind,command.request,command.operation_id)!=(operation_kind,request,operation_id)
            or (request.opportunity_ref,request.contact_policy_ref,request.target_route_ref)!=(work.selector.opportunity_ref,work.selector.policy_ref,work.selector.route_ref)
            or scope is work.scope or scope.operation!='write' or scope.namespace!=work.namespace
            or authority.actor!=work.authority.actor or authority.purpose!='expression' or tuple(authority.audience)!=(work.selector.audience,)
            or guard!=work.owner_guard or owner.principal!=work.owner.principal or work.db.in_transaction):
        raise AuthorityUnavailable('initial Contact cannot use sealed READ as fresh WRITE or change original child/cause/grant')
    if work.service.port.validate_fence(scope)!=scope.permit or _observe_owner(work.graph,authority,scope)!=(guard,owner):
        raise AuthorityUnavailable('initial Contact fresh WRITE lacks its real current Owner/fence')
    with read_installed_current_contact_policy_v1(work.graph._GraphCoordinator__c04_authority_port_v3,scope,
            work.policy_atom.value['policy_id'])as current:
        if current.original.digest!=work.current_policy.original.digest:
            raise AuthorityUnavailable('initial Contact current policy changed before WRITE')
        binding=(work,scope,guard,owner,authority,command,request_digest,current)
        token=_WRITE.set(binding)
        try:yield binding
        finally:_WRITE.reset(token)
    work.service.port.validate_fence(scope)


def initial_contact_followup_read_plan_v3(db,namespace,event,original):
    from .domain_background_read_v3 import _active_v3
    from .d01_production_operations_v1 import production_read_plan_v1
    from .contact_product_adapter_v1 import CONTACT_CURRENT_TYPES
    from ..graph_types import owner_grant_key
    parent=_active_v3(db)
    if parent is None or parent.contact_initial_component is None:return None
    work=require_initial_contact_plan_source_v3(parent,event,original)
    if work is None:return None
    required=(work.selector.opportunity_ref,work.selector.policy_ref,work.selector.route_ref,
        work.projection.get(AtomKey.from_token(work.selector.route_ref)).value['verification_ref'])
    keys=[owner_grant_key(*namespace.as_tuple),*(AtomKey.from_token(ref)for ref in required)]
    keys.extend(v.key for v in original['receipt'].write_versions if v.key.type_name!='memory.source')
    return production_read_plan_v1(CONTACT_CURRENT_TYPES,keys,
        tuple(sorted(set(ref for refs in work.purpose_roots.values()for ref in refs))),
        (event.trigger_original.original_ref,))


def initial_contact_plan_read_roots_v3(db,namespace,request):
    from .domain_background_read_v3 import _active_v3
    parent=_active_v3(db)
    if parent is None or parent.contact_initial_component is None:return None
    work=require_initial_contact_source_work_v3(parent.contact_initial_component)
    if (not work.complete or work.namespace!=namespace or (request.opportunity_ref,request.contact_policy_ref,request.target_route_ref)
            !=(work.selector.opportunity_ref,work.selector.policy_ref,work.selector.route_ref)):
        raise AuthorityUnavailable('initial Contact read plan changed its exact original qualified metadata roots')
    return tuple(sorted(set(ref for refs in work.purpose_roots.values()for ref in refs)))


def initial_contact_source_barrier_v3(db,namespace,query,source_refs,dependent_ref):
    from .domain_background_read_v3 import _active_v3
    from .dispatch_source_correction_barrier import CorrectionBarrierReadV1
    from ..domains.d06 import source_correction_head_key
    parent=_active_v3(db)
    if parent is None or parent.contact_initial_component is None:return None
    work=require_initial_contact_source_work_v3(parent.contact_initial_component)
    if namespace!=work.namespace or query!=work.query or not work.complete or work.source_material is None:
        raise AuthorityUnavailable('initial Contact correction barrier lacks its actual current two-purpose material')
    missing=[]
    for ref in source_refs:
        witness=work.source_material.witnesses.get(ref)
        if witness is None or not witness.valid or witness.revision<1:
            missing.append('current_source_unavailable:'+dependent_ref);continue
        witness.require_current_v3()
        key=AtomKey.from_token(ref)
        head=work.projection.get(source_correction_head_key(namespace,key.owner.subject))
        if head.valid or head.revision!=0:missing.append('source_pending_reevaluation:'+dependent_ref)
    return CorrectionBarrierReadV1(tuple(dict.fromkeys(missing)))


def initial_contact_source_commitment_v3(db,frame,atom):
    from .domain_background_read_v3 import _active_v3
    from ..domains.d08.contact_plan_v3 import ContactReadCommitmentV3
    parent=_active_v3(db)
    if parent is None or parent.contact_initial_component is None:return None
    if atom.key.type_name!='memory.source':return None
    work=require_initial_contact_source_work_v3(parent.contact_initial_component)
    material=work.source_material
    if (material is None or frame.envelope.authority.namespace!=work.namespace
            or atom.key.token not in material.purposes):
        raise AuthorityUnavailable('initial Contact historical Source commitment has no actual qualified material')
    purpose=next(iter(material.purposes[atom.key.token]))
    material.require_current(db=db,prepared_full_read=None,namespace=work.namespace,
        source_ref=atom.key.token,audiences=(work.selector.audience,),purpose=purpose)
    witness=material.witnesses[atom.key.token]
    record=material.source_records[atom.key.token]
    if (atom.revision,atom.valid,atom.value)!=(witness.revision,witness.valid,record.to_dict()):
        raise AuthorityUnavailable('initial Contact historical Source differs from its actual protected EOF')
    codec,_,_,count,*_=witness.header
    return ContactReadCommitmentV3(atom.key.token,atom.revision,atom.valid,'graph_atoms',codec,count,
        witness.payload_sha256,None,None)


def initial_contact_plan_business_deadline_v3(db,frame,request,opportunity,inputs,grant):
    """Standing business terms outlive this local WRITE; no local Scope is extended."""
    from .domain_background_read_v3 import _active_v3
    from ..domains.d01.production_operations_v1 import plain_v1
    parent=_active_v3(db)
    if parent is None or parent.contact_initial_component is None:return None
    work=require_initial_contact_source_work_v3(parent.contact_initial_component)
    material=work.source_material
    if (material is None or not parent.sealed or not work.complete or _WRITE.get()is None
            or _WRITE.get()[0]is not work or frame.envelope.authority.namespace!=work.namespace
            or (request.opportunity_ref,request.contact_policy_ref,request.target_route_ref)!=
                (work.selector.opportunity_ref,work.selector.policy_ref,work.selector.route_ref)
            or inputs.policy_original.original_ref!=work.current_policy.original.original_ref
            or inputs.policy_original.original_digest!=work.current_policy.original.digest
            or grant!=work.service.bundle.installation_policy.root_grant):
        raise AuthorityUnavailable('Contact business deadline requires its actual standing policy/cause/original Root grant')
    material.require_current(db=db,prepared_full_read=None,namespace=work.namespace,
        source_ref=opportunity.value['source_ref'],audiences=(work.selector.audience,),purpose='expression')
    original=work.current_policy.original
    deadline=float(min(original.policy.window_end,opportunity.value['expires_at'],
        inputs.candidate.check.valid_until,grant.valid_until_utc))
    terms={'schema':'d10.contact-business-deadline.v3','namespace':plain_v1(work.namespace),
        'deadline_utc':deadline,'policy_original_ref':original.original_ref,'policy_original_digest':original.digest,
        'policy_window_id':original.window_id,'policy_window_end_utc':original.policy.window_end,
        'opportunity_ref':opportunity.key.token,'opportunity_revision':opportunity.revision,
        'opportunity_digest':canonical_digest(opportunity.value),'opportunity_expires_at_utc':opportunity.value['expires_at'],
        'raw_check_digest':canonical_digest(inputs.candidate.check),'raw_check_valid_until_utc':inputs.candidate.check.valid_until,
        'parent_budget_lease_ref':grant.lease_id,'root_grant_version':grant.version,'root_grant_digest':canonical_digest(grant),
        'root_grant_valid_until_utc':grant.valid_until_utc}
    previous=getattr(work,'business_deadline_terms',None)
    if previous is not None and previous!=terms:
        raise AuthorityUnavailable('Contact immutable original business deadline terms changed during Plan WRITE')
    work.business_deadline_terms=terms
    return deadline
