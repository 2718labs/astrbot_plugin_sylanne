"""Contact domain Source recipe hosted by the actual background operation."""
from dataclasses import dataclass
from weakref import WeakKeyDictionary
from ..authority_service.contract import AuthorityUnavailable
from ..graph_types import AtomKey,GraphAtom,GraphVersion
from ..runtime_contracts import NamespaceId,canonical_digest
from ..runtime_storage_v3 import runtime_storage_quantum_v3
from .dispatch_current_inventory_v3 import _CurrentNamespaceInventoryKernelV3
from .contact_domain_source_v3 import (register_contact_domain_work_v3,require_contact_domain_work_v3,
    bind_contact_domain_originals_v3,ContactDomainSourceMaterialReadV3,release_contact_domain_materials_v3)

_ISSUER = object()
_COMPONENTS = WeakKeyDictionary()

@dataclass(frozen=True,slots=True)
class ContactDomainSelectorV3:
    namespace: NamespaceId
    contact_id: str
    phase: str
    causal_dedupe: str
    @property
    def stage(self):
        return self.phase
    def __post_init__(self):
        if type(self.namespace) is not NamespaceId or not self.contact_id.startswith('contact:') or self.phase not in {
                'contact_followup','contact_generation_preparation','contact_review_preparation','contact_final','contact_prospective'} or not self.causal_dedupe:
            raise AuthorityUnavailable('Contact domain Source requires its exact closed phase/cause selector')


class ContactDomainProjectionV3:
    def __init__(self,issuer,state):
        if issuer is not _ISSUER or not state.graph_eof:
            raise AuthorityUnavailable('Contact domain projection requires complete actual metadata EOF')
        self.work = state
        self.epochs = (state.graph_stamp[1],)
    @property
    def atoms(self):
        require_contact_domain_work_v3(self.work)
        return tuple(self.work.atoms)
    @property
    def versions(self):
        return tuple(GraphVersion(atom.key,atom.revision) for atom in self.atoms)
    def get(self,key):
        state = require_contact_domain_work_v3(self.work)
        if NamespaceId.from_key(key)!=state.namespace:
            raise AuthorityUnavailable('Contact domain projection crossed namespace')
        if key.type_name == 'memory.source':
            if state.source_material is None or key.token not in state.source_material.source_records:
                raise AuthorityUnavailable('Contact domain source is outside its independent qualified material')
            return GraphAtom(key,state.source_material.witnesses[key.token].revision,
                state.source_material.source_records[key.token].to_dict(),True)
        atom = next((atom for atom in state.atoms if atom.key==key),None)
        if atom is not None:
            return atom
        from .domain_background_read_v3 import read_bound_background_graph_atom_v3
        handled,atom = read_bound_background_graph_atom_v3(state.db,state.namespace,key)
        if not handled:
            raise AuthorityUnavailable('Contact domain head lost its actual background parent')
        return atom


class ContactDomainSourceReadV3(_CurrentNamespaceInventoryKernelV3):
    def __init__(self,issuer,parent,selector):
        from .domain_background_read_v3 import require_actual_background_attachment_owner_v3
        from .contact_graph_runtime_v2 import InstalledContactModelGraphRuntimeV2
        if issuer is not _ISSUER or type(selector) is not ContactDomainSelectorV3:
            raise AuthorityUnavailable('Contact domain component has no actual private producer')
        require_actual_background_attachment_owner_v3(parent,db=parent.db)
        service = parent.graph._GraphCoordinator__contact_model_runtime_v2
        if type(service) is not InstalledContactModelGraphRuntimeV2 or service.bundle is not parent.bundle:
            raise AuthorityUnavailable('Contact domain Source has no actual installed Contact runtime/policy pair')
        service._current()
        joint_recipe=_issue_joint_contact_receiver_recipe_v3(parent,selector)
        regular_source=(parent.authority.purpose=='expression' and
            tuple(parent.authority.audience)==(parent.contact_plan_locators[selector.contact_id].plan.audience_id,))
        if (parent.sealed or parent.fence is None or parent.read_scope is not parent.fence.scope
                or parent.kind not in {'followup','followup_child'} or parent.dedupe_key!=selector.causal_dedupe
                or selector.namespace!=parent.namespace or not (regular_source or joint_recipe is not None)):
            raise AuthorityUnavailable('Contact domain component cannot borrow another phase/cause/Scope')
        self.parent,self.selector,self.contact_selector,self.request = parent,selector,selector,selector
        self.joint_receiver_recipe=joint_recipe
        self.service,self.graph,self.store,self.db,self.namespace = service,parent.graph,parent.store,parent.db,parent.namespace
        self.operation,self.handle,self.work,self.scope,self.fence = parent.operation,parent.operation.handle,parent.work,parent.read_scope,parent.fence
        self.graph_stamp,self.selection_digest,self.contact_issuer = parent.graph_stamp,parent.selection_digest,service.issuer
        self.phase,self.complete,self.closed = 'plan_locator',False,False
        self.prefinal,self.reserved = self,0
        self.contact_policy,self.current_policy,self.policy_lifetime = None,None,None
        self.issued_capabilities,self.attachments,self.pending = [],{},None
        self.heads,self.sources,self.atoms = {},{},[]
        self.source_selection,self.source_reader,self.source_material,self.projection = None,None,None,None
        self.prepared,self.prepared_locator,self.result = None,None,None
        self.owner,self.owner_guard,self.authority = parent.owner,parent.owner_guard,parent.authority
        self.operation_id = parent.operation.operation_id
        register_contact_domain_work_v3(self)
        _COMPONENTS[self] = (parent,selector,service,self.operation,self.scope,self.graph_stamp,self.selection_digest,self.joint_receiver_recipe)
        from ..authority_service.contact_background_graph_v3 import ContactPlanLocatorEOFV3
        self.contact_locator = ContactPlanLocatorEOFV3(self)
    def require_actual_v3(self):
        from .domain_background_read_v3 import require_actual_background_attachment_owner_v3
        require_actual_background_attachment_owner_v3(self.parent,db=self.db)
        self.service._current()
        if self.closed or _COMPONENTS.get(self)!=(self.parent,self.selector,self.service,self.operation,self.scope,self.graph_stamp,self.selection_digest,self.joint_receiver_recipe):
            raise AuthorityUnavailable('Contact domain material lost its actual parent/phase/operation/Scope')
        if self.joint_receiver_recipe is not None:self.joint_receiver_recipe.require_v3(self)
        return self
    _actual = require_actual_v3
    def require_current(self,*,meter):
        self.require_actual_v3()
        self.parent.require_data_current_v3(meter)
        return self
    def require_current_v3(self):
        if not self.db.in_transaction:
            raise AuthorityUnavailable('Contact domain metadata requires its actual parent SQL quantum')
        with runtime_storage_quantum_v3(self.db) as meter:
            return self.require_current(meter=meter)
    def _next(self,meter):
        super()._next(meter)
        if self.pending is not None:
            key,revision,valid,_type,cell = self.pending
            self.heads[key.token] = (revision,valid,cell)

    def _graph_eof_v3(self):
        self.sources = {ref:ContactDomainSourceMetadataV3(_ISSUER,self,original) for ref,original in self.sources.items()}
        self.projection = ContactDomainProjectionV3(_ISSUER,self)
    def observe_current_v3(self):
        from .domain_followup_consumer_v1 import _observe_owner
        from .d10_contact_policy_authority_v1 import read_installed_current_contact_policy_v1
        from .first_ingress_v2 import trusted_upper
        from contextlib import ExitStack
        if self.db.in_transaction:
            raise AuthorityUnavailable('Contact domain Owner/policy observation cannot wait inside Graph SQL')
        self.graph._validate_read_fence_v3(self.fence)
        guard,owner = _observe_owner(self.graph,self.authority,self.scope)
        if (guard,owner)!=(self.owner_guard,self.owner):
            raise AuthorityUnavailable('Contact domain original effective subject/Owner changed')
        if self.policy_lifetime is not None:
            self.policy_lifetime.close()
        lifetime = ExitStack()
        policy_refs = [atom for atom in self.atoms if atom.key.type_name=='d10.contact_policy.v1' and atom.valid
            and atom.value['approval_ref']==self.contact_locator.values[('plan','policy_original_ref')]]
        if len(policy_refs)!=1:
            raise AuthorityUnavailable('Contact domain signed Plan has no unique actual current policy')
        issued = lifetime.enter_context(read_installed_current_contact_policy_v1(
            self.graph._GraphCoordinator__c04_authority_port_v3,self.scope,policy_refs[0].value['policy_id']))
        if issued.original.digest!=self.contact_locator.values[('plan','policy_original_digest')]:
            lifetime.close()
            raise AuthorityUnavailable('Contact domain standing policy differs from its original Plan')
        self.policy_lifetime,self.current_policy,self.contact_policy = lifetime,issued,issued.original
        self.now_utc = trusted_upper(self.service.port.read_ingress_clock(self.service.bundle.ingress_clock))
        deadline = min(self.contact_locator.plan_metadata['valid_until_utc'],issued.original.policy.window_end,
            self.service.bundle.installation_policy.root_grant.valid_until_utc)
        if self.operation.deadline_utc is not None:
            deadline = min(deadline,self.operation.deadline_utc)
        if self.now_utc>=deadline:
            raise AuthorityUnavailable('Contact domain original deadline expired')
        self.operation.deadline_utc = self.work.deadline_utc = float(deadline)
    def advance(self,meter):
        self.require_current(meter=meter)
        if self.phase=='plan_locator':
            self.contact_locator.advance(meter)
            if self.contact_locator.complete:
                from .contact_host_stage_work_v3 import ContactHostPreparedMetadataReadV3
                self.prepared_locator = ContactHostPreparedMetadataReadV3(self,'contact_generation')
                self.phase = 'prepared_metadata'
        elif self.phase == 'prepared_metadata':
            self.prepared_locator.advance(meter)
            if self.prepared_locator.complete:
                if self.selector.phase=='contact_followup':
                    if self.prepared_locator.model_phase=='contact_generation' and self.prepared_locator.values is not None:
                        self.generation_metadata=self.prepared_locator
                        from .contact_host_stage_work_v3 import ContactHostPreparedMetadataReadV3
                        self.prepared_locator=ContactHostPreparedMetadataReadV3(self,'contact_review')
                    else:
                        self._begin_namespace_v3()
                elif self.selector.phase == 'contact_generation_preparation':
                    self.generation_metadata = self.prepared_locator
                    self._begin_namespace_v3()
                elif self.prepared_locator.model_phase == 'contact_generation':
                    if self.prepared_locator.values is None:
                        raise AuthorityUnavailable('Contact review/final requires actual generation prepared metadata')
                    self.generation_metadata = self.prepared_locator
                    if self.selector.phase in {'contact_final','contact_prospective'}:
                        from .contact_host_stage_work_v3 import ContactHostPreparedMetadataReadV3
                        self.prepared_locator = ContactHostPreparedMetadataReadV3(self,'contact_review')
                    else:
                        self._begin_namespace_v3()
                else:
                    if self.prepared_locator.values is None:
                        raise AuthorityUnavailable('Contact final requires actual review prepared metadata')
                    self._begin_namespace_v3()
        elif self.phase=='namespace':
            if self.authority_epochs is None:
                self.authority_epochs=self._epochs(meter)
            if self.cell is None:
                self._next(meter)
            else:
                self._cell(meter)
            if self.graph_eof:
                self.phase='policy'
        elif self.phase=='source':
            from .contact_joint_context_source_v3 import begin_contact_joint_observation_read_v3
            joint=begin_contact_joint_observation_read_v3(self)
            if not joint.complete:
                joint.advance(meter)
                return
            if self.source_reader is None:
                self.source_reader=ContactDomainSourceMaterialReadV3(self)
            self.source_reader.advance_v3(meter)
            if self.source_reader.complete:
                self.source_material=self.source_reader.proof
                self.phase='protected'
        else:
            raise AuthorityUnavailable('Contact domain local phase requires its registered outside-Graph observer')
    def _begin_namespace_v3(self):
        from .contact_product_adapter_v1 import CONTACT_CURRENT_TYPES
        from ..domains.d08.contact_plan_v2 import CURRENT_TYPES as PLAN_CURRENT_TYPES
        self._initialize_storage_kernel_v3(self.operation,self.fence,namespace=self.namespace,graph_stamp=self.graph_stamp,
            catalogue_hash=self.store._registry.catalogue_hash,projection_types=(frozenset(CONTACT_CURRENT_TYPES)|PLAN_CURRENT_TYPES)-{'memory.source'},
            selected_tokens=frozenset(),census_schema='sylanne.contact-domain-full-inventory.v3',
            leaf_schema='sylanne.contact-domain-full-inventory-leaf.v3')
        self.phase = 'namespace'
    def release_payload_v3(self):
        from .contact_joint_context_source_v3 import release_contact_joint_observation_v3
        release_contact_joint_observation_v3(self)
        release_contact_domain_materials_v3(self)
        if self.policy_lifetime is not None:
            self.policy_lifetime.close()
        for registry,original in self.issued_capabilities:
            registry.pop(original,None)
        self.issued_capabilities.clear()
        self.source_material=self.source_reader=self.projection=None
        self.heads,self.sources,self.atoms={},{},[]
        self.closed=True
        if self.joint_receiver_recipe is not None:_JOINT_RECEIVER_RECIPES.pop(self.joint_receiver_recipe,None)
        _COMPONENTS.pop(self,None)


class ContactDomainSourceMetadataV3:
    def __init__(self,issuer,state,original):
        from .dispatch_current_inventory_v3 import VerifiedDispatchSourceMetadataV3,_SOURCE_ISSUED
        if issuer is not _ISSUER or type(original) is not VerifiedDispatchSourceMetadataV3:
            raise AuthorityUnavailable('Contact domain Source metadata requires actual complete census EOF')
        require_contact_domain_work_v3(state)
        self.work,self.original=state,original
        expected=(state.db,original.source_key,original.revision,original.valid,original.cell_id,original.header,
            original.payload_sha256,original.metadata,original.scope,original.graph_stamp,original.query,
            original.operation_id,original.selection_digest)
        if _SOURCE_ISSUED.get(original)!=expected or original.scope!=state.scope:
            raise AuthorityUnavailable('Contact domain Source metadata changed its actual origin')
        for name in ('source_key','revision','valid','cell_id','header','payload_sha256','metadata'):
            setattr(self,name,getattr(original,name))
    def require_current_v3(self):
        state=require_contact_domain_work_v3(self.work)
        state.require_current_v3()
        from .dispatch_current_inventory_v3 import _SOURCE_ISSUED
        original=self.original
        if _SOURCE_ISSUED.get(original)!=(state.db,self.source_key,self.revision,self.valid,self.cell_id,self.header,self.payload_sha256,
                self.metadata,state.scope,state.graph_stamp,state.query,state.operation.operation_id,state.selection_digest):
            raise AuthorityUnavailable('Contact domain Source metadata lost its actual same-parent EOF')
        return self


def prepare_contact_domain_source_read_v3(parent,selector):
    return ContactDomainSourceReadV3(_ISSUER,parent,selector)


def contact_domain_original_point_v3(db,*,table,columns,key_columns,key):
    from .contact_domain_source_v3 import contact_domain_work_for_db_v3,require_contact_domain_fresh_write_v3
    from .natural_producer_qualification_v1 import _HOST_ATTACHMENT_SHAPES_V3
    from .domain_background_read_v3 import BackgroundReadNeededV3
    state = contact_domain_work_for_db_v3(db)
    if state is None:
        return False,None
    from .contact_continuation_v1 import read_current_contact_continuation_write_attempt_v1
    handled,row=read_current_contact_continuation_write_attempt_v1(state,db,table=table,columns=columns,key_columns=key_columns,key=key)
    if handled:return True,row
    from .contact_joint_context_source_v3 import contact_joint_original_point_v3
    handled,row=contact_joint_original_point_v3(state,db,table=table,columns=columns,key_columns=key_columns,key=key)
    if handled:return True,row
    if state.source_material is None or not state.complete:
        raise AuthorityUnavailable('Contact domain protected original cannot precede actual Source qualification')
    if state.parent.sealed:
        require_contact_domain_fresh_write_v3(state,db)
    allowed = {'graph_atoms','graph_history','graph_contact_expression_plan_originals_v2','graph_contact_expression_plan_originals_v3',
        'graph_contact_model_originals_v2','graph_bundle_operations','graph_domain_production_originals_v1','graph_domain_production_originals_v3',
        'graph_events','graph_bundle_fences_v2','runtime_resource_quotes','runtime_budget_grants','runtime_budget_reservations',
        'runtime_budget_operations','runtime_jobs','runtime_job_operations',
        'graph_d10_production_inputs_v1','graph_contact_prospective_originals_v1','graph_owner_domain_attempts_v3',
        'graph_contact_segment_originals_v1','graph_contact_effect_originals_v1','graph_contact_effect_accounting_attempts_v1',
        'graph_domain_production_outbox_v1'}
    if table not in allowed:
        raise AuthorityUnavailable('Contact domain original table is outside its closed Contact recipe')
    if table == 'runtime_resource_quotes' and state.parent.sealed:
        return True,_read_current_contact_domain_quote_v3(state,columns,key_columns,key)
    original_columns,original_keys = tuple(columns),dict(zip(key_columns,key))
    if table == 'graph_atoms':
        atom = AtomKey.from_token(original_keys['token'])
        key_columns,key,columns = ('token','bot','persona'),(atom.token,*state.namespace.as_tuple),('revision','value','valid')
        if atom.type_name == 'memory.source' and atom.token not in state.source_material.source_records:
            raise AuthorityUnavailable('Contact domain body is outside its exact Source material')
    elif table == 'graph_history':
        atom = AtomKey.from_token(original_keys['token'])
        key_columns,key,columns = ('token','revision'),(atom.token,original_keys['revision']),('event_id','value','valid','event_bot','event_persona','event_session','dependencies')
        if atom.type_name == 'memory.source' and (atom.token not in state.source_material.source_records
                or state.source_material.witnesses[atom.token].revision != original_keys['revision']):
            raise AuthorityUnavailable('Contact historical body has no actual current exact Source qualification')
    request = (table,tuple(columns),tuple(key_columns),tuple(key))
    if request[:3] not in _HOST_ATTACHMENT_SHAPES_V3:
        raise AuthorityUnavailable('Contact domain original has no fixed registered column/key recipe')
    if table in {'graph_atoms','graph_history'}:
        if NamespaceId.from_key(atom) != state.namespace:
            raise AuthorityUnavailable('Contact domain exact body crossed namespace')
    elif table == 'runtime_jobs':
        if not str(key[0]).startswith('contact-model-job-v2:'):
            raise AuthorityUnavailable('Contact domain job is not its actual model family')
    elif table in {'runtime_resource_quotes','runtime_budget_grants','runtime_budget_reservations'}:
        if table != 'runtime_resource_quotes' and key[0] != state.contact_locator.plan_metadata['parent_budget_lease_id']:
            raise AuthorityUnavailable('Contact domain budget metadata changed its original parent')
    elif tuple(key[:2]) != state.namespace.as_tuple:
        raise AuthorityUnavailable('Contact domain ledger crossed namespace')
    task = state.attachments.get(request)
    if task is None:
        if state.parent.sealed:
            raise AuthorityUnavailable('Contact fresh WRITE cannot read an original absent from its actual READ preparation')
        raise BackgroundReadNeededV3(('contact_domain_attachment',state.selector.contact_id,state.selector.phase,request))
    with runtime_storage_quantum_v3(db) as meter:
        row = task.require_row_v3(state,meter)
    if row is None:
        return True,None
    if table in {'graph_atoms','graph_history'}:
        values = dict(zip(columns,row))
        values.update(zip(key_columns,key))
        if any(values.get(name) != value for name,value in original_keys.items()):
            raise AuthorityUnavailable('Contact domain original changed its exact full key/event identity')
        return True,tuple(values[name] for name in original_columns)
    return True,row


def prepare_contact_domain_attachment_v3(state,request):
    require_contact_domain_work_v3(state)
    if state.parent.sealed or not state.complete or state.source_material is None:
        raise AuthorityUnavailable('Contact domain attachment must originate in its qualified READ phase')
    if request[0] == 'contact_plan_physical_payload':
        from .contact_original_read_v3 import ContactPlanPhysicalPayloadReadV3
        return ContactPlanPhysicalPayloadReadV3(state,request)
    if request[0] == 'contact_payload_commitment':
        from .contact_original_read_v3 import ContactPayloadCommitmentEOFV3
        return ContactPayloadCommitmentEOFV3(state,request)
    if request[0] == 'contact_historical_inventory':
        from .contact_original_read_v3 import ContactHistoricalInventoryReadV3
        return ContactHistoricalInventoryReadV3(state,request)
    if request[0] == 'graph_dependencies':
        if (request[1],request[2],request[4]) != (('dependency_token','dependency_revision'),('dependent_token',),'dependency_token') or NamespaceId.from_key(AtomKey.from_token(request[3][0])) != state.namespace:
            raise AuthorityUnavailable('Contact domain dependency metadata has another fixed namespace/recipe')
        from .natural_producer_qualification_v1 import _HostProducerMetadataScanV3
        return _HostProducerMetadataScanV3(state,request)
    from .natural_producer_qualification_v1 import _HostProducerAttachmentV3
    return _HostProducerAttachmentV3(state,request)


class ContactDomainAttachmentReadV3:
    def __init__(self,state,request):
        self.owner,self.request = state,request
        self.task = prepare_contact_domain_attachment_v3(state,request)
        self.complete = False
    def advance(self,meter):
        self.owner.require_current(meter=meter)
        self.task.advance(meter)
        if self.task.complete:
            self.owner.attachments[self.request] = self.task
            self.complete = True


def _read_current_contact_domain_quote_v3(state,columns,key_columns,key):
    from .contact_domain_source_v3 import require_contact_domain_fresh_write_v3
    from .issuers import _decode_quote, _payload
    from ..runtime_contracts import canonical_serialize
    if (tuple(columns),tuple(key_columns)) != (('quote_json','signature'),('quote_id','version')):
        raise AuthorityUnavailable('Contact domain current quote requires its exact two-field recipe')
    require_contact_domain_fresh_write_v3(state,state.db)
    with runtime_storage_quantum_v3(state.db) as meter:
        row = _runtime_bounded_contact_budget_row_v3(state,meter,'runtime_resource_quotes',tuple(columns),
            'quote_id=? AND version=?',tuple(key))
    if row is None:
        return None
    state.service.resource_issuer._signer.verify('resource-quote.v1',row[0],row[1])
    quote = _decode_quote(row[0])
    expected_work = ('message' if state.selector.phase == 'contact_final' else
        'contact_generation' if state.selector.phase == 'contact_generation_preparation' else 'contact_review')
    if ((quote.bot_id,quote.persona_id) != state.namespace.as_tuple
            or quote.parent_budget_lease_ref != state.contact_locator.plan_metadata['parent_budget_lease_id']
            or quote.operation_id != state.parent.local_result[7][0] or quote.work_kind != expected_work
            or (quote.quote_id,quote.version) != tuple(key) or canonical_serialize(_payload(quote)) != row[0]):
        raise AuthorityUnavailable('Contact domain quote changed its actual child/parent/namespace')
    return row


def _runtime_bounded_contact_budget_row_v3(state,meter,table,columns,where,key):
    from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3
    state.require_current(meter=meter)
    return _runtime_bounded_fixed_row_v3(state.db,meter,table,columns,where,key)


def contact_domain_budget_lease_v3(db,lease_id):
    from .contact_domain_source_v3 import contact_domain_work_for_db_v3,require_contact_domain_fresh_write_v3
    state = contact_domain_work_for_db_v3(db)
    if state is None:
        return False,None
    if (not state.complete or state.source_material is None
            or lease_id != state.contact_locator.plan_metadata['parent_budget_lease_id']):
        raise AuthorityUnavailable('Contact domain budget read changed its actual finite parent')
    if state.parent.sealed:
        require_contact_domain_fresh_write_v3(state,db)
    columns = ('lease_id','parent_id','bot_id','persona_id','currency','limits_json','used_json',
        'reserved_json','unconfirmed_json','version','state')
    with runtime_storage_quantum_v3(db) as meter:
        row = _runtime_bounded_contact_budget_row_v3(state,meter,'runtime_budget_leases',columns,'lease_id=?',(lease_id,))
    if row is None or row[0] != lease_id or row[2:4] != state.namespace.as_tuple:
        raise AuthorityUnavailable('Contact domain parent budget metadata crossed namespace')
    import json
    from ..runtime_contracts import canonical_serialize
    for index in (5,6,7,8):
        if canonical_serialize(json.loads(row[index])) != row[index]:
            raise AuthorityUnavailable('Contact domain current budget counter lacks its exact canonical EOF')
    return True,row


_JOINT_RECEIVER_RECIPES=WeakKeyDictionary()

class _JointContactReceiverRecipeV3:
    def __init__(self,issuer,parent,selector,preparation,cause):
        if issuer is not _ISSUER:raise AuthorityUnavailable('actual Joint Contact receiver recipe issuer required')
        self.parent,self.selector,self.preparation,self.cause=parent,selector,preparation,cause
        self.audience=preparation.audience[0]
        self.purpose_groups=preparation.source_purpose_groups
        self.identity=(parent,selector,preparation.digest,cause['receipt_digest'],cause['dedupe_key'],
            preparation.request.qualified_contact_dedupe_key,self.audience,self.purpose_groups)
        _JOINT_RECEIVER_RECIPES[self]=self.identity
    def require_v3(self,work):
        from .domain_background_read_v3 import require_actual_background_attachment_owner_v3
        require_actual_background_attachment_owner_v3(self.parent,db=self.parent.db)
        if (_JOINT_RECEIVER_RECIPES.get(self)!=self.identity or work.joint_receiver_recipe is not self
                or work.parent is not self.parent or work.selector is not self.selector
                or self.parent.kind!='followup' or self.parent.authority.purpose!='context'
                or self.parent.authority.audience!=('owner',) or self.parent.read_scope is not work.scope):
            raise AuthorityUnavailable('Contact Joint Source recipe lost its exact original metadata READ identity')
        owner=self.parent.owner
        purposes={purpose for _,items in self.purpose_groups for purpose in items}
        if not purposes<=set(owner.purposes) or self.audience not in owner.audiences:
            raise AuthorityUnavailable('Contact current Owner lacks actual independent Source purposes/recipient scope')
        return self


def _issue_joint_contact_receiver_recipe_v3(parent,selector):
    from .contact_prospective_v1 import read_joint_contact_prospective_cause_v1
    from .joint_contact_preparation_v1 import EVENT
    if (parent.kind!='followup' or selector.phase!='contact_prospective' or parent.authority.purpose!='context'
            or parent.authority.audience!=('owner',) or parent.dedupe_key!=selector.causal_dedupe):
        return None
    preparation,cause=read_joint_contact_prospective_cause_v1(parent.db,namespace=parent.namespace,
        dedupe_key=selector.causal_dedupe,contact_id=selector.contact_id,
        issuer=parent.graph._GraphCoordinator__d11_issuer)
    if (preparation.owner_acl_actor!=parent.owner.actor or preparation.namespace!=parent.namespace
            or preparation.request.contact_id!=selector.contact_id or preparation.purpose!='expression'
            or len(preparation.audience)!=1 or preparation.absolute_deadline_utc<=parent.now):
        raise AuthorityUnavailable('Contact Joint receiver signed current intent/Owner/deadline/Source scope differs')
    return _JointContactReceiverRecipeV3(_ISSUER,parent,selector,preparation,cause)
