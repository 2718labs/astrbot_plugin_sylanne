"""Contact Domain Source material from its actual stage Work and original Scope."""
from contextvars import ContextVar
from contextlib import contextmanager
from types import MappingProxyType
from weakref import WeakKeyDictionary,WeakSet

from ..authority_service.contract import AuthorityUnavailable
from ..authority_service.current_authority_graph_read_v3 import _AuthoritySourceMaterialReadV3
from ..graph_types import AtomKey,GraphAtom,GraphVersion

_ISSUER = object()
_DOMAIN_WORKS = WeakSet()
_DOMAIN_MATERIALS = WeakKeyDictionary()
_DOMAIN_PREPARED = WeakKeyDictionary()
_DOMAIN_READING = ContextVar('contact_actual_domain_source_work_v3',default=None)


def register_contact_domain_work_v3(work):
    from .contact_domain_source_work_v3 import ContactDomainSourceReadV3
    if type(work) is not ContactDomainSourceReadV3:
        raise AuthorityUnavailable('Contact Domain material requires its actual fixed stage Work')
    _DOMAIN_WORKS.add(work)


def require_contact_domain_work_v3(work,*,db=None):
    from .contact_domain_source_work_v3 import ContactDomainSourceReadV3
    if type(work) is not ContactDomainSourceReadV3 or work not in _DOMAIN_WORKS:
        raise AuthorityUnavailable('Contact cannot borrow a generic Domain or Authority context')
    work.require_actual_v3()
    if db is not None and db is not work.db:
        raise AuthorityUnavailable('Contact Domain material changed its actual SourceDB')
    return work


@contextmanager
def bind_contact_domain_originals_v3(work):
    require_contact_domain_work_v3(work)
    token = _DOMAIN_READING.set(work)
    try:
        yield work
    finally:
        _DOMAIN_READING.reset(token)


def contact_domain_work_for_db_v3(db):
    work = _DOMAIN_READING.get()
    if work is None:
        from .domain_background_read_v3 import _active_v3
        parent = _active_v3(db)
        work = None if parent is None else parent.contact_active_component
    return None if work is None else require_contact_domain_work_v3(work,db=db)


class ContactDomainSourceSelectionV3:
    def __init__(self,issuer,work):
        if issuer is not _ISSUER:
            raise AuthorityUnavailable('Contact Domain source selection requires its installed producer')
        require_contact_domain_work_v3(work)
        work.contact_locator.require_v3(work)
        self.work = work
        self.root,self.audience = work.contact_locator.root,work.contact_locator.audience
        roots = set(work.contact_locator.roots)
        originals = tuple(reader for reader in (getattr(work,'generation_metadata',None),getattr(work,'prepared_locator',None))
            if reader is not None and reader.values is not None)
        qualified = {row['key']:row['revision'] for row in work.contact_locator.versions.values()
            if AtomKey.from_token(row['key']).type_name == 'memory.source' and row['revision']>0}
        for reader in originals:
            for ref,revision in reader.frozen.sources:
                if qualified.get(ref)!=revision:
                    raise AuthorityUnavailable('Contact Domain frozen Source escapes its exact Plan qualified positive reads')
                roots.add(ref)
        self.roots = tuple(sorted(roots))
        from .contact_source_purposes_v3 import contact_plan_source_purpose_groups_v3
        self.purpose_groups=contact_plan_source_purpose_groups_v3(work,work.contact_locator,self.roots)
        self.joint_recipe=getattr(work,'joint_receiver_recipe',None)
        if self.joint_recipe is not None:
            preparation=self.joint_recipe.preparation
            locator=work.contact_locator
            from ..graph_types import Owner
            from ..domains.d08.contact_plan_v2 import PLAN
            plan_key=AtomKey(Owner('activity',*work.namespace.as_tuple,locator.plan_metadata['activity_id']),
                PLAN,locator.plan_metadata['plan_id'])
            actual=work.heads.get(plan_key.token)
            if (preparation.contact_plan_ref!=plan_key.token or actual is None
                    or actual[:2]!=(preparation.contact_plan_revision,True)
                    or preparation.contact_plan_original_digest!=locator.digest
                    or preparation.parent_budget_lease_ref!=locator.plan_metadata['parent_budget_lease_id']
                    or preparation.parent_grant_digest!=locator.plan_metadata['budget_grant_digest']
                    or preparation.parent_grant_version!=locator.plan_metadata['budget_grant_version']
                    or not set(preparation.source_refs)<=set(self.roots)):
                raise AuthorityUnavailable('Contact Joint receiver actual signed Plan/parent/Source metadata differs')
        if self.joint_recipe is not None:
            recipe=self.joint_recipe.require_v3(work)
            if self.audience!=recipe.audience or self.purpose_groups!=recipe.purpose_groups:
                raise AuthorityUnavailable('Contact Joint receiver Source selection changed signed Preparation/Plan intersection')
        self.purpose,self.attention,self.maximum_ancestors = 'expression',None,256
        self.identity = (work,work.scope,work.operation,work.contact_locator.digest,self.root,self.audience,self.roots,self.purpose_groups,self.joint_recipe)
    def require_v3(self,work):
        require_contact_domain_work_v3(work)
        work.contact_locator.require_v3(work)
        if (work is not self.work or self.identity != (work,work.scope,work.operation,
                work.contact_locator.digest,self.root,self.audience,self.roots,self.purpose_groups,self.joint_recipe)
                or work.source_selection is not self):
            raise AuthorityUnavailable('Contact Domain source selection lost its actual same-Work origin')
        if self.joint_recipe is not None:self.joint_recipe.require_v3(work)
        for row in work.contact_locator.versions.values():
            current = work.heads.get(row['key'])
            if row['revision'] == 0:
                if current is not None:
                    raise AuthorityUnavailable('Contact Domain negative Source/rights dependency appeared')
            elif current is None or current[0] != row['revision'] or not current[1]:
                raise AuthorityUnavailable('Contact Domain current Source/rights dependency changed')
        for ref,revision in work.contact_locator.protected_history:
            current = work.heads.get(ref)
            if current is None or current[0] != revision or not current[1]:
                raise AuthorityUnavailable('Contact Domain historical protected body lacks current exact rights/version')
        return self


class ContactDomainSourceMaterialReadV3(_AuthoritySourceMaterialReadV3):
    def __init__(self,work):
        require_contact_domain_work_v3(work)
        work.source_selection = ContactDomainSourceSelectionV3(_ISSUER,work)
        super().__init__(work,work.source_selection)
    def advance_v3(self,meter):
        from .contact_joint_context_source_v3 import advance_contact_joint_source_rights_v3
        self.work.require_current(meter=meter);self.selection.require_v3(self.work)
        if advance_contact_joint_source_rights_v3(self,meter):return
        return super().advance_v3(meter)
    def _body_refs_v3(self):
        return tuple(sorted(self.witnesses))
    def _seal_material_v3(self):
        require_contact_domain_work_v3(self.work)
        return PreparedContactDomainSourceMaterialV3(_ISSUER,self)


class PreparedContactDomainSourceMaterialV3:
    def __init__(self,issuer,reader):
        if issuer is not _ISSUER or type(reader) is not ContactDomainSourceMaterialReadV3 or not reader.complete:
            raise AuthorityUnavailable('Contact Domain body requires its actual complete Source reader')
        work = require_contact_domain_work_v3(reader.work)
        reader.selection.require_v3(work)
        self.work,self.selection,self.namespace,self.operation,self.scope = (
            work,reader.selection,work.namespace,work.operation,work.scope)
        self.source_ref,self.audiences = reader.selection.root,(reader.selection.audience,)
        self.source_records = MappingProxyType(dict(reader.records))
        self.witnesses = MappingProxyType(dict(reader.witnesses))
        self.metadata_records = MappingProxyType(dict(reader.metadata_records))
        self.rights_versions = tuple(reader.versions)
        self.purposes=MappingProxyType({ref:frozenset(values)for ref,values in reader.qualified_purposes.items()})
        _DOMAIN_MATERIALS[self] = self._identity_v3()
        from .contact_joint_context_source_v3 import register_contact_joint_material_v3
        register_contact_joint_material_v3(self,reader)
    def _identity_v3(self):
        return (self.work,self.selection,self.namespace,self.operation,self.scope,self.source_ref,self.audiences,
            self.source_records,self.witnesses,self.metadata_records,self.rights_versions,self.purposes)
    def require_current(self,*,db,prepared_full_read,namespace,source_ref,audiences,purpose='expression'):
        work = require_contact_domain_work_v3(self.work,db=db)
        if (type(self) is not PreparedContactDomainSourceMaterialV3 or _DOMAIN_MATERIALS.get(self) != self._identity_v3()
                or contact_domain_work_for_db_v3(db) is not work or not db.in_transaction
                or namespace != self.namespace or source_ref not in self.source_records
                or tuple(audiences) != self.audiences or purpose != 'expression' or purpose not in self.purposes.get(source_ref,())
                or work.source_material is not self or self.scope is not work.scope
                or prepared_full_read is not None and prepared_full_read is not work.prepared):
            raise AuthorityUnavailable('Contact Domain Source body changed its actual purpose/audience/Scope/Work')
        if work.parent.sealed:
            require_contact_domain_fresh_write_v3(work,db)
        from .contact_joint_context_source_v3 import require_contact_joint_material_purpose_v3
        require_contact_joint_material_purpose_v3(self,work=work,source_ref=source_ref,audiences=audiences,purpose=purpose)
        self.selection.require_v3(work)
        for witness in self.witnesses.values():
            witness.require_current_v3()
        return self
    def source_record_for_v3(self,**kwargs):
        self.require_current(**kwargs)
        return self.source_records[kwargs['source_ref']]
    def source_family_for_v3(self,*,db,prepared_full_read,namespace,source_ref,audiences):
        self.require_current(db=db,prepared_full_read=prepared_full_read,namespace=namespace,
            source_ref=source_ref,audiences=audiences)
        from ..memory_types import source_key,access_key
        from ..domains.d06 import source_correction_head_key
        pending,seen,versions,lineage = [source_ref],set(),[],[]
        while pending:
            ref = pending.pop()
            if ref in seen:
                continue
            if 'expression'not in self.purposes.get(ref,()):
                raise AuthorityUnavailable('Contact expression ancestry lacks its independently qualified expression purpose')
            seen.add(ref)
            lineage.append(ref)
            key = AtomKey.from_token(ref)
            access = access_key(*namespace.as_tuple,key.owner.subject)
            versions.extend((GraphVersion(key,self.witnesses[ref].revision),
                GraphVersion(access,self.work.projection.get(access).revision),
                GraphVersion(source_correction_head_key(namespace,key.owner.subject),0)))
            pending.extend(source_key(*namespace.as_tuple,parent).token
                for parent in self.metadata_records[ref].parent_source_ids)
        return tuple(lineage),tuple(sorted(versions,key=lambda row:row.key.token))


def require_contact_domain_expression_projection_v3(material,*,db,prepared,namespace,source_ref,audiences):
    if type(material) is not PreparedContactDomainSourceMaterialV3:
        raise AuthorityUnavailable('Contact requires its independently issued actual Domain material')
    material.require_current(db=db,prepared_full_read=prepared,namespace=namespace,
        source_ref=source_ref,audiences=audiences)
    return material.work.projection


def contact_domain_expression_kwargs_v3(db):
    work = contact_domain_work_for_db_v3(db)
    if work is None:
        return None
    if work.source_material is None:
        raise AuthorityUnavailable('Contact Domain protected Source has not completed its actual rights/body EOF')
    return {'prepared_source_material':work.source_material,'prepared_full_read':work.prepared,'db':db}


def release_contact_domain_materials_v3(work):
    _DOMAIN_WORKS.discard(work)
    for material in tuple(_DOMAIN_MATERIALS):
        if material.work is work:
            _DOMAIN_MATERIALS.pop(material,None)
    if work.prepared is not None:
        _DOMAIN_PREPARED.pop(work.prepared,None)


def track_contact_domain_metadata_v3(work,registry,original):
    from .contact_domain_source_work_v3 import ContactDomainSourceReadV3
    if type(work) is not ContactDomainSourceReadV3:
        return False
    require_contact_domain_work_v3(work)
    work.operation.retain(128)
    work.issued_capabilities.append((registry,original))
    return True


_DOMAIN_WRITES = WeakKeyDictionary()
_DOMAIN_WRITE_CURRENT = ContextVar('contact_domain_fresh_write_v3', default=None)


class _ContactDomainFreshWriteV3:
    def __init__(self,issuer,work,scope,guard,owner,authority,command,request_digest,policy):
        if issuer is not _ISSUER:
            raise AuthorityUnavailable('Contact domain WRITE requires its actual current observer')
        self.work,self.scope,self.guard,self.owner,self.authority = work,scope,guard,owner,authority
        self.command,self.request_digest,self.policy = command,request_digest,policy
        self.deadline = min(work.operation.deadline_utc,policy.original.policy.window_end)
        _DOMAIN_WRITES[self] = self._identity()
    def _identity(self):
        return (self.work,self.scope,self.guard,self.owner,self.authority,self.command,self.request_digest,self.policy,self.deadline)
    def require_current(self,db):
        work = require_contact_domain_work_v3(self.work,db=db)
        if (_DOMAIN_WRITES.get(self) != self._identity() or _DOMAIN_WRITE_CURRENT.get() is not self
                or not work.complete or not work.parent.sealed or not db.in_transaction
                or not work.store._lock._is_owned() or self.scope.operation != 'write'
                or self.scope is work.scope or self.owner.principal != work.owner.principal
                or self.guard != work.owner_guard or self.policy.original.digest != work.contact_policy.digest):
            raise AuthorityUnavailable('Contact retained READ bytes have no actual fresh WRITE binder')
        work.parent.require_write_data_v3(db,self.scope,self.owner)
        work.require_current_v3()
        work.source_selection.require_v3(work)
        for witness in work.source_material.witnesses.values():
            witness.require_current_v3()
        return self


@contextmanager
def bind_contact_domain_fresh_write_v3(runtime,*,authority,operation_kind,request,operation_id,
        request_digest,scope,guard,owner):
    from .domain_background_read_v3 import _active_v3,require_actual_background_attachment_owner_v3
    from .domain_followup_consumer_v1 import _observe_owner
    from .d10_contact_policy_authority_v1 import read_installed_current_contact_policy_v1
    from .first_ingress_v2 import trusted_upper
    parent = _active_v3(runtime.graph._GraphCoordinator__store._db)
    if parent is None or parent.contact_active_component is None:
        yield None
        return
    require_actual_background_attachment_owner_v3(parent,db=parent.db)
    work = require_contact_domain_work_v3(parent.contact_active_component)
    actual = parent.local_result
    command = actual[6]
    if (runtime is not runtime.graph._GraphCoordinator__domain_production_runtime_v1
            or runtime.graph is not work.graph or work.service is not runtime.graph._GraphCoordinator__contact_model_runtime_v2
            or not parent.sealed or not work.complete or parent.kind != 'followup_child'
            or command is None or (command.operation_kind,command.request) != (operation_kind,request)
            or actual[7][0] != operation_id or request.contact_id != work.selector.contact_id
            or (scope.operation,scope.namespace) != ('write',work.namespace) or scope is work.scope
            or scope.permit is work.scope.permit or authority.namespace != work.namespace
            or authority.purpose != 'expression' or tuple(authority.audience) != (work.source_selection.audience,)):
        raise AuthorityUnavailable('Contact domain fresh WRITE cannot select another actual child/phase/Scope')
    expected_phase = ('contact_prospective' if operation_kind == 'prepare_contact_prospective_v1' else
        'contact_final' if operation_kind == 'prepare_contact_dispatch_v3' else
        'contact_generation_preparation' if operation_kind == 'prepare_contact_model_v2' and request.phase == 'contact_generation' else
        'contact_review_preparation' if operation_kind == 'prepare_contact_model_v2' and request.phase == 'contact_review' else None)
    if expected_phase != work.selector.phase:
        raise AuthorityUnavailable('Contact domain fresh WRITE changed its Source use phase')
    if work.db.in_transaction:
        raise AuthorityUnavailable('Contact fresh WRITE Owner/policy observation must precede Graph SQL')
    if work.service.port.validate_fence(scope) != scope.permit or _observe_owner(work.graph,authority,scope) != (guard,owner):
        raise AuthorityUnavailable('Contact domain fresh WRITE lacks its actual current Owner observation')
    if guard != work.owner_guard or owner.principal != work.owner.principal:
        raise AuthorityUnavailable('Contact domain fresh WRITE changed the original authenticated Source subject')
    policy_rows = [atom for atom in work.atoms if atom.valid and atom.key.type_name == 'd10.contact_policy.v1'
        and atom.value['approval_ref'] == work.contact_locator.values[('plan','policy_original_ref')]]
    if len(policy_rows) != 1:
        raise AuthorityUnavailable('Contact domain fresh WRITE has no unique signed policy locator')
    with read_installed_current_contact_policy_v1(work.graph._GraphCoordinator__c04_authority_port_v3,
            scope,policy_rows[0].value['policy_id']) as current_policy:
        if (current_policy is None or current_policy.original.digest != work.contact_policy.digest
                or current_policy.original.original_ref != work.contact_locator.values[('plan','policy_original_ref')]):
            raise AuthorityUnavailable('Contact domain current standing policy changed before fresh WRITE')
        now = trusted_upper(work.service.port.read_ingress_clock(work.service.bundle.ingress_clock))
        if now >= min(work.operation.deadline_utc,current_policy.original.policy.window_end):
            raise AuthorityUnavailable('Contact domain retained material cannot extend its original deadline')
        binding = _ContactDomainFreshWriteV3(_ISSUER,work,scope,guard,owner,authority,command,request_digest,current_policy)
        token = _DOMAIN_WRITE_CURRENT.set(binding)
        try:
            yield binding
        finally:
            _DOMAIN_WRITE_CURRENT.reset(token)
            _DOMAIN_WRITES.pop(binding,None)
    work.service.port.validate_fence(scope)


def require_contact_domain_fresh_write_v3(work,db):
    binding = _DOMAIN_WRITE_CURRENT.get()
    if binding is None or binding.work is not work:
        raise AuthorityUnavailable('Contact domain Source READ does not grant a child WRITE')
    return binding.require_current(db)
