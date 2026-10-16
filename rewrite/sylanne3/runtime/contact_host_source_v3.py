"""Contact Host Source material from its actual stage Work and original Scope."""
from contextvars import ContextVar
from contextlib import contextmanager
from types import MappingProxyType
from weakref import WeakKeyDictionary,WeakSet

from ..authority_service.contract import AuthorityUnavailable
from ..authority_service.current_authority_graph_read_v3 import _AuthoritySourceMaterialReadV3
from ..graph_types import AtomKey,GraphAtom,GraphVersion

_ISSUER = object()
_HOST_WORKS = WeakSet()
_HOST_MATERIALS = WeakKeyDictionary()
_HOST_PREPARED = WeakKeyDictionary()
_HOST_READING = ContextVar('contact_actual_host_source_work_v3',default=None)


def register_contact_host_work_v3(work):
    from .contact_host_stage_work_v3 import ContactHostStageReadWorkV3
    if type(work) is not ContactHostStageReadWorkV3:
        raise AuthorityUnavailable('Contact Host material requires its actual fixed stage Work')
    _HOST_WORKS.add(work)


def require_contact_host_work_v3(work,*,db=None):
    from .contact_host_stage_work_v3 import ContactHostStageReadWorkV3
    if type(work) is not ContactHostStageReadWorkV3 or work not in _HOST_WORKS:
        raise AuthorityUnavailable('Contact cannot borrow a generic Host or Authority context')
    work.require_actual_v3()
    if db is not None and db is not work.db:
        raise AuthorityUnavailable('Contact Host material changed its actual SourceDB')
    return work


@contextmanager
def bind_contact_host_originals_v3(work):
    require_contact_host_work_v3(work)
    token = _HOST_READING.set(work)
    try:
        yield work
    finally:
        _HOST_READING.reset(token)


def contact_host_work_for_db_v3(db):
    work = _HOST_READING.get()
    return None if work is None else require_contact_host_work_v3(work,db=db)


class ContactHostSourceSelectionV3:
    def __init__(self,issuer,work):
        if issuer is not _ISSUER:
            raise AuthorityUnavailable('Contact Host source selection requires its installed producer')
        require_contact_host_work_v3(work)
        work.contact_locator.require_v3(work)
        self.work = work
        self.root,self.audience = work.contact_locator.root,work.contact_locator.audience
        roots = set(work.contact_locator.roots)
        originals = tuple(reader for reader in (getattr(work,'generation_metadata',None),work.prepared_locator)
            if reader is not None and reader.values is not None)
        qualified = {row['key']:row['revision'] for row in work.contact_locator.versions.values()
            if AtomKey.from_token(row['key']).type_name == 'memory.source' and row['revision']>0}
        for reader in originals:
            for ref,revision in reader.frozen.sources:
                if qualified.get(ref)!=revision:
                    raise AuthorityUnavailable('Contact Host frozen Source escapes its exact Plan qualified positive reads')
                roots.add(ref)
        self.roots = tuple(sorted(roots))
        from .contact_source_purposes_v3 import contact_plan_source_purpose_groups_v3
        self.purpose_groups=contact_plan_source_purpose_groups_v3(work,work.contact_locator,self.roots)
        self.purpose,self.attention,self.maximum_ancestors = 'expression',None,256
        self.identity = (work,work.scope,work.operation,work.contact_locator.digest,self.root,self.audience,self.roots,self.purpose_groups)
    def require_v3(self,work):
        require_contact_host_work_v3(work)
        work.contact_locator.require_v3(work)
        if (work is not self.work or self.identity != (work,work.scope,work.operation,
                work.contact_locator.digest,self.root,self.audience,self.roots,self.purpose_groups)
                or work.source_selection is not self):
            raise AuthorityUnavailable('Contact Host source selection lost its actual same-Work origin')
        for row in work.contact_locator.versions.values():
            current = work.heads.get(row['key'])
            if row['revision'] == 0:
                if current is not None:
                    raise AuthorityUnavailable('Contact Host negative Source/rights dependency appeared')
            elif current is None or current[0] != row['revision'] or not current[1]:
                raise AuthorityUnavailable('Contact Host current Source/rights dependency changed')
        for ref,revision in work.contact_locator.protected_history:
            current = work.heads.get(ref)
            if current is None or current[0] != revision or not current[1]:
                raise AuthorityUnavailable('Contact Host historical protected body lacks current exact rights/version')
        return self


class ContactHostSourceMaterialReadV3(_AuthoritySourceMaterialReadV3):
    def __init__(self,work):
        require_contact_host_work_v3(work)
        if work.owner_command is not None:
            if work.owner_entry is None or work.owner_entry.require_for_v3(work)!=(work.owner_guard,work.owner):
                raise AuthorityUnavailable('Contact Source body requires its completed actual Owner metadata entry')
        work.source_selection = ContactHostSourceSelectionV3(_ISSUER,work)
        super().__init__(work,work.source_selection)
    def _body_refs_v3(self):
        return tuple(sorted(self.witnesses))
    def _seal_material_v3(self):
        require_contact_host_work_v3(self.work)
        return PreparedContactHostSourceMaterialV3(_ISSUER,self)


class PreparedContactHostSourceMaterialV3:
    def __init__(self,issuer,reader):
        if issuer is not _ISSUER or type(reader) is not ContactHostSourceMaterialReadV3 or not reader.complete:
            raise AuthorityUnavailable('Contact Host body requires its actual complete Source reader')
        work = require_contact_host_work_v3(reader.work)
        reader.selection.require_v3(work)
        self.work,self.selection,self.namespace,self.operation,self.scope = (
            work,reader.selection,work.namespace,work.operation,work.scope)
        self.source_ref,self.audiences = reader.selection.root,(reader.selection.audience,)
        self.source_records = MappingProxyType(dict(reader.records))
        self.witnesses = MappingProxyType(dict(reader.witnesses))
        self.metadata_records = MappingProxyType(dict(reader.metadata_records))
        self.rights_versions = tuple(reader.versions)
        self.purposes=MappingProxyType({ref:frozenset(values)for ref,values in reader.qualified_purposes.items()})
        _HOST_MATERIALS[self] = self._identity_v3()
    def _identity_v3(self):
        return (self.work,self.selection,self.namespace,self.operation,self.scope,self.source_ref,self.audiences,
            self.source_records,self.witnesses,self.metadata_records,self.rights_versions,self.purposes)
    def require_current(self,*,db,prepared_full_read,namespace,source_ref,audiences,purpose='expression'):
        work = require_contact_host_work_v3(self.work,db=db)
        if (type(self) is not PreparedContactHostSourceMaterialV3 or _HOST_MATERIALS.get(self) != self._identity_v3()
                or _HOST_READING.get() is not work or not db.in_transaction
                or namespace != self.namespace or source_ref not in self.source_records
                or tuple(audiences) != self.audiences or purpose != 'expression' or purpose not in self.purposes.get(source_ref,())
                or work.source_material is not self or self.scope is not work.scope
                or prepared_full_read is not None and prepared_full_read is not work.prepared):
            raise AuthorityUnavailable('Contact Host Source body changed its actual purpose/audience/Scope/Work')
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


def require_contact_host_expression_projection_v3(material,*,db,prepared,namespace,source_ref,audiences):
    if type(material) is not PreparedContactHostSourceMaterialV3:
        raise AuthorityUnavailable('Contact requires its independently issued actual Host material')
    material.require_current(db=db,prepared_full_read=prepared,namespace=namespace,
        source_ref=source_ref,audiences=audiences)
    return material.work.projection


def contact_host_expression_kwargs_v3(db):
    work = contact_host_work_for_db_v3(db)
    if work is None:
        return None
    if work.source_material is None:
        raise AuthorityUnavailable('Contact Host protected Source has not completed its actual rights/body EOF')
    return {'prepared_source_material':work.source_material,'prepared_full_read':work.prepared,'db':db}


def release_contact_host_materials_v3(work):
    _HOST_WORKS.discard(work)
    for material in tuple(_HOST_MATERIALS):
        if material.work is work:
            _HOST_MATERIALS.pop(material,None)
    if work.prepared is not None:
        _HOST_PREPARED.pop(work.prepared,None)


def track_contact_host_metadata_v3(work,registry,original):
    from .contact_host_stage_work_v3 import ContactHostStageReadWorkV3
    if type(work) is not ContactHostStageReadWorkV3:
        return False
    require_contact_host_work_v3(work)
    work.operation.retain(128)
    work.issued_capabilities.append((registry,original))
    return True



def require_contact_host_material_scope_v3(material,*,work,db):
    """Verify the actual private Source material identity and all qualified groups.

    This is a current-data check; it grants neither WRITE nor expression use.
    Expression consumers retain their original purpose-specific entry.
    """
    require_contact_host_work_v3(work,db=db)
    if (type(material) is not PreparedContactHostSourceMaterialV3
            or _HOST_MATERIALS.get(material) != material._identity_v3()
            or material.work is not work or material.scope is not work.scope
            or work.source_material is not material or material.selection is not work.source_selection
            or _HOST_READING.get() is not work or not db.in_transaction):
        raise AuthorityUnavailable('Contact Source material lacks its actual complete private producer/scope')
    material.selection.require_v3(work)
    for ref,purposes in material.selection.purpose_groups:
        if not set(purposes).issubset(material.purposes.get(ref,())):
            raise AuthorityUnavailable('Contact current Source material is missing an independently qualified purpose')
    for witness in material.witnesses.values():
        witness.require_current_v3()
    return material
