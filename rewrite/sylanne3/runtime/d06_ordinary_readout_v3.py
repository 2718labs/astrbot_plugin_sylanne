"""Ordinary persona disclosure owned by exact internal-Life Numeric consumers.

The existing Numeric READ/Owner/source kernels supply physical mechanics. This
module issues a separate consolidation/audience proof, never a D04 capability.
"""
from contextlib import contextmanager
from dataclasses import asdict,dataclass,replace
from weakref import WeakKeyDictionary

from ..authority_service.contract import AuthorityUnavailable
from ..graph_types import AtomKey,GraphAtom,GraphSnapshot,GraphVersion,NamespaceEpoch,Owner,owner_grant_key
from ..memory_types import access_key,source_key,validate_access
from ..domains.d06 import source_correction_head_key
from ..runtime_contracts import NamespaceId,canonical_digest

_KEY=object()
_OWNERS=WeakKeyDictionary()
_HOST=WeakKeyDictionary()
_AUTHORITY=WeakKeyDictionary()
_ISSUED=WeakKeyDictionary()
_ROLE_OPERATIONS=frozenset({
    'prepare_internal_life_numeric','acquire_internal_life_numeric','adopt_internal_life_numeric',
    'prepare_internal_life_numeric_drive','prepare_internal_life_numeric_joint',
    'prepare_internal_life_interval_baseline','adopt_internal_life_numeric_trace',
    'read_current_life_numeric_model_draft_v3','qualify_current_life_numeric_candidate_v3',
    'read_current_life_numeric_joint_prepared_v3','read_current_life_numeric_trace_v3'})


class _LifeOrdinaryOriginOwnerV3:
    def __init__(self,key,consumer,*,authority):
        if key is not _KEY:raise TypeError('actual Life Numeric origin issuer required')
        self.consumer,self.is_authority=consumer,authority
        work=consumer.work
        self.work,self.db,self.namespace,self.operation=work,consumer.db,consumer.namespace,consumer.operation
        self.origin_signer=(consumer.installed_reader.readers.issuer._signer if authority
            else consumer.graph._GraphCoordinator__d11_issuer._signer)
        self.origin_columns,self.origin_support_readsets,self.origin_history=[],{},{}
        self.namespace_reader=self
        self.control=self.head=self.origins=self.readout=self.selected_readout=None
        self.control_atoms=[]
        self.support_atoms={}
        self.support_sources={}
        self.authority_epochs=(tuple(work.graph_stamp[1:]) if authority else tuple(consumer.authority_epochs))
        self.purpose='consolidation'
        self.audience=tuple(consumer.prepared_metadata['audience']) if authority else tuple(consumer.authority.audience)
        _OWNERS[self]=(consumer,work,self.operation,work.selection_digest,authority,self.audience)
    @property
    def heads(self):
        return self.work.heads if self.is_authority else self.consumer.heads
    @property
    def atoms(self):
        return tuple(self.work.members.values()) if self.is_authority else tuple(self.support_atoms.values())
    @property
    def sources(self):
        return self.work.sources if self.is_authority else self.support_sources
    @contextmanager
    def quantum_v3(self):
        require_life_ordinary_origin_owner_v3(self)
        if self.is_authority:
            with self.work.quantum_v3() as meter:yield meter
        else:
            from ..runtime_storage_v3 import runtime_storage_quantum_v3
            r=self.consumer
            with r.store._lock,runtime_storage_quantum_v3(r.db) as meter:
                r.require_current(meter=meter)
                yield meter
                r.require_current(meter=meter)


def is_life_ordinary_origin_owner_v3(value):
    return type(value)is _LifeOrdinaryOriginOwnerV3 and value in _OWNERS


def require_life_ordinary_origin_owner_v3(value):
    if type(value)is not _LifeOrdinaryOriginOwnerV3:
        raise AuthorityUnavailable('Life ordinary origin requires its actual Numeric adapter')
    c,w=value.consumer,value.work
    if (_OWNERS.get(value)!=(c,w,value.operation,w.selection_digest,value.is_authority,value.audience)
            or w.operation is not value.operation or value.operation.closed):
        raise AuthorityUnavailable('Life ordinary origin left its actual Work/selection/lifetime')
    if value.is_authority:
        from ..authority_service.life_numeric_source_read_v3 import require_authority_numeric_metadata_work_v3
        require_authority_numeric_metadata_work_v3(c)
        if not c.complete or w.namespace_reader is None or not w.namespace_reader.graph_eof:
            raise AuthorityUnavailable('Life Authority role requires its own complete event Source/namespace EOF')
        if tuple(c.prepared_metadata['audience'])!=value.audience:
            raise AuthorityUnavailable('Life Authority role changed its actual acquired audience')
    else:
        from .current_life_numeric_metadata_v1 import require_numeric_owner_metadata_work_v1
        require_numeric_owner_metadata_work_v1(c)
        if (c.operation_kind not in _ROLE_OPERATIONS or not c.inventory_sealed
                or c.general_owner_entry is None or c.authority.purpose not in {'context','consolidation'}
                or tuple(c.authority.audience)!=value.audience):
            raise AuthorityUnavailable('Life role requires its exact consolidation Numeric READ')
        if c.read_finished:
            from .current_method_learning_read_v3 import _require_current_general_method_source_write_phase_v1
            _require_current_general_method_source_write_phase_v1(c)
        else:c.general_owner_entry.require_for_v3(c)
    grant_purposes=c.owner_entry.grant['purposes'] if value.is_authority else c.owner_binding.purposes
    if 'consolidation' not in grant_purposes:
        raise AuthorityUnavailable('Life role requires actual Owner consolidation permission')
    if len(value.audience)!=1 or not value.audience[0] or value.audience[0]=='*':
        raise AuthorityUnavailable('Life role requires its actual single installed audience')
    w._require_invocation(c.graph) if not value.is_authority else w._actual()
    return value


def _prepare_control_and_origins_v3(owner):
    from .d01_ordinary_origin_read_v3 import _column,read_current_ordinary_origins_v3
    from ..domains.d01 import PersonaDomain
    if owner.head is not None:return
    ns=owner.namespace
    keys=(AtomKey(Owner('persona',*ns.as_tuple),'d01.persona_activation.v1','current'),owner_grant_key(*ns.as_tuple))
    atoms=[]
    for key in keys:
        header=owner.heads.get(key.token)
        if header is None or not header[1]:raise AuthorityUnavailable('Life actual role control Head unavailable')
        column=_column(owner,'graph_atoms','value',('token',),(key.token,),'activation',cell_id=header[2])
        atoms.append(GraphAtom(key,header[0],column.metadata,True))
    c=owner.consumer
    guard=c.owner_entry.head.guard if owner.is_authority else c.owner_guard
    epoch=NamespaceEpoch(*ns.as_tuple,owner.work.graph_stamp[0]) if owner.is_authority else c.graph_stamp[1]
    control=PersonaDomain.resolve_active_role_control_v3(GraphSnapshot(tuple(atoms),(epoch,)),
        namespace=ns,current_guard=guard)
    owner.control_atoms=atoms
    owner.control=control
    owner.head,owner.origins=read_current_ordinary_origins_v3(owner,control)
    actual=owner.heads.get(owner.head.plan_ref.key.token)
    if actual is None or actual[:2]!=(owner.head.plan_ref.revision,True):
        raise AuthorityUnavailable('Life actual current plan differs from reconstructed ordinary lineage')
    owner.control=replace(control,read_versions=(control.read_versions[0],owner.head.plan_ref,control.read_versions[1]))


@dataclass(frozen=True, slots=True)
class LifeOrdinarySupportHeadV3:
    ref: str
    revision: int
    valid: bool
    cell_id: str | None


@dataclass(frozen=True, slots=True)
class LifeOrdinaryReadoutManifestV3:
    namespace: NamespaceId
    head_id: str
    plan_ref: tuple[str, int]
    activation_ref: tuple[str, int]
    purpose: str
    audience: tuple[str, ...]
    origins: tuple[dict, ...]
    support_heads: tuple[LifeOrdinarySupportHeadV3, ...]
    access_epoch: int
    delete_epoch: int
    schema: str = 'd06.ordinary-role-support-manifest.v3'

    @property
    def digest(self):
        return canonical_digest(asdict(self))


@dataclass(frozen=True, slots=True)
class LifeOrdinaryReadoutManifestV4:
    namespace: NamespaceId
    head_id: str
    plan_ref: tuple[str, int]
    activation_ref: tuple[str, int]
    purpose: str
    audience: tuple[str, ...]
    origins: tuple[dict, ...]
    support_heads: tuple[LifeOrdinarySupportHeadV3, ...]
    access_epoch: int
    delete_epoch: int
    single_event_controls: tuple
    schema: str = 'd06.ordinary-role-support-manifest.v4'

    @property
    def digest(self):
        return canonical_digest(asdict(self))


def _qualify_life_role_support_metadata_v3(owner,head_value,origins,*,purpose,audience,extra_sources=()):
    """Current Source ALL uses metadata only; support text never enters event sources."""
    ns = owner.namespace
    if purpose != 'consolidation' or not audience or tuple(sorted(set(audience))) != audience:
        raise AuthorityUnavailable('Life role support requires its exact actual consolidation audiences')
    from ..domains.d01.production_operations_v1 import plain_v1
    atoms = {atom.key.token:atom for atom in owner.namespace_reader.atoms}
    current_sources = owner.namespace_reader.sources
    support_heads = {}

    def head(ref,revision,valid):
        actual = owner.namespace_reader.heads.get(ref)
        if revision == 0:
            if actual is not None:
                raise AuthorityUnavailable('Life ordinary support correction absence changed')
            value = LifeOrdinarySupportHeadV3(ref,0,False,None)
        else:
            if actual is None or actual[:2] != (revision,valid):
                raise AuthorityUnavailable('Life ordinary support actual Head differs from metadata EOF')
            value = LifeOrdinarySupportHeadV3(ref,revision,valid,actual[2])
        prior = support_heads.get(ref)
        if prior is not None and prior != value:
            raise AuthorityUnavailable('Life ordinary support repeats a conflicting current Head')
        support_heads[ref] = value

    def visit(ref,born,active,done):
        if ref in active or len(active)+len(done) >= 256:
            raise AuthorityUnavailable('Life ordinary support ancestry is cyclic or exceeds its bound')
        if ref in done:
            return
        key = AtomKey.from_token(ref)
        witness = current_sources.get(ref)
        if (key != source_key(*ns.as_tuple,key.owner.subject or '') or witness is None
                or not witness.valid or witness.revision < 1
                or born is not None and born.get(key) != witness.revision):
            raise AuthorityUnavailable('Life ordinary support Source is absent or changed from its actual producer read')
        ak = access_key(*ns.as_tuple,key.owner.subject)
        ck = source_correction_head_key(ns,key.owner.subject)
        access = atoms.get(ak.token)
        if access is None or not access.valid or ck.token in owner.namespace_reader.heads:
            raise AuthorityUnavailable('Life ordinary support access/correction is unavailable')
        validate_access(access.value)
        raw = witness.metadata
        if (raw['source_id'] != key.owner.subject or access.value['source_id'] != raw['source_id']
                or access.value['status'] != 'active' or purpose not in raw['purposes']
                or purpose not in access.value['purposes']
                or not set(audience) <= set(raw['audiences'])
                or not set(audience) <= set(access.value['audiences'])):
            raise AuthorityUnavailable('Life ordinary support lacks the current purpose/audience rights')
        active.add(ref)
        for parent in raw['parent_source_ids']:
            visit(source_key(*ns.as_tuple,parent).token,born,active,done)
        active.remove(ref)
        done.add(ref)
        head(ref,witness.revision,True)
        head(ak.token,access.revision,True)
        head(ck.token,0,False)
    for origin in origins:
        if origin.namespace != ns or origin.active_head != head_value.head_id:
            raise AuthorityUnavailable("Life block origin differs from actual current plan")
        active,done=set(),set()
        born=owner.origin_support_readsets.get(origin.proposal_ref,{})
        for selection in origin.support:
            visit(selection.source.key.token,born,active,done)
            if current_sources[selection.source.key.token].revision != selection.source.revision:
                raise AuthorityUnavailable("Life ordinary root differs from actual signed producer version")
    active,done=set(),set()
    for token in extra_sources:visit(token,None,active,done)
    manifest = LifeOrdinaryReadoutManifestV3(ns,head_value.head_id,
        (head_value.plan_ref.key.token,head_value.plan_ref.revision),
        (head_value.activation_ref.key.token,head_value.activation_ref.revision),
        purpose,audience,tuple(plain_v1(o) for o in origins),
        tuple(support_heads[ref] for ref in sorted(support_heads)),
        *owner.authority_epochs)
    return manifest



class PreparedLifeOrdinaryReadoutV3:
    def __init__(self,key,owner,manifest):
        if key is not _KEY:raise TypeError('actual Life consolidation Source ALL required')
        self.owner,self.manifest=owner,manifest
        _ISSUED[self]=(owner,owner.operation,owner.work,manifest.digest)
    def require_current_v3(self):
        o=require_life_ordinary_origin_owner_v3(self.owner)
        if _ISSUED.get(self)!=(o,o.operation,o.work,self.manifest.digest):
            raise AuthorityUnavailable('Life readout lost its private same-Work issuance')
        with o.quantum_v3() as meter:
            _require_manifest_heads_v3(o.db,self.manifest,meter)
        if type(self.manifest)is LifeOrdinaryReadoutManifestV4:
            from .d01_single_event_readout_v4 import require_current_single_event_controls_v4
            require_current_single_event_controls_v4(o,self.manifest.single_event_controls)
        return self
    @property
    def control(self):
        self.require_current_v3()
        return self.owner.control
    @property
    def selected_readout(self):
        from .selected_persona_readout_v4 import require_selected_persona_readout_v4
        self.require_current_v3()
        value=self.owner.selected_readout
        if value is None:raise AuthorityUnavailable('Life selected Body was not independently prepared')
        return require_selected_persona_readout_v4(value,self.owner,value.consumer_scope)
    @property
    def read_versions(self):
        return self.selected_readout.read_versions
    def project_selected_v4(self,*,role_binding_complete=False):
        from ..domains.d01 import PersonaDomain
        return PersonaDomain().project_selected_v4(self.selected_readout,
            role_binding_complete=role_binding_complete)
    def project_v3(self,plan):
        from ..domains.d01 import PersonaDomain
        self.require_current_v3()
        if (plan.namespace!=self.manifest.namespace or plan.head_id!=self.manifest.head_id
                or tuple((b.block_id,canonical_digest(b.claim))for b in plan.blocks
                    if b.block_id in {o.block.block_id for o in self.owner.origins})
                    !=tuple((o.block.block_id,o.block.claim_digest)for o in self.owner.origins)):
            raise AuthorityUnavailable('Life decoded actual plan differs from its Source-qualified commitments')
        return PersonaDomain().project(plan,context_tags=(),role_binding_complete=False,ordinary_readout=self)


def require_life_ordinary_projection_v3(value,plan):
    if type(value)is not PreparedLifeOrdinaryReadoutV3 or value.owner.is_authority:
        raise AuthorityUnavailable('Life PersonaView requires its actual Host Numeric Source proof')
    value.require_current_v3()
    if (plan.namespace!=value.manifest.namespace or plan.head_id!=value.manifest.head_id
            or tuple((b.block_id,canonical_digest(b.claim))for b in plan.blocks
                if b.block_id in {o.block.block_id for o in value.owner.origins})
                !=tuple((o.block.block_id,o.block.claim_digest)for o in value.owner.origins)):
        raise AuthorityUnavailable('Life ordinary readout differs from its actual original plan commitments')
    return frozenset(o.block.block_id for o in value.owner.origins)


def prepare_current_life_ordinary_readout_v3(reader):
    if reader.operation_kind not in _ROLE_OPERATIONS:return None
    from .current_life_numeric_metadata_v1 import require_numeric_owner_metadata_work_v1
    from .current_method_learning_read_v3 import qualify_method_source_metadata_kernel_v1,_GENERAL_METHOD_SOURCE_TASKS_V1,method_graph_head_v3
    require_numeric_owner_metadata_work_v1(reader)
    owner=_HOST.get(reader)
    if owner is None:
        if reader.db.in_transaction:raise AuthorityUnavailable('Life role origin preparation must precede Graph transaction')
        owner=_LifeOrdinaryOriginOwnerV3(_KEY,reader,authority=False);_HOST[reader]=owner
    if owner.readout is not None:
        _prepare_life_selected_v4(owner)
        return owner.readout.require_current_v3()
    _prepare_control_and_origins_v3(owner)
    from .d01_single_event_readout_v4 import prepare_single_event_ordinary_controls_v4,finish_single_event_ordinary_controls_v4
    control=prepare_single_event_ordinary_controls_v4(owner,owner.origins)
    owner.origins=control.origins
    roots=tuple(sorted({s.source.key.token for origin in owner.origins for s in origin.support}|set(control.source_roots)))
    records,_=qualify_method_source_metadata_kernel_v1(reader,roots,
        purposes=tuple(dict.fromkeys((reader.authority.purpose,'consolidation'))))
    owner.support_sources={ref:_GENERAL_METHOD_SOURCE_TASKS_V1[reader][ref] for ref in records}
    for ref in records:
        key=AtomKey.from_token(ref)
        for selected in (access_key(*reader.namespace.as_tuple,key.owner.subject),source_correction_head_key(reader.namespace,key.owner.subject)):
            atom=method_graph_head_v3(reader.db,reader.namespace,selected)
            owner.support_atoms[selected.token]=atom
    manifest=_qualify_life_role_support_metadata_v3(owner,owner.head,owner.origins,
        purpose='consolidation',audience=owner.audience,extra_sources=control.source_roots)
    controls,owner.origins=finish_single_event_ordinary_controls_v4(owner,control,manifest.support_heads)
    manifest=_life_manifest_with_controls_v4(manifest,owner.origins,controls)
    reader.operation.retain(_heap_manifest_v3(manifest)+4096)
    owner.readout=PreparedLifeOrdinaryReadoutV3(_KEY,owner,manifest)
    _prepare_life_selected_v4(owner)
    return owner.readout.require_current_v3()


def _heap_manifest_v3(manifest):
    from .dispatch_current_inventory_v3 import _heap
    return _heap(asdict(manifest))*3


def require_bound_life_ordinary_readout_v3(db,*,frame=None):
    from .current_method_learning_read_v3 import _method_active
    reader=_method_active(db)
    owner=None if reader is None else _HOST.get(reader)
    if owner is None or owner.readout is None:
        raise AuthorityUnavailable('Life actual ordinary Source preparation is unavailable')
    value=owner.readout.require_current_v3()
    if frame is not None and (frame.envelope.authority.namespace!=owner.namespace
            or frame.envelope.authority.purpose not in {'context','consolidation'}
            or frame.envelope.authority.audience!=owner.audience):
        raise AuthorityUnavailable('Life frame changed its actual readout purpose/audience')
    return value


def life_role_manifest_wire_v3(manifest):
    from ..domains.d01.production_operations_v1 import plain_v1
    return plain_v1(manifest)


def validate_life_role_manifest_wire_v3(raw,namespace):
    if type(raw)is dict and raw.get("schema")=="d06.ordinary-role-support-manifest.v4":
        return _validate_life_role_manifest_wire_v4(raw,namespace)
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    from .d01_ordinary_origin_v3 import OrdinaryBlockOriginV3
    if (type(raw)is not dict or set(raw)!=set(LifeOrdinaryReadoutManifestV3.__dataclass_fields__)
            or raw['schema']!='d06.ordinary-role-support-manifest.v3'
            or raw['namespace']!={'bot_id':namespace.bot_id,'persona_id':namespace.persona_id}
            or raw['purpose']!='consolidation' or type(raw['audience'])is not list
            or len(raw['audience'])!=1 or not raw['audience'][0] or raw['audience'][0]=='*'):
        raise AuthorityUnavailable('Life durable role manifest needs its actual consolidation/single audience')
    value=LifeOrdinaryReadoutManifestV3(namespace,raw['head_id'],tuple(raw['plan_ref']),
        tuple(raw['activation_ref']),raw['purpose'],tuple(raw['audience']),tuple(raw['origins']),
        tuple(LifeOrdinarySupportHeadV3(**h)for h in raw['support_heads']),raw['access_epoch'],raw['delete_epoch'])
    if life_role_manifest_wire_v3(value)!=raw:raise AuthorityUnavailable('Life role manifest wire differs')
    for ref,revision in (value.plan_ref,value.activation_ref):
        if NamespaceId.from_key(AtomKey.from_token(ref))!=namespace or type(revision)is not int or revision<1:
            raise AuthorityUnavailable('Life role manifest has a foreign or nonpositive control version')
    origins=tuple(decode_typed_production_value_v1(item,OrdinaryBlockOriginV3)for item in value.origins)
    if len({o.block.block_id for o in origins})!=len(origins):raise AuthorityUnavailable('Life ordinary origins repeat a block')
    if any(o.origin_kind=='ordinary_single_event_growth_v1'for o in origins):
        raise AuthorityUnavailable('single-event origins cannot downgrade to the V3 Life support wire')
    if any(o.namespace!=namespace or o.active_head!=value.head_id for o in origins):
        raise AuthorityUnavailable('Life ordinary origin manifest changed its actual head')
    if any(type(v)is not int or v<0 for v in (value.access_epoch,value.delete_epoch)):
        raise AuthorityUnavailable('Life role manifest rights epochs differ')
    heads=value.support_heads
    if len({h.ref for h in heads})!=len(heads):raise AuthorityUnavailable('Life role support Head repeats')
    for h in heads:
        key=AtomKey.from_token(h.ref)
        if (NamespaceId.from_key(key)!=namespace or key.type_name not in {'memory.source','memory.access','d06.source_correction_head.v1'}
                or type(h.revision)is not int or h.revision<0 or h.revision==0 and (h.valid or h.cell_id is not None)
                or h.revision>0 and not h.valid):
            raise AuthorityUnavailable('Life role support Head metadata differs')
    return value


def _require_manifest_heads_v3(db,manifest,meter):
    rights=meter.read_fixed_row(db,'graph_authority_epochs',('access_epoch','delete_epoch'),
        'bot=? AND persona=?',manifest.namespace.as_tuple)
    if rights!=(manifest.access_epoch,manifest.delete_epoch):
        raise AuthorityUnavailable('Life ordinary Source access/deletion epoch changed')
    for ref,revision in (manifest.plan_ref,manifest.activation_ref):
        row=meter.read_fixed_row(db,'graph_atoms',('revision','valid'),'token=? AND bot=? AND persona=?',(ref,*manifest.namespace.as_tuple))
        if row!=(revision,1):raise AuthorityUnavailable('Life actual current role head changed')
    current_heads=[];physical_change=False
    for h in manifest.support_heads:
        row=meter.read_fixed_row(db,'graph_atoms',('revision','valid','value_cell_id'),
            'token=? AND bot=? AND persona=?',(h.ref,*manifest.namespace.as_tuple))
        if row==(None if h.revision==0 else (h.revision,1,h.cell_id)):
            current_heads.append(h)
        elif h.revision>0 and row is not None and row[:2]==(h.revision,1):
            current_heads.append(replace(h,cell_id=row[2]));physical_change=True
        else:
            raise AuthorityUnavailable('Life current ordinary Source/access/correction Head changed')
    if physical_change:
        owner=_bound_life_control_owner_v4(db,manifest.namespace)
        _require_life_manifest_match_v1(owner,manifest,
            replace(manifest,support_heads=tuple(current_heads)),meter=meter)


def _require_life_manifest_match_v1(owner,old,current,*,meter=None):
    from .role_manifest_logical_preservation_v1 import (
        prepare_role_manifest_logical_preservation_v1,
        require_role_manifest_logical_preservation_v1)
    old_wire=life_role_manifest_wire_v3(old)if type(old)in (
        LifeOrdinaryReadoutManifestV3,LifeOrdinaryReadoutManifestV4)else old
    current_wire=life_role_manifest_wire_v3(current)if type(current)in (
        LifeOrdinaryReadoutManifestV3,LifeOrdinaryReadoutManifestV4)else current
    validate_life_role_manifest_wire_v3(old_wire,owner.namespace)
    validate_life_role_manifest_wire_v3(current_wire,owner.namespace)
    if old_wire==current_wire:return
    task=prepare_role_manifest_logical_preservation_v1(owner,old_wire,current_wire)
    if meter is not None:
        return require_role_manifest_logical_preservation_v1(task,owner,old_wire,current_wire,meter=meter)
    from ..runtime_storage_v3 import runtime_storage_quantum_v3
    with runtime_storage_quantum_v3(owner.db)as actual:
        return require_role_manifest_logical_preservation_v1(task,owner,old_wire,current_wire,meter=actual)


def require_life_role_manifest_current_v3(db,namespace,raw):
    from ..runtime_storage_v3 import runtime_storage_quantum_v3
    manifest=validate_life_role_manifest_wire_v3(raw,namespace)
    with runtime_storage_quantum_v3(db)as meter:_require_manifest_heads_v3(db,manifest,meter)
    if type(manifest)is LifeOrdinaryReadoutManifestV4:
        from .d01_single_event_readout_v4 import require_current_single_event_controls_v4
        require_current_single_event_controls_v4(_bound_life_control_owner_v4(db,namespace),manifest.single_event_controls)
    return manifest


def compose_life_ordinary_metadata_cas_v3(db,prepared_inputs,read_versions,limits):
    from .current_method_learning_read_v3 import PreparedMethodDomainInputsV3
    if type(prepared_inputs)is not PreparedMethodDomainInputsV3:return read_versions
    reader=prepared_inputs.owner
    if reader.operation_kind not in _ROLE_OPERATIONS:return read_versions
    proof=require_bound_life_ordinary_readout_v3(db)
    full={v.key:v.revision for v in read_versions}
    manifest=proof.manifest
    additions=[GraphVersion(AtomKey.from_token(h.ref),h.revision)for h in manifest.support_heads]
    additions.extend(GraphVersion(AtomKey.from_token(ref),rev)for ref,rev in (manifest.plan_ref,manifest.activation_ref))
    if type(manifest)is LifeOrdinaryReadoutManifestV4:
        from .d01_single_event_readout_v4 import single_event_control_versions_v4
        additions.extend(single_event_control_versions_v4(manifest.single_event_controls))
    for v in additions:
        if v.key in full and full[v.key]!=v.revision:raise AuthorityUnavailable('Life Body and separate support guards disagree')
        full[v.key]=v.revision
    if len(full)>limits.max_graph_heads:raise AuthorityUnavailable('Life complete guards exceed original head bound')
    return tuple(GraphVersion(k,rev)for k,rev in sorted(full.items(),key=lambda item:item[0].token))


def require_life_ordinary_body_v3(reader):
    if reader.operation_kind in _ROLE_OPERATIONS:
        owner=_HOST.get(reader)
        if owner is None or owner.readout is None:raise AuthorityUnavailable('Life Body requires its own completed role Source ALL')
        owner.readout.require_current_v3()


def require_life_original_manifest_v3(reader,raw):
    if reader.operation_kind not in _ROLE_OPERATIONS:return
    owner=_HOST.get(reader)
    if owner is None or owner.readout is None:raise AuthorityUnavailable('Life original role readout not prepared')
    manifest=raw.get('role_support_manifest')
    validate_life_role_manifest_wire_v3(manifest,reader.namespace)
    _require_life_manifest_match_v1(owner,manifest,owner.readout.manifest)


def prepare_authority_life_ordinary_readout_v3(work):
    from ..authority_service.life_numeric_source_read_v3 import numeric_authority_source_reader_v3
    consumer=numeric_authority_source_reader_v3(work)
    if consumer is None:return None
    owner=_AUTHORITY.get(work)
    if owner is not None and owner.readout is not None:
        _prepare_life_selected_v4(owner)
        return owner.readout.require_current_v3()
    if work.db.in_transaction or work.phase!='validate':
        raise AuthorityUnavailable('Life Authority ordinary Source must precede frozen request Body')
    if owner is None:
        owner=_LifeOrdinaryOriginOwnerV3(_KEY,consumer,authority=True);_AUTHORITY[work]=owner
    _prepare_control_and_origins_v3(owner)
    from .d01_single_event_readout_v4 import prepare_single_event_ordinary_controls_v4,finish_single_event_ordinary_controls_v4
    control=prepare_single_event_ordinary_controls_v4(owner,owner.origins)
    owner.origins=control.origins
    manifest=_qualify_life_role_support_metadata_v3(owner,owner.head,owner.origins,
        purpose='consolidation',audience=owner.audience,extra_sources=control.source_roots)
    controls,owner.origins=finish_single_event_ordinary_controls_v4(owner,control,manifest.support_heads)
    manifest=_life_manifest_with_controls_v4(manifest,owner.origins,controls)
    raw=consumer.prepared_metadata.get('role_support_manifest')
    validate_life_role_manifest_wire_v3(raw,owner.namespace)
    _require_life_manifest_match_v1(owner,raw,manifest)
    owner.operation.retain(_heap_manifest_v3(manifest)+4096)
    owner.readout=PreparedLifeOrdinaryReadoutV3(_KEY,owner,manifest)
    _prepare_life_selected_v4(owner)
    return owner.readout.require_current_v3()


def require_authority_life_ordinary_readout_v3(db,installed_reader,intent,prepared):
    from ..authority_service.current_authority_graph_read_v3 import _authority_attachment_owner_v3
    work=_authority_attachment_owner_v3(db)
    owner=None if work is None else _AUTHORITY.get(work)
    if (owner is None or owner.consumer.installed_reader is not installed_reader
            or work.request!=intent or owner.readout is None):
        raise AuthorityUnavailable('Life frozen Body requires its own completed Authority ordinary Source proof')
    owner.readout.require_current_v3()
    _require_life_manifest_match_v1(owner,prepared.role_support_manifest,owner.readout.manifest)
    return owner.readout.manifest


def release_life_ordinary_readout_v3(consumer):
    owner=_HOST.pop(consumer,None) or _AUTHORITY.pop(consumer,None)
    if owner is None:return
    from .role_manifest_logical_preservation_v1 import release_role_manifest_logical_preservation_v1
    release_role_manifest_logical_preservation_v1(owner)
    from .d01_single_event_readout_v4 import release_single_event_readout_v4
    release_single_event_readout_v4(owner)
    from .selected_persona_readout_v4 import release_selected_persona_readout_v4
    release_selected_persona_readout_v4(owner)
    _OWNERS.pop(owner,None)
    if owner.readout is not None:_ISSUED.pop(owner.readout,None)
    owner.origin_columns.clear();owner.origin_support_readsets.clear();owner.origin_history.clear()
    owner.control_atoms.clear();owner.support_atoms.clear();owner.support_sources.clear()
    owner.control=owner.head=owner.origins=owner.readout=owner.selected_readout=None


def life_role_manifest_versions_v3(raw,namespace):
    manifest=validate_life_role_manifest_wire_v3(raw,namespace)
    versions=tuple(GraphVersion(AtomKey.from_token(h.ref),h.revision)for h in manifest.support_heads)
    if type(manifest)is LifeOrdinaryReadoutManifestV4:
        from .d01_single_event_readout_v4 import single_event_control_versions_v4
        versions+=single_event_control_versions_v4(manifest.single_event_controls)
    return versions



def _life_manifest_with_controls_v4(base,origins,controls):
    from ..domains.d01.production_operations_v1 import plain_v1
    fields=(base.namespace,base.head_id,base.plan_ref,base.activation_ref,base.purpose,base.audience,
        tuple(plain_v1(o)for o in origins),base.support_heads,base.access_epoch,base.delete_epoch)
    return LifeOrdinaryReadoutManifestV4(*fields,controls)if controls else LifeOrdinaryReadoutManifestV3(*fields)


def _validate_life_role_manifest_wire_v4(raw,namespace):
    from .d01_single_event_readout_v4 import validate_single_event_controls_wire_v4
    if set(raw)!=set(LifeOrdinaryReadoutManifestV4.__dataclass_fields__):
        raise AuthorityUnavailable('Life V4 manifest differs from its closed registered fields')
    common={key:value for key,value in raw.items()if key!='single_event_controls'}
    common['schema']='d06.ordinary-role-support-manifest.v3'
    common['origins']=[item for item in raw['origins']if item['origin_kind']!='ordinary_single_event_growth_v1']
    # Shared structural validation is not a permission downgrade; V4 controls remain mandatory below.
    base=validate_life_role_manifest_wire_v3(common,namespace)
    controls=validate_single_event_controls_wire_v4(raw['single_event_controls'],namespace)
    if not controls:raise AuthorityUnavailable('Life V4 requires its actual scoped single-event controls')
    single={o['block']['block_id']for o in raw['origins']if o['origin_kind']=='ordinary_single_event_growth_v1'}
    if single!={c.block_id for c in controls}:
        raise AuthorityUnavailable('Life single-event origin/control membership differs')
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    from .d01_ordinary_origin_v3 import OrdinaryBlockOriginV3
    actual_origins=tuple(decode_typed_production_value_v1(item,OrdinaryBlockOriginV3)for item in raw["origins"])
    if (len({o.block.block_id for o in actual_origins})!=len(actual_origins)
            or any(o.namespace!=namespace or o.active_head!=base.head_id for o in actual_origins)):
        raise AuthorityUnavailable("Life V4 origin selectors differ from its actual head")
    value=LifeOrdinaryReadoutManifestV4(base.namespace,base.head_id,base.plan_ref,base.activation_ref,
        base.purpose,base.audience,tuple(raw["origins"]),base.support_heads,base.access_epoch,base.delete_epoch,controls)
    if life_role_manifest_wire_v3(value)!=raw:raise AuthorityUnavailable('Life V4 canonical wire differs')
    return value


def _bound_life_control_owner_v4(db,namespace):
    from ..runtime_storage_v3 import runtime_storage_v3,_operation
    active=_operation(runtime_storage_v3(db))
    owners=tuple(owner for owner in (*_HOST.values(),*_AUTHORITY.values())
        if owner.db is db and owner.namespace==namespace and owner.operation is active)
    if len(owners)!=1:raise AuthorityUnavailable('Life V4 current controls require their actual unique bound Source Work')
    return require_life_ordinary_origin_owner_v3(owners[0])



def current_life_ordinary_block_mask_v4(reader):
    owner=_HOST.get(reader)or _AUTHORITY.get(reader)
    if owner is None or owner.readout is None:
        raise AuthorityUnavailable('Life block Body requires its actual completed scope/controls/Source ALL')
    owner.readout.require_current_v3()
    return frozenset(origin.block.block_id for origin in owner.origins)


def _prepare_life_selected_v4(owner):
    from .selected_persona_readout_v4 import (current_selected_persona_scope_v4,
        prepare_selected_persona_readout_v4)
    scope=current_selected_persona_scope_v4(owner)
    owner.selected_readout=prepare_selected_persona_readout_v4(owner,owner.control,owner.head,
        actual_scope=scope,read_values=True)
    return owner.selected_readout


def require_bound_life_selected_persona_readout_v4(db,namespace,*,frame=None):
    owner=_bound_life_control_owner_v4(db,namespace)
    if frame is not None and (frame.envelope.authority.namespace!=owner.namespace
            or frame.envelope.authority.purpose not in {'context','consolidation'}
            or frame.envelope.authority.audience!=owner.audience):
        raise AuthorityUnavailable('Life selected readout changed its actual frame use')
    if owner.readout is None:raise AuthorityUnavailable('Life selected readout not prepared')
    return owner.readout.selected_readout
