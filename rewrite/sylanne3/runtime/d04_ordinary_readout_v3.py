"""Private D04 ordinary-role readout and its separate durable support manifest."""
from dataclasses import asdict, dataclass
from weakref import WeakKeyDictionary

from ..authority_service.contract import AuthorityUnavailable
from ..graph_types import AtomKey, GraphVersion
from ..memory_types import access_key, source_key, validate_access
from ..domains.d06 import source_correction_head_key
from ..runtime_contracts import NamespaceId, canonical_digest

_ISSUED = WeakKeyDictionary()
_KEY = object()


@dataclass(frozen=True, slots=True)
class D04RoleSupportHeadV3:
    ref: str
    revision: int
    valid: bool
    cell_id: str | None


@dataclass(frozen=True, slots=True)
class D04RoleReadoutManifestV3:
    namespace: NamespaceId
    head_id: str
    plan_ref: tuple[str, int]
    activation_ref: tuple[str, int]
    purpose: str
    audience: tuple[str, ...]
    origins: tuple[dict, ...]
    support_heads: tuple[D04RoleSupportHeadV3, ...]
    access_epoch: int
    delete_epoch: int
    schema: str = 'd04.ordinary-role-support-manifest.v3'

    @property
    def digest(self):
        return canonical_digest(asdict(self))


class PreparedD04OrdinaryReadoutV3:
    def __init__(self,key,owner,head,origins,manifest):
        if key is not _KEY:
            raise TypeError('D04 readout requires actual same-Work Source ALL')
        self.owner,self.head,self.origins,self.manifest = owner,head,origins,manifest
        _ISSUED[self] = (owner,owner.operation,owner.fence,head,origins,manifest.digest)

    def require_current_v3(self,owner):
        from .d04_source_work_v3 import require_installed_d04_source_reader_v3
        require_installed_d04_source_reader_v3(owner)
        if (self.owner is not owner or _ISSUED.get(self) !=
                (owner,owner.operation,owner.fence,self.head,self.origins,self.manifest.digest)):
            raise AuthorityUnavailable('D04 ordinary readout left its actual originating Source Work')
        with owner.quantum_v3() as meter:
            owner.require_current(meter=meter)
            for head in self.manifest.support_heads:
                current = meter.read_fixed_row(owner.db,'graph_atoms',
                    ('revision','valid','value_cell_id'),'token=? AND bot=? AND persona=?',
                    (head.ref,*owner.namespace.as_tuple))
                expected = None if head.revision == 0 else (head.revision,int(head.valid),head.cell_id)
                if current != expected:
                    raise AuthorityUnavailable('D04 ordinary support Source/access/correction Head changed')
        return self

    @property
    def control(self):
        self.require_current_v3(self.owner)
        return self.owner.current_control
    @property
    def selected_readout(self):
        from .selected_persona_readout_v4 import require_selected_persona_readout_v4
        self.require_current_v3(self.owner)
        value=self.owner.selected_readout
        if value is None:raise AuthorityUnavailable('D04 selected Body was not independently prepared')
        return require_selected_persona_readout_v4(value,self.owner,None)
    @property
    def read_versions(self):
        return self.selected_readout.read_versions
    def project_selected_v4(self,*,role_binding_complete):
        from ..domains.d01 import PersonaDomain
        return PersonaDomain().project_selected_v4(self.selected_readout,
            role_binding_complete=role_binding_complete)
    def project_v3(self,plan,*,role_binding_complete):
        from ..domains.d01 import PersonaDomain
        from .d04_source_work_v3 import require_installed_d04_source_reader_v3
        owner = require_installed_d04_source_reader_v3(self.owner)
        self.require_current_v3(owner)
        if (plan.namespace != self.head.namespace or plan.head_id != self.head.head_id
                or tuple((b.block_id,canonical_digest(b.claim)) for b in plan.blocks
                    if b.block_id in {o.block.block_id for o in self.origins})
                != tuple((o.block.block_id,o.block.claim_digest) for o in self.origins)):
            raise AuthorityUnavailable('D04 decoded actual plan differs from qualified ordinary block commitments')
        return PersonaDomain().project(plan,context_tags=(),
            role_binding_complete=role_binding_complete,ordinary_readout=self)


def require_d04_ordinary_projection_v3(value,plan):
    if type(value) is not PreparedD04OrdinaryReadoutV3:
        raise AuthorityUnavailable('D04 PersonaView requires its actual privately prepared ordinary readout')
    value.require_current_v3(value.owner)
    if plan.namespace != value.head.namespace or plan.head_id != value.head.head_id:
        raise AuthorityUnavailable('D04 ordinary readout plan differs from its actual qualified head')
    return frozenset(origin.block.block_id for origin in value.origins)


def _qualify_d04_role_support_metadata_v3(owner,head_value,origins,*,purpose,audience):
    """Current Source ALL uses metadata only; support text never enters event sources."""
    ns = owner.namespace
    if purpose != 'expression' or not audience or tuple(sorted(set(audience))) != audience:
        raise AuthorityUnavailable('D04 role support requires its exact actual expression audiences')
    from ..domains.d01.production_operations_v1 import plain_v1
    atoms = {atom.key.token:atom for atom in owner.namespace_reader.atoms}
    current_sources = owner.namespace_reader.sources
    support_heads = {}

    def head(ref,revision,valid):
        actual = owner.namespace_reader.heads.get(ref)
        if revision == 0:
            if actual is not None:
                raise AuthorityUnavailable('D04 ordinary support correction absence changed')
            value = D04RoleSupportHeadV3(ref,0,False,None)
        else:
            if actual is None or actual[:2] != (revision,valid):
                raise AuthorityUnavailable('D04 ordinary support actual Head differs from metadata EOF')
            value = D04RoleSupportHeadV3(ref,revision,valid,actual[2])
        prior = support_heads.get(ref)
        if prior is not None and prior != value:
            raise AuthorityUnavailable('D04 ordinary support repeats a conflicting current Head')
        support_heads[ref] = value

    for origin in origins:
        if origin.namespace != ns or origin.active_head != head_value.head_id:
            raise AuthorityUnavailable('D04 block origin differs from actual current plan')
        active,done = set(),set()
        born = owner.origin_support_readsets.get(origin.proposal_ref, {})
        def visit(ref):
            if ref in active or len(active)+len(done) >= 256:
                raise AuthorityUnavailable('D04 ordinary support ancestry is cyclic or exceeds its bound')
            if ref in done:
                return
            key = AtomKey.from_token(ref)
            witness = current_sources.get(ref)
            if (key != source_key(*ns.as_tuple,key.owner.subject or '') or witness is None
                    or not witness.valid or witness.revision < 1
                    or born.get(key) != witness.revision):
                raise AuthorityUnavailable('D04 ordinary support Source is absent or changed from its actual producer read')
            ak = access_key(*ns.as_tuple,key.owner.subject)
            ck = source_correction_head_key(ns,key.owner.subject)
            access = atoms.get(ak.token)
            if access is None or not access.valid or ck.token in owner.namespace_reader.heads:
                raise AuthorityUnavailable('D04 ordinary support access/correction is unavailable')
            validate_access(access.value)
            raw = witness.metadata
            if (raw['source_id'] != key.owner.subject or access.value['source_id'] != raw['source_id']
                    or access.value['status'] != 'active' or purpose not in raw['purposes']
                    or purpose not in access.value['purposes']
                    or not set(audience) <= set(raw['audiences'])
                    or not set(audience) <= set(access.value['audiences'])):
                raise AuthorityUnavailable('D04 ordinary support lacks the current purpose/audience rights')
            active.add(ref)
            for parent in raw['parent_source_ids']:
                visit(source_key(*ns.as_tuple,parent).token)
            active.remove(ref)
            done.add(ref)
            head(ref,witness.revision,True)
            head(ak.token,access.revision,True)
            head(ck.token,0,False)
        for selection in origin.support:
            visit(selection.source.key.token)
            if current_sources[selection.source.key.token].revision != selection.source.revision:
                raise AuthorityUnavailable('D04 ordinary root differs from actual signed producer version')
    manifest = D04RoleReadoutManifestV3(ns,head_value.head_id,
        (head_value.plan_ref.key.token,head_value.plan_ref.revision),
        (head_value.activation_ref.key.token,head_value.activation_ref.revision),
        purpose,audience,tuple(plain_v1(o) for o in origins),
        tuple(support_heads[ref] for ref in sorted(support_heads)),
        *owner.authority_epochs)
    return manifest


def d04_role_manifest_wire_v3(manifest):
    from ..domains.d01.production_operations_v1 import plain_v1
    return plain_v1(manifest)


def validate_d04_role_manifest_wire_v3(raw,namespace):
    from ..domains.d01.production_operations_v1 import plain_v1
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    from .d01_ordinary_origin_v3 import OrdinaryBlockOriginV3
    if type(raw) is not dict or set(raw) != set(D04RoleReadoutManifestV3.__dataclass_fields__):
        raise AuthorityUnavailable('D04 durable role support manifest fields differ')
    if (raw['schema'] != 'd04.ordinary-role-support-manifest.v3'
            or raw['namespace'] != plain_v1(namespace) or raw['purpose'] != 'expression'
            or type(raw['audience']) is not list or not raw['audience']
            or raw['audience'] != sorted(set(raw['audience']))):
        raise AuthorityUnavailable('D04 durable role support actual namespace/use differs')
    for name in ('plan_ref','activation_ref'):
        value = raw[name]
        if type(value) is not list or len(value) != 2 or type(value[1]) is not int or value[1] < 1:
            raise AuthorityUnavailable('D04 durable role head version differs')
        key = AtomKey.from_token(value[0])
        if NamespaceId.from_key(key) != namespace:
            raise AuthorityUnavailable('D04 durable role head crosses namespace')
    if type(raw['origins']) is not list or type(raw['support_heads']) is not list:
        raise AuthorityUnavailable('D04 durable role support groups require complete tuples')
    seen = set()
    for original in raw['origins']:
        origin = decode_typed_production_value_v1(original,OrdinaryBlockOriginV3)
        if (origin.namespace != namespace or origin.active_head != raw['head_id']
                or origin.block.block_id in seen or plain_v1(origin) != original):
            raise AuthorityUnavailable('D04 durable ordinary origin selector differs')
        if origin.origin_kind=='ordinary_single_event_growth_v1':
            raise AuthorityUnavailable('single-event blocks require an actual scoped V4 consumer; this D04 request has no selector')
        seen.add(origin.block.block_id)
    refs = set()
    for item in raw['support_heads']:
        if type(item) is not dict or set(item) != set(D04RoleSupportHeadV3.__dataclass_fields__):
            raise AuthorityUnavailable('D04 durable support Head fields differ')
        key = AtomKey.from_token(item['ref'])
        if (NamespaceId.from_key(key) != namespace or key.type_name not in {
                'memory.source','memory.access','d06.source_correction_head.v1'}
                or item['ref'] in refs or type(item['revision']) is not int or item['revision'] < 0
                or type(item['valid']) is not bool
                or item['revision'] == 0 and (item['valid'] or item['cell_id'] is not None)
                or item['revision'] > 0 and (not item['valid'] or type(item['cell_id']) is not str)):
            raise AuthorityUnavailable('D04 durable support Head identity differs')
        refs.add(item['ref'])
    for name in ('access_epoch','delete_epoch'):
        if type(raw[name]) is not int or raw[name] < 0:
            raise AuthorityUnavailable('D04 durable support rights epoch differs')
    return raw


def d04_role_manifest_versions_v3(raw,namespace):
    validate_d04_role_manifest_wire_v3(raw,namespace)
    return tuple(GraphVersion(AtomKey.from_token(item['ref']),item['revision'])
        for item in raw['support_heads'])


def require_current_d04_role_manifest_heads_v3(db,namespace,raw):
    validate_d04_role_manifest_wire_v3(raw,namespace)
    if not db.in_transaction:
        raise AuthorityUnavailable('D04 current durable role support needs the actual pinned transaction')
    for item in raw['support_heads']:
        actual = db.execute('SELECT revision,valid,value_cell_id FROM graph_atoms WHERE token=? AND bot=? AND persona=?',
            (item['ref'],*namespace.as_tuple)).fetchone()
        expected = None if item['revision'] == 0 else (item['revision'],int(item['valid']),item['cell_id'])
        if actual != expected:
            raise AuthorityUnavailable('D04 durable ordinary support Head changed')
    rights = db.execute('SELECT access_epoch,delete_epoch FROM graph_authority_epochs WHERE bot=? AND persona=?',
        namespace.as_tuple).fetchone()
    if rights != (raw['access_epoch'],raw['delete_epoch']):
        raise AuthorityUnavailable('D04 durable ordinary support rights epoch changed')
    return raw


def require_bound_d04_role_readout_v3(db,namespace,*,frozen=None,manifest=None):
    from .d04_source_work_v3 import _BOUND,require_installed_d04_source_reader_v3
    owner = _BOUND.get()
    if owner is None:
        raise AuthorityUnavailable('D04 claim consumer lacks its independently issued current Source readout')
    require_installed_d04_source_reader_v3(owner)
    if owner.db is not db or owner.namespace != namespace or owner.write_scope is None:
        raise AuthorityUnavailable('D04 ordinary readout is outside its actual fresh-WRITE consumer')
    prepared = owner.ordinary_readout.require_current_v3(owner)
    raw = d04_role_manifest_wire_v3(prepared.manifest)
    if manifest is not None and raw != manifest:
        raise AuthorityUnavailable('D04 immutable role support differs from fresh current Source qualification')
    if frozen is not None and (frozen.input.role.head_id != owner.role.head_id
            or frozen.input.role.namespace != namespace):
        raise AuthorityUnavailable('D04 frozen persona differs from qualified actual current role')
    return prepared


def prepare_d04_ordinary_readout_v3(owner,head_value,origins,*,purpose,audience):
    from .d04_source_work_v3 import require_installed_d04_source_reader_v3
    require_installed_d04_source_reader_v3(owner)
    from .d01_single_event_readout_v4 import prepare_single_event_ordinary_controls_v4
    control=prepare_single_event_ordinary_controls_v4(owner,origins)
    origins=control.origins
    manifest = _qualify_d04_role_support_metadata_v3(owner,head_value,origins,purpose=purpose,audience=audience)
    return PreparedD04OrdinaryReadoutV3(_KEY,owner,head_value,origins,manifest)


def release_prepared_d04_ordinary_readout_v3(value):
    if type(value)is PreparedD04OrdinaryReadoutV3:
        from .selected_persona_readout_v4 import release_selected_persona_readout_v4
        release_selected_persona_readout_v4(value.owner)
        _ISSUED.pop(value,None)



def current_d04_ordinary_block_mask_v4(owner):
    from .d04_source_work_v3 import require_installed_d04_source_reader_v3
    require_installed_d04_source_reader_v3(owner)
    prepared=owner.ordinary_readout
    if type(prepared)is not PreparedD04OrdinaryReadoutV3:
        raise AuthorityUnavailable('D04 block Body requires its actual completed metadata/Source readout')
    prepared.require_current_v3(owner)
    return frozenset(origin.block.block_id for origin in prepared.origins)


def require_bound_d04_selected_persona_readout_v4(db,namespace,*,frozen=None,manifest=None):
    return require_bound_d04_role_readout_v3(db,namespace,frozen=frozen,manifest=manifest).selected_readout
