"""Selected persona Body on independently qualified ordinary consumer Works.

The complete plan is scanned canonically, but only permitted claim paths and
separately requested value rules are retained. No partial PersonaPlan is made.
"""
from dataclasses import dataclass
from weakref import WeakKeyDictionary

from ..authority_service.contract import AuthorityUnavailable
from ..domains.d01 import ActiveRoleHeadControlV3, PersonaBlock, ValueRule
from ..graph_types import GraphVersion, NamespaceEpoch
from ..runtime_contracts import canonical_digest
from .d01_ordinary_origin_stream_v3 import OrdinaryOriginMetadataStreamV3
from .d01_ordinary_origin_read_v3 import OrdinaryOriginColumnV3, _actual, _fixed
from .d01_ordinary_origin_v3 import OrdinaryHeadCommitmentV3

_KEY = object()
_PARTS = WeakKeyDictionary()
_ISSUED = WeakKeyDictionary()
_READOUTS = WeakKeyDictionary()


def _need(value, reason):
    if not value:
        raise AuthorityUnavailable(reason)


def _prepared(owner):
    from .d06_ordinary_readout_v3 import is_life_ordinary_origin_owner_v3
    _actual(owner)
    if is_life_ordinary_origin_owner_v3(owner):
        prepared = owner.readout
        _need(prepared is not None, 'selected Life Body requires its actual completed Source readout')
        prepared.require_current_v3()
    else:
        from .d04_source_work_v3 import require_installed_d04_source_reader_v3
        require_installed_d04_source_reader_v3(owner)
        prepared = owner.ordinary_readout
        _need(prepared is not None, 'selected D04 Body requires its actual completed Source readout')
        prepared.require_current_v3(owner)
    return prepared


def _scope(owner, prepared, actual_scope):
    from .d06_ordinary_readout_v3 import is_life_ordinary_origin_owner_v3
    if not is_life_ordinary_origin_owner_v3(owner):
        _need(actual_scope is None, 'D04 has no finite Goal/Plan/Action/Project selector')
        return None
    from .d11_life_contract_v1 import LifeInputRefV1
    from .d06_ordinary_readout_v3 import LifeOrdinaryReadoutManifestV4
    if type(prepared.manifest) is LifeOrdinaryReadoutManifestV4:
        from .d01_single_event_readout_v4 import _life_scope
        selected = _life_scope(owner)
        _need(type(actual_scope) is LifeInputRefV1 and actual_scope == selected,
              'selected Life Body has another actual prepared Project selector')
        expected = (selected.ref, selected.revision, selected.digest)
        _need(all(row.consumer_selector == expected for row in prepared.manifest.single_event_controls),
              'selected Life Body changed its independently qualified finite scope')
        return expected
    _need(actual_scope is None, 'ordinary V3 has no issued scoped-claim control')
    return None


def current_selected_persona_scope_v4(owner):
    """Return only the selector authenticated by this actual completed readout."""
    prepared = _prepared(owner)
    from .d06_ordinary_readout_v3 import (is_life_ordinary_origin_owner_v3,
        LifeOrdinaryReadoutManifestV4)
    if is_life_ordinary_origin_owner_v3(owner) and type(prepared.manifest) is LifeOrdinaryReadoutManifestV4:
        from .d01_single_event_readout_v4 import _life_scope
        return _life_scope(owner)
    return None


def _binding(owner, control, head, actual_scope):
    prepared = _prepared(owner)
    from .d06_ordinary_readout_v3 import is_life_ordinary_origin_owner_v3
    actual_control = owner.control if is_life_ordinary_origin_owner_v3(owner) else owner.current_control
    _need(type(control) is ActiveRoleHeadControlV3 and control is actual_control
          and type(head) is OrdinaryHeadCommitmentV3 and head is owner.head
          and (control.namespace, control.head_id, control.plan_key, control.plan_version)
              == (head.namespace, head.head_id, head.plan_ref.key, head.version)
          and head.plan_ref in control.read_versions and head.activation_ref in control.read_versions,
          'selected Body requires the actual complete current control and metadata head')
    current = _fixed(owner, 'graph_atoms', ('revision','valid','value_cell_id'),
        'token=? AND bot=? AND persona=?', (head.plan_ref.key.token,*owner.namespace.as_tuple))
    _need(current is not None and current[:2] == (head.plan_ref.revision,1),
          'selected Body plan Head changed from its independently verified lineage')
    return prepared, _scope(owner, prepared, actual_scope), current


class _SelectedPlanStreamV4(OrdinaryOriginMetadataStreamV3):
    def __init__(self, *, selected_indexes, read_values, ensure_ascii, reserve):
        super().__init__(profile='plan', ensure_ascii=ensure_ascii, reserve=reserve)
        self.selected_indexes, self.read_values = selected_indexes, read_values

    def _retains(self, path):
        if path and path[0] == 'values':
            return self.read_values
        if len(path) >= 3 and path[0] == 'blocks' and path[2] == 'claim':
            return path[1] in self.selected_indexes
        return super()._retains(path)


class _SelectedPlanColumnV4(OrdinaryOriginColumnV3):
    def __init__(self, owner, control, head, actual_scope, allowed, read_values):
        prepared, selector, current = _binding(owner, control, head, actual_scope)
        self.control, self.head, self.actual_scope = control, head, actual_scope
        self.prepared, self.selector = prepared, selector
        self.allowed, self.read_values = allowed, read_values
        super().__init__(owner, table='graph_atoms', column='value', key_columns=('token',),
            key=(head.plan_ref.key.token,), profile='plan', cell_id=current[2])
        indexes = frozenset(index for index, block in enumerate(head.blocks) if block.block_id in allowed)
        self.parser = _SelectedPlanStreamV4(selected_indexes=indexes, read_values=read_values,
            ensure_ascii=self.cell is None or self.cell.header[0] == 'canonical-json.ascii.v1',
            reserve=self.reserve)

    def require_v3(self):
        super().require_v3()
        prepared, selector, current = _binding(self.owner, self.control, self.head, self.actual_scope)
        _need(prepared is self.prepared and selector == self.selector
              and current[2] == (None if self.cell is None else self.cell.cell_id),
              'selected plan column left its exact originating Source/readout scope')
        return self


@dataclass(frozen=True, eq=False)
class _QualifiedSelectedBodiesV4:
    blocks: tuple
    withheld: tuple
    def __init__(self, key, blocks, withheld):
        if key is not _KEY:
            raise TypeError('selected blocks require actual canonical Body EOF')
        object.__setattr__(self, 'blocks', blocks)
        object.__setattr__(self, 'withheld', withheld)


@dataclass(frozen=True, eq=False)
class _QualifiedSelectedValuesV4:
    values: tuple
    def __init__(self, key, values):
        if key is not _KEY:
            raise TypeError('selected values require independent actual canonical field EOF')
        object.__setattr__(self, 'values', values)


def read_selected_persona_bodies_v4(actual_reader, control, head_metadata, *,
        actual_scope=None, read_values=False):
    """Retain only actual ordinary-readout paths, then validate every commitment.

    read_values only narrows this consumer's existing role-value READ profile.
    It never turns a metadata Head or a caller-supplied block list into a grant.
    """
    owner, head = actual_reader, head_metadata
    _need(type(read_values) is bool, 'selected values switch must be a boolean selector')
    prepared, selector, current = _binding(owner, control, head, actual_scope)
    from .d06_ordinary_readout_v3 import is_life_ordinary_origin_owner_v3
    origins = owner.origins if is_life_ordinary_origin_owner_v3(owner) else prepared.origins
    allowed = frozenset(origin.block.block_id for origin in origins)
    by_id = {block.block_id:block for block in head.blocks}
    _need(len(by_id) == len(head.blocks) and allowed <= by_id.keys()
          and all(by_id[block_id].claim_protocol is None and by_id[block_id].kind != 'semantic_identity'
                  for block_id in allowed),
          'ordinary selection cannot authorize a semantic, conditioned or method claim')
    column = _SelectedPlanColumnV4(owner, control, head, actual_scope, allowed, read_values)
    while not column.complete:
        with owner.quantum_v3() as meter:
            column.advance(meter)
    owner.origin_columns.append(column)
    raw = column.metadata
    _need(column.semantic_digest == head.plan_value_digest
          and set(column.fields[()]) == {'plan_id','namespace','version','blocks','values','authored'}
          and raw['namespace'] == {'bot_id':owner.namespace.bot_id,'persona_id':owner.namespace.persona_id}
          and (raw['plan_id'],raw['version'],raw['authored']) == (head.plan_id,head.version,head.authored)
          and len(raw['blocks']) == len(head.blocks)
          and column.commitments[('values',)] == head.values_digest,
          'selected canonical plan differs from the actual complete metadata original')
    from ..domains.d01 import _persona_block, _value_rule
    blocks, withheld = [], []
    for index, expected in enumerate(head.blocks):
        value, path = raw['blocks'][index], ('blocks',index)
        _need(column.fields[path] == {'block_id','kind','claim','plasticity'}
              and (value['block_id'],value['kind'],value['plasticity']) ==
                  (expected.block_id,expected.kind,expected.plasticity)
              and column.commitments[path+('claim',)] == expected.claim_digest
              and column.parser.claim_protocols[path+('claim',)] == expected.claim_protocol,
              'selected block metadata or exact claim commitment changed')
        if expected.block_id in allowed:
            block = _persona_block(value)
            _need(canonical_digest(block.claim) == expected.claim_digest,
                  'selected claim Body differs from its complete metadata commitment')
            blocks.append(block)
        else:
            _need('claim' not in value, 'withheld claim Body was retained')
            reason = 'scope_not_selected' if expected.claim_protocol is None and expected.kind != 'semantic_identity' else 'unavailable_protocol'
            withheld.append((expected.block_id,reason))
    bodies = _QualifiedSelectedBodiesV4(_KEY, tuple(blocks), tuple(withheld))
    values = None
    if read_values:
        _need(type(raw['values']) is list and canonical_digest(raw['values']) == head.values_digest,
              'selected values require the complete actual values field original')
        values = _QualifiedSelectedValuesV4(_KEY, tuple(_value_rule(value) for value in raw['values']))
    common = (owner,owner.operation,owner.work,prepared,control,head,selector,column)
    _PARTS[bodies] = common
    if values is not None:
        _PARTS[values] = common
    return bodies, values


@dataclass(frozen=True, slots=True, weakref_slot=True, eq=False)
class SelectedPersonaReadoutV4:
    control: ActiveRoleHeadControlV3
    head: OrdinaryHeadCommitmentV3
    consumer_scope: object
    selected_blocks: tuple[PersonaBlock,...]
    withheld_blocks: tuple[tuple[str,str],...]
    values: tuple[ValueRule,...] | None
    read_versions: tuple[GraphVersion,...]
    query_epochs: tuple
    cohort_digest: str
    source_qualification_digest: str
    deadline_utc: float


def issue_selected_persona_readout_v4(actual_reader, control, head_metadata,
        qualified_selected_bodies, qualified_values, actual_scope):
    owner, bodies, values = actual_reader, qualified_selected_bodies, qualified_values
    prepared, selector, current = _binding(owner, control, head_metadata, actual_scope)
    _need(type(bodies) is _QualifiedSelectedBodiesV4 and bodies in _PARTS,
          'actual privately selected Body proof required')
    saved = _PARTS[bodies]
    _need(saved[:7] == (owner,owner.operation,owner.work,prepared,control,head_metadata,selector),
          'selected Body proof differs from the actual consumer Work/head/scope')
    if values is not None:
        _need(type(values) is _QualifiedSelectedValuesV4 and _PARTS.get(values) == saved,
              'values proof differs from the independently read complete field')
    saved[7].require_v3()
    versions = {value.key:value for value in (*control.read_versions,head_metadata.plan_ref)}
    from ..graph_types import AtomKey
    for item in prepared.manifest.support_heads:
        version = GraphVersion(AtomKey.from_token(item.ref),item.revision)
        _need(version.key not in versions or versions[version.key] == version,
              'selected Body and Source metadata guards disagree')
        versions[version.key] = version
    from .d06_ordinary_readout_v3 import LifeOrdinaryReadoutManifestV4
    if type(prepared.manifest) is LifeOrdinaryReadoutManifestV4:
        from .d01_single_event_readout_v4 import single_event_control_versions_v4
        for version in single_event_control_versions_v4(prepared.manifest.single_event_controls):
            _need(version.key not in versions or versions[version.key] == version,
                  'selected Body and scoped current controls disagree')
            versions[version.key] = version
    _need(owner.operation.deadline_utc is not None, 'selected Body must retain its original finite deadline')
    manifest_digest = prepared.manifest.digest
    result = SelectedPersonaReadoutV4(control,head_metadata,actual_scope,bodies.blocks,bodies.withheld,
        None if values is None else values.values,tuple(versions[k] for k in sorted(versions,key=lambda k:k.token)),
        (NamespaceEpoch(*control.namespace.as_tuple,control.graph_epoch),),manifest_digest,canonical_digest((manifest_digest,prepared.manifest.support_heads)),
        owner.operation.deadline_utc)
    _ISSUED[result] = (owner,bodies,values,saved,canonical_digest(result))
    _READOUTS[owner] = result
    return result


def prepare_selected_persona_readout_v4(actual_reader, control, head_metadata, *,
        actual_scope=None, read_values=True):
    existing = _READOUTS.get(actual_reader)
    if existing is not None:
        require_selected_persona_readout_v4(existing,actual_reader,actual_scope)
        _need(existing.control is control and existing.head is head_metadata
              and (not read_values or existing.values is not None),
              'selected Body was already issued for another field selection')
        return existing
    blocks, values = read_selected_persona_bodies_v4(actual_reader,control,head_metadata,
        actual_scope=actual_scope,read_values=read_values)
    return issue_selected_persona_readout_v4(actual_reader,control,head_metadata,blocks,values,actual_scope)


def require_selected_persona_readout_v4(value, actual_reader, actual_scope):
    _need(type(value) is SelectedPersonaReadoutV4 and value in _ISSUED,
          'persona projection requires an actual private Selected V4 issuance')
    owner,bodies,values,saved,digest = _ISSUED[value]
    _need(owner is actual_reader and value.control is saved[4] and value.head is saved[5]
          and canonical_digest(value) == digest
          and value.consumer_scope == actual_scope and value.selected_blocks == bodies.blocks
          and value.withheld_blocks == bodies.withheld
          and value.values == (None if values is None else values.values),
          'Selected V4 value was not issued for this exact consumer')
    prepared,selector,current = _binding(owner,value.control,value.head,actual_scope)
    _need(saved[:7] == (owner,owner.operation,owner.work,prepared,value.control,value.head,selector)
          and prepared.manifest.digest == value.cohort_digest
          and owner.operation.deadline_utc == value.deadline_utc,
          'Selected V4 lifetime, Source proof or current selector changed')
    saved[7].require_v3()
    return value


def require_projectable_selected_persona_readout_v4(value):
    _need(type(value) is SelectedPersonaReadoutV4 and value in _ISSUED,
          'actual Selected V4 private issuance required')
    return require_selected_persona_readout_v4(value,_ISSUED[value][0],value.consumer_scope)


def release_selected_persona_readout_v4(actual_reader):
    value = _READOUTS.pop(actual_reader,None)
    if value is not None:
        issued = _ISSUED.pop(value,None)
        if issued is not None:
            _PARTS.pop(issued[1],None)
            if issued[2] is not None:
                _PARTS.pop(issued[2],None)


def require_selected_persona_control_header_v4(value, key, revision):
    """Read one actual control header; this never authorizes a claim Body."""
    selected=require_projectable_selected_persona_readout_v4(value)
    owner=_ISSUED[selected][0]
    _need(GraphVersion(key,revision) in selected.control.read_versions,
          'selected control header is outside its exact three-version readset')
    current=_fixed(owner,'graph_atoms',('revision','valid','value_cell_id'),
        'token=? AND bot=? AND persona=?',(key.token,*owner.namespace.as_tuple))
    _need(current is not None and current[:2]==(revision,1),
          'selected actual control header changed or became unavailable')
    return current[0],bool(current[1]),current[2]
