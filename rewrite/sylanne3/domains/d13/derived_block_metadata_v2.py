"""D13 V2 metadata with the exact completion/Source/Access turn closure."""
from dataclasses import dataclass, fields
import math
import json

from ...graph_types import AtomKey, Owner, TypeSpec
from ...runtime_contracts import NamespaceId, VersionedRef, canonical_serialize, schema_hash

METADATA_TYPE = 'd13.derived_block_metadata.v2'
from .derived_block_metadata_v1 import DerivedTurnExpiryV1

def _digest(value):
    return type(value) is str and len(value) == 64 and all(c in '0123456789abcdef' for c in value)

@dataclass(frozen=True, slots=True)
class DerivedBlockMetadataV2:
    namespace: NamespaceId
    block_ref: str
    conversation_ref: str
    scene_ref: VersionedRef
    audience_ref: VersionedRef
    payload_digest: str
    payload_length_bytes: int
    source_dependencies: tuple[VersionedRef, ...]
    turn_expiries: tuple[DerivedTurnExpiryV1, ...]
    job_ref: str
    candidate_ref: str
    compiler_version: str
    paid_original_operation_id: str
    paid_original_digest: str
    paid_evidence_digest: str
    paid_settlement_digest: str
    expires_at_utc: float
    status: str
    schema: str = METADATA_TYPE
    def __post_init__(self):
        if (self.schema != METADATA_TYPE or type(self.namespace) is not NamespaceId
                or type(self.scene_ref) is not VersionedRef or type(self.audience_ref) is not VersionedRef
                or any(type(value) is not str or not value for value in (self.block_ref, self.conversation_ref,
                    self.job_ref, self.candidate_ref, self.compiler_version, self.paid_original_operation_id))
                or not all(_digest(value) for value in (self.payload_digest, self.paid_original_digest,
                    self.paid_evidence_digest, self.paid_settlement_digest))
                or type(self.payload_length_bytes) is not int or not 1 <= self.payload_length_bytes <= 524288
                or self.status not in {'standby', 'active', 'retired'}
                or type(self.turn_expiries) is not tuple or not 1 <= len(self.turn_expiries) <= 64
                or any(type(turn) is not DerivedTurnExpiryV1 for turn in self.turn_expiries)
                or any(b.sequence != a.sequence + 1 for a,b in zip(self.turn_expiries,self.turn_expiries[1:]))
                or type(self.source_dependencies) is not tuple
                or len(self.source_dependencies) > 192 or any(type(ref) is not VersionedRef for ref in self.source_dependencies)
                or len({ref.ref for ref in self.source_dependencies}) != len(self.source_dependencies)
                or not {turn.source_ref for turn in self.turn_expiries} <= set(self.source_dependencies)
                or type(self.expires_at_utc) not in (int,float) or not math.isfinite(self.expires_at_utc)
                or self.expires_at_utc > min(turn.original_expires_at_utc for turn in self.turn_expiries)):
            raise ValueError('derived metadata lacks its exact bounded original/source/expiry commitment')
        scene = AtomKey.from_token(self.scene_ref.ref)
        from ...runtime_contracts import current_canonical_output_meter
        meter = current_canonical_output_meter()
        if meter is not None:meter.charge_encode(len(self.scene_ref.ref))
        if (self.scene_ref.version < 1 or scene.owner.kind != 'scene' or scene.type_name != 'd03.role_binding'
                or NamespaceId.from_key(scene) != self.namespace):
            raise ValueError('derived metadata requires its actual same-namespace scene binding')
        require_derived_turn_dependencies_v2(self.namespace, scene.owner.subject, self.conversation_ref,
            self.turn_expiries, self.source_dependencies)
        text = canonical_serialize(self)
        body = text.encode('utf-8')
        if meter is not None:meter.charge_encode(len(body))
        if len(body) > 65536:
            raise ValueError('derived metadata exceeds its current read transport bound')



def require_derived_turn_dependencies_v2(namespace, scene_id, conversation_ref, turns, dependencies):
    """Exact producer closure; constructing expected keys confers no Graph authority."""
    from dataclasses import replace
    from ...memory_types import source_key, access_key
    from ..d09.turn_order import turn_completion_key
    from ...runtime_contracts import TurnAnchorV1, current_canonical_output_meter
    if (type(namespace) is not NamespaceId or type(turns) is not tuple or not 1 <= len(turns) <= 64
            or type(dependencies) is not tuple or not 1 <= len(dependencies) <= 192
            or any(type(ref) is not VersionedRef or ref.version < 1 for ref in dependencies)
            or any(type(turn) not in (DerivedTurnExpiryV1, TurnAnchorV1) for turn in turns)):
        raise ValueError('derived turn closure requires its finite original typed inventory')
    by_token = {ref.ref: ref for ref in dependencies}
    if len(by_token) != len(dependencies):
        raise ValueError('derived turn closure cannot repeat a dependency token')
    meter = current_canonical_output_meter()
    first = turn_completion_key(namespace, scene_id, conversation_ref, turns[0].sequence)
    if meter is not None:
        # canonical_digest's string is metered by the shared serializer; its
        # additional ASCII/UTF8 copy has this exact fixed-dict/string size.
        encoded = len('{"conversation_ref":}') + 2 + sum(
            2 if char in {'"','\\','\b','\f','\n','\r','\t'} else
            6 if ord(char)<32 or 127<=ord(char)<=65535 else 12 if ord(char)>65535 else 1
            for char in conversation_ref)
        meter.charge_encode(encoded)
    prefix = first.name.rsplit(':', 1)[0]
    expected = []
    for turn in turns:
        source = AtomKey.from_token(turn.source_ref.ref)
        if meter is not None:meter.charge_encode(len(turn.source_ref.ref))
        if (turn.source_ref.version < 1 or NamespaceId.from_key(source) != namespace
                or source != source_key(*namespace.as_tuple, source.owner.subject)):
            raise ValueError('derived turn Source differs from its canonical namespace/key')
        raw_token = replace(first, name=prefix + ':' + str(turn.sequence)).token
        access_token = access_key(*namespace.as_tuple, source.owner.subject).token
        if meter is not None:meter.charge_encode(len(raw_token) + len(access_token))
        raw, access = by_token.get(raw_token), by_token.get(access_token)
        if raw is None or access is None or by_token.get(turn.source_ref.ref) != turn.source_ref:
            raise ValueError('derived turn closure lacks its exact completion/Source/Access triple')
        if type(turn) is TurnAnchorV1 and (turn.raw_ref != raw or turn.access_ref != access
                or turn.conversation_ref != conversation_ref):
            raise ValueError('derived turn anchors differ from the complete producer dependency triple')
        expected.extend((raw, turn.source_ref, access))
    if tuple(dict.fromkeys(expected)) != dependencies:
        raise ValueError('derived turn closure has missing/extra dependencies or original order drift')


def decode_derived_block_metadata_v2(value):
    def exact_typed(raw, cls):
        if type(raw) is not dict:
            raise ValueError('derived metadata typed member requires an exact object')
        expected = {field.name for field in fields(cls)}
        if '$type' in raw:
            if set(raw) != expected | {'$type'} or raw['$type'] != cls.__module__ + '.' + cls.__qualname__:
                raise ValueError('derived metadata canonical member has another exact type')
            return {name: raw[name] for name in expected}
        if set(raw) != expected:
            raise ValueError('derived metadata member has another closed schema')
        return dict(raw)
    value = exact_typed(value, DerivedBlockMetadataV2)
    if type(value) is not dict or set(value) != {field.name for field in fields(DerivedBlockMetadataV2)}:
        raise ValueError('derived block metadata is another closed schema')
    if (type(value['source_dependencies']) is not list or type(value['turn_expiries']) is not list
            or any(type(row) is not dict or set(exact_typed(row, DerivedTurnExpiryV1)) != {'sequence', 'source_ref', 'original_expires_at_utc'}
                for row in value['turn_expiries'])):
        raise ValueError('derived metadata collections have another closed schema')
    raw = dict(value)
    raw['namespace'] = NamespaceId(**exact_typed(raw['namespace'], NamespaceId))
    for name in ('scene_ref', 'audience_ref'):
        raw[name] = VersionedRef(**exact_typed(raw[name], VersionedRef))
    raw['source_dependencies'] = tuple(VersionedRef(**exact_typed(ref, VersionedRef)) for ref in raw['source_dependencies'])
    raw['turn_expiries'] = tuple(DerivedTurnExpiryV1(row['sequence'], VersionedRef(**exact_typed(row['source_ref'], VersionedRef)),
        row['original_expires_at_utc']) for row in raw['turn_expiries'])
    return DerivedBlockMetadataV2(**raw)


def derived_block_type_specs_v2():
    return (TypeSpec(METADATA_TYPE, ('persona',), 'cache', decode_derived_block_metadata_v2,
        writer_domain='d13', schema_version=2, schema_hash=schema_hash({'type':METADATA_TYPE,'version':2,'body':'d11.derived_payload.v1','wire':'closed_plain_or_exact_canonical_dto','sources':'exact_ordered_turn_completion_source_access_closure'})),)


def derived_block_metadata_key_v2(metadata):
    if type(metadata) is not DerivedBlockMetadataV2:
        raise TypeError('derived metadata key requires its exact namespace/block identity')
    return AtomKey(Owner('persona', *metadata.namespace.as_tuple), METADATA_TYPE, metadata.block_ref)


def derived_block_metadata_value_v2(metadata):
    if type(metadata) is not DerivedBlockMetadataV2:
        raise TypeError('actual derived metadata required')
    return json.loads(canonical_serialize(metadata))


def decode_derived_block_metadata_history_v2(key,value):
    """Historical/deletion decoder selected by the actual formal Graph token."""
    from .derived_block_metadata_v1 import METADATA_TYPE as LEGACY_TYPE,decode_derived_block_metadata_v1,derived_block_metadata_key_v1
    if type(key)is not AtomKey or key.owner.kind!='persona':
        raise ValueError('historical derived metadata requires its exact persona Graph key')
    if key.type_name==LEGACY_TYPE:
        metadata=decode_derived_block_metadata_v1(value);actual=derived_block_metadata_key_v1(metadata)
    elif key.type_name==METADATA_TYPE:
        metadata=decode_derived_block_metadata_v2(value);actual=derived_block_metadata_key_v2(metadata)
    else:raise ValueError('historical derived metadata has an unregistered version')
    if actual!=key:raise ValueError('historical derived metadata key/schema identity differs')
    return metadata
