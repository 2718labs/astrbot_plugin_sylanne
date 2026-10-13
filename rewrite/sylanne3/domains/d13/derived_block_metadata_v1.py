"""Content-free D13 metadata; deletable bytes live only in D11's derived payload table."""
from dataclasses import dataclass, fields
import math
import json

from ...graph_types import AtomKey, Owner, TypeSpec
from ...runtime_contracts import NamespaceId, VersionedRef, canonical_serialize, schema_hash

METADATA_TYPE = 'd13.derived_block_metadata.v1'

def _digest(value):
    return type(value) is str and len(value) == 64 and all(c in '0123456789abcdef' for c in value)

@dataclass(frozen=True, slots=True)
class DerivedTurnExpiryV1:
    sequence: int
    source_ref: VersionedRef
    original_expires_at_utc: float
    def __post_init__(self):
        if (type(self.sequence) is not int or self.sequence < 0 or type(self.source_ref) is not VersionedRef
                or type(self.original_expires_at_utc) not in (int, float) or not math.isfinite(self.original_expires_at_utc)):
            raise ValueError('derived cache keeps actual turn identity and original absolute expiry')

@dataclass(frozen=True, slots=True)
class DerivedBlockMetadataV1:
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
        for dependency in self.source_dependencies:
            key = AtomKey.from_token(dependency.ref)
            if key.type_name != 'memory.source' or NamespaceId.from_key(key) != self.namespace:
                raise ValueError('derived metadata source dependencies must be actual same-namespace Sources')
        if len(canonical_serialize(self).encode('utf-8')) > 65536:
            raise ValueError('derived metadata exceeds its current read transport bound')


def decode_derived_block_metadata_v1(value):
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
    value = exact_typed(value, DerivedBlockMetadataV1)
    if type(value) is not dict or set(value) != {field.name for field in fields(DerivedBlockMetadataV1)}:
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
    return DerivedBlockMetadataV1(**raw)


def derived_block_type_specs_v1():
    return (TypeSpec(METADATA_TYPE, ('persona',), 'cache', decode_derived_block_metadata_v1,
        writer_domain='d13', schema_hash=schema_hash({'type':METADATA_TYPE,'version':1,'body':'d11.derived_payload.v1','wire':'closed_plain_or_exact_canonical_dto','sources':'same_namespace_memory_source'})),)


def derived_block_metadata_key_v1(metadata):
    if type(metadata) is not DerivedBlockMetadataV1:
        raise TypeError('derived metadata key requires its exact namespace/block identity')
    return AtomKey(Owner('persona', *metadata.namespace.as_tuple), METADATA_TYPE, metadata.block_ref)


def derived_block_metadata_value_v1(metadata):
    if type(metadata) is not DerivedBlockMetadataV1:
        raise TypeError('actual derived metadata required')
    return json.loads(canonical_serialize(metadata))
