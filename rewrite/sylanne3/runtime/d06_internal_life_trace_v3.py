"""Explicit Life Episode-v2 trace contract; decoding never issues encoding.

The current installed product has no authenticated Life C02/baseline producer
or consumer reader. Public snapshot-only consumers therefore remain on HOLD.
This version is separate from the unchanged subjective trace v1/v2 wires.
"""
from dataclasses import dataclass
import math

from ..graph_types import AtomKey, Owner, TypeSpec
from ..runtime_contracts import NamespaceId, schema_hash
from .d06_internal_life_episode_v2 import EPISODE, _sha

TRACE = 'memory.subjective_trace.v3'


def internal_life_trace_key_v3(namespace, trace_id):
    if type(namespace) is not NamespaceId or type(trace_id) is not str or not 1<=len(trace_id)<=512:
        raise ValueError('Life trace exact namespace/identity differs')
    return AtomKey(Owner('event',*namespace.as_tuple,trace_id),TRACE,'record')


@dataclass(frozen=True, slots=True)
class InternalLifeSubjectiveTraceV3:
    trace_id: str
    episode_ref: str
    episode_provenance_digest: str
    encoding_baseline_ref: str
    encoding_baseline_digest: str
    encoding_operation_id: str
    model_original_digest: str
    perspective_ref: str
    then_feeling_refs: tuple[str,...]
    interpretation_refs: tuple[str,...]
    detail_weights: tuple[tuple[str,float],...]
    schema: str = TRACE

    def __post_init__(self):
        episode=AtomKey.from_token(self.episode_ref);ns=NamespaceId.from_key(episode)
        internal_life_trace_key_v3(ns,self.trace_id)
        if (self.schema!=TRACE or episode.type_name!=EPISODE
                or type(self.encoding_operation_id) is not str or not self.encoding_operation_id
                or AtomKey.from_token(self.encoding_baseline_ref).type_name!='d04.encoding_baseline.v1'
                or AtomKey.from_token(self.perspective_ref).type_name!='d03.self_perspective.v1'):
            raise ValueError('Life trace requires separate Episode-v2/actual baseline/producer identities')
        for value in (self.episode_provenance_digest,self.encoding_baseline_digest,self.model_original_digest):_sha(value)
        for values in (self.then_feeling_refs,self.interpretation_refs):
            if type(values) is not tuple or len(values)>128 or len(set(values))!=len(values):
                raise ValueError('Life trace finite reference inventory differs')
        for ref in (self.encoding_baseline_ref,self.perspective_ref,*self.then_feeling_refs,*self.interpretation_refs):
            if NamespaceId.from_key(AtomKey.from_token(ref))!=ns:
                raise ValueError('Life trace crosses namespace')
        if type(self.detail_weights) is not tuple or len(self.detail_weights)>128:
            raise ValueError('Life trace finite detail inventory differs')
        for row in self.detail_weights:
            if (type(row) is not tuple or len(row)!=2 or type(row[0]) is not str or not row[0]
                    or type(row[1]) not in (int,float) or not math.isfinite(row[1]) or not 0<=row[1]<=1):
                raise ValueError('Life trace detail weight differs')
        if len({row[0] for row in self.detail_weights})!=len(self.detail_weights):
            raise ValueError('Life trace detail weights repeat')


def decode_internal_life_trace_v3(raw):
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    return decode_typed_production_value_v1(raw,InternalLifeSubjectiveTraceV3)


def internal_life_trace_type_spec_v3():
    return TypeSpec(TRACE,('event',),'source',decode_internal_life_trace_v3,immutable=True,
        writer_domain='d06',schema_version=3,
        schema_hash=schema_hash({'type':TRACE,'fields':tuple(InternalLifeSubjectiveTraceV3.__dataclass_fields__),
            'issuer':'installed-life-c02-originals-only'}))


def require_installed_internal_life_encoding_reader_v3():
    # No caller callback, phase flag, decoded trace or generic fenced snapshot
    # supplies the missing actual producer/original/current-generation reader.
    raise ValueError('installed Life C02/baseline producer and private current trace reader unavailable; HOLD')
