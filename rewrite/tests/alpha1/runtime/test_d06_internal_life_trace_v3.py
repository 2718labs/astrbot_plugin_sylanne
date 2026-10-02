"""New version decoding/current locator/HOLD, not a Life C02 acceptance."""
from dataclasses import replace

import pytest

from test_d06_internal_life_episode_v2 import fixture_proof,NS,D
from sylanne3.graph_types import AtomKey,Owner,TypeRegistry
from sylanne3.graph_store import GraphStore
from sylanne3.memory_repository import MemoryRepository
from sylanne3.domains.d01.production_operations_v1 import plain_v1
from sylanne3.domains.d06 import D06DomainAdapter,D06DomainProvider
from sylanne3.domains.d06.pipeline import D06MemoryPipeline
from sylanne3.memory_types import validate_subjective_trace_v2
from sylanne3.runtime_contracts import NamespaceId
from sylanne3.runtime.d06_internal_life_episode_v2 import EPISODE,require_internal_life_episode_locator_v2
from sylanne3.runtime.d06_internal_life_trace_v3 import (
    TRACE,InternalLifeSubjectiveTraceV3,decode_internal_life_trace_v3,internal_life_trace_type_spec_v3,
    require_installed_internal_life_encoding_reader_v3,
)


def trace():
    proof,_,_=fixture_proof()
    baseline=AtomKey(Owner('event',*NS.as_tuple,'baseline'),'d04.encoding_baseline.v1','record')
    return InternalLifeSubjectiveTraceV3('trace',proof.episode.episode_ref,D,baseline.token,D,
        'actual-encoding:fixture',D,proof.event.perspective_ref,(),(),(('detail',.5),))


def test_trace_v3_closed_roundtrip_and_old_v2_rejects_new_episode():
    value=trace();assert decode_internal_life_trace_v3(plain_v1(value))==value
    assert internal_life_trace_type_spec_v3().immutable
    assert any(spec.name==TRACE for spec in D06DomainProvider.type_specs())
    with pytest.raises(ValueError):validate_subjective_trace_v2(plain_v1(value))


@pytest.mark.parametrize('change',['old_episode','cross_ns','unknown_field','bool_weight','missing_original'])
def test_trace_v3_codec_does_not_promote_legacy_or_unknown_originals(change):
    value=trace();raw=plain_v1(value)
    if change=='old_episode':raw['episode_ref']=AtomKey(AtomKey.from_token(value.episode_ref).owner,'memory.episode.v1','record').token
    elif change=='cross_ns':raw['perspective_ref']=AtomKey(Owner('persona','other','persona'),'d03.self_perspective.v1','record').token
    elif change=='unknown_field':raw['caller_authorized']=True
    elif change=='bool_weight':raw['detail_weights']=[['detail',True]]
    else:del raw['model_original_digest']
    with pytest.raises((ValueError,TypeError)):decode_internal_life_trace_v3(raw)


@pytest.mark.parametrize('change',['wrong_type','wrong_name','namespace'])
def test_current_episode_reader_requires_exact_type_scope_and_proof_locator(change):
    proof,_,_=fixture_proof();key=AtomKey.from_token(proof.episode.episode_ref)
    ref=(AtomKey(key.owner,'memory.episode.v1',key.name).token if change=='wrong_type' else
        AtomKey(key.owner,EPISODE,'wrong').token if change=='wrong_name' else proof.episode.episode_ref)
    ns=NamespaceId('other','persona') if change=='namespace' else NS
    with pytest.raises(ValueError,match='locator'):require_internal_life_episode_locator_v2(ns,ref,proof)


def test_public_pipeline_and_constructed_trace_have_no_installed_issuer(tmp_path):
    store=GraphStore(tmp_path/'graph.db',TypeRegistry())
    try:
        pipeline=D06MemoryPipeline(D06DomainAdapter(NS),MemoryRepository(store,*NS.as_tuple))
        # No Source/trace DTO or generic snapshot is used as an issuer; reject
        # before reading a caller-selected Source in this uninstalled path.
        with pytest.raises(ValueError,match='private current trace reader unavailable'):
            pipeline.read_committed_encoding('source','trace',audience='owner',purpose='retrieval',trace_version=3)
        with pytest.raises(ValueError,match='HOLD'):require_installed_internal_life_encoding_reader_v3()
    finally:store.close()
