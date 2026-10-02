"""Permanent Life-only closed contracts and real Graph invalidation.

The activity DTO here is deliberately unissued. GraphStore cases prove SQL
atomicity/invalidation, not Authority qualification or installed permission.
"""
from dataclasses import replace
import sqlite3

import pytest

from sylanne3.contracts import Event, Scope
from sylanne3.graph_store import GraphStore
from sylanne3.graph_types import AtomKey, GraphAtom, GraphCandidate, GraphSnapshot, GraphVersion, GraphWrite, Owner, TypeRegistry, TypeSpec, owner_grant_key
from sylanne3.memory_types import SourceRecord, source_key, access_key
from sylanne3.domains.d03.self_perspective import self_mapping_key, self_perspective_key
from sylanne3.domains.d06 import D06DomainProvider, source_correction_head_key
from sylanne3.domains.d01.production_operations_v1 import plain_v1
from sylanne3.runtime_contracts import NamespaceId, QueryEpoch, canonical_digest, canonical_serialize
from sylanne3.runtime.domain_production_contracts_v1 import ProductionQueryCoverageV1
from sylanne3.runtime.d06_life_activity_lineage_v1 import QualifiedLifeActivityV1
from sylanne3.runtime.d06_internal_life_episode_v2 import (
    EVENT, EPISODE, PROVENANCE, ELIGIBILITY, KINDS, InternalLifeEventV1, InternalLifeEpisodeV2,
    EpisodeReadV2, InternalLifeEpisodeProvenanceV2, internal_life_episode_keys_v2,
    internal_life_episode_type_specs_v2, internal_life_writes_from_proof_v2,
    decode_internal_life_value_v2, _require_qualified_activity_v1, require_exact_internal_life_issuance_v2,
)
from sylanne3.runtime.c09_graph_rebase_candidate_v1 import _dependency_closure


NS = NamespaceId('bot', 'persona')
D = 'a' * 64


def fixture_proof():
    source = source_key(*NS.as_tuple, 'experience')
    mapping = self_mapping_key(NS)
    perspective = self_perspective_key(NS, 'perspective:self-v1:fixture')
    artifact = AtomKey(Owner('activity', *NS.as_tuple, 'effect:fixture'), 'd11.life_artifact.v1', 'record')
    settlement = AtomKey(Owner('persona', *NS.as_tuple), 'd02.settlement.v1', 'settlement')
    record = SourceRecord(source.owner.subject, 'Activity occurred; text content is not an external fact',
        'persona:persona', 'internal', 'confirmed', 1., 2., 'terminal:fixture', ('owner',),
        ('context', 'consolidation'), (), 'same_root')
    values = {
        source: record.to_dict(), access_key(*NS.as_tuple, record.source_id): {
            'source_id':record.source_id, 'audiences':['owner'], 'purposes':['context','consolidation'],
            'status':'active', 'recorded_at':2.},
        mapping: {'mapping_id':'self-map:fixture', 'persona_ref':'persona:persona', 'self_entity_ref':'entity:fixture',
            'certification_ref':'authority:self-identity:fixture', 'role_head_id':'role:fixture', 'graph_incarnation':'incarnation:fixture', 'status':'active'},
        perspective: {'perspective_id':perspective.name, 'persona_ref':'persona:persona', 'self_entity_ref':'entity:fixture',
            'scene_ref':'scene:context', 'identity_mapping_ref':mapping.token,
            'arrival_event_ref':AtomKey(Owner('event', *NS.as_tuple, 'arrival'), 'd03.world_event', 'record').token,
            'role_head_id':'role:fixture'},
        owner_grant_key(*NS.as_tuple): {'fixture':'actual owner head'},
    }
    correction = source_correction_head_key(NS, record.source_id)
    reads = tuple(sorted((*(EpisodeReadV2(key.token, 1, canonical_digest(value), True) for key,value in values.items()),
        EpisodeReadV2(correction.token, 0, canonical_digest({}), False)), key=lambda row: row.ref))
    activity = QualifiedLifeActivityV1(source.token, 1, canonical_digest(record.to_dict()), 'activity:fixture', 'effect:fixture',
        'execution:fixture', artifact.token, D, 'claim:fixture', 'terminal:fixture', 7, 1., 2., settlement.token, D,
        tuple(GraphVersion(AtomKey.from_token(row.ref), row.revision) for row in reads))
    keys = internal_life_episode_keys_v2(NS, source.token)
    event = InternalLifeEventV1(keys[0].token, NS, 1, 'incarnation:fixture', 'advance:fixture', activity,
        mapping.token, perspective.token, 'scene:context')
    episode = InternalLifeEpisodeV2(keys[1].token, (source.token,), keys[0].token)
    coverage = (ProductionQueryCoverageV1(QueryEpoch(NS, 'namespace', 1), 'd03.self_perspective.v1',
        (GraphVersion(perspective,1),), True, None),)
    return InternalLifeEpisodeProvenanceV2(event, episode, 'encode:fixture', D, reads, reads, coverage), values, correction


def test_public_qualified_activity_and_external_dto_are_not_issuers():
    proof, _, _ = fixture_proof()
    with sqlite3.connect(':memory:') as db:
        db.execute('BEGIN')
        with pytest.raises(ValueError, match='not this SQL-qualified'):
            _require_qualified_activity_v1(proof.event.activity, db=db, frame=object())
    with pytest.raises(ValueError, match='active installed'):
        require_exact_internal_life_issuance_v2(None, object(), object())


def test_closed_event_and_episode_roundtrip_does_not_use_world_event():
    proof, _, _ = fixture_proof()
    for write in internal_life_writes_from_proof_v2(proof):
        value = decode_internal_life_value_v2(write.key.type_name, write.value)
        assert canonical_serialize(plain_v1(value)) == canonical_serialize(write.value)
    assert proof.event.reality == 'internal_life'
    assert proof.event.assertion_scope == 'activity_occurred_only'
    assert not any(write.key.type_name == 'd03.world_event' for write in internal_life_writes_from_proof_v2(proof))
    assert proof.event.scene_ref == 'scene:context'


@pytest.mark.parametrize('changes', [{'reality':'host_observed'}, {'assertion_scope':'text_is_external_fact'},
    {'activation_generation':True}, {'namespace':NamespaceId('other','persona')}, {'event_ref':'forged'}])
def test_event_rejects_promotion_generation_and_cross_namespace(changes):
    proof, _, _ = fixture_proof()
    with pytest.raises((ValueError, TypeError)):
        replace(proof.event, **changes)


@pytest.mark.parametrize('kind', ['memory.source','memory.access','d06.source_correction_head.v1',
    'd11.owner_grant.v1','d03.self_identity_mapping.v1','d03.self_perspective.v1'])
def test_projection_cannot_omit_required_head_with_recomputed_proof_digest(kind):
    proof, _, _ = fixture_proof()
    rows = tuple(row for row in proof.current_reads if AtomKey.from_token(row.ref).type_name != kind)
    with pytest.raises(ValueError): replace(proof, current_reads=rows)


def test_old_provider_schema_hash_and_episode_validator_remain_strict():
    from sylanne3.memory_types import validate_episode
    proof, _, _ = fixture_proof()
    with pytest.raises(ValueError): validate_episode(plain_v1(proof.episode))
    specs = {spec.name:spec for spec in D06DomainProvider.type_specs()}
    assert specs['memory.episode.v1'].immutable and specs[EPISODE].immutable
    assert specs[EPISODE].schema_version == 2
    assert specs[EVENT].immutable and specs[PROVENANCE].immutable and not specs[ELIGIBILITY].immutable


@pytest.fixture
def actual_graph(tmp_path):
    proof, values, correction = fixture_proof()
    registry = TypeRegistry()
    # Source permission/Owner issuance is deliberately a fixture schema seam.
    for kind in {key.type_name for key in values} | {correction.type_name}:
        registry.register(TypeSpec(kind, ('event','persona'), 'state', lambda value:None,
            writer_domain='d06', schema_hash=D))
    for spec in internal_life_episode_type_specs_v2(): registry.register(spec)
    store = GraphStore(tmp_path / 'graph.db', registry)
    owner = owner_grant_key(*NS.as_tuple)
    seeds = tuple(GraphWrite(key,value) for key,value in values.items() if key != owner)
    seed = GraphCandidate(Event(Scope(*NS.as_tuple, 'activity:fixture'), 'seed', 0., 'fixture.seed', {}),
        tuple(GraphVersion(write.key,0) for write in seeds), seeds)
    assert store.graph_commit(seed).status == 'committed'
    # A fixture Owner row is not an issuance; the real public GraphStore path
    # correctly refuses writing it. Installed tests supply the actual W01 row.
    store._db.execute('INSERT INTO graph_atoms VALUES(?,?,?,?,?,?,?,?,?,?)',
        (owner.token,*NS.as_tuple,owner.owner.kind,owner.owner.subject,owner.type_name,owner.name,
            1,canonical_serialize(values[owner]),1))
    writes = internal_life_writes_from_proof_v2(proof)
    reads = tuple(GraphVersion(AtomKey.from_token(row.ref), row.revision) for row in proof.current_reads) + tuple(
        GraphVersion(write.key,0) for write in writes)
    candidate = GraphCandidate(Event(Scope(*NS.as_tuple, 'activity:fixture'), proof.producing_operation_id,
        2., 'fixture.internal_life', {}), reads, writes)
    yield store, proof, candidate, values, correction
    store.close()


def test_actual_graph_fact_membership_and_negative_correction_invalidation(actual_graph):
    store, proof, candidate, values, correction = actual_graph
    assert store.graph_commit(candidate).status == 'committed'
    keys = internal_life_episode_keys_v2(NS, proof.event.activity.source_ref)
    for key in keys[:3]:
        assert store._db.execute('SELECT dependencies FROM graph_history WHERE token=? AND revision=1', (key.token,)).fetchone() == ('[]',)
    changed = GraphCandidate(Event(Scope(*NS.as_tuple, 'activity:fixture'), 'correction', 3., 'fixture.correction', {}),
        (GraphVersion(correction,0),), (GraphWrite(correction, {'correction':'new'}),))
    assert store.graph_commit(changed).status == 'committed'
    assert store._db.execute('SELECT valid FROM graph_atoms WHERE token=?',(keys[3].token,)).fetchone() == (0,)
    assert all(store._db.execute('SELECT valid FROM graph_atoms WHERE token=?',(key.token,)).fetchone() == (1,) for key in keys[:3])


def test_actual_graph_rollback_has_no_partial_episode_or_proof(actual_graph):
    store, proof, candidate, _, _ = actual_graph
    def refuse(db, receipt): raise ValueError('actual same-transaction proof refusal')
    with pytest.raises(ValueError,match='proof refusal'): store.graph_commit(candidate, _receipt_hook=refuse)
    for key in internal_life_episode_keys_v2(NS,proof.event.activity.source_ref):
        assert store._db.execute('SELECT 1 FROM graph_atoms WHERE token=?',(key.token,)).fetchone() is None
        assert store._db.execute('SELECT 1 FROM graph_history WHERE token=?',(key.token,)).fetchone() is None


def test_typed_c09_closure_reaches_source_free_event_and_episode(actual_graph):
    store, proof, candidate, _, _ = actual_graph
    assert store.graph_commit(candidate).status == 'committed'
    keys = internal_life_episode_keys_v2(NS, proof.event.activity.source_ref)
    affected = _dependency_closure(store._db, {proof.event.activity.source_ref})
    assert {key.token for key in keys} <= set(affected)
