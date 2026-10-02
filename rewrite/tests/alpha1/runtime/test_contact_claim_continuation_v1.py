"""Claim identity/refusal seams; these do not authenticate an installed reader.

Plan/Owner authentication is substituted only at this unit seam. Actual typed
policy/claim values and SQL head reads exercise parent identity and refusal;
the final installed stage/provider lifecycle remains a separate acceptance.
"""
from dataclasses import asdict, dataclass, replace
import json
import sqlite3
from types import SimpleNamespace

import pytest

from sylanne3.domains.d09 import ClaimKind
from sylanne3.authority_service.d10_contact_policy_service_v1 import D10ContactPolicyOriginalV1
from sylanne3.domains.d10 import ContactPolicy, contact_policy_graph_write
from sylanne3.domains.d10.contact_claim_v2 import contact_claim_key_v2, contact_window_id_v2
from sylanne3.graph_types import AtomKey, GraphAtom, Owner
from sylanne3.runtime import contact_claim_adoption_v1 as claims
from sylanne3.runtime.contact_final_action_v1 import (
    contact_action_parameters_digest_v1, contact_final_action_ids_v1,
    contact_whole_grant_request_v1,
)
from sylanne3.runtime_contracts import GraphVersion, NamespaceId, VersionedRef, canonical_digest


NS = NamespaceId('bot', 'persona')


@dataclass(frozen=True)
class _PlanSeam:
    target_entity_ref: str
    policy_original_ref: str
    policy_original_digest: str
    opportunity_ref: VersionedRef


class _SqlRead:
    def __init__(self):
        self.inventory_reads = 0

    def head(self, db, key, *, required=False):
        row = db.execute('SELECT revision,value FROM heads WHERE token=?', (key.token,)).fetchone()
        if row is None:
            raise AssertionError('unexpected missing fixture head')
        return GraphAtom(key, row[0], json.loads(row[1]))

    def complete_inventory(self, db, kind):
        self.inventory_reads += 1
        return tuple(GraphAtom(AtomKey.from_token(token), revision, json.loads(value))
            for token, revision, value in db.execute(
                'SELECT token,revision,value FROM heads WHERE kind=?', (kind,)))


@pytest.fixture
def fixture(monkeypatch):
    plan_key = AtomKey(Owner('activity', *NS.as_tuple, 'activity:one'),
        'd08.contact_expression_plan.v1', 'plan:one')
    opportunity = AtomKey(Owner('persona', *NS.as_tuple), 'd10.proactive_opportunity.v1', 'opportunity:one')
    policy = ContactPolicy('policy:one', NS, 1, 'user:one', 'private', 'ordinary', True, False, 1, 0.0, 24.0)
    original = D10ContactPolicyOriginalV1('authority:fixture','authority','installation',NS,policy,
        'owner','sha256:'+'a'*64,1,1,contact_window_id_v2(policy),'approve','issue',0.,'a'*64)
    plan = _PlanSeam('user:one', original.original_ref, original.digest, VersionedRef(opportunity.token, 1))
    write = contact_policy_graph_write(policy, owner_grant_revision=1,
        approval_ref=original.original_ref, approval_authority_id='authority', installation_id='installation')
    segments = tuple(SimpleNamespace(position=index, payload_digest='b' * 64,
        prerequisite_segment_ref=None if index == 0 else 'segment:0',
        segment=SimpleNamespace(segment_id='segment:' + str(index), effect_id='effect:' + str(index), body='text'),
        claims=(SimpleNamespace(kind=ClaimKind.REPORTED_CLAIM),)) for index in range(2))
    content = SimpleNamespace(namespace=NS, contact_id='contact:one', activity_id='activity:one',
        plan_version=GraphVersion(plan_key, 1), plan_digest=canonical_digest(plan),
        audience_id='user:one', required_slots=(), segments=segments, cancellation_epoch=0,
        digest='c' * 64)
    monkeypatch.setattr(claims, 'decode_contact_plan_v1', lambda value: plan)
    monkeypatch.setattr(claims, 'require_current_contact_policy_v1',
        lambda *args, **kwargs: original)
    db = sqlite3.connect(':memory:')
    db.execute('CREATE TABLE heads(token TEXT PRIMARY KEY,kind TEXT,revision INTEGER,value TEXT)')
    db.execute('INSERT INTO heads VALUES(?,?,?,?)', (plan_key.token, plan_key.type_name, 1, '{}'))
    db.execute('INSERT INTO heads VALUES(?,?,?,?)', (write.key.token, write.key.type_name, 1, json.dumps(write.value)))
    read = _SqlRead()
    claim, _, _ = claims._expected_claim(db, read, content, object(), object(), 1.0)
    key = contact_claim_key_v2(NS, content.contact_id)
    db.execute('INSERT INTO heads VALUES(?,?,?,?)', (key.token, key.type_name, 1, json.dumps(asdict(claim))))
    yield db, read, content, claim, key
    db.close()


def _continue(fixture, index):
    db, read, content, _, _ = fixture
    return claims.read_current_own_contact_continuation_v1(db, read, content=content,
        segment_index=index, current_policy=object(), scope=object(), now_utc=1.0)


def _write_claim(fixture, claim, revision=1):
    db, _, _, _, key = fixture
    db.execute('UPDATE heads SET value=?,revision=? WHERE token=?',
        (json.dumps(asdict(claim)), revision, key.token))


def test_initial_claim_uses_whole_parent_and_separate_first_action(fixture):
    _, read, content, claim, _ = fixture
    parent = contact_whole_grant_request_v1(content)
    assert claim.communication_action_id == parent.communication_action_id == 'communication:one'
    assert claim.communication_action_id != contact_final_action_ids_v1(content.contact_id, 0)['action']
    continuation = _continue(fixture, 0)
    assert continuation.communication_action_id == parent.communication_action_id
    assert continuation.segment_effect_id == content.segments[0].segment.effect_id
    assert read.inventory_reads == 2


@pytest.mark.parametrize('index', (True, False, -1, 2, 3, 0.0, '0'))
def test_invalid_actual_segment_index_is_rejected_before_read(fixture, index):
    reads = fixture[1].inventory_reads
    with pytest.raises(ValueError, match='actual finite content'):
        _continue(fixture, index)
    with pytest.raises(ValueError, match='actual finite content'):
        contact_action_parameters_digest_v1(fixture[2], index)
    assert fixture[1].inventory_reads == reads


def test_first_action_id_cannot_impersonate_the_whole_parent(fixture):
    claim = replace(fixture[3], communication_action_id=contact_final_action_ids_v1(fixture[2].contact_id, 0)['action'])
    _write_claim(fixture, claim)
    with pytest.raises(ValueError, match='scope or approval changed'):
        _continue(fixture, 0)


@pytest.mark.parametrize('observation', ('accepted', 'delivered'))
def test_later_segment_refuses_mutable_success_observation(fixture, observation):
    _write_claim(fixture, fixture[3].observe('effect:0', observation))
    with pytest.raises(ValueError, match='authenticated predecessor prefix'):
        _continue(fixture, 1)


def test_initial_claim_requires_unconsumed_revision_one(fixture):
    _write_claim(fixture, fixture[3], revision=2)
    with pytest.raises(ValueError, match='unconsumed staged original'):
        _continue(fixture, 0)


def test_unknown_prior_effect_cannot_continue(fixture):
    _write_claim(fixture, fixture[3].observe('effect:0', 'unknown'))
    with pytest.raises(ValueError, match='released, unknown or already observed'):
        _continue(fixture, 1)
