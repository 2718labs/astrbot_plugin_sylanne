"""Permanent content-only contracts and actual SQLite schema guards.

The occurrence is an unissued DTO fixture. These cases do not grant Owner,
worker, model or current Source permission and are not installed acceptance.
"""
from dataclasses import replace
import json
import sqlite3

import pytest

from test_d06_internal_life_episode_v2 import fixture_proof, D
from sylanne3.domains.d01.production_operations_v1 import plain_v1
from sylanne3.model_broker.natural_reply import NaturalReplyInstallationV2
from sylanne3.graph_types import AtomKey, GraphVersion
from sylanne3.model_broker.internal_life_content_v1 import (
    InternalLifeContentInputV1, freeze_internal_life_content_request_v1,
    thaw_internal_life_content_request_v1, internal_life_content_ids_v1,
    parse_internal_life_content_output_v1, OUTPUT_SCHEMA,
)
from sylanne3.runtime.d06_internal_life_encoding_v1 import InternalLifeEncodingCauseV1
from sylanne3.runtime.internal_life_content_preparation_v1 import (
    TABLE, TRIGGERS, install_internal_life_content_schema_v1,
    require_internal_life_content_schema_v1, InternalLifeContentPreparedV1,
    decode_internal_life_prepared_v1,
)
from sylanne3.runtime_contracts import canonical_digest, canonical_serialize


def frozen_fixture():
    proof, _, _ = fixture_proof()
    cause = InternalLifeEncodingCauseV1(proof, 'prepared:fixture', D)
    input = InternalLifeContentInputV1(cause,
        GraphVersion(AtomKey.from_token(proof.episode.episode_ref), 1),
        GraphVersion(AtomKey.from_token(proof.event.self_mapping_ref), 1),
        GraphVersion(AtomKey.from_token(proof.event.perspective_ref), 1), 'owner', 3., 30., D)
    return freeze_internal_life_content_request_v1(input,
        NaturalReplyInstallationV2('installation', D, 'provider', 'model', 1024))


def prepared_fixture(frozen):
    ids = internal_life_content_ids_v1(frozen.input.cause)
    event = frozen.input.cause.occurrence.event
    return InternalLifeContentPreparedV1(event.namespace, event.activity.activity_id,
        frozen.installation_id, ids['job'], ids['prepare'], ids['acquire'], ids['action'], ids['call'],
        frozen.input.episode_version.key.token, frozen.input.occurrence_digest, D,
        event.activation_generation, event.graph_incarnation, canonical_serialize(plain_v1(frozen)),
        frozen.digest, ids['quote'], 1, D, D, 'provider:installed')


def test_complete_typed_frozen_roundtrip_and_minimal_occurrence_payload():
    frozen = frozen_fixture()
    raw = plain_v1(frozen)
    assert thaw_internal_life_content_request_v1(raw) == frozen
    assert type(raw['input']['episode_version']['key']) is str
    provider = json.loads(frozen.wire_json)
    assert 'evidence_unavailable' in frozen.wire_json
    assert 'undetermined' in frozen.wire_json
    assert 'Activity occurred; text content' not in frozen.wire_json
    assert 'historical_reads' not in frozen.wire_json
    assert 'before_interval' not in frozen.wire_json
    assert provider


@pytest.mark.parametrize('field', ['messages', 'wire_json', 'template_digest', 'purpose'])
def test_frozen_provider_or_template_drift_is_rejected(field):
    frozen = frozen_fixture()
    bad = {'messages': ({'role': 'user', 'content': 'forged'},), 'wire_json': '{}',
        'template_digest': 'b' * 64, 'purpose': 'expression'}[field]
    with pytest.raises((TypeError, ValueError)):
        replace(frozen, **{field: bad})


@pytest.mark.parametrize('revision', [True, 0, -1])
def test_exact_input_revision_never_accepts_bool_or_absence(revision):
    frozen = frozen_fixture()
    with pytest.raises((TypeError, ValueError)):
        replace(frozen.input, episode_version=GraphVersion(frozen.input.episode_version.key, revision))


def test_once_identity_is_occurrence_not_encoding_operation_or_model_wording():
    frozen = frozen_fixture()
    cause = frozen.input.cause
    ids = internal_life_content_ids_v1(cause)
    # A different current request/time or signed preparation locator cannot
    # create a second job/call for the same immutable authenticated occurrence.
    other = replace(cause, prepared_original_ref='prepared:another', prepared_original_digest='b' * 64)
    assert internal_life_content_ids_v1(other) == ids
    changed = replace(cause.occurrence, producing_operation_id='encode:different')
    assert internal_life_content_ids_v1(replace(cause, occurrence=changed)) != ids
    assert len(set(ids.values())) == len(ids)


def test_prepared_complete_roundtrip_and_wrong_once_locator_refusal():
    prepared = prepared_fixture(frozen_fixture())
    assert decode_internal_life_prepared_v1(plain_v1(prepared)) == prepared
    with pytest.raises(ValueError): replace(prepared, prepare_operation_id='new-caller-operation')
    with pytest.raises(ValueError): replace(prepared, activation_generation=True)


def test_candidate_is_only_model_description_without_numerical_promotion():
    frozen = frozen_fixture()
    raw = {'schema': OUTPUT_SCHEMA, 'occurrence_digest': frozen.input.occurrence_digest,
        'summary': 'The supplied internal activity occurred.', 'keywords': ['activity']}
    candidate = parse_internal_life_content_output_v1(json.dumps(raw), frozen)
    assert candidate.assertion_scope == 'model_description_only'
    assert candidate.before_state_status == 'evidence_unavailable'
    assert candidate.comparison_status == 'undetermined'
    assert candidate.affect_status == 'unavailable'
    raw['before_interval'] = [0, 0]
    with pytest.raises(ValueError): parse_internal_life_content_output_v1(json.dumps(raw), frozen)


@pytest.mark.parametrize('wrong', ['column', 'trigger'])
def test_actual_sqlite_wrong_existing_schema_or_missing_immutable_trigger_refuses(wrong):
    with sqlite3.connect(':memory:') as db:
        if wrong == 'column':
            db.execute(f'CREATE TABLE {TABLE}(bot TEXT)')
        else:
            install_internal_life_content_schema_v1(db)
            db.execute(f'DROP TRIGGER {TABLE}_no_delete')
        with pytest.raises(ValueError, match='exact DDL'):
            require_internal_life_content_schema_v1(db)


def test_actual_sqlite_original_append_rolls_back_and_schema_is_exact():
    with sqlite3.connect(':memory:', isolation_level=None) as db:
        install_internal_life_content_schema_v1(db)
        require_internal_life_content_schema_v1(db)
        db.execute('BEGIN')
        db.execute(f'INSERT INTO {TABLE} VALUES(?,?,?,?,?,?,?)',
            ('bot', 'persona', 'prepared', 'life-content-job:fixture', '{}', canonical_digest({}), D))
        db.execute('ROLLBACK')
        assert db.execute(f'SELECT count(*) FROM {TABLE}').fetchone() == (0,)
