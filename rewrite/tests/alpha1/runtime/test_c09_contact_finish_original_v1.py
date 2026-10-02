"""Actual Core fence/Graph historical joins and content-free archive seams.

Core begin/finish, canonical SQL joins and immutable archive run for real.
Owner/provider TypeSpecs and the source seal are bounded fixture inputs;
these cases do not attest installed freeze authentication or a signed switch.
No network client or real account is constructed.
"""
from copy import deepcopy
from dataclasses import asdict, replace
import json

import pytest

from test_contact_final_c09_joins_v1 import history_join
from test_contact_qualification_evidence_v1 import sql_evidence
from sylanne3.authority_service.core import AuthorityServiceCore
from sylanne3.authority_service.contract import JournalHead, AuthorityUnavailable
from sylanne3.authority_service.v2_fence_store import AuthorityV2FenceStore
from sylanne3.authority_service.v2_contract import to_wire, canonical_digest as adigest
from sylanne3.authority_service.c09_recovery_frame_v4 import make_source_seal_v4, make_fact_frame_v4, make_source_pin_v4
from sylanne3.authority_service.c09_source_prepare_v4 import persist_execution_source_bundle_in_tx_v4
from sylanne3.authority_service.c09_contact_finish_original_v1 import (
    TABLE, COLUMNS, capture_contact_finish_originals_v1, read_contact_finish_originals_v1,
    contact_graph_fact_v1, contact_finish_original_from_wire_v1, verify_contact_finish_recovery_v1,
    contact_finish_inventory_fact_v1, validate_contact_finish_frame_inventory_v1,
    _contact_finish_graph_scope_v1, _issue_contact_finish_scope_v1,
)
from sylanne3.runtime.contact_final_stage_v1 import _contact_final_result_v1
from sylanne3.runtime.domain_production_originals_v1 import install_domain_production_originals_v1, _receipt_wire
from sylanne3.runtime.c09_storage_rebase_contract_v1 import SanitizedGraphFactV4
from sylanne3.runtime_contracts import canonical_digest, canonical_serialize
from sylanne3.domains.d01.production_operations_v1 import plain_v1


@pytest.fixture
def finished(history_join, tmp_path):
    evidence, payload, receipt, _digest, _result, store = history_join
    ns = evidence.namespace; db = store._db
    core = AuthorityServiceCore(tmp_path/'finish-core.db', create=True,
        authorizer=lambda *args: True, deletion_verifier=lambda *args: True,
        execution_verifier=lambda *args: True, effect_verifier=lambda *args: True,
        dispatch_verifier=lambda *args: True)
    core._db.execute("UPDATE authority_meta SET value='authority' WHERE key='authority_id'")
    core.register_namespace('fixture', 'authority:fixture', 'holder',
        JournalHead('deletion', 0, 'genesis'), JournalHead('execution', 0, 'genesis'))
    anchor = core.current_anchor('fixture', 'authority:fixture')
    fences = AuthorityV2FenceStore(core._db, create=True, lock=core._lock)
    request = 'a'*64
    attempt = 'owner-domain-' + canonical_digest((ns, 'operation', request))[:48]
    permit = fences.begin_fence(subject='subject', holder='holder', operation='write',
        current_anchor=anchor, operation_id=attempt)
    snapshot = replace(evidence.effect_snapshot, anchor=anchor, permit_digest=adigest(permit))
    qualified = replace(evidence.qualification, d08_scope=replace(evidence.qualification.d08_scope,
        authority_head=anchor, authority_snapshot_digest=adigest(snapshot)))
    evidence = replace(evidence, effect_snapshot=snapshot, qualification=qualified)
    proof = deepcopy(payload['provenance']); proof['qualification_evidence'] = plain_v1(evidence)
    proof['qualification_digest'] = qualified.digest
    payload = {'namespace': asdict(ns), 'identity': {'operation_id': 'operation'},
        'authority': {'activation_generation': 1}, 'provenance': proof}
    digest = canonical_digest(payload)
    from sylanne3.graph_types import AtomKey
    result = _contact_final_result_v1(receipt=receipt, original_digest=digest,
        job_id=AtomKey.from_token(proof['job_ref']).name,
        admission_ref=proof['admission_ref'], dispatch_request_digest=proof['request_digest'])
    wire = canonical_serialize(to_wire(permit))
    db.execute('UPDATE graph_owner_domain_attempts_v3 SET attempt_id=?,anchor_json=?,permit_json=?,receipt_json=?',
        (attempt, canonical_serialize(asdict(anchor)), wire, canonical_serialize(result)))
    db.execute('UPDATE graph_bundle_fences_v2 SET permit_json=?', (wire,))
    install_domain_production_originals_v1(db)
    db.execute('INSERT INTO graph_bundle_operations VALUES(?,?,?,?,?,?,?,?)',
        (*ns.as_tuple, 'operation', receipt.operation_digest, receipt.activity_id, receipt.effect_id,
            receipt.commit_seq, canonical_serialize(_receipt_wire(receipt))))
    db.execute('INSERT INTO graph_domain_production_originals_v1 VALUES(?,?,?,?,?,?,?,?,?,?,?,?)',
        (*ns.as_tuple, 'operation', 'd08', 'prepare_contact_dispatch', request, digest,
            canonical_serialize(payload), '[]', receipt.operation_digest,
            canonical_serialize(_receipt_wire(receipt)), canonical_digest(receipt)))
    db.commit()
    finish_digest = 'sha256:' + canonical_digest({'schema': 'w01.owner-domain-write.v3',
        'operation_id': 'operation', 'request_digest': request, 'permit_token': permit.token})
    fences.finish_fence(permit, subject='subject', current_anchor=anchor,
        request_id='finish:'+attempt, request_digest=finish_digest)
    seal = make_source_seal_v4(authority_id='authority', installation_id='installation',
        namespace='authority:fixture', operation_id='delete:fixture', execution_journal_id='execution',
        execution_seq=0, execution_digest='genesis', prior_prefix_digest=None,
        suffix_row_commitments=(), accepted_receipt_digest='a'*64)
    fact = SanitizedGraphFactV4('operation', 'b'*64, 'c'*64, None)
    yield core, store, ns, seal, fact, permit
    core._db.close()


def capture(case):
    core, store, ns, seal, fact, _permit = case
    with core._tx() as control:
        store._db.execute('BEGIN')
        try:
            return capture_contact_finish_originals_v1(core_db=control, business=store._db,
                namespace_id=ns, seal=seal, verifier_commitment='d'*64,
                registry=store._registry, graph_facts=(fact,))
        finally:
            store._db.rollback()


def test_actual_finished_fence_and_business_join_archives_without_token_or_content(finished):
    original, = capture(finished)
    assert capture(finished) == (original,)
    encoded = canonical_serialize(asdict(original))
    assert finished[-1].token not in encoded and 'Fixture' not in encoded
    assert original.finish_request_id == 'finish:'+finished[-1].operation_id
    assert contact_finish_original_from_wire_v1(json.loads(encoded)) == original
    with finished[0]._tx() as db:
        assert read_contact_finish_originals_v1(db, namespace=original.namespace,
            operation_id=original.operation_id) == (original,)
        with pytest.raises(Exception, match='immutable'):
            db.execute('UPDATE '+TABLE+" SET original_digest=?", ('e'*64,))


@pytest.mark.parametrize('change', ('active', 'missing', 'wrong_finish', 'wrong_permit', 'missing_attempt'))
def test_actual_missing_pending_or_changed_core_finish_never_archives(finished, change):
    core, store, _ns, _seal, _fact, permit = finished
    if change == 'active':
        core._db.execute("UPDATE authority_v2_fences SET state='active',finish_request_id=NULL,finish_request_digest=NULL")
    elif change == 'missing': core._db.execute('DELETE FROM authority_v2_fences')
    elif change == 'wrong_finish': core._db.execute("UPDATE authority_v2_fences SET finish_request_digest=?", ('sha256:'+'e'*64,))
    elif change == 'wrong_permit':
        core._db.execute("UPDATE authority_v2_fences SET permit=?", (canonical_serialize(to_wire(replace(permit, holder='changed'))).encode(),))
    elif change == 'missing_attempt': store._db.execute('DELETE FROM graph_owner_domain_attempts_v3'); store._db.commit()
    with pytest.raises((AuthorityUnavailable, ValueError)): capture(finished)
    assert core._db.execute("SELECT name FROM sqlite_master WHERE name=?", (TABLE,)).fetchone() is None


@pytest.mark.parametrize('field', ('generation', 'fence_epoch', 'fence_revision', 'observed_execution_seq'))
def test_archive_bool_integer_identity_rejected_even_after_digest_recompute(finished, field):
    original, = capture(finished); raw = asdict(original); raw[field] = True
    from dataclasses import fields
    body = dict(raw); body['pinned_anchor'] = original.pinned_anchor; body['observed_core_anchor'] = original.observed_core_anchor
    raw['original_digest'] = canonical_digest(tuple(body[f.name] for f in fields(type(original)) if f.name != 'original_digest'))
    with pytest.raises(AuthorityUnavailable): contact_finish_original_from_wire_v1(raw)


def test_caller_constructed_port_or_scope_cannot_issue_authority():
    from sylanne3.authority_service.c09_current_recovery_originals_v4 import InstalledC09RecoveryOriginalsV4
    port = object.__new__(InstalledC09RecoveryOriginalsV4); port._snapshot = ('caller',)
    with pytest.raises(AuthorityUnavailable): _issue_contact_finish_scope_v1(port, ())
    with pytest.raises(AuthorityUnavailable):
        with _contact_finish_graph_scope_v1(object()): pass


@pytest.fixture
def consumed(finished):
    """Actual fence classifier retirement and cold SQLite archive, unsigned frame seam."""
    core, _store, _ns, seal, _fact, _permit = finished
    original, = capture(finished)
    facts = make_fact_frame_v4(authority_id=seal.authority_id, installation_id=seal.installation_id,
        namespace=seal.namespace, operation_id=seal.operation_id, old_journal_id=seal.execution_journal_id,
        old_seq=0, old_chain_head_digest='genesis', prior_fact_frame_digests=(),
        verifier_commitment='d'*64, executions=(), d02_facts=(), d11_facts=(), unknown_facts=(),
        graph_facts=tuple(sorted((contact_graph_fact_v1(original), contact_finish_inventory_fact_v1(seal.operation_id, (original,))), key=lambda f:f.operation_id)))
    pin = make_source_pin_v4(seal=seal, facts=facts)
    prepared = {'facts_digest': facts.facts_digest, 'facts_pin_original': asdict(pin),
        'old_core_anchor_original': asdict(original.observed_core_anchor),
        'new_core_anchor_original': asdict(replace(original.observed_core_anchor, activation_generation=2)),
        'anchor_transition_original': {'before_anchor': asdict(original.observed_core_anchor),
            'after_anchor': asdict(replace(original.observed_core_anchor, activation_generation=2))}}
    from sylanne3.authority_service.c09_authority_storage_rebase import _CoreTransform, _LEDGER_DDL
    transform = _CoreTransform(namespace=seal.namespace, operation_id=seal.operation_id,
        authority_id=seal.authority_id, pin_digest=pin.pin_digest, new_journal_id='next-execution',
        old_journal_id='execution', new_anchor_nonce='e'*64, continuation_permit_token='f'*64,
        old_seq=0, old_digest='genesis', facts=facts, execution_rows=())
    with core._tx() as db:
        persist_execution_source_bundle_in_tx_v4(db, seal=seal, pin=pin, facts=facts)
        columns = tuple(r[1] for r in db.execute('PRAGMA table_info(authority_v2_fences)'))
        output, changes = transform('authority_v2_fences', columns, tuple(db.execute('SELECT * FROM authority_v2_fences')))
        assert output == () and len(changes) == 1
        assert transform.consumed[('fence', original.owner_attempt_id)] == (original.owner_attempt_id, original.fence_row_commitment)
        db.execute(_LEDGER_DDL)
        db.execute('INSERT INTO authority_c09_consumed_execution_v1 VALUES(?,?,?,?,?,?)',
            (seal.namespace, 'fence', original.owner_attempt_id, original.owner_attempt_id, original.fence_row_commitment, pin.pin_digest))
        db.execute('DELETE FROM authority_v2_fences')
    return core.path, original, facts, pin, prepared


def test_actual_consumed_fence_archive_cold_join_without_surviving_fence(consumed):
    import sqlite3
    path, original, facts, pin, prepared = consumed
    with sqlite3.connect(path) as db:
        db.execute('BEGIN')
        assert db.execute('SELECT count(*) FROM authority_v2_fences').fetchone() == (0,)
        assert validate_contact_finish_frame_inventory_v1(db, facts) == (original,)
        assert verify_contact_finish_recovery_v1(db, original=original, facts=facts, pin=pin, prepared=prepared) == original


@pytest.mark.parametrize('change', ('consumed', 'pin', 'anchor', 'transition', 'all_archive', 'archive_trigger', 'inventory_member'))
def test_consumed_cold_join_or_complete_inventory_drift_refuses(consumed, change):
    import sqlite3
    path, original, facts, pin, prepared = consumed
    with sqlite3.connect(path) as db:
        if change == 'consumed': db.execute("UPDATE authority_c09_consumed_execution_v1 SET original_commitment=?", ('e'*64,))
        if change == 'pin': prepared = {**prepared, 'facts_pin_original': {**asdict(pin), 'pin_digest': 'e'*64}}
        if change == 'anchor': prepared = {**prepared, 'old_core_anchor_original': asdict(replace(original.observed_core_anchor, activation_generation=2))}
        if change == 'transition': prepared = {**prepared, 'anchor_transition_original': {'before_anchor': {}, 'after_anchor': {}}}
        if change == 'all_archive': db.execute('DROP TABLE '+TABLE)
        if change == 'archive_trigger': db.execute('DROP TRIGGER '+TABLE+'_no_delete')
        if change == 'inventory_member':
            body = {f: getattr(facts, f) for f in facts.__dataclass_fields__ if f not in {'facts_digest', 'schema'}}
            body['graph_facts'] = tuple(f for f in facts.graph_facts if not f.operation_id.startswith('c09-contact-finish-inventory:'))
            facts = make_fact_frame_v4(**body)
        db.commit(); db.execute('BEGIN')
        with pytest.raises(AuthorityUnavailable):
            validate_contact_finish_frame_inventory_v1(db, facts)
            verify_contact_finish_recovery_v1(db, original=original, facts=facts, pin=pin, prepared=prepared)


def test_contact_physical_erasure_remains_hold_pending_inventory_version_decision(finished):
    from sylanne3.authority_service.c09_contact_finish_original_v1 import require_contact_finish_graph_erasure_v1
    with pytest.raises(AuthorityUnavailable, match='versioned finish inventory unresolved'):
        require_contact_finish_graph_erasure_v1(finished[1]._db, namespace=finished[2], operation_id='operation', proof={})
