"""The joint graph candidate retains every active edge and drive."""

from dataclasses import asdict, replace
import json

import pytest

from sylanne3.contracts import canonical_json
from sylanne3.domains.d04 import (
    CommittedRef, FeelingState, RootBlockIdentity, decode_numeric_checkpoint,
    encode_numeric_checkpoint,
)
from sylanne3.domains.d04.numeric_coupling import REGISTERED_AXIS_IDS, build_numeric_coupling_write
from sylanne3.domains.d04.numeric_drive import sourced_numeric_drive_write
from sylanne3.domains.d07 import D07DomainProvider
from sylanne3.graph_types import AtomKey, GraphVersion, Owner
from sylanne3.memory_types import source_key
from sylanne3.runtime.joint_numeric_component import JointNumericHold, read_joint_numeric_component
from sylanne3.runtime_contracts import QueryEpoch

from rewrite.tests.alpha1.runtime.test_authoritative_coupling_snapshot import (
    _add_checkpoint, _fixture, _insert,
)
from rewrite.tests.alpha1.runtime.test_current_numeric_sources import _drive


def _component(tmp_path, *, edge_interval=(1.0, 2.0), include_second_drive=True):
    store, namespace, scheme, assets, source, root = _fixture(tmp_path)
    other = _add_checkpoint(store._db, namespace, scheme, assets, source, "block-other")
    edge = build_numeric_coupling_write(
        scheme=scheme, edge_version=1, left_ref=root.token,
        left_axis=REGISTERED_AXIS_IDS[0], right_ref=other.token,
        right_axis=REGISTERED_AXIS_IDS[0], coefficient=0.05,
        source_ref=source.token, effective_from=edge_interval[0],
        effective_until=edge_interval[1],
    )
    _insert(store._db, namespace, edge.key, edge.value)
    for checkpoint in (root, other) if include_second_drive else (root,):
        drive = sourced_numeric_drive_write(_drive(checkpoint, source))
        _insert(store._db, namespace, drive.key, drive.value)
    return store, namespace, scheme, root, other, edge


def _read(store, namespace, scheme, root, *, life_source_bridge=None):
    store._db.execute("BEGIN IMMEDIATE")
    try:
        return read_joint_numeric_component(
            store._db, namespace=namespace, registry=store._registry,
            scheme=scheme, root_ref=root.token, role_start=1.0, role_end=2.0,
            expected_query_epoch=QueryEpoch(namespace, "all", 1),
            expected_graph_incarnation="graph:one", expected_graph_revision=1,
            expected_access_epoch=0, expected_delete_epoch=0,
            audience=("owner",), purpose="context",
            _life_source_bridge=life_source_bridge,
        )
    finally:
        store._db.execute("ROLLBACK")


def test_complete_two_block_component_is_unsigned_hold(tmp_path):
    store, namespace, scheme, root, other, edge = _component(tmp_path)
    try:
        result = _read(store, namespace, scheme, root)
        assert result.checkpoint_refs == tuple(sorted((root.token, other.token)))
        assert result.edges[0].edge_id == edge.value["edge_id"]
        assert len(result.block_drives) == 2
        assert result.query_epoch.revision == 1
        assert result.status == "hold"
        assert "joint_operator_asset_and_abi2_binding" in result.missing_sources
    finally:
        store.close()


def test_transitive_edge_expands_component_and_requires_third_drive(tmp_path):
    store, namespace, scheme, assets, source, root = _fixture(tmp_path)
    try:
        middle = _add_checkpoint(store._db, namespace, scheme, assets, source, "middle")
        third = _add_checkpoint(store._db, namespace, scheme, assets, source, "third")
        for left, right in ((root, middle), (middle, third)):
            edge = build_numeric_coupling_write(
                scheme=scheme, edge_version=1, left_ref=left.token,
                left_axis=REGISTERED_AXIS_IDS[0], right_ref=right.token,
                right_axis=REGISTERED_AXIS_IDS[0], coefficient=0.05,
                source_ref=source.token, effective_from=1.0, effective_until=2.0,
            )
            _insert(store._db, namespace, edge.key, edge.value)
        for checkpoint in (root, middle):
            drive = sourced_numeric_drive_write(_drive(checkpoint, source))
            _insert(store._db, namespace, drive.key, drive.value)
        with pytest.raises(JointNumericHold, match="no complete interval drive"):
            _read(store, namespace, scheme, root)
        third_drive = sourced_numeric_drive_write(_drive(third, source))
        _insert(store._db, namespace, third_drive.key, third_drive.value)
        result = _read(store, namespace, scheme, root)
        assert result.checkpoint_refs == tuple(sorted((root.token, middle.token, third.token)))
        assert len(result.edges) == 2
    finally:
        store.close()


@pytest.mark.parametrize("case", ("missing_drive", "partial_edge", "stale_epoch"))
def test_incomplete_component_never_drops_an_edge_or_block(tmp_path, case):
    store, namespace, scheme, root, _other, edge = _component(
        tmp_path, include_second_drive=case != "missing_drive",
        edge_interval=(1.5, 2.5) if case == "partial_edge" else (1.0, 2.0),
    )
    try:
        if case == "stale_epoch":
            store._db.execute("UPDATE graph_epochs SET revision=2")
        with pytest.raises(JointNumericHold):
            _read(store, namespace, scheme, root)
    finally:
        store.close()


def test_new_feeling_joint_freezes_current_interpretation_and_source_closure(tmp_path):
    store, namespace, scheme, root, _other, _edge = _component(tmp_path)
    try:
        source = source_key(*namespace.as_tuple, "source-1")
        for spec in D07DomainProvider.type_specs():
            store._registry.register(spec)
        drive = sourced_numeric_drive_write(_drive(root, source))
        interpretation_key = AtomKey(
            Owner("activity", *namespace.as_tuple, "activity-1"),
            "d07.current_interpretation.v1", "interpretation-1",
        )
        feeling_key = AtomKey(
            Owner("persona", *namespace.as_tuple), "d04.feeling_state.v1", root.name,
        )
        feeling = FeelingState(
            root.name, source.token, scheme.scheme_version, scheme.operator_version,
            ((REGISTERED_AXIS_IDS[0], 0.2),), ("facet-1",),
            (interpretation_key.token,), (drive.key.token,), (source.token,),
            scheme.parameter_version, scheme.coupling_version, 1.0,
        )
        _insert(store._db, namespace, feeling_key, asdict(feeling))
        encoded = store._db.execute(
            "SELECT value FROM graph_atoms WHERE token=?", (root.token,),
        ).fetchone()[0]
        checkpoint = decode_numeric_checkpoint(json.loads(encoded))
        checkpoint = replace(
            checkpoint,
            block=RootBlockIdentity(root.name, "template-1", "feeling",
                                    source.token, "facet-1", source.owner.subject),
            graph_state=CommittedRef(feeling_key.token, 1),
        )
        store._db.execute(
            "UPDATE graph_atoms SET value=? WHERE token=?",
            (canonical_json(encode_numeric_checkpoint(checkpoint)), root.token),
        )
        with pytest.raises(JointNumericHold, match="interpretation original is unavailable"):
            _read(store, namespace, scheme, root)
        _insert(store._db, namespace, interpretation_key, {
            "schema": "d07.current_interpretation.v1",
            "interpretation_id": "interpretation-1", "activity_id": "activity-1",
            "question_key": "question:memory", "proposition": "source remains relevant",
            "stance": "support", "subjective_conviction": 0.7,
            "evidence_status": "insufficient", "source_refs": [source.token],
            "source_families": ["family-1"], "meaningful_unknowns": [],
            "current": True,
        })
        result = _read(store, namespace, scheme, root)
        assert GraphVersion(interpretation_key, 1) in result.read_versions
        store._db.execute(
            "UPDATE graph_atoms SET valid=0 WHERE token=?", (interpretation_key.token,),
        )
        with pytest.raises(JointNumericHold, match="interpretation original is unavailable"):
            _read(store, namespace, scheme, root)
    finally:
        store.close()


def test_ordinary_derived_source_cannot_use_life_joint_bridge(tmp_path):
    from sylanne3.memory_types import SourceRecord, access_key
    store, namespace, scheme, root, _other, _edge = _component(tmp_path)
    try:
        assert len(_read(store, namespace, scheme, root).block_drives) == 2
        source = source_key(*namespace.as_tuple, "source-1")
        original = SourceRecord.from_dict(json.loads(store._db.execute(
            "SELECT value FROM graph_atoms WHERE token=?", (source.token,),
        ).fetchone()[0]))
        parent = replace(original, source_id="source-parent", provenance_root="family-parent")
        _insert(store._db, namespace, source_key(*namespace.as_tuple, parent.source_id), parent.to_dict())
        _insert(store._db, namespace, access_key(*namespace.as_tuple, parent.source_id), {
            "source_id": parent.source_id, "audiences": ["owner"],
            "purposes": ["context"], "status": "active", "recorded_at": 0.0,
        })
        derived = replace(original, source_kind="internal", parent_source_ids=(parent.source_id,))
        store._db.execute("UPDATE graph_atoms SET value=? WHERE token=?",
            (canonical_json(derived.to_dict()), source.token))
        changes = store._db.total_changes
        with pytest.raises(JointNumericHold, match="requires an independent root source"):
            _read(store, namespace, scheme, root)
        assert store._db.total_changes == changes
    finally:
        store.close()


def test_constructed_life_bridge_has_no_private_issuance(tmp_path):
    from sylanne3.runtime.d06_life_numeric_joint_v1 import _LifeJointSourceBridgeV1
    store, namespace, scheme, root, _other, _edge = _component(tmp_path)
    try:
        assert len(_read(store, namespace, scheme, root).block_drives) == 2
        unissued = _LifeJointSourceBridgeV1(object(), object(), None, None)
        changes = store._db.total_changes
        with pytest.raises(ValueError, match="requires its live private issuance"):
            _read(store, namespace, scheme, root, life_source_bridge=unissued)
        assert store._db.total_changes == changes
    finally:
        store.close()


def _life_job_serialization_case_v1(tmp_path):
    """Unsigned data-only vector; no Source permission, job admission or native run."""
    from types import SimpleNamespace
    from sylanne3.graph_types import GraphAtom, GraphSnapshot, NamespaceEpoch
    from sylanne3.runtime_contracts import (AuthorityContext, CommandEnvelope, OperationIdentity,
        VersionGuard, SourceQualification, RUNTIME_SCHEMA, canonical_digest)
    from sylanne3.runtime.jobs import PersistentJob
    from sylanne3.runtime.d11_types import job_graph_write
    from sylanne3.runtime.d04_current_joint_replay_input_v2 import D04CurrentJointReplayInputV2
    from sylanne3.runtime.d04_joint_product_assembly_v3 import D04JointProductPreparationV3
    from sylanne3.runtime.d04_semantic_mapping_v3 import D04JointEvidenceInputsV3, joint_evidence_field_v3
    from sylanne3.runtime.d04_appraisal_driver_v3 import graph_read_rows_v3
    store, ns, scheme, root, _, _ = _component(tmp_path)
    try:
        component = _read(store, ns, scheme, root)
        atoms = []
        for version in component.read_versions:
            row = store._db.execute('SELECT revision,value,valid FROM graph_atoms WHERE token=?',
                (version.key.token,)).fetchone()
            if version.revision == 0:
                assert row is None
                atoms.append(GraphAtom(version.key, 0, {}, False))
            else:
                assert row[0] == version.revision
                atoms.append(GraphAtom(version.key, row[0], json.loads(row[1]), bool(row[2])))
    finally:
        store.close()
    job = PersistentJob('serial-job', 'serial-op', 'serial-activity', None, *ns.as_tuple,
        'serial-input', 'running', 'd04.joint_numeric', {}, None, '2030-01-01T00:00:00Z',
        'serial-budget', 'serial-cpu', {}, 'serial-worker', '2030-01-01T00:00:00Z', 1, 0, {}, None)
    key = job_graph_write(job).key
    snapshot = GraphSnapshot(tuple(sorted((*atoms, GraphAtom(key, 0, {}, False)), key=lambda a:a.key.token)),
        (NamespaceEpoch(*ns.as_tuple, 1),))
    identity = OperationIdentity(job.activity_id, None, job.operation_id, 'joint_advance',
        job.operation_id, canonical_digest({'input_refs': []}))
    envelope = CommandEnvelope(RUNTIME_SCHEMA, identity,
        AuthorityContext('serial-actor', 'd04', 'serial-capability', ns, ('persona',),
            'context', ('owner',), 'serial-policy', 1, 1),
        VersionGuard(snapshot.versions, (component.query_epoch,), 0, 0, component.catalogue_hash,
            'serial-scheme', 'serial-operator', 'serial-policy', (), (), ()),
        SourceQualification((), 'derived', None, 0.0, 'inference', 'ineligible', None, 'not_applicable'),
        (), job.budget_ref, 1000.0, 250.0, 'serial-interval', ())
    preparation = D04JointProductPreparationV3(envelope,
        D04CurrentJointReplayInputV2(component, (), (), ()), None, snapshot)
    rows = graph_read_rows_v3(snapshot, snapshot.versions)
    stamp = {'namespace': asdict(ns), 'graph_revision': component.graph_revision,
        'query_epoch': asdict(component.query_epoch), 'graph_incarnation': component.graph_incarnation}
    fields = {'read_versions_digest': {'versions': [{'ref':r.ref,'revision':r.revision} for r in rows]},
        'snapshot_stamp_digest': stamp,
        'closure_digest': {'snapshot_stamp': stamp, 'numeric_scan_rows': ['unchanged-current-numeric']},
        'absent_reads_digest': {'absent_rows': [asdict(r) for r in rows if r.revision == 0],
            'negative_numeric_inventory': {'complete': True}},
        'source_closure_digest': {'unmodified_binary64': 0.1}}
    evidence = D04JointEvidenceInputsV3(ns, component.candidate_digest, component.checkpoint_refs,
        tuple((name, canonical_json(joint_evidence_field_v3(name, value)[0]))
            for name, value in sorted(fields.items())), rows, None)
    return preparation, evidence, job, SimpleNamespace(graph_revision=2), NamespaceEpoch(*ns.as_tuple, 2)


@pytest.mark.parametrize('job_is_component_dependency', (False, True))
def test_life_job_rebinding_changes_only_actual_job_and_stamp_data(tmp_path, job_is_component_dependency):
    from sylanne3.runtime.d06_life_numeric_joint_v1 import _rebase_life_joint_job_input_v1
    from sylanne3.runtime.d11_types import job_graph_write
    from sylanne3.runtime_contracts import canonical_digest
    preparation, evidence, job, metadata, epoch = _life_job_serialization_case_v1(tmp_path)
    key = job_graph_write(job).key
    if job_is_component_dependency:
        from sylanne3.runtime.joint_numeric_component import joint_numeric_component_digest_v1
        prior = preparation.current.component
        versions = tuple(sorted((*prior.read_versions, GraphVersion(key, 0)), key=lambda v:v.key.token))
        prior = replace(prior, read_versions=versions, read_values_digest=canonical_digest(tuple(sorted(
            (atom.key.token, atom.revision, canonical_digest(atom.value), atom.valid)
            for atom in preparation.snapshot.atoms))))
        prior = replace(prior, candidate_digest=joint_numeric_component_digest_v1(prior))
        preparation = replace(preparation, current=replace(preparation.current, component=prior))
        evidence = replace(evidence, component_digest=prior.candidate_digest)
    before = canonical_digest((preparation, evidence))
    updated, output = _rebase_life_joint_job_input_v1(preparation, evidence, job, metadata, epoch)
    if job_is_component_dependency:
        assert GraphVersion(key, 1) in updated.current.component.read_versions
        assert GraphVersion(key, 0) not in updated.current.component.read_versions
        assert updated.current.component.read_values_digest == canonical_digest(tuple(sorted(
            (atom.key.token, atom.revision, canonical_digest(atom.value), atom.valid)
            for atom in updated.snapshot.atoms)))
    else:
        assert updated.current.component.read_versions == preparation.current.component.read_versions
        assert updated.current.component.read_values_digest == preparation.current.component.read_values_digest
    key = job_graph_write(job).key
    assert updated.snapshot.get(key).revision == 1
    assert updated.snapshot.get(key).value == job_graph_write(job).value
    assert all(updated.snapshot.get(atom.key) == atom for atom in preparation.snapshot.atoms if atom.key != key)
    assert updated.current.component.query_epoch.revision == 2
    assert updated.current.component.graph_revision == 2
    assert updated.current.component.candidate_digest != preparation.current.component.candidate_digest
    assert updated.envelope.version_guard.read_versions == updated.snapshot.versions
    assert updated.envelope.version_guard.query_epochs == (updated.current.component.query_epoch,)
    assert (updated.envelope.deadline_utc, updated.envelope.monotonic_deadline,
        updated.envelope.parent_budget_lease_ref, updated.envelope.authority) == (
        preparation.envelope.deadline_utc, preparation.envelope.monotonic_deadline,
        preparation.envelope.parent_budget_lease_ref, preparation.envelope.authority)
    assert dict(output.field_payloads)['source_closure_digest'] == dict(evidence.field_payloads)['source_closure_digest']
    expected_absent = [asdict(row) for row in evidence.read_rows if row.revision == 0 and row.ref != key.token]
    assert json.loads(dict(output.field_payloads)['absent_reads_digest'])['payload']['absent_rows'] == expected_absent
    assert canonical_digest((preparation, evidence)) == before


@pytest.mark.parametrize('invalid', ('occupied_job', 'different_read_rows'))
def test_life_job_data_rebinding_refuses_non_original_negative_input(tmp_path, invalid):
    from sylanne3.graph_types import GraphAtom, GraphSnapshot
    from sylanne3.runtime.d06_life_numeric_joint_v1 import _rebase_life_joint_job_input_v1
    from sylanne3.runtime.d11_types import job_graph_write
    preparation, evidence, job, metadata, epoch = _life_job_serialization_case_v1(tmp_path)
    if invalid == 'occupied_job':
        key = job_graph_write(job).key
        preparation = replace(preparation, snapshot=GraphSnapshot(tuple(
            GraphAtom(key, 1, job_graph_write(job).value, True) if atom.key == key else atom
            for atom in preparation.snapshot.atoms), preparation.snapshot.epochs))
    else:
        evidence = replace(evidence, read_rows=evidence.read_rows[:-1])
    with pytest.raises(ValueError, match='actual frozen negative read'):
        _rebase_life_joint_job_input_v1(preparation, evidence, job, metadata, epoch)


def test_original_reader_keeps_normal_route_without_life_write_proof():
    """Explicit unselected SQL fixture; this is no production Source admission."""
    import sqlite3
    from sylanne3.runtime_contracts import NamespaceId, canonical_digest
    from sylanne3.runtime.d04_appraisal_driver_v3 import (
        install_d04_appraisal_schema_v3, read_d04_original_v3, record_d04_original_in_transaction_v3)
    from sylanne3.runtime.d06_life_numeric_joint_v1 import read_bound_life_joint_new_original_v1
    db = sqlite3.connect(':memory:')
    ns = NamespaceId('original-bot', 'original-persona')
    try:
        db.execute('BEGIN')
        install_d04_appraisal_schema_v3(db)
        selected = dict(table='graph_d04_originals_v3', columns=('payload_json', 'payload_digest'),
            key_columns=('bot', 'persona', 'kind', 'original_ref'),
            key=(*ns.as_tuple, 'numeric_prepared', 'original-operation'))
        assert read_bound_life_joint_new_original_v1(db, **selected) == (False, None)
        assert read_d04_original_v3(db, ns, 'numeric_prepared', 'original-operation') is None
        payload = {'schema': 'test-only-original', 'value': 'retained'}
        digest = record_d04_original_in_transaction_v3(db, ns, 'numeric_prepared', 'original-operation', payload)
        assert digest == canonical_digest(payload)
        assert read_d04_original_v3(db, ns, 'numeric_prepared', 'original-operation') == (payload, digest)
        assert record_d04_original_in_transaction_v3(db, ns, 'numeric_prepared', 'original-operation', payload) == digest
        with pytest.raises(ValueError, match='reused with changed payload'):
            record_d04_original_in_transaction_v3(db, ns, 'numeric_prepared', 'original-operation', {'value': 'changed'})
        assert read_bound_life_joint_new_original_v1(db, **selected) == (False, None)
    finally:
        db.rollback()
        db.close()


def test_life_bridge_typed_getter_rejects_unissued_bridge(tmp_path):
    """Typed Life Source reads exist only through the private live issuance."""
    from sylanne3.runtime.d06_life_numeric_joint_v1 import _LifeJointSourceBridgeV1
    from sylanne3.runtime.life_numeric_source_bridge_v1 import (
        life_joint_bridge_reader_v1, read_life_joint_bridge_atom_v1,
        read_life_joint_bridge_rows_v1)
    store, _namespace, _scheme, _assets, _source, root = _fixture(tmp_path)
    unissued = _LifeJointSourceBridgeV1(object(), object(), None, None)
    store._db.execute("BEGIN IMMEDIATE")
    try:
        with pytest.raises(ValueError, match="live private issuance"):
            life_joint_bridge_reader_v1(store._db, unissued)
        with pytest.raises(TypeError, match="exact atom key"):
            read_life_joint_bridge_atom_v1(store._db, unissued, root.token)
        with pytest.raises(ValueError, match="live private issuance"):
            read_life_joint_bridge_rows_v1(store._db, unissued, ("d04.numeric_coupling.v1",))
        with pytest.raises(TypeError, match="exact type names"):
            read_life_joint_bridge_rows_v1(store._db, unissued, ())
    finally:
        store._db.execute("ROLLBACK")
