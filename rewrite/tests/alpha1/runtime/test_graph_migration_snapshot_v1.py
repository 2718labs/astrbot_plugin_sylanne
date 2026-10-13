"""Focused closure and tamper checks for the graph migration source helper."""

from dataclasses import replace
from hashlib import sha256

import pytest

from sylanne3.graph_store import GraphMigrationVerifiedTransferV1, GraphStore
from sylanne3.graph_types import AtomKey, Owner, TypeRegistry
from sylanne3.runtime.graph_migration_snapshot_v1 import (
    IncompleteMigrationClosure, import_snapshot_into_isolated_target_in_tx,
    _inventory, read_target_import_receipt, seal_source_namespace_in_tx,
    validate_snapshot_for_isolated_target,
)
from sylanne3.runtime_contracts import NamespaceId, SnapshotRequirementsV2
from sylanne3.runtime_contracts import canonical_digest, canonical_serialize
from sylanne3.runtime.natural_reply_job_v2 import install_schema as install_natural_preparations
from sylanne3.runtime.natural_review_issue_v2 import install_review_attempt_schema
from sylanne3.runtime.d12_compiled_candidate_store_v1 import (
    install_d12_compiled_candidate_store_v1,
)
from sylanne3.authority_service.internal_work_contract import InternalWorkBindingV1
from sylanne3.domains.d02.body_quote_original import install_body_quote_schema
from sylanne3.graph_coordinator import namespace_ref
from sylanne3.runtime.c04_internal_work_original_v1 import (
    C04InternalWorkPreparedV1, install_c04_internal_work_original_v1,
    record_c04_internal_work_prepared_v1,
)


NAMESPACE = NamespaceId("migration-bot", "migration-persona")


def test_life_family_checks_empty_schema_and_exact_objects(tmp_path):
    source = GraphStore(tmp_path / "life-schema.db", TypeRegistry())
    try:
        tables = {name: rows for name, _, rows in _inventory(source._db, NAMESPACE)}
        assert tables["graph_d11_life_originals_v1"] == ()
        assert tables["graph_d11_life_artifact_stage_v1"] == ()
        source._db.execute("CREATE INDEX life_unreviewed ON graph_d11_life_originals_v1(kind)")
        with pytest.raises(IncompleteMigrationClosure, match="Life durable schema differs"):
            _inventory(source._db, NAMESPACE)
        source._db.execute("DROP INDEX life_unreviewed")
        source._db.execute("ALTER TABLE graph_d11_life_artifact_stage_v1 ADD COLUMN unexpected TEXT")
        with pytest.raises(IncompleteMigrationClosure, match="Life durable schema differs"):
            _inventory(source._db, NAMESPACE)
    finally:
        source.close()


def test_life_family_rejects_unregistered_noncanonical_and_cross_namespace_rows():
    from sylanne3.runtime.graph_migration_snapshot_v1 import _validate_life_row
    from sylanne3.runtime.domain_production_erasure_v1 import TABLE_COLUMNS
    from sylanne3.runtime.d11_artifact_draft_contract_v1 import DraftActivityScopeV1, draft_to_wire_v1
    from sylanne3.runtime.d11_life_contract_v1 import LifeInputRefV1
    from sylanne3.memory_types import source_key

    table = "graph_d11_life_originals_v1"
    scope = DraftActivityScopeV1("activity", "actor", "ingress", "c02",
        LifeInputRefV1(source_key(*NAMESPACE.as_tuple, "source").token, 1, "a" * 64),
        "lease", "registration", "b" * 64, "2030-01-01T00:00:00Z", "owner", 1, "c" * 64)
    raw = draft_to_wire_v1(scope)
    payload = canonical_serialize(raw)
    # A typed codec check alone is not a signed or committed producer original.
    row = (*NAMESPACE.as_tuple, "activity_scope", "scope", "producer", payload, canonical_digest(raw), "d" * 64)
    assert _validate_life_row(table, TABLE_COLUMNS[table], row, NAMESPACE)[2] == scope
    bad_rows = (
        (*row[:2], "unregistered_future_kind", *row[3:]),
        (*row[:5], payload + " ", *row[6:]),
        (*row[:5], payload[:-1] + ',"schema":"d11.artifact-draft-activity-scope.v1"}', *row[6:]),
        (*row[:6], "e" * 64, row[7]),
        (*row[:7], "invalid-signature"),
        ("other-bot", row[1], *row[2:]),
    )
    for invalid in bad_rows:
        with pytest.raises(IncompleteMigrationClosure, match="Life durable row is not closed"):
            _validate_life_row(table, TABLE_COLUMNS[table], invalid, NAMESPACE)


def test_life_stage_source_and_target_require_prepared_original_and_preserve_blob(tmp_path):
    from sylanne3.runtime.graph_migration_snapshot_v1 import _check_snapshot_rows, _hash, _validate_life_row
    from sylanne3.runtime.domain_production_erasure_v1 import TABLE_COLUMNS
    from sylanne3.runtime.d11_life_contract_v1 import ARTIFACT_SCHEMA, RECIPE_ID, life_artifact_ref_v1
    from sylanne3.memory_types import SourceRecord, source_key

    capability = object()
    source = GraphStore(tmp_path / "life-source.db", TypeRegistry())
    target = GraphStore(tmp_path / "life-target.db", TypeRegistry())
    source._coordinator_capability = target._coordinator_capability = capability
    try:
        expected = source.install_graph_recovery_genesis(_requirements(), _capability=capability)
        snapshot = _seal(source, capability, expected)
        record = SourceRecord("source", "Bounded test input", "actor", "reported", "confirmed",
            0, 0, "test-source", ("owner",), ("context",))
        artifact = dict(schema=ARTIFACT_SCHEMA, recipe_id=RECIPE_ID, recipe_version=1,
            activity_id="activity", effect_id="effect", attempt_id="attempt",
            source_ref=source_key(*NAMESPACE.as_tuple, "source").token, source_revision=1,
            source_digest=canonical_digest(record.to_dict()), source_record=record.to_dict())
        blob = canonical_serialize(artifact).encode("utf-8")
        row = (*NAMESPACE.as_tuple, "execution", "a" * 64, life_artifact_ref_v1(NAMESPACE, "effect"),
            blob, sha256(blob).hexdigest(), len(blob), None)
        table = "graph_d11_life_artifact_stage_v1"
        assert _validate_life_row(table, TABLE_COLUMNS[table], row, NAMESPACE)[1]["artifact_bytes"] is blob
        assert _hash(row) != _hash((*row[:5], blob.decode(), *row[6:]))
        source._db.execute("INSERT INTO " + table + " VALUES(?,?,?,?,?,?,?,?,?)", row)
        with pytest.raises(IncompleteMigrationClosure, match="no exact prepared execution"):
            _inventory(source._db, NAMESPACE)
        entries = tuple((name, columns, (row,) if name == table else rows)
            for name, columns, rows in snapshot.tables)
        with pytest.raises(IncompleteMigrationClosure, match="no exact prepared execution"):
            _check_snapshot_rows(target._db, replace(snapshot, tables=entries))
        assert target._db.execute("SELECT count(*) FROM " + table).fetchone() == (0,)
    finally:
        source.close()
        target.close()


def _requirements():
    return SnapshotRequirementsV2(
        namespace=NAMESPACE, authority_id="authority-a",
        authority_namespace="authority-namespace-a", activation_generation=1,
        deletion_journal_id="deletion-a", deletion_seq=0,
        deletion_digest="genesis", execution_journal_id="execution-a",
        execution_seq=0, execution_digest="genesis", revocation_epoch=0,
        graph_incarnation="graph-source-a")


def _seal(store, capability, expected):
    with store._lock:
        store._db.execute("BEGIN IMMEDIATE")
        try:
            sealed = seal_source_namespace_in_tx(
                store, NAMESPACE, transfer_id="transfer-a",
                source_installation_id="source-installation-a",
                permit_token="source-permit-token-a", expected=expected,
                _capability=capability)
            store._db.execute("COMMIT")
            return sealed
        except BaseException:
            store._db.execute("ROLLBACK")
            raise


class _TrustedTransfer:
    def __init__(self, receipt, proof):
        self.receipt, self.proof = receipt, proof

    def verify_local(self, value):
        if value is not self.receipt:
            raise PermissionError("unrecognized transfer")
        return self.proof


def test_seals_namespace_rows_and_checks_isolated_target(tmp_path):
    capability = object()
    source = GraphStore(tmp_path / "source.db", TypeRegistry())
    target = GraphStore(tmp_path / "target.db", TypeRegistry())
    source._coordinator_capability = target._coordinator_capability = capability
    try:
        expected = source.install_graph_recovery_genesis(
            _requirements(), _capability=capability)
        with source._lock:
            source._db.execute(
                "INSERT INTO runtime_jobs(job_id,operation_id,activity_id,effect_id,"
                "bot_id,persona_id,snapshot_ref,phase,work_kind,continuation_json,"
                "wake_condition_json,deadline_utc,budget_ref,resource_ref,"
                "operator_versions_json,lease_holder,lease_expires_utc,fence,"
                "cancel_epoch,usage_json,result_ref) "
                "VALUES('job-a','op-a','activity-a','effect-a',?,?,"
                "'snapshot-a','queued','work-a','{}','{}','', '', '', '{}',"
                "NULL,NULL,0,0,'{}',NULL)", NAMESPACE.as_tuple)
            source._db.execute(
                "INSERT INTO graph_bundle_outbox VALUES(?,?,?,?,?)",
                (*NAMESPACE.as_tuple, "outbox-a", "op-a", "pending"))
            source._db.execute(
                "INSERT INTO graph_bundle_outbox VALUES(?,?,?,?,?)",
                ("other-bot", "other-persona", "outbox-b", "op-b", "pending"))
            # Snapshot routing preserves opaque immutable root bytes; the
            # restored Owner and D11 originals still need independent proof.
            source._db.execute(
                "INSERT INTO graph_bundle_operations "
                "(bot,persona,operation_id,digest,activity_id,effect_id,"
                "commit_seq,receipt_json) VALUES(?,?,?,?,?,?,?,?)",
                (*NAMESPACE.as_tuple, "root-op", "a" * 64, "root-activity",
                 None, 1, '{"ledger_refs":[],"outbox_refs":[]}'),
            )
            source._db.execute(
                "INSERT INTO graph_d04_root_adoption_originals_v2 "
                "VALUES(?,?,?,?,?)",
                (*NAMESPACE.as_tuple, "root-op", '{}', "b" * 64),
            )
        snapshot = _seal(source, capability, expected)
        rows = {name: values for name, _, values in snapshot.tables}
        assert len(rows["runtime_jobs"]) == 1
        assert len(rows["graph_bundle_outbox"]) == 1
        assert len(rows["graph_recovery_metadata_v2"]) == 1
        assert rows["graph_d04_root_adoption_originals_v2"] == (
            (*NAMESPACE.as_tuple, "root-op", '{}', "b" * 64),
        )
        assert snapshot.source_metadata == expected
        assert snapshot.digest.startswith("sha256:")
        validate_snapshot_for_isolated_target(target, snapshot,
                                              _capability=capability)
        target_requirements = replace(
            _requirements(), activation_generation=3, revocation_epoch=1,
            graph_incarnation="graph-target-a")
        transfer_receipt = object()
        target._migration_transfer_verifier = _TrustedTransfer(
            transfer_receipt, GraphMigrationVerifiedTransferV1(
                snapshot.transfer_id, expected, target_requirements,
                "target_recovering", snapshot.digest))
        with target._lock:
            target._db.execute("BEGIN IMMEDIATE")
            try:
                imported = import_snapshot_into_isolated_target_in_tx(
                    target, snapshot, target_requirements, transfer_receipt,
                    _capability=capability)
                assert imported.source_graph_revision == 0
                assert imported.target_graph_revision == 1
                target._db.execute("COMMIT")
            except BaseException:
                target._db.execute("ROLLBACK")
                raise
        target.close()
        target = GraphStore(tmp_path / "target.db", TypeRegistry())
        target._coordinator_capability = capability
        assert read_target_import_receipt(
            target, NAMESPACE, snapshot.transfer_id,
            _capability=capability) == imported
        assert target._db.execute(
            "SELECT original_json,original_digest FROM "
            "graph_d04_root_adoption_originals_v2 WHERE bot=? AND persona=? "
            "AND operation_id='root-op'", NAMESPACE.as_tuple,
        ).fetchone() == ('{}', "b" * 64)
        assert target.graph_recovery_metadata(
            NAMESPACE, _capability=capability).requirements == target_requirements
        with pytest.raises(IncompleteMigrationClosure, match="digest changed"):
            validate_snapshot_for_isolated_target(
                target, replace(snapshot, graph_epoch=1), _capability=capability)
    finally:
        source.close()
        target.close()


def test_refuses_unreviewed_table_and_stale_graph_stamp(tmp_path):
    capability = object()
    source = GraphStore(tmp_path / "source.db", TypeRegistry())
    source._coordinator_capability = capability
    try:
        expected = source.install_graph_recovery_genesis(
            _requirements(), _capability=capability)
        with pytest.raises(IncompleteMigrationClosure, match="stamp changed"):
            _seal(source, capability,
                  replace(expected, graph_revision=expected.graph_revision + 1))
        with source._lock:
            source._db.execute("CREATE TABLE graph_future_state(bot TEXT,persona TEXT)")
        with pytest.raises(IncompleteMigrationClosure, match="unreviewed durable tables"):
            _seal(source, capability, expected)
    finally:
        source.close()


def test_seals_queued_natural_review_and_rejects_future_review_table(tmp_path):
    capability = object()
    source = GraphStore(tmp_path / "review.db", TypeRegistry())
    source._coordinator_capability = capability
    try:
        expected = source.install_graph_recovery_genesis(
            _requirements(), _capability=capability)
        with source._lock:
            install_natural_preparations(source._db)
            install_review_attempt_schema(source._db)
            source._db.execute(
                "INSERT INTO graph_natural_review_preparations_v2 "
                "(bot,persona,parent_original_id,job_id,original_operation_id,"
                "seal_json,frozen_json,read_versions_json,query_epochs_json,"
                "graph_epoch,access_epoch,deletion_epoch,state) "
                "VALUES(?,?,?,?,?,'{}','{}','[]','[]',0,0,0,'queued')",
                (*NAMESPACE.as_tuple, "parent-a", "review-job-a", "review-op-a"))
        snapshot = _seal(source, capability, expected)
        rows = {name: values for name, _, values in snapshot.tables}
        assert len(rows["graph_natural_review_preparations_v2"]) == 1
        assert "graph_natural_review_attempts_v2" in rows
        assert "graph_natural_review_content_reads_v2" in rows
        with source._lock:
            source._db.execute(
                "CREATE TABLE graph_natural_review_future_v3(bot TEXT,persona TEXT)")
        with pytest.raises(IncompleteMigrationClosure, match="unreviewed durable tables"):
            _seal(source, capability, expected)
    finally:
        source.close()


def test_migration_round_trips_owner_revoke_and_d12_original_rows(tmp_path):
    capability = object()
    source = GraphStore(tmp_path / "owner-d12-source.db", TypeRegistry())
    target = GraphStore(tmp_path / "owner-d12-target.db", TypeRegistry())
    source._coordinator_capability = target._coordinator_capability = capability
    try:
        expected = source.install_graph_recovery_genesis(
            _requirements(), _capability=capability)
        candidate_json = '{"candidate":"a"}'
        candidate = (
            "migration-bot", "migration-persona", "candidate:affect-a",
            "d04", "sha256:input-a", "sha256:schema-a", "sha256:candidate-a",
            candidate_json, sha256(candidate_json.encode("utf-8")).hexdigest(),
        )
        attempt = (
            "migration-bot", "migration-persona", "compile-op-a",
            "sha256:request-a", "d12-compile-attempt-a",
        )
        intent_columns = (
            "bot,persona,operation_id,request_digest,operation_json,pending_receipt_json,"
            "attempt_id,requirements_json,anchor_json,pre_graph_revision,pre_graph_epoch,"
            "pre_access_epoch,permit_json,finish_request_id,finish_request_digest,state"
        )
        intent_rows = (
            ("migration-bot", "migration-persona", "revoke-pending", "sha256:req-p",
             "{}", "{}", "attempt-p", "{}", "{}", 1, 1, 1, None, None, None,
             "prepared"),
            ("migration-bot", "migration-persona", "revoke-committed", "sha256:req-c",
             "{}", "{}", "attempt-c", "{}", "{}", 1, 1, 1, "{}", "finish-c",
             "sha256:finish-c", "committed"),
        )
        operation = (
            "migration-bot", "migration-persona", "revoke-committed", "sha256:req-c",
            "grant-a", "sha256:grant-revoked", "graph-source-a", "sha256:grant-old",
            2, 2, "sha256:receipt-c", "{}", "attempt-c", "finish-c",
            "sha256:finish-c",
        )
        prepared = C04InternalWorkPreparedV1(
            InternalWorkBindingV1(
                namespace_ref(NAMESPACE), "activity-c04", "operation-c04",
                "execution-c04", "a" * 64, "resource-quote-c04", 1,
                "b" * 64, "body-quote-c04", 1, "c" * 64,
                AtomKey(Owner("activity", *NAMESPACE.as_tuple, "activity-c04"),
                        "d02.reservation.v1", "reservation-c04").token,
                "component-c04", "budget-c04", 1,
                "algorithm-c04", "policy-c04"),
            "profile-c04", 1, "state-c04", 1, 1,
            "owner-c04", 1, "d" * 64, "budget-operation-c04", "e" * 64,
            (("state-c04", 1), ("reservation-c04", 1)), 1, 1, 0)
        with source._lock:
            db = source._db
            db.execute("BEGIN IMMEDIATE")
            try:
                install_d12_compiled_candidate_store_v1(db)
                install_c04_internal_work_original_v1(db)
                install_body_quote_schema(db)
                # Opaque bytes test namespace routing/schema parity only. The
                # independent D02 signer and current Owner must recheck them
                # before a restored preparation can authorize work.
                db.execute(
                    "INSERT INTO d02_fixed_body_policies_v1 VALUES(?,?,?,?,?,?,?)",
                    (*NAMESPACE.as_tuple, "policy-c04", 1, "policy-bytes", "signature", "active"),
                )
                db.execute(
                    "INSERT INTO d02_body_quotes_v1 VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (*NAMESPACE.as_tuple, "body-quote-c04", 1, "policy-c04", 1,
                     "operation-c04", "b" * 64, "quote-bytes", "signature"),
                )
                db.execute(
                    "INSERT INTO d02_body_quotes_v1 VALUES(?,?,?,?,?,?,?,?,?,?)",
                    ("other-bot", "other-persona", "body-quote-other", 1,
                     "policy-other", 1, "operation-other", "f" * 64,
                     "other-quote-bytes", "other-signature"),
                )
                record_c04_internal_work_prepared_v1(db, NAMESPACE, prepared)
                assert tuple(row[1] for row in db.execute("PRAGMA table_info(graph_d12_compile_attempts_v1)")) == (
                    "bot", "persona", "operation_id", "request_digest", "attempt_id")
                db.executemany(
                    f"INSERT INTO graph_owner_revoke_intents_v1 ({intent_columns}) "
                    "VALUES(" + ",".join("?" for _ in range(16)) + ")", intent_rows)
                db.execute(
                    "INSERT INTO graph_owner_revoke_operations_v1 VALUES(" +
                    ",".join("?" for _ in range(15)) + ")", operation)
                db.execute("INSERT INTO graph_d12_domain_candidates_v1 VALUES(" +
                           ",".join("?" for _ in range(9)) + ")", candidate)
                db.execute("INSERT INTO graph_d12_compile_attempts_v1 VALUES(?,?,?,?,?)",
                           attempt)
                db.execute("COMMIT")
            except BaseException:
                db.execute("ROLLBACK")
                raise
        snapshot = _seal(source, capability, expected)
        rows = {name: values for name, _, values in snapshot.tables}
        # The graph snapshot cannot establish that an old Owner grant/revoke
        # head is still current at the independent Authority.
        assert "authority_owner_grant_revoke_current_head_merge" in (
            snapshot.deferred_dependencies)
        assert "authority_internal_work_claim_terminal_current_head_merge" in (
            snapshot.deferred_dependencies)
        assert "d02_body_policy_quote_signature_and_current_owner_recheck" in (
            snapshot.deferred_dependencies)
        assert {row[-1] for row in rows["graph_owner_revoke_intents_v1"]} == {
            "prepared", "committed"}
        assert rows["graph_owner_revoke_operations_v1"] == (operation,)
        assert rows["graph_d12_domain_candidates_v1"] == (candidate,)
        assert rows["graph_d12_domain_candidates_v1"][0][-1] == sha256(
            candidate_json.encode("utf-8")).hexdigest()
        assert rows["graph_d12_compile_attempts_v1"] == (attempt,)
        assert rows["graph_c04_internal_work_prepared_v1"][0][2] == "operation-c04"
        assert rows["graph_c04_internal_work_prepared_v1"][0][3] == (
            prepared.binding.binding_digest)
        assert len(rows["d02_fixed_body_policies_v1"]) == 1
        assert rows["d02_body_quotes_v1"][0][2] == "body-quote-c04"
        assert len(rows["d02_body_quotes_v1"]) == 1

        with target._lock:
            db = target._db
            db.execute("BEGIN IMMEDIATE")
            try:
                install_d12_compiled_candidate_store_v1(db)
                install_c04_internal_work_original_v1(db)
                install_body_quote_schema(db)
                assert tuple(row[1] for row in db.execute("PRAGMA table_info(graph_d12_compile_attempts_v1)")) == (
                    "bot", "persona", "operation_id", "request_digest", "attempt_id")
                db.execute("COMMIT")
            except BaseException:
                db.execute("ROLLBACK")
                raise
        validate_snapshot_for_isolated_target(target, snapshot,
                                              _capability=capability)
        target_requirements = replace(
            _requirements(), activation_generation=3, revocation_epoch=1,
            graph_incarnation="graph-target-a")
        receipt = object()
        target._migration_transfer_verifier = _TrustedTransfer(
            receipt, GraphMigrationVerifiedTransferV1(
                snapshot.transfer_id, expected, target_requirements,
                "target_recovering", snapshot.digest))
        with target._lock:
            target._db.execute("BEGIN IMMEDIATE")
            try:
                # Snapshot bytes preserve these rows, but cannot authorize an
                # Owner grant without the independent current Authority head.
                with pytest.raises(PermissionError, match="Authority head"):
                    import_snapshot_into_isolated_target_in_tx(
                        target, snapshot, target_requirements, receipt,
                        _capability=capability)
            finally:
                target._db.execute("ROLLBACK")
        restored = {name: values for name, _, values in _inventory(target._db, NAMESPACE)}
        for table in (
                "graph_owner_revoke_intents_v1", "graph_owner_revoke_operations_v1",
                "graph_d12_domain_candidates_v1", "graph_d12_compile_attempts_v1"):
            assert restored[table] == ()
        assert restored["graph_c04_internal_work_prepared_v1"] == ()
        assert restored["d02_fixed_body_policies_v1"] == ()
        assert restored["d02_body_quotes_v1"] == ()
    finally:
        source.close()
        target.close()


def test_target_import_rejects_wrong_transfer_and_existing_history(tmp_path):
    capability = object()
    source = GraphStore(tmp_path / "source.db", TypeRegistry())
    target = GraphStore(tmp_path / "target.db", TypeRegistry())
    source._coordinator_capability = target._coordinator_capability = capability
    try:
        expected = source.install_graph_recovery_genesis(
            _requirements(), _capability=capability)
        snapshot = _seal(source, capability, expected)
        validate_snapshot_for_isolated_target(target, snapshot,
                                              _capability=capability)
        target_requirements = replace(
            _requirements(), activation_generation=3, revocation_epoch=1,
            graph_incarnation="graph-target-a")
        transfer_receipt = object()
        target._migration_transfer_verifier = _TrustedTransfer(
            transfer_receipt, GraphMigrationVerifiedTransferV1(
                snapshot.transfer_id, expected, target_requirements,
                "target_recovering", "wrong-digest"))
        with target._lock:
            target._db.execute("BEGIN IMMEDIATE")
            try:
                with pytest.raises(PermissionError, match="does not bind"):
                    import_snapshot_into_isolated_target_in_tx(
                        target, snapshot, target_requirements, transfer_receipt,
                        _capability=capability)
            finally:
                target._db.execute("ROLLBACK")
        target._migration_transfer_verifier = _TrustedTransfer(
            transfer_receipt, GraphMigrationVerifiedTransferV1(
                snapshot.transfer_id, expected, target_requirements,
                "target_recovering", snapshot.digest))
        with target._lock:
            target._db.execute(
                "INSERT INTO graph_bundle_outbox VALUES(?,?,?,?,?)",
                (*NAMESPACE.as_tuple, "existing", "op-existing", "pending"))
            target._db.execute("BEGIN IMMEDIATE")
            try:
                with pytest.raises(IncompleteMigrationClosure, match="not isolated"):
                    import_snapshot_into_isolated_target_in_tx(
                        target, snapshot, target_requirements, transfer_receipt,
                        _capability=capability)
            finally:
                target._db.execute("ROLLBACK")
        assert read_target_import_receipt(
            target, NAMESPACE, snapshot.transfer_id,
            _capability=capability) is None
    finally:
        source.close()
        target.close()
