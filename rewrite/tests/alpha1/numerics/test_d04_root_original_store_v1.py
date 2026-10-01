"""Root originals survive reopening and fail closed on altered bytes."""

import sqlite3
from dataclasses import replace
import hashlib
import json

import pytest

from sylanne3.contracts import canonical_json
from sylanne3.domains.d04.encoding_baseline import CommittedRef
from sylanne3.domains.d04.root import NumericCheckpoint, encode_numeric_checkpoint
from sylanne3.domains.d04.root import (
    AuthoredRootBlockInput, AuthoredRootInput, compile_authored_root_candidate,
)
from sylanne3.domains.d04.numeric_coupling import REGISTERED_AXIS_IDS
from sylanne3.graph_types import AtomKey, Owner
from sylanne3.graph_store import GraphStore
from sylanne3.graph_types import TypeRegistry
from sylanne3.native_runtime.authored_root_initial_box import run_authored_root_initial_box_math
from sylanne3.runtime.d04_root_original_store_v1 import (
    D04RootOriginalHold, install_d04_root_original_store_v1,
    read_d04_root_original_in_transaction, record_d04_root_original_in_transaction,
)
from sylanne3.runtime_contracts import NamespaceId

from rewrite.tests.alpha1.numerics.test_authored_root_initial_box import (
    _candidate, native_asset,
)
from rewrite.tests.alpha1.numerics.test_d04_checkpoint_initial_box import installed_package


def test_graph_store_provisions_root_original_schema_on_create_and_reopen(tmp_path):
    """A root original can share the real graph DB; root adoption stays gated."""
    path = tmp_path / "graph.db"
    for _ in range(2):
        store = GraphStore(path, TypeRegistry())
        try:
            db = store._db
            table = db.execute(
                "SELECT name FROM sqlite_master WHERE type='table' "
                "AND name='graph_d04_root_originals_v1'",
            ).fetchone()
            triggers = {row[0] for row in db.execute(
                "SELECT name FROM sqlite_master WHERE type='trigger' "
                "AND tbl_name='graph_d04_root_originals_v1'",
            )}
            assert table == ("graph_d04_root_originals_v1",)
            assert triggers == {
                "graph_d04_root_original_no_update_v1",
                "graph_d04_root_original_no_delete_v1",
            }
            assert db.execute(
                "SELECT COUNT(*) FROM graph_d04_root_originals_v1",
            ).fetchone() == (0,)
        finally:
            store.close()


def _original(package_root):
    base = _candidate()
    affect_path = package_root / "resources/catalogue/d04-affect-scheme.json"
    operator_path = package_root / "resources/catalogue/d04-fixed-block-operator.json"
    affect = json.loads(affect_path.read_text(encoding="utf8"))
    assets = replace(
        base.preset.assets,
        scheme_version=affect["scheme_version"],
        operator_version=affect["operator_version"],
        parameter_version=affect["parameter_version"],
        coupling_version=affect["coupling_version"],
        scheme_sha256=hashlib.sha256(affect_path.read_bytes()).hexdigest(),
        operator_sha256=hashlib.sha256(operator_path.read_bytes()).hexdigest(),
    )
    preset = replace(base.preset, assets=assets, axes=REGISTERED_AXIS_IDS)
    blocks = tuple(AuthoredRootBlockInput(
        item.block, REGISTERED_AXIS_IDS, item.latent_state,
        item.ordered_box, item.initial_error_ref,
    ) for item in base.checkpoints)
    selected = AuthoredRootInput(
        base.candidate_id, base.namespace, base.author_id, base.draft_id,
        base.cursor, preset.digest, assets.digest, blocks,
    )
    return compile_authored_root_candidate(preset, selected)


def _create(tmp_path, package_root, handle):
    path = tmp_path / "root.sqlite"
    db = sqlite3.connect(path)
    db.execute("PRAGMA foreign_keys=ON")
    db.executescript("""
        CREATE TABLE graph_bundle_operations (
          bot TEXT, persona TEXT, operation_id TEXT, digest TEXT,
          activity_id TEXT, effect_id TEXT, commit_seq INTEGER,
          receipt_json TEXT, PRIMARY KEY(bot,persona,operation_id));
        CREATE TABLE graph_events (
          bot TEXT, persona TEXT, session TEXT, event_id TEXT,
          reads TEXT, revisions TEXT, epoch_revision INTEGER);
        CREATE TABLE graph_history (
          token TEXT, revision INTEGER, value TEXT, valid INTEGER,
          event_bot TEXT, event_persona TEXT, event_session TEXT,
          event_id TEXT);
    """)
    install_d04_root_original_store_v1(db)
    original = _original(package_root)
    math = run_authored_root_initial_box_math(handle, original)
    operation = "root:operation"
    namespace = NamespaceId(*original.namespace)
    checkpoints = []
    versions = []
    for source, box in zip(original.checkpoints, math.blocks):
        state = AtomKey(Owner("persona", *source.namespace),
                        "d04.feeling_state.v1" if source.block.kind == "feeling"
                        else "d04.mood_field.v1", source.block_id)
        key = AtomKey(Owner("persona", *source.namespace),
                      "d04.numeric_checkpoint.v1", source.block_id)
        checkpoint = NumericCheckpoint(
            source.block_id, source.namespace, source.block, source.assets,
            source.asset_digest, source.axes, source.latent_state,
            source.ordered_box, box.verified_initial_error,
            "trusted_initial_box", box.initial_box_sha256, source.cursor,
            CommittedRef(state.token, 1), "f" * 64, operation, "none", None,
        )
        checkpoints.append(checkpoint)
        versions.extend(([state.token, 1], [key.token, 1]))
    db.execute("INSERT INTO graph_bundle_operations VALUES(?,?,?,?,?,?,?,?)", (
        *namespace.as_tuple, operation, "a" * 64, "activity:root", None, 1,
        canonical_json({"ledger_refs": [], "outbox_refs": []}),
    ))
    db.execute("INSERT INTO graph_events VALUES(?,?,?,?,?,?,?)", (
        *namespace.as_tuple, "activity:root", operation,
        canonical_json([]), canonical_json(versions), 2,
    ))
    for checkpoint in checkpoints:
        key = AtomKey(Owner("persona", *namespace.as_tuple),
                      "d04.numeric_checkpoint.v1", checkpoint.block.block_id)
        db.execute("INSERT INTO graph_history VALUES(?,?,?,?,?,?,?,?)", (
            key.token, 1, canonical_json(encode_numeric_checkpoint(checkpoint)), 1,
            *namespace.as_tuple, "activity:root", operation,
        ))
    result = record_d04_root_original_in_transaction(
        db, namespace=namespace, operation_id=operation, original=original,
        checkpoints=tuple(checkpoints), handle=handle, package_root=package_root,
    )
    again = record_d04_root_original_in_transaction(
        db, namespace=namespace, operation_id=operation, original=original,
        checkpoints=tuple(checkpoints), handle=handle, package_root=package_root,
    )
    assert result == again
    db.commit()
    db.close()
    return path, namespace, operation, result


def test_original_reopens_with_same_receipt_and_native_replay(tmp_path, installed_package):
    package_root, handle = installed_package
    path, namespace, operation, recorded = _create(tmp_path, package_root, handle)
    db = sqlite3.connect(path)
    try:
        db.execute("BEGIN")
        restored = read_d04_root_original_in_transaction(
            db, namespace=namespace, operation_id=operation, handle=handle,
            package_root=package_root,
        )
        assert restored == recorded
        assert len(restored.replay_digests) == 2
        assert restored.status == "original_recorded_not_product_adoption"
    finally:
        db.close()


def test_altered_original_is_held_after_reopen(tmp_path, installed_package):
    package_root, handle = installed_package
    path, namespace, operation, _ = _create(tmp_path, package_root, handle)
    db = sqlite3.connect(path)
    try:
        db.execute("DROP TRIGGER graph_d04_root_original_no_update_v1")
        db.execute("UPDATE graph_d04_root_originals_v1 SET candidate_digest=?",
                   ("0" * 64,))
        db.commit()
        db.execute("BEGIN")
        with pytest.raises(D04RootOriginalHold, match="digest differs"):
            read_d04_root_original_in_transaction(
                db, namespace=namespace, operation_id=operation, handle=handle,
                package_root=package_root,
            )
    finally:
        db.close()
