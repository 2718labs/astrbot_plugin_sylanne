"""Immutable D04 authored-root original beside W01's graph commit.

W01 calls record inside the transaction that writes the root graph event and
bundle receipt. Read is permitted only inside W01's already fenced transaction.
This table preserves replay inputs; it does not create another graph authority
or issue a numeric adoption credential.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import json
from pathlib import Path
import sqlite3

from ..contracts import canonical_json
from ..domains.d04.root import (
    AuthoredRootCandidate, NumericCheckpoint, decode_numeric_checkpoint,
    decode_root_candidate, encode_numeric_checkpoint, encode_root_candidate,
)
from ..graph_types import AtomKey, GraphVersion, NamespaceEpoch, Owner
from ..native_runtime.d04_root_numeric_replay import verify_d04_root_numeric_original
from ..native_runtime.d04_candidate import _assets
from ..native_runtime.loader import ABI2NativeLibrary
from ..runtime_contracts import CommitReceipt, NamespaceId, canonical_digest


class D04RootOriginalHold(ValueError):
    """A root original, graph receipt or numeric replay is absent or inconsistent."""


@dataclass(frozen=True, slots=True)
class D04RootOriginalRecordV1:
    operation_id: str
    candidate: AuthoredRootCandidate
    checkpoints: tuple[NumericCheckpoint, ...]
    commit_receipt: CommitReceipt
    replay_digests: tuple[str, ...]
    record_digest: str
    status: str = "original_recorded_not_product_adoption"


def install_d04_root_original_store_v1(db: sqlite3.Connection) -> None:
    """Schema hook for W01 provisioning, called before its graph transaction."""
    db.executescript("""
        CREATE TABLE IF NOT EXISTS graph_d04_root_originals_v1 (
            bot TEXT NOT NULL, persona TEXT NOT NULL,
            operation_id TEXT NOT NULL, candidate_digest TEXT NOT NULL,
            original_json TEXT NOT NULL, checkpoints_json TEXT NOT NULL,
            receipt_digest TEXT NOT NULL, replay_digests_json TEXT NOT NULL,
            record_digest TEXT NOT NULL,
            PRIMARY KEY(bot,persona,operation_id),
            FOREIGN KEY(bot,persona,operation_id)
              REFERENCES graph_bundle_operations(bot,persona,operation_id));
        CREATE TRIGGER IF NOT EXISTS graph_d04_root_original_no_update_v1
          BEFORE UPDATE ON graph_d04_root_originals_v1
          BEGIN SELECT RAISE(ABORT, 'D04 root original is immutable'); END;
        CREATE TRIGGER IF NOT EXISTS graph_d04_root_original_no_delete_v1
          BEFORE DELETE ON graph_d04_root_originals_v1
          BEGIN SELECT RAISE(ABORT, 'D04 root original is immutable'); END;
    """)


def _transaction(db: sqlite3.Connection) -> None:
    if not isinstance(db, sqlite3.Connection) or not db.in_transaction:
        raise D04RootOriginalHold("D04 root original needs W01's graph transaction")


def _versions(encoded: str) -> tuple[GraphVersion, ...]:
    rows = json.loads(encoded)
    if type(rows) is not list:
        raise ValueError("graph versions are invalid")
    return tuple(GraphVersion(AtomKey.from_token(token), revision)
                 for token, revision in rows)


def _receipt(db: sqlite3.Connection, namespace: NamespaceId,
             operation_id: str) -> CommitReceipt:
    row = db.execute(
        "SELECT digest,activity_id,effect_id,commit_seq,receipt_json "
        "FROM graph_bundle_operations WHERE bot=? AND persona=? AND operation_id=?",
        namespace.as_tuple + (operation_id,),
    ).fetchone()
    if row is None:
        raise D04RootOriginalHold("root commit receipt is absent")
    event = db.execute(
        "SELECT reads,revisions,epoch_revision FROM graph_events "
        "WHERE bot=? AND persona=? AND session=? AND event_id=?",
        namespace.as_tuple + (row[1], operation_id),
    ).fetchone()
    if event is None:
        raise D04RootOriginalHold("root graph event is absent")
    try:
        data = json.loads(row[4])
        if (canonical_json(data) != row[4] or type(data) is not dict
                or type(data.get("ledger_refs")) is not list
                or type(data.get("outbox_refs")) is not list):
            raise ValueError("noncanonical receipt")
        return CommitReceipt(
            "committed", operation_id, row[0], row[1], row[2], row[3],
            _versions(event[0]), _versions(event[1]),
            (NamespaceEpoch(*namespace.as_tuple, event[2]),),
            tuple(data["ledger_refs"]), tuple(data["outbox_refs"]),
        )
    except (TypeError, ValueError, KeyError, IndexError) as exc:
        raise D04RootOriginalHold("root commit receipt is malformed") from exc


def _checkpoints(db: sqlite3.Connection, namespace: NamespaceId,
                 operation_id: str, original: AuthoredRootCandidate,
                 checkpoints: tuple[NumericCheckpoint, ...],
                 receipt: CommitReceipt) -> None:
    if (type(original) is not AuthoredRootCandidate
            or type(checkpoints) is not tuple
            or len(checkpoints) != len(original.checkpoints)
            or any(type(item) is not NumericCheckpoint for item in checkpoints)
            or tuple(item.block.block_id for item in checkpoints)
               != tuple(item.block_id for item in original.checkpoints)
            or original.namespace != namespace.as_tuple):
        raise D04RootOriginalHold("root original block set is incomplete")
    writes = set(receipt.write_versions)
    for checkpoint in checkpoints:
        key = AtomKey(Owner("persona", *namespace.as_tuple),
                      "d04.numeric_checkpoint.v1", checkpoint.block.block_id)
        if checkpoint.commit_operation_id != operation_id or checkpoint.namespace != namespace.as_tuple:
            raise D04RootOriginalHold("root checkpoint operation differs")
        if GraphVersion(AtomKey.from_token(checkpoint.graph_state.ref),
                        checkpoint.graph_state.revision) not in writes:
            raise D04RootOriginalHold("root receipt omits the paired state write")
        versions = tuple(item for item in writes if item.key == key)
        if len(versions) != 1:
            raise D04RootOriginalHold("root receipt omits a checkpoint write")
        version = versions[0]
        history = db.execute(
            "SELECT value,valid FROM graph_history WHERE token=? AND revision=? "
            "AND event_bot=? AND event_persona=? AND event_session=? AND event_id=?",
            (key.token, version.revision, *namespace.as_tuple,
             receipt.activity_id, operation_id),
        ).fetchone()
        expected = canonical_json(encode_numeric_checkpoint(checkpoint))
        if history != (expected, 1):
            raise D04RootOriginalHold("root graph history differs from original checkpoint")


def _installed_assets(root: Path, handle: ABI2NativeLibrary,
                      original: AuthoredRootCandidate) -> None:
    """Tie replay to installed Scheme/operator bytes, not DTO hash claims."""
    try:
        affect, affect_hash, operator, operator_hash = _assets(root, handle)
        assets = original.preset.assets
        versions = ("scheme_version", "operator_version",
                    "parameter_version", "coupling_version")
        if (assets.scheme_sha256 != affect_hash
                or assets.operator_sha256 != operator_hash
                or any(getattr(assets, name) != affect.get(name)
                       or getattr(assets, name) != operator.get(name)
                       for name in versions)
                or tuple(axis["axis_id"] for axis in affect["axes"])
                   != original.preset.axes
                or tuple(operator["axis_ids"]) != original.preset.axes
                or affect["parameter_bounds"] != operator["parameter_bounds"]):
            raise ValueError("installed root Scheme or operator differs")
    except (KeyError, TypeError, ValueError, OSError) as exc:
        raise D04RootOriginalHold("installed root Scheme/operator is unavailable") from exc


def _payload(operation_id: str, original: AuthoredRootCandidate,
             checkpoints: tuple[NumericCheckpoint, ...], receipt: CommitReceipt,
             replay_digests: tuple[str, ...]) -> tuple:
    original_json = canonical_json(encode_root_candidate(original))
    checkpoints_json = canonical_json([encode_numeric_checkpoint(item)
                                       for item in checkpoints])
    receipt_digest = canonical_digest(asdict(receipt))
    replay_json = canonical_json(list(replay_digests))
    record_digest = canonical_digest({
        "schema": "d04.root-original-record.v1", "operation_id": operation_id,
        "original": original_json, "checkpoints": checkpoints_json,
        "receipt": receipt_digest, "replays": replay_json,
    })
    return (original.digest, original_json, checkpoints_json, receipt_digest,
            replay_json, record_digest)


def record_d04_root_original_in_transaction(
    db: sqlite3.Connection, *, namespace: NamespaceId, operation_id: str,
    original: AuthoredRootCandidate, checkpoints: tuple[NumericCheckpoint, ...],
    handle: ABI2NativeLibrary, package_root: Path,
) -> D04RootOriginalRecordV1:
    """W01 record hook after graph writes, before committing the same transaction."""
    _transaction(db)
    if type(namespace) is not NamespaceId or type(operation_id) is not str or not operation_id:
        raise TypeError("root record requires namespace and operation ID")
    receipt = _receipt(db, namespace, operation_id)
    _checkpoints(db, namespace, operation_id, original, checkpoints, receipt)
    _installed_assets(package_root, handle, original)
    replay_digests = tuple(canonical_digest(asdict(verify_d04_root_numeric_original(
        handle, original, checkpoint,
    ))) for checkpoint in checkpoints)
    payload = _payload(operation_id, original, checkpoints, receipt, replay_digests)
    prior = db.execute(
        "SELECT candidate_digest,original_json,checkpoints_json,receipt_digest,"
        "replay_digests_json,record_digest FROM graph_d04_root_originals_v1 "
        "WHERE bot=? AND persona=? AND operation_id=?",
        namespace.as_tuple + (operation_id,),
    ).fetchone()
    if prior is not None:
        if prior != payload:
            raise D04RootOriginalHold("root operation retry differs from original")
    else:
        db.execute(
            "INSERT INTO graph_d04_root_originals_v1 VALUES(?,?,?,?,?,?,?,?,?)",
            namespace.as_tuple + (operation_id, *payload),
        )
    return D04RootOriginalRecordV1(operation_id, original, checkpoints,
                                   receipt, replay_digests, payload[-1])


def read_d04_root_original_in_transaction(
    db: sqlite3.Connection, *, namespace: NamespaceId, operation_id: str,
    handle: ABI2NativeLibrary, package_root: Path,
) -> D04RootOriginalRecordV1:
    """W01 read hook under its live fence; recheck receipt and native math."""
    _transaction(db)
    if type(namespace) is not NamespaceId or type(operation_id) is not str or not operation_id:
        raise TypeError("root read requires namespace and operation ID")
    row = db.execute(
        "SELECT candidate_digest,original_json,checkpoints_json,receipt_digest,"
        "replay_digests_json,record_digest FROM graph_d04_root_originals_v1 "
        "WHERE bot=? AND persona=? AND operation_id=?",
        namespace.as_tuple + (operation_id,),
    ).fetchone()
    if row is None:
        raise D04RootOriginalHold("root original is absent")
    try:
        original_data = json.loads(row[1])
        checkpoint_data = json.loads(row[2])
        replay_data = json.loads(row[4])
        if (canonical_json(original_data) != row[1]
                or canonical_json(checkpoint_data) != row[2]
                or canonical_json(replay_data) != row[4]
                or type(checkpoint_data) is not list or type(replay_data) is not list):
            raise ValueError("noncanonical original")
        original = decode_root_candidate(original_data)
        checkpoints = tuple(decode_numeric_checkpoint(item) for item in checkpoint_data)
        receipt = _receipt(db, namespace, operation_id)
        _checkpoints(db, namespace, operation_id, original, checkpoints, receipt)
        _installed_assets(package_root, handle, original)
        replay_digests = tuple(canonical_digest(asdict(verify_d04_root_numeric_original(
            handle, original, checkpoint,
        ))) for checkpoint in checkpoints)
        expected = _payload(operation_id, original, checkpoints, receipt, replay_digests)
    except (TypeError, ValueError, KeyError, IndexError) as exc:
        raise D04RootOriginalHold("root original failed replay") from exc
    if row != expected or original.digest != row[0]:
        raise D04RootOriginalHold("root original or receipt digest differs")
    return D04RootOriginalRecordV1(operation_id, original, checkpoints,
                                   receipt, replay_digests, row[-1])


__all__ = ["D04RootOriginalHold", "D04RootOriginalRecordV1",
           "install_d04_root_original_store_v1",
           "record_d04_root_original_in_transaction",
           "read_d04_root_original_in_transaction"]
