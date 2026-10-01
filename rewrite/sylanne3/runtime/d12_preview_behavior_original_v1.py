"""Immutable D07 behavior report accompanying a W01-issued D12 preview."""

from __future__ import annotations

import hashlib
import json
import sqlite3

from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize
from .d12_scheme_behavior_preview_v1 import (
    D12AttentionProbeOutputV1, D12BehaviorExperimentReportV1,
    D12BehaviorExperimentSpecV1,
)


def install_d12_preview_behavior_original_v1(db: sqlite3.Connection) -> None:
    if not db.in_transaction:
        raise ValueError("caller-owned graph transaction required")
    db.execute("""CREATE TABLE IF NOT EXISTS graph_d12_preview_behavior_originals_v1 (
        bot TEXT NOT NULL, persona TEXT NOT NULL, operation_id TEXT NOT NULL,
        compiled_digest TEXT NOT NULL, preview_seal TEXT NOT NULL,
        cost_ref TEXT NOT NULL, plan_digest TEXT NOT NULL,
        report_digest TEXT NOT NULL, report_json TEXT NOT NULL,
        report_sha256 TEXT NOT NULL,
        PRIMARY KEY(bot,persona,operation_id),
        UNIQUE(bot,persona,preview_seal))""")
    db.execute("""CREATE TRIGGER IF NOT EXISTS graph_d12_preview_behavior_no_update_v1
        BEFORE UPDATE ON graph_d12_preview_behavior_originals_v1
        BEGIN SELECT RAISE(ABORT, 'D12 preview behavior original is immutable'); END""")
    db.execute("""CREATE TRIGGER IF NOT EXISTS graph_d12_preview_behavior_no_delete_v1
        BEFORE DELETE ON graph_d12_preview_behavior_originals_v1
        BEGIN SELECT RAISE(ABORT, 'D12 preview behavior original is immutable'); END""")


def record_d12_preview_behavior_original_v1(
    db: sqlite3.Connection, namespace: NamespaceId, *,
    operation_id: str, compiled_digest: str, preview_seal: str,
    cost_ref: str, plan_digest: str,
    report: D12BehaviorExperimentReportV1,
) -> None:
    """Record the actual bounded comparison, never an unbound PASS flag."""
    if not db.in_transaction or type(report) is not D12BehaviorExperimentReportV1:
        raise ValueError("typed behavior report and graph transaction required")
    payload = {
        name: getattr(report, name) for name in report.__dataclass_fields__
        if name != "report_digest"
    }
    if (report.status != "isolated_behavior_only"
            or report.hold_reason is not None
            or report.report_digest != canonical_digest(payload)
            or report.spec.operation_id != operation_id
            or report.spec.namespace != namespace
            or report.spec.compiled_digest != compiled_digest):
        raise ValueError("D07 behavior report does not bind the preview")
    encoded = canonical_serialize(report)
    row = (compiled_digest, preview_seal, cost_ref, plan_digest,
           report.report_digest, encoded,
           hashlib.sha256(encoded.encode("utf-8")).hexdigest())
    identity = (*namespace.as_tuple, operation_id)
    prior = db.execute(
        "SELECT compiled_digest,preview_seal,cost_ref,plan_digest,"
        "report_digest,report_json,report_sha256 "
        "FROM graph_d12_preview_behavior_originals_v1 "
        "WHERE bot=? AND persona=? AND operation_id=?", identity,
    ).fetchone()
    if prior is not None and prior != row:
        raise ValueError("preview behavior original differs")
    if prior is None:
        db.execute(
            "INSERT INTO graph_d12_preview_behavior_originals_v1 "
            "VALUES(?,?,?,?,?,?,?,?,?,?)", (*identity, *row),
        )


def verify_d12_preview_behavior_original_v1(
    db: sqlite3.Connection, namespace: NamespaceId, *,
    operation_id: str, compiled_digest: str, preview_seal: str,
    cost_ref: str, plan_digest: str,
    report: D12BehaviorExperimentReportV1,
) -> bool:
    if not db.in_transaction:
        raise ValueError("caller-owned graph transaction required")
    encoded = canonical_serialize(report)
    return db.execute(
        "SELECT compiled_digest,preview_seal,cost_ref,plan_digest,"
        "report_digest,report_json,report_sha256 "
        "FROM graph_d12_preview_behavior_originals_v1 "
        "WHERE bot=? AND persona=? AND operation_id=?",
        (*namespace.as_tuple, operation_id),
    ).fetchone() == (
        compiled_digest, preview_seal, cost_ref, plan_digest,
        report.report_digest, encoded,
        hashlib.sha256(encoded.encode("utf-8")).hexdigest(),
    )


def read_d12_preview_behavior_original_v1(
    db: sqlite3.Connection, namespace: NamespaceId, *, operation_id: str,
) -> tuple[str, str, str, str, D12BehaviorExperimentReportV1] | None:
    """Rehydrate exact immutable bytes without rerunning the paid experiment."""
    if not db.in_transaction:
        raise ValueError("caller-owned graph transaction required")
    row = db.execute(
        "SELECT compiled_digest,preview_seal,cost_ref,plan_digest,"
        "report_digest,report_json,report_sha256 "
        "FROM graph_d12_preview_behavior_originals_v1 "
        "WHERE bot=? AND persona=? AND operation_id=?",
        (*namespace.as_tuple, operation_id),
    ).fetchone()
    if row is None:
        return None
    compiled_digest, preview_seal, cost_ref, plan_digest, digest, encoded, sha = row
    if hashlib.sha256(encoded.encode("utf-8")).hexdigest() != sha:
        raise ValueError("D12 behavior report bytes changed")
    value = json.loads(encoded)
    spec = value["spec"]
    ns = spec["namespace"]
    if ns["bot_id"] != namespace.bot_id or ns["persona_id"] != namespace.persona_id:
        raise ValueError("D12 behavior namespace changed")
    spec["namespace"] = namespace
    spec["scheme_fields"] = tuple(spec["scheme_fields"])
    decoded_spec = D12BehaviorExperimentSpecV1(**{
        key: val for key, val in spec.items() if key != "$type"
    })

    def output(item: dict) -> D12AttentionProbeOutputV1:
        item = {key: val for key, val in item.items() if key != "$type"}
        item["ranked_scores"] = tuple(tuple(row) for row in item["ranked_scores"])
        item["auxiliary_ticket_refs"] = tuple(item["auxiliary_ticket_refs"])
        return D12AttentionProbeOutputV1(**item)

    value["spec"] = decoded_spec
    for name in ("baseline_outputs", "candidate_outputs"):
        value[name] = tuple(output(item) for item in value[name])
    for name in ("coverage", "changed_probe_ids"):
        value[name] = tuple(value[name])
    report = D12BehaviorExperimentReportV1(**{
        key: val for key, val in value.items() if key != "$type"
    })
    payload = {
        name: getattr(report, name) for name in report.__dataclass_fields__
        if name != "report_digest"
    }
    if (canonical_serialize(report) != encoded
            or report.report_digest != digest
            or canonical_digest(payload) != digest
            or decoded_spec.operation_id != operation_id
            or decoded_spec.compiled_digest != compiled_digest):
        raise ValueError("D12 behavior report identity changed")
    return compiled_digest, preview_seal, cost_ref, plan_digest, report


__all__ = (
    "install_d12_preview_behavior_original_v1",
    "record_d12_preview_behavior_original_v1",
    "read_d12_preview_behavior_original_v1",
    "verify_d12_preview_behavior_original_v1",
)
