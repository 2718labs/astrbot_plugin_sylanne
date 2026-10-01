"""Immutable typed D09 behavior report beside a W01-issued D12 preview."""

from __future__ import annotations

from hashlib import sha256
import json
import sqlite3

from ...runtime_contracts import NamespaceId, canonical_digest, canonical_serialize
from .d09_preview import (
    D12D09PreviewReportV1, D12D09PreviewSpecV1, D12D09ProbeOutputV1,
)


_TABLE = "graph_d12_d09_preview_originals_v1"


def install_d09_preview_original_v1(db: sqlite3.Connection) -> None:
    if not db.in_transaction:
        raise ValueError("caller-owned graph transaction required")
    db.execute(f"""CREATE TABLE IF NOT EXISTS {_TABLE} (
        bot TEXT NOT NULL, persona TEXT NOT NULL, operation_id TEXT NOT NULL,
        compiled_digest TEXT NOT NULL, preview_seal TEXT NOT NULL,
        cost_ref TEXT NOT NULL, plan_digest TEXT NOT NULL,
        report_digest TEXT NOT NULL, report_json TEXT NOT NULL,
        report_sha256 TEXT NOT NULL,
        PRIMARY KEY(bot,persona,operation_id),
        UNIQUE(bot,persona,preview_seal))""")
    db.execute(f"""CREATE TRIGGER IF NOT EXISTS graph_d12_d09_preview_no_update_v1
        BEFORE UPDATE ON {_TABLE}
        BEGIN SELECT RAISE(ABORT, 'D09 preview original is immutable'); END""")
    db.execute(f"""CREATE TRIGGER IF NOT EXISTS graph_d12_d09_preview_no_delete_v1
        BEFORE DELETE ON {_TABLE}
        BEGIN SELECT RAISE(ABORT, 'D09 preview original is immutable'); END""")


def _report_payload(report: D12D09PreviewReportV1) -> dict:
    return {
        name: getattr(report, name) for name in report.__dataclass_fields__
        if name != "report_digest"
    }


def _validate_binding(
    namespace: NamespaceId, operation_id: str, compiled_digest: str,
    report: D12D09PreviewReportV1,
) -> None:
    if (type(namespace) is not NamespaceId
            or type(report) is not D12D09PreviewReportV1
            or report.status != "isolated_behavior_only"
            or report.hold_reason is not None
            or report.spec.namespace != namespace
            or report.spec.operation_id != operation_id
            or report.spec.compiled_digest != compiled_digest
            or report.report_digest != canonical_digest(_report_payload(report))):
        raise ValueError("D09 behavior report does not bind the preview")


def record_d09_preview_original_v1(
    db: sqlite3.Connection, namespace: NamespaceId, *,
    operation_id: str, compiled_digest: str, preview_seal: str,
    cost_ref: str, plan_digest: str, report: D12D09PreviewReportV1,
) -> None:
    """Store the actual typed D09 report, idempotent on exact replay only."""
    if not db.in_transaction:
        raise ValueError("caller-owned graph transaction required")
    _validate_binding(namespace, operation_id, compiled_digest, report)
    encoded = canonical_serialize(report)
    row = (compiled_digest, preview_seal, cost_ref, plan_digest,
           report.report_digest, encoded, sha256(encoded.encode()).hexdigest())
    identity = (*namespace.as_tuple, operation_id)
    prior = db.execute(
        f"SELECT compiled_digest,preview_seal,cost_ref,plan_digest,"
        f"report_digest,report_json,report_sha256 FROM {_TABLE} "
        "WHERE bot=? AND persona=? AND operation_id=?", identity,
    ).fetchone()
    if prior is not None and prior != row:
        raise ValueError("D09 preview original differs")
    if prior is None:
        db.execute(f"INSERT INTO {_TABLE} VALUES(?,?,?,?,?,?,?,?,?,?)",
                   (*identity, *row))


def verify_d09_preview_original_v1(
    db: sqlite3.Connection, namespace: NamespaceId, *,
    operation_id: str, compiled_digest: str, preview_seal: str,
    cost_ref: str, plan_digest: str, report: D12D09PreviewReportV1,
) -> bool:
    if not db.in_transaction:
        raise ValueError("caller-owned graph transaction required")
    _validate_binding(namespace, operation_id, compiled_digest, report)
    encoded = canonical_serialize(report)
    return db.execute(
        f"SELECT compiled_digest,preview_seal,cost_ref,plan_digest,"
        f"report_digest,report_json,report_sha256 FROM {_TABLE} "
        "WHERE bot=? AND persona=? AND operation_id=?",
        (*namespace.as_tuple, operation_id),
    ).fetchone() == (
        compiled_digest, preview_seal, cost_ref, plan_digest,
        report.report_digest, encoded, sha256(encoded.encode()).hexdigest(),
    )


def read_d09_preview_original_v1(
    db: sqlite3.Connection, namespace: NamespaceId, *, operation_id: str,
) -> tuple[str, str, str, str, D12D09PreviewReportV1] | None:
    """Decode exact original bytes; read grants no adoption authority."""
    if not db.in_transaction:
        raise ValueError("caller-owned graph transaction required")
    row = db.execute(
        f"SELECT compiled_digest,preview_seal,cost_ref,plan_digest,"
        f"report_digest,report_json,report_sha256 FROM {_TABLE} "
        "WHERE bot=? AND persona=? AND operation_id=?",
        (*namespace.as_tuple, operation_id),
    ).fetchone()
    if row is None:
        return None
    compiled_digest, preview_seal, cost_ref, plan_digest, digest, encoded, raw_sha = row
    if sha256(encoded.encode()).hexdigest() != raw_sha:
        raise ValueError("D09 preview report bytes changed")
    try:
        value = json.loads(encoded)
        raw_spec = dict(value["spec"])
        raw_ns = raw_spec["namespace"]
        if (raw_ns["bot_id"], raw_ns["persona_id"]) != namespace.as_tuple:
            raise ValueError("D09 preview namespace changed")
        raw_spec["namespace"] = namespace
        raw_spec["scheme_fields"] = tuple(raw_spec["scheme_fields"])
        raw_spec.pop("$type", None)
        spec = D12D09PreviewSpecV1(**raw_spec)

        def output(raw: dict) -> D12D09ProbeOutputV1:
            raw = dict(raw)
            raw.pop("$type", None)
            return D12D09ProbeOutputV1(**raw)

        value["spec"] = spec
        for name in ("baseline_outputs", "candidate_outputs"):
            value[name] = tuple(output(item) for item in value[name])
        for name in ("coverage", "changed_probe_ids"):
            value[name] = tuple(value[name])
        value.pop("$type", None)
        report = D12D09PreviewReportV1(**value)
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("D09 preview report shape changed") from exc
    if (canonical_serialize(report) != encoded
            or report.report_digest != digest
            or report.report_digest != canonical_digest(_report_payload(report))):
        raise ValueError("D09 preview report identity changed")
    _validate_binding(namespace, operation_id, compiled_digest, report)
    return compiled_digest, preview_seal, cost_ref, plan_digest, report


__all__ = (
    "install_d09_preview_original_v1", "record_d09_preview_original_v1",
    "verify_d09_preview_original_v1", "read_d09_preview_original_v1",
)
