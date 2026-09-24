"""D11's durable initial dispatch admission identity.

Only the graph coordinator may construct a committed receipt.  A parsed value
or a matching digest is evidence to inspect, never permission to send.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, fields
from datetime import datetime
import json
import re
from typing import Mapping

from ..contracts import canonical_json
from ..dispatch_runtime import DispatchRequest
from ..runtime_contracts import (
    CheckReceipt, NamespaceId, VersionedRef, canonical_digest,
)
from ..runtime_journal import (
    BudgetConstraint, QuotaOccupancy, RecoveryConstraintFootprint,
    ReservationConstraint,
)


SCHEMA = "sylanne.d11.dispatch_admission.v1"
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")


def _nonempty(value: object, name: str) -> None:
    if type(value) is not str or not value or len(value) > 4096:
        raise ValueError(f"invalid {name}")


def _digest(value: object, name: str) -> None:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise ValueError(f"invalid {name}")


def _version(value: object, name: str) -> None:
    if type(value) is not int or value < 0:
        raise ValueError(f"invalid {name}")


@dataclass(frozen=True)
class DispatchAdmissionV1:
    """Exact candidate, graph, check and budget facts fixed by one graph commit."""

    namespace: str
    graph_incarnation: str
    activity_id: str
    effect_id: str
    attempt_id: str
    operation_id: str
    dispatch_generation: int
    admission_ref: str
    candidate_digest: str
    request_digest: str
    action_intent_digest: str
    action_intent_schema_version: str
    action_schema_digest: str
    action_schema_version: str
    required_checks_digest: str
    required_checks_schema_version: str
    grant_digest: str
    batch_digest: str
    segment_index: int
    payload_digest: str
    account_ref: str
    destination_ref: str
    scene_ref: str
    owner_head_ref: str
    role_ref: str
    binding_ref: str
    object_ref: str
    action_ref: str
    purpose: str
    audience: tuple[str, ...]
    graph_reads: tuple[tuple[str, int], ...]
    query_epoch: int
    access_epoch: int
    delete_epoch: int
    check_receipts: tuple[CheckReceipt, ...]
    budget_parent_lease_ref: str
    budget_lease_ref: str
    budget_reservation_operation_id: str
    budget_reservation_digest: str
    budget_ceiling: Mapping[str, int]
    budget_currency: str
    budget_version: int
    contact_reservation_ref: str | None
    utc_deadline: str
    clock_policy_ref: str
    clock_policy_digest: str
    schema: str = SCHEMA

    def __post_init__(self) -> None:
        if self.schema != SCHEMA:
            raise ValueError("unsupported dispatch admission schema")
        for name in (
            "namespace", "graph_incarnation", "activity_id", "effect_id",
            "attempt_id", "operation_id", "admission_ref",
            "action_intent_schema_version", "action_schema_version",
            "required_checks_schema_version", "account_ref", "destination_ref",
            "scene_ref", "owner_head_ref", "role_ref", "binding_ref",
            "object_ref", "action_ref", "purpose", "budget_parent_lease_ref",
            "budget_lease_ref", "budget_reservation_operation_id",
            "budget_currency", "clock_policy_ref",
        ):
            _nonempty(getattr(self, name), name)
        if self.contact_reservation_ref is not None:
            _nonempty(self.contact_reservation_ref, "contact_reservation_ref")
        for name in (
            "candidate_digest", "request_digest", "action_intent_digest",
            "action_schema_digest", "required_checks_digest", "grant_digest",
            "batch_digest", "payload_digest", "budget_reservation_digest",
            "clock_policy_digest",
        ):
            _digest(getattr(self, name), name)
        for name in (
            "dispatch_generation", "segment_index", "query_epoch",
            "access_epoch", "delete_epoch", "budget_version",
        ):
            _version(getattr(self, name), name)
        if type(self.audience) is not tuple or not self.audience:
            raise ValueError("admission needs a finite audience")
        for item in self.audience:
            _nonempty(item, "audience")
        if len(set(self.audience)) != len(self.audience):
            raise ValueError("admission audience repeats")
        if type(self.graph_reads) is not tuple or not self.graph_reads:
            raise ValueError("admission needs a complete graph read set")
        for ref, revision in self.graph_reads:
            _nonempty(ref, "graph read")
            _version(revision, "graph read revision")
        if len({ref for ref, _ in self.graph_reads}) != len(self.graph_reads):
            raise ValueError("admission graph reads repeat")
        if (type(self.check_receipts) is not tuple or not self.check_receipts
                or any(type(item) is not CheckReceipt for item in self.check_receipts)):
            raise ValueError("admission needs actual typed check receipts")
        if len({item.check_kind for item in self.check_receipts}) != len(self.check_receipts):
            raise ValueError("admission check kinds repeat")
        if type(self.budget_ceiling) is not dict or not self.budget_ceiling:
            raise ValueError("admission needs a positive budget ceiling")
        if any(type(name) is not str or not name or type(amount) is not int
               or amount <= 0 for name, amount in self.budget_ceiling.items()):
            raise ValueError("invalid admission budget ceiling")
        if not re.fullmatch(r"[A-Z]{3}", self.budget_currency):
            raise ValueError("invalid admission budget currency")
        if type(self.utc_deadline) is not str or not re.fullmatch(
                r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", self.utc_deadline):
            raise ValueError("invalid admission UTC deadline")
        try:
            datetime.fromisoformat(self.utc_deadline.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("invalid admission UTC deadline") from exc

    def require_current(self, now_utc: float) -> None:
        deadline = datetime.fromisoformat(
            self.utc_deadline.replace("Z", "+00:00"))
        if deadline.timestamp() <= now_utc:
            raise ValueError("dispatch admission UTC deadline has expired")

    @property
    def digest(self) -> str:
        return canonical_digest(asdict(self))

    @property
    def initial_check_evidence_digest(self) -> str:
        return canonical_digest(self.check_receipts)


@dataclass(frozen=True)
class DispatchAdmissionReceiptV1:
    admission: DispatchAdmissionV1
    graph_revision: int
    graph_epoch: int
    receipt_digest: str

    @property
    def graph_version(self) -> str:
        return f"graph:{self.graph_revision}"

    def __post_init__(self) -> None:
        _version(self.graph_revision, "graph_revision")
        _version(self.graph_epoch, "graph_epoch")
        _digest(self.receipt_digest, "receipt_digest")
        if self.receipt_digest != canonical_digest({
            "admission_digest": self.admission.digest,
            "graph_revision": self.graph_revision,
            "graph_epoch": self.graph_epoch,
        }):
            raise ValueError("admission receipt digest differs")


def check_receipts_against_specs(admission: DispatchAdmissionV1, specs: tuple,
                                 now_utc: float) -> None:
    """Check exact frozen spec cardinality and full receipt scope; provenance is external."""
    if len(specs) != len(admission.check_receipts):
        raise ValueError("dispatch check set is incomplete")
    by_kind = {item.check_kind: item for item in admission.check_receipts}
    if set(by_kind) != {item.check_kind for item in specs}:
        raise ValueError("dispatch check kind set differs")
    for spec in specs:
        receipt = by_kind[spec.check_kind]
        if ((receipt.issuer, receipt.subject_ref, receipt.action_ref,
             receipt.purpose, receipt.input_versions) !=
            (spec.provider_id, spec.subject_ref, spec.action_ref,
             spec.purpose, spec.required_input_versions)
                or receipt.result != "pass" or receipt.coverage != "full"
                or receipt.valid_until < now_utc):
            raise ValueError(f"dispatch check {spec.check_kind} is stale or incomplete")


def namespace_of(admission: DispatchAdmissionV1) -> NamespaceId:
    parts = admission.namespace.split("/", 1)
    if len(parts) != 2:
        raise ValueError("invalid dispatch namespace")
    return NamespaceId(*parts)


def install_schema(db) -> None:
    db.execute("""CREATE TABLE IF NOT EXISTS graph_dispatch_admissions (
        bot TEXT NOT NULL, persona TEXT NOT NULL, admission_ref TEXT NOT NULL,
        operation_id TEXT NOT NULL, effect_id TEXT NOT NULL,
        admission_digest TEXT NOT NULL, admission_json TEXT NOT NULL,
        graph_revision INTEGER NOT NULL, graph_epoch INTEGER NOT NULL,
        receipt_digest TEXT NOT NULL, request_json TEXT,
        PRIMARY KEY(bot, persona, admission_ref),
        UNIQUE(bot, persona, operation_id, effect_id)
    )""")
    if "request_json" not in {row[1] for row in db.execute(
            "PRAGMA table_info(graph_dispatch_admissions)")}:
        db.execute("ALTER TABLE graph_dispatch_admissions ADD COLUMN request_json TEXT")


def insert_admission(db, receipt: DispatchAdmissionReceiptV1,
                     request: DispatchRequest) -> None:
    """Persist the proven command in the admission's existing graph transaction."""
    admission = receipt.admission
    if type(request) is not DispatchRequest or not _request_matches(admission, request):
        raise ValueError("dispatch request differs from admission")
    namespace = namespace_of(admission)
    install_schema(db)
    db.execute(
        "INSERT INTO graph_dispatch_admissions(bot,persona,admission_ref,"
        "operation_id,effect_id,admission_digest,admission_json,graph_revision,"
        "graph_epoch,receipt_digest,request_json) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
        namespace.as_tuple + (
            admission.admission_ref, admission.operation_id, admission.effect_id,
            admission.digest, _stored_json(admission), receipt.graph_revision,
            receipt.graph_epoch, receipt.receipt_digest, _stored_json(request),
        ),
    )


def _stored_json(value: object) -> str:
    return canonical_json(json.loads(json.dumps(asdict(value), allow_nan=False)))


def _request_matches(admission: DispatchAdmissionV1,
                     request: DispatchRequest) -> bool:
    return (
        request.namespace == admission.namespace
        and (request.activity_id, request.effect_id, request.attempt_id,
             request.operation_id) == (
                 admission.activity_id, admission.effect_id, admission.attempt_id,
                 admission.operation_id)
        and canonical_digest(request) == admission.request_digest
        and request.dispatch_generation == admission.dispatch_generation
        and request.segment_index == admission.segment_index
        and request.payload_digest == admission.payload_digest
    )


def _decode_request(raw: str) -> DispatchRequest:
    data = json.loads(raw)
    if type(data) is not dict or set(data) != {field.name for field in fields(DispatchRequest)}:
        raise ValueError("invalid stored dispatch request")
    footprint = data["footprint"]
    if type(footprint) is not dict or set(footprint) != {
            field.name for field in fields(RecoveryConstraintFootprint)}:
        raise ValueError("invalid stored dispatch footprint")
    for name, item_type in (
        ("quota_occupancies", QuotaOccupancy),
        ("reservations", ReservationConstraint),
        ("budgets", BudgetConstraint),
    ):
        if type(footprint[name]) is not list:
            raise ValueError("invalid stored dispatch footprint")
        footprint[name] = tuple(item_type(**item) for item in footprint[name])
    for name in ("conflict_keys", "object_gate_keys"):
        if type(footprint[name]) is not list:
            raise ValueError("invalid stored dispatch footprint")
        footprint[name] = tuple(footprint[name])
    data["footprint"] = RecoveryConstraintFootprint(**footprint)
    if type(data["required_check_refs"]) is not list:
        raise ValueError("invalid stored dispatch request")
    data["required_check_refs"] = tuple(data["required_check_refs"])
    request = DispatchRequest(**data)
    if _stored_json(request) != raw:
        raise ValueError("stored dispatch request is not canonical")
    return request


def load_request(db, namespace: NamespaceId,
                 admission_ref: str) -> tuple[DispatchAdmissionReceiptV1, DispatchRequest] | None:
    """Read historical command evidence; this grants no current send authority."""
    receipt = load_admission(db, namespace, admission_ref)
    if receipt is None:
        return None
    if "request_json" not in {row[1] for row in db.execute(
            "PRAGMA table_info(graph_dispatch_admissions)")}:
        return None
    raw = db.execute(
        "SELECT request_json FROM graph_dispatch_admissions "
        "WHERE bot=? AND persona=? AND admission_ref=?",
        namespace.as_tuple + (admission_ref,),
    ).fetchone()[0]
    if raw is None:  # Legacy admission rows never stored the issued command.
        return None
    request = _decode_request(raw)
    if not _request_matches(receipt.admission, request):
        raise ValueError("stored dispatch request identity differs")
    return receipt, request


def _decode_check(data: object) -> CheckReceipt:
    if type(data) is not dict or set(data) != {
        "check_kind", "subject_ref", "action_ref", "purpose", "input_versions",
        "coverage", "result", "valid_until", "issuer",
    } or type(data["input_versions"]) is not list:
        raise ValueError("invalid stored dispatch check receipt")
    versions = []
    for item in data["input_versions"]:
        if type(item) is not dict or set(item) != {"ref", "version"}:
            raise ValueError("invalid stored dispatch check version")
        versions.append(VersionedRef(**item))
    return CheckReceipt(**{**data, "input_versions": tuple(versions)})


def load_admission(db, namespace: NamespaceId,
                   admission_ref: str) -> DispatchAdmissionReceiptV1 | None:
    if db.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='graph_dispatch_admissions'"
    ).fetchone() is None:
        return None
    row = db.execute(
        "SELECT operation_id,effect_id,admission_digest,admission_json,"
        "graph_revision,graph_epoch,receipt_digest FROM graph_dispatch_admissions "
        "WHERE bot=? AND persona=? AND admission_ref=?",
        namespace.as_tuple + (admission_ref,),
    ).fetchone()
    if row is None:
        return None
    data = json.loads(row[3])
    if type(data) is not dict or type(data.get("check_receipts")) is not list:
        raise ValueError("invalid stored dispatch admission")
    data["check_receipts"] = tuple(_decode_check(item)
                                   for item in data["check_receipts"])
    for field in ("audience", "graph_reads"):
        if type(data.get(field)) is not list:
            raise ValueError("invalid stored dispatch admission read set")
        data[field] = tuple(tuple(item) if field == "graph_reads" else item
                            for item in data[field])
    admission = DispatchAdmissionV1(**data)
    if (admission.operation_id != row[0] or admission.effect_id != row[1]
            or admission.digest != row[2]
            or namespace_of(admission) != namespace
            or admission.admission_ref != admission_ref):
        raise ValueError("stored dispatch admission identity differs")
    return DispatchAdmissionReceiptV1(admission, row[4], row[5], row[6])


__all__ = [
    "SCHEMA", "DispatchAdmissionV1", "DispatchAdmissionReceiptV1",
    "check_receipts_against_specs", "namespace_of",
    "install_schema", "insert_admission", "load_admission", "load_request",
]
