"""Authenticated D02 resource and D11 budget/job admission authorities.

The issuers keep signed grants in the same business SQLite transaction.  A
command envelope is only an audit assertion: admission requires an untampered
D02 quote and D11 lease grant whose identities and ceilings match the command.
No function in this module opens, commits, or rolls back a database.
"""

from __future__ import annotations

from dataclasses import dataclass, fields
from datetime import datetime, timezone
import hashlib
import hmac
import json
import math
import re
import time
from typing import Mapping

from ..graph_coordinator import (
    BudgetAdmission, JobBinding, RuntimeAdmission, ScheduleAdmission,
    budget_operation_digest,
)
from ..graph_types import AtomKey
from ..runtime_contracts import (
    CommandEnvelope, DomainBundle, canonical_serialize,
)
from .budget import get_budget_lease
from .jobs import PersistentJob, get_job


MAX_DIMENSIONS = 32
MAX_QUANTITY = 9_000_000_000_000_000
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
_CURRENCY = re.compile(r"^[A-Z]{3}$")


class IssuerAuthorityDenied(PermissionError):
    pass


def _id(value: str, field: str) -> str:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise ValueError(f"invalid {field}")
    return value


def _ref(value: str | None, field: str, *, optional: bool = False) -> str | None:
    if value is None and optional:
        return None
    if not isinstance(value, str) or not 1 <= len(value) <= 4096:
        raise ValueError(f"invalid {field}")
    return value


def _finite(value: float, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise ValueError(f"{field} must be finite")
    return float(value)


def _now_utc(value: float | None) -> float:
    return _finite(time.time() if value is None else value, "now_utc")


def _amounts(value: Mapping[str, int], *, nonempty: bool = True) -> dict[str, int]:
    if not isinstance(value, Mapping) or len(value) > MAX_DIMENSIONS:
        raise ValueError("resource amounts have too many dimensions")
    result: dict[str, int] = {}
    for name, amount in value.items():
        _id(name, "resource dimension")
        if isinstance(amount, bool) or not isinstance(amount, int) or not 0 <= amount <= MAX_QUANTITY:
            raise ValueError("resource quantities must be bounded non-negative integers")
        if amount:
            result[name] = amount
    if nonempty and not result:
        raise ValueError("resource ceiling must contain a positive amount")
    return result


def _tuple_refs(value, field: str) -> tuple[str, ...]:
    result = tuple(value)
    if len(set(result)) != len(result):
        raise ValueError(f"{field} contains duplicates")
    for item in result:
        _ref(item, field)
    return result


def _within(actual: Mapping[str, int], ceiling: Mapping[str, int]) -> bool:
    return all(amount <= ceiling.get(name, 0) for name, amount in actual.items())


@dataclass(frozen=True)
class ResourceQuote:
    quote_id: str
    version: int
    bot_id: str
    persona_id: str
    activity_id: str
    operation_id: str
    effect_id: str | None
    parent_budget_lease_ref: str
    work_kind: str
    snapshot_ref: str
    deadline_utc: float
    resource_ref: str
    graph_job_ref: str | None
    outbox_refs: tuple[str, ...]
    d02_settlement_refs: tuple[str, ...]
    ceiling: Mapping[str, int]
    required_worker_fence: int | None
    valid_until_utc: float

    def __post_init__(self) -> None:
        for name in ("quote_id", "bot_id", "persona_id", "activity_id",
                     "operation_id", "parent_budget_lease_ref", "work_kind",
                     "snapshot_ref", "resource_ref"):
            _id(getattr(self, name), name)
        if self.effect_id is not None:
            _id(self.effect_id, "effect_id")
        if not isinstance(self.version, int) or isinstance(self.version, bool) or self.version < 1:
            raise ValueError("quote version must be positive")
        deadline = _finite(self.deadline_utc, "deadline_utc")
        valid_until = _finite(self.valid_until_utc, "valid_until_utc")
        if valid_until < deadline:
            raise ValueError("resource quote expires before the command deadline")
        if self.graph_job_ref is not None:
            _ref(self.graph_job_ref, "graph_job_ref")
            try:
                key = AtomKey.from_token(self.graph_job_ref)
            except (TypeError, ValueError) as exc:
                raise ValueError("graph_job_ref must be a canonical atom token") from exc
            if key.type_name != "runtime.job":
                raise ValueError("graph_job_ref must identify runtime.job")
        outbox = _tuple_refs(self.outbox_refs, "outbox_refs")
        settlements = _tuple_refs(self.d02_settlement_refs, "d02_settlement_refs")
        if outbox and self.graph_job_ref is None:
            raise ValueError("outbox refs require a graph job")
        if self.required_worker_fence is not None and (
                not isinstance(self.required_worker_fence, int)
                or isinstance(self.required_worker_fence, bool)
                or self.required_worker_fence < 0):
            raise ValueError("required_worker_fence must be non-negative")
        object.__setattr__(self, "outbox_refs", outbox)
        object.__setattr__(self, "d02_settlement_refs", settlements)
        object.__setattr__(self, "ceiling", _amounts(self.ceiling))
        object.__setattr__(self, "deadline_utc", deadline)
        object.__setattr__(self, "valid_until_utc", valid_until)


@dataclass(frozen=True)
class BudgetLeaseGrant:
    grant_id: str
    version: int
    bot_id: str
    persona_id: str
    lease_id: str
    currency: str
    max_ceiling: Mapping[str, int]
    allowed_work_kinds: tuple[str, ...]
    valid_until_utc: float
    policy_ref: str

    def __post_init__(self) -> None:
        for name in ("grant_id", "bot_id", "persona_id", "lease_id", "policy_ref"):
            _id(getattr(self, name), name)
        if not isinstance(self.version, int) or isinstance(self.version, bool) or self.version < 1:
            raise ValueError("grant version must be positive")
        if not _CURRENCY.fullmatch(self.currency):
            raise ValueError("grant currency must be an uppercase three-letter code")
        kinds = _tuple_refs(self.allowed_work_kinds, "allowed_work_kinds")
        if not kinds:
            raise ValueError("budget grant requires an allowed work kind")
        object.__setattr__(self, "allowed_work_kinds", kinds)
        object.__setattr__(self, "max_ceiling", _amounts(self.max_ceiling))
        object.__setattr__(self, "valid_until_utc",
                           _finite(self.valid_until_utc, "valid_until_utc"))


@dataclass(frozen=True)
class ResourceOutcome:
    outcome_id: str
    version: int
    quote_id: str
    bot_id: str
    persona_id: str
    activity_id: str
    operation_id: str
    actual: Mapping[str, int] | None
    execution_revoked: bool
    provider_receipt_ref: str

    def __post_init__(self) -> None:
        for name in ("outcome_id", "quote_id", "bot_id", "persona_id",
                     "activity_id", "operation_id", "provider_receipt_ref"):
            _id(getattr(self, name), name)
        if not isinstance(self.version, int) or isinstance(self.version, bool) or self.version < 1:
            raise ValueError("outcome version must be positive")
        if self.actual is not None:
            object.__setattr__(self, "actual", _amounts(self.actual, nonempty=False))
        if not isinstance(self.execution_revoked, bool):
            raise ValueError("execution_revoked must be boolean")


def _payload(value: object) -> dict[str, object]:
    return {field.name: getattr(value, field.name) for field in fields(value)}


def _decode_quote(payload: str) -> ResourceQuote:
    value = json.loads(payload)
    value["outbox_refs"] = tuple(value["outbox_refs"])
    value["d02_settlement_refs"] = tuple(value["d02_settlement_refs"])
    return ResourceQuote(**value)


def _decode_grant(payload: str) -> BudgetLeaseGrant:
    value = json.loads(payload)
    value["allowed_work_kinds"] = tuple(value["allowed_work_kinds"])
    return BudgetLeaseGrant(**value)


def _decode_outcome(payload: str) -> ResourceOutcome:
    return ResourceOutcome(**json.loads(payload))


class _Signer:
    def __init__(self, signing_key: bytes):
        if not isinstance(signing_key, bytes) or len(signing_key) < 32:
            raise ValueError("issuer signing key must contain at least 32 bytes")
        self.__key = bytes(signing_key)

    def sign(self, kind: str, payload: str) -> str:
        return hmac.new(self.__key, (kind + "\n" + payload).encode("utf-8"),
                        hashlib.sha256).hexdigest()

    def verify(self, kind: str, payload: str, signature: str) -> None:
        if not hmac.compare_digest(self.sign(kind, payload), signature):
            raise IssuerAuthorityDenied(f"{kind} signature is invalid")


def install_schema(db) -> None:
    db.execute("""
        CREATE TABLE IF NOT EXISTS runtime_resource_quotes(
            quote_id TEXT NOT NULL,
            version INTEGER NOT NULL,
            quote_json TEXT NOT NULL,
            signature TEXT NOT NULL,
            status TEXT NOT NULL,
            PRIMARY KEY(quote_id,version)
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS runtime_budget_grants(
            lease_id TEXT NOT NULL,
            version INTEGER NOT NULL,
            grant_json TEXT NOT NULL,
            signature TEXT NOT NULL,
            status TEXT NOT NULL,
            PRIMARY KEY(lease_id,version)
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS runtime_resource_outcomes(
            quote_id TEXT NOT NULL,
            operation_id TEXT NOT NULL,
            version INTEGER NOT NULL,
            outcome_json TEXT NOT NULL,
            signature TEXT NOT NULL,
            PRIMARY KEY(quote_id,operation_id,version)
        )
    """)


def _insert_signed(db, table: str, key_columns: tuple[str, ...],
                   key_values: tuple[object, ...], payload_column: str,
                   payload: str, signature: str, *, status: bool = False) -> None:
    columns = key_columns + (payload_column, "signature") + (("status",) if status else ())
    values = key_values + (payload, signature) + (("active",) if status else ())
    placeholders = ",".join("?" for _ in columns)
    try:
        db.execute(
            f"INSERT INTO {table}({','.join(columns)}) VALUES({placeholders})", values,
        )
    except Exception as exc:
        raise IssuerAuthorityDenied("signed authority identity already exists") from exc


class D02ResourceIssuer:
    """Authenticates bounded D02 quotes and provider outcomes."""

    def __init__(self, signing_key: bytes, *, outcome_verifier=None):
        self._signer = _Signer(signing_key)
        if outcome_verifier is not None and not callable(outcome_verifier):
            raise TypeError("outcome_verifier must be callable")
        self._outcome_verifier = outcome_verifier

    def _verify_outcome_authority(self, outcome: ResourceOutcome,
                                  quote: ResourceQuote, db) -> None:
        if self._outcome_verifier is None:
            raise IssuerAuthorityDenied(
                "server-side provider outcome verifier is unavailable"
            )
        try:
            result = self._outcome_verifier(outcome, quote, db)
        except Exception as exc:
            raise IssuerAuthorityDenied(
                "server-side provider outcome verification failed"
            ) from exc
        if result is not True:
            raise IssuerAuthorityDenied(
                "provider receipt or execution revocation is not independently verified"
            )

    def issue_quote(self, db, quote: ResourceQuote) -> str:
        if not isinstance(quote, ResourceQuote):
            raise TypeError("quote must be ResourceQuote")
        payload = canonical_serialize(_payload(quote))
        signature = self._signer.sign("resource-quote.v1", payload)
        _insert_signed(
            db, "runtime_resource_quotes", ("quote_id", "version"),
            (quote.quote_id, quote.version), "quote_json", payload, signature,
            status=True,
        )
        return signature

    def issue_outcome(self, db, outcome: ResourceOutcome) -> str:
        if not isinstance(outcome, ResourceOutcome):
            raise TypeError("outcome must be ResourceOutcome")
        quote = self._load_quote(db, outcome.quote_id, None)
        if ((outcome.bot_id, outcome.persona_id) != (quote.bot_id, quote.persona_id)
                or outcome.activity_id != quote.activity_id
                or outcome.operation_id != quote.operation_id):
            raise IssuerAuthorityDenied("outcome identity differs from its quote")
        if outcome.actual is not None:
            if not _within(outcome.actual, quote.ceiling):
                raise IssuerAuthorityDenied("outcome actual exceeds quote ceiling")
            if outcome.actual != quote.ceiling and not outcome.execution_revoked:
                raise IssuerAuthorityDenied(
                    "released quote ceiling requires revoked execution authority"
                )
        self._verify_outcome_authority(outcome, quote, db)
        payload = canonical_serialize(_payload(outcome))
        signature = self._signer.sign("resource-outcome.v1", payload)
        _insert_signed(
            db, "runtime_resource_outcomes",
            ("quote_id", "operation_id", "version"),
            (outcome.quote_id, outcome.operation_id, outcome.version),
            "outcome_json", payload, signature,
        )
        return signature

    def _load_quote(self, db, quote_id: str,
                    version: int | None) -> ResourceQuote:
        if version is None:
            row = db.execute(
                "SELECT quote_json,signature,status FROM runtime_resource_quotes "
                "WHERE quote_id=? ORDER BY version DESC LIMIT 1", (quote_id,),
            ).fetchone()
        else:
            row = db.execute(
                "SELECT quote_json,signature,status FROM runtime_resource_quotes "
                "WHERE quote_id=? AND version=?", (quote_id, version),
            ).fetchone()
        if row is None or row[2] != "active":
            raise IssuerAuthorityDenied("qualified D02 resource quote is absent")
        self._signer.verify("resource-quote.v1", row[0], row[1])
        try:
            return _decode_quote(row[0])
        except (TypeError, ValueError, KeyError, json.JSONDecodeError) as exc:
            raise IssuerAuthorityDenied("resource quote payload is invalid") from exc

    def qualified_quote(self, envelope: CommandEnvelope, db, *,
                        now_utc: float | None = None) -> ResourceQuote:
        if not isinstance(envelope, CommandEnvelope):
            raise TypeError("envelope must be CommandEnvelope")
        refs = envelope.version_guard.resource_lease_versions
        if len(refs) != 1:
            raise IssuerAuthorityDenied("exactly one qualified resource quote is required")
        quote = self._load_quote(db, refs[0].ref, refs[0].version)
        identity = envelope.identity
        namespace = envelope.authority.namespace
        now_utc = _now_utc(now_utc)
        if (envelope.deadline_utc <= now_utc
                or quote.valid_until_utc <= now_utc
                or (quote.bot_id, quote.persona_id) != namespace.as_tuple
                or quote.activity_id != identity.activity_id
                or quote.operation_id != identity.operation_id
                or quote.effect_id != identity.effect_id
                or quote.parent_budget_lease_ref != envelope.parent_budget_lease_ref
                or quote.deadline_utc != envelope.deadline_utc
                or quote.valid_until_utc < envelope.deadline_utc
                or quote.required_worker_fence != envelope.authority.worker_fence):
            raise IssuerAuthorityDenied("resource quote is not bound to this command")
        return quote

    def qualified_outcome(self, quote: ResourceQuote, db) -> ResourceOutcome:
        row = db.execute(
            "SELECT outcome_json,signature FROM runtime_resource_outcomes "
            "WHERE quote_id=? AND operation_id=? ORDER BY version DESC LIMIT 1",
            (quote.quote_id, quote.operation_id),
        ).fetchone()
        if row is None:
            raise IssuerAuthorityDenied("signed provider outcome is absent")
        self._signer.verify("resource-outcome.v1", row[0], row[1])
        try:
            outcome = _decode_outcome(row[0])
        except (TypeError, ValueError, KeyError, json.JSONDecodeError) as exc:
            raise IssuerAuthorityDenied("provider outcome payload is invalid") from exc
        if ((outcome.bot_id, outcome.persona_id) != (quote.bot_id, quote.persona_id)
                or outcome.quote_id != quote.quote_id
                or outcome.operation_id != quote.operation_id
                or outcome.activity_id != quote.activity_id):
            raise IssuerAuthorityDenied("provider outcome differs from resource quote")
        if outcome.actual is not None and not _within(outcome.actual, quote.ceiling):
            raise IssuerAuthorityDenied("provider outcome exceeds quote ceiling")
        self._verify_outcome_authority(outcome, quote, db)
        return outcome

    def authorize_schedule(self, envelope: CommandEnvelope, db, *,
                           now_utc: float | None = None) -> bool:
        quote = self.qualified_quote(envelope, db, now_utc=now_utc)
        if quote.graph_job_ref is None:
            raise IssuerAuthorityDenied("scheduling quote lacks a graph job identity")
        return True

    def authorize_resources(self, bundle: DomainBundle, db, *,
                            now_utc: float | None = None) -> bool:
        if not isinstance(bundle, DomainBundle):
            raise TypeError("bundle must be DomainBundle")
        quote = self.qualified_quote(bundle.envelope, db, now_utc=now_utc)
        expected_jobs = (quote.graph_job_ref,) if quote.graph_job_ref is not None else ()
        if (bundle.persistent_job_refs != expected_jobs
                or bundle.outbox_refs != quote.outbox_refs
                or bundle.d02_settlement_refs != quote.d02_settlement_refs):
            raise IssuerAuthorityDenied("bundle runtime refs differ from the resource quote")
        return True


class D11BudgetGrantIssuer:
    """Signs and verifies durable D11 lease grants without D02 authority."""

    def __init__(self, signing_key: bytes):
        self._signer = _Signer(signing_key)

    def issue_budget_grant(self, db, grant: BudgetLeaseGrant) -> str:
        if not isinstance(grant, BudgetLeaseGrant):
            raise TypeError("grant must be BudgetLeaseGrant")
        lease = get_budget_lease(db, grant.lease_id)
        if ((grant.bot_id, grant.persona_id, grant.currency)
                != (lease.bot_id, lease.persona_id, lease.currency)):
            raise IssuerAuthorityDenied("budget grant differs from durable lease")
        for name, amount in grant.max_ceiling.items():
            if amount > lease.limits.get(name, 0):
                raise IssuerAuthorityDenied("budget grant exceeds durable lease limit")
        payload = canonical_serialize(_payload(grant))
        signature = self._signer.sign("budget-grant.v1", payload)
        _insert_signed(
            db, "runtime_budget_grants", ("lease_id", "version"),
            (grant.lease_id, grant.version), "grant_json", payload, signature,
            status=True,
        )
        return signature

    def _load_grant(self, db, lease_id: str) -> BudgetLeaseGrant:
        row = db.execute(
            "SELECT grant_json,signature,status FROM runtime_budget_grants "
            "WHERE lease_id=? ORDER BY version DESC LIMIT 1", (lease_id,),
        ).fetchone()
        if row is None or row[2] != "active":
            raise IssuerAuthorityDenied("signed D11 budget lease grant is absent")
        self._signer.verify("budget-grant.v1", row[0], row[1])
        try:
            return _decode_grant(row[0])
        except (TypeError, ValueError, KeyError, json.JSONDecodeError) as exc:
            raise IssuerAuthorityDenied("budget grant payload is invalid") from exc

    def current_budget_grant(self, db, lease_id: str) -> BudgetLeaseGrant:
        """Verify and return the active signed grant in this business transaction."""
        return self._load_grant(db, lease_id)

    def signed_budget_grant_at_version(self, db, lease_id: str,
                                       version: int) -> tuple[BudgetLeaseGrant, str]:
        """Verify an original signed grant for receipt replay, regardless of current status."""
        row = db.execute(
            "SELECT grant_json,signature FROM runtime_budget_grants "
            "WHERE lease_id=? AND version=?", (lease_id, version),
        ).fetchone()
        if row is None:
            raise IssuerAuthorityDenied("historical D11 budget lease grant is absent")
        self._signer.verify("budget-grant.v1", row[0], row[1])
        try:
            grant = _decode_grant(row[0])
        except (TypeError, ValueError, KeyError, json.JSONDecodeError) as exc:
            raise IssuerAuthorityDenied("historical budget grant payload is invalid") from exc
        if (grant.lease_id, grant.version) != (lease_id, version):
            raise IssuerAuthorityDenied("historical budget grant identity differs")
        return grant, row[1]


class D11BudgetJobIssuer(D11BudgetGrantIssuer):
    """Issues typed GraphCoordinator admissions from signed D02 and D11 state."""

    def __init__(self, d02_issuer: D02ResourceIssuer, signing_key: bytes):
        if not isinstance(d02_issuer, D02ResourceIssuer):
            raise TypeError("d02_issuer must be D02ResourceIssuer")
        super().__init__(signing_key)
        self._d02 = d02_issuer

    @property
    def resource_issuer(self) -> D02ResourceIssuer:
        """Return the D02 authority this budget issuer actually verifies."""
        return self._d02

    def _admission_state(self, envelope: CommandEnvelope, db, *, now_utc: float):
        quote = self._d02.qualified_quote(envelope, db, now_utc=now_utc)
        grant = self._load_grant(db, envelope.parent_budget_lease_ref)
        lease = get_budget_lease(db, grant.lease_id)
        if (envelope.deadline_utc <= now_utc
                or quote.valid_until_utc <= now_utc
                or grant.valid_until_utc <= now_utc
                or lease.state != "active"
                or (grant.bot_id, grant.persona_id, grant.currency)
                != (lease.bot_id, lease.persona_id, lease.currency)
                or (quote.bot_id, quote.persona_id) != (grant.bot_id, grant.persona_id)
                or quote.parent_budget_lease_ref != grant.lease_id
                or quote.work_kind not in grant.allowed_work_kinds
                or quote.valid_until_utc > grant.valid_until_utc
                or envelope.authority.provider_policy_ref != grant.policy_ref):
            raise IssuerAuthorityDenied("quote is outside the signed budget grant")
        if any(amount > grant.max_ceiling.get(name, 0)
               for name, amount in quote.ceiling.items()):
            raise IssuerAuthorityDenied("quote ceiling exceeds the signed budget grant")
        return quote, grant, lease

    @staticmethod
    def _deadline_text(timestamp: float) -> str:
        try:
            return datetime.fromtimestamp(timestamp, timezone.utc).isoformat().replace(
                "+00:00", "Z"
            )
        except (OverflowError, OSError, ValueError) as exc:
            raise IssuerAuthorityDenied("command deadline is not representable") from exc

    def job_for(self, envelope: CommandEnvelope, db, *,
                now_utc: float | None = None) -> PersistentJob:
        quote, _, lease = self._admission_state(
            envelope, db, now_utc=_now_utc(now_utc)
        )
        if quote.graph_job_ref is None:
            raise IssuerAuthorityDenied("resource quote has no scheduled graph job")
        try:
            key = AtomKey.from_token(quote.graph_job_ref)
        except (TypeError, ValueError) as exc:
            raise IssuerAuthorityDenied("resource quote graph job ref is invalid") from exc
        namespace = envelope.authority.namespace
        if (key.type_name != "runtime.job" or key.owner.kind != "activity"
                or (key.owner.bot, key.owner.persona) != namespace.as_tuple
                or key.owner.subject != envelope.identity.activity_id):
            raise IssuerAuthorityDenied("resource quote graph job crosses command authority")
        return PersistentJob(
            key.name, envelope.identity.operation_id, envelope.identity.activity_id,
            envelope.identity.effect_id, namespace.bot_id, namespace.persona_id,
            quote.snapshot_ref, "queued", quote.work_kind, {}, None,
            self._deadline_text(envelope.deadline_utc), lease.lease_id,
            quote.resource_ref, {"resource_quote": f"{quote.quote_id}:{quote.version}"},
            None, None, 0, 0, {}, None,
        )

    def admit_schedule(self, envelope: CommandEnvelope, db, *,
                       now_utc: float | None = None) -> ScheduleAdmission:
        now_utc = _now_utc(now_utc)
        quote, _, lease = self._admission_state(envelope, db, now_utc=now_utc)
        if quote.required_worker_fence is not None:
            raise IssuerAuthorityDenied("new schedule cannot start with an existing worker fence")
        return ScheduleAdmission(
            BudgetAdmission(lease.lease_id, lease.version, dict(quote.ceiling)),
            self.job_for(envelope, db, now_utc=now_utc),
        )

    def admit_runtime(self, bundle: DomainBundle, db, *,
                      now_utc: float | None = None) -> RuntimeAdmission:
        if not isinstance(bundle, DomainBundle):
            raise TypeError("bundle must be DomainBundle")
        envelope = bundle.envelope
        now_utc = _now_utc(now_utc)
        quote, _, lease = self._admission_state(envelope, db, now_utc=now_utc)
        self._d02.authorize_resources(bundle, db, now_utc=now_utc)
        digest = budget_operation_digest(envelope, lease.lease_id, dict(quote.ceiling))
        reservation = db.execute(
            "SELECT digest,ceiling_json,state FROM runtime_budget_reservations "
            "WHERE lease_id=? AND operation_id=?",
            (lease.lease_id, quote.operation_id),
        ).fetchone()
        pre_reserved = reservation is not None
        if pre_reserved and (
                reservation[0] != digest
                or json.loads(reservation[1]) != dict(quote.ceiling)
                or reservation[2] not in {"reserved", "unknown"}):
            raise IssuerAuthorityDenied("durable reservation differs from signed quote")
        jobs: tuple[JobBinding, ...] = ()
        if quote.graph_job_ref is not None:
            job_id = AtomKey.from_token(quote.graph_job_ref).name
            if pre_reserved:
                try:
                    job = get_job(db, job_id)
                except Exception as exc:
                    raise IssuerAuthorityDenied("pre-reserved quote lacks its durable job") from exc
            else:
                job = self.job_for(envelope, db, now_utc=now_utc)
            if envelope.authority.worker_fence is not None:
                if (job.phase != "running"
                        or job.lease_holder != envelope.authority.actor
                        or job.fence != envelope.authority.worker_fence
                        or job.cancel_epoch != 0):
                    raise IssuerAuthorityDenied("worker fence differs from durable job")
            elif job.phase == "running":
                raise IssuerAuthorityDenied("running job result requires a worker fence")
            jobs = (JobBinding(quote.graph_job_ref, job, quote.outbox_refs),)
        settle_now = bool(bundle.d11_cost_settlement_refs)
        actual = None
        execution_revoked = False
        if settle_now:
            if reservation is not None and reservation[2] == "unknown":
                raise IssuerAuthorityDenied("unknown reservation requires explicit resolution flow")
            outcome = self._d02.qualified_outcome(quote, db)
            actual = None if outcome.actual is None else dict(outcome.actual)
            execution_revoked = outcome.execution_revoked
        return RuntimeAdmission(
            BudgetAdmission(
                lease.lease_id, lease.version, dict(quote.ceiling),
                pre_reserved=pre_reserved, settle_now=settle_now, actual=actual,
                execution_revoked=execution_revoked,
                reservation_operation_id=quote.operation_id if pre_reserved else None,
            ),
            jobs,
        )


def build_runtime_issuers(signing_key: bytes, *,
                          outcome_verifier=None) -> tuple[D02ResourceIssuer, D11BudgetJobIssuer]:
    """Build issuers around a host key that is never persisted in business DBs."""
    d02 = D02ResourceIssuer(signing_key, outcome_verifier=outcome_verifier)
    return d02, D11BudgetJobIssuer(d02, signing_key)


__all__ = [
    "BudgetLeaseGrant", "D02ResourceIssuer", "D11BudgetGrantIssuer", "D11BudgetJobIssuer",
    "IssuerAuthorityDenied", "ResourceOutcome", "ResourceQuote",
    "build_runtime_issuers", "install_schema",
]
