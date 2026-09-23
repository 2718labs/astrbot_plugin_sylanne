"""D11-owned graph projections for runtime jobs, outbox work and cost.

These atoms are strict, queryable projections.  The authoritative mutable
state remains in ``runtime_jobs`` and the runtime budget tables.  Coordinator
code must call :func:`reconcile_runtime_write` inside the same SQLite
transaction before accepting the corresponding graph bundle.
"""

from __future__ import annotations

from dataclasses import dataclass, fields
import hashlib
import json
import re
from typing import Any, Mapping

from ..graph_types import AtomKey, GraphWrite, Owner, TypeSpec
from ..runtime_contracts import (
    DomainProposal, NamespaceId, ProviderDescriptor, RUNTIME_SCHEMA,
    canonical_digest, schema_hash,
)
from .budget import get_budget_lease
from .jobs import PersistentJob, get_job


D11_PROPOSAL_SCHEMA = "d11.runtime.proposal.v1"
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_CURRENCY = re.compile(r"^[A-Z]{3}$")
_JOB_PHASES = frozenset({
    "queued", "running", "waiting", "deferred", "draining", "cancelled",
    "completed", "failed", "pending_confirmation",
})
_OUTBOX_PHASES = frozenset({
    "pending", "sending", "ack", "delivered", "failed", "unknown", "cancelled",
})
_TYPE_NAMES = frozenset({"runtime.job", "runtime.outbox", "runtime.cost_settlement"})
MAX_DIMENSIONS = 32
MAX_QUANTITY = 9_000_000_000_000_000


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


def _digest(value: str | None, field: str, *, optional: bool = False) -> str | None:
    if value is None and optional:
        return None
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        raise ValueError(f"{field} must be a lowercase SHA-256 digest")
    return value


def _amounts(value: Mapping[str, int] | None, *, allow_none: bool = False,
             require_nonempty: bool = False) -> dict[str, int] | None:
    if value is None:
        if allow_none:
            return None
        raise ValueError("cost amounts cannot be null")
    if not isinstance(value, Mapping) or len(value) > MAX_DIMENSIONS:
        raise ValueError("cost amounts have too many dimensions")
    result: dict[str, int] = {}
    for dimension, amount in value.items():
        _id(dimension, "cost dimension")
        if isinstance(amount, bool) or not isinstance(amount, int):
            raise ValueError("cost amounts must use integer base units")
        if amount < 0 or amount > MAX_QUANTITY:
            raise ValueError("cost amount is outside the supported range")
        if amount:
            result[dimension] = amount
    if require_nonempty and not result:
        raise ValueError("cost ceiling must contain a positive amount")
    return result


def _within(actual: Mapping[str, int], ceiling: Mapping[str, int]) -> bool:
    return all(amount <= ceiling.get(dimension, 0)
               for dimension, amount in actual.items())


@dataclass(frozen=True)
class RuntimeJobValue:
    bot_id: str
    persona_id: str
    activity_id: str
    operation_id: str
    effect_id: str | None
    job_id: str
    snapshot_ref: str
    phase: str
    work_kind: str
    continuation_digest: str
    wake_condition_digest: str | None
    deadline_utc: str
    parent_budget_lease_ref: str
    resource_ref: str
    operator_versions_digest: str
    lease_holder: str | None
    lease_expires_utc: str | None
    fence: int
    cancel_epoch: int
    usage_digest: str
    result_ref: str | None

    def __post_init__(self) -> None:
        for name in ("bot_id", "persona_id", "activity_id", "operation_id",
                     "job_id", "snapshot_ref", "work_kind",
                     "parent_budget_lease_ref", "resource_ref"):
            _id(getattr(self, name), name)
        for name in ("effect_id", "lease_holder", "result_ref"):
            value = getattr(self, name)
            if value is not None:
                _id(value, name)
        for name in ("deadline_utc", "lease_expires_utc"):
            _ref(getattr(self, name), name, optional=(name == "lease_expires_utc"))
        for name in ("continuation_digest", "wake_condition_digest",
                     "operator_versions_digest", "usage_digest"):
            _digest(getattr(self, name), name,
                    optional=(name == "wake_condition_digest"))
        if self.phase not in _JOB_PHASES:
            raise ValueError("unsupported runtime job phase")
        if not isinstance(self.fence, int) or isinstance(self.fence, bool) or self.fence < 0:
            raise ValueError("fence must be a non-negative integer")
        if (not isinstance(self.cancel_epoch, int) or isinstance(self.cancel_epoch, bool)
                or self.cancel_epoch < 0):
            raise ValueError("cancel_epoch must be a non-negative integer")
        if (self.lease_holder is None) != (self.lease_expires_utc is None):
            raise ValueError("lease holder and expiry must be present together")


@dataclass(frozen=True)
class RuntimeOutboxValue:
    bot_id: str
    persona_id: str
    activity_id: str
    operation_id: str
    effect_id: str | None
    outbox_id: str
    job_id: str
    job_ref: str
    payload_ref: str
    idempotency_key: str
    phase: str
    dispatch_generation: int

    def __post_init__(self) -> None:
        for name in ("bot_id", "persona_id", "activity_id", "operation_id",
                     "outbox_id", "job_id", "payload_ref", "idempotency_key"):
            _id(getattr(self, name), name)
        if self.effect_id is not None:
            _id(self.effect_id, "effect_id")
        _ref(self.job_ref, "job_ref")
        try:
            job_key = AtomKey.from_token(self.job_ref)
        except (TypeError, ValueError) as exc:
            raise ValueError("job_ref must be a canonical graph atom token") from exc
        if job_key.type_name != "runtime.job":
            raise ValueError("outbox job_ref must identify runtime.job")
        if self.phase not in _OUTBOX_PHASES:
            raise ValueError("unsupported outbox phase")
        if (not isinstance(self.dispatch_generation, int)
                or isinstance(self.dispatch_generation, bool)
                or self.dispatch_generation < 0):
            raise ValueError("dispatch_generation must be a non-negative integer")


@dataclass(frozen=True)
class RuntimeCostSettlement:
    bot_id: str
    persona_id: str
    activity_id: str
    bundle_operation_id: str
    effect_id: str | None
    settlement_id: str
    lease_id: str
    currency: str
    cost_operation_id: str
    status: str
    ceiling: Mapping[str, int]
    actual: Mapping[str, int] | None
    unconfirmed: Mapping[str, int]
    budget_phase: str
    budget_operation_id: str
    budget_receipt_digest: str
    prior_unknown_ref: str | None
    execution_revoked: bool

    def __post_init__(self) -> None:
        for name in ("bot_id", "persona_id", "activity_id", "bundle_operation_id",
                     "settlement_id", "lease_id", "cost_operation_id",
                     "budget_operation_id"):
            _id(getattr(self, name), name)
        if self.effect_id is not None:
            _id(self.effect_id, "effect_id")
        if not _CURRENCY.fullmatch(self.currency):
            raise ValueError("currency must be an uppercase three-letter code")
        ceiling = _amounts(self.ceiling, require_nonempty=True)
        actual = _amounts(self.actual, allow_none=True)
        unconfirmed = _amounts(self.unconfirmed)
        _digest(self.budget_receipt_digest, "budget_receipt_digest")
        if self.prior_unknown_ref is not None:
            _ref(self.prior_unknown_ref, "prior_unknown_ref")
            try:
                prior = AtomKey.from_token(self.prior_unknown_ref)
            except (TypeError, ValueError) as exc:
                raise ValueError("prior_unknown_ref must be a canonical atom token") from exc
            if prior.type_name != "runtime.cost_settlement":
                raise ValueError("prior_unknown_ref must identify a cost settlement")
        if not isinstance(self.execution_revoked, bool):
            raise ValueError("execution_revoked must be boolean")
        if self.status == "pending_confirmation":
            if (actual is not None or unconfirmed != ceiling
                    or self.budget_phase != "settle"
                    or self.budget_operation_id != self.cost_operation_id
                    or self.prior_unknown_ref is not None):
                raise ValueError("unknown cost must retain its full original ceiling")
        elif self.status == "settled":
            if actual is None or unconfirmed:
                raise ValueError("settled cost requires known actual and no unknown balance")
            if not _within(actual, ceiling):
                raise ValueError("actual cost exceeds its ceiling")
            if actual != ceiling and not self.execution_revoked:
                raise ValueError("released cost ceiling requires revoked execution authority")
            if self.prior_unknown_ref is None:
                if (self.budget_phase != "settle"
                        or self.budget_operation_id != self.cost_operation_id):
                    raise ValueError("direct settlement must use the original cost operation")
            elif (self.budget_phase != "resolve"
                  or self.budget_operation_id == self.cost_operation_id):
                raise ValueError("unknown resolution requires an independent resolve receipt")
        else:
            raise ValueError("cost status must be settled or pending_confirmation")
        object.__setattr__(self, "ceiling", ceiling)
        object.__setattr__(self, "actual", actual)
        object.__setattr__(self, "unconfirmed", unconfirmed)


def _value_dict(value: object) -> dict[str, Any]:
    return {field.name: getattr(value, field.name) for field in fields(value)}


def _strict_payload(payload: object, value_type: type) -> object:
    if type(payload) is not dict:
        raise TypeError("D11 graph payload must be an object")
    expected = {field.name for field in fields(value_type)}
    actual = set(payload)
    if actual != expected:
        raise ValueError(
            f"{value_type.__name__} payload fields must match exactly; "
            f"missing={sorted(expected - actual)!r}, extra={sorted(actual - expected)!r}"
        )
    return value_type(**payload)


_VALUE_TYPES = {
    "runtime.job": RuntimeJobValue,
    "runtime.outbox": RuntimeOutboxValue,
    "runtime.cost_settlement": RuntimeCostSettlement,
}


def _type_schema(name: str, value_type: type) -> dict[str, object]:
    return {
        "type": name,
        "schema_version": 1,
        "owner_kinds": ["activity"],
        "storage_role": "state",
        "writer_domain": "d11",
        "fields": [field.name for field in fields(value_type)],
    }


TYPE_SCHEMA_HASHES = {
    name: schema_hash(_type_schema(name, value_type))
    for name, value_type in sorted(_VALUE_TYPES.items())
}
D11_PROPOSAL_SCHEMA_HASH = schema_hash({
    "proposal": D11_PROPOSAL_SCHEMA,
    "runtime_schema": RUNTIME_SCHEMA,
    "types": TYPE_SCHEMA_HASHES,
})


def graph_type_specs() -> tuple[TypeSpec, ...]:
    return tuple(
        TypeSpec(
            name, ("activity",), "state",
            lambda payload, cls=value_type: _strict_payload(payload, cls),
            writer_domain="d11", schema_hash=TYPE_SCHEMA_HASHES[name],
        )
        for name, value_type in sorted(_VALUE_TYPES.items())
    )


def runtime_job_key(bot_id: str, persona_id: str, activity_id: str,
                    job_id: str) -> AtomKey:
    return AtomKey(Owner("activity", bot_id, persona_id, activity_id),
                   "runtime.job", _id(job_id, "job_id"))


def runtime_outbox_key(bot_id: str, persona_id: str, activity_id: str,
                       outbox_id: str) -> AtomKey:
    return AtomKey(Owner("activity", bot_id, persona_id, activity_id),
                   "runtime.outbox", _id(outbox_id, "outbox_id"))


def runtime_cost_settlement_key(bot_id: str, persona_id: str,
                                activity_id: str, settlement_id: str) -> AtomKey:
    return AtomKey(Owner("activity", bot_id, persona_id, activity_id),
                   "runtime.cost_settlement", _id(settlement_id, "settlement_id"))


def job_value(job: PersistentJob) -> RuntimeJobValue:
    if not isinstance(job, PersistentJob):
        raise TypeError("job must be PersistentJob")
    return RuntimeJobValue(
        job.bot_id, job.persona_id, job.activity_id, job.operation_id,
        job.effect_id, job.job_id, job.snapshot_ref, job.phase, job.work_kind,
        canonical_digest(job.continuation),
        canonical_digest(job.wake_condition) if job.wake_condition is not None else None,
        job.deadline_utc, job.budget_ref, job.resource_ref,
        canonical_digest(job.operator_versions), job.lease_holder,
        job.lease_expires_utc, job.fence, job.cancel_epoch,
        canonical_digest(job.usage), job.result_ref,
    )


def job_graph_write(job: PersistentJob) -> GraphWrite:
    value = job_value(job)
    return GraphWrite(
        runtime_job_key(value.bot_id, value.persona_id, value.activity_id,
                        value.job_id),
        _value_dict(value),
    )


def outbox_graph_write(value: RuntimeOutboxValue,
                       job_key: AtomKey) -> GraphWrite:
    if not isinstance(value, RuntimeOutboxValue):
        raise TypeError("value must be RuntimeOutboxValue")
    if not isinstance(job_key, AtomKey) or job_key.type_name != "runtime.job":
        raise TypeError("job_key must identify runtime.job")
    if value.job_ref != job_key.token or value.job_id != job_key.name:
        raise ValueError("outbox job identity differs from its graph dependency")
    return GraphWrite(
        runtime_outbox_key(value.bot_id, value.persona_id, value.activity_id,
                           value.outbox_id),
        _value_dict(value), (job_key,),
    )


def cost_settlement_graph_write(value: RuntimeCostSettlement,
                                dependencies: tuple[AtomKey, ...] = ()) -> GraphWrite:
    if not isinstance(value, RuntimeCostSettlement):
        raise TypeError("value must be RuntimeCostSettlement")
    return GraphWrite(
        runtime_cost_settlement_key(
            value.bot_id, value.persona_id, value.activity_id, value.settlement_id,
        ),
        _value_dict(value), dependencies,
    )


def _decode(write: GraphWrite) -> object:
    try:
        value_type = _VALUE_TYPES[write.key.type_name]
    except KeyError:
        raise ValueError("D11 write has an unsupported graph type") from None
    return _strict_payload(write.value, value_type)


def validate_d11_writes(writes: tuple[GraphWrite, ...], namespace: NamespaceId,
                        *, operation_id: str, activity_id: str,
                        effect_id: str | None) -> bool:
    if not isinstance(namespace, NamespaceId):
        raise TypeError("namespace must be NamespaceId")
    if not isinstance(writes, tuple) or any(not isinstance(write, GraphWrite) for write in writes):
        raise TypeError("writes must be a tuple of GraphWrite values")
    _id(operation_id, "operation_id")
    _id(activity_id, "activity_id")
    if effect_id is not None:
        _id(effect_id, "effect_id")
    jobs: dict[str, tuple[AtomKey, RuntimeJobValue]] = {}
    outbox_ids: set[str] = set()
    idempotency_keys: set[str] = set()
    settlement_ids: set[str] = set()
    cost_operations: set[str] = set()
    decoded: list[tuple[GraphWrite, object]] = []
    for write in writes:
        if (write.key.type_name not in _TYPE_NAMES
                or write.key.owner.kind != "activity"
                or NamespaceId.from_key(write.key) != namespace
                or write.key.owner.subject != activity_id):
            raise ValueError("D11 write has the wrong type, namespace, or activity owner")
        value = _decode(write)
        decoded.append((write, value))
        value_operation = (value.bundle_operation_id
                           if isinstance(value, RuntimeCostSettlement)
                           else value.operation_id)
        if ((value.bot_id, value.persona_id) != namespace.as_tuple
                or value.activity_id != activity_id
                or value_operation != operation_id
                or value.effect_id != effect_id):
            raise ValueError("D11 payload identity differs from the command envelope")
        if isinstance(value, RuntimeJobValue):
            if value.job_id in jobs or write.key.name != value.job_id:
                raise ValueError("duplicate or mismatched runtime job")
            jobs[value.job_id] = (write.key, value)
        elif isinstance(value, RuntimeOutboxValue):
            if (value.outbox_id in outbox_ids or value.idempotency_key in idempotency_keys
                    or write.key.name != value.outbox_id):
                raise ValueError("duplicate or mismatched runtime outbox")
            if value.phase != "pending":
                raise ValueError("new D11 outbox write must start pending")
            outbox_ids.add(value.outbox_id)
            idempotency_keys.add(value.idempotency_key)
        else:
            if (value.settlement_id in settlement_ids
                    or value.cost_operation_id in cost_operations
                    or write.key.name != value.settlement_id):
                raise ValueError("duplicate or mismatched runtime cost settlement")
            settlement_ids.add(value.settlement_id)
            cost_operations.add(value.cost_operation_id)
    for write, value in decoded:
        if isinstance(value, RuntimeOutboxValue):
            linked = jobs.get(value.job_id)
            if (linked is None or linked[0].token != value.job_ref
                    or linked[0] not in write.dependencies):
                raise ValueError("outbox requires its matching same-proposal runtime job")
    return True


class D11RuntimeProvider:
    """Pure D11 proposal validator; SQLite reconciliation remains coordinator-owned."""

    @property
    def descriptor(self) -> ProviderDescriptor:
        return ProviderDescriptor(
            provider_id="d11.runtime", contract_version=RUNTIME_SCHEMA,
            request_schema_hash=D11_PROPOSAL_SCHEMA_HASH,
            response_schema_hash=schema_hash({"domain": "d11", "response": "validated.v1"}),
            owner_capabilities=("activity",),
            supported_modalities=("runtime",),
            supported_purposes=("schedule", "settle", "dispatch"),
            supported_platforms=("windows", "linux", "macos"),
            timeout_mode="persistent_deadline",
            cancellation_mode="fenced_cooperative",
            idempotency_mode="operation_id",
            cost_reporting_mode="actual_or_unconfirmed",
            health_capabilities=("runtime_table_reconciliation",),
            recovery_capabilities=("query_operation", "fenced_resume"),
        )

    def type_specs(self) -> tuple[TypeSpec, ...]:
        return graph_type_specs()

    def register_types(self) -> tuple[str, ...]:
        return tuple(spec.name for spec in self.type_specs())

    def validate(self, proposal: DomainProposal, snapshot: object) -> DomainProposal:
        if not isinstance(proposal, DomainProposal):
            raise TypeError("proposal must be DomainProposal")
        if (proposal.domain != "d11"
                or proposal.proposal_schema != D11_PROPOSAL_SCHEMA
                or proposal.proposal_schema_hash != D11_PROPOSAL_SCHEMA_HASH):
            raise ValueError("unsupported D11 runtime proposal")
        identity = proposal.envelope.identity
        validate_d11_writes(
            proposal.typed_writes, proposal.envelope.authority.namespace,
            operation_id=identity.operation_id,
            activity_id=identity.activity_id, effect_id=identity.effect_id,
        )
        return proposal

    def compile_scheme(self, draft: object, snapshot: object) -> object:
        return {"schema": D11_PROPOSAL_SCHEMA,
                "type_hashes": dict(TYPE_SCHEMA_HASHES)}

    def project(self, query: object, snapshot: object) -> object:
        return snapshot

    def invalidate(self, refs: tuple[object, ...]) -> tuple[object, ...]:
        return tuple(refs)

    def cleanup(self, plan: object) -> dict[str, object]:
        return {"domain": "d11", "status": "delegated_to_runtime", "plan": plan}


def _budget_operation(db, bot_id: str, persona_id: str,
                      operation_id: str, phase: str):
    row = db.execute(
        "SELECT digest,lease_id,receipt_json FROM runtime_budget_operations "
        "WHERE bot_id=? AND persona_id=? AND operation_id=? AND phase=?",
        (bot_id, persona_id, operation_id, phase),
    ).fetchone()
    if row is None:
        raise ValueError("independent budget operation receipt is absent")
    return row


def cost_settlement_from_runtime(
        db, *, bot_id: str, persona_id: str, activity_id: str,
        bundle_operation_id: str, effect_id: str | None, settlement_id: str,
        lease_id: str, cost_operation_id: str, budget_operation_id: str,
        budget_phase: str, prior_unknown_ref: str | None,
        execution_revoked: bool) -> RuntimeCostSettlement:
    lease = get_budget_lease(db, lease_id)
    if (lease.bot_id, lease.persona_id) != (bot_id, persona_id):
        raise ValueError("budget lease belongs to another namespace")
    reservation = db.execute(
        "SELECT ceiling_json,state,actual_json FROM runtime_budget_reservations "
        "WHERE lease_id=? AND operation_id=?", (lease_id, cost_operation_id),
    ).fetchone()
    if reservation is None:
        raise ValueError("cost reservation is absent")
    receipt_row = _budget_operation(
        db, bot_id, persona_id, budget_operation_id, budget_phase,
    )
    if receipt_row[1] != lease_id:
        raise ValueError("budget receipt belongs to another lease")
    receipt = json.loads(receipt_row[2])
    receipt_digest = hashlib.sha256(receipt_row[2].encode("utf-8")).hexdigest()
    ceiling = json.loads(reservation[0])
    prior_settle = _budget_operation(
        db, bot_id, persona_id, cost_operation_id, "settle",
    )
    prior_was_unknown = json.loads(prior_settle[2])["status"] == "pending_confirmation"
    if reservation[1] == "unknown":
        if (budget_phase != "settle" or budget_operation_id != cost_operation_id
                or receipt["status"] != "pending_confirmation"
                or prior_unknown_ref is not None):
            raise ValueError("unknown cost lacks its original pending receipt")
        status = "pending_confirmation"
        actual = None
        unconfirmed = ceiling
    elif reservation[1] == "settled":
        if receipt["status"] != "settled":
            raise ValueError("settled cost lacks an independent settled receipt")
        if prior_was_unknown:
            if (budget_phase != "resolve" or budget_operation_id == cost_operation_id
                    or prior_unknown_ref is None):
                raise ValueError("unknown cost resolution lacks an independent receipt")
        elif (budget_phase != "settle" or budget_operation_id != cost_operation_id
              or prior_unknown_ref is not None):
            raise ValueError("direct cost settlement references the wrong receipt")
        status = "settled"
        actual = json.loads(reservation[2]) if reservation[2] is not None else {}
        unconfirmed = {}
    else:
        raise ValueError("cost reservation has not been settled")
    return RuntimeCostSettlement(
        bot_id, persona_id, activity_id, bundle_operation_id, effect_id,
        settlement_id, lease_id, lease.currency, cost_operation_id, status,
        ceiling, actual, unconfirmed, budget_phase, budget_operation_id,
        receipt_digest, prior_unknown_ref, execution_revoked,
    )


def reconcile_runtime_write(db, write: GraphWrite) -> bool:
    if not isinstance(write, GraphWrite):
        raise TypeError("write must be GraphWrite")
    value = _decode(write)
    if isinstance(value, RuntimeJobValue):
        authoritative = job_graph_write(get_job(db, value.job_id))
        if authoritative.key != write.key or authoritative.value != write.value:
            raise ValueError("runtime.job graph projection differs from runtime_jobs")
    elif isinstance(value, RuntimeOutboxValue):
        job = get_job(db, value.job_id)
        expected_job_key = runtime_job_key(
            job.bot_id, job.persona_id, job.activity_id, job.job_id,
        )
        if (value.job_ref != expected_job_key.token
                or value.operation_id != job.operation_id
                or value.activity_id != job.activity_id
                or value.effect_id != job.effect_id
                or (value.bot_id, value.persona_id) != (job.bot_id, job.persona_id)):
            raise ValueError("runtime.outbox differs from its authoritative job")
    else:
        authoritative = cost_settlement_from_runtime(
            db, bot_id=value.bot_id, persona_id=value.persona_id,
            activity_id=value.activity_id,
            bundle_operation_id=value.bundle_operation_id,
            effect_id=value.effect_id, settlement_id=value.settlement_id,
            lease_id=value.lease_id, cost_operation_id=value.cost_operation_id,
            budget_operation_id=value.budget_operation_id,
            budget_phase=value.budget_phase,
            prior_unknown_ref=value.prior_unknown_ref,
            execution_revoked=value.execution_revoked,
        )
        if authoritative != value:
            raise ValueError("runtime.cost_settlement differs from budget authority")
    return True


__all__ = [
    "D11_PROPOSAL_SCHEMA", "D11_PROPOSAL_SCHEMA_HASH", "D11RuntimeProvider",
    "RuntimeCostSettlement", "RuntimeJobValue", "RuntimeOutboxValue",
    "TYPE_SCHEMA_HASHES", "cost_settlement_from_runtime",
    "cost_settlement_graph_write", "graph_type_specs", "job_graph_write",
    "job_value", "outbox_graph_write", "reconcile_runtime_write",
    "runtime_cost_settlement_key", "runtime_job_key", "runtime_outbox_key",
    "validate_d11_writes",
]
