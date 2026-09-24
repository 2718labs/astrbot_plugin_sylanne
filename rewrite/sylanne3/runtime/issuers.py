"""Authenticated D02 resource and D11 budget/job admission authorities.

The issuers keep signed grants in the same business SQLite transaction.  A
command envelope is only an audit assertion: admission requires an untampered
D02 quote and D11 lease grant whose identities and ceilings match the command.
No function in this module opens, commits, or rolls back a database.
"""

from __future__ import annotations

from dataclasses import dataclass, fields, replace
from datetime import datetime, timezone
import hashlib
import hmac
import json
import math
import re
import sqlite3
import time
from typing import Mapping

from ..graph_coordinator import (
    BudgetAdmission, JobBinding, RuntimeAdmission, ScheduleAdmission,
    budget_operation_digest,
)
from ..graph_types import AtomKey
from ..runtime_contracts import (
    CommandEnvelope, DomainBundle, canonical_digest, canonical_serialize,
)
from .budget import get_budget_lease
from .d11_types import runtime_job_key
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


D03_ARRIVAL_WORK_KIND = "d03.message_received"
D03_SELF_IDENTITY_PROJECTION_WORK_KIND = "d03.self_identity_projection"
D04_BASELINE_WORK_KIND = "d04.encoding_baseline"
D06_FIRST_INGRESS_C02_WORK_KIND = "d06.first_ingress_c02"
_MODEL_COST_DIMENSIONS = frozenset({
    "input_tokens", "output_tokens", "model_tokens", "model_microusd",
})


@dataclass(frozen=True)
class D03ArrivalQuotePolicy:
    """D02-signed installed price, distinct from D11's total grant ceiling."""

    policy_id: str
    bot_id: str
    persona_id: str
    installation_id: str
    grant_id: str
    grant_version: int
    lease_id: str
    provider_policy_ref: str
    quote_ceiling: Mapping[str, int]
    deadline_after_seconds: float
    snapshot_ref: str
    resource_ref: str

    def __post_init__(self) -> None:
        for name in ("policy_id", "bot_id", "persona_id", "installation_id",
                     "grant_id", "lease_id", "provider_policy_ref",
                     "snapshot_ref", "resource_ref"):
            _id(getattr(self, name), name)
        if type(self.grant_version) is not int or self.grant_version < 1:
            raise ValueError("D03 arrival grant version is invalid")
        deadline = _finite(self.deadline_after_seconds, "deadline_after_seconds")
        if deadline <= 0:
            raise ValueError("D03 arrival deadline bound must be positive")
        object.__setattr__(self, "deadline_after_seconds", deadline)
        object.__setattr__(self, "quote_ceiling", _amounts(self.quote_ceiling))


@dataclass(frozen=True)
class D04BaselineQuotePolicy:
    """Signed installed D04 price, separate from D03 and D06 work."""

    policy_id: str
    bot_id: str
    persona_id: str
    installation_id: str
    grant_id: str
    grant_version: int
    lease_id: str
    provider_policy_ref: str
    quote_ceiling: Mapping[str, int]
    deadline_after_seconds: float
    snapshot_ref: str
    resource_ref: str

    def __post_init__(self) -> None:
        for name in ("policy_id", "bot_id", "persona_id", "installation_id",
                     "grant_id", "lease_id", "provider_policy_ref",
                     "snapshot_ref", "resource_ref"):
            _id(getattr(self, name), name)
        if type(self.grant_version) is not int or self.grant_version < 1:
            raise ValueError("D04 baseline grant version is invalid")
        deadline = _finite(self.deadline_after_seconds, "deadline_after_seconds")
        if deadline <= 0:
            raise ValueError("D04 baseline deadline bound must be positive")
        object.__setattr__(self, "deadline_after_seconds", deadline)
        object.__setattr__(self, "quote_ceiling", _amounts(self.quote_ceiling))


@dataclass(frozen=True)
class D03SelfIdentityProjectionQuotePolicy:
    """Signed stage price and exact Authority-qualified mapping candidate."""

    policy_id: str
    bot_id: str
    persona_id: str
    installation_id: str
    grant_id: str
    grant_version: int
    lease_id: str
    provider_policy_ref: str
    quote_ceiling: Mapping[str, int]
    deadline_after_seconds: float
    snapshot_ref: str
    resource_ref: str
    source_ref: str
    arrival_ref: str
    mapping_ref: str
    mapping_revision: int
    perspective_ref: str
    certification_ref: str
    qualified_mapping_digest: str
    activity_id: str
    operation_id: str

    def __post_init__(self) -> None:
        for name in ("policy_id", "bot_id", "persona_id", "installation_id",
                     "grant_id", "lease_id", "provider_policy_ref",
                     "snapshot_ref", "resource_ref", "activity_id", "operation_id"):
            _id(getattr(self, name), name)
        for name in ("source_ref", "arrival_ref", "mapping_ref",
                     "perspective_ref", "certification_ref"):
            _ref(getattr(self, name), name)
        if type(self.grant_version) is not int or self.grant_version < 1:
            raise ValueError("D03 projection grant version is invalid")
        if type(self.mapping_revision) is not int or self.mapping_revision < 0:
            raise ValueError("D03 projection mapping revision is invalid")
        if (type(self.qualified_mapping_digest) is not str
                or re.fullmatch(r"[0-9a-f]{64}", self.qualified_mapping_digest) is None):
            raise ValueError("D03 projection mapping digest is invalid")
        deadline = _finite(self.deadline_after_seconds, "deadline_after_seconds")
        if deadline <= 0:
            raise ValueError("D03 projection deadline bound must be positive")
        object.__setattr__(self, "deadline_after_seconds", deadline)
        object.__setattr__(self, "quote_ceiling", _amounts(self.quote_ceiling))


@dataclass(frozen=True)
class D06FirstIngressC02QuotePolicy:
    """D02 signature binds one independently priced C02 to its original call."""

    policy_id: str
    bot_id: str
    persona_id: str
    installation_id: str
    grant_id: str
    grant_version: int
    lease_id: str
    provider_policy_ref: str
    quote_ceiling: Mapping[str, int]
    deadline_after_seconds: float
    snapshot_ref: str
    resource_ref: str
    job_id: str
    original_activity_id: str
    original_operation_id: str
    acquire_operation_id: str
    original_call_id: str
    binding_digest: str
    model_request_digest: str
    cost_operation_id: str
    cost_receipt_digest: str
    source_ref: str
    baseline_ref: str
    baseline_revision: int
    consumer_operation_id: str

    def __post_init__(self) -> None:
        for name in ("policy_id", "bot_id", "persona_id", "installation_id",
                     "grant_id", "lease_id", "provider_policy_ref",
                     "snapshot_ref", "resource_ref", "job_id",
                     "original_activity_id", "original_operation_id",
                     "acquire_operation_id", "original_call_id",
                     "cost_operation_id", "consumer_operation_id"):
            _id(getattr(self, name), name)
        for name in ("source_ref", "baseline_ref"):
            _ref(getattr(self, name), name)
        for name in ("binding_digest", "model_request_digest", "cost_receipt_digest"):
            digest = getattr(self, name)
            if type(digest) is not str or not re.fullmatch(r"[0-9a-f]{64}", digest):
                raise ValueError(f"D06 C02 {name} must be SHA-256")
        if type(self.grant_version) is not int or self.grant_version < 1:
            raise ValueError("D06 C02 grant version is invalid")
        if type(self.baseline_revision) is not int or self.baseline_revision < 1:
            raise ValueError("D06 C02 baseline revision is invalid")
        deadline = _finite(self.deadline_after_seconds, "deadline_after_seconds")
        if deadline <= 0:
            raise ValueError("D06 C02 deadline bound must be positive")
        ceiling = _amounts(self.quote_ceiling)
        if _MODEL_COST_DIMENSIONS & ceiling.keys():
            raise ValueError("D06 C02 cannot price the original model call again")
        object.__setattr__(self, "deadline_after_seconds", deadline)
        object.__setattr__(self, "quote_ceiling", ceiling)


def _d03_policy_id(installation_id: str, grant: BudgetLeaseGrant) -> str:
    return "d03-policy-" + canonical_digest({
        "installation_id": installation_id,
        "namespace": [grant.bot_id, grant.persona_id],
        "grant_id": grant.grant_id, "grant_version": grant.version,
    })[:40]


def d03_arrival_quote_id(namespace, operation_id: str) -> str:
    """The graph can predeclare the exact D02 guard before its transaction."""
    return "d03-arrival-q-" + canonical_digest({
        "namespace": list(namespace.as_tuple), "operation_id": operation_id,
    })[:40]


def _d03_quote_refs(policy: D03ArrivalQuotePolicy,
                    envelope: CommandEnvelope) -> tuple[str, str]:
    snapshot = "d03snap:" + policy.policy_id + ":" + canonical_digest({
        "policy": _payload(policy),
        "guard": replace(envelope.version_guard, resource_lease_versions=()),
        "identity": envelope.identity,
        "source_qualification": envelope.source_qualification,
    })[:32]
    resource = "d03src:" + canonical_digest({
        "policy_id": policy.policy_id, "resource_ref": policy.resource_ref,
        "input_refs": envelope.input_refs,
    })[:56]
    return snapshot, resource


def _d03_projection_policy_id(installation_id: str, grant: BudgetLeaseGrant,
                              operation_id: str) -> str:
    return "d03-self-policy-" + canonical_digest({
        "installation_id": installation_id,
        "namespace": [grant.bot_id, grant.persona_id],
        "grant_id": grant.grant_id, "grant_version": grant.version,
        "operation_id": operation_id,
    })[:40]


def d03_self_identity_projection_quote_id(namespace, operation_id: str) -> str:
    return "d03-self-q-" + canonical_digest({
        "namespace": list(namespace.as_tuple), "operation_id": operation_id,
    })[:40]


def _d03_projection_quote_refs(policy: D03SelfIdentityProjectionQuotePolicy,
                               envelope: CommandEnvelope) -> tuple[str, str]:
    snapshot = "d03selfsnap:" + policy.policy_id + ":" + canonical_digest({
        "policy": _payload(policy),
        "guard": replace(envelope.version_guard, resource_lease_versions=()),
        "identity": envelope.identity,
        "source_qualification": envelope.source_qualification,
        "input_refs": envelope.input_refs,
    })[:32]
    resource = "d03selfsrc:" + canonical_digest({
        "policy_id": policy.policy_id, "resource_ref": policy.resource_ref,
        "qualified_mapping_digest": policy.qualified_mapping_digest,
        "source_ref": policy.source_ref,
    })[:56]
    return snapshot, resource


def _d03_projection_inputs(envelope: CommandEnvelope):
    from ..domains.d03.self_perspective import self_mapping_key
    from .d03_self_identity_projection_identity import d03_self_identity_projection_activity_id_v1

    identity, authority = envelope.identity, envelope.authority
    if (authority.actor != "host" or authority.issuer_domain != "d11"
            or authority.worker_fence is not None
            or authority.purpose != "context"
            or not {"persona", "event"} <= set(authority.owner_scope)
            or identity.phase != D03_SELF_IDENTITY_PROJECTION_WORK_KIND
            or identity.effect_id is not None
            or len(envelope.input_refs) != 1
            or envelope.source_qualification.source_refs != envelope.input_refs
            or identity.canonical_input_digest != canonical_digest({
                "input_refs": list(envelope.input_refs),
            })):
        raise IssuerAuthorityDenied("D03 projection requires exact host stage identity")
    try:
        source = AtomKey.from_token(envelope.input_refs[0])
        expected_activity = d03_self_identity_projection_activity_id_v1(
            authority.namespace, source.token)
    except (TypeError, ValueError) as exc:
        raise IssuerAuthorityDenied("D03 projection source identity is invalid") from exc
    if (source.owner.kind != "event" or source.name != "record"
            or identity.activity_id != expected_activity):
        raise IssuerAuthorityDenied("D03 projection activity differs from source")
    guarded = {item.key: item.revision for item in envelope.version_guard.read_versions}
    if (len(guarded) != len(envelope.version_guard.read_versions)
            or guarded.get(source, 0) < 1):
        raise IssuerAuthorityDenied("D03 projection source needs a committed guard")
    mapping = self_mapping_key(authority.namespace)
    if mapping not in guarded or guarded[mapping] < 0:
        raise IssuerAuthorityDenied("D03 projection mapping needs a version guard")
    arrival = [item.key for item in envelope.version_guard.read_versions
               if item.key.type_name == "d03.world_event"]
    if len(arrival) != 1 or guarded[arrival[0]] < 1:
        raise IssuerAuthorityDenied("D03 projection needs one committed arrival")
    return source, mapping, arrival[0], guarded


def _d03_projection_retry_operation(
        db, namespace, source_ref: str, certification_ref: str,
        original_ingress_operation_id: str,
        operation_id: str, lease_id: str) -> bool:
    """Accept only a contiguous, locally rejected, unreserved retry chain.

    W01 separately verifies that each old Authority fence has finished before
    appending a lineage row. A graph row alone is not that Authority proof.
    """
    from ..authority_service.v2_contract import FencePermitV2, from_wire
    from .d03_self_identity_projection_identity import (
        d03_self_identity_projection_operation_id_v1,
        d03_self_identity_projection_retry_operation_id_v2,
    )

    base = d03_self_identity_projection_operation_id_v1(
        namespace, source_ref, certification_ref)
    if operation_id == base:
        return True
    try:
        rows = db.execute(
            "SELECT operation_id,previous_operation_id,retry_index,"
            "previous_bundle_digest,previous_attempt_id,previous_rejection_digest "
            "FROM graph_stage_retry_lineage_v1 WHERE bot=? AND persona=? "
            "AND stage=? AND source_ref=? AND original_operation_id=? "
            "ORDER BY retry_index",
            namespace.as_tuple + ("d03",
                                  source_ref, original_ingress_operation_id),
        ).fetchall()
    except sqlite3.Error as exc:
        raise IssuerAuthorityDenied("D03 projection retry lineage is absent") from exc
    if not rows or len(rows) > 64:
        raise IssuerAuthorityDenied("D03 projection retry lineage is incomplete")
    previous = base
    for index, row in enumerate(rows, 1):
        next_id, prior_id, ordinal, prior_digest, attempt_id, rejection_digest = row
        expected = d03_self_identity_projection_retry_operation_id_v2(
            namespace, source_ref, certification_ref, previous, index)
        if (ordinal != index or prior_id != previous or next_id != expected
                or type(prior_digest) is not str
                or type(attempt_id) is not str
                or type(rejection_digest) is not str):
            raise IssuerAuthorityDenied("D03 projection retry chain differs")
        intent = db.execute(
            "SELECT digest,fence_attempt_id,graph_revision,graph_epoch "
            "FROM graph_bundle_intents_v2 WHERE bot=? AND persona=? "
            "AND operation_id=?", namespace.as_tuple + (previous,),
        ).fetchone()
        rejection = db.execute(
            "SELECT digest,status,permit_json,graph_revision,graph_epoch,"
            "finish_request_id,finish_request_digest "
            "FROM graph_bundle_rejections_v2 WHERE bot=? AND persona=? "
            "AND operation_id=?", namespace.as_tuple + (previous,),
        ).fetchone()
        if (intent is None or rejection is None
                or intent[:2] != (prior_digest, attempt_id)
                or rejection[:2] != (prior_digest, "rejected_no_commit")
                or rejection[3:5] != intent[2:4]
                or rejection_digest != canonical_digest(list(rejection))
                or rejection[5] != "abort:" + attempt_id):
            raise IssuerAuthorityDenied("D03 projection prior retry is not durably rejected")
        try:
            permit = from_wire(json.loads(rejection[2]))
        except (TypeError, ValueError, KeyError, json.JSONDecodeError) as exc:
            raise IssuerAuthorityDenied("D03 projection retry permit is invalid") from exc
        if (type(permit) is not FencePermitV2
                or permit.operation != "write" or permit.operation_id != attempt_id
                or rejection[6] != "sha256:" + canonical_digest({
                    "operation_id": attempt_id, "permit_token": permit.token,
                    "action": "rejected_no_commit",
                    "business_operation_id": previous,
                    "bundle_digest": prior_digest,
                })):
            raise IssuerAuthorityDenied("D03 projection retry finish identity differs")
        for table in ("graph_bundle_operations", "graph_bundle_fences_v2"):
            if db.execute(
                    f"SELECT 1 FROM {table} WHERE bot=? AND persona=? "
                    "AND operation_id=?", namespace.as_tuple + (previous,),
            ).fetchone() is not None:
                raise IssuerAuthorityDenied("D03 projection prior attempt committed")
        if (db.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' "
                "AND name='graph_d03_self_projection_issuance_v1'",
        ).fetchone() is not None and db.execute(
                "SELECT 1 FROM graph_d03_self_projection_issuance_v1 "
                "WHERE bot=? AND persona=? AND operation_id=?",
                namespace.as_tuple + (previous,),
        ).fetchone() is not None):
            raise IssuerAuthorityDenied("D03 projection prior issuance survived rollback")
        if db.execute(
                "SELECT 1 FROM runtime_resource_quotes WHERE quote_id=?",
                (d03_self_identity_projection_quote_id(namespace, previous),),
        ).fetchone() is not None:
            raise IssuerAuthorityDenied("D03 projection prior quote survived rollback")
        if (db.execute(
                "SELECT 1 FROM runtime_budget_reservations WHERE lease_id=? "
                "AND operation_id=?", (lease_id, previous),
            ).fetchone() is not None
                or db.execute(
                    "SELECT 1 FROM runtime_budget_operations WHERE bot_id=? "
                    "AND persona_id=? AND operation_id=? AND phase='reserve'",
                    namespace.as_tuple + (previous,),
                ).fetchone() is not None):
            raise IssuerAuthorityDenied("D03 projection prior budget is unresolved")
        previous = next_id
    if operation_id != previous:
        raise IssuerAuthorityDenied("D03 projection retry is not the lineage head")
    current = db.execute(
        "SELECT digest FROM graph_bundle_intents_v2 WHERE bot=? AND persona=? "
        "AND operation_id=?", namespace.as_tuple + (operation_id,),
    ).fetchone()
    stage_head = db.execute(
        "SELECT operation_id,bundle_digest FROM graph_d03_self_projection_intents_v1 "
        "WHERE bot=? AND persona=? AND source_ref=? AND original_operation_id=?",
        namespace.as_tuple + (source_ref, original_ingress_operation_id),
    ).fetchone()
    if current is None or stage_head != (operation_id, current[0]):
        raise IssuerAuthorityDenied("D03 projection retry head lacks current intent")
    for table in ("graph_bundle_operations", "graph_bundle_fences_v2",
                  "graph_bundle_rejections_v2"):
        if db.execute(
                f"SELECT 1 FROM {table} WHERE bot=? AND persona=? AND operation_id=?",
                namespace.as_tuple + (operation_id,),
        ).fetchone() is not None:
            raise IssuerAuthorityDenied("D03 projection retry operation is terminal")
    return True


def _d04_policy_id(installation_id: str, grant: BudgetLeaseGrant) -> str:
    return "d04-baseline-policy-" + canonical_digest({
        "installation_id": installation_id,
        "namespace": [grant.bot_id, grant.persona_id],
        "grant_id": grant.grant_id, "grant_version": grant.version,
    })[:40]


def d04_baseline_quote_id(namespace, operation_id: str) -> str:
    return "d04-baseline-q-" + canonical_digest({
        "namespace": list(namespace.as_tuple), "operation_id": operation_id,
    })[:40]


def _d04_quote_refs(policy: D04BaselineQuotePolicy,
                    envelope: CommandEnvelope) -> tuple[str, str]:
    snapshot = "d04snap:" + policy.policy_id + ":" + canonical_digest({
        "policy": _payload(policy),
        "guard": replace(envelope.version_guard, resource_lease_versions=()),
        "identity": envelope.identity,
        "source_qualification": envelope.source_qualification,
        "input_refs": envelope.input_refs,
    })[:32]
    resource = "d04src:" + canonical_digest({
        "policy_id": policy.policy_id, "resource_ref": policy.resource_ref,
        "input_refs": envelope.input_refs,
    })[:56]
    return snapshot, resource


def _d04_baseline_input_keys(envelope: CommandEnvelope) -> tuple[AtomKey, AtomKey]:
    """Require a committed source and a distinct D03 prerequisite event."""
    identity = envelope.identity
    authority = envelope.authority
    if (authority.actor != "host" or authority.issuer_domain != "d11"
            or authority.worker_fence is not None
            or "event" not in authority.owner_scope
            or identity.phase != "encoding_baseline"
            or identity.effect_id is not None
            or len(envelope.input_refs) != 2
            or envelope.source_qualification.source_refs != envelope.input_refs[:1]
            or identity.canonical_input_digest != canonical_digest({
                "input_refs": list(envelope.input_refs),
            })):
        raise IssuerAuthorityDenied("D04 baseline requires exact host stage identity")
    try:
        source, event = (AtomKey.from_token(ref) for ref in envelope.input_refs)
    except (TypeError, ValueError) as exc:
        raise IssuerAuthorityDenied("D04 baseline input reference is invalid") from exc
    if (source.type_name != "memory.source" or event.type_name != "d03.world_event"
            or source.owner.kind != "event" or event.owner.kind != "event"
            or (source.owner.bot, source.owner.persona)
            != authority.namespace.as_tuple
            or (event.owner.bot, event.owner.persona)
            != authority.namespace.as_tuple):
        raise IssuerAuthorityDenied("D04 baseline lacks same-namespace D03 prerequisite")
    guarded = {item.key: item.revision for item in envelope.version_guard.read_versions}
    if (len(guarded) != len(envelope.version_guard.read_versions)
            or guarded.get(source, 0) < 1 or guarded.get(event, 0) < 1):
        raise IssuerAuthorityDenied("D04 baseline source and event need committed guards")
    return source, event


def _d06_c02_policy_id(installation_id: str, grant: BudgetLeaseGrant,
                       operation_id: str) -> str:
    return "d06-c02-policy-" + canonical_digest({
        "installation_id": installation_id,
        "namespace": [grant.bot_id, grant.persona_id],
        "grant_id": grant.grant_id, "grant_version": grant.version,
        "operation_id": operation_id,
    })[:40]


def d06_first_ingress_c02_quote_id(namespace, operation_id: str) -> str:
    return "d06-c02-q-" + canonical_digest({
        "namespace": list(namespace.as_tuple), "operation_id": operation_id,
    })[:40]


def _d06_c02_quote_refs(policy: D06FirstIngressC02QuotePolicy,
                        envelope: CommandEnvelope) -> tuple[str, str]:
    snapshot = "d06c02snap:" + policy.policy_id + ":" + canonical_digest({
        "policy": _payload(policy),
        "guard": replace(envelope.version_guard, resource_lease_versions=()),
        "identity": envelope.identity,
        "source_qualification": envelope.source_qualification,
        "input_refs": envelope.input_refs,
    })[:32]
    resource = "d06c02src:" + canonical_digest({
        "policy_id": policy.policy_id, "resource_ref": policy.resource_ref,
        "input_refs": envelope.input_refs,
    })[:56]
    return snapshot, resource


def _d06_c02_input_keys(envelope: CommandEnvelope) -> tuple[AtomKey, AtomKey, AtomKey]:
    identity = envelope.identity
    authority = envelope.authority
    if (authority.issuer_domain != "d06" or authority.worker_fence is None
            or "event" not in authority.owner_scope
            or identity.phase != "first_ingress_c02"
            or identity.effect_id is not None
            or len(envelope.input_refs) != 3
            or envelope.source_qualification.source_refs != envelope.input_refs[:1]
            or identity.canonical_input_digest != canonical_digest({
                "input_refs": list(envelope.input_refs),
            })):
        raise IssuerAuthorityDenied("D06 C02 requires exact worker stage identity")
    try:
        source, event, baseline = (
            AtomKey.from_token(ref) for ref in envelope.input_refs
        )
    except (TypeError, ValueError) as exc:
        raise IssuerAuthorityDenied("D06 C02 input reference is invalid") from exc
    namespace = authority.namespace.as_tuple
    if (source.type_name != "memory.source" or source.owner.kind != "event"
            or source.name != "record"
            or event.type_name != "d03.world_event" or event.owner.kind != "event"
            or baseline.type_name != "d04.encoding_baseline.v1"
            or baseline.owner != source.owner
            or any((key.owner.bot, key.owner.persona) != namespace
                   for key in (source, event, baseline))):
        raise IssuerAuthorityDenied("D06 C02 inputs cross source or namespace")
    guarded = {item.key: item.revision for item in envelope.version_guard.read_versions}
    if (len(guarded) != len(envelope.version_guard.read_versions)
            or any(guarded.get(key, 0) < 1 for key in (source, event, baseline))):
        raise IssuerAuthorityDenied("D06 C02 input refs need committed guards")
    return source, event, baseline


@dataclass(frozen=True)
class _D06C02Origin:
    job_id: str
    activity_id: str
    operation_id: str
    acquire_operation_id: str
    call_id: str
    binding_digest: str
    model_request_digest: str
    cost_operation_id: str
    cost_receipt_digest: str
    source_ref: str
    consumer_operation_id: str
    installation_id: str


def _d06_c02_origin(db, envelope: CommandEnvelope, job_id: str,
                    d02_issuer: "D02ResourceIssuer", *, now_utc: float) -> _D06C02Origin:
    """Read original committed identities; this is no Authority result grant."""
    from ..memory_types import access_key
    from .encoding_call_binding import binding_to_json, load_binding
    from .first_ingress_c02_identity import first_ingress_c02_consumer_operation_id_v1
    from .model_cost_settlement import OriginalModelCostCommitV1

    source, event, baseline = _d06_c02_input_keys(envelope)
    namespace = envelope.authority.namespace
    try:
        job = get_job(db, job_id)
        binding = load_binding(db, namespace, job_id)
        if binding is None:
            raise IssuerAuthorityDenied("D06 C02 original call binding is absent")
        acquire_id = binding.request["acquire_operation_id"]
        acquire = db.execute(
            "SELECT i.job_id,i.original_operation_id,i.actor,i.encoding_binding_json,"
            "i.requirements_json,r.job_json FROM graph_job_acquire_intents_v2 AS i "
            "JOIN graph_job_acquire_receipts_v2 AS r "
            "ON r.bot=i.bot AND r.persona=i.persona "
            "AND r.acquire_operation_id=i.acquire_operation_id "
            "WHERE i.bot=? AND i.persona=? AND i.acquire_operation_id=?",
            namespace.as_tuple + (acquire_id,),
        ).fetchone()
        metadata = db.execute(
            "SELECT requirements_json FROM graph_recovery_metadata_v2 "
            "WHERE bot=? AND persona=?", namespace.as_tuple,
        ).fetchone()
        provision = db.execute(
            "SELECT receipt_json FROM graph_namespace_provisioning_v2 "
            "WHERE bot=? AND persona=?", namespace.as_tuple,
        ).fetchone()
        original_quote_ref = job.operator_versions["resource_quote"]
        original_quote_id, version_text = original_quote_ref.rsplit(":", 1)
        original_quote_version = int(version_text)
        original_quote = d02_issuer.original_signed_quote(
            db, original_quote_id, original_quote_version)
        lease_expires = datetime.fromisoformat(
            job.lease_expires_utc.replace("Z", "+00:00"))
    except (KeyError, ValueError, TypeError, IndexError, AttributeError) as exc:
        raise IssuerAuthorityDenied("D06 C02 original identity is incomplete") from exc
    if (acquire is None or metadata is None or provision is None
            or job.work_kind != "d06.encode_source" or job.phase != "running"
            or job.cancel_epoch != 0 or job.fence < 1
            or lease_expires.tzinfo is None
            or lease_expires.timestamp() <= now_utc
            or (job.bot_id, job.persona_id) != namespace.as_tuple
            or job.activity_id != envelope.identity.activity_id
            or job.operation_id != binding.budget_reservation_operation_id
            or job.budget_ref != binding.budget_lease_id
            or envelope.parent_budget_lease_ref != job.budget_ref
            or job.lease_holder != envelope.authority.actor
            or job.fence != envelope.authority.worker_fence
            or binding.source_id != source.owner.subject
            or (original_quote.bot_id, original_quote.persona_id,
                original_quote.activity_id, original_quote.operation_id,
                original_quote.parent_budget_lease_ref, original_quote.work_kind)
            != (*namespace.as_tuple, job.activity_id, job.operation_id,
                job.budget_ref, "d06.encode_source")
            or acquire[:4] != (job_id, job.operation_id,
                               job.lease_holder, binding_to_json(binding))):
        raise IssuerAuthorityDenied("D06 C02 differs from current original job")
    try:
        frozen_job = json.loads(acquire[5])
        historical_requirements = json.loads(acquire[4])
        requirements = json.loads(metadata[0])
        genesis = json.loads(provision[0])
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise IssuerAuthorityDenied("D06 C02 original graph identity is invalid") from exc
    if (type(frozen_job) is not dict or type(historical_requirements) is not dict
            or type(requirements) is not dict or type(genesis) is not dict
            or frozen_job.get("job_id") != job_id
            or frozen_job.get("fence") != job.fence
            or frozen_job.get("lease_holder") != job.lease_holder
            or frozen_job.get("lease_expires_utc") != job.lease_expires_utc
            or historical_requirements.get("graph_incarnation")
            != requirements.get("graph_incarnation")
            or genesis.get("graph_incarnation") != requirements.get("graph_incarnation")
            or genesis.get("authority_id") != requirements.get("authority_id")
            or genesis.get("authority_namespace")
            != requirements.get("authority_namespace")
            or genesis.get("namespace") != {
                "bot_id": namespace.bot_id, "persona_id": namespace.persona_id,
            }):
        raise IssuerAuthorityDenied("D06 C02 original acquire or installation differs")
    if db.execute(
            "SELECT 1 FROM runtime_encoding_call_redactions_v1 "
            "WHERE bot=? AND persona=? AND (call_id=? OR source_id=?)",
            namespace.as_tuple + (binding.call_id, binding.source_id),
    ).fetchone() is not None:
        raise IssuerAuthorityDenied("D06 C02 original call has been redacted")
    source_row = db.execute(
        "SELECT revision,valid FROM graph_atoms WHERE token=?", (source.token,),
    ).fetchone()
    access = access_key(*namespace.as_tuple, binding.source_id)
    access_row = db.execute(
        "SELECT revision,valid FROM graph_atoms WHERE token=?", (access.token,),
    ).fetchone()
    event_row = db.execute(
        "SELECT revision,valid,value FROM graph_atoms WHERE token=?", (event.token,),
    ).fetchone()
    baseline_row = db.execute(
        "SELECT revision,valid,value FROM graph_atoms WHERE token=?", (baseline.token,),
    ).fetchone()
    guarded = {item.key: item.revision for item in envelope.version_guard.read_versions}
    if (source_row != (binding.source_revision, 1)
            or access_row != (binding.access_revision, 1)
            or guarded.get(source) != binding.source_revision
            or guarded.get(access) != binding.access_revision
            or event_row is None or event_row[:2] != (guarded[event], 1)
            or baseline_row is None or baseline_row[:2] != (guarded[baseline], 1)):
        raise IssuerAuthorityDenied("D06 C02 source, access or baseline is stale")
    try:
        event_value = json.loads(event_row[2])
        baseline_value = json.loads(baseline_row[2])
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise IssuerAuthorityDenied("D06 C02 D03/D04 evidence is invalid") from exc
    if (type(event_value) is not dict or type(baseline_value) is not dict
            or event_value.get("event_id") != event.owner.subject
            or event_value.get("kind") != "message_received"
            or event_value.get("reality") != "host_observed"
            or event_value.get("source_refs") != [source.token]
            or baseline_value.get("baseline_id") != baseline.name
            or baseline_value.get("source_refs") != [source.token]):
        raise IssuerAuthorityDenied("D06 C02 D03/D04 evidence differs from source")
    cost_operation_id = "model-cost-" + canonical_digest({
        "namespace": list(namespace.as_tuple), "call_id": binding.call_id,
    })[:48]
    cost_row = db.execute(
        "SELECT activity_id,commit_seq,receipt_json FROM graph_bundle_operations "
        "WHERE bot=? AND persona=? AND operation_id=?",
        namespace.as_tuple + (cost_operation_id,),
    ).fetchone()
    if cost_row is None or cost_row[0] != job.activity_id:
        raise IssuerAuthorityDenied("D06 C02 original model cost receipt is absent")
    try:
        cost_data = json.loads(cost_row[2])
        if type(cost_data) is not dict:
            raise ValueError("model cost receipt must be an object")
        cost = OriginalModelCostCommitV1(**cost_data["original_model_cost"])
    except (TypeError, ValueError, KeyError, json.JSONDecodeError) as exc:
        raise IssuerAuthorityDenied("D06 C02 original model cost receipt is invalid") from exc
    cost_atom = db.execute(
        "SELECT valid FROM graph_atoms WHERE token=?", (cost.cost_ref,),
    ).fetchone()
    settled = db.execute(
        "SELECT state FROM runtime_budget_reservations "
        "WHERE lease_id=? AND operation_id=?",
        (job.budget_ref, job.operation_id),
    ).fetchone()
    settle_op = db.execute(
        "SELECT 1 FROM runtime_budget_operations WHERE bot_id=? AND persona_id=? "
        "AND operation_id=? AND phase='settle'",
        namespace.as_tuple + (job.operation_id,),
    ).fetchone()
    if (cost.status != "committed" or cost.operation_id != cost_operation_id
            or cost.call_id != binding.call_id
            or (cost.quote_id, cost.quote_version)
            != (original_quote_id, original_quote_version)
            or cost.commit_seq != cost_row[1]
            or cost_atom != (1,) or settled != ("settled",)
            or settle_op is None):
        raise IssuerAuthorityDenied("D06 C02 original model cost is not fully settled")
    consumer = first_ingress_c02_consumer_operation_id_v1(
        namespace=namespace,
        authority_id=requirements["authority_id"],
        authority_namespace=requirements["authority_namespace"],
        installation_id=genesis["installation_id"],
        job_id=job_id, acquire_operation_id=acquire_id,
        original_operation_id=job.operation_id, call_id=binding.call_id,
        binding_digest=binding.binding_digest,
        model_request_digest=binding.model_request_digest,
    )
    return _D06C02Origin(
        job_id, job.activity_id, job.operation_id, acquire_id,
        binding.call_id, binding.binding_digest, binding.model_request_digest,
        cost_operation_id, canonical_digest(cost_data), source.token,
        consumer, genesis["installation_id"],
    )


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


def _decode_d03_policy(payload: str) -> D03ArrivalQuotePolicy:
    return D03ArrivalQuotePolicy(**json.loads(payload))


def _decode_d04_policy(payload: str) -> D04BaselineQuotePolicy:
    return D04BaselineQuotePolicy(**json.loads(payload))


def _decode_d03_projection_policy(payload: str) -> D03SelfIdentityProjectionQuotePolicy:
    return D03SelfIdentityProjectionQuotePolicy(**json.loads(payload))


def _decode_d06_c02_policy(payload: str) -> D06FirstIngressC02QuotePolicy:
    return D06FirstIngressC02QuotePolicy(**json.loads(payload))


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
    db.execute("""
        CREATE TABLE IF NOT EXISTS runtime_d03_arrival_quote_policies(
            policy_id TEXT PRIMARY KEY,
            policy_json TEXT NOT NULL,
            signature TEXT NOT NULL,
            status TEXT NOT NULL
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS runtime_d04_baseline_quote_policies(
            policy_id TEXT PRIMARY KEY,
            policy_json TEXT NOT NULL,
            signature TEXT NOT NULL,
            status TEXT NOT NULL
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS runtime_d03_self_projection_quote_policies(
            policy_id TEXT PRIMARY KEY,
            policy_json TEXT NOT NULL,
            signature TEXT NOT NULL,
            status TEXT NOT NULL
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS runtime_d06_c02_quote_policies(
            policy_id TEXT PRIMARY KEY,
            policy_json TEXT NOT NULL,
            signature TEXT NOT NULL,
            status TEXT NOT NULL
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

    def _install_d03_arrival_policy(self, db, policy: D03ArrivalQuotePolicy) -> str:
        """Sign once within the caller's business transaction; replay is exact."""
        payload = canonical_serialize(_payload(policy))
        signature = self._signer.sign("d03-arrival-policy.v1", payload)
        row = db.execute(
            "SELECT policy_json,signature,status FROM runtime_d03_arrival_quote_policies "
            "WHERE policy_id=?", (policy.policy_id,),
        ).fetchone()
        if row is not None:
            self._signer.verify("d03-arrival-policy.v1", row[0], row[1])
            if row != (payload, signature, "active"):
                raise IssuerAuthorityDenied("D03 arrival policy replay differs")
            return signature
        db.execute(
            "INSERT INTO runtime_d03_arrival_quote_policies"
            "(policy_id,policy_json,signature,status) VALUES(?,?,?,'active')",
            (policy.policy_id, payload, signature),
        )
        return signature

    def _load_d03_arrival_policy(self, db, policy_id: str) -> D03ArrivalQuotePolicy:
        row = db.execute(
            "SELECT policy_json,signature,status FROM runtime_d03_arrival_quote_policies "
            "WHERE policy_id=?", (policy_id,),
        ).fetchone()
        if row is None or row[2] != "active":
            raise IssuerAuthorityDenied("active signed D03 arrival policy is absent")
        self._signer.verify("d03-arrival-policy.v1", row[0], row[1])
        try:
            policy = _decode_d03_policy(row[0])
        except (TypeError, ValueError, KeyError, json.JSONDecodeError) as exc:
            raise IssuerAuthorityDenied("signed D03 arrival policy is invalid") from exc
        if policy.policy_id != policy_id:
            raise IssuerAuthorityDenied("signed D03 arrival policy identity differs")
        return policy

    def _issue_bound_stage_quote(self, db, quote: ResourceQuote) -> str:
        """Idempotent signed quote for a policy-checked stage issuer."""
        row = db.execute(
            "SELECT quote_json,signature,status FROM runtime_resource_quotes "
            "WHERE quote_id=? AND version=?", (quote.quote_id, quote.version),
        ).fetchone()
        if row is not None:
            self._signer.verify("resource-quote.v1", row[0], row[1])
            if row[2] != "active" or _decode_quote(row[0]) != quote:
                raise IssuerAuthorityDenied("signed stage quote replay differs")
            return row[1]
        return self.issue_quote(db, quote)

    def _qualified_d03_arrival_policy(self, db, envelope: CommandEnvelope,
                                      quote: ResourceQuote,
                                      grant: BudgetLeaseGrant) -> D03ArrivalQuotePolicy:
        parts = quote.snapshot_ref.split(":")
        if len(parts) != 3 or parts[0] != "d03snap":
            raise IssuerAuthorityDenied("D03 arrival quote lacks policy binding")
        policy = self._load_d03_arrival_policy(db, parts[1])
        snapshot_ref, resource_ref = _d03_quote_refs(policy, envelope)
        if (policy.policy_id != _d03_policy_id(policy.installation_id, grant)
                or (policy.bot_id, policy.persona_id)
                != envelope.authority.namespace.as_tuple
                or (policy.grant_id, policy.grant_version, policy.lease_id,
                    policy.provider_policy_ref) != (
                    grant.grant_id, grant.version, grant.lease_id, grant.policy_ref)
                or quote.snapshot_ref != snapshot_ref
                or quote.resource_ref != resource_ref
                or dict(quote.ceiling) != dict(policy.quote_ceiling)):
            raise IssuerAuthorityDenied("D03 arrival quote differs from signed policy")
        return policy

    def _install_d03_projection_policy(
            self, db, policy: D03SelfIdentityProjectionQuotePolicy) -> str:
        payload = canonical_serialize(_payload(policy))
        signature = self._signer.sign("d03-self-projection-policy.v1", payload)
        row = db.execute(
            "SELECT policy_json,signature,status FROM runtime_d03_self_projection_quote_policies "
            "WHERE policy_id=?", (policy.policy_id,),
        ).fetchone()
        if row is not None:
            self._signer.verify("d03-self-projection-policy.v1", row[0], row[1])
            if row != (payload, signature, "active"):
                raise IssuerAuthorityDenied("D03 projection policy replay differs")
            return signature
        db.execute(
            "INSERT INTO runtime_d03_self_projection_quote_policies"
            "(policy_id,policy_json,signature,status) VALUES(?,?,?,'active')",
            (policy.policy_id, payload, signature),
        )
        return signature

    def _load_d03_projection_policy(
            self, db, policy_id: str) -> D03SelfIdentityProjectionQuotePolicy:
        row = db.execute(
            "SELECT policy_json,signature,status FROM runtime_d03_self_projection_quote_policies "
            "WHERE policy_id=?", (policy_id,),
        ).fetchone()
        if row is None or row[2] != "active":
            raise IssuerAuthorityDenied("active signed D03 projection policy is absent")
        self._signer.verify("d03-self-projection-policy.v1", row[0], row[1])
        try:
            policy = _decode_d03_projection_policy(row[0])
        except (TypeError, ValueError, KeyError, json.JSONDecodeError) as exc:
            raise IssuerAuthorityDenied("signed D03 projection policy is invalid") from exc
        if policy.policy_id != policy_id:
            raise IssuerAuthorityDenied("signed D03 projection policy identity differs")
        return policy

    def _qualified_d03_projection_policy(
            self, db, envelope: CommandEnvelope, quote: ResourceQuote,
            grant: BudgetLeaseGrant) -> D03SelfIdentityProjectionQuotePolicy:
        parts = quote.snapshot_ref.split(":")
        if len(parts) != 3 or parts[0] != "d03selfsnap":
            raise IssuerAuthorityDenied("D03 projection quote lacks policy binding")
        policy = self._load_d03_projection_policy(db, parts[1])
        snapshot_ref, resource_ref = _d03_projection_quote_refs(policy, envelope)
        if (policy.policy_id != _d03_projection_policy_id(
                    policy.installation_id, grant, envelope.identity.operation_id)
                or (policy.bot_id, policy.persona_id)
                != envelope.authority.namespace.as_tuple
                or (policy.grant_id, policy.grant_version, policy.lease_id,
                    policy.provider_policy_ref) != (
                    grant.grant_id, grant.version, grant.lease_id, grant.policy_ref)
                or quote.snapshot_ref != snapshot_ref
                or quote.resource_ref != resource_ref
                or quote.quote_id != d03_self_identity_projection_quote_id(
                    envelope.authority.namespace, envelope.identity.operation_id)
                or (quote.activity_id, quote.operation_id, quote.effect_id)
                != (policy.activity_id, policy.operation_id, None)
                or quote.graph_job_ref is not None or quote.outbox_refs
                or quote.d02_settlement_refs
                or dict(quote.ceiling) != dict(policy.quote_ceiling)):
            raise IssuerAuthorityDenied("D03 projection quote differs from signed policy")
        return policy

    def _install_d04_baseline_policy(self, db, policy: D04BaselineQuotePolicy) -> str:
        payload = canonical_serialize(_payload(policy))
        signature = self._signer.sign("d04-baseline-policy.v1", payload)
        row = db.execute(
            "SELECT policy_json,signature,status FROM runtime_d04_baseline_quote_policies "
            "WHERE policy_id=?", (policy.policy_id,),
        ).fetchone()
        if row is not None:
            self._signer.verify("d04-baseline-policy.v1", row[0], row[1])
            if row != (payload, signature, "active"):
                raise IssuerAuthorityDenied("D04 baseline policy replay differs")
            return signature
        db.execute(
            "INSERT INTO runtime_d04_baseline_quote_policies"
            "(policy_id,policy_json,signature,status) VALUES(?,?,?,'active')",
            (policy.policy_id, payload, signature),
        )
        return signature

    def _load_d04_baseline_policy(self, db, policy_id: str) -> D04BaselineQuotePolicy:
        row = db.execute(
            "SELECT policy_json,signature,status FROM runtime_d04_baseline_quote_policies "
            "WHERE policy_id=?", (policy_id,),
        ).fetchone()
        if row is None or row[2] != "active":
            raise IssuerAuthorityDenied("active signed D04 baseline policy is absent")
        self._signer.verify("d04-baseline-policy.v1", row[0], row[1])
        try:
            policy = _decode_d04_policy(row[0])
        except (TypeError, ValueError, KeyError, json.JSONDecodeError) as exc:
            raise IssuerAuthorityDenied("signed D04 baseline policy is invalid") from exc
        if policy.policy_id != policy_id:
            raise IssuerAuthorityDenied("signed D04 baseline policy identity differs")
        return policy

    def _qualified_d04_baseline_policy(self, db, envelope: CommandEnvelope,
                                       quote: ResourceQuote,
                                       grant: BudgetLeaseGrant) -> D04BaselineQuotePolicy:
        parts = quote.snapshot_ref.split(":")
        if len(parts) != 3 or parts[0] != "d04snap":
            raise IssuerAuthorityDenied("D04 baseline quote lacks policy binding")
        policy = self._load_d04_baseline_policy(db, parts[1])
        snapshot_ref, resource_ref = _d04_quote_refs(policy, envelope)
        if (policy.policy_id != _d04_policy_id(policy.installation_id, grant)
                or (policy.bot_id, policy.persona_id)
                != envelope.authority.namespace.as_tuple
                or (policy.grant_id, policy.grant_version, policy.lease_id,
                    policy.provider_policy_ref) != (
                    grant.grant_id, grant.version, grant.lease_id, grant.policy_ref)
                or quote.snapshot_ref != snapshot_ref
                or quote.resource_ref != resource_ref
                or quote.quote_id != d04_baseline_quote_id(
                    envelope.authority.namespace, envelope.identity.operation_id)
                or dict(quote.ceiling) != dict(policy.quote_ceiling)):
            raise IssuerAuthorityDenied("D04 baseline quote differs from signed policy")
        return policy

    def _install_d06_c02_policy(self, db, policy: D06FirstIngressC02QuotePolicy) -> str:
        payload = canonical_serialize(_payload(policy))
        signature = self._signer.sign("d06-first-ingress-c02-policy.v1", payload)
        row = db.execute(
            "SELECT policy_json,signature,status FROM runtime_d06_c02_quote_policies "
            "WHERE policy_id=?", (policy.policy_id,),
        ).fetchone()
        if row is not None:
            self._signer.verify("d06-first-ingress-c02-policy.v1", row[0], row[1])
            if row != (payload, signature, "active"):
                raise IssuerAuthorityDenied("D06 C02 policy replay differs")
            return signature
        db.execute(
            "INSERT INTO runtime_d06_c02_quote_policies"
            "(policy_id,policy_json,signature,status) VALUES(?,?,?,'active')",
            (policy.policy_id, payload, signature),
        )
        return signature

    def _load_d06_c02_policy(self, db, policy_id: str) -> D06FirstIngressC02QuotePolicy:
        row = db.execute(
            "SELECT policy_json,signature,status FROM runtime_d06_c02_quote_policies "
            "WHERE policy_id=?", (policy_id,),
        ).fetchone()
        if row is None or row[2] != "active":
            raise IssuerAuthorityDenied("active signed D06 C02 policy is absent")
        self._signer.verify("d06-first-ingress-c02-policy.v1", row[0], row[1])
        try:
            policy = _decode_d06_c02_policy(row[0])
        except (TypeError, ValueError, KeyError, json.JSONDecodeError) as exc:
            raise IssuerAuthorityDenied("signed D06 C02 policy is invalid") from exc
        if policy.policy_id != policy_id:
            raise IssuerAuthorityDenied("signed D06 C02 policy identity differs")
        return policy

    def _qualified_d06_c02_policy(self, db, envelope: CommandEnvelope,
                                  quote: ResourceQuote,
                                  grant: BudgetLeaseGrant) -> D06FirstIngressC02QuotePolicy:
        parts = quote.snapshot_ref.split(":")
        if len(parts) != 3 or parts[0] != "d06c02snap":
            raise IssuerAuthorityDenied("D06 C02 quote lacks policy binding")
        policy = self._load_d06_c02_policy(db, parts[1])
        snapshot_ref, resource_ref = _d06_c02_quote_refs(policy, envelope)
        if (policy.policy_id != _d06_c02_policy_id(
                    policy.installation_id, grant, envelope.identity.operation_id)
                or (policy.bot_id, policy.persona_id)
                != envelope.authority.namespace.as_tuple
                or (policy.grant_id, policy.grant_version, policy.lease_id,
                    policy.provider_policy_ref) != (
                    grant.grant_id, grant.version, grant.lease_id, grant.policy_ref)
                or quote.snapshot_ref != snapshot_ref
                or quote.resource_ref != resource_ref
                or quote.quote_id != d06_first_ingress_c02_quote_id(
                    envelope.authority.namespace, envelope.identity.operation_id)
                or quote.activity_id != policy.original_activity_id
                or quote.operation_id != policy.consumer_operation_id
                or quote.graph_job_ref is not None or quote.outbox_refs
                or quote.d02_settlement_refs
                or dict(quote.ceiling) != dict(policy.quote_ceiling)):
            raise IssuerAuthorityDenied("D06 C02 quote differs from signed policy")
        return policy

    def issue_outcome(self, db, outcome: ResourceOutcome) -> str:
        if not isinstance(outcome, ResourceOutcome):
            raise TypeError("outcome must be ResourceOutcome")
        quote = self._load_quote(db, outcome.quote_id, None)
        if ((outcome.bot_id, outcome.persona_id) != (quote.bot_id, quote.persona_id)
                or outcome.activity_id != quote.activity_id
                or outcome.operation_id != quote.operation_id):
            raise IssuerAuthorityDenied("outcome identity differs from its quote")
        if outcome.actual is not None:
            if any(outcome.actual.get(name, 0) < amount
                   for name, amount in quote.ceiling.items()) and not outcome.execution_revoked:
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

    def original_signed_quote(self, db, quote_id: str, version: int) -> ResourceQuote:
        """Read original signed accounting bounds after expiry or revocation.

        This historical read authorizes no new work or budget reservation.
        The caller must independently join the original job, Authority call,
        and durable budget reservation before recording a cost.
        """
        row = db.execute(
            "SELECT quote_json,signature FROM runtime_resource_quotes "
            "WHERE quote_id=? AND version=?", (quote_id, version),
        ).fetchone()
        if row is None:
            raise IssuerAuthorityDenied("original signed D02 quote is absent")
        self._signer.verify("resource-quote.v1", row[0], row[1])
        try:
            quote = _decode_quote(row[0])
        except (TypeError, ValueError, KeyError, json.JSONDecodeError) as exc:
            raise IssuerAuthorityDenied("original signed D02 quote is invalid") from exc
        if (quote.quote_id, quote.version) != (quote_id, version):
            raise IssuerAuthorityDenied("original signed D02 quote identity differs")
        return quote

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

    def issue_d03_arrival_quote(self, db, envelope: CommandEnvelope,
                                admin_policy, *, installation_id: str,
                                now_utc: float | None = None) -> ResourceQuote:
        """Sign an arrival price and quote in the caller's existing transaction.

        The caller must supply the OS-verified administrator profile and must
        independently prove D06 source and D03 scene in this graph snapshot.
        This method never commits, reserves, or asserts a cost settlement.
        """
        from ..host.authority_profile import AdminD03ArrivalPolicy

        if type(admin_policy) is not AdminD03ArrivalPolicy:
            raise IssuerAuthorityDenied("installed D03 arrival policy is required")
        if not isinstance(envelope, CommandEnvelope):
            raise TypeError("envelope must be CommandEnvelope")
        _id(installation_id, "installation_id")
        now = _now_utc(now_utc)
        identity = envelope.identity
        authority = envelope.authority
        if (authority.actor != "host" or authority.issuer_domain != "d11"
                or authority.worker_fence is not None
                or identity.phase != "arrival"
                or envelope.version_guard.resource_lease_versions
                or len(envelope.input_refs) != 1
                or envelope.source_qualification.source_refs != envelope.input_refs):
            raise IssuerAuthorityDenied("D03 arrival quote requires exact host input identity")
        try:
            source = AtomKey.from_token(envelope.input_refs[0])
        except (TypeError, ValueError) as exc:
            raise IssuerAuthorityDenied("D03 arrival source reference is invalid") from exc
        if (source.type_name != "memory.source"
                or (source.owner.bot, source.owner.persona)
                != authority.namespace.as_tuple):
            raise IssuerAuthorityDenied("D03 arrival source crosses namespace")
        grant = self._load_grant(db, envelope.parent_budget_lease_ref)
        lease = get_budget_lease(db, grant.lease_id)
        if (D03_ARRIVAL_WORK_KIND not in grant.allowed_work_kinds
                or (grant.bot_id, grant.persona_id) != authority.namespace.as_tuple
                or (lease.bot_id, lease.persona_id, lease.currency)
                != (grant.bot_id, grant.persona_id, grant.currency)
                or lease.state != "active"
                or grant.policy_ref != authority.provider_policy_ref
                or grant.valid_until_utc <= now
                or not now < envelope.deadline_utc <= min(
                    now + admin_policy.deadline_after_seconds,
                    grant.valid_until_utc)):
            raise IssuerAuthorityDenied("D03 arrival lacks current signed grant or deadline")
        if any(amount > grant.max_ceiling.get(name, 0)
               for name, amount in admin_policy.quote_ceiling.items()):
            raise IssuerAuthorityDenied("D03 arrival quote exceeds signed grant")
        policy = D03ArrivalQuotePolicy(
            _d03_policy_id(installation_id, grant), *authority.namespace.as_tuple,
            installation_id, grant.grant_id, grant.version, grant.lease_id,
            grant.policy_ref, dict(admin_policy.quote_ceiling),
            admin_policy.deadline_after_seconds, admin_policy.snapshot_ref,
            admin_policy.resource_ref,
        )
        snapshot_ref, resource_ref = _d03_quote_refs(policy, envelope)
        quote_id = d03_arrival_quote_id(authority.namespace, identity.operation_id)
        quote = ResourceQuote(
            quote_id, 1, *authority.namespace.as_tuple, identity.activity_id,
            identity.operation_id, identity.effect_id, grant.lease_id,
            D03_ARRIVAL_WORK_KIND, snapshot_ref, envelope.deadline_utc,
            resource_ref, None, (), (), dict(policy.quote_ceiling),
            authority.worker_fence, envelope.deadline_utc,
        )
        install_schema(db)
        existing = db.execute(
            "SELECT 1 FROM runtime_resource_quotes WHERE quote_id=? AND version=1",
            (quote.quote_id,),
        ).fetchone()
        if existing is None and any(
                amount > lease.limits.get(name, 0) - lease.used.get(name, 0)
                - lease.reserved.get(name, 0) - lease.unconfirmed.get(name, 0)
                for name, amount in policy.quote_ceiling.items()):
            raise IssuerAuthorityDenied("D03 arrival budget has insufficient capacity")
        self._d02._install_d03_arrival_policy(db, policy)
        self._d02._issue_bound_stage_quote(db, quote)
        return quote

    def issue_d04_baseline_quote(self, db, envelope: CommandEnvelope,
                                 admin_policy, *, installation_id: str,
                                 now_utc: float | None = None) -> ResourceQuote:
        """Issue only a separately installed D04 price in the caller transaction.

        The stage coordinator must still prove current graph reads and commit
        its own operation/reservation; this method supplies no such receipt.
        """
        from ..host.authority_profile import AdminD04EncodingBaselinePolicy

        if type(admin_policy) is not AdminD04EncodingBaselinePolicy:
            raise IssuerAuthorityDenied("installed D04 baseline policy is required")
        if not isinstance(envelope, CommandEnvelope):
            raise TypeError("envelope must be CommandEnvelope")
        _id(installation_id, "installation_id")
        if envelope.version_guard.resource_lease_versions:
            raise IssuerAuthorityDenied("D04 baseline quote request has prior resource refs")
        source, event = _d04_baseline_input_keys(envelope)
        now = _now_utc(now_utc)
        grant = self._load_grant(db, envelope.parent_budget_lease_ref)
        lease = get_budget_lease(db, grant.lease_id)
        authority = envelope.authority
        if (D04_BASELINE_WORK_KIND not in grant.allowed_work_kinds
                or (grant.bot_id, grant.persona_id) != authority.namespace.as_tuple
                or (lease.bot_id, lease.persona_id, lease.currency)
                != (grant.bot_id, grant.persona_id, grant.currency)
                or lease.state != "active"
                or grant.policy_ref != authority.provider_policy_ref
                or grant.valid_until_utc <= now
                or not now < envelope.deadline_utc <= min(
                    now + admin_policy.deadline_after_seconds,
                    grant.valid_until_utc)):
            raise IssuerAuthorityDenied("D04 baseline lacks current signed grant or deadline")
        if any(amount > grant.max_ceiling.get(name, 0)
               for name, amount in admin_policy.quote_ceiling.items()):
            raise IssuerAuthorityDenied("D04 baseline quote exceeds signed grant")
        for key in (source, event):
            row = db.execute(
                "SELECT revision,valid,value FROM graph_atoms WHERE token=?", (key.token,),
            ).fetchone()
            guarded = next(item.revision for item in
                           envelope.version_guard.read_versions if item.key == key)
            if row is None or row[:2] != (guarded, 1):
                raise IssuerAuthorityDenied("D04 baseline prerequisite is not current")
            if key == event:
                try:
                    fact = json.loads(row[2])
                except (TypeError, ValueError, json.JSONDecodeError) as exc:
                    raise IssuerAuthorityDenied("D04 prerequisite event is invalid") from exc
                if (type(fact) is not dict
                        or fact.get("event_id") != event.owner.subject
                        or fact.get("kind") != "message_received"
                        or fact.get("reality") != "host_observed"
                        or fact.get("source_refs") != [source.token]
                        or fact.get("learned_at")
                        != envelope.source_qualification.learned_at):
                    raise IssuerAuthorityDenied("D04 prerequisite does not bind this source")
        policy = D04BaselineQuotePolicy(
            _d04_policy_id(installation_id, grant), *authority.namespace.as_tuple,
            installation_id, grant.grant_id, grant.version, grant.lease_id,
            grant.policy_ref, dict(admin_policy.quote_ceiling),
            admin_policy.deadline_after_seconds, admin_policy.snapshot_ref,
            admin_policy.resource_ref,
        )
        snapshot_ref, resource_ref = _d04_quote_refs(policy, envelope)
        quote = ResourceQuote(
            d04_baseline_quote_id(authority.namespace, envelope.identity.operation_id),
            1, *authority.namespace.as_tuple, envelope.identity.activity_id,
            envelope.identity.operation_id, None, grant.lease_id,
            D04_BASELINE_WORK_KIND, snapshot_ref, envelope.deadline_utc,
            resource_ref, None, (), (), dict(policy.quote_ceiling), None,
            envelope.deadline_utc,
        )
        install_schema(db)
        existing = db.execute(
            "SELECT 1 FROM runtime_resource_quotes WHERE quote_id=? AND version=1",
            (quote.quote_id,),
        ).fetchone()
        if existing is None and any(
                amount > lease.limits.get(name, 0) - lease.used.get(name, 0)
                - lease.reserved.get(name, 0) - lease.unconfirmed.get(name, 0)
                for name, amount in policy.quote_ceiling.items()):
            raise IssuerAuthorityDenied("D04 baseline budget has insufficient capacity")
        self._d02._install_d04_baseline_policy(db, policy)
        self._d02._issue_bound_stage_quote(db, quote)
        return quote

    def issue_d03_self_identity_projection_quote(
            self, db, envelope: CommandEnvelope, admin_policy, *,
            installation_id: str, qualified_mapping,
            now_utc: float | None = None) -> ResourceQuote:
        """Price one mapping plus perspective stage, without certifying identity."""
        from ..domains.d03.self_perspective import (
            SelfIdentityMapping, self_perspective_id, self_perspective_key,
        )
        from ..host.authority_profile import AdminD03SelfIdentityProjectionPolicy
        from ..memory_types import access_key
        from .d03_self_identity_projection_identity import (
            d03_self_identity_projection_operation_id_v1,
        )

        if type(admin_policy) is not AdminD03SelfIdentityProjectionPolicy:
            raise IssuerAuthorityDenied("installed D03 projection policy is required")
        if type(qualified_mapping) is not SelfIdentityMapping:
            raise IssuerAuthorityDenied("Authority-qualified D03 mapping is required")
        if not isinstance(envelope, CommandEnvelope):
            raise TypeError("envelope must be CommandEnvelope")
        _id(installation_id, "installation_id")
        if envelope.version_guard.resource_lease_versions:
            raise IssuerAuthorityDenied("D03 projection quote request has prior resource refs")
        source, mapping, arrival, guarded = _d03_projection_inputs(envelope)
        namespace = envelope.authority.namespace
        expected_operation = d03_self_identity_projection_operation_id_v1(
            namespace, source.token, qualified_mapping.certification_ref)
        if (qualified_mapping.persona_ref != f"persona:{namespace.persona_id}"
                or qualified_mapping.status != "active"):
            raise IssuerAuthorityDenied("D03 projection mapping or operation differs")
        if envelope.identity.operation_id != expected_operation:
            if len(envelope.causation) != 1:
                raise IssuerAuthorityDenied("D03 projection retry lacks original ingress")
            _d03_projection_retry_operation(
                db, namespace, source.token, qualified_mapping.certification_ref,
                envelope.causation[0], envelope.identity.operation_id,
                envelope.parent_budget_lease_ref)
            expected_operation = envelope.identity.operation_id
        now = _now_utc(now_utc)
        grant = self._load_grant(db, envelope.parent_budget_lease_ref)
        lease = get_budget_lease(db, grant.lease_id)
        authority = envelope.authority
        if (D03_SELF_IDENTITY_PROJECTION_WORK_KIND not in grant.allowed_work_kinds
                or (grant.bot_id, grant.persona_id) != namespace.as_tuple
                or (lease.bot_id, lease.persona_id, lease.currency)
                != (grant.bot_id, grant.persona_id, grant.currency)
                or lease.state != "active"
                or grant.policy_ref != authority.provider_policy_ref
                or grant.valid_until_utc <= now
                or not now < envelope.deadline_utc <= min(
                    now + admin_policy.deadline_after_seconds,
                    grant.valid_until_utc)):
            raise IssuerAuthorityDenied("D03 projection lacks current signed grant or deadline")
        if any(amount > grant.max_ceiling.get(name, 0)
               for name, amount in admin_policy.quote_ceiling.items()):
            raise IssuerAuthorityDenied("D03 projection quote exceeds signed grant")
        access = access_key(*namespace.as_tuple, source.owner.subject)
        if guarded.get(access, 0) < 1:
            raise IssuerAuthorityDenied("D03 projection source access needs current guard")
        for key in (source, access, arrival, mapping):
            row = db.execute(
                "SELECT revision,valid,value FROM graph_atoms WHERE token=?", (key.token,),
            ).fetchone()
            if key == mapping and guarded[mapping] == 0 and row is None:
                continue
            if row is None or row[:2] != (guarded[key], 1):
                raise IssuerAuthorityDenied("D03 projection prerequisite is not current")
            if key == arrival:
                try:
                    event = json.loads(row[2])
                except (TypeError, ValueError, json.JSONDecodeError) as exc:
                    raise IssuerAuthorityDenied("D03 projection arrival is invalid") from exc
        if (type(event) is not dict
                or event.get("event_id") != arrival.owner.subject
                or event.get("kind") != "message_received"
                or event.get("reality") != "host_observed"
                or event.get("source_refs") != [source.token]
                or type(event.get("scene_ref")) is not str
                or not event["scene_ref"].startswith("scene:")):
            raise IssuerAuthorityDenied("D03 projection arrival differs from source")
        requirements_row = db.execute(
            "SELECT requirements_json FROM graph_recovery_metadata_v2 "
            "WHERE bot=? AND persona=?", namespace.as_tuple,
        ).fetchone()
        if requirements_row is None:
            raise IssuerAuthorityDenied("D03 projection graph incarnation is unavailable")
        try:
            requirements = json.loads(requirements_row[0])
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise IssuerAuthorityDenied("D03 projection graph incarnation is invalid") from exc
        if (type(requirements) is not dict
                or qualified_mapping.graph_incarnation
                != requirements.get("graph_incarnation")):
            raise IssuerAuthorityDenied("D03 projection mapping graph incarnation differs")
        perspective = self_perspective_key(namespace, self_perspective_id(
            namespace, event["scene_ref"], arrival.token))
        if guarded.get(perspective) != 0 or db.execute(
                "SELECT 1 FROM graph_atoms WHERE token=?", (perspective.token,),
        ).fetchone() is not None:
            raise IssuerAuthorityDenied("D03 projection perspective is already committed")
        policy = D03SelfIdentityProjectionQuotePolicy(
            _d03_projection_policy_id(installation_id, grant, expected_operation),
            *namespace.as_tuple, installation_id,
            grant.grant_id, grant.version, grant.lease_id, grant.policy_ref,
            dict(admin_policy.quote_ceiling), admin_policy.deadline_after_seconds,
            admin_policy.snapshot_ref, admin_policy.resource_ref,
            source.token, arrival.token, mapping.token, guarded[mapping],
            perspective.token, qualified_mapping.certification_ref,
            canonical_digest(_payload(qualified_mapping)),
            envelope.identity.activity_id, expected_operation,
        )
        snapshot_ref, resource_ref = _d03_projection_quote_refs(policy, envelope)
        quote = ResourceQuote(
            d03_self_identity_projection_quote_id(namespace, expected_operation),
            1, *namespace.as_tuple, envelope.identity.activity_id,
            expected_operation, None, grant.lease_id,
            D03_SELF_IDENTITY_PROJECTION_WORK_KIND, snapshot_ref,
            envelope.deadline_utc, resource_ref, None, (), (),
            dict(policy.quote_ceiling), None, envelope.deadline_utc,
        )
        install_schema(db)
        existing = db.execute(
            "SELECT 1 FROM runtime_resource_quotes WHERE quote_id=? AND version=1",
            (quote.quote_id,),
        ).fetchone()
        if existing is None and any(
                amount > lease.limits.get(name, 0) - lease.used.get(name, 0)
                - lease.reserved.get(name, 0) - lease.unconfirmed.get(name, 0)
                for name, amount in policy.quote_ceiling.items()):
            raise IssuerAuthorityDenied("D03 projection budget has insufficient capacity")
        self._d02._install_d03_projection_policy(db, policy)
        self._d02._issue_bound_stage_quote(db, quote)
        return quote

    def issue_d06_first_ingress_c02_quote(
            self, db, envelope: CommandEnvelope, admin_policy, *,
            installation_id: str, job_id: str,
            now_utc: float | None = None) -> ResourceQuote:
        """Price one C02 stage after independently settled original model work.

        This signs no C02 adoption, graph write, or zero-cost outcome. The
        caller still needs a fresh Authority result and fenced graph commit.
        """
        from ..host.authority_profile import AdminD06FirstIngressC02Policy

        if type(admin_policy) is not AdminD06FirstIngressC02Policy:
            raise IssuerAuthorityDenied("installed D06 C02 policy is required")
        if not isinstance(envelope, CommandEnvelope):
            raise TypeError("envelope must be CommandEnvelope")
        _id(installation_id, "installation_id")
        _id(job_id, "job_id")
        if envelope.version_guard.resource_lease_versions:
            raise IssuerAuthorityDenied("D06 C02 quote request has prior resource refs")
        _, _, baseline = _d06_c02_input_keys(envelope)
        now = _now_utc(now_utc)
        origin = _d06_c02_origin(db, envelope, job_id, self._d02, now_utc=now)
        grant = self._load_grant(db, envelope.parent_budget_lease_ref)
        lease = get_budget_lease(db, grant.lease_id)
        authority = envelope.authority
        if (origin.installation_id != installation_id
                or origin.consumer_operation_id != envelope.identity.operation_id
                or D06_FIRST_INGRESS_C02_WORK_KIND not in grant.allowed_work_kinds
                or (grant.bot_id, grant.persona_id) != authority.namespace.as_tuple
                or (lease.bot_id, lease.persona_id, lease.currency)
                != (grant.bot_id, grant.persona_id, grant.currency)
                or lease.state != "active"
                or grant.policy_ref != authority.provider_policy_ref
                or grant.valid_until_utc <= now
                or not now < envelope.deadline_utc <= min(
                    now + admin_policy.deadline_after_seconds,
                    grant.valid_until_utc)):
            raise IssuerAuthorityDenied("D06 C02 lacks original consumer or current grant")
        if any(amount > grant.max_ceiling.get(name, 0)
               for name, amount in admin_policy.quote_ceiling.items()):
            raise IssuerAuthorityDenied("D06 C02 quote exceeds signed grant")
        policy = D06FirstIngressC02QuotePolicy(
            _d06_c02_policy_id(installation_id, grant, origin.consumer_operation_id),
            *authority.namespace.as_tuple, installation_id,
            grant.grant_id, grant.version, grant.lease_id, grant.policy_ref,
            dict(admin_policy.quote_ceiling), admin_policy.deadline_after_seconds,
            admin_policy.snapshot_ref, admin_policy.resource_ref,
            origin.job_id, origin.activity_id, origin.operation_id,
            origin.acquire_operation_id, origin.call_id,
            origin.binding_digest, origin.model_request_digest,
            origin.cost_operation_id, origin.cost_receipt_digest,
            origin.source_ref, baseline.token,
            next(item.revision for item in envelope.version_guard.read_versions
                 if item.key == baseline), origin.consumer_operation_id,
        )
        snapshot_ref, resource_ref = _d06_c02_quote_refs(policy, envelope)
        quote = ResourceQuote(
            d06_first_ingress_c02_quote_id(authority.namespace,
                                           origin.consumer_operation_id),
            1, *authority.namespace.as_tuple, origin.activity_id,
            origin.consumer_operation_id, None, grant.lease_id,
            D06_FIRST_INGRESS_C02_WORK_KIND, snapshot_ref,
            envelope.deadline_utc, resource_ref, None, (), (),
            dict(policy.quote_ceiling), authority.worker_fence,
            envelope.deadline_utc,
        )
        install_schema(db)
        existing = db.execute(
            "SELECT 1 FROM runtime_resource_quotes WHERE quote_id=? AND version=1",
            (quote.quote_id,),
        ).fetchone()
        if existing is None and any(
                amount > lease.limits.get(name, 0) - lease.used.get(name, 0)
                - lease.reserved.get(name, 0) - lease.unconfirmed.get(name, 0)
                for name, amount in policy.quote_ceiling.items()):
            raise IssuerAuthorityDenied("D06 C02 budget has insufficient capacity")
        self._d02._install_d06_c02_policy(db, policy)
        self._d02._issue_bound_stage_quote(db, quote)
        return quote

    def authorize_existing_encoding_job(self, db, job: PersistentJob, *,
                                        now_utc: float) -> bool:
        """Recheck the original signed grant and quote without reserving again."""
        if type(job) is not PersistentJob or job.work_kind != "d06.encode_source":
            raise IssuerAuthorityDenied("only a typed source encoding job may be acquired")
        grant = self._load_grant(db, job.budget_ref)
        lease = get_budget_lease(db, grant.lease_id)
        quote_ref = job.operator_versions.get("resource_quote")
        if type(quote_ref) is not str or ":" not in quote_ref:
            raise IssuerAuthorityDenied("encoding job has no original D02 quote")
        quote_id, version_text = quote_ref.rsplit(":", 1)
        try:
            version = int(version_text)
        except ValueError as exc:
            raise IssuerAuthorityDenied("encoding quote version is invalid") from exc
        quote = self._d02._load_quote(db, quote_id, version)
        key = runtime_job_key(job.bot_id, job.persona_id, job.activity_id, job.job_id)
        reservation = db.execute(
            "SELECT state FROM runtime_budget_reservations WHERE lease_id=? AND operation_id=?",
            (job.budget_ref, job.operation_id),
        ).fetchone()
        if (now_utc >= grant.valid_until_utc or now_utc >= quote.valid_until_utc
                or lease.state != "active" or reservation is None
                or reservation[0] != "reserved"
                or (grant.bot_id, grant.persona_id) != (job.bot_id, job.persona_id)
                or (quote.bot_id, quote.persona_id, quote.activity_id,
                    quote.operation_id, quote.graph_job_ref,
                    quote.parent_budget_lease_ref, quote.work_kind) != (
                    job.bot_id, job.persona_id, job.activity_id,
                    job.operation_id, key.token, job.budget_ref, job.work_kind)
                or job.work_kind not in grant.allowed_work_kinds):
            raise IssuerAuthorityDenied("encoding job lost its original signed authority")
        return True

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
        if quote.work_kind == D03_ARRIVAL_WORK_KIND:
            self._d02._qualified_d03_arrival_policy(db, envelope, quote, grant)
        if quote.work_kind == D03_SELF_IDENTITY_PROJECTION_WORK_KIND:
            source, mapping, arrival, guarded = _d03_projection_inputs(envelope)
            policy = self._d02._qualified_d03_projection_policy(
                db, envelope, quote, grant)
            if len(envelope.causation) != 1:
                raise IssuerAuthorityDenied("D03 projection lacks original ingress")
            _d03_projection_retry_operation(
                db, envelope.authority.namespace, source.token,
                policy.certification_ref, envelope.causation[0],
                envelope.identity.operation_id, quote.parent_budget_lease_ref)
            if ((policy.source_ref, policy.mapping_ref, policy.arrival_ref,
                 policy.mapping_revision, policy.activity_id, policy.operation_id)
                != (source.token, mapping.token, arrival.token, guarded[mapping],
                    envelope.identity.activity_id, envelope.identity.operation_id)):
                raise IssuerAuthorityDenied("D03 projection signed inputs changed")
            for key in (source, mapping, arrival):
                row = db.execute(
                    "SELECT revision,valid FROM graph_atoms WHERE token=?", (key.token,),
                ).fetchone()
                if key == mapping and guarded[mapping] == 0 and row is None:
                    continue
                if row != (guarded[key], 1):
                    raise IssuerAuthorityDenied("D03 projection prerequisite is stale")
            if db.execute("SELECT 1 FROM graph_atoms WHERE token=?",
                          (policy.perspective_ref,)).fetchone() is not None:
                raise IssuerAuthorityDenied("D03 projection perspective already exists")
        if quote.work_kind == D04_BASELINE_WORK_KIND:
            _d04_baseline_input_keys(envelope)
            if (quote.graph_job_ref is not None or quote.outbox_refs
                    or quote.d02_settlement_refs):
                raise IssuerAuthorityDenied("D04 baseline quote contains unrelated runtime refs")
            self._d02._qualified_d04_baseline_policy(db, envelope, quote, grant)
        if quote.work_kind == D06_FIRST_INGRESS_C02_WORK_KIND:
            _, _, baseline = _d06_c02_input_keys(envelope)
            policy = self._d02._qualified_d06_c02_policy(db, envelope, quote, grant)
            origin = _d06_c02_origin(
                db, envelope, policy.job_id, self._d02, now_utc=now_utc)
            baseline_revision = next(
                item.revision for item in envelope.version_guard.read_versions
                if item.key == baseline)
            if (policy.installation_id != origin.installation_id
                    or (policy.job_id, policy.original_activity_id,
                        policy.original_operation_id, policy.acquire_operation_id,
                        policy.original_call_id, policy.binding_digest,
                        policy.model_request_digest, policy.cost_operation_id,
                        policy.cost_receipt_digest, policy.source_ref,
                        policy.baseline_ref, policy.baseline_revision,
                        policy.consumer_operation_id) != (
                        origin.job_id, origin.activity_id, origin.operation_id,
                        origin.acquire_operation_id, origin.call_id,
                        origin.binding_digest, origin.model_request_digest,
                        origin.cost_operation_id, origin.cost_receipt_digest,
                        origin.source_ref, baseline.token, baseline_revision,
                        origin.consumer_operation_id)):
                raise IssuerAuthorityDenied("D06 C02 original signed binding changed")
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
    "BudgetLeaseGrant", "D02ResourceIssuer", "D03ArrivalQuotePolicy", "D03_ARRIVAL_WORK_KIND", "D03SelfIdentityProjectionQuotePolicy", "D03_SELF_IDENTITY_PROJECTION_WORK_KIND", "D04BaselineQuotePolicy", "D04_BASELINE_WORK_KIND", "D06FirstIngressC02QuotePolicy", "D06_FIRST_INGRESS_C02_WORK_KIND", "D11BudgetGrantIssuer", "D11BudgetJobIssuer", "d03_arrival_quote_id", "d03_self_identity_projection_quote_id", "d04_baseline_quote_id", "d06_first_ingress_c02_quote_id",
    "IssuerAuthorityDenied", "ResourceOutcome", "ResourceQuote",
    "build_runtime_issuers", "install_schema",
]
