"""Installed D13 counter CPU resource ceiling policy and deterministic D02 quote request.

The installer owns the signing key.  A request is only a candidate: D02 must
sign it, and W01 must still verify current Owner, graph, body and budget facts.
No platform execution or resource outcome is asserted here.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import hmac
import json
import math
import re
import sqlite3

from ..runtime_contracts import CommandEnvelope, NamespaceId, canonical_digest, canonical_serialize
from ..graph_types import AtomKey, Owner
from .budget import get_budget_lease, require_budget_family_admissible
from .issuers import (
    D11BudgetGrantIssuer, IssuerAuthorityDenied, ResourceQuote,
)


D13_COUNTER_CPU_WORK_KIND = "d13.full_http_counter.v1"
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_POLICY_SCHEMA = "sylanne3.d13.counter.cpu_quote_policy.v1"
_REQUEST_SCHEMA = "sylanne3.d13.counter.cpu_quote_request.v1"


def _identifier(value: str, name: str) -> None:
    if type(value) is not str or _ID.fullmatch(value) is None:
        raise ValueError(f"invalid {name}")


def _transaction(db: sqlite3.Connection) -> None:
    if type(db) is not sqlite3.Connection or not db.in_transaction:
        raise IssuerAuthorityDenied("D13 counter CPU quote needs caller-owned transaction")


@dataclass(frozen=True, slots=True)
class D13CounterCpuQuotePolicyV1:
    policy_id: str
    version: int
    namespace: NamespaceId
    installation_id: str
    algorithm_ref: str
    cpu_ms_ceiling: int
    valid_until_utc: float
    work_kind: str = D13_COUNTER_CPU_WORK_KIND
    schema: str = _POLICY_SCHEMA

    def __post_init__(self) -> None:
        if type(self.namespace) is not NamespaceId:
            raise TypeError("typed D13 counter policy namespace required")
        for name in ("policy_id", "installation_id", "algorithm_ref"):
            _identifier(getattr(self, name), name)
        if (self.schema != _POLICY_SCHEMA
                or self.work_kind != D13_COUNTER_CPU_WORK_KIND
                or type(self.version) is not int or self.version < 1
                or type(self.cpu_ms_ceiling) is not int
                or self.cpu_ms_ceiling != 1000
                or type(self.valid_until_utc) not in (int, float)
                or not math.isfinite(self.valid_until_utc)):
            raise ValueError("invalid installed D13 counter CPU quote policy")
        object.__setattr__(self, "valid_until_utc", float(self.valid_until_utc))


def install_d13_counter_cpu_quote_schema_v1(db: sqlite3.Connection) -> None:
    _transaction(db)
    db.execute("""CREATE TABLE IF NOT EXISTS runtime_d13_counter_cpu_quote_policies_v1 (
        bot TEXT NOT NULL, persona TEXT NOT NULL, policy_id TEXT NOT NULL,
        version INTEGER NOT NULL, policy_json TEXT NOT NULL, signature TEXT NOT NULL,
        PRIMARY KEY(bot,persona,policy_id,version))""")
    db.execute("""CREATE TRIGGER IF NOT EXISTS runtime_d13_counter_cpu_policy_no_update_v1
        BEFORE UPDATE ON runtime_d13_counter_cpu_quote_policies_v1
        BEGIN SELECT RAISE(ABORT, 'D13 counter CPU quote policy is immutable'); END""")
    db.execute("""CREATE TRIGGER IF NOT EXISTS runtime_d13_counter_cpu_policy_no_delete_v1
        BEFORE DELETE ON runtime_d13_counter_cpu_quote_policies_v1
        BEGIN SELECT RAISE(ABORT, 'D13 counter CPU quote policy is immutable'); END""")
    db.execute("""CREATE TABLE IF NOT EXISTS runtime_d13_counter_cpu_quote_requests_v1 (
        bot TEXT NOT NULL, persona TEXT NOT NULL, operation_id TEXT NOT NULL,
        policy_id TEXT NOT NULL, policy_version INTEGER NOT NULL,
        request_json TEXT NOT NULL, quote_json TEXT NOT NULL, signature TEXT NOT NULL,
        PRIMARY KEY(bot,persona,operation_id), UNIQUE(quote_json))""")
    db.execute("""CREATE TRIGGER IF NOT EXISTS runtime_d13_counter_cpu_request_no_update_v1
        BEFORE UPDATE ON runtime_d13_counter_cpu_quote_requests_v1
        BEGIN SELECT RAISE(ABORT, 'D13 counter CPU quote request is immutable'); END""")
    db.execute("""CREATE TRIGGER IF NOT EXISTS runtime_d13_counter_cpu_request_no_delete_v1
        BEFORE DELETE ON runtime_d13_counter_cpu_quote_requests_v1
        BEGIN SELECT RAISE(ABORT, 'D13 counter CPU quote request is immutable'); END""")


class D13CounterCpuQuotePolicyAuthorityV1:
    """HMAC authority constructed only with a protected installation key."""

    def __init__(self, signing_key: bytes):
        if type(signing_key) is not bytes or len(signing_key) < 32:
            raise ValueError("D13 counter installation signing key needs at least 32 bytes")
        self.__key = bytes(signing_key)

    def _sign(self, kind: str, payload: str) -> str:
        return hmac.new(self.__key, (kind + "\n" + payload).encode("utf-8"),
                        hashlib.sha256).hexdigest()

    def _verify(self, kind: str, payload: str, signature: str) -> None:
        if (type(signature) is not str or _DIGEST.fullmatch(signature) is None
                or not hmac.compare_digest(self._sign(kind, payload), signature)):
            raise IssuerAuthorityDenied(f"D13 counter {kind} signature differs")

    def install_policy(self, db: sqlite3.Connection,
                       policy: D13CounterCpuQuotePolicyV1) -> str:
        """Install exact policy bytes once in the caller's business transaction."""
        _transaction(db)
        if type(policy) is not D13CounterCpuQuotePolicyV1:
            raise TypeError("typed D13 counter CPU quote policy required")
        install_d13_counter_cpu_quote_schema_v1(db)
        payload = canonical_serialize(asdict(policy))
        signature = self._sign("d13-counter-cpu-quote-policy.v1", payload)
        key = (*policy.namespace.as_tuple, policy.policy_id, policy.version)
        prior = db.execute(
            "SELECT policy_json,signature FROM runtime_d13_counter_cpu_quote_policies_v1 "
            "WHERE bot=? AND persona=? AND policy_id=? AND version=?", key,
        ).fetchone()
        if prior is not None:
            self._verify("d13-counter-cpu-quote-policy.v1", *prior)
            if prior != (payload, signature):
                raise IssuerAuthorityDenied("D13 counter CPU policy replay differs")
        else:
            db.execute("INSERT INTO runtime_d13_counter_cpu_quote_policies_v1 VALUES(?,?,?,?,?,?)",
                       (*key, payload, signature))
        return signature

    def read_policy(self, db: sqlite3.Connection, namespace: NamespaceId,
                    policy_id: str, version: int) -> D13CounterCpuQuotePolicyV1:
        """Reread exact signed bytes; this historical read grants no work."""
        _transaction(db)
        if type(namespace) is not NamespaceId or type(version) is not int or version < 1:
            raise TypeError("typed D13 counter policy locator required")
        _identifier(policy_id, "policy_id")
        row = db.execute(
            "SELECT policy_json,signature FROM runtime_d13_counter_cpu_quote_policies_v1 "
            "WHERE bot=? AND persona=? AND policy_id=? AND version=?",
            (*namespace.as_tuple, policy_id, version),
        ).fetchone()
        if row is None:
            raise IssuerAuthorityDenied("signed D13 counter CPU quote policy absent")
        self._verify("d13-counter-cpu-quote-policy.v1", *row)
        try:
            raw = json.loads(row[0])
            policy = D13CounterCpuQuotePolicyV1(
                **{**raw, "namespace": NamespaceId(**raw["namespace"])})
        except (TypeError, ValueError, KeyError, json.JSONDecodeError) as exc:
            raise IssuerAuthorityDenied("signed D13 counter CPU quote policy invalid") from exc
        if (policy.namespace != namespace or policy.policy_id != policy_id
                or policy.version != version
                or canonical_serialize(asdict(policy)) != row[0]):
            raise IssuerAuthorityDenied("signed D13 counter CPU quote policy identity differs")
        return policy

    def request_quote(self, db: sqlite3.Connection, *,
                      namespace: NamespaceId, policy_id: str, policy_version: int,
                      envelope: CommandEnvelope, owner,
                      d11_issuer: D11BudgetGrantIssuer, algorithm_ref: str,
                      now_utc: float) -> ResourceQuote:
        """Record and return a deterministic, unsigned single CPU dimension quote.

        W01 supplies its already fenced OwnerLeaseBindingV1. The caller must
        separately have W01's live Owner/Authority and graph checks in force.
        """
        from ..graph_coordinator import OwnerLeaseBindingV1

        _transaction(db)
        if (type(namespace) is not NamespaceId
                or type(envelope) is not CommandEnvelope
                or type(owner) is not OwnerLeaseBindingV1
                or not isinstance(d11_issuer, D11BudgetGrantIssuer)):
            raise TypeError("typed D13 counter quote request inputs required")
        _identifier(algorithm_ref, "algorithm_ref")
        if (type(now_utc) not in (int, float) or not math.isfinite(now_utc)
                or envelope.version_guard.resource_lease_versions):
            raise IssuerAuthorityDenied("D13 counter pre-quote time or resource guard differs")
        now = float(now_utc)
        policy = self.read_policy(db, namespace, policy_id, policy_version)
        authority = envelope.authority
        identity = envelope.identity
        if (policy.algorithm_ref != algorithm_ref
                or authority.namespace != namespace
                or identity.effect_id is None
                or identity.phase != "prepare_current_d13_counter_cpu_v1"
                or authority.issuer_domain != "d13"
                or owner.namespace != namespace
                or owner.actor != authority.actor
                or owner.purpose != authority.purpose
                or (owner.audience,) != authority.audience
                or "d13.counter.cpu.prepare" not in owner.capabilities
                or not now < envelope.deadline_utc <= policy.valid_until_utc):
            raise IssuerAuthorityDenied("D13 counter policy, Owner or envelope identity differs")
        grant = d11_issuer.current_budget_grant(db, envelope.parent_budget_lease_ref)
        lease = get_budget_lease(db, envelope.parent_budget_lease_ref)
        require_budget_family_admissible(db, lease.lease_id)
        cpu = policy.cpu_ms_ceiling
        if (grant.lease_id != envelope.parent_budget_lease_ref
                or (grant.bot_id, grant.persona_id) != namespace.as_tuple
                or D13_COUNTER_CPU_WORK_KIND not in grant.allowed_work_kinds
                or grant.valid_until_utc < envelope.deadline_utc
                or grant.max_ceiling.get("cpu_ms", 0) < cpu
                or (lease.bot_id, lease.persona_id, lease.currency)
                   != (grant.bot_id, grant.persona_id, grant.currency)
                or lease.state != "active"
                or cpu > lease.limits.get("cpu_ms", 0)
                   - lease.used.get("cpu_ms", 0)
                   - lease.reserved.get("cpu_ms", 0)
                   - lease.unconfirmed.get("cpu_ms", 0)):
            raise IssuerAuthorityDenied("D13 counter current D11 CPU capacity insufficient")
        request = {
            "schema": _REQUEST_SCHEMA, "namespace": namespace.as_tuple,
            "operation_id": identity.operation_id,
            "envelope_digest": canonical_digest(envelope),
            "policy_id": policy.policy_id, "policy_version": policy.version,
            "policy_digest": canonical_digest(policy),
            "owner_grant_id": owner.grant_id,
            "owner_grant_revision": owner.grant_revision,
            "owner_grant_digest": owner.grant_digest,
            "grant_id": grant.grant_id, "grant_version": grant.version,
        }
        return self._record_checked_quote_v1(db, namespace=namespace, envelope=envelope,
            policy=policy, request=request)

    def _record_checked_quote_v1(self, db, *, namespace, envelope, policy, request):
        """Sign/store only after a fixed Owner/Self wrapper checked actual qualification."""
        _transaction(db)
        identity, cpu = envelope.identity, policy.cpu_ms_ceiling
        policy_id, policy_version = policy.policy_id, policy.version
        request_json = canonical_serialize(request)
        request_digest = canonical_digest(request)
        quote_id = "d13countercpu-" + canonical_digest({
            "namespace": namespace.as_tuple, "operation_id": identity.operation_id})[:48]
        quote = ResourceQuote(
            quote_id, 1, *namespace.as_tuple, identity.activity_id,
            identity.operation_id, identity.effect_id,
            envelope.parent_budget_lease_ref, D13_COUNTER_CPU_WORK_KIND,
            "d13countercpupolicy:" + canonical_digest(policy)[:48],
            envelope.deadline_utc, "d13countercpu:" + request_digest[:48],
            None, (), (AtomKey(
                Owner("activity", *namespace.as_tuple, identity.activity_id),
                "d02.settlement.v1", "d13countercpu-" + request_digest[:48],
            ).token,), {"cpu_ms": cpu}, None,
            envelope.deadline_utc,
        )
        quote_json = canonical_serialize(asdict(quote))
        signature = self._sign("d13-counter-cpu-quote-request.v1", request_json + "\n" + quote_json)
        key = (*namespace.as_tuple, identity.operation_id)
        prior = db.execute(
            "SELECT policy_id,policy_version,request_json,quote_json,signature "
            "FROM runtime_d13_counter_cpu_quote_requests_v1 "
            "WHERE bot=? AND persona=? AND operation_id=?", key,
        ).fetchone()
        if prior is not None:
            self._verify("d13-counter-cpu-quote-request.v1", prior[2] + "\n" + prior[3], prior[4])
            if prior != (policy_id, policy_version, request_json, quote_json, signature):
                raise IssuerAuthorityDenied("D13 counter CPU operation quote request replay differs")
        else:
            db.execute("INSERT INTO runtime_d13_counter_cpu_quote_requests_v1 VALUES(?,?,?,?,?,?,?,?)",
                       (*key, policy_id, policy_version, request_json, quote_json,
                        signature))
        return quote

    def read_original_request_quote(
            self, db: sqlite3.Connection, namespace: NamespaceId,
            operation_id: str) -> tuple[D13CounterCpuQuotePolicyV1, ResourceQuote]:
        """Authenticate the immutable policy request behind one D02 quote."""
        _transaction(db)
        _identifier(operation_id, "operation_id")
        row = db.execute(
            "SELECT policy_id,policy_version,request_json,quote_json,signature "
            "FROM runtime_d13_counter_cpu_quote_requests_v1 "
            "WHERE bot=? AND persona=? AND operation_id=?",
            (*namespace.as_tuple, operation_id),
        ).fetchone()
        if row is None:
            raise IssuerAuthorityDenied("D13 counter original CPU quote request absent")
        self._verify("d13-counter-cpu-quote-request.v1", row[2] + "\n" + row[3], row[4])
        policy = self.read_policy(db, namespace, row[0], row[1])
        try:
            request, raw_quote = json.loads(row[2]), json.loads(row[3])
            quote = ResourceQuote(**raw_quote)
        except (TypeError, ValueError, KeyError, json.JSONDecodeError) as exc:
            raise IssuerAuthorityDenied("D13 counter original CPU quote request unreadable") from exc
        if (request.get("schema") != _REQUEST_SCHEMA
                or request.get("namespace") != list(namespace.as_tuple)
                or request.get("operation_id") != operation_id
                or request.get("policy_id") != policy.policy_id
                or request.get("policy_version") != policy.version
                or request.get("policy_digest") != canonical_digest(policy)
                or quote.operation_id != operation_id
                or (quote.bot_id, quote.persona_id) != namespace.as_tuple
                or quote.work_kind != D13_COUNTER_CPU_WORK_KIND
                or quote.snapshot_ref != "d13countercpupolicy:" + canonical_digest(policy)[:48]
                or canonical_serialize(request) != row[2]
                or canonical_serialize(asdict(quote)) != row[3]):
            raise IssuerAuthorityDenied("D13 counter original CPU quote request differs")
        if len(quote.d02_settlement_refs) != 1:
            raise IssuerAuthorityDenied("D13 counter original settlement key is absent")
        settlement = AtomKey.from_token(quote.d02_settlement_refs[0])
        expected = AtomKey(
            Owner("activity", *namespace.as_tuple, quote.activity_id),
            "d02.settlement.v1", "d13countercpu-" + canonical_digest(request)[:48],
        )
        if settlement != expected:
            raise IssuerAuthorityDenied("D13 counter original settlement key differs")
        return policy, quote


__all__ = [
    "D13_COUNTER_CPU_WORK_KIND", "D13CounterCpuQuotePolicyV1",
    "D13CounterCpuQuotePolicyAuthorityV1", "install_d13_counter_cpu_quote_schema_v1",
]
