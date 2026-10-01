"""D02 installed fixed-component policy and original BodyQuote authority.

Only an explicitly installed policy can initialize a body or price work. W01
owns the graph transaction and must guard the current state and full active
reservation inventory before adopting these writes.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
import hashlib
import hmac
import json
import sqlite3

from ...graph_types import GraphWrite
from ...runtime.issuers import D02ResourceIssuer, ResourceQuote
from ...runtime_contracts import (
    CommandEnvelope, NamespaceId, canonical_digest, canonical_serialize,
)
from . import (
    BodyDomain, BodyProfile, BodyQuote, BodyReservation, BodyState,
    WorkComponent,
)


class BodyQuoteUnavailable(ValueError):
    """Installed body policy or original quote is absent or inconsistent."""


@dataclass(frozen=True)
class FixedBodyPolicyV1:
    policy_id: str
    version: int
    profile: BodyProfile
    initial_state: BodyState
    work_kind: str
    component: WorkComponent
    valid_until: float

    def __post_init__(self) -> None:
        if (not self.policy_id or type(self.version) is not int
                or self.version < 1 or type(self.profile) is not BodyProfile
                or type(self.initial_state) is not BodyState
                or self.initial_state.profile_id != self.profile.profile_id
                or self.initial_state.version != 1
                or self.work_kind not in self.profile.work_kinds
                or type(self.component) is not WorkComponent
                or self.component.fixed_cost <= 0
                or self.component.duration_rate != 0):
            raise BodyQuoteUnavailable("fixed body policy is incomplete")


@dataclass(frozen=True)
class OriginalFixedBodyReservation:
    body_quote: BodyQuote
    body_quote_version: int
    reservation: BodyReservation
    reservation_write: GraphWrite
    replayed: bool = False


def install_body_quote_schema(db: sqlite3.Connection) -> None:
    db.execute("""
        CREATE TABLE IF NOT EXISTS d02_fixed_body_policies_v1 (
            bot TEXT NOT NULL, persona TEXT NOT NULL,
            policy_id TEXT NOT NULL, version INTEGER NOT NULL,
            policy_json TEXT NOT NULL, signature TEXT NOT NULL,
            status TEXT NOT NULL,
            PRIMARY KEY (bot, persona, policy_id, version)
        )
    """)
    db.execute("""
        CREATE TABLE IF NOT EXISTS d02_body_quotes_v1 (
            bot TEXT NOT NULL, persona TEXT NOT NULL,
            quote_id TEXT NOT NULL,
            quote_version INTEGER NOT NULL,
            policy_id TEXT NOT NULL, policy_version INTEGER NOT NULL,
            operation_id TEXT NOT NULL, resource_quote_digest TEXT NOT NULL,
            body_quote_json TEXT NOT NULL, signature TEXT NOT NULL,
            PRIMARY KEY (bot, persona, quote_id),
            UNIQUE (bot, persona, operation_id)
        )
    """)
    for table in ("d02_fixed_body_policies_v1", "d02_body_quotes_v1"):
        for operation in ("UPDATE", "DELETE"):
            db.execute(f"""
                CREATE TRIGGER IF NOT EXISTS {table}_{operation.lower()}_immutable
                BEFORE {operation} ON {table}
                BEGIN SELECT RAISE(ABORT, 'D02 original is immutable'); END
            """)


class D02BodyQuoteAuthority:
    """Signs installed fixed policies and original body quotes in the DB."""

    def __init__(self, signing_key: bytes):
        if type(signing_key) is not bytes or len(signing_key) < 32:
            raise ValueError("D02 body quote signing key must contain 32 bytes")
        self._key = signing_key

    def _sign(self, kind: str, payload: str) -> str:
        return hmac.new(self._key, (kind + "\n" + payload).encode("utf-8"),
                        hashlib.sha256).hexdigest()

    def _verify(self, kind: str, payload: str, signature: str) -> None:
        if not hmac.compare_digest(self._sign(kind, payload), signature):
            raise BodyQuoteUnavailable("D02 body original signature differs")

    def install_policy(self, db: sqlite3.Connection,
                       policy: FixedBodyPolicyV1) -> None:
        """W01 calls this only from a trusted administrator installation."""
        if (not isinstance(db, sqlite3.Connection) or not db.in_transaction
                or type(policy) is not FixedBodyPolicyV1):
            raise BodyQuoteUnavailable("trusted policy installation transaction required")
        payload = canonical_serialize(asdict(policy))
        signature = self._sign("d02-fixed-body-policy.v1", payload)
        namespace = policy.profile.namespace
        row = db.execute(
            "SELECT policy_json,signature,status FROM d02_fixed_body_policies_v1 "
            "WHERE bot=? AND persona=? AND policy_id=? AND version=?",
            namespace.as_tuple + (policy.policy_id, policy.version),
        ).fetchone()
        if row is not None:
            if row != (payload, signature, "active"):
                raise BodyQuoteUnavailable("D02 body policy replay differs")
            return
        db.execute(
            "INSERT INTO d02_fixed_body_policies_v1 VALUES(?,?,?,?,?,?,?)",
            namespace.as_tuple + (policy.policy_id, policy.version,
                                  payload, signature, "active"),
        )

    def policy(self, db: sqlite3.Connection, namespace: NamespaceId, policy_id: str,
               version: int) -> FixedBodyPolicyV1:
        if type(namespace) is not NamespaceId:
            raise BodyQuoteUnavailable("body policy namespace is required")
        try:
            row = db.execute(
                "SELECT policy_json,signature,status FROM d02_fixed_body_policies_v1 "
                "WHERE bot=? AND persona=? AND policy_id=? AND version=?",
                namespace.as_tuple + (policy_id, version),
            ).fetchone()
        except sqlite3.Error as exc:
            raise BodyQuoteUnavailable("installed body policy is unavailable") from exc
        if row is None or row[2] != "active":
            raise BodyQuoteUnavailable("active body policy is absent")
        self._verify("d02-fixed-body-policy.v1", row[0], row[1])
        try:
            raw = json.loads(row[0])
            raw["profile"]["namespace"] = NamespaceId(**raw["profile"]["namespace"])
            raw["profile"]["applicable_axes"] = tuple(raw["profile"]["applicable_axes"])
            raw["profile"]["work_kinds"] = tuple(raw["profile"]["work_kinds"])
            raw["profile"] = BodyProfile(**raw["profile"])
            raw["initial_state"] = BodyState(**raw["initial_state"])
            raw["component"] = WorkComponent(**raw["component"])
            policy = FixedBodyPolicyV1(**raw)
        except (ValueError, TypeError, KeyError) as exc:
            raise BodyQuoteUnavailable("installed body policy payload is invalid") from exc
        if (policy.policy_id, policy.version, policy.profile.namespace) != (
                policy_id, version, namespace):
            raise BodyQuoteUnavailable("installed body policy identity differs")
        return policy

    def initial_writes(self, db: sqlite3.Connection, namespace: NamespaceId,
                       policy_id: str,
                       version: int) -> tuple[GraphWrite, GraphWrite]:
        policy = self.policy(db, namespace, policy_id, version)
        return (BodyDomain.profile_write(policy.profile),
                BodyDomain.state_write(policy.profile.namespace,
                                       policy.initial_state))

    def issue_fixed_quote_and_reservation(
        self, db: sqlite3.Connection, resource_issuer: D02ResourceIssuer,
        envelope: CommandEnvelope, resource_quote: ResourceQuote,
        policy_id: str, policy_version: int, state: BodyState,
        current_reservations: tuple[BodyReservation, ...],
        reservation_id: str, effect_id: str,
    ) -> OriginalFixedBodyReservation:
        if (not isinstance(db, sqlite3.Connection) or not db.in_transaction
                or type(resource_issuer) is not D02ResourceIssuer
                or type(envelope) is not CommandEnvelope
                or type(resource_quote) is not ResourceQuote
                or type(state) is not BodyState):
            raise BodyQuoteUnavailable("typed body quote transaction required")
        namespace = envelope.authority.namespace
        policy = self.policy(db, namespace, policy_id, policy_version)
        identity = envelope.identity
        if (policy.profile.namespace != namespace
                or state.profile_id != policy.profile.profile_id
                or resource_issuer.original_signed_quote(
                    db, resource_quote.quote_id, resource_quote.version)
                != resource_quote
                or (resource_quote.bot_id, resource_quote.persona_id)
                != namespace.as_tuple
                or (resource_quote.activity_id, resource_quote.operation_id,
                    resource_quote.work_kind) != (
                    identity.activity_id, identity.operation_id, policy.work_kind)
                or resource_quote.effect_id != identity.effect_id):
            raise BodyQuoteUnavailable("body and resource quote identity differs")
        domain = BodyDomain()
        quote = domain.quote_work(
            policy.profile, state, identity.activity_id, policy.work_kind,
            0.0, (policy.component,), valid_until=policy.valid_until,
        )
        quote = replace(quote, quote_id="body-quote:" + canonical_digest({
            "namespace": list(namespace.as_tuple),
            "operation_id": identity.operation_id,
            "policy_id": policy.policy_id, "policy_version": policy.version,
        }))
        existing = db.execute(
            "SELECT 1 FROM d02_body_quotes_v1 WHERE bot=? AND persona=? "
            "AND quote_id=?", namespace.as_tuple + (quote.quote_id,),
        ).fetchone()
        if existing is not None:
            original = self.original_body_quote(
                db, quote.quote_id, 1, resource_quote, identity.operation_id,
            )
            matches = tuple(item for item in current_reservations
                            if item.reservation_id == reservation_id)
            if (original != quote or len(matches) != 1
                    or matches[0].quote_id != quote.quote_id
                    or matches[0].effect_id != effect_id):
                raise BodyQuoteUnavailable("body quote replay differs or reservation is absent")
            return OriginalFixedBodyReservation(
                original, 1, matches[0],
                BodyDomain.reservation_write(namespace, identity.activity_id,
                                             matches[0]), True,
            )
        reservation = domain.reserve_work(
            state, current_reservations, quote, reservation_id, effect_id,
        )
        payload = canonical_serialize(asdict(quote))
        resource_digest = canonical_digest(resource_quote)
        signed = self._sign("d02-body-quote.v1", canonical_serialize({
            "quote": asdict(quote), "quote_version": 1,
            "policy_id": policy_id,
            "policy_version": policy_version,
            "operation_id": identity.operation_id,
            "resource_quote_digest": resource_digest,
        }))
        try:
            db.execute(
                "INSERT INTO d02_body_quotes_v1 VALUES(?,?,?,?,?,?,?,?,?,?)",
                namespace.as_tuple + (quote.quote_id, 1, policy_id,
                policy_version, identity.operation_id, resource_digest,
                payload, signed),
            )
        except sqlite3.IntegrityError as exc:
            raise BodyQuoteUnavailable("body quote identity already exists") from exc
        return OriginalFixedBodyReservation(
            quote, 1, reservation,
            BodyDomain.reservation_write(namespace, identity.activity_id,
                                         reservation),
        )

    def original_body_quote(
        self, db: sqlite3.Connection, quote_id: str, quote_version: int,
        resource_quote: ResourceQuote, operation_id: str,
    ) -> BodyQuote:
        try:
            row = db.execute(
                "SELECT quote_version,policy_id,policy_version,operation_id,"
                "resource_quote_digest,body_quote_json,signature "
                "FROM d02_body_quotes_v1 WHERE bot=? AND persona=? "
                "AND quote_id=? AND operation_id=?",
                (resource_quote.bot_id, resource_quote.persona_id,
                 quote_id, operation_id),
            ).fetchone()
        except sqlite3.Error as exc:
            raise BodyQuoteUnavailable("original body quote is unavailable") from exc
        if (row is None or row[0] != quote_version or row[3] != operation_id
                or row[4] != canonical_digest(resource_quote)):
            raise BodyQuoteUnavailable("original body quote binding differs")
        self._verify("d02-body-quote.v1", canonical_serialize({
            "quote": json.loads(row[5]), "quote_version": row[0],
            "policy_id": row[1], "policy_version": row[2],
            "operation_id": row[3], "resource_quote_digest": row[4],
        }), row[6])
        try:
            raw = json.loads(row[5])
            raw["components"] = tuple(WorkComponent(**part)
                                      for part in raw["components"])
            quote = BodyQuote(**raw)
        except (ValueError, TypeError, KeyError) as exc:
            raise BodyQuoteUnavailable("original body quote payload is invalid") from exc
        if quote.quote_id != quote_id:
            raise BodyQuoteUnavailable("original body quote identity differs")
        return quote
