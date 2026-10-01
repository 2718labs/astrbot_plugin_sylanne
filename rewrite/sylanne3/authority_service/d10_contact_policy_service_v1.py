"""Owner-session-issued contact permission on the installed Core and fence.

The Graph may mirror these originals. It cannot issue consent, change a quota
window or revoke an original by writing a policy atom.
"""
from dataclasses import asdict, dataclass
import hashlib
import hmac
import json
import math

from .contract import AuthorityUnavailable
from .v2_contract import FencePermitV2
from .v2_owner_session import OwnerSessionLoginRequestV1, _principal
from .v2_owner_ticket_store import AuthorityV2OwnerTicketStore
from ..domains.d10 import ContactPolicy
from ..domains.d10.contact_claim_v2 import contact_window_id_v2
from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize

TABLE = "authority_d10_contact_policy_originals_v1"
DDL = """CREATE TABLE authority_d10_contact_policy_originals_v1(
authority_namespace TEXT NOT NULL, installation_id TEXT NOT NULL,
policy_id TEXT NOT NULL, policy_version INTEGER NOT NULL CHECK(policy_version>0),
operation_id TEXT NOT NULL, action TEXT NOT NULL CHECK(action IN ('issue','revoke')),
payload_json TEXT NOT NULL, payload_digest TEXT NOT NULL, signature TEXT NOT NULL,
PRIMARY KEY(authority_namespace,installation_id,operation_id),
UNIQUE(authority_namespace,installation_id,policy_id,policy_version,action))"""
TRIGGERS = tuple((TABLE + "_no_" + action, "CREATE TRIGGER " + TABLE + "_no_" + action
    + " BEFORE " + action.upper() + " ON " + TABLE
    + " BEGIN SELECT RAISE(ABORT,'contact policy originals are immutable'); END")
    for action in ("update", "delete"))


@dataclass(frozen=True, slots=True)
class D10ContactPolicyOriginalV1:
    authority_namespace: str
    authority_id: str
    installation_id: str
    namespace: NamespaceId
    policy: ContactPolicy
    owner_actor_id: str
    owner_head_digest: str
    owner_authorization_revision: int
    owner_principal_epoch: int
    window_id: str
    operation_id: str
    action: str
    issued_at_utc: float
    signature: str
    schema: str = "d10.owner-contact-policy-original.v1"

    def __post_init__(self):
        if (self.schema != "d10.owner-contact-policy-original.v1"
                or type(self.namespace) is not NamespaceId or type(self.policy) is not ContactPolicy
                or self.policy.namespace != self.namespace
                or self.window_id != contact_window_id_v2(self.policy)
                or self.action not in {"issue", "revoke"}
                or type(self.owner_authorization_revision) is not int or self.owner_authorization_revision < 1
                or type(self.owner_principal_epoch) is not int or self.owner_principal_epoch < 0
                or type(self.issued_at_utc) not in {int, float} or not math.isfinite(self.issued_at_utc)
                or type(self.signature) is not str or len(self.signature) != 64
                or any(c not in "0123456789abcdef" for c in self.signature)):
            raise ValueError("exact Owner contact-policy original required")
        for name in ("authority_namespace", "authority_id", "installation_id", "owner_actor_id",
                     "owner_head_digest", "operation_id"):
            if type(getattr(self, name)) is not str or not getattr(self, name):
                raise ValueError("contact-policy original lacks its current identity")

    @property
    def original_ref(self):
        return "d10-contact-policy:" + canonical_digest((self.authority_namespace,
            self.installation_id, self.operation_id))

    @property
    def digest(self):
        return canonical_digest(self)


def contact_policy_original_to_wire_v1(original):
    if type(original) is not D10ContactPolicyOriginalV1:
        raise TypeError("exact contact-policy original required")
    return asdict(original)


def contact_policy_original_from_wire_v1(raw):
    if type(raw) is not dict or set(raw) != set(D10ContactPolicyOriginalV1.__dataclass_fields__):
        raise ValueError("contact-policy original fields differ")
    ns = NamespaceId(**raw["namespace"])
    policy = ContactPolicy(**{**raw["policy"], "namespace": NamespaceId(**raw["policy"]["namespace"])})
    return D10ContactPolicyOriginalV1(**{**raw, "namespace": ns, "policy": policy})


class InstalledD10ContactPolicyServiceV1:
    def __init__(self, *, fences, owner_tickets, owner_service, namespace,
                 installation_id, signing_key, trusted_now_utc, create=False):
        if (type(owner_tickets) is not AuthorityV2OwnerTicketStore
                or owner_tickets._core is not fences.core or owner_service.core is not fences.core
                or owner_service.fences is not fences or owner_service.installation_id != installation_id
                or type(namespace) is not NamespaceId or type(signing_key) is not bytes or len(signing_key) != 32):
            raise AuthorityUnavailable("contact policy needs the actual paired Owner and Core")
        self.fences, self.core, self.tickets = fences, fences.core, owner_tickets
        self.owner_service, self.namespace, self.installation_id = owner_service, namespace, installation_id
        self._key, self._clock = signing_key, trusted_now_utc
        with self.core._tx() as db:
            row = db.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (TABLE,)).fetchone()
            if row is None and create:
                db.execute(DDL)
            elif row is None or row[0] != DDL:
                raise AuthorityUnavailable("installed contact-policy ledger schema differs")
            for name, ddl in TRIGGERS:
                row = db.execute("SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?", (name,)).fetchone()
                if row is None and create:
                    db.execute(ddl)
                elif row is None or row[0] != ddl:
                    raise AuthorityUnavailable("installed contact-policy immutability schema differs")

    def _sign(self, material):
        return hmac.new(self._key, canonical_serialize(material).encode("utf-8"), hashlib.sha256).hexdigest()

    def _decode(self, row):
        original = contact_policy_original_from_wire_v1(json.loads(row[6]))
        material = asdict(original); material.pop("signature")
        if (row != (original.authority_namespace, original.installation_id, original.policy.policy_id,
                original.policy.version, original.operation_id, original.action,
                canonical_serialize(original), original.digest, original.signature)
                or not hmac.compare_digest(original.signature, self._sign(material))
                or original.authority_namespace != self.fences.namespace
                or original.installation_id != self.installation_id or original.namespace != self.namespace):
            raise AuthorityUnavailable("contact-policy ledger original changed")
        return original

    def _head(self, db, policy_id):
        rows = db.execute("SELECT * FROM " + TABLE + " WHERE authority_namespace=? AND installation_id=? "
            "AND policy_id=? ORDER BY policy_version DESC, CASE action WHEN 'revoke' THEN 0 ELSE 1 END LIMIT 1",
            (self.fences.namespace, self.installation_id, policy_id)).fetchall()
        return None if not rows else self._decode(rows[0])

    def _current_owner(self, db, observed, permit):
        head = self.tickets.current_migration_head_in_tx(db, authority_namespace=self.fences.namespace)
        if (head is None or head.state != "active" or head.guard != observed.guard
                or head.guard.authority_id != permit.authority_id
                or head.guard.pending_revoke_operation_id is not None
                or head.guard.minimum_revocation_epoch
                or head.guard.minimum_revocation_revision >= head.guard.authorization_revision):
            raise AuthorityUnavailable("contact-policy Owner head changed")
        return head

    def change(self, *, credential, subject, permit, actor, session_token, session_request,
               operation_id, action, policy):
        if (type(permit) is not FencePermitV2 or permit.operation != "write"
                or type(session_request) is not OwnerSessionLoginRequestV1
                or session_request.audience != "owner" or type(policy) is not ContactPolicy
                or policy.namespace != self.namespace or action not in {"issue", "revoke"}
                or type(operation_id) is not str or not operation_id):
            raise AuthorityUnavailable("contact policy requires an authenticated Owner write")
        observed, returned = self.owner_service.get_current_owner_authority_for_fence_v1(
            credential=credential, subject=subject, permit=permit, actor=actor,
            session_token=session_token, session_request=session_request)
        if returned != permit:
            raise AuthorityUnavailable("contact-policy Owner qualification changed its fence")
        with self.fences._frozen() as (db, deletion, execution, _):
            anchor = self.fences._current_locked(db, deletion, execution)
            self.fences.fences.validate_fence_locked(db, permit, subject=subject, current_anchor=anchor)
            self.tickets._owner_sessions.require_current_in_tx(db, token=session_token, request=session_request)
            head = self._current_owner(db, observed, permit)
            current = self._head(db, policy.policy_id)
            epoch = self._principal_epoch(db, head)
            prior = db.execute("SELECT * FROM " + TABLE + " WHERE authority_namespace=? AND installation_id=? AND operation_id=?",
                (self.fences.namespace, self.installation_id, operation_id)).fetchone()
            if prior is not None:
                value = self._decode(prior)
                if ((value.action, value.policy, value.owner_actor_id, value.owner_head_digest) != (
                        action, policy, actor, head.guard.authorization_head) or current != value
                        or value.owner_principal_epoch != epoch
                        or action == "issue" and self._clock() >= policy.window_end):
                    raise AuthorityUnavailable("contact-policy operation replay differs")
                return value
            if action == "issue":
                if (current is not None and current.action == "issue" and current.policy == policy
                        and current.owner_actor_id == actor
                        and current.owner_head_digest == head.guard.authorization_head
                        and current.owner_principal_epoch == epoch and self._clock() < policy.window_end):
                    # A previous Core issue may precede its Graph mirror. Reuse
                    # that exact still-current consent; do not create a nonce.
                    return current
                if policy.version != (1 if current is None else current.policy.version + 1):
                    raise AuthorityUnavailable("contact policy must advance its exact current version")
                if self._clock() >= policy.window_end:
                    raise AuthorityUnavailable("contact policy window already expired")
            elif current is None or current.action != "issue" or current.policy != policy:
                raise AuthorityUnavailable("revocation must name the exact issued contact policy")
            material = dict(authority_namespace=self.fences.namespace, authority_id=self.core._id(db),
                installation_id=self.installation_id, namespace=self.namespace, policy=policy,
                owner_actor_id=actor, owner_head_digest=head.guard.authorization_head,
                owner_authorization_revision=head.guard.authorization_revision,
                owner_principal_epoch=epoch,
                window_id=contact_window_id_v2(policy), operation_id=operation_id, action=action,
                issued_at_utc=self._clock(), schema="d10.owner-contact-policy-original.v1")
            value = D10ContactPolicyOriginalV1(**material, signature=self._sign(material))
            db.execute("INSERT INTO " + TABLE + " VALUES(?,?,?,?,?,?,?,?,?)", (
                value.authority_namespace, value.installation_id, policy.policy_id, policy.version,
                operation_id, action, canonical_serialize(value), value.digest, value.signature))
            return value

    def read_current(self, *, credential, subject, permit, policy_id):
        observed, returned = self.owner_service.get_current_background_owner_authority_for_fence_v1(
            credential=credential, subject=subject, permit=permit)
        if returned != permit:
            raise AuthorityUnavailable("contact-policy read changed its Owner fence")
        with self.fences._frozen() as (db, deletion, execution, _):
            anchor = self.fences._current_locked(db, deletion, execution)
            self.fences.fences.validate_fence_locked(db, permit, subject=subject, current_anchor=anchor)
            head = self._current_owner(db, observed, permit)
            value = self._head(db, policy_id)
            now = self._clock()
            if (value is None or value.action != "issue" or value.authority_id != self.core._id(db)
                    or value.owner_head_digest != head.guard.authorization_head
                    or value.owner_authorization_revision != head.guard.authorization_revision
                    or value.owner_principal_epoch != self._principal_epoch(db, head)
                    or not value.policy.window_start <= now < value.policy.window_end):
                return None
            return value

    def _principal_epoch(self, db, head):
        # Principal epoch is checked without requiring a still-live dashboard
        # session: an issued policy outlives logout, but not principal revocation.
        row = db.execute("SELECT revocation_epoch FROM authority_owner_session_principals_v1 "
            "WHERE authority_namespace=? AND installation_id=? AND principal_json=?",
            (self.fences.namespace, self.installation_id, _principal(head.issue_operation.principal))).fetchone()
        return row[0] if row is not None else 0
