"""Transport-neutral owner-claim and authorization-guard DTOs.

These values describe an independently paired creator claim and the Authority
control-plane sequence. Parsing a ticket or receipt does not consume a ticket,
authenticate its presenter, install a graph grant, or authorize content access.
The business graph remains the only store of grant capabilities and ACL state.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import hashlib
import json
import re
from typing import Any

from .contract import identifier
from ..runtime_contracts import NamespaceId


SCHEMA = "sylanne3.authority.owner.v1"
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_HEAD = re.compile(r"(?:genesis|sha256:[0-9a-f]{64})\Z")
_CHALLENGE = re.compile(r"[A-Za-z0-9_-]{32,128}\Z")
_UTC = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")


def _digest(value: str, name: str, *, head: bool = False) -> None:
    if type(value) is not str or (_HEAD if head else _DIGEST).fullmatch(value) is None:
        raise ValueError(f"invalid {name}")


def _namespace(value: NamespaceId) -> None:
    if type(value) is not NamespaceId:
        raise TypeError("namespace must be NamespaceId")


def _revision(value: int, name: str, *, minimum: int = 0) -> None:
    if type(value) is not int or value < minimum:
        raise ValueError(f"{name} must be an integer >= {minimum}")


def _utc(value: str) -> None:
    if type(value) is not str or _UTC.fullmatch(value) is None:
        raise ValueError("expiry must be canonical UTC seconds")
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise ValueError("expiry is not a valid UTC instant") from exc


@dataclass(frozen=True, slots=True)
class OwnerPrincipalV1:
    """A stable account incarnation, distinct from a dashboard display name."""

    identity_provider: str
    account_ref: str
    account_incarnation: str

    def __post_init__(self) -> None:
        for name in ("identity_provider", "account_ref", "account_incarnation"):
            identifier(getattr(self, name), name)


@dataclass(frozen=True, slots=True)
class OwnerClaimTicketV1:
    """One independently paired claim for one newly created namespace."""

    authority_id: str
    installation_id: str
    namespace: NamespaceId
    principal: OwnerPrincipalV1
    ticket_id: str
    creation_operation_id: str
    creation_digest: str
    policy_digest: str
    challenge: str
    expires_at_utc: str
    schema: str = SCHEMA

    def __post_init__(self) -> None:
        if self.schema != SCHEMA:
            raise ValueError("unknown owner contract schema")
        for name in ("authority_id", "installation_id", "ticket_id",
                     "creation_operation_id"):
            identifier(getattr(self, name), name)
        _namespace(self.namespace)
        if type(self.principal) is not OwnerPrincipalV1:
            raise TypeError("stable owner principal is required")
        _digest(self.creation_digest, "creation_digest")
        _digest(self.policy_digest, "policy_digest")
        if type(self.challenge) is not str or _CHALLENGE.fullmatch(self.challenge) is None:
            raise ValueError("claim challenge must be an opaque random token")
        _utc(self.expires_at_utc)


@dataclass(frozen=True, slots=True)
class OwnerAuthorizationGuardV1:
    """Authority sequence and minimum revoke watermark, never a graph ACL."""

    authority_id: str
    installation_id: str
    namespace: NamespaceId
    authorization_revision: int
    authorization_head: str
    minimum_revocation_revision: int
    minimum_revocation_epoch: int
    pending_revoke_operation_id: str | None = None
    schema: str = SCHEMA

    def __post_init__(self) -> None:
        if self.schema != SCHEMA:
            raise ValueError("unknown owner contract schema")
        identifier(self.authority_id, "authority_id")
        identifier(self.installation_id, "installation_id")
        _namespace(self.namespace)
        _revision(self.authorization_revision, "authorization_revision")
        _digest(self.authorization_head, "authorization_head", head=True)
        if (self.authorization_revision == 0) != (self.authorization_head == "genesis"):
            raise ValueError("authorization genesis must match revision zero")
        _revision(self.minimum_revocation_revision, "minimum_revocation_revision")
        _revision(self.minimum_revocation_epoch, "minimum_revocation_epoch")
        if self.pending_revoke_operation_id is not None:
            identifier(self.pending_revoke_operation_id, "pending_revoke_operation_id")


@dataclass(frozen=True, slots=True)
class OwnerAuthorizationOperationV1:
    """Exact issue/revoke operation identity; service admission is separate."""

    action: str
    operation_id: str
    authority_id: str
    installation_id: str
    namespace: NamespaceId
    principal: OwnerPrincipalV1
    grant_id: str
    grant_digest: str
    expected_grant_revision: int
    expected_guard: OwnerAuthorizationGuardV1
    ticket: OwnerClaimTicketV1 | None = None
    request_digest: str | None = None
    schema: str = SCHEMA

    def __post_init__(self) -> None:
        if self.schema != SCHEMA or self.action not in {"issue", "revoke"}:
            raise ValueError("unknown owner operation schema or action")
        for name in ("operation_id", "authority_id", "installation_id", "grant_id"):
            identifier(getattr(self, name), name)
        _namespace(self.namespace)
        if type(self.principal) is not OwnerPrincipalV1:
            raise TypeError("stable owner principal is required")
        _digest(self.grant_digest, "grant_digest")
        _revision(self.expected_grant_revision, "expected_grant_revision",
                  minimum=0 if self.action == "issue" else 1)
        if type(self.expected_guard) is not OwnerAuthorizationGuardV1:
            raise TypeError("current authorization guard is required")
        if (self.expected_guard.authority_id != self.authority_id
                or self.expected_guard.installation_id != self.installation_id
                or self.expected_guard.namespace != self.namespace):
            raise ValueError("operation differs from expected guard identity")
        if self.action == "issue":
            if self.expected_grant_revision != 0 or type(self.ticket) is not OwnerClaimTicketV1:
                raise ValueError("first issue requires an unconsumed claim ticket")
            if (self.ticket.authority_id != self.authority_id
                    or self.ticket.installation_id != self.installation_id
                    or self.ticket.namespace != self.namespace
                    or self.ticket.principal != self.principal
                    or self.ticket.creation_operation_id == self.operation_id):
                raise ValueError("claim ticket differs from issue identity")
        elif self.ticket is not None:
            raise ValueError("revoke cannot consume a claim ticket")
        expected_digest = "sha256:" + hashlib.sha256(
            _canonical_json(_operation_wire(self, include_digest=False))).hexdigest()
        if self.request_digest is None:
            object.__setattr__(self, "request_digest", expected_digest)
        elif self.request_digest != expected_digest:
            raise ValueError("owner operation request digest differs")


@dataclass(frozen=True, slots=True)
class OwnerAuthorizationReceiptV1:
    """Phase assertion; only an independently verified service receipt counts."""

    operation: OwnerAuthorizationOperationV1
    phase: str
    receipt_ref: str
    guard: OwnerAuthorizationGuardV1
    grant_revision: int | None = None
    graph_access_epoch: int | None = None
    schema: str = SCHEMA

    def __post_init__(self) -> None:
        if self.schema != SCHEMA or self.phase not in {"pending", "committed"}:
            raise ValueError("unknown owner receipt schema or phase")
        if type(self.operation) is not OwnerAuthorizationOperationV1:
            raise TypeError("owner operation is required")
        identifier(self.receipt_ref, "receipt_ref")
        if type(self.guard) is not OwnerAuthorizationGuardV1:
            raise TypeError("authorization guard is required")
        operation = self.operation
        if (self.guard.authority_id != operation.authority_id
                or self.guard.installation_id != operation.installation_id
                or self.guard.namespace != operation.namespace
                or self.guard.authorization_revision
                < operation.expected_guard.authorization_revision
                or self.guard.minimum_revocation_revision
                < operation.expected_guard.minimum_revocation_revision
                or self.guard.minimum_revocation_epoch
                < operation.expected_guard.minimum_revocation_epoch):
            raise ValueError("owner receipt guard differs from operation")
        if self.phase == "pending":
            if self.grant_revision is not None or self.graph_access_epoch is not None:
                raise ValueError("pending owner operation has no graph grant receipt")
            if (operation.action == "revoke"
                    and self.guard.pending_revoke_operation_id != operation.operation_id):
                raise ValueError("pending revoke requires independent content barrier")
        else:
            if (self.guard.authorization_revision
                    <= operation.expected_guard.authorization_revision):
                raise ValueError("committed owner operation needs a newer authorization head")
            _revision(self.grant_revision, "grant_revision", minimum=1)
            _revision(self.graph_access_epoch, "graph_access_epoch")
            if self.grant_revision != operation.expected_grant_revision + 1:
                raise ValueError("owner grant revision differs from operation")
            if (operation.action == "revoke"
                    and self.guard.minimum_revocation_revision
                    < self.guard.authorization_revision):
                raise ValueError("committed revoke lacks an independent watermark")


@dataclass(frozen=True, slots=True)
class OwnerGraphCommitProofV1:
    """Canonical graph receipt identity; trust comes only from graph verification."""

    namespace: NamespaceId
    operation_id: str
    request_digest: str
    grant_id: str
    grant_digest: str
    graph_incarnation: str
    grant_revision: int
    graph_access_epoch: int
    graph_epoch: int
    graph_receipt_digest: str
    schema: str = SCHEMA

    def __post_init__(self) -> None:
        if self.schema != SCHEMA:
            raise ValueError("unknown owner graph proof schema")
        _namespace(self.namespace)
        for name in ("operation_id", "grant_id", "graph_incarnation"):
            identifier(getattr(self, name), name)
        for name in ("request_digest", "grant_digest", "graph_receipt_digest"):
            _digest(getattr(self, name), name)
        _revision(self.grant_revision, "grant_revision", minimum=1)
        _revision(self.graph_access_epoch, "graph_access_epoch")
        _revision(self.graph_epoch, "graph_epoch")


def _namespace_wire(namespace: NamespaceId) -> dict[str, str]:
    return {"bot_id": namespace.bot_id, "persona_id": namespace.persona_id}


def _principal_wire(principal: OwnerPrincipalV1) -> dict[str, str]:
    return {"identity_provider": principal.identity_provider,
            "account_ref": principal.account_ref,
            "account_incarnation": principal.account_incarnation}


def _ticket_wire(value: OwnerClaimTicketV1) -> dict[str, Any]:
    return {"schema": value.schema, "kind": "owner_claim_ticket_v1",
            "authority_id": value.authority_id, "installation_id": value.installation_id,
            "namespace": _namespace_wire(value.namespace),
            "principal": _principal_wire(value.principal), "ticket_id": value.ticket_id,
            "creation_operation_id": value.creation_operation_id,
            "creation_digest": value.creation_digest, "policy_digest": value.policy_digest,
            "challenge": value.challenge, "expires_at_utc": value.expires_at_utc}


def _guard_wire(value: OwnerAuthorizationGuardV1) -> dict[str, Any]:
    return {"schema": value.schema, "kind": "owner_authorization_guard_v1",
            "authority_id": value.authority_id, "installation_id": value.installation_id,
            "namespace": _namespace_wire(value.namespace),
            "authorization_revision": value.authorization_revision,
            "authorization_head": value.authorization_head,
            "minimum_revocation_revision": value.minimum_revocation_revision,
            "minimum_revocation_epoch": value.minimum_revocation_epoch,
            "pending_revoke_operation_id": value.pending_revoke_operation_id}


def _operation_wire(value: OwnerAuthorizationOperationV1, *,
                    include_digest: bool = True) -> dict[str, Any]:
    result = {"schema": value.schema, "kind": "owner_authorization_operation_v1",
              "action": value.action, "operation_id": value.operation_id,
              "authority_id": value.authority_id,
              "installation_id": value.installation_id,
              "namespace": _namespace_wire(value.namespace),
              "principal": _principal_wire(value.principal),
              "grant_id": value.grant_id, "grant_digest": value.grant_digest,
              "expected_grant_revision": value.expected_grant_revision,
              "expected_guard": _guard_wire(value.expected_guard),
              "ticket": _ticket_wire(value.ticket) if value.ticket is not None else None}
    if include_digest:
        result["request_digest"] = value.request_digest
    return result


def to_wire(value: OwnerPrincipalV1 | OwnerClaimTicketV1 |
            OwnerAuthorizationGuardV1 | OwnerAuthorizationOperationV1 |
            OwnerAuthorizationReceiptV1 | OwnerGraphCommitProofV1) -> dict[str, Any]:
    if type(value) is OwnerGraphCommitProofV1:
        return {"schema": value.schema, "kind": "owner_graph_commit_proof_v1",
                "namespace": _namespace_wire(value.namespace),
                "operation_id": value.operation_id,
                "request_digest": value.request_digest,
                "grant_id": value.grant_id, "grant_digest": value.grant_digest,
                "graph_incarnation": value.graph_incarnation,
                "grant_revision": value.grant_revision,
                "graph_access_epoch": value.graph_access_epoch,
                "graph_epoch": value.graph_epoch,
                "graph_receipt_digest": value.graph_receipt_digest}
    if type(value) is OwnerPrincipalV1:
        return {"schema": SCHEMA, "kind": "owner_principal_v1", **_principal_wire(value)}
    if type(value) is OwnerClaimTicketV1:
        return _ticket_wire(value)
    if type(value) is OwnerAuthorizationGuardV1:
        return _guard_wire(value)
    if type(value) is OwnerAuthorizationOperationV1:
        return _operation_wire(value)
    if type(value) is OwnerAuthorizationReceiptV1:
        return {"schema": value.schema, "kind": "owner_authorization_receipt_v1",
                "operation": _operation_wire(value.operation), "phase": value.phase,
                "receipt_ref": value.receipt_ref, "guard": _guard_wire(value.guard),
                "grant_revision": value.grant_revision,
                "graph_access_epoch": value.graph_access_epoch}
    raise TypeError("unsupported owner contract value")


def _fields(value: object, expected: set[str], name: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != expected:
        raise ValueError(f"invalid {name} fields")
    return value


def _decode_namespace(value: object) -> NamespaceId:
    data = _fields(value, {"bot_id", "persona_id"}, "namespace")
    return NamespaceId(**data)


def _decode_principal(value: object) -> OwnerPrincipalV1:
    data = _fields(value, {"identity_provider", "account_ref",
                           "account_incarnation"}, "owner principal")
    return OwnerPrincipalV1(**data)


def from_wire(value: object) -> (OwnerPrincipalV1 | OwnerClaimTicketV1 |
                                  OwnerAuthorizationGuardV1 |
                                  OwnerAuthorizationOperationV1 |
                                  OwnerAuthorizationReceiptV1 | OwnerGraphCommitProofV1):
    if type(value) is not dict or value.get("schema") != SCHEMA:
        raise ValueError("unknown owner contract schema")
    kind = value.get("kind")
    if kind == "owner_graph_commit_proof_v1":
        _fields(value, {"schema", "kind", "namespace", "operation_id",
                        "request_digest", "grant_id", "grant_digest",
                        "graph_incarnation", "grant_revision", "graph_access_epoch",
                        "graph_epoch", "graph_receipt_digest"}, "owner graph proof")
        return OwnerGraphCommitProofV1(
            **{key: item for key, item in value.items() if key not in {
                "kind", "namespace"}}, namespace=_decode_namespace(value["namespace"]))
    if kind == "owner_principal_v1":
        _fields(value, {"schema", "kind", "identity_provider", "account_ref",
                        "account_incarnation"}, "owner principal")
        return _decode_principal({key: value[key] for key in (
            "identity_provider", "account_ref", "account_incarnation")})
    if kind == "owner_claim_ticket_v1":
        _fields(value, {"schema", "kind", "authority_id", "installation_id",
                        "namespace", "principal", "ticket_id", "creation_operation_id",
                        "creation_digest", "policy_digest", "challenge",
                        "expires_at_utc"}, "owner claim ticket")
        return OwnerClaimTicketV1(
            **{key: item for key, item in value.items() if key not in {
                "kind", "namespace", "principal"}},
            namespace=_decode_namespace(value["namespace"]),
            principal=_decode_principal(value["principal"]),
        )
    if kind == "owner_authorization_guard_v1":
        _fields(value, {"schema", "kind", "authority_id", "installation_id",
                        "namespace", "authorization_revision", "authorization_head",
                        "minimum_revocation_revision", "minimum_revocation_epoch",
                        "pending_revoke_operation_id"}, "owner authorization guard")
        return OwnerAuthorizationGuardV1(
            **{key: item for key, item in value.items() if key not in {
                "kind", "namespace"}}, namespace=_decode_namespace(value["namespace"]),
        )
    if kind == "owner_authorization_operation_v1":
        _fields(value, {"schema", "kind", "action", "operation_id", "authority_id",
                        "installation_id", "namespace", "principal", "grant_id",
                        "grant_digest", "expected_grant_revision", "expected_guard",
                        "ticket", "request_digest"}, "owner authorization operation")
        guard = from_wire(value["expected_guard"])
        ticket = from_wire(value["ticket"]) if value["ticket"] is not None else None
        if value["request_digest"] is None:
            raise ValueError("owner operation request digest is required")
        if type(guard) is not OwnerAuthorizationGuardV1 or (
                ticket is not None and type(ticket) is not OwnerClaimTicketV1):
            raise ValueError("owner operation nested kind mismatch")
        return OwnerAuthorizationOperationV1(
            **{key: item for key, item in value.items() if key not in {
                "kind", "namespace", "principal", "expected_guard", "ticket"}},
            namespace=_decode_namespace(value["namespace"]),
            principal=_decode_principal(value["principal"]),
            expected_guard=guard, ticket=ticket,
        )
    if kind == "owner_authorization_receipt_v1":
        _fields(value, {"schema", "kind", "operation", "phase", "receipt_ref",
                        "guard", "grant_revision", "graph_access_epoch"},
                "owner authorization receipt")
        operation, guard = from_wire(value["operation"]), from_wire(value["guard"])
        if (type(operation) is not OwnerAuthorizationOperationV1
                or type(guard) is not OwnerAuthorizationGuardV1):
            raise ValueError("owner receipt nested kind mismatch")
        return OwnerAuthorizationReceiptV1(
            operation, value["phase"], value["receipt_ref"], guard,
            value["grant_revision"], value["graph_access_epoch"], value["schema"],
        )
    raise ValueError("unknown owner contract kind")


def _canonical_json(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def canonical_bytes(value: OwnerPrincipalV1 | OwnerClaimTicketV1 |
                    OwnerAuthorizationGuardV1 | OwnerAuthorizationOperationV1 |
                    OwnerAuthorizationReceiptV1) -> bytes:
    return _canonical_json(to_wire(value))


def canonical_digest(value: OwnerPrincipalV1 | OwnerClaimTicketV1 |
                     OwnerAuthorizationGuardV1 | OwnerAuthorizationOperationV1 |
                     OwnerAuthorizationReceiptV1) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate owner JSON field")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError(f"nonfinite owner JSON number: {value}")


def decode_bytes(data: bytes) -> (OwnerPrincipalV1 | OwnerClaimTicketV1 |
                                  OwnerAuthorizationGuardV1 |
                                  OwnerAuthorizationOperationV1 |
                                  OwnerAuthorizationReceiptV1 | OwnerGraphCommitProofV1):
    if type(data) is not bytes:
        raise TypeError("owner wire data must be bytes")
    value = from_wire(json.loads(data.decode("utf-8"),
                                 object_pairs_hook=_unique_pairs,
                                 parse_constant=_reject_constant))
    if canonical_bytes(value) != data:
        raise ValueError("owner wire data is not canonical")
    return value


__all__ = ("SCHEMA", "OwnerPrincipalV1", "OwnerClaimTicketV1",
           "OwnerAuthorizationGuardV1", "OwnerAuthorizationOperationV1",
           "OwnerAuthorizationReceiptV1", "OwnerGraphCommitProofV1",
           "to_wire", "from_wire",
           "canonical_bytes", "canonical_digest", "decode_bytes")
