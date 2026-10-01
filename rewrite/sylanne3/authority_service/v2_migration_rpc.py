"""Strict migration management RPC slice for an installed mTLS route.

The route supplies its verified peer credential and current TLS channel binding.
The resolver must read administrator-installed identity and pairing facts; no
identity, permission, graph proof, or file path comes from the request body.
"""

from __future__ import annotations

from dataclasses import dataclass, fields
import re
from types import UnionType
from typing import Callable, Mapping, Union, get_args, get_origin, get_type_hints

from ..runtime.restore_anchor import RestoreAnchor
from ..runtime_contracts import NamespaceId, NamespaceRuntimeState, SnapshotRequirementsV2
from .contract import AuthorityUnavailable, identifier
from .v2_migration_contract import (
    MigrationCurrentNamespaceV2, MigrationPermitV2, MigrationPlanV2,
    MigrationRecoveryV2, MigrationStageReceiptV2, MigrationStatusV2,
    SourceSnapshotReceiptV2, TargetRecoveryReceiptV2,
)
from .v2_migration_service import AuthorityV2MigrationService
from .v2_owner_contract import (
    OwnerMigrationHeadV1, from_wire as owner_from_wire,
    to_wire as owner_to_wire,
)


SCHEMA = "sylanne.authority.migration.rpc.v2"
_HEX = re.compile(r"^[0-9a-f]{64}$")
_TYPES = frozenset({
    RestoreAnchor, NamespaceId, SnapshotRequirementsV2, MigrationPlanV2,
    MigrationPermitV2, SourceSnapshotReceiptV2, TargetRecoveryReceiptV2,
    MigrationStageReceiptV2, MigrationStatusV2, MigrationCurrentNamespaceV2,
    MigrationRecoveryV2, OwnerMigrationHeadV1,
})
_OPERATIONS = {
    "begin_transfer": ("request_id", "plan"),
    "revoke_source": ("request_id", "permit", "snapshot"),
    "prepare_target": ("request_id", "transfer_id"),
    "activate_target": ("request_id", "permit", "recovery"),
    "recover_transfer": ("transfer_id",),
}


def _wire(value: object) -> object:
    if type(value) is OwnerMigrationHeadV1:
        return owner_to_wire(value)
    if type(value) in _TYPES:
        return {field.name: _wire(getattr(value, field.name)) for field in fields(value)}
    if type(value) is NamespaceRuntimeState:
        return value.value
    if type(value) is tuple:
        return [_wire(item) for item in value]
    if value is None or type(value) in {str, int, bool}:
        return value
    raise AuthorityUnavailable("unsupported migration wire value")


def to_wire(value: object) -> object:
    """Encode only the known migration DTO graph; never arbitrary objects."""
    if type(value) not in _TYPES:
        raise AuthorityUnavailable("unknown migration DTO")
    return _wire(value)


def _decode(value: object, kind: object) -> object:
    origin = get_origin(kind)
    if origin in (UnionType, Union):
        variants = get_args(kind)
        if value is None and type(None) in variants:
            return None
        matches = [item for item in variants if item is not type(None)]
        if len(matches) != 1:
            raise ValueError("ambiguous migration wire union")
        return _decode(value, matches[0])
    if origin is tuple:
        args = get_args(kind)
        if type(value) is not list or len(args) != 2 or args[1] is not Ellipsis:
            raise ValueError("invalid migration wire tuple")
        return tuple(_decode(item, args[0]) for item in value)
    if kind is NamespaceRuntimeState:
        if type(value) is not str:
            raise ValueError("invalid migration state")
        return NamespaceRuntimeState(value)
    if kind is OwnerMigrationHeadV1:
        decoded = owner_from_wire(value)
        if type(decoded) is not OwnerMigrationHeadV1:
            raise ValueError("invalid Owner migration head kind")
        return decoded
    if kind in (str, int, bool):
        if type(value) is not kind:
            raise ValueError("invalid migration scalar")
        return value
    if kind in _TYPES:
        if type(value) is not dict:
            raise ValueError("invalid migration object")
        shape = fields(kind)
        if set(value) != {field.name for field in shape}:
            raise ValueError("migration wire fields differ")
        hints = get_type_hints(kind)
        return kind(**{field.name: _decode(value[field.name], hints[field.name])
                       for field in shape})
    raise ValueError("unknown migration wire type")


def from_wire(value: object, kind: type) -> object:
    """Reject extra fields, type coercion, and unknown DTO versions."""
    if kind not in _TYPES:
        raise AuthorityUnavailable("unknown migration DTO")
    try:
        result = _decode(value, kind)
        if to_wire(result) != value:
            raise ValueError("noncanonical migration DTO")
        return result
    except (TypeError, ValueError, KeyError, AttributeError) as exc:
        raise AuthorityUnavailable("invalid migration wire DTO") from exc


def response_from_wire(value: object, operation: str) -> (
        tuple[MigrationStageReceiptV2, MigrationStatusV2] | MigrationRecoveryV2):
    """Decode an exact versioned result before a client uses any returned permit."""
    if (operation not in _OPERATIONS or type(value) is not dict
            or set(value) != {"schema", "operation", "result"}
            or value["schema"] != SCHEMA or value["operation"] != operation
            or type(value["result"]) is not dict):
        raise AuthorityUnavailable("migration RPC response version differs")
    result = value["result"]
    if operation == "recover_transfer":
        if set(result) != {"recovery"}:
            raise AuthorityUnavailable("migration recovery response differs")
        return from_wire(result["recovery"], MigrationRecoveryV2)
    if set(result) != {"receipt", "status"}:
        raise AuthorityUnavailable("migration stage response differs")
    receipt = from_wire(result["receipt"], MigrationStageReceiptV2)
    status = from_wire(result["status"], MigrationStatusV2)
    phase = {
        "begin_transfer": "begun", "revoke_source": "revoked",
        "prepare_target": "target_prepared", "activate_target": "activated",
    }[operation]
    if (receipt.phase != phase or receipt.transfer_id != status.plan.transfer_id
            or receipt not in status.receipts):
        raise AuthorityUnavailable("migration stage response identity differs")
    return receipt, status


@dataclass(frozen=True, slots=True)
class MigrationManagementBindingV2:
    """Trusted installed facts for this verified peer, profile, and TLS channel."""

    peer_certificate_sha256: str
    profile_id: str
    channel_binding_sha256: str
    namespace: str
    role: str
    holder: str
    installation_id: str
    source_holder: str
    source_installation_id: str
    target_holder: str
    target_installation_id: str

    def __post_init__(self) -> None:
        for name in ("peer_certificate_sha256", "channel_binding_sha256"):
            value = getattr(self, name)
            if type(value) is not str or _HEX.fullmatch(value) is None:
                raise ValueError("invalid management channel identity")
        for name in ("profile_id", "namespace", "holder", "installation_id",
                     "source_holder", "source_installation_id", "target_holder",
                     "target_installation_id"):
            identifier(getattr(self, name), name)
        if self.role not in {"source", "target"}:
            raise ValueError("invalid migration management role")
        if (self.holder, self.installation_id) != (
            (self.source_holder, self.source_installation_id)
            if self.role == "source" else
            (self.target_holder, self.target_installation_id)
        ):
            raise ValueError("management role identity differs")


class MigrationRpcHandlerV2:
    """One route handler; installation owns the trusted resolver and services."""

    def __init__(self, services: Mapping[str, AuthorityV2MigrationService], *,
                 resolve_management_binding: Callable[[object, str, str, str],
                                                      MigrationManagementBindingV2 | None]):
        if (not isinstance(services, Mapping) or not services
                or not callable(resolve_management_binding)):
            raise ValueError("installed migration services and resolver required")
        self._services = dict(services)
        if any(type(name) is not str
               or type(service) is not AuthorityV2MigrationService
               or service.namespace != name
               for name, service in self._services.items()):
            raise ValueError("migration service namespace differs")
        self._resolve = resolve_management_binding

    def handle(self, *, credential: object, profile_id: str,
               channel_binding_sha256: str, command: object) -> dict[str, object]:
        if type(command) is not dict or command.get("schema") != SCHEMA:
            raise AuthorityUnavailable("migration RPC version unavailable")
        operation = command.get("operation")
        if type(operation) is not str or operation not in _OPERATIONS:
            raise AuthorityUnavailable("migration RPC operation unavailable")
        if set(command) != {"schema", "operation", "namespace", *_OPERATIONS[operation]}:
            raise AuthorityUnavailable("migration RPC fields differ")
        try:
            namespace = identifier(command["namespace"], "namespace")
            identifier(profile_id, "profile_id")
            if (type(channel_binding_sha256) is not str
                    or _HEX.fullmatch(channel_binding_sha256) is None):
                raise ValueError("channel binding unavailable")
            peer_hash = credential.certificate_sha256
            if type(peer_hash) is not str or _HEX.fullmatch(peer_hash) is None:
                raise ValueError("verified peer unavailable")
        except (AttributeError, TypeError, ValueError) as exc:
            raise AuthorityUnavailable("migration management channel unavailable") from exc
        service = self._services.get(namespace)
        if service is None:
            raise AuthorityUnavailable("migration namespace unavailable")
        try:
            binding = self._resolve(credential, profile_id,
                                    channel_binding_sha256, namespace)
        except Exception as exc:
            raise AuthorityUnavailable("trusted migration binding unavailable") from exc
        if (type(binding) is not MigrationManagementBindingV2
                or (binding.peer_certificate_sha256, binding.profile_id,
                    binding.channel_binding_sha256, binding.namespace)
                != (peer_hash, profile_id, channel_binding_sha256, namespace)):
            raise AuthorityUnavailable("migration management binding denied")
        role = "source" if operation in {"begin_transfer", "revoke_source"} else (
            "target" if operation in {"prepare_target", "activate_target"} else None)
        if role is not None and binding.role != role:
            raise AuthorityUnavailable("migration management role denied")
        subject = "mtls:sha256:" + peer_hash
        args = {"credential": credential, "subject": subject}
        if operation == "begin_transfer":
            plan = from_wire(command["plan"], MigrationPlanV2)
            self._plan_bound(plan, binding)
            args.update(plan=plan, request_id=identifier(command["request_id"], "request_id"))
        elif operation == "revoke_source":
            permit = from_wire(command["permit"], MigrationPermitV2)
            snapshot = from_wire(command["snapshot"], SourceSnapshotReceiptV2)
            self._permit_bound(permit, binding)
            args.update(permit=permit, snapshot=snapshot,
                        request_id=identifier(command["request_id"], "request_id"))
        elif operation == "prepare_target":
            args.update(transfer_id=identifier(command["transfer_id"], "transfer_id"),
                        request_id=identifier(command["request_id"], "request_id"))
        elif operation == "activate_target":
            permit = from_wire(command["permit"], MigrationPermitV2)
            recovery = from_wire(command["recovery"], TargetRecoveryReceiptV2)
            self._permit_bound(permit, binding)
            args.update(permit=permit, recovery=recovery,
                        request_id=identifier(command["request_id"], "request_id"))
        else:
            args["transfer_id"] = identifier(command["transfer_id"], "transfer_id")
        if operation != "begin_transfer":
            # The lookup is read-only. It binds transfer IDs and replay attempts
            # to installed source/target facts before any stage can be returned.
            transfer_id = args.get("transfer_id") or args["permit"].transfer_id
            history = service.recover_transfer(**{
                "credential": credential, "subject": subject,
                "transfer_id": transfer_id}).history
            self._plan_bound(history.plan, binding)
        result = getattr(service, operation)(**args)
        if operation == "recover_transfer":
            wire_result = {"recovery": to_wire(result)}
        else:
            receipt, status = result
            wire_result = {"receipt": to_wire(receipt), "status": to_wire(status)}
        return {"schema": SCHEMA, "operation": operation,
                "result": wire_result}

    @staticmethod
    def _plan_bound(plan: MigrationPlanV2, binding: MigrationManagementBindingV2) -> None:
        if (plan.namespace, plan.source_holder, plan.source_installation_id,
            plan.target_holder, plan.target_installation_id) != (
            binding.namespace, binding.source_holder,
            binding.source_installation_id, binding.target_holder,
            binding.target_installation_id):
            raise AuthorityUnavailable("migration plan differs from installed pairing")

    @staticmethod
    def _permit_bound(permit: MigrationPermitV2,
                      binding: MigrationManagementBindingV2) -> None:
        if (permit.namespace, permit.holder, permit.installation_id) != (
                binding.namespace, binding.holder, binding.installation_id):
            raise AuthorityUnavailable("migration permit differs from management role")


__all__ = ["SCHEMA", "MigrationManagementBindingV2", "MigrationRpcHandlerV2",
           "from_wire", "response_from_wire", "to_wire"]
