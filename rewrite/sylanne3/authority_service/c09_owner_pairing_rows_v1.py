"""Exact C09 inventory for the installer-owned Owner identity tables.

Identity/public-key pairings and revoke state are content-free authority facts.
A source deletion must neither drop them nor turn a revoked binding active.
"""
from __future__ import annotations
import json

from .contract import AuthorityUnavailable, identifier
from .v2_owner_contract import (
    OwnerClaimTicketV1, OwnerActorBindingV1, OwnerPrincipalV1,
    canonical_bytes, decode_bytes,
)
from .v2_owner_proof import OwnerCredentialRegistrationV1, from_wire as proof_from_wire
from ..host.owner_identity_sqlite import (
    _CREATION, _CREDENTIAL, _ACTOR, _ACTOR_UNIQUE, _certificate, _time, _registration_bytes,
)

SCHEMAS = {
    "authority_owner_creation_pairings_v1": _CREATION,
    "authority_owner_credential_pairings_v1": _CREDENTIAL,
    "authority_owner_actor_bindings_v1": _ACTOR,
}
COLUMNS = {
    "authority_owner_creation_pairings_v1": ("authority_namespace", "ticket_bytes", "client_certificate_sha256", "valid_until_utc"),
    "authority_owner_credential_pairings_v1": ("authority_namespace", "principal_bytes", "registration_bytes", "client_certificate_sha256", "valid_until_utc"),
    "authority_owner_actor_bindings_v1": ("authority_namespace", "actor_id", "installation_id", "principal_bytes", "binding_bytes", "revision", "active"),
}


def verify_owner_pairing_schema_v1(db):
    seen = {row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    paired = set(SCHEMAS) & seen
    if paired and not {"authority_owner_creation_pairings_v1", "authority_owner_credential_pairings_v1"} <= paired:
        raise AuthorityUnavailable("C09 Owner pairing schema is partial")
    for name in paired:
        if db.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (name,)).fetchone() != (SCHEMAS[name],):
            raise AuthorityUnavailable("C09 installed Owner pairing schema differs")
    if "authority_owner_actor_bindings_v1" in paired and db.execute(
            "SELECT sql FROM sqlite_master WHERE type='index' AND name='authority_owner_actor_live_principal_v1'").fetchone() != (_ACTOR_UNIQUE,):
        raise AuthorityUnavailable("C09 Owner pairing uniqueness schema differs")


def _original(raw, cls):
    if type(raw) is not bytes:
        raise ValueError("Owner pairing original must be SQLite BLOB bytes")
    value = decode_bytes(raw)
    if type(value) is not cls or canonical_bytes(value) != raw:
        raise ValueError("Owner pairing typed original bytes differ")
    return value


def validate_owner_pairing_row_v1(table, columns, row, *, authority_id):
    try:
        if table not in SCHEMAS or tuple(columns) != COLUMNS[table]:
            raise ValueError("Owner pairing table/columns differ")
        namespace = row[0]
        identifier(namespace, "authority_namespace")
        if table == "authority_owner_creation_pairings_v1":
            ticket = _original(row[1], OwnerClaimTicketV1)
            from ..graph_coordinator import namespace_ref
            if ticket.authority_id != authority_id or namespace_ref(ticket.namespace) != namespace:
                raise ValueError("Owner creation pairing namespace/authority differs")
            _certificate(row[2]); _time(row[3])
        elif table == "authority_owner_credential_pairings_v1":
            principal = _original(row[1], OwnerPrincipalV1)
            registration = proof_from_wire(json.loads(row[2]))
            if (type(registration) is not OwnerCredentialRegistrationV1 or type(row[2]) is not bytes
                    or _registration_bytes(registration) != row[2] or registration.principal != principal
                    or registration.authority_id != authority_id or registration.authority_namespace != namespace):
                raise ValueError("Owner credential pairing identity differs")
            _certificate(row[3]); _time(row[4])
        else:
            from ..graph_coordinator import namespace_ref
            principal = _original(row[3], OwnerPrincipalV1)
            binding = _original(row[4], OwnerActorBindingV1)
            if (binding.authority_id != authority_id or namespace_ref(binding.namespace) != namespace
                    or (binding.actor_id, binding.installation_id, binding.principal, binding.revision) !=
                       (row[1], row[2], principal, row[5]) or type(row[6]) is not int or row[6] not in (0, 1)):
                raise ValueError("Owner actor pairing/revoke state differs")
        return namespace
    except (TypeError, ValueError, KeyError, UnicodeError) as exc:
        raise AuthorityUnavailable("C09 cannot classify installed Owner pairing original: " + table) from exc
