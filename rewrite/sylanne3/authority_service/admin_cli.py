"""Offline Owner pairing commands for an already-open installed Authority.

The caller is the separate Authority administrator process. This module does
not accept a database path, credential, callback name, or client certificate
digest from command line input. A standalone loader is deliberately absent
until the installer provides a pinned configuration registry.
"""

from __future__ import annotations

import argparse
import ctypes
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import json
import os
import sys
from typing import TextIO

from .contract import AuthorityUnavailable, identifier
from .core import AuthorityServiceCore
from .v2_owner_contract import (
    OwnerActorBindingV1, OwnerClaimTicketV1, OwnerPrincipalV1,
    from_wire as owner_from_wire,
)
from .v2_owner_proof import (
    OwnerCredentialRegistrationV1, from_wire as proof_from_wire,
)
from ..host.owner_identity_sqlite import AuthorityOwnerPairingSource
from ..graph_coordinator import namespace_ref


_REVOKE = frozenset({"revoke-creation", "revoke-credential", "revoke-actor"})
_ACTIONS = (
    "inspect", "pair-creation", "pair-credential", "pair-actor",
    "revoke-creation", "revoke-credential", "revoke-actor",
)
_MAX_INPUT_CHARS = 16_384


class AdminCliHold(AuthorityUnavailable):
    """No verified local administrator or installed Authority binding."""


@dataclass(frozen=True, slots=True)
class AdminOwnerCommandV1:
    action: str
    authority_namespace: str
    profile_id: str
    installation_id: str
    payload: object | None = None
    valid_until_utc: datetime | None = None

    def __post_init__(self) -> None:
        if self.action not in _ACTIONS:
            raise ValueError("unsupported Owner administration command")
        for name in ("authority_namespace", "profile_id", "installation_id"):
            identifier(getattr(self, name), name)
        if self.valid_until_utc is not None and (
            type(self.valid_until_utc) is not datetime
            or self.valid_until_utc.tzinfo is None
            or self.valid_until_utc.utcoffset() != timedelta(0)
            or self.valid_until_utc.microsecond
        ):
            raise ValueError("pairing expiry must be canonical UTC seconds")


def _require_windows_administrator_token() -> None:
    """Check effective Windows token membership, including UAC filtering."""
    if os.name != "nt":
        raise AdminCliHold("Windows administrator token is unavailable; HOLD")
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi.ConvertStringSidToSidW.argtypes = (ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_void_p))
    advapi.ConvertStringSidToSidW.restype = ctypes.c_int
    advapi.CheckTokenMembership.argtypes = (
        ctypes.c_void_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_int),
    )
    advapi.CheckTokenMembership.restype = ctypes.c_int
    kernel.LocalFree.argtypes = (ctypes.c_void_p,)
    kernel.LocalFree.restype = ctypes.c_void_p
    sid = ctypes.c_void_p()
    if not advapi.ConvertStringSidToSidW("S-1-5-32-544", ctypes.byref(sid)):
        raise AdminCliHold("Windows administrator SID lookup failed; HOLD")
    try:
        member = ctypes.c_int()
        if not advapi.CheckTokenMembership(None, sid, ctypes.byref(member)) or not member.value:
            raise AdminCliHold("effective Windows administrator token required; HOLD")
    finally:
        kernel.LocalFree(sid)


def _installed(daemon: object, command: AdminOwnerCommandV1):
    # Exact class and same-Core checks prevent an injected plugin facade from
    # choosing an unrelated database or installing its own permissive callback.
    from .daemon import AuthorityDaemon

    if type(daemon) is not AuthorityDaemon:
        raise AdminCliHold("installed Authority daemon required; HOLD")
    if os.name == "nt":
        _require_windows_administrator_token()
    else:
        from .linux_installation_security_v1 import require_linux_administrator_v1
        require_linux_administrator_v1()
    daemon.require_offline_admin_maintenance()
    core, pairings = daemon.core, daemon.owner_pairings
    if (type(core) is not AuthorityServiceCore
            or type(pairings) is not AuthorityOwnerPairingSource
            or pairings._core is not core):
        raise AdminCliHold("installed Owner pairing store differs; HOLD")
    certificate = daemon.installed_peer_certificate_sha256(
        command.profile_id, command.installation_id,
        command.authority_namespace,
    )
    if (type(certificate) is not str or len(certificate) != 64
            or any(char not in "0123456789abcdef" for char in certificate)):
        raise AdminCliHold("installed peer certificate identity is unavailable; HOLD")
    permission = ("owner_identity_revoke" if command.action in _REVOKE
                  else "owner_identity_pair")
    credential = daemon.require_local_administrator(permission, command.authority_namespace)
    with core._tx() as db:
        pairings._require_mode(db)
        pairings._scope(db, command.authority_namespace, core._id(db))
    return core, pairings, certificate, credential


def _match_identity(command: AdminOwnerCommandV1, value: object,
                    authority_id: str) -> None:
    if (value.authority_id != authority_id
            or value.installation_id != command.installation_id
            or (value.authority_namespace if type(value) is OwnerCredentialRegistrationV1
                else namespace_ref(value.namespace)) != command.authority_namespace):
        raise AdminCliHold("Owner payload differs from installed Authority identity; HOLD")


def run_installed_admin_command_v1(daemon: object,
                                   command: AdminOwnerCommandV1) -> dict[str, object]:
    """Use only an installed daemon and current OS administrator token."""
    if type(command) is not AdminOwnerCommandV1:
        raise TypeError("typed Owner administration command required")
    core, pairings, certificate, credential = _installed(daemon, command)
    with core._tx() as db:
        authority_id = core._id(db)
    action, value = command.action, command.payload
    if action == "inspect":
        if value is not None and type(value) is not OwnerPrincipalV1:
            raise TypeError("inspect selector must be an Owner principal")
        creation = pairings.current_creation_pairing(command.authority_namespace)
        pairing = (pairings.current_owner_pairing(command.authority_namespace, value)
                   if value is not None else None)
        now = pairings._now()
        return {
            "status": "inspected", "authority_id": authority_id,
            "authority_namespace": command.authority_namespace,
            "installation_id": command.installation_id,
            "creation_paired": bool(
                creation is not None
                and creation.ticket.authority_id == authority_id
                and creation.ticket.installation_id == command.installation_id
                and creation.client_certificate_sha256 == certificate
                and now < creation.valid_until_utc
            ),
            "principal_queried": value is not None,
            "credential_paired": bool(
                pairing is not None
                and pairing.registration.authority_id == authority_id
                and pairing.registration.installation_id == command.installation_id
                and pairing.client_certificate_sha256 == certificate
                and now < pairing.valid_until_utc
            ),
        }
    if action == "pair-creation":
        if type(value) is not OwnerClaimTicketV1 or command.valid_until_utc is None:
            raise TypeError("typed creation ticket and expiry required")
        _match_identity(command, value, authority_id)
        pair_original = getattr(daemon, "pair_original_creation_ticket", None)
        if not callable(pair_original):
            raise AdminCliHold("pinned W01 original creation verification is unavailable; HOLD")
        ticket_expiry = datetime.strptime(value.expires_at_utc, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc)
        if command.valid_until_utc > ticket_expiry:
            raise AdminCliHold("pairing cannot outlive original claim ticket; HOLD")
        try:
            pair_original(
                administrator_credential=credential,
                authority_namespace=command.authority_namespace, ticket=value,
                client_certificate_sha256=certificate,
                valid_until_utc=command.valid_until_utc)
        except Exception as exc:
            raise AdminCliHold("pinned W01 original creation verification failed; HOLD") from exc
    elif action == "pair-credential":
        if type(value) is not OwnerCredentialRegistrationV1 or command.valid_until_utc is None:
            raise TypeError("typed Owner registration and expiry required")
        _match_identity(command, value, authority_id)
        pairings.pair_credential(
            administrator_credential=credential, registration=value,
            client_certificate_sha256=certificate,
            valid_until_utc=command.valid_until_utc,
        )
    elif action == "pair-actor":
        if type(value) is not OwnerActorBindingV1:
            raise TypeError("typed Owner actor binding required")
        _match_identity(command, value, authority_id)
        pairings.pair_actor(administrator_credential=credential, binding=value)
    elif action == "revoke-creation":
        if value is not None:
            raise TypeError("creation revoke takes no payload")
        pairings.revoke_creation(administrator_credential=credential,
                                 authority_namespace=command.authority_namespace)
    elif action == "revoke-credential":
        if type(value) is not OwnerPrincipalV1:
            raise TypeError("typed Owner principal required")
        pairings.revoke_credential(
            administrator_credential=credential,
            authority_namespace=command.authority_namespace, principal=value,
        )
    else:
        if type(value) is not OwnerActorBindingV1:
            raise TypeError("typed Owner actor binding required")
        _match_identity(command, value, authority_id)
        pairings.revoke_actor(administrator_credential=credential, binding=value)
    return {"status": "applied", "action": action,
            "authority_namespace": command.authority_namespace}


def _payload(action: str, wire: object) -> tuple[object | None, datetime | None]:
    if type(wire) is not dict:
        raise ValueError("Owner command input must be a JSON object")
    if action in {"inspect", "revoke-credential"}:
        expected = set() if action == "inspect" and not wire else {"principal"}
        if set(wire) != expected:
            raise ValueError("Owner principal selector fields differ")
        return (owner_from_wire(wire["principal"]) if expected else None), None
    if action == "revoke-creation":
        if wire:
            raise ValueError("creation revoke input must be empty")
        return None, None
    field = {
        "pair-creation": "ticket", "pair-credential": "registration",
        "pair-actor": "binding", "revoke-actor": "binding",
    }[action]
    expected = {field, "valid_until_utc"} if action in {
        "pair-creation", "pair-credential"} else {field}
    if set(wire) != expected:
        raise ValueError("Owner pairing input fields differ")
    value = (proof_from_wire(wire[field]) if field == "registration"
             else owner_from_wire(wire[field]))
    if "valid_until_utc" not in wire:
        return value, None
    stamp = wire["valid_until_utc"]
    if type(stamp) is not str or len(stamp) != 20:
        raise ValueError("pairing expiry must be UTC seconds")
    parsed = datetime.strptime(stamp, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != stamp:
        raise ValueError("pairing expiry must be canonical UTC seconds")
    return value, parsed


def main(argv: list[str] | None = None, *, daemon: object | None = None,
         input_stream: TextIO | None = None,
         output_stream: TextIO | None = None) -> int:
    """Embedded local CLI. A standalone invocation has no installed trust root."""
    parser = argparse.ArgumentParser(prog="sylanne-authority-admin")
    parser.add_argument("action", choices=_ACTIONS)
    parser.add_argument("--namespace", required=True)
    parser.add_argument("--profile-id", required=True)
    parser.add_argument("--installation-id", required=True)
    args = parser.parse_args(argv)
    output = output_stream or sys.stdout
    try:
        if daemon is None:
            raise AdminCliHold("installed Authority daemon is unavailable; HOLD")
        # Authorize before reading possibly untrusted JSON from the console.
        probe = AdminOwnerCommandV1(
            args.action, args.namespace, args.profile_id, args.installation_id)
        _installed(daemon, probe)
        source = input_stream or sys.stdin
        raw = ("{}" if args.action in {"inspect", "revoke-creation"}
               else source.read(_MAX_INPUT_CHARS + 1))
        if len(raw) > _MAX_INPUT_CHARS:
            raise ValueError("Owner command input is too large")
        payload, expiry = _payload(args.action, json.loads(raw or "{}"))
        result = run_installed_admin_command_v1(daemon, AdminOwnerCommandV1(
            args.action, args.namespace, args.profile_id,
            args.installation_id, payload, expiry,
        ))
        print(json.dumps(result, sort_keys=True), file=output)
        return 0
    except (AuthorityUnavailable, TypeError, ValueError, KeyError) as exc:
        print(json.dumps({"status": "HOLD", "reason": str(exc)}, sort_keys=True),
              file=output)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ("AdminCliHold", "AdminOwnerCommandV1", "run_installed_admin_command_v1", "main")
