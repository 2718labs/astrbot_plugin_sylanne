"""Administrator-installed local migration peers and durable revocation.

This registry is fed by the Authority installation, never by an RPC body. It
does not verify source snapshots or target recovery; those are separate gates.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import re
from typing import Mapping

from ..runtime_contracts import NamespaceId
from .contract import AuthorityUnavailable, identifier
from .core import AuthorityServiceCore
from .mtls_server import AdministratorInstallationV2, MtlsPeerCredential
from .v2_migration_contract import MigrationPlanV2
from .v2_migration_rpc import MigrationManagementBindingV2


_HEX = re.compile(r"^[0-9a-f]{64}$")
_SCHEMA = "sylanne.authority.installed-migration-pairing.v1"
_ROLES = {
    "begin": "source", "revoke": "source",
    "prepare_target": "target", "activate_target": "target",
}


@dataclass(frozen=True, slots=True)
class AdministratorMigrationPairingV1:
    namespace: str
    namespace_id: NamespaceId
    source_certificate_sha256: str
    source_profile_id: str
    source_holder: str
    source_installation_id: str
    target_certificate_sha256: str
    target_profile_id: str
    target_holder: str
    target_installation_id: str

    def __post_init__(self) -> None:
        for name in ("namespace", "source_profile_id", "source_holder",
                     "source_installation_id", "target_profile_id",
                     "target_holder", "target_installation_id"):
            identifier(getattr(self, name), name)
        if type(self.namespace_id) is not NamespaceId:
            raise ValueError("migration namespace identity is invalid")
        for name in ("source_certificate_sha256", "target_certificate_sha256"):
            value = getattr(self, name)
            if type(value) is not str or _HEX.fullmatch(value) is None:
                raise ValueError("migration peer certificate is invalid")
        if (self.source_certificate_sha256 == self.target_certificate_sha256
                or self.source_holder == self.target_holder
                or self.source_installation_id == self.target_installation_id):
            raise ValueError("migration peers must be distinct")

    def canonical_record(self) -> str:
        value = {
            "schema": _SCHEMA, "namespace": self.namespace,
            "bot_id": self.namespace_id.bot_id,
            "persona_id": self.namespace_id.persona_id,
            "source": [self.source_certificate_sha256, self.source_profile_id,
                       self.source_holder, self.source_installation_id],
            "target": [self.target_certificate_sha256, self.target_profile_id,
                       self.target_holder, self.target_installation_id],
        }
        return json.dumps(value, sort_keys=True, separators=(",", ":"))


class InstalledMigrationPairingRegistry:
    """Same-Core pairing state; a revoked pairing never silently reactivates."""

    def __init__(
        self, core: AuthorityServiceCore,
        pairings: Mapping[str, AdministratorMigrationPairingV1],
        installations: Mapping[tuple[str, str], AdministratorInstallationV2],
        namespace_bindings: Mapping[tuple[str, str, NamespaceId], str],
    ) -> None:
        if type(core) is not AuthorityServiceCore or not pairings:
            raise AuthorityUnavailable("installed migration Authority is required")
        self._core = core
        self._pairings = dict(pairings)
        for namespace, pairing in self._pairings.items():
            if type(pairing) is not AdministratorMigrationPairingV1 or namespace != pairing.namespace:
                raise AuthorityUnavailable("installed migration pairing namespace differs")
            for role in ("source", "target"):
                cert = getattr(pairing, f"{role}_certificate_sha256")
                profile = getattr(pairing, f"{role}_profile_id")
                installed = installations.get((cert, profile))
                if (type(installed) is not AdministratorInstallationV2
                        or (installed.administrator_holder, installed.installation_id)
                        != (getattr(pairing, f"{role}_holder"),
                            getattr(pairing, f"{role}_installation_id"))
                        or namespace_bindings.get((cert, profile, pairing.namespace_id))
                        != namespace):
                    raise AuthorityUnavailable("migration peer differs from installed namespace")

    def install_schema(self, administrator_credential: object) -> None:
        """Installer-only transition; never called while opening an existing service."""
        for namespace in self._pairings:
            self._core._require(administrator_credential, "migration_pair_install", namespace)
        with self._core._tx() as db:
            db.execute("""
                CREATE TABLE IF NOT EXISTS authority_migration_pairings_v1(
                    namespace TEXT PRIMARY KEY,
                    record_json TEXT NOT NULL,
                    state TEXT NOT NULL CHECK(state IN ('active','revoked'))
                )
            """)

    def register(self, administrator_credential: object, namespace: str) -> None:
        """Persist one exact installed pairing; a revoked row cannot be reused."""
        pairing = self._pairings.get(namespace)
        if pairing is None:
            raise AuthorityUnavailable("migration pairing is not installed")
        self._core._require(administrator_credential, "migration_pair_register", namespace)
        with self._core._tx() as db:
            self._check_schema(db)
            if db.execute("SELECT 1 FROM authority_migration_pairings_v1 WHERE namespace=?",
                          (namespace,)).fetchone() is not None:
                raise AuthorityUnavailable("migration pairing already registered")
            db.execute("INSERT INTO authority_migration_pairings_v1 VALUES(?,?,?)",
                       (namespace, pairing.canonical_record(), "active"))

    def revoke(self, administrator_credential: object, namespace: str) -> None:
        if namespace not in self._pairings:
            raise AuthorityUnavailable("migration pairing is not installed")
        self._core._require(administrator_credential, "migration_pair_revoke", namespace)
        with self._core._tx() as db:
            if not self._matches(db, namespace):
                raise AuthorityUnavailable("active installed pairing is unavailable")
            db.execute("UPDATE authority_migration_pairings_v1 SET state='revoked' "
                       "WHERE namespace=?", (namespace,))

    @staticmethod
    def _check_schema(db) -> None:
        columns = tuple(row[1] for row in db.execute(
            "PRAGMA table_info(authority_migration_pairings_v1)"))
        if columns != ("namespace", "record_json", "state"):
            raise AuthorityUnavailable("installed migration pairing store is absent")

    def _matches(self, db, namespace: str) -> bool:
        self._check_schema(db)
        pairing = self._pairings.get(namespace)
        if pairing is None:
            return False
        row = db.execute(
            "SELECT record_json,state FROM authority_migration_pairings_v1 "
            "WHERE namespace=?", (namespace,)).fetchone()
        return row == (pairing.canonical_record(), "active")

    def _active(self, namespace: str) -> bool:
        with self._core._tx() as db:
            return self._matches(db, namespace)

    def resolve_management_binding(
        self, credential: object, profile_id: str,
        channel_binding_sha256: str, namespace: str,
    ) -> MigrationManagementBindingV2 | None:
        """Called on every RPC attempt, including a replay or recovery read."""
        if (type(credential) is not MtlsPeerCredential
                or type(channel_binding_sha256) is not str
                or _HEX.fullmatch(channel_binding_sha256) is None):
            return None
        pairing = self._pairings.get(namespace)
        if pairing is None or not self._active(namespace):
            return None
        for role in ("source", "target"):
            if (credential.certificate_sha256, profile_id) != (
                    getattr(pairing, f"{role}_certificate_sha256"),
                    getattr(pairing, f"{role}_profile_id")):
                continue
            return MigrationManagementBindingV2(
                credential.certificate_sha256, profile_id,
                channel_binding_sha256, namespace, role,
                getattr(pairing, f"{role}_holder"),
                getattr(pairing, f"{role}_installation_id"),
                pairing.source_holder, pairing.source_installation_id,
                pairing.target_holder, pairing.target_installation_id,
            )
        return None

    def verify_pairing(self, credential: object, subject: str,
                       plan: MigrationPlanV2, phase: str) -> bool:
        """Stage gate, independent of caller-provided pairing or graph claims."""
        if (type(plan) is not MigrationPlanV2
                or type(credential) is not MtlsPeerCredential
                or subject != "mtls:sha256:" + credential.certificate_sha256):
            return False
        pairing = self._pairings.get(plan.namespace)
        role = _ROLES.get(phase)
        if pairing is None or role is None or not self._active(plan.namespace):
            return False
        return (
            credential.certificate_sha256
            == getattr(pairing, f"{role}_certificate_sha256")
            and (plan.namespace_id, plan.source_holder,
                 plan.source_installation_id, plan.target_holder,
                 plan.target_installation_id)
            == (pairing.namespace_id, pairing.source_holder,
                pairing.source_installation_id, pairing.target_holder,
                pairing.target_installation_id)
        )


__all__ = ["AdministratorMigrationPairingV1", "InstalledMigrationPairingRegistry"]
