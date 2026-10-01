"""Administrator-paired local target reservations; references are never paths."""
from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import json
import re
from pathlib import Path

from ..runtime.lifecycle_operations_v1 import digest
from ..runtime_contracts import NamespaceId, canonical_serialize
from .contract import AuthorityUnavailable
from .installed_migration_pairing import InstalledMigrationPairingRegistry


@dataclass(frozen=True, slots=True)
class D12TargetLeaseOriginalV1:
    lease_ref: str
    target_ref: str
    authority_namespace: str
    namespace_id: NamespaceId
    installation_id: str
    holder: str
    graph_incarnation: str
    graph_db: str
    schema_digest: str
    catalogue_digest: str
    expires_at_utc: str
    policy_ref: str
    policy_digest: str

    def __post_init__(self):
        for value in (self.lease_ref, self.target_ref, self.installation_id, self.holder,
                      self.graph_incarnation, self.authority_namespace, self.policy_ref):
            if type(value) is not str or not value or len(value) > 256:
                raise ValueError("bounded installed target identity required")
        if type(self.namespace_id) is not NamespaceId or not Path(self.graph_db).is_absolute():
            raise ValueError("installed target namespace and absolute administrator path required")
        expiry = datetime.fromisoformat(self.expires_at_utc.replace("Z", "+00:00"))
        if expiry.utcoffset() is None or expiry.utcoffset().total_seconds():
            raise ValueError("target reservation expiry must be UTC")
        for value in (self.schema_digest, self.catalogue_digest, self.policy_digest):
            if type(value) is not str or re.fullmatch(r"sha256:[0-9a-f]{64}", value) is None:
                raise ValueError("target reservation digest required")

    @property
    def original_digest(self):
        return digest(self)


class InstalledD12TargetRegistryV1:
    def __init__(self, *, pairing_registry, target_leases, utc_clock):
        if type(pairing_registry) is not InstalledMigrationPairingRegistry or not callable(utc_clock):
            raise TypeError("actual installed pairing registry and trusted clock required")
        self.pairings, self.core = pairing_registry, pairing_registry._core
        self.clock = utc_clock
        self.configured = {item.lease_ref: item for item in target_leases}
        if len(self.configured) != len(target_leases) or any(type(item) is not D12TargetLeaseOriginalV1 for item in target_leases):
            raise ValueError("unique typed administrator target leases required")
        if len({item.target_ref for item in target_leases}) != len(target_leases):
            raise ValueError("target selection must be unambiguous")

    def install_schema(self, administrator_credential):
        for item in self.configured.values():
            self.core._require(administrator_credential, "d12_target_install", item.authority_namespace)
        with self.core._tx() as db:
            db.execute("CREATE TABLE IF NOT EXISTS authority_d12_target_leases_v1(lease_ref TEXT PRIMARY KEY, "
                       "record_json TEXT NOT NULL,state TEXT NOT NULL,transfer_id TEXT)")

    def register(self, administrator_credential, lease_ref):
        item = self.configured[lease_ref]
        self.core._require(administrator_credential, "d12_target_register", item.authority_namespace)
        # The target is created and installed by the administrator. Its schema
        # and empty contents are independently inspected before reservation.
        from ..runtime.graph_migration_snapshot_v1 import _schema_digest, _catalogue_digest, _inventory
        import sqlite3
        path = Path(item.graph_db)
        if not path.is_file() or path.is_symlink():
            raise AuthorityUnavailable("installed target Graph file is unavailable")
        connection = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)
        try:
            connection.execute("BEGIN")
            if (_schema_digest(connection), _catalogue_digest(connection)) != (item.schema_digest, item.catalogue_digest):
                raise AuthorityUnavailable("target installed schema/catalogue differs")
            if any(rows for _, _, rows in _inventory(connection, item.namespace_id)):
                raise AuthorityUnavailable("target is not an isolated empty namespace")
        finally:
            connection.close()
        with self.core._tx() as db:
            self._require_pairing(db, item)
            db.execute("INSERT INTO authority_d12_target_leases_v1 VALUES(?,?,'reserved',NULL)",
                       (lease_ref, canonical_serialize(asdict(item))))

    def _require_pairing(self, db, item):
        if not self.pairings._matches(db, item.authority_namespace):
            raise AuthorityUnavailable("current migration pairing is revoked or absent")
        pairing = self.pairings._pairings[item.authority_namespace]
        if (pairing.namespace_id, pairing.target_holder, pairing.target_installation_id) != (
                item.namespace_id, item.holder, item.installation_id):
            raise AuthorityUnavailable("target lease differs from administrator pairing")

    def _read(self, db, lease_ref):
        item = self.configured.get(lease_ref)
        row = db.execute("SELECT record_json,state,transfer_id FROM authority_d12_target_leases_v1 WHERE lease_ref=?",
                         (lease_ref,)).fetchone()
        if (item is None or row is None or row[0] != canonical_serialize(asdict(item))
                or row[1] not in {"reserved", "active"}):
            raise AuthorityUnavailable("current installed target reservation unavailable")
        self._require_pairing(db, item)
        now = self.clock()
        if type(now) is not datetime or now.tzinfo is None or now.utcoffset().total_seconds() != 0:
            raise AuthorityUnavailable("trusted target reservation UTC clock unavailable")
        if row[1] == "reserved" and now >= datetime.fromisoformat(item.expires_at_utc.replace("Z", "+00:00")):
            raise AuthorityUnavailable("target reservation expired")
        path = Path(item.graph_db)
        if not path.is_file() or path.is_symlink():
            raise AuthorityUnavailable("target reservation file unavailable")
        return item, row[2]

    def read_current_target_lease_v1(self, *, target_ref=None, lease_ref=None):
        if (target_ref is None) == (lease_ref is None):
            raise ValueError("select exactly one opaque target or lease reference")
        if target_ref is not None:
            selected = [item.lease_ref for item in self.configured.values() if item.target_ref == target_ref]
            if len(selected) != 1:
                raise AuthorityUnavailable("target has no installed pairing")
            lease_ref = selected[0]
        with self.core._tx() as db:
            return self._read(db, lease_ref)[0]

    def claim_target_for_transfer_v1(self, *, lease_ref, plan):
        with self.core._tx() as db:
            item, transfer = self._read(db, lease_ref)
            if (item.authority_namespace, item.namespace_id, item.installation_id, item.holder) != (
                    plan.namespace, plan.namespace_id, plan.target_installation_id, plan.target_holder):
                raise AuthorityUnavailable("target lease does not bind this migration")
            if transfer not in {None, plan.transfer_id}:
                raise AuthorityUnavailable("target reserved by a different original transfer")
            db.execute("UPDATE authority_d12_target_leases_v1 SET transfer_id=? WHERE lease_ref=? AND transfer_id IS NULL",
                       (plan.transfer_id, lease_ref))
            return item

    def require_current_target_lease_in_tx_v1(self, db, *, plan, permit, held):
        """Final activation gate, using the existing frozen-head Core tx only."""
        if db is not self.core._db or not db.in_transaction:
            raise AuthorityUnavailable("target lease gate requires the existing Core transaction")
        rows = tuple(db.execute("SELECT lease_ref FROM authority_d12_target_leases_v1 WHERE transfer_id=?",
                                (plan.transfer_id,)))
        if len(rows) != 1:
            raise AuthorityUnavailable("transfer lacks one original target reservation")
        item, transfer = self._read(db, rows[0][0])
        current = self.core._row(db, plan.namespace)
        if (transfer != plan.transfer_id or item.namespace_id != plan.namespace_id
                or item.authority_namespace != plan.namespace
                or item.holder != plan.target_holder or item.installation_id != plan.target_installation_id
                or item.graph_incarnation != held.new_graph_incarnation
                or (permit.holder, permit.installation_id, permit.generation) != (
                    item.holder, item.installation_id, held.target_generation)
                or (current[0], current[1], current[2], current[3]) != (
                    item.holder, permit.generation, "recovering", plan.transfer_id)):
            raise AuthorityUnavailable("current target reservation differs before activation CAS")
        # This change shares activate_target's Core transaction. A rejected CAS
        # rolls it back. Once activated, expiry is historical, never a new lease.
        db.execute("UPDATE authority_d12_target_leases_v1 SET state='active' WHERE lease_ref=? AND transfer_id=?",
                   (item.lease_ref, plan.transfer_id))

    def read_current_target_lease_digest_v1(self, *, plan, target_lease_ref, current):
        with self.core._tx() as db:
            item, transfer = self._read(db, target_lease_ref)
            row = self.core._row(db, plan.namespace)
            if (transfer != plan.transfer_id or item.holder != plan.target_holder
                    or current.phase != "active" or current.holder != item.holder
                    or row[0] != item.holder or row[1] != current.generation
                    or row[2] != "active" or self.core._anchor(db, plan.namespace, row) != current.anchor):
                raise AuthorityUnavailable("target activation or original reservation differs")
            return item.original_digest


__all__ = ("D12TargetLeaseOriginalV1", "InstalledD12TargetRegistryV1")
