"""Typed, immutable administrator installation policy for v2 namespace genesis.

Construction checks consistency, but does not prove file provenance. Production
callers obtain this value through the administrator-owned profile loader.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
from types import MappingProxyType
from typing import TYPE_CHECKING

from .authority_service.contract import identifier
from .runtime.budget import BudgetLease
from .runtime_contracts import NamespaceId

if TYPE_CHECKING:
    from .runtime.issuers import BudgetLeaseGrant


_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


@dataclass(frozen=True, slots=True)
class AdminInstallationPolicy:
    namespace: NamespaceId
    authority_namespace: str
    installation_id: str
    manifest_digest: str
    administrator_holder: str
    expected_authority_id: str
    catalogue_hash: str
    scheme_version: str
    operator_version: str
    policy_version: str
    root_lease: BudgetLease
    root_grant: BudgetLeaseGrant

    def __post_init__(self) -> None:
        # Delay this import: issuers depends on GraphCoordinator, whose v2
        # provisioning path consumes this value class.
        from .runtime.issuers import BudgetLeaseGrant

        if type(self.namespace) is not NamespaceId:
            raise TypeError("installation namespace must be NamespaceId")
        for name in ("authority_namespace", "installation_id",
                     "administrator_holder", "expected_authority_id"):
            identifier(getattr(self, name), name)
        for name in ("manifest_digest", "catalogue_hash"):
            value = getattr(self, name)
            if type(value) is not str or _SHA256.fullmatch(value) is None:
                raise ValueError(f"{name} must be a lowercase SHA-256 digest")
        for name in ("scheme_version", "operator_version", "policy_version"):
            value = getattr(self, name)
            if type(value) is not str or not value or len(value) > 128:
                raise ValueError(f"invalid {name}")
        if type(self.root_lease) is not BudgetLease:
            raise TypeError("root_lease must be BudgetLease")
        if type(self.root_grant) is not BudgetLeaseGrant:
            raise TypeError("root_grant must be BudgetLeaseGrant")
        lease = self.root_lease
        grant = self.root_grant
        if (lease.parent_id is not None or lease.version != 1 or lease.state != "active"
                or lease.used or lease.reserved or lease.unconfirmed):
            raise ValueError("root lease must start active, unused and without a parent")
        if grant.version != 1:
            raise ValueError("root grant must be initial")
        if ((lease.bot_id, lease.persona_id) != self.namespace.as_tuple
                or (grant.bot_id, grant.persona_id) != self.namespace.as_tuple
                or grant.lease_id != lease.lease_id
                or grant.currency != lease.currency):
            raise ValueError("root budget identities differ from installation namespace")
        if any(amount > lease.limits.get(name, 0)
               for name, amount in grant.max_ceiling.items()):
            raise ValueError("root grant exceeds administrator root lease")

        # Budget dataclasses normalize into mutable dicts. Snapshot their data
        # and replace only these newly-created copies with read-only mappings.
        lease_copy = BudgetLease(
            lease.lease_id, lease.parent_id, lease.bot_id, lease.persona_id,
            lease.currency, dict(lease.limits), dict(lease.used),
            dict(lease.reserved), dict(lease.unconfirmed), lease.version,
            lease.state,
        )
        for name in ("limits", "used", "reserved", "unconfirmed"):
            object.__setattr__(lease_copy, name,
                               MappingProxyType(dict(getattr(lease_copy, name))))
        grant_copy = BudgetLeaseGrant(
            grant.grant_id, grant.version, grant.bot_id, grant.persona_id,
            grant.lease_id, grant.currency, dict(grant.max_ceiling),
            tuple(grant.allowed_work_kinds), grant.valid_until_utc,
            grant.policy_ref,
        )
        object.__setattr__(grant_copy, "max_ceiling",
                           MappingProxyType(dict(grant_copy.max_ceiling)))
        object.__setattr__(self, "root_lease", lease_copy)
        object.__setattr__(self, "root_grant", grant_copy)

    def digest_payload(self) -> dict[str, object]:
        """Return the complete durable policy as canonical-JSON-compatible data."""
        lease = self.root_lease
        grant = self.root_grant
        return {
            "namespace": {
                "bot_id": self.namespace.bot_id,
                "persona_id": self.namespace.persona_id,
            },
            "authority_namespace": self.authority_namespace,
            "installation_id": self.installation_id,
            "manifest_digest": self.manifest_digest,
            "administrator_holder": self.administrator_holder,
            "expected_authority_id": self.expected_authority_id,
            "catalogue_hash": self.catalogue_hash,
            "scheme_version": self.scheme_version,
            "operator_version": self.operator_version,
            "policy_version": self.policy_version,
            "root_lease": {
                "lease_id": lease.lease_id, "parent_id": lease.parent_id,
                "bot_id": lease.bot_id, "persona_id": lease.persona_id,
                "currency": lease.currency, "limits": dict(lease.limits),
                "used": dict(lease.used), "reserved": dict(lease.reserved),
                "unconfirmed": dict(lease.unconfirmed),
                "version": lease.version, "state": lease.state,
            },
            "root_grant": {
                "grant_id": grant.grant_id, "version": grant.version,
                "bot_id": grant.bot_id, "persona_id": grant.persona_id,
                "lease_id": grant.lease_id, "currency": grant.currency,
                "max_ceiling": dict(grant.max_ceiling),
                "allowed_work_kinds": list(grant.allowed_work_kinds),
                "valid_until_utc": grant.valid_until_utc,
                "policy_ref": grant.policy_ref,
            },
        }


__all__ = ["AdminInstallationPolicy"]
