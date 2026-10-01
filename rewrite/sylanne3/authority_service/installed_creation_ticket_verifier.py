"""Check a first Owner ticket against pinned W01 genesis and current Authority.

This is an offline administrator port. The graph is evidence of creation, not
evidence of the ticket principal or the administrator's chosen policy. The
caller must hold the installer's exclusive Authority maintenance lock until
the pairing write finishes; separate SQLite files cannot form one transaction.
"""

from __future__ import annotations

from contextlib import closing
from dataclasses import asdict, fields
import json
from pathlib import Path
import sqlite3

from ..contracts import canonical_json
from ..graph_coordinator import GraphCoordinator, NamespaceProvisionReceiptV2, namespace_ref
from ..runtime_contracts import NamespaceId, SnapshotRequirementsV2, canonical_digest
from ..runtime.restore_anchor import RestoreAnchor
from .core import AuthorityServiceCore
from .v2_owner_contract import OwnerClaimTicketV1


def _canonical(raw: str) -> object:
    value = json.loads(raw)
    if canonical_json(value) != raw:
        raise ValueError("noncanonical W01 original")
    return value


class PinnedInstalledCreationTicketVerifier:
    """Require exact GraphStore genesis and the same Core's live zero-head anchor."""

    def __init__(self, graph_db_path: str | Path, core: AuthorityServiceCore):
        path = Path(graph_db_path)
        if not path.is_absolute() or not path.is_file():
            raise ValueError("administrator-pinned graph database is required")
        if type(core) is not AuthorityServiceCore:
            raise TypeError("the installed Authority Core is required")
        self._path = path.resolve(strict=True)
        self._core = core

    def __call__(self, ticket: OwnerClaimTicketV1) -> bool:
        if type(ticket) is not OwnerClaimTicketV1:
            return False
        try:
            before = self._current_anchor(ticket)
            if before is None:
                return False
            with closing(sqlite3.connect(self._path.as_uri() + "?mode=ro", uri=True)) as db:
                db.execute("PRAGMA query_only=ON")
                db.execute("BEGIN")
                try:
                    valid = self._graph_original(db, ticket, before)
                finally:
                    db.execute("ROLLBACK")
            return valid and self._current_anchor(ticket) == before
        except Exception:
            return False

    def _current_anchor(self, ticket: OwnerClaimTicketV1) -> RestoreAnchor | None:
        namespace = namespace_ref(ticket.namespace)
        with self._core._tx() as db:
            if (db.execute("SELECT value FROM authority_meta WHERE key='service_mode'")
                    .fetchone() != ("v2-only",)
                    or self._core._id(db) != ticket.authority_id):
                return None
            self._core._require_no_deletion_migration(db)
            row = self._core._row(db, namespace)
            self._core._verify_current_heads(namespace, row)
            if (row[0] is None or row[1] != 1 or row[2] != "active"
                    or row[3] is not None or row[5] != 0 or row[9] != "clear"
                    or row[7:9] != (0, "genesis")
                    or row[11:13] != (0, "genesis")):
                return None
            for table in (
                "authority_owner_claim_tickets_v1",
                "authority_owner_issue_pending_v1",
                "authority_owner_issue_committed_v1",
                "authority_owner_revoke_pending_v1",
                "authority_owner_revoke_committed_v1",
            ):
                if db.execute(
                    f"SELECT 1 FROM {table} WHERE authority_namespace=? LIMIT 1",
                    (namespace,),
                ).fetchone() is not None:
                    return None
            return self._core._anchor(db, namespace, row)

    @staticmethod
    def _graph_original(db: sqlite3.Connection, ticket: OwnerClaimTicketV1,
                        anchor: RestoreAnchor) -> bool:
        ns = ticket.namespace.as_tuple
        namespace = namespace_ref(ticket.namespace)
        provision = db.execute(
            "SELECT operation_id,digest,receipt_json FROM graph_namespace_provisioning_v2 "
            "WHERE bot=? AND persona=?", ns,
        ).fetchone()
        intent = db.execute(
            "SELECT operation_id,digest,identity_json,genesis_request_id,"
            "fence_attempt_id,graph_incarnation,anchor_json "
            "FROM graph_namespace_provision_intents_v2 WHERE bot=? AND persona=?", ns,
        ).fetchone()
        recovery = db.execute(
            "SELECT schema,requirements_json,graph_revision "
            "FROM graph_recovery_metadata_v2 WHERE bot=? AND persona=?", ns,
        ).fetchone()
        if any(row is None for row in (provision, intent, recovery)):
            return False
        if (provision[:2] != intent[:2]
                or provision[:2] != (ticket.creation_operation_id,
                                      ticket.creation_digest.removeprefix("sha256:"))
                or recovery[0] != "sylanne3.authority.v2"
                or recovery[2] < 0):
            return False
        if (db.execute(
                "SELECT COUNT(*) FROM graph_namespace_provisioning_v2 WHERE operation_id=?",
                (ticket.creation_operation_id,),
            ).fetchone() != (1,)
                or db.execute(
                    "SELECT COUNT(*) FROM graph_namespace_provision_intents_v2 "
                    "WHERE operation_id=?", (ticket.creation_operation_id,),
                ).fetchone() != (1,)):
            return False
        receipt_data = _canonical(provision[2])
        requirements_data = _canonical(recovery[1])
        identity = _canonical(intent[2])
        saved_anchor = _canonical(intent[6])
        if (type(receipt_data) is not dict
                or set(receipt_data) != {field.name for field in fields(NamespaceProvisionReceiptV2)}
                or type(requirements_data) is not dict
                or set(requirements_data) != {field.name for field in fields(SnapshotRequirementsV2)}
                or type(identity) is not dict
                or set(identity) != {"policy", "authority_id", "subject", "holder",
                                      "installation_id", "authority_namespace"}
                or saved_anchor != asdict(anchor)):
            return False
        receipt = NamespaceProvisionReceiptV2(**{
            **receipt_data, "namespace": NamespaceId(**receipt_data["namespace"]),
        })
        requirements = SnapshotRequirementsV2(**{
            **requirements_data,
            "namespace": NamespaceId(**requirements_data["namespace"]),
        })
        fixed = GraphCoordinator._fixed_provision_ids(intent[2], intent[0], intent[1])
        if (intent[3:6] != fixed
                or receipt.namespace != ticket.namespace
                or receipt.operation_id != intent[0]
                or receipt.input_digest != intent[1]
                or receipt.authority_id != ticket.authority_id
                or receipt.installation_id != ticket.installation_id
                or receipt.authority_namespace != namespace
                or receipt.graph_incarnation != intent[5]
                or receipt.fence_attempt_id != intent[4]
                or receipt.generation != 1 or receipt.graph_revision != 0
                or receipt.graph_epoch != 0
                or identity["authority_id"] != ticket.authority_id
                or identity["installation_id"] != ticket.installation_id
                or identity["authority_namespace"] != namespace
                or canonical_digest(identity["policy"]) != intent[1]
                or requirements.namespace != ticket.namespace
                or requirements.authority_id != ticket.authority_id
                or requirements.authority_namespace != namespace
                or requirements.graph_incarnation != intent[5]
                or requirements.activation_generation != anchor.activation_generation
                or requirements.deletion_journal_id != anchor.deletion_journal_id
                or requirements.deletion_seq != anchor.deletion_seq
                or requirements.deletion_digest != anchor.deletion_digest
                or requirements.execution_journal_id != anchor.execution_journal_id
                or requirements.execution_seq != anchor.execution_seq
                or requirements.execution_digest != anchor.execution_digest
                or requirements.revocation_epoch != anchor.revocation_epoch):
            return False
        guards = db.execute(
            "SELECT kind,ref,version FROM graph_guard_versions "
            "WHERE bot=? AND persona=? ORDER BY kind,ref", ns,
        ).fetchall()
        expected_guards = sorted((
            ("scheme", "current", receipt.scheme_version),
            ("operator", "current", receipt.operator_version),
            ("policy", "current", receipt.policy_version),
            ("activation", "current", "1"),
        ))
        if guards != expected_guards:
            return False
        epoch = db.execute(
            "SELECT revision FROM graph_epochs WHERE bot=? AND persona=?", ns,
        ).fetchone()
        access = db.execute(
            "SELECT access_epoch,delete_epoch FROM graph_authority_epochs "
            "WHERE bot=? AND persona=?", ns,
        ).fetchone()
        if ((epoch is not None and epoch[0] < 0)
                or (access is not None and access != (0, 0))):
            return False
        if db.execute(
            "SELECT 1 FROM graph_owner_issue_intents_v1 "
            "WHERE bot=? AND persona=? LIMIT 1", ns,
        ).fetchone() is not None:
            return False
        if db.execute(
            "SELECT 1 FROM graph_owner_issue_operations_v1 "
            "WHERE bot=? AND persona=? LIMIT 1", ns,
        ).fetchone() is not None:
            return False
        if db.execute(
            "SELECT 1 FROM graph_owner_revoke_operations_v1 "
            "WHERE bot=? AND persona=? LIMIT 1", ns,
        ).fetchone() is not None:
            return False
        return True
