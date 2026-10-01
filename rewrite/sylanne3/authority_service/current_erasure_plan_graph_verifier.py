"""Authority-owned, pinned CURRENT Graph read for a C09 erasure plan."""

from __future__ import annotations

from contextlib import closing
from dataclasses import asdict, fields
import json
from pathlib import Path
import sqlite3

from ..contracts import canonical_json
from ..graph_types import owner_grant_key, validate_owner_grant_v1
from ..runtime.c09_erasure_plan_original_v1 import (
    C09ErasurePlanOriginalV1, current_c09_source_read_versions_v1,
    read_c09_erasure_plan_original_v1,
)
from ..runtime_contracts import NamespaceId, SnapshotRequirementsV2, canonical_digest
from .contract import AuthorityUnavailable


def _canonical(raw: str):
    value = json.loads(raw)
    if canonical_json(value) != raw:
        raise ValueError("noncanonical Graph JSON")
    return value


class PinnedCurrentErasurePlanGraphVerifier:
    """Read the plan and every current dependency in one Graph snapshot.

    The caller holds an actual active read fence, with no Core SQL transaction.
    No request field may select the database or supply a Graph assertion.
    """

    def __init__(self, graph_db_path: str | Path):
        path = Path(graph_db_path)
        if not path.is_absolute():
            raise ValueError("Graph database path must be absolute")
        self._path = path.resolve(strict=True)
        if not self._path.is_file():
            raise ValueError("pinned Graph database is not a file")

    def verify(self, *, namespace: NamespaceId, operation_id: str,
               source_id: str, anchor, grant_digest: str,
               installation_id: str, principal,
               applied_epoch: int, storage_admission=None,
               owner_proof=None, owner_guard=None, holder=None) -> C09ErasurePlanOriginalV1:
        try:
            with closing(sqlite3.connect(self._path.as_uri() + "?mode=ro", uri=True)) as db:
                db.execute("PRAGMA query_only=ON")
                db.execute("BEGIN")
                try:
                    return self._check(db, namespace, operation_id, source_id,
                                       anchor, grant_digest, installation_id,
                                       principal, applied_epoch, storage_admission,
                                       owner_proof, owner_guard, holder)
                finally:
                    db.execute("ROLLBACK")
        except Exception as exc:
            raise AuthorityUnavailable("current pinned C09 Graph plan unavailable") from exc

    @staticmethod
    def _check(db, namespace, operation_id, source_id, anchor,
               grant_digest, installation_id, principal, applied_epoch,
               storage_admission, owner_proof, owner_guard, holder):
        ns = namespace.as_tuple
        original = read_c09_erasure_plan_original_v1(db, namespace, operation_id)
        if (original is None or original.root_source_ids != (source_id,)
                or original.owner_grant_digest != grant_digest):
            raise ValueError("C09 plan identity differs")
        recovery = db.execute(
            "SELECT schema,requirements_json,graph_revision FROM graph_recovery_metadata_v2 "
            "WHERE bot=? AND persona=?", ns).fetchone()
        epoch = db.execute(
            "SELECT revision FROM graph_epochs WHERE bot=? AND persona=?", ns).fetchone()
        rights = db.execute(
            "SELECT access_epoch,delete_epoch FROM graph_authority_epochs "
            "WHERE bot=? AND persona=?", ns).fetchone()
        if (recovery is None or recovery[0] != "sylanne3.authority.v2"
                or epoch is None or rights is None):
            raise ValueError("C09 Graph metadata absent")
        raw = _canonical(recovery[1])
        if (type(raw) is not dict
                or set(raw) != {field.name for field in fields(SnapshotRequirementsV2)}
                or raw["namespace"] != asdict(namespace)):
            raise ValueError("C09 Graph requirements differ")
        target = SnapshotRequirementsV2(**{**raw, "namespace": namespace})
        if (target.authority_namespace != anchor.namespace
                or target.authority_id != anchor.authority_id
                or target.activation_generation != anchor.activation_generation
                or target.deletion_journal_id != anchor.deletion_journal_id
                or target.deletion_seq != anchor.deletion_seq
                or target.deletion_digest != anchor.deletion_digest
                or target.execution_journal_id != anchor.execution_journal_id
                or target.execution_seq != anchor.execution_seq
                or target.execution_digest != anchor.execution_digest
                or target.revocation_epoch != anchor.revocation_epoch
                or target.graph_incarnation != original.graph_incarnation
                or epoch != (original.graph_epoch,)
                or rights != (original.access_epoch, original.delete_epoch)
                or original.delete_epoch != applied_epoch):
            raise ValueError("C09 Graph stamp differs from Authority")
        key = owner_grant_key(*ns)
        row = db.execute(
            "SELECT revision,value,valid FROM graph_atoms WHERE token=? AND bot=? "
            "AND persona=?", (key.token, *ns)).fetchone()
        if row is None or row[2] != 1 or row[0] != 1:
            raise ValueError("C09 Owner grant unavailable")
        grant = _canonical(row[1])
        validate_owner_grant_v1(grant)
        if (grant["state"] != "pending_authority"
                or grant["authority_id"] != anchor.authority_id
                or grant["installation_id"] != installation_id
                or grant["principal"] != asdict(principal)
                or grant["activation_generation"] != anchor.activation_generation
                or "workbench.erase" not in grant["capabilities"]
                or "owner" not in grant["audiences"]
                or "sha256:" + canonical_digest(grant) != grant_digest):
            raise ValueError("C09 current Owner grant differs")
        if storage_admission is None:
            if (grant["graph_incarnation"] != original.graph_incarnation
                    or owner_proof is not None
                    and owner_proof.graph_incarnation != original.graph_incarnation):
                raise ValueError("C09 original Owner location differs")
        else:
            from .d12_owner_storage_admission_v1 import D12OwnerStorageAdmissionV1
            from .v2_owner_contract import canonical_digest as owner_digest
            admission = storage_admission
            if (type(admission) is not D12OwnerStorageAdmissionV1
                    or owner_proof is None or owner_guard is None
                    or admission.namespace != namespace
                    or admission.authority_namespace != anchor.namespace
                    or admission.installation_id != installation_id
                    or admission.holder != holder
                    or admission.principal != principal
                    or admission.source_owner_guard != owner_guard
                    or admission.source_grant_ref != key.token
                    or admission.source_grant_revision != row[0]
                    or admission.source_grant_digest != grant_digest
                    or owner_proof.grant_digest != grant_digest
                    or owner_guard.authorization_head != owner_digest(owner_proof)
                    or admission.source_graph_incarnation != grant["graph_incarnation"]
                    or admission.source_graph_incarnation != owner_proof.graph_incarnation
                    or admission.current_graph_incarnation != original.graph_incarnation
                    or admission.activation_generation != target.activation_generation
                    or admission.revocation_epoch != target.revocation_epoch):
                raise ValueError("C09 actual Owner storage continuation differs")
        if original.read_versions != current_c09_source_read_versions_v1(
                db, namespace, source_id):
            raise ValueError("C09 source ancestry changed")
        return original


__all__ = ("PinnedCurrentErasurePlanGraphVerifier",)
