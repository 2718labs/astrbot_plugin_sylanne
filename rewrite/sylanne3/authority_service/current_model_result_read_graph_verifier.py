"""Pinned, read-only business graph check for a completed model result."""

from __future__ import annotations

from contextlib import closing
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import sqlite3

from ..contracts import canonical_json
from ..graph_types import owner_grant_key, validate_owner_grant_v1
from ..memory_types import SourceRecord, access_key, source_key, validate_access
from ..runtime_contracts import NamespaceId, SnapshotRequirementsV2
from .v2_contract import FencePermitV2
from .v2_model_egress_contract import ModelEgressIntentV1
from .v2_model_result_read_contract import ModelResultReadRequestV1
from .v2_owner_contract import (
    OwnerAuthorizationGuardV1, OwnerGraphCommitProofV1,
    canonical_digest as owner_digest,
)


def _canonical(raw: str):
    value = json.loads(raw)
    if raw != canonical_json(value):
        raise ValueError("noncanonical graph value")
    return value


class PinnedCurrentModelResultReadGraphVerifier:
    """Checks Owner grant, source ACL and activation in one SQLite read snapshot.

    It deliberately has no dependency on running jobs, pending outbox rows or
    budget reservations. Those were admission facts; the Authority ledger is
    the only source of the completed response and its terminal receipt.
    """

    def __init__(self, graph_db_path: str | Path):
        path = Path(graph_db_path)
        if not path.is_absolute():
            raise ValueError("graph database path must be administrator-pinned and absolute")
        self._path = path.resolve(strict=True)
        if not self._path.is_file():
            raise ValueError("pinned graph database is not a file")

    def current(self, request: ModelResultReadRequestV1,
                intent: ModelEgressIntentV1, guard: OwnerAuthorizationGuardV1,
                permit: FencePermitV2) -> bool:
        if (type(request) is not ModelResultReadRequestV1
                or type(intent) is not ModelEgressIntentV1
                or type(guard) is not OwnerAuthorizationGuardV1
                or type(permit) is not FencePermitV2
                or permit.operation != "read"
                or (permit.authority_id, permit.namespace, permit.operation_id) !=
                   (request.authority_id, request.authority_namespace,
                    request.read_operation_id)
                or (intent.authority_id, intent.namespace, intent.call_id) !=
                   (request.authority_id, request.authority_namespace,
                    request.call_id)
                or (guard.authority_id, guard.installation_id, guard.namespace) !=
                   (request.authority_id, request.installation_id, request.namespace)
                or guard.pending_revoke_operation_id is not None):
            return False
        try:
            with closing(sqlite3.connect(self._path.as_uri() + "?mode=ro", uri=True)) as db:
                db.execute("PRAGMA query_only=ON")
                db.execute("BEGIN")
                try:
                    return self._check(db, request, intent, guard, permit)
                finally:
                    db.execute("ROLLBACK")
        except Exception:
            return False

    @staticmethod
    def _check(db: sqlite3.Connection, request: ModelResultReadRequestV1,
               intent: ModelEgressIntentV1, guard: OwnerAuthorizationGuardV1,
               permit: FencePermitV2) -> bool:
        ns = request.namespace.as_tuple
        meta = db.execute(
            "SELECT schema,requirements_json,graph_revision FROM graph_recovery_metadata_v2 "
            "WHERE bot=? AND persona=?", ns).fetchone()
        graph_epoch = db.execute(
            "SELECT revision FROM graph_epochs WHERE bot=? AND persona=?", ns).fetchone()
        epochs = db.execute(
            "SELECT access_epoch,delete_epoch FROM graph_authority_epochs "
            "WHERE bot=? AND persona=?", ns).fetchone()
        if (meta is None or meta[0] != "sylanne3.authority.v2"
                or graph_epoch is None or epochs is None):
            return False
        data = _canonical(meta[1])
        if type(data) is not dict or data.get("namespace") != asdict(request.namespace):
            return False
        requirements = SnapshotRequirementsV2(**{
            **data, "namespace": NamespaceId(**data["namespace"])})
        anchor = permit.pinned_anchor
        if (requirements.namespace != request.namespace
                or (requirements.authority_id, requirements.authority_namespace,
                    requirements.activation_generation,
                    requirements.deletion_journal_id, requirements.deletion_seq,
                    requirements.deletion_digest, requirements.execution_journal_id,
                    requirements.execution_seq, requirements.execution_digest,
                    requirements.revocation_epoch) !=
                   (anchor.authority_id, anchor.namespace,
                    anchor.activation_generation, anchor.deletion_journal_id,
                    anchor.deletion_seq, anchor.deletion_digest,
                    anchor.execution_journal_id, anchor.execution_seq,
                    anchor.execution_digest, anchor.revocation_epoch)
                or intent.authority_activation_generation != anchor.activation_generation
                or epochs[1] != intent.delete_epoch
                or guard.minimum_revocation_epoch > epochs[0]):
            return False

        grant_row = db.execute(
            "SELECT revision,value,valid FROM graph_atoms WHERE token=?",
            (owner_grant_key(*ns).token,)).fetchone()
        if grant_row is None or grant_row[2] != 1:
            return False
        grant = _canonical(grant_row[1])
        validate_owner_grant_v1(grant)
        proof_row = db.execute(
            "SELECT operation_id,request_digest,grant_id,grant_digest,"
            "graph_incarnation,graph_access_epoch,graph_epoch,"
            "graph_receipt_digest,proof_json "
            "FROM graph_owner_issue_operations_v1 WHERE bot=? AND persona=? "
            "AND operation_id=?", ns + (grant["issue_operation_id"],),
        ).fetchone()
        if proof_row is None:
            return False
        proof = OwnerGraphCommitProofV1(
            request.namespace, proof_row[0], proof_row[1], proof_row[2],
            proof_row[3], proof_row[4], grant["grant_revision"],
            proof_row[5], proof_row[6], proof_row[7])
        if (grant_row[0] != grant["grant_revision"]
                or proof_row[8] != canonical_json(asdict(proof))
                or "sha256:" + hashlib.sha256(
                    canonical_json(grant).encode("utf-8")).hexdigest() != proof.grant_digest
                or grant["grant_id"] != proof.grant_id
                or grant["issue_operation_id"] != proof.operation_id
                or grant["principal"] != asdict(request.owner_session_request.principal)
                or grant["authority_id"] != request.authority_id
                or grant["installation_id"] != request.installation_id
                or grant["activation_generation"] != anchor.activation_generation
                or grant["graph_incarnation"] != requirements.graph_incarnation
                or proof.graph_incarnation != requirements.graph_incarnation
                or proof.graph_access_epoch > epochs[0]
                or proof.graph_epoch > graph_epoch[0]
                or grant["scope"] != "bot/persona"
                or guard.authorization_revision != grant["grant_revision"]
                or guard.authorization_head != owner_digest(proof)
                or guard.minimum_revocation_revision > guard.authorization_revision
                or "workbench.read" not in grant["capabilities"]
                or request.purpose not in grant["purposes"]
                or not set(request.audience).issubset(grant["audiences"])):
            return False

        if (not intent.source_refs or len(intent.source_refs) != len(intent.source_revisions)
                or len(intent.source_refs) != len(intent.access_revisions)):
            return False
        for source_id in intent.source_refs:
            source_token = source_key(*ns, source_id).token
            access_token = access_key(*ns, source_id).token
            source_row = db.execute(
                "SELECT revision,value,valid FROM graph_atoms WHERE token=?",
                (source_token,)).fetchone()
            access_row = db.execute(
                "SELECT revision,value,valid FROM graph_atoms WHERE token=?",
                (access_token,)).fetchone()
            dependency = db.execute(
                "SELECT dependency_revision FROM graph_dependencies WHERE "
                "dependent_token=? AND dependency_token=?",
                (access_token, source_token)).fetchone()
            if (source_row is None or access_row is None
                    or source_row[2] != 1 or access_row[2] != 1
                    or (source_id, source_row[0]) not in intent.source_revisions
                    or (source_id, access_row[0]) not in intent.access_revisions
                    or dependency != (source_row[0],)):
                return False
            source = SourceRecord.from_dict(_canonical(source_row[1]))
            access = _canonical(access_row[1])
            validate_access(access)
            if (source.source_id != source_id or access["source_id"] != source_id
                    or access["status"] != "active"
                    or request.source_purpose not in source.purposes
                    or request.source_purpose not in access["purposes"]
                    or not set(request.audience).issubset(source.audiences)
                    or not set(request.audience).issubset(access["audiences"])):
                return False
        return True


__all__ = ("PinnedCurrentModelResultReadGraphVerifier",)
