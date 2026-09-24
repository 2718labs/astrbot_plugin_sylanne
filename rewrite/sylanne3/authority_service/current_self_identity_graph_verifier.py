"""Pinned, read-only D01 head check for an Authority self-identity receipt."""

from __future__ import annotations

from contextlib import closing
from dataclasses import asdict
import json
from pathlib import Path
import sqlite3

from ..contracts import canonical_json
from ..domains.d01 import PersonaActivation, _validate_persona_plan
from ..graph_types import AtomKey, Owner, owner_grant_key, validate_owner_grant_v1
from ..runtime.restore_anchor import RestoreAnchor
from ..runtime_contracts import NamespaceId, SnapshotRequirementsV2, canonical_digest
from .v2_owner_contract import (
    OwnerAuthorizationGuardV1, OwnerGraphCommitProofV1,
    canonical_digest as owner_digest,
)


def _canonical(raw: str):
    value = json.loads(raw)
    if canonical_json(value) != raw:
        raise ValueError("noncanonical graph value")
    return value


class PinnedCurrentSelfIdentityGraphVerifier:
    """Return a current incarnation and role head, never a content permit."""

    def __init__(self, graph_db_path: str | Path):
        path = Path(graph_db_path)
        if not path.is_absolute():
            raise ValueError("self identity graph path must be administrator-pinned")
        self._path = path.resolve(strict=True)
        if not self._path.is_file():
            raise ValueError("pinned graph database is not a file")

    def current(self, namespace: NamespaceId, anchor: RestoreAnchor,
                installation_id: str,
                guard: OwnerAuthorizationGuardV1) -> tuple[str, str] | None:
        if (type(namespace) is not NamespaceId or type(anchor) is not RestoreAnchor
                or type(guard) is not OwnerAuthorizationGuardV1
                or guard.namespace != namespace
                or guard.authority_id != anchor.authority_id
                or guard.installation_id != installation_id
                or guard.pending_revoke_operation_id is not None
                or guard.minimum_revocation_revision >= guard.authorization_revision
                or guard.minimum_revocation_epoch > 0):
            return None
        try:
            with closing(sqlite3.connect(self._path.as_uri() + "?mode=ro", uri=True)) as db:
                db.execute("PRAGMA query_only=ON")
                db.execute("BEGIN")
                try:
                    return self._check(db, namespace, anchor, installation_id, guard)
                finally:
                    db.execute("ROLLBACK")
        except Exception:
            return None

    @staticmethod
    def _check(db, namespace, anchor, installation_id, guard):
        ns = namespace.as_tuple
        meta = db.execute(
            "SELECT schema,requirements_json FROM graph_recovery_metadata_v2 "
            "WHERE bot=? AND persona=?", ns).fetchone()
        epoch = db.execute(
            "SELECT revision FROM graph_epochs WHERE bot=? AND persona=?", ns).fetchone()
        access = db.execute(
            "SELECT access_epoch,delete_epoch FROM graph_authority_epochs "
            "WHERE bot=? AND persona=?", ns).fetchone()
        if (meta is None or meta[0] != "sylanne3.authority.v2"
                or epoch is None or access is None or access[1] != 0):
            return None
        raw = _canonical(meta[1])
        if type(raw) is not dict or raw.get("namespace") != asdict(namespace):
            return None
        requirements = SnapshotRequirementsV2(**{
            **raw, "namespace": NamespaceId(**raw["namespace"]),
        })
        if (requirements.namespace != namespace
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
                    anchor.execution_digest, anchor.revocation_epoch)):
            return None
        activation_key = AtomKey(Owner("persona", *ns),
                                 "d01.persona_activation.v1", "current")
        activation_row = db.execute(
            "SELECT revision,value,valid FROM graph_atoms WHERE token=?",
            (activation_key.token,)).fetchone()
        grant_row = db.execute(
            "SELECT revision,value,valid FROM graph_atoms WHERE token=?",
            (owner_grant_key(*ns).token,)).fetchone()
        if (activation_row is None or activation_row[2] != 1
                or grant_row is None or grant_row[2] != 1):
            return None
        activation_data = _canonical(activation_row[1])
        if (type(activation_data) is not dict
                or activation_data.get("namespace") != asdict(namespace)):
            return None
        activation = PersonaActivation(**{
            **activation_data, "namespace": namespace,
        })
        grant = _canonical(grant_row[1])
        validate_owner_grant_v1(grant)
        proof_row = db.execute(
            "SELECT operation_id,request_digest,grant_id,grant_digest,"
            "graph_incarnation,graph_access_epoch,graph_epoch,"
            "graph_receipt_digest,proof_json "
            "FROM graph_owner_issue_operations_v1 WHERE bot=? AND persona=? "
            "AND operation_id=?",
            ns + (grant["issue_operation_id"],)).fetchone()
        if proof_row is None:
            return None
        proof = OwnerGraphCommitProofV1(
            namespace, proof_row[0], proof_row[1], proof_row[2], proof_row[3],
            proof_row[4], grant["grant_revision"], proof_row[5],
            proof_row[6], proof_row[7])
        if (proof_row[8] != canonical_json(asdict(proof))
                or proof.grant_id != grant["grant_id"]
                or proof.grant_digest != "sha256:" + canonical_digest(grant)
                or proof.grant_revision != grant_row[0]
                or proof.operation_id != grant["issue_operation_id"]
                or proof.graph_incarnation != requirements.graph_incarnation
                or guard.authorization_head != owner_digest(proof)
                or proof.graph_access_epoch > access[0]
                or proof.graph_epoch > epoch[0]):
            return None
        plan_key = AtomKey(Owner("persona", *ns),
                           "d01.persona_plan.v1", activation.plan_id)
        plan = db.execute(
            "SELECT revision,value,valid FROM graph_atoms WHERE token=?",
            (plan_key.token,)).fetchone()
        if plan is None or plan[2] != 1:
            return None
        plan_value = _canonical(plan[1])
        _validate_persona_plan(plan_value)
        if (type(plan_value) is not dict
                or plan_value.get("namespace") != asdict(namespace)
                or plan_value.get("plan_id") != activation.plan_id
                or plan_value.get("version") != activation.plan_version
                or activation.graph_incarnation != requirements.graph_incarnation
                or activation.activation_generation != anchor.activation_generation
                or activation.owner_grant_id != grant["grant_id"]
                or activation.owner_grant_revision != grant_row[0]
                or activation.authorization_revision != guard.authorization_revision
                or grant["authority_id"] != anchor.authority_id
                or grant["installation_id"] != installation_id
                or grant["graph_incarnation"] != requirements.graph_incarnation
                or grant["activation_generation"] != anchor.activation_generation
                or guard.authorization_revision != grant["grant_revision"]
                or guard.minimum_revocation_revision > guard.authorization_revision):
            return None
        return requirements.graph_incarnation, activation.head_id


__all__ = ("PinnedCurrentSelfIdentityGraphVerifier",)
