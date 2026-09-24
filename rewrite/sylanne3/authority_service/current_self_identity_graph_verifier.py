"""Pinned, read-only D01 head check for an Authority self-identity receipt."""

from __future__ import annotations

from contextlib import closing
from dataclasses import asdict
import json
from pathlib import Path
import sqlite3

from ..contracts import canonical_json
from ..domains.d01 import PersonaActivation, _validate_persona_plan
from ..graph_coordinator import RoleInitializationReceiptV1
from ..graph_types import AtomKey, Owner, owner_grant_key, validate_owner_grant_v1
from ..runtime.role_resources import RoleRuntimeResourcesV1, role_resources_key
from ..runtime.restore_anchor import RestoreAnchor
from ..runtime_contracts import NamespaceId, SnapshotRequirementsV2, canonical_digest
from .v2_owner_contract import (
    OwnerAuthorizationGuardV1, OwnerGraphCommitProofV1,
    canonical_digest as owner_digest,
)
from .v2_contract import FencePermitV2, from_wire as fence_from_wire, to_wire as fence_to_wire


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
                guard: OwnerAuthorizationGuardV1) -> tuple[str, str, int, int] | None:
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
            "SELECT schema,requirements_json,graph_revision FROM graph_recovery_metadata_v2 "
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
        resource_key = role_resources_key(namespace, activation.plan_id)
        resource_row = db.execute(
            "SELECT revision,value,valid FROM graph_atoms WHERE token=?",
            (resource_key.token,)).fetchone()
        if resource_row is None or resource_row[2] != 1 or resource_row[0] != 1:
            return None
        resource_value = _canonical(resource_row[1])
        resources = RoleRuntimeResourcesV1(**resource_value)
        role_intent = db.execute(
            "SELECT operation_id,input_digest,fence_attempt_id,requirements_json,"
            "anchor_json,graph_revision,graph_epoch FROM graph_role_init_intents_v1 "
            "WHERE bot=? AND persona=?", ns).fetchone()
        role_request = db.execute(
            "SELECT operation_id,request_digest,input_digest "
            "FROM graph_role_init_request_proofs_v1 WHERE bot=? AND persona=?",
            ns).fetchone()
        role_row = db.execute(
            "SELECT operation_id,input_digest,permit_json,receipt_json,"
            "pre_graph_revision,pre_graph_epoch,post_graph_revision,"
            "post_graph_epoch,finish_request_id,finish_request_digest "
            "FROM graph_role_init_receipts_v1 WHERE bot=? AND persona=?",
            ns).fetchone()
        if role_intent is None or role_request is None or role_row is None:
            return None
        role_data = _canonical(role_row[3])
        if (type(role_data) is not dict
                or set(role_data) != set(RoleInitializationReceiptV1.__dataclass_fields__)
                or role_data.get("namespace") != asdict(namespace)):
            return None
        role_receipt = RoleInitializationReceiptV1(**{
            **role_data, "namespace": namespace,
        })
        original_input_digest = "sha256:" + canonical_digest({
            "schema": "sylanne3.graph.role_initialization.v1",
            "namespace": list(ns), "operation_id": role_receipt.operation_id,
            "request_digest": role_receipt.request_digest,
            "plan": plan_value, "principal": grant["principal"],
            "resources": resource_value, "owner_proof": asdict(proof),
        })
        original_requirements = _canonical(role_intent[3])
        original_anchor = _canonical(role_intent[4])
        permit_wire = _canonical(role_row[2])
        role_permit = fence_from_wire(permit_wire)
        expected_finish_digest = "sha256:" + canonical_digest({
            "operation_id": role_intent[2],
            "permit_token": role_permit.token,
            "action": "finish_role_initialization",
            "business_operation_id": role_receipt.operation_id,
            "input_digest": role_receipt.input_digest,
        })
        if (type(role_permit) is not FencePermitV2
                or fence_to_wire(role_permit) != permit_wire
                or role_permit.operation != "write"
                or (role_permit.authority_id, role_permit.namespace,
                    role_permit.generation) != (
                        anchor.authority_id, anchor.namespace,
                        anchor.activation_generation)
                or original_anchor != asdict(role_permit.pinned_anchor)
                or type(original_requirements) is not dict
                or original_requirements.get("namespace") != asdict(namespace)
                or original_requirements.get("authority_id") != anchor.authority_id
                or original_requirements.get("authority_namespace") != anchor.namespace
                or original_requirements.get("graph_incarnation")
                   != requirements.graph_incarnation
                or role_request != (
                    role_intent[0], role_receipt.request_digest,
                    role_intent[1])
                or role_row[:2] != role_intent[:2]
                or role_row[4:8] != (
                    role_intent[5], role_intent[6],
                    role_receipt.graph_revision, role_receipt.graph_epoch)
                or role_row[8:] != (role_receipt.finish_request_id,
                                    role_receipt.finish_request_digest)
                or role_receipt.operation_id != role_intent[0]
                or role_receipt.input_digest != role_intent[1]
                or role_receipt.input_digest != original_input_digest
                or role_intent[2] != "role-write-" + canonical_digest({
                    "namespace": list(ns),
                    "operation_id": role_receipt.operation_id,
                    "input_digest": role_receipt.input_digest,
                })[:48]
                or role_receipt.fence_attempt_id != role_intent[2]
                or role_receipt.head_id != activation.head_id
                or role_receipt.plan_id != activation.plan_id
                or role_receipt.owner_grant_id != grant["grant_id"]
                or role_receipt.owner_grant_revision != grant_row[0]
                or role_receipt.owner_authorization_head != guard.authorization_head
                or role_receipt.graph_incarnation != requirements.graph_incarnation
                or (resources.namespace, resources.operation_id,
                    resources.plan_id, resources.head_id) != (
                        namespace, role_receipt.operation_id,
                        activation.plan_id, activation.head_id)
                or role_receipt.graph_revision > meta[2]
                or role_receipt.graph_epoch > epoch[0]
                or role_receipt.finish_request_id != "finish:" + role_intent[2]
                or role_receipt.finish_request_digest != expected_finish_digest):
            return None
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
        return requirements.graph_incarnation, activation.head_id, meta[2], epoch[0]


__all__ = ("PinnedCurrentSelfIdentityGraphVerifier",)
