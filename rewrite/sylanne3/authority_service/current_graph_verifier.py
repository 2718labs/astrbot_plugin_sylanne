"""Pinned, same-host CURRENT graph check for a first Owner issue.

The graph database path is supplied by trusted installation configuration, not
by a claimant. This checks business facts in one read-only SQLite snapshot.
The injected callback must independently confirm the exact *finished* Authority
fence; a graph-side finish request is not evidence that Authority accepted it.
This does not attest a remote graph or defend against hostile host code/UID.
"""

from __future__ import annotations

from contextlib import closing
from dataclasses import asdict, fields
import json
from pathlib import Path
import sqlite3
from typing import Callable

from .v2_contract import FencePermitV2, from_wire, to_wire
from .v2_owner_contract import OwnerAuthorizationOperationV1, OwnerGraphCommitProofV1
from ..contracts import canonical_json
from ..graph_coordinator import NamespaceProvisionReceiptV2
from ..graph_types import owner_grant_key, owner_grant_policy_digest_v1, validate_owner_grant_v1
from ..runtime_contracts import NamespaceId, SnapshotRequirementsV2, canonical_digest


def _json(value: str):
    decoded = json.loads(value)
    if canonical_json(decoded) != value:
        raise ValueError("noncanonical graph JSON")
    return decoded


def _one(db: sqlite3.Connection, query: str, namespace: NamespaceId):
    return db.execute(query, namespace.as_tuple).fetchone()


class PinnedCurrentGraphVerifier:
    """Callable for ``AuthorityV2OwnerTicketStore.graph_commit_verifier``.

    ``finished_fence_verifier(permit, finish_id, finish_digest)`` must read the
    independent Authority service's durable operation and return exact ``True``
    only when it is finished with those exact identifiers. It must not infer
    completion from the graph row or trust a claimant-provided assertion.
    """

    def __init__(self, graph_db_path: str | Path, *,
                 finished_fence_verifier: Callable[[FencePermitV2, str, str], bool]):
        path = Path(graph_db_path)
        if not path.is_absolute():
            raise ValueError("graph database path must be administrator-pinned and absolute")
        if not callable(finished_fence_verifier):
            raise TypeError("independent finished-fence verifier is required")
        self._path = path.resolve(strict=True)
        if not self._path.is_file():
            raise ValueError("pinned graph database is not a file")
        self._finished_fence_verifier = finished_fence_verifier

    def __call__(self, operation: OwnerAuthorizationOperationV1,
                 proof: OwnerGraphCommitProofV1) -> bool:
        if (type(operation) is not OwnerAuthorizationOperationV1
                or operation.action != "issue" or operation.ticket is None
                or type(proof) is not OwnerGraphCommitProofV1
                or proof.namespace != operation.namespace
                or proof.operation_id != operation.operation_id
                or proof.request_digest != operation.request_digest
                or proof.grant_id != operation.grant_id
                or proof.grant_digest != operation.grant_digest
                or proof.grant_revision != 1):
            return False
        try:
            with closing(sqlite3.connect(self._path.as_uri() + "?mode=ro", uri=True)) as db:
                db.execute("PRAGMA query_only=ON")
                db.execute("BEGIN")
                try:
                    return self._check(db, operation, proof)
                finally:
                    db.execute("ROLLBACK")
        except Exception:
            return False

    def _check(self, db: sqlite3.Connection, operation: OwnerAuthorizationOperationV1,
               proof: OwnerGraphCommitProofV1) -> bool:
        namespace = operation.namespace
        ticket = operation.ticket
        recovery = _one(db,
            "SELECT schema,requirements_json,graph_revision "
            "FROM graph_recovery_metadata_v2 WHERE bot=? AND persona=?", namespace)
        epoch = _one(db,
            "SELECT revision FROM graph_epochs WHERE bot=? AND persona=?", namespace)
        access = _one(db,
            "SELECT access_epoch,delete_epoch FROM graph_authority_epochs "
            "WHERE bot=? AND persona=?", namespace)
        provision_row = _one(db,
            "SELECT operation_id,digest,receipt_json FROM graph_namespace_provisioning_v2 "
            "WHERE bot=? AND persona=?", namespace)
        issue = _one(db,
            "SELECT operation_id,request_digest,grant_id,grant_digest,graph_incarnation,"
            "graph_access_epoch,graph_epoch,graph_receipt_digest,proof_json "
            "FROM graph_owner_issue_operations_v1 WHERE bot=? AND persona=?", namespace)
        intents = db.execute(
            "SELECT operation_id,grant_digest,fence_attempt_id,requirements_json,"
            "anchor_json,graph_revision,graph_epoch FROM graph_owner_issue_intents_v1 "
            "WHERE bot=? AND persona=? AND operation_id=? AND grant_digest=? LIMIT 2",
            namespace.as_tuple + (operation.operation_id, operation.grant_digest),
        ).fetchall()
        fence = _one(db,
            "SELECT operation_id,permit_json,pre_graph_revision,pre_graph_epoch,"
            "post_graph_revision,post_graph_epoch,finish_request_id,finish_request_digest "
            "FROM graph_owner_issue_fences_v1 WHERE bot=? AND persona=?", namespace)
        if (len(intents) != 1 or any(row is None for row in (
                recovery, epoch, access, provision_row, issue, fence))):
            return False
        intent = intents[0]
        if (recovery[0] != "sylanne3.authority.v2" or recovery[2] != 1
                or epoch != (proof.graph_epoch,) or epoch != (1,)
                or access != (proof.graph_access_epoch, 0) or access != (1, 0)):
            return False
        requirements_data = _json(recovery[1])
        if (type(requirements_data) is not dict
                or set(requirements_data) != {f.name for f in fields(SnapshotRequirementsV2)}
                or requirements_data["namespace"] != asdict(namespace)):
            return False
        requirements = SnapshotRequirementsV2(**{
            **requirements_data, "namespace": namespace})
        if (requirements.authority_id != operation.authority_id
                or requirements.graph_incarnation != proof.graph_incarnation
                or requirements.activation_generation != 1
                or requirements.revocation_epoch != 0):
            return False
        provision_data = _json(provision_row[2])
        if (type(provision_data) is not dict
                or set(provision_data) != {f.name for f in fields(NamespaceProvisionReceiptV2)}
                or provision_data["namespace"] != asdict(namespace)):
            return False
        provision = NamespaceProvisionReceiptV2(**{
            **provision_data, "namespace": namespace})
        if (provision_row[:2] != (ticket.creation_operation_id,
                                 ticket.creation_digest.removeprefix("sha256:"))
                or provision.operation_id != ticket.creation_operation_id
                or provision.input_digest != ticket.creation_digest.removeprefix("sha256:")
                or provision.namespace != namespace
                or provision.installation_id != operation.installation_id
                or provision.authority_id != operation.authority_id
                or provision.authority_namespace != requirements.authority_namespace
                or provision.graph_incarnation != proof.graph_incarnation
                or provision.generation != 1
                or provision.graph_revision != 0 or provision.graph_epoch != 0):
            return False
        if issue != (operation.operation_id, operation.request_digest,
                     operation.grant_id, operation.grant_digest,
                     proof.graph_incarnation, 1, proof.graph_epoch,
                     proof.graph_receipt_digest, canonical_json(asdict(proof))):
            return False
        key = owner_grant_key(*namespace.as_tuple)
        atom = db.execute(
            "SELECT bot,persona,owner_kind,subject,type_name,name,revision,value,valid "
            "FROM graph_atoms WHERE token=?", (key.token,)).fetchone()
        if (atom is None or atom[:7] != (namespace.bot_id, namespace.persona_id,
                "persona", None, key.type_name, "primary", 1) or atom[8] != 1):
            return False
        grant = _json(atom[7])
        validate_owner_grant_v1(grant)
        principal = asdict(operation.principal)
        if (grant["authority_id"] != operation.authority_id
                or grant["installation_id"] != operation.installation_id
                or grant["grant_id"] != operation.grant_id
                or grant["principal"] != principal
                or grant["ticket_id"] != ticket.ticket_id
                or grant["creation_operation_id"] != ticket.creation_operation_id
                or grant["creation_digest"] != ticket.creation_digest
                or grant["issue_operation_id"] != operation.operation_id
                or grant["graph_incarnation"] != proof.graph_incarnation
                or "sha256:" + canonical_digest(grant) != operation.grant_digest
                or owner_grant_policy_digest_v1(
                    grant, bot=namespace.bot_id, persona=namespace.persona_id)
                    != ticket.policy_digest):
            return False
        history = db.execute(
            "SELECT revision,value,valid,dependencies,event_bot,event_persona,"
            "event_session,event_id FROM graph_history WHERE token=?", (key.token,)).fetchall()
        if history != [(1, atom[7], 1, "[]", namespace.bot_id,
                        namespace.persona_id, "owner-authorization-v1",
                        operation.operation_id)]:
            return False
        event = db.execute(
            "SELECT revisions,epoch_revision FROM graph_events "
            "WHERE bot=? AND persona=? AND session=? AND event_id=?",
            namespace.as_tuple + ("owner-authorization-v1", operation.operation_id),
        ).fetchone()
        if event != (canonical_json([[key.token, 1]]), proof.graph_epoch):
            return False
        expected_attempt = "owner-write-" + canonical_digest({
            "namespace": list(namespace.as_tuple), "operation_id": operation.operation_id,
            "grant_digest": operation.grant_digest})[:48]
        if (intent[:3] != (operation.operation_id, operation.grant_digest,
                           expected_attempt)
                or intent[3] != canonical_json(asdict(requirements))
                or intent[5:] != (0, 0)
                or fence[0] != operation.operation_id
                or fence[2:6] != (0, 0, 1, proof.graph_epoch)):
            return False
        permit_wire = _json(fence[1])
        permit = from_wire(permit_wire)
        if (type(permit) is not FencePermitV2
                or canonical_json(to_wire(permit)) != fence[1]
                or permit.operation_id != expected_attempt
                or permit.operation != "write" or permit.generation != 1
                or permit.authority_id != operation.authority_id
                or permit.namespace != requirements.authority_namespace
                or intent[4] != canonical_json(asdict(permit.pinned_anchor))):
            return False
        digest = "sha256:" + canonical_digest({
            "schema": "sylanne3.graph.owner_issue_receipt.v1",
            "namespace": list(namespace.as_tuple),
            "operation_id": operation.operation_id,
            "request_digest": operation.request_digest,
            "grant_id": operation.grant_id,
            "grant_digest": operation.grant_digest,
            "graph_incarnation": proof.graph_incarnation,
            "grant_revision": 1,
            "graph_access_epoch": 1,
            "graph_epoch": proof.graph_epoch,
            "graph_revision": 1,
            "atom_token": key.token,
        })
        finish_id = "finish:" + expected_attempt
        finish_digest = "sha256:" + canonical_digest({
            "operation_id": expected_attempt, "permit_token": permit.token,
            "action": "finish_owner_issue",
            "business_operation_id": operation.operation_id,
            "graph_receipt_digest": proof.graph_receipt_digest,
        })
        if (digest != proof.graph_receipt_digest
                or fence[6:] != (finish_id, finish_digest)):
            return False
        # A graph row records an intended finish only. The callback must verify
        # independent Authority durability while this graph snapshot remains open.
        return self._finished_fence_verifier(permit, finish_id, finish_digest) is True


__all__ = ("PinnedCurrentGraphVerifier",)
