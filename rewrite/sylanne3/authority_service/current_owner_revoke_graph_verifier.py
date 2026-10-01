"""Pinned, read-only GraphStore proof check for a first Owner revoke.

The graph database is selected by trusted installation configuration.  A
graph-side finish request is only an intention: the injected Authority reader
must independently establish that the exact write fence finished durably.
"""

from __future__ import annotations

from contextlib import closing
from dataclasses import asdict, fields, replace
import json
from pathlib import Path
import sqlite3
from typing import Callable

from ..contracts import Event, Scope, canonical_json
from ..graph_types import owner_grant_key, validate_owner_grant_v1
from ..runtime_contracts import SnapshotRequirementsV2, canonical_digest
from .v2_contract import FencePermitV2, from_wire as fence_from_wire, to_wire as fence_to_wire
from .v2_owner_contract import (
    OwnerAuthorizationOperationV1, OwnerAuthorizationReceiptV1,
    OwnerGraphCommitProofV1,
    canonical_digest as owner_digest,
)


def _canonical(raw: str):
    value = json.loads(raw)
    if canonical_json(value) != raw:
        raise ValueError("noncanonical graph JSON")
    return value


def _revoke_invalidations(db: sqlite3.Connection, namespace, grant_token: str,
                          graph_epoch: int, operation_id: str) -> list[list]:
    """Recompute GraphStore's pre-revoke reverse closure from durable edges.

    Rewriting the grant removes its outgoing edges, while downstream edges stay
    in ``graph_dependencies``.  Every previously valid downstream atom must
    have exactly one matching invalidation history row and current invalid head.
    """
    ns = namespace.as_tuple
    seen = {grant_token}
    pending = [grant_token]
    closure = set()
    while pending:
        token = pending.pop()
        for (dependent,) in db.execute(
                "SELECT dependent_token FROM graph_dependencies "
                "WHERE dependency_token=?", (token,)):
            closure.add(dependent)
            if dependent not in seen:
                seen.add(dependent)
                pending.append(dependent)
    expected = []
    session = "owner-authorization-revoke-v1"
    for token in sorted(closure - {grant_token}):
        current = db.execute(
            "SELECT bot,persona,revision,value,valid FROM graph_atoms "
            "WHERE token=?", (token,),
        ).fetchone()
        prior = db.execute(
            "SELECT h.revision,h.value,h.valid,h.dependencies "
            "FROM graph_history AS h JOIN graph_events AS e ON "
            "e.bot=h.event_bot AND e.persona=h.event_persona "
            "AND e.session=h.event_session AND e.event_id=h.event_id "
            "WHERE h.token=? AND e.epoch_revision<? "
            "ORDER BY h.revision DESC LIMIT 1", (token, graph_epoch),
        ).fetchone()
        dependencies = db.execute(
            "SELECT dependency_token,dependency_revision "
            "FROM graph_dependencies WHERE dependent_token=? "
            "ORDER BY dependency_token", (token,),
        ).fetchall()
        history = db.execute(
            "SELECT revision,value,valid,dependencies FROM graph_history "
            "WHERE token=? AND event_bot=? AND event_persona=? "
            "AND event_session=? AND event_id=?",
            (token,) + ns + (session, operation_id),
        ).fetchall()
        prior_dependencies = _canonical(prior[3]) if prior is not None else None
        if (type(prior_dependencies) is not list
                or any(type(edge) is not list or len(edge) != 2
                       or type(edge[0]) is not str or not edge[0]
                       or type(edge[1]) is not int or edge[1] < 0
                       for edge in prior_dependencies)
                or len({edge[0] for edge in prior_dependencies})
                != len(prior_dependencies)):
            raise ValueError("Owner revoke prior dependency history is invalid")
        if (current is None or prior is None or current[:2] != ns
                or {edge[0]: edge[1] for edge in prior_dependencies}
                != dict(dependencies)):
            raise ValueError("Owner revoke dependency closure differs")
        if prior[2] == 1:
            revision = prior[0] + 1
            if (current[2:] != (revision, prior[1], 0)
                    or history != [(revision, prior[1], 0,
                                    canonical_json([list(row) for row in dependencies]))]):
                raise ValueError("Owner revoke invalidated head differs")
            expected.append([token, revision])
        elif prior[2] == 0:
            if current[2:] != prior[:3] or history:
                raise ValueError("Owner revoke prior invalid head changed")
        else:
            raise ValueError("invalid graph history validity")
    event_history = db.execute(
        "SELECT token,revision,valid FROM graph_history "
        "WHERE event_bot=? AND event_persona=? AND event_session=? "
        "AND event_id=? ORDER BY token",
        ns + (session, operation_id),
    ).fetchall()
    expected_history = sorted(
        [(grant_token, 2, 1)] + [(token, revision, 0)
                                 for token, revision in expected]
    )
    if event_history != expected_history:
        raise ValueError("Owner revoke event history differs from closure")
    return expected


class PinnedCurrentOwnerRevokeGraphVerifier:
    """Verify a rev2 grant against the current graph and an independent fence.

    ``finished_fence_verifier(permit, finish_id, finish_digest)`` must read the
    independent Authority operation and return exact ``True`` only for its
    durable finished state.  It must never infer completion from graph rows.
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
                or operation.action != "revoke" or operation.ticket is not None
                or operation.expected_grant_revision != 1
                or type(proof) is not OwnerGraphCommitProofV1
                or proof.namespace != operation.namespace
                or proof.operation_id != operation.operation_id
                or proof.request_digest != operation.request_digest
                or proof.grant_id != operation.grant_id
                or proof.grant_digest != operation.grant_digest
                or proof.grant_revision != 2):
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
        ns = namespace.as_tuple
        recovery = db.execute(
            "SELECT schema,requirements_json,graph_revision "
            "FROM graph_recovery_metadata_v2 WHERE bot=? AND persona=?", ns,
        ).fetchone()
        epoch = db.execute(
            "SELECT revision FROM graph_epochs WHERE bot=? AND persona=?", ns,
        ).fetchone()
        access = db.execute(
            "SELECT access_epoch,delete_epoch FROM graph_authority_epochs "
            "WHERE bot=? AND persona=?", ns,
        ).fetchone()
        issue = db.execute(
            "SELECT operation_id,request_digest,grant_id,grant_digest,"
            "graph_incarnation,graph_access_epoch,graph_epoch,"
            "graph_receipt_digest,proof_json FROM graph_owner_issue_operations_v1 "
            "WHERE bot=? AND persona=?", ns,
        ).fetchone()
        revoke = db.execute(
            "SELECT operation_id,request_digest,grant_id,grant_digest,"
            "graph_incarnation,previous_grant_digest,graph_access_epoch,"
            "graph_epoch,graph_receipt_digest,proof_json,fence_attempt_id,"
            "finish_request_id,finish_request_digest "
            "FROM graph_owner_revoke_operations_v1 WHERE bot=? AND persona=?",
            ns,
        ).fetchone()
        intent = db.execute(
            "SELECT operation_id,request_digest,operation_json,pending_receipt_json,"
            "attempt_id,requirements_json,anchor_json,pre_graph_revision,"
            "pre_graph_epoch,pre_access_epoch,permit_json,finish_request_id,"
            "finish_request_digest,state FROM graph_owner_revoke_intents_v1 "
            "WHERE bot=? AND persona=? AND operation_id=?",
            ns + (operation.operation_id,),
        ).fetchone()
        if any(row is None for row in (recovery, epoch, access, issue, revoke, intent)):
            return False
        if (recovery[0] != "sylanne3.authority.v2"
                or recovery[2] < intent[7] + 1
                or epoch[0] < proof.graph_epoch
                or access != (proof.graph_access_epoch, 0)
                or proof.graph_access_epoch != intent[9] + 1
                or proof.graph_epoch != intent[8] + 1):
            return False
        requirements_data = _canonical(recovery[1])
        if (type(requirements_data) is not dict
                or set(requirements_data) != {field.name for field in fields(SnapshotRequirementsV2)}
                or requirements_data["namespace"] != asdict(namespace)):
            return False
        requirements = SnapshotRequirementsV2(**{
            **requirements_data, "namespace": namespace,
        })
        if (requirements.authority_id != operation.authority_id
                or requirements.graph_incarnation != proof.graph_incarnation
                or requirements.activation_generation != 1
                or requirements.revocation_epoch != 0):
            return False
        if (_canonical(intent[5]) != asdict(requirements)
                or intent[0:2] != (operation.operation_id, operation.request_digest)
                or _canonical(intent[2]) != asdict(operation)
                or intent[7] < 1 or intent[8] < 1
                or intent[9] < 1 or intent[13] != "committed"):
            return False
        expected_attempt = "owner-revoke-write-" + canonical_digest({
            "namespace": list(ns), "operation_id": operation.operation_id,
            "grant_digest": operation.grant_digest,
        })[:48]
        if intent[4] != expected_attempt:
            return False
        pending_guard = replace(
            operation.expected_guard,
            pending_revoke_operation_id=operation.operation_id,
        )
        pending_receipt = OwnerAuthorizationReceiptV1(
            operation, "pending", "owner-revoke-pending:"
            + operation.request_digest.removeprefix("sha256:")[:48],
            pending_guard,
        )
        if _canonical(intent[3]) != asdict(pending_receipt):
            return False
        issue_proof = OwnerGraphCommitProofV1(
            namespace, issue[0], issue[1], issue[2], issue[3], issue[4],
            1, issue[5], issue[6], issue[7],
        )
        if (issue[2] != operation.grant_id
                or issue[4] != proof.graph_incarnation
                or issue[5] != 1 or issue[6] != 1
                or issue[8] != canonical_json(asdict(issue_proof))
                or operation.expected_guard.authorization_revision != 1
                or operation.expected_guard.authorization_head != owner_digest(issue_proof)
                or operation.expected_guard.pending_revoke_operation_id is not None):
            return False
        key = owner_grant_key(*ns)
        atom = db.execute(
            "SELECT bot,persona,owner_kind,subject,type_name,name,revision,value,valid "
            "FROM graph_atoms WHERE token=?", (key.token,),
        ).fetchone()
        if (atom is None or atom[:7] != (namespace.bot_id, namespace.persona_id,
                "persona", None, key.type_name, "primary", 2) or atom[8] != 1):
            return False
        revoked_grant = _canonical(atom[7])
        validate_owner_grant_v1(revoked_grant)
        if (revoked_grant["state"] != "revoked"
                or revoked_grant["grant_revision"] != 2
                or revoked_grant["authority_id"] != operation.authority_id
                or revoked_grant["installation_id"] != operation.installation_id
                or revoked_grant["grant_id"] != operation.grant_id
                or revoked_grant["principal"] != asdict(operation.principal)
                or revoked_grant["graph_incarnation"] != proof.graph_incarnation
                or "sha256:" + canonical_digest(revoked_grant) != proof.grant_digest):
            return False
        history = db.execute(
            "SELECT revision,value,valid,dependencies,event_bot,event_persona,"
            "event_session,event_id FROM graph_history WHERE token=? ORDER BY revision",
            (key.token,),
        ).fetchall()
        if (len(history) != 2
                or history[0][0] != 1 or history[1] != (
                    2, atom[7], 1, "[]", namespace.bot_id, namespace.persona_id,
                    "owner-authorization-revoke-v1", operation.operation_id)
                or history[0][2:] != (1, "[]", namespace.bot_id,
                    namespace.persona_id, "owner-authorization-v1", issue[0])):
            return False
        original_grant = _canonical(history[0][1])
        validate_owner_grant_v1(original_grant)
        expected_revoked = {**original_grant, "state": "revoked", "grant_revision": 2}
        if (revoked_grant != expected_revoked
                or original_grant["state"] != "pending_authority"
                or original_grant["grant_revision"] != 1
                or original_grant["issue_operation_id"] != issue[0]
                or original_grant["authority_id"] != operation.authority_id
                or original_grant["installation_id"] != operation.installation_id
                or original_grant["principal"] != asdict(operation.principal)
                or original_grant["grant_id"] != operation.grant_id
                or original_grant["graph_incarnation"] != proof.graph_incarnation
                or "sha256:" + canonical_digest(original_grant) != issue[3]):
            return False
        issue_receipt_digest = "sha256:" + canonical_digest({
            "schema": "sylanne3.graph.owner_issue_receipt.v1",
            "namespace": list(ns), "operation_id": issue[0],
            "request_digest": issue[1], "grant_id": issue[2],
            "grant_digest": issue[3], "graph_incarnation": issue[4],
            "grant_revision": 1, "graph_access_epoch": 1,
            "graph_epoch": 1, "graph_revision": 1,
            "atom_token": key.token,
        })
        if issue[7] != issue_receipt_digest:
            return False
        issue_event = db.execute(
            "SELECT digest,reads,epoch_reads,revisions,invalidated,epoch_revision "
            "FROM graph_events "
            "WHERE bot=? AND persona=? AND session='owner-authorization-v1' "
            "AND event_id=?", ns + (issue[0],),
        ).fetchone()
        revoke_event = db.execute(
            "SELECT digest,reads,epoch_reads,revisions,invalidated,epoch_revision "
            "FROM graph_events "
            "WHERE bot=? AND persona=? AND session='owner-authorization-revoke-v1' "
            "AND event_id=?", ns + (operation.operation_id,),
        ).fetchone()
        expected_issue_event = Event(
            Scope(*ns, "owner-authorization-v1"), issue[0], 0,
            "first_owner_grant", {"request_digest": issue[1],
                                  "grant_digest": issue[3]},
        )
        expected_revoke_event = Event(
            Scope(*ns, "owner-authorization-revoke-v1"), operation.operation_id,
            0, "owner_grant_revoked", {
                "request_digest": operation.request_digest,
                "grant_digest": operation.grant_digest,
            },
        )
        invalidated = _revoke_invalidations(
            db, namespace, key.token, proof.graph_epoch, operation.operation_id)
        if (issue_event != (
                expected_issue_event.digest, canonical_json([[key.token, 0]]),
                canonical_json([[*ns, 0]]), canonical_json([[key.token, 1]]),
                "[]", 1)
                or revoke_event != (
                    expected_revoke_event.digest,
                    canonical_json([[key.token, 1]]),
                    canonical_json([[*ns, intent[8]]]),
                    canonical_json([[key.token, 2]]),
                    canonical_json(invalidated), proof.graph_epoch)):
            return False
        if revoke != (
                operation.operation_id, operation.request_digest,
                operation.grant_id, operation.grant_digest,
                proof.graph_incarnation, issue[3], proof.graph_access_epoch,
                proof.graph_epoch, proof.graph_receipt_digest,
                canonical_json(asdict(proof)), intent[4], intent[11], intent[12]):
            return False
        permit_wire = _canonical(intent[10])
        permit = fence_from_wire(permit_wire)
        if (type(permit) is not FencePermitV2
                or canonical_json(fence_to_wire(permit)) != intent[10]
                or permit.operation != "write" or permit.operation_id != intent[4]
                or permit.authority_id != operation.authority_id
                or permit.namespace != requirements.authority_namespace
                or permit.generation != requirements.activation_generation
                or intent[6] != canonical_json(asdict(permit.pinned_anchor))):
            return False
        digest = "sha256:" + canonical_digest({
            "schema": "sylanne3.graph.owner_revoke_receipt.v1",
            "namespace": list(ns), "operation_id": operation.operation_id,
            "request_digest": operation.request_digest,
            "grant_id": operation.grant_id, "grant_digest": operation.grant_digest,
            "graph_incarnation": proof.graph_incarnation,
            "grant_revision": 2, "graph_access_epoch": proof.graph_access_epoch,
            "graph_epoch": proof.graph_epoch,
            "graph_revision": intent[7] + 1, "atom_token": key.token,
        })
        finish_id = "finish:" + intent[4]
        finish_digest = "sha256:" + canonical_digest({
            "action": "finish_owner_revoke", "operation_id": intent[4],
            "permit_token": permit.token,
        })
        if (digest != proof.graph_receipt_digest
                or (intent[11], intent[12]) != (finish_id, finish_digest)):
            return False
        return self._finished_fence_verifier(permit, finish_id, finish_digest) is True


__all__ = ("PinnedCurrentOwnerRevokeGraphVerifier",)
