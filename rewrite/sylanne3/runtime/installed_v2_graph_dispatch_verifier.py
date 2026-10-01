"""Pinned, read-only Graph proof for an installed Authority V2 dispatch fence.

The Authority still owns Owner revocation and execution-journal decisions. This
reader proves that its effect and conflict keys originate from one currently
usable Graph admission; it never releases content or creates a permit.
"""

from __future__ import annotations

from dataclasses import asdict
from contextlib import closing
import json
import math
from pathlib import Path
import sqlite3
from typing import Callable, Mapping

from ..authority_service.local_bridge import constraint_keys_from_footprint
from ..authority_service.v2_owner_contract import OwnerGraphCommitProofV1
from ..contracts import canonical_json
from ..domains.d08.execution import (
    ActionSchema, ActionSchemaRecord, GoalExecutionProvider,
    RequiredCheckRegistry,
)
from ..graph_store import GraphStore
from ..graph_types import owner_grant_key, validate_owner_grant_v1
from ..runtime_contracts import NamespaceId, canonical_digest
from .dispatch_admission import check_receipts_against_specs, load_request
from .natural_dispatch_current_read_v2 import (
    read_current_natural_dispatch_segment_in_transaction_v2,
    recover_natural_dispatch_candidate_in_transaction_v2,
)


def _current_owner_graph(db, namespace: NamespaceId, admission, metadata) -> bool:
    """Match the active Graph grant to its immutable issue receipt."""
    row = db.execute(
        "SELECT revision,value,valid FROM graph_atoms WHERE token=?",
        (owner_grant_key(*namespace.as_tuple).token,),
    ).fetchone()
    proof_row = db.execute(
        "SELECT operation_id,request_digest,grant_id,grant_digest,"
        "graph_incarnation,graph_access_epoch,graph_epoch,"
        "graph_receipt_digest,proof_json FROM graph_owner_issue_operations_v1 "
        "WHERE bot=? AND persona=?", namespace.as_tuple,
    ).fetchone()
    epochs = db.execute(
        "SELECT access_epoch,delete_epoch FROM graph_authority_epochs "
        "WHERE bot=? AND persona=?", namespace.as_tuple,
    ).fetchone()
    if row is None or proof_row is None or epochs is None:
        return False
    grant = json.loads(row[1])
    validate_owner_grant_v1(grant)
    proof = OwnerGraphCommitProofV1(
        namespace, proof_row[0], proof_row[1], proof_row[2], proof_row[3],
        proof_row[4], grant["grant_revision"], proof_row[5], proof_row[6],
        proof_row[7],
    )
    requirements = metadata.requirements
    return (
        row == (1, canonical_json(grant), 1)
        and proof_row[8] == canonical_json(asdict(proof))
        and "sha256:" + canonical_digest(grant) == proof.grant_digest
        and (grant["issue_operation_id"], grant["grant_id"])
        == (proof.operation_id, proof.grant_id)
        and grant["state"] == "pending_authority"
        and (grant["graph_incarnation"], proof.graph_incarnation,
             admission.graph_incarnation)
        == (requirements.graph_incarnation,) * 3
        and grant["activation_generation"]
        == requirements.activation_generation
        and grant["authority_id"] == requirements.authority_id
        and grant["scope"] == "/".join(namespace.as_tuple)
        and requirements.revocation_epoch == 0
        and proof.graph_access_epoch <= epochs[0]
        and proof.graph_epoch <= db.execute(
            "SELECT revision FROM graph_epochs WHERE bot=? AND persona=?",
            namespace.as_tuple,
        ).fetchone()[0]
        and (admission.access_epoch, admission.delete_epoch) == epochs
        and admission.owner_head_ref == grant["grant_id"]
        and admission.purpose in grant["purposes"]
        and set(admission.audience).issubset(grant["audiences"])
    )


def _current_d08_and_checks(
    db, namespace: NamespaceId, admission, request, recovered, now_utc: float,
) -> bool:
    evidence = recovered.evidence
    refs = (evidence.action_ref, evidence.schema_ref, evidence.grant_ref)
    values = []
    for ref, expected in zip(refs, recovered.write_versions[:3]):
        if ref != expected[0]:
            return False
        row = db.execute(
            "SELECT revision,value,valid FROM graph_atoms "
            "WHERE token=? AND bot=? AND persona=?",
            (ref,) + namespace.as_tuple,
        ).fetchone()
        if row is None or row[0] != expected[1] or row[2] != 1:
            return False
        values.append(json.loads(row[1]))
    validators = {spec.name: spec.validator
                  for spec in GoalExecutionProvider().register_types()}
    action = validators["d08.action_intent.v1"](values[0])
    schema = validators["d08.action_schema.v1"](values[1])
    grant = validators["d08.communication_intent_grant.v1"](values[2])
    if type(schema) is not ActionSchemaRecord:
        return False
    frozen = ActionSchema(
        schema.schema_id, schema.action_kind, schema.proactive,
        schema.required_checks,
    )
    if (ActionSchemaRecord.bind(action, frozen) != schema
            or frozen.proactive
            or len(action.required_checks) != 5
            or (canonical_digest(action), canonical_digest(schema),
                canonical_digest(grant)) != (
                    admission.action_intent_digest,
                    admission.action_schema_digest, admission.grant_digest)
            or (action.action_id, action.target_ref, action.purpose)
            != (admission.action_ref, admission.object_ref,
                admission.purpose)
            or (action.identity.operation_id, action.identity.effect_id,
                action.identity.activity_id)
            != (request.operation_id, request.effect_id,
                request.activity_id)
            or grant.required_check_refs != request.required_check_refs
            or grant.purpose != admission.purpose):
        return False
    check_receipts_against_specs(
        admission, action.required_checks, now_utc)
    registry = RequiredCheckRegistry()
    registry.register(frozen)
    qualified = registry.qualify(
        action, admission.check_receipts, now=now_utc)
    return (
        qualified.status == "qualified"
        and qualified.receipt_digest == grant.qualification_receipt_digest
        and grant.valid_until > now_utc
        and grant.audiences == admission.audience
        and grant.target_ref == action.target_ref
        and admission.required_checks_digest
        == canonical_digest(action.required_checks)
    )


def make_installed_v2_graph_dispatch_verifier(
    graph_path: str | Path,
    namespace_map: Mapping[str, NamespaceId],
    trusted_utc: Callable[[], float],
) -> Callable[[str, str, tuple[str, ...]], bool]:
    """Bind a trusted Graph file, namespace map and clock before Authority opens."""
    path = Path(graph_path).resolve(strict=True)
    if (not path.is_file() or not callable(trusted_utc)
            or not namespace_map or any(
                type(key) is not str or not key
                or type(value) is not NamespaceId
                for key, value in namespace_map.items()
            ) or len(set(namespace_map.values())) != len(namespace_map)):
        raise ValueError("installed V2 dispatch verifier configuration differs")
    namespaces = dict(namespace_map)

    def verify(authority_namespace: str, effect_id: str,
               constraint_keys: tuple[str, ...]) -> bool:
        namespace = namespaces.get(authority_namespace)
        if (namespace is None or type(effect_id) is not str or not effect_id
                or type(constraint_keys) is not tuple):
            return False
        try:
            now_utc = trusted_utc()
            if (type(now_utc) not in (int, float)
                    or not math.isfinite(now_utc)):
                return False
            with closing(sqlite3.connect(
                    path.as_uri() + "?mode=ro", uri=True)) as db:
                db.execute("PRAGMA query_only=ON")
                db.execute("BEGIN")
                rows = db.execute(
                    "SELECT admission_ref FROM graph_dispatch_admissions "
                    "WHERE bot=? AND persona=? AND effect_id=?",
                    namespace.as_tuple + (effect_id,),
                ).fetchall()
                if len(rows) != 1:
                    return False
                loaded = load_request(db, namespace, rows[0][0])
                if loaded is None:
                    return False
                receipt, request = loaded
                admission = receipt.admission
                if (request.effect_id != effect_id
                        or request.namespace != "/".join(namespace.as_tuple)
                        or request.footprint.effect_id != effect_id
                        or request.footprint.namespace
                        != "/".join(namespace.as_tuple)
                        or constraint_keys_from_footprint(request.footprint)
                        != constraint_keys):
                    return False
                admission.require_current(now_utc)
                metadata_row = db.execute(
                    "SELECT schema,requirements_json,graph_revision "
                    "FROM graph_recovery_metadata_v2 WHERE bot=? AND persona=?",
                    namespace.as_tuple,
                ).fetchone()
                metadata = GraphStore._decode_recovery(
                    metadata_row, namespace)
                if (metadata is None
                        or not _current_owner_graph(
                            db, namespace, admission, metadata)):
                    return False
                recovered = (
                    recover_natural_dispatch_candidate_in_transaction_v2(
                        db, namespace, request.operation_id))
                if (recovered is None
                        or not _current_d08_and_checks(
                            db, namespace, admission, request,
                            recovered, now_utc)
                        or read_current_natural_dispatch_segment_in_transaction_v2(
                            db, namespace, request, now_utc=now_utc) is None):
                    return False
                return True
        except (LookupError, OSError, sqlite3.Error, TypeError, ValueError,
                RuntimeError):
            return False

    return verify


__all__ = ["make_installed_v2_graph_dispatch_verifier"]
