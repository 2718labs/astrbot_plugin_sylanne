"""D11 signs graph evidence only after a current same-transaction D04 read."""

from dataclasses import replace
import json

import pytest

from sylanne3.authority_service.v2_contract import FencePermitV2
from sylanne3.graph_types import NamespaceEpoch
from sylanne3.runtime.issuers import (
    D02ResourceIssuer, D11BudgetJobIssuer, IssuerAuthorityDenied, install_schema,
)
from sylanne3.runtime.restore_anchor import RestoreAnchor
from sylanne3.runtime_contracts import FenceScope

from test_authoritative_coupling_snapshot import _fixture, _read


def _scope(namespace):
    anchor = RestoreAnchor(
        authority_id="authority-A", namespace="authority-namespace-A",
        activation_generation=1, deletion_journal_id="deletion-A",
        deletion_seq=0, deletion_digest="genesis",
        execution_journal_id="execution-A", execution_seq=0,
        execution_digest="genesis", revocation_epoch=0, proof="opaque-proof",
    )
    permit = FencePermitV2(
        authority_id=anchor.authority_id, namespace=anchor.namespace,
        subject="subject-A", holder="holder-A", generation=1,
        operation="write", operation_id="write-attempt-A", token="t" * 32,
        fence_epoch=7, revision=2, pinned_anchor=anchor,
    )
    return FenceScope(
        namespace, anchor.namespace, 1, "write", permit.operation_id,
        permit, anchor, NamespaceEpoch(*namespace.as_tuple, 1), 1,
    )


def _issue(issuer, db, candidate, scope, store, scheme, operation_id="op-one"):
    return issuer._issue_d04_coupling_graph_evidence_v1(
        db, candidate=candidate, write_scope=scope, registry=store._registry,
        scheme=scheme, audience=("owner",), purpose="context",
        operation_id=operation_id,
    )


def test_d11_graph_evidence_exact_replay_and_tamper_hold(tmp_path):
    store, namespace, scheme, assets, _source, root = _fixture(tmp_path)
    db = store._db
    install_schema(db)
    issuer = D11BudgetJobIssuer(D02ResourceIssuer(b"d" * 32), b"j" * 32)
    scope = _scope(namespace)
    candidate = _read(store, namespace, scheme, assets, root)
    try:
        with pytest.raises(IssuerAuthorityDenied, match="write transaction"):
            _issue(issuer, db, candidate, scope, store, scheme)
        db.execute("BEGIN IMMEDIATE")
        with pytest.raises(IssuerAuthorityDenied, match="graph stamp differs"):
            _issue(issuer, db, candidate, replace(scope, graph_revision=2),
                   store, scheme)
        issued = _issue(issuer, db, candidate, scope, store, scheme)
        assert _issue(issuer, db, candidate, scope, store, scheme) == issued
        verified = issuer._verify_d04_coupling_graph_evidence_v1(
            db, namespace=namespace, operation_id="op-one",
        )
        assert verified[0] == issued[0]
        evidence = json.loads(verified[1])
        assert evidence["candidate"]["graph_incarnation"] == "graph:one"
        assert evidence["candidate"]["query_epoch"]["revision"] == 1
        assert evidence["candidate"]["read_versions"]
        assert evidence["write_scope"]["attempt_id"] == scope.operation_id
        with pytest.raises(IssuerAuthorityDenied, match="identity conflicts"):
            _issue(issuer, db, replace(candidate, snapshot_digest="a" * 64),
                   scope, store, scheme)
        db.execute("COMMIT")

        original = json.loads(db.execute(
            "SELECT value FROM graph_atoms WHERE token=?", (root.token,),
        ).fetchone()[0])
        from sylanne3.contracts import canonical_json

        db.execute("UPDATE graph_atoms SET value=? WHERE token=?",
                   (canonical_json({**original, "readout_proof_digest": "b" * 64}),
                    root.token))
        db.execute("BEGIN IMMEDIATE")
        with pytest.raises(IssuerAuthorityDenied, match="not current"):
            _issue(issuer, db, candidate, scope, store, scheme, "op-two")
        assert _issue(issuer, db, candidate, scope, store, scheme) == issued
        db.execute("COMMIT")

        db.execute("UPDATE runtime_d04_coupling_graph_evidence_v1 "
                   "SET candidate_digest=? WHERE bot=? AND persona=? AND operation_id=?",
                   ("0" * 64, *namespace.as_tuple, "op-one"))
        with pytest.raises(IssuerAuthorityDenied, match="invalid"):
            issuer._verify_d04_coupling_graph_evidence_v1(
                db, namespace=namespace, operation_id="op-one")
    finally:
        if db.in_transaction:
            db.execute("ROLLBACK")
        store.close()
