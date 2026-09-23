"""Local Authority composition checks the independent durable write fence."""

from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
import sqlite3

import pytest

from rewrite.tests.alpha1.runtime.test_authority_v2_fence_service import installed
from sylanne3.authority_service.contract import AuthorityUnavailable
from sylanne3.authority_service.local_composition import compose_local_owner_authority
from sylanne3.authority_service.mtls_server import AdministratorInstallationV2
from sylanne3.runtime_contracts import NamespaceId


ROLE = NamespaceId("bot", "persona")


def _compose(tmp_path, service, core, *, graph_path=None, bindings=True):
    graph_path = Path(graph_path) if graph_path is not None else tmp_path / "graph.db"
    if graph_path.is_absolute() and not graph_path.exists():
        sqlite3.connect(graph_path).close()
    return compose_local_owner_authority(
        core=core, v2_fences={"ns-a": service}, graph_db_path=graph_path,
        utc_clock=lambda: datetime.now(timezone.utc),
        first_claim_verifier=lambda *_: False,
        claimant_verifier=lambda *_: False,
        administrator_authorizer=lambda *_: False,
        publisher_manifest_verifier=lambda *_: False,
        installations_v2={("a" * 64, "profile"): AdministratorInstallationV2(
            "installation", "holder-a", "policy", "capabilities-v2", "b" * 64)},
        namespace_bindings_v2={
            ("a" * 64, "profile", ROLE): "ns-a"} if bindings else {},
        create_owner_schema=True,
    )


def test_composition_reads_exact_finished_authority_fence(tmp_path):
    service, core, _, deletion, guard, execution, _ = installed(tmp_path)
    try:
        server = _compose(tmp_path, service, core)
        verifier = server._v2_owner_tickets._graph_commit_verifier
        finished = verifier._finished_fence_verifier
        anchor = service.current_anchor(credential="ok", subject="subject-a")
        permit = service.begin_fence(
            credential="ok", subject="subject-a", holder="holder-a",
            operation="write", operation_id="owner-write", expected_anchor=anchor)
        digest = "sha256:" + "c" * 64
        assert finished(permit, "finish-owner-write", digest) is False
        service.finish_fence(
            credential="ok", subject="subject-a", permit=permit,
            request_id="finish-owner-write", request_digest=digest)
        assert finished(permit, "finish-owner-write", digest) is True
        unrelated = service.begin_fence(
            credential="ok", subject="subject-a", holder="holder-a",
            operation="write", operation_id="unrelated-write", expected_anchor=anchor)
        assert finished(unrelated, "finish-unrelated-write", digest) is False
        service.finish_fence(
            credential="ok", subject="subject-a", permit=unrelated,
            request_id="finish-unrelated-write", request_digest=digest)
        assert unrelated.fence_epoch > permit.fence_epoch
        assert finished(permit, "finish-owner-write", digest) is True
        assert finished(permit, "other-finish", digest) is False
        assert finished(permit, "finish-owner-write", "sha256:" + "d" * 64) is False
        assert finished(
            replace(permit, operation_id=unrelated.operation_id),
            "finish-owner-write", digest) is False
        assert finished(replace(permit, operation="read"), "finish-owner-write", digest) is False
        different_token = permit.token[:-1] + ("A" if permit.token[-1] != "A" else "B")
        assert finished(replace(permit, token=different_token), "finish-owner-write", digest) is False
        with core._tx() as db:
            db.execute("UPDATE authority_namespaces SET revocation_epoch=1 WHERE namespace='ns-a'")
        assert finished(permit, "finish-owner-write", digest) is False
    finally:
        core.close()
        deletion.close()
        guard.close()
        execution.close()


def test_composition_requires_pinned_graph_and_installed_identity(tmp_path):
    service, core, _, deletion, guard, execution, _ = installed(tmp_path)
    try:
        with pytest.raises(AuthorityUnavailable, match="bindings"):
            _compose(tmp_path, service, core, bindings=False)
        with pytest.raises(ValueError, match="absolute"):
            _compose(tmp_path, service, core, graph_path="relative-graph.db")
    finally:
        core.close()
        deletion.close()
        guard.close()
        execution.close()
