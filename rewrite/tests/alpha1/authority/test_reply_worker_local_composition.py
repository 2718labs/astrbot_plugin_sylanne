"""The installed worker result reader pins both D06 and reply graph checks."""

from datetime import datetime, timezone
import sqlite3

import pytest

from rewrite.tests.alpha1.runtime.test_authority_v2_fence_service import installed
from sylanne3.authority_service.contract import AuthorityUnavailable
from sylanne3.authority_service.current_model_egress_graph_verifier import (
    PinnedCurrentModelEgressGraphVerifier,
)
from sylanne3.authority_service.current_reply_worker_model_result_graph_verifier import (
    PinnedCurrentReplyWorkerModelResultGraphVerifier,
)
from sylanne3.authority_service.local_composition import compose_local_owner_authority
from sylanne3.authority_service.mtls_server import AdministratorInstallationV2
from sylanne3.authority_service.v2_model_egress_service import AuthorityV2ModelEgressService
from sylanne3.authority_service.v2_model_egress_store import AuthorityV2ModelEgressStore
from sylanne3.runtime.issuers import D02ResourceIssuer, D11BudgetJobIssuer
from sylanne3.runtime_contracts import NamespaceId


def test_installed_reply_worker_reader_pins_graph_and_rejects_other_peer(tmp_path):
    fences, core, _, deletion, guard, execution, _ = installed(tmp_path)
    try:
        path = tmp_path / "graph.db"
        sqlite3.connect(path).close()
        issuer = D11BudgetJobIssuer(D02ResourceIssuer(b"d" * 32), b"j" * 32)
        model_graph = PinnedCurrentModelEgressGraphVerifier(
            path, d11_issuer=issuer, trusted_now_utc=lambda: 1.0)
        model = object.__new__(AuthorityV2ModelEgressService)
        model._store = AuthorityV2ModelEgressStore(
            core._db, create=True, lock=core._lock)
        model._fences = fences
        model._graph_verifier = model_graph
        model._admin_model_policy = object()
        peer = ("a" * 64, "profile")
        namespace = NamespaceId("bot", "persona")
        kwargs = dict(
            core=core, v2_fences={"ns-a": fences}, graph_db_path=path,
            utc_clock=lambda: datetime.now(timezone.utc),
            first_claim_verifier=lambda *_: False,
            claimant_verifier=lambda *_: False,
            administrator_authorizer=lambda *_: False,
            publisher_manifest_verifier=lambda *_: False,
            installations_v2={peer: AdministratorInstallationV2(
                "installation", "holder-a", "policy", "capabilities-v2", "b" * 64)},
            namespace_bindings_v2={(peer[0], peer[1], namespace): "ns-a"},
            v2_model_egress={"ns-a": model},
            worker_result_readers_v2={"ns-a": peer},
            create_owner_schema=True, create_worker_result_schema=True,
        )
        server = compose_local_owner_authority(**kwargs)
        worker = server._v2_worker_model_result_reads["ns-a"]
        assert type(worker._reply_graph) is PinnedCurrentReplyWorkerModelResultGraphVerifier
        assert worker._reply_graph._path == model_graph._path
        assert worker._reply_graph._issuer is issuer
        assert worker._graph._issuer is issuer

        with pytest.raises(AuthorityUnavailable, match="worker result reader installation"):
            compose_local_owner_authority(**{
                **kwargs,
                "worker_result_readers_v2": {"ns-a": ("c" * 64, "profile")},
            })
    finally:
        core.close()
        deletion.close()
        guard.close()
        execution.close()
