"""Migration RPC contract tests against the real local Authority state machine."""

import pytest

from sylanne3.authority_service.contract import AuthorityUnavailable
from sylanne3.authority_service.v2_migration_contract import (
    MigrationPlanV2, MigrationStatusV2,
)
from sylanne3.authority_service.v2_migration_rpc import (
    MigrationManagementBindingV2, MigrationRpcHandlerV2, from_wire,
    response_from_wire, to_wire,
)
from sylanne3.authority_service.mtls_server import MtlsPeerCredential
from sylanne3.runtime_contracts import NamespaceId
from test_v2_migration_local_state import (
    _close, _open, _source_receipt, _target_receipt,
)


SOURCE = MtlsPeerCredential("a" * 64)
TARGET = MtlsPeerCredential("b" * 64)
ALIEN = MtlsPeerCredential("c" * 64)
CHANNEL = "d" * 64
SCHEMA = "sylanne.authority.migration.rpc.v2"


def _setup(tmp_path, *, pairing=True):
    (tmp_path / "pairing.txt").write_text(
        "install-source>install-target:transfer-a", encoding="utf-8")
    bundle = _open(tmp_path, create=True)
    service, migration, *_ = bundle
    if not pairing:
        migration._pairing_verifier = None
    else:
        migration._pairing_verifier = lambda *_: True
    before = service.current_anchor(
        credential="admin", subject="subject-a")
    bundle[3]._authorize_callback = lambda credential, *_: credential in (SOURCE, TARGET, "admin")
    plan = MigrationPlanV2(
        "transfer-a", "ns-a", NamespaceId("bot", "persona"),
        "holder-source", "install-source", "holder-target",
        "install-target", before)

    def resolve(peer, profile, channel, namespace):
        if namespace != "ns-a" or profile != "profile-a" or channel != CHANNEL:
            return None
        role = "source" if peer == SOURCE else "target" if peer == TARGET else None
        if role is None:
            return None
        return MigrationManagementBindingV2(
            peer.certificate_sha256, profile, channel, namespace,
            role, "holder-" + role, "install-" + role,
            "holder-source", "install-source", "holder-target",
            "install-target")

    handler = MigrationRpcHandlerV2(
        {"ns-a": migration}, resolve_management_binding=resolve)
    return bundle, handler, plan


def _call(handler, peer, operation, **body):
    return handler.handle(
        credential=peer, profile_id="profile-a",
        channel_binding_sha256=CHANNEL,
        command={"schema": SCHEMA, "operation": operation,
                 "namespace": "ns-a", **body})


def test_strict_wire_roundtrip_and_rejects_client_proof_flags(tmp_path):
    bundle, handler, plan = _setup(tmp_path)
    try:
        assert from_wire(to_wire(plan), MigrationPlanV2) == plan
        invalid = to_wire(plan)
        invalid["before_anchor"]["activation_generation"] = True
        with pytest.raises(AuthorityUnavailable):
            from_wire(invalid, MigrationPlanV2)
        with pytest.raises(AuthorityUnavailable):
            _call(handler, SOURCE, "begin_transfer", request_id="begin-a",
                  plan=to_wire(plan), verified=True)
        with pytest.raises(AuthorityUnavailable):
            _call(handler, SOURCE, "begin_transfer", request_id="begin-a",
                  plan=to_wire(plan), snapshot_path="claimed.snapshot")
    finally:
        _close(bundle)


def test_real_begin_replay_and_management_identity_binding(tmp_path):
    bundle, handler, plan = _setup(tmp_path)
    try:
        command = {"request_id": "begin-a", "plan": to_wire(plan)}
        with pytest.raises(AuthorityUnavailable):
            _call(handler, TARGET, "begin_transfer", **command)
        with pytest.raises(AuthorityUnavailable):
            _call(handler, ALIEN, "begin_transfer", **command)
        first = _call(handler, SOURCE, "begin_transfer", **command)
        assert first["schema"] == SCHEMA
        assert first["result"]["status"]["phase"] == "begun"
        assert response_from_wire(first, "begin_transfer")[0].request_id == "begin-a"
        with pytest.raises(AuthorityUnavailable):
            response_from_wire({**first, "schema": "old"}, "begin_transfer")
        with pytest.raises(AuthorityUnavailable):
            response_from_wire({**first, "verified": True}, "begin_transfer")
        assert _call(handler, SOURCE, "begin_transfer", **command) == first
        with pytest.raises(AuthorityUnavailable):
            _call(handler, SOURCE, "begin_transfer", request_id="begin-a",
                  plan={**to_wire(plan), "target_installation_id": "other"})
        with pytest.raises(AuthorityUnavailable):
            handler.handle(
                credential=SOURCE, profile_id="profile-a",
                channel_binding_sha256="e" * 64,
                command={"schema": SCHEMA, "operation": "recover_transfer",
                         "namespace": "ns-a", "transfer_id": "transfer-a"})
        recovered = _call(handler, SOURCE, "recover_transfer",
                          transfer_id="transfer-a")
        assert recovered["result"]["recovery"]["history"]["receipts"][0]["request_id"] == "begin-a"
    finally:
        _close(bundle)


def test_missing_trusted_pairing_holds_before_state_transition(tmp_path):
    bundle, handler, plan = _setup(tmp_path, pairing=False)
    try:
        with pytest.raises(AuthorityUnavailable, match="pairing"):
            _call(handler, SOURCE, "begin_transfer", request_id="begin-a",
                  plan=to_wire(plan))
        assert bundle[3]._db.execute(
            "SELECT phase FROM authority_namespaces WHERE namespace='ns-a'"
        ).fetchone()[0] == "active"
    finally:
        _close(bundle)


def test_source_and_target_channels_advance_only_with_trusted_graph_verifiers(tmp_path):
    bundle, handler, plan = _setup(tmp_path)
    try:
        (tmp_path / "source.snapshot").write_bytes(b"controlled source closure")
        begun = _call(handler, SOURCE, "begin_transfer", request_id="begin-a",
                      plan=to_wire(plan))
        status = from_wire(begun["result"]["status"], MigrationStatusV2)
        snapshot = _source_receipt(tmp_path, status)
        service = bundle[1]
        original = service._source_verifier
        service._source_verifier = None
        with pytest.raises(AuthorityUnavailable, match="source graph snapshot verifier"):
            _call(handler, SOURCE, "revoke_source", request_id="revoke-a",
                  permit=to_wire(status.source_permit), snapshot=to_wire(snapshot))
        service._source_verifier = original
        with pytest.raises(AuthorityUnavailable):
            _call(handler, TARGET, "revoke_source", request_id="revoke-a",
                  permit=to_wire(status.source_permit), snapshot=to_wire(snapshot))
        revoked = _call(handler, SOURCE, "revoke_source", request_id="revoke-a",
                        permit=to_wire(status.source_permit), snapshot=to_wire(snapshot))
        assert revoked["result"]["status"]["phase"] == "revoked"
        with pytest.raises(AuthorityUnavailable):
            _call(handler, SOURCE, "prepare_target", transfer_id="transfer-a",
                  request_id="prepare-a")
        prepared = _call(handler, TARGET, "prepare_target", transfer_id="transfer-a",
                         request_id="prepare-a")
        assert _call(handler, TARGET, "prepare_target", transfer_id="transfer-a",
                     request_id="prepare-a") == prepared
        status = from_wire(prepared["result"]["status"], MigrationStatusV2)
        (tmp_path / "target-graph-commit.bin").write_bytes(b"controlled target receipt")
        (tmp_path / "unknown-constraints.bin").write_bytes(b"controlled unknowns")
        recovery = _target_receipt(tmp_path, status)
        original = service._target_verifier
        service._target_verifier = None
        with pytest.raises(AuthorityUnavailable, match="target graph recovery verifier"):
            _call(handler, TARGET, "activate_target", request_id="activate-a",
                  permit=to_wire(status.target_permit), recovery=to_wire(recovery))
        service._target_verifier = original
        activated = _call(handler, TARGET, "activate_target", request_id="activate-a",
                          permit=to_wire(status.target_permit), recovery=to_wire(recovery))
        assert activated["result"]["status"]["phase"] == "activated"
        assert _call(handler, TARGET, "activate_target", request_id="activate-a",
                     permit=to_wire(status.target_permit), recovery=to_wire(recovery)) == activated
    finally:
        _close(bundle)
