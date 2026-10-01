"""Real Authority state and independent journal checks for target import proof."""

from dataclasses import replace

import pytest

from rewrite.tests.alpha1.authority import test_v2_migration_local_state as fixture
from sylanne3.runtime.graph_migration_snapshot_v1 import FORMAT
from sylanne3.runtime.graph_migration_transfer_verifier_v2 import (
    InstalledGraphMigrationTransferVerifierV2,
)


def test_installed_verifier_rereads_authority_and_rejects_spoofs(tmp_path, monkeypatch):
    original_receipt = fixture._source_receipt
    monkeypatch.setattr(
        fixture, "_source_receipt",
        lambda root, status: replace(original_receipt(root, status),
                                     snapshot_format=FORMAT))
    (tmp_path / "pairing.txt").write_text(
        "install-source>install-target:transfer-a", encoding="utf-8")
    (tmp_path / "source.snapshot").write_bytes(b"sealed source graph")
    bundle = fixture._open(tmp_path, create=True)
    try:
        service, migration, _, _, deletion, _, _ = bundle
        _, begun = migration.begin_transfer(
            credential="admin", subject="subject-a",
            plan=fixture._plan(service), request_id="begin-a")
        with pytest.raises(PermissionError):
            InstalledGraphMigrationTransferVerifierV2(
                authority=migration, credential="admin", subject="subject-a",
                target_installation_id="install-target",
                target_requirements=fixture._requirements(
                    begun.current_anchor, incarnation="target-incarnation")
            ).prepare(begun.source_permit)

        _, revoked = migration.revoke_source(
            credential="admin", subject="subject-a",
            permit=begun.source_permit,
            snapshot=fixture._source_receipt(tmp_path, begun),
            request_id="revoke-a")
        _, prepared = migration.prepare_target(
            credential="admin", subject="subject-a",
            transfer_id=fixture.TRANSFER, request_id="prepare-a")
        target = fixture._requirements(
            prepared.current_anchor, incarnation="target-incarnation")
        verifier = InstalledGraphMigrationTransferVerifierV2(
            authority=migration, credential="admin", subject="subject-a",
            target_installation_id="install-target", target_requirements=target)
        handle = verifier.prepare(prepared.target_permit)
        with monkeypatch.context() as patch:
            patch.setattr(migration, "recover_transfer",
                          lambda **_kwargs: (_ for _ in ()).throw(
                              AssertionError("Authority I/O inside graph transaction")))
            proof = verifier.verify_local(handle)
        assert proof.transfer_id == fixture.TRANSFER
        assert proof.source_snapshot_digest == revoked.source_snapshot.snapshot_digest
        assert proof.source.graph_revision == revoked.source_snapshot.graph_revision
        assert proof.target == target
        assert proof.authority_phase == "target_recovering"

        with pytest.raises(PermissionError):
            verifier.verify_local({"verified": True, "permit": prepared.target_permit})
        with pytest.raises(PermissionError):
            verifier.verify_local(replace(prepared.target_permit,
                                          token="a" * 32))
        with pytest.raises(PermissionError):
            verifier.verify_local(prepared.target_permit)
        with pytest.raises(PermissionError):
            InstalledGraphMigrationTransferVerifierV2(
                authority=migration, credential="admin", subject="subject-a",
                target_installation_id="install-target",
                target_requirements=replace(target, activation_generation=4)
            ).prepare(prepared.target_permit)

        deletion.append_intent(
            namespace="ns-a", operation_id="later-delete",
            closure_roots=("source-root",), epoch=1, policy_ref="policy-a")
        with pytest.raises(PermissionError, match="journal state"):
            verifier.prepare(prepared.target_permit)
        with pytest.raises(PermissionError, match="unprepared"):
            verifier.verify_local(handle)
        verifier.discard(handle)
        with pytest.raises(PermissionError, match="unprepared"):
            verifier.verify_local(handle)

    finally:
        fixture._close(bundle)
