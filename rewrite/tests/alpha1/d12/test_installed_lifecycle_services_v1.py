"""D12 product admission on actual signed Owner, Graph, Core and job stores.

The clock is a controlled fixture. No model, provider, platform or deployed
server is called; these tests do not claim remote pairing or Linux installation.
"""
from dataclasses import replace
import json
import time
from uuid import uuid4

import pytest

from rewrite.tests.alpha1.integration.test_owner_signed_chain import _real_owner_chain
from rewrite.tests.alpha1.authority.test_local_owner_round_trip import PEER, ROLE
from sylanne3.graph_types import owner_grant_key
from sylanne3.host.v2_fence_port import VerifiedIngressClockV2
from sylanne3.authority_service.v2_clock import IngressClockSampleV2
from sylanne3.runtime.d11_types import (graph_type_specs, runtime_job_key,
    D11RuntimeProvider, D11_PROPOSAL_SCHEMA, D11_PROPOSAL_SCHEMA_HASH)
from sylanne3.runtime.d12_installed_services_v1 import install_d12_services_v1
from sylanne3.runtime.lifecycle_operations_v1 import D12PrerequisiteUnavailable, digest
from sylanne3.runtime.jobs import PersistentJob, create_job, get_job


def _current_owner(chain):
    chain.coordinator._GraphCoordinator__owner_principal_resolver = chain.current_principal
    if "d11" not in chain.coordinator._GraphCoordinator__providers:
        chain.coordinator.register_provider(chain.bootstrap, "d11", D11RuntimeProvider(),
            D11_PROPOSAL_SCHEMA, D11_PROPOSAL_SCHEMA_HASH)
    request = replace(chain.issue_request, audience="owner")
    challenge = chain.sessions.begin_login(transport_credential=PEER, request=request)
    token = chain.sessions.accept_login(transport_credential=PEER, challenge=challenge,
        signature=chain.key.sign(challenge.signed_bytes()))
    return chain.coordinator.grant_current_owner(chain.bootstrap, actor="owner-actor",
        namespace=ROLE, domains=("d11",), purpose="audit", audience="owner",
        activation_generation=1, owner_session_token=token, owner_session_request=request)


def _clock(chain):
    mono = time.monotonic()
    return VerifiedIngressClockV2(IngressClockSampleV2(chain.authority_id, "installation",
        "fixture-clock", time.time(), mono, "fixture-epoch", 0.01), mono, mono, time.time()+0.01)


def test_signed_owner_cancel_updates_runtime_graph_and_replays_once(tmp_path):
    chain = _real_owner_chain(tmp_path, extra_purpose="audit", extra_capability="workbench.control",
                              extra_specs=graph_type_specs())
    graph = chain.resources[0]
    chain.port.read_ingress_clock = lambda _: _clock(chain)
    try:
        port = install_d12_services_v1(chain.coordinator, bootstrap=chain.bootstrap)
        job = PersistentJob("job-d12", "job-create", "activity-d12", None,
            *ROLE.as_tuple, "snapshot-d12", "queued", "d12-test-work", {}, None,
            "2099-01-01T00:00:00Z", "budget-d12", "resource-d12", {}, None, None, 0, 0, {}, None)
        with graph._lock:
            graph._db.execute("BEGIN IMMEDIATE")
            create_job(graph._db, job, "job-create", "a" * 64)
            graph._db.execute("COMMIT")
        authority, lease, _ = _current_owner(chain)
        operation = str(uuid4())
        intent = {"object_ref": "job:job-d12", "control": "cancel_job", "config_diff": {}, "test_intent": None}
        original = port.commit_current_control_v1(authority, lease, operation_id=operation,
            request_digest=digest(intent), input_data=intent)
        assert original.state == "completed" and original.result.cancellation_confirmed
        assert port.read_current_backend_operation_original_v1(authority, lease,
            original_ref=original.original_ref) == original
        assert port.commit_current_control_v1(authority, lease, operation_id=operation,
            request_digest=digest(intent), input_data=intent) == original
        current = get_job(graph._db, job.job_id)
        assert current.cancel_epoch == 1 and current.phase == "cancelled"
        projection = json.loads(graph._db.execute("SELECT value FROM graph_atoms WHERE token=?",
            (runtime_job_key(*ROLE.as_tuple, job.activity_id, job.job_id).token,)).fetchone()[0])
        assert projection["cancel_epoch"] == 1 and projection["phase"] == "cancelled"
        assert not graph._db.in_transaction
        chain.sessions.logout(transport_credential=PEER,
            token=chain.coordinator._GraphCoordinator__owner_session_proofs[lease][0],
            request=chain.coordinator._GraphCoordinator__owner_session_proofs[lease][1])
        with pytest.raises(Exception):
            port.read_current_backend_operation_original_v1(authority, lease, original_ref=original.original_ref)
    finally:
        for resource in chain.resources:
            resource.close()


def test_unpaired_transfer_holds_before_creating_an_attempt(tmp_path):
    chain = _real_owner_chain(tmp_path, extra_purpose="audit", extra_capability="workbench.transfer",
                              extra_specs=graph_type_specs())
    try:
        port = install_d12_services_v1(chain.coordinator, bootstrap=chain.bootstrap)
        authority, lease, _ = _current_owner(chain)
        operation = str(uuid4())
        with pytest.raises(D12PrerequisiteUnavailable, match="installed_transfer_pairing_unavailable"):
            port.prepare_current_transfer_v1(authority, lease, operation_id=operation,
                request_digest=digest("unpaired"), input_data={"mode": "relocate", "target": "/tmp/browser-target",
                    "manifest_ref": "/tmp/browser-manifest", "scope_selection": ["namespace:bot/persona"]})
        db = chain.resources[0]._db
        assert db.execute("SELECT 1 FROM graph_owner_domain_attempts_v3 WHERE operation_id=?", (operation,)).fetchone() is None
        assert db.execute("SELECT 1 FROM graph_d12_backend_operations_v1 WHERE operation_id=?", (operation,)).fetchone() is None
    finally:
        for resource in chain.resources:
            resource.close()


def test_paired_relocation_freezes_source_and_recovers_exact_status(tmp_path):
    from datetime import datetime, timedelta, timezone
    from pathlib import Path
    from rewrite.tests.alpha1.authority.test_local_owner_round_trip import ADMIN, AUTH_NS, SUBJECT, WORKER
    from sylanne3.authority_service.mtls_server import AdministratorInstallationV2, MtlsPeerCredential
    from sylanne3.authority_service.installed_migration_pairing import (
        AdministratorMigrationPairingV1, InstalledMigrationPairingRegistry)
    from sylanne3.authority_service.installed_migration_graph_proofs import InstalledSourceGraphProofV1
    from sylanne3.authority_service.v2_migration_service import AuthorityV2MigrationService
    from sylanne3.authority_service.v2_migration_store import AuthorityV2MigrationStore
    from sylanne3.authority_service.d12_target_registry_v1 import D12TargetLeaseOriginalV1, InstalledD12TargetRegistryV1
    from sylanne3.authority_service.d12_operation_status_v1 import InstalledD12OperationStatusServiceV1
    from sylanne3.authority_service.d12_operation_status_rpc_v1 import (
        install_d12_operation_status_service_v1, dispatch_d12_operation_status_v1)
    from sylanne3.authority_service.v2_contract import to_wire as fence_wire
    from sylanne3.authority_service.v2_owner_session import to_wire as session_wire
    from sylanne3.graph_store import GraphStore
    from sylanne3.host.d12_operation_status_port_v1 import InstalledD12OperationStatusPortV1
    from sylanne3.host.d12_local_transfer_factory_v1 import (install_local_d12_transfer_port_v1,
        install_d12_isolated_target_schema_v1)
    from sylanne3.runtime.d12_installed_transfer_registry_v1 import InstalledD12TransferManifestV1
    from sylanne3.runtime.graph_migration_snapshot_v1 import _install_import_receipt_schema, _schema_digest, _catalogue_digest
    from sylanne3.runtime.lifecycle_operations_v1 import decode_original

    chain = _real_owner_chain(tmp_path, extra_purpose="audit", extra_capability="workbench.transfer",
                              extra_specs=graph_type_specs())
    graph, core = chain.resources[:2]
    target_peer = MtlsPeerCredential("b" * 64)
    before_auth = core._authorize_callback
    core._authorize_callback = lambda credential, action, namespace, holder: (
        namespace == AUTH_NS and (
            credential == ADMIN and action in {"migration_pair_install", "migration_pair_register", "d12_target_install", "d12_target_register", "d12_operation_install"}
            or credential == PEER and action in {"migration_begin", "migration_revoke", "migration_recover", "d12_operation_status"}
            or credential == target_peer and action in {"migration_prepare_target", "migration_activate", "migration_recover"})) or before_auth(credential, action, namespace, holder)
    chain.port.read_ingress_clock = lambda _: _clock(chain)
    factory = None
    target_live_graph = None
    try:
        with graph._lock:
            _install_import_receipt_schema(graph._db)
        target_path = tmp_path / "target-business.db"
        install_d12_isolated_target_schema_v1(graph_db=target_path, registry=graph._registry,
            schema_fence_port=chain.port, holder="target-holder")
        installations = {
            ("a" * 64, "installed"): AdministratorInstallationV2("installation", "administrator", "policy", "capabilities-v2", "c" * 64),
            ("b" * 64, "target-profile"): AdministratorInstallationV2("target-installation", "target-holder", "policy", "capabilities-v2", "d" * 64)}
        bindings = {("a" * 64, "installed", ROLE): AUTH_NS, ("b" * 64, "target-profile", ROLE): AUTH_NS}
        pairing = AdministratorMigrationPairingV1(AUTH_NS, ROLE, "a" * 64, "installed",
            "administrator", "installation", "b" * 64, "target-profile", "target-holder", "target-installation")
        pairs = InstalledMigrationPairingRegistry(core, {AUTH_NS: pairing}, installations, bindings)
        pairs.install_schema(ADMIN)
        pairs.register(ADMIN, AUTH_NS)
        now = lambda: datetime.now(timezone.utc)
        lease_original = D12TargetLeaseOriginalV1("target-lease", "target-local", AUTH_NS, ROLE,
            "target-installation", "target-holder", "target-incarnation", str(target_path),
            _schema_digest(graph._db), _catalogue_digest(graph._db),
            (now() + timedelta(hours=1)).isoformat(), "relocation-policy", digest("policy"))
        targets = InstalledD12TargetRegistryV1(pairing_registry=pairs, target_leases=(lease_original,), utc_clock=now)
        targets.install_schema(ADMIN)
        targets.register(ADMIN, "target-lease")
        migration = AuthorityV2MigrationService(fences=chain.service,
            store=AuthorityV2MigrationStore(core._db, lock=core._lock, create=True),
            pairing_verifier=pairs.verify_pairing,
            source_snapshot_verifier=InstalledSourceGraphProofV1(graph_db=tmp_path / "business.db",
                namespace=AUTH_NS, namespace_id=ROLE, installation_id="installation"),
            target_recovery_verifier=None, owner_tickets=chain.server._v2_owner_tickets)
        manifest = InstalledD12TransferManifestV1("manifest-relocate", ROLE, AUTH_NS,
            "installation", "administrator", "target-local", ("namespace:bot/persona",),
            _schema_digest(graph._db), _catalogue_digest(graph._db), "relocation-policy", digest("policy"))
        transfer = install_local_d12_transfer_port_v1(source_store=graph,
            source_graph_db=tmp_path / "business.db",
            source_recovery_capability=chain.coordinator._GraphCoordinator__graph_capability,
            migration=migration, manifests=(manifest,), target_registry=targets,
            source_credential=PEER, source_subject=SUBJECT, target_credential=target_peer,
            target_subject="mtls:sha256:" + "b" * 64)
        factory = transfer.target_factory
        status_service = InstalledD12OperationStatusServiceV1(fences=chain.service,
            owner_tickets=chain.server._v2_owner_tickets, source_graph_db=tmp_path / "business.db",
            namespace_id=ROLE, installation_id="installation", migration=migration)
        status_service.install_schema(ADMIN)
        install_d12_operation_status_service_v1(chain.server, status_service)
        class LocalStatusTransport(InstalledD12OperationStatusPortV1):
            def _call(self, *, method, namespace, actor, token, request, original_ref, permit=None, refresh=False):
                assert namespace == ROLE
                command = {"namespace": AUTH_NS, "owner_actor_id": actor, "owner_session_token": token,
                    "owner_session_request": session_wire(request), "original_ref": original_ref}
                command.update({"permit": fence_wire(permit)} if permit is not None else {"refresh": refresh})
                result = dispatch_d12_operation_status_v1(chain.server, method, PEER, "installed", "c" * 64, command)
                return None if result["original"] is None else decode_original(result["original"])
        status = LocalStatusTransport(coordinator=chain.coordinator, bootstrap=chain.bootstrap, authority_port=chain.port)
        port = install_d12_services_v1(chain.coordinator, bootstrap=chain.bootstrap,
            transfer_port=transfer, operation_status_port=status)
        authority, lease, _ = _current_owner(chain)
        intent = {"mode": "relocate", "target": "target-local", "manifest_ref": "manifest-relocate",
                  "scope_selection": ["namespace:bot/persona"]}
        prepared = port.prepare_current_transfer_v1(authority, lease, operation_id=str(uuid4()),
            request_digest=digest(intent), input_data=intent)
        _, data = port.lifecycle.store.plan(ROLE, prepared.plan_ref)
        execute = {"plan_ref": prepared.plan_ref, "target_lease_ref": "target-lease", "current_epochs": {
            "schema": "d12.transfer_expected_epochs.v1", "plan_digest": prepared.plan_digest,
            "graph_revision": data["graph_revision"], "access_epoch": data["access_epoch"],
            "delete_epoch": data["delete_epoch"], "activation_generation": 1}}
        operation_id = str(uuid4())
        real_activate = migration.activate_target
        activation_calls = []
        def lose_activation_ack(**kwargs):
            activation_calls.append(kwargs["request_id"])
            real_activate(**kwargs)
            raise TimeoutError("controlled transport lost the committed activation ACK")
        migration.activate_target = lose_activation_ack
        result = port.execute_current_transfer_v1(authority, lease, operation_id=operation_id,
            request_digest=digest(execute), input_data=execute)
        assert activation_calls == [operation_id + ":activate"]
        assert result.state == "completed" and result.result.target_activated and result.result.source_revoked
        assert result.original_ref.startswith("d12authority:")
        recovered = migration.recover_transfer(credential=PEER, subject=SUBJECT, transfer_id=result.result.transfer_id)
        assert [receipt.phase for receipt in recovered.history.receipts] == ["begun", "revoked", "target_prepared", "activated"]
        assert migration._source_verifier(recovered.history.source_snapshot, recovered.history.plan,
                                         recovered.history.source_permit)
        assert port.read_current_backend_operation_original_v1(authority, lease, original_ref=result.original_ref) == result
        assert port.execute_current_transfer_v1(authority, lease, operation_id=operation_id,
            request_digest=digest(execute), input_data=execute) == result
        # Status lives in Core: replay and query never change the frozen source.
        assert migration._source_verifier(recovered.history.source_snapshot, recovered.history.plan,
                                         recovered.history.source_permit)
        token, request = chain.coordinator._GraphCoordinator__owner_session_proofs[lease]
        # Logout remains independently revocable even after source content is frozen.
        chain.sessions.logout(transport_credential=PEER, token=token, request=request)
        with pytest.raises(Exception):
            port.read_current_backend_operation_original_v1(authority, lease, original_ref=result.original_ref)

        # Pair a distinct target key and fresh signed session through the actual
        # registration services. Nothing copies the source private key/session.
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from sylanne3.authority_service.v2_owner_proof import OwnerCredentialRegistrationV1
        from sylanne3.authority_service.v2_owner_contract import OwnerActorBindingV1
        from sylanne3.authority_service.d12_target_owner_admission_v1 import InstalledD12TargetOwnerAdmissionServiceV1
        from sylanne3.authority_service.d12_target_owner_rpc_v1 import install_d12_target_owner_service_v1
        from sylanne3.graph_coordinator import GraphCoordinator
        from sylanne3.graph_store import ProductionGraphStore
        from rewrite.tests.alpha1.authority.test_local_owner_round_trip import LocalFencePort
        from sylanne3.runtime_contracts import InstallationGrantV2
        target_subject = "mtls:sha256:" + "b" * 64
        pre_target_auth = core._authorize_callback
        core._authorize_callback = lambda credential, action, namespace, holder: (
            namespace == AUTH_NS and (
                credential == target_peer and action in {"read", "write", "current", "owner_pair", "owner_session", "owner_guard_read", "d12_operation_status"}
                or credential == ADMIN and action == "d12_target_owner_install")) or pre_target_auth(credential, action, namespace, holder)
        chain.source.revoke_credential(administrator_credential=ADMIN,
            authority_namespace=AUTH_NS, principal=chain.principal)
        target_key = Ed25519PrivateKey.generate()
        target_registration = OwnerCredentialRegistrationV1(chain.authority_id, AUTH_NS,
            "target-installation", chain.principal, "target-owner-key", 1,
            target_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw), "target-enroll")
        chain.source.pair_credential(administrator_credential=ADMIN, registration=target_registration,
            client_certificate_sha256="b" * 64, valid_until_utc=(now()+timedelta(hours=1)).replace(microsecond=0))
        chain.source.pair_actor(administrator_credential=ADMIN, binding=OwnerActorBindingV1(
            chain.authority_id, "target-installation", ROLE, "target-owner-actor", chain.principal, 1))
        chain.server._v2_owner_proofs.register_credential(transport_credential=target_peer, registration=target_registration)
        target_request = replace(request, installation_id="target-installation", credential_id="target-owner-key")
        challenge = chain.sessions.begin_login(transport_credential=target_peer, request=target_request)
        target_token = chain.sessions.accept_login(transport_credential=target_peer, challenge=challenge,
            signature=target_key.sign(challenge.signed_bytes()))
        target_owner = InstalledD12TargetOwnerAdmissionServiceV1(migration=migration,
            owner_tickets=chain.server._v2_owner_tickets, target_graph_db=target_path,
            namespace_id=ROLE, target_installation_id="target-installation", target_holder="target-holder",
            policy_ref="target-owner-policy", policy_digest=digest("target-owner-policy"),
            operation_status_service=status_service)
        target_owner.install_schema(ADMIN)
        chain.server._installations_v2.update(installations)
        chain.server._namespace_bindings_v2.update(bindings)
        install_d12_target_owner_service_v1(chain.server, target_owner)
        factory.close()
        factory = None
        target_live_graph = ProductionGraphStore(target_path, graph._registry)
        class TargetPort(LocalFencePort):
            def current_anchor(self, **kwargs):
                self._outside_graph()
                return self.service.current_anchor(credential=target_peer, subject=target_subject)
            def begin_fence(self, *, namespace, authority_namespace, holder, generation,
                            operation, operation_id, expected_anchor, **kwargs):
                self._outside_graph()
                assert generation == 3 and holder == "target-holder"
                return self.service.begin_fence(credential=target_peer, subject=target_subject,
                    holder=holder, operation=operation, operation_id=operation_id, expected_anchor=expected_anchor)
            def validate_fence(self, scope):
                self._outside_graph()
                return self.service.validate_fence(credential=target_peer, subject=target_subject, permit=scope.permit)
            def finish_fence(self, scope, *, request_id, request_digest):
                self._outside_graph()
                return self.service.finish_fence(credential=target_peer, subject=target_subject, permit=scope.permit,
                    request_id=request_id, request_digest=request_digest)
            def get_current_owner_guard_for_fence(self, **kwargs):
                raise AssertionError("target Owner cannot fall back to source guard admission")
            def get_current_owner_authority_for_fence_v1(self, *, namespace, authority_namespace, permit,
                    owner_actor_id, owner_session_token, owner_session_request):
                self._outside_graph()
                return target_owner.get_current_owner_authority_for_fence_v1(credential=target_peer,
                    subject=target_subject, permit=permit, actor=owner_actor_id,
                    session_token=owner_session_token, session_request=owner_session_request)
        target_port = TargetPort(target_live_graph, chain.service, chain.server._v2_owner_tickets, chain.authority_id)
        target_port.installation_grant = InstallationGrantV2(chain.authority_id, target_subject,
            "target-holder", "target-installation", "d" * 64, "publisher-trust", "2", "b" * 64)
        def target_principal(actor, namespace):
            paired = chain.source.current_actor_binding(authority_namespace=AUTH_NS,
                installation_id="target-installation", actor_id=actor)
            return paired.principal if paired is not None and namespace == ROLE else None
        target_bootstrap = object()
        target_coordinator = GraphCoordinator(target_live_graph, target_bootstrap,
            holder="target-holder", content_fence_v2=target_port, owner_principal_resolver=target_principal)
        target_coordinator.register_provider(target_bootstrap, "d11", D11RuntimeProvider(),
            D11_PROPOSAL_SCHEMA, D11_PROPOSAL_SCHEMA_HASH)
        target_authority, target_owner_lease, binding = target_coordinator.grant_current_owner(target_bootstrap,
            actor="target-owner-actor", namespace=ROLE, domains=("d11",), purpose="audit", audience="owner",
            activation_generation=3, owner_session_token=target_token, owner_session_request=target_request)
        assert binding.target_admission.target_installation_id == "target-installation"
        assert binding.target_admission.source_grant_digest == prepared.owner_grant_digest
        assert binding.graph_incarnation == "target-incarnation"
        records = target_coordinator.query(target_authority, target_owner_lease,
            type_names=(owner_grant_key(*ROLE.as_tuple).type_name,), owner_kind="persona")
        assert len(records.snapshot.atoms) == 1
        source_grant = graph._db.execute("SELECT value FROM graph_atoms WHERE token=?", (owner_grant_key(*ROLE.as_tuple).token,)).fetchone()
        target_grant = target_live_graph._db.execute("SELECT value FROM graph_atoms WHERE token=?", (owner_grant_key(*ROLE.as_tuple).token,)).fetchone()
        assert target_grant == source_grant  # Immutable source grant is not reauthored.
        target_status = status_service.read_current_operation_original_v1(credential=target_peer,
            actor="target-owner-actor", session_token=target_token, session_request=target_request,
            original_ref=result.original_ref)
        assert target_status == result
        # C09's D12 Core transformation is checked with these actual durable
        # rows. This is row-retirement coverage, not a full C09 maintenance run.
        from sylanne3.authority_service.d12_c09_core_rows_v1 import COLUMNS, validate_d12_core_row_v1
        from sylanne3.authority_service.c09_authority_storage_rebase import _CoreTransform
        anchor = chain.service.current_anchor(credential=target_peer, subject=target_subject)
        transform = _CoreTransform(namespace=AUTH_NS, operation_id="d12-row-retirement-check",
            authority_id=chain.authority_id, pin_digest=digest("row-codec-fixture"),
            new_journal_id="row-codec-next-journal", old_journal_id=anchor.execution_journal_id,
            new_anchor_nonce="c" * 64, continuation_permit_token="t" * 48,
            old_seq=anchor.execution_seq, old_digest=anchor.execution_digest,
            facts=None, execution_rows=())
        for table in ("authority_d12_operation_originals_v1", "authority_d12_target_leases_v1", "authority_d12_target_owner_admissions_v1"):
            columns=COLUMNS[table]
            rows = tuple(core._db.execute("SELECT * FROM " + table))
            assert rows
            for row in rows:
                assert validate_d12_core_row_v1(table, columns, row)[0] == AUTH_NS
            survivors, retired = transform(table, columns, rows)
            assert survivors == () and len(retired) == len(rows)
            assert all(item.new_commitment is None for item in retired)
        assert transform.consumed
        chain.sessions.logout(transport_credential=target_peer, token=target_token, request=target_request)
        def background_read(operation):
            anchor = chain.service.current_anchor(credential=target_peer, subject=target_subject)
            permit = chain.service.begin_fence(credential=target_peer, subject=target_subject,
                holder="target-holder", operation="read", operation_id=operation, expected_anchor=anchor)
            try:
                return target_owner.get_current_background_owner_authority_for_fence_v1(
                    credential=target_peer, subject=target_subject, permit=permit)[0]
            finally:
                chain.service.finish_fence(credential=target_peer, subject=target_subject,
                    permit=permit, request_id="finish-"+operation, request_digest=digest(operation))
        assert background_read("background-after-browser-logout").target_admission == binding.target_admission
        with pytest.raises(Exception):
            target_coordinator.query(target_authority, target_owner_lease,
                type_names=(owner_grant_key(*ROLE.as_tuple).type_name,), owner_kind="persona")
        chain.source.revoke_credential(administrator_credential=ADMIN,
            authority_namespace=AUTH_NS, principal=chain.principal)
        with pytest.raises(Exception):
            background_read("background-after-key-revoke")
        with pytest.raises(Exception):
            status_service.read_current_operation_original_v1(credential=PEER, actor="owner-actor",
                session_token=token, session_request=request, original_ref=result.original_ref)
    finally:
        if target_live_graph is not None:
            target_live_graph.close()
        if factory is not None:
            factory.close()
        for resource in chain.resources:
            resource.close()
