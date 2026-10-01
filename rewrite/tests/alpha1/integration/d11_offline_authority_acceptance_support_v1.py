"""Actual initial four-store D11 service and current Host admission composition.

The fixture uses the existing real Owner/TLS/CPU/initial C09 stores. Local
installation provisioning is controlled here; no boundary, permit, paid fact,
prepared row, source, claim or terminal is inserted as acceptance evidence.
"""
from dataclasses import replace
import hashlib
import hmac
import os
from pathlib import Path
from dataclasses import dataclass
import sqlite3
import tempfile
from types import SimpleNamespace
import time

from sylanne3.authority_service.c09_graph_application_v1 import InstalledC09GraphApplicationV1
from sylanne3.authority_service.c09_close_apply_v1 import InstalledC09CloseApplyV1
from sylanne3.authority_service.c09_process_identity_v1 import read_process_identity_v1
from sylanne3.authority_service.c09_storage_maintenance_v1 import InstalledC09WriterGateV1
from sylanne3.authority_service.d12_owner_storage_admission_v1 import InstalledD12OwnerStorageAdmissionServiceV1
from sylanne3.authority_service.d11_offline_tick_service_v1 import AuthorityD11OfflineTickServiceV1
from sylanne3.authority_service.v2_deletion_recovery_service import AuthorityV2DeletionPendingRecovery
from sylanne3.authority_service.v2_scoped_erasure_store import AuthorityV2ScopedErasureStore
from sylanne3.host.c09_storage_admission_v1 import InstalledHostStorageAdmissionV1


@dataclass
class FreshOfflineStorageCaseV1:
    storage_control: object
    lease: object
    protected_directory: object

    def close(self):
        self.lease.close()
        self.protected_directory.cleanup()


def install_fresh_offline_storage_case_v1(*, core, protected, execution, graph_store,
        root, server_kwargs, peer, namespace, authority_namespace, registry):
    """Use the installer genesis and actual initial four-file selection.

    All migrations have run before Owner login or business writes. The later
    numeric/root installation shares this selection instead of replacing it.
    """
    from sylanne3.authority_service.c09_storage_control_v1 import C09StorageControlV1, InstalledC09InstanceLeaseV1
    from sylanne3.authority_service.installer_genesis_v1 import (
        record_installer_genesis_original_v1, install_first_graph_provision_composition_v1,
    )
    from sylanne3.authority_service.linux_bootstrap_v1 import build_initial_inventory_v1, bootstrap_current_storage_v1
    protected_directory = tempfile.TemporaryDirectory(prefix="sylanne-offline-current-control-")
    protected_root = Path(protected_directory.name)
    lease = InstalledC09InstanceLeaseV1(protected_root / "instance.lock")
    try:
        key = protected_root / "control.key"
        key.write_bytes(os.urandom(32))
        files = {"core": Path(core.path).resolve(), "deletion": Path(protected.deletion.path).resolve(),
            "execution": Path(execution.path).resolve(), "graph": Path(root / "business.db").resolve()}
        installation_peer = (peer.certificate_sha256, "reply")
        installation = server_kwargs["installations_v2"][installation_peer]
        config = SimpleNamespace(instance_lock=lease.path, authority_db=files["core"], deletion_db=files["deletion"],
            graph_db=files["graph"], execution_journals={authority_namespace: SimpleNamespace(path=files["execution"])},
            installations_v2={installation_peer: installation},
            namespace_bindings_v2={(*installation_peer, namespace): authority_namespace})
        authority_id = core._db.execute("SELECT value FROM authority_meta WHERE key='authority_id'").fetchone()[0]
        control = C09StorageControlV1(control_path=protected_root / "control.db", key_path=key,
            installation_id=installation.installation_id, authority_id=authority_id,
            control_store_id="offline-acceptance-control", key_id="offline-acceptance-key", lease=lease,
            resource_roots=(Path(root).resolve(),))
        managed = root / "offline-managed-artifacts"
        managed.mkdir()
        directories = {name: managed / name for name in ("controlled_backup", "export", "rebuild_temp", "cache")}
        for directory in directories.values():
            directory.mkdir()
        with protected.deletion._lock, execution._lock, core._lock, graph_store._lock:
            record_installer_genesis_original_v1(core=core, config=config, registry=registry,
                instance_lease=lease, files=files)
            with protected.deletion.freeze_writes():
                deletion_head = protected.deletion.verified_head()
            for path in files.values():
                with sqlite3.connect(path) as db:
                    assert db.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()[0] == 0
            inventory = build_initial_inventory_v1(authority_id=authority_id, installation_id=installation.installation_id,
                namespace=authority_namespace, files=files, directories=directories)
            bootstrap_current_storage_v1(control=control, files=files, inventory=inventory,
                identities={"core": authority_id, "deletion": deletion_head.journal_id,
                    "execution": execution.journal_id, "graph": "unprovisioned"})
        core.install_current_c09_storage_reader_v1(reader=control)
        install_first_graph_provision_composition_v1(protected, config, registry)
        return FreshOfflineStorageCaseV1(control, lease, protected_directory)
    except BaseException:
        lease.close()
        protected_directory.cleanup()
        raise


def install_actual_offline_authority_case_v1(case):
    graph, store, core, server = case["graph"], case["store"], case["core"], case["server"]
    authority_namespace = case["authority_namespace"]
    selected = graph._actual_d04_authority_acceptance_v3
    control = selected.storage_control
    fence_service = server._v2_fences[authority_namespace]
    bridge = server._v2_execution[authority_namespace]
    assert bridge.core is core and fence_service.core is core
    context = control.read_verified_current_storage_v1()
    context.require_current("business")
    assert context.stage != "RELEASED", "this fixture is actual initial selection, not a C09 rebase"
    graph_path = Path(store._db.execute("PRAGMA database_list").fetchone()[2]).resolve()
    assert graph_path == Path(next(member["resolved_path"] for member in context.manifest["members"] if member["role"] == "graph"))
    scoped = AuthorityV2ScopedErasureStore(core=core, fences=fence_service.fences,
        deletion=bridge.deletion, execution=bridge.journal, namespace=authority_namespace)
    recovery = AuthorityV2DeletionPendingRecovery(core=core, fences=fence_service.fences,
        deletion=bridge.deletion, execution=bridge.journal, namespace=authority_namespace, scoped_store=scoped)
    subject = "mtls:sha256:" + case["peer"].certificate_sha256
    application = InstalledC09GraphApplicationV1(control=control, core=core, scoped=scoped,
        coordinator=graph, bootstrap=case["bootstrap"], namespace=case["namespace"], subject=subject, credential=case["peer"])
    close_apply = InstalledC09CloseApplyV1(control=control, service=fence_service, recovery=recovery,
        graph_application=application, subject=subject, credential=case["peer"])
    control.install_applied_reader_v1(close_apply)
    owner_service = InstalledD12OwnerStorageAdmissionServiceV1(fences=fence_service, owner_tickets=server._v2_owner_tickets,
        graph_db_path=graph_path, namespace_id=case["namespace"], installation_id=case["policy"].installation_id,
        holder=case["policy"].administrator_holder, control=control, close_apply=close_apply)
    bundle = graph._GraphCoordinator__d04_installed_joint_assembly.admin_bundle
    service = AuthorityD11OfflineTickServiceV1(bridge=bridge, owner_tickets=server._v2_owner_tickets,
        namespace=case["namespace"], installation_id=case["policy"].installation_id,
        manifest_digest=case["manifest_digest"], graph_db_path=graph_path, issuer=case["d11_issuer"],
        resource_issuer=case["d02_issuer"], credential=case["peer"],
        signing_key=hmac.new(bundle.d11_signing_key, b"sylanne.authority.d11-offline-signing.v1", hashlib.sha256).digest(),
        trusted_now_utc=time.time, owner_service=owner_service)
    # Keep the real RPC/service gates while exposing the underlying error in
    # this permanent acceptance's log; transport deliberately sanitizes it.
    import functools
    import traceback
    def diagnosed(method):
        @functools.wraps(method)
        def call(*args, **kwargs):
            try:
                return method(*args, **kwargs)
            except Exception:
                traceback.print_exc()
                raise
        return call
    for method in ("execute_d11_offline_tick_v1", "read_d11_offline_tick_original_v1",
            "read_historical_d11_offline_tick_original_v1", "recover_claimed_d11_offline_tick_v1",
            "offline_adoption_bridge_v1", "offline_historical_accounting_v1", "offline_unstarted_cancellation_v1"):
        setattr(service, method, diagnosed(getattr(service, method)))
    if not hasattr(server, "_d11_offline_tick_services_v1"):
        server._d11_offline_tick_services_v1 = {}
    assert authority_namespace not in server._d11_offline_tick_services_v1
    server._d11_offline_tick_services_v1[authority_namespace] = service
    core.install_execution_redaction_d11_offline_service_v1(authority_namespace, service)
    # The supervisor boundary registers this actual live PID/birth against the
    # independently observed selected pointer and files, then gives the Host
    # those exact admitted values. It does not assert lifecycle state.
    process = read_process_identity_v1(os.getpid())
    assert process is not None
    gate = InstalledC09WriterGateV1(control=control)
    gate.register_peer_process_v1(peer=(case["peer"].certificate_sha256, bundle.tls_profile.profile_id), process_id=os.getpid(),
        process_incarnation="offline-acceptance-host:" + process["birth"], pointer_version=context.pointer_version,
        storage_generation=context.storage_generation)
    admission = InstalledHostStorageAdmissionV1(case["policy"].installation_id, case["grant"].authority_id,
        context.pointer_version, context.storage_generation, context.manifest_digest, graph_path, process)
    admission.require_current_process_v1()
    return service, owner_service, admission
