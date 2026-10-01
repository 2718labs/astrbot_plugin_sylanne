"""Controlled-provider four-store C09 acceptance, with real cold OS processes.

No privileged Linux installer/adapter or external production provider is used.
The test provider actually owns its separate cache, purges its bytes and signs
an independent reread. Owner and deletion receipts use the real production
stores. No cleanup evidence or N/A result is planted into Authority state.
"""
from __future__ import annotations

from contextlib import closing
from dataclasses import asdict, replace
from datetime import datetime, timezone
import base64
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
from uuid import uuid4

from sylanne3.authority_service.contract import AuthorityUnavailable
from sylanne3.authority_service.c09_storage_control_v1 import C09StorageControlV1, InstalledC09InstanceLeaseV1, SURFACES
from sylanne3.authority_service.c09_storage_maintenance_v1 import InstalledC09WriterGateV1, InstalledC09MaintenanceV1
from sylanne3.authority_service.c09_surface_cleanup_v1 import InstalledC09SurfaceCleanupV1
from sylanne3.authority_service.c09_close_apply_v1 import InstalledC09CloseApplyV1
from sylanne3.authority_service.c09_graph_application_v1 import InstalledC09GraphApplicationV1
from sylanne3.authority_service.c09_installed_factory_v1 import _LocalInstalledFencePortV1
from sylanne3.authority_service.current_erasure_service import CurrentErasureAuthority
from sylanne3.authority_service.current_accepted_erasure_read import CurrentAcceptedErasureReadService
from sylanne3.authority_service.erasure_closure_inventory import AuthorityErasureClosureInventory, SurfaceTargetV1
from sylanne3.authority_service.v2_deletion_migration import AuthorityV2DeletionMigration
from sylanne3.authority_service.v2_deletion_tail_migration import AuthorityV2DeletionTailMigration
from sylanne3.authority_service.v2_scoped_erasure_store import AuthorityV2ScopedErasureStore
from sylanne3.authority_service.v2_deletion_recovery_service import AuthorityV2DeletionPendingRecovery
from sylanne3.authority_service.v2_deletion_graph_read import AuthorityV2DeletionGraphReadService
from sylanne3.authority_service.linux_bootstrap_v1 import initialize_fresh_authority_v1, build_initial_inventory_v1, bootstrap_current_storage_v1
from sylanne3.authority_service.core import AuthorityServiceCore
from sylanne3.authority_service.v2_deletion_guard import AuthorityV2DeletionGuard
from sylanne3.authority_service.v2_execution_journal import AuthorityV2ExecutionJournal
from sylanne3.authority_service.v2_fence_store import AuthorityV2FenceStore
from sylanne3.authority_service.v2_fence_service import AuthorityV2FenceService
from sylanne3.authority_service.installed_core_verifiers import installed_core_verifier_factory
from sylanne3.authority_service.v2_owner_session import AuthorityV2OwnerSessionStore
from sylanne3.authority_service.v2_owner_proof import AuthorityV2OwnerProofStore
from sylanne3.host.owner_identity_sqlite import AuthorityOwnerPairingSource
from sylanne3.host.owner_deployment import OwnerDeploymentVerifier
from sylanne3.domains.d02.body_quote_original import D02BodyQuoteAuthority
from sylanne3.domains.d06 import D06DomainProvider
from sylanne3.graph_coordinator import GraphCoordinator
from sylanne3.graph_store import GraphStore, ProductionGraphStore
from sylanne3.graph_types import TypeRegistry, GraphCandidate, GraphWrite, owner_grant_spec
from sylanne3.contracts import Event, Scope
from sylanne3.memory_types import SourceRecord, source_key, access_key
from sylanne3.runtime.issuers import D02ResourceIssuer
from sylanne3.runtime.c09_installation_inventory_v2 import InstallationFilesystemManifestV2, InstalledResourceV2
from sylanne3.runtime_contracts import canonical_digest, canonical_serialize

from rewrite.tests.alpha1.integration.test_owner_signed_chain import _real_owner_chain
from rewrite.tests.alpha1.authority.test_local_owner_round_trip import ROLE, AUTH_NS, SUBJECT, ADMIN, WORKER, PEER
from rewrite.tests.alpha1.authority.test_local_owner_round_trip import LocalFencePort


PROVIDER = "controlled-local-cache-provider"
CLOCK_SOURCE = "controlled-c09-kernel-clock"
PRIVATE = "C09_ERASED_PRIVATE_SENTINEL_20260930"
SURVIVOR = "C09_SURVIVING_SOURCE_SENTINEL_20260930"


def _registry():
    registry = TypeRegistry(); registry.register(owner_grant_spec())
    for spec in D06DomainProvider.type_specs(): registry.register(spec)
    return registry


def _authorize(credential, action, namespace, holder):
    # Explicit installation policy for this controlled acceptance identity.
    # It changes no proof, table, head, Owner signature or receipt.
    return credential in {ADMIN, WORKER, PEER} and namespace in {None, AUTH_NS, "seed"} and holder in {None, "administrator", "seed-holder"}


def _json_write(path, value):
    path.write_text(canonical_serialize(value), encoding="utf-8")


def _provider_action(root, request):
    """A separate provider process owns these bytes and its private signing key."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    specification = json.loads((root / "provider.json").read_text())
    expected = {"provider_id", "installation_id", "authority_id", "namespace", "operation_id", "manifest_digest", "action"}
    if set(request) != expected or any(request[name] != specification[name] for name in
            ("provider_id", "installation_id", "authority_id", "namespace")) or request["action"] not in {"purge", "read"}:
        raise AssertionError("controlled provider scope differs")
    cache = root / "owned-cache"
    files = tuple(sorted(cache.iterdir()))
    if any(not path.is_file() or path.is_symlink() for path in files):
        raise AssertionError("controlled provider cache inventory is incomplete")
    if request["action"] == "purge":
        for path in files: path.unlink()
        descriptor = os.open(cache, os.O_RDONLY | os.O_DIRECTORY)
        try: os.fsync(descriptor)
        finally: os.close(descriptor)
    survivors = tuple(sorted(path.name for path in cache.iterdir()))
    payload = {"schema": "c09.controlled-provider-cache-reread.v1", "request_digest": canonical_digest(request),
        "provider_id": PROVIDER, "operation_id": request["operation_id"], "manifest_digest": request["manifest_digest"],
        "state": "absent" if not survivors else "present", "survivors": survivors}
    key = Ed25519PrivateKey.from_private_bytes((root / "provider.key").read_bytes())
    return {"payload": payload, "signature": base64.b64encode(key.sign(
        b"c09.controlled-provider-cache-reread.v1\0" + canonical_serialize(payload).encode())).decode()}


class ControlledProviderCacheCleanerV1:
    """Actual provider cleaner contract; not a privileged Linux adapter substitute."""
    def __init__(self, root): self.root = Path(root)

    def _call(self, control, operation_id, action):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        context = control.read_verified_current_storage_v1(); context.require_current("maintenance")
        request = {"provider_id": PROVIDER, "installation_id": control.installation_id, "authority_id": control.authority_id,
            "namespace": AUTH_NS, "operation_id": operation_id, "manifest_digest": context.manifest_digest, "action": action}
        result = subprocess.run([sys.executable, __file__, "provider", str(self.root)], input=canonical_serialize(request),
            text=True, capture_output=True, check=True, timeout=30)
        original = json.loads(result.stdout)
        Ed25519PublicKey.from_public_bytes((self.root / "provider.pub").read_bytes()).verify(
            base64.b64decode(original["signature"], validate=True),
            b"c09.controlled-provider-cache-reread.v1\0" + canonical_serialize(original["payload"]).encode())
        if (original["payload"]["request_digest"] != canonical_digest(request)
                or original["payload"]["state"] != "absent" or original["payload"]["survivors"]):
            raise AuthorityUnavailable("controlled provider retained cache bytes")
        return original

    def clean_installed_surface_v1(self, *, operation_id, storage_reader):
        context = storage_reader.read_verified_current_storage_v1()
        plan = storage_reader.read_build_original_v1(operation_id=operation_id, kind="purge_model_prompt_caches")
        if plan is None:
            plan = storage_reader.record_cleanup_plan_v1(operation_id=operation_id, surface="model_prompt_caches",
                details={"provider_id": PROVIDER, "public_key_sha256": hashlib.sha256((self.root / "provider.pub").read_bytes()).hexdigest()})
        purged = self._call(storage_reader, operation_id, "purge")
        reread = self._call(storage_reader, operation_id, "read")
        return storage_reader.sign_original_v1("sylanne3.c09.surface-evidence.v1", {
            "schema": "sylanne3.c09.surface-evidence.v1", "installation_id": storage_reader.installation_id,
            "issuer_id": storage_reader.authority_id, "operation_id": operation_id, "surface": "model_prompt_caches",
            "manifest_digest": context.manifest_digest, "action": "purged", "plan_digest": plan["original_digest"],
            "before_observations": [purged], "after_observations": [reread]}, "evidence_digest")

    def reread_installed_surface_v1(self, *, operation_id, storage_reader, original):
        storage_reader.verify_original_v1(original, "evidence_digest")
        actual = self._call(storage_reader, operation_id, "read")
        if actual != original["after_observations"][0]:
            raise AuthorityUnavailable("controlled provider independent reread changed")
        return {"evidence_digest": original["evidence_digest"], "after_observations": [actual]}


def _control(root, packet):
    protected = root / "protected"
    lease = InstalledC09InstanceLeaseV1(protected / "instance.lock")
    control = C09StorageControlV1(control_path=protected / "control.db", key_path=protected / "control.key",
        installation_id="installation", authority_id=packet["authority_id"], control_store_id="controlled-c09-test",
        key_id="controlled-c09-key", lease=lease, resource_roots=(root / "state",))
    return control, lease


def _inventory(raw):
    raw = dict(raw); raw["resources"] = tuple(InstalledResourceV2(**{**r, "content_coverage": tuple(r["content_coverage"])}) for r in raw["resources"])
    return InstallationFilesystemManifestV2(**raw)


def _compose(control, graph, coordinator, bootstrap, service, scoped, recovery, accepted, inventory, root):
    gate = InstalledC09WriterGateV1(control=control)
    closure = AuthorityErasureClosureInventory(scoped=scoped, installation_id="installation")
    app = InstalledC09GraphApplicationV1(control=control, core=service.core, scoped=scoped, coordinator=coordinator,
        bootstrap=bootstrap, namespace=ROLE, subject=SUBJECT, credential=WORKER)
    closed = InstalledC09CloseApplyV1(control=control, service=service, recovery=recovery,
        graph_application=app, subject=SUBJECT, credential=WORKER)
    resource = D02ResourceIssuer(b"controlled-c09-resource-key" * 2)
    body = D02BodyQuoteAuthority(b"controlled-c09-body-key" * 2)
    service.core.install_current_c09_recovery_readers_v4(closure=closure, graph=graph, namespace_id=ROLE,
        resource_issuer=resource, body_authority=body, internal_services={})
    cleaners = {name: InstalledC09SurfaceCleanupV1(control=control, gate=gate, inventory_manifest=inventory, surface=name, registry=graph._registry)
        for name in SURFACES - {"model_prompt_caches"}}
    cleaners["model_prompt_caches"] = ControlledProviderCacheCleanerV1(root / "provider")
    maintenance = InstalledC09MaintenanceV1(control=control, gate=gate, core=service.core, closure=closure, graph=graph,
        namespace_id=ROLE, accepted_service=accepted, inventory_manifest=inventory, target_directory=root / "state" / "rebuild_temp",
        subject=SUBJECT, credential=WORKER, service_handles=(graph,), surface_services=cleaners, close_apply_service=closed)
    control.install_applied_reader_v1(closed)
    return maintenance, closure


def _fresh_installed_factory(state, *, extra_specs=()):
    """Actual fresh initializer and first-provision original, without a seed namespace."""
    from types import SimpleNamespace
    from sylanne3.authority_service.mtls_server import AdministratorInstallationV2
    from sylanne3.authority_service.v2_owner_contract import OwnerPrincipalV1
    from sylanne3.runtime.issuers import build_runtime_issuers
    root = state.parent
    files = {"core": state / "authority.db", "deletion": state / "deletion.db", "execution": state / "execution.db", "graph": state / "business.db"}
    installation = AdministratorInstallationV2("installation", "administrator", "controlled-installation-policy", "2", "b" * 64, CLOCK_SOURCE, 10)
    execution_spec = SimpleNamespace(path=files["execution"], journal_id="execution:controlled-c09")
    config = SimpleNamespace(authority_db=files["core"], deletion_db=files["deletion"], graph_db=files["graph"],
        instance_lock=root / "protected" / "instance.lock", execution_journals={AUTH_NS: execution_spec}, c09_storage_v1=None,
        installations_v2={(PEER.certificate_sha256, "installed"): installation},
        namespace_bindings_v2={(PEER.certificate_sha256, "installed", ROLE): AUTH_NS},
        reverse_handoff_profiles={}, reverse_handoff_issuers={}, core_authorizer=_authorize,
        local_administrator_credential=lambda action, namespace: ADMIN,
        administrator_authorizer=lambda credential, action, namespace, holder: credential == PEER,
        publisher_manifest_verifier=lambda profile, name, version, pin: pin == installation.manifest_digest)
    registry = _registry()
    lease = InstalledC09InstanceLeaseV1(config.instance_lock)
    identities = initialize_fresh_authority_v1(config, registry, instance_lease=lease)
    directories = {name: state / name for name in ("controlled_backup", "export", "rebuild_temp", "cache")}
    for directory in directories.values(): directory.mkdir()
    inventory = build_initial_inventory_v1(authority_id=identities["authority_id"], installation_id="installation",
        namespace=AUTH_NS, files=files, directories=directories)
    control = C09StorageControlV1(control_path=root / "protected" / "control.db", key_path=root / "protected" / "control.key",
        installation_id="installation", authority_id=identities["authority_id"], control_store_id="controlled-c09-test",
        key_id="controlled-c09-key", lease=lease, resource_roots=(state,))
    bootstrap_current_storage_v1(control=control, files=files, inventory=inventory, identities={"core": identities["authority_id"],
        "deletion": identities["deletion_journal_id"], "execution": identities["execution_journal_id"], "graph": "unprovisioned"})
    deletion = AuthorityV2DeletionGuard(files["deletion"])
    execution = AuthorityV2ExecutionJournal(files["execution"], namespace=AUTH_NS, journal_id=identities["execution_journal_id"], installed_storage_reader=control)
    verifiers = installed_core_verifier_factory(deletion, {AUTH_NS: execution})
    core = AuthorityServiceCore(files["core"], authorizer=_authorize, deletion_verifier=verifiers.deletion,
        execution_verifier=verifiers.execution, effect_verifier=verifiers.effect, dispatch_verifier=verifiers.dispatch)
    core.install_current_c09_storage_reader_v1(reader=control)
    fences = AuthorityV2FenceStore(core._db, lock=core._lock)
    service = AuthorityV2FenceService(core=core, fences=fences, deletion=deletion, execution=execution, namespace=AUTH_NS)
    from sylanne3.authority_service.installer_genesis_v1 import install_first_graph_provision_composition_v1
    install_first_graph_provision_composition_v1(service, config, registry)
    graph = ProductionGraphStore(files["graph"], registry)
    port = LocalFencePort(graph, service, None, identities["authority_id"])
    port.c09_control, port.c09_lease, port.c09_inventory = control, lease, inventory
    port.c09_config = config
    _, issuer = build_runtime_issuers(b"issuer-key-" * 4)
    bootstrap = object(); coordinator = GraphCoordinator(graph, bootstrap, holder="administrator", content_fence_v2=port, d11_issuer=issuer)
    return coordinator, bootstrap, service, None, {}, OwnerPrincipalV1("paired-idp", "account", "incarnation-1"), identities["authority_id"], (graph, core, deletion, execution)


def initialize_and_prepare(root, *, additional_sources=()):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    state, protected, provider = (root / name for name in ("state", "protected", "provider"))
    for directory in (state, protected, provider): directory.mkdir()
    (protected / "control.key").write_bytes(os.urandom(32)); (protected / "instance.lock").write_bytes(b"\0")
    key = Ed25519PrivateKey.generate()
    (provider / "provider.key").write_bytes(key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()))
    (provider / "provider.pub").write_bytes(key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))
    (provider / "owned-cache").mkdir(); (provider / "owned-cache" / "prompt-cache.bin").write_bytes(PRIVATE.encode())
    chain = _real_owner_chain(state, extra_purpose="context", extra_capability="workbench.erase", extra_specs=D06DomainProvider.type_specs(),
        installation_factory=_fresh_installed_factory, extra_purposes=("audit",), extra_capabilities=("workbench.correct",))
    (protected / "test-owner.key").write_bytes(chain.key.private_bytes(serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw, serialization.NoEncryption()))
    core, service = chain.service.core, chain.service
    core._authorize_callback = _authorize
    chain.resources[0].close()
    graph = ProductionGraphStore(state / "business.db", _registry())
    chain.port.graph = graph
    coordinator = GraphCoordinator(graph, chain.bootstrap, holder="administrator", content_fence_v2=chain.port,
        owner_principal_resolver=chain.current_principal)
    coordinator.register_provider(chain.bootstrap, "d06", D06DomainProvider(), "d06.contract.v1", D06DomainProvider().descriptor.request_schema_hash)
    # Real typed graph writes create two deletion-related sources and one
    # unrelated surviving source; immutable history is later reread cold.
    sources = []
    for name, text, parents in (("erase-parent", PRIVATE, ()), ("erase-child", PRIVATE + "_DERIVED", ("erase-parent",)),
            ("survive", SURVIVOR, ())) + tuple(additional_sources):
        source, access = source_key(*ROLE.as_tuple, name), access_key(*ROLE.as_tuple, name)
        record = SourceRecord(name, text, "speaker", "reported", "reported", 1.0, 2.0, "family:" + name,
            ("owner",), ("context",), parent_source_ids=parents)
        snapshot = GraphStore.graph_snapshot(graph, (source, access), _capability=graph._coordinator_capability)
        GraphStore.graph_commit(graph, GraphCandidate(Event(Scope(*ROLE.as_tuple, "source-init"), "seed:" + name, 2.0, "d06.source", {}),
            snapshot.versions, (GraphWrite(source, record.to_dict()), GraphWrite(access,
                {"source_id": name, "audiences": ["owner"], "purposes": ["context"], "status": "active", "recorded_at": 2.0}, (source,))), snapshot.epochs),
            _capability=graph._coordinator_capability)
        sources.append(source.token)
    scoped = AuthorityV2ScopedErasureStore(core=core, fences=service.fences, deletion=service.deletion, execution=service.execution, namespace=AUTH_NS)
    scoped.migrate_zero_history(credential=WORKER)
    request = replace(chain.issue_request, audience="owner")
    challenge = chain.sessions.begin_login(transport_credential=PEER, request=request)
    token = chain.sessions.accept_login(transport_credential=PEER, challenge=challenge, signature=chain.key.sign(challenge.signed_bytes()))
    authority, owner_lease, _ = coordinator.grant_current_owner(chain.bootstrap, actor="owner-actor", namespace=ROLE,
        domains=("d06",), purpose="context", audience="owner", activation_generation=1, owner_session_token=token, owner_session_request=request)
    operation = str(uuid4())
    plan = coordinator.issue_current_c09_erasure_plan_v1(authority, owner_lease, operation_id=operation, source_ref=sources[0])
    recovery = AuthorityV2DeletionPendingRecovery(core=core, fences=service.fences, deletion=service.deletion,
        execution=service.execution, namespace=AUTH_NS, scoped_store=scoped)
    pending = AuthorityV2DeletionGraphReadService(fence_service=service, owner_tickets=chain.server._v2_owner_tickets)
    chain.port.get_pending_deletion_for_graph_write = lambda **kwargs: pending.get_pending_deletion_for_graph_write(
        credential=WORKER, subject=SUBJECT, installation_id="installation", deletion_operation_id=kwargs["deletion_operation_id"], permit=kwargs["permit"])
    erasure = CurrentErasureAuthority(recovery, graph_coordinator=coordinator, graph_bootstrap=chain.bootstrap, namespace_id=ROLE,
        pending_graph_reader=pending, installation_id="installation", fence_service=service, owner_sessions=chain.sessions,
        owner_tickets=chain.server._v2_owner_tickets, scoped_store=scoped, plan_graph_coordinator=coordinator, graph_db_path=state / "business.db")
    receipt, permit = erasure.prepare_request(credential=WORKER, subject=SUBJECT, holder="administrator", installation_id="installation",
        owner_actor_id="owner-actor", owner_session_token=token, owner_session_request=request, deletion_operation_id=operation, source_id=plan.source_id)
    barrier = coordinator.commit_current_c09_source_barrier_v1(chain.bootstrap, namespace=ROLE, deletion_operation_id=operation, permit=permit)
    accepted, accepted_permit = erasure.accept_verified_graph_barrier(credential=WORKER, subject=SUBJECT, pending_mutation_id=receipt.pending.mutation_id)
    coordinator.release_current_owner_lease(chain.bootstrap, owner_lease)
    accepted_reader = CurrentAcceptedErasureReadService(fence_service=service, owner_tickets=chain.server._v2_owner_tickets, scoped_store=scoped)
    files = {"core": Path(core.path), "deletion": Path(service.deletion.path), "execution": Path(service.execution.path), "graph": state / "business.db"}
    inventory = chain.port.c09_inventory
    packet = {"authority_id": chain.authority_id, "operation_id": operation, "inventory": asdict(inventory),
        "erased_refs": sources[:2], "survivor_ref": sources[2], "barrier_digest": canonical_digest(barrier)}
    if additional_sources:packet['next_erased_refs']=sources[3:]
    from sylanne3.authority_service.v2_owner_session import to_wire as owner_session_to_wire
    packet["owner_login_request"] = owner_session_to_wire(chain.issue_request)
    _json_write(root / "packet.json", packet)
    _json_write(provider / "provider.json", {"provider_id": PROVIDER, "installation_id": "installation", "authority_id": chain.authority_id, "namespace": AUTH_NS})
    # All initial selected bytes and independent heads are observed. The
    # no-execution history is established by actual empty journal scans.
    for path in files.values():
        with closing(sqlite3.connect(path)) as db:
            if db.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()[0] != 0: raise AssertionError("actual source WAL busy")
    metadata, _ = coordinator._v2_graph_stamp(ROLE)
    control, lease = chain.port.c09_control, chain.port.c09_lease
    try:
        maintenance, closure = _compose(control, graph, coordinator, chain.bootstrap, service, scoped, recovery, accepted_reader, inventory, root)
        targets = tuple(SurfaceTargetV1(name, "sqlite_execution_journal" if name == "execution_journal_payloads" else "installed_current_four_store",
            str(service.execution.path.resolve()) if name == "execution_journal_payloads" else str(state),
            "c09.installed.v1", service.execution.journal_id if name == "execution_journal_payloads" else "generation:0", "installed") for name in sorted(SURFACES))
        closure.install_registry(credential=ADMIN, targets=targets)
        closure.begin_run(credential=WORKER, subject=SUBJECT, accepted_mutation_id=accepted.pending.mutation_id)
        result = maintenance.prepare_storage_rebase_v1(operation_id=operation)
        assert control.read_verified_current_storage_v1().stage == "PREPARED"
        return {"stage": "PREPARED", "generation": result["maintenance_generation"], "process_id": os.getpid()}
    finally:
        lease.close()


def _reopen(root):
    packet = json.loads((root / "packet.json").read_text())
    control, lease = _control(root, packet)
    context = control.read_verified_current_storage_v1()
    paths = {m["role"]: Path(m["resolved_path"]) for m in context.manifest["members"]}
    deletion = AuthorityV2DeletionGuard(paths["deletion"])
    execution = AuthorityV2ExecutionJournal(paths["execution"], namespace=AUTH_NS,
        journal_id=next(m["incarnation_or_journal_id"] for m in context.manifest["members"] if m["role"] == "execution"),
        installed_storage_reader=control)
    verifiers = installed_core_verifier_factory(deletion, {AUTH_NS: execution})
    core = AuthorityServiceCore(paths["core"], authorizer=_authorize, deletion_verifier=verifiers.deletion,
        execution_verifier=verifiers.execution, effect_verifier=verifiers.effect, dispatch_verifier=verifiers.dispatch)
    core.install_current_c09_storage_reader_v1(reader=control)
    fences = AuthorityV2FenceStore(core._db, lock=core._lock)
    service = AuthorityV2FenceService(core=core, fences=fences, deletion=deletion, execution=execution, namespace=AUTH_NS)
    scoped = AuthorityV2ScopedErasureStore(core=core, fences=fences, deletion=deletion, execution=execution, namespace=AUTH_NS)
    recovery = AuthorityV2DeletionPendingRecovery(core=core, fences=fences, deletion=deletion, execution=execution,
        namespace=AUTH_NS, scoped_store=scoped)
    graph = ProductionGraphStore(paths["graph"], _registry()); bootstrap = object()
    coordinator = GraphCoordinator(graph, bootstrap, holder="administrator", content_fence_v2=_LocalInstalledFencePortV1(service, WORKER, SUBJECT, ROLE))
    # Cleanup does not issue a new Owner deletion or source read; the existing
    # accepted scope and independent journals qualify maintenance continuation.
    maintenance, _ = _compose(control, graph, coordinator, bootstrap, service, scoped, recovery, None,
        _inventory(packet["inventory"]), root)
    return packet, control, lease, maintenance, graph, core, deletion, execution


def _fresh_source_owner_after_release(root, packet, control, maintenance, graph, core, deletion, execution):
    """Real new Ed25519 login, immutable source Owner, normal read and write."""
    import math, time
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from sylanne3.authority_service.local_composition import compose_local_owner_authority
    from sylanne3.authority_service.v2_owner_session import from_wire as owner_session_from_wire
    from sylanne3.authority_service.mtls_server import AdministratorInstallationV2
    from sylanne3.authority_service.d12_owner_storage_admission_v1 import InstalledD12OwnerStorageAdmissionServiceV1
    from sylanne3.authority_service.linux_clock_v1 import LinuxKernelClockProviderV1
    from sylanne3.authority_service.v2_clock import IngressClockSampleV2
    from sylanne3.host.authority_profile import AdminIngressClockPolicy
    from sylanne3.host.v2_fence_port import VerifiedIngressClockV2
    from sylanne3.graph_types import owner_grant_key, AtomKey
    from sylanne3.domains.d06.source_access_revocation import SourceAccessRevocationRequest
    now = lambda: datetime.now(timezone.utc).replace(microsecond=0)
    service = maintenance.close_apply_service.service
    selected_graph_path = Path(graph._db.execute("PRAGMA database_list").fetchone()[2])
    registry = graph._registry
    graph.close()
    # A normal Host opens its own selected current handle/coordinator after
    # release. Never rebind a production store or rewrite its private lease.
    graph = ProductionGraphStore(selected_graph_path, registry)
    pairings = AuthorityOwnerPairingSource(core, utc_clock=now, create=False)
    verifier = OwnerDeploymentVerifier(pairings, now)
    proofs = AuthorityV2OwnerProofStore(core, utc_clock=now, pairing_verifier=verifier.pair_credential,
        current_pairing_source=pairings, create=False)
    sessions = AuthorityV2OwnerSessionStore(core, utc_clock=now, current_pairing_source=pairings, create=False)
    clock_provider = LinuxKernelClockProviderV1(source_id=CLOCK_SOURCE, maximum_error_seconds=10)
    server = compose_local_owner_authority(core=core, v2_fences={AUTH_NS: service}, graph_db_path=Path(graph._db.execute("PRAGMA database_list").fetchone()[2]),
        utc_clock=now, first_claim_verifier=lambda *_: False, claimant_verifier=None,
        owner_proofs=proofs, owner_sessions=sessions, creation_pairing_source=pairings, create_owner_schema=False,
        administrator_authorizer=lambda credential, *_: credential == PEER,
        publisher_manifest_verifier=lambda *_: True,
        installations_v2={(PEER.certificate_sha256, "installed"): AdministratorInstallationV2(
            "installation", "administrator", "controlled-installation-policy", "2", "b" * 64, CLOCK_SOURCE, 10)},
        namespace_bindings_v2={(PEER.certificate_sha256, "installed", ROLE): AUTH_NS}, clock_provider=clock_provider)
    tickets = server._v2_owner_tickets
    owner_service = InstalledD12OwnerStorageAdmissionServiceV1(fences=service, owner_tickets=tickets,
        graph_db_path=Path(graph._db.execute("PRAGMA database_list").fetchone()[2]), namespace_id=ROLE,
        installation_id="installation", holder="administrator", control=control, close_apply=maintenance.close_apply_service)
    port = LocalFencePort(graph, service, tickets, packet["authority_id"])
    def current_guard(**kwargs):
        return tickets.get_current_guard(credential=WORKER, authority_namespace=AUTH_NS,
            installation_id="installation", subject=SUBJECT, permit=kwargs["permit"],
            owner_actor_id=kwargs.get("owner_actor_id"), owner_session_token=kwargs.get("owner_session_token"),
            owner_session_request=kwargs.get("owner_session_request")), kwargs["permit"]
    port.get_current_owner_guard_for_fence = current_guard
    port.get_current_owner_authority_for_fence_v1 = lambda **kwargs: owner_service.get_current_owner_authority_for_fence_v1(
        credential=WORKER, subject=SUBJECT, permit=kwargs["permit"], actor=kwargs["owner_actor_id"],
        session_token=kwargs["owner_session_token"], session_request=kwargs["owner_session_request"])
    def clock_read(policy):
        assert type(policy) is AdminIngressClockPolicy and policy.source_id == CLOCK_SOURCE
        core._require(PEER, "clock", AUTH_NS)
        before = time.monotonic(); reading = clock_provider(); after = time.monotonic()
        assert reading.healthy and reading.utc_error_seconds <= policy.max_utc_error_seconds and after - before <= policy.max_round_trip_seconds
        sample = IngressClockSampleV2(packet["authority_id"], "installation", reading.source_id, reading.utc_seconds,
            reading.monotonic_seconds, reading.epoch, reading.utc_error_seconds)
        return VerifiedIngressClockV2(sample, before, after, math.nextafter(math.fsum((sample.utc_seconds, sample.utc_error_seconds, after - before)), math.inf))
    port.read_ingress_clock = clock_read
    def principal(actor, namespace):
        actual = pairings.current_actor_binding(authority_namespace=AUTH_NS, installation_id="installation", actor_id=actor)
        return actual.principal if actual is not None and namespace == ROLE else None
    bootstrap = object()
    coordinator = GraphCoordinator(graph, bootstrap, holder="administrator", content_fence_v2=port,
        owner_principal_resolver=principal, scene_clock_policy=AdminIngressClockPolicy(CLOCK_SOURCE, 10, 10))
    provider = D06DomainProvider(); coordinator.register_provider(bootstrap, "d06", provider, "d06.contract.v1", provider.descriptor.request_schema_hash)
    from sylanne3.runtime.d11_types import D11RuntimeProvider, D11_PROPOSAL_SCHEMA
    owner_provider = D11RuntimeProvider()
    coordinator.register_provider(bootstrap, "d11", owner_provider, D11_PROPOSAL_SCHEMA,
        owner_provider.descriptor.request_schema_hash)
    request = replace(owner_session_from_wire(packet["owner_login_request"]), audience="owner")
    key = Ed25519PrivateKey.from_private_bytes((root / "protected" / "test-owner.key").read_bytes())
    challenge = sessions.begin_login(transport_credential=PEER, request=request)
    token = sessions.accept_login(transport_credential=PEER, challenge=challenge, signature=key.sign(challenge.signed_bytes()))
    owner_key = owner_grant_key(*ROLE.as_tuple)
    with graph._lock:
        immutable = graph._db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=?", (owner_key.token,)).fetchone()
    authority, owner_lease, binding = coordinator.grant_current_owner(bootstrap, actor="owner-actor", namespace=ROLE,
        domains=("d06",), purpose="context", audience="owner", activation_generation=1,
        owner_session_token=token, owner_session_request=request)
    assert binding.storage_admission is not None and binding.target_admission is None
    snapshot = coordinator.read_snapshot(authority, owner_lease, (AtomKey.from_token(packet["survivor_ref"]),))
    assert snapshot.atoms[0].valid and snapshot.atoms[0].value["text"] == SURVIVOR
    coordinator.release_current_owner_lease(bootstrap, owner_lease)
    authority, owner_lease, _ = coordinator.grant_current_owner(bootstrap, actor="owner-actor", namespace=ROLE,
        domains=("d06", "d11"), purpose="audit", audience="owner", activation_generation=1,
        owner_session_token=token, owner_session_request=request)
    receipt = coordinator.revoke_source_access_v1(authority, owner_lease,
        SourceAccessRevocationRequest("survive", "owner-actor", str(uuid4()), time.time()))
    assert receipt.source_id == "survive"
    coordinator.release_current_owner_lease(bootstrap, owner_lease)
    with graph._lock:
        assert graph._db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=?", (owner_key.token,)).fetchone() == immutable
        access = graph._db.execute("SELECT value FROM graph_atoms WHERE token=?", (access_key(*ROLE.as_tuple, "survive").token,)).fetchone()
        assert json.loads(access[0])["status"] == "withdrawn"
    sessions.logout(transport_credential=PEER, request=request, token=token)
    graph.close()
    return {"fresh_owner_read": True, "fresh_owner_write": True}


def resume(root, phase):
    if phase == "switch":
        # The real cold installed entry selects PREPARED before a constructor
        # can write a schema/WAL into the immutable frozen source bundle.
        packet = json.loads((root / "packet.json").read_text())
        control, lease = _control(root, packet)
        try:
            from sylanne3.authority_service.c09_preopen_switch_v1 import switch_cold_prepared_storage_before_open_v1
            context = switch_cold_prepared_storage_before_open_v1(control=control, registry=_registry())
            assert context.stage == "SWITCHED"
            return {"stage": context.stage, "generation": context.storage_generation, "process_id": os.getpid()}
        finally:
            lease.close()
    packet, control, lease, maintenance, graph, core, deletion, execution = _reopen(root)
    try:
        operation = packet["operation_id"]
        if phase == "switch":
            assert control.read_verified_current_storage_v1().stage == "PREPARED"
            maintenance.switch_prepared_storage_v1(operation_id=operation)
            assert maintenance.restart_required
        elif phase == "release":
            maintenance.resume_storage_maintenance_v1(operation_id=operation)
        else:
            context = control.read_verified_current_storage_v1(); context.require_current("business")
            assert context.stage == "RELEASED"
            from current_source_location_acceptance_support_v1 import assert_current_source_location_v1
            assert assert_current_source_location_v1(maintenance, credential=WORKER,
                subject=SUBJECT, holder="administrator") == context.storage_generation
            with graph._lock:
                for ref in packet["erased_refs"]:
                    rows = graph._db.execute("SELECT value,valid FROM graph_history WHERE token=?", (ref,)).fetchall()
                    assert rows and all(json.loads(value)["schema"] == "sylanne3.graph.erased_value.v1" and valid == 0 for value, valid in rows)
                survivor = graph._db.execute("SELECT value,valid FROM graph_atoms WHERE token=?", (packet["survivor_ref"],)).fetchone()
                assert survivor[1] == 1 and SURVIVOR in survivor[0]
            assert not tuple((root / "provider" / "owned-cache").iterdir())
            for name in ("authority.db", "deletion.db", "execution.db", "business.db"):
                assert not (root / "state" / name).exists()
            ordinary = _fresh_source_owner_after_release(root, packet, control, maintenance, graph, core, deletion, execution)
        context = control.read_verified_current_storage_v1()
        return {"stage": context.stage, "generation": context.storage_generation, "process_id": os.getpid(),
            **(ordinary if phase == "verify" else {})}
    finally:
        for handle in (graph, execution, deletion, core):
            try: handle.close()
            except (sqlite3.Error, AttributeError): pass
        lease.close()


if __name__ == "__main__":
    phase, root = sys.argv[1], Path(sys.argv[2])
    if phase == "provider": result = _provider_action(root, json.loads(sys.stdin.read()))
    elif phase == "prepare": result = initialize_and_prepare(root)
    else: result = resume(root, phase)
    print(canonical_serialize(result))
