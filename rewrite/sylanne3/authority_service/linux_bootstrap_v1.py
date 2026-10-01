"""One-way, fresh-only initialization used by the Linux installer.

No running service calls this module. It initializes independent empty journals
under the instance lease, installs all current schemas, then seals v2-only.
"""
from __future__ import annotations

import asyncio
from contextlib import closing
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
import sqlite3

from .contract import AuthorityUnavailable
from .core import AuthorityServiceCore
from .c09_storage_control_v1 import C09StorageControlV1, InstalledC09InstanceLeaseV1, ROLES, SURFACES, digest, file_observation_v1
from .c09_authority_storage_rebase import _objects, _root
from .installed_core_verifiers import installed_core_verifier_factory
from .reverse_handoff import ReverseGraphClaimClient
from .v2_deletion_guard import AuthorityV2DeletionGuard
from .v2_execution_journal import AuthorityV2ExecutionJournal
from .v2_fence_service import AuthorityV2FenceService
from .v2_fence_store import AuthorityV2FenceStore
from .v2_model_egress_store import AuthorityV2ModelEgressStore
from .v2_worker_model_result_attempts import AuthorityV2WorkerModelResultAttempts
from .v2_owner_session import AuthorityV2OwnerSessionStore
from .v2_owner_proof import AuthorityV2OwnerProofStore
from .v2_deletion_migration import AuthorityV2DeletionMigration
from .v2_deletion_tail_migration import AuthorityV2DeletionTailMigration
from .v2_scoped_erasure_store import AuthorityV2ScopedErasureStore
from ..graph_store import ProductionGraphStore
from ..host.owner_deployment import compose_owner_deployment, OwnerDeploymentVerifier
from ..host.owner_identity_sqlite import AuthorityOwnerPairingSource
from ..runtime.deletion import DeletionJournal
from ..runtime.c09_installation_inventory_v2 import InstallationFilesystemManifestV2, InstalledResourceV2
from ..runtime_contracts import canonical_digest


def initialize_fresh_authority_v1(config, registry, *, instance_lease=None):
    """Return real new Authority identity; refuse existing or partial databases."""
    if instance_lease is None:
        with InstalledC09InstanceLeaseV1(config.instance_lock) as held:
            return initialize_fresh_authority_v1(config, registry, instance_lease=held)
    if (type(instance_lease) is not InstalledC09InstanceLeaseV1
            or instance_lease.path.resolve() != Path(config.instance_lock).resolve()):
        raise AuthorityUnavailable("fresh installer requires the actual held instance lease")
    instance_lease.require_held()
    if len(config.execution_journals) != 1 or config.c09_storage_v1 is not None:
        raise AuthorityUnavailable("fresh initializer requires one unbound C09 cohort")
    namespace = next(iter(config.execution_journals))
    paths = (config.authority_db, config.deletion_db, config.graph_db,
             config.execution_journals[namespace].path)
    if any(Path(path).exists() for path in paths):
        raise AuthorityUnavailable("fresh install refuses existing or partial state; inspect and recover it explicitly")
    for path in paths:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
    graph = ProductionGraphStore(config.graph_db, registry)
    graph.close()
    deletion = DeletionJournal(config.deletion_db, create=True)
    deletion.close()
    guard = AuthorityV2DeletionGuard(config.deletion_db)
    installed = config.execution_journals[namespace]
    execution = AuthorityV2ExecutionJournal(installed.path, namespace=namespace,
        journal_id=installed.journal_id, create=True)
    core = server = None
    try:
        verifiers = installed_core_verifier_factory(guard, {namespace: execution})
        core = AuthorityServiceCore(config.authority_db, create=True, authorizer=config.core_authorizer,
            deletion_verifier=verifiers.deletion, execution_verifier=verifiers.execution,
            effect_verifier=verifiers.effect, dispatch_verifier=verifiers.dispatch)
        with guard.freeze_writes():
            deletion_head = guard.verified_head()
        holder = next(iter(config.installations_v2.values())).administrator_holder
        core.register_namespace(config.local_administrator_credential("install", namespace),
            namespace, holder, deletion_head, execution.verified_head())
        core.seal_v2_only(config.local_administrator_credential("seal_v2_only", namespace))
        fences = AuthorityV2FenceStore(core._db, create=True, lock=core._lock)
        service = AuthorityV2FenceService(core=core, fences=fences, deletion=guard,
            execution=execution, namespace=namespace)
        migration = config.local_administrator_credential("migrate_deletion", namespace)
        for cls in (AuthorityV2DeletionMigration, AuthorityV2DeletionTailMigration):
            cls(core=core, fences=fences, deletion=guard, execution=execution, namespace=namespace).run(credential=migration)
        AuthorityV2ScopedErasureStore(core=core, fences=fences, deletion=guard, execution=execution,
            namespace=namespace).migrate_zero_history(credential=migration)
        AuthorityV2ModelEgressStore(core._db, create=True, lock=core._lock)
        AuthorityV2WorkerModelResultAttempts(core._db, create=True, lock=core._lock)
        clock = lambda: datetime.now(timezone.utc)
        pairings = AuthorityOwnerPairingSource(core, utc_clock=clock, create=True)
        verifier = OwnerDeploymentVerifier(pairings, clock)
        AuthorityV2OwnerProofStore(core, utc_clock=clock, pairing_verifier=verifier.pair_credential, create=True)
        sessions = AuthorityV2OwnerSessionStore(core, utc_clock=clock, current_pairing_source=pairings, create=True)
        server = compose_owner_deployment(core=core, v2_fences={namespace: service}, graph_db_path=config.graph_db,
            utc_clock=clock, identity=pairings, administrator_authorizer=config.administrator_authorizer,
            publisher_manifest_verifier=config.publisher_manifest_verifier, installations_v2=config.installations_v2,
            namespace_bindings_v2=config.namespace_bindings_v2,
            v2_final_handoff_reverse={key: ReverseGraphClaimClient(value) for key, value in config.reverse_handoff_profiles.items()},
            v2_final_handoff_issuers=config.reverse_handoff_issuers, owner_sessions=sessions, create_owner_schema=True)
        authority_id = core._db.execute("SELECT value FROM authority_meta WHERE key='authority_id'").fetchone()[0]
        from .installer_genesis_v1 import record_installer_genesis_original_v1
        genesis = record_installer_genesis_original_v1(core=core, config=config, registry=registry,
            instance_lease=instance_lease, files={"core": config.authority_db, "deletion": config.deletion_db,
                "execution": installed.path, "graph": config.graph_db})
        result = {"authority_id": authority_id, "namespace": namespace,
            "deletion_journal_id": deletion_head.journal_id, "execution_journal_id": execution.journal_id,
            "first_graph_genesis_digest": genesis.original_digest}
    finally:
        if server is not None:
            asyncio.run(server.aclose())
        for handle in (core, execution, guard):
            if handle is not None:
                handle._db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                handle.close()
    return result


def build_initial_inventory_v1(*, authority_id, installation_id, namespace, files, directories):
    resources = []
    for role in ROLES:
        for suffix, kind in (("", "sqlite_db"), ("-wal", "sqlite_wal"), ("-shm", "sqlite_shm")):
            resources.append(InstalledResourceV2(role + (":" + kind if suffix else ""), kind,
                str(Path(files[role]).resolve()), namespace, authority_id + ":" + role, 1, 0,
                "administrator", "sqlite3", tuple(sorted(SURFACES)), "c09.installed.v1")
                if not suffix else InstalledResourceV2(role + ":" + kind, kind,
                str(Path(files[role]).resolve()) + suffix, namespace, authority_id + ":" + role, 1, 0,
                "administrator", "sqlite3", tuple(sorted(SURFACES)), "c09.installed.v1"))
    coverages = {"controlled_backup": ("controlled_backups",), "export": ("imports_exports",),
        "rebuild_temp": ("sqlite_wal_free_pages",), "cache": tuple(sorted(SURFACES - {"controlled_backups"}))}
    for kind, path in sorted(directories.items()):
        resources.append(InstalledResourceV2(kind, kind, str(Path(path).resolve()), namespace,
            authority_id + ":" + kind, 1, 0, "administrator", "managed_directory",
            coverages[kind], "c09.installed.v1"))
    resources = tuple(sorted(resources, key=lambda item: item.path))
    schema = "sylanne3.c09.installation_filesystem_manifest.v2"
    return InstallationFilesystemManifestV2(authority_id, installation_id, namespace, resources,
        canonical_digest((schema, authority_id, installation_id, namespace, resources)))


def bootstrap_current_storage_v1(*, control, files, inventory, identities):
    """Observe the actual closed genesis files, then commit the signed pointer."""
    members = []
    for role in ROLES:
        path = Path(files[role])
        observation = file_observation_v1(path, exclusive=True)
        with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)) as db:
            db.execute("PRAGMA query_only=ON")
            if db.execute("PRAGMA quick_check").fetchone() != ("ok",):
                raise AuthorityUnavailable("fresh installed SQLite integrity differs")
            schema_root, logical_root = digest(_objects(db)), _root(db)
        members.append(dict(role=role, **observation, store_id=control.authority_id + ":" + role,
            schema_version="4" if role == "execution" else "2" if role == "deletion" else "1",
            namespace=inventory.namespace, storage_generation=0, incarnation_or_journal_id=identities[role],
            logical_data_root=logical_root, schema_objects_digest=schema_root,
            cold_read_digest=digest(("fresh_closed_genesis", role, schema_root, logical_root, observation)),
            wal_policy="checkpointed_closed_before_switch", companion_resource_ids=[role + ":wal", role + ":shm", role + ":journal"]))
    manifest = dict(schema="sylanne3.c09.storage_manifest.v1", authority_id=control.authority_id,
        installation_id=control.installation_id, cohort_namespaces=[inventory.namespace], generation=0,
        prior_manifest_digest=None, members=members, inventory_manifest_digest=inventory.manifest_digest,
        certificate_digest=None, graph_issue_digest=None, recovery_pin_digest=None,
        cumulative_tombstone_root=canonical_digest(()), deletion_watermark=0)
    manifest["manifest_digest"] = digest(manifest)
    return control.bootstrap_installed_storage_v1(manifest=manifest)
