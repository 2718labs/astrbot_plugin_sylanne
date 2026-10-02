"""Cold-open and lifecycle for an installer-owned Authority process.

This module does not load executable policy from disk. The service
installer must construct ``AuthorityDeploymentConfig`` with its trusted OS
identity, publisher, and journal verification adapters before calling open.
"""

from __future__ import annotations

import asyncio
from contextlib import closing
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
import sqlite3
import threading
from types import MappingProxyType

from .contract import AuthorityUnavailable
from .core import AuthorityServiceCore
from .deployment_config import AuthorityCoreVerifiers, AuthorityDeploymentConfig, ExecutionJournalInstallation
from .installed_creation_ticket_verifier import PinnedInstalledCreationTicketVerifier
from .current_model_egress_graph_verifier import PinnedCurrentModelEgressGraphVerifier
from .v2_clock import AuthorityClockReadingV2
from .v2_model_egress_service import AuthorityV2ModelEgressService
from .v2_model_egress_store import AuthorityV2ModelEgressStore
from .reverse_handoff import ReverseGraphClaimClient
from .v2_deletion_guard import AuthorityV2DeletionGuard
from .v2_deletion_recovery_service import AuthorityV2DeletionPendingRecovery
from .v2_scoped_erasure_store import AuthorityV2ScopedErasureStore
from .current_erasure_service import CurrentErasureAuthority
from .current_accepted_erasure_read import CurrentAcceptedErasureReadService
from .v2_execution_journal import AuthorityV2ExecutionJournal
from .v2_fence_service import AuthorityV2FenceService
from .v2_fence_store import AuthorityV2FenceStore
from .v2_owner_session import AuthorityV2OwnerSessionStore
from .v2_owner_contract import OwnerClaimTicketV1
from ..host.owner_deployment import compose_owner_deployment
from ..host.owner_identity_sqlite import AuthorityOwnerPairingSource
from ..runtime.installed_v2_graph_dispatch_verifier import (
    make_installed_v2_graph_dispatch_verifier,
)


_CORE_TABLES = frozenset({
    "authority_meta", "authority_namespaces", "authority_transfers",
    "authority_permits", "authority_effects", "authority_events",
})
_CORE_TRIGGERS = frozenset({
    "authority_events_no_update", "authority_events_no_delete",
})
_OWNER_TABLES = frozenset({
    "authority_owner_creation_pairings_v1",
    "authority_owner_credential_pairings_v1",
    "authority_owner_actor_bindings_v1",
    "authority_owner_credentials_v1",
    "authority_owner_enrollments_v1",
    "authority_owner_proof_challenges_v1",
    "authority_owner_login_challenges_v1",
    "authority_owner_sessions_v1",
    "authority_owner_session_principals_v1",
    "authority_owner_session_revoked_keys_v1",
    "authority_owner_claim_tickets_v1",
    "authority_owner_issue_pending_v1",
    "authority_owner_issue_committed_v1",
    "authority_owner_authorization_heads_v1",
    "authority_owner_revoke_pending_v1",
    "authority_owner_revoke_committed_v1",
})


def _installed_file(path: Path, label: str) -> Path:
    if not path.is_absolute() or not path.is_file():
        raise AuthorityUnavailable(f"installed {label} file is absent or unsafe")
    for component in (path, *path.parents):
        if (component.is_symlink()
                or getattr(component, "is_junction", lambda: False)()):
            raise AuthorityUnavailable(f"installed {label} traverses a reparse point")
    return path.resolve(strict=True)


def _preflight(config: AuthorityDeploymentConfig) -> dict[str, Path]:
    paths = {
        "authority": _installed_file(config.authority_db, "Authority DB"),
        "deletion": _installed_file(config.deletion_db, "deletion journal"),
        "graph": _installed_file(config.graph_db, "graph DB"),
        "lock": _installed_file(config.instance_lock, "instance lock"),
    }
    for namespace, installation in config.execution_journals.items():
        paths["execution:" + namespace] = _installed_file(
            installation.path, "execution journal")
    for namespace, installation in (config.c04_installations_v2 or {}).items():
        key = _installed_file(installation.component_key_path,
                              "C04 component key")
        package_root = installation.package_root
        if (not package_root.is_absolute() or not package_root.is_dir()
                or any(component.is_symlink()
                       or getattr(component, "is_junction", lambda: False)()
                       for component in (package_root, *package_root.parents))
                or key.is_relative_to(package_root.resolve(strict=True))):
            raise AuthorityUnavailable("C04 formal package or protected key is unsafe")
        paths["c04_key:" + namespace] = key
    for namespace, installation in (
            getattr(config, "c04_installations_v3", None) or {}).items():
        key = _installed_file(installation.component_key_path,
                              "C04 V3 component key")
        package_root = installation.package_root
        if (not package_root.is_absolute() or not package_root.is_dir()
                or any(component.is_symlink()
                       or getattr(component, "is_junction", lambda: False)()
                       for component in (package_root, *package_root.parents))
                or key.is_relative_to(package_root.resolve(strict=True))):
            raise AuthorityUnavailable("C04 V3 formal package or protected key is unsafe")
        paths["c04_v3_key:" + namespace] = key
    if len(set(paths.values())) != len(paths):
        raise AuthorityUnavailable("installed Authority assets share a file")
    for name in ("certificate", "private_key", "client_trust_root"):
        _installed_file(Path(getattr(config.tls, name)), "Authority TLS " + name)
    for profile in config.reverse_handoff_profiles.values():
        for name in ("trust_root", "client_certificate", "client_private_key"):
            _installed_file(Path(getattr(profile, name)), "reverse TLS " + name)
    with closing(sqlite3.connect(paths["authority"].as_uri() + "?mode=ro", uri=True)) as db:
        db.execute("PRAGMA query_only=ON")
        if db.execute("PRAGMA quick_check").fetchone() != ("ok",):
            raise AuthorityUnavailable("installed Authority DB integrity differs")
        rows = db.execute("SELECT type,name FROM sqlite_master").fetchall()
        tables = {name for kind, name in rows if kind == "table"}
        triggers = {name for kind, name in rows if kind == "trigger"}
        if (not (_CORE_TABLES | _OWNER_TABLES) <= tables
                or not _CORE_TRIGGERS <= triggers
                or "authority_owner_actor_live_principal_v1" not in
                   {name for kind, name in rows if kind == "index"}):
            raise AuthorityUnavailable("initialized Authority Core or Owner schema is absent")
        from .d10_contact_policy_service_v1 import TABLE as contact_table, DDL as contact_ddl
        if contact_table in tables and db.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?",
                (contact_table,)).fetchone() != (contact_ddl,):
            raise AuthorityUnavailable("installed D10 contact policy Core schema differs")
        if contact_table in tables:
            from .c09_contact_policy_rows_v1 import require_contact_policy_schema_v1
            require_contact_policy_schema_v1(db)
        meta = dict(db.execute("SELECT key,value FROM authority_meta"))
        if (not meta.get("authority_id") or meta.get("service_mode") != "v2-only"):
            raise AuthorityUnavailable("installed Authority is not sealed v2-only")
        present = {row[0] for row in db.execute("SELECT namespace FROM authority_namespaces")}
        if not set(config.execution_journals) <= present:
            raise AuthorityUnavailable("installed Authority namespace is absent")
    with closing(sqlite3.connect(paths["graph"].as_uri() + "?mode=ro", uri=True)) as db:
        db.execute("PRAGMA query_only=ON")
        graph_tables = {row[0] for row in db.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        if not {"graph_type_catalog", "graph_namespace_provisioning_v2",
                "graph_owner_issue_operations_v1"} <= graph_tables:
            raise AuthorityUnavailable("initialized Owner graph schema is absent")
    return paths


def _instance_lock(path: Path):
    from .c09_storage_control_v1 import InstalledC09InstanceLeaseV1
    if path.stat().st_size < 1:
        raise AuthorityUnavailable("installed instance lock has no byte")
    return InstalledC09InstanceLeaseV1(path)


def _release_instance_lock(handle):
    handle.close()


def _resolve_current_c09_config(config, lease):
    if config.c09_storage_v2 is not None:
        installed = config.c09_storage_v2
        from .c09_storage_control_v1 import C09StorageControlV1
        from .c09_control_selector_v2 import InstalledC09ControlSelectorV2
        from .c09_sanitized_history_v2 import InstalledC09StorageReaderV2
        # The old Control is retired. Construct only its protected identity;
        # never call its SQL opener or V1 recovery/bootstrap path.
        _installed_file(installed.key_path, "C09 V2 identity key")
        _installed_file(installed.selector_path, "C09 V2 selector")
        _installed_file(installed.selector_journal_path, "C09 V2 selector journal")
        control = C09StorageControlV1(control_path=installed.control_path,
            key_path=installed.key_path, installation_id=installed.installation_id,
            authority_id=installed.authority_id, control_store_id=installed.control_store_id,
            key_id=installed.key_id, lease=lease, resource_roots=installed.resource_roots)
        selector = InstalledC09ControlSelectorV2(control,
            installed.selector_path, installed.selector_journal_path)
        reader = InstalledC09StorageReaderV2(control=control, selector=selector)
        context = reader.read_verified_current_storage_v2()
        context.require_current("recovery")
        namespaces = sorted(config.execution_journals)
        if (context.manifest["cohort_namespaces"] != namespaces
                or context.manifest["authority_id"] != installed.authority_id
                or context.manifest["installation_id"] != installed.installation_id
                or any(item.installation_id != installed.installation_id
                       for item in config.installations_v2.values())):
            raise AuthorityUnavailable("C09 V2 installed factual cohort differs")
        members = {member["role"]: member for member in context.manifest["members"]}
        namespace = namespaces[0]
        return replace(config, authority_db=Path(members["core"]["resolved_path"]),
            deletion_db=Path(members["deletion"]["resolved_path"]),
            graph_db=Path(members["graph"]["resolved_path"]),
            execution_journals={namespace: ExecutionJournalInstallation(
                Path(members["execution"]["resolved_path"]),
                members["execution"]["incarnation_or_journal_id"])}), reader
    installed = config.c09_storage_v1
    if installed is None:
        return config, None
    from .c09_storage_control_v1 import C09StorageControlV1
    _installed_file(installed.control_path, "C09 control log")
    _installed_file(installed.key_path, "C09 control key")
    control = C09StorageControlV1(control_path=installed.control_path,
        key_path=installed.key_path, installation_id=installed.installation_id,
        authority_id=installed.authority_id, control_store_id=installed.control_store_id,
        key_id=installed.key_id, lease=lease, resource_roots=installed.resource_roots)
    from .c09_preopen_switch_v1 import switch_cold_prepared_storage_before_open_v1
    before_stage = control.read_verified_current_storage_v1().stage
    if before_stage == "INTENT":
        with control._db() as db:
            operation = control._current(db)["active_operation_id"]
        complete = all(control.read_build_original_v1(operation_id=operation, kind=kind) is not None
            for kind in ("graph_candidate", "storage_candidate", "prepared_checkpoint_inputs_v1", "current_inventory_scan_v3"))
        if complete:
            from .c09_retired_final_scan_v1 import resume_retired_final_scan_before_open_v1
            resume_retired_final_scan_before_open_v1(control=control,
                registry=None if config.c09_maintenance_factory is None else config.c09_maintenance_factory.registry)
        else:
            from .c09_cold_intent_v1 import resume_early_intent_before_open_v1
            resume_early_intent_before_open_v1(config=config, control=control)
    switch_cold_prepared_storage_before_open_v1(control=control,
        registry=None if config.c09_maintenance_factory is None else config.c09_maintenance_factory.registry)
    current = control.read_verified_current_storage_v1()
    if before_stage in {"INTENT", "PREPARED"} and current.stage == "SWITCHED":
        from .contract import AuthorityColdRestartRequired
        raise AuthorityColdRestartRequired("C09 preopen switched; restart in a new OS process before cleanup")
    members = {member["role"]: member for member in current.manifest["members"]}
    namespaces = set(config.execution_journals)
    if current.manifest["cohort_namespaces"] != sorted(namespaces):
        raise AuthorityUnavailable("C09 current manifest namespace coverage differs")
    namespace = next(iter(namespaces))
    return replace(config, authority_db=Path(members["core"]["resolved_path"]),
        deletion_db=Path(members["deletion"]["resolved_path"]),
        graph_db=Path(members["graph"]["resolved_path"]),
        execution_journals={namespace: ExecutionJournalInstallation(
            Path(members["execution"]["resolved_path"]),
            members["execution"]["incarnation_or_journal_id"])}), control


class AuthorityFactualDaemonV2:
    """Cold selected factual reader with no model, sender or business listener."""

    def __init__(self, config, lock_handle, reader):
        from .core import AuthorityFactualReadCoreV2
        self.config = config
        self._lock_handle = lock_handle
        self.reader = reader
        self.core = AuthorityFactualReadCoreV2(reader=reader,
            authorizer=config.core_authorizer)
        self._closed = False

    @property
    def is_listening(self):
        return False

    def read_current_sanitized_execution_v2(self, *, credential, namespace, execution_id):
        if self._closed:
            raise AuthorityUnavailable("C09 V2 factual daemon is closed")
        return self.core.read_current_sanitized_execution_v2(
            credential=credential, namespace=namespace, execution_id=execution_id)

    async def start(self):
        raise AuthorityUnavailable("C09 V2 factual-only daemon: business/accounting listener HOLD")

    async def aclose(self):
        if not self._closed:
            self._closed = True
            try:
                self.core.close()
            finally:
                _release_instance_lock(self._lock_handle)
                self._lock_handle = None


class AuthorityDaemon:
    """One local listener and the exact durable objects it reopened."""

    def __init__(self, config, lock_handle, core, deletion, execution, pairings,
                 server):
        self.config = config
        self._lock_handle = lock_handle
        self.core = core
        self.deletion = deletion
        self.execution = MappingProxyType(dict(execution))
        self.owner_pairings = pairings
        self._creation_verifier = PinnedInstalledCreationTicketVerifier(
            config.graph_db, core)
        self._maintenance_lock = threading.RLock()
        self.server = server
        self.installations_v2 = config.installations_v2
        self.namespace_bindings_v2 = config.namespace_bindings_v2
        self._listener: asyncio.AbstractServer | None = None
        self._starting = False
        self._closed = False
        self.c09_control = None
        self.c09_gate = None
        self.c09_maintenance = None

    @property
    def is_listening(self) -> bool:
        return self._listener is not None and self._listener.is_serving()

    async def wait_for_cold_restart_v1(self) -> None:
        """Supervisor boundary: drain RPC, close all handles, then exit process.

        Reopening in this process is deliberately unsupported. Its PID/birth
        remains a cache-holder original until the service supervisor restarts it.
        """
        await self.server.c09_restart_requested_v1.wait()
        await self.aclose()

    async def resume_cold_maintenance_v1(self) -> bool:
        """Resume the exact durable operation before opening ordinary RPCs."""
        if self.c09_control is None:
            return False
        context = self.c09_control.read_verified_current_storage_v1()
        if context.stage in {"READY", "RELEASED"}:
            context.require_current("business")
            return False
        with self.c09_control._db() as db:
            operation_id = self.c09_control._current(db)["active_operation_id"]
        await asyncio.to_thread(self.c09_maintenance.resume_storage_maintenance_v1,
                                operation_id=operation_id)
        return self.c09_maintenance.restart_required

    async def wait_until_stopped_v1(self, stop) -> bool:
        """A service wrapper exits on true so its OS supervisor can restart it."""
        stopped = asyncio.create_task(asyncio.to_thread(stop.wait))
        restarted = asyncio.create_task(self.wait_for_cold_restart_v1())
        try:
            done, _ = await asyncio.wait((stopped, restarted), return_when=asyncio.FIRST_COMPLETED)
            if restarted in done:
                await restarted
                stop.set()
                await stopped
                return True
            return False
        finally:
            stop.set()
            if not restarted.done():
                restarted.cancel()
            await asyncio.gather(stopped, restarted, return_exceptions=True)

    def require_offline_admin_maintenance(self) -> None:
        with self._maintenance_lock:
            if (self._closed or self._lock_handle is None
                    or self._starting or self._listener is not None):
                raise AuthorityUnavailable("offline Authority maintenance requires stopped locked daemon")

    def verify_original_creation_ticket(self, ticket: OwnerClaimTicketV1) -> bool:
        """Read W01 genesis against this installed Core while offline lock is held."""
        with self._maintenance_lock:
            self.require_offline_admin_maintenance()
            return self._creation_verifier(ticket)

    def pair_original_creation_ticket(
            self, *, administrator_credential: object,
            authority_namespace: str, ticket: OwnerClaimTicketV1,
            client_certificate_sha256: str,
            valid_until_utc: datetime) -> None:
        """Verify the original and write the pairing under one maintenance lock."""
        with self._maintenance_lock:
            self.require_offline_admin_maintenance()
            if not self._creation_verifier(ticket):
                raise AuthorityUnavailable("pinned W01 original creation verification failed")
            ticket_expiry = datetime.strptime(
                ticket.expires_at_utc, "%Y-%m-%dT%H:%M:%SZ").replace(
                    tzinfo=timezone.utc)
            if valid_until_utc > ticket_expiry:
                raise AuthorityUnavailable("Owner pairing exceeds original ticket expiry")
            try:
                self.owner_pairings.pair_creation(
                    administrator_credential=administrator_credential,
                    authority_namespace=authority_namespace, ticket=ticket,
                    client_certificate_sha256=client_certificate_sha256,
                    valid_until_utc=valid_until_utc)
            except sqlite3.IntegrityError as exc:
                raise AuthorityUnavailable("Owner creation pairing already exists") from exc

    def require_local_administrator(self, action: str, namespace: str) -> object:
        self.require_offline_admin_maintenance()
        try:
            credential = self.config.local_administrator_credential(action, namespace)
        except Exception as exc:
            raise AuthorityUnavailable("local OS administrator credential is unavailable") from exc
        self.core._require(credential, action, namespace)
        return credential

    def installed_peer_certificate_sha256(
            self, profile_id: str, installation_id: str, namespace: str) -> str:
        self.require_offline_admin_maintenance()
        matches = {
            certificate for (certificate, profile, _), mapped
            in self.namespace_bindings_v2.items()
            if (profile == profile_id and mapped == namespace
                and self.installations_v2[(certificate, profile)].installation_id
                == installation_id)
        }
        if len(matches) != 1:
            raise AuthorityUnavailable("installed Owner peer identity is absent or ambiguous")
        return matches.pop()

    async def start(self) -> asyncio.AbstractServer:
        with self._maintenance_lock:
            if self._closed or self._starting or self._listener is not None:
                raise AuthorityUnavailable("Authority daemon is not stopped")
            self._starting = True
        try:
            listener = await self.server.start(
                self.config.bind_host, self.config.bind_port, self.config.tls)
            with self._maintenance_lock:
                closed = self._closed
                if not closed:
                    self._listener = listener
            if closed:
                listener.close()
                await listener.wait_closed()
                raise AuthorityUnavailable("Authority daemon closed during startup")
            return listener
        except BaseException:
            await self.aclose()
            raise
        finally:
            with self._maintenance_lock:
                self._starting = False

    async def aclose(self) -> None:
        with self._maintenance_lock:
            if self._closed:
                return
            self._closed = True
            listener = self._listener
            self._listener = None
        if listener is not None:
            listener.close()
            await listener.wait_closed()
        # Refuse to close Core beneath a still-running supervisor action.
        for service in getattr(self.server, "_d12_installation_lifecycle_services_v1", {}).values():
            await asyncio.to_thread(service.close)
        try:
            await self.server.aclose()
        finally:
            if self.c09_maintenance is not None:
                self.c09_maintenance.graph.close()
            self.core.close()
            for journal in self.execution.values():
                journal.close()
            self.deletion.close()
            if self._lock_handle is not None:
                try:
                    _release_instance_lock(self._lock_handle)
                finally:
                    self._lock_handle = None


def _compose_installed_authority_server_v1(config, paths, core, deletion, execution, reverse):
    fences = AuthorityV2FenceStore(core._db, create=False, lock=core._lock)
    natural = config.natural_model_authorities_v2 or {}
    installed_clock_limits = {}
    for item in natural.values():
        installation = config.installations_v2[item.observer_peer]
        source_id = installation.source_id
        installed_clock_limits[source_id] = min(
            installed_clock_limits.get(source_id, installation.max_utc_error_seconds),
            installation.max_utc_error_seconds)

    def installed_clock_reading() -> AuthorityClockReadingV2:
        provider = config.clock_provider
        if provider is None:
            raise AuthorityUnavailable("installed Authority clock is unavailable")
        reading = provider()
        if (type(reading) is not AuthorityClockReadingV2
                or not reading.healthy):
            raise AuthorityUnavailable("installed Authority clock is unhealthy")
        maximum_error = installed_clock_limits.get(reading.source_id)
        if natural and (maximum_error is None
                        or reading.utc_error_seconds > maximum_error):
            raise AuthorityUnavailable("installed Authority clock source or error bound differs")
        return reading

    if natural:
        reading = installed_clock_reading()
        if any(reading.source_id != config.installations_v2[
                item.observer_peer].source_id for item in natural.values()):
            raise AuthorityUnavailable("installed model clock source or error bound differs")
    installed_utc_clock = (
        (lambda: datetime.fromtimestamp(installed_clock_reading().utc_seconds,
                                        tz=timezone.utc))
        if natural else config.utc_clock)
    namespace_map = {}
    for (_peer, _profile, graph_namespace), authority_namespace in (
            config.namespace_bindings_v2.items()):
        previous = namespace_map.setdefault(
            authority_namespace, graph_namespace)
        if previous != graph_namespace:
            raise AuthorityUnavailable("installed Graph namespace mapping differs")
    if set(namespace_map) != set(execution):
        raise AuthorityUnavailable("installed dispatch namespace coverage differs")
    dispatch_verifier = (
        make_installed_v2_graph_dispatch_verifier(
            paths["graph"], namespace_map,
            lambda: installed_clock_reading().utc_seconds)
        if config.clock_provider is not None else None
    )
    dispatch_verifiers = (
        {namespace: dispatch_verifier for namespace in execution}
        if dispatch_verifier is not None else {})
    services = {
        namespace: AuthorityV2FenceService(
            core=core, fences=fences, deletion=deletion,
            execution=journal, namespace=namespace,
            v2_dispatch_verifier=dispatch_verifiers.get(namespace))
        for namespace, journal in execution.items()
    }
    if config.c09_maintenance_factory is not None:
        from .c09_installed_factory_v1 import InstalledC09MaintenanceFactoryV1
        from .installer_genesis_v1 import install_first_graph_provision_composition_v1
        if type(config.c09_maintenance_factory) is not InstalledC09MaintenanceFactoryV1:
            raise AuthorityUnavailable("first Graph provisioning actual installed maintenance registry is unavailable")
        for service in services.values():
            install_first_graph_provision_composition_v1(service, config, config.c09_maintenance_factory.registry)
    models = {}
    if natural:
        model_store = AuthorityV2ModelEgressStore(
            core._db, create=False, lock=core._lock)
        for namespace, item in natural.items():
            source_id = config.installations_v2[item.observer_peer].source_id

            def paired_clock(expected_source=source_id):
                reading = installed_clock_reading()
                if reading.source_id != expected_source:
                    raise AuthorityUnavailable("model clock source changed")
                return reading.utc_seconds, reading.epoch

            history_verifier = None
            if item.installation_bundle is not None:
                from .d13_natural_frame_verifier_v1 import build_authority_d13_natural_frame_verifier_v1
                history_verifier = build_authority_d13_natural_frame_verifier_v1(
                    bundle=item.installation_bundle, d11_issuer=item.d11_issuer, authority_store=model_store)
            verifier = PinnedCurrentModelEgressGraphVerifier(
                paths["graph"], d11_issuer=item.d11_issuer,
                trusted_now_utc=lambda: installed_clock_reading().utc_seconds,
                trusted_paired_clock=paired_clock, natural_history_verifier=history_verifier)
            models[namespace] = AuthorityV2ModelEgressService(
                model_store, services[namespace], graph_verifier=verifier,
                admin_model_policy=item.workflows)
    pairings = AuthorityOwnerPairingSource(
        core, utc_clock=installed_utc_clock, create=False)
    sessions = AuthorityV2OwnerSessionStore(
        core, utc_clock=installed_utc_clock,
        current_pairing_source=pairings, create=False)
    server = compose_owner_deployment(
        core=core, v2_fences=services, graph_db_path=paths["graph"],
        utc_clock=installed_utc_clock, identity=pairings,
        administrator_authorizer=config.administrator_authorizer,
        publisher_manifest_verifier=config.publisher_manifest_verifier,
        installations_v2=config.installations_v2,
        namespace_bindings_v2=config.namespace_bindings_v2,
        v2_final_handoff_reverse=reverse,
        v2_final_handoff_issuers=config.reverse_handoff_issuers,
        v2_dispatch_verifiers=dispatch_verifiers,
        v2_model_egress=models,
        model_observers_v2={namespace: item.observer_peer
                            for namespace, item in natural.items()},
        accounting_observers_v2={namespace: item.observer_peer
                                 for namespace, item in natural.items()},
        worker_result_readers_v2={namespace: item.observer_peer
                                  for namespace, item in natural.items()},
        worker_result_fact_committers_v2=config.worker_result_fact_committers_v2,
        self_identity_readers_v2=config.self_identity_readers_v2,
        host_onebot_observations_v2=config.host_onebot_observations_v2,
        model_result_source_purposes={namespace: "expression"
                                      for namespace in natural},
        clock_provider=installed_clock_reading if natural else None,
        owner_sessions=sessions, create_owner_schema=False)
    with core._tx() as db:
        scoped_table = db.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' "
            "AND name='authority_scoped_erasure_v2'").fetchone() is not None
        scoped_namespaces = ({row[0] for row in db.execute(
            "SELECT namespace FROM authority_scoped_erasure_v2")}
            if scoped_table else set())
    for (peer, profile, _graph_namespace), namespace in config.namespace_bindings_v2.items():
        if namespace not in scoped_namespaces:
            continue
        installation = config.installations_v2[(peer, profile)]
        if (namespace, installation.installation_id) in server._current_erasure_prepares:
            continue
        scoped = AuthorityV2ScopedErasureStore(
            core=core, fences=fences, deletion=deletion,
            execution=execution[namespace], namespace=namespace)
        recovery = AuthorityV2DeletionPendingRecovery(
            core=core, fences=fences, deletion=deletion,
            execution=execution[namespace], namespace=namespace,
            scoped_store=scoped)
        erasure = CurrentErasureAuthority(
            recovery, fence_service=services[namespace],
            owner_sessions=sessions, owner_tickets=server._v2_owner_tickets,
            installation_id=installation.installation_id,
            scoped_store=scoped, graph_db_path=paths["graph"])
        server.install_current_erasure_prepare(
            namespace, installation.installation_id, erasure)
        server.install_current_accepted_erasure_read(
            namespace, installation.installation_id,
            CurrentAcceptedErasureReadService(
                fence_service=services[namespace],
                owner_tickets=server._v2_owner_tickets,
                scoped_store=scoped))
    from .d04_appraisal_result_service_v3 import AuthorityD04AppraisalResultServiceV3
    def appraisal_trusted_now():
        sample = installed_clock_reading()
        return sample.utc_seconds + sample.utc_error_seconds

    for namespace, model_installation in natural.items():
        if model_installation.workflows.appraisal is None:
            continue
        peer = model_installation.observer_peer
        installed = config.installations_v2[peer]
        server.install_d04_appraisal_result_reader_v3(namespace, AuthorityD04AppraisalResultServiceV3(
            store=models[namespace]._store, fences=services[namespace], graph_db_path=paths["graph"],
            d11_issuer=model_installation.d11_issuer, installation_id=installed.installation_id,
            read_subject="mtls:sha256:" + peer[0], holder=installed.administrator_holder,
            trusted_now_utc=appraisal_trusted_now))
    from .d07_cognition_result_service_v1 import AuthorityD07CognitionResultServiceV1
    for namespace, model_installation in natural.items():
        if model_installation.workflows.d07_cognition is None:
            continue
        peer = model_installation.observer_peer
        installed = config.installations_v2[peer]
        server.install_d07_cognition_result_reader_v1(namespace, AuthorityD07CognitionResultServiceV1(
            store=models[namespace]._store, fences=services[namespace], graph_db_path=paths["graph"],
            d11_issuer=model_installation.d11_issuer, installation_id=installed.installation_id,
            read_subject="mtls:sha256:" + peer[0], holder=installed.administrator_holder,
            trusted_now_utc=appraisal_trusted_now))
    c04_v2 = config.c04_installations_v2 or {}
    c04_v3 = getattr(config, "c04_installations_v3", None) or {}
    for namespace in sorted(set(c04_v2) | set(c04_v3)):
        installed = {}
        credential = config.local_administrator_credential(
            "c04_execute", namespace)
        if namespace in c04_v2:
            from .installed_c04_executor_v2 import (
                compose_installed_c04_executor_v2,
            )
            installation = c04_v2[namespace]
            key = paths["c04_key:" + namespace].read_bytes()
            if len(key) != 32:
                raise AuthorityUnavailable("C04 protected component key is unavailable")
            installed["d06.association_activation.v2"] = (
                compose_installed_c04_executor_v2(
                    bridge=server._v2_execution[namespace],
                    namespace=namespace_map[namespace],
                    graph_db_path=paths["graph"],
                    package_root=installation.package_root,
                    trusted_manifest_sha256=installation.formal_manifest_sha256,
                    component_signing_key=key,
                    credential=credential,
                    install_bridge_verifier=False))
        if namespace in c04_v3:
            from .installed_c04_executor_v3 import (
                compose_installed_c04_executor_v3,
            )
            installation = c04_v3[namespace]
            key = paths["c04_v3_key:" + namespace].read_bytes()
            if len(key) != 32:
                raise AuthorityUnavailable("C04 V3 protected component key is unavailable")
            c04_model_installation = natural.get(namespace)
            if c04_model_installation is None:
                raise AuthorityUnavailable("C04 V3 independent D02/D11 issuer installation is absent")
            installed["d06.association_activation.v3"] = (
                compose_installed_c04_executor_v3(
                    bridge=server._v2_execution[namespace],
                    namespace=namespace_map[namespace],
                    graph_db_path=paths["graph"],
                    package_root=installation.package_root,
                    trusted_manifest_sha256=installation.formal_manifest_sha256,
                    component_signing_key=key,
                    credential=credential,
                    resource_issuer=c04_model_installation.d11_issuer.resource_issuer,
                    budget_issuer=c04_model_installation.d11_issuer,
                    install_bridge_verifier=False))

        core.install_execution_redaction_c04_services(
            namespace, {algorithm: pair[0]
                        for algorithm, pair in installed.items()})

        def verify_c04_version(binding, claim, terminal, *, versions=installed):
            pair = versions.get(binding.algorithm_ref)
            return (pair is not None and
                    pair[0].installed_algorithm_id == binding.algorithm_ref and
                    pair[0].verify_installed_terminal(
                        binding, claim, terminal) is True)

        server._v2_execution[namespace].install_internal_work_terminal_verifier(
            verify_c04_version)
        if "d06.association_activation.v2" in installed:
            server.install_c04_executor_v2(
                namespace, *installed["d06.association_activation.v2"])
        if "d06.association_activation.v3" in installed:
            server.install_c04_executor_v3(
                namespace, *installed["d06.association_activation.v3"])
            model_installation = natural.get(namespace)
            if model_installation is not None:
                from .d04_numeric_service_v3 import AuthorityD04NumericServiceV3
                from ..host.installed_d04_numeric_build_v3 import read_installed_d04_numeric_identity_v3
                import hashlib
                import hmac
                identities = {config.installations_v2[(peer, profile)].installation_id
                    for (peer, profile, _), mapped in config.namespace_bindings_v2.items()
                    if mapped == namespace}
                if len(identities) != 1:
                    raise AuthorityUnavailable("D04 numeric namespace needs one paired executor installation")
                historical_recipe = None
                if model_installation.installation_bundle is not None:
                    from ..host.installed_package_history_v1 import build_installed_authority_d04_recipe_history_v1
                    historical_recipe = build_installed_authority_d04_recipe_history_v1(
                        model_installation.installation_bundle, c04_v3[namespace].package_root)
                numeric_key = hmac.new(paths["c04_v3_key:" + namespace].read_bytes(),
                    b"sylanne.authority.d04-numeric-signing.v3", hashlib.sha256).digest()
                numeric_identity = read_installed_d04_numeric_identity_v3(
                    c04_v3[namespace].package_root, c04_v3[namespace].formal_manifest_sha256)
                server.install_d04_numeric_service_v3(namespace, AuthorityD04NumericServiceV3(
                    bridge=server._v2_execution[namespace], owner_tickets=server._v2_owner_tickets,
                    namespace=namespace_map[namespace], installation_id=next(iter(identities)),
                    graph_db_path=paths["graph"], resource_issuer=model_installation.d11_issuer.resource_issuer,
                    budget_issuer=model_installation.d11_issuer,
                    credential=credential, signing_key=numeric_key,
                    trusted_now_utc=lambda: installed_clock_reading().utc_seconds,
                    installed_identity=numeric_identity, historical_recipe_reader=historical_recipe))
                from .d04_series_service_v1 import AuthorityD04SeriesServiceV1
                server._d04_series_services_v1[namespace] = AuthorityD04SeriesServiceV1(
                    numeric_service=server._d04_numeric_services_v3[namespace])
                core.install_execution_redaction_d04_series_service_v1(
                    namespace, server._d04_series_services_v1[namespace])
                from .d04_root_execution_service_v3 import AuthorityD04RootExecutionServiceV3
                from ..host.installed_d04_root_build_v3 import read_installed_d04_root_identity_v3
                root_identity = read_installed_d04_root_identity_v3(
                    c04_v3[namespace].package_root, c04_v3[namespace].formal_manifest_sha256)
                root_key = hmac.new(paths["c04_v3_key:" + namespace].read_bytes(),
                    b"sylanne.authority.d04-root-signing.v3", hashlib.sha256).digest()
                root_service = AuthorityD04RootExecutionServiceV3(
                    bridge=server._v2_execution[namespace], owner_tickets=server._v2_owner_tickets,
                    namespace=namespace_map[namespace], installation_id=next(iter(identities)),
                    graph_db_path=paths["graph"], resource_issuer=model_installation.d11_issuer.resource_issuer,
                    budget_issuer=model_installation.d11_issuer, credential=credential, signing_key=root_key,
                    trusted_now_utc=lambda: installed_clock_reading().utc_seconds,
                    installed_identity=root_identity, historical_recipe_reader=historical_recipe)
                if not hasattr(server, "_d04_root_services_v3"):
                    server._d04_root_services_v3 = {}
                if namespace in server._d04_root_services_v3:
                    raise AuthorityUnavailable("D04 root service already installed")
                server._d04_root_services_v3[namespace] = root_service
                core.install_execution_redaction_d04_root_service_v3(namespace, root_service)
    return pairings, server


def open_authority_daemon(config: AuthorityDeploymentConfig) -> AuthorityDaemon:
    """Reopen an installed Authority; never initialize or replace a missing DB."""
    if type(config) is not AuthorityDeploymentConfig:
        raise TypeError("installer-owned AuthorityDeploymentConfig is required")
    lock_handle = _instance_lock(_installed_file(config.instance_lock, "instance lock"))
    deletion = None
    execution = {}
    core = None
    try:
        config, control = _resolve_current_c09_config(config, lock_handle)
        if config.c09_storage_v2 is not None:
            return AuthorityFactualDaemonV2(config, lock_handle, control)
        paths = _preflight(config)
        # Fail on unusable TLS material before touching persistent SQLite state.
        config.tls.ssl_context()
        reverse = {namespace: ReverseGraphClaimClient(profile)
                   for namespace, profile in config.reverse_handoff_profiles.items()}
        deletion = AuthorityV2DeletionGuard(paths["deletion"])
        for namespace, installation in config.execution_journals.items():
            execution[namespace] = AuthorityV2ExecutionJournal(
                paths["execution:" + namespace], namespace=namespace,
                journal_id=installation.journal_id, create=False,
                installed_storage_reader=control)
        verifiers = config.core_verifier_factory(
            deletion, MappingProxyType(dict(execution)))
        if type(verifiers) is not AuthorityCoreVerifiers:
            raise AuthorityUnavailable("installer must supply all trusted Core verifiers")
        core = AuthorityServiceCore(
            paths["authority"], authorizer=config.core_authorizer,
            deletion_verifier=verifiers.deletion,
            execution_verifier=verifiers.execution,
            effect_verifier=verifiers.effect,
            dispatch_verifier=verifiers.dispatch, create=False)
        if control is not None:
            with core._lock:
                if core._id(core._db) != control.authority_id:
                    raise AuthorityUnavailable("C09 selected Core Authority identity differs")
            core.install_current_c09_storage_reader_v1(reader=control)
        pairings, server = _compose_installed_authority_server_v1(
            config, paths, core, deletion, execution, reverse)
        daemon = AuthorityDaemon(config, lock_handle, core, deletion, execution,
                                 pairings, server)
        if control is not None:
            from .c09_storage_maintenance_v1 import InstalledC09WriterGateV1, InstalledC09MaintenanceV1
            gate = InstalledC09WriterGateV1(control=control)
            maintenance = config.c09_maintenance_factory(daemon=daemon, control=control, gate=gate)
            if (type(maintenance) is not InstalledC09MaintenanceV1
                    or maintenance.control is not control or maintenance.gate is not gate
                    or maintenance.core is not core):
                raise AuthorityUnavailable("installed C09 maintenance composition differs")
            control.install_applied_reader_v1(maintenance.close_apply_service)
            daemon.c09_control, daemon.c09_gate, daemon.c09_maintenance = control, gate, maintenance
            server.install_current_c09_maintenance_v1(maintenance)
            from .d12_owner_storage_admission_v1 import InstalledD12OwnerStorageAdmissionServiceV1
            from .d12_target_owner_rpc_v1 import install_d12_owner_storage_service_v1
            location = maintenance.current_source_location
            namespace = location.namespace
            holders = {config.installations_v2[(peer, profile)].administrator_holder
                for (peer, profile, graph_namespace), bound_namespace in config.namespace_bindings_v2.items()
                if bound_namespace == namespace and graph_namespace == maintenance.namespace_id
                and config.installations_v2[(peer, profile)].installation_id == control.installation_id}
            if len(holders) != 1:
                raise AuthorityUnavailable("current storage needs one exact installed namespace holder")
            storage_owner = InstalledD12OwnerStorageAdmissionServiceV1(
                fences=server._v2_fences[namespace], owner_tickets=server._v2_owner_tickets,
                graph_db_path=location._graph_db_path, namespace_id=maintenance.namespace_id,
                installation_id=control.installation_id, holder=next(iter(holders)),
                control=control, close_apply=maintenance.close_apply_service)
            install_d12_owner_storage_service_v1(server, storage_owner)
            model = server._v2_model_egress.get(namespace)
            if model is not None:
                model.install_current_source_location_v1(location)
            self_identity = server._v2_self_identity.get(namespace)
            if self_identity is not None:
                self_identity.install_current_source_location_v1(location, storage_owner)
            for registry in (server._d04_numeric_services_v3, getattr(server, "_d04_root_services_v3", {})):
                numeric = registry.get(namespace)
                if numeric is not None:
                    numeric.install_storage_owner_service_v1(storage_owner)
            offline_installation = (config.natural_model_authorities_v2 or {}).get(namespace)
            offline_bundle = None if offline_installation is None else offline_installation.installation_bundle
            if offline_bundle is not None and server._clock_provider is not None:
                import hashlib
                import hmac
                from .d10_contact_policy_service_v1 import InstalledD10ContactPolicyServiceV1
                contact_service = InstalledD10ContactPolicyServiceV1(
                    fences=server._v2_fences[namespace], owner_tickets=server._v2_owner_tickets,
                    owner_service=getattr(server, "_d12_target_owner_services_v1", {}).get(
                        (namespace, control.installation_id), storage_owner),
                    namespace=maintenance.namespace_id, installation_id=control.installation_id,
                    signing_key=hmac.new(offline_bundle.d11_signing_key,
                        b"sylanne.authority.d10-contact-policy-signing.v1", hashlib.sha256).digest(),
                    trusted_now_utc=lambda: server._clock_provider().utc_seconds, create=True)
                server._d10_contact_policy_services_v1[(namespace, control.installation_id)] = contact_service
                if offline_bundle.model_workflows.contact_generation is not None:
                    from .contact_model_result_service_v1 import InstalledContactModelResultServiceV1
                    model._graph_verifier.install_contact_policy_service_v1(contact_service)
                    from ..host.model_workflows_v3 import AdminModelWorkflowsV3
                    if type(offline_bundle.model_workflows) is AdminModelWorkflowsV3:
                        from .contact_model_result_service_v2 import InstalledContactModelResultServiceV2 as InstalledContactModelResultServiceV1
                        install_contact_reader = server.install_contact_model_result_reader_v2
                    else:
                        install_contact_reader = server.install_contact_model_result_reader_v1
                    install_contact_reader(namespace, InstalledContactModelResultServiceV1(
                        store=model._store, fences=server._v2_fences[namespace],
                        graph_db_path=location._graph_db_path, d11_issuer=offline_installation.d11_issuer,
                        installation_id=control.installation_id,
                        read_subject="mtls:sha256:" + offline_installation.observer_peer[0],
                        holder=next(iter(holders)), trusted_now_utc=appraisal_trusted_now,
                        source_location=location, contact_policy_service=contact_service))
            if (offline_bundle is not None and "d10.offline_observed_tick.v1" in
                    offline_bundle.installation_policy.root_grant.allowed_work_kinds):
                from .d11_offline_tick_service_v1 import AuthorityD11OfflineTickServiceV1
                import hashlib
                import hmac
                if server._clock_provider is None:
                    raise AuthorityUnavailable("offline tick requires actual installed trusted clock")
                offline_service = AuthorityD11OfflineTickServiceV1(
                    bridge=server._v2_execution[namespace], owner_tickets=server._v2_owner_tickets,
                    namespace=maintenance.namespace_id, installation_id=control.installation_id,
                    manifest_digest=offline_bundle.installation_policy.manifest_digest,
                    graph_db_path=location._graph_db_path, issuer=offline_installation.d11_issuer,
                    resource_issuer=offline_installation.d11_issuer.resource_issuer,
                    credential=config.local_administrator_credential("execution", namespace),
                    signing_key=hmac.new(offline_bundle.d11_signing_key,
                        b"sylanne.authority.d11-offline-signing.v1", hashlib.sha256).digest(),
                    trusted_now_utc=lambda: server._clock_provider().utc_seconds,
                    owner_service=getattr(server, "_d12_target_owner_services_v1", {}).get(
                        (namespace, control.installation_id), storage_owner))
                if not hasattr(server, "_d11_offline_tick_services_v1"):
                    server._d11_offline_tick_services_v1 = {}
                if namespace in server._d11_offline_tick_services_v1:
                    raise AuthorityUnavailable("offline tick service already installed")
                server._d11_offline_tick_services_v1[namespace] = offline_service
                core.install_execution_redaction_d11_offline_service_v1(namespace, offline_service)
            if (offline_bundle is not None and "d10.life.source_note.v1" in
                    offline_bundle.installation_policy.root_grant.allowed_work_kinds):
                from .d11_life_service_v1 import AuthorityD11LifeServiceV1
                import hashlib
                import hmac
                life_installation = (config.c04_installations_v3 or {}).get(namespace)
                if life_installation is None or server._clock_provider is None:
                    raise AuthorityUnavailable("Life requires actual installed package and trusted clock")
                life = AuthorityD11LifeServiceV1(bridge=server._v2_execution[namespace],
                    owner_tickets=server._v2_owner_tickets, namespace=maintenance.namespace_id,
                    installation_id=control.installation_id,
                    manifest_digest=life_installation.formal_manifest_sha256,
                    graph_db_path=location._graph_db_path, issuer=offline_installation.d11_issuer,
                    resource_issuer=offline_installation.d11_issuer.resource_issuer,
                    credential=config.local_administrator_credential("execution", namespace),
                    signing_key=hmac.new(offline_bundle.d11_signing_key,
                        b"sylanne.authority.d11-life-signing.v1", hashlib.sha256).digest(),
                    trusted_now_utc=lambda: server._clock_provider().utc_seconds,
                    owner_service=getattr(server, "_d12_target_owner_services_v1", {}).get(
                        (namespace, control.installation_id), storage_owner), package_root=life_installation.package_root, body_quote_authority=config.c09_maintenance_factory.body_authority)
                server._d11_life_services_v1[namespace] = life
                core.install_execution_redaction_d11_life_service_v1(namespace, life)
            current = control.read_verified_current_storage_v1()
            if current.stage in {"READY", "RELEASED"}:
                current.require_current("business")
        return daemon
    except BaseException:
        if core is not None:
            core.close()
        for journal in execution.values():
            journal.close()
        if deletion is not None:
            deletion.close()
        _release_instance_lock(lock_handle)
        raise


__all__ = ("AuthorityDaemon", "open_authority_daemon")
