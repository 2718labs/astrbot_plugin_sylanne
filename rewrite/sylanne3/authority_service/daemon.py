"""Cold-open and lifecycle for an installer-owned Authority process.

This module does not load executable policy from disk. The service
installer must construct ``AuthorityDeploymentConfig`` with its trusted OS
identity, publisher, and journal verification adapters before calling open.
"""

from __future__ import annotations

import asyncio
from contextlib import closing, contextmanager
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
import sqlite3
import threading
from queue import Queue
from concurrent.futures import Future
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


def _preflight(config: AuthorityDeploymentConfig, *, composition=None) -> dict[str, Path]:
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
    if composition is not None and composition.selected is not None:
        composition.require_current()
        return paths
    with closing(sqlite3.connect(paths["authority"].as_uri() + "?mode=ro", uri=True)) as db:
        db.execute("PRAGMA query_only=ON")
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
        from .c09_habit_policy_rows_v1 import require_habit_core_schema_v1
        require_habit_core_schema_v1(db)
        from .installation_management_v1 import TABLES as management_tables, TRIGGERS as management_triggers
        management_schema = {**management_tables, **management_triggers}
        if set(management_tables) & tables:
            for name, ddl in management_schema.items():
                if db.execute("SELECT sql FROM sqlite_master WHERE name=?", (name,)).fetchone() != (ddl,):
                    raise AuthorityUnavailable("installed management schema differs")
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
        control.install_selected_producer_config_v3(config)
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
    control.install_selected_producer_config_v3(config)
    return config, control


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
        """A composed business daemon already passed the private bootstrap qualification."""
        self._resolved_storage_composition_v3.require_current()
        return False

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
            if await self.resume_cold_maintenance_v1():
                from .contract import AuthorityColdRestartRequired
                raise AuthorityColdRestartRequired("C09 switched actual storage; restart before opening business RPCs")
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


def _compose_installed_fence_components_v3(config, paths, core, deletion, execution):
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
    return fences, services, natural, installed_clock_reading, installed_utc_clock, dispatch_verifiers, namespace_map


def _compose_installed_authority_server_v1(config, paths, core, deletion, execution, reverse):
    fences, services, natural, installed_clock_reading, installed_utc_clock, dispatch_verifiers, namespace_map = (
        _compose_installed_fence_components_v3(config, paths, core, deletion, execution))
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
                from .d13_natural_frame_verifier_v6 import build_authority_d13_natural_frame_verifier_v6
                from ..host.model_workflows_v6 import AdminModelWorkflowsV6
                from ..model_broker.natural_reply_history_v6 import TEMPLATE_VERSION as V6_TEMPLATE
                workflows=item.installation_bundle.model_workflows
                actual_v6=(type(workflows) is AdminModelWorkflowsV6 and workflows.natural_generation is not None
                    and workflows.natural_generation.template_version==V6_TEMPLATE)
                from .d13_natural_frame_verifier_v7 import build_authority_d13_natural_frame_verifier_v7
                from ..host.model_workflows_v7 import AdminModelWorkflowsV7
                from ..host.model_workflows_v8 import AdminModelWorkflowsV8
                from ..host.model_workflows_v9 import AdminModelWorkflowsV9
                from ..model_broker.natural_reply_history_v7 import TEMPLATE_VERSION as V7_TEMPLATE
                actual_v7=(type(workflows) in {AdminModelWorkflowsV7, AdminModelWorkflowsV8, AdminModelWorkflowsV9} and workflows.natural_generation is not None
                    and workflows.natural_generation.template_version==V7_TEMPLATE)
                history_factory=(build_authority_d13_natural_frame_verifier_v7 if actual_v7 else
                    build_authority_d13_natural_frame_verifier_v6 if actual_v6 else build_authority_d13_natural_frame_verifier_v1)
                history_verifier=history_factory(bundle=item.installation_bundle,d11_issuer=item.d11_issuer,authority_store=model_store)
            verifier = PinnedCurrentModelEgressGraphVerifier(
                paths["graph"], d11_issuer=item.d11_issuer,
                trusted_now_utc=lambda: installed_clock_reading().utc_seconds,
                trusted_paired_clock=paired_clock, natural_history_verifier=history_verifier,
                artifact_draft_bundle=item.installation_bundle)
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
    for namespace, model_service in models.items():
        history = model_service._graph_verifier._natural_history
        if history is not None:
            history.install_actual_execution_bridge_v3(server._v2_execution[namespace])
    from .installation_management_v1 import InstallationManagementServiceV1
    from .installation_management_rpc_v1 import install_installation_management_v1
    with core._tx() as db:
        installed_management = (db.execute("SELECT installation_id,namespace,authority_profile FROM "
            "authority_installation_management_v1").fetchall()
            if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND "
                "name='authority_installation_management_v1'").fetchone() else [])
    for installation_id, namespace, profile in installed_management:
        if (namespace not in services or not any(
                peer_profile == profile and item.installation_id == installation_id
                for (_, peer_profile), item in config.installations_v2.items())):
            raise AuthorityUnavailable("management metadata differs from installed peer")
        install_installation_management_v1(server, InstallationManagementServiceV1(
            core, sessions, namespace=namespace, installation_id=installation_id,
            authority_profile=profile, utc_clock=installed_utc_clock,
            administrator_authorizer=config.administrator_authorizer))
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
            trusted_now_utc=appraisal_trusted_now, installed_bundle=model_installation.installation_bundle))
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
                    self_identity_read_credential=config.local_administrator_credential(
                        "c04_self_identity_read", namespace),
                    install_bridge_verifier=False))

        if "d06.association_activation.v3" in installed:
            installed["d06.association_activation.direct_seed.v4"] = installed["d06.association_activation.v3"]

        core.install_execution_redaction_c04_services(
            namespace, {algorithm: pair[0]
                        for algorithm, pair in installed.items()})

        def verify_c04_version(binding, claim, terminal, *, versions=installed):
            pair = versions.get(binding.algorithm_ref)
            return (pair is not None and
                    pair[0].accepts_installed_binding(binding) and
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


def _install_current_life_model_readers_v1(server,*,namespace,installation,storage_owner,location):
    """Attach the existing exact Life readers to the installed selected Core graph."""
    import hmac
    from ..host.authority_profile import AdminInstallationBundle
    from ..domains.d02.body_quote_original import D02BodyQuoteAuthority
    from ..runtime.d06_structured_experience_v1 import InstalledD06StructuredExperienceReadersV1
    bundle=installation.installation_bundle
    if type(bundle)is not AdminInstallationBundle:
        raise AuthorityUnavailable('Life model readers require the actual installed bundle')
    workflows=bundle.model_workflows
    if workflows.version<3:return
    if workflows.life_content is None and workflows.life_numeric is None:return
    model=server._v2_model_egress.get(namespace)
    worker=server._v2_worker_model_result_reads.get(namespace)
    if (model is None or worker is None or server._clock_provider is None
            or bundle.installation_policy.namespace!=storage_owner.namespace_id
            or bundle.installation_policy.authority_namespace!=namespace
            or bundle.installation_policy.installation_id!=storage_owner.installation_id
            or model._graph_verifier._artifact_draft_bundle is not bundle
            or model._graph_verifier._issuer is not installation.d11_issuer
            or model._graph_verifier._path!=location._graph_db_path
            or storage_owner.graph_path!=location._graph_db_path):
        raise AuthorityUnavailable('Life model readers crossed the actual installed model/Owner/Graph identity')
    key=hmac.digest(bundle.d02_signing_key,b'sylanne3.d02.body_quote_original.v1\0'
        +bundle.installation_policy.installation_id.encode('utf-8'),'sha256')
    readers=InstalledD06StructuredExperienceReadersV1(issuer=installation.d11_issuer,
        resource_issuer=installation.d11_issuer.resource_issuer,body_quote_authority=D02BodyQuoteAuthority(key))
    def trusted_upper():
        reading=server._clock_provider()
        return reading.utc_seconds+reading.utc_error_seconds
    shared=dict(store=model._store,fences=server._v2_fences[namespace],graph_db_path=location._graph_db_path,
        d11_issuer=installation.d11_issuer,installation_id=storage_owner.installation_id,
        read_subject=worker._read_subject,holder=storage_owner.holder,trusted_now_utc=trusted_upper,
        source_location=location)
    if workflows.life_content is not None:
        from .internal_life_model_graph_v2 import InstalledInternalLifeModelGraphReaderV2
        from .internal_life_model_result_service_v2 import InstalledInternalLifeModelResultServiceV2
        reader=InstalledInternalLifeModelGraphReaderV2(owner_storage=storage_owner,structured_readers=readers,
            bundle=bundle,read_subject=worker._read_subject)
        model._graph_verifier.install_internal_life_reader_v2(reader)
        server.install_internal_life_model_result_reader_v2(namespace,
            InstalledInternalLifeModelResultServiceV2(**shared,graph_reader=reader))
    if workflows.life_numeric is not None:
        from .current_life_numeric_v1 import InstalledLifeNumericModelGraphReaderV1
        from .life_numeric_model_result_service_v1 import InstalledLifeNumericModelResultServiceV1
        reader=InstalledLifeNumericModelGraphReaderV1(owner_storage=storage_owner,structured_readers=readers,
            bundle=bundle,read_subject=worker._read_subject)
        model._graph_verifier.install_life_numeric_reader_v1(reader)
        server.install_life_numeric_model_result_reader_v1(namespace,
            InstalledLifeNumericModelResultServiceV1(**shared,graph_reader=reader))


def _compose_business_daemon_v3(config, lock_handle, composition):
    """Reopen an installed Authority; never initialize or replace a missing DB."""
    composition.require_current()
    deletion = None
    execution = {}
    core = None
    try:
        control=composition.control
        paths = _preflight(config, composition=composition)
        store_kwargs=composition.store_kwargs()
        # Fail on unusable TLS material before touching persistent SQLite state.
        config.tls.ssl_context()
        reverse = {namespace: ReverseGraphClaimClient(profile)
                   for namespace, profile in config.reverse_handoff_profiles.items()}
        deletion = AuthorityV2DeletionGuard(paths["deletion"], **store_kwargs)
        for namespace, installation in config.execution_journals.items():
            execution[namespace] = AuthorityV2ExecutionJournal(
                paths["execution:" + namespace], namespace=namespace,
                journal_id=installation.journal_id, create=False,
                installed_storage_reader=control, **store_kwargs)
        verifiers = config.core_verifier_factory(
            deletion, MappingProxyType(dict(execution)))
        if type(verifiers) is not AuthorityCoreVerifiers:
            raise AuthorityUnavailable("installer must supply all trusted Core verifiers")
        core = AuthorityServiceCore(
            paths["authority"], authorizer=config.core_authorizer,
            deletion_verifier=verifiers.deletion,
            execution_verifier=verifiers.execution,
            effect_verifier=verifiers.effect,
            dispatch_verifier=verifiers.dispatch, create=False, **store_kwargs)
        if control is not None:
            with core._lock:
                if core._id(core._db) != control.authority_id:
                    raise AuthorityUnavailable("C09 selected Core Authority identity differs")
            core.install_current_c09_storage_reader_v1(reader=control)
        pairings, server = _compose_installed_authority_server_v1(
            config, paths, core, deletion, execution, reverse)
        daemon = AuthorityDaemon(config, lock_handle, core, deletion, execution,
                                 pairings, server)
        daemon._resolved_storage_composition_v3=composition
        if control is not None:
            from .c09_storage_maintenance_v1 import InstalledC09WriterGateV1, InstalledC09MaintenanceV1
            gate = composition.peer_gate
            if type(gate) is not InstalledC09WriterGateV1 or gate._installed_config_v3 is not config:
                raise AuthorityUnavailable("actual qualified selected peer registry Gate required before business composition")
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
            from .current_authority_graph_read_v3 import install_authority_graph_read_service_registry_v3
            install_authority_graph_read_service_registry_v3(server,namespace=namespace,source_location=location)
            if model is not None:
                from .owner_location_read_v3 import install_d07_model_seal_owner_observer_v3
                install_d07_model_seal_owner_observer_v3(server, storage_owner)
            for registry in (server._d04_numeric_services_v3, getattr(server, "_d04_root_services_v3", {})):
                numeric = registry.get(namespace)
                if numeric is not None:
                    numeric.install_storage_owner_service_v1(storage_owner)
            offline_installation = (config.natural_model_authorities_v2 or {}).get(namespace)
            offline_bundle = None if offline_installation is None else offline_installation.installation_bundle
            if offline_bundle is not None:
                _install_current_life_model_readers_v1(server,namespace=namespace,installation=offline_installation,
                    storage_owner=storage_owner,location=location)
            if offline_bundle is not None and offline_bundle.habit_runtime_policy is not None:
                from ..host.habit_runtime_policy_v1 import HabitRuntimePolicyV1
                from .d10_habit_ledger_v1 import habit_signing_key_v1
                from .d10_habit_policy_service_v1 import InstalledD10HabitPolicyServiceV1
                from .current_habit_occurrence_v1 import InstalledCurrentHabitOccurrenceV1
                if type(offline_bundle.habit_runtime_policy)is not HabitRuntimePolicyV1 or self_identity is None:
                    raise AuthorityUnavailable("Habit requires its actual installed policy and current Self")
                offline_bundle.habit_runtime_policy.require_installation_v1(offline_bundle.installation_policy)
                def habit_trusted_now_v1():
                    reading=config.clock_provider()
                    return reading.utc_seconds+reading.utc_error_seconds
                habit_policy=InstalledD10HabitPolicyServiceV1(fences=server._v2_fences[namespace],
                    owner_tickets=server._v2_owner_tickets,owner_service=storage_owner,
                    namespace=maintenance.namespace_id,installation_id=control.installation_id,
                    signing_key=habit_signing_key_v1(offline_bundle),trusted_now_utc=habit_trusted_now_v1,create=True)
                habit_current=InstalledCurrentHabitOccurrenceV1(self_identity_service=self_identity,
                    budget_issuer=offline_installation.d11_issuer,clock_provider=config.clock_provider,
                    installed_bundle=offline_bundle,policy_service=habit_policy,create=True)
                server._d10_habit_policy_services_v1[(namespace,control.installation_id)]=habit_policy
                server._current_habit_occurrence_v1[(namespace,control.installation_id)]=habit_current
                maintenance._installed_d10_habit_policy_service_v1=habit_policy
                maintenance._installed_current_habit_occurrence_v1=habit_current
            if offline_bundle is not None:
                from .current_named_joint_binding_v1 import InstalledCurrentNamedJointBindingV1
                if self_identity is None:
                    raise AuthorityUnavailable('Named Joint requires its actual current Self/Owner composition')
                server._current_named_joint_binding_v1[(namespace, control.installation_id)] = InstalledCurrentNamedJointBindingV1(
                    self_identity_service=self_identity, budget_issuer=offline_installation.d11_issuer,
                    clock_provider=config.clock_provider, installed_bundle=offline_bundle, package_root=offline_installation.package_root)
            if offline_bundle is not None and offline_bundle.d13_paid_precompression is not None:
                from .d13_authority_model_source_v3 import InstalledD13AuthorityModelReaderV3
                model=server._v2_model_egress.get(namespace)
                worker=server._v2_worker_model_result_reads.get(namespace)
                if model is None or worker is None:
                    raise AuthorityUnavailable("D13 Source reader lacks its actual paired model/result services")
                d13_reader=InstalledD13AuthorityModelReaderV3(owner_storage=storage_owner,bundle=offline_bundle,
                    issuer=offline_installation.d11_issuer,model_service=model,worker_service=worker)
                model._graph_verifier.install_d13_paid_reader_v3(d13_reader)
            if offline_bundle is not None and offline_bundle.artifact_draft is not None:
                from .artifact_model_graph_v3 import InstalledArtifactDraftModelGraphReaderV3
                model=server._v2_model_egress.get(namespace)
                worker=server._v2_worker_model_result_reads.get(namespace)
                if model is None or worker is None:
                    raise AuthorityUnavailable("Artifact model reader lacks actual paired model/worker installation")
                artifact_reader=InstalledArtifactDraftModelGraphReaderV3(owner_storage=storage_owner,bundle=offline_bundle,
                    issuer=offline_installation.d11_issuer,model_service=model,worker_service=worker,
                    habit_service=server._current_habit_occurrence_v1.get((namespace,control.installation_id)))
                model._graph_verifier.install_artifact_model_reader_v3(artifact_reader)
            from .conditioned_child_contract_v1 import ROOT_WORK_KIND as CONDITIONED_CHILD_ROOT_WORK_KIND
            if(offline_bundle is not None and CONDITIONED_CHILD_ROOT_WORK_KIND in
                    offline_bundle.installation_policy.root_grant.allowed_work_kinds):
                from .current_conditioned_child_v1 import InstalledCurrentConditionedChildV1
                if self_identity is None:
                    raise AuthorityUnavailable('conditioned child requires its actual current Self/Owner composition')
                server.install_current_conditioned_child_v1(namespace,InstalledCurrentConditionedChildV1(
                    self_identity_service=self_identity,budget_issuer=offline_installation.d11_issuer,
                    clock_provider=config.clock_provider,installed_bundle=offline_bundle))
            if (offline_bundle is not None and "d11.foreground_cycle.v1" in
                    offline_bundle.installation_policy.root_grant.allowed_work_kinds):
                from .current_foreground_activity_v1 import InstalledCurrentForegroundActivityV1
                if self_identity is None:
                    raise AuthorityUnavailable("foreground activity requires its actual current self service")
                foreground = InstalledCurrentForegroundActivityV1(
                    self_identity_service=self_identity,
                    budget_issuer=offline_installation.d11_issuer,
                    clock_provider=config.clock_provider,
                    installed_bundle=offline_bundle,
                    filesystem_manifest=(config.c09_maintenance_factory.inventory
                        if "d10.life.artifact_draft.v1" in offline_bundle.installation_policy.root_grant.allowed_work_kinds
                        else None))
                server.install_current_foreground_activity_v1(namespace, foreground)
                from ..host.model_workflows_v7 import AdminModelWorkflowsV7
                from ..host.model_workflows_v8 import AdminModelWorkflowsV8
                from ..host.model_workflows_v9 import AdminModelWorkflowsV9
                if type(offline_bundle.model_workflows) in {AdminModelWorkflowsV7, AdminModelWorkflowsV8, AdminModelWorkflowsV9}:
                    from .d13_installed_counter_factory_v1 import install_d13_core_counter_v1
                    from ..runtime.d13_counter_cpu_quote_policy_v1 import D13CounterCpuQuotePolicyAuthorityV1
                    from ..domains.d02.body_quote_original import D02BodyQuoteAuthority
                    import hmac
                    assets=(config.d13_counter_assets_v1 or {}).get(namespace)
                    if assets is None or model is None:
                        raise AuthorityUnavailable("V7 requires its actual protected counter assets and model store")
                    counter_cpu=D13CounterCpuQuotePolicyAuthorityV1(hmac.digest(offline_bundle.d11_signing_key,
                        b"sylanne3.d13.counter.cpu_quote_policy.v1\0"+control.installation_id.encode(),"sha256"))
                    counter_body=D02BodyQuoteAuthority(hmac.digest(offline_bundle.d02_signing_key,
                        b"sylanne3.d02.body_quote_original.v1\0"+control.installation_id.encode(),"sha256"))
                    counter=install_d13_core_counter_v1(foreground_observer=foreground,
                        bridge=server._v2_execution[namespace],
                        execute_credential=config.local_administrator_credential("c04_execute",namespace),
                        assets=assets,cpu_quote_authority=counter_cpu,body_quote_authority=counter_body,
                        authority_store=model._store,create=False)
                    server.install_d13_core_counter_v1(namespace,counter)
                    maintenance._d13_core_counter_v1=counter
                if 'd10.life.source_note.v1' in offline_bundle.installation_policy.root_grant.allowed_work_kinds:
                    from .current_owner_source_note_task_v1 import InstalledCurrentOwnerSourceNoteTaskV1
                    server.install_current_owner_source_note_task_v1(namespace,
                        InstalledCurrentOwnerSourceNoteTaskV1(self_identity_service=self_identity,
                            budget_issuer=offline_installation.d11_issuer,
                            clock_provider=config.clock_provider, installed_bundle=offline_bundle))
            if offline_bundle is not None:
                from .current_named_joint_source_note_v1 import install_named_source_note_original_services_v1
                install_named_source_note_original_services_v1(server._current_named_joint_binding_v1[(namespace,control.installation_id)],
                    server._v2_foreground_activity.get(namespace),server._v2_owner_source_note_tasks.get(namespace))
            if (offline_bundle is not None and "artifact_draft_v1" in
                    offline_bundle.installation_policy.root_grant.allowed_work_kinds):
                from ..runtime.d11_artifact_draft_model_v1 import installed_artifact_draft_workflow_v1
                from .d11_artifact_draft_model_v1 import AuthorityArtifactDraftModelResultServiceV1
                installed_artifact_draft_workflow_v1(offline_bundle)
                if model is None or self_identity is None or server._clock_provider is None:
                    raise AuthorityUnavailable("artifact draft requires actual model/self/current clock composition")
                worker = server._v2_worker_model_result_reads[namespace]
                server.install_artifact_draft_model_result_reader_v1(namespace,
                    AuthorityArtifactDraftModelResultServiceV1(store=model._store, fences=server._v2_fences[namespace],
                        graph_db_path=location._graph_db_path, d11_issuer=offline_installation.d11_issuer,
                        installed_bundle=offline_bundle, installation_id=control.installation_id,
                        read_subject=worker._read_subject, holder=next(iter(holders)),
                        trusted_now_utc=lambda: server._clock_provider().utc_seconds,
                        read_attempts=worker._attempts,graph_reader=model._graph_verifier._artifact_model_reader_v3))
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
                p2 = server.install_contact_p2_service_v1(contact_service, location)
                from .contact_effect_accounting_v1 import InstalledContactEffectAccountingServiceV1
                server._contact_effect_accounting_v1[(namespace, control.installation_id)] = (
                    InstalledContactEffectAccountingServiceV1(p2_service=p2,
                        accounting=server._v2_accounting[namespace], bundle=offline_bundle, create=True))
                if offline_bundle.model_workflows.contact_generation is not None:
                    from .contact_model_result_service_v1 import InstalledContactModelResultServiceV1
                    model._graph_verifier.install_contact_policy_service_v1(contact_service)
                    from ..host.model_workflows_v3 import AdminModelWorkflowsV3
                    from ..host.model_workflows_v4 import AdminModelWorkflowsV4
                    from ..host.model_workflows_v5 import AdminModelWorkflowsV5
                    from ..host.model_workflows_v6 import AdminModelWorkflowsV6
                    from ..host.model_workflows_v7 import AdminModelWorkflowsV7
                    from ..host.model_workflows_v8 import AdminModelWorkflowsV8
                    from ..host.model_workflows_v9 import AdminModelWorkflowsV9
                    if type(offline_bundle.model_workflows) in (AdminModelWorkflowsV3, AdminModelWorkflowsV4, AdminModelWorkflowsV5, AdminModelWorkflowsV6, AdminModelWorkflowsV7, AdminModelWorkflowsV8, AdminModelWorkflowsV9):
                        from .contact_model_result_service_v2 import InstalledContactModelResultServiceV2 as InstalledContactModelResultServiceV1
                        install_contact_reader = server.install_contact_model_result_reader_v2
                    else:
                        install_contact_reader = server.install_contact_model_result_reader_v1
                    def contact_trusted_now():
                        sample = server._clock_provider()
                        return sample.utc_seconds + sample.utc_error_seconds
                    install_contact_reader(namespace, InstalledContactModelResultServiceV1(
                        store=model._store, fences=server._v2_fences[namespace],
                        graph_db_path=location._graph_db_path, d11_issuer=offline_installation.d11_issuer,
                        installation_id=control.installation_id,
                        read_subject="mtls:sha256:" + offline_installation.observer_peer[0],
                        holder=next(iter(holders)), trusted_now_utc=contact_trusted_now,
                        source_location=location, contact_policy_service=contact_service))
                    if namespace in server._contact_model_reads_v2:
                        server.install_contact_prospective_observer_v1(namespace, bundle=offline_bundle)
                        server.install_contact_continuation_observer_v1(namespace, bundle=offline_bundle)
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
                    credential=config.local_administrator_credential("c04_execute", namespace),
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
            if (offline_bundle is not None and {"d10.life.source_note.v1", "d10.life.artifact_draft.v1"}.intersection(
                    offline_bundle.installation_policy.root_grant.allowed_work_kinds)):
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
                    credential=config.local_administrator_credential("c04_execute", namespace),
                    signing_key=hmac.new(offline_bundle.d11_signing_key,
                        b"sylanne.authority.d11-life-signing.v1", hashlib.sha256).digest(),
                    trusted_now_utc=lambda: server._clock_provider().utc_seconds,
                    owner_service=getattr(server, "_d12_target_owner_services_v1", {}).get(
                        (namespace, control.installation_id), storage_owner),
                    package_root=life_installation.package_root,
                    body_quote_authority=config.c09_maintenance_factory.body_authority,
                    current_source_location=location, installed_bundle=offline_bundle,
                    draft_inventory_manifest=(config.c09_maintenance_factory.inventory
                        if "d10.life.artifact_draft.v1" in offline_bundle.installation_policy.root_grant.allowed_work_kinds
                        else None),
                    draft_self_identity=(self_identity
                        if "d10.life.artifact_draft.v1" in offline_bundle.installation_policy.root_grant.allowed_work_kinds else None),
                    draft_self_read_credential=(config.local_administrator_credential("c04_self_identity_read", namespace)
                        if "d10.life.artifact_draft.v1" in offline_bundle.installation_policy.root_grant.allowed_work_kinds else None))
                server._d11_life_services_v1[namespace] = life
                core.install_execution_redaction_d11_life_service_v1(namespace, life)
            composition.require_current()
        return daemon
    except BaseException:
        if core is not None:
            core.close()
        for journal in execution.values():
            journal.close()
        if deletion is not None:
            deletion.close()
        raise


_COMPOSITION_V3 = object()


@contextmanager
def _bootstrap_control_quantum_v3(control):
    from ..runtime.c09_paged_sql_v2 import (current_c09_sql_meter_v2,
        require_c09_reserved_meter_v3,C09PagedCaptureHold)
    try:
        meter=current_c09_sql_meter_v2()
    except C09PagedCaptureHold:
        with control.reserve_control_read_v3() as budget:
            yield require_c09_reserved_meter_v3(budget)
    else:
        yield meter


class _ResolvedStorageCompositionV3:
    """Private completed physical selection; executable permissions stay in Core."""
    def __init__(self, issuer, config, control, context, selected, maintenance_basis):
        if issuer is not _COMPOSITION_V3:
            raise AuthorityUnavailable("actual bootstrap storage composition required")
        self.config,self.control,self.context=config,control,context
        self.selected,self.maintenance_basis=selected,maintenance_basis
        self.peer_gate=None

    def require_current(self):
        if self.control is None:
            return
        with _bootstrap_control_quantum_v3(self.control) as meter:
            if self.maintenance_basis is not None:
                self.maintenance_basis.require_current(meter=meter)
            else:
                self.context.require_current("business" if self.context.stage in {"READY","RELEASED"} else "maintenance")

    def store_kwargs(self):
        if self.maintenance_basis is not None:
            return dict(maintenance_basis=self.maintenance_basis,storage_context=self.context)
        if self.selected is not None:
            return dict(selected_storage=self.selected,storage_context=self.context)
        return {}

    def open_graph(self, registry):
        from ..graph_store import ProductionGraphStore
        self.require_current()
        from ..runtime_storage_v3 import install_runtime_storage_schema_v3
        if self.maintenance_basis is not None:
            with _bootstrap_control_quantum_v3(self.control):
                graph=ProductionGraphStore(self.config.graph_db,registry,**self.store_kwargs())
                try:install_runtime_storage_schema_v3(graph._db,handle=graph._runtime_storage_v3)
                except BaseException:
                    graph.close()
                    raise
        else:
            graph=ProductionGraphStore(self.config.graph_db,registry,**self.store_kwargs())
            if self.selected is not None:
                try:install_runtime_storage_schema_v3(graph._db,handle=graph._runtime_storage_v3)
                except BaseException:
                    graph.close()
                    raise
        return graph


def _selected_config_v3(config, context):
    members={member["role"]:member for member in context.manifest["members"]}
    namespaces=sorted(config.execution_journals)
    installed=config.c09_storage_v1
    if (context.manifest["cohort_namespaces"]!=namespaces
            or context.manifest["installation_id"]!=installed.installation_id
            or context.manifest["authority_id"]!=installed.authority_id
            or any(item.installation_id!=installed.installation_id for item in config.installations_v2.values())):
        raise AuthorityUnavailable("selected composition differs from actual installed cohort")
    namespace=namespaces[0]
    return replace(config,authority_db=Path(members["core"]["resolved_path"]),
        deletion_db=Path(members["deletion"]["resolved_path"]),graph_db=Path(members["graph"]["resolved_path"]),
        execution_journals={namespace:ExecutionJournalInstallation(Path(members["execution"]["resolved_path"]),
            members["execution"]["incarnation_or_journal_id"])})


def _compose_cold_maintenance_services_v3(composition):
    from .c09_installed_factory_v1 import InstalledAuthorityMaintenanceServicesV3
    from .local_composition import compose_installed_owner_ticket_store_v3
    from ..host.owner_deployment import OwnerDeploymentVerifier
    from .v2_owner_proof import AuthorityV2OwnerProofStore
    from .v2_execution_bridge import AuthorityV2ExecutionBridge
    config=composition.config
    paths=_preflight(config,composition=composition)
    kwargs=composition.store_kwargs()
    deletion=None
    execution={}
    core=None
    try:
        deletion=AuthorityV2DeletionGuard(paths["deletion"],**kwargs)
        for namespace,installation in config.execution_journals.items():
            execution[namespace]=AuthorityV2ExecutionJournal(paths["execution:"+namespace],namespace=namespace,
                journal_id=installation.journal_id,create=False,installed_storage_reader=composition.control,**kwargs)
        verifiers=config.core_verifier_factory(deletion,MappingProxyType(dict(execution)))
        if type(verifiers) is not AuthorityCoreVerifiers:
            raise AuthorityUnavailable("actual installed maintenance Core verifiers required")
        core=AuthorityServiceCore(paths["authority"],authorizer=config.core_authorizer,
            deletion_verifier=verifiers.deletion,execution_verifier=verifiers.execution,
            effect_verifier=verifiers.effect,dispatch_verifier=verifiers.dispatch,create=False,**kwargs)
        core.install_current_c09_storage_reader_v1(reader=composition.control)
        fences,services,natural,clock,utc_clock,dispatch,namespace_map=(
            _compose_installed_fence_components_v3(config,paths,core,deletion,execution))
        factory=config.c09_maintenance_factory
        namespace=next(iter(execution))
        installed=config.installations_v2[factory.peer]
        credential=config.local_administrator_credential("c09_maintenance",namespace)
        core._require(credential,"execution_redaction_install",namespace)
        pairings=AuthorityOwnerPairingSource(core,utc_clock=utc_clock,create=False)
        sessions=AuthorityV2OwnerSessionStore(core,utc_clock=utc_clock,current_pairing_source=pairings,create=False)
        identity=OwnerDeploymentVerifier(pairings,utc_clock)
        # The same genuine proof-store constructor and verifiers are used by ordinary composition.
        AuthorityV2OwnerProofStore(core,utc_clock=utc_clock,pairing_verifier=identity.pair_credential,
            session_verifier=None,current_pairing_source=pairings,create=False)
        owner_tickets=compose_installed_owner_ticket_store_v3(core=core,services=services,
            graph_db_path=paths["graph"],utc_clock=utc_clock,first_claim_verifier=identity.first_claim,
            verified_claimant=None,owner_sessions=sessions,creation_pairing_source=pairings)
        scoped=AuthorityV2ScopedErasureStore(core=core,fences=fences,deletion=deletion,
            execution=execution[namespace],namespace=namespace)
        recovery=AuthorityV2DeletionPendingRecovery(core=core,fences=fences,deletion=deletion,
            execution=execution[namespace],namespace=namespace,scoped_store=scoped)
        erasure=CurrentErasureAuthority(recovery,fence_service=services[namespace],owner_sessions=sessions,
            owner_tickets=owner_tickets,installation_id=installed.installation_id,scoped_store=scoped,
            graph_db_path=paths["graph"])
        accepted=CurrentAcceptedErasureReadService(fence_service=services[namespace],
            owner_tickets=owner_tickets,scoped_store=scoped)
        bridge=AuthorityV2ExecutionBridge(core=core,fences=fences,journal=execution[namespace],namespace=namespace,
            deletion=deletion,owner_tickets=owner_tickets,owner_installation_id=installed.installation_id,
            v2_dispatch_verifier=dispatch.get(namespace))
        historical={}
        for version,installations in ((2,config.c04_installations_v2 or {}),(3,config.c04_installations_v3 or {})):
            item=installations.get(namespace)
            if item is None:
                continue
            if version==2:
                from .installed_c04_executor_v2 import compose_installed_c04_service_v2
                historical["d06.association_activation.v2"]=compose_installed_c04_service_v2(bridge=bridge,
                    namespace=namespace_map[namespace],graph_db_path=paths["graph"],package_root=item.package_root,
                    trusted_manifest_sha256=item.formal_manifest_sha256,
                    component_signing_key=paths["c04_key:"+namespace].read_bytes(),credential=credential,
                    install_bridge_verifier=False)
            else:
                from .installed_c04_executor_v3 import compose_installed_c04_service_v3
                policy=natural[namespace]
                service=compose_installed_c04_service_v3(bridge=bridge,namespace=namespace_map[namespace],
                    graph_db_path=paths["graph"],package_root=item.package_root,
                    trusted_manifest_sha256=item.formal_manifest_sha256,
                    component_signing_key=paths["c04_v3_key:"+namespace].read_bytes(),credential=credential,
                    resource_issuer=policy.d11_issuer.resource_issuer,budget_issuer=policy.d11_issuer,
                    self_identity_read_credential=config.local_administrator_credential("c04_self_identity_read",namespace),
                    install_bridge_verifier=False)
                historical["d06.association_activation.v3"]=service
                historical["d06.association_activation.direct_seed.v4"]=service
        core.install_execution_redaction_c04_services(namespace,historical)
        return InstalledAuthorityMaintenanceServicesV3(config,core,deletion,MappingProxyType(execution),
            services[namespace],pairings,sessions,owner_tickets,scoped,recovery,erasure,accepted)
    except BaseException:
        if core is not None:core.close()
        for journal in execution.values():journal.close()
        if deletion is not None:deletion.close()
        raise


class _AuthorityBootstrapPlanV3:
    def __init__(self,config,lease):
        self.config,self.lease=config,lease
        self.control=None
        self.phase="identity"
        self.metadata=self.selected=self.context=self.composition=None
        self.legacy_reader=None
        self.maintenance=self.services=self.actor=self.operation=None
        self.business=None
        self.factual=None
        self.counter_builders=[]
        self.counter_index=0
        self.failure=None

    def _progress(self):
        return dict(status="progress",phase=self.phase)

    def advance(self):
        if self.failure is not None:
            raise self.failure
        if self.phase=="identity":
            if self.config.c09_storage_v2 is not None:
                config,reader=_resolve_current_c09_config(self.config,self.lease)
                self.factual=AuthorityFactualDaemonV2(config,self.lease,reader)
                self.phase="factual_ready"
                return self.factual
            _,self.control=_resolve_current_c09_config(self.config,self.lease)
            self.phase="control" if self.control is not None else "business_compose"
            if self.control is None:
                self.composition=_ResolvedStorageCompositionV3(_COMPOSITION_V3,self.config,None,None,None,None)
            return self._progress()
        if self.phase=="control":
            self.metadata=self.control.read_verified_control_status_v3()
            if self.metadata["status"]=="complete":self.phase="selected"
            return self._progress()
        if self.phase=="selected":
            if self.metadata["manifest_schema"]=="sylanne3.c09.storage_manifest.v3":
                from .c09_selected_history_v3 import VerifiedSelectedHistoryReadV3
                selected=self.control.advance_selected_history_read_v3()
                if type(selected) is not VerifiedSelectedHistoryReadV3:return selected
                self.selected=selected
                self.phase="physical_composition"
            else:
                from .c09_paged_recovery_facts_v2 import begin_selected_legacy_prepared_reader_v2
                with _bootstrap_control_quantum_v3(self.control) as meter:
                    self.legacy_reader=begin_selected_legacy_prepared_reader_v2(self.control,meter=meter)
                self.phase="legacy_selected" if self.legacy_reader is not None else "physical_composition"
            return self._progress()
        if self.phase=="legacy_selected":
            with _bootstrap_control_quantum_v3(self.control) as meter:
                summary=self.legacy_reader.advance(meter=meter)
                if summary is not None:
                    summary.require_current(meter=meter)
                    self.control._c09_selected_legacy_prepared_v2=summary
                    self.phase="physical_composition"
            return self._progress()
        if self.phase=="physical_composition":
            maintenance_basis=None
            with _bootstrap_control_quantum_v3(self.control) as meter:
                if self.selected is not None:
                    from .c09_selected_history_v3 import begin_selected_physical_composition_v3
                    physical=begin_selected_physical_composition_v3(self.control,view=self.selected,meter=meter)
                    self.context=physical.context
                    if self.context.stage in {"INTENT","PREPARED","SWITCHED","CLEANED"}:
                        maintenance_basis=physical.require_current_for_maintenance_v3(meter=meter,
                            context=self.context,operation_id=self.metadata["active_operation_id"])
                else:
                    self.context=self.control.read_verified_current_storage_v2(meter=meter)
                self.context.require_current("maintenance")
            config=_selected_config_v3(self.config,self.context)
            self.composition=_ResolvedStorageCompositionV3(_COMPOSITION_V3,config,self.control,self.context,
                self.selected,maintenance_basis)
            self.phase="peer_registry"
            return self._progress()
        if self.phase=="peer_registry":
            from .c09_storage_maintenance_v1 import InstalledC09WriterGateV1
            factory=self.composition.config.c09_maintenance_factory
            result=factory.advance_peer_registry_preparation_v3(control=self.control,
                config=self.composition.config,context=self.context)
            if type(result) is not InstalledC09WriterGateV1:return result
            self.composition.peer_gate=factory.take_prepared_peer_registry_gate_v3(
                control=self.control,config=self.composition.config)
            self.phase="business_qualification" if self.context.stage in {"READY","RELEASED"} else "maintenance_compose"
            return self._progress()
        if self.phase=="business_qualification":
            if self.selected is None and (self.context.stage!="READY" or self.context.storage_generation!=0):
                raise AuthorityUnavailable("ordinary bootstrap requires real initial READY or completed RELEASED V3")
            if self.selected is not None:
                from .c09_close_apply_v1 import SelectedAppliedReadV3
                proof=self.control.advance_selected_storage_applied_read_v3()
                if type(proof) is not SelectedAppliedReadV3:return proof
            with _bootstrap_control_quantum_v3(self.control):self.context.require_current("business")
            self.phase="business_compose"
            return self._progress()
        if self.phase=="maintenance_compose":
            self.services=_compose_cold_maintenance_services_v3(self.composition)
            self.maintenance=self.config.c09_maintenance_factory.compose_for_cold_maintenance_v3(
                self.services,self.composition)
            self.actor=self.maintenance.bind_current_thread_actor_v3(operation_id=self.metadata["active_operation_id"])
            if self.selected is not None:
                from ..runtime_storage_v3 import begin_maintenance_runtime_operation_v3
                self.operation=begin_maintenance_runtime_operation_v3(self.services.core._runtime_storage_v3,
                    actor=self.actor,core=self.services.core,credential=self.maintenance.credential)
                self.phase="maintenance_selected_state"
            else:
                self.phase="maintenance_advance"
            return self._progress()
        if self.phase=="maintenance_selected_state":
            from ..runtime_storage_v3 import bind_maintenance_runtime_operation_v3
            with _bootstrap_control_quantum_v3(self.control):
                with bind_maintenance_runtime_operation_v3(self.operation,self.services.core._db):
                    self.services.recovery.initialize_current_selected_state_v3()
            self.phase="maintenance_advance"
            return self._progress()
        if self.phase=="maintenance_advance":
            from ..runtime_storage_v3 import bind_maintenance_runtime_operation_v3
            if self.operation is None:
                result=self.maintenance.advance_storage_maintenance_current_thread_v3(operation_id=self.actor.operation_id)
            else:
                with bind_maintenance_runtime_operation_v3(self.operation,self.services.core._db):
                    result=self.maintenance.advance_storage_maintenance_current_thread_v3(operation_id=self.actor.operation_id)
            if result["status"]=="failed":
                raise AuthorityUnavailable("C09 maintenance first failure: "+result["reason"])
            if self.maintenance.restart_required:
                self._close_maintenance()
                from .contract import AuthorityColdRestartRequired
                raise AuthorityColdRestartRequired("C09 actual SWITCHED requires a new OS process")
            if result["status"]=="complete" and result["phase"]=="PREPARED":
                return dict(result,status="progress")
            if result["status"]=="complete" and result["phase"]=="RELEASED":
                self.phase="maintenance_release_check"
            return result
        if self.phase=="maintenance_release_check":
            status=self.control.read_verified_control_status_v3()
            if status["status"]!="complete":return status
            if status["stage"]!="RELEASED" or status["active_operation_id"]!=self.actor.operation_id:
                raise AuthorityUnavailable("actual signed maintenance RELEASED operation differs")
            self._close_maintenance()
            # Reconstruct protected identity after closing the actual old composition.
            # Its one-use gate/applied-reader and selected caches must never be reused.
            self.control=self.metadata=self.selected=self.context=self.composition=None
            self.legacy_reader=None
            self.phase="identity"
            return self._progress()
        if self.phase=="business_compose":
            self.business=_compose_business_daemon_v3(self.composition.config,self.lease,self.composition)
            if self.selected is not None:
                from .d13_provider_http_admission_v1 import RuntimeCounterCallIndexBuilderV3
                self.counter_builders=[RuntimeCounterCallIndexBuilderV3(counter)
                    for counter in self.business.server._d13_core_counters_v1.values()]
            self.phase="counter_bootstrap"
            return self._progress()
        if self.phase=="counter_bootstrap":
            if self.counter_index<len(self.counter_builders):
                result=self.counter_builders[self.counter_index].advance()
                if result["status"]=="complete":self.counter_index+=1
                return self._progress()
            self.composition.require_current()
            self.phase="ready"
            return self.business
        raise AuthorityUnavailable("actual bootstrap phase differs")

    def _close_maintenance(self):
        from ..runtime_storage_v3 import finish_runtime_storage_operation_v3
        if self.actor is not None:self.actor.close_current_thread_v3()
        finish_runtime_storage_operation_v3(self.operation)
        self.operation=None
        if self.maintenance is not None:self.maintenance.graph.close()
        if self.services is not None:
            self.services.core.close()
            for journal in self.services.execution.values():journal.close()
            self.services.deletion.close()
        self.actor=self.maintenance=self.services=None

    def close(self):
        if self.control is not None and self.config.c09_maintenance_factory is not None:
            self.config.c09_maintenance_factory.close_peer_registry_preparation_v3(self.control)
        self._close_maintenance()
        if self.business is not None and self.phase!="ready":
            asyncio.run(self.business.aclose())
            self.business=None
            self.lease=None
        if self.business is None and self.lease is not None:
            _release_instance_lock(self.lease)
            self.lease=None


class AuthorityBootstrapDaemonV3:
    """Installer-owned lifecycle; one bounded queue and one actual bootstrap thread."""
    def __init__(self,config,lease):
        self.config=config
        self._plan=_AuthorityBootstrapPlanV3(config,lease)
        self._queue=Queue(maxsize=1)
        self._thread=None
        self._ready_lock=asyncio.Lock()
        self._daemon=None
        self._factual=None
        self._failure=None
        self._pending=None
        self._pending_command=None
        self._closed=False

    @property
    def is_listening(self):
        return self._daemon is not None and self._daemon.is_listening

    def _run(self):
        while True:
            command,future=self._queue.get()
            try:
                if command=="close":
                    self._plan.close()
                    future.set_result(None)
                    return
                result=self._plan.advance()
                if type(result) is AuthorityDaemon:
                    self._daemon=result
                elif type(result) is AuthorityFactualDaemonV2:
                    self._factual=result
                future.set_result(result)
                if self._daemon is not None or self._factual is not None:return
            except BaseException as exc:
                self._failure=exc
                self._plan.failure=exc
                try:self._plan.close()
                finally:future.set_exception(exc)
                return

    async def _harvest_pending(self):
        future=self._pending
        if future is None:return None
        result=await asyncio.shield(asyncio.wrap_future(future))
        if self._pending is future:
            self._pending=None
            self._pending_command=None
        return result

    async def _request(self,command):
        if self._pending is not None:
            pending_command=self._pending_command
            result=await self._harvest_pending()
            if pending_command==command:return result
            if self._daemon is not None or self._factual is not None:return None
        if self._failure is not None:raise self._failure
        if self._thread is None:
            self._thread=threading.Thread(target=self._run,
                name="authority-bootstrap-"+str(self.config.instance_lock),daemon=True)
            self._thread.start()
        future=Future()
        self._pending=future
        self._pending_command=command
        self._queue.put_nowait((command,future))
        return await self._harvest_pending()

    async def await_business_ready_v3(self):
        if self.config.c09_storage_v2 is not None:
            raise AuthorityUnavailable("C09 V2 remains factual-only; ordinary business admission HOLD")
        async with self._ready_lock:
            if self._closed:raise AuthorityUnavailable("actual Authority bootstrap is closed")
            while self._daemon is None:
                result=await self._request("advance")
                if type(result) is AuthorityDaemon:return result
                await asyncio.sleep(0.025)
            return self._daemon

    async def await_factual_ready_v2(self):
        if self.config.c09_storage_v2 is None:
            raise AuthorityUnavailable("the installed factual-only V2 reader is absent")
        async with self._ready_lock:
            if self._closed:raise AuthorityUnavailable("actual Authority bootstrap is closed")
            if self._factual is None:
                result=await self._request("advance")
                if type(result) is not AuthorityFactualDaemonV2:
                    raise AuthorityUnavailable("actual installed factual V2 composition differs")
            return self._factual

    async def await_offline_ready_v3(self):
        return await self.await_business_ready_v3()

    async def resume_cold_maintenance_v1(self):
        await self.await_business_ready_v3()
        return False

    async def start(self):
        daemon=await self.await_business_ready_v3()
        return await daemon.start()

    async def aclose(self):
        async with self._ready_lock:
            if self._closed:return
            self._closed=True
            if self._pending is not None and self._failure is None:
                await self._harvest_pending()
            if self._daemon is not None:
                await self._daemon.aclose()
            elif self._factual is not None:
                await self._factual.aclose()
            elif self._thread is None:
                self._plan.close()
            elif self._failure is None:
                await self._request("close")


def open_authority_daemon(config: AuthorityDeploymentConfig) -> AuthorityBootstrapDaemonV3:
    """Acquire only installed identity and the live OS lease; no SQL or listener."""
    if type(config) is not AuthorityDeploymentConfig:
        raise TypeError("installer-owned AuthorityDeploymentConfig is required")
    lease=_instance_lock(_installed_file(config.instance_lock,"instance lock"))
    return AuthorityBootstrapDaemonV3(config,lease)


__all__=("AuthorityDaemon","AuthorityBootstrapDaemonV3","open_authority_daemon")
