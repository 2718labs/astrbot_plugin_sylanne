"""Installer-owned inputs for reopening an existing local Authority service.

This is a typed in-process installation boundary, not a file format. In
particular, Python callback names must never be loaded from a request or an
ordinary configuration file. A Windows service installer must supply the
policy and verifier implementations when it constructs this object.
"""

from __future__ import annotations

from ..host.model_workflows_v3 import AdminModelWorkflowsV3
from ..host.model_workflows_v4 import AdminModelWorkflowsV4
from ..host.model_workflows_v5 import AdminModelWorkflowsV5
from ..host.model_workflows_v6 import AdminModelWorkflowsV6
from ..host.model_workflows_v7 import AdminModelWorkflowsV7
from dataclasses import dataclass
from datetime import datetime
import json
from pathlib import Path
from types import MappingProxyType
from typing import Callable, Mapping

from .contract import AuthorityUnavailable
from .mtls_server import AdministratorInstallationV2, AuthorityServerTlsConfig
from .v2_clock import AuthorityClockReadingV2
from .installed_platform_observation import HostOneBotObservationInstallationV2
from .reverse_handoff import AdministratorReverseHandoffProfile
from .v2_deletion_guard import AuthorityV2DeletionGuard
from .v2_execution_journal import AuthorityV2ExecutionJournal
from ..runtime_contracts import NamespaceId
from ..runtime.issuers import D11BudgetJobIssuer
from ..host.authority_profile import AdminModelWorkflowsV2


ASSET_MANIFEST_SCHEMA = "sylanne3.authority.installed-assets.v1"


@dataclass(frozen=True, slots=True)
class AuthorityCoreVerifiers:
    """Existing, independently installed Core verification callbacks."""

    deletion: Callable
    execution: Callable
    effect: Callable
    dispatch: Callable

    def __post_init__(self) -> None:
        for name in ("deletion", "execution", "effect", "dispatch"):
            if not callable(getattr(self, name)):
                raise AuthorityUnavailable(f"trusted Core {name} verifier is required")


@dataclass(frozen=True, slots=True)
class ExecutionJournalInstallation:
    path: Path
    journal_id: str

    def __post_init__(self) -> None:
        if type(self.journal_id) is not str or not self.journal_id:
            raise AuthorityUnavailable("installed execution journal ID is required")
        object.__setattr__(self, "path", Path(self.path))


@dataclass(frozen=True, slots=True)
class InstalledC04AuthorityV2:
    """Administrator-owned formal build pin and separate component secret."""

    package_root: Path
    formal_manifest_sha256: str
    component_key_path: Path

    def __post_init__(self) -> None:
        for name in ("package_root", "component_key_path"):
            value = Path(getattr(self, name))
            if not value.is_absolute():
                raise AuthorityUnavailable("C04 installed path must be absolute")
            object.__setattr__(self, name, value)
        digest = self.formal_manifest_sha256
        if (type(digest) is not str or len(digest) != 64 or
                any(ch not in "0123456789abcdef" for ch in digest)):
            raise AuthorityUnavailable("C04 external formal manifest pin is unavailable")


@dataclass(frozen=True, slots=True)
class InstalledC04AuthorityV3:
    """Independent administrator-owned V3 package pin and component secret."""

    package_root: Path
    formal_manifest_sha256: str
    component_key_path: Path

    def __post_init__(self) -> None:
        for name in ("package_root", "component_key_path"):
            value = Path(getattr(self, name))
            if not value.is_absolute():
                raise AuthorityUnavailable("C04 V3 installed path must be absolute")
            object.__setattr__(self, name, value)
        digest = self.formal_manifest_sha256
        if (type(digest) is not str or len(digest) != 64 or
                any(ch not in "0123456789abcdef" for ch in digest)):
            raise AuthorityUnavailable("C04 V3 external formal manifest pin is unavailable")


@dataclass(frozen=True, slots=True)
class InstalledNaturalModelAuthorityV2:
    """Administrator-installed model signing authority and exact mTLS reader."""

    d11_issuer: D11BudgetJobIssuer
    workflows: AdminModelWorkflowsV2 | AdminModelWorkflowsV3 | AdminModelWorkflowsV4 | AdminModelWorkflowsV5 | AdminModelWorkflowsV6
    observer_peer: tuple[str, str]
    installation_bundle: object | None = None

    def __post_init__(self) -> None:
        if (type(self.d11_issuer) is not D11BudgetJobIssuer
                or type(self.workflows) not in (AdminModelWorkflowsV2, AdminModelWorkflowsV3, AdminModelWorkflowsV4, AdminModelWorkflowsV5, AdminModelWorkflowsV6, AdminModelWorkflowsV7)
                or self.workflows.natural_generation is None
                or self.workflows.natural_review is None
                or type(self.observer_peer) is not tuple
                or len(self.observer_peer) != 2):
            raise AuthorityUnavailable("installed natural model authority is incomplete")
        if type(self.workflows) in (AdminModelWorkflowsV4, AdminModelWorkflowsV5, AdminModelWorkflowsV6, AdminModelWorkflowsV7):
            from ..host.authority_profile import AdminInstallationBundle
            if (type(self.installation_bundle) is not AdminInstallationBundle
                    or self.installation_bundle.model_workflows is not self.workflows):
                raise AuthorityUnavailable("V4 model Authority needs its exact installed bundle/workflow objects")
        if self.installation_bundle is not None:
            from ..host.authority_profile import AdminInstallationBundle
            if (type(self.installation_bundle) is not AdminInstallationBundle
                    or self.installation_bundle.model_workflows != self.workflows):
                raise AuthorityUnavailable("natural Authority D13 profile differs from installed workflows")



@dataclass(frozen=True, slots=True)
class InstalledC09AuthorityV1:
    control_path: Path
    key_path: Path
    installation_id: str
    authority_id: str
    control_store_id: str
    key_id: str
    resource_roots: tuple[Path, ...]

    def __post_init__(self):
        from .contract import identifier
        for name in ("control_path", "key_path"):
            path = Path(getattr(self, name))
            if not path.is_absolute():
                raise AuthorityUnavailable("installed C09 path must be absolute")
            object.__setattr__(self, name, path)
        for name in ("installation_id", "authority_id", "control_store_id", "key_id"):
            identifier(getattr(self, name), name)
        roots = tuple(Path(path) for path in self.resource_roots)
        if not roots or any(not path.is_absolute() for path in roots):
            raise AuthorityUnavailable("installed C09 resource roots required")
        object.__setattr__(self, "resource_roots", roots)


@dataclass(frozen=True, slots=True)
class InstalledC09AuthorityV2(InstalledC09AuthorityV1):
    """Protected, separate selector installation; never a caller-selected path."""

    schema: str = "sylanne3.authority.c09-selector-installation.v2"

    def __post_init__(self):
        InstalledC09AuthorityV1.__post_init__(self)
        if self.schema != "sylanne3.authority.c09-selector-installation.v2":
            raise AuthorityUnavailable("installed C09 V2 schema differs")

    @property
    def selector_path(self):
        return Path(str(self.control_path) + ".selector-v2")

    @property
    def selector_journal_path(self):
        return Path(str(self.control_path) + ".selector-v2.journal")


@dataclass(frozen=True, slots=True)
class AuthorityDeploymentConfig:
    """Pinned data, peer identities, and trusted callbacks supplied by installer.

    ``core_verifier_factory`` receives the *reopened* independent journals.
    It must return actual verification implementations; the daemon neither
    substitutes permissive callbacks nor creates missing durable state.
    """

    authority_db: Path
    deletion_db: Path
    graph_db: Path
    instance_lock: Path
    execution_journals: Mapping[str, ExecutionJournalInstallation]
    tls: AuthorityServerTlsConfig
    bind_host: str
    bind_port: int
    installations_v2: Mapping[tuple[str, str], AdministratorInstallationV2]
    namespace_bindings_v2: Mapping[tuple[str, str, NamespaceId], str]
    reverse_handoff_profiles: Mapping[str, AdministratorReverseHandoffProfile]
    reverse_handoff_issuers: Mapping[str, str]
    core_authorizer: Callable
    core_verifier_factory: Callable[
        [AuthorityV2DeletionGuard, Mapping[str, AuthorityV2ExecutionJournal]],
        AuthorityCoreVerifiers,
    ]
    administrator_authorizer: Callable
    publisher_manifest_verifier: Callable
    utc_clock: Callable[[], datetime]
    local_administrator_credential: Callable[[str, str], object]
    natural_model_authorities_v2: Mapping[str, InstalledNaturalModelAuthorityV2] | None = None
    clock_provider: Callable[[], AuthorityClockReadingV2] | None = None
    self_identity_readers_v2: Mapping[str, tuple[str, str]] | None = None
    worker_result_fact_committers_v2: Mapping[str, tuple[str, str]] | None = None
    host_onebot_observations_v2: Mapping[str, HostOneBotObservationInstallationV2] | None = None
    c04_installations_v2: Mapping[str, InstalledC04AuthorityV2] | None = None
    c04_installations_v3: Mapping[str, InstalledC04AuthorityV3] | None = None
    c09_storage_v1: InstalledC09AuthorityV1 | None = None
    c09_maintenance_factory: Callable | None = None
    c09_storage_v2: InstalledC09AuthorityV2 | None = None
    d13_counter_assets_v1: Mapping[str, object] | None = None

    def __post_init__(self) -> None:
        for name in ("authority_db", "deletion_db", "graph_db", "instance_lock"):
            object.__setattr__(self, name, Path(getattr(self, name)))
        for name in ("execution_journals", "installations_v2",
                     "namespace_bindings_v2", "reverse_handoff_profiles",
                     "reverse_handoff_issuers"):
            value = getattr(self, name)
            if not isinstance(value, Mapping) or not value:
                raise AuthorityUnavailable(f"installed {name} is required")
            object.__setattr__(self, name, MappingProxyType(dict(value)))
        namespaces = set(self.execution_journals)
        if (set(self.namespace_bindings_v2.values()) != namespaces
                or set(self.reverse_handoff_profiles) != namespaces
                or set(self.reverse_handoff_issuers) != namespaces):
            raise AuthorityUnavailable("installed namespace, journal and reverse handoff coverage differs")
        if any(type(namespace) is not str or not namespace
               or type(item) is not ExecutionJournalInstallation
               for namespace, item in self.execution_journals.items()):
            raise AuthorityUnavailable("installed execution journals are invalid")
        if any(type(peer) is not tuple or len(peer) != 2
               or type(peer[0]) is not str or len(peer[0]) != 64
               or any(ch not in "0123456789abcdef" for ch in peer[0])
               or type(peer[1]) is not str or not peer[1]
               or type(item) is not AdministratorInstallationV2
               for peer, item in self.installations_v2.items()):
            raise AuthorityUnavailable("installed mTLS peer identities are invalid")
        if any(type(key) is not tuple or len(key) != 3
               or (key[0], key[1]) not in self.installations_v2
               or type(key[2]) is not NamespaceId
               for key in self.namespace_bindings_v2):
            raise AuthorityUnavailable("installed namespace bindings are invalid")
        for namespace, profile in self.reverse_handoff_profiles.items():
            if (type(profile) is not AdministratorReverseHandoffProfile
                    or profile.namespace != namespace
                    or not any(mapped == namespace
                               and profile_id == profile.profile_id
                               and self.installations_v2[(certificate, profile_id)].installation_id
                               == profile.installation_id
                               for (certificate, profile_id, _), mapped
                               in self.namespace_bindings_v2.items())):
                raise AuthorityUnavailable("reverse handoff installation differs")
            issuer = self.reverse_handoff_issuers[namespace]
            if type(issuer) is not str or not issuer:
                raise AuthorityUnavailable("installed graph claim issuer is required")
        for name in ("core_authorizer", "core_verifier_factory",
                     "administrator_authorizer", "publisher_manifest_verifier",
                     "utc_clock", "local_administrator_credential"):
            if not callable(getattr(self, name)):
                raise AuthorityUnavailable(f"trusted {name} is required")
        authorities = self.natural_model_authorities_v2
        if authorities is not None:
            if (not isinstance(authorities, Mapping) or not authorities
                    or not callable(self.clock_provider)):
                raise AuthorityUnavailable("natural model authority needs installed clock provider")
            for namespace, authority in authorities.items():
                if (namespace not in namespaces
                        or type(authority) is not InstalledNaturalModelAuthorityV2
                        or authority.observer_peer not in self.installations_v2
                        or not any(peer == authority.observer_peer[0]
                                       and profile == authority.observer_peer[1]
                                       and mapped == namespace
                                       for (peer, profile, _), mapped
                                       in self.namespace_bindings_v2.items())
                        or self.installations_v2[authority.observer_peer].source_id is None):
                    raise AuthorityUnavailable("natural model installation identity differs")
            object.__setattr__(self, "natural_model_authorities_v2",
                               MappingProxyType(dict(authorities)))
        for field_name in ("self_identity_readers_v2",
                           "worker_result_fact_committers_v2"):
            readers = getattr(self, field_name)
            if readers is None:
                continue
            if (not isinstance(readers, Mapping)
                    or any(namespace not in namespaces
                           or peer not in self.installations_v2
                           or not any(candidate == peer[0] and profile == peer[1]
                                      and mapped == namespace
                                      for (candidate, profile, _), mapped
                                      in self.namespace_bindings_v2.items())
                           for namespace, peer in readers.items())):
                raise AuthorityUnavailable(f"installed {field_name} identity differs")
            object.__setattr__(self, field_name, MappingProxyType(dict(readers)))
        observations = self.host_onebot_observations_v2
        if observations is not None:
            if (not isinstance(observations, Mapping)
                    or any(namespace not in namespaces
                           or type(value) is not HostOneBotObservationInstallationV2
                           for namespace, value in observations.items())):
                raise AuthorityUnavailable("installed OneBot observation identity differs")
            object.__setattr__(self, "host_onebot_observations_v2",
                               MappingProxyType(dict(observations)))
        c04 = self.c04_installations_v2
        if c04 is not None:
            if (not isinstance(c04, Mapping) or
                    any(namespace not in namespaces or
                        type(item) is not InstalledC04AuthorityV2
                        for namespace, item in c04.items())):
                raise AuthorityUnavailable("installed C04 namespace or pin differs")
            object.__setattr__(self, "c04_installations_v2",
                               MappingProxyType(dict(c04)))
        c04_v3 = self.c04_installations_v3
        if c04_v3 is not None:
            if (not isinstance(c04_v3, Mapping) or
                    any(namespace not in namespaces or
                        type(item) is not InstalledC04AuthorityV3
                        for namespace, item in c04_v3.items())):
                raise AuthorityUnavailable("installed C04 V3 namespace or pin differs")
            object.__setattr__(self, "c04_installations_v3",
                               MappingProxyType(dict(c04_v3)))
        counter_assets = self.d13_counter_assets_v1
        if counter_assets is not None:
            from .d13_installed_counter_factory_v1 import InstalledD13CounterAssetsV1
            if not isinstance(counter_assets, Mapping) or not counter_assets:
                raise AuthorityUnavailable("installed D13 counter assets require exact namespace coverage")
            for namespace, item in counter_assets.items():
                if (namespace not in namespaces or type(item) is not InstalledD13CounterAssetsV1
                        or not any(mapped == namespace and graph_ns == item.namespace
                            and self.installations_v2[(peer, profile)].installation_id == item.installation_id
                            and self.installations_v2[(peer, profile)].manifest_digest == item.package_manifest_sha256
                            for (peer, profile, graph_ns), mapped in self.namespace_bindings_v2.items())):
                    raise AuthorityUnavailable("installed D13 counter assets cross namespace, installation or package")
            object.__setattr__(self, "d13_counter_assets_v1", MappingProxyType(dict(counter_assets)))
        if self.c09_storage_v2 is not None:
            if (type(self.c09_storage_v2) is not InstalledC09AuthorityV2
                    or self.c09_storage_v1 is not None
                    or self.c09_maintenance_factory is not None
                    or len(namespaces) != 1):
                raise AuthorityUnavailable("C09 V2 factual installation is exclusive of V1 business composition")
        elif self.c09_storage_v1 is not None:
            if (type(self.c09_storage_v1) is not InstalledC09AuthorityV1
                    or len(namespaces) != 1 or not callable(self.c09_maintenance_factory)):
                raise AuthorityUnavailable("installed C09 single cohort and trusted maintenance factory required")
        elif self.c09_maintenance_factory is not None:
            raise AuthorityUnavailable("C09 maintenance factory requires installed control")
        if type(self.tls) is not AuthorityServerTlsConfig:
            raise AuthorityUnavailable("installed Authority mTLS server config is required")
        if (type(self.bind_host) is not str or self.bind_host not in {"127.0.0.1", "::1"}
                or type(self.bind_port) is not int or not 1 <= self.bind_port <= 65535):
            raise AuthorityUnavailable("Authority listener requires a fixed loopback port")


def _record(value: object, fields: set[str], label: str) -> dict:
    if type(value) is not dict or set(value) != fields:
        raise AuthorityUnavailable(f"installed {label} fields differ")
    return value


def load_installed_asset_config_v1(
    manifest_path: str | Path, *, core_authorizer: Callable,
    core_verifier_factory: Callable, administrator_authorizer: Callable,
    publisher_manifest_verifier: Callable, utc_clock: Callable[[], datetime],
    local_administrator_credential: Callable[[str, str], object],
    c09_maintenance_factory: Callable | None = None,
) -> AuthorityDeploymentConfig:
    """Parse fixed installer data; executable trust is supplied out of band.

    The caller must pin and ACL-protect ``manifest_path`` in the Windows
    service installation. Parsing a file is never proof that its paths or
    callback implementations are administrator-authorized.
    """
    path = Path(manifest_path)
    if not path.is_absolute() or not path.is_file():
        raise AuthorityUnavailable("installed asset manifest is absent or unsafe")
    if any(component.is_symlink()
           or getattr(component, "is_junction", lambda: False)()
           for component in (path, *path.parents)):
        raise AuthorityUnavailable("installed asset manifest traverses a reparse point")
    if path.stat().st_size > 65_536:
        raise AuthorityUnavailable("installed asset manifest exceeds limit")
    try:
        def unique_pairs(pairs):
            result = {}
            for key, item in pairs:
                if key in result:
                    raise ValueError("duplicate installed asset key")
                result[key] = item
            return result

        value = json.loads(path.read_text(encoding="utf-8"),
                           object_pairs_hook=unique_pairs)
    except (OSError, UnicodeError, ValueError) as exc:
        raise AuthorityUnavailable("installed asset manifest cannot be read") from exc
    fields = {
        "schema", "authority_db", "deletion_db", "graph_db", "instance_lock",
        "bind_host", "bind_port", "tls", "execution_journals",
        "installations_v2", "namespace_bindings_v2", "reverse_handoff",
    }
    optional_c04_fields = {"c04_installations_v2", "c04_installations_v3", "c09_storage_v1", "c09_storage_v2", "d13_counter_assets_v1"}
    if (type(value) is not dict or not fields <= set(value) or
            not set(value).issubset(fields | optional_c04_fields)):
        raise AuthorityUnavailable("installed asset manifest fields differ")
    manifest = value
    if manifest["schema"] != ASSET_MANIFEST_SCHEMA:
        raise AuthorityUnavailable("installed asset manifest version differs")
    tls = _record(manifest["tls"], {
        "certificate", "private_key", "client_trust_root",
        "timeout_seconds", "max_message_bytes",
    }, "TLS")
    if any(type(tls[key]) is not str for key in (
            "certificate", "private_key", "client_trust_root")):
        raise AuthorityUnavailable("installed TLS paths differ")
    def records(name: str) -> list[dict]:
        rows = manifest[name]
        if type(rows) is not list or not rows or any(type(row) is not dict for row in rows):
            raise AuthorityUnavailable(f"installed {name} rows differ")
        return rows

    journals = {}
    for raw in records("execution_journals"):
        row = _record(raw, {"namespace", "path", "journal_id"}, "execution journal")
        namespace = row["namespace"]
        if type(namespace) is not str or namespace in journals:
            raise AuthorityUnavailable("installed execution namespace repeats")
        journals[namespace] = ExecutionJournalInstallation(row["path"], row["journal_id"])
    installations = {}
    for raw in records("installations_v2"):
        row = _record(raw, {
            "certificate_sha256", "profile_id", "installation_id",
            "administrator_holder", "publisher_policy_ref",
            "service_capability_version", "manifest_digest", "source_id",
            "max_utc_error_seconds",
        }, "peer installation")
        key = (row["certificate_sha256"], row["profile_id"])
        if key in installations:
            raise AuthorityUnavailable("installed peer identity repeats")
        installations[key] = AdministratorInstallationV2(
            row["installation_id"], row["administrator_holder"],
            row["publisher_policy_ref"], row["service_capability_version"],
            row["manifest_digest"], row["source_id"],
            row["max_utc_error_seconds"])
    bindings = {}
    for raw in records("namespace_bindings_v2"):
        row = _record(raw, {
            "certificate_sha256", "profile_id", "bot_id", "persona_id",
            "authority_namespace",
        }, "namespace binding")
        key = (row["certificate_sha256"], row["profile_id"],
               NamespaceId(row["bot_id"], row["persona_id"]))
        if key in bindings:
            raise AuthorityUnavailable("installed namespace binding repeats")
        bindings[key] = row["authority_namespace"]
    reverse = {}
    issuers = {}
    for raw in records("reverse_handoff"):
        row = _record(raw, {
            "namespace", "profile_id", "installation_id", "host", "port",
            "server_name", "expected_host_certificate_sha256", "trust_root",
            "client_certificate", "client_private_key", "timeout_seconds",
            "max_message_bytes", "issuer_id",
        }, "reverse handoff")
        namespace = row["namespace"]
        if type(namespace) is not str or namespace in reverse:
            raise AuthorityUnavailable("installed reverse handoff repeats")
        reverse[namespace] = AdministratorReverseHandoffProfile(
            namespace, row["profile_id"], row["installation_id"],
            row["host"], row["port"], row["server_name"],
            row["expected_host_certificate_sha256"], Path(row["trust_root"]),
            Path(row["client_certificate"]), Path(row["client_private_key"]),
            row["timeout_seconds"], row["max_message_bytes"])
        issuers[namespace] = row["issuer_id"]
    c04 = {}
    if "c04_installations_v2" in manifest:
        for raw in records("c04_installations_v2"):
            row = _record(raw, {"namespace", "package_root",
                                "formal_manifest_sha256", "component_key_path"},
                          "C04 installation")
            namespace = row["namespace"]
            if type(namespace) is not str or namespace in c04:
                raise AuthorityUnavailable("installed C04 namespace repeats")
            c04[namespace] = InstalledC04AuthorityV2(
                row["package_root"], row["formal_manifest_sha256"],
                row["component_key_path"])
    c04_v3 = {}
    if "c04_installations_v3" in manifest:
        for raw in records("c04_installations_v3"):
            row = _record(raw, {"namespace", "package_root",
                                "formal_manifest_sha256", "component_key_path"},
                          "C04 V3 installation")
            namespace = row["namespace"]
            if type(namespace) is not str or namespace in c04_v3:
                raise AuthorityUnavailable("installed C04 V3 namespace repeats")
            c04_v3[namespace] = InstalledC04AuthorityV3(
                row["package_root"], row["formal_manifest_sha256"],
                row["component_key_path"])
    counter_assets = None
    if "d13_counter_assets_v1" in manifest:
        from dataclasses import fields as dataclass_fields
        from .d13_installed_counter_factory_v1 import InstalledD13CounterAssetsV1
        counter_assets = {}
        required = {field.name for field in dataclass_fields(InstalledD13CounterAssetsV1)}
        for raw in records("d13_counter_assets_v1"):
            row = _record(raw, required | {"authority_namespace"}, "D13 counter assets")
            namespace = row.pop("authority_namespace")
            graph_ns = _record(row["namespace"], {"bot_id", "persona_id"}, "D13 Graph namespace")
            if type(namespace) is not str or namespace in counter_assets:
                raise AuthorityUnavailable("installed D13 counter namespace repeats")
            counter_assets[namespace] = InstalledD13CounterAssetsV1(**{**row, "namespace": NamespaceId(**graph_ns)})
    c09 = None
    c09_v2 = None
    if "c09_storage_v1" in manifest and "c09_storage_v2" in manifest:
        raise AuthorityUnavailable("installed C09 V1/V2 selectors are mutually exclusive")
    if "c09_storage_v1" in manifest:
        row = _record(manifest["c09_storage_v1"], {
            "control_path", "key_path", "installation_id", "authority_id",
            "control_store_id", "key_id", "resource_roots"}, "C09 storage")
        if type(row["resource_roots"]) is not list:
            raise AuthorityUnavailable("installed C09 roots must be a list")
        c09 = InstalledC09AuthorityV1(**row)
    if "c09_storage_v2" in manifest:
        row = _record(manifest["c09_storage_v2"], {
            "schema", "control_path", "key_path", "installation_id", "authority_id",
            "control_store_id", "key_id", "resource_roots"}, "C09 V2 storage")
        if type(row["resource_roots"]) is not list:
            raise AuthorityUnavailable("installed C09 V2 roots must be a list")
        c09_v2 = InstalledC09AuthorityV2(**row)
    return AuthorityDeploymentConfig(
        manifest["authority_db"], manifest["deletion_db"],
        manifest["graph_db"], manifest["instance_lock"], journals,
        AuthorityServerTlsConfig(**tls), manifest["bind_host"],
        manifest["bind_port"], installations, bindings, reverse, issuers,
        core_authorizer, core_verifier_factory, administrator_authorizer,
        publisher_manifest_verifier, utc_clock,
        local_administrator_credential, c04_installations_v2=c04,
        c04_installations_v3=c04_v3, c09_storage_v1=c09,
        c09_maintenance_factory=c09_maintenance_factory, c09_storage_v2=c09_v2,
        d13_counter_assets_v1=counter_assets)


__all__ = ("ASSET_MANIFEST_SCHEMA", "AuthorityCoreVerifiers",
           "AuthorityDeploymentConfig", "ExecutionJournalInstallation",
           "InstalledNaturalModelAuthorityV2", "InstalledC04AuthorityV2",
           "InstalledC04AuthorityV3", "InstalledC09AuthorityV1", "InstalledC09AuthorityV2",
           "load_installed_asset_config_v1")
