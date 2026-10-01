"""Check installed release bytes against an administrator-pinned manifest."""

from __future__ import annotations

from dataclasses import dataclass, replace
import hashlib
import hmac
import json
import os
from pathlib import Path
import platform
import re
from typing import Literal


_MANIFEST = "release-manifest.json"
_NATIVE_NAMES = {
    "windows": "sylanne3_kernel.dll",
    "linux": "libsylanne3_kernel.so",
    "macos": "libsylanne3_kernel.dylib",
}
_ARCHES = {
    "windows": {"x86_64"},
    "linux": {"x86_64", "aarch64"},
    "macos": {"x86_64", "aarch64"},
}
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")

VerificationReason = Literal[
    "verified", "invalid_expected_digest", "manifest_missing", "manifest_digest_mismatch",
    "manifest_invalid", "platform_mismatch", "abi_mismatch", "cpu_features_unverified",
    "file_mismatch", "unlisted_executable", "unsafe_package_path", "scan_failed",
    "runtime_unqualified",
]


@dataclass(frozen=True, slots=True)
class InstalledPackageVerification:
    verified: bool
    reason: VerificationReason
    manifest_digest: str | None = None
    package_version: str | None = None
    build_mode: str | None = None
    candidate_scope: str | None = None
    failed_path: str | None = None
    runtime_scope: str | None = None
    catalogue_hash: str | None = None


@dataclass(frozen=True, slots=True)
class BackendCandidateQualification:
    """Verified candidate scope; neither installation authority nor delivery readiness."""

    qualified: bool
    reason: str
    manifest_digest: str | None = None
    catalogue_hash: str | None = None
    runtime_scope: str | None = None


def verify_backend_candidate_qualification(
    package_root: Path | str,
    expected_manifest_digest: str,
    *,
    available_cpu_features: frozenset[str] | None = None,
) -> BackendCandidateQualification:
    """Verify a pinned backend candidate against its active 13-domain registry.

    Schema V1 retains diagnostics-only semantics. Schema V2 admits production
    acceptance mechanics; each effect still needs installed Authority admission.
    """
    installed = verify_installed_package(
        package_root, expected_manifest_digest,
        available_cpu_features=available_cpu_features,
    )
    is_snapshot = installed.build_mode == "snapshot-alpha1-test"
    if (not installed.verified or installed.build_mode not in {"backend-alpha1-candidate", "snapshot-alpha1-test"}
            or installed.candidate_scope != ("alpha1-test" if is_snapshot else "backend-only")):
        return BackendCandidateQualification(False, "candidate_package_unverified")
    root = Path(package_root).absolute()
    try:
        manifest_path = _safe_file(root, _MANIFEST)
        if manifest_path is None:
            raise ValueError("manifest_missing")
        manifest_bytes = manifest_path.read_bytes()
        if not hmac.compare_digest(hashlib.sha256(manifest_bytes).hexdigest(), expected_manifest_digest):
            raise ValueError("manifest_changed_after_verification")
        manifest = json.loads(manifest_bytes)
        qualification = manifest.get("backend_qualification")
        schemas = {
            "sylanne.backend-alpha1-candidate-qualification.v1": False,
            "sylanne.backend-alpha1-candidate-qualification.v2": True,
            "sylanne.alpha1-test-snapshot-qualification.v1": True,
        }
        if type(qualification) is not dict or qualification.get("schema") not in schemas:
            raise ValueError("qualification_schema_invalid")
        production = schemas[qualification["schema"]]
        if is_snapshot:
            from .alpha1_test_snapshot_v1 import QUALIFICATION_SCHEMA, validate_test_snapshot_manifest_v1
            if qualification["schema"] != QUALIFICATION_SCHEMA:
                raise ValueError("test_snapshot_qualification_schema_invalid")
            validate_test_snapshot_manifest_v1(manifest)
        elif qualification["schema"] == "sylanne.alpha1-test-snapshot-qualification.v1":
            raise ValueError("test_snapshot_mode_required")
        runtime_scope = ("backend-production-acceptance" if production
                         else "limited-diagnostics")
        effect_gate = ("requires_installed_authority_and_current_effect_admission"
                       if production else "disabled")
        expected_gates = [
            "catalogue_runtime_verified", "migration_validated",
            "formal_alpha1_source_freeze", "full_host_acceptance",
        ]
        if (not isinstance(qualification, dict)
                or qualification.get("status") != ("alpha1_test_snapshot" if is_snapshot else "backend_candidate")
                or qualification.get("product_status") != ("test_snapshot" if is_snapshot else "candidate_only")
                or qualification.get("runtime_scope") != runtime_scope
                or qualification.get("message_processing") != effect_gate
                or qualification.get("outbound_sending") != effect_gate
                or qualification.get("unmet_product_gates") != expected_gates
                or qualification.get("native_abi_version") != 2
                or qualification.get("native_math_contract") != "abi2.fixed-block-interval.v1"
                or qualification.get("fresh_install_only") is not True):
            raise ValueError("qualification_binding_invalid")
        if qualification.get("registry_source") != "sylanne3.domain_registry:discover_domain_registry":
            raise ValueError("qualification_registry_source_invalid")
        catalogue_path = _safe_file(root, "resources/catalogue/current.json")
        migration_path = _safe_file(root, "resources/migrations/v1.json")
        scheme_path = _safe_file(root, "resources/catalogue/d04-affect-scheme.json")
        if any(path is None for path in (catalogue_path, migration_path, scheme_path)):
            raise ValueError("qualification_resource_missing")
        catalogue = json.loads(catalogue_path.read_bytes())
        migration = json.loads(migration_path.read_bytes())
        scheme_data = json.loads(scheme_path.read_bytes())
        domains = [f"d{number:02d}" for number in range(1, 14)]
        if (catalogue.get("activation_status") != "candidate_only"
                or not str(catalogue.get("release_eligibility", "")).startswith("HOLD:")
                or catalogue.get("declared_domains") != domains
                or catalogue.get("missing_domain_exports") != []
                or qualification.get("catalogue_hash") != catalogue.get("catalogue_hash")
                or qualification.get("domains") != domains
                or qualification.get("catalogue_status") != "candidate_only"
                or qualification.get("catalogue_release_eligibility") != catalogue.get("release_eligibility")):
            raise ValueError("catalogue_candidate_binding_invalid")
        if (migration.get("legacy_data_policy") != "registered_migrators"
                or not str(migration.get("release_eligibility", "")).startswith("HOLD:")
                or any(type(item) is not dict
                       or item.get("activation") != "prohibited_preview_only"
                       for item in migration.get("migrations", []))):
            raise ValueError("migration_fresh_install_gate_invalid")
        migration_binding = qualification.get("migration_policy")
        expected_native_policy = {
            "schema": "sylanne.native-data-policy.v1",
            "startup_gate": "sylanne3.host.legacy_data_preflight:inspect_native_data_dir_v1",
            "graph_file": "sylanne3.sqlite3",
            "allowed_graph_sidecars": ["sylanne3.sqlite3-wal", "sylanne3.sqlite3-shm"],
            "fresh_install": "absent_or_empty_plugin_data_dir_only",
            "existing_native": "exact_catalogue_and_authority_recovery_required",
            "other_data": "migration_required_before_graph_open",
            "automatic_legacy_migration": False,
        }
        if (not isinstance(migration_binding, dict)
                or migration_binding.get("sha256") != hashlib.sha256(migration_path.read_bytes()).hexdigest()
                or migration_binding.get("legacy_data_policy") != migration.get("legacy_data_policy")
                or migration_binding.get("native_data_policy") != expected_native_policy
                or migration.get("native_data_policy") != expected_native_policy
                or migration_binding.get("activation") != "prohibited_preview_only"):
            raise ValueError("migration_binding_invalid")

        expected_asset_fields = {
            "context_scheme": ("resources/catalogue/d03-neutral-context-scheme.json", "context_scheme"),
            "affect_scheme": ("resources/catalogue/d04-affect-scheme.json", "affect_scheme"),
            "fixed_block_operator": ("resources/catalogue/d04-fixed-block-operator.json", "fixed_block_operator"),
            "tanh_readout": ("resources/catalogue/d04-tanh-readout.v1.json", "tanh_readout"),
        }
        if production:
            expected_asset_fields.update({
                "interval_projection_policy": (
                    "resources/catalogue/d04-interval-projection-policy.v2.json",
                    "interval_projection_policy"),
                "joint_state_output_policy": (
                    "resources/catalogue/d04-joint-state-output-policy.v1.json",
                    "joint_state_output_policy"),
                "authored_root_topology": (
                    "resources/catalogue/d04-authored-root-topology.v3.json", "authored_root_topology"),
                "semantic_mapping_profile": (
                    "resources/catalogue/d04-semantic-mapping-profile.v3.json",
                    "semantic_mapping_profile"),
                "authored_root_preset": (
                    "resources/catalogue/d04-authored-root-preset.v3.json",
                    "authored_root_preset"),
            })
        asset_bindings = qualification.get("assets")
        if not isinstance(asset_bindings, dict):
            raise ValueError("qualification_assets_missing")
        files = {row["path"]: row for row in manifest["files"] if isinstance(row, dict)}
        for name, (relative, manifest_name) in expected_asset_fields.items():
            asset = asset_bindings.get(name)
            claim = manifest.get(manifest_name)
            entry = files.get(relative)
            path = _safe_file(root, relative)
            if (not isinstance(asset, dict) or asset.get("path") != relative
                    or not isinstance(claim, dict) or claim.get("path") != relative
                    or not isinstance(entry, dict) or path is None
                    or asset.get("sha256") != entry.get("sha256")
                    or claim.get("sha256") != entry.get("sha256")
                    or hashlib.sha256(path.read_bytes()).hexdigest() != entry.get("sha256")):
                raise ValueError(f"qualification_asset_binding_invalid:{name}")

        from ..domain_registry import discover_domain_registry
        from ..domains.d04 import AffectAxis, AffectScheme

        scheme = AffectScheme(
            schema=scheme_data["schema"],
            scheme_version=scheme_data["scheme_version"],
            operator_version=scheme_data["operator_version"],
            parameter_version=scheme_data["parameter_version"],
            coupling_version=scheme_data["coupling_version"],
            axes=tuple(AffectAxis(**axis) for axis in scheme_data["axes"]),
            parameter_bounds=tuple(tuple(item) for item in scheme_data["parameter_bounds"]),
        )
        registry = discover_domain_registry(active_affect_scheme=scheme)
        if (not registry.complete
                or registry.required_domains != tuple(domains)
                or registry.type_registry.catalogue_hash != catalogue.get("catalogue_hash")):
            raise ValueError("active_registry_mismatch")
        if production:
            expected_fields = {
                "schema", "status", "product_status", "runtime_scope", "message_processing",
                "outbound_sending", "unmet_product_gates", "catalogue_hash", "domains",
                "registry_source", "catalogue_status", "catalogue_release_eligibility",
                "native_abi_version", "native_math_contract", "fresh_install_only",
                "migration_policy", "assets",
            }
            source = manifest.get("source")
            if (set(qualification) != expected_fields
                    or type(source) is not dict or type(source.get("dirty")) is not bool
                    or type(source.get("git_sha")) is not str
                    or re.fullmatch(r"[0-9a-f]{40,64}", source["git_sha"]) is None):
                raise ValueError("production_qualification_identity_invalid")
            _verify_source_inventory_v1(manifest)
        return BackendCandidateQualification(
            True, ("verified_backend_candidate_production_acceptance" if production
                   else "verified_backend_candidate_diagnostics_only"),
            expected_manifest_digest, registry.type_registry.catalogue_hash,
            runtime_scope,
        )
    except (OSError, UnicodeDecodeError, KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        return BackendCandidateQualification(False, str(exc), expected_manifest_digest)


def _verify_source_inventory_v1(manifest: dict) -> None:
    """Bind all packaged non-native source/resource bytes, including dirty edits."""
    inventory = manifest.get("source_inventory")
    native = manifest.get("native")
    rows = manifest.get("files")
    if (type(inventory) is not dict or type(native) is not dict
            or type(rows) is not list
            or set(inventory) != {"schema", "files", "sha256"}
            or inventory.get("schema") != "sylanne.packaged-source-inventory.v1"):
        raise ValueError("source_inventory_invalid")
    expected = sorted((row for row in rows if row["path"] != native["path"]),
                      key=lambda row: row["path"])
    encoded = json.dumps(expected, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=True).encode("utf-8")
    if (inventory.get("files") != expected
            or inventory.get("sha256") != hashlib.sha256(encoded).hexdigest()):
        raise ValueError("source_inventory_binding_invalid")


def verify_installed_backend_runtime_v1(
    package_root: Path | str, expected_manifest_digest: str, *,
    available_cpu_features: frozenset[str] | None = None,
) -> InstalledPackageVerification:
    """Verify production runtime bytes and scope without granting any effect.

    Formal delivery keeps its READY/clean/version requirements. A freshly pinned
    V2 candidate may enter backend acceptance using the same production ports.
    V1 diagnostics and dev probes cannot obtain production scope here.
    """
    installed = verify_installed_package(
        package_root, expected_manifest_digest,
        available_cpu_features=available_cpu_features,
    )
    if not installed.verified:
        return installed
    if installed.build_mode in {"backend-alpha1-candidate", "snapshot-alpha1-test"}:
        qualified = verify_backend_candidate_qualification(
            package_root, expected_manifest_digest,
            available_cpu_features=available_cpu_features,
        )
        if qualified.qualified and qualified.runtime_scope == "backend-production-acceptance":
            return replace(installed, runtime_scope=qualified.runtime_scope,
                           catalogue_hash=qualified.catalogue_hash)
        return replace(installed, verified=False, reason="runtime_unqualified")
    if installed.build_mode != "formal-alpha1" or installed.package_version != "3.0.0-alpha1":
        return replace(installed, verified=False, reason="runtime_unqualified")
    root = Path(package_root).absolute()
    try:
        manifest_path = _safe_file(root, _MANIFEST)
        if manifest_path is None:
            raise ValueError("manifest_missing")
        manifest_bytes = manifest_path.read_bytes()
        if hashlib.sha256(manifest_bytes).hexdigest() != expected_manifest_digest:
            raise ValueError("manifest_changed")
        manifest = json.loads(manifest_bytes)
        source = manifest.get("source")
        if (type(source) is not dict or source.get("dirty") is not False
                or type(source.get("git_sha")) is not str
                or re.fullmatch(r"[0-9a-f]{40,64}", source["git_sha"]) is None
                or "backend_qualification" in manifest):
            raise ValueError("formal_source_invalid")
        catalogue_path = _safe_file(root, "resources/catalogue/current.json")
        scheme_path = _safe_file(root, "resources/catalogue/d04-affect-scheme.json")
        migration_path = _safe_file(root, "resources/migrations/v1.json")
        if any(path is None for path in (catalogue_path, scheme_path, migration_path)):
            raise ValueError("formal_resources_missing")
        catalogue = json.loads(catalogue_path.read_bytes())
        scheme_data = json.loads(scheme_path.read_bytes())
        migration = json.loads(migration_path.read_bytes())
        domains = [f"d{number:02d}" for number in range(1, 14)]
        if (catalogue.get("activation_status") != "runtime_verified"
                or catalogue.get("release_eligibility") != "READY"
                or catalogue.get("declared_domains") != domains
                or catalogue.get("missing_domain_exports") != []
                or migration.get("legacy_data_policy") != "registered_migrators"
                or migration.get("native_data_policy", {}).get("automatic_legacy_migration") is not False
                or not migration.get("migrations")):
            raise ValueError("formal_catalogue_invalid")
        if installed.candidate_scope == "backend-only":
            if (not str(migration.get("release_eligibility", "")).startswith("HOLD:")
                    or any(item.get("activation") != "prohibited_preview_only"
                           for item in migration["migrations"])):
                raise ValueError("formal_backend_migration_invalid")
        elif (migration.get("release_eligibility") != "READY"
              or any(item.get("activation") != "validated"
                     for item in migration["migrations"])):
            raise ValueError("formal_migration_invalid")
        from ..domain_registry import discover_domain_registry
        from ..domains.d04 import AffectAxis, AffectScheme

        scheme = AffectScheme(
            schema=scheme_data["schema"], scheme_version=scheme_data["scheme_version"],
            operator_version=scheme_data["operator_version"],
            parameter_version=scheme_data["parameter_version"],
            coupling_version=scheme_data["coupling_version"],
            axes=tuple(AffectAxis(**axis) for axis in scheme_data["axes"]),
            parameter_bounds=tuple(tuple(item) for item in scheme_data["parameter_bounds"]),
        )
        registry = discover_domain_registry(active_affect_scheme=scheme)
        if (not registry.complete or registry.required_domains != tuple(domains)
                or registry.type_registry.catalogue_hash != catalogue.get("catalogue_hash")):
            raise ValueError("formal_active_registry_mismatch")
        return replace(installed, runtime_scope="formal-alpha1",
                       catalogue_hash=registry.type_registry.catalogue_hash)
    except (OSError, UnicodeDecodeError, KeyError, TypeError, ValueError):
        return replace(installed, verified=False, reason="runtime_unqualified")


def _host_target() -> tuple[str | None, str | None]:
    os_name = {"Windows": "windows", "Linux": "linux", "Darwin": "macos"}.get(platform.system())
    arch = {
        "AMD64": "x86_64", "x86_64": "x86_64", "aarch64": "aarch64", "arm64": "aarch64",
    }.get(platform.machine())
    return os_name, arch


def _is_link(path: Path) -> bool:
    return path.is_symlink() or bool(getattr(path, "is_junction", lambda: False)())


def _safe_file(root: Path, relative: str) -> Path | None:
    if (not relative or "\\" in relative or "\x00" in relative or relative.startswith("/")):
        return None
    parts = relative.split("/")
    if any(part in {"", ".", ".."} for part in parts) or ":" in parts[0]:
        return None
    path = root
    for part in parts:
        path = path / part
        if _is_link(path):
            return None
    return path if path.is_file() else None


def _is_executable_file(name: str) -> bool:
    lowered = name.casefold()
    return (lowered.endswith((".py", ".pyc", ".pyw", ".pyd", ".dll", ".dylib", ".so", ".exe"))
            or ".so." in lowered)


def _unlisted_executable(root: Path, listed: dict[str, dict]) -> str | None:
    def raise_walk_error(error: OSError) -> None:
        raise error

    for directory, dirs, files in os.walk(root, followlinks=False, onerror=raise_walk_error):
        folder = Path(directory)
        dirs[:] = [name for name in dirs if name != "__pycache__"]
        for name in dirs:
            candidate = folder / name
            if _is_link(candidate):
                return candidate.relative_to(root).as_posix()
        for name in files:
            if not _is_executable_file(name):
                continue
            candidate = folder / name
            relative = candidate.relative_to(root).as_posix()
            if relative not in listed or _is_link(candidate):
                return relative
    return None


def verify_installed_package(
    package_root: Path | str,
    expected_manifest_digest: str,
    *,
    available_cpu_features: frozenset[str] | None = None,
) -> InstalledPackageVerification:
    """Verify an extracted package; never turn this result into admission alone.

    ``available_cpu_features`` must come from a trusted host probe. A package
    requiring features cannot pass if the host has not supplied that evidence.
    """
    if not isinstance(expected_manifest_digest, str) or not _DIGEST.fullmatch(expected_manifest_digest):
        return InstalledPackageVerification(False, "invalid_expected_digest")
    root = Path(package_root).absolute()
    if any(_is_link(candidate) for candidate in (root, *root.parents)):
        return InstalledPackageVerification(False, "unsafe_package_path")
    manifest_path = _safe_file(root, _MANIFEST)
    if manifest_path is None:
        return InstalledPackageVerification(False, "manifest_missing")
    try:
        manifest_bytes = manifest_path.read_bytes()
    except OSError:
        return InstalledPackageVerification(False, "manifest_missing")
    digest = hashlib.sha256(manifest_bytes).hexdigest()
    if not hmac.compare_digest(digest, expected_manifest_digest):
        return InstalledPackageVerification(False, "manifest_digest_mismatch", digest)
    invalid = InstalledPackageVerification(False, "manifest_invalid", digest)
    try:
        manifest = json.loads(manifest_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return invalid
    if not isinstance(manifest, dict) or type(manifest.get("schema_version")) is not int or manifest["schema_version"] != 1:
        return invalid
    version = manifest.get("package_version")
    mode = manifest.get("build_mode")
    target = manifest.get("platform")
    native = manifest.get("native")
    entries = manifest.get("files")
    if (not isinstance(version, str) or not version
            or mode not in {"dev-probe", "formal-alpha1", "backend-alpha1-candidate", "snapshot-alpha1-test"}
            or not isinstance(target, dict) or not isinstance(native, dict)
            or not isinstance(entries, list) or not entries):
        return invalid
    scope = manifest.get("candidate_scope")
    if mode == "snapshot-alpha1-test":
        try:
            from .alpha1_test_snapshot_v1 import validate_test_snapshot_manifest_v1
            validate_test_snapshot_manifest_v1(manifest)
        except (ValueError, TypeError, KeyError):
            return invalid
    qualifier = manifest.get("backend_qualification")
    production_candidate = (type(qualifier) is dict and qualifier.get("schema")
                            == "sylanne.backend-alpha1-candidate-qualification.v2")
    if ((mode == "backend-alpha1-candidate"
         and (scope != "backend-only" or not production_candidate
              and version != "3.0.0-dev.1"))
            or (mode == "formal-alpha1" and scope not in {None, "backend-only"})
            or (mode == "dev-probe" and scope not in {None, "backend-only"})):
        return invalid
    os_name, arch = target.get("os"), target.get("arch")
    if (os_name not in _NATIVE_NAMES or arch not in _ARCHES[os_name]
            or target.get("native_filename") != _NATIVE_NAMES[os_name]):
        return invalid
    host_os, host_arch = _host_target()
    if (os_name, arch) != (host_os, host_arch):
        return InstalledPackageVerification(False, "platform_mismatch", digest)
    if type(target.get("abi_version")) is not int or target["abi_version"] != 2:
        return InstalledPackageVerification(False, "abi_mismatch", digest)
    if manifest.get("native_math") != {
        "contract": "abi2.fixed-block-interval.v1", "capability_flags": 1,
    }:
        return invalid
    libc = target.get("libc")
    if os_name == "linux":
        if libc not in {"glibc", "musl"}:
            return invalid
        if platform.libc_ver()[0] != libc:
            return InstalledPackageVerification(False, "platform_mismatch", digest)
    elif libc is not None:
        return invalid
    features = target.get("cpu_features")
    if (not isinstance(features, list) or any(not isinstance(item, str) for item in features)
            or features != sorted(set(features))
            or any(not re.fullmatch(r"[a-z0-9][a-z0-9_.+-]*", item) for item in features)):
        return invalid
    if not set(features).issubset(available_cpu_features or frozenset()):
        return InstalledPackageVerification(False, "cpu_features_unverified", digest)

    listed: dict[str, dict] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            return invalid
        relative = entry.get("path")
        size = entry.get("bytes")
        sha = entry.get("sha256")
        if (not isinstance(relative, str) or relative == _MANIFEST or relative in listed
                or type(size) is not int or size < 0 or not isinstance(sha, str)
                or not _DIGEST.fullmatch(sha)):
            return invalid
        listed[relative] = entry
    native_path = f"rewrite/sylanne3/_native/{os_name}-{arch}/{_NATIVE_NAMES[os_name]}"
    if native_path not in listed or native != listed[native_path]:
        return invalid
    if mode in {"backend-alpha1-candidate", "snapshot-alpha1-test"}:
        required = {
            "rewrite/sylanne3/domain_registry.py",
            "rewrite/sylanne3/host/legacy_data_preflight.py",
            "rewrite/sylanne3/native_runtime/__init__.py",
            "rewrite/sylanne3/workbench_api/__init__.py",
            *(f"rewrite/sylanne3/domains/d{number:02d}/__init__.py"
              for number in range(1, 14)),
            "resources/catalogue/current.json",
            "resources/catalogue/d01-onboarding-presets.json",
            "resources/catalogue/d03-neutral-context-scheme.json",
            "resources/catalogue/d04-affect-scheme.json",
            "resources/catalogue/d04-fixed-block-operator.json",
            "resources/catalogue/d04-tanh-readout.v1.json",
            "resources/migrations/README.md",
            "resources/migrations/v1.json",
        }
        if not required.issubset(listed):
            return invalid
    for relative, entry in listed.items():
        path = _safe_file(root, relative)
        if path is None:
            return InstalledPackageVerification(False, "file_mismatch", digest, failed_path=relative)
        sha = hashlib.sha256()
        size = 0
        try:
            with path.open("rb") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    size += len(chunk)
                    sha.update(chunk)
        except OSError:
            return InstalledPackageVerification(False, "file_mismatch", digest, failed_path=relative)
        if size != entry["bytes"] or not hmac.compare_digest(sha.hexdigest(), entry["sha256"]):
            return InstalledPackageVerification(False, "file_mismatch", digest, failed_path=relative)
    try:
        extra = _unlisted_executable(root, listed)
    except OSError:
        return InstalledPackageVerification(False, "scan_failed", digest)
    if extra is not None:
        return InstalledPackageVerification(False, "unlisted_executable", digest, failed_path=extra)
    return InstalledPackageVerification(
        True, "verified", digest, version, mode, scope,
    )
