"""Same-resource D04 original interpretation across registered package changes.

This is public Host startup evidence. It does not claim to read private Authority
configuration, authenticate an original, or replace the current Owner/fence.
Only exact unchanged D04 resource bytes are supported by this compatible lane.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
from types import MappingProxyType

from ..authority_service.contract import AuthorityUnavailable
from ..authority_service.d12_package_files_v2 import InstalledPackageSelectionFilesV2, decode_package_selection_v2, _sha
from ..authority_service.d12_configuration_cohort_v2 import read_verified_host_profile_cohort_v2
from ..authority_service.linux_installation_security_v1 import read_installed_bytes_v1
from ..runtime_contracts import NamespaceId

D04_RESOURCE_PATHS_V1 = (
    "resources/catalogue/d04-affect-scheme.json",
    "resources/catalogue/d04-authored-root-preset.v3.json",
    "resources/catalogue/d04-authored-root-topology.v3.json",
    "resources/catalogue/d04-fixed-block-operator.json",
    "resources/catalogue/d04-interval-projection-policy.v2.json",
    "resources/catalogue/d04-joint-state-output-policy.v1.json",
    "resources/catalogue/d04-semantic-mapping-profile.v3.json",
    "resources/catalogue/d04-tanh-readout.v1.json",
)


def _resource_inventory(package):
    raw = read_installed_bytes_v1(Path(package.package_root) / "release-manifest.json", limit=4 * 1024 * 1024)
    if hashlib.sha256(raw).hexdigest() != package.manifest_sha256:
        raise AuthorityUnavailable("D04 historical resource manifest changed")
    manifest = json.loads(raw)
    result = []
    for path in D04_RESOURCE_PATHS_V1:
        entries = [item for item in manifest["files"] if item.get("path") == path]
        content = read_installed_bytes_v1(Path(package.package_root) / path)
        digest = hashlib.sha256(content).hexdigest()
        if len(entries) != 1 or entries[0].get("sha256") != digest or entries[0].get("bytes") != len(content):
            raise AuthorityUnavailable("D04 historical resource is not exactly manifest listed")
        result.append((path, len(content), digest))
    return tuple(result)


@dataclass(frozen=True, slots=True)
class D04HistoricalSemanticAssetsV1:
    original_manifest_sha256: str
    current_manifest_sha256: str
    original_cohort_digest: str
    current_selection_digest: str
    resources: tuple[tuple[str, int, str], ...]


class InstalledHistoricalD04CompatibilityV1:
    """Construct in installed composition, outside Graph/Core transactions."""
    def __init__(self, *, package_files, namespace, installation_id,
                 current_manifest_sha256, historical_eligibility,
                 host_installation=None, authority_private_config=False):
        from ..authority_service.d12_public_history_eligibility_v1 import require_actual_historical_eligibility_v1
        retained_manifests = require_actual_historical_eligibility_v1(historical_eligibility,
            package_files=package_files, namespace=namespace, installation_id=installation_id,
            current_manifest_sha256=current_manifest_sha256)
        if (type(package_files) is not InstalledPackageSelectionFilesV2 or type(namespace) is not NamespaceId
                or type(installation_id) is not str or not installation_id
                or not _sha(current_manifest_sha256) or type(retained_manifests) is not tuple
                or len(retained_manifests) > 128 or len(set(retained_manifests)) != len(retained_manifests)
                or any(not _sha(value) for value in retained_manifests)):
            raise TypeError("actual registered D04 historical composition required")
        selection, current, public_evidence = package_files.read_selected_host_cohort_v2()
        if host_installation is not None:
            from .v2_installation import V2InstallationAssembly
            from .c09_storage_admission_v1 import require_current_selected_host_admission_v2
            if (type(host_installation) is not V2InstallationAssembly or authority_private_config is not False
                    or require_current_selected_host_admission_v2(host_installation.storage_admission,
                        host_installation.admin_bundle, host_installation.package_root) != selection):
                raise AuthorityUnavailable("historical D04 Host lacks actual current Unix cohort admission")
        elif authority_private_config is True:
            actual, actual_cohort, _private_config = package_files.read_selected_configuration_cohort_v2()
            if actual != selection or actual_cohort != current:
                raise AuthorityUnavailable("historical D04 Authority composition differs")
        else:
            raise AuthorityUnavailable("historical D04 needs actual Host admission or private Authority composition")
        policy = public_evidence["host_profile"]["installation_policy"]
        if (selection.installation_id != installation_id or current.installation_id != installation_id
                or current.package.manifest_sha256 != current_manifest_sha256
                or policy["namespace"] != {"bot_id": namespace.bot_id, "persona_id": namespace.persona_id}
                or Path(__file__).resolve(strict=True) != Path(current.package.package_root) /
                    "rewrite/sylanne3/host/installed_d04_historical_compatibility_v1.py"):
            raise AuthorityUnavailable("historical D04 compatibility is not the selected installed code")
        self.namespace, self.installation_id = namespace, installation_id
        self.current_manifest_sha256 = current_manifest_sha256
        self.selection, self.public_evidence = selection, public_evidence
        self._host_installation = host_installation
        self._files = package_files
        self._historical_eligibility = historical_eligibility
        from ..authority_service.d12_public_history_eligibility_v1 import qualified_registry_commitment_v1
        self._qualified_manifests = tuple(sorted({current_manifest_sha256, *retained_manifests}))
        self._registry_commitment = qualified_registry_commitment_v1(package_files, self._qualified_manifests)
        control_raw = {"selection.json": read_installed_bytes_v1(package_files.control_directory / "selection.json")}
        if decode_package_selection_v2(json.loads(control_raw["selection.json"])) != selection:
            raise AuthorityUnavailable("selection changed before D04 historical resource qualification")
        self._control_bytes = {name: hashlib.sha256(raw).digest() for name, raw in control_raw.items()}
        resources = _resource_inventory(current.package)
        qualified = {}
        for manifest in retained_manifests:
            installation, prior = package_files.read_registered_cohort_for_manifest_v2(manifest)
            if (installation != installation_id or prior.installation_id != installation_id
                    or prior.identity_commitment != current.identity_commitment
                    or prior.credential_profile_directory != current.credential_profile_directory
                    or prior.compatibility_plan_ref != current.compatibility_plan_ref
                    or prior.supervisor_policy_digest != current.supervisor_policy_digest):
                raise AuthorityUnavailable("D04 historical cohort changes stable authority")
            read_verified_host_profile_cohort_v2(prior)
            if _resource_inventory(prior.package) != resources:
                raise AuthorityUnavailable("D04 resource changes require an explicit versioned migration")
            qualified[manifest] = D04HistoricalSemanticAssetsV1(manifest, current_manifest_sha256,
                prior.cohort_digest, selection.selection_digest, resources)
        self._qualified = MappingProxyType(qualified)
        self.require_current_selection_v1()
        actual, actual_cohort, _ = package_files.read_selected_host_cohort_v2()
        if actual != selection or actual_cohort != current:
            raise AuthorityUnavailable("current Host cohort changed during historical qualification")
        self.observe_current_process_v1()

    def require_current_selection_v1(self):
        from ..authority_service.d12_public_history_eligibility_v1 import require_unchanged_historical_eligibility_v1
        require_unchanged_historical_eligibility_v1(self._historical_eligibility)
        from ..authority_service.d12_public_history_eligibility_v1 import qualified_registry_commitment_v1
        if qualified_registry_commitment_v1(self._files, self._qualified_manifests) != self._registry_commitment:
            raise AuthorityUnavailable("D04 qualified historical cohort or registry policy changed")
        for name, expected in self._control_bytes.items():
            if hashlib.sha256(read_installed_bytes_v1(self._files.control_directory / name)).digest() != expected:
                raise AuthorityUnavailable("D04 selected cohort or registry changed")

    def observe_current_process_v1(self):
        """Call outside SQL at the actual current-fence observer boundary."""
        self.require_current_selection_v1()
        if self._host_installation is not None:
            from .c09_storage_admission_v1 import require_current_selected_host_admission_v2
            installed = self._host_installation
            if require_current_selected_host_admission_v2(installed.storage_admission,
                    installed.admin_bundle, installed.package_root) != self.selection:
                raise AuthorityUnavailable("historical D04 actual Host cohort admission changed")

    def require_original_manifest_v1(self, manifest):
        """Resource interpretation only; caller must read an actual signed original."""
        self.require_current_selection_v1()
        if not _sha(manifest):
            raise AuthorityUnavailable("D04 original manifest is malformed")
        value = self._qualified.get(manifest)
        if value is None:
            raise AuthorityUnavailable("D04 original manifest lacks retained same-resource qualification")
        return value
