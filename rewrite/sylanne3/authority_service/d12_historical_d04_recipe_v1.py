"""Retained package identity for historical D04 originals only.

The independently signed execution claim and actual Graph/accounting originals
remain the Authority service's responsibility. This component proves which
registered old recipe describes those bytes. It never issues a claim, current
source qualification, adoption witness, or package compatibility receipt.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import subprocess
import sys
from types import MappingProxyType

from .contract import AuthorityUnavailable
from .d12_package_files_v2 import InstalledPackageSelectionFilesV2, decode_package_selection_v2, _canonical, _sha
from .d12_configuration_cohort_v2 import read_verified_configuration_cohort_v2
from .linux_installation_security_v1 import read_installed_bytes_v1
from ..runtime_contracts import NamespaceId

SCHEMA = "d12.historical-d04-recipe.v1"
PACKET_LIMIT = 32 * 1024 * 1024
RESULT_LIMIT = 128 * 1024
KINDS = frozenset(("numeric", "authored_root"))


def _decode(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate historical verifier field")
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite historical verifier value")))


def _run_retained_recipe_worker_v1(package_root, manifest_sha256, operation, payload):
    """Fixed pure worker; its response is mathematical evidence, never authority.

    The public reader qualifies both roots before calling this primitive. Keeping
    this primitive separate also permits permanent mathematical verification of
    actual retained artifacts without pretending an unprivileged test directory
    is a production package registry.
    """
    if operation not in {"identity", "numeric_math", "authored_root_math"} or not _sha(manifest_sha256):
        raise ValueError("fixed historical verifier operation required")
    packet = _canonical(dict(schema=SCHEMA, package_root=str(package_root),
        manifest_sha256=manifest_sha256, operation=operation, payload=payload))
    if len(packet) > PACKET_LIMIT:
        raise AuthorityUnavailable("historical verifier input exceeds fixed bound")
    worker = Path(__file__).with_name("d12_historical_d04_worker_v1.py")
    try:
        result = subprocess.run([sys.executable, "-I", "-B", str(worker)],
            input=packet, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env={"LANG": "C.UTF-8"}, cwd="/", close_fds=True, timeout=180, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise AuthorityUnavailable("retained recipe verifier unavailable") from exc
    if result.returncode or len(result.stdout) > RESULT_LIMIT:
        # Never echo a historical body or arbitrary child stderr into status.
        raise AuthorityUnavailable("retained recipe pure verification failed")
    value = _decode(result.stdout)
    if (type(value) is not dict or set(value) != {"schema", "request_sha256", "operation", "result"}
            or value["schema"] != SCHEMA or value["operation"] != operation
            or value["request_sha256"] != hashlib.sha256(packet).hexdigest()):
        raise AuthorityUnavailable("historical verifier response binding differs")
    return value["result"]


@dataclass(frozen=True, slots=True)
class HistoricalD04RecipeIdentityV1:
    kind: str
    manifest_sha256: str
    cohort_ref: str
    cohort_digest: str
    current_selection_digest: str
    identity: tuple[tuple[str, str], ...]
    # Deliberately no admission, execution, or trusted-replay flag.


class InstalledHistoricalD04RecipeReaderV1:
    """Production-owned historical recipe inventory, prepared outside SQL.

    Construct after reading actual retained journal/original manifest references.
    Package verification and separate-process imports happen only here. The
    narrow lookup performs bounded protected selection/registry rereads and
    compares an already authenticated original with an already qualified recipe.
    """
    def __init__(self, *, package_files, namespace, installation_id,
                 current_manifest_sha256, historical_eligibility):
        from .d12_public_history_eligibility_v1 import require_actual_historical_eligibility_v1
        retained_manifests = require_actual_historical_eligibility_v1(historical_eligibility,
            package_files=package_files, namespace=namespace, installation_id=installation_id,
            current_manifest_sha256=current_manifest_sha256)
        if (type(package_files) is not InstalledPackageSelectionFilesV2
                or type(namespace) is not NamespaceId or type(installation_id) is not str
                or not _sha(current_manifest_sha256) or type(retained_manifests) is not tuple
                or len(retained_manifests) > 128 or len(set(retained_manifests)) != len(retained_manifests)
                or any(not _sha(value) for value in retained_manifests)):
            raise TypeError("fixed actual historical recipe composition required")
        self._files = package_files
        self._historical_eligibility = historical_eligibility
        selection, current, configuration = package_files.read_selected_configuration_cohort_v2()
        policy = configuration["host_profile"]["installation_policy"]
        if (selection.installation_id != installation_id or current.installation_id != installation_id
                or selection.manifest_sha256 != current_manifest_sha256
                or policy["namespace"] != {"bot_id": namespace.bot_id, "persona_id": namespace.persona_id}
                or Path(__file__).resolve(strict=True) != Path(current.package.package_root) /
                    "rewrite/sylanne3/authority_service/d12_historical_d04_recipe_v1.py"):
            raise AuthorityUnavailable("historical reader is not the selected installed composition")
        self.namespace, self.installation_id = namespace, installation_id
        self.current_manifest_sha256 = current_manifest_sha256
        self.selection = selection
        from .d12_public_history_eligibility_v1 import qualified_registry_commitment_v1
        self._qualified_manifests = tuple(sorted({current_manifest_sha256, *retained_manifests}))
        self._registry_commitment = qualified_registry_commitment_v1(package_files, self._qualified_manifests)
        selection_bytes = read_installed_bytes_v1(package_files.control_directory / "selection.json")
        if decode_package_selection_v2(_decode(selection_bytes)) != selection:
            raise AuthorityUnavailable("package selection changed before historical qualification")
        self._selection_sha = hashlib.sha256(selection_bytes).digest()
        identities, packages = {}, {}
        for manifest in retained_manifests:
            actual_installation, old = package_files.read_registered_cohort_for_manifest_v2(manifest)
            if (actual_installation != installation_id or old.installation_id != installation_id
                    or old.identity_commitment != current.identity_commitment
                    or old.credential_profile_directory != current.credential_profile_directory
                    or old.compatibility_plan_ref != current.compatibility_plan_ref
                    or old.supervisor_policy_digest != current.supervisor_policy_digest):
                raise AuthorityUnavailable("retained cohort changes stable installation authority")
            read_verified_configuration_cohort_v2(old)
            result = _run_retained_recipe_worker_v1(old.package.package_root, manifest, "identity", None)
            if type(result) is not dict or set(result) != KINDS:
                raise AuthorityUnavailable("retained package lacks closed D04 recipe identities")
            for kind, identity in result.items():
                expected = {"algorithm_id", "algorithm_build_digest", "native_manifest_sha256",
                    "native_sha256", "output_policy_digest"}
                if kind == "authored_root":
                    expected |= {"preset_id", "preset_digest"}
                if (type(identity) is not dict or set(identity) != expected
                        or identity["native_manifest_sha256"] != manifest
                        or any(type(value) is not str or not value for value in identity.values())
                        or any(not _sha(identity[key]) for key in expected - {"algorithm_id", "preset_id"})):
                    raise AuthorityUnavailable("retained recipe identity is incomplete")
                identities[(manifest, kind)] = HistoricalD04RecipeIdentityV1(kind, manifest,
                    old.cohort_ref, old.cohort_digest, selection.selection_digest, tuple(sorted(identity.items())))
            packages[manifest] = old.package
        self._identities = MappingProxyType(identities)
        self._packages = MappingProxyType(packages)
        self.require_unchanged_selection_v1()
        actual_selection, actual_cohort, _ = package_files.read_selected_configuration_cohort_v2()
        if actual_selection != selection or actual_cohort != current:
            raise AuthorityUnavailable("current cohort changed during historical qualification")
        self.require_unchanged_selection_v1()

    def require_unchanged_selection_v1(self):
        """Bounded file reads only; never starts SQL, RPC, imports, or a child."""
        from .d12_public_history_eligibility_v1 import require_unchanged_historical_eligibility_v1
        require_unchanged_historical_eligibility_v1(self._historical_eligibility)
        from .d12_public_history_eligibility_v1 import qualified_registry_commitment_v1
        if (hashlib.sha256(read_installed_bytes_v1(self._files.control_directory / "selection.json")).digest() != self._selection_sha
                or qualified_registry_commitment_v1(self._files, self._qualified_manifests) != self._registry_commitment):
            raise AuthorityUnavailable("historical recipe selection or qualified registry cohort changed")

    def require_qualified_recipe_v1(self, binding, *, kind):
        from .d04_numeric_contract_v3 import D04NumericBindingV3
        from .d04_root_execution_contract_v3 import D04RootExecutionBindingV3
        expected_type = {"numeric": D04NumericBindingV3, "authored_root": D04RootExecutionBindingV3}.get(kind)
        if (expected_type is None or type(binding) is not expected_type
                or binding.namespace != self.namespace or binding.installation_id != self.installation_id):
            raise AuthorityUnavailable("historical original installation differs")
        self.require_unchanged_selection_v1()
        identity = self._identities.get((binding.native_manifest_sha256, kind))
        if identity is None or any(getattr(binding, name) != value for name, value in identity.identity):
            raise AuthorityUnavailable("actual historical original has no qualified retained recipe")
        return identity

    def verify_historical_math_v1(self, binding, *, kind, payload):
        """Pure detached evidence only, after caller authenticates current originals.

        Call outside all SQL transactions. Body access still requires the real
        current content/storage/Owner fence. A cost-only or erased body never
        obtains a reconstruction through this method.
        """
        identity = self.require_qualified_recipe_v1(binding, kind=kind)
        package = self._packages[identity.manifest_sha256]
        self._files.verify_registered_package_v2(package)
        result = _run_retained_recipe_worker_v1(package.package_root, identity.manifest_sha256,
            "numeric_math" if kind == "numeric" else "authored_root_math", payload)
        if type(result) is not dict or result.get("binding_digest") != binding.digest:
            raise AuthorityUnavailable("historical math result does not describe the actual original")
        self.require_unchanged_selection_v1()
        return result
