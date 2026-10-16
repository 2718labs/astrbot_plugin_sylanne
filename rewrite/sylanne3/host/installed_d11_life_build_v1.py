"""Actual installed file closure of the fixed Life executor and verifier."""
import hashlib
import hmac
import json
from pathlib import Path

from .installed_package import verify_installed_backend_runtime_v1
from ..runtime_contracts import canonical_digest
from ..authority_service.contract import AuthorityUnavailable


class HistoricalD11LifeKeyUnavailableV1(AuthorityUnavailable):
    """The registered historical selector has no key authenticating its claim."""

EXECUTOR_FILES = (
    "rewrite/sylanne3/runtime/d01_life_activation_original_v1.py",
    "rewrite/sylanne3/runtime/d11_life_scope_v1.py",
    "rewrite/sylanne3/runtime/d08_life_admission_v1.py",
    "rewrite/sylanne3/runtime/d08_source_note_action_v1.py",
    "rewrite/sylanne3/runtime/d02_life_body_preparation_v1.py",
    "rewrite/sylanne3/authority_service/d11_life_execution_inventory_v1.py",
    "rewrite/sylanne3/runtime/d11_life_preparation_v1.py",
    "rewrite/sylanne3/runtime/d02_life_effect_v1.py",
    "rewrite/sylanne3/domains/d03/context.py",
    "rewrite/sylanne3/domains/d05/relationship.py",
    "rewrite/sylanne3/domains/d07/qualified_attention_read.py",
    "rewrite/sylanne3/domains/d08/execution.py",
    "rewrite/sylanne3/authority_service/d11_life_service_v1.py",
    "rewrite/sylanne3/authority_service/d11_bounded_execution_lifecycle_v1.py",
    "rewrite/sylanne3/authority_service/d11_life_journal_v1.py",
    "rewrite/sylanne3/runtime/d11_life_contract_v1.py",
    "rewrite/sylanne3/runtime/d11_life_source_note_v1.py",
    "rewrite/sylanne3/runtime_contracts.py",
    "rewrite/sylanne3/domains/d01/production_operations_v1.py",
)
VERIFIER_FILES = (
    "rewrite/sylanne3/runtime/d11_life_source_note_v1.py",
    "rewrite/sylanne3/runtime/d11_life_contract_v1.py",
    "rewrite/sylanne3/memory_types.py",
    "rewrite/sylanne3/runtime_contracts.py",
    "rewrite/sylanne3/domains/d01/production_operations_v1.py",
)
DRAFT_EXTRA_FILES = (
    "rewrite/sylanne3/runtime/d11_artifact_draft_contract_v1.py",
    "rewrite/sylanne3/authority_service/d11_artifact_draft_executor_v1.py",
    "rewrite/sylanne3/authority_service/current_source_location_v1.py",
    "rewrite/sylanne3/runtime/d01_production_operations_v1.py",
    "rewrite/sylanne3/authority_service/v2_worker_model_result_attempts.py",
)


def read_installed_d11_life_build_v1(package_root, manifest_digest, *, recipe_id="d10.source-note.v1"):
    from ..runtime.d11_artifact_draft_contract_v1 import RECIPE_ID as DRAFT_RECIPE
    if recipe_id not in {"d10.source-note.v1", DRAFT_RECIPE}:
        raise ValueError("only the registered source-note and artifact draft build closures are supported")
    executor_files, verifier_files = EXECUTOR_FILES, VERIFIER_FILES
    build_schema = "d11.life-installed-build.v1"
    if recipe_id == DRAFT_RECIPE:
        extra = DRAFT_EXTRA_FILES
        executor_files = (*EXECUTOR_FILES, *extra)
        verifier_files = (*VERIFIER_FILES, *extra)
        build_schema = "d11.artifact-draft-installed-build.v1"
    root = Path(package_root).resolve(strict=True)
    installed = verify_installed_backend_runtime_v1(root, manifest_digest)
    if not installed.verified or installed.runtime_scope not in {"formal-alpha1", "backend-production-acceptance", "backend-local-alpha2-acceptance", "backend-beta1-server-test"}:
        raise ValueError("Life requires the actual qualified installed backend package")
    manifest = json.loads((root / "release-manifest.json").read_bytes())
    sources = {}
    for relative in set(executor_files + verifier_files):
        rows = tuple(row for row in manifest["files"] if row["path"] == relative)
        path = root / relative
        data = path.read_bytes()
        identity = {"path": relative, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
        if len(rows) != 1 or any(rows[0].get(k) != v for k, v in identity.items()):
            raise ValueError("Life installed build file differs from manifest: " + relative)
        module_path = Path(__file__).resolve().parents[1] / relative.removeprefix("rewrite/sylanne3/")
        if module_path.resolve() != path.resolve():
            raise ValueError("Life loaded source origin differs from installed manifest")
        sources[relative] = identity
    return {name: canonical_digest({"schema": build_schema, "kind": name,
        "manifest_digest": manifest_digest, "files": [sources[p] for p in sorted(paths)]})
        for name, paths in (("algorithm_build_digest", executor_files), ("postcondition_build_digest", verifier_files))}


def read_registered_historical_d11_life_build_v1(package_files, *, binding):
    """Authenticate old registered bytes for passive facts; never execution.

    No arbitrary root or bypass-origin option exists on the execution reader.
    This entry requires the real protected registry, pins the exact old cohort,
    and opens only its root-owned files. It never imports or runs old modules.
    Historical D11 signature material is read by the separate passive key
    reader below; a receipt never selects a key path.
    """
    from ..authority_service.d12_package_files_v2 import InstalledPackageSelectionFilesV2
    from ..authority_service.linux_installation_security_v1 import read_installed_bytes_v1
    from ..runtime.d11_life_contract_v1 import LIFE_BINDING_TYPES
    if type(package_files) is not InstalledPackageSelectionFilesV2 or type(binding) not in LIFE_BINDING_TYPES:
        raise TypeError("historical Life facts require the actual protected registry and closed original binding")
    installation_id, cohort = package_files.read_registered_cohort_for_manifest_v2(binding.manifest_digest)
    if installation_id != binding.installation_id:
        raise ValueError("historical Life package belongs to another installed identity")
    package = cohort.package
    root = Path(package.package_root)
    manifest_bytes = read_installed_bytes_v1(root / "release-manifest.json", limit=4 * 1024 * 1024)
    if hashlib.sha256(manifest_bytes).hexdigest() != binding.manifest_digest:
        raise ValueError("historical registered Life manifest bytes changed")
    manifest = json.loads(manifest_bytes)
    if (manifest.get("schema_version") != 1 or manifest.get("package_version") != package.package_version
            or type(manifest.get("files")) is not list or not manifest["files"]):
        raise ValueError("historical registered Life manifest shape differs")
    # The protected cohort pins the external configuration/key selectors.
    # Check those exact bytes without applying today's runtime catalogue to
    # the old package or claiming old code is runnable on the current host.
    for item in cohort.files:
        data = read_installed_bytes_v1(item.path, limit=4 * 1024 * 1024)
        if hashlib.sha256(data).hexdigest() != item.sha256:
            raise ValueError("historical Life protected configuration/key selector changed")
    if binding.recipe_id == "d10.source-note.v1":
        executors, verifiers, schema = EXECUTOR_FILES, VERIFIER_FILES, "d11.life-installed-build.v1"
    elif binding.recipe_id == "artifact_draft_v1":
        executors, verifiers, schema = (*EXECUTOR_FILES, *DRAFT_EXTRA_FILES), (*VERIFIER_FILES, *DRAFT_EXTRA_FILES), "d11.artifact-draft-installed-build.v1"
    else:
        raise ValueError("unknown historical Life recipe version")
    sources = {}
    for relative in set(executors + verifiers):
        rows = tuple(row for row in manifest["files"] if row.get("path") == relative)
        data = read_installed_bytes_v1(root / relative, limit=4 * 1024 * 1024)
        identity = {"path": relative, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
        if len(rows) != 1 or any(rows[0].get(key) != value for key, value in identity.items()):
            raise ValueError("historical Life original closure file changed: " + relative)
        sources[relative] = identity
    if package_files.read_registered_cohort_for_manifest_v2(binding.manifest_digest) != (installation_id, cohort):
        raise ValueError("historical Life registry changed during passive verification")
    build = {name: canonical_digest({"schema": schema, "kind": name,
        "manifest_digest": binding.manifest_digest, "files": [sources[path] for path in sorted(paths)]})
        for name, paths in (("algorithm_build_digest", executors), ("postcondition_build_digest", verifiers))}
    if any(getattr(binding, name) != value for name, value in build.items()):
        raise ValueError("historical Life original does not match its exact registered old bytes")
    return build


def read_registered_historical_d11_life_key_v1(package_files, *, binding, claim):
    """Read the old cohort's protected D11 selector and authenticate its claim.

    Registered cohorts pin the credential directory, but their old schema
    does not contain a key-byte digest. Therefore an overwritten/rotated key
    is accepted only if its actual bytes authenticate this original signed
    claim; a same path or a current bundle is never evidence of key equality.
    """
    from ..authority_service.linux_installation_security_v1 import (
        read_installed_bytes_v1, read_installed_json_v1,
    )
    from ..authority_service.d12_configuration_cohort_v2 import derive_cohort_identity_commitment_v2
    from ..runtime.d11_life_contract_v1 import LIFE_START_TYPES, life_to_wire_v1, life_mutation_id_v1
    from ..runtime_contracts import canonical_serialize
    if (type(claim) not in LIFE_START_TYPES or claim.binding_digest != binding.digest
            or claim.execution_id != binding.execution_id
            or claim.executor_installation_id != binding.installation_id
            or claim.claim_id != life_mutation_id_v1(binding, "claim")):
        raise HistoricalD11LifeKeyUnavailableV1("historical Life key requires the exact original signed claim")
    read_registered_historical_d11_life_build_v1(package_files, binding=binding)
    installation_id, cohort = package_files.read_registered_cohort_for_manifest_v2(binding.manifest_digest)
    values = {}
    for item in cohort.files:
        raw = read_installed_bytes_v1(item.path, limit=1048576)
        if hashlib.sha256(raw).hexdigest() != item.sha256:
            raise HistoricalD11LifeKeyUnavailableV1("historical Life protected selector changed")
        values[item.role] = read_installed_json_v1(item.path)
        if hashlib.sha256(read_installed_bytes_v1(item.path)).hexdigest() != item.sha256:
            raise HistoricalD11LifeKeyUnavailableV1("historical Life selector changed while reading")
    identity = derive_cohort_identity_commitment_v2(deployment=values["deployment"],
        assets=values["assets"], profile=values["host_profile"], package=cohort.package,
        credential_profile_directory=cohort.credential_profile_directory)
    policy = values["host_profile"]["installation_policy"]
    if (installation_id != binding.installation_id or identity != cohort.identity_commitment
            or policy["installation_id"] != binding.installation_id
            or policy["expected_authority_id"] != binding.authority_id
            or policy["authority_namespace"] != binding.authority_namespace
            or policy["namespace"] != {"bot_id": binding.namespace.bot_id, "persona_id": binding.namespace.persona_id}):
        raise HistoricalD11LifeKeyUnavailableV1("historical Life selector crossed original installation")
    # Existing schema-2 Host D11 selector is fixed, not receipt-controlled.
    key_path = Path(cohort.credential_profile_directory) / "d11-signing.key"
    try:
        raw_key = read_installed_bytes_v1(key_path, limit=32, private=True,
            allowed_gid=values["deployment"]["host_gid"])
    except (OSError, AuthorityUnavailable) as exc:
        raise HistoricalD11LifeKeyUnavailableV1("registered historical D11 key unavailable") from exc
    if len(raw_key) != 32:
        raise HistoricalD11LifeKeyUnavailableV1("registered historical D11 key bytes differ")
    key = hmac.new(raw_key, b"sylanne.authority.d11-life-signing.v1", hashlib.sha256).digest()
    payload = life_to_wire_v1(claim)
    signature = payload.pop("signature")
    if not hmac.compare_digest(signature, hmac.new(key,
            canonical_serialize(payload).encode(), hashlib.sha256).hexdigest()):
        raise HistoricalD11LifeKeyUnavailableV1("registered D11 key does not authenticate historical claim")
    if package_files.read_registered_cohort_for_manifest_v2(binding.manifest_digest) != (installation_id, cohort):
        raise HistoricalD11LifeKeyUnavailableV1("historical Life selector changed during key qualification")
    return key
