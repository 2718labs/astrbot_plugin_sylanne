"""Public, signed, content-free historical package qualification.

The protected supervisor publishes only after reading actual signed selection,
compatibility and four-store backup observations. Host readers never open the
private supervisor database. Parsed or self-hashed request DTOs cannot produce
the process-local qualification consumed by installed historical readers.
"""
from dataclasses import asdict, dataclass
import hashlib
import json
import os
import fcntl
from pathlib import Path
from uuid import uuid4
from weakref import WeakValueDictionary

from .contract import AuthorityUnavailable
from .d12_package_files_v2 import InstalledPackageSelectionFilesV2, PackageSelectionV2, decode_package_selection_v2, _canonical, _sha, _protected_directory
from .d12_package_history_eligibility_v1 import InstalledPackageHistoryEligibilityV1
from .d12_package_supervisor_journal_v2 import InstalledPackageSupervisorJournalV2, _SupervisorJournalKernelV2
from .d12_historical_manifest_inventory_v1 import decode_historical_manifest_inventory_v1
from .d12_managed_backup_v2 import decode_managed_backup_v2
from .linux_installation_security_v1 import read_installed_bytes_v1, require_linux_administrator_v1
from ..runtime_contracts import NamespaceId, canonical_digest

SCHEMA = "d12.public-historical-package-eligibility.v1"
DOMAIN = b"sylanne3.d12.public-historical-package-eligibility.v1\0"
_ISSUED = WeakValueDictionary()


def qualified_registry_commitment_v1(package_files, manifests):
    """Short protected read of exactly the already-qualified cohort identities.

    Registering an unrelated future candidate does not revoke current readers
    and does not confer any historical eligibility on that candidate.
    """
    from .d12_package_files_v2 import REGISTRY_SCHEMA, _decode_bytes
    from .d12_configuration_cohort_v2 import decode_configuration_cohort_v2
    if (type(package_files) is not InstalledPackageSelectionFilesV2
            or type(manifests) is not tuple or not manifests or len(manifests) > 128
            or manifests != tuple(sorted(set(manifests))) or any(not _sha(m) for m in manifests)):
        raise AuthorityUnavailable("exact previously qualified registry manifest set required")
    raw = _decode_bytes(read_installed_bytes_v1(package_files.control_directory / "registry.json"))
    if (type(raw) is not dict or set(raw) != {"schema", "installation_id", "cohorts", "maintenance_policy"}
            or raw["schema"] != REGISTRY_SCHEMA or type(raw["cohorts"]) is not list
            or not 1 <= len(raw["cohorts"]) <= 128):
        raise AuthorityUnavailable("closed protected package registry required")
    policy = raw["maintenance_policy"]
    if (type(policy) is not dict or set(policy) != {"compatibility_plan_ref", "supervisor_policy_digest"}
            or type(policy["compatibility_plan_ref"]) is not str or not policy["compatibility_plan_ref"]
            or not _sha(policy["supervisor_policy_digest"])):
        raise AuthorityUnavailable("fixed historical registry policy differs")
    cohorts = tuple(decode_configuration_cohort_v2(value) for value in raw["cohorts"])
    if (len({c.cohort_ref for c in cohorts}) != len(cohorts)
            or any(c.installation_id != raw["installation_id"] for c in cohorts)):
        raise AuthorityUnavailable("historical registry cohort identities differ")
    selected = []
    for manifest in manifests:
        matches = [c for c in cohorts if c.package.manifest_sha256 == manifest]
        if len(matches) != 1:
            raise AuthorityUnavailable("qualified historical cohort was removed or its manifest duplicated")
        selected.append(asdict(matches[0]))
    return canonical_digest((REGISTRY_SCHEMA, raw["installation_id"], policy, selected))


def _decode(raw):
    names = {"schema", "selection", "authority_id", "authority_namespace", "namespace", "installation_id",
        "history_inventory", "selection_history", "backup_observation_ref", "backup_observation_digest",
        "backup_manifest_digest", "original_digest"}
    if type(raw) is not dict or set(raw) != names or raw["schema"] != SCHEMA:
        raise AuthorityUnavailable("closed public historical eligibility required")
    selection = decode_package_selection_v2(raw["selection"])
    namespace = NamespaceId(**raw["namespace"])
    inventory = decode_historical_manifest_inventory_v1(raw["history_inventory"])
    history = raw["selection_history"]
    from .d12_package_history_eligibility_v1 import PackageSelectionHistoryV1
    if type(history) is not dict or set(history) != set(PackageSelectionHistoryV1.__dataclass_fields__):
        raise AuthorityUnavailable("complete authenticated selection history required")
    body = dict(history); committed = body.pop("history_digest")
    manifests = history["ever_active_manifests"]
    if (canonical_digest(body) != committed or not _sha(committed)
            or type(manifests) is not list or manifests != sorted(set(manifests))
            or any(not _sha(value) for value in manifests)
            or history["qualification_stage"] not in {"active", "rollback_complete", "switched_pending_readiness", "rollback_pending_readiness"}
            or history["selection_digest"] != selection.selection_digest or selection.revision < 1
            or history["installation_id"] != selection.installation_id
            or raw["installation_id"] != selection.installation_id or inventory["installation_id"] != selection.installation_id
            or history["authority_id"] != raw["authority_id"]
            or history["authority_namespace"] != raw["authority_namespace"]
            or inventory["authority_namespace"] != raw["authority_namespace"] or inventory["namespace"] != asdict(namespace)
            or any(not _sha(raw[key]) for key in ("backup_observation_digest", "backup_manifest_digest", "original_digest"))
            or not {row["manifest_sha256"] for row in inventory["manifest_groups"]} <= set(manifests)):
        raise AuthorityUnavailable("public history includes an unproven staged package or different scope")
    material = dict(raw); material.pop("original_digest")
    if canonical_digest(material) != raw["original_digest"]:
        raise AuthorityUnavailable("public historical eligibility commitment differs")
    return selection, namespace, tuple(sorted({row["manifest_sha256"] for row in inventory["manifest_groups"]}))


@dataclass(frozen=True, slots=True, weakref_slot=True)
class HistoricalPackageEligibilityV1:
    selection: PackageSelectionV2
    namespace: NamespaceId
    authority_namespace: str
    installation_id: str
    retained_manifests: tuple[str, ...]
    original_digest: str
    path: Path
    file_digest: str
    control_directory: Path


def require_actual_historical_eligibility_v1(value, *, package_files, namespace, installation_id, current_manifest_sha256):
    if (type(value) is not HistoricalPackageEligibilityV1 or _ISSUED.get(id(value)) is not value
            or type(package_files) is not InstalledPackageSelectionFilesV2
            or value.control_directory != package_files.control_directory or value.namespace != namespace
            or value.installation_id != installation_id or value.selection.manifest_sha256 != current_manifest_sha256
            or hashlib.sha256(read_installed_bytes_v1(value.path)).hexdigest() != value.file_digest):
        raise AuthorityUnavailable("actual signed installed historical qualification required")
    selected, _, _ = package_files.read_selected_host_cohort_v2()
    if selected != value.selection:
        raise AuthorityUnavailable("historical qualification belongs to another current selection")
    return value.retained_manifests


def require_unchanged_historical_eligibility_v1(value):
    """Short immutable-file check for use after outside-SQL qualification."""
    if (type(value) is not HistoricalPackageEligibilityV1 or _ISSUED.get(id(value)) is not value
            or hashlib.sha256(read_installed_bytes_v1(value.path)).hexdigest() != value.file_digest):
        raise AuthorityUnavailable("actual historical qualification was replaced or is not issued")


class InstalledPublicHistoricalEligibilityReaderV1:
    def __init__(self, *, package_files):
        if type(package_files) is not InstalledPackageSelectionFilesV2:
            raise TypeError("actual protected package selection required")
        self.files = package_files

    def read_current_v1(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        selected, cohort, _ = self.files.read_selected_host_cohort_v2()
        if selected.revision == 0:
            raise AuthorityUnavailable("initial installation needs no historical-package qualification")
        path = self.files.control_directory / "history-eligibility" / (selected.selection_digest + ".json")
        encoded = read_installed_bytes_v1(path)
        def unique(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("duplicate historical eligibility field")
                result[key] = value
            return result
        packet = json.loads(encoded, object_pairs_hook=unique)
        if type(packet) is not dict or set(packet) != {"original", "signature"}:
            raise AuthorityUnavailable("signed public historical eligibility packet required")
        key = read_installed_bytes_v1(self.files.control_directory / "journal-public.key", limit=32)
        try:
            Ed25519PublicKey.from_public_bytes(key).verify(bytes.fromhex(packet["signature"]), DOMAIN + _canonical(packet["original"]))
        except Exception as exc:
            raise AuthorityUnavailable("public historical qualification signature differs") from exc
        selection, namespace, manifests = _decode(packet["original"])
        if selection != selected:
            raise AuthorityUnavailable("public history describes another selected package")
        for manifest in manifests:
            installation, prior = self.files.read_registered_cohort_for_manifest_v2(manifest)
            if installation != selected.installation_id or prior.identity_commitment != cohort.identity_commitment:
                raise AuthorityUnavailable("historically active package lacks its exact stable registration")
        if self.files.read_selected_host_cohort_v2()[0] != selected:
            raise AuthorityUnavailable("selection changed while reading historical qualification")
        raw = packet["original"]
        result = HistoricalPackageEligibilityV1(selected, namespace, raw["authority_namespace"], raw["installation_id"],
            manifests, raw["original_digest"], path, hashlib.sha256(encoded).hexdigest(), self.files.control_directory)
        _ISSUED[id(result)] = result
        return result


def publish_actual_historical_eligibility_v1(*, package_files, supervisor_journal, supervisor_writer, authority_namespace):
    """Private fixed supervisor step after actual pointer switch, before readiness.

    This performs no package/data switch and grants no business admission. All
    source facts are fetched from the actual independent signed journal here.
    """
    require_linux_administrator_v1()
    if (type(supervisor_journal) is not InstalledPackageSupervisorJournalV2
            or type(supervisor_writer) is not _SupervisorJournalKernelV2
            or supervisor_writer.key is None or supervisor_writer.db.in_transaction
            or supervisor_writer.policy_digest != supervisor_journal.policy
            or Path(supervisor_writer.db.execute("PRAGMA database_list").fetchone()[2]).resolve(strict=True)
                != (supervisor_journal.directory / "supervisor.sqlite3").resolve(strict=True)):
        raise AuthorityUnavailable("actual independent protected supervisor writer required")
    from cryptography.hazmat.primitives import serialization
    key = supervisor_writer.key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    if key != supervisor_journal.public_key:
        raise AuthorityUnavailable("supervisor publication key differs from installed public verifier")
    history = InstalledPackageHistoryEligibilityV1(package_files=package_files,
        supervisor_journal=supervisor_journal, authority_namespace=authority_namespace).read_actual_selection_history_v1()
    selected, _, _ = package_files.read_selected_configuration_cohort_v2()
    if not history.transitions or selected.selection_digest != history.selection_digest:
        raise AuthorityUnavailable("historical publication needs an actual switched selection")
    # The final transition identifies the actual backup used for this selected
    # package. Look it up through signed receipt observations, never a DTO.
    intent = supervisor_journal.read_verified_intent_v2(selected.operation_id)
    matches = {}
    for receipt in supervisor_journal.read_verified_receipts_v2(selected.operation_id):
        for reference, _ in receipt.observation_refs:
            if reference == intent.accepted_original_ref:
                continue
            observed = supervisor_journal.read_verified_observation_v2(selected.operation_id, reference)
            if observed.kind == "managed_backup" and observed.body.get("manifest_digest") == history.transitions[-1][3]:
                matches[reference] = observed
    if len(matches) != 1:
        raise AuthorityUnavailable("selected history has no exact unique managed backup")
    observed = next(iter(matches.values()))
    backup = decode_managed_backup_v2(observed.body)
    inventory = decode_historical_manifest_inventory_v1(backup["history_inventory"])
    original = dict(schema=SCHEMA, selection=asdict(selected), authority_id=history.authority_id,
        authority_namespace=authority_namespace, namespace=inventory["namespace"], installation_id=selected.installation_id,
        history_inventory=inventory, selection_history=json.loads(_canonical(asdict(history))),
        backup_observation_ref=observed.observation_ref, backup_observation_digest=observed.observation_digest,
        backup_manifest_digest=backup["manifest_digest"])
    original["original_digest"] = canonical_digest(original)
    _decode(original)
    packet = _canonical(dict(original=original, signature=supervisor_writer.key.sign(DOMAIN + _canonical(original)).hex()))
    if len(packet) > 1024 * 1024:
        raise AuthorityUnavailable("historical qualification exceeds bounded public file")
    directory = package_files.control_directory / "history-eligibility"
    directory.mkdir(mode=0o755, exist_ok=True)
    fd = _protected_directory(directory)
    lock = None
    try:
        lock = os.open("publish.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=fd)
        from .linux_installation_security_v1 import _check
        _check(lock, directory=False, private=True, allowed_gid=0)
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        name = selected.selection_digest + ".json"
        if (directory / name).exists() or (directory / name).is_symlink():
            existing = InstalledPublicHistoricalEligibilityReaderV1(package_files=package_files).read_current_v1()
            saved = json.loads(read_installed_bytes_v1(existing.path))["original"]
            if (saved["backup_manifest_digest"] != original["backup_manifest_digest"]
                    or saved["history_inventory"] != original["history_inventory"]):
                raise AuthorityUnavailable("historical qualification publication replay differs")
            return existing
        temporary = "." + selected.selection_digest + "." + str(uuid4()) + ".tmp"
        target = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC, 0o644, dir_fd=fd)
        try:
            remaining = memoryview(packet)
            while remaining:
                count = os.write(target, remaining)
                if count <= 0:
                    raise OSError("historical qualification short write")
                remaining = remaining[count:]
            os.fsync(target)
        finally:
            os.close(target)
        if package_files.read_selected_package_v2()[0] != selected:
            raise AuthorityUnavailable("selection changed before historical qualification publication")
        # The fixed publication lock excludes another accepted writer. A crash
        # leaves either an unpublished complete temporary or a complete final
        # original; a partial final document is never exposed to startup.
        os.rename(temporary, name, src_dir_fd=fd, dst_dir_fd=fd)
        os.fsync(fd)
    finally:
        if lock is not None:
            os.close(lock)
        os.close(fd)
    return InstalledPublicHistoricalEligibilityReaderV1(package_files=package_files).read_current_v1()
