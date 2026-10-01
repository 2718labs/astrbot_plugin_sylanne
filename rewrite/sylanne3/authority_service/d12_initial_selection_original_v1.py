"""Signed installer origin of the package-selection chain.

The fixed installer records this only after the actual initial four-file seal.
The protected registry alone is never proof that a staged package was active.
"""
from dataclasses import asdict, dataclass
import json
from uuid import UUID

from .contract import AuthorityUnavailable
from .d12_package_files_v2 import PackageSelectionV2, decode_package_selection_v2, _canonical, _digest, _sha
from .d12_package_supervisor_journal_v2 import InstalledPackageSupervisorJournalV2
from .linux_installation_security_v1 import read_installed_bytes_v1

SCHEMA = "d12.initial-package-selection.v1"
SIGNATURE_DOMAIN = b"sylanne3.d12.initial-package-selection.v1\0"


@dataclass(frozen=True, slots=True)
class InitialPackageSelectionOriginalV1:
    installation_id: str
    authority_id: str
    namespace_cohort: tuple[str, ...]
    selection: PackageSelectionV2
    identity_commitment: str
    supervisor_policy_digest: str
    initial_storage_manifest_digest: str
    initial_storage_generation: int
    initial_pointer_version: int
    issuer_operation_id: str
    original_digest: str
    schema: str = SCHEMA

    def __post_init__(self):
        if (self.schema != SCHEMA or type(self.selection) is not PackageSelectionV2
                or self.selection.installation_id != self.installation_id or not self.authority_id
                or self.selection.revision != 0 or self.selection.package_epoch != 0
                or self.selection.prior_selection_digest is not None
                or type(self.namespace_cohort) is not tuple or not self.namespace_cohort
                or self.namespace_cohort != tuple(sorted(set(self.namespace_cohort)))
                or any(type(value) is not str or not value for value in self.namespace_cohort)
                or type(self.initial_storage_generation) is not int or self.initial_storage_generation != 0
                or type(self.initial_pointer_version) is not int or self.initial_pointer_version < 0
                or any(not _sha(value) for value in (self.identity_commitment, self.supervisor_policy_digest,
                    self.initial_storage_manifest_digest, self.original_digest))):
            raise ValueError("fixed actual installer selection/seal identity required")
        operation = UUID(self.issuer_operation_id)
        if operation.version != 4 or str(operation) != self.issuer_operation_id:
            raise ValueError("canonical installer operation required")
        body = asdict(self); body.pop("original_digest")
        if _digest(body) != self.original_digest:
            raise ValueError("initial selection original commitment differs")


def initial_selection_original_from_wire_v1(raw):
    if type(raw) is not dict or set(raw) != set(InitialPackageSelectionOriginalV1.__dataclass_fields__):
        raise ValueError("closed initial selection original required")
    value = dict(raw)
    if type(value["namespace_cohort"]) is not list:
        raise ValueError("initial selection cohort must be an array")
    value["namespace_cohort"] = tuple(value["namespace_cohort"])
    value["selection"] = decode_package_selection_v2(value["selection"])
    return InitialPackageSelectionOriginalV1(**value)


def read_initial_selection_original_v1(*, package_files, supervisor_journal):
    """Read the protected signed installer original; never synthesize from today."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from .d12_package_files_v2 import InstalledPackageSelectionFilesV2
    if (type(package_files) is not InstalledPackageSelectionFilesV2
            or type(supervisor_journal) is not InstalledPackageSupervisorJournalV2
            or package_files.control_directory != supervisor_journal.directory):
        raise AuthorityUnavailable("actual common protected package control required")
    raw = read_installed_bytes_v1(package_files.control_directory / "initial-selection.json", limit=65536)
    def unique(pairs):
        result = {}
        for name, value in pairs:
            if name in result:
                raise ValueError("duplicate initial selection field")
            result[name] = value
        return result
    packet = json.loads(raw, object_pairs_hook=unique)
    if type(packet) is not dict or set(packet) != {"original", "signature"}:
        raise AuthorityUnavailable("signed initial selection packet required")
    original = initial_selection_original_from_wire_v1(packet["original"])
    try:
        Ed25519PublicKey.from_public_bytes(supervisor_journal.public_key).verify(
            bytes.fromhex(packet["signature"]), SIGNATURE_DOMAIN + _canonical(packet["original"]))
    except Exception as exc:
        raise AuthorityUnavailable("initial package selection signature differs") from exc
    installation, cohort = package_files.read_registered_cohort_for_manifest_v2(original.selection.manifest_sha256)
    if (installation != original.installation_id or cohort.cohort_ref != original.selection.cohort_ref
            or cohort.cohort_digest != original.selection.cohort_digest
            or cohort.identity_commitment != original.identity_commitment
            or cohort.supervisor_policy_digest != original.supervisor_policy_digest
            or supervisor_journal.policy != original.supervisor_policy_digest
            or cohort.package.release_ref != original.selection.release_ref):
        raise AuthorityUnavailable("initial selected cohort is not the exact protected registration")
    return original
