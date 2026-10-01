"""Protected package-selection filesystem component for external maintenance.

This is not an Owner grant, compatibility proof, process supervisor or readiness
receipt. Only the independent maintenance supervisor may call the private CAS
primitive after its durable authenticated intent and actual two-service drain.
Startup readers are non-mutating and select only administrator-registered roots.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from uuid import UUID, uuid4

from .contract import AuthorityUnavailable
from .linux_installation_security_v1 import read_installed_json_v1, require_linux_administrator_v1
from ..host.installed_package import verify_installed_backend_runtime_v1

SELECTION_SCHEMA = "sylanne3.d12.package-selection.v2"
REGISTRY_SCHEMA = "sylanne3.d12.package-registry.v2"


def _canonical(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def _digest(value):
    return hashlib.sha256(_canonical(value)).hexdigest()


def _sha(value):
    return type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None


@dataclass(frozen=True, slots=True)
class RegisteredPackageV2:
    release_ref: str
    package_root: str
    manifest_sha256: str
    package_version: str

    def __post_init__(self):
        path = Path(self.package_root)
        if (type(self.release_ref) is not str or not self.release_ref
                or not path.is_absolute() or str(path) != self.package_root
                or ".." in path.parts or not _sha(self.manifest_sha256)
                or type(self.package_version) is not str or not self.package_version.startswith("3.")):
            raise ValueError("exact registered alpha3 package identity required")


@dataclass(frozen=True, slots=True)
class PackageSelectionV2:
    installation_id: str
    revision: int
    package_epoch: int
    operation_id: str
    release_ref: str
    manifest_sha256: str
    cohort_ref: str
    cohort_digest: str
    prior_selection_digest: str | None
    selection_digest: str
    schema: str = SELECTION_SCHEMA

    def __post_init__(self):
        if (self.schema != SELECTION_SCHEMA or type(self.installation_id) is not str or not self.installation_id
                or type(self.revision) is not int or self.revision < 0
                or type(self.package_epoch) is not int or self.package_epoch < 0
                or type(self.release_ref) is not str or not self.release_ref
                or type(self.cohort_ref) is not str or not self.cohort_ref or not _sha(self.cohort_digest)
                or not _sha(self.manifest_sha256) or not _sha(self.selection_digest)
                or (self.revision == 0) != (self.prior_selection_digest is None)
                or self.prior_selection_digest is not None and not _sha(self.prior_selection_digest)):
            raise ValueError("fixed package selection fields differ")
        try:
            parsed = UUID(self.operation_id)
        except (ValueError, TypeError, AttributeError) as exc:
            raise ValueError("package selection requires canonical UUID4 operation") from exc
        if parsed.version != 4 or str(parsed) != self.operation_id:
            raise ValueError("package selection requires canonical UUID4 operation")
        body = asdict(self); body.pop("selection_digest")
        if self.selection_digest != _digest(body):
            raise ValueError("package selection commitment differs")


def decode_package_selection_v2(value):
    if type(value) is not dict or set(value) != set(PackageSelectionV2.__dataclass_fields__):
        raise ValueError("exact package selection object required")
    return PackageSelectionV2(**value)


def next_package_selection_v2(current, *, operation_id, package, cohort_ref, cohort_digest):
    if type(current) is not PackageSelectionV2 or type(package) is not RegisteredPackageV2:
        raise TypeError("actual decoded selection and registered package required")
    body = dict(schema=SELECTION_SCHEMA, installation_id=current.installation_id,
        revision=current.revision + 1, package_epoch=current.package_epoch + 1,
        operation_id=operation_id, release_ref=package.release_ref,
        cohort_ref=cohort_ref, cohort_digest=cohort_digest,
        manifest_sha256=package.manifest_sha256, prior_selection_digest=current.selection_digest)
    return PackageSelectionV2(**body, selection_digest=_digest(body))


def _decode_bytes(raw):
    def unique(pairs):
        result = {}
        for name, value in pairs:
            if name in result: raise ValueError("duplicate selection field")
            result[name] = value
        return result
    return decode_package_selection_v2(json.loads(raw, object_pairs_hook=unique))


def _read_at(directory_fd, name):
    fd = os.open(name, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW, dir_fd=directory_fd)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 65536:
            raise AuthorityUnavailable("bounded regular package selection required")
        raw = os.read(fd, 65537)
        if len(raw) > 65536 or os.read(fd, 1): raise AuthorityUnavailable("package selection exceeds bound")
        return _decode_bytes(raw)
    finally:
        os.close(fd)


def _compare_replace_pointer_at(directory_fd, *, expected, desired):
    """CAS under caller's protected directory and exclusive supervisor lock.

    Filesystem primitive only, deliberately not exported as an authorization API.
    Exact desired replay reads the original; a third value never gets overwritten.
    """
    if type(expected) is not PackageSelectionV2 or type(desired) is not PackageSelectionV2:
        raise TypeError("typed package selection CAS required")
    if (desired.installation_id != expected.installation_id or desired.revision != expected.revision + 1
            or desired.package_epoch != expected.package_epoch + 1
            or desired.prior_selection_digest != expected.selection_digest):
        raise AuthorityUnavailable("package pointer transition is not its exact predecessor")
    current = _read_at(directory_fd, "selection.json")
    if current == desired:
        os.fsync(directory_fd)
        return current
    if current != expected:
        raise AuthorityUnavailable("package pointer changed; original switch outcome must be resolved")
    temporary = ".selection-" + str(uuid4()) + ".tmp"
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                 0o644, dir_fd=directory_fd)
    try:
        raw = memoryview(_canonical(asdict(desired)))
        while raw:
            written = os.write(fd, raw)
            if written <= 0: raise OSError("package pointer short write")
            raw = raw[written:]
        os.fsync(fd)
    finally:
        os.close(fd)
    # A failed rename leaves a bounded unpublished temporary, never a guessed
    # rollback. Recovery consults the durable intent and actual selected record.
    os.replace(temporary, "selection.json", src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
    os.fsync(directory_fd)
    if _read_at(directory_fd, "selection.json") != desired:
        raise AuthorityUnavailable("package pointer reread differs after switch")
    return desired


def _protected_directory(path):
    """Return descriptor to a root-owned immutable-to-Host canonical directory."""
    path = Path(path)
    if not path.is_absolute() or ".." in path.parts:
        raise AuthorityUnavailable("absolute protected package control directory required")
    descriptors = []
    try:
        fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        descriptors.append(fd)
        from .linux_installation_security_v1 import _check
        _check(fd, directory=True)
        for part in path.parts[1:]:
            fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
            descriptors.append(fd); _check(fd, directory=True)
        result = descriptors.pop()
        return result
    finally:
        for fd in reversed(descriptors): os.close(fd)


class InstalledPackageSelectionFilesV2:
    """Fixed registry/selection paths, never caller-supplied package destinations."""
    def __init__(self, *, control_directory):
        self.control_directory = Path(control_directory)
        fd = _protected_directory(self.control_directory); os.close(fd)

    def read_registered_cohorts_v2(self):
        from .d12_configuration_cohort_v2 import decode_configuration_cohort_v2
        registry=read_installed_json_v1(self.control_directory/'registry.json')
        if (set(registry)!={'schema','installation_id','cohorts','maintenance_policy'}
                or registry['schema']!=REGISTRY_SCHEMA or type(registry['cohorts']) is not list
                or not 1<=len(registry['cohorts'])<=128):
            raise AuthorityUnavailable('fixed bounded package registry required')
        values=tuple(decode_configuration_cohort_v2(raw) for raw in registry['cohorts'])
        if (len({item.cohort_ref for item in values})!=len(values)
                or any(item.installation_id!=registry['installation_id'] for item in values)):
            raise AuthorityUnavailable('registered cohort identities differ or repeat')
        self.read_maintenance_policy_v2()
        return registry['installation_id'],values

    def read_registered_cohort_v2(self, cohort_ref):
        from .d12_configuration_cohort_v2 import decode_configuration_cohort_v2
        registry = read_installed_json_v1(self.control_directory / "registry.json")
        if (set(registry) != {"schema", "installation_id", "cohorts", "maintenance_policy"}
                or registry["schema"] != REGISTRY_SCHEMA or type(registry["cohorts"]) is not list
                or not 1 <= len(registry["cohorts"]) <= 128):
            raise AuthorityUnavailable("fixed bounded package registry required")
        entries = tuple(decode_configuration_cohort_v2(row) for row in registry["cohorts"])
        if (len({entry.cohort_ref for entry in entries}) != len(entries)
                or any(entry.installation_id != registry['installation_id'] for entry in entries)):
            raise AuthorityUnavailable("duplicate cohort or mismatched registered installation")
        found = tuple(entry for entry in entries if entry.cohort_ref == cohort_ref)
        if len(found) != 1: raise AuthorityUnavailable("release is not independently registered")
        return registry['installation_id'], found[0]

    def read_maintenance_policy_v2(self):
        registry = read_installed_json_v1(self.control_directory / 'registry.json')
        if (set(registry) != {'schema', 'installation_id', 'cohorts', 'maintenance_policy'}
                or registry['schema'] != REGISTRY_SCHEMA):
            raise AuthorityUnavailable('fixed package registry required')
        policy = registry['maintenance_policy']
        if (type(policy) is not dict or set(policy) != {'compatibility_plan_ref', 'supervisor_policy_digest'}
                or type(policy['compatibility_plan_ref']) is not str or not policy['compatibility_plan_ref']
                or not _sha(policy['supervisor_policy_digest'])):
            raise AuthorityUnavailable('fixed maintenance policy required')
        return dict(policy)

    def read_registered_cohort_for_manifest_v2(self, manifest_sha256):
        from .d12_configuration_cohort_v2 import decode_configuration_cohort_v2
        if not _sha(manifest_sha256):raise AuthorityUnavailable('exact historical manifest required')
        registry = read_installed_json_v1(self.control_directory / 'registry.json')
        if (set(registry) != {'schema', 'installation_id', 'cohorts', 'maintenance_policy'}
                or registry['schema'] != REGISTRY_SCHEMA or type(registry['cohorts']) is not list
                or not 1 <= len(registry['cohorts']) <= 128):
            raise AuthorityUnavailable('fixed package registry required')
        cohorts = tuple(decode_configuration_cohort_v2(raw) for raw in registry['cohorts'])
        if (len({cohort.cohort_ref for cohort in cohorts}) != len(cohorts)
                or any(cohort.installation_id != registry['installation_id'] for cohort in cohorts)):
            raise AuthorityUnavailable('historical registry cohort identity differs')
        matches = []
        for cohort in cohorts:
            if cohort.package.manifest_sha256 == manifest_sha256:matches.append((registry['installation_id'], cohort))
        if len(matches) != 1:
            raise AuthorityUnavailable('historical manifest has no unique registered configuration cohort')
        return matches[0]

    def read_selected_configuration_cohort_v2(self):
        from .d12_configuration_cohort_v2 import read_verified_configuration_cohort_v2
        selection = decode_package_selection_v2(read_installed_json_v1(self.control_directory / "selection.json"))
        _, cohort = self.read_registered_cohort_v2(selection.cohort_ref)
        package = cohort.package
        if (cohort.installation_id != selection.installation_id or package.manifest_sha256 != selection.manifest_sha256
                or package.release_ref != selection.release_ref or cohort.cohort_digest != selection.cohort_digest):
            raise AuthorityUnavailable("selected package differs from registered installation")
        configuration = read_verified_configuration_cohort_v2(cohort)
        reread = decode_package_selection_v2(read_installed_json_v1(self.control_directory / "selection.json"))
        if reread != selection:
            raise AuthorityUnavailable("package selection changed while qualifying startup")
        return selection, cohort, configuration

    def read_selected_package_v2(self):
        selection, cohort, _ = self.read_selected_configuration_cohort_v2()
        return selection, cohort.package

    def read_selected_host_cohort_v2(self):
        from .d12_configuration_cohort_v2 import read_verified_host_profile_cohort_v2
        selection = decode_package_selection_v2(read_installed_json_v1(self.control_directory / 'selection.json'))
        installation, cohort = self.read_registered_cohort_v2(selection.cohort_ref)
        if (installation != selection.installation_id or cohort.cohort_digest != selection.cohort_digest
                or cohort.package.release_ref != selection.release_ref
                or cohort.package.manifest_sha256 != selection.manifest_sha256):
            raise AuthorityUnavailable('selected public Host cohort differs')
        evidence = read_verified_host_profile_cohort_v2(cohort)
        after = decode_package_selection_v2(read_installed_json_v1(self.control_directory / 'selection.json'))
        if after != selection:raise AuthorityUnavailable('selection changed while reading Host public evidence')
        return selection, cohort, evidence

    @staticmethod
    def verify_registered_package_v2(package):
        if type(package) is not RegisteredPackageV2: raise TypeError("registered package required")
        root = Path(package.package_root)
        fd = _protected_directory(root); os.close(fd)
        # Every descendant must also be protected, not merely the top directory.
        for directory, dirs, files in os.walk(root, followlinks=False):
            for name in dirs + files:
                path = Path(directory) / name
                info = path.lstat()
                if (stat.S_ISLNK(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022
                        or not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode))
                        or stat.S_ISREG(info.st_mode) and info.st_nlink != 1):
                    raise AuthorityUnavailable("registered package contains unprotected object")
                from .linux_installation_security_v1 import _check
                flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
                if stat.S_ISDIR(info.st_mode): flags |= os.O_DIRECTORY
                item_fd = os.open(path, flags)
                try: _check(item_fd, directory=stat.S_ISDIR(info.st_mode))
                finally: os.close(item_fd)
        result = verify_installed_backend_runtime_v1(root, package.manifest_sha256)
        if not result.verified or result.package_version != package.package_version:
            raise AuthorityUnavailable("registered package bytes/platform/catalogue are not qualified")
        return result

    def _switch_after_supervisor_authorization_v2(self, *, expected, desired):
        """Internal only: outer supervisor owns durable authorization and drain."""
        require_linux_administrator_v1()
        from .d12_configuration_cohort_v2 import read_verified_configuration_cohort_v2
        _, cohort = self.read_registered_cohort_v2(desired.cohort_ref)
        candidate = cohort.package
        _, old_cohort = self.read_registered_cohort_v2(expected.cohort_ref)
        if (cohort.installation_id != desired.installation_id or candidate.manifest_sha256 != desired.manifest_sha256
                or candidate.release_ref != desired.release_ref or cohort.cohort_digest != desired.cohort_digest
                or old_cohort.cohort_digest != expected.cohort_digest
                or cohort.identity_commitment != old_cohort.identity_commitment):
            raise AuthorityUnavailable("switch candidate is not the registered package")
        read_verified_configuration_cohort_v2(old_cohort)
        read_verified_configuration_cohort_v2(cohort)
        decode_package_selection_v2(read_installed_json_v1(self.control_directory / "selection.json"))
        directory_fd = _protected_directory(self.control_directory)
        lock_fd = None
        try:
            lock_fd = os.open("selection.lock", os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory_fd)
            from .linux_installation_security_v1 import _check
            _check(lock_fd, directory=False, private=True, allowed_gid=0)
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return _compare_replace_pointer_at(directory_fd, expected=expected, desired=desired)
        finally:
            if lock_fd is not None: os.close(lock_fd)
            os.close(directory_fd)
