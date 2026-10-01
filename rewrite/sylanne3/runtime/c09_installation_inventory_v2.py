"""Read-only C09 installation filesystem inventory.

An installer pins the manifest digest outside this module. A scan observes the
actual files under its declared ownership; neither DTO nor scan is a cleanup
receipt or proof that undisclosed external copies do not exist.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import re
import stat

from ..runtime_contracts import canonical_digest


_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/@#=+-]{0,255}\Z")
_HEX = re.compile(r"[0-9a-f]{64}\Z")
_KINDS = frozenset({
    "sqlite_db", "sqlite_wal", "sqlite_shm", "controlled_backup",
    "export", "rebuild_temp", "cache",
})
_DIRECTORIES = frozenset({"controlled_backup", "export", "rebuild_temp", "cache"})
_REQUIRED = frozenset({"sqlite_db", "sqlite_wal", "sqlite_shm"}) | _DIRECTORIES


class InventoryHold(RuntimeError):
    """Inventory changed, is unreadable, or cannot establish ownership."""


def _identifier(value: str, name: str) -> None:
    if type(value) is not str or _ID.fullmatch(value) is None:
        raise ValueError(f"invalid {name}")


def _digest(value: str, name: str) -> None:
    if type(value) is not str or _HEX.fullmatch(value) is None:
        raise ValueError(f"invalid {name}")


def _resolved(path: str) -> Path:
    if type(path) is not str or not path or "\x00" in path:
        raise ValueError("invalid installed path")
    target = Path(path)
    if not target.is_absolute() or str(target.resolve(strict=False)) != path:
        raise ValueError("installed path must be absolute and resolved")
    return target


@dataclass(frozen=True, slots=True)
class InstalledResourceV2:
    resource_id: str
    kind: str
    path: str
    namespace: str
    store_id: str
    store_generation: int
    deletion_watermark: int
    owner: str
    file_format: str
    content_coverage: tuple[str, ...]
    cleaner_version: str

    def __post_init__(self) -> None:
        for name in ("resource_id", "namespace", "store_id", "owner",
                     "file_format", "cleaner_version"):
            _identifier(getattr(self, name), name)
        if self.kind not in _KINDS:
            raise ValueError("unknown installed resource kind")
        _resolved(self.path)
        for name in ("store_generation", "deletion_watermark"):
            value = getattr(self, name)
            if type(value) is not int or value < 0:
                raise ValueError(f"invalid {name}")
        if self.store_generation < 1:
            raise ValueError("store generation is absent")
        if (type(self.content_coverage) is not tuple or not self.content_coverage
                or self.content_coverage != tuple(sorted(set(self.content_coverage)))):
            raise ValueError("content coverage is not explicit and canonical")
        for item in self.content_coverage:
            _identifier(item, "content_coverage")


@dataclass(frozen=True, slots=True)
class InstallationFilesystemManifestV2:
    authority_id: str
    installation_id: str
    namespace: str
    resources: tuple[InstalledResourceV2, ...]
    manifest_digest: str
    schema: str = "sylanne3.c09.installation_filesystem_manifest.v2"

    def __post_init__(self) -> None:
        for name in ("authority_id", "installation_id", "namespace"):
            _identifier(getattr(self, name), name)
        if self.schema != "sylanne3.c09.installation_filesystem_manifest.v2":
            raise ValueError("inventory manifest schema differs")
        if (type(self.resources) is not tuple or
                any(type(item) is not InstalledResourceV2 for item in self.resources)
                or tuple(sorted(self.resources, key=lambda item: item.path)) != self.resources
                or len({item.path for item in self.resources}) != len(self.resources)
                or len({item.resource_id for item in self.resources}) != len(self.resources)
                or not _REQUIRED.issubset({item.kind for item in self.resources})
                or any(item.namespace != self.namespace for item in self.resources)):
            raise ValueError("installation resource set is incomplete or ambiguous")
        paths = [Path(item.path) for item in self.resources]
        for index, left in enumerate(paths):
            for right in paths[index + 1:]:
                if left in right.parents or right in left.parents:
                    raise ValueError("installed resource paths overlap")
        groups: dict[str, dict[str, InstalledResourceV2]] = {}
        for item in self.resources:
            if item.kind not in {"sqlite_db", "sqlite_wal", "sqlite_shm"}:
                continue
            group = groups.setdefault(item.store_id, {})
            if item.kind in group:
                raise ValueError("SQLite companion kind repeated")
            group[item.kind] = item
        if not groups or any(set(group) != {"sqlite_db", "sqlite_wal", "sqlite_shm"}
                             for group in groups.values()):
            raise ValueError("SQLite DB/WAL/SHM registration incomplete")
        for group in groups.values():
            db, wal, shm = (group[k] for k in ("sqlite_db", "sqlite_wal", "sqlite_shm"))
            if (wal.path != db.path + "-wal" or shm.path != db.path + "-shm"
                    or len({item.store_generation for item in group.values()}) != 1
                    or len({item.deletion_watermark for item in group.values()}) != 1):
                raise ValueError("SQLite companions do not bind one store generation")
        _digest(self.manifest_digest, "manifest_digest")
        if self.manifest_digest != canonical_digest((
                self.schema, self.authority_id, self.installation_id,
                self.namespace, self.resources)):
            raise ValueError("installation manifest digest differs")


@dataclass(frozen=True, slots=True)
class ObservedFileV2:
    resource_id: str
    path: str
    file_type: str
    device: int
    inode: int
    size: int
    mtime_ns: int
    content_sha256: str | None


@dataclass(frozen=True, slots=True)
class InstallationFilesystemScanV2:
    manifest_digest: str
    observed: tuple[ObservedFileV2, ...]
    scan_digest: str
    schema: str = "sylanne3.c09.installation_filesystem_scan.v2"

    def __post_init__(self) -> None:
        if self.schema != "sylanne3.c09.installation_filesystem_scan.v2":
            raise ValueError("inventory scan schema differs")
        _digest(self.manifest_digest, "manifest_digest")
        if (type(self.observed) is not tuple
                or tuple(sorted(self.observed, key=lambda row: row.path)) != self.observed
                or len({row.path for row in self.observed}) != len(self.observed)):
            raise ValueError("inventory observation is not canonical")
        _digest(self.scan_digest, "scan_digest")
        if self.scan_digest != canonical_digest((
                self.schema, self.manifest_digest, self.observed)):
            raise ValueError("inventory scan digest differs")


def _observe(path: Path, resource_id: str) -> ObservedFileV2:
    try:
        before = path.lstat()
        if stat.S_ISLNK(before.st_mode):
            raise InventoryHold(f"registered symlink: {path}")
        if stat.S_ISDIR(before.st_mode):
            kind, body_digest = "directory", None
        elif stat.S_ISREG(before.st_mode):
            kind = "file"
            hasher = hashlib.sha256()
            with path.open("rb") as source:
                for block in iter(lambda: source.read(1024 * 1024), b""):
                    hasher.update(block)
            body_digest = hasher.hexdigest()
        else:
            raise InventoryHold(f"unsupported registered file: {path}")
        after = path.lstat()
    except OSError as exc:
        raise InventoryHold(f"registered path unreadable: {path}") from exc
    identity = lambda info: (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)
    if identity(before) != identity(after):
        raise InventoryHold(f"registered path changed during scan: {path}")
    return ObservedFileV2(resource_id, str(path), kind, before.st_dev,
                          before.st_ino, before.st_size, before.st_mtime_ns,
                          body_digest)


def scan_installed_filesystem_v2(
    manifest: InstallationFilesystemManifestV2, *,
    pinned_manifest_digest: str,
) -> InstallationFilesystemScanV2:
    """Cold enumerate exactly the manifest's managed paths; never mutate them."""
    if type(manifest) is not InstallationFilesystemManifestV2:
        raise TypeError("installed filesystem manifest required")
    _digest(pinned_manifest_digest, "pinned_manifest_digest")
    if manifest.manifest_digest != pinned_manifest_digest:
        raise InventoryHold("installed manifest differs from trusted digest")
    observed = []
    for resource in manifest.resources:
        path = Path(resource.path)
        try:
            exists = path.exists()
        except OSError as exc:
            raise InventoryHold(f"registered path inaccessible: {path}") from exc
        if not exists:
            if resource.kind in {"sqlite_wal", "sqlite_shm"}:
                continue  # Transient companion absence is observed, never N/A.
            raise InventoryHold(f"registered path missing: {path}")
        root = _observe(path, resource.resource_id)
        expected_type = "directory" if resource.kind in _DIRECTORIES else "file"
        if root.file_type != expected_type:
            raise InventoryHold(f"registered path type differs: {path}")
        observed.append(root)
        if root.file_type == "directory":
            try:
                def unreadable(exc):
                    raise InventoryHold(f"managed tree unreadable: {path}") from exc

                for walk_root, dirs, files in os.walk(
                        path, followlinks=False, onerror=unreadable):
                    dirs.sort()
                    files.sort()
                    for name in (*dirs, *files):
                        child = Path(walk_root) / name
                        if child.resolve(strict=False) != child:
                            raise InventoryHold(f"unresolved managed child: {child}")
                        observed.append(_observe(child, resource.resource_id))
            except OSError as exc:
                raise InventoryHold(f"managed tree unreadable: {path}") from exc
    observed.sort(key=lambda row: row.path)
    rows = tuple(observed)
    schema = "sylanne3.c09.installation_filesystem_scan.v2"
    return InstallationFilesystemScanV2(
        manifest.manifest_digest, rows,
        canonical_digest((schema, manifest.manifest_digest, rows)), schema)


def require_exact_cold_rescan_v2(
    manifest: InstallationFilesystemManifestV2,
    baseline: InstallationFilesystemScanV2, *,
    pinned_manifest_digest: str,
    pinned_scan_digest: str,
) -> InstallationFilesystemScanV2:
    if type(baseline) is not InstallationFilesystemScanV2:
        raise TypeError("prior cold scan required")
    _digest(pinned_scan_digest, "pinned_scan_digest")
    if baseline.scan_digest != pinned_scan_digest:
        raise InventoryHold("frozen inventory differs from trusted digest")
    current = scan_installed_filesystem_v2(
        manifest, pinned_manifest_digest=pinned_manifest_digest)
    if baseline.manifest_digest != manifest.manifest_digest or current != baseline:
        raise InventoryHold("managed filesystem changed since frozen inventory")
    return current


__all__ = [
    "InventoryHold", "InstalledResourceV2", "InstallationFilesystemManifestV2",
    "ObservedFileV2", "InstallationFilesystemScanV2",
    "scan_installed_filesystem_v2", "require_exact_cold_rescan_v2",
]
