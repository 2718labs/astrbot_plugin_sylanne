"""Fixed codecs and independent file checks for installed C09 build receipts."""
from __future__ import annotations

from contextlib import closing
from dataclasses import fields, is_dataclass
from pathlib import Path
import os
import sqlite3
import types
from typing import get_args, get_origin, get_type_hints, Union

from .contract import AuthorityUnavailable
from .c09_authority_storage_rebase import (
    RebasedFileV1, RowDispositionV1, AuthorityStorageRebaseCandidateV1,
    _identity, _file_sha, _root,
)
from .c09_graph_rebase_issue_v1 import AuthorityGraphRebaseIssuedV1
from ..runtime.c09_graph_rebase_candidate_v1 import GraphRebaseCandidateV1, GraphRebaseMirrorV1
from ..runtime.c09_storage_rebase_contract_v1 import (
    GraphRowDispositionV1, GraphTableDispositionManifestV1, GraphErasureRebaseCertificateV1,
)
from ..runtime_contracts import NamespaceId, canonical_digest

_TYPES = frozenset({RebasedFileV1, RowDispositionV1, AuthorityStorageRebaseCandidateV1,
    AuthorityGraphRebaseIssuedV1, GraphRebaseCandidateV1, GraphRebaseMirrorV1,
    GraphRowDispositionV1, GraphTableDispositionManifestV1, GraphErasureRebaseCertificateV1, NamespaceId})


def open_registered_candidate_v1(*, control, operation_id, role, target, source_root):
    """Recover only this build's allocated inode; complete bytes are compared later."""
    from .c09_storage_control_v1 import C09StorageControlV1, _regular_path
    if type(control) is not C09StorageControlV1:
        raise TypeError("actual installed C09 control required")
    control.lease.require_held()
    target = _regular_path(target, exists=False)
    intent = control.read_operation_event_v1(operation_id, "INTENT")
    if intent["details"]["targets"].get(role) != str(target):
        raise AuthorityUnavailable("C09 allocation differs from registered INTENT")
    original = control.read_build_original_v1(operation_id=operation_id, kind="allocation_" + role)
    if original is None:
        if target.exists():
            # Creation and logging may be interrupted before any SQLite write.
            if target.stat().st_size != 0:
                raise AuthorityUnavailable("C09 unregistered nonempty candidate retained for repair")
        else:
            fd = os.open(target, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
            os.fsync(fd)
            os.close(fd)
        stat = target.stat()
        original = control.record_build_original_v1(operation_id=operation_id, kind="allocation_" + role,
            details={"role": role, "target_path": str(target), "device": stat.st_dev,
                "file_id": stat.st_ino, "source_root": source_root})
    stat = target.stat()
    details = original["details"]
    if (details != {"role": role, "target_path": str(target), "device": stat.st_dev,
            "file_id": stat.st_ino, "source_root": source_root}):
        raise AuthorityUnavailable("C09 allocated inode or frozen source differs")
    actual = sqlite3.connect(target, isolation_level=None)
    try:
        actual.execute("PRAGMA synchronous=FULL")
        objects = actual.execute("SELECT name FROM sqlite_master").fetchall()
        if objects:
            if actual.execute("PRAGMA integrity_check").fetchone() != ("ok",):
                raise AuthorityUnavailable("C09 allocated committed candidate integrity differs")
            actual.close()
            return sqlite3.connect(":memory:", isolation_level=None), True
        if actual.execute("PRAGMA freelist_count").fetchone() != (0,):
            raise AuthorityUnavailable("C09 incomplete candidate has unexplained retained pages")
        actual.execute("PRAGMA journal_mode=DELETE")
        return actual, False
    except BaseException:
        actual.close()
        raise


def verify_recomputed_candidate_v1(expected, target):
    if any(Path(str(target) + suffix).exists() for suffix in ("-wal", "-shm", "-journal")):
        raise AuthorityUnavailable("C09 recomputed frozen candidate has sidecars")
    with closing(sqlite3.connect(Path(target).as_uri() + "?mode=ro&immutable=1", uri=True)) as actual:
        actual.execute("BEGIN")
        for pragma in ("user_version", "application_id"):
            if actual.execute("PRAGMA " + pragma).fetchone() != expected.execute("PRAGMA " + pragma).fetchone():
                raise AuthorityUnavailable("C09 recomputed candidate pragma differs")
        from .c09_authority_storage_rebase import _objects
        if _objects(actual) != _objects(expected) or _root(actual) != _root(expected):
            raise AuthorityUnavailable("C09 existing candidate differs from frozen deterministic build")
        if actual.execute("PRAGMA foreign_key_check").fetchone() is not None:
            raise AuthorityUnavailable("C09 existing candidate foreign keys differ")


def decode_installed_build_original_v1(value, annotation):
    """The type comes from installed code; JSON cannot select a class or module."""
    origin, args = get_origin(annotation), get_args(annotation)
    if origin in {types.UnionType, Union}:
        for item in args:
            try:
                return decode_installed_build_original_v1(value, item)
            except (TypeError, ValueError):
                pass
        raise ValueError("C09 build union differs")
    if origin is tuple:
        if type(value) not in {tuple, list}:
            raise ValueError("C09 build tuple differs")
        if len(args) == 2 and args[1] is Ellipsis:
            return tuple(decode_installed_build_original_v1(item, args[0]) for item in value)
        if len(value) != len(args):
            raise ValueError("C09 build tuple arity differs")
        return tuple(decode_installed_build_original_v1(item, kind) for item, kind in zip(value, args))
    if annotation in {str, int, bool, type(None)}:
        if type(value) is not annotation:
            raise ValueError("C09 build scalar differs")
        return value
    if annotation not in _TYPES or not is_dataclass(annotation):
        raise TypeError("unregistered C09 build original type")
    if type(value) is not dict or set(value) != {f.name for f in fields(annotation)}:
        raise ValueError("C09 build original fields differ")
    hints = get_type_hints(annotation)
    return annotation(**{name: decode_installed_build_original_v1(item, hints[name])
        for name, item in value.items()})


def verify_rebased_file_original_v1(original):
    if type(original) is not RebasedFileV1:
        raise TypeError("typed C09 rebuilt file original required")
    path = Path(original.target_path).resolve(strict=True)
    if (_identity(path) != original.target_identity
            or _file_sha(path) != original.target_sha256
            or any(Path(str(path) + suffix).exists() for suffix in ("-wal", "-shm", "-journal"))):
        raise AuthorityUnavailable("C09 registered candidate file identity or bytes differ")
    with closing(sqlite3.connect(path.as_uri() + "?mode=ro&immutable=1", uri=True)) as db:
        db.execute("BEGIN")
        if db.execute("PRAGMA integrity_check").fetchone() != ("ok",):
            raise AuthorityUnavailable("C09 registered candidate integrity differs")
        root = _root(db)
    if root != original.target_data_root or canonical_digest((str(path), root)) != original.cold_read_digest:
        raise AuthorityUnavailable("C09 registered candidate independent root differs")
    return original


def verify_authority_candidate_original_v1(candidate):
    if type(candidate) is not AuthorityStorageRebaseCandidateV1:
        raise TypeError("typed C09 storage candidate required")
    body = tuple(getattr(candidate, field.name) for field in fields(candidate) if field.name != "candidate_digest")
    if canonical_digest(body) != candidate.candidate_digest:
        raise AuthorityUnavailable("C09 storage candidate commitment differs")
    for original in (candidate.core, candidate.execution, candidate.deletion):
        verify_rebased_file_original_v1(original)
    return candidate
