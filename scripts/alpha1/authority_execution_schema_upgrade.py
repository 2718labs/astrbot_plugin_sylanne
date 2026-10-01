"""Explicit offline ExecutionJournal schema v1 -> v2 metadata migration.

Only the schema_version meta row changes. The v1 chain and Core head must
agree, and a verified SQLite backup is kept. A diagnostic fixture may use the
exclusive instance lock without SCM; production needs an installed stopped
service and publisher-root acceptance, which current staging cannot provide.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from _runtime_bootstrap import load_canonical_runtime_v1
load_canonical_runtime_v1(ROOT)

from sylanne3.authority_service.v2_execution_journal import (  # noqa: E402
    AuthorityV2ExecutionJournal,
)


def _file(path: Path, label: str) -> Path:
    if (not path.is_absolute() or path.is_symlink() or not path.is_file()
            or any(parent.is_symlink() or getattr(parent, "is_junction", lambda: False)()
                   for parent in path.parents)):
        raise ValueError(f"installed {label} file is absent or unsafe")
    return path.resolve(strict=True)


def _stopped(install_root: Path | None, lock_path: Path,
             diagnostic_offline_fixture: bool, trusted_root_sha256: str | None,
             authority_db: Path, execution_db: Path, namespace: str, journal_id: str):
    if os.name != "nt":
        raise RuntimeError("ExecutionJournal offline schema migration requires Windows")
    import msvcrt

    if diagnostic_offline_fixture:
        if install_root is not None:
            raise ValueError("diagnostic fixture cannot claim an installed service root")
        evidence = "exclusive_fixture_instance_lock_only"
    else:
        if install_root is None:
            raise RuntimeError("installed Authority root and stopped SCM proof are required; HOLD")
        root = install_root.resolve(strict=True)
        marker = json.loads((root / "authority-deployment.json").read_bytes())
        if (marker.get("schema") != "sylanne.authority.deployment-state.v1"
                or marker.get("status") != "formal_authority_release"
                or marker.get("service_registered") is not True):
            raise RuntimeError("formal installed Authority service proof is absent; HOLD")
        if trusted_root_sha256 is None or marker.get("publisher_key_sha256") != trusted_root_sha256:
            raise RuntimeError("externally pinned publisher root is absent; HOLD")
        from authority_installer import verify_publisher_bundle

        trust = root / marker["trust_dir"]
        verified = verify_publisher_bundle(
            trust / "authority.zip", trust / "publisher.sig", trust / "publisher.pub",
            trusted_root_sha256=trusted_root_sha256,
            expected_package_sha256=marker["package_sha256"],
            expected_manifest_sha256=marker["manifest_sha256"],
        )
        if (verified.get("status") != "formal_authority_release"
                or verified.get("formal_publisher_root") != "installed"):
            raise RuntimeError("current Authority bundle remains diagnostic; HOLD")
        assets = json.loads((root / "state" / "installed-assets.json").read_bytes())
        matching = [row for row in assets.get("execution_journals", [])
                    if row.get("namespace") == namespace]
        if (Path(assets.get("authority_db", "")).resolve() != authority_db
                or Path(assets.get("instance_lock", "")).resolve() != lock_path.resolve()
                or len(matching) != 1
                or Path(matching[0].get("path", "")).resolve() != execution_db
                or matching[0].get("journal_id") != journal_id):
            raise RuntimeError("installed Core, lock or journal binding differs; HOLD")
        output = subprocess.run(("sc.exe", "query", "SylanneAuthority"),
                                check=True, capture_output=True, text=True).stdout
        match = re.search(r"STATE\s*:\s*(\d+)", output)
        if match is None or int(match.group(1)) != 1:
            raise RuntimeError("Authority SCM service is not stopped; HOLD")
        evidence = "scm_stopped_and_exclusive_instance_lock"
    handle = _file(lock_path, "instance lock").open("r+b")
    try:
        if handle.seek(0, 2) < 1:
            raise RuntimeError("Authority instance lock has no byte")
        handle.seek(0)
        msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
    except BaseException:
        handle.close()
        raise RuntimeError("Authority instance lock is active; HOLD") from None
    return handle, evidence


def _core_head(db: sqlite3.Connection, namespace: str) -> tuple[str, int, str]:
    row = db.execute(
        "SELECT execution_journal_id,execution_seq,execution_digest "
        "FROM authority_namespaces WHERE namespace=?", (namespace,),
    ).fetchone()
    if row is None:
        raise RuntimeError("Authority Core namespace is absent; HOLD")
    return row


def upgrade_execution_schema(
    *, authority_db: Path, execution_db: Path, instance_lock: Path,
    namespace: str, journal_id: str, backup: Path,
    install_root: Path | None = None,
    diagnostic_offline_fixture: bool = False,
    trusted_root_sha256: str | None = None,
) -> dict:
    """Upgrade an independently checked v1 journal under exclusive stop proof."""
    authority_db = _file(authority_db, "Core")
    execution_db = _file(execution_db, "ExecutionJournal")
    if backup.exists() or backup.resolve() in {authority_db, execution_db}:
        raise FileExistsError("backup target must be new and separate")
    if not backup.is_absolute():
        raise ValueError("backup target must be absolute")
    handle, stopped_evidence = _stopped(
        install_root, instance_lock, diagnostic_offline_fixture,
        trusted_root_sha256, authority_db, execution_db, namespace, journal_id)
    journal = None
    try:
        journal = AuthorityV2ExecutionJournal(
            execution_db, namespace=namespace, journal_id=journal_id,
            create=False)
        if journal._schema_version != "1":
            raise RuntimeError("ExecutionJournal is not schema v1; HOLD")
        original_head = journal.verified_head()
        with sqlite3.connect(authority_db.as_uri() + "?mode=ro", uri=True) as core:
            core.execute("PRAGMA query_only=ON")
            if _core_head(core, namespace) != (
                original_head.journal_id, original_head.seq, original_head.digest,
            ):
                raise RuntimeError("Core and v1 ExecutionJournal heads differ; HOLD")
        backup.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(backup) as target:
            journal._db.backup(target)
        checked_backup = AuthorityV2ExecutionJournal(
            backup, namespace=namespace, journal_id=journal_id, create=False)
        try:
            if checked_backup._schema_version != "1" or checked_backup.verified_head() != original_head:
                raise RuntimeError("recoverable v1 backup verification failed; HOLD")
        finally:
            checked_backup.close()
        backup_sha = hashlib.sha256(backup.read_bytes()).hexdigest()
        core = sqlite3.connect(authority_db, isolation_level=None, timeout=5)
        try:
            core.execute("BEGIN IMMEDIATE")
            with journal.freeze_writes():
                current = journal.verified_head()
                if (journal._schema_version != "1" or current != original_head
                        or _core_head(core, namespace) != (
                            current.journal_id, current.seq, current.digest)):
                    raise RuntimeError("offline Core/journal read set changed; HOLD")
                cursor = journal._db.execute(
                    "UPDATE authority_v2_execution_meta SET value='2' "
                    "WHERE key='schema_version' AND value='1'")
                if cursor.rowcount != 1:
                    raise RuntimeError("v1 schema marker changed; HOLD")
            core.execute("COMMIT")
        except BaseException:
            if core.in_transaction:
                core.execute("ROLLBACK")
            raise
        finally:
            core.close()
        journal.close()
        journal = AuthorityV2ExecutionJournal(
            execution_db, namespace=namespace, journal_id=journal_id, create=False)
        if journal._schema_version != "2" or journal.verified_head() != original_head:
            raise RuntimeError("v2 reopen or preserved chain head differs; HOLD")
        return {
            "status": "diagnostic_schema_upgrade" if diagnostic_offline_fixture else "offline_schema_upgrade",
            "namespace": namespace, "journal_id": journal_id,
            "sequence": original_head.seq, "chain_digest": original_head.digest,
            "backup": str(backup), "backup_sha256": backup_sha,
            "stopped_evidence": stopped_evidence,
            "schema_version": "2", "core_head_unchanged": True,
        }
    finally:
        if journal is not None:
            journal.close()
        import msvcrt
        try:
            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
        finally:
            handle.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Offline ExecutionJournal v1 to v2 schema gate")
    parser.add_argument("--authority-db", type=Path, required=True)
    parser.add_argument("--execution-db", type=Path, required=True)
    parser.add_argument("--instance-lock", type=Path, required=True)
    parser.add_argument("--namespace", required=True)
    parser.add_argument("--journal-id", required=True)
    parser.add_argument("--backup", type=Path, required=True)
    parser.add_argument("--install-root", type=Path)
    parser.add_argument("--trusted-root-sha256")
    parser.add_argument("--diagnostic-offline-fixture", action="store_true")
    args = parser.parse_args()
    print(json.dumps(upgrade_execution_schema(
        authority_db=args.authority_db,
        execution_db=args.execution_db,
        instance_lock=args.instance_lock,
        namespace=args.namespace, journal_id=args.journal_id,
        backup=args.backup, install_root=args.install_root,
        diagnostic_offline_fixture=args.diagnostic_offline_fixture,
        trusted_root_sha256=args.trusted_root_sha256,
    ), sort_keys=True))


if __name__ == "__main__":
    main()
