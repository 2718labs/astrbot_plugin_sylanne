"""Offline v1 journal migration keeps the chain and Core head intact."""

from __future__ import annotations

import asyncio
from dataclasses import replace
import json
import msvcrt
from pathlib import Path
import sqlite3
import sys

import pytest

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / "rewrite"))
sys.path.insert(0, str(ROOT / "scripts" / "alpha1"))

from rewrite.tests.alpha1.authority.test_authority_daemon_cold_open import _installed_config, NAMESPACE  # noqa: E402
from rewrite.tests.alpha1.runtime.test_authority_v2_execution_journal import anchor, pending  # noqa: E402
from authority_execution_schema_upgrade import upgrade_execution_schema  # noqa: E402
from sylanne3.authority_service.v2_execution_journal import AuthorityV2ExecutionJournal  # noqa: E402


def _v1_fixture(tmp_path: Path):
    config, _, bootstrap = _installed_config(tmp_path)
    asyncio.run(bootstrap.aclose())
    execution = config.execution_journals[NAMESPACE]
    journal = AuthorityV2ExecutionJournal(
        execution.path, namespace=NAMESPACE, journal_id=execution.journal_id,
        create=False)
    before = replace(anchor(namespace=NAMESPACE),
                     execution_journal_id=execution.journal_id)
    appended = journal.append_once(pending(before=before))
    journal.close()
    with sqlite3.connect(config.authority_db) as db:
        db.execute(
            "UPDATE authority_namespaces SET execution_seq=1,execution_digest=? "
            "WHERE namespace=?", (appended.chain_digest, NAMESPACE),
        )
    with sqlite3.connect(execution.path) as db:
        db.execute("UPDATE authority_v2_execution_meta SET value='1' WHERE key='schema_version'")
    return config, execution, appended.chain_digest


def test_offline_fixture_backup_and_only_version_change(tmp_path: Path) -> None:
    config, execution, digest = _v1_fixture(tmp_path)
    backup = tmp_path / "backups" / "execution-v1.db"
    with pytest.raises(RuntimeError, match="installed Authority root"):
        upgrade_execution_schema(
            authority_db=config.authority_db, execution_db=execution.path,
            instance_lock=config.instance_lock, namespace=NAMESPACE,
            journal_id=execution.journal_id, backup=backup,
        )
    assert not backup.exists()
    (tmp_path / "authority-deployment.json").write_text(json.dumps({
        "schema": "sylanne.authority.deployment-state.v1",
        "status": "disabled_diagnostic_staging",
        "service_registered": False,
    }), encoding="utf-8")
    with pytest.raises(RuntimeError, match="formal installed Authority service proof"):
        upgrade_execution_schema(
            authority_db=config.authority_db, execution_db=execution.path,
            instance_lock=config.instance_lock, namespace=NAMESPACE,
            journal_id=execution.journal_id, backup=backup,
            install_root=tmp_path, trusted_root_sha256="0" * 64,
        )
    assert not backup.exists()
    with config.instance_lock.open("r+b") as lock:
        lock.seek(0)
        msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
        try:
            with pytest.raises(RuntimeError, match="instance lock is active"):
                upgrade_execution_schema(
                    authority_db=config.authority_db, execution_db=execution.path,
                    instance_lock=config.instance_lock, namespace=NAMESPACE,
                    journal_id=execution.journal_id, backup=backup,
                    diagnostic_offline_fixture=True,
                )
        finally:
            lock.seek(0)
            msvcrt.locking(lock.fileno(), msvcrt.LK_UNLCK, 1)
    assert not backup.exists()
    result = upgrade_execution_schema(
        authority_db=config.authority_db, execution_db=execution.path,
        instance_lock=config.instance_lock, namespace=NAMESPACE,
        journal_id=execution.journal_id, backup=backup,
        diagnostic_offline_fixture=True,
    )
    assert result["status"] == "diagnostic_schema_upgrade"
    assert result["core_head_unchanged"] is True
    assert result["sequence"] == 1 and result["chain_digest"] == digest
    with sqlite3.connect(execution.path) as db:
        assert dict(db.execute("SELECT key,value FROM authority_v2_execution_meta"))["schema_version"] == "2"
    with sqlite3.connect(backup) as db:
        assert dict(db.execute("SELECT key,value FROM authority_v2_execution_meta"))["schema_version"] == "1"
    with sqlite3.connect(config.authority_db) as db:
        assert db.execute(
            "SELECT execution_journal_id,execution_seq,execution_digest "
            "FROM authority_namespaces WHERE namespace=?", (NAMESPACE,),
        ).fetchone() == (execution.journal_id, 1, digest)


def test_core_head_mismatch_holds_without_schema_change(tmp_path: Path) -> None:
    config, execution, _ = _v1_fixture(tmp_path)
    with sqlite3.connect(config.authority_db) as db:
        db.execute("UPDATE authority_namespaces SET execution_digest=? WHERE namespace=?",
                   ("sha256:" + "0" * 64, NAMESPACE))
    backup = tmp_path / "mismatch-backup.db"
    with pytest.raises(RuntimeError, match="Core and v1 ExecutionJournal heads differ"):
        upgrade_execution_schema(
            authority_db=config.authority_db, execution_db=execution.path,
            instance_lock=config.instance_lock, namespace=NAMESPACE,
            journal_id=execution.journal_id, backup=backup,
            diagnostic_offline_fixture=True,
        )
    assert not backup.exists()
    with sqlite3.connect(execution.path) as db:
        assert dict(db.execute(
            "SELECT key,value FROM authority_v2_execution_meta"))["schema_version"] == "1"
