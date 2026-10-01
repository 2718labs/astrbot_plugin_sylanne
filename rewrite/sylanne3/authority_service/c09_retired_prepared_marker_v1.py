"""Cold relation check for retirement of the compatibility PREPARED slot.

The old source guard stays intact. Only the newly rebuilt Core archives this
exact V4 source seal, and its real sanitized independent journal prefix proves
the cut. No legacy V3 SWITCHED receipt is invented.
"""
from contextlib import closing
from dataclasses import asdict
import json
from pathlib import Path
import sqlite3

from .contract import AuthorityUnavailable
from .c09_recovery_frame_v4 import C09ExecutionSourceSealV4
from .c09_originals_archive_v1 import read_archived_original_v1
from .erasure_recovery_pin_v4 import read_execution_recovery_facts_pin_v4_locked, read_execution_recovery_facts_v4_locked
from .c09_recovery_resolver_v4 import read_recovery_bindings_v1_locked
from ..runtime_contracts import canonical_digest, canonical_serialize


def verify_retired_prepared_marker_v1(*, core_path, execution_path, source_core_path, namespace, operation_id,
        expected_pin_digest, expected_issue_digest, expected_new_journal_id, maintenance_generation):
    for path in (core_path, execution_path):
        if any(Path(str(path) + suffix).exists() for suffix in ("-wal", "-shm", "-journal")):
            raise AuthorityUnavailable("C09 retired marker cold files have sidecars")
    with closing(sqlite3.connect(Path(core_path).as_uri() + "?mode=ro&immutable=1", uri=True)) as core, closing(
            sqlite3.connect(Path(execution_path).as_uri() + "?mode=ro&immutable=1", uri=True)) as journal:
        core.execute("PRAGMA query_only=ON"); journal.execute("PRAGMA query_only=ON")
        if core.execute("SELECT 1 FROM authority_execution_redaction_seals_v3 WHERE namespace=?", (namespace,)).fetchone():
            raise AuthorityUnavailable("C09 rebased Core still has an active old PREPARED slot")
        row = core.execute("SELECT seal_json,seal_digest FROM authority_c09_execution_source_seals_v4 WHERE namespace=? AND operation_id=?",
            (namespace, operation_id)).fetchone()
        if row is None:
            raise AuthorityUnavailable("C09 actual V4 source original absent")
        archive = read_archived_original_v1(core, namespace=namespace, operation_id=operation_id, original_kind="seal")
        source_core_path = Path(source_core_path)
        uri = source_core_path.as_uri() + "?mode=ro" + ("" if any(Path(str(source_core_path) + suffix).exists()
            for suffix in ("-wal", "-shm", "-journal")) else "&immutable=1")
        # During sealing the source still has its held installed writer gate;
        # during preopen it has already passed the exact sidecar-free hashes.
        with closing(sqlite3.connect(uri, uri=True)) as source_db:
            source_db.execute("PRAGMA query_only=ON")
            source_marker = source_db.execute("SELECT operation_id,seal_json FROM authority_execution_redaction_seals_v3 WHERE namespace=?", (namespace,)).fetchone()
            source_original = source_db.execute("SELECT seal_json,seal_digest FROM authority_c09_execution_source_seals_v4 WHERE namespace=? AND operation_id=?",
                (namespace, operation_id)).fetchone()
        if source_original != row:
            raise AuthorityUnavailable("C09 new immutable source original differs from actual source Core")
        if source_marker is None:
            if archive is not None:
                raise AuthorityUnavailable("C09 archive claims a source PREPARED marker that never existed")
        elif (source_marker != (operation_id, row[0]) or archive is None
                or (archive["original_json"], archive["original_digest"], archive["maintenance_generation"]) !=
                    (row[0], row[1], maintenance_generation)):
            raise AuthorityUnavailable("C09 exact source marker archive/retirement differs")
        raw = json.loads(row[0])
        if raw.get("schema") != "sylanne3.c09.execution_source_seal.v4":
            raise AuthorityUnavailable("C09 unknown legacy PREPARED marker cannot be retired")
        raw["suffix_row_commitments"] = tuple(raw["suffix_row_commitments"])
        seal = C09ExecutionSourceSealV4(**raw)
        pin = read_execution_recovery_facts_pin_v4_locked(core, namespace, operation_id=operation_id)
        facts = read_execution_recovery_facts_v4_locked(core, namespace, operation_id=operation_id)
        bindings = read_recovery_bindings_v1_locked(core, namespace=namespace, operation_id=operation_id)
        prefix = journal.execute("SELECT authority_id,namespace,operation_id,old_journal_id,old_seq,old_digest,facts_pin_digest,graph_issue_digest,new_journal_id FROM authority_v2_execution_redacted_prefix_v4 WHERE singleton=1").fetchone()
        meta = dict(journal.execute("SELECT key,value FROM authority_v2_execution_meta"))
        source = {"schema": "sylanne3.execution.core_redaction_source.v1", "core_path": str(Path(core_path).resolve()),
            "authority_id": seal.authority_id, "namespace": namespace, "journal_id": expected_new_journal_id}
        core_row = core.execute("SELECT generation,execution_journal_id FROM authority_namespaces WHERE namespace=?", (namespace,)).fetchone()
        if (row != (canonical_serialize(asdict(seal)), seal.seal_digest)
                or (seal.namespace, seal.operation_id) != (namespace, operation_id)
                or pin is None or facts is None or bindings is None
                or pin.pin_digest != expected_pin_digest or pin.seal_digest != seal.seal_digest
                or (pin.old_journal_id, pin.old_seq, pin.old_digest) !=
                   (seal.execution_journal_id, seal.execution_seq, seal.execution_digest)
                or pin.facts_digest != facts.facts_digest or bindings.facts_digest != facts.facts_digest
                or prefix != (seal.authority_id, namespace, operation_id, seal.execution_journal_id,
                    seal.execution_seq, seal.execution_digest, pin.pin_digest, expected_issue_digest, expected_new_journal_id)
                or meta != {"schema_version": "4", "namespace": namespace, "journal_id": expected_new_journal_id,
                    "core_redaction_source": json.dumps(source, sort_keys=True, separators=(",", ":"))}
                or core_row is None or core_row[1] != expected_new_journal_id):
            raise AuthorityUnavailable("C09 archive/source cut/facts/current independent prefix relation differs")
        return canonical_digest(("sylanne3.c09.retired-prepared-source-marker.v1", seal.seal_digest,
            pin.pin_digest, facts.facts_digest, bindings.bindings_digest, prefix, core_row, maintenance_generation))
