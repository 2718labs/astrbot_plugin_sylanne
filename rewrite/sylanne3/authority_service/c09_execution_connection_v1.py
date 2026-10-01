"""A read-only execution-original reader over a qualified maintenance connection.

It has no journal constructor, append port, business admission or recovery ACK.
The source inode and schema come from the protected current storage lineage.
"""
from __future__ import annotations

import json
from pathlib import Path

from .contract import AuthorityUnavailable
from .v2_execution_journal import (
    _OBJECTS, _OBJECTS_V4, _OBJECTS_V4_LEGACY, _CORE_SEAL_SOURCE_KEY, _CORE_SEAL_SOURCE_SCHEMA,
    AuthorityV2ExecutionJournal, scan_execution_original_rows_v1,
    decode_internal_original_row_v1, internal_original_append_receipt_v1)


class C09ExecutionOriginalsConnectionV1:
    def __init__(self, *, db, control, namespace):
        from .c09_storage_control_v1 import C09StorageControlV1
        from .current_source_location_v1 import read_current_storage_lineage_v1
        if type(control) is not C09StorageControlV1 or not db.in_transaction:
            raise AuthorityUnavailable("execution originals need protected control and pinned source SQL")
        control.lease.require_held()
        context = control.read_verified_current_storage_v1(verify_files=False)
        context.require_current("maintenance")
        read_current_storage_lineage_v1(control, context, namespace=namespace,
            installation_id=control.installation_id)
        member = next(m for m in context.manifest["members"] if m["role"] == "execution")
        actual_path = Path(db.execute("PRAGMA database_list").fetchone()[2]).resolve(strict=True)
        if member["namespace"] != namespace or str(actual_path) != member["resolved_path"]:
            raise AuthorityUnavailable("execution source SQL crossed selected inode")
        control.verify_member_v1(member, prepared=False)
        self._db, self.path, self.namespace = db, actual_path, namespace
        self.journal_id = member["incarnation_or_journal_id"]
        objects = {(kind, name): ddl for kind, name, ddl in db.execute(
            "SELECT type,name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'")}
        meta = dict(db.execute("SELECT key,value FROM authority_v2_execution_meta"))
        expected = {"schema_version": meta.get("schema_version"),
            "namespace": namespace, "journal_id": self.journal_id}
        if _CORE_SEAL_SOURCE_KEY in meta:
            expected[_CORE_SEAL_SOURCE_KEY] = meta[_CORE_SEAL_SOURCE_KEY]
        if (objects not in (_OBJECTS, _OBJECTS_V4, _OBJECTS_V4_LEGACY)
                or meta != expected or meta["schema_version"] not in {"1", "2", "4"}
                or (meta["schema_version"] == "4") != (objects in (_OBJECTS_V4, _OBJECTS_V4_LEGACY))):
            raise AuthorityUnavailable("actual execution source schema differs")
        self._schema_version = meta["schema_version"]
        if self._schema_version == "4":
            prefix = db.execute("SELECT authority_id,namespace,operation_id,old_journal_id,"
                "old_seq,old_digest,facts_pin_digest,graph_issue_digest,new_journal_id "
                "FROM authority_v2_execution_redacted_prefix_v4 WHERE singleton=1").fetchone()
            original = context.prepared_original
            head = None if original is None else original["old_execution_head_original"]
            if (original is None or prefix is None
                    or db.execute("SELECT count(*) FROM authority_v2_execution_redacted_prefix_v4").fetchone() != (1,)
                    or prefix != (control.authority_id, namespace, original["operation_id"],
                        head["journal_id"], head["seq"], head["digest"],
                        original["facts_pin_original"]["pin_digest"],
                        original["graph_issue_original"]["issue_digest"], self.journal_id)):
                raise AuthorityUnavailable("execution prefix differs from signed selected transition")
        if _CORE_SEAL_SOURCE_KEY in meta:
            source = json.loads(meta[_CORE_SEAL_SOURCE_KEY])
            core = next(m for m in context.manifest["members"] if m["role"] == "core")
            expected_source = {"schema": _CORE_SEAL_SOURCE_SCHEMA,
                "core_path": core["resolved_path"], "authority_id": control.authority_id,
                "namespace": namespace, "journal_id": self.journal_id}
            if source != expected_source or json.dumps(source, sort_keys=True, separators=(",", ":")) != meta[_CORE_SEAL_SOURCE_KEY]:
                raise AuthorityUnavailable("execution actual source Core link differs")

    def read_verified_rows_v1(self):
        if not self._db.in_transaction:
            raise AuthorityUnavailable("execution source snapshot ended")
        return scan_execution_original_rows_v1(self)

    def _decode_internal_row(self, row):
        return decode_internal_original_row_v1(self, row)

    def _internal_append_receipt(self, row, binding, phase):
        return internal_original_append_receipt_v1(self.journal_id, row, binding, phase)

    expected_digest = staticmethod(AuthorityV2ExecutionJournal.expected_digest)
