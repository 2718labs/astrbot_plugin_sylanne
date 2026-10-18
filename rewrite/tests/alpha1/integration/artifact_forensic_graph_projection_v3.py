"""Package-external Root forensic projection of actual graph-storage.v3 bytes.

Both underlying connections open the immutable snapshot with mode=ro. TEMP
views expose the exact legacy logical column names needed by existing signature
and history validators. They do not install RuntimeStorage, issue a Work,
register a permission, rewrite JSON, modify an original, or authorize business
access. Each requested cell is independently consumed through full segment EOF
and checked against its actual header, producer and physical row reference.
"""
from contextlib import contextmanager
from pathlib import Path
from hashlib import sha256
import json
import os
import sqlite3

from sylanne3.runtime_contracts import canonical_digest, canonical_serialize
from sylanne3.graph_types import AtomKey
from sylanne3.segmented_sql_cell_v1 import (
    DDLS, TRIGGERS, GRAPH_REF_DDLS_V3, LAYOUT_SCHEMA, LAYOUT_SCHEMA_DIGEST, MAX_SEGMENT_BYTES)
from sylanne3.runtime.c09_canonical_json_stream_v2 import C09CanonicalJSONStreamV2


class _ForensicCellsV3:
    def __init__(self, db, bundle):
        self.db, self.policy = db, bundle.installation_policy
        self.cache = {}
        self.first_error = None
        for name, ddl in {**DDLS, **GRAPH_REF_DDLS_V3}.items():
            if self.db.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (name,)).fetchone() != (ddl,):
                raise ValueError("forensic physical schema differs: " + name)
        for name, ddl in TRIGGERS.items():
            if self.db.execute("SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?", (name,)).fetchone() != (ddl,):
                raise ValueError("forensic immutable trigger differs: " + name)
        self.layout = db.execute("SELECT singleton,schema,storage_instance_id,role,layout_id,layout_schema_digest,"
            "authority_id,authority_namespace,installation_id,storage_generation,origin_scope_digest "
            "FROM segmented_storage_layout_v1").fetchall()
        if len(self.layout) != 1:
            raise ValueError("one actual installed Graph layout required")
        self.layout = self.layout[0]
        row = self.layout
        if (row[:2] != (1, LAYOUT_SCHEMA) or row[3:6] != ("graph", "graph-storage.v3", LAYOUT_SCHEMA_DIGEST)
                or row[6:9] != (self.policy.expected_authority_id, self.policy.authority_namespace, self.policy.installation_id)
                or type(row[9]) is not int or row[9] < 1):
            raise ValueError("actual graph layout does not belong to the protected installed Root")
        for digest in (row[2], row[10]):
            if type(digest) is not str or len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
                raise ValueError("actual Graph layout instance/origin commitment required")

    def projected_text(self, cell, table, token, revision):
        try:
            return self.text(cell, table, token, revision)
        except BaseException as error:
            if self.first_error is None:
                self.first_error = error
            raise

    def one(self, table, columns, where, args):
        return self.db.execute("SELECT " + ",".join(columns) + " FROM " + table + " WHERE " + where, args).fetchone()

    def exists(self, table):
        return self.db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone() is not None

    def _runtime_origin(self, cell, header, table, token, revision):
        if not self.exists("runtime_cell_origins_v3"):
            return False
        row = self.one("runtime_cell_origins_v3",
            ("origin_digest", "selection_digest", "role", "authority_id", "installation_id", "namespace_json",
             "operation_id", "event_digest", "locator_json", "read_proof_json"), "origin_digest=?", (header[7],))
        if row is None:
            return False
        namespace, locator, proof = json.loads(row[5]), json.loads(row[8]), json.loads(row[9])
        if any(canonical_serialize(value) != encoded for value, encoded in
                ((namespace, row[5]), (locator, row[8]), (proof, row[9]))):
            raise ValueError("actual runtime origin bytes are not canonical")
        origin = dict(schema="sylanne3.runtime-cell-origin.v3", selection_digest=row[1],
            role=row[2], authority_id=row[3], installation_id=row[4], namespace=namespace,
            operation_id=row[6], event_digest=row[7], locator=locator, read_proof=proof)
        if (canonical_digest(origin) != row[0] or row[0] != header[7]
                or row[2:5] != ("graph", self.policy.expected_authority_id, self.policy.installation_id)
                or row[6] != header[2]
                or canonical_digest(dict(schema="sylanne3.runtime-cell-identity.v3", instance=self.layout[2],
                    origin_digest=row[0], locator=locator, payload_sha256=header[5])) != cell):
            raise ValueError("actual runtime producer identity/layout/cell digest differs")
        # These are the ordinary Graph producer's exact actual event/history joins.
        # Contact Plan streams have a different dedicated producer recipe.
        if proof.get("schema") == "sylanne.contact-plan-stream-origin.v3":
            raise ValueError("Contact Plan stream is outside this Artifact forensic projection")
        key = AtomKey.from_token(token)
        if (table not in {"graph_atoms", "graph_history"} or locator != {
                "table": "graph_atoms", "token": token, "revision": revision}
                or header[1] != key.token or namespace != list(self.policy.namespace.as_tuple)
                or proof["event_scope"][:2] != namespace or proof["event_scope"][3] != row[6]):
            raise ValueError("actual runtime Graph row location/namespace differs")
        event = self.one("graph_events", ("digest", "reads", "epoch_reads"),
            "bot=? AND persona=? AND session=? AND event_id=?", tuple(proof["event_scope"]))
        history = self.one("graph_history",
            ("value_cell_id", "dependencies", "event_bot", "event_persona", "event_session", "event_id"),
            "token=? AND revision=?", (token, revision))
        if (event != (row[7], canonical_serialize(proof["reads"]), canonical_serialize(proof["epochs"]))
                or history is None or history[0] != cell or list(history[2:]) != proof["event_scope"]
                or sorted(item[0] for item in json.loads(history[1])) != sorted(proof["dependencies"])):
            raise ValueError("actual runtime Graph producer lost its event/readset/history")
        return True

    def _owner_source_origin(self, cell, header, table, token, revision):
        if not self.exists("graph_owner_source_prepared_v3"):
            return False
        row = self.one("graph_owner_source_prepared_v3",
            ("prepared_digest", "bot", "persona", "operation_id", "attempt_id", "request_claim_digest", "metadata_json",
             "input_sha256", "input_bytes", "original_digest", "original_bytes", "source_sha256", "source_bytes", "phase"),
            "prepared_digest=?", (header[7],))
        if row is None:
            return False
        value = json.loads(row[6])
        ns = (row[1], row[2])
        cursor = self.one("segmented_cell_writes_v1",
            ("origin_scope_digest", "logical_locator_json", "producer_operation_id", "erasure_owner_ref", "phase",
             "next_ordinal", "next_byte_offset", "prefix_root", "prefix_sha256", "expected_total_bytes",
             "verify_next_ordinal", "verify_next_byte_offset", "verify_prefix_root", "verify_prefix_sha256"),
            "cell_id=?", (cell,))
        attempt = self.one("graph_owner_domain_attempts_v3",
            ("request_digest", "attempt_id", "graph_revision", "graph_epoch", "permit_json", "receipt_json"),
            "bot=? AND persona=? AND operation_id=?", (*ns, row[3]))
        bundle = self.one("graph_bundle_operations", ("digest", "activity_id", "effect_id", "commit_seq", "receipt_json"),
            "bot=? AND persona=? AND operation_id=?", (*ns, row[3]))
        original = self.one("graph_domain_production_originals_v3",
            ("domain", "operation_kind", "original_digest", "original_payload_cell_id", "prepared_digest", "bundle_digest"),
            "bot=? AND persona=? AND operation_id=?", (*ns, row[3]))
        history = self.one("graph_history",
            ("value_cell_id", "valid", "event_bot", "event_persona", "event_session", "event_id"),
            "token=? AND revision=1", (value["source_ref"],))
        event = None if bundle is None else self.one("graph_events", ("digest", "reads", "epoch_reads"),
            "bot=? AND persona=? AND session=? AND event_id=?", (*ns, bundle[1], row[3]))
        from sylanne3.runtime.owner_material_source_storage_v3 import _qualify_owner_source_cell_values_v3
        proof = _qualify_owner_source_cell_values_v3(row, cursor, attempt, bundle, original, history, event,
            cell_id=cell, header=header, authority_id=self.policy.expected_authority_id,
            installation_id=self.policy.installation_id, authority_namespace=self.policy.authority_namespace)
        if proof is None or proof["phase"] != "committed":
            raise ValueError("unattached/pending Owner Source cell is not a forensic business original")
        wanted = "original" if table == "graph_domain_production_originals_v3" else "source"
        if (proof["cell_name"] != wanted or ns != self.policy.namespace.as_tuple
                or table in {"graph_atoms", "graph_history"} and
                   (token != value["source_ref"] or revision != 1)
                or table == "graph_domain_production_originals_v3" and token != row[3]):
            raise ValueError("actual committed Owner Source cell is attached to another physical location")
        return True

    def _capture_origin(self, cell, header, table, token, revision):
        cursor = self.one("segmented_cell_writes_v1",
            ("origin_scope_digest", "logical_locator_json", "codec_id", "producer_operation_id", "erasure_owner_ref",
             "phase", "next_ordinal", "next_byte_offset", "prefix_root", "prefix_sha256", "expected_total_bytes",
             "verify_next_ordinal", "verify_next_byte_offset", "verify_prefix_root", "verify_prefix_sha256"),
            "cell_id=?", (cell,))
        if cursor is None:
            raise ValueError("cell has no actual runtime, committed Owner Source or sealed capture producer")
        locator = json.loads(cursor[1])
        key = [token] if table == "graph_atoms" else [token, revision]
        if (table not in {"graph_atoms", "graph_history"} or canonical_serialize(locator) != cursor[1]
                or set(locator) != {"role", "family", "primary_key", "column", "source_schema_digest"}
                or (locator["role"], locator["family"], locator["primary_key"], locator["column"]) !=
                   ("graph", table, key, "value")
                or type(locator["source_schema_digest"]) is not str or len(locator["source_schema_digest"]) != 64
                or any(c not in "0123456789abcdef" for c in locator["source_schema_digest"])
                or header[1] != token or header[7] != self.layout[10]
                or cursor[:1] != (header[7],) or cursor[2:5] != (header[0], header[2], header[1])
                or cursor[5] != "sealed" or cursor[6:10] != (header[4], header[3], header[6], header[5])
                or cursor[10] != header[3] or cursor[11:15] != (header[4], header[3], header[6], header[5])):
            raise ValueError("actual sealed capture location/producer/EOF cursor differs")
        if canonical_digest(dict(schema="sylanne3.segmented-cell-identity.v1", instance=self.layout[2],
                scope=header[7], erasure_owner=header[1], producer=header[2], locator=locator)) != cell:
            raise ValueError("actual capture cell identity differs from exact layout/scope/row locator")
        return True

    def text(self, cell, table, token, revision):
        key = (cell, table, token, revision)
        if key in self.cache:
            return self.cache[key]
        if table in {"graph_atoms", "graph_history"}:
            atom_key = AtomKey.from_token(token)
            if (atom_key.owner.bot, atom_key.owner.persona) != self.policy.namespace.as_tuple:
                raise ValueError("forensic Graph value crossed its actual namespace")
            ref = self.one(table, ("value_cell_id",), "token=? AND revision=?", (token, revision))
        elif table == "graph_domain_production_originals_v3":
            ref = self.one(table, ("original_payload_cell_id",), "bot=? AND persona=? AND operation_id=?",
                (*self.policy.namespace.as_tuple, token))
        else:
            raise ValueError("unregistered forensic logical value family")
        if ref != (cell,):
            raise ValueError("cell is not referenced by the exact physical row")
        header = self.one("segmented_cells_v1", ("codec_id", "erasure_owner_ref", "producer_operation_id", "total_bytes",
            "segment_count", "payload_sha256", "ordered_segment_root", "origin_scope_digest"), "cell_id=?", (cell,))
        if (header is None or header[0] not in {"canonical-json.ascii.v1", "canonical-json.utf8.v1"}
                or type(header[3]) is not int or header[3] < 0
                or type(header[4]) is not int or header[4] < 0):
            raise ValueError("actual canonical sealed cell header required")
        if not self._runtime_origin(cell, header, table, token, revision):
            if not self._owner_source_origin(cell, header, table, token, revision):
                self._capture_origin(cell, header, table, token, revision)
        parser = C09CanonicalJSONStreamV2(ensure_ascii=header[0] == "canonical-json.ascii.v1")
        digest, root, offset, chunks = sha256(), canonical_digest(("sylanne3.segmented-cell-genesis.v1", cell)), 0, []
        for ordinal in range(header[4]):
            row = self.one("segmented_cell_segments_v1", ("byte_offset", "payload", "payload_sha256"),
                "cell_id=? AND ordinal=?", (cell, ordinal))
            if (row is None or row[0] != offset or type(row[1]) is not bytes
                    or not 0 < len(row[1]) <= MAX_SEGMENT_BYTES or sha256(row[1]).hexdigest() != row[2]):
                raise ValueError("actual segment order/offset/size/SHA differs")
            parser.feed(row[1], lambda event: None)
            digest.update(row[1])
            root = canonical_digest(("sylanne3.segmented-cell-link.v1", root, cell, ordinal, offset, len(row[1]), row[2]))
            offset += len(row[1]); chunks.append(row[1])
            if offset > header[3]:
                raise ValueError("cell exceeds its original declared byte count")
        extra = self.one("segmented_cell_segments_v1", ("ordinal",), "cell_id=? AND ordinal>=? LIMIT 1", (cell, header[4]))
        parsed = parser.finish()
        if extra is not None or (offset, digest.hexdigest(), root, parsed.byte_count, parsed.sha256) != (
                header[3], header[5], header[6], header[3], header[5]):
            raise ValueError("actual complete cell EOF/length/hash/ordered root/canonical codec differs")
        value = b"".join(chunks).decode("utf-8")
        self.cache[key] = value
        return value


@contextmanager
def forensic_artifact_snapshot_connection_v3(*, snapshot, bundle):
    """Logical read projection only. No runtime handle, Work or business right."""
    if os.name != "posix" or os.geteuid() != 0:
        raise PermissionError("isolated Root-only forensic projection required")
    uri = Path(snapshot).as_uri() + "?mode=ro"
    physical = sqlite3.connect(uri, uri=True)
    logical = sqlite3.connect(uri, uri=True)
    try:
        physical.execute("PRAGMA query_only=ON"); physical.execute("BEGIN")
        cells = _ForensicCellsV3(physical, bundle)
        logical.execute("PRAGMA temp_store=MEMORY")
        logical.create_function("forensic_original_cell_v3", 4, cells.projected_text)
        logical.execute("CREATE TEMP VIEW graph_atoms AS SELECT token,bot,persona,owner_kind,subject,type_name,name,revision,"
            "forensic_original_cell_v3(value_cell_id,'graph_atoms',token,revision) AS value,valid,value_cell_id FROM main.graph_atoms")
        logical.execute("CREATE TEMP VIEW graph_history AS SELECT token,revision,"
            "forensic_original_cell_v3(value_cell_id,'graph_history',token,revision) AS value,valid,"
            "dependencies,event_bot,event_persona,event_session,event_id,value_cell_id FROM main.graph_history")
        # Life and D07 signed originals remain exact payload_json/signature TEXT.
        text_families = {
            "graph_d11_life_originals_v1": ("bot", "persona", "kind", "original_ref", "producing_operation_id",
                "payload_json", "payload_digest", "signature"),
            "graph_d07_execution_originals_v1": ("bot", "persona", "kind", "original_ref",
                "payload_json", "payload_digest", "signature"),
            "graph_domain_production_originals_v1": ("bot", "persona", "operation_id", "domain", "operation_kind",
                "request_digest", "original_digest", "original_payload_json", "read_versions_json",
                "bundle_digest", "receipt_json", "receipt_digest"),
        }
        for table, columns in text_families.items():
            if not cells.exists(table):
                continue
            schema = physical.execute("PRAGMA table_info(" + table + ")").fetchall()
            if tuple(row[1] for row in schema) != columns or any(row[2].upper() != "TEXT" for row in schema):
                raise ValueError("actual original JSON/signature TEXT family ABI differs: " + table)
        from sylanne3.runtime.domain_production_originals_v1 import _validate_physical_original_metadata_v3
        if cells.exists("graph_domain_production_originals_v3"):
            duplicates = physical.execute("SELECT 1 FROM graph_domain_production_originals_v3 p "
                "JOIN graph_domain_production_originals_v1 l USING(bot,persona,operation_id) LIMIT 1").fetchone()
            if duplicates is not None:
                raise ValueError("logical/physical domain producer identity is ambiguous")
            for bot, persona, operation in physical.execute(
                    "SELECT bot,persona,operation_id FROM graph_domain_production_originals_v3 "
                    "WHERE bot=? AND persona=?", cells.policy.namespace.as_tuple):
                row = cells.one("graph_domain_production_originals_v3",
                    ("domain", "operation_kind", "request_digest", "original_digest", "original_payload_cell_id",
                     "prepared_digest", "read_versions_json", "bundle_digest", "receipt_json", "receipt_digest"),
                    "bot=? AND persona=? AND operation_id=?", (bot, persona, operation))
                _validate_physical_original_metadata_v3(physical, cells.policy.namespace, operation, row)
            logical.execute("CREATE TEMP VIEW graph_domain_production_originals_v1 AS "
                "SELECT bot,persona,operation_id,domain,operation_kind,request_digest,original_digest,original_payload_json,"
                "read_versions_json,bundle_digest,receipt_json,receipt_digest FROM main.graph_domain_production_originals_v1 "
                "UNION ALL SELECT bot,persona,operation_id,domain,operation_kind,request_digest,original_digest,"
                "forensic_original_cell_v3(original_payload_cell_id,'graph_domain_production_originals_v3',operation_id,0),"
                "read_versions_json,bundle_digest,receipt_json,receipt_digest FROM main.graph_domain_production_originals_v3")
        logical.execute("PRAGMA query_only=ON")
        try:
            yield logical
        except BaseException as error:
            if cells.first_error is not None:
                raise cells.first_error from error
            raise
    finally:
        logical.close()
        physical.close()
