"""Fixed candidate qualification subprocess: immutable copies, no execution.

The authenticated parent already proves unchanged interpretation and actual
source signatures/whole-store commitments. This process uses candidate codecs,
catalogue and ABI capability exports against the exact stopped backup bytes.
It grants no business admission and never evaluates native mathematics.
"""
from __future__ import annotations
from dataclasses import asdict
import ctypes
import hashlib
import json
import os
from pathlib import Path
import resource
import sqlite3
import sys
import time

SCHEMA = "d12.candidate-readonly-qualification.v2"


def _file_digest(path):
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(block)
    return result.hexdigest()


def _json(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate fixed qualification field")
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique,
        parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite qualification field")))


def _install_audit(uris, native):
    def audit(event, args):
        if (event.startswith(("socket.", "subprocess.", "os.exec", "os.spawn"))
                or event in {"os.system", "os.fork", "os.forkpty", "os.remove", "os.rename",
                    "os.mkdir", "os.rmdir", "os.chmod", "os.chown", "os.link", "os.symlink",
                    "os.truncate", "os.utime", "os.putenv", "os.unsetenv"}):
            raise RuntimeError("candidate reader prohibits external effects")
        if event == "open":
            _path, mode, flags = args
            if (type(mode) is str and any(c in mode for c in "wax+")
                    or type(flags) is int and flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND)):
                raise RuntimeError("candidate reader prohibits file writes")
        if event == "ctypes.dlopen" and args[0] != str(native):
            raise RuntimeError("candidate reader permits only the exact pinned native handle")
        if event == "sqlite3.connect" and args[0] not in uris | {":memory:"}:
            raise RuntimeError("candidate reader permits only immutable registered copies or schema memory")
    sys.addaudithook(audit)


def _graph(db, registry, ns, authority_namespace):
    from sylanne3.graph_types import AtomKey
    from sylanne3.runtime_contracts import canonical_digest, canonical_serialize
    from sylanne3.runtime.c09_d04_originals_v3 import TABLE as D04_TABLE, read_d04_inventory_row_v3
    from sylanne3.runtime.c09_budget_rows_v1 import TABLES as BUDGET_TABLES, validate_c09_budget_schema_v1, validate_c09_budget_row_v1
    from sylanne3.runtime.domain_production_erasure_v1 import TABLE_COLUMNS, validate_domain_production_schema_v1, validate_domain_production_row_v1
    from sylanne3.runtime.domain_production_original_codec_v1 import decode_domain_production_original_row_v1, decode_domain_production_outbox_row_v1
    from sylanne3.runtime.c09_d07_execution_v1 import (
        TABLE as D07_TABLE, STAGE_TABLE, ACCOUNTING_TABLE, validate_d07_schema_v1,
        read_d07_inventory_row_v1, validate_d07_stage_attempt_row_v1, validate_d07_accounting_attempt_row_v1,
    )
    from sylanne3.graph_store import GraphStore
    metadata = GraphStore._decode_recovery(db.execute(
        "SELECT schema,requirements_json,graph_revision FROM graph_recovery_metadata_v2 WHERE bot=? AND persona=?",
        ns.as_tuple).fetchone(), ns)
    if metadata is None or metadata.requirements.authority_namespace != authority_namespace:
        raise ValueError("candidate actual Graph namespace/recovery original differs")
    tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    erased = set()
    if "graph_c09_erased_keys_v1" in tables:
        erased = {r[0] for r in db.execute("SELECT key_digest FROM graph_c09_erased_keys_v1 WHERE bot=? AND persona=?", ns.as_tuple)}
        if erased and not db.execute("SELECT 1 FROM graph_c09_rebase_certificates_v1 WHERE bot=? AND persona=? LIMIT 1", ns.as_tuple).fetchone():
            raise ValueError("erased candidate rows lack actual transition certificate")
    validated = {}
    for table in ("graph_atoms", "graph_history"):
        columns = tuple(r[1] for r in db.execute('PRAGMA table_info("' + table + '")'))
        count = 0
        for row in db.execute('SELECT * FROM "' + table + '"'):
            value = dict(zip(columns, row, strict=True)); key = AtomKey.from_token(value["token"])
            body = _json(value["value"])
            if body.get("schema") == "sylanne3.graph.erased_value.v1":
                wanted = {"schema": "sylanne3.graph.erased_value.v1", "key_digest": canonical_digest(key.token)}
                if (body != wanted or value["valid"] != 0 or wanted["key_digest"] not in erased
                        or table == "graph_history" and value["dependencies"] != "[]"):
                    raise ValueError("candidate erased row is not the exact actual content-free marker")
            else:
                registry.validate(key, body)
            if canonical_serialize(body) != value["value"]:
                raise ValueError("candidate graph body is noncanonical")
            count += 1
        validated[table] = count
    validate_c09_budget_schema_v1(db)
    validate_domain_production_schema_v1(db)
    validate_d07_schema_v1(db)
    selected = ({D04_TABLE, D07_TABLE, STAGE_TABLE, ACCOUNTING_TABLE,
        "graph_domain_production_originals_v1", "graph_domain_production_outbox_v1"}
        | BUDGET_TABLES | set(TABLE_COLUMNS)) & tables
    for table in sorted(selected):
        columns = tuple(r[1] for r in db.execute('PRAGMA table_info("' + table + '")'))
        count = 0
        for row in db.execute('SELECT * FROM "' + table + '"'):
            if table == D04_TABLE:
                read_d04_inventory_row_v3(columns, row, authority_namespace=authority_namespace)
            elif table in BUDGET_TABLES:
                validate_c09_budget_row_v1(table, columns, row)
            elif table in TABLE_COLUMNS:
                validate_domain_production_row_v1(table, columns, row, authority_namespace=authority_namespace)
            elif table == D07_TABLE:
                read_d07_inventory_row_v1(columns, row, authority_namespace=authority_namespace)
            elif table == STAGE_TABLE:
                validate_d07_stage_attempt_row_v1(columns, row)
            elif table == ACCOUNTING_TABLE:
                validate_d07_accounting_attempt_row_v1(columns, row)
            elif table == "graph_domain_production_originals_v1":
                decode_domain_production_original_row_v1(row, ns, registry=registry)
            else:
                decode_domain_production_outbox_row_v1(row, ns)
            count += 1
        validated[table] = count
    return validated


def _sqlite_sequence(db, tables, known):
    """SQLite's actual internal AUTOINCREMENT ledger is a closed fixed type."""
    if "sqlite_sequence" not in tables:
        return
    if (tuple(r[1] for r in db.execute("PRAGMA table_info(sqlite_sequence)")) != ("name", "seq")
            or db.execute("SELECT sql FROM sqlite_master WHERE name='sqlite_sequence'").fetchone()
                != ("CREATE TABLE sqlite_sequence(name,seq)",)):
        raise ValueError("candidate SQLite sequence schema differs")
    rows = tuple(db.execute("SELECT name,seq FROM sqlite_sequence"))
    if len({r[0] for r in rows}) != len(rows):
        raise ValueError("candidate SQLite sequence identities repeat")
    for name, seq in rows:
        if name not in known or type(seq) is not int or seq < 0:
            raise ValueError("candidate SQLite sequence references an unknown table")
        ddl = db.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (name,)).fetchone()
        if ddl is None or "AUTOINCREMENT" not in ddl[0].upper():
            raise ValueError("candidate sequence is not a real AUTOINCREMENT table")
        quoted = '"' + name.replace('"', '""') + '"'
        primary = [r for r in db.execute("PRAGMA table_info(" + quoted + ")") if r[5]]
        if len(primary) != 1 or primary[0][2].upper() != "INTEGER":
            raise ValueError("candidate sequence primary key differs")
        key = '"' + primary[0][1].replace('"', '""') + '"'
        maximum = db.execute("SELECT max(" + key + ") FROM " + quoted).fetchone()[0]
        if maximum is not None and seq < maximum:
            raise ValueError("candidate sequence would reuse a consumed identity")


def main():
    resource.setrlimit(resource.RLIMIT_CPU, (150, 150))
    resource.setrlimit(resource.RLIMIT_AS, (1024**3, 1024**3))
    resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))
    raw = sys.stdin.buffer.read(65537)
    if len(raw) > 65536:
        raise ValueError("candidate request exceeds bound")
    packet = _json(raw)
    if (type(packet) is not dict or set(packet) != {"schema", "package_root", "manifest_sha256", "copies", "namespace", "authority_namespace"}
            or packet["schema"] != SCHEMA or set(packet["copies"]) != {"core", "deletion", "execution", "graph"}):
        raise ValueError("closed candidate read-only request required")
    root = Path(packet["package_root"]).resolve(strict=True)
    manifest = _json((root / "release-manifest.json").read_bytes())
    if hashlib.sha256((root / "release-manifest.json").read_bytes()).hexdigest() != packet["manifest_sha256"]:
        raise ValueError("candidate manifest bytes changed")
    paths = {role: Path(copy["backup_observation"]["resolved_path"]).resolve(strict=True)
        for role, copy in packet["copies"].items()}
    uris = {role: path.as_uri() + "?mode=ro&immutable=1" for role, path in paths.items()}
    for role, path in paths.items():
        if any(Path(str(path) + suffix).exists() for suffix in ("-wal", "-shm", "-journal")):
            raise ValueError("candidate backup is not actually closed and sidecar-free")
        expected = packet["copies"][role]["backup_observation"]
        if (not 0 <= expected["prepared_size"] <= 8 * 1024**3 or path.stat().st_size != expected["prepared_size"]
                or _file_digest(path) != expected["prepared_sha256"]):
            raise ValueError("candidate backup bytes differ")
    _install_audit(set(uris.values()), root / manifest["native"]["path"])
    sys.path.insert(0, str(root / "rewrite"))
    from sylanne3.host.installed_package import verify_installed_backend_runtime_v1
    from sylanne3.host.affect_scheme_asset import load_verified_affect_scheme
    from sylanne3.domain_registry import discover_domain_registry, REQUIRED_DOMAINS
    from sylanne3.native_runtime.loader import load_production_native
    from sylanne3.runtime_contracts import NamespaceId, canonical_digest
    from sylanne3.authority_service.d12_sqlite_backup_v2 import sqlite_logical_inventory_v2
    from sylanne3.authority_service.c09_authority_storage_rebase import _KNOWN_CORE_TABLES, _KNOWN_DELETION_TABLES
    from sylanne3.runtime.c09_graph_rebase_candidate_v1 import _KNOWN as GRAPH_TABLES
    verification = verify_installed_backend_runtime_v1(root, packet["manifest_sha256"])
    if not verification.verified:
        raise ValueError("candidate package verification failed")
    scheme = load_verified_affect_scheme(root, packet["manifest_sha256"]).scheme
    domains = discover_domain_registry(active_affect_scheme=scheme)
    if not domains.complete or tuple(sorted(domains.registrations)) != REQUIRED_DOMAINS:
        raise ValueError("actual candidate thirteen-domain registry is incomplete")
    catalogue = _json((root / "resources/catalogue/current.json").read_bytes())
    if catalogue.get("catalogue_hash") != domains.type_registry.catalogue_hash:
        raise ValueError("candidate installed type catalogue differs from actual registrations")
    native = load_production_native(root, trusted_manifest_sha256=packet["manifest_sha256"])
    if native.capabilities.max_dimension < 72 or not native.capabilities.supports_initial_box_math_v1:
        raise ValueError("candidate native cannot interpret installed D04 recipe")
    known = {"core": _KNOWN_CORE_TABLES, "deletion": _KNOWN_DELETION_TABLES,
        "execution": {"authority_v2_execution_meta", "authority_v2_execution_entries", "authority_v2_execution_redacted_prefix_v4"},
        "graph": GRAPH_TABLES}
    inventories, typed = {}, {}
    for role in sorted(uris):
        db = sqlite3.connect(uris[role], uri=True, isolation_level=None)
        try:
            db.execute("PRAGMA query_only=ON"); db.execute("PRAGMA temp_store=MEMORY"); db.execute("BEGIN")
            if db.execute("PRAGMA quick_check").fetchone() != ("ok",):
                raise ValueError("candidate exact backup integrity differs")
            tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            _sqlite_sequence(db, tables, known[role])
            if not tables.issubset(set(known[role]) | {"sqlite_sequence"}):
                raise ValueError("candidate does not classify every actual table")
            inventories[role] = sqlite_logical_inventory_v2(db, maximum_rows=100000, deadline=time.monotonic() + 60)
            if inventories[role] != packet["copies"][role]["logical_inventory"]:
                raise ValueError("candidate whole-store row or DDL interpretation differs")
            if role == "graph":
                typed = _graph(db, domains.type_registry, NamespaceId(**packet["namespace"]), packet["authority_namespace"])
        finally:
            db.close()
    for name, module in tuple(sys.modules.items()):
        if name == "sylanne3" or name.startswith("sylanne3."):
            filename = getattr(module, "__file__", None)
            if filename is None or not Path(filename).resolve().is_relative_to(root / "rewrite/sylanne3"):
                raise ValueError("candidate imported a foreign runtime module")
    result = dict(manifest_sha256=packet["manifest_sha256"], catalogue_hash=domains.type_registry.catalogue_hash,
        domains=REQUIRED_DOMAINS, native=asdict(native.capabilities), inventories=inventories,
        decoded_rows=typed, qualification="unchanged_interpretation_and_actual_typed_rows", writes_performed=False,
        business_admission=False)
    result["result_digest"] = canonical_digest(result)
    print(json.dumps(dict(schema=SCHEMA, request_sha256=hashlib.sha256(raw).hexdigest(), result=result),
        sort_keys=True, separators=(",", ":"), allow_nan=False))


if __name__ == "__main__":
    main()
