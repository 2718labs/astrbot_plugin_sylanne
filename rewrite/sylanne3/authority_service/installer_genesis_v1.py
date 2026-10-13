"""Once-only handoff from a real fresh installer to first Graph provisioning.

An installed namespace is not generally a reusable genesis. The immutable
original below is issued only after fresh register/seal and zero-history schema
installation under the OS instance lease. Its one request consumption keeps the
same generation and independent anchor; it does not register another namespace.
"""
from __future__ import annotations

from contextlib import closing
from dataclasses import asdict, dataclass, fields
import json
from pathlib import Path
import sqlite3

from .contract import AuthorityUnavailable, identifier
from .c09_storage_control_v1 import InstalledC09InstanceLeaseV1, file_identity_v1
from ..runtime.restore_anchor import RestoreAnchor
from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize

SCHEMA = "sylanne3.authority.awaiting-first-graph-provision.v1"
TABLE = "authority_installer_graph_genesis_v1"
CONSUMPTIONS = "authority_installer_graph_genesis_consumptions_v1"
DDL = {
    TABLE: f"CREATE TABLE {TABLE}(namespace TEXT PRIMARY KEY,original_json TEXT NOT NULL,original_digest TEXT NOT NULL) STRICT",
    CONSUMPTIONS: f"CREATE TABLE {CONSUMPTIONS}(namespace TEXT PRIMARY KEY,request_id TEXT NOT NULL UNIQUE,request_json TEXT NOT NULL,receipt_json TEXT NOT NULL,receipt_digest TEXT NOT NULL) STRICT",
}


@dataclass(frozen=True, slots=True)
class AwaitingFirstGraphProvisionV1:
    authority_id: str
    installation_id: str
    namespace: NamespaceId
    authority_namespace: str
    holder: str
    subject: str
    peer_certificate_sha256: str
    profile_id: str
    manifest_digest: str
    catalogue_hash: str
    installer_configuration_digest: str
    anchor: RestoreAnchor
    initial_authority_event: tuple
    file_identities: tuple[tuple[str, str, int, int], ...]
    original_digest: str
    schema: str = SCHEMA

    def __post_init__(self):
        if self.schema != SCHEMA or type(self.namespace) is not NamespaceId or type(self.anchor) is not RestoreAnchor:
            raise ValueError("typed fresh installer genesis required")
        for name in ("authority_id", "installation_id", "authority_namespace", "holder", "subject", "profile_id"):
            identifier(getattr(self, name), name)
        for name in ("peer_certificate_sha256", "manifest_digest", "catalogue_hash", "installer_configuration_digest", "original_digest"):
            value = getattr(self, name)
            if type(value) is not str or len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
                raise ValueError("installer genesis commitment differs")
        from ..graph_coordinator import namespace_ref
        if (namespace_ref(self.namespace) != self.authority_namespace or self.subject != "mtls:sha256:" + self.peer_certificate_sha256
                or self.anchor.authority_id != self.authority_id or self.anchor.namespace != self.authority_namespace
                or self.anchor.activation_generation != 1 or self.anchor.revocation_epoch != 0
                or self.anchor.deletion_seq != 0 or self.anchor.execution_seq != 0
                or self.anchor.deletion_digest != "genesis" or self.anchor.execution_digest != "genesis"
                or type(self.initial_authority_event) is not tuple or len(self.initial_authority_event) != 6
                or self.initial_authority_event[1:4] != (self.authority_namespace, "install", 1)
                or self.initial_authority_event[5] != canonical_digest(self.initial_authority_event[:5])):
            raise ValueError("installer genesis is not exact settled generation one")
        if (tuple(row[0] for row in self.file_identities) != ("core", "deletion", "execution", "graph")
                or any(type(row) is not tuple or len(row) != 4 or not Path(row[1]).is_absolute()
                    or type(row[2]) is not int or type(row[3]) is not int for row in self.file_identities)):
            raise ValueError("installer genesis exact four-file identities required")
        body = {name: getattr(self, name) for name in self.__dataclass_fields__ if name != "original_digest"}
        if self.original_digest != canonical_digest(body):
            raise ValueError("installer genesis original commitment differs")


def _install_schema(db, *, create=False):
    for table, ddl in DDL.items():
        row = db.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone()
        if row is None:
            if not create:
                raise AuthorityUnavailable("installer genesis schema is partial or absent")
            db.execute(ddl)
            for action in ("UPDATE", "DELETE"):
                db.execute(f"CREATE TRIGGER {table}_no_{action.lower()} BEFORE {action} ON {table} "
                    "BEGIN SELECT RAISE(ABORT,'installer genesis original is immutable'); END")
        elif row != (ddl,):
            raise AuthorityUnavailable("installer genesis schema differs")


def decode_installer_genesis_original_v1(raw):
    if type(raw) is not dict or set(raw) != set(AwaitingFirstGraphProvisionV1.__dataclass_fields__):
        raise ValueError("installer genesis fixed original fields differ")
    value = dict(raw); value["namespace"] = NamespaceId(**value["namespace"])
    value["anchor"] = RestoreAnchor(**value["anchor"])
    value["initial_authority_event"] = tuple(value["initial_authority_event"])
    value["file_identities"] = tuple(tuple(row) for row in value["file_identities"])
    return AwaitingFirstGraphProvisionV1(**value)


def read_installer_genesis_original_v1_locked(db, namespace):
    if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (TABLE,)).fetchone() is None:
        return None
    _install_schema(db)
    row = db.execute(f"SELECT original_json,original_digest FROM {TABLE} WHERE namespace=?", (namespace,)).fetchone()
    if row is None: return None
    original = decode_installer_genesis_original_v1(json.loads(row[0]))
    if row != (canonical_serialize(asdict(original)), original.original_digest):
        raise AuthorityUnavailable("installer genesis original bytes differ")
    return original


def _require_initial_core_state(core, db, original):
    namespace = original.authority_namespace
    if tuple(db.execute("SELECT namespace FROM authority_namespaces")) != ((namespace,),):
        raise AuthorityUnavailable("installer genesis requires the exact single installed cohort")
    if (core._anchor(db, namespace, core._row(db, namespace)) != original.anchor
            or tuple(db.execute("SELECT seq,namespace,kind,generation,detail_digest FROM authority_events")) !=
               (tuple(original.initial_authority_event[:5]),)):
        raise AuthorityUnavailable("installer genesis Authority history changed")
    if db.execute("SELECT value FROM authority_meta WHERE key='service_mode'").fetchone() != ("v2-only",):
        raise AuthorityUnavailable("installer genesis requires persistent v2-only seal")
    tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    forbidden = {"authority_permits", "authority_transfers", "authority_effects", "authority_v2_fences", "authority_v2_epochs",
        "authority_v2_mutations", "authority_v2_never_begun", "authority_model_egress_v1", "authority_worker_result_read_attempts_v1"}
    forbidden |= {name for name in tables if name.startswith("authority_owner_")}
    for table in forbidden & tables:
        if db.execute(f'SELECT 1 FROM "{table}" LIMIT 1').fetchone():
            raise AuthorityUnavailable("installer genesis has prior Owner or business work: " + table)
    state = db.execute("SELECT aggregate_phase,active_operation_id,applied_seq,closed_seq FROM authority_scoped_erasure_v2 WHERE namespace=?", (namespace,)).fetchone()
    if state != ("clear", None, 0, None):
        raise AuthorityUnavailable("installer genesis zero-history scoped deletion original differs")


def record_installer_genesis_original_v1(*, core, config, registry, instance_lease, files):
    if type(instance_lease) is not InstalledC09InstanceLeaseV1 or instance_lease.path.resolve() != Path(config.instance_lock).resolve():
        raise AuthorityUnavailable("fresh installer genesis requires its actual instance lease")
    instance_lease.require_held()
    if len(config.installations_v2) != 1 or len(config.namespace_bindings_v2) != 1:
        raise AuthorityUnavailable("fresh installer genesis requires one exact protected peer/namespace binding")
    (peer, installation), = config.installations_v2.items()
    (binding, namespace), = config.namespace_bindings_v2.items()
    if binding[:2] != peer or namespace not in config.execution_journals:
        raise AuthorityUnavailable("fresh installer peer and namespace installation differ")
    role = binding[2]
    if type(role) is not NamespaceId:
        raise AuthorityUnavailable("fresh installer typed NamespaceId binding required")
    observed = []
    for kind in ("core", "deletion", "execution", "graph"):
        identity = file_identity_v1(files[kind])
        observed.append((kind, identity["resolved_path"], identity["device"], identity["file_id"]))
    with closing(sqlite3.connect(Path(files["graph"]).resolve().as_uri() + "?mode=ro", uri=True)) as graph:
        graph.execute("BEGIN")
        for table in ("graph_atoms", "graph_history", "graph_events", "graph_recovery_metadata_v2"):
            if graph.execute(f"SELECT 1 FROM {table} LIMIT 1").fetchone():
                raise AuthorityUnavailable("fresh installer Graph has prior business history")
    with core._tx() as db:
        _install_schema(db, create=True)
        event = tuple(db.execute("SELECT seq,namespace,kind,generation,detail_digest FROM authority_events"))
        if len(event) != 1: raise AuthorityUnavailable("fresh installer exact initialization event is absent")
        body = dict(authority_id=core._id(db), installation_id=installation.installation_id, namespace=role,
            authority_namespace=namespace, holder=installation.administrator_holder,
            subject="mtls:sha256:" + peer[0], peer_certificate_sha256=peer[0], profile_id=peer[1],
            manifest_digest=installation.manifest_digest, catalogue_hash=registry.catalogue_hash,
            installer_configuration_digest=canonical_digest((peer, installation, role, namespace, registry.catalogue_hash, tuple(observed))),
            anchor=core._anchor(db, namespace, core._row(db, namespace)),
            initial_authority_event=(*event[0], canonical_digest(event[0])), file_identities=tuple(observed), schema=SCHEMA)
        body["original_digest"] = canonical_digest(body)
        original = AwaitingFirstGraphProvisionV1(**body)
        _require_initial_core_state(core, db, original)
        if db.execute(f"SELECT 1 FROM {TABLE} LIMIT 1").fetchone():
            raise AuthorityUnavailable("fresh installer genesis original already exists")
        db.execute(f"INSERT INTO {TABLE} VALUES(?,?,?)", (namespace, canonical_serialize(asdict(original)), original.original_digest))
        return original


def install_first_graph_provision_composition_v1(service, config, registry):
    """Bind actual protected deployment and installed registry, never a wire DTO."""
    from ..graph_types import TypeRegistry
    if type(registry) is not TypeRegistry:
        raise AuthorityUnavailable("first Graph provisioning actual installed registry is absent")
    matches = [(binding, mapped) for binding, mapped in config.namespace_bindings_v2.items() if mapped == service.namespace]
    if len(matches) != 1 or len(config.namespace_bindings_v2) != 1 or len(config.installations_v2) != 1:
        raise AuthorityUnavailable("first Graph provisioning requires one actual installed cohort")
    (binding, namespace), = matches
    peer, role = binding[:2], binding[2]
    installed = config.installations_v2.get(peer)
    if installed is None or type(role) is not NamespaceId:
        raise AuthorityUnavailable("first Graph provisioning actual peer installation is absent")
    current = {"peer": peer, "namespace": role, "authority_namespace": namespace, "installation": installed,
        "catalogue_hash": registry.catalogue_hash,
        "files": {"core": str(Path(config.authority_db).resolve()), "deletion": str(Path(config.deletion_db).resolve()),
            "execution": str(Path(config.execution_journals[namespace].path).resolve()), "graph": str(Path(config.graph_db).resolve())}}
    prior = getattr(service, "_first_graph_provision_composition_v1", None)
    if prior is not None and prior != current:
        raise AuthorityUnavailable("first Graph provisioning composition is already bound")
    service._first_graph_provision_composition_v1 = current


def prepare_installer_genesis_consumption_v1(service):
    """Observe current file identities under journal freezes, outside Core SQL."""
    composition = getattr(service, "_first_graph_provision_composition_v1", None)
    reader = getattr(service.core, "_c09_storage_reader_v1", None)
    if composition is None or reader is None:
        return None
    context = reader.read_verified_current_storage_v1(verify_files=False)
    # Do not invoke business/applied readers in a non-initial generation.
    if context.stage != "READY" or context.storage_generation != 0 or context.pointer_version != 0:
        return None
    identities = []
    for role in ("core", "deletion", "execution", "graph"):
        item = file_identity_v1(composition["files"][role])
        identities.append((role, item["resolved_path"], item["device"], item["file_id"]))
    if tuple(identities) != tuple((m["role"], m["resolved_path"], m["device"], m["file_id"]) for m in context.manifest["members"]):
        raise AuthorityUnavailable("first Graph provisioning current file identity differs")
    return context, composition, tuple(identities)


def consume_installer_genesis_v1_locked(service, db, *, namespace_id, subject, holder, request_id, request_json, deletion_head, execution_head, preflight=None):
    original = read_installer_genesis_original_v1_locked(db, service.namespace)
    if original is None: return False
    if (original.namespace != namespace_id or original.subject != subject or original.holder != holder
            or (deletion_head.journal_id, deletion_head.seq, deletion_head.digest) !=
               (original.anchor.deletion_journal_id, 0, "genesis")
            or (execution_head.journal_id, execution_head.seq, execution_head.digest) !=
               (original.anchor.execution_journal_id, 0, "genesis")):
        raise AuthorityUnavailable("installer genesis original subject/cohort/heads differ")
    if preflight is None:
        raise AuthorityUnavailable("installer first Graph provision requires current installed composition and initial four-file selection")
    context, composition, identities = preflight
    current = context._reader
    if (context.storage_generation != 0 or context.pointer_version != 0 or context.stage != "READY"
            or current.authority_id != original.authority_id or current.installation_id != original.installation_id):
        raise AuthorityUnavailable("installer first Graph provision current generation differs")
    if identities != original.file_identities:
        raise AuthorityUnavailable("installer first Graph provision exact current four-file identities differ")
    peer, installation = composition["peer"], composition["installation"]
    if ((peer[0], peer[1], installation.installation_id, installation.administrator_holder, installation.manifest_digest,
            composition["catalogue_hash"], composition["namespace"], composition["authority_namespace"]) !=
            (original.peer_certificate_sha256, original.profile_id, original.installation_id, original.holder,
             original.manifest_digest, original.catalogue_hash, original.namespace, original.authority_namespace)
            or canonical_digest((peer, installation, composition["namespace"], composition["authority_namespace"],
                composition["catalogue_hash"], identities)) != original.installer_configuration_digest):
        raise AuthorityUnavailable("installer first Graph provision current package/catalogue/configuration differs")
    # Short authenticated pointer recheck only. No file or Graph reader is
    # called while the Core SQL transaction is held.
    with current._db() as control:
        head = current._current(control)
        if ((head["stage"], head["pointer_version"], head["current_manifest_digest"]) !=
                ("READY", context.pointer_version, context.manifest_digest)):
            raise AuthorityUnavailable("installer first Graph provision current pointer changed")
    row = db.execute(f"SELECT request_id,request_json,receipt_json,receipt_digest FROM {CONSUMPTIONS} WHERE namespace=?", (service.namespace,)).fetchone()
    if row is not None:
        if row[:2] != (request_id, request_json): raise AuthorityUnavailable("installer first Graph provision was consumed by another request")
        receipt = json.loads(row[2])
        if (canonical_digest(receipt) != row[3] or receipt.get("original_digest") != original.original_digest):
            raise AuthorityUnavailable("installer genesis consumption receipt differs")
        return True
    _require_initial_core_state(service.core, db, original)
    receipt = {"schema": "sylanne3.authority.first-graph-provision-consumed.v1", "namespace": service.namespace,
        "original_digest": original.original_digest, "request_id": request_id, "request_digest": canonical_digest(request_json),
        "anchor_digest": canonical_digest(original.anchor)}
    db.execute(f"INSERT INTO {CONSUMPTIONS} VALUES(?,?,?,?,?)", (service.namespace, request_id, request_json,
        canonical_serialize(receipt), canonical_digest(receipt)))
    service.core._event(db, service.namespace, "installer_first_graph_provision", 1,
        (original.original_digest, request_id, canonical_digest(request_json)))
    return True


def validate_installer_genesis_row_v1(table, columns, row):
    if table == TABLE:
        if tuple(columns) != ("namespace", "original_json", "original_digest"): raise AuthorityUnavailable("installer genesis columns differ")
        value = decode_installer_genesis_original_v1(json.loads(row[1]))
        if row != (value.authority_namespace, canonical_serialize(asdict(value)), value.original_digest):
            raise AuthorityUnavailable("installer genesis original identity differs")
    elif table == CONSUMPTIONS:
        if tuple(columns) != ("namespace", "request_id", "request_json", "receipt_json", "receipt_digest"):
            raise AuthorityUnavailable("installer genesis consumption columns differ")
        receipt = json.loads(row[3])
        if (set(receipt) != {"schema", "namespace", "original_digest", "request_id", "request_digest", "anchor_digest"}
                or receipt["schema"] != "sylanne3.authority.first-graph-provision-consumed.v1"
                or receipt["namespace"] != row[0] or receipt["request_id"] != row[1]
                or canonical_serialize(receipt) != row[3] or canonical_digest(receipt) != row[4]
                or receipt["request_digest"] != canonical_digest(row[2])):
            raise AuthorityUnavailable("installer genesis consumption original differs")
    else: raise AuthorityUnavailable("unknown installer genesis table")
