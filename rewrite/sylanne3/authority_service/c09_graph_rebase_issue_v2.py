"""Independent Core issuance for fully verified compact C09 V2 candidates."""
from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import hmac
import json

from .contract import AuthorityUnavailable
from ..runtime_contracts import canonical_digest, canonical_serialize
from ..runtime.c09_paged_capture_contract_v2 import (
    GraphErasureRebaseCertificateV2, c09_paged_value_to_wire_v2,
    c09_paged_value_from_wire_v2, MAX_DESCRIPTOR_BYTES_V2,
)

_SCHEMA = "sylanne3.authority.c09_graph_rebase_issue.v2"
_TABLE = "authority_c09_graph_rebase_issues_v2"
_DDL = "CREATE TABLE authority_c09_graph_rebase_issues_v2 (namespace TEXT NOT NULL, operation_id TEXT NOT NULL, issue_json TEXT NOT NULL, PRIMARY KEY(namespace,operation_id)) STRICT"
ISSUE_DDLS_V2 = {_TABLE: _DDL}
ISSUE_TRIGGERS_V2 = {f"{_TABLE}_{action.lower()}_immutable": f"CREATE TRIGGER {_TABLE}_{action.lower()}_immutable BEFORE {action} ON {_TABLE} BEGIN SELECT RAISE(ABORT,\'C09 V2 issue immutable\'); END" for action in ("UPDATE", "DELETE")}


@dataclass(frozen=True, slots=True)
class AuthorityGraphRebaseIssuedV2:
    certificate: GraphErasureRebaseCertificateV2
    issue_digest: str
    signature: str
    schema: str = _SCHEMA

    def __post_init__(self):
        if (type(self.certificate) is not GraphErasureRebaseCertificateV2
                or self.schema != _SCHEMA
                or self.issue_digest != canonical_digest((self.schema, self.certificate))
                or type(self.signature) is not str or len(self.signature) != 64
                or any(c not in "0123456789abcdef" for c in self.signature)):
            raise AuthorityUnavailable("C09 V2 issued original differs")
        if len(canonical_serialize(self).encode("utf-8")) > MAX_DESCRIPTOR_BYTES_V2:
            raise AuthorityUnavailable("C09 V2 issue exceeds the fixed descriptor bound")


def _wire(issue):
    return {"schema": issue.schema, "certificate": c09_paged_value_to_wire_v2(issue.certificate),
            "issue_digest": issue.issue_digest, "signature": issue.signature}


def _read_issue(db, namespace, operation_id):
    present = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (_TABLE,)).fetchone()
    if present is None:
        return None
    row = db.execute("SELECT length(CAST(issue_json AS BLOB)) FROM authority_c09_graph_rebase_issues_v2 WHERE namespace=? AND operation_id=?",
                     (namespace, operation_id)).fetchone()
    if row is None:
        return None
    if row[0] > MAX_DESCRIPTOR_BYTES_V2:
        raise AuthorityUnavailable("C09 V2 issued original exceeds its descriptor bound")
    raw = db.execute("SELECT issue_json FROM authority_c09_graph_rebase_issues_v2 WHERE namespace=? AND operation_id=?",
                     (namespace, operation_id)).fetchone()[0]
    value = json.loads(raw)
    if type(value) is not dict or set(value) != {"schema", "certificate", "issue_digest", "signature"}:
        raise AuthorityUnavailable("C09 V2 issued original has unknown fields")
    issue = AuthorityGraphRebaseIssuedV2(
        c09_paged_value_from_wire_v2(value["certificate"], GraphErasureRebaseCertificateV2),
        value["issue_digest"], value["signature"], value["schema"])
    scope = issue.certificate.candidate.scope
    if (scope.authority_namespace, scope.operation_id) != (namespace, operation_id) or canonical_serialize(_wire(issue)) != raw:
        raise AuthorityUnavailable("C09 V2 issue row or namespace differs")
    return issue


def _verify_signature(issue, key):
    expected = hmac.new(key, (_SCHEMA + "\n" + issue.issue_digest).encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, issue.signature):
        raise AuthorityUnavailable("C09 V2 installed issue signature differs")


def _require_private_cold(session, verified):
    from .c09_paged_capture_control_v2 import C09PagedCaptureSessionV2
    from ..runtime.c09_graph_rebase_candidate_v2 import VerifiedGraphRebaseColdV2
    if type(session) is not C09PagedCaptureSessionV2 or type(verified) is not VerifiedGraphRebaseColdV2:
        raise AuthorityUnavailable("actual installed scope and independent Graph cold handle required")
    session.require_current()
    candidate = verified.require_current()
    if (verified.session is not session or candidate.scope != session.scope
            or verified.pair.source_original != candidate.source
            or verified.target_identity != candidate.target_identity
            or verified.target_file_sha256 != candidate.target_file_sha256):
        raise AuthorityUnavailable("C09 V2 cold source, target or scope differs")
    m = session._control.maintenance
    m.core._require(m.credential, "execution_redaction_install", m.closure.namespace)
    m.closure.qualify_current_registry_location_v1(
        credential=m.credential, subject=m.subject, operation_id=session.scope.operation_id)
    installed = m.core._c09_maintenance_authority_v1
    if installed is None:
        raise AuthorityUnavailable("actual installed C09 issue signer absent")
    key, inventory, _ = installed
    if (inventory is not m.inventory_manifest or inventory.namespace != session.scope.authority_namespace
            or inventory.installation_id != session.scope.installation_id
            or inventory.authority_id != session.scope.authority_id):
        raise AuthorityUnavailable("C09 V2 issue crosses the installed inventory")
    frozen = m.gate.read_quiescence_original_v1(operation_id=session.scope.operation_id)
    m.control.verify_original_v1(frozen, "quiescence_digest")
    if frozen["quiescence_digest"] != session.scope.writer_freeze_digest:
        raise AuthorityUnavailable("C09 V2 actual writer freeze differs")
    facts = session.require_recovery_facts_v2(verified.pair)
    completion = facts.require_complete(scope_digest=session.scope.scope_digest,
                                        facts_pin_digest=facts._completion.pin_digest)
    return m, key, candidate, completion


def issue_current_graph_rebase_v2(session, verified):
    """Only a complete private cold handle can request the installed Core signer."""
    m, key, candidate, facts = _require_private_cold(session, verified)
    prior = m.control.read_build_original_v1(operation_id=session.scope.operation_id,
                                           kind="capture_prior_graph_certificate_v2")
    if prior is None:
        raise AuthorityUnavailable("actual prior Graph certificate inspection is not complete")
    details = prior["details"]
    if set(details) != {"schema", "scope_digest", "prior_schema", "prior_digest"} or details["scope_digest"] != session.scope.scope_digest:
        raise AuthorityUnavailable("C09 V2 prior certificate inspection differs")
    certificate = GraphErasureRebaseCertificateV2(candidate, facts.pin_digest,
        m.inventory_manifest.manifest_digest, details["prior_schema"], details["prior_digest"],
        verified.cold_read_digest)
    committed = canonical_digest((_SCHEMA, certificate))
    issue = AuthorityGraphRebaseIssuedV2(certificate, committed,
        hmac.new(key, (_SCHEMA + "\n" + committed).encode(), hashlib.sha256).hexdigest())
    from .erasure_closure_inventory import CleanupRunV2, _TABLES
    from .c09_connection_state_v1 import authority_id_in_tx_v1
    from .c09_pre_graph_core_dependency_source_v3 import close_pre_graph_core_dependencies_v3
    from ..runtime.c09_paged_sql_v2 import current_c09_sql_meter_v2
    close_pre_graph_core_dependencies_v3(session,meter=current_c09_sql_meter_v2())
    with m.core._tx() as db:
        run = m.closure._read_record(db, _TABLES[1], session.scope.operation_id, CleanupRunV2)
        if (run is None or authority_id_in_tx_v1(db) != session.scope.authority_id
                or run.accepted_receipt_digest != session.scope.accepted_receipt_digest
                or run.graph_barrier_receipt_digest != session.scope.barrier_digest):
            raise AuthorityUnavailable("C09 V2 actual accepted run changed before issue")
        m.closure._accepted_locked(db, run, m.subject)
        saved = db.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (_TABLE,)).fetchone()
        if saved is None:
            db.execute(_DDL)
            for action in ("UPDATE", "DELETE"):
                db.execute(f"CREATE TRIGGER {_TABLE}_{action.lower()}_immutable BEFORE {action} ON {_TABLE} BEGIN SELECT RAISE(ABORT,'C09 V2 issue immutable'); END")
        elif saved[0] != _DDL:
            raise AuthorityUnavailable("C09 V2 issue schema differs")
        previous = _read_issue(db, session.scope.authority_namespace, session.scope.operation_id)
        if previous is None:
            db.execute("INSERT INTO authority_c09_graph_rebase_issues_v2 VALUES(?,?,?)",
                (session.scope.authority_namespace, session.scope.operation_id, canonical_serialize(_wire(issue))))
        elif previous != issue:
            raise AuthorityUnavailable("C09 V2 Core issue replay differs")
    session.require_current()
    m.control.record_build_original_v1(operation_id=session.scope.operation_id,
        kind="graph_issued_v2", details=_wire(issue))
    return issue


def require_current_graph_rebase_issue_v2(session, verified, issued):
    m, key, candidate, facts = _require_private_cold(session, verified)
    if type(issued) is not AuthorityGraphRebaseIssuedV2:
        raise AuthorityUnavailable("actual Core-issued V2 original required")
    _verify_signature(issued, key)
    if (issued.certificate.candidate != candidate
            or issued.certificate.facts_pin_digest != facts.pin_digest
            or issued.certificate.cold_read_digest != verified.cold_read_digest):
        raise AuthorityUnavailable("C09 V2 issue differs from current complete facts and cold candidate")
    with m.core._tx() as db:
        if _read_issue(db, session.scope.authority_namespace, session.scope.operation_id) != issued:
            raise AuthorityUnavailable("actual Core V2 issue original is absent or changed")
    registered = m.control.read_build_original_v1(operation_id=session.scope.operation_id, kind="graph_issued_v2")
    if registered is None or registered["details"] != _wire(issued):
        raise AuthorityUnavailable("actual Control issue original differs")
    return issued.certificate


def require_registered_c09_core_schema_v2(session, original):
    """Classify only this installed version's exact fixed Core issue objects."""
    session.require_current()
    kind = original.object_type
    name = original.name
    sql = original.sql
    expected = ISSUE_DDLS_V2 if kind == "table" else ISSUE_TRIGGERS_V2 if kind == "trigger" else {}
    if original.table_name != _TABLE or expected.get(name) != sql:
        raise AuthorityUnavailable("unregistered C09 V2 Core schema object")
    return True


def require_registered_c09_core_row_v2(session, table, columns, row, *, meter):
    """Validate a prior compact issued original without retaining its response body."""
    session.require_current()
    if table != _TABLE or tuple(columns) != ("namespace", "operation_id", "issue_json") or len(row) != 3:
        raise AuthorityUnavailable("unregistered C09 V2 Core row")
    namespace, operation_id, raw = row
    if namespace != session.scope.authority_namespace or type(raw) is not str:
        raise AuthorityUnavailable("C09 V2 issued row crosses namespace")
    encoded = len(raw.encode("utf-8"))
    if encoded > MAX_DESCRIPTOR_BYTES_V2:
        raise AuthorityUnavailable("C09 V2 issued row exceeds its fixed bound")
    value = json.loads(raw)
    if type(value) is not dict or set(value) != {"schema", "certificate", "issue_digest", "signature"}:
        raise AuthorityUnavailable("C09 V2 issued row shape differs")
    issue = AuthorityGraphRebaseIssuedV2(
        c09_paged_value_from_wire_v2(value["certificate"], GraphErasureRebaseCertificateV2),
        value["issue_digest"], value["signature"], value["schema"])
    scope = issue.certificate.candidate.scope
    m = session._control.maintenance
    if (scope.authority_id != m.control.authority_id or scope.installation_id != m.control.installation_id
            or (scope.authority_namespace, scope.operation_id) != (namespace, operation_id)
            or canonical_serialize(_wire(issue)) != raw):
        raise AuthorityUnavailable("C09 V2 issued row identity or original bytes differ")
    installed = m.core._c09_maintenance_authority_v1
    if installed is None:
        raise AuthorityUnavailable("actual installed C09 verifier absent")
    _verify_signature(issue, installed[0])
    return issue


_COMPLETION = object()


class VerifiedGraphRebaseCompletionV2:
    __slots__ = ("_issuer", "_session", "facts_pin_digest", "graph_issue_digest",
                 "graph_mirror_digest", "old_execution_journal_id",
                 "old_execution_seq", "old_execution_digest")

    def __init__(self, token, session, issue, mirror, facts):
        if token is not _COMPLETION:
            raise AuthorityUnavailable("actual independent C09 completion required")
        self._issuer, self._session = token, session
        self.facts_pin_digest = facts.pin_digest
        self.graph_issue_digest = issue.issue_digest
        self.graph_mirror_digest = mirror["original_digest"]
        self.old_execution_journal_id = facts.old_journal_id
        self.old_execution_seq = facts.old_seq
        self.old_execution_digest = facts.old_digest

    def __eq__(self, other):
        if type(other) is not VerifiedGraphRebaseCompletionV2 or self._issuer is not _COMPLETION or other._issuer is not _COMPLETION:
            return False
        names = ("facts_pin_digest", "graph_issue_digest", "graph_mirror_digest", "old_execution_journal_id", "old_execution_seq", "old_execution_digest")
        return self._session is other._session and all(getattr(self, name) == getattr(other, name) for name in names)

    def require_current(self):
        if self._issuer is not _COMPLETION:
            raise AuthorityUnavailable("C09 completion identity changed")
        current = require_graph_rebase_completion_v2(self._session)
        names = ("facts_pin_digest", "graph_issue_digest", "graph_mirror_digest",
                 "old_execution_journal_id", "old_execution_seq", "old_execution_digest")
        if any(getattr(self, name) != getattr(current, name) for name in names):
            raise AuthorityUnavailable("C09 completion no longer belongs to this actual stage")
        return self


def require_graph_rebase_completion_v2(session):
    """Recheck immutable source Core and a genuinely completed post-mirror original."""
    from contextlib import closing
    from pathlib import Path
    import sqlite3
    from .c09_paged_capture_control_v2 import C09PagedCaptureSessionV2
    from .c09_paged_recovery_facts_v2 import _decode_completion
    from .c09_role_capture_pair_v2 import InstalledC09RolePairV2
    if type(session) is not C09PagedCaptureSessionV2:
        raise AuthorityUnavailable("actual installed capture session required")
    session.require_current()
    m = session._control.maintenance
    m.core._require(m.credential, "execution_redaction_install", m.closure.namespace)
    current = m.control.read_verified_current_storage_v1(verify_files=False)
    core_member = next(member for member in current.manifest["members"] if member["role"] == "core")
    m.control.verify_member_v1(core_member, prepared=False)
    source = Path(core_member["resolved_path"])
    actual_close = m._closed_connection_originals_v3.get(id(m.core))
    if (actual_close is None or actual_close[0] is not m.core
            or Path(actual_close[2]["path"]).resolve(strict=True) != source.resolve(strict=True)):
        raise AuthorityUnavailable("C09 immutable Core completion lacks actual same-handle close evidence")
    if any(Path(str(source) + suffix).exists() for suffix in ("-wal", "-shm", "-journal")):
        raise AuthorityUnavailable("C09 source Core has not completed its actual close boundary")
    with closing(sqlite3.connect(source.as_uri() + "?mode=ro&immutable=1", uri=True)) as db:
        db.execute("PRAGMA query_only=ON"); db.execute("BEGIN")
        issue = _read_issue(db, session.scope.authority_namespace, session.scope.operation_id)
    if issue is None:
        raise AuthorityUnavailable("actual immutable source Core V2 issue absent")
    installed = m.core._c09_maintenance_authority_v1
    if installed is None:
        raise AuthorityUnavailable("actual installed C09 issue verifier absent")
    _verify_signature(issue, installed[0])
    if issue.certificate.candidate.scope != session.scope:
        raise AuthorityUnavailable("C09 immutable issue belongs to another capture scope")
    registered = m.control.read_build_original_v1(operation_id=session.scope.operation_id, kind="graph_issued_v2")
    if registered is None or registered["details"] != _wire(issue):
        raise AuthorityUnavailable("C09 immutable Core issue is not its signed Control original")
    mirror = m.control.read_build_original_v1(operation_id=session.scope.operation_id, kind="graph_mirror_v2")
    if mirror is None:
        raise AuthorityUnavailable("actual completed Graph post-mirror original absent")
    details = mirror["details"]
    fields = {"schema", "scope_digest", "certificate_digest", "graph_issue_digest", "target_path",
              "target_identity", "target_file_sha256", "cold_read_digest"}
    if (set(details) != fields or details["schema"] != "sylanne3.c09.graph-mirror-completion.v2"
            or details["scope_digest"] != session.scope.scope_digest
            or details["certificate_digest"] != issue.certificate.certificate_digest
            or details["graph_issue_digest"] != issue.issue_digest):
        raise AuthorityUnavailable("C09 post-mirror original identity differs")
    producer = session._control._role_pairs.get("graph")
    pair = None if producer is None else producer.pair
    if type(pair) is not InstalledC09RolePairV2:
        raise AuthorityUnavailable("actual registered Graph role pair required")
    pair.require_current()
    target = Path(pair.target_path)
    stat = target.stat()
    identity = (stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns)
    if details["target_path"] != pair.target_path or tuple(details["target_identity"]) != identity:
        raise AuthorityUnavailable("C09 mirrored target path or completed file identity changed")
    if any(Path(str(target) + suffix).exists() for suffix in ("-wal", "-shm", "-journal")):
        raise AuthorityUnavailable("C09 mirrored target is not a closed file")
    with closing(sqlite3.connect(target.as_uri() + "?mode=ro&immutable=1", uri=True)) as db:
        db.execute("PRAGMA query_only=ON"); db.execute("BEGIN")
        namespace = json.loads(session.scope.graph_namespace)
        row = db.execute("SELECT certificate_json,issue_digest FROM graph_c09_rebase_certificates_v2 WHERE bot=? AND persona=? AND operation_id=?",
                         (*namespace, session.scope.operation_id)).fetchone()
    if row != (canonical_serialize(c09_paged_value_to_wire_v2(issue.certificate)), issue.issue_digest):
        raise AuthorityUnavailable("C09 actual Graph mirror differs from Core signed certificate")
    completed = m.control.read_build_original_v1(operation_id=session.scope.operation_id, kind="capture_facts_complete_v2")
    if completed is None:
        raise AuthorityUnavailable("actual signed complete paged facts original absent")
    completion = _decode_completion(completed["details"])
    if (completion.scope_digest != session.scope.scope_digest
            or completion.facts_intent_digest != session.scope.facts_pin_intent_digest
            or completion.pin_digest != issue.certificate.facts_pin_digest):
        raise AuthorityUnavailable("C09 completed facts pin differs from the independently signed Core issue")
    session.require_current()
    return VerifiedGraphRebaseCompletionV2(_COMPLETION, session, issue, mirror, completion)


def record_current_graph_rebase_mirror_v2(session, verified, issued):
    """Record only the independent fresh post-mirror scan of the real issued row."""
    from .c09_pre_graph_core_dependency_source_v3 import close_pre_graph_core_dependencies_v3
    from ..runtime.c09_paged_sql_v2 import current_c09_sql_meter_v2
    close_pre_graph_core_dependencies_v3(session,meter=current_c09_sql_meter_v2())
    from ..runtime.c09_graph_rebase_candidate_v2 import VerifiedGraphRebaseColdV2
    from .c09_paged_capture_control_v2 import C09PagedCaptureSessionV2
    if (type(session) is not C09PagedCaptureSessionV2
            or type(verified) is not VerifiedGraphRebaseColdV2
            or type(issued) is not AuthorityGraphRebaseIssuedV2):
        raise AuthorityUnavailable("actual post-mirror cold and signed Core original required")
    session.require_current()
    m = session._control.maintenance
    candidate = verified.require_current()
    expected_mirror = canonical_digest(('sylanne3.c09.actual-graph-mirror.v2',
        session.scope.scope_digest,issued.issue_digest,issued.certificate.certificate_digest))
    if (verified.session is not session or verified.cold_phase!='post_mirror'
            or verified.validated_mirror_digest!=expected_mirror or verified.issued_digest!=issued.issue_digest
            or candidate!=issued.certificate.candidate or candidate.scope!=session.scope):
        raise AuthorityUnavailable('actual same-session post-mirror cold result required')
    installed=m.core._c09_maintenance_authority_v1
    if installed is None:raise AuthorityUnavailable('actual installed C09 signer absent')
    _verify_signature(issued,installed[0])
    original_issue=m.control.read_build_original_v1(operation_id=session.scope.operation_id,kind='graph_issued_v2')
    if original_issue is None or original_issue['details']!=_wire(issued):
        raise AuthorityUnavailable('post-mirror actual issued Control original differs')
    details={'schema':'sylanne3.c09.graph-mirror-completion.v2','scope_digest':session.scope.scope_digest,
        'certificate_digest':issued.certificate.certificate_digest,'graph_issue_digest':issued.issue_digest,
        'target_path':verified.pair.target_path,'target_identity':list(verified.target_identity),
        'target_file_sha256':verified.target_file_sha256,'cold_read_digest':verified.cold_read_digest}
    actual_close = m._closed_connection_originals_v3.get(id(m.core))
    if actual_close is not None and actual_close[0] is m.core:
        completion = require_graph_rebase_completion_v2(session)
        existing = m.control.read_build_original_v1(operation_id=session.scope.operation_id, kind="graph_mirror_v2")
        if (existing is None or completion.graph_issue_digest != issued.issue_digest
                or completion.facts_pin_digest != issued.certificate.facts_pin_digest
                or issued.certificate.candidate.scope != session.scope
                or existing["details"]["certificate_digest"] != issued.certificate.certificate_digest):
            raise AuthorityUnavailable("closed-source mirror replay differs from actual original completion")
        if existing["details"]!=details:raise AuthorityUnavailable("closed-source mirror actual target/cold identity differs")
        session.retain_actual_post_mirror_graph_v3(verified)
        return existing
    m.core._require(m.credential,"execution_redaction_install",m.closure.namespace)
    with m.core._tx() as db:
        if _read_issue(db, session.scope.authority_namespace, session.scope.operation_id) != issued:
            raise AuthorityUnavailable("post-mirror lost its actual Core issue")
    facts = session.require_recovery_facts_v2(verified.pair)
    facts.require_complete(scope_digest=session.scope.scope_digest,
                           facts_pin_digest=issued.certificate.facts_pin_digest)
    original = m.control.record_build_original_v1(operation_id=session.scope.operation_id,
                                                kind="graph_mirror_v2", details=details)
    session.require_current()
    session.close_completed_authority_sources_v2()
    session.retain_actual_post_mirror_graph_v3(verified)
    return original


def require_historical_graph_issue_v2(session, schema, operation_id, certificate_digest):
    """Authenticate the selected historical Graph issue with its real Core key."""
    from contextlib import contextmanager, closing
    from pathlib import Path
    import sqlite3
    from ..runtime.c09_paged_sql_v2 import current_c09_sql_meter_v2
    session.require_current()
    m=session._control.maintenance
    meter=current_c09_sql_meter_v2()
    current=m.control.read_verified_current_storage_v2(meter=meter,verify_files=False)
    original=current.prepared_original
    if (current.storage_generation==0 or original is None or original["operation_id"]!=operation_id
            or current.manifest["certificate_digest"]!=certificate_digest):
        raise AuthorityUnavailable("historical Graph issue is not the actual selected predecessor")
    if schema not in {"sylanne3.graph.c09_erasure_rebase.v1","sylanne3.graph.c09_erasure_rebase.v2"}:
        raise AuthorityUnavailable("unregistered historical Graph certificate schema")
    installed=m.core._c09_maintenance_authority_v1
    if installed is None:
        raise AuthorityUnavailable("actual installed historical Graph signer absent")
    member=next(item for item in current.manifest["members"] if item["role"]=="core")
    @contextmanager
    def source_transaction():
        actual=m._closed_connection_originals_v3.get(id(m.core))
        if actual is None:
            with m.core._tx() as db:
                yield db
        else:
            source=Path(member["resolved_path"])
            if actual[0] is not m.core or Path(actual[2]["path"]).resolve(strict=True)!=source.resolve(strict=True):
                raise AuthorityUnavailable("historical Graph source lacks actual Core close identity")
            if any(Path(str(source)+suffix).exists() for suffix in ("-wal","-shm","-journal")):
                raise AuthorityUnavailable("historical closed Core source has companions")
            with closing(sqlite3.connect(source.as_uri()+"?mode=ro&immutable=1",uri=True)) as db:
                db.execute("PRAGMA query_only=ON");db.execute("BEGIN")
                yield db
    with source_transaction() as db:
        if schema=="sylanne3.graph.c09_erasure_rebase.v1":
            from .c09_graph_rebase_issue_v1 import read_graph_rebase_issue_original_v1,verify_graph_rebase_issue_signature_v1
            present=db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='authority_c09_graph_rebase_issues_v1'").fetchone()
            if present is None:
                raise AuthorityUnavailable("actual historical Core V1 issue schema absent")
            row=db.execute("SELECT operation_id,length(CAST(issue_json AS BLOB)) FROM authority_c09_graph_rebase_issues_v1 WHERE namespace=?",(session.scope.authority_namespace,)).fetchone()
            if row is None or row[0]!=operation_id:
                archived=db.execute("SELECT length(CAST(original_json AS BLOB)) FROM authority_c09_originals_archive_v1 WHERE namespace=? AND operation_id=? AND original_kind='graph_issue'",(session.scope.authority_namespace,operation_id)).fetchone()
                size=None if archived is None else archived[0]
            else:size=row[1]
            if size is None or size>MAX_DESCRIPTOR_BYTES_V2:
                raise AuthorityUnavailable("historical Core V1 issue absent or exceeds fixed descriptor bound")
            meter.charge_read(size)
            issue=read_graph_rebase_issue_original_v1(db,session.scope.authority_namespace,operation_id)
            if issue is None:
                raise AuthorityUnavailable("actual historical Core V1 issue absent")
            verify_graph_rebase_issue_signature_v1(issue,installed[0])
            identity=(issue.authority_id,issue.installation_id,issue.namespace,issue.operation_id,
                issue.certificate_digest,issue.maintenance_generation)
        else:
            issue=_read_issue(db,session.scope.authority_namespace,operation_id)
            if issue is None:
                raise AuthorityUnavailable("actual historical Core V2 issue absent")
            _verify_signature(issue,installed[0])
            scope=issue.certificate.candidate.scope
            identity=(scope.authority_id,scope.installation_id,scope.authority_namespace,scope.operation_id,
                issue.certificate.certificate_digest,scope.maintenance_generation)
    expected=(session.scope.authority_id,session.scope.installation_id,session.scope.authority_namespace,
        operation_id,certificate_digest,current.storage_generation)
    if identity!=expected or issue.issue_digest!=current.manifest["graph_issue_digest"]:
        raise AuthorityUnavailable("actual selected historical Graph Core issue differs")
    session.require_current()
    return dict(issue_schema=issue.schema,issue_digest=issue.issue_digest,
        certificate_digest=certificate_digest,maintenance_generation=current.storage_generation)
