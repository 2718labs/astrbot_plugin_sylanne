"""Core-authenticated C09 Graph rebase issuance, bound to installed keys."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import hmac
import json
import sqlite3
from pathlib import Path

from .contract import AuthorityUnavailable, identifier


_TABLE = "authority_c09_graph_rebase_issues_v1"
_DDL = f"""CREATE TABLE {_TABLE}(
    namespace TEXT PRIMARY KEY, operation_id TEXT NOT NULL UNIQUE,
    issue_json TEXT NOT NULL) STRICT"""
_SCHEMA = "sylanne3.authority.c09_graph_rebase_issue.v1"


def _canonical_digest(value) -> str:
    from ..runtime_contracts import canonical_digest

    return canonical_digest(value)


def _canonical_serialize(value) -> str:
    from ..runtime_contracts import canonical_serialize

    return canonical_serialize(value)


@dataclass(frozen=True, slots=True)
class AuthorityGraphRebaseIssuedV1:
    authority_id: str
    installation_id: str
    namespace: str
    operation_id: str
    certificate_digest: str
    candidate_digest: str
    facts_pin_digest: str
    accepted_receipt_digest: str
    source_files_fingerprint: str
    target_file_sha256: str
    source_path: str
    target_path: str
    source_identity: tuple[int, int, int, int]
    target_identity: tuple[int, int, int, int]
    maintenance_generation: int
    issue_digest: str
    signature: str
    stage: str = "PREPARED"
    schema: str = _SCHEMA

    def __post_init__(self) -> None:
        for name in ("authority_id", "installation_id", "namespace",
                     "operation_id"):
            identifier(getattr(self, name), name)
        for name in ("certificate_digest", "candidate_digest",
                     "facts_pin_digest", "accepted_receipt_digest",
                     "source_files_fingerprint", "target_file_sha256",
                     "issue_digest", "signature"):
            value = getattr(self, name)
            if (type(value) is not str or len(value) != 64
                    or any(ch not in "0123456789abcdef" for ch in value)):
                raise ValueError(f"invalid {name}")
        for name in ("source_path", "target_path"):
            value = getattr(self, name)
            if (type(value) is not str or not Path(value).is_absolute()
                    or str(Path(value).resolve(strict=False)) != value):
                raise ValueError(f"invalid {name}")
        for name in ("source_identity", "target_identity"):
            value = getattr(self, name)
            if (type(value) is not tuple or len(value) != 4
                    or any(type(part) is not int or part < 0 for part in value)):
                raise ValueError(f"invalid {name}")
        if type(self.maintenance_generation) is not int or self.maintenance_generation < 1:
            raise ValueError("invalid maintenance generation")
        if (self.schema != _SCHEMA or self.stage != "PREPARED"
                or self.issue_digest != _canonical_digest((
                    self.schema, self.authority_id, self.installation_id,
                    self.namespace, self.operation_id,
                    self.certificate_digest, self.candidate_digest,
                    self.facts_pin_digest, self.accepted_receipt_digest,
                    self.source_files_fingerprint, self.target_file_sha256,
                    self.source_path, self.target_path,
                    self.source_identity, self.target_identity,
                    self.maintenance_generation, self.stage))):
            raise ValueError("C09 Core issue commitment differs")


def sign_graph_rebase_issue_v1(*, key: bytes, authority_id: str,
                               installation_id: str, namespace: str,
                               operation_id: str, certificate_digest: str,
                               candidate_digest: str, facts_pin_digest: str,
                               accepted_receipt_digest: str,
                               source_files_fingerprint: str,
                               target_file_sha256: str,
                               source_path: str, target_path: str,
                               source_identity: tuple[int, int, int, int],
                               target_identity: tuple[int, int, int, int],
                               maintenance_generation: int) -> AuthorityGraphRebaseIssuedV1:
    if type(key) is not bytes or len(key) < 32:
        raise AuthorityUnavailable("installed C09 maintenance signing key unavailable")
    body = (authority_id, installation_id, namespace, operation_id,
            certificate_digest, candidate_digest, facts_pin_digest,
            accepted_receipt_digest, source_files_fingerprint,
            target_file_sha256, source_path, target_path,
            source_identity, target_identity, maintenance_generation)
    digest = _canonical_digest((_SCHEMA, *body, "PREPARED"))
    signature = hmac.new(key, (_SCHEMA + "\n" + digest).encode(),
                         hashlib.sha256).hexdigest()
    return AuthorityGraphRebaseIssuedV1(*body, digest, signature)


def verify_graph_rebase_issue_signature_v1(
        issue: AuthorityGraphRebaseIssuedV1, key: bytes) -> None:
    expected = hmac.new(key, (_SCHEMA + "\n" + issue.issue_digest).encode(),
                        hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, issue.signature):
        raise AuthorityUnavailable("installed C09 issue signature differs")


def install_graph_rebase_issue_schema_v1(db: sqlite3.Connection) -> None:
    db.execute(_DDL.replace("CREATE TABLE ", "CREATE TABLE IF NOT EXISTS ", 1))
    for action in ("UPDATE", "DELETE"):
        db.execute(
            f"CREATE TRIGGER IF NOT EXISTS {_TABLE}_{action.lower()}_immutable "
            f"BEFORE {action} ON {_TABLE} "
            "BEGIN SELECT RAISE(ABORT,'C09 Graph issue immutable'); END")
    expected = db.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?",
                          (_TABLE,)).fetchone()
    if expected != (_DDL,):
        raise AuthorityUnavailable("C09 Graph issue schema differs")


def read_graph_rebase_issue_v1_locked(
        db: sqlite3.Connection, namespace: str, operation_id: str | None = None) -> AuthorityGraphRebaseIssuedV1 | None:
    install_graph_rebase_issue_schema_v1(db)
    return read_graph_rebase_issue_original_v1(db, namespace, operation_id)


def read_graph_rebase_issue_original_v1(
        db: sqlite3.Connection, namespace: str, operation_id: str | None = None) -> AuthorityGraphRebaseIssuedV1 | None:
    """Read an already installed issue; safe on a frozen immutable source."""
    row = db.execute(f"SELECT operation_id,issue_json FROM {_TABLE} WHERE namespace=?",
                     (namespace,)).fetchone()
    if operation_id is not None and (row is None or row[0] != operation_id):
        from .c09_originals_archive_v1 import read_archived_original_v1
        archived = read_archived_original_v1(db,namespace=namespace,operation_id=operation_id,original_kind="graph_issue")
        row = None if archived is None else (operation_id,archived["original_json"])
    if row is None:
        return None
    try:
        raw = json.loads(row[1])
        raw["source_identity"] = tuple(raw["source_identity"])
        raw["target_identity"] = tuple(raw["target_identity"])
        issue = AuthorityGraphRebaseIssuedV1(**raw)
    except (TypeError, ValueError, KeyError) as exc:
        raise AuthorityUnavailable("C09 Graph issue malformed") from exc
    if (issue.namespace != namespace or issue.operation_id != row[0]
            or _canonical_serialize(asdict(issue)) != row[1]):
        raise AuthorityUnavailable("C09 Graph issue original differs")
    return issue


__all__ = ["AuthorityGraphRebaseIssuedV1", "sign_graph_rebase_issue_v1",
           "verify_graph_rebase_issue_signature_v1",
           "install_graph_rebase_issue_schema_v1",
           "read_graph_rebase_issue_v1_locked"]


def issue_graph_rebase_in_tx_v1(db, *, key, manifest, candidate, run, pin):
    """Persist the actual signed issue in the caller-owned source Core transaction."""
    from .c09_connection_state_v1 import authority_id_in_tx_v1
    from .erasure_closure_inventory import AuthorityErasureClosureInventory, CleanupRunV2, _TABLES
    from .erasure_recovery_pin_v4 import read_execution_recovery_facts_pin_v4_locked, read_execution_recovery_facts_v4_locked
    from ..runtime_contracts import canonical_serialize
    from ..runtime.c09_graph_rebase_candidate_v1 import GraphRebaseCandidateV1
    if type(candidate) is not GraphRebaseCandidateV1:
        raise AuthorityUnavailable("actual C09 Graph candidate required")
    namespace, operation_id = candidate.certificate_draft.namespace, candidate.operation_id
    installation_id = manifest.installation_id
    certificate = candidate.certificate_draft
    actual_run = AuthorityErasureClosureInventory._read_record(db, _TABLES[1], operation_id, CleanupRunV2)
    if (actual_run != run or run.accepted_receipt_digest != certificate.accepted_receipt_digest
            or run.graph_barrier_receipt_digest != certificate.barrier_receipt_digest
            or certificate.authority_id != authority_id_in_tx_v1(db)
            or installation_id != certificate.installation_id or namespace != manifest.namespace
            or candidate.frozen_inventory_digest != manifest.manifest_digest
            or read_execution_recovery_facts_pin_v4_locked(db, namespace, operation_id=operation_id) != pin
            or read_execution_recovery_facts_v4_locked(db, namespace, operation_id=operation_id) is None):
        raise AuthorityUnavailable("C09 current signed originals differ")
    issue = sign_graph_rebase_issue_v1(
        key=key, authority_id=authority_id_in_tx_v1(db),
        installation_id=installation_id,
        namespace=namespace, operation_id=operation_id,
        certificate_digest=certificate.certificate_digest,
        candidate_digest=candidate.candidate_digest,
        facts_pin_digest=pin.pin_digest,
        accepted_receipt_digest=run.accepted_receipt_digest,
        source_files_fingerprint=candidate.source_files_fingerprint,
        target_file_sha256=candidate.new_file_sha256,
        source_path=candidate.source_path,
        target_path=candidate.target_path,
        source_identity=candidate.source_identity,
        target_identity=candidate.target_identity,
        maintenance_generation=candidate.maintenance_generation)
    prior = read_graph_rebase_issue_v1_locked(db, namespace,operation_id=operation_id)
    if prior is not None:
        if prior != issue:
            raise AuthorityUnavailable("C09 Graph issue replay differs")
        return prior
    slot = read_graph_rebase_issue_v1_locked(db,namespace)
    if slot is None:
        db.execute("INSERT INTO authority_c09_graph_rebase_issues_v1 (namespace,operation_id,issue_json) VALUES(?,?,?)", (namespace,operation_id,canonical_serialize(asdict(issue))))
    else:
        from .c09_originals_archive_v1 import archive_exact_original_v1
        archive_exact_original_v1(db,namespace=namespace,operation_id=operation_id,
            original_kind="graph_issue",original_digest=issue.issue_digest,
            original_json=canonical_serialize(asdict(issue)),maintenance_generation=issue.maintenance_generation)
    return issue


def verify_graph_rebase_issue_in_tx_v1(db, *, key, manifest, issued, certificate):
    """Verify installed signing material and exact persisted issue/pin originals."""
    from .c09_connection_state_v1 import authority_id_in_tx_v1
    from .erasure_recovery_pin_v4 import read_execution_recovery_facts_pin_v4_locked
    from ..runtime.c09_storage_rebase_contract_v1 import GraphErasureRebaseCertificateV1
    if (type(issued) is not AuthorityGraphRebaseIssuedV1
            or type(certificate) is not GraphErasureRebaseCertificateV1
            or issued.certificate_digest != certificate.certificate_digest):
        raise AuthorityUnavailable("authenticated C09 Graph issue required")
    authority_id_in_tx_v1(db)
    verify_graph_rebase_issue_signature_v1(issued, key)
    prior = read_graph_rebase_issue_original_v1(db, issued.namespace,operation_id=issued.operation_id)
    pin = read_execution_recovery_facts_pin_v4_locked(db, issued.namespace,operation_id=issued.operation_id)
    if (prior != issued or pin is None
            or pin.pin_digest != issued.facts_pin_digest
            or issued.authority_id != authority_id_in_tx_v1(db)
            or issued.installation_id != manifest.installation_id
            or issued.namespace != manifest.namespace
            or issued.maintenance_generation !=
               certificate.maintenance_generation
            or (certificate.authority_id, certificate.installation_id,
                certificate.namespace, certificate.operation_id,
                certificate.accepted_receipt_digest,
                certificate.frozen_inventory_digest) != (
                    issued.authority_id, issued.installation_id,
                    issued.namespace, issued.operation_id,
                    issued.accepted_receipt_digest,
                    manifest.manifest_digest)):
        raise AuthorityUnavailable("current C09 Graph issue differs")
    return True
