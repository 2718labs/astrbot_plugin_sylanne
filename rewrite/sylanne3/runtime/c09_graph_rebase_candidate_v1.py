"""Read-only-source, fresh-file Graph erasure rebase candidate.

The caller must independently authenticate the closed-writer snapshot, closure,
and installed table inventory. This builder never signs a Graph certificate or
claims that Authority deletion can close. It refuses populated unknown tables.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, fields
from contextlib import closing, nullcontext
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3

from ..graph_types import AtomKey
from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize
from .c09_storage_rebase_contract_v1 import (
    GraphRowDispositionV1, GraphTableDispositionManifestV1,
    GraphErasureRebaseCertificateV1,
)
from .c09_erasure_barrier_store_v1 import (
    read_c09_erasure_barrier_v1, verify_c09_graph_barrier_v1,
)
from .c09_erasure_plan_original_v1 import read_c09_erasure_plan_original_v1
from .graph_migration_snapshot_v1 import _KNOWN as _INSTALLED_TABLES
from .c09_foreground_attempt_v1 import (TABLE as _FOREGROUND_ATTEMPT_TABLE,
    verify_foreground_attempts_from_selected_core_v1)
from .c09_d04_originals_v3 import (
    TABLE as _D04_TABLE, COLUMNS as _D04_COLUMNS,
    D04ErasureInventoryHold, read_d04_inventory_row_v3,
    d04_original_dispositions_v3,
)
from .domain_production_erasure_v1 import (
    TABLE_COLUMNS as _DOMAIN_COLUMNS, validate_domain_production_schema_v1,
    validate_domain_production_row_v1, domain_production_original_dispositions_v1,
)
from .domain_production_original_codec_v1 import (
    ORIGINAL_COLUMNS as _SHARED_ORIGINAL_COLUMNS, OUTBOX_COLUMNS as _SHARED_OUTBOX_COLUMNS,
    decode_domain_production_original_row_v1, decode_domain_production_outbox_row_v1,
)
from .c09_budget_rows_v1 import TABLES as _BUDGET_TABLES, validate_c09_budget_row_v1, validate_c09_budget_schema_v1
from .graph_catalogue_upgrade_v1 import (
    COLUMNS as _CATALOGUE_COLUMNS, validate_catalogue_upgrade_schema_v1,
    validate_catalogue_upgrade_row_v1, catalogue_upgrade_c09_rows_v1,
)
from .c09_d07_execution_v1 import (
    TABLE as _D07_TABLE, STAGE_TABLE as _D07_STAGE_TABLE, ACCOUNTING_TABLE as _D07_ACCOUNTING_TABLE,
    COLUMNS as _D07_COLUMNS, validate_d07_schema_v1, read_d07_inventory_row_v1, d07_original_dispositions_v1,
    validate_d07_stage_attempt_row_v1, validate_d07_accounting_attempt_row_v1,
)
from .c09_contact_originals_v1 import (
    TABLE as _CONTACT_TABLE, COLUMNS as _CONTACT_COLUMNS,
    validate_contact_schema_v1, read_contact_inventory_row_v1, contact_original_dispositions_v1,
)
from .c09_contact_originals_v2 import (
    TABLE as _CONTACT_V2_TABLE, COLUMNS as _CONTACT_V2_COLUMNS,
    validate_contact_schema_v2, read_contact_inventory_row_v2, contact_original_dispositions_v2,
)
_C04_BASELINE_TABLE = "graph_c04_encoding_baselines_v3"
_SHARED_ORIGINAL_TABLE = "graph_domain_production_originals_v1"
_SHARED_OUTBOX_TABLE = "graph_domain_production_outbox_v1"


_HEX = re.compile(r"[0-9a-f]{64}\Z")
_BODY_TABLES = frozenset({"graph_atoms", "graph_history"})
_EDGE_TABLES = frozenset({"graph_dependencies", "graph_dependency_edges"})
_COMMITMENT_TABLES = frozenset({
    "graph_events", "graph_epochs", "graph_authority_epochs",
    "graph_type_catalog", "graph_type_authority",
    "graph_c09_erasure_barriers_v1",
    "graph_c09_erasure_plans_v1", "graph_source_access_revocations_v1",
    "graph_c09_cumulative_applications_v1",
})
_KNOWN = _INSTALLED_TABLES | _BODY_TABLES | _EDGE_TABLES | _COMMITMENT_TABLES | frozenset({
    "graph_c09_rebase_certificates_v1", "graph_c09_erased_keys_v1",
    "d02_resource_actuals_v1", "d02_resource_execution_receipts_v1",
    "d06_index_erasure_receipts", "d06_index_generations",
    "d06_index_receipts", "d06_index_source_blocks", "d06_index_sources",
    "graph_c04_association_inputs_v3", "runtime_d11_d04_root_freezes_v2",
    "runtime_d11_d04_root_freezes_v3",
    "graph_d07_behavior_original_v1",
}) | frozenset(_DOMAIN_COLUMNS) | {_SHARED_ORIGINAL_TABLE, _SHARED_OUTBOX_TABLE, _D07_TABLE,
    _D07_STAGE_TABLE, _D07_ACCOUNTING_TABLE, _C04_BASELINE_TABLE, _CONTACT_TABLE, _CONTACT_V2_TABLE}
_ERASED_SCHEMA = "sylanne3.graph.erased_value.v1"
_REBASE_TABLES = frozenset({"graph_c09_rebase_certificates_v1", "graph_c09_erased_keys_v1"})
_FACT_COLUMNS = frozenset({"token", "dependent_token", "dependency_token", "root_source_ref",
                           "source_ref", "source_token", "event_id", "digest", "request_digest",
                           "receipt_digest", "commitment", "operation_id"})


class GraphRebaseHold(RuntimeError):
    """The candidate cannot prove a complete, content-free row disposition."""


def _sha(value: str, name: str) -> None:
    if type(value) is not str or _HEX.fullmatch(value) is None:
        raise ValueError(f"invalid {name}")


def _quoted(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def _row_digest(value: tuple) -> str:
    """Commit SQLite blobs without putting their bytes in a certificate."""
    return canonical_digest(tuple(
        {"blob_sha256": hashlib.sha256(item).hexdigest(), "size": len(item)}
        if type(item) is bytes else item for item in value))


def _stream_file_sha256_v1(path: Path) -> str:
    """Hash the complete file with a fixed 64 KiB read workspace."""
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(65536), b""):
            digest.update(block)
    return digest.hexdigest()


def graph_source_files_fingerprint_v1(source_path: Path) -> str:
    """Pin the closed SQLite DB and any present WAL/SHM sidecars by bytes."""
    source = Path(source_path).resolve(strict=True)
    rows = []
    for suffix in ("", "-wal", "-shm"):
        path = Path(str(source) + suffix)
        if not path.exists():
            continue
        if not path.is_file() or path.is_symlink():
            raise GraphRebaseHold("Graph snapshot component is not a regular file")
        before = path.stat()
        hasher = hashlib.sha256()
        with path.open("rb") as stream:
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                hasher.update(block)
        after = path.stat()
        if ((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
                != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)):
            raise GraphRebaseHold("Graph snapshot changed during fingerprint")
        rows.append((suffix or "db", before.st_dev, before.st_ino,
                     before.st_size, hasher.hexdigest()))
    if not rows or rows[0][0] != "db":
        raise GraphRebaseHold("Graph snapshot DB is absent")
    return canonical_digest((str(source), tuple(rows)))


@dataclass(frozen=True, slots=True)
class GraphRebaseInputV1:
    namespace: NamespaceId
    operation_id: str
    accepted_receipt_digest: str
    barrier_receipt_digest: str
    certified_closure_digest: str
    writer_freeze_digest: str
    frozen_inventory_digest: str
    source_files_fingerprint: str
    affected_source_refs: tuple[str, ...]
    affected_atom_refs: tuple[str, ...]
    table_inventory: tuple[str, ...]
    installation_id: str = ""

    def __post_init__(self) -> None:
        if type(self.namespace) is not NamespaceId:
            raise TypeError("typed Graph namespace required")
        if type(self.operation_id) is not str or not self.operation_id:
            raise ValueError("C09 operation is absent")
        if type(self.installation_id) is not str or not self.installation_id:
            raise ValueError("installed Graph rebase identity is absent")
        for name in ("accepted_receipt_digest", "barrier_receipt_digest",
                     "certified_closure_digest", "writer_freeze_digest",
                     "frozen_inventory_digest", "source_files_fingerprint"):
            _sha(getattr(self, name), name)
        for name in ("affected_source_refs", "affected_atom_refs"):
            refs = getattr(self, name)
            if type(refs) is not tuple or not refs or refs != tuple(sorted(set(refs))):
                raise ValueError(f"{name} must be complete and canonical")
            for ref in refs:
                if NamespaceId.from_key(AtomKey.from_token(ref)) != self.namespace:
                    raise ValueError("C09 closure crosses namespace")
        if not set(self.affected_source_refs).issubset(self.affected_atom_refs):
            raise ValueError("source closure is absent from atom closure")
        if (type(self.table_inventory) is not tuple
                or self.table_inventory != tuple(sorted(set(self.table_inventory)))
                or not _BODY_TABLES.issubset(self.table_inventory)):
            raise ValueError("installed table inventory is incomplete")


@dataclass(frozen=True, slots=True)
class GraphRebaseCandidateV1:
    namespace: NamespaceId
    operation_id: str
    source_files_fingerprint: str
    source_closure_digest: str
    frozen_inventory_digest: str
    table_manifests: tuple[GraphTableDispositionManifestV1, ...]
    new_file_sha256: str
    candidate_digest: str
    new_incarnation: str
    maintenance_generation: int
    newly_erased_key_digests: tuple[str, ...]
    cumulative_erased_key_digests: tuple[str, ...]
    source_path: str
    target_path: str
    source_identity: tuple[int, int, int, int]
    target_identity: tuple[int, int, int, int]
    certificate_draft: GraphErasureRebaseCertificateV1
    affected_atom_refs: tuple[str, ...]
    writer_freeze_digest: str
    status: str = "candidate_only_hold"
    schema: str = "sylanne3.graph.c09_rebase_candidate.v1"

    def __post_init__(self) -> None:
        if (type(self.namespace) is not NamespaceId or self.status != "candidate_only_hold"
                or self.schema != "sylanne3.graph.c09_rebase_candidate.v1"):
            raise ValueError("Graph rebase candidate cannot claim cleanup")
        for name in ("source_files_fingerprint", "source_closure_digest",
                     "frozen_inventory_digest", "new_file_sha256", "candidate_digest",
                     "writer_freeze_digest"):
            _sha(getattr(self, name), name)
        if (type(self.new_incarnation) is not str or not self.new_incarnation
                or type(self.maintenance_generation) is not int
                or self.maintenance_generation < 1
                or not self.newly_erased_key_digests
                or self.cumulative_erased_key_digests != tuple(sorted(set(
                    self.cumulative_erased_key_digests)))
                or not set(self.newly_erased_key_digests).issubset(
                    self.cumulative_erased_key_digests)):
            raise ValueError("Graph rebase generation or tombstones differ")
        if (type(self.certificate_draft) is not GraphErasureRebaseCertificateV1
                or self.certificate_draft.new_incarnation != self.new_incarnation
                or self.certificate_draft.maintenance_generation != self.maintenance_generation
                or self.certificate_draft.cumulative_erased_key_digests
                   != self.cumulative_erased_key_digests
                or self.certificate_draft.component_hashes[0][1]
                   != self.new_file_sha256):
            raise ValueError("Graph certificate draft differs from candidate")
        if (type(self.affected_atom_refs) is not tuple
                or not self.affected_atom_refs
                or self.affected_atom_refs != tuple(sorted(set(self.affected_atom_refs)))):
            raise ValueError("Graph rebase affected atoms differ")
        if self.candidate_digest != canonical_digest((
                self.schema, self.namespace, self.operation_id,
                self.source_files_fingerprint, self.source_closure_digest,
                self.frozen_inventory_digest, self.table_manifests,
                self.new_file_sha256, self.new_incarnation,
                self.maintenance_generation, self.newly_erased_key_digests,
                self.cumulative_erased_key_digests, self.source_path,
                self.target_path, self.source_identity, self.target_identity,
                self.certificate_draft, self.affected_atom_refs,
                self.writer_freeze_digest, self.status)):
            raise ValueError("Graph rebase candidate digest differs")


@dataclass(frozen=True, slots=True)
class GraphRebaseMirrorV1:
    certificate: GraphErasureRebaseCertificateV1
    core_issue_digest: str
    final_file_sha256: str
    final_file_identity: tuple[int, int, int, int]
    new_data_root: str
    cold_read_digest: str

    def __post_init__(self) -> None:
        for name in ("core_issue_digest", "final_file_sha256",
                     "new_data_root", "cold_read_digest"):
            _sha(getattr(self, name), name)
        if (type(self.certificate) is not GraphErasureRebaseCertificateV1
                or self.new_data_root != self.certificate.new_data_root
                or self.cold_read_digest != self.certificate.cold_read_digest):
            raise ValueError("Graph mirror differs from issued certificate")


def _table_rows(db: sqlite3.Connection, table: str):
    columns = tuple(row[1] for row in db.execute(f"PRAGMA table_info({_quoted(table)})"))
    pk = tuple(row[1] for row in sorted(
        (row for row in db.execute(f"PRAGMA table_info({_quoted(table)})") if row[5]),
        key=lambda row: row[5]))
    if not columns:
        raise GraphRebaseHold(f"table has no visible columns: {table}")
    rows = db.execute(f"SELECT * FROM {_quoted(table)}").fetchall()
    if rows and not pk:
        raise GraphRebaseHold(f"populated table has no stable primary key: {table}")
    return columns, pk, rows


def _disposition_manifest(table: str, rows: list[GraphRowDispositionV1]):
    ordered = tuple(sorted(rows, key=lambda item: item.row_key_digest))
    schema = "sylanne3.graph.c09_table_disposition.v1"
    return GraphTableDispositionManifestV1(
        table, ordered, canonical_digest((table, ordered, schema)))


def _installed_closure(db: sqlite3.Connection, request: GraphRebaseInputV1) -> set[str]:
    plan = read_c09_erasure_plan_original_v1(
        db, request.namespace, request.operation_id)
    original = read_c09_erasure_barrier_v1(
        db, request.namespace, request.operation_id)
    if (plan is None or original is None
            or canonical_digest(original) != request.barrier_receipt_digest
            or plan.operation_id != original.operation_id
            or plan.graph_incarnation != original.graph_incarnation
            or plan.source_ref not in original.affected_source_refs):
        raise GraphRebaseHold("installed C09 plan/barrier original is absent")
    barrier = verify_c09_graph_barrier_v1(
        db, request.namespace, request.operation_id,
        request_digest=original.request_digest,
        pending_receipt_digest=original.pending_receipt_digest,
    )
    if (barrier is None or barrier.closure_digest != request.certified_closure_digest
            or barrier.affected_source_refs != request.affected_source_refs):
        raise GraphRebaseHold("installed C09 Graph barrier/closure differs")
    affected = _dependency_closure(db, set(barrier.affected_source_refs))
    if affected != set(request.affected_atom_refs):
        missing = sorted(affected - set(request.affected_atom_refs))
        extra = sorted(set(request.affected_atom_refs) - affected)
        raise GraphRebaseHold(
            f"Graph closure differs from durable dependencies: missing={missing[:3]!r}, "
            f"extra={extra[:3]!r}")
    return affected


def _validate_internal_life_episode_history_inventory_v2(db):
    """Authenticate new historical proofs from actual production/member SQL.

    Current withdrawal does not invalidate historical occurrence. Missing or
    changed actual originals do; a typed DTO alone is no erasure proof.
    """
    from .d06_internal_life_episode_v2 import PROVENANCE, decode_internal_life_value_v2, validate_internal_life_episode_history_v2
    if not db.in_transaction:
        raise GraphRebaseHold('Life episode history inventory requires actual pinned SQL')
    seen=set()
    for table in _BODY_TABLES:
        rows=db.execute(f"SELECT token,value FROM {table} WHERE json_extract(token,'$[4]')=? ORDER BY token LIMIT 1025",
            (PROVENANCE,)).fetchall()
        if len(rows)>1024:raise GraphRebaseHold('Life episode historical proof inventory exceeds bound; HOLD')
        for token,encoded in rows:
            if (token,encoded) in seen:continue
            seen.add((token,encoded))
            try:
                proof=decode_internal_life_value_v2(PROVENANCE,json.loads(encoded))
                from .d06_internal_life_episode_v2 import internal_life_episode_keys_v2
                if token!=internal_life_episode_keys_v2(proof.event.namespace,proof.event.activity.source_ref)[2].token:
                    raise ValueError('Life historical proof key differs')
                validate_internal_life_episode_history_v2(db,proof)
            except (ValueError,TypeError,KeyError) as exc:
                raise GraphRebaseHold('Life episode historical production original/membership differs; HOLD') from exc


def _dependency_closure(db: sqlite3.Connection, affected: set[str]) -> set[str]:
    current = list(db.execute(
        "SELECT dependent_token,dependency_token FROM graph_dependencies"))
    historical = list(db.execute(
        "SELECT dependent_token,dependency_token FROM graph_dependency_edges"))
    for token, dependencies in db.execute("SELECT token,dependencies FROM graph_history"):
        try:
            values = json.loads(dependencies)
            if type(values) is not list:
                raise ValueError("dependencies must be a list")
            historical.extend((token, item[0]) for item in values
                              if type(item) is list and len(item) == 2
                              and type(item[0]) is str and type(item[1]) is int)
            if any(type(item) is not list or len(item) != 2
                   or type(item[0]) is not str or type(item[1]) is not int
                   for item in values):
                raise ValueError("dependency pair malformed")
        except (TypeError, ValueError) as exc:
            raise GraphRebaseHold(f"historical dependency original unreadable: {token}") from exc
    values = []
    for table in _BODY_TABLES:
        for token, value in db.execute(f"SELECT token,value FROM {table}"):
            try:
                decoded = json.loads(value)
                key = AtomKey.from_token(token)
            except (TypeError, ValueError) as exc:
                raise GraphRebaseHold(
                    f"unparseable Graph nested original: {table} token {token}") from exc
            values.append((token, key.type_name, decoded))
            if key.type_name == "d09.natural_batch_disposition.v1":
                from ..domains.d09.natural_disposition_v1 import natural_disposition_from_wire_v1
                try:
                    disposition = natural_disposition_from_wire_v1(decoded)
                    if (disposition.namespace != NamespaceId.from_key(key) or key.owner.kind != "activity"
                            or key.owner.subject != disposition.activity_id):
                        raise ValueError("natural disposition metadata changed its actual owner identity")
                    for version in disposition.dependency_refs:
                        dependency = AtomKey.from_token(version.ref)
                        if (NamespaceId.from_key(dependency) != disposition.namespace
                                or dependency.type_name not in {"memory.source", "memory.access", "d06.source_correction_head.v1"}):
                            raise ValueError("natural disposition source qualification closure differs")
                except (ValueError, TypeError, KeyError) as exc:
                    raise GraphRebaseHold("natural disposition exact Source-bearing metadata differs; HOLD") from exc
                # No metadata exemption: the normal nested-reference closure below
                # retires current/history roster bodies when a qualification ref
                # is erased. Core admission/unknown/cost originals keep their
                # independently registered fact retention and cannot be cleared.
            from .internal_life_content_adoption_v1 import (
                PROVENANCE as LCP, decode_content_v1, content_keys_v1)
            if key.type_name == LCP:
                try:
                    proof = decode_content_v1(LCP, decoded)
                    keys = content_keys_v1(proof.trace.episode_ref)
                    if key != keys[1]:
                        raise ValueError("content provenance locator differs")
                    from .d04_root_original_store_v1 import _receipt
                    receipt = _receipt(db, proof.trace.namespace, proof.trace.producing_operation_id)
                    members = {v.key.token for v in receipt.write_versions}
                    content = {v.token for v in keys}
                    jobs = members - content
                    if (len(members) != 4 or not content <= members or len(jobs) != 1
                            or AtomKey.from_token(next(iter(jobs))).type_name != "runtime.job"):
                        raise ValueError("content adoption four-member receipt differs")
                    references = {proof.trace.episode_ref,
                        *(r.ref for r in proof.historical_reads), *(r.ref for r in proof.current_reads)}
                    historical.extend((member, ref) for member in members for ref in references)
                    historical.extend((member, sibling) for member in members for sibling in members if member != sibling)
                except (TypeError, ValueError, KeyError) as exc:
                    raise GraphRebaseHold("Life content historical closure unreadable; HOLD") from exc
            from .d06_internal_life_episode_v2 import KINDS as IK, PROVENANCE as IP, ELIGIBILITY as IE, decode_internal_life_value_v2
            from .d06_internal_life_trace_v3 import TRACE as IT, decode_internal_life_trace_v3
            if key.type_name == IT:
                trace=decode_internal_life_trace_v3(json.loads(value))
                historical.append((token,trace.episode_ref))
                historical.append((token,trace.encoding_baseline_ref))
                historical.extend((token,ref) for ref in (trace.perspective_ref,*trace.then_feeling_refs,*trace.interpretation_refs))
            if key.type_name in IK:
                proof = decode_internal_life_value_v2(key.type_name, decoded)
                if key.type_name == IP:
                    historical.extend((token, row.ref) for row in proof.historical_reads)
                    historical.extend(((proof.event.event_ref, token), (proof.episode.episode_ref, token)))
                elif key.type_name == IE:
                    historical.extend(((token, proof.episode_ref), (token, proof.event_ref), (token, proof.provenance_ref)))
            from ..domains.d09.contact_batch_v2 import PROVENANCE as CP, ELIGIBILITY as CE, decode_contact_batch_companion_v2, contact_batch_keys_v2
            from ..domains.d08.contact_plan_v2 import PROVENANCE as CPP,ELIGIBILITY as CPE,decode_contact_plan_member_v2,contact_plan_keys_v2
            from ..domains.d08.contact_plan_v3 import PROVENANCE as CPP3,ELIGIBILITY as CPE3,decode_contact_plan_member_v3,contact_plan_keys_v3
            if key.type_name in {CPP3,CPE3}:
                proof3 = decode_contact_plan_member_v3(key.type_name,decoded)
                if key.type_name == CPP3:
                    if key != contact_plan_keys_v3(proof3.plan)[1]:
                        raise GraphRebaseHold('Contact Plan3 metadata provenance key differs')
                    historical.extend((token,row.ref) for row in proof3.historical_reads)
                    historical.append((contact_plan_keys_v3(proof3.plan)[0].token,token))
                else:
                    historical.extend(((token,proof3.plan_ref.ref),(token,proof3.provenance_ref.ref)))
            if key.type_name in {CPP,CPE}:
                proof=decode_contact_plan_member_v2(key.type_name,decoded)
                if key.type_name==CPP:
                    if key!=contact_plan_keys_v2(proof.plan)[1]:
                        raise GraphRebaseHold('Contact Plan v2 exact historical provenance key differs; HOLD')
                    historical.extend((token,row.ref) for row in proof.historical_reads)
                    historical.append((contact_plan_keys_v2(proof.plan)[0].token,token))
                else:
                    historical.extend(((token,proof.plan_ref.ref),(token,proof.provenance_ref.ref)))
            if key.type_name in {CP,CE}:
                proof=decode_contact_batch_companion_v2(key.type_name,decoded)
                if key.type_name==CP:
                    if key != contact_batch_keys_v2(proof.batch.content.namespace,proof.batch.content.activity_id,proof.batch.content.contact_id)[1]:
                        raise GraphRebaseHold('Contact v2 historical provenance key differs; HOLD')
                    historical.extend((token,row.ref) for row in proof.historical_reads)
                    historical.append((contact_batch_keys_v2(proof.batch.content.namespace,proof.batch.content.activity_id,proof.batch.content.contact_id)[0].token,token))
                else:
                    historical.extend(((token,proof.batch_ref),(token,proof.provenance_ref)))
            from ..domains.d09.contact_batch_v3 import PROVENANCE as CP3, ELIGIBILITY as CE3, decode_contact_batch_companion_v3, contact_batch_keys_v3
            if key.type_name in {CP3,CE3}:
                proof3=decode_contact_batch_companion_v3(key.type_name,decoded)
                if key.type_name==CP3:
                    batch_keys3=contact_batch_keys_v3(proof3.batch.content.namespace,proof3.batch.content.activity_id,proof3.batch.content.contact_id)
                    if key != batch_keys3[1]:
                        raise GraphRebaseHold('Contact3 exact historical provenance key differs; HOLD')
                    historical.extend((token,row.ref) for row in proof3.historical_reads)
                    historical.append((batch_keys3[0].token,token))
                else:
                    historical.extend(((token,proof3.batch_ref),(token,proof3.provenance_ref)))
            from .d10_life_progress_provenance_v1 import PROVENANCE_TYPE as PP,ELIGIBILITY_TYPE as PE,decode_life_progress_auxiliary_v1
            if key.type_name in {PP,PE}:
                proof=decode_life_progress_auxiliary_v1(key.type_name,decoded)
                if key.type_name==PP:
                    historical.extend(((token,proof.terminal_provenance_ref),(proof.fact_ref,token)))
                else:
                    historical.extend(((token,proof.fact_ref),(token,proof.provenance_ref),(token,proof.terminal_eligibility_ref)))
            from .d11_life_fact_provenance_v1 import PROVENANCE_TYPE, ELIGIBILITY_TYPE, decode_life_fact_auxiliary_v1
            if key.type_name in {PROVENANCE_TYPE,ELIGIBILITY_TYPE}:
                proof=decode_life_fact_auxiliary_v1(key.type_name,decoded)
                # Physical closure includes immutable facts and their proofs;
                # these deletion edges are not Graph invalidation edges.
                if key.type_name==PROVENANCE_TYPE:
                    historical.extend((token,row.ref) for row in proof.reads)
                    historical.append((proof.fact_ref,token))
                else:
                    historical.extend(((token,proof.fact_ref),(token,proof.provenance_ref)))
            from .d11_life_outcome_provenance_v1 import PROVENANCE_TYPE as OP, ELIGIBILITY_TYPE as OE, decode_life_outcome_auxiliary_v1
            if key.type_name in {OP,OE}:
                proof=decode_life_outcome_auxiliary_v1(key.type_name,decoded)
                if key.type_name==OP:
                    historical.extend(((token,proof.terminal_provenance_ref),(token,proof.action_ref),(proof.fact_ref,token)))
                else:
                    historical.extend(((token,proof.fact_ref),(token,proof.provenance_ref),(token,proof.terminal_eligibility_ref)))
    edges = current + historical
    source_ids = {AtomKey.from_token(token).owner.subject for token in affected
                  if AtomKey.from_token(token).type_name == "memory.source"}
    while True:
        expanded = affected | {dependent for dependent, dependency in edges
                               if dependency in affected and
                               AtomKey.from_token(dependent).type_name != "memory.access"}
        expanded |= {token for token, type_name, value in values
                     if type_name != "memory.access"
                     and _nested_hits(value, affected, source_ids)}
        if expanded == affected:
            break
        affected = expanded
    return affected


def _nested_hits(value: object, affected: set[str], source_ids: set[str],
                 *, field: str = "") -> bool:
    if type(value) is str:
        if field.endswith("_json"):
            try:
                decoded = json.loads(value)
            except (TypeError, ValueError) as exc:
                raise GraphRebaseHold("unreadable nested serialized original") from exc
            return _nested_hits(decoded, affected, source_ids)
        return (value in affected or any(token in value for token in affected)
                or ("source" in field.lower() and value in source_ids))
    if type(value) is list:
        return any(_nested_hits(item, affected, source_ids, field=field)
                   for item in value)
    if type(value) is dict:
        return any(_nested_hits(item, affected, source_ids, field=key)
                   for key, item in value.items())
    return False


def _row_has_erased_original(table: str, columns: tuple[str, ...], row: tuple,
                             affected: set[str], source_ids: set[str],
                             row_key: str) -> bool:
    for name, value in zip(columns, row):
        if type(value) is not str:
            continue
        if name.endswith("_json") or name in {
                "value", "dependencies", "reads", "epoch_reads", "revisions",
                "invalidated", "payload", "body_json", "original"}:
            try:
                decoded = json.loads(value)
            except (TypeError, ValueError) as exc:
                raise GraphRebaseHold(
                    f"unparseable nested original: {table}.{name} row {row_key}") from exc
            if _nested_hits(decoded, affected, source_ids, field=name):
                return True
        elif _nested_hits(value, affected, source_ids, field=name):
            return True
    return False


def _affected_operations(db: sqlite3.Connection, affected: set[str]) -> set[str]:
    operations = set()
    for operation_id, reads, revisions, invalidated in db.execute(
            "SELECT event_id,reads,revisions,invalidated FROM graph_events"):
        try:
            bodies = (json.loads(reads), json.loads(revisions), json.loads(invalidated))
        except (TypeError, ValueError) as exc:
            raise GraphRebaseHold(
                f"Graph event references unreadable: {operation_id}") from exc
        if any(_nested_hits(body, affected, set()) for body in bodies):
            operations.add(operation_id)
    return operations


def _operation_body_row(columns: tuple[str, ...], row: tuple,
                        operations: set[str]) -> bool:
    if "operation_id" not in columns or row[columns.index("operation_id")] not in operations:
        return False
    return any(name in {"value", "content", "payload", "input", "output"}
               or (name.endswith("_json") and name not in {
                   "receipt_json", "proof_json", "requirements_json",
                   "anchor_json"}) for name in columns)


def _recovery_generation(db: sqlite3.Connection, namespace: NamespaceId,
                         barrier_incarnation: str) -> tuple[int, str]:
    row = db.execute("SELECT requirements_json FROM graph_recovery_metadata_v2 "
                     "WHERE bot=? AND persona=?", namespace.as_tuple).fetchone()
    if row is None:
        raise GraphRebaseHold("Graph recovery head is absent")
    try:
        requirements = json.loads(row[0])
    except (TypeError, ValueError) as exc:
        raise GraphRebaseHold("Graph recovery requirements malformed") from exc
    if requirements.get("graph_incarnation") != barrier_incarnation:
        raise GraphRebaseHold("C09 barrier differs from Graph recovery incarnation")
    generations = db.execute("SELECT MAX(maintenance_generation) "
                             "FROM graph_c09_erased_keys_v1").fetchone()[0] if db.execute(
                                 "SELECT 1 FROM sqlite_master WHERE type='table' "
                                 "AND name='graph_c09_erased_keys_v1'").fetchone() else None
    return (generations or 0) + 1, secrets.token_hex(16)


def _file_identity(path: Path) -> tuple[int, int, int, int]:
    stat = path.stat()
    return stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns


def _shared_domain_dispositions_v1(db, table, columns, rows, *, registry, affected, affected_operations, source_ids):
    expected = _SHARED_ORIGINAL_COLUMNS if table == _SHARED_ORIGINAL_TABLE else _SHARED_OUTBOX_COLUMNS
    if columns != expected:
        raise GraphRebaseHold("shared domain original/outbox columns differ")
    from .domain_production_originals_v1 import install_domain_production_originals_v1, _receipt
    from .domain_production_commit_v1 import install_domain_production_outbox_v1
    with closing(sqlite3.connect(":memory:")) as expected_db:
        install_domain_production_originals_v1(expected_db); install_domain_production_outbox_v1(expected_db)
        names = tuple(expected_db.execute("SELECT type,name,sql FROM sqlite_master WHERE tbl_name=? AND sql IS NOT NULL ORDER BY type,name", (table,)))
    actual = tuple(db.execute("SELECT type,name,sql FROM sqlite_master WHERE tbl_name=? AND sql IS NOT NULL ORDER BY type,name", (table,)))
    if actual != names:
        raise GraphRebaseHold("shared domain installed schema objects differ")
    result = []
    if rows and table == _SHARED_ORIGINAL_TABLE:
        from ..graph_types import TypeRegistry
        if type(registry) is not TypeRegistry:
            raise GraphRebaseHold("actual installed domain TypeRegistry is required for shared originals")
        installed = {spec.name: spec for spec in registry.specs}
        for name, writer, schema_hash in db.execute("SELECT name,writer_domain,schema_hash FROM graph_type_authority"):
            if name not in installed or (installed[name].writer_domain or "", installed[name].schema_hash or "") != (writer, schema_hash):
                raise GraphRebaseHold("shared original registry differs from installed Graph catalogue")
    for row in rows:
        namespace = NamespaceId(row[0], row[1])
        if table == _SHARED_ORIGINAL_TABLE:
            original = decode_domain_production_original_row_v1(row, namespace, registry=registry)
            receipt = _receipt(json.loads(row[10]))
            bundle = db.execute("SELECT digest,activity_id,effect_id,commit_seq FROM graph_bundle_operations WHERE bot=? AND persona=? AND operation_id=?",
                (*namespace.as_tuple, original["operation_id"])).fetchone()
            if bundle != (receipt.operation_digest, receipt.activity_id, receipt.effect_id, receipt.commit_seq):
                raise GraphRebaseHold("shared original lacks its actual Graph bundle receipt")
            payload = json.loads(row[7])
            contact_final = row[3] == 'd08' and row[4] in {'prepare_contact_dispatch','prepare_contact_dispatch_v3'}
            if contact_final:
                from .c09_contact_final_v1 import validate_contact_final_original_joins_v1
                try:
                    validate_contact_final_original_joins_v1(db,namespace=namespace,
                        operation_id=original['operation_id'],payload=payload,receipt=receipt,
                        original_digest=row[6],registry=registry)
                except (ValueError,TypeError,KeyError) as error:
                    raise GraphRebaseHold('Contact final historical COMMIT/qualification inventory differs') from error
            removed = (original["operation_id"] in affected_operations or bool(set(original["graph_refs"]) & affected)
                or _nested_hits(json.loads(row[7]), affected, source_ids))
            if contact_final and removed:
                from .c09_contact_final_v1 import require_contact_final_erasure_finish_v1
                try:
                    require_contact_final_erasure_finish_v1(payload['provenance'], db=db,
                        namespace=namespace, operation_id=original['operation_id'])
                except ValueError as error:
                    raise GraphRebaseHold(str(error)) from error
            result.append("derived_removed" if removed else "preserved_exact")
        else:
            original = decode_domain_production_outbox_row_v1(row, namespace, db=db)
            linked = db.execute(f"SELECT * FROM {_SHARED_ORIGINAL_TABLE} WHERE bot=? AND persona=? AND operation_id=?",
                (*namespace.as_tuple, original["causal_operation_id"])).fetchone()
            if row[8] == "retired":
                result.append("preserved_exact")
                continue
            if linked is None:
                raise GraphRebaseHold("active shared outbox lacks its exact causal original")
            if row[5] == "actual_internal_experience_requires_encoding":
                from .domain_production_originals_v1 import read_adopted_domain_operation_v1
                from .domain_production_contracts_v1 import ProductionOutboxStageV1, ProductionOriginalRefV1
                from .domain_production_followups_v1 import verify_current_followup_trigger_v1
                started = not db.in_transaction
                if started:
                    db.execute("BEGIN")
                try:
                    causal = read_adopted_domain_operation_v1(db, namespace, original["causal_operation_id"])
                    event = ProductionOutboxStageV1(namespace, row[3], row[4], row[5],
                        ProductionOriginalRefV1("d10.actual_life_experience", row[6], row[7]))
                    verify_current_followup_trigger_v1(db, namespace, event, causal, None)
                finally:
                    if started:
                        db.rollback()
            linked_rows = [linked]
            if row[10] is not None:
                receipt = json.loads(row[10])
                for command in receipt["completed_commands"]:
                    child = db.execute(f"SELECT * FROM {_SHARED_ORIGINAL_TABLE} WHERE bot=? AND persona=? AND operation_id=?",
                        (*namespace.as_tuple, command["operation_id"])).fetchone()
                    if child is None:
                        raise GraphRebaseHold("shared outbox lost its completed child original")
                    linked_rows.append(child)
            elif row[5] == "actual_offline_simulation_experiences_require_encoding":
                raise GraphRebaseHold("shared outbox special trigger requires its installed original reader")
            elif row[5] != "actual_internal_experience_requires_encoding" and (row[7] != linked[6] or row[6] != linked[3] + "-current:" + linked[6][:48]):
                raise GraphRebaseHold("shared outbox trigger differs from exact causal original")
            linked_status = _shared_domain_dispositions_v1(db, _SHARED_ORIGINAL_TABLE, _SHARED_ORIGINAL_COLUMNS,
                tuple(linked_rows), registry=registry, affected=affected, affected_operations=affected_operations, source_ids=source_ids)
            removed = ("derived_removed" in linked_status or original["original_ref"] in affected
                or original["causal_operation_id"] in affected_operations)
            # A consumed receipt's cold reader joins every causal/child body.
            # Its deletion commitment is retained in the row manifest, while
            # the derived outbox row must leave with any erased dependency.
            result.append("derived_removed" if removed else "preserved_exact")
    return tuple(result)


def _validate_c04_baseline_inventory_v3(db):
    if not db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (_C04_BASELINE_TABLE,)).fetchone():
        return
    from .c04_encoding_baseline_store_v3 import install_c04_encoding_baseline_store_v3, read_c04_encoding_baseline_v3
    with closing(sqlite3.connect(":memory:", isolation_level=None)) as expected:
        install_c04_encoding_baseline_store_v3(expected)
        wanted = tuple(expected.execute("SELECT type,name,sql FROM sqlite_master WHERE tbl_name=? ORDER BY type,name", (_C04_BASELINE_TABLE,)))
    actual = tuple(db.execute("SELECT type,name,sql FROM sqlite_master WHERE tbl_name=? ORDER BY type,name", (_C04_BASELINE_TABLE,)))
    if actual != wanted:
        raise GraphRebaseHold("C04 encoding baseline fixed immutable schema differs")
    started = not db.in_transaction
    if started:
        db.execute("BEGIN")
    try:
        for bot, persona, operation, source_ref in db.execute(
                "SELECT bot,persona,encoding_operation_id,source_ref FROM graph_c04_encoding_baselines_v3").fetchall():
            read_c04_encoding_baseline_v3(db, namespace=NamespaceId(bot, persona), encoding_operation_id=operation, source_ref=source_ref)
    finally:
        if started:
            db.rollback()


def _cold_graph_data_root(path: Path, namespace: NamespaceId,
                          affected: set[str], incarnation: str,
                          cumulative: tuple[str, ...], *, candidate_connection=None, registry=None,
                          completion_control=None, operation_id=None, qualified_retention_manifests=None) -> tuple[str, str]:
    if candidate_connection is None and any(Path(str(path) + suffix).exists() for suffix in ("-wal", "-shm", "-journal")):
        raise GraphRebaseHold("cold closed Graph candidate has sidecars")
    manager = nullcontext(candidate_connection) if candidate_connection is not None else closing(
        sqlite3.connect(path.as_uri() + "?mode=ro&immutable=1", uri=True))
    with manager as db:
        if not db.in_transaction:
            db.execute("BEGIN")
        verify_foreground_attempts_from_selected_core_v1(db, control=completion_control, operation_id=operation_id)
        validate_domain_production_schema_v1(db)
        validate_catalogue_upgrade_schema_v1(db)
        validate_c09_budget_schema_v1(db)
        validate_d07_schema_v1(db)
        validate_contact_schema_v1(db)
        _validate_c04_baseline_inventory_v3(db)
        tables = tuple(sorted(name for (name,) in db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name NOT LIKE 'sqlite_%' AND name!='graph_c09_rebase_certificates_v1'")))
        manifests = []
        for table in tables:
            columns, pk, rows = _table_rows(db, table)
            if table in _BUDGET_TABLES:
                for row in rows:
                    validate_c09_budget_row_v1(table, columns, row)
            positions = tuple(columns.index(column) for column in pk)
            ordered = sorted(rows, key=lambda row: tuple(str(row[i]) for i in positions))
            manifests.append((table, tuple(_row_digest(row) for row in ordered)))
        recovery = db.execute(
            "SELECT requirements_json FROM graph_recovery_metadata_v2 "
            "WHERE bot=? AND persona=?", namespace.as_tuple).fetchone()
        if recovery is None or json.loads(recovery[0]).get("graph_incarnation") != incarnation:
            raise GraphRebaseHold("cold Graph recovery incarnation differs")
        markers = []
        source_ids = {AtomKey.from_token(token).owner.subject for token in affected
                      if AtomKey.from_token(token).type_name == "memory.source"}
        operations = _affected_operations(db, affected)
        catalogue_rows = catalogue_upgrade_c09_rows_v1(db, affected=affected, affected_operations=operations)
        for token in sorted(affected):
            row = db.execute("SELECT value,valid FROM graph_atoms WHERE token=?",
                             (token,)).fetchone()
            if row is not None:
                marker = json.loads(row[0])
                if (row[1] != 0 or type(marker) is not dict
                        or marker.get("schema") != _ERASED_SCHEMA
                        or marker.get("key_digest") != canonical_digest(token)):
                    raise GraphRebaseHold(f"cold Graph atom remains readable: {token}")
            markers.append((canonical_digest(token), row is not None))
            for value, valid, dependencies in db.execute(
                    "SELECT value,valid,dependencies FROM graph_history WHERE token=?",
                    (token,)):
                marker = json.loads(value)
                if (valid != 0 or dependencies != "[]"
                        or type(marker) is not dict
                        or marker.get("schema") != _ERASED_SCHEMA
                        or marker.get("key_digest") != canonical_digest(token)):
                    raise GraphRebaseHold(f"cold Graph history remains readable: {token}")
        for table in _EDGE_TABLES:
            for dependent, dependency in db.execute(
                    f"SELECT dependent_token,dependency_token FROM {table}"):
                if dependent in affected or dependency in affected:
                    raise GraphRebaseHold(
                        f"cold Graph dependency survives: {table}")
        for table in tables:
            if table in _COMMITMENT_TABLES | _REBASE_TABLES | _EDGE_TABLES:
                continue
            columns, pk, rows = _table_rows(db, table)
            if table in catalogue_rows:
                if any(old != updated for old, updated, _ in catalogue_rows[table]):
                    raise GraphRebaseHold('cold catalogue metadata still contains affected source references')
                continue
            if table in _BUDGET_TABLES:
                for row in rows:
                    validate_c09_budget_row_v1(table, columns, row)
                continue
            if table == _D04_TABLE:
                try:
                    dispositions = d04_original_dispositions_v3(columns, rows,
                        affected=affected, affected_operations=operations,
                        nested_hits=_nested_hits, source_ids=source_ids,
                        authority_namespace=json.loads(recovery[0])["authority_namespace"])
                except (D04ErasureInventoryHold, ValueError, TypeError, KeyError) as exc:
                    raise GraphRebaseHold("cold D04 original inventory differs") from exc
                if "derived_removed" in dispositions:
                    raise GraphRebaseHold("cold D04 body original survives its erased closure")
                # Only this closed per-kind codec exempts the exact fixed
                # accounting contracts from generic source-reference scanning.
                continue
            if table == _D07_TABLE:
                dispositions = d07_original_dispositions_v1(columns, rows, affected=affected, affected_operations=operations,
                    nested_hits=_nested_hits, source_ids=source_ids, authority_namespace=json.loads(recovery[0])["authority_namespace"])
                if "derived_removed" in dispositions:
                    raise GraphRebaseHold("cold D07 execution body survives erased closure")
                continue
            if table=='graph_contact_expression_plan_originals_v2':
                from .c09_contact_plan_originals_v2 import validate_contact_plan_original_schema_v2,contact_plan_original_dispositions_v2
                validate_contact_plan_original_schema_v2(db)
                dispositions=contact_plan_original_dispositions_v2(db,columns,rows,
                    affected=affected,affected_operations=operations)
                if 'derived_removed' in dispositions:
                    raise GraphRebaseHold('cold Contact Plan v2 body original survives erased closure')
                continue
            if table == _CONTACT_V2_TABLE:
                dispositions = contact_original_dispositions_v2(columns, rows, affected=affected, affected_operations=operations,
                    nested_hits=_nested_hits, source_ids=source_ids, authority_namespace=json.loads(recovery[0])["authority_namespace"])
                if "derived_removed" in dispositions:
                    raise GraphRebaseHold("cold contact original body survives erased closure")
                continue
            if table == _CONTACT_TABLE:
                dispositions = contact_original_dispositions_v1(columns, rows, affected=affected, affected_operations=operations,
                    nested_hits=_nested_hits, source_ids=source_ids, authority_namespace=json.loads(recovery[0])["authority_namespace"])
                if "derived_removed" in dispositions:
                    raise GraphRebaseHold("cold contact original body survives erased closure")
                continue
            if table in {_D07_STAGE_TABLE, _D07_ACCOUNTING_TABLE}:
                validator = validate_d07_stage_attempt_row_v1 if table == _D07_STAGE_TABLE else validate_d07_accounting_attempt_row_v1
                for row in rows:
                    validator(columns, row)
                continue
            if table in _DOMAIN_COLUMNS:
                dispositions = domain_production_original_dispositions_v1(table, columns, rows,
                    affected=affected, affected_operations=operations, nested_hits=_nested_hits,
                    source_ids=source_ids, authority_namespace=json.loads(recovery[0])["authority_namespace"], db=db,
                    qualified_retention_manifests=qualified_retention_manifests, qualified_retention_operation_id=operation_id)
                if "derived_removed" in dispositions:
                    raise GraphRebaseHold("cold domain body survives its erased closure")
                continue
            if table in {_SHARED_ORIGINAL_TABLE, _SHARED_OUTBOX_TABLE}:
                dispositions = _shared_domain_dispositions_v1(db, table, columns, rows, registry=registry,
                    affected=affected, affected_operations=operations, source_ids=source_ids)
                if "derived_removed" in dispositions:
                    raise GraphRebaseHold("cold shared domain body survives its erased closure")
                continue
            for row in rows:
                if table in _BODY_TABLES:
                    token = row[columns.index("token")]
                    # These exact rows have already been checked above for an
                    # unreadable, content-free marker (including every history
                    # revision and its empty dependency list). The surviving
                    # key identifies the tombstone; it is not source content.
                    if token in affected or AtomKey.from_token(token).type_name == "memory.access":
                        continue
                row_key = canonical_digest((table, tuple(
                    row[columns.index(column)] for column in pk)))[:16]
                if (_row_has_erased_original(
                        table, columns, row, affected, source_ids, row_key)
                        or _operation_body_row(columns, row, operations)):
                    raise GraphRebaseHold(
                        f"cold nested original survives: {table} row {row_key}")
        keys = tuple(sorted(row[0] for row in db.execute(
            "SELECT key_digest FROM graph_c09_erased_keys_v1 "
            "WHERE bot=? AND persona=?", namespace.as_tuple)))
        if keys != cumulative:
            raise GraphRebaseHold("cold Graph cumulative tombstone differs")
        root = canonical_digest(tuple(manifests))
        cold = canonical_digest((root, incarnation, tuple(markers), keys))
        return root, cold


def _certificate_draft(**values) -> GraphErasureRebaseCertificateV1:
    values["schema"] = "sylanne3.graph.c09_erasure_rebase.v1"
    ordered = tuple(values[field.name] for field in fields(
        GraphErasureRebaseCertificateV1) if field.name != "certificate_digest")
    values["certificate_digest"] = canonical_digest(ordered)
    return GraphErasureRebaseCertificateV1(**values)


def build_graph_rebase_candidate_v1(
    source_path: Path, target_path: Path, *, request: GraphRebaseInputV1,
    completion_control=None, registry=None, contact_finish_scope=None, life_completed_scope=None,
) -> GraphRebaseCandidateV1:
    from ..authority_service.c09_contact_finish_original_v1 import _contact_finish_graph_scope_v1
    try:
        with _contact_finish_graph_scope_v1(contact_finish_scope):
            return _build_graph_rebase_candidate_v1(source_path, target_path, request=request,
                completion_control=completion_control, registry=registry,
                life_completed_scope=life_completed_scope)
    finally:
        if life_completed_scope is not None:
            from ..authority_service.c09_life_completed_archive_v1 import revoke_completed_life_scope_v1
            revoke_completed_life_scope_v1(life_completed_scope.port)


def _build_graph_rebase_candidate_v1(
    source_path: Path, target_path: Path, *, request: GraphRebaseInputV1,
    completion_control=None, registry=None, life_completed_scope=None,
) -> GraphRebaseCandidateV1:
    """Build a fresh SQLite candidate; never copy old DB pages or modify source."""
    if type(request) is not GraphRebaseInputV1:
        raise TypeError("typed Graph rebase input required")
    source = Path(source_path).resolve(strict=True)
    target = Path(target_path).resolve(strict=False)
    if target == source or (target.exists() and completion_control is None) or not target.parent.is_dir():
        raise GraphRebaseHold("target must be a distinct new file")
    active_sidecars = tuple(suffix for suffix in ("-wal", "-shm")
                            if Path(str(source) + suffix).exists())
    if active_sidecars:
        raise GraphRebaseHold(
            f"Graph WAL/SHM must be drained before immutable old-file read: {active_sidecars}")
    if graph_source_files_fingerprint_v1(source) != request.source_files_fingerprint:
        raise GraphRebaseHold("closed Graph snapshot fingerprint differs")
    # The installed writer gate has drained/closed the old Graph and the
    # complete DB/WAL/SHM inventory was checked above. A normal WAL-mode
    # read-only connection can itself create empty sidecars and invalidate
    # this closed-file observation; immutable reads cannot do that.
    db = sqlite3.connect(source.as_uri() + "?mode=ro&immutable=1", uri=True)
    created = False
    built = False
    try:
        db.execute("BEGIN")
        objects = db.execute(
            "SELECT type,name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' "
            "ORDER BY type,name").fetchall()
        user_version = db.execute("PRAGMA user_version").fetchone()[0]
        application_id = db.execute("PRAGMA application_id").fetchone()[0]
        source_sequences = (db.execute("SELECT name,seq FROM sqlite_sequence").fetchall()
                            if db.execute("SELECT 1 FROM sqlite_master WHERE name='sqlite_sequence'").fetchone()
                            else [])
        tables = tuple(sorted(name for kind, name, _ in objects if kind == "table"))
        if tables != request.table_inventory:
            raise GraphRebaseHold("installed table inventory differs from SQLite")
        if any(kind == "view" for kind, _, _ in objects):
            raise GraphRebaseHold("unclassified Graph view exists")
        descriptions = {}
        validate_domain_production_schema_v1(db)
        validate_catalogue_upgrade_schema_v1(db)
        validate_c09_budget_schema_v1(db)
        validate_d07_schema_v1(db)
        validate_contact_schema_v1(db)
        _validate_c04_baseline_inventory_v3(db)
        for table in tables:
            columns, pk, rows = _table_rows(db, table)
            if table not in _KNOWN:
                raise GraphRebaseHold(f"unclassified installed Graph table: {table}")
            if table in _CATALOGUE_COLUMNS:
                for row in rows:
                    validate_catalogue_upgrade_row_v1(table, columns, row)
            if table == 'graph_contact_background_scheduler_v3':
                from .contact_background_scheduler_v3 import DDL as scheduler_ddl,validate_contact_scheduler_row_v3
                if db.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?",(table,)).fetchone() != (scheduler_ddl,):
                    raise GraphRebaseHold('Contact scheduling metadata schema differs')
                for row in rows:
                    validate_contact_scheduler_row_v3(columns,row)
            if table == 'graph_contact_background_invocations_v1':
                from .contact_background_invocation_v1 import (
                    require_contact_background_schema_v1, validate_contact_background_inventory_row_v1)
                require_contact_background_schema_v1(db)
                for row in rows:
                    validate_contact_background_inventory_row_v1(columns,row)
                if rows:
                    raise GraphRebaseHold('Contact background authenticated carrier/disposal remains HOLD')
            if table == 'graph_contact_owner_invocations_v3':
                from .c09_contact_owner_invocation_v3 import (
                    require_contact_owner_invocation_schema_v3, validate_contact_owner_inventory_row_v3,
                )
                require_contact_owner_invocation_schema_v3(db)
                for row in rows:
                    validate_contact_owner_inventory_row_v3(columns, row)
                if rows:
                    raise GraphRebaseHold('Contact Owner V3 authenticated carrier/disposal consumer is not yet closed; HOLD')
            if table=='graph_internal_life_paid_originals_v2':
                from .internal_life_paid_result_v2 import require_life_paid_schema_v2,validate_life_paid_inventory_v2
                require_life_paid_schema_v2(db)
                for row in rows:validate_life_paid_inventory_v2(columns,row)
                if rows and life_completed_scope is None:raise GraphRebaseHold('Life paid result/content disposal originals are not yet closed')
            if table == 'graph_internal_life_worker_originals_v2':
                from .internal_life_content_worker_v2 import require_life_worker_schema_v2,validate_life_worker_inventory_row_v2
                require_life_worker_schema_v2(db)
                for row in rows:validate_life_worker_inventory_row_v2(columns,row)
                if rows and life_completed_scope is None:
                    raise GraphRebaseHold('Life worker V2 model/accounting/disposal originals are not yet closed')
            if table == 'graph_internal_life_content_originals_v1':
                from .c09_internal_life_content_v1 import (
                    require_internal_life_content_schema_v1,
                    validate_internal_life_content_inventory_row_v1,
                )
                require_internal_life_content_schema_v1(db)
                for row in rows:
                    validate_internal_life_content_inventory_row_v1(columns, row)
                if rows and life_completed_scope is None:
                    raise GraphRebaseHold('Life content worker/accounting/disposal originals are not yet closed')
            if table == "graph_d07_behavior_original_v1" and columns != (
                    "bot","persona","operation_id","work_kind","request_digest",
                    "stage_digest","input_digest","request_json","stage_json","source_refs_json"):
                raise GraphRebaseHold("D07 behavior original content inventory differs")
            if table == _D04_TABLE:
                if columns != _D04_COLUMNS:
                    raise GraphRebaseHold("D04 original content inventory differs")
                try:
                    authority_scope = db.execute("SELECT requirements_json FROM graph_recovery_metadata_v2 WHERE bot=? AND persona=?", request.namespace.as_tuple).fetchone()
                    if authority_scope is None:
                        raise GraphRebaseHold("D04 inventory lacks actual Graph recovery scope")
                    authority_namespace = json.loads(authority_scope[0])["authority_namespace"]
                    for row in rows:
                        read_d04_inventory_row_v3(columns, row, authority_namespace=authority_namespace)
                except (D04ErasureInventoryHold, ValueError, TypeError, KeyError) as exc:
                    raise GraphRebaseHold("installed D04 original kind/codec differs") from exc
            if table=="graph_owner_goal_cancellation_projections_v1":
                from .owner_goal_projection_v1 import validate_goal_projection_row_v1
                for row in rows:validate_goal_projection_row_v1(columns,row,db=db)
            if table in _DOMAIN_COLUMNS:
                if columns != _DOMAIN_COLUMNS[table]:
                    raise GraphRebaseHold("installed domain input columns differ")
                for row in rows:
                    validate_domain_production_row_v1(table, columns, row)
            if table in _BUDGET_TABLES:
                for row in rows:
                    validate_c09_budget_row_v1(table, columns, row)
            if table == _D07_TABLE:
                if columns != _D07_COLUMNS:
                    raise GraphRebaseHold("D07 original installed columns differ")
                authority_scope = json.loads(db.execute("SELECT requirements_json FROM graph_recovery_metadata_v2 WHERE bot=? AND persona=?",
                    request.namespace.as_tuple).fetchone()[0])["authority_namespace"]
                for row in rows:
                    read_d07_inventory_row_v1(columns, row, authority_namespace=authority_scope)
            if table == _CONTACT_V2_TABLE:
                validate_contact_schema_v2(db)
                if columns != _CONTACT_V2_COLUMNS:
                    raise GraphRebaseHold("contact original installed columns differ")
                for row in rows:
                    read_contact_inventory_row_v2(columns, row)
            if table == _CONTACT_TABLE:
                if columns != _CONTACT_COLUMNS:
                    raise GraphRebaseHold("contact original installed columns differ")
                for row in rows:
                    read_contact_inventory_row_v1(columns, row)
            if table=='graph_contact_expression_plan_originals_v2':
                from .c09_contact_plan_originals_v2 import validate_contact_plan_original_schema_v2,validate_contact_plan_original_history_row_v2
                validate_contact_plan_original_schema_v2(db)
                for row in rows:validate_contact_plan_original_history_row_v2(db,columns,row)
            if table in {_D07_STAGE_TABLE, _D07_ACCOUNTING_TABLE}:
                validator = validate_d07_stage_attempt_row_v1 if table == _D07_STAGE_TABLE else validate_d07_accounting_attempt_row_v1
                for row in rows:
                    validator(columns, row)
            descriptions[table] = (columns, pk, rows)
        foreground_attempts = verify_foreground_attempts_from_selected_core_v1(
            db, control=completion_control, operation_id=request.operation_id)
        _validate_internal_life_episode_history_inventory_v2(db)
        affected = _installed_closure(db, request)
        affected_operations = _affected_operations(db, affected)
        barrier = read_c09_erasure_barrier_v1(
            db, request.namespace, request.operation_id)
        generation, new_incarnation = _recovery_generation(
            db, request.namespace, barrier.graph_incarnation)
        if completion_control is not None:
            plan = completion_control.read_build_original_v1(operation_id=request.operation_id, kind="graph_build_plan")
            if plan is None:
                plan = completion_control.record_build_original_v1(operation_id=request.operation_id,
                    kind="graph_build_plan", details={"request_digest": canonical_digest(request),
                        "new_incarnation": new_incarnation, "maintenance_generation": generation})
            if (plan["details"]["request_digest"] != canonical_digest(request)
                    or plan["details"]["maintenance_generation"] != generation):
                raise GraphRebaseHold("C09 registered Graph build input differs")
            new_incarnation = plan["details"]["new_incarnation"]
        recovery_row = db.execute(
            "SELECT requirements_json,graph_revision FROM graph_recovery_metadata_v2 "
            "WHERE bot=? AND persona=?", request.namespace.as_tuple).fetchone()
        if recovery_row is None:
            raise GraphRebaseHold("Graph recovery metadata absent")
        recovery_requirements = json.loads(recovery_row[0])
        old_graph_epoch = db.execute("SELECT revision FROM graph_epochs "
                                     "WHERE bot=? AND persona=?",
                                     request.namespace.as_tuple).fetchone()
        old_authority_epochs = db.execute(
            "SELECT access_epoch,delete_epoch FROM graph_authority_epochs "
            "WHERE bot=? AND persona=?", request.namespace.as_tuple).fetchone()
        if (old_graph_epoch != (barrier.graph_epoch_after,)
                or old_authority_epochs != (
                    barrier.access_epoch_after, barrier.delete_epoch_after)):
            raise GraphRebaseHold("C09 Graph head differs from frozen barrier")
        prior_erased = set()
        if "graph_c09_erased_keys_v1" in descriptions:
            key_columns, _, old_keys = descriptions["graph_c09_erased_keys_v1"]
            for row in old_keys:
                if (row[key_columns.index("bot")], row[key_columns.index("persona")]) == request.namespace.as_tuple:
                    prior_erased.add(row[key_columns.index("key_digest")])
        prior_certificate_digest = None
        if "graph_c09_rebase_certificates_v1" in descriptions:
            from .c09_graph_originals_read_v4 import read_graph_rebase_certificate_v1
            cert_columns, _, cert_rows = descriptions["graph_c09_rebase_certificates_v1"]
            prior_certificates = []
            for row in cert_rows:
                if (row[cert_columns.index("bot")], row[cert_columns.index("persona")]) != request.namespace.as_tuple:
                    continue
                prior_certificates.append(read_graph_rebase_certificate_v1(
                    db, request.namespace, row[cert_columns.index("operation_id")]))
            if prior_certificates:
                prior = max(prior_certificates, key=lambda item: item.maintenance_generation)
                if (prior.maintenance_generation + 1 != generation
                        or prior.new_incarnation != barrier.graph_incarnation
                        or set(prior.cumulative_erased_key_digests) != prior_erased):
                    raise GraphRebaseHold("prior Graph erasure certificate chain differs")
                prior_certificate_digest = prior.certificate_digest
        if bool(prior_erased) != bool(prior_certificate_digest):
            raise GraphRebaseHold("prior Graph erased keys lack transition certificate")
        newly_erased = {canonical_digest(token) for token in affected} - prior_erased
        if not newly_erased:
            raise GraphRebaseHold("C09 operation has no new Graph key to erase")
        cumulative_erased = tuple(sorted(prior_erased | newly_erased))
        source_ids = {AtomKey.from_token(token).owner.subject
                      for token in request.affected_source_refs}
        catalogue_rows = catalogue_upgrade_c09_rows_v1(db, affected=affected, affected_operations=affected_operations)
        d04_dispositions = ()
        if _D04_TABLE in descriptions:
            columns, _, rows = descriptions[_D04_TABLE]
            try:
                d04_dispositions = d04_original_dispositions_v3(columns, rows,
                    affected=affected, affected_operations=affected_operations,
                    nested_hits=_nested_hits, source_ids=source_ids,
                    authority_namespace=recovery_requirements["authority_namespace"])
            except (D04ErasureInventoryHold, ValueError, TypeError, KeyError) as exc:
                raise GraphRebaseHold("D04 original erasure linkage differs") from exc
        domain_dispositions = {}
        for table, (columns, _pk, rows) in descriptions.items():
            if table in {'graph_internal_life_paid_originals_v2',
                    'graph_internal_life_worker_originals_v2', 'graph_internal_life_content_originals_v1'}:
                if rows or life_completed_scope is not None:
                    from ..authority_service.c09_life_completed_archive_v1 import completed_life_table_dispositions_v1
                    domain_dispositions[table] = completed_life_table_dispositions_v1(db,
                        scope=life_completed_scope, table=table, columns=columns, rows=rows,
                        affected=affected, affected_operations=affected_operations)
                else:
                    domain_dispositions[table] = ()
                continue
            if table=='graph_contact_expression_plan_originals_v2':
                from .c09_contact_plan_originals_v2 import contact_plan_original_dispositions_v2
                domain_dispositions[table]=contact_plan_original_dispositions_v2(db,columns,rows,
                    affected=affected,affected_operations=affected_operations)
                continue
            if table == _CONTACT_V2_TABLE:
                domain_dispositions[table] = contact_original_dispositions_v2(columns, rows, affected=affected,
                    affected_operations=affected_operations, nested_hits=_nested_hits, source_ids=source_ids,
                    authority_namespace=recovery_requirements["authority_namespace"])
            if table == _CONTACT_TABLE:
                domain_dispositions[table] = contact_original_dispositions_v1(columns, rows, affected=affected,
                    affected_operations=affected_operations, nested_hits=_nested_hits, source_ids=source_ids,
                    authority_namespace=recovery_requirements["authority_namespace"])
            elif table == _D07_TABLE:
                domain_dispositions[table] = d07_original_dispositions_v1(columns, rows, affected=affected,
                    affected_operations=affected_operations, nested_hits=_nested_hits, source_ids=source_ids,
                    authority_namespace=recovery_requirements["authority_namespace"])
            elif table in {_D07_STAGE_TABLE, _D07_ACCOUNTING_TABLE}:
                domain_dispositions[table] = tuple("preserved_exact" for _ in rows)
            elif table in _DOMAIN_COLUMNS:
                domain_dispositions[table] = domain_production_original_dispositions_v1(table, columns, rows,
                    affected=affected, affected_operations=affected_operations, nested_hits=_nested_hits,
                    source_ids=source_ids, authority_namespace=recovery_requirements["authority_namespace"], db=db)
            elif table in {_SHARED_ORIGINAL_TABLE, _SHARED_OUTBOX_TABLE}:
                domain_dispositions[table] = _shared_domain_dispositions_v1(db, table, columns, rows, registry=registry,
                    affected=affected, affected_operations=affected_operations, source_ids=source_ids)
        foreground_dispositions = {}
        if foreground_attempts:
            original_rows = descriptions[_SHARED_ORIGINAL_TABLE][2]
            original_dispositions = dict(zip((row[:3] for row in original_rows),
                domain_dispositions[_SHARED_ORIGINAL_TABLE], strict=True))
            for original in foreground_attempts.values():
                disposition = original_dispositions[original.row[:3]]
                if disposition not in {"preserved_exact", "derived_removed"}:
                    raise GraphRebaseHold("foreground adopted original has no closed body disposition")
                foreground_dispositions[original.attempt_id] = disposition
        available = set()
        for table in _BODY_TABLES:
            columns, _, rows = descriptions[table]
            available.update(row[columns.index("token")] for row in rows)
        if not affected.issubset(available):
            raise GraphRebaseHold("certified closure references absent Graph atoms")
        recomputed = False
        if completion_control is None:
            try:
                fd = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                os.close(fd)
                created = True
            except FileExistsError as exc:
                raise GraphRebaseHold("target must remain a new file") from exc
            new = sqlite3.connect(target)
        else:
            from ..authority_service.c09_build_originals_v1 import open_registered_candidate_v1
            new, recomputed = open_registered_candidate_v1(control=completion_control,
                operation_id=request.operation_id, role="graph", target=target,
                source_root=request.source_files_fingerprint)
        try:
            new.execute("PRAGMA foreign_keys=OFF")
            new.execute("BEGIN IMMEDIATE")
            for kind, name, ddl in objects:
                if kind == "table":
                    if ddl is None:
                        raise GraphRebaseHold(f"table schema unavailable: {name}")
                    new.execute(ddl)
            if "graph_c09_erased_keys_v1" not in tables:
                new.execute("CREATE TABLE graph_c09_erased_keys_v1 ("
                            "bot TEXT NOT NULL, persona TEXT NOT NULL, "
                            "key_digest TEXT NOT NULL, maintenance_generation INTEGER NOT NULL, "
                            "operation_id TEXT NOT NULL, "
                            "PRIMARY KEY(bot,persona,key_digest))")
            if "graph_c09_rebase_certificates_v1" not in tables:
                new.execute("CREATE TABLE graph_c09_rebase_certificates_v1 ("
                            "bot TEXT NOT NULL, persona TEXT NOT NULL, "
                            "operation_id TEXT NOT NULL, certificate_json TEXT NOT NULL, "
                            "PRIMARY KEY(bot,persona,operation_id))")
            manifests = []
            for table in tables:
                columns, pk, rows = descriptions[table]
                positions = tuple(columns.index(name) for name in pk)
                insert = (f"INSERT INTO {_quoted(table)} ({','.join(_quoted(c) for c in columns)}) "
                          f"VALUES ({','.join('?' for _ in columns)})")
                dispositions = []
                for row_index, old in enumerate(rows):
                    key_digest = canonical_digest((table, tuple(old[i] for i in positions)))
                    updated = list(old)
                    disposition = "preserved_exact"
                    row_key = key_digest[:16]
                    if table in catalogue_rows:
                        original, retained, disposition = catalogue_rows[table][row_index]
                        if original != old:
                            raise GraphRebaseHold('catalogue row inventory changed during rebase')
                        updated = list(retained)
                    elif table == _FOREGROUND_ATTEMPT_TABLE and old[4] in foreground_dispositions:
                        # The exact shared original codec supplies the full Source/job closure.
                        disposition = foreground_dispositions[old[4]]
                    elif table == _D04_TABLE:
                        disposition = d04_dispositions[row_index]
                    elif table in _BUDGET_TABLES:
                        # Only strictly decoded fixed financial rows are
                        # exempt from source-reference/operation body scans.
                        validate_c09_budget_row_v1(table, columns, old)
                    elif table in domain_dispositions:
                        disposition = domain_dispositions[table][row_index]
                        if table == _SHARED_OUTBOX_TABLE and disposition == "payload_erased_retained_facts":
                            updated[columns.index("state")] = "retired"
                    elif (table in _BODY_TABLES
                            and old[columns.index("token")] in affected
                            and canonical_digest(old[columns.index("token")])
                                not in prior_erased):
                        token = old[columns.index("token")]
                        updated[columns.index("value")] = canonical_serialize({
                            "schema": _ERASED_SCHEMA, "key_digest": canonical_digest(token)})
                        updated[columns.index("valid")] = 0
                        if table == "graph_history":
                            updated[columns.index("dependencies")] = "[]"
                        disposition = "payload_erased_retained_facts"
                    elif table in _EDGE_TABLES and (
                            old[columns.index("dependent_token")] in affected
                            or old[columns.index("dependency_token")] in affected):
                        disposition = "derived_removed"
                    elif table == "graph_recovery_metadata_v2" and (
                            old[columns.index("bot")], old[columns.index("persona")]) == request.namespace.as_tuple:
                        try:
                            requirements = json.loads(old[columns.index("requirements_json")])
                            if requirements["graph_incarnation"] != barrier.graph_incarnation:
                                raise ValueError("old incarnation differs")
                        except (TypeError, ValueError, KeyError) as exc:
                            raise GraphRebaseHold("Graph recovery head unreadable") from exc
                        requirements["graph_incarnation"] = new_incarnation
                        updated[columns.index("requirements_json")] = canonical_serialize(requirements)
                        disposition = "rebuilt_from_surviving_sources"
                    elif table in _BODY_TABLES and AtomKey.from_token(
                            old[columns.index("token")]).type_name == "memory.access":
                        # Revocation and its history are non-body authority facts.
                        if _row_has_erased_original(
                                table, columns, old, affected, source_ids, row_key):
                            value = json.loads(old[columns.index("value")])
                            if type(value) is not dict or value.get("status") not in {
                                    "active", "withdrawn"}:
                                raise GraphRebaseHold("source access original is malformed")
                    elif table not in _COMMITMENT_TABLES | _REBASE_TABLES and (
                            _row_has_erased_original(
                                table, columns, old, affected, source_ids, row_key)
                            or _operation_body_row(columns, old, affected_operations)):
                        disposition = "derived_removed"
                    elif table in _COMMITMENT_TABLES:
                        # Events and barrier originals contain references and old digests,
                        # but no source body. Their commitments must remain byte-for-byte.
                        _row_has_erased_original(
                            table, columns, old, affected, source_ids, row_key)
                    if disposition != "derived_removed":
                        new.execute(insert, tuple(updated))
                    dispositions.append(GraphRowDispositionV1(
                        key_digest, _row_digest(old), disposition,
                        None if disposition == "derived_removed" else
                        _row_digest(tuple(updated))))
                manifests.append(_disposition_manifest(table, dispositions))
            for key_digest in sorted(newly_erased):
                new.execute("INSERT INTO graph_c09_erased_keys_v1 VALUES(?,?,?,?,?)",
                            (*request.namespace.as_tuple, key_digest, generation,
                             request.operation_id))
            for generated in sorted(_REBASE_TABLES - set(tables)):
                manifests.append(_disposition_manifest(generated, []))
            if source_sequences:
                new.execute("DELETE FROM sqlite_sequence")
                new.executemany("INSERT INTO sqlite_sequence(name,seq) VALUES(?,?)",
                                source_sequences)
            new.execute(f"PRAGMA user_version={user_version}")
            new.execute(f"PRAGMA application_id={application_id}")
            for kind, name, ddl in objects:
                if kind in {"index", "trigger"} and ddl is not None:
                    new.execute(ddl)
            if new.execute("PRAGMA foreign_key_check").fetchone() is not None:
                raise GraphRebaseHold("candidate Graph foreign keys differ")
            if new.execute("PRAGMA integrity_check").fetchone() != ("ok",):
                raise GraphRebaseHold("candidate Graph integrity differs")
            new.commit()
            if not recomputed and new.execute("PRAGMA journal_mode=WAL").fetchall() != [("wal",)]:
                raise GraphRebaseHold("Graph candidate installed WAL policy differs")
            if recomputed:
                from ..authority_service.c09_build_originals_v1 import verify_recomputed_candidate_v1
                verify_recomputed_candidate_v1(new, target)
                expected_root = _cold_graph_data_root(target, request.namespace, affected,
                    new_incarnation, cumulative_erased, candidate_connection=new, registry=registry,
                    completion_control=completion_control, operation_id=request.operation_id,
                    qualified_retention_manifests=tuple(manifests))
                if expected_root != _cold_graph_data_root(target, request.namespace, affected,
                        new_incarnation, cumulative_erased, registry=registry,
                        completion_control=completion_control, operation_id=request.operation_id,
                        qualified_retention_manifests=tuple(manifests)):
                    raise GraphRebaseHold("existing Graph candidate closure differs")
        except Exception:
            new.rollback()
            raise
        finally:
            new.close()
        # Drain all construction cursors before the independent final writer
        # checkpoint. A same-connection PRAGMA may be SQLITE_LOCKED while its
        # completed schema/inspection cursors have not yet been finalized.
        with closing(sqlite3.connect(target, isolation_level=None)) as checkpoint_db:
            checkpoint_db.execute("PRAGMA synchronous=FULL")
            checkpoint = checkpoint_db.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchall()[0]
            if checkpoint[0] != 0:
                raise GraphRebaseHold("Graph candidate checkpoint remains busy")
        if graph_source_files_fingerprint_v1(source) != request.source_files_fingerprint:
            raise GraphRebaseHold("closed Graph source changed during rebase")
        file_hash = _stream_file_sha256_v1(target)
        data_root, cold_read = _cold_graph_data_root(
            target, request.namespace, affected, new_incarnation,
            cumulative_erased, registry=registry,
            completion_control=completion_control, operation_id=request.operation_id,
            qualified_retention_manifests=tuple(manifests))
        manifests = tuple(sorted(manifests, key=lambda item: item.table_name))
        removed = tuple((manifest.table_name, row.row_key_digest,
                         row.old_commitment) for manifest in manifests
                        for row in manifest.rows if row.disposition == "derived_removed")
        certificate = _certificate_draft(
            authority_id=recovery_requirements["authority_id"],
            installation_id=request.installation_id,
            namespace=recovery_requirements["authority_namespace"],
            operation_id=request.operation_id,
            accepted_receipt_digest=request.accepted_receipt_digest,
            barrier_receipt_digest=request.barrier_receipt_digest,
            frozen_inventory_digest=request.frozen_inventory_digest,
            old_incarnation=barrier.graph_incarnation,
            old_revision=recovery_row[1],
            old_graph_epoch=old_graph_epoch[0],
            old_access_epoch=old_authority_epochs[0],
            old_delete_epoch=old_authority_epochs[1],
            new_incarnation=new_incarnation,
            maintenance_generation=generation,
            table_manifests=manifests,
            source_closure_digest=request.certified_closure_digest,
            derived_closure_digest=canonical_digest(removed),
            prior_certificate_digest=prior_certificate_digest,
            prior_erased_key_digests=tuple(sorted(prior_erased)),
            newly_erased_key_digests=tuple(sorted(newly_erased)),
            cumulative_erased_key_digests=cumulative_erased,
            tombstone_root=canonical_digest(cumulative_erased),
            new_data_root=data_root,
            component_hashes=tuple(sorted((
                ("graph_candidate_db", file_hash),
                ("graph_source_snapshot", request.source_files_fingerprint)))),
            cold_read_digest=cold_read,
        )
        schema = "sylanne3.graph.c09_rebase_candidate.v1"
        status = "candidate_only_hold"
        candidate = GraphRebaseCandidateV1(
            request.namespace, request.operation_id,
            request.source_files_fingerprint, request.certified_closure_digest,
            request.frozen_inventory_digest, manifests, file_hash,
            canonical_digest((schema, request.namespace, request.operation_id,
                              request.source_files_fingerprint,
                              request.certified_closure_digest,
                              request.frozen_inventory_digest, manifests,
                              file_hash, new_incarnation, generation,
                              tuple(sorted(newly_erased)), cumulative_erased,
                              str(source), str(target), _file_identity(source),
                              _file_identity(target), certificate,
                              tuple(sorted(affected)), request.writer_freeze_digest,
                              status)),
            new_incarnation, generation, tuple(sorted(newly_erased)),
            cumulative_erased, str(source), str(target),
            _file_identity(source), _file_identity(target), certificate,
            tuple(sorted(affected)), request.writer_freeze_digest)
        if completion_control is not None:
            completion_control.record_build_original_v1(operation_id=request.operation_id,
                kind="graph_candidate", details={"candidate": asdict(candidate)})
        built = True
        return candidate
    except sqlite3.Error as exc:
        raise GraphRebaseHold("Graph rebase SQLite operation failed") from exc
    finally:
        db.close()
        # A failed build remains in the registered rebuild inventory for repair.


def build_installed_graph_rebase_candidate_v1(
    source_path: Path, target_path: Path, *,
    accepted_service: object, credential: object, subject: str,
    installation_id: str, namespace: NamespaceId, operation_id: str,
    permit: object, inventory_manifest: object,
    pinned_manifest_digest: str, writer_freeze_digest: str,
    completion_control=None, registry=None, contact_finish_scope=None, life_completed_scope=None,
    current_inventory_qualifier=None, current_inventory_view=None,
) -> GraphRebaseCandidateV1:
    """Derive the rebase input from installed Authority and Graph originals."""
    from ..authority_service.current_accepted_erasure_read import (
        CurrentAcceptedErasureReadService,
    )
    from ..authority_service.v2_contract import deletion_scope_digest
    from ..memory_types import source_key
    from .c09_installation_inventory_v2 import (
        InstallationFilesystemManifestV2, scan_installed_filesystem_v2,
    )

    if (type(accepted_service) is not CurrentAcceptedErasureReadService
            or type(inventory_manifest) is not InstallationFilesystemManifestV2
            or type(namespace) is not NamespaceId):
        raise TypeError("installed Authority/Graph/inventory inputs required")
    _sha(writer_freeze_digest, "writer_freeze_digest")
    source = Path(source_path).resolve(strict=True)
    target = Path(target_path).resolve(strict=False)
    if current_inventory_qualifier is None:
        if current_inventory_view is not None:raise GraphRebaseHold("inventory view has no installed issuer")
        scan_installed_filesystem_v2(
            inventory_manifest, pinned_manifest_digest=pinned_manifest_digest)
        if not any(item.kind == "sqlite_db" and item.path == str(source)
                   for item in inventory_manifest.resources):
            raise GraphRebaseHold("Graph source is absent from installed inventory")
    else:
        from ..authority_service.current_source_location_v1 import InstalledCurrentSourceLocationQualifierV1
        if (type(current_inventory_qualifier) is not InstalledCurrentSourceLocationQualifierV1
                or current_inventory_qualifier._fences is not accepted_service._service
                or current_inventory_view.manifest!=inventory_manifest
                or pinned_manifest_digest!=inventory_manifest.manifest_digest
                or current_inventory_view.location.accepted_receipt.pending.deletion_operation_id!=operation_id):
            raise GraphRebaseHold("current inventory composition differs")
        current_inventory_qualifier.require_inventory_graph_source_v1(current_inventory_view,source)
        current_inventory_qualifier.scan_installation_inventory_v1(current_inventory_view)
    if not any(item.kind == "rebuild_temp" and item.path in
               {str(parent) for parent in (target.parent, *target.parents)}
               for item in inventory_manifest.resources):
        raise GraphRebaseHold("Graph target is outside installed rebuild inventory")
    if any(Path(str(source) + suffix).exists() for suffix in ("-wal", "-shm")):
        raise GraphRebaseHold("Graph WAL/SHM must be drained before old-file read")
    with closing(sqlite3.connect(source.as_uri() + "?mode=ro&immutable=1", uri=True)) as db:
        db.execute("BEGIN")
        if current_inventory_qualifier is not None:
            current_inventory_qualifier.require_accepted_graph_snapshot_v1(db,current_inventory_view.location,graph_db_path=source)
        plan = read_c09_erasure_plan_original_v1(db, namespace, operation_id)
        barrier = read_c09_erasure_barrier_v1(db, namespace, operation_id)
        if plan is None or barrier is None:
            raise GraphRebaseHold("installed C09 plan/barrier original absent")
        scope_digest = deletion_scope_digest(
            plan.root_source_ids, barrier.delete_epoch_after, plan.policy_ref)
    accepted = accepted_service.read_current_accepted_erasure_v1(
        credential=credential, subject=subject,
        installation_id=installation_id,
        deletion_operation_id=operation_id,
        scope_digest=scope_digest, permit=permit)
    with closing(sqlite3.connect(source.as_uri() + "?mode=ro&immutable=1", uri=True)) as db:
        db.execute("BEGIN")
        request = derive_graph_rebase_input_in_tx_v1(db, source_path=source,
            namespace=namespace, operation_id=operation_id, installation_id=installation_id,
            accepted=accepted, pinned_manifest_digest=pinned_manifest_digest,
            writer_freeze_digest=writer_freeze_digest)
    return build_graph_rebase_candidate_v1(source, target, request=request, completion_control=completion_control,
        registry=registry, contact_finish_scope=contact_finish_scope,
        life_completed_scope=life_completed_scope)


def derive_graph_rebase_input_in_tx_v1(db, *, source_path, namespace, operation_id,
        installation_id, accepted, pinned_manifest_digest, writer_freeze_digest):
    """Use actual accepted plan/barrier/dependency rows under the pinned source read."""
    from ..memory_types import source_key
    if not db.in_transaction or Path(db.execute("PRAGMA database_list").fetchone()[2]).resolve() != Path(source_path).resolve():
        raise GraphRebaseHold("Graph rebase input requires this actual source transaction")
    plan = read_c09_erasure_plan_original_v1(db, namespace, operation_id)
    barrier = read_c09_erasure_barrier_v1(db, namespace, operation_id)
    if plan is None or barrier is None:
        raise GraphRebaseHold("actual accepted Graph plan/barrier absent")
    roots = tuple(source_key(*namespace.as_tuple, source_id).token for source_id in plan.root_source_ids)
    if (roots != barrier.root_source_refs or plan.operation_id != barrier.operation_id
            or plan.graph_incarnation != barrier.graph_incarnation):
        raise GraphRebaseHold("C09 plan and barrier source roots differ")
    if (accepted.deletion_epoch != barrier.delete_epoch_after
            or accepted.closure_roots != plan.root_source_ids
            or accepted.graph_barrier_digest != "sha256:" + canonical_digest(barrier)
            or accepted.pending_receipt.pending.request_digest.removeprefix("sha256:") != barrier.request_digest
            or canonical_digest(accepted.pending_receipt) != barrier.pending_receipt_digest):
        raise GraphRebaseHold("Authority accepted original differs from Graph barrier")
    closure = tuple(sorted(_dependency_closure(db, set(barrier.affected_source_refs))))
    inventory = tuple(sorted(name for (name,) in db.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")))
    return GraphRebaseInputV1(
        namespace, operation_id, canonical_digest(accepted.accepted_receipt),
        canonical_digest(barrier), barrier.closure_digest,
        writer_freeze_digest, pinned_manifest_digest,
        graph_source_files_fingerprint_v1(Path(source_path)),
        barrier.affected_source_refs, closure, inventory, installation_id,
    )


def install_verified_graph_rebase_certificate_v1(
    candidate: GraphRebaseCandidateV1, *, core: object,
    credential: object, issued: object, registry=None,
) -> GraphRebaseMirrorV1:
    """Mirror a current Core-issued transition into the fresh Graph file.

    The Core ledger and its installed signing key are checked on every call;
    possessing a certificate DTO or candidate file is never sufficient.
    """
    from ..authority_service.core import AuthorityServiceCore
    from ..authority_service.c09_graph_rebase_issue_v1 import (
        AuthorityGraphRebaseIssuedV1,
    )
    from .c09_graph_originals_read_v4 import read_graph_rebase_certificate_v1

    if (type(candidate) is not GraphRebaseCandidateV1
            or type(core) is not AuthorityServiceCore
            or type(issued) is not AuthorityGraphRebaseIssuedV1):
        raise TypeError("installed Core issue and Graph candidate required")
    core.verify_current_graph_rebase_issue_v1(credential, issued, candidate.certificate_draft)
    key, manifest, _ = core._c09_maintenance_authority_v1
    with core._tx() as core_db:
        return install_graph_rebase_certificate_connection_v1(candidate, core_db=core_db,
            signing_key=key, inventory_manifest=manifest,
            completion_control=core._c09_storage_reader_v1, issued=issued, registry=registry)


__all__ = [
    "GraphRebaseHold", "GraphRebaseInputV1", "GraphRebaseCandidateV1",
    "GraphRebaseMirrorV1",
    "graph_source_files_fingerprint_v1", "build_graph_rebase_candidate_v1",
    "build_installed_graph_rebase_candidate_v1",
    "install_verified_graph_rebase_certificate_v1",
]


def install_graph_rebase_certificate_connection_v1(
        candidate, *, core_db, signing_key, inventory_manifest, completion_control, issued, registry=None):
    """Mirror through real pinned Core rows and retain independent physical completion."""
    from ..authority_service.c09_graph_rebase_issue_v1 import (
        AuthorityGraphRebaseIssuedV1, verify_graph_rebase_issue_in_tx_v1)
    from ..authority_service.c09_build_originals_v1 import decode_installed_build_original_v1
    from ..authority_service.c09_storage_control_v1 import C09StorageControlV1
    from .c09_graph_originals_read_v4 import read_graph_rebase_certificate_v1
    if (type(candidate) is not GraphRebaseCandidateV1
            or type(issued) is not AuthorityGraphRebaseIssuedV1
            or type(completion_control) is not C09StorageControlV1 or not core_db.in_transaction):
        raise TypeError("actual pinned Core and installed completion control required")
    completion_control.lease.require_held()
    certificate = candidate.certificate_draft
    source, target = Path(candidate.source_path), Path(candidate.target_path)
    if (issued.candidate_digest != candidate.candidate_digest
            or issued.certificate_digest != certificate.certificate_digest
            or issued.target_file_sha256 != candidate.new_file_sha256
            or issued.source_files_fingerprint != candidate.source_files_fingerprint
            or issued.source_path != candidate.source_path
            or issued.target_path != candidate.target_path
            or issued.source_identity != candidate.source_identity
            or issued.target_identity != candidate.target_identity
            or issued.maintenance_generation != candidate.maintenance_generation
            or issued.stage != "PREPARED"):
        raise GraphRebaseHold("Core issue differs from Graph candidate")
    completed = completion_control.read_build_original_v1(
        operation_id=candidate.operation_id, kind="graph_mirror")
    db = sqlite3.connect(target)
    try:
        db.execute("BEGIN IMMEDIATE")
        if verify_graph_rebase_issue_in_tx_v1(core_db, key=signing_key,
                manifest=inventory_manifest, issued=issued, certificate=certificate) is not True:
            raise GraphRebaseHold("current Core Graph rebase issue unverified")
        prior = read_graph_rebase_certificate_v1(
            db, candidate.namespace, candidate.operation_id)
        if prior is not None:
            if prior != certificate or completed is None:
                raise GraphRebaseHold("Graph certificate has no authenticated mirror completion original")
            db.rollback()
            root, cold = _cold_graph_data_root(
                target, candidate.namespace, set(candidate.affected_atom_refs),
                candidate.new_incarnation, candidate.cumulative_erased_key_digests,
                candidate_connection=db, registry=registry,
                completion_control=completion_control, operation_id=candidate.operation_id)
            actual = GraphRebaseMirrorV1(certificate, issued.issue_digest,
                _stream_file_sha256_v1(target), _file_identity(target), root, cold)
            saved = decode_installed_build_original_v1(completed["details"]["mirror"], GraphRebaseMirrorV1)
            if (actual != saved or canonical_serialize(completed["details"]) != canonical_serialize({
                    "candidate_digest": candidate.candidate_digest, "mirror": asdict(saved)})
                    or (root, cold) != (certificate.new_data_root, certificate.cold_read_digest)):
                raise GraphRebaseHold("authenticated Graph mirror completion differs")
            return saved
        if completed is not None:
            raise GraphRebaseHold("Graph mirror completion has no actual certificate")
        if (_file_identity(source) != candidate.source_identity
                or _file_identity(target) != candidate.target_identity
                or graph_source_files_fingerprint_v1(source)
                   != candidate.source_files_fingerprint
                or _stream_file_sha256_v1(target)
                   != candidate.new_file_sha256):
            raise GraphRebaseHold("Graph candidate file identity changed before mirror")
        db.execute("INSERT INTO graph_c09_rebase_certificates_v1 "
                   "(bot,persona,operation_id,certificate_json) VALUES(?,?,?,?)",
                   (*candidate.namespace.as_tuple, candidate.operation_id,
                    canonical_serialize(asdict(certificate))))
        if read_graph_rebase_certificate_v1(
                db, candidate.namespace, candidate.operation_id) != certificate:
            raise GraphRebaseHold("Graph certificate mirror cold read differs")
        db.commit()
        if db.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()[0] != 0:
            raise GraphRebaseHold("mirrored Graph candidate checkpoint remains busy")
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
    root, cold = _cold_graph_data_root(
        target, candidate.namespace, set(candidate.affected_atom_refs),
        candidate.new_incarnation, candidate.cumulative_erased_key_digests, registry=registry,
        completion_control=completion_control, operation_id=candidate.operation_id)
    if (root, cold) != (certificate.new_data_root, certificate.cold_read_digest):
        raise GraphRebaseHold("mirrored Graph data root differs")
    mirror = GraphRebaseMirrorV1(
        certificate, issued.issue_digest,
        _stream_file_sha256_v1(target),
        _file_identity(target), root, cold)
    completion_control.record_build_original_v1(operation_id=candidate.operation_id,
        kind="graph_mirror", details={"candidate_digest": candidate.candidate_digest, "mirror": asdict(mirror)})
    return mirror
