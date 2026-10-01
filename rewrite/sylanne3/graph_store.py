"""Transactional typed graph storage on the foundation SQLite connection."""

from __future__ import annotations

import json
import hashlib
import secrets
from contextlib import contextmanager
from dataclasses import asdict, dataclass, fields
from typing import Protocol

from .contracts import Event, EventConflict, StaleRead, canonical_json, json_object, nonempty
from .graph_types import (
    AtomKey,
    GraphAtom,
    GraphPage,
    GraphCandidate,
    GraphReceipt,
    GraphSnapshot,
    GraphVersion,
    NamespaceEpoch,
    OWNER_GRANT_TYPE,
    owner_grant_key,
    validate_owner_grant_v1,
    TypeRegistry,
)
from .store import Store
from .runtime import install_schema as install_runtime_schema
from .runtime_contracts import NamespaceId, SnapshotRequirementsV2
from .authority_service.v2_owner_contract import OwnerMigrationHeadV1
from .runtime_contracts import canonical_digest


@dataclass(frozen=True, slots=True)
class GraphRecoveryMetadataV2:
    """Stored comparison target and namespace commit stamp, not an Authority permit.

    Every protected business commit must advance graph_revision when its writer
    is connected to this seam; this storage slice does not connect those writers.
    """

    requirements: SnapshotRequirementsV2
    graph_revision: int

    def __post_init__(self):
        if type(self.requirements) is not SnapshotRequirementsV2:
            raise TypeError("requirements must be SnapshotRequirementsV2")
        if type(self.graph_revision) is not int or self.graph_revision < 0:
            raise ValueError("graph_revision must be a nonnegative integer")


@dataclass(frozen=True, slots=True)
class GraphMigrationVerifiedTransferV1:
    """Result of a trusted local check of an externally verified transfer receipt.

    This is a comparison result, not a caller-supplied permission. The bound
    verifier must authenticate the Authority transfer and journal continuity
    before returning it; remote work belongs outside the graph transaction.
    """

    transfer_id: str
    source: GraphRecoveryMetadataV2
    target: SnapshotRequirementsV2
    authority_phase: str
    source_snapshot_digest: str
    owner_head: OwnerMigrationHeadV1 | None = None

    def __post_init__(self):
        nonempty(self.transfer_id, "transfer_id")
        if type(self.source) is not GraphRecoveryMetadataV2:
            raise TypeError("source must be GraphRecoveryMetadataV2")
        if type(self.target) is not SnapshotRequirementsV2:
            raise TypeError("target must be SnapshotRequirementsV2")
        nonempty(self.source_snapshot_digest, "source_snapshot_digest")
        if self.owner_head is not None and type(self.owner_head) is not OwnerMigrationHeadV1:
            raise TypeError("owner_head must be the frozen Authority head")


class GraphMigrationTransferVerifier(Protocol):
    """Pinned installation verifier for a previously authenticated transfer."""

    def verify_local(self, transfer_receipt: object) -> GraphMigrationVerifiedTransferV1:
        ...


def _assert_migration_owner_head_in_transaction(
        db, namespace: NamespaceId, head: OwnerMigrationHeadV1 | None) -> None:
    """Compare restored graph originals with Authority's frozen latest Owner head."""
    key = owner_grant_key(*namespace.as_tuple)
    grant_row = db.execute(
        "SELECT revision,value,valid FROM graph_atoms WHERE token=?",
        (key.token,),
    ).fetchone()
    issue_row = db.execute(
        "SELECT operation_id,request_digest,grant_id,grant_digest,"
        "graph_incarnation,graph_access_epoch,graph_epoch,"
        "graph_receipt_digest,proof_json FROM graph_owner_issue_operations_v1 "
        "WHERE bot=? AND persona=?", namespace.as_tuple,
    ).fetchone()
    revoke_row = db.execute(
        "SELECT operation_id,request_digest,grant_id,grant_digest,"
        "graph_incarnation,previous_grant_digest,graph_access_epoch,"
        "graph_epoch,graph_receipt_digest,proof_json "
        "FROM graph_owner_revoke_operations_v1 WHERE bot=? AND persona=?",
        namespace.as_tuple,
    ).fetchone()
    if head is None:
        if any(row is not None for row in (grant_row, issue_row, revoke_row)):
            raise PermissionError("restored Owner graph lacks current Authority head")
        return
    if (type(head) is not OwnerMigrationHeadV1
            or head.issue_operation.namespace != namespace
            or head.guard.namespace != namespace
            or grant_row is None or grant_row[2] != 1
            or issue_row is None):
        raise PermissionError("restored Owner issue identity differs")
    try:
        grant = json.loads(grant_row[1])
        validate_owner_grant_v1(grant)
    except (TypeError, ValueError) as exc:
        raise PermissionError("restored Owner grant is invalid") from exc
    issue = head.issue_proof
    expected_issue = (
        issue.operation_id, issue.request_digest, issue.grant_id,
        issue.grant_digest, issue.graph_incarnation,
        issue.graph_access_epoch, issue.graph_epoch,
        issue.graph_receipt_digest, canonical_json(asdict(issue)),
    )
    expected_digest = "sha256:" + canonical_digest(grant)
    access = db.execute(
        "SELECT access_epoch FROM graph_authority_epochs "
        "WHERE bot=? AND persona=?", namespace.as_tuple,
    ).fetchone()
    if (grant_row[1] != canonical_json(grant)
            or grant_row[0] != head.grant_revision
            or grant["grant_revision"] != head.grant_revision
            or grant["state"] != ("revoked" if head.state == "revoked"
                                   else "pending_authority")
            or grant["grant_id"] != head.issue_operation.grant_id
            or expected_digest != head.grant_digest
            or access != (head.graph_access_epoch,)
            or issue_row != expected_issue):
        raise PermissionError("restored Owner graph is behind Authority head")
    if head.state == "active":
        if revoke_row is not None:
            raise PermissionError("restored Owner revoke lacks Authority head")
        return
    revoke = head.revoke_proof
    if revoke is None or revoke_row != (
            revoke.operation_id, revoke.request_digest, revoke.grant_id,
            revoke.grant_digest, revoke.graph_incarnation,
            issue.grant_digest, revoke.graph_access_epoch,
            revoke.graph_epoch, revoke.graph_receipt_digest,
            canonical_json(asdict(revoke))):
        raise PermissionError("restored Owner rev2 proof differs from Authority")


@dataclass(frozen=True, slots=True)
class DeletionHistoryCursor:
    """Last completed history row, or the next edge offset in a split row."""

    key: AtomKey
    revision: int
    edge_offset: int = 0

    def __post_init__(self):
        if not isinstance(self.key, AtomKey):
            raise TypeError("cursor key must be AtomKey")
        if type(self.revision) is not int or self.revision < 1:
            raise ValueError("cursor revision must be positive")
        if type(self.edge_offset) is not int or self.edge_offset < 0:
            raise ValueError("cursor edge offset must be nonnegative")


@dataclass(frozen=True, slots=True)
class DeletionDependencyEdge:
    dependent: GraphVersion
    dependency: GraphVersion


@dataclass(frozen=True, slots=True)
class DeletionHistoryRow:
    atom: GraphAtom
    event_session: str
    event_id: str
    dependency_count: int


@dataclass(frozen=True, slots=True)
class DeletionSnapshotPage:
    """Internal evidence only; the coordinator must supply production read admission."""

    snapshot: GraphSnapshot
    read_set: tuple[GraphVersion, ...]
    current_reverse_edges: tuple[DeletionDependencyEdge, ...]
    history_rows: tuple[DeletionHistoryRow, ...]
    history_edges: tuple[DeletionDependencyEdge, ...]
    next_after: DeletionHistoryCursor | None
    complete: bool

    @property
    def epoch(self) -> NamespaceEpoch:
        return self.snapshot.epochs[0]


class GraphStore(Store):
    """Adds a typed, multi-owner graph to :class:`Store`'s database and lock."""

    def __init__(self, path, registry: TypeRegistry, *,
                 migration_transfer_verifier: GraphMigrationTransferVerifier | None = None):
        if not isinstance(registry, TypeRegistry):
            raise TypeError("registry must be TypeRegistry")
        self._registry = registry.freeze()
        self._migration_transfer_verifier = migration_transfer_verifier
        super().__init__(path)
        with self._lock:
            try:
                self._create_graph_schema()
                from .runtime.d04_joint_advance_v2 import install_joint_advance_store_v2
                from .runtime.d04_joint_output_original_store_v1 import (
                    install_d04_joint_output_original_store_v1,
                )
                from .runtime.d04_root_original_store_v1 import (
                    install_d04_root_original_store_v1,
                )
                from .runtime.d04_root_adoption_original_v2 import (
                    install_d04_root_adoption_original_v2,
                )
                from .runtime.d04_root_original_store_v3 import (
                    install_d04_root_original_store_v3,
                )
                from .runtime.d11_d04_root_freeze_v3 import install_d11_root_freeze_v3
                install_joint_advance_store_v2(self._db)
                install_d04_joint_output_original_store_v1(self._db)
                install_d04_root_original_store_v1(self._db)
                install_d04_root_adoption_original_v2(self._db)
                install_d04_root_original_store_v3(self._db)
                install_d11_root_freeze_v3(self._db)
                from .runtime.d04_appraisal_driver_v3 import install_d04_appraisal_schema_v3
                from .runtime.d07_current_behavior_v1 import install_current_d07_behavior_schema_v1
                from .runtime.lifecycle_operations_v1 import LifecycleOriginalStoreV1
                install_d04_appraisal_schema_v3(self._db)
                from .runtime.d04_installed_stage_fence_v3 import install_schema as install_d04_stage_fence
                install_d04_stage_fence(self._db)
                install_current_d07_behavior_schema_v1(self._db)
                LifecycleOriginalStoreV1(db=self._db, lock=self._lock).install_schema()
                from .runtime.d13_paid_intent_original_v1 import (
                    install_d13_paid_intent_original_v1,
                )
                install_d13_paid_intent_original_v1(self._db)
                from .runtime.d13_paid_coordinator_v1 import (
                    install_d13_paid_coordinator_schema_v1,
                )
                install_d13_paid_coordinator_schema_v1(self._db)
                from .runtime.installed_d13_wire_evidence_v1 import install_d13_wire_evidence_schema_v1
                install_d13_wire_evidence_schema_v1(self._db)
                from .runtime.d04_semantic_installation_original_v3 import install_d04_semantic_installation_schema_v3
                install_d04_semantic_installation_schema_v3(self._db)
                from .runtime.d04_owner_initialization_v3 import install_d04_root_topology_originals_v3
                install_d04_root_topology_originals_v3(self._db)
                from .runtime.d13_outbound_observation_v1 import install_d13_outbound_schema_v1
                install_d13_outbound_schema_v1(self._db)
                from .domains.d02.body_quote_original import install_body_quote_schema
                install_body_quote_schema(self._db)
                from .runtime.c04_encoding_baseline_store_v3 import install_c04_encoding_baseline_store_v3
                install_c04_encoding_baseline_store_v3(self._db)
                from .runtime.c04_frozen_association_original_v3 import install_c04_frozen_association_original_v3
                from .runtime.c04_product_original_v3 import install_c04_product_original_v3
                from .runtime.c04_interpretation_policy_v3 import install_c04_interpretation_policy_original_v3
                install_c04_frozen_association_original_v3(self._db)
                install_c04_product_original_v3(self._db)
                install_c04_interpretation_policy_original_v3(self._db)
                from .runtime.c04_historical_accounting_v1 import install_c04_historical_schema_v1
                install_c04_historical_schema_v1(self._db)
                from .runtime.c04_historical_accounting_v1 import install_c04_adoption_provenance_schema_v3
                install_c04_adoption_provenance_schema_v3(self._db)
                from .authority_service.c09_graph_application_v1 import install_c09_graph_application_schema_v1
                install_c09_graph_application_schema_v1(self._db)
                from .runtime.d01_production_operations_v1 import install_d01_production_schema_v1
                from .runtime.d02_production_operations_v1 import install_d02_production_schema_v1
                from .runtime.d05_production_operations_v1 import install_d05_production_schema_v1
                from .runtime.d08_production_operations_v1 import install_d08_production_schema_v1
                from .runtime.d10_production_operations_v1 import install_d10_production_schema_v1
                from .runtime.d11_offline_originals_v1 import install_d11_offline_schema_v1
                from .runtime.d11_life_preparation_v1 import install_d11_life_schema_v1
                for install in (install_d01_production_schema_v1, install_d02_production_schema_v1,
                        install_d05_production_schema_v1, install_d08_production_schema_v1,
                        install_d10_production_schema_v1, install_d11_offline_schema_v1, install_d11_life_schema_v1):
                    install(self._db)
                self._db.execute("BEGIN IMMEDIATE")
                install_runtime_schema(self._db)
                from .runtime.d12_installed_graph_schema_v1 import install_d12_installed_graph_schema_v1
                install_d12_installed_graph_schema_v1(self._db)
                from .runtime.c09_erasure_barrier_store_v1 import (
                    install_c09_erasure_barrier_store_v1,
                )
                from .runtime.c09_erasure_plan_original_v1 import (
                    install_c09_erasure_plan_schema_v1,
                )
                from .runtime.c04_cpu_quote_policy import (
                    install_c04_cpu_quote_schema_v1,
                )
                from .runtime.c04_frozen_association_original_v2 import (
                    install_c04_frozen_association_original_v2,
                )
                from .runtime.c04_internal_work_original_v1 import (
                    install_c04_internal_work_original_v1,
                )
                from .runtime.d11_c04_internal_cost import (
                    install_d11_c04_cost_schema,
                )
                from .domains.d02.c04_fixed_component_cost import (
                    install_d02_c04_body_cost_schema,
                )
                install_c09_erasure_barrier_store_v1(self._db)
                install_c09_erasure_plan_schema_v1(self._db)
                install_c04_cpu_quote_schema_v1(self._db)
                install_c04_internal_work_original_v1(self._db)
                install_c04_frozen_association_original_v2(self._db)
                install_d11_c04_cost_schema(self._db)
                install_d02_c04_body_cost_schema(self._db)
                from .runtime.source_attachment_graph_v2 import install_media_blob_schema
                install_media_blob_schema(self._db)
                self._check_catalog()
                self._db.execute("COMMIT")
            except BaseException:
                if self._db.in_transaction:
                    self._db.execute("ROLLBACK")
                super().close()
                raise

    def _create_graph_schema(self):
        self._db.executescript("""
            CREATE TABLE IF NOT EXISTS graph_type_catalog (
                name TEXT PRIMARY KEY,
                owner_kinds TEXT NOT NULL,
                storage_role TEXT NOT NULL,
                immutable INTEGER NOT NULL CHECK(immutable IN (0, 1)),
                schema_version INTEGER NOT NULL CHECK(schema_version > 0));
            CREATE TABLE IF NOT EXISTS graph_atoms (
                token TEXT PRIMARY KEY,
                bot TEXT NOT NULL,
                persona TEXT NOT NULL,
                owner_kind TEXT NOT NULL,
                subject TEXT,
                type_name TEXT NOT NULL,
                name TEXT NOT NULL,
                revision INTEGER NOT NULL CHECK(revision > 0),
                value TEXT NOT NULL,
                valid INTEGER NOT NULL CHECK(valid IN (0, 1)));
            CREATE INDEX IF NOT EXISTS graph_atoms_namespace
                ON graph_atoms(bot, persona);
            CREATE INDEX IF NOT EXISTS graph_atoms_namespace_type_token
                ON graph_atoms(bot, persona, type_name, token);
            CREATE INDEX IF NOT EXISTS graph_d09_turn_slot_origin
                ON graph_atoms(bot, persona, json_extract(value, '$.origin_ref'))
                WHERE type_name='d09.turn_slot.v1';
            CREATE TABLE IF NOT EXISTS graph_dependencies (
                dependent_token TEXT NOT NULL,
                dependency_token TEXT NOT NULL,
                dependency_revision INTEGER NOT NULL CHECK(dependency_revision >= 0),
                PRIMARY KEY(dependent_token, dependency_token),
                FOREIGN KEY(dependent_token) REFERENCES graph_atoms(token));
            CREATE INDEX IF NOT EXISTS graph_dependencies_reverse
                ON graph_dependencies(dependency_token);
            CREATE TABLE IF NOT EXISTS graph_epochs (
                bot TEXT NOT NULL,
                persona TEXT NOT NULL,
                revision INTEGER NOT NULL CHECK(revision >= 0),
                PRIMARY KEY(bot, persona));
            CREATE TABLE IF NOT EXISTS graph_events (
                bot TEXT NOT NULL,
                persona TEXT NOT NULL,
                session TEXT NOT NULL,
                event_id TEXT NOT NULL,
                digest TEXT NOT NULL,
                reads TEXT NOT NULL,
                epoch_reads TEXT NOT NULL,
                revisions TEXT NOT NULL,
                invalidated TEXT NOT NULL,
                epoch_revision INTEGER NOT NULL CHECK(epoch_revision >= 0),
                PRIMARY KEY(bot, persona, session, event_id));
            CREATE TABLE IF NOT EXISTS graph_history (
                token TEXT NOT NULL,
                revision INTEGER NOT NULL CHECK(revision > 0),
                value TEXT NOT NULL,
                valid INTEGER NOT NULL CHECK(valid IN (0, 1)),
                dependencies TEXT NOT NULL,
                event_bot TEXT NOT NULL,
                event_persona TEXT NOT NULL,
                event_session TEXT NOT NULL,
                event_id TEXT NOT NULL,
                PRIMARY KEY(token, revision),
                FOREIGN KEY(event_bot, event_persona, event_session, event_id)
                    REFERENCES graph_events(bot, persona, session, event_id));
            CREATE TABLE IF NOT EXISTS graph_d13_retirements_v1 (
                bot TEXT NOT NULL, persona TEXT NOT NULL,
                operation_id TEXT NOT NULL, input_digest TEXT NOT NULL,
                block_token TEXT NOT NULL, old_revision INTEGER NOT NULL,
                cache_revision INTEGER NOT NULL, graph_revision INTEGER NOT NULL,
                graph_epoch INTEGER NOT NULL, cleanup_task_ref TEXT NOT NULL,
                receipt_json TEXT NOT NULL,
                PRIMARY KEY(bot, persona, operation_id),
                UNIQUE(bot, persona, block_token));
            CREATE TABLE IF NOT EXISTS graph_d13_cleanup_tasks_v1 (
                bot TEXT NOT NULL, persona TEXT NOT NULL,
                task_ref TEXT NOT NULL, block_token TEXT NOT NULL,
                retirement_operation_id TEXT NOT NULL,
                state TEXT NOT NULL CHECK(state='pending'),
                PRIMARY KEY(bot, persona, task_ref),
                UNIQUE(bot, persona, block_token));
            CREATE TABLE IF NOT EXISTS graph_d13_inbound_turn_attempts_v1 (
                bot TEXT NOT NULL, persona TEXT NOT NULL,
                ingress_operation_id TEXT NOT NULL,
                c02_operation_id TEXT NOT NULL,
                attempt_id TEXT NOT NULL,
                anchor_json TEXT NOT NULL,
                pre_graph_revision INTEGER NOT NULL,
                pre_graph_epoch INTEGER NOT NULL,
                permit_json TEXT,
                finish_request_id TEXT,
                finish_request_digest TEXT,
                receipt_json TEXT,
                PRIMARY KEY(bot, persona, ingress_operation_id),
                UNIQUE(bot, persona, attempt_id));
            CREATE TABLE IF NOT EXISTS graph_d13_precompression_attempts_v2 (
                bot TEXT NOT NULL, persona TEXT NOT NULL,
                operation_id TEXT NOT NULL, intent_digest TEXT NOT NULL,
                intent_json TEXT NOT NULL,
                attempt_id TEXT NOT NULL, anchor_json TEXT NOT NULL,
                pre_graph_revision INTEGER NOT NULL,
                pre_graph_epoch INTEGER NOT NULL,
                permit_json TEXT, finish_request_id TEXT,
                finish_request_digest TEXT, receipt_json TEXT,
                rejected_json TEXT,
                finish_confirmed INTEGER NOT NULL DEFAULT 0
                    CHECK(finish_confirmed IN (0,1)),
                PRIMARY KEY(bot, persona, operation_id),
                UNIQUE(bot, persona, attempt_id));
            CREATE TABLE IF NOT EXISTS graph_d13_worker_attempts_v2 (
                bot TEXT NOT NULL, persona TEXT NOT NULL,
                operation_id TEXT NOT NULL, request_digest TEXT NOT NULL,
                attempt_id TEXT NOT NULL, anchor_json TEXT NOT NULL,
                pre_graph_revision INTEGER NOT NULL,
                pre_graph_epoch INTEGER NOT NULL,
                permit_json TEXT, finish_request_id TEXT,
                finish_request_digest TEXT, receipt_json TEXT,
                PRIMARY KEY(bot, persona, operation_id),
                UNIQUE(bot, persona, attempt_id));
            CREATE TABLE IF NOT EXISTS graph_d13_paid_write_attempts_v1 (
                bot TEXT NOT NULL, persona TEXT NOT NULL,
                phase TEXT NOT NULL, operation_id TEXT NOT NULL,
                attempt_id TEXT NOT NULL, request_digest TEXT NOT NULL,
                anchor_json TEXT NOT NULL,
                pre_graph_revision INTEGER NOT NULL,
                pre_graph_epoch INTEGER NOT NULL,
                permit_json TEXT, finish_request_id TEXT,
                finish_request_digest TEXT, receipt_json TEXT,
                PRIMARY KEY(bot, persona, phase, operation_id),
                UNIQUE(bot, persona, attempt_id));
            CREATE TABLE IF NOT EXISTS graph_type_authority (
                name TEXT PRIMARY KEY,
                writer_domain TEXT NOT NULL,
                schema_hash TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS graph_source_access_revocations_v1 (
                bot TEXT NOT NULL, persona TEXT NOT NULL,
                request_id TEXT NOT NULL, operation_id TEXT NOT NULL,
                request_digest TEXT NOT NULL, request_json TEXT NOT NULL,
                attempt_id TEXT NOT NULL, anchor_json TEXT NOT NULL,
                requirements_json TEXT NOT NULL,
                pre_graph_revision INTEGER NOT NULL,
                pre_graph_epoch INTEGER NOT NULL,
                permit_json TEXT, finish_request_id TEXT,
                finish_request_digest TEXT, receipt_json TEXT,
                rejected INTEGER NOT NULL DEFAULT 0 CHECK(rejected IN (0,1)),
                PRIMARY KEY(bot,persona,request_id),
                UNIQUE(bot,persona,operation_id),
                UNIQUE(bot,persona,attempt_id));
            CREATE TABLE IF NOT EXISTS graph_authority_epochs (
                bot TEXT NOT NULL, persona TEXT NOT NULL,
                access_epoch INTEGER NOT NULL DEFAULT 0,
                delete_epoch INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY(bot, persona));
            CREATE TABLE IF NOT EXISTS graph_guard_versions (
                bot TEXT NOT NULL, persona TEXT NOT NULL,
                kind TEXT NOT NULL, ref TEXT NOT NULL, version TEXT NOT NULL,
                PRIMARY KEY(bot, persona, kind, ref));
            CREATE TABLE IF NOT EXISTS graph_bundle_operations (
                bot TEXT NOT NULL, persona TEXT NOT NULL,
                operation_id TEXT NOT NULL, digest TEXT NOT NULL,
                activity_id TEXT NOT NULL, effect_id TEXT,
                commit_seq INTEGER NOT NULL, receipt_json TEXT NOT NULL,
                PRIMARY KEY(bot, persona, operation_id));
            CREATE TABLE IF NOT EXISTS graph_product_advances (
                bot TEXT NOT NULL, persona TEXT NOT NULL,
                operation_id TEXT NOT NULL, process_id TEXT NOT NULL,
                feeling_ref TEXT NOT NULL, mood_ref TEXT NOT NULL,
                parent_operation_id TEXT NOT NULL, replay_key TEXT NOT NULL,
                from_cursor REAL NOT NULL, to_cursor REAL NOT NULL,
                candidate_digest TEXT NOT NULL, numeric_input_digest TEXT NOT NULL,
                numeric_output_digest TEXT NOT NULL,
                native_manifest_sha256 TEXT NOT NULL, native_sha256 TEXT NOT NULL,
                previous_error_bound REAL NOT NULL, next_error_bound REAL NOT NULL,
                PRIMARY KEY(bot, persona, operation_id),
                UNIQUE(bot, persona, process_id, replay_key),
                FOREIGN KEY(bot, persona, operation_id)
                    REFERENCES graph_bundle_operations(bot, persona, operation_id));
            CREATE INDEX IF NOT EXISTS graph_product_advances_interval
                ON graph_product_advances(bot, persona, process_id, from_cursor, to_cursor);
            CREATE TABLE IF NOT EXISTS graph_bundle_sequence (
                bot TEXT NOT NULL, persona TEXT NOT NULL,
                last_seq INTEGER NOT NULL,
                PRIMARY KEY(bot, persona));
            CREATE TABLE IF NOT EXISTS graph_bundle_refs (
                bot TEXT NOT NULL, persona TEXT NOT NULL,
                operation_id TEXT NOT NULL, ref_kind TEXT NOT NULL,
                ref TEXT NOT NULL,
                PRIMARY KEY(bot, persona, ref_kind, ref),
                FOREIGN KEY(bot,persona,operation_id)
                    REFERENCES graph_bundle_operations(bot,persona,operation_id));
            CREATE TABLE IF NOT EXISTS graph_bundle_outbox (
                bot TEXT NOT NULL, persona TEXT NOT NULL,
                outbox_ref TEXT NOT NULL,
                operation_id TEXT NOT NULL,
                phase TEXT NOT NULL CHECK(phase IN ('pending','claimed','cancelled')),
                PRIMARY KEY(bot,persona,outbox_ref),
                FOREIGN KEY(bot,persona,operation_id)
                    REFERENCES graph_bundle_operations(bot,persona,operation_id));
            CREATE TABLE IF NOT EXISTS graph_outbox_jobs (
                bot TEXT NOT NULL, persona TEXT NOT NULL,
                outbox_ref TEXT NOT NULL, job_id TEXT NOT NULL,
                operation_id TEXT NOT NULL,
                PRIMARY KEY(bot,persona,outbox_ref),
                FOREIGN KEY(job_id) REFERENCES runtime_jobs(job_id));
            CREATE TABLE IF NOT EXISTS graph_dependency_edges (
                dependent_token TEXT NOT NULL, dependency_token TEXT NOT NULL,
                dependency_revision INTEGER NOT NULL,
                edge_kind TEXT NOT NULL,
                operation_id TEXT NOT NULL,
                PRIMARY KEY(dependent_token,dependency_token,edge_kind,operation_id));
            CREATE TABLE IF NOT EXISTS graph_recovery_metadata_v2 (
                bot TEXT NOT NULL, persona TEXT NOT NULL,
                schema TEXT NOT NULL CHECK(schema='sylanne3.authority.v2'),
                requirements_json TEXT NOT NULL,
                graph_revision INTEGER NOT NULL CHECK(graph_revision >= 0),
                PRIMARY KEY(bot,persona));
            CREATE TABLE IF NOT EXISTS graph_namespace_provisioning_v2 (
                bot TEXT NOT NULL, persona TEXT NOT NULL,
                operation_id TEXT NOT NULL, digest TEXT NOT NULL,
                receipt_json TEXT NOT NULL,
                PRIMARY KEY(bot,persona));
            CREATE TABLE IF NOT EXISTS graph_owner_issue_operations_v1 (
                bot TEXT NOT NULL, persona TEXT NOT NULL,
                operation_id TEXT NOT NULL,
                request_digest TEXT NOT NULL,
                grant_id TEXT NOT NULL,
                grant_digest TEXT NOT NULL,
                graph_incarnation TEXT NOT NULL,
                graph_access_epoch INTEGER NOT NULL CHECK(graph_access_epoch > 0),
                graph_epoch INTEGER NOT NULL CHECK(graph_epoch > 0),
                graph_receipt_digest TEXT NOT NULL,
                proof_json TEXT NOT NULL,
                PRIMARY KEY(bot,persona), UNIQUE(operation_id), UNIQUE(grant_id));
            CREATE TABLE IF NOT EXISTS graph_owner_issue_intents_v1 (
                bot TEXT NOT NULL, persona TEXT NOT NULL,
                operation_id TEXT NOT NULL, grant_digest TEXT NOT NULL,
                fence_attempt_id TEXT NOT NULL UNIQUE,
                requirements_json TEXT NOT NULL, anchor_json TEXT NOT NULL,
                graph_revision INTEGER NOT NULL, graph_epoch INTEGER NOT NULL,
                PRIMARY KEY(bot,persona,operation_id,grant_digest));
            CREATE TABLE IF NOT EXISTS graph_owner_issue_fences_v1 (
                bot TEXT NOT NULL, persona TEXT NOT NULL,
                operation_id TEXT NOT NULL, permit_json TEXT NOT NULL,
                pre_graph_revision INTEGER NOT NULL, pre_graph_epoch INTEGER NOT NULL,
                post_graph_revision INTEGER NOT NULL, post_graph_epoch INTEGER NOT NULL,
                finish_request_id TEXT NOT NULL, finish_request_digest TEXT NOT NULL,
                PRIMARY KEY(bot,persona));
            CREATE TABLE IF NOT EXISTS graph_owner_issue_rejections_v1 (
                bot TEXT NOT NULL, persona TEXT NOT NULL,
                operation_id TEXT NOT NULL, grant_digest TEXT NOT NULL,
                status TEXT NOT NULL CHECK(status='rejected_no_commit'),
                permit_json TEXT NOT NULL,
                graph_revision INTEGER NOT NULL, graph_epoch INTEGER NOT NULL,
                finish_request_id TEXT NOT NULL, finish_request_digest TEXT NOT NULL,
                PRIMARY KEY(bot,persona,operation_id,grant_digest),
                FOREIGN KEY(bot,persona,operation_id,grant_digest)
                    REFERENCES graph_owner_issue_intents_v1(
                        bot,persona,operation_id,grant_digest));
            CREATE TABLE IF NOT EXISTS graph_owner_revoke_intents_v1 (
                bot TEXT NOT NULL, persona TEXT NOT NULL,
                operation_id TEXT NOT NULL, request_digest TEXT NOT NULL,
                operation_json TEXT NOT NULL, pending_receipt_json TEXT NOT NULL,
                attempt_id TEXT NOT NULL UNIQUE,
                requirements_json TEXT NOT NULL, anchor_json TEXT NOT NULL,
                pre_graph_revision INTEGER NOT NULL,
                pre_graph_epoch INTEGER NOT NULL,
                pre_access_epoch INTEGER NOT NULL,
                permit_json TEXT, finish_request_id TEXT,
                finish_request_digest TEXT,
                state TEXT NOT NULL CHECK(state IN ('prepared','committed')),
                PRIMARY KEY(bot,persona,operation_id));
            CREATE TABLE IF NOT EXISTS graph_owner_revoke_operations_v1 (
                bot TEXT NOT NULL, persona TEXT NOT NULL,
                operation_id TEXT NOT NULL, request_digest TEXT NOT NULL,
                grant_id TEXT NOT NULL, grant_digest TEXT NOT NULL,
                graph_incarnation TEXT NOT NULL,
                previous_grant_digest TEXT NOT NULL,
                graph_access_epoch INTEGER NOT NULL,
                graph_epoch INTEGER NOT NULL,
                graph_receipt_digest TEXT NOT NULL, proof_json TEXT NOT NULL,
                fence_attempt_id TEXT NOT NULL,
                finish_request_id TEXT NOT NULL,
                finish_request_digest TEXT NOT NULL,
                PRIMARY KEY(bot,persona), UNIQUE(operation_id));
            CREATE TABLE IF NOT EXISTS graph_role_init_intents_v1 (
                bot TEXT NOT NULL, persona TEXT NOT NULL,
                operation_id TEXT NOT NULL, input_digest TEXT NOT NULL,
                fence_attempt_id TEXT NOT NULL UNIQUE,
                requirements_json TEXT NOT NULL, anchor_json TEXT NOT NULL,
                graph_revision INTEGER NOT NULL, graph_epoch INTEGER NOT NULL,
                PRIMARY KEY(bot,persona));
            CREATE TABLE IF NOT EXISTS graph_role_init_request_proofs_v1 (
                bot TEXT NOT NULL, persona TEXT NOT NULL,
                operation_id TEXT NOT NULL, request_digest TEXT NOT NULL,
                input_digest TEXT NOT NULL,
                PRIMARY KEY(bot,persona),
                FOREIGN KEY(bot,persona) REFERENCES graph_role_init_intents_v1(bot,persona));
            CREATE TRIGGER IF NOT EXISTS graph_role_init_request_proof_no_update_v1
                BEFORE UPDATE ON graph_role_init_request_proofs_v1
                BEGIN SELECT RAISE(ABORT, 'role request proof is immutable'); END;
            CREATE TRIGGER IF NOT EXISTS graph_role_init_request_proof_no_delete_v1
                BEFORE DELETE ON graph_role_init_request_proofs_v1
                BEGIN SELECT RAISE(ABORT, 'role request proof is immutable'); END;
            CREATE TABLE IF NOT EXISTS graph_role_init_receipts_v1 (
                bot TEXT NOT NULL, persona TEXT NOT NULL,
                operation_id TEXT NOT NULL, input_digest TEXT NOT NULL,
                permit_json TEXT NOT NULL, receipt_json TEXT NOT NULL,
                pre_graph_revision INTEGER NOT NULL, pre_graph_epoch INTEGER NOT NULL,
                post_graph_revision INTEGER NOT NULL, post_graph_epoch INTEGER NOT NULL,
                finish_request_id TEXT NOT NULL, finish_request_digest TEXT NOT NULL,
                PRIMARY KEY(bot,persona),
                FOREIGN KEY(bot,persona) REFERENCES graph_role_init_intents_v1(bot,persona));
            CREATE TABLE IF NOT EXISTS graph_role_init_rejections_v1 (
                bot TEXT NOT NULL, persona TEXT NOT NULL,
                operation_id TEXT NOT NULL,
                status TEXT NOT NULL CHECK(status='rejected_no_commit'),
                permit_json TEXT NOT NULL,
                graph_revision INTEGER NOT NULL, graph_epoch INTEGER NOT NULL,
                finish_request_id TEXT NOT NULL,
                finish_request_digest TEXT NOT NULL,
                PRIMARY KEY(bot,persona),
                FOREIGN KEY(bot,persona) REFERENCES graph_role_init_intents_v1(bot,persona));
            CREATE TRIGGER IF NOT EXISTS graph_role_init_rejection_no_update_v1
                BEFORE UPDATE ON graph_role_init_rejections_v1
                BEGIN SELECT RAISE(ABORT, 'role rejection is immutable'); END;
            CREATE TRIGGER IF NOT EXISTS graph_role_init_rejection_no_delete_v1
                BEFORE DELETE ON graph_role_init_rejections_v1
                BEGIN SELECT RAISE(ABORT, 'role rejection is immutable'); END;
            CREATE TABLE IF NOT EXISTS graph_scene_binding_intents_v1 (
                bot TEXT NOT NULL, persona TEXT NOT NULL,
                operation_id TEXT NOT NULL, input_digest TEXT NOT NULL,
                binding_id TEXT NOT NULL, fence_attempt_id TEXT NOT NULL UNIQUE,
                requirements_json TEXT NOT NULL, anchor_json TEXT NOT NULL,
                graph_revision INTEGER NOT NULL, graph_epoch INTEGER NOT NULL,
                PRIMARY KEY(bot,persona,operation_id));
            CREATE TABLE IF NOT EXISTS graph_scene_binding_request_proofs_v1 (
                bot TEXT NOT NULL, persona TEXT NOT NULL,
                operation_id TEXT NOT NULL, request_digest TEXT NOT NULL,
                principal_json TEXT NOT NULL, frozen_json TEXT NOT NULL,
                input_digest TEXT NOT NULL,
                PRIMARY KEY(bot,persona,operation_id),
                FOREIGN KEY(bot,persona,operation_id)
                    REFERENCES graph_scene_binding_intents_v1(bot,persona,operation_id));
            CREATE TRIGGER IF NOT EXISTS graph_scene_binding_request_proof_no_update_v1
                BEFORE UPDATE ON graph_scene_binding_request_proofs_v1
                BEGIN SELECT RAISE(ABORT, 'scene request proof is immutable'); END;
            CREATE TRIGGER IF NOT EXISTS graph_scene_binding_request_proof_no_delete_v1
                BEFORE DELETE ON graph_scene_binding_request_proofs_v1
                BEGIN SELECT RAISE(ABORT, 'scene request proof is immutable'); END;
            CREATE TABLE IF NOT EXISTS graph_scene_binding_receipts_v1 (
                bot TEXT NOT NULL, persona TEXT NOT NULL,
                operation_id TEXT NOT NULL, input_digest TEXT NOT NULL,
                permit_json TEXT NOT NULL, receipt_json TEXT NOT NULL,
                pre_graph_revision INTEGER NOT NULL, pre_graph_epoch INTEGER NOT NULL,
                post_graph_revision INTEGER NOT NULL, post_graph_epoch INTEGER NOT NULL,
                finish_request_id TEXT NOT NULL, finish_request_digest TEXT NOT NULL,
                PRIMARY KEY(bot,persona,operation_id),
                FOREIGN KEY(bot,persona,operation_id)
                    REFERENCES graph_scene_binding_intents_v1(bot,persona,operation_id));
            CREATE TABLE IF NOT EXISTS graph_scene_binding_rejections_v1 (
                bot TEXT NOT NULL, persona TEXT NOT NULL,
                operation_id TEXT NOT NULL,
                status TEXT NOT NULL CHECK(status='rejected_no_commit'),
                permit_json TEXT NOT NULL,
                graph_revision INTEGER NOT NULL, graph_epoch INTEGER NOT NULL,
                finish_request_id TEXT NOT NULL,
                finish_request_digest TEXT NOT NULL,
                PRIMARY KEY(bot,persona,operation_id),
                FOREIGN KEY(bot,persona,operation_id)
                    REFERENCES graph_scene_binding_intents_v1(bot,persona,operation_id));
            CREATE TRIGGER IF NOT EXISTS graph_scene_binding_rejection_no_update_v1
                BEFORE UPDATE ON graph_scene_binding_rejections_v1
                BEGIN SELECT RAISE(ABORT, 'scene rejection is immutable'); END;
            CREATE TRIGGER IF NOT EXISTS graph_scene_binding_rejection_no_delete_v1
                BEFORE DELETE ON graph_scene_binding_rejections_v1
                BEGIN SELECT RAISE(ABORT, 'scene rejection is immutable'); END;
            CREATE TABLE IF NOT EXISTS graph_bundle_fences_v2 (
                bot TEXT NOT NULL, persona TEXT NOT NULL,
                operation_id TEXT NOT NULL, digest TEXT NOT NULL,
                permit_json TEXT NOT NULL,
                pre_graph_revision INTEGER NOT NULL,
                pre_graph_epoch INTEGER NOT NULL,
                post_graph_revision INTEGER NOT NULL,
                post_graph_epoch INTEGER NOT NULL,
                finish_request_id TEXT NOT NULL,
                finish_request_digest TEXT NOT NULL,
                PRIMARY KEY(bot,persona,operation_id));
            CREATE TABLE IF NOT EXISTS graph_bundle_intents_v2 (
                bot TEXT NOT NULL, persona TEXT NOT NULL,
                operation_id TEXT NOT NULL, digest TEXT NOT NULL,
                fence_attempt_id TEXT NOT NULL UNIQUE,
                requirements_json TEXT NOT NULL, anchor_json TEXT NOT NULL,
                graph_revision INTEGER NOT NULL, graph_epoch INTEGER NOT NULL,
                PRIMARY KEY(bot,persona,operation_id));
            CREATE TABLE IF NOT EXISTS graph_first_ingress_c02_candidates_v1 (
                bot TEXT NOT NULL, persona TEXT NOT NULL,
                operation_id TEXT NOT NULL,
                schema TEXT NOT NULL CHECK(schema='sylanne.first-ingress-c02-candidate.v1'),
                bundle_digest TEXT NOT NULL,
                fence_attempt_id TEXT NOT NULL,
                bundle_json TEXT NOT NULL,
                evidence_json TEXT NOT NULL,
                PRIMARY KEY(bot,persona,operation_id),
                FOREIGN KEY(bot,persona,operation_id)
                    REFERENCES graph_bundle_intents_v2(bot,persona,operation_id));
            CREATE TABLE IF NOT EXISTS graph_bundle_rejections_v2 (
                bot TEXT NOT NULL, persona TEXT NOT NULL,
                operation_id TEXT NOT NULL, digest TEXT NOT NULL,
                status TEXT NOT NULL CHECK(status='rejected_no_commit'),
                permit_json TEXT NOT NULL,
                graph_revision INTEGER NOT NULL, graph_epoch INTEGER NOT NULL,
                finish_request_id TEXT NOT NULL,
                finish_request_digest TEXT NOT NULL,
                PRIMARY KEY(bot,persona,operation_id),
                FOREIGN KEY(bot,persona,operation_id)
                    REFERENCES graph_bundle_intents_v2(bot,persona,operation_id));
            CREATE TABLE IF NOT EXISTS graph_first_ingress_intents_v2 (
                bot TEXT NOT NULL, persona TEXT NOT NULL,
                operation_id TEXT NOT NULL,
                identity_json TEXT NOT NULL,
                learned_at REAL NOT NULL,
                deadline_utc REAL NOT NULL,
                monotonic_deadline REAL NOT NULL,
                fence_attempt_id TEXT NOT NULL UNIQUE,
                requirements_json TEXT NOT NULL,
                anchor_json TEXT NOT NULL,
                graph_revision INTEGER NOT NULL,
                graph_epoch INTEGER NOT NULL,
                PRIMARY KEY(bot,persona,operation_id));
            CREATE TABLE IF NOT EXISTS graph_job_acquire_intents_v2 (
                bot TEXT NOT NULL, persona TEXT NOT NULL,
                acquire_operation_id TEXT NOT NULL, request_digest TEXT NOT NULL,
                job_id TEXT NOT NULL, original_operation_id TEXT NOT NULL,
                actor TEXT NOT NULL, fixed_now_utc TEXT NOT NULL,
                lease_seconds INTEGER NOT NULL, expected_job_revision INTEGER NOT NULL,
                expected_fence INTEGER NOT NULL, expected_cancel_epoch INTEGER NOT NULL,
                fence_attempt_id TEXT NOT NULL UNIQUE,
                requirements_json TEXT NOT NULL, anchor_json TEXT NOT NULL,
                graph_revision INTEGER NOT NULL, graph_epoch INTEGER NOT NULL,
                PRIMARY KEY(bot,persona,acquire_operation_id));
            CREATE TABLE IF NOT EXISTS graph_job_acquire_receipts_v2 (
                bot TEXT NOT NULL, persona TEXT NOT NULL,
                acquire_operation_id TEXT NOT NULL, request_digest TEXT NOT NULL,
                job_json TEXT NOT NULL, permit_json TEXT NOT NULL,
                pre_graph_revision INTEGER NOT NULL, pre_graph_epoch INTEGER NOT NULL,
                post_graph_revision INTEGER NOT NULL, post_graph_epoch INTEGER NOT NULL,
                finish_request_id TEXT NOT NULL, finish_request_digest TEXT NOT NULL,
                PRIMARY KEY(bot,persona,acquire_operation_id),
                FOREIGN KEY(bot,persona,acquire_operation_id)
                    REFERENCES graph_job_acquire_intents_v2(bot,persona,acquire_operation_id));
            CREATE TABLE IF NOT EXISTS graph_job_acquire_rejections_v2 (
                bot TEXT NOT NULL, persona TEXT NOT NULL,
                acquire_operation_id TEXT NOT NULL,
                status TEXT NOT NULL CHECK(status='rejected_no_commit'),
                permit_json TEXT NOT NULL,
                graph_revision INTEGER NOT NULL, graph_epoch INTEGER NOT NULL,
                finish_request_id TEXT NOT NULL, finish_request_digest TEXT NOT NULL,
                PRIMARY KEY(bot,persona,acquire_operation_id),
                FOREIGN KEY(bot,persona,acquire_operation_id)
                    REFERENCES graph_job_acquire_intents_v2(bot,persona,acquire_operation_id));
            CREATE TRIGGER IF NOT EXISTS graph_job_acquire_intent_no_update_v2
                BEFORE UPDATE ON graph_job_acquire_intents_v2
                BEGIN SELECT RAISE(ABORT, 'job acquire intent is immutable'); END;
            CREATE TRIGGER IF NOT EXISTS graph_job_acquire_intent_no_delete_v2
                BEFORE DELETE ON graph_job_acquire_intents_v2
                BEGIN SELECT RAISE(ABORT, 'job acquire intent is immutable'); END;
            CREATE TRIGGER IF NOT EXISTS graph_job_acquire_receipt_no_update_v2
                BEFORE UPDATE ON graph_job_acquire_receipts_v2
                BEGIN SELECT RAISE(ABORT, 'job acquire receipt is immutable'); END;
            CREATE TRIGGER IF NOT EXISTS graph_job_acquire_receipt_no_delete_v2
                BEFORE DELETE ON graph_job_acquire_receipts_v2
                BEGIN SELECT RAISE(ABORT, 'job acquire receipt is immutable'); END;
            CREATE TRIGGER IF NOT EXISTS graph_job_acquire_rejection_no_update_v2
                BEFORE UPDATE ON graph_job_acquire_rejections_v2
                BEGIN SELECT RAISE(ABORT, 'job acquire rejection is immutable'); END;
            CREATE TRIGGER IF NOT EXISTS graph_job_acquire_rejection_no_delete_v2
                BEFORE DELETE ON graph_job_acquire_rejections_v2
                BEGIN SELECT RAISE(ABORT, 'job acquire rejection is immutable'); END;
            CREATE TRIGGER IF NOT EXISTS graph_first_ingress_intent_no_update_v2
                BEFORE UPDATE ON graph_first_ingress_intents_v2
                BEGIN SELECT RAISE(ABORT, 'first ingress intent is immutable'); END;
            CREATE TRIGGER IF NOT EXISTS graph_first_ingress_intent_no_delete_v2
                BEFORE DELETE ON graph_first_ingress_intents_v2
                BEGIN SELECT RAISE(ABORT, 'first ingress intent is immutable'); END;
            CREATE TABLE IF NOT EXISTS graph_first_ingress_rejections_v2 (
                bot TEXT NOT NULL, persona TEXT NOT NULL,
                operation_id TEXT NOT NULL,
                status TEXT NOT NULL CHECK(status='rejected_no_commit'),
                permit_json TEXT NOT NULL,
                graph_revision INTEGER NOT NULL,
                graph_epoch INTEGER NOT NULL,
                finish_request_id TEXT NOT NULL,
                finish_request_digest TEXT NOT NULL,
                PRIMARY KEY(bot,persona,operation_id),
                FOREIGN KEY(bot,persona,operation_id)
                    REFERENCES graph_first_ingress_intents_v2(bot,persona,operation_id));
            CREATE TRIGGER IF NOT EXISTS graph_first_ingress_rejection_no_update_v2
                BEFORE UPDATE ON graph_first_ingress_rejections_v2
                BEGIN SELECT RAISE(ABORT, 'first ingress rejection is immutable'); END;
            CREATE TRIGGER IF NOT EXISTS graph_first_ingress_rejection_no_delete_v2
                BEFORE DELETE ON graph_first_ingress_rejections_v2
                BEGIN SELECT RAISE(ABORT, 'first ingress rejection is immutable'); END;
            CREATE TRIGGER IF NOT EXISTS graph_bundle_rejection_no_update_v2
                BEFORE UPDATE ON graph_bundle_rejections_v2
                BEGIN SELECT RAISE(ABORT, 'bundle rejection is immutable'); END;
            CREATE TRIGGER IF NOT EXISTS graph_bundle_rejection_no_delete_v2
                BEFORE DELETE ON graph_bundle_rejections_v2
                BEGIN SELECT RAISE(ABORT, 'bundle rejection is immutable'); END;
            CREATE TRIGGER IF NOT EXISTS graph_bundle_intent_no_update_v2
                BEFORE UPDATE ON graph_bundle_intents_v2
                BEGIN SELECT RAISE(ABORT, 'bundle intent is immutable'); END;
            CREATE TRIGGER IF NOT EXISTS graph_bundle_intent_no_delete_v2
                BEFORE DELETE ON graph_bundle_intents_v2
                BEGIN SELECT RAISE(ABORT, 'bundle intent is immutable'); END;
            CREATE TRIGGER IF NOT EXISTS graph_first_ingress_c02_candidate_no_update_v1
                BEFORE UPDATE ON graph_first_ingress_c02_candidates_v1
                BEGIN SELECT RAISE(ABORT, 'C02 candidate is immutable'); END;
            CREATE TABLE IF NOT EXISTS graph_namespace_provision_intents_v2 (
                bot TEXT NOT NULL, persona TEXT NOT NULL,
                operation_id TEXT NOT NULL, digest TEXT NOT NULL,
                identity_json TEXT NOT NULL, genesis_request_id TEXT NOT NULL,
                fence_attempt_id TEXT NOT NULL, graph_incarnation TEXT NOT NULL,
                anchor_json TEXT,
                PRIMARY KEY(bot,persona),
                UNIQUE(genesis_request_id), UNIQUE(fence_attempt_id),
                UNIQUE(graph_incarnation));
            CREATE TRIGGER IF NOT EXISTS graph_namespace_provision_intent_no_delete_v2
                BEFORE DELETE ON graph_namespace_provision_intents_v2
                BEGIN SELECT RAISE(ABORT, 'provisioning intent is immutable'); END;
            CREATE TRIGGER IF NOT EXISTS graph_namespace_provision_intent_anchor_once_v2
                BEFORE UPDATE ON graph_namespace_provision_intents_v2
                WHEN OLD.anchor_json IS NOT NULL OR NEW.anchor_json IS NULL
                  OR NEW.bot != OLD.bot OR NEW.persona != OLD.persona
                  OR NEW.operation_id != OLD.operation_id OR NEW.digest != OLD.digest
                  OR NEW.identity_json != OLD.identity_json
                  OR NEW.genesis_request_id != OLD.genesis_request_id
                  OR NEW.fence_attempt_id != OLD.fence_attempt_id
                  OR NEW.graph_incarnation != OLD.graph_incarnation
                BEGIN SELECT RAISE(ABORT, 'provisioning intent is immutable'); END;
        """)
        # Existing local graphs predate the finish acknowledgement. A missing
        # acknowledgement is deliberately replayed once after restart.
        columns = {row[1] for row in self._db.execute(
            "PRAGMA table_info(graph_d13_precompression_attempts_v2)")}
        if "finish_confirmed" not in columns:
            self._db.execute(
                "ALTER TABLE graph_d13_precompression_attempts_v2 ADD COLUMN "
                "finish_confirmed INTEGER NOT NULL DEFAULT 0 "
                "CHECK(finish_confirmed IN (0,1))")
        if "rejected_json" not in columns:
            self._db.execute(
                "ALTER TABLE graph_d13_precompression_attempts_v2 "
                "ADD COLUMN rejected_json TEXT")

    @staticmethod
    def _catalog_row(spec):
        return (
            spec.name,
            canonical_json(sorted(spec.owner_kinds)),
            spec.storage_role,
            int(spec.immutable),
            spec.schema_version,
        )

    def _check_catalog(self):
        expected = tuple(self._catalog_row(spec) for spec in self._registry.specs)
        actual = tuple(self._db.execute(
            "SELECT name,owner_kinds,storage_role,immutable,schema_version "
            "FROM graph_type_catalog ORDER BY name"
        ).fetchall())
        authority = tuple(self._db.execute(
            "SELECT name,writer_domain,schema_hash FROM graph_type_authority ORDER BY name"
        ).fetchall())
        expected_authority = tuple((spec.name, spec.writer_domain or "",
                                    spec.schema_hash or "") for spec in self._registry.specs)
        # The reserved Owner type gains one exact terminal rev2 value. Migrate
        # only the prior reviewed hash; no other writer identity may drift.
        old_owner_hash = hashlib.sha256(
            b"sylanne3.graph.owner_grant.v1:strict:pending").hexdigest()
        old_authority = tuple(
            (name, writer, old_owner_hash if name == OWNER_GRANT_TYPE else digest)
            for name, writer, digest in expected_authority)
        if (actual == expected and authority == old_authority
                and authority != expected_authority):
            rows = self._db.execute(
                "SELECT token,revision,value,valid FROM graph_atoms WHERE type_name=?",
                (OWNER_GRANT_TYPE,),
            ).fetchall()
            for token, revision, raw, valid in rows:
                value = json.loads(raw)
                validate_owner_grant_v1(value)
                history = self._db.execute(
                    "SELECT revision,value,valid,event_session,event_id "
                    "FROM graph_history WHERE token=?", (token,),
                ).fetchall()
                if (canonical_json(value) != raw or revision != 1 or valid != 1
                        or value.get("state") != "pending_authority"
                        or value.get("grant_revision") != 1
                        or history != [(1, raw, 1, "owner-authorization-v1",
                                        value["issue_operation_id"])]):
                    raise ValueError("Owner grant catalogue migration requires rev1")
            self._db.execute(
                "UPDATE graph_type_authority SET schema_hash=? WHERE name=? AND schema_hash=?",
                (dict((name, digest) for name, _, digest in expected_authority)[OWNER_GRANT_TYPE],
                 OWNER_GRANT_TYPE, old_owner_hash),
            )
            authority = expected_authority
        # These additions have reviewed append-only identities.  Every
        # previously installed row must still match exactly, including its
        # owner, storage, writer domain and schema hash.
        append_types = frozenset({
            "runtime.role_resources.v1", "d06.recollection_projection.v1",
            "d12.active_scheme_head.v1", "d07.concern_round.v1",
            "d08.natural_expression_plan.v2",
            "d04.encoding_baseline.v2", "d04.encoding_projection_receipt.v2",
            "memory.source.v2",
        })
        expected_names = {row[0] for row in expected}
        missing = expected_names - {row[0] for row in actual}
        authority_missing = expected_names - {row[0] for row in authority}
        if (actual and authority and missing and missing == authority_missing
                and missing <= append_types
                and actual == tuple(row for row in expected if row[0] not in missing)
                and authority == tuple(row for row in expected_authority
                                       if row[0] not in missing)
                and all(not self._db.execute(
                    "SELECT 1 FROM graph_atoms WHERE type_name=? LIMIT 1",
                    (name,),
                ).fetchone() for name in missing)):
            self._db.executemany(
                "INSERT INTO graph_type_catalog"
                "(name,owner_kinds,storage_role,immutable,schema_version) "
                "VALUES(?,?,?,?,?)",
                (row for row in expected if row[0] in missing),
            )
            self._db.executemany(
                "INSERT INTO graph_type_authority"
                "(name,writer_domain,schema_hash) VALUES(?,?,?)",
                (row for row in expected_authority if row[0] in missing),
            )
            actual = expected
            authority = expected_authority
        if actual and actual != expected:
            raise ValueError("graph type catalog does not match this registry")
        if not actual:
            self._db.executemany(
                "INSERT INTO graph_type_catalog(name,owner_kinds,storage_role,immutable,schema_version) "
                "VALUES(?,?,?,?,?)", expected
            )
        if authority and authority != expected_authority:
            raise ValueError("graph type authority catalogue does not match this registry; migration required")
        if not authority:
            # Existing nonempty graphs have no writer provenance. Only a separate
            # reviewed migration may grant their types production write authority.
            count = self._db.execute("SELECT COUNT(*) FROM graph_atoms").fetchone()[0]
            if count and any(spec.writer_domain for spec in self._registry.specs):
                raise ValueError("legacy graph requires explicit writer-authority migration")
            self._db.executemany(
                "INSERT INTO graph_type_authority(name,writer_domain,schema_hash) VALUES(?,?,?)",
                expected_authority,
            )

    def _validate_key(self, key: AtomKey):
        if not isinstance(key, AtomKey):
            raise TypeError("graph key must be AtomKey")
        spec = self._registry.spec(key.type_name)
        if key.owner.kind not in spec.owner_kinds:
            raise ValueError(
                f"type {spec.name!r} does not support owner kind {key.owner.kind!r}"
            )
        return spec

    @staticmethod
    def _namespace(key: AtomKey):
        return key.owner.bot, key.owner.persona

    def _require_coordinator(self, capability):
        if isinstance(self, ProductionGraphStore) and (
                capability is None or capability is not getattr(self, "_coordinator_capability", None)):
            raise PermissionError("production graph access requires GraphCoordinator")

    def _require_recovery_capability(self, capability):
        if (capability is None or
                capability is not getattr(self, "_coordinator_capability", None)):
            raise PermissionError("graph recovery metadata requires GraphCoordinator")

    @staticmethod
    def _recovery_payload(requirements):
        if type(requirements) is not SnapshotRequirementsV2:
            raise TypeError("requirements must be SnapshotRequirementsV2")
        return canonical_json(asdict(requirements))

    @staticmethod
    def _decode_recovery(row, namespace):
        if row is None:
            return None
        schema, encoded, revision = row
        data = json.loads(encoded)
        expected = {field.name for field in fields(SnapshotRequirementsV2)}
        if (schema != "sylanne3.authority.v2" or not isinstance(data, dict)
                or set(data) != expected or not isinstance(data["namespace"], dict)
                or set(data["namespace"]) != {"bot_id", "persona_id"}):
            raise ValueError("incompatible graph recovery metadata")
        data["namespace"] = NamespaceId(**data["namespace"])
        result = GraphRecoveryMetadataV2(SnapshotRequirementsV2(**data), revision)
        if result.requirements.namespace != namespace:
            raise ValueError("graph recovery metadata crosses namespace")
        return result

    def _recovery_row(self, namespace):
        return self._db.execute(
            "SELECT schema,requirements_json,graph_revision "
            "FROM graph_recovery_metadata_v2 WHERE bot=? AND persona=?",
            namespace.as_tuple,
        ).fetchone()

    def _has_namespace_history(self, namespace, *, provision_intent=None):
        """Reject history in this namespace and unowned legacy records.

        Some old tables omit namespace columns but carry a lease, quote or
        canonical graph token. An owner is accepted only when that other
        namespace already has durable recovery metadata; an orphan remains a
        global blocker rather than being assigned to an arbitrary new role.
        """
        def sealed_elsewhere(bot, persona):
            try:
                owner = NamespaceId(bot, persona)
                return (owner != namespace and
                        self._decode_recovery(self._recovery_row(owner), owner) is not None)
            except (TypeError, ValueError):
                return False

        def lease_owner(lease_id):
            row = self._db.execute(
                "SELECT bot_id,persona_id FROM runtime_budget_leases WHERE lease_id=?",
                (lease_id,),
            ).fetchone()
            return row if row is not None and sealed_elsewhere(*row) else None

        def graph_tokens_owned_elsewhere(table):
            for dependent, dependency in self._db.execute(
                    f"SELECT dependent_token,dependency_token FROM {table}"):
                try:
                    left = AtomKey.from_token(dependent)
                    right = AtomKey.from_token(dependency)
                    left_owner = (left.owner.bot, left.owner.persona)
                    right_owner = (right.owner.bot, right.owner.persona)
                except (TypeError, ValueError):
                    return False
                if (left_owner != right_owner
                        or not sealed_elsewhere(*left_owner)):
                    return False
                row = self._db.execute(
                    "SELECT bot,persona FROM graph_atoms WHERE token=?",
                    (dependent,),
                ).fetchone()
                if row != left_owner:
                    return False
            return True

        globally_unowned = {
            "runtime_character_clocks", "runtime_clock_operations",
            "runtime_deadlines", "runtime_deadline_operations",
        }
        for (table,) in self._db.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"):
            if table == "graph_namespace_provision_intents_v2" and provision_intent is not None:
                row = self._db.execute(
                    "SELECT operation_id,digest FROM graph_namespace_provision_intents_v2 "
                    "WHERE bot=? AND persona=?", namespace.as_tuple).fetchone()
                if row != provision_intent:
                    return True
                continue
            if table in {"graph_recovery_metadata_v2", "graph_type_catalog",
                         "graph_type_authority"}:
                continue
            quoted = '"' + table.replace('"', '""') + '"'
            if table in globally_unowned:
                if self._db.execute(f"SELECT 1 FROM {quoted} LIMIT 1").fetchone():
                    return True
                continue
            if table in {"graph_dependencies", "graph_dependency_edges"}:
                if not graph_tokens_owned_elsewhere(table):
                    return True
                continue
            if table == "runtime_budget_reservations":
                if any(lease_owner(row[0]) is None for row in self._db.execute(
                        "SELECT lease_id FROM runtime_budget_reservations")):
                    return True
                continue
            if table == "runtime_budget_grants":
                for lease_id, version, payload in self._db.execute(
                        "SELECT lease_id,version,grant_json FROM runtime_budget_grants"):
                    owner = lease_owner(lease_id)
                    try:
                        grant = json.loads(payload)
                    except (TypeError, ValueError):
                        return True
                    if (owner is None or type(grant) is not dict
                            or (grant.get("bot_id"), grant.get("persona_id")) != owner
                            or grant.get("lease_id") != lease_id
                            or grant.get("version") != version):
                        return True
                continue
            if table == "runtime_resource_quotes":
                for quote_id, version, payload in self._db.execute(
                        "SELECT quote_id,version,quote_json FROM runtime_resource_quotes"):
                    try:
                        quote = json.loads(payload)
                    except (TypeError, ValueError):
                        return True
                    if (type(quote) is not dict
                            or quote.get("quote_id") != quote_id
                            or quote.get("version") != version
                            or (quote.get("bot_id"), quote.get("persona_id"))
                            != lease_owner(quote.get("parent_budget_lease_ref"))):
                        return True
                continue
            if table == "runtime_resource_outcomes":
                for quote_id, operation_id, version, payload in self._db.execute(
                        "SELECT quote_id,operation_id,version,outcome_json "
                        "FROM runtime_resource_outcomes"):
                    try:
                        outcome = json.loads(payload)
                    except (TypeError, ValueError):
                        return True
                    if (type(outcome) is not dict
                            or outcome.get("quote_id") != quote_id
                            or outcome.get("operation_id") != operation_id
                            or outcome.get("version") != version):
                        return True
                    quotes = self._db.execute(
                        "SELECT quote_json FROM runtime_resource_quotes WHERE quote_id=?",
                        (quote_id,),
                    ).fetchall()
                    matched = False
                    for (quote_payload,) in quotes:
                        try:
                            quote = json.loads(quote_payload)
                        except (TypeError, ValueError):
                            return True
                        if (type(quote) is dict
                                and quote.get("operation_id") == operation_id
                                and (quote.get("bot_id"), quote.get("persona_id"))
                                == (outcome.get("bot_id"), outcome.get("persona_id"))
                                and sealed_elsewhere(quote.get("bot_id"),
                                                     quote.get("persona_id"))):
                            matched = True
                            break
                    if not matched:
                        return True
                continue
            columns = {row[1] for row in self._db.execute(
                f"PRAGMA table_info({quoted})")}
            if {"bot", "persona"}.issubset(columns):
                pair = ("bot", "persona")
            elif {"bot_id", "persona_id"}.issubset(columns):
                pair = ("bot_id", "persona_id")
            elif {"event_bot", "event_persona"}.issubset(columns):
                pair = ("event_bot", "event_persona")
            else:
                if self._db.execute(f"SELECT 1 FROM {quoted} LIMIT 1").fetchone():
                    return True
                continue
            if self._db.execute(
                    f'SELECT 1 FROM {quoted} WHERE {pair[0]}=? AND {pair[1]}=? LIMIT 1',
                    namespace.as_tuple).fetchone():
                return True
        return False

    def graph_recovery_metadata(self, namespace, *, _capability=None):
        """Read stored v2 requirements, never derive them from a current anchor."""
        self._require_recovery_capability(_capability)
        if type(namespace) is not NamespaceId:
            raise TypeError("namespace must be NamespaceId")
        with self._lock:
            self._ensure_open()
            row = self._recovery_row(namespace)
            if row is None and self._has_namespace_history(namespace):
                raise RuntimeError("namespace has unsealed business state")
            return self._decode_recovery(row, namespace)

    def _install_graph_recovery_genesis_locked(self, requirements, *,
                                               _capability=None, provision_intent=None):
        """Stage genesis in the caller's existing business SQL transaction."""
        self._require_recovery_capability(_capability)
        encoded = self._recovery_payload(requirements)
        if (requirements.activation_generation == 0 or requirements.revocation_epoch != 0
                or requirements.deletion_seq != 0 or requirements.execution_seq != 0):
            raise ValueError("graph genesis requires an active zero-head snapshot")
        with self._lock:
            self._ensure_open()
            if not self._db.in_transaction:
                raise RuntimeError("graph genesis requires an active SQL transaction")
            if self._recovery_row(requirements.namespace) is not None:
                raise StaleRead("graph recovery metadata already installed")
            if self._has_namespace_history(
                    requirements.namespace, provision_intent=provision_intent):
                raise RuntimeError("namespace has unsealed business state")
            self._db.execute(
                "INSERT INTO graph_recovery_metadata_v2"
                "(bot,persona,schema,requirements_json,graph_revision) "
                "VALUES(?,?,?,?,0)",
                requirements.namespace.as_tuple + (requirements.schema, encoded),
            )
            return GraphRecoveryMetadataV2(requirements, 0)

    def install_graph_recovery_genesis(self, requirements, *, _capability=None):
        """Install explicit zero-head metadata only for an empty namespace."""
        self._require_recovery_capability(_capability)
        with self._lock:
            self._ensure_open()
            self._db.execute("BEGIN IMMEDIATE")
            try:
                result = self._install_graph_recovery_genesis_locked(
                    requirements, _capability=_capability)
                self._db.execute("COMMIT")
            except BaseException:
                self._db.execute("ROLLBACK")
                raise
        return result

    def cas_c09_recovery_identity_v1(self, expected, replacement, *, storage_reader, core,
                                     credential, _capability=None):
        """Apply the signed current C09 transition; ordinary CAS keeps its identity guard."""
        from .authority_service.c09_storage_control_v1 import C09StorageControlV1
        from .authority_service.core import AuthorityServiceCore
        from pathlib import Path
        self._require_recovery_capability(_capability)
        if (type(storage_reader) is not C09StorageControlV1 or type(core) is not AuthorityServiceCore
                or type(expected) is not GraphRecoveryMetadataV2
                or getattr(core, "_c09_storage_reader_v1", None) is not storage_reader):
            raise PermissionError("installed C09 recovery identity authority required")
        before = expected.requirements
        core._require(credential, "deletion", before.authority_namespace)
        context = storage_reader.read_verified_current_storage_v1()
        context.require_current("maintenance")
        if context.stage not in {"SWITCHED", "CLEANED"} or context.prepared_original is None:
            raise StaleRead("C09 current transition is not open for recovery identity")
        prepared = context.prepared_original
        members = {member["role"]: member for member in context.manifest["members"]}
        path = self._db.execute("PRAGMA database_list").fetchone()
        old = prepared["old_execution_head_original"]
        with core._lock:
            if core._db is None or not core._db.in_transaction:
                raise RuntimeError("C09 recovery identity needs actual Core and Graph transactions")
            anchor = core._anchor(core._db, before.authority_namespace,
                core._row(core._db, before.authority_namespace))
        if (path is None or str(Path(path[2]).resolve()) != members["graph"]["resolved_path"]
                or before.namespace != replacement.namespace
                or before.authority_id != replacement.authority_id or before.authority_id != core._id(core._db)
                or before.authority_namespace != replacement.authority_namespace
                or before.activation_generation != replacement.activation_generation
                or before.graph_incarnation != replacement.graph_incarnation
                or before.graph_incarnation != members["graph"]["incarnation_or_journal_id"]
                or before.execution_journal_id != old["journal_id"] or before.execution_seq > old["seq"]
                or (before.execution_seq == old["seq"] and before.execution_digest != old["digest"])
                or replacement.execution_journal_id != members["execution"]["incarnation_or_journal_id"]
                or (replacement.deletion_journal_id, replacement.deletion_seq, replacement.deletion_digest,
                    replacement.execution_journal_id, replacement.execution_seq, replacement.execution_digest,
                    replacement.revocation_epoch, replacement.activation_generation) != (
                    anchor.deletion_journal_id, anchor.deletion_seq, anchor.deletion_digest,
                    anchor.execution_journal_id, anchor.execution_seq, anchor.execution_digest,
                    anchor.revocation_epoch, anchor.activation_generation)
                or replacement.deletion_seq < before.deletion_seq
                or replacement.revocation_epoch < before.revocation_epoch):
            raise StaleRead("actual C09 signed identity transition differs from current stores")
        with self._lock:
            if not self._db.in_transaction:
                raise RuntimeError("C09 recovery identity needs current Graph transaction")
            changed = self._db.execute("UPDATE graph_recovery_metadata_v2 SET requirements_json=?,graph_revision=graph_revision+1 "
                "WHERE bot=? AND persona=? AND schema=? AND requirements_json=? AND graph_revision=?",
                (self._recovery_payload(replacement), *before.namespace.as_tuple, before.schema,
                    self._recovery_payload(before), expected.graph_revision)).rowcount
            if changed != 1:
                raise StaleRead("C09 recovery identity CAS changed")
            return GraphRecoveryMetadataV2(replacement, expected.graph_revision + 1)

    def cas_graph_recovery_metadata(self, expected, replacement, *, _capability=None):
        """Advance the namespace commit stamp inside the caller's SQL transaction."""
        self._require_recovery_capability(_capability)
        if type(expected) is not GraphRecoveryMetadataV2:
            raise TypeError("expected must be GraphRecoveryMetadataV2")
        encoded = self._recovery_payload(replacement)
        before = expected.requirements
        if (replacement.namespace != before.namespace
                or replacement.authority_id != before.authority_id
                or replacement.authority_namespace != before.authority_namespace
                or replacement.activation_generation != before.activation_generation
                or replacement.deletion_journal_id != before.deletion_journal_id
                or replacement.execution_journal_id != before.execution_journal_id
                or replacement.graph_incarnation != before.graph_incarnation):
            raise StaleRead("graph recovery identity changed")
        if (replacement.deletion_seq < before.deletion_seq
                or replacement.execution_seq < before.execution_seq
                or replacement.revocation_epoch < before.revocation_epoch):
            raise StaleRead("graph recovery watermark regressed")
        if ((replacement.deletion_seq == before.deletion_seq
             and replacement.deletion_digest != before.deletion_digest)
                or (replacement.execution_seq == before.execution_seq
                    and replacement.execution_digest != before.execution_digest)):
            raise StaleRead("graph recovery digest changed without journal advance")
        with self._lock:
            self._ensure_open()
            if not self._db.in_transaction:
                raise RuntimeError("graph recovery CAS requires an active SQL transaction")
            changed = self._db.execute(
                "UPDATE graph_recovery_metadata_v2 SET requirements_json=?,"
                "graph_revision=graph_revision+1 WHERE bot=? AND persona=? "
                "AND schema=? AND requirements_json=? AND graph_revision=?",
                (encoded, *before.namespace.as_tuple, before.schema,
                 self._recovery_payload(before), expected.graph_revision),
            ).rowcount
            if changed != 1:
                raise StaleRead("graph recovery metadata changed")
            return GraphRecoveryMetadataV2(replacement, expected.graph_revision + 1)

    def cas_graph_migration_recovery_metadata(
            self, expected, replacement, transfer_receipt, *, _capability=None):
        """CAS a migration target in the caller's transaction after trusted proof.

        Only the verifier bound when this store was opened may authenticate the
        transfer. It must perform any remote checks before this short local CAS.
        The caller owns the surrounding graph import, receipt, COMMIT/ROLLBACK.
        """
        self._require_recovery_capability(_capability)
        if type(expected) is not GraphRecoveryMetadataV2:
            raise TypeError("expected must be GraphRecoveryMetadataV2")
        encoded = self._recovery_payload(replacement)
        verifier = self._migration_transfer_verifier
        if verifier is None:
            raise RuntimeError("trusted migration transfer verifier is unavailable")
        proof = verifier.verify_local(transfer_receipt)
        if (type(proof) is not GraphMigrationVerifiedTransferV1
                or proof.source != expected or proof.target != replacement
                or proof.authority_phase != "target_recovering"):
            raise PermissionError("migration transfer proof does not match target recovery")
        before = expected.requirements
        if (replacement.namespace != before.namespace
                or replacement.authority_id != before.authority_id
                or replacement.authority_namespace != before.authority_namespace
                or replacement.deletion_journal_id != before.deletion_journal_id
                or replacement.execution_journal_id != before.execution_journal_id
                or replacement.activation_generation != before.activation_generation + 2
                or replacement.graph_incarnation == before.graph_incarnation):
            raise StaleRead("graph migration identity or generation changed")
        if (replacement.deletion_seq < before.deletion_seq
                or replacement.execution_seq < before.execution_seq
                or replacement.revocation_epoch <= before.revocation_epoch):
            raise StaleRead("graph migration watermark regressed")
        if ((replacement.deletion_seq == before.deletion_seq
             and replacement.deletion_digest != before.deletion_digest)
                or (replacement.execution_seq == before.execution_seq
                    and replacement.execution_digest != before.execution_digest)):
            raise StaleRead("graph migration digest changed without journal advance")
        with self._lock:
            self._ensure_open()
            if not self._db.in_transaction:
                raise RuntimeError("graph migration CAS requires an active SQL transaction")
            _assert_migration_owner_head_in_transaction(
                self._db, before.namespace, proof.owner_head)
            changed = self._db.execute(
                "UPDATE graph_recovery_metadata_v2 SET requirements_json=?,"
                "graph_revision=graph_revision+1 WHERE bot=? AND persona=? "
                "AND schema=? AND requirements_json=? AND graph_revision=?",
                (encoded, *before.namespace.as_tuple, before.schema,
                 self._recovery_payload(before), expected.graph_revision),
            ).rowcount
            if changed != 1:
                raise StaleRead("graph migration recovery metadata changed")
            return GraphRecoveryMetadataV2(replacement, expected.graph_revision + 1)

    def graph_epoch(self, bot, persona, *, _capability=None):
        self._require_coordinator(_capability)
        nonempty(bot, "bot")
        nonempty(persona, "persona")
        with self._lock:
            self._ensure_open()
            row = self._db.execute(
                "SELECT revision FROM graph_epochs WHERE bot=? AND persona=?", (bot, persona)
            ).fetchone()
            return NamespaceEpoch(bot, persona, row[0] if row else 0)

    def graph_snapshot(self, keys, *, _capability=None):
        self._require_coordinator(_capability)
        keys = tuple(keys)
        if len(set(keys)) != len(keys):
            raise ValueError("duplicate graph snapshot keys")
        for key in keys:
            self._validate_key(key)
        namespaces = tuple(dict.fromkeys(self._namespace(key) for key in keys))
        with self._lock:
            self._ensure_open()
            self._db.execute("BEGIN")
            try:
                atoms = []
                for key in keys:
                    self._assert_c09_key_not_erased(key)
                    row = self._db.execute(
                        "SELECT revision,value,valid FROM graph_atoms WHERE token=?", (key.token,)
                    ).fetchone()
                    atoms.append(
                        GraphAtom(key, row[0], json.loads(row[1]), bool(row[2]))
                        if row else GraphAtom(key, 0, {}, False)
                    )
                epochs = []
                for bot, persona in namespaces:
                    row = self._db.execute(
                        "SELECT revision FROM graph_epochs WHERE bot=? AND persona=?",
                        (bot, persona),
                    ).fetchone()
                    epochs.append(NamespaceEpoch(bot, persona, row[0] if row else 0))
                self._db.execute("COMMIT")
                return GraphSnapshot(tuple(atoms), tuple(epochs))
            except BaseException:
                self._db.execute("ROLLBACK")
                raise

    def _assert_c09_key_not_erased(self, key: AtomKey) -> None:
        """A C09 rebase tombstone permanently closes the old graph address."""
        if self._db.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' "
                "AND name='graph_c09_erased_keys_v1'").fetchone() is None:
            return
        if self._db.execute(
                "SELECT 1 FROM graph_c09_erased_keys_v1 "
                "WHERE bot=? AND persona=? AND key_digest=?",
                (*self._namespace(key), canonical_digest(key.token)),
        ).fetchone() is not None:
            raise PermissionError("C09 erased graph address cannot be reused or read raw")


    @staticmethod
    def _version_rows(encoded):
        return tuple(GraphVersion(AtomKey.from_token(token), revision)
                     for token, revision in json.loads(encoded))

    def graph_event_receipt(self, event, *, _capability=None):
        self._require_coordinator(_capability)
        if not isinstance(event, Event):
            raise TypeError('event must be Event')
        digest = event.digest
        scope = event.scope
        with self._lock:
            self._ensure_open()
            prior = self._db.execute(
                'SELECT digest,revisions,invalidated,epoch_revision FROM graph_events '
                'WHERE bot=? AND persona=? AND session=? AND event_id=?',
                (scope.bot, scope.persona, scope.session, event.event_id)).fetchone()
            if prior is None:
                return None
            if prior[0] != digest:
                raise EventConflict('event ID reused with different content')
            return GraphReceipt('duplicate', self._version_rows(prior[1]),
                self._version_rows(prior[2]), NamespaceEpoch(scope.bot, scope.persona, prior[3]))

    def graph_query(self, bot, persona, *, type_names=(), owner_kind=None,
                    subject=None, after=None, limit=100, expected_epoch=None,
                    include_invalid=False, _capability=None):
        self._require_coordinator(_capability)
        nonempty(bot, 'bot')
        nonempty(persona, 'persona')
        if type(limit) is not int or not 1 <= limit <= 512:
            raise ValueError('limit must be an integer from 1 to 512')
        if type(include_invalid) is not bool:
            raise TypeError('include_invalid must be bool')
        if not isinstance(type_names, tuple) or len(set(type_names)) != len(type_names):
            raise ValueError('type_names must be a unique tuple')
        for name in type_names:
            self._registry.spec(name)
        if owner_kind is not None and owner_kind not in ('persona', 'relation', 'scene', 'event', 'activity'):
            raise ValueError('unknown owner kind')
        if subject is not None:
            nonempty(subject, 'subject')
        if after is not None:
            self._validate_key(after)
            if self._namespace(after) != (bot, persona):
                raise ValueError('cursor crosses namespace')
        if expected_epoch is not None:
            if not isinstance(expected_epoch, NamespaceEpoch):
                raise TypeError('expected_epoch must be NamespaceEpoch')
            if (expected_epoch.bot, expected_epoch.persona) != (bot, persona):
                raise ValueError('epoch crosses namespace')
        clauses, args = ['bot=?', 'persona=?'], [bot, persona]
        if type_names:
            clauses.append('type_name IN (' + ','.join('?' for _ in type_names) + ')')
            args.extend(type_names)
        for column, value in (('owner_kind', owner_kind), ('subject', subject)):
            if value is not None:
                clauses.append(column + '=?')
                args.append(value)
        if not include_invalid:
            clauses.append('valid=1')
        if after is not None:
            clauses.append('token>?')
            args.append(after.token)
        args.append(limit + 1)
        with self._lock:
            self._ensure_open()
            self._db.execute('BEGIN')
            try:
                epoch = GraphStore.graph_epoch(self, bot, persona, _capability=_capability)
                if expected_epoch is not None and epoch != expected_epoch:
                    raise StaleRead('query namespace changed between pages')
                rows = self._db.execute(
                    'SELECT token,revision,value,valid FROM graph_atoms WHERE '
                    + ' AND '.join(clauses) + ' ORDER BY token LIMIT ?', args).fetchall()
                atoms = tuple(GraphAtom(AtomKey.from_token(row[0]), row[1],
                    json.loads(row[2]), bool(row[3])) for row in rows[:limit])
                next_after = atoms[-1].key if len(rows) > limit else None
                self._db.execute('COMMIT')
                return GraphPage(GraphSnapshot(atoms, (epoch,)), next_after)
            except BaseException:
                self._db.execute('ROLLBACK')
                raise

    def _deletion_snapshot_page(self, namespace: NamespaceId, keys: tuple[AtomKey, ...], *,
                                after: DeletionHistoryCursor | None = None,
                                expected_epoch: NamespaceEpoch | None = None,
                                limit: int = 100, edge_limit: int = 512,
                                _capability=None) -> DeletionSnapshotPage:
        """Read a same-namespace deletion candidate in one SQLite read transaction.

        History is a namespace-wide scan: old reverse edges can belong to atoms
        whose current dependency was replaced. The page proves no deletion or
        Authority intent; a production caller must use its existing read fence.
        """
        self._require_recovery_capability(_capability)
        if not isinstance(namespace, NamespaceId):
            raise TypeError("namespace must be NamespaceId")
        keys = tuple(keys)
        if not keys or len(keys) > 512 or len(set(keys)) != len(keys):
            raise ValueError("keys must be a unique tuple of 1 to 512 graph keys")
        for key in keys:
            self._validate_key(key)
            if self._namespace(key) != namespace.as_tuple:
                raise ValueError("key crosses namespace")
        if type(limit) is not int or not 1 <= limit <= 512:
            raise ValueError("limit must be an integer from 1 to 512")
        if type(edge_limit) is not int or not 1 <= edge_limit <= 512:
            raise ValueError("edge_limit must be an integer from 1 to 512")
        if after is not None:
            if not isinstance(after, DeletionHistoryCursor):
                raise TypeError("after must be DeletionHistoryCursor")
            if self._namespace(after.key) != namespace.as_tuple:
                raise ValueError("cursor crosses namespace")
            if expected_epoch is None:
                raise ValueError("expected_epoch is required for continuation")
        if expected_epoch is not None:
            if not isinstance(expected_epoch, NamespaceEpoch):
                raise TypeError("expected_epoch must be NamespaceEpoch")
            if (expected_epoch.bot, expected_epoch.persona) != namespace.as_tuple:
                raise ValueError("epoch crosses namespace")

        with self._lock:
            self._ensure_open()
            self._db.execute("BEGIN")
            try:
                epoch = GraphStore.graph_epoch(
                    self, *namespace.as_tuple, _capability=_capability)
                if expected_epoch is not None and epoch != expected_epoch:
                    raise StaleRead("deletion snapshot namespace epoch changed")
                if after is not None:
                    cursor_row = self._db.execute(
                        "SELECT dependencies FROM graph_history WHERE token=? AND revision=? "
                        "AND event_bot=? AND event_persona=?",
                        (after.key.token, after.revision, *namespace.as_tuple),
                    ).fetchone()
                    if cursor_row is None:
                        raise StaleRead("deletion history cursor is absent")
                    if after.edge_offset:
                        cursor_dependencies = json.loads(cursor_row[0])
                        if (type(cursor_dependencies) is not list
                                or after.edge_offset >= len(cursor_dependencies)):
                            raise StaleRead("deletion history cursor edge offset is invalid")

                atoms = []
                for key in keys:
                    row = self._db.execute(
                        "SELECT revision,value,valid FROM graph_atoms "
                        "WHERE token=? AND bot=? AND persona=?",
                        (key.token, *namespace.as_tuple)).fetchone()
                    atoms.append(GraphAtom(key, row[0], json.loads(row[1]), bool(row[2]))
                                 if row else GraphAtom(key, 0, {}, False))
                placeholders = ",".join("?" for _ in keys)
                reverse_rows = self._db.execute(
                    "SELECT d.dependent_token,d.dependency_token,d.dependency_revision,"
                    "a.revision,a.value,a.valid FROM graph_dependencies d "
                    "JOIN graph_atoms a ON a.token=d.dependent_token "
                    f"WHERE d.dependency_token IN ({placeholders}) "
                    "AND a.bot=? AND a.persona=? "
                    "ORDER BY d.dependent_token,d.dependency_token",
                    tuple(key.token for key in keys) + namespace.as_tuple).fetchall()
                known = set(keys)
                reverse_edges = []
                for dependent_token, dependency_token, dependency_revision, revision, value, valid in reverse_rows:
                    dependent = AtomKey.from_token(dependent_token)
                    dependency = AtomKey.from_token(dependency_token)
                    if (self._namespace(dependent) != namespace.as_tuple
                            or self._namespace(dependency) != namespace.as_tuple):
                        raise StaleRead("cross-namespace current dependency")
                    if dependent not in known:
                        atoms.append(GraphAtom(dependent, revision, json.loads(value), bool(valid)))
                        known.add(dependent)
                    reverse_edges.append(DeletionDependencyEdge(
                        GraphVersion(dependent, revision),
                        GraphVersion(dependency, dependency_revision)))

                history_where = "h.event_bot=? AND h.event_persona=?"
                history_args = list(namespace.as_tuple)
                if after is not None:
                    history_where += (" AND (h.token>? OR (h.token=? AND h.revision>?)"
                                      " OR (h.token=? AND h.revision=? AND ?>0))")
                    history_args.extend((after.key.token, after.key.token, after.revision,
                                         after.key.token, after.revision, after.edge_offset))
                history_rows_sql = self._db.execute(
                    "SELECT h.token,h.revision,h.value,h.valid,h.dependencies,"
                    "h.event_session,h.event_id FROM graph_history h WHERE "
                    + history_where + " ORDER BY h.token,h.revision LIMIT ?",
                    tuple(history_args) + (limit + 1,)).fetchall()
                result_rows = []
                history_edges = []
                position = after
                for token, revision, value, valid, encoded, session, event_id in history_rows_sql[:limit]:
                    key = AtomKey.from_token(token)
                    if self._namespace(key) != namespace.as_tuple:
                        raise StaleRead("cross-namespace history row")
                    dependencies = json.loads(encoded)
                    if type(dependencies) is not list:
                        raise StaleRead("invalid history dependencies")
                    offset = (after.edge_offset if after is not None and after.edge_offset
                              and key == after.key and revision == after.revision else 0)
                    if offset >= len(dependencies) and offset:
                        raise StaleRead("history edge cursor is out of range")
                    result_rows.append(DeletionHistoryRow(
                        GraphAtom(key, revision, json.loads(value), bool(valid)),
                        session, event_id, len(dependencies)))
                    capacity = edge_limit - len(history_edges)
                    end = min(len(dependencies), offset + capacity)
                    for dependency_token, dependency_revision in dependencies[offset:end]:
                        dependency = AtomKey.from_token(dependency_token)
                        if self._namespace(dependency) != namespace.as_tuple:
                            raise StaleRead("cross-namespace history dependency")
                        history_edges.append(DeletionDependencyEdge(
                            GraphVersion(key, revision),
                            GraphVersion(dependency, dependency_revision)))
                    if end < len(dependencies):
                        position = DeletionHistoryCursor(key, revision, end)
                        break
                    position = DeletionHistoryCursor(key, revision)
                    if len(history_edges) == edge_limit:
                        break
                more = bool(position and position.edge_offset) or len(history_rows_sql) > len(result_rows)
                snapshot = GraphSnapshot(tuple(atoms), (epoch,))
                self._db.execute("COMMIT")
                return DeletionSnapshotPage(
                    snapshot, snapshot.versions, tuple(reverse_edges), tuple(result_rows),
                    tuple(history_edges), position if more else None, not more)
            except BaseException:
                self._db.execute("ROLLBACK")
                raise

    def _current_revision(self, token):
        row = self._db.execute(
            "SELECT revision FROM graph_atoms WHERE token=?", (token,)
        ).fetchone()
        return row[0] if row else 0

    def _reverse_closure(self, seeds):
        """Follow old reverse edges even through keys that will be rewritten."""
        seen = set(seeds)
        closure = set()
        pending = list(seeds)
        while pending:
            token = pending.pop()
            rows = self._db.execute(
                "SELECT dependent_token FROM graph_dependencies WHERE dependency_token=?",
                (token,),
            ).fetchall()
            for (dependent,) in rows:
                closure.add(dependent)
                if dependent not in seen:
                    seen.add(dependent)
                    pending.append(dependent)
        return closure

    def _assert_acyclic(self, namespace, replacements):
        # Replacing outgoing edges with empty sets cannot introduce a cycle.
        if not any(replacements.values()):
            return
        bot, persona = namespace
        nodes = {
            row[0]: set() for row in self._db.execute(
                "SELECT token FROM graph_atoms WHERE bot=? AND persona=?", (bot, persona)
            )
        }
        for dependent, dependency in self._db.execute(
            "SELECT d.dependent_token,d.dependency_token FROM graph_dependencies d "
            "JOIN graph_atoms a ON a.token=d.dependent_token WHERE a.bot=? AND a.persona=?",
            (bot, persona),
        ):
            nodes.setdefault(dependent, set()).add(dependency)
            nodes.setdefault(dependency, set())
        for token, dependencies in replacements.items():
            nodes[token] = set(dependencies)
            for dependency in dependencies:
                nodes.setdefault(dependency, set())
        # Kahn's algorithm avoids Python's recursion ceiling for long memory chains.
        indegree = {token: 0 for token in nodes}
        for dependencies in nodes.values():
            for dependency in dependencies:
                indegree[dependency] += 1
        ready = [token for token, degree in indegree.items() if degree == 0]
        visited = 0
        while ready:
            token = ready.pop()
            visited += 1
            for dependency in nodes[token]:
                indegree[dependency] -= 1
                if indegree[dependency] == 0:
                    ready.append(dependency)
        if visited != len(nodes):
            raise ValueError("instantaneous dependency cycle")

    def _prepare_graph_candidate(self, candidate: GraphCandidate, *,
                                 _owner_issue: bool = False,
                                 _owner_revoke: bool = False):
        if not isinstance(candidate, GraphCandidate):
            raise TypeError("candidate must be GraphCandidate")
        event = candidate.event
        namespace = (event.scope.bot, event.scope.persona)
        reads = tuple(candidate.reads)
        writes = tuple(candidate.writes)
        epochs = tuple(candidate.epochs)
        read_keys = [read.key for read in reads]
        write_keys = [write.key for write in writes]
        if len(set(read_keys)) != len(read_keys):
            raise ValueError("duplicate graph reads")
        if len(set(write_keys)) != len(write_keys):
            raise ValueError("duplicate graph writes")
        if len({(epoch.bot, epoch.persona) for epoch in epochs}) != len(epochs):
            raise ValueError("duplicate namespace epochs")
        if not set(write_keys).issubset(read_keys):
            raise ValueError("every graph write must have a read version")
        for read in reads:
            self._validate_key(read.key)
            if self._namespace(read.key) != namespace:
                raise ValueError("cross-namespace graph candidate")
        for epoch in epochs:
            if (epoch.bot, epoch.persona) != namespace:
                raise ValueError("cross-namespace epoch")
        read_set = set(read_keys)
        prepared = []
        for write in writes:
            if write.key.type_name == OWNER_GRANT_TYPE and not (
                    _owner_issue or _owner_revoke):
                raise PermissionError("Owner grant requires a fenced W01 authorization path")
            spec = self._validate_key(write.key)
            if self._namespace(write.key) != namespace:
                raise ValueError("cross-namespace graph candidate")
            if any(self._namespace(key) != namespace for key in write.dependencies):
                raise ValueError("cross-namespace dependency")
            if not set(write.dependencies).issubset(read_set):
                raise ValueError("dependencies must belong to the complete read set")
            if spec.immutable and write.dependencies:
                raise ValueError("immutable graph atoms cannot have invalidating dependencies")
            prepared.append((write, spec, canonical_json(self._registry.validate(write.key, write.value))))
        # The Event is the idempotency unit. A retry may legitimately rebuild its
        # candidate from the now-current snapshot, so candidate CAS material is
        # retained for audit but is not part of the event conflict digest.
        digest = event.digest
        scope_key = (event.scope.bot, event.scope.persona, event.scope.session, event.event_id)
        return namespace, reads, writes, epochs, prepared, digest, scope_key

    def graph_commit(self, candidate: GraphCandidate, *, _guard=None, _receipt_hook=None,
                     _capability=None, _transaction_state=None):
        self._require_coordinator(_capability)
        prepared = self._prepare_graph_candidate(candidate)
        with self._lock:
            self._ensure_open()
            if _transaction_state is not None:
                _transaction_state["phase"] = "begin_attempted"
            self._db.execute("BEGIN IMMEDIATE")
            if _transaction_state is not None:
                _transaction_state["phase"] = "transaction_open"
            try:
                receipt = self._graph_commit_core(
                    *prepared, _guard=_guard, _receipt_hook=_receipt_hook)
                if _transaction_state is not None:
                    _transaction_state["phase"] = "commit_attempted"
                self._db.execute("COMMIT")
                if _transaction_state is not None:
                    _transaction_state["phase"] = "committed"
                return receipt
            except BaseException:
                self._db.execute("ROLLBACK")
                if (_transaction_state is not None
                        and _transaction_state["phase"] != "commit_attempted"):
                    _transaction_state["phase"] = "rolled_back"
                raise

    def _graph_commit_in_transaction(self, candidate: GraphCandidate, *,
                                     _guard=None, _receipt_hook=None, _capability=None,
                                     _owner_issue: bool = False,
                                     _owner_revoke: bool = False):
        """Run a graph commit inside the coordinator's existing write transaction.

        Caller holds this store's lock and owns COMMIT or ROLLBACK.
        """
        self._require_recovery_capability(_capability)
        if not self._lock._is_owned() or not self._db.in_transaction:
            raise RuntimeError("graph transaction requires the store lock and active transaction")
        self._ensure_open()
        prepared = self._prepare_graph_candidate(
            candidate, _owner_issue=_owner_issue, _owner_revoke=_owner_revoke)
        return self._graph_commit_core(*prepared, _guard=_guard, _receipt_hook=_receipt_hook)

    @contextmanager
    def _provisional_graph_stage_in_transaction(
            self, candidate: GraphCandidate, *, _capability=None):
        """Expose a tentative graph E+1 only inside a caller-owned transaction.

        Every row, event, history entry and epoch written by this stage is
        rolled back before the caller may seal a final candidate. A check made
        here is only a provisional candidate: it must be reissued against the
        final graph rows in the final receipt hook before admission.
        """
        self._require_recovery_capability(_capability)
        if not self._lock._is_owned() or not self._db.in_transaction:
            raise RuntimeError("provisional stage requires the held graph transaction")
        if (type(candidate) is not GraphCandidate or not candidate.writes
                or len(candidate.epochs) != 1):
            raise ValueError("provisional stage needs one guarded graph write")
        event = candidate.event
        staged_event = Event(
            event.scope, "provisional:" + secrets.token_hex(24),
            event.occurred_at, event.kind, event.payload)
        staged = GraphCandidate(
            staged_event, candidate.reads, candidate.writes, candidate.epochs)
        name = "provisional_" + secrets.token_hex(16)
        self._db.execute("SAVEPOINT " + name)
        try:
            receipt = self._graph_commit_in_transaction(
                staged, _capability=_capability)
            if receipt.status != "committed":
                raise EventConflict("provisional graph event unexpectedly replayed")
            yield receipt
        finally:
            self._db.execute("ROLLBACK TO SAVEPOINT " + name)
            self._db.execute("RELEASE SAVEPOINT " + name)

    def _graph_commit_core(self, namespace, reads, writes, epochs, prepared,
                           digest, scope_key, *, _guard=None, _receipt_hook=None):
        if _guard is not None:
            _guard(self._db)
        for write in writes:
            self._assert_c09_key_not_erased(write.key)
        prior = self._db.execute(
            "SELECT digest,revisions,invalidated,epoch_revision FROM graph_events "
            "WHERE bot=? AND persona=? AND session=? AND event_id=?", scope_key
        ).fetchone()
        if prior:
            if prior[0] != digest:
                raise EventConflict("event ID reused with different graph candidate")
            receipt = GraphReceipt(
                "duplicate", self._version_rows(prior[1]),
                self._version_rows(prior[2]),
                NamespaceEpoch(namespace[0], namespace[1], prior[3]),
            )
            if _receipt_hook is not None:
                _receipt_hook(self._db, receipt)
            return receipt
        for read in reads:
            actual = self._current_revision(read.key.token)
            if actual != read.revision:
                raise StaleRead(
                    f"{read.key.token}: expected {read.revision}, observed {actual}"
                )
        epoch_row = self._db.execute(
            "SELECT revision FROM graph_epochs WHERE bot=? AND persona=?", namespace
        ).fetchone()
        current_epoch = epoch_row[0] if epoch_row else 0
        for epoch in epochs:
            if epoch.revision != current_epoch:
                raise StaleRead(
                    f"namespace epoch: expected {epoch.revision}, observed {current_epoch}"
                )
        for write, spec, _ in prepared:
            if spec.immutable and self._current_revision(write.key.token) != 0:
                raise ValueError(f"immutable graph atom already exists: {write.key.token}")

        write_tokens = {write.key.token for write in writes}
        closure = self._reverse_closure(write_tokens)
        to_invalidate = closure - write_tokens
        replacements = {
            write.key.token: tuple(key.token for key in write.dependencies)
            for write in writes
        }
        self._assert_acyclic(namespace, replacements)

        post_revisions = {read.key.token: read.revision for read in reads}
        for write in writes:
            post_revisions[write.key.token] = post_revisions[write.key.token] + 1
        post_valid = {}
        for token in to_invalidate:
            row = self._db.execute(
                "SELECT valid FROM graph_atoms WHERE token=?", (token,)
            ).fetchone()
            post_valid[token] = False if row else False
        for write in writes:
            post_valid[write.key.token] = True
        for write in writes:
            for dependency in write.dependencies:
                token = dependency.token
                if token in post_valid:
                    valid = post_valid[token]
                else:
                    row = self._db.execute(
                        "SELECT valid FROM graph_atoms WHERE token=?", (token,)
                    ).fetchone()
                    # Revision-zero dependencies are explicit observations of
                    # absence. They remain valid until that key first appears,
                    # at which point the reverse edge invalidates the dependent.
                    valid = bool(row[0]) if row else True
                if not valid:
                    raise ValueError(
                        f"dependency is absent or invalid after transaction: {token}"
                    )

        invalidation_rows = []
        for token in sorted(to_invalidate):
            row = self._db.execute(
                "SELECT revision,value,valid FROM graph_atoms WHERE token=?", (token,)
            ).fetchone()
            if row and row[2]:
                invalidation_rows.append((token, row[0] + 1, row[1]))

        state_changed = bool(writes or invalidation_rows)
        new_epoch = current_epoch + int(state_changed)
        revisions = tuple(
            GraphVersion(write.key, post_revisions[write.key.token]) for write in writes
        )
        invalidated = tuple(
            GraphVersion(AtomKey.from_token(token), revision)
            for token, revision, _ in invalidation_rows
        )
        reads_json = canonical_json([[r.key.token, r.revision] for r in reads])
        epoch_reads_json = canonical_json(
            [[e.bot, e.persona, e.revision] for e in epochs]
        )
        revisions_json = canonical_json(
            [[r.key.token, r.revision] for r in revisions]
        )
        invalidated_json = canonical_json(
            [[r.key.token, r.revision] for r in invalidated]
        )
        self._db.execute(
            "INSERT INTO graph_events(bot,persona,session,event_id,digest,reads,epoch_reads,"
            "revisions,invalidated,epoch_revision) VALUES(?,?,?,?,?,?,?,?,?,?)",
            scope_key + (digest, reads_json, epoch_reads_json, revisions_json,
                         invalidated_json, new_epoch),
        )

        for write, _, value_json in prepared:
            token = write.key.token
            revision = post_revisions[token]
            owner = write.key.owner
            self._db.execute(
                "INSERT INTO graph_atoms(token,bot,persona,owner_kind,subject,type_name,name,"
                "revision,value,valid) VALUES(?,?,?,?,?,?,?,?,?,1) "
                "ON CONFLICT(token) DO UPDATE SET revision=excluded.revision,"
                "value=excluded.value,valid=1",
                (token, owner.bot, owner.persona, owner.kind, owner.subject,
                 write.key.type_name, write.key.name, revision, value_json),
            )
            self._db.execute(
                "DELETE FROM graph_dependencies WHERE dependent_token=?", (token,)
            )
            dependency_rows = []
            for dependency in write.dependencies:
                dep_revision = post_revisions.get(dependency.token)
                if dep_revision is None:
                    dep_revision = self._current_revision(dependency.token)
                dependency_rows.append((token, dependency.token, dep_revision))
            self._db.executemany(
                "INSERT INTO graph_dependencies(dependent_token,dependency_token,"
                "dependency_revision) VALUES(?,?,?)", dependency_rows
            )
            dependencies_json = canonical_json(
                [[dependency, revision] for _, dependency, revision in dependency_rows]
            )
            self._db.execute(
                "INSERT INTO graph_history(token,revision,value,valid,dependencies,event_bot,"
                "event_persona,event_session,event_id) VALUES(?,?,?,?,?,?,?,?,?)",
                (token, revision, value_json, 1, dependencies_json) + scope_key,
            )

        for token, revision, value_json in invalidation_rows:
            self._db.execute(
                "UPDATE graph_atoms SET revision=?,valid=0 WHERE token=?",
                (revision, token),
            )
            dependencies = self._db.execute(
                "SELECT dependency_token,dependency_revision FROM graph_dependencies "
                "WHERE dependent_token=? ORDER BY dependency_token", (token,)
            ).fetchall()
            self._db.execute(
                "INSERT INTO graph_history(token,revision,value,valid,dependencies,event_bot,"
                "event_persona,event_session,event_id) VALUES(?,?,?,?,?,?,?,?,?)",
                (token, revision, value_json, 0,
                 canonical_json([list(row) for row in dependencies])) + scope_key,
            )

        if state_changed:
            self._db.execute(
                "INSERT INTO graph_epochs(bot,persona,revision) VALUES(?,?,?) "
                "ON CONFLICT(bot,persona) DO UPDATE SET revision=excluded.revision",
                namespace + (new_epoch,),
            )
        receipt = GraphReceipt(
            "committed", revisions, invalidated,
            NamespaceEpoch(namespace[0], namespace[1], new_epoch),
        )
        if _receipt_hook is not None:
            _receipt_hook(self._db, receipt)
        return receipt


class ProductionGraphStore(GraphStore):
    """Production-facing class that closes legacy untyped and direct graph APIs.

    Host setup keeps the store private and passes domain code a coordinator.
    Python module internals remain part of the trusted computing base.
    """

    @staticmethod
    def _deny():
        raise PermissionError("production graph access requires GraphCoordinator")

    def snapshot(self, *args, **kwargs):
        self._deny()

    def commit(self, *args, **kwargs):
        self._deny()

    def graph_snapshot(self, *args, **kwargs):
        self._deny()

    def graph_epoch(self, *args, **kwargs):
        self._deny()

    def graph_query(self, *args, **kwargs):
        self._deny()

    def graph_event_receipt(self, *args, **kwargs):
        self._deny()

    def graph_commit(self, *args, **kwargs):
        self._deny()
