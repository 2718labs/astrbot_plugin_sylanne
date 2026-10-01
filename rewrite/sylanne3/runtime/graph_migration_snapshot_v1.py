"""Fail-closed, namespace-only graph migration inventory and source seal.

W01 owns the Authority permit check and the surrounding trusted graph transaction.
This module never imports rows, advances an Authority head, or activates a graph.
Unknown tables and records without a provable namespace owner stop sealing.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
import json
import re

from ..contracts import canonical_json
from ..graph_store import (
    GraphMigrationVerifiedTransferV1, GraphRecoveryMetadataV2, GraphStore,
)
from ..graph_types import AtomKey
from ..runtime_contracts import NamespaceId, SnapshotRequirementsV2, canonical_digest


FORMAT = "sylanne.graph-namespace-snapshot.v1"
_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_IMPORT_TABLE = "graph_migration_import_receipts_v1"
_DEFERRED = ("d06_projection_rebuild_and_block_reconciliation",
             "authority_deletion_execution_current_head_merge",
             "authority_owner_grant_revoke_current_head_merge",
             "authority_internal_work_claim_terminal_current_head_merge",
             "d02_body_policy_quote_signature_and_current_owner_recheck",
             "unknown_effect_and_unconfirmed_cost_reconciliation",
             "target_grants_and_worker_qualification")

# Explicit catalogue: adding a durable table requires a routing decision here.
_DIRECT = frozenset("""
 atoms events graph_atoms graph_authority_epochs graph_bundle_fences_v2
 d02_fixed_body_policies_v1 d02_body_quotes_v1
 graph_bundle_intents_v2 graph_bundle_operations graph_bundle_outbox
 graph_bundle_refs graph_bundle_rejections_v2 graph_bundle_sequence
 graph_c02_cost_attempts_v1 graph_context_reply_acquires_v2
 graph_c09_erasure_barriers_v1 graph_c09_erasure_plans_v1
 graph_d04_installed_stage_attempts_v3 graph_d04_root_topology_originals_v3
 graph_d04_semantic_installations_v3 graph_d04_owner_install_attempts_v3
 runtime_d11_owner_role_clock_originals_v1
 graph_c04_internal_work_prepared_v1 graph_c04_encoding_baselines_v3
 graph_c04_association_inputs_v2
 graph_c04_association_inputs_v3 graph_c04_product_requests_v3
 graph_c04_code_policy_originals_v3 graph_c04_adoptions_v3 graph_owner_domain_attempts_v3
 graph_c04_historical_accounting_v1 graph_c04_historical_job_closures_v1
 graph_c04_adoption_provenance_v3
 graph_c09_cumulative_applications_v1
 d11_c04_cpu_cost_originals_v1
 d02_c04_body_cost_originals_v1
 runtime_c04_cpu_quote_policies_v1 runtime_c04_cpu_quote_requests_v1
 graph_context_reply_attempts_v2 graph_context_reply_call_bindings_v2
 graph_context_reply_preparations_v2 graph_context_reply_terminals_v2
 graph_d03_arrival_issuance_v2 graph_d03_self_projection_intents_v1
 graph_d03_self_projection_issuance_v1 graph_d04_baseline_intents_v1
 graph_d04_baseline_issuance_v1 graph_d04_root_originals_v1 graph_d04_root_adoption_originals_v2
 graph_d04_joint_advances_v2 graph_d04_joint_advance_members_v2
 graph_d04_joint_numeric_originals_v1 graph_d04_joint_output_originals_v1 graph_d04_joint_output_closures_v1
 graph_d04_originals_v3 graph_d04_root_originals_v3
 runtime_d11_d04_root_freezes_v2 runtime_d11_d04_root_freezes_v3
 graph_domain_production_originals_v1 graph_domain_production_outbox_v1
 graph_contact_model_originals_v1
 graph_d01_production_inputs_v1 graph_d02_production_policies_v1 graph_d02_action_components_v1
 graph_d05_production_policies_v1 graph_d05_boundary_intents_v1
 graph_d08_joint_plan_intents_v1 graph_d08_party_consents_v1
 graph_d10_production_inputs_v1 graph_d10_observed_ticks_v1
 graph_d11_offline_originals_v1
 graph_d07_execution_originals_v1 graph_d07_stage_attempts_v1 graph_d07_accounting_attempts_v1
 graph_d07_behavior_original_v1
 graph_d07_attention_issuance_v1 graph_d07_attention_decisions_v2 graph_d07_observed_focus_v2 graph_d07_deferred_release_v2
 graph_d12_compilation_operations_v1
 graph_d12_compilation_originals_v1 graph_d12_preview_operations_v1
 graph_d12_preview_originals_v1 graph_d12_preview_behavior_originals_v1
 graph_d12_d09_preview_originals_v1
 graph_d12_backend_operations_v1 graph_d12_backend_originals_v1
 graph_d12_lifecycle_plans_v1 graph_d12_lifecycle_steps_v1
 graph_d12_adoption_operations_v1
 graph_d12_preview_fence_attempts_v1
 graph_d13_cleanup_tasks_v1
 graph_d13_inbound_turn_attempts_v1 graph_d13_precompression_attempts_v2
 graph_d13_outbound_observations_v1
 graph_d13_wire_evidence_v1
 graph_d13_paid_intent_originals_v1 graph_d13_paid_call_originals_v1 graph_d13_paid_write_attempts_v1
 graph_d13_retirements_v1 graph_d13_worker_attempts_v2
 graph_d13_paid_schedule_inputs_v1 graph_d13_paid_scene_jobs_v1
 graph_d13_paid_result_reads_v1 graph_d13_paid_cost_receipts_v1
 graph_dispatch_action_job_bindings_v1 graph_dispatch_admissions
 graph_epochs graph_events graph_first_ingress_c02_candidates_v1
 graph_first_ingress_c02_candidates_v2 graph_first_ingress_c02_committed_seals_v2
 graph_first_ingress_c02_terminal_reads_v2 graph_first_ingress_identity_v1
 graph_first_ingress_intents_v2 graph_first_ingress_rejections_v2
 graph_guard_versions graph_job_acquire_intents_v2
 graph_job_acquire_receipts_v2 graph_job_acquire_rejections_v2
 graph_namespace_provision_intents_v2 graph_namespace_provisioning_v2
 graph_migration_import_receipts_v1
 graph_natural_generation_acquires_v2 graph_natural_generation_attempts_v2
 graph_natural_generation_scopes_v2 graph_natural_generation_terminals_v2
 graph_natural_generation_output_reads_v2
 graph_natural_generation_preparations_v2
 graph_natural_review_preparations_v2 graph_natural_review_attempts_v2
 graph_natural_review_content_reads_v2 graph_natural_review_acquires_v2
 graph_natural_review_terminals_v2 graph_natural_review_output_reads_v2
 graph_natural_paid_review_reads_v2
 graph_original_model_cost_attempts_v1 graph_outbox_jobs
 graph_owner_issue_fences_v1 graph_owner_issue_intents_v1
 graph_owner_issue_operations_v1 graph_owner_issue_rejections_v1
 graph_owner_revoke_intents_v1 graph_owner_revoke_operations_v1
 graph_post_c02_reply_dispatch_attempts_v2
 graph_post_c02_reply_model_acquires_v1 graph_post_c02_reply_model_attempts_v1
 graph_post_c02_reply_model_preparations_v1 graph_post_c02_reply_ownership_v1
 graph_product_advances graph_recovery_metadata_v2
 graph_d12_domain_candidates_v1 graph_d12_compile_attempts_v1
 graph_role_init_intents_v1 graph_role_init_receipts_v1
 graph_role_init_rejections_v1 graph_role_init_request_proofs_v1
 graph_scene_binding_intents_v1 graph_scene_binding_receipts_v1
 graph_scene_binding_rejections_v1 graph_scene_binding_request_proofs_v1
 graph_source_access_revocations_v1 graph_stage_candidate_reads_v1
 graph_stage_retry_lineage_v1 ingress_first_observations
 graph_source_attachment_blobs_v2
 runtime_d04_coupling_graph_evidence_v1 runtime_encoding_call_bindings_v1
 runtime_encoding_call_redactions_v1 runtime_ingress_issuance
 runtime_d12_preview_cost_v1
 runtime_budget_leases runtime_budget_operations runtime_job_operations
 runtime_jobs
""".split())
_TOKEN_LINKED = frozenset({"graph_dependencies", "graph_dependency_edges"})
_LEASE_LINKED = frozenset({"runtime_budget_reservations", "runtime_budget_debt_blocks"})
_GLOBAL_EMPTY = frozenset("""
 runtime_deadlines
 runtime_deadline_operations  
  
 
 
 
  
 activation_meta activation_state activation_events deletion_meta
 deletion_events execution_metadata execution_entries execution_effects
""".split())
_CATALOGUE = frozenset({"graph_type_catalog", "graph_type_authority"})
_SIGNED_JSON = frozenset(('runtime_budget_grants', 'runtime_resource_quotes', 'runtime_resource_outcomes', 'runtime_d03_arrival_quote_policies', 'runtime_private_reply_dispatch_policies_v1', 'runtime_d04_baseline_quote_policies', 'runtime_d03_self_projection_quote_policies', 'runtime_d06_c02_quote_policies', 'runtime_d06_correction_quote_policies'))
_CLOCK_LINKED = frozenset({"runtime_character_clocks", "runtime_clock_operations"})
_SPECIAL = _CLOCK_LINKED | frozenset({"graph_history"}) | _TOKEN_LINKED | _LEASE_LINKED | _SIGNED_JSON
_KNOWN = _DIRECT | _SPECIAL | _GLOBAL_EMPTY | _CATALOGUE


class IncompleteMigrationClosure(ValueError):
    """A source table, owner, or external recovery dependency is unresolved."""


@dataclass(frozen=True, slots=True)
class NamespaceGraphSnapshotV1:
    transfer_id: str
    namespace: NamespaceId
    source_installation_id: str
    permit_token: str
    source_metadata: GraphRecoveryMetadataV2
    graph_epoch: int
    schema_digest: str
    catalogue_digest: str
    tables: tuple[tuple[str, tuple[str, ...], tuple[tuple[object, ...], ...]], ...]
    deferred_dependencies: tuple[str, ...]
    digest: str

    @property
    def closure_digest(self) -> str:
        return _hash((self.schema_digest, self.catalogue_digest, self.tables))


@dataclass(frozen=True, slots=True)
class TargetGraphImportReceiptV1:
    transfer_id: str
    namespace: NamespaceId
    snapshot_digest: str
    closure_digest: str
    source_graph_revision: int
    source_graph_incarnation: str
    target_graph_revision: int
    target_graph_incarnation: str
    target_activation_generation: int
    graph_epoch: int
    graph_commit_digest: str


def _install_import_receipt_schema(db) -> None:
    db.execute("""CREATE TABLE IF NOT EXISTS graph_migration_import_receipts_v1 (
        bot TEXT NOT NULL, persona TEXT NOT NULL, transfer_id TEXT NOT NULL,
        snapshot_digest TEXT NOT NULL, closure_digest TEXT NOT NULL,
        source_graph_revision INTEGER NOT NULL,
        target_graph_revision INTEGER NOT NULL,
        receipt_json TEXT NOT NULL,
        PRIMARY KEY(bot,persona,transfer_id))""")
    db.execute("""CREATE TRIGGER IF NOT EXISTS graph_migration_import_no_update_v1
        BEFORE UPDATE ON graph_migration_import_receipts_v1
        BEGIN SELECT RAISE(ABORT, 'migration import receipt is immutable'); END""")
    db.execute("""CREATE TRIGGER IF NOT EXISTS graph_migration_import_no_delete_v1
        BEFORE DELETE ON graph_migration_import_receipts_v1
        BEGIN SELECT RAISE(ABORT, 'migration import receipt is immutable'); END""")


def _hash(payload: object) -> str:
    return "sha256:" + sha256(canonical_json(_json_value(payload)).encode("utf-8")).hexdigest()


def _json_value(value: object) -> object:
    if type(value) is tuple:
        return [_json_value(item) for item in value]
    if type(value) is list:
        return [_json_value(item) for item in value]
    if type(value) is dict:
        return {key: _json_value(item) for key, item in value.items()}
    if value is None or type(value) in (str, int, float, bool):
        return value
    raise IncompleteMigrationClosure("snapshot contains a non-JSON database value")


def _table_names(db) -> set[str]:
    return {name for (name,) in db.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")}


def _columns(db, table: str) -> tuple[str, ...]:
    if _IDENT.fullmatch(table) is None:
        raise IncompleteMigrationClosure("invalid table name")
    return tuple(row[1] for row in db.execute(f"PRAGMA table_info({table})"))


def _schema_digest(db) -> str:
    return _hash(tuple(db.execute(
        "SELECT type,name,tbl_name,sql FROM sqlite_master "
        "WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name")))


def _catalogue_digest(db) -> str:
    return _hash((
        tuple(db.execute("SELECT * FROM graph_type_catalog ORDER BY name")),
        tuple(db.execute("SELECT * FROM graph_type_authority ORDER BY name")),
    ))


def _owner_of_token(token: str) -> tuple[str, str]:
    try:
        key = AtomKey.from_token(token)
        return key.owner.bot, key.owner.persona
    except (TypeError, ValueError) as exc:
        raise IncompleteMigrationClosure("invalid graph token") from exc


def _signed_row_metadata(table, columns, row):
    """Route original signed data without resigning, rewriting or granting it."""
    from . import issuers
    field = ("grant_json" if table == "runtime_budget_grants" else "quote_json" if table == "runtime_resource_quotes"
             else "outcome_json" if table == "runtime_resource_outcomes" else "policy_json")
    if not {field, "signature"} <= set(columns):
        raise IncompleteMigrationClosure("signed resource columns differ")
    raw = row[columns.index(field)]
    value = json.loads(raw)
    signature = row[columns.index("signature")]
    if type(signature) is not str or re.fullmatch(r"[0-9a-f]{64}", signature) is None:
        raise IncompleteMigrationClosure("signed resource signature is malformed")
    decoders = {
        "runtime_budget_grants": issuers._decode_grant,
        "runtime_resource_quotes": issuers._decode_quote,
        "runtime_resource_outcomes": issuers._decode_outcome,
        "runtime_d03_arrival_quote_policies": issuers._decode_d03_policy,
        "runtime_d04_baseline_quote_policies": issuers._decode_d04_policy,
        "runtime_d03_self_projection_quote_policies": issuers._decode_d03_projection_policy,
        "runtime_d06_c02_quote_policies": issuers._decode_d06_c02_policy,
        "runtime_d06_correction_quote_policies": issuers._decode_d06_correction_policy,
    }
    if table == "runtime_private_reply_dispatch_policies_v1":
        if (type(value) is not dict or value.get("schema") != "sylanne.private-reply-dispatch-policy.v1"
                or type(value.get("namespace")) is not list or len(value["namespace"]) != 2
                or value.get("lease_id") is None):
            raise IncompleteMigrationClosure("private dispatch policy scope differs")
        owner = tuple(value["namespace"])
        if row[columns.index("policy_id")] != "private-reply-dispatch-policy-" + canonical_digest(raw)[:40]:
            raise IncompleteMigrationClosure("private dispatch policy identity differs")
    else:
        decoded = decoders[table](raw)
        owner = (decoded.bot_id, decoded.persona_id)
        if set(value) != set(decoded.__dataclass_fields__):
            raise IncompleteMigrationClosure("signed resource payload fields differ")
        for name in ("quote_id", "lease_id", "policy_id", "operation_id", "version"):
            if name in columns and hasattr(decoded, name) and row[columns.index(name)] != getattr(decoded, name):
                raise IncompleteMigrationClosure("signed resource row and original identity differ")
    NamespaceId(*owner)
    lease = value.get("parent_budget_lease_ref") if table == "runtime_resource_quotes" else value.get("lease_id")
    return owner, lease, value


def _clock_original_index(columns, rows):
    from .clock import _mapping_from_dict, _mapping_dict
    required = {"bot", "persona", "revision", "operation_id", "original_json", "original_digest", "signature"}
    if not required <= set(columns):
        raise IncompleteMigrationClosure("D11 clock original namespace schema differs")
    result = {}
    for row in rows:
        get = lambda name: row[columns.index(name)]
        raw = json.loads(get("original_json"))
        owner = (get("bot"), get("persona"))
        mapping = _mapping_dict(_mapping_from_dict(raw["mapping"]))
        if (raw.get("schema") != "d11.owner-role-clock-original.v1"
                or raw.get("namespace") != {"bot_id": owner[0], "persona_id": owner[1]}
                or raw.get("revision") != get("revision") or raw.get("operation_id") != get("operation_id")
                or canonical_digest(raw) != get("original_digest") or len(get("signature")) != 64
                or raw["mapping"] != mapping):
            raise IncompleteMigrationClosure("D11 clock original identity differs")
        key = (mapping["mapping_id"], mapping["version"])
        if key in result:
            raise IncompleteMigrationClosure("D11 clock original ownership ambiguous")
        result[key] = (owner, raw)
    return result


def _clock_row_owner(table, columns, row, originals):
    get = lambda name: row[columns.index(name)]
    original = originals.get((get("mapping_id"), get("version")))
    if original is None:
        raise IncompleteMigrationClosure("role clock has no explicit signed Owner original")
    owner, body = original
    if table == "runtime_character_clocks":
        if {name: get(name) for name in columns} != body["mapping"]:
            raise IncompleteMigrationClosure("role clock differs from its exact original")
    elif (get("operation_id") != body["clock_operation_id"] or get("digest") != body["clock_operation_digest"]
            or json.loads(get("mapping_json")) != body["mapping"]):
        raise IncompleteMigrationClosure("role clock issuance operation differs")
    return owner


def _routed_rows(db, table: str, columns: tuple[str, ...],
                 namespace: NamespaceId) -> tuple[tuple[object, ...], ...]:
    if table in _CLOCK_LINKED:
        source = "runtime_d11_owner_role_clock_originals_v1"
        originals = _clock_original_index(_columns(db, source), tuple(db.execute(f"SELECT * FROM {source}")))
        return tuple(row for row in db.execute(f"SELECT * FROM {table}")
            if _clock_row_owner(table, columns, row, originals) == namespace.as_tuple)
    if table in _SIGNED_JSON:
        result = []
        for row in db.execute(f"SELECT * FROM {table}"):
            owner, lease, payload = _signed_row_metadata(table, columns, row)
            if lease is not None and db.execute("SELECT bot_id,persona_id FROM runtime_budget_leases WHERE lease_id=?", (lease,)).fetchone() != owner:
                raise IncompleteMigrationClosure("signed resource parent budget crosses namespace")
            if table == "runtime_resource_outcomes":
                quotes = db.execute("SELECT quote_json FROM runtime_resource_quotes WHERE quote_id=?", (payload["quote_id"],)).fetchall()
                if not quotes or any((json.loads(q[0])["bot_id"], json.loads(q[0])["persona_id"]) != owner for q in quotes):
                    raise IncompleteMigrationClosure("outcome has no same-namespace original quote")
            if owner == namespace.as_tuple:
                result.append(row)
        return tuple(result)
    if table in _GLOBAL_EMPTY:
        if db.execute(f"SELECT 1 FROM {table} LIMIT 1").fetchone():
            raise IncompleteMigrationClosure(f"{table} has unscoped durable rows")
        return ()
    if table in _CATALOGUE:
        return ()  # The full immutable catalogue is bound by its digest.
    if table == "graph_history":
        if not {"token", "event_bot", "event_persona"} <= set(columns):
            raise IncompleteMigrationClosure("graph_history routing columns changed")
        rows = []
        for row in db.execute("SELECT * FROM graph_history"):
            owner = _owner_of_token(row[columns.index("token")])
            event_owner = (row[columns.index("event_bot")],
                           row[columns.index("event_persona")])
            if owner != event_owner:
                raise IncompleteMigrationClosure("graph history token crosses namespace")
            if owner == namespace.as_tuple:
                rows.append(row)
        return tuple(rows)
    if table in _TOKEN_LINKED:
        rows = []
        if not {"dependent_token", "dependency_token"} <= set(columns):
            raise IncompleteMigrationClosure(f"{table} routing columns changed")
        for row in db.execute(f"SELECT * FROM {table}"):
            left = _owner_of_token(row[columns.index("dependent_token")])
            right = _owner_of_token(row[columns.index("dependency_token")])
            if left != right:
                raise IncompleteMigrationClosure(f"{table} crosses namespace")
            atom_owner = db.execute(
                "SELECT bot,persona FROM graph_atoms WHERE token=?",
                (row[columns.index("dependent_token")],)).fetchone()
            if atom_owner != left:
                raise IncompleteMigrationClosure(f"{table} dependent atom is absent")
            if left == namespace.as_tuple:
                rows.append(row)
        return tuple(rows)
    if table in _LEASE_LINKED:
        if "lease_id" not in columns:
            raise IncompleteMigrationClosure(f"{table} lease routing changed")
        rows = []
        for row in db.execute(f"SELECT * FROM {table}"):
            lease = row[columns.index("lease_id")]
            owner = db.execute(
                "SELECT bot_id,persona_id FROM runtime_budget_leases WHERE lease_id=?",
                (lease,)).fetchone()
            if owner is None:
                raise IncompleteMigrationClosure(f"{table} has orphan lease")
            if table == "runtime_budget_debt_blocks":
                cause = row[columns.index("cause_lease_id")]
                cause_owner = db.execute(
                    "SELECT bot_id,persona_id FROM runtime_budget_leases WHERE lease_id=?",
                    (cause,)).fetchone()
                if cause_owner != owner:
                    raise IncompleteMigrationClosure("budget debt cause crosses namespace")
            if tuple(owner) == namespace.as_tuple:
                rows.append(row)
        return tuple(rows)
    if table in _DIRECT:
        if {"bot", "persona"} <= set(columns):
            pair = ("bot", "persona")
        elif {"bot_id", "persona_id"} <= set(columns):
            pair = ("bot_id", "persona_id")
        else:
            raise IncompleteMigrationClosure(f"{table} has no reviewed namespace route")
        rows = tuple(db.execute(
            f"SELECT * FROM {table} WHERE {pair[0]}=? AND {pair[1]}=?",
            namespace.as_tuple))
        if table == "graph_atoms":
            for row in db.execute("SELECT * FROM graph_atoms"):
                if _owner_of_token(row[columns.index("token")]) != (
                        row[columns.index("bot")], row[columns.index("persona")]):
                    raise IncompleteMigrationClosure("graph atom token crosses namespace")
        if table == "runtime_budget_leases":
            for row in rows:
                parent = row[columns.index("parent_id")]
                if parent is not None:
                    owner = db.execute(
                        "SELECT bot_id,persona_id FROM runtime_budget_leases "
                        "WHERE lease_id=?", (parent,)).fetchone()
                    if owner != namespace.as_tuple:
                        raise IncompleteMigrationClosure("budget parent crosses namespace")
        if table == "runtime_jobs":
            for row in rows:
                budget_ref = row[columns.index("budget_ref")]
                if budget_ref:
                    owner = db.execute(
                        "SELECT bot_id,persona_id FROM runtime_budget_leases "
                        "WHERE lease_id=?", (budget_ref,)).fetchone()
                    if owner != namespace.as_tuple:
                        raise IncompleteMigrationClosure("job budget crosses namespace")
        if table == "runtime_encoding_call_bindings_v1":
            for row in rows:
                lease_id = row[columns.index("budget_lease_id")]
                owner = db.execute(
                    "SELECT bot_id,persona_id FROM runtime_budget_leases "
                    "WHERE lease_id=?", (lease_id,)).fetchone()
                if owner != namespace.as_tuple:
                    raise IncompleteMigrationClosure("encoding budget crosses namespace")
        return rows
    raise IncompleteMigrationClosure(f"unreviewed table {table}")


def _inventory(db, namespace: NamespaceId):
    names = _table_names(db)
    unknown = names - _KNOWN
    if unknown:
        raise IncompleteMigrationClosure(
            "unreviewed durable tables: " + ", ".join(sorted(unknown)))
    required = {"graph_atoms", "graph_epochs", "graph_events", "graph_history",
                "graph_recovery_metadata_v2", "graph_type_catalog",
                "graph_type_authority", "runtime_jobs", "runtime_budget_leases"}
    if missing := required - names:
        raise IncompleteMigrationClosure(
            "missing required tables: " + ", ".join(sorted(missing)))
    tables = []
    for name in sorted(names):
        if name in _CATALOGUE or name in _GLOBAL_EMPTY:
            _routed_rows(db, name, _columns(db, name), namespace)
            continue
        columns = _columns(db, name)
        rows = _routed_rows(db, name, columns, namespace)
        # Sorting encoded rows makes the digest independent of SQLite scan order.
        ordered = tuple(sorted(rows, key=lambda row: canonical_json(_json_value(row))))
        tables.append((name, columns, ordered))
    return tuple(tables)


def seal_source_namespace_in_tx(store: GraphStore, namespace: NamespaceId,
                                *, transfer_id: str,
                                source_installation_id: str,
                                permit_token: str,
                                expected: GraphRecoveryMetadataV2,
                                _capability: object) -> NamespaceGraphSnapshotV1:
    """Seal after W01 validates a live source_snapshot permit and freezes writes.

    The caller holds store._lock and BEGIN IMMEDIATE. This helper operates in
    that one SQL transaction. The returned digest is a content checksum, not an
    Authority receipt or proof of a current deletion/execution head. The
    caller must commit the receipt-schema installation before publishing the
    snapshot; a rolled-back schema would invalidate its schema digest.
    """
    store._require_recovery_capability(_capability)
    if (type(namespace) is not NamespaceId
            or type(expected) is not GraphRecoveryMetadataV2
            or expected.requirements.namespace != namespace
            or any(type(s) is not str or not s for s in (
                transfer_id, source_installation_id, permit_token))):
        raise ValueError("typed source migration identity required")
    store._ensure_open()
    if not store._db.in_transaction:
        raise RuntimeError("source snapshot requires trusted graph transaction")
    _install_import_receipt_schema(store._db)
    actual = store._decode_recovery(store._recovery_row(namespace), namespace)
    if actual != expected:
        raise IncompleteMigrationClosure("source graph stamp changed")
    epoch = store._db.execute(
        "SELECT revision FROM graph_epochs WHERE bot=? AND persona=?",
        namespace.as_tuple).fetchone()
    epoch = epoch[0] if epoch else 0
    tables = _inventory(store._db, namespace)
    # D06's separate projection is deliberately rebuilt under target fences;
    # it may never certify an absent source until its graph epoch is current.
    deferred = _DEFERRED
    payload = (FORMAT, transfer_id, namespace.as_tuple,
               source_installation_id, permit_token,
               asdict(actual), epoch, _schema_digest(store._db),
               _catalogue_digest(store._db), tables, deferred)
    return NamespaceGraphSnapshotV1(
        transfer_id, namespace, source_installation_id, permit_token,
        actual, epoch, payload[7], payload[8], tables, deferred,
        _hash(payload))


def validate_snapshot_for_isolated_target(target: GraphStore,
                                          snapshot: NamespaceGraphSnapshotV1,
                                          *, _capability: object) -> None:
    """Prepare local receipt schema and check an empty target, without importing."""
    target._require_recovery_capability(_capability)
    _validate_snapshot_payload(snapshot)
    with target._lock:
        target._ensure_open()
        if target._db.in_transaction:
            raise RuntimeError("target preflight needs its own read transaction")
        _install_import_receipt_schema(target._db)
        target._db.execute("BEGIN")
        try:
            _check_empty_target_in_tx(target._db, snapshot)
        finally:
            target._db.execute("ROLLBACK")


def _validate_snapshot_payload(snapshot: NamespaceGraphSnapshotV1) -> None:
    if type(snapshot) is not NamespaceGraphSnapshotV1:
        raise TypeError("typed namespace snapshot required")
    if (type(snapshot.namespace) is not NamespaceId
            or type(snapshot.source_metadata) is not GraphRecoveryMetadataV2
            or snapshot.source_metadata.requirements.namespace != snapshot.namespace
            or type(snapshot.graph_epoch) is not int or snapshot.graph_epoch < 0):
        raise IncompleteMigrationClosure("snapshot graph identity differs")
    payload = (FORMAT, snapshot.transfer_id, snapshot.namespace.as_tuple,
               snapshot.source_installation_id, snapshot.permit_token,
               asdict(snapshot.source_metadata), snapshot.graph_epoch,
               snapshot.schema_digest, snapshot.catalogue_digest,
               snapshot.tables, snapshot.deferred_dependencies)
    if _hash(payload) != snapshot.digest:
        raise IncompleteMigrationClosure("source snapshot digest changed")
    if snapshot.deferred_dependencies != _DEFERRED:
        raise IncompleteMigrationClosure("snapshot recovery obligations differ")


def _check_empty_target_in_tx(db, snapshot: NamespaceGraphSnapshotV1) -> None:
    if (_schema_digest(db) != snapshot.schema_digest
            or _catalogue_digest(db) != snapshot.catalogue_digest):
        raise IncompleteMigrationClosure("target schema or type catalogue differs")
    empty = _inventory(db, snapshot.namespace)
    if empty != tuple((name, columns, ()) for name, columns, _ in snapshot.tables):
        raise IncompleteMigrationClosure("target namespace is not isolated and empty")
    names = tuple(name for name, _, _ in snapshot.tables)
    if (names != tuple(sorted(names)) or len(set(names)) != len(names)
            or set(names) != _table_names(db) - _CATALOGUE - _GLOBAL_EMPTY):
        raise IncompleteMigrationClosure("snapshot table coverage differs")
    _check_snapshot_rows(db, snapshot)


def _check_snapshot_rows(db, snapshot: NamespaceGraphSnapshotV1) -> None:
    namespace = snapshot.namespace.as_tuple
    entries = {name: (columns, rows) for name, columns, rows in snapshot.tables}
    clock_columns, clock_rows = entries.get("runtime_d11_owner_role_clock_originals_v1", ((), ()))
    clock_originals = _clock_original_index(clock_columns, clock_rows) if clock_columns else {}
    lease_columns, leases = entries["runtime_budget_leases"]
    lease_ids = {row[lease_columns.index("lease_id")] for row in leases}
    for name, columns, rows in snapshot.tables:
        if columns != _columns(db, name):
            raise IncompleteMigrationClosure(f"{name} column coverage differs")
        for row in rows:
            if type(row) is not tuple or len(row) != len(columns):
                raise IncompleteMigrationClosure(f"{name} row width differs")
            if name in _CLOCK_LINKED and _clock_row_owner(name, columns, row, clock_originals) != namespace:
                raise IncompleteMigrationClosure("role clock crosses snapshot namespace")
            if name in _SIGNED_JSON:
                owner, lease, payload = _signed_row_metadata(name, columns, row)
                if owner != namespace or lease is not None and lease not in lease_ids:
                    raise IncompleteMigrationClosure("signed resource original crosses snapshot scope")
                if name == "runtime_resource_outcomes":
                    qcols, qrows = entries["runtime_resource_quotes"]
                    if not any(q[qcols.index("quote_id")] == payload["quote_id"] for q in qrows):
                        raise IncompleteMigrationClosure("resource outcome lost its original quote")
            if name in _DIRECT:
                pair = (("bot", "persona") if "bot" in columns else
                        ("bot_id", "persona_id"))
                if not set(pair) <= set(columns) or tuple(
                        row[columns.index(key)] for key in pair) != namespace:
                    raise IncompleteMigrationClosure(f"{name} row crosses namespace")
            if name == "graph_atoms" and _owner_of_token(
                    row[columns.index("token")]) != namespace:
                raise IncompleteMigrationClosure("graph atom token crosses namespace")
            if name == "graph_history":
                if (_owner_of_token(row[columns.index("token")]) != namespace
                        or (row[columns.index("event_bot")],
                            row[columns.index("event_persona")]) != namespace):
                    raise IncompleteMigrationClosure("graph history crosses namespace")
            if name in _TOKEN_LINKED and any(
                    _owner_of_token(row[columns.index(key)]) != namespace
                    for key in ("dependent_token", "dependency_token")):
                raise IncompleteMigrationClosure(f"{name} crosses namespace")
            if name in _LEASE_LINKED and row[columns.index("lease_id")] not in lease_ids:
                raise IncompleteMigrationClosure(f"{name} has absent lease")
            if name == "runtime_budget_leases":
                parent = row[columns.index("parent_id")]
                if parent is not None and parent not in lease_ids:
                    raise IncompleteMigrationClosure("budget parent is absent")
            if name == "runtime_budget_debt_blocks" and row[
                    columns.index("cause_lease_id")] not in lease_ids:
                raise IncompleteMigrationClosure("budget debt cause is absent")
            if name == "runtime_jobs":
                budget = row[columns.index("budget_ref")]
                if budget and budget not in lease_ids:
                    raise IncompleteMigrationClosure("job budget is absent")
            if name == "runtime_encoding_call_bindings_v1" and row[
                    columns.index("budget_lease_id")] not in lease_ids:
                raise IncompleteMigrationClosure("encoding budget is absent")
    recovery_columns, recovery_rows = entries["graph_recovery_metadata_v2"]
    expected = (*namespace, snapshot.source_metadata.requirements.schema,
                GraphStore._recovery_payload(snapshot.source_metadata.requirements),
                snapshot.source_metadata.graph_revision)
    if (recovery_columns != ("bot", "persona", "schema", "requirements_json",
                             "graph_revision") or recovery_rows != (expected,)):
        raise IncompleteMigrationClosure("source recovery row differs from stamp")
    epoch_columns, epoch_rows = entries["graph_epochs"]
    if epoch_columns != ("bot", "persona", "revision") or (
            epoch_rows != ((*namespace, snapshot.graph_epoch),)
            if epoch_rows else snapshot.graph_epoch != 0):
        raise IncompleteMigrationClosure("source graph epoch row differs")


def _read_import_receipt_locked(db, namespace: NamespaceId,
                                transfer_id: str) -> TargetGraphImportReceiptV1 | None:
    row = db.execute(
        "SELECT snapshot_digest,closure_digest,source_graph_revision,"
        "target_graph_revision,receipt_json FROM graph_migration_import_receipts_v1 "
        "WHERE bot=? AND persona=? AND transfer_id=?",
        (*namespace.as_tuple, transfer_id)).fetchone()
    if row is None:
        return None
    data = json.loads(row[4])
    if type(data) is not dict or set(data) != set(
            TargetGraphImportReceiptV1.__dataclass_fields__):
        raise IncompleteMigrationClosure("migration import receipt shape differs")
    data["namespace"] = NamespaceId(**data["namespace"])
    receipt = TargetGraphImportReceiptV1(**data)
    content = asdict(receipt)
    content.pop("graph_commit_digest")
    if (receipt.namespace != namespace or receipt.transfer_id != transfer_id
            or row[:4] != (receipt.snapshot_digest, receipt.closure_digest,
                           receipt.source_graph_revision,
                           receipt.target_graph_revision)
            or receipt.graph_commit_digest != _hash(content)):
        raise IncompleteMigrationClosure("migration import receipt digest differs")
    return receipt


def read_target_import_receipt(target: GraphStore, namespace: NamespaceId,
                               transfer_id: str, *, _capability: object
                               ) -> TargetGraphImportReceiptV1 | None:
    """Reread the immutable import receipt without claiming Authority activation."""
    target._require_recovery_capability(_capability)
    with target._lock:
        target._ensure_open()
        return _read_import_receipt_locked(target._db, namespace, transfer_id)


def import_snapshot_into_isolated_target_in_tx(
        target: GraphStore, snapshot: NamespaceGraphSnapshotV1,
        target_requirements: SnapshotRequirementsV2, transfer_receipt: object,
        *, _capability: object) -> TargetGraphImportReceiptV1:
    """Import and CAS inside W01's trusted graph transaction; never activate.

    W01 must authenticate target_recovery permit and independent journal heads
    before this call. The store-bound verifier must authenticate the transfer
    receipt locally. The caller owns COMMIT/ROLLBACK; a savepoint prevents a
    caught exception from leaving partial imported rows.
    """
    target._require_recovery_capability(_capability)
    _validate_snapshot_payload(snapshot)
    if (type(target_requirements) is not SnapshotRequirementsV2
            or target_requirements.namespace != snapshot.namespace):
        raise ValueError("typed target requirements for snapshot namespace required")
    verifier = target._migration_transfer_verifier
    if verifier is None:
        raise RuntimeError("trusted migration transfer verifier is unavailable")
    proof = verifier.verify_local(transfer_receipt)
    if (type(proof) is not GraphMigrationVerifiedTransferV1
            or proof.transfer_id != snapshot.transfer_id
            or proof.source != snapshot.source_metadata
            or proof.source_snapshot_digest != snapshot.digest
            or proof.target != target_requirements
            or proof.authority_phase != "target_recovering"):
        raise PermissionError("trusted transfer does not bind snapshot and target")
    with target._lock:
        target._ensure_open()
        if not target._db.in_transaction:
            raise RuntimeError("target import requires trusted graph transaction")
        db = target._db
        db.execute("SAVEPOINT graph_migration_import_v1")
        try:
            _install_import_receipt_schema(db)
            prior = _read_import_receipt_locked(
                db, snapshot.namespace, snapshot.transfer_id)
            if prior is not None:
                if (prior.snapshot_digest != snapshot.digest
                        or prior.closure_digest != snapshot.closure_digest
                        or prior.target_graph_incarnation
                           != target_requirements.graph_incarnation
                        or prior.target_activation_generation
                           != target_requirements.activation_generation):
                    raise IncompleteMigrationClosure("migration import replay differs")
                db.execute("RELEASE graph_migration_import_v1")
                return prior
            _check_empty_target_in_tx(db, snapshot)
            # Explicit parent ordering; deferred FK checks still run before
            # the caller commits if this connection enables foreign keys.
            priority = {"runtime_budget_leases": 0, "graph_atoms": 1,
                        "graph_events": 2, "graph_recovery_metadata_v2": 3,
                        "graph_history": 4, "graph_dependencies": 4,
                        "graph_dependency_edges": 4}
            for name, columns, rows in sorted(
                    snapshot.tables, key=lambda item: (priority.get(item[0], 5), item[0])):
                if not rows:
                    continue
                statement = (f"INSERT INTO {name} ({','.join(columns)}) VALUES ("
                             + ",".join("?" for _ in columns) + ")")
                db.executemany(statement, rows)
            if _inventory(db, snapshot.namespace) != snapshot.tables:
                raise IncompleteMigrationClosure("imported graph closure differs")
            changed = target.cas_graph_migration_recovery_metadata(
                snapshot.source_metadata, target_requirements,
                transfer_receipt, _capability=_capability)
            content = dict(
                transfer_id=snapshot.transfer_id,
                namespace=snapshot.namespace,
                snapshot_digest=snapshot.digest,
                closure_digest=snapshot.closure_digest,
                source_graph_revision=snapshot.source_metadata.graph_revision,
                source_graph_incarnation=(
                    snapshot.source_metadata.requirements.graph_incarnation),
                target_graph_revision=changed.graph_revision,
                target_graph_incarnation=target_requirements.graph_incarnation,
                target_activation_generation=target_requirements.activation_generation,
                graph_epoch=snapshot.graph_epoch)
            # The digest covers every receipt field except itself.
            commit_digest = _hash({key: asdict(value) if hasattr(value, "__dataclass_fields__")
                                   else value for key, value in content.items()})
            receipt = TargetGraphImportReceiptV1(
                **content, graph_commit_digest=commit_digest)
            db.execute(
                "INSERT INTO graph_migration_import_receipts_v1 "
                "(bot,persona,transfer_id,snapshot_digest,closure_digest,"
                "source_graph_revision,target_graph_revision,receipt_json) "
                "VALUES(?,?,?,?,?,?,?,?)",
                (*snapshot.namespace.as_tuple, snapshot.transfer_id,
                 snapshot.digest, snapshot.closure_digest,
                 snapshot.source_metadata.graph_revision, changed.graph_revision,
                 canonical_json(_json_value(asdict(receipt)))))
            if _read_import_receipt_locked(db, snapshot.namespace,
                                           snapshot.transfer_id) != receipt:
                raise IncompleteMigrationClosure("import receipt is not rereadable")
            db.execute("RELEASE graph_migration_import_v1")
            return receipt
        except BaseException:
            db.execute("ROLLBACK TO graph_migration_import_v1")
            db.execute("RELEASE graph_migration_import_v1")
            raise


__all__ = ["IncompleteMigrationClosure", "NamespaceGraphSnapshotV1",
           "TargetGraphImportReceiptV1", "seal_source_namespace_in_tx",
           "validate_snapshot_for_isolated_target",
           "import_snapshot_into_isolated_target_in_tx",
           "read_target_import_receipt"]
