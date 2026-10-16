"""One canonical production DDL for optional installed W01 feature stores.

Both source construction and empty target construction call these functions.
The migration schema commitment is over sqlite_master's exact SQL bytes; no DDL
is read from the source database or supplied by a transfer request.
"""
from __future__ import annotations


def install_d12_compile_attempt_schema_v1(db):
    db.execute("""CREATE TABLE IF NOT EXISTS graph_d12_compile_attempts_v1 (
        bot TEXT NOT NULL, persona TEXT NOT NULL, operation_id TEXT NOT NULL,
        request_digest TEXT NOT NULL, attempt_id TEXT NOT NULL,
        PRIMARY KEY(bot,persona,operation_id), UNIQUE(attempt_id))""")
    db.execute("""CREATE TRIGGER IF NOT EXISTS graph_d12_compile_attempt_no_update_v1
        BEFORE UPDATE ON graph_d12_compile_attempts_v1
        BEGIN SELECT RAISE(ABORT, 'D12 compile attempt is immutable'); END""")
    db.execute("""CREATE TRIGGER IF NOT EXISTS graph_d12_compile_attempt_no_delete_v1
        BEFORE DELETE ON graph_d12_compile_attempts_v1
        BEGIN SELECT RAISE(ABORT, 'D12 compile attempt is immutable'); END""")


def install_d12_adoption_schema_v1(db):
    db.execute("""CREATE TABLE IF NOT EXISTS graph_d12_adoption_operations_v1 (
        bot TEXT NOT NULL, persona TEXT NOT NULL, operation_id TEXT NOT NULL,
        request_digest TEXT NOT NULL, attempt_id TEXT NOT NULL,
        receipt_json TEXT NOT NULL, receipt_sha256 TEXT NOT NULL,
        PRIMARY KEY(bot,persona,operation_id), UNIQUE(attempt_id))""")
    db.execute("""CREATE TRIGGER IF NOT EXISTS graph_d12_adoption_no_update_v1
        BEFORE UPDATE ON graph_d12_adoption_operations_v1
        BEGIN SELECT RAISE(ABORT, 'D12 adoption is immutable'); END""")
    db.execute("""CREATE TRIGGER IF NOT EXISTS graph_d12_adoption_no_delete_v1
        BEFORE DELETE ON graph_d12_adoption_operations_v1
        BEGIN SELECT RAISE(ABORT, 'D12 adoption is immutable'); END""")


def install_d12_original_model_cost_schema_v1(db):
    db.execute("""CREATE TABLE IF NOT EXISTS graph_original_model_cost_attempts_v1 (
        bot TEXT NOT NULL, persona TEXT NOT NULL,
        call_id TEXT NOT NULL, intent_digest TEXT NOT NULL,
        attempt_id TEXT NOT NULL, anchor_json TEXT NOT NULL,
        state TEXT NOT NULL CHECK(state IN ('open','closed','committed')),
        PRIMARY KEY(bot, persona, call_id), UNIQUE(attempt_id))""")


def install_d12_installed_graph_schema_v1(db):
    """Install empty tables only, in the caller's existing schema transaction."""
    if not db.in_transaction:
        raise RuntimeError("installed Graph schema transaction required")
    from .scheme_original_store_v1 import install_scheme_original_store_v1
    from .d12_compiled_candidate_store_v1 import install_d12_compiled_candidate_store_v1
    install_scheme_original_store_v1(db)
    install_d12_compiled_candidate_store_v1(db)
    install_d12_compile_attempt_schema_v1(db)
    install_d12_adoption_schema_v1(db)
    install_d12_original_model_cost_schema_v1(db)
    from .domain_production_originals_v1 import install_domain_production_originals_v1
    from .domain_production_commit_v1 import install_domain_production_outbox_v1
    install_domain_production_originals_v1(db)
    from .d03_world_history_v1 import install_world_history_schema_v1
    install_world_history_schema_v1(db)
    install_domain_production_outbox_v1(db)
    from .d07_execution_v1 import install_d07_execution_schema_v1
    install_d07_execution_schema_v1(db)
    from .d07_graph_stages_v1 import install_d07_graph_stage_schema_v1
    install_d07_graph_stage_schema_v1(db)
    from .d07_accounting_v1 import install_d07_accounting_schema_v1
    install_d07_accounting_schema_v1(db)



__all__ = ("install_d12_compile_attempt_schema_v1", "install_d12_adoption_schema_v1",
           "install_d12_original_model_cost_schema_v1", "install_d12_installed_graph_schema_v1")
