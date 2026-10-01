"""Permanent acceptance over actual installed D04 originals, without execution.

The caller has already run the real signed Owner, paid appraisal, full/LOO ABI2,
independent terminal and atomic adoption. This helper never seeds proof rows.
It verifies the C09 installed classifier and closure; it makes no four-file
SWITCHED/CLEANED/RELEASED claim.
"""
from copy import deepcopy
import json
import sqlite3

import pytest

from sylanne3.runtime.c09_d04_originals_v3 import (
    COLUMNS, TABLE, BODY_KINDS, FACT_KINDS, D04ErasureInventoryHold,
    d04_original_dispositions_v3, read_d04_inventory_row_v3,
)
from sylanne3.runtime.c09_graph_rebase_candidate_v1 import _dependency_closure, _nested_hits
from sylanne3.runtime_contracts import canonical_digest, canonical_serialize


def assert_actual_d04_original_erasure_inventory_v3(case, execution):
    """Check content removal and exact accounting retention from real bytes."""
    store, namespace, source = case["store"], case["namespace"], case["source_ref"]
    with store._lock:
        columns = tuple(r[1] for r in store._db.execute(f"PRAGMA table_info({TABLE})"))
        assert columns == COLUMNS
        rows = store._db.execute(f"SELECT * FROM {TABLE} WHERE bot=? AND persona=? ORDER BY kind,original_ref",
            namespace.as_tuple).fetchall()
        closure = _dependency_closure(store._db, {source})
        authority_namespace = json.loads(store._db.execute("SELECT requirements_json FROM graph_recovery_metadata_v2 WHERE bot=? AND persona=?", namespace.as_tuple).fetchone()[0])["authority_namespace"]
    originals = [read_d04_inventory_row_v3(columns, row, authority_namespace=authority_namespace) for row in rows]
    assert {"semantic_mapping", "numeric_prepared", "numeric_artifact", "numeric_claim", "numeric_measurement",
        "numeric_terminal", "numeric_cost", "numeric_accounting_prepared", "numeric_adoption", "joint_evidence_payloads"} <= {
        kind for kind, _, _, _ in originals}
    from sylanne3.graph_types import AtomKey
    dispositions = d04_original_dispositions_v3(columns, rows, affected=closure,
        affected_operations=set(), nested_hits=_nested_hits,
        source_ids={AtomKey.from_token(source).owner.subject}, authority_namespace=authority_namespace)
    removed = {kind for (kind, _, _, _), status in zip(originals, dispositions) if status == "derived_removed"}
    assert {"appraisal", "appraisal_request", "appraisal_result", "appraisal_acceptance", "semantic_mapping",
        "numeric_prepared", "numeric_artifact", "joint_evidence_payloads"} <= removed
    for (kind, _, _, _), status in zip(originals, dispositions):
        assert kind in BODY_KINDS | FACT_KINDS
        if kind in FACT_KINDS:
            assert status == "preserved_exact"
    # Fresh in-memory file construction exercises the exact production row
    # disposition without copying raw source pages or changing live triggers.
    with sqlite3.connect(":memory:") as fresh:
        fresh.execute(f"CREATE TABLE {TABLE}(bot,persona,kind,original_ref,payload_json,payload_digest,"
            "PRIMARY KEY(bot,persona,kind,original_ref))")
        survivors = [row for row, status in zip(rows, dispositions) if status == "preserved_exact"]
        fresh.executemany(f"INSERT INTO {TABLE} VALUES(?,?,?,?,?,?)", survivors)
        actual = fresh.execute(f"SELECT * FROM {TABLE} ORDER BY kind,original_ref").fetchall()
        assert actual == survivors
        assert not removed & {row[2] for row in actual}
        from sylanne3.runtime.d04_numeric_cost_v3 import read_d04_numeric_cost_original_v3
        from sylanne3.runtime.d04_numeric_accounting_prepared_v3 import read_numeric_accounting_prepared_v3
        accounting = read_numeric_accounting_prepared_v3(fresh, namespace, execution.prepared.binding.operation_id)
        cost = read_d04_numeric_cost_original_v3(fresh, namespace, execution.prepared.binding.operation_id)
        assert accounting.binding == execution.prepared.binding
        assert accounting.prepared_digest == execution.prepared.digest
        assert cost.actual_cpu_ns == execution.terminal.measurement.actual_cpu_ns
        assert cost.terminal_digest == execution.terminal.digest
    # Corrupt copies, never successful fabricated originals, must fail closed.
    changed = list(rows[0]); changed[2] = "unrecognized_installed_kind"
    with pytest.raises(D04ErasureInventoryHold, match="unclassified"):
        read_d04_inventory_row_v3(columns, changed, authority_namespace=authority_namespace)
    index = next(i for i, row in enumerate(rows) if row[2] == "numeric_accounting_prepared")
    changed = list(rows[index]); raw = deepcopy(originals[index][2]); raw["read_rows"] = []
    changed[4] = canonical_serialize(raw); changed[5] = canonical_digest(raw)
    with pytest.raises(D04ErasureInventoryHold, match="fields differ"):
        read_d04_inventory_row_v3(columns, changed, authority_namespace=authority_namespace)
    return {"original_count": len(rows), "removed_kind_count": len(removed), "preserved_fact_count": len(survivors)}
