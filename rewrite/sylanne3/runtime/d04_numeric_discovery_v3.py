"""Bounded recovery discovery from already committed appraisal stage originals."""
import json
from ..graph_types import AtomKey
from ..runtime_contracts import NamespaceId
from .d04_installed_numeric_v3 import numeric_ids_v3


def discover_pending_d04_numeric_v3(graph, bootstrap, bundle, *, after=None, limit=32):
    graph._admin(bootstrap)
    if type(limit) is not int or not 1 <= limit <= 32 or after is not None and type(after) is not str:
        raise ValueError("D04 discovery requires a bounded stable operation cursor")
    if bundle.d04_joint_numeric is None or bundle.d04_semantic_drive is None:
        return {"items": (), "next_after": None}
    assembly = graph._GraphCoordinator__d04_installed_joint_assembly
    if assembly is None or assembly.admin_bundle is not bundle:
        raise ValueError("D04 recovery discovery is not this installed assembly")
    ns, store = bundle.installation_policy.namespace, graph._GraphCoordinator__store
    with store._lock:
        db = store._db
        db.execute("BEGIN")
        try:
            rows = db.execute("SELECT operation_id,c02_operation_id,source_ref,receipt_json "
                "FROM graph_d04_installed_stage_attempts_v3 WHERE bot=? AND persona=? AND stage='adopt' "
                "AND receipt_json IS NOT NULL AND operation_id>? ORDER BY operation_id LIMIT ?",
                (*ns.as_tuple, after or "", limit + 1)).fetchall()
            items = []
            for operation, c02, source, receipt in rows[:limit]:
                value = json.loads(receipt)
                key = AtomKey.from_token(source)
                if key.type_name != "memory.source" or NamespaceId.from_key(key) != ns:
                    raise ValueError("D04 recovery original source scope is invalid")
                if value.get("status") != "adopted":
                    continue
                if db.execute("SELECT 1 FROM graph_first_ingress_c02_committed_seals_v2 "
                        "WHERE bot=? AND persona=? AND operation_id=?", (*ns.as_tuple, c02)).fetchone() is None:
                    raise ValueError("D04 adopted appraisal lost its original committed C02")
                numeric = numeric_ids_v3(ns, c02)["operation"]
                if db.execute("SELECT 1 FROM graph_d04_originals_v3 WHERE bot=? AND persona=? "
                        "AND original_ref=? AND kind IN ('numeric_adoption','numeric_historical_cost')",
                        (*ns.as_tuple, numeric)).fetchone():
                    continue
                refusal = db.execute("SELECT 1 FROM graph_d04_installed_stage_attempts_v3 WHERE bot=? AND persona=? "
                    "AND c02_operation_id=? AND stage IN ('drive','numeric_prepare') "
                    "AND json_extract(receipt_json,'$.status')='held'", (*ns.as_tuple, c02)).fetchone()
                if refusal is None:
                    items.append({"c02_operation_id": c02, "source_ref": source})
            return {"items": tuple(items), "next_after": rows[limit - 1][0] if len(rows) > limit else None}
        finally:
            db.rollback()
