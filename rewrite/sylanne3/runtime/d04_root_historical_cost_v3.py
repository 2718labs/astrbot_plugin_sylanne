"""Close independently measured authored-root CPU without adopting its content."""
from dataclasses import asdict, replace
from types import SimpleNamespace
import time

from ..contracts import Event, Scope
from ..graph_store import GraphStore
from ..graph_types import GraphCandidate, GraphVersion
from ..runtime_contracts import canonical_digest
from .d04_appraisal_driver_v3 import read_d04_original_v3, record_d04_original_in_transaction_v3
from .d04_root_accounting_prepared_v3 import read_root_accounting_prepared_v3, decode_root_accounting_prepared_payload_v3
from .d04_root_adoption_execution_v3 import _stage_root_actual_cpu_v3
from .d04_root_execution_v3 import root_execution_ids_v3


def settle_historical_root_cpu_v3(graph, bootstrap, bundle, *, operation_id):
    from .c04_authority_port_v3 import InstalledC04AuthorityPortV3
    from ..authority_service.d04_root_accounting_v3 import (
        D04RootHistoricalCostGrantV3, root_accounting_to_wire_v3, root_accounting_from_wire_v3)
    graph._admin(bootstrap)
    port, store = graph._GraphCoordinator__c04_authority_port_v3, graph._GraphCoordinator__store
    if type(port) is not InstalledC04AuthorityPortV3 or port._bundle is not bundle:
        raise ValueError("root historical CPU requires its actual paired installation")
    namespace = bundle.installation_policy.namespace
    with store._lock:
        db = store._db
        db.execute("BEGIN")
        try:
            saved = read_root_accounting_prepared_v3(db, namespace, operation_id,
                resource_issuer=graph._GraphCoordinator__d02_issuer,
                budget_issuer=graph._GraphCoordinator__d11_issuer)
            completed = read_d04_original_v3(db, namespace, "root_historical_cost", operation_id)
            original_gate = read_d04_original_v3(db, namespace, "root_accounting_gate", operation_id)
            adopted = read_d04_original_v3(db, namespace, "root_execution_link", operation_id)
        finally:
            db.rollback()
    if saved is None or adopted is not None:
        raise ValueError("root historical CPU is absent or already adopted atomically")
    raw, _ = saved
    binding, _, _, _, _ = decode_root_accounting_prepared_payload_v3(raw)
    if completed is not None:
        if original_gate is None:
            raise ValueError("root historical cost lacks its original accounting gate")
        gate = root_accounting_from_wire_v3(original_gate[0])
        port.root_accounting(binding, "recover_finish", gate)
        return completed[0]
    gate = port.root_accounting(binding, "begin")
    if type(gate) is not D04RootHistoricalCostGrantV3 or gate.original.binding != binding:
        raise ValueError("root actual historical CPU gate differs")
    original = gate.original
    prepared = SimpleNamespace(binding=binding, digest=raw["prepared_digest"],
        quote_payload_json=raw["quote_payload_json"], reserve_receipt_json=raw["reserve_receipt_json"])
    port.root_accounting(binding, "validate", gate)
    with store._lock:
        db = store._db
        db.execute("BEGIN IMMEDIATE")
        try:
            if read_root_accounting_prepared_v3(db, namespace, operation_id,
                    resource_issuer=graph._GraphCoordinator__d02_issuer,
                    budget_issuer=graph._GraphCoordinator__d11_issuer) != saved:
                raise ValueError("root historical accounting original changed")
            before, epoch = graph._v2_graph_stamp(namespace)
            anchor = gate.permit.pinned_anchor
            target = replace(before.requirements, deletion_seq=anchor.deletion_seq,
                deletion_digest=anchor.deletion_digest, execution_seq=anchor.execution_seq,
                execution_digest=anchor.execution_digest, revocation_epoch=anchor.revocation_epoch)
            if not graph._anchor_matches(target, anchor):
                raise ValueError("root historical selected storage/namespace generation differs")
            record_d04_original_in_transaction_v3(db, namespace, "root_accounting_gate", operation_id,
                root_accounting_to_wire_v3(gate))
            cost, write = _stage_root_actual_cpu_v3(graph, db, prepared, original)
            if db.execute("SELECT 1 FROM graph_atoms WHERE token=?", (write.key.token,)).fetchone():
                raise ValueError("root historical cost atom exists without closure original")
            event_id = "d04-root-historical:" + canonical_digest((namespace, operation_id))[:48]
            activity = root_execution_ids_v3(namespace, operation_id)["activity"]
            candidate = GraphCandidate(Event(Scope(*namespace.as_tuple, activity), event_id, time.time(),
                "d04.authored_root_historical_cpu.v3", {"binding_digest": binding.digest,
                "original_digest": original.digest}), (GraphVersion(write.key, 0),), (write,), (epoch,))
            def record(_db, receipt):
                store.cas_graph_recovery_metadata(before, target, _capability=graph._GraphCoordinator__graph_capability)
            receipt = GraphStore._graph_commit_in_transaction(store, candidate,
                _receipt_hook=record, _capability=graph._GraphCoordinator__graph_capability)
            if receipt.status != "committed":
                raise ValueError("root actual historical CPU event did not commit")
            result = {"schema": "d04.authored-root-historical-cost.v3", "operation_id": operation_id,
                "binding_digest": binding.digest, "original_digest": original.digest,
                "cost_original_digest": canonical_digest(cost), "event_id": event_id,
                "graph_receipt_digest": canonical_digest(receipt), "adoption_status": "not_adopted",
                "execution_status": original.measurement.status,
                "actual_cpu_ns": original.measurement.actual_cpu_ns, "actual_cpu_ms": original.measurement.actual_cpu_ms}
            record_d04_original_in_transaction_v3(db, namespace, "root_historical_cost", operation_id, result)
            db.commit()
        except BaseException:
            db.rollback()
            raise
    port.root_accounting(binding, "finish", gate)
    return result
