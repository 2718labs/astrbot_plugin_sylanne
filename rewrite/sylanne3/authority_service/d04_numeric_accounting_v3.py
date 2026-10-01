"""Actual original numeric CPU accounting; no content or adoption permission."""
from dataclasses import asdict,dataclass
import json
import sqlite3

from ..runtime_contracts import canonical_digest,canonical_serialize
from .contract import AuthorityUnavailable
from .d04_numeric_contract_v3 import (D04NumericBindingV3,D04NumericTerminalV3,
    D04NumericMeasuredCostClosureV3,from_wire as original_from_wire,to_wire as original_to_wire)
from .v2_contract import FencePermitV2,from_wire as fence_from_wire,to_wire as fence_to_wire


@dataclass(frozen=True,slots=True)
class D04NumericHistoricalCostGrantV3:
    permit: FencePermitV2
    original: D04NumericTerminalV3 | D04NumericMeasuredCostClosureV3
    projection_digest: str
    schema: str = "d04.numeric-historical-cost-grant.v3"

    def __post_init__(self):
        if (type(self.permit) is not FencePermitV2 or self.permit.operation!="accounting"
                or type(self.original) not in {D04NumericTerminalV3,D04NumericMeasuredCostClosureV3}
                or self.schema!="d04.numeric-historical-cost-grant.v3"
                or self.permit.namespace!=self.original.binding.authority_namespace
                or self.original.measurement.status not in {"completed","failed"}
                or self.projection_digest!=canonical_digest((self.permit,self.original.digest,"actual_numeric_cost_only"))):
            raise ValueError("historical numeric cost requires actual original accounting grant")

    @property
    def binding(self):return self.original.binding

    @property
    def actual_cpu_ns(self):return self.original.measurement.actual_cpu_ns

    @property
    def actual_cpu_ms(self):return self.original.measurement.actual_cpu_ms

    @property
    def digest(self):return canonical_digest(asdict(self))


def numeric_accounting_to_wire_v3(value):
    if type(value) is not D04NumericHistoricalCostGrantV3:raise TypeError("numeric accounting grant required")
    return {"permit":fence_to_wire(value.permit),"original":original_to_wire(value.original),
        "projection_digest":value.projection_digest,"schema":value.schema}


def numeric_accounting_from_wire_v3(raw):
    if type(raw) is not dict or set(raw)!=set(D04NumericHistoricalCostGrantV3.__dataclass_fields__):
        raise ValueError("numeric accounting grant fields differ")
    kind=(D04NumericMeasuredCostClosureV3 if raw["original"].get("schema")=="d04.numeric-measured-cost-closure.v3" else D04NumericTerminalV3)
    value=D04NumericHistoricalCostGrantV3(fence_from_wire(raw["permit"]),original_from_wire(raw["original"],kind),raw["projection_digest"],raw["schema"])
    if numeric_accounting_to_wire_v3(value)!=raw:raise ValueError("numeric accounting wire is noncanonical")
    return value


def _verify_actual_graph_cost(service,binding,gate):
    from ..runtime.d04_appraisal_driver_v3 import read_d04_original_v3
    from ..runtime.d04_numeric_cost_v3 import read_d04_numeric_cost_original_v3
    from ..graph_store import GraphStore
    from ..graph_types import GraphReceipt,NamespaceEpoch
    db=sqlite3.connect(service.graph_path.as_uri()+"?mode=ro",uri=True,isolation_level=None)
    try:
        db.execute("BEGIN")
        selected=read_d04_original_v3(db,binding.namespace,"numeric_accounting_gate",binding.operation_id)
        receipt=read_d04_original_v3(db,binding.namespace,"numeric_historical_cost",binding.operation_id)
        cost=read_d04_numeric_cost_original_v3(db,binding.namespace,binding.operation_id)
        event_id="d04-numeric-historical:"+canonical_digest((binding.namespace,binding.operation_id))[:48]
        event=db.execute("SELECT revisions,invalidated,epoch_revision FROM graph_events WHERE bot=? AND persona=? AND session=? AND event_id=?",
            (*binding.namespace.as_tuple,binding.activity_id,event_id)).fetchone()
        if (selected is None or numeric_accounting_from_wire_v3(selected[0])!=gate or receipt is None or cost is None or event is None):
            raise AuthorityUnavailable("historical numeric cost lacks actual same-operation Graph originals")
        fact=gate.original;result=receipt[0]
        graph_receipt=GraphReceipt("committed",GraphStore._version_rows(event[0]),GraphStore._version_rows(event[1]),
            NamespaceEpoch(*binding.namespace.as_tuple,event[2]))
        if (cost.binding_digest!=binding.digest or cost.terminal_digest!=fact.digest
                or cost.terminal_ref!=fact.terminal_ref or cost.actual_cpu_ns!=fact.measurement.actual_cpu_ns
                or cost.actual_cpu_ms!=fact.measurement.actual_cpu_ms or result.get("binding_digest")!=binding.digest
                or result.get("original_digest",result.get("terminal_digest"))!=fact.digest
                or result.get("cost_original_digest")!=cost.digest or result.get("event_id")!=event_id
                or result.get("adoption_status")!="not_adopted"
                or result.get("graph_receipt_digest")!=canonical_digest(graph_receipt)):
            raise AuthorityUnavailable("historical numeric actual CPU/event commitments differ")
        metadata=db.execute("SELECT requirements_json FROM graph_recovery_metadata_v2 WHERE bot=? AND persona=?",binding.namespace.as_tuple).fetchone()
        requirements=json.loads(metadata[0]) if metadata else {}
        anchor=gate.permit.pinned_anchor
        if (not service._graph_location_matches(requirements,anchor)
                or (requirements.get("execution_seq"),requirements.get("execution_digest"))!=(anchor.execution_seq,anchor.execution_digest)):
            raise AuthorityUnavailable("historical numeric Graph did not reach its actual accounting anchor")
    finally:
        db.close()


def operate_d04_numeric_accounting_v3(service,binding,action,gate=None):
    from .d04_numeric_service_v3 import AuthorityD04NumericServiceV3
    if type(service) is not AuthorityD04NumericServiceV3 or type(binding) is not D04NumericBindingV3 or action not in {"begin","validate","finish","recover_finish"}:
        raise AuthorityUnavailable("actual installed numeric accounting service/action required")
    service._binding_scope(binding);bridge=service.bridge
    bridge.core._require(service.credential,"accounting",bridge.namespace)
    operation_id="d04-numeric-accounting:"+canonical_digest((binding.authority_namespace,binding.installation_id,binding.execution_id))
    if action!="begin" and (type(gate) is not D04NumericHistoricalCostGrantV3 or gate.binding!=binding or gate.permit.operation_id!=operation_id):
        raise AuthorityUnavailable("numeric accounting exact original grant required")
    if action in {"finish","recover_finish"}:
        with bridge.core._tx() as db:
            bridge.core.require_current_storage_generation_locked(db,namespace=bridge.namespace,action="accounting")
            row=bridge.fences._row(db,operation_id)
            if row is not None and row[6]=="finished":
                if (bridge.fences._permit(row)!=gate.permit or row[8:10]!=(operation_id+":finished","sha256:"+gate.digest)):
                    raise AuthorityUnavailable("numeric accounting finish replay changed original")
                return True
    claim,terminal=service.read_d04_numeric_originals_v3(binding)
    original=terminal or service.read_d04_numeric_measured_cost_closure_v3(binding)
    if claim is None or original is None:
        raise AuthorityUnavailable("numeric claim-only work remains unknown and occupied")
    if action in {"finish","recover_finish"}:
        _verify_actual_graph_cost(service,binding,gate)
    with service._frozen() as (db,deletion,execution):
        anchor,holder=service._current_anchor_locked(db,deletion,execution,action="accounting")
        if (anchor.activation_generation!=binding.activation_generation
                or type(original) is D04NumericMeasuredCostClosureV3 and execution.journal_id!=original.current_anchor.execution_journal_id):
            raise AuthorityUnavailable("numeric historical accounting generation/journal differs")
        if original.terminal_sequence>execution.seq:
            raise AuthorityUnavailable("numeric historical cost is ahead of current independent journal")
        command="sha256:"+canonical_digest((binding.digest,original.digest,"historical_accounting"))
        if action=="begin":
            permit=bridge.fences.begin_fence_locked(db,subject=service._subject,holder=holder,operation="accounting",
                current_anchor=anchor,operation_id=operation_id,command_digest=command)
            return D04NumericHistoricalCostGrantV3(permit,original,canonical_digest((permit,original.digest,"actual_numeric_cost_only")))
        if gate.original!=original or gate.permit.command_digest!=command:
            raise AuthorityUnavailable("historical numeric accounting original changed")
        bridge.fences.validate_fence_locked(db,gate.permit,subject=service._subject,current_anchor=anchor)
        if action in {"finish","recover_finish"}:
            bridge.fences.finish_fence_locked(db,gate.permit,subject=service._subject,current_anchor=anchor,
                request_id=operation_id+":finished",request_digest="sha256:"+gate.digest)
        return True
