"""Actual original root CPU accounting; no content or adoption permission."""
from dataclasses import asdict,dataclass
import json
import sqlite3

from ..runtime_contracts import canonical_digest,canonical_serialize
from .contract import AuthorityUnavailable
from .d04_root_execution_contract_v3 import (D04RootExecutionBindingV3,D04RootExecutionTerminalV3,
    D04RootMeasuredCostClosureV3,root_execution_from_wire_v3 as original_from_wire,root_execution_to_wire_v3 as original_to_wire)
from .v2_contract import FencePermitV2,from_wire as fence_from_wire,to_wire as fence_to_wire


@dataclass(frozen=True,slots=True)
class D04RootHistoricalCostGrantV3:
    permit: FencePermitV2
    original: D04RootExecutionTerminalV3 | D04RootMeasuredCostClosureV3
    projection_digest: str
    schema: str = "d04.root-historical-cost-grant.v3"

    def __post_init__(self):
        if (type(self.permit) is not FencePermitV2 or self.permit.operation!="accounting"
                or type(self.original) not in {D04RootExecutionTerminalV3,D04RootMeasuredCostClosureV3}
                or self.schema!="d04.root-historical-cost-grant.v3"
                or self.permit.namespace!=self.original.binding.authority_namespace
                or self.original.measurement.status not in {"completed","failed"}
                or self.projection_digest!=canonical_digest((self.permit,self.original.digest,"actual_root_cost_only"))):
            raise ValueError("historical root cost requires actual original accounting grant")

    @property
    def binding(self):return self.original.binding

    @property
    def actual_cpu_ns(self):return self.original.measurement.actual_cpu_ns

    @property
    def actual_cpu_ms(self):return self.original.measurement.actual_cpu_ms

    @property
    def digest(self):return canonical_digest(asdict(self))


def root_accounting_to_wire_v3(value):
    if type(value) is not D04RootHistoricalCostGrantV3:raise TypeError("root accounting grant required")
    return {"permit":fence_to_wire(value.permit),"original":original_to_wire(value.original),
        "projection_digest":value.projection_digest,"schema":value.schema}


def root_accounting_from_wire_v3(raw):
    if type(raw) is not dict or set(raw)!=set(D04RootHistoricalCostGrantV3.__dataclass_fields__):
        raise ValueError("root accounting grant fields differ")
    kind=(D04RootMeasuredCostClosureV3 if raw["original"].get("schema")=="d04.authored-root-measured-cost-closure.v3" else D04RootExecutionTerminalV3)
    value=D04RootHistoricalCostGrantV3(fence_from_wire(raw["permit"]),original_from_wire(raw["original"],kind),raw["projection_digest"],raw["schema"])
    if root_accounting_to_wire_v3(value)!=raw:raise ValueError("root accounting wire is noncanonical")
    return value


def _verify_actual_graph_cost(service,binding,gate):
    from ..runtime.d04_appraisal_driver_v3 import read_d04_original_v3
    from ..runtime.d04_root_execution_v3 import root_execution_ids_v3
    from ..graph_store import GraphStore
    from ..graph_types import GraphReceipt,NamespaceEpoch,AtomKey,Owner
    db=sqlite3.connect(service.graph_path.as_uri()+"?mode=ro",uri=True,isolation_level=None)
    try:
        db.execute("BEGIN")
        selected=read_d04_original_v3(db,binding.namespace,"root_accounting_gate",binding.operation_id)
        receipt=read_d04_original_v3(db,binding.namespace,"root_historical_cost",binding.operation_id)
        cost=read_d04_original_v3(db,binding.namespace,"root_cost",binding.operation_id)
        event_id="d04-root-historical:"+canonical_digest((binding.namespace,binding.operation_id))[:48]
        session=root_execution_ids_v3(binding.namespace,binding.operation_id)["activity"]
        event=db.execute("SELECT revisions,invalidated,epoch_revision FROM graph_events WHERE bot=? AND persona=? AND session=? AND event_id=?",(*binding.namespace.as_tuple,session,event_id)).fetchone()
        if (selected is None or root_accounting_from_wire_v3(selected[0])!=gate or receipt is None or cost is None or event is None):raise AuthorityUnavailable("root historical actual originals absent")
        fact=gate.original;result=receipt[0];paid=cost[0]
        actual=GraphReceipt("committed",GraphStore._version_rows(event[0]),GraphStore._version_rows(event[1]),NamespaceEpoch(*binding.namespace.as_tuple,event[2]))
        if (paid.get("binding_digest")!=binding.digest or paid.get("terminal_digest")!=fact.digest
                or (paid.get("actual_cpu_ns"),paid.get("actual_cpu_ms"))!=(fact.measurement.actual_cpu_ns,fact.measurement.actual_cpu_ms)
                or result.get("binding_digest")!=binding.digest or result.get("original_digest")!=fact.digest
                or result.get("cost_original_digest")!=canonical_digest(paid) or result.get("event_id")!=event_id
                or result.get("adoption_status")!="not_adopted" or result.get("graph_receipt_digest")!=canonical_digest(actual)):
            raise AuthorityUnavailable("root historical CPU/event commitments differ")
        write=json.loads(paid["graph_write_json"]);raw=write["key"];ref=AtomKey(Owner(**raw["owner"]),raw["type_name"],raw["name"]).token
        versions={item.key.token:item.revision for item in actual.revisions}
        row=db.execute("SELECT value,valid,event_bot,event_persona,event_session,event_id FROM graph_history WHERE token=? AND revision=?",(ref,versions.get(ref,-1))).fetchone()
        if set(versions)!={ref} or row is None or row[1:]!=(1,*binding.namespace.as_tuple,session,event_id) or json.loads(row[0])!=write["value"]:raise AuthorityUnavailable("root historical CPU actual Graph history differs")
        metadata=db.execute("SELECT requirements_json FROM graph_recovery_metadata_v2 WHERE bot=? AND persona=?",binding.namespace.as_tuple).fetchone()
        req=json.loads(metadata[0]) if metadata else {};anchor=gate.permit.pinned_anchor
        if not service._graph_location_matches(req,anchor) or (req.get("execution_seq"),req.get("execution_digest"))!=(anchor.execution_seq,anchor.execution_digest):raise AuthorityUnavailable("root accounting Graph actual anchor differs")
    finally:db.close()


def operate_d04_root_accounting_v3(service,binding,action,gate=None):
    from .d04_root_execution_service_v3 import AuthorityD04RootExecutionServiceV3
    if type(service) is not AuthorityD04RootExecutionServiceV3 or type(binding) is not D04RootExecutionBindingV3 or action not in {"begin","validate","finish","recover_finish"}:
        raise AuthorityUnavailable("actual installed root accounting service/action required")
    service._binding_scope(binding);bridge=service.bridge
    bridge.core._require(service.credential,"accounting",bridge.namespace)
    operation_id="d04-root-accounting:"+canonical_digest((binding.authority_namespace,binding.installation_id,binding.execution_id))
    if action!="begin" and (type(gate) is not D04RootHistoricalCostGrantV3 or gate.binding!=binding or gate.permit.operation_id!=operation_id):
        raise AuthorityUnavailable("root accounting exact original grant required")
    if action in {"finish","recover_finish"}:
        with bridge.core._tx() as db:
            bridge.core.require_current_storage_generation_locked(db,namespace=bridge.namespace,action="accounting")
            row=bridge.fences._row(db,operation_id)
            if row is not None and row[6]=="finished":
                if (bridge.fences._permit(row)!=gate.permit or row[8:10]!=(operation_id+":finished","sha256:"+gate.digest)):
                    raise AuthorityUnavailable("root accounting finish replay changed original")
                return True
    claim,terminal=service.read_d04_root_originals_v3(binding)
    original=terminal or service.read_d04_root_measured_cost_closure_v3(binding)
    if claim is None or original is None:
        raise AuthorityUnavailable("root claim-only work remains unknown and occupied")
    if action in {"finish","recover_finish"}:
        _verify_actual_graph_cost(service,binding,gate)
    with service._frozen() as (db,deletion,execution):
        anchor,holder=service._current_anchor_locked(db,deletion,execution,action="accounting")
        if (anchor.activation_generation!=binding.activation_generation
                or type(original) is D04RootMeasuredCostClosureV3 and execution.journal_id!=original.current_anchor.execution_journal_id):
            raise AuthorityUnavailable("root historical accounting generation/journal differs")
        if original.terminal_sequence>execution.seq:
            raise AuthorityUnavailable("root historical cost is ahead of current independent journal")
        command="sha256:"+canonical_digest((binding.digest,original.digest,"historical_accounting"))
        if action=="begin":
            permit=bridge.fences.begin_fence_locked(db,subject=service._subject,holder=holder,operation="accounting",
                current_anchor=anchor,operation_id=operation_id,command_digest=command)
            return D04RootHistoricalCostGrantV3(permit,original,canonical_digest((permit,original.digest,"actual_root_cost_only")))
        if gate.original!=original or gate.permit.command_digest!=command:
            raise AuthorityUnavailable("historical root accounting original changed")
        bridge.fences.validate_fence_locked(db,gate.permit,subject=service._subject,current_anchor=anchor)
        if action in {"finish","recover_finish"}:
            bridge.fences.finish_fence_locked(db,gate.permit,subject=service._subject,current_anchor=anchor,
                request_id=operation_id+":finished",request_digest="sha256:"+gate.digest)
        return True
