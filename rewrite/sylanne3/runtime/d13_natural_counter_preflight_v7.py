"""Core-issued prospective frame and settled CPU before generation's write fence.

This is a finite original-operation continuation. Transport uncertainty is not
converted into no work or a new nonce, and progress never authorizes a model.
"""
from dataclasses import dataclass
from ..authority_service.d13_core_counter_contract_v1 import (D13CurrentFramePrepareSelectorV7,
    D13CoreFrameIntentHeaderV7,D13CounterCPUPrepareInstructionV1,D13CounterAwaitingAccountingV1,
    D13CoreFullWireEnvelopeV1)
from ..host.d13_core_counter_port_v1 import InstalledD13CoreCounterPortV1
from ..runtime_contracts import VersionedRef,canonical_digest
from ..domains.d08.natural_plan import natural_plan_id_v2,natural_plan_key_v2
from ..model_broker.natural_reply_history_v7 import TEMPLATE_VERSION
from .first_ingress_v2 import trusted_upper

@dataclass(frozen=True,slots=True)
class D13CountedNaturalPreflightV7:
    frame:D13CoreFrameIntentHeaderV7
    selector:object
    envelope:D13CoreFullWireEnvelopeV1


def count_before_natural_generation_v7(graph,bootstrap,bundle,*,c02_operation_id,source_ref):
    graph._admin(bootstrap)
    if bundle.model_workflows.natural_generation.template_version!=TEMPLATE_VERSION:
        raise ValueError('V7 independent counter cannot consume another natural template')
    store=graph._GraphCoordinator__store;port=graph._GraphCoordinator__content_fence_v2
    ns=bundle.installation_policy.namespace
    # This is a locator only. Core independently verifies C02/Source/Owner and derives the actual plan.
    with store._lock:
        if store._db.in_transaction:raise ValueError('counter CPU must precede the generation business transaction')
        rows=store._db.execute('SELECT activity_id FROM graph_bundle_operations WHERE bot=? AND persona=? AND operation_id=?',
            (*ns.as_tuple,c02_operation_id)).fetchall()
        if len(rows)!=1:raise ValueError('actual C02 bundle metadata locator is absent or ambiguous')
        metadata,_=graph._v2_graph_stamp(ns)
        plan_key=natural_plan_key_v2(ns,rows[0][0],natural_plan_id_v2(ns,c02_operation_id,source_ref))
    operation='d13-count:'+canonical_digest({'schema':'sylanne3.d13.first-counter-operation.v7','namespace':ns,
        'installation_id':bundle.installation_policy.installation_id,'parent':c02_operation_id,'source_ref':source_ref})[:48]
    selector=D13CurrentFramePrepareSelectorV7(bundle.installation_policy.installation_id,
        metadata.requirements.authority_namespace,ns,c02_operation_id,VersionedRef(plan_key.token,1),operation)
    client=InstalledD13CoreCounterPortV1(port,policy=bundle.d13_wire_policy)
    frame=client.prepare_current_d13_frame_v7(selector)
    if type(frame) is D13CounterCPUPrepareInstructionV1:
        graph.prepare_current_d13_counter_cpu_v1(bootstrap,bundle,instruction=frame)
        frame=client.prepare_current_d13_frame_v7(selector)
    if type(frame) is not D13CoreFrameIntentHeaderV7:
        raise ValueError('original counter CPU preparation remains pending; no model admission')
    now=trusted_upper(port.read_ingress_clock(graph._GraphCoordinator__scene_clock_policy))
    count_selector,result=client.count_original_header_v7(frame=frame,now_utc=now)
    if type(result) is D13CounterAwaitingAccountingV1:
        graph.settle_current_d13_counter_cpu_v1(bootstrap,bundle,frame_intent_id=frame.frame_intent_id,
            counter_operation_id=frame.counter_operation_id,awaiting=result)
        now=trusted_upper(port.read_ingress_clock(graph._GraphCoordinator__scene_clock_policy))
        count_selector,result=client.count_original_header_v7(frame=frame,now_utc=now)
    if type(result) is not D13CoreFullWireEnvelopeV1:
        raise ValueError('original observed counter still needs actual accounting; no model admission')
    return D13CountedNaturalPreflightV7(frame,count_selector,result)


def record_counted_d13_preflight_v7(db,*,bundle,counted,now_utc):
    from ..authority_service.d13_wire_evidence_v7 import (install_d13_core_wire_evidence_schema_v1,
        record_signed_d13_core_wire_evidence_v1)
    if type(counted) is not D13CountedNaturalPreflightV7 or not db.in_transaction:
        raise ValueError('Core count original import requires the actual generation short transaction')
    install_d13_core_wire_evidence_schema_v1(db)
    return record_signed_d13_core_wire_evidence_v1(db,policy=bundle.d13_wire_policy,
        selector=counted.selector,frame=counted.frame,envelope=counted.envelope,now_utc=now_utc)
