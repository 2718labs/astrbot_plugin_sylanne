"""Fixed positive C03/C04 facts for the existing independent Foreground issuer."""
import json
from ..graph_types import AtomKey
from ..runtime_contracts import canonical_digest
from .c04_self_scope_v4 import PREPARE_OPERATION, PrepareIngressC04RequestV1, ingress_c04_ids_v4
from .c04_ingress_preparation_v4 import ADOPT_OPERATION, self_c04_anchor_refs_v4
from .d06_ingress_c03_selection_v1 import read_adopted_ingress_c03_selection_v1
from .d07_ingress_recall_result_v1 import read_adopted_ingress_recall_routing_v1


def qualify_self_c04_foreground_v4(db, *, request, bundle, issuer):
    from ..authority_service.current_foreground_activity_v1 import (
        _source_family_current_sql_v1, foreground_typed_command_digest_v1)
    from .domain_production_registry_v1 import installed_operation_v1
    if request.operation_kind not in {PREPARE_OPERATION,ADOPT_OPERATION}:
        raise ValueError("only the two fixed Self C04 operations may use child activity")
    actual=read_adopted_ingress_c03_selection_v1(db,namespace=request.namespace,c02_operation_id=request.c02_operation_id)
    if actual is None:
        raise ValueError("Self C04 has no adopted C03 selection")
    selected,original,_=actual
    body=PrepareIngressC04RequestV1(request.c02_operation_id,request.cycle_job_ref,request.cue_source_ref,
        "d06-current:"+original["original_digest"][:48],canonical_digest(selected),bundle.d06_recall.policy_digest)
    ids=ingress_c04_ids_v4(request.namespace,request.c02_operation_id,original["original_digest"])
    if (selected.selected_source_ref is None or selected.namespace!=request.namespace
            or (selected.installation_id,selected.manifest_digest)!=(bundle.installation_policy.installation_id,bundle.installation_policy.manifest_digest)
            or selected.cue_source_ref!=request.cue_source_ref or selected.cycle_job_ref!=request.cycle_job_ref
            or (selected.purpose,selected.audience)!=(request.purpose,request.audiences)
            or selected.child_activity_id!=request.activity_id
            or request.operation_id!=ids["prepare" if request.operation_kind==PREPARE_OPERATION else "adopt"]
            or request.request_digest!=foreground_typed_command_digest_v1(installed_operation_v1(request.operation_kind),body)):
        raise ValueError("Self C04 fixed actual C03/child/command scope differs")
    if request.operation_kind==PREPARE_OPERATION:
        from .c04_association_graph_collector_v2 import _collect_c04_association_graph_originals_from_roots_v2
        from ..domains.d06.current_association_candidates import CurrentAssociationBudgetV1
        routing=read_adopted_ingress_recall_routing_v1(db,namespace=request.namespace,
            c02_operation_id=request.c02_operation_id,issuer=issuer)
        if routing is None or canonical_digest(routing)!=selected.routing_adoption_digest:
            raise ValueError("Self C04 lost its actual routing profile")
        p=next(p for p in bundle.d06_recall.profiles if p.name==routing["mode"])
        policy=bundle.d06_recall
        focus,ticket,mood=self_c04_anchor_refs_v4(db,request.namespace)
        closure=_collect_c04_association_graph_originals_from_roots_v2(db,request.namespace,
            cue_source_ref=selected.cue_source_ref,focus_ref=focus,attention_ticket_ref=ticket,mood_ref=mood,
            budget=CurrentAssociationBudgetV1(p.max_hops,policy.max_edges,p.max_nodes,policy.max_iterations,
                min(p.max_candidates,policy.max_recollection_candidates)),context_tags=(),
            activation_roots=(selected.cue_source_ref,selected.selected_source_ref))
        reads=tuple((row.key,row.revision) for row in closure.reads)
    else:
        from .c04_internal_work_original_v1 import read_c04_internal_work_prepared_v1
        from .c04_frozen_association_original_v3 import read_c04_frozen_association_original_v4, _verify_current_association_input_heads_common_v3
        prepared=read_c04_internal_work_prepared_v1(db,request.namespace,ids["prepare"])
        if prepared is None:
            raise ValueError("Self C04 adoption has no actual prepared original")
        work=read_c04_frozen_association_original_v4(db,request.namespace,prepared.binding)
        if work.direct_selection!=selected:
            raise ValueError("Self C04 adoption borrowed another frozen selection")
        _verify_current_association_input_heads_common_v3(db,work)
        reads=tuple((AtomKey.from_token(row.ref),row.revision) for row in work.reads)
    versions=dict(reads)
    roots=tuple(key.token for key,_ in reads if key.type_name=="memory.source")
    # Keep each existing family's 32-node restriction; aggregate observation is
    # bounded by the already collected C04 input, not an arbitrary roots DTO.
    for root in roots:
        for version in _source_family_current_sql_v1(db,namespace=request.namespace,roots=(root,),
                purpose=request.purpose,audiences=request.audiences):
            previous=versions.get(version.key,version.revision)
            if previous!=version.revision:
                raise ValueError("Self C04 independent Source closure changed")
            versions[version.key]=version.revision
    head=db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=?",
        (selected.selected_source_ref,)).fetchone()
    if head is None or head[2]!=1 or (head[0],canonical_digest(json.loads(head[1])))!=(selected.selected_source_revision,selected.selected_source_digest):
        raise ValueError("Self C04 selected historical Source changed")
    return selected,ids,versions
