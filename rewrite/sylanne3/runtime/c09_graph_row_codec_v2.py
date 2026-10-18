"""Per-original C09 domain codecs; no V1 all-original collection wrapper.

Each result belongs to one already byte-reserved source row. Family identity
links are returned only for that row and stored by the durable closure producer.
Accounting joins use exact source SQL keys rather than namespace dictionaries.
"""
from __future__ import annotations

from dataclasses import dataclass,asdict

from .c09_paged_sql_v2 import C09PagedCaptureHold


@dataclass(frozen=True, slots=True)
class C09DomainRowV2:
    family: str
    kind: str
    original_ref: str
    payload: object
    original_commitment: str
    body_bearing: bool


_D04_IDENTITIES=frozenset({'operation_id','job_id','call_id','original_ref','appraisal_ref',
    'root_ref','root_digest','predecessor_ref','predecessor_digest','numeric_operation_id',
    'numeric_prepared_digest','prepared_digest','binding_digest','input_digest','result_digest'})
_D07_IDENTITIES=frozenset({'operation_id','job_id','call_id','execution_id','prepared_digest',
    'binding_digest','result_digest','actual_result_digest','interpretation_ref','input_digest',
    'original_operation_id','stage_input_digest'})
_CONTACT_IDENTITIES=frozenset({'job_id','call_id','prepared_digest','binding_digest',
    'producing_operation_id','plan_original_digest','contact_id','model_request_digest'})


def read_c09_domain_row_v2(table,columns,row,*,authority_namespace,issuer):
    from . import c09_d04_originals_v3 as d04
    from . import c09_d07_execution_v1 as d07
    from . import c09_contact_originals_v1 as contact
    from . import c09_contact_originals_v2 as contact2
    from . import domain_production_erasure_v1 as domain
    from .contact_plan_adoption_v3 import TABLE as PLAN3_TABLE,COLUMNS as PLAN3_COLUMNS,SIGN_KIND as PLAN3_SIGN,validate_contact_plan_original_payload_v3
    from .c09_contact_effect_accounting_v1 import GRAPH_TABLES, validate_graph_financial_row_v1
    if table=="graph_world_revision_erasure_barriers_v1":
        from .d03_world_history_v1 import decode_world_erasure_barrier_row_v1,ERASURE_SIGN_KIND
        value=decode_world_erasure_barrier_row_v1(columns,row)
        from ..runtime_contracts import namespace_ref,canonical_digest
        if authority_namespace is not None and namespace_ref(value.namespace)!=authority_namespace:
            raise C09PagedCaptureHold('World barrier differs from actual Authority namespace')
        issuer._signer.verify(ERASURE_SIGN_KIND,row[8],row[10])
        kind,ref,raw,digest,body='world_erasure_barrier',canonical_digest(tuple(row[:4])),asdict(value),row[9],False
    elif table=="graph_owner_goal_cancellation_projections_v1":
        from .owner_goal_projection_v1 import validate_goal_projection_row_v1
        observed,receipt=validate_goal_projection_row_v1(columns,row,issuer=issuer)
        kind,ref,raw,digest,body="goal_metadata_projection",receipt.operation_id,asdict(receipt),receipt.digest,False
    elif table=='graph_contact_prospective_successors_v1':
        from .contact_prospective_v1 import read_c09_contact_successor_row_v1
        kind,ref,raw,digest=read_c09_contact_successor_row_v1(columns,row,authority_namespace=authority_namespace,issuer=issuer)
        body=True
    elif table=='graph_contact_prospective_originals_v1':
        from .contact_prospective_v1 import read_c09_contact_prospective_row_v1
        kind,ref,raw,digest=read_c09_contact_prospective_row_v1(columns,row,authority_namespace=authority_namespace,issuer=issuer)
        body=True
    elif table=='graph_contact_segment_originals_v1':
        from .contact_continuation_v1 import read_c09_contact_segment_row_v1
        kind,ref,raw,digest=read_c09_contact_segment_row_v1(columns,row,authority_namespace=authority_namespace,issuer=issuer)
        body=True
    elif table in GRAPH_TABLES:
        kind,ref,raw,digest=validate_graph_financial_row_v1(table,columns,row,issuer=issuer)
        body=False
    elif table == PLAN3_TABLE:
        from .contact_plan_adoption_v3 import contact_plan_logical_descriptor_v3
        from ..runtime_contracts import NamespaceId,canonical_digest,canonical_serialize,namespace_ref
        if tuple(columns)!=PLAN3_COLUMNS or len(row)!=len(PLAN3_COLUMNS):
            raise C09PagedCaptureHold('Contact Plan3 exact physical original columns differ')
        raw = contact_plan_logical_descriptor_v3(row)
        ns = NamespaceId(row[0],row[1])
        if namespace_ref(ns)!=authority_namespace:
            raise C09PagedCaptureHold('Contact Plan3 physical original namespace differs')
        issuer._signer.verify(PLAN3_SIGN,canonical_serialize(raw),row[13])
        kind,ref,digest,body = 'plan_physical',row[2],row[8],True
    elif table==d04.TABLE:
        kind,ref,raw,digest=d04.read_d04_inventory_row_v3(columns,row,authority_namespace=authority_namespace)
        body=kind in d04.BODY_KINDS
    elif table==d07.TABLE:
        kind,ref,raw,digest=d07.read_d07_inventory_row_v1(columns,row,authority_namespace=authority_namespace,issuer=issuer)
        body=kind in d07.BODY_KINDS
    elif table==contact.TABLE:
        kind,ref,raw,digest=contact.read_contact_inventory_row_v1(columns,row,authority_namespace=authority_namespace,issuer=issuer)
        body=kind in contact.BODY_KINDS
    elif table==contact2.TABLE:
        kind,ref,raw,digest=contact2.read_contact_inventory_row_v2(columns,row,authority_namespace=authority_namespace,issuer=issuer)
        body=kind in contact2.BODY_KINDS
    elif table in domain.DERIVED_STORE_TABLES_V6:
        kind,ref,raw,digest=domain._validate_derived_store_row_v6(table,columns,row,authority_namespace=authority_namespace)
        body=table=='graph_d11_derived_cache_payloads_v1'
    elif table in domain.TABLE_COLUMNS and table not in domain.DERIVED_STORE_TABLES_V6:
        kind,ref,raw,digest=domain.validate_domain_production_row_v1(table,columns,row,authority_namespace=authority_namespace)
        body=table not in domain.SOURCE_INDEPENDENT_POLICY_TABLES
        if table=='graph_d05_production_policies_v1' and raw.get('schema_version') is None: body=False
        if table=='graph_d11_life_originals_v1':
            from .c09_life_originals_v1 import FACT_KINDS,life_original_content_projection_v1
            if kind in FACT_KINDS:
                if domain.domain_production_source_closure_v1(table,kind,row[columns.index('payload_json')]):
                    raise C09PagedCaptureHold('Life accounting fact unexpectedly carries Source body references')
                body=False
        elif table=='graph_d11_offline_originals_v1' and kind in {
                'accounting_prepared','historical_accounting_gate','historical_accounting_receipt',
                'cancellation_gate','cancellation_receipt'}:
            if domain.domain_production_source_closure_v1(table,kind,row[columns.index('payload_json')]):
                raise C09PagedCaptureHold('offline accounting fact unexpectedly carries Source body references')
            body=False
    else:
        raise C09PagedCaptureHold('domain row requires its registered V2 codec: '+table)
    return C09DomainRowV2(table,kind,ref,raw,digest,body)


def c09_domain_nested_payload_v2(original):
    from .c09_d04_originals_v3 import TABLE as d04,decoded_nested_original_v3
    from .c09_d07_execution_v1 import TABLE as d07,decoded_nested_d07_original_v1
    from .c09_contact_originals_v1 import TABLE as contact
    from .c09_contact_originals_v2 import TABLE as contact2
    if original.family=='graph_d11_life_originals_v1':
        from .c09_life_originals_v1 import life_original_content_projection_v1
        return life_original_content_projection_v1(original.kind,original.payload)
    if original.family==d04: return decoded_nested_original_v3(original.payload)
    if original.family in {d07,contact,contact2}: return decoded_nested_d07_original_v1(original.payload)
    return original.payload


def iter_c09_domain_identity_links_v2(original):
    from .c09_d04_originals_v3 import TABLE as d04
    from .c09_d07_execution_v1 import TABLE as d07
    from .c09_contact_originals_v1 import TABLE as contact
    from .c09_contact_originals_v2 import TABLE as contact2
    if original.family==d04: names=_D04_IDENTITIES;suffixes=('_original_ref','_original_digest','_prepared_digest','_binding_digest')
    elif original.family==d07: names=_D07_IDENTITIES;suffixes=()
    elif original.family in {contact,contact2}: names=_CONTACT_IDENTITIES;suffixes=()
    else:
        from .domain_production_erasure_v1 import _linked_identities
        yield from _linked_identities(c09_domain_nested_payload_v2(original))
        return
    yield from _identities(c09_domain_nested_payload_v2(original),names,suffixes)


def _identities(value,names,suffixes):
    if type(value) is dict:
        for name,item in value.items():
            if type(item) is str and (name in names or suffixes and name.endswith(suffixes)): yield item
            elif type(item) in {dict,list}: yield from _identities(item,names,suffixes)
    elif type(value) is list:
        for item in value: yield from _identities(item,names,suffixes)


def verify_c09_d07_accounting_join_v2(original,*,read_original):
    """read_original(kind,ref) is the exact metered frozen-source SQL lookup."""
    if original.kind not in {'paid_cost','partial_cost','body_cost','call'}: return
    account=read_original('accounting_prepared',original.original_ref)
    if account is None: raise C09PagedCaptureHold('D07 actual fact lacks its accounting preparation')
    raw=original.payload;prepared=account.payload
    if original.kind=='call':
        if ((raw['job_id'],raw['call_id'],raw['binding_digest'],raw['budget_reservation_operation_id'],raw['budget_reservation_digest'])!=
                (prepared['job_id'],prepared['call_id'],prepared['prepared_digest'],prepared['operation_id'],prepared['reservation_digest'])):
            raise C09PagedCaptureHold('D07 actual call differs from its original once reservation')
    elif raw['prepared_digest']!=prepared['prepared_digest'] or read_original('call',original.original_ref) is None:
        raise C09PagedCaptureHold('D07 actual paid cost differs from its once call')


def verify_c09_contact_accounting_join_v2(original,*,read_original,read_account_by_digest):
    raw=original.payload;ref=original.original_ref;kind=original.kind
    if kind in {'call','paid_cost','terminal','prepare_commit'}:
        account=read_original('accounting_prepared',ref)
        if account is None: raise C09PagedCaptureHold('Contact actual fact lacks its accounting preparation')
        prepared=account.payload
        if kind=='call':
            if ((raw['job_id'],raw['call_id'],raw['binding_digest'],raw['budget_reservation_operation_id'],raw['budget_reservation_digest'])!=
                    (prepared['job_id'],prepared['call_id'],prepared['prepared_digest'],prepared['prepare_operation_id'],prepared['reservation_digest'])):
                raise C09PagedCaptureHold('Contact actual call differs from its once reservation')
        elif raw['prepared_digest']!=prepared['prepared_digest'] or kind in {'paid_cost','terminal'} and read_original('call',ref) is None:
            raise C09PagedCaptureHold('Contact actual paid fact differs from its original call')
    elif kind=='stage_attempt':
        account=read_account_by_digest(raw['prepared_digest'])
        if account is None or account.payload['job_id']!=raw['job_id']:
            raise C09PagedCaptureHold('Contact stage lacks its actual accounting preparation')
    elif kind in {'stage_permit','stage_receipt'}:
        attempt=read_original('stage_attempt',ref)
        if attempt is None or raw['attempt_id']!=attempt.payload['attempt_id']:
            raise C09PagedCaptureHold('Contact stage completion lacks its durable attempt')

        if kind=='stage_receipt':
            from .c09_contact_originals_v2 import TABLE as contact2
            if original.family==contact2 and (raw['prepared_digest']!=attempt.payload['prepared_digest'] or raw['operation_id']!=ref):
                raise C09PagedCaptureHold('Contact V2 actual stage receipt differs from its original attempt')


def iter_c09_typed_graph_edges_v2(db,key,decoded):
    """Exact V1 physical deletion directions for one validated typed Graph row.

    The caller stores each edge with the actual source page ordinal/commitment;
    this generator neither scans Graph nor collects edges across a namespace.
    """
    import json
    from ..graph_types import AtomKey
    from ..runtime_contracts import NamespaceId
    GraphRebaseHold=C09PagedCaptureHold
    token=key.token
    if key.type_name == 'd09.natural_batch_disposition.v1':
        from ..domains.d09.natural_disposition_v1 import natural_disposition_from_wire_v1
        try:
            disposition = natural_disposition_from_wire_v1(decoded)
            if disposition.namespace != NamespaceId.from_key(key) or key.owner.kind != 'activity' or key.owner.subject != disposition.activity_id:
                raise ValueError('natural disposition metadata changed its actual owner identity')
            for version in disposition.dependency_refs:
                dependency = AtomKey.from_token(version.ref)
                if NamespaceId.from_key(dependency) != disposition.namespace or dependency.type_name not in {'memory.source', 'memory.access', 'd06.source_correction_head.v1'}:
                    raise ValueError('natural disposition source qualification closure differs')
        except (ValueError, TypeError, KeyError) as exc:
            raise GraphRebaseHold('natural disposition exact Source-bearing metadata differs; HOLD') from exc
    from .internal_life_content_adoption_v1 import PROVENANCE as LCP, decode_content_v1, content_keys_v1
    if key.type_name == LCP:
        try:
            proof = decode_content_v1(LCP, decoded)
            keys = content_keys_v1(proof.trace.episode_ref)
            if key != keys[1]:
                raise ValueError('content provenance locator differs')
            from .d04_root_original_store_v1 import _receipt
            receipt = _receipt(db, proof.trace.namespace, proof.trace.producing_operation_id)
            members = {v.key.token for v in receipt.write_versions}
            content = {v.token for v in keys}
            jobs = members - content
            if len(members) != 4 or not content <= members or len(jobs) != 1 or (AtomKey.from_token(next(iter(jobs))).type_name != 'runtime.job'):
                raise ValueError('content adoption four-member receipt differs')
            references = {proof.trace.episode_ref, *(r.ref for r in proof.historical_reads), *(r.ref for r in proof.current_reads)}
            yield from ((member, ref) for member in members for ref in references)
            yield from ((member, sibling) for member in members for sibling in members if member != sibling)
        except (TypeError, ValueError, KeyError) as exc:
            raise GraphRebaseHold('Life content historical closure unreadable; HOLD') from exc
    from .d06_internal_life_episode_v2 import KINDS as IK, PROVENANCE as IP, ELIGIBILITY as IE, decode_internal_life_value_v2
    from .d06_internal_life_trace_v3 import TRACE as IT, decode_internal_life_trace_v3
    if key.type_name == IT:
        trace = decode_internal_life_trace_v3(decoded)
        yield (token, trace.episode_ref)
        yield (token, trace.encoding_baseline_ref)
        yield from ((token, ref) for ref in (trace.perspective_ref, *trace.then_feeling_refs, *trace.interpretation_refs))
    if key.type_name in IK:
        proof = decode_internal_life_value_v2(key.type_name, decoded)
        if key.type_name == IP:
            yield from ((token, row.ref) for row in proof.historical_reads)
            yield from ((proof.event.event_ref, token), (proof.episode.episode_ref, token))
        elif key.type_name == IE:
            yield from ((token, proof.episode_ref), (token, proof.event_ref), (token, proof.provenance_ref))
    from ..domains.d09.contact_batch_v2 import PROVENANCE as CP, ELIGIBILITY as CE, decode_contact_batch_companion_v2, contact_batch_keys_v2
    from ..domains.d08.contact_plan_v2 import PROVENANCE as CPP, ELIGIBILITY as CPE, decode_contact_plan_member_v2, contact_plan_keys_v2
    from ..domains.d08.contact_plan_v3 import PROVENANCE as CPP3,ELIGIBILITY as CPE3,decode_contact_plan_member_v3,contact_plan_keys_v3
    if key.type_name in {CPP3,CPE3}:
        proof3 = decode_contact_plan_member_v3(key.type_name,decoded)
        if key.type_name == CPP3:
            if key != contact_plan_keys_v3(proof3.plan)[1]:
                raise GraphRebaseHold('Contact Plan3 metadata historical provenance key differs')
            yield from ((token,row.ref) for row in proof3.historical_reads)
            yield (contact_plan_keys_v3(proof3.plan)[0].token,token)
        else:
            yield from ((token,proof3.plan_ref.ref),(token,proof3.provenance_ref.ref))
    if key.type_name in {CPP, CPE}:
        proof = decode_contact_plan_member_v2(key.type_name, decoded)
        if key.type_name == CPP:
            if key != contact_plan_keys_v2(proof.plan)[1]:
                raise GraphRebaseHold('Contact Plan v2 exact historical provenance key differs; HOLD')
            yield from ((token, row.ref) for row in proof.historical_reads)
            yield (contact_plan_keys_v2(proof.plan)[0].token, token)
        else:
            yield from ((token, proof.plan_ref.ref), (token, proof.provenance_ref.ref))
    if key.type_name in {CP, CE}:
        proof = decode_contact_batch_companion_v2(key.type_name, decoded)
        if key.type_name == CP:
            if key != contact_batch_keys_v2(proof.batch.content.namespace, proof.batch.content.activity_id, proof.batch.content.contact_id)[1]:
                raise GraphRebaseHold('Contact v2 historical provenance key differs; HOLD')
            yield from ((token, row.ref) for row in proof.historical_reads)
            yield (contact_batch_keys_v2(proof.batch.content.namespace, proof.batch.content.activity_id, proof.batch.content.contact_id)[0].token, token)
        else:
            yield from ((token, proof.batch_ref), (token, proof.provenance_ref))
    from ..domains.d09.contact_batch_v3 import PROVENANCE as CP3, ELIGIBILITY as CE3, decode_contact_batch_companion_v3, contact_batch_keys_v3
    if key.type_name in {CP3, CE3}:
        proof3 = decode_contact_batch_companion_v3(key.type_name, decoded)
        if key.type_name == CP3:
            batch_keys3 = contact_batch_keys_v3(proof3.batch.content.namespace, proof3.batch.content.activity_id, proof3.batch.content.contact_id)
            if key != batch_keys3[1]:
                raise GraphRebaseHold('Contact3 exact historical provenance key differs; HOLD')
            yield from ((token, row.ref) for row in proof3.historical_reads)
            yield (batch_keys3[0].token, token)
        else:
            yield from ((token, proof3.batch_ref), (token, proof3.provenance_ref))
    from .d10_life_progress_provenance_v1 import PROVENANCE_TYPE as PP, ELIGIBILITY_TYPE as PE, decode_life_progress_auxiliary_v1
    if key.type_name in {PP, PE}:
        proof = decode_life_progress_auxiliary_v1(key.type_name, decoded)
        if key.type_name == PP:
            yield from ((token, proof.terminal_provenance_ref), (proof.fact_ref, token))
        else:
            yield from ((token, proof.fact_ref), (token, proof.provenance_ref), (token, proof.terminal_eligibility_ref))
    from .d11_life_fact_provenance_v1 import PROVENANCE_TYPE, ELIGIBILITY_TYPE, decode_life_fact_auxiliary_v1
    if key.type_name in {PROVENANCE_TYPE, ELIGIBILITY_TYPE}:
        proof = decode_life_fact_auxiliary_v1(key.type_name, decoded)
        if key.type_name == PROVENANCE_TYPE:
            yield from ((token, row.ref) for row in proof.reads)
            yield (proof.fact_ref, token)
        else:
            yield from ((token, proof.fact_ref), (token, proof.provenance_ref))
    from .d11_life_outcome_provenance_v1 import PROVENANCE_TYPE as OP, ELIGIBILITY_TYPE as OE, decode_life_outcome_auxiliary_v1
    if key.type_name in {OP, OE}:
        proof = decode_life_outcome_auxiliary_v1(key.type_name, decoded)
        if key.type_name == OP:
            yield from ((token, proof.terminal_provenance_ref), (token, proof.action_ref), (proof.fact_ref, token))
        else:
            yield from ((token, proof.fact_ref), (token, proof.provenance_ref), (token, proof.terminal_eligibility_ref))


def classify_c09_domain_row_v2(original,columns,row,*,closure,nested_hit,origin,verify_original_joins):
    """One source row in the real closure round, with family-local links only.

    nested_hit must be the completed paged Source/atom sweep for this same row.
    verify_original_joins is the installed driver's real point-original reader;
    an accounting fact is preserved only after its actual joins were checked.
    """
    if type(nested_hit) is not bool or type(original) is not C09DomainRowV2:
        raise C09PagedCaptureHold('complete actual domain-row reference sweep required')
    verify_original_joins(original)
    if not original.body_bearing:return 'preserved_exact'
    from .domain_production_erasure_v1 import domain_production_source_closure_v1,TABLE_COLUMNS
    values=dict(zip(columns,row,strict=True))
    hit=(closure.contains_atom(original.original_ref) or closure.contains_operation(original.original_ref)
        or closure.contains_domain_link(original.family,original.original_ref)
        or any(closure.contains_operation(values[name]) for name in ('producing_operation_id','job_id')
            if name in values and values[name] is not None)
        or nested_hit)
    if not hit and original.family in TABLE_COLUMNS:
        hit=any(closure.contains_atom(ref) for ref in domain_production_source_closure_v1(
            original.family,original.kind,values['payload_json']))
    if not hit:hit=any(closure.contains_domain_link(original.family,ref) or closure.contains_operation(ref) or closure.contains_atom(ref) for ref in iter_c09_domain_identity_links_v2(original))
    if not hit:return 'preserved_exact'
    if closure._state()[3]=='sealed':return 'derived_removed'
    closure.add_domain_link(original.family,original.original_ref,**origin)
    closure.add_domain_link(original.family,original.original_commitment,**origin)
    for ref in iter_c09_domain_identity_links_v2(original):closure.add_domain_link(original.family,ref,**origin)
    return 'derived_removed'


def verify_c09_life_domain_join_v2(db,original,columns,row,*,index,read_d07_original=None):
    """Actual full signed Life original and registered unique point parents."""
    if original.family!='graph_d11_life_originals_v1':raise C09PagedCaptureHold('actual Life family required')
    from ..runtime_contracts import NamespaceId
    from .c09_life_originals_v1 import (decode_life_original_content_v1,validate_life_original_join_row_v2,
        validate_c4_original_join_row_v2,validate_c4_phase_original_join_row_v3,C4_KINDS,C4_PHASE_KINDS)
    values=dict(zip(columns,row,strict=True));ns=NamespaceId(values['bot'],values['persona'])
    value=decode_life_original_content_v1(original.kind,values['payload_json'])
    args=dict(ns=ns,kind=original.kind,ref=original.original_ref,op=values['producing_operation_id'],
        value=value,raw=original.payload,digest=original.original_commitment,read_original=index.life_point_original)
    if original.kind in C4_KINDS:
        validate_c4_original_join_row_v2(db,**args,read_prepared_by_call=index.life_prepared_by_call)
    elif original.kind in C4_PHASE_KINDS:
        validate_c4_phase_original_join_row_v3(db,**args,read_prepared_by_call=index.life_prepared_by_call)
    else:validate_life_original_join_row_v2(db,**args,read_d07_original=read_d07_original)


def classify_c09_shared_original_row_v2(db,row,*,registry,closure,nested_hit):
    """Validate one W01 original/receipt and its completed reference sweep."""
    import json
    from ..runtime_contracts import NamespaceId
    from .domain_production_original_codec_v1 import decode_domain_production_original_row_v1
    from .domain_production_originals_v1 import _receipt
    if type(nested_hit) is not bool:raise C09PagedCaptureHold('completed actual shared-row nested sweep required')
    ns=NamespaceId(row[0],row[1]);actual=decode_domain_production_original_row_v1(row,ns,registry=registry)
    receipt=_receipt(json.loads(row[10]));op=actual['operation_id']
    bundle=db.execute('SELECT digest,activity_id,effect_id,commit_seq FROM graph_bundle_operations WHERE bot=? AND persona=? AND operation_id=?',(*ns.as_tuple,op)).fetchone()
    if bundle!=(receipt.operation_digest,receipt.activity_id,receipt.effect_id,receipt.commit_seq):
        raise C09PagedCaptureHold('shared original lacks actual Graph bundle receipt')
    payload=json.loads(row[7]);contact=row[3]=='d08' and row[4] in {'prepare_contact_dispatch','prepare_contact_dispatch_v3'}
    if contact:
        from .c09_contact_final_v1 import validate_contact_final_original_joins_v1
        validate_contact_final_original_joins_v1(db,namespace=ns,operation_id=op,payload=payload,receipt=receipt,original_digest=row[6],registry=registry)
    removed=closure.contains_operation(op) or any(closure.contains_atom(ref) for ref in actual['graph_refs']) or nested_hit
    if contact and removed:
        from .c09_contact_final_v1 import require_contact_final_erasure_finish_v1
        require_contact_final_erasure_finish_v1(payload['provenance'],db=db,namespace=ns,operation_id=op)
    return 'derived_removed' if removed else 'preserved_exact'


def classify_c09_shared_outbox_row_v2(db,row,*,closure,read_causal_disposition):
    """Actual causal/child originals; callback must independently verify each."""
    import json
    from ..runtime_contracts import NamespaceId
    from .domain_production_original_codec_v1 import decode_domain_production_outbox_row_v1
    ns=NamespaceId(row[0],row[1]);actual=decode_domain_production_outbox_row_v1(row,ns,db=db)
    if row[8]=='retired':return 'preserved_exact'
    from .c09_paged_sql_v2 import current_c09_sql_meter_v2
    from .domain_production_original_codec_v1 import ORIGINAL_COLUMNS
    meter=current_c09_sql_meter_v2()
    linked=meter.read_fixed_row(db,'graph_domain_production_originals_v1',ORIGINAL_COLUMNS,
        'bot=? AND persona=? AND operation_id=?',(*ns.as_tuple,actual['causal_operation_id']))
    if linked is None:raise C09PagedCaptureHold('active shared outbox lacks its exact causal original')
    if row[5]=='actual_internal_experience_requires_encoding':
        from .domain_production_originals_v1 import read_adopted_domain_operation_v1
        from .domain_production_contracts_v1 import ProductionOutboxStageV1,ProductionOriginalRefV1
        from .domain_production_followups_v1 import verify_current_followup_trigger_v1
        event=ProductionOutboxStageV1(ns,row[3],row[4],row[5],ProductionOriginalRefV1('d10.actual_life_experience',row[6],row[7]))
        verify_current_followup_trigger_v1(db,ns,event,read_adopted_domain_operation_v1(db,ns,actual['causal_operation_id']),None)
    elif row[10] is None and row[5]=='actual_offline_simulation_experiences_require_encoding':
        raise C09PagedCaptureHold('offline outbox trigger requires its actual installed original reader')
    elif row[5]!='actual_internal_experience_requires_encoding' and (row[7]!=linked[6] or row[6]!=linked[3]+'-current:'+linked[6][:48]):
        raise C09PagedCaptureHold('shared outbox trigger differs from its exact causal original')
    causal=read_causal_disposition(ns,actual['causal_operation_id'])
    if causal is None:raise C09PagedCaptureHold('active shared outbox lacks its actual causal original')
    removed=causal=='derived_removed' or closure.contains_atom(actual['original_ref']) or closure.contains_operation(actual['causal_operation_id'])
    if row[10] is not None:
        for command in json.loads(row[10])['completed_commands']:
            child=read_causal_disposition(ns,command['operation_id'])
            if child is None:raise C09PagedCaptureHold('shared outbox lost its actual completed child')
            removed=removed or child=='derived_removed'
    return 'derived_removed' if removed else 'preserved_exact'


def classify_c09_derived_store_row_v2(db,table,columns,row,*,closure,authority_namespace,require_erased_fact,meter):
    """One actual D13 payload/activation/wire fact and its exact paid/history joins.

    require_erased_fact is the installed actual-candidate or prior private view
    consumer. It must prove the exact metadata marker and retained row inside
    its signed/full-EOF disposition roots; marker existence alone is insufficient.
    """
    from .domain_production_erasure_v1 import (_validate_derived_store_row_v6,_json,DomainProductionErasureHold,
        _derived_store_metadata_history_key_v6,_require_derived_payload_metadata_closure_v6,
        DERIVED_WIRE_FACT_TABLES_V6,_derived_wire_metadata_members_v6)
    from ..graph_types import AtomKey,GraphVersion
    from ..runtime_contracts import NamespaceId,canonical_digest
    from ..domains.d13.derived_block_metadata_v2 import decode_derived_block_metadata_history_v2
    from ..graph_coordinator import namespace_ref
    kind, ref, raw, digest = _validate_derived_store_row_v6(table, columns, row)
    data = dict(zip(columns, row))
    ns = NamespaceId(data['bot'], data['persona'])
    if authority_namespace is not None and namespace_ref(ns) != authority_namespace:
        return 'preserved_exact'
    if table in DERIVED_WIRE_FACT_TABLES_V6:
        members = _derived_wire_metadata_members_v6(table, raw)
    else:
        key = _derived_store_metadata_history_key_v6(db,ns,data['block_ref'],data.get('after_revision'),meter=meter)
        members = [(key, data.get('after_revision'), data.get('after_digest'))]
    removed = False
    for key, revision, expected_digest in members:
        if revision is None:
            archived = db.execute('SELECT revision,value,valid,event_id,event_bot,event_persona,event_session FROM graph_history WHERE token=? ORDER BY revision DESC LIMIT 1', (key.token,)).fetchone()
        else:
            archived = db.execute('SELECT revision,value,valid,event_id,event_bot,event_persona,event_session FROM graph_history WHERE token=? AND revision=?', (key.token, revision)).fetchone()
        if archived is None:
            raise DomainProductionErasureHold('derived evidence has no exact historical metadata member')
        archived_value=_json(archived[1])
        erased_marker={'schema':'sylanne3.graph.erased_value.v1','key_digest':canonical_digest(key.token)}
        if archived_value == erased_marker:
            if archived[2]!=0:raise DomainProductionErasureHold('derived erased marker claims a valid metadata head')
            if table == 'graph_d11_derived_cache_payloads_v1':
                raise DomainProductionErasureHold('erased metadata cannot preserve its derived body BLOB')
            require_erased_fact(db,table,columns,row,namespace=ns,key=key,revision=archived[0],meter=meter)
            continue
        metadata = decode_derived_block_metadata_history_v2(key,archived_value)
        if (expected_digest is not None and canonical_digest(metadata) != expected_digest) or (table not in DERIVED_WIRE_FACT_TABLES_V6 and metadata.payload_digest != data['payload_digest']):
            raise DomainProductionErasureHold('derived metadata differs from actual cache/evidence commitments')
        if table == 'graph_d11_derived_cache_payloads_v1':
            from ..domains.d13.provider import _block_from_graph_value
            block = _block_from_graph_value(raw)
            _require_derived_payload_metadata_closure_v6(metadata,block)
            if len(data['payload_bytes']) != metadata.payload_length_bytes or block.source_dependencies != metadata.source_dependencies or block.job_ref != metadata.job_ref or (block.candidate_ref != metadata.candidate_ref):
                raise DomainProductionErasureHold('derived payload lost actual metadata Source/paid-family ownership')
            paid = db.execute('SELECT operation_id,original_digest FROM graph_d13_paid_intent_originals_v1 WHERE bot=? AND persona=? AND job_ref=?', (*ns.as_tuple, metadata.job_ref)).fetchone()
            if paid != (metadata.paid_original_operation_id, metadata.paid_original_digest):
                raise DomainProductionErasureHold('derived payload lacks its actual paid original identity')
            removed = any(closure.contains_atom(ref) for ref in (key.token,*(source.ref for source in metadata.source_dependencies))) or closure.contains_operation(metadata.paid_original_operation_id)
        elif table == 'graph_d13_derived_activations_v6':
            previous = db.execute('SELECT value,valid FROM graph_history WHERE token=? AND revision=?', (key.token, data['before_revision'])).fetchone()
            if previous is None:raise DomainProductionErasureHold('derived activation lost its actual prior metadata')
            previous_value=_json(previous[0]);decode_derived_block_metadata_history_v2(key,previous_value)
            if (canonical_digest(previous_value)!=data['before_digest']
                    or archived[3]!=data['operation_id'] or metadata.status!='active'):
                raise DomainProductionErasureHold('derived activation lost its actual before/after Graph receipt transition')
            from ..graph_types import GraphReceipt, NamespaceEpoch
            from ..graph_store import GraphStore
            event = db.execute('SELECT revisions,invalidated,epoch_revision FROM graph_events WHERE bot=? AND persona=? AND session=? AND event_id=?', (*ns.as_tuple, archived[6], data['operation_id'])).fetchone()
            if event is None or archived[4:6] != ns.as_tuple:
                raise DomainProductionErasureHold('derived activation has no actual same-namespace Graph event receipt')
            receipt = GraphReceipt('committed', GraphStore._version_rows(event[0]), GraphStore._version_rows(event[1]), NamespaceEpoch(*ns.as_tuple, event[2]))
            if canonical_digest(receipt) != data['receipt_digest'] or GraphVersion(key, data['after_revision']) not in receipt.revisions:
                raise DomainProductionErasureHold('derived activation receipt digest differs from its actual original Graph event')
    return 'derived_removed' if removed else 'preserved_exact'


from .c09_canonical_json_stream_v2 import C09CanonicalJSONStreamV2


class C09MemoryAccessJSONStreamV3(C09CanonicalJSONStreamV2):
    """Actual Access metadata without another whole-object JSON round trip."""
    def __init__(self,*,source_arena=None,**profile):
        import weakref
        super().__init__(**profile)
        self.fields=set();self.metadata={};self.scalar=bytearray();self.unique={};self.decoded_bytes=0
        self._source_arena=weakref.WeakSet() if source_arena is None else source_arena
        self._source_arena.add(self)

    def _source_heap_bytes(self):
        import sys
        return (sys.getsizeof(self.__dict__)+sys.getsizeof(self.fields)+sys.getsizeof(self.metadata)
            +sys.getsizeof(self.scalar)+sys.getsizeof(self.unique)+self.decoded_bytes
            +sum(sys.getsizeof(value) for value in self.metadata.values() if type(value) is list)
            +sum(sys.getsizeof(value) for value in self.unique.values()))

    def _require_arena(self,extra=0):
        from .c09_paged_sql_v2 import current_c09_sql_meter_v2
        meter=current_c09_sql_meter_v2()
        if sum(parser._source_heap_bytes() for parser in self._source_arena)+extra>meter.budget.reserved_arena_bytes:
            raise C09PagedCaptureHold('actual Access metadata/copies exceed reserved arena')

    def copy(self):
        from copy import deepcopy
        self._require_arena(self._source_heap_bytes())
        result=super().copy()
        result.__dict__.update(deepcopy({name:value for name,value in self.__dict__.items() if name!='_source_arena'}))
        result._source_arena=self._source_arena;self._source_arena.add(result);self._require_arena();return result

    def _emit(self,emit,kind,path,start,end,**values):
        import json,sys
        from ..memory_types import _ACCESS_FIELDS
        arrays={'audiences','purposes'}
        if kind=='key':
            if len(path)!=1 or values['key'] not in _ACCESS_FIELDS:raise ValueError('memory access fields must match exactly')
            self.fields.add(values['key'])
        elif kind in ('object_start','array_start'):
            if kind=='object_start':
                if path:raise TypeError('Access field cannot be an object')
            elif len(path)!=1 or path[0] not in arrays:raise TypeError('Access field has another registered JSON type')
            else:self.metadata[path[0]]=[];self.unique[path[0]]=set()
        elif kind=='scalar_start':
            if (not path or len(path)>2 or path[0] not in _ACCESS_FIELDS
                    or len(path)==1 and path[0] in arrays or len(path)==2 and path[0] not in arrays):
                raise TypeError('Access scalar has another registered JSON path')
            self.scalar.clear()
        elif kind=='scalar_chunk':
            self._require_arena(len(values['raw'])*4+sys.getsizeof(self.scalar)+16384)
            self.scalar.extend(values['raw'])
        elif kind=='scalar_end':
            self._require_arena(len(self.scalar)*4+sys.getsizeof('')+16384)
            value=json.loads(self.scalar);self.decoded_bytes+=sys.getsizeof(value)
            if len(path)==1:self.metadata[path[0]]=value
            else:
                if type(value) is not str:raise ValueError('Access array item must be a string')
                seen=self.unique[path[0]]
                if value in seen:raise ValueError('Access arrays must contain unique strings')
                self._require_arena(sys.getsizeof(value)+sys.getsizeof(seen)*4+16384)
                seen.add(value);self.metadata[path[0]].append(value)
            self.scalar.clear();self._require_arena()
        super()._emit(emit,kind,path,start,end,**values)

    def finish(self):
        import sys
        from ..memory_types import _ACCESS_FIELDS,validate_access_metadata_v1
        result=super().finish()
        if self.fields!=_ACCESS_FIELDS:raise ValueError('memory access fields must match exactly')
        copies=sum(sys.getsizeof(())+len(value)*sys.getsizeof(None)
            for value in self.metadata.values() if type(value) is list)
        sets=sum(sys.getsizeof(value)*4 for value in self.unique.values())
        self._require_arena(copies+sets+16384)
        validate_access_metadata_v1(**self.metadata)
        return result


class C09MemorySourceJSONStreamV3(C09CanonicalJSONStreamV2):
    """Exact SourceRecord semantics without retaining the source text.

    Parser integrity and semantic completion confer no capture or read authority.
    Metadata and array uniqueness use the actual quantum's reserved arena.
    """
    def __init__(self, *, source_arena=None, atom_pattern=None, **profile):
        super().__init__(**profile)
        self._source_fields = set()
        self._source_metadata = {}
        self._source_scalar = bytearray()
        self._source_text_characters = 0
        self._source_text_nonempty = False
        self._source_text_high = None
        self._source_unique = {}
        self._source_decoded_bytes = 0
        import weakref
        self._source_arena = weakref.WeakSet() if source_arena is None else source_arena
        self._source_arena.add(self)
        self._source_atom_pattern=atom_pattern
        self._source_atom_prefix=[]
        self._source_atom_prefix_bytes=0
        self._source_atom_position=0
        self._source_atom_hit=False
        if atom_pattern is not None:
            if type(atom_pattern) is not str or not atom_pattern:
                raise ValueError('actual nonempty atom pattern required')
            self._source_require_arena(len(atom_pattern)*(__import__('sys').getsizeof(0)+8))
            for index,char in enumerate(atom_pattern):
                matched=0 if index==0 else self._source_atom_prefix[-1]
                while matched and atom_pattern[matched]!=char:
                    matched=self._source_atom_prefix[matched-1]
                if index and atom_pattern[matched]==char:matched+=1
                self._source_atom_prefix.append(matched)
                self._source_atom_prefix_bytes+=__import__('sys').getsizeof(matched)


    def _source_heap_bytes(self):
        import sys
        total = sys.getsizeof(self.__dict__) + sys.getsizeof(self._source_fields)
        total += sys.getsizeof(self._source_metadata) + sys.getsizeof(self._source_scalar)
        total += sys.getsizeof(self._source_unique)
        total += self._source_decoded_bytes
        total += sum(sys.getsizeof(value) for value in self._source_metadata.values() if type(value) is list)
        total += sum(sys.getsizeof(value) for value in self._source_unique.values())
        total += sys.getsizeof(self._source_atom_pattern)+sys.getsizeof(self._source_atom_prefix)
        total += self._source_atom_prefix_bytes
        return total

    def _source_require_arena(self, extra=0):
        from .c09_paged_sql_v2 import current_c09_sql_meter_v2
        meter = current_c09_sql_meter_v2()
        if meter is None:
            raise C09PagedCaptureHold('Source semantic stream requires its actual reserved quantum')
        retained = sum(parser._source_heap_bytes() for parser in self._source_arena)
        if retained + extra > meter.budget.reserved_arena_bytes:
            raise C09PagedCaptureHold('Source semantic retained objects/copy exceed its reserved arena')

    def copy(self):
        from copy import deepcopy
        self._source_require_arena(self._source_heap_bytes())
        result = super().copy()
        result.__dict__.update(deepcopy({name: value for name, value in self.__dict__.items()
            if name != '_source_arena'}))
        result._source_arena = self._source_arena
        result._source_arena.add(result)
        result._source_require_arena()
        return result

    def _source_character(self,codepoint):
        from ..memory_types import _MAX_TEXT_LENGTH
        self._source_text_characters += 1
        self._source_text_nonempty = True
        if self._source_text_characters > _MAX_TEXT_LENGTH:
            raise ValueError('text must contain at most 65536 characters')
        pattern=self._source_atom_pattern
        if pattern is not None and not self._source_atom_hit:
            char=chr(codepoint);matched=self._source_atom_position
            while matched and pattern[matched]!=char:matched=self._source_atom_prefix[matched-1]
            if pattern[matched]==char:matched+=1
            self._source_atom_hit=matched==len(pattern)
            self._source_atom_position=matched


    def _append_decoded_codepoint(self, codepoint):
        state = self._string
        if state is None or state['mode'] != 'value' or state['path'] != ('text',):
            return super()._append_decoded_codepoint(codepoint)
        high = self._source_text_high
        if high is not None:
            self._source_text_high = None
            if 0xdc00 <= codepoint <= 0xdfff:
                self._source_character(0x10000+((high-0xd800)<<10)+codepoint-0xdc00)
                return
            self._source_character(high)
        if 0xd800 <= codepoint <= 0xdbff:
            self._source_text_high = codepoint
        else:
            self._source_character(codepoint)

    def _emit(self, emit, kind, path, start, end, **values):
        import json
        from ..memory_types import _SOURCE_FIELDS
        arrays = {'audiences', 'purposes', 'parent_source_ids'}
        if kind == 'key':
            if len(path) != 1 or values['key'] not in _SOURCE_FIELDS:
                raise ValueError('source record fields must match exactly')
            self._source_fields.add(values['key'])
        elif kind in ('object_start', 'array_start'):
            if kind == 'object_start':
                if path:
                    raise TypeError('source record field cannot be an object')
            elif len(path) != 1 or path[0] not in arrays:
                raise TypeError('source record field must have its registered JSON type')
            else:
                self._source_metadata[path[0]] = []
                self._source_unique[path[0]] = set()
        elif kind == 'scalar_start':
            if (not path or len(path) > 2 or path[0] not in _SOURCE_FIELDS
                    or (len(path) == 1 and path[0] in arrays)
                    or (len(path) == 2 and path[0] not in arrays)):
                raise TypeError('source record scalar has another registered field path')
            if path == ('text',):
                if values['scalar_kind'] != 'string':
                    raise TypeError('text must be a string')
            else:
                self._source_scalar = bytearray()
        elif kind == 'scalar_chunk' and path != ('text',):
            raw = values['raw']
            # Account real retained strings and containers across both parser
            # passes and quantum copies, rather than a multiplier on JSON bytes.
            import sys
            self._source_require_arena(len(raw) * 4 + sys.getsizeof(self._source_scalar) + 16384)
            self._source_scalar.extend(raw)
        elif kind == 'scalar_end':
            if path == ('text',):
                if self._source_text_high is not None:
                    self._source_character(self._source_text_high)
                    self._source_text_high = None
                if not self._source_text_nonempty:
                    raise ValueError('text must be a nonempty string')
            else:
                import sys
                self._source_require_arena(len(self._source_scalar) * 4 + sys.getsizeof('') + 16384)
                decoded = json.loads(self._source_scalar)
                self._source_decoded_bytes += sys.getsizeof(decoded)
                if len(path) == 1:
                    self._source_metadata[path[0]] = decoded
                else:
                    if type(decoded) is not str:
                        raise ValueError('Source array item must be a nonempty string')
                    seen = self._source_unique[path[0]]
                    if decoded in seen:
                        raise ValueError('Source arrays must contain unique strings')
                    self._source_require_arena(sys.getsizeof(decoded) + sys.getsizeof(seen) * 4 + 16384)
                    seen.add(decoded)
                    self._source_metadata[path[0]].append(decoded)
                self._source_scalar = bytearray()
                self._source_require_arena()
        super()._emit(emit, kind, path, start, end, **values)

    def finish(self):
        from ..memory_types import validate_source_metadata_v1, _SOURCE_FIELDS
        import sys
        tuple_copies = sum(sys.getsizeof(()) + len(value) * sys.getsizeof(None)
            for value in self._source_metadata.values() if type(value) is list)
        # The original tuple/set validator owns temporary containers too; retain
        # explicit headroom based on the actual unique-set capacities.
        validation_sets = sum(sys.getsizeof(value) * 4 for value in self._source_unique.values())
        self._source_require_arena(tuple_copies + validation_sets + 16384)
        result = super().finish()
        if self._source_fields != _SOURCE_FIELDS or not self._source_text_nonempty:
            raise ValueError('source record fields must match exactly')
        # The same metadata rules serve the actual SourceRecord constructor;
        # original text was validated character by character without retention.
        metadata = dict(self._source_metadata)
        for name in ('audiences', 'purposes', 'parent_source_ids'):
            metadata[name] = tuple(metadata[name])
        validate_source_metadata_v1(**metadata)
        return result



class C09MemorySourceRowCaptureV3:
    """Private frozen Source row capture; a restart rebuilds from actual byte zero."""
    def __init__(self,build,shape,key,metadata,*,pattern_kind=None,pattern_ref=None):
        from .c09_graph_rebase_candidate_v2 import InstalledGraphRebaseBuildV2
        from ..graph_types import AtomKey
        from .c09_paged_sql_v2 import begin_c09_row_commitment_v2,begin_c09_json_cell_commitment_v2
        if type(build) is not InstalledGraphRebaseBuildV2 or shape.table not in {'graph_atoms','graph_history'}:
            raise C09PagedCaptureHold('actual installed Graph Source capture required')
        build.require_current()
        atom=AtomKey.from_token(key[0])
        if (atom.type_name!='memory.source' or atom.owner.kind!='event'
                or (atom.owner.bot,atom.owner.persona)!=tuple(__import__('json').loads(build.scope.graph_namespace))):
            raise C09PagedCaptureHold('actual Source capture belongs to another registered namespace/type')
        source=build.pair.source
        from .c09_paged_sql_v2 import _quote,current_c09_sql_meter_v2
        where=' AND '.join(_quote(name)+' COLLATE BINARY = ?' for name in shape.primary_key_columns)
        revision=current_c09_sql_meter_v2().read_fixed_row(source,shape.table,('revision',),where,key)
        value_kind,value_size=metadata[shape.columns.index('value')]
        if revision is None or value_kind!='text':
            raise C09PagedCaptureHold('actual Source capture revision/text is absent')
        self.build,self.shape,self.key,self.metadata=build,shape,key,metadata
        self.row=begin_c09_row_commitment_v2(source,shape,key,metadata)
        self.value=begin_c09_json_cell_commitment_v2(source,shape,key,'value',
            expected_size=value_size,expected_revision=revision[0])
        self.pattern_kind,self.pattern_ref=pattern_kind,pattern_ref
        self.value.parser=C09MemorySourceJSONStreamV3(ensure_ascii=True,
            source_arena=build.session._source_parser_arena_v3,
            atom_pattern=pattern_ref if pattern_kind=='atom' else None)
        self.quantum_completed=False

    def next_quantum(self,budget):
        """Return an isolated prospective state; caller retains it after real exit."""
        from copy import copy
        import codecs
        from .c09_paged_sql_v2 import advance_c09_row_commitment_v2,advance_c09_json_cell_commitment_v2,current_c09_sql_meter_v2
        self.build.require_current()
        result=copy(self);result.quantum_completed=False
        result.row=copy(self.row);result.row.row_hash=self.row.row_hash.copy()
        if self.row.blob_hash is not None:result.row.blob_hash=self.row.blob_hash.copy()
        if self.row.utf8 is not None:
            result.row.utf8=codecs.getincrementaldecoder('utf-8')('strict')
            result.row.utf8.setstate(self.row.utf8.getstate())
        result.value=copy(self.value);result.value.parser=self.value.parser.copy()
        if not result.row.complete:
            advance_c09_row_commitment_v2(self.build.pair.source,self.shape,budget,cursor=result.row,meter=current_c09_sql_meter_v2())
        elif not result.value.complete:
            advance_c09_json_cell_commitment_v2(self.build.pair.source,self.shape,budget,cursor=result.value,meter=current_c09_sql_meter_v2())
        self.build.require_current()
        return result

    def require_complete(self,build,shape,key,metadata):
        build.require_current()
        if (self.build is not build or self.shape!=shape or self.key!=key or self.metadata!=metadata
                or not self.quantum_completed or not self.row.complete or not self.value.complete):
            raise C09PagedCaptureHold('Source row requires actual same-build complete quantum/semantic EOF')
        return self.row.commitment


    def require_nested_hit(self,build,shape,key,metadata,small_sql):
        """Complete same-row semantics plus original atom/Source-ID matching."""
        self.require_complete(build,shape,key,metadata)
        from .c09_closure_index_v2 import _nested_pattern_hit
        if self.pattern_kind not in {'atom','source_id'} or type(self.pattern_ref) is not str:
            raise C09PagedCaptureHold('Source nested result lacks its actual closure pattern')
        source_id=self.pattern_kind=='source_id'
        hit=_nested_pattern_hit(small_sql,self.pattern_ref,source_id=source_id)
        hit|=_nested_pattern_hit(self.value.parser._source_metadata,self.pattern_ref,source_id=source_id)
        return hit or (not source_id and self.value.parser._source_atom_hit)


class _C09RegisteredGraphValueV3(C09CanonicalJSONStreamV2):
    """Bounded prepared value for a real registered Graph validator."""
    def __init__(self, *, source_arena=None, **profile):
        super().__init__(**profile)
        from weakref import WeakSet
        self._source_arena=WeakSet() if source_arena is None else source_arena
        self._source_arena.add(self)
        self.value=None;self.scalar=bytearray();self._containers={}
    def _source_heap_bytes(self):
        from .c09_logical_source_v3 import _retained_size
        import sys
        return sys.getsizeof(self.__dict__)+_retained_size((self.value,self.scalar,self._containers,self._stack,self._string),set())+32768
    def _require(self,extra=0):
        from .c09_paged_sql_v2 import current_c09_sql_meter_v2
        meter=current_c09_sql_meter_v2()
        if sum(value._source_heap_bytes() for value in self._source_arena)+extra>meter.budget.reserved_arena_bytes:
            raise C09PagedCaptureHold('registered prepared Graph value exceeds actual Source arena; unsupported consumer')
    def _put(self,path,value):
        self._require(__import__('sys').getsizeof(value)+16384)
        if not path:self.value=value
        else:
            parent=self._containers[path[:-1]]
            if type(parent) is list:
                if path[-1]!=len(parent):raise C09PagedCaptureHold('registered Graph array index changed')
                parent.append(value)
            else:parent[path[-1]]=value
    def _emit(self,emit,kind,path,start,end,**values):
        if kind in ('object_start','array_start'):
            value={} if kind=='object_start' else []
            self._put(path,value);self._containers[path]=value
        elif kind=='scalar_start':self.scalar=bytearray()
        elif kind=='scalar_chunk':
            self._require(len(values['raw'])*8+16384);self.scalar.extend(values['raw'])
        elif kind=='scalar_end':
            self._require(len(self.scalar)*8+16384)
            self._put(path,__import__('json').loads(self.scalar));self.scalar=bytearray()
        super()._emit(emit,kind,path,start,end,**values)
    def copy(self):
        from copy import deepcopy
        self._require(self._source_heap_bytes())
        result=super().copy()
        values=deepcopy({'value':self.value,'scalar':self.scalar,'containers':self._containers})
        result.value,result.scalar,result._containers=values['value'],values['scalar'],values['containers']
        result._source_arena=self._source_arena;self._source_arena.add(result);result._require();return result


class C09MappedGraphRowCaptureV3:
    """Real mapped Source row; physical shape never becomes an inline SQL view."""
    def __init__(self,build,shape,key,metadata,*,pattern_kind=None,pattern_ref=None):
        from .c09_graph_rebase_candidate_v2 import InstalledGraphRebaseBuildV2
        from .c09_paged_sql_v2 import current_c09_sql_meter_v2,_quote
        from .c09_logical_source_v3 import read_c09_logical_source_shape_v3,begin_logical_source_row_v3
        from ..graph_types import AtomKey
        if type(build) is not InstalledGraphRebaseBuildV2 or shape.table not in ('graph_atoms','graph_history') or 'value_cell_id' not in shape.columns:
            raise C09PagedCaptureHold('actual registered mapped Graph row required')
        build.require_current();meter=current_c09_sql_meter_v2()
        self.build,self.shape,self.key,self.metadata=build,shape,tuple(key),metadata
        self.pattern_kind,self.pattern_ref=pattern_kind,pattern_ref
        self.atom=AtomKey.from_token(key[0])
        if (self.atom.owner.bot,self.atom.owner.persona)!=tuple(__import__('json').loads(build.scope.graph_namespace)):
            raise C09PagedCaptureHold('mapped Graph Source belongs to another actual namespace')
        self.scope=build.session.begin_source_physical_read_v3(build.pair,meter=meter)
        self.logical_shape=read_c09_logical_source_shape_v3(self.scope,shape.table,meter=meter)
        if self.logical_shape.physical_shape!=shape:
            raise C09PagedCaptureHold('mapped Graph Source actual physical DDL changed')
        where=' AND '.join(_quote(name)+' COLLATE BINARY = ?' for name in shape.primary_key_columns)
        header_ref=meter.read_fixed_row(build.pair.source,shape.table,('revision','value_cell_id'),where,key)
        if header_ref is None:raise C09PagedCaptureHold('mapped Graph Source physical row is absent')
        header=self.scope.read_cell_header_v3(header_ref[1],meter=meter)
        self.row=begin_logical_source_row_v3(self.scope,self.logical_shape,self.key,meter)
        self.header=tuple(header);self.expected_revision=header_ref[0]
        from types import SimpleNamespace
        marker=False
        if self.atom.type_name=='memory.source' and header[4]<=512:
            raw,total=self.scope.read_cell_fragment_v3(header[0],start=0,length=header[4],meter=meter)
            if total!=header[4]:raise C09PagedCaptureHold('mapped Source provisional marker length changed')
            try:marker=__import__('json').loads(raw).get('schema')=='sylanne3.graph.erased_value.v1'
            except (ValueError,AttributeError):marker=False
        self.source_metadata=self.atom.type_name=='memory.source' and not marker
        if self.source_metadata:
            parser=C09MemorySourceJSONStreamV3(ensure_ascii=header[1]=='canonical-json.ascii.v1',
                source_arena=self.scope.arena,atom_pattern=pattern_ref if pattern_kind=='atom' else None)
        else:
            registry=build.session._control.maintenance.graph._registry
            # The actual registered type must exist before accepting any value.
            registry.spec(self.atom.type_name)
            parser=_C09RegisteredGraphValueV3(source_arena=self.scope.arena,ensure_ascii=header[1]=='canonical-json.ascii.v1')
        self.value=SimpleNamespace(parser=parser,complete=False,expected_size=header[4],expected_revision=header_ref[0])
        self.quantum_completed=False
    def next_quantum(self,budget):
        from copy import copy
        from .c09_paged_sql_v2 import require_c09_reserved_meter_v3
        self.build.require_current();meter=require_c09_reserved_meter_v3(budget)
        result=copy(self);result.quantum_completed=False
        result.value=copy(self.value);result.value.parser=self.value.parser.copy()
        if not self.row.complete:result.row=self.row.advance(meter)
        fragment=result.row.last_logical_fragment
        if fragment is not None and fragment[0]=='value':result.value.parser.feed(fragment[1],lambda event:None)
        if result.row.last_cell_eof=='value' and not result.value.complete:
            result.value.parser.finish();result.value.complete=True
            if result.source_metadata:
                from ..memory_types import source_key
                if source_key(self.atom.owner.bot,self.atom.owner.persona,result.value.parser._source_metadata['source_id'])!=self.atom:
                    raise C09PagedCaptureHold('mapped Source payload identity differs from actual canonical Graph key')
            else:
                value=result.value.parser.value
                if type(value) is dict and value.get('schema')=='sylanne3.graph.erased_value.v1':
                    from ..runtime_contracts import canonical_digest
                    if value!={'schema':'sylanne3.graph.erased_value.v1','key_digest':canonical_digest(self.atom.token)}:
                        raise C09PagedCaptureHold('actual mapped erased marker differs')
                else:
                    from .c09_logical_source_v3 import _retained_size
                    result.value.parser._require(_retained_size(value,set())*4+65536)
                    self.build.session._control.maintenance.graph._registry.validate(self.atom,value)
        self.build.require_current();return result
    def require_complete(self,build,shape,key,metadata):
        build.require_current()
        if (self.build is not build or self.shape!=shape or self.key!=tuple(key) or self.metadata!=metadata
                or not self.quantum_completed or not self.row.complete or not self.value.complete):
            raise C09PagedCaptureHold('mapped Source requires same actual row/semantic/quantum EOF')
        return self.row.result.commitment
    def require_nested_hit(self,build,shape,key,metadata,small_sql):
        self.require_complete(build,shape,key,metadata)
        from .c09_closure_index_v2 import _nested_pattern_hit
        if self.pattern_kind not in ('atom','source_id') or type(self.pattern_ref) is not str:
            raise C09PagedCaptureHold('mapped Source lacks actual closure pattern')
        source_id=self.pattern_kind=='source_id'
        semantic=self.value.parser._source_metadata if self.source_metadata else self.value.parser.value
        hit=_nested_pattern_hit(small_sql,self.pattern_ref,source_id=source_id)
        hit|=_nested_pattern_hit(semantic,self.pattern_ref,source_id=source_id)
        return hit or (self.source_metadata and not source_id and self.value.parser._source_atom_hit)
