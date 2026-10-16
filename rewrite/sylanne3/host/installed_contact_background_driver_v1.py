"""Resume original Contact model/final/outbox work through the installed Host."""
import json

from ..runtime.contact_plan_adoption_v2 import TABLE as PLAN_TABLE, read_adopted_contact_plan_v2
from ..runtime.contact_background_invocation_v1 import TABLE as INVOCATION_TABLE, recover_contact_background_dispatch_v1
from ..runtime.contact_model_job_v2 import contact_model_ids_v2
from ..runtime.contact_paid_original_v2 import read_contact_original_v2
from ..runtime.jobs import get_job
from ..runtime.contact_background_scheduler_v3 import read_contact_scheduler_cursor_v3,record_contact_scheduler_progress_v3


def read_contact_background_page_v1(graph, bootstrap, bundle, *, after=None, limit=32):
    graph._admin(bootstrap)
    assembly = graph._GraphCoordinator__d04_installed_joint_assembly
    if assembly is None or assembly.admin_bundle is not bundle or not 1 <= limit <= 32:
        raise ValueError('Contact discovery requires its actual installed bounded namespace')
    ns = bundle.installation_policy.namespace
    store = graph._GraphCoordinator__store
    with store._lock:
        store._db.execute('BEGIN')
        try:
            if after is None:
                after = read_contact_scheduler_cursor_v3(store._db,ns)
            from ..runtime.contact_plan_adoption_v3 import TABLE as PLAN_TABLE3
            ids = tuple(row[0] for row in store._db.execute('SELECT contact_id FROM (SELECT contact_id FROM '+PLAN_TABLE+
                ' WHERE bot=? AND persona=? UNION SELECT contact_id FROM '+PLAN_TABLE3+' WHERE bot=? AND persona=?) '
                'WHERE contact_id>? ORDER BY contact_id LIMIT ?',(*ns.as_tuple,*ns.as_tuple,after,limit)))
            return {'contact_ids':ids,'next_after':ids[-1] if len(ids) == limit else None}
        finally:
            store._db.rollback()


def read_contact_background_item_v1(graph,bootstrap,bundle,*,contact_id):
    from ..runtime.contact_graph_runtime_v2 import contact_model_runtime_v2
    service = contact_model_runtime_v2(graph,bootstrap,bundle)
    return service._contact_host_read_work_v3(contact_id,'contact_generation','background_item')


def _qualified_contact_background_item_v3(service,work):
    from ..runtime.contact_host_source_v3 import require_contact_host_work_v3
    from ..authority_service.contact_model_graph_v2 import require_contact_scope_current_v2
    require_contact_host_work_v3(work,db=service.store._db)
    if work.service is not service or work.selector.stage != 'background_item' or work.phase != 'semantic':
        raise ValueError('Contact item requires its actual installed Source-qualified Host stage')
    ns,db = work.namespace,service.store._db
    plan,expression,raw,_ = read_adopted_contact_plan_v2(db,namespace=ns,contact_id=work.selector.contact_id,issuer=service.issuer)
    require_contact_scope_current_v2(db,plan,expression,now=work.now_utc)
    audience = json.loads(plan.audience_id)
    if type(audience) is not list or len(audience) != 2:
        raise ValueError('Contact signed private route audience differs')
    final = db.execute(f'SELECT invocation.operation_id FROM {INVOCATION_TABLE} AS invocation '
        'JOIN graph_bundle_outbox AS outbox ON outbox.bot=invocation.bot AND outbox.persona=invocation.persona '
        'AND outbox.operation_id=invocation.operation_id WHERE invocation.bot=? AND invocation.persona=? '
        "AND outbox.phase='pending' AND json_extract(invocation.payload_json,'$.request.contact_id')=? LIMIT 1",
        (*ns.as_tuple,plan.contact_id)).fetchone()
    phase = None
    if final is None:
        for name,metadata in (('contact_generation',work.generation_metadata),('contact_review',work.prepared_locator)):
            if metadata.values is None:
                break
            job = get_job(db,metadata.ids['job'])
            if job is None:
                raise ValueError('Contact prepared locator lost its actual durable job')
            if job.phase != 'completed':
                phase = name
                break
    return {'contact_id':plan.contact_id,'trusted_umo':audience[0],'phase':phase,
        'final_operation_id':None if final is None else final[0]}


async def run_contact_background_page_v1(runtime, installation, host, *, after=None):
    context, server, listener, candidates = host
    page = await runtime._worker.call(lambda graph: read_contact_background_page_v1(graph,runtime._v2_bootstrap,
        installation.admin_bundle,after=after))
    progress = []
    for contact_id in page['contact_ids']:
        if runtime._contact_background_stopping:
            break
        phase = None
        state,code = 'waiting','phase_not_prepared'
        try:
            item = await runtime._worker.call(lambda graph, selected=contact_id: read_contact_background_item_v1(
                graph,runtime._v2_bootstrap,installation.admin_bundle,contact_id=selected))
            from ..graph_worker import OwnedGraphStorageResultV3
            if type(item) is not OwnedGraphStorageResultV3:
                raise ValueError('Contact qualification lost its actual Source result lease')
            item,item_retention = item.take_value_v3()
            item_retention.release()
            operation = item['final_operation_id']
            phase = 'final' if operation is not None else item['phase']
            if operation is not None:
                result = await runtime._worker.call(lambda graph, selected=operation: recover_contact_background_dispatch_v1(
                    graph,runtime._v2_bootstrap,installation.admin_bundle,operation_id=selected))
                result = runtime._consume_background_graph_result_v3(result)
                if result.get('coverage') == 'complete':
                    delivered = await runtime.dispatch_committed_contact_v3(installation,operation_id=operation,
                        context=context,server=server,listener=listener,candidates=candidates)
                    try:
                        # This installation has no delivery evaluator. Paid-prefix
                        # readiness never verifies its communicated Goal predicate.
                        state,code = ('waiting' if delivered.status=='pending_verification' else 'unknown'),delivered.status
                        progress.append({'contact_id':item['contact_id'],'status':delivered.status})
                    finally:
                        delivered.release_v3()
            elif item['phase'] is not None:
                result = await runtime.run_installed_contact_model_v2(installation,context=context,
                    trusted_umo=item['trusted_umo'],contact_id=item['contact_id'],phase=item['phase'])
                state,code = ('progress' if result.status in {'review_required','whole_batch_paid_pass'}
                    else 'unknown' if result.status in {'terminal_hold','cost_hold'} else 'held'),result.status
                progress.append({'contact_id':item['contact_id'],'phase':item['phase'],'status':result.status})
                if result.status in {'review_required','whole_batch_paid_pass'}:
                    runtime.resume_pending_domain_followups_v1(installation)
        except Exception as exc:
            state,code = 'held',type(exc).__name__
            progress.append({'contact_id':contact_id,'status':'held','error_code':type(exc).__name__})
        await runtime._worker.call(lambda graph, selected=contact_id, actual_phase=phase, actual_state=state, actual_code=code:
            record_contact_scheduler_progress_v3(graph,runtime._v2_bootstrap,installation.admin_bundle,
                contact_id=selected,phase=actual_phase,status=actual_state,code=actual_code))
    if page['next_after'] is None and not runtime._contact_background_stopping:
        await runtime._worker.call(lambda graph: record_contact_scheduler_progress_v3(graph,runtime._v2_bootstrap,
            installation.admin_bundle,contact_id='',phase=None,status='cursor',code='sweep'))
    return {'next_after':page['next_after'],'progress':tuple(progress)}
