"""Use the completed, independently authorized D04 Source continuation."""


def read_current_d04_post_appraisal_context_v3(graph, db, namespace, c02_operation_id, source_ref, now_utc, epoch):
    from .d04_source_work_v3 import require_bound_installed_d04_source_v3
    actual=require_bound_installed_d04_source_v3(graph,db,namespace,
        c02_operation_id=c02_operation_id,source_ref=source_ref)
    if actual is None:
        raise ValueError('D04 continuation requires its actual completed Source READ')
    if actual.current is None or actual.graph_stamp[1]!=epoch or now_utc>=actual.operation.deadline_utc:
        raise ValueError('D04 actual independently prepared continuation changed or expired')
    return actual.current
