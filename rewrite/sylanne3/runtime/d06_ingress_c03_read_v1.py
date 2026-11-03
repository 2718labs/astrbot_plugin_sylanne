"""Private, bounded C03 retrieval before the existing foreground write transaction.

This produces selection metadata only. It neither records a recollection nor
discloses candidate bodies to a model or reply.
"""
from contextlib import contextmanager
from dataclasses import dataclass
from .foreground_activity_issuance_v1 import require_foreground_activity_issuance_v1

OPERATION = "select_ingress_recall_seed_v1"
_KEY = object()
_ACTIVE = {}


@dataclass(frozen=True, slots=True)
class SelectIngressRecallSeedRequestV1:
    c02_operation_id: str
    source_ref: str
    job_ref: str
    policy_digest: str
    need_digest: str

    def __post_init__(self):
        from .d07_ingress_recall_preparation_v1 import PrepareIngressRecallModelRequestV1
        PrepareIngressRecallModelRequestV1(self.c02_operation_id, self.source_ref,
            self.job_ref, self.policy_digest, self.need_digest)


@dataclass(frozen=True, slots=True, init=False)
class _IssuedIngressC03ReadV1:
    graph: object
    issued: object
    scope: object
    request: SelectIngressRecallSeedRequestV1
    routing: object
    routing_digest: str
    need: object
    policy: object
    plans: tuple
    outcome: object
    outcome_digest: str
    closure_versions: tuple
    query_epoch: object
    access_epoch: int
    delete_epoch: int
    elapsed_seconds: float
    search_stop_reason: str
    search_cursor: str | None

    def __init__(self, key, **values):
        if key is not _KEY:
            raise TypeError("C03 read handle is created only by the fixed installed retrieval")
        for name, value in values.items():
            object.__setattr__(self, name, value)


def require_ingress_c03_read_v1(value, graph, issued, scope, request):
    evidence = require_foreground_activity_issuance_v1(issued, graph, scope)
    if (type(value) is not _IssuedIngressC03ReadV1 or _ACTIVE.get(id(value)) is not value
            or value.graph is not graph or value.issued is not issued or value.scope is not scope
            or value.request != request or evidence.request.operation_kind != OPERATION):
        raise ValueError("C03 selection lacks its actual private retrieval/foreground pairing")
    return value


def issue_ingress_c03_read_from_source_task_v3(task):
    from .d06_c03_search_source_v3 import require_c03_source_task_material_v3
    value = _IssuedIngressC03ReadV1(_KEY, **require_c03_source_task_material_v3(task))
    _ACTIVE[id(value)] = value
    return value


def release_ingress_c03_source_handle_v3(value):
    if _ACTIVE.get(id(value)) is value:
        _ACTIVE.pop(id(value))


@contextmanager
def read_ingress_c03_for_foreground_v1(graph, *, issued, scope, request, bundle):
    from .d06_c03_search_source_v3 import read_prepared_ingress_c03_for_scope_v3
    if bundle is not graph._GraphCoordinator__d07_execution_service_v1.bundle:
        raise TypeError("C03 selection requires its actual installed bundle")
    value = read_prepared_ingress_c03_for_scope_v3(graph, issued, scope, request)
    yield require_ingress_c03_read_v1(value, graph, issued, scope, request)
