"""Private installed handles for independently qualified Owner management tasks."""
from contextlib import contextmanager
from dataclasses import dataclass

from ..runtime_contracts import FenceScope, canonical_digest
from ..authority_service.current_owner_source_note_task_v1 import (
    OwnerTaskActivityRequestV1, OwnerTaskActivityValuesChildRequestV1, OwnerTaskActivityEvidenceV1, owner_task_fence_operation_id_v1)

_KEY = object()
_ACTIVE = {}


@dataclass(frozen=True, slots=True, init=False)
class _IssuedOwnerSourceNoteTaskV1:
    graph: object
    scope: FenceScope
    evidence: OwnerTaskActivityEvidenceV1
    digest: str
    execution_original: object

    def __init__(self, key, graph, scope, evidence, execution_original):
        if key is not _KEY:
            raise TypeError('Owner task handles belong to the actual installed paired observer')
        for name, value in (('graph', graph), ('scope', scope), ('evidence', evidence),
                ('digest', canonical_digest(evidence)),('execution_original',execution_original)):
            object.__setattr__(self, name, value)


@contextmanager
def owner_source_note_task_for_fence_v1(graph, *, scope, request):
    from ..graph_coordinator import GraphCoordinator
    from ..host.v2_fence_port import V2FencePort
    if (type(graph) is not GraphCoordinator or type(scope) is not FenceScope
            or type(request) not in {OwnerTaskActivityRequestV1,OwnerTaskActivityValuesChildRequestV1}
            or scope.operation != 'write' or scope.operation_id != owner_task_fence_operation_id_v1(request)):
        raise TypeError('Owner task issuance requires its actual Graph and exact named write scope')
    port = graph._GraphCoordinator__content_fence_v2
    if type(port) is not V2FencePort or graph._GraphCoordinator__store._db.in_transaction:
        raise ValueError('Owner task qualification must precede the actual SQL transaction')
    evidence, permit = port.admit_owner_source_note_task_for_fence_v1(scope=scope, request=request)
    if (type(evidence) is not OwnerTaskActivityEvidenceV1 or evidence.request != request
            or permit != scope.permit or evidence.current_self.permit != permit
            or evidence.query_epoch.revision != scope.graph_epoch.revision
            or evidence.current_self.graph_revision != scope.graph_revision):
        raise ValueError('Owner task paired result changed its actual request/permit/Graph stamp')
    execution_original = None
    if request.operation_kind == 'checkpoint_owner_source_note_task_v1':
        from .jobs import get_job
        from .owner_source_note_task_contract_v1 import OwnerSourceNoteTaskContinuationV2
        from .domain_production_erasure_v1 import decode_typed_production_value_v1
        from .d11_life_preparation_v1 import read_prepared_life_by_ref_v1
        from .domain_production_originals_v1 import read_adopted_domain_operation_v1
        from ..graph_types import AtomKey
        from ..host.d11_life_port_v1 import InstalledD11LifePortV1
        store=graph._GraphCoordinator__store
        prepared=None
        with store._lock:
            db=store._db;db.execute('BEGIN')
            try:
                job=get_job(db,AtomKey.from_token(request.task_job_ref).name)
                cont=decode_typed_production_value_v1(dict(job.continuation),OwnerSourceNoteTaskContinuationV2)
                if cont.step=='execute_life':
                    rows=db.execute("SELECT original_ref FROM graph_d11_life_originals_v1 WHERE bot=? AND persona=? AND kind='prepared' AND json_extract(payload_json,'$.plan.activity_id')=? ORDER BY original_ref LIMIT 2",
                        (*request.namespace.as_tuple,job.activity_id)).fetchall()
                    if len(rows)!=1:raise ValueError('Owner task Native observation requires one actual same-task preparation')
                    prepared=read_prepared_life_by_ref_v1(db,namespace=request.namespace,
                        prepared_original_ref=rows[0][0],issuer=graph._GraphCoordinator__d11_issuer)
                    production=read_adopted_domain_operation_v1(db,request.namespace,prepared.prepare_operation_id)
                    auth=evidence.authorization
                    if (production is None or production['operation_kind']!='prepare_life'
                            or prepared.plan.project.ref!=auth.request.project_ref
                            or prepared.plan.input_source.ref!=auth.request.body_source_ref
                            or prepared.binding.parent_budget_lease_ref!=auth.cause.parent_budget_lease_ref):
                        raise ValueError('Owner task Native preparation belongs to another actual authorized task')
            finally:db.rollback()
        if prepared is not None:
            claim,terminal=InstalledD11LifePortV1(port).read_d11_life_original_v1(binding=prepared.binding)
            execution_original=(prepared,claim,terminal)
    issued = _IssuedOwnerSourceNoteTaskV1(_KEY, graph, scope, evidence, execution_original)
    _ACTIVE[id(issued)] = issued
    try:
        yield issued
    finally:
        del _ACTIVE[id(issued)]


def require_owner_source_note_task_issuance_v1(issued, graph, scope):
    if (type(issued) is not _IssuedOwnerSourceNoteTaskV1 or _ACTIVE.get(id(issued)) is not issued
            or issued.graph is not graph or issued.scope != scope
            or issued.digest != canonical_digest(issued.evidence)):
        raise ValueError('Owner task actual private issued handle is absent or changed')
    return issued.evidence


def reobserve_owner_source_note_task_v1(issued, graph, scope):
    evidence = require_owner_source_note_task_issuance_v1(issued, graph, scope)
    if graph._GraphCoordinator__store._db.in_transaction:
        raise ValueError('Owner task currentness RPC must run outside SQL')
    current, permit = graph._GraphCoordinator__content_fence_v2.read_current_owner_source_note_task_for_fence_v1(
        scope=scope, original_request=evidence.request)
    from dataclasses import replace
    if permit != scope.permit or replace(current, observed_at_utc=evidence.observed_at_utc) != evidence:
        raise ValueError('Owner task actual current authorization/Self/Source/job changed')
    return current


def require_owner_source_note_task_execution_original_v1(issued,graph,scope):
    require_owner_source_note_task_issuance_v1(issued,graph,scope)
    return issued.execution_original
