"""Private, bounded C03 retrieval before the existing foreground write transaction.

This produces selection metadata only. It neither records a recollection nor
discloses candidate bodies to a model or reply.
"""
from contextlib import contextmanager
from dataclasses import dataclass, replace
from types import SimpleNamespace
import json
import time

from ..graph_store import GraphStore
from ..graph_types import AtomKey, GraphVersion
from ..runtime_contracts import canonical_digest
from ..memory_repository import MemoryRepository
from ..domains.d06 import D06DomainAdapter, RecallIntent, TriggerKind, RetrievalChannel, source_correction_head_key
from ..domains.d06.pipeline import D06MemoryPipeline, SearchPlan, RetrievalOutcome
from ..memory_retrieval import MemoryQuery, MemoryBatch
from .foreground_activity_issuance_v1 import require_foreground_activity_issuance_v1, reobserve_foreground_activity_v1
from .d07_ingress_recall_result_v1 import read_adopted_ingress_recall_routing_v1
from .d06_ingress_recall_v1 import read_adopted_ingress_recall_need_v1
from .d01_production_operations_v1 import MissingProductionOriginalV1

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


def _retrieve_bounded_ingress_pages_v1(pipeline, qualification, candidate_id, plan, *,
        evidence, epoch, rights, profile, policy):
    """One predicate, advancing only its actual cursor within the installed total budget."""
    batches, cursor, candidates_used, nodes_used = [], None, 0, 0
    deadline = time.monotonic() + policy.read_timeout_seconds
    stop = "round_budget"
    for _ in range(profile.max_rounds):
        remaining_candidates = profile.max_candidates - candidates_used
        remaining_nodes = profile.max_nodes - nodes_used
        if remaining_candidates <= 0 or remaining_nodes <= 0:
            stop = "candidate_budget" if remaining_candidates <= 0 else "node_budget"
            break
        if time.monotonic() >= deadline:
            raise MissingProductionOriginalV1("bounded_c03_read_deadline")
        batch = pipeline.retriever.search(plan.query,
            audience=evidence.request.audiences[0], purpose=evidence.request.purpose,
            max_candidates=min(policy.max_candidates_per_channel, remaining_candidates),
            max_nodes=remaining_nodes,
            page_size=min(policy.max_candidates_per_channel, remaining_candidates),
            max_pages=1, expected_epoch=epoch, after=cursor)
        batches.append(batch)
        candidates_used += batch.candidate_count
        nodes_used += batch.node_count
        if batch.complete:
            cursor, stop = None, "complete"
            break
        if batch.continuation is None or batch.continuation == cursor:
            cursor, stop = batch.continuation, "no_progress"
            break
        cursor = batch.continuation
    if not batches:
        raise MissingProductionOriginalV1("actual_c03_bounded_query_page")
    combined = MemoryBatch(tuple(hit for batch in batches for hit in batch.hits), epoch,
        candidates_used, nodes_used, sum(batch.page_count for batch in batches),
        stop == "complete", cursor)
    candidates = pipeline.adapter.assemble_candidates(candidate_id,
        (RetrievalChannel(plan.name, combined, plan.activation),),
        purpose=evidence.request.purpose, max_candidates=profile.max_candidates,
        access_epoch=rights[0], delete_epoch=rights[1])
    # Generic D06 candidate content refs are source IDs. C03 persists the exact
    # graph locator from the actual Source hit; the candidate identity stays intact.
    refs = {hit.record.source_id: hit.key.token for hit in combined.hits}
    candidates = replace(candidates, items=tuple(
        replace(item, content_ref=refs[item.content_ref]) for item in candidates.items))
    versions = {version.key: version for hit in combined.hits for version in hit.proof_versions}
    outcome = RetrievalOutcome("candidate", candidates,
        tuple(sorted(versions.values(), key=lambda version: version.key.token)), epoch,
        tuple(batches), qualification, "not_requested")
    return outcome, stop, None if cursor is None else cursor.token


@contextmanager
def read_ingress_c03_for_foreground_v1(graph, *, issued, scope, request, bundle):
    evidence = require_foreground_activity_issuance_v1(issued, graph, scope)
    if (type(request) is not SelectIngressRecallSeedRequestV1
            or evidence.request.operation_kind != OPERATION
            or bundle is not graph._GraphCoordinator__d07_execution_service_v1.bundle):
        raise TypeError("C03 search needs its actual installed foreground command")
    store, issuer = graph._GraphCoordinator__store, graph._GraphCoordinator__d11_issuer
    ns = evidence.request.namespace
    with store._lock:
        db = store._db
        if db.in_transaction:
            raise ValueError("bounded C03 repository reads stay outside the write transaction")
        db.execute("BEGIN")
        try:
            routing = read_adopted_ingress_recall_routing_v1(db, namespace=ns,
                c02_operation_id=request.c02_operation_id, issuer=issuer)
            need = read_adopted_ingress_recall_need_v1(db, namespace=ns, c02_operation_id=request.c02_operation_id)
            epoch = graph._v2_graph_stamp(ns)[1]
            rights = db.execute("SELECT access_epoch,delete_epoch FROM graph_authority_epochs WHERE bot=? AND persona=?",
                ns.as_tuple).fetchone()
            if (routing is None or need is None or canonical_digest(need) != request.need_digest
                    or need.source_ref != request.source_ref or need.cycle_job_ref != request.job_ref
                    or request.policy_digest != bundle.d06_recall.policy_digest
                    or routing["stop_reason"] != "search_required" or not routing["query_terms"] or not routing["triggers"]):
                raise MissingProductionOriginalV1("actual_adopted_search_routing_and_need")
            if epoch.revision != evidence.query_epoch.revision or rights != (evidence.access_epoch, evidence.delete_epoch):
                raise ValueError("C03 search snapshot differs from its independent foreground issuance")
        finally:
            db.rollback()
    # One compound structural predicate is one channel, within the original
    # 32-candidate/128-node cap. Terms remain predicates, never semantic facts.
    query = MemoryQuery("source", terms=tuple(routing["query_terms"]))
    plans = (SearchPlan("ingress_structural_v1", query, 0.5),)
    policy = bundle.d06_recall
    profile = next(profile for profile in policy.profiles if profile.name == routing["mode"])
    repository = MemoryRepository(store, *ns.as_tuple)
    repository.store = SimpleNamespace(
        _registry=store._registry,
        graph_snapshot=lambda keys: GraphStore.graph_snapshot(store, keys, _capability=store._coordinator_capability),
        graph_epoch=lambda bot, persona: GraphStore.graph_epoch(store, bot, persona, _capability=store._coordinator_capability),
        graph_query=lambda bot, persona, **options: GraphStore.graph_query(
            store, bot, persona, **options, _capability=store._coordinator_capability))
    pipeline = D06MemoryPipeline(D06DomainAdapter(ns), repository)
    qualification = pipeline.adapter.qualify_recall(RecallIntent(
        "ingress-c03:" + canonical_digest((ns, request.c02_operation_id))[:40],
        TriggerKind(routing["triggers"][0]), "actual_adopted_ingress_routing"))
    began = time.monotonic()
    outcome, search_stop_reason, search_cursor = _retrieve_bounded_ingress_pages_v1(
        pipeline, qualification,
        "ingress-candidates:" + canonical_digest((ns, request.c02_operation_id, query))[:40],
        plans[0], evidence=evidence, epoch=epoch, rights=rights, profile=profile, policy=policy)
    elapsed = time.monotonic() - began
    if elapsed >= policy.read_timeout_seconds:
        raise MissingProductionOriginalV1("bounded_c03_read_deadline")
    if (outcome.epoch != epoch or outcome.candidates is None
            or sum(batch.node_count for batch in outcome.batches) > profile.max_nodes
            or sum(batch.candidate_count for batch in outcome.batches) > profile.max_candidates):
        raise MissingProductionOriginalV1("actual_bounded_c03_candidate_inventory")
    versions = {version.key: version for version in outcome.proof_versions}
    with store._lock:
        db.execute("BEGIN")
        try:
            if graph._v2_graph_stamp(ns)[1] != epoch:
                raise ValueError("C03 query epoch changed during retrieval")
            if db.execute("SELECT access_epoch,delete_epoch FROM graph_authority_epochs WHERE bot=? AND persona=?",
                    ns.as_tuple).fetchone() != rights:
                raise ValueError("C03 source access/delete barrier changed during retrieval")
            for version in tuple(versions.values()):
                if version.key.type_name != "memory.source":
                    continue
                key = source_correction_head_key(ns, version.key.owner.subject)
                row = db.execute("SELECT revision FROM graph_atoms WHERE token=?", (key.token,)).fetchone()
                versions[key] = GraphVersion(key, 0 if row is None else row[0])
            for version in versions.values():
                row = db.execute("SELECT revision FROM graph_atoms WHERE token=?", (version.key.token,)).fetchone()
                if (0 if row is None else row[0]) != version.revision:
                    raise ValueError("C03 actual source/ancestor/correction version changed")
        finally:
            db.rollback()
    reobserve_foreground_activity_v1(issued, graph, scope)
    value = _IssuedIngressC03ReadV1(_KEY, graph=graph, issued=issued, scope=scope, request=request,
        routing=routing, routing_digest=canonical_digest(routing), need=need, policy=policy, plans=plans,
        outcome=outcome, outcome_digest=canonical_digest(outcome),
        closure_versions=tuple(sorted(versions.values(), key=lambda version: version.key.token)),
        query_epoch=epoch, access_epoch=rights[0], delete_epoch=rights[1], elapsed_seconds=elapsed,
        search_stop_reason=search_stop_reason, search_cursor=search_cursor)
    _ACTIVE[id(value)] = value
    try:
        yield value
    finally:
        _ACTIVE.pop(id(value), None)
