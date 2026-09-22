"""Bounded synchronous bridge from recall policy plans to structured memory reads.

Callers should run this API off-thread.  A database read already in progress is
allowed to finish within the retriever's bounds; if the policy timeout expires
in the meantime its late evidence is not accepted.  This module performs no
host actions, sends no messages, and commits no recall experience.
"""

from dataclasses import dataclass
import math
import time

from .contracts import StaleRead
from .graph_types import NamespaceEpoch
from .memory_retrieval import MemoryBatch, MemoryQuery, MemoryRetriever
from .recall_policy import (
    Action,
    Budget,
    Evidence,
    Plan,
    RecallPolicy,
    RecallRequest,
    SearchResult,
)


_TERMINAL_ACTIONS = {
    Action.READY,
    Action.CLARIFY,
    Action.INSUFFICIENT,
    Action.DEFERRED,
}
_SEARCH_ACTIONS = {Action.WORKING_SET, Action.LIGHT_SEARCH, Action.DEEP_SEARCH}
_EXTERNAL_SOURCE_KINDS = {"observed", "reported"}


def _nonempty(value, label):
    if type(value) is not str or not value:
        raise ValueError(f"{label} must be a nonempty string")


def _working_ids(value):
    if type(value) is not tuple:
        raise TypeError("working_ids must be a tuple")
    if len(value) > 64:
        raise ValueError("working_ids cannot contain more than 64 IDs")
    for source_id in value:
        _nonempty(source_id, "working_ids item")
    if len(set(value)) != len(value):
        raise ValueError("working_ids must be unique")
    return value


def _optional_time(value, label):
    if value is not None and (
        type(value) not in (int, float) or not math.isfinite(value) or value < 0
    ):
        raise ValueError(f"{label} must be a finite nonnegative real number or None")


@dataclass(frozen=True)
class RecallBatch:
    """One retriever batch and the single declared gap it was allowed to fill."""

    operation_id: str
    action: Action
    gap: str
    query: MemoryQuery
    batch: MemoryBatch


@dataclass(frozen=True)
class RecallOutcome:
    """Terminal policy result plus auditable retrieval coverage and actual usage."""

    plan: Plan
    batches: tuple[RecallBatch, ...]
    epoch: NamespaceEpoch
    usage: Budget


class MemoryRecall:
    """Execute a :class:`RecallPolicy` using only trusted named query predicates."""

    def __init__(self, retriever, *, clock=time.monotonic):
        if not isinstance(retriever, MemoryRetriever):
            raise TypeError("retriever must be MemoryRetriever")
        if not callable(clock):
            raise TypeError("clock must be callable")
        self.retriever = retriever
        self._clock = clock

    def run(
        self,
        request,
        queries: dict[str, MemoryQuery],
        *,
        audience,
        purpose,
        working_ids=(),
        as_known_at=None,
        valid_at=None,
    ):
        if not isinstance(request, RecallRequest):
            raise TypeError("request must be RecallRequest")
        if type(queries) is not dict:
            raise TypeError("queries must be a dict")
        queries = queries.copy()
        _nonempty(audience, "audience")
        _nonempty(purpose, "purpose")
        _optional_time(as_known_at, "as_known_at")
        _optional_time(valid_at, "valid_at")
        working_ids = _working_ids(working_ids)
        declared_gaps = set(request.gaps)
        for gap, query in queries.items():
            _nonempty(gap, "query name")
            if gap not in declared_gaps:
                raise ValueError(f"query name is not a declared gap: {gap}")
            if not isinstance(query, MemoryQuery):
                raise TypeError("query values must be MemoryQuery")

        policy = RecallPolicy(request, clock=self._clock)
        repository = self.retriever.repository
        epoch = repository.store.graph_epoch(repository.bot, repository.persona)
        covered_batches = []
        actual_rounds = 0
        actual_candidates = 0
        actual_nodes = 0
        cursors = {}
        exhausted = set()

        while True:
            plan = policy.next()
            if plan.action in _TERMINAL_ACTIONS:
                final_epoch = repository.store.graph_epoch(repository.bot, repository.persona)
                if final_epoch != epoch:
                    raise StaleRead("memory namespace changed during recall")
                return RecallOutcome(
                    plan=plan,
                    batches=tuple(covered_batches),
                    epoch=epoch,
                    usage=Budget(actual_rounds, actual_candidates, actual_nodes, 0),
                )

            actual_rounds += 1
            result_evidence = []
            round_candidates = 0
            round_nodes = 0

            # Mandatory checks in this slice are intentionally unresolved.  In
            # particular, lexical query matches can never satisfy policy checks.
            if plan.action in _SEARCH_ACTIONS:
                for gap in plan.targets:
                    if self._deadline_reached(policy):
                        break
                    base_query = queries.get(gap)
                    if base_query is None:
                        continue
                    query = base_query
                    after = None
                    track_cursor = plan.action in {Action.LIGHT_SEARCH, Action.DEEP_SEARCH}

                    if plan.action is Action.WORKING_SET:
                        if not working_ids:
                            continue
                        allowed = set(working_ids)
                        ids = (
                            tuple(item for item in base_query.ids if item in allowed)
                            if base_query.ids
                            else working_ids
                        )
                        if not ids:
                            continue
                        query = MemoryQuery(
                            base_query.kind,
                            ids=ids,
                            terms=base_query.terms,
                            subject_id=base_query.subject_id,
                        )
                    elif gap in exhausted:
                        continue
                    else:
                        after = cursors.get(gap)

                    while True:
                        if self._deadline_reached(policy):
                            break
                        candidate_limit = plan.reservation.candidates - round_candidates
                        node_limit = plan.reservation.nodes - round_nodes
                        if candidate_limit <= 0 or node_limit <= 0:
                            break
                        call_candidates = min(4096, candidate_limit)
                        call_nodes = min(4096, node_limit)
                        batch = self.retriever.search(
                            query,
                            audience=audience,
                            purpose=purpose,
                            as_known_at=as_known_at,
                            valid_at=valid_at,
                            max_candidates=call_candidates,
                            max_nodes=call_nodes,
                            page_size=min(32, call_candidates),
                            max_pages=4,
                            expected_epoch=epoch,
                            after=after,
                        )
                        round_candidates += batch.candidate_count
                        round_nodes += batch.node_count
                        if (
                            round_candidates > plan.reservation.candidates
                            or round_nodes > plan.reservation.nodes
                        ):
                            raise ValueError("retriever usage exceeds reserved budget")
                        covered_batches.append(
                            RecallBatch(plan.operation_id, plan.action, gap, query, batch)
                        )
                        result_evidence.extend(self._evidence(batch, gap))

                        if track_cursor:
                            if batch.complete:
                                exhausted.add(gap)
                                cursors.pop(gap, None)
                            elif batch.continuation is not None:
                                cursors[gap] = batch.continuation
                        if (
                            batch.hits
                            or batch.complete
                            or batch.continuation is None
                            or self._deadline_reached(policy)
                        ):
                            break
                        after = batch.continuation

            actual_candidates += round_candidates
            actual_nodes += round_nodes
            policy.accept(SearchResult(
                request_id=request.request_id,
                operation_id=plan.operation_id,
                action=plan.action,
                evidence=tuple(result_evidence),
                candidates_used=round_candidates,
                nodes_used=round_nodes,
                model_calls_used=0,
            ))

    def _deadline_reached(self, policy):
        now = self._clock()
        if (
            type(now) not in (int, float)
            or isinstance(now, bool)
            or not math.isfinite(now)
        ):
            raise ValueError("clock must return a finite number")
        return now >= policy.deadline

    @staticmethod
    def _evidence(batch, gap):
        evidence = []
        for hit in batch.hits:
            for source in hit.sources:
                evidence.append(Evidence(
                    source_id=source.source_id,
                    source_family=source.provenance_root,
                    fills=(gap,),
                    external=source.source_kind in _EXTERNAL_SOURCE_KINDS,
                ))
        return evidence
