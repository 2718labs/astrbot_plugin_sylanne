"""Frozen, graph-free input and deterministic D06 association CPU work.

W01 collects these *original* graph reads under one fence.  This module can
validate and execute the frozen input, but cannot read a graph or issue C04.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import math

from ...contracts import canonical_json
from ...graph_types import AtomKey, GraphAtom, NamespaceEpoch
from ...memory_association import ActivationPolicy, AssociationActivator, AssociationEdge
from ...memory_types import SourceRecord, access_key, source_key, validate_access, validate_association
from ...runtime_contracts import NamespaceId
from . import SelectionTicket, source_correction_head_key
from .current_association_candidates import CurrentAssociationBudgetV1


ALGORITHM_ID = "d06.association_activation.v2"
_MAX_READS = 1024


def _digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _nonempty(value: object, name: str) -> None:
    if type(value) is not str or not value:
        raise ValueError(f"{name} must be a nonempty string")


def _fields(value: object, expected: set[str], name: str) -> dict:
    if type(value) is not dict or set(value) != expected:
        raise ValueError(f"{name} fields differ")
    return value


@dataclass(frozen=True, slots=True)
class FrozenGraphReadV2:
    """One exact graph head; revision zero is an explicit absent read."""

    key: AtomKey
    revision: int
    valid: bool
    value_json: str | None

    def __post_init__(self) -> None:
        if (type(self.key) is not AtomKey or type(self.revision) is not int
                or self.revision < 0 or type(self.valid) is not bool):
            raise TypeError("frozen graph read needs an exact key, revision and validity")
        if self.revision == 0:
            if self.valid or self.value_json is not None:
                raise ValueError("absent graph head must be revision zero without a value")
        elif (type(self.value_json) is not str
              or type(json.loads(self.value_json)) is not dict
              or canonical_json(json.loads(self.value_json)) != self.value_json):
            raise ValueError("present graph head needs a canonical complete JSON object")

    @classmethod
    def from_atom(cls, atom: GraphAtom) -> FrozenGraphReadV2:
        if type(atom) is not GraphAtom or atom.revision < 1:
            raise ValueError("a present original GraphAtom is required")
        return cls(atom.key, atom.revision, atom.valid, canonical_json(atom.value))

    @classmethod
    def absent(cls, key: AtomKey) -> FrozenGraphReadV2:
        return cls(key, 0, False, None)

    @property
    def value(self) -> dict | None:
        return None if self.value_json is None else json.loads(self.value_json)

    def semantic_row(self) -> dict:
        return {"key": self.key.token, "revision": self.revision,
                "valid": self.valid, "value": self.value}


@dataclass(frozen=True, slots=True)
class AssociationQueryCoverageV2:
    """One W01 edge query, including an empty page and its continuation proof."""

    source_ref: str
    hop: int
    edge_refs: tuple[str, ...]
    next_after: str | None = None

    def __post_init__(self) -> None:
        _nonempty(self.source_ref, "query source_ref")
        if type(self.hop) is not int or self.hop not in (0, 1):
            raise ValueError("association query hop must be zero or one")
        if (type(self.edge_refs) is not tuple or len(set(self.edge_refs)) != len(self.edge_refs)
                or any(type(ref) is not str or not ref for ref in self.edge_refs)):
            raise ValueError("query edge refs must be distinct graph refs")
        if self.next_after is not None:
            AtomKey.from_token(self.next_after)

    @property
    def coverage(self) -> str:
        return "complete" if self.next_after is None else "truncated"

    def semantic_row(self) -> dict:
        return {"source_ref": self.source_ref, "hop": self.hop,
                "edge_refs": sorted(self.edge_refs), "next_after": self.next_after,
                "coverage": self.coverage}


@dataclass(frozen=True, slots=True)
class D04SalienceOriginalV2:
    """D04's prepared salience projection bound to its source and mood head."""

    source_ref: str
    mood_ref: str
    base_interval: tuple[float, float]
    conditioned_interval: tuple[float, float]
    coupling_version: str

    def __post_init__(self) -> None:
        AtomKey.from_token(self.source_ref)
        AtomKey.from_token(self.mood_ref)
        _nonempty(self.coupling_version, "coupling_version")
        for name in ("base_interval", "conditioned_interval"):
            value = getattr(self, name)
            if (type(value) is not tuple or len(value) != 2
                    or any(type(number) not in (int, float) or not math.isfinite(number)
                           or not 0 <= number <= 1 for number in value)):
                raise ValueError(f"{name} must be a bounded two-value interval")

    def semantic_row(self) -> dict:
        return {"source_ref": self.source_ref, "mood_ref": self.mood_ref,
                "base_interval": list(self.base_interval),
                "conditioned_interval": list(self.conditioned_interval),
                "coupling_version": self.coupling_version}


@dataclass(frozen=True, slots=True)
class AssociationWorkInputV2:
    namespace: NamespaceId
    activity_id: str
    operation_id: str
    cue_source_ref: str
    focus_ref: str
    attention_ticket_ref: str
    mood_ref: str
    selection_ticket: SelectionTicket
    salience_original: D04SalienceOriginalV2
    audience: str
    purpose: str
    context_tags: tuple[str, ...]
    policy: ActivationPolicy
    budget: CurrentAssociationBudgetV1
    reads: tuple[FrozenGraphReadV2, ...]
    edge_queries: tuple[AssociationQueryCoverageV2, ...]
    graph_epoch: NamespaceEpoch
    truncated: bool = False
    algorithm_id: str = ALGORITHM_ID

    def __post_init__(self) -> None:
        if type(self.namespace) is not NamespaceId or type(self.graph_epoch) is not NamespaceEpoch:
            raise TypeError("association input needs typed namespace and observation epoch")
        if (self.graph_epoch.bot, self.graph_epoch.persona) != self.namespace.as_tuple:
            raise ValueError("association observation crosses namespace")
        for name in ("activity_id", "operation_id", "audience", "purpose"):
            _nonempty(getattr(self, name), name)
        if self.algorithm_id != ALGORITHM_ID:
            raise ValueError("association algorithm is not installed")
        if type(self.policy) is not ActivationPolicy or type(self.budget) is not CurrentAssociationBudgetV1:
            raise TypeError("fixed typed activation policy and five budgets required")
        if (self.policy.max_iterations != self.budget.max_iterations
                or self.policy.max_nodes != self.budget.max_nodes
                or (self.policy.leak, self.policy.spread, self.policy.min_activation)
                != (0.5, 0.25, 1e-6)):
            raise ValueError("activation policy differs from installed numeric policy or budget")
        if (type(self.selection_ticket) is not SelectionTicket
                or type(self.salience_original) is not D04SalienceOriginalV2
                or self.selection_ticket.activity_id != self.activity_id
                or self.salience_original.source_ref != self.cue_source_ref
                or self.salience_original.mood_ref != self.mood_ref):
            raise ValueError("D07 selection and D04 salience originals differ")
        if (type(self.context_tags) is not tuple or len(self.context_tags) > 8
                or len(set(self.context_tags)) != len(self.context_tags)
                or any(type(tag) is not str or not tag for tag in self.context_tags)):
            raise ValueError("context tags must be a bounded distinct tuple")
        if type(self.truncated) is not bool:
            raise TypeError("truncation must be explicit")
        if (type(self.reads) is not tuple or len(self.reads) > _MAX_READS
                or any(type(item) is not FrozenGraphReadV2 for item in self.reads)
                or len({item.key for item in self.reads}) != len(self.reads)):
            raise ValueError("frozen graph reads must be bounded and unique")
        if (type(self.edge_queries) is not tuple or len(self.edge_queries) > self.budget.max_nodes
                or any(type(item) is not AssociationQueryCoverageV2 for item in self.edge_queries)
                or len({item.source_ref for item in self.edge_queries}) != len(self.edge_queries)):
            raise ValueError("edge queries must be bounded and unique")
        if any((item.key.owner.bot, item.key.owner.persona) != self.namespace.as_tuple
               for item in self.reads):
            raise ValueError("frozen graph read crosses namespace")
        self._validate_closure()

    def _validate_closure(self) -> None:
        _validate_complete_graph_closure_v1(self, mood_type="d04.mood_field.v1")

    def semantic_payload(self) -> dict:
        """Canonicalizable replay identity; observation epoch is intentionally separate."""
        return {
            "schema": "sylanne.d06.association-work-input.v2",
            "algorithm_id": self.algorithm_id,
            "namespace": list(self.namespace.as_tuple),
            "activity_id": self.activity_id,
            "operation_id": self.operation_id,
            "cue_source_ref": self.cue_source_ref,
            "focus_ref": self.focus_ref,
            "attention_ticket_ref": self.attention_ticket_ref,
            "mood_ref": self.mood_ref,
            "selection_ticket": {
                "ticket_id": self.selection_ticket.ticket_id,
                "activity_id": self.selection_ticket.activity_id,
                "candidate_set_id": self.selection_ticket.candidate_set_id,
                "selected_candidate_ids": list(self.selection_ticket.selected_candidate_ids),
                "focus_epoch": self.selection_ticket.focus_epoch,
            },
            "salience_original": self.salience_original.semantic_row(),
            "audience": self.audience,
            "purpose": self.purpose,
            "context_tags": sorted(self.context_tags),
            "policy": {"leak": self.policy.leak, "spread": self.policy.spread,
                       "max_iterations": self.policy.max_iterations,
                       "max_nodes": self.policy.max_nodes,
                       "min_activation": self.policy.min_activation},
            "budget": {"max_hops": self.budget.max_hops,
                       "max_edges": self.budget.max_edges,
                       "max_nodes": self.budget.max_nodes,
                       "max_iterations": self.budget.max_iterations,
                       "max_candidates": self.budget.max_candidates},
            "reads": [item.semantic_row() for item in sorted(self.reads,
                                                               key=lambda row: row.key.token)],
            "edge_queries": [item.semantic_row() for item in sorted(
                self.edge_queries, key=lambda row: row.source_ref)],
            "truncated": self.truncated,
        }

    @property
    def input_digest(self) -> str:
        return _digest(self.semantic_payload())

    def to_dict(self) -> dict:
        """Durable W01 prepare payload, including its independent observed epoch."""
        return {**self.semantic_payload(),
                "graph_epoch": {"bot": self.graph_epoch.bot,
                                "persona": self.graph_epoch.persona,
                                "revision": self.graph_epoch.revision}}

    def to_json(self) -> str:
        return canonical_json(self.to_dict())

    @classmethod
    def from_json(cls, value: str) -> AssociationWorkInputV2:
        if type(value) is not str:
            raise TypeError("frozen association JSON must be a string")
        decoded = json.loads(value)
        if canonical_json(decoded) != value:
            raise ValueError("frozen association JSON must be canonical")
        result = cls.from_dict(decoded)
        if result.to_json() != value:
            raise ValueError("frozen association JSON row order must be canonical")
        return result

    @classmethod
    def from_dict(cls, value: dict) -> AssociationWorkInputV2:
        _fields(value, {
                "schema", "algorithm_id", "namespace", "activity_id", "operation_id",
                "cue_source_ref", "focus_ref", "attention_ticket_ref", "mood_ref",
                "selection_ticket", "salience_original", "audience", "purpose",
                "context_tags", "policy", "budget", "reads", "edge_queries",
                "truncated", "graph_epoch"}, "frozen association input")
        if value["schema"] != "sylanne.d06.association-work-input.v2":
            raise ValueError("frozen association input schema differs")
        namespace = value["namespace"]
        selection = _fields(value["selection_ticket"], {
            "ticket_id", "activity_id", "candidate_set_id", "selected_candidate_ids",
            "focus_epoch"}, "D07 selection ticket")
        salience = _fields(value["salience_original"], {
            "source_ref", "mood_ref", "base_interval", "conditioned_interval",
            "coupling_version"}, "D04 salience original")
        policy = _fields(value["policy"], {
            "leak", "spread", "max_iterations", "max_nodes", "min_activation"},
            "activation policy")
        budget = _fields(value["budget"], {
            "max_hops", "max_edges", "max_nodes", "max_iterations", "max_candidates"},
            "association budget")
        epoch = _fields(value["graph_epoch"], {"bot", "persona", "revision"},
                        "observation epoch")
        if (type(namespace) is not list or len(namespace) != 2
                or type(value["reads"]) is not list
                or type(value["edge_queries"]) is not list
                or type(value["context_tags"]) is not list
                or type(selection["selected_candidate_ids"]) is not list
                or type(salience["base_interval"]) is not list
                or type(salience["conditioned_interval"]) is not list
                or any(type(row) is not dict for row in value["reads"])
                or any(type(row) is not dict for row in value["edge_queries"])):
            raise ValueError("frozen association input rows differ")
        for row in value["reads"]:
            _fields(row, {"key", "revision", "valid", "value"}, "graph read")
        for row in value["edge_queries"]:
            _fields(row, {"source_ref", "hop", "edge_refs", "next_after", "coverage"},
                    "edge query")
            if (type(row["edge_refs"]) is not list
                    or row["coverage"] != ("complete" if row["next_after"] is None
                                           else "truncated")):
                raise ValueError("edge query coverage differs")
        reads = tuple(FrozenGraphReadV2(
            AtomKey.from_token(row["key"]), row["revision"], row["valid"],
            None if row["value"] is None else canonical_json(row["value"]))
            for row in value["reads"])
        queries = tuple(AssociationQueryCoverageV2(
            row["source_ref"], row["hop"], tuple(row["edge_refs"]),
            row["next_after"]) for row in value["edge_queries"])
        return cls(
            NamespaceId(*namespace), value["activity_id"], value["operation_id"],
            value["cue_source_ref"], value["focus_ref"],
            value["attention_ticket_ref"], value["mood_ref"],
            SelectionTicket(selection["ticket_id"], selection["activity_id"],
                            selection["candidate_set_id"],
                            tuple(selection["selected_candidate_ids"]),
                            selection["focus_epoch"]),
            D04SalienceOriginalV2(salience["source_ref"], salience["mood_ref"],
                                  tuple(salience["base_interval"]),
                                  tuple(salience["conditioned_interval"]),
                                  salience["coupling_version"]),
            value["audience"], value["purpose"], tuple(value["context_tags"]),
            ActivationPolicy(**policy), CurrentAssociationBudgetV1(**budget),
            reads, queries, NamespaceEpoch(**epoch), value["truncated"],
            value["algorithm_id"],
        )


@dataclass(frozen=True, slots=True)
class AssociationWorkCandidateV2:
    source_ref: str
    activation: float
    mood_weighted_activation: float
    evidence_eligibility: str = "subjective_association_only"


@dataclass(frozen=True, slots=True)
class AssociationWorkResultV2:
    input_digest: str
    candidates: tuple[AssociationWorkCandidateV2, ...]
    edge_refs: tuple[str, ...]
    visited_nodes: int
    visited_edges: int
    iterations: int
    stop_reason: str
    coverage: str
    result_digest: str


def activate_association_work_v2(work: AssociationWorkInputV2) -> AssociationWorkResultV2:
    """Run the installed activation and deterministic candidate ranking once."""
    if type(work) is not AssociationWorkInputV2:
        raise TypeError("only a frozen AssociationWorkInputV2 is executable")
    work._validate_closure()
    by_key = {item.key: item for item in work.reads}
    traversed: list[AssociationEdge] = []
    edge_refs: list[str] = []
    allowed = {work.cue_source_ref}
    frontier = {work.cue_source_ref}
    queries = {item.source_ref: item for item in work.edge_queries}
    for _ in range(work.budget.max_hops):
        next_frontier: set[str] = set()
        for source in sorted(frontier):
            query = queries.get(source)
            if query is None:
                continue
            for ref in sorted(query.edge_refs):
                row = by_key[AtomKey.from_token(ref)]
                value = row.value
                fit = 1.0 if not value["context_tags"] else float(bool(
                    set(value["context_tags"]) & set(work.context_tags)))
                if fit == 0:
                    continue
                target = value["target_ref"]
                traversed.append(AssociationEdge(source, target, value["weight"], fit, ref))
                edge_refs.append(ref)
                allowed.add(target)
                next_frontier.add(target)
        frontier = next_frontier
        if not frontier:
            break
    activation = AssociationActivator(work.policy).propagate(
        {work.cue_source_ref: 1.0}, tuple(traversed))
    salience = sum(work.salience_original.conditioned_interval) / 2.0
    ranked = sorted((AssociationWorkCandidateV2(ref, score, score * salience)
                     for ref, score in activation.activations
                     if ref != work.cue_source_ref and ref in allowed and score > 0),
                    key=lambda item: (-item.mood_weighted_activation, item.source_ref))
    selected = tuple(ranked[:work.budget.max_candidates])
    if work.budget.max_hops == 0:
        reason = "hop_budget_exhausted"
    elif work.truncated:
        reason = "traversal_budget_or_page_limit"
    elif len(ranked) > len(selected):
        reason = "candidate_limit"
    elif not selected:
        reason = "no_eligible_association"
    else:
        reason = activation.stop_reason
    rows = {"schema": "sylanne.d06.association-work-result.v2",
            "input_digest": work.input_digest,
            "candidates": [{"source_ref": item.source_ref,
                            "activation": item.activation,
                            "mood_weighted_activation": item.mood_weighted_activation,
                            "evidence_eligibility": item.evidence_eligibility}
                           for item in selected],
            "edge_refs": sorted(edge_refs),
            "visited_nodes": len(activation.visited_refs),
            "visited_edges": len(edge_refs),
            "iterations": activation.iterations,
            "stop_reason": reason,
            "coverage": "partial" if work.truncated else "bounded_complete"}
    return AssociationWorkResultV2(
        work.input_digest, selected, tuple(sorted(edge_refs)),
        rows["visited_nodes"], rows["visited_edges"], activation.iterations,
        reason, rows["coverage"], _digest(rows))


__all__ = ["ALGORITHM_ID", "FrozenGraphReadV2", "AssociationQueryCoverageV2",
           "D04SalienceOriginalV2",
           "AssociationWorkInputV2", "AssociationWorkCandidateV2",
           "AssociationWorkResultV2", "activate_association_work_v2"]


def _validate_complete_graph_closure_v1(self, *, mood_type):
    """Shared exact closure checks; lineage is selected by a fixed DTO reader."""
    by_key = {item.key: item for item in self.reads}
    refs = (self.cue_source_ref, self.focus_ref, self.attention_ticket_ref, self.mood_ref)
    keys = tuple(AtomKey.from_token(ref) for ref in refs)
    cue, focus, ticket, mood = keys
    expected = ("memory.source", "d07.focus.v1", "d07.attention_ticket.v1",
                mood_type)
    if tuple(key.type_name for key in keys) != expected:
        raise ValueError("cue, focus, ticket or mood graph type differs")
    if any((key.owner.bot, key.owner.persona) != self.namespace.as_tuple for key in keys):
        raise ValueError("frozen anchor crosses namespace")
    for key in keys:
        row = by_key.get(key)
        if row is None or row.revision < 1 or not row.valid:
            raise ValueError("cue, focus, ticket and mood need present original heads")
    focus_value = by_key[focus].value
    ticket_value = by_key[ticket].value
    # D04 owns the payload schema. Its source dependencies are part of the
    # frozen input even when attention and traversal never visit them.
    from ..d04.affect import AffectProvider, MoodField

    if mood_type == "d04.mood_field.v1":
        mood_spec = next(spec for spec in AffectProvider().type_specs()
                         if spec.name == "d04.mood_field.v1")
        mood_value = mood_spec.validator(by_key[mood].value)
        if type(mood_value) is not MoodField:
            raise ValueError("legacy Mood original type differs")
    elif mood_type == "d04.authored_mood_state.v1":
        from ..d04.authored_lineage_v3 import decode_authored_mood_state_v1
        mood_value = decode_authored_mood_state_v1(by_key[mood].value)
    else:
        raise ValueError("unregistered complete-closure Mood lineage")
    if (mood_type == "d04.mood_field.v1" and mood_value.mood_id != mood.token
            or mood_type == "d04.authored_mood_state.v1" and (
                mood.owner.kind != "persona" or mood.name != mood_value.block_id
                or by_key[mood].revision != mood_value.revision)):
        raise ValueError("mood original identity differs")
    if (focus_value["primary_ticket_ref"] != ticket.token
            or ticket_value["ticket_id"] != ticket.name
            or focus_value["focus_epoch"] != self.selection_ticket.focus_epoch
            or cue.token not in ticket_value["source_refs"]
            or ticket_value["causal_root"] not in ticket_value["source_refs"]
            or not ticket_value["eligible"] or not ticket_value["resources_available"]
            or ticket_value["cancel_refs"]):
        raise ValueError("D07 focus and ticket do not select the cue")
    edges = {item.key: item for item in self.reads
             if item.key.type_name == "memory.association.v1"}
    if len(edges) > self.budget.max_edges:
        raise ValueError("edge read count exceeds max_edges")
    query_refs: set[str] = set()
    query_by_source = {}
    for query in self.edge_queries:
        source = AtomKey.from_token(query.source_ref)
        if (source.type_name != "memory.source" or source.owner.kind != "event"
                or (source.owner.bot, source.owner.persona) != self.namespace.as_tuple):
            raise ValueError("edge query needs a source owner")
        if (query.next_after is not None
                and (not query.edge_refs
                     or query.next_after != max(query.edge_refs))):
            raise ValueError("query continuation must be its final included edge")
        query_by_source[source.token] = query
        if self.budget.max_hops == 0 or query.hop >= self.budget.max_hops:
            raise ValueError("edge query exceeds hop budget")
        for ref in query.edge_refs:
            key = AtomKey.from_token(ref)
            row = edges.get(key)
            if (row is None or key.owner.subject != source.owner.subject
                    or key.type_name != "memory.association.v1"
                    or ref in query_refs):
                raise ValueError("edge query does not match complete original edge reads")
            query_refs.add(ref)
    if query_refs != {key.token for key in edges}:
        raise ValueError("unaccounted association edge original")
    if self.budget.max_hops and cue.token not in query_by_source:
        raise ValueError("cue edge query is missing")
    if self.budget.max_hops == 0 and self.edge_queries:
        raise ValueError("zero-hop input cannot query edges")
    required_sources = {cue.token, *ticket_value["source_refs"],
                        *mood_value.source_refs}
    reachable = {cue.token: 0}
    for row in edges.values():
        if row.revision < 1 or not row.valid:
            raise ValueError("association edge original is invalid")
        value = row.value
        validate_association(value)
        if (row.key.name != value["association_id"]
                or source_key(*self.namespace.as_tuple, row.key.owner.subject).token
                != value["source_ref"]):
            raise ValueError("association edge address differs from source")
        required_sources.update((value["source_ref"], value["target_ref"],
                                 *value["basis_source_refs"]))
    # A complete page for every reached node inside the hop bound is needed
    # to claim complete coverage. Missing pages must be marked truncated.
    for hop in range(self.budget.max_hops):
        for ref, distance in tuple(reachable.items()):
            if distance != hop:
                continue
            query = query_by_source.get(ref)
            if query is None:
                if not self.truncated:
                    raise ValueError("reachable source query is absent without truncation")
                continue
            if query.hop != hop:
                raise ValueError("edge query hop differs from reachable graph")
            for edge_ref in query.edge_refs:
                value = edges[AtomKey.from_token(edge_ref)].value
                if (value["context_tags"]
                        and not set(value["context_tags"]) & set(self.context_tags)):
                    continue
                target = value["target_ref"]
                reachable.setdefault(target, hop + 1)
    if any(ref not in reachable for ref in query_by_source):
        raise ValueError("edge query is outside reachable hop closure")
    if any(query.next_after is not None for query in self.edge_queries) and not self.truncated:
        raise ValueError("page continuation requires explicit truncation")
    pending = list(required_sources)
    seen = set()
    parents_by_ref: dict[str, tuple[str, ...]] = {}
    while pending:
        ref = pending.pop()
        if ref in seen:
            continue
        if len(seen) >= self.budget.max_nodes:
            raise ValueError("source and ancestor closure exceeds max_nodes")
        seen.add(ref)
        key = AtomKey.from_token(ref)
        if key != source_key(*self.namespace.as_tuple, key.owner.subject):
            raise ValueError("association source key is not canonical")
        access = access_key(*self.namespace.as_tuple, key.owner.subject)
        correction = source_correction_head_key(self.namespace, key.owner.subject)
        source_row, access_row, correction_row = (by_key.get(item)
                                                  for item in (key, access, correction))
        if (source_row is None or source_row.revision < 1 or not source_row.valid
                or access_row is None or access_row.revision < 1 or not access_row.valid
                or correction_row is None):
            raise ValueError("source, access or explicit correction head is missing")
        record = SourceRecord.from_dict(source_row.value)
        validate_access(access_row.value)
        if (record.source_id != key.owner.subject
                or access_row.value["source_id"] != record.source_id
                or record.assertion_status not in {"confirmed", "reported"}
                or self.audience not in record.audiences
                or self.purpose not in record.purposes
                or access_row.value["status"] != "active"
                or self.audience not in access_row.value["audiences"]
                or self.purpose not in access_row.value["purposes"]):
            raise PermissionError("association source is unavailable")
        if correction_row.revision != 0 or correction_row.valid:
            raise ValueError("association source has a correction head")
        parents = tuple(source_key(*self.namespace.as_tuple, parent).token
                        for parent in record.parent_source_ids)
        parents_by_ref[ref] = parents
        pending.extend(parents)
    active: set[str] = set()
    settled: set[str] = set()

    def has_cycle(ref: str) -> bool:
        if ref in active:
            return True
        if ref in settled:
            return False
        active.add(ref)
        if any(has_cycle(parent) for parent in parents_by_ref[ref]):
            return True
        active.remove(ref)
        settled.add(ref)
        return False

    if any(has_cycle(ref) for ref in required_sources):
        raise ValueError("source ancestor closure has a cycle")
    expected_keys = set(keys) | set(edges)
    for ref in seen:
        source = AtomKey.from_token(ref)
        expected_keys.update((source, access_key(*self.namespace.as_tuple,
                                                 source.owner.subject),
                              source_correction_head_key(self.namespace,
                                                         source.owner.subject)))
    if set(by_key) != expected_keys:
        raise ValueError("unbound or missing original in association input")
