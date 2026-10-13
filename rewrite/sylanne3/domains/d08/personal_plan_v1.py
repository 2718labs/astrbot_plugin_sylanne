"""Bounded personal plans and reproducible D08 choice, without execution authority."""
from dataclasses import dataclass, fields
import math

from ...graph_types import AtomKey, TypeSpec
from ...runtime_contracts import VersionedRef, canonical_serialize, schema_hash
from .execution import GoalPredicate, JointPlan, PlanNode, _predicate, _strings, _text, _positive

PLAN_TYPE = "d08.personal_plan.v1"
DECISION_TYPE = "d08.decision_record.v2"
POLICY_VERSION = "d08.bounded-choice.v3:1"
PLAN_STATES = frozenset({"active", "waiting", "paused", "satisfied", "abandoned", "superseded"})


def _versions(values, label, limit=128):
    if (type(values) is not tuple or len(values) > limit
            or any(type(row) is not VersionedRef for row in values)
            or len({row.ref for row in values}) != len(values)):
        raise ValueError(label + " requires bounded distinct actual versions")
    for row in values:
        AtomKey.from_token(row.ref)


@dataclass(frozen=True)
class PlanNodeV2(PlanNode):
    observable_postconditions: tuple[GoalPredicate, ...] = ()
    pending_original_effects: tuple[str, ...] = ()
    carried_forward_verified: tuple[str, ...] = ()
    wait_condition: str | None = None
    cost_ceiling: tuple[tuple[str, int], ...] = ()
    schema: str = "d08.plan-node.v2"

    def __post_init__(self):
        super().__post_init__()
        if (self.schema != "d08.plan-node.v2" or not self.observable_postconditions
                or len(self.observable_postconditions) > 8
                or any(type(p) is not GoalPredicate for p in self.observable_postconditions)
                or self.success_predicate not in self.observable_postconditions):
            raise ValueError("plan node requires its frozen observable postconditions")
        for name in ("pending_original_effects", "carried_forward_verified"):
            object.__setattr__(self, name, _strings(getattr(self, name), name))
            if len(getattr(self, name)) > 32:
                raise ValueError("plan effect references exceed the bounded window")
        if set(self.pending_original_effects) & set(self.carried_forward_verified):
            raise ValueError("an effect cannot be both unknown and verified")
        if self.wait_condition is not None:
            _text(self.wait_condition, "wait_condition")
        if self.pending_original_effects and self.wait_condition is None:
            raise ValueError("unknown effects require a concrete original-result wake condition")
        if (type(self.cost_ceiling) is not tuple or len(self.cost_ceiling) > 32
                or len({name for name, _ in self.cost_ceiling}) != len(self.cost_ceiling)
                or any(type(amount) is not int or not 0 <= amount <= 9_000_000_000_000_000
                       for _, amount in self.cost_ceiling)):
            raise ValueError("plan cost ceilings require finite integer base units")
        for name, _ in self.cost_ceiling:
            _text(name, "cost dimension")


@dataclass(frozen=True, slots=True)
class PersonalPlanV1:
    plan_id: str
    revision: int
    goal_ref: str
    goal_revision: int
    state: str
    actor_ref: str
    nodes: tuple[PlanNodeV2, ...]
    candidate_refs: tuple[str, ...]
    pause_conditions: tuple[str, ...]
    waiting_conditions: tuple[str, ...]
    cancel_conditions: tuple[str, ...]
    source_refs: tuple[str, ...]
    fact_versions: tuple[VersionedRef, ...]
    parent_plan_revision_ref: VersionedRef | None
    schema: str = PLAN_TYPE
    method_candidates: tuple[tuple[str, str], ...] = ()

    def __post_init__(self):
        _text(self.plan_id, "plan_id", "plan:")
        _positive(self.revision, "revision")
        _positive(self.goal_revision, "goal_revision")
        _text(self.actor_ref, "actor_ref", "persona:")
        if (self.schema != PLAN_TYPE or self.state not in PLAN_STATES
                or AtomKey.from_token(self.goal_ref).type_name != "d08.goal.v1"
                or type(self.nodes) is not tuple or not 1 <= len(self.nodes) <= 8
                or any(type(node) is not PlanNodeV2 or node.owner_ref != self.actor_ref for node in self.nodes)):
            raise ValueError("personal plan requires a bounded single-subject window")
        node_ids = {node.node_id for node in self.nodes}
        if len(node_ids) != len(self.nodes) or any(not set(node.depends_on) <= node_ids for node in self.nodes):
            raise ValueError("personal plan node/dependency identity differs")
        JointPlan._assert_acyclic(self.nodes)
        for name in ("candidate_refs", "pause_conditions", "waiting_conditions", "cancel_conditions", "source_refs"):
            object.__setattr__(self, name, _strings(getattr(self, name), name))
        if len(self.candidate_refs) > 6 or not self.source_refs:
            raise ValueError("personal plan candidates/sources exceed their contract")
        if (type(self.method_candidates) is not tuple or len(self.method_candidates) > 6
                or any(type(row) is not tuple or len(row) != 2
                    or any(type(ref) is not str or not ref for ref in row) for row in self.method_candidates)
                or len({row[0] for row in self.method_candidates}) != len(self.method_candidates)
                or not {row[0] for row in self.method_candidates} <= set(self.candidate_refs)):
            raise ValueError("method identity requires bounded distinct adopted plan candidates")
        object.__setattr__(self, "method_candidates", tuple(sorted(self.method_candidates)))
        if self.state == "waiting" and not self.waiting_conditions:
            raise ValueError("waiting requires a concrete wake condition")
        if not self.cancel_conditions:
            raise ValueError("a personal plan requires an explicit cancellation condition")
        for ref in self.source_refs:
            if AtomKey.from_token(ref).type_name != "memory.source":
                raise ValueError("plan sources must be actual D06 sources")
        _versions(self.fact_versions, "plan facts")
        if not self.fact_versions or any(row.ref == self.goal_ref for row in self.fact_versions):
            raise ValueError("plan evidence must exclude its own mutable goal")
        parent = self.parent_plan_revision_ref
        if self.revision == 1:
            if parent is not None:
                raise ValueError("new plan cannot claim an old revision")
        elif (type(parent) is not VersionedRef or parent.version != self.revision - 1
                or AtomKey.from_token(parent.ref).type_name != PLAN_TYPE):
            raise ValueError("plan revision requires its exact predecessor")
        if len(canonical_serialize(self).encode("utf-8")) > 131072:
            raise ValueError("personal plan exceeds its encoded bound")


@dataclass(frozen=True, slots=True)
class QualifiedPersonalCandidateV1:
    """Pure selector input; installed readers establish these facts, not models."""
    candidate_ref: str
    action_ref: str
    node_id: str
    semantic_digest: str
    hard_status: str
    irreversible_exposure: int
    observable_postcondition: bool
    established_deadline: float | None
    quote_ref: str | None
    pending_original_effects: tuple[str, ...] = ()
    carried_forward_verified: tuple[str, ...] = ()
    numeric_discriminator_unresolved: bool = False
    recovery_branch: bool = False
    established_commitment: bool = False

    def __post_init__(self):
        for name in ("candidate_ref", "action_ref", "node_id"):
            _text(getattr(self, name), name)
        if len(self.semantic_digest) != 64 or any(c not in "0123456789abcdef" for c in self.semantic_digest):
            raise ValueError("candidate semantics require the canonical exact digest")
        if self.hard_status not in {"eligible", "REQUIRED_CHECK_UNRESOLVED", "REJECTED",
                "WAIT_COST_EVIDENCE", "WAIT_ORIGINAL_EFFECT", "WAIT_BUDGET"}:
            raise ValueError("candidate hard status differs")
        if type(self.irreversible_exposure) is not int or not 0 <= self.irreversible_exposure <= 3:
            raise ValueError("candidate exposure class differs")
        for name in ("observable_postcondition", "numeric_discriminator_unresolved", "recovery_branch", "established_commitment"):
            if type(getattr(self, name)) is not bool:
                raise TypeError("candidate discriminators must be exact booleans")
        if self.established_deadline is not None and (type(self.established_deadline) not in (int, float)
                or not math.isfinite(self.established_deadline)):
            raise ValueError("candidate deadline must be actually established and finite")
        for name in ("pending_original_effects", "carried_forward_verified"):
            object.__setattr__(self, name, _strings(getattr(self, name), name))
        if self.hard_status == "eligible" and (self.quote_ref is None or self.pending_original_effects):
            raise ValueError("eligible choice requires known costs and no unresolved original effect")
        if len(canonical_serialize(self).encode("utf-8")) > 16384:
            raise ValueError("candidate exceeds its encoded bound")


@dataclass(frozen=True, slots=True)
class DecisionRecordV2:
    decision_id: str
    chosen_action_ref: str | None
    eligible_action_refs: tuple[str, ...]
    rejected_reasons: tuple[tuple[str, str], ...]
    unknown_refs: tuple[str, ...]
    source_refs: tuple[str, ...]
    policy_version: str
    preference_edges: tuple[tuple[str, str], ...]
    sccs: tuple[tuple[str, ...], ...]
    conflict_refs: tuple[str, ...]
    unknown_reason: str | None
    read_versions: tuple[VersionedRef, ...]
    quote_ref: str | None
    carried_forward_verified: tuple[str, ...]
    schema: str = DECISION_TYPE

    def __post_init__(self):
        _text(self.decision_id, "decision_id", "decision:")
        if self.schema != DECISION_TYPE or self.policy_version != POLICY_VERSION:
            raise ValueError("decision must identify its frozen reproducible policy")
        for name in ("eligible_action_refs", "unknown_refs", "source_refs", "conflict_refs", "carried_forward_verified"):
            object.__setattr__(self, name, _strings(getattr(self, name), name))
        if len(self.eligible_action_refs) > 6 or len(self.preference_edges) > 30 or not self.source_refs:
            raise ValueError("decision exceeds its bounded candidate/edge/source contract")
        if self.chosen_action_ref is not None and self.chosen_action_ref not in self.eligible_action_refs:
            raise ValueError("a decision cannot choose an ineligible action")
        if self.chosen_action_ref is not None and self.quote_ref is None:
            raise ValueError("selected action must retain its actual cost quote")
        if len(self.rejected_reasons) > 6 or len({ref for ref, _ in self.rejected_reasons}) != len(self.rejected_reasons):
            raise ValueError("decision reasons repeat a candidate")
        for left, right in (*self.preference_edges, *self.rejected_reasons):
            _text(left, "decision reference")
            _text(right, "decision reason/reference")
        if len(self.sccs) > 6 or sum(len(scc) for scc in self.sccs) > 6:
            raise ValueError("decision SCC exceeds six candidates")
        _versions(self.read_versions, "decision reads", limit=1024)
        if len(canonical_serialize(self).encode("utf-8")) > 131072:
            raise ValueError("decision exceeds its encoded bound")


def preference_sccs_v1(candidate_refs, preference_edges):
    """Six-vertex deterministic transitive closure, independent of input order."""
    vertices = tuple(sorted(candidate_refs))
    if len(vertices) > 6 or len(set(vertices)) != len(vertices) or len(preference_edges) > 30:
        raise ValueError("preference graph exceeds its contract")
    edges = set(preference_edges)
    if any(a == b or a not in vertices or b not in vertices for a, b in edges):
        raise ValueError("preference edges must join two candidate vertices")
    reachable = {ref: {ref} for ref in vertices}
    for left, right in edges:
        reachable[left].add(right)
    for via in vertices:
        for start in vertices:
            if via in reachable[start]:
                reachable[start].update(reachable[via])
    remaining, result = set(vertices), []
    for vertex in vertices:
        if vertex in remaining:
            group = tuple(ref for ref in vertices if ref in reachable[vertex] and vertex in reachable[ref])
            result.append(group)
            remaining.difference_update(group)
    return tuple(result)


def select_personal_step_v2(*, decision_id, candidates, preference_edges, source_refs, read_versions):
    if (type(candidates) is not tuple or not 1 <= len(candidates) <= 6
            or any(type(c) is not QualifiedPersonalCandidateV1 for c in candidates)
            or len({c.candidate_ref for c in candidates}) != len(candidates)
            or len({c.action_ref for c in candidates}) != len(candidates)):
        raise ValueError("choice requires one bounded distinct candidate set")
    all_refs = {c.candidate_ref for c in candidates}
    preference_sccs_v1(all_refs, preference_edges)
    eligible = tuple(sorted((c for c in candidates if c.hard_status == "eligible"), key=lambda c: c.candidate_ref))
    # An already-established, feasible obligation is lexicographically prior
    # to soft preferences; it never makes an ineligible candidate eligible.
    priority = [c for c in eligible if c.established_commitment]
    ranked = tuple(priority) if priority else eligible
    refs = {c.candidate_ref for c in eligible}
    ranked_refs = {c.candidate_ref for c in ranked}
    edges = tuple(sorted((a, b) for a, b in set(preference_edges) if a in refs and b in refs))
    sccs = preference_sccs_v1(refs, edges)
    component = {ref: index for index, group in enumerate(sccs) for ref in group}
    dominated = {component[b] for a, b in edges if a in ranked_refs and b in ranked_refs and component[a] != component[b]}
    frontier = [c for c in ranked if component[c.candidate_ref] not in dominated]
    chosen, unknown = None, None
    if frontier:
        def rank(candidate):
            return (candidate.irreversible_exposure, not candidate.observable_postcondition,
                candidate.established_deadline if candidate.established_deadline is not None else math.inf)
        best = min(rank(c) for c in frontier)
        finalists = [c for c in frontier if rank(c) == best]
        if any(c.numeric_discriminator_unresolved for c in finalists):
            unknown = "NUMERIC_DISCRIMINATOR_UNRESOLVED"
        elif len({c.semantic_digest for c in finalists}) == 1:
            chosen = min(finalists, key=lambda c: c.candidate_ref)
        else:
            unknown = "PREFERENCE_CONFLICT_UNRESOLVED"
        if chosen is None:
            recovery = [c for c in eligible if c.recovery_branch and not c.numeric_discriminator_unresolved]
            if recovery and len({c.semantic_digest for c in recovery}) == 1:
                chosen = min(recovery, key=lambda c: c.candidate_ref)
    else:
        unknown = "NO_QUALIFIED_STEP"
    reasons = []
    for candidate in sorted(candidates, key=lambda c: c.candidate_ref):
        if chosen is not None and candidate == chosen:
            continue
        reason = candidate.hard_status if candidate.hard_status != "eligible" else (
            unknown or "PREFERENCE_POLICY_NOT_SELECTED")
        reasons.append((candidate.candidate_ref, reason))
    return DecisionRecordV2(decision_id, chosen.action_ref if chosen else None,
        tuple(c.action_ref for c in eligible), tuple(reasons),
        tuple(sorted({ref for c in candidates for ref in c.pending_original_effects})), source_refs,
        POLICY_VERSION, edges, sccs, tuple(ref for group in sccs if len(group) > 1 for ref in group),
        unknown, read_versions, chosen.quote_ref if chosen else None,
        tuple(sorted({ref for c in candidates for ref in c.carried_forward_verified})))


def decode_personal_plan_type_v1(type_name, value):
    cls = {PLAN_TYPE: PersonalPlanV1, DECISION_TYPE: DecisionRecordV2}[type_name]
    names = {field.name for field in fields(cls)}
    if (type(value) is not dict or (set(value) != names and
            not (cls is PersonalPlanV1 and set(value) == names - {"method_candidates"}))):
        raise ValueError("personal plan/decision has unexpected fields")
    raw = dict(value)
    if cls is PersonalPlanV1:
        raw.setdefault("method_candidates", [])
        raw["method_candidates"] = tuple(tuple(row) for row in raw["method_candidates"])
    if cls is PersonalPlanV1:
        nodes = []
        for node in raw["nodes"]:
            nested = dict(node)
            nested["success_predicate"] = _predicate(nested["success_predicate"])
            nested["observable_postconditions"] = tuple(_predicate(p) for p in nested["observable_postconditions"])
            for name in ("depends_on", "pending_original_effects", "carried_forward_verified"):
                nested[name] = tuple(nested[name])
            nested["cost_ceiling"] = tuple(tuple(row) for row in nested["cost_ceiling"])
            nodes.append(PlanNodeV2(**nested))
        raw["nodes"] = tuple(nodes)
        for name in ("candidate_refs", "pause_conditions", "waiting_conditions", "cancel_conditions", "source_refs"):
            raw[name] = tuple(raw[name])
        raw["fact_versions"] = tuple(VersionedRef(**row) for row in raw["fact_versions"])
        if raw["parent_plan_revision_ref"] is not None:
            raw["parent_plan_revision_ref"] = VersionedRef(**raw["parent_plan_revision_ref"])
    else:
        for name in ("eligible_action_refs", "unknown_refs", "source_refs", "conflict_refs", "carried_forward_verified"):
            raw[name] = tuple(raw[name])
        for name in ("rejected_reasons", "preference_edges", "sccs"):
            raw[name] = tuple(tuple(row) for row in raw[name])
        raw["read_versions"] = tuple(VersionedRef(**row) for row in raw["read_versions"])
    return cls(**raw)


def personal_plan_type_specs_v1():
    return tuple(TypeSpec(kind, ("activity",), "state",
        lambda value, kind=kind: decode_personal_plan_type_v1(kind, value),
        immutable=kind == DECISION_TYPE, writer_domain="d08", schema_version=2 if kind == DECISION_TYPE else 1,
        schema_hash=schema_hash({"type": kind, "fields": tuple(cls.__dataclass_fields__), "node": 2}))
        for kind, cls in ((PLAN_TYPE, PersonalPlanV1), (DECISION_TYPE, DecisionRecordV2)))


def decision_policy_status_v1(type_name):
    if type_name == "d08.decision_record.v1":
        return "legacy_policy_not_reproducible"
    if type_name == DECISION_TYPE:
        return POLICY_VERSION
    raise ValueError("unknown decision-record schema")
