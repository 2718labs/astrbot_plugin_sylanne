"""Deterministic recall routing; this module performs no I/O or host actions."""

from dataclasses import dataclass
from enum import Enum
import math
import time


class Trigger(Enum):
    EXPLICIT_HISTORY = "explicit_history"
    CONTEXT_GAP = "context_gap"
    CORRECTION = "correction"
    COMMITMENT = "commitment"
    DECISION = "decision"
    ASSOCIATION = "association"
    DEADLINE = "deadline"
    MAINTENANCE = "maintenance"
    GREETING = "greeting"
    UNCERTAIN = "uncertain"


class Action(Enum):
    EXACT_CHECK = "exact_check"
    WORKING_SET = "working_set"
    LIGHT_SEARCH = "light_search"
    DEEP_SEARCH = "deep_search"
    READY = "ready"
    CLARIFY = "clarify"
    INSUFFICIENT = "insufficient"
    DEFERRED = "deferred"


def _nonempty(value, label):
    if type(value) is not str or not value:
        raise ValueError(f"{label} must be a nonempty string")


def _count(value, label):
    if type(value) is not int or value < 0:
        raise ValueError(f"{label} must be a nonnegative integer")


def _positive_finite(value, label):
    if type(value) not in (int, float) or isinstance(value, bool) or not math.isfinite(value) or value <= 0:
        raise ValueError(f"{label} must be a finite positive number")


def _names(value, label):
    if type(value) is not tuple:
        raise TypeError(f"{label} must be a tuple")
    for item in value:
        _nonempty(item, f"{label} item")
    if len(set(value)) != len(value):
        raise ValueError(f"{label} must be unique")


@dataclass(frozen=True)
class Budget:
    rounds: int
    candidates: int
    nodes: int
    model_calls: int

    def __post_init__(self):
        for name in ("rounds", "candidates", "nodes", "model_calls"):
            _count(getattr(self, name), name)
        if self.model_calls > 2:
            raise ValueError("model_calls cannot exceed 2")

    def covers(self, other):
        return all(getattr(self, name) >= getattr(other, name) for name in self.__dataclass_fields__)

    def subtract(self, other):
        if not self.covers(other):
            raise ValueError("reservation exceeds remaining budget")
        return Budget(*(getattr(self, name) - getattr(other, name) for name in self.__dataclass_fields__))

    def add(self, other):
        # Refunds cannot increase model calls past the request's initial maximum in normal use.
        return Budget(*(getattr(self, name) + getattr(other, name) for name in self.__dataclass_fields__))


ZERO_BUDGET = Budget(0, 0, 0, 0)


@dataclass(frozen=True)
class Evidence:
    source_id: str
    source_family: str
    fills: tuple[str, ...] = ()
    checks: tuple[str, ...] = ()
    score: float = 0.0
    external: bool = True

    def __post_init__(self):
        _nonempty(self.source_id, "source_id")
        _nonempty(self.source_family, "source_family")
        _names(self.fills, "fills")
        _names(self.checks, "checks")
        if type(self.score) not in (int, float) or isinstance(self.score, bool) or not math.isfinite(self.score):
            raise ValueError("score must be a finite number")
        if type(self.external) is not bool:
            raise TypeError("external must be bool")


def _merge_evidence(old, new):
    if old.source_family != new.source_family or old.external is not new.external:
        raise ValueError("conflicting evidence for source_id")
    return Evidence(
        source_id=old.source_id,
        source_family=old.source_family,
        fills=tuple(dict.fromkeys(old.fills + new.fills)),
        checks=tuple(dict.fromkeys(old.checks + new.checks)),
        score=max(old.score, new.score),
        external=old.external,
    )


@dataclass(frozen=True)
class RecallRequest:
    request_id: str
    trigger: Trigger
    gaps: tuple[str, ...]
    required_checks: tuple[str, ...]
    budget: Budget
    timeout_seconds: float = 5.0

    def __post_init__(self):
        _nonempty(self.request_id, "request_id")
        if type(self.trigger) is not Trigger:
            raise TypeError("trigger must be Trigger")
        _names(self.gaps, "gaps")
        _names(self.required_checks, "required_checks")
        if not isinstance(self.budget, Budget):
            raise TypeError("budget must be Budget")
        _positive_finite(self.timeout_seconds, "timeout_seconds")


@dataclass(frozen=True)
class Plan:
    request_id: str
    operation_id: str
    action: Action
    targets: tuple[str, ...] = ()
    reservation: Budget = ZERO_BUDGET
    evidence: tuple[Evidence, ...] = ()
    missing_gaps: tuple[str, ...] = ()
    missing_checks: tuple[str, ...] = ()
    activated_source_ids: tuple[str, ...] = ()
    external_evidence_families: tuple[str, ...] = ()
    recall_experience: bool = False
    action_authorized: bool = False


@dataclass(frozen=True)
class SearchResult:
    request_id: str
    operation_id: str
    action: Action
    evidence: tuple[Evidence, ...] = ()
    candidates_used: int = 0
    nodes_used: int = 0
    model_calls_used: int = 0

    def __post_init__(self):
        _nonempty(self.request_id, "request_id")
        _nonempty(self.operation_id, "operation_id")
        if type(self.action) is not Action:
            raise TypeError("action must be Action")
        if type(self.evidence) is not tuple or any(not isinstance(item, Evidence) for item in self.evidence):
            raise TypeError("evidence must be a tuple of Evidence")
        for name in ("candidates_used", "nodes_used", "model_calls_used"):
            _count(getattr(self, name), name)


class RecallPolicy:
    """A bounded, deterministic state machine whose caller supplies all evidence."""

    _EXPERIENCE_TRIGGERS = {Trigger.EXPLICIT_HISTORY, Trigger.ASSOCIATION}
    _IMPLICIT_CHECKS = {
        Trigger.CORRECTION: "relevant_source_version",
        Trigger.COMMITMENT: "commitment_preconditions",
        Trigger.DEADLINE: "bound_responsibility_status",
    }

    def __init__(self, recall_request, *, clock=time.monotonic):
        if not isinstance(recall_request, RecallRequest):
            raise TypeError("recall_request must be RecallRequest")
        if not callable(clock):
            raise TypeError("clock must be callable")
        started_at = clock()
        if type(started_at) not in (int, float) or isinstance(started_at, bool) or not math.isfinite(started_at):
            raise ValueError("clock must return a finite number")
        deadline = started_at + recall_request.timeout_seconds
        _positive_finite(deadline, "deadline")
        self.request = recall_request
        self._clock = clock
        self.deadline = deadline
        self.remaining = recall_request.budget
        self.pending_plan = None
        self._sequence = 0
        self._completed_actions = set()
        self._accepted = {}
        self._evidence = {}
        self._missing_gaps = list(recall_request.gaps)
        checks = list(recall_request.required_checks)
        if recall_request.trigger is Trigger.UNCERTAIN and "trigger_classification" not in checks:
            checks.insert(0, "trigger_classification")
        implicit = self._IMPLICIT_CHECKS.get(recall_request.trigger)
        if implicit is not None and implicit not in checks:
            checks.insert(0, implicit)
        self._missing_checks = checks
        self._no_improvement = 0

    def next(self):
        if self._timed_out():
            return self._terminal(Action.INSUFFICIENT)
        if self.pending_plan is not None:
            return self.pending_plan
        if self.request.trigger is Trigger.MAINTENANCE:
            return self._terminal(Action.DEFERRED)
        if self._missing_checks:
            if self._no_improvement >= 2:
                return self._terminal(Action.INSUFFICIENT)
            reservation = Budget(
                1,
                min(8, self.remaining.candidates),
                min(32, self.remaining.nodes),
                0,
            )
            return self._dispatch(Action.EXACT_CHECK, tuple(self._missing_checks), reservation)
        if Action.WORKING_SET not in self._completed_actions:
            reservation = Budget(
                1,
                min(8, self.remaining.candidates),
                min(32, self.remaining.nodes),
                0,
            )
            return self._dispatch(Action.WORKING_SET, tuple(self._missing_gaps), reservation)
        if not self._missing_gaps:
            return self._terminal(Action.READY)
        if self.request.trigger is Trigger.CONTEXT_GAP and "referent" in self._missing_gaps:
            return self._terminal(Action.CLARIFY)
        if self._no_improvement >= 2:
            return self._terminal(Action.INSUFFICIENT)
        if Action.LIGHT_SEARCH not in self._completed_actions:
            reservation = Budget(1, min(8, self.remaining.candidates), min(6, self.remaining.nodes), 0)
            return self._dispatch(Action.LIGHT_SEARCH, tuple(self._missing_gaps), reservation)
        if Action.DEEP_SEARCH not in self._completed_actions:
            reservation = Budget(
                1,
                self.remaining.candidates,
                self.remaining.nodes,
                min(2, self.remaining.model_calls),
            )
            if reservation.candidates or reservation.nodes or reservation.model_calls:
                return self._dispatch(Action.DEEP_SEARCH, tuple(self._missing_gaps), reservation)
        return self._terminal(Action.INSUFFICIENT)

    def accept(self, result):
        if not isinstance(result, SearchResult):
            raise TypeError("result must be SearchResult")
        if result.request_id != self.request.request_id:
            raise ValueError("result request_id does not match request")
        previous = self._accepted.get(result.operation_id)
        if previous is not None:
            if previous != result:
                raise ValueError("conflicting result for operation_id")
            return
        plan = self.pending_plan
        if plan is None or result.operation_id != plan.operation_id:
            raise ValueError("result operation_id is not pending")
        if result.action is not plan.action:
            raise ValueError("result action does not match plan")
        if (
            result.candidates_used > plan.reservation.candidates
            or result.nodes_used > plan.reservation.nodes
            or result.model_calls_used > plan.reservation.model_calls
        ):
            raise ValueError("result usage exceeds reserved budget")
        used = Budget(1, result.candidates_used, result.nodes_used, result.model_calls_used)

        staged_evidence = dict(self._evidence)
        staged_missing_gaps = list(self._missing_gaps)
        staged_missing_checks = list(self._missing_checks)
        for item in result.evidence:
            old = staged_evidence.get(item.source_id)
            staged_evidence[item.source_id] = item if old is None else _merge_evidence(old, item)
            staged_missing_gaps = [name for name in staged_missing_gaps if name not in item.fills]
            staged_missing_checks = [name for name in staged_missing_checks if name not in item.checks]

        before = (len(self._missing_gaps), len(self._missing_checks))
        after = (len(staged_missing_gaps), len(staged_missing_checks))
        timed_out = self._timed_out()
        if not timed_out:
            self._evidence = staged_evidence
            self._missing_gaps = staged_missing_gaps
            self._missing_checks = staged_missing_checks
            if after < before:
                self._no_improvement = 0
            elif result.action is not Action.WORKING_SET:
                self._no_improvement += 1

        refund = Budget(
            0,
            plan.reservation.candidates - used.candidates,
            plan.reservation.nodes - used.nodes,
            plan.reservation.model_calls - used.model_calls,
        )
        self.remaining = self.remaining.add(refund)
        self._accepted[result.operation_id] = result
        if not timed_out:
            self._completed_actions.add(result.action)
        self.pending_plan = None

    def _timed_out(self):
        now = self._clock()
        if type(now) not in (int, float) or isinstance(now, bool) or not math.isfinite(now):
            raise ValueError("clock must return a finite number")
        return now >= self.deadline

    def _dispatch(self, action, targets, reservation):
        if not self.remaining.covers(reservation):
            return self._terminal(Action.INSUFFICIENT)
        self.remaining = self.remaining.subtract(reservation)
        self._sequence += 1
        self.pending_plan = Plan(
            request_id=self.request.request_id,
            operation_id=f"{self.request.request_id}:{self._sequence}:{action.value}",
            action=action,
            targets=targets,
            reservation=reservation,
        )
        return self.pending_plan

    def _terminal(self, action):
        evidence = tuple(self._evidence.values())
        source_ids = tuple(item.source_id for item in evidence)
        families = tuple(dict.fromkeys(item.source_family for item in evidence if item.external))
        experience = bool(evidence) and self.request.trigger in self._EXPERIENCE_TRIGGERS
        return Plan(
            request_id=self.request.request_id,
            operation_id="",
            action=action,
            evidence=evidence,
            missing_gaps=tuple(self._missing_gaps),
            missing_checks=tuple(self._missing_checks),
            activated_source_ids=source_ids,
            external_evidence_families=families,
            recall_experience=experience,
            action_authorized=False,
        )


@dataclass(frozen=True)
class ContinuationEstimate:
    """Inputs to the MEM-07 optional-frontier continuation decision."""

    policy_version: str
    policy_scope: str
    frontier_id: str
    evidence_gain: float | None
    latency_cost: float | None
    call_cost: float | None
    context_interference: float | None
    weights: tuple[float, float, float, float]
    threshold: float
    no_progress_count: int
    budget_admitted: bool
    deadline_admitted: bool
    permission_admitted: bool
    entry_admitted: bool
    mandatory_outstanding: bool

    def __post_init__(self):
        for name in ("policy_version", "policy_scope", "frontier_id"):
            _nonempty(getattr(self, name), name)
        for name in ("evidence_gain", "latency_cost", "call_cost", "context_interference"):
            value = getattr(self, name)
            if value is not None:
                _unit_interval(value, name)
        if type(self.weights) is not tuple or len(self.weights) != 4:
            raise TypeError("weights must be a four-item tuple")
        normalized = tuple(_unit_interval(value, "weight") for value in self.weights)
        if not math.isclose(sum(normalized), 1.0, rel_tol=0.0, abs_tol=1e-12):
            raise ValueError("weights must sum to 1")
        object.__setattr__(self, "weights", normalized)
        object.__setattr__(self, "threshold", _unit_interval(self.threshold, "threshold"))
        _count(self.no_progress_count, "no_progress_count")
        for name in (
            "budget_admitted",
            "deadline_admitted",
            "permission_admitted",
            "entry_admitted",
            "mandatory_outstanding",
        ):
            if type(getattr(self, name)) is not bool:
                raise TypeError(f"{name} must be bool")


@dataclass(frozen=True)
class ContinuationReceipt:
    policy_version: str
    policy_scope: str
    frontier_id: str
    estimates: tuple[float | None, float | None, float | None, float | None]
    weights: tuple[float, float, float, float]
    threshold: float
    net_value: float | None
    no_progress_count: int
    decision: str
    stop_reason: str | None
    missing_prerequisites: tuple[str, ...]
    request_complete: bool = False


def evaluate_continuation(estimate: ContinuationEstimate) -> ContinuationReceipt:
    """Evaluate one optional C03 frontier without weakening mandatory checks."""

    if not isinstance(estimate, ContinuationEstimate):
        raise TypeError("estimate must be ContinuationEstimate")
    values = (
        estimate.evidence_gain,
        estimate.latency_cost,
        estimate.call_cost,
        estimate.context_interference,
    )
    missing = tuple(
        name for name, value in zip(
            ("evidence_gain", "latency_cost", "call_cost", "context_interference"),
            values,
        ) if value is None
    )
    net_value = None
    if not missing:
        gain, latency, call, interference = values
        net_value = (
            estimate.weights[0] * gain
            - estimate.weights[1] * latency
            - estimate.weights[2] * call
            - estimate.weights[3] * interference
        )

    admission = {
        "budget": estimate.budget_admitted,
        "deadline": estimate.deadline_admitted,
        "permission": estimate.permission_admitted,
        "entry": estimate.entry_admitted,
    }
    failed_admission = tuple(name for name, allowed in admission.items() if not allowed)
    missing_prerequisites = tuple(dict.fromkeys(missing + failed_admission))
    if missing:
        decision, stop_reason = "stop", "unknown_cost"
    elif estimate.mandatory_outstanding:
        decision, stop_reason = "stop", "mandatory_outstanding"
    elif estimate.no_progress_count >= 2:
        decision, stop_reason = "stop", "no_progress"
    elif failed_admission:
        decision, stop_reason = "stop", "admission_failed"
    elif net_value is not None and net_value > estimate.threshold:
        decision, stop_reason = "continue", None
    else:
        decision, stop_reason = "stop", "net_value_not_above_threshold"
    return ContinuationReceipt(
        estimate.policy_version,
        estimate.policy_scope,
        estimate.frontier_id,
        values,
        estimate.weights,
        estimate.threshold,
        net_value,
        estimate.no_progress_count,
        decision,
        stop_reason,
        missing_prerequisites,
        False,
    )


def _unit_interval(value, label):
    if type(value) not in (int, float) or isinstance(value, bool) or not math.isfinite(value):
        raise ValueError(f"{label} must be finite")
    value = float(value)
    if not 0.0 <= value <= 1.0:
        raise ValueError(f"{label} must be between 0 and 1")
    return value
