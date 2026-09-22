"""Deterministic compilation and evaluation of pure graph operators."""

import asyncio
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass

from .contracts import StepResult, json_object, nonempty
from .graph_types import AtomKey, GraphAtom, GraphSnapshot, GraphWrite


def _keys(value, label):
    if not isinstance(value, tuple):
        raise TypeError(f"{label} must be a tuple")
    if any(not isinstance(item, AtomKey) for item in value):
        raise TypeError(f"{label} must contain only AtomKey values")
    if len(set(value)) != len(value):
        raise ValueError(f"{label} must not contain duplicate keys")
    return value


@dataclass(frozen=True)
class OperatorSpec:
    name: str
    inputs: tuple[AtomKey, ...]
    outputs: tuple[AtomKey, ...]
    compute: Callable[[Mapping[AtomKey, dict]], Mapping[AtomKey, dict]]
    delayed_inputs: tuple[AtomKey, ...] = ()

    def __post_init__(self):
        nonempty(self.name, "operator name")
        _keys(self.inputs, "inputs")
        _keys(self.outputs, "outputs")
        _keys(self.delayed_inputs, "delayed_inputs")
        if not self.outputs:
            raise ValueError("operator outputs must not be empty")
        if not callable(self.compute):
            raise TypeError("operator compute must be callable")
        if not set(self.delayed_inputs).issubset(self.inputs):
            raise ValueError("delayed_inputs must be a subset of inputs")


def _snapshot_atom(snapshot, key):
    atom = snapshot.get(key)
    if atom is None:
        return None
    if not hasattr(atom, "key") or atom.key != key:
        raise TypeError("snapshot returned a malformed graph atom")
    return atom


class OperatorPlan:
    def __init__(self, ordered_specs, required_keys, instantaneous_children):
        self._specs = tuple(ordered_specs)
        self.order = tuple(spec.name for spec in self._specs)
        self.required_keys = tuple(required_keys)
        self._children = {
            name: tuple(sorted(children)) for name, children in instantaneous_children.items()
        }

    def job(self, snapshot, changed=None):
        if not isinstance(snapshot, GraphSnapshot):
            raise TypeError("snapshot must be GraphSnapshot")
        detached_snapshot = GraphSnapshot(
            tuple(GraphAtom(atom.key, atom.revision, atom.value, atom.valid) for atom in snapshot.atoms),
            snapshot.epochs,
        )
        changed_keys = self._changed_keys(changed)
        active = self._active_operators(detached_snapshot, changed_keys)
        return OperatorJob(
            tuple(spec for spec in self._specs if spec.name in active),
            detached_snapshot,
        )

    def evaluate(self, snapshot, changed=None):
        job = self.job(snapshot, changed)
        return job.step(max(1, len(self._specs)), _NeverCancelled()).value

    @staticmethod
    def _changed_keys(changed):
        if changed is None:
            return None
        if not isinstance(changed, Iterable) or isinstance(changed, (str, bytes)):
            raise TypeError("changed must be an iterable of AtomKey values")
        changed_keys = tuple(changed)
        if any(not isinstance(item, AtomKey) for item in changed_keys):
            raise TypeError("changed must contain only AtomKey values")
        return changed_keys

    def _active_operators(self, snapshot, changed):
        if changed is None:
            return {spec.name for spec in self._specs}

        active = set()
        changed_set = set(changed)
        for spec in self._specs:
            dirty_output = any(
                (current := _snapshot_atom(snapshot, output_key)) is None or not current.valid
                for output_key in spec.outputs
            )
            if changed_set.intersection(spec.inputs) or dirty_output:
                active.add(spec.name)

        pending = list(active)
        while pending:
            parent = pending.pop()
            for child in self._children[parent]:
                if child not in active:
                    active.add(child)
                    pending.append(child)
        return active


class _NeverCancelled:
    @staticmethod
    def is_set():
        return False


class OperatorJob:
    def __init__(self, specs, snapshot):
        self._specs = specs
        self._snapshot = snapshot
        self._position = 0
        self._staged = {}
        self._writes = []
        self._result = None

    def step(self, budget, cancelled):
        if type(budget) is not int or budget < 1:
            raise ValueError("budget must be a positive integer")
        if cancelled.is_set():
            raise asyncio.CancelledError()
        if self._result is not None:
            return StepResult(True, self._result)

        stop = min(self._position + budget, len(self._specs))
        while self._position < stop:
            if cancelled.is_set():
                raise asyncio.CancelledError()
            self._execute(self._specs[self._position])
            self._position += 1

        if self._position == len(self._specs):
            self._result = tuple(self._writes)
            return StepResult(True, self._result)
        return StepResult(False)

    def _execute(self, spec):
        values = {}
        for input_key in spec.inputs:
            if input_key not in spec.delayed_inputs and input_key in self._staged:
                value = self._staged[input_key]
            else:
                current = _snapshot_atom(self._snapshot, input_key)
                if current is None or not current.valid:
                    raise ValueError(
                        f"operator {spec.name!r} has missing or invalid input {input_key.token}"
                    )
                value = current.value
            values[input_key] = json_object(value)

        returned = spec.compute(values)
        if not isinstance(returned, Mapping):
            raise TypeError(f"operator {spec.name!r} must return a mapping")
        try:
            returned_keys = set(returned.keys())
        except TypeError as exc:
            raise TypeError(f"operator {spec.name!r} returned malformed output keys") from exc
        expected = set(spec.outputs)
        if returned_keys != expected or any(not isinstance(item, AtomKey) for item in returned_keys):
            raise ValueError(f"operator {spec.name!r} must return exactly its declared outputs")

        dependencies = tuple(key for key in spec.inputs if key not in spec.delayed_inputs)
        pending_writes = tuple(
            GraphWrite(output_key, returned[output_key], dependencies)
            for output_key in spec.outputs
        )
        for write in pending_writes:
            self._writes.append(write)
            self._staged[write.key] = write.value


def compile_operators(specs):
    """Validate and compile pure DAG operators into a deterministic plan."""
    if not isinstance(specs, Iterable) or isinstance(specs, (str, bytes)):
        raise TypeError("specs must be an iterable of OperatorSpec values")
    specs = tuple(specs)
    if any(not isinstance(spec, OperatorSpec) for spec in specs):
        raise TypeError("specs must contain only OperatorSpec values")

    by_name = {}
    producers = {}
    for spec in specs:
        if spec.name in by_name:
            raise ValueError(f"duplicate operator name: {spec.name}")
        by_name[spec.name] = spec
        for output_key in spec.outputs:
            previous = producers.get(output_key)
            if previous is not None:
                raise ValueError(
                    f"multiple writers for {output_key.token}: {previous!r} and {spec.name!r}"
                )
            producers[output_key] = spec.name

    children = {name: set() for name in by_name}
    incoming = {name: 0 for name in by_name}
    for spec in specs:
        for input_key in spec.inputs:
            if input_key in spec.delayed_inputs:
                continue
            producer = producers.get(input_key)
            if producer is not None and spec.name not in children[producer]:
                children[producer].add(spec.name)
                incoming[spec.name] += 1

    ready = sorted(name for name, count in incoming.items() if count == 0)
    ordered = []
    while ready:
        name = ready.pop(0)
        ordered.append(by_name[name])
        for child in sorted(children[name]):
            incoming[child] -= 1
            if incoming[child] == 0:
                ready.append(child)
                ready.sort()
    if len(ordered) != len(specs):
        raise ValueError("unsupported instantaneous operator cycle (numerical SCCs are not supported)")

    required = {key for spec in specs for key in spec.inputs + spec.outputs}
    return OperatorPlan(ordered, sorted(required, key=lambda item: item.token), children)
