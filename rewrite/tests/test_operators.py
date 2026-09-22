import asyncio
import threading
import unittest

from sylanne3.contracts import Scope
from sylanne3.graph_types import AtomKey, GraphAtom, GraphSnapshot, Owner
from sylanne3.operators import OperatorSpec, compile_operators
from sylanne3.scheduler import BoundedScheduler


OWNER = Owner("persona", "bot", "persona")


def key(name, type_name="number"):
    return AtomKey(OWNER, type_name, name)


def snapshot(*atoms):
    return GraphSnapshot(tuple(atoms), ())


def atom(atom_key, value, revision=1, valid=True):
    return GraphAtom(atom_key, revision, value, valid)


class OperatorCompilationTests(unittest.TestCase):
    def test_plan_order_and_required_keys_are_deterministic(self):
        source, left, right, result = map(key, ("source", "left", "right", "result"))
        specs = (
            OperatorSpec("z_right", (source,), (right,), lambda values: {right: {"n": values[source]["n"] + 1}}),
            OperatorSpec("a_join", (left, right), (result,), lambda values: {result: {"n": values[left]["n"] + values[right]["n"]}}),
            OperatorSpec("m_left", (source,), (left,), lambda values: {left: {"n": values[source]["n"] * 2}}),
        )

        plan = compile_operators(specs)

        self.assertEqual(plan.order, ("m_left", "z_right", "a_join"))
        self.assertEqual(plan.required_keys, tuple(sorted((source, left, right, result), key=lambda item: item.token)))

    def test_compile_rejects_multiple_writers_bad_keys_and_delayed_non_inputs(self):
        source, output = key("source"), key("output")
        identity = lambda values: {output: values[source]}
        with self.assertRaises(ValueError):
            compile_operators((
                OperatorSpec("one", (source,), (output,), identity),
                OperatorSpec("two", (source,), (output,), identity),
            ))
        with self.assertRaises(TypeError):
            compile_operators((OperatorSpec("bad", ("not-a-key",), (output,), identity),))
        with self.assertRaises(ValueError):
            compile_operators((OperatorSpec("bad", (source,), (output,), identity, (output,)),))

    def test_compile_rejects_instantaneous_cycles_instead_of_claiming_scc_support(self):
        left, right = key("left"), key("right")
        with self.assertRaisesRegex(ValueError, "cycle|SCC"):
            compile_operators((
                OperatorSpec("left", (right,), (left,), lambda values: {left: values[right]}),
                OperatorSpec("right", (left,), (right,), lambda values: {right: values[left]}),
            ))


class OperatorEvaluationTests(unittest.TestCase):
    def test_full_and_sparse_recomputation_are_equivalent(self):
        a, b, x, y, total = map(key, ("a", "b", "x", "y", "total"))
        plan = compile_operators((
            OperatorSpec("x", (a,), (x,), lambda values: {x: {"n": values[a]["n"] * 10}}),
            OperatorSpec("y", (b,), (y,), lambda values: {y: {"n": values[b]["n"] * 100}}),
            OperatorSpec("total", (x, y), (total,), lambda values: {total: {"n": values[x]["n"] + values[y]["n"]}}),
        ))
        current = snapshot(
            atom(a, {"n": 3}, 2), atom(b, {"n": 5}),
            atom(x, {"n": 20}), atom(y, {"n": 500}), atom(total, {"n": 520}),
        )

        full = plan.evaluate(current)
        sparse = plan.evaluate(current, changed=(a,))

        self.assertEqual([write.key for write in sparse], [x, total])
        full_values = {write.key: write.value for write in full}
        self.assertEqual({write.key: write.value for write in sparse}, {x: full_values[x], total: full_values[total]})
        self.assertEqual(sparse[-1].dependencies, (x, y))

    def test_delayed_input_reads_frozen_value_even_when_producer_runs_first(self):
        source, state, observed = key("source"), key("state"), key("observed")
        plan = compile_operators((
            OperatorSpec("a_stage", (source,), (state,), lambda values: {state: {"n": values[source]["n"]}}),
            OperatorSpec("z_observe_old", (state,), (observed,), lambda values: {observed: {"n": values[state]["n"]}}, (state,)),
        ))

        writes = plan.evaluate(snapshot(atom(source, {"n": 9}), atom(state, {"n": 2}), atom(observed, {"n": 1})))

        self.assertEqual([write.value for write in writes], [{"n": 9}, {"n": 2}])
        self.assertEqual(writes[1].dependencies, ())

    def test_missing_or_invalid_input_requires_staged_replacement(self):
        source, staged, result = key("source"), key("staged"), key("result")
        consumer = OperatorSpec("consumer", (staged,), (result,), lambda values: {result: values[staged]})
        with self.assertRaisesRegex(ValueError, "missing|invalid"):
            compile_operators((consumer,)).evaluate(snapshot())
        with self.assertRaisesRegex(ValueError, "missing|invalid"):
            compile_operators((consumer,)).evaluate(snapshot(atom(staged, {}, valid=False)))

        producer = OperatorSpec("producer", (source,), (staged,), lambda values: {staged: values[source]})
        writes = compile_operators((consumer, producer)).evaluate(
            snapshot(atom(source, {"n": 4}), atom(staged, {}, valid=False))
        )
        self.assertEqual(writes[-1].value, {"n": 4})

    def test_compute_cannot_mutate_snapshot_or_another_operator_input(self):
        source, first, second = key("source"), key("first"), key("second")
        retained = {}

        def mutator(values):
            values[source]["items"].append("mutated")
            result = {first: {"items": values[source]["items"]}}
            retained["result"] = result[first]
            return result

        plan = compile_operators((
            OperatorSpec("a_mutator", (source,), (first,), mutator),
            OperatorSpec("b_reader", (source,), (second,), lambda values: {second: {"items": values[source]["items"]}}),
        ))
        original = atom(source, {"items": ["original"]})

        writes = plan.evaluate(snapshot(original))
        retained["result"]["items"].append("late")

        self.assertEqual(original.value, {"items": ["original"]})
        self.assertEqual(writes[0].value, {"items": ["original", "mutated"]})
        self.assertEqual(writes[1].value, {"items": ["original"]})

    def test_compute_must_return_exact_declared_output_mapping(self):
        source, output, extra = key("source"), key("output"), key("extra")
        current = snapshot(atom(source, {"n": 1}))
        for returned in ({}, {output: {"n": 1}, extra: {}}, {"bad": {}}):
            plan = compile_operators((OperatorSpec("bad", (source,), (output,), lambda values, returned=returned: returned),))
            with self.assertRaises((TypeError, ValueError)):
                plan.evaluate(current)

    def test_changed_activates_readers_dirty_outputs_and_only_instantaneous_descendants(self):
        source, other, mid, direct, delayed, clean = map(key, ("source", "other", "mid", "direct", "delayed", "clean"))
        plan = compile_operators((
            OperatorSpec("mid", (source,), (mid,), lambda values: {mid: values[source]}),
            OperatorSpec("direct", (mid,), (direct,), lambda values: {direct: values[mid]}),
            OperatorSpec("delayed", (mid,), (delayed,), lambda values: {delayed: values[mid]}, (mid,)),
            OperatorSpec("clean", (other,), (clean,), lambda values: {clean: values[other]}),
        ))
        current = snapshot(
            atom(source, {"n": 2}), atom(other, {"n": 8}), atom(mid, {"n": 1}),
            atom(direct, {"n": 1}), atom(delayed, {"n": 1}), atom(clean, {}, valid=False),
        )

        writes = plan.evaluate(current, changed=(source,))

        self.assertEqual([write.key for write in writes], [clean, mid, direct])


class OperatorJobTests(unittest.TestCase):
    def test_step_executes_at_most_budget_operators(self):
        source, first, second, third = map(key, ("source", "first", "second", "third"))
        calls = []

        def compute(name, input_key, output_key):
            def run(values):
                calls.append(name)
                return {output_key: {"n": values[input_key]["n"] + 1}}
            return run

        plan = compile_operators((
            OperatorSpec("first", (source,), (first,), compute("first", source, first)),
            OperatorSpec("second", (first,), (second,), compute("second", first, second)),
            OperatorSpec("third", (second,), (third,), compute("third", second, third)),
        ))
        job = plan.job(snapshot(atom(source, {"n": 0})))
        cancelled = threading.Event()

        first_step = job.step(2, cancelled)
        self.assertFalse(first_step.done)
        self.assertIsNone(first_step.value)
        self.assertEqual(calls, ["first", "second"])

        final_step = job.step(2, cancelled)
        self.assertTrue(final_step.done)
        self.assertEqual(calls, ["first", "second", "third"])
        self.assertEqual([write.value for write in final_step.value], [{"n": 1}, {"n": 2}, {"n": 3}])

    def test_step_observes_cancellation_between_operators(self):
        source, first, second = map(key, ("source", "first", "second"))
        cancelled = threading.Event()
        calls = []

        def cancel_after_first(values):
            calls.append("first")
            cancelled.set()
            return {first: values[source]}

        plan = compile_operators((
            OperatorSpec("first", (source,), (first,), cancel_after_first),
            OperatorSpec("second", (first,), (second,), lambda values: calls.append("second") or {second: values[first]}),
        ))

        with self.assertRaises(asyncio.CancelledError):
            plan.job(snapshot(atom(source, {"n": 1}))).step(2, cancelled)
        self.assertEqual(calls, ["first"])

    def test_interleaved_jobs_keep_staged_values_isolated(self):
        source, middle, result = map(key, ("source", "middle", "result"))
        plan = compile_operators((
            OperatorSpec("middle", (source,), (middle,), lambda values: {middle: {"n": values[source]["n"] * 10}}),
            OperatorSpec("result", (middle,), (result,), lambda values: {result: {"n": values[middle]["n"] + 1}}),
        ))
        first_job = plan.job(snapshot(atom(source, {"n": 2})))
        second_job = plan.job(snapshot(atom(source, {"n": 7})))
        cancelled = threading.Event()

        self.assertFalse(first_job.step(1, cancelled).done)
        self.assertFalse(second_job.step(1, cancelled).done)
        first_result = first_job.step(1, cancelled).value
        second_result = second_job.step(1, cancelled).value

        self.assertEqual(first_result[-1].value, {"n": 21})
        self.assertEqual(second_result[-1].value, {"n": 71})

    def test_job_detaches_snapshot_before_it_can_wait_in_a_queue(self):
        source, result = map(key, ("source", "result"))
        plan = compile_operators((
            OperatorSpec("result", (source,), (result,), lambda values: {result: values[source]}),
        ))
        source_atom = atom(source, {"items": ["queued"]})
        job = plan.job(snapshot(source_atom))
        source_atom.value["items"].append("changed-after-enqueue")

        completed = job.step(1, threading.Event())

        self.assertTrue(completed.done)
        self.assertEqual(completed.value[0].value, {"items": ["queued"]})

    def test_invalid_later_output_does_not_leave_a_partial_step(self):
        source, first, second = map(key, ("source", "first", "second"))
        calls = 0

        def compute(values):
            nonlocal calls
            calls += 1
            if calls == 1:
                return {first: values[source], second: {"invalid": object()}}
            return {first: values[source], second: {"n": 2}}

        job = compile_operators((
            OperatorSpec("multiple", (source,), (first, second), compute),
        )).job(snapshot(atom(source, {"n": 1})))

        with self.assertRaises(TypeError):
            job.step(1, threading.Event())
        completed = job.step(1, threading.Event())

        self.assertTrue(completed.done)
        self.assertEqual([write.key for write in completed.value], [first, second])
        self.assertEqual([write.value for write in completed.value], [{"n": 1}, {"n": 2}])


class OperatorSchedulerIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def test_scheduler_drives_operator_job_across_quanta(self):
        source, first, second, third = map(key, ("source", "first", "second", "third"))
        calls = []

        def increment(name, input_key, output_key):
            def compute(values):
                calls.append(name)
                return {output_key: {"n": values[input_key]["n"] + 1}}
            return compute

        plan = compile_operators((
            OperatorSpec("first", (source,), (first,), increment("first", source, first)),
            OperatorSpec("second", (first,), (second,), increment("second", first, second)),
            OperatorSpec("third", (second,), (third,), increment("third", second, third)),
        ))
        scheduler = BoundedScheduler(workers=1, capacity=1, quantum=1)
        try:
            writes = await scheduler.run(
                Scope("bot", "persona", "session"),
                plan.job(snapshot(atom(source, {"n": 0}))),
            )
        finally:
            await scheduler.close()

        self.assertEqual(calls, ["first", "second", "third"])
        self.assertEqual(writes[-1].value, {"n": 3})

    async def test_scheduler_cancels_running_operator_job_as_asyncio_cancellation(self):
        source, first, second = map(key, ("source", "first", "second"))
        entered = threading.Event()
        release = threading.Event()
        calls = []

        def blocking_first(values):
            calls.append("first")
            entered.set()
            release.wait(2)
            return {first: values[source]}

        plan = compile_operators((
            OperatorSpec("first", (source,), (first,), blocking_first),
            OperatorSpec("second", (first,), (second,), lambda values: calls.append("second") or {second: values[first]}),
        ))
        scheduler = BoundedScheduler(workers=1, capacity=1, quantum=2)
        task = asyncio.create_task(scheduler.run(
            Scope("bot", "persona", "session"),
            plan.job(snapshot(atom(source, {"n": 1}))),
        ))
        try:
            self.assertTrue(await asyncio.to_thread(entered.wait, 2))
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
        finally:
            release.set()
            await scheduler.close()

        self.assertEqual(calls, ["first"])


if __name__ == "__main__":
    unittest.main()
