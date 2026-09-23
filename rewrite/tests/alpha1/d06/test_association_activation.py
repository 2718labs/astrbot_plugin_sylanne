import unittest

from sylanne3.memory_association import (
    ActivationPolicy,
    AssociationActivator,
    AssociationEdge,
)


class AssociationActivationTests(unittest.TestCase):
    def test_cycle_is_bounded_and_does_not_reinforce_edge_weights(self):
        edges = (
            AssociationEdge("a", "b", 1.0, 1.0, "basis-ab"),
            AssociationEdge("b", "a", 1.0, 1.0, "basis-ba"),
        )
        policy = ActivationPolicy(
            leak=0.45,
            spread=0.35,
            max_iterations=12,
            max_nodes=8,
            min_activation=0.01,
        )

        result = AssociationActivator(policy).propagate({"a": 1.0}, edges)

        self.assertLessEqual(result.iterations, 12)
        self.assertEqual(result.stop_reason, "converged")
        self.assertEqual(tuple(edge.weight for edge in edges), (1.0, 1.0))
        self.assertTrue(all(0.0 <= value <= 1.0 for _, value in result.activations))
        self.assertGreater(dict(result.activations)["b"], 0.0)

    def test_context_fit_changes_path_without_changing_source_fact(self):
        edges = (
            AssociationEdge("cue", "personal", 0.7, 1.0, "private-history"),
            AssociationEdge("cue", "generic", 0.9, 0.1, "semantic-match"),
        )
        result = AssociationActivator(
            ActivationPolicy(0.5, 0.4, 6, 8, 1e-6)
        ).propagate({"cue": 1.0}, edges)

        values = dict(result.activations)
        self.assertGreater(values["personal"], values["generic"])
        self.assertEqual(result.basis_refs, ("private-history", "semantic-match"))

    def test_invalid_stability_and_capacity_inputs_fail_closed(self):
        with self.assertRaisesRegex(ValueError, "spread must be less than leak"):
            ActivationPolicy(0.2, 0.2, 4, 8, 0.01)
        activator = AssociationActivator(ActivationPolicy(0.5, 0.3, 4, 1, 0.01))
        with self.assertRaisesRegex(ValueError, "max_nodes"):
            activator.propagate(
                {"a": 1.0},
                (AssociationEdge("a", "b", 1.0, 1.0, "basis"),),
            )


if __name__ == "__main__":
    unittest.main()
