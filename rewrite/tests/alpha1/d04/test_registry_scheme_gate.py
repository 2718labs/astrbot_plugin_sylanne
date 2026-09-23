import unittest

from sylanne3.domain_registry import discover_domain_registry
from sylanne3.domains.d04 import AffectAxis, AffectScheme


def _scheme() -> AffectScheme:
    return AffectScheme(
        schema="d04.affect.scheme.v1",
        scheme_version="scheme:affect:1",
        operator_version="operator:affect:1",
        parameter_version="parameter:affect:1",
        coupling_version="coupling:affect:1",
        axes=(AffectAxis("care", "normalized", "care for another"),),
        parameter_bounds=(),
    )


class RegistrySchemeGateTests(unittest.TestCase):
    def test_unbound_d04_remains_discoverable_but_blocks_completeness(self):
        registry = discover_domain_registry()
        self.assertIn("d04", registry.registrations)
        self.assertIn("d04", registry.unavailable)
        self.assertIn("active D04 scheme", registry.unavailable["d04"])
        self.assertFalse(registry.complete)
        self.assertTrue(any(spec.writer_domain == "d04" for spec in registry.type_registry.specs))

    def test_caller_supplied_scheme_restores_complete_registry(self):
        scheme = _scheme()
        registry = discover_domain_registry(active_affect_scheme=scheme)
        self.assertIs(registry.active_affect_scheme, scheme)
        self.assertNotIn("d04", registry.unavailable)
        self.assertEqual(dict(registry.unavailable), {})
        self.assertTrue(registry.complete)
        self.assertIs(registry.registrations["d04"].provider._active_scheme, scheme)


if __name__ == "__main__":
    unittest.main()
