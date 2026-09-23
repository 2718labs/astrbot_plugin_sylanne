import unittest

from sylanne3.graph_types import TypeRegistry
from sylanne3.memory_types import register_memory_types


class MemoryRegistryTests(unittest.TestCase):
    def test_every_memory_type_has_d06_writer_and_content_addressed_schema(self):
        registry = TypeRegistry()
        register_memory_types(registry)

        for type_name in ("memory.source", "memory.access", "memory.interpretation"):
            with self.subTest(type_name=type_name):
                spec = registry.spec(type_name)
                self.assertEqual(spec.writer_domain, "d06")
                self.assertIsNotNone(spec.schema_hash)
                self.assertEqual(len(spec.schema_hash), 64)


if __name__ == "__main__":
    unittest.main()
