import math
import unittest
from dataclasses import FrozenInstanceError

from sylanne3.graph_types import Owner, TypeRegistry
from sylanne3.memory_types import (
    InterpretationRecord,
    SourceRecord,
    access_key,
    interpretation_key,
    register_memory_types,
    source_key,
    validate_access,
)


def source_value(**changes):
    value = {
        "source_id": "source-1",
        "text": "The bridge sensor reported movement.",
        "speaker_id": "speaker-1",
        "source_kind": "reported",
        "assertion_status": "reported",
        "occurred_at": None,
        "recorded_at": 12.5,
        "provenance_root": "message-1",
        "audiences": ("private",),
        "purposes": ("context", "audit"),
        "parent_source_ids": (),
        "independence": "unknown",
    }
    value.update(changes)
    return value


def interpretation_value(**changes):
    value = {
        "interpretation_id": "interpretation-1",
        "source_ids": ("source-1",),
        "subject_id": "bridge-1",
        "claim": "Movement may require review.",
        "status": "reported",
        "valid_from": 10,
        "recorded_at": 13,
        "valid_to": None,
    }
    value.update(changes)
    return value


class MemoryRecordTests(unittest.TestCase):
    def test_source_roundtrip_uses_json_arrays_and_is_frozen(self):
        record = SourceRecord(**source_value())
        payload = record.to_dict()
        self.assertEqual(payload["audiences"], ["private"])
        self.assertEqual(payload["purposes"], ["context", "audit"])
        self.assertEqual(payload["parent_source_ids"], [])
        self.assertEqual(SourceRecord.from_dict(payload), record)
        payload["audiences"].append("public")
        self.assertEqual(record.audiences, ("private",))
        with self.assertRaises(FrozenInstanceError):
            record.text = "changed"

    def test_interpretation_roundtrip_and_closed_open_interval_shape(self):
        record = InterpretationRecord(**interpretation_value(valid_to=20.0))
        payload = record.to_dict()
        self.assertEqual(payload["source_ids"], ["source-1"])
        self.assertEqual(InterpretationRecord.from_dict(payload), record)
        with self.assertRaises(ValueError):
            InterpretationRecord(**interpretation_value(valid_to=9.99))
        InterpretationRecord(**interpretation_value(valid_to=10))

    def test_from_dict_requires_exact_fields_and_json_array_tuples(self):
        payload = SourceRecord(**source_value()).to_dict()
        for changed in (
            {key: value for key, value in payload.items() if key != "speaker_id"},
            {**payload, "unexpected": True},
            {**payload, "audiences": ("private",)},
        ):
            with self.subTest(keys=tuple(changed)):
                with self.assertRaises((TypeError, ValueError)):
                    SourceRecord.from_dict(changed)

        interpretation = InterpretationRecord(**interpretation_value()).to_dict()
        with self.assertRaises(ValueError):
            InterpretationRecord.from_dict({**interpretation, "unexpected": 1})
        with self.assertRaises(ValueError):
            InterpretationRecord.from_dict(
                {key: value for key, value in interpretation.items() if key != "valid_to"}
            )

    def test_records_reject_invalid_enums_ids_text_and_tuple_values(self):
        bad_sources = (
            {"source_id": ""},
            {"text": ""},
            {"text": "x" * 65537},
            {"source_kind": "observed", "assertion_status": "retracted"},
            {"source_kind": "hearsay"},
            {"independence": "assumed"},
            {"audiences": ["private"]},
            {"audiences": ("private", "private")},
            {"audiences": ("*",)},
            {"purposes": ("context", "future-use")},
            {"parent_source_ids": ("",)},
        )
        for change in bad_sources:
            with self.subTest(change=change):
                with self.assertRaises((TypeError, ValueError)):
                    SourceRecord(**source_value(**change))

        bad_interpretations = (
            {"source_ids": ()},
            {"source_ids": ("source-1", "source-1")},
            {"source_ids": ["source-1"]},
            {"claim": ""},
            {"claim": "x" * 65537},
            {"status": "active"},
        )
        for change in bad_interpretations:
            with self.subTest(change=change):
                with self.assertRaises((TypeError, ValueError)):
                    InterpretationRecord(**interpretation_value(**change))

    def test_times_are_finite_nonnegative_real_numbers_and_never_bool(self):
        bad_times = (-1, True, False, math.inf, -math.inf, math.nan, "1")
        for value in bad_times:
            with self.subTest(source_recorded_at=value):
                with self.assertRaises((TypeError, ValueError)):
                    SourceRecord(**source_value(recorded_at=value))
            with self.subTest(interpretation_valid_from=value):
                with self.assertRaises((TypeError, ValueError)):
                    InterpretationRecord(**interpretation_value(valid_from=value))
        for value in bad_times:
            if value is None:
                continue
            with self.subTest(source_occurred_at=value):
                with self.assertRaises((TypeError, ValueError)):
                    SourceRecord(**source_value(occurred_at=value))
        SourceRecord(**source_value(occurred_at=None, recorded_at=0))


class MemoryGraphTypeTests(unittest.TestCase):
    def test_keys_use_event_owner_and_exact_type_and_name(self):
        owner = Owner("event", "bot", "persona", "source-1")
        self.assertEqual(source_key("bot", "persona", "source-1").owner, owner)
        self.assertEqual(
            (source_key("bot", "persona", "source-1").type_name,
             source_key("bot", "persona", "source-1").name),
            ("memory.source", "record"),
        )
        self.assertEqual(
            (access_key("bot", "persona", "source-1").owner,
             access_key("bot", "persona", "source-1").type_name,
             access_key("bot", "persona", "source-1").name),
            (owner, "memory.access", "access"),
        )
        interpretation = interpretation_key("bot", "persona", "interpretation-1")
        self.assertEqual(
            (interpretation.owner, interpretation.type_name, interpretation.name),
            (Owner("event", "bot", "persona", "interpretation-1"),
             "memory.interpretation", "current"),
        )

    def test_access_validation_is_strict_and_does_not_canonicalize(self):
        value = {
            "source_id": "source-1",
            "audiences": ["private"],
            "purposes": ["expression", "audit"],
            "status": "active",
            "recorded_at": 2.0,
        }
        before = {key: list(item) if isinstance(item, list) else item for key, item in value.items()}
        self.assertIsNone(validate_access(value))
        self.assertEqual(value, before)
        bad_values = (
            {**value, "extra": 1},
            {key: item for key, item in value.items() if key != "status"},
            {**value, "audiences": ("private",)},
            {**value, "audiences": ["private", "private"]},
            {**value, "audiences": ["*"]},
            {**value, "purposes": ["unknown"]},
            {**value, "status": "deleted"},
            {**value, "recorded_at": True},
        )
        for bad in bad_values:
            with self.subTest(bad=bad):
                with self.assertRaises((TypeError, ValueError)):
                    validate_access(bad)

    def test_registry_adds_exact_memory_types_and_validators(self):
        registry = TypeRegistry()
        register_memory_types(registry)
        specs = {spec.name: spec for spec in registry.specs}
        self.assertEqual(set(specs), {
            "memory.source", "memory.access", "memory.interpretation",
            "memory.episode.v1", "memory.subjective_trace.v1",
        })
        self.assertEqual(
            (specs["memory.source"].owner_kinds,
             specs["memory.source"].storage_role,
             specs["memory.source"].immutable),
            (("event",), "source", True),
        )
        for name in ("memory.access", "memory.interpretation"):
            self.assertEqual(specs[name].owner_kinds, ("event",))
            self.assertEqual(specs[name].storage_role, "state")
            self.assertFalse(specs[name].immutable)
        for name in ("memory.episode.v1", "memory.subjective_trace.v1"):
            self.assertEqual(specs[name].owner_kinds, ("event",))
            self.assertEqual(specs[name].storage_role, "source")
            self.assertTrue(specs[name].immutable)

        source = SourceRecord(**source_value()).to_dict()
        interpretation = InterpretationRecord(**interpretation_value()).to_dict()
        access = {
            "source_id": "source-1",
            "audiences": ["private"],
            "purposes": ["context"],
            "status": "withdrawn",
            "recorded_at": 15,
        }
        registry.validate(source_key("bot", "persona", "source-1"), source)
        registry.validate(access_key("bot", "persona", "source-1"), access)
        registry.validate(
            interpretation_key("bot", "persona", "interpretation-1"), interpretation
        )


if __name__ == "__main__":
    unittest.main()
