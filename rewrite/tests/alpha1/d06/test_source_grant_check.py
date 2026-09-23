from dataclasses import replace
import unittest

from sylanne3.domains.d06 import D06DomainProvider, SourceGrantRead
from sylanne3.domains.d08 import ActionIntent, GoalPredicate, RequiredCheckSpec
from sylanne3.graph_types import GraphAtom, GraphSnapshot, NamespaceEpoch
from sylanne3.memory_types import SourceRecord, access_key, source_key
from sylanne3.runtime_contracts import OperationIdentity, VersionedRef, canonical_digest


def _source(source_id: str, *, parents=(), audience=("entity:alice",)):
    source = SourceRecord(
        source_id, "a remembered fact", "speaker", "reported", "reported",
        1.0, 2.0, "family", audience, ("context", "expression"), parents,
    )
    key = source_key("bot", "persona", source_id)
    access = access_key("bot", "persona", source_id)
    return (
        GraphAtom(key, 1, source.to_dict()),
        GraphAtom(access, 1, {
            "source_id": source_id, "audiences": list(audience),
            "purposes": ["context", "expression"], "status": "active", "recorded_at": 2.0,
        }),
    )


def _case(*, atoms=None, extra_versions=()):
    if atoms is None:
        atoms = _source("child", parents=("parent",)) + _source("parent")
    root = source_key("bot", "persona", "child").token
    versions = tuple(VersionedRef(atom.key.token, atom.revision) for atom in atoms) + extra_versions
    spec = RequiredCheckSpec(
        "source_grant", "d06.source_grant", "persona:persona", "action:send",
        "respond", root, versions,
    )
    intent = ActionIntent(
        "action:send", 1, "goal:send", (), "entity:alice", "message", "respond",
        "reversible", "0" * 64,
        OperationIdentity("activity:send", "effect:send", "attempt:1", "prepare",
                          "operation:send", canonical_digest({"input_refs": [root]})),
        "schema:send", (spec,), GoalPredicate("communicated", "d11.delivery", (), 0.0, None),
        ("message:alice",), None, (root,),
    )
    read = SourceGrantRead(
        GraphSnapshot(tuple(atoms), (NamespaceEpoch("bot", "persona", 7),)),
        ("entity:alice",), "expression", True, True,
    )
    return intent, read


class SourceGrantCheckTests(unittest.TestCase):
    def check(self, intent, read):
        return D06DomainProvider.provide_required_check(intent, read, valid_until=10.0)

    def test_complete_current_source_and_ancestor_pass_as_candidate(self):
        intent, read = _case()
        receipt = self.check(intent, read)
        self.assertEqual((receipt.result, receipt.coverage), ("pass", "full"))
        self.assertEqual(receipt.input_versions, intent.required_checks[0].required_input_versions)

    def test_withdrawn_parent_or_wrong_audience_fails(self):
        intent, read = _case()
        atoms = list(read.snapshot.atoms)
        parent_access = atoms[3]
        atoms[3] = replace(parent_access, value={**parent_access.value, "status": "withdrawn"})
        withdrawn = replace(read, snapshot=replace(read.snapshot, atoms=tuple(atoms)))
        self.assertEqual(self.check(intent, withdrawn).result, "fail")
        wrong_audience = replace(read, audience=("group:friends",))
        self.assertEqual(self.check(intent, wrong_audience).result, "fail")

    def test_missing_ancestor_or_access_and_stale_version_stay_unknown(self):
        intent, read = _case()
        for atoms in (read.snapshot.atoms[:2], read.snapshot.atoms[:-1]):
            incomplete = replace(read, snapshot=replace(read.snapshot, atoms=atoms))
            self.assertEqual(self.check(intent, incomplete).result, "unknown")
        changed = list(read.snapshot.atoms)
        changed[1] = replace(changed[1], revision=2)
        stale = replace(read, snapshot=replace(read.snapshot, atoms=tuple(changed)))
        self.assertEqual(self.check(intent, stale).result, "unknown")

    def test_snapshot_without_current_barrier_or_full_coverage_never_passes(self):
        intent, read = _case()
        for read_case in (replace(read, current_barrier_confirmed=False),
                          replace(read, complete=False),
                          replace(read, purpose="context")):
            receipt = self.check(intent, read_case)
            self.assertEqual((receipt.result, receipt.coverage), ("unknown", "partial"))

    def test_unverifiable_non_graph_criteria_stays_unknown(self):
        intent, read = _case()
        spec = intent.required_checks[0]
        unknown_spec = replace(spec, criteria_version="policy:1",
                               required_input_versions=spec.required_input_versions +
                               (VersionedRef("policy:1", 1),))
        receipt = self.check(replace(intent, required_checks=(unknown_spec,)), read)
        self.assertEqual((receipt.result, receipt.coverage), ("unknown", "partial"))


if __name__ == "__main__":
    unittest.main()
