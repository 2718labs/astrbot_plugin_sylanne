import unittest

from sylanne3.domains.d06 import D06DomainAdapter, ErasureRequest
from sylanne3.graph_types import AtomKey, Owner
from sylanne3.memory_types import source_key
from sylanne3.runtime_contracts import NamespaceId


class DeletionClosureTests(unittest.TestCase):
    def setUp(self):
        self.namespace = NamespaceId("bot", "persona")
        self.domain = D06DomainAdapter(self.namespace)
        self.root = source_key("bot", "persona", "source-1")

    def _key(self, type_name, name):
        return AtomKey(Owner("event", "bot", "persona", "source-1"), type_name, name)

    def test_closure_candidate_preserves_relation_kinds_and_before_epochs(self):
        current = self._key("memory.interpretation", "current")
        historical = self._key("d06.recollection.v1", "history")
        association = self._key("memory.association", "edge")
        cache = self._key("memory.cache", "projection")
        request = ErasureRequest(
            "erase-1", (self.root.token,), "all_derived", 7, 11,
        )

        closure = self.domain.prepare_deletion_closure(
            request,
            current_dependency_refs=(current.token,),
            historical_source_refs=(historical.token,),
            association_refs=(association.token,),
            graph_cache_refs=(cache.token,),
        )

        self.assertEqual(closure.namespace, self.namespace)
        self.assertEqual(closure.root_refs, (self.root.token,))
        self.assertEqual(closure.current_dependency_refs, (current.token,))
        self.assertEqual(closure.historical_source_refs, (historical.token,))
        self.assertEqual(closure.association_refs, (association.token,))
        self.assertEqual(closure.graph_cache_refs, (cache.token,))
        self.assertEqual(closure.access_epoch_before, 7)
        self.assertEqual(closure.delete_epoch_before, 11)
        self.assertEqual(closure.status, "proposal_requires_authority_v2")
        self.assertNotIn("barrier_installed", closure.__dict__)
        self.assertNotIn("accepted", closure.__dict__)
        self.assertNotIn("issuer", closure.__dict__)

    def test_cross_namespace_or_noncanonical_closure_ref_is_rejected(self):
        request = ErasureRequest(
            "erase-1", (self.root.token,), "all_derived", 7, 11,
        )
        foreign = source_key("bot", "other-persona", "source-1")
        with self.assertRaisesRegex(ValueError, "cross namespace"):
            self.domain.prepare_deletion_closure(
                request, historical_source_refs=(foreign.token,),
            )
        with self.assertRaisesRegex(ValueError, "canonical graph atom"):
            self.domain.prepare_deletion_closure(
                request, association_refs=("caller-digest-is-not-evidence",),
            )

    def test_erasure_plan_remains_pending_without_authority_evidence(self):
        request = ErasureRequest(
            "erase-1", (self.root.token,), "all_derived", 7, 11,
        )
        plan = self.domain.plan_erasure(request)
        self.assertEqual(plan.status, "pending_runtime_authority")
        self.assertNotIn(plan.status, {"accepted", "closed", "barrier_installed"})


if __name__ == "__main__":
    unittest.main()
