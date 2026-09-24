"""The installed Owner budget adapter forwards signed facts to the graph read."""

from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace
import unittest

from sylanne3.authority_service.v2_owner_contract import OwnerPrincipalV1
from sylanne3.authority_service.v2_owner_session import OwnerSessionLoginRequestV1
from sylanne3.graph_coordinator import CreationBudgetProofV1, namespace_ref
from sylanne3.runtime_contracts import NamespaceId
from sylanne3.workbench_api.d01_onboarding import VerifiedBudgetLease
from sylanne3.workbench_api.installed_owner_ports import InstalledOwnerOnboardingPorts
from sylanne3.workbench_api.service import AuthenticatedSession


class InstalledOwnerBudgetPortTests(unittest.TestCase):
    def test_returns_only_current_graph_budget_proof(self):
        namespace = NamespaceId("bot", "persona")
        principal = OwnerPrincipalV1("idp", "account", "incarnation")
        request = OwnerSessionLoginRequestV1(
            "authority", namespace_ref(namespace), "installation", principal,
            "credential", 1, "owner", "https://owner.example",
        )
        session = AuthenticatedSession(
            "owner-actor", "session", {},
            {"bot/persona": frozenset({"owner"})}, {},
            owner_session_token="signed-token", owner_session_request=request,
        )
        budget = VerifiedBudgetLease(
            namespace, "lease", "lease", 2, "sha256:" + "a" * 64,
        )
        proof = CreationBudgetProofV1(
            budget, "grant", 1, "sha256:" + "b" * 64, 1, 1, "head",
        )

        class Graph:
            calls = []
            result = proof

            def read_current_creation_budget_v2(self, **kwargs):
                self.calls.append(kwargs)
                return self.result

        graph = Graph()
        port = object.__new__(InstalledOwnerOnboardingPorts)
        port._policy = SimpleNamespace(
            namespace=namespace, expected_authority_id="authority",
            installation_id="installation", authority_namespace=namespace_ref(namespace),
        )
        port._coordinator = graph
        self.assertEqual(port.resolve_current_budget_lease(
            namespace=namespace, budget_ref="lease", session=session,
            principal=principal), budget)
        self.assertEqual(graph.calls, [{
            "namespace": namespace, "budget_ref": "lease",
            "actor_id": "owner-actor", "principal": principal,
            "owner_session_token": "signed-token",
            "owner_session_request": request,
        }])
        self.assertIsNone(port.resolve_current_budget_lease(
            namespace=NamespaceId("other", "persona"), budget_ref="lease",
            session=session, principal=principal))
        self.assertIsNone(port.resolve_current_budget_lease(
            namespace=namespace, budget_ref="lease",
            session=replace(session, owner_session_token=None), principal=principal))
        self.assertEqual(len(graph.calls), 1)
        graph.result = replace(proof, budget=replace(budget, budget_ref="other"))
        self.assertIsNone(port.resolve_current_budget_lease(
            namespace=namespace, budget_ref="lease", session=session,
            principal=principal))


if __name__ == "__main__":
    unittest.main()
