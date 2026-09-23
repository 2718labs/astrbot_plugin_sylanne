from uuid import uuid4

from sylanne3.authority_service.v2_owner_contract import OwnerAuthorizationGuardV1, OwnerPrincipalV1
from sylanne3.domains.d01 import PersonaBlock, ValueRule
from sylanne3.runtime_contracts import NamespaceId
from sylanne3.workbench_api.d01_onboarding import (
    CurrentD01OnboardingResolver, CurrentOwnerIdentity, VerifiedCreationResources,
    VerifiedModelCapability, VerifiedBudgetLease,
)
from sylanne3.workbench_api.service import AuthenticatedSession


NAMESPACE = NamespaceId("bot", "persona")
SCOPE = "bot/persona"
PRINCIPAL = OwnerPrincipalV1("paired-key", "account", "incarnation")
GUARD = OwnerAuthorizationGuardV1("authority", "install", NAMESPACE, 1,
                                  "sha256:" + "a" * 64, 0, 0)
SESSION = AuthenticatedSession(
    "paired-actor", "dashboard-session",
    {SCOPE: frozenset({"workbench.create"})},
    {SCOPE: frozenset({"owner"})},
    {SCOPE: frozenset({"workbench_user_action"})},
    host_username="admin",
)
INPUT = {
    "display_name": "小岚", "blueprint": "blank",
    "model_capability_ref": "model:installed", "budget_ref": "budget:installed",
}
DIGEST = "sha256:" + "a" * 64


class Namespaces:
    def resolve_installed_namespace(self, *, scope):
        return NAMESPACE if scope == SCOPE else None


class Owners:
    def resolve_current_owner_identity(self, *, session, scope, namespace):
        return CurrentOwnerIdentity(session.actor_id, session.session_id,
                                    scope, namespace, PRINCIPAL, GUARD)


class Catalogue:
    def resolve_current_resources(self, *, namespace, blueprint_ref,
                                  model_capability_ref, budget_ref):
        if (namespace, blueprint_ref, model_capability_ref, budget_ref) != (
                NAMESPACE, "blank", "model:installed", "budget:installed"):
            return None
        return VerifiedCreationResources(
            namespace, blueprint_ref, model_capability_ref, budget_ref, 1,
            "sha256:" + "c" * 64,
            (PersonaBlock("value-1", "value", "关心别人", "growth"),),
            (ValueRule("honesty", "诚实", ("conversation",), (), ()),),
            VerifiedModelCapability(namespace, model_capability_ref, "provider/model", 3,
                                    "sha256:" + "a" * 64),
            VerifiedBudgetLease(namespace, budget_ref, "lease:current", 2,
                                "sha256:" + "b" * 64),
        )


def resolve(resolver, *, operation_id=None, input_data=None, session=SESSION):
    return resolver.resolve_create_character(
        session=session, scope=SCOPE, purpose="workbench_user_action",
        audience="owner", operation_id=operation_id or str(uuid4()),
        request_digest=DIGEST, input_data=INPUT if input_data is None else input_data,
    )


def test_trusted_local_selection_builds_authored_plan_with_stable_retry_id():
    resolver = CurrentD01OnboardingResolver(
        namespaces=Namespaces(), owners=Owners(), catalogue=Catalogue())
    operation_id = str(uuid4())
    first = resolve(resolver, operation_id=operation_id)
    again = resolve(resolver, operation_id=operation_id)
    assert first == again
    assert first.plan.authored is True
    assert first.plan.namespace == NAMESPACE
    assert first.plan.blocks[0] == PersonaBlock(
        "identity", "semantic_identity", "小岚", "read_only")
    assert first.plan.blocks[1].claim == "关心别人"
    assert first.plan.values[0].rule_id == "honesty"
    assert first.principal == PRINCIPAL
    assert first.resources.model.resource_ref == "provider/model"
    assert first.resources.budget.lease_ref == "lease:current"
    assert resolve(resolver).plan.plan_id != first.plan.plan_id


def test_missing_trusted_port_or_unavailable_capability_holds_creation():
    assert resolve(CurrentD01OnboardingResolver()) is None
    resolver = CurrentD01OnboardingResolver(
        namespaces=Namespaces(), owners=Owners(), catalogue=Catalogue())
    for field, value in (("model_capability_ref", "model:browser-invented"),
                         ("budget_ref", "budget:browser-invented"),
                         ("blueprint", "example")):
        payload = {**INPUT, field: value}
        assert resolve(resolver, input_data=payload) is None


def test_dashboard_name_is_not_owner_and_mismatched_pairing_holds_creation():
    class WrongOwner(Owners):
        def resolve_current_owner_identity(self, *, session, scope, namespace):
            return CurrentOwnerIdentity("admin", session.session_id,
                                        scope, namespace, PRINCIPAL, GUARD)

    resolver = CurrentD01OnboardingResolver(
        namespaces=Namespaces(), owners=WrongOwner(), catalogue=Catalogue())
    assert resolve(resolver) is None


def test_mismatched_installed_namespace_holds_creation():
    class WrongNamespace(Namespaces):
        def resolve_installed_namespace(self, *, scope):
            return NamespaceId("other-bot", "persona")

    resolver = CurrentD01OnboardingResolver(
        namespaces=WrongNamespace(), owners=Owners(), catalogue=Catalogue())
    assert resolve(resolver) is None


def test_revoke_in_progress_holds_creation():
    class RevokingOwner(Owners):
        def resolve_current_owner_identity(self, *, session, scope, namespace):
            guard = OwnerAuthorizationGuardV1(
                "authority", "install", NAMESPACE, 1, "sha256:" + "a" * 64,
                0, 0, pending_revoke_operation_id="revoke-1")
            return CurrentOwnerIdentity(session.actor_id, session.session_id,
                                        scope, namespace, PRINCIPAL, guard)

    resolver = CurrentD01OnboardingResolver(
        namespaces=Namespaces(), owners=RevokingOwner(), catalogue=Catalogue())
    assert resolve(resolver) is None


def test_committed_replay_uses_owner_pairing_without_current_resource_catalogue():
    class UnavailableCatalogue:
        def resolve_current_resources(self, **_kwargs):
            raise AssertionError("committed replay must not select new resources")

    class ReplayGraph:
        def replay_committed_role_initialization_v2(self, **kwargs):
            assert kwargs == {
                "namespace": NAMESPACE, "operation_id": operation_id,
                "request_digest": DIGEST, "principal": PRINCIPAL,
            }
            return "original-receipt"

    operation_id = str(uuid4())
    resolver = CurrentD01OnboardingResolver(
        namespaces=Namespaces(), owners=Owners(), catalogue=UnavailableCatalogue())
    assert resolver.replay_committed_create_character(
        coordinator=ReplayGraph(), session=SESSION, scope=SCOPE,
        purpose="workbench_user_action", audience="owner",
        operation_id=operation_id, request_digest=DIGEST,
    ) == "original-receipt"


def test_missing_current_model_can_reject_original_pending_intent_with_owner():
    class UnavailableCatalogue:
        def resolve_current_resources(self, **_kwargs):
            return None

    class PendingGraph:
        def reject_unresolvable_role_initialization_v2(self, **kwargs):
            assert kwargs == {
                "namespace": NAMESPACE, "operation_id": operation_id,
                "request_digest": DIGEST, "principal": PRINCIPAL,
            }
            return True

    operation_id = str(uuid4())
    resolver = CurrentD01OnboardingResolver(
        namespaces=Namespaces(), owners=Owners(), catalogue=UnavailableCatalogue())
    assert resolve(resolver, operation_id=operation_id) is None
    assert resolver.reject_unresolvable_create_character(
        coordinator=PendingGraph(), session=SESSION, scope=SCOPE,
        purpose="workbench_user_action", audience="owner",
        operation_id=operation_id, request_digest=DIGEST,
    )
