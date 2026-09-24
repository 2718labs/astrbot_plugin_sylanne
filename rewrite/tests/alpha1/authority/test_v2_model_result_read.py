"""Result release requires a fresh Owner read, not the original send receipt."""

from dataclasses import replace
from types import SimpleNamespace

import pytest

from sylanne3.authority_service.v2_owner_contract import OwnerPrincipalV1
from sylanne3.authority_service.v2_owner_session import OwnerSessionLoginRequestV1
from sylanne3.authority_service.v2_model_egress_contract import (
    ModelEgressObservationV1, ModelTerminalReceiptV2,
)
from sylanne3.authority_service.contract import AuthorityUnavailable
from sylanne3.runtime_contracts import NamespaceId


def _request():
    from sylanne3.authority_service.v2_model_result_read_contract import ModelResultReadRequestV1

    principal = OwnerPrincipalV1("test-idp", "account-1", "incarnation-1")
    session = OwnerSessionLoginRequestV1(
        "authority-1", "namespace-1", "installation-1", principal,
        "credential-1", 1, "owner", "https://dashboard.example")
    return ModelResultReadRequestV1(
        authority_id="authority-1", authority_namespace="namespace-1",
        namespace=NamespaceId("bot-1", "persona-1"),
        installation_id="installation-1", owner_actor_id="actor-1",
        owner_session_request=session, purpose="workbench_view",
        source_purpose="audit", audience=("owner",),
        call_id="call-1", read_operation_id="read-1")


def test_result_read_request_binds_current_owner_and_fixed_purpose():
    request = _request()
    assert request.owner_session_request.installation_id == request.installation_id
    with pytest.raises(ValueError):
        replace(request, purpose="*")
    with pytest.raises(ValueError):
        replace(request, source_purpose="*")
    with pytest.raises(ValueError):
        replace(request, audience=("owner", "owner"))
    with pytest.raises(ValueError):
        replace(request, installation_id="other-installation")


def test_result_read_service_exists_as_separate_owner_gate():
    from sylanne3.authority_service.v2_model_result_read_service import AuthorityV2ModelResultReadService

    assert AuthorityV2ModelResultReadService.__name__ == "AuthorityV2ModelResultReadService"


def test_result_contains_exact_terminal_receipt_binding():
    from sylanne3.authority_service.v2_model_result_read_contract import ModelResultReadV1

    observation = ModelEgressObservationV1(
        "authority-1", "namespace-1", "worker-1", "operation-1",
        "call-1", "a" * 64, "completed", "{}", (), (), None)
    receipt = ModelTerminalReceiptV2(
        "b" * 64, "call-1", "a" * 64, "c" * 64,
        observation.digest, "sha256:" + "d" * 64, "installation-1", "e" * 64)
    result = ModelResultReadV1("call-1", observation, receipt)
    assert result.terminal_receipt.admission_id == "b" * 64
    with pytest.raises(ValueError):
        replace(result, terminal_receipt=replace(receipt, observation_digest="f" * 64))


@pytest.mark.parametrize("change", ["session", "guard"])
def test_read_refuses_owner_change_after_graph_snapshot(change):
    from sylanne3.authority_service.v2_model_result_read_service import AuthorityV2ModelResultReadService

    request = _request()
    calls = []
    state = {"current": True}

    class Fences:
        namespace = "namespace-1"

        def current_anchor(self, **kwargs):
            return SimpleNamespace(authority_id="authority-1")

        def begin_fence(self, **kwargs):
            calls.append("begin")
            return SimpleNamespace(token="permit-token")

        def validate_fence(self, **kwargs):
            calls.append("validate")

        def finish_fence(self, **kwargs):
            calls.append("finish")

    class Graph:
        def current(self, *_args):
            calls.append("graph")
            state["current"] = False
            return True

    service = object.__new__(AuthorityV2ModelResultReadService)
    service._fences = Fences()
    service._graph = Graph()
    service._installation_id = "installation-1"
    service._source_purpose = "audit"
    service._read_subject = "reader-1"
    service._holder = "holder-1"

    def guard(*_args):
        calls.append("guard")
        if not state["current"] and change == "session":
            raise AuthorityUnavailable("Owner session is not current")
        return "old-head" if state["current"] else "revoked-head"

    def terminal(*_args, content, **_kwargs):
        calls.append("body" if content else "terminal")
        return object(), object(), None

    service._current_guard = guard
    service._terminal_in_frozen = terminal
    with pytest.raises(AuthorityUnavailable):
        service.read_completed(
            credential=object(), owner_session_token="original-session",
            request=request)
    assert calls == ["begin", "validate", "guard", "terminal", "graph",
                     "validate", "guard", "finish"]


@pytest.mark.parametrize("state", ["active", "finished"])
def test_uncertain_finish_reuses_original_request_identity(state):
    from sylanne3.authority_service.v2_model_result_read_service import AuthorityV2ModelResultReadService

    request = _request()
    permit = SimpleNamespace(
        token="original-permit-token", operation="read", authority_id="authority-1")
    finishes = []

    class Fences:
        namespace = "namespace-1"

        def finish_fence(self, **kwargs):
            finishes.append((kwargs["request_id"], kwargs["request_digest"]))

        def get_fence_operation(self, **kwargs):
            assert kwargs["operation_id"] == request.read_operation_id
            return permit, state

    service = object.__new__(AuthorityV2ModelResultReadService)
    service._fences = Fences()
    service._read_subject = "reader-1"
    service._installation_id = "installation-1"
    service._source_purpose = "audit"
    service._finish(object(), request, permit)
    service.recover_finish(credential=object(), request=request)
    assert len(finishes) == 2 and finishes[0] == finishes[1]


def test_source_purpose_must_match_service_installation_policy():
    from sylanne3.authority_service.v2_model_result_read_service import AuthorityV2ModelResultReadService

    service = object.__new__(AuthorityV2ModelResultReadService)
    service._fences = SimpleNamespace(namespace="namespace-1")
    service._installation_id = "installation-1"
    service._source_purpose = "consolidation"
    with pytest.raises(AuthorityUnavailable, match="installation-bound"):
        service.read_completed(
            credential=object(), owner_session_token="session-token",
            request=_request())
