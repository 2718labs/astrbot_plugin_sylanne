from __future__ import annotations

from uuid import uuid4
import pytest

from sylanne3.domains.d12 import CharacterDraft, D12DomainProvider, D12TypeSpec, graph_type_specs
from sylanne3.graph_types import TypeRegistry
from sylanne3.workbench_api import AuthenticatedSession, RequestContext, WorkbenchService


SCOPE = "bot/persona"
CONTEXT = RequestContext(origin_verified=True, csrf_verified=True, session_bound=True)


def session(*capabilities: str) -> AuthenticatedSession:
    return AuthenticatedSession("actor", "session", {SCOPE: frozenset(capabilities)},
                                {SCOPE: frozenset({"owner"})},
                                {SCOPE: frozenset({"workbench_view", "workbench_user_action"})})


def request(action="read_character_view", **input_data):
    body = {"view_type": "overview"} if action == "read_character_view" else {}
    body.update(input_data)
    return {"schema_version": "d12.contract.v1", "action": action, "scope": SCOPE,
            "purpose": "workbench_view" if action == "read_character_view" else "workbench_user_action",
            "audience": "owner", "operation_id": str(uuid4()),
            "input": body}


def test_rejects_client_actor_claim_and_unverified_request_context():
    payload = request(); payload["actor"] = "escalate"
    rejected = WorkbenchService().handle(payload, session=session("workbench.read"), context=CONTEXT)
    assert rejected.problem["code"] == "invalid_request"
    csrf = WorkbenchService().handle(request(), session=session("workbench.read"),
                                     context=RequestContext(True, False, True))
    assert csrf.status == "unauthorized"
    assert csrf.problem["code"] == "request_context_unverified"


def test_rejects_unknown_action_input_and_unbounded_page_size():
    malformed = request(); malformed["input"]["graph_write"] = {"unsafe": True}
    answer = WorkbenchService().handle(malformed, session=session("workbench.read"), context=CONTEXT)
    assert answer.problem["code"] == "invalid_request"
    oversized = request(page_size=101)
    answer = WorkbenchService().handle(oversized, session=session("workbench.read"), context=CONTEXT)
    assert answer.problem["code"] == "invalid_request"


def test_scope_capability_purpose_and_audience_are_all_server_enforced():
    denied = WorkbenchService().handle(request("compile_scheme"), session=session("workbench.read"), context=CONTEXT)
    assert denied.status == "unauthorized"
    assert denied.problem["code"] == "capability_denied"


def test_missing_provider_returns_unavailable_without_a_write_receipt():
    answer = WorkbenchService().handle(request("erase_or_retire"), session=session("workbench.erase"), context=CONTEXT)
    assert answer.status == "unavailable"
    assert answer.receipt is None
    assert answer.problem["code"] == "provider_unavailable"


class Reader:
    def read_projection(self, **_):
        return {"status": "partial", "projection": {"private": "must not leak"},
                "receipt": {"private": "must not leak"}, "problem": {"code": "rebuild"}}

    def execute(self, **_):
        raise AssertionError("not used")


def test_partial_provider_projection_fails_closed_without_content():
    answer = WorkbenchService(Reader()).handle(request(), session=session("workbench.read"), context=CONTEXT)
    assert answer.status == "partial"
    assert answer.projection is None
    assert answer.receipt is None


class Compiler:
    def read_projection(self, **_):
        raise AssertionError("not used")

    def execute(self, **_):
        return {"status": "ready", "activated": True, "receipt": {"operation_id": "wrong"}}


def test_compile_cannot_claim_activation_through_candidate_endpoint():
    answer = WorkbenchService(Compiler()).handle(request("compile_scheme"),
                                                session=session("workbench.compile"), context=CONTEXT)
    assert answer.status == "unavailable"
    assert answer.problem["code"] == "invalid_provider_response"


class WrongReceipt:
    def read_projection(self, **_):
        raise AssertionError("not used")

    def execute(self, **_):
        return {"status": "ready", "receipt": {"operation_id": "other-operation"}}


def test_command_rejects_provider_receipt_for_another_operation():
    answer = WorkbenchService(WrongReceipt()).handle(
        request("compile_scheme"), session=session("workbench.compile"), context=CONTEXT,
    )
    assert answer.status == "unavailable" and answer.receipt is None
    assert answer.problem["code"] == "invalid_provider_response"


def test_d12_draft_types_preserve_candidate_boundary_and_schema_digest():
    draft = CharacterDraft(SCOPE, 0, {"identity": "candidate"}, {"identity": "authored"})
    assert draft.revision == 0
    assert len(D12TypeSpec().digest) == 64


def test_d12_administrative_candidates_have_strict_shared_graph_specs():
    specs = graph_type_specs()
    assert len(specs) == 3
    assert all(spec.writer_domain == "d12" and spec.schema_hash for spec in specs)
    registry = TypeRegistry()
    for spec in specs:
        registry.register(spec)
    draft = {"schema": "d12.character_draft.v1", "scope": SCOPE, "revision": 0,
             "fields": {"identity": "candidate"}, "field_sources": {"identity": "authored"}}
    specs[0].validator(draft)
    with pytest.raises(ValueError, match="exactly"):
        specs[0].validator({**draft, "activated": True})
    with pytest.raises(ValueError, match="field_sources"):
        specs[0].validator({**draft, "field_sources": {}})
    assert len(registry.catalogue_hash) == 64


def test_d12_provider_registers_only_admin_candidate_types():
    provider = D12DomainProvider()
    assert provider.register_types() == tuple(spec.name for spec in graph_type_specs())
    assert provider.descriptor.provider_id == "d12.workbench"
    assert len(provider.descriptor.request_schema_hash) == 64
