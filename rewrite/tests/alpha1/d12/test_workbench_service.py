from __future__ import annotations

from uuid import uuid4
from dataclasses import replace
import sqlite3
import pytest

from sylanne3.domains.d12 import CharacterDraft, D12DomainProvider, D12TypeSpec, graph_type_specs
from sylanne3.graph_types import TypeRegistry
from sylanne3.workbench_api import AuthenticatedSession, RequestContext, WorkbenchService
from sylanne3.workbench_api.issuer import CoordinatorGrant, GraphWorkbenchIssuer
from sylanne3.domains.d12.scheme_command import (
    D12CompiledSchemeV1, D12DomainCompileReceiptV1, D12IsolatedPreviewV1,
    D12PreviewCertificateV1, compiled_scheme_digest_v1,
)
from sylanne3.domains.d12.types import active_scheme_head_key, character_draft_key
from sylanne3.runtime.scheme_original_store_v1 import (
    CompilationOriginalV1, PreviewOriginalV1, install_scheme_original_store_v1,
    record_compilation_original_for_operation_v1,
    record_preview_original_for_operation_v1,
    read_compilation_original_for_operation_v1,
    read_preview_original_for_operation_v1,
)
from sylanne3.runtime_contracts import AuthorityContext, NamespaceId, canonical_digest
from sylanne3.domains.d12.scoped_erasure import SCOPED_ERASURE_REQUEST_SCHEMA_V2


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


@pytest.mark.parametrize("operation_id", [
    "00000000-0000-0000-0000-000000000001",  # UUID1-style version bits
    "{550e8400-e29b-41d4-a716-446655440000}",  # non-canonical UUID4
])
def test_rejects_noncanonical_or_non_uuid4_operation_id(operation_id):
    payload = request()
    payload["operation_id"] = operation_id
    answer = WorkbenchService().handle(
        payload, session=session("workbench.read"), context=CONTEXT)
    assert answer.status == "unavailable"
    assert answer.problem["code"] == "invalid_request"


def test_real_d06_source_view_reaches_issuer_only_with_read_grant():
    calls = []

    class SourceReader:
        def read_projection(self, **kwargs):
            calls.append(kwargs)
            return {"status": "unavailable", "problem": {"code": "view_unsupported"}}

    payload = request(view_type="d06.memory_sources.v1")
    denied = WorkbenchService(SourceReader()).handle(
        payload, session=session("workbench.correct"), context=CONTEXT)
    assert denied.problem["code"] == "capability_denied" and not calls

    answer = WorkbenchService(SourceReader()).handle(
        payload, session=session("workbench.read"), context=CONTEXT)
    assert answer.problem["code"] == "view_unsupported"
    assert len(calls) == 1
    assert calls[0]["view_type"] == "d06.memory_sources.v1"
    assert calls[0]["scope"] == SCOPE

    unsupported = WorkbenchService(SourceReader()).handle(
        request(view_type="d06.private_memory.v1"),
        session=session("workbench.read"), context=CONTEXT)
    assert unsupported.problem["code"] == "invalid_request"
    assert len(calls) == 1


def test_scope_capability_purpose_and_audience_are_all_server_enforced():
    denied = WorkbenchService().handle(request("compile_scheme", draft_ref="draft:current",
                                                budget_ref="budget:one"),
                                       session=session("workbench.read"), context=CONTEXT)
    assert denied.status == "unauthorized"
    assert denied.problem["code"] == "capability_denied"


def test_erasure_stops_before_any_provider_without_a_write_receipt():
    payload = request("erase_or_retire", schema=SCOPED_ERASURE_REQUEST_SCHEMA_V2,
                      source_id="source:a")
    payload["purpose"] = "audit"
    owner = AuthenticatedSession("actor", "session", {SCOPE: frozenset({"workbench.erase"})},
                                 {SCOPE: frozenset({"owner"})},
                                 {SCOPE: frozenset({"audit"})})
    answer = WorkbenchService().handle(payload, session=owner, context=CONTEXT)
    assert answer.status == "unavailable"
    assert answer.receipt is None
    assert answer.problem["code"] == "erasure_authority_unavailable"

    class FalseSuccess:
        def execute(self, **_):
            raise AssertionError("no deletion callback can claim acceptance")

    blocked = WorkbenchService(FalseSuccess()).handle(
        payload,
        session=owner, context=CONTEXT)
    assert blocked.status == "unavailable" and blocked.receipt is None
    assert blocked.problem["code"] == "erasure_authority_unavailable"

    malformed = WorkbenchService(FalseSuccess()).handle(
        request("erase_or_retire", schema=SCOPED_ERASURE_REQUEST_SCHEMA_V2,
                source_id=" "),
        session=owner, context=CONTEXT)
    assert malformed.problem["code"] == "invalid_request"
    assert malformed.receipt is None


def test_erasure_authority_accepted_response_never_claims_cleanup():
    operation_id = str(uuid4())
    accepted = {
        "status": "accepted",
        "receipt": {
            "schema": "d12.scoped_erasure_accepted.v1",
            "phase": "authority_accepted", "operation_id": operation_id,
            "source_id": "source:a", "deletion_epoch": 2,
            "scope_digest": "sha256:" + "a" * 64,
            "graph_barrier_digest": "sha256:" + "b" * 64,
            "cleanup_complete": False,
        },
    }
    response = WorkbenchService._command_response(
        "erase_or_retire", operation_id, {"source_id": "source:a"}, accepted)
    assert response.status == "accepted"
    assert response.receipt["phase"] == "authority_accepted"
    assert response.receipt["cleanup_complete"] is False

    forged_closed = {**accepted, "receipt": {
        **accepted["receipt"], "cleanup_complete": True,
    }}
    rejected = WorkbenchService._command_response(
        "erase_or_retire", operation_id, {"source_id": "source:a"}, forged_closed)
    assert rejected.status == "unavailable"
    assert rejected.receipt is None


@pytest.mark.parametrize(("action", "input_data", "code"), [
    ("prepare_transfer", {"mode": "relocate", "target": "host:other",
                          "manifest_ref": "untrusted", "scope_selection": [SCOPE]},
     "backend_issuer_unavailable"),
    ("execute_transfer", {"plan_ref": "untrusted", "current_epochs": {"schema": "d12.transfer_expected_epochs.v1",
                              "plan_digest": "sha256:" + "a" * 64, "graph_revision": 1,
                              "access_epoch": 0, "delete_epoch": 0, "activation_generation": 1},
                          "target_lease_ref": "untrusted"},
     "backend_issuer_unavailable"),
])
def test_transfer_stops_before_provider_and_requires_session_capability(
        action, input_data, code):
    class FalseSuccess:
        def execute(self, **_):
            raise AssertionError("a provider callback cannot claim transfer acceptance")

    payload = request(action, **input_data)
    denied = WorkbenchService(FalseSuccess()).handle(
        payload, session=session("workbench.read"), context=CONTEXT)
    assert denied.status == "unauthorized" and denied.receipt is None
    assert denied.problem["code"] == "capability_denied"

    held = WorkbenchService(FalseSuccess()).handle(
        payload, session=session("workbench.transfer"), context=CONTEXT)
    assert held.status == "unavailable" and held.receipt is None
    assert held.problem["code"] == code


@pytest.mark.parametrize(("action", "input_data", "capability", "code"), [
    ("install_or_upgrade", {"release_manifest_ref": "untrusted",
                            "target_capability": "v2", "migration_plan_ref": "untrusted"},
     "workbench.maintain", "backend_issuer_unavailable"),
    ("configure_or_control", {"config_diff": {"enabled": True},
                              "object_ref": "control:one", "control": "pause",
                              "test_intent": {"source": "manual"}},
     "workbench.control", "backend_issuer_unavailable"),
])
def test_maintenance_and_control_stop_before_generic_provider(
        action, input_data, capability, code):
    class FalseSuccess:
        def execute(self, **_):
            raise AssertionError("generic callback cannot claim a trusted admin action")

    payload = request(action, **input_data)
    denied = WorkbenchService(FalseSuccess()).handle(
        payload, session=session("workbench.read"), context=CONTEXT)
    assert denied.status == "unauthorized" and denied.receipt is None
    assert denied.problem["code"] == "capability_denied"

    held = WorkbenchService(FalseSuccess()).handle(
        payload, session=session(capability), context=CONTEXT)
    assert held.status == "unavailable" and held.receipt is None
    assert held.problem["code"] == code


def test_support_export_cannot_accept_a_generic_provider_receipt():
    class FalseSuccess:
        def execute(self, **_):
            raise AssertionError("unwired command must not reach an issuer")

    answer = WorkbenchService(FalseSuccess()).handle(
        request("diagnose_and_export_support"),
        session=session("workbench.diagnose"), context=CONTEXT)
    assert answer.status == "unavailable" and answer.receipt is None
    assert answer.problem["code"] == "invalid_request"

    bounded = request(
        "diagnose_and_export_support", question="view_health",
        allowed_data=["view_status"],
        retention_policy_ref="d12.local_manual_retention.v1",
        local_destination="managed")
    answer = WorkbenchService(FalseSuccess()).handle(
        bounded, session=session("workbench.diagnose"), context=CONTEXT)
    assert answer.status == "unavailable" and answer.receipt is None
    assert answer.problem["code"] == "support_issuer_unavailable"


def test_experiment_rejects_unknown_flavor_and_generic_provider_receipt():
    compiled_digest = "a" * 64
    input_data = {
        "experiment": "d12.scheme_preview.v1",
        "input_refs": [compiled_digest],
        "budget_ref": "budget:one",
        "retention_policy_ref": "d12.preview_original.v1",
    }

    class FalseSuccess:
        def execute(self, **_):
            raise AssertionError("generic issuer cannot submit an experiment receipt")

    rejected = WorkbenchService(FalseSuccess()).handle(
        request("run_experiment", **input_data),
        session=session("workbench.experiment"), context=CONTEXT)
    assert rejected.status == "unavailable" and rejected.receipt is None
    assert rejected.problem["code"] == "experiment_issuer_unavailable"

    invalid = WorkbenchService(FalseSuccess()).handle(
        request("run_experiment", **{**input_data, "experiment": "arbitrary_script"}),
        session=session("workbench.experiment"), context=CONTEXT)
    assert invalid.problem["code"] == "experiment_issuer_unavailable"


@pytest.mark.parametrize("action,input_data,capability", [
    ("create_character", {"display_name": "小岚", "blueprint": "d01.persona.warm-listener.v1",
                          "model_capability_ref": "host/model", "budget_ref": "host/budget"},
     "workbench.create"),
    ("bind_scene", {"scene_ref": "scene:private-123", "visibility": "private",
                    "acknowledgement": True}, "workbench.bind_scene"),
])
def test_onboarding_commands_require_trusted_issuer_and_durable_receipt(action, input_data, capability):
    class NoWriter:
        def execute(self, **_):
            return {"status": "unavailable", "problem": {"code": "action_issuer_unavailable"}}

    payload = request(action, **input_data)
    denied = WorkbenchService().handle(payload, session=session("workbench.read"), context=CONTEXT)
    assert denied.status == "unauthorized" and denied.receipt is None

    missing = WorkbenchService().handle(payload, session=session(capability), context=CONTEXT)
    assert missing.status == "unavailable" and missing.receipt is None

    unavailable = WorkbenchService(NoWriter()).handle(payload, session=session(capability), context=CONTEXT)
    assert unavailable.status == "unavailable" and unavailable.receipt is None


@pytest.mark.parametrize("action,input_data,receipt", [
    ("create_character", {"display_name": "小岚", "blueprint": "d01.persona.curious-maker.v1",
                          "model_capability_ref": "host/model", "budget_ref": "host/budget"},
     {"phase": "role_initialized", "role_ref": "bot/persona"}),
    ("bind_scene", {"scene_ref": "scene:private-123", "visibility": "private",
                    "acknowledgement": True},
     {"phase": "scene_bound", "scene_ref": "scene:private-123"}),
])
def test_onboarding_does_not_accept_incomplete_success_receipt(action, input_data, receipt):
    class FalseSuccess:
        def execute(self, **kwargs):
            return {"status": "ready", "receipt": {"operation_id": kwargs["operation_id"], **receipt}}

    capability = "workbench.create" if action == "create_character" else "workbench.bind_scene"
    answer = WorkbenchService(FalseSuccess()).handle(
        request(action, **input_data), session=session(capability), context=CONTEXT)
    assert answer.status == "unavailable" and answer.receipt is None
    assert answer.problem["code"] == "invalid_provider_response"


def test_scene_visibility_must_be_explicitly_acknowledged():
    answer = WorkbenchService().handle(
        request("bind_scene", scene_ref="scene:group-123", visibility="group",
                acknowledgement=False),
        session=session("workbench.bind_scene"), context=CONTEXT)
    assert answer.problem["code"] == "invalid_request"


@pytest.mark.parametrize("blueprint", ["", "../preset", "d01..preset", "d01/preset", "x" * 193])
def test_create_rejects_malformed_blueprint_reference(blueprint):
    answer = WorkbenchService().handle(
        request("create_character", display_name="小岚", blueprint=blueprint,
                model_capability_ref="host/model", budget_ref="host/budget"),
        session=session("workbench.create"), context=CONTEXT)
    assert answer.status == "unavailable"
    assert answer.problem["code"] == "invalid_request"


def test_scene_receipt_must_identify_the_requested_scene():
    class WrongScene:
        def execute(self, **kwargs):
            return {"status": "ready", "receipt": {
                "operation_id": kwargs["operation_id"], "phase": "scene_bound",
                "scene_ref": "scene:another", "binding_revision": 1,
            }}

    answer = WorkbenchService(WrongScene()).handle(
        request("bind_scene", scene_ref="scene:chosen", visibility="private",
                acknowledgement=True),
        session=session("workbench.bind_scene"), context=CONTEXT)
    assert answer.status == "unavailable" and answer.receipt is None


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
    answer = WorkbenchService(Compiler()).handle(request("compile_scheme", draft_ref="draft:current",
                                                          budget_ref="budget:one"),
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
        request("compile_scheme", draft_ref="draft:current", budget_ref="budget:one"),
        session=session("workbench.compile"), context=CONTEXT,
    )
    assert answer.status == "unavailable" and answer.receipt is None
    assert answer.problem["code"] == "invalid_provider_response"


def test_scheme_server_commands_read_durable_originals_and_hold_without_adoption_port(tmp_path):
    namespace = NamespaceId("bot", "persona")
    path = tmp_path / "graph.db"
    with sqlite3.connect(path) as db:
        db.execute("BEGIN IMMEDIATE")
        install_scheme_original_store_v1(db)
        db.commit()

    class Port:
        def with_current_creator_draft_v1(self, *args, **kwargs):
            raise AssertionError("high-level trusted port owns current read")

        def compile_current_scheme_for_operation_v1(
                self, authority, lease, *, operation_id, draft_ref, budget_ref):
            assert lease is self and budget_ref == "budget:one"
            receipt = D12DomainCompileReceiptV1(
                "d01", ("d01.voice",), "a" * 64, "candidate:d01", "b" * 64)
            compiled = D12CompiledSchemeV1(
                namespace, draft_ref, 2, "c" * 64,
                active_scheme_head_key(namespace).token, 1, 4, 3, 2,
                (receipt,), "", "issuer-compilation")
            compiled = replace(compiled,
                               compiled_digest=compiled_scheme_digest_v1(compiled))
            original = CompilationOriginalV1(operation_id, compiled, "d" * 64,
                                             "e" * 64)
            with sqlite3.connect(path) as db:
                db.execute("BEGIN IMMEDIATE")
                record_compilation_original_for_operation_v1(db, original)
                db.commit()
            return original

        def read_compilation_original_v1(self, authority, lease, *, compiled_digest):
            with sqlite3.connect(path) as db:
                db.execute("BEGIN IMMEDIATE")
                original = read_compilation_original_for_operation_v1(
                    db, namespace, compiled_digest=compiled_digest)
                db.rollback()
            return original.compiled if original else None

        def preview_current_scheme_for_operation_v1(
                self, authority, lease, *, operation_id, compiled_digest, budget_ref):
            assert lease is self and budget_ref == "budget:one"
            with sqlite3.connect(path) as db:
                db.execute("BEGIN IMMEDIATE")
                compilation = read_compilation_original_for_operation_v1(
                    db, namespace, compiled_digest=compiled_digest)
                db.rollback()
            result = D12IsolatedPreviewV1(
                compiled_digest, NamespaceId("sandbox", "preview"),
                compilation.compiled.draft_digest, 4, 4, (), (), (), "cost:one")
            certificate = D12PreviewCertificateV1(
                compiled_digest, result.sandbox_namespace, "cost:one",
                "f" * 64)
            original = PreviewOriginalV1(
                operation_id, certificate, result, "1" * 64, "2" * 64,
                canonical_digest(result))
            with sqlite3.connect(path) as db:
                db.execute("BEGIN IMMEDIATE")
                record_preview_original_for_operation_v1(
                    db, compilation.compiled, original)
                db.commit()
            return original

        def read_preview_original_v1(self, authority, lease, *, preview_seal):
            with sqlite3.connect(path) as db:
                db.execute("BEGIN IMMEDIATE")
                original = read_preview_original_for_operation_v1(
                    db, namespace, preview_seal=preview_seal)
                db.rollback()
            return original.certificate if original else None

    port = Port()

    class Coordinator:
        def query(self, *args, **kwargs):
            raise AssertionError("scheme commands use the trusted port")

    class Grants:
        def resolve(self, *, session, scope, purpose, audience):
            authority = AuthorityContext(
                "actor", "d12", "creator-capability", namespace,
                ("persona",), purpose, (audience,), "policy", 1)
            return CoordinatorGrant(scope, authority, port,
                                    frozenset({"workbench.compile",
                                               "workbench.experiment",
                                               "workbench.activate"}))

    class Views:
        def view_types(self, authority):
            return {}

    workbench = WorkbenchService(GraphWorkbenchIssuer(
        Coordinator(), Grants(), Views(), scheme_port=port))
    creator = session("workbench.compile", "workbench.experiment",
                      "workbench.activate")
    draft_ref = character_draft_key(namespace).token
    compiled = workbench.handle(
        request("compile_scheme", draft_ref=draft_ref, budget_ref="budget:one"),
        session=creator, context=CONTEXT)
    assert compiled.status == "ready"
    assert compiled.receipt["phase"] == "compiled_candidate_recorded"
    preview = workbench.handle(
        request("preview_scheme", compiled_digest=compiled.receipt["compiled_digest"],
                budget_ref="budget:one"), session=creator, context=CONTEXT)
    assert preview.status == "ready"
    assert preview.receipt["phase"] == "isolated_preview_recorded"
    adoption = workbench.handle(
        request("activate_scheme", compiled_digest=compiled.receipt["compiled_digest"],
                preview_seal=preview.receipt["preview_seal"]),
        session=creator, context=CONTEXT)
    assert adoption.status == "unavailable"
    assert adoption.problem["code"] == "scheme_current_transaction_unavailable"


def test_source_correction_is_versioned_and_cannot_claim_a_commit_without_authority():
    class SpuriousWriter:
        def execute(self, **_):
            raise AssertionError("correction must not reach a generic writer")

    payload = request(
        "correct_or_edit", schema="d12.source_correction.v1",
        correction_kind="source_claim", statement="周一那件事是我说错了",
        source_refs=["source:owner-statement"], target_refs=["memory:prior-claim"],
        access_epoch=2, deletion_epoch=1,
    )
    answer = WorkbenchService(SpuriousWriter()).handle(
        payload, session=session("workbench.correct"), context=CONTEXT)
    assert answer.status == "unavailable" and answer.receipt is None
    assert answer.problem["code"] == "source_correction_commit_unavailable"
    assert answer.problem["schema"] == "d12.source_correction_response.v1"

    for invalid in (
        {"schema": "d12.source_correction.v2"},
        {"correction_kind": "creative_edit"},
        {"source_refs": []},
        {"target_refs": ["memory:prior-claim", "memory:prior-claim"]},
        {"access_epoch": True},
        {"statement": " "},
    ):
        malformed = {**payload, "input": {**payload["input"], **invalid}}
        rejected = WorkbenchService(SpuriousWriter()).handle(
            malformed, session=session("workbench.correct"), context=CONTEXT)
        assert rejected.problem["code"] == "invalid_request"
        assert rejected.receipt is None

    denied = WorkbenchService(SpuriousWriter()).handle(
        payload, session=session("workbench.read"), context=CONTEXT)
    assert denied.problem["code"] == "capability_denied"


def test_d12_draft_types_preserve_candidate_boundary_and_schema_digest():
    draft = CharacterDraft(SCOPE, 0, {"identity": "candidate"}, {"identity": "authored"})
    assert draft.revision == 0
    assert len(D12TypeSpec().digest) == 64


def test_d12_administrative_candidates_have_strict_shared_graph_specs():
    specs = graph_type_specs()
    assert len(specs) == 4
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
