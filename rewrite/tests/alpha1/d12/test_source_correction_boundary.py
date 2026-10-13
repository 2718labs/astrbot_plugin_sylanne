"""The D12 correction route must remain HOLD without a real W01 commit port."""

from __future__ import annotations

from dataclasses import replace
from uuid import uuid4

from sylanne3.authority_service.v2_owner_contract import OwnerPrincipalV1
from sylanne3.authority_service.v2_owner_session import OwnerSessionLoginRequestV1
from sylanne3.runtime_contracts import NamespaceId
from sylanne3.workbench_api import (
    AuthenticatedSession, GraphWorkbenchIssuer, RequestContext, WorkbenchService,
)
from sylanne3.workbench_api.source_correction import SourceCorrectionRequestV1


SCOPE = "bot/persona"
CONTEXT = RequestContext(True, True, True)
LOGIN = OwnerSessionLoginRequestV1(
    authority_id="authority", authority_namespace="bot/persona",
    installation_id="installation",
    principal=OwnerPrincipalV1("host", "owner", "incarnation"),
    credential_id="credential", credential_epoch=1, audience="owner",
    dashboard_origin="https://localhost:8080",
)
SESSION = AuthenticatedSession(
    "actor", "session", {SCOPE: frozenset({"workbench.correct"})},
    {SCOPE: frozenset({"owner"})},
    {SCOPE: frozenset({"workbench_user_action"})},
    owner_session_token="signed-owner-token", owner_session_request=LOGIN,
)


def command() -> dict:
    return {
        "schema_version": "d12.contract.v1", "action": "correct_or_edit",
        "scope": SCOPE, "purpose": "workbench_user_action", "audience": "owner",
        "operation_id": str(uuid4()), "input": {
            "schema": "d12.source_correction.v1", "correction_kind": "source_claim",
            "statement": "当时在忙", "source_refs": ["source:original"],
            "target_refs": ["interpretation:old"],
            "access_epoch": 3, "deletion_epoch": 2,
            "impact_preview_ref": "preview:untrusted",
        },
    }


class NoViews:
    def view_types(self, *_):
        return {}


class NoReadGrant:
    def resolve(self, **_):
        raise AssertionError("a read lease cannot authorize correction")


class NoCorrectionPort:
    def query(self, *_args, **_kwargs):
        raise AssertionError("a graph read cannot authorize correction")


def test_signed_owner_and_preview_still_hold_without_w01_commit_port():
    issuer = GraphWorkbenchIssuer(NoCorrectionPort(), NoReadGrant(), NoViews())
    answer = WorkbenchService(issuer).handle(command(), session=SESSION, context=CONTEXT)
    assert answer.status == "unavailable" and answer.receipt is None
    assert answer.problem["code"] == "source_correction_commit_unavailable"


def test_dedicated_port_receives_typed_request_but_rejects_nonreceipt():
    class UntrustedPort(NoCorrectionPort):
        received = None

        def commit_source_correction_v1(self, **kwargs):
            self.received = kwargs
            return {"status": "ready", "phase": "source_correction_committed"}

    port = UntrustedPort()
    installation_policy = object()
    admin_policy = object()
    issuer = GraphWorkbenchIssuer(
        port, NoReadGrant(), NoViews(),
        correction_installation_policy=installation_policy,
        correction_admin_policy=admin_policy,
    )
    request = command()
    answer = WorkbenchService(issuer).handle(request, session=SESSION, context=CONTEXT)
    assert answer.status == "unavailable" and answer.receipt is None
    assert answer.problem["code"] == "source_correction_receipt_invalid"
    submitted = port.received
    assert type(submitted["request"]) is SourceCorrectionRequestV1
    assert submitted["request"].operation_id == request["operation_id"]
    assert submitted["request"].source_refs == ("source:original",)
    assert submitted["request"].target_refs == ("interpretation:old",)
    assert submitted["principal"] == LOGIN.principal
    assert submitted["owner_session_request"] == LOGIN
    assert submitted["purpose"] == "workbench_user_action"
    assert submitted["audience"] == "owner"
    assert submitted["installation_policy"] is installation_policy
    assert submitted["admin_policy"] is admin_policy


def test_dedicated_port_rejects_statement_changed_after_command_digest():
    class ShouldNotCommit(NoCorrectionPort):
        def commit_source_correction_v1(self, **_):
            raise AssertionError("mismatched statement reached W01")

    issuer = GraphWorkbenchIssuer(ShouldNotCommit(), NoReadGrant(), NoViews())
    request = command()
    from sylanne3.workbench_api.service import request_digest

    digest = "sha256:" + request_digest({
        "action": request["action"], "scope": request["scope"],
        "purpose": request["purpose"], "audience": request["audience"],
        "operation_id": request["operation_id"], "input": request["input"],
    })
    typed = SourceCorrectionRequestV1(
        namespace=NamespaceId("bot", "persona"),
        operation_id=request["operation_id"], request_digest=digest,
        statement=request["input"]["statement"], source_refs=("source:original",),
        target_refs=("interpretation:old",), access_epoch=3, deletion_epoch=2,
        impact_preview_ref="preview:untrusted",
    )
    changed = replace(typed, statement="当时不在忙")
    result = issuer.correct_source_claim(
        session=SESSION, scope=SCOPE, purpose="workbench_user_action",
        audience="owner", request=changed,
    )
    assert result["problem"]["code"] == "source_correction_request_digest_mismatch"


def test_dedicated_port_is_not_called_without_signed_owner_session():
    class ShouldNotCommit(NoCorrectionPort):
        def commit_source_correction_v1(self, **_):
            raise AssertionError("unsigned Owner session reached the commit port")

    unsigned = AuthenticatedSession(
        SESSION.actor_id, SESSION.session_id, SESSION.scope_capabilities,
        SESSION.scope_audiences, SESSION.scope_purposes,
    )
    issuer = GraphWorkbenchIssuer(ShouldNotCommit(), NoReadGrant(), NoViews())
    answer = WorkbenchService(issuer).handle(command(), session=unsigned, context=CONTEXT)
    assert answer.status == "unavailable" and answer.receipt is None
    assert answer.problem["code"] == "signed_owner_session_unavailable"


def test_correction_context_requires_read_and_correct_and_signed_owner_before_grant():
    issuer = GraphWorkbenchIssuer(NoCorrectionPort(), NoReadGrant(), NoViews())
    for capabilities, token in (({"workbench.read"}, "signed"),
                                ({"workbench.correct"}, "signed"),
                                ({"workbench.read", "workbench.correct"}, "")):
        candidate = replace(SESSION, scope_capabilities={SCOPE: frozenset(capabilities)},
                            owner_session_token=token)
        answer = issuer.read_source_correction_context_v1(session=candidate, scope=SCOPE,
            purpose="workbench_user_action", audience="owner", source_id="actual-source")
        assert answer["status"] == "unavailable"
        assert answer["problem"]["code"] == "source_correction_policy_unavailable"


def test_correction_context_rejects_client_authority_fields_and_requires_owner_purpose():
    payload = {"schema_version": "d12.contract.v1", "action": "read_source_correction_context_v1",
        "scope": SCOPE, "purpose": "workbench_user_action", "audience": "owner",
        "operation_id": str(uuid4()), "input": {"source_id": "actual-source", "access_epoch": 7}}
    owner = replace(SESSION, scope_capabilities={SCOPE: frozenset({"workbench.read", "workbench.correct"})})
    for values in ({"source_id": "actual-source", "access_epoch": 7}, {"source_id": " "}, {}):
        answer = WorkbenchService().handle({**payload, "input": values}, session=owner, context=CONTEXT)
        assert answer.problem["code"] == "invalid_request"
        assert answer.receipt is None
