"""Current graph and real Authority ledger select a paid generation digest."""

from dataclasses import asdict, replace
from pathlib import Path
import json
import sqlite3
import sys
import time
from types import SimpleNamespace
from uuid import uuid4

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "runtime"))
import test_graph_v2_provisioning as graph_fixture
from test_first_ingress_c02_commit import c02_case
from test_natural_generation_issue_v2 import (
    _natural_generation_paid_lifecycle_case, context_reply_c02_case,
)
from test_first_encoding_cost_graph_commit import AccountingPort
from test_scene_binding_v2 import _session

from sylanne3.authority_service.contract import AuthorityUnavailable, JournalHead
from sylanne3.authority_service.mtls_server import (
    AdministratorInstallationV2, AuthorityRpcServer, MtlsPeerCredential,
)
from sylanne3.authority_service.core import AuthorityServiceCore
from sylanne3.authority_service.current_model_egress_graph_verifier import (
    PinnedCurrentModelEgressGraphVerifier,
)
from sylanne3.authority_service.v2_deletion_guard import AuthorityV2DeletionGuard
from sylanne3.authority_service.v2_execution_journal import AuthorityV2ExecutionJournal
from sylanne3.authority_service.v2_fence_service import AuthorityV2FenceService
from sylanne3.authority_service.v2_fence_store import AuthorityV2FenceStore
from sylanne3.authority_service.v2_model_egress_contract import (
    HostObservedModelCompletionV2,
)
from sylanne3.authority_service.v2_model_egress_service import (
    AuthorityV2ModelEgressService,
)
from sylanne3.authority_service.v2_model_egress_store import AuthorityV2ModelEgressStore
from sylanne3.authority_service.d13_natural_frame_verifier_v1 import build_authority_d13_natural_frame_verifier_v1
from sylanne3.authority_service.v2_natural_generation_output_contract import (
    natural_generation_output_attempt_id_v2,
)
from sylanne3.authority_service.v2_natural_generation_output_service import (
    AuthorityV2NaturalGenerationOutputService,
    PinnedNaturalGenerationOriginalPaidVerifierV2,
)
from sylanne3.authority_service.v2_natural_generation_content_service import (
    AuthorityV2NaturalGenerationContentService,
    PinnedCurrentNaturalGenerationContentVerifierV2,
)
from sylanne3.authority_service.v2_natural_generation_content_contract import (
    natural_generation_content_attempt_id_v2,
)
from sylanne3.authority_service.v2_natural_review_output_service import (
    AuthorityV2NaturalReviewOutputService,
    PinnedNaturalReviewOriginalPaidVerifierV2,
)
from sylanne3.authority_service.v2_natural_review_output_contract import (
    natural_review_output_attempt_id_v2,
)
from sylanne3.authority_service.v2_natural_paid_review_contract import (
    NaturalPaidReviewCurrentReadV2, from_wire as paid_review_from_wire,
    natural_paid_review_attempt_id_v2, to_wire as paid_review_to_wire,
)
from sylanne3.authority_service.v2_natural_paid_review_service import (
    AuthorityV2NaturalPaidReviewService,
    PinnedCurrentNaturalPaidReviewVerifierV2,
)
from sylanne3.model_broker.natural_review import OUTPUT_SCHEMA as REVIEW_OUTPUT_SCHEMA
from sylanne3.model_broker.natural_reply import OUTPUT_SCHEMA
from sylanne3.domains.d08.natural_plan import decode_natural_plan_v2
from sylanne3.domains.d06.source_access_revocation import SourceAccessRevocationRequest
from sylanne3.graph_types import AtomKey
from sylanne3.graph_coordinator import UnavailableGuard
from sylanne3.runtime.deletion import DeletionJournal
from sylanne3.runtime.natural_generation_issue_v2 import (
    read_original_scoped_query_proof_v2,
)
from sylanne3.runtime.natural_reply_job_v2 import read_original_preparation
from sylanne3.runtime.natural_review_issue_v2 import (
    verify_current_generation_content_for_review_v2,
)
from sylanne3.runtime_contracts import canonical_digest, canonical_serialize


@pytest.mark.parametrize("mode", (
    "result", "revoke", "terminal", "review", "review_acquire",
    "review_begin_absent", "review_paid", "review_terminal",
    "review_lost_output_ack", "review_current",
    "lost_output_ack"))
def test_original_generation_digest_comes_from_real_authority_observation(
        request, tmp_path, monkeypatch, mode):
    _real_authority_case(request, tmp_path, monkeypatch, mode)


def _real_authority_case(request, tmp_path, monkeypatch, mode, *,
                         before_revoke=None, daemon_reopen=None):
    revoke_before_admission = mode == "revoke"
    authority_namespace = "opaque:persona"
    deletion = DeletionJournal(tmp_path / "deletion.db", create=True)
    guard = AuthorityV2DeletionGuard(tmp_path / "deletion.db")
    execution = AuthorityV2ExecutionJournal(
        tmp_path / "execution.db", namespace=authority_namespace,
        journal_id="execution", create=True)
    head = deletion.latest_head()
    deletion_head = JournalHead(head.journal_id, head.seq, head.chain_digest)
    with monkeypatch.context() as seeded_id:
        seeded_id.setattr(
            "sylanne3.authority_service.core.uuid.uuid4", lambda: "authority")
        core = AuthorityServiceCore(
            tmp_path / "authority.db", create=True,
            authorizer=lambda credential, *_: credential == "ok",
            deletion_verifier=lambda _ns, _before, current, phase:
                current == deletion_head and phase == "clear",
            execution_verifier=lambda _ns, _before, current, _phase:
                current == execution.verified_head(),
            effect_verifier=lambda *_: True,
            dispatch_verifier=lambda *_: True,
        )
    try:
        core.register_namespace(
            "ok", authority_namespace, "administrator", deletion_head,
            execution.verified_head())
        core.seal_v2_only("ok")
        fences = AuthorityV2FenceService(
            core=core, fences=AuthorityV2FenceStore(
                core._db, create=True, lock=core._lock),
            deletion=guard, execution=execution, namespace=authority_namespace)
        original_anchor = fences.current_anchor(
            credential="ok", subject="administrator")

        class CoreAnchoredGraphPort(graph_fixture.AuthorityPort):
            def provision_namespace(self, *, namespace, request_id):
                result = super().provision_namespace(
                    namespace=namespace, request_id=request_id)
                self.anchors[namespace] = original_anchor
                return replace(result, authority_id=original_anchor.authority_id,
                               anchor=original_anchor)

        monkeypatch.setattr(graph_fixture, "AuthorityPort", CoreAnchoredGraphPort)
        context_reply_c02_case = request.getfixturevalue("context_reply_c02_case")
        paid_output = {}
        daemon_model_service = None
        daemon_cleanup = None

        class RevokedBeforeDispatch(Exception):
            pass

        def revoke_original_access(case, saved, anchor):
            original_case = case["owner_scene_case"]
            bootstrap_case = case["case"]
            if isinstance(bootstrap_case, dict):
                bootstrap_case = bootstrap_case["case"]
            token, owner_request = _session(original_case)
            owner, owner_lease, _ = case["graph"].grant_current_owner(
                bootstrap_case[2], actor="paired-owner",
                namespace=case["namespace"], domains=("d06", "d11"),
                purpose="audit", audience="owner",
                activation_generation=anchor.activation_generation,
                owner_session_token=token,
                owner_session_request=owner_request)
            try:
                source_id = AtomKey.from_token(
                    saved.frozen.input.plan.units[0].source_refs[0].ref,
                ).owner.subject
                access_ref = saved.frozen.input.plan.units[0].access_refs[0].ref
                access = json.loads(case["store"]._db.execute(
                    "SELECT value FROM graph_atoms WHERE token=?",
                    (access_ref,),
                ).fetchone()[0])
                recorded_at = access["recorded_at"] + 1.0
                with monkeypatch.context() as revoke_clock:
                    revoke_clock.setattr(
                        original_case[2], "read_ingress_clock",
                        lambda _: SimpleNamespace(
                            utc_upper_bound_seconds=recorded_at + 1.0,
                            monotonic_after_seconds=time.monotonic()))
                    revoked = case["graph"].revoke_source_access_v1(
                        owner, owner_lease, SourceAccessRevocationRequest(
                            source_id, "paired-owner", str(uuid4()),
                            recorded_at))
                assert revoked.source_id == source_id
            finally:
                case["graph"].release_current_owner_lease(
                    bootstrap_case[2], owner_lease)

        def paid_fact_factory(case, saved, running, call, draft, anchor, natural):
            nonlocal core, fences, daemon_model_service, daemon_cleanup
            assert anchor == original_anchor
            if daemon_reopen is not None and daemon_model_service is None:
                core, fences, daemon_model_service, daemon_cleanup = daemon_reopen(
                    case=case, saved=saved, natural=natural, core=core,
                    fences=fences, deletion=deletion, guard=guard,
                    execution=execution, graph_path=case["store"]._db.execute(
                        "PRAGMA database_list").fetchone()[2],
                    authority_namespace=authority_namespace,
                    original_anchor=original_anchor)
            plan = saved.frozen.input.plan
            unit = plan.units[0]
            speech_act = next(value for value in plan.allowed_speech_acts
                              if value != "promise")
            paid_output["value"] = canonical_serialize({
                "schema": OUTPUT_SCHEMA, "body": unit.qualified_text,
                "units": [{
                    "start": 0, "end": len(unit.qualified_text),
                    "kind": unit.kind.value, "basis_ids": [unit.basis_id],
                    "speech_act": speech_act, "promise_grant_id": None,
                    "slot_ids": list(plan.required_slots),
                }],
            })
            graph_path = case["store"]._db.execute(
                "PRAGMA database_list").fetchone()[2]
            now = saved.frozen.input.frozen_at_utc + 1.0
            model_store = (daemon_model_service._store if daemon_model_service is not None else
                AuthorityV2ModelEgressStore(core._db, create=True, lock=core._lock))
            history = build_authority_d13_natural_frame_verifier_v1(bundle=natural,
                d11_issuer=case["graph"]._GraphCoordinator__d11_issuer, authority_store=model_store)
            verifier = PinnedCurrentModelEgressGraphVerifier(
                graph_path, d11_issuer=case["graph"]._GraphCoordinator__d11_issuer,
                trusted_now_utc=lambda: now,
                trusted_paired_clock=lambda: (now, "natural-paid-test-clock"), natural_history_verifier=history)
            egress = daemon_model_service or AuthorityV2ModelEgressService(
                AuthorityV2ModelEgressStore(
                    core._db, create=True, lock=core._lock),
                fences, graph_verifier=verifier,
                admin_model_policy=natural.model_workflows)
            prepared, permit = egress.prepare_fenced(
                credential="ok", subject=draft.subject,
                holder="administrator", draft=draft, expected_anchor=anchor,
                installation_id=saved.seal.installation_id)
            intent = prepared.intent
            assert verifier.complete_graph_current(intent)
            if revoke_before_admission:
                revoke_original_access(case, saved, anchor)
                assert not verifier.complete_graph_current(intent)
                with pytest.raises(AuthorityUnavailable):
                    egress.admit_dispatch_once_v2(
                        credential="ok", subject=draft.subject,
                        holder="administrator", intent=intent,
                        expected_anchor=anchor, request=call,
                        installation_id=saved.seal.installation_id,
                        observer_peer_sha256="1" * 64,
                        observer_profile_id="observer",
                        manifest_digest="2" * 64,
                        host_incarnation="3" * 64)
                raise RevokedBeforeDispatch
            _, observed_permit, admission = egress.admit_dispatch_once_v2(
                credential="ok", subject=draft.subject,
                holder="administrator", intent=intent,
                expected_anchor=anchor, request=call,
                installation_id=saved.seal.installation_id,
                observer_peer_sha256="1" * 64,
                observer_profile_id="observer", manifest_digest="2" * 64,
                host_incarnation="3" * 64)
            assert observed_permit == permit
            report = HostObservedModelCompletionV2(
                admission.admission_id, admission.host_incarnation,
                intent.call_id, intent.request_digest, intent.provider_id,
                intent.model_id, intent.provider_config_digest,
                canonical_serialize({"text": paid_output["value"]}),
                (("output_tokens", 1),), (), "controlled-provider-call")
            observed, finished_permit, terminal = egress.complete_observed_v2(
                credential="ok", subject=draft.subject,
                holder="administrator", intent=intent,
                expected_anchor=anchor, admission=admission, report=report,
                installation_id=saved.seal.installation_id,
                observer_peer_sha256="1" * 64,
                observer_profile_id="observer", manifest_digest="2" * 64)
            assert finished_permit == permit
            return intent, (observed, permit, admission, terminal)

        if revoke_before_admission:
            with pytest.raises(RevokedBeforeDispatch):
                _natural_generation_paid_lifecycle_case(
                    context_reply_c02_case, monkeypatch,
                    paid_fact_factory=paid_fact_factory, complete_terminal=False)
            return
        case = _natural_generation_paid_lifecycle_case(
            context_reply_c02_case, monkeypatch,
            paid_fact_factory=paid_fact_factory, complete_terminal=False)
        graph_path = case["store"]._db.execute(
            "PRAGMA database_list").fetchone()[2]
        history = build_authority_d13_natural_frame_verifier_v1(bundle=case["installed"],
            d11_issuer=case["graph"]._GraphCoordinator__d11_issuer,
            authority_store=AuthorityV2ModelEgressStore(core._db, create=True, lock=core._lock))
        reader = AuthorityV2NaturalGenerationOutputService(
            store=AuthorityV2ModelEgressStore(
                core._db, create=True, lock=core._lock),
            fences=fences,
            graph_verifier=PinnedNaturalGenerationOriginalPaidVerifierV2(
                graph_path),
            installation_id=case["saved"].seal.installation_id,
            read_subject=case["intent"].subject, holder="administrator",
            trusted_now_utc=lambda: case["saved"].frozen.input.frozen_at_utc + 1)
        if mode in {"terminal", "review", "review_acquire", "review_paid",
                    "review_terminal", "review_lost_output_ack",
                    "review_current",
                    "review_begin_absent",
                    "lost_output_ack"}:
            read_attempts = []

            class LostOutputAck(Exception):
                pass

            def output_port(request, *, now_utc):
                result = reader.read_original_natural_generation_output_v2(
                    credential="ok", request=request, now_utc=now_utc)
                read_attempts.append(request.read_attempt_id)
                if mode == "lost_output_ack" and len(read_attempts) == 1:
                    raise LostOutputAck("Authority finished; graph missed output")
                return result

            case["graph"]._GraphCoordinator__natural_generation_output_port = (
                output_port)
            operation_id = "natural-generation-terminal-" + canonical_digest({
                "namespace": case["namespace"].as_tuple,
                "original_operation_id": case["saved"].seal.original_operation_id,
            })[:48]
            terminal_lease, terminal_capability = case["graph"].grant(
                case["c02_case"]["case"][2],
                actor=case["c02_case"]["case"][4].administrator_holder,
                issuer_domain="d11", namespace=case["namespace"],
                domains=("d11",),
                activation_generation=case["intent"].authority_activation_generation,
                operation_id=operation_id)
            terminal_authority = replace(
                case["call"].envelope.authority,
                capability_ref=terminal_capability, worker_fence=None)
            try:
                if mode == "lost_output_ack":
                    with pytest.raises(LostOutputAck):
                        case["graph"].complete_natural_generation_model_job_v2(
                            terminal_authority, terminal_lease,
                            case["saved"].seal.c02_operation_id,
                            case["intent"], case["installed"])
                completed = case["graph"].complete_natural_generation_model_job_v2(
                    terminal_authority, terminal_lease,
                    case["saved"].seal.c02_operation_id, case["intent"],
                    case["installed"])
                assert completed.phase == "completed"
                if mode == "lost_output_ack":
                    assert len(read_attempts) == 2
                    assert read_attempts == [
                        natural_generation_output_attempt_id_v2(
                            case["saved"].seal.original_operation_id, attempt)
                        for attempt in (1, 2)]
                durable = case["graph"].read_natural_generation_terminal_receipt_v2(
                    terminal_authority, terminal_lease,
                    case["saved"].seal.c02_operation_id, case["installed"])
                assert durable.output_digest == canonical_digest(
                    json.loads(paid_output["value"]))
                assert case["graph"].complete_natural_generation_model_job_v2(
                    terminal_authority, terminal_lease,
                    case["saved"].seal.c02_operation_id, case["intent"],
                    case["installed"]) == completed
                if mode in {"review", "review_acquire", "review_paid",
                            "review_terminal", "review_lost_output_ack",
                            "review_current",
                            "review_begin_absent"}:
                    content_graph = PinnedCurrentNaturalGenerationContentVerifierV2(
                        graph_path, natural_history_verifier=history)
                    content_service = AuthorityV2NaturalGenerationContentService(
                        original=reader, graph=content_graph,
                        trusted_now_utc=lambda:
                            case["saved"].frozen.input.frozen_at_utc + 1)
                    case["graph"]._GraphCoordinator__natural_generation_content_port = (
                        lambda request, *, now_utc:
                            content_service.read_current_natural_generation_content_v2(
                                credential="ok", request=request, now_utc=now_utc))
                    with monkeypatch.context() as review_ready:
                        if mode == "review_begin_absent":
                            port = case["owner_scene_case"][2]
                            original_begin = port.begin_fence
                            review_begin_attempts = []

                            def fail_first_review_begin(**kwargs):
                                operation_id = kwargs["operation_id"]
                                if operation_id.startswith("natural-review-write-"):
                                    review_begin_attempts.append(operation_id)
                                    if len(review_begin_attempts) == 1:
                                        raise RuntimeError("begin failed before Authority")
                                return original_begin(**kwargs)

                            review_ready.setattr(port, "begin_fence",
                                                 fail_first_review_begin)
                        review_ready.setattr(
                            case["owner_scene_case"][2],
                            "natural_review_paid_consumer_ready_v2",
                            lambda **kwargs: True,
                            raising=False)
                        if mode == "review_begin_absent":
                            with pytest.raises(Exception,
                                               match="natural review write begin unknown"):
                                case["graph"].prepare_post_c02_natural_review_v2(
                                    terminal_authority, terminal_lease,
                                    case["saved"].seal.c02_operation_id,
                                    case["installed"])
                        review_saved = (
                            case["graph"].prepare_post_c02_natural_review_v2(
                                terminal_authority, terminal_lease,
                                case["saved"].seal.c02_operation_id,
                                case["installed"]))
                        if mode == "review_begin_absent":
                            assert len(review_begin_attempts) == 2
                            assert review_begin_attempts[0] == (
                                review_begin_attempts[1])
                            assert case["store"]._db.execute(
                                "SELECT COUNT(*) FROM "
                                "graph_natural_review_preparations_v2 WHERE "
                                "bot=? AND persona=? AND parent_original_id=?",
                                case["namespace"].as_tuple +
                                (case["saved"].seal.c02_operation_id,),
                            ).fetchone() == (1,)
                        if mode in {"review_acquire", "review_paid",
                                    "review_terminal", "review_lost_output_ack",
                                    "review_current"}:
                            review_workflow = (
                                case["installed"].model_workflows.natural_review)
                            bootstrap_case = case["c02_case"]["case"]
                            review_lease, review_cap = case["graph"].grant(
                                bootstrap_case[2],
                                actor=bootstrap_case[4].administrator_holder,
                                issuer_domain="d11", namespace=case["namespace"],
                                domains=("d11",),
                                activation_generation=original_anchor.activation_generation,
                                operation_id=review_saved.seal.acquire_operation_id)
                            review_authority = replace(
                                terminal_authority,
                                capability_ref=review_cap,
                                provider_policy_ref=review_workflow.provider_config_ref)
                            try:
                                review_job, review_call = (
                                    case["graph"].acquire_post_c02_natural_review_v2(
                                        review_authority, review_lease,
                                        case["saved"].seal.c02_operation_id,
                                        case["installed"], lease_seconds=60))
                                review_call, review_draft, review_anchor = (
                                    case["graph"].read_natural_model_egress_preparation_v2(
                                        replace(review_authority,
                                                worker_fence=review_job.fence),
                                        review_lease,
                                        case["saved"].seal.c02_operation_id,
                                        "review", case["installed"]))
                                assert review_call.call_id == review_saved.seal.call_id
                                assert review_draft.budget_reservation_operation_id == (
                                    review_saved.seal.reservation_operation_id)
                                review_verifier = PinnedCurrentModelEgressGraphVerifier(
                                    graph_path,
                                    d11_issuer=case["graph"]._GraphCoordinator__d11_issuer,
                                    trusted_now_utc=lambda:
                                        case["saved"].frozen.input.frozen_at_utc + 1,
                                    trusted_paired_clock=lambda: (
                                        case["saved"].frozen.input.frozen_at_utc + 1,
                                        "review-paid-test-clock"), natural_history_verifier=history)
                                review_egress = daemon_model_service or AuthorityV2ModelEgressService(
                                    AuthorityV2ModelEgressStore(
                                        core._db, create=True, lock=core._lock),
                                    fences, graph_verifier=review_verifier,
                                    admin_model_policy=case["installed"].model_workflows)
                                prepared, _ = review_egress.prepare_fenced(
                                    credential="ok", subject=review_draft.subject,
                                    holder="administrator", draft=review_draft,
                                    expected_anchor=review_anchor,
                                    installation_id=review_saved.seal.installation_id)
                                assert review_verifier.complete_graph_current(
                                    prepared.intent)
                                if mode in {"review_paid", "review_terminal",
                                            "review_lost_output_ack",
                                            "review_current"}:
                                    review_intent = prepared.intent
                                    _, _, review_admission = (
                                        review_egress.admit_dispatch_once_v2(
                                            credential="ok",
                                            subject=review_draft.subject,
                                            holder="administrator",
                                            intent=review_intent,
                                            expected_anchor=review_anchor,
                                            request=review_call,
                                            installation_id=review_saved.seal.installation_id,
                                            observer_peer_sha256="1" * 64,
                                            observer_profile_id="observer",
                                            manifest_digest="2" * 64,
                                            host_incarnation="3" * 64))
                                    review_text = canonical_serialize({
                                        "schema": REVIEW_OUTPUT_SCHEMA,
                                        "verdict": "pass", "issues": [],
                                    })
                                    review_report = HostObservedModelCompletionV2(
                                        review_admission.admission_id,
                                        review_admission.host_incarnation,
                                        review_intent.call_id,
                                        review_intent.request_digest,
                                        review_intent.provider_id,
                                        review_intent.model_id,
                                        review_intent.provider_config_digest,
                                        canonical_serialize({"text": review_text}),
                                        (("output_tokens", 1),), (),
                                        "controlled-review-provider-call")
                                    review_observed, review_permit, review_terminal = (
                                        review_egress.complete_observed_v2(
                                            credential="ok",
                                            subject=review_draft.subject,
                                            holder="administrator",
                                            intent=review_intent,
                                            expected_anchor=review_anchor,
                                            admission=review_admission,
                                            report=review_report,
                                            installation_id=review_saved.seal.installation_id,
                                            observer_peer_sha256="1" * 64,
                                            observer_profile_id="observer",
                                            manifest_digest="2" * 64))
                                    review_fact = (review_observed, review_permit,
                                                   review_admission, review_terminal)
                                    case["graph"]._GraphCoordinator__model_terminal_cost_port = (
                                        lambda actual: review_fact
                                        if actual == review_intent else None)
                                    case["graph"]._GraphCoordinator__accounting_maintenance_port = (
                                        AccountingPort(case["store"], review_fact))
                                    quote_id, quote_version = review_job.operator_versions[
                                        "resource_quote"].rsplit(":", 1)
                                    review_cost = (
                                        case["graph"].commit_natural_review_model_cost_v2(
                                            bootstrap_case[2], case["namespace"],
                                            review_intent, quote_id=quote_id,
                                            quote_version=int(quote_version)))
                                    assert review_cost.status == "committed"
                                    review_request = (
                                        case["graph"].read_natural_review_output_request_v2(
                                            replace(review_authority,
                                                    worker_fence=review_job.fence),
                                            review_lease,
                                            case["saved"].seal.c02_operation_id,
                                            case["installed"]))
                                    review_selector = (
                                        AuthorityV2NaturalReviewOutputService(
                                            store=AuthorityV2ModelEgressStore(
                                                core._db, create=True, lock=core._lock),
                                            fences=fences,
                                            graph_verifier=
                                                PinnedNaturalReviewOriginalPaidVerifierV2(
                                                    graph_path),
                                            installation_id=review_saved.seal.installation_id,
                                            read_subject=review_intent.subject,
                                            holder="administrator",
                                            trusted_now_utc=lambda:
                                                case["saved"].frozen.input.frozen_at_utc + 1))
                                    if mode == "review_paid":
                                        paid_review = (
                                            review_selector.read_original_natural_review_output_v2(
                                                credential="ok", request=review_request,
                                                now_utc=0.0))
                                        assert paid_review.verdict == "pass"
                                        assert paid_review.output_digest == canonical_digest(
                                            json.loads(review_text))
                                        assert not hasattr(paid_review, "body")
                                    if mode in {"review_terminal",
                                                "review_lost_output_ack"}:
                                        review_attempts = []

                                        class LostReviewOutputAck(Exception):
                                            pass

                                        def review_output_port(request, *, now_utc):
                                            output = (
                                                review_selector.read_original_natural_review_output_v2(
                                                    credential="ok", request=request,
                                                    now_utc=now_utc))
                                            review_attempts.append(request.read_attempt_id)
                                            if (mode == "review_lost_output_ack"
                                                    and len(review_attempts) == 1):
                                                raise LostReviewOutputAck(
                                                    "review selector finished; graph missed output")
                                            return output

                                        case["graph"]._GraphCoordinator__natural_review_output_port = (
                                            review_output_port)
                                        terminal_id = (
                                            "natural-review-terminal-" +
                                            canonical_digest({
                                                "namespace": case["namespace"].as_tuple,
                                                "original_operation_id":
                                                    review_saved.seal.original_operation_id,
                                            })[:48])
                                        review_terminal_lease, review_terminal_cap = (
                                            case["graph"].grant(
                                                bootstrap_case[2],
                                                actor=bootstrap_case[4].administrator_holder,
                                                issuer_domain="d11",
                                                namespace=case["namespace"],
                                                domains=("d11",),
                                                activation_generation=
                                                    original_anchor.activation_generation,
                                                operation_id=terminal_id))
                                        try:
                                            review_terminal_authority = replace(
                                                review_authority,
                                                capability_ref=review_terminal_cap,
                                                worker_fence=None)
                                            if mode == "review_lost_output_ack":
                                                with pytest.raises(LostReviewOutputAck):
                                                    case["graph"].complete_natural_review_model_job_v2(
                                                        review_terminal_authority,
                                                        review_terminal_lease,
                                                        case["saved"].seal.c02_operation_id,
                                                        review_intent,
                                                        case["installed"])
                                            finished_review = (
                                                case["graph"].complete_natural_review_model_job_v2(
                                                    review_terminal_authority,
                                                    review_terminal_lease,
                                                    case["saved"].seal.c02_operation_id,
                                                    review_intent,
                                                    case["installed"]))
                                            assert finished_review.phase == "completed"
                                            durable_review = (
                                                case["graph"].read_natural_review_terminal_receipt_v2(
                                                    review_terminal_authority,
                                                    review_terminal_lease,
                                                    case["saved"].seal.c02_operation_id,
                                                    case["installed"]))
                                            assert durable_review.output_digest == (
                                                canonical_digest(json.loads(
                                                    review_text)))
                                            assert durable_review.verdict == "pass"
                                            if mode == "review_current":
                                                paid_request = (
                                                    case["graph"].read_natural_paid_review_request_v2(
                                                        review_terminal_authority,
                                                        review_terminal_lease,
                                                        case["saved"].seal.c02_operation_id,
                                                        case["installed"]))
                                                paid_service = (
                                                    AuthorityV2NaturalPaidReviewService(
                                                        generation=reader,
                                                        review=review_selector,
                                                        graph=PinnedCurrentNaturalPaidReviewVerifierV2(
                                                            graph_path, natural_history_verifier=history),
                                                        trusted_now_utc=lambda:
                                                            case["saved"].frozen.input.frozen_at_utc + 1))
                                                paid_current = (
                                                    paid_service.read_current_natural_paid_review_v2(
                                                        credential="ok",
                                                        request=paid_request,
                                                        now_utc=0.0))
                                                assert paid_current.generation_output[
                                                    "body"] == json.loads(
                                                        paid_output["value"])["body"]
                                                assert paid_current.parsed_review.verdict == "pass"
                                                assert paid_current.paid_receipt.verdict == "pass"
                                                assert paid_review_from_wire(
                                                    paid_review_to_wire(paid_current),
                                                    NaturalPaidReviewCurrentReadV2) == (
                                                        paid_current)
                                                peer = MtlsPeerCredential("9" * 64)
                                                rpc = object.__new__(AuthorityRpcServer)
                                                rpc._v2_natural_paid_review_reads = {
                                                    authority_namespace: SimpleNamespace(
                                                        _generation=SimpleNamespace(
                                                            _read_subject=
                                                                "mtls:sha256:" +
                                                                peer.certificate_sha256),
                                                        read_current_natural_paid_review_v2=
                                                            lambda **kwargs: paid_current)}
                                                rpc._worker_result_readers_v2 = {
                                                    authority_namespace:
                                                        (peer.certificate_sha256,
                                                         "natural-profile")}
                                                rpc._installations_v2 = {
                                                    (peer.certificate_sha256,
                                                     "natural-profile"):
                                                        AdministratorInstallationV2(
                                                            case["installed"].installation_policy.installation_id,
                                                            "administrator", "policy", "v2", "f" * 64)}
                                                rpc._namespace_bindings_v2 = {
                                                    (peer.certificate_sha256,
                                                     "natural-profile",
                                                     case["namespace"]):
                                                        authority_namespace}
                                                rpc._authority_id = lambda: original_anchor.authority_id
                                                rpc._bound_v2_service = lambda *_: None
                                                assert rpc._v2_command(
                                                    "natural_paid_review_current_read_v2",
                                                    peer, "natural-profile", "f" * 64,
                                                    {"namespace": authority_namespace,
                                                     "read_request": paid_review_to_wire(
                                                         paid_request)}) == {
                                                    "result": paid_review_to_wire(
                                                        paid_current)}
                                                case["graph"]._GraphCoordinator__natural_paid_review_current_port = (
                                                    lambda request, *, now_utc:
                                                        paid_service.read_current_natural_paid_review_v2(
                                                            credential="ok", request=request,
                                                            now_utc=now_utc))
                                                final_candidate = (
                                                    case["graph"].read_current_natural_final_candidate_v2(
                                                        review_terminal_authority,
                                                        review_terminal_lease,
                                                        case["saved"].seal.c02_operation_id,
                                                        case["installed"]))
                                                assert final_candidate.status == (
                                                    "candidate_hold_w01_final_admission")
                                                assert final_candidate.material is not None
                                                if before_revoke is not None:
                                                    before_revoke({
                                                        "case": case,
                                                        "paid_current": paid_current,
                                                        "final_candidate": final_candidate,
                                                        "installed": case["installed"],
                                                        "review_terminal_authority":
                                                            review_terminal_authority,
                                                        "review_terminal_lease":
                                                            review_terminal_lease,
                                                        "now_utc":
                                                            case["saved"].frozen.input.frozen_at_utc + 1,
                                                        "parent_original_id":
                                                            case["saved"].seal.c02_operation_id,
                                                        "authority_core": core,
                                                        "authority_fences": fences,
                                                        "authority_execution": execution,
                                                        "original_anchor": original_anchor,
                                                    })
                                                revoke_original_access(
                                                    {**case, "case": case["c02_case"]},
                                                    case["saved"], original_anchor)
                                                with case["store"]._lock:
                                                    current_db = case["store"]._db
                                                    current_db.execute("BEGIN")
                                                    try:
                                                        _, revoked_epoch = (
                                                            case["graph"]._v2_graph_stamp(
                                                                case["namespace"]))
                                                        with pytest.raises(
                                                                UnavailableGuard):
                                                            case["graph"]._verify_natural_paid_review_current_locked(
                                                                case["namespace"],
                                                                case["saved"].seal.c02_operation_id,
                                                                case["installed"],
                                                                paid_current,
                                                                case["saved"].frozen.input.frozen_at_utc + 1,
                                                                revoked_epoch)
                                                    finally:
                                                        current_db.execute("ROLLBACK")
                                                with pytest.raises(
                                                        AuthorityUnavailable,
                                                        match="current scope"):
                                                    paid_service.read_current_natural_paid_review_v2(
                                                        credential="ok",
                                                        request=replace(
                                                            paid_request,
                                                            read_attempt_id=
                                                            natural_paid_review_attempt_id_v2(
                                                                review_saved.seal.original_operation_id,
                                                                2)),
                                                        now_utc=0.0)
                                            if mode == "review_lost_output_ack":
                                                assert review_attempts == [
                                                    natural_review_output_attempt_id_v2(
                                                        review_saved.seal.original_operation_id,
                                                        attempt)
                                                    for attempt in (1, 2)]
                                        finally:
                                            case["graph"].release_authority_lease(
                                                bootstrap_case[2],
                                                review_terminal_lease)
                                        return
                                    from sylanne3.runtime.model_cost_settlement import (
                                        original_model_cost_operation_id_v1,
                                    )
                                    review_cost_id = original_model_cost_operation_id_v1(
                                        case["namespace"], review_saved.seal.call_id)
                                    with sqlite3.connect(graph_path) as tamper_db:
                                        tamper_db.execute(
                                            "UPDATE graph_bundle_operations SET "
                                            "receipt_json=? WHERE bot=? AND persona=? "
                                            "AND operation_id=?",
                                            ("{}",) + case["namespace"].as_tuple +
                                            (review_cost_id,),
                                        )
                                    with pytest.raises(AuthorityUnavailable,
                                                       match="review original paid graph"):
                                        review_selector.read_original_natural_review_output_v2(
                                            credential="ok", request=replace(
                                                review_request, read_attempt_id=
                                                natural_review_output_attempt_id_v2(
                                                    review_saved.seal.original_operation_id,
                                                    2)), now_utc=0.0)
                            finally:
                                case["graph"].release_authority_lease(
                                    bootstrap_case[2], review_lease)
                    assert review_saved.stage == "review"
                    assert review_saved.state == "queued"
                    assert review_saved.seal.parent_budget_lease_id == (
                        case["saved"].seal.parent_budget_lease_id)
                    return
                content_request = (
                    case["graph"].read_natural_generation_content_request_v2(
                        terminal_authority, terminal_lease,
                        case["saved"].seal.c02_operation_id,
                        case["installed"]))
                content_graph = PinnedCurrentNaturalGenerationContentVerifierV2(
                    graph_path, natural_history_verifier=history)
                content_service = AuthorityV2NaturalGenerationContentService(
                    original=reader, graph=content_graph,
                    trusted_now_utc=lambda:
                        case["saved"].frozen.input.frozen_at_utc + 1)
                content = content_service.read_current_natural_generation_content_v2(
                    credential="ok", request=content_request, now_utc=0.0)
                assert content.text == paid_output["value"]
                assert content.output_digest == durable.output_digest
                assert content.current_read_versions
                with case["store"]._lock:
                    db = case["store"]._db
                    db.execute("BEGIN")
                    try:
                        terminal_saved = read_original_preparation(
                            db, case["namespace"],
                            case["saved"].seal.c02_operation_id,
                            "generation")
                        scoped = read_original_scoped_query_proof_v2(
                            db, terminal_saved)
                        adopted_row = db.execute(
                            "SELECT value FROM graph_atoms WHERE token=?",
                            (terminal_saved.frozen.input.plan.plan_ref.ref,),
                        ).fetchone()
                        adopted = decode_natural_plan_v2(
                            json.loads(adopted_row[0]))
                        review_input = verify_current_generation_content_for_review_v2(
                            db, generation=terminal_saved, content=content,
                            scoped_proof=scoped, adopted_plan=adopted,
                            now_utc=case["saved"].frozen.input.frozen_at_utc + 1)
                        assert review_input["body"] == (
                            json.loads(paid_output["value"])["body"])
                    finally:
                        db.execute("ROLLBACK")
                revoke_original_access(
                    {**case, "case": case["c02_case"]},
                    case["saved"], original_anchor)
                with pytest.raises(AuthorityUnavailable,
                                   match="current review scope"):
                    content_service.read_current_natural_generation_content_v2(
                        credential="ok", request=replace(
                            content_request, read_attempt_id=
                            natural_generation_content_attempt_id_v2(
                                case["saved"].seal.original_operation_id, 2)),
                        now_utc=0.0)
            finally:
                case["graph"].release_authority_lease(
                    case["c02_case"]["case"][2], terminal_lease)
            return
        output = reader.read_original_natural_generation_output_v2(
            credential="ok", request=case["request"], now_utc=0.0)
        assert output.status == "untrusted_content_candidate"
        assert output.output_digest == canonical_digest(
            json.loads(paid_output["value"]))
        assert output.terminal_receipt_digest == canonical_digest(
            asdict(case["terminal"]))
        assert not hasattr(output, "body")

        from sylanne3.runtime.model_cost_settlement import (
            original_model_cost_operation_id_v1,
        )
        cost_id = original_model_cost_operation_id_v1(
            case["namespace"], case["saved"].seal.call_id)
        with sqlite3.connect(graph_path) as graph_db:
            graph_db.execute(
                "UPDATE graph_bundle_operations SET receipt_json=? "
                "WHERE bot=? AND persona=? AND operation_id=?",
                ("{}",) + case["namespace"].as_tuple + (cost_id,))
        next_request = replace(
            case["request"], read_attempt_id=natural_generation_output_attempt_id_v2(
                case["saved"].seal.original_operation_id, 2))
        with pytest.raises(AuthorityUnavailable, match="paid graph"):
            reader.read_original_natural_generation_output_v2(
                credential="ok", request=next_request, now_utc=0.0)
    finally:
        if 'daemon_cleanup' in locals() and daemon_cleanup is not None:
            daemon_cleanup()
        core.close()
        deletion.close()
        execution.close()
