"""V2 graph job, real Authority model ledger, and current result read."""

from dataclasses import replace
from pathlib import Path
import asyncio
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
from test_context_reply_prepare_v2 import (
    _context_reply_original_paid_lifecycle_case, context_reply_c02_case,
)
from test_scene_binding_v2 import _session

from sylanne3.authority_service.contract import AuthorityUnavailable, JournalHead
from sylanne3.authority_service.core import AuthorityServiceCore
from sylanne3.authority_service.current_context_reply_original_verifier import (
    PinnedCurrentContextReplyOriginalVerifier,
)
from sylanne3.authority_service.current_model_egress_graph_verifier import (
    PinnedCurrentModelEgressGraphVerifier,
)
from sylanne3.authority_service.v2_context_reply_result_service import (
    AuthorityV2ContextReplyResultReadService,
)
from sylanne3.authority_service.v2_context_reply_result_contract import (
    context_reply_read_attempt_id_v1,
)
from sylanne3.authority_service.v2_deletion_guard import AuthorityV2DeletionGuard
from sylanne3.authority_service.v2_execution_journal import (
    AuthorityV2ExecutionJournal,
)
from sylanne3.authority_service.v2_fence_service import AuthorityV2FenceService
from sylanne3.authority_service.v2_fence_store import AuthorityV2FenceStore
from sylanne3.authority_service.v2_model_egress_contract import (
    HostObservedModelCompletionV2,
)
from sylanne3.authority_service.v2_model_egress_service import (
    AuthorityV2ModelEgressService,
)
from sylanne3.authority_service.v2_model_egress_store import (
    AuthorityV2ModelEgressStore,
)
from sylanne3.model_broker.context_reply import OUTPUT_SCHEMA
from sylanne3.domains.d06.source_access_revocation import SourceAccessRevocationRequest
from sylanne3.graph_types import AtomKey
from sylanne3.runtime.context_reply_job_v2 import (
    read_original_context_reply_call_binding_v2,
    read_original_context_reply_preparation_v2,
)
from sylanne3.runtime.jobs import get_job
from sylanne3.runtime_context import (
    AcquiredPostC02ContextReplyModelV2, RuntimeContext,
)
from sylanne3.runtime.deletion import DeletionJournal
from sylanne3.runtime_contracts import canonical_serialize


def test_settled_graph_call_reads_real_authority_observation_and_rejects_revoke(
        request, tmp_path, monkeypatch):
    authority_namespace = "opaque:persona"
    deletion = DeletionJournal(tmp_path / "real-deletion.db", create=True)
    guard = AuthorityV2DeletionGuard(tmp_path / "real-deletion.db")
    execution = AuthorityV2ExecutionJournal(
        tmp_path / "real-execution.db", namespace=authority_namespace,
        journal_id="real-execution", create=True)
    head = deletion.latest_head()
    deletion_head = JournalHead(head.journal_id, head.seq, head.chain_digest)
    # The existing graph fixture's Owner operation pins this identifier.
    # Only the core's UUID source is deterministic; its journals, nonce,
    # fences and model ledger remain real Authority state-machine writes.
    with monkeypatch.context() as seeded_id:
        seeded_id.setattr(
            "sylanne3.authority_service.core.uuid.uuid4",
            lambda: "authority")
        core = AuthorityServiceCore(
            tmp_path / "real-authority.db", create=True,
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
            core=core,
            fences=AuthorityV2FenceStore(core._db, create=True, lock=core._lock),
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
        graph_case = request.getfixturevalue("context_reply_c02_case")

        def paid_fact_factory(*, draft, anchor, saved, graph, store,
                              installed, **_):
            assert anchor == original_anchor
            graph_path = store._db.execute("PRAGMA database_list").fetchone()[2]
            now = saved.frozen_request.input.frozen_at_utc + 1.0
            verifier = PinnedCurrentModelEgressGraphVerifier(
                graph_path,
                d11_issuer=graph._GraphCoordinator__d11_issuer,
                trusted_now_utc=lambda: now,
                trusted_paired_clock=lambda: (now, "real-ledger-test-clock"),
            )
            authority_store = AuthorityV2ModelEgressStore(
                core._db, create=True, lock=core._lock)
            egress = AuthorityV2ModelEgressService(
                authority_store, fences, graph_verifier=verifier,
                admin_model_policy=installed.model_workflows)
            with sqlite3.connect(graph_path) as db:
                db.execute("BEGIN")
                original = read_original_context_reply_preparation_v2(
                    db, saved.seal.namespace, saved.seal.c02_operation_id,
                    saved.seal.source_ref)
                call = read_original_context_reply_call_binding_v2(
                    db, original).model_call_request
                db.execute("ROLLBACK")
            prepared, permit = egress.prepare_fenced(
                credential="ok", subject=draft.subject,
                holder="administrator", draft=draft, expected_anchor=anchor,
                installation_id=saved.seal.installation_id)
            intent = prepared.intent
            _, observed_permit, admission = egress.admit_dispatch_once_v2(
                credential="ok", subject=draft.subject,
                holder="administrator", intent=intent,
                expected_anchor=anchor, request=call,
                installation_id=saved.seal.installation_id,
                observer_peer_sha256="1" * 64,
                observer_profile_id="real-observer",
                manifest_digest="2" * 64,
                host_incarnation="3" * 64)
            assert observed_permit == permit
            evidence = saved.frozen_request.input.evidence[0]
            body = evidence.text
            output = canonical_serialize({
                "schema": OUTPUT_SCHEMA, "body": body,
                "spans": [{
                    "start": 0, "end": len(body),
                    "source_ref": evidence.ref.ref,
                    "source_revision": evidence.ref.version,
                    "access_ref": evidence.access_ref.ref,
                    "access_revision": evidence.access_ref.version,
                    "source_quote": body,
                }],
            })
            report = HostObservedModelCompletionV2(
                admission.admission_id, admission.host_incarnation,
                intent.call_id, intent.request_digest,
                intent.provider_id, intent.model_id,
                intent.provider_config_digest,
                canonical_serialize({"text": output}),
                (("output_tokens", 1),), (), "controlled-provider-call")
            observed, finished_permit, terminal = egress.complete_observed_v2(
                credential="ok", subject=draft.subject,
                holder="administrator", intent=intent,
                expected_anchor=anchor, admission=admission,
                report=report, installation_id=saved.seal.installation_id,
                observer_peer_sha256="1" * 64,
                observer_profile_id="real-observer",
                manifest_digest="2" * 64)
            assert finished_permit == permit
            assert egress.recover_fenced(
                credential="ok", subject=draft.subject,
                intent=intent)[0] == observed
            return intent, (observed, permit, admission, terminal)

        case = _context_reply_original_paid_lifecycle_case(
            graph_case, monkeypatch, paid_fact_factory=paid_fact_factory)
        graph_path = case["store"]._db.execute(
            "PRAGMA database_list").fetchone()[2]
        # Exercise the plugin runtime's idempotent settlement/recovery path
        # against the same original graph job and real Authority fact.
        with sqlite3.connect(graph_path) as db:
            db.execute("BEGIN")
            saved = read_original_context_reply_preparation_v2(
                db, case["namespace"], case["c02"].operation_id,
                case["source_ref"])
            call = read_original_context_reply_call_binding_v2(
                db, saved).model_call_request
            db.execute("ROLLBACK")

        class GraphWorkerInline:
            async def call(self, callback):
                return callback(case["graph"])

        runtime = object.__new__(RuntimeContext)
        runtime._worker = GraphWorkerInline()
        runtime._v2_model_bundle = case["installed"]
        runtime._v2_policy = case["case"][4]
        runtime._v2_installation_grant = (
            case["owner_scene_case"][2].installation_grant)
        runtime._v2_bootstrap = case["case"][2]
        runtime._v2_port = case["owner_scene_case"][2]
        runtime._v2_namespace_provisioned = True
        acquired = AcquiredPostC02ContextReplyModelV2(
            call.envelope.authority, object(), saved,
            get_job(case["store"]._db, saved.seal.job_id), call)
        recovered = asyncio.run(runtime.settle_post_c02_context_reply_model_v2(
            acquired, case["intent"], case["terminal"]))
        assert recovered is not None
        assert recovered[0].status == "duplicate"
        assert recovered[1] == case["result_request"]
        result_reader = AuthorityV2ContextReplyResultReadService(
            store=AuthorityV2ModelEgressStore(
                core._db, create=True, lock=core._lock),
            fences=fences,
            graph_verifier=PinnedCurrentContextReplyOriginalVerifier(graph_path),
            installation_id=case["saved"].seal.installation_id,
            read_subject=case["intent"].subject, holder="administrator",
            trusted_now_utc=lambda:
                case["saved"].frozen_request.input.frozen_at_utc + 1.0)
        result_request = case["result_request"]
        delivered = result_reader.prepare(
            credential="ok", request=result_request,
            now_utc=case["saved"].frozen_request.input.frozen_at_utc + 1.0)
        assert delivered.result.status == "paid_current_source_verified_hold"
        assert delivered.result.provider_observation.provider_call_ref == (
            "controlled-provider-call")
        result_reader.finish_delivery(credential="ok", delivery=delivered)
        core.close()
        core = AuthorityServiceCore(
            tmp_path / "real-authority.db", create=False,
            authorizer=lambda credential, *_: credential == "ok",
            deletion_verifier=lambda _ns, _before, current, phase:
                current == deletion_head and phase == "clear",
            execution_verifier=lambda _ns, _before, current, _phase:
                current == execution.verified_head(),
            effect_verifier=lambda *_: True,
            dispatch_verifier=lambda *_: True,
        )
        fences = AuthorityV2FenceService(
            core=core,
            fences=AuthorityV2FenceStore(core._db, create=False,
                                        lock=core._lock),
            deletion=guard, execution=execution, namespace=authority_namespace)
        result_reader = AuthorityV2ContextReplyResultReadService(
            store=AuthorityV2ModelEgressStore(
                core._db, create=False, lock=core._lock),
            fences=fences,
            graph_verifier=PinnedCurrentContextReplyOriginalVerifier(graph_path),
            installation_id=case["saved"].seal.installation_id,
            read_subject=case["intent"].subject, holder="administrator",
            trusted_now_utc=lambda:
                case["saved"].frozen_request.input.frozen_at_utc + 1.0)
        second_request = replace(
            result_request,
            read_attempt_id=context_reply_read_attempt_id_v1(
                case["saved"].seal.original_operation_id, 2))
        restarted = result_reader.prepare(
            credential="ok", request=second_request,
            now_utc=case["saved"].frozen_request.input.frozen_at_utc + 1.0)
        assert restarted.result.provider_observation == (
            delivered.result.provider_observation)
        result_reader.finish_delivery(credential="ok", delivery=restarted)
        original_case = case["owner_scene_case"]
        token, owner_request = _session(original_case)
        owner, owner_lease, _ = case["graph"].grant_current_owner(
            case["case"][2], actor="paired-owner", namespace=case["namespace"],
            domains=("d06", "d11"), purpose="audit", audience="owner",
            activation_generation=case["anchor"].activation_generation,
            owner_session_token=token, owner_session_request=owner_request)
        try:
            source_id = AtomKey.from_token(
                case["saved"].frozen_request.input.evidence[0].ref.ref).owner.subject
            access_ref = case["saved"].frozen_request.input.evidence[0].access_ref.ref
            access = json.loads(case["store"]._db.execute(
                "SELECT value FROM graph_atoms WHERE token=?", (access_ref,)
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
                        source_id, "paired-owner", str(uuid4()), recorded_at))
            assert revoked.source_id == source_id
        finally:
            case["graph"].release_current_owner_lease(case["case"][2], owner_lease)
        with pytest.raises(AuthorityUnavailable):
            result_reader.prepare(
                credential="ok", request=replace(
                    result_request, read_attempt_id=
                    context_reply_read_attempt_id_v1(
                        case["saved"].seal.original_operation_id, 3)),
                now_utc=case["saved"].frozen_request.input.frozen_at_utc + 1.0)
    finally:
        core.close()
        deletion.close()
        guard.close()
        execution.close()
