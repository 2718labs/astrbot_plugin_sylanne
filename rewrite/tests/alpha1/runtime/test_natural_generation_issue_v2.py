"""A C02/source has exactly one paid reply workflow identity."""

import sqlite3
import json
import time
from dataclasses import asdict, replace
from types import SimpleNamespace

import pytest

from sylanne3.runtime.context_reply_job_v2 import (
    context_reply_job_ids_v2, install_schema as install_context_schema,
)
from sylanne3.runtime.natural_generation_issue_v2 import (
    NaturalGenerationIssueHold, assert_natural_reply_identity_unused_v2,
    issue_original_natural_generation_in_transaction_v2,
)
from sylanne3.runtime.natural_reply_job_v2 import (
    install_schema as install_natural_schema, read_original_preparation,
)
from sylanne3.runtime.budget import (
    BudgetLease, create_budget_lease, get_budget_lease,
    install_schema as install_budget_schema,
)
from sylanne3.runtime.jobs import get_job, install_schema as install_jobs_schema
from sylanne3.runtime.issuers import BudgetLeaseGrant
from sylanne3.domains.d08.natural_plan import (
    decode_natural_plan_v2, prepare_coordinator_natural_plan_write_v2,
)
from sylanne3.graph_types import GraphVersion
from sylanne3.model_broker.context_reply import ContextReplyPartV1
from sylanne3.model_broker.natural_reply import (
    NaturalReplyInputV2, NaturalReplyInstallationV2, TEMPLATE_VERSION,
    freeze_natural_reply_request_v2,
)
from sylanne3.model_broker.natural_review import REVIEW_TEMPLATE_VERSION
from sylanne3.authority_service.v2_contract import FencePermitV2
from sylanne3.authority_service.v2_model_egress_contract import (
    ModelAdmissionV2, ModelEgressIntentV1, ModelEgressRecoveryV1,
    ModelTerminalReceiptV2,
)
from sylanne3.runtime.reply_model_job import (
    install_schema as install_legacy_schema, reply_job_original_operation_id_v1,
)
from sylanne3.runtime_contracts import (
    AuthorityContext, NamespaceId, QueryEpoch, canonical_digest,
)
from sylanne3.runtime_contracts import VersionedRef
from tests.alpha1.d08.test_goal_execution_domain import _natural_preparation_case
from test_context_reply_prepare_v2 import (
    _context_reply_original_paid_lifecycle_case, context_reply_c02_case,
)
from test_first_ingress_c02_commit import c02_case
from test_first_encoding_cost_graph_commit import AccountingPort


@pytest.mark.parametrize("workflow", ("source_reply", "context_reply"))
def test_original_reply_identity_blocks_natural_generation_in_same_tx(workflow):
    db = sqlite3.connect(":memory:")
    db.execute("BEGIN")
    install_legacy_schema(db)
    install_context_schema(db)
    install_natural_schema(db)
    namespace = NamespaceId("bot", "persona")
    c02_operation_id, source_ref = "c02:one", "source:one"
    assert_natural_reply_identity_unused_v2(db, namespace, c02_operation_id, source_ref)
    original = (reply_job_original_operation_id_v1(c02_operation_id, source_ref)
                if workflow == "source_reply" else
                context_reply_job_ids_v2(namespace, c02_operation_id, source_ref)[1])
    table = ("graph_post_c02_reply_model_attempts_v1" if workflow == "source_reply"
             else "graph_context_reply_attempts_v2")
    db.execute(
        f"INSERT INTO {table}(bot,persona,original_operation_id,input_digest,"
        "attempt_id,anchor_json,graph_revision,graph_epoch,state) "
        "VALUES(?,?,?,?,?,?,?,?,?)",
        (*namespace.as_tuple, original, "digest", "attempt", "{}", 1, 1, "open"),
    )
    with pytest.raises(NaturalGenerationIssueHold, match="identity"):
        assert_natural_reply_identity_unused_v2(
            db, namespace, c02_operation_id, source_ref)
    db.rollback()


def test_natural_generation_reserves_original_job_and_seal_in_one_tx():
    plan, evidence, before, candidate, plan_key, _, _ = _natural_preparation_case()
    namespace = plan.namespace
    grant = BudgetLeaseGrant(
        "grant:root", 1, *namespace.as_tuple, "budget:root", "USD",
        {"tokens": 200}, ("natural_generation", "natural_review"),
        100.0, "policy:root",
    )
    from dataclasses import replace
    evidence = replace(evidence, budget_grant_digest=canonical_digest(grant))
    write, _ = prepare_coordinator_natural_plan_write_v2(
        plan=plan, evidence=evidence, snapshot=before,
        d06_candidates=(candidate,), access_epoch=2, deletion_epoch=0,
        now_utc=10.0,
    )
    adopted = decode_natural_plan_v2(write.value)
    frozen = freeze_natural_reply_request_v2(
        NaturalReplyInputV2(
            ContextReplyPartV1("question", evidence.source_ref,
                               VersionedRef(plan.audience_id, 1), 80.0,
                               "What did Alice report?"),
            plan, (), 10.0, 79.0,
        ),
        NaturalReplyInstallationV2(
            "installation", "a" * 64, "provider", "model", 256),
    )
    workflow = SimpleNamespace(
        quote_ceiling={"tokens": 100}, work_kind="natural_generation",
        purpose="proposal", template_version=TEMPLATE_VERSION,
        audiences=(plan.audience_id,), provider_id="provider", model_id="model",
        provider_config_digest="a" * 64, provider_config_ref="provider:config",
        max_output_tokens=256, timeout_seconds=10.0,
    )
    policy = SimpleNamespace(
        namespace=namespace, root_lease=SimpleNamespace(lease_id="budget:root"),
        root_grant=grant, installation_id="installation",
    )
    installed = SimpleNamespace(
        installation_policy=policy,
        model_workflows=SimpleNamespace(natural_generation=workflow),
    )
    db = sqlite3.connect(":memory:")
    install_budget_schema(db)
    install_jobs_schema(db)
    install_natural_schema(db)
    db.execute("BEGIN")
    create_budget_lease(
        db, BudgetLease("budget:root", None, *namespace.as_tuple, "USD",
                        {"tokens": 200}, {}, {}, {}, 1, "active"),
        "create:budget", "b" * 64,
    )
    d11 = SimpleNamespace(current_budget_grant=lambda db, lease_id: grant)
    quotes = []
    d02 = SimpleNamespace(issue_quote=lambda db, quote: quotes.append(quote))
    versions = (GraphVersion(plan_key, 1), *adopted.qualified_read_versions)
    mismatched = freeze_natural_reply_request_v2(
        replace(frozen.input, plan=replace(plan, final_effect_id="effect:wrong")),
        frozen.installation,
    )
    with pytest.raises(NaturalGenerationIssueHold, match="scope or budget"):
        issue_original_natural_generation_in_transaction_v2(
            db, namespace=namespace, plan=adopted, frozen=mismatched,
            read_versions=versions, query_epochs=(QueryEpoch(namespace, "all", 6),),
            graph_epoch=6, access_epoch=2, deletion_epoch=0,
            installed_bundle=installed, d02_issuer=d02, d11_issuer=d11,
            now_utc=10.0,
        )
    assert get_budget_lease(db, grant.lease_id).reserved == {}
    job, quote, _, seal = issue_original_natural_generation_in_transaction_v2(
        db, namespace=namespace, plan=adopted, frozen=frozen,
        read_versions=versions, query_epochs=(QueryEpoch(namespace, "all", 6),),
        graph_epoch=6, access_epoch=2, deletion_epoch=0,
        installed_bundle=installed, d02_issuer=d02, d11_issuer=d11, now_utc=10.0,
    )
    assert quotes == [quote]
    assert get_job(db, job.job_id) == job
    assert seal.reservation_operation_id == quote.operation_id
    assert get_budget_lease(db, grant.lease_id).reserved == {"tokens": 100}
    db.rollback()
    assert db.execute("SELECT 1 FROM runtime_jobs").fetchone() is None
    assert db.execute("SELECT 1 FROM graph_natural_generation_preparations_v2").fetchone() is None


def _natural_generation_paid_lifecycle_case(
        context_reply_c02_case, monkeypatch, *,
        paid_fact_factory=None, complete_terminal=True):
    case = _context_reply_original_paid_lifecycle_case(
        context_reply_c02_case, monkeypatch, stop_before_paid=True)
    store, graph, namespace = case["store"], case["graph"], case["namespace"]
    account_value = json.loads(store._db.execute(
        "SELECT value FROM graph_atoms WHERE type_name='d03.account_binding'").fetchone()[0])
    from d13_natural_fixture_v4 import commit_natural_fixture_inbound_turn_v4
    commit_natural_fixture_inbound_turn_v4(graph=graph, bootstrap=case["case"][2], namespace=namespace,
        source_ref=case["source_ref"], c02_operation_id=case["c02"].operation_id,
        now_utc=account_value["valid_from"] + 1.0)
    from sylanne3.model_broker.natural_reply_history_v4 import TEMPLATE_VERSION as CURRENT_TEMPLATE_VERSION
    with store._lock:
        store._db.execute("BEGIN IMMEDIATE")
        try:
            epoch = graph._v2_graph_stamp(namespace)[1]
            account = store._db.execute(
                "SELECT value FROM graph_atoms WHERE type_name='d03.account_binding'"
            ).fetchone()
            assert account is not None, "missing account binding"
            account_value = json.loads(account[0])
            now = account_value["valid_from"] + 1.0
            assert account_value["valid_until"] is None or now < account_value["valid_until"], account_value
            current = graph._current_natural_generation_inputs_locked(
                namespace, case["c02"].operation_id,
                case["source_ref"], now, epoch)
            assert current[5].status == "complete"
            assert current[7].ref in {
                version.key.token for version in current[5].read_versions}
            assert current[8].ref == current[2].binding_version.key.token
            workflow = case["installed"].model_workflows.context_reply
            natural = replace(case["installed"], model_workflows=replace(
                case["installed"].model_workflows,
                natural_generation=replace(
                    workflow, work_kind="natural_generation",
                    template_version=CURRENT_TEMPLATE_VERSION),
                natural_review=replace(
                    workflow, work_kind="natural_review",
                    template_version=REVIEW_TEMPLATE_VERSION),
            ))
            prepared = graph._prepare_natural_generation_scope_locked(
                namespace, case["c02"].operation_id,
                case["source_ref"], natural, now, epoch)
            from sylanne3.runtime.natural_scoped_query_proof_v2 import (
                assert_original_scoped_d06_projection_v2,
                natural_private_scope_from_binding_v2,
                read_natural_scoped_query_proof_v2,
            )
            scoped = read_natural_scoped_query_proof_v2(
                store._db, natural_private_scope_from_binding_v2(
                    current[2], prepared[2]), now_utc=now)
            assert_original_scoped_d06_projection_v2(scoped, prepared[2])
            assert prepared[0].key.type_name == "d08.natural_expression_plan.v2"
            assert prepared[2].input.plan.scene_ref == current[7]
            store._db.execute(
                "UPDATE graph_atoms SET valid=0 WHERE token=?", (current[7].ref,))
            with pytest.raises(Exception, match="scene role"):
                graph._current_natural_generation_inputs_locked(
                    namespace, case["c02"].operation_id,
                    case["source_ref"], now, epoch)
            store._db.execute(
                "UPDATE graph_atoms SET valid=1 WHERE token=?", (current[7].ref,))
        finally:
            if store._db.in_transaction:
                store._db.execute("ROLLBACK")
    port = case["owner_scene_case"][2]
    clock_start = time.monotonic()
    monkeypatch.setattr(port, "read_ingress_clock", lambda policy: SimpleNamespace(
        utc_upper_bound_seconds=now + time.monotonic() - clock_start,
        monotonic_after_seconds=time.monotonic()))
    with pytest.raises(Exception, match="paid consumer unavailable"):
        graph.prepare_post_c02_natural_generation_v2(
            case["case"][2], namespace, case["c02"].operation_id,
            case["source_ref"], natural)
    monkeypatch.setattr(port, "natural_paid_consumer_ready_v2",
                        lambda **kwargs: True, raising=False)
    saved = graph.prepare_post_c02_natural_generation_v2(
        case["case"][2], namespace, case["c02"].operation_id,
        case["source_ref"], natural)
    assert saved.state == "queued"
    assert store._db.execute(
        "SELECT COUNT(*) FROM graph_atoms WHERE type_name="
        "'d08.natural_expression_plan.v2' AND valid=1"
    ).fetchone() == (1,)
    assert store._db.execute(
        "SELECT COUNT(*) FROM runtime_jobs "
        "WHERE work_kind='natural_generation' AND phase='queued'"
    ).fetchone() == (1,)
    assert graph.prepare_post_c02_natural_generation_v2(
        case["case"][2], namespace, case["c02"].operation_id,
        case["source_ref"], natural) == saved
    generation = natural.model_workflows.natural_generation
    activation = graph._v2_graph_stamp(namespace)[0].requirements.activation_generation
    worker_lease, capability = graph.grant(
        case["case"][2], actor=case["case"][4].administrator_holder,
        issuer_domain="d11", namespace=namespace, domains=("d11",),
        activation_generation=activation,
        operation_id=saved.seal.acquire_operation_id)
    worker = AuthorityContext(
        case["case"][4].administrator_holder, "d11", capability,
        namespace, ("activity",), "proposal",
        (saved.frozen.input.plan.audience_id,),
        generation.provider_config_ref, activation)
    try:
        running, call = graph.acquire_post_c02_natural_generation_v2(
            worker, worker_lease, case["c02"].operation_id, natural,
            lease_seconds=60)
        assert running.phase == "running"
        assert call.call_id == saved.seal.call_id
        assert call.digest != saved.seal.model_request_digest
        from sylanne3.graph_store import GraphStore
        from sylanne3.graph_types import GraphCandidate, GraphWrite
        from sylanne3.contracts import Event, Scope
        from sylanne3.memory_types import SourceRecord, source_key
        with store._lock:
            store._db.execute("BEGIN IMMEDIATE")
            try:
                unrelated = source_key(*namespace.as_tuple, "unrelated-natural-test")
                original_source = store._db.execute(
                    "SELECT value FROM graph_atoms WHERE token=?",
                    (case["source_ref"],),
                ).fetchone()
                value = replace(
                    SourceRecord.from_dict(json.loads(original_source[0])),
                    source_id="unrelated-natural-test").to_dict()
                metadata, prior_epoch = graph._v2_graph_stamp(namespace)
                receipt = GraphStore._graph_commit_in_transaction(
                    store, GraphCandidate(
                        Event(Scope(*namespace.as_tuple, "unrelated-natural-test"),
                              "unrelated-natural-test", now, "domain_bundle", {}),
                        (GraphVersion(unrelated, 0),),
                        (GraphWrite(unrelated, value),), (prior_epoch,)),
                    _capability=graph._GraphCoordinator__graph_capability)
                assert receipt.status == "committed"
                store.cas_graph_recovery_metadata(
                    metadata, metadata.requirements,
                    _capability=graph._GraphCoordinator__graph_capability)
                store._db.execute("COMMIT")
            except BaseException:
                store._db.execute("ROLLBACK")
                raise
        prepared_call, draft, anchor = (
            graph.read_natural_model_egress_preparation_v2(
                replace(worker, worker_fence=running.fence), worker_lease,
                case["c02"].operation_id, "generation", natural))
        assert prepared_call == call
        assert draft.request_digest == call.digest
        assert draft.budget_reservation_operation_id == (
            saved.seal.reservation_operation_id)
        assert anchor is not None
        proof_row = store._db.execute(
            "SELECT proof_json FROM graph_natural_generation_scopes_v2 "
            "WHERE bot=? AND persona=? AND parent_original_id=?",
            namespace.as_tuple + (case["c02"].operation_id,),
        ).fetchone()
        assert proof_row is not None
        store._db.execute(
            "UPDATE graph_natural_generation_scopes_v2 SET proof_json='{}' "
            "WHERE bot=? AND persona=? AND parent_original_id=?",
            namespace.as_tuple + (case["c02"].operation_id,),
        )
        store._db.commit()
        with pytest.raises(Exception):
            graph.read_natural_model_egress_preparation_v2(
                replace(worker, worker_fence=running.fence), worker_lease,
                case["c02"].operation_id, "generation", natural)
        store._db.execute(
            "UPDATE graph_natural_generation_scopes_v2 SET proof_json=? "
            "WHERE bot=? AND persona=? AND parent_original_id=?",
            (proof_row[0],) + namespace.as_tuple + (case["c02"].operation_id,),
        )
        store._db.commit()
        access_token = store._db.execute(
            "SELECT token FROM graph_atoms WHERE type_name='memory.access'"
        ).fetchone()[0]
        store._db.execute(
            "UPDATE graph_atoms SET valid=0 WHERE token=?", (access_token,))
        store._db.commit()
        with pytest.raises(Exception):
            graph.read_natural_model_egress_preparation_v2(
                replace(worker, worker_fence=running.fence), worker_lease,
                case["c02"].operation_id, "generation", natural)
        store._db.execute(
            "UPDATE graph_atoms SET valid=1 WHERE token=?", (access_token,))
        store._db.commit()
        if paid_fact_factory is None:
            intent = ModelEgressIntentV1(
                **asdict(draft), fence_token="m" * 32,
                fence_epoch=1, fence_revision=0,
                anchor_digest=canonical_digest(asdict(anchor)))
            observed = ModelEgressRecoveryV1(
                intent, "observed", "e" * 64, (("output_tokens", 1),), ())
            admission = ModelAdmissionV2(
                "f" * 64, draft.authority_id, draft.namespace,
                draft.subject, draft.operation_id, draft.call_id,
                draft.request_digest, draft.provider_config_digest,
                saved.seal.installation_id, "1" * 64,
                "observer", "2" * 64, "3" * 64)
            terminal = ModelTerminalReceiptV2(
                admission.admission_id, draft.call_id, draft.request_digest,
                "4" * 64, observed.observation_digest, "sha256:" + "5" * 64,
                saved.seal.installation_id, "3" * 64)
            permit = FencePermitV2(
                draft.authority_id, draft.namespace, draft.subject,
                "holder", 1, "model_egress", draft.operation_id,
                intent.fence_token, 1, 0, anchor)
            fact = (observed, permit, admission, terminal)
        else:
            intent, fact = paid_fact_factory(
                case, saved, running, call, draft, anchor, natural)
            observed, permit, admission, terminal = fact
        graph._GraphCoordinator__model_terminal_cost_port = lambda actual: (
            fact if actual == intent else None)
        graph._GraphCoordinator__accounting_maintenance_port = (
            AccountingPort(store, fact))
        quote_id, quote_version = running.operator_versions[
            "resource_quote"].rsplit(":", 1)
        cost = graph.commit_natural_generation_model_cost_v2(
            case["case"][2], namespace, intent,
            quote_id=quote_id, quote_version=int(quote_version))
        assert cost.status == "committed"
        with pytest.raises(Exception, match="identity differs"):
            graph.commit_context_reply_model_cost_v2(
                case["case"][2], namespace, intent,
                quote_id=quote_id, quote_version=int(quote_version))
        output_request = graph.read_natural_generation_output_request_v2(
            replace(worker, worker_fence=running.fence), worker_lease,
            case["c02"].operation_id, natural)
        assert output_request.original_operation_id == saved.seal.original_operation_id
        assert output_request.typed_model_request_digest == call.digest
        assert output_request.call_id == saved.seal.call_id
        result = {
            "store": store, "graph": graph, "namespace": namespace,
            "saved": saved, "call": call, "intent": intent,
            "terminal": terminal, "fact": fact, "installed": natural,
            "request": output_request,
            "owner_scene_case": case["owner_scene_case"],
            "c02_case": case,
        }
        if not complete_terminal:
            return result
        from sylanne3.authority_service.v2_natural_generation_output_contract import (
            NaturalGenerationOriginalOutputV2,
        )
        output_reads = []
        def original_output(request, *, now_utc):
            output_reads.append(request.read_attempt_id)
            return NaturalGenerationOriginalOutputV2(
                request, canonical_digest(asdict(saved.seal)), call.digest,
                canonical_digest(asdict(intent)),
                canonical_digest(asdict(terminal)),
                observed.observation_digest, "9" * 64,
                "untrusted_content_candidate")
        graph._GraphCoordinator__natural_generation_output_port = original_output
        terminal_operation = "natural-generation-terminal-" + canonical_digest({
            "namespace": namespace.as_tuple,
            "original_operation_id": saved.seal.original_operation_id,
        })[:48]
        terminal_lease, terminal_capability = graph.grant(
            case["case"][2], actor=case["case"][4].administrator_holder,
            issuer_domain="d11", namespace=namespace, domains=("d11",),
            activation_generation=activation,
            operation_id=terminal_operation)
        terminal_authority = replace(
            worker, capability_ref=terminal_capability, worker_fence=None)
        try:
            valid_output_port = graph._GraphCoordinator__natural_generation_output_port
            graph._GraphCoordinator__natural_generation_output_port = (
                lambda request, *, now_utc: replace(
                    valid_output_port(request, now_utc=now_utc),
                    original_seal_digest="8" * 64))
            with pytest.raises(Exception, match="paid original differs"):
                graph.complete_natural_generation_model_job_v2(
                    terminal_authority, terminal_lease,
                    case["c02"].operation_id, intent, natural)
            assert get_job(store._db, saved.seal.job_id).phase == "running"
            graph._GraphCoordinator__natural_generation_output_port = valid_output_port
            original_begin = port.begin_fence
            missed_begin = []
            def lose_terminal_begin_once(**kwargs):
                if (kwargs["operation_id"].startswith(
                        "natural-generation-terminal-write-")
                        and not missed_begin):
                    missed_begin.append(kwargs["operation_id"])
                    raise RuntimeError("terminal begin unknown")
                return original_begin(**kwargs)
            monkeypatch.setattr(port, "begin_fence", lose_terminal_begin_once)
            with pytest.raises(Exception, match="terminal begin unknown"):
                graph.complete_natural_generation_model_job_v2(
                    terminal_authority, terminal_lease,
                    case["c02"].operation_id, intent, natural)
            assert get_job(store._db, saved.seal.job_id).phase == "running"
            monkeypatch.setattr(port, "begin_fence", original_begin)
            original_finish = port.finish_fence
            lost_finish = []
            def drop_terminal_finish_once(scope, *, request_id, request_digest):
                if (request_id.startswith(
                        "finish:natural-generation-terminal-write-")
                        and not lost_finish):
                    lost_finish.append(request_id)
                    raise RuntimeError("lost terminal finish ACK")
                return original_finish(
                    scope, request_id=request_id,
                    request_digest=request_digest)
            monkeypatch.setattr(port, "finish_fence", drop_terminal_finish_once)
            with pytest.raises(RuntimeError, match="lost terminal finish ACK"):
                graph.complete_natural_generation_model_job_v2(
                    terminal_authority, terminal_lease,
                    case["c02"].operation_id, intent, natural)
            assert get_job(store._db, saved.seal.job_id).phase == "completed"
            finished = graph.complete_natural_generation_model_job_v2(
                terminal_authority, terminal_lease,
                case["c02"].operation_id, intent, natural)
            assert finished.phase == "completed"
            assert graph.complete_natural_generation_model_job_v2(
                terminal_authority, terminal_lease,
                case["c02"].operation_id, intent, natural) == finished
            assert len(output_reads) == 2  # forged result, then one accepted selector
            assert graph.read_natural_generation_terminal_receipt_v2(
                terminal_authority, terminal_lease,
                case["c02"].operation_id, natural).output_digest == "9" * 64
            content_request = graph.read_natural_generation_content_request_v2(
                terminal_authority, terminal_lease,
                case["c02"].operation_id, natural)
            assert content_request.output_digest == "9" * 64
            assert content_request.purpose == "review"
            assert content_request.read_attempt_id != output_request.read_attempt_id
            row = store._db.execute(
                "SELECT output_receipt_json FROM graph_natural_generation_terminals_v2 "
                "WHERE bot=? AND persona=? AND original_operation_id=?",
                namespace.as_tuple + (saved.seal.original_operation_id,),
            ).fetchone()
            no_reply = json.loads(row[0])
            no_reply["status"] = "no_reply_hold"
            store._db.execute(
                "UPDATE graph_natural_generation_terminals_v2 "
                "SET output_receipt_json=? WHERE bot=? AND persona=? "
                "AND original_operation_id=?",
                (json.dumps(no_reply, sort_keys=True, separators=(",", ":")),)
                + namespace.as_tuple + (saved.seal.original_operation_id,),
            )
            store._db.commit()
            with pytest.raises(Exception, match="scope changed"):
                graph.read_natural_generation_content_request_v2(
                    terminal_authority, terminal_lease,
                    case["c02"].operation_id, natural)
            store._db.execute(
                "UPDATE graph_natural_generation_terminals_v2 "
                "SET output_receipt_json=? WHERE bot=? AND persona=? "
                "AND original_operation_id=?",
                (row[0],) + namespace.as_tuple
                + (saved.seal.original_operation_id,),
            )
            store._db.commit()
            with store._lock:
                store._db.execute("BEGIN")
                try:
                    terminal_saved = read_original_preparation(
                        store._db, namespace, case["c02"].operation_id,
                        "generation")
                    assert terminal_saved.state == "terminal"
                    assert terminal_saved.terminal_output_digest == "9" * 64
                finally:
                    store._db.execute("ROLLBACK")
        finally:
            graph.release_authority_lease(case["case"][2], terminal_lease)
        return result
    finally:
        graph.release_authority_lease(case["case"][2], worker_lease)


def test_coordinator_natural_current_read_requires_live_unique_scene_role(
        context_reply_c02_case, monkeypatch):
    _natural_generation_paid_lifecycle_case(context_reply_c02_case, monkeypatch)
