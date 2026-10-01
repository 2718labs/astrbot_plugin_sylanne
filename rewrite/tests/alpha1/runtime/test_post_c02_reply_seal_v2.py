"""Mechanical K03 seal probe using a real C02/D03/attention/quote graph.

The expression and Authority effect facts below are synthetic fixtures.  This
probe can expose transaction and issuer mismatches but cannot qualify a real
reply or confer permission to send.
"""

from dataclasses import replace
import time
import pytest

from sylanne3.authority_service.v2_contract import (
    AuthorityCurrentEffectSnapshotV2, canonical_digest as authority_digest,
)
from sylanne3.authority_service.v2_execution_bridge import CurrentEffectReadV2
from sylanne3.domains.d09 import (
    ClaimKind, ClaimUse, D09ExpressionProvider, ExpressionClaim, SegmentCandidate,
    SourceReplyExpressionV1, segment_payload_digest,
)
from sylanne3.host.authority_profile import AdminPrivateReplyDispatchPolicy
from sylanne3.host.v2_fence_port import VerifiedIngressClockV2
from sylanne3.authority_service.v2_clock import IngressClockSampleV2
from sylanne3.runtime.first_ingress_v2 import trusted_upper
from sylanne3.host.post_c02_reply_driver import post_c02_reply_operation_id
from sylanne3.runtime.budget import reserve_budget
from sylanne3.runtime.jobs import create_job
from sylanne3.runtime.post_c02_reply_bundle_v2 import (
    post_c02_dispatch_runtime_refs_v2,
    prepare_post_c02_reply_bundle_candidate_v2,
)
from sylanne3.runtime.installed_dispatch_admission_issuer import (
    InstalledDispatchAdmissionIssuer,
)
from sylanne3.runtime_contracts import (
    AuthorityContext, CommandEnvelope, FenceScope, OperationIdentity,
    RUNTIME_SCHEMA, VersionedRef, canonical_digest,
)
from sylanne3.graph_coordinator import UnavailableGuard, budget_operation_digest
from sylanne3.domains.d08 import GoalExecutionProvider

from test_reply_entity_route_v2 import (
    canonical_private_case, _prepare_canonical_reply_job, _read,
)
from test_post_c02_reply_model_job_v1 import private_reply_c02_case
from test_first_ingress_c02_commit import c02_case


def _durable_counts(db):
    tables = (
        "graph_events", "graph_atoms", "graph_dispatch_admissions",
        "runtime_jobs", "graph_bundle_outbox", "graph_outbox_jobs",
    )
    existing = {row[0] for row in db.execute(
        "SELECT name FROM sqlite_master WHERE type='table'")}
    return {name: (db.execute(f"SELECT COUNT(*) FROM {name}").fetchone()[0]
                   if name in existing else None)
            for name in tables}


@pytest.mark.parametrize("expired", (False, True))
def test_canonical_private_reply_seal_rechecks_clock_and_rolls_back(
        canonical_private_case, monkeypatch, expired):
    (store, graph, namespace, seal, source_ref, installed, _, c02,
     attention_envelope) = _prepare_canonical_reply_job(
         canonical_private_case, monkeypatch)
    context = graph._GraphCoordinator__providers["d03"][0]
    graph._GraphCoordinator__dispatch_admission_issuer = (
        InstalledDispatchAdmissionIssuer(
            context=context,
            d11_issuer=graph._GraphCoordinator__d11_issuer,
            d02_issuer=graph._GraphCoordinator__d02_issuer))
    policy = AdminPrivateReplyDispatchPolicy(
        30.0, {"cpu_ms": 1}, "k03-snapshot", "k03-resource", 800, 15.0)
    operation_id = post_c02_reply_operation_id(
        seal.consumer_operation_id, source_ref)
    for domain, provider, schema in (
            ("d08", GoalExecutionProvider(), "d08.proposal.v1"),
            ("d09", D09ExpressionProvider(), "d09.proposal.v1")):
        if domain not in graph._GraphCoordinator__providers:
            graph.register_provider(
                canonical_private_case[2], domain, provider, schema,
                provider.descriptor.request_schema_hash)
    actor = canonical_private_case[4].administrator_holder
    port = graph._GraphCoordinator__content_fence_v2
    with store._lock:
        metadata, epoch = graph._v2_graph_stamp(namespace)
    anchor = port.anchors[namespace]
    lease, capability = graph.grant(
        canonical_private_case[2], actor=actor, issuer_domain="d11",
        namespace=namespace, domains=("d08", "d09", "d11"),
        activation_generation=anchor.activation_generation,
        operation_id=operation_id)
    attempt_id = "k03-seal-mechanical-attempt"
    permit = port.begin_fence(
        namespace=namespace, authority_namespace=anchor.namespace,
        holder=actor, generation=anchor.activation_generation,
        operation="write", operation_id=attempt_id, expected_anchor=anchor)
    scope = FenceScope(
        namespace, anchor.namespace, anchor.activation_generation,
        "write", attempt_id, permit, anchor, epoch, metadata.graph_revision)
    now = time.time()
    with store._lock:
        before = _durable_counts(store._db)
        store._db.execute("BEGIN IMMEDIATE")
        try:
            route, _ = _read(graph, store, namespace, c02, source_ref,
                             product_route=True)
            snapshot, query = graph._dispatch_full_graph_snapshot_locked(namespace)
            inputs, assert_route = graph._current_post_c02_reply_route_locked(
                namespace, c02.operation_id, source_ref, now,
                snapshot.epochs[0])
            assert assert_route == route
            identity = OperationIdentity(
                c02.activity_id, "effect:k03-seal-mechanical",
                "attempt:k03-seal-mechanical", "post_c02_reply_dispatch",
                operation_id, canonical_digest({"input_refs": [source_ref]}))
            job_ref, outbox_ref, _ = post_c02_dispatch_runtime_refs_v2(
                namespace, identity)
            grant = canonical_private_case[4].root_grant
            quote = graph._GraphCoordinator__d11_issuer.issue_private_reply_dispatch_quote_v2(
                store._db, policy=policy, namespace=namespace,
                identity=identity, parent_grant=grant,
                deadline_utc=now + 10, graph_job_ref=job_ref,
                outbox_refs=(outbox_ref,), now_utc=now)
            store._db.execute(
                "INSERT INTO graph_guard_versions(bot,persona,kind,ref,version) "
                "VALUES(?,?,?,?,?)",
                namespace.as_tuple + (
                    "resource_lease", quote.quote_id, str(quote.version)),
            )
            envelope = CommandEnvelope(
                RUNTIME_SCHEMA, identity,
                AuthorityContext(
                    actor, "d11", capability, namespace,
                    ("activity", "persona"), "expression",
                    (route.conversation_ref,), grant.policy_ref,
                    anchor.activation_generation),
                replace(attention_envelope.version_guard,
                        read_versions=snapshot.versions,
                        query_epochs=(query,),
                        resource_lease_versions=(VersionedRef(
                            quote.quote_id, quote.version),)),
                attention_envelope.source_qualification,
                (source_ref,), grant.lease_id, quote.deadline_utc,
                time.monotonic() + 10, "interval", (c02.operation_id,))
            reserve_budget(store._db, grant.lease_id, operation_id,
                           budget_operation_digest(
                               envelope, grant.lease_id, dict(quote.ceiling)),
                           quote.ceiling)
            job = replace(graph._GraphCoordinator__d11_issuer.job_for(
                envelope, store._db, now_utc=now), phase="waiting",
                wake_condition={
                    "kind": "post_c02_reply_host_takeover",
                    "operation_id": operation_id})
            create_job(store._db, job, "fixture-k03-seal-job",
                       canonical_digest(job))
            body = inputs.source.source.text
            claim = ExpressionClaim(
                "claim:k03-seal", body, ClaimKind.REPORTED_CLAIM,
                (source_ref,), (route.conversation_ref,), ("expression",),
                source_ref)
            use = ClaimUse(claim.claim_id, 0, len(body),
                           ClaimKind.REPORTED_CLAIM)
            segment = SegmentCandidate(
                "segment:" + "b" * 64, identity.effect_id, body,
                (use,), ("reply",), (), 0.0)
            expression = SourceReplyExpressionV1(
                (claim,), (segment,), segment_payload_digest(
                    body, (), (use,)), "b" * 64, "c" * 64, "d" * 64)
            effect_snapshot = AuthorityCurrentEffectSnapshotV2(
                anchor.authority_id, anchor.namespace, anchor,
                authority_digest(permit), anchor.execution_seq,
                anchor.execution_digest, "complete", ())
            current_effect = CurrentEffectReadV2(
                anchor.authority_id, anchor.namespace, identity.effect_id,
                anchor.activation_generation, "absent", anchor.execution_seq,
                anchor.execution_digest)
            staged = graph._stage_post_c02_reply_prebatch_locked(
                envelope=envelope, c02_receipt=c02, route=route,
                source_ref=source_ref, attention=inputs.attention.ticket,
                focus=inputs.attention.focus, budget_grant=grant,
                resource_quote=quote, expression=expression, anchor=anchor,
                scope=scope, current_effect=current_effect,
                effect_snapshot=effect_snapshot, now_utc=now)
            (staged_envelope, staged_d08, action, _, checks, _,
             staged_binding, route_grant) = staged
            bundle_candidate = prepare_post_c02_reply_bundle_candidate_v2(
                envelope=staged_envelope, action=action,
                staged_d08=staged_d08, checks=checks.checks,
                expression=expression, route=route,
                route_binding=staged_binding,
                pre_frozen_grant=route_grant, quote=quote,
                budget_grant=grant, pre_reserved_job=job,
                now_utc=now, conversation_epoch=query.revision + 1)
            prepared = (inputs, route, envelope, expression, grant, quote,
                        job, staged, bundle_candidate)
            # The inherited legacy port fixture exposes an untyped clock.
            # This typed sample is synthetic and tests only the seal mechanics.
            clock_monotonic = time.monotonic()
            clock_utc = (quote.deadline_utc + 1.0 if expired
                         else time.time() + 0.2)
            clock_reading = VerifiedIngressClockV2(
                IngressClockSampleV2(
                    anchor.authority_id,
                    canonical_private_case[4].installation_id,
                    canonical_private_case[5].source_id,
                    clock_utc - 0.1, clock_monotonic,
                    "fixture-clock-epoch", 0.1),
                clock_monotonic - 0.01, clock_monotonic,
                clock_utc)
            assert trusted_upper(clock_reading) > now
            if expired:
                assert trusted_upper(clock_reading) >= quote.deadline_utc
            with pytest.raises(
                    UnavailableGuard,
                    match=("final dispatch clock or check expired" if expired
                           else "trusted dispatch admission fence evidence unavailable")):
                graph._seal_post_c02_reply_dispatch_locked(
                    lease=lease, scope=scope, metadata=metadata,
                    clock_reading=clock_reading, owner_guard=None,
                    current_effect=current_effect,
                    effect_snapshot=effect_snapshot, now_utc=now,
                    prepared=prepared, finish_id="fixture-k03-finish",
                    finish_digest=canonical_digest({
                        "operation_id": operation_id}))
        finally:
            store._db.execute("ROLLBACK")
        assert _durable_counts(store._db) == before
