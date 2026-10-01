"""A real C02 and D03 arrival identify one current private account entity."""

from dataclasses import replace
import json
import time

import pytest

from sylanne3.graph_types import AtomKey, GraphCandidate, Owner
from sylanne3.contracts import Event, EventConflict, Scope
from sylanne3.host.current_scene import CurrentHostScene
from sylanne3.host.identity import astrbot_namespace
from sylanne3.memory_types import SourceRecord, access_key, source_key
from sylanne3.model_broker.reply_language import ReplySourceSnapshot
from sylanne3.runtime.reply_entity_route_v2 import (
    ReplyEntityRouteHold, read_current_reply_entity_route_binding_v2,
)
from sylanne3.runtime.reply_model_job import (
    CurrentReplyModelInputsV1, CurrentReplyRouteManifestV2,
    read_current_reply_route_manifest_v2,
)
from sylanne3.runtime.first_ingress_v2 import scene_ref_for_conversation
from sylanne3.runtime_contracts import canonical_digest, canonical_serialize

from test_post_c02_reply_model_job_v1 import private_reply_c02_case
from test_first_ingress_c02_commit import c02_case
from sylanne3.host.authority_profile import AdminD06FirstIngressC02Policy
from sylanne3.host.authority_profile import (
    AdminInstallationBundle, AdminD07AttentionPolicy,
)
from sylanne3.host.post_c02_attention_driver import (
    post_c02_attention_operation_id, prepare_post_c02_attention_v1,
)
from sylanne3.runtime.first_ingress_v2 import trusted_upper
from sylanne3.runtime_contracts import AuthorityContext
from sylanne3.runtime_contracts import (
    OperationIdentity, QueryEpoch, FenceScope, VersionedRef,
)
from sylanne3.graph_coordinator import UnavailableGuard, budget_operation_digest
from sylanne3.authority_service.v2_contract import (
    AuthorityCurrentEffectSnapshotV2, canonical_digest as authority_digest,
)
from sylanne3.authority_service.v2_execution_bridge import CurrentEffectReadV2
from sylanne3.runtime_contracts import CommandEnvelope, RUNTIME_SCHEMA, VersionGuard
from sylanne3.domains.d09 import (
    ClaimKind, ClaimUse, D09ExpressionProvider, ExpressionClaim, SegmentCandidate,
    SourceReplyExpressionV1, segment_payload_digest,
)
from sylanne3.domains.d08 import GoalExecutionProvider
from sylanne3.domains.d08 import ActionSchemaRecord
from sylanne3.domains.d03.prebatch_social import issue_prebatch_private_social_v1
from sylanne3.runtime.post_c02_reply_action_v2 import (
    prepare_post_c02_reply_action_provisional_v2,
    issue_post_c02_reply_action_v2,
)
from sylanne3.runtime.budget import reserve_budget
from sylanne3.runtime.jobs import create_job
from sylanne3.runtime.post_c02_reply_bundle_v2 import (
    post_c02_dispatch_runtime_refs_v2,
    prepare_post_c02_reply_bundle_candidate_v2,
)
from sylanne3.runtime.installed_dispatch_admission_issuer import (
    InstalledDispatchAdmissionIssuer,
)
from sylanne3.runtime.dispatch_check_reissue import (
    reissue_and_require_identical_checks,
)
from sylanne3.host.authority_profile import AdminPrivateReplyDispatchPolicy
from sylanne3.host.post_c02_reply_driver import post_c02_reply_operation_id
from sylanne3.graph_coordinator import namespace_ref
from test_first_ingress_c02_terminal_cost_v2 import _committed_case
from test_post_c02_reply_model_job_v1 import _reply_workflows
import test_first_ingress_c02_commit
import test_graph_v2_provisioning
import test_scene_binding_v2


CANONICAL_PLATFORM = '["platform-id","onebot","bot-self"]'
CANONICAL_CONVERSATION = '["umo:private:user","user-id"]'


@pytest.fixture
def canonical_private_case(monkeypatch, request):
    original_policy = test_graph_v2_provisioning.policy_for
    original_scene_ref = test_scene_binding_v2.scene_ref_for_conversation
    original_ingress = test_first_ingress_c02_commit._ingress_inputs
    original_c02_scene = test_first_ingress_c02_commit._scene_case

    def policy_for_canonical_host(store, persona="persona", *, scheme="scheme-1"):
        policy = original_policy(store, persona, scheme=scheme)
        namespace = astrbot_namespace("platform-id", "bot-self", persona)
        return replace(
            policy, namespace=namespace,
            authority_namespace=namespace_ref(namespace),
            root_lease=replace(policy.root_lease, lease_id="lease-" + namespace.persona_id,
                               bot_id=namespace.bot_id, persona_id=namespace.persona_id),
            root_grant=replace(policy.root_grant, lease_id="lease-" + namespace.persona_id,
                               bot_id=namespace.bot_id, persona_id=namespace.persona_id,
                               allowed_work_kinds=tuple(dict.fromkeys((
                                   *policy.root_grant.allowed_work_kinds, "message")))),
        )

    def canonical_ingress(namespace):
        host, clock, encoding = original_ingress(namespace)
        return (replace(host, platform_ref=CANONICAL_PLATFORM,
                        conversation_ref=CANONICAL_CONVERSATION),
                clock, encoding)

    def canonical_scene(namespace, _platform, _conversation, visibility, scene_ref):
        return CurrentHostScene(
            namespace, CANONICAL_PLATFORM, CANONICAL_CONVERSATION,
            visibility, scene_ref)

    def dispatch_scene(*args, **kwargs):
        kwargs["extra_work_kinds"] = tuple(dict.fromkeys((
            *kwargs.get("extra_work_kinds", ()), "message")))
        kwargs["extra_specs"] = tuple(kwargs.get("extra_specs", ())) + (
            GoalExecutionProvider().register_types()
            + D09ExpressionProvider().register_types())
        return original_c02_scene(*args, **kwargs)

    monkeypatch.setattr(test_graph_v2_provisioning, "policy_for",
                        policy_for_canonical_host)
    monkeypatch.setattr(
        test_scene_binding_v2, "scene_ref_for_conversation",
        lambda namespace, _platform, _conversation:
        original_scene_ref(namespace, CANONICAL_PLATFORM,
                           CANONICAL_CONVERSATION))
    monkeypatch.setattr(test_scene_binding_v2, "CurrentHostScene", canonical_scene)
    monkeypatch.setattr(test_first_ingress_c02_commit, "_ingress_inputs",
                        canonical_ingress)
    monkeypatch.setattr(test_first_ingress_c02_commit, "_scene_case",
                        dispatch_scene)
    return request.getfixturevalue("private_reply_c02_case")


def _current_join(case):
    store, coordinator, bootstrap, namespace, policy, clock, intent, read, _ = case
    c02 = coordinator.commit_first_ingress_c02_v2(
        bootstrap, intent, read, policy,
        AdminD06FirstIngressC02Policy(
            120.0, {"cpu_ms": 3}, "c02-snapshot", "c02-resource"), clock)
    source_id = store._db.execute(
        "SELECT source_ref FROM graph_first_ingress_identity_v1 WHERE bot=? "
        "AND persona=?", namespace.as_tuple,
    ).fetchone()[0]
    source_ref = source_key(*namespace.as_tuple, source_id).token
    return c02, source_ref


def _read(coordinator, store, namespace, c02, source_ref, *, product_route=False):
    snapshot, query = coordinator._dispatch_full_graph_snapshot_locked(namespace)
    source_key_value = AtomKey.from_token(source_ref)
    platform_ref, conversation_ref = store._db.execute(
        "SELECT platform_ref,conversation_ref FROM graph_first_ingress_identity_v1 "
        "WHERE bot=? AND persona=? AND source_ref=?",
        namespace.as_tuple + (source_key_value.owner.subject,),
    ).fetchone()
    scene_ref = scene_ref_for_conversation(
        namespace, platform_ref, conversation_ref)
    if product_route:
        source_atom = snapshot.get(source_key_value)
        access_atom = snapshot.get(access_key(
            *namespace.as_tuple, source_key_value.owner.subject))
        inputs = CurrentReplyModelInputsV1(
            c02, ReplySourceSnapshot(
                SourceRecord.from_dict(source_atom.value), source_ref,
                source_atom.revision, access_atom.revision),
            None, conversation_ref, snapshot)
        route = read_current_reply_route_manifest_v2(
            store._db, namespace, inputs, source_ref)
    else:
        # The older C02 fixture uses literal platform/conversation strings.
        # This branch isolates its real graph account join after C02+arrival.
        route = CurrentReplyRouteManifestV2(
            namespace, c02.operation_id, source_ref, platform_ref,
            conversation_ref, scene_ref, canonical_digest({
                "account_ref": platform_ref,
                "destination_ref": conversation_ref,
                "scene_ref": scene_ref,
            }))
    binding = read_current_reply_entity_route_binding_v2(
        store._db, namespace, route, query, now_utc=time.time())
    return route, binding


def test_real_c02_arrival_current_account_join_and_faults(private_reply_c02_case):
    case = private_reply_c02_case
    store, coordinator, _, namespace, *_ = case
    c02, source_ref = _current_join(case)
    with store._lock:
        store._db.execute("BEGIN IMMEDIATE")
        try:
            route, binding = _read(coordinator, store, namespace, c02, source_ref)
            assert binding.target_entity_ref.startswith("entity:account-v1:")
            assert binding.conversation_ref == route.conversation_ref
            assert binding.binding_scan_versions == (binding.binding_version,)
            assert binding.arrival_event_version == binding.binding_evidence_event_version

            store._db.execute("SAVEPOINT missing_binding")
            store._db.execute(
                "UPDATE graph_atoms SET valid=0 WHERE token=?",
                (binding.binding_version.key.token,))
            with pytest.raises(ReplyEntityRouteHold, match="absent"):
                _read(coordinator, store, namespace, c02, source_ref)
            store._db.execute("ROLLBACK TO missing_binding")
            store._db.execute("RELEASE missing_binding")

            store._db.execute("SAVEPOINT duplicate_binding")
            duplicate_key = AtomKey(
                Owner("persona", *namespace.as_tuple),
                "d03.account_binding", "account:duplicate")
            prior = json.loads(store._db.execute(
                "SELECT value FROM graph_atoms WHERE token=?",
                (binding.binding_version.key.token,),
            ).fetchone()[0])
            prior["account_id"] = "account:duplicate"
            store._db.execute(
                "INSERT INTO graph_atoms (token,bot,persona,owner_kind,subject,"
                "type_name,name,revision,value,valid) VALUES (?,?,?,?,?,?,?,?,?,1)",
                (duplicate_key.token, *namespace.as_tuple, "persona", None,
                 "d03.account_binding", "account:duplicate", 1,
                 canonical_serialize(prior)))
            with pytest.raises(ReplyEntityRouteHold, match="ambiguous"):
                _read(coordinator, store, namespace, c02, source_ref)
            store._db.execute("ROLLBACK TO duplicate_binding")
            store._db.execute("RELEASE duplicate_binding")

            store._db.execute("SAVEPOINT revoked_event")
            store._db.execute(
                "UPDATE graph_atoms SET valid=0 WHERE token=?",
                (binding.binding_evidence_event_version.key.token,))
            with pytest.raises(ReplyEntityRouteHold, match="absent"):
                _read(coordinator, store, namespace, c02, source_ref)
            store._db.execute("ROLLBACK TO revoked_event")
            store._db.execute("RELEASE revoked_event")
        finally:
            store._db.execute("ROLLBACK")


def test_canonical_private_c02_route_joins_arrival_account(canonical_private_case):
    case = canonical_private_case
    store, coordinator, _, namespace, *_ = case
    c02, source_ref = _current_join(case)
    with store._lock:
        store._db.execute("BEGIN IMMEDIATE")
        try:
            route, binding = _read(
                coordinator, store, namespace, c02, source_ref,
                product_route=True)
            assert route.platform_ref == CANONICAL_PLATFORM
            assert route.conversation_ref == CANONICAL_CONVERSATION
            assert binding.target_entity_ref.startswith("entity:account-v1:")
            assert binding.binding_version.revision == 1
        finally:
            store._db.execute("ROLLBACK")


def test_reply_dispatch_pre_p2_attempt_keeps_one_handler_and_deadline(
        canonical_private_case):
    case = canonical_private_case
    store, graph, _, namespace, *_ = case
    c02, source_ref = _current_join(case)
    operation_id = post_c02_reply_operation_id(c02.operation_id, source_ref)
    anchor = graph._GraphCoordinator__content_fence_v2.anchors[namespace]
    deadline = time.time() + 20.0
    with store._lock:
        metadata, epoch = graph._v2_graph_stamp(namespace)
        attempt = graph._open_post_c02_reply_dispatch_attempt_locked(
            namespace=namespace, operation_id=operation_id,
            handler_invocation_id="handler:original",
            request_digest="b" * 64, input_digest="a" * 64,
            handler_deadline_utc=deadline,
            frozen_deadline_utc=deadline - 1.0,
            metadata=metadata, epoch=epoch, anchor=anchor)
        assert store._db.execute(
            "SELECT state,attempt_id,handler_deadline_utc "
            "FROM graph_post_c02_reply_dispatch_attempts_v2 "
            "WHERE bot=? AND persona=? AND operation_id=?",
            namespace.as_tuple + (operation_id,),
        ).fetchone() == ("open", attempt, deadline)
        with pytest.raises(UnavailableGuard, match="same-permit recovery"):
            graph._open_post_c02_reply_dispatch_attempt_locked(
                namespace=namespace, operation_id=operation_id,
                handler_invocation_id="handler:original",
                request_digest="b" * 64, input_digest="a" * 64,
                handler_deadline_utc=deadline,
                frozen_deadline_utc=deadline - 1.0,
                metadata=metadata, epoch=epoch, anchor=anchor)
        with pytest.raises(EventConflict, match="attempt identity changed"):
            graph._open_post_c02_reply_dispatch_attempt_locked(
                namespace=namespace, operation_id=operation_id,
                handler_invocation_id="handler:replacement",
                request_digest="b" * 64,
                input_digest="a" * 64,
                handler_deadline_utc=deadline + 1.0,
                frozen_deadline_utc=deadline - 1.0,
                metadata=metadata, epoch=epoch, anchor=anchor)


def _prepare_canonical_reply_job(case, monkeypatch):
    store, graph, namespace, c02_intent, seal, pinned, _ = (
        _committed_case(case, monkeypatch))
    graph._GraphCoordinator__original_c02_cost_intent_port = (
        lambda _request: c02_intent)
    graph.recover_committed_first_ingress_c02_unknown_cost_v2_pinned(
        case[2], namespace, seal.consumer_operation_id, pinned)
    workflows = _reply_workflows()
    workflows = replace(
        workflows,
        reply=replace(workflows.reply,
                      audiences=(CANONICAL_CONVERSATION,)))
    installed = AdminInstallationBundle(
        object(), case[4], b"d11", b"d02", ingress_clock=case[5],
        d07_attention=AdminD07AttentionPolicy(
            300.0, {"cpu_ms": 1}, "attention-snapshot", "attention-resource"),
        model_workflows=workflows)
    c02, snapshot, qualification, audience, guard, anchor, clock, policy, competitor = (
        graph.read_post_c02_attention_inputs_v1(
            case[2], namespace, seal.consumer_operation_id, None, installed))
    assert competitor is None
    assert audience == CANONICAL_CONVERSATION
    source_ref = qualification.source_refs[0]
    operation_id = post_c02_attention_operation_id(c02.operation_id, source_ref)
    lease, capability = graph.grant(
        case[2], actor=case[4].administrator_holder,
        issuer_domain="d11", namespace=namespace, domains=("d07",),
        activation_generation=anchor.activation_generation,
        operation_id=operation_id)
    try:
        authority = AuthorityContext(
            case[4].administrator_holder, "d11", capability, namespace,
            ("persona",), "expression", (audience,),
            case[4].root_grant.policy_ref, anchor.activation_generation)
        candidate = prepare_post_c02_attention_v1(
            c02_receipt=c02, source_ref=source_ref, snapshot=snapshot,
            qualification=qualification, authority=authority, guard=guard,
            parent_budget_lease_ref=case[4].root_grant.lease_id,
            conversation_ref=audience, now_utc=trusted_upper(clock),
            monotonic_deadline=clock.monotonic_after_seconds + 299.0,
            ticket_lifetime_seconds=299.0,
            current_policy=policy.policy,
            active_head_ref=policy.active_head_ref)
        assert graph.commit_post_c02_attention_v1(
            candidate.bundle, lease, installed).status == "committed"
    finally:
        graph.release_authority_lease(case[2], lease)
    prepared = graph.prepare_post_c02_reply_model_job_v1(
        case[2], namespace, seal.consumer_operation_id, source_ref, installed)
    return (store, graph, namespace, seal, source_ref, installed, prepared,
            c02, candidate.bundle.envelope)


def test_canonical_private_c02_settles_and_prepares_signed_reply_job(
        canonical_private_case, monkeypatch):
    _, _, _, _, _, _, prepared, _, _ = _prepare_canonical_reply_job(
        canonical_private_case, monkeypatch)
    assert prepared.job.phase == "queued"
    assert prepared.quote.work_kind == "reply"


def test_canonical_private_reply_freezes_real_e_to_e_plus_one_check_versions(
        canonical_private_case, monkeypatch):
    """A synthetic expression tests actual staged rows, never authorization."""
    store, graph, namespace, seal, source_ref, _, prepared, c02, attention_envelope = (
        _prepare_canonical_reply_job(canonical_private_case, monkeypatch))
    policy = AdminPrivateReplyDispatchPolicy(
        30.0, {"cpu_ms": 1}, "k03-snapshot", "k03-resource", 800, 15.0)
    context = graph._GraphCoordinator__providers["d03"][0]
    graph._GraphCoordinator__dispatch_admission_issuer = (
        InstalledDispatchAdmissionIssuer(
            context=context,
            d11_issuer=graph._GraphCoordinator__d11_issuer,
            d02_issuer=graph._GraphCoordinator__d02_issuer))
    with store._lock:
        metadata, epoch = graph._v2_graph_stamp(namespace)
    port = graph._GraphCoordinator__content_fence_v2
    anchor = port.anchors[namespace]
    attempt_id = "k03-prebatch-fixture-attempt"
    permit = port.begin_fence(
        namespace=namespace, authority_namespace=anchor.namespace,
        holder="administrator", generation=1, operation="write",
        operation_id=attempt_id, expected_anchor=anchor)
    scope = FenceScope(
        namespace, anchor.namespace, 1, "write", attempt_id,
        permit, anchor, epoch, metadata.graph_revision)
    assert port.validate_fence(scope) == permit
    with store._lock:
        store._db.execute("BEGIN IMMEDIATE")
        try:
            route, binding = _read(
                graph, store, namespace, c02,
                source_ref, product_route=True)
            snapshot, query = graph._dispatch_full_graph_snapshot_locked(namespace)
            operation_id = post_c02_reply_operation_id(
                seal.consumer_operation_id, source_ref)
            identity = OperationIdentity(
                c02.activity_id, "effect:prebatch-test",
                "attempt:prebatch-test", "post_c02_reply_dispatch",
                operation_id, canonical_digest({"input_refs": [source_ref]}))
            job_ref, outbox_ref, _ = post_c02_dispatch_runtime_refs_v2(
                namespace, identity)
            now = time.time()
            grant = canonical_private_case[4].root_grant
            current_grant = graph._GraphCoordinator__d11_issuer.current_budget_grant(
                store._db, grant.lease_id)
            assert grant == current_grant, (grant, current_grant)
            assert "message" in grant.allowed_work_kinds, grant.allowed_work_kinds
            assert grant.valid_until_utc > now + 10, (grant.valid_until_utc, now)
            quote = graph._GraphCoordinator__d11_issuer.issue_private_reply_dispatch_quote_v2(
                store._db, policy=policy, namespace=namespace,
                identity=identity, parent_grant=grant,
                deadline_utc=now + 10, graph_job_ref=job_ref,
                outbox_refs=(outbox_ref,), now_utc=now)
            envelope = CommandEnvelope(
                RUNTIME_SCHEMA, identity,
                replace(attention_envelope.authority,
                        owner_scope=("activity", "event", "persona"),
                        audience=(route.conversation_ref,)),
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
            job = replace(
                graph._GraphCoordinator__d11_issuer.job_for(
                    envelope, store._db, now_utc=now),
                phase="waiting", wake_condition={
                    "kind": "post_c02_reply_host_takeover",
                    "operation_id": operation_id})
            create_job(store._db, job, "fixture-k03-job",
                       canonical_digest(job))
            expected = QueryEpoch(namespace, "all", query.revision + 1)
            raw = graph._read_post_c02_check_versions_locked(
                namespace, route, binding, source_ref,
                c02.operation_id, grant, quote,
                graph._GraphCoordinator__content_fence_v2.anchors[namespace],
                expected_query=expected, now_utc=now, projected=True)
            assert raw.query == expected
            assert len(raw.sets) == 5
            inputs, current_route = graph._current_post_c02_reply_route_locked(
                namespace, c02.operation_id, source_ref, now,
                snapshot.epochs[0])
            assert current_route == route
            body = inputs.source.source.text
            claim = ExpressionClaim(
                "claim:prebatch-test", body, ClaimKind.REPORTED_CLAIM,
                (source_ref,), (route.conversation_ref,), ("expression",),
                source_ref)
            use = ClaimUse(claim.claim_id, 0, len(body), ClaimKind.REPORTED_CLAIM)
            segment = SegmentCandidate(
                "segment:" + "b" * 64, identity.effect_id, body,
                (use,), ("reply",), (), 0.0)
            expression = SourceReplyExpressionV1(
                (claim,), (segment,), segment_payload_digest(body, (), (use,)),
                "b" * 64, "c" * 64, "d" * 64)
            common = dict(
                envelope=envelope, c02_receipt=c02, route=route,
                route_binding=binding, source_ref=source_ref,
                attention=inputs.attention.ticket, focus=inputs.attention.focus,
                budget_grant=grant, resource_quote=quote,
                expression=expression,
                anchor=graph._GraphCoordinator__content_fence_v2.anchors[namespace],
                now_utc=now)
            provisional = prepare_post_c02_reply_action_provisional_v2(
                **common, snapshot=snapshot, expected_query=expected,
                projected_check_inputs=raw)
            assert provisional.status == "provisional", provisional.missing
            staged_envelope, staged_action, stage = (
                graph._prepare_post_c02_reply_action_stage_locked(
                    envelope, provisional, snapshot, now_utc=now))
            with store._provisional_graph_stage_in_transaction(
                    stage, _capability=graph._GraphCoordinator__graph_capability):
                actual_snapshot, actual_query = (
                    graph._dispatch_full_graph_snapshot_locked(namespace))
                actual_route, actual_binding = _read(
                    graph, store, namespace, c02, source_ref, product_route=True)
                assert actual_route == route
                actual = graph._read_post_c02_check_versions_locked(
                    namespace, route, actual_binding, source_ref,
                    c02.operation_id, grant, quote, common["anchor"],
                    expected_query=actual_query, now_utc=now, projected=False)
                issued = issue_post_c02_reply_action_v2(
                    **common, snapshot=actual_snapshot, query=actual_query,
                    check_inputs=actual)
                assert issued == replace(provisional, status="candidate")
                assert actual_query == expected
                assert staged_action.typed_writes
                social = issue_prebatch_private_social_v1(
                    store._db, actual_snapshot, actual_query, issued.intent,
                    ActionSchemaRecord.bind(issued.intent, issued.schema),
                    expression, route=route, route_binding=binding,
                    context=context, scope=scope, now_utc=now)
                assert social.status == "checks_candidate", social
            assert graph._dispatch_full_graph_snapshot_locked(namespace)[1] == query
            assert all(store._db.execute(
                "SELECT 1 FROM graph_atoms WHERE token=?", (write.key.token,)
            ).fetchone() is None for write in staged_action.typed_writes)
            # Typed test evidence exercises reader wiring only. The fake port
            # has no independent effect journal, so this is never a product PASS.
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
            assert staged[4].graph_epoch == expected.revision
            (staged_envelope, staged_d08, action, social, checks,
             original_binding, staged_binding, route_grant) = staged
            bundle_candidate = prepare_post_c02_reply_bundle_candidate_v2(
                envelope=staged_envelope, action=action,
                staged_d08=staged_d08, checks=checks.checks,
                expression=expression, route=route,
                route_binding=staged_binding,
                pre_frozen_grant=route_grant, quote=quote,
                budget_grant=grant, pre_reserved_job=job,
                now_utc=now, conversation_epoch=expected.revision)
            assert bundle_candidate.status == "candidate"
            bundle = bundle_candidate.bundle
            final_event = Event(
                Scope(*namespace.as_tuple, identity.activity_id),
                identity.operation_id,
                bundle.envelope.source_qualification.learned_at,
                "domain_bundle", {"bundle_digest": bundle.digest})
            final_graph_candidate = GraphCandidate(
                final_event, bundle.envelope.version_guard.read_versions,
                tuple(write for proposal in bundle.proposals
                      for write in proposal.typed_writes),
                (snapshot.epochs[0],))
            graph_receipt = store._graph_commit_in_transaction(
                final_graph_candidate,
                _capability=graph._GraphCoordinator__graph_capability)
            batch_ref = next(
                write.key.token for proposal in bundle.proposals
                for write in proposal.typed_writes
                if write.key.type_name == "d09.verified_segment_batch.v1")
            def final_reissuer(db, receipt, read_scope, final_now):
                return graph._reissue_post_c02_reply_final_checks_locked(
                    db, receipt, read_scope, final_now,
                    envelope=envelope, c02_receipt=c02, route=route,
                    source_ref=source_ref, attention=inputs.attention.ticket,
                    focus=inputs.attention.focus, budget_grant=grant,
                    resource_quote=quote, expression=expression, anchor=anchor,
                    current_effect=current_effect,
                    effect_snapshot=effect_snapshot,
                    expected_action=action, expected_social=social,
                    expected_original_binding=original_binding,
                    expected_staged_binding=staged_binding,
                    expected_grant=route_grant, batch_ref=batch_ref)

            final = reissue_and_require_identical_checks(
                store._db, checks, graph_receipt, scope, now_utc=now,
                installed_reissuer=final_reissuer)
            assert final.candidate.checks == checks.checks
            batch_value = json.loads(store._db.execute(
                "SELECT value FROM graph_atoms WHERE token=?", (batch_ref,)
            ).fetchone()[0])
            batch_value["segments"][0]["body"] = "tampered"
            store._db.execute(
                "UPDATE graph_atoms SET value=? WHERE token=?",
                (canonical_serialize(batch_value), batch_ref))
            with pytest.raises(UnavailableGuard, match="social batch differs"):
                reissue_and_require_identical_checks(
                    store._db, checks, graph_receipt, scope, now_utc=now,
                    installed_reissuer=final_reissuer)
        finally:
            store._db.execute("ROLLBACK")
    assert store._db.execute(
        "SELECT 1 FROM graph_atoms WHERE token=?", (batch_ref,)
    ).fetchone() is None
