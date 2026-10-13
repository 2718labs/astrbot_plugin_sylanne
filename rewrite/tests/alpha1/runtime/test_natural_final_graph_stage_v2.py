"""Real paid originals can reach the provisional natural final checks."""

from dataclasses import replace
from pathlib import Path
import json
import sys
import time

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "authority"))
from test_natural_generation_real_authority_output import (  # noqa: E402
    _real_authority_case, context_reply_c02_case, c02_case,
)

from sylanne3.contracts import Event, Scope
from sylanne3.authority_service.v2_clock import IngressClockSampleV2
from sylanne3.domains.d08.natural_plan import decode_natural_plan_v2
from sylanne3.graph_coordinator import budget_operation_digest
from sylanne3.graph_types import AtomKey, GraphCandidate
from sylanne3.host.v2_fence_port import VerifiedIngressClockV2
from sylanne3.memory_types import access_key
from sylanne3.runtime.dispatch_candidate import (
    validate_dispatch_candidate_writes,
)
from sylanne3.runtime.budget import reserve_budget
from sylanne3.runtime.natural_generation_issue_v2 import (
    read_original_scoped_query_proof_v2,
)
from sylanne3.runtime.natural_reply_job_v2 import (
    read_original_call_binding, read_original_preparation,
)
from sylanne3.runtime.natural_final_admission_v2 import (
    prepare_natural_final_bundle_v2,
)
from sylanne3.runtime.natural_dispatch_admission_v2 import (
    issue_natural_dispatch_admission_v2,
)
from sylanne3.runtime.dispatch_admission import insert_admission
from sylanne3.runtime.jobs import create_job
from sylanne3.runtime.post_c02_reply_bundle_v2 import (
    post_c02_dispatch_runtime_refs_v2,
)
from sylanne3.runtime_contracts import (
    AuthorityContext, FenceScope, OperationIdentity, VersionedRef,
    canonical_digest,
)


def test_paid_natural_final_stages_current_five_checks(
        request, tmp_path, monkeypatch):
    def before_revoke(value):
        case = value["case"]
        graph, store, namespace = case["graph"], case["store"], case["namespace"]
        final = value["final_candidate"]
        material = final.material
        assert material is not None
        installed = value["installed"]
        now = value["now_utc"]
        port = graph._GraphCoordinator__content_fence_v2
        metadata, epoch = graph._v2_graph_stamp(namespace)
        target = metadata.requirements
        anchor = port.current_anchor(
            namespace=namespace,
            authority_namespace=target.authority_namespace)
        attempt_id = "natural-final-stage:" + material.final_operation_id
        permit = port.begin_fence(
            namespace=namespace,
            authority_namespace=target.authority_namespace,
            holder=graph._GraphCoordinator__holder,
            generation=target.activation_generation,
            operation="write", operation_id=attempt_id,
            expected_anchor=anchor, retain_on_unknown=True)
        scope = FenceScope(
            namespace, target.authority_namespace,
            target.activation_generation, "write", attempt_id,
            permit, anchor, epoch, metadata.graph_revision)
        current_effect = port.read_current_effect(
            namespace=namespace,
            authority_namespace=target.authority_namespace,
            effect_id=material.final_effect_id)
        effect_snapshot = port.read_current_effect_snapshot_for_write_fence(
            namespace=namespace,
            authority_namespace=target.authority_namespace,
            permit=permit)
        owner_guard, owner_permit = port.get_current_owner_guard_for_fence(
            namespace=namespace,
            authority_namespace=target.authority_namespace,
            permit=permit)
        assert owner_permit == permit
        clock_policy = graph._GraphCoordinator__dispatch_clock_policy
        monotonic = time.monotonic()
        clock = VerifiedIngressClockV2(
            IngressClockSampleV2(
                anchor.authority_id,
                installed.installation_policy.installation_id,
                clock_policy.source_id, now, monotonic,
                "natural-final-test", 0.0),
            monotonic, monotonic, now)
        lease, capability = graph.grant(
            case["c02_case"]["case"][2],
            actor=case["c02_case"]["case"][4].administrator_holder,
            issuer_domain="d11", namespace=namespace,
            domains=("d08", "d09", "d11"),
            activation_generation=target.activation_generation,
            operation_id=material.final_operation_id)
        try:
            authority = AuthorityContext(
                case["c02_case"]["case"][4].administrator_holder,
                "d11", capability, namespace, ("activity",),
                "expression", (material.audience_id,),
                installed.installation_policy.root_grant.policy_ref,
                target.activation_generation)
            pending_stages = graph.discover_pending_post_c02_natural_stages_v2(
                authority, lease, installed_bundle=installed)
            assert any(
                item.parent_original_id == value["parent_original_id"]
                and item.generation_state == "terminal"
                and item.review_state == "terminal"
                for item in pending_stages.items)
            with store._lock:
                db = store._db
                db.execute("BEGIN IMMEDIATE")
                try:
                    assert graph._v2_graph_stamp(namespace) == (metadata, epoch)
                    generation = read_original_preparation(
                        db, namespace, value["parent_original_id"], "generation")
                    assert generation is not None
                    call = read_original_call_binding(db, generation)
                    assert call is not None
                    scoped = read_original_scoped_query_proof_v2(db, generation)
                    inputs, route = graph._current_post_c02_reply_route_locked(
                        namespace, value["parent_original_id"],
                        material.source_ref.ref, now, epoch)
                    snapshot, query = graph._dispatch_full_graph_snapshot_locked(
                        namespace)
                    barrier = db.execute(
                        "SELECT access_epoch,delete_epoch FROM graph_authority_epochs "
                        "WHERE bot=? AND persona=?", namespace.as_tuple,
                    ).fetchone()
                    grant = installed.installation_policy.root_grant
                    identity = OperationIdentity(
                        material.final_activity_id, material.final_effect_id,
                        "natural-final-attempt:" + canonical_digest({
                            "operation_id": material.final_operation_id,
                        })[:40], "post_c02_reply_dispatch",
                        material.final_operation_id,
                        canonical_digest({"input_refs": [material.source_ref.ref]}))
                    job_ref, outbox_ref, _ = post_c02_dispatch_runtime_refs_v2(
                        namespace, identity)
                    deadline = min(
                        generation.frozen.input.plan.valid_until_utc,
                        now + installed.private_reply_dispatch.deadline_after_seconds,
                        grant.valid_until_utc)
                    quote = graph._GraphCoordinator__d11_issuer.issue_private_reply_dispatch_quote_v2(
                        db, policy=installed.private_reply_dispatch,
                        namespace=namespace, identity=identity,
                        parent_grant=grant, deadline_utc=deadline,
                        graph_job_ref=job_ref, outbox_refs=(outbox_ref,),
                        now_utc=now)
                    db.execute(
                        "INSERT OR IGNORE INTO graph_guard_versions"
                        "(bot,persona,kind,ref,version) VALUES(?,?,?,?,?)",
                        namespace.as_tuple + (
                            "resource_lease", quote.quote_id, str(quote.version)))
                    base = call.request.envelope
                    guard = replace(
                        base.version_guard, read_versions=snapshot.versions,
                        query_epochs=(query,), access_epoch=barrier[0],
                        delete_epoch=barrier[1], focus_lease_versions=(),
                        resource_lease_versions=(VersionedRef(
                            quote.quote_id, quote.version),))
                    envelope = replace(
                        base, identity=identity, authority=authority,
                        version_guard=guard,
                        input_refs=(material.source_ref.ref,),
                        parent_budget_lease_ref=grant.lease_id,
                        deadline_utc=deadline,
                        monotonic_deadline=time.monotonic() + 60,
                        causation=(value["parent_original_id"],))
                    reserve_budget(
                        db, grant.lease_id, material.final_operation_id,
                        budget_operation_digest(
                            envelope, grant.lease_id, dict(quote.ceiling)),
                        quote.ceiling)
                    stage, checks, social, _d08, _original_binding, _staged_binding, projected = (
                        graph._stage_natural_final_pregrant_locked(
                            envelope=envelope, final=final, route=route,
                            original_scope_proof=scoped,
                            budget_grant=grant, resource_quote=quote,
                            scope=scope, current_effect=current_effect,
                            effect_snapshot=effect_snapshot,
                            expected_access_delete_epoch=barrier,
                            now_utc=now))
                    assert stage.status == "candidate_hold_w01_current_five_checks"
                    assert social.status == "checks_candidate"
                    assert tuple(check.check_kind for check in checks) == (
                        "role_binding", "boundary", "source_grant",
                        "commitment_conflict", "dispatch_budget")
                    granted = graph._freeze_natural_final_grant_locked(
                        final, generation.frozen.input.plan,
                        decode_natural_plan_v2(next(
                            atom.value for atom in snapshot.atoms
                            if atom.key.token ==
                            generation.frozen.input.plan.plan_ref.ref)),
                        stage, checks, now_utc=now)
                    assert granted.communication_grant is not None
                    job = replace(
                        graph._GraphCoordinator__d11_issuer.job_for(
                            envelope, db, now_utc=now),
                        phase="waiting", wake_condition={
                            "kind": "post_c02_reply_host_takeover",
                            "operation_id": material.final_operation_id,
                        })
                    create_job(
                        db, job, "job:" + canonical_digest({
                            "natural_final_operation_id":
                                material.final_operation_id,
                            "job_ref": job_ref,
                        })[:48], canonical_digest(job))
                    bundle = prepare_natural_final_bundle_v2(
                        envelope=stage.proposal.envelope, final=final,
                        candidate=granted, schema=stage.schema,
                        checks=checks, staged_d08=stage.proposal,
                        quote=quote, budget_grant=grant,
                        pre_reserved_job=job, now_utc=now)
                    assert bundle.status == "candidate_hold_w01_final_admission", bundle.missing
                    assert bundle.bundle is not None
                    bound = bundle.bundle
                    writes = tuple((proposal.domain, write)
                                   for proposal in bound.proposals
                                   for write in proposal.typed_writes)
                    evidence = validate_dispatch_candidate_writes(
                        writes, namespace=namespace,
                        identity=bound.envelope.identity,
                        read_versions=bound.envelope.version_guard.read_versions,
                        source_refs=bound.envelope.source_qualification.source_refs,
                        access_epoch=barrier[0], delete_epoch=barrier[1],
                        query_epoch=query.revision)
                    assert graph._check_guard(db, bound) == snapshot
                    for proposal in bound.proposals:
                        provider = graph._GraphCoordinator__providers[
                            proposal.domain][0]
                        validated = provider.validate(proposal, snapshot)
                        assert validated is True or validated == proposal
                    def after_graph_write(_db, receipt, recovered, admissions):
                        assert receipt.status == "committed"
                        assert recovered == evidence
                        assert len(admissions) == 1
                        checked, _binding, _snapshot, _query, _projection = (
                            graph._reissue_natural_final_after_graph_locked(
                                bundle=bound, final=final,
                                paid=value["paid_current"],
                                candidate=evidence, stage=stage,
                                scope=scope, route=route,
                                original_scope_proof=scoped,
                                budget_grant=grant, resource_quote=quote,
                                current_effect=current_effect,
                                effect_snapshot=effect_snapshot,
                                provisional_checks=checks,
                                projected_check_versions=projected,
                                now_utc=now))
                        assert checked.status == (
                            "admitted_runtime_hold_graph_final_claim")
                        admission, dispatch = issue_natural_dispatch_admission_v2(
                            db=_db, bundle=bound, evidence=evidence,
                            final=final, runtime=checked, checks=checks,
                            graph_receipt=receipt, scope=scope,
                            clock_reading=clock, clock_policy=clock_policy,
                            owner_guard=owner_guard,
                            current_effect=current_effect,
                            effect_snapshot=effect_snapshot,
                            route=_binding, snapshot=_snapshot,
                            query=_query, projection=_projection,
                            now_utc=now)
                        insert_admission(_db, admission, dispatch)
                        from sylanne3.runtime.natural_final_authorization_original_v3 import _capture_natural_final_authorization_original_v3
                        original=_capture_natural_final_authorization_original_v3(
                            coordinator=graph,db=_db,bundle=bound,evidence=recovered,graph_receipt=receipt,
                            scope=scope,clock_reading=clock,clock_policy=clock_policy,owner_guard=owner_guard,
                            current_effect=current_effect,effect_snapshot=effect_snapshot,
                            route=_binding,snapshot=_snapshot,query=_query,projection=_projection,
                            checks=checks,now_utc=now,admission=admission,request=dispatch)
                        source_id = AtomKey.from_token(
                            material.source_ref.ref).owner.subject
                        access = access_key(*namespace.as_tuple, source_id)
                        _db.execute(
                            "UPDATE graph_atoms SET valid=0 WHERE token=?",
                            (access.token,))
                        with pytest.raises(Exception, match="closure|access|source"):
                            graph._reissue_natural_final_after_graph_locked(
                                bundle=bound, final=final,
                                paid=value["paid_current"],
                                candidate=evidence, stage=stage,
                                scope=scope, route=route,
                                original_scope_proof=scoped,
                                budget_grant=grant, resource_quote=quote,
                                current_effect=current_effect,
                                effect_snapshot=effect_snapshot,
                                provisional_checks=checks,
                                projected_check_versions=projected,
                                now_utc=now)
                        return admission, dispatch, original

                    from sylanne3.contracts import canonical_json
                    from sylanne3.authority_service.v2_contract import to_wire
                    graph._commit_domain_bundle_fenced(
                        bound, lease, in_transaction=True,
                        v2_write=(metadata, epoch, "finish:" + attempt_id,
                                  "sha256:" + canonical_digest({
                                      "test": "natural-final-stage",
                                      "attempt_id": attempt_id}),
                                  canonical_json(to_wire(permit))),
                        now_utc=now,
                        natural_final_admission=after_graph_write)
                    from dataclasses import asdict
                    actual_original=json.loads(db.execute(
                        "SELECT receipt_json FROM graph_bundle_operations WHERE bot=? AND persona=? AND operation_id=?",
                        (*namespace.as_tuple,material.final_operation_id)).fetchone()[0])["natural_final_authorization_original"]
                    assert actual_original["schema"]=="sylanne.natural_final_authorization_original.v3"
                    payload=actual_original["payload"]
                    assert actual_original["original_digest"]==canonical_digest(payload)
                    assert payload["owner_guard"]==asdict(owner_guard)
                    assert payload["scope"]["permit"]==to_wire(permit)
                    assert payload["identity"]["operation_id"]==material.final_operation_id
                    assert payload["scope"]["operation_id"]==attempt_id
                    assert payload["scope"]["graph_epoch"]["revision"]+1==payload["query"]["revision"]
                finally:
                    db.execute("ROLLBACK")
        finally:
            graph.release_authority_lease(case["c02_case"]["case"][2], lease)
            port.finish_fence(
                scope, request_id="finish:" + attempt_id,
                request_digest="sha256:" + canonical_digest({
                    "test": "natural-final-stage", "attempt_id": attempt_id,
                }))

    _real_authority_case(
        request, tmp_path, monkeypatch, "review_current",
        before_revoke=before_revoke)


def _real_natural_final_commit_case(
        request, tmp_path, monkeypatch, *, after_commit=None,
        lose_final_finish_once=False):
    def before_revoke(value):
        case = value["case"]
        graph, store, namespace = case["graph"], case["store"], case["namespace"]
        material = value["final_candidate"].material
        assert material is not None
        port = graph._GraphCoordinator__content_fence_v2
        original_clock = port.read_ingress_clock
        now = value["now_utc"]
        monotonic = time.monotonic()
        policy = graph._GraphCoordinator__dispatch_clock_policy
        anchor = port.current_anchor(
            namespace=namespace,
            authority_namespace=graph._v2_graph_stamp(namespace)[0]
            .requirements.authority_namespace)
        clock = VerifiedIngressClockV2(
            IngressClockSampleV2(
                anchor.authority_id,
                value["installed"].installation_policy.installation_id,
                policy.source_id, now, monotonic, "natural-final-commit", 0.0),
            monotonic, monotonic, now)
        monkeypatch.setattr(
            port, "read_ingress_clock",
            lambda requested: clock if requested == policy else original_clock(requested))
        lease, capability = graph.grant(
            case["c02_case"]["case"][2],
            actor=case["c02_case"]["case"][4].administrator_holder,
            issuer_domain="d11", namespace=namespace,
            domains=("d08", "d09", "d11"),
            activation_generation=graph._v2_graph_stamp(namespace)[0]
            .requirements.activation_generation,
            operation_id=material.final_operation_id)
        authority = AuthorityContext(
            case["c02_case"]["case"][4].administrator_holder,
            "d11", capability, namespace, ("activity",), "expression",
            (material.audience_id,),
            value["installed"].installation_policy.root_grant.policy_ref,
            graph._v2_graph_stamp(namespace)[0]
            .requirements.activation_generation)
        try:
            original_finish = port.finish_fence
            lost = False
            if lose_final_finish_once:
                def lose_once(scope, *, request_id, request_digest):
                    nonlocal lost
                    if (scope.operation_id.startswith("natural-final:")
                            and not lost):
                        lost = True
                        raise RuntimeError("lost natural final finish ACK")
                    return original_finish(
                        scope, request_id=request_id,
                        request_digest=request_digest)
                monkeypatch.setattr(port, "finish_fence", lose_once)
                with pytest.raises(RuntimeError, match="lost natural final finish ACK"):
                    graph.commit_post_c02_natural_final_v2(
                        authority, lease, value["parent_original_id"],
                        value["installed"])
                assert lost
            receipt = graph.commit_post_c02_natural_final_v2(
                authority, lease, value["parent_original_id"],
                value["installed"])
            assert receipt.status == (
                "duplicate" if lose_final_finish_once else "committed")
            assert receipt.operation_id == material.final_operation_id
            committed = graph.read_committed_natural_dispatch_v2(
                authority, lease, material.final_operation_id)
            assert committed is not None
            assert committed[2].effect_id == material.final_effect_id
            assert committed[3].operation_id == material.final_operation_id
            page = graph.discover_pending_post_c02_natural_dispatch_v2(
                authority, lease)
            assert any(item.operation_id == material.final_operation_id
                       for item in page.items)
            progress = graph.read_natural_original_progress_v2(
                authority, lease, value["parent_original_id"],
                value["installed"])
            assert progress.generation.state == "terminal"
            assert progress.review.state == "terminal"
            assert progress.final_operation_id == material.final_operation_id
            restored_generation = graph.read_natural_original_stage_preparation_v2(
                authority, lease, value["parent_original_id"],
                "generation", value["installed"])
            restored_review = graph.read_natural_original_stage_preparation_v2(
                authority, lease, value["parent_original_id"],
                "review", value["installed"])
            assert restored_generation.state == "terminal"
            assert restored_review.state == "terminal"
            assert restored_generation.seal.original_operation_id == (
                progress.generation.original_operation_id)
            assert restored_review.seal.original_operation_id == (
                progress.review.original_operation_id)
            unfinished = graph.discover_pending_post_c02_natural_stages_v2(
                authority, lease, installed_bundle=value["installed"])
            assert not any(item.parent_original_id == value["parent_original_id"]
                           for item in unfinished.items)
            if after_commit is not None:
                after_commit(graph, authority, lease, receipt, committed, value)
        finally:
            if lose_final_finish_once:
                monkeypatch.setattr(port, "finish_fence", original_finish)
            graph.release_authority_lease(case["c02_case"]["case"][2], lease)

    _real_authority_case(
        request, tmp_path, monkeypatch, "review_current",
        before_revoke=before_revoke)


def test_paid_natural_final_commits_admission(
        request, tmp_path, monkeypatch):
    _real_natural_final_commit_case(request, tmp_path, monkeypatch)


def test_paid_natural_final_recovers_lost_finish(
        request, tmp_path, monkeypatch):
    _real_natural_final_commit_case(
        request, tmp_path, monkeypatch, lose_final_finish_once=True)
