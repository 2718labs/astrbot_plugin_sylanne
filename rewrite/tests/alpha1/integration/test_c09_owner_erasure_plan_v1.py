"""One-source C09 plan original under a real signed Owner installation."""

from dataclasses import replace
from uuid import uuid4

import pytest

from rewrite.tests.alpha1.integration.test_owner_signed_chain import (
    PEER, ROLE, _real_owner_chain,
)
from sylanne3.contracts import Event, Scope
from sylanne3.domains.d06 import D06DomainProvider
from sylanne3.graph_coordinator import GraphCoordinator, UnavailableGuard
from sylanne3.graph_store import GraphStore, ProductionGraphStore, TypeRegistry
from sylanne3.graph_types import GraphCandidate, GraphWrite, owner_grant_spec
from sylanne3.memory_types import SourceRecord, access_key, source_key
from sylanne3.runtime.c09_erasure_plan_original_v1 import (
    read_c09_erasure_plan_original_v1,
)
from sylanne3.authority_service.c09_owner_pairing_rows_v1 import (
    SCHEMAS as OWNER_PAIRING_SCHEMAS, verify_owner_pairing_schema_v1,
    validate_owner_pairing_row_v1,
)


def test_signed_owner_plan_persists_and_rejects_changed_access(tmp_path):
    chain = _real_owner_chain(
        tmp_path, extra_purpose="context",
        extra_capability="workbench.erase",
        extra_specs=D06DomainProvider.type_specs(),
    )
    registry = TypeRegistry()
    registry.register(owner_grant_spec())
    for spec in D06DomainProvider.type_specs():
        registry.register(spec)
    graph = None
    try:
        # The real Ed25519-paired Owner installation must be classified in
        # C09's four-file inventory, including current/revoked identity facts.
        with chain.service.core._tx() as db:
            verify_owner_pairing_schema_v1(db)
            for table in OWNER_PAIRING_SCHEMAS:
                columns = tuple(row[1] for row in db.execute(f"PRAGMA table_info({table})"))
                originals = db.execute(f"SELECT * FROM {table}").fetchall()
                assert originals
                for row in originals:
                    assert validate_owner_pairing_row_v1(table, columns, row,
                        authority_id=chain.authority_id) == chain.service.namespace
        graph = ProductionGraphStore(tmp_path / "business.db", registry)
        coordinator = GraphCoordinator(
            graph, chain.bootstrap, holder="administrator",
            content_fence_v2=chain.port,
            owner_principal_resolver=chain.current_principal,
        )
        provider = D06DomainProvider()
        coordinator.register_provider(
            chain.bootstrap, "d06", provider, "d06.contract.v1",
            provider.descriptor.request_schema_hash,
        )
        source = source_key(*ROLE.as_tuple, "source-c09")
        access = access_key(*ROLE.as_tuple, "source-c09")
        record = SourceRecord(
            "source-c09", "private", "speaker", "reported", "reported",
            1.0, 2.0, "family", ("owner",), ("context",),
        )
        access_value = {
            "source_id": "source-c09", "audiences": ["owner"],
            "purposes": ["context"], "status": "active", "recorded_at": 2.0,
        }
        snapshot = GraphStore.graph_snapshot(
            graph, (source, access), _capability=graph._coordinator_capability)
        GraphStore.graph_commit(
            graph, GraphCandidate(
                Event(Scope(*ROLE.as_tuple, "seed"), "seed-c09-source", 2.0,
                      "seed", {}), snapshot.versions,
                (GraphWrite(source, record.to_dict()),
                 GraphWrite(access, access_value, (source,))), snapshot.epochs,
            ), _capability=graph._coordinator_capability,
        )
        login_request = replace(chain.issue_request, audience="owner")
        challenge = chain.sessions.begin_login(
            transport_credential=PEER, request=login_request)
        token = chain.sessions.accept_login(
            transport_credential=PEER, challenge=challenge,
            signature=chain.key.sign(challenge.signed_bytes()))
        authority, lease, _ = coordinator.grant_current_owner(
            chain.bootstrap, actor="owner-actor", namespace=ROLE,
            domains=("d06",), purpose="context", audience="owner",
            activation_generation=1, owner_session_token=token,
            owner_session_request=login_request,
        )
        try:
            operation_id = str(uuid4())
            original = coordinator.issue_current_c09_erasure_plan_v1(
                authority, lease, operation_id=operation_id,
                source_ref=source.token)
            assert original.root_source_ids == ("source-c09",)
            assert original.scope_kind == "one_source"
            assert original.source_ref == source.token
            assert coordinator.read_current_c09_erasure_plan_v1(
                authority, lease, operation_id=operation_id) == original
            assert coordinator.issue_current_c09_erasure_plan_v1(
                authority, lease, operation_id=operation_id,
                source_ref=source.token) == original
            assert read_c09_erasure_plan_original_v1(
                graph._db, ROLE, operation_id) == original
            changed = {**access_value, "status": "withdrawn", "recorded_at": 3.0}
            snapshot = GraphStore.graph_snapshot(
                graph, (source, access),
                _capability=graph._coordinator_capability)
            GraphStore.graph_commit(
                graph, GraphCandidate(
                    Event(Scope(*ROLE.as_tuple, "seed"), "withdraw-c09-source",
                          3.0, "seed", {}), snapshot.versions,
                    (GraphWrite(access, changed, (source,)),), snapshot.epochs,
                ), _capability=graph._coordinator_capability,
            )
            with pytest.raises(UnavailableGuard):
                coordinator.read_current_c09_erasure_plan_v1(
                    authority, lease, operation_id=operation_id)
        finally:
            coordinator.release_current_owner_lease(chain.bootstrap, lease)
    finally:
        if graph is not None:
            graph.close()
        for resource in chain.resources:
            resource.close()


def test_d01_frozen_method_original_legacy_defaults_preserve_signed_wire_and_reject_partial_schema():
    from sylanne3.graph_types import AtomKey, GraphVersion, Owner
    from sylanne3.runtime_contracts import NamespaceId, QueryEpoch, canonical_serialize
    from sylanne3.domains.d01.production_operations_v1 import plain_v1
    from sylanne3.runtime.d01_production_operations_v1 import FrozenValuesCandidateSetV1, FrozenValuesContextV1
    from sylanne3.runtime.domain_production_erasure_v1 import (decode_domain_production_content_v1,
        decode_typed_production_value_v1, DomainProductionErasureHold)
    owner = Owner("activity", "bot", "persona", "activity:codec")
    candidate_head = GraphVersion(AtomKey(owner, "d08.action_intent.v1", "action:codec"), 1)
    context_head = GraphVersion(AtomKey(owner, "d03.world_event", "event:codec"), 1)
    candidates = {"candidates": [["candidate:codec", []]], "candidate_heads": [plain_v1(candidate_head)]}
    context = {"context_tags": [], "context_heads": [plain_v1(context_head)], "role_binding_complete": False}
    for kind, raw, expected in (("values_candidates", candidates, FrozenValuesCandidateSetV1),
            ("values_context", context, FrozenValuesContextV1)):
        encoded = canonical_serialize(raw)
        decoded = decode_domain_production_content_v1("graph_d01_production_inputs_v1", kind, encoded)
        assert type(decoded) is expected and canonical_serialize(raw) == encoded
        with pytest.raises(DomainProductionErasureHold):
            decode_domain_production_content_v1("graph_d01_production_inputs_v1", kind,
                canonical_serialize({**raw, "unregistered": None}))
    old_context = decode_typed_production_value_v1(context, FrozenValuesContextV1)
    assert old_context.condition_heads == () and old_context.condition_query_epoch is None
    with pytest.raises(DomainProductionErasureHold):
        decode_typed_production_value_v1({**context, "condition_heads": []}, FrozenValuesContextV1)
    current_context = {**context, "condition_heads": [],
        "condition_query_epoch": plain_v1(QueryEpoch(NamespaceId("bot", "persona"), "namespace", 4))}
    assert decode_domain_production_content_v1("graph_d01_production_inputs_v1", "values_context",
        canonical_serialize(current_context)).condition_query_epoch.revision == 4



def _closed_personal_candidate_fixture():
    """Codec-only metadata, with no claim of adoption, signed eligibility or execution."""
    from rewrite.tests.alpha1.model_broker.test_artifact_draft_v1 import frozen, phase
    from sylanne3.domains.d01.production_operations_v1 import plain_v1
    from sylanne3.domains.d08.personal_candidate_v1 import (ArtifactPhaseCandidateBindingV1,
        PrepareCurrentPersonalCandidatesRequestV1, CurrentPersonalNeedQualificationV1,
        CurrentPersonalCandidateEligibilityV1, PreparedPersonalCandidateV1, PreparedPersonalCandidateSetV1)
    from sylanne3.graph_types import AtomKey, GraphVersion, GraphAtom
    from sylanne3.runtime_contracts import QueryEpoch, canonical_digest
    from sylanne3.runtime.domain_production_contracts_v1 import ProductionOriginalRefV1, ProductionQueryCoverageV1
    from sylanne3.runtime.d08_personal_candidate_v1 import prospective_personal_decision_key_v1, prospective_personal_future_identity_v1
    input = frozen(phase(index=2))
    selector, ns = input.selector, input.selector.task.namespace
    owner = AtomKey.from_token(selector.plan_ref).owner
    goal = GraphVersion(AtomKey(owner, "d08.goal.v1", "goal:codec"), 1)
    plan = GraphVersion(AtomKey.from_token(selector.plan_ref), selector.plan_revision)
    condition = GraphVersion(AtomKey(owner, "d07.current_interpretation.v1", "condition:codec"), 1)
    versions = (plan, goal, condition, *(GraphVersion(AtomKey.from_token(row.ref), row.revision) for row in input.sources))
    page = ProductionQueryCoverageV1(QueryEpoch(ns, "namespace", 7), "d07.current_interpretation.v1", (condition,), True, None)
    original = ProductionOriginalRefV1("d07.need-qualified", "need:codec", "1" * 64, versions)
    binding = ArtifactPhaseCandidateBindingV1("candidate:full", "task:full", selector.task, selector.method_ref,
        selector.phase_index, selector.phase_kind, input.extent, input.target, input.prior_content,
        "scope:codec", selector.prev_phase_original_ref, selector.prev_phase_original_digest)
    request = PrepareCurrentPersonalCandidatesRequestV1(plan.key.token, goal.key.token, plan.revision, goal.revision,
        "selection:codec", "evaluation:codec", original.original_ref, (binding,))
    need = CurrentPersonalNeedQualificationV1(original, plan, goal, versions, (page,), True, False, (), 400.0)
    eligibility = CurrentPersonalCandidateEligibilityV1(binding.candidate_ref, binding.node_id, binding.digest,
        "REQUIRED_CHECK_UNRESOLVED", (original,), versions, (page,), 1, None)
    future = prospective_personal_future_identity_v1(ns, request, binding, GraphAtom(plan.key, plan.revision,
        {"plan_id": "plan:codec", "revision": 2}, True), 400.0, "parent:codec")
    candidate = PreparedPersonalCandidateV1(binding, eligibility, None, None, None, (), "2" * 64, future)
    prepared = PreparedPersonalCandidateSetV1(ns, "persona:" + ns.persona_id, "prepare:codec", request.selection_operation_id,
        prospective_personal_decision_key_v1(ns, owner.subject, request.selection_operation_id, plan.key.token).token,
        plan, goal, tuple(row.ref for row in input.sources), versions, (page,), request.value_evaluation_operation_id,
        "3" * 64, need, (candidate,), "parent:codec", "owner:codec", 1, "4" * 64, 0, 0)
    return request, prepared, input, plain_v1


def test_c09_exact_candidate_preparation_and_phase_prior_sources_are_in_reference_closure():
    from sylanne3.runtime.domain_production_erasure_v1 import (decode_personal_candidate_request_v1,
        validate_domain_stage_provenance_v1, personal_candidate_reference_closure_v1,
        decode_typed_production_value_v1, DomainProductionErasureHold)
    from sylanne3.model_broker.artifact_draft_v1 import ArtifactDraftInputV2
    request, prepared, input, plain = _closed_personal_candidate_fixture()
    raw = plain(prepared)
    assert decode_personal_candidate_request_v1("prepare_personal_candidates_v1", plain(request)) == request
    closure = validate_domain_stage_provenance_v1("d08", "prepare_personal_candidates_v1", {"prepared_candidates": raw})
    expected = {prepared.plan_head.key.token, prepared.goal_head.key.token,
        input.task_source_ref, input.prior_content.source_head.ref, *prepared.source_refs,
        *(version.key.token for version in prepared.need.read_versions)}
    assert expected <= set(closure)
    phase_closure = personal_candidate_reference_closure_v1(plain(input), ArtifactDraftInputV2)
    assert {input.task_source_ref, input.prior_content.source_head.ref,
        input.selector.plan_ref, input.selector.decision_ref} <= set(phase_closure)
    assert decode_typed_production_value_v1(plain(input), ArtifactDraftInputV2) == input
    for extra in ({"unknown": None}, {"execution_grant": True}):
        with pytest.raises(DomainProductionErasureHold):
            validate_domain_stage_provenance_v1("d08", "prepare_personal_candidates_v1", {"prepared_candidates": raw, **extra})
    with pytest.raises(ValueError):
        decode_personal_candidate_request_v1("prepare_personal_candidates_v1", {**plain(request), "phase_price_reader": "chosen-by-payload"})
    with pytest.raises(DomainProductionErasureHold):
        decode_personal_candidate_request_v1("unregistered_personal_candidate_operation", plain(request))
    with pytest.raises(DomainProductionErasureHold):
        validate_domain_stage_provenance_v1("d07", "prepare_personal_candidates_v1", {"prepared_candidates": raw})


def test_c09_candidate_preparation_rejects_wrong_need_scope_or_fake_future_decision():
    from sylanne3.runtime.domain_production_erasure_v1 import validate_domain_stage_provenance_v1, DomainProductionErasureHold
    from sylanne3.graph_types import AtomKey
    request, prepared, _, plain = _closed_personal_candidate_fixture()
    unrelated = replace(prepared.goal_head, key=AtomKey(prepared.goal_head.key.owner, "d08.goal.v1", "goal:other"))
    for changed in (replace(prepared, need=replace(prepared.need, goal_head=unrelated)),
            replace(prepared, need=replace(prepared.need, complete=False)),
            replace(prepared, future_decision_ref=AtomKey(prepared.plan_head.key.owner, "d08.decision_record.v2", "decision:other").token)):
        with pytest.raises(DomainProductionErasureHold):
            validate_domain_stage_provenance_v1("d08", "prepare_personal_candidates_v1", {"prepared_candidates": plain(changed)})


def test_c09_prepared_selection_has_exact_request_provenance_and_no_action_grant_fields():
    from sylanne3.graph_types import AtomKey
    from sylanne3.domains.d08.personal_candidate_v1 import SelectCurrentPersonalStepRequestV2
    from sylanne3.domains.d08.personal_plan_v1 import QualifiedPersonalCandidateV1, select_personal_step_v2
    from sylanne3.runtime.domain_production_erasure_v1 import (decode_personal_candidate_request_v1,
        validate_domain_stage_provenance_v1, DomainProductionErasureHold)
    request, prepared, _, plain = _closed_personal_candidate_fixture()
    selected_request = SelectCurrentPersonalStepRequestV2(request.plan_ref, request.goal_ref, prepared.preparation_operation_id)
    assert decode_personal_candidate_request_v1("select_personal_step_v2", plain(selected_request)) == selected_request
    candidate = prepared.candidates[0]
    evidence = QualifiedPersonalCandidateV1(candidate.binding.candidate_ref, candidate.future_identity.action_ref,
        candidate.binding.node_id, candidate.binding.digest, "REQUIRED_CHECK_UNRESOLVED", 1, True, None, None)
    record = select_personal_step_v2(decision_id=AtomKey.from_token(prepared.future_decision_ref).name,
        candidates=(evidence,), preference_edges=(), source_refs=prepared.source_refs, read_versions=())
    provenance = {"decision": plain(record), "candidate_evidence": [plain(evidence)],
        "prepared_candidates_operation_id": prepared.preparation_operation_id,
        "prepared_candidates_digest": "5" * 64, "value_evaluation": prepared.value_evaluation_digest}
    closure = validate_domain_stage_provenance_v1("d08", "select_personal_step_v2", provenance)
    assert set(prepared.source_refs) <= set(closure) and record.chosen_action_ref is None
    for changed in ({**provenance, "dispatch_grant": True}, {**provenance, "prepared_candidates_digest": "invalid"},
            {**provenance, "candidate_evidence": []}):
        with pytest.raises(ValueError):
            validate_domain_stage_provenance_v1("d08", "select_personal_step_v2", changed)
    with pytest.raises(DomainProductionErasureHold):
        validate_domain_stage_provenance_v1("d07", "select_personal_step_v2", provenance)
