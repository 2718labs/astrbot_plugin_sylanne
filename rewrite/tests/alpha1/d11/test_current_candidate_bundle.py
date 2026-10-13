"""The D11 read gate must bind the committed D08/D09 candidate before any claim."""

from __future__ import annotations

from dataclasses import asdict, replace
from copy import deepcopy
import json

from sylanne3.domains.d08 import (
    ActionIntent, ActionSchema, ActionSchemaRecord, CommunicationIntentGrant,
    GoalPredicate, RequiredCheckSpec, SegmentGrant,
)
from sylanne3.domains.d09 import (
    ClaimKind, ClaimUse, D09ExpressionProvider, ExpressionClaim,
    SegmentCandidate, segment_payload_digest,
)
from sylanne3.domains.d11.final_admission import _current_candidate_bundle
from sylanne3.graph_types import AtomKey, GraphAtom, GraphSnapshot, NamespaceEpoch, Owner
from sylanne3.runtime.dispatch_candidate import DispatchCandidateEvidenceV1
from sylanne3.runtime_contracts import (
    NamespaceId, OperationIdentity, VersionedRef, canonical_digest, canonical_serialize,
)


def _candidate_graph():
    namespace = NamespaceId("bot", "persona")
    owner = Owner("activity", "bot", "persona", "activity:send")
    checks = tuple(
        RequiredCheckSpec(kind, provider, "persona:persona", "action:send", "respond",
                          "policy:one", (VersionedRef("policy:one", 1),))
        for kind, provider in (
            ("role_binding", "d03.role_binding"),
            ("boundary", "d05.boundary"),
            ("source_grant", "d06.source_grant"),
            ("commitment_conflict", "d08.commitment_conflict"),
            ("dispatch_budget", "d11.dispatch_budget"),
        )
    )
    identity = OperationIdentity(
        "activity:send", "effect:send", "attempt:one", "prepare", "operation:send",
        canonical_digest({"input": "send"}),
    )
    intent = ActionIntent(
        "action:send", 1, "goal:send", (), "entity:alice", "message", "respond",
        "reversible", "0" * 64, identity, "schema:send", checks,
        GoalPredicate("communicated", "d11.delivery", (), 0.0, None),
        ("message:alice",), None, ("source:one",),
    )
    schema = ActionSchemaRecord.bind(intent, ActionSchema("schema:send", "message", False, checks))
    check_refs = tuple("check:" + canonical_digest({
        "kind": item.check_kind, "provider": item.provider_id,
        "subject": item.subject_ref, "action": item.action_ref,
        "purpose": item.purpose, "criteria_version": item.criteria_version,
        "input_versions": item.required_input_versions,
    }) for item in checks)
    use = ClaimUse("claim:one", 0, 5, ClaimKind.REPORTED_CLAIM)
    segment = SegmentGrant(
        "segment:one", "effect:send", 0,
        segment_payload_digest("Hello", (), (use,)), 20, (), None,
        check_refs, 100.0, 0,
    )
    grant = CommunicationIntentGrant(
        "communication-grant:" + "1" * 64, "communication:one", "contact:one", 1,
        intent.action_id, intent.action_id, intent.revision, intent.target_ref,
        (intent.target_ref,), "expression", (), (ClaimKind.REPORTED_CLAIM.value,),
        (), (segment,), "2" * 64, check_refs, 100.0, 0,
    )
    provider = D09ExpressionProvider()
    claim = ExpressionClaim(
        "claim:one", "Hello", ClaimKind.REPORTED_CLAIM, intent.source_refs,
        grant.audiences, ("expression",), "disclosure:one",
    )
    blueprint = provider.prepare_blueprint(grant, "scene:one", 1, (claim,), now=1.0).blueprint
    assert blueprint is not None
    batch = provider.build_verified_batch_v1(
        grant, blueprint,
        (SegmentCandidate("segment:one", "effect:send", "Hello", (use,), (), (), 0.0),),
        now=1.0,
    )
    values = (
        ("d08.action_intent.v1", intent.action_id, asdict(intent)),
        ("d08.action_schema.v1", schema.schema_ref, asdict(schema)),
        ("d08.communication_intent_grant.v1", grant.grant_id, asdict(grant)),
        ("d09.verified_segment_batch.v1", batch["batch_id"], batch),
    )
    atoms = tuple(GraphAtom(AtomKey(owner, type_name, name), 1,
                            json.loads(canonical_serialize(value)))
                  for type_name, name, value in values)
    candidate = DispatchCandidateEvidenceV1(
        intent.identity.operation_id, *(atom.key.token for atom in atoms),
        canonical_digest(intent), canonical_digest(schema), canonical_digest(grant),
        batch["batch_digest"], intent.source_refs, (), (), 1, 1, 1,
    )
    snapshot = GraphSnapshot(atoms, (NamespaceEpoch("bot", "persona", 1),))
    return candidate, intent, snapshot, namespace


def test_current_committed_bundle_is_structurally_bound_but_not_an_admission():
    candidate, intent, snapshot, namespace = _candidate_graph()
    assert _current_candidate_bundle(candidate, intent, snapshot, namespace, 5.0)
    assert not _current_candidate_bundle(candidate, intent, snapshot, namespace, 101.0)


def test_changed_batch_or_grant_does_not_reuse_candidate_digest():
    candidate, intent, snapshot, namespace = _candidate_graph()
    for index, change in ((2, {"contact_id": "contact:other"}),
                          (3, {"target_ref": "entity:other"})):
        atom = snapshot.atoms[index]
        changed = replace(atom, value={**atom.value, **change})
        current = replace(snapshot, atoms=(*snapshot.atoms[:index], changed,
                                           *snapshot.atoms[index + 1:]))
        assert not _current_candidate_bundle(candidate, intent, current, namespace, 5.0)


def test_self_consistent_batch_digest_cannot_expand_frozen_segment_scope():
    candidate, intent, snapshot, namespace = _candidate_graph()
    value = deepcopy(snapshot.atoms[3].value)
    value["segments"][0]["max_chars"] = 1000
    value["batch_digest"] = canonical_digest({
        key: item for key, item in value.items() if key != "batch_digest"
    })
    changed = replace(snapshot.atoms[3], value=value)
    current = replace(snapshot, atoms=(*snapshot.atoms[:3], changed))
    assert not _current_candidate_bundle(
        replace(candidate, batch_digest=value["batch_digest"]),
        intent, current, namespace, 5.0,
    )


def test_candidate_cannot_point_to_foreign_owner_or_missing_atom():
    candidate, intent, snapshot, namespace = _candidate_graph()
    foreign = replace(snapshot.atoms[3], key=AtomKey(
        Owner("activity", "bot", "other", "activity:send"),
        "d09.verified_segment_batch.v1", snapshot.atoms[3].key.name,
    ))
    assert not _current_candidate_bundle(
        replace(candidate, batch_ref=foreign.key.token), intent,
        replace(snapshot, atoms=(*snapshot.atoms[:3], foreign)), namespace, 5.0,
    )
    assert not _current_candidate_bundle(candidate, intent,
                                         replace(snapshot, atoms=snapshot.atoms[:3]), namespace, 5.0)


def test_foreground_typed_body_and_closed_wire_cannot_change_issuer_or_claim_authority():
    import pytest
    from sylanne3.authority_service.current_foreground_activity_v1 import (
        ForegroundActivityRequestV1, foreground_from_wire_v1, foreground_to_wire_v1,
        foreground_typed_command_digest_v1,
    )
    from sylanne3.runtime.domain_production_registry_v1 import installed_operation_v1
    from sylanne3.runtime.foreground_cycle_v1 import CreateForegroundCycleRequestV1, foreground_cycle_ids_v1
    from sylanne3.runtime.d11_types import runtime_job_key
    from sylanne3.memory_types import source_key
    ns = NamespaceId("wire-bot", "wire-persona")
    source = source_key(*ns.as_tuple, "a" * 64).token
    operation = installed_operation_v1("create_foreground_cycle")
    body = CreateForegroundCycleRequestV1("c02-original", source, "existing-protected-child")
    digest = foreground_typed_command_digest_v1(operation, body)
    assert digest != foreground_typed_command_digest_v1(operation, replace(body, protected_reply_lease_ref="other-child"))
    with pytest.raises((ValueError, TypeError)):
        foreground_typed_command_digest_v1(replace(operation, domain="d08"), body)
    activity_id, job_id = foreground_cycle_ids_v1(ns, body.c02_operation_id)
    request = ForegroundActivityRequestV1(ns, "installation-wire", "ingress-original", body.c02_operation_id,
        source, source, runtime_job_key(*ns.as_tuple, activity_id, job_id).token, 0, 0, activity_id,
        "cycle-create", operation.operation_kind, digest, "existing-root", "context", ("audience-wire",), 100.0)
    wire = foreground_to_wire_v1(request)
    assert foreground_from_wire_v1(wire, ForegroundActivityRequestV1) == request
    with pytest.raises(ValueError):
        foreground_from_wire_v1({**wire, "authority_approved": True}, ForegroundActivityRequestV1)


def test_foreground_current_source_closure_rejects_withdrawal_and_key_alias_without_writes():
    import sqlite3
    import pytest
    from sylanne3.authority_service.contract import AuthorityUnavailable
    from sylanne3.authority_service.current_foreground_activity_v1 import _source_family_current_sql_v1
    from sylanne3.memory_types import SourceRecord, source_key, access_key
    ns = NamespaceId("source-bot", "source-persona")
    record = SourceRecord("a" * 64, "local source fixture", "speaker-fixture", "reported", "reported",
        None, 1.0, "original-fixture", ("audience-fixture",), ("context",))
    key = source_key(*ns.as_tuple, record.source_id)
    access = {"source_id": record.source_id, "status": "active", "audiences": list(record.audiences),
        "purposes": list(record.purposes), "recorded_at": 1.0}
    with sqlite3.connect(":memory:") as db:
        db.execute("CREATE TABLE graph_atoms(bot TEXT,persona TEXT,token TEXT PRIMARY KEY,revision INTEGER,value TEXT,valid INTEGER)")
        for atom_key, value in ((key, record.to_dict()), (access_key(*ns.as_tuple, record.source_id), access)):
            db.execute("INSERT INTO graph_atoms VALUES(?,?,?,?,?,?)", (*ns.as_tuple, atom_key.token, 1, canonical_serialize(value), 1))
        versions = _source_family_current_sql_v1(db, namespace=ns, roots=(key.token,), purpose="context", audiences=record.audiences)
        assert next(item for item in versions if item.key == key).revision == 1
        db.execute("UPDATE graph_atoms SET value=? WHERE token=?", (canonical_serialize({**access, "status": "withdrawn"}),
            access_key(*ns.as_tuple, record.source_id).token))
        before = db.total_changes
        with pytest.raises(AuthorityUnavailable):
            _source_family_current_sql_v1(db, namespace=ns, roots=(key.token,), purpose="context", audiences=record.audiences)
        assert db.total_changes == before
        db.execute("UPDATE graph_atoms SET value=? WHERE token=?", (canonical_serialize(replace(record, source_id="b" * 64).to_dict()), key.token))
        before = db.total_changes
        with pytest.raises(AuthorityUnavailable):
            _source_family_current_sql_v1(db, namespace=ns, roots=(key.token,), purpose="context", audiences=record.audiences)
        assert db.total_changes == before


def test_foreground_job_apply_requires_private_current_witness_and_leaves_sql_unchanged():
    import sqlite3
    import pytest
    from types import SimpleNamespace
    from sylanne3.runtime.domain_production_commit_v1 import apply_foreground_cycle_before_graph_write_v1
    from sylanne3.runtime.foreground_cycle_v1 import ForegroundCycleStageV1, AcquireForegroundCycleRequestV1
    from sylanne3.runtime.jobs import PersistentJob, install_schema, create_job, get_job
    from sylanne3.runtime.d11_types import runtime_job_key
    job = PersistentJob("existing-job", "original-operation", "existing-activity", None, "bot", "persona",
        "snapshot-original", "queued", "fixture.metadata", {}, None, "2030-01-01T00:00:00Z",
        "existing-root", "foreground-cycle-resource", {}, None, None, 0, 0, {}, None)
    with sqlite3.connect(":memory:") as db:
        install_schema(db)
        create_job(db, job, "create-fixture", "a" * 64)
        request = AcquireForegroundCycleRequestV1(runtime_job_key("bot", "persona", job.activity_id, job.job_id).token,
            "entity:registered-self-fixture", 30)
        # A structural proposal is deliberately not installed Authority issuance.
        proposal = ForegroundCycleStageV1(None, None, request, job, replace(job, phase="running"))
        witness = SimpleNamespace(stage=proposal)
        before = db.total_changes
        with pytest.raises(ValueError):
            apply_foreground_cycle_before_graph_write_v1(witness, object(), db)
        assert db.total_changes == before
        assert get_job(db, job.job_id) == job


def _foreground_phase_plan_fixture():
    from sylanne3.domains.d01 import TONE_SAMPLE_METHOD_V1
    from sylanne3.model_broker.artifact_draft_v1 import (
        ArtifactDraftPhaseSelectorV2, artifact_draft_task_selector_v1,
        artifact_draft_phase_original_ref_v2, artifact_draft_model_ids_v2,
    )
    from sylanne3.runtime.foreground_call_plan_v1 import (
        ForegroundArtifactPhaseGroupV2, ForegroundModelAttemptV1,
        ForegroundModelAttemptV2, ForegroundCallPlanV2,
    )
    namespace = NamespaceId("bot", "persona")
    task = artifact_draft_task_selector_v1(namespace, c02_operation_id="c02:phase",
        root_registration_ref="draft-root:phase")
    owner = AtomKey.from_token(task.cycle_job_ref).owner
    sample = ArtifactDraftPhaseSelectorV2(task,
        AtomKey(owner, "d08.decision_record.v2", "phase-decision").token, 1, "a" * 64,
        AtomKey(owner, "d08.personal_plan.v1", "phase-plan").token, 1, "b" * 64,
        TONE_SAMPLE_METHOD_V1, 0, "tone_sample", None, None)
    first = (artifact_draft_phase_original_ref_v2(sample) + ":verified", "c" * 64)
    check = replace(sample, phase_index=1, phase_kind="sample_check",
        prev_phase_original_ref=first[0], prev_phase_original_digest=first[1])
    second = (artifact_draft_phase_original_ref_v2(check) + ":verified", "d" * 64)
    full = replace(sample, phase_index=2, phase_kind="full",
        prev_phase_original_ref=second[0], prev_phase_original_digest=second[1])
    rows = []
    for selector, inputs, outputs, state in ((sample, 6000, 1000, "completed"), (full, 10000, 2000, "reserved")):
        ids = artifact_draft_model_ids_v2(selector)
        rows.append(ForegroundModelAttemptV2("C4", ids["call"], None, ids["prepare"],
            "reservation:" + selector.phase_kind, "root-lease", inputs, outputs, state,
            ids["result"] if state == "completed" else None, phase_selector=selector))
    mandatory = tuple(ForegroundModelAttemptV1(slot, "call:" + slot, None,
        "reserve:" + slot, "digest:" + slot,
        "reply-lease" if slot in {"C5", "C6"} else "root-lease", inputs, outputs, "reserved")
        for slot, inputs, outputs in (("C1", 6000, 800), ("C2", 6000, 800), ("C5", 8000, 2000), ("C6", 12000, 1400)))
    group = ForegroundArtifactPhaseGroupV2(full, (first, second))
    plan = ForegroundCallPlanV2("root-lease", "reply-lease", (*mandatory, *rows), phase_group=group)
    return plan, mandatory, tuple(rows), sample, check, first


def test_foreground_phase_plan_preserves_physical_caps_and_closed_v1_wire():
    import pytest
    from sylanne3.domains.d01.production_operations_v1 import plain_v1
    from sylanne3.runtime.foreground_call_plan_v1 import (
        ForegroundCallPlanV1, foreground_call_plan_from_wire_v1, foreground_call_plan_from_wire_v2,
    )
    plan, mandatory, rows, _, _, _ = _foreground_phase_plan_fixture()
    assert len(plan.attempts) == 6
    assert sum(row.input_ceiling for row in plan.attempts) == 48000
    assert sum(row.output_ceiling for row in plan.attempts) == 8000
    assert foreground_call_plan_from_wire_v2(plain_v1(plan)) == plan
    legacy = ForegroundCallPlanV1("root-lease", "reply-lease", mandatory)
    assert foreground_call_plan_from_wire_v1(plain_v1(legacy)) == legacy
    with pytest.raises(ValueError, match="fields differ"):
        foreground_call_plan_from_wire_v1(plain_v1(plan))
    with pytest.raises(ValueError, match="finite slot caps"):
        replace(rows[0], input_ceiling=6001)


def test_foreground_phase_plan_cannot_hide_calls_or_add_tone_route_c3():
    import pytest
    from sylanne3.runtime.foreground_call_plan_v1 import (
        ForegroundArtifactPhaseGroupV2, ForegroundCallPlanV2, ForegroundModelAttemptV1,
    )
    plan, mandatory, rows, sample, _, _ = _foreground_phase_plan_fixture()
    with pytest.raises(ValueError, match="completed sample|hide its actual"):
        replace(plan, attempts=(*mandatory, rows[1]))
    first_group = ForegroundArtifactPhaseGroupV2(sample)
    recalled = ForegroundModelAttemptV1("C3", "recall-call", None, "recall-reserve", "recall-digest",
        "root-lease", 100, 10, "completed", "recall-result")
    with pytest.raises(ValueError, match="existing C3"):
        ForegroundCallPlanV2("root-lease", "reply-lease", (mandatory[0], recalled,
            replace(rows[0], state="reserved", terminal_ref=None)), phase_group=first_group)


def test_foreground_phase_checkpoint_cannot_skip_verified_prefix():
    import pytest
    from sylanne3.runtime.foreground_call_plan_v1 import (
        ForegroundArtifactPhaseGroupV2, ForegroundCallPlanV2, require_foreground_phase_checkpoint_v2,
    )
    full, mandatory, rows, sample, check, first = _foreground_phase_plan_fixture()
    before = ForegroundCallPlanV2("root-lease", "reply-lease", (*mandatory, rows[0]),
        phase_group=ForegroundArtifactPhaseGroupV2(sample))
    with pytest.raises(ValueError, match="skip"):
        require_foreground_phase_checkpoint_v2(before, full)
    after_sample = replace(before, phase_group=ForegroundArtifactPhaseGroupV2(check, (first,)))
    require_foreground_phase_checkpoint_v2(before, after_sample)
    require_foreground_phase_checkpoint_v2(after_sample, full)
    with pytest.raises(ValueError, match="erase"):
        from sylanne3.runtime.foreground_call_plan_v1 import ForegroundCallPlanV1
        require_foreground_phase_checkpoint_v2(after_sample,
            ForegroundCallPlanV1("root-lease", "reply-lease", mandatory))
