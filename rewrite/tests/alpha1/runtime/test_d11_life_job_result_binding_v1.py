"""Permanent Life result scope, signed SQL reader and transaction regressions.

These isolated fixtures exercise the real schema, artifact producer, Jobs,
post-CAS original writer and installed signed reader. They seed a bounded Graph
receipt/history for that SQL seam; they do not claim Authority/W01 end-to-end
acceptance, which remains the separate installed product test.
"""
from copy import deepcopy
from dataclasses import replace
import hashlib
import json
import secrets
from types import SimpleNamespace

import pytest

from sylanne3.domains.d01.production_operations_v1 import plain_v1
from sylanne3.graph_store import GraphStore
from sylanne3.graph_types import AtomKey, GraphVersion, TypeRegistry
from sylanne3.memory_types import SourceRecord, source_key, access_key
from sylanne3.runtime_contracts import CommitReceipt, NamespaceId, OperationIdentity, canonical_digest, canonical_serialize
from sylanne3.runtime.budget import BudgetLease, create_budget_lease, reserve_budget, settle_budget
from sylanne3.runtime.c09_life_originals_v1 import decode_life_original_content_v1
from sylanne3.runtime.domain_production_erasure_v1 import DomainProductionErasureHold
from sylanne3.runtime.d11_life_contract_v1 import (
    D11LifeExecutionBindingV1, D11LifeClaimV1, D11LifeTerminalV1, RoleSegmentStartV1,
    LifeTerminalPayloadV1, LifeInputRefV1, WORK_KIND, life_artifact_ref_v1,
    life_mutation_id_v1, life_adoption_operation_id_v1, life_job_result_binding_v1,
    RegisteredLifePlanV2,
)
from sylanne3.runtime.d11_life_graph_types_v1 import life_fact_writes_v1
from sylanne3.runtime.d11_life_preparation_v1 import install_d11_life_schema_v1, TABLE, SIGN_KIND, D11LifePreparedV1, life_input_digest_v1
from sylanne3.runtime.d10_offline_tick_execution_v1 import OfflineTickGraphReadV1
from sylanne3.runtime.d11_life_source_note_v1 import generate_source_note_bytes_v1, write_life_artifact_stage_v1
from sylanne3.runtime.d11_life_terminal_v1 import (
    LifeTerminalBundleV1, record_life_terminal_after_cas_v1, read_adopted_life_original_v1,
    validate_life_job_result_members_v1, validate_current_life_job_result_v1,
)
from sylanne3.runtime.d11_types import job_graph_write
from sylanne3.runtime.issuers import D02ResourceIssuer, D11BudgetJobIssuer
from sylanne3.runtime.jobs import PersistentJob, create_job, acquire_job, checkpoint_job, transition_job, get_job


D = "a" * 64
START = "2030-01-01T00:00:00Z"
END = "2030-01-01T00:00:01Z"
DEADLINE = "2030-01-01T00:01:00Z"


def _binding(namespace=NamespaceId("bot", "persona"), **changes):
    values = dict(namespace=namespace, authority_namespace="authority:fixture", authority_id="authority-1",
        installation_id="installation-1", manifest_digest=D, activation_generation=1,
        operation_id="root-1", prepare_operation_id="d11-life-prepare:root-1", activity_id="activity-1",
        effect_id="effect:one", attempt_id="attempt:one", execution_id="execution-1", job_id="job-1",
        job_holder="worker-1", job_fence=1, job_lease_expires_utc=DEADLINE, job_cancel_epoch=0,
        plan_original_ref="plan-1", plan_digest=D, prepared_original_ref="prepared-1", input_digest=D,
        clock_original_digest=D, owner_grant_ref="owner-1", owner_grant_revision=1, owner_grant_digest=D,
        parent_budget_lease_ref="lease-1", quote_id="quote-1", quote_version=1, quote_digest=D,
        reservation_operation_id="reserve-1", reservation_digest=D, cpu_ceiling_ms=100,
        deadline_utc=DEADLINE, algorithm_build_digest=D, postcondition_build_digest=D,
        artifact_ref=life_artifact_ref_v1(namespace, "effect:one"))
    values.update(changes)
    return D11LifeExecutionBindingV1(**values)


def _terminal(binding, data, prepared_digest=D):
    claim_id = life_mutation_id_v1(binding, "claim")
    start = RoleSegmentStartV1(binding.digest, prepared_digest, binding.execution_id, claim_id, 1,
        binding.installation_id, "worker-incarnation", START, "0", "clock-1", 1, D)
    claim = D11LifeClaimV1(binding, start, "journal-1", "sha256:" + D, claim_id)
    payload = LifeTerminalPayloadV1(binding.digest, prepared_digest, binding.execution_id, 1, claim.claim_digest,
        "completed", 4, binding.artifact_ref, hashlib.sha256(data).hexdigest(), len(data), None,
        END, "1", binding.postcondition_build_digest, D)
    return D11LifeTerminalV1(binding, claim, payload, claim.journal_id, 2, "sha256:" + "b" * 64,
        life_mutation_id_v1(binding, "terminal"))


@pytest.fixture
def case(tmp_path):
    store = GraphStore(tmp_path / "business.db", TypeRegistry())
    db = store._db
    install_d11_life_schema_v1(db)
    issuer = D11BudgetJobIssuer(D02ResourceIssuer(secrets.token_bytes(32)), secrets.token_bytes(32))
    b = _binding()
    source = SourceRecord("input-1", "Fixture source", "user-1", "reported", "confirmed", 0, 0,
        "fixture-source", ("audience-1",), ("context", "consolidation"),parent_source_ids=("parent-1",))
    source_json = canonical_serialize(source.to_dict())
    source_ref = source_key(*b.namespace.as_tuple, source.source_id).token
    from sylanne3.graph_types import Owner
    keys=[AtomKey(Owner('activity',*b.namespace.as_tuple,b.activity_id),kind,name) for kind,name in (
        ('d10.life_project.v1','project'),('d10.life_recipe.v1','recipe'),('d08.action_intent.v1','action:one'))]
    from sylanne3.domains.d08.execution import ActionIntent, GoalPredicate, RequiredCheckSpec
    from sylanne3.runtime_contracts import VersionedRef
    identity=OperationIdentity(activity_id=b.activity_id,effect_id=b.effect_id,attempt_id=b.attempt_id,phase='prepare_source_note_action',operation_id=b.operation_id,canonical_input_digest=D)
    action=ActionIntent(keys[2].name,1,'goal:fixture',(),'target:fixture','source_note','consolidation','internal',D,
        identity,'fixture.source-note.schema',(RequiredCheckSpec('fixture-check','fixture-provider','subject',keys[2].name,'consolidation','criteria',(VersionedRef('criteria',1),)),),
        GoalPredicate('artifact_verified','fixture-postcondition',(),0.,None),(b.artifact_ref,),None,(source_ref,))
    access=access_key(*b.namespace.as_tuple,source.source_id)
    values=[(AtomKey.from_token(source_ref),source_json),(access,canonical_serialize({'source_id':source.source_id,
        'audiences':list(source.audiences),'purposes':list(source.purposes),'status':'active','recorded_at':0.})),
        (keys[0],'{}'),(keys[1],'{}'),(keys[2],canonical_serialize(plain_v1(action)))]
    from sylanne3.graph_types import owner_grant_key
    values.append((owner_grant_key(*b.namespace.as_tuple),'{}'))
    parent=SourceRecord('parent-1','Fixture parent','user-1','reported','confirmed',0,0,'parent-root',source.audiences,source.purposes)
    values.extend(((source_key(*b.namespace.as_tuple,parent.source_id),canonical_serialize(parent.to_dict())),
        (access_key(*b.namespace.as_tuple,parent.source_id),canonical_serialize({'source_id':parent.source_id,'audiences':list(parent.audiences),'purposes':list(parent.purposes),'status':'active','recorded_at':0.}))))
    rows=tuple(OfflineTickGraphReadV1(key.token,1,value,True) for key,value in values)
    from sylanne3.domains.d06 import source_correction_head_key
    rows=(*rows,*(OfflineTickGraphReadV1(source_correction_head_key(b.namespace,identifier).token,0,'{}',False) for identifier in (source.source_id,parent.source_id)))
    refs=[LifeInputRefV1(key.token,1,canonical_digest(json.loads(value))) for key,value in values]
    plan=RegisteredLifePlanV2(refs[2],refs[3],refs[4],refs[0],refs[1],b.activity_id,b.effect_id,b.attempt_id,
        b.operation_id,('audience-1',),b.parent_budget_lease_ref,b.cpu_ceiling_ms,DEADLINE,D,D,None)
    b=replace(b,plan_digest=canonical_digest(plain_v1(plan)),input_digest=life_input_digest_v1(plan,source_json,rows))
    command=OperationIdentity(b.activity_id,b.effect_id,b.prepare_operation_id,'prepare_life',b.prepare_operation_id,D)
    prepared=D11LifePreparedV1(b,b.prepare_operation_id,plan,source_json,*('{}',)*9,rows,START,
        canonical_serialize(plain_v1(command)),D,'fixture-prepare-attempt')
    encoded=canonical_serialize(plain_v1(prepared));digest=prepared.digest
    signature=issuer._signer.sign(SIGN_KIND,canonical_serialize((b.namespace,'prepared',b.prepared_original_ref,digest)))
    db.execute('INSERT INTO '+TABLE+' VALUES(?,?,?,?,?,?,?,?)',(*b.namespace.as_tuple,'prepared',b.prepared_original_ref,
        b.prepare_operation_id,encoded,digest,signature))
    for key,value in values:
        db.execute('INSERT INTO graph_history VALUES(?,?,?,?,?,?,?,?,?)',(key.token,1,value,1,'[]',
            *b.namespace.as_tuple,b.activity_id,'fixture-input'))
    data = generate_source_note_bytes_v1(prepared)
    terminal = _terminal(b, data,prepared.digest)
    db.execute("BEGIN IMMEDIATE")
    create_budget_lease(db, BudgetLease("lease-1", None, "bot", "persona", "USD",
        {"thread_cpu_ms": 100}, {}, {}, {}, 1, "active"), "create-lease", D)
    reserve_budget(db, "lease-1", "reserve-1", D, {"thread_cpu_ms": 100})
    create_job(db, PersistentJob(b.job_id, b.operation_id, b.activity_id, b.effect_id, *b.namespace.as_tuple,
        "input-1", "queued", WORK_KIND, {}, None, DEADLINE, "lease-1", "quote-1", {}, None, None, 0, 0, {}, None),
        "create-job", D)
    acquire_job(db, b.job_id, b.job_holder, now_utc=START, lease_seconds=60)
    write_life_artifact_stage_v1(db, prepared, data)
    db.commit()
    value = SimpleNamespace(store=store, db=db, issuer=issuer, binding=b, prepared=prepared,
        terminal=terminal, data=data, path=tmp_path / "business.db")
    yield value
    store.close()


def _adopt_sql(case, *, wrong_job_result=False):
    """Seed actual receipt members, then exercise the real post-CAS SQL writer."""
    db, b, terminal = case.db, case.binding, case.terminal
    facts = life_fact_writes_v1(case.prepared, terminal.claim, terminal,
        (case.data, terminal.payload.artifact_digest, len(case.data)))
    artifact = next(w for w in facts if w.key.token == b.artifact_ref)
    mapping = life_job_result_binding_v1(terminal, artifact_graph_digest=canonical_digest(artifact.value))
    settle_budget(db, "lease-1", "reserve-1", D, {"thread_cpu_ms": 4}, execution_revoked=True)
    job = checkpoint_job(db, b.job_id, b.job_holder, 1, continuation={}, usage={"thread_cpu_ms": 4})
    job = transition_job(db, b.job_id, b.job_holder, 1, target_phase="completed",
        result_ref="wrong-but-ascii" if wrong_job_result else mapping["result_ref"])
    writes = (*facts, job_graph_write(job))
    operation = life_adoption_operation_id_v1(b)
    versions = tuple(GraphVersion(w.key, 2 if w.key.type_name == "runtime.job" else 1) for w in writes)
    reads=tuple(GraphVersion(AtomKey.from_token(row.ref),row.revision) for row in case.prepared.read_rows)
    receipt = CommitReceipt("committed", operation, D, b.activity_id, b.effect_id, 1, reads, versions, (), (), ())
    db.execute("INSERT INTO graph_events VALUES(?,?,?,?,?,?,?,?,?,?)",
        (*b.namespace.as_tuple, b.activity_id, operation, D, "[]", "[]", "[]", "[]", 1))
    db.execute("INSERT INTO graph_bundle_operations VALUES(?,?,?,?,?,?,?,?)",
        (*b.namespace.as_tuple, operation, D, b.activity_id, b.effect_id, 1, canonical_serialize(plain_v1(receipt))))
    for write, version in zip(writes, versions):
        db.execute("INSERT INTO graph_history(token,revision,value,valid,dependencies,event_bot,event_persona,event_session,event_id) VALUES(?,?,?,?,?,?,?,?,?)",
            (write.key.token, version.revision, canonical_serialize(write.value), 1,
                canonical_serialize([[key.token,dict((v.key.token,v.revision) for v in (*reads,*versions))[key.token]]
                    for key in sorted(write.dependencies,key=lambda k:k.token)]), *b.namespace.as_tuple, b.activity_id, operation))
    stage = SimpleNamespace(proposals=(SimpleNamespace(typed_writes=writes),))
    empty = SimpleNamespace(proposals=())
    staged = LifeTerminalBundleV1(None, empty, stage, terminal, case.prepared, (case.prepared.plan.input_source.ref,))
    record_life_terminal_after_cas_v1(db, issuer=case.issuer, staged=staged, graph_receipt=receipt)
    return receipt


def _read(case, db=None):
    return read_adopted_life_original_v1(db or case.db, namespace=case.binding.namespace,
        result_ref=case.binding.artifact_ref, issuer=case.issuer)


def _resign_fixture(case, value):
    """A trusted-but-mismatched original must still fail the independent joins."""
    wire, digest = canonical_serialize(value), canonical_digest(value)
    signature = case.issuer._signer.sign(SIGN_KIND,
        canonical_serialize((case.binding.namespace, "adopted_life", case.binding.artifact_ref, digest)))
    case.db.execute("UPDATE " + TABLE + " SET payload_json=?,payload_digest=?,signature=? WHERE kind='adopted_life'",
        (wire, digest, signature))


def test_signed_mapping_survives_cold_read_without_current_job_or_preparation(case):
    case.db.execute("BEGIN IMMEDIATE")
    _adopt_sql(case)
    adopted = _read(case)
    mapping = adopted["job_result_binding"]
    assert len(mapping["result_ref"]) == 80 and mapping["result_ref"].isascii()
    assert get_job(case.db, "job-1").result_ref == mapping["result_ref"]
    assert adopted["result_ref"] == case.binding.artifact_ref
    assert decode_life_original_content_v1("adopted_life", canonical_serialize(adopted)) == adopted
    # Historical result authentication uses committed member history, not today's job.
    case.db.execute("DELETE FROM runtime_jobs WHERE job_id='job-1'")
    case.db.commit()
    import sqlite3
    with sqlite3.connect(case.path.as_uri() + "?mode=ro", uri=True) as cold:
        cold.execute("PRAGMA query_only=ON")
        cold.execute("BEGIN")
        assert _read(case, cold) == adopted
        assert _read(case, cold) == adopted
        assert cold.total_changes == 0


@pytest.mark.parametrize("field,bad", [
    ("namespace", {"bot_id": "other-bot", "persona_id": "persona"}),
    ("activation_generation", 2), ("activation_generation", True),
    ("job_id", "other-job"), ("operation_id", "other-root"),
    ("producing_operation_id", "other-adoption"), ("execution_id", "other-execution"),
    ("artifact_ref", "other-ref"), ("artifact_name", "same-name-in-other-scope"),
    ("artifact_revision", 2), ("artifact_graph_digest", "c" * 64), ("artifact_digest", "d" * 64),
    ("artifact_length", 1), ("prepared_digest", "e" * 64),
    ("terminal_ref", "other-terminal"), ("terminal_digest", "f" * 64),
    ("result_ref", "wrong-but-ascii"),
])
def test_resigned_mapping_scope_tampering_is_rejected(case, field, bad):
    case.db.execute("BEGIN IMMEDIATE")
    _adopt_sql(case)
    value = deepcopy(_read(case))
    value["job_result_binding"][field] = bad
    _resign_fixture(case, value)
    with pytest.raises((ValueError, TypeError)):
        _read(case)
    with pytest.raises((ValueError, TypeError, DomainProductionErasureHold)):
        decode_life_original_content_v1("adopted_life", canonical_serialize(value))
    case.db.rollback()


def test_actual_artifact_member_rejects_self_consistent_mapping_of_another_digest(case):
    case.db.execute("BEGIN IMMEDIATE")
    _adopt_sql(case)
    value = _read(case)
    receipt = value["write_commitments"]
    artifact = json.loads(case.db.execute("SELECT value FROM graph_history WHERE token=?",
        (case.binding.artifact_ref,)).fetchone()[0])
    job_key = next(row["ref"] for row in receipt if AtomKey.from_token(row["ref"]).type_name == "runtime.job")
    job = json.loads(case.db.execute("SELECT value FROM graph_history WHERE token=?", (job_key,)).fetchone()[0])
    other = life_job_result_binding_v1(case.terminal, artifact_graph_digest="c" * 64)
    job["result_ref"] = other["result_ref"]
    with pytest.raises(ValueError, match="actual artifact member"):
        validate_life_job_result_members_v1(other, terminal=case.terminal,
            artifact_value=artifact, artifact_revision=1, job_value=job)
    case.db.rollback()


@pytest.mark.parametrize("fail_after_record", [False, True])
def test_mapping_failure_rolls_back_job_settlement_ledger_and_signed_original(case, fail_after_record):
    case.db.execute("BEGIN IMMEDIATE")
    with pytest.raises(ValueError):
        try:
            _adopt_sql(case, wrong_job_result=not fail_after_record)
            raise ValueError("simulated enclosing business failure after signed result")
        except BaseException:
            case.db.rollback()
            raise
    assert get_job(case.db, "job-1").phase == "running"
    assert get_job(case.db, "job-1").result_ref is None
    assert case.db.execute("SELECT state FROM runtime_budget_reservations WHERE operation_id='reserve-1'").fetchone() == ("reserved",)
    assert case.db.execute("SELECT COUNT(*) FROM runtime_budget_operations WHERE phase='settle'").fetchone() == (0,)
    assert case.db.execute("SELECT COUNT(*) FROM graph_bundle_operations").fetchone() == (0,)
    assert case.db.execute("SELECT COUNT(*) FROM " + TABLE + " WHERE kind='adopted_life'").fetchone() == (0,)
    assert case.db.execute("SELECT adopted_operation_id FROM graph_d11_life_artifact_stage_v1").fetchone() == (None,)


def test_a_committed_receipt_without_actual_ledger_is_rejected(case):
    case.db.execute("BEGIN IMMEDIATE")
    _adopt_sql(case)
    case.db.execute("DELETE FROM graph_bundle_operations")
    with pytest.raises(ValueError, match="actually committed"):
        _read(case)
    case.db.rollback()


def test_cross_namespace_same_name_does_not_bind_a_job(case):
    b = case.binding
    existing = AtomKey.from_token(b.artifact_ref)
    from sylanne3.graph_types import Owner
    other = NamespaceId("other-bot", "persona")
    same_name = AtomKey(Owner("activity", *other.as_tuple, b.effect_id), existing.type_name, existing.name)
    assert same_name.name == existing.name and same_name.token != existing.token
    with pytest.raises(ValueError, match="stable effect"):
        replace(b, namespace=other, artifact_ref=same_name.token)
    assert _binding(activation_generation=2).artifact_ref == b.artifact_ref
    other_terminal = _terminal(_binding(activation_generation=2), case.data)
    assert life_job_result_binding_v1(other_terminal, artifact_graph_digest=D)["result_ref"] != life_job_result_binding_v1(case.terminal, artifact_graph_digest=D)["result_ref"]


@pytest.mark.parametrize("field,bad", [("operation_id", "other-root"), ("job_id", "other-job"),
    ("result_ref", "other-result"), ("usage_digest", "c" * 64)])
def test_resigned_original_rejects_wrong_actual_historical_job_member(case, field, bad):
    case.db.execute("BEGIN IMMEDIATE")
    _adopt_sql(case)
    value = deepcopy(_read(case))
    row = next(r for r in value["write_commitments"] if AtomKey.from_token(r["ref"]).type_name == "runtime.job")
    old = case.db.execute("SELECT value FROM graph_history WHERE token=? AND revision=?",
        (row["ref"], row["revision"])).fetchone()[0]
    job = json.loads(old)
    job[field] = bad
    row["digest"] = canonical_digest(job)
    case.db.execute("UPDATE graph_history SET value=? WHERE token=? AND revision=?",
        (canonical_serialize(job), row["ref"], row["revision"]))
    _resign_fixture(case, value)
    with pytest.raises(ValueError, match="actual job member"):
        _read(case)
    case.db.rollback()


@pytest.mark.parametrize("changes", [{"bot_id": "other-bot"}, {"persona_id": "other-persona"},
    {"activity_id": "other-activity"}, {"effect_id": "other-effect"}, {"job_id": "other-job"},
    {"operation_id": "other-root"}, {"result_ref": "other-result"}, {"usage": {"thread_cpu_ms": 5}}])
def test_current_lineage_rejects_current_job_scope_or_result_tampering(case, changes):
    case.db.execute("BEGIN IMMEDIATE")
    _adopt_sql(case)
    value = _read(case)
    job = get_job(case.db, "job-1")
    assert validate_current_life_job_result_v1(job, adopted=value) == job.result_ref
    with pytest.raises(ValueError, match="current SQL job"):
        validate_current_life_job_result_v1(replace(job, **changes), adopted=value)
    case.db.rollback()


@pytest.mark.parametrize("untyped", (False, True))
def test_current_lineage_rejects_missing_or_untyped_sql_job(case, untyped):
    from sylanne3.runtime.d11_life_terminal_v1 import read_current_life_job_result_v1
    case.db.execute("BEGIN IMMEDIATE")
    _adopt_sql(case)
    value = _read(case)
    if untyped:
        job = SimpleNamespace(**vars(get_job(case.db, "job-1")))
    else:
        case.db.execute("DELETE FROM runtime_jobs WHERE job_id='job-1'")
        job = None
    with pytest.raises(ValueError, match="absent or untyped"):
        if untyped:
            validate_current_life_job_result_v1(job, adopted=value)
        else:
            read_current_life_job_result_v1(case.db, job_id="job-1", adopted=value)
    case.db.rollback()
