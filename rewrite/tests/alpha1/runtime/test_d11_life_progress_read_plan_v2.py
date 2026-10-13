"""Real typed Life planning separates project originals from D06 roots."""
import pytest

from test_d11_life_job_result_binding_v1 import case, _adopt_sql
from sylanne3.graph_types import AtomKey, Owner
from sylanne3.runtime_contracts import canonical_serialize
from sylanne3.runtime.d11_life_contract_v1 import RegisteredLifeOutcomeV2
from sylanne3.runtime.d11_life_preparation_v1 import _record
from sylanne3.runtime.d11_life_outcome_provenance_v1 import life_outcome_key_v1
from sylanne3.runtime.d10_production_operations_v1 import AdvanceCurrentLifeRequestV1
from sylanne3.runtime.domain_production_read_plans_v1 import read_plan_current_domain_operation_v1


def seed(case):
    db=case.db;ns=case.binding.namespace
    for row in case.prepared.read_rows:
        if not row.revision:continue
        key=AtomKey.from_token(row.ref)
        db.execute('INSERT INTO graph_atoms VALUES(?,?,?,?,?,?,?,?,?,?)',
            (key.token,*ns.as_tuple,key.owner.kind,key.owner.subject,key.type_name,key.name,1,row.value_json,1))
    key=AtomKey(Owner('persona',*ns.as_tuple),'d03.entity_anchor','entity:fixture')
    raw={'entity_id':'target:fixture','entity_kind':'activity','owner_scope':'persona:'+ns.persona_id,
        'creation_evidence_refs':[case.prepared.plan.project.ref,case.prepared.plan.input_source.ref],'status':'active'}
    db.execute('INSERT INTO graph_atoms VALUES(?,?,?,?,?,?,?,?,?,?)',
        (key.token,*ns.as_tuple,key.owner.kind,key.owner.subject,key.type_name,key.name,1,canonical_serialize(raw),1))
    return key


def read(case,request):
    return read_plan_current_domain_operation_v1(case.db,namespace=case.binding.namespace,
        activity_id=case.binding.activity_id,domain='d10',operation_kind='advance_life',request=request)


def test_real_v2_planner_retains_project_original_full_queries_and_source_roots(case):
    case.db.execute('BEGIN IMMEDIATE');entity=seed(case);_adopt_sql(case)
    b=case.binding;p=case.prepared.plan
    _record(case.db,issuer=case.issuer,namespace=b.namespace,kind='plan',ref=b.plan_original_ref,
        operation_id=b.operation_id,value=p)
    cost=AtomKey(Owner('activity',*b.namespace.as_tuple,b.activity_id),'runtime.cost_settlement','settlement:fixture')
    outcome=RegisteredLifeOutcomeV2(b.plan_original_ref,life_outcome_key_v1(b,p.action_intent.ref).token,
        case.terminal.claim.original_ref,case.terminal.original_ref,b.artifact_ref,
        case.terminal.payload.artifact_digest,(cost.token,))
    _record(case.db,issuer=case.issuer,namespace=b.namespace,kind='outcome',ref='outcome:fixture',
        operation_id='outcome-operation',value=outcome)
    actual=read(case,AdvanceCurrentLifeRequestV1(p.project.ref,'outcome:fixture'))
    assert all(AtomKey.from_token(ref).type_name=='memory.source' for ref in actual.source_roots)
    assert p.input_source.ref in actual.source_roots and p.project.ref in actual.required_original_refs
    assert AtomKey.from_token(p.project.ref) in actual.exact_keys
    assert {'d03.entity_anchor','d03.role_binding','d05.boundary_rule','d08.action_outcome.v1','d02.body_state.v1'}<=set(actual.fixed_type_ids)
    assert any(key.type_name=='d11.life_outcome_eligibility.v1' for key in actual.exact_keys)
    case.db.rollback()


def test_absent_v2_original_still_uses_strict_generic_source_contract(case):
    case.db.execute('BEGIN IMMEDIATE');seed(case)
    request=AdvanceCurrentLifeRequestV1(case.prepared.plan.project.ref,'missing-outcome')
    from sylanne3.runtime.d10_production_operations_v1 import read_plan_current_d10_operation_v1
    generic=read_plan_current_d10_operation_v1(case.db,namespace=case.binding.namespace,
        activity_id=case.binding.activity_id,operation_kind='advance_life',request=request)
    assert read(case,request)==generic
    assert 'missing-outcome' in generic.required_original_refs
    from sylanne3.runtime.d01_production_operations_v1 import production_read_plan_v1
    with pytest.raises(ValueError,match='source roots require exact D06'):
        production_read_plan_v1(generic.fixed_type_ids,generic.exact_keys,
            (case.prepared.plan.project.ref,),generic.required_original_refs)
    case.db.rollback()


def test_untyped_request_cannot_select_installed_v2_planner(case):
    case.db.execute('BEGIN IMMEDIATE');seed(case)
    from types import SimpleNamespace
    with pytest.raises(ValueError):read(case,SimpleNamespace(project_ref=case.prepared.plan.project.ref,activity_outcome_ref='fake'))
    case.db.rollback()


def test_exact_external_original_reader_sqlite_transaction_and_foreign_type(tmp_path):
    """Source-seam signing/typing regression; no Native or Authority qualification."""
    import json
    import secrets
    import sqlite3
    from sylanne3.runtime_contracts import NamespaceId, canonical_digest, canonical_serialize
    from sylanne3.runtime.issuers import D02ResourceIssuer, D11BudgetJobIssuer
    from sylanne3.runtime.d05_production_operations_v1 import InstalledD05ProductionReadersV1
    from sylanne3.runtime.domain_production_contracts_v1 import ProductionOriginalRefV1, ProductionReadPlanV1
    from sylanne3.runtime.domain_production_read_plans_v1 import read_current_domain_original_refs_v1

    issuer = D11BudgetJobIssuer(D02ResourceIssuer(secrets.token_bytes(32)), secrets.token_bytes(32))
    readers = InstalledD05ProductionReadersV1(issuer=issuer)
    namespace = NamespaceId("reader-source-bot", "reader-source-persona")
    # This is a declared local signing fixture. It makes no trusted-time or
    # independent Authority claim; authentication here is the actual D11 signer.
    payload = canonical_serialize({"schema": "fixture.d11.external-reader-original.v1",
        "namespace": namespace.as_tuple, "original_ref": "fixture:external-reader:one"})
    signing_domain = "fixture.d11.external-reader-original.v1"
    signature = issuer._signer.sign(signing_domain, payload)
    with sqlite3.connect(tmp_path / "external-original-reader.sqlite") as db:
        db.execute("CREATE TABLE fixture_external_original (original_ref TEXT PRIMARY KEY, payload_json TEXT NOT NULL, signature TEXT NOT NULL)")
        db.execute("INSERT INTO fixture_external_original VALUES(?,?,?)", ("fixture:external-reader:one", payload, signature))
        db.commit()
        db.execute("BEGIN IMMEDIATE")
        try:
            ref, encoded, saved_signature = db.execute("SELECT original_ref,payload_json,signature FROM fixture_external_original").fetchone()
            issuer._signer.verify(signing_domain, encoded, saved_signature)
            original = ProductionOriginalRefV1("d11.clock_sample", ref, canonical_digest(json.loads(encoded)))
            plan = ProductionReadPlanV1((), (), (), ())
            actual = read_current_domain_original_refs_v1(db, namespace=namespace, plan=plan,
                installed_readers=readers, authenticated_external_originals=(original,))
            assert actual == (original,)
            with pytest.raises(TypeError, match="outside-transaction originals"):
                read_current_domain_original_refs_v1(db, namespace=namespace, plan=plan, installed_readers=readers,
                    authenticated_external_originals=({"kind": original.kind, "original_ref": original.original_ref,
                        "original_digest": original.original_digest, "read_versions": ()},))
        finally:
            db.rollback()
