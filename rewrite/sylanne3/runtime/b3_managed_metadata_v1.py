"""Fixed B3 managed selector metadata and actual retirement row commitments."""
from ..runtime_contracts import NamespaceId,canonical_digest,canonical_serialize
from .c09_paged_sql_v2 import c09_row_commitment_v2

JOINT_TABLE="graph_joint_window_managed_guards_v1"
HABIT_TABLE="graph_habit_managed_execution_v1"
JOINT_SIGN="d11.joint-window-managed-guard.v1"
HABIT_SIGN="d11.habit-managed-execution-metadata.v1"
JOINT_FIELDS=("selector_digest","executor_kind","input_ref","input_digest","request_digest","window_ref",
    "window_birth_revision","window_birth_digest","node_id","plan_ref","registration_operation_id",
    "registration_receipt_digest","action_ref","binding_ref","birth_operation_id","birth_receipt_digest","retired","signature")
HABIT_FIELDS=("selector_commitment","decision_ref","decision_digest","phase_selector_digest","future_identity_digest",
    "policy_ref","policy_revision","core_original_ref","core_original_digest","current_state",
    "producer_operation_id","producer_receipt_digest","retired","signature")
TABLES=frozenset({JOINT_TABLE,HABIT_TABLE})
DDLS={
 JOINT_TABLE:"CREATE TABLE "+JOINT_TABLE+" (bot TEXT NOT NULL,persona TEXT NOT NULL,selector_digest TEXT NOT NULL,executor_kind TEXT,input_ref TEXT,input_digest TEXT,request_digest TEXT,window_ref TEXT,window_birth_revision INTEGER,window_birth_digest TEXT,node_id TEXT,plan_ref TEXT,registration_operation_id TEXT,registration_receipt_digest TEXT,action_ref TEXT,binding_ref TEXT,birth_operation_id TEXT,birth_receipt_digest TEXT,retired INTEGER NOT NULL,signature TEXT NOT NULL,PRIMARY KEY(bot,persona,selector_digest))",
 HABIT_TABLE:"CREATE TABLE "+HABIT_TABLE+" (bot TEXT NOT NULL,persona TEXT NOT NULL,selector_commitment TEXT NOT NULL,decision_ref TEXT,decision_digest TEXT,phase_selector_digest TEXT,future_identity_digest TEXT,policy_ref TEXT,policy_revision INTEGER,core_original_ref TEXT,core_original_digest TEXT,current_state TEXT NOT NULL,producer_operation_id TEXT,producer_receipt_digest TEXT,retired INTEGER NOT NULL,signature TEXT NOT NULL,PRIMARY KEY(bot,persona,selector_commitment))",
}

def metadata_columns_v1(table):
    if table==JOINT_TABLE:return("bot","persona",*JOINT_FIELDS)
    if table==HABIT_TABLE:return("bot","persona",*HABIT_FIELDS)
    raise ValueError("unregistered B3 managed metadata table")

def install_managed_metadata_table_v1(db,table):
    """One canonical DDL; the actual installed caller owns its transaction and commit."""
    if table not in TABLES:raise ValueError("unregistered B3 managed metadata table")
    ddl=DDLS[table]
    current=db.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name=?",(table,)).fetchone()
    if current is None:db.execute(ddl)
    elif current!=(ddl,):raise ValueError("installed B3 managed metadata schema differs")

def install_b3_managed_metadata_for_registry_v1(db,registry):
    installed={spec.name for spec in registry.specs}
    required={JOINT_TABLE:"d08.joint_window.v1",HABIT_TABLE:"d10.habit_policy.v1"}
    for table,type_name in required.items():
        if type_name not in installed:continue
        install_managed_metadata_table_v1(db,table)

def _sha(value):
    if type(value)is not str or len(value)!=64 or any(c not in"0123456789abcdef"for c in value):
        raise ValueError("managed metadata requires its exact SHA256 commitment")
    return value

def _text(value):
    if type(value)is not str or not value:raise ValueError("managed metadata requires its real locator")
    return value

def _namespace_ref(namespace,ref,type_name):
    from ..graph_types import AtomKey
    key=AtomKey.from_token(ref)
    if NamespaceId.from_key(key)!=namespace or key.type_name!=type_name:
        raise ValueError("managed metadata locator crossed its fixed namespace/type")
    return key

def validate_managed_metadata_row_v1(table,columns,row,*,issuer):
    expected=metadata_columns_v1(table)
    if tuple(columns)!=expected or len(row)!=len(expected):
        raise ValueError("managed metadata exact columns differ")
    value=dict(zip(expected,row,strict=True));ns=NamespaceId(value["bot"],value["persona"])
    fields=JOINT_FIELDS if table==JOINT_TABLE else HABIT_FIELDS
    sign=JOINT_SIGN if table==JOINT_TABLE else HABIT_SIGN
    body=tuple(row[2:-1]);issuer._signer.verify(sign,canonical_serialize((ns,body)),row[-1])
    _sha(body[0])
    if type(value["retired"])is not int or value["retired"]not in(0,1):
        raise ValueError("managed metadata retirement state differs")
    if value["retired"]:
        remaining=tuple(value[name]for name in fields[1:-2])if table==JOINT_TABLE else(
            *(value[name]for name in HABIT_FIELDS[1:9]),value["producer_operation_id"],value["producer_receipt_digest"])
        if any(v is not None for v in remaining)or table==HABIT_TABLE and value["current_state"]!="retired":
            raise ValueError("retired managed metadata retained plaintext locators")
        return ns,value
    if table==JOINT_TABLE:
        from .joint_window_management_v1 import MANAGED_EXECUTORS,managed_window_selector_digest_v1
        if value["executor_kind"]not in MANAGED_EXECUTORS:
            raise ValueError("managed window executor is not a fixed local family")
        for name in("input_ref","window_ref","node_id","plan_ref","registration_operation_id"):_text(value[name])
        for name in("input_digest","request_digest","window_birth_digest","registration_receipt_digest"):_sha(value[name])
        if type(value["window_birth_revision"])is not int or value["window_birth_revision"]<1:
            raise ValueError("managed window birth revision differs")
        _namespace_ref(ns,value["window_ref"],"d08.joint_window.v1")
        _namespace_ref(ns,value["plan_ref"],"d08.long_term_plan.v1")
        selector=managed_window_selector_digest_v1(ns,value["executor_kind"],value["input_ref"],value["input_digest"])
        if selector!=value["selector_digest"]:raise ValueError("managed window selector commitment differs")
        birth=tuple(value[name]for name in("action_ref","binding_ref","birth_operation_id","birth_receipt_digest"))
        if birth[2]is None:
            if any(v is not None for v in birth):raise ValueError("managed window fictional partial birth")
        else:
            _text(birth[2]);_sha(birth[3]);_namespace_ref(ns,birth[0],"d08.action_intent.v1")
            if value["executor_kind"]=="source_note":
                if birth[1]is not None:raise ValueError("SourceNote management cannot borrow a Joint binding")
            else:_text(birth[1])
    else:
        for name in("decision_ref","policy_ref","core_original_ref","producer_operation_id"):_text(value[name])
        for name in("decision_digest","phase_selector_digest","future_identity_digest","core_original_digest","producer_receipt_digest"):_sha(value[name])
        if type(value["policy_revision"])is not int or value["policy_revision"]<1 or value["current_state"]not in{"enabled","paused","stopped","superseded"}:
            raise ValueError("managed Habit actual policy state/revision differs")
        _namespace_ref(ns,value["policy_ref"],"d10.habit_policy.v1")
        material=(ns,"d10.habit-draft-selector.v1",value["decision_ref"],value["decision_digest"],value["phase_selector_digest"],value["future_identity_digest"])
        selector=canonical_digest(issuer._signer.sign(HABIT_SIGN,canonical_serialize(material)))
        if selector!=value["selector_commitment"]:raise ValueError("managed Habit selector commitment differs")
    return ns,value

def retired_managed_metadata_row_v1(table,columns,row,*,issuer):
    ns,value=validate_managed_metadata_row_v1(table,columns,row,issuer=issuer)
    if table==JOINT_TABLE:
        body=(value["selector_digest"],*([None]*15),1);kind=JOINT_SIGN
    else:
        body=(value["selector_commitment"],*([None]*8),"retired",None,None,1);kind=HABIT_SIGN
    return(*ns.as_tuple,*body,issuer._signer.sign(kind,canonical_serialize((ns,body))))

def habit_managed_live_producer_commitment_v1(namespace,operation_id,*,issuer):
    _text(operation_id)
    material=(namespace,"d10.habit-managed-live-producer.v1",operation_id)
    return canonical_digest(issuer._signer.sign(HABIT_SIGN,canonical_serialize(material)))

def managed_metadata_retirement_fact_v1(table,columns,row,*,issuer):
    ns,value=validate_managed_metadata_row_v1(table,columns,row,issuer=issuer)
    if value["retired"]:raise ValueError("business retirement cannot reissue an opaque deny row")
    if table!=HABIT_TABLE:raise ValueError("business retirement facts belong to the fixed Habit policy producer")
    retired=retired_managed_metadata_row_v1(table,columns,row,issuer=issuer)
    producer=habit_managed_live_producer_commitment_v1(ns,value["producer_operation_id"],issuer=issuer)
    return{"table":table,"selector_commitment":row[2],"old_row_commitment":c09_row_commitment_v2(tuple(row)),
        "new_row_commitment":c09_row_commitment_v2(retired),"old_producer_commitment":producer}

def validate_managed_metadata_retirement_facts_v1(raw):
    if type(raw)is not list:raise ValueError("managed retirement provenance must be its fixed tuple array")
    result=[];seen=set()
    for fact in raw:
        if(type(fact)is not dict or set(fact)!={"table","selector_commitment","old_row_commitment","new_row_commitment","old_producer_commitment"}
                or fact["table"]not in TABLES):
            raise ValueError("managed retirement provenance fields differ")
        key=(fact["table"],_sha(fact["selector_commitment"]))
        if key in seen:raise ValueError("managed retirement repeats its selected row")
        seen.add(key)
        for name in("old_row_commitment","new_row_commitment","old_producer_commitment"):_sha(fact[name])
        result.append(dict(fact))
    return tuple(result)

def _policy_metadata_rows_v1(db,namespace,policy_ref):
    from ..runtime_storage_v3 import runtime_storage_quantum_v3,_runtime_bounded_fixed_row_v3
    columns=metadata_columns_v1(HABIT_TABLE);after="";rows=[]
    with runtime_storage_quantum_v3(db)as meter:
        while True:
            row=_runtime_bounded_fixed_row_v3(db,meter,HABIT_TABLE,columns,
                "bot=? AND persona=? AND policy_ref=? AND selector_commitment>? ORDER BY selector_commitment",
                (*namespace.as_tuple,policy_ref,after))
            if row is None:return tuple(rows)
            rows.append(tuple(row));after=row[2]
            if len(rows)>1:raise ValueError("Habit policy has more than one current managed generation")

def prepare_habit_managed_metadata_retirements_v1(db,*,namespace,policy_ref,new_executor_kind,new_target_ref,issuer):
    facts=[]
    for row in _policy_metadata_rows_v1(db,namespace,policy_ref):
        actual,value=validate_managed_metadata_row_v1(HABIT_TABLE,metadata_columns_v1(HABIT_TABLE),row,issuer=issuer)
        if actual!=namespace or value["retired"]:
            raise ValueError("Habit policy query selected another namespace or an opaque retired row")
        if new_executor_kind!="draft_file"or value["decision_ref"]!=new_target_ref:
            facts.append(managed_metadata_retirement_fact_v1(HABIT_TABLE,metadata_columns_v1(HABIT_TABLE),row,issuer=issuer))
    return tuple(facts)

def decode_managed_metadata_retirement_shape_v1(domain,kind,retirement_raw):
    from .d10_habit_v1 import POLICY_OPERATIONS
    if domain!="d10"or kind not in POLICY_OPERATIONS:
        raise ValueError("managed retirement shape belongs to the fixed Habit policy producers")
    facts=validate_managed_metadata_retirement_facts_v1(retirement_raw)
    if any(fact["table"]!=HABIT_TABLE for fact in facts)or len(facts)>1:
        raise ValueError("Habit policy retirement shape permits only its one actual prior managed generation")
    return facts

def validate_managed_metadata_retirement_provenance_v1(domain,kind,request,provenance):
    from .d10_habit_v1 import POLICY_OPERATIONS
    from ..domains.d10.habit_policy_v1 import HabitPolicyDefinitionV1
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    if(domain!="d10"or kind not in POLICY_OPERATIONS or type(provenance)is not dict
            or "managed_metadata_retirements_v1"not in provenance):
        raise ValueError("managed retirement provenance belongs to its exact Habit policy producer")
    definition=decode_typed_production_value_v1(request["definition"],HabitPolicyDefinitionV1)
    return decode_managed_metadata_retirement_shape_v1(domain,kind,provenance["managed_metadata_retirements_v1"])

def apply_habit_managed_metadata_retirements_after_cas_v1(db,*,witness,primary,receipt,issuer):
    from .domain_production_commit_v1 import _ProductionCommitWitnessV1,_ACTIVE,_members
    from .d10_habit_v1 import POLICY_OPERATIONS
    from ..domains.d01.production_operations_v1 import plain_v1
    from ..domains.d10.habit_policy_v1 import HABIT_POLICY_TYPE,graph_adopted_habit_policy_from_wire_v1
    import json
    if(type(witness)is not _ProductionCommitWitnessV1 or _ACTIVE.get(id(witness))is not witness
            or _members(witness.stage)[0]is not primary or primary.operation_kind not in POLICY_OPERATIONS
            or db is not witness.graph._GraphCoordinator__store._db or not db.in_transaction
            or not witness.graph._GraphCoordinator__store._lock._is_owned()
            or receipt.status!="committed"or receipt.operation_id!=primary.operation_id
            or witness.operation.operation_kind!=primary.operation_kind):
        raise ValueError("managed retirement requires its actual same-CAS private policy witness")
    payload=json.loads(primary.original_payload_json)
    if canonical_digest(plain_v1(witness.request))!=canonical_digest(payload["request"]):
        raise ValueError("managed retirement changed its exact actual typed policy command")
    declared=validate_managed_metadata_retirement_provenance_v1(primary.domain,primary.operation_kind,
        payload["request"],payload["provenance"])
    writes=tuple(w for p in primary.proposals for w in p.typed_writes if w.key.type_name==HABIT_POLICY_TYPE)
    if len(writes)!=1:raise ValueError("managed retirement needs its one actual adopted policy member")
    write=writes[0];policy=graph_adopted_habit_policy_from_wire_v1(write.value);definition=policy.definition
    if not any(v.key==write.key for v in receipt.write_versions):
        raise ValueError("managed retirement policy was not in its actual COMMIT")
    expected=prepare_habit_managed_metadata_retirements_v1(db,namespace=definition.namespace,
        policy_ref=write.key.token,new_executor_kind=definition.executor_kind,new_target_ref=definition.target_ref,issuer=issuer)
    if tuple(declared)!=expected:raise ValueError("managed retirement selectors changed after their actual pre-CAS declaration")
    columns=metadata_columns_v1(HABIT_TABLE);written=[]
    for fact in declared:
        row=next(row for row in _policy_metadata_rows_v1(db,definition.namespace,write.key.token)if row[2]==fact["selector_commitment"])
        if c09_row_commitment_v2(row)!=fact["old_row_commitment"]:
            raise ValueError("managed retirement actual old row commitment differs")
        updated=retired_managed_metadata_row_v1(HABIT_TABLE,columns,row,issuer=issuer)
        if c09_row_commitment_v2(updated)!=fact["new_row_commitment"]:
            raise ValueError("managed retirement actual signed opaque output commitment differs")
        db.execute("UPDATE "+HABIT_TABLE+" SET "+",".join(name+"=?"for name in HABIT_FIELDS[1:])+
            " WHERE bot=? AND persona=? AND selector_commitment=?",(*updated[3:],*definition.namespace.as_tuple,updated[2]))
        written.append(updated[2])
    return tuple(written)
