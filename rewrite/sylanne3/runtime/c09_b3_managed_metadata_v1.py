"""C09 proofs for B3 managed selectors, using actual captured W01 originals."""
import json
from ..graph_types import AtomKey,GraphVersion
from ..runtime_contracts import NamespaceId,canonical_digest,canonical_serialize
from .b3_managed_metadata_v1 import (JOINT_TABLE,HABIT_TABLE,TABLES,JOINT_SIGN,HABIT_SIGN,
    metadata_columns_v1,validate_managed_metadata_row_v1,retired_managed_metadata_row_v1,
    habit_managed_live_producer_commitment_v1,validate_managed_metadata_retirement_provenance_v1)
from .c09_paged_sql_v2 import C09PagedCaptureHold,c09_row_commitment_v2,_capture_write_v2

ORIGINAL_TABLE="graph_domain_production_originals_v1"
HABIT_POLICY_KIND="b3.habit-managed-policy-producer.v1"
HABIT_BIRTH_KIND="b3.habit-managed-generation-birth.v1"
HABIT_RETIRE_KIND="b3.habit-managed-business-retirement.v1"
JOINT_REG_KIND="b3.joint-window-managed-registration.v1"
JOINT_BIRTH_KIND="b3.joint-window-managed-birth.v1"
_LOOKUP_COLUMNS=("source_primary_key_json","row_commitment","original_commitment","origin_stream_id","origin_record_ordinal")
_ATTEMPT_COLUMNS=("bot","persona","operation_id","request_digest","attempt_id","anchor_json","graph_revision","graph_epoch","permit_json","receipt_json")
_FENCE_COLUMNS=("bot","persona","operation_id","digest","permit_json","pre_graph_revision","pre_graph_epoch",
    "post_graph_revision","post_graph_epoch","finish_request_id","finish_request_digest")

def _issuer(build):return build.session.get_c09_domain_original_issuer_v2()

def _joint_original_locator_v1(namespace,operation_id,kind,issuer):
    return canonical_digest(issuer._signer.sign(JOINT_SIGN,canonical_serialize((namespace,kind,operation_id))))

def _retired_locator_v1(selector,row_commitment):
    return canonical_digest(("b3.actual-business-retired-row.v1",selector,row_commitment))

def _policy_member_v1(payload,receipt):
    from ..domains.d10.habit_policy_v1 import HABIT_POLICY_TYPE,graph_adopted_habit_policy_from_wire_v1
    writes=tuple(w for w in payload["writes"]if AtomKey.from_token(w["key"]).type_name==HABIT_POLICY_TYPE)
    if len(writes)!=1:raise C09PagedCaptureHold("managed Habit original needs its one actual policy write")
    write=writes[0];key=AtomKey.from_token(write["key"]);policy=graph_adopted_habit_policy_from_wire_v1(write["value"])
    versions=tuple(v for v in receipt.write_versions if v.key==key)
    if len(versions)!=1 or versions[0].revision<1:
        raise C09PagedCaptureHold("managed Habit policy is absent from its actual COMMIT members")
    return key,policy,versions[0]

def _commit_parent_v1(build,shape,row,meter):
    from .domain_production_original_codec_v1 import ORIGINAL_COLUMNS,decode_domain_production_original_row_v1
    from .domain_production_originals_v1 import _receipt
    from ..authority_service.v2_contract import FencePermitV2,from_wire
    if shape.table!=ORIGINAL_TABLE or shape.columns!=ORIGINAL_COLUMNS:
        raise C09PagedCaptureHold("B3 metadata parent is not its fixed actual W01 original schema")
    ns=NamespaceId(*row[:2]);data=dict(zip(shape.columns,row,strict=True))
    decode_domain_production_original_row_v1(tuple(row),ns,registry=build.session._control.maintenance.graph._registry)
    payload=json.loads(data["original_payload_json"]);receipt=_receipt(json.loads(data["receipt_json"]))
    if(receipt.status!="committed"or receipt.commit_seq is None or receipt.commit_seq<1
            or receipt.operation_id!=data["operation_id"]or canonical_digest(receipt)!=data["receipt_digest"]):
        raise C09PagedCaptureHold("B3 metadata parent lacks an actual committed W01 receipt")
    operation=data["operation_id"];source=build.pair.source
    bundle_columns=("bot","persona","operation_id","digest","activity_id","effect_id","commit_seq","receipt_json")
    bundle=meter.read_fixed_row(source,"graph_bundle_operations",bundle_columns,
        "bot=? AND persona=? AND operation_id=?",(*ns.as_tuple,operation))
    if (bundle is None or bundle[:7]!=(*ns.as_tuple,operation,data["bundle_digest"],receipt.activity_id,receipt.effect_id,receipt.commit_seq)
            or _receipt(json.loads(bundle[7]))!=receipt):
        raise C09PagedCaptureHold("B3 metadata parent lost its actual bundle COMMIT four-tuple")
    attempt=meter.read_fixed_row(source,"graph_owner_domain_attempts_v3",_ATTEMPT_COLUMNS,
        "bot=? AND persona=? AND operation_id=?",(*ns.as_tuple,operation))
    fence=meter.read_fixed_row(source,"graph_bundle_fences_v2",_FENCE_COLUMNS,
        "bot=? AND persona=? AND operation_id=?",(*ns.as_tuple,operation))
    if(attempt is None or fence is None or attempt[3]!=data["request_digest"]or attempt[8]is None
            or attempt[9]is None or fence[3]!=data["bundle_digest"]or fence[4]!=attempt[8]
            or fence[5:7]!=attempt[6:8]or fence[7:9]!=(attempt[6]+1,attempt[7]+1)):
        raise C09PagedCaptureHold("B3 metadata actual Owner attempt/fence pre/post join differs")
    permit=from_wire(json.loads(attempt[8]))
    if(type(permit)is not FencePermitV2 or permit.operation!="write"or permit.operation_id!=attempt[4]
            or permit.generation!=payload["authority"]["activation_generation"]
            or json.loads(attempt[8])["pinned_anchor"]!=json.loads(attempt[5])):
        raise C09PagedCaptureHold("B3 metadata actual W01 permit/anchor differs")
    if attempt[4]!=operation and not attempt[4].startswith("foreground-domain-"):
        finish="sha256:"+canonical_digest({"schema":"w01.owner-domain-write.v3","operation_id":operation,
            "request_digest":data["request_digest"],"permit_token":permit.token})
    else:
        # Only an actually matching Self/Habit/foreground row takes this existing
        # independent Core path. Ordinary Owner policy rows never become FG DTOs.
        actual=build.session.read_finished_foreground_graph_original_v2(build.pair,tuple(attempt),meter=meter)
        if actual.row!=tuple(attempt)or actual.namespace!=ns or actual.operation_id!=operation:
            raise C09PagedCaptureHold("B3 metadata actual independently issued attempt differs")
        finish=actual.finish_digest
    if fence[9:]!=("finish:"+attempt[4],finish):
        raise C09PagedCaptureHold("B3 metadata actual W01 finish identity differs")
    saved=json.loads(attempt[9])
    if(saved.get("schema")!="sylanne.domain-production-receipt.v1"or saved.get("operation_id")!=operation
            or saved.get("original_digest")!=data["original_digest"]or saved.get("receipt_digest")!=canonical_digest(receipt)
            or saved.get("operation_kind")!=data["operation_kind"]or saved.get("domain")!=data["domain"]
            or saved.get("receipt")!=json.loads(data["receipt_json"])):
        raise C09PagedCaptureHold("B3 metadata attempt receipt is not its exact actual original output")
    side=(("graph_bundle_operations",bundle_columns,(*ns.as_tuple,operation),tuple(bundle)),
        ("graph_owner_domain_attempts_v3",_ATTEMPT_COLUMNS,(*ns.as_tuple,operation),tuple(attempt)),
        ("graph_bundle_fences_v2",_FENCE_COLUMNS,(*ns.as_tuple,operation),tuple(fence)))
    return ns,data,payload,receipt,side

def _index_entry_v1(build,shape,key,row,stream,ordinal,kind,ref,original_commitment):
    values=(build.scope.scope_digest,shape.table,row[0],row[1],kind,ref,canonical_serialize(key),
        c09_row_commitment_v2(tuple(row)),original_commitment,row[2],None,None,stream.stream_id,ordinal)
    _capture_write_v2(build.pair.candidate,"INSERT INTO c09_domain_original_lookup_v2 VALUES("+",".join("?"for _ in range(14))+")",values)

def index_b3_managed_original_v1(build,stream,shape,key,row,meter):
    if shape.table!=ORIGINAL_TABLE:return
    from .d10_habit_v1 import POLICY_OPERATIONS
    from .c09_paged_sql_v2 import current_c09_capture_row_position_v2
    data=dict(zip(shape.columns,row,strict=True));raw=json.loads(data["original_payload_json"])
    provenance=raw["provenance"]
    relevant=(data["operation_kind"]in POLICY_OPERATIONS or data["operation_kind"]=="prepare_joint_window_v1"
        or provenance.get("managed_window_argument")is not None)
    if not relevant:return
    actual_stream,ordinal=current_c09_capture_row_position_v2()
    if actual_stream!=stream.stream_id or tuple(key)!=tuple(row[:3])or not build.pair.candidate.in_transaction:
        raise C09PagedCaptureHold("B3 metadata lookup must commit with its actual captured source row")
    ns,data,payload,receipt,side=_commit_parent_v1(build,shape,tuple(row),meter);issuer=_issuer(build)
    operation=data["operation_id"];kind=data["operation_kind"]
    if kind in POLICY_OPERATIONS:
        if data["domain"]!="d10":raise C09PagedCaptureHold("Habit metadata producer crossed its fixed domain")
        key_policy,policy,version=_policy_member_v1(payload,receipt)
        locator=habit_managed_live_producer_commitment_v1(ns,operation,issuer=issuer)
        _index_entry_v1(build,shape,key,row,stream,ordinal,HABIT_POLICY_KIND,locator,data["original_digest"])
        target=payload["provenance"].get("habit_draft_managed_target")
        if target is not None:
            _index_entry_v1(build,shape,key,row,stream,ordinal,HABIT_BIRTH_KIND,target["selector_commitment"],data["original_digest"])
        if "managed_metadata_retirements_v1"in provenance:
            facts=validate_managed_metadata_retirement_provenance_v1(data["domain"],kind,payload["request"],provenance)
            for fact in facts:
                ref=_retired_locator_v1(fact["selector_commitment"],fact["new_row_commitment"])
                _index_entry_v1(build,shape,key,row,stream,ordinal,HABIT_RETIRE_KIND,ref,data["original_digest"])
    if kind=="prepare_joint_window_v1":
        ref=_joint_original_locator_v1(ns,operation,JOINT_REG_KIND,issuer)
        _index_entry_v1(build,shape,key,row,stream,ordinal,JOINT_REG_KIND,ref,data["original_digest"])
    if provenance.get("managed_window_argument")is not None:
        ref=_joint_original_locator_v1(ns,operation,JOINT_BIRTH_KIND,issuer)
        _index_entry_v1(build,shape,key,row,stream,ordinal,JOINT_BIRTH_KIND,ref,data["original_digest"])

def _read_indexed_parent_v1(build,namespace,kind,ref,meter):
    from .c09_graph_rebase_candidate_v2 import _actual_source_row_origin_v2
    from .c09_paged_sql_v2 import read_c09_table_shape_v2
    saved=meter.read_fixed_row(build.pair.candidate,"c09_domain_original_lookup_v2",_LOOKUP_COLUMNS,
        "scope_digest=? AND family=? AND bot=? AND persona=? AND kind=? AND original_ref=?",
        (build.scope.scope_digest,ORIGINAL_TABLE,*namespace.as_tuple,kind,ref))
    if saved is None:return None
    key=tuple(json.loads(saved[0]));shape=read_c09_table_shape_v2(build.pair.source,ORIGINAL_TABLE,meter=meter)
    row=meter.read_row(build.pair.source,shape,key)
    if row is None or c09_row_commitment_v2(tuple(row))!=saved[1]:
        raise C09PagedCaptureHold("B3 metadata lookup lost its actual frozen source parent")
    origin=_actual_source_row_origin_v2(build,shape,key,tuple(row),meter)
    if(origin["origin_stream_id"],origin["origin_record_ordinal"],origin["origin_commitment"])!=(saved[3],saved[4],saved[1]):
        raise C09PagedCaptureHold("B3 metadata parent lookup is outside its actual captured source member")
    ns,data,payload,receipt,side=_commit_parent_v1(build,shape,tuple(row),meter)
    from .d10_habit_v1 import POLICY_OPERATIONS
    if kind in {HABIT_POLICY_KIND,HABIT_BIRTH_KIND,HABIT_RETIRE_KIND}:
        if data["domain"]!="d10"or data["operation_kind"]not in POLICY_OPERATIONS:
            raise C09PagedCaptureHold("Habit metadata lookup points to another producer family")
        if kind==HABIT_POLICY_KIND:
            expected=habit_managed_live_producer_commitment_v1(ns,data["operation_id"],issuer=_issuer(build))
            if expected!=ref:raise C09PagedCaptureHold("Habit metadata source lookup has another opaque producer")
        elif kind==HABIT_BIRTH_KIND:
            target=payload["provenance"].get("habit_draft_managed_target")
            if type(target)is not dict or target.get("selector_commitment")!=ref:
                raise C09PagedCaptureHold("Habit metadata birth lookup has another real selector")
        else:
            facts=validate_managed_metadata_retirement_provenance_v1(data["domain"],data["operation_kind"],payload["request"],payload["provenance"])
            if len(tuple(f for f in facts if _retired_locator_v1(f["selector_commitment"],f["new_row_commitment"])==ref))!=1:
                raise C09PagedCaptureHold("Habit metadata retirement lookup has another exact opaque output")
    elif kind==JOINT_REG_KIND:
        if (data["domain"],data["operation_kind"])!=("d08","prepare_joint_window_v1")or _joint_original_locator_v1(ns,data["operation_id"],kind,_issuer(build))!=ref:
            raise C09PagedCaptureHold("Joint metadata registration lookup has another actual producer")
    elif kind==JOINT_BIRTH_KIND:
        if payload["provenance"].get("managed_window_argument")is None or _joint_original_locator_v1(ns,data["operation_id"],kind,_issuer(build))!=ref:
            raise C09PagedCaptureHold("Joint metadata birth lookup has another actual argument/producer")
    else:raise C09PagedCaptureHold("unknown fixed B3 metadata source lookup kind")
    if ns!=namespace or data["original_digest"]!=saved[2]:
        raise C09PagedCaptureHold("B3 metadata parent lookup crossed its actual namespace/original")
    for table,columns,sidekey,siderow in side:
        side_shape=read_c09_table_shape_v2(build.pair.source,table,meter=meter)
        if side_shape.columns!=columns:
            raise C09PagedCaptureHold("B3 metadata COMMIT side original schema differs")
        _actual_source_row_origin_v2(build,side_shape,sidekey,siderow,meter)
    return data,payload,receipt

def _habit_generation_descriptor_v1(build,namespace,parent,selector):
    data,payload,receipt=parent;key,policy,version=_policy_member_v1(payload,receipt)
    target=payload["provenance"].get("habit_draft_managed_target")
    fields={"selector_commitment","decision_ref","decision_digest","phase_selector_digest","future_identity_digest"}
    if(type(target)is not dict or set(target)!=fields or target["selector_commitment"]!=selector
            or target["decision_ref"]!=policy.definition.target_ref or policy.definition.executor_kind!="draft_file"):
        raise C09PagedCaptureHold("Habit managed selector has no unique actual generation birth descriptor")
    material=(namespace,"d10.habit-draft-selector.v1",target["decision_ref"],target["decision_digest"],
        target["phase_selector_digest"],target["future_identity_digest"])
    if canonical_digest(_issuer(build)._signer.sign(HABIT_SIGN,canonical_serialize(material)))!=selector:
        raise C09PagedCaptureHold("Habit generation birth changed its actual HMAC selector")
    return dict(target)

def _habit_policy_summary_v1(parent):
    data,payload,receipt=parent;key,policy,version=_policy_member_v1(payload,receipt);definition=policy.definition
    if policy.adoption_operation_id!=data["operation_id"]:
        raise C09PagedCaptureHold("Habit metadata actual adopted policy producer identity differs")
    return{"namespace":definition.namespace,"policy_ref":key.token,"policy_revision":definition.revision,
        "core_original_ref":policy.core_original_ref,"core_original_digest":policy.core_original_digest,
        "state":definition.state,"target_ref":definition.target_ref,"executor_kind":definition.executor_kind,
        "producer_operation_id":data["operation_id"],"producer_receipt_digest":canonical_digest(receipt)}

def _expected_habit_row_v1(build,policy,birth):
    if policy["executor_kind"]!="draft_file"or policy["target_ref"]!=birth["decision_ref"]:
        raise C09PagedCaptureHold("Habit current producer changed its actual selected managed generation")
    ns=policy["namespace"];body=(birth["selector_commitment"],birth["decision_ref"],birth["decision_digest"],
        birth["phase_selector_digest"],birth["future_identity_digest"],policy["policy_ref"],policy["policy_revision"],
        policy["core_original_ref"],policy["core_original_digest"],policy["state"],policy["producer_operation_id"],
        policy["producer_receipt_digest"],0)
    return(*ns.as_tuple,*body,_issuer(build)._signer.sign(HABIT_SIGN,canonical_serialize((ns,body))))

def _require_prior_retired_v1(build,table,key,row_commitment,meter):
    view=build.prior_view
    if view is None:return False
    from .c09_graph_originals_read_v5 import VerifiedPriorGraphCertificateViewV2,VerifiedPagedPriorGraphCertificateViewV2
    if type(view)is VerifiedPagedPriorGraphCertificateViewV2:
        reader=view.reader
        from .c09_graph_rebase_candidate_v2 import _read_graph_disposition_original_row_v3
        saved=_read_graph_disposition_original_row_v3(reader.pair.source,
            reader.certificate.candidate.scope.scope_digest,table,key,meter)
        matches=saved is not None and saved[6]==row_commitment
    elif type(view)is VerifiedPriorGraphCertificateViewV2:
        reader=view.reader
        manifest=meter.read_fixed_row(reader.pair.candidate,"c09_prior_graph_manifests_v2",("table_index",),
            "scope_digest=? AND certificate_operation_id=? AND table_name=?",(reader.scope,reader.operation,table))
        saved=None if manifest is None else meter.read_fixed_row(reader.pair.candidate,"c09_prior_graph_rows_v2",
            ("new_commitment",),"scope_digest=? AND certificate_operation_id=? AND table_index=? AND row_key_digest=?",
            (reader.scope,reader.operation,manifest[0],canonical_digest((table,key))))
        matches=saved==(row_commitment,)
    else:raise C09PagedCaptureHold("managed metadata prior view has no actual installed certificate type")
    if not matches:return False
    proof=view.require_target_row_disposition(table,key,row_commitment,meter=meter)
    if proof.disposition=="derived_removed"or proof.new_commitment!=row_commitment:
        raise C09PagedCaptureHold("opaque managed deny row is outside its actual prior sealed target")
    return True

def _joint_registration_row_v1(build,namespace,parent,value):
    from ..domains.d08.long_term_plan_v1 import JOINT_WINDOW_TYPE,long_term_value_from_wire_v1
    from .joint_window_management_v1 import managed_window_selector_digest_v1
    data,payload,receipt=parent
    if(data["domain"],data["operation_kind"])!=("d08","prepare_joint_window_v1"):
        raise C09PagedCaptureHold("managed Joint registration lacks its fixed actual producer")
    writes=tuple(w for w in payload["writes"]if w["key"]==value["window_ref"])
    if len(writes)!=1:raise C09PagedCaptureHold("managed Joint registration lost its actual window write")
    write=writes[0];key=AtomKey.from_token(write["key"]);window=long_term_value_from_wire_v1(JOINT_WINDOW_TYPE,write["value"])
    members=tuple(v for v in receipt.write_versions if v.key==key)
    nodes=tuple(n for n in window.node_drafts if n.node_id==value["node_id"])
    if len(members)!=1 or len(nodes)!=1 or window.namespace!=namespace:
        raise C09PagedCaptureHold("managed Joint node/window is outside actual COMMIT membership")
    node=nodes[0];selector=managed_window_selector_digest_v1(namespace,node.executor_kind,node.typed_request_ref,node.typed_input_original_digest)
    body=(selector,node.executor_kind,node.typed_request_ref,node.typed_input_original_digest,node.typed_request_digest,
        key.token,members[0].revision,canonical_digest(write["value"]),node.node_id,window.long_term_plan_ref,
        data["operation_id"],canonical_digest(receipt),None,None,None,None,0)
    return(*namespace.as_tuple,*body,_issuer(build)._signer.sign(JOINT_SIGN,canonical_serialize((namespace,body))))

def _joint_birth_row_v1(build,namespace,parent,registration,value):
    from .joint_window_management_v1 import managed_window_argument_from_wire_v1
    data,payload,receipt=parent
    argument=managed_window_argument_from_wire_v1(payload["provenance"]["managed_window_argument"])
    if(argument.executor_kind!=value["executor_kind"]or argument.window_ref!=value["window_ref"]
            or argument.node_id!=value["node_id"]or argument.typed_input_original_ref!=value["input_ref"]
            or argument.typed_input_original_digest!=value["input_digest"]or argument.typed_request_digest!=value["request_digest"]):
        raise C09PagedCaptureHold("managed Joint birth changed its actual registered window/input selector")
    if argument.executor_kind=="source_note":
        actions=tuple(w["key"]for w in payload["writes"]if AtomKey.from_token(w["key"]).type_name=="d08.action_intent.v1")
        if len(actions)!=1:raise C09PagedCaptureHold("managed SourceNote birth lacks its one actual Action member")
        action,binding=actions[0],None
    else:
        from .joint_node_execution_v1 import decode_joint_binding_v1
        actual=decode_joint_binding_v1(payload["request"]["binding"])
        action,binding=actual.action_ref,actual.original_ref
    if not any(v.key.token==action for v in receipt.write_versions):
        raise C09PagedCaptureHold("managed Joint birth Action was not in actual COMMIT membership")
    body=(*registration[2:-1][:12],action,binding,data["operation_id"],canonical_digest(receipt),0)
    return(*namespace.as_tuple,*body,_issuer(build)._signer.sign(JOINT_SIGN,canonical_serialize((namespace,body))))

_PROOF_ISSUER=object()
class _ManagedSourceRowProofV1:
    __slots__=("build","table","key","row","commitment","scope_pin","namespace","value","phase",
        "ready","policy","birth","retirement","registration","selector")
    def __init__(self,issuer,build,shape,key,row,meter):
        if issuer is not _PROOF_ISSUER:raise TypeError("actual private C09 managed source proof required")
        from .b3_managed_metadata_v1 import DDLS
        from .c09_graph_rebase_candidate_v2 import _actual_source_row_origin_v2
        actual=meter.read_fixed_row(build.pair.source,"sqlite_master",("sql",),"type=? AND name=?",("table",shape.table))
        if actual!=(DDLS[shape.table],)or tuple(key)!=tuple(row[:3]):
            raise C09PagedCaptureHold("managed metadata actual source schema/primary key differs")
        self.build,self.table,self.key,self.row=build,shape.table,tuple(key),tuple(row)
        self.commitment=c09_row_commitment_v2(self.row)
        self.scope_pin=(build.scope.scope_digest,build.pair.source_original.role_source_digest)
        self.namespace,self.value=validate_managed_metadata_row_v1(shape.table,shape.columns,self.row,issuer=_issuer(build))
        _actual_source_row_origin_v2(build,shape,self.key,self.row,meter)
        self.policy=self.birth=self.retirement=self.registration=None;self.ready=False
        self.selector=row[2]
        self.phase="prior"if self.value["retired"]else("policy"if shape.table==HABIT_TABLE else"joint_registration")

    def require_v1(self,build,shape,key,row):
        build.require_current()
        if(self.build is not build or self.table!=shape.table or self.key!=tuple(key)
                or self.scope_pin!=(build.scope.scope_digest,build.pair.source_original.role_source_digest)
                or self.commitment!=c09_row_commitment_v2(tuple(row))):
            raise C09PagedCaptureHold("managed metadata proof crossed its actual Source row/scope")
        return self

    def advance_v1(self,meter):
        build=self.build;issuer=_issuer(build);ns=self.namespace;value=self.value
        if self.ready:return True
        if self.phase=="prior":
            if _require_prior_retired_v1(build,self.table,self.key,self.commitment,meter):
                self.ready=True;return True
            if self.table!=HABIT_TABLE:
                raise C09PagedCaptureHold("opaque Joint deny has no actual prior sealed retirement target")
            self.phase="retirement";return False
        if self.phase=="retirement":
            parent=_read_indexed_parent_v1(build,ns,HABIT_RETIRE_KIND,_retired_locator_v1(self.selector,self.commitment),meter)
            if parent is None:raise C09PagedCaptureHold("opaque Habit deny lacks its actual business retirement or prior C09 output")
            data,payload,receipt=parent
            facts=validate_managed_metadata_retirement_provenance_v1(data["domain"],data["operation_kind"],payload["request"],payload["provenance"])
            actual=tuple(f for f in facts if f["table"]==HABIT_TABLE and f["selector_commitment"]==self.selector and f["new_row_commitment"]==self.commitment)
            if len(actual)!=1:raise C09PagedCaptureHold("opaque Habit deny is not the exact actual declared W01 retirement")
            new_policy=_habit_policy_summary_v1(parent)
            self.retirement={"fact":actual[0],"new_policy":new_policy};self.phase="policy";return False
        if self.phase=="policy":
            ref=(self.retirement["fact"]["old_producer_commitment"]if self.retirement is not None else
                habit_managed_live_producer_commitment_v1(ns,value["producer_operation_id"],issuer=issuer))
            parent=_read_indexed_parent_v1(build,ns,HABIT_POLICY_KIND,ref,meter)
            if parent is None:raise C09PagedCaptureHold("managed Habit row has no actual live policy producer")
            if habit_managed_live_producer_commitment_v1(ns,parent[0]["operation_id"],issuer=issuer)!=ref:
                raise C09PagedCaptureHold("managed Habit old producer HMAC locator differs")
            self.policy=_habit_policy_summary_v1(parent)
            if self.retirement is not None:
                new=self.retirement["new_policy"];old=self.policy
                if(new["policy_ref"]!=old["policy_ref"]or new["policy_revision"]!=old["policy_revision"]+1
                        or new["executor_kind"]=="draft_file"and new["target_ref"]==old["target_ref"]):
                    raise C09PagedCaptureHold("Habit retirement is not its actual changed executor/generation transition")
            self.phase="birth";return False
        if self.phase=="birth":
            parent=_read_indexed_parent_v1(build,ns,HABIT_BIRTH_KIND,self.selector,meter)
            if parent is None:raise C09PagedCaptureHold("managed Habit generation has no unique actual birth COMMIT")
            self.birth=_habit_generation_descriptor_v1(build,ns,parent,self.selector)
            if _policy_member_v1(parent[1],parent[2])[0].token!=self.policy["policy_ref"]:
                raise C09PagedCaptureHold("Habit birth belongs to another actual policy")
            expected=_expected_habit_row_v1(build,self.policy,self.birth)
            if self.retirement is None:
                if expected!=self.row:raise C09PagedCaptureHold("current Habit metadata differs from actual policy/birth outputs")
            else:
                fact=self.retirement["fact"]
                if c09_row_commitment_v2(expected)!=fact["old_row_commitment"]:
                    raise C09PagedCaptureHold("retired Habit old row has no actual producer/birth reconstruction")
                retired=retired_managed_metadata_row_v1(HABIT_TABLE,metadata_columns_v1(HABIT_TABLE),expected,issuer=issuer)
                if retired!=self.row or c09_row_commitment_v2(retired)!=fact["new_row_commitment"]:
                    raise C09PagedCaptureHold("Habit actual opaque retirement output differs")
            self.ready=True;return True
        if self.phase=="joint_registration":
            ref=_joint_original_locator_v1(ns,value["registration_operation_id"],JOINT_REG_KIND,issuer)
            parent=_read_indexed_parent_v1(build,ns,JOINT_REG_KIND,ref,meter)
            if parent is None:raise C09PagedCaptureHold("managed Joint selector has no actual window registration COMMIT")
            self.registration=_joint_registration_row_v1(build,ns,parent,value)
            if value["birth_operation_id"]is None:
                if self.registration!=self.row:raise C09PagedCaptureHold("managed Joint pending selector differs from actual registration")
                self.ready=True;return True
            self.phase="joint_birth";return False
        if self.phase=="joint_birth":
            ref=_joint_original_locator_v1(ns,value["birth_operation_id"],JOINT_BIRTH_KIND,issuer)
            parent=_read_indexed_parent_v1(build,ns,JOINT_BIRTH_KIND,ref,meter)
            if parent is None:raise C09PagedCaptureHold("managed Joint birth lacks actual W01 COMMIT")
            expected=_joint_birth_row_v1(build,ns,parent,self.registration,value)
            if expected!=self.row:raise C09PagedCaptureHold("managed Joint selector differs from actual registration/birth")
            self.ready=True;return True
        raise C09PagedCaptureHold("unknown fixed managed metadata proof phase")

def prepare_b3_managed_source_row_v1(build,shape,key,row,meter):
    if shape.table not in TABLES:return True
    build.require_current()
    proof=build.b3_managed_metadata_proof_v1
    if(proof is None or proof.table!=shape.table or proof.key!=tuple(key)
            or proof.commitment!=c09_row_commitment_v2(tuple(row))):
        proof=_ManagedSourceRowProofV1(_PROOF_ISSUER,build,shape,key,row,meter)
        build.b3_managed_metadata_proof_v1=proof
        return False
    proof.require_v1(build,shape,key,row)
    return proof.advance_v1(meter)

def require_b3_managed_source_row_v1(build,shape,key,row):
    proof=build.b3_managed_metadata_proof_v1
    if type(proof)is not _ManagedSourceRowProofV1 or not proof.ready:
        raise C09PagedCaptureHold("managed metadata row has not completed its actual fixed Source proof")
    return proof.require_v1(build,shape,key,row)

def validate_b3_managed_source_row_v1(session,shape,row):
    if shape.table not in TABLES:return False
    validate_managed_metadata_row_v1(shape.table,shape.columns,tuple(row),
        issuer=session.get_c09_domain_original_issuer_v2())
    return True

def _managed_affected_v1(proof,closure,nested_hit):
    if proof.namespace!=closure.namespace or proof.value["retired"]:return False
    value=proof.value
    if proof.table==HABIT_TABLE:
        refs=(value["policy_ref"],value["decision_ref"],value["core_original_ref"])
        operations=(value["producer_operation_id"],)
    else:
        refs=tuple(value[name]for name in("input_ref","window_ref","plan_ref","action_ref","binding_ref")if value[name]is not None)
        operations=tuple(value[name]for name in("registration_operation_id","birth_operation_id")if value[name]is not None)
    return(bool(nested_hit)or closure.contains_row(proof.table,proof.key)
        or any(closure.contains_atom(ref)for ref in refs)
        or any(closure.contains_operation(operation)for operation in operations))

def expand_b3_managed_metadata_closure_v1(build,shape,key,row,closure,nested_hit,origin):
    if shape.table not in TABLES:return False
    proof=require_b3_managed_source_row_v1(build,shape,key,row)
    if _managed_affected_v1(proof,closure,nested_hit):
        closure.add_row(shape.table,tuple(key),**origin)
    return True

def classify_b3_managed_metadata_row_v1(build,shape,key,row,closure,nested_hit):
    proof=require_b3_managed_source_row_v1(build,shape,key,row)
    if _managed_affected_v1(proof,closure,nested_hit):
        target=retired_managed_metadata_row_v1(shape.table,shape.columns,tuple(row),issuer=_issuer(build))
        # The normal C09 row publisher commits this exact source/target pair,
        # its old/new commitments and the source stream member in one SQL TX.
        return"payload_erased_retained_facts",target
    return"preserved_exact",tuple(row)

def require_b3_managed_target_row_v1(progress,shape,key,row,meter):
    if shape.table not in TABLES:return False
    validate_managed_metadata_row_v1(shape.table,shape.columns,tuple(row),
        issuer=progress.session.get_c09_domain_original_issuer_v2())
    if not progress.source_semantic_eof:
        raise C09PagedCaptureHold("managed target cannot precede the actual independent source semantic EOF")
    saved=meter.read_fixed_row(progress.read_db,"c09_graph_dispositions_v2",
        ("source_primary_key_json","old_commitment","disposition","new_commitment","origin_stream_id","origin_record_ordinal"),
        "scope_digest=? AND table_name=? AND key_digest=?",
        (progress.session.scope.scope_digest,shape.table,canonical_digest((shape.table,tuple(key)))))
    if(saved is None or saved[0]!=canonical_serialize(tuple(key))or saved[3]!=c09_row_commitment_v2(tuple(row))
            or saved[2]not in{"preserved_exact","payload_erased_retained_facts"}):
        raise C09PagedCaptureHold("managed target has no exact independently recomputed source disposition")
    from .c09_paged_sql_v2 import require_c09_capture_member_v2,read_c09_table_shape_v2
    from .c09_graph_rebase_candidate_v2 import _actual_source_locator_v2
    source_shape=read_c09_table_shape_v2(progress.pair.source,shape.table,meter=meter)
    locator=_actual_source_locator_v2(progress.cold_build,source_shape,meter)
    if locator.identity.stream_id!=saved[4]:
        raise C09PagedCaptureHold("managed target Source origin changed its actual sealed stream")
    require_c09_capture_member_v2(progress.read_db,locator.identity,saved[5],tuple(key),saved[1],meter=meter)
    if saved[2]=="payload_erased_retained_facts":
        values=dict(zip(shape.columns,row,strict=True))
        if values["retired"]!=1:
            raise C09PagedCaptureHold("erased managed metadata did not preserve its opaque deny state")
    return True

def require_b3_managed_schema_object_v1(original):
    if original.table_name not in TABLES:return False
    from .b3_managed_metadata_v1 import DDLS
    if original.object_type!="table"or original.name!=original.table_name or original.sql!=DDLS[original.table_name]:
        raise C09PagedCaptureHold("managed metadata requires its exact fixed installed schema object")
    return True
