"""Two actual Native Life consumers on the ordinary Numeric Source READ kernel."""
from dataclasses import dataclass,replace
from weakref import WeakKeyDictionary

from ..authority_service.contract import AuthorityUnavailable
from ..authority_service.d04_numeric_contract_v3 import D04NumericBindingV3,from_wire
from ..graph_types import AtomKey
from ..runtime_contracts import NamespaceId,canonical_digest,canonical_serialize
from ..runtime_storage_v3 import runtime_storage_quantum_v3,_runtime_bounded_fixed_row_v3
from .current_life_numeric_read_v3 import (require_numeric_read_work_v3,_NumericWireProjectionV3,
    _version_key,_current_read_now)
from .current_life_numeric_metadata_v1 import _NumericMetadataColumnV1,_metadata
from .dispatch_current_inventory_v3 import _heap,_detach_value_v3
from .d06_life_numeric_joint_v1 import PrepareLifeNumericJointRequestV1,life_numeric_joint_ids_v1
from .d06_life_numeric_trace_v1 import AdoptLifeNumericTraceRequestV1,life_numeric_trace_keys_v1,life_numeric_trace_operation_v1
from .d04_life_encoding_baseline_v1 import life_encoding_baseline_ids_v1

JOINT_PREPARED_READ_V3="read_current_life_numeric_joint_prepared_v3"
TRACE_READ_V3="read_current_life_numeric_trace_v3"
_NATIVE_CONTROLS=WeakKeyDictionary()
_NATIVE_ENVIRONMENTS=WeakKeyDictionary()
_NATIVE_PREPARED_RESULTS={}
_NATIVE_RECHECKS=WeakKeyDictionary()
_INPUT_PATHS=(("schema",),("read_rows",),("installed_identity",),("mapping_original_refs",),
    ("command_envelope","identity"),("command_envelope","authority"),
    ("command_envelope","version_guard","read_versions"),("command_envelope","input_refs"),
    ("command_envelope","parent_budget_lease_ref"),("command_envelope","deadline_utc"),
    ("worker_original",),("numeric_request","drives"))
_JOB_PATHS=(("job_id",),("operation_id",),("activity_id",),("bot_id",),("persona_id",),("phase",),("work_kind",),
    ("deadline_utc",),("budget_ref",),("lease_holder",),("lease_expires_utc",),("fence",),("cancel_epoch",),("continuation",))
_JOB_META_COLUMNS=("operation_id","activity_id","bot_id","persona_id","phase","work_kind","deadline_utc",
    "budget_ref","lease_holder","lease_expires_utc","fence","cancel_epoch")
_LEASE_META_COLUMNS=("bot_id","persona_id","currency","version","state")

class _NativeInputProjectionV3(_NumericWireProjectionV3):
    def retain_path_v3(self,path):
        if path[:1]==("read_rows",):
            return len(path)<=2 or len(path)==3 and path[-1]in {"ref","revision","valid"}
        if path[:2]==("numeric_request","drives"):
            return len(path)<=3 or len(path)==4 and path[-1]in {"source_ref","source_revision","drive_ref"}
        return super().retain_path_v3(path)
    def finish_v3(self):
        self._actual()
        if self.buffer:self._feed_v3()
        result=self.parser.finish();self.eof_digest=result.sha256
        from .dispatch_current_inventory_v3 import _freeze_value_v3
        self.column.operation.retain(_heap(self.value)*2+1024)
        self.frozen=_freeze_value_v3(self.value)
        self.nodes={};self.value=None;self.scalar=bytearray();self.text_parts=[];self.text_chars=[]
        self.parser=None;self.complete=True
        return _detach_value_v3(self.frozen)

class _NativePreparedWireV3:
    def __init__(self,column):
        self.column=column
        self.input=_NativeInputProjectionV3(column,field_path=("input_payload_json",),paths=_INPUT_PATHS)
        self.job=_NumericWireProjectionV3(column,field_path=("job_payload_json",),paths=_JOB_PATHS)
    def consume_codepoint_v3(self,path,codepoint):
        self.column._actual()
        if (self.column.native_wire is not self or self.column.profile!="native_prepared"):
            raise AuthorityUnavailable("Native opaque metadata lost its exact private issued column")
        if path==("input_payload_json",):return self.input.consume_codepoint_v3(path,codepoint)
        if path==("job_payload_json",):return self.job.consume_codepoint_v3(path,codepoint)
        return False

class NumericNativePreparedMetadataColumnV3(_NumericMetadataColumnV1):
    def __init__(self,task,*,cell=None):
        super().__init__(task,cell=cell)
        if task.identity[0]!="d04"or self.profile!="native_prepared":
            raise AuthorityUnavailable("Native metadata column requires the exact actual D04 preparation selector")
        self.native_wire=_NativePreparedWireV3(self)
        from .current_method_learning_read_v3 import _MethodJSONStreamV3
        self.parser=_MethodJSONStreamV3(self,ensure_ascii=True,wire_metadata=self.native_wire)
    def advance(self,meter):
        complete=super().advance(meter)
        if complete and not self.native_wire.input.complete:
            self.input_metadata=self.native_wire.input.finish_v3()
            self.job_metadata=self.native_wire.job.finish_v3()
        return complete

@dataclass
class _NativeControlV3:
    work:object
    operation:object
    selection:object
    scope:object
    request:object
    binding:object
    ids:dict
    prepared_task:object
    input_metadata:dict
    job_metadata:dict
    metadata_tasks:tuple
    job:tuple
    quote:object
    grant:object
    reservation:tuple
    tokens:set
    originals:set
    operations:set
    histories:dict
    paid:dict
    life:dict
    plan:object=None
    envelope:object=None

def _require_control_v3(reader,*,sources=True):
    r=require_numeric_read_work_v3(reader)
    c=_NATIVE_CONTROLS.get(r)
    if c is None or (c.work,c.operation,c.selection,c.scope,c.request)!=(r.work,r.operation,r.selection_digest,r.fence.scope,r.request):
        raise AuthorityUnavailable("Native consumer changed its exact signed metadata/Work identity")
    with runtime_storage_quantum_v3(r.db)as meter:
        r.require_current(meter=meter)
        for task in c.metadata_tasks:
            if (r.attachments.get(("numeric_owner_metadata",task.identity))is not task or not task.complete
                    or task.reader is not r):
                raise AuthorityUnavailable("Native metadata recheck lost its exact issued whole-EOF task")
            current=_native_metadata_row_v3(r,meter,task.table,task.header_columns,
                " AND ".join(name+"=?"for name in task.key_columns),task.key)
            if current!=task.metadata:
                raise AuthorityUnavailable("Native metadata original header changed across actual EOF")
        actual=_native_metadata_row_v3(r,meter,"runtime_jobs",_JOB_META_COLUMNS,"job_id=?",(c.binding.job_id,))
        reservation=_native_metadata_row_v3(r,meter,"runtime_budget_reservations",("digest","state"),
            "lease_id=? AND operation_id=?",(c.binding.parent_budget_lease_ref,c.binding.reservation_operation_id))
    if actual!=c.job or reservation!=c.reservation:
        raise AuthorityUnavailable("Native actual original job/reservation metadata changed")
    if sources:
        if r.numeric_source_permission is None:raise AuthorityUnavailable("Native original body lacks ALL current Source EOF")
        r.numeric_source_permission.require_for_v1(r)
    return r,c

def prepare_native_numeric_read_metadata_v3(reader):
    r=require_numeric_read_work_v3(reader)
    if r.operation_kind==JOINT_PREPARED_READ_V3:
        if type(r.request)is not PrepareLifeNumericJointRequestV1:raise TypeError("exact Native joint locator required")
        ids=life_numeric_joint_ids_v1(r.namespace,r.request.episode_ref,r.request.appraisal_ref)
        operation=ids["operation"]
    elif r.operation_kind==TRACE_READ_V3:
        if type(r.request)is not AdoptLifeNumericTraceRequestV1:raise TypeError("exact Native trace locator required")
        operation=r.request.joint_operation_id;ids=None
    else:raise AuthorityUnavailable("unregistered Native Life consumer")
    raw,task=_metadata(r,"d04","native_prepared",operation)
    binding=from_wire(raw["binding"],D04NumericBindingV3)
    input_meta=task.column.input_metadata;job_meta=task.column.job_metadata;continuation=job_meta["continuation"]
    if ids is None:ids=life_numeric_joint_ids_v1(r.namespace,r.request.episode_ref,continuation["appraisal_ref"])
    installation=r.graph._GraphCoordinator__d04_installed_joint_assembly.installation_policy
    if (binding.namespace!=r.namespace or (binding.operation_id,binding.job_id,binding.execution_id,binding.quote_id,
            binding.input_original_ref,binding.activity_id)!=(ids["operation"],ids["job"],ids["execution"],ids["quote"],ids["input"],ids["activity"])
            or operation!=ids["operation"]or raw["original_ref"]!=ids["input"]
            or binding.installation_id!=installation.installation_id or binding.authority_id!=r.fence.scope.permit.authority_id
            or binding.authority_namespace!=r.fence.scope.authority_namespace
            or binding.activation_generation!=r.authority.activation_generation
            or continuation["schema"]!="d04.internal-life-numeric-continuation.v1"
            or continuation["episode_ref"]!=r.request.episode_ref or continuation["causal_operation_id"]!=r.request.causal_operation_id
            or continuation["mapping_ref"]not in input_meta["mapping_original_refs"]
            or task.column.native_wire.input.eof_digest!=binding.input_digest
            or input_meta["installed_identity"]["owner_grant_ref"]!=binding.owner_grant_ref
            or input_meta["installed_identity"]["owner_grant_revision"]!=binding.owner_grant_revision
            or input_meta["installed_identity"]["owner_grant_digest"]!=binding.owner_grant_digest
            or job_meta["job_id"]!=binding.job_id or job_meta["operation_id"]!=binding.operation_id
            or job_meta["work_kind"]!="d04.joint_numeric_cpu.v3"or job_meta["cancel_epoch"]!=0):
        raise AuthorityUnavailable("Native prepared metadata differs from actual installed once joint/Owner/input identity")
    if r.operation_kind==JOINT_PREPARED_READ_V3 and continuation["appraisal_ref"]!=r.request.appraisal_ref:
        raise AuthorityUnavailable("Native exact joint appraisal locator changed")
    quote_raw,quote_task=_metadata(r,"quote","quote",binding.quote_id)
    policy=r.graph._GraphCoordinator__d04_installed_joint_assembly.admin_bundle.d04_joint_numeric
    grant_raw,grant_task=_metadata(r,"native_grant","native_grant",(binding.parent_budget_lease_ref,policy.grant_version))
    from .issuers import _decode_quote,_decode_grant
    quote=_decode_quote(canonical_serialize(quote_raw));grant=_decode_grant(canonical_serialize(grant_raw))
    with runtime_storage_quantum_v3(r.db)as meter:
        job=_runtime_bounded_fixed_row_v3(r.db,meter,"runtime_jobs",_JOB_META_COLUMNS,"job_id=?",(binding.job_id,))
        lease=_runtime_bounded_fixed_row_v3(r.db,meter,"runtime_budget_leases",_LEASE_META_COLUMNS,"lease_id=?",(binding.parent_budget_lease_ref,))
        reservation=_runtime_bounded_fixed_row_v3(r.db,meter,"runtime_budget_reservations",("digest","state"),
            "lease_id=? AND operation_id=?",(binding.parent_budget_lease_ref,binding.reservation_operation_id))
    if (job is None or lease is None or reservation is None or job[0]!=binding.operation_id or job[1]!=binding.activity_id
            or job[2:4]!=r.namespace.as_tuple or job[5]!="d04.joint_numeric_cpu.v3"or job[-1]!=0
            or canonical_digest(quote)!=binding.quote_digest
            or (quote.quote_id,quote.version,quote.parent_budget_lease_ref,quote.operation_id,quote.work_kind)!=
                (binding.quote_id,binding.quote_version,binding.parent_budget_lease_ref,binding.operation_id,"d04.joint_numeric_cpu.v3")
            or (grant.lease_id,grant.grant_id,grant.version)!=(binding.parent_budget_lease_ref,policy.grant_id,policy.grant_version)
            or (grant.bot_id,grant.persona_id)!=r.namespace.as_tuple or "d04.joint_numeric_cpu.v3"not in grant.allowed_work_kinds
            or reservation[0]!=binding.reservation_digest or reservation[1]not in {"reserved","settled"}
            or lease[:2]!=r.namespace.as_tuple or lease[2]!=grant.currency):
        raise AuthorityUnavailable("Native actual CPU quote/grant/job/reservation lineage differs")
    roots={continuation["source_ref"]};expectations={};tokens=set();histories={};paid_controls={};life_control={}
    for row in input_meta["read_rows"]:
        key=AtomKey.from_token(row["ref"])
        if NamespaceId.from_key(key)!=r.namespace:raise AuthorityUnavailable("Native prepared current row crossed namespace")
        tokens.add(key.token)
        if key.type_name in {"memory.source","memory.access"}:
            expectations[key.token]=row["revision"]
            if key.type_name=="memory.source":roots.add(key.token)
    envelope=input_meta["command_envelope"]
    if (envelope["authority"]["purpose"]!="consolidation"or continuation["source_ref"]not in envelope["input_refs"]
            or tuple(envelope["authority"]["audience"])!=tuple(r.authority.audience)):
        raise AuthorityUnavailable("Native prepared signed actual Source purpose/audience differs")
    for version in envelope["version_guard"]["read_versions"]:
        key=_version_key(version);tokens.add(key.token)
        if NamespaceId.from_key(key)!=r.namespace:raise AuthorityUnavailable("Native prepared version crossed namespace")
        if key.type_name in {"memory.source","memory.access"}:
            if key.token in expectations and expectations[key.token]!=version["revision"]:
                raise AuthorityUnavailable("Native prepared exact Source duplicate versions differ")
            expectations[key.token]=version["revision"]
            if key.type_name=="memory.source":roots.add(key.token)
    for drive in input_meta["numeric_request"]["drives"]:
        roots.add(drive["source_ref"]);expectations[drive["source_ref"]]=drive["source_revision"]
    tasks=[task,quote_task,grant_task]
    from .d06_life_numeric_context_v1 import life_numeric_context_ids_v1
    context,context_task=_metadata(r,"life","context",life_numeric_context_ids_v1(r.namespace,r.request.episode_ref)["original"])
    before,before_task=_metadata(r,"life","before",context["before_ref"])
    tasks.extend((context_task,before_task))
    originals={ids["input"],continuation["context_ref"],continuation["drive_ref"],context["before_ref"],before["root_operation_id"],*input_meta["mapping_original_refs"]}
    operations={ids["operation"],ids["prepare"],context["operation_id"],before["root_operation_id"],r.request.causal_operation_id}
    if r.operation_kind==TRACE_READ_V3:
        numeric,numeric_task=_metadata(r,"joint","joint",operation);tasks.append(numeric_task)
        from ..memory_types import access_key
        for drive_ref,revision,source_ref,source_revision,access_ref,access_revision,family_ref in numeric["source_versions"]:
            source=AtomKey.from_token(source_ref)
            if access_key(*r.namespace.as_tuple,source.owner.subject).token!=access_ref:
                raise AuthorityUnavailable("Native joint Source has another canonical access ref")
            drive,drive_task=_metadata(r,"graph","drive",drive_ref);tasks.append(drive_task)
            if (drive_task.metadata[0]!=revision or drive["source_ref"]!=source_ref or drive["source_revision"]!=source_revision):
                raise AuthorityUnavailable("Native joint drive metadata differs from exact source versions")
            roots.add(source_ref);expectations[source_ref]=source_revision;expectations[access_ref]=access_revision;tokens.add(drive_ref)
        keys=life_numeric_trace_keys_v1(r.namespace,r.request.episode_ref,operation)
        trace,trace_task=_metadata(r,"life","native_trace",keys[0].token);tasks.append(trace_task)
        bid=life_encoding_baseline_ids_v1(r.namespace,r.request.episode_ref,operation)
        baseline,baseline_task=_metadata(r,"life","native_baseline",bid["original"]);tasks.append(baseline_task)
        if (trace["trace"]["trace_ref"]!=keys[0].token or trace["trace"]["episode_ref"]!=r.request.episode_ref
                or trace["trace"]["baseline"]["source_ref"]!=continuation["source_ref"]
                or baseline["joint_operation_id"]!=operation or baseline["episode_ref"]!=r.request.episode_ref
                or baseline["source_ref"]!=continuation["source_ref"]):
            raise AuthorityUnavailable("Native trace/baseline signed selectors differ from exact actual occurrence")
        from ..model_broker.internal_life_numeric_v1 import InternalLifeNumericIdentityV1,internal_life_numeric_ids_v1
        identity=InternalLifeNumericIdentityV1(r.namespace,r.request.episode_ref,context["execution_id"],context["source_ref"],
            context["occurrence_digest"],context["before_digest"],context_task.column.canonical_digest)
        model_ids=internal_life_numeric_ids_v1(identity)
        for appraisal_ref,acceptance_digest in baseline["appraisal_acceptance_digests"]:
            accepted,accepted_task=_metadata(r,"life","native_acceptance",appraisal_ref);tasks.append(accepted_task)
            if (accepted["appraisal_ref"]!=appraisal_ref or accepted["job_id"]!=model_ids["job"]
                    or accepted["operation_id"]!=model_ids["adopt"]
                    or accepted_task.column.canonical_digest!=acceptance_digest
                    or accepted["context_digest"]!=context_task.column.canonical_digest
                    or accepted["before_digest"]!=context["before_digest"]):
                raise AuthorityUnavailable("Native signed baseline paid appraisal selector differs from actual context")
            prepared_model,prepared_model_task=_metadata(r,"life","prepared",model_ids["job"])
            binding_model,binding_model_task=_metadata(r,"life","binding",model_ids["job"])
            request_model,request_model_task=_metadata(r,"life","request",model_ids["job"])
            acquired,acquire_task=_metadata(r,"life","acquire_commit",model_ids["job"])
            paid,paid_task=_metadata(r,"life","paid",model_ids["job"])
            model_quote_raw,model_quote_task=_metadata(r,"quote","quote",prepared_model["quote_id"])
            tasks.extend((prepared_model_task,binding_model_task,request_model_task,acquire_task,paid_task,model_quote_task))
            model_quote=_decode_quote(canonical_serialize(model_quote_raw))
            if (prepared_model_task.column.canonical_digest!=accepted["prepared_digest"]
                    or prepared_model["frozen"]["identity"]["source_ref"]!=context["source_ref"]
                    or prepared_model["job_id"]!=model_ids["job"]
                    or paid["prepared_digest"]!=prepared_model_task.column.canonical_digest
                    or paid["binding_digest"]!=request_model["binding_digest"]
                    or request_model["binding_digest"]!=acquired["binding_digest"]
                    or request_model["request_digest"]!=acquired["request_digest"]):
                raise AuthorityUnavailable("Native paid appraisal original metadata family does not close")
            tokens.add(appraisal_ref)
            from .d11_types import runtime_job_key
            model_job_key=runtime_job_key(*r.namespace.as_tuple,prepared_model["activity_id"],model_ids["job"]).token
            tokens.add(model_job_key);histories.setdefault(model_job_key,set()).update((1,2,3))
            histories.setdefault(appraisal_ref,set()).add(1)
            for row in (*prepared_model["read_rows"],*accepted["read_rows"]):
                tokens.add(row["ref"])
                if AtomKey.from_token(row["ref"]).type_name in {"memory.source","memory.access"}:
                    expectations[row["ref"]]=row["revision"]
                    if AtomKey.from_token(row["ref"]).type_name=="memory.source":roots.add(row["ref"])
            request_envelope=request_model_task.column.envelope_metadata["envelope"]
            for version in request_envelope["version_guard"]["read_versions"]:
                key=_version_key(version);tokens.add(key.token)
                if key.type_name in {"memory.source","memory.access"}:
                    expectations[key.token]=version["revision"]
                    if key.type_name=="memory.source":roots.add(key.token)
            tokens.add(paid["cost"]["cost_ref"])
            originals.update((appraisal_ref,model_ids["job"],accepted["result_original_ref"],accepted["cost_original_ref"]))
            from .model_cost_settlement import original_model_cost_operation_id_v1
            operations.update((model_ids["prepare"],model_ids["acquire"],model_ids["adopt"],
                original_model_cost_operation_id_v1(r.namespace,prepared_model["call_id"])))
            paid_controls[model_ids["job"]]={"ids":model_ids,"accepted":accepted,"quote":model_quote,
                "prepared":prepared_model,"binding":binding_model,"request":request_model,"paid":paid}
        originals.update((keys[0].token,bid["original"]))
        operations.update((bid["operation"],life_numeric_trace_operation_v1(r.namespace,r.request.episode_ref,operation)))
        tokens.update(key.token for key in keys)
        for row in trace["current_reads"]:
            tokens.add(row["ref"])
            if AtomKey.from_token(row["ref"]).type_name in {"memory.source","memory.access"}:
                expectations[row["ref"]]=row["revision"]
                if AtomKey.from_token(row["ref"]).type_name=="memory.source":roots.add(row["ref"])
        for row in trace["historical_reads"]:
            if row["revision"]>0:
                tokens.add(row["ref"]);histories.setdefault(row["ref"],set()).add(row["revision"])
    if r.operation_kind==TRACE_READ_V3:
        from .d06_internal_life_episode_v2 import PROVENANCE as EPISODE_PROVENANCE
        episode=AtomKey.from_token(r.request.episode_ref)
        ep_key=AtomKey(episode.owner,EPISODE_PROVENANCE,"record")
        episode_meta,episode_task=_metadata(r,"graph","episode",ep_key.token)
        activity=episode_meta["event"]["activity"]
        adopted,adopted_task=_metadata(r,"life","native_life_adopted",activity["artifact_ref"])
        tasks.append(adopted_task)
        from .d11_life_contract_v1 import D11LifeExecutionBindingV1,life_from_wire_v1
        life_binding=life_from_wire_v1(adopted["terminal"]["binding"],D11LifeExecutionBindingV1)
        if (life_binding.namespace!=r.namespace or life_binding.execution_id!=activity["execution_id"]
                or life_binding.activity_id!=activity["activity_id"]or life_binding.effect_id!=activity["effect_id"]
                or life_binding.artifact_ref!=activity["artifact_ref"]
                or adopted["terminal"]["original_ref"]!=activity["terminal_original_ref"]):
            raise AuthorityUnavailable("Native occurrence Life original metadata does not bind actual activity")
        from .d10_life_outcome_v2 import life_experience_provenance_ref_v1,life_experience_source_id_v1
        from ..memory_types import source_key
        if source_key(*r.namespace.as_tuple,life_experience_source_id_v1(life_binding)).token!=activity["source_ref"]:
            raise AuthorityUnavailable("Native occurrence Life Source metadata identity differs")
        experience_ref=life_experience_provenance_ref_v1(life_binding)
        experience,experience_task=_metadata(r,"life","native_life_experience",experience_ref)
        life_prepared,life_prepared_task=_metadata(r,"life","native_life_prepared",life_binding.prepared_original_ref)
        tasks.extend((experience_task,life_prepared_task))
        if (experience["source_ref"]!=activity["source_ref"]or experience["binding"]!=adopted["terminal"]["binding"]
                or life_prepared["binding"]!=adopted["terminal"]["binding"]):
            raise AuthorityUnavailable("Native Life prepared/experience metadata crossed signed occurrence binding")
        for row in life_prepared["read_rows"]:
            tokens.add(row["ref"]);histories.setdefault(row["ref"],set()).add(row["revision"])
            if AtomKey.from_token(row["ref"]).type_name in {"memory.source","memory.access"}:
                if row["ref"]in expectations and expectations[row["ref"]]!=row["revision"]:
                    raise AuthorityUnavailable("Native Life lineage duplicate Source versions differ")
                expectations[row["ref"]]=row["revision"]
                if AtomKey.from_token(row["ref"]).type_name=="memory.source":roots.add(row["ref"])
        source_ref=life_prepared["plan"]["input_source"]["ref"]
        access_ref=life_prepared["plan"]["input_access"]["ref"]
        roots.add(source_ref)
        expectations[source_ref]=life_prepared["plan"]["input_source"]["revision"]
        expectations[access_ref]=life_prepared["plan"]["input_access"]["revision"]
        originals.update((experience_ref,life_binding.prepared_original_ref,life_binding.plan_original_ref,life_binding.execution_id,
            life_binding.artifact_ref,adopted["terminal"]["original_ref"],adopted["terminal"]["claim"]["original_ref"],
            experience["experience"]["action_outcome_ref"],*experience["experience"]["cost_refs"]))
        operations.update((life_binding.prepare_operation_id,life_binding.operation_id,adopted["producing_operation_id"],
            experience["adopted_operation_id"]))
        from .d11_types import runtime_job_key
        life_job_key=runtime_job_key(*r.namespace.as_tuple,life_binding.activity_id,life_binding.job_id).token
        tokens.add(life_job_key)
        import json
        from .d11_life_contract_v1 import LifeBodyComponentContractV1
        contract_raw=json.loads(life_prepared["plan"]["body_effect_request_json"])
        contract=LifeBodyComponentContractV1(**contract_raw)
        from dataclasses import fields
        if set(contract_raw)!={f.name for f in fields(LifeBodyComponentContractV1)}:
            raise AuthorityUnavailable("Native Life Body metadata is not its exact fixed locator contract")
        from .d11_life_accounting_v1 import life_accounting_original_ref_v1
        accounting_ref=life_accounting_original_ref_v1(life_binding)
        accounting,accounting_task=_metadata(r,"life","native_life_accounting",accounting_ref)
        cpu_quote_raw,cpu_quote_task=_metadata(r,"quote","quote",life_binding.quote_id)
        body_quote_raw,body_quote_task=_metadata(r,"quote","quote",contract.resource_quote_ref)
        life_quote=_decode_quote(canonical_serialize(cpu_quote_raw));body_resource_quote=_decode_quote(canonical_serialize(body_quote_raw))
        life_grant=_decode_grant(accounting["signed_grant_json"])
        grant_raw,life_grant_task=_metadata(r,"native_grant","native_grant",(life_grant.lease_id,life_grant.version))
        if (accounting["binding"]!=adopted["terminal"]["binding"]or accounting["prepare_operation_id"]!=life_binding.prepare_operation_id
                or canonical_serialize(life_quote)!=accounting["quote_json"]
                or canonical_digest(life_quote)!=life_binding.quote_digest
                or canonical_digest(body_resource_quote)!=contract.resource_quote_digest
                or canonical_serialize(life_grant)!=canonical_serialize(grant_raw)
                or life_grant.lease_id!=life_binding.parent_budget_lease_ref):
            raise AuthorityUnavailable("Native Life metadata signed quote/grant/accounting identity differs")
        tasks.extend((accounting_task,cpu_quote_task,body_quote_task,life_grant_task))
        originals.update((accounting_ref,"life-body:"+contract.body_prepare_operation_id))
        operations.add(contract.body_prepare_operation_id)
        tokens.update((contract.reservation_ref,contract.settlement_ref))
        for item in adopted["write_commitments"]:
            tokens.add(item["ref"]);histories.setdefault(item["ref"],set()).add(item["revision"])
        life_control={"jobs":(life_binding.job_id,),"binding":life_binding,"experience_ref":experience_ref,
            "adopted":adopted,"prepared":life_prepared,"accounting":accounting,"contract":contract,
            "quotes":(life_quote,body_resource_quote),"grant":life_grant}
        action_ref="life-root:"+life_binding.operation_id
        action,action_task=_metadata(r,"life","native_life_action",action_ref);tasks.append(action_task)
        if (action["action_operation_id"]!=life_binding.operation_id
                or action["action_intent_ref"]!=life_prepared["plan"]["action_intent"]["ref"]):
            raise AuthorityUnavailable("Native Life action metadata is another actual prepared Root")
        originals.add(action_ref)
        for ref,revision,*_ in (*action["context_commitments"],*action["write_commitments"]):
            key=AtomKey.from_token(ref);tokens.add(ref);histories.setdefault(ref,set()).add(revision)
            if key.type_name in {"memory.source","memory.access"}:
                expectations[ref]=revision
                if key.type_name=="memory.source":roots.add(ref)
        for ref,revision,digest,producer,receipt_digest in action["context_commitments"]:operations.add(producer)
        roots.add(action["input_source_ref"])
        life_control["action"]=action;life_control["action_ref"]=action_ref
    _NATIVE_CONTROLS[r]=_NativeControlV3(r.work,r.operation,r.selection_digest,r.fence.scope,r.request,binding,ids,task,
        input_meta,job_meta,tuple(tasks),job,quote,grant,reservation,tokens,originals,operations,histories,paid_controls,life_control)
    return roots,expectations,tuple(tasks)

def observe_native_numeric_read_environment_v3(reader):
    r=require_numeric_read_work_v3(reader);c=_NATIVE_CONTROLS.get(r)
    if (c is None or (c.work,c.operation,c.selection,c.scope,c.request)!=(r.work,r.operation,r.selection_digest,r.fence.scope,r.request)
            or r.numeric_source_permission is None or r.numeric_source_permission.reader is not r
            or not r.inventory_sealed):
        raise AuthorityUnavailable("Native environment observation lacks actual completed metadata/Source Work")
    if r.db.in_transaction:raise AuthorityUnavailable("Native current encoding observation must precede Graph SQL")
    if r.operation_kind==JOINT_PREPARED_READ_V3:return None
    from .installed_c04_encoding_context_v3 import observe_installed_c04_encoding_environment_v3
    environment=observe_installed_c04_encoding_environment_v3(r.graph,r.graph._GraphCoordinator__bootstrap,r.namespace)
    _NATIVE_ENVIRONMENTS[r]=(c.work,c.operation,c.scope,c.request,environment)
    return environment

def require_native_numeric_read_point_v3(reader,request):
    r,c=_require_control_v3(reader)
    table,columns,keycols,key=request
    shape=(tuple(columns),tuple(keycols))
    if table=="graph_atoms":
        if shape not in {(("revision","value","valid"),("token","bot","persona")), (("revision","value","valid"),("token",)), (("value","valid"),("token",)), (("value",),("token",))}:
            raise AuthorityUnavailable("Native exact Graph body point has another registered shape")
        if tuple(keycols)==("token","bot","persona") and tuple(key[1:])!=r.namespace.as_tuple:
            raise AuthorityUnavailable("Native exact Graph key crossed its actual namespace")
        token=key[0];atom=AtomKey.from_token(token)
        if NamespaceId.from_key(atom)!=r.namespace:raise AuthorityUnavailable("Native Graph point crossed namespace")
        if atom.type_name in {"memory.source","memory.access","d06.source_correction_head.v1"}:
            from .current_method_learning_read_v3 import _GENERAL_METHOD_SOURCE_TASKS_V1
            from ..memory_types import source_key
            leaf=_GENERAL_METHOD_SOURCE_TASKS_V1.get(r,{}).get(source_key(*r.namespace.as_tuple,atom.owner.subject or "").token)
            if leaf is None or not leaf.complete:raise AuthorityUnavailable("Native Source body lacks exact completed source leaf")
        elif token not in c.tokens and not (c.plan is not None and atom in c.plan.exact_keys):
            raise AuthorityUnavailable("Native Graph point escaped exact signed current-row recipe")
        return r
    from .natural_producer_qualification_v1 import _HOST_ATTACHMENT_SHAPES_V3
    from .current_life_numeric_read_v3 import _JOB_COLUMNS,_LEASE_COLUMNS
    native_shapes={
        ("runtime_jobs",_JOB_COLUMNS,("job_id",)),("runtime_budget_leases",_LEASE_COLUMNS,("lease_id",)),
        ("runtime_budget_reservations",("ceiling_json","state","actual_json"),("lease_id","operation_id")),
        ("runtime_budget_reservations",("state","digest"),("lease_id","operation_id")),
        ("runtime_budget_reservations",("digest","ceiling_json"),("lease_id","operation_id")),
        ("runtime_budget_operations",("digest","lease_id","receipt_json"),("bot_id","persona_id","operation_id","phase")),
        ("runtime_budget_operations",("digest","lease_id","resolution_binding_json"),("bot_id","persona_id","operation_id","phase")),
        ("graph_bundle_fences_v2",("permit_json","pre_graph_revision","pre_graph_epoch","post_graph_revision","post_graph_epoch",
            "finish_request_id","finish_request_digest"),("bot","persona","operation_id")),
        ("d02_body_quotes_v1",("quote_version","policy_id","policy_version","operation_id","resource_quote_digest","body_quote_json","signature"),
            ("bot","persona","quote_id")),
    }
    if request[:3]not in _HOST_ATTACHMENT_SHAPES_V3|native_shapes:
        raise AuthorityUnavailable("Native body point uses an unregistered exact table/column shape")
    if table=="graph_history":
        allowed=key[0]in c.tokens and key[1]in {1,*c.histories.get(key[0],set())}
    elif table=="graph_dependencies":allowed=key[0]in c.tokens
    elif table=="graph_d04_originals_v3":
        allowed=tuple(key[:2])==r.namespace.as_tuple and key[2]in {"numeric_prepared","numeric_measurement","numeric_artifact"} and key[3]==c.binding.operation_id
    elif table=="graph_d11_life_originals_v1":
        kinds={"numeric_context_v1","numeric_drive_v1","d04_before_v1","numeric_trace_v1","d04_interval_baseline_v1",
            "numeric_appraisal_acceptance_v1","numeric_prepared_v1","numeric_binding_v1","numeric_request_v1","numeric_acquire_commit_v1","numeric_paid_v1","numeric_call_v1",
            "experience","prepared","adopted_life","adoption_bridge","adoption_receipt","accounting_prepared","life_body_preparation","source_note_action","plan","outcome"}
        allowed=tuple(key[:2])==r.namespace.as_tuple and key[2]in kinds and key[3]in c.originals
    elif table in {"graph_domain_production_originals_v1","graph_bundle_operations","graph_d04_joint_numeric_originals_v1","graph_d04_joint_output_originals_v1","graph_c04_encoding_baselines_v3","graph_events","graph_d04_joint_advances_v2"}:
        allowed=tuple(key[:2])==r.namespace.as_tuple and any(value in c.operations or value in c.originals for value in key[2:])
    elif table=="runtime_budget_operations":
        allowed=(tuple(key[:2])==r.namespace.as_tuple and (
            key[3]=="settle"and key[2]in {c.binding.reservation_operation_id,*(p["ids"]["prepare"]for p in c.paid.values())}
            or c.life and key[3]in {"reserve","settle"}and key[2]==c.life["binding"].reservation_operation_id))
    elif table=="runtime_budget_reservations":
        allowed=tuple(key)in ({(p["quote"].parent_budget_lease_ref,p["ids"]["prepare"])for p in c.paid.values()}|{
            (c.binding.parent_budget_lease_ref,c.binding.reservation_operation_id)}|{
            *(( (c.life["binding"].parent_budget_lease_ref,c.life["binding"].reservation_operation_id),)if c.life else ())})
    elif table=="runtime_budget_leases":
        allowed=tuple(keycols)==("lease_id",)and key[0]in {c.binding.parent_budget_lease_ref,
            *(p["quote"].parent_budget_lease_ref for p in c.paid.values()),*(q.parent_budget_lease_ref for q in c.life.get("quotes",()))}
    elif table=="runtime_budget_grants":
        allowed=tuple(key)==(c.life["grant"].lease_id,c.life["grant"].version)if c.life else False
    elif table=="d02_body_quotes_v1":
        allowed=(c.life and tuple(key[:2])==r.namespace.as_tuple and key[2]==c.life["contract"].body_quote_ref)
    elif table=="graph_bundle_fences_v2":
        allowed=tuple(key[:2])==r.namespace.as_tuple and key[2]in c.operations
    elif table=="graph_original_model_cost_attempts_v1":
        allowed=tuple(key[:2])==r.namespace.as_tuple and key[2]in {p["prepared"]["call_id"]for p in c.paid.values()}
    elif table=="runtime_jobs":allowed=tuple(keycols)==("job_id",)and len(key)==1 and key[0]in {c.binding.job_id,*c.paid.keys(),*c.life.get("jobs",())}
    elif table in {"graph_d11_domain_inputs_v1","graph_d11_domain_policies_v1","graph_d04_root_originals_v3","graph_d04_semantic_mapping_originals_v3"} and c.plan is not None:
        allowed=tuple(key[:2])==r.namespace.as_tuple and any(value in set(c.plan.required_original_refs)|c.originals|c.operations for value in key[2:])
    else:allowed=False
    if not allowed:raise AuthorityUnavailable("Native protected original point escaped its exact actual preparation/trace recipe")
    return r

@dataclass(frozen=True,slots=True)
class CurrentLifeNumericTraceOriginalsV3:
    trace:object
    baseline:object
    provenance:object
    c04_record:object
    drive:object
    output_original_digest:str
    heads:tuple
    histories:tuple

def read_native_numeric_read_result_v3(reader):
    r,c=_require_control_v3(reader)
    from .d04_numeric_cost_v3 import read_d04_numeric_prepared_v3
    prepared=read_d04_numeric_prepared_v3(r.db,r.namespace,c.binding.operation_id)
    if prepared is None or prepared.binding!=c.binding or prepared.digest!=c.prepared_task.column.canonical_digest:
        raise AuthorityUnavailable("Native typed original differs from authenticated metadata EOF")
    if r.operation_kind==JOINT_PREPARED_READ_V3:
        from .d04_appraisal_driver_v3 import read_d04_original_v3
        measurement=read_d04_original_v3(r.db,r.namespace,"numeric_measurement",c.binding.operation_id)
        artifact=read_d04_original_v3(r.db,r.namespace,"numeric_artifact",c.binding.operation_id)
        _NATIVE_PREPARED_RESULTS[id(prepared)]=(prepared,r,measurement,artifact)
        return prepared
    observed=_NATIVE_ENVIRONMENTS.get(r)
    if observed is None or observed[:4]!=(c.work,c.operation,c.scope,c.request):
        raise AuthorityUnavailable("Native trace body lacks its same-Work observed installed environment")
    environment=observed[4]
    from .d04_installed_numeric_v3 import _ready_from_original_v3
    from .d06_structured_experience_v1 import InstalledD06StructuredExperienceReadersV1
    readers=InstalledD06StructuredExperienceReadersV1(issuer=r.graph._GraphCoordinator__d11_issuer,
        resource_issuer=r.graph._GraphCoordinator__d02_issuer,body_quote_authority=r.graph._GraphCoordinator__body_quote_authority)
    from .d06_life_numeric_trace_v1 import read_plan_life_numeric_trace_v1,read_current_life_numeric_trace_v1,require_current_life_numeric_trace_v1,OPERATION
    plan=read_plan_life_numeric_trace_v1(r.db,namespace=r.namespace,activity_id=r.numeric_native_activity_id,operation_kind=OPERATION,request=r.request)
    if not set(plan.source_roots)<=set(r.numeric_source_permission.source_refs):
        raise AuthorityUnavailable("Native body planner introduced Source outside metadata closure")
    c.plan=plan
    ready=_ready_from_original_v3(prepared)
    envelope=replace(ready.preparation.envelope,authority=r.authority,
        identity=replace(ready.preparation.envelope.identity,activity_id=r.numeric_native_activity_id,operation_id=r.operation_id),
        deadline_utc=r.operation.deadline_utc,monotonic_deadline=r.initial_monotonic_deadline)
    c.envelope=envelope
    from .domain_production_read_plans_v1 import read_current_domain_policy_refs_v1,read_current_domain_original_refs_v1
    policies=read_current_domain_policy_refs_v1(r.db,namespace=r.namespace,plan=plan,installed_readers=readers)
    originals=read_current_domain_original_refs_v1(r.db,namespace=r.namespace,plan=plan,installed_readers=readers)
    from .domain_production_frame_v1 import freeze_domain_production_frame_v1
    frame=freeze_domain_production_frame_v1(r.graph,r.db,envelope=envelope,current_owner=r.owner_binding,
        scope=r.fence.scope,plan=plan,now_utc=environment.as_known_at,observed_originals=originals,installed_policy_refs=policies)
    current=read_current_life_numeric_trace_v1(r.db,frame=frame,request=r.request,installed_readers=readers,environment=environment)
    trace=require_current_life_numeric_trace_v1(current,db=r.db,frame=frame)
    from .d01_production_operations_v1 import CurrentDomainReadV1
    from .current_method_learning_read_v3 import read_bound_method_learning_attachment_v3
    read=CurrentDomainReadV1(frame);keys=life_numeric_trace_keys_v1(r.namespace,r.request.episode_ref,r.request.joint_operation_id)
    heads=tuple(read.head(r.db,key,required=True)for key in keys);histories=[]
    for key in keys:
        handled,row=read_bound_native_numeric_history_v3(r.db,key.token,1,("value","valid","event_id"))
        if not handled:raise AuthorityUnavailable("Native companion history lacks actual source-gated input EOF")
        histories.append(row)
    from .d06_life_numeric_drive_v1 import read_current_life_numeric_drive_v1,PrepareLifeNumericDriveRequestV1
    drive=read_current_life_numeric_drive_v1(r.db,frame=frame,request=PrepareLifeNumericDriveRequestV1(
        r.request.episode_ref,r.request.causal_operation_id,c.job_metadata["continuation"]["appraisal_ref"]),installed_readers=readers).original
    with runtime_storage_quantum_v3(r.db)as meter:
        output=_runtime_bounded_fixed_row_v3(r.db,meter,"graph_d04_joint_output_originals_v1",("original_digest",),
            "bot=? AND persona=? AND operation_id=?",(*r.namespace.as_tuple,r.request.joint_operation_id))
    if output is None or output[0]!=current.baseline.c04_record.proof.output_original_digest:
        raise AuthorityUnavailable("Native trace companion actual joint output commitment differs")
    return CurrentLifeNumericTraceOriginalsV3(trace,current.baseline.original,current.provenance,current.baseline.c04_record,
        drive,output[0],heads,tuple(histories))

def release_native_numeric_read_payloads_v3(reader):
    peak=_NATIVE_RECHECKS.pop(reader,None)
    if peak is not None:
        peak.value=None;reader.operation.unregister_retained_state_v3(peak)
    _NATIVE_CONTROLS.pop(reader,None)
    observed=_NATIVE_ENVIRONMENTS.pop(reader,None)
    if observed is not None:
        from .installed_c04_encoding_context_v3 import _ENVIRONMENTS
        _ENVIRONMENTS.pop(id(observed[4]),None)
    for identity,record in tuple(_NATIVE_PREPARED_RESULTS.items()):
        if record[1]is reader:_NATIVE_PREPARED_RESULTS.pop(identity)

def require_native_numeric_metadata_selector_v3(reader,identity):
    r=require_numeric_read_work_v3(reader)
    if r.operation_kind not in {JOINT_PREPARED_READ_V3,TRACE_READ_V3}:
        raise AuthorityUnavailable("Native metadata has no actual fixed consumer")
    mode,profile,ref=identity
    operation=(life_numeric_joint_ids_v1(r.namespace,r.request.episode_ref,r.request.appraisal_ref)["operation"]
        if r.operation_kind==JOINT_PREPARED_READ_V3 else r.request.joint_operation_id)
    if (mode,profile)==("d04","native_prepared") and ref==operation:return r
    if r.operation_kind==TRACE_READ_V3:
        keys=life_numeric_trace_keys_v1(r.namespace,r.request.episode_ref,operation)
        bid=life_encoding_baseline_ids_v1(r.namespace,r.request.episode_ref,operation)
        if mode=="life"and profile in {"native_life_adopted","native_life_experience","native_life_prepared","native_life_accounting","native_life_action"}:
            from .d06_internal_life_episode_v2 import PROVENANCE
            episode=AtomKey.from_token(r.request.episode_ref)
            episode_meta,_=_metadata(r,"graph","episode",AtomKey(episode.owner,PROVENANCE,"record").token)
            activity=episode_meta["event"]["activity"]
            if profile=="native_life_adopted"and ref==activity["artifact_ref"]:return r
            adopted,adopted_task=_metadata(r,"life","native_life_adopted",activity["artifact_ref"])
            from .d11_life_contract_v1 import D11LifeExecutionBindingV1,life_from_wire_v1
            b=life_from_wire_v1(adopted["terminal"]["binding"],D11LifeExecutionBindingV1)
            from .d10_life_outcome_v2 import life_experience_provenance_ref_v1
            from .d11_life_accounting_v1 import life_accounting_original_ref_v1
            expected=(life_experience_provenance_ref_v1(b)if profile=="native_life_experience"else
                life_accounting_original_ref_v1(b)if profile=="native_life_accounting"else
                "life-root:"+b.operation_id if profile=="native_life_action"else b.prepared_original_ref)
            if ref==expected:return r
        if (mode,profile)==("life","native_acceptance"):
            baseline_task=r.attachments.get(("numeric_owner_metadata",("life","native_baseline",bid["original"])))
            if baseline_task is None or not baseline_task.complete:
                raise AuthorityUnavailable("Native appraisal selector precedes actual signed baseline EOF")
            baseline=_detach_value_v3(baseline_task.result)
            if ref in {pair[0]for pair in baseline["appraisal_acceptance_digests"]}:return r
        if (mode,profile,ref)in {("life","native_trace",keys[0].token),("life","native_baseline",bid["original"])}:
            return r
    if (mode,profile)==("native_grant","native_grant"):
        task=r.attachments.get(("numeric_owner_metadata",("d04","native_prepared",operation)))
        if task is None or not task.complete:
            raise AuthorityUnavailable("Native CPU grant selector precedes actual preparation metadata EOF")
        raw=_detach_value_v3(task.result)
        binding=from_wire(raw["binding"],D04NumericBindingV3)
        policy=r.graph._GraphCoordinator__d04_installed_joint_assembly.admin_bundle.d04_joint_numeric
        if ref==(binding.parent_budget_lease_ref,policy.grant_version):return r
        if r.operation_kind==TRACE_READ_V3:
            from .d06_internal_life_episode_v2 import PROVENANCE
            episode=AtomKey.from_token(r.request.episode_ref)
            metadata,_=_metadata(r,"graph","episode",AtomKey(episode.owner,PROVENANCE,"record").token)
            adopted,_=_metadata(r,"life","native_life_adopted",metadata["event"]["activity"]["artifact_ref"])
            from .d11_life_contract_v1 import D11LifeExecutionBindingV1,life_from_wire_v1
            life_binding=life_from_wire_v1(adopted["terminal"]["binding"],D11LifeExecutionBindingV1)
            from .d11_life_accounting_v1 import life_accounting_original_ref_v1
            accounting,_=_metadata(r,"life","native_life_accounting",life_accounting_original_ref_v1(life_binding))
            from .issuers import _decode_grant
            grant=_decode_grant(accounting["signed_grant_json"])
            if ref==(grant.lease_id,grant.version)and grant.lease_id==life_binding.parent_budget_lease_ref:return r
    raise AuthorityUnavailable("Native metadata selector escaped exact installed preparation/trace identity")

def require_native_numeric_metadata_eof_v3(task):
    r=require_native_numeric_metadata_selector_v3(task.reader,task.identity)
    mode,profile,ref=task.identity
    if mode=="d04":
        raw=_detach_value_v3(task.column.frozen)
        binding=from_wire(raw["binding"],D04NumericBindingV3)
        operation=task.key[-1]
        if task.column.canonical_digest!=task.metadata[0]or binding.namespace!=r.namespace or binding.operation_id!=operation:
            raise AuthorityUnavailable("Native preparation metadata differs from complete actual original digest")
        ids=life_numeric_joint_ids_v1(r.namespace,r.request.episode_ref,task.column.job_metadata["continuation"]["appraisal_ref"])
        with runtime_storage_quantum_v3(r.db)as meter:
            committed=_runtime_bounded_fixed_row_v3(r.db,meter,"graph_bundle_operations",("commit_seq",),
                "bot=? AND persona=? AND operation_id=?",(*r.namespace.as_tuple,ids["prepare"]))
            producer=_runtime_bounded_fixed_row_v3(r.db,meter,"graph_domain_production_originals_v1",("operation_kind",),
                "bot=? AND persona=? AND operation_id=?",(*r.namespace.as_tuple,ids["prepare"]))
        if committed is None or committed[0]<1 or producer!=("prepare_internal_life_numeric_joint",):
            raise AuthorityUnavailable("Native preparation lacks actual W01 producing joint operation")
    elif mode=="life":
        if profile in {"native_life_adopted","native_life_experience","native_life_prepared","native_life_accounting","native_life_action"}:
            raw=_detach_value_v3(task.column.frozen)
            if profile=="native_life_adopted":
                from .d06_internal_life_episode_v2 import PROVENANCE
                episode=AtomKey.from_token(r.request.episode_ref)
                metadata,_=_metadata(r,"graph","episode",AtomKey(episode.owner,PROVENANCE,"record").token)
                activity=metadata["event"]["activity"]
                binding_raw=raw["terminal"]["binding"]
                if raw["result_ref"]!=activity["artifact_ref"]or raw["terminal"]["original_ref"]!=activity["terminal_original_ref"]:
                    raise AuthorityUnavailable("Native signed adopted Life metadata differs from exact occurrence")
                operation=raw["producing_operation_id"]
            else:
                from .d06_internal_life_episode_v2 import PROVENANCE
                episode=AtomKey.from_token(r.request.episode_ref)
                metadata,_=_metadata(r,"graph","episode",AtomKey(episode.owner,PROVENANCE,"record").token)
                adopted,_=_metadata(r,"life","native_life_adopted",metadata["event"]["activity"]["artifact_ref"])
                binding_raw=adopted["terminal"]["binding"]
                if profile!="native_life_action"and raw["binding"]!=binding_raw:
                    raise AuthorityUnavailable("Native signed Life metadata differs from actual adopted binding")
                operation=(raw["adopted_operation_id"]if profile=="native_life_experience"else
                    binding_raw["operation_id"]if profile=="native_life_action"else binding_raw["prepare_operation_id"])
            from .d11_life_contract_v1 import D11LifeExecutionBindingV1,life_from_wire_v1
            binding=life_from_wire_v1(binding_raw,D11LifeExecutionBindingV1)
            if binding.namespace!=r.namespace:
                raise AuthorityUnavailable("Native signed Life metadata crossed actual namespace")
        elif profile=="native_acceptance":
            from .d06_life_numeric_context_v1 import life_numeric_context_ids_v1
            context,ctx_task=_metadata(r,"life","context",life_numeric_context_ids_v1(r.namespace,r.request.episode_ref)["original"])
            from ..model_broker.internal_life_numeric_v1 import InternalLifeNumericIdentityV1,internal_life_numeric_ids_v1
            identity=InternalLifeNumericIdentityV1(r.namespace,r.request.episode_ref,context["execution_id"],context["source_ref"],
                context["occurrence_digest"],context["before_digest"],ctx_task.column.canonical_digest)
            operation=internal_life_numeric_ids_v1(identity)["adopt"]
        else:
            operation=(life_numeric_trace_operation_v1(r.namespace,r.request.episode_ref,r.request.joint_operation_id)
                if profile=="native_trace" else life_encoding_baseline_ids_v1(r.namespace,r.request.episode_ref,r.request.joint_operation_id)["operation"])
        if task.metadata[0]!=operation:
            raise AuthorityUnavailable("Native signed trace/baseline has another actual producing operation")
    return task

def require_native_numeric_read_inventory_v3(reader,type_id):
    r,c=_require_control_v3(reader)
    from .d04_life_encoding_baseline_v1 import INVENTORIES
    from .d06_life_numeric_trace_v1 import KINDS
    allowed=frozenset((*INVENTORIES,"d01.persona_activation.v1","d01.persona_plan.v1","d03.self_perspective.v1",*KINDS))
    if (r.operation_kind!=TRACE_READ_V3 or c.plan is None or type_id not in allowed
            or type_id not in c.plan.fixed_type_ids):
        raise AuthorityUnavailable("Native trace inventory escaped its actual fixed installed family recipe")
    return r

class NativeTraceDependenciesTaskV3:
    def __init__(self,reader,token):
        r,c=_require_control_v3(reader)
        _require_native_dependencies_v3(r,c,token)
        self.reader,self.token=r,token;self.cursor="";self.rows=[];self.complete=False
        self.stamp=r.graph_stamp
    def advance(self,meter):
        r,c=_require_control_v3(self.reader)
        if r.graph_stamp!=self.stamp:raise AuthorityUnavailable("Native trace dependencies changed actual graph stamp")
        if self.complete:return True
        row=_runtime_bounded_fixed_row_v3(r.db,meter,"graph_dependencies",("dependency_token","dependency_revision"),
            "dependent_token=? AND dependency_token>? ORDER BY dependency_token",(self.token,self.cursor))
        if row is None:self.complete=True;return True
        from .domain_production_contracts_v1 import ProductionOperationLimitsV1
        if len(self.rows)>=ProductionOperationLimitsV1().max_graph_heads:
            raise AuthorityUnavailable("Native trace dependency coverage exceeds its original production frame bound")
        r.operation.retain(_heap(row)+256);self.rows.append(row);self.cursor=row[0]
        return False
    def require_header_v1(self,meter):
        r,c=_require_control_v3(self.reader)
        if not self.complete or r.graph._v2_graph_stamp(r.namespace)!=self.stamp:
            raise AuthorityUnavailable("Native trace dependency metadata lost complete current EOF")
        return self

def read_bound_native_numeric_trace_dependencies_v3(db,token):
    from .current_method_learning_read_v3 import _method_active,_need_method_input
    r=_method_active(db)
    if r is None or r.operation_kind!=TRACE_READ_V3:return False,None
    _require_control_v3(r)
    r,c=_require_control_v3(r);_require_native_dependencies_v3(r,c,token)
    identity=("native_numeric_trace_dependencies",token)
    task=r.attachments.get(identity)
    if task is None or not task.complete:_need_method_input(r,identity)
    with runtime_storage_quantum_v3(db)as meter:task.require_header_v1(meter)
    return True,tuple(task.rows)

def require_current_native_numeric_prepared_result_v3(graph,request,value,bundle):
    from .current_method_learning_read_v3 import _READERS
    record=_NATIVE_PREPARED_RESULTS.get(id(value))
    if record is None or record[0]is not value:
        raise AuthorityUnavailable("Native issuance requires its actual retained qualified preparation result")
    r=record[1];c=_NATIVE_CONTROLS.get(r)
    if (r not in _READERS or r.graph is not graph or r.request!=request or r.operation_kind!=JOINT_PREPARED_READ_V3
            or not r.read_finished or not r.complete or r.operation.closed or c is None or c.binding!=value.binding
            or graph._GraphCoordinator__d04_installed_joint_assembly.admin_bundle is not bundle
            or graph._GraphCoordinator__owner_leases.get(r.lease)!=r.owner_binding
            or graph._GraphCoordinator__owner_session_proofs.get(r.lease)!=r.session_proof):
        raise AuthorityUnavailable("Native issuance lost its actual current Owner/result lifetime")
    graph._authorize(r.lease,r.authority,frozenset({"d11"}),owner_read=True)
    token,session_request=r.session_proof
    port=graph._GraphCoordinator__content_fence_v2
    if graph._GraphCoordinator__store._db.in_transaction:
        raise AuthorityUnavailable("Native Owner/session observation must precede issuance transaction")
    if port.current_owner_session(namespace=r.namespace,authority_namespace=r.fence.scope.authority_namespace,
            request=session_request,token=token)is not True:
        raise AuthorityUnavailable("Native issuance current Owner session ended")
    _current_read_now(r)
    with graph._GraphCoordinator__store._lock:
        if graph._v2_graph_stamp(r.namespace)!=r.graph_stamp:
            raise AuthorityUnavailable("Native Source/current facts changed before actual queue claim")
    return value,record[2],record[3]

def read_bound_native_numeric_history_v3(db,token,revision,columns):
    from .current_life_numeric_paid_write_v3 import read_bound_numeric_paid_history_v3
    handled,value=read_bound_numeric_paid_history_v3(db,token,revision,columns)
    if handled:return handled,value
    from .current_method_learning_read_v3 import _method_active,read_bound_method_learning_attachment_v3
    r=_method_active(db)
    if r is None or r.operation_kind!=TRACE_READ_V3:return False,None
    caller_columns=tuple(columns)
    allowed={("value","valid"),("value","valid","event_id"),("event_id","value","valid"),
        ("value","valid","event_bot","event_persona","event_session","event_id")}
    if caller_columns not in allowed:
        raise AuthorityUnavailable("Native history has another exact actual reader shape")
    request=("graph_history",("event_id","value","valid"),("token","revision"),(token,revision))
    require_native_numeric_read_point_v3(r,request)
    return read_bound_method_learning_attachment_v3(db,table="graph_history",columns=caller_columns,
        key_columns=("token","revision"),key=(token,revision))

def require_native_numeric_read_quote_v3(reader,db,issuer,quote_id,version):
    r,c=_require_control_v3(reader)
    if db is not r.db or issuer is not r.graph._GraphCoordinator__d02_issuer:
        raise AuthorityUnavailable("Native paid quote consumer crossed actual installed authority")
    quotes=(c.quote,*(p["quote"]for p in c.paid.values()),*c.life.get("quotes",()))
    for quote in quotes:
        if (quote.quote_id,quote.version)==(quote_id,version):return True,quote
    raise AuthorityUnavailable("Native paid quote escaped its exact actual original family")


def _require_native_dependencies_v3(r,c,token):
    expected=life_numeric_trace_keys_v1(r.namespace,r.request.episode_ref,r.request.joint_operation_id)[-1].token
    from .d11_life_fact_provenance_v1 import ELIGIBILITY_TYPE as LIFE_ELIGIBILITY
    from .d11_life_outcome_provenance_v1 import ELIGIBILITY_TYPE as OUTCOME_ELIGIBILITY
    from .d10_life_progress_provenance_v1 import ELIGIBILITY_TYPE as PROGRESS_ELIGIBILITY
    key=AtomKey.from_token(token)
    if (r.operation_kind!=TRACE_READ_V3 or NamespaceId.from_key(key)!=r.namespace
            or token!=expected and (token not in c.tokens or key.type_name not in
                {LIFE_ELIGIBILITY,OUTCOME_ELIGIBILITY,PROGRESS_ELIGIBILITY})):
        raise AuthorityUnavailable("Native dependency family escaped its exact signed Life/trace eligibility")

def read_bound_native_numeric_dependencies_v3(db,*,table,columns,key_columns,key,order_column):
    from .current_method_learning_read_v3 import _method_active
    r=_method_active(db)
    if r is None or r.operation_kind!=TRACE_READ_V3:return False,None
    if (table,tuple(columns),tuple(key_columns),order_column)!=("graph_dependencies",
            ("dependency_token","dependency_revision"),("dependent_token",),"dependency_token") or len(key)!=1:
        raise AuthorityUnavailable("Native many-point reader requires its exact existing dependency cursor")
    return read_bound_native_numeric_trace_dependencies_v3(db,key[0])

def read_bound_native_life_action_refs_v3(db,namespace,action_ref):
    from .current_method_learning_read_v3 import _method_active
    r=_method_active(db)
    if r is None or r.operation_kind!=TRACE_READ_V3:return False,None
    r,c=_require_control_v3(r)
    if namespace!=r.namespace or action_ref!=c.life["prepared"]["plan"]["action_intent"]["ref"]:
        raise AuthorityUnavailable("Native Life action lookup crossed exact signed prepared Root")
    return True,((c.life["action_ref"],),)

class NativeLifeArtifactTaskV3:
    def __init__(self,reader,execution_id):
        r,c=_require_control_v3(reader)
        if r.operation_kind!=TRACE_READ_V3 or not c.life or execution_id!=c.life["binding"].execution_id:
            raise AuthorityUnavailable("Native artifact requires its exact completed Life execution")
        self.reader,self.execution_id=r,execution_id;self.offset=0;self.body=bytearray()
        self.metadata=self.row=None;self.complete=False
        from .c09_canonical_json_stream_v2 import C09CanonicalJSONStreamV2
        self.parser=C09CanonicalJSONStreamV2(ensure_ascii=True)
        r.operation.register_retained_state_v3(self)
    def _runtime_retained_heap_bytes_v3(self):
        return _heap(self.metadata)+_heap(self.row)+len(self.body)*2+65536
    def advance(self,meter):
        r,c=_require_control_v3(self.reader)
        where="bot=? AND persona=? AND execution_id=?";key=(*r.namespace.as_tuple,self.execution_id)
        columns=("binding_digest","artifact_ref","artifact_digest","artifact_length")
        metadata=_runtime_bounded_fixed_row_v3(r.db,meter,"graph_d11_life_artifact_stage_v1",columns,where,key)
        if self.metadata is None:
            if (metadata is None or metadata[:2]!=(c.life["binding"].digest,c.life["binding"].artifact_ref)
                    or not 1<=metadata[3]<=262144):
                raise AuthorityUnavailable("Native actual durable Life artifact differs from completed binding")
            self.metadata=metadata;return False
        if metadata!=self.metadata:raise AuthorityUnavailable("Native artifact metadata changed before whole EOF")
        from .c09_paged_sql_v2 import read_legacy_sql_cell_fragment_v2
        raw,total,kind=read_legacy_sql_cell_fragment_v2(r.db,table="graph_d11_life_artifact_stage_v1",
            column="artifact_bytes",where=where,parameters=key,start=self.offset,
            length=min(1024,self.metadata[3]-self.offset),meter=meter)
        if kind!="blob"or total!=self.metadata[3]:raise AuthorityUnavailable("Native artifact actual BLOB identity changed")
        if raw:
            r.operation.reserve_retained_state_growth_v3(self,len(raw)*6+4096)
            self.body.extend(raw);self.parser.feed(raw,lambda event:None);self.offset+=len(raw)
            r.operation.finish_retained_state_growth_v3(self);return False
        eof=self.parser.finish()
        if eof.sha256!=self.metadata[2]or eof.byte_count!=total:
            raise AuthorityUnavailable("Native artifact canonical SHA/length EOF differs")
        r.operation.reserve_retained_state_growth_v3(self,total*8+4096)
        data=bytes(self.body);self.body.clear()
        self.row=(self.metadata[0],self.metadata[1],data,self.metadata[2],self.metadata[3])
        self.complete=True;r.operation.finish_retained_state_growth_v3(self);return True
    def require_header_v1(self,meter):
        r,c=_require_control_v3(self.reader)
        actual=_runtime_bounded_fixed_row_v3(r.db,meter,"graph_d11_life_artifact_stage_v1",
            ("binding_digest","artifact_ref","artifact_digest","artifact_length"),
            "bot=? AND persona=? AND execution_id=?",(*r.namespace.as_tuple,self.execution_id))
        if not self.complete or actual!=self.metadata:raise AuthorityUnavailable("Native artifact lost complete current EOF")
        return self

def read_bound_native_life_artifact_v3(db,prepared):
    from .current_method_learning_read_v3 import _method_active,_need_method_input
    r=_method_active(db)
    if r is None or r.operation_kind!=TRACE_READ_V3:return False,None
    r,c=_require_control_v3(r)
    if prepared.binding!=c.life["binding"]:
        raise AuthorityUnavailable("Native artifact consumer crossed actual signed Life prepared binding")
    identity=("native_life_artifact",prepared.binding.execution_id)
    task=r.attachments.get(identity)
    if task is None or not task.complete:_need_method_input(r,identity)
    with runtime_storage_quantum_v3(db)as meter:task.require_header_v1(meter)
    return True,task.row

def read_bound_native_numeric_history_by_event_v3(db,token,event_id):
    from .current_method_learning_read_v3 import _method_active
    r=_method_active(db)
    if r is None or r.operation_kind!=TRACE_READ_V3:return False,None
    r,c=_require_control_v3(r)
    contract=c.life["contract"]
    if (token,event_id)!=(contract.reservation_ref,contract.body_prepare_operation_id):
        raise AuthorityUnavailable("Native Body history escaped actual signed reservation producing operation")
    handled,row=read_bound_native_numeric_history_v3(db,token,1,("event_id","value","valid"))
    with runtime_storage_quantum_v3(db)as meter:
        count=r.db.execute("SELECT count(*) FROM graph_history WHERE token=? AND event_id=?",(token,event_id)).fetchone()[0]
        meter.charge_read(8)
    return True,()if row is None or row[0]!=event_id else (row,)if count==1 else ()


class _NativeSeriesLocatorColumnV3(_NumericMetadataColumnV1):
    def retain_path_v3(self,path):
        return not path or path in {("root_ref",),("numeric_operation_id",)}

class NativeNonSeriesMetadataTaskV3:
    def __init__(self,reader,operation_id):
        r,c=_require_control_v3(reader)
        if r.operation_kind!=TRACE_READ_V3 or operation_id!=c.binding.operation_id:
            raise AuthorityUnavailable("Native nonSeries EOF needs its exact actual once CPU binding")
        self.reader,self.operation_id=r,operation_id
        self.table,self.column_name="graph_d04_originals_v3","payload_json"
        self.key_columns=("bot","persona","kind","original_ref")
        self.profile="native_series_locator";self.key=None;self.column=None
        self.cursor="";self.headers=[];self.metadata=None;self.complete=False;self.stamp=r.graph_stamp
    def advance(self,meter):
        r,c=_require_control_v3(self.reader)
        prefix=_runtime_bounded_fixed_row_v3(r.db,meter,"graph_d04_originals_v3",("payload_digest",),
            "bot=? AND persona=? AND kind=? AND original_ref=?",(*r.namespace.as_tuple,"series_final_native_prefix",self.operation_id))
        if prefix is not None:raise AuthorityUnavailable("Native once profile does not satisfy nonSeries prefix absence")
        if self.column is not None:
            if not self.column.advance(meter):return False
            raw=_detach_value_v3(self.column.frozen)
            if self.column.canonical_digest!=self.metadata[1]or raw["root_ref"]!=self.key[-1]:
                raise AuthorityUnavailable("Native series locator full original digest/header EOF differs")
            if raw["numeric_operation_id"]==self.operation_id:
                raise AuthorityUnavailable("Native once profile does not satisfy actual nonSeries root identity")
            self.headers.append((self.key[-1],self.metadata[1]));self.cursor=self.key[-1]
            self.column=None;return False
        row=_runtime_bounded_fixed_row_v3(r.db,meter,self.table,("original_ref","payload_digest"),
            "bot=? AND persona=? AND kind=? AND original_ref>? ORDER BY original_ref",
            (*r.namespace.as_tuple,"series_root",self.cursor))
        if row is None:self.complete=True;return True
        self.key=(*r.namespace.as_tuple,"series_root",row[0]);self.metadata=row
        self.column=_NativeSeriesLocatorColumnV3(self)
        r.operation.retain(_heap(row)+256)
        return False
    def require_header_v1(self,meter):
        r,c=_require_control_v3(self.reader)
        if not self.complete or r.graph_stamp!=self.stamp:
            raise AuthorityUnavailable("Native nonSeries metadata EOF lost actual current selection/epoch")
        prefix=_runtime_bounded_fixed_row_v3(r.db,meter,self.table,("payload_digest",),
            "bot=? AND persona=? AND kind=? AND original_ref=?",(*r.namespace.as_tuple,"series_final_native_prefix",self.operation_id))
        if prefix is not None:raise AuthorityUnavailable("Native nonSeries actual prefix absence changed")
        count=r.db.execute("SELECT count(*) FROM graph_d04_originals_v3 WHERE bot=? AND persona=? AND kind='series_root'",
            r.namespace.as_tuple).fetchone()[0];meter.charge_read(8)
        if count!=len(self.headers):raise AuthorityUnavailable("Native nonSeries complete metadata catalogue changed")
        for ref,digest in self.headers:
            actual=_runtime_bounded_fixed_row_v3(r.db,meter,self.table,("payload_digest",),
                "bot=? AND persona=? AND kind=? AND original_ref=?",(*r.namespace.as_tuple,"series_root",ref))
            if actual!=(digest,):raise AuthorityUnavailable("Native nonSeries exact original header changed")
        return self

def read_bound_native_nonseries_original_v3(db,namespace,operation_id):
    from .current_method_learning_read_v3 import _method_active,_need_method_input
    r=_method_active(db)
    if r is None or r.operation_kind!=TRACE_READ_V3:return False,None
    r,c=_require_control_v3(r)
    if namespace!=r.namespace or operation_id!=c.binding.operation_id:
        raise AuthorityUnavailable("Native nonSeries consumer crossed its exact once CPU operation")
    identity=("native_nonseries_metadata",operation_id)
    task=r.attachments.get(identity)
    if task is None or not task.complete:_need_method_input(r,identity)
    with runtime_storage_quantum_v3(db)as meter:task.require_header_v1(meter)
    return True,None

def read_bound_native_numeric_point_v3(db,*,table,columns,key_columns,key):
    from .current_life_numeric_paid_write_v3 import read_bound_numeric_paid_point_v3
    handled,value=read_bound_numeric_paid_point_v3(db,table=table,columns=columns,key_columns=key_columns,key=key)
    if handled:return handled,value
    from .current_method_learning_read_v3 import _method_active,read_bound_method_learning_attachment_v3
    r=_method_active(db)
    if r is None or r.operation_kind!=TRACE_READ_V3:return False,None
    request=(table,tuple(columns),tuple(key_columns),tuple(key))
    require_native_numeric_read_point_v3(r,request)
    return read_bound_method_learning_attachment_v3(db,table=table,columns=tuple(columns),
        key_columns=tuple(key_columns),key=tuple(key))

class _NativeMetadataRecheckPeakV3:
    def __init__(self,reader):
        self.reader,self.value=reader,None
        reader.operation.register_retained_state_v3(self)
    def _runtime_retained_heap_bytes_v3(self):return _heap(self.value)+256

def _native_metadata_row_v3(r,meter,table,columns,where,key):
    from .c09_paged_sql_v2 import _quote
    peak=_NATIVE_RECHECKS.get(r)
    if peak is None:peak=_NativeMetadataRecheckPeakV3(r);_NATIVE_RECHECKS[r]=peak
    lengths=r.db.execute("SELECT "+",".join("length(CAST("+_quote(n)+" AS BLOB))"for n in columns)
        +" FROM "+_quote(table)+" WHERE "+where+" LIMIT 1",key).fetchone()
    meter.charge_read(8*len(columns))
    if lengths is None:
        peak.value=None;r.operation.refresh_retained_state_v3(peak);return None
    amount=sum(n or 0 for n in lengths)
    meter.require_available(amount+256)
    r.operation.reserve_retained_state_growth_v3(peak,amount*8+4096)
    peak.value=meter.read_fixed_row(r.db,table,columns,where,key)
    r.operation.finish_retained_state_growth_v3(peak)
    return peak.value

def recheck_native_numeric_metadata_header_v3(task,meter):
    r=require_numeric_read_work_v3(task.reader)
    from .current_life_numeric_metadata_v1 import NumericMetadataTaskV1
    if (r.operation_kind not in {JOINT_PREPARED_READ_V3,TRACE_READ_V3}or type(task)is not NumericMetadataTaskV1
            or r.attachments.get(("numeric_owner_metadata",task.identity))is not task):
        raise AuthorityUnavailable("Native header peak requires its actual private issued metadata task")
    return _native_metadata_row_v3(r,meter,task.table,task.header_columns,
        " AND ".join(name+"=?"for name in task.key_columns),task.key)

def recheck_native_numeric_source_header_v3(reader,meter,task):
    r=require_numeric_read_work_v3(reader)
    from .current_method_learning_read_v3 import _GENERAL_METHOD_SOURCE_TASKS_V1
    if (r.operation_kind not in {JOINT_PREPARED_READ_V3,TRACE_READ_V3}
            or _GENERAL_METHOD_SOURCE_TASKS_V1.get(r,{}).get(task.key.token)is not task
            or task.reader()is not r or NamespaceId.from_key(task.key)!=r.namespace):
        raise AuthorityUnavailable("Native Source header peak requires its exact actual completed ancestor leaf")
    return _native_metadata_row_v3(r,meter,"graph_atoms",("revision","valid","value_cell_id"),
        "token=? AND bot=? AND persona=?",(task.key.token,*r.namespace.as_tuple))
