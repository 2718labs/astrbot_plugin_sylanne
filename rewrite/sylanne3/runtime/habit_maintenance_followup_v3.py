"""Actual Habit outcome and expired registration receivers; no execution refresh."""
from dataclasses import fields
from weakref import WeakKeyDictionary
from ..authority_service.contract import AuthorityUnavailable
from ..graph_types import AtomKey
from ..runtime_contracts import NamespaceId,canonical_digest,canonical_serialize
from .dispatch_initial_source_read_v3 import DispatchOriginalJSONReadV3
from .conditioned_producer_source_metadata_v3 import ConditionedLocatorJSONV3,ConditionedMetadataJSONStreamV3
EVENT="actual_life_outcome_available_for_habit_v3"
TARGET_PROVENANCE_V3="habit_original_maintenance_followup_v3"
_ISSUER=object()
_STATES=WeakKeyDictionary()
_PREPARED=WeakKeyDictionary()

def source_note_habit_outcome_events_v3(db,*,frame,prepared,terminal,issuer):
    from .d11_life_contract_v1 import RegisteredLifePlanV2
    if type(prepared.plan)is not RegisteredLifePlanV2:return ()
    from .d11_life_preparation_v1 import _read
    saved=_read(db,issuer=issuer,namespace=terminal.binding.namespace,kind="source_note_action",
        ref="life-root:"+terminal.binding.operation_id)
    if saved is None:raise AuthorityUnavailable("Life outcome has no actual signed SourceNote Action root")
    raw,operation=saved
    if raw["schema"]!="d08.habit-source-note-action-original.v1":return ()
    from .d10_habit_v1 import habit_source_note_original_from_wire_v1
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    root=habit_source_note_original_from_wire_v1(raw);b=terminal.binding
    actual=read_adopted_domain_operation_v1(db,b.namespace,operation)
    if(actual is None or(actual["domain"],actual["operation_kind"])!=("d08","prepare_current_habit_source_note_action_v1")
            or operation!=root.action_operation_id or canonical_digest(actual["receipt"])!=root.receipt_digest
            or(root.action_intent_ref,root.activity_id,root.effect_id)!=(prepared.plan.action_intent.ref,b.activity_id,b.effect_id)):
        raise AuthorityUnavailable("Habit outcome event changed its actual signed Action producer/Lineage")
    from .domain_production_contracts_v1 import ProductionOutboxStageV1,ProductionOriginalRefV1
    return(ProductionOutboxStageV1(b.namespace,frame.envelope.identity.operation_id,"d10",EVENT,
        ProductionOriginalRefV1("d08.habit_source_note_action","life-root:"+operation,canonical_digest(raw))),)

def _retain_v3(profile,path):
    if not path:return True
    if profile in {"occurrence","policy","progress","signed_action","signed_outcome"}:return True
    if path[0]in {"schema","namespace","identity","parent_budget"}:return True
    if path[0]=="request":return len(path)==1 or path[1]in {"activity_outcome_ref","occurrence_ref","expected_revision"}
    if path[0]!="provenance":return False
    if len(path)==1:return True
    if path[1]in {"occurrence","actual_progress","terminal","core_qualification"}:return True
    if path[1]=="core_standing_original":return len(path)==2 or path[2]=="operation_id"
    if path[1]!="habit_activity_execution_v1":return False
    return not(len(path)>=4 and path[2]=="selector"and path[3]=="command")

class _ColumnV3(DispatchOriginalJSONReadV3):
    def __init__(self,state,profile,*,table,column,key_columns,key,cell_id=None):
        self.state,self.profile=state,profile
        super().__init__(state,table=table,column=column,key_columns=key_columns,key=key,cell_id=cell_id)
        if self.cell is not None:
            from ..runtime_storage_v3 import begin_runtime_cell_read_v3
            self.cell=begin_runtime_cell_read_v3(self.db,cell_id,erasure_owner_ref=key[0])
            if self.cell.header[0]not in {"canonical-json.ascii.v1","canonical-json.utf8.v1"}:
                raise AuthorityUnavailable("Habit maintenance metadata requires actual canonical cell")
        self.capture=ConditionedLocatorJSONV3(self)
        self.capture.retain_path_v3=lambda path:_retain_v3(profile,path)
        self.parser=ConditionedMetadataJSONStreamV3(self.capture,
            ensure_ascii=self.cell is None or self.cell.header[0]=="canonical-json.ascii.v1")
    def _actual(self):self.state.require_current();return self
    def _emit(self,event):self.capture._emit_v3(event);self.value=self.capture.value

class _MaintenanceLocatorV3:
    def __init__(self,issuer,graph,context,bundle,operation,work,key,header,*,expired=None):
        if issuer is not _ISSUER:raise AuthorityUnavailable("Actual Habit maintenance receiver factory required")
        self.graph,self.context,self.bundle,self.operation,self.work=graph,context,bundle,operation,work
        self.store=graph._GraphCoordinator__store;self.db=self.store._db
        self.namespace=bundle.installation_policy.namespace;self.key,self.header=key,header
        self.graph_stamp=graph._v2_graph_stamp(self.namespace)
        self.expired=expired;self.phase="cause";self.column=None;self.pending=None
        self.producers={};self.heads={};self.history=[];self.signed={}
        self.occurrence=self.occurrence_ref=self.current_policy=self.standing_policy=None
        self.qualification=self.qualification_ref=self.qualification_digest=None
        self.registration=self.root=self.progress=self.outcome=None
        self.policy_cursor=0;self.result=None
        _STATES[self]=(graph,context,bundle,operation,work,key,header,self.graph_stamp,expired)
    def require_current(self):
        from ..runtime_context import RuntimeContext
        if(_STATES.get(self)!=(self.graph,self.context,self.bundle,self.operation,self.work,self.key,self.header,self.graph_stamp,self.expired)
                or type(self.context)is not RuntimeContext or self.context._v2_coordinator is not self.graph
                or self.context._v2_model_bundle is not self.bundle or self.context._v2_namespace!=self.namespace
                or self.operation.closed or self.work.state is not self or self.work.operation is not self.operation
                or self.work.coordinator is not self.graph or self.graph._v2_graph_stamp(self.namespace)!=self.graph_stamp):
            raise AuthorityUnavailable("Habit maintenance metadata lost actual RuntimeContext/Work/Graph")
        if self.result is None:self.work._require_invocation(self.graph)
        return self
    def _producer_v3(self,operation,meter):
        old=self.producers.get(operation)
        if old is not None:return old
        header=meter.read_fixed_row(self.db,"graph_domain_production_originals_v1",
            ("domain","operation_kind","request_digest","original_digest","receipt_digest","bundle_digest"),
            "bot=? AND persona=? AND operation_id=?",(*self.namespace.as_tuple,operation))
        bundle=meter.read_fixed_row(self.db,"graph_bundle_operations",("digest","commit_seq"),
            "bot=? AND persona=? AND operation_id=?",(*self.namespace.as_tuple,operation))
        if(header is None or bundle is None or bundle[0]!=header[5]or type(bundle[1])is not int or bundle[1]<1):
            raise AuthorityUnavailable("Habit maintenance metadata has no real positive producer COMMIT")
        self.column=_ColumnV3(self,"producer",table="graph_domain_production_originals_v1",
            column="original_payload_json",key_columns=("bot","persona","operation_id"),key=(*self.namespace.as_tuple,operation))
        self.pending=("producer",operation,header,bundle);return None
    def _head_v3(self,ref,profile,meter):
        if ref in self.heads:return self.heads[ref][1]
        key=AtomKey.from_token(ref)
        if NamespaceId.from_key(key)!=self.namespace or key.type_name!={"occurrence":"d10.habit_occurrence.v1","policy":"d10.habit_policy.v1","progress":"d10.life_progress.v1"}[profile]:
            raise AuthorityUnavailable("Habit maintenance metadata selected another actual family/namespace")
        row=meter.read_fixed_row(self.db,"graph_atoms",("revision","valid","value_cell_id"),
            "bot=? AND persona=? AND token=?",(*self.namespace.as_tuple,ref))
        if row is None or row[1]!=1 or type(row[0])is not int or row[0]<1 or row[2]is None:
            raise AuthorityUnavailable("Habit maintenance has no live actual selected metadata head")
        self.column=_ColumnV3(self,profile,table="graph_atoms",column="value",
            key_columns=("token","bot","persona"),key=(ref,*self.namespace.as_tuple),cell_id=row[2])
        self.pending=("head",ref,row,profile);return None
    def _signed_v3(self,kind,ref,meter):
        k=(kind,ref)
        if k in self.signed:return self.signed[k][1]
        header=meter.read_fixed_row(self.db,"graph_d11_life_originals_v1",
            ("producing_operation_id","payload_digest","signature"),
            "bot=? AND persona=? AND kind=? AND original_ref=?",(*self.namespace.as_tuple,kind,ref))
        if header is None:raise AuthorityUnavailable("Habit maintenance lacks actual signed Action/outcome original")
        from .d11_life_preparation_v1 import SIGN_KIND
        self.graph._GraphCoordinator__d11_issuer._signer.verify(SIGN_KIND,
            canonical_serialize((self.namespace,kind,ref,header[1])),header[2])
        self.column=_ColumnV3(self,"signed_action"if kind=="source_note_action"else"signed_outcome",
            table="graph_d11_life_originals_v1",column="payload_json",
            key_columns=("bot","persona","kind","original_ref"),key=(*self.namespace.as_tuple,kind,ref))
        self.pending=("signed",k,header);return None
    def _finish_column_v3(self):
        c=self.column;p=self.pending;raw=c.require_v3(self)
        if p[0]=="producer":
            _,operation,header,bundle=p
            if(c.sha256!=header[3]or raw["schema"]!=header[0]+".current-"+header[1]+".v1"
                    or raw["namespace"]!={"bot_id":self.namespace.bot_id,"persona_id":self.namespace.persona_id}
                    or(raw["identity"]["operation_id"],raw["identity"]["phase"])!=(operation,header[1])):
                raise AuthorityUnavailable("Habit maintenance canonical producer EOF changed its exact actual identity")
            self.producers[operation]=(header,raw,bundle)
        elif p[0]=="head":
            _,ref,header,profile=p
            if profile=="occurrence":
                from ..domains.d10.habit_occurrence_v1 import habit_value_from_wire_v1,habit_occurrence_key_v1,HabitOccurrenceV1
                if c.capture.fields_seen!={f.name for f in fields(HabitOccurrenceV1)}:
                    raise AuthorityUnavailable("Habit maintenance occurrence exact fields differ")
                value=habit_value_from_wire_v1("d10.habit_occurrence.v1",raw)
                if value.namespace!=self.namespace or habit_occurrence_key_v1(self.namespace,value.occurrence_id).token!=ref:
                    raise AuthorityUnavailable("Habit maintenance occurrence fullPK differs")
            elif profile=="progress":
                from ..domains.d10.production_operations_v1 import LifeProgressHeadV1
                from .domain_production_erasure_v1 import decode_typed_production_value_v1
                decode_typed_production_value_v1(raw,LifeProgressHeadV1);value=raw
            else:
                from ..domains.d10.habit_policy_v1 import graph_adopted_habit_policy_from_wire_v1,habit_policy_key_v1
                value=graph_adopted_habit_policy_from_wire_v1(raw)
                if value.definition.namespace!=self.namespace or habit_policy_key_v1(self.namespace,value.definition.policy_id).token!=ref:
                    raise AuthorityUnavailable("Habit maintenance policy fullPK differs")
            self.heads[ref]=(header,value)
        elif p[0]=="signed":
            _,key,header=p
            if c.sha256!=header[1]:raise AuthorityUnavailable("Habit signed Action/outcome canonical EOF differs")
            self.signed[key]=(header,raw)
        else:
            _,row=p
            from ..domains.d10.habit_policy_v1 import graph_adopted_habit_policy_from_wire_v1
            policy=graph_adopted_habit_policy_from_wire_v1(raw)
            if policy.definition.namespace!=self.namespace:raise AuthorityUnavailable("Historical policy metadata crossed namespace")
            self.history.append((row,policy))
            if(policy.definition.revision,policy.digest)==(self.occurrence.policy_revision,self.occurrence.policy_digest):
                if self.standing_policy is not None:raise AuthorityUnavailable("Historical standing policy metadata is ambiguous")
                self.standing_policy=policy
        self.column=self.pending=None
    def advance(self,meter):
        self.require_current()
        row=meter.read_fixed_row(self.db,"graph_domain_production_outbox_v1",
            ("causal_operation_id","receiver_domain","event_kind","original_ref","original_digest","state","consumer_operation_id"),
            "bot=? AND persona=? AND dedupe_key=?",(*self.namespace.as_tuple,self.key))
        if row!=self.header:raise AuthorityUnavailable("Habit maintenance actual pending event changed")
        if self.column is not None:
            if self.column.advance(meter):self._finish_column_v3()
            return False
        if self.phase=="cause":
            cause=self._producer_v3(self.header[0],meter)
            if cause is None:return False
            header,raw,_=cause
            if self.expired is None:
                if header[:2]!=("d10","advance_life")or self.header[1:3]!=("d10",EVENT):
                    raise AuthorityUnavailable("Habit outcome receiver has another fixed producer")
                raw_root=self._signed_v3("source_note_action",self.header[3],meter)
                if raw_root is None:return False
                from .d10_habit_v1 import habit_source_note_original_from_wire_v1,HabitSourceNoteOriginalV1
                self.root=habit_source_note_original_from_wire_v1(raw_root)
                if type(self.root)is not HabitSourceNoteOriginalV1 or canonical_digest(raw_root)!=self.header[4]:
                    raise AuthorityUnavailable("Habit outcome receiver lost its actual signed Habit Action root")
                self.occurrence_ref=self.root.occurrence_ref
                self.qualification_ref,self.qualification_digest=self.root.qualification_original_ref,self.root.qualification_original_digest
            else:
                if header[:2]!=("d10","register_habit_occurrence_v1"):
                    raise AuthorityUnavailable("Only an actually registered waiting occurrence can become miss maintenance")
                from ..domains.d10.habit_occurrence_v1 import habit_value_from_wire_v1,habit_occurrence_key_v1
                value=habit_value_from_wire_v1("d10.habit_occurrence.v1",raw["provenance"]["occurrence"])
                self.occurrence_ref=habit_occurrence_key_v1(self.namespace,value.occurrence_id).token
            self.phase="occurrence";return False
        if self.phase=="occurrence":
            occurrence=self._head_v3(self.occurrence_ref,"occurrence",meter)
            if occurrence is None:return False
            self.occurrence=occurrence
            if self.expired is not None:
                from .first_ingress_v2 import trusted_upper
                now=trusted_upper(self.graph._GraphCoordinator__content_fence_v2.read_ingress_clock(self.graph._GraphCoordinator__scene_clock_policy))
                if occurrence.state not in {"registered","waiting"}or occurrence.qualification_original_ref is not None or now<occurrence.original_deadline_utc:
                    raise AuthorityUnavailable("Miss receiver cannot clear an admitted/active/unknown or unexpired original effect")
            else:
                if occurrence.state not in {"qualified","active","unknown"}or occurrence.qualification_original_ref!=self.qualification_ref:
                    raise AuthorityUnavailable("Habit outcome receiver changed actual previous qualification")
                action=self._producer_v3(self.root.action_operation_id,meter)
                if action is None:return False
                from .habit_followup_source_v3 import _metadata_producer_selector_v3,_ExecutionProducerLocatorV3
                selected=_metadata_producer_selector_v3(*action[0][:2],action[1]["provenance"]["habit_activity_execution_v1"])
                if(type(selected)is not _ExecutionProducerLocatorV3 or selected.occurrence_ref!=self.occurrence_ref
                        or(selected.qualification_original_ref,selected.qualification_original_digest)!=(self.qualification_ref,self.qualification_digest)):
                    raise AuthorityUnavailable("Habit outcome lacks its exact real Action producer qualification tuple")
                self.qualification=selected.qualification_selector
            self.phase="policy";return False
        if self.phase=="policy":
            policy=self._head_v3(self.occurrence.policy_ref,"policy",meter)
            if policy is None:return False
            self.current_policy=policy
            if(policy.definition.revision,policy.digest)==(self.occurrence.policy_revision,self.occurrence.policy_digest):
                self.standing_policy=policy
            self.phase="history"if self.standing_policy is None else"standing";return False
        if self.phase=="history":
            row=meter.read_fixed_row(self.db,"graph_history",("revision","event_bot","event_persona","event_id","valid","value_cell_id"),
                "token=? AND revision>? ORDER BY revision",(self.occurrence.policy_ref,self.policy_cursor))
            if row is None:
                if self.standing_policy is None:raise AuthorityUnavailable("Habit maintenance original standing history is absent or retired")
                self.phase="standing";return False
            if row[1:3]!=self.namespace.as_tuple:raise AuthorityUnavailable("Habit standing history crossed namespace")
            self.policy_cursor=row[0]
            if row[4]!=1:return False
            self.column=_ColumnV3(self,"policy",table="graph_history",column="value",
                key_columns=("token","revision"),key=(self.occurrence.policy_ref,row[0]),cell_id=row[5])
            self.pending=("history",row);return False
        if self.phase=="standing":
            standing=self._producer_v3(self.standing_policy.adoption_operation_id,meter)
            if standing is None:return False
            from .d10_habit_v1 import POLICY_OPERATIONS,habit_registration_operation_id_v1
            if standing[0][0]!="d10"or standing[0][1]not in POLICY_OPERATIONS:
                raise AuthorityUnavailable("Habit standing metadata has no actual policy producer")
            registration=self._producer_v3(habit_registration_operation_id_v1(self.namespace,self.occurrence.occurrence_id),meter)
            if registration is None:return False
            if registration[0][:2]!=("d10","register_habit_occurrence_v1"):
                raise AuthorityUnavailable("Habit maintenance actual registration producer differs")
            self.registration=registration
            if self.qualification is not None:
                q=self.qualification
                if(q.occurrence_original_ref,q.occurrence_original_digest,q.standing_authorization_original_ref,q.standing_authorization_original_digest)!=(
                        "d10-current:"+registration[0][3][:48],registration[0][3],self.standing_policy.core_original_ref,self.standing_policy.core_original_digest):
                    raise AuthorityUnavailable("Habit maintenance historical qualification/registration/standing tuple differs")
            self.phase="outcome"if self.expired is None else"ready";return False
        if self.phase=="outcome":
            cause=self.producers[self.header[0]];raw=cause[1];progress=raw["provenance"]["actual_progress"]
            from .d11_life_contract_v1 import RegisteredLifeOutcomeV2,life_from_wire_v1
            outcome_raw=self._signed_v3("outcome",raw["request"]["activity_outcome_ref"],meter)
            if outcome_raw is None:return False
            self.outcome=life_from_wire_v1(outcome_raw,RegisteredLifeOutcomeV2);self.progress=progress
            from ..graph_types import Owner
            progress_ref=AtomKey(Owner("activity",*self.namespace.as_tuple,self.occurrence.activity_id),
                "d10.life_progress.v1",self.occurrence.effect_id).token
            current=self._head_v3(progress_ref,"progress",meter)
            if current is None:return False
            if current!=progress:raise AuthorityUnavailable("Habit current progress differs from actual positive Life COMMIT")
            self.progress_ref=progress_ref
            o=self.occurrence
            if(progress["activity_id"],progress["effect_id"],progress["recipe_ref"],progress["terminal_ref"])!=(
                    o.activity_id,o.effect_id,o.recipe_ref,self.outcome.terminal_original_ref):
                raise AuthorityUnavailable("Habit actual Life progress belongs to another original occurrence/effect")
            self.phase="ready";return False
        self.result=HabitMaintenanceFollowupPreparedV3(_ISSUER,self);return True

class HabitMaintenanceFollowupPreparedV3:
    def __init__(self,issuer,state):
        if issuer is not _ISSUER or state.phase!="ready":raise AuthorityUnavailable("Actual complete maintenance metadata required")
        from ..authority_service.current_habit_maintenance_v1 import HabitOriginalMaintenanceSelectorV1
        from .d10_habit_v1 import RecordHabitMissRequestV1,AdoptHabitOutcomeRequestV1
        from .habit_maintenance_issuance_v1 import habit_maintenance_typed_command_digest_v1
        from .domain_production_registry_v1 import installed_operation_v1
        from ..domains.d01.production_operations_v1 import plain_v1
        o=state.occurrence;revision=state.heads[state.occurrence_ref][0][0]
        if state.expired is not None:
            kind="record_habit_miss_v1";command=RecordHabitMissRequestV1(state.occurrence_ref,revision,o.cue_original_ref)
        else:
            from ..memory_types import source_key
            from .d10_life_outcome_v2 import life_experience_source_id_from_identity_v3
            experience=source_key(*state.namespace.as_tuple,life_experience_source_id_from_identity_v3(
                state.namespace,o.activity_id,o.effect_id)).token
            kind="adopt_habit_outcome_v1"
            command=AdoptHabitOutcomeRequestV1(state.occurrence_ref,revision,state.progress_ref,
                state.heads[state.progress_ref][0][0],state.producers[state.header[0]][1]["request"]["activity_outcome_ref"],
                state.outcome.terminal_original_ref,tuple(state.outcome.paid_cost_refs),experience,
                "d10-current:"+state.producers[state.header[0]][0][3][:48])
        operation="habit-original-maintenance:"+canonical_digest((state.namespace,state.key,kind,state.occurrence_ref,revision))[:48]
        standing=state.producers[state.standing_policy.adoption_operation_id][1]["provenance"]["core_standing_original"]
        current=state.current_policy;old=state.standing_policy;registration=state.registration
        selector=HabitOriginalMaintenanceSelectorV1(state.namespace,state.bundle.installation_policy.installation_id,
            o.policy_ref,kind,operation,habit_maintenance_typed_command_digest_v1(installed_operation_v1(kind),command),
            state.occurrence_ref,revision,current.core_original_ref,current.core_original_digest,
            old.core_original_ref,old.core_original_digest,standing["operation_id"],
            "d10-current:"+registration[0][3][:48],registration[0][3],o.cue_original_ref,o.cue_original_digest,
            command,state.qualification,state.qualification_ref,state.qualification_digest)
        self.graph,self.context,self.bundle=state.graph,state.context,state.bundle
        self.locator,self.selector,self.kind,self.request=state,selector,kind,command
        self.producer_digest,self.receipt_digest=state.producers[state.header[0]][0][3:5]
        self.target=plain_v1({"schema":"d10.habit-original-maintenance-followup-target.v3","dedupe_key":state.key,
            "producer_operation_id":state.header[0],"producer_original_digest":self.producer_digest,
            "producer_receipt_digest":self.receipt_digest,"event_kind":state.header[2],"selector":selector,
            "selector_digest":canonical_digest(selector)})
        _PREPARED[self]=(state,selector,kind,command,canonical_digest(self.target))
    def require_current(self,graph,context,bundle):
        s=self.locator;s.require_current()
        if(_PREPARED.get(self)!=(s,self.selector,self.kind,self.request,canonical_digest(self.target))
                or s.result is not self or(graph,context,bundle)!=(self.graph,self.context,self.bundle)):
            raise AuthorityUnavailable("Habit maintenance handoff lost its complete actual metadata/typed selector")
        return self

def is_maintenance_locator_v3(value):return type(value)is _MaintenanceLocatorV3

def promote_expired_habit_followup_v3(locator):
    from .first_ingress_v2 import trusted_upper
    from .habit_activity_history_v1 import _root_selector_v1
    from .habit_followup_source_v3 import _ExecutionProducerLocatorV3
    old=locator.selector.old_selector
    root=old.qualification_selector if type(old)is _ExecutionProducerLocatorV3 else _root_selector_v1(old)
    now=trusted_upper(locator.graph._GraphCoordinator__content_fence_v2.read_ingress_clock(locator.graph._GraphCoordinator__scene_clock_policy))
    if now<root.original_deadline_utc:return False
    if locator.producer_header[:2]!=("d10","register_habit_occurrence_v1"):
        raise AuthorityUnavailable("Expired unregistered/admitted Habit cause cannot execute or invent miss maintenance")
    state=_MaintenanceLocatorV3(_ISSUER,locator.graph,locator.context,locator.bundle,locator.operation,
        locator.work,locator.key,locator.header,expired=locator)
    locator.work.state=state;locator.work.phase="habit_expired_original_metadata_eof"
    return True

def prepare_current_habit_maintenance_followup_v3(graph,bootstrap,bundle,*,dedupe_key,context):
    from ..runtime_context import RuntimeContext
    from ..graph_worker import require_graph_storage_work_admission_v3,create_graph_storage_work_v3
    from ..runtime_storage_v3 import (begin_runtime_storage_operation_v3,bind_runtime_storage_operation_v3,
        runtime_storage_quantum_v3,finish_runtime_storage_operation_v3)
    from .current_habit_source_read_v3 import HABIT_SOURCE_WORK_KIND_V3
    from .first_ingress_v2 import trusted_upper
    from uuid import uuid4
    graph._admin(bootstrap);require_graph_storage_work_admission_v3(graph)
    now=trusted_upper(graph._GraphCoordinator__content_fence_v2.read_ingress_clock(graph._GraphCoordinator__scene_clock_policy))
    operation=begin_runtime_storage_operation_v3(graph._GraphCoordinator__store._db,"habit-maintenance-followup:"+uuid4().hex,now+60.0)
    try:
        with bind_runtime_storage_operation_v3(operation,graph._GraphCoordinator__store._db),graph._GraphCoordinator__store._lock,runtime_storage_quantum_v3(graph._GraphCoordinator__store._db)as meter:
            header=meter.read_fixed_row(graph._GraphCoordinator__store._db,"graph_domain_production_outbox_v1",
                ("causal_operation_id","receiver_domain","event_kind","original_ref","original_digest","state","consumer_operation_id"),
                "bot=? AND persona=? AND dedupe_key=?",(*bundle.installation_policy.namespace.as_tuple,dedupe_key))
        if header is None or header[2]!=EVENT:
            finish_runtime_storage_operation_v3(operation);return False,None
        if(type(context)is not RuntimeContext or context._v2_coordinator is not graph
                or context._v2_bootstrap is not bootstrap or context._v2_model_bundle is not bundle
                or header[1]!="d10"or header[5]not in {"pending","waiting"}or header[6]is not None
                or dedupe_key!=canonical_digest((bundle.installation_policy.namespace,header[0],header[1],header[2]))):
            raise AuthorityUnavailable("Habit outcome receiver needs actual RuntimeContext and pending exact event")
        state=_MaintenanceLocatorV3(_ISSUER,graph,context,bundle,operation,None,dedupe_key,header)
        work=create_graph_storage_work_v3(graph,kind=HABIT_SOURCE_WORK_KIND_V3,operation_id=operation.operation_id,
            selection_digest=operation.selection_digest,deadline_utc=operation.deadline_utc,state=state,operation=operation)
        state.work=work;_STATES[state]=(graph,context,bundle,operation,work,dedupe_key,header,state.graph_stamp,None)
        work._require_invocation(graph,initial=True);work.phase="habit_outcome_original_metadata_eof"
        return True,work
    except BaseException:finish_runtime_storage_operation_v3(operation);raise

def advance_habit_maintenance_locator_v3(graph,work):
    from ..runtime_storage_v3 import bind_runtime_storage_operation_v3,runtime_storage_quantum_v3
    from ..graph_worker import GraphStorageStepV3
    s=work.state
    if s.graph is not graph or not is_maintenance_locator_v3(s):raise AuthorityUnavailable("Actual maintenance metadata Work required")
    with bind_runtime_storage_operation_v3(work.operation,s.db),s.store._lock,runtime_storage_quantum_v3(s.db)as meter:
        complete=s.advance(meter)
    return GraphStorageStepV3("complete",s.result)if complete else GraphStorageStepV3("progress")

def finish_habit_maintenance_locator_v3(graph,work,error):
    from ..runtime_storage_v3 import finish_runtime_storage_operation_v3
    s=work.state
    if s.graph is not graph or s.work is not work:raise AuthorityUnavailable("Maintenance finalizer crossed actual Work")
    if error is None:work.result_lease=work.operation
    else:_STATES.pop(s,None);finish_runtime_storage_operation_v3(work.operation)

def require_habit_maintenance_terminal_v3(value,work):
    if(type(value)is not HabitMaintenanceFollowupPreparedV3 or value.locator is not work.state
            or value.locator.work is not work or value.locator.result is not value):
        raise AuthorityUnavailable("Actual same-Work complete Habit maintenance handoff required")
    return value.require_current(work.coordinator,value.context,value.bundle)

def prepare_habit_maintenance_followup_child_v3(graph,context,bundle,*,handoff):
    handoff.require_current(graph,context,bundle)
    work=graph.maintain_current_habit_original_v1(context,handoff.selector)
    from .habit_followup_source_v3 import _CHILDREN
    _CHILDREN[work.state]=(handoff,canonical_digest(handoff.target))
    return work

def validate_habit_maintenance_child_source_v3(reader,handoff,digest):
    handoff.require_current(reader.graph,handoff.context,handoff.bundle)
    from .habit_maintenance_source_v3 import habit_maintenance_source_reader_v3
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    state=habit_maintenance_source_reader_v3(reader)
    if(state is None or state.context is not handoff.context or state.selector!=handoff.selector
            or reader.request!=handoff.request or digest!=canonical_digest(handoff.target)):
        raise AuthorityUnavailable("Habit maintenance child changed its complete frozen selector/command")
    producer=read_adopted_domain_operation_v1(reader.db,reader.namespace,handoff.locator.header[0])
    if producer is None or producer["original_digest"]!=handoff.producer_digest or canonical_digest(producer["receipt"])!=handoff.receipt_digest:
        raise AuthorityUnavailable("Habit maintenance child lost actual pending cause COMMIT")

def record_habit_maintenance_followup_after_cas_v3(witness,db,*,frame,stage,receipt,original,pair):
    from .domain_production_commit_v1 import _ACTIVE,_ProductionCommitWitnessV1
    from .habit_followup_source_v3 import _require_actual_followup_w01_phase_v3
    from .habit_maintenance_issuance_v1 import require_habit_maintenance_issuance_v1
    from .habit_maintenance_provenance_v1 import MAINTENANCE_PROVENANCE_V1
    import json
    actual,handoff,reader=pair;phase=_require_actual_followup_w01_phase_v3(witness,reader)
    facts=require_habit_maintenance_issuance_v1(phase.issued,reader.graph,phase.scope)
    if(type(witness)is not _ProductionCommitWitnessV1 or _ACTIVE.get(id(witness))is not witness
            or witness.frame is not actual or frame is not actual or witness.graph is not reader.graph
            or witness.runtime is not reader.runtime or witness.scope is not phase.scope
            or witness.request!=handoff.request or witness.operation.operation_kind!=handoff.kind
            or facts.request!=handoff.selector or receipt.status!="committed"
            or receipt.operation_id!=handoff.selector.operation_id or receipt.operation_digest!=witness.bundle.digest
            or not db.in_transaction or db is not reader.db or stage.original_digest!=original.original_digest):
        raise AuthorityUnavailable("Habit maintenance disposition needs actual private current Core same-CAS witness")
    from ..domains.d01.production_operations_v1 import plain_v1
    provenance=json.loads(stage.original_payload_json)["provenance"][MAINTENANCE_PROVENANCE_V1]
    if(provenance["selector"]!=plain_v1(handoff.selector)
            or json.loads(stage.original_payload_json)["provenance"].get(TARGET_PROVENANCE_V3)!=handoff.target):
        raise AuthorityUnavailable("Habit maintenance original did not seal its complete actual event selector")
    value={"schema":"d10.habit-original-maintenance-followup-disposition.v3","state":"completed","target":handoff.target,
        "consumer_operation_id":receipt.operation_id,"receipt_digest":canonical_digest(receipt),
        "original_ref":original.original_ref,"original_digest":original.original_digest}
    cursor=db.execute("UPDATE graph_domain_production_outbox_v1 SET state=?,consumer_operation_id=?,receipt_json=? "
        "WHERE bot=? AND persona=? AND dedupe_key=? AND causal_operation_id=? AND receiver_domain=? AND event_kind=? "
        "AND original_ref=? AND original_digest=? AND state=? AND consumer_operation_id IS ?",
        ("completed",receipt.operation_id,canonical_serialize(value),*reader.namespace.as_tuple,handoff.locator.key,*handoff.locator.header))
    if cursor.rowcount!=1:raise AuthorityUnavailable("Habit maintenance event changed before same-CAS disposition")
    return value

from contextlib import contextmanager
@contextmanager
def bind_habit_maintenance_followup_frame_v3(frame,reader):
    from .habit_followup_source_v3 import bind_followup_frame_v3,release_followup_frame_v3
    bind_followup_frame_v3(frame,reader)
    try:yield
    finally:release_followup_frame_v3(frame)

def validate_habit_maintenance_followup_provenance_v3(domain,kind,provenance):
    if type(provenance)is not dict or TARGET_PROVENANCE_V3 not in provenance:return None
    from .habit_maintenance_provenance_v1 import MAINTENANCE_PROVENANCE_V1,validate_habit_maintenance_provenance_v1
    from ..authority_service.current_habit_maintenance_v1 import habit_maintenance_selector_from_wire_v1,habit_maintenance_selector_to_wire_v1
    from .habit_census_provenance_v1 import _digest_v1
    raw=provenance[TARGET_PROVENANCE_V3]
    names={"schema","dedupe_key","producer_operation_id","producer_original_digest","producer_receipt_digest","event_kind","selector","selector_digest"}
    if(type(raw)is not dict or set(raw)!=names or raw["schema"]!="d10.habit-original-maintenance-followup-target.v3"
            or MAINTENANCE_PROVENANCE_V1 not in provenance):
        raise ValueError("Habit maintenance followup target lacks its exact closed provenance/schema")
    selector=habit_maintenance_selector_from_wire_v1(raw["selector"])
    actual,_,_,_=validate_habit_maintenance_provenance_v1(domain,kind,provenance[MAINTENANCE_PROVENANCE_V1])
    receiver,event=("d11","habit_occurrence_registered_requires_qualification")if kind=="record_habit_miss_v1"else("d10",EVENT)
    operation="habit-original-maintenance:"+canonical_digest((selector.namespace,raw["dedupe_key"],kind,selector.occurrence_ref,selector.expected_revision))[:48]
    if(selector!=actual or raw["selector"]!=habit_maintenance_selector_to_wire_v1(selector)
            or raw["selector_digest"]!=canonical_digest(selector)or selector.operation_id!=operation
            or raw["event_kind"]!=event
            or raw["dedupe_key"]!=canonical_digest((selector.namespace,raw["producer_operation_id"],receiver,event))):
        raise ValueError("Habit maintenance followup changed its complete event/selector/operation tuple")
    for name in ("producer_original_digest","producer_receipt_digest"):_digest_v1(raw[name])
    return {name:value for name,value in provenance.items()if name!=TARGET_PROVENANCE_V3}

def append_habit_maintenance_followup_target_v3(provenance,pair):
    if provenance is not None and TARGET_PROVENANCE_V3 in provenance:
        raise AuthorityUnavailable("Habit maintenance target is reserved for its actual private Source frame")
    if pair is None or type(pair[1])is not HabitMaintenanceFollowupPreparedV3:return provenance
    return {**(provenance or {}),TARGET_PROVENANCE_V3:pair[1].target}
