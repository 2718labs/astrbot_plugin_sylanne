"""Same-Work Borrowed Habit metadata EOF. This proof never grants body access."""
from dataclasses import fields
from types import MappingProxyType
from weakref import WeakKeyDictionary
from ..authority_service.contract import AuthorityUnavailable
from ..graph_types import AtomKey
from ..runtime_contracts import NamespaceId,canonical_digest
from .b3_managed_metadata_v1 import (JOINT_TABLE,HABIT_TABLE,metadata_columns_v1,
    validate_managed_metadata_row_v1)
from .dispatch_initial_source_read_v3 import DispatchOriginalJSONReadV3
from .conditioned_producer_source_metadata_v3 import ConditionedLocatorJSONV3,ConditionedMetadataJSONStreamV3

BORROWED_HABIT_METADATA_OPERATIONS_V3=frozenset({
    "prepare_source_note_body","prepare_life",
    "prepare_artifact_draft_model_v2","acquire_artifact_draft_model_v2",
    "propose_artifact_draft_phase_action_v2","prepare_artifact_draft_body",
    "input:register_artifact_phase_draft_plan_v2",
    "prepare_artifact_draft_model","acquire_artifact_draft_model"})
_ISSUER=object()
_STATES=WeakKeyDictionary()
_PROOFS=WeakKeyDictionary()

def _actual_reader_v3(reader):
    from .current_method_learning_read_v3 import (BorrowedMethodLearningReadV3,_READERS,
        _require_borrowed_issuance_v3)
    from .domain_production_registry_v1 import installed_operation_v1
    from ..runtime_storage_v3 import runtime_storage_v3
    if(type(reader)is not BorrowedMethodLearningReadV3 or reader not in _READERS
            or reader.operation_kind not in BORROWED_HABIT_METADATA_OPERATIONS_V3
            or reader.work.kind!="current_method_learning_read_v3" or reader.work.state is not reader
            or reader.work.operation is not reader.operation or reader.operation.closed
            or reader.work.coordinator is not reader.graph or reader.runtime.graph is not reader.graph
            or reader.work.operation_id!=reader.operation_id
            or reader.selector.operation_kind!=reader.operation_kind
            or reader.selector.operation_id!=reader.operation_id
            or reader.selector.request_digest!=reader.request_digest
            or type(reader.request)is not installed_operation_v1(reader.operation_kind).request_type
            or reader.issued.scope.operation!="write"
            or reader.issued.scope.namespace!=reader.namespace
            or runtime_storage_v3(reader.db)is not reader.operation.handle
            or _require_borrowed_issuance_v3(reader.issued,reader.graph)!=reader.evidence):
        raise AuthorityUnavailable("Habit metadata requires the actual installed Borrowed command/issuance/Work")
    reader.require_current()
    return reader

class _OccurrenceColumnV3(DispatchOriginalJSONReadV3):
    def __init__(self,state,header):
        r=state.reader;self.state,self.header=state,header
        super().__init__(r,table="graph_atoms",column="value",key_columns=("token","bot","persona"),
            key=(header[0],*r.namespace.as_tuple),cell_id=header[3])
        from ..runtime_storage_v3 import begin_runtime_cell_read_v3
        from ..domains.d10.habit_occurrence_v1 import HabitOccurrenceV1
        self.cell=begin_runtime_cell_read_v3(r.db,header[3],erasure_owner_ref=header[0])
        if self.cell.header[0]not in {"canonical-json.ascii.v1","canonical-json.utf8.v1"}:
            raise AuthorityUnavailable("Habit occurrence metadata requires its actual canonical cell")
        names=frozenset(f.name for f in fields(HabitOccurrenceV1))
        self.capture=ConditionedLocatorJSONV3(self)
        self.capture.retain_path_v3=lambda path:not path or path[0]in names
        self.parser=ConditionedMetadataJSONStreamV3(self.capture,
            ensure_ascii=self.cell.header[0]=="canonical-json.ascii.v1")
    def _actual(self):self.state.require_current_v3();return self
    def _emit(self,event):
        self.capture._emit_v3(event);self.value=self.capture.value
    def advance(self,meter):
        r=self.state.reader;self._actual()
        current=meter.read_fixed_row(r.db,"graph_atoms",("token","revision","valid","value_cell_id"),
            "bot=? AND persona=? AND token=?",(*r.namespace.as_tuple,self.header[0]))
        if current!=self.header:raise AuthorityUnavailable("Habit occurrence metadata head changed during EOF")
        return super().advance(meter)

class _BorrowedHabitMetadataEOFV3:
    def __init__(self,issuer,state):
        if issuer is not _ISSUER or not state.complete:
            raise AuthorityUnavailable("Borrowed Habit metadata proof requires its actual complete stream")
        self.state=state
        self.occurrences=tuple(state.occurrences)
        self.rows=MappingProxyType({table:tuple(rows)for table,rows in state.rows.items()})
        self.commitment=state.commitment
        _PROOFS[self]=(state,state.binding,self.occurrences,self.rows,self.commitment)
    def require_current_v3(self,reader):
        s=self.state;s.require_current_v3()
        if(reader is not s.reader or _PROOFS.get(self)!=(s,s.binding,self.occurrences,self.rows,self.commitment)
                or not s.complete or s.proof is not self or self.commitment!=s.commitment):
            raise AuthorityUnavailable("Borrowed Habit metadata proof lost its complete actual Work")
        return self
    def occurrences_for_action_v3(self,action_ref):
        self.require_current_v3(self.state.reader)
        key=AtomKey.from_token(action_ref)
        if NamespaceId.from_key(key)!=self.state.reader.namespace or key.type_name!="d08.action_intent.v1":
            raise AuthorityUnavailable("Habit occurrence lookup needs its actual namespace Action")
        return tuple(entry for entry in self.occurrences if entry[1]is not None
            and entry[1].action_intent_ref==action_ref)
    def managed_rows_v3(self,table):
        self.require_current_v3(self.state.reader)
        if table not in {JOINT_TABLE,HABIT_TABLE}:raise AuthorityUnavailable("Unknown managed metadata table")
        return self.rows[table]

class _MetadataStateV3:
    def __init__(self,issuer,reader):
        if issuer is not _ISSUER:raise AuthorityUnavailable("Actual Borrowed metadata factory required")
        _actual_reader_v3(reader)
        self.reader=reader
        self.binding=(reader.graph,reader.work,reader.operation,reader.issued,reader.issued.scope,
            reader.selector,reader.operation_kind,reader.request_digest,reader.graph_stamp,
            reader.expected_rights,reader.authority_epochs,reader.owner_head,reader.selection_digest)
        self.phase="occurrences";self.cursor="";self.column=None
        self.occurrences=[];self.rows={JOINT_TABLE:[],HABIT_TABLE:[]}
        self.commitment=canonical_digest(("sylanne.borrowed-habit-metadata-eof.v3",reader.namespace,self.binding[6:]))
        self.complete=False;self.proof=None
        _STATES[reader]=self
    def require_current_v3(self):
        r=_actual_reader_v3(self.reader)
        if(_STATES.get(r)is not self or self.binding!=(r.graph,r.work,r.operation,r.issued,r.issued.scope,
                r.selector,r.operation_kind,r.request_digest,r.graph_stamp,r.expected_rights,
                r.authority_epochs,r.owner_head,r.selection_digest)):
            raise AuthorityUnavailable("Borrowed Habit metadata scope/selection/rights changed")
        return self
    def _record_v3(self,value):
        self.reader.operation.retain(1024)
        self.commitment=canonical_digest(("sylanne.borrowed-habit-metadata-leaf.v3",self.commitment,value))
    def advance(self,meter):
        self.require_current_v3();r=self.reader
        if self.complete:return True
        if self.phase=="occurrences":
            if self.column is not None:
                if not self.column.advance(meter):return False
                c=self.column;raw=c.require_v3(r)
                from ..domains.d10.habit_occurrence_v1 import HabitOccurrenceV1,habit_value_from_wire_v1
                actual=None
                if c.header[2]==1 or raw.get("schema")=="d10.habit-occurrence.v1":
                    if self.column.capture.fields_seen!={f.name for f in fields(HabitOccurrenceV1)}:
                        raise AuthorityUnavailable("Habit occurrence metadata has a different declared fieldset")
                    actual=habit_value_from_wire_v1("d10.habit_occurrence.v1",raw)
                    from ..domains.d10.habit_occurrence_v1 import habit_occurrence_key_v1
                    if actual.namespace!=r.namespace or habit_occurrence_key_v1(r.namespace,actual.occurrence_id).token!=c.header[0]:
                        raise AuthorityUnavailable("Habit occurrence fullPK differs from its actual canonical metadata")
                entry=(tuple(c.header),actual,c.sha256,c.byte_count)
                self.occurrences.append(entry);self._record_v3(entry);self.column=None
                return False
            row=meter.read_fixed_row(r.db,"graph_atoms",("token","revision","valid","value_cell_id"),
                "bot=? AND persona=? AND type_name=? AND token>? ORDER BY token",
                (*r.namespace.as_tuple,"d10.habit_occurrence.v1",self.cursor))
            if row is None:
                self._record_v3(("occurrence_eof",self.cursor));self.phase=JOINT_TABLE;self.cursor="";return False
            key=AtomKey.from_token(row[0])
            if(NamespaceId.from_key(key)!=r.namespace or key.type_name!="d10.habit_occurrence.v1"
                    or type(row[1])is not int or row[1]<1 or row[2]not in(0,1)or row[3]is None):
                raise AuthorityUnavailable("Habit occurrence metadata contains a malformed actual head")
            self.cursor=row[0];self.column=_OccurrenceColumnV3(self,tuple(row));return False
        table=self.phase;columns=metadata_columns_v1(table)
        cursor_name="selector_digest"if table==JOINT_TABLE else"selector_commitment"
        row=meter.read_fixed_row(r.db,table,columns,
            "bot=? AND persona=? AND "+cursor_name+">? ORDER BY "+cursor_name,
            (*r.namespace.as_tuple,self.cursor))
        if row is not None:
            ns,_=validate_managed_metadata_row_v1(table,columns,row,issuer=r.graph._GraphCoordinator__d11_issuer)
            if ns!=r.namespace:raise AuthorityUnavailable("Managed metadata census crossed namespace")
            self.rows[table].append(tuple(row));self.cursor=row[2];self._record_v3((table,tuple(row)));return False
        self._record_v3((table,"eof",self.cursor))
        if table==JOINT_TABLE:self.phase=HABIT_TABLE;self.cursor="";return False
        self.complete=True;self.proof=_BorrowedHabitMetadataEOFV3(_ISSUER,self);return True

def advance_borrowed_habit_metadata_eof_v3(reader,meter):
    _actual_reader_v3(reader)
    state=_STATES.get(reader)
    if state is None:state=_MetadataStateV3(_ISSUER,reader)
    return state.advance(meter)

def require_borrowed_habit_metadata_eof_v3(reader):
    _actual_reader_v3(reader);state=_STATES.get(reader)
    if state is None or not state.complete or state.proof is None:
        raise AuthorityUnavailable("Actual complete occurrence and both signed managed-table EOFs required")
    return state.proof.require_current_v3(reader)

def release_borrowed_habit_metadata_v3(reader):
    state=_STATES.pop(reader,None)
    if state is not None:
        _PROOFS.pop(state.proof,None)
        state.occurrences.clear();state.rows.clear();state.column=state.proof=None

def read_bound_borrowed_habit_inventory_v3(db,namespace,type_name):
    """Use the actual recipe's bounded typed inventory; this adds no allowed family."""
    from .current_method_learning_read_v3 import (_method_active,BorrowedMethodLearningReadV3,
        method_domain_inventory_v3)
    r=_method_active(db)
    if type(r)is not BorrowedMethodLearningReadV3 or r.operation_kind not in BORROWED_HABIT_METADATA_OPERATIONS_V3:
        return False,None
    require_borrowed_habit_metadata_eof_v3(r)
    if namespace!=r.namespace:raise AuthorityUnavailable("Borrowed Life inventory crossed namespace")
    return True,method_domain_inventory_v3(db,namespace,type_name)
