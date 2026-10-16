"""Installed Habit immutable originals and accepted-C09 retirement row codecs."""
from dataclasses import asdict,dataclass,fields
import hashlib,hmac,json
from .contract import AuthorityUnavailable
from .d10_habit_contract_v1 import (HabitStandingPolicyOriginalV1,HabitOccurrenceQualificationOriginalV1,
    HabitWindowCueOriginalV1,habit_standing_policy_original_from_wire_v1,habit_standing_policy_original_to_wire_v1,
    habit_occurrence_qualification_from_wire_v1,habit_occurrence_qualification_to_wire_v1,
    habit_window_cue_original_from_wire_v1,habit_window_cue_original_to_wire_v1)
from ..runtime_contracts import canonical_digest,canonical_serialize

MAX_PAYLOAD_BYTES=32768
SIGNING_PURPOSE=b"sylanne.authority.d10-habit-signing.v1"
POLICY_TABLE="authority_d10_habit_policy_originals_v1"
OCCURRENCE_TABLE="authority_d10_habit_occurrence_originals_v1"
POLICY_COLUMNS=("authority_namespace","installation_id","policy_commitment","policy_revision",
    "cancellation_generation","operation_commitment","row_kind","payload_json","payload_digest","signature","target_commitment","project_commitment")
OCCURRENCE_COLUMNS=("authority_namespace","installation_id","policy_commitment","policy_revision",
    "cancellation_generation","operation_commitment","row_kind","original_commitment","payload_json","payload_digest","signature","target_commitment","project_commitment","effect_commitment")
POLICY_DDL="""CREATE TABLE authority_d10_habit_policy_originals_v1(
authority_namespace TEXT NOT NULL,installation_id TEXT NOT NULL,policy_commitment TEXT NOT NULL,
policy_revision INTEGER NOT NULL CHECK(policy_revision>0),cancellation_generation INTEGER NOT NULL CHECK(cancellation_generation>=0),
operation_commitment TEXT NOT NULL,row_kind TEXT NOT NULL CHECK(row_kind IN ('policy_issue','policy_revise','policy_revoke','retirement')),
payload_json TEXT NOT NULL,payload_digest TEXT NOT NULL,signature TEXT NOT NULL,
target_commitment TEXT NOT NULL,project_commitment TEXT NOT NULL,
PRIMARY KEY(authority_namespace,installation_id,operation_commitment),
UNIQUE(authority_namespace,installation_id,policy_commitment,policy_revision,row_kind,operation_commitment))"""
OCCURRENCE_DDL="""CREATE TABLE authority_d10_habit_occurrence_originals_v1(
authority_namespace TEXT NOT NULL,installation_id TEXT NOT NULL,policy_commitment TEXT NOT NULL,
policy_revision INTEGER NOT NULL CHECK(policy_revision>0),cancellation_generation INTEGER NOT NULL CHECK(cancellation_generation>=0),
operation_commitment TEXT NOT NULL,row_kind TEXT NOT NULL CHECK(row_kind IN ('occurrence_qualification','window_cue','retirement')),
original_commitment TEXT NOT NULL,payload_json TEXT NOT NULL,payload_digest TEXT NOT NULL,signature TEXT NOT NULL,
target_commitment TEXT NOT NULL,project_commitment TEXT NOT NULL,effect_commitment TEXT,
PRIMARY KEY(authority_namespace,installation_id,operation_commitment),
UNIQUE(authority_namespace,installation_id,original_commitment))"""
def habit_ledger_triggers_v1(table):
    if table not in(POLICY_TABLE,OCCURRENCE_TABLE):raise ValueError("fixed Habit ledger required")
    return tuple((table+"_no_"+action,"CREATE TRIGGER "+table+"_no_"+action+" BEFORE "+action.upper()+" ON "+table
        +" BEGIN SELECT RAISE(ABORT,'Habit originals are immutable'); END")for action in("update","delete"))

def habit_signing_key_v1(bundle):
    from ..host.authority_profile import AdminInstallationBundle
    if type(bundle)is not AdminInstallationBundle:raise TypeError("actual installed Habit bundle required")
    return hmac.new(bundle.d11_signing_key,SIGNING_PURPOSE,hashlib.sha256).digest()

def habit_identity_commitment_v1(key,kind,value):
    if type(key)is not bytes or len(key)!=32 or kind not in{"policy","operation","original"}or type(value)is not str or not value:
        raise TypeError("fixed installed Habit identity commitment required")
    return hmac.new(key,canonical_serialize(("habit-identity.v1",kind,value)).encode("utf8"),hashlib.sha256).hexdigest()

@dataclass(frozen=True,slots=True)
class HabitRetirementV1:
    authority_namespace:str
    installation_id:str
    policy_commitment:str
    policy_revision:int
    cancellation_generation:int
    operation_commitment:str
    original_commitment:str|None
    target_commitment:str
    project_commitment:str
    effect_commitment:str|None
    accepted_receipt_digest:str
    maintenance_generation:int
    disposition:str
    signature:str
    schema:str="d10.habit-retirement.v1"
    def __post_init__(self):
        if(self.schema!="d10.habit-retirement.v1"or not self.authority_namespace or not self.installation_id
                or type(self.policy_revision)is not int or self.policy_revision<1
                or type(self.cancellation_generation)is not int or self.cancellation_generation<0
                or type(self.maintenance_generation)is not int or self.maintenance_generation<1
                or self.disposition not in{"policy_retired","qualification_retired","cue_retired"}):
            raise ValueError("Habit retirement requires actual accepted C09 scope and original identity floors")
        for value in(self.policy_commitment,self.operation_commitment,self.target_commitment,self.project_commitment,self.accepted_receipt_digest,self.signature):
            if type(value)is not str or len(value)!=64 or any(c not in"0123456789abcdef"for c in value):
                raise ValueError("Habit retirement commitment differs")
        if(self.disposition=="qualification_retired")!=(self.effect_commitment is not None):
            raise ValueError("Habit opaque effect obligation must identify exactly a qualification retirement")
        if self.effect_commitment is not None and(len(self.effect_commitment)!=64 or any(c not in"0123456789abcdef"for c in self.effect_commitment)):
            raise ValueError("Habit opaque effect commitment differs")
        if self.original_commitment is not None and(len(self.original_commitment)!=64 or any(c not in"0123456789abcdef"for c in self.original_commitment)):
            raise ValueError("Habit retirement original commitment differs")
    @property
    def digest(self):return canonical_digest(self)

def habit_retirement_from_wire_v1(raw):
    if type(raw)is not dict or set(raw)!={f.name for f in fields(HabitRetirementV1)}:raise ValueError("Habit retirement fields differ")
    return HabitRetirementV1(**raw)

def habit_ledger_decode_v1(table,columns,row,*,key,authority_namespace,authority_id,installation_id):
    expected=POLICY_COLUMNS if table==POLICY_TABLE else OCCURRENCE_COLUMNS if table==OCCURRENCE_TABLE else None
    if expected is None or tuple(columns)!=expected or len(row)!=len(expected):raise AuthorityUnavailable("Habit ledger row shape differs")
    data=dict(zip(columns,row))
    if len(data["payload_json"].encode("utf8"))>MAX_PAYLOAD_BYTES:raise AuthorityUnavailable("Habit immutable payload exceeds original fixed C09 row admission")
    raw=json.loads(data["payload_json"])
    kind=data["row_kind"]
    if kind=="retirement":value=habit_retirement_from_wire_v1(raw);wire=asdict(value)
    elif kind in{"policy_issue","policy_revise","policy_revoke"}and table==POLICY_TABLE:
        value=habit_standing_policy_original_from_wire_v1(raw);wire=habit_standing_policy_original_to_wire_v1(value)
        if kind!="policy_"+value.action:raise AuthorityUnavailable("Habit policy row action differs")
    elif kind=="occurrence_qualification"and table==OCCURRENCE_TABLE:
        value=habit_occurrence_qualification_from_wire_v1(raw);wire=habit_occurrence_qualification_to_wire_v1(value)
    elif kind=="window_cue"and table==OCCURRENCE_TABLE:
        value=habit_window_cue_original_from_wire_v1(raw);wire=habit_window_cue_original_to_wire_v1(value)
    else:raise AuthorityUnavailable("Habit ledger closed row kind differs")
    material={k:v for k,v in wire.items()if k!="signature"}
    signature=hmac.new(key,canonical_serialize(material).encode("utf8"),hashlib.sha256).hexdigest()
    if(data["authority_namespace"]!=authority_namespace or value.authority_namespace!=authority_namespace
            or data["installation_id"]!=installation_id or value.installation_id!=installation_id
            or canonical_serialize(wire)!=data["payload_json"]or value.digest!=data["payload_digest"]
            or value.signature!=data["signature"]or not hmac.compare_digest(signature,value.signature)):
        raise AuthorityUnavailable("Habit immutable row canonical/signature/installation differs")
    if type(value)is HabitRetirementV1:
        expected_identity=(value.policy_commitment,value.policy_revision,value.cancellation_generation,value.operation_commitment)
        if table==OCCURRENCE_TABLE and value.original_commitment!=data["original_commitment"]:
            raise AuthorityUnavailable("Habit retirement original identity differs")
    else:
        if value.authority_id!=authority_id:raise AuthorityUnavailable("Habit original actual Authority differs")
        definition=value.definition if kind in{"policy_issue","policy_revise","policy_revoke"}else None
        selector=None if definition is not None else value.selector
        policy_id=definition.policy_id if definition is not None else _policy_id_v1(selector.policy_ref)
        expected_identity=(habit_identity_commitment_v1(key,"policy",policy_id),
            definition.revision if definition is not None else selector.policy_revision,
            definition.cancellation_generation if definition is not None else selector.cancellation_generation,
            habit_identity_commitment_v1(key,"operation",value.operation_id if definition is not None else selector.operation_id))
        if table==OCCURRENCE_TABLE and data["original_commitment"]!=habit_identity_commitment_v1(key,"original",value.original_ref):
            raise AuthorityUnavailable("Habit original immutable identity differs")
    if(data["target_commitment"],data["project_commitment"])!=(value.target_commitment,value.project_commitment):
        raise AuthorityUnavailable("Habit signed opaque target/project differs from actual row identity")
    if table==OCCURRENCE_TABLE and data["effect_commitment"]!=getattr(value,"effect_commitment",None):
        raise AuthorityUnavailable("Habit signed opaque effect differs from actual row identity")
    if type(value)is HabitStandingPolicyOriginalV1:
        if(value.target_commitment,value.project_commitment)!=(
                habit_scope_identity_commitment_v1(key,"target",value.namespace,value.installation_id,value.definition.target_ref),
                habit_scope_identity_commitment_v1(key,"project",value.namespace,value.installation_id,value.definition.project_ref)):
            raise AuthorityUnavailable("Habit actual standing target/project commitments differ from signed Definition")
    if type(value)is HabitOccurrenceQualificationOriginalV1 and value.effect_commitment!=habit_scope_identity_commitment_v1(
            key,"effect",value.namespace,value.installation_id,value.selector.effect_id):
        raise AuthorityUnavailable("Habit qualification effect differs from actual signed selector")
    if expected_identity!=tuple(data[x]for x in("policy_commitment","policy_revision","cancellation_generation","operation_commitment")):
        raise AuthorityUnavailable("Habit ledger fixed identity/floors differ")
    return value

def _policy_id_v1(ref):
    from ..graph_types import AtomKey
    return AtomKey.from_token(ref).name


def habit_scope_identity_commitment_v1(key,kind,namespace,installation_id,value):
    from ..runtime_contracts import NamespaceId
    if(type(key)is not bytes or len(key)!=32 or kind not in{'target','project','effect'}or type(namespace)is not NamespaceId
            or type(installation_id)is not str or not installation_id or type(value)is not str or not value):
        raise TypeError('actual installed Habit target/project/effect identity required')
    return hmac.new(key,canonical_serialize(('habit-scoped-identity.v1',namespace,installation_id,kind,value)).encode('utf8'),hashlib.sha256).hexdigest()
