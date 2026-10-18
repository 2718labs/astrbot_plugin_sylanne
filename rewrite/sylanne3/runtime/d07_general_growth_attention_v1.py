"""Actual same-CAS Life outcome metadata and fair General growth attention.

These originals retain causal facts and original bounds. They issue no Owner,
Self, Source or model permit; current installed readers qualify each use.
"""
from __future__ import annotations

from dataclasses import dataclass,replace,fields
from weakref import WeakKeyDictionary
import json
import math

from ..runtime_contracts import AuthorityContext,NamespaceId,VersionedRef,canonical_digest,canonical_serialize
from ..graph_types import AtomKey,GraphVersion,GraphWrite,owner_grant_key
from .domain_production_contracts_v1 import ProductionOwnerGuardV1,ProductionOriginalRefV1
from .d07_execution_v1 import D07SemanticQuestionV1

TRIGGER_KIND="general_growth_outcome_trigger_v1"
TRIGGER_EVENT="actual_life_outcome_available_for_growth"
ATTENTION_KIND="general_growth_attention_v1"
QUESTION_SCHEMA="d07.general-growth-semantic-question.v1"
_ISSUER=object()
_CAPTURED=WeakKeyDictionary()

def _utc_v1(value):
    from datetime import datetime
    return datetime.fromisoformat(value.replace("Z","+00:00")).timestamp()

def _source_refs_v1(values,namespace,*,empty=False):
    if type(values)is not tuple or not empty and not values or len(values)>16 or len(set(values))!=len(values):
        raise ValueError("General growth requires its actual bounded unique Source locators")
    for ref in values:
        key=AtomKey.from_token(ref)
        if key.type_name!="memory.source"or NamespaceId.from_key(key)!=namespace:
            raise ValueError("General growth Source metadata crossed namespace/type")

def _digest_v1(value):
    if type(value)is not str or len(value)!=64 or any(part not in "0123456789abcdef"for part in value):
        raise ValueError("General growth requires actual canonical SHA256 commitments")


def _actual_general_growth_budget_ancestry_v1(db,lease_ref,issuer):
    from .budget import get_budget_lease,_lease_from_row,require_budget_family_admissible
    from .domain_background_read_v3 import _active_v3,background_point_v3
    owner=_active_v3(db);seen=set();originals=[];first=None;current=lease_ref
    while current is not None:
        if current in seen:raise ValueError("General original budget ancestry has a cycle")
        seen.add(current)
        if owner is None:lease=get_budget_lease(db,current)
        else:
            columns=("lease_id","parent_id","bot_id","persona_id","currency","limits_json","used_json",
                "reserved_json","unconfirmed_json","version","state")
            row=background_point_v3(db,table="runtime_budget_leases",columns=columns,
                key_columns=("lease_id",),key=(current,),legacy_reader=lambda:None)
            lease=_lease_from_row(row)
        grant=issuer.current_budget_grant(db,current)
        if ((grant.bot_id,grant.persona_id,grant.lease_id)!=(lease.bot_id,lease.persona_id,lease.lease_id)
                or lease.state!="active"or first is not None and(lease.bot_id,lease.persona_id)!=(first[0].bot_id,first[0].persona_id)):
            raise ValueError("General original budget ancestor is no longer active in its namespace")
        if first is None:
            require_budget_family_admissible(db,current)
            first=(lease,grant)
        originals.append((current,grant.version,canonical_digest(grant),grant.valid_until_utc))
        current=lease.parent_id
    return (*first,tuple(originals))

@dataclass(frozen=True,slots=True)
class D10GeneralGrowthOutcomeParentMetadataV1:
    namespace:NamespaceId
    activity_id:str
    effect_id:str
    plan_original:ProductionOriginalRefV1
    terminal_original:ProductionOriginalRefV1
    binding_digest:str
    outcome_original:ProductionOriginalRefV1
    parent_budget_lease_ref:str
    parent_grant_digest:str
    original_budget_ancestry:tuple[tuple[str,int,str,float],...]
    original_plan_deadline_utc:float
    original_binding_deadline_utc:float
    context_source_refs:tuple[str,...]
    owner_guard:ProductionOwnerGuardV1
    source_authority:AuthorityContext
    schema:str="d10.general-growth-outcome-parent-metadata.v1"

    def __post_init__(self):
        if (self.schema!="d10.general-growth-outcome-parent-metadata.v1"or type(self.namespace)is not NamespaceId
                or type(self.owner_guard)is not ProductionOwnerGuardV1 or type(self.source_authority)is not AuthorityContext
                or self.source_authority.namespace!=self.namespace
                or type(self.plan_original)is not ProductionOriginalRefV1
                or type(self.terminal_original)is not ProductionOriginalRefV1
                or type(self.outcome_original)is not ProductionOriginalRefV1 or self.outcome_original.kind!="d11.life_outcome"):
            raise ValueError("General outcome parent metadata requires exact existing typed originals")
        _source_refs_v1(self.context_source_refs,self.namespace)
        for digest in (self.binding_digest,self.parent_grant_digest):_digest_v1(digest)
        for value in (self.original_plan_deadline_utc,self.original_binding_deadline_utc):
            if type(value)not in(int,float)or not math.isfinite(value):
                raise ValueError("General outcome retains finite original absolute deadlines")

def actual_general_growth_outcome_parent_metadata_v1(db,*,frame,plan,prepared,terminal,
        context_source_refs,outcome_original_ref,outcome_original_digest,issuer):
    """Called only where actual D10 _actual_outcome already returned these values."""
    from .d11_life_contract_v1 import D11LifeTerminalV1,D11DraftTerminalV1
    from .d11_life_preparation_v1 import D11LifePreparedV1,D11DraftPreparedV1
    from .d11_artifact_draft_contract_v1 import RegisteredDraftFilePlanV3
    from .d11_life_contract_v1 import RegisteredLifePlanV2
    from .issuers import D11BudgetJobIssuer
    if (not db.in_transaction or type(issuer)is not D11BudgetJobIssuer
            or type(terminal)not in{D11LifeTerminalV1,D11DraftTerminalV1}
            or type(plan)not in{RegisteredLifePlanV2,RegisteredDraftFilePlanV3}
            or type(prepared)not in{D11LifePreparedV1,D11DraftPreparedV1} or terminal.binding!=prepared.binding
            or prepared.plan!=plan):
        raise ValueError("General metadata must derive from actual installed paid Life originals")
    binding=terminal.binding;namespace=frame.envelope.authority.namespace
    if binding.namespace!=namespace:
        raise ValueError("General Life parent changed its actual namespace")
    if (binding.parent_budget_lease_ref!=frame.envelope.parent_budget_lease_ref
            or binding.owner_grant_ref!=frame.owner_guard.grant_ref
            or binding.owner_grant_revision!=frame.owner_guard.grant_revision
            or binding.owner_grant_digest!=frame.owner_guard.grant_digest):
        return None
    lease,grant,ancestry=_actual_general_growth_budget_ancestry_v1(db,binding.parent_budget_lease_ref,issuer)
    if (lease.state!="active"or(lease.bot_id,lease.persona_id)!=namespace.as_tuple
            or(grant.bot_id,grant.persona_id,grant.lease_id)!=(*namespace.as_tuple,lease.lease_id)):
        raise ValueError("General Life actual current parent grant/lease differs")
    plan_original=ProductionOriginalRefV1("d11.life_plan",binding.plan_original_ref,binding.plan_digest)
    terminal_original=ProductionOriginalRefV1("d11.life_terminal",terminal.original_ref,canonical_digest(terminal))
    return D10GeneralGrowthOutcomeParentMetadataV1(namespace,binding.activity_id,binding.effect_id,
        plan_original,terminal_original,binding.digest,ProductionOriginalRefV1("d11.life_outcome",outcome_original_ref,outcome_original_digest),
        binding.parent_budget_lease_ref,canonical_digest(grant),ancestry,
        _utc_v1(plan.deadline_utc),_utc_v1(binding.deadline_utc),tuple(context_source_refs),
        frame.owner_guard,frame.envelope.authority)

class _GeneralGrowthOutcomeCaptureV1:
    def __init__(self,issuer,witness,metadata,grant,deadline,status):
        if issuer is not _ISSUER:raise TypeError("actual General W01 metadata capture issuer required")
        self.witness,self.graph,self.frame,self.stage=witness,witness.graph,witness.frame,witness.stage
        self.metadata,self.grant,self.deadline,self.status=metadata,grant,deadline,status
        _CAPTURED[self]=(witness,self.graph,self.frame,self.stage,metadata,grant,deadline,status,
            witness.scope,witness.bundle,witness.scope.permit)

def capture_actual_general_growth_outcome_before_cas_v1(witness,db):
    from .domain_production_commit_v1 import _ProductionCommitWitnessV1,_ACTIVE
    from ..domains.d10.production_operations_v1 import CurrentLifeEffectExperienceBundleV1
    if (type(witness)is not _ProductionCommitWitnessV1 or _ACTIVE.get(id(witness))is not witness
            or type(witness.stage)is not CurrentLifeEffectExperienceBundleV1
            or witness.stage.life_stage.operation_kind!="advance_life"):
        return None
    graph=witness.graph;frame=witness.frame;stage=witness.stage
    if (db is not graph._GraphCoordinator__store._db or not db.in_transaction
            or not graph._GraphCoordinator__store._lock._is_owned()
            or witness.bundle.envelope!=frame.envelope or stage.envelope!=frame.envelope):
        raise ValueError("General outcome capture requires the actual active W01 transaction/witness")
    metadata=stage.general_growth_parent_metadata
    if metadata is None:return None
    if (type(metadata)is not D10GeneralGrowthOutcomeParentMetadataV1
            or metadata.namespace!=frame.envelope.authority.namespace
            or metadata.owner_guard!=frame.owner_guard or metadata.source_authority!=frame.envelope.authority
            or metadata.context_source_refs!=stage.experience_refs
            or metadata.parent_budget_lease_ref!=frame.envelope.parent_budget_lease_ref):
        raise ValueError("General outcome metadata differs from its actual current commit witness")
    issuer=graph._GraphCoordinator__d11_issuer
    lease,grant,ancestry=_actual_general_growth_budget_ancestry_v1(db,metadata.parent_budget_lease_ref,issuer)
    if ancestry!=metadata.original_budget_ancestry:raise ValueError("General parent ancestry changed before CAS")
    if (canonical_digest(grant)!=metadata.parent_grant_digest or lease.state!="active"
            or(grant.bot_id,grant.persona_id)!=(metadata.namespace.bot_id,metadata.namespace.persona_id)):
        raise ValueError("General outcome original parent grant/lease changed before its real CAS")
    deadline=min(frame.envelope.deadline_utc,metadata.original_plan_deadline_utc,
        metadata.original_binding_deadline_utc,*[item[3]for item in ancestry])
    status="qualified"if frame.now_utc<deadline and"d07.cognition"in grant.allowed_work_kinds else"waiting_for_original"
    return _GeneralGrowthOutcomeCaptureV1(_ISSUER,witness,metadata,grant,deadline,status)

@dataclass(frozen=True,slots=True)
class D10GeneralGrowthOutcomeTriggerV1:
    namespace:NamespaceId
    original_ref:str
    causal_operation_id:str
    causal_original:ProductionOriginalRefV1
    outcome_original:ProductionOriginalRefV1
    causal_receipt_digest:str
    causal_commit_seq:int
    activity_id:str
    effect_id:str
    project_ref:str
    context_source_versions:tuple[GraphVersion,...]
    context_original_refs:tuple[ProductionOriginalRefV1,...]
    original_parent_budget_lease_ref:str
    original_parent_grant_digest:str
    original_budget_ancestry:tuple[tuple[str,int,str,float],...]
    original_deadline_utc:float
    owner_guard:ProductionOwnerGuardV1
    source_authority:AuthorityContext
    authorization_status:str
    schema:str="d10.general-growth-outcome-trigger.v1"

    def __post_init__(self):
        if (self.schema!="d10.general-growth-outcome-trigger.v1"or type(self.namespace)is not NamespaceId
                or type(self.owner_guard)is not ProductionOwnerGuardV1
                or type(self.source_authority)is not AuthorityContext or self.source_authority.namespace!=self.namespace
                or type(self.causal_original)is not ProductionOriginalRefV1
                or type(self.outcome_original)is not ProductionOriginalRefV1 or self.outcome_original.kind!="d11.life_outcome"
                or type(self.causal_commit_seq)is not int or self.causal_commit_seq<1
                or type(self.original_deadline_utc)not in(int,float)or not math.isfinite(self.original_deadline_utc)
                or self.authorization_status not in{"qualified","waiting_for_original"}):
            raise ValueError("General outcome trigger has another exact actual causal metadata schema")
        _digest_v1(self.causal_receipt_digest);_digest_v1(self.original_parent_grant_digest)
        if (type(self.context_source_versions)is not tuple or not 1<=len(self.context_source_versions)<=16
                or any(type(item)is not GraphVersion or item.revision<1 for item in self.context_source_versions)):
            raise ValueError("General outcome has no actual positive Source CAS members")
        _source_refs_v1(tuple(item.key.token for item in self.context_source_versions),self.namespace)
        if (type(self.context_original_refs)is not tuple or not 1<=len(self.context_original_refs)<=16
                or any(type(item)is not ProductionOriginalRefV1 for item in self.context_original_refs)):
            raise ValueError("General outcome requires actual parent original refs/digests")
        if self.original_ref!=general_growth_outcome_trigger_ref_v1(self.namespace,self.causal_operation_id):
            raise ValueError("General outcome trigger changed stable actual cause identity")

    @property
    def digest(self):
        from ..domains.d01.production_operations_v1 import plain_v1
        return canonical_digest(plain_v1(self))

def general_growth_outcome_trigger_ref_v1(namespace,operation_id):
    return"general-growth-outcome:"+canonical_digest((namespace,operation_id))[:48]

def record_actual_general_growth_outcome_after_cas_v1(db,*,capture,receipt,causal_original):
    """Record metadata under the existing signed D10 input schema in this CAS."""
    from ..runtime_contracts import CommitReceipt
    from .domain_production_contracts_v1 import ProductionOutboxStageV1
    from ..domains.d01.production_operations_v1 import plain_v1
    if capture is None:return None
    if (type(capture)is not _GeneralGrowthOutcomeCaptureV1 or _CAPTURED.get(capture)!=(
            capture.witness,capture.graph,capture.frame,capture.stage,capture.metadata,capture.grant,
            capture.deadline,capture.status,capture.witness.scope,capture.witness.bundle,capture.witness.scope.permit)
            or type(receipt)is not CommitReceipt or receipt.status!="committed"
            or receipt.operation_id!=capture.stage.life_stage.operation_id
            or type(causal_original)is not ProductionOriginalRefV1
            or db is not capture.graph._GraphCoordinator__store._db or not db.in_transaction):
        raise ValueError("General outcome trigger requires its actual captured same-CAS W01 receipt")
    graph=capture.graph;metadata=capture.metadata;namespace=metadata.namespace
    actual=db.execute("SELECT digest,activity_id,effect_id,commit_seq FROM graph_bundle_operations "
        "WHERE bot=? AND persona=? AND operation_id=?",(*namespace.as_tuple,receipt.operation_id)).fetchone()
    if actual!=(receipt.operation_digest,receipt.activity_id,receipt.effect_id,receipt.commit_seq):
        raise ValueError("General outcome receipt has no exact actual shared ledger occurrence")
    sources=tuple(version for version in receipt.write_versions if version.key.token in metadata.context_source_refs)
    if {version.key.token for version in sources}!=set(metadata.context_source_refs):
        raise ValueError("General context Source was not created by this actual composite outcome CAS")
    primary=capture.stage.life_stage
    payload=json.loads(primary.original_payload_json);progress=payload["provenance"]["actual_progress"]
    if (progress["activity_id"],progress["effect_id"])!=(metadata.activity_id,metadata.effect_id):
        raise ValueError("General outcome trigger is not its actual completed Life effect")
    ref=general_growth_outcome_trigger_ref_v1(namespace,receipt.operation_id)
    trigger=D10GeneralGrowthOutcomeTriggerV1(namespace,ref,receipt.operation_id,causal_original,
        metadata.outcome_original,canonical_digest(receipt),receipt.commit_seq,metadata.activity_id,metadata.effect_id,progress["project_ref"],
        sources,(metadata.outcome_original,metadata.plan_original,metadata.terminal_original,causal_original),
        metadata.parent_budget_lease_ref,metadata.parent_grant_digest,metadata.original_budget_ancestry,capture.deadline,
        metadata.owner_guard,metadata.source_authority,capture.status)
    raw=plain_v1(trigger);encoded=canonical_serialize(raw);digest=canonical_digest(raw)
    issuer=graph._GraphCoordinator__d11_issuer
    signature=issuer._signer.sign("d11.d10-production-input.v1",encoded)
    roots=canonical_serialize(tuple(version.key.token for version in sources))
    expected=(TRIGGER_KIND,receipt.operation_id,encoded,digest,signature,roots)
    prior=db.execute("SELECT kind,producing_operation_id,payload_json,payload_digest,signature,source_refs_json "
        "FROM graph_d10_production_inputs_v1 WHERE bot=? AND persona=? AND original_ref=?",
        (*namespace.as_tuple,ref)).fetchone()
    if prior is not None and prior!=expected:
        raise ValueError("General growth actual outcome trigger stable identity already has different original bytes")
    if prior is None:
        db.execute("INSERT INTO graph_d10_production_inputs_v1 VALUES(?,?,?,?,?,?,?,?,?)",
            (*namespace.as_tuple,ref,*expected))
    original=ProductionOriginalRefV1("d10."+TRIGGER_KIND,ref,digest,sources)
    _CAPTURED.pop(capture,None)
    return original

def read_actual_general_growth_outcome_trigger_v1(db,*,namespace,original_ref,issuer):
    from .natural_producer_qualification_v1 import _producer_original_point_v3
    from .domain_background_read_v3 import background_json_loads_v3,background_json_matches_v3,background_json_digest_v3,background_verify_signature_v3
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    row=_producer_original_point_v3(db,table="graph_d10_production_inputs_v1",
        columns=("kind","producing_operation_id","payload_json","payload_digest","signature","source_refs_json"),
        key_columns=("bot","persona","original_ref"),key=(*namespace.as_tuple,original_ref),
        legacy_reader=lambda:db.execute("SELECT kind,producing_operation_id,payload_json,payload_digest,signature,source_refs_json "
            "FROM graph_d10_production_inputs_v1 WHERE bot=? AND persona=? AND original_ref=?",
            (*namespace.as_tuple,original_ref)).fetchone())
    if row is None:return None
    if row[0]!=TRIGGER_KIND:raise ValueError("General outcome locator has another exact installed D10 input kind")
    raw=background_json_loads_v3(row[2])
    if not background_json_matches_v3(row[2],raw)or background_json_digest_v3(row[2],raw)!=row[3]:
        raise ValueError("General signed trigger differs from its whole canonical EOF")
    background_verify_signature_v3(issuer._signer,"d11.d10-production-input.v1",row[2],row[4])
    trigger=decode_typed_production_value_v1(raw,D10GeneralGrowthOutcomeTriggerV1)
    if (trigger.namespace!=namespace or trigger.original_ref!=original_ref
            or trigger.causal_operation_id!=row[1] or trigger.digest!=row[3]
            or background_json_loads_v3(row[5])!=[item.key.token for item in trigger.context_source_versions]):
        raise ValueError("General actual signed trigger namespace/cause/context Source closure differs")
    causal=read_general_growth_causal_metadata_v1(db,namespace=namespace,trigger=trigger)
    if (causal["domain"]!="d10"or causal["operation_kind"]!="advance_life"
            or causal["original_digest"]!=trigger.causal_original.original_digest
            or trigger.causal_original.original_ref!="d10-current:"+causal["original_digest"][:48]
            or canonical_digest(causal["receipt"])!=trigger.causal_receipt_digest
            or causal["receipt"].commit_seq!=trigger.causal_commit_seq
            or any(item not in causal["receipt"].write_versions for item in trigger.context_source_versions)):
        raise ValueError("General trigger lost its actual same-CAS D10 outcome adoption")
    return trigger

def require_current_general_growth_outcome_trigger_v1(db,*,read,trigger,issuer):
    """Metadata original is a cause, while actual current rights are separate."""
    from .d01_production_operations_v1 import MissingProductionOriginalV1
    frame=read.frame;namespace=frame.envelope.authority.namespace
    actual=read_actual_general_growth_outcome_trigger_v1(db,namespace=namespace,original_ref=trigger.original_ref,issuer=issuer)
    if actual!=trigger:raise ValueError("General trigger changed its actual signed original")
    if trigger.authorization_status!="qualified":
        raise MissingProductionOriginalV1("general_growth_original_parent_work_authorization")
    if frame.now_utc>=trigger.original_deadline_utc:
        raise MissingProductionOriginalV1("general_growth_original_authorization_deadline_expired")
    if (frame.owner_guard!=trigger.owner_guard
            or frame.envelope.parent_budget_lease_ref!=trigger.original_parent_budget_lease_ref
            or frame.envelope.authority.actor!=trigger.source_authority.actor
            or frame.envelope.authority.activation_generation!=trigger.source_authority.activation_generation
            or not set(frame.envelope.authority.audience)<=set(trigger.source_authority.audience)):
        raise ValueError("General outcome current Owner/actor/Source audience/root lease changed")
    lease,grant,ancestry=_actual_general_growth_budget_ancestry_v1(db,trigger.original_parent_budget_lease_ref,issuer)
    if ancestry!=trigger.original_budget_ancestry:raise MissingProductionOriginalV1("general_growth_original_budget_ancestry_changed")
    if (lease.state!="active"or canonical_digest(grant)!=trigger.original_parent_grant_digest
            or frame.now_utc>=grant.valid_until_utc or"d07.cognition"not in grant.allowed_work_kinds):
        raise MissingProductionOriginalV1("general_growth_original_parent_grant_or_lease_not_current")
    for version in trigger.context_source_versions:
        from .natural_producer_qualification_v1 import _producer_original_point_v3
        current=_producer_original_point_v3(db,table="graph_atoms",columns=("revision","valid"),
            key_columns=("token","bot","persona"),key=(version.key.token,*namespace.as_tuple),
            legacy_reader=lambda:db.execute("SELECT revision,valid FROM graph_atoms WHERE token=? AND bot=? AND persona=?",
                (version.key.token,*namespace.as_tuple)).fetchone())
        if current!=(version.revision,1):
            raise ValueError("General context Source changed from its actual Life outcome CAS version")
        # Only current consolidation qualification permits the later body read.
        for audience in frame.envelope.authority.audience:
            read.source_family(db,(version.key.token,),purpose="consolidation",audience=audience)
    return trigger


def _general_growth_adopted_metadata_row_v1(db,namespace,operation_id):
    from .natural_producer_qualification_v1 import _producer_original_point_v3
    from .domain_production_originals_v1 import TABLE,PHYSICAL_TABLE
    columns=("domain","operation_kind","original_digest","bundle_digest","receipt_digest","read_versions_json","receipt_json")
    key=(*namespace.as_tuple,operation_id)
    row=_producer_original_point_v3(db,table=TABLE,columns=columns,
        key_columns=("bot","persona","operation_id"),key=key,
        legacy_reader=lambda:db.execute("SELECT "+",".join(columns)+" FROM "+TABLE+
            " WHERE bot=? AND persona=? AND operation_id=?",key).fetchone())
    if row is None:
        row=_producer_original_point_v3(db,table=PHYSICAL_TABLE,columns=columns,
            key_columns=("bot","persona","operation_id"),key=key,
            legacy_reader=lambda:db.execute("SELECT "+",".join(columns)+" FROM "+PHYSICAL_TABLE+
                " WHERE bot=? AND persona=? AND operation_id=?",key).fetchone())
    return row

def read_general_growth_causal_metadata_v1(db,*,namespace,trigger):
    """Read only actual receipt/read-set metadata; never decode the D10 report."""
    from .natural_producer_qualification_v1 import _producer_original_point_v3
    from .domain_background_read_v3 import background_json_loads_v3,_active_v3
    from .domain_production_originals_v1 import _receipt
    from ..domains.d01.production_operations_v1 import plain_v1
    row=_general_growth_adopted_metadata_row_v1(db,namespace,trigger.causal_operation_id)
    if row is None:raise ValueError("General actual causal metadata is absent")
    receipt=_receipt(background_json_loads_v3(row[6]))
    reads=tuple(GraphVersion(AtomKey.from_token(ref),revision)for ref,revision in background_json_loads_v3(row[5]))
    if (row[:2]!=("d10","advance_life")or row[2]!=trigger.causal_original.original_digest
            or receipt.operation_id!=trigger.causal_operation_id or receipt.operation_digest!=row[3]
            or canonical_digest(receipt)!=row[4]or row[4]!=trigger.causal_receipt_digest
            or any(NamespaceId.from_key(version.key)!=namespace for version in reads)):
        raise ValueError("General actual causal read-set/receipt/original commitments differ")
    actual=_producer_original_point_v3(db,table="graph_bundle_operations",
        columns=("digest","activity_id","effect_id","commit_seq"),
        key_columns=("bot","persona","operation_id"),key=(*namespace.as_tuple,trigger.causal_operation_id),
        legacy_reader=lambda:db.execute("SELECT digest,activity_id,effect_id,commit_seq FROM graph_bundle_operations "
            "WHERE bot=? AND persona=? AND operation_id=?",(*namespace.as_tuple,trigger.causal_operation_id)).fetchone())
    if actual!=(receipt.operation_digest,receipt.activity_id,receipt.effect_id,receipt.commit_seq):
        raise ValueError("General causal metadata has no actual W01 ledger occurrence")
    owner=_active_v3(db)
    if owner is not None and owner.entry is not None and owner.entry[0]==trigger.causal_operation_id:
        locator=owner.entry_column
        if (locator is None or not locator.complete or not locator.column.complete
                or locator.column.sha256!=row[2]or owner.entry_metadata[0]!=("d10","advance_life",row[2])):
            raise ValueError("General causal header has no same-Work whole raw EOF commitment")
    return{"domain":"d10","operation_kind":"advance_life","original_digest":row[2],
        "read_versions":reads,"receipt":receipt,"payload":{"namespace":plain_v1(namespace),
            "authority":plain_v1(trigger.source_authority),"parent_budget":trigger.original_parent_budget_lease_ref,
            "owner_guard":plain_v1(trigger.owner_guard)}}


@dataclass(frozen=True,slots=True,kw_only=True)
class D07GeneralGrowthQuestionV1(D07SemanticQuestionV1):
    target_block:str
    target_digest:str
    scope:str
    general_growth_attention_ref:str
    outcome_original_ref:str
    outcome_original_digest:str
    depth_basis:str
    stage_causal_depth:int
    context_source_refs:tuple[str,...]
    support_source_refs:tuple[str,...]
    context_original_refs:tuple[ProductionOriginalRefV1,...]
    outcome_trigger_ref:str
    outcome_trigger_digest:str
    causal_operation_id:str
    causal_receipt_digest:str
    original_parent_budget_lease_ref:str
    original_parent_grant_digest:str
    original_deadline_utc:float
    schema:str=QUESTION_SCHEMA

    def __post_init__(self):
        D07SemanticQuestionV1(self.question_key,self.question,self.target_ref,self.source_refs)
        namespace=NamespaceId.from_key(AtomKey.from_token(self.target_ref.ref))
        if (self.schema!=QUESTION_SCHEMA or self.scope not in{"local","core"}
                or self.question_key!="d01.growth:"+self.target_block+":"+self.scope
                or AtomKey.from_token(self.target_ref.ref).type_name!="d01.persona_plan.v1"
                or self.depth_basis!="independent_outcome_stage.v1"or type(self.stage_causal_depth)is not int
                or self.stage_causal_depth!=0
                or self.general_growth_attention_ref!=general_growth_attention_original_ref_v1(
                    namespace,self.outcome_original_digest,self.target_block,self.scope)):
            raise ValueError("General question requires its actual ordinary block and active persona-plan version")
        _source_refs_v1(self.context_source_refs,namespace)
        _source_refs_v1(self.support_source_refs,namespace,empty=True)
        union=tuple(dict.fromkeys((*self.context_source_refs,*self.support_source_refs)))
        if set(self.context_source_refs)&set(self.support_source_refs)or self.source_refs!=union:
            raise ValueError("General context and independent support must stay separate exact columns")
        for value in(self.target_digest,self.outcome_original_digest,self.outcome_trigger_digest,self.causal_receipt_digest,self.original_parent_grant_digest):
            _digest_v1(value)
        if (type(self.context_original_refs)is not tuple or not self.context_original_refs
                or any(type(item)is not ProductionOriginalRefV1 for item in self.context_original_refs)
                or type(self.original_deadline_utc)not in(int,float)or not math.isfinite(self.original_deadline_utc)):
            raise ValueError("General question requires actual original causes and an unchanged absolute deadline")

@dataclass(frozen=True,slots=True)
class RegisterGeneralGrowthAttentionRequestV1:
    outcome_trigger_ref:str
    outcome_trigger_digest:str
    target_ref:VersionedRef
    target_block:str
    target_digest:str
    scope:str
    context_source_refs:tuple[str,...]
    support_source_refs:tuple[str,...]

    def __post_init__(self):
        if type(self.target_ref)is not VersionedRef or self.target_ref.version<1 or self.scope not in{"local","core"}:
            raise ValueError("General attention request requires an actual positive target version")
        namespace=NamespaceId.from_key(AtomKey.from_token(self.target_ref.ref))
        _source_refs_v1(self.context_source_refs,namespace)
        _source_refs_v1(self.support_source_refs,namespace,empty=True)
        _digest_v1(self.outcome_trigger_digest);_digest_v1(self.target_digest)

@dataclass(frozen=True,slots=True)
class D07GeneralGrowthAttentionOriginalV1:
    namespace:NamespaceId
    original_ref:str
    registration_operation_id:str
    registration_receipt_digest:str
    ticket_ref:GraphVersion
    ticket_digest:str
    semantic_question_ref:str
    semantic_question_digest:str
    outcome_trigger_ref:str
    outcome_trigger_digest:str
    causal_operation_id:str
    causal_receipt_digest:str
    owner_guard:ProductionOwnerGuardV1
    source_authority:AuthorityContext
    original_parent_budget_lease_ref:str
    original_parent_grant_digest:str
    original_deadline_utc:float
    context_source_refs:tuple[str,...]
    support_source_refs:tuple[str,...]
    schema:str="d07.general-growth-attention.v1"

    def __post_init__(self):
        if (self.schema!="d07.general-growth-attention.v1"or type(self.namespace)is not NamespaceId
                or type(self.ticket_ref)is not GraphVersion or self.ticket_ref.revision<1
                or self.ticket_ref.key.type_name!="d07.attention_ticket.v1"
                or NamespaceId.from_key(self.ticket_ref.key)!=self.namespace
                or type(self.owner_guard)is not ProductionOwnerGuardV1 or type(self.source_authority)is not AuthorityContext
                or self.source_authority.namespace!=self.namespace or self.source_authority.purpose!="consolidation"
                or type(self.original_deadline_utc)not in(int,float)or not math.isfinite(self.original_deadline_utc)):
            raise ValueError("General attention requires actual current Owner/Source/receipt/deadline metadata")
        _source_refs_v1(self.context_source_refs,self.namespace)
        _source_refs_v1(self.support_source_refs,self.namespace,empty=True)
        for value in(self.registration_receipt_digest,self.ticket_digest,self.semantic_question_digest,
                self.outcome_trigger_digest,self.causal_receipt_digest,self.original_parent_grant_digest):
            _digest_v1(value)

def general_growth_attention_ids_v1(namespace,outcome_original_digest,target_block,scope):
    _digest_v1(outcome_original_digest)
    tag=canonical_digest((namespace,outcome_original_digest,target_block,scope))[:48]
    return{"operation":"general-growth-register:"+tag,"activity":"general-growth-attention:"+tag,
        "ticket":"attention:general-growth:"+tag,"question":"general-growth-question:"+tag,
        "attention":"general-growth-attention-original:"+tag}

class InstalledD07GeneralGrowthAttentionReadersV1:
    def __init__(self,*,graph,issuer,bundle):
        from ..graph_coordinator import GraphCoordinator
        from .issuers import D11BudgetJobIssuer
        from ..host.authority_profile import AdminInstallationBundle
        if (type(graph)is not GraphCoordinator or issuer is not graph._GraphCoordinator__d11_issuer
                or type(issuer)is not D11BudgetJobIssuer or type(bundle)is not AdminInstallationBundle
                or graph._GraphCoordinator__d04_installed_joint_assembly is None
                or graph._GraphCoordinator__d04_installed_joint_assembly.admin_bundle is not bundle):
            raise TypeError("General attention needs this actual installed Graph/issuer/profile")
        self.graph,self.issuer,self.bundle=graph,issuer,bundle

def _actual_general_target_v1(read,db,target_ref,target_block,target_digest):
    from ..domains.d01 import PersonaDomain
    from ..domains.d01 import method_policy_state_v1
    from ..domains.d01.production_operations_v1 import plain_v1
    active=PersonaDomain().resolve_active_role(read.frame.snapshot,
        namespace=read.frame.envelope.authority.namespace,current_guard=read.frame.owner_guard)
    atom=read.head(db,target_ref.ref,required=True)
    expected=PersonaDomain.plan_write(active.plan).key
    block=next((value for value in active.plan.blocks if value.block_id==target_block),None)
    if (atom.key!=expected or atom.revision!=target_ref.version or block is None
            or block.kind=="semantic_identity"or block.plasticity!="growth"
            or method_policy_state_v1(block.claim)is not None
            or canonical_digest(plain_v1(block))!=target_digest):
        from .d01_production_operations_v1 import MissingProductionOriginalV1
        raise MissingProductionOriginalV1("actual_current_ordinary_general_growth_target")
    return atom,block

def read_plan_register_general_growth_attention_v1(db,*,namespace,request,issuer):
    from .d01_production_operations_v1 import production_read_plan_v1,MissingProductionOriginalV1
    from ..domains.d12.types import active_scheme_head_key
    from ..domains.d07 import attention_ticket_key
    trigger=read_actual_general_growth_outcome_trigger_v1(db,namespace=namespace,original_ref=request.outcome_trigger_ref,issuer=issuer)
    if trigger is None:raise MissingProductionOriginalV1("general_growth_original_authorization_deadline")
    ids=general_growth_attention_ids_v1(namespace,trigger.outcome_original.original_digest,request.target_block,request.scope)
    keys=(AtomKey.from_token(request.target_ref.ref),owner_grant_key(*namespace.as_tuple),active_scheme_head_key(namespace),
        attention_ticket_key(namespace,ids["ticket"]))
    roots=tuple(dict.fromkeys((*request.context_source_refs,*request.support_source_refs)))
    return production_read_plan_v1(("d01.persona_activation.v1","d01.persona_plan.v1"),keys,roots,
        (request.outcome_trigger_ref,*[item.original_ref for item in trigger.context_original_refs]))

def stage_register_general_growth_attention_v1(db,*,frame,request,installed_readers):
    from .d01_production_operations_v1 import CurrentDomainReadV1,MissingProductionOriginalV1,waiting_stage_v1
    from ..domains.d07 import AttentionTicket,D07DomainProvider,attention_ticket_key
    from ..domains.d01.production_operations_v1 import stage_result_v1,plain_v1
    from .domain_followup_consumer_v1 import require_background_followup_v1
    if type(request)is not RegisterGeneralGrowthAttentionRequestV1 or type(installed_readers)is not InstalledD07GeneralGrowthAttentionReadersV1:
        raise TypeError("exact actual General growth attention producer required")
    graph=installed_readers.graph;issued=graph._GraphCoordinator__domain_production_runtime_v1._active_background_followup_v1
    require_background_followup_v1(issued,graph,issued.authority,frame.envelope.identity.operation_id)
    if (frame.envelope.authority.actor!=issued.authority.actor
            or frame.envelope.authority.namespace!=issued.authority.namespace
            or frame.envelope.authority.purpose!="consolidation"):
        raise ValueError("General child must retain the actual private Owner actor/namespace and consolidation admission")
    if (issued.event.event_kind!=TRIGGER_EVENT or issued.event.receiver_domain!="d01"
            or issued.command is None or issued.command.receiver_domain!="d07"
            or issued.command.operation_kind!="register_general_growth_attention_v1"or issued.command.request!=request):
        raise ValueError("General attention cannot borrow another receiver/cause/command private issuance")
    try:
        read=CurrentDomainReadV1(frame);read.check(db);namespace=frame.envelope.authority.namespace
        trigger=read_actual_general_growth_outcome_trigger_v1(db,namespace=namespace,original_ref=request.outcome_trigger_ref,issuer=installed_readers.issuer)
        if trigger is None:raise MissingProductionOriginalV1("general_growth_original_authorization_deadline")
        if trigger.digest!=request.outcome_trigger_digest or trigger.causal_operation_id!=issued.event.causal_operation_id:
            raise ValueError("General attention request changed the actual causal metadata trigger")
        require_current_general_growth_outcome_trigger_v1(db,read=read,trigger=trigger,issuer=installed_readers.issuer)
        if frame.envelope.authority.purpose!="consolidation"or frame.envelope.deadline_utc>trigger.original_deadline_utc:
            raise ValueError("General attention must use actual consolidation admission and original absolute deadline")
        contexts=tuple(version.key.token for version in trigger.context_source_versions)
        if request.context_source_refs!=contexts:
            raise ValueError("General context column differs from the actual Life outcome Source CAS members")
        target,block=_actual_general_target_v1(read,db,request.target_ref,request.target_block,request.target_digest)
        support={}
        for audience in frame.envelope.authority.audience:
            support=read.source_family(db,request.support_source_refs,purpose="consolidation",audience=audience)if request.support_source_refs else{}
        for ref,record in support.items():
            if (record.assertion_status!="confirmed"or record.source_kind!="observed"
                    or record.independence!="independent"or record.parent_source_ids):
                raise ValueError("General support requires actual independent confirmed observed roots")
        causal=read_general_growth_causal_metadata_v1(db,namespace=namespace,trigger=trigger)
        allowed={version.key.token for version in causal["read_versions"]if version.key.type_name=="memory.source"}
        if not set(request.support_source_refs)<=allowed:
            raise ValueError("General support source expanded the actual original causal parent read set")
        ids=general_growth_attention_ids_v1(namespace,trigger.outcome_original.original_digest,request.target_block,request.scope)
        ticket_key=attention_ticket_key(namespace,ids["ticket"])
        if read.head(db,ticket_key).revision:
            original=read_general_growth_attention_original_v1(db,namespace=namespace,original_ref=ids["attention"],issuer=installed_readers.issuer)
            if original is None:raise ValueError("General ticket exists without its actual signed original")
            raise MissingProductionOriginalV1("actual_general_growth_attention_already_registered")
        lease,grant,_=_actual_general_growth_budget_ancestry_v1(db,trigger.original_parent_budget_lease_ref,installed_readers.issuer)
        from ..host.model_workflows_v8 import AdminModelWorkflowsV8,is_installed_general_growth_cognition_slot_v1
        from ..host.model_workflows_v9 import AdminModelWorkflowsV9
        workflows=installed_readers.bundle.model_workflows
        if type(workflows) not in (AdminModelWorkflowsV8, AdminModelWorkflowsV9):raise MissingProductionOriginalV1("actual_installed_general_growth_workflow_v8")
        workflow=workflows.general_growth_cognition
        if workflow is None:raise MissingProductionOriginalV1("actual_installed_general_growth_cognition_slot")
        if not is_installed_general_growth_cognition_slot_v1(installed_readers.bundle,workflow):
            raise ValueError("General attention resources changed the exact installed workflow slot")
        available=(workflow is not None and"d07.cognition"in grant.allowed_work_kinds
            and all(ceiling<=min(lease.available(name),grant.max_ceiling.get(name,0))
                for name,ceiling in workflow.quote_ceiling.items()))
        if not available:raise MissingProductionOriginalV1("actual_original_general_growth_model_resources")
        roots=tuple(dict.fromkeys((*contexts,*request.support_source_refs)))
        question=D07GeneralGrowthQuestionV1(question_key="d01.growth:"+block.block_id+":"+request.scope,
            question="Evaluate this exact ordinary block and scope using the actual Life outcome as context and only the supplied independent roots as support.",
            target_ref=request.target_ref,source_refs=roots,target_block=block.block_id,target_digest=request.target_digest,
            scope=request.scope,general_growth_attention_ref=ids["attention"],
            outcome_original_ref=trigger.outcome_original.original_ref,outcome_original_digest=trigger.outcome_original.original_digest,
            depth_basis="independent_outcome_stage.v1",stage_causal_depth=0,context_source_refs=contexts,support_source_refs=request.support_source_refs,
            context_original_refs=(*trigger.context_original_refs,ProductionOriginalRefV1("d10."+TRIGGER_KIND,trigger.original_ref,trigger.digest)),
            outcome_trigger_ref=trigger.original_ref,outcome_trigger_digest=trigger.digest,causal_operation_id=trigger.causal_operation_id,
            causal_receipt_digest=trigger.causal_receipt_digest,original_parent_budget_lease_ref=trigger.original_parent_budget_lease_ref,
            original_parent_grant_digest=trigger.original_parent_grant_digest,original_deadline_utc=trigger.original_deadline_utc)
        ticket=AttentionTicket(ids["ticket"],question.question_key,target.key.token,contexts[0],"background",
            0.,0.,0.,0.,0.,0.,0.,0.,0.,frame.snapshot.epochs[0].revision,
            min(frame.envelope.deadline_utc,trigger.original_deadline_utc),True,available,(),roots)
        write=GraphWrite(ticket_key,{"schema":ticket_key.type_name,**plain_v1(ticket)},
            tuple(AtomKey.from_token(ref)for ref in roots)+(target.key,))
        provider=D07DomainProvider()
        return stage_result_v1(frame,"d07","register_general_growth_attention_v1",request,writes=(write,),
            provenance={"general_growth_question":question,"general_growth_ticket":ticket,
                "outcome_trigger":ProductionOriginalRefV1("d10."+TRIGGER_KIND,trigger.original_ref,trigger.digest)},
            receiver_events=(("d07","general_growth_attention_available_for_service"),),
            proposal_schema="d07.proposal.v1",proposal_hash=provider.descriptor.request_schema_hash)
    except MissingProductionOriginalV1 as missing:
        return waiting_stage_v1(frame,"d07","register_general_growth_attention_v1",request,missing)

def record_general_growth_attention_after_cas_v1(db,*,frame,stage,receipt,issuer):
    from .d07_execution_v1 import record_d07_original_in_transaction_v1
    from ..domains.d01.production_operations_v1 import plain_v1
    if stage.operation_kind!="register_general_growth_attention_v1"or stage.coverage!="complete":return None
    raw=json.loads(stage.original_payload_json)["provenance"]
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    from ..domains.d07 import AttentionTicket
    question=decode_typed_production_value_v1(raw["general_growth_question"],D07GeneralGrowthQuestionV1)
    ticket=decode_typed_production_value_v1(raw["general_growth_ticket"],AttentionTicket)
    namespace=frame.envelope.authority.namespace
    ids=general_growth_attention_ids_v1(namespace,question.outcome_original_digest,question.target_block,question.scope)
    from ..domains.d07 import attention_ticket_key
    key=attention_ticket_key(namespace,ticket.ticket_id)
    versions=tuple(value for value in receipt.write_versions if value.key==key)
    if len(versions)!=1 or receipt.status!="committed"or receipt.operation_id!=stage.operation_id:
        raise ValueError("General fair ticket has no exact actual registration CAS member")
    history=db.execute("SELECT event_bot,event_persona,event_id,valid FROM graph_history WHERE token=? AND revision=?",
        (key.token,versions[0].revision)).fetchone()
    if history!=(*namespace.as_tuple,receipt.operation_id,1):
        raise ValueError("General ticket has no immutable actual producing history occurrence")
    question_digest=record_d07_original_in_transaction_v1(db,issuer,namespace,"semantic_question",ids["question"],plain_v1(question))
    original=D07GeneralGrowthAttentionOriginalV1(namespace,ids["attention"],stage.operation_id,canonical_digest(receipt),
        versions[0],canonical_digest({"schema":key.type_name,**plain_v1(ticket)}),ids["question"],question_digest,
        question.outcome_trigger_ref,question.outcome_trigger_digest,question.causal_operation_id,question.causal_receipt_digest,
        frame.owner_guard,frame.envelope.authority,question.original_parent_budget_lease_ref,question.original_parent_grant_digest,
        question.original_deadline_utc,question.context_source_refs,question.support_source_refs)
    digest=record_d07_original_in_transaction_v1(db,issuer,namespace,ATTENTION_KIND,ids["attention"],plain_v1(original))
    return ProductionOriginalRefV1("d07."+ATTENTION_KIND,ids["attention"],digest,(versions[0],))

def read_general_growth_attention_original_v1(db,*,namespace,original_ref,issuer):
    from .d07_execution_v1 import read_d07_original_v1
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    row=read_d07_original_v1(db,issuer,namespace,ATTENTION_KIND,original_ref)
    if row is None:return None
    value=decode_typed_production_value_v1(row[0],D07GeneralGrowthAttentionOriginalV1)
    from ..domains.d01.production_operations_v1 import plain_v1
    if value.namespace!=namespace or value.original_ref!=original_ref or canonical_digest(plain_v1(value))!=row[1]:
        raise ValueError("General attention original differs from its exact namespace/canonical signed EOF")
    from .domain_production_originals_v1 import read_adopted_domain_operation_v1
    adopted=read_adopted_domain_operation_v1(db,namespace,value.registration_operation_id)
    if (adopted is None or(adopted["domain"],adopted["operation_kind"])!=("d07","register_general_growth_attention_v1")
            or canonical_digest(adopted["receipt"])!=value.registration_receipt_digest
            or value.ticket_ref not in adopted["receipt"].write_versions):
        raise ValueError("General attention has no actual adopted registration receipt")
    return value

def read_general_growth_ticket_original_v1(db,*,read,ticket,issuer):
    """Called only for the actual explicit General ticket variant in full fairness."""
    if not ticket.ticket_id.startswith("attention:general-growth:"):return None
    from ..domains.d01.production_operations_v1 import plain_v1
    namespace=read.frame.envelope.authority.namespace
    original_ref="general-growth-attention-original:"+ticket.ticket_id.removeprefix("attention:general-growth:")
    original=read_general_growth_attention_original_v1(db,namespace=namespace,original_ref=original_ref,issuer=issuer)
    if original is None:raise ValueError("General fair inventory ticket lost its exact signed original")
    from .domain_background_read_v3 import background_history_v3,background_json_loads_v3,background_json_digest_v3
    birth=background_history_v3(db,original.ticket_ref.key.token,original.ticket_ref.revision,
        columns=("event_bot","event_persona","event_id","value","valid"))
    if (birth is None or birth[:3]!=(*namespace.as_tuple,original.registration_operation_id)or birth[4]!=1
            or background_json_digest_v3(birth[3],background_json_loads_v3(birth[3]))!=original.ticket_digest):
        raise ValueError("General fair ticket lost its exact immutable registration birth")
    atom=read.head(db,original.ticket_ref.key,required=True)
    if (canonical_digest(atom.value)!=original.ticket_digest
            or ticket.source_refs!=tuple(dict.fromkeys((*original.context_source_refs,*original.support_source_refs)))
            or ticket.question_key!=read_general_growth_question_v1(db,namespace=namespace,ref=original.semantic_question_ref,issuer=issuer)[0].question_key):
        raise ValueError("General fair inventory ticket/source union/question changed")
    return ProductionOriginalRefV1("d07."+ATTENTION_KIND,original.original_ref,
        canonical_digest(plain_v1(original)),
        (original.ticket_ref,))

def read_general_growth_question_v1(db,*,namespace,ref,issuer):
    from .d07_execution_v1 import read_d07_original_v1
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    from ..domains.d01.production_operations_v1 import plain_v1
    row=read_d07_original_v1(db,issuer,namespace,"semantic_question",ref)
    if row is None:return None
    if row[0].get("schema")!=QUESTION_SCHEMA:return None
    question=decode_typed_production_value_v1(row[0],D07GeneralGrowthQuestionV1)
    if canonical_digest(plain_v1(question))!=row[1]:
        raise ValueError("General question lost actual complete canonical signed bytes")
    return question,row[1]

def validate_general_growth_registration_provenance_v1(provenance):
    from .domain_production_erasure_v1 import decode_typed_production_value_v1,_references
    from ..domains.d07 import AttentionTicket
    if set(provenance)!={"general_growth_question","general_growth_ticket","outcome_trigger"}:
        from .domain_production_erasure_v1 import DomainProductionErasureHold
        raise DomainProductionErasureHold("General attention provenance has another actual registered schema")
    question=decode_typed_production_value_v1(provenance["general_growth_question"],D07GeneralGrowthQuestionV1)
    ticket=decode_typed_production_value_v1(provenance["general_growth_ticket"],AttentionTicket)
    if ticket.source_refs!=question.source_refs or ticket.question_key!=question.question_key:
        raise ValueError("General registration ticket differs from its actual question/context/support")
    return tuple(sorted(set(_references(provenance))))

_GENERAL_READ_PARENTS=WeakKeyDictionary()

def general_growth_followup_parent_v1(db,*,event,issuer):
    """Read an exact metadata-only General parent; ordinary events stay separate."""
    if event.event_kind==TRIGGER_EVENT and event.receiver_domain=="d01":
        ref=event.trigger_original.original_ref
        if not ref.startswith("general-growth-outcome:"):return None
        trigger=read_actual_general_growth_outcome_trigger_v1(db,namespace=event.namespace,original_ref=ref,issuer=issuer)
        if trigger is None or trigger.digest!=event.trigger_original.original_digest:
            raise ValueError("General event lost its exact actual signed trigger")
        return trigger
    if event.event_kind=="general_growth_attention_available_for_service"and event.receiver_domain=="d07":
        attention=read_general_growth_attention_original_v1(db,namespace=event.namespace,
            original_ref=event.trigger_original.original_ref,issuer=issuer)
        if attention is None or attention.causal_operation_id is None:
            raise ValueError("General service event has no actual signed attention original")
        from ..domains.d01.production_operations_v1 import plain_v1
        if canonical_digest(plain_v1(attention))!=event.trigger_original.original_digest:
            raise ValueError("General service event changed its actual attention commitment")
        trigger=read_actual_general_growth_outcome_trigger_v1(db,namespace=event.namespace,
            original_ref=attention.outcome_trigger_ref,issuer=issuer)
        if trigger is None or trigger.digest!=attention.outcome_trigger_digest:
            raise ValueError("General attention lost original outcome authorization metadata")
        return trigger
    return None

def bind_general_growth_followup_parent_v1(db,reader,event,trigger):
    from .domain_background_read_v3 import _active_v3,require_actual_background_attachment_owner_v3
    require_actual_background_attachment_owner_v3(reader,db=db)
    if _active_v3(db)is not reader or reader.kind not in{"followup","followup_child"}:
        raise ValueError("General parent metadata binding requires this actual original Background Work")
    if trigger is None:return None
    actual=general_growth_followup_parent_v1(db,event=event,issuer=reader.graph._GraphCoordinator__d11_issuer)
    if actual!=trigger:raise ValueError("General background parent is not its exact signed producer")
    _GENERAL_READ_PARENTS[reader]=(event,trigger,reader.operation,reader.graph_stamp)
    return trigger

def general_growth_parent_from_prepared_v1(prepared,event,command):
    prepared.require_v3(prepared.graph);reader=prepared.owner
    stored=_GENERAL_READ_PARENTS.get(reader)
    if stored is None:return None
    if (stored[0]!=event or stored[2]is not reader.operation or stored[3]!=reader.graph_stamp
            or command is not None and command not in prepared.local_result[5].commands):
        raise ValueError("General actual prepared parent metadata changed event/command/Work")
    return stored[1]

def general_growth_child_command_allowed_v1(issued,graph,command):
    from .domain_followup_consumer_v1 import require_background_followup_v1
    require_background_followup_v1(issued,graph,issued.authority,issued.operation_id)
    if command is None:return False
    if (issued.event.event_kind==TRIGGER_EVENT and issued.event.receiver_domain=="d01"
            and command.receiver_domain=="d07"and command.operation_kind=="register_general_growth_attention_v1"
            and type(command.request)is RegisterGeneralGrowthAttentionRequestV1):
        return True
    if (issued.event.event_kind=="general_growth_attention_available_for_service"
            and issued.event.receiver_domain=="d07"and command.receiver_domain=="d07"
            and command.operation_kind=="serve_concern"):
        from .d07_current_behavior_v1 import ServeCurrentConcernRequestV1
        return type(command.request)is ServeCurrentConcernRequestV1 and command.request.category=="background"
    return False

def actual_general_growth_child_deadline_v1(issued,graph):
    from .domain_followup_consumer_v1 import require_background_followup_v1
    require_background_followup_v1(issued,graph,issued.authority,issued.operation_id)
    trigger=issued.general_growth_parent_metadata
    if trigger is None:return None
    if not general_growth_child_command_allowed_v1(issued,graph,issued.command):
        raise ValueError("General metadata cannot alter a different child command or receiver")
    if (type(trigger)is not D10GeneralGrowthOutcomeTriggerV1
            or trigger.namespace!=issued.authority.namespace
            or trigger.authorization_status!="qualified"):
        from .d01_production_operations_v1 import MissingProductionOriginalV1
        raise MissingProductionOriginalV1("general_growth_original_parent_work_authorization")
    return trigger.original_deadline_utc

def resolve_general_growth_outcome_followup_v1(db,read,event,trigger,*,issuer):
    from ..domains.d01 import PersonaDomain
    from ..domains.d01 import method_policy_state_v1
    from ..domains.d01.production_operations_v1 import plain_v1
    from .domain_production_followups_v1 import DomainFollowupCommandV1,DomainFollowupResolutionV1
    from .d01_production_operations_v1 import MissingProductionOriginalV1
    frame=read.frame;namespace=event.namespace
    continuation="general-growth-followup:"+canonical_digest((namespace,event.dedupe_key))[:48]
    def waiting(reason):
        return DomainFollowupResolutionV1("waiting_for_original",(),(),(reason,),continuation)
    if trigger is None:return waiting("general_growth_original_authorization_deadline")
    try:require_current_general_growth_outcome_trigger_v1(db,read=read,trigger=trigger,issuer=issuer)
    except MissingProductionOriginalV1 as missing:
        return DomainFollowupResolutionV1("waiting_for_original",(),(),missing.missing_inputs,continuation)
    causal=read_general_growth_causal_metadata_v1(db,namespace=namespace,trigger=trigger)
    refs=tuple(sorted(version.key.token for version in causal["read_versions"]if version.key.type_name=="memory.source"
        and version.key.token not in{item.key.token for item in trigger.context_source_versions}))
    records={}
    for audience in frame.envelope.authority.audience:
        records=read.source_family(db,refs,purpose="consolidation",audience=audience)if refs else{}
    support=tuple(ref for ref in refs if records[ref].assertion_status=="confirmed"and records[ref].source_kind=="observed"
        and records[ref].independence=="independent"and not records[ref].parent_source_ids)
    if len(support)+len(trigger.context_source_versions)>16:return waiting("bounded_general_growth_actual_support_inventory")
    active=PersonaDomain().resolve_active_role(frame.snapshot,namespace=namespace,current_guard=frame.owner_guard)
    key=PersonaDomain.plan_write(active.plan).key;head=read.head(db,key,required=True)
    contexts=tuple(item.key.token for item in trigger.context_source_versions)
    targets=[block for block in active.plan.blocks if block.kind!="semantic_identity"and block.plasticity=="growth"
        and method_policy_state_v1(block.claim)is None]
    if not targets:return waiting("actual_current_ordinary_general_growth_target")
    commands=[];missing=[]
    for block in sorted(targets,key=lambda value:value.block_id):
        for scope in("local","core"):
            if len(commands)>=frame.limits.max_followup_jobs:
                missing.append("bounded_general_growth_target_tail");break
            ids=general_growth_attention_ids_v1(namespace,trigger.outcome_original.original_digest,block.block_id,scope)
            request=RegisterGeneralGrowthAttentionRequestV1(trigger.original_ref,trigger.digest,
                VersionedRef(key.token,head.revision),block.block_id,canonical_digest(plain_v1(block)),scope,contexts,support)
            commands.append(DomainFollowupCommandV1("d07","register_general_growth_attention_v1",request,
                ids["activity"],frame.envelope.authority.audience[0],frame.envelope.authority.audience))
    return DomainFollowupResolutionV1("partial"if missing else"ready",tuple(commands),
        (key.token,),tuple(dict.fromkeys(missing)),continuation if missing else None)

def resolve_general_growth_service_followup_v1(db,read,event,trigger,*,issuer):
    from .domain_production_followups_v1 import DomainFollowupCommandV1,DomainFollowupResolutionV1
    from .d07_current_behavior_v1 import ServeCurrentConcernRequestV1
    from .d01_production_operations_v1 import MissingProductionOriginalV1
    from ..domains.d07 import AttentionTicket
    from ..domains.d07.concern_round import(ConcernRoundV1,read_concern_round,choose_concern_segment,begin_concern_round)
    from .d12_current_d07_policy_v1 import read_current_d07_attention_policy_v1
    frame=read.frame;namespace=event.namespace
    continuation="general-growth-service:"+canonical_digest((namespace,event.dedupe_key))[:48]
    def waiting(reason):
        return DomainFollowupResolutionV1("waiting_for_original",(),(event.trigger_original.original_ref,),(reason,),continuation)
    if trigger is None:return waiting("general_growth_original_authorization_deadline")
    try:require_current_general_growth_outcome_trigger_v1(db,read=read,trigger=trigger,issuer=issuer)
    except MissingProductionOriginalV1 as missing:
        return DomainFollowupResolutionV1("waiting_for_original",(),(),missing.missing_inputs,continuation)
    attention=read_general_growth_attention_original_v1(db,namespace=namespace,original_ref=event.trigger_original.original_ref,issuer=issuer)
    if attention is None:return waiting("actual_general_growth_attention_original")
    original=read_general_growth_question_v1(db,namespace=namespace,ref=attention.semantic_question_ref,issuer=issuer)
    if original is None or original[1]!=attention.semantic_question_digest:
        raise ValueError("General service lost its actual registered semantic question")
    question=original[0]
    tickets=[]
    for atom in read.complete_inventory(db,"d07.attention_ticket.v1"):
        if not atom.valid:continue
        raw={name:value for name,value in atom.value.items()if name!="schema"}
        ticket=AttentionTicket(**{**raw,"source_refs":tuple(raw["source_refs"]),"cancel_refs":tuple(raw["cancel_refs"])})
        if ticket.ticket_id.startswith("attention:general-growth:"):
            read_general_growth_ticket_original_v1(db,read=read,ticket=ticket,issuer=issuer)
        else:
            from ..host.post_c02_attention_driver import post_c02_attention_operation_id
            from .domain_background_read_v3 import background_rows_v3,background_point_v3
            rows=background_rows_v3(db,table="graph_d07_attention_issuance_v1",columns=("operation_id","c02_operation_id","bundle_digest"),
                group_columns=("bot","persona","source_ref"),group=(*namespace.as_tuple,ticket.causal_root),
                order_columns=("operation_id",),limit=2,
                legacy_reader=lambda:db.execute("SELECT operation_id,c02_operation_id,bundle_digest FROM graph_d07_attention_issuance_v1 "
                    "WHERE bot=? AND persona=? AND source_ref=? ORDER BY operation_id LIMIT 2",
                    (*namespace.as_tuple,ticket.causal_root)).fetchall())
            matched=[row for row in rows if ticket.ticket_id=="attention:"+canonical_digest({"operation_id":row[0]})[:48]
                and row[0]==post_c02_attention_operation_id(row[1],ticket.causal_root)]
            if len(matched)!=1:raise ValueError("General fairness inventory has an unauthenticated actual non-General ticket")
            ledger=background_point_v3(db,table="graph_bundle_operations",columns=("digest","commit_seq"),
                key_columns=("bot","persona","operation_id"),key=(*namespace.as_tuple,matched[0][0]),
                legacy_reader=lambda:db.execute("SELECT digest,commit_seq FROM graph_bundle_operations "
                    "WHERE bot=? AND persona=? AND operation_id=?",(*namespace.as_tuple,matched[0][0])).fetchone())
            if ledger is None or ledger[0]!=matched[0][2]or ledger[1]<1:
                raise ValueError("General fairness ticket issuance has no actual adopted bundle occurrence")
        tickets.append(ticket)
    policy=read_current_d07_attention_policy_v1(db,namespace).policy
    found=read_concern_round(frame.snapshot,namespace,"background")
    state=found[0]if found else ConcernRoundV1(namespace.persona_id,"background",0,0,(),(),(),())
    focus=next((atom for atom in frame.snapshot.atoms if atom.key.type_name=="d07.focus.v1"and atom.valid),None)
    focus_epoch=0 if focus is None else focus.value["focus_epoch"]
    choice=choose_concern_segment(state,tuple(tickets),policy,now=frame.now_utc,focus_epoch=focus_epoch)
    if choice is None:
        runnable={ticket.concern_ref or ticket.causal_root for ticket in tickets if ticket.category=="background"
            and ticket.eligible and ticket.resources_available and not ticket.cancel_refs and ticket.valid_until>frame.now_utc}
        parked=dict(state.parked)
        for group in state.groups:
            if group not in runnable:parked[group]=frame.now_utc
        candidate=replace(state,parked=tuple(sorted(parked.items())))
        candidate=begin_concern_round(candidate,tuple(tickets),now=frame.now_utc).next_round
        choice=choose_concern_segment(candidate,tuple(tickets),policy,now=frame.now_utc,focus_epoch=focus_epoch)
    if choice is None or choice.ticket_id!=attention.ticket_ref.key.name:
        return waiting("general_growth_original_ticket_not_selected_by_current_fair_round")
    request=ServeCurrentConcernRequestV1("background",attention.semantic_question_ref)
    activity="general-growth-cognition:"+canonical_digest((namespace,question.outcome_original_digest,question.target_block,question.scope))[:48]
    command=DomainFollowupCommandV1("d07","serve_concern",request,activity,
        frame.envelope.authority.audience[0],frame.envelope.authority.audience)
    return DomainFollowupResolutionV1("ready",(command,),(attention.ticket_ref.key.token,),(),None)

def general_growth_attention_original_ref_v1(namespace,outcome_original_digest,target_block,scope):
    return general_growth_attention_ids_v1(namespace,outcome_original_digest,target_block,scope)["attention"]

def read_current_general_growth_attention_v1(db,issuer,namespace,attention_ref):
    value=read_general_growth_attention_original_v1(db,namespace=namespace,original_ref=attention_ref,issuer=issuer)
    if value is None:return None
    from .d07_execution_v1 import read_d07_original_v1
    row=read_d07_original_v1(db,issuer,namespace,ATTENTION_KIND,attention_ref)
    return value,row[1]

def read_general_growth_followup_cause_v1(db,*,namespace,event_kind,causal_operation_id,original_ref,issuer):
    """Return the actual small causal metadata projection for this exact event."""
    if event_kind!=TRIGGER_EVENT:return None
    from .domain_background_read_v3 import _active_v3,background_json_loads_v3
    owner=_active_v3(db)
    if owner is None:
        from .d01_production_operations_v1 import MissingProductionOriginalV1
        raise MissingProductionOriginalV1("actual_segmented_general_growth_metadata_read")
    if (owner.entry is None or owner.entry[0]!=causal_operation_id or owner.entry[2]!=TRIGGER_EVENT
            or owner.entry_column is None or not owner.entry_column.complete):
        raise ValueError("General cause requires its actual same-Work opaque whole original EOF")
    trigger_ref=(original_ref if original_ref.startswith("general-growth-outcome:")else
        general_growth_outcome_trigger_ref_v1(namespace,causal_operation_id))
    trigger=read_actual_general_growth_outcome_trigger_v1(db,namespace=namespace,original_ref=trigger_ref,issuer=issuer)
    if trigger is not None:return read_general_growth_causal_metadata_v1(db,namespace=namespace,trigger=trigger)
    # Old originals without a saved authorization deadline are metadata only.
    from .natural_producer_qualification_v1 import _producer_original_point_v3
    from .domain_production_originals_v1 import _receipt
    row=_general_growth_adopted_metadata_row_v1(db,namespace,causal_operation_id)
    if row is None or row[:2]!=("d10","advance_life")or owner.entry_column.column.sha256!=row[2]:
        raise ValueError("Old General cause lost its actual metadata header/full raw EOF")
    return{"domain":row[0],"operation_kind":row[1],"original_digest":row[2],
        "read_versions":tuple(GraphVersion(AtomKey.from_token(ref),rev)for ref,rev in background_json_loads_v3(row[5])),
        "receipt":_receipt(background_json_loads_v3(row[6])),"payload":owner.entry_metadata[1]}

def general_growth_background_parent_v1(reader):
    value=_GENERAL_READ_PARENTS.get(reader)
    if value is None:return None
    if value[2]is not reader.operation or value[3]!=reader.graph_stamp:
        raise ValueError("General metadata reader lost its original operation/stamp")
    return value[1]

def general_growth_parent_metadata_status_v1(db,*,trigger,owner,authority,issuer,now):
    if trigger is None:return"general_growth_original_authorization_deadline"
    if trigger.authorization_status!="qualified":return"general_growth_original_parent_work_authorization"
    if now>=trigger.original_deadline_utc:return"general_growth_original_authorization_deadline_expired"
    current=ProductionOwnerGuardV1(owner_grant_key(*trigger.namespace.as_tuple).token,owner.grant_revision,
        owner.grant_digest.removeprefix("sha256:"),owner.authorization_head.removeprefix("sha256:"))
    if (current!=trigger.owner_guard or authority.actor!=trigger.source_authority.actor
            or authority.namespace!=trigger.namespace or authority.activation_generation!=trigger.source_authority.activation_generation
            or not set(authority.audience)<=set(trigger.source_authority.audience)
            or "consolidation"not in owner.purposes):
        return"general_growth_original_owner_or_source_actor_not_current"
    lease,grant,ancestry=_actual_general_growth_budget_ancestry_v1(db,trigger.original_parent_budget_lease_ref,issuer)
    if ancestry!=trigger.original_budget_ancestry:return"general_growth_original_budget_ancestry_changed"
    if (lease.state!="active"or canonical_digest(grant)!=trigger.original_parent_grant_digest
            or now>=grant.valid_until_utc or"d07.cognition"not in grant.allowed_work_kinds):
        return"general_growth_original_parent_grant_or_lease_not_current"
    return None

def require_general_growth_background_budget_point_v1(reader,table,key):
    trigger=general_growth_background_parent_v1(reader)
    if trigger is None or reader.kind not in{"followup","followup_child"}:
        raise ValueError("General budget metadata requires this actual signed parent Work")
    allowed={item[0]for item in trigger.original_budget_ancestry}
    if not key or key[0]not in allowed:
        raise ValueError("General budget point expanded the exact original parent ancestry")
    return trigger

def decode_general_growth_attention_content_v1(kind,raw):
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    if kind==ATTENTION_KIND:return decode_typed_production_value_v1(raw,D07GeneralGrowthAttentionOriginalV1)
    if kind=="semantic_question"and raw.get("schema")==QUESTION_SCHEMA:
        return decode_typed_production_value_v1(raw,D07GeneralGrowthQuestionV1)
    raise ValueError("General attention decoder has another exact original kind/schema")


def read_plan_general_growth_followup_v1(db,*,namespace,event,trigger,issuer):
    from .d01_production_operations_v1 import production_read_plan_v1
    from ..domains.d12.types import active_scheme_head_key
    keys=[version.key for version in trigger.context_source_versions]+[active_scheme_head_key(namespace)]
    roots=[key.token for key in keys]
    if event.event_kind==TRIGGER_EVENT:
        causal=read_general_growth_causal_metadata_v1(db,namespace=namespace,trigger=trigger)
        roots.extend(version.key.token for version in causal["read_versions"]if version.key.type_name=="memory.source")
        fixed=("d01.persona_activation.v1","d01.persona_plan.v1")
    else:
        attention=read_general_growth_attention_original_v1(db,namespace=namespace,
            original_ref=event.trigger_original.original_ref,issuer=issuer)
        question=read_general_growth_question_v1(db,namespace=namespace,ref=attention.semantic_question_ref,issuer=issuer)[0]
        roots=list(question.source_refs)
        keys.extend((attention.ticket_ref.key,AtomKey.from_token(question.target_ref.ref)))
        fixed=("d07.concern_round.v1","d07.attention_ticket.v1","d07.focus.v1","d01.persona_activation.v1","d01.persona_plan.v1")
    return production_read_plan_v1(fixed,keys,tuple(dict.fromkeys(roots)),(event.trigger_original.original_ref,))



_GENERAL_SOURCE_TASKS=WeakKeyDictionary()
_GENERAL_SOURCE_PROOFS=WeakKeyDictionary()
_GENERAL_SOURCE_ISSUER=object()

def _general_growth_source_heap_v1(reader,extra=0):
    from .domain_background_read_v3 import _heap
    total=extra
    for task in _GENERAL_SOURCE_TASKS.get(reader,{}).values():
        total+=_heap((task.key,task.header,task.fragment,task.metadata),set())
        if task.parser is not None:
            parser=task.parser
            total+=parser._source_heap_bytes()+_heap((parser._stack,parser._string,parser._literal,
                parser._number,parser._active_scalar),set())
    reader.reserve_heap_v3(extra=total)
    return total

def _new_general_growth_source_parser_v1(reader,*,ensure_ascii):
    from .c09_graph_row_codec_v2 import C09MemorySourceJSONStreamV3
    from weakref import ref as weak_ref
    reader_ref=weak_ref(reader)
    class _ActualGeneralSourceParser(C09MemorySourceJSONStreamV3):
        def _source_require_arena(self,extra=0):
            _general_growth_source_heap_v1(reader_ref(),extra)
            return super()._source_require_arena(extra)
    return _ActualGeneralSourceParser(ensure_ascii=ensure_ascii)

class _GeneralGrowthSourceMetadataEOFV1:
    def __init__(self,issuer,reader,ref):
        if issuer is not _GENERAL_SOURCE_ISSUER:raise TypeError("actual General Source metadata leaf issuer required")
        from .domain_background_read_v3 import require_actual_background_attachment_owner_v3
        require_actual_background_attachment_owner_v3(reader,db=reader.db)
        from weakref import ref as weak_ref
        self.reader=weak_ref(reader);self.key=AtomKey.from_token(ref)
        if self.key.type_name!="memory.source"or NamespaceId.from_key(self.key)!=reader.namespace:
            raise ValueError("General Source metadata leaf crossed actual Source namespace")
        self.header=None;self.cell=None;self.parser=None;self.fragment=b"";self.offset=0;self.total=None
        self.phase="header";self.metadata=None;self.sha256=None;self.complete=False
    def advance(self,meter):
        from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3,begin_runtime_cell_read_v3
        from .c09_paged_sql_v2 import read_legacy_sql_cell_fragment_v2,legacy_cell_read_transaction_v2
        reader=self.reader();reader.require_data_current_v3(meter)
        if self.complete:return True
        if self.phase=="header":
            self.header=_runtime_bounded_fixed_row_v3(reader.db,meter,"graph_atoms",
                ("revision","valid","value_cell_id"),"token=? AND bot=? AND persona=?",
                (self.key.token,*reader.namespace.as_tuple))
            if self.header is None or self.header[0]<1 or self.header[1]!=1:
                raise ValueError("General Source metadata lost its actual positive current head")
            self.cell=begin_runtime_cell_read_v3(reader.db,self.header[2],erasure_owner_ref=self.key.token)if self.header[2]is not None else None
            codec=None if self.cell is None else self.cell.header[0]
            if codec not in(None,"canonical-json.ascii.v1","canonical-json.utf8.v1"):
                raise ValueError("General Source metadata has another actual cell codec")
            self.parser=_new_general_growth_source_parser_v1(reader,ensure_ascii=codec!="canonical-json.utf8.v1")
            self.phase="source";return False
        if self.fragment:
            part=self.fragment[:1024]
            _general_growth_source_heap_v1(reader,len(part)*4+65536)
            self.parser.feed(part,lambda event:None)
            self.fragment=self.fragment[len(part):]
            return False
        if self.cell is not None:chunk=self.cell.read_fragment(meter=meter)
        else:
            with legacy_cell_read_transaction_v2(reader.db):
                if self.total is None:
                    meter.require_available(1024)
                    row=reader.db.execute("SELECT typeof(value),length(CAST(value AS BLOB)) FROM graph_atoms "
                        "WHERE token=? AND bot=? AND persona=?",(self.key.token,*reader.namespace.as_tuple)).fetchone()
                    meter.charge_read(16)
                    if row is None or row[0]!="text":raise ValueError("General Source original byte length/kind disappeared")
                    self.total=row[1]
                if self.offset<self.total:
                    chunk,total,kind=read_legacy_sql_cell_fragment_v2(reader.db,table="graph_atoms",column="value",
                        where="token=? AND bot=? AND persona=?",parameters=(self.key.token,*reader.namespace.as_tuple),
                        start=self.offset,length=min(16384,self.total-self.offset),meter=meter)
                    if(total,kind)!=(self.total,"text"):raise ValueError("General Source original byte count/kind changed")
                    self.offset+=len(chunk)
                else:chunk=None
        if chunk is not None:
            _general_growth_source_heap_v1(reader,len(chunk)+65536);self.fragment=chunk;return False
        result=self.parser.finish()
        if self.cell is not None:
            if(result.sha256,result.byte_count)!=(self.cell.finish(meter=meter),self.cell.header[3]):
                raise ValueError("General Source actual raw EOF/cell digest differs")
        elif result.byte_count!=self.total:raise ValueError("General Source legacy original EOF differs")
        _general_growth_source_heap_v1(reader,_general_metadata_copy_size_v1(self.parser._source_metadata))
        metadata=dict(self.parser._source_metadata)
        for name in("audiences","purposes","parent_source_ids"):metadata[name]=tuple(metadata[name])
        if metadata["source_id"]!=self.key.owner.subject:
            raise ValueError("General Source metadata identity differs from actual key")
        _general_growth_source_heap_v1(reader,_general_metadata_copy_size_v1(metadata))
        self.metadata=metadata;self.sha256=result.sha256;self.complete=True;return True
    def require_v1(self,reader,meter):
        from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3
        if self.reader()is not reader or _GENERAL_SOURCE_TASKS.get(reader,{}).get(self.key.token)is not self or not self.complete:
            raise ValueError("General Source metadata is not this actual Work's complete original leaf")
        reader.require_data_current_v3(meter)
        current=_runtime_bounded_fixed_row_v3(reader.db,meter,"graph_atoms",
            ("revision","valid","value_cell_id"),"token=? AND bot=? AND persona=?",(self.key.token,*reader.namespace.as_tuple))
        if current!=self.header:raise ValueError("General Source metadata changed its physical head after actual EOF")
        return self

def _general_metadata_copy_size_v1(value):
    from .domain_background_read_v3 import _heap
    return _heap(value,set())+65536

def start_general_growth_source_metadata_task_v1(reader,ref):
    if general_growth_background_parent_v1(reader)is None:
        raise ValueError("General Source metadata request lacks actual signed parent Work")
    tasks=_GENERAL_SOURCE_TASKS.setdefault(reader,{})
    task=tasks.get(ref)
    if task is None:task=_GeneralGrowthSourceMetadataEOFV1(_GENERAL_SOURCE_ISSUER,reader,ref);tasks[ref]=task
    return task

class _GeneralGrowthBackgroundSourcesQualifiedV1:
    def __init__(self,issuer,reader,roots,authority,refs):
        if issuer is not _GENERAL_SOURCE_ISSUER:raise TypeError("actual General all-parent Source qualification issuer required")
        from weakref import ref as weak_ref
        self.reader,self.roots,self.authority,self.refs=weak_ref(reader),roots,authority,refs
        self.operation,self.graph_stamp,self.owner_guard=reader.operation,reader.graph_stamp,reader.owner_guard
        _GENERAL_SOURCE_PROOFS[reader]=self
    def require_for_v1(self,reader,roots,authority):
        from .domain_background_read_v3 import require_actual_background_attachment_owner_v3
        require_actual_background_attachment_owner_v3(reader,db=reader.db)
        if (_GENERAL_SOURCE_PROOFS.get(reader)is not self or self.reader()is not reader
                or self.operation is not reader.operation or self.graph_stamp!=reader.graph_stamp
                or self.owner_guard!=reader.owner_guard or self.roots!=tuple(sorted(set(roots)))
                or self.authority.actor!=authority.actor or self.authority.namespace!=authority.namespace
                or self.authority.activation_generation!=authority.activation_generation
                or self.authority.purpose!=authority.purpose or self.authority.audience!=authority.audience):
            raise ValueError("General Source metadata qualification lost its actual current Work/Owner/actor/purpose")
        return self

def require_general_growth_background_sources_v1(reader,roots,authority):
    from .domain_background_read_v3 import BackgroundReadNeededV3,background_graph_head_v3,background_json_loads_v3
    from .c09_paged_sql_v2 import current_c09_sql_meter_v2
    from ..memory_types import source_key,access_key,validate_access
    from ..domains.d06 import source_correction_head_key
    roots=tuple(sorted(set(roots)));meter=current_c09_sql_meter_v2()
    if not roots:return None
    parent=general_growth_background_parent_v1(reader)
    if parent is None or authority.purpose!="consolidation":
        raise ValueError("General Source qualification lacks actual original parent/purpose")
    causal=read_general_growth_causal_metadata_v1(reader.db,namespace=reader.namespace,trigger=parent)
    allowed={version.key.token for version in parent.context_source_versions}
    allowed.update(version.key.token for version in causal["read_versions"]if version.key.type_name=="memory.source")
    if not set(roots)<=allowed:raise ValueError("General Source body plan expanded its actual original parent Source read-set")
    records={};active=set()
    def visit(ref):
        if ref in active:raise ValueError("General Source actual parent closure has a cycle")
        if ref in records:return
        if len(records)+len(active)>=256:raise ValueError("General Source closure exceeds original all-parent bound")
        task=_GENERAL_SOURCE_TASKS.get(reader,{}).get(ref)
        if task is None or not task.complete:
            if reader.sealed:raise ValueError("General Source metadata was not actually prepared before WRITE")
            raise BackgroundReadNeededV3(("general_growth_source_metadata",ref))
        task.require_v1(reader,meter);value=task.metadata;source_id=value["source_id"]
        access=background_graph_head_v3(reader.db,reader.namespace,access_key(*reader.namespace.as_tuple,source_id))
        correction=background_graph_head_v3(reader.db,reader.namespace,source_correction_head_key(reader.namespace,source_id))
        if access is None or access[0]<1 or access[2]!=1 or correction is not None:
            raise ValueError("General Source is corrected or lacks its current Access positive/negative heads")
        acl=background_json_loads_v3(access[1]);validate_access(acl)
        if (value["assertion_status"]not in{"confirmed","reported"}or "consolidation"not in value["purposes"]
                or acl["source_id"]!=source_id or acl["status"]!="active"or "consolidation"not in acl["purposes"]
                or not set(authority.audience)<=set(value["audiences"])or not set(authority.audience)<=set(acl["audiences"])):
            raise ValueError("General Source ancestor lacks current original consolidation audience permission")
        active.add(ref)
        for source_id in value["parent_source_ids"]:visit(source_key(*reader.namespace.as_tuple,source_id).token)
        if value["parent_source_ids"]and value["provenance_root"]not in{
                records[source_key(*reader.namespace.as_tuple,source_id).token]["provenance_root"]for source_id in value["parent_source_ids"]}:
            raise ValueError("General Source actual provenance root disagrees with its parents")
        active.remove(ref);records[ref]=value
    for ref in roots:visit(ref)
    proof=_GeneralGrowthBackgroundSourcesQualifiedV1(_GENERAL_SOURCE_ISSUER,reader,roots,authority,tuple(sorted(records)))
    return proof.require_for_v1(reader,roots,authority)

def read_general_growth_background_source_metadata_v1(reader,ref):
    from .c09_paged_sql_v2 import current_c09_sql_meter_v2
    task=_GENERAL_SOURCE_TASKS.get(reader,{}).get(ref)
    if task is None:raise ValueError("actual General Source metadata leaf is absent")
    return task.require_v1(reader,current_c09_sql_meter_v2()).metadata

def release_general_growth_source_metadata_v1(reader):
    _GENERAL_SOURCE_PROOFS.pop(reader,None);_GENERAL_SOURCE_TASKS.pop(reader,None)
