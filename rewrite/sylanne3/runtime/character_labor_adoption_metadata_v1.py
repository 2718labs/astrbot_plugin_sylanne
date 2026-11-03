"""Bodyless same-W01 character-labor adoption commitments.

This original authenticates committed members. It grants no Source, Body,
execution, budget, or expired fence permission.
"""
from __future__ import annotations

from dataclasses import dataclass, fields
from hashlib import sha256
from threading import get_ident
from weakref import WeakKeyDictionary
import json

from ..authority_service.contract import AuthorityUnavailable
from ..contracts import canonical_json
from ..domains.d01.production_operations_v1 import plain_v1
from ..graph_types import AtomKey
from ..runtime_contracts import NamespaceId, CommitReceipt, canonical_digest, canonical_serialize
from ..runtime_storage_v3 import (
    runtime_storage_v3, runtime_storage_quantum_v3, read_runtime_cell_origin_v3,
)
from .domain_production_contracts_v1 import ProductionOriginalRefV1

KIND = "character_labor_adoption_metadata_v1"
SCHEMA = "d11.character-labor-adoption-metadata.v1"
_HEADER = ("cell_id","codec_id","erasure_owner_ref","producer_operation_id",
    "total_bytes","segment_count","payload_sha256","ordered_segment_root","origin_scope_digest")
_ROLES = {
    "d02.body_state.v1":"body_state",
    "d02.reservation.v1":"reservation",
    "d02.settlement.v1":"settlement",
    "d02.character_labor_rebuild_head.v1":"chronological_head",
    "d02.character_labor_correction_revision.v1":"correction",
    "runtime.job":"job",
    "runtime.cost_settlement":"cost",
    "d08.action_outcome.v1":"outcome",
    "d11.life_artifact.v1":"artifact",
    "d11.role_segment_start.v1":"segment_start",
    "d11.role_segment_end.v1":"segment_end",
    "d11.life_fact_provenance.v1":"fact_provenance",
    "d11.life_fact_eligibility.v1":"fact_eligibility",
    "d11.life_outcome_provenance.v1":"outcome_provenance",
    "d11.life_outcome_eligibility.v1":"outcome_eligibility",
}
_MEMBERS = {}


def _digest(value):
    if type(value) is not str or len(value)!=64 or any(c not in "0123456789abcdef" for c in value):
        raise ValueError("exact labor adoption metadata digest required")


def _closed(raw, cls):
    if type(raw)is not dict or set(raw)!={f.name for f in fields(cls)}:
        raise ValueError("labor adoption metadata fields differ")
    return dict(raw)


def character_labor_adoption_metadata_ref_v1(prepared_original_ref):
    if type(prepared_original_ref)is not str or not prepared_original_ref:
        raise ValueError("actual Prepared locator required")
    return prepared_original_ref


@dataclass(frozen=True,slots=True)
class CharacterLaborCommittedMemberV1:
    role: str
    ref: str
    revision: int
    value_digest: str
    cell_header: tuple
    event_scope: tuple[str,...]
    dependencies: tuple[tuple[str,int],...]
    component_ids: tuple[str,...]

    def __post_init__(self):
        key=AtomKey.from_token(self.ref)
        if (self.role not in {*_ROLES.values(),"body_read","checkpoint","invalidated"}
                or self.role in _ROLES.values() and _ROLES.get(key.type_name)!=self.role
                or self.role in {"body_read","checkpoint"} and key.type_name!="d02.body_state.v1"
                or type(self.revision)is not int or self.revision<1
                or type(self.cell_header)is not tuple or len(self.cell_header)!=9
                or self.cell_header[1]!="canonical-json.ascii.v1"
                or self.cell_header[2]!=self.ref
                or type(self.cell_header[4])is not int or self.cell_header[4]<1
                or type(self.cell_header[5])is not int or self.cell_header[5]<1
                or type(self.event_scope)is not tuple or len(self.event_scope)!=4
                or type(self.dependencies)is not tuple or len(set(self.dependencies))!=len(self.dependencies)
                or type(self.component_ids)is not tuple or len(set(self.component_ids))!=len(self.component_ids)):
            raise ValueError("labor committed member has another role, scope or physical seal")
        for digest in (self.value_digest,self.cell_header[0],*self.cell_header[6:]):
            _digest(digest)
        if self.value_digest!=self.cell_header[6]:
            raise ValueError("labor value commitment differs from its actual canonical cell bytes")
        if self.role not in {"body_read","checkpoint","invalidated"} and self.cell_header[3]!=self.event_scope[3]:
            raise ValueError("labor physical cell producer differs from its history event")
        for ref,revision in self.dependencies:
            if type(revision)is not int or revision<0 or NamespaceId.from_key(AtomKey.from_token(ref))!=NamespaceId.from_key(key):
                raise ValueError("labor committed dependency crossed namespace")


@dataclass(frozen=True,slots=True)
class CharacterLaborAdoptionMetadataV1:
    namespace: NamespaceId
    authority_id: str
    authority_namespace: str
    installation_id: str
    manifest_digest: str
    execution_id: str
    effect_id: str
    binding_digest: str
    prepared_original: ProductionOriginalRefV1
    prepared_metadata_original: ProductionOriginalRefV1
    basis_original: ProductionOriginalRefV1
    segment_original: ProductionOriginalRefV1
    authority_segment_digest: str
    component_ids: tuple[str,...]
    permit_digest: str
    permit_operation_id: str
    bridge_digest: str
    bridge_original_digest: str
    before_anchor_digest: str
    after_anchor_digest: str
    finish_id: str
    finish_digest: str
    operation_id: str
    activity_id: str
    operation_digest: str
    commit_seq: int
    event_digest: str
    receipt_digest: str
    adoption_receipt_digest: str
    adopted_original: ProductionOriginalRefV1
    write_members: tuple[CharacterLaborCommittedMemberV1,...]
    invalidated_members: tuple[CharacterLaborCommittedMemberV1,...]
    invalidated_vector_sha256: str
    invalidated_vector_bytes: int
    invalidated_vector_count: int
    body_read: CharacterLaborCommittedMemberV1 | None
    checkpoint: CharacterLaborCommittedMemberV1
    checkpoint_original_digest: str
    checkpoint_receipt_digest: str
    census_digest: str
    mixed_inventory_digest: str
    body_stage_digest: str
    resource_head_ref: str
    resource_head_revision: int
    correction_ref: str | None
    schema: str = SCHEMA

    def __post_init__(self):
        if (self.schema!=SCHEMA or type(self.namespace)is not NamespaceId
                or type(self.commit_seq)is not int or self.commit_seq<0
                or type(self.write_members)is not tuple or not self.write_members
                or any(type(v)is not CharacterLaborCommittedMemberV1 for v in self.write_members)
                or tuple(v.ref for v in self.write_members)!=tuple(sorted(v.ref for v in self.write_members))
                or len({v.ref for v in self.write_members})!=len(self.write_members)
                or type(self.checkpoint)is not CharacterLaborCommittedMemberV1
                or self.checkpoint.role!="checkpoint"
                or self.body_read is not None and (
                    type(self.body_read)is not CharacterLaborCommittedMemberV1 or self.body_read.role!="body_read")
                or type(self.component_ids)is not tuple or len(set(self.component_ids))!=len(self.component_ids)):
            raise ValueError("exact bodyless labor adoption metadata required")
        if (type(self.invalidated_members)is not tuple
                or any(type(v)is not CharacterLaborCommittedMemberV1 or v.role!="invalidated"for v in self.invalidated_members)
                or tuple(v.ref for v in self.invalidated_members)!=tuple(sorted(v.ref for v in self.invalidated_members))
                or len({v.ref for v in self.invalidated_members})!=len(self.invalidated_members)
                or {v.ref for v in self.invalidated_members}&{v.ref for v in self.write_members}
                or any(v.event_scope!=(*self.namespace.as_tuple,self.activity_id,self.operation_id)for v in self.invalidated_members)):
            raise ValueError("labor invalidation vector is not its actual distinct same-event history")
        invalidated=canonical_json([[v.ref,v.revision]for v in self.invalidated_members]).encode("ascii")
        if (self.invalidated_vector_sha256!=sha256(invalidated).hexdigest()
                or type(self.invalidated_vector_bytes)is not int or self.invalidated_vector_bytes!=len(invalidated)
                or type(self.invalidated_vector_count)is not int or self.invalidated_vector_count!=len(self.invalidated_members)):
            raise ValueError("labor invalidation column SHA/bytes/count differs from its complete actual vector")
        for original in (self.prepared_original,self.prepared_metadata_original,self.basis_original,
                self.segment_original,self.adopted_original):
            if type(original)is not ProductionOriginalRefV1 or original.read_versions:
                raise ValueError("labor metadata retains immutable original locators without current grants")
        for digest in (self.manifest_digest,self.binding_digest,self.authority_segment_digest,
                self.permit_digest,self.bridge_digest,self.bridge_original_digest,
                self.before_anchor_digest,self.after_anchor_digest,self.operation_digest,self.event_digest,
                self.receipt_digest,self.adoption_receipt_digest,self.checkpoint_original_digest,
                self.checkpoint_receipt_digest,self.census_digest,self.mixed_inventory_digest,self.body_stage_digest):
            _digest(digest)
        if self.finish_id!=self.permit_operation_id+":committed" or self.finish_digest!="sha256:"+canonical_digest((self.bridge_digest,"committed")):
            raise ValueError("labor metadata changed its actual permit finish tuple")
        roles={v.role for v in self.write_members}
        required={"chronological_head","job","cost","outcome","segment_start","segment_end",
            "fact_provenance","fact_eligibility","outcome_provenance","outcome_eligibility"}
        if not required<=roles or ("body_state" in roles)!=(self.body_read is None):
            raise ValueError("labor metadata omits an actual required role or unchanged Body")
        if ("correction" in roles)!=(self.correction_ref is not None):
            raise ValueError("labor correction membership differs")
        for member in (*self.write_members,*self.invalidated_members,self.checkpoint,*(()if self.body_read is None else(self.body_read,))):
            if NamespaceId.from_key(AtomKey.from_token(member.ref))!=self.namespace:
                raise ValueError("labor metadata crossed namespace")
        for member in self.write_members:
            if member.event_scope!=(*self.namespace.as_tuple,self.activity_id,self.operation_id):
                raise ValueError("labor write is outside its actual adoption event")
        heads=tuple(v for v in self.write_members if v.role=="chronological_head")
        if len(heads)!=1 or (heads[0].ref,heads[0].revision)!=(self.resource_head_ref,self.resource_head_revision):
            raise ValueError("labor chronological head differs")
        corrections=tuple(v.ref for v in self.write_members if v.role=="correction")
        if corrections!=(()if self.correction_ref is None else(self.correction_ref,)):
            raise ValueError("labor correction locator differs")


def character_labor_adoption_metadata_from_wire_v1(raw):
    value=_closed(raw,CharacterLaborAdoptionMetadataV1)
    value["namespace"]=NamespaceId(**value["namespace"])
    for name in ("prepared_original","prepared_metadata_original","basis_original","segment_original","adopted_original"):
        original=_closed(value[name],ProductionOriginalRefV1)
        original["read_versions"]=tuple(original["read_versions"])
        value[name]=ProductionOriginalRefV1(**original)
    def member(raw):
        item=_closed(raw,CharacterLaborCommittedMemberV1)
        for name in ("cell_header","event_scope","dependencies","component_ids"):
            item[name]=tuple(item[name])
        item["dependencies"]=tuple(tuple(v)for v in item["dependencies"])
        return CharacterLaborCommittedMemberV1(**item)
    value["write_members"]=tuple(member(v)for v in value["write_members"])
    value["invalidated_members"]=tuple(member(v)for v in value["invalidated_members"])
    value["checkpoint"]=member(value["checkpoint"])
    if value["body_read"]is not None:value["body_read"]=member(value["body_read"])
    value["component_ids"]=tuple(value["component_ids"])
    result=CharacterLaborAdoptionMetadataV1(**value)
    if plain_v1(result)!=raw:
        raise ValueError("labor adoption metadata wire is noncanonical")
    return result


def _actual(graph,db,witness,staged,receipt):
    from .d11_life_adoption_v1 import _ACTIVE,_LifeCommitWitnessV1,_bundle
    from .d11_life_terminal_v1 import CharacterLaborTerminalBundleV1
    from .current_character_labor_adoption_v1 import require_character_labor_adoption_after_cas_v1
    store=graph._GraphCoordinator__store
    if (type(witness)is not _LifeCommitWitnessV1 or _ACTIVE.get(id(witness))is not witness
            or witness.graph is not graph or witness.staged is not staged
            or type(staged)is not CharacterLaborTerminalBundleV1
            or witness.bundle!=_bundle(staged) or db is not store._db
            or not store._lock._is_owned() or not db.in_transaction
            or type(receipt)is not CommitReceipt or receipt.status!="committed"):
        raise AuthorityUnavailable("labor metadata requires its actual active same-W01 witness")
    inputs=require_character_labor_adoption_after_cas_v1(staged.adoption_inputs,
        db=db,frame=witness.frame,receipt=receipt)
    handle=runtime_storage_v3(db)
    if handle is None:
        raise AuthorityUnavailable("labor metadata requires its actual physical selected runtime")
    from ..runtime_storage_v3 import _operation
    operation=_operation(handle)
    if operation is not staged.adoption_inputs.operation:
        raise AuthorityUnavailable("labor metadata crossed its retained actual operation")
    return inputs,handle,operation


def _cell_member(db,meter,*,role,ref,revision,value_digest,scope=None,components=(),dependencies=None,byte_count=None):
    row=meter.read_fixed_row(db,"graph_history",
        ("value_cell_id","valid","event_bot","event_persona","event_session","event_id","dependencies"),
        "token=? AND revision=?",(ref,revision))
    if row is None or row[1]!=(0 if role=="invalidated"else 1) or not row[0] or scope is not None and row[2:6]!=scope:
        raise AuthorityUnavailable("labor committed history lacks its exact valid physical event member")
    header=meter.read_fixed_row(db,"segmented_cells_v1",_HEADER,"cell_id=?",(row[0],))
    if header is None or header[2]!=ref or header[6]!=value_digest or byte_count is not None and header[4]!=byte_count:
        raise AuthorityUnavailable("labor committed value differs from its actual physical seal")
    original=read_runtime_cell_origin_v3(db,row[0],header=header[1:],meter=meter)
    if scope is not None and role!="invalidated" and (original is None or original["operation_id"]!=scope[3]
            or original["namespace"]!=list(scope[:2])
            or original["locator"]!={"table":"graph_atoms","token":ref,"revision":revision}):
        raise AuthorityUnavailable("labor fresh cell lost its official same-W01 producer")
    root=canonical_digest(("sylanne3.segmented-cell-genesis.v1",header[0]))
    offset=0
    if header[5]>meter.budget.max_records:
        raise AuthorityUnavailable("labor physical metadata requires its registered segmented continuation")
    for ordinal in range(header[5]):
        # SQLite computes the BLOB length; payload bytes never cross this boundary.
        meter.charge_read(80)
        part=db.execute("SELECT byte_offset,length(payload),payload_sha256 FROM segmented_cell_segments_v1 "
            "WHERE cell_id=? AND ordinal=?",(header[0],ordinal)).fetchone()
        if part is None or part[0]!=offset or type(part[1])is not int or part[1]<1:
            raise AuthorityUnavailable("labor physical segment metadata has an incomplete ordered range")
        _digest(part[2])
        root=canonical_digest(("sylanne3.segmented-cell-link.v1",root,header[0],ordinal,part[0],part[1],part[2]))
        offset+=part[1]
    tail=meter.read_fixed_row(db,"segmented_cell_segments_v1",("ordinal",),
        "cell_id=? AND ordinal>=?",(header[0],header[5]))
    if tail is not None or offset!=header[4] or root!=header[7]:
        raise AuthorityUnavailable("labor physical segment metadata differs from its complete header root")
    actualdeps=json.loads(row[6])
    if type(actualdeps)is not list or canonical_json(actualdeps)!=row[6]:
        raise AuthorityUnavailable("labor historical dependencies are noncanonical")
    refs=tuple(v[0]for v in actualdeps)
    if dependencies is not None and set(refs)!=set(dependencies):
        raise AuthorityUnavailable("labor staged dependencies differ from its real history")
    return CharacterLaborCommittedMemberV1(role,ref,revision,value_digest,tuple(header),tuple(row[2:6]),tuple(tuple(v)for v in actualdeps),tuple(components))


class _CommittedMembersV1:
    def __init__(self,witness,staged,receipt,operation,writes,invalidated,invalidated_commitment,body,checkpoint,event_digest):
        self.witness,self.staged,self.receipt,self.operation=witness,staged,receipt,operation
        self.thread=get_ident()
        self.invalidated_commitment=invalidated_commitment
        self.writes,self.invalidated,self.body,self.checkpoint,self.event_digest=writes,invalidated,body,checkpoint,event_digest

    def _runtime_retained_heap_bytes_v3(self):
        from .current_character_labor_adoption_v1 import _payload_heap_v1
        return _payload_heap_v1((self.writes,self.invalidated,self.body,self.checkpoint,self.event_digest))+1024

    def release_v1(self):
        _MEMBERS.pop(id(self.witness),None)
        self.operation.unregister_retained_state_v3(self)
        self.witness=self.staged=self.receipt=self.operation=None
        self.writes=self.invalidated=();self.body=self.checkpoint=None


def release_character_labor_adoption_metadata_v1(witness):
    proof=_MEMBERS.get(id(witness))
    if proof is not None and proof.witness is witness:proof.release_v1()


def require_character_labor_committed_members_v1(graph,db,*,witness,staged,receipt):
    inputs,handle,operation=_actual(graph,db,witness,staged,receipt)
    prior=_MEMBERS.get(id(witness))
    if prior is not None:
        if (prior.witness is not witness or prior.staged is not staged or prior.receipt!=receipt
                or prior.operation is not operation or prior.thread!=get_ident()):
            raise AuthorityUnavailable("labor committed metadata seal crossed its actual transaction")
        return prior
    from .d11_life_terminal_v1 import life_terminal_stages_v1
    writes=tuple(w for s in life_terminal_stages_v1(staged)for p in s.proposals for w in p.typed_writes)
    versions={v.key.token:v.revision for v in receipt.write_versions}
    if len(versions)!=len(receipt.write_versions) or len(writes)!=len(versions) or {w.key.token for w in writes}!=set(versions):
        raise AuthorityUnavailable("labor committed receipt has another complete write set")
    scope=(*inputs[0].binding.namespace.as_tuple,receipt.activity_id,receipt.operation_id)
    members=[]
    with runtime_storage_quantum_v3(db)as meter:
        event=meter.read_fixed_row(db,"graph_events",("digest","invalidated"),
            "bot=? AND persona=? AND session=? AND event_id=?",scope)
        ledger=meter.read_fixed_row(db,"graph_bundle_operations",("digest","commit_seq"),
            "bot=? AND persona=? AND operation_id=?",(*scope[:2],scope[3]))
        if event is None or ledger!=(receipt.operation_digest,receipt.commit_seq):
            raise AuthorityUnavailable("labor physical members lost the real W01 ledger/event")
        for write in sorted(writes,key=lambda w:w.key.token):
            role=_ROLES.get(write.key.type_name)
            if role is None:
                raise AuthorityUnavailable("unregistered labor terminal write role")
            # This value already passed actual Source/Body qualification and W01.
            # No SQL payload is read. The Graph writer uses precisely this codec.
            payload=canonical_json(write.value).encode("ascii")
            meter.require_available(len(payload)*2+1024)
            meter.charge_encode(len(payload))
            value_digest=sha256(payload).hexdigest()
            components=tuple(write.value["settled_components"])if role=="reservation"else()
            members.append(_cell_member(db,meter,role=role,ref=write.key.token,
                revision=versions[write.key.token],value_digest=value_digest,scope=scope,
                components=components,dependencies=tuple(k.token for k in write.dependencies),byte_count=len(payload)))
        invalidated=[]
        invalidations=json.loads(event[1])
        if type(invalidations)is not list or canonical_json(invalidations)!=event[1]:
            raise AuthorityUnavailable("labor actual invalidation vector is not canonical metadata")
        for ref,revision in sorted(invalidations):
            key=AtomKey.from_token(ref)
            graph._GraphCoordinator__store._registry.spec(key.type_name)
            if NamespaceId.from_key(key)!=inputs[0].binding.namespace:
                raise AuthorityUnavailable("labor invalidation crossed namespace")
            cell=meter.read_fixed_row(db,"graph_history",("value_cell_id",),
                "token=? AND revision=?",(ref,revision))
            header=None if cell is None or not cell[0]else meter.read_fixed_row(
                db,"segmented_cells_v1",_HEADER,"cell_id=?",(cell[0],))
            if header is None:raise AuthorityUnavailable("labor invalidation lacks its actual physical history")
            invalidated.append(_cell_member(db,meter,role="invalidated",ref=ref,revision=revision,
                value_digest=header[6],scope=scope))
        body=None
        r=staged.adoption_inputs._actual_v1()
        if not any(v.role=="body_state"for v in members):
            ref=r.census.body_state.ref
            atom=r.body_atoms[ref]
            payload=canonical_json(atom.value).encode("ascii")
            meter.require_available(len(payload)*2+1024);meter.charge_encode(len(payload))
            body=_cell_member(db,meter,role="body_read",ref=ref,revision=atom.revision,
                value_digest=sha256(payload).hexdigest(),byte_count=len(payload))
        checkpoint=staged.body_result.checkpoint
        key,revision=checkpoint[0]
        # The checkpoint's physical payload hash is already bound to the actual
        # selected history. Its domain digest remains separately authenticated.
        cell=meter.read_fixed_row(db,"graph_history",("value_cell_id",),"token=? AND revision=?",(key,revision))
        header=None if cell is None or not cell[0]else meter.read_fixed_row(
            db,"segmented_cells_v1",_HEADER,"cell_id=?",(cell[0],))
        if header is None:
            raise AuthorityUnavailable("labor actual checkpoint has no selected physical seal")
        checkpoint_member=_cell_member(db,meter,role="checkpoint",ref=key,revision=revision,value_digest=header[6])
    proof=_CommittedMembersV1(witness,staged,receipt,operation,tuple(members),tuple(invalidated),
        (sha256(event[1].encode("ascii")).hexdigest(),len(event[1]),len(invalidations)),body,checkpoint_member,event[0])
    operation.register_retained_state_v3(proof)
    _MEMBERS[id(witness)]=proof
    return proof


def _signed_header(db,meter,*,namespace,kind,ref,operation_id,digest,issuer,sign_kind):
    from .d11_life_preparation_v1 import TABLE
    row=meter.read_fixed_row(db,TABLE,("producing_operation_id","payload_digest","signature"),
        "bot=? AND persona=? AND kind=? AND original_ref=?",(*namespace.as_tuple,kind,ref))
    if row is None or row[:2]!=(operation_id,digest):
        raise AuthorityUnavailable("labor metadata lost an actual immutable signed original")
    issuer._signer.verify(sign_kind,canonical_serialize((namespace,kind,ref,digest)),row[2])


def record_character_labor_adoption_metadata_after_cas_v1(graph,db,*,witness,staged,receipt,
        adopted_original,segment_original,result):
    from .d11_life_preparation_v1 import _record,SIGN_KIND
    from .d11_life_adoption_v1 import life_adoption_receipt_from_wire_v1
    from ..authority_service.d11_life_bridge_v1 import life_bridge_to_wire_v1
    from .d11_character_labor_accounting_v1 import KIND as basis_kind,SIGN_KIND as basis_sign
    from .d11_character_work_segment_v1 import SEGMENT_KIND
    proof=require_character_labor_committed_members_v1(graph,db,witness=witness,staged=staged,receipt=receipt)
    r=staged.adoption_inputs._actual_v1()
    b,gate=r.gate.binding,r.gate
    issuer=graph._GraphCoordinator__d11_issuer
    actual_result=life_adoption_receipt_from_wire_v1(result)
    if (type(adopted_original)is not ProductionOriginalRefV1 or type(segment_original)is not ProductionOriginalRefV1
            or adopted_original.kind!="d11.life_adopted_life" or adopted_original.original_ref!=b.artifact_ref
            or segment_original.kind!="d11.life_"+SEGMENT_KIND or segment_original.original_ref!=r.segment.segment_id
            or segment_original.original_digest!=canonical_digest(plain_v1(r.segment))
            or actual_result.operation_id!=receipt.operation_id or actual_result.binding_digest!=b.digest
            or actual_result.graph_receipt_digest!=canonical_digest(receipt)
            or (actual_result.original_ref,actual_result.original_digest)!=(adopted_original.original_ref,adopted_original.original_digest)
            or actual_result.bridge_digest!=gate.qualification_digest
            or actual_result.terminal_digest!=canonical_digest(plain_v1(gate.terminal))
            or actual_result.status!=gate.terminal.status
            or actual_result.source_refs!=staged.source_refs
            or actual_result.actual_cpu_ms!=gate.terminal.actual_cpu_ms):
        raise AuthorityUnavailable("labor metadata producer changed its actual terminal/segment/receipt originals")
    basis=r.accounting_bases[b.execution_id]
    basis_ref="character-labor-accounting:"+b.execution_id
    basis_digest=canonical_digest(plain_v1(basis))
    prepared_digest=r.metadata.prepared_digest
    prepared_metadata_ref="character-labor-prepared-metadata:"+b.execution_id
    metadata_digest=r.metadata_tasks[("prepared_metadata",prepared_metadata_ref)].metadata[1]
    bridge_digest=canonical_digest(life_bridge_to_wire_v1(gate))
    result_digest=canonical_digest(result)
    with runtime_storage_quantum_v3(db)as meter:
        for kind,ref,op,digest,sign in (
            ("character_labor_prepared_v1",b.prepared_original_ref,b.prepare_operation_id,prepared_digest,SIGN_KIND),
            ("character_labor_prepared_metadata_v1",prepared_metadata_ref,b.prepare_operation_id,metadata_digest,SIGN_KIND),
            (basis_kind,basis_ref,b.prepare_operation_id,basis_digest,basis_sign),
            (SEGMENT_KIND,segment_original.original_ref,receipt.operation_id,segment_original.original_digest,SIGN_KIND),
            ("adopted_life",adopted_original.original_ref,receipt.operation_id,adopted_original.original_digest,SIGN_KIND),
            ("adoption_bridge",b.execution_id,receipt.operation_id,bridge_digest,SIGN_KIND),
            ("adoption_receipt",b.execution_id,receipt.operation_id,result_digest,SIGN_KIND)):
            _signed_header(db,meter,namespace=b.namespace,kind=kind,ref=ref,operation_id=op,digest=digest,issuer=issuer,sign_kind=sign)
        def original(kind,ref,digest):
            return ProductionOriginalRefV1("d11.life_"+kind,ref,digest)
        value=CharacterLaborAdoptionMetadataV1(b.namespace,b.authority_id,b.authority_namespace,b.installation_id,
            b.manifest_digest,b.execution_id,b.effect_id,b.digest,
            original("character_labor_prepared_v1",b.prepared_original_ref,prepared_digest),
            original("character_labor_prepared_metadata_v1",prepared_metadata_ref,metadata_digest),
            original(basis_kind,basis_ref,basis_digest),segment_original,canonical_digest(plain_v1(r.segment)),
            tuple(r.segment.component_ids),canonical_digest(gate.permit),gate.permit.operation_id,
            gate.qualification_digest,bridge_digest,canonical_digest(gate.before_anchor),canonical_digest(gate.after_anchor),
            gate.permit.operation_id+":committed","sha256:"+canonical_digest((gate.qualification_digest,"committed")),
            receipt.operation_id,receipt.activity_id,receipt.operation_digest,receipt.commit_seq,proof.event_digest,
            canonical_digest(receipt),result_digest,adopted_original,proof.writes,proof.invalidated,*proof.invalidated_commitment,proof.body,proof.checkpoint,
            staged.body_result.checkpoint[1][2],canonical_digest(staged.body_result.checkpoint[1][1]),
            canonical_digest(r.census),r.census.mixed_inventory_digest,staged.body_stage.original_digest,
            next(v.ref for v in proof.writes if v.role=="chronological_head"),staged.body_result.head.revision,
            next((v.ref for v in proof.writes if v.role=="correction"),None))
        raw=plain_v1(value)
        character_labor_adoption_metadata_from_wire_v1(raw)
        return _record(db,issuer=issuer,namespace=b.namespace,kind=KIND,
            ref=character_labor_adoption_metadata_ref_v1(b.prepared_original_ref),operation_id=receipt.operation_id,value=raw)


def read_character_labor_adoption_metadata_v1(db,*,namespace,prepared_original_ref,issuer):
    """Authenticate only this closed metadata value under the actual runtime.

    This does not issue a cold-finish capability. The installed ACK Work must
    independently join receipt, event and historical physical members.
    """
    from .d11_life_preparation_v1 import TABLE,SIGN_KIND
    from ..runtime_storage_v3 import _operation
    handle=runtime_storage_v3(db)
    if handle is None:
        raise AuthorityUnavailable("labor metadata needs an actual selected runtime operation")
    _operation(handle)
    ref=character_labor_adoption_metadata_ref_v1(prepared_original_ref)
    with runtime_storage_quantum_v3(db)as meter:
        row=meter.read_fixed_row(db,TABLE,("producing_operation_id","payload_json","payload_digest","signature"),
            "bot=? AND persona=? AND kind=? AND original_ref=?",(*namespace.as_tuple,KIND,ref))
        if row is None:return None
        raw=json.loads(row[1])
        if canonical_serialize(raw)!=row[1]or canonical_digest(raw)!=row[2]:
            raise AuthorityUnavailable("labor adoption metadata canonical EOF digest differs")
        issuer._signer.verify(SIGN_KIND,canonical_serialize((namespace,KIND,ref,row[2])),row[3])
        value=character_labor_adoption_metadata_from_wire_v1(raw)
        if value.namespace!=namespace or value.prepared_original.original_ref!=prepared_original_ref or value.operation_id!=row[0]:
            raise AuthorityUnavailable("labor metadata immutable identity differs")
        return value,ProductionOriginalRefV1("d11.life_"+KIND,ref,row[2])


# A cold ACK owns only installed Root metadata. It never creates a new gate,
# materializes Prepared, or recalculates a Body settlement.
COLD_ACK_KIND = "current_character_labor_cold_ack_v1"
_COLD_KEY = object()
_COLD_READERS = {}
_COLD_RESULTS = {}
_COLD_ACKNOWLEDGED_V1 = WeakKeyDictionary()
_HISTORY = ("token","revision","value_cell_id","valid","dependencies",
    "event_bot","event_persona","event_session","event_id")


class NoCommittedLaborAdoptionV1:
    def __init__(self,key,reader):
        if key is not _COLD_KEY:raise TypeError("actual completed metadata absence required")
        self.reader=reader
        _COLD_RESULTS[self]=(reader,reader.identity)

    def release_payload_v3(self):
        self.reader.release_payload_v3()


class PreparedCharacterLaborColdAckV1:
    def __init__(self,key,reader):
        if key is not _COLD_KEY:raise TypeError("actual complete cold metadata Work required")
        self.reader=reader
        _COLD_RESULTS[self]=(reader,reader.identity)

    def finish_v1(self,graph,work):
        r=_require_cold_result_v1(self,graph,work)
        # The RPC independently checks its own invocation, exact original gate,
        # same finished tuple or still-current original fence and current Owner.
        from ..host.d11_life_port_v1 import InstalledD11LifePortV1
        port=InstalledD11LifePortV1(graph._GraphCoordinator__content_fence_v2)
        port.life_adoption_bridge_v1(binding=r.gate.binding,action="finish",gate=r.gate,outcome="committed")
        _COLD_ACKNOWLEDGED_V1[self]=(r,r.identity,work,r.header[1],r.metadata.bridge_original_digest,
            r.metadata.adoption_receipt_digest,r.metadata.receipt_digest)
        return dict(r.adoption_result)

    def release_payload_v3(self):
        self.reader.release_payload_v3()


def require_character_labor_cold_execution_originals_v1(result,graph,work):
    """Actual signed originals become adopted execution facts only after ACK."""
    if type(result)is not PreparedCharacterLaborColdAckV1:
        raise AuthorityUnavailable("actual positive cold labor result required")
    r=_require_cold_result_v1(result,graph,work)
    if _COLD_ACKNOWLEDGED_V1.get(result)!=(r,r.identity,work,r.header[1],
            r.metadata.bridge_original_digest,r.metadata.adoption_receipt_digest,r.metadata.receipt_digest):
        raise AuthorityUnavailable("cold execution originals require the successful original strict finish ACK")
    gate=r.gate
    return gate.binding,gate.prepared_digest,gate.terminal.claim,gate.terminal


def require_no_committed_character_labor_adoption_v1(result,graph,work):
    if type(result)is not NoCommittedLaborAdoptionV1:
        raise AuthorityUnavailable("actual complete cold metadata absence marker required")
    _require_cold_result_v1(result,graph,work)
    return result


def _require_cold_result_v1(result,graph,work):
    r=result.reader
    if (_COLD_RESULTS.get(result)!=(r,r.identity)or r.graph is not graph or r.work is not work
            or not r.complete or r.result is not result or r.db.in_transaction or r.store._lock._is_owned()):
        raise AuthorityUnavailable("cold labor result is not this retained actual metadata Work")
    from ..runtime_storage_v3 import bind_runtime_storage_operation_v3
    with bind_runtime_storage_operation_v3(r.operation,r.db):
        with r.store._lock:
            r.db.execute("BEGIN")
            try:
                with runtime_storage_quantum_v3(r.db)as meter:
                    r.require_v1(meter)
                    header=r._row(meter,"graph_d11_life_originals_v1",
                        ("producing_operation_id","payload_digest","signature"),
                        "bot=? AND persona=? AND kind=? AND original_ref=?",
                        (*r.namespace.as_tuple,KIND,r.prepared_ref))
                    if header!=r.header:raise AuthorityUnavailable("cold labor original header changed")
                    if type(result)is PreparedCharacterLaborColdAckV1:
                        from ..authority_service.d11_life_bridge_v1 import life_bridge_to_wire_v1
                        m=r.metadata
                        if (canonical_digest(plain_v1(m))!=header[1]
                                or canonical_digest(life_bridge_to_wire_v1(r.gate))!=m.bridge_original_digest
                                or canonical_digest(r.adoption_result)!=m.adoption_receipt_digest
                                or canonical_digest(r.receipt)!=m.receipt_digest):
                            raise AuthorityUnavailable("cold labor retained signed metadata commitments changed")
            finally:r.db.rollback()
    return r


class CharacterLaborHistoricalMembersPlanV1:
    """A pure request plan, never an Owner, Source, or finish capability.

    Each driver independently authenticates selection_basis and executes only
    these fixed metadata requests under its own actual Work/session and meter.
    No input tuple, computed result, or this object's type grants permission.
    """
    def __init__(self,*,namespace,members,selection_basis,current_incarnation):
        if (type(namespace)is not NamespaceId or type(members)is not tuple
                or any(type(v)is not CharacterLaborCommittedMemberV1
                    or NamespaceId.from_key(AtomKey.from_token(v.ref))!=namespace for v in members)
                or selection_basis is not None and (type(selection_basis)is not tuple or len(selection_basis)!=5)):
            raise TypeError("closed historical metadata plan values required")
        self.namespace,self.members=namespace,members
        self.selection_basis,self.current_incarnation=selection_basis,current_incarnation
        self.certificates={};self.verified_streams={};self.verified_members={}
        self.basis_identity=None;self.generator=None

    def _basis_v1(self):
        if self.selection_basis is None:
            raise AuthorityUnavailable("history relocation has no authenticated selection basis")
        return self.selection_basis

    def requests_v1(self):
        if self.generator is not None:raise ValueError("historical metadata plan already started")
        self.generator=self._requests_v1()
        return self.generator

    def _requests_v1(self):
        for member in self.members:
            if (member.ref,member.revision)not in self.verified_members:
                yield from self._history_v1(member)
        return dict(self.verified_members)

    def retained_payload_v1(self):
        def frames(generator):
            if generator is None or not hasattr(generator,"gi_frame"):return ()
            local=()if generator.gi_frame is None else tuple(v for k,v in generator.gi_frame.f_locals.items()if k!="self")
            return local,frames(generator.gi_yieldfrom)
        return self.members,self.certificates,self.verified_streams,self.verified_members,frames(self.generator)

    def release_v1(self):
        if self.generator is not None:self.generator.close()
        self.generator=None;self.members=()
        self.certificates.clear();self.verified_streams.clear();self.verified_members.clear()

    def _certificate_v1(self,digest):
        from .c09_paged_capture_contract_v2 import GraphErasureRebaseCertificateV2,c09_paged_value_from_wire_v2
        if digest in self.certificates:return self.certificates[digest]
        after="";found=None
        while True:
            row=yield ("row","graph_c09_rebase_certificates_v2",("operation_id",),
                "bot=? AND persona=? AND operation_id>? ORDER BY operation_id",(*self.namespace.as_tuple,after))
            if row is None:break
            after=row[0]
            raw,_=yield ("column","graph_c09_rebase_certificates_v2","certificate_json",
                ("bot","persona","operation_id"),(*self.namespace.as_tuple,after))
            value=c09_paged_value_from_wire_v2(raw,GraphErasureRebaseCertificateV2)
            if value.candidate.scope.operation_id!=after:
                raise AuthorityUnavailable("cold history certificate mirror operation differs")
            if value.certificate_digest==digest:
                if found is not None:raise AuthorityUnavailable("cold history certificate digest is ambiguous")
                found=value
        if found is None or found.candidate.scope.graph_namespace!=canonical_serialize(self.namespace.as_tuple):
            raise AuthorityUnavailable("cold history actual namespace certificate mirror is absent")
        self.certificates[digest]=found
        return found

    def _stream_v1(self,locator):
        from .c09_paged_capture_contract_v2 import (
            C09CompleteStreamV2,c09_paged_value_from_wire_v2,begin_c09_stream_v2,verify_c09_page_v2)
        identity,seal=locator.identity,locator.complete
        if identity.stream_id in self.verified_streams:
            if self.verified_streams[identity.stream_id]!=locator:
                raise AuthorityUnavailable("cold history signed stream identity changed")
            return
        saved=yield ("row","c09_capture_streams_v2",("status","seal_json"),"stream_id=?",(identity.stream_id,))
        if saved is None or saved[0]!="sealed"or c09_paged_value_from_wire_v2(json.loads(saved[1]),C09CompleteStreamV2)!=seal:
            raise AuthorityUnavailable("cold history directory has no actual complete seal")
        cursor=begin_c09_stream_v2(identity)
        while cursor.page_index<seal.page_count:
            page,records=yield ("page",identity,cursor.page_index)
            cursor=verify_c09_page_v2(identity,cursor,page,records)
        if (cursor.record_offset,cursor.encoded_bytes,cursor.page_index,cursor.record_chain,cursor.previous_page_digest)!=(
                seal.record_count,seal.encoded_bytes,seal.page_count,seal.record_root,seal.page_root):
            raise AuthorityUnavailable("cold history page EOF does not reach its signed root")
        extra=yield ("row","c09_capture_pages_v2",("page_index",),"stream_id=? AND page_index>=?",(identity.stream_id,seal.page_count))
        if extra is not None:raise AuthorityUnavailable("cold history stream has unsealed extra pages")
        extra=yield ("row","c09_capture_members_v2",("record_ordinal",),"stream_id=? AND record_ordinal>?",(identity.stream_id,seal.record_count))
        if extra is not None:raise AuthorityUnavailable("cold history stream has unsealed extra members")
        self.verified_streams[identity.stream_id]=locator

    def _family_v1(self,certificate):
        from .c09_paged_capture_contract_v2 import (
            C09StreamIdentityV2,C09CompleteStreamV2,C09SealedStreamLocatorV2,c09_paged_value_from_wire_v2)
        outer=certificate.candidate.disposition_directory
        if outer.identity.family!="c09_graph_disposition_directory_v2":
            raise AuthorityUnavailable("cold history certificate has another directory type")
        yield from self._stream_v1(outer)
        row=yield ("row",outer.identity.family,("scope_digest","family","identity_json","complete_json"),
            "scope_digest=? AND family=?",(certificate.candidate.scope.scope_digest,"graph_history"))
        if row is None:raise AuthorityUnavailable("cold history signed history family is absent")
        yield ("member",outer,(row[0],row[1]),row)
        identity=c09_paged_value_from_wire_v2(json.loads(row[2]),C09StreamIdentityV2)
        complete=c09_paged_value_from_wire_v2(json.loads(row[3]),C09CompleteStreamV2)
        if (identity.scope_digest!=row[0]or identity.family!="graph_history"or identity.stream_kind!="row_dispositions"
                or identity.role_source_digest!=certificate.candidate.source.role_source_digest):
            raise AuthorityUnavailable("cold history family escaped its actual signed Source")
        locator=C09SealedStreamLocatorV2("graph",identity,complete)
        yield from self._stream_v1(locator)
        return locator

    def _history_v1(self,member):
        key=(member.ref,member.revision)
        actual=yield ("row","graph_history",_HISTORY,"token=? AND revision=?",key)
        if actual is None or actual[:2]!=key or actual[3]!=(0 if member.role=="invalidated"else 1) or tuple(actual[5:])!=member.event_scope:
            raise AuthorityUnavailable("cold labor historical GraphVersion/event is absent or invalid")
        if actual[4]!=canonical_serialize(member.dependencies):
            raise AuthorityUnavailable("cold labor historical dependency versions changed")
        header=yield ("row","segmented_cells_v1",_HEADER,"cell_id=?",(actual[2],))
        if header is None or (header[1],header[2],header[4],header[6])!=(
                member.cell_header[1],member.ref,member.cell_header[4],member.value_digest):
            raise AuthorityUnavailable("cold labor historical canonical value commitment changed")
        original=yield ("origin",header)
        if header==member.cell_header:
            if member.role!="invalidated" and original is not None and original["operation_id"]!=member.event_scope[3]:
                raise AuthorityUnavailable("cold labor unchanged historical producer differs")
        else:
            yield from self._relocation_v1(member,tuple(actual),tuple(header))
        root=canonical_digest(("sylanne3.segmented-cell-genesis.v1",header[0]))
        offset=0
        for ordinal in range(header[5]):
            segment=yield ("segment",(header[0],ordinal))
            if segment is None or segment[0]!=offset or type(segment[1])is not int or segment[1]<1:
                raise AuthorityUnavailable("cold labor physical metadata range is incomplete")
            _digest(segment[2])
            root=canonical_digest(("sylanne3.segmented-cell-link.v1",root,header[0],ordinal,*segment))
            offset+=segment[1]
        tail=yield ("row","segmented_cell_segments_v1",("ordinal",),"cell_id=? AND ordinal>=?",(header[0],header[5]))
        if tail is not None or offset!=header[4]or root!=header[7]:
            raise AuthorityUnavailable("cold labor physical metadata EOF differs from its seal")
        self.verified_members[key]=(tuple(actual),tuple(header))

    def _relocation_v1(self,member,actual,header):
        from .c09_paged_capture_contract_v2 import (
            C09StreamIdentityV2,C09CompleteStreamV2,C09SealedStreamLocatorV2,c09_paged_value_from_wire_v2)
        from .c09_graph_rebase_candidate_v2 import _graph_logical_preservation_original_v3
        identity=self._basis_v1()
        if self.basis_identity is not None and self.basis_identity!=identity:
            raise AuthorityUnavailable("cold labor selected certificate changed")
        self.basis_identity=identity
        digest,scope_digest,authority,authority_namespace,installation=identity
        if digest is None:raise AuthorityUnavailable("cold labor physical change lacks a current certificate")
        certificate=yield from self._certificate_v1(digest)
        scope=certificate.candidate.scope
        if ((scope.scope_digest,scope.authority_id,scope.authority_namespace,scope.installation_id)!=(
                scope_digest,authority,authority_namespace,installation)
                or certificate.candidate.new_incarnation!=self.current_incarnation):
            raise AuthorityUnavailable("cold labor certificate differs from the installed current Graph")
        physical=canonical_digest(actual)
        seen=set();key=(member.ref,member.revision)
        while header!=member.cell_header:
            if certificate.certificate_digest in seen:
                raise AuthorityUnavailable("cold labor prior certificate chain is cyclic")
            seen.add(certificate.certificate_digest)
            family=yield from self._family_v1(certificate)
            proof=yield ("disposition",certificate.candidate.scope.scope_digest,key)
            if proof is None or proof[:3]!=(certificate.candidate.scope.scope_digest,"graph_history",
                    canonical_digest(("graph_history",key))):
                raise AuthorityUnavailable("cold labor migration lacks the exact history-PK disposition")
            yield ("member",family,key,proof)
            if proof[5]=="preserved_exact":
                if proof[4]!=proof[6]or proof[6]!=physical:
                    raise AuthorityUnavailable("cold labor preserved_exact history physical commitment differs")
            elif len(proof)==13 and proof[5]=="logical_preserved_v3":
                source=yield ("row","c09_capture_streams_v2",("identity_json","status","seal_json"),"stream_id=?",(proof[7],))
                if source is None or source[1]!="sealed":
                    raise AuthorityUnavailable("cold labor actual Source stream is absent")
                stream=c09_paged_value_from_wire_v2(json.loads(source[0]),C09StreamIdentityV2)
                complete=c09_paged_value_from_wire_v2(json.loads(source[2]),C09CompleteStreamV2)
                if (stream.scope_digest!=certificate.candidate.scope.scope_digest
                        or stream.role_source_digest!=certificate.candidate.source.role_source_digest
                        or stream.stream_kind!="graph_facts"or stream.family!="graph_history"
                        or complete.record_count!=family.complete.record_count):
                    raise AuthorityUnavailable("cold labor Source stream escaped signed history scope")
                yield from self._stream_v1(C09SealedStreamLocatorV2("graph",stream,complete))
                descriptor=yield ("descriptor",stream,key,proof[8])
                if (descriptor["source_role_digest"]!=certificate.candidate.source.role_source_digest
                        or descriptor["logical_shape_digest"]!=stream.schema_digest
                        or canonical_digest(descriptor)!=proof[4]
                        or header[3]!=certificate.candidate.scope.operation_id
                        or header[8]!=certificate.candidate.scope.scope_digest):
                    raise AuthorityUnavailable("cold labor actual Source descriptor/target capture identity differs")
                raw=json.loads(proof[12])
                if type(raw)is not dict or set(raw)!={"target_cell_seal","logical_equivalence_original"}:
                    raise AuthorityUnavailable("cold labor history logical original grammar differs")
                source_header=tuple(raw["logical_equivalence_original"]["source_cell_header"])
                expected=_graph_logical_preservation_original_v3(certificate.candidate.scope.scope_digest,
                    "graph_history",key,descriptor,source_header,header,physical)
                if proof[9:]!=expected or proof[4]!=expected[0]or proof[6]!=physical:
                    raise AuthorityUnavailable("cold labor history Source/target equivalence differs")
                header=source_header;physical=descriptor["physical_row_commitment"]
            else:raise AuthorityUnavailable("cold labor history was erased, rebuilt, derived or is unknown")
            if header==member.cell_header:break
            prior=certificate.prior_certificate_digest_or_none
            if prior is None or certificate.prior_certificate_schema_or_none!="sylanne3.graph.c09_erasure_rebase.v2":
                raise AuthorityUnavailable("cold labor history lacks its actual prior certificate chain")
            previous=yield from self._certificate_v1(prior)
            previous_scope=previous.candidate.scope
            if ((previous_scope.authority_id,previous_scope.authority_namespace,previous_scope.installation_id)!=(
                    authority,authority_namespace,installation)
                    or previous.candidate.new_incarnation!=certificate.candidate.old_incarnation
                    or previous_scope.maintenance_generation>=certificate.candidate.scope.maintenance_generation):
                raise AuthorityUnavailable("cold labor history prior certificate is not its actual predecessor")
            certificate=previous



class _CharacterLaborAdoptionMetadataEngineV1:
    def _row(self,meter,table,columns,where,key):
        return meter.read_fixed_row(self.db,table,columns,where,key)


    def advance_v1(self,meter):
        self.require_v1(meter)
        if self.complete:return True
        if self.pending is None:
            try:self.pending=next(self.generator)
            except StopIteration:
                self._finish_v1();return True
        request=self.pending
        if request[0]=="column":
            from .current_character_labor_adoption_v1 import _LocatorMetadataColumnV1
            _,table,column,keys,key=request
            name=(table,column,keys,key)
            c=self.columns.get(name)
            if c is None:
                c=_LocatorMetadataColumnV1(self,table,column,keys,key)
                self.columns[name]=c
            if not c.advance(meter):
                self.operation.refresh_retained_state_v3(self);return False
            value=(c.value,c.digest)
        elif request[0]=="row":
            _,table,columns,where,key=request
            value=self._row(meter,table,columns,where,key)
        elif request[0]=="page":
            from .c09_paged_sql_v2 import read_capture_page_v2
            value=read_capture_page_v2(self.db,request[1],request[2])
        elif request[0]=="member":
            from .c09_historical_proof_row_codec_v2 import _require_exact_structural_member
            _require_exact_structural_member(self.db,request[1],request[2],request[3],meter)
            value=True
        elif request[0]=="descriptor":
            from .c09_paged_sql_v2 import require_c09_logical_source_row_member_v3
            value=require_c09_logical_source_row_member_v3(self.db,request[1],
                role="graph",table_name="graph_history",key=request[2],record_ordinal=request[3],meter=meter)
        elif request[0]=="disposition":
            from .c09_graph_rebase_candidate_v2 import _read_graph_disposition_original_row_v3
            value=_read_graph_disposition_original_row_v3(self.db,request[1],"graph_history",request[2],meter)
        elif request[0]=="origin":
            value=read_runtime_cell_origin_v3(self.db,request[1][0],header=request[1][1:],meter=meter)
        elif request[0]=="segment":
            meter.charge_read(80)
            value=self.db.execute("SELECT byte_offset,length(payload),payload_sha256 FROM segmented_cell_segments_v1 "
                "WHERE cell_id=? AND ordinal=?",request[1]).fetchone()
        else:raise AuthorityUnavailable("unregistered cold labor metadata continuation")
        from .current_character_labor_adoption_v1 import _payload_heap_v1
        self.operation.reserve_retained_state_growth_v3(self,_payload_heap_v1(value)*3+65536)
        try:
            try:self.pending=self.generator.send(value)
            except StopIteration:self.pending=None;self._finish_v1()
        finally:self.operation.finish_retained_state_growth_v3(self)
        return self.complete


    def _signed_v1(self,kind,ref,expected_digest,operation_id):
        from .d11_life_preparation_v1 import TABLE,SIGN_KIND
        header=yield ("row",TABLE,("producing_operation_id","payload_digest","signature"),
            "bot=? AND persona=? AND kind=? AND original_ref=?",(*self.namespace.as_tuple,kind,ref))
        if header is None or header[:2]!=(operation_id,expected_digest):
            raise AuthorityUnavailable("cold labor signed original identity/digest differs")
        value,digest=yield ("column",TABLE,"payload_json",("bot","persona","kind","original_ref"),
            (*self.namespace.as_tuple,kind,ref))
        if digest!=header[1]:raise AuthorityUnavailable("cold labor signed original canonical EOF differs")
        self.issuer._signer.verify(
            SIGN_KIND,canonical_serialize((self.namespace,kind,ref,digest)),header[2])
        return value


    def _basis_v1(self):
        handle=runtime_storage_v3(self.db)
        if handle.host_binding is not None:
            from ..host.c09_storage_admission_v1 import VerifiedHostGraphStorageBindingV4
            binding=handle.host_binding
            if type(binding)is not VerifiedHostGraphStorageBindingV4:
                raise AuthorityUnavailable("cold history needs its actual verified Host storage binding")
            binding.require_business_v4()
            return (binding.certificate_digest,binding.capture_scope_digest,binding.authority_id,
                binding.authority_namespace,binding.installation_id)
        if handle.selected is None:return None
        basis=handle.selected.basis
        return (basis.manifest["certificate_digest"],basis.prepared["capture_scope_digest"],
            basis.control.authority_id,basis.prepared["namespace"],basis.control.installation_id)


    def _run_v1(self):
        from .d11_life_preparation_v1 import TABLE,SIGN_KIND
        from .issuers import _decode_grant
        if self.host_root_required:
            grant=self.bundle.installation_policy.root_grant
            self.grant_header=yield ("row","runtime_budget_grants",("version","status","signature"),
                "lease_id=? ORDER BY version DESC",(grant.lease_id,))
            if self.grant_header is None or self.grant_header[:2]!=(grant.version,"active"):
                raise AuthorityUnavailable("cold labor needs its actual current signed Root resource grant")
            raw,digest=yield ("column","runtime_budget_grants","grant_json",("lease_id","version"),(grant.lease_id,grant.version))
            actual=_decode_grant(canonical_serialize(raw))
            self.issuer._signer.verify("budget-grant.v1",canonical_serialize(raw),self.grant_header[2])
            if actual!=grant or (grant.bot_id,grant.persona_id)!=self.namespace.as_tuple:
                raise AuthorityUnavailable("cold labor current Root resource grant differs from installation")
        self.header=yield ("row",TABLE,("producing_operation_id","payload_digest","signature"),
            "bot=? AND persona=? AND kind=? AND original_ref=?",(*self.namespace.as_tuple,KIND,self.prepared_ref))
        if self.header is None:return
        raw,digest=yield ("column",TABLE,"payload_json",("bot","persona","kind","original_ref"),
            (*self.namespace.as_tuple,KIND,self.prepared_ref))
        if digest!=self.header[1]:raise AuthorityUnavailable("cold labor metadata canonical EOF differs")
        self.issuer._signer.verify(
            SIGN_KIND,canonical_serialize((self.namespace,KIND,self.prepared_ref,digest)),self.header[2])
        self.metadata=character_labor_adoption_metadata_from_wire_v1(raw)
        m=self.metadata
        if (m.namespace!=self.namespace or m.operation_id!=self.header[0]
                or m.prepared_original.original_ref!=self.prepared_ref):
            raise AuthorityUnavailable("cold labor metadata belongs to another actual operation/namespace")
        if self.host_root_required:
            p=self.bundle.installation_policy
            if (m.authority_id,m.authority_namespace,m.installation_id,m.manifest_digest)!=(
                    p.expected_authority_id,p.authority_namespace,p.installation_id,p.manifest_digest):
                raise AuthorityUnavailable("cold labor metadata belongs to another installed Host")
        elif (m.binding_digest,m.permit_digest,m.bridge_digest)!=(
                self.expected_gate.binding.digest,canonical_digest(self.expected_gate.permit),self.expected_gate.qualification_digest):
            raise AuthorityUnavailable("Authority ACK metadata is not its actual original gate")
        bridge=yield from self._signed_v1("adoption_bridge",m.execution_id,m.bridge_original_digest,m.operation_id)
        from ..authority_service.d11_life_bridge_v1 import life_bridge_from_wire_v1
        self.gate=life_bridge_from_wire_v1(bridge)
        if not self.host_root_required and self.gate!=self.expected_gate:
            raise AuthorityUnavailable("Authority ACK signed bridge differs from its actual original gate")
        self.adoption_result=yield from self._signed_v1("adoption_receipt",m.execution_id,m.adoption_receipt_digest,m.operation_id)
        self._join_identity_v1()
        adopted=None
        if not self.host_root_required:
            adopted=yield from self._signed_v1("adopted_life",m.adopted_original.original_ref,m.adopted_original.original_digest,m.operation_id)
            segment=yield from self._signed_v1("character_work_segment_v1",m.segment_original.original_ref,m.segment_original.original_digest,m.operation_id)
            from .d11_character_work_segment_v1 import character_work_segment_from_wire_v1
            self._join_v1(adopted,character_work_segment_from_wire_v1(segment))
        event_key=(*self.namespace.as_tuple,m.activity_id,m.operation_id)
        ledger=yield ("row","graph_bundle_operations",("digest","activity_id","effect_id","commit_seq"),
            "bot=? AND persona=? AND operation_id=?",(*self.namespace.as_tuple,m.operation_id))
        event=yield ("row","graph_events",("digest","epoch_revision"),
            "bot=? AND persona=? AND session=? AND event_id=?",event_key)
        if ledger!=(m.operation_digest,m.activity_id,m.effect_id,m.commit_seq)or event is None or event[0]!=m.event_digest:
            raise AuthorityUnavailable("cold labor actual W01 ledger/event identity differs")
        values={};column_digests={};column_sizes={}
        for column,table,keys,key in (
                ("receipt_json","graph_bundle_operations",("bot","persona","operation_id"),(*self.namespace.as_tuple,m.operation_id)),
                ("reads","graph_events",("bot","persona","session","event_id"),event_key),
                ("revisions","graph_events",("bot","persona","session","event_id"),event_key),
                ("invalidated","graph_events",("bot","persona","session","event_id"),event_key)):
            values[column],column_digests[column]=yield ("column",table,column,keys,key)
            column_sizes[column]=self.columns[(table,column,keys,key)].total
        from ..graph_types import GraphVersion,NamespaceEpoch
        self.receipt=CommitReceipt("committed",m.operation_id,*ledger,
            tuple(GraphVersion(AtomKey.from_token(k),v)for k,v in values["reads"]),
            tuple(GraphVersion(AtomKey.from_token(k),v)for k,v in values["revisions"]),
            (NamespaceEpoch(*self.namespace.as_tuple,event[1]),),
            tuple(values["receipt_json"]["ledger_refs"]),tuple(values["receipt_json"]["outbox_refs"]))
        if (canonical_digest(self.receipt)!=m.receipt_digest
                or not self.host_root_required and adopted["graph_receipt_json"]!=canonical_serialize(plain_v1(self.receipt))
                or sorted(values["invalidated"])!=sorted([v.ref,v.revision]for v in m.invalidated_members)
                or (column_digests["invalidated"],column_sizes["invalidated"],len(values["invalidated"]))!=(
                    m.invalidated_vector_sha256,m.invalidated_vector_bytes,m.invalidated_vector_count)
                or {(v.key.token,v.revision)for v in self.receipt.write_versions}!={(v.ref,v.revision)for v in m.write_members}):
            raise AuthorityUnavailable("cold labor complete actual receipt/write membership differs")
        fence=yield ("row","graph_bundle_fences_v2",("permit_json","pre_graph_revision","pre_graph_epoch",
            "post_graph_revision","post_graph_epoch","finish_request_id","finish_request_digest"),
            "bot=? AND persona=? AND operation_id=?",(*self.namespace.as_tuple,m.operation_id))
        from ..authority_service.v2_contract import to_wire
        gate=self.gate
        if fence!=(canonical_serialize(to_wire(gate.permit)),gate.before_graph_revision,gate.before_graph_epoch,
                gate.before_graph_revision+1,gate.before_graph_epoch+1,m.finish_id,m.finish_digest):
            raise AuthorityUnavailable("cold labor actual fence/finish tuple differs")
        if not self.host_root_required:
            self.history_plan=CharacterLaborHistoricalMembersPlanV1(namespace=self.namespace,
                members=(*m.write_members,*m.invalidated_members,m.checkpoint,*(()if m.body_read is None else(m.body_read,))),
                selection_basis=self._basis_v1(),current_incarnation=runtime_storage_v3(self.db).member["incarnation_or_journal_id"])
            yield from self.history_plan.requests_v1()
            self.verified_members=self.history_plan.verified_members


    def _join_identity_v1(self):
        m=self.metadata;gate=self.gate;b=gate.binding
        from .d11_life_adoption_v1 import life_adoption_receipt_from_wire_v1
        from .d11_life_contract_v1 import life_adoption_operation_id_v1
        result=life_adoption_receipt_from_wire_v1(self.adoption_result)
        if ((b.namespace,b.authority_id,b.authority_namespace,b.installation_id,b.manifest_digest,b.execution_id,b.effect_id,
                b.digest,b.prepared_original_ref,gate.prepared_digest,life_adoption_operation_id_v1(b))!=(
                m.namespace,m.authority_id,m.authority_namespace,m.installation_id,m.manifest_digest,m.execution_id,m.effect_id,
                m.binding_digest,m.prepared_original.original_ref,m.prepared_original.original_digest,m.operation_id)
                or canonical_digest(gate.permit)!=m.permit_digest or gate.permit.operation_id!=m.permit_operation_id
                or gate.qualification_digest!=m.bridge_digest or canonical_digest(gate.before_anchor)!=m.before_anchor_digest
                or canonical_digest(gate.after_anchor)!=m.after_anchor_digest
                or result.original_digest!=m.adopted_original.original_digest
                or result.original_ref!=m.adopted_original.original_ref or result.operation_id!=m.operation_id
                or result.graph_receipt_digest!=m.receipt_digest or result.binding_digest!=m.binding_digest
                or result.bridge_digest!=m.bridge_digest or result.terminal_digest!=canonical_digest(plain_v1(gate.terminal))
                or result.status!=gate.terminal.status or result.actual_cpu_ms!=gate.terminal.actual_cpu_ms):
            raise AuthorityUnavailable("cold labor signed metadata/bridge/result identity differs")

    def _join_v1(self,adopted,segment):
        self._join_identity_v1()
        m=self.metadata;gate=self.gate
        from .d11_life_adoption_v1 import life_adoption_receipt_from_wire_v1
        from .d11_life_contract_v1 import life_from_wire_v1,D11LifeTerminalV1
        result=life_adoption_receipt_from_wire_v1(self.adoption_result)
        if (canonical_digest(plain_v1(segment))!=m.authority_segment_digest
                or (segment.segment_id,segment.binding_digest,segment.component_ids)!=(
                    m.segment_original.original_ref,m.binding_digest,m.component_ids)):
            raise AuthorityUnavailable("cold labor actual signed segment differs from adoption metadata")
        expected={"schema","namespace","result_ref","producing_operation_id","job_result_binding",
            "prepared_digest","terminal","source_refs","graph_receipt_json","write_commitments"}
        if (type(adopted)is not dict or set(adopted)!=expected or adopted["schema"]!="d11.adopted-life-original.v4"
                or adopted["namespace"]!=plain_v1(m.namespace)or adopted["result_ref"]!=m.adopted_original.original_ref
                or adopted["producing_operation_id"]!=m.operation_id or adopted["prepared_digest"]!=m.prepared_original.original_digest
                or life_from_wire_v1(adopted["terminal"],D11LifeTerminalV1)!=gate.terminal
                or tuple(adopted["source_refs"])!=result.source_refs
                or sorted(adopted["write_commitments"],key=lambda v:v["ref"])!=[
                    {"ref":v.ref,"revision":v.revision,"digest":v.value_digest}for v in m.write_members]):
            raise AuthorityUnavailable("cold labor adopted-v4 bodyless original differs from signed members")



class CharacterLaborColdAckReadV1(_CharacterLaborAdoptionMetadataEngineV1):
    def __init__(self,key,graph,bootstrap,namespace,prepared_ref,bundle,operation,clock,stamp):
        if key is not _COLD_KEY:raise TypeError("actual installed cold metadata factory required")
        import time
        from .first_ingress_v2 import trusted_upper
        self.graph,self.bootstrap,self.namespace,self.prepared_ref=graph,bootstrap,namespace,prepared_ref
        self.issuer=graph._GraphCoordinator__d11_issuer
        self.host_root_required=True;self.expected_gate=None
        self.store=graph._GraphCoordinator__store
        self.db=self.store._db
        self.bundle,self.operation,self.clock=bundle,operation,clock
        self.selection_digest=operation.selection_digest
        self.graph_stamp=stamp
        self.thread=get_ident()
        self.monotonic_deadline=time.monotonic()+operation.deadline_utc-trusted_upper(clock)
        self.work=None;self.identity=None;self.complete=False;self.result=None;self.lease=None;self.authority=None
        self.grant_header=self.header=self.metadata=self.gate=self.adoption_result=None
        self.columns={};self.pending=None;self.column=None;self.generator=self._run_v1()
        self.history_plan=None;self.verified_members={};self.receipt=None

    def _identity_v1(self):
        return (self.graph,self.bootstrap,self.namespace,self.prepared_ref,self.bundle,self.operation,
            self.work,self.selection_digest,self.graph_stamp,self.thread,self.monotonic_deadline)

    def _runtime_retained_heap_bytes_v3(self):
        from .current_character_labor_adoption_v1 import _payload_heap_v1
        local=()if self.generator is None or self.generator.gi_frame is None else tuple(
            v for k,v in self.generator.gi_frame.f_locals.items()if k!="self")
        columns=tuple((v.body,v.fragment,v.value)for v in self.columns.values())
        return _payload_heap_v1((columns,self.metadata,self.gate,self.adoption_result,
            self.verified_members,local,self.pending,
            ()if self.history_plan is None else self.history_plan.retained_payload_v1()))+65536

    def require_v1(self,meter=None):
        import time
        if (_COLD_READERS.get(self)is not self.identity or self.identity!=self._identity_v1()
                or self.thread!=get_ident()or self.operation.closed or self.work.state is not self
                or self.work.coordinator is not self.graph or self.work.operation is not self.operation
                or self.work.kind!=COLD_ACK_KIND or self.work.operation_id!=self.operation.operation_id
                or time.monotonic()>=self.monotonic_deadline):
            raise AuthorityUnavailable("cold labor metadata lost its actual Root Work/selection/deadline")
        self.graph._admin(self.bootstrap)
        if meter is not None:
            self.operation.handle.require_current(meter)
            if self.lease is not None:self.graph._authorize(self.lease,self.authority,("d11",))
            if (not self.db.in_transaction or not self.store._lock._is_owned()
                    or self.graph._v2_graph_stamp(self.namespace)!=self.graph_stamp):
                raise AuthorityUnavailable("cold labor selected Graph metadata changed")
            grant=self.bundle.installation_policy.root_grant
            current=self._row(meter,"runtime_budget_grants",("version","status","signature"),
                "lease_id=? ORDER BY version DESC",(grant.lease_id,))
            if self.grant_header is not None and current!=self.grant_header:
                raise AuthorityUnavailable("cold labor actual installed Root grant changed")
        return self

    def _finish_v1(self):
        self.complete=True
        self.result=(NoCommittedLaborAdoptionV1 if self.metadata is None else PreparedCharacterLaborColdAckV1)(_COLD_KEY,self)

    def release_payload_v3(self):
        if _COLD_READERS.pop(self,None)is None:return
        if self.result is not None:
            _COLD_ACKNOWLEDGED_V1.pop(self.result,None)
            _COLD_RESULTS.pop(self.result,None)
        if self.generator is not None:self.generator.close()
        self.generator=self.pending=self.column=None
        self.columns.clear();self.verified_members.clear()
        if self.history_plan is not None:self.history_plan.release_v1()
        self.history_plan=None
        self.metadata=self.gate=self.adoption_result=self.result=None
        self.operation.unregister_retained_state_v3(self)
        if self.lease is not None:
            self.graph.release_authority_lease(self.bootstrap,self.lease);self.lease=None


def begin_current_character_labor_cold_ack_v1(graph,bootstrap,*,namespace,prepared_original_ref):
    from ..host.authority_profile import current_owner_metadata_installation_v3
    from ..graph_worker import create_graph_storage_work_v3
    from ..runtime_storage_v3 import begin_runtime_storage_operation_v3,bind_runtime_storage_operation_v3,finish_runtime_storage_operation_v3
    from .first_ingress_v2 import trusted_upper
    graph._admin(bootstrap)
    store=graph._GraphCoordinator__store
    bundle=current_owner_metadata_installation_v3(graph)[0]
    if (type(namespace)is not NamespaceId or namespace!=bundle.installation_policy.namespace
            or type(prepared_original_ref)is not str or not prepared_original_ref
            or store._db.in_transaction or store._lock._is_owned()):
        raise AuthorityUnavailable("cold labor ACK needs the actual installed namespace/Root metadata entry")
    clock=graph._GraphCoordinator__content_fence_v2.read_ingress_clock(graph._GraphCoordinator__scene_clock_policy)
    deadline=bundle.installation_policy.root_grant.valid_until_utc
    if trusted_upper(clock)>=deadline:
        raise AuthorityUnavailable("cold labor current Root resource deadline is exhausted")
    opid="labor-cold-ack:"+canonical_digest((namespace,prepared_original_ref))[:48]
    operation=begin_runtime_storage_operation_v3(store._db,opid,deadline)
    if operation is None:raise AuthorityUnavailable("cold labor ACK requires actual bounded selected runtime storage")
    reader=None
    try:
        with bind_runtime_storage_operation_v3(operation,store._db):
            with store._lock:
                store._db.execute("BEGIN")
                try:stamp=graph._v2_graph_stamp(namespace)
                finally:store._db.rollback()
        reader=CharacterLaborColdAckReadV1(_COLD_KEY,graph,bootstrap,namespace,prepared_original_ref,
            bundle,operation,clock,stamp)
        reader.work=create_graph_storage_work_v3(graph,kind=COLD_ACK_KIND,operation_id=opid,
            selection_digest=operation.selection_digest,deadline_utc=deadline,state=reader,operation=operation)
        reader.identity=reader._identity_v1()
        _COLD_READERS[reader]=reader.identity
        operation.register_retained_state_v3(reader)
        return reader.work
    except BaseException as first:
        if reader is not None:
            try:reader.release_payload_v3()
            except BaseException as later:first.add_note("cold labor metadata payload release failed: "+type(later).__name__)
        try:finish_runtime_storage_operation_v3(operation)
        except BaseException as later:first.add_note("cold labor metadata operation release failed: "+type(later).__name__)
        raise


def advance_current_character_labor_cold_ack_v1(graph,work):
    from ..runtime_storage_v3 import bind_runtime_storage_operation_v3
    from ..graph_worker import GraphStorageStepV3
    r=work.state
    if type(r)is not CharacterLaborColdAckReadV1 or r.graph is not graph or r.work is not work:
        raise AuthorityUnavailable("actual cold labor metadata Work required")
    work._require_invocation(graph)
    if r.gate is not None and r.lease is None:
        # A process lease isolates this metadata Work. Its historical actor is
        # never treated as current Owner or Source/Body permission.
        from ..runtime_contracts import AuthorityContext
        gate=r.gate
        r.lease,capability=graph.grant(r.bootstrap,actor=gate.owner_actor_id,issuer_domain="d11",
            namespace=r.namespace,domains=("d11",),activation_generation=gate.binding.activation_generation,
            operation_id=r.operation.operation_id)
        owners=tuple(sorted(graph._GraphCoordinator__leases[r.lease][5]))
        r.authority=AuthorityContext(gate.owner_actor_id,"d11",capability,r.namespace,owners,"audit",
            ("owner",),r.bundle.installation_policy.root_grant.policy_ref,gate.binding.activation_generation)
    with bind_runtime_storage_operation_v3(r.operation,r.db):
        with r.store._lock:
            if r.db.in_transaction:raise AuthorityUnavailable("cold labor metadata cannot inherit Graph SQL")
            r.db.execute("BEGIN")
            try:
                with runtime_storage_quantum_v3(r.db)as meter:r.advance_v1(meter)
            finally:r.db.rollback()
    return GraphStorageStepV3("complete",r.result)if r.complete else GraphStorageStepV3("progress")


def finish_current_character_labor_cold_ack_v1(graph,work,error):
    from ..runtime_storage_v3 import finish_runtime_storage_operation_v3
    r=work.state
    if type(r)is not CharacterLaborColdAckReadV1 or r.graph is not graph or r.work is not work:
        raise AuthorityUnavailable("actual cold labor metadata finish required")
    if error is None:
        if not r.complete or type(r.result)not in {PreparedCharacterLaborColdAckV1,NoCommittedLaborAdoptionV1}:
            raise AuthorityUnavailable("cold labor metadata cannot publish an incomplete result")
        work.result_lease=r.operation
        return
    try:r.release_payload_v3()
    except BaseException as later:error.add_note("cold labor metadata payload release failed: "+type(later).__name__)
    try:finish_runtime_storage_operation_v3(r.operation)
    except BaseException as later:error.add_note("cold labor metadata operation release failed: "+type(later).__name__)


_ACK_KEY = object()
_ACK_TASKS = {}
_ACK_RESULTS = {}


def _authority_ack_owner_v1(owner,gate,meter=None):
    from ..authority_service.character_labor_source_read_v1 import require_actual_character_labor_ack_metadata_owner_v1
    return require_actual_character_labor_ack_metadata_owner_v1(owner,gate=gate,meter=meter)


class CharacterLaborAuthorityAckMetadataTaskV1(_CharacterLaborAdoptionMetadataEngineV1):
    def __init__(self,key,owner,gate):
        if key is not _ACK_KEY:raise TypeError("actual Authority ACK metadata factory required")
        owner=_authority_ack_owner_v1(owner,gate)
        self.owner,self.expected_gate=owner,gate
        self.db,self.namespace,self.operation=owner.db,owner.namespace,owner.operation
        self.selection_digest,self.issuer=owner.selection_digest,owner.issuer
        self.prepared_ref=gate.binding.prepared_original_ref
        self.host_root_required=False
        self.thread=get_ident()
        self.identity=(owner,self.db,self.namespace,self.operation,self.selection_digest,self.issuer,gate,self.thread)
        self.complete=False;self.result=None;self.header=self.metadata=self.gate=self.adoption_result=None
        self.columns={};self.pending=None;self.column=None
        self.history_plan=None;self.verified_members={};self.receipt=None
        self.generator=self._run_v1()

    def require_v1(self,meter=None):
        owner=_authority_ack_owner_v1(self.owner,self.expected_gate,meter)
        if (_ACK_TASKS.get(owner)is not self or self.thread!=get_ident()
                or self.identity!=(owner,owner.db,owner.namespace,owner.operation,owner.selection_digest,
                    owner.issuer,self.expected_gate,self.thread)
                or self.operation.closed):
            raise AuthorityUnavailable("Authority labor ACK metadata left its actual private Work")
        return self

    def _runtime_retained_heap_bytes_v3(self):
        from .current_character_labor_adoption_v1 import _payload_heap_v1
        local=()if self.generator is None or self.generator.gi_frame is None else tuple(
            v for k,v in self.generator.gi_frame.f_locals.items()if k!="self")
        columns=tuple((c.body,c.fragment,c.value)for c in self.columns.values())
        return _payload_heap_v1((columns,self.metadata,self.gate,self.adoption_result,
            self.verified_members,local,self.pending,
            ()if self.history_plan is None else self.history_plan.retained_payload_v1()))+65536

    def _finish_v1(self):
        self.complete=True
        cls=NoCommittedCharacterLaborAuthorityAckV1 if self.metadata is None else CharacterLaborAuthorityAckMetadataV1
        self.result=cls(_ACK_KEY,self)

    def release_payload_v3(self):
        if _ACK_TASKS.pop(self.owner,None)is not self:return
        if self.result is not None:_ACK_RESULTS.pop(self.result,None)
        self.operation.unregister_retained_state_v3(self)
        if self.generator is not None:self.generator.close()
        if self.history_plan is not None:self.history_plan.release_v1()
        self.columns.clear();self.verified_members.clear()
        self.generator=self.pending=self.column=self.history_plan=None
        self.metadata=self.gate=self.adoption_result=self.receipt=self.result=None
        self.owner=self.expected_gate=self.identity=None


class NoCommittedCharacterLaborAuthorityAckV1:
    def __init__(self,key,task):
        if key is not _ACK_KEY:raise TypeError("actual complete Authority metadata absence required")
        self.task=task
        _ACK_RESULTS[self]=(task,task.identity,None)

    def require_current_v1(self,owner,*,gate,meter=None):
        task=self.task
        task.require_v1(meter)
        if (_ACK_RESULTS.get(self)!=(task,task.identity,None)or task.owner is not owner
                or task.expected_gate!=gate or task.result is not self or not task.complete
                or task.metadata is not None or task.header is not None):
            raise AuthorityUnavailable("Authority ACK absence is not this actual complete Work")
        return self


class CharacterLaborAuthorityAckMetadataV1:
    def __init__(self,key,task):
        if key is not _ACK_KEY:raise TypeError("actual complete Authority ACK metadata issuer required")
        self.task=task
        self.metadata,self.receipt,self.gate=task.metadata,task.receipt,task.gate
        self.adoption_result=dict(task.adoption_result)
        seal=canonical_digest((plain_v1(self.metadata),self.receipt,self.gate,self.adoption_result))
        _ACK_RESULTS[self]=(task,task.identity,seal)

    def require_current_v1(self,owner,*,gate,meter=None):
        task=self.task
        task.require_v1(meter)
        actual=(task,task.identity,canonical_digest((plain_v1(self.metadata),self.receipt,self.gate,self.adoption_result)))
        if (_ACK_RESULTS.get(self)!=actual or task.owner is not owner or task.expected_gate!=gate
                or task.result is not self or not task.complete or self.gate!=gate
                or (self.metadata,self.receipt,self.gate,self.adoption_result)!=(
                    task.metadata,task.receipt,task.gate,task.adoption_result)):
            raise AuthorityUnavailable("Authority ACK proof is not its actual same-Work complete metadata")
        return self


def create_character_labor_adoption_ack_metadata_task_v1(owner,*,gate):
    owner=_authority_ack_owner_v1(owner,gate)
    task=_ACK_TASKS.get(owner)
    if task is not None:
        if task.expected_gate!=gate:raise AuthorityUnavailable("Authority ACK task changed its original gate")
        return task.require_v1()
    task=CharacterLaborAuthorityAckMetadataTaskV1(_ACK_KEY,owner,gate)
    _ACK_TASKS[owner]=task
    try:task.operation.register_retained_state_v3(task)
    except BaseException:
        _ACK_TASKS.pop(owner,None)
        raise
    return task


def require_character_labor_adoption_ack_metadata_v1(task,owner,*,gate,meter=None):
    if type(task)is not CharacterLaborAuthorityAckMetadataTaskV1 or _ACK_TASKS.get(owner)is not task:
        raise AuthorityUnavailable("actual Authority labor ACK metadata task required")
    task.require_v1(meter)
    if not task.complete or type(task.result)not in {CharacterLaborAuthorityAckMetadataV1,NoCommittedCharacterLaborAuthorityAckV1}:
        raise AuthorityUnavailable("Authority labor ACK metadata has not reached complete EOF")
    return task.result.require_current_v1(owner,gate=gate,meter=meter)


def release_character_labor_adoption_ack_metadata_v1(owner):
    task=_ACK_TASKS.get(owner)
    if task is not None:task.release_payload_v3()
