"""Authenticated mixed execution facts pinned to one real Life write fence."""
from dataclasses import dataclass, fields

from .contract import AuthorityUnavailable
from .v2_contract import FencePermitV2, RestoreAnchor, _anchor_from_wire, _anchor_wire
from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize
from ..domains.d01.production_operations_v1 import plain_v1
from ..runtime.d11_offline_originals_v1 import _digest, _text

SIGN_KIND = "d11.life-execution-inventory.v1"
FAMILIES = frozenset({"dispatch","internal","numeric","authored_root","series","offline_tick","life"})

@dataclass(frozen=True, slots=True)
class LifeMixedExecutionFactV1:
    family: str
    execution_id: str
    effect_id: str | None
    operation_id: str
    binding_digest: str
    claim_sequence: int
    claim_digest: str
    terminal_sequence: int | None
    terminal_digest: str | None
    status: str

    def __post_init__(self):
        if self.family not in FAMILIES or self.status not in {"claimed","completed","failed","unknown","dispatch_unresolved"}:
            raise ValueError("closed real execution family/status required")
        for value in (self.execution_id,self.operation_id): _text(value)
        _digest(self.binding_digest)
        if type(self.claim_sequence) is not int or self.claim_sequence < 1 or not self.claim_digest.startswith("sha256:"):
            raise ValueError("real claim chain required")
        _digest(self.claim_digest[7:])
        if self.terminal_sequence is not None:
            if type(self.terminal_sequence) is not int or self.terminal_sequence <= self.claim_sequence or not self.terminal_digest.startswith("sha256:"):
                raise ValueError("real terminal chain required")
            _digest(self.terminal_digest[7:])
        elif self.terminal_digest is not None or self.status not in {"claimed","dispatch_unresolved"}:
            raise ValueError("missing terminal cannot become completed")

@dataclass(frozen=True, slots=True)
class LifeExecutionInventoryV1:
    namespace: NamespaceId
    authority_namespace: str
    authority_id: str
    installation_id: str
    manifest_digest: str
    anchor: RestoreAnchor
    permit_digest: str
    entries: tuple[LifeMixedExecutionFactV1, ...]
    signature: str
    schema: str = "d11.life-execution-inventory.v1"

    def __post_init__(self):
        if (self.schema != "d11.life-execution-inventory.v1" or type(self.namespace) is not NamespaceId
                or type(self.anchor) is not RestoreAnchor or type(self.entries) is not tuple
                or any(type(e) is not LifeMixedExecutionFactV1 for e in self.entries)
                or tuple(sorted(self.entries,key=lambda e:(e.family,e.execution_id))) != self.entries
                or len({(e.family,e.execution_id) for e in self.entries}) != len(self.entries)
                or self.anchor.namespace != self.authority_namespace or self.anchor.authority_id != self.authority_id
                or any((e.terminal_sequence or e.claim_sequence) > self.anchor.execution_seq for e in self.entries)):
            raise ValueError("Life inventory must describe one actual complete mixed head")
        for value in (self.manifest_digest,self.permit_digest,self.signature): _digest(value)

    @property
    def digest(self): return canonical_digest(plain_v1(self))


def life_execution_inventory_to_wire_v1(value):
    if type(value) is not LifeExecutionInventoryV1: raise TypeError("closed Life inventory required")
    raw=plain_v1(value)
    raw["anchor"]=_anchor_wire(value.anchor)
    return raw


def life_execution_inventory_from_wire_v1(raw):
    if type(raw) is not dict or set(raw) != {f.name for f in fields(LifeExecutionInventoryV1)}:
        raise ValueError("Life inventory fields differ")
    value=dict(raw)
    value["namespace"]=NamespaceId(**value["namespace"])
    value["anchor"]=_anchor_from_wire(value["anchor"])
    value["entries"]=tuple(LifeMixedExecutionFactV1(**e) for e in value["entries"])
    result=LifeExecutionInventoryV1(**value)
    if life_execution_inventory_to_wire_v1(result) != raw: raise ValueError("Life inventory is noncanonical")
    return result


def verify_life_execution_inventory_v1(value,issuer):
    if type(value) is not LifeExecutionInventoryV1: raise TypeError("actual Life inventory required")
    raw=life_execution_inventory_to_wire_v1(value)
    signature=raw.pop("signature")
    issuer._signer.verify(SIGN_KIND,canonical_serialize(raw),signature)
    return value


def mixed_execution_facts_locked_v1(bridge,db,rows,permit):
    """Every row first authenticates its installed family; no unknown row is skipped."""
    from .v2_contract import decode_bytes, PendingMutationV2
    from .d04_numeric_journal_v3 import ENTRY_PREFIX as NUMERIC, decode_numeric_row_v3
    from .d04_root_execution_journal_v3 import ROOT_ENTRY_PREFIX_V3 as ROOT, decode_root_execution_row_v3
    from .d04_series_journal_v1 import ENTRY_PREFIX as SERIES, decode_series_row_v1
    from .d11_offline_tick_journal_v1 import ENTRY_PREFIX as OFFLINE
    from .d11_life_journal_v1 import ENTRY_PREFIX as LIFE
    bridge.core._verify_execution_redaction_c04_rows(bridge.journal,rows,journal_id=bridge.journal.journal_id)
    registries=((NUMERIC,"numeric",bridge.core._execution_redaction_d04_numeric_services_v3,"verify_numeric_journal_row_v3"),
        (ROOT,"authored_root",bridge.core._execution_redaction_d04_root_services_v3,"verify_root_journal_row_v3"),
        (SERIES,"series",bridge.core._execution_redaction_d04_series_services_v1,"verify_series_journal_row_v1"),
        (OFFLINE,"offline_tick",bridge.core._execution_redaction_d11_offline_services_v1,"verify_offline_tick_journal_row_v1"),
        (LIFE,"life",bridge.core._execution_redaction_d11_life_services_v1,"verify_life_journal_row_v1"))
    facts={}
    for row in rows:
        selected=next(((family,registry,method) for prefix,family,registry,method in registries if row[4].startswith(prefix)),None)
        if selected is not None:
            family,registry,method=selected
            service=registry.get(bridge.namespace)
            if service is None: raise AuthorityUnavailable("actual installed mixed family verifier absent")
            binding,claim,terminal=getattr(service,method)(bridge.journal,row)
            measurement = {"numeric":decode_numeric_row_v3,"authored_root":decode_root_execution_row_v3,"series":decode_series_row_v1}[family](bridge.journal,row)[2] if family in {"numeric","authored_root","series"} else None
            if family == "series": binding=binding.numeric
            digest=binding.digest
            effect=binding.effect_id if family == "life" else None
        elif row[4].startswith(b'{"binding":'):
            family="internal"
            binding,claim,terminal=bridge.journal._decode_internal_row(row)
            digest=binding.binding_digest
            effect=None
        else:
            pending=decode_bytes(row[4])
            if type(pending) is not PendingMutationV2: raise AuthorityUnavailable("unregistered mixed execution row")
            continue  # Authenticated dispatch original joins are checked below against actual Core indices.
        key=(family,binding.execution_id)
        prior=facts.get(key)
        if terminal is None:
            if prior is not None: raise AuthorityUnavailable("mixed execution repeats actual claim")
            facts[key]=LifeMixedExecutionFactV1(family,binding.execution_id,effect,binding.operation_id,digest,row[0],row[6],None,None,"claimed")
        else:
            if prior is None or prior.binding_digest != digest or prior.terminal_sequence is not None:
                raise AuthorityUnavailable("mixed terminal lacks exact actual claim")
            facts[key]=LifeMixedExecutionFactV1(family,binding.execution_id,effect,binding.operation_id,digest,
                prior.claim_sequence,prior.claim_digest,row[0],row[6],
                ("completed" if measurement.status == "chunk_completed" else measurement.status)
                    if family in {"numeric","authored_root","series"} else terminal.status)
    effects=bridge._unresolved_effects_locked(db,permit=permit,execution_rows=rows)
    for e in effects:
        facts[("dispatch",e.effect_id)]=LifeMixedExecutionFactV1("dispatch",e.effect_id,e.effect_id,e.operation_id,
            canonical_digest(e),e.execution_seq,e.append_digest,None,None,"dispatch_unresolved")
    return tuple(sorted(facts.values(),key=lambda e:(e.family,e.execution_id)))


def read_life_execution_inventory_v1(service,*,permit,binding=None):
    from ..runtime.d11_life_contract_v1 import D11DraftExecutionBindingV1
    if (type(permit) is not FencePermitV2 or permit.operation not in {"write", "accounting"}
            or permit.namespace != service.bridge.namespace
            or permit.operation == "accounting" and type(binding) is not D11DraftExecutionBindingV1):
        raise AuthorityUnavailable("Life inventory requires actual ordinary write fence")
    service.bridge.core._require(service.credential,"execution",service.bridge.namespace)
    with service._frozen() as (db,deletion,execution,_deletion_history):
        if _deletion_history: service.bridge.core.require_current_content_ready_locked(db,namespace=service.bridge.namespace)
        actual_head,rows=service.bridge.journal._scan_locked()
        if actual_head != execution: raise AuthorityUnavailable("Life inventory mixed head changed")
        anchor,_=service._current(db,deletion,execution)
        if permit.operation == "accounting":
            from .d11_life_journal_v1 import read_life_rows_locked_v1
            head,claim,terminal,_,_=read_life_rows_locked_v1(service.bridge.journal,binding)
            original,row=service._gate(db,binding,"terminal")
            if (claim is None or terminal is not None or original!=permit or row[6]!="active"
                    or (head.seq,head.digest)!=(claim.claim_sequence,claim.claim_digest)
                    or permit.command_digest!="sha256:"+canonical_digest((binding.digest,claim.claim_digest))):
                raise AuthorityUnavailable("draft inventory needs its exact original unresolved claim continuation")
            service._verify_payload(claim.payload)
        service.bridge.fences.validate_fence_locked(db,permit,subject=permit.subject,current_anchor=anchor)
        if permit.pinned_anchor != anchor: raise AuthorityUnavailable("Life inventory actual head changed")
        entries=mixed_execution_facts_locked_v1(service.bridge,db,rows,permit)
        raw={"namespace":plain_v1(service.namespace),"authority_namespace":service.bridge.namespace,
            "authority_id":permit.authority_id,"installation_id":service.installation_id,"manifest_digest":service.manifest_digest,
            "anchor":_anchor_wire(anchor),"permit_digest":canonical_digest(permit),"entries":plain_v1(entries),"schema":"d11.life-execution-inventory.v1"}
        raw["signature"]=service.issuer._signer.sign(SIGN_KIND,canonical_serialize(raw))
        return life_execution_inventory_from_wire_v1(raw)
