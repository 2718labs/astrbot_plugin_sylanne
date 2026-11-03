"""Host adoption inputs for the explicit character-labor protocol.

The original adoption WRITE remains owned by the Life bridge. This Work owns
only bounded metadata, independently qualified Sources and their retained inputs.
"""
from dataclasses import dataclass,fields,is_dataclass
from types import SimpleNamespace
from weakref import WeakKeyDictionary
from threading import get_ident
from contextlib import contextmanager
from contextvars import ContextVar
import time
import sys

from ..authority_service.contract import AuthorityUnavailable
from ..graph_types import AtomKey, GraphAtom, GraphVersion, owner_grant_key
from ..runtime_contracts import AuthorityContext, FenceScope, NamespaceId, canonical_digest, canonical_serialize
from ..graph_worker import GraphStorageStepV3, GraphStorageWorkV3, create_graph_storage_work_v3
from ..runtime_storage_v3 import (begin_runtime_storage_operation_v3, bind_runtime_storage_operation_v3,
    finish_runtime_storage_operation_v3, runtime_storage_quantum_v3, runtime_storage_v3,
    begin_runtime_cell_read_v3)
from .dispatch_current_inventory_v3 import _CurrentNamespaceInventoryKernelV3, _heap, _detach_value_v3
from .d11_character_work_segment_v1 import (CharacterLaborPreparedMetadataV1, PREPARED_METADATA_KIND,
    BODY_KIND, ADMISSION_KIND, SEGMENT_KIND, character_labor_prepared_metadata_from_wire_v1,
    labor_body_preparation_from_wire_v1, character_labor_admission_from_wire_v1,
    character_work_segment_from_wire_v1)
from .d11_life_preparation_v1 import TABLE, SIGN_KIND
from ..domains.d01.production_operations_v1 import plain_v1

def _payload_heap_v1(value,seen=None):
    if seen is None:seen=set()
    if id(value)in seen:return 0
    seen.add(id(value))
    size=sys.getsizeof(value)
    if is_dataclass(value):
        return size+sum(_payload_heap_v1(getattr(value,f.name),seen)for f in fields(value))
    if type(value)is dict:
        return size+sum(_payload_heap_v1(k,seen)+_payload_heap_v1(v,seen)for k,v in value.items())
    if type(value)in (tuple,list,set,frozenset):
        return size+sum(_payload_heap_v1(v,seen)for v in value)
    return size


KIND = "current_character_labor_adoption_v1"
_ISSUER = object()
_READERS = WeakKeyDictionary()
_INPUTS = WeakKeyDictionary()
_FRAMES = WeakKeyDictionary()
_BODY_READERS = WeakKeyDictionary()
_COLUMN_VALUES = WeakKeyDictionary()
_BOUND = ContextVar("character_labor_adoption_inputs_v1",default=None)
_OBSERVED=WeakKeyDictionary()
_BODY_TYPES = frozenset({"d02.body_state.v1", "d02.body_profile.v1", "d02.reservation.v1",
    "d02.settlement.v1", "d02.character_labor_rebuild_head.v1"})


def _identity(r):
    return (r.graph,r.work,r.operation,r.scope,r.gate,r.life_port,r.port,r.bundle,
        r.expected_metadata,r.expected_prepared_header,r.namespace,r.selection_digest,
        r.graph_stamp,r.catalogue_hash,r.authority,r.lease,r.thread,r.monotonic_deadline)


def require_actual_character_labor_adoption_reader_v1(reader, *, meter=None):
    if (type(reader) is not CharacterLaborAdoptionReadV1 or _READERS.get(reader) != _identity(reader)
            or type(reader.work) is not GraphStorageWorkV3 or reader.work.kind != KIND
            or reader.work.state is not reader or reader.work.operation is not reader.operation
            or reader.work.coordinator is not reader.graph or reader.operation.closed
            or reader.work.operation_id != reader.operation_id
            or reader.work.selection_digest != reader.selection_digest or reader.thread != get_ident()
            or reader.scope.operation != "write" or reader.scope.permit != reader.gate.permit
            or reader.scope.operation_id != reader.gate.permit.operation_id):
        raise AuthorityUnavailable("labor adoption requires its actual named Host Work and original WRITE")
    if time.monotonic() >= reader.monotonic_deadline:
        raise AuthorityUnavailable("labor adoption exhausted its original current Root resource deadline")
    reader.graph._authorize(reader.lease,reader.authority,reader.domains)
    if meter is not None:
        reader.operation.handle.require_current(meter)
        if (reader.db is not reader.store._db or not reader.db.in_transaction
                or not reader.store._lock._is_owned()
                or reader.graph._v2_graph_stamp(reader.namespace) != reader.graph_stamp
                or reader._epochs(meter) != reader.authority_epochs
                or reader.store._registry.catalogue_hash != reader.catalogue_hash):
            raise AuthorityUnavailable("labor adoption current Graph/storage/Source stamp changed")
        if reader.resource_verified:
            reader._require_resource_head_v1(meter)
        if reader.general_owner_entry is not None:
            reader.general_owner_entry.require_for_v3(reader)
    return reader


def character_labor_adoption_source_identity_v1(reader):
    r = require_actual_character_labor_adoption_reader_v1(reader)
    return _identity(r)


def require_current_character_labor_adoption_owner_reader_v1(reader):
    r = require_actual_character_labor_adoption_reader_v1(reader)
    if not r.metadata_sealed or r.metadata_identity is None or r.resource_proof is None:
        raise AuthorityUnavailable("labor Owner observation requires actual signed metadata and current resources")
    return r.graph,r.port,r.bundle,r.scope,r.owner_groups


def character_labor_adoption_owner_metadata_identity_v1(reader):
    require_current_character_labor_adoption_owner_reader_v1(reader)
    return reader.metadata_identity


def character_labor_adoption_source_groups_v1(reader, roots):
    r = require_actual_character_labor_adoption_reader_v1(reader)
    if (not r.metadata_sealed or r.selected_plan is None
            or tuple(sorted(set(roots))) != tuple(sorted(r.metadata.source_roots))):
        raise AuthorityUnavailable("labor Source roots differ from its signed C metadata recipe")
    return r.owner_groups


def character_labor_adoption_metadata_head_v1(reader,key):
    r = require_actual_character_labor_adoption_reader_v1(reader)
    if NamespaceId.from_key(key) != r.namespace or not r.graph_eof:
        raise AuthorityUnavailable("labor Source controls require its complete fixed metadata census")
    head = r.heads.get(key.token)
    atom = r.control_atoms.get(key.token)
    if head is None:
        return GraphAtom(key,0,{},False)
    if atom is None:
        raise AuthorityUnavailable("labor Source control is outside the actual ACL/correction projection")
    return atom


def character_labor_adoption_metadata_spec_v1(reader, identity):
    r = require_actual_character_labor_adoption_reader_v1(reader)
    if identity not in r.metadata_selected:
        raise AuthorityUnavailable("labor locator was not selected by its private fixed recipe")
    kind,ref = identity
    if kind in {"duration_basis","duration_accounting"}:
        entry=next((e for e in r.census.entries if e.execution_id==ref and
            e.classification in {"character_labor_v1","retained_duration_v1"}),None)
        if entry is None:raise AuthorityUnavailable("labor duration locator is outside its actual signed complete census")
        if kind=="duration_basis":
            from .d11_character_labor_accounting_v1 import KIND as basis_kind
            original_kind=basis_kind
            original_ref="character-labor-accounting:"+ref
        else:
            basis=r.accounting_bases.get(ref)
            if basis is None:raise AuthorityUnavailable("labor old accounting requires its actual signed duration basis")
            original_kind="accounting_prepared"
            original_ref=basis.accounting_ref
        return (TABLE,"payload_json",("bot","persona","kind","original_ref"),
            (*r.namespace.as_tuple,original_kind,original_ref),
            ("producing_operation_id","payload_digest","signature"),((),),None)
    if kind=="action_admission":
        if ref!="d08-life-admission:"+r.gate.binding.execution_id:
            raise AuthorityUnavailable("labor action admission left its actual C execution")
        return (TABLE,"payload_json",("bot","persona","kind","original_ref"),
            (*r.namespace.as_tuple,"action_admission",ref),
            ("producing_operation_id","payload_digest","signature"),((),),None)
    if kind=="component":
        if r.component_pending!=identity and identity not in r.metadata_tasks:
            raise AuthorityUnavailable("labor component lacks its complete namespace metadata selector")
        return ("graph_d02_action_components_v1","payload_json",("bot","persona","original_ref"),
            (*r.namespace.as_tuple,ref),("producing_operation_id","payload_digest","signature"),((),),
            "d11.d02-completed-action-component.v1")
    if kind=="body_install":
        if ref not in r.initial_checkpoint_refs.values():
            raise AuthorityUnavailable("initial Body checkpoint is outside the actual fixed history producer")
        return (TABLE,"payload_json",("bot","persona","kind","original_ref"),
            (*r.namespace.as_tuple,"body_policy_checkpoint_v1",ref),
            ("producing_operation_id","payload_digest","signature"),((),),None)
    if kind in {"body_install_reads","body_install_writes","body_install_epochs","body_install_invalidated"}:
        if ref not in r.initial_checkpoints:
            raise AuthorityUnavailable("initial Body event requires its authenticated signed checkpoint")
        column={"body_install_reads":"reads","body_install_writes":"revisions",
            "body_install_epochs":"epoch_reads","body_install_invalidated":"invalidated"}[kind]
        return ("graph_events",column,("bot","persona","session","event_id"),
            (*r.namespace.as_tuple,"c04.fixed_body_install.v1",ref),("digest","epoch_revision"),((),),None)
    if kind in {"checkpoint_receipt","checkpoint_reads","checkpoint_writes"}:
        if ref not in r.receipt_locators:
            raise AuthorityUnavailable("labor checkpoint receipt is not a selected actual history producer")
        if kind=="checkpoint_receipt":
            return ("graph_bundle_operations","receipt_json",("bot","persona","operation_id"),
                (*r.namespace.as_tuple,ref),("digest","activity_id","effect_id","commit_seq"),((),),None)
        column="reads" if kind=="checkpoint_reads" else "revisions"
        return ("graph_events",column,("bot","persona","session","event_id"),
            (*r.namespace.as_tuple,r.receipt_locators[ref],ref),("digest","epoch_revision"),((),),None)
    if kind == "root_grant":
        grant = r.bundle.installation_policy.root_grant
        if ref != grant.lease_id:
            raise AuthorityUnavailable("labor resource grant differs from its installed Root")
        return ("runtime_budget_grants","grant_json",("lease_id","version"),(ref,grant.version),
            ("version","status","signature"),((),),"budget-grant.v1")
    if kind in {"prepare_receipt","prepare_reads","prepare_writes"}:
        op=r.expected_metadata.binding.prepare_operation_id
        if ref!=op:raise AuthorityUnavailable("labor C receipt locator changed")
        if kind=="prepare_receipt":
            return ("graph_bundle_operations","receipt_json",("bot","persona","operation_id"),
                (*r.namespace.as_tuple,op),("digest","activity_id","effect_id","commit_seq"),((),),None)
        column="reads" if kind=="prepare_reads" else "revisions"
        return ("graph_events",column,("bot","persona","session","event_id"),
            (*r.namespace.as_tuple,r.expected_metadata.binding.activity_id,op),("digest","epoch_revision"),((),),None)
    original_kind = {"prepared_metadata":PREPARED_METADATA_KIND,"body_preparation":BODY_KIND,
        "admission":ADMISSION_KIND}.get(kind)
    if original_kind is not None:
        expected = {
            "prepared_metadata":"character-labor-prepared-metadata:"+r.gate.binding.execution_id,
            "body_preparation":r.expected_metadata.plan.labor_body_preparation_original.original_ref,
            "admission":r.expected_metadata.labor_admission_ref}
        if ref != expected[kind]:
            raise AuthorityUnavailable("labor metadata locator differs from its exact binding/B/C")
        return (TABLE,"payload_json",("bot","persona","kind","original_ref"),
            (*r.namespace.as_tuple,original_kind,ref),
            ("producing_operation_id","payload_digest","signature"),((),),None)
    if kind == "policy":
        if r.body_preparation is None or ref != r.body_preparation.policy.policy_ref:
            raise AuthorityUnavailable("labor policy requires its actual signed B metadata")
        policy = r.body_preparation.policy
        return ("graph_d02_production_policies_v1","payload_json",
            ("bot","persona","policy_ref","revision"),(*r.namespace.as_tuple,ref,policy.revision),
            ("kind","profile_id","payload_digest","signature"),((),),"d11.d02-production-policy.v1")
    raise AuthorityUnavailable("unknown labor adoption metadata profile")


def retain_character_labor_adoption_metadata_path_v1(task,path):
    # These four schemas are closed and contain no Source/Prepared Body.
    character_labor_adoption_metadata_spec_v1(task.reader,task.identity)
    return True


def finish_character_labor_adoption_metadata_v1(task,value):
    r = require_actual_character_labor_adoption_reader_v1(task.reader)
    kind,ref = task.identity
    if value is None:
        raise AuthorityUnavailable("selected new labor metadata is absent; absence cannot select legacy")
    if kind in {"duration_basis","duration_accounting"}:
        from .d11_character_labor_accounting_v1 import (
            KIND as basis_kind,SIGN_KIND as basis_sign,character_labor_accounting_basis_from_wire_v1,_require_accounting)
        entry=next(e for e in r.census.entries if e.execution_id==ref)
        if kind=="duration_basis":
            original_ref="character-labor-accounting:"+ref
            r.issuer._signer.verify(basis_sign,canonical_serialize((
                r.namespace,basis_kind,original_ref,task.metadata[1])),task.metadata[2])
            basis=character_labor_accounting_basis_from_wire_v1(value)
            b=entry.binding
            if ((basis.namespace,basis.binding_digest,basis.prepare_operation_id,basis.prepared_ref,basis.prepared_digest)
                    !=(r.namespace,b.digest,b.prepare_operation_id,b.prepared_original_ref,entry.prepared_digest)
                    or task.metadata[0]!=b.prepare_operation_id
                    or (entry.classification=="retained_duration_v1"
                        and (entry.accounting_basis_ref,entry.accounting_basis_digest)!=(original_ref,task.metadata[1]))):
                raise AuthorityUnavailable("labor duration basis differs from its actual census claim/Prepared binding")
            if b==r.gate.binding and (basis.policy!=r.body_preparation.policy or basis.quote!=r.body_preparation.quote
                    or basis.body_preparation_digest!=r.metadata.plan.labor_body_preparation_original.original_digest
                    or basis.admission_digest!=r.metadata.labor_admission_digest):
                raise AuthorityUnavailable("labor current duration basis changed its actual B/C policy or first reservation")
            r.accounting_bases[ref]=basis
            return basis
        basis=r.accounting_bases[ref]
        r.issuer._signer.verify(SIGN_KIND,canonical_serialize((
            r.namespace,"accounting_prepared",basis.accounting_ref,task.metadata[1])),task.metadata[2])
        from .d11_life_accounting_v1 import D11LifeAccountingPreparedV1
        from .d10_offline_tick_execution_v1 import _decode_json
        accounting=_decode_json(canonical_serialize(value),D11LifeAccountingPreparedV1)
        if (accounting.binding!=entry.binding or task.metadata[0]!=basis.prepare_operation_id
                or task.metadata[1]!=basis.accounting_digest):
            raise AuthorityUnavailable("labor duration basis lost its independently signed original accounting contract")
        _require_accounting(basis,accounting)
        r.accounting_originals[ref]=accounting
        return accounting
    if kind=="action_admission":
        import json
        from .d08_life_admission_v1 import LifeActionAdmissionOriginalV1
        r.issuer._signer.verify(SIGN_KIND,canonical_serialize((
            r.namespace,"action_admission",ref,task.metadata[1])),task.metadata[2])
        raw=dict(value)
        raw["read_refs"]=tuple(raw["read_refs"])
        original=LifeActionAdmissionOriginalV1(**raw)
        m=r.metadata
        if (original.binding_digest!=m.binding.digest or original.plan_digest!=m.binding.plan_digest
                or original.prepare_operation_id!=m.binding.prepare_operation_id
                or original.prepare_receipt_digest!=m.receipt_digest
                or task.metadata[0]!=m.binding.prepare_operation_id
                or original.action_operation_id!=m.binding.operation_id):
            raise AuthorityUnavailable("labor action admission changed its actual signed C/plan/receipt")
        template=json.loads(original.frame_template_json)
        if set(template)!={"envelope_json","owner_guard","types","policies","originals"}:
            raise AuthorityUnavailable("labor signed admission template is not the actual closed metadata recipe")
        r.action_admission,r.action_template=original,template
        r.signed_originals[("action_admission",ref)]=(value,task.metadata[0])
        return original
    if kind=="component":
        from .d02_production_operations_v1 import CompletedActionBodyComponentV1
        raw=dict(value)
        raw["paid_cost_refs"]=tuple(raw["paid_cost_refs"])
        original=CompletedActionBodyComponentV1(**raw)
        if original.original_ref!=ref:
            raise AuthorityUnavailable("labor fixed component differs from its actual signed original locator")
        return original
    if kind=="body_install":
        from .d02_character_labor_rebuild_v1 import (
            BODY_POLICY_CHECKPOINT_KIND_V1,BODY_POLICY_CHECKPOINT_SIGN_KIND_V1,body_policy_checkpoint_from_wire_v1)
        r.issuer._signer.verify(BODY_POLICY_CHECKPOINT_SIGN_KIND_V1,canonical_serialize((
            r.namespace,BODY_POLICY_CHECKPOINT_KIND_V1,ref,task.metadata[1])),task.metadata[2])
        original=body_policy_checkpoint_from_wire_v1(value)
        if (original.namespace!=r.namespace or original.original_ref!=ref
                or task.metadata[0]!=original.producing_operation_id
                or r.initial_checkpoint_refs.get(original.producing_operation_id)!=ref
                or original.authority_namespace!=r.scope.authority_namespace):
            raise AuthorityUnavailable("labor initial checkpoint differs from its actual signed installation producer")
        r.graph._GraphCoordinator__body_quote_authority._verify(
            "d02-fixed-body-policy.v1",original.policy_json,original.policy_signature)
        r.initial_checkpoints[original.producing_operation_id]=original
        return original
    if kind in {"checkpoint_receipt","checkpoint_reads","checkpoint_writes",
            "body_install_reads","body_install_writes","body_install_epochs","body_install_invalidated"}:
        return value
    if kind == "root_grant":
        from .issuers import _decode_grant
        grant = _decode_grant(canonical_serialize(value))
        if (grant != r.bundle.installation_policy.root_grant or task.metadata[:2] != (grant.version,"active")
                or (grant.bot_id,grant.persona_id) != r.namespace.as_tuple
                or grant.valid_until_utc != r.operation.deadline_utc
                or r.life_work_kind not in grant.allowed_work_kinds):
            raise AuthorityUnavailable("labor settlement resources differ from the current installed signed Root grant")
        r.resource_grant = grant
        r.resource_signature = task.metadata[2]
        r.resource_verified = True
        r.resource_proof = (r.bundle,grant,task.column.canonical_digest,task.metadata,
            r.operation,r.operation.handle,r.selection_digest,r.gate)
        return grant
    if kind=="passive_policy":
        from .d02_production_operations_v1 import PassiveBodyPolicyV1
        from ..domains.d02 import BodyPassiveRates
        raw=dict(value)
        raw["namespace"]=NamespaceId(**raw["namespace"])
        raw["rates"]=BodyPassiveRates(**raw["rates"])
        policy=PassiveBodyPolicyV1(**raw)
        if ((policy.policy_ref,policy.revision)!=ref or policy.namespace!=r.namespace
                or policy.profile_id!=r.policy.profile_id
                or task.metadata[:2]!=("passive",policy.profile_id)):
            raise AuthorityUnavailable("labor passive policy differs from its actual complete signed profile census")
        return policy
    if kind == "policy":
        from ..domains.d02.character_labor_v1 import character_labor_policy_from_wire_v1
        policy = character_labor_policy_from_wire_v1(value)
        if policy != r.body_preparation.policy or task.metadata[:2] != ("labor",policy.profile_id):
            raise AuthorityUnavailable("labor B policy differs from the actual signed installed policy")
        r.policy = policy
        return policy
    if kind in {"prepare_receipt","prepare_reads","prepare_writes"}:
        return value
    original_kind = {"prepared_metadata":PREPARED_METADATA_KIND,"body_preparation":BODY_KIND,"admission":ADMISSION_KIND}[kind]
    r.issuer._signer.verify(SIGN_KIND,
        canonical_serialize((r.namespace,original_kind,ref,task.metadata[1])),task.metadata[2])
    decoder = {"prepared_metadata":character_labor_prepared_metadata_from_wire_v1,
        "body_preparation":labor_body_preparation_from_wire_v1,
        "admission":character_labor_admission_from_wire_v1}[kind]
    if kind=="admission":
        if (type(value)is not dict or set(value)!={"schema","admission","body_preparation_digest","receipt_digest"}
                or value["schema"]!="d11.character-labor-admission-original.v1"
                or value["body_preparation_digest"]!=r.metadata.plan.labor_body_preparation_original.original_digest
                or value["receipt_digest"]!=r.metadata.receipt_digest):
            raise AuthorityUnavailable("labor C signed wrapper changed its actual B/C receipt commitments")
        original=decoder(value["admission"])
    else:
        original=decoder(value)
    if original.namespace != r.namespace:
        raise AuthorityUnavailable("labor signed metadata crossed namespace")
    if kind == "prepared_metadata":
        m = _require_bodyless_prepared_metadata_v1(original)
        if (m != r.expected_metadata or m.binding != r.gate.binding
                or m.prepared_digest != r.gate.prepared_digest
                or task.metadata[0] != m.binding.prepare_operation_id
                or r._prepared_header_v1() != r.expected_prepared_header):
            raise AuthorityUnavailable("labor metadata is not the same actual signed new Prepared/C output")
        r.metadata = m
    elif kind == "body_preparation":
        loc = r.metadata.plan.labor_body_preparation_original
        if (task.metadata[:2] != (original.body_prepare_operation_id,loc.original_digest)
                or original.action_operation_id != r.metadata.plan.operation_id
                or original.effect_id != r.gate.binding.effect_id
                or set(original.source_refs) - set(r.metadata.source_roots)):
            raise AuthorityUnavailable("labor B original differs from the same actual C plan/effect/Source roots")
        r.body_preparation = original
    else:
        m,b = r.metadata,r.body_preparation
        if (original.binding_digest != r.gate.binding.digest
                or original.admission_ref != m.labor_admission_ref
                or task.metadata[:2] != (original.admission_operation_id,m.labor_admission_digest)
                or original.prepared_original_ref != m.prepared_ref
                or original.body_preparation_ref != m.plan.labor_body_preparation_original.original_ref
                or original.body_preparation_digest != m.plan.labor_body_preparation_original.original_digest
                or original.policy_digest != canonical_digest(plain_v1(b.policy))
                or original.reservation_ref != b.reservation_ref
                or original.reservation_revision != b.reservation_revision
                or original.reservation_digest != b.reservation_digest):
            raise AuthorityUnavailable("labor actual signed admission is not this B/C/Prepared binding")
        r.admission = original
    r.signed_originals[(original_kind,ref)]=(value,task.metadata[0])
    return original


def require_character_labor_adoption_column_v1(reader,*,table,column,key_columns,key,metadata_task=None):
    r = require_actual_character_labor_adoption_reader_v1(reader)
    locator=(table,column,tuple(key_columns),tuple(key))
    if metadata_task is not None:
        if (r.metadata_tasks.get(metadata_task.identity) is not metadata_task
                or tuple(metadata_task.spec[:4]) != locator):
            raise AuthorityUnavailable("labor metadata column lacks its actual selected signed locator task")
        return r
    if locator not in r.body_locators:
        raise AuthorityUnavailable("labor Body column is outside its actual sealed selection")
    if r.general_owner_entry is None or r.source_qualification is None:
        raise AuthorityUnavailable("labor Body requires independent current Owner and complete Source permission")
    r.source_qualification.require_for_v3(r)
    if table == "graph_atoms" and AtomKey.from_token(key[0]).type_name == "memory.source":
        if r.phase != "source_body" or key[0] not in r.source_qualification.source_refs:
            raise AuthorityUnavailable("labor full Source is outside the actual ancestor closure")
    elif not r.source_all_complete:
        raise AuthorityUnavailable("labor Prepared and Body remain sealed before whole-Source EOF")
    return r


def require_character_labor_adoption_body_v1(reader,table,key,*,column="value"):
    r = require_actual_character_labor_adoption_reader_v1(reader)
    matches=[loc for loc in r.body_locators if loc[0]==table and loc[1]==column and loc[3]==tuple(key)]
    if len(matches)!=1:
        raise AuthorityUnavailable("labor protected body has no exact selected column")
    return require_character_labor_adoption_column_v1(r,table=table,column=column,
        key_columns=matches[0][2],key=key)


def require_character_labor_adoption_point_v1(reader,request):
    r = require_actual_character_labor_adoption_reader_v1(reader)
    table,columns,key_columns,key = request
    keys=tuple(key_columns)
    actual=any(loc[0]==table and loc[2]==keys and loc[3]==tuple(key)for loc in r.body_locators)
    if not actual:
        raise AuthorityUnavailable("labor point is not in its actual retained metadata/body inventory")
    if any(c in {"value","payload_json"} for c in columns):
        require_character_labor_adoption_body_v1(r,table,key,
            column="value" if "value" in columns else "payload_json")
    return True


class CharacterLaborAdoptionReadV1(_CurrentNamespaceInventoryKernelV3):
    def __init__(self,graph,bootstrap,life_port,gate,expected,prepared_header,operation,lease,authority,clock):
        self.graph=graph
        self.store,self.db=graph._GraphCoordinator__store,graph._GraphCoordinator__store._db
        self.bootstrap,self.life_port,self.port=bootstrap,life_port,life_port.port
        from ..host.authority_profile import current_owner_metadata_installation_v3
        self.bundle=current_owner_metadata_installation_v3(graph)[0]
        self.gate,self.expected_metadata,self.expected_prepared_header=gate,expected,tuple(prepared_header)
        self.operation_id=operation.operation_id
        self.operation_kind="adopt_character_labor_terminal_v1"
        self.authority,self.lease,self.clock=authority,lease,clock
        self.domains=frozenset(graph._GraphCoordinator__leases[lease][4])
        self.thread=get_ident()
        from .first_ingress_v2 import trusted_upper
        self.monotonic_deadline=time.monotonic()+operation.deadline_utc-trusted_upper(clock)
        self.work=None
        self.scope=FenceScope(expected.namespace,gate.binding.authority_namespace,
            gate.binding.activation_generation,"write",gate.permit.operation_id,gate.permit,
            gate.after_anchor,graph._v2_graph_stamp(expected.namespace)[1],gate.before_graph_revision)
        fence=SimpleNamespace(scope=self.scope)
        self._initialize_storage_kernel_v3(operation,fence,namespace=expected.namespace,
            graph_stamp=graph._v2_graph_stamp(expected.namespace),catalogue_hash=self.store._registry.catalogue_hash,
            projection_types=frozenset(),selected_tokens=frozenset(),
            census_schema="sylanne3.character-labor-adoption-header-census.v1",
            leaf_schema="sylanne3.character-labor-adoption-header-leaf.v1")
        self.authority_epochs=self._epochs_at_begin_v1()
        self.issuer=graph._GraphCoordinator__d11_issuer
        from .d11_life_contract_v1 import life_work_kind_v1
        self.life_work_kind=life_work_kind_v1(gate.binding)
        self.phase="resource"
        self.resource_verified=False
        self.resource_grant=self.resource_signature=self.resource_proof=None
        self.metadata=self.body_preparation=self.admission=self.policy=self.prepared=None
        self.action_admission=None
        self.action_template=None
        self.inventory_types=frozenset(_BODY_TYPES)
        self.metadata_tasks={}
        self.metadata_selected=set()
        self.metadata_identity=None
        self.metadata_sealed=False
        self.owner_groups=()
        self.general_owner_entry=self.owner_binding=self.owner_guard=None
        self.source_qualification=None
        self.source_all_complete=False
        self.source_columns={}
        self.source_bodies={}
        self.control_atoms={}
        self.selected_headers={}
        self.body_locators=set()
        self.columns={}
        self.body_atoms={}
        self.segments=[]
        self.body_cursor=""
        self.segment_cursor=""
        self.passive_cursor=("",0)
        self.passive_pending=None
        self.passive_policies=[]
        self.passive_complete=False
        self.checkpoints={}
        self.checkpoint_pending=None
        self.checkpoint_queue=None
        self.checkpoint_complete=False
        self.initial_checkpoint_refs={}
        self.initial_checkpoints={}
        self.initial_checkpoint_fences={}
        self.checkpoint_fence_pending=None
        self.component_cursor=""
        self.component_pending=None
        self.components=[]
        self.components_complete=False
        self.receipt_locators={}
        self.accounting_bases={}
        self.accounting_originals={}
        self.basis_entries=None
        self.basis_position=0
        self.bases_complete=False
        self.final_negative_heads={}
        self.observation=None
        self.execution_inventory=None
        self.signed_originals={}
        self.artifact_header=self.artifact_row=self.artifact_stream=self.artifact_parser=self.artifact_expected=None
        self.artifact_body=bytearray()
        self.artifact_offset=0
        self.artifact_complete=False
        self.current_column=None
        self.current_locator=None
        self.metadata_index=0
        self.selected_plan=None
        self.selected_envelope=None
        self.inputs_sealed=False
        self.read_finished=False
        self.census=self.segment=self.claim=self.terminal=None
        self.core_segments={}
        self.core_cursor=0
        self.core_complete=False
        self.reservation_scan_complete=False
        self.result=None

    def _runtime_retained_heap_bytes_v3(self):
        payload=_payload_heap_v1((self.expected_metadata,self.expected_prepared_header,self.metadata,self.body_preparation,self.admission,self.prepared,
            self.census,self.segment,self.claim,self.terminal,self.core_segments,self.execution_inventory,self.passive_policies,
            self.checkpoints,self.components,self.accounting_bases,self.accounting_originals,self.signed_originals,
            self.initial_checkpoint_refs,self.initial_checkpoints,self.initial_checkpoint_fences,
            self.artifact_header,self.artifact_row,self.artifact_body,self.artifact_expected,
            self.final_negative_heads,(_FRAMES.get(self.result) if self.result is not None else None)))
        return payload+_heap((self.metadata_tasks,self.metadata_selected,self.metadata_identity,
            self.source_columns,self.source_bodies,self.control_atoms,self.selected_headers,self.body_locators,
            self.columns,self.body_atoms,self.segments,self.metadata,self.body_preparation,
            self.admission,self.census,self.segment,self.resource_proof,self.current_column))+65536

    def require_current(self,*,meter=None):
        return require_actual_character_labor_adoption_reader_v1(self,meter=meter)

    def _epochs_at_begin_v1(self):
        with runtime_storage_quantum_v3(self.db) as meter:
            return self._epochs(meter)

    def _prepared_header_v1(self):
        with runtime_storage_quantum_v3(self.db) as meter:
            return meter.read_fixed_row(self.db,TABLE,("producing_operation_id","payload_digest","signature"),
                "bot=? AND persona=? AND kind=? AND original_ref=?",
                (*self.namespace.as_tuple,"character_labor_prepared_v1",self.expected_metadata.prepared_ref))

    def _require_resource_head_v1(self,meter):
        grant=self.resource_grant
        row=meter.read_fixed_row(self.db,"runtime_budget_grants",("version","status","signature"),
            "lease_id=? ORDER BY version DESC",(grant.lease_id,))
        if row != (grant.version,"active",self.resource_signature):
            raise AuthorityUnavailable("labor current Root resource grant changed or was revoked")

    def _metadata_v1(self,identity,meter):
        self.metadata_selected.add(identity)
        task=self.metadata_tasks.get(identity)
        if task is None:
            from .current_beta1_source_read_v3 import create_current_beta1_metadata_task_v3
            task=create_current_beta1_metadata_task_v3(self,identity)
            self.metadata_tasks[identity]=task
            return False
        return task.advance(meter)

    def _next(self,meter):
        if self.source_inspection_task is not None:
            return self._advance_source_inspection_v3(meter)
        row=meter.read_fixed_row(self.db,"graph_atoms",("token","revision","valid","type_name","value_cell_id"),
            "bot=? AND persona=? AND token>? ORDER BY token",(*self.namespace.as_tuple,self.cursor))
        if row is None:
            if self._epochs(meter)!=self.authority_epochs:
                raise AuthorityUnavailable("labor namespace metadata Source epochs changed at EOF")
            self.graph_eof=True
            for version in self.metadata.read_versions:
                key=AtomKey.from_token(version.ref)
                head=self.selected_headers.get(version.ref)
                if key.type_name not in _BODY_TYPES and (0 if head is None else head[0])!=version.version:
                    raise AuthorityUnavailable("labor original C non-Body metadata/read dependency changed")
            self.phase="core"
            return
        token,revision,valid,type_name,cell_id=row
        key=AtomKey.from_token(token)
        if (NamespaceId.from_key(key)!=self.namespace or key.type_name!=type_name
                or type(revision)is not int or revision<1 or valid not in (0,1) or cell_id is None):
            raise AuthorityUnavailable("labor namespace fixed metadata head is invalid")
        self.store._validate_key(key)
        if type_name in self.inventory_types and type_name not in _BODY_TYPES and token not in {v.ref for v in self.metadata.read_versions}:
            raise AuthorityUnavailable("labor original C admission inventory gained an unqualified current Body head")
        self.cursor=token
        self.pending=(key,revision,valid,type_name,cell_id)
        # Header/origin EOF is a metadata commitment; it never claims payload EOF.
        cell=begin_runtime_cell_read_v3(self.db,cell_id,erasure_owner_ref=token)
        self.root=canonical_digest((self.leaf_schema,self.root,token,revision,valid,type_name,cell_id,cell.header))
        expected={v.ref:v.version for v in self.metadata.read_versions}
        if token in expected or type_name in self.inventory_types or key==owner_grant_key(*self.namespace.as_tuple):
            self.selected_headers[token]=(revision,valid,cell_id,tuple(cell.header))
        from ..domains.d06 import SOURCE_CORRECTION_HEAD_TYPE
        is_control=type_name in {"memory.access",SOURCE_CORRECTION_HEAD_TYPE}
        if type_name=="memory.source":
            self._start_source_inspection_v3(self,meter)
        elif is_control:
            self.cell=cell
            self._begin_census_value_v3(cell.header[0],meter)
            self.body=bytearray()
        else:
            self.count+=1
            self.pending=None

    def _finish_census_value_v3(self,key,revision,valid,type_name,cell,digest):
        import json
        self._reserve(len(self.body)*8+32768)
        atom=GraphAtom(key,revision,json.loads(self.body),bool(valid))
        self.control_atoms[key.token]=atom
        self.heads[key.token]=(revision,valid,cell)

    def _graph_eof_v3(self):
        self.phase="core"

    def _seal_metadata_v1(self,meter):
        m,b,a=self.metadata,self.body_preparation,self.admission
        if (self.policy!=b.policy
                or self.graph_stamp[0].graph_revision!=self.gate.before_graph_revision
                or self.graph_stamp[1].revision!=self.gate.before_graph_epoch
                or self.graph_stamp[0].requirements is None
                or not self.graph._anchor_matches(self.graph_stamp[0].requirements,self.gate.before_anchor)):
            raise AuthorityUnavailable("labor original C/current adoption metadata stamp differs")
        from ..runtime_contracts import CommitReceipt
        from ..graph_types import NamespaceEpoch
        op=m.binding.prepare_operation_id
        rt=self.metadata_tasks[("prepare_receipt",op)]
        reads=self.metadata_tasks[("prepare_reads",op)]
        writes=self.metadata_tasks[("prepare_writes",op)]
        def versions(task):
            if type(task.result)is not list:raise AuthorityUnavailable("labor C event versions lack complete metadata EOF")
            return tuple(GraphVersion(AtomKey.from_token(token),revision)for token,revision in task.result)
        receipt=CommitReceipt("committed",op,*rt.metadata,versions(reads),versions(writes),
            (NamespaceEpoch(*self.namespace.as_tuple,reads.metadata[1]),),
            tuple(rt.result["ledger_refs"]),tuple(rt.result["outbox_refs"]))
        expected={v.key.token:v.revision for v in receipt.read_versions}
        expected.update({v.key.token:v.revision for v in receipt.write_versions})
        if (canonical_digest(receipt)!=m.receipt_digest or dict((v.ref,v.version)for v in m.read_versions)!=expected
                or reads.metadata!=writes.metadata or receipt.invalidated_epochs[0].revision!=m.graph_epoch
                or rt.column.canonical_digest!=canonical_digest(rt.result)):
            raise AuthorityUnavailable("labor metadata does not match the real complete C receipt/event/read-set")
        self.issuer._signer.verify(SIGN_KIND,canonical_serialize((self.namespace,
            "character_labor_prepared_v1",m.prepared_ref,self.expected_prepared_header[1])),
            self.expected_prepared_header[2])
        self.prepare_receipt=receipt
        self.inventory_types=frozenset(self.action_template["types"])|_BODY_TYPES
        self.owner_groups=tuple((purpose,tuple(m.plan.audiences),tuple(m.source_roots))
            for purpose in ("context","consolidation"))
        from .d01_production_operations_v1 import production_read_plan_v1
        self.selected_plan=production_read_plan_v1(self.inventory_types,
            tuple(AtomKey.from_token(v.ref)for v in m.read_versions),m.source_roots)
        self.metadata_identity=(self.work,self.operation,self.scope,self.gate,m,b,a,self.policy,
            tuple((identity,task.metadata,task.column.canonical_digest,task.column.byte_count)
                for identity,task in self.metadata_tasks.items()),
            self.graph_stamp,self.query,self.selection_digest,self.owner_groups)
        self.metadata_sealed=True
        self.phase="census"

    def _new_column_v1(self,locator,cell=None):
        from .current_method_learning_read_v3 import MethodJSONColumnV3,_ISSUER
        self.body_locators.add(locator)
        table,column,key_columns,key=locator
        result=MethodJSONColumnV3(_ISSUER,self,table=table,column=column,key_columns=key_columns,key=key,cell=cell)
        self.columns[locator]=result
        return result

    def _finish_column_v1(self,column,meter):
        self.operation.reserve_retained_state_growth_v3(self,column.byte_count*10+65536)
        try:
            value=column.json_v3()
            _COLUMN_VALUES[column]=value
        finally:
            self.operation.finish_retained_state_growth_v3(self)
        return value

    def _sources_v1(self,meter):
        from .current_beta1_source_read_v3 import qualify_current_beta1_source_groups_v3
        from .current_method_learning_read_v3 import MethodInputNeededV3
        try:
            self.source_qualification=qualify_current_beta1_source_groups_v3(self,self.metadata.source_roots)
        except MethodInputNeededV3 as needed:
            kind,ref=needed.request
            if kind!="beta1_source_metadata":
                raise AuthorityUnavailable("labor Source walker requested an unrelated Method input")
            from .current_beta1_source_read_v3 import create_current_beta1_source_metadata_task_v3
            task=create_current_beta1_source_metadata_task_v3(self,ref)
            task.advance(meter)
            return
        versions={v.ref:v.version for v in self.metadata.read_versions}
        if any(versions.get(v.key.token)!=v.revision for v in self.source_qualification.versions):
            raise AuthorityUnavailable("labor current Source/ACL/Correction ancestry differs from original C read-set")
        self.phase="source_body"

    def _source_body_v1(self,meter):
        todo=next((ref for ref in self.source_qualification.source_refs if ref not in self.source_bodies),None)
        if todo is None:
            self.source_all_complete=True
            self.phase="prepared"
            return
        head=self.heads.get(todo)
        if head is None or head[1]!=1:
            raise AuthorityUnavailable("labor qualified Source lacks its actual namespace metadata head")
        locator=("graph_atoms","value",("token","bot","persona"),(todo,*self.namespace.as_tuple))
        column=self.source_columns.get(todo)
        if column is None:
            cell=begin_runtime_cell_read_v3(self.db,head[2],erasure_owner_ref=todo)
            column=self._new_column_v1(locator,cell)
            self.source_columns[todo]=column
            return
        if not column.advance(meter):return
        from ..memory_types import SourceRecord
        value=self._finish_column_v1(column,meter)
        SourceRecord.from_dict(value)
        original=self.source_inspections[todo]
        if (column.sha256!=original.payload_sha256 or original.revision!=head[0]
                or column.canonical_digest!=original.semantic_digest
                or any((tuple(value[k]) if type(value.get(k)) is list else value.get(k))!=v
                    for k,v in original.metadata.items())):
            raise AuthorityUnavailable("labor whole Source differs from its actual inspection metadata/producer")
        self.source_bodies[todo]=value
        self.operation.refresh_retained_state_v3(self)

    def _prepared_v1(self,meter):
        locator=(TABLE,"payload_json",("bot","persona","kind","original_ref"),
            (*self.namespace.as_tuple,"character_labor_prepared_v1",self.metadata.prepared_ref))
        column=self.columns.get(locator)
        if column is None:
            self._new_column_v1(locator)
            return
        if not column.advance(meter):return
        if column.canonical_digest!=self.metadata.prepared_digest or self._prepared_header_v1()!=self.expected_prepared_header:
            raise AuthorityUnavailable("labor new Prepared whole EOF differs from its signed metadata/header")
        value=self._finish_column_v1(column,meter)
        from .d11_life_preparation_v1 import life_prepared_from_wire_v1,D11CharacterLaborLifePreparedV1
        meter.charge_encode(column.byte_count)
        self.operation.reserve_retained_state_growth_v3(self,column.byte_count*12+65536)
        try:
            self.prepared=life_prepared_from_wire_v1(value)
        finally:self.operation.finish_retained_state_growth_v3(self)
        p,m=self.prepared,self.metadata
        if (type(p)is not D11CharacterLaborLifePreparedV1 or p.binding!=m.binding or p.plan!=m.plan
                or p.prepare_operation_id!=self.expected_prepared_header[0]
                or p.labor_admission_ref!=m.labor_admission_ref or p.labor_admission_digest!=m.labor_admission_digest
                or p.admission_ref!="d08-life-admission:"+m.binding.execution_id
                or p.admission_digest!=self.metadata_tasks[("action_admission",p.admission_ref)].metadata[1]
                or any(getattr(p,name)!=getattr(m,name)for name in (
                    "clock_mapping_json","clock_original_json","quote_json","signed_grant_json",
                    "signed_grant_signature","parent_budget_json","reserve_receipt_json","owner_guard_json",
                    "prepare_command_identity_json","owner_prepare_request_digest","owner_prepare_attempt_id",
                    "prepared_at_utc","requirements_json","graph_revision","graph_epoch",
                    "job_projection_json","job_projection_revision"))):
            raise AuthorityUnavailable("labor full new Prepared changed its bodyless B/C/clock/Owner commitments")
        self.signed_originals[("character_labor_prepared_v1",m.prepared_ref)]=(value,self.expected_prepared_header[0])
        self.phase="artifact"

    def _artifact_v1(self,meter):
        from .d11_life_source_note_v1 import STAGE_TABLE,artifact_value_v1
        from .runtime_canonical_stream_v3 import RuntimeCanonicalStreamV3
        from .c09_paged_sql_v2 import read_legacy_sql_cell_fragment_v2
        import hashlib
        if self.terminal.status!="completed":
            self.artifact_complete=True
            self.phase="bodies"
            return
        b=self.gate.binding
        header=meter.read_fixed_row(self.db,STAGE_TABLE,
            ("binding_digest","artifact_ref","artifact_digest","artifact_length"),
            "bot=? AND persona=? AND execution_id=?",(*self.namespace.as_tuple,b.execution_id))
        expected=(b.digest,b.artifact_ref,self.terminal.payload.artifact_digest,self.terminal.payload.artifact_length)
        if header!=expected or type(header[3])is not int or not 1<=header[3]<=262144:
            raise AuthorityUnavailable("labor durable artifact fixed header differs from actual signed terminal/binding")
        if self.artifact_header is None:
            if not self.source_all_complete:
                raise AuthorityUnavailable("labor artifact remains sealed before its actual whole-Source EOF")
            self.artifact_header=header
            size=len(self.prepared.source_record_json)*6
            meter.charge_encode(size)
            self.operation.reserve_retained_state_growth_v3(self,size*4+65536)
            try:
                self.artifact_expected=artifact_value_v1(self.prepared)
                self.artifact_stream=RuntimeCanonicalStreamV3(self.artifact_expected,self.operation)
                self.artifact_parser=hashlib.sha256()
            finally:self.operation.finish_retained_state_growth_v3(self)
            return
        if self.artifact_header!=header:
            raise AuthorityUnavailable("labor durable artifact changed during its actual physical EOF")
        if not self.artifact_stream.complete:
            self.artifact_stream.read_fragment(meter)
            return
        if self.artifact_offset<header[3]:
            raw,total,kind=read_legacy_sql_cell_fragment_v2(self.db,table=STAGE_TABLE,
                column="artifact_bytes",where="bot=? AND persona=? AND execution_id=?",
                parameters=(*self.namespace.as_tuple,b.execution_id),start=self.artifact_offset,
                length=min(1024,header[3]-self.artifact_offset),meter=meter)
            if kind!="blob"or total!=header[3]:
                raise AuthorityUnavailable("labor durable artifact physical BLOB identity changed")
            self.operation.reserve_retained_state_growth_v3(self,len(raw)*4+4096)
            try:
                self.artifact_body.extend(raw)
                self.artifact_parser.update(raw)
                self.artifact_offset+=len(raw)
            finally:self.operation.finish_retained_state_growth_v3(self)
            return
        if (self.artifact_parser.hexdigest()!=header[2]
                or self.artifact_stream.hash.hexdigest()!=header[2]
                or self.artifact_stream.offset!=header[3]):
            raise AuthorityUnavailable("labor artifact physical EOF does not equal its exact canonical Source-note recipe")
        self.operation.reserve_retained_state_growth_v3(self,header[3]*2+4096)
        try:
            self.artifact_row=(header[0],header[1],bytes(self.artifact_body),header[2],header[3])
            self.artifact_body.clear()
            self.artifact_stream=self.artifact_parser=self.artifact_expected=None
            self.artifact_complete=True
            self.phase="bodies"
        finally:self.operation.finish_retained_state_growth_v3(self)

    def _bodies_v1(self,meter):
        if self.current_column is not None:
            c=self.current_column
            if not c.advance(meter):return
            value=self._finish_column_v1(c,meter)
            token=self.current_locator[3][0]
            h=self.selected_headers[token]
            self.body_atoms[token]=GraphAtom(AtomKey.from_token(token),h[0],value,bool(h[1]),_canonical_original=c)
            self.current_column=self.current_locator=None
            self.operation.refresh_retained_state_v3(self)
            return
        tokens=sorted(ref for ref in self.selected_headers if ref>self.body_cursor)
        if not tokens:
            self.reservation_scan_complete=True
            self.phase="passive"
            return
        token=tokens[0]
        self.body_cursor=token
        h=self.selected_headers[token]
        key=AtomKey.from_token(token)
        if key.type_name=="memory.source":
            if token not in self.source_bodies:
                raise AuthorityUnavailable("labor selected Source is outside the actual qualified full closure")
            self.body_atoms[token]=GraphAtom(key,h[0],self.source_bodies[token],bool(h[1]),_canonical_original=self.source_columns[token])
            return
        if key.token in self.control_atoms:
            self.body_atoms[token]=self.control_atoms[token]
            return
        locator=("graph_atoms","value",("token","bot","persona"),(token,*self.namespace.as_tuple))
        self.current_locator=locator
        self.current_column=self._new_column_v1(locator,
            begin_runtime_cell_read_v3(self.db,h[2],erasure_owner_ref=token))

    def _passive_v1(self,meter):
        if self.passive_pending is not None:
            identity=self.passive_pending
            if not self._metadata_v1(identity,meter):return
            self.passive_policies.append(self.metadata_tasks[identity].result)
            self.passive_cursor=identity[1]
            self.passive_pending=None
            self.operation.refresh_retained_state_v3(self)
            return
        row=meter.read_fixed_row(self.db,"graph_d02_production_policies_v1",("policy_ref","revision"),
            "bot=? AND persona=? AND kind='passive' AND profile_id=? "
            "AND (policy_ref>? OR (policy_ref=? AND revision>?)) ORDER BY policy_ref,revision",
            (*self.namespace.as_tuple,self.policy.profile_id,self.passive_cursor[0],
                self.passive_cursor[0],self.passive_cursor[1]))
        if row is None:
            self.passive_complete=True
            self.phase="segments"
            return
        self.passive_pending=("passive_policy",tuple(row))

    def _segments_v1(self,meter):
        if self.current_column is not None:
            c=self.current_column
            if not c.advance(meter):return
            header=self.current_segment_header
            if c.canonical_digest!=header[1]:
                raise AuthorityUnavailable("labor prior segment whole EOF changed its signed commitment")
            ref=self.current_locator[3][-1]
            self.issuer._signer.verify(SIGN_KIND,
                canonical_serialize((self.namespace,SEGMENT_KIND,ref,header[1])),header[2])
            value=self._finish_column_v1(c,meter)
            segment=character_work_segment_from_wire_v1(value)
            _verify_segment_v1(self,segment)
            if segment.segment_id!=ref:
                raise AuthorityUnavailable("labor retained prior segment differs from its exact original locator")
            self.segments.append(segment)
            self.segment_cursor=ref
            self.current_column=self.current_locator=None
            self.operation.refresh_retained_state_v3(self)
            return
        row=meter.read_fixed_row(self.db,TABLE,
            ("original_ref","producing_operation_id","payload_digest","signature"),
            "bot=? AND persona=? AND kind=? AND original_ref>? ORDER BY original_ref",
            (*self.namespace.as_tuple,SEGMENT_KIND,self.segment_cursor))
        if row is None:
            combined=dict(self.core_segments)
            for segment in self.segments:
                prior=combined.get(segment.segment_id)
                if prior is not None and prior!=segment:
                    raise AuthorityUnavailable("labor Graph/Core segment originals conflict for the same actual claim")
                combined[segment.segment_id]=segment
            self.segments=list(combined.values())
            self.phase="accounting_bases"
            return
        ref,*header=row
        self.current_segment_header=tuple(header)
        self.current_locator=(TABLE,"payload_json",("bot","persona","kind","original_ref"),
            (*self.namespace.as_tuple,SEGMENT_KIND,ref))
        self.current_column=self._new_column_v1(self.current_locator)

    def _accounting_bases_v1(self,meter):
        if self.basis_entries is None:
            self.basis_entries=tuple(e for e in self.census.entries
                if e.classification in {"character_labor_v1","retained_duration_v1"})
        if self.basis_position==len(self.basis_entries):
            self.bases_complete=True
            self.phase="checkpoints"
            return
        entry=self.basis_entries[self.basis_position]
        for kind in ("duration_basis","duration_accounting"):
            if not self._metadata_v1((kind,entry.execution_id),meter):return
        self.basis_position+=1

    def _checkpoint_receipt_v1(self,operation,activity,meter):
        self.receipt_locators[operation]=activity
        for kind in ("checkpoint_receipt","checkpoint_reads","checkpoint_writes"):
            if not self._metadata_v1((kind,operation),meter):return None
        from ..runtime_contracts import CommitReceipt
        from ..graph_types import NamespaceEpoch
        rt=self.metadata_tasks[("checkpoint_receipt",operation)]
        rd=self.metadata_tasks[("checkpoint_reads",operation)]
        wr=self.metadata_tasks[("checkpoint_writes",operation)]
        if rt.metadata[1]!=activity or rd.metadata!=wr.metadata:
            raise AuthorityUnavailable("labor checkpoint receipt/event identity differs")
        def gv(task):
            return tuple(GraphVersion(AtomKey.from_token(k),v)for k,v in task.result)
        return CommitReceipt("committed",operation,*rt.metadata,gv(rd),gv(wr),
            (NamespaceEpoch(*self.namespace.as_tuple,rd.metadata[1]),),
            tuple(rt.result["ledger_refs"]),tuple(rt.result["outbox_refs"]))

    def _initial_checkpoint_receipt_v1(self,operation,ref,revision,meter):
        from ..contracts import Event,Scope
        import json
        if revision!=1:
            raise AuthorityUnavailable("initial Body installation checkpoint is not its actual first GraphVersion")
        original_ref=self.initial_checkpoint_refs.get(operation)
        if original_ref is None:
            rows=self.db.execute("SELECT original_ref FROM "+TABLE+
                " WHERE bot=? AND persona=? AND kind='body_policy_checkpoint_v1' AND producing_operation_id=?"
                " ORDER BY original_ref LIMIT 2",(*self.namespace.as_tuple,operation)).fetchall()
            meter.charge_read(sum(len(row[0].encode("utf-8"))for row in rows))
            if len(rows)!=1:
                raise AuthorityUnavailable("initial Body history has no unique signed installation checkpoint")
            self.initial_checkpoint_refs[operation]=rows[0][0]
            self.operation.refresh_retained_state_v3(self)
            return None
        if not self._metadata_v1(("body_install",original_ref),meter):return None
        original=self.initial_checkpoints[operation]
        receipt=original.graph_receipt
        if not any(v.ref==ref and v.version==revision for v,_ in original.write_digests):
            raise AuthorityUnavailable("initial Body checkpoint does not contain this exact selected historical state")
        raw=json.loads(original.event_json)
        event=Event(Scope(**raw["scope"]),raw["event_id"],raw["occurred_at"],raw["kind"],raw["payload"])
        expected={
            "body_install_reads":[[v.ref,0]for v,_ in original.write_digests],
            "body_install_writes":[[v.key.token,v.revision]for v in receipt.revisions],
            "body_install_epochs":[[*self.namespace.as_tuple,original.before_epoch]],
            "body_install_invalidated":[[v.key.token,v.revision]for v in receipt.invalidated]}
        for kind,value in expected.items():
            if not self._metadata_v1((kind,operation),meter):return None
            task=self.metadata_tasks[(kind,operation)]
            if task.result!=value or task.metadata!=(event.digest,receipt.epoch.revision):
                raise AuthorityUnavailable("initial Body checkpoint differs from the actual complete Graph event metadata")
        for version in (*receipt.revisions,*receipt.invalidated):
            history=meter.read_fixed_row(self.db,"graph_history",
                ("valid","event_bot","event_persona","event_session","event_id"),
                "token=? AND revision=?",(version.key.token,version.revision))
            if history!=(int(version in receipt.revisions),*self.namespace.as_tuple,event.scope.session,operation):
                raise AuthorityUnavailable("initial Body checkpoint members lack their exact valid producer history")
        if operation not in self.initial_checkpoint_fences:
            self.checkpoint_fence_pending=operation
            self.phase="checkpoint_fence"
            return None
        return receipt

    def _checkpoints_v1(self,meter):
        if self.checkpoint_queue is None:
            ref=self.census.body_state.ref
            versions={self.census.body_state.version}
            has_checkpoint_head=False
            for atom in self.body_atoms.values():
                if atom.key.type_name=="d02.character_labor_rebuild_head.v1" and atom.valid:
                    value=atom.value
                    if value["profile_id"]!=self.policy.profile_id:continue
                    has_checkpoint_head=True
                    if "checkpoint_revision" not in value:
                        raise AuthorityUnavailable("labor historical checkpoint lacks its actual fixed GraphVersion")
                    if value["checkpoint_ref"]!=ref:
                        raise AuthorityUnavailable("labor checkpoint changed its actual Body state ref")
                    versions.add(value["checkpoint_revision"])
            if not has_checkpoint_head:versions.add(1)
            self.checkpoint_queue=[(ref,revision)for revision in sorted(versions)]
        if not self.checkpoint_queue:
            self.checkpoint_complete=True
            self.phase="components"
            return
        ref,revision=self.checkpoint_queue[0]
        if self.checkpoint_pending is None:
            header=meter.read_fixed_row(self.db,"graph_history",
                ("valid","value_cell_id","event_bot","event_persona","event_session","event_id"),
                "token=? AND revision=?",(ref,revision))
            if header is None or header[0]!=1 or header[2:4]!=self.namespace.as_tuple or header[1]is None:
                raise AuthorityUnavailable("labor checkpoint lacks its actual valid same-namespace history")
            locator=("graph_history","value",("token","revision"),(ref,revision))
            column=self._new_column_v1(locator,begin_runtime_cell_read_v3(self.db,header[1],erasure_owner_ref=ref))
            self.checkpoint_pending=(header,column)
            return
        header,column=self.checkpoint_pending
        if not column.complete:
            column.advance(meter)
            return
        if header[4]=="c04.fixed_body_install.v1":
            receipt=self._initial_checkpoint_receipt_v1(header[5],ref,revision,meter)
        else:
            receipt=self._checkpoint_receipt_v1(header[5],header[4],meter)
        if receipt is None:return
        from ..domains.d02 import BodyState
        from ..graph_types import GraphReceipt
        from ..runtime_contracts import VersionedRef
        value=self._finish_column_v1(column,meter)
        state=BodyState(**value)
        if (state.version!=revision or state.profile_id!=self.policy.profile_id
                or GraphVersion(AtomKey.from_token(ref),revision)not in (
                    receipt.revisions if type(receipt)is GraphReceipt else receipt.write_versions)):
            raise AuthorityUnavailable("labor checkpoint Body version/profile is not its real committing event")
        for atom in self.body_atoms.values():
            if (atom.key.type_name=="d02.character_labor_rebuild_head.v1" and atom.valid
                    and atom.value["profile_id"]==self.policy.profile_id
                    and atom.value["checkpoint_revision"]==revision
                    and (atom.value["checkpoint_digest"]!=column.canonical_digest
                        or atom.value["checkpoint_cursor"]!=state.cursor)):
                raise AuthorityUnavailable("labor checkpoint original differs from its actual rebuild head")
        if type(receipt)is GraphReceipt:
            original=self.initial_checkpoints[header[5]]
            if (VersionedRef(ref,revision),column.canonical_digest)not in original.write_digests:
                raise AuthorityUnavailable("labor initial Body canonical EOF differs from its independently signed policy checkpoint")
        self.checkpoints[(ref,revision)]=(state,receipt,column.canonical_digest,header)
        self.checkpoint_pending=None
        self.checkpoint_queue.pop(0)
        self.operation.refresh_retained_state_v3(self)

    def _components_v1(self,meter):
        if self.component_pending is not None:
            identity=self.component_pending
            if not self._metadata_v1(identity,meter):return
            task=self.metadata_tasks[identity]
            receipt=self._checkpoint_receipt_v1(task.metadata[0],
                self.component_activity,meter) if self.component_activity is not None else None
            if self.component_activity is None:
                head=meter.read_fixed_row(self.db,"graph_bundle_operations",("activity_id",),
                    "bot=? AND persona=? AND operation_id=?",(*self.namespace.as_tuple,task.metadata[0]))
                if head is None:raise AuthorityUnavailable("labor component lost its real committing operation")
                self.component_activity=head[0]
                return
            if receipt is None:return
            self.components.append((task.result,task.metadata[0],task.metadata[1],receipt))
            self.component_cursor=identity[1]
            self.component_pending=None
            self.component_activity=None
            self.operation.refresh_retained_state_v3(self)
            return
        row=meter.read_fixed_row(self.db,"graph_d02_action_components_v1",("original_ref",),
            "bot=? AND persona=? AND original_ref>? ORDER BY original_ref",
            (*self.namespace.as_tuple,self.component_cursor))
        if row is None:
            self.components_complete=True
            self.inputs_sealed=True
            self.complete=True
            self.result=PreparedCharacterLaborAdoptionV1(_ISSUER,self)
            self.phase="sealed"
            return
        self.component_pending=("component",row[0])
        self.component_activity=None

    def advance_v1(self,meter):
        self.require_current(meter=meter)
        if self.phase=="resource":
            if self._metadata_v1(("root_grant",self.bundle.installation_policy.root_grant.lease_id),meter):
                self.phase="metadata"
        elif self.phase=="metadata":
            todo=(("prepared_metadata","character-labor-prepared-metadata:"+self.gate.binding.execution_id),
                ("body_preparation",self.expected_metadata.plan.labor_body_preparation_original.original_ref),
                ("admission",self.expected_metadata.labor_admission_ref),
                ("action_admission","d08-life-admission:"+self.gate.binding.execution_id),
                ("prepare_receipt",self.gate.binding.prepare_operation_id),
                ("prepare_reads",self.gate.binding.prepare_operation_id),
                ("prepare_writes",self.gate.binding.prepare_operation_id))
            if self.metadata_index<len(todo):
                if self._metadata_v1(todo[self.metadata_index],meter):self.metadata_index+=1
            elif self._metadata_v1(("policy",self.body_preparation.policy.policy_ref),meter):
                self._seal_metadata_v1(meter)
        elif self.phase=="census":
            self._cell(meter) if self.cell is not None else self._next(meter)
        elif self.phase=="sources":self._sources_v1(meter)
        elif self.phase=="source_body":self._source_body_v1(meter)
        elif self.phase=="prepared":self._prepared_v1(meter)
        elif self.phase=="artifact":self._artifact_v1(meter)
        elif self.phase=="bodies":self._bodies_v1(meter)
        elif self.phase=="passive":self._passive_v1(meter)
        elif self.phase=="segments":self._segments_v1(meter)
        elif self.phase=="accounting_bases":self._accounting_bases_v1(meter)
        elif self.phase=="checkpoints":self._checkpoints_v1(meter)
        elif self.phase=="components":self._components_v1(meter)

    def release_payload_v3(self):
        if self not in _READERS:return
        from .current_beta1_source_read_v3 import release_current_beta1_source_work_v3
        from .source_inspection_metadata_read_v3 import release_inspection_metadata_owner_v3
        first=None
        for label,action in (("Source tasks",lambda:release_current_beta1_source_work_v3(self)),
                ("inspection metadata",lambda:release_inspection_metadata_owner_v3(self)),
                ("Owner metadata",lambda:self.general_owner_entry.release_v3()
                    if self.general_owner_entry is not None else None)):
            try:action()
            except BaseException as later:
                if first is None:first=later
                else:first.add_note("labor "+label+" release failed: "+type(later).__name__)
        _READERS.pop(self,None)
        if self.result is not None:
            _INPUTS.pop(self.result,None);_FRAMES.pop(self.result,None);_BODY_READERS.pop(self.result,None)
        self.metadata_tasks.clear();self.metadata_selected.clear()
        for column in self.columns.values():_COLUMN_VALUES.pop(column,None)
        self.columns.clear();self.source_columns.clear();self.source_bodies.clear()
        self.source_inspections.clear();self.sources.clear();self.heads.clear()
        self.control_atoms.clear();self.selected_headers.clear();self.body_atoms.clear()
        self.segments.clear();self.passive_policies.clear();self.body_locators.clear()
        self.checkpoints.clear();self.components.clear();self.accounting_bases.clear();self.accounting_originals.clear()
        self.initial_checkpoint_refs.clear();self.initial_checkpoints.clear();self.initial_checkpoint_fences.clear()
        self.checkpoint_fence_pending=None
        self.final_negative_heads.clear();self.signed_originals.clear()
        self.artifact_header=self.artifact_row=self.artifact_stream=self.artifact_parser=self.artifact_expected=None
        self.artifact_body.clear();self.execution_inventory=None
        if self.observation is not None:_OBSERVED.pop(self.observation,None)
        self.observation=None
        self.current_column=self.current_locator=self.source_inspection_task=None
        self.source_qualification=self.selected_plan=self.resource_proof=None
        self.metadata_identity=self.metadata=self.body_preparation=self.admission=self.prepared=None
        self.action_admission=self.action_template=None
        self.census=self.segment=self.claim=self.terminal=None
        self.core_segments.clear()
        self.basis_entries=self.checkpoint_pending=self.component_pending=None
        self.expected_metadata=self.expected_prepared_header=None
        self.body=None;self.fragment=b"";self.cell=self.parser=self.pending=None
        self.result=None
        if first is not None:raise first


def _verify_segment_v1(reader,segment):
    import hmac,hashlib
    from .d11_character_work_segment_v1 import CharacterWorkSegmentOriginalV1
    if type(segment)is not CharacterWorkSegmentOriginalV1 or segment.namespace!=reader.namespace:
        raise AuthorityUnavailable("labor segment has another closed schema/namespace")
    raw=plain_v1(segment)
    signature=raw.pop("signature")
    key=hmac.new(reader.bundle.d11_signing_key,b"sylanne.authority.d11-life-signing.v1",hashlib.sha256).digest()
    expected=hmac.new(key,canonical_serialize(raw).encode(),hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature,expected):
        raise AuthorityUnavailable("labor segment lost its actual installed Authority signature")
    return segment


def _capture_current_core_v1(r):
    from ..authority_service.character_labor_census_v1 import verify_character_labor_census_v1
    from .d11_life_contract_v1 import D11LifeClaimV1,D11LifeTerminalV1
    if r.db.in_transaction or r.store._lock._is_owned():
        raise AuthorityUnavailable("labor Core originals must be observed outside Graph SQL/lock")
    r.life_port.life_adoption_bridge_v1(binding=r.gate.binding,action="validate",gate=r.gate)
    claim,terminal=r.life_port.read_own_d11_life_execution_original_v1(binding=r.gate.binding)
    if (type(claim)is not D11LifeClaimV1 or type(terminal)is not D11LifeTerminalV1
            or terminal!=r.gate.terminal or terminal.claim!=claim
            or terminal.payload.prepared_digest!=r.metadata.prepared_digest):
        raise AuthorityUnavailable("labor adoption lost its actual same-bridge signed claim and terminal")
    segment=r.life_port.read_d11_character_work_segment_v1(binding=r.gate.binding,permit=r.gate.permit)
    _verify_segment_v1(r,segment)
    b,m=r.body_preparation,r.metadata
    if (segment.binding_digest!=r.gate.binding.digest or segment.prepared_digest!=m.prepared_digest
            or segment.admission_ref!=m.labor_admission_ref
            or segment.admission_original_digest!=m.labor_admission_digest
            or segment.body_preparation_ref!=m.plan.labor_body_preparation_original.original_ref
            or segment.body_preparation_digest!=m.plan.labor_body_preparation_original.original_digest
            or (segment.recipe_ref,segment.recipe_revision,segment.recipe_digest)!=(b.recipe_ref,b.recipe_revision,b.recipe_digest)
            or segment.policy_digest!=canonical_digest(plain_v1(b.policy))
            or (segment.claim_sequence,segment.claim_digest,segment.claim_original_ref)
                !=(claim.claim_sequence,claim.claim_digest,claim.original_ref)
            or (segment.terminal_sequence,segment.terminal_digest,segment.terminal_original_ref)
                !=(terminal.terminal_sequence,terminal.terminal_digest,terminal.original_ref)
            or segment.status!=terminal.status):
        raise AuthorityUnavailable("labor actual segment is not this same B/C/claim/terminal/clock")
    from ..authority_service.d11_life_execution_inventory_v1 import verify_life_execution_inventory_v1
    inventory=r.life_port.read_d11_life_execution_inventory_v1(
        namespace=r.gate.binding.authority_namespace,permit=r.gate.permit)
    verify_life_execution_inventory_v1(inventory,r.issuer)
    census=r.life_port.read_d11_character_labor_census_v1(namespace=r.gate.binding.authority_namespace,
        permit=r.gate.permit,body_profile_id=b.policy.profile_id)
    verify_character_labor_census_v1(r.issuer,census,permit=r.gate.permit)
    if (canonical_digest(inventory)!=census.mixed_inventory_digest
            or inventory.namespace!=r.namespace or inventory.authority_namespace!=r.scope.authority_namespace
            or inventory.authority_id!=r.gate.binding.authority_id
            or inventory.installation_id!=r.gate.binding.installation_id
            or inventory.manifest_digest!=r.gate.binding.manifest_digest
            or inventory.anchor!=r.gate.after_anchor or inventory.permit_digest!=canonical_digest(r.gate.permit)):
        raise AuthorityUnavailable("labor current signed execution inventory differs from its original WRITE and complete mixed census")
    r.execution_inventory=inventory
    if (census.namespace!=r.namespace or census.selection_digest!=r.selection_digest
            or census.graph_stamp!=(r.graph_stamp[1].revision,*r.authority_epochs)):
        raise AuthorityUnavailable("labor complete mixed census differs from its actual selected Graph/Body stamp")
    target=tuple(e for e in census.entries if e.execution_id==r.gate.binding.execution_id)
    if (len(target)!=1 or target[0].binding!=r.gate.binding
            or target[0].classification!="character_labor_v1"
            or target[0].prepared_digest!=m.prepared_digest
            or target[0].prepared_metadata_digest!=r.metadata_tasks[("prepared_metadata",
                "character-labor-prepared-metadata:"+r.gate.binding.execution_id)].metadata[1]
            or target[0].claim_digest!=claim.claim_digest or target[0].terminal_digest!=terminal.terminal_digest):
        raise AuthorityUnavailable("labor full census did not include this actual new Prepared and terminal")
    r.claim,r.terminal,r.segment,r.census=claim,terminal,segment,census
    r.core_segments[segment.segment_id]=segment
    r.operation.refresh_retained_state_v3(r)
    r.phase="core_pages"


class PreparedCharacterLaborAdoptionV1:
    def __init__(self,issuer,reader):
        if issuer is not _ISSUER or not reader.inputs_sealed or not reader.source_all_complete:
            raise AuthorityUnavailable("labor adoption input seal requires actual complete Source and Body EOF")
        self.owner=reader
        self.graph,self.operation,self.scope=reader.graph,reader.operation,reader.scope
        self.prepared,self.body_preparation,self.admission=reader.prepared,reader.body_preparation,reader.admission
        self.segment,self.census=reader.segment,reader.census
        self.source_versions=reader.source_qualification.versions
        self.resource_proof=reader.resource_proof
        self.gate=reader.gate
        self.identity=(reader,reader.work,reader.operation,reader.scope,reader.metadata_identity,
            reader.root,reader.count,reader.prepared,reader.body_preparation,reader.admission,
            reader.segment,reader.census,reader.resource_proof,reader.source_qualification,
            tuple((key,column.canonical_digest,column.byte_count)for key,column in reader.columns.items()),
            tuple(reader.segments))
        _INPUTS[self]=self.identity

    def _actual_v1(self):
        r=require_actual_character_labor_adoption_reader_v1(self.owner)
        if (_INPUTS.get(self)is not self.identity or r.result is not self
                or not r.inputs_sealed or not r.source_all_complete
                or (self.prepared,self.body_preparation,self.admission,self.segment,self.census,self.resource_proof)
                    !=(r.prepared,r.body_preparation,r.admission,r.segment,r.census,r.resource_proof)):
            raise AuthorityUnavailable("labor retained inputs lost their actual same-Work EOF seal")
        return r

    def require_inputs_v1(self,graph,*,gate,db,scope,owner):
        r=self._actual_v1()
        if (graph is not r.graph or db is not r.db or scope is not r.scope or gate is not r.gate
                or owner is not r.owner_binding or not db.in_transaction or not r.store._lock._is_owned()):
            raise AuthorityUnavailable("labor final CAS requires its original WRITE/current Owner/selected Work")
        with runtime_storage_quantum_v3(db)as meter:
            r.require_current(meter=meter)
            r.source_qualification.require_for_v3(r)
            for task in r.metadata_tasks.values():task.require_header_v3(meter)
            if r._prepared_header_v1()!=r.expected_prepared_header:
                raise AuthorityUnavailable("labor final CAS new Prepared header changed")
            for token,head in r.selected_headers.items():
                row=meter.read_fixed_row(db,"graph_atoms",("revision","valid","value_cell_id"),
                    "bot=? AND persona=? AND token=?",(*r.namespace.as_tuple,token))
                if row!=head[:3]:
                    raise AuthorityUnavailable("labor selected Body/metadata head changed before final CAS")
        return self

    def head_v1(self,key):
        r=self._actual_v1()
        if NamespaceId.from_key(key)!=r.namespace:
            raise AuthorityUnavailable("labor sealed head crossed namespace")
        atom=r.body_atoms.get(key.token) or r.final_negative_heads.get(key.token)
        if atom is None:
            if key.token in r.selected_headers:
                raise AuthorityUnavailable("labor selected Body has not completed its real EOF")
            if key not in r.selected_plan.exact_keys and key.type_name not in _BODY_TYPES:
                raise AuthorityUnavailable("labor absent head is outside its fixed sealed recipe")
            return GraphAtom(key,0,{},False)
        return atom

    def complete_inventory_v1(self,type_name):
        r=self._actual_v1()
        if type_name not in r.inventory_types or not r.reservation_scan_complete:
            raise AuthorityUnavailable("labor complete inventory lacks its actual namespace/body EOF")
        return tuple(atom for token,atom in sorted(r.body_atoms.items())if atom.key.type_name==type_name)

    def require_frame_v1(self,frame):
        from .domain_production_contracts_v1 import CurrentOperationFrameV1
        from .d11_life_terminal_v1 import life_adoption_operation_id_v1
        r=self._actual_v1()
        if (type(frame)is not CurrentOperationFrameV1
                or frame.envelope.identity.operation_id!=life_adoption_operation_id_v1(r.gate.binding)
                or frame.envelope.authority is not r.authority
                or frame.owner_guard.grant_ref!=owner_grant_key(*r.namespace.as_tuple).token
                or frame.owner_guard.grant_revision!=r.owner_binding.grant_revision
                or frame.owner_guard.grant_digest!=r.owner_binding.grant_digest.removeprefix("sha256:")):
            raise AuthorityUnavailable("labor W01 frame is not its same adoption bridge and sealed inputs")
        from .d01_production_operations_v1 import CurrentDomainReadV1
        CurrentDomainReadV1(frame).check(r.db)
        _FRAMES[self]=(frame,r.db,get_ident(),frame.envelope.version_guard,
            frame.snapshot.epochs,frame.envelope.identity.operation_id,r.scope,r.metadata.prepared_digest)
        return self

    def release_payload_v3(self):
        r=self.owner
        _INPUTS.pop(self,None);_FRAMES.pop(self,None);_BODY_READERS.pop(self,None)
        first=None
        try:r.release_payload_v3()
        except BaseException as error:first=error
        if r.lease is not None:
            try:
                r.graph.release_authority_lease(r.bootstrap,r.lease)
                r.lease=None
            except BaseException as later:
                if first is None:first=later
                else:first.add_note("labor process lease release failed: "+type(later).__name__)
        self.identity=self.prepared=self.body_preparation=self.admission=self.segment=self.census=self.resource_proof=None
        self.source_versions=()
        if first is not None:raise first


def require_character_labor_adoption_inputs_v1(inputs,*,graph,db,scope,owner):
    if type(inputs)is not PreparedCharacterLaborAdoptionV1:
        raise AuthorityUnavailable("actual private labor adoption inputs required")
    return inputs.require_inputs_v1(graph,gate=inputs.gate,db=db,scope=scope,owner=owner)


def require_character_labor_adoption_after_cas_v1(inputs,*,db,frame,receipt):
    from ..runtime_contracts import CommitReceipt
    from .d04_root_original_store_v1 import _receipt
    r=inputs._actual_v1()if type(inputs)is PreparedCharacterLaborAdoptionV1 else None
    saved=_FRAMES.get(inputs)
    if (r is None or saved is None or saved[0]is not frame or saved[1]is not db
            or saved[2]!=get_ident() or db is not r.db or not db.in_transaction
            or not r.store._lock._is_owned() or type(receipt)is not CommitReceipt
            or receipt.status!="committed" or receipt.operation_id!=saved[5]
            or receipt.operation_id==r.scope.operation_id
            or receipt!=_receipt(db,r.namespace,receipt.operation_id)):
        raise AuthorityUnavailable("labor after-CAS recorder needs the actual saved W01 receipt and captured frame")
    expected={v.key.token:v.revision for v in saved[3].read_versions}
    actual={v.key.token:v.revision for v in receipt.read_versions}
    if (actual!=expected or len(actual)!=len(receipt.read_versions)
            or len(receipt.invalidated_epochs)!=1 or len(saved[4])!=1
            or receipt.invalidated_epochs[0].revision!=saved[4][0].revision+1
            or inputs.segment.prepared_digest!=saved[7]
            or inputs.segment.prepared_digest!=r.metadata.prepared_digest):
        raise AuthorityUnavailable("labor W01 receipt changed its complete pre-CAS inputs or E+1/prepared EOF")
    with runtime_storage_quantum_v3(db)as meter:
        epoch=meter.read_fixed_row(db,"graph_epochs",("revision",),"bot=? AND persona=?",r.namespace.as_tuple)
        rights=meter.read_fixed_row(db,"graph_authority_epochs",("access_epoch","delete_epoch"),
            "bot=? AND persona=?",r.namespace.as_tuple)
        if epoch!=(receipt.invalidated_epochs[0].revision,)or rights!=(saved[3].access_epoch,saved[3].delete_epoch):
            raise AuthorityUnavailable("labor actual same-CAS epoch/Source rights changed")
        for version in receipt.write_versions:
            if NamespaceId.from_key(version.key)!=r.namespace:
                raise AuthorityUnavailable("labor W01 receipt wrote another namespace")
            head=meter.read_fixed_row(db,"graph_atoms",("revision","valid"),
                "token=? AND bot=? AND persona=?",(version.key.token,*r.namespace.as_tuple))
            history=meter.read_fixed_row(db,"graph_history",
                ("event_bot","event_persona","event_session","event_id","valid"),
                "token=? AND revision=?",(version.key.token,version.revision))
            if (head is None or head[0]!=version.revision or history is None
                    or history[:4]!=(*r.namespace.as_tuple,receipt.activity_id,receipt.operation_id)
                    or history[4]!=head[1]):
                raise AuthorityUnavailable("labor after-CAS output is not its actual same-event history")
    return (r.prepared,r.body_preparation,r.admission,r.segment,r.census,r.gate,
        r.source_qualification.versions,r.resource_proof)


def require_character_labor_adoption_body_readers_v1(inputs,*,db,frame):
    from .d02_production_operations_v1 import InstalledD02ProductionReadersV1
    if type(inputs)is not PreparedCharacterLaborAdoptionV1:
        raise AuthorityUnavailable("labor Body readers require actual sealed Host adoption inputs")
    r=inputs._actual_v1()
    inputs.require_inputs_v1(r.graph,gate=r.gate,db=db,scope=r.scope,owner=r.owner_binding)
    inputs.require_frame_v1(frame)
    reader=_BODY_READERS.get(inputs)
    if reader is None:
        reader=InstalledD02ProductionReadersV1(issuer=r.issuer,
            body_quote_authority=r.graph._GraphCoordinator__body_quote_authority,
            role_clock_reader=r.graph._GraphCoordinator__d04_semantic_mapping_reader,
            installed_bundle=r.bundle,labor_census=r.census,labor_scope=r.scope)
        _BODY_READERS[inputs]=reader
    return reader


def require_character_labor_adoption_body_reader_scope_v1(reader,*,db,read,state):
    matches=tuple((inputs,r)for inputs,r in _BODY_READERS.items()if r is reader)
    if len(matches)!=1:
        raise AuthorityUnavailable("labor Body scope is not the actual Host adoption reader")
    inputs,_=matches[0]
    r=inputs._actual_v1()
    inputs.require_inputs_v1(r.graph,gate=r.gate,db=db,scope=r.scope,owner=r.owner_binding)
    inputs.require_frame_v1(read.frame)
    atom=inputs.head_v1(AtomKey.from_token(r.census.body_state.ref))
    if (not atom.valid or atom.revision!=state.version or atom.revision!=r.census.body_state.version
            or canonical_digest(atom.value)!=r.census.body_state_value_digest or state.cursor!=r.census.body_state_cursor):
        raise AuthorityUnavailable("labor Body version/value/cursor differs from the complete actual census")
    return r.census,r.scope


def begin_current_character_labor_adoption_v1(graph,bootstrap,*,life_port,gate,prepared_metadata,prepared_header):
    from ..host.d11_life_port_v1 import InstalledD11LifePortV1
    from ..host.v2_fence_port import V2FencePort
    from ..host.authority_profile import current_owner_metadata_installation_v3
    from ..authority_service.d11_life_bridge_v1 import D11LifeAdoptionBridgeV1
    from .first_ingress_v2 import trusted_upper
    from .d11_life_terminal_v1 import life_adoption_operation_id_v1
    graph._admin(bootstrap)
    store=graph._GraphCoordinator__store
    if (type(life_port)is not InstalledD11LifePortV1 or type(life_port.port)is not V2FencePort
            or life_port.port is not graph._GraphCoordinator__content_fence_v2
            or type(gate)is not D11LifeAdoptionBridgeV1
            or type(prepared_metadata)is not CharacterLaborPreparedMetadataV1
            or prepared_metadata.binding!=gate.binding or prepared_metadata.prepared_digest!=gate.prepared_digest
            or type(prepared_header)is not tuple or len(prepared_header)!=3
            or prepared_header[:2]!=(gate.binding.prepare_operation_id,prepared_metadata.prepared_digest)
            or store._db.in_transaction or store._lock._is_owned()):
        raise AuthorityUnavailable("labor new Host Work requires actual positive new metadata/header and original bridge WRITE")
    bundle=current_owner_metadata_installation_v3(graph)[0]
    policy=bundle.installation_policy
    b=gate.binding
    if (policy.namespace,policy.authority_namespace,policy.expected_authority_id,policy.installation_id,policy.manifest_digest)!=(
            b.namespace,b.authority_namespace,b.authority_id,b.installation_id,b.manifest_digest):
        raise AuthorityUnavailable("labor new Host Work differs from its actual protected installed bundle")
    life_port.life_adoption_bridge_v1(binding=b,action="validate",gate=gate)
    clock=life_port.port.read_ingress_clock(graph._GraphCoordinator__scene_clock_policy)
    deadline=bundle.installation_policy.root_grant.valid_until_utc
    if trusted_upper(clock)>=deadline:
        raise AuthorityUnavailable("labor current Root resource deadline is exhausted")
    # Resource upper bound only: authenticate the exact currently active signed
    # grant before reading namespace metadata, Sources or selected payload.
    operation=begin_runtime_storage_operation_v3(store._db,gate.permit.operation_id,deadline)
    if operation is None:
        raise AuthorityUnavailable("labor new Host Work needs its actual installed bounded storage")
    lease=None
    r=None
    try:
        types={AtomKey.from_token(v.ref).type_name for v in prepared_metadata.read_versions}|set(_BODY_TYPES)
        domains=tuple(sorted({store._registry.spec(t).writer_domain for t in types}|{"d02","d06","d10","d11"}))
        lease,capability=graph.grant(bootstrap,actor=gate.owner_actor_id,issuer_domain="d10",namespace=b.namespace,
            domains=domains,activation_generation=b.activation_generation,
            operation_id=life_adoption_operation_id_v1(b))
        owners=tuple(sorted(graph._GraphCoordinator__leases[lease][5]))
        authority=AuthorityContext(gate.owner_actor_id,"d10",capability,b.namespace,owners,"consolidation",
            prepared_metadata.plan.audiences,policy.root_grant.policy_ref,b.activation_generation)
        with bind_runtime_storage_operation_v3(operation,store._db):
            with store._lock:
                store._db.execute("BEGIN")
                try:r=CharacterLaborAdoptionReadV1(graph,bootstrap,life_port,gate,prepared_metadata,
                    prepared_header,operation,lease,authority,clock)
                finally:store._db.rollback()
        r.work=create_graph_storage_work_v3(graph,kind=KIND,operation_id=operation.operation_id,
            selection_digest=operation.selection_digest,deadline_utc=operation.deadline_utc,state=r,operation=operation)
        _READERS[r]=_identity(r)
        operation.register_retained_state_v3(r)
        from .current_beta1_source_read_v3 import register_current_beta1_source_work_v3
        register_current_beta1_source_work_v3(r,r.work)
        return r.work
    except BaseException as first:
        for label,action in (("payload",lambda:r.release_payload_v3()if r is not None else None),
                ("operation",lambda:finish_runtime_storage_operation_v3(operation)),
                ("process lease",lambda:graph.release_authority_lease(bootstrap,lease)if lease is not None else None)):
            try:action()
            except BaseException as later:first.add_note("labor adoption "+label+" release failed: "+type(later).__name__)
        raise


def advance_current_character_labor_adoption_v1(graph,work):
    r=require_actual_character_labor_adoption_reader_v1(work.state)
    if graph is not r.graph or work is not r.work:
        raise AuthorityUnavailable("labor advance belongs to another actual Graph Work")
    work._require_invocation(graph)
    with bind_runtime_storage_operation_v3(r.operation,r.db):
        r.life_port.life_adoption_bridge_v1(binding=r.gate.binding,action="validate",gate=r.gate)
        from .source_inspection_metadata_read_v3 import resolve_pending_inspection_metadata_core_v3
        if resolve_pending_inspection_metadata_core_v3(work):
            return GraphStorageStepV3("progress")
        if r.phase=="core":_capture_current_core_v1(r)
        elif r.phase=="core_pages":_capture_core_segment_page_v1(r)
        elif r.phase=="checkpoint_fence":_capture_initial_checkpoint_fence_v1(r)
        elif r.phase=="owner":
            from ..authority_service.owner_location_read_v3 import prepare_current_host_character_labor_adoption_owner_entry_v1
            entry=prepare_current_host_character_labor_adoption_owner_entry_v1(r)
            try:
                r.owner_binding=entry.require_permission_v3(r)
                r.owner_guard=entry.current_owner_guard
                r.general_owner_entry=entry
                r.phase="sources"
            except BaseException:
                entry.release_v3()
                raise
        else:
            with r.store._lock:
                if r.db.in_transaction:raise AuthorityUnavailable("labor Work cannot inherit a Graph transaction")
                r.db.execute("BEGIN")
                try:
                    with runtime_storage_quantum_v3(r.db)as meter:r.advance_v1(meter)
                finally:r.db.rollback()
        r.life_port.life_adoption_bridge_v1(binding=r.gate.binding,action="validate",gate=r.gate)
    return GraphStorageStepV3("complete",r.result)if r.complete else GraphStorageStepV3("progress")


def finish_current_character_labor_adoption_v1(graph,work,error):
    r=work.state
    if graph is not r.graph or work is not r.work:
        raise AuthorityUnavailable("labor finish belongs to another actual Work")
    if error is None:
        if not r.complete or type(r.result)is not PreparedCharacterLaborAdoptionV1:
            raise AuthorityUnavailable("labor finish cannot publish partial metadata or Body inputs")
        work.result_lease=r.operation
        return
    first=error
    for label,action in (("payload",r.release_payload_v3),
            ("operation",lambda:finish_runtime_storage_operation_v3(r.operation)),
            ("process lease",lambda:graph.release_authority_lease(r.bootstrap,r.lease)if r.lease is not None else None)):
        try:action()
        except BaseException as later:first.add_note("labor adoption "+label+" release failed: "+type(later).__name__)


def require_character_labor_adoption_graph_atom_v1(original,*,key,revision,value,valid):
    r=require_actual_character_labor_adoption_reader_v1(original.owner)
    locator=(original.table,original.column,original.key_columns,original.key)
    head=r.selected_headers.get(key.token)
    if key.type_name=="memory.source":
        source=r.source_inspections.get(key.token)
        expected=None if source is None else (source.revision,int(source.valid),source.cell_id)
    else:expected=None if head is None else head[:3]
    if (r.columns.get(locator)is not original or locator not in r.body_locators
            or locator!=("graph_atoms","value",("token","bot","persona"),(key.token,*r.namespace.as_tuple))
            or not original.complete or _COLUMN_VALUES.get(original)is not value
            or expected is None or expected[:2]!=(revision,int(valid))
            or original.cell is None or original.cell.cell_id!=expected[2]):
        raise AuthorityUnavailable("labor Graph atom lacks its actual selected canonical column EOF")
    r.store._validate_key(key)
    if valid:r.store._registry.spec(key.type_name).validator(value)
    return value


def is_character_labor_adoption_body_reader_v1(reader):
    return any(value is reader for value in _BODY_READERS.values())


def require_character_labor_adoption_settlement_metadata_v1(inputs,*,db,frame):
    if type(inputs)is not PreparedCharacterLaborAdoptionV1:
        raise AuthorityUnavailable("actual retained labor settlement inputs required")
    r=inputs._actual_v1()
    inputs.require_inputs_v1(r.graph,gate=r.gate,db=db,scope=r.scope,owner=r.owner_binding)
    inputs.require_frame_v1(frame)
    if not r.passive_complete or not r.reservation_scan_complete or not r.checkpoint_complete or not r.components_complete:
        raise AuthorityUnavailable("labor settlement requires complete signed policy and Body inventories")
    return CharacterLaborSettlementMetadataV1(tuple(r.passive_policies),tuple(r.segments),
        tuple(r.body_atoms.values()),tuple(r.checkpoints.items()),tuple(r.components),
        r.census,r.source_qualification.versions)


@dataclass(frozen=True,slots=True)
class CharacterLaborSettlementMetadataV1:
    passive_policies:tuple
    segments:tuple
    body_atoms:tuple
    checkpoints:tuple
    components:tuple
    census:object
    source_versions:tuple


@contextmanager
def bind_character_labor_adoption_inputs_v1(inputs,*,graph,db,scope,owner,frame):
    require_character_labor_adoption_inputs_v1(inputs,graph=graph,db=db,scope=scope,owner=owner)
    if _BOUND.get()is not None:
        raise AuthorityUnavailable("another labor adoption frame is already bound")
    token=_BOUND.set((inputs,db,frame,get_ident()))
    try:
        inputs.require_frame_v1(frame)
        with bind_runtime_storage_operation_v3(inputs.operation,db):yield inputs
    finally:_BOUND.reset(token)


def read_bound_character_labor_adoption_head_v1(db,namespace,key):
    bound=_BOUND.get()
    if bound is None:return False,None
    inputs,actual_db,frame,thread=bound
    r=inputs._actual_v1()
    if actual_db is not db or thread!=get_ident()or namespace!=r.namespace or not db.in_transaction:
        raise AuthorityUnavailable("labor sealed head crossed its actual frame/Graph transaction")
    return True,inputs.head_v1(key)


def read_bound_character_labor_adoption_inventory_v1(frame,db,type_name):
    bound=_BOUND.get()
    if bound is None:return False,None
    inputs,actual_db,actual_frame,thread=bound
    if actual_db is not db or actual_frame is not frame or thread!=get_ident():
        raise AuthorityUnavailable("labor inventory crossed its actual retained frame")
    return True,inputs.complete_inventory_v1(type_name)


LOCATOR_KIND="current_character_labor_adoption_locator_v1"
_LOCATORS=WeakKeyDictionary()
_LOCATOR_RESULTS=WeakKeyDictionary()


class _LocatorMetadataColumnV1:
    """Whole canonical EOF for one closed Root-metadata column, never a Body."""
    def __init__(self,reader,table,column,key_columns,key,*,signature_kind=None,signature=None):
        from .c09_canonical_json_stream_v2 import C09CanonicalJSONStreamV2
        self.reader,self.table,self.column=reader,table,column
        self.key_columns,self.key=tuple(key_columns),tuple(key)
        self.signature_kind,self.signature=signature_kind,signature
        self.body=bytearray()
        self.fragment=b""
        self.fragment_offset=self.offset=0
        self.total=None
        self.complete=False
        self.value=self.digest=None
        self.parser=C09CanonicalJSONStreamV2(ensure_ascii=True)
        self.hmac=None
        if signature_kind is not None:
            import hmac,hashlib
            self.hmac=hmac.new(reader.bundle.d11_signing_key,
                (signature_kind+"\n").encode(),hashlib.sha256)

    def advance(self,meter):
        import json,hmac
        from .c09_paged_sql_v2 import read_legacy_sql_cell_fragment_v2,legacy_cell_read_transaction_v2,_quote
        r=self.reader
        r.require_v1(meter)
        if self.complete:return True
        if self.fragment_offset<len(self.fragment):
            end=min(self.fragment_offset+1024,len(self.fragment))
            part=self.fragment[self.fragment_offset:end]
            r.operation.reserve_retained_state_growth_v3(r,len(part)*8+32768)
            try:
                self.parser.feed(part,lambda event:None)
                self.body.extend(part)
            finally:r.operation.finish_retained_state_growth_v3(r)
            self.fragment_offset=end
            return False
        where=" AND ".join(_quote(name)+"=?"for name in self.key_columns)
        if self.total is None:
            row=r.db.execute("SELECT typeof("+_quote(self.column)+"),length(CAST("+
                _quote(self.column)+" AS BLOB)) FROM "+_quote(self.table)+" WHERE "+where,self.key).fetchone()
            meter.charge_read(24)
            if row is None or row[0]!="text":
                raise AuthorityUnavailable("labor Root metadata column is absent or not a canonical original")
            self.total=row[1]
            return False
        if self.offset<self.total:
            with legacy_cell_read_transaction_v2(r.db):
                chunk,total,kind=read_legacy_sql_cell_fragment_v2(r.db,table=self.table,column=self.column,
                    where=where,parameters=self.key,start=self.offset,length=min(16384,self.total-self.offset),meter=meter)
            if (total,kind)!=(self.total,"text"):
                raise AuthorityUnavailable("labor Root metadata physical column changed")
            self.offset+=len(chunk)
            self.fragment,self.fragment_offset=chunk,0
            if self.hmac is not None:self.hmac.update(chunk)
            r.operation.refresh_retained_state_v3(r)
            return False
        parsed=self.parser.finish()
        if parsed.byte_count!=self.total:
            raise AuthorityUnavailable("labor Root metadata canonical EOF byte count differs")
        if self.hmac is not None and not hmac.compare_digest(self.hmac.hexdigest(),self.signature):
            raise AuthorityUnavailable("labor Root metadata lost its actual current signed grant")
        meter.charge_encode(len(self.body))
        r.operation.reserve_retained_state_growth_v3(r,len(self.body)*10+65536)
        try:
            self.value=json.loads(self.body)
            self.digest=parsed.sha256
            self.complete=True
            self.parser=None
            self.fragment=b""
        finally:r.operation.finish_retained_state_growth_v3(r)
        return True


class CharacterLaborAdoptionLocatorReadV1:
    def __init__(self,graph,bootstrap,namespace,prepared_ref,bundle,operation,clock,stamp):
        self.graph,self.bootstrap,self.namespace,self.prepared_ref=graph,bootstrap,namespace,prepared_ref
        self.store=graph._GraphCoordinator__store
        self.db=self.store._db
        self.bundle,self.operation,self.clock=bundle,operation,clock
        self.selection_digest=operation.selection_digest
        self.graph_stamp=stamp
        self.thread=get_ident()
        from .first_ingress_v2 import trusted_upper
        self.monotonic_deadline=time.monotonic()+operation.deadline_utc-trusted_upper(clock)
        self.work=None
        self.phase="grant_header"
        self.columns={}
        self.resource_verified=False
        self.grant_header=None
        self.header=None
        self.kind=None
        self.sidecar_header=None
        self.metadata=None
        self.receipt_header=None
        self.event_header=None
        self.complete=False
        self.result=None

    def _runtime_retained_heap_bytes_v3(self):
        columns=tuple((c.body,c.fragment,c.value)for c in self.columns.values())
        return _heap(columns)+_payload_heap_v1(self.metadata)+65536

    def _identity_v1(self):
        return (self.graph,self.bootstrap,self.namespace,self.prepared_ref,self.bundle,self.operation,
            self.selection_digest,self.graph_stamp,self.thread,self.monotonic_deadline,self.work)

    def require_v1(self,meter=None):
        if (_LOCATORS.get(self)!=self._identity_v1()or self.thread!=get_ident()
                or self.operation.closed or self.work.state is not self or self.work.coordinator is not self.graph
                or self.work.operation is not self.operation or self.work.kind!=LOCATOR_KIND
                or self.work.operation_id!=self.operation.operation_id
                or time.monotonic()>=self.monotonic_deadline):
            raise AuthorityUnavailable("labor Root metadata locator lost its actual named Work/deadline/installation")
        self.graph._admin(self.bootstrap)
        if meter is not None:
            self.operation.handle.require_current(meter)
            if (not self.db.in_transaction or not self.store._lock._is_owned()
                    or self.graph._v2_graph_stamp(self.namespace)!=self.graph_stamp):
                raise AuthorityUnavailable("labor Root metadata selection or namespace stamp changed")
            grant=self.bundle.installation_policy.root_grant
            head=meter.read_fixed_row(self.db,"runtime_budget_grants",("version","status","signature"),
                "lease_id=? ORDER BY version DESC",(grant.lease_id,))
            if self.grant_header is not None and head!=self.grant_header:
                raise AuthorityUnavailable("labor Root metadata current signed grant changed")
        return self

    def _column_v1(self,name,table,column,keys,key,meter,**kwargs):
        c=self.columns.get(name)
        if c is None:
            c=_LocatorMetadataColumnV1(self,table,column,keys,key,**kwargs)
            self.columns[name]=c
            return None
        return c if c.advance(meter)else None

    def _finish_v1(self):
        self.complete=True
        self.result=PreparedCharacterLaborAdoptionLocatorV1(_ISSUER,self)

    def advance_v1(self,meter):
        self.require_v1(meter)
        grant=self.bundle.installation_policy.root_grant
        if self.phase=="grant_header":
            head=meter.read_fixed_row(self.db,"runtime_budget_grants",("version","status","signature"),
                "lease_id=? ORDER BY version DESC",(grant.lease_id,))
            if head is None or head[:2]!=(grant.version,"active"):
                raise AuthorityUnavailable("labor Root metadata requires its current installed signed grant version")
            self.grant_header=head
            self.phase="grant"
            return
        if self.phase=="grant":
            c=self._column_v1("grant","runtime_budget_grants","grant_json",("lease_id","version"),
                (grant.lease_id,grant.version),meter,signature_kind="budget-grant.v1",signature=self.grant_header[2])
            if c is None:return
            from .issuers import _decode_grant
            current=_decode_grant(c.body.decode())
            if current!=grant or (grant.bot_id,grant.persona_id)!=self.namespace.as_tuple:
                raise AuthorityUnavailable("labor Root metadata grant differs from its protected installation")
            self.resource_verified=True
            self.phase="header"
            return
        if not self.resource_verified:
            raise AuthorityUnavailable("labor Prepared locators cannot precede current Root resource admission")
        if self.phase=="header":
            headers=[]
            issuer=self.graph._GraphCoordinator__d11_issuer
            for kind in ("prepared","character_labor_prepared_v1"):
                row=meter.read_fixed_row(self.db,TABLE,("producing_operation_id","payload_digest","signature"),
                    "bot=? AND persona=? AND kind=? AND original_ref=?",
                    (*self.namespace.as_tuple,kind,self.prepared_ref))
                if row is not None:
                    issuer._signer.verify(SIGN_KIND,
                        canonical_serialize((self.namespace,kind,self.prepared_ref,row[1])),row[2])
                    headers.append((kind,row))
            if len(headers)!=1:
                raise AuthorityUnavailable("labor adoption needs exactly one actual old/new signed Prepared header")
            self.kind,self.header=headers[0]
            if self.kind=="prepared":
                self._finish_v1()
                return
            self.phase="sidecar_header"
            return
        if self.phase=="sidecar_header":
            rows=self.db.execute("SELECT original_ref,producing_operation_id,payload_digest,signature FROM "+
                TABLE+" WHERE bot=? AND persona=? AND kind=? AND producing_operation_id=? ORDER BY original_ref LIMIT 2",
                (*self.namespace.as_tuple,PREPARED_METADATA_KIND,self.header[0])).fetchall()
            meter.charge_read(sum(sum(len(str(v).encode())for v in row)for row in rows))
            if len(rows)!=1:
                raise AuthorityUnavailable("actual new Prepared has no unique bodyless metadata sidecar")
            self.sidecar_ref,*header=rows[0]
            self.sidecar_header=tuple(header)
            self.phase="sidecar"
            return
        if self.phase=="sidecar":
            c=self._column_v1("sidecar",TABLE,"payload_json",("bot","persona","kind","original_ref"),
                (*self.namespace.as_tuple,PREPARED_METADATA_KIND,self.sidecar_ref),meter)
            if c is None:return
            issuer=self.graph._GraphCoordinator__d11_issuer
            if c.digest!=self.sidecar_header[1]:
                raise AuthorityUnavailable("labor sidecar whole canonical EOF differs from its saved commitment")
            issuer._signer.verify(SIGN_KIND,canonical_serialize((self.namespace,
                PREPARED_METADATA_KIND,self.sidecar_ref,c.digest)),self.sidecar_header[2])
            self.operation.reserve_retained_state_growth_v3(self,len(c.body)*10+65536)
            try:self.metadata=_require_bodyless_prepared_metadata_v1(character_labor_prepared_metadata_from_wire_v1(c.value))
            finally:self.operation.finish_retained_state_growth_v3(self)
            m=self.metadata
            policy=self.bundle.installation_policy
            if (m.prepared_ref!=self.prepared_ref or m.prepared_digest!=self.header[1]
                    or m.binding.prepare_operation_id!=self.header[0]
                    or self.sidecar_header[0]!=self.header[0]
                    or self.sidecar_ref!="character-labor-prepared-metadata:"+m.binding.execution_id
                    or (m.namespace,m.binding.authority_namespace,m.binding.authority_id,m.binding.installation_id,
                        m.binding.manifest_digest)!=(self.namespace,policy.authority_namespace,policy.expected_authority_id,
                            policy.installation_id,policy.manifest_digest)):
                raise AuthorityUnavailable("labor sidecar differs from its actual new Prepared/C/installed binding")
            self.phase="receipt_header"
            return
        m=self.metadata
        op=m.binding.prepare_operation_id
        if self.phase=="receipt_header":
            self.receipt_header=meter.read_fixed_row(self.db,"graph_bundle_operations",
                ("digest","activity_id","effect_id","commit_seq"),"bot=? AND persona=? AND operation_id=?",
                (*self.namespace.as_tuple,op))
            self.event_header=meter.read_fixed_row(self.db,"graph_events",("digest","epoch_revision"),
                "bot=? AND persona=? AND session=? AND event_id=?",
                (*self.namespace.as_tuple,m.binding.activity_id,op))
            if (self.receipt_header is None or self.event_header is None
                    or self.receipt_header[1:3]!=(m.binding.activity_id,m.binding.effect_id)
                    or self.event_header[1]!=m.graph_epoch):
                raise AuthorityUnavailable("labor new sidecar lacks its actual C bundle/event")
            self.phase="receipt"
            return
        for name,column,table,keys,key in (
                ("receipt","receipt_json","graph_bundle_operations",("bot","persona","operation_id"),(*self.namespace.as_tuple,op)),
                ("reads","reads","graph_events",("bot","persona","session","event_id"),(*self.namespace.as_tuple,m.binding.activity_id,op)),
                ("writes","revisions","graph_events",("bot","persona","session","event_id"),(*self.namespace.as_tuple,m.binding.activity_id,op))):
            c=self._column_v1(name,table,column,keys,key,meter)
            if c is None:return
        from ..runtime_contracts import CommitReceipt
        from ..graph_types import NamespaceEpoch
        reads=tuple(GraphVersion(AtomKey.from_token(k),v)for k,v in self.columns["reads"].value)
        writes=tuple(GraphVersion(AtomKey.from_token(k),v)for k,v in self.columns["writes"].value)
        raw=self.columns["receipt"].value
        receipt=CommitReceipt("committed",op,*self.receipt_header,reads,writes,
            (NamespaceEpoch(*self.namespace.as_tuple,m.graph_epoch),),tuple(raw["ledger_refs"]),tuple(raw["outbox_refs"]))
        versions={v.key.token:v.revision for v in reads}
        versions.update({v.key.token:v.revision for v in writes})
        if (canonical_digest(receipt)!=m.receipt_digest
                or versions!={v.ref:v.version for v in m.read_versions}
                or not writes):
            raise AuthorityUnavailable("labor sidecar does not belong to the complete actual C receipt/read-set")
        self._finish_v1()

    def release_payload_v3(self):
        if _LOCATORS.pop(self,None)is None:return
        if self.result is not None:_LOCATOR_RESULTS.pop(self.result,None)
        self.columns.clear()
        self.metadata=self.result=None


class PreparedCharacterLaborAdoptionLocatorV1:
    def __init__(self,issuer,reader):
        if issuer is not _ISSUER or not reader.complete:
            raise AuthorityUnavailable("labor locator requires its real complete signed Root metadata Work")
        self.reader=reader
        _LOCATOR_RESULTS[self]=(reader,reader.kind,reader.header,reader.metadata,reader.sidecar_header)

    def require_v1(self,graph,*,namespace,prepared_original_ref):
        r=self.reader
        r.require_v1()
        if (_LOCATOR_RESULTS.get(self)!=(r,r.kind,r.header,r.metadata,r.sidecar_header)
                or graph is not r.graph or namespace!=r.namespace or prepared_original_ref!=r.prepared_ref
                or r.db.in_transaction or r.store._lock._is_owned()):
            raise AuthorityUnavailable("labor locator is not this retained Root metadata original")
        with bind_runtime_storage_operation_v3(r.operation,r.db):
            with r.store._lock:
                r.db.execute("BEGIN")
                try:
                    with runtime_storage_quantum_v3(r.db)as meter:
                        r.require_v1(meter)
                        header=meter.read_fixed_row(r.db,TABLE,
                            ("producing_operation_id","payload_digest","signature"),
                            "bot=? AND persona=? AND kind=? AND original_ref=?",
                            (*r.namespace.as_tuple,r.kind,r.prepared_ref))
                        if header!=r.header:
                            raise AuthorityUnavailable("labor locator Prepared fixed header changed")
                finally:r.db.rollback()
        return r.metadata,r.header

    def release_payload_v3(self):
        self.reader.release_payload_v3()


def begin_current_character_labor_adoption_locator_v1(graph,bootstrap,*,namespace,prepared_original_ref):
    from ..host.authority_profile import current_owner_metadata_installation_v3
    from .first_ingress_v2 import trusted_upper
    graph._admin(bootstrap)
    store=graph._GraphCoordinator__store
    bundle=current_owner_metadata_installation_v3(graph)[0]
    if (type(namespace)is not NamespaceId or namespace!=bundle.installation_policy.namespace
            or type(prepared_original_ref)is not str or not prepared_original_ref
            or store._db.in_transaction or store._lock._is_owned()):
        raise AuthorityUnavailable("labor locator requires actual installed Root namespace and fixed Prepared ref")
    port=graph._GraphCoordinator__content_fence_v2
    clock=port.read_ingress_clock(graph._GraphCoordinator__scene_clock_policy)
    deadline=bundle.installation_policy.root_grant.valid_until_utc
    if trusted_upper(clock)>=deadline:
        raise AuthorityUnavailable("labor locator current Root resource deadline is exhausted")
    opid="labor-adoption-locator:"+canonical_digest((namespace,prepared_original_ref))[:48]
    operation=begin_runtime_storage_operation_v3(store._db,opid,deadline)
    if operation is None:
        raise AuthorityUnavailable("labor locator needs actual bounded installed selected storage")
    reader=None
    try:
        with bind_runtime_storage_operation_v3(operation,store._db):
            with store._lock:
                store._db.execute("BEGIN")
                try:stamp=graph._v2_graph_stamp(namespace)
                finally:store._db.rollback()
        reader=CharacterLaborAdoptionLocatorReadV1(graph,bootstrap,namespace,prepared_original_ref,bundle,operation,clock,stamp)
        reader.work=create_graph_storage_work_v3(graph,kind=LOCATOR_KIND,operation_id=opid,
            selection_digest=operation.selection_digest,deadline_utc=deadline,state=reader,operation=operation)
        _LOCATORS[reader]=reader._identity_v1()
        operation.register_retained_state_v3(reader)
        return reader.work
    except BaseException as first:
        if reader is not None:reader.release_payload_v3()
        try:finish_runtime_storage_operation_v3(operation)
        except BaseException as later:first.add_note("labor locator retention release failed: "+type(later).__name__)
        raise


def advance_current_character_labor_adoption_locator_v1(graph,work):
    reader=work.state
    if type(reader)is not CharacterLaborAdoptionLocatorReadV1 or reader.graph is not graph or reader.work is not work:
        raise AuthorityUnavailable("actual Root labor locator Work required")
    work._require_invocation(graph)
    with bind_runtime_storage_operation_v3(reader.operation,reader.db):
        with reader.store._lock:
            if reader.db.in_transaction:raise AuthorityUnavailable("labor locator cannot inherit Graph SQL")
            reader.db.execute("BEGIN")
            try:
                with runtime_storage_quantum_v3(reader.db)as meter:reader.advance_v1(meter)
            finally:reader.db.rollback()
    return GraphStorageStepV3("complete",reader.result)if reader.complete else GraphStorageStepV3("progress")


def finish_current_character_labor_adoption_locator_v1(graph,work,error):
    reader=work.state
    if type(reader)is not CharacterLaborAdoptionLocatorReadV1 or reader.graph is not graph or reader.work is not work:
        raise AuthorityUnavailable("actual Root labor locator finish required")
    if error is None:
        if not reader.complete or type(reader.result)is not PreparedCharacterLaborAdoptionLocatorV1:
            raise AuthorityUnavailable("labor locator cannot publish partial or unknown metadata")
        work.result_lease=reader.operation
        return
    try:reader.release_payload_v3()
    except BaseException as later:error.add_note("labor locator payload release failed: "+type(later).__name__)
    try:finish_runtime_storage_operation_v3(reader.operation)
    except BaseException as later:error.add_note("labor locator retention release failed: "+type(later).__name__)


def _require_bodyless_prepared_metadata_v1(metadata):
    import json
    from .d11_life_contract_v1 import RegisteredCharacterLaborLifePlanV1
    from .d11_types import RuntimeJobValue,_strict_payload
    if (type(metadata)is not CharacterLaborPreparedMetadataV1
            or type(metadata.plan)is not RegisteredCharacterLaborLifePlanV1
            or metadata.plan.body_effect_request_json is not None):
        raise AuthorityUnavailable("labor locator cannot carry a legacy/full Body preparation plan")
    raw=json.loads(metadata.job_projection_json)
    job=_strict_payload(raw,RuntimeJobValue)
    b=metadata.binding
    if ((job.bot_id,job.persona_id,job.activity_id,job.operation_id,job.effect_id,job.job_id,
            job.parent_budget_lease_ref,job.fence,job.cancel_epoch)!=(b.namespace.bot_id,b.namespace.persona_id,
                b.activity_id,b.operation_id,b.effect_id,b.job_id,b.parent_budget_lease_ref,b.job_fence,b.job_cancel_epoch)
            or canonical_serialize(raw)!=metadata.job_projection_json):
        raise AuthorityUnavailable("labor metadata job projection is not its actual closed digest-only C header")
    return metadata


def require_character_labor_adoption_resource_proof_v1(inputs,*,graph,db,scope,owner):
    """Existing runtime-resource upper bound; never a new CPU/job/Source grant."""
    if type(inputs)is not PreparedCharacterLaborAdoptionV1:
        raise AuthorityUnavailable("actual retained labor inputs required for their Root resource proof")
    r=inputs._actual_v1()
    inputs.require_inputs_v1(graph,gate=r.gate,db=db,scope=scope,owner=owner)
    proof=r.resource_proof
    if (proof is None or proof is not inputs.resource_proof or proof[0]is not r.bundle
            or proof[1]is not r.resource_grant or proof[4]is not r.operation
            or proof[5]is not r.operation.handle or proof[6]!=r.selection_digest or proof[7]is not r.gate):
        raise AuthorityUnavailable("labor frame resource prerequisite differs from its actual admitted Root Work")
    return proof


def require_character_labor_adoption_accounting_bases_v1(inputs,*,db,frame):
    if type(inputs)is not PreparedCharacterLaborAdoptionV1:
        raise AuthorityUnavailable("actual complete labor duration inputs required")
    r=inputs._actual_v1()
    inputs.require_inputs_v1(r.graph,gate=r.gate,db=db,scope=r.scope,owner=r.owner_binding)
    inputs.require_frame_v1(frame)
    expected={e.execution_id for e in r.census.entries if e.classification in {
        "character_labor_v1","retained_duration_v1"}}
    if not r.bases_complete or set(r.accounting_bases)!=expected or set(r.accounting_originals)!=expected:
        raise AuthorityUnavailable("labor duration policies are not a complete actual census/accounting bijection")
    return tuple(r.accounting_bases[key]for key in sorted(expected))


class ObservedCharacterLaborAdoptionV1:
    def __init__(self,issuer,inputs):
        if issuer is not _ISSUER:
            raise AuthorityUnavailable("labor terminal observation requires its actual Source Work")
        r=inputs._actual_v1()
        from .domain_production_contracts_v1 import ProductionOriginalRefV1
        self.inputs,self.port,self.prepared=inputs,r.life_port,r.prepared
        self.claim,self.terminal=r.claim,r.terminal
        self.original=ProductionOriginalRefV1("d11.life_terminal",r.terminal.original_ref,
            canonical_digest(plain_v1(r.terminal)))
        _OBSERVED[self]=(inputs,r.life_port,r.claim,r.terminal,r.metadata.prepared_digest,self.original)


def observe_current_character_labor_adoption_terminal_v1(inputs):
    if type(inputs)is not PreparedCharacterLaborAdoptionV1:
        raise AuthorityUnavailable("actual sealed labor inputs required for terminal observation")
    r=inputs._actual_v1()
    if r.observation is None:r.observation=ObservedCharacterLaborAdoptionV1(_ISSUER,inputs)
    return require_current_character_labor_adoption_observation_v1(r.observation)


def require_current_character_labor_adoption_observation_v1(observation):
    if type(observation)is not ObservedCharacterLaborAdoptionV1:
        raise AuthorityUnavailable("actual private Host labor terminal observation required")
    inputs=observation.inputs
    r=inputs._actual_v1()
    if (_OBSERVED.get(observation)!=(inputs,r.life_port,r.claim,r.terminal,
            r.metadata.prepared_digest,observation.original)
            or observation.port is not r.life_port or observation.prepared is not r.prepared
            or observation.claim!=r.claim or observation.terminal!=r.terminal
            or r.terminal.claim!=r.claim or r.terminal!=r.gate.terminal
            or r.segment.prepared_digest!=r.metadata.prepared_digest):
        raise AuthorityUnavailable("labor observation changed its actual Core/Prepared EOF/segment binding")
    return observation


def _final_head_v1(reader,key,meter):
    r=reader
    row=meter.read_fixed_row(r.db,"graph_atoms",("revision","valid","value_cell_id"),
        "bot=? AND persona=? AND token=?",(*r.namespace.as_tuple,key.token))
    atom=r.body_atoms.get(key.token)
    if row is None:
        if atom is not None:
            raise AuthorityUnavailable("labor final dependency disappeared after its actual Body EOF")
        negative=GraphAtom(key,0,{},False)
        r.final_negative_heads[key.token]=negative
        return negative
    if atom is None or (atom.revision,int(atom.valid))!=row[:2]:
        raise AuthorityUnavailable("labor final target already exists without this Work's selected canonical EOF")
    header=r.selected_headers.get(key.token)
    if header is None or header[:3]!=row:
        raise AuthorityUnavailable("labor final target changed its actual metadata/header/cell identity")
    return atom


def prepare_character_labor_adoption_frame_v1(inputs,*,graph,db,observation,now_utc):
    """One real pre-CAS frame from this retained Work; no SQL Body fallback."""
    import json,math
    from ..graph_types import GraphSnapshot,Owner
    from ..runtime_contracts import (CommandEnvelope,OperationIdentity,QueryEpoch,
        VersionGuard,SourceQualification,RUNTIME_SCHEMA,VersionedRef)
    from .domain_production_contracts_v1 import (CurrentOperationFrameV1,ProductionOwnerGuardV1,
        ProductionQueryCoverageV1,ProductionPolicyRefV1,ProductionOriginalRefV1,ProductionOperationLimitsV1)
    from .d11_life_terminal_v1 import AdoptCurrentLifeRequestV1,life_adoption_operation_id_v1
    from .d11_life_graph_types_v1 import life_role_segment_key_v1
    from .d11_life_fact_provenance_v1 import PROVENANCE_TYPE,ELIGIBILITY_TYPE,life_fact_auxiliary_key_v1
    from .d11_life_outcome_provenance_v1 import life_outcome_read_keys_v1
    from .d11_types import runtime_job_key,runtime_cost_settlement_key
    from ..domains.d02.character_labor_v1 import character_labor_rebuild_key_v1,character_labor_correction_key_v1
    from .first_ingress_v2 import trusted_upper
    if type(inputs)is not PreparedCharacterLaborAdoptionV1:
        raise AuthorityUnavailable("actual sealed labor adoption inputs required")
    r=inputs._actual_v1()
    r.work._require_invocation(graph)
    inputs.require_inputs_v1(graph,gate=r.gate,db=db,scope=r.scope,owner=r.owner_binding)
    observed=require_current_character_labor_adoption_observation_v1(observation)
    if observed.inputs is not inputs:
        raise AuthorityUnavailable("labor frame observation belongs to another actual Work")
    if type(now_utc)not in (int,float)or not math.isfinite(now_utc):
        raise AuthorityUnavailable("labor frame requires its actual current trusted time")
    now=max(now_utc,trusted_upper(r.clock))
    resource=require_character_labor_adoption_resource_proof_v1(inputs,graph=graph,db=db,
        scope=r.scope,owner=r.owner_binding)
    deadline=min(resource[1].valid_until_utc,resource[4].deadline_utc)
    if now>=deadline:
        raise AuthorityUnavailable("labor settlement exhausted its original actual resource deadline")
    b=r.gate.binding
    keys={AtomKey.from_token(ref)for ref in r.body_atoms}
    keys.update(r.selected_plan.exact_keys)
    keys.add(owner_grant_key(*r.namespace.as_tuple))
    keys.add(runtime_job_key(*r.namespace.as_tuple,b.activity_id,b.job_id))
    keys.add(runtime_cost_settlement_key(*r.namespace.as_tuple,b.activity_id,b.reservation_operation_id))
    facts=(AtomKey.from_token(b.artifact_ref),life_role_segment_key_v1(b,"start"),life_role_segment_key_v1(b,"end"))
    keys.update(facts)
    keys.update(life_fact_auxiliary_key_v1(fact,kind)for fact in facts for kind in (PROVENANCE_TYPE,ELIGIBILITY_TYPE))
    keys.update(life_outcome_read_keys_v1(b,r.prepared.plan.action_intent.ref))
    body_key=AtomKey.from_token(r.census.body_state.ref)
    head_key=character_labor_rebuild_key_v1(r.namespace,r.policy.profile_id)
    head=r.body_atoms.get(head_key.token)
    if head is not None and head.valid and head.value["revision"]!=head.revision:
        raise AuthorityUnavailable("labor rebuild head value revision differs from its real GraphVersion")
    revision=1 if head is None or not head.valid else head.revision+1
    correction=character_labor_correction_key_v1(r.namespace,r.policy.profile_id,revision)
    keys.update((body_key,AtomKey.from_token(r.body_preparation.reservation_ref),
        AtomKey.from_token(r.body_preparation.settlement_ref),head_key,correction))
    atoms=[]
    with runtime_storage_quantum_v3(db)as meter:
        for key in sorted(keys,key=lambda k:k.token):
            if NamespaceId.from_key(key)!=r.namespace:
                raise AuthorityUnavailable("labor final recipe crossed its actual namespace")
            atoms.append(_final_head_v1(r,key,meter))
        guard_versions={}
        for kind in ("scheme","operator","policy"):
            row=meter.read_fixed_row(db,"graph_guard_versions",("version",),
                "bot=? AND persona=? AND ref='current' AND kind=?",(*r.namespace.as_tuple,kind))
            if row is None:
                raise AuthorityUnavailable("labor final installed scheme/operator/policy metadata is absent")
            guard_versions[kind]=row[0]
    snapshot=GraphSnapshot(tuple(atoms),(r.scope.graph_epoch,))
    pages=[]
    for type_name in sorted(r.inventory_types):
        versions=tuple(GraphVersion(AtomKey.from_token(token),head[0])
            for token,head in sorted(r.selected_headers.items())
            if AtomKey.from_token(token).type_name==type_name)
        pages.append(ProductionQueryCoverageV1(QueryEpoch(r.namespace,type_name,r.scope.graph_epoch.revision),
            type_name,versions,True,None))
    query_epochs=(QueryEpoch(r.namespace,"namespace",r.scope.graph_epoch.revision),
        *(page.epoch for page in pages))
    owner=r.owner_binding
    if (owner.actor!=r.authority.actor or r.authority.purpose not in owner.purposes
            or not set(r.authority.audience)<=owner.audiences
            or owner.authorization_head!=r.gate.owner_authority.guard.authorization_head
            or owner.authorization_revision!=r.gate.owner_authority.guard.authorization_revision):
        raise AuthorityUnavailable("labor final actual Owner does not admit its original paired Source groups")
    owner_guard=ProductionOwnerGuardV1(owner_grant_key(*r.namespace.as_tuple).token,
        owner.grant_revision,owner.grant_digest.removeprefix("sha256:"),
        owner.authorization_head.removeprefix("sha256:"))
    source_grants=tuple(VersionedRef(v.key.token,v.revision)for v in r.source_qualification.versions
        if v.key.type_name=="memory.access")
    guard=VersionGuard(snapshot.versions,query_epochs,*r.authority_epochs,r.catalogue_hash,
        guard_versions["scheme"],guard_versions["operator"],guard_versions["policy"],
        source_grants,(),())
    refs=(b.prepared_original_ref,observed.original.original_ref)
    envelope=CommandEnvelope(RUNTIME_SCHEMA,OperationIdentity(b.activity_id,b.effect_id,b.attempt_id,
        "adopt_life",life_adoption_operation_id_v1(b),canonical_digest({"input_refs":list(refs)})),
        r.authority,guard,SourceQualification(tuple(r.metadata.source_roots),"derived",None,now,
            "inference","ineligible",None,"not_applicable"),refs,b.parent_budget_lease_ref,deadline,
        r.monotonic_deadline,"life-terminal:"+b.execution_id,())
    policies={}
    for raw in r.action_template["policies"]:
        pin=ProductionPolicyRefV1(**raw)
        policies[(pin.policy_ref,pin.revision)]=pin
    for policy in (r.policy,*r.passive_policies):
        pin=ProductionPolicyRefV1(policy.policy_ref,policy.revision,canonical_digest(plain_v1(policy)))
        prior=policies.get((pin.policy_ref,pin.revision))
        if prior is not None and prior!=pin:
            raise AuthorityUnavailable("labor final policy changed its actual signed original digest")
        policies[(pin.policy_ref,pin.revision)]=pin
    originals={(o["kind"],o["original_ref"]):ProductionOriginalRefV1(
        o["kind"],o["original_ref"],o["original_digest"])for o in r.action_template["originals"]}
    originals[(observed.original.kind,observed.original.original_ref)]=observed.original
    for policy in (r.policy,*r.passive_policies):
        kind="d02.labor_policy" if policy is r.policy else "d02.passive_policy"
        originals[(kind,policy.policy_ref)]=ProductionOriginalRefV1(kind,policy.policy_ref,canonical_digest(plain_v1(policy)))
    action_task=r.metadata_tasks[("action_admission","d08-life-admission:"+b.execution_id)]
    for kind,ref,digest in (
            ("d11.life_character_labor_body_preparation_v1",r.metadata.plan.labor_body_preparation_original.original_ref,
                r.metadata.plan.labor_body_preparation_original.original_digest),
            ("d11.life_character_labor_admission_v1",r.metadata.labor_admission_ref,r.metadata.labor_admission_digest),
            ("d11.life_action_admission","d08-life-admission:"+b.execution_id,action_task.metadata[1])):
        originals[(kind,ref)]=ProductionOriginalRefV1(kind,ref,digest)
    frame=CurrentOperationFrameV1(envelope,snapshot,now,owner_guard,b.activation_generation,tuple(pages),
        tuple(policies[key]for key in sorted(policies)),tuple(originals[key]for key in sorted(originals)),
        ProductionOperationLimitsV1())
    r.operation.refresh_retained_state_v3(r)
    with bind_character_labor_adoption_inputs_v1(inputs,graph=graph,db=db,scope=r.scope,owner=owner,frame=frame):
        inputs.require_frame_v1(frame)
    return frame,AdoptCurrentLifeRequestV1(b.prepared_original_ref)


def _capture_core_segment_page_v1(r):
    from ..authority_service.character_labor_census_v1 import verify_character_labor_segment_page_v1
    if r.db.in_transaction or r.store._lock._is_owned():
        raise AuthorityUnavailable("labor census pages must be observed outside Graph SQL/lock")
    page=r.life_port.read_d11_character_labor_segment_page_v1(namespace=r.scope.authority_namespace,
        permit=r.gate.permit,census=r.census,cursor=r.core_cursor,limit=1)
    verify_character_labor_segment_page_v1(r.issuer,page,census=r.census,
        permit=r.gate.permit,cursor=r.core_cursor,limit=1)
    for item in page.items:
        segment=item.segment
        prior=r.core_segments.get(segment.segment_id)
        if prior is not None and prior!=segment:
            raise AuthorityUnavailable("labor same-census pages changed an actual original claim segment")
        r.core_segments[segment.segment_id]=segment
    if page.next_cursor is None:
        expected={e.execution_id for e in r.census.entries if e.classification!="fixed_v1"}
        if {s.execution_id for s in r.core_segments.values()}!=expected:
            raise AuthorityUnavailable("labor complete census page EOF did not cover every actual claimed duration")
        r.core_complete=True
        r.metadata_identity=(*r.metadata_identity,r.census,r.segment,
            tuple(sorted(r.core_segments.items())),page.census_digest,page.ordered_entry_root)
        r.phase="owner"
    else:r.core_cursor=page.next_cursor
    r.operation.refresh_retained_state_v3(r)


def require_character_labor_adoption_execution_inventory_v1(inputs,*,db,frame):
    if type(inputs)is not PreparedCharacterLaborAdoptionV1:
        raise AuthorityUnavailable("actual sealed labor inputs required for their signed mixed inventory")
    r=inputs._actual_v1()
    inputs.require_inputs_v1(r.graph,gate=r.gate,db=db,scope=r.scope,owner=r.owner_binding)
    inputs.require_frame_v1(frame)
    if r.execution_inventory is None or canonical_digest(r.execution_inventory)!=r.census.mixed_inventory_digest:
        raise AuthorityUnavailable("labor mixed inventory lost its same-census original binding")
    return r.execution_inventory


def read_bound_character_labor_adoption_artifact_v1(db,prepared):
    bound=_BOUND.get()
    if bound is None:return False,None
    inputs,actual_db,frame,thread=bound
    r=inputs._actual_v1()
    if (actual_db is not db or thread!=get_ident()or prepared is not r.prepared
            or not db.in_transaction or not r.store._lock._is_owned()
            or not r.artifact_complete):
        raise AuthorityUnavailable("labor artifact consumer lost its actual sealed Source Work/frame")
    with runtime_storage_quantum_v3(db)as meter:
        r.require_current(meter=meter)
        if r.terminal.status=="completed":
            from .d11_life_source_note_v1 import STAGE_TABLE
            header=meter.read_fixed_row(db,STAGE_TABLE,
                ("binding_digest","artifact_ref","artifact_digest","artifact_length"),
                "bot=? AND persona=? AND execution_id=?",(*r.namespace.as_tuple,r.gate.binding.execution_id))
            if header!=r.artifact_header or r.artifact_row is None:
                raise AuthorityUnavailable("labor artifact fixed current header changed after complete canonical EOF")
    return True,r.artifact_row


def read_bound_character_labor_adoption_original_v1(db,*,namespace,kind,ref,issuer):
    bound=_BOUND.get()
    if bound is None:return False,None
    inputs,actual_db,frame,thread=bound
    r=inputs._actual_v1()
    if (actual_db is not db or thread!=get_ident()or namespace!=r.namespace
            or issuer is not r.issuer or not db.in_transaction or not r.store._lock._is_owned()):
        raise AuthorityUnavailable("labor signed original crossed its actual current frame/installation")
    key=(kind,ref)
    if kind not in {PREPARED_METADATA_KIND,BODY_KIND,ADMISSION_KIND,"action_admission","character_labor_prepared_v1"}:
        return False,None
    if key not in r.signed_originals:
        raise AuthorityUnavailable("labor signed input original has no selected complete canonical EOF")
    saved=r.signed_originals[key]
    with runtime_storage_quantum_v3(db)as meter:
        r.require_current(meter=meter)
        if kind=="character_labor_prepared_v1":
            if ref!=r.metadata.prepared_ref or r._prepared_header_v1()!=r.expected_prepared_header:
                raise AuthorityUnavailable("labor current Prepared changed its authenticated whole-column EOF")
        else:
            matches=[task for task in r.metadata_tasks.values()
                if task.spec[0]==TABLE and task.spec[3]==(*namespace.as_tuple,kind,ref)]
            if len(matches)!=1 or not matches[0].complete:
                raise AuthorityUnavailable("labor signed original lacks its exact private EOF task")
            matches[0].require_header_v3(meter)
    return True,saved


def require_character_labor_adoption_prepared_digest_v1(prepared):
    bound=_BOUND.get()
    if bound is None:
        raise AuthorityUnavailable("labor Prepared digest needs its actual sealed adoption frame")
    inputs,db,frame,thread=bound
    r=inputs._actual_v1()
    if prepared is not r.prepared or thread!=get_ident()or db is not r.db:
        raise AuthorityUnavailable("labor Prepared digest crossed its actual private Source Work")
    return r.metadata.prepared_digest


# The entry is a scheduling continuation. Its locators carry no Source rights.
_ENTRY_LIVE_V1={}
_ENTRY_PENDING_V1={}


class _CharacterLaborAdoptionEntryV1:
    def __init__(self,graph,bootstrap,parent,namespace,prepared_ref):
        from secrets import token_bytes
        self.graph,self.bootstrap,self.work=graph,bootstrap,parent
        self.namespace,self.prepared_ref=namespace,prepared_ref
        self.ticket,self.thread,self.deadline=parent.ticket,get_ident(),parent.deadline_utc
        self.token=token_bytes(32)
        self.pending=set()
        self.accounted_operation=parent.operation
        self.negative=self.metadata=self.header=self.gate=self.life_port=None
        self.commit_started=self.abandon_attempted=self.closed=False
        self.first_error=None
        parent.operation.register_retained_state_v3(self)
        _ENTRY_LIVE_V1[self.token]=self

    def _runtime_retained_heap_bytes_v3(self):
        return 16384+_payload_heap_v1((self.namespace,self.prepared_ref,self.metadata,self.header,self.pending))

    def require_identity_v1(self,graph):
        if (_ENTRY_LIVE_V1.get(self.token)is not self or self.closed or graph is not self.graph
                or self.thread!=get_ident()or self.work.coordinator is not graph
                or self.work.ticket!=self.ticket):
            raise AuthorityUnavailable("labor entry lost its actual retained Work/ticket/owner thread")
        graph._admin(self.bootstrap)
        return self

    def _remember_v1(self,error):
        if self.first_error is None:self.first_error=error

    def _abandon_v1(self):
        if self.gate is None or self.commit_started or self.abandon_attempted:return
        store=self.graph._GraphCoordinator__store
        if store._db.in_transaction or store._lock._is_owned():
            raise AuthorityUnavailable("labor entry cannot finish an original bridge inside Graph SQL")
        self.abandon_attempted=True
        self.life_port.life_adoption_bridge_v1(binding=self.gate.binding,action="finish",
            gate=self.gate,outcome="abandoned")

    def failed_v1(self,error):
        self._remember_v1(error)
        try:self._abandon_v1()
        except BaseException as later:error.add_note("labor pre-commit bridge abandonment failed: "+type(later).__name__)
        raise error

    def _handoff_v1(self,stage):
        from secrets import token_bytes
        from ..graph_storage_handoff_v3 import issue_graph_storage_handoff_v3
        from .first_ingress_v2 import trusted_upper
        self.require_identity_v1(self.graph)
        parent=self.work
        parent._require_invocation(self.graph)
        if not parent.terminal or not parent._finish_called or parent.phase!="complete":
            raise AuthorityUnavailable("labor continuation needs its actual completed metadata parent")
        locator=token_bytes(32)
        _ENTRY_PENDING_V1[locator]=(self,parent,stage)
        self.pending.add(locator)
        now=trusted_upper(self.graph._GraphCoordinator__content_fence_v2.read_ingress_clock(
            self.graph._GraphCoordinator__scene_clock_policy))
        try:
            return issue_graph_storage_handoff_v3(parent,factory=_start_character_labor_adoption_entry_v1,
                command=locator,deadline_utc=min(self.deadline,parent.deadline_utc),observed_utc=now)
        except BaseException:
            _ENTRY_PENDING_V1.pop(locator,None);self.pending.discard(locator)
            raise

    def cold_v1(self,result):
        try:
            from .character_labor_adoption_metadata_v1 import (
                PreparedCharacterLaborColdAckV1,require_no_committed_character_labor_adoption_v1)
            self.require_identity_v1(self.graph)
            self.work._require_invocation(self.graph)
            if type(result)is PreparedCharacterLaborColdAckV1:
                return result.finish_v1(self.graph,self.work)
            self.negative=require_no_committed_character_labor_adoption_v1(result,self.graph,self.work)
            return self._handoff_v1("locator")
        except BaseException as first:
            self._remember_v1(first)
            raise

    def located_v1(self,prepared):
        try:
            from ..host.d11_life_port_v1 import InstalledD11LifePortV1
            from ..authority_service.d11_life_bridge_v1 import D11LifeAdoptionBridgeV1
            self.require_identity_v1(self.graph)
            self.work._require_invocation(self.graph)
            if type(prepared)is not PreparedCharacterLaborAdoptionLocatorV1 or prepared.reader is not self.work.state:
                raise AuthorityUnavailable("labor entry needs its actual terminal Locator preparation")
            metadata,header=prepared.require_v1(self.graph,namespace=self.namespace,prepared_original_ref=self.prepared_ref)
            if metadata is None:
                from .d11_life_adoption_v1 import _adopt_legacy_current_life_v1
                return _adopt_legacy_current_life_v1(self.graph,self.bootstrap,
                    namespace=self.namespace,prepared_original_ref=self.prepared_ref)
            self.life_port=InstalledD11LifePortV1(self.graph._GraphCoordinator__content_fence_v2)
            gate=self.life_port.life_adoption_bridge_v1(binding=metadata.binding,action="begin")
            if type(gate)is not D11LifeAdoptionBridgeV1 or gate.binding!=metadata.binding:
                raise AuthorityUnavailable("labor Locator received another actual original bridge")
            self.metadata,self.header,self.gate=metadata,header,gate
            return self._handoff_v1("source")
        except BaseException as first:
            self._remember_v1(first)
            raise

    def committed_v1(self,inputs):
        try:
            from .d11_life_adoption_v1 import commit_current_character_labor_adoption_v1
            self.require_identity_v1(self.graph)
            self.work._require_invocation(self.graph)
            if (type(inputs)is not PreparedCharacterLaborAdoptionV1 or inputs.owner.work is not self.work
                    or inputs.gate is not self.gate or not self.work.terminal or not self.work._finish_called
                    or self.work.phase!="complete"):
                raise AuthorityUnavailable("labor commit needs its actual completed Source Work and sealed inputs")
            self.commit_started=True
            return commit_current_character_labor_adoption_v1(self.graph,self.bootstrap,inputs)
        except BaseException as first:
            self._remember_v1(first)
            raise

    def adopt_child_v1(self,child,stage):
        if (type(child)is not GraphStorageWorkV3 or child.coordinator is not self.graph
                or child.ticket!=self.ticket or child.terminal or child.deadline_utc>self.deadline
                or child.operation is self.work.operation
                or child.kind!=(LOCATOR_KIND if stage=="locator"else KIND)):
            raise AuthorityUnavailable("labor child changed its actual ticket/deadline/named independent retention")
        previous=self.accounted_operation
        child.operation.register_retained_state_v3(self)
        self.accounted_operation=child.operation
        previous.unregister_retained_state_v3(self)
        self.work=child
        self.metadata=self.header=None
        return child.map_terminal_v3("issuer",
            self.located_v1 if stage=="locator"else self.committed_v1,self.failed_v1)

    def close_v1(self):
        if self.closed:return
        first=self.first_error
        try:self._abandon_v1()
        except BaseException as later:
            if first is None:first=later
            else:first.add_note("labor entry cleanup bridge finish failed: "+type(later).__name__)
        self.closed=True
        _ENTRY_LIVE_V1.pop(self.token,None)
        for locator in self.pending:_ENTRY_PENDING_V1.pop(locator,None)
        self.pending.clear()
        try:self.accounted_operation.unregister_retained_state_v3(self)
        except BaseException as later:
            if first is None:first=later
            else:first.add_note("labor entry retention unregister failed: "+type(later).__name__)
        self.graph=self.bootstrap=self.work=self.accounted_operation=None
        self.negative=self.metadata=self.header=self.gate=self.life_port=None
        if first is not None and first is not self.first_error:raise first


def begin_current_character_labor_adoption_entry_v1(graph,bootstrap,*,namespace,prepared_original_ref):
    """Cold ACK first; a real absence continues to the independent Locator."""
    from contextlib import ExitStack
    from .character_labor_adoption_metadata_v1 import begin_current_character_labor_cold_ack_v1
    from ..graph_worker import OwnedGraphStorageResultV3
    parent=begin_current_character_labor_cold_ack_v1(graph,bootstrap,namespace=namespace,
        prepared_original_ref=prepared_original_ref)
    lifetime=ExitStack()
    try:
        record=_CharacterLaborAdoptionEntryV1(graph,bootstrap,parent,namespace,prepared_original_ref)
        lifetime.callback(record.close_v1)
        parent.adopt_request_lifetime_v3(lifetime)
        return parent.map_terminal_v3("issuer",record.cold_v1,record.failed_v1)
    except BaseException as first:
        try:lifetime.close()
        except BaseException as later:first.add_note("labor entry registration cleanup failed: "+type(later).__name__)
        if not parent.terminal:
            try:
                discarded=parent._finish_and_map(graph,None,first)
                if type(discarded)is OwnedGraphStorageResultV3:discarded.release_v3()
            except BaseException as later:
                if later is not first:first.add_note("labor initial cold Work cleanup failed: "+type(later).__name__)
        raise


def _start_character_labor_adoption_entry_v1(graph,locator):
    from ..graph_worker import _STORAGE_INVOCATION_V3,OwnedGraphStorageResultV3
    record,parent,stage=_ENTRY_PENDING_V1.pop(locator,(None,None,None))
    if record is None or type(locator)is not bytes:
        raise AuthorityUnavailable("labor once-only scheduling locator is absent or already consumed")
    record.pending.discard(locator)
    record.require_identity_v1(graph)
    invocation=_STORAGE_INVOCATION_V3.get()
    if (invocation is None or not invocation.initial or invocation.mode!="ordinary"
            or invocation.coordinator is not graph or invocation.ticket!=record.ticket
            or record.work is not parent):
        raise AuthorityUnavailable("labor child requires its actual initial same-ticket handoff")
    child=None
    try:
        if stage=="locator":
            # The marker is consumed, then its actual payload/result lease is
            # closed before admitting the next independently metered Work.
            record.negative.release_payload_v3()
            finish_runtime_storage_operation_v3(parent.operation)
            if not parent.operation.closed:
                raise AuthorityUnavailable("labor negative cold metadata retention has not actually closed")
            record.negative=None
            child=begin_current_character_labor_adoption_locator_v1(graph,record.bootstrap,
                namespace=record.namespace,prepared_original_ref=record.prepared_ref)
        elif stage=="source":
            child=begin_current_character_labor_adoption_v1(graph,record.bootstrap,
                life_port=record.life_port,gate=record.gate,
                prepared_metadata=record.metadata,prepared_header=record.header)
        else:
            raise AuthorityUnavailable("labor entry has an unknown fixed scheduling phase")
        return record.adopt_child_v1(child,stage)
    except BaseException as first:
        record._remember_v1(first)
        try:record._abandon_v1()
        except BaseException as later:first.add_note("labor child factory bridge abandonment failed: "+type(later).__name__)
        if (type(child)is GraphStorageWorkV3 and child.coordinator is graph
                and child.ticket==record.ticket and not child.terminal):
            try:
                discarded=child._finish_and_map(graph,None,first)
                if type(discarded)is OwnedGraphStorageResultV3:discarded.release_v3()
            except BaseException as later:
                if later is not first:first.add_note("labor child factory release failed: "+type(later).__name__)
        raise


_EXECUTION_ENTRIES_V1={}
_EXECUTION_PENDING_V1={}


class _CharacterLaborExecutionEntryV1:
    def __init__(self,graph,bootstrap,parent,namespace,prepared_ref):
        from secrets import token_bytes
        from ..runtime_storage_v3 import RuntimeStorageOperationV3,_INSTALLED
        self.graph,self.bootstrap,self.parent=graph,bootstrap,parent
        self.namespace,self.prepared_ref=namespace,prepared_ref
        self.ticket,self.thread=parent.ticket,get_ident()
        self.token=token_bytes(32)
        self.deadline=min(parent.deadline_utc,parent.operation.deadline_utc)
        self.operation=RuntimeStorageOperationV3(_INSTALLED,parent.operation.handle,
            parent.operation_id+":execution-metadata",self.deadline)
        self.binding=self.prepared_digest=self.claim=self.terminal=self.installed=None
        self.waiting=self.legacy=None
        self.locator=None
        self.negative=None
        self.closed=False
        self.first_error=None
        try:self.operation.register_retained_state_v3(self)
        except BaseException as first:
            try:self.operation.release()
            except BaseException as later:first.add_note("labor execution metadata allocation cleanup failed: "+type(later).__name__)
            raise
        _EXECUTION_ENTRIES_V1[self.token]=self

    def _runtime_retained_heap_bytes_v3(self):
        return 16384+_payload_heap_v1((self.namespace,self.prepared_ref,self.binding,
            self.prepared_digest,self.claim,self.terminal,self.waiting,self.legacy,self.negative))

    def require_v1(self,graph):
        if (_EXECUTION_ENTRIES_V1.get(self.token)is not self or self.closed or graph is not self.graph
                or self.thread!=get_ident()or self.operation.closed
                or self.operation.handle is not self.parent.operation.handle
                or self.parent.coordinator is not graph or self.parent.ticket!=self.ticket):
            raise AuthorityUnavailable("labor execution lost its actual metadata retention/ticket/installation")
        self.parent._require_invocation(graph)
        graph._admin(self.bootstrap)
        return self

    def failed_v1(self,error):
        if self.first_error is None:self.first_error=error
        raise error

    def _observe_v1(self,action):
        from .d11_life_contract_v1 import D11LifeClaimV1,D11LifeTerminalV1
        self.operation.reserve_retained_state_growth_v3(self,_payload_heap_v1(self.binding)*8+65536)
        try:
            if action=="read":claim,terminal=self.installed.read_own_d11_life_execution_original_v1(binding=self.binding)
            elif action=="execute":claim,terminal=self.installed.execute_d11_life_v1(binding=self.binding)
            elif action=="recover":claim,terminal=self.installed.recover_claimed_d11_life_v1(binding=self.binding)
            else:raise AuthorityUnavailable("labor execution has an unknown fixed Core observation action")
            if (claim is not None and (type(claim)is not D11LifeClaimV1 or claim.binding!=self.binding)
                    or terminal is not None and (type(terminal)is not D11LifeTerminalV1
                        or terminal.binding!=self.binding or terminal.claim!=claim
                        or terminal.payload.prepared_digest!=self.prepared_digest)
                    or claim is None and terminal is not None):
                raise AuthorityUnavailable("labor Core originals differ from the actual authenticated C binding")
            self.claim,self.terminal=claim,terminal
        finally:self.operation.finish_retained_state_growth_v3(self)

    def _waiting_v1(self,state):
        from .d11_life_driver_v1 import LifeExecutionProgressV1
        self.waiting=LifeExecutionProgressV1(self.prepared_ref,self.claim,self.terminal,None,state)
        self.operation.refresh_retained_state_v3(self)
        return self.waiting

    def _handoff_v1(self,stage):
        from ..graph_storage_handoff_v3 import issue_graph_storage_handoff_v3
        from .first_ingress_v2 import trusted_upper
        from secrets import token_bytes
        self.require_v1(self.graph)
        if not self.parent.terminal or not self.parent._finish_called or self.parent.phase!="complete":
            raise AuthorityUnavailable("labor execution handoff requires its actual completed metadata Work")
        locator=token_bytes(32)
        self.locator=locator
        _EXECUTION_PENDING_V1[locator]=(self,self.parent,stage)
        now=trusted_upper(self.graph._GraphCoordinator__content_fence_v2.read_ingress_clock(
            self.graph._GraphCoordinator__scene_clock_policy))
        try:
            return issue_graph_storage_handoff_v3(self.parent,
                factory=_start_character_labor_execution_stage_v1,command=locator,
                deadline_utc=self.deadline,observed_utc=now)
        except BaseException:
            _EXECUTION_PENDING_V1.pop(locator,None)
            self.locator=None
            raise

    def cold_v1(self,result):
        from .character_labor_adoption_metadata_v1 import (
            PreparedCharacterLaborColdAckV1,require_no_committed_character_labor_adoption_v1,
            require_character_labor_cold_execution_originals_v1)
        try:
            self.require_v1(self.graph)
            if type(result)is PreparedCharacterLaborColdAckV1:
                adoption=result.finish_v1(self.graph,self.parent)
                self.binding,self.prepared_digest,self.claim,self.terminal=(
                    require_character_labor_cold_execution_originals_v1(result,self.graph,self.parent))
                self.operation.refresh_retained_state_v3(self)
                return adoption
            self.negative=require_no_committed_character_labor_adoption_v1(result,self.graph,self.parent)
            return self._handoff_v1("locator")
        except BaseException as first:
            if self.first_error is None:self.first_error=first
            raise

    def located_v1(self,prepared):
        from ..host.d11_life_port_v1 import InstalledD11LifePortV1
        from ..host.v2_fence_port import V2FenceOutcomeUnknown
        try:
            self.require_v1(self.graph)
            if (type(prepared)is not PreparedCharacterLaborAdoptionLocatorV1
                    or prepared.reader is not self.parent.state or not self.parent.terminal
                    or not self.parent._finish_called or self.parent.phase!="complete"):
                raise AuthorityUnavailable("labor execution needs its actual terminal metadata Locator")
            metadata,header=prepared.require_v1(self.graph,namespace=self.namespace,
                prepared_original_ref=self.prepared_ref)
            if metadata is None:
                # The Locator proved the unique old signed header. The private
                # driver independently repeats that positive classification.
                from .d11_life_driver_v1 import _run_legacy_prepared_source_note_v1
                self.legacy=_run_legacy_prepared_source_note_v1(self.graph,self.bootstrap,
                    namespace=self.namespace,prepared_original_ref=self.prepared_ref)
                self.operation.refresh_retained_state_v3(self)
                return self.legacy
            self.binding,self.prepared_digest=metadata.binding,metadata.prepared_digest
            self.installed=InstalledD11LifePortV1(self.graph._GraphCoordinator__content_fence_v2)
            self.operation.refresh_retained_state_v3(self)
            self._observe_v1("read")
            if self.claim is None:
                try:self._observe_v1("execute")
                except V2FenceOutcomeUnknown:
                    self._observe_v1("read")
                    if self.claim is None:return self._waiting_v1("execution_ack_unknown")
            if self.claim is None:
                raise AuthorityUnavailable("labor successful execute returned no actual consumed claim")
            if self.terminal is None:self._observe_v1("recover")
            if self.claim is None:
                raise AuthorityUnavailable("labor original consumed claim disappeared during same-binding recovery")
            if self.terminal is None:return self._waiting_v1("claimed_waiting_actual_executor")
            return self._handoff_v1("adoption")
        except BaseException as first:
            if self.first_error is None:self.first_error=first
            raise

    def progress_v1(self,result):
        from .d11_life_driver_v1 import LifeExecutionProgressV1
        from .d11_life_adoption_v1 import D11LifeAdoptionReceiptV1
        from .d11_life_terminal_v1 import life_adoption_operation_id_v1
        from ..graph_storage_handoff_v3 import _TERMINAL_RETENTION
        try:
            self.require_v1(self.graph)
            if self.legacy is not None:
                if (result is not self.legacy or type(result)is not LifeExecutionProgressV1
                        or result.prepared_original_ref!=self.prepared_ref):
                    raise AuthorityUnavailable("legacy Life driver did not return its actual progress result")
                progress=result
            elif self.waiting is not None:
                if result is not self.waiting:
                    raise AuthorityUnavailable("labor waiting progress is not its actual same-call Core observation")
                progress=result
            else:
                if type(result)is not dict or self.claim is None or self.terminal is None:
                    raise AuthorityUnavailable("labor progress needs the actual completed adoption receipt")
                raw=dict(result);raw["source_refs"]=tuple(raw["source_refs"])
                receipt=D11LifeAdoptionReceiptV1(**raw)
                if (receipt.operation_id!=life_adoption_operation_id_v1(self.binding)
                        or receipt.binding_digest!=self.binding.digest
                        or receipt.terminal_digest!=canonical_digest(plain_v1(self.terminal))
                        or receipt.status!=self.terminal.status
                        or receipt.actual_cpu_ms!=self.terminal.actual_cpu_ms):
                    raise AuthorityUnavailable("labor adoption receipt differs from its actual claim/terminal")
                progress=LifeExecutionProgressV1(self.prepared_ref,self.claim,self.terminal,
                    result,"adopted_"+self.terminal.status)
            retained=_TERMINAL_RETENTION.get()
            if retained is None:
                lease=self.parent.result_lease
            else:
                work,lease=retained
                work._require_invocation(self.graph)
                if work.ticket!=self.ticket:
                    raise AuthorityUnavailable("labor result retention belongs to another worker ticket")
            if lease is None or lease.handle is not self.operation.handle or lease.closed:
                raise AuthorityUnavailable("labor progress has no actual final result retention owner")
            lease.retain(_payload_heap_v1(progress)+65536)
            if progress.adoption is not None:
                wake=getattr(self.graph,"_GraphCoordinator__domain_followup_wake_v1",None)
                if callable(wake):wake()
            return progress
        except BaseException as first:
            if self.first_error is None:self.first_error=first
            raise

    def close_v1(self):
        if self.closed:return
        self.closed=True
        _EXECUTION_ENTRIES_V1.pop(self.token,None)
        if self.locator is not None:_EXECUTION_PENDING_V1.pop(self.locator,None)
        first=self.first_error
        try:self.operation.release()
        except BaseException as later:
            if first is None:first=later
            else:first.add_note("labor execution metadata retention release failed: "+type(later).__name__)
        self.graph=self.bootstrap=self.parent=self.operation=self.installed=None
        self.binding=self.claim=self.terminal=self.waiting=self.legacy=self.negative=None
        self.locator=self.prepared_digest=None
        if first is not None and first is not self.first_error:raise first


def begin_current_character_labor_execution_entry_v1(graph,bootstrap,*,namespace,prepared_original_ref):
    """Finish an existing adoption first, else observe or once-execute C."""
    from contextlib import ExitStack
    from ..graph_worker import OwnedGraphStorageResultV3
    from .character_labor_adoption_metadata_v1 import begin_current_character_labor_cold_ack_v1
    parent=begin_current_character_labor_cold_ack_v1(graph,bootstrap,
        namespace=namespace,prepared_original_ref=prepared_original_ref)
    lifetime=ExitStack()
    try:
        record=_CharacterLaborExecutionEntryV1(graph,bootstrap,parent,namespace,prepared_original_ref)
        lifetime.callback(record.close_v1)
        parent.adopt_request_lifetime_v3(lifetime)
        parent.map_terminal_v3("issuer",record.cold_v1,record.failed_v1)
        return parent.map_terminal_v3("service",record.progress_v1,record.failed_v1)
    except BaseException as first:
        try:lifetime.close()
        except BaseException as later:first.add_note("labor execution entry cleanup failed: "+type(later).__name__)
        if not parent.terminal:
            try:
                discarded=parent._finish_and_map(graph,None,first)
                if type(discarded)is OwnedGraphStorageResultV3:discarded.release_v3()
            except BaseException as later:
                if later is not first:first.add_note("labor execution Locator cleanup failed: "+type(later).__name__)
        raise


def _start_character_labor_execution_stage_v1(graph,locator):
    from ..graph_worker import _STORAGE_INVOCATION_V3,OwnedGraphStorageResultV3
    from .character_labor_adoption_metadata_v1 import COLD_ACK_KIND
    record,parent,stage=_EXECUTION_PENDING_V1.pop(locator,(None,None,None))
    if record is None or type(locator)is not bytes or record.locator is not locator:
        raise AuthorityUnavailable("labor execution scheduling locator is absent or already consumed")
    record.require_v1(graph)
    invocation=_STORAGE_INVOCATION_V3.get()
    if (invocation is None or not invocation.initial or invocation.mode!="ordinary"
            or invocation.coordinator is not graph or invocation.ticket!=record.ticket
            or record.parent is not parent):
        raise AuthorityUnavailable("labor execution must continue its actual initial same-worker ticket")
    record.locator=None
    child=None
    try:
        if stage=="locator":
            record.negative.release_payload_v3()
            finish_runtime_storage_operation_v3(parent.operation)
            if not parent.operation.closed:
                raise AuthorityUnavailable("labor execution cold absence metadata retention has not actually closed")
            record.negative=None
            child=begin_current_character_labor_adoption_locator_v1(graph,record.bootstrap,
                namespace=record.namespace,prepared_original_ref=record.prepared_ref)
        elif stage=="adoption":
            child=begin_current_character_labor_adoption_entry_v1(graph,record.bootstrap,
                namespace=record.namespace,prepared_original_ref=record.prepared_ref)
        else:
            raise AuthorityUnavailable("labor execution has an unknown fixed scheduling phase")
        if (type(child)is not GraphStorageWorkV3 or child.coordinator is not graph or child.ticket!=record.ticket
                or child.terminal or child.deadline_utc>record.deadline
                or child.operation.handle is not record.operation.handle
                or child.kind!=(LOCATOR_KIND if stage=="locator"else COLD_ACK_KIND)):
            raise AuthorityUnavailable("labor execution child changed its ticket/resource deadline/named kind")
        record.parent=child
        if stage=="locator":
            child.map_terminal_v3("issuer",record.located_v1,record.failed_v1)
        return child
    except BaseException as first:
        if record.first_error is None:record.first_error=first
        if (type(child)is GraphStorageWorkV3 and child.coordinator is graph
                and child.ticket==record.ticket and not child.terminal):
            try:
                discarded=child._finish_and_map(graph,None,first)
                if type(discarded)is OwnedGraphStorageResultV3:discarded.release_v3()
            except BaseException as later:
                if later is not first:first.add_note("labor execution child cleanup failed: "+type(later).__name__)
        raise


def _capture_initial_checkpoint_fence_v1(r):
    if r.db.in_transaction or r.store._lock._is_owned():
        raise AuthorityUnavailable("initial Body finished-fence metadata must be read outside Graph SQL")
    original=r.initial_checkpoints[r.checkpoint_fence_pending]
    permit,status=r.port.get_fence_operation(namespace=r.namespace,
        authority_namespace=original.authority_namespace,operation_id=original.attempt_id)
    if (permit is None or status!="finished"or permit.operation!="write"
            or permit.operation_id!=original.attempt_id or permit.namespace!=original.authority_namespace
            or permit.generation!=original.activation_generation or canonical_digest(permit)!=original.permit_digest):
        raise AuthorityUnavailable("initial Body checkpoint has no actual same-digest finished Core WRITE")
    r.initial_checkpoint_fences[original.producing_operation_id]=(permit,status)
    r.checkpoint_fence_pending=None
    r.phase="checkpoints"
    r.operation.refresh_retained_state_v3(r)
