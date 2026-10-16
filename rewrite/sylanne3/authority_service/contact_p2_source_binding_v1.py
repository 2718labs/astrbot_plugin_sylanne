"""Actual issued Source-location and installed Core selection facts for P2's Core transaction."""
from dataclasses import dataclass
from weakref import WeakKeyDictionary
from .contract import AuthorityUnavailable
from .current_source_location_v1 import require_current_source_anchor_in_tx_v1
from .current_authority_graph_read_v3 import AuthorityGraphReadWorkV3
from ..runtime_storage_v3 import runtime_storage_v3
_ISSUED=WeakKeyDictionary()

@dataclass(frozen=True,eq=False)
class ContactP2SourceBindingV1:
    location_service:object
    location:object
    core_handle:object
    core_db:object
    selection_digest:str
    pointer_version:int
    manifest_digest:str
    storage_generation:int
    control:object
    expected_anchor:object
    holder:str

def capture_contact_p2_source_binding_v1(work,*,expected_anchor):
    if type(work)is not AuthorityGraphReadWorkV3:raise AuthorityUnavailable('P2 source binding requires its actual registered READ Work')
    service=work.controller.location
    with work.quantum_v3()as meter:
        value=service._require_issued(work.contact_location,'business')
    value.context.require_current('business')
    if value.core_anchor!=expected_anchor:raise AuthorityUnavailable('P2 Source observation belongs to another exact handoff Core anchor')
    db=work.controller.fences.core._db;handle=runtime_storage_v3(db)
    if (handle is None or handle.db is not db or handle.role!='core' or handle._closed
            or handle.selected.basis.control is not service._control or handle.selection_digest!=work.selection_digest
            or (handle.context.pointer_version,handle.context.manifest_digest,handle.context.storage_generation)!=(
                value.pointer_version,value.manifest_digest,value.storage_generation)):
        raise AuthorityUnavailable('P2 Source has another actual installed selected Core binding')
    result=ContactP2SourceBindingV1(service,value,handle,db,handle.selection_digest,value.pointer_version,
        value.manifest_digest,value.storage_generation,service._control,expected_anchor,value.holder)
    _ISSUED[result]=(service,value,handle,db,handle.selection_digest,value.pointer_version,value.manifest_digest,
        value.storage_generation,service._control,expected_anchor,value.holder)
    return result

def require_contact_p2_source_binding_in_tx_v1(db,binding,*,expected_anchor,holder):
    if (type(binding)is not ContactP2SourceBindingV1 or _ISSUED.get(binding)!=(binding.location_service,binding.location,
            binding.core_handle,binding.core_db,binding.selection_digest,binding.pointer_version,binding.manifest_digest,
            binding.storage_generation,binding.control,binding.expected_anchor,binding.holder)
            or db is not binding.core_db or not db.in_transaction or expected_anchor!=binding.expected_anchor or holder!=binding.holder):
        raise AuthorityUnavailable('P2 Core transaction lost its actual privately issued Source observation')
    value=binding.location_service._require_issued(binding.location,'business')
    handle=runtime_storage_v3(db)
    if (value.core_anchor!=expected_anchor or handle is not binding.core_handle or handle.db is not db or handle.role!='core'
            or handle._closed or handle.selection_digest!=binding.selection_digest or handle.selected.basis.control is not binding.control
            or (handle.context.pointer_version,handle.context.manifest_digest,handle.context.storage_generation)!=(
                binding.pointer_version,binding.manifest_digest,binding.storage_generation)
            or (value.context.pointer_version,value.context.manifest_digest,value.context.storage_generation)!=(
                binding.pointer_version,binding.manifest_digest,binding.storage_generation)):
        raise AuthorityUnavailable('P2 Core current selected binding or original Source anchor changed')
    require_current_source_anchor_in_tx_v1(db,namespace=binding.location_service.namespace,expected_anchor=expected_anchor,holder=holder)
    return value
