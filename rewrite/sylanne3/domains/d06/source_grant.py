"""Pure D06 source-grant check for a D08 action candidate.

The caller must obtain the snapshot under the authorized graph read fence and
confirm the current access/deletion barrier with D11. A receipt is only a
candidate; D11 rechecks these facts in final delivery admission.
"""

from __future__ import annotations

from dataclasses import dataclass
import math

from ...graph_types import AtomKey, GraphSnapshot
from ...memory_types import SourceRecord, access_key, source_key, validate_access
from ...runtime_contracts import CheckReceipt
from ..d08.execution import ActionIntent


@dataclass(frozen=True)
class SourceGrantRead:
    snapshot: GraphSnapshot
    audience: tuple[str, ...]
    purpose: str
    complete: bool
    current_barrier_confirmed: bool

    def __post_init__(self) -> None:
        if not isinstance(self.snapshot, GraphSnapshot):
            raise TypeError("snapshot must be a GraphSnapshot")
        if (type(self.audience) is not tuple or not self.audience
                or any(type(item) is not str or not item for item in self.audience)):
            raise ValueError("audience must name every recipient")
        if self.purpose not in {"context", "expression", "consolidation", "audit"}:
            raise ValueError("unknown D06 source purpose")
        if type(self.complete) is not bool or type(self.current_barrier_confirmed) is not bool:
            raise TypeError("read coverage and current barrier must be booleans")


def provide_source_grant_check(
    intent: ActionIntent, read: SourceGrantRead, *, valid_until: float,
) -> CheckReceipt:
    """Check every source and ancestor against one fenced, complete read set.

    ``current_barrier_confirmed`` means D11 independently checked the current
    access/deletion watermarks and independent deletion intent. A plain graph
    snapshot cannot establish that fact, so its default is closed.
    """
    if not isinstance(intent, ActionIntent) or not isinstance(read, SourceGrantRead):
        raise TypeError("typed action and source read are required")
    if type(valid_until) not in (int, float) or not math.isfinite(valid_until) or valid_until < 0:
        raise ValueError("valid_until must be a finite nonnegative time")
    specs = [item for item in intent.required_checks if item.check_kind == "source_grant"]
    if len(specs) != 1 or specs[0].provider_id != "d06.source_grant":
        raise ValueError("action must require exactly one D06 source-grant check")
    spec = specs[0]
    if spec.action_ref != intent.action_id or spec.purpose != intent.purpose:
        raise ValueError("source-grant check scope differs from action")

    def receipt(result: str, coverage: str) -> CheckReceipt:
        return CheckReceipt(spec.check_kind, spec.subject_ref, spec.action_ref,
                            spec.purpose, spec.required_input_versions, coverage,
                            result, float(valid_until), spec.provider_id)

    # An action's delivery consumes sources for expression. Other D06 purposes
    # cannot silently authorize that delivery.
    if read.purpose != "expression" or not read.complete or not read.current_barrier_confirmed:
        return receipt("unknown", "partial")
    atoms = {atom.key: atom for atom in read.snapshot.atoms}
    if len(atoms) != len(read.snapshot.atoms) or len(read.snapshot.epochs) != 1:
        return receipt("unknown", "partial")
    epoch = read.snapshot.epochs[0]
    expected = {item.ref: item.version for item in spec.required_input_versions}
    if len(expected) != len(spec.required_input_versions):
        return receipt("unknown", "partial")
    # Every pinned input, including criteria, must be a graph atom in this
    # authorized read. A non-graph version requires another verifier.
    try:
        pinned_keys = {AtomKey.from_token(ref): version for ref, version in expected.items()}
    except (TypeError, ValueError):
        return receipt("unknown", "partial")
    if len(pinned_keys) != len(expected):
        return receipt("unknown", "partial")
    if any(key not in atoms or atoms[key].revision != version or not atoms[key].valid
           for key, version in pinned_keys.items()):
        return receipt("unknown", "partial")

    pending = list(intent.source_refs)
    visited: set[str] = set()
    while pending:
        token = pending.pop()
        try:
            key = AtomKey.from_token(token)
        except (TypeError, ValueError):
            return receipt("unknown", "partial")
        if (key.type_name != "memory.source" or key.name != "record"
                or key.owner.kind != "event"
                or (key.owner.bot, key.owner.persona) != (epoch.bot, epoch.persona)):
            return receipt("unknown", "partial")
        source_id = key.owner.subject
        if source_id in visited:
            continue
        visited.add(source_id)
        access = access_key(epoch.bot, epoch.persona, source_id)
        source_atom, access_atom = atoms.get(key), atoms.get(access)
        if (source_atom is None or access_atom is None or key not in pinned_keys
                or access not in pinned_keys or source_atom.revision < 1
                or access_atom.revision < 1 or not source_atom.valid or not access_atom.valid):
            return receipt("unknown", "partial")
        try:
            source = SourceRecord.from_dict(source_atom.value)
            validate_access(access_atom.value)
        except (TypeError, ValueError):
            return receipt("unknown", "partial")
        if source.source_id != source_id or access_atom.value["source_id"] != source_id:
            return receipt("unknown", "partial")
        if (access_atom.value["status"] != "active"
                or read.purpose not in source.purposes
                or read.purpose not in access_atom.value["purposes"]
                or not set(read.audience).issubset(source.audiences)
                or not set(read.audience).issubset(access_atom.value["audiences"])):
            return receipt("fail", "full")
        pending.extend(source_key(epoch.bot, epoch.persona, parent).token
                       for parent in source.parent_source_ids)
    return receipt("pass", "full")


def provide_prepared_source_grant_check_v3(intent, *, prepared_inventory, db, audience, purpose, valid_until):
    """The same D06 grant rules over actual private full-EOF Source metadata."""
    from ...runtime.dispatch_current_inventory_v3 import PreparedCurrentDispatchInventoryV3, PreparedCurrentDispatchSuccessorInventoryV3
    if (type(prepared_inventory) not in (PreparedCurrentDispatchInventoryV3,PreparedCurrentDispatchSuccessorInventoryV3)
            or not isinstance(intent,ActionIntent)):
        raise TypeError('actual prepared inventory and typed action required')
    prepared_inventory.require_current(db,prepared_inventory.namespace,prepared_inventory.query)
    if (type(audience) is not tuple or not audience or any(type(v) is not str or not v for v in audience)
            or purpose not in {'context','expression','consolidation','audit'}):
        raise ValueError('actual D06 purpose and complete recipients required')
    if type(valid_until) not in (int,float) or not math.isfinite(valid_until) or valid_until<0:
        raise ValueError('valid_until must be a finite nonnegative time')
    specs=[item for item in intent.required_checks if item.check_kind=='source_grant']
    if len(specs)!=1 or specs[0].provider_id!='d06.source_grant':
        raise ValueError('action must require exactly one D06 source-grant check')
    spec=specs[0]
    if spec.action_ref!=intent.action_id or spec.purpose!=intent.purpose:
        raise ValueError('source-grant check scope differs from action')
    def receipt(result,coverage):
        return CheckReceipt(spec.check_kind,spec.subject_ref,spec.action_ref,spec.purpose,
            spec.required_input_versions,coverage,result,float(valid_until),spec.provider_id)
    if purpose!='expression':return receipt('unknown','partial')
    expected={item.ref:item.version for item in spec.required_input_versions}
    if len(expected)!=len(spec.required_input_versions):return receipt('unknown','partial')
    ns=prepared_inventory.namespace
    try:
        pinned={AtomKey.from_token(ref):version for ref,version in expected.items()}
    except (TypeError,ValueError):return receipt('unknown','partial')
    if len(pinned)!=len(expected):return receipt('unknown','partial')
    for key,version in pinned.items():
        if key.type_name=='memory.source':
            source=prepared_inventory.source_metadata(db,ns,prepared_inventory.query,key,require_grant=False)
            if source.revision!=version or not source.valid:return receipt('unknown','partial')
        else:
            atom=prepared_inventory.projection.get(key)
            if atom is None or atom.revision!=version or not atom.valid:return receipt('unknown','partial')
    pending=list(intent.source_refs);visited=set()
    while pending:
        token=pending.pop()
        try:key=AtomKey.from_token(token)
        except (TypeError,ValueError):return receipt('unknown','partial')
        if (key.type_name!='memory.source' or key.name!='record' or key.owner.kind!='event'
                or (key.owner.bot,key.owner.persona)!=ns.as_tuple):return receipt('unknown','partial')
        source_id=key.owner.subject
        if source_id in visited:continue
        visited.add(source_id)
        access=access_key(*ns.as_tuple,source_id)
        source=prepared_inventory.source_metadata(db,ns,prepared_inventory.query,key,require_grant=False)
        access_atom=prepared_inventory.projection.get(access)
        if (access_atom is None or key not in pinned or access not in pinned or source.revision<1
                or access_atom.revision<1 or not source.valid or not access_atom.valid):return receipt('unknown','partial')
        try:validate_access(access_atom.value)
        except (TypeError,ValueError):return receipt('unknown','partial')
        metadata=source.metadata
        if metadata['source_id']!=source_id or access_atom.value['source_id']!=source_id:
            return receipt('unknown','partial')
        if (access_atom.value['status']!='active' or purpose not in metadata['purposes']
                or purpose not in access_atom.value['purposes'] or not set(audience)<=set(metadata['audiences'])
                or not set(audience)<=set(access_atom.value['audiences'])):return receipt('fail','full')
        pending.extend(source_key(*ns.as_tuple,parent).token for parent in metadata['parent_source_ids'])
    return receipt('pass','full')


__all__ = ["SourceGrantRead", "provide_source_grant_check", "provide_prepared_source_grant_check_v3"]
