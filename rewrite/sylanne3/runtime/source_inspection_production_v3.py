"""Prepare only actual D06 output inspection CAS keys before the same READ seals."""
from dataclasses import replace
from weakref import WeakKeyDictionary

from ..authority_service.contract import AuthorityUnavailable
from ..domains.d06.inspection_metadata_v1 import inspection_key_v1
from .source_inspection_producer_targets_v1 import (
    SIMPLE_INSPECTION_PRODUCERS_V1, inspection_producer_target_keys_v1)

_TARGETS = WeakKeyDictionary()


def augment_current_source_inspection_outputs_v3(reader, snapshot):
    from .current_method_learning_read_v3 import (
        _MethodLearningReadV3, BorrowedMethodLearningReadV3, _method_active, _READERS)
    if reader.operation_kind not in SIMPLE_INSPECTION_PRODUCERS_V1:
        return False
    if (type(reader) not in (_MethodLearningReadV3, BorrowedMethodLearningReadV3)
            or reader not in _READERS or _method_active(reader.db) is not reader
            or reader.inputs_sealed or reader.read_finished or reader.business_started
            or reader.work.state is not reader or reader.work.operation is not reader.operation
            or reader.operation.closed or not reader.db.in_transaction):
        raise AuthorityUnavailable('Source output planning requires its actual unsealed same-Work READ')
    reader.require_current()
    targets = inspection_producer_target_keys_v1(reader.namespace, reader.operation_kind,
        reader.request, operation_id=reader.operation_id)
    before = _TARGETS.setdefault(reader, (targets, reader.selected_plan))
    if targets != before[0]:
        raise AuthorityUnavailable('Source output keys changed after their original preselection')
    versions = {v.key: v.revision for v in snapshot.versions}
    if any(key not in versions for key in targets):
        raise AuthorityUnavailable('Source producer target lacks its actual current CAS read')
    metadata = tuple(inspection_key_v1(key, versions[key] + 1) for key in targets)
    missing = tuple(key for key in metadata if key not in reader.selected_plan.exact_keys)
    if missing:
        from .domain_production_contracts_v1 import ProductionOperationLimitsV1
        keys = tuple(sorted(set((*reader.selected_plan.exact_keys, *missing)), key=lambda k:k.token))
        if len(keys) > ProductionOperationLimitsV1().max_graph_heads:
            raise AuthorityUnavailable('Source inspection output closure exceeds the original head bound')
        # The next ordinary selected-input pass reads actual headers and rebuilds
        # the frame under the original Source/Owner/fence/deadline, before seal.
        reader.selected_plan = replace(reader.selected_plan, exact_keys=keys)
        reader.frame_fields = None
        return True
    if any(versions.get(key) != 0 for key in metadata):
        raise AuthorityUnavailable('Source inspection immutable output is occupied or not actually CAS-read')
    return False


def source_inspection_prepared_plan_v3(db, *, graph, scope, plan):
    from .current_method_learning_read_v3 import _method_active, _READERS
    reader = _method_active(db)
    saved = _TARGETS.get(reader) if reader is not None else None
    if saved is None:
        return plan
    if (reader not in _READERS or reader.graph is not graph or reader.db is not db
            or reader.work.state is not reader or reader.operation.closed
            or not reader.inputs_sealed or scope.operation != 'write'
            or scope.namespace != reader.namespace or plan != saved[1]):
        raise AuthorityUnavailable('Source inspection WRITE changed the actual prepared base plan or Work')
    # Only the exact independently prepared plan is substituted. Normal frame
    # construction still validates the new WRITE scope, original Owner and Source.
    return reader.selected_plan
