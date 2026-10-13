"""Current Owner-fenced recording of a concrete Host's observed boundaries."""
from dataclasses import dataclass
import json

from ..authority_service.v2_owner_contract import OwnerPrincipalV1
from ..graph_types import owner_grant_key
from ..runtime_contracts import AuthorityContext, canonical_digest
from .d11_host_lifecycle_v1 import (InstalledHostLifecycleObserverV1, HostLifecycleRequestV1,
    read_current_host_lifecycle_scope_v1)
from .first_ingress_v2 import trusted_upper

_ACTIVE = {}


@dataclass(frozen=True, slots=True)
class _BackgroundHostLifecycleV1:
    graph: object
    authority: AuthorityContext
    owner: object
    operation_id: str
    observer: InstalledHostLifecycleObserverV1
    observation: object


def require_background_host_lifecycle_v1(value, graph, authority, operation_id):
    if (type(value) is not _BackgroundHostLifecycleV1 or _ACTIVE.get(id(value)) is not value
            or value.graph is not graph or value.authority != authority or value.operation_id != operation_id
            or value.observer.context._v2_coordinator is not graph):
        raise ValueError("actual installed Host lifecycle issuance unavailable")
    value.observer.verify_observation_v1(value.observation)
    return value.owner


def _record_legacy_host_lifecycle_v1(graph, bootstrap, bundle, *, observer, observation):
    graph._admin(bootstrap)
    if type(observer) is not InstalledHostLifecycleObserverV1:
        raise TypeError("concrete installed Host lifecycle observer required")
    observer.verify_observation_v1(observation)
    if (observer.context._v2_coordinator is not graph or observer.context._v2_model_bundle is not bundle
            or observer.context._v2_bootstrap is not bootstrap):
        raise ValueError("Host lifecycle belongs to another installed runtime")
    ns, store, port = bundle.installation_policy.namespace, graph._GraphCoordinator__store, graph._GraphCoordinator__content_fence_v2
    operation_id = "host-observed:" + canonical_digest((ns, observation.kind,
        observation.host_incarnation, observation.observation_id))[:48]
    now = trusted_upper(port.read_ingress_clock(graph._GraphCoordinator__scene_clock_policy))
    with store._lock:
        metadata, _ = graph._v2_graph_stamp(ns)
        row = store._db.execute("SELECT value,valid FROM graph_atoms WHERE token=?",
            (owner_grant_key(*ns.as_tuple).token,)).fetchone()
        if row is None or row[1] != 1:
            raise ValueError("Host observation awaits actual initial Owner")
        original = json.loads(row[0])
        audiences, purposes, _ = read_current_host_lifecycle_scope_v1(store._db, namespace=ns,
            issuer=graph._GraphCoordinator__d11_issuer, now_utc=now)
    principal = OwnerPrincipalV1(**original["principal"])
    pairing = port.current_owner_principal_binding(namespace=ns,
        authority_namespace=metadata.requirements.authority_namespace, principal=principal)
    if pairing is None:
        raise ValueError("Host lifecycle current Owner is unpaired")
    authority = AuthorityContext(pairing.actor_id, "d11", "installed-host:" + operation_id,
        ns, ("d06", "d11"), purposes[0], audiences,
        port.installation_grant.publisher_policy_ref, metadata.requirements.activation_generation)
    captured = []
    from .domain_followup_consumer_v1 import _observe_owner
    def observe(scope):
        result = _observe_owner(graph, authority, scope)
        captured[:] = [result]
        return result
    graph._read_v2(authority, lambda: None, fence_observer=observe)
    issued = _BackgroundHostLifecycleV1(graph, authority, captured[0][1], operation_id, observer, observation)
    _ACTIVE[id(issued)] = issued
    try:
        return graph._GraphCoordinator__domain_production_runtime_v1.run_current(authority, None,
            operation_kind="record_host_lifecycle",
            request=HostLifecycleRequestV1(observation.kind, observation.host_incarnation, observation.observation_id),
            operation_id=operation_id, activity_id="d11.host_lifecycle.v1", audience_ref=authority.audience[0],
            parent_budget_lease_ref=bundle.installation_policy.root_grant.lease_id,
            _background_host_lifecycle=issued)
    finally:
        _ACTIVE.pop(id(issued), None)


def record_current_host_lifecycle_v1(graph,bootstrap,bundle,*,observer,observation):
    from ..runtime_storage_v3 import runtime_storage_v3
    if runtime_storage_v3(graph._GraphCoordinator__store._db) is None:
        return _record_legacy_host_lifecycle_v1(graph,bootstrap,bundle,observer=observer,observation=observation)
    from .domain_background_read_v3 import prepare_domain_background_read_v3,raise_background_work_error_v3
    observer.verify_observation_v1(observation)
    ns=bundle.installation_policy.namespace
    operation_id='host-observed:'+canonical_digest((ns,observation.kind,observation.host_incarnation,observation.observation_id))[:48]
    now=trusted_upper(graph._GraphCoordinator__content_fence_v2.read_ingress_clock(graph._GraphCoordinator__scene_clock_policy))
    work=prepare_domain_background_read_v3(graph,bootstrap,bundle,kind='host_lifecycle',operation_id=operation_id,
        deadline_utc=now+60,context=observer.context,observer=observer,observation=observation)
    work.map_terminal_v3('issuer',lambda prepared:finish_background_host_lifecycle_data_v3(graph,prepared),raise_background_work_error_v3)
    return work


def prepare_background_host_lifecycle_data_v3(reader):
    from .domain_background_read_v3 import prepare_background_command_frame_v3
    request=HostLifecycleRequestV1(reader.observation.kind,reader.observation.host_incarnation,reader.observation.observation_id)
    frame=prepare_background_command_frame_v3(reader,operation_kind='record_host_lifecycle',request=request,
        operation_id=reader.operation.operation_id,activity_id='d11.host_lifecycle.v1',audience_ref=reader.authority.audience[0],
        parent_budget_lease_ref=reader.bundle.installation_policy.root_grant.lease_id)
    return request,frame


def finish_background_host_lifecycle_data_v3(graph,prepared):
    from .domain_background_read_v3 import PreparedBackgroundOperationV3,bind_background_reads_v3
    if type(prepared)is not PreparedBackgroundOperationV3:raise TypeError('actual Host background preparation required')
    prepared.require_v3(graph);reader=prepared.owner;request,frame=prepared.local_result
    issued=_BackgroundHostLifecycleV1(graph,reader.authority,reader.owner,reader.operation.operation_id,reader.observer,reader.observation)
    _ACTIVE[id(issued)]=issued
    try:
        with bind_background_reads_v3(reader,db=reader.db):
            return graph._GraphCoordinator__domain_production_runtime_v1.run_current(reader.authority,None,
                operation_kind='record_host_lifecycle',request=request,operation_id=issued.operation_id,
                activity_id='d11.host_lifecycle.v1',audience_ref=reader.authority.audience[0],
                parent_budget_lease_ref=reader.bundle.installation_policy.root_grant.lease_id,
                _background_host_lifecycle=issued)
    finally:_ACTIVE.pop(id(issued),None)
