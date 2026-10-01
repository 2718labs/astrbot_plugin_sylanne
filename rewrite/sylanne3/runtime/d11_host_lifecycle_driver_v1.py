"""Current Owner-fenced recording of a concrete Host's observed boundaries."""
from dataclasses import dataclass
import json

from ..authority_service.v2_owner_contract import OwnerPrincipalV1
from ..graph_types import owner_grant_key
from ..runtime_contracts import AuthorityContext, canonical_digest
from .d11_host_lifecycle_v1 import InstalledHostLifecycleObserverV1, HostLifecycleRequestV1

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


def record_current_host_lifecycle_v1(graph, bootstrap, bundle, *, observer, observation):
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
    with store._lock:
        metadata, _ = graph._v2_graph_stamp(ns)
        row = store._db.execute("SELECT value,valid FROM graph_atoms WHERE token=?",
            (owner_grant_key(*ns.as_tuple).token,)).fetchone()
        if row is None or row[1] != 1:
            raise ValueError("Host observation awaits actual initial Owner")
        original = json.loads(row[0])
    principal = OwnerPrincipalV1(**original["principal"])
    pairing = port.current_owner_principal_binding(namespace=ns,
        authority_namespace=metadata.requirements.authority_namespace, principal=principal)
    if pairing is None:
        raise ValueError("Host lifecycle current Owner is unpaired")
    purposes = set(original["purposes"]) & {"context", "audit", "consolidation"}
    if not purposes:
        raise ValueError("Host lifecycle lacks explicit Owner source purpose")
    authority = AuthorityContext(pairing.actor_id, "d11", "installed-host:" + operation_id,
        ns, ("d06", "d11"), sorted(purposes)[0], tuple(sorted(original["audiences"])),
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
