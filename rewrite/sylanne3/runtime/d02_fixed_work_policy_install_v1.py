"""Explicit Owner/admin fixed-work policy adoption, preserving an existing body."""
from dataclasses import asdict
import json

from ..contracts import Event, Scope
from ..domains.d02 import BodyDomain
from ..domains.d02.body_quote_original import FixedBodyPolicyV1, install_body_quote_schema
from ..graph_store import GraphStore
from ..graph_types import GraphCandidate, GraphVersion
from ..runtime_contracts import canonical_digest, canonical_serialize


def register_current_fixed_body_work_policy_v1(graph, bootstrap, authority, lease, *, operation_id, policy):
    graph._admin(bootstrap)
    if (type(policy) is not FixedBodyPolicyV1 or policy.profile.namespace != authority.namespace
            or policy.work_kind not in {"d06.c04_internal_cpu.v1", "d07.cognition"}
            or graph._GraphCoordinator__body_quote_authority is None):
        raise ValueError("an explicit supported installed fixed body policy is required")
    graph._authorize(lease, authority, frozenset(("d02",)), owner_read=True)
    owner = graph._GraphCoordinator__owner_leases.get(lease)
    if owner is None or "d02.body_policy.install" not in owner.capabilities:
        raise ValueError("current signed Owner body-policy installation capability is required")
    namespace, store = authority.namespace, graph._GraphCoordinator__store
    signer = graph._GraphCoordinator__body_quote_authority
    request_digest = canonical_digest(("d02.fixed-work-policy-adoption.v1", namespace, operation_id, policy))
    profile_write = BodyDomain.profile_write(policy.profile)
    state_write = BodyDomain.state_write(namespace, policy.initial_state)
    def commit(db, metadata, epoch, now, current_owner, scope):
        if policy.valid_until <= now:
            raise ValueError("fixed body work policy expired before actual Owner adoption")
        install_body_quote_schema(db)
        profile = db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=?", (profile_write.key.token,)).fetchone()
        state = db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=?", (state_write.key.token,)).fetchone()
        if (profile is None) != (state is None):
            raise ValueError("body profile/state initialization is partial")
        if profile is None:
            writes = (profile_write, state_write)
            reads = (GraphVersion(profile_write.key, 0), GraphVersion(state_write.key, 0))
        else:
            initial = db.execute("SELECT value,valid FROM graph_history WHERE token=? AND revision=1",
                (state_write.key.token,)).fetchone()
            if (profile[2] != 1 or state[2] != 1 or json.loads(profile[1]) != profile_write.value
                    or initial is None or initial[1] != 1 or json.loads(initial[0]) != state_write.value):
                raise ValueError("additional work policy cannot rewrite the original body definition or reset current state")
            # Current fatigue, energy, cursor and unsettled components remain
            # actual current state. Only the explicitly signed work policy is
            # added for an already allowed work kind in the same profile.
            writes = ()
            reads = (GraphVersion(profile_write.key, profile[0]), GraphVersion(state_write.key, state[0]))
        signer.install_policy(db, policy)
        if signer.policy(db, namespace, policy.policy_id, policy.version) != policy:
            raise ValueError("fixed body work policy signature/original did not round trip")
        event = Event(Scope(*namespace.as_tuple, "d02.fixed_work_policy.v1"), operation_id, now,
            "fixed_body_work_policy_adopted", {"policy_id": policy.policy_id, "policy_version": policy.version,
                "policy_digest": canonical_digest(policy), "work_kind": policy.work_kind})
        def adopted(_db, receipt):
            store.cas_graph_recovery_metadata(metadata, metadata.requirements,
                _capability=graph._GraphCoordinator__graph_capability)
        receipt = GraphStore._graph_commit_in_transaction(store, GraphCandidate(event, reads, writes, (epoch,)),
            _receipt_hook=adopted, _capability=graph._GraphCoordinator__graph_capability)
        if receipt.status != "committed":
            raise ValueError("fixed body work policy current adoption did not commit")
        return {"schema": "d02.fixed-work-policy-adoption.v1", "operation_id": operation_id,
            "policy_id": policy.policy_id, "policy_version": policy.version, "policy_digest": canonical_digest(policy),
            "work_kind": policy.work_kind, "body_initialized": profile is None,
            "graph_receipt_digest": canonical_digest(receipt)}
    return graph._owner_domain_write_v3(authority, lease, operation_id=operation_id,
        request_digest=request_digest, domains=("d02",), capability="d02.body_policy.install", commit=commit)
