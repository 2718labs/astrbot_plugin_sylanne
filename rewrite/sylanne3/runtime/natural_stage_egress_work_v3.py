"""Natural acquire -> fresh Source READ, with Graph-thread lease cleanup.

Handoff bytes select original identities. They convey no Source or execution
permission; the child reopens the exact installed operation with current rights.
"""
from contextlib import ExitStack
from dataclasses import asdict, dataclass, replace
from datetime import datetime
import json

from ..authority_service.contract import AuthorityUnavailable
from ..graph_worker import GraphStorageWorkV3
from ..graph_storage_handoff_v3 import issue_graph_storage_handoff_v3
from ..runtime_contracts import AuthorityContext, canonical_digest, canonical_serialize
from ..runtime_storage_v3 import runtime_storage_v3
from .current_graph_full_read_v3 import NATURAL_MODEL_FULL_READ_V3
from .first_ingress_v2 import trusted_upper
from .natural_reply_job_v2 import SavedNaturalPreparationV2


@dataclass(frozen=True, slots=True)
class NaturalStageEgressV3:
    authority: object
    job: object
    call: object
    prepared: tuple


def _installed(graph, bootstrap, bundle):
    graph._admin(bootstrap)
    assembly = graph._GraphCoordinator__d04_installed_joint_assembly
    if assembly is None or assembly.admin_bundle is not bundle:
        raise AuthorityUnavailable("natural stage requires its actual installed assembly")
    return bundle.installation_policy, graph._GraphCoordinator__content_fence_v2


def _attach_lifetime(work, lifetime):
    # The full Source producer already owns its private binder stack.
    moved = lifetime.pop_all()
    if work._request_lifetime is None:
        work.adopt_request_lifetime_v3(moved)
    else:
        work._request_lifetime.callback(moved.close)
    return work


def _original_deadline(graph, expected):
    ns = tuple(expected["namespace"])
    with graph._GraphCoordinator__store._lock:
        row = graph._GraphCoordinator__store._db.execute(
            "SELECT deadline_utc FROM runtime_jobs WHERE bot_id=? AND persona_id=? "
            "AND job_id=? AND operation_id=? AND work_kind=?",
            (*ns, expected["job_id"], expected["original_operation_id"],
             "natural_" + expected["stage"])).fetchone()
    if row is None:
        raise AuthorityUnavailable("natural stage lost its original scoped job deadline")
    return min(expected["deadline_utc"],
        datetime.fromisoformat(row[0].replace("Z", "+00:00")).timestamp())


def _authority(graph, bootstrap, bundle, expected, *, worker_fence=None):
    policy, port = _installed(graph, bootstrap, bundle)
    workflow = getattr(bundle.model_workflows, "natural_" + expected["stage"])
    if ((policy.namespace.as_tuple, policy.installation_id) !=
            (tuple(expected["namespace"]), expected["installation_id"])
            or workflow is None or workflow.work_kind != "natural_" + expected["stage"]
            or workflow.purpose != "proposal" or expected["audience_id"] not in workflow.audiences):
        raise AuthorityUnavailable("natural stage changed its exact installation/workflow/audience")
    anchor = port.current_anchor(namespace=policy.namespace,
        authority_namespace=policy.authority_namespace)
    if anchor.activation_generation != expected["activation_generation"]:
        raise AuthorityUnavailable("natural stage activation changed before its fresh Source READ")
    lease, capability = graph.grant(bootstrap, actor=port.installation_grant.subject,
        issuer_domain="d11", namespace=policy.namespace, domains=("d11",),
        activation_generation=anchor.activation_generation,
        operation_id=expected["acquire_operation_id"])
    authority = AuthorityContext(port.installation_grant.subject, "d11", capability,
        policy.namespace, ("activity",), workflow.purpose, (expected["audience_id"],),
        workflow.provider_config_ref, anchor.activation_generation,
        worker_fence=worker_fence)
    return authority, lease


def _current_saved(graph, authority, lease, bundle, expected):
    saved = graph.read_natural_original_stage_preparation_v2(authority, lease,
        expected["parent_original_id"], expected["stage"], bundle)
    if (type(saved) is not SavedNaturalPreparationV2
            or canonical_digest(asdict(saved.seal)) != expected["seal_digest"]):
        raise AuthorityUnavailable("natural stage original seal changed")
    if expected["stage"] == "review":
        generation = graph.read_natural_original_stage_preparation_v2(authority, lease,
            expected["parent_original_id"], "generation", bundle)
        if (type(generation) is not SavedNaturalPreparationV2 or generation.state != "terminal"
                or canonical_digest(asdict(generation.seal)) != expected["generation_seal_digest"]):
            raise AuthorityUnavailable("natural review lost its actual terminal generation")
    return saved


def start_installed_natural_stage_v3(graph, bootstrap, bundle, *, saved,
        generation_saved, lease_seconds):
    """Return the real Work to the worker, never unpack an unfinished acquire."""
    policy, port = _installed(graph, bootstrap, bundle)
    if (type(saved) is not SavedNaturalPreparationV2
            or type(generation_saved) is not SavedNaturalPreparationV2
            or saved.stage not in {"generation", "review"}
            or generation_saved.stage != "generation"
            or saved.parent_original_id != generation_saved.parent_original_id):
        raise ValueError("natural stage requires its exact generation/review originals")
    anchor = port.current_anchor(namespace=policy.namespace,
        authority_namespace=policy.authority_namespace)
    expected = {"namespace": policy.namespace.as_tuple, "installation_id": policy.installation_id,
        "stage": saved.stage, "parent_original_id": saved.parent_original_id,
        "original_operation_id": saved.seal.original_operation_id,
        "acquire_operation_id": saved.seal.acquire_operation_id, "job_id": saved.seal.job_id,
        "seal_digest": canonical_digest(asdict(saved.seal)),
        "generation_seal_digest": canonical_digest(asdict(generation_saved.seal)),
        "audience_id": generation_saved.frozen.input.plan.audience_id,
        "activation_generation": anchor.activation_generation,
        "deadline_utc": min(generation_saved.frozen.input.expires_at_utc,
            generation_saved.frozen.input.plan.valid_until_utc)}
    authority, lease = _authority(graph, bootstrap, bundle, expected)
    lifetime = ExitStack()
    lifetime.callback(graph.release_authority_lease, bootstrap, lease)
    try:
        deadline = _original_deadline(graph, expected)
        def acquire(proof):
            current = _current_saved(graph, authority, lease, bundle, expected)
            if current.state == "terminal":
                reader = getattr(graph, "read_natural_" + expected["stage"] + "_terminal_receipt_v2")
                return "terminal", reader(authority, lease, expected["parent_original_id"], bundle)
            if current.state not in {"queued", "acquired"}:
                raise AuthorityUnavailable("natural original stage is no longer runnable")
            return graph._acquire_post_c02_natural_stage_v2(authority, lease,
                expected["parent_original_id"], bundle, stage=expected["stage"],
                lease_seconds=lease_seconds, _prepared_full_read=proof)
        if runtime_storage_v3(graph._GraphCoordinator__store._db) is None:
            value = acquire(None)
            if value[0] == "terminal":
                return value
            job, call = value
            acquired_authority = replace(authority, worker_fence=job.fence)
            prepared = graph.read_natural_model_egress_preparation_v2(acquired_authority,
                lease, expected["parent_original_id"], expected["stage"], bundle)
            return NaturalStageEgressV3(acquired_authority, job, call, prepared)
        work = graph._prepare_full_read_then_call_v3(authority, lease,
            NATURAL_MODEL_FULL_READ_V3, acquire, deadline_utc=deadline,
            c02_operation_id=expected["parent_original_id"])
        def acquired(value):
            if value[0] == "terminal":
                return value
            job, call = value
            if (job.job_id != expected["job_id"] or job.operation_id != expected["original_operation_id"]
                    or call.identity.operation_id != expected["acquire_operation_id"]):
                raise AuthorityUnavailable("natural acquire returned another original job/call")
            command = {"schema": "natural.stage-egress-handoff.v3", "expected": expected,
                "worker_fence": job.fence, "call_id": call.call_id,
                "call_digest": call.digest, "deadline_utc": deadline}
            detached_command = canonical_serialize(command).encode()
            value = job = call = None
            # End the acquire's revoked producer binders and local authority on
            # the Graph thread before its child opens a fresh Source context.
            # Result storage remains owned by the actual worker operation.
            parent_lifetime, work._request_lifetime = work._request_lifetime, None
            if parent_lifetime is not None:
                parent_lifetime.close()
            now = trusted_upper(port.read_ingress_clock(bundle.ingress_clock))
            return issue_graph_storage_handoff_v3(work, factory=_start_fresh_egress_v3,
                command=detached_command, deadline_utc=deadline, observed_utc=now)
        def failed(error):
            raise error
        work.map_terminal_v3("service", acquired, failed)
        return _attach_lifetime(work, lifetime)
    finally:
        lifetime.close()


def _start_fresh_egress_v3(graph, command):
    raw = json.loads(command)
    if (type(raw) is not dict or set(raw) != {"schema", "expected", "worker_fence",
            "call_id", "call_digest", "deadline_utc"}
            or raw["schema"] != "natural.stage-egress-handoff.v3"
            or raw["expected"]["stage"] not in {"generation", "review"}):
        raise ValueError("natural egress requires its exact finite handoff")
    expected = raw["expected"]
    assembly = graph._GraphCoordinator__d04_installed_joint_assembly
    if assembly is None:
        raise AuthorityUnavailable("natural egress lost its installed assembly")
    bundle, bootstrap = assembly.admin_bundle, graph._GraphCoordinator__bootstrap
    authority, lease = _authority(graph, bootstrap, bundle, expected,
        worker_fence=raw["worker_fence"])
    lifetime = ExitStack()
    lifetime.callback(graph.release_authority_lease, bootstrap, lease)
    try:
        deadline = min(raw["deadline_utc"], _original_deadline(graph, expected))
        def read(proof):
            current = _current_saved(graph, authority, lease, bundle, expected)
            if current.state != "acquired":
                raise AuthorityUnavailable("natural egress is not the original acquired stage")
            prepared = graph.read_natural_model_egress_preparation_v2(authority, lease,
                expected["parent_original_id"], expected["stage"], bundle,
                _prepared_full_read=proof, _include_job_v3=True)
            call, draft, anchor, job = prepared
            if (call.call_id != raw["call_id"] or call.digest != raw["call_digest"]
                    or call.envelope.authority != authority or job.fence != raw["worker_fence"]
                    or job.operation_id != expected["original_operation_id"]):
                raise AuthorityUnavailable("natural fresh egress changed its exact call/authority/fence")
            return NaturalStageEgressV3(authority, job, call, (call, draft, anchor))
        work = graph._prepare_full_read_then_call_v3(authority, lease,
            NATURAL_MODEL_FULL_READ_V3, read, deadline_utc=deadline,
            c02_operation_id=expected["parent_original_id"])
        if type(work) is not GraphStorageWorkV3:
            raise TypeError("natural handoff child requires its actual fresh Source Work")
        return _attach_lifetime(work, lifetime)
    finally:
        lifetime.close()
