"""Metadata-only Owner reply cancellation on the existing W01 job ledger.

Authority accepts the intent first. These pure functions need a genuine current
Owner frame and its independently observed Core original before any job changes.
"""
from dataclasses import dataclass, replace

from ..authority_service.contract import AuthorityUnavailable
from ..domains.d01.production_operations_v1 import plain_v1, stage_owner_stop_reply_result_v1
from ..graph_types import AtomKey
from ..runtime_contracts import NamespaceId, canonical_digest, canonical_serialize
from .d01_production_operations_v1 import CurrentDomainReadV1, production_read_plan_v1
from .d11_types import D11RuntimeProvider, D11_PROPOSAL_SCHEMA, job_graph_write
from .domain_production_originals_v1 import read_adopted_domain_operation_v1
from .foreground_cycle_v1 import (decode_foreground_job_v1, foreground_cycle_from_wire_v1,
    foreground_cycle_ids_v1, _adopted_c02_v1)
from .jobs import get_job, cancel_job, _save_job

_TERMINAL = frozenset({"completed", "failed", "cancelled"})


@dataclass(frozen=True, slots=True)
class OwnerReplyCycleIdentityV1:
    namespace: NamespaceId
    c02_operation_id: str
    cycle_job_ref: str
    create_operation_id: str
    create_original_ref: str
    create_original_digest: str
    c02_receipt_digest: str
    responsibility_ref: str | None
    responsibility_digest: str | None


@dataclass(frozen=True, slots=True)
class OwnerReplyMetadataSnapshotV1:
    identity: OwnerReplyCycleIdentityV1
    jobs: tuple
    child_originals: tuple
    pending_effect_refs: tuple
    graph_revision: int
    graph_epoch: int
    expected_cancel_generation: int
    target_cancel_generation: int


def read_original_owner_reply_cycle_identity_v1(db, *, namespace, request):
    """Historical create/C02 metadata only; this grants no current capability."""
    from ..authority_service.owner_stop_reply_v1 import OwnerStopReplyRequestV1
    if (not db.in_transaction or type(namespace) is not NamespaceId
            or type(request) is not OwnerStopReplyRequestV1 or request.namespace != namespace):
        raise AuthorityUnavailable("StopReply metadata needs its exact pinned namespace request")
    key = AtomKey.from_token(request.cycle_job_ref)
    activity, job_id = foreground_cycle_ids_v1(namespace, request.c02_operation_id)
    cycle = decode_foreground_job_v1(plain_v1(get_job(db, job_id)), namespace=namespace)
    continuation = foreground_cycle_from_wire_v1(cycle.continuation)
    if (job_graph_write(cycle).key != key or cycle.activity_id != activity
            or continuation.c02_operation_id != request.c02_operation_id):
        raise AuthorityUnavailable("StopReply locator differs from the actual C02 cycle")
    create = read_adopted_domain_operation_v1(db, namespace, cycle.operation_id)
    if create is None or (create["domain"], create["operation_kind"]) not in {
            ("d11", "create_foreground_cycle"), ("d11", "create_foreground_cycle_v2")}:
        raise AuthorityUnavailable("StopReply target has no actual foreground create original")
    provenance = create["payload"]["provenance"]
    born = decode_foreground_job_v1(provenance["after_job"], namespace=namespace)
    from .natural_producer_qualification_v1 import _producer_original_point_v3
    from .domain_background_read_v3 import background_json_matches_v3
    birth = _producer_original_point_v3(db, table='runtime_job_operations',
        columns=('digest', 'job_id', 'job_json'),
        key_columns=('bot_id', 'persona_id', 'operation_id', 'phase'),
        key=(*namespace.as_tuple, cycle.operation_id, 'create'),
        legacy_reader=lambda: db.execute("SELECT digest,job_id,job_json FROM runtime_job_operations "
            "WHERE bot_id=? AND persona_id=? AND operation_id=? AND phase='create'",
            (*namespace.as_tuple, cycle.operation_id)).fetchone())
    if (provenance["before_job"] is not None or born.phase != "queued" or born.cancel_epoch
            or birth is None or birth[:2] != (canonical_digest(born.continuation), born.job_id)
            or not background_json_matches_v3(birth[2], plain_v1(born))
            or (cycle.job_id, cycle.operation_id, cycle.activity_id, cycle.budget_ref, cycle.deadline_utc)
                != (born.job_id, born.operation_id, born.activity_id, born.budget_ref, born.deadline_utc)):
        raise AuthorityUnavailable("StopReply immutable create/job occurrence differs")
    responsibility_ref = getattr(continuation, "responsibility_ref", None)
    responsibility_digest = getattr(continuation, "responsibility_digest", None)
    born_continuation = foreground_cycle_from_wire_v1(born.continuation)
    if (responsibility_ref, responsibility_digest) != (
            getattr(born_continuation, "responsibility_ref", None),
            getattr(born_continuation, "responsibility_digest", None)):
        raise AuthorityUnavailable("StopReply current cycle changed its original responsibility")
    if responsibility_ref is not None:
        from .foreground_cycle_v1 import ForegroundResponsibilityV1
        from .domain_production_original_codec_v1 import decode_typed_production_value_v1
        responsibility = decode_typed_production_value_v1(
            provenance["foreground_responsibility"], ForegroundResponsibilityV1)
        if (responsibility.digest != responsibility_digest or responsibility.namespace != namespace
                or responsibility.c02_operation_id != request.c02_operation_id):
            raise AuthorityUnavailable("StopReply responsibility/create commitment differs")
    c02 = _adopted_c02_v1(db, namespace, request.c02_operation_id)
    identity = OwnerReplyCycleIdentityV1(namespace, request.c02_operation_id, key.token,
        cycle.operation_id, "d11-current:" + create["original_digest"][:48],
        create["original_digest"], canonical_digest(c02), responsibility_ref, responsibility_digest)
    return identity, cycle


def read_plan_owner_stop_reply_v1(db, *, namespace, request, issuer):
    """Read actual create/C02/child metadata without Source content eligibility."""
    from .foreground_cycle_v1 import (read_original_reply_child_jobs_v1,
        read_original_reply_pending_effects_v1)
    identity, cycle = read_original_owner_reply_cycle_identity_v1(db, namespace=namespace, request=request)
    children = read_original_reply_child_jobs_v1(db, namespace=namespace, cycle=cycle, issuer=issuer)
    jobs, commitments = [cycle], []
    seen = {cycle.job_id}
    for child, original_ref, original_digest in children:
        if (child.job_id in seen or (child.bot_id, child.persona_id) != namespace.as_tuple
                or get_job(db, child.job_id) != child):
            raise AuthorityUnavailable("StopReply child original is duplicate or outside the actual scope")
        seen.add(child.job_id)
        jobs.append(child)
        commitments.append((job_graph_write(child).key.token, original_ref, original_digest))
    from .natural_producer_qualification_v1 import _producer_original_point_v3
    metadata = _producer_original_point_v3(db, table='graph_recovery_metadata_v2',
        columns=('graph_revision',), key_columns=('bot', 'persona'), key=namespace.as_tuple,
        legacy_reader=lambda: db.execute(
            "SELECT graph_revision FROM graph_recovery_metadata_v2 WHERE bot=? AND persona=?",
            namespace.as_tuple).fetchone())
    epoch = _producer_original_point_v3(db, table='graph_epochs',
        columns=('revision',), key_columns=('bot', 'persona'), key=namespace.as_tuple,
        legacy_reader=lambda: db.execute("SELECT revision FROM graph_epochs WHERE bot=? AND persona=?",
            namespace.as_tuple).fetchone())
    if metadata is None or epoch is None:
        raise AuthorityUnavailable("StopReply actual Graph metadata is absent")
    target = cycle.cancel_epoch + (0 if cycle.phase in _TERMINAL else 1)
    pending = read_original_reply_pending_effects_v1(db, namespace=namespace, cycle=cycle,
        children=tuple(jobs[1:]), issuer=issuer)
    return OwnerReplyMetadataSnapshotV1(identity, tuple(jobs), tuple(commitments),
        pending, metadata[0], epoch[0], cycle.cancel_epoch, target)


def read_plan_owner_stop_reply_projection_v1(db, *, namespace, request, original_ref, issuer):
    metadata = read_plan_owner_stop_reply_v1(db, namespace=namespace, request=request, issuer=issuer)
    return production_read_plan_v1((), tuple(job_graph_write(job).key for job in metadata.jobs),
        (), (original_ref,))


@dataclass(frozen=True, slots=True)
class OwnerStopReplyProjectionStageV1:
    frame: object
    request: object
    original: object
    before_jobs: tuple
    after_jobs: tuple
    stage: object


def _cancel_operation_v1(operation_id, job_id):
    return "owner-stop-job:" + canonical_digest((operation_id, job_id))[:48]


def stage_owner_stop_reply_projection_v1(db, *, frame, request, original, installed_readers):
    from ..authority_service.owner_stop_reply_v1 import require_owner_stop_reply_original_v1
    read = CurrentDomainReadV1(frame)
    read.check(db)
    ns = frame.envelope.authority.namespace
    require_owner_stop_reply_original_v1(original, request=request)
    read.original(original.original_ref, kind="owner_stop_reply_v1", digest=original.original_digest[7:])
    owner = frame.owner_guard
    if (ns != request.namespace or original.namespace != ns
            or (original.owner_grant_ref, original.owner_grant_revision, original.owner_grant_digest)
                != (owner.grant_ref, owner.grant_revision, "sha256:" + owner.grant_digest)
            or original.activation_generation != frame.activation_generation):
        raise AuthorityUnavailable("StopReply projection needs its same actual current Owner frame")
    owner_refs = tuple(item for item in original.authority_refs if item[0] == "owner")
    if (len(owner_refs) != 1 or owner_refs[0][1].removeprefix("owner-authority:").removeprefix("sha256:")
            != owner.owner_head_digest):
        raise AuthorityUnavailable("StopReply initiating Owner head differs from the actual current frame")
    metadata = read_plan_owner_stop_reply_v1(db, namespace=ns, request=request, issuer=installed_readers.issuer)
    if ("reply_cycle_create", metadata.identity.create_original_ref,
            "sha256:" + metadata.identity.create_original_digest) not in original.authority_refs:
        raise AuthorityUnavailable("StopReply projection changed its accepted create identity")
    target = original.result.effective_version
    cycle = metadata.jobs[0]
    if cycle.cancel_epoch not in {request.expected_cancel_generation, target}:
        raise AuthorityUnavailable("StopReply projection cancellation algebra changed")
    after = []
    for job in metadata.jobs:
        operation = _cancel_operation_v1(original.operation_id, job.job_id)
        prior = db.execute("SELECT digest,job_id,job_json FROM runtime_job_operations "
            "WHERE bot_id=? AND persona_id=? AND operation_id=? AND phase='cancel'",
            (*ns.as_tuple, operation)).fetchone()
        if prior is not None:
            if prior[0:2] != (original.original_digest[7:], job.job_id):
                raise AuthorityUnavailable("StopReply original job cancellation identity changed")
            updated = job
        elif job.phase in _TERMINAL:
            updated = job
        elif job.lease_holder is not None:
            updated = replace(job, phase="draining", cancel_epoch=job.cancel_epoch + 1, fence=job.fence + 1)
        else:
            updated = replace(job, phase="cancelled", cancel_epoch=job.cancel_epoch + 1, wake_condition=None)
        if job.job_id == cycle.job_id:
            continuation = foreground_cycle_from_wire_v1(job.continuation)
            updated = replace(updated, cancel_epoch=target,
                continuation=plain_v1(replace(continuation, cancel_generation=target)))
        after.append(updated)
    after = tuple(after)
    staged = stage_owner_stop_reply_result_v1(frame, "d11", "owner_stop_reply_v1", request,
        writes=tuple(job_graph_write(job) for job in after),
        provenance={"stop_original_ref": original.original_ref, "stop_original_digest": original.original_digest,
            "cycle_identity": metadata.identity, "before_jobs": metadata.jobs, "after_jobs": after,
            "child_originals": metadata.child_originals}, proposal_schema=D11_PROPOSAL_SCHEMA,
        proposal_hash=D11RuntimeProvider().descriptor.request_schema_hash)
    return OwnerStopReplyProjectionStageV1(frame, request, original, metadata.jobs, after, staged)


def apply_owner_stop_reply_projection_once_v1(db, stage, installed_readers):
    if type(stage) is not OwnerStopReplyProjectionStageV1:
        raise TypeError("actual pure StopReply stage required")
    if stage_owner_stop_reply_projection_v1(db, frame=stage.frame, request=stage.request,
            original=stage.original, installed_readers=installed_readers) != stage:
        raise AuthorityUnavailable("StopReply projection changed before its real Graph CAS")
    result = []
    for before, after in zip(stage.before_jobs, stage.after_jobs, strict=True):
        operation = _cancel_operation_v1(stage.original.operation_id, before.job_id)
        prior = db.execute("SELECT digest,job_id FROM runtime_job_operations WHERE bot_id=? AND persona_id=? "
            "AND operation_id=? AND phase='cancel'", (before.bot_id, before.persona_id, operation)).fetchone()
        if prior is not None:
            if prior != (stage.original.original_digest[7:], before.job_id) or before != after:
                raise AuthorityUnavailable("StopReply existing immutable cancellation differs")
            result.append(before)
            continue
        actual = cancel_job(db, before.job_id, operation, stage.original.original_digest[7:])
        if before is stage.before_jobs[0] and actual != after:
            # Existing cancel_job owns the once operation; only its foreground
            # continuation algebra is added to that same immutable occurrence.
            if replace(actual, continuation=after.continuation) != after:
                raise AuthorityUnavailable("StopReply actual parent cancellation differs")
            _save_job(db, after)
            db.execute("UPDATE runtime_job_operations SET job_json=? WHERE bot_id=? AND persona_id=? "
                "AND operation_id=? AND phase='cancel' AND job_id=?", (canonical_serialize(plain_v1(after)),
                before.bot_id, before.persona_id, operation, before.job_id))
            actual = after
        if actual != after:
            raise AuthorityUnavailable("StopReply actual child cancellation differs from its proposal")
        result.append(actual)
    return tuple(result)


def read_original_owner_stop_reply_projection_v1(db, *, namespace, original):
    """Read the actual W01 adoption and its exact job-cancel occurrences."""
    from ..authority_service.owner_stop_reply_v1 import require_owner_stop_reply_original_v1
    require_owner_stop_reply_original_v1(original)
    adopted = read_adopted_domain_operation_v1(db, namespace, original.operation_id)
    if adopted is None:
        return None
    if (adopted["domain"], adopted["operation_kind"]) != ("d11", "owner_stop_reply_v1"):
        raise AuthorityUnavailable("StopReply operation is not its actual Graph projection")
    provenance = adopted["payload"]["provenance"]
    if (provenance["stop_original_ref"], provenance["stop_original_digest"]) != (original.original_ref, original.original_digest):
        raise AuthorityUnavailable("StopReply Graph projection refers to another accepted original")
    for raw in provenance["after_jobs"]:
        from .jobs import _job_from_dict
        projected = _job_from_dict(raw)
        operation = _cancel_operation_v1(original.operation_id, projected.job_id)
        row = db.execute("SELECT digest,job_id,job_json FROM runtime_job_operations WHERE bot_id=? AND persona_id=? "
            "AND operation_id=? AND phase='cancel'", (*namespace.as_tuple, operation)).fetchone()
        if row != (original.original_digest[7:], projected.job_id, canonical_serialize(plain_v1(projected))):
            raise AuthorityUnavailable("StopReply projection lost its immutable actual job cancellation")
    return "d11-current:" + adopted["original_digest"][:48]
