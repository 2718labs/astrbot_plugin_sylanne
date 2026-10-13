"""Initial-only fixed-Self SourceNote responsibility over actual Owner task authorization."""
from dataclasses import dataclass, fields, replace

from ..domains.d01.production_operations_v1 import plain_v1, stage_result_v1
from ..domains.d03.self_perspective import self_mapping_key, SelfIdentityMapping
from ..graph_types import AtomKey
from ..runtime_contracts import canonical_digest
from .d01_production_operations_v1 import CurrentDomainReadV1, MissingProductionOriginalV1, production_read_plan_v1
from .domain_production_erasure_v1 import decode_typed_production_value_v1
from .domain_production_originals_v1 import read_adopted_domain_operation_v1
from .foreground_cycle_v1 import (
    ForegroundResponsibilityV1, ForegroundCycleContinuationV2, CreateForegroundCycleRequestV2,
    InstalledForegroundCycleReadersV1, ForegroundCycleStageV1, CheckpointForegroundCycleRequestV1,
    SCHEMA_V2, foreground_cycle_ids_v1, foreground_responsibility_ref_v1,
    derive_current_foreground_responsibility_v1, prepare_foreground_cycle_in_transaction_v1,
    _adopted_c02_v1, _original_encoding_attempt_v1,
)
from .foreground_call_plan_v1 import ForegroundCallPlanV1, foreground_reply_budget_ids_v1, prepare_foreground_reply_allocation_v1
from .d11_types import runtime_job_key, job_graph_write, D11RuntimeProvider, D11_PROPOSAL_SCHEMA
from .d11_life_preparation_v1 import _read, _record
from .source_note_task_authorization_v1 import SourceNoteTaskAuthorizationV1, read_source_note_task_authorization_v1

OPERATION = "create_source_note_foreground_cycle_v1"
RESPONSIBILITY_SCHEMA = "d11.foreground-source-note-responsibility.v1"
CONTINUATION_SCHEMA = "d11.foreground-source-note-continuation.v1"
RESPONSIBILITY_KIND = "source_note_foreground_responsibility"


@dataclass(frozen=True, slots=True)
class CreateSourceNoteForegroundCycleRequestV1:
    authorization_original_ref: str

    def __post_init__(self):
        if type(self.authorization_original_ref) is not str or not self.authorization_original_ref.startswith("source-note-task-authorization:"):
            raise ValueError("SourceNote initial creation requires its actual Owner authorization locator")


@dataclass(frozen=True, slots=True, kw_only=True)
class ForegroundSourceNoteResponsibilityV1(ForegroundResponsibilityV1):
    authorization_original_ref: str
    authorization_original_digest: str
    source_refs: tuple[str, ...]
    mode: str = "source_note_authorized_v1"
    schema: str = RESPONSIBILITY_SCHEMA

    def __post_init__(self):
        if self.schema != RESPONSIBILITY_SCHEMA or self.mode != "source_note_authorized_v1":
            raise ValueError("exact initial SourceNote responsibility variant required")
        raw = {field.name: getattr(self, field.name) for field in fields(ForegroundResponsibilityV1)}
        raw.update(schema="d11.foreground-responsibility.v1", mode="bounded_causal_window_v1")
        ForegroundResponsibilityV1(**raw)
        CreateSourceNoteForegroundCycleRequestV1(self.authorization_original_ref)
        if not self.source_refs or any(AtomKey.from_token(ref).type_name != "memory.source" for ref in self.source_refs):
            raise ValueError("SourceNote responsibility preserves all actual authorized Source roots for C09")
        if len(self.authorization_original_digest) != 64 or any(c not in "0123456789abcdef" for c in self.authorization_original_digest):
            raise ValueError("SourceNote responsibility requires its actual Owner authorization commitment")


@dataclass(frozen=True, slots=True, kw_only=True)
class ForegroundSourceNoteContinuationV1(ForegroundCycleContinuationV2):
    authorization_original_ref: str
    authorization_original_digest: str
    schema: str = CONTINUATION_SCHEMA

    def __post_init__(self):
        if self.schema != CONTINUATION_SCHEMA:
            raise ValueError("exact SourceNote continuation schema required")
        raw = {field.name: getattr(self, field.name) for field in fields(ForegroundCycleContinuationV2)}
        raw["schema"] = SCHEMA_V2
        ForegroundCycleContinuationV2(**raw)
        if type(self.call_plan) is not ForegroundCallPlanV1:
            raise ValueError("SourceNote cannot carry an Artifact C4 phase call plan")
        CreateSourceNoteForegroundCycleRequestV1(self.authorization_original_ref)
        if len(self.authorization_original_digest) != 64 or any(c not in "0123456789abcdef" for c in self.authorization_original_digest):
            raise ValueError("SourceNote continuation lost its immutable authorization digest")


def require_current_source_note_authorization_v1(db, *, frame, authorization, issuer, installed_bundle):
    read = CurrentDomainReadV1(frame)
    ns = frame.envelope.authority.namespace
    if (type(authorization) is not SourceNoteTaskAuthorizationV1 or authorization.namespace != ns
            or installed_bundle.installation_policy.installation_id != authorization.installation_id
            or installed_bundle.installation_policy.manifest_digest != authorization.manifest_digest
            or frame.owner_guard != authorization.owner_guard
            or frame.envelope.parent_budget_lease_ref != authorization.parent_budget_lease_ref
            or frame.now_utc >= authorization.original_deadline_utc):
        raise ValueError("SourceNote immutable task lost current Owner/root/deadline qualification")
    qualified = {}
    for name, version, digest in authorization.heads:
        atom = read.head(db, version.key, required=True)
        if atom.revision != version.revision or canonical_digest(atom.value) != digest:
            raise MissingProductionOriginalV1("SourceNote_current_authorized_head:" + name)
        qualified[name] = atom.value
    role, account = qualified["role"], qualified["account"]
    if (role["status"] != "active" or frame.now_utc < role["effective_from"]
            or role["effective_until"] is not None and frame.now_utc >= role["effective_until"]
            or frame.now_utc < account["valid_from"]
            or account["valid_until"] is not None and frame.now_utc >= account["valid_until"]):
        raise MissingProductionOriginalV1("SourceNote_initial_current_role_account_time_before_any_allocation")
    grant = issuer.current_budget_grant(db, authorization.parent_budget_lease_ref)
    if (grant.grant_id, grant.version, canonical_digest(grant)) != (
            authorization.parent_grant_id, authorization.parent_grant_version, authorization.parent_grant_digest):
        raise ValueError("SourceNote immutable authorization changed its actual parent grant")
    read.source_family(db, authorization.source_refs)
    return authorization


def derive_source_note_foreground_responsibility_v1(db, *, namespace, request, installed_readers, owner_guard,
        parent_budget_lease_ref, purpose, audiences, now_utc):
    saved = read_source_note_task_authorization_v1(db, namespace=namespace,
        original_ref=request.authorization_original_ref, issuer=installed_readers.issuer)
    if saved is None:
        raise MissingProductionOriginalV1("actual_signed_Owner_SourceNote_task_authorization")
    authorization, actual = saved
    base_request = CreateForegroundCycleRequestV2(authorization.request.c02_operation_id,
        authorization.request.source_ref, foreground_reply_budget_ids_v1(namespace, authorization.request.c02_operation_id)[0],
        cause_original_ref=authorization.cause_original_ref)
    base = derive_current_foreground_responsibility_v1(db, namespace=namespace, request=base_request,
        installed_bundle=installed_readers.installed_bundle, issuer=installed_readers.issuer, owner_guard=owner_guard,
        parent_budget_lease_ref=parent_budget_lease_ref, purpose=purpose, audiences=audiences, now_utc=now_utc)
    if (base.cause_original_digest != authorization.cause_original_digest or base.owner_guard != authorization.owner_guard
            or base.parent_budget_lease_ref != authorization.parent_budget_lease_ref
            or authorization.original_deadline_utc > base.deadline_utc):
        raise ValueError("SourceNote task cannot extend or replace its original C02 causal scope")
    raw = {field.name: getattr(base, field.name) for field in fields(ForegroundResponsibilityV1)}
    raw.update(mode="source_note_authorized_v1", schema=RESPONSIBILITY_SCHEMA,
        deadline_utc=authorization.original_deadline_utc,
        authorization_original_ref=authorization.original_ref, authorization_original_digest=authorization.digest,
        source_refs=authorization.source_refs)
    return ForegroundSourceNoteResponsibilityV1(**raw), authorization


def stage_create_source_note_foreground_cycle_v1(db, *, frame, request, installed_readers):
    if type(request) is not CreateSourceNoteForegroundCycleRequestV1 or type(installed_readers) is not InstalledForegroundCycleReadersV1:
        raise TypeError("SourceNote creation requires its actual fixed-Self installed foreground readers")
    read = CurrentDomainReadV1(frame); read.check(db)
    ns = frame.envelope.authority.namespace
    responsibility, authorization = derive_source_note_foreground_responsibility_v1(db, namespace=ns, request=request,
        installed_readers=installed_readers, owner_guard=frame.owner_guard,
        parent_budget_lease_ref=frame.envelope.parent_budget_lease_ref, purpose=frame.envelope.authority.purpose,
        audiences=frame.envelope.authority.audience, now_utc=frame.now_utc)
    require_current_source_note_authorization_v1(db, frame=frame, authorization=authorization,
        issuer=installed_readers.issuer, installed_bundle=installed_readers.installed_bundle)
    mapping = decode_typed_production_value_v1(read.head(db, self_mapping_key(ns), required=True).value, SelfIdentityMapping)
    if mapping.status != "active" or frame.envelope.authority.actor != mapping.self_entity_ref:
        raise ValueError("SourceNote initial producer must be its actual independent mapped Self")
    if frame.envelope.deadline_utc != responsibility.deadline_utc:
        raise ValueError("SourceNote Self creation must retain its independently frozen authorization deadline")
    c02_id, source_ref = authorization.request.c02_operation_id, authorization.request.source_ref
    activity_id, job_id = foreground_cycle_ids_v1(ns, c02_id)
    if read.head(db, runtime_job_key(*ns.as_tuple, activity_id, job_id)).revision:
        raise ValueError("SourceNote authorization cannot upgrade an existing natural or Artifact foreground cycle")
    reply_ref = foreground_reply_budget_ids_v1(ns, c02_id)[0]
    allocation = prepare_foreground_reply_allocation_v1(db, namespace=ns, c02_operation_id=c02_id, source_ref=source_ref,
        parent_budget_lease_ref=authorization.parent_budget_lease_ref, issuer=installed_readers.issuer,
        installed_bundle=installed_readers.installed_bundle, now_utc=frame.now_utc, deadline_utc=responsibility.deadline_utc)
    receipt = _adopted_c02_v1(db, ns, c02_id)
    attempt = _original_encoding_attempt_v1(db, namespace=ns, c02_operation_id=c02_id, source_ref=source_ref,
        parent_budget_ref=authorization.parent_budget_lease_ref, issuer=installed_readers.issuer)
    plan = ForegroundCallPlanV1(authorization.parent_budget_lease_ref, reply_ref, (attempt,))
    job, staged = prepare_foreground_cycle_in_transaction_v1(db, frame=frame, c02_receipt=receipt,
        source_ref=source_ref, call_plan=plan, issuer=installed_readers.issuer, reply_allocation=allocation)
    if staged is None:
        raise ValueError("SourceNote initial cycle target already exists")
    raw = dict(job.continuation)
    raw.update(schema=CONTINUATION_SCHEMA, responsibility_ref=foreground_responsibility_ref_v1(ns, c02_id),
        responsibility_digest=responsibility.digest, authorization_original_ref=authorization.original_ref,
        authorization_original_digest=authorization.digest)
    from .foreground_cycle_v1 import foreground_cycle_from_wire_v1
    continuation = foreground_cycle_from_wire_v1(raw)
    job = replace(job, continuation=plain_v1(continuation))
    stage = stage_result_v1(frame, "d11", OPERATION, request, writes=(job_graph_write(job),),
        provenance={"before_job": None, "after_job": job, "reply_allocation": allocation,
            "responsibility": responsibility, "source_note_authorization": authorization},
        receiver_events=(("d11", "foreground_cycle_ready"),), proposal_schema=D11_PROPOSAL_SCHEMA,
        proposal_hash=D11RuntimeProvider().descriptor.request_schema_hash)
    return ForegroundCycleStageV1(frame, stage, request, None, job, allocation)


def record_source_note_responsibility_after_cas_v1(db, *, frame, stage, receipt, installed_readers):
    import json
    value = decode_typed_production_value_v1(json.loads(stage.original_payload_json)["provenance"]["responsibility"], ForegroundSourceNoteResponsibilityV1)
    if receipt.status != "committed" or receipt.operation_id != frame.envelope.identity.operation_id:
        raise ValueError("SourceNote responsibility requires its actual Self creation W01 receipt")
    return _record(db, issuer=installed_readers.issuer, namespace=value.namespace, kind=RESPONSIBILITY_KIND,
        ref=foreground_responsibility_ref_v1(value.namespace, value.c02_operation_id), operation_id=receipt.operation_id, value=value)


def require_current_source_note_responsibility_v1(db, *, namespace, job, installed_bundle, issuer,
        owner_guard, purpose, audiences, now_utc):
    from .foreground_cycle_v1 import foreground_cycle_from_wire_v1
    from ..authority_service.current_foreground_activity_v1 import _source_family_current_sql_v1
    continuation = foreground_cycle_from_wire_v1(job.continuation)
    if type(continuation) is not ForegroundSourceNoteContinuationV1:
        raise TypeError("SourceNote current responsibility requires its exact continuation variant")
    signed = _read(db, issuer=issuer, namespace=namespace, kind=RESPONSIBILITY_KIND, ref=continuation.responsibility_ref)
    if signed is None:
        raise MissingProductionOriginalV1("actual_SourceNote_initial_Self_responsibility_original")
    value = decode_typed_production_value_v1(signed[0], ForegroundSourceNoteResponsibilityV1)
    created = read_adopted_domain_operation_v1(db, namespace, signed[1])
    auth_saved = read_source_note_task_authorization_v1(db, namespace=namespace,
        original_ref=value.authorization_original_ref, issuer=issuer)
    if (created is None or auth_saved is None or signed[1] != job.operation_id
            or created["domain"] != "d11" or created["operation_kind"] != OPERATION
            or value.digest != continuation.responsibility_digest
            or (value.authorization_original_ref, value.authorization_original_digest) != (
                continuation.authorization_original_ref, continuation.authorization_original_digest)
            or created["payload"]["provenance"]["responsibility"] != signed[0]):
        raise ValueError("SourceNote responsibility lost its actual immutable Self creation occurrence")
    authorization, auth_actual = auth_saved
    if (authorization.digest != value.authorization_original_digest or authorization.source_refs != value.source_refs
            or authorization.owner_guard != owner_guard
            or installed_bundle.installation_policy.installation_id != value.installation_id
            or installed_bundle.installation_policy.manifest_digest != value.manifest_digest
            or now_utc >= value.deadline_utc or value.deadline_utc != authorization.original_deadline_utc
            or job.budget_ref != authorization.parent_budget_lease_ref):
        raise ValueError("SourceNote original responsibility lost current Owner/install/root/deadline qualification")
    import json
    qualified_heads = {}
    for name, version, digest in authorization.heads:
        row = db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=? AND bot=? AND persona=?",
            (version.key.token, *namespace.as_tuple)).fetchone()
        if row is None or row[2] != 1 or row[0] != version.revision or canonical_digest(json.loads(row[1])) != digest:
            raise MissingProductionOriginalV1("actual_current_SourceNote_authorization_head:" + name)
        qualified_heads[name] = json.loads(row[1])
    role, account = qualified_heads["role"], qualified_heads["account"]
    if (role["status"] != "active" or role["effective_from"] > now_utc
            or role["effective_until"] is not None and now_utc >= role["effective_until"]
            or account["valid_from"] > now_utc or account["valid_until"] is not None and now_utc >= account["valid_until"]):
        raise MissingProductionOriginalV1("SourceNote_current_authorized_role_account_time")
    from dataclasses import asdict
    if (installed_bundle.foreground is None
            or canonical_digest(asdict(installed_bundle.foreground)) != value.foreground_policy_digest
            or canonical_digest(asdict(installed_bundle.foreground.deadline_policy)) != value.deadline_policy_digest):
        raise ValueError("SourceNote immutable responsibility changed its actual installed foreground/deadline policy")
    mapping = db.execute("SELECT value,valid FROM graph_atoms WHERE token=?", (self_mapping_key(namespace).token,)).fetchone()
    if mapping is None or mapping[1] != 1 or canonical_digest(json.loads(mapping[0])) != value.self_mapping_digest:
        raise ValueError("SourceNote current independent Self mapping differs from its original creation")
    self_value = decode_typed_production_value_v1(json.loads(mapping[0]), SelfIdentityMapping)
    if self_value.status != "active" or created["payload"]["authority"]["actor"] != self_value.self_entity_ref:
        raise ValueError("SourceNote original creator cannot substitute Owner for its independent Self")
    grant = issuer.current_budget_grant(db, job.budget_ref)
    from .budget import require_budget_family_admissible
    require_budget_family_admissible(db, job.budget_ref)
    if grant != installed_bundle.installation_policy.root_grant or (grant.grant_id, grant.version, canonical_digest(grant)) != (
            value.parent_grant_id, value.parent_grant_version, value.parent_grant_digest):
        raise ValueError("SourceNote parent grant changed after its immutable task authorization")
    _source_family_current_sql_v1(db, namespace=namespace, roots=authorization.source_refs, purpose=purpose, audiences=audiences)
    return value


def read_plan_source_note_foreground_v1(db, *, namespace, request, installed_readers):
    saved = read_source_note_task_authorization_v1(db, namespace=namespace,
        original_ref=request.authorization_original_ref, issuer=installed_readers.issuer)
    if saved is None:
        raise MissingProductionOriginalV1("actual_Owner_SourceNote_authorization_read_plan")
    authorization, actual = saved
    from .foreground_cycle_v1 import foreground_cycle_read_plan_v1
    from ..graph_types import owner_grant_key
    plan = foreground_cycle_read_plan_v1(namespace=namespace,
        c02_receipt=_adopted_c02_v1(db, namespace, authorization.request.c02_operation_id),
        source_ref=authorization.request.source_ref)
    keys = (*plan.exact_keys, *(version.key for name, version, digest in authorization.heads),
        self_mapping_key(namespace), owner_grant_key(*namespace.as_tuple))
    originals = (authorization.original_ref, authorization.authorization_operation_id,
        authorization.cause_original_ref, authorization.request.c02_operation_id,
        *(version.key.token for name, version, digest in authorization.heads if name not in {"source", "body_source"}))
    return production_read_plan_v1((), tuple(dict.fromkeys(keys)), authorization.source_refs, originals)


def validate_source_note_responsibility_archive_v1(db, *, namespace, job):
    """Exact passive creation lineage; it never supplies current Source permission."""
    import json
    from .foreground_cycle_v1 import foreground_cycle_from_wire_v1, decode_foreground_job_v1
    from .source_note_task_authorization_v1 import OPERATION as AUTHORIZE_OPERATION
    from .jobs import _utc
    current = decode_foreground_job_v1(plain_v1(job), namespace=namespace)
    continuation = foreground_cycle_from_wire_v1(current.continuation)
    if type(continuation) is not ForegroundSourceNoteContinuationV1:
        raise ValueError("SourceNote archive requires its exact retained continuation")
    original = read_adopted_domain_operation_v1(db, namespace, current.operation_id)
    if original is None or (original["domain"], original["operation_kind"]) != ("d11", OPERATION):
        raise MissingProductionOriginalV1("actual_SourceNote_initial_creation_history")
    proof = original["payload"]["provenance"]
    if set(proof) != {"before_job", "after_job", "reply_allocation", "responsibility", "source_note_authorization"} or proof["before_job"] is not None:
        raise ValueError("SourceNote initial archive has another closed producer")
    value = decode_typed_production_value_v1(proof["responsibility"], ForegroundSourceNoteResponsibilityV1)
    authorization = decode_typed_production_value_v1(proof["source_note_authorization"], SourceNoteTaskAuthorizationV1)
    born_job = decode_foreground_job_v1(proof["after_job"], namespace=namespace)
    born = foreground_cycle_from_wire_v1(born_job.continuation)
    if (type(born) is not ForegroundSourceNoteContinuationV1 or value.namespace != namespace
            or (value.authorization_original_ref, value.authorization_original_digest, value.source_refs) != (
                authorization.original_ref, authorization.digest, authorization.source_refs)
            or (born.responsibility_ref, born.responsibility_digest, born.authorization_original_ref, born.authorization_original_digest) != (
                continuation.responsibility_ref, value.digest, authorization.original_ref, authorization.digest)
            or (current.job_id, current.operation_id, current.activity_id, current.budget_ref, current.deadline_utc) != (
                born_job.job_id, original["receipt"].operation_id, born_job.activity_id, born_job.budget_ref, born_job.deadline_utc)
            or _utc(current.deadline_utc, "deadline_utc").timestamp() != value.deadline_utc
            or authorization.original_deadline_utc != value.deadline_utc):
        raise ValueError("SourceNote archive changed its immutable authorized task/creation/root/deadline")
    owner = read_adopted_domain_operation_v1(db, namespace, authorization.authorization_operation_id)
    if (owner is None or (owner["domain"], owner["operation_kind"]) != ("d11", AUTHORIZE_OPERATION)
            or owner["payload"]["authority"]["actor"] != authorization.owner_actor_ref
            or owner["payload"]["provenance"] != {"source_note_task_authorization": plain_v1(authorization)}
            or owner["receipt"].commit_seq >= original["receipt"].commit_seq):
        raise ValueError("SourceNote creation lacks its earlier actual independent Owner task authorization")
    for name, version, digest in authorization.heads:
        archived = db.execute("SELECT value,valid FROM graph_history WHERE token=? AND revision=?",
            (version.key.token, version.revision)).fetchone()
        if archived is None or archived[1] != 1 or canonical_digest(json.loads(archived[0])) != digest:
            raise MissingProductionOriginalV1("actual_SourceNote_authorized_historical_head:" + name)
    mapping_reads = tuple(version for version in original["read_versions"] if version.key == self_mapping_key(namespace))
    if len(mapping_reads) != 1:
        raise ValueError("SourceNote creation lacks its actual independent Self mapping read")
    mapping = db.execute("SELECT value,valid FROM graph_history WHERE token=? AND revision=?",
        (mapping_reads[0].key.token, mapping_reads[0].revision)).fetchone()
    if mapping is None or mapping[1] != 1 or canonical_digest(json.loads(mapping[0])) != value.self_mapping_digest:
        raise ValueError("SourceNote creation changed its actual historical Self mapping")
    self_value = decode_typed_production_value_v1(json.loads(mapping[0]), SelfIdentityMapping)
    if self_value.status != "active" or original["payload"]["authority"]["actor"] != self_value.self_entity_ref:
        raise ValueError("SourceNote creation did not use its actual independent Self")
    version = next((version for version in original["receipt"].write_versions if version.key == job_graph_write(born_job).key), None)
    if version is None:
        raise ValueError("SourceNote original creation receipt lacks its real Graph job write")
    archived = db.execute("SELECT event_id,value,valid FROM graph_history WHERE token=? AND revision=?",
        (version.key.token, version.revision)).fetchone()
    from ..runtime_contracts import canonical_serialize
    if archived != (current.operation_id, canonical_serialize(job_graph_write(born_job).value), 1):
        raise ValueError("SourceNote initial responsibility lost its actual matching Graph history occurrence")
    return value


def read_source_note_responsibility_original_v1(db, *, namespace, job, issuer):
    value = validate_source_note_responsibility_archive_v1(db, namespace=namespace, job=job)
    ref = foreground_responsibility_ref_v1(namespace, value.c02_operation_id)
    actual = _read(db, issuer=issuer, namespace=namespace, kind=RESPONSIBILITY_KIND, ref=ref)
    auth = read_source_note_task_authorization_v1(db, namespace=namespace,
        original_ref=value.authorization_original_ref, issuer=issuer)
    if actual is None or actual[1] != job.operation_id or actual[0] != plain_v1(value) or auth is None or auth[0].digest != value.authorization_original_digest:
        raise ValueError("SourceNote retained lineage lacks its authenticated D11 creation/Owner originals")
    grant, signature = issuer.signed_budget_grant_at_version(db, value.parent_budget_lease_ref, value.parent_grant_version)
    if canonical_digest(grant) != value.parent_grant_digest:
        raise ValueError("SourceNote retained lineage changed its actual signed parent grant")
    from .c09_life_originals_v1 import read_foreground_post_c02_cause_original_v1
    cause = read_foreground_post_c02_cause_original_v1(db, namespace=namespace, issuer=issuer, original_ref=value.cause_original_ref)
    if canonical_digest(plain_v1(cause)) != value.cause_original_digest:
        raise ValueError("SourceNote retained lineage changed its original causal commitment")
    return value


SOURCE_NOTE_FOREGROUND_DOMAINS_V1 = {
    OPERATION: "d11", "prepare_selected_source_note_action_v2": "d08", "prepare_source_note_body": "d02",
    "input:register_life_plan_v2": "d10", "adopt_relationship_revision_v2": "d05",
}
SOURCE_NOTE_FOREGROUND_OPERATIONS_V1 = frozenset({*SOURCE_NOTE_FOREGROUND_DOMAINS_V1,
    "acquire_foreground_cycle", "checkpoint_source_note_foreground_cycle_v1", "wake_foreground_cycle",
    "prepare_ingress_recall_need_v1", "select_ingress_recall_seed_v1", "prepare_ingress_recall_model_v1",
    "acquire_ingress_recall_model_v1", "prepare_ingress_recall_result_read_v1", "finish_ingress_recall_model_v1",
    "adopt_ingress_recall_model_v1", "prepare_ingress_c04_v1", "adopt_ingress_c04_v1",
    "prepare_personal_candidates_v1", "select_personal_step_v2",
    "focus_life_project", "prepare_life", "input:register_life_outcome_v2", "advance_life", "settle_personal_goal"})


def qualify_source_note_foreground_v1(db, *, request, job, issuer, installed_bundle, owner_guard, now_utc, atom):
    """Independent Core readonly SourceNote slice; caller strings cannot grant task rights."""
    from .domain_production_registry_v1 import installed_operation_v1
    from ..authority_service.current_foreground_activity_v1 import foreground_typed_command_digest_v1
    from .source_note_task_authorization_v1 import KIND as AUTH_KIND, NOTE_WORK_KIND
    from .d11_life_preparation_v1 import TABLE
    from .foreground_cycle_v1 import foreground_cycle_from_wire_v1
    if request.operation_kind not in SOURCE_NOTE_FOREGROUND_OPERATIONS_V1 or request.draft_root_registration_ref is not None:
        raise ValueError("SourceNote responsibility permits only its closed internal task pipeline")
    if job is None:
        if request.operation_kind != OPERATION:
            raise MissingProductionOriginalV1("actual_initial_SourceNote_absent_cycle_target")
        refs = db.execute("SELECT original_ref FROM " + TABLE + " WHERE bot=? AND persona=? AND kind=? "
            "AND json_extract(payload_json,'$.request.c02_operation_id')=? "
            "AND json_extract(payload_json,'$.request.source_ref')=? ORDER BY original_ref LIMIT 129",
            (*request.namespace.as_tuple, AUTH_KIND, request.c02_operation_id, request.cue_source_ref)).fetchall()
        if len(refs) > 128:
            raise MissingProductionOriginalV1("bounded_SourceNote_actual_authorization_inventory")
        exact = [ref for (ref,) in refs if foreground_typed_command_digest_v1(installed_operation_v1(OPERATION),
            CreateSourceNoteForegroundCycleRequestV1(ref)) == request.request_digest]
        if len(exact) != 1:
            raise MissingProductionOriginalV1("exact_signed_SourceNote_authorization_from_current_typed_request_digest")
        original_ref = exact[0]
    else:
        continuation = foreground_cycle_from_wire_v1(job.continuation)
        if type(continuation) is not ForegroundSourceNoteContinuationV1:
            raise ValueError("SourceNote task cannot borrow another foreground responsibility variant")
        original_ref = continuation.authorization_original_ref
    saved = read_source_note_task_authorization_v1(db, namespace=request.namespace, original_ref=original_ref, issuer=issuer)
    if saved is None:
        raise MissingProductionOriginalV1("actual_signed_current_SourceNote_Owner_task_authorization")
    authorization, actual = saved
    if (authorization.namespace != request.namespace or authorization.owner_guard != owner_guard
            or authorization.installation_id != installed_bundle.installation_policy.installation_id
            or authorization.manifest_digest != installed_bundle.installation_policy.manifest_digest
            or (authorization.request.c02_operation_id, authorization.request.source_ref, authorization.parent_budget_lease_ref) != (
                request.c02_operation_id, request.cue_source_ref, request.parent_budget_lease_ref)
            or request.requested_deadline_utc > authorization.original_deadline_utc or now_utc >= authorization.original_deadline_utc
            or request.plan_ref is not None and request.plan_ref != authorization.request.plan_ref):
        raise ValueError("SourceNote independent admission changed its actual signed Owner/task/root/deadline")
    qualified = {}
    for name, version, digest in authorization.heads:
        value = atom(version.key)
        row = db.execute("SELECT revision FROM graph_atoms WHERE token=?", (version.key.token,)).fetchone()
        if row != (version.revision,) or canonical_digest(value) != digest:
            raise MissingProductionOriginalV1("SourceNote_current_independent_authorized_head:" + name)
        qualified[name] = value
    role, account = qualified["role"], qualified["account"]
    if (role["status"] != "active" or now_utc < role["effective_from"]
            or role["effective_until"] is not None and now_utc >= role["effective_until"]
            or now_utc < account["valid_from"]
            or account["valid_until"] is not None and now_utc >= account["valid_until"]):
        raise MissingProductionOriginalV1("SourceNote_independent_initial_role_account_time")
    grant = issuer.current_budget_grant(db, request.parent_budget_lease_ref)
    if NOTE_WORK_KIND not in grant.allowed_work_kinds or (grant.grant_id, grant.version, canonical_digest(grant)) != (
            authorization.parent_grant_id, authorization.parent_grant_version, authorization.parent_grant_digest):
        raise ValueError("SourceNote independent admission requires its actual originally authorized root work kind")
    if job is not None:
        value = require_current_source_note_responsibility_v1(db, namespace=request.namespace, job=job,
            installed_bundle=installed_bundle, issuer=issuer, owner_guard=owner_guard,
            purpose=request.purpose, audiences=request.audiences, now_utc=now_utc)
        if value.authorization_original_digest != authorization.digest:
            raise ValueError("SourceNote independent admission lost its actual immutable task digest")
    return authorization


CHECKPOINT_OPERATION_V1 = "checkpoint_source_note_foreground_cycle_v1"


@dataclass(frozen=True, slots=True)
class CheckpointSourceNoteForegroundCycleRequestV1(CheckpointForegroundCycleRequestV1):
    continuation: ForegroundSourceNoteContinuationV1

    def __post_init__(self):
        if type(self.continuation) is not ForegroundSourceNoteContinuationV1:
            raise TypeError("SourceNote checkpoint retains only its exact immutable responsibility continuation variant")


def stage_checkpoint_source_note_foreground_cycle_v1(db, *, frame, request, installed_readers):
    from .foreground_cycle_v1 import stage_current_foreground_cycle_in_transaction_v1
    if type(request) is not CheckpointSourceNoteForegroundCycleRequestV1:
        raise TypeError("exact SourceNote checkpoint request required")
    return stage_current_foreground_cycle_in_transaction_v1(db, frame=frame, request=request, installed_readers=installed_readers)
