"""Real W01 preparation, budget reservation and signed Life source closure."""

from .d11_life_contract_v1 import LIFE_BINDING_TYPES, LIFE_CLAIM_TYPES, LIFE_TERMINAL_TYPES
from .d11_life_contract_v1 import D11DraftExecutionBindingV1, draft_artifact_ref_v1, life_work_kind_v1
from .d11_artifact_draft_contract_v1 import (RegisteredDraftFilePlanV3, DraftRootCapabilityV1,
    DraftActivityScopeV1, draft_from_wire_v1, RECIPE_ID as DRAFT_RECIPE, POSTCONDITION_ID as DRAFT_POSTCONDITION)
from dataclasses import dataclass, replace
from datetime import datetime, timezone
import json

from ..domains.d01.production_operations_v1 import plain_v1, stage_result_v1
from ..domains.d08.execution import _decode_intent
from ..graph_types import AtomKey, GraphWrite, GraphVersion, Owner, owner_grant_key
from ..memory_types import SourceRecord, access_key
from ..runtime_contracts import canonical_digest, canonical_serialize, VersionedRef
from .d01_production_operations_v1 import CurrentDomainReadV1, MissingProductionOriginalV1
from .d11_life_contract_v1 import (RegisteredLifePlanV2, D11LifeExecutionBindingV1, D11LifeTerminalV1, life_from_wire_v1,
    life_to_wire_v1, life_artifact_ref_v1, WORK_KIND, ALGORITHM_ID, POSTCONDITION_ID, RECIPE_ID)
from .d10_offline_tick_execution_v1 import (OfflineTickGraphReadV1, _decode_json, read_current_offline_clock_reference_v1)
from .d11_life_source_note_v1 import install_life_artifact_stage_schema_v1
from .d11_offline_originals_v1 import _utc
from .budget import get_budget_lease, require_budget_family_admissible, reserve_budget
from .issuers import D11BudgetJobIssuer, D02ResourceIssuer, ResourceQuote
from .jobs import PersistentJob, create_job, acquire_job, get_job
from .d11_types import job_graph_write
from .clock import CharacterClockMapping

TABLE = "graph_d11_life_originals_v1"
SIGN_KIND = "d11.life-original.v1"
DDL = "CREATE TABLE graph_d11_life_originals_v1 (bot TEXT NOT NULL,persona TEXT NOT NULL,kind TEXT NOT NULL,original_ref TEXT NOT NULL,producing_operation_id TEXT NOT NULL,payload_json TEXT NOT NULL,payload_digest TEXT NOT NULL,signature TEXT NOT NULL,PRIMARY KEY(bot,persona,kind,original_ref))"


@dataclass(frozen=True, slots=True)
class PrepareCurrentLifeRequestV1:
    plan_original_ref: str
    prepare_operation_id: str


@dataclass(frozen=True, slots=True)
class D11LifePreparedV1:
    binding: D11LifeExecutionBindingV1
    prepare_operation_id: str
    plan: RegisteredLifePlanV2
    source_record_json: str
    clock_mapping_json: str
    clock_original_json: str
    quote_json: str
    signed_grant_json: str
    signed_grant_signature: str
    parent_budget_json: str
    reserve_receipt_json: str
    owner_guard_json: str
    owner_grant_json: str
    read_rows: tuple[OfflineTickGraphReadV1, ...]
    prepared_at_utc: str
    prepare_command_identity_json: str
    owner_prepare_request_digest: str
    owner_prepare_attempt_id: str
    admission_ref: str | None = None
    admission_digest: str | None = None
    requirements_json: str | None = None
    graph_revision: int | None = None
    graph_epoch: int | None = None
    job_projection_json: str | None = None
    job_projection_revision: int | None = None
    schema: str = "d11.life-prepared.v1"

    def __post_init__(self):
        if (self.schema != "d11.life-prepared.v1" or type(self.binding) is not D11LifeExecutionBindingV1
                or type(self.plan) is not RegisteredLifePlanV2 or type(self.read_rows) is not tuple
                or not self.read_rows or len(self.read_rows) > 1024
                or any(type(row) is not OfflineTickGraphReadV1 for row in self.read_rows)):
            raise ValueError("Life immutable preparation requires its closed complete inputs")
        b, p = self.binding, self.plan
        if (b.plan_digest != canonical_digest(plain_v1(p)) or b.input_digest != life_input_digest_v1(p, self.source_record_json, self.read_rows)
                or (p.activity_id, p.effect_id, p.attempt_id, p.operation_id, p.parent_budget_lease_ref, p.cpu_ceiling_ms,
                    p.algorithm_build_digest, p.postcondition_build_digest) !=
                (b.activity_id, b.effect_id, b.attempt_id, b.operation_id, b.parent_budget_lease_ref, b.cpu_ceiling_ms,
                    b.algorithm_build_digest, b.postcondition_build_digest)
                or canonical_digest(json.loads(self.source_record_json)) != p.input_source.digest
                or self.prepare_operation_id != b.prepare_operation_id):
            raise ValueError("Life prepared binding/source/plan commitments differ")
        _utc(self.prepared_at_utc)
        SourceRecord.from_dict(json.loads(self.source_record_json))
        if canonical_serialize(json.loads(self.source_record_json)) != self.source_record_json:
            raise ValueError("Life source bytes must be canonical")
        from ..runtime_contracts import OperationIdentity
        from .d10_offline_tick_execution_v1 import _decode_json
        command = _decode_json(self.prepare_command_identity_json, OperationIdentity)
        if (command.operation_id,command.phase,command.attempt_id,command.activity_id,command.effect_id) != (b.prepare_operation_id,"prepare_life",b.prepare_operation_id,b.activity_id,b.effect_id):
            raise ValueError("Life prepared command identity is not its real prepare command")
        from .d11_offline_originals_v1 import _digest,_text
        _digest(self.owner_prepare_request_digest);_text(self.owner_prepare_attempt_id)
        if (self.admission_ref is None)!=(self.admission_digest is None): raise ValueError("Life admission locator and commitment must be paired")
        if self.admission_digest is not None: _digest(self.admission_digest)
        final = (self.requirements_json, self.graph_revision, self.graph_epoch, self.job_projection_json, self.job_projection_revision)
        if any(x is not None for x in final) and any(x is None for x in final):
            raise ValueError("Life post-CAS original requires one complete Graph stamp")

    @property
    def digest(self):
        return canonical_digest(plain_v1(self))


@dataclass(frozen=True, slots=True)
class DraftReadCommitmentV1:
    ref: str
    revision: int
    value_digest: str
    valid: bool

    def __post_init__(self):
        from .d11_offline_originals_v1 import _digest
        if (AtomKey.from_token(self.ref).type_name != "memory.source"
                or type(self.revision) is not int or self.revision < 1 or self.valid is not True):
            raise ValueError("draft content commitment requires an actual valid Source revision")
        _digest(self.value_digest)


def life_read_digest_v1(row):
    if type(row) is DraftReadCommitmentV1:
        return row.value_digest
    if type(row) is OfflineTickGraphReadV1:
        return canonical_digest(json.loads(row.value_json))
    raise TypeError("closed actual Life read commitment required")


def life_read_matches_v1(row, actual):
    if type(row) is DraftReadCommitmentV1:
        return (actual is not None and (actual[0], canonical_digest(json.loads(actual[1])), bool(actual[2])) ==
            (row.revision, row.value_digest, row.valid))
    return actual == (row.revision, row.value_json, int(row.valid)) or row.revision == 0 and actual is None


@dataclass(frozen=True, slots=True)
class D11DraftPreparedV1(D11LifePreparedV1):
    schema: str = "d11.draft-prepared.v1"

    def __post_init__(self):
        from .d11_artifact_draft_contract_v1 import MAX_METADATA_BYTES
        if (self.schema != "d11.draft-prepared.v1" or type(self.binding) is not D11DraftExecutionBindingV1
                or type(self.plan) is not RegisteredDraftFilePlanV3 or self.source_record_json is not None
                or type(self.read_rows) is not tuple or not 1 <= len(self.read_rows) <= 1024
                or any(type(row) not in {OfflineTickGraphReadV1, DraftReadCommitmentV1} for row in self.read_rows)
                or any(type(row) is OfflineTickGraphReadV1 and AtomKey.from_token(row.ref).type_name == "memory.source"
                    for row in self.read_rows)):
            raise ValueError("draft prepared metadata addresses Source bodies without embedding them")
        b, p = self.binding, self.plan
        if (b.plan_digest != p.digest or b.input_digest != life_input_digest_v1(p, None, self.read_rows)
                or (p.activity_id, p.effect_id, p.attempt_id, p.operation_id, p.parent_budget_lease_ref,
                    p.cpu_ceiling_ms, p.algorithm_build_digest, p.postcondition_build_digest,
                    p.execution_call_id, p.activity_scope_ref, p.activity_scope_digest,
                    p.target.digest, p.target.root_registration_ref, p.target.root_registration_digest) !=
                   (b.activity_id, b.effect_id, b.attempt_id, b.operation_id, b.parent_budget_lease_ref,
                    b.cpu_ceiling_ms, b.algorithm_build_digest, b.postcondition_build_digest,
                    b.execution_call_id, b.activity_scope_ref, b.activity_scope_digest,
                    b.target_scope_digest, b.root_registration_ref, b.root_registration_digest)
                or self.prepare_operation_id != b.prepare_operation_id):
            raise ValueError("draft immutable preparation crossed actual plan/content/scope commitments")
        from ..runtime_contracts import OperationIdentity
        command = _decode_json(self.prepare_command_identity_json, OperationIdentity)
        if ((command.operation_id, command.phase, command.attempt_id, command.activity_id, command.effect_id) !=
                (b.prepare_operation_id, "prepare_life", b.prepare_operation_id, b.activity_id, b.effect_id)):
            raise ValueError("draft preparation lost its exact original command identity")
        _utc(self.prepared_at_utc)
        from .d11_offline_originals_v1 import _digest, _text
        _digest(self.owner_prepare_request_digest); _text(self.owner_prepare_attempt_id)
        if (self.admission_ref is None) != (self.admission_digest is None):
            raise ValueError("draft admission locator/digest must be paired")
        final = (self.requirements_json, self.graph_revision, self.graph_epoch, self.job_projection_json, self.job_projection_revision)
        if any(v is not None for v in final) and any(v is None for v in final):
            raise ValueError("draft preparation requires one actual complete post-CAS Graph stamp")
        if len(canonical_serialize(plain_v1(self)).encode("utf-8")) > MAX_METADATA_BYTES:
            raise ValueError("draft prepared original metadata exceeds 65536 bytes")


@dataclass(frozen=True, slots=True)
class LifePreparationStageV1:
    frame: object
    stage: object
    prepared: D11LifePreparedV1
    job: PersistentJob
    writes: tuple[GraphWrite, ...]
    read_versions: tuple[GraphVersion, ...]
    admission_reader: object
    before_capture_stage: object | None = None
    habit_occurrence_transition: "HabitLifeOccurrenceTransitionV1 | None" = None


def life_ids_v1(plan):
    suffix = canonical_digest((plan.activity_id, plan.effect_id, plan.attempt_id, plan.operation_id))[:48]
    return {name: "d11-life-" + name + ":" + suffix for name in ("job", "execution", "quote", "reservation", "prepared")}


def life_ids_from_binding_v1(binding):
    # "result" is the signed adopted-original locator, not the bounded Jobs ID.
    return {"job": binding.job_id, "execution": binding.execution_id, "quote": binding.quote_id,
        "reservation": binding.reservation_operation_id, "prepared": binding.prepared_original_ref, "result": binding.artifact_ref}


def life_input_digest_v1(plan, source_json, rows):
    if type(plan) is RegisteredDraftFilePlanV3:
        if source_json is not None:
            raise ValueError("draft input commitment must not embed Source body bytes")
        return canonical_digest({"schema": "d11.draft-frozen-input.v1", "plan": plain_v1(plan),
            "source_record_digest": plan.input_source.digest, "rows": plain_v1(rows)})
    return canonical_digest({"schema": "d11.life-frozen-input.v1", "plan": plain_v1(plan),
        "source_record_digest": canonical_digest(json.loads(source_json)), "rows": plain_v1(rows)})


def install_d11_life_schema_v1(db):
    if db.in_transaction:
        raise ValueError("install Life schemas before runtime transactions")
    db.execute(DDL.replace("CREATE TABLE ", "CREATE TABLE IF NOT EXISTS ", 1))
    install_life_artifact_stage_schema_v1(db)


def _record(db, *, issuer, namespace, kind, ref, operation_id, value):
    if not db.in_transaction or type(issuer) is not D11BudgetJobIssuer:
        raise TypeError("Life originals require actual installed issuer in W01 SQL transaction")
    wire, digest = canonical_serialize(plain_v1(value)), canonical_digest(plain_v1(value))
    signature = issuer._signer.sign(SIGN_KIND, canonical_serialize((namespace, kind, ref, digest)))
    expected = (operation_id, wire, digest, signature)
    from .artifact_host_result_archive_source_v3 import read_bound_artifact_archive_record_v3
    archive,old=read_bound_artifact_archive_record_v3(db,issuer=issuer,namespace=namespace,kind=kind,ref=ref,
        operation_id=operation_id,value=value)
    from .current_life_numeric_paid_write_v3 import read_bound_numeric_paid_point_v3,read_bound_numeric_seal_point_v3
    handled=archive
    if not handled:handled,old=read_bound_numeric_seal_point_v3(db,table=TABLE,columns=("producing_operation_id","payload_json","payload_digest","signature"),
        key_columns=("bot","persona","kind","original_ref"),key=(*namespace.as_tuple,kind,ref))
    if not handled:handled,old=read_bound_numeric_paid_point_v3(db,table=TABLE,columns=("producing_operation_id","payload_json","payload_digest","signature"),
        key_columns=("bot","persona","kind","original_ref"),key=(*namespace.as_tuple,kind,ref))
    if not handled:
        old = db.execute("SELECT producing_operation_id,payload_json,payload_digest,signature FROM " + TABLE +
            " WHERE bot=? AND persona=? AND kind=? AND original_ref=?", (*namespace.as_tuple, kind, ref)).fetchone()
    if old is not None and old != expected:
        raise ValueError("Life immutable original replay differs")
    if old is None:
        db.execute("INSERT INTO " + TABLE + " VALUES(?,?,?,?,?,?,?,?)", (*namespace.as_tuple, kind, ref, *expected))
    from .domain_production_contracts_v1 import ProductionOriginalRefV1
    return ProductionOriginalRefV1("d11.life_" + kind, ref, digest)


def _read_signed_life_payload_v1(db, *, issuer, namespace, kind, ref):
    from .natural_producer_qualification_v1 import _producer_original_point_v3
    row = _producer_original_point_v3(db, table='graph_d11_life_originals_v1', columns=('producing_operation_id', 'payload_json', 'payload_digest', 'signature'), key_columns=('bot', 'persona', 'kind', 'original_ref'), key=(lambda _producer_params_v3: (_producer_params_v3[0],_producer_params_v3[1],_producer_params_v3[2],_producer_params_v3[3]))((*namespace.as_tuple, kind, ref)), legacy_reader=lambda: db.execute("SELECT producing_operation_id,payload_json,payload_digest,signature FROM " + TABLE +
        " WHERE bot=? AND persona=? AND kind=? AND original_ref=?", (*namespace.as_tuple, kind, ref)).fetchone())
    if row is None:
        return None
    from .domain_background_read_v3 import (
        background_json_loads_v3, background_json_matches_v3, background_json_digest_v3)
    raw = background_json_loads_v3(row[1])
    if (not background_json_matches_v3(row[1], raw)
            or background_json_digest_v3(row[1], raw) != row[2]):
        raise ValueError("Life signed original bytes changed")
    issuer._signer.verify(SIGN_KIND, canonical_serialize((namespace, kind, ref, row[2])), row[3])
    from ..authority_service.life_model_original_family_read_v3 import register_life_model_signed_body_v3
    register_life_model_signed_body_v3(db, kind, ref, raw, row[0])
    return raw, row[0]


def _read(db, *, issuer, namespace, kind, ref):
    saved = _read_signed_life_payload_v1(db, issuer=issuer, namespace=namespace, kind=kind, ref=ref)
    if saved is None:
        return None
    raw, operation_id = saved
    if kind in {"c4_no_dispatch", "c4_phase_no_dispatch"}:
        from .c09_life_originals_v1 import require_c4_no_dispatch_cost_original_commit_v1
        require_c4_no_dispatch_cost_original_commit_v1(db, namespace=namespace, operation_id=operation_id)
    elif kind in {"c4_paid", "c4_result", "c4_phase_paid", "c4_phase_result"}:
        from .c09_life_originals_v1 import require_c4_model_cost_original_commit_v1
        require_c4_model_cost_original_commit_v1(db, namespace=namespace, operation_id=operation_id)
    elif kind == "numeric_paid_v1":
        from .d06_life_numeric_paid_v1 import _verify_life_numeric_paid_original_v1
        _verify_life_numeric_paid_original_v1(db, namespace=namespace, issuer=issuer,
            job_id=ref, signed_original=saved)
    else:
        from .domain_production_read_plans_v1 import _committed
        _committed(db, namespace, operation_id)
    return saved


def _plan_current(db, read, plan):
    if type(plan) is RegisteredDraftFilePlanV3:
        return _draft_plan_current_v1(db, read, plan)
    from .d08_source_note_action_v1 import source_note_attempt_id_v1
    if plan.attempt_id != source_note_attempt_id_v1(read.frame.envelope.authority.namespace,
            plan.project.ref, plan.operation_id):
        raise ValueError('Life current plan lacks its exact installed typed source-note attempt')
    for frozen in (plan.project, plan.recipe, plan.action_intent, plan.input_source, plan.input_access):
        atom = read.head(db, frozen.ref, required=True)
        if atom.revision != frozen.revision or canonical_digest(atom.value) != frozen.digest:
            raise ValueError("Life registered current input revision/digest changed")
    project = read.head(db, plan.project.ref, required=True)
    recipe = read.head(db, plan.recipe.ref, required=True)
    action_atom = read.head(db, plan.action_intent.ref, required=True)
    action = _decode_intent(action_atom.value)
    if (project.key.type_name != "d10.life_project.v1" or project.value["reality"] != "real_execution"
            or project.value["next_step"] != "source_note" or recipe.key.type_name != "d10.activity_recipe.v1"
            or recipe.value != {"recipe_id": RECIPE_ID, "version": 1, "reality": "real_execution", "allowed_steps": ["source_note"], "preemptible": True}
            or action_atom.key.type_name != "d08.action_intent.v1"
            or (action.identity.activity_id, action.identity.effect_id, action.identity.attempt_id, action.identity.operation_id) !=
                (plan.activity_id, plan.effect_id, plan.attempt_id, plan.operation_id)
            or tuple(action.source_refs) != (plan.input_source.ref,)
            or action.success_predicate.kind != "artifact_verified"
            or action.success_predicate.observation_provider != POSTCONDITION_ID
            or dict(action.success_predicate.parameters) != {"artifact_ref": life_artifact_ref_v1(read.frame.envelope.authority.namespace, plan.effect_id),
                "input_digest": plan.input_source.digest, "build_digest": plan.postcondition_build_digest}):
        raise ValueError("Life fixed project/recipe/action/postcondition contract differs")
    source_atom = read.head(db, plan.input_source.ref, required=True)
    actual_access = access_key(*read.frame.envelope.authority.namespace.as_tuple, SourceRecord.from_dict(source_atom.value).source_id)
    if (plan.input_access.ref != actual_access.token or action.action_kind != "source_note"
            or action.success_predicate.valid_from > read.frame.now_utc
            or action.success_predicate.valid_until is not None and action.success_predicate.valid_until <= read.frame.now_utc):
        raise ValueError("Life actual Source/access/action postcondition window differs")
    for purpose in ("context", "consolidation"):
        for audience in plan.audiences:
            read.source_family(db, (plan.input_source.ref,), purpose=purpose, audience=audience)
    source = read.head(db, plan.input_source.ref, required=True)
    if plan.input_access.ref != access_key(*read.frame.envelope.authority.namespace.as_tuple, source.key.owner.subject).token:
        raise ValueError("Life source access belongs to another source")
    record = SourceRecord.from_dict(source.value)
    if len(record.text.encode("utf-8")) > 65536 or len(canonical_serialize(source.value).encode("utf-8")) > 131072:
        raise ValueError("Life source-note input is over the fixed bound")
    return action, source


def _draft_plan_current_v1(db, read, plan):
    from .d08_life_admission_v1 import _adopted
    from .current_method_learning_read_v3 import (
        method_post_commit_atom_digest_v3, method_current_or_post_parameter_digest_v3)
    for frozen in (plan.project, plan.recipe, plan.action_intent, plan.input_source, plan.input_access, plan.content.content):
        atom = read.head(db, frozen.ref, required=True)
        if (atom.revision, method_post_commit_atom_digest_v3(db, atom)) != (frozen.revision, frozen.digest):
            raise ValueError("draft exact current typed input revision/digest changed")
        _adopted(db, read, atom)
    project, recipe, action_atom, source = (read.head(db, getattr(plan, name).ref, required=True)
        for name in ("project", "recipe", "action_intent", "input_source"))
    action = _decode_intent(action_atom.value)
    artifact_ref = draft_artifact_ref_v1(read.frame.envelope.authority.namespace, plan.effect_id)
    if (project.key.type_name != "d10.life_project.v1" or project.value["reality"] != "real_execution"
            or project.value["next_step"] != DRAFT_RECIPE
            or recipe.key.type_name != "d10.activity_recipe.v1"
            or recipe.value != {"recipe_id": DRAFT_RECIPE, "version": 1, "reality": "real_execution",
                "allowed_steps": [DRAFT_RECIPE], "preemptible": True}
            or action.action_kind != DRAFT_RECIPE or action_atom.key.type_name != "d08.action_intent.v1"
            or (action.identity.activity_id, action.identity.effect_id, action.identity.attempt_id, action.identity.operation_id) !=
               (plan.activity_id, plan.effect_id, plan.attempt_id, plan.operation_id)
            or tuple(action.source_refs) != tuple(dict.fromkeys((plan.input_source.ref, *plan.content.source_refs)))
            or action.effect_scope != (artifact_ref,)
            or action.success_predicate.kind != "artifact_verified"
            or action.success_predicate.observation_provider != DRAFT_POSTCONDITION
            or dict(action.success_predicate.parameters) != {"artifact_ref": artifact_ref,
                "content_digest": plan.content.content_digest, "target_scope_digest": plan.target.digest,
                "build_digest": plan.postcondition_build_digest}
            or action.parameters_digest != method_current_or_post_parameter_digest_v3(
                db, read.frame.envelope.authority.namespace, plan.operation_id,
                (plain_v1(plan.target), plain_v1(plan.content)))):
        raise ValueError("draft actual project/recipe/Action/parameter/postcondition binding differs")
    if plan.input_access.ref != access_key(*read.frame.envelope.authority.namespace.as_tuple,
            SourceRecord.from_dict(source.value).source_id).token:
        raise ValueError("draft access belongs to another Source")
    for purpose in ("context", "consolidation"):
        for audience in plan.audiences:
            read.source_family(db, tuple(dict.fromkeys((plan.input_source.ref, *plan.content.source_refs))),
                purpose=purpose, audience=audience)
    if (action.success_predicate.valid_from > read.frame.now_utc
            or action.success_predicate.valid_until is not None and action.success_predicate.valid_until <= read.frame.now_utc):
        raise ValueError("draft exact postcondition window expired")
    return action, source


def require_draft_authority_inputs_v1(db, *, frame, plan, issuer):
    read = CurrentDomainReadV1(frame)
    scope_raw = _read(db, issuer=issuer, namespace=frame.envelope.authority.namespace,
        kind="activity_scope", ref=plan.activity_scope_ref)
    root_raw = _read(db, issuer=issuer, namespace=frame.envelope.authority.namespace,
        kind="draft_root_capability", ref=plan.target.root_registration_ref)
    if scope_raw is None or root_raw is None:
        raise MissingProductionOriginalV1("actual_ingress_activity_scope_and_installed_draft_root_capability")
    if (canonical_digest(scope_raw[0]), canonical_digest(root_raw[0])) != (
            plan.activity_scope_digest, plan.target.root_registration_digest):
        raise ValueError("draft actual signed scope/root commitment changed")
    scope = draft_from_wire_v1(scope_raw[0], DraftActivityScopeV1)
    root = draft_from_wire_v1(root_raw[0], DraftRootCapabilityV1)
    read.original(plan.activity_scope_ref, kind="d11.life_activity_scope", digest=plan.activity_scope_digest)
    read.original(root.registration_ref, kind="d11.life_draft_root_capability", digest=plan.target.root_registration_digest)
    if ((scope.activity_id, scope.actor_ref, scope.source, scope.parent_budget_lease_ref,
            scope.root_registration_ref, scope.root_registration_digest) !=
            (plan.activity_id, frame.envelope.authority.actor, plan.input_source, plan.parent_budget_lease_ref,
             plan.target.root_registration_ref, plan.target.root_registration_digest)
            or root.registration_ref != plan.target.root_registration_ref or root.resource_id != plan.target.root_resource_id
            or root.root_identity != plan.target.root_identity or plan.target.filename not in root.filenames
            or plan.target.max_bytes > root.max_bytes or root.source_ref != scope.source.ref
            or (scope.owner_grant_ref, scope.owner_grant_revision, scope.owner_grant_digest) !=
               (frame.owner_guard.grant_ref, frame.owner_guard.grant_revision, frame.owner_guard.grant_digest)
            or (root.owner_grant_ref, root.owner_grant_revision, root.owner_grant_digest) !=
               (frame.owner_guard.grant_ref, frame.owner_guard.grant_revision, frame.owner_guard.grant_digest)
            or frame.now_utc >= min(_utc(scope.valid_until_utc).timestamp(), _utc(root.valid_until_utc).timestamp())
            or _utc(plan.deadline_utc) > min(_utc(scope.valid_until_utc), _utc(root.valid_until_utc))):
        raise ValueError("draft activity is outside its actual Source/Owner/root/budget/deadline scope")
    from .ingress_observation import read_committed_ingress_identity
    ingress = read_committed_ingress_identity(db, frame.envelope.authority.namespace,
        SourceRecord.from_dict(read.head(db, scope.source.ref, required=True).value).source_id)
    if ingress is None:
        raise MissingProductionOriginalV1("actual_committed_draft_ingress_identity")
    read.original(scope.ingress_original_ref)
    read.original(scope.c02_original_ref)
    if plan.target.mode == "replace":
        require_draft_predecessor_original_v1(db, frame=frame, plan=plan, issuer=issuer)
    return scope, root


def draft_predecessor_original_refs_v1(db, *, namespace, target):
    """Select the one original marker; this does not authenticate its body."""
    if target.mode == "create":
        return ()
    from .artifact_borrowed_source_v3 import artifact_borrowed_recipe_index_v3
    artifact,index=artifact_borrowed_recipe_index_v3(db,namespace=namespace,family="life_index",
        kind="adopted_by_marker",ref=target.expected_prior_effect_marker)
    if artifact:
        if len(index)!=1:raise MissingProductionOriginalV1("unique_actual_adopted_draft_predecessor")
        ref,original=index[0]
        if original["terminal"]["binding"]["schema"]!="d11.draft-execution-binding.v1":
            raise ValueError("predecessor marker selects another Life recipe")
        return ref,original["terminal"]["binding"]["prepared_original_ref"]
    rows = db.execute("SELECT original_ref,payload_json FROM " + TABLE +
        " WHERE bot=? AND persona=? AND kind='adopted_life' "
        "AND json_extract(payload_json,'$.terminal.payload.readback.effect_marker')=? LIMIT 2",
        (*namespace.as_tuple, target.expected_prior_effect_marker)).fetchall()
    if len(rows) != 1:
        raise MissingProductionOriginalV1("unique_actual_adopted_draft_predecessor")
    terminal = life_from_wire_v1(json.loads(rows[0][1])["terminal"], D11LifeTerminalV1)
    if type(terminal.binding) is not D11DraftExecutionBindingV1:
        raise ValueError("predecessor marker selects another Life recipe")
    return (rows[0][0], terminal.binding.prepared_original_ref)


def require_draft_predecessor_original_v1(db, *, frame, plan, issuer):
    from .d11_life_terminal_v1 import read_adopted_life_original_v1
    from .d11_life_adoption_v1 import require_draft_terminal_readback_v1
    from .d11_life_contract_v1 import D11DraftTerminalV1, D11LifeTerminalV1
    namespace, target = frame.envelope.authority.namespace, plan.target
    ref, _ = draft_predecessor_original_refs_v1(db, namespace=namespace, target=target)
    adopted = read_adopted_life_original_v1(db, namespace=namespace, result_ref=ref, issuer=issuer)
    if adopted is None:
        raise MissingProductionOriginalV1("actual_signed_adopted_draft_predecessor")
    terminal = life_from_wire_v1(adopted["terminal"], D11LifeTerminalV1)
    if type(terminal) is not D11DraftTerminalV1 or terminal.binding.effect_id == plan.effect_id:
        raise ValueError("draft replacement predecessor is not another actual draft effect")
    previous = read_prepared_life_v1(db, binding=terminal.binding, issuer=issuer)
    if previous is None:
        raise MissingProductionOriginalV1("actual_signed_draft_predecessor_preparation")
    witness = require_draft_terminal_readback_v1(prepared=previous, terminal=terminal)
    if witness.root_registration_digest != previous.plan.target.root_registration_digest:
        raise ValueError("draft predecessor lost its original root provenance")
    if witness.root_registration_digest != target.root_registration_digest:
        from .artifact_continuation_originals_v1 import require_actual_renewed_predecessor_v1
        require_actual_renewed_predecessor_v1(db, frame=frame, plan=plan,
            previous=previous, terminal=terminal, witness=witness, issuer=issuer)
    if ((witness.filename, witness.version,
            witness.content_digest, witness.file_identity, witness.effect_marker) !=
            (target.filename, target.expected_prior_version,
             target.expected_prior_digest, target.expected_prior_identity, target.expected_prior_effect_marker)
            or previous.plan.target.root_resource_id != target.root_resource_id
            or previous.plan.target.root_identity != target.root_identity):
        raise ValueError("draft replacement froze an invented predecessor version/identity")
    read = CurrentDomainReadV1(frame)
    read.original(ref, kind="d11.life_adopted_life", digest=canonical_digest(adopted))
    read.original(terminal.binding.prepared_original_ref)
    return witness


def record_registered_draft_observation_admission_v1(db, *, frame, issuer, original_ref, admission):
    """Adopt a read admission only after its actual quoted/reserved W01 commit."""
    from .d11_artifact_draft_contract_v1 import DraftObservationAdmissionV1
    from .d08_life_admission_v1 import _adopted
    from .budget import require_budget_family_admissible
    if type(admission) is not DraftObservationAdmissionV1:
        raise TypeError("closed draft observation admission required")
    read = CurrentDomainReadV1(frame);read.check(db)
    parameters = json.loads(admission.request_parameters_json)
    if original_ref != parameters["admission_original_ref"]:
        raise ValueError("observation admission locator changed before signing")
    intent = read.head(db, parameters["observation_intent_ref"], required=True)
    action = _decode_intent(intent.value)
    _adopted(db, read, intent)
    if (action.action_kind != "artifact_draft_verify_v1"
            or action.identity.effect_id != parameters["original_effect_id"]
            or action.schema_id != "d11.artifact-draft-observation.action.v1"
            or action.purpose != frame.envelope.authority.purpose or action.source_refs != admission.source_refs
            or action.parameters_digest != canonical_digest(parameters)):
        raise ValueError("observation admission has no actual adopted exact readonly ActionIntent")
    read.source_family(db, admission.source_refs)
    quote = issuer.resource_issuer.original_signed_quote(db, admission.quote_id, admission.quote_version)
    ceiling = {"thread_cpu_ms": parameters["cpu_ceiling_ms"], "read_bytes": parameters["read_bytes_ceiling"]}
    if (canonical_digest(quote) != admission.quote_digest or quote.ceiling != ceiling
            or quote.work_kind != "d11.life.artifact_observation.v1"
            or quote.activity_id != action.identity.activity_id or quote.operation_id != frame.envelope.identity.operation_id
            or quote.parent_budget_lease_ref != parameters["parent_budget_lease_ref"]
            or quote.effect_id != parameters["original_effect_id"]):
        raise ValueError("observation admission differs from the actual signed read quote")
    require_budget_family_admissible(db, parameters["parent_budget_lease_ref"])
    reservation = db.execute("SELECT digest,ceiling_json,state,actual_json FROM runtime_budget_reservations WHERE lease_id=? AND operation_id=?",
        (parameters["parent_budget_lease_ref"], parameters["reservation_ref"])).fetchone()
    if reservation != (parameters["reservation_digest"], canonical_serialize(ceiling), "reserved", None):
        raise MissingProductionOriginalV1("actual_separate_bounded_observation_reservation")
    read.committed_operation(db, frame.envelope.identity.operation_id)
    return _record(db, issuer=issuer, namespace=frame.envelope.authority.namespace,
        kind="draft_observation_admission", ref=original_ref, operation_id=frame.envelope.identity.operation_id, value=admission)


def record_registered_life_plan_v2(db, *, frame, issuer, original_ref, producing_operation_id, plan, installed_build,
        body_quote_authority=None):
    if type(plan) not in {RegisteredLifePlanV2, RegisteredDraftFilePlanV3}:
        raise TypeError("actual RegisteredLifePlanV2 required")
    read = CurrentDomainReadV1(frame)
    read.check(db)
    _plan_current(db, read, plan)
    if type(plan) is RegisteredDraftFilePlanV3:
        require_draft_authority_inputs_v1(db, frame=frame, plan=plan, issuer=issuer)
        from .d08_life_admission_v1 import record_draft_action_root_v1
        record_draft_action_root_v1(db, frame=frame, plan=plan, issuer=issuer)
        from ..domains.d02.body_quote_original import D02BodyQuoteAuthority
        from .d02_life_body_preparation_v1 import read_current_draft_body_component_contract_v1
        if type(body_quote_authority) is not D02BodyQuoteAuthority or plan.body_effect_request_json is None:
            raise MissingProductionOriginalV1("actual_draft_body_B_before_final_plan_C")
        actual_body=read_current_draft_body_component_contract_v1(db,frame=frame,action_intent_ref=plan.action_intent.ref,
            issuer=issuer,resource_issuer=issuer.resource_issuer,body_quote_authority=body_quote_authority)
        if canonical_serialize(plain_v1(actual_body))!=plan.body_effect_request_json:
            raise ValueError("draft final plan body contract differs from actual adopted B")
        quote=issuer.resource_issuer.original_signed_quote(db,actual_body.resource_quote_ref,actual_body.resource_quote_version)
        if plan.cpu_ceiling_ms>quote.ceiling.get("cpu_ms",0) or _utc(plan.deadline_utc).timestamp()>quote.valid_until_utc:
            raise ValueError("draft final plan CPU/deadline exceeds its actual Body B quote")
    if any(getattr(plan, name) != installed_build[name] for name in ("algorithm_build_digest", "postcondition_build_digest")):
        raise ValueError("Life plan build differs from actual installed file closure")
    read.committed_operation(db, producing_operation_id)
    return _record(db, issuer=issuer, namespace=frame.envelope.authority.namespace, kind="plan", ref=original_ref,
        operation_id=producing_operation_id, value=plan)


def read_registered_life_plan_v2(db, *, namespace, issuer, original_ref):
    original = _read(db, issuer=issuer, namespace=namespace, kind="plan", ref=original_ref)
    return None if original is None else life_from_wire_v1(original[0], RegisteredLifePlanV2)


def life_prepared_from_wire_v1(raw):
    from dataclasses import fields
    if type(raw) is not dict or set(raw) != {f.name for f in fields(D11LifePreparedV1)}:
        raise ValueError("Life prepared fields differ")
    value = dict(raw)
    value["binding"] = life_from_wire_v1(value["binding"], D11LifeExecutionBindingV1)
    value["plan"] = life_from_wire_v1(value["plan"], RegisteredLifePlanV2)
    cls = D11DraftPreparedV1 if raw["schema"] == "d11.draft-prepared.v1" else D11LifePreparedV1
    value["read_rows"] = tuple((DraftReadCommitmentV1(**row) if cls is D11DraftPreparedV1 and "value_digest" in row
        else OfflineTickGraphReadV1(**row)) for row in value["read_rows"])
    result = cls(**value)
    if plain_v1(result) != raw:
        raise ValueError("Life prepared is noncanonical")
    return result


def read_prepared_life_v1(db, *, binding, issuer):
    original = _read(db, issuer=issuer, namespace=binding.namespace, kind="prepared", ref=binding.prepared_original_ref)
    if original is None:
        return None
    value = life_prepared_from_wire_v1(original[0])
    if value.binding != binding or value.prepare_operation_id != original[1] or value.requirements_json is None:
        raise ValueError("Life signed preparation lacks its exact actual CAS")
    from ..authority_service.life_model_original_family_read_v3 import register_life_model_prepared_body_v3
    register_life_model_prepared_body_v3(db, value)
    return value


def read_prepared_life_by_ref_v1(db, *, namespace, prepared_original_ref, issuer):
    original = _read(db, issuer=issuer, namespace=namespace, kind="prepared", ref=prepared_original_ref)
    if original is None:
        return None
    value = life_prepared_from_wire_v1(original[0])
    if (value.binding.namespace != namespace or value.binding.prepared_original_ref != prepared_original_ref
            or value.prepare_operation_id != original[1] or value.requirements_json is None):
        raise ValueError("Life signed preparation current selector differs")
    return value


def prepare_current_life_in_transaction_v1(db, *, frame, request, issuer, resource_issuer, installation_id,
        authority_id, authority_namespace, manifest_digest, job_holder, installed_build, body_quote_authority, admission_reader,
        before_capture_policy=None):
    from .domain_production_contracts_v1 import CurrentOperationFrameV1
    if (type(frame) is not CurrentOperationFrameV1 or type(request) is not PrepareCurrentLifeRequestV1
            or type(issuer) is not D11BudgetJobIssuer or type(resource_issuer) is not D02ResourceIssuer):
        raise TypeError("Life preparation needs actual installed W01 inputs")
    read = CurrentDomainReadV1(frame)
    read.check(db)
    ns = frame.envelope.authority.namespace
    plan = read_registered_life_plan_v2(db, namespace=ns, issuer=issuer, original_ref=request.plan_original_ref)
    if plan is None:
        raise MissingProductionOriginalV1("actual_registered_life_plan_v2")
    action, source = _plan_current(db, read, plan)
    from .joint_node_execution_v1 import require_joint_bound_action_gate_v1
    require_joint_bound_action_gate_v1(db, namespace=ns, action_ref=plan.action_intent.ref, issuer=issuer, frame=frame)
    expected_prepare_operation='d11-life-prepare:'+plan.operation_id
    if type(plan)is RegisteredDraftFilePlanV3 and request.prepare_operation_id!=expected_prepare_operation:
        from .d11_life_product_adapter_v1 import registered_phase_draft_prepare_operation_id_v2
        expected_prepare_operation=registered_phase_draft_prepare_operation_id_v2(db,frame=frame,request=request,plan=plan,issuer=issuer)
    if ((frame.envelope.identity.operation_id, frame.envelope.identity.phase, frame.envelope.identity.attempt_id,
                frame.envelope.identity.activity_id, frame.envelope.identity.effect_id) !=
                (request.prepare_operation_id, "prepare_life", request.prepare_operation_id, plan.activity_id, plan.effect_id)
            or request.prepare_operation_id != expected_prepare_operation
            or frame.envelope.parent_budget_lease_ref != plan.parent_budget_lease_ref
            or tuple(frame.envelope.authority.audience) != plan.audiences
            or any(getattr(plan, n) != installed_build[n] for n in ("algorithm_build_digest", "postcondition_build_digest"))):
        raise ValueError("Life current identity/audience/budget/build differs")
    ids = life_ids_v1(plan)
    job_key = AtomKey(Owner("activity", *ns.as_tuple, plan.activity_id), "runtime.job", ids["job"])
    if read.head(db, job_key).revision != 0:
        raise MissingProductionOriginalV1("resume_actual_original_life_preparation")
    before_stage = None
    if before_capture_policy is not None:
        from .d04_life_before_original_v1 import capture_life_d04_before_in_tx_v1
        before_stage = capture_life_d04_before_in_tx_v1(
            db, frame=frame, request=request, issuer=issuer, policy=before_capture_policy)
    mapping, clock_json = read_current_offline_clock_reference_v1(db, namespace=ns, issuer=issuer)
    clock = json.loads(clock_json)
    read.original(mapping.mapping_id, kind="d11.role_clock", digest=clock["original_digest"])
    parent = get_budget_lease(db, plan.parent_budget_lease_ref)
    grant = issuer.current_budget_grant(db, parent.lease_id)
    require_budget_family_admissible(db, parent.lease_id)
    work_kind, algorithm_id = life_work_kind_v1(plan), plan.executor_id
    if (parent.state != "active" or (parent.bot_id, parent.persona_id) != ns.as_tuple
            or grant.valid_until_utc <= frame.now_utc or work_kind not in grant.allowed_work_kinds
            or plan.cpu_ceiling_ms > grant.max_ceiling.get("thread_cpu_ms", 0)):
        raise MissingProductionOriginalV1("actual_signed_life_thread_cpu_budget")
    deadline = min(frame.envelope.deadline_utc, _utc(plan.deadline_utc).timestamp(), grant.valid_until_utc, _utc(mapping.valid_until_utc).timestamp())
    if deadline - frame.now_utc < 1:
        raise MissingProductionOriginalV1("actual_life_execution_deadline")
    draft = type(plan) is RegisteredDraftFilePlanV3
    rows = tuple((DraftReadCommitmentV1(a.key.token, a.revision, canonical_digest(a.value), a.valid)
        if draft and a.key.type_name == "memory.source" else
        OfflineTickGraphReadV1(a.key.token, a.revision, canonical_serialize(a.value), a.valid))
        for a in frame.snapshot.atoms if a.key != job_key)
    source_json = None if draft else canonical_serialize(source.value)
    input_digest = life_input_digest_v1(plan, source_json, rows)
    quote = ResourceQuote(ids["quote"], 1, *ns.as_tuple, plan.activity_id, request.prepare_operation_id, plan.effect_id,
        parent.lease_id, work_kind, "life-input:" + input_digest[:48], deadline, algorithm_id, job_key.token,
        (), (), {"thread_cpu_ms": plan.cpu_ceiling_ms}, 1, deadline)
    resource_issuer.issue_quote(db, quote)
    quoted = replace(frame.envelope, deadline_utc=deadline, authority=replace(frame.envelope.authority, worker_fence=1),
        version_guard=replace(frame.envelope.version_guard, resource_lease_versions=(VersionedRef(quote.quote_id, 1),)))
    if issuer._admission_state(quoted, db, now_utc=frame.now_utc)[0] != quote:
        raise ValueError("Life quote is outside actual installed budget admission")
    reserve_digest = canonical_digest(("d11.life-reserve.v1", ns, plan.operation_id, input_digest, canonical_digest(quote), frame.owner_guard))
    receipt = reserve_budget(db, parent.lease_id, ids["reservation"], reserve_digest, quote.ceiling)
    if receipt.status != "reserved":
        raise MissingProductionOriginalV1("actual_life_reserved_thread_cpu")
    reserve = db.execute("SELECT receipt_json FROM runtime_budget_operations WHERE bot_id=? AND persona_id=? AND operation_id=? AND phase='reserve'",
        (*ns.as_tuple, ids["reservation"])).fetchone()
    signed = db.execute("SELECT grant_json,signature FROM runtime_budget_grants WHERE lease_id=? AND version=?", (parent.lease_id, grant.version)).fetchone()
    deadline_text = datetime.fromtimestamp(deadline, timezone.utc).isoformat().replace("+00:00", "Z")
    job = PersistentJob(ids["job"], plan.operation_id, plan.activity_id, plan.effect_id, *ns.as_tuple,
        quote.snapshot_ref, "queued", work_kind, {"schema": "d11.life-job.v1", "prepared_original_ref": ids["prepared"],
            "plan_original_ref": request.plan_original_ref, "input_digest": input_digest, "execution_id": ids["execution"]},
        None, deadline_text, parent.lease_id, algorithm_id, {"algorithm": algorithm_id,
            "algorithm_build": plan.algorithm_build_digest, "postcondition_build": plan.postcondition_build_digest,
            "resource_quote": quote.quote_id + ":1"}, None, None, 0, 0, {}, None)
    create_job(db, job, "create:" + plan.operation_id, canonical_digest(plain_v1(job)))
    job = acquire_job(db, job.job_id, job_holder, now_utc=datetime.fromtimestamp(frame.now_utc, timezone.utc).isoformat().replace("+00:00", "Z"),
        lease_seconds=min(60, int(deadline - frame.now_utc)))
    binding_cls = D11DraftExecutionBindingV1 if type(plan) is RegisteredDraftFilePlanV3 else D11LifeExecutionBindingV1
    draft_fields = {} if binding_cls is D11LifeExecutionBindingV1 else dict(execution_call_id=plan.execution_call_id,
        activity_scope_ref=plan.activity_scope_ref, activity_scope_digest=plan.activity_scope_digest,
        target_scope_digest=plan.target.digest, root_registration_ref=plan.target.root_registration_ref,
        root_registration_digest=plan.target.root_registration_digest)
    artifact_ref = (draft_artifact_ref_v1(ns, plan.effect_id) if draft_fields else life_artifact_ref_v1(ns, plan.effect_id))
    binding = binding_cls(ns, authority_namespace, authority_id, installation_id, manifest_digest,
        frame.activation_generation, plan.operation_id, request.prepare_operation_id, plan.activity_id, plan.effect_id, plan.attempt_id, ids["execution"],
        ids["job"], job.lease_holder, job.fence, job.lease_expires_utc, job.cancel_epoch, request.plan_original_ref,
        canonical_digest(plain_v1(plan)), ids["prepared"], input_digest, clock["original_digest"], frame.owner_guard.grant_ref,
        frame.owner_guard.grant_revision, frame.owner_guard.grant_digest, parent.lease_id, quote.quote_id, 1,
        canonical_digest(quote), ids["reservation"], reserve_digest, plan.cpu_ceiling_ms, deadline_text,
        plan.algorithm_build_digest, plan.postcondition_build_digest, artifact_ref, **draft_fields)
    owner = read.head(db, owner_grant_key(*ns.as_tuple), required=True)
    attempt = db.execute("SELECT request_digest,attempt_id FROM graph_owner_domain_attempts_v3 WHERE bot=? AND persona=? AND operation_id=?",
        (*ns.as_tuple, request.prepare_operation_id)).fetchone()
    if attempt is None or attempt[1] != admission_reader.scope.operation_id:
        raise ValueError("Life prepare requires actual current Owner command attempt")
    prepared_cls = D11DraftPreparedV1 if draft else D11LifePreparedV1
    prepared = prepared_cls(binding, request.prepare_operation_id, plan, source_json,
        canonical_serialize(plain_v1(mapping)), clock_json, canonical_serialize(plain_v1(quote)), *signed,
        canonical_serialize(plain_v1(parent)), reserve[0], canonical_serialize(plain_v1(frame.owner_guard)), canonical_serialize(owner.value),
        rows, datetime.fromtimestamp(frame.now_utc, timezone.utc).isoformat().replace("+00:00", "Z"),
        canonical_serialize(plain_v1(frame.envelope.identity)), attempt[0], attempt[1])
    from .d08_life_admission_v1 import evaluate_life_admission_v1
    evaluate_life_admission_v1(db, frame=frame, prepared=prepared, reader=admission_reader, new_work=True)
    stage = stage_result_v1(frame, "d10", "prepare_life", request, provenance={"prepared_binding": binding,
        "execution": "requires_actual_d11_once_claim_and_durable_artifact_postcondition"})
    preparation=LifePreparationStageV1(frame, stage, prepared, job, (job_graph_write(job),), frame.snapshot.versions, admission_reader, before_stage)
    from .d10_habit_v1 import attach_habit_life_occurrence_transition_v1
    return attach_habit_life_occurrence_transition_v1(db,preparation=preparation,issuer=issuer)


def record_life_preparation_after_cas_v1(db, *, issuer, preparation, graph_receipt):
    from ..runtime_contracts import CommitReceipt
    if (type(preparation) is not LifePreparationStageV1 or type(graph_receipt) is not CommitReceipt
            or graph_receipt.status != "committed" or graph_receipt.operation_id != preparation.prepared.prepare_operation_id):
        raise TypeError("Life needs actual same-transaction W01 preparation receipt")
    p, b = preparation.prepared, preparation.prepared.binding
    actual = db.execute("SELECT digest,commit_seq FROM graph_bundle_operations WHERE bot=? AND persona=? AND operation_id=?",
        (*b.namespace.as_tuple, p.prepare_operation_id)).fetchone()
    if actual != (graph_receipt.operation_digest, graph_receipt.commit_seq) or get_job(db, b.job_id) != preparation.job:
        raise ValueError("Life preparation actual bundle/job differs")
    metadata = db.execute("SELECT requirements_json,graph_revision FROM graph_recovery_metadata_v2 WHERE bot=? AND persona=?", b.namespace.as_tuple).fetchone()
    epoch = db.execute("SELECT revision FROM graph_epochs WHERE bot=? AND persona=?", b.namespace.as_tuple).fetchone()
    key = job_graph_write(preparation.job).key
    jobrow = db.execute("SELECT value,revision FROM graph_atoms WHERE token=? AND valid=1", (key.token,)).fetchone()
    if metadata is None or epoch is None or jobrow is None or json.loads(jobrow[0]) != job_graph_write(preparation.job).value:
        raise ValueError("Life preparation current post-CAS originals are absent")
    p = replace(p, requirements_json=metadata[0], graph_revision=metadata[1], graph_epoch=epoch[0], job_projection_json=jobrow[0], job_projection_revision=jobrow[1])
    from .d08_life_admission_v1 import record_life_action_admission_after_cas_v1
    admission = record_life_action_admission_after_cas_v1(db, preparation=preparation, prepared=p, receipt=graph_receipt)
    p = replace(p, admission_ref=admission.original_ref, admission_digest=admission.original_digest)
    original = _record(db, issuer=issuer, namespace=b.namespace, kind="prepared", ref=b.prepared_original_ref,
        operation_id=p.prepare_operation_id, value=p)
    from .d11_life_accounting_v1 import record_life_accounting_prepared_after_cas_v1
    record_life_accounting_prepared_after_cas_v1(db, issuer=issuer, prepared=p)
    if preparation.before_capture_stage is not None:
        from .d04_life_before_original_v1 import record_life_d04_before_after_cas_v1
        record_life_d04_before_after_cas_v1(db, stage=preparation.before_capture_stage,
            prepared=p, graph_receipt=graph_receipt, issuer=issuer)
    return original


def read_current_prepared_life_v1(db, *, binding, issuer, resource_issuer, now_utc, for_execution=True):
    if not db.in_transaction or type(binding) not in LIFE_BINDING_TYPES:
        raise ValueError("Life current preparation requires actual pinned SQL")
    p = read_prepared_life_v1(db, binding=binding, issuer=issuer)
    if p is None:
        raise ValueError("Life signed preparation is absent")
    if for_execution:
        from .joint_node_execution_v1 import require_joint_bound_action_gate_v1
        require_joint_bound_action_gate_v1(db, namespace=binding.namespace, action_ref=p.plan.action_intent.ref, issuer=issuer)
        metadata = db.execute("SELECT requirements_json,graph_revision FROM graph_recovery_metadata_v2 WHERE bot=? AND persona=?", binding.namespace.as_tuple).fetchone()
        epoch = db.execute("SELECT revision FROM graph_epochs WHERE bot=? AND persona=?", binding.namespace.as_tuple).fetchone()
        if metadata != (p.requirements_json, p.graph_revision) or epoch != (p.graph_epoch,):
            raise ValueError("Life first claim Graph stamp changed")
    for frozen in p.read_rows:
        row = db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=?", (frozen.ref,)).fetchone()
        if not life_read_matches_v1(frozen, row):
            from .d10_habit_v1 import require_habit_life_input_own_delta_v1
            if not require_habit_life_input_own_delta_v1(db,prepared=p,frozen=frozen,actual=row,issuer=issuer):
                raise ValueError("Life current source/access/Owner/action closure changed")
    from .d11_life_accounting_v1 import read_life_accounting_prepared_v1
    accounting = read_life_accounting_prepared_v1(db, binding=binding, issuer=issuer, resource_issuer=resource_issuer)
    if accounting is None or accounting.prepared_digest != p.digest:
        raise ValueError("Life original accounting preparation is absent")
    _verify_life_current_budget_v1(db,p,issuer,resource_issuer,now_utc,for_execution=for_execution)
    job = get_job(db, binding.job_id)
    _verify_life_running_job_v1(p,job)
    row = db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=?", (job_graph_write(job).key.token,)).fetchone()
    history = db.execute("SELECT event_id,value,valid FROM graph_history WHERE token=? AND revision=?",(job_graph_write(job).key.token,p.job_projection_revision)).fetchone()
    if row != (p.job_projection_revision,p.job_projection_json,1) or history != (p.prepare_operation_id,p.job_projection_json,1) or canonical_serialize(job_graph_write(job).value) != p.job_projection_json:
        raise ValueError("Life acquired job is not its actual prepare-CAS member")
    if for_execution and (job.phase, job.lease_holder, job.fence, job.cancel_epoch, job.lease_expires_utc) != (
            "running", binding.job_holder, binding.job_fence, 0, binding.job_lease_expires_utc):
        raise ValueError("Life actual acquired worker lease changed")
    if for_execution and now_utc >= min(_utc(binding.deadline_utc).timestamp(), _utc(binding.job_lease_expires_utc).timestamp()):
        raise ValueError("Life actual execution deadline expired")
    mapping, clock = read_current_offline_clock_reference_v1(db, namespace=binding.namespace, issuer=issuer)
    if (canonical_serialize(plain_v1(mapping)), clock) != (p.clock_mapping_json, p.clock_original_json):
        raise ValueError("Life actual signed role clock changed")
    return p


def _verify_life_current_budget_v1(db, prepared, issuer, resource_issuer, now_utc, *, for_execution):
    from .budget import BudgetLease
    b = prepared.binding
    quote = resource_issuer.original_signed_quote(db, b.quote_id, b.quote_version)
    if canonical_serialize(plain_v1(quote)) != prepared.quote_json or canonical_digest(quote) != b.quote_digest:
        raise ValueError("Life actual signed execution quote changed")
    grant = issuer.current_budget_grant(db, b.parent_budget_lease_ref)
    signed = db.execute("SELECT grant_json,signature FROM runtime_budget_grants WHERE lease_id=? AND version=?", (grant.lease_id, grant.version)).fetchone()
    if signed != (prepared.signed_grant_json, prepared.signed_grant_signature):
        raise ValueError("Life current signed grant differs from prepared original")
    current = get_budget_lease(db, b.parent_budget_lease_ref)
    original = _decode_json(prepared.parent_budget_json, BudgetLease)
    if (current.state != "active" or (current.lease_id,current.parent_id,current.bot_id,current.persona_id,current.currency,current.limits) !=
            (original.lease_id,original.parent_id,original.bot_id,original.persona_id,original.currency,original.limits)):
        raise ValueError("Life actual parent budget contract changed")
    require_budget_family_admissible(db, b.parent_budget_lease_ref)
    reservation = db.execute("SELECT digest,ceiling_json,state,actual_json FROM runtime_budget_reservations WHERE lease_id=? AND operation_id=?",
        (b.parent_budget_lease_ref, b.reservation_operation_id)).fetchone()
    reserve = db.execute("SELECT receipt_json FROM runtime_budget_operations WHERE bot_id=? AND persona_id=? AND operation_id=? AND phase='reserve'",
        (*b.namespace.as_tuple, b.reservation_operation_id)).fetchone()
    if reservation != (b.reservation_digest, canonical_serialize({"thread_cpu_ms":b.cpu_ceiling_ms}), "reserved", None) or reserve != (prepared.reserve_receipt_json,):
        raise ValueError("Life actual CPU reservation is no longer the prepared reserve")
    if for_execution and now_utc >= min(grant.valid_until_utc, _utc(b.deadline_utc).timestamp(), _utc(b.job_lease_expires_utc).timestamp()):
        raise ValueError("Life actual signed budget or worker deadline expired")


def _verify_life_running_job_v1(prepared, job):
    b = prepared.binding
    work_kind = life_work_kind_v1(b)
    algorithm_id = b.algorithm_id
    continuation = {"schema":"d11.life-job.v1","prepared_original_ref":b.prepared_original_ref,
        "plan_original_ref":b.plan_original_ref,"input_digest":b.input_digest,"execution_id":b.execution_id}
    if ((job.job_id,job.operation_id,job.activity_id,job.effect_id,job.bot_id,job.persona_id,job.phase,job.work_kind,
            job.lease_holder,job.fence,job.lease_expires_utc,job.cancel_epoch,job.deadline_utc,job.budget_ref,job.resource_ref,job.snapshot_ref) !=
            (b.job_id,b.operation_id,b.activity_id,b.effect_id,*b.namespace.as_tuple,"running",work_kind,b.job_holder,b.job_fence,
             b.job_lease_expires_utc,b.job_cancel_epoch,b.deadline_utc,b.parent_budget_lease_ref,algorithm_id,"life-input:"+b.input_digest[:48])
            or dict(job.continuation) != continuation or job.wake_condition is not None or job.result_ref is not None or dict(job.usage)
            or dict(job.operator_versions) != {"algorithm":algorithm_id,"algorithm_build":b.algorithm_build_digest,
                "postcondition_build":b.postcondition_build_digest,"resource_quote":b.quote_id+":"+str(b.quote_version)}):
        raise ValueError("Life genuine acquired job content differs from exact preparation")


def verify_life_preparation_in_transaction_v1(db, preparation, issuer, resource_issuer):
    if type(preparation) is not LifePreparationStageV1 or not db.in_transaction:
        raise TypeError("Life pending preparation requires actual W01 transaction")
    frame,p = preparation.frame, preparation.prepared
    read = CurrentDomainReadV1(frame)
    read.check(db)
    if p.requirements_json is not None or p.binding.namespace != frame.envelope.authority.namespace:
        raise ValueError("Life pending preparation contains final or foreign stamp")
    if read_registered_life_plan_v2(db, namespace=p.binding.namespace, issuer=issuer, original_ref=p.binding.plan_original_ref) != p.plan:
        raise ValueError("Life signed plan differs from pending preparation")
    _plan_current(db, read, p.plan)
    from .d08_life_admission_v1 import evaluate_life_admission_v1
    evaluate_life_admission_v1(db, frame=frame, prepared=p, reader=preparation.admission_reader, new_work=True)
    _verify_life_current_budget_v1(db,p,issuer,resource_issuer,frame.now_utc,for_execution=True)
    _verify_life_running_job_v1(p,get_job(db,p.binding.job_id))
    if preparation.job != get_job(db,p.binding.job_id) or preparation.writes != (job_graph_write(preparation.job),) or preparation.read_versions != frame.snapshot.versions:
        raise ValueError("Life pending job/write/read set differs")
    key=job_graph_write(preparation.job).key
    if frame.snapshot.get(key).revision != 0 or db.execute("SELECT 1 FROM graph_atoms WHERE token=?",(key.token,)).fetchone():
        raise ValueError("Life first job projection lacks actual pre-CAS absence")
    from .d10_habit_v1 import verify_habit_life_occurrence_transition_v1
    verify_habit_life_occurrence_transition_v1(db,preparation=preparation,issuer=issuer)
    return preparation
