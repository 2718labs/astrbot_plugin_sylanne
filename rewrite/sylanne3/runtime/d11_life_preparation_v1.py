"""Real W01 preparation, budget reservation and signed Life source closure."""
from dataclasses import dataclass, replace
from datetime import datetime, timezone
import json

from ..domains.d01.production_operations_v1 import plain_v1, stage_result_v1
from ..domains.d08.execution import _decode_intent
from ..graph_types import AtomKey, GraphWrite, GraphVersion, Owner, owner_grant_key
from ..memory_types import SourceRecord, access_key
from ..runtime_contracts import canonical_digest, canonical_serialize, VersionedRef
from .d01_production_operations_v1 import CurrentDomainReadV1, MissingProductionOriginalV1
from .d11_life_contract_v1 import (RegisteredLifePlanV2, D11LifeExecutionBindingV1, life_from_wire_v1,
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
class LifePreparationStageV1:
    frame: object
    stage: object
    prepared: D11LifePreparedV1
    job: PersistentJob
    writes: tuple[GraphWrite, ...]
    read_versions: tuple[GraphVersion, ...]
    admission_reader: object
    before_capture_stage: object | None = None


def life_ids_v1(plan):
    suffix = canonical_digest((plan.activity_id, plan.effect_id, plan.attempt_id, plan.operation_id))[:48]
    return {name: "d11-life-" + name + ":" + suffix for name in ("job", "execution", "quote", "reservation", "prepared")}


def life_ids_from_binding_v1(binding):
    # "result" is the signed adopted-original locator, not the bounded Jobs ID.
    return {"job": binding.job_id, "execution": binding.execution_id, "quote": binding.quote_id,
        "reservation": binding.reservation_operation_id, "prepared": binding.prepared_original_ref, "result": binding.artifact_ref}


def life_input_digest_v1(plan, source_json, rows):
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
    old = db.execute("SELECT producing_operation_id,payload_json,payload_digest,signature FROM " + TABLE +
        " WHERE bot=? AND persona=? AND kind=? AND original_ref=?", (*namespace.as_tuple, kind, ref)).fetchone()
    if old is not None and old != expected:
        raise ValueError("Life immutable original replay differs")
    if old is None:
        db.execute("INSERT INTO " + TABLE + " VALUES(?,?,?,?,?,?,?,?)", (*namespace.as_tuple, kind, ref, *expected))
    from .domain_production_contracts_v1 import ProductionOriginalRefV1
    return ProductionOriginalRefV1("d11.life_" + kind, ref, digest)


def _read(db, *, issuer, namespace, kind, ref):
    row = db.execute("SELECT producing_operation_id,payload_json,payload_digest,signature FROM " + TABLE +
        " WHERE bot=? AND persona=? AND kind=? AND original_ref=?", (*namespace.as_tuple, kind, ref)).fetchone()
    if row is None:
        return None
    raw = json.loads(row[1])
    if canonical_serialize(raw) != row[1] or canonical_digest(raw) != row[2]:
        raise ValueError("Life signed original bytes changed")
    issuer._signer.verify(SIGN_KIND, canonical_serialize((namespace, kind, ref, row[2])), row[3])
    from .domain_production_read_plans_v1 import _committed
    _committed(db, namespace, row[0])
    return raw, row[0]


def _plan_current(db, read, plan):
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


def record_registered_life_plan_v2(db, *, frame, issuer, original_ref, producing_operation_id, plan, installed_build):
    if type(plan) is not RegisteredLifePlanV2:
        raise TypeError("actual RegisteredLifePlanV2 required")
    read = CurrentDomainReadV1(frame)
    read.check(db)
    _plan_current(db, read, plan)
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
    value["read_rows"] = tuple(OfflineTickGraphReadV1(**row) for row in value["read_rows"])
    result = D11LifePreparedV1(**value)
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
    if ((frame.envelope.identity.operation_id, frame.envelope.identity.phase, frame.envelope.identity.attempt_id,
                frame.envelope.identity.activity_id, frame.envelope.identity.effect_id) !=
                (request.prepare_operation_id, "prepare_life", request.prepare_operation_id, plan.activity_id, plan.effect_id)
            or request.prepare_operation_id != "d11-life-prepare:" + plan.operation_id
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
    if (parent.state != "active" or (parent.bot_id, parent.persona_id) != ns.as_tuple
            or grant.valid_until_utc <= frame.now_utc or WORK_KIND not in grant.allowed_work_kinds
            or plan.cpu_ceiling_ms > grant.max_ceiling.get("thread_cpu_ms", 0)):
        raise MissingProductionOriginalV1("actual_signed_life_thread_cpu_budget")
    deadline = min(frame.envelope.deadline_utc, _utc(plan.deadline_utc).timestamp(), grant.valid_until_utc, _utc(mapping.valid_until_utc).timestamp())
    if deadline - frame.now_utc < 1:
        raise MissingProductionOriginalV1("actual_life_execution_deadline")
    rows = tuple(OfflineTickGraphReadV1(a.key.token, a.revision, canonical_serialize(a.value), a.valid)
        for a in frame.snapshot.atoms if a.key != job_key)
    source_json = canonical_serialize(source.value)
    input_digest = life_input_digest_v1(plan, source_json, rows)
    quote = ResourceQuote(ids["quote"], 1, *ns.as_tuple, plan.activity_id, request.prepare_operation_id, plan.effect_id,
        parent.lease_id, WORK_KIND, "life-input:" + input_digest[:48], deadline, ALGORITHM_ID, job_key.token,
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
        quote.snapshot_ref, "queued", WORK_KIND, {"schema": "d11.life-job.v1", "prepared_original_ref": ids["prepared"],
            "plan_original_ref": request.plan_original_ref, "input_digest": input_digest, "execution_id": ids["execution"]},
        None, deadline_text, parent.lease_id, ALGORITHM_ID, {"algorithm": ALGORITHM_ID,
            "algorithm_build": plan.algorithm_build_digest, "postcondition_build": plan.postcondition_build_digest,
            "resource_quote": quote.quote_id + ":1"}, None, None, 0, 0, {}, None)
    create_job(db, job, "create:" + plan.operation_id, canonical_digest(plain_v1(job)))
    job = acquire_job(db, job.job_id, job_holder, now_utc=datetime.fromtimestamp(frame.now_utc, timezone.utc).isoformat().replace("+00:00", "Z"),
        lease_seconds=min(60, int(deadline - frame.now_utc)))
    binding = D11LifeExecutionBindingV1(ns, authority_namespace, authority_id, installation_id, manifest_digest,
        frame.activation_generation, plan.operation_id, request.prepare_operation_id, plan.activity_id, plan.effect_id, plan.attempt_id, ids["execution"],
        ids["job"], job.lease_holder, job.fence, job.lease_expires_utc, job.cancel_epoch, request.plan_original_ref,
        canonical_digest(plain_v1(plan)), ids["prepared"], input_digest, clock["original_digest"], frame.owner_guard.grant_ref,
        frame.owner_guard.grant_revision, frame.owner_guard.grant_digest, parent.lease_id, quote.quote_id, 1,
        canonical_digest(quote), ids["reservation"], reserve_digest, plan.cpu_ceiling_ms, deadline_text,
        plan.algorithm_build_digest, plan.postcondition_build_digest, life_artifact_ref_v1(ns, plan.effect_id))
    owner = read.head(db, owner_grant_key(*ns.as_tuple), required=True)
    attempt = db.execute("SELECT request_digest,attempt_id FROM graph_owner_domain_attempts_v3 WHERE bot=? AND persona=? AND operation_id=?",
        (*ns.as_tuple, request.prepare_operation_id)).fetchone()
    if attempt is None or attempt[1] != admission_reader.scope.operation_id:
        raise ValueError("Life prepare requires actual current Owner command attempt")
    prepared = D11LifePreparedV1(binding, request.prepare_operation_id, plan, source_json,
        canonical_serialize(plain_v1(mapping)), clock_json, canonical_serialize(plain_v1(quote)), *signed,
        canonical_serialize(plain_v1(parent)), reserve[0], canonical_serialize(plain_v1(frame.owner_guard)), canonical_serialize(owner.value),
        rows, datetime.fromtimestamp(frame.now_utc, timezone.utc).isoformat().replace("+00:00", "Z"),
        canonical_serialize(plain_v1(frame.envelope.identity)), attempt[0], attempt[1])
    from .d08_life_admission_v1 import evaluate_life_admission_v1
    evaluate_life_admission_v1(db, frame=frame, prepared=prepared, reader=admission_reader)
    stage = stage_result_v1(frame, "d10", "prepare_life", request, provenance={"prepared_binding": binding,
        "execution": "requires_actual_d11_once_claim_and_durable_artifact_postcondition"})
    return LifePreparationStageV1(frame, stage, prepared, job, (job_graph_write(job),), frame.snapshot.versions, admission_reader, before_stage)


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
    if not db.in_transaction or type(binding) is not D11LifeExecutionBindingV1:
        raise ValueError("Life current preparation requires actual pinned SQL")
    p = read_prepared_life_v1(db, binding=binding, issuer=issuer)
    if p is None:
        raise ValueError("Life signed preparation is absent")
    if for_execution:
        metadata = db.execute("SELECT requirements_json,graph_revision FROM graph_recovery_metadata_v2 WHERE bot=? AND persona=?", binding.namespace.as_tuple).fetchone()
        epoch = db.execute("SELECT revision FROM graph_epochs WHERE bot=? AND persona=?", binding.namespace.as_tuple).fetchone()
        if metadata != (p.requirements_json, p.graph_revision) or epoch != (p.graph_epoch,):
            raise ValueError("Life first claim Graph stamp changed")
    for frozen in p.read_rows:
        row = db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=?", (frozen.ref,)).fetchone()
        if row != (frozen.revision, frozen.value_json, int(frozen.valid)) and not (frozen.revision == 0 and row is None):
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
    continuation = {"schema":"d11.life-job.v1","prepared_original_ref":b.prepared_original_ref,
        "plan_original_ref":b.plan_original_ref,"input_digest":b.input_digest,"execution_id":b.execution_id}
    if ((job.job_id,job.operation_id,job.activity_id,job.effect_id,job.bot_id,job.persona_id,job.phase,job.work_kind,
            job.lease_holder,job.fence,job.lease_expires_utc,job.cancel_epoch,job.deadline_utc,job.budget_ref,job.resource_ref,job.snapshot_ref) !=
            (b.job_id,b.operation_id,b.activity_id,b.effect_id,*b.namespace.as_tuple,"running",WORK_KIND,b.job_holder,b.job_fence,
             b.job_lease_expires_utc,b.job_cancel_epoch,b.deadline_utc,b.parent_budget_lease_ref,ALGORITHM_ID,"life-input:"+b.input_digest[:48])
            or dict(job.continuation) != continuation or job.wake_condition is not None or job.result_ref is not None or dict(job.usage)
            or dict(job.operator_versions) != {"algorithm":ALGORITHM_ID,"algorithm_build":b.algorithm_build_digest,
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
    evaluate_life_admission_v1(db, frame=frame, prepared=p, reader=preparation.admission_reader)
    _verify_life_current_budget_v1(db,p,issuer,resource_issuer,frame.now_utc,for_execution=True)
    _verify_life_running_job_v1(p,get_job(db,p.binding.job_id))
    if preparation.job != get_job(db,p.binding.job_id) or preparation.writes != (job_graph_write(preparation.job),) or preparation.read_versions != frame.snapshot.versions:
        raise ValueError("Life pending job/write/read set differs")
    key=job_graph_write(preparation.job).key
    if frame.snapshot.get(key).revision != 0 or db.execute("SELECT 1 FROM graph_atoms WHERE token=?",(key.token,)).fetchone():
        raise ValueError("Life first job projection lacks actual pre-CAS absence")
    return preparation
