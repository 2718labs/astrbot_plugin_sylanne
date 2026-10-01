"""D07 actual paid execution transaction bodies, consumed only by W01.

The caller owns the Owner fence, Graph CAS and SQLite transaction. No network,
provider call, native work, BEGIN or COMMIT occurs in this module. Immutable
signed originals are in the shared business database, never a parallel graph.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, replace
from datetime import datetime, timezone
from decimal import Decimal
import json

from ..authority_service.v2_model_egress_contract import ModelEgressIntentV1
from ..authority_service.v2_model_egress_wire import to_wire as model_to_wire
from ..domains.d02 import BodyDomain, BodyProfile, BodyReservation, BodyState
from ..domains.d02.body_quote_original import D02BodyQuoteAuthority
from ..domains.d06 import source_correction_head_key
from ..domains.d07 import SimulationRequest
from ..domains.d07.current_issuer_v1 import qualify_current_source_heads_v1
from ..graph_types import AtomKey, GraphSnapshot, GraphVersion, GraphWrite, Owner
from ..memory_types import SourceRecord, access_key, source_key
from ..model_broker.broker import ModelCallRequest
from ..model_broker.d07_cognition_v1 import (
    D07CognitionInputV1, D07CognitionInstallationV1, D07QualifiedSourceV1,
    FrozenD07CognitionRequestV1, WORK_KIND, TEMPLATE_DIGEST,
    freeze_d07_cognition_request_v1, thaw_d07_cognition_request_v1, parse_d07_cognition_output_v1,
)
from ..runtime_contracts import NamespaceId, VersionedRef, canonical_digest, canonical_serialize
from .budget import reserve_budget, get_budget_lease, require_budget_family_admissible, settle_budget, settle_budget_partial
from .clock import CharacterClockMapping, get_clock_mapping, _mapping_dict
from .d07_current_behavior_v1 import D07CurrentBehaviorStageV1, D07ExecutionOriginalV1, _heads, _json
from .domain_production_contracts_v1 import CurrentOperationFrameV1, ProductionOriginalRefV1
from .d11_types import job_graph_write, cost_settlement_from_runtime, cost_settlement_graph_write
from .issuers import ResourceQuote
from .jobs import PersistentJob, get_job, transition_job, create_job
from .model_cost_settlement import (OriginalModelCostFactV1, prepare_original_model_cost_plan,
    apply_original_model_budget_in_transaction, original_model_budget_measurement,
    original_model_cost_operation_id_v1)

TABLE = "graph_d07_execution_originals_v1"
SIGN_KIND = "d07.execution-original.v1"
KINDS = frozenset({"prepared", "prepare_commit", "request", "call", "result_attempt", "result", "paid_cost",
    "partial_cost", "body_cost", "execution", "adopted", "simulation_request", "simulation_budget", "reflection_request", "accounting_prepared", "semantic_question", "budget_allocation", "budget_closed"})


def install_d07_execution_schema_v1(db):
    db.execute(f"""CREATE TABLE IF NOT EXISTS {TABLE} (
        bot TEXT NOT NULL, persona TEXT NOT NULL, kind TEXT NOT NULL,
        original_ref TEXT NOT NULL, payload_json TEXT NOT NULL, payload_digest TEXT NOT NULL,
        signature TEXT NOT NULL, PRIMARY KEY(bot,persona,kind,original_ref))""")
    for action in ("UPDATE", "DELETE"):
        db.execute(f"""CREATE TRIGGER IF NOT EXISTS {TABLE}_no_{action.lower()}
            BEFORE {action} ON {TABLE}
            BEGIN SELECT RAISE(ABORT,'D07 execution original is immutable'); END""")


def record_d07_original_in_transaction_v1(db, issuer, namespace, kind, ref, payload):
    if not db.in_transaction or kind not in KINDS:
        raise ValueError("D07 registered original requires W01 transaction")
    wire = canonical_serialize(_json(payload))
    digest = canonical_digest(json.loads(wire))
    signature = issuer._signer.sign(SIGN_KIND, canonical_serialize((namespace, kind, ref, digest)))
    prior = read_d07_original_v1(db, issuer, namespace, kind, ref)
    if prior is not None:
        if prior != (json.loads(wire), digest):
            raise ValueError("D07 original identity reused with different bytes")
        return digest
    db.execute(f"INSERT INTO {TABLE} VALUES(?,?,?,?,?,?,?)", (*namespace.as_tuple, kind, ref, wire, digest, signature))
    return digest


def read_d07_original_v1(db, issuer, namespace, kind, ref):
    exists = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (TABLE,)).fetchone()
    if exists is None:
        return None
    row = db.execute(f"SELECT payload_json,payload_digest,signature FROM {TABLE} "
        "WHERE bot=? AND persona=? AND kind=? AND original_ref=?", (*namespace.as_tuple, kind, ref)).fetchone()
    if row is None:
        return None
    raw = json.loads(row[0])
    if kind not in KINDS or canonical_serialize(raw) != row[0] or canonical_digest(raw) != row[1]:
        raise ValueError("D07 immutable original bytes changed")
    issuer._signer.verify(SIGN_KIND, canonical_serialize((namespace, kind, ref, row[1])), row[2])
    return raw, row[1]


@dataclass(frozen=True, slots=True)
class D07ExecutionReadV1:
    ref: str
    revision: int
    valid: bool
    value_json: str

    def __post_init__(self):
        AtomKey.from_token(self.ref)
        if (type(self.revision) is not int or self.revision < 0 or type(self.valid) is not bool
                or canonical_serialize(json.loads(self.value_json)) != self.value_json):
            raise ValueError("D07 exact graph read original required")


@dataclass(frozen=True, slots=True)
class D07PreparedExecutionV1:
    namespace: NamespaceId
    operation_id: str
    activity_id: str
    effect_id: str
    attempt_id: str
    job_id: str
    call_id: str
    execution_id: str
    work_kind: str
    stage_input_digest: str
    frozen_json: str
    read_rows: tuple[D07ExecutionReadV1, ...]
    query_inventory_json: str
    external_content_originals_json: str
    audience: tuple[str, ...]
    purpose: str
    owner_guard_json: str
    owner_authority_json: str
    quote_id: str
    quote_version: int
    quote_digest: str
    reservation_digest: str
    body_policy_id: str
    body_policy_version: int
    body_quote_ref: str
    body_quote_version: int
    body_quote_digest: str
    body_reservation_ref: str
    body_state_ref: str
    body_profile_ref: str
    component_id: str
    clock_mapping_json: str
    clock_original_digest: str
    activation_generation: int
    graph_epoch: int
    access_epoch: int
    delete_epoch: int
    schema: str = "d07.prepared-execution.v1"

    @property
    def digest(self):
        return canonical_digest(asdict(self))

    @property
    def prepare_operation_id(self):
        return "d07-prepare:" + self.operation_id


@dataclass(frozen=True, slots=True)
class D07PreparationStageV1:
    frame: CurrentOperationFrameV1
    stage: D07CurrentBehaviorStageV1
    prepared: D07PreparedExecutionV1
    job: PersistentJob
    writes: tuple[GraphWrite, ...]
    read_versions: tuple[GraphVersion, ...]
    replayed: bool = False


@dataclass(frozen=True, slots=True)
class D07SemanticQuestionV1:
    question_key: str
    question: str
    target_ref: VersionedRef
    source_refs: tuple[str, ...]
    schema: str = "d07.registered-semantic-question.v1"

    def __post_init__(self):
        if (self.schema != "d07.registered-semantic-question.v1" or type(self.target_ref) is not VersionedRef
                or self.target_ref.version < 1 or type(self.source_refs) is not tuple
                or not 1 <= len(self.source_refs) <= 16 or len(set(self.source_refs)) != len(self.source_refs)
                or any(type(v) is not str or not v or len(v) > 1024 for v in (self.question_key, self.question))):
            raise ValueError("D07 exact bounded registered semantic question required")
        if type(self.target_ref.ref) is not str or not self.target_ref.ref or len(self.target_ref.ref) > 4096:
            raise ValueError("D07 semantic target locator differs")
        for ref in self.source_refs:
            if AtomKey.from_token(ref).type_name != "memory.source":
                raise ValueError("D07 semantic question sources must be actual D06 roots")


def record_current_d07_semantic_question_in_transaction_v1(db, issuer, frame, ref, question):
    if not db.in_transaction or type(question) is not D07SemanticQuestionV1:
        raise ValueError("D07 question registration requires actual Owner W01 transaction")
    target = resolve_current_d07_semantic_target_v1(db, issuer, frame, question)
    _source_input(frame, question.source_refs)
    digest = record_d07_original_in_transaction_v1(db, issuer, frame.envelope.authority.namespace,
        "semantic_question", ref, asdict(question))
    return ProductionOriginalRefV1("d07.semantic_question", ref, digest, target.read_versions)


@dataclass(frozen=True, slots=True)
class D07SemanticTargetOriginalV1:
    kind: str
    original_ref: str
    revision: int
    original_digest: str
    value_json: str
    source_refs: tuple[str, ...]
    read_versions: tuple[GraphVersion, ...]

    def __post_init__(self):
        if (self.kind not in {"graph_head", "d08_joint_plan_intent"} or type(self.original_ref) is not str
                or not self.original_ref or type(self.revision) is not int or self.revision < 1
                or canonical_digest(json.loads(self.value_json)) != self.original_digest
                or canonical_serialize(json.loads(self.value_json)) != self.value_json
                or type(self.source_refs) is not tuple or type(self.read_versions) is not tuple):
            raise ValueError("D07 exact bounded semantic target original differs")
        if len(self.value_json.encode()) > 8192 or len(self.source_refs) > 16 or len(set(self.source_refs)) != len(self.source_refs):
            raise ValueError("D07 semantic target exceeds installed bounds")
        for ref in self.source_refs:
            if AtomKey.from_token(ref).type_name != "memory.source":
                raise ValueError("D07 semantic target requires actual D06 sources")
        if any(type(v) is not GraphVersion or v.revision < 1 for v in self.read_versions):
            raise ValueError("D07 semantic target current read versions differ")


def read_d07_joint_plan_semantic_target_v1(db, issuer, namespace, target_ref):
    """The only non-Graph semantic target is an actual signed D08 plan intent."""
    from .domain_production_erasure_v1 import decode_typed_production_value_v1
    from .d08_production_operations_v1 import JointPlanIntentOriginalV1
    table = "graph_d08_joint_plan_intents_v1"
    if db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchone() is None:
        raise ValueError("D07 exact signed D08 semantic target unavailable")
    row = db.execute(f"SELECT producing_operation_id,payload_json,payload_digest,signature,source_refs_json FROM {table} "
        "WHERE bot=? AND persona=? AND original_ref=?", (*namespace.as_tuple, target_ref.ref)).fetchone()
    if row is None:
        raise ValueError("D07 semantic locator is not an installed target original")
    issuer._signer.verify("d11.d08-joint-plan-intent.v1", row[1], row[3])
    raw = json.loads(row[1])
    intent = decode_typed_production_value_v1(raw, JointPlanIntentOriginalV1)
    if (canonical_serialize(raw) != row[1] or canonical_digest(raw) != row[2] or intent.revision != target_ref.version
            or tuple(json.loads(row[4])) != intent.source_refs):
        raise ValueError("D07 signed D08 exact target revision/content commitment differs")
    original = db.execute("SELECT receipt_json,commit_seq FROM graph_bundle_operations WHERE bot=? AND persona=? AND operation_id=?",
        (*namespace.as_tuple, row[0])).fetchone()
    if original is None or original[1] < 1 or json.loads(original[0]).get("commit_seq") != original[1]:
        raise ValueError("D07 signed semantic target lost its actual producing Graph operation")
    versions = []
    for ref in intent.current_goal_refs:
        key = AtomKey.from_token(ref)
        goal = db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=?", (ref,)).fetchone()
        if (NamespaceId.from_key(key) != namespace or key.type_name != "d08.goal.v1" or goal is None
                or goal[2] != 1 or goal[0] < 1 or json.loads(goal[1]).get("state") != "active"):
            raise ValueError("D07 signed plan target requires its actual current active goals")
        versions.append(GraphVersion(key, goal[0]))
    return D07SemanticTargetOriginalV1("d08_joint_plan_intent", target_ref.ref, target_ref.version, row[2], row[1], intent.source_refs, tuple(versions))


def resolve_current_d07_semantic_target_v1(db, issuer, frame, question):
    try:
        key = AtomKey.from_token(question.target_ref.ref)
    except (ValueError, TypeError):
        target = read_d07_joint_plan_semantic_target_v1(db, issuer, frame.envelope.authority.namespace, question.target_ref)
        matches = [original for original in frame.observed_originals if original.original_ref == target.original_ref]
        if len(matches) != 1 or matches[0].kind != "d08.joint_plan_intent" or matches[0].original_digest != target.original_digest:
            raise ValueError("D07 exact signed joint-plan target is not in actual current original frame")
        _source_input(frame, target.source_refs)
        if any(frame.snapshot.get(v.key) is None or not frame.snapshot.get(v.key).valid
                or frame.snapshot.get(v.key).revision != v.revision for v in target.read_versions):
            raise ValueError("D07 signed semantic target current goal closure is not guarded")
        return target
    atom = frame.snapshot.get(key)
    if atom is None or not atom.valid or atom.revision != question.target_ref.version:
        raise ValueError("D07 semantic current Graph target is not in authorized frame")
    return D07SemanticTargetOriginalV1("graph_head", key.token, atom.revision, canonical_digest(atom.value),
        canonical_serialize(atom.value), (), (GraphVersion(key, atom.revision),))


def read_current_d07_semantic_question_v1(db, issuer, namespace, ref):
    row = read_d07_original_v1(db, issuer, namespace, "semantic_question", ref)
    if row is None:
        return None
    raw = row[0]
    return D07SemanticQuestionV1(**{**raw, "target_ref": VersionedRef(**raw["target_ref"]),
        "source_refs": tuple(raw["source_refs"])})


def d07_execution_ids_v1(namespace, operation_id, kind):
    suffix = canonical_digest((namespace, operation_id, kind))[:48]
    return {"job": "d07-job:" + suffix, "call": "d07-call:" + suffix,
        "execution": "d07-execution:" + suffix, "quote": "d07-quote:" + suffix,
        "reservation": "d07-body:" + suffix, "settlement": "d07-settle:" + suffix}


def read_prepared_d07_execution_v1(db, issuer, namespace, job_id):
    row = read_d07_original_v1(db, issuer, namespace, "prepared", job_id)
    if row is None:
        return None
    raw = dict(row[0])
    raw["namespace"] = NamespaceId(**raw["namespace"])
    raw["read_rows"] = tuple(D07ExecutionReadV1(**r) for r in raw["read_rows"])
    raw["audience"] = tuple(raw["audience"])
    value = D07PreparedExecutionV1(**raw)
    if value.namespace != namespace or value.job_id != job_id or value.digest != row[1]:
        raise ValueError("D07 prepared identity differs")
    thaw_d07_cognition_request_v1(json.loads(value.frozen_json))
    return value


def _read_rows(snapshot, versions):
    rows = []
    for version in sorted(versions, key=lambda v: v.key.token):
        atom = snapshot.get(version.key)
        if atom is None or atom.revision != version.revision:
            raise ValueError("D07 current execution read is not in frame")
        rows.append(D07ExecutionReadV1(atom.key.token, atom.revision, atom.valid, canonical_serialize(atom.value)))
    return tuple(rows)


def require_current_d07_content_reads_v1(db, prepared, *, issuer=None):
    if not db.in_transaction:
        raise ValueError("D07 current execution proof requires pinned transaction")
    rows = prepared.read_rows
    inventory = prepared.query_inventory_json
    if issuer is not None:
        committed = read_d07_original_v1(db, issuer, prepared.namespace, "prepare_commit", prepared.job_id)
        if committed is None or committed[0]["prepared_digest"] != prepared.digest:
            raise ValueError("D07 actual prepared Graph commit original missing")
        rows = tuple(D07ExecutionReadV1(**r) for r in committed[0]["post_read_rows"])
        inventory = committed[0]["post_query_inventory_json"]
        for external in json.loads(prepared.external_content_originals_json):
            if set(external) != {"kind", "ref", "revision", "digest"} or external["kind"] != "d08_joint_plan_intent":
                raise ValueError("D07 unregistered external content original kind")
            actual = read_d07_joint_plan_semantic_target_v1(db, issuer, prepared.namespace, VersionedRef(external["ref"], external["revision"]))
            if actual.original_digest != external["digest"]:
                raise ValueError("D07 exact signed semantic target changed")
    for row in rows:
        if NamespaceId.from_key(AtomKey.from_token(row.ref)) != prepared.namespace:
            raise ValueError("D07 frozen read crosses namespace")
        current = db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=?", (row.ref,)).fetchone()
        if row.revision == 0:
            if row.valid or current is not None:
                raise ValueError("D07 exact negative content read now exists")
        elif (current is None or (current[0], bool(current[2])) != (row.revision, row.valid)
                or canonical_serialize(json.loads(current[1])) != row.value_json):
            raise ValueError("D07 actual cognition content became stale")
    for page in json.loads(inventory):
        if not page["complete"]:
            raise ValueError("D07 incomplete query cannot prove exact current selection")
        rows = db.execute("SELECT token,revision FROM graph_atoms WHERE bot=? AND persona=? AND type_name=? ORDER BY token LIMIT 129",
            (*prepared.namespace.as_tuple, page["type_id"])).fetchall()
        if len(rows) > 128 or rows != [tuple(r) for r in page["rows"]]:
            raise ValueError("D07 actual negative/query selection scope changed")


def _source_input(frame, roots):
    heads = _heads(frame.snapshot)
    qualify_current_source_heads_v1(frame.envelope.authority.namespace, roots, heads,
        audience=frame.envelope.authority.audience[0], purpose=frame.envelope.authority.purpose)
    values = []
    for ref in roots:
        atom = frame.snapshot.get(AtomKey.from_token(ref))
        if atom is None or not atom.valid:
            raise ValueError("D07 model source is unavailable")
        values.append(D07QualifiedSourceV1(VersionedRef(ref, atom.revision), SourceRecord.from_dict(atom.value)))
    return tuple(values)


def freeze_current_d07_stage_v1(frame, stage, workflow, installation_id):
    """Derive the model's question and sources from actual installed stage data."""
    if stage.status != "queued" or stage.envelope != frame.envelope or workflow.work_kind != WORK_KIND:
        raise ValueError("D07 actual queued current stage/workflow required")
    if stage.work_kind == "concern":
        choice = stage.provenance["choice"]
        tickets = tuple(t for t in stage.provenance["tickets"] if t.ticket_id == choice.ticket_id)
        if len(tickets) != 1:
            raise ValueError("D07 actual concern choice is not unique")
        ticket = tickets[0]
        target_ref = ticket.concern_ref or source_key(*frame.envelope.authority.namespace.as_tuple,
            AtomKey.from_token(ticket.source_refs[0]).owner.subject).token
        question = ticket.question_key
        if ticket.concern_ref:
            concern = frame.snapshot.get(AtomKey.from_token(ticket.concern_ref))
            if concern is None or not concern.valid or concern.key.type_name != "d07.concern.v1":
                raise ValueError("D07 chosen concern original unavailable")
            question = "Examine the unresolved concern anchored at " + concern.value["anchor_ref"]
        input = D07CognitionInputV1(frame.envelope.authority.namespace, frame.envelope.identity.activity_id,
            "concern", ticket.question_key, question, target_ref, _source_input(frame, ticket.source_refs))
        semantic = stage.provenance.get("semantic_question")
        if semantic is not None:
            if type(semantic) is not D07SemanticQuestionV1 or set(semantic.source_refs) != set(ticket.source_refs):
                raise ValueError("D07 actual semantic question differs from chosen source scope")
            target = stage.provenance.get("semantic_target")
            if (type(target) is not D07SemanticTargetOriginalV1 or target.original_ref != semantic.target_ref.ref
                    or target.revision != semantic.target_ref.version):
                raise ValueError("D07 exact authenticated semantic target missing from preparation")
            input = replace(input, question_key=semantic.question_key, question=semantic.question,
                target_ref=semantic.target_ref.ref, target_original_json=target.value_json,
                target_original_kind=target.kind, target_original_digest=target.original_digest)
    elif stage.work_kind == "simulation":
        registered = stage.provenance["request"]
        if type(registered) is not SimulationRequest or registered.predictions:
            raise ValueError("D07 simulation intent must not contain fabricated future predictions")
        input = D07CognitionInputV1(frame.envelope.authority.namespace, registered.activity_id, "simulation",
            "simulation:" + frame.envelope.identity.operation_id, "Compare the supplied hypothetical assumptions",
            stage.request.simulation_request_ref, _source_input(frame, registered.snapshot_refs),
            baseline=registered.baseline, alternatives=registered.alternatives, unknowns=registered.unknowns)
    elif stage.work_kind == "reflection":
        request = stage.provenance["reflection_request"]
        checkpoint = frame.snapshot.get(AtomKey.from_token(request["reflection_ref"]))
        if checkpoint is None or not checkpoint.valid or checkpoint.value["status"] != "continue":
            raise ValueError("D07 reflection must wait for a new information trigger")
        input = D07CognitionInputV1(frame.envelope.authority.namespace, frame.envelope.identity.activity_id,
            "reflection", request["question_key"], request["question"], request["reflection_ref"],
            _source_input(frame, tuple(request["source_refs"])), tuple(checkpoint.value["unresolved_slots"]),
            tuple(checkpoint.value["discriminating_refs"]), request["causal_depth"])
    else:
        raise ValueError("unregistered D07 current cognitive work")
    installation = D07CognitionInstallationV1(installation_id, workflow.provider_id, workflow.model_id,
        workflow.provider_config_ref, workflow.provider_config_digest, workflow.max_output_tokens)
    return freeze_d07_cognition_request_v1(input, installation)


def _clock_original(db, issuer, namespace, mapping):
    from .d11_role_clock_installation_v1 import TABLE as CLOCK_TABLE, SIGN_KIND as CLOCK_SIGN_KIND
    rows = db.execute(f"SELECT original_json,original_digest,signature FROM {CLOCK_TABLE} WHERE bot=? AND persona=? AND revision=?",
        (*namespace.as_tuple, mapping.version)).fetchall()
    if len(rows) != 1:
        raise ValueError("D07 role time requires its actual signed Owner clock original")
    wire, digest, signature = rows[0]
    issuer._signer.verify(CLOCK_SIGN_KIND, wire, signature)
    raw = json.loads(wire)
    if (canonical_digest(raw) != digest or raw["mapping"] != _mapping_dict(mapping)
            or get_clock_mapping(db, mapping.mapping_id, mapping.version) != mapping):
        raise ValueError("D07 actual role clock original differs")
    return digest


def prepare_d07_execution_in_transaction_v1(db, *, frame, stage, workflow, installation_id,
        d11_issuer, resource_issuer, body_authority, clock_mapping, body_policy_id, body_policy_version):
    """Return exact D02 reservation+D11 job writes for one atomic W01 preparation."""
    if (not db.in_transaction or type(frame) is not CurrentOperationFrameV1
            or type(stage) is not D07CurrentBehaviorStageV1 or type(body_authority) is not D02BodyQuoteAuthority
            or type(clock_mapping) is not CharacterClockMapping or stage.envelope.identity.effect_id is None):
        raise ValueError("D07 actual Owner/role-resource preparation required")
    envelope, ns = frame.envelope, frame.envelope.authority.namespace
    identity = envelope.identity
    ids = d07_execution_ids_v1(ns, identity.operation_id, stage.work_kind)
    prior = read_prepared_d07_execution_v1(db, d11_issuer, ns, ids["job"])
    if prior is not None:
        raise ValueError("D07 preparation replay must read its actual operation receipt")
    if (workflow.purpose != "proposal" or not set(envelope.authority.audience) <= set(workflow.audiences)):
        raise ValueError("D07 cognition workflow purpose/audience is unconfigured")
    lease = get_budget_lease(db, envelope.parent_budget_lease_ref)
    require_budget_family_admissible(db, lease.lease_id)
    grant = d11_issuer.current_budget_grant(db, lease.lease_id)
    if (WORK_KIND not in grant.allowed_work_kinds or (lease.bot_id, lease.persona_id) != ns.as_tuple
            or any(v > grant.max_ceiling.get(k, 0) for k, v in workflow.quote_ceiling.items())):
        raise ValueError("D07 explicit signed workflow budget is insufficient")
    frozen = freeze_current_d07_stage_v1(frame, stage, workflow, installation_id)
    clock_digest = _clock_original(db, d11_issuer, ns, clock_mapping)
    clock_mapping.character_at(datetime.fromtimestamp(frame.now_utc, timezone.utc).isoformat().replace("+00:00", "Z"))
    policy = body_authority.policy(db, ns, body_policy_id, body_policy_version)
    if policy.work_kind != WORK_KIND:
        raise ValueError("D07 explicitly installed fixed body policy required")
    limits = [envelope.deadline_utc, policy.valid_until,
        datetime.fromisoformat(clock_mapping.valid_until_utc.replace("Z", "+00:00")).timestamp()]
    if stage.work_kind in {"concern", "reflection"}:
        choice = stage.provenance["choice"]
        limits.append(next(t.valid_until for t in stage.provenance["tickets"] if t.ticket_id == choice.ticket_id))
    deadline_upper = min(limits)
    if deadline_upper <= frame.now_utc:
        raise ValueError("D07 current selected ticket/clock/body policy lifetime is exhausted")
    if deadline_upper != envelope.deadline_utc:
        envelope = replace(envelope, deadline_utc=deadline_upper,
            monotonic_deadline=min(envelope.monotonic_deadline, __import__("time").monotonic() + deadline_upper - frame.now_utc))
        frame = replace(frame, envelope=envelope)
        stage = replace(stage, envelope=envelope, proposal=replace(stage.proposal, envelope=envelope))
    profile_key = BodyDomain.profile_write(policy.profile).key
    state_key = BodyDomain.state_write(ns, policy.initial_state).key
    profile_atom, state_atom = (frame.snapshot.get(key) for key in (profile_key, state_key))
    if (profile_atom is None or not profile_atom.valid or profile_atom.value != _json(asdict(policy.profile))
            or state_atom is None or not state_atom.valid):
        raise ValueError("D07 actual current BodyProfile/BodyState absent")
    state = BodyState(**state_atom.value)
    inventory = db.execute("SELECT token,revision,value,valid FROM graph_atoms WHERE bot=? AND persona=? "
        "AND type_name='d02.reservation.v1' ORDER BY token LIMIT 129", ns.as_tuple).fetchall()
    if len(inventory) > 128:
        raise ValueError("D07 body reservation inventory requires bounded continuation")
    reservations = []
    reads = {v.key: v for v in frame.snapshot.versions}
    for ref, revision, value, valid in inventory:
        key = AtomKey.from_token(ref)
        atom = frame.snapshot.get(key)
        if valid != 1 or atom is None or atom.revision != revision or atom.value != json.loads(value):
            raise ValueError("D07 full current body reservation inventory must be in Owner frame")
        reservations.append(BodyReservation(**{**atom.value, "settled_components": tuple(atom.value["settled_components"])}))
    deadline = datetime.fromtimestamp(envelope.deadline_utc, timezone.utc).isoformat().replace("+00:00", "Z")
    original_ref = "d07-prepared:" + identity.operation_id
    continuation = {"request": _json(stage.request), "input_digest": stage.input_digest,
        "choice": _json(stage.provenance.get("choice")), "original_ref": original_ref,
        "prepared_job_id": ids["job"], "quote_id": ids["quote"], "quote_version": 1,
        "call_id": ids["call"], "work_kind": stage.work_kind}
    if stage.work_kind == "simulation":
        continuation.update({"simulation_request_ref": stage.request.simulation_request_ref,
            "registered_request": _json(stage.provenance["request"]),
            "dedicated_budget_original_ref": stage.provenance["dedicated_budget_original"]})
    if stage.work_kind == "reflection":
        continuation.update(_json(stage.provenance["reflection_request"]))
        continuation["reflection_category"] = stage.request.category
    job = PersistentJob(ids["job"], identity.operation_id, identity.activity_id, identity.effect_id,
        *ns.as_tuple, original_ref, "queued", "d07." + stage.work_kind, continuation, None, deadline,
        lease.lease_id, ids["quote"], {"executor": "d07.installed-cognition.v1", "policy": workflow.template_version},
        None, None, 0, 0, {}, None)
    settlement_key = AtomKey(Owner("activity", *ns.as_tuple, identity.activity_id), "d02.settlement.v1", ids["settlement"])
    quote = ResourceQuote(ids["quote"], 1, *ns.as_tuple, identity.activity_id, identity.operation_id,
        identity.effect_id, lease.lease_id, WORK_KIND, "d07-input:" + frozen.input_digest[:48],
        envelope.deadline_utc, "d07-resource:" + canonical_digest(workflow.provider_config_ref)[:48],
        job_graph_write(job).key.token, (), (settlement_key.token,), dict(workflow.quote_ceiling), None, envelope.deadline_utc)
    resource_issuer.issue_quote(db, quote)
    db.execute("INSERT INTO graph_guard_versions(bot,persona,kind,ref,version) VALUES(?,?,?,?,?)",
        (*ns.as_tuple, "resource_lease", quote.quote_id, str(quote.version)))
    quoted_envelope = replace(envelope, version_guard=replace(envelope.version_guard,
        resource_lease_versions=(VersionedRef(quote.quote_id, quote.version),)))
    body = body_authority.issue_fixed_quote_and_reservation(db, resource_issuer, quoted_envelope, quote,
        body_policy_id, body_policy_version, state, tuple(reservations), ids["reservation"], identity.effect_id)
    if body.replayed:
        raise ValueError("D07 orphan prior body quote cannot authorize a new execution")
    reservation_digest = canonical_digest({"schema": "d07.execution-reservation.v1", "frozen": frozen,
        "stage_input_digest": stage.input_digest, "job": job, "quote": quote, "body_quote": body.body_quote,
        "clock_digest": clock_digest, "owner_guard": frame.owner_guard})
    reserve_budget(db, lease.lease_id, identity.operation_id, reservation_digest, quote.ceiling)
    # Accounting heads change legitimately at settlement. Only content/query
    # dependencies remain the execution/adoption current-read requirement.
    content_versions = tuple(v for v in frame.snapshot.versions if not v.key.type_name.startswith(("runtime.", "d02.")))
    rows = _read_rows(frame.snapshot, content_versions)
    query = tuple({"type_id": p.type_id, "rows": tuple((v.key.token, v.revision) for v in p.row_versions),
        "complete": p.complete} for p in frame.query_coverage if not p.type_id.startswith(("runtime.", "d02.")))
    target = stage.provenance.get("semantic_target")
    external_originals = () if target is None or target.kind == "graph_head" else (
        {"kind": target.kind, "ref": target.original_ref, "revision": target.revision, "digest": target.original_digest},)
    prepared = D07PreparedExecutionV1(ns, identity.operation_id, identity.activity_id, identity.effect_id,
        identity.attempt_id, job.job_id, ids["call"], ids["execution"], stage.work_kind, stage.input_digest,
        canonical_serialize(asdict(frozen)), rows, canonical_serialize(query), canonical_serialize(external_originals), envelope.authority.audience,
        envelope.authority.purpose, canonical_serialize(asdict(frame.owner_guard)), canonical_serialize(asdict(envelope.authority)), quote.quote_id, quote.version,
        canonical_digest(quote), reservation_digest, body_policy_id, body_policy_version, body.body_quote.quote_id,
        body.body_quote_version, canonical_digest(body.body_quote), body.reservation_write.key.token,
        state_key.token, profile_key.token, policy.component.component_id, canonical_serialize(_mapping_dict(clock_mapping)),
        clock_digest, frame.activation_generation, frame.snapshot.epochs[0].revision,
        envelope.version_guard.access_epoch, envelope.version_guard.delete_epoch)
    require_current_d07_content_reads_v1(db, prepared)
    for key in (body.reservation_write.key, job_graph_write(job).key, settlement_key):
        if db.execute("SELECT 1 FROM graph_atoms WHERE token=?", (key.token,)).fetchone() is not None:
            raise ValueError("D07 new execution resource/job/settlement must be truly absent")
        reads[key] = GraphVersion(key, 0)
    updated_envelope = replace(quoted_envelope, version_guard=replace(quoted_envelope.version_guard,
        read_versions=tuple(reads.values())))
    updated_frame = replace(frame, envelope=updated_envelope)
    updated_stage = replace(stage, envelope=updated_envelope,
        proposal=replace(stage.proposal, envelope=updated_envelope, required_bundle_parts=("persistent_job",)),
        read_versions=tuple(reads.values()))
    record_d07_original_in_transaction_v1(db, d11_issuer, ns, "prepared", job.job_id, asdict(prepared))
    record_d07_original_in_transaction_v1(db, d11_issuer, ns, "accounting_prepared", job.job_id,
        {"schema": "d07.accounting-prepared.v1", "prepared_digest": prepared.digest,
         **{name: _json(getattr(prepared, name)) for name in D07_ACCOUNTING_FIELDS}})
    create_job(db, job, job.operation_id, reservation_digest)
    return D07PreparationStageV1(updated_frame, updated_stage, prepared, job,
        (body.reservation_write, job_graph_write(job)), tuple(reads.values()))


def verify_current_d07_preparation_stage_v1(db, preparation, service):
    """DB-only independent recheck of the fixed prepared member set before CAS."""
    if not db.in_transaction or type(preparation) is not D07PreparationStageV1:
        raise ValueError("D07 fixed preparation verification needs W01 transaction")
    prepared, frame, stage = preparation.prepared, preparation.frame, preparation.stage
    current = read_prepared_d07_execution_v1(db, service.d11_issuer, prepared.namespace, prepared.job_id)
    if current != prepared or get_job(db, prepared.job_id) != preparation.job:
        raise ValueError("D07 prepared/runtime job original differs")
    if preparation.replayed:
        require_current_d07_content_reads_v1(db, prepared, issuer=service.d11_issuer)
        if preparation.writes:
            raise ValueError("D07 preparation replay must not reapply member writes")
        return
    require_current_d07_content_reads_v1(db, prepared)
    quote = service.resource_issuer.original_signed_quote(db, prepared.quote_id, prepared.quote_version)
    body_quote = service.body_authority.original_body_quote(db, prepared.body_quote_ref,
        prepared.body_quote_version, quote, prepared.operation_id)
    reservation = db.execute("SELECT digest,ceiling_json,state FROM runtime_budget_reservations WHERE lease_id=? AND operation_id=?",
        (quote.parent_budget_lease_ref, prepared.operation_id)).fetchone()
    if (canonical_digest(quote) != prepared.quote_digest or canonical_digest(body_quote) != prepared.body_quote_digest
            or reservation != (prepared.reservation_digest, canonical_serialize(dict(quote.ceiling)), "reserved")
            or preparation.job.phase != "queued" or preparation.job.fence != 0 or preparation.job.cancel_epoch
            or quote.graph_job_ref != job_graph_write(preparation.job).key.token
            or len(preparation.writes) != 2 or preparation.writes[1] != job_graph_write(preparation.job)
            or preparation.writes[0].key.token != prepared.body_reservation_ref
            or preparation.writes[0].value["quote_id"] != prepared.body_quote_ref
            or preparation.writes[0].value["effect_id"] != prepared.effect_id):
        raise ValueError("D07 actual signed quote/reserve/fixed member set differs")
    workflow = service.bundle.model_workflows.d07_cognition
    frozen = freeze_current_d07_stage_v1(frame, stage, workflow, service.bundle.installation_policy.installation_id)
    if canonical_serialize(asdict(frozen)) != prepared.frozen_json or stage.input_digest != prepared.stage_input_digest:
        raise ValueError("D07 exact current source/choice/model wire changed before preparation CAS")
    if stage.work_kind == "concern":
        from .d07_current_behavior_v1 import advance_current_concerns_v1, D07ConcernInputsV1
        provenance = stage.provenance
        checked = advance_current_concerns_v1(frame.envelope, stage.request,
            D07ConcernInputsV1(frame.snapshot, provenance["tickets"], provenance["policy"],
                provenance["issuance_originals"], provenance["trigger"], frame.now_utc, provenance["focus_epoch"]))
        if (checked.proposal.typed_writes != stage.proposal.typed_writes or checked.input_digest != stage.input_digest
                or checked.provenance != {k: v for k, v in stage.provenance.items() if k not in {"semantic_question", "semantic_target"}}
                or checked.status != "queued"):
            raise ValueError("D07 installed pure fair choice differs from actual preparation")
        if "semantic_question" in stage.provenance and resolve_current_d07_semantic_target_v1(db, service.d11_issuer,
                frame, stage.provenance["semantic_question"]) != stage.provenance["semantic_target"]:
            raise ValueError("D07 signed semantic target differs before exact preparation CAS")
    elif stage.work_kind == "reflection":
        from .d07_reflection_execution_v1 import read_actual_d07_reflection_request_v1
        actual = read_actual_d07_reflection_request_v1(db, service.d11_issuer, prepared.namespace,
            stage.request.trigger_original_ref)
        if actual is None or asdict(actual) != stage.provenance["reflection_request"]:
            raise ValueError("D07 reflection preparation lost its actual adopted cognition/root depth")
        from .d07_current_behavior_v1 import advance_current_concerns_v1, D07ConcernInputsV1
        provenance = stage.provenance
        checked = advance_current_concerns_v1(frame.envelope, stage.request,
            D07ConcernInputsV1(frame.snapshot, provenance["tickets"], provenance["policy"],
                provenance["issuance_originals"], provenance["trigger"], frame.now_utc, provenance["focus_epoch"]))
        if (checked.proposal.typed_writes != stage.proposal.typed_writes or checked.input_digest != stage.input_digest
                or checked.provenance != {k: v for k, v in provenance.items() if k != "reflection_request"}
                or checked.status != "queued"):
            raise ValueError("D07 reflection fair preparation choice changed")


def record_d07_preparation_after_cas_v1(db, issuer, preparation, graph_receipt):
    """Seal actual post-prepare content heads after all exact member CAS writes."""
    if not db.in_transaction or type(preparation) is not D07PreparationStageV1:
        raise ValueError("D07 prepared closure requires actual same-transaction Graph CAS")
    prepared = preparation.prepared
    if getattr(graph_receipt, "status", None) != "committed":
        raise ValueError("D07 preparation graph receipt did not commit")
    for write in (*preparation.stage.proposal.typed_writes, *preparation.writes):
        row = db.execute("SELECT value,valid FROM graph_atoms WHERE token=?", (write.key.token,)).fetchone()
        if row is None or row[1] != 1 or json.loads(row[0]) != write.value:
            raise ValueError("D07 fixed preparation member was not adopted")
    rows = []
    for observed in prepared.read_rows:
        row = db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=?", (observed.ref,)).fetchone()
        rows.append(D07ExecutionReadV1(observed.ref, row[0], bool(row[2]), canonical_serialize(json.loads(row[1])))
            if row else observed)
    query = []
    for page in json.loads(prepared.query_inventory_json):
        values = db.execute("SELECT token,revision FROM graph_atoms WHERE bot=? AND persona=? AND type_name=? ORDER BY token LIMIT 129",
            (*prepared.namespace.as_tuple, page["type_id"])).fetchall()
        if len(values) > 128:
            raise ValueError("D07 post-prepare query closure exceeds bound")
        query.append({**page, "rows": values})
    value = {"schema": "d07.preparation-commit.v1", "prepared_digest": prepared.digest,
        "prepare_operation_id": prepared.prepare_operation_id, "graph_receipt_digest": canonical_digest(graph_receipt),
        "writes_digest": canonical_digest((*preparation.stage.proposal.typed_writes, *preparation.writes)),
        "post_read_rows": _json(tuple(rows)), "post_query_inventory_json": canonical_serialize(query)}
    return record_d07_original_in_transaction_v1(db, issuer, prepared.namespace, "prepare_commit", prepared.job_id, value)


def record_registered_simulation_request_in_transaction_v1(db, issuer, frame, ref, request):
    """Only W01's actual Owner command may register an unexecuted simulation intent."""
    if (not db.in_transaction or type(frame) is not CurrentOperationFrameV1
            or type(request) is not SimulationRequest or request.predictions
            or request.activity_id != frame.envelope.identity.activity_id or len(request.alternatives) > 2):
        raise ValueError("D07 exact registered hypothetical intent required")
    lease = get_budget_lease(db, frame.envelope.parent_budget_lease_ref)
    require_budget_family_admissible(db, lease.lease_id)
    if lease.parent_id is None or (lease.bot_id, lease.persona_id) != frame.envelope.authority.namespace.as_tuple:
        raise ValueError("simulation requires an actual dedicated child budget")
    _source_input(frame, request.snapshot_refs)
    grant = issuer.current_budget_grant(db, lease.lease_id)
    budget = {"schema": "d07.dedicated-simulation-budget.v1", "namespace": asdict(frame.envelope.authority.namespace),
        "lease_id": lease.lease_id, "parent_id": lease.parent_id, "grant": asdict(grant),
        "grant_digest": canonical_digest(grant), "owner_guard": asdict(frame.owner_guard)}
    record_d07_original_in_transaction_v1(db, issuer, frame.envelope.authority.namespace, "simulation_budget", lease.lease_id, budget)
    original = {"schema": "d07.registered-simulation-original.v1", "request": asdict(request),
        "request_digest": canonical_digest(request), "dedicated_budget_ref": lease.lease_id,
        "owner_guard": asdict(frame.owner_guard)}
    record_d07_original_in_transaction_v1(db, issuer, frame.envelope.authority.namespace, "simulation_request", ref, original)
    return ProductionOriginalRefV1("d07.simulation_request", ref, canonical_digest(request))


def read_registered_simulation_request_v1(db, issuer, namespace, ref):
    row = read_d07_original_v1(db, issuer, namespace, "simulation_request", ref)
    if row is None:
        raise ValueError("D07 actual registered simulation request missing")
    raw = row[0]["request"]
    result = SimulationRequest(**{**raw, "snapshot_refs": tuple(raw["snapshot_refs"]),
        "alternatives": tuple(raw["alternatives"]), "predictions": tuple(tuple(p) for p in raw["predictions"]),
        "unknowns": tuple(raw["unknowns"])})
    if canonical_digest(result) != row[0]["request_digest"]:
        raise ValueError("D07 signed registered simulation semantic commitment differs")
    return result


def seal_d07_request_in_transaction_v1(db, issuer, prepared, request):
    frozen = thaw_d07_cognition_request_v1(json.loads(prepared.frozen_json))
    job = get_job(db, prepared.job_id)
    if (not db.in_transaction or type(request) is not ModelCallRequest or request.call_id != prepared.call_id
            or request.prompt_template_digest != TEMPLATE_DIGEST or request.identity.phase != WORK_KIND
            or dict(request.payload) != json.loads(frozen.canonical_wire)
            or request.envelope.authority.namespace != prepared.namespace
            or request.envelope.authority.worker_fence != job.fence
            or request.envelope.authority.actor != job.lease_holder or job.phase != "running"):
        raise ValueError("D07 exact acquired current request required")
    from .reply_model_job import reply_request_wire_v1
    return record_d07_original_in_transaction_v1(db, issuer, prepared.namespace, "request", prepared.job_id,
        reply_request_wire_v1(request.envelope, request))


def read_original_d07_request_v1(db, issuer, prepared):
    from .natural_reply_job_v2 import _request_from_wire
    row = read_d07_original_v1(db, issuer, prepared.namespace, "request", prepared.job_id)
    if row is None:
        raise ValueError("D07 acquired request original missing")
    return _request_from_wire(canonical_serialize(row[0]))


def seal_d07_call_in_transaction_v1(db, issuer, prepared, intent):
    request = read_original_d07_request_v1(db, issuer, prepared)
    job = get_job(db, prepared.job_id)
    if (not db.in_transaction or type(intent) is not ModelEgressIntentV1
            or (intent.job_id, intent.call_id, intent.request_digest, intent.binding_digest,
                intent.budget_reservation_operation_id, intent.budget_reservation_digest) !=
               (prepared.job_id, prepared.call_id, request.digest, prepared.digest,
                prepared.operation_id, prepared.reservation_digest)
            or job.phase != "running" or job.fence != intent.worker_fence or job.lease_holder != intent.subject):
        raise ValueError("D07 Authority egress differs from original acquired call")
    return record_d07_original_in_transaction_v1(db, issuer, prepared.namespace, "call", prepared.job_id,
        model_to_wire(intent))


def read_current_original_ref_v1(db, namespace, ref, *, issuer):
    rows = db.execute(f"SELECT kind,payload_digest FROM {TABLE} WHERE bot=? AND persona=? AND original_ref=?",
        (*namespace.as_tuple, ref)).fetchall()
    if not rows:
        return None
    if len(rows) > 1:
        # The public preparation locator refers to the content original;
        # fixed accounting siblings share its job ID but do not replace it.
        rows = [r for r in rows if r[0] in {"prepared", "adopted", "simulation_request", "simulation_budget", "semantic_question", "reflection_request", "execution"}]
    if len(rows) != 1:
        raise ValueError("D07 original locator has conflicting kinds")
    kind, digest = rows[0]
    actual = read_d07_original_v1(db, issuer, namespace, kind, ref)
    versions = ()
    if kind == "prepared":
        versions = tuple(GraphVersion(AtomKey.from_token(r["ref"]), r["revision"]) for r in actual[0]["read_rows"])
    elif kind == "simulation_request":
        request = read_registered_simulation_request_v1(db, issuer, namespace, ref)
        digest = canonical_digest(request)
    elif kind == "simulation_budget":
        lease = get_budget_lease(db, ref)
        grant = issuer.current_budget_grant(db, ref)
        raw = actual[0]
        if (lease.parent_id is None or raw["lease_id"] != lease.lease_id or raw["parent_id"] != lease.parent_id
                or raw["grant"] != _json(asdict(grant)) or raw["grant_digest"] != canonical_digest(grant)):
            raise ValueError("D07 dedicated simulation budget current signed original differs")
        return ProductionOriginalRefV1("d11.dedicated-simulation-budget", ref, digest, ())
    elif kind == "adopted":
        raw = actual[0]
        key = AtomKey.from_token(raw["interpretation_ref"])
        row = db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=?", (key.token,)).fetchone()
        if (row is None or row[2] != 1 or row[0] != raw["interpretation_revision"]
                or canonical_digest(json.loads(row[1])) != raw["interpretation_value_digest"]):
            raise ValueError("D07 adopted interpretation current original differs")
        return ProductionOriginalRefV1("d07.actual-adopted-interpretation", ref, raw["interpretation_value_digest"],
            (GraphVersion(key, row[0]),))
    return ProductionOriginalRefV1("d07." + kind, ref, digest, versions)


def stage_actual_d07_interpretation_writes_v1(db, *, prepared, issuer, envelope):
    """Actual model findings become D07 candidates only within exact paid scope."""
    from ..domains.d07 import CurrentInterpretationCandidate, D07DomainProvider, Stance, EvidenceStatus
    from ..authority_service.d07_current_execution_v1 import D07CognitionResultReadV1, from_wire
    require_current_d07_content_reads_v1(db, prepared, issuer=issuer)
    frozen = thaw_d07_cognition_request_v1(json.loads(prepared.frozen_json))
    if frozen.input.work_kind == "simulation":
        return (), ()  # Branches already preserve hypothetical eligibility.
    paid = read_d07_original_v1(db, issuer, prepared.namespace, "paid_cost", prepared.job_id)
    body = read_d07_original_v1(db, issuer, prepared.namespace, "body_cost", prepared.job_id)
    actual = read_d07_original_v1(db, issuer, prepared.namespace, "result", "d07-result:" + prepared.call_id)
    if paid is None or body is None or actual is None or not paid[0]["paid"] or body[0]["unpaid_cost"]:
        raise ValueError("D07 semantic candidates need actual paid scoped model/body originals")
    result = from_wire(actual[0], D07CognitionResultReadV1)
    text = json.loads(result.observation.result_json)
    if set(text) != {"text"}:
        raise ValueError("D07 semantic candidate result is not original model text")
    suggestion = parse_d07_cognition_output_v1(text["text"], frozen)
    sources = {s.source_ref.ref: s.record for s in frozen.input.sources}
    writes, reads = [], []
    for index, finding in enumerate(suggestion.findings):
        candidate = CurrentInterpretationCandidate("d07-interpretation:" + canonical_digest(
            (prepared.namespace, prepared.call_id, suggestion.output_digest, index))[:48], prepared.activity_id,
            frozen.input.question_key, finding.proposition, Stance(finding.stance), finding.subjective_conviction,
            EvidenceStatus(finding.evidence_status), finding.source_refs,
            tuple(sorted({sources[ref].provenance_root for ref in finding.source_refs})), suggestion.unknowns)
        write = D07DomainProvider.current_interpretation_write(envelope, candidate,
            source_dependencies=tuple(AtomKey.from_token(ref) for ref in finding.source_refs))
        row = db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=?", (write.key.token,)).fetchone()
        if row is not None:
            if row[2] != 1 or json.loads(row[1]) != write.value:
                raise ValueError("D07 model interpretation key conflicts with existing graph")
            continue
        writes.append(write)
        reads.append(GraphVersion(write.key, 0))
    return tuple(writes), tuple(reads)


def record_d07_adopted_interpretations_after_cas_v1(db, issuer, prepared, writes, *, operation_id, receipt):
    """Expose only actual exact Graph adoption, never a self-authenticated DTO."""
    result = read_d07_original_v1(db, issuer, prepared.namespace, "result", "d07-result:" + prepared.call_id)
    if result is None or getattr(receipt, "status", None) != "committed":
        raise ValueError("D07 actual scoped result/Graph adoption receipt missing")
    for write in writes:
        if write.key.type_name != "d07.current_interpretation.v1":
            continue
        current = db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=?", (write.key.token,)).fetchone()
        history = None if current is None else db.execute("SELECT event_id,value,valid FROM graph_history WHERE token=? AND revision=?",
            (write.key.token, current[0])).fetchone()
        if (current is None or current[2] != 1 or json.loads(current[1]) != write.value
                or history is None or history[0] != operation_id or history[2] != 1 or json.loads(history[1]) != write.value):
            raise ValueError("D07 interpretation was not adopted by its actual graph event")
        original = {"schema": "d07.actual-cognition-adoption.v1", "interpretation_ref": write.key.token,
            "interpretation_revision": current[0], "interpretation_value_digest": canonical_digest(write.value),
            "adoption_operation_id": operation_id, "graph_receipt_digest": canonical_digest(receipt),
            "prepared_digest": prepared.digest, "actual_result_digest": result[1], "question_scope": write.value["question_key"],
            "supporting_refs": write.value["source_refs"], "meaningful_unknowns": write.value["meaningful_unknowns"]}
        record_d07_original_in_transaction_v1(db, issuer, prepared.namespace, "adopted", write.key.token, original)


def _clock_from_json(value):
    raw = json.loads(value)
    return CharacterClockMapping(**{**raw, "character_origin": Decimal(raw["character_origin"]), "rate": Decimal(raw["rate"])})


D07_ACCOUNTING_FIELDS = (
    "namespace", "operation_id", "activity_id", "effect_id", "attempt_id", "job_id", "call_id", "execution_id",
    "work_kind", "stage_input_digest", "quote_id", "quote_version", "quote_digest", "reservation_digest",
    "body_policy_id", "body_policy_version", "body_quote_ref", "body_quote_version", "body_quote_digest",
    "body_reservation_ref", "body_state_ref", "body_profile_ref", "component_id", "clock_mapping_json",
    "clock_original_digest", "activation_generation", "graph_epoch", "access_epoch", "delete_epoch")


class D07AccountingPreparedV1:
    """Strict content-free view of the real prepared identity for paid recovery."""
    def __init__(self, raw):
        if (type(raw) is not dict or set(raw) != {"schema", "prepared_digest", *D07_ACCOUNTING_FIELDS}
                or raw["schema"] != "d07.accounting-prepared.v1"):
            raise ValueError("D07 exact historical accounting prepared fields required")
        self._raw = raw
        for name in D07_ACCOUNTING_FIELDS:
            setattr(self, name, NamespaceId(**raw[name]) if name == "namespace" else raw[name])
        self.digest = raw["prepared_digest"]
        self.prepare_operation_id = "d07-prepare:" + self.operation_id


def read_d07_accounting_prepared_v1(db, issuer, namespace, job_id):
    row = read_d07_original_v1(db, issuer, namespace, "accounting_prepared", job_id)
    return None if row is None else D07AccountingPreparedV1(row[0])


def settle_d07_original_model_cost_in_transaction_v1(db, *, prepared, fact, issuer, resource_issuer):
    """Content-free actual settlement survives current source withdrawal."""
    if not db.in_transaction or type(fact) is not OriginalModelCostFactV1:
        raise ValueError("D07 actual independent cost transaction required")
    saved = read_d07_original_v1(db, issuer, prepared.namespace, "call", prepared.job_id)
    accounting = read_d07_original_v1(db, issuer, prepared.namespace, "accounting_prepared", prepared.job_id)
    if (saved is None or saved[0] != model_to_wire(fact.intent) or accounting is None
            or accounting[0]["prepared_digest"] != prepared.digest
            or (fact.intent.job_id, fact.intent.call_id, fact.intent.binding_digest,
                fact.intent.budget_reservation_operation_id) !=
               (prepared.job_id, prepared.call_id, prepared.digest, prepared.operation_id)):
        raise ValueError("D07 actual cost differs from preserved original accounting identity")
    prior = read_d07_original_v1(db, issuer, prepared.namespace, "paid_cost", prepared.job_id)
    if prior is not None:
        if (prior[0]["terminal_digest"] != canonical_digest(asdict(fact.receipt))
                or prior[0]["prepared_digest"] != prepared.digest):
            raise ValueError("D07 paid cost conflicts with actual original terminal")
        return prior[0], ()
    quote = resource_issuer.original_signed_quote(db, prepared.quote_id, prepared.quote_version)
    preparation = read_d07_original_v1(db, issuer, prepared.namespace, "prepare_commit", prepared.job_id)
    graph_preparation = db.execute("SELECT activity_id FROM graph_bundle_operations WHERE bot=? AND persona=? AND operation_id=?",
        (*prepared.namespace.as_tuple, prepared.prepare_operation_id)).fetchone()
    reserved = db.execute("SELECT digest,ceiling_json,state FROM runtime_budget_reservations WHERE lease_id=? AND operation_id=?",
        (quote.parent_budget_lease_ref, prepared.operation_id)).fetchone()
    reserve_original = db.execute("SELECT digest FROM runtime_budget_operations WHERE bot_id=? AND persona_id=? AND operation_id=? AND phase='reserve'",
        (*prepared.namespace.as_tuple, prepared.operation_id)).fetchone()
    if (canonical_digest(quote) != prepared.quote_digest or graph_preparation != (prepared.activity_id,)
            or reserved is None or reserved[0] != prepared.reservation_digest
            or reserved[2] not in {"reserved", "unknown", "partial_unknown", "partial_overrun", "settled", "overrun"}
            or json.loads(reserved[1]) != dict(quote.ceiling) or reserve_original != (prepared.reservation_digest,)
            or quote.graph_job_ref != job_graph_write(get_job(db, prepared.job_id)).key.token
            or (quote.operation_id, quote.work_kind, quote.effect_id, quote.parent_budget_lease_ref) !=
               (prepared.operation_id, WORK_KIND, prepared.effect_id, fact.intent.budget_lease_id)
            or dict(quote.ceiling) != dict(fact.intent.budget_ceiling)
            or fact.intent.budget_reservation_digest != prepared.reservation_digest):
        raise ValueError("D07 actual prepared graph/reserve/signed quote original differs")
    known, unknown = original_model_budget_measurement(fact, quote, work_kind=WORK_KIND)
    if known and unknown:
        receipt = settle_budget_partial(db, quote.parent_budget_lease_ref, prepared.operation_id,
            prepared.reservation_digest, known, unknown, execution_revoked=True)
    else:
        receipt = settle_budget(db, quote.parent_budget_lease_ref, prepared.operation_id,
            prepared.reservation_digest, None if unknown else known, execution_revoked=True)
    cost_id = original_model_cost_operation_id_v1(prepared.namespace, prepared.call_id)
    cost = cost_settlement_graph_write(cost_settlement_from_runtime(db, bot_id=prepared.namespace.bot_id,
        persona_id=prepared.namespace.persona_id, activity_id=prepared.activity_id, bundle_operation_id=cost_id,
        effect_id=prepared.effect_id, settlement_id=cost_id, lease_id=quote.parent_budget_lease_ref,
        cost_operation_id=prepared.operation_id, budget_operation_id=prepared.operation_id,
        budget_phase="settle", prior_unknown_ref=None, execution_revoked=True))
    paid = receipt.status in {"settled", "overrun"} and not unknown
    value = {"schema": "d07.paid-model-result.v1", "prepared_digest": prepared.digest,
        "result_ref": "d07-result:" + prepared.call_id, "result_digest": fact.recovery.observation_digest, "cost_ref": cost.key.token,
        "cost_value": cost.value, "budget_receipt": asdict(receipt),
        "unknown_dimensions": unknown, "paid": paid,
        "terminal_digest": canonical_digest(asdict(fact.receipt))}
    ref = prepared.job_id if paid else prepared.job_id + ":" + canonical_digest(value)
    record_d07_original_in_transaction_v1(db, issuer, prepared.namespace, "paid_cost" if paid else "partial_cost", ref, value)
    return value, (cost,)



def settle_d07_paid_result_in_transaction_v1(db, *, prepared, result_read, fact, issuer, resource_issuer,
        holder, fence):
    """Import the actual scoped content after its independent actual settlement."""
    from ..authority_service.d07_current_execution_v1 import D07CognitionResultReadV1
    if not db.in_transaction or type(result_read) is not D07CognitionResultReadV1:
        raise ValueError("D07 actual independent result transaction required")
    result_read.require_original(fact.intent, prepared)
    if (fact.recovery.state != "observed" or fact.recovery.content_erased
            or result_read.terminal_receipt != fact.receipt
            or result_read.observation.digest != fact.recovery.observation_digest
            or result_read.observation.usage != fact.recovery.usage or result_read.observation.cost != fact.recovery.cost):
        raise ValueError("D07 actual scoped output differs from the independent cost observation")
    record_d07_original_in_transaction_v1(db, issuer, prepared.namespace, "result",
        "d07-result:" + prepared.call_id, asdict(result_read))
    return settle_d07_original_model_cost_in_transaction_v1(db, prepared=prepared, fact=fact,
        issuer=issuer, resource_issuer=resource_issuer)


def stage_d07_body_cost_in_transaction_v1(db, *, prepared, issuer, resource_issuer, body_authority):
    """Exactly three writes against the current same ledger, without resetting it."""
    if not db.in_transaction:
        raise ValueError("D07 current body settlement needs W01 transaction")
    existing = read_d07_original_v1(db, issuer, prepared.namespace, "body_cost", prepared.job_id)
    if existing is not None:
        return (), (), existing[0]
    paid = read_d07_original_v1(db, issuer, prepared.namespace, "paid_cost", prepared.job_id)
    if paid is None or not paid[0]["paid"]:
        raise ValueError("D07 current body settlement requires actual fully measured model cost")
    quote = resource_issuer.original_signed_quote(db, prepared.quote_id, prepared.quote_version)
    body_quote = body_authority.original_body_quote(db, prepared.body_quote_ref, prepared.body_quote_version,
        quote, prepared.operation_id)
    if canonical_digest(quote) != prepared.quote_digest or canonical_digest(body_quote) != prepared.body_quote_digest:
        raise ValueError("D07 original signed resource/body quote differs")
    keys = (AtomKey.from_token(prepared.body_state_ref), AtomKey.from_token(prepared.body_reservation_ref),
        AtomKey.from_token(quote.d02_settlement_refs[0]))
    reads = []
    values = []
    for key in keys:
        row = db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=?", (key.token,)).fetchone()
        if key == keys[2]:
            if row is not None:
                raise ValueError("D07 body settlement target exists without original")
            reads.append(GraphVersion(key, 0))
        else:
            if row is None or row[2] != 1:
                raise ValueError("D07 current same body ledger unavailable")
            reads.append(GraphVersion(key, row[0]))
            values.append(json.loads(row[1]))
    state = BodyState(**values[0])
    reservation = BodyReservation(**{**values[1], "settled_components": tuple(values[1]["settled_components"])})
    if (state.profile_id != body_quote.profile_id or state.version < body_quote.state_version
            or reservation.quote_id != body_quote.quote_id or reservation.effect_id != prepared.effect_id
            or len(body_quote.components) != 1 or body_quote.components[0].component_id != prepared.component_id
            or body_quote.components[0].duration_rate != 0):
        raise ValueError("D07 current body lineage/reservation differs from original")
    component_ref = "d07-component:" + prepared.call_id
    settlement = BodyDomain().settle_component(state, reservation, prepared.component_id,
        actual_cost=body_quote.components[0].fixed_cost, component_receipt=component_ref)
    if settlement.duplicate:
        raise ValueError("D07 original body component already charged without matching receipt")
    writes = (BodyDomain.state_write(prepared.namespace, settlement.state),
        BodyDomain.reservation_write(prepared.namespace, prepared.activity_id, settlement.reservation),
        BodyDomain.settlement_write(prepared.namespace, prepared.activity_id, keys[2].name, settlement))
    value = {"schema": "d07.fixed-body-cost.v1", "prepared_digest": prepared.digest,
        "terminal_digest": paid[0]["terminal_digest"], "result_digest": paid[0]["result_digest"], "component_ref": component_ref,
        "settlement_ref": writes[2].key.token, "writes_digest": canonical_digest(writes),
        "fixed_cost": body_quote.components[0].fixed_cost, "overrun": settlement.overrun,
        "unpaid_cost": settlement.unpaid_cost}
    return writes, tuple(reads), value


def record_d07_body_cost_after_cas_v1(db, *, prepared, issuer, writes, original):
    if not db.in_transaction or len(writes) != 3:
        raise ValueError("D07 body original requires actual three-write CAS")
    for write in writes:
        row = db.execute("SELECT value,valid FROM graph_atoms WHERE token=?", (write.key.token,)).fetchone()
        if row is None or row[1] != 1 or json.loads(row[0]) != write.value:
            raise ValueError("D07 body cost graph CAS did not happen")
    if original["writes_digest"] != canonical_digest(writes):
        raise ValueError("D07 body original differs from actual CAS")
    return record_d07_original_in_transaction_v1(db, issuer, prepared.namespace, "body_cost", prepared.job_id, original)


def stage_d07_execution_original_in_transaction_v1(db, *, prepared, issuer, holder, fence):
    """Produce the real activity projection only after actual model and body cost."""
    from ..authority_service.d07_current_execution_v1 import D07CognitionResultReadV1, from_wire
    paid = read_d07_original_v1(db, issuer, prepared.namespace, "paid_cost", prepared.job_id)
    body = read_d07_original_v1(db, issuer, prepared.namespace, "body_cost", prepared.job_id)
    if paid is None or body is None or not paid[0]["paid"] or body[0]["unpaid_cost"]:
        raise ValueError("D07 result cannot be adopted before actual computation/body settlement")
    prior = read_d07_original_v1(db, issuer, prepared.namespace, "execution", "d07-terminal:" + prepared.call_id)
    if prior is not None:
        return decode_d07_execution_original_v1(prior[0]), ()
    result = read_d07_original_v1(db, issuer, prepared.namespace, "result", paid[0]["result_ref"])
    read = from_wire(result[0], D07CognitionResultReadV1)
    frozen = thaw_d07_cognition_request_v1(json.loads(prepared.frozen_json))
    response = json.loads(read.observation.result_json)
    if set(response) != {"text"} or type(response["text"]) is not str:
        raise ValueError("D07 provider exact text response required")
    suggestion = parse_d07_cognition_output_v1(response["text"], frozen)
    mapping = _clock_from_json(prepared.clock_mapping_json)
    if _clock_original(db, issuer, prepared.namespace, mapping) != prepared.clock_original_digest:
        raise ValueError("D07 actual original role mapping changed")
    start_wall, end_wall = read.timing.started_at, read.timing.ended_at
    start = float(mapping.character_at(datetime.fromtimestamp(start_wall, timezone.utc).isoformat().replace("+00:00", "Z")))
    end = float(mapping.character_at(datetime.fromtimestamp(end_wall, timezone.utc).isoformat().replace("+00:00", "Z")))
    terminal_ref = "d07-terminal:" + prepared.call_id
    execution = D07ExecutionOriginalV1(terminal_ref, prepared.operation_id, prepared.activity_id,
        prepared.effect_id, prepared.attempt_id, prepared.execution_id, prepared.stage_input_digest,
        suggestion.output_digest, prepared.work_kind, start, end, mapping.mapping_id, str(mapping.version),
        get_job(db, prepared.job_id).budget_ref, (paid[0]["cost_ref"],),
        tuple(s.source_ref.ref for s in frozen.input.sources), prepared.activation_generation,
        suggestion.resolved_slots, suggestion.discriminating_refs, suggestion.predictions, frozen.input.causal_depth)
    record_d07_original_in_transaction_v1(db, issuer, prepared.namespace, "execution", terminal_ref, asdict(execution))
    job = transition_job(db, prepared.job_id, holder, fence, target_phase="completed", result_ref=terminal_ref)
    return execution, (job_graph_write(job),)


def decode_d07_execution_original_v1(raw):
    data = dict(raw)
    for name in ("cost_receipt_refs", "source_refs", "resolved_slots", "discriminating_refs"):
        data[name] = tuple(data[name])
    data["predictions"] = tuple(tuple(p) for p in data["predictions"])
    return D07ExecutionOriginalV1(**data)
