"""W01 terminal bundle from an authenticated installed Life observation."""
from dataclasses import dataclass
import json
import weakref

from ..runtime_contracts import canonical_digest, canonical_serialize, CommitReceipt
from ..domains.d01.production_operations_v1 import plain_v1, stage_result_v1
from ..domains.d08.execution import ActionOutcome, GoalExecutionProvider, _decode_intent
from ..domains.d08.production_operations_v1 import observed_action_outcome_key_v1
from ..graph_types import AtomKey, GraphWrite, Owner, owner_grant_key
from .d01_production_operations_v1 import CurrentDomainReadV1, MissingProductionOriginalV1, production_read_plan_v1
from .d11_life_contract_v1 import D11LifeClaimV1, D11LifeTerminalV1, WORK_KIND, life_to_wire_v1
from .d11_life_preparation_v1 import D11LifePreparedV1, read_prepared_life_v1, life_ids_from_binding_v1, TABLE, SIGN_KIND, _record, _read
from .d11_life_source_note_v1 import verify_durable_life_artifact_v1, mark_life_artifact_adopted_v1
from .d11_life_graph_types_v1 import life_fact_writes_v1, life_role_segment_key_v1
from .budget import settle_budget
from .jobs import get_job, checkpoint_job, transition_job
from .d11_types import (job_graph_write, cost_settlement_from_runtime, cost_settlement_graph_write,
    runtime_cost_settlement_key, D11RuntimeProvider, D11_PROPOSAL_SCHEMA)
from .domain_production_contracts_v1 import ProductionOriginalRefV1
from .d11_offline_originals_v1 import _utc

_KEY = object()
_OBSERVATIONS = {}


@dataclass(frozen=True, slots=True, weakref_slot=True, init=False)
class ObservedLifeTerminalV1:
    port: object
    prepared: D11LifePreparedV1
    claim: D11LifeClaimV1
    terminal: D11LifeTerminalV1
    original: ProductionOriginalRefV1

    def __init__(self, key, port, prepared, claim, terminal):
        if key is not _KEY:
            raise TypeError("Life observation requires actual installed paired original read")
        original = ProductionOriginalRefV1("d11.life_terminal", terminal.original_ref, canonical_digest(plain_v1(terminal)))
        for name, value in (("port", port), ("prepared", prepared), ("claim", claim), ("terminal", terminal), ("original", original)):
            object.__setattr__(self, name, value)
        ident = id(self)
        _OBSERVATIONS[ident] = (weakref.ref(self, lambda _: _OBSERVATIONS.pop(ident, None)), port,
            prepared.digest, canonical_digest(plain_v1(claim)), original)


def require_observed_life_terminal_v1(observation):
    from ..host.d11_life_port_v1 import InstalledD11LifePortV1
    registered = _OBSERVATIONS.get(id(observation))
    if (type(observation) is not ObservedLifeTerminalV1 or registered is None or registered[0]() is not observation
            or type(observation.port) is not InstalledD11LifePortV1 or registered[1] is not observation.port
            or registered[2:] != (observation.prepared.digest, canonical_digest(plain_v1(observation.claim)), observation.original)
            or observation.original.original_digest != canonical_digest(plain_v1(observation.terminal))
            or observation.terminal.claim != observation.claim or observation.terminal.binding != observation.prepared.binding
            or observation.terminal.payload.prepared_digest != observation.prepared.digest):
        raise ValueError("Life observation was copied or changed")
    return observation


def observe_current_life_terminal_v1(port, prepared):
    from ..host.d11_life_port_v1 import InstalledD11LifePortV1
    if type(port) is not InstalledD11LifePortV1 or type(prepared) is not D11LifePreparedV1:
        raise TypeError("actual installed Life port and signed prepared original required")
    claim, terminal = port.read_d11_life_original_v1(binding=prepared.binding)
    if claim is None or terminal is None:
        raise MissingProductionOriginalV1("actual_independent_life_terminal_after_once_claim")
    if (type(claim) is not D11LifeClaimV1 or type(terminal) is not D11LifeTerminalV1
            or terminal.claim != claim or terminal.binding != prepared.binding or terminal.payload.prepared_digest != prepared.digest):
        raise ValueError("Life paired actual terminal differs from frozen preparation")
    return ObservedLifeTerminalV1(_KEY, port, prepared, claim, terminal)


@dataclass(frozen=True, slots=True)
class AdoptCurrentLifeRequestV1:
    prepared_original_ref: str


class InstalledLifeTerminalReadersV1:
    def __init__(self, *, issuer, observation, admission_reader):
        from .issuers import D11BudgetJobIssuer
        if type(issuer) is not D11BudgetJobIssuer:
            raise TypeError("Life terminal needs actual installed budget issuer")
        self.issuer = issuer
        self.observation = require_observed_life_terminal_v1(observation)
        from .d08_life_admission_v1 import InstalledLifeAdmissionReaderV1
        if type(admission_reader) is not InstalledLifeAdmissionReaderV1: raise TypeError("Life terminal requires its actual installed admission reader")
        self.admission_reader = admission_reader


@dataclass(frozen=True, slots=True)
class LifeTerminalBundleV1:
    envelope: object
    memory_stage: object
    runtime_stage: object
    terminal: D11LifeTerminalV1
    prepared: D11LifePreparedV1
    source_refs: tuple[str, ...]


def life_adoption_operation_id_v1(binding):
    return "d11-life-adopt:" + canonical_digest((binding.namespace, binding.execution_id, binding.digest))[:48]


def read_plan_current_life_terminal_v1(db, *, namespace, activity_id, operation_kind, request):
    if operation_kind != "adopt_life" or type(request) is not AdoptCurrentLifeRequestV1:
        raise TypeError("registered fixed Life terminal request required")
    keys = [owner_grant_key(*namespace.as_tuple)]
    row = db.execute("SELECT payload_json FROM " + TABLE + " WHERE bot=? AND persona=? AND kind='prepared' AND original_ref=?",
        (*namespace.as_tuple, request.prepared_original_ref)).fetchone()
    if row:
        from .d11_life_preparation_v1 import life_prepared_from_wire_v1
        p = life_prepared_from_wire_v1(json.loads(row[0]))
        b = p.binding
        if b.activity_id != activity_id:
            raise ValueError("Life terminal activity differs")
        keys += [AtomKey.from_token(r.ref) for r in p.read_rows]
        keys += [AtomKey( Owner("activity", *namespace.as_tuple, b.activity_id), "runtime.job", b.job_id),
            runtime_cost_settlement_key(*namespace.as_tuple, b.activity_id, b.reservation_operation_id),
            AtomKey.from_token(b.artifact_ref), life_role_segment_key_v1(b, "start"), life_role_segment_key_v1(b, "end")]
        action_row = db.execute("SELECT value FROM graph_atoms WHERE token=?", (p.plan.action_intent.ref,)).fetchone()
        action = _decode_intent(json.loads(action_row[0]))
        keys.append(observed_action_outcome_key_v1(AtomKey.from_token(p.plan.action_intent.ref), action))
    return production_read_plan_v1((), tuple(dict.fromkeys(keys)), (), (request.prepared_original_ref,))


def stage_current_life_terminal_in_transaction_v1(db, *, frame, request, installed_readers):
    if type(installed_readers) is not InstalledLifeTerminalReadersV1:
        raise TypeError("Life adoption needs its actual sealed installed terminal reader")
    read = CurrentDomainReadV1(frame)
    read.check(db)
    observation = require_observed_life_terminal_v1(installed_readers.observation)
    p, terminal = observation.prepared, observation.terminal
    b = p.binding
    if (request.prepared_original_ref != b.prepared_original_ref or read_prepared_life_v1(db, binding=b, issuer=installed_readers.issuer) != p
            or frame.envelope.identity.operation_id != life_adoption_operation_id_v1(b)
            or (frame.envelope.identity.activity_id, frame.envelope.identity.effect_id) != (b.activity_id, b.effect_id)
            or frame.owner_guard.grant_ref != b.owner_grant_ref or frame.owner_guard.grant_revision != b.owner_grant_revision
            or frame.owner_guard.grant_digest != b.owner_grant_digest or frame.activation_generation != b.activation_generation
            or frame.envelope.parent_budget_lease_ref != b.parent_budget_lease_ref):
        raise ValueError("Life adoption current prepared/Owner/activity/budget differs")
    read.original(observation.original.original_ref, kind=observation.original.kind, digest=observation.original.original_digest)
    from .d11_life_preparation_v1 import _plan_current
    action, _ = _plan_current(db, read, p.plan)
    from .d08_life_admission_v1 import require_current_life_action_admission_v1
    require_current_life_action_admission_v1(db,prepared=p,reader=installed_readers.admission_reader,now_utc=frame.now_utc,frame=frame)
    artifact = verify_durable_life_artifact_v1(db, p, digest=terminal.payload.artifact_digest,
        length=terminal.payload.artifact_length) if terminal.status == "completed" else None
    job = get_job(db, b.job_id)
    job_atom = read.head(db, job_graph_write(job).key, required=True)
    if (job_atom.revision != p.job_projection_revision or canonical_serialize(job_atom.value) != p.job_projection_json
            or (job.operation_id, job.activity_id, job.effect_id, job.work_kind, job.fence, job.cancel_epoch) !=
                (b.operation_id, b.activity_id, b.effect_id, WORK_KIND, b.job_fence, b.job_cancel_epoch)):
        raise ValueError("Life adopted original job differs from actual claim")
    actual = None if terminal.status == "unknown" else {"thread_cpu_ms": terminal.actual_cpu_ms}
    settle_budget(db, b.parent_budget_lease_ref, b.reservation_operation_id, b.reservation_digest, actual, execution_revoked=True)
    if job.phase != "running" or (job.lease_holder, job.lease_expires_utc) != (b.job_holder, b.job_lease_expires_utc):
        raise ValueError("Life actual consumed worker lease changed")
    if actual is not None:
        job = checkpoint_job(db, job.job_id, b.job_holder, b.job_fence, continuation=job.continuation, usage=actual)
    job = transition_job(db, job.job_id, b.job_holder, b.job_fence,
        target_phase={"completed": "completed", "failed": "failed", "unknown": "pending_confirmation"}[terminal.status],
        result_ref=b.artifact_ref if terminal.status == "completed" else None)
    cost = cost_settlement_from_runtime(db, bot_id=b.namespace.bot_id, persona_id=b.namespace.persona_id, activity_id=b.activity_id,
        bundle_operation_id=frame.envelope.identity.operation_id, effect_id=b.effect_id, settlement_id=b.reservation_operation_id,
        lease_id=b.parent_budget_lease_ref, cost_operation_id=b.reservation_operation_id, budget_operation_id=b.reservation_operation_id,
        budget_phase="settle", prior_unknown_ref=None, execution_revoked=True)
    fact_writes = life_fact_writes_v1(p, observation.claim, terminal, artifact)
    runtime = stage_result_v1(frame, "d11", "adopt_life", request,
        writes=(job_graph_write(job), cost_settlement_graph_write(cost), *fact_writes),
        provenance={"actual_terminal": terminal, "actual_cost": cost, "actual_job": job},
        proposal_schema=D11_PROPOSAL_SCHEMA, proposal_hash=D11RuntimeProvider().descriptor.request_schema_hash)
    outcome_key = observed_action_outcome_key_v1(AtomKey.from_token(p.plan.action_intent.ref), action)
    outcome = ActionOutcome(outcome_key.name, action.action_id, b.effect_id, b.attempt_id,
        "completed_verified" if terminal.status == "completed" else "unknown" if terminal.status == "unknown" else "failed_verified",
        "installed_artifact_readback" if terminal.status == "completed" else "actual_execution_terminal",
        (terminal.original_ref,), (b.effect_id,) if terminal.status == "completed" else (),
        (b.effect_id,) if terminal.status == "unknown" else (), "life-settlement:" + canonical_digest((b.namespace, b.effect_id)),
        _utc(terminal.payload.completed_at_utc).timestamp())
    goal = stage_result_v1(frame, "d08", "adopt_life", request, writes=(GraphWrite(outcome_key, plain_v1(outcome),
        (AtomKey.from_token(p.plan.action_intent.ref), *tuple(w.key for w in fact_writes))),),
        provenance={"action_outcome": outcome, "actual_terminal": terminal, "actual_cost": cost,
            "postcondition_build_digest": b.postcondition_build_digest},
        receiver_events=(("d10", "actual_life_terminal_requires_current_body_and_progress_qualification"),),
        proposal_schema="d08.proposal.v1", proposal_hash=GoalExecutionProvider().descriptor.request_schema_hash)
    sources = (p.plan.input_source.ref,) if terminal.status == "completed" else ()
    return LifeTerminalBundleV1(frame.envelope, goal, runtime, terminal, p, sources)


def record_life_terminal_after_cas_v1(db, *, issuer, staged, graph_receipt):
    if type(staged) is not LifeTerminalBundleV1 or type(graph_receipt) is not CommitReceipt:
        raise TypeError("actual Life W01 terminal receipt required")
    b = staged.prepared.binding
    if graph_receipt.operation_id != life_adoption_operation_id_v1(b) or graph_receipt.status != "committed":
        raise ValueError("Life actual terminal bundle receipt identity differs")
    actual = db.execute("SELECT digest,commit_seq FROM graph_bundle_operations WHERE bot=? AND persona=? AND operation_id=?",
        (*b.namespace.as_tuple, graph_receipt.operation_id)).fetchone()
    if actual != (graph_receipt.operation_digest, graph_receipt.commit_seq):
        raise ValueError("Life terminal receipt is not its actual W01 operation")
    writes = tuple(w for s in (staged.memory_stage, staged.runtime_stage) for p in s.proposals for w in p.typed_writes)
    versions = {v.key.token: v.revision for v in graph_receipt.write_versions}
    if set(versions) != {w.key.token for w in writes}:
        raise ValueError("Life terminal bundle has another member set")
    for write in writes:
        row = db.execute("SELECT event_id,value,valid FROM graph_history WHERE token=? AND revision=?", (write.key.token, versions[write.key.token])).fetchone()
        if row != (graph_receipt.operation_id, canonical_serialize(write.value), 1):
            raise ValueError("Life terminal/job/cost/artifact/D08 are not one actual bundle")
    if staged.terminal.status == "completed":
        mark_life_artifact_adopted_v1(db, b, graph_receipt.operation_id)
    value = {"schema": "d11.adopted-life-original.v1", "namespace": plain_v1(b.namespace),
        "result_ref": b.artifact_ref, "producing_operation_id": graph_receipt.operation_id,
        "prepared_digest": staged.prepared.digest, "terminal": life_to_wire_v1(staged.terminal),
        "source_refs": list(staged.source_refs), "graph_receipt_json": canonical_serialize(plain_v1(graph_receipt)),
        "write_commitments": [{"ref": w.key.token, "revision": versions[w.key.token], "digest": canonical_digest(w.value)} for w in writes]}
    return _record(db, issuer=issuer, namespace=b.namespace, kind="adopted_life", ref=b.artifact_ref,
        operation_id=graph_receipt.operation_id, value=value)


def read_adopted_life_original_v1(db, *, namespace, result_ref, issuer):
    original = _read(db, issuer=issuer, namespace=namespace, kind="adopted_life", ref=result_ref)
    if original is None:
        return None
    value = original[0]
    if set(value) != {"schema", "namespace", "result_ref", "producing_operation_id", "prepared_digest", "terminal", "source_refs", "graph_receipt_json", "write_commitments"}:
        raise ValueError("Life adopted original fields differ")
    from .d11_life_contract_v1 import life_from_wire_v1, D11LifeTerminalV1
    terminal = life_from_wire_v1(value["terminal"], D11LifeTerminalV1)
    if (value["schema"] != "d11.adopted-life-original.v1" or value["result_ref"] != result_ref
            or terminal.binding.namespace != namespace or terminal.binding.artifact_ref != result_ref
            or value["prepared_digest"] != terminal.payload.prepared_digest or value["producing_operation_id"] != original[1]):
        raise ValueError("Life adopted original actual identity differs")
    from .d10_offline_tick_execution_v1 import _decode_json
    receipt = _decode_json(value["graph_receipt_json"], CommitReceipt)
    if receipt.status != "committed" or receipt.operation_id != original[1]:
        raise ValueError("Life adopted original receipt differs")
    actual = db.execute("SELECT digest,commit_seq FROM graph_bundle_operations WHERE bot=? AND persona=? AND operation_id=?",
        (*namespace.as_tuple, receipt.operation_id)).fetchone()
    if actual != (receipt.operation_digest, receipt.commit_seq):
        raise ValueError("Life historical receipt differs from actual committed operation")
    versions = {v.key.token: v.revision for v in receipt.write_versions}
    if versions != {r["ref"]: r["revision"] for r in value["write_commitments"]}:
        raise ValueError("Life adopted original receipt write membership differs")
    for row in value["write_commitments"]:
        history = db.execute("SELECT event_id,value,valid FROM graph_history WHERE token=? AND revision=?", (row["ref"], row["revision"])).fetchone()
        if history is None or history[0] != original[1] or history[2] != 1 or canonical_digest(json.loads(history[1])) != row["digest"]:
            raise ValueError("Life adopted original immutable member history differs")
    return value
