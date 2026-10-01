"""Current D06+D11 adoption of an independently measured offline tick.

The paired Authority read happens before Graph SQL. Only its sealed observation
can reach the fixed current compiler; settlement uses exact original reserve.
"""
from dataclasses import dataclass
from datetime import datetime
from decimal import Context, DivisionByZero, InvalidOperation, Overflow, ROUND_HALF_EVEN, localcontext
import json
import weakref

from ..authority_service.d11_offline_tick_contract_v1 import D11OfflineTickClaimV1, D11OfflineTickTerminalV1
from ..domains.d01.production_operations_v1 import plain_v1, stage_result_v1
from ..domains.d06 import D06DomainProvider, SourceAdmission
from ..graph_types import AtomKey, GraphWrite, Owner, owner_grant_key
from ..memory_types import source_key, access_key
from ..runtime_contracts import CommitReceipt, DomainProposal, NamespaceId, canonical_digest, canonical_serialize
from .budget import settle_budget
from .d01_production_operations_v1 import CurrentDomainReadV1, MissingProductionOriginalV1, production_read_plan_v1
from .d10_offline_tick_execution_v1 import D10OfflineTickPreparedV1, offline_tick_ids_v1, read_prepared_offline_tick_v1, _decode_json
from .d11_offline_originals_v1 import TABLE, SIGN_KIND, WORK_KIND
from .d11_types import D11RuntimeProvider, D11_PROPOSAL_SCHEMA, RuntimeJobValue, job_graph_write, cost_settlement_from_runtime, cost_settlement_graph_write, runtime_cost_settlement_key, runtime_job_key
from .domain_production_contracts_v1 import ProductionOriginalRefV1, StagedDomainOperationV1
from .jobs import get_job, checkpoint_job, transition_job
from .issuers import D11BudgetJobIssuer
from .clock import CharacterClockMapping

_OBSERVED = object()
_OBSERVATIONS = {}


@dataclass(frozen=True, slots=True, init=False, weakref_slot=True)
class _ObservedOfflineTickTerminalV1:
    prepared: D10OfflineTickPreparedV1
    claim: D11OfflineTickClaimV1
    terminal: D11OfflineTickTerminalV1
    port: object
    original: ProductionOriginalRefV1

    def __init__(self, key, port, prepared, claim, terminal):
        if key is not _OBSERVED:
            raise TypeError("offline terminal observation requires actual paired original read")
        original = ProductionOriginalRefV1("d11.offline_tick_terminal", terminal.original_ref, canonical_digest(plain_v1(terminal)))
        for name, value in (("port", port), ("prepared", prepared), ("claim", claim), ("terminal", terminal), ("original", original)):
            object.__setattr__(self, name, value)
        identifier = id(self)
        _OBSERVATIONS[identifier] = (weakref.ref(self, lambda _: _OBSERVATIONS.pop(identifier, None)),
            port, prepared.digest, canonical_digest(plain_v1(claim)), original)


def require_observed_offline_tick_terminal_v1(observation):
    from ..host.v2_fence_port import V2FencePort
    registered = _OBSERVATIONS.get(id(observation))
    if (type(observation) is not _ObservedOfflineTickTerminalV1 or registered is None or registered[0]() is not observation
            or type(observation.port) is not V2FencePort or registered[1] is not observation.port
            or registered[2:] != (observation.prepared.digest, canonical_digest(plain_v1(observation.claim)), observation.original)
            or observation.original.original_digest != canonical_digest(plain_v1(observation.terminal))
            or observation.terminal.claim != observation.claim or observation.terminal.binding != observation.prepared.binding
            or observation.terminal.payload.prepared_digest != observation.prepared.digest):
        raise ValueError("actual paired offline terminal observation is copied or altered")
    return observation


def observe_current_offline_tick_terminal_v1(port, prepared):
    from ..host.v2_fence_port import V2FencePort
    if type(port) is not V2FencePort or type(prepared) is not D10OfflineTickPreparedV1 or prepared.requirements_json is None:
        raise TypeError("offline terminal needs installed paired port and actual post-CAS preparation")
    claim, terminal = port.read_d11_offline_tick_original_v1(binding=prepared.binding)
    if claim is None:
        raise MissingProductionOriginalV1("actual_independent_offline_tick_once_claim")
    if type(claim) is not D11OfflineTickClaimV1 or claim.binding != prepared.binding or claim.payload.prepared_digest != prepared.digest:
        raise ValueError("paired offline claim differs from actual frozen preparation")
    if terminal is None:
        raise MissingProductionOriginalV1("actual_independent_offline_tick_terminal_after_claim")
    if (type(terminal) is not D11OfflineTickTerminalV1 or terminal.claim != claim
            or terminal.binding != prepared.binding or terminal.payload.prepared_digest != prepared.digest):
        raise ValueError("paired offline terminal does not join actual original preparation/claim")
    if terminal.result is not None:
        mapping = _decode_json(prepared.clock_mapping_json, CharacterClockMapping)
        result = terminal.result
        context = Context(prec=28, rounding=ROUND_HALF_EVEN, Emin=-999999, Emax=999999,
            capitals=1, clamp=0, traps=[InvalidOperation, DivisionByZero, Overflow])
        with localcontext(context):
            expected_character_at = str(mapping.character_at(result.scheduled_at_utc))
        if ((result.clock_mapping_ref, result.clock_mapping_version) != (mapping.mapping_id, mapping.version)
                or result.character_at != expected_character_at):
            raise ValueError("actual independent tick result differs from exact signed clock arithmetic")
    return _ObservedOfflineTickTerminalV1(_OBSERVED, port, prepared, claim, terminal)


@dataclass(frozen=True, slots=True)
class AdoptCurrentOfflineTickRequestV1:
    prepared_original_ref: str


class InstalledD10OfflineTerminalReadersV1:
    def __init__(self, *, issuer, observation):
        if type(issuer) is not D11BudgetJobIssuer or type(observation) is not _ObservedOfflineTickTerminalV1:
            raise TypeError("installed offline consumer requires real paired terminal observation")
        self.issuer, self.observation = issuer, observation
        require_observed_offline_tick_terminal_v1(observation)


@dataclass(frozen=True, slots=True)
class OfflineTickTerminalBundleV1:
    envelope: object
    memory_stage: StagedDomainOperationV1
    runtime_stage: StagedDomainOperationV1
    terminal: D11OfflineTickTerminalV1
    prepared: D10OfflineTickPreparedV1
    source_refs: tuple[str, ...]
    member_domains: tuple[str, ...] = ("d06", "d11")
    bundle_kind: str = "d11.actual-offline-tick-cost-and-simulated-source.v1"


def offline_tick_adoption_operation_id_v1(binding):
    return "d11-offline-tick-adopt:" + canonical_digest((binding.namespace, binding.execution_id, binding.digest))[:48]


def read_plan_current_offline_tick_terminal_v1(db, *, namespace, activity_id, operation_kind, request):
    if operation_kind != "adopt_offline_tick" or type(request) is not AdoptCurrentOfflineTickRequestV1:
        raise TypeError("exact registered offline tick adoption request required")
    keys, originals = [owner_grant_key(*namespace.as_tuple)], [request.prepared_original_ref]
    row = db.execute("SELECT payload_json FROM " + TABLE + " WHERE bot=? AND persona=? AND kind='prepared_tick' AND original_ref=?",
        (*namespace.as_tuple, request.prepared_original_ref)).fetchone()
    if row:
        raw = json.loads(row[0])
        binding = raw["binding"]
        if binding["activity_id"] != activity_id:
            raise ValueError("offline adoption must retain actual original activity")
        ids = offline_tick_ids_v1(namespace, binding["schedule_ref"], binding["scheduled_at_utc"])
        keys += [AtomKey(Owner("activity", *namespace.as_tuple, activity_id), "runtime.job", binding["job_id"]),
            runtime_cost_settlement_key(*namespace.as_tuple, activity_id, ids["reservation"]),
            source_key(*namespace.as_tuple, ids["source"]), access_key(*namespace.as_tuple, ids["source"])]
    return production_read_plan_v1((), keys, (), originals)


def stage_current_offline_tick_terminal_in_transaction_v1(db, *, frame, request, installed_readers):
    if type(installed_readers) is not InstalledD10OfflineTerminalReadersV1:
        raise TypeError("offline adoption needs its exact installed observed-original reader")
    read = CurrentDomainReadV1(frame)
    read.check(db)
    observation = require_observed_offline_tick_terminal_v1(installed_readers.observation)
    prepared = read_prepared_offline_tick_v1(db, namespace=frame.envelope.authority.namespace,
        prepared_original_ref=request.prepared_original_ref, issuer=installed_readers.issuer)
    if prepared is None or prepared != observation.prepared:
        raise ValueError("offline actual prepared row differs from authenticated terminal binding")
    terminal, binding = observation.terminal, prepared.binding
    read.original(observation.original.original_ref, kind=observation.original.kind, digest=observation.original.original_digest)
    if (frame.envelope.identity.operation_id != offline_tick_adoption_operation_id_v1(binding)
            or frame.envelope.identity.activity_id != binding.activity_id
            or frame.owner_guard.grant_ref != binding.owner_grant_ref
            or frame.owner_guard.grant_revision != binding.owner_grant_revision
            or frame.owner_guard.grant_digest != binding.owner_grant_digest
            or frame.activation_generation != binding.activation_generation
            or frame.envelope.parent_budget_lease_ref != binding.parent_budget_lease_ref):
        raise ValueError("offline adoption current Owner/activity/budget changed")
    ids = offline_tick_ids_v1(binding.namespace, binding.schedule_ref, binding.scheduled_at_utc)
    job = get_job(db, binding.job_id)
    job_atom = read.head(db, job_graph_write(job).key, required=True)
    original_job = _decode_json(prepared.job_projection_json, RuntimeJobValue)
    if job_atom.revision != prepared.job_projection_revision or job_atom.value != plain_v1(original_job):
        raise ValueError("offline consumer original running job projection changed")
    if (job.operation_id, job.activity_id, job.work_kind, job.fence, job.cancel_epoch) != (
            binding.operation_id, binding.activity_id, WORK_KIND, binding.job_fence, binding.job_cancel_epoch):
        raise ValueError("offline consumer actual durable job differs from original claim")
    actual = None if terminal.status == "unknown" else {"thread_cpu_ms": terminal.actual_cpu_ms}
    budget_receipt = settle_budget(db, binding.parent_budget_lease_ref, binding.reservation_operation_id,
        binding.reservation_digest, actual, execution_revoked=True)
    if job.phase == "running":
        if (job.lease_holder, job.lease_expires_utc) != (binding.job_holder, binding.job_lease_expires_utc):
            raise ValueError("offline actual worker lease differs from independently claimed lease")
        if actual is not None:
            job = checkpoint_job(db, job.job_id, binding.job_holder, binding.job_fence,
                continuation=job.continuation, usage=actual)
        job = transition_job(db, job.job_id, binding.job_holder, binding.job_fence,
            target_phase="completed" if terminal.status == "completed" else "failed" if terminal.status == "failed" else "pending_confirmation",
            result_ref=ids["result"] if terminal.status == "completed" else None)
    elif (job.phase != ("completed" if terminal.status == "completed" else "failed" if terminal.status == "failed" else "pending_confirmation")
            or job.result_ref != (ids["result"] if terminal.status == "completed" else None)
            or dict(job.usage) != (actual or {})):
        raise ValueError("offline compiler replay does not match exact terminal job disposition")
    cost = cost_settlement_from_runtime(db, bot_id=binding.namespace.bot_id, persona_id=binding.namespace.persona_id,
        activity_id=binding.activity_id, bundle_operation_id=frame.envelope.identity.operation_id, effect_id=None,
        settlement_id=ids["reservation"], lease_id=binding.parent_budget_lease_ref,
        cost_operation_id=binding.reservation_operation_id, budget_operation_id=binding.reservation_operation_id,
        budget_phase="settle", prior_unknown_ref=None, execution_revoked=True)
    runtime_writes = (job_graph_write(job), cost_settlement_graph_write(cost))
    source_refs, writes = (), ()
    if terminal.status == "completed":
        owner = read.head(db, owner_grant_key(*binding.namespace.as_tuple), required=True)
        purposes = tuple(sorted(set(prepared.schedule.purposes) & set(owner.value["purposes"])))
        audience = tuple(frame.envelope.authority.audience)
        if audience != prepared.schedule.audiences or not set(audience) <= set(owner.value["audiences"]) or not purposes:
            raise ValueError("offline new simulated source cannot widen actual schedule/Owner rights")
        result = terminal.result
        admission = SourceAdmission(ids["source"], canonical_serialize(plain_v1(result)), "persona:" + binding.namespace.persona_id,
            "simulated", "simulated", "none", "committed", datetime.fromisoformat(result.scheduled_at_utc.replace('Z','+00:00')).timestamp(),
            frame.now_utc, "offline-schedule:" + binding.schedule_ref, audience, purposes)
        from .d10_production_operations_v1 import _memory_experience_proposal_v1
        memory_proposal, source_refs, _ = _memory_experience_proposal_v1(frame, (admission,))
        writes = memory_proposal.typed_writes
    memory = stage_result_v1(frame, "d06", "adopt_offline_tick", request, writes=writes,
        provenance={"prepared_original": ProductionOriginalRefV1("d11.prepared_offline_tick", binding.prepared_original_ref, prepared.digest),
            "actual_terminal": terminal, "source_refs": source_refs, "terminal_status": terminal.status},
        proposal_schema="d06.contract.v1", proposal_hash=D06DomainProvider().descriptor.request_schema_hash)
    runtime = stage_result_v1(frame, "d11", "adopt_offline_tick", request, writes=runtime_writes,
        provenance={"actual_terminal": terminal, "actual_cost": cost, "actual_job": job},
        proposal_schema=D11_PROPOSAL_SCHEMA, proposal_hash=D11RuntimeProvider().descriptor.request_schema_hash)
    return OfflineTickTerminalBundleV1(frame.envelope, memory, runtime, terminal, prepared, source_refs)


@dataclass(frozen=True, slots=True)
class AdoptedOfflineTickOriginalV1:
    namespace: NamespaceId
    result_ref: str
    producing_operation_id: str
    prepared_original_ref: str
    prepared_digest: str
    terminal: D11OfflineTickTerminalV1
    cost_ref: str
    source_refs: tuple[str, ...]
    graph_receipt_json: str
    schema: str = "d11.actual-adopted-offline-tick-original.v1"

    def __post_init__(self):
        if (self.schema != "d11.actual-adopted-offline-tick-original.v1" or type(self.namespace) is not NamespaceId
                or type(self.terminal) is not D11OfflineTickTerminalV1 or self.terminal.binding.namespace != self.namespace
                or self.producing_operation_id != offline_tick_adoption_operation_id_v1(self.terminal.binding)
                or self.prepared_original_ref != self.terminal.binding.prepared_original_ref
                or self.prepared_digest != self.terminal.payload.prepared_digest
                or len(self.source_refs) != (1 if self.terminal.status == "completed" else 0)):
            raise ValueError("offline adopted original lost its exact actual causal identity")
        receipt = _decode_json(self.graph_receipt_json, CommitReceipt)
        if (receipt.status != "committed" or receipt.operation_id != self.producing_operation_id
                or receipt.activity_id != self.terminal.binding.activity_id):
            raise ValueError("offline actual adopted original needs its same W01 receipt")
        ids = offline_tick_ids_v1(self.namespace, self.terminal.binding.schedule_ref, self.terminal.binding.scheduled_at_utc)
        if (self.result_ref != ids["result"] or self.cost_ref != runtime_cost_settlement_key(*self.namespace.as_tuple,
                self.terminal.binding.activity_id, ids["reservation"]).token
                or self.source_refs != ((source_key(*self.namespace.as_tuple, ids["source"]).token,) if self.terminal.status == "completed" else ())):
            raise ValueError("offline adopted source/cost/result keys differ from original occurrence")


def record_offline_tick_terminal_after_cas_v1(db, *, issuer, staged, graph_receipt):
    if type(staged) is not OfflineTickTerminalBundleV1 or type(graph_receipt) is not CommitReceipt:
        raise TypeError("exact independent offline terminal composite receipt required")
    binding = staged.prepared.binding
    row = db.execute("SELECT digest,commit_seq FROM graph_bundle_operations WHERE bot=? AND persona=? AND operation_id=?",
        (*binding.namespace.as_tuple, graph_receipt.operation_id)).fetchone()
    if row != (graph_receipt.operation_digest, graph_receipt.commit_seq):
        raise ValueError("offline terminal receipt is not its actual W01 bundle")
    versions = {version.key: version.revision for version in graph_receipt.write_versions}
    writes = tuple(write for member in (staged.memory_stage, staged.runtime_stage) for proposal in member.proposals for write in proposal.typed_writes)
    if set(versions) != {write.key for write in writes}:
        raise ValueError("offline terminal adoption contains another actual member set")
    for write in writes:
        actual = db.execute("SELECT event_id,value,valid FROM graph_history WHERE token=? AND revision=?", (write.key.token, versions[write.key])).fetchone()
        if actual != (graph_receipt.operation_id, canonical_serialize(write.value), 1):
            raise ValueError("offline terminal source/job/cost did not adopt as one actual bundle")
    ids = offline_tick_ids_v1(binding.namespace, binding.schedule_ref, binding.scheduled_at_utc)
    value = AdoptedOfflineTickOriginalV1(binding.namespace, ids["result"], graph_receipt.operation_id,
        binding.prepared_original_ref, staged.prepared.digest, staged.terminal,
        runtime_cost_settlement_key(*binding.namespace.as_tuple, binding.activity_id, ids["reservation"]).token,
        staged.source_refs, canonical_serialize(plain_v1(graph_receipt)))
    wire, digest = canonical_serialize(plain_v1(value)), canonical_digest(plain_v1(value))
    signature = issuer._signer.sign(SIGN_KIND, canonical_serialize((binding.namespace, "adopted_tick", value.result_ref, digest)))
    expected = (value.producing_operation_id, wire, digest, signature)
    prior = db.execute("SELECT producing_operation_id,payload_json,payload_digest,signature FROM " + TABLE +
        " WHERE bot=? AND persona=? AND kind='adopted_tick' AND original_ref=?", (*binding.namespace.as_tuple, value.result_ref)).fetchone()
    if prior is not None and prior != expected:
        raise ValueError("offline actual terminal adoption original replay changed")
    if prior is None:
        db.execute("INSERT INTO " + TABLE + " VALUES(?,?,?,?,?,?,?,?)", (*binding.namespace.as_tuple, "adopted_tick", value.result_ref, *expected))
    return ProductionOriginalRefV1("d11.completed_offline_tick" if staged.terminal.status == "completed" else "d11.offline_tick_accounting",
        value.result_ref, digest)


def read_adopted_offline_tick_original_v1(db, *, namespace, result_ref, issuer):
    row = db.execute("SELECT producing_operation_id,payload_json,payload_digest,signature FROM " + TABLE +
        " WHERE bot=? AND persona=? AND kind='adopted_tick' AND original_ref=?", (*namespace.as_tuple, result_ref)).fetchone()
    if row is None:
        return None
    value = _decode_json(row[1], AdoptedOfflineTickOriginalV1)
    digest = canonical_digest(plain_v1(value))
    issuer._signer.verify(SIGN_KIND, canonical_serialize((namespace, "adopted_tick", result_ref, digest)), row[3])
    if value.namespace != namespace or value.result_ref != result_ref or row[:1] != (value.producing_operation_id,) or digest != row[2]:
        raise ValueError("offline actual adopted original identity/content differs")
    validate_adopted_offline_tick_history_v1(db, value)
    return value


def validate_adopted_offline_tick_history_v1(db, value):
    """Exact immutable job/source/cost membership, independent of current job."""
    namespace, result_ref = value.namespace, value.result_ref
    receipt = _decode_json(value.graph_receipt_json, CommitReceipt)
    actual = db.execute("SELECT digest,commit_seq FROM graph_bundle_operations WHERE bot=? AND persona=? AND operation_id=?",
        (*namespace.as_tuple, value.producing_operation_id)).fetchone()
    if actual != (receipt.operation_digest, receipt.commit_seq):
        raise ValueError("offline adopted original lost its actual W01 bundle")
    refs = {version.key.token: version for version in receipt.write_versions}
    binding = value.terminal.binding
    job_ref = runtime_job_key(*namespace.as_tuple, binding.activity_id, binding.job_id).token
    required = {job_ref, value.cost_ref, *value.source_refs}
    if not required <= set(refs):
        raise ValueError("offline adopted source/job/cost is not in its actual composite receipt")
    for ref in required:
        history = db.execute("SELECT event_id,valid FROM graph_history WHERE token=? AND revision=?", (ref, refs[ref].revision)).fetchone()
        if history != (value.producing_operation_id, 1):
            raise ValueError("offline adopted original lost its actual member history")
    job_row = db.execute("SELECT value FROM graph_history WHERE token=? AND revision=?",
        (job_ref, refs[job_ref].revision)).fetchone()
    job = _decode_json(job_row[0], RuntimeJobValue)
    actual = {} if value.terminal.status == "unknown" else {"thread_cpu_ms": value.terminal.actual_cpu_ms}
    if ((job.bot_id, job.persona_id, job.activity_id, job.operation_id, job.job_id, job.work_kind,
            job.fence, job.cancel_epoch, job.parent_budget_lease_ref, job.lease_holder, job.lease_expires_utc)
            != (*namespace.as_tuple, binding.activity_id, binding.operation_id, binding.job_id, WORK_KIND,
                binding.job_fence, binding.job_cancel_epoch, binding.parent_budget_lease_ref, None, None)
            or job.phase != ("completed" if value.terminal.status == "completed" else "failed" if value.terminal.status == "failed" else "pending_confirmation")
            or job.result_ref != (result_ref if value.terminal.status == "completed" else None)
            or job.usage_digest != canonical_digest(actual)):
        raise ValueError("offline adopted historical job identity/result/usage differs from its terminal")
    return value
