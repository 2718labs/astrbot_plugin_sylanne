"""Installed D07 graph/job original reader and bounded host scheduler adapter.

Create per Owner-fenced operation with W01's CurrentOperationFrameV1. The
credential-owning execution_reader is installed at host startup and reads the
real Authority terminal before a graph transaction; it is never a command arg.
"""
from __future__ import annotations

from datetime import datetime, timezone
import json

from ..domains.d07 import AttentionPolicy, AttentionTicket, D07DomainProvider, SimulationRequest
from ..domains.d07.concern_round import ConcernServiceChoiceV1
from ..graph_types import AtomKey, GraphAtom, GraphSnapshot, GraphVersion, NamespaceEpoch
from ..runtime_contracts import canonical_digest, canonical_serialize
from ..runtime.budget import get_budget_lease
from ..runtime.domain_production_contracts_v1 import (
    CurrentOperationFrameV1, ProductionOriginalRefV1, ProductionOutboxStageV1,
    StagedDomainOperationV1,
)
from ..runtime.d07_current_behavior_v1 import (
    D07ConcernInputsV1, D07ExecutionOriginalV1, D07ReflectionInputsV1,
    D07SimulationInputsV1, _json,
)
from ..runtime.d11_types import cost_settlement_from_runtime, graph_type_specs
from ..runtime.jobs import PersistentJob, create_job, get_job


class InstalledD07BehaviorPortV1:
    """Concrete current DB reader; execution transport remains an installed port.

    execution_reader.read_verified_terminal(ref) returns a D07ExecutionOriginalV1
    from authenticated prepared/Authority result/time/cost originals. It must
    perform RPC outside W01's transaction, cache that verified original for this
    one frame, and verify_prepared_terminal(...) rechecks its exact identity.
    D11's production handler executes jobs via that same installed service.
    """

    def __init__(self, frame: CurrentOperationFrameV1, *, policy: AttentionPolicy,
                 execution_reader, installed_executor_ref: str):
        if (type(frame) is not CurrentOperationFrameV1 or type(policy) is not AttentionPolicy
                or not installed_executor_ref or execution_reader is None):
            raise ValueError("installed D07 current frame/policy/execution service required")
        self.frame, self.policy = frame, policy
        self.execution_reader, self.installed_executor_ref = execution_reader, installed_executor_ref

    def _snapshot(self, db, envelope) -> GraphSnapshot:
        if not db.in_transaction or envelope != self.frame.envelope:
            raise ValueError("D07 installed reader must run in its bound W01 transaction")
        ns = envelope.authority.namespace
        epochs = db.execute("SELECT revision FROM graph_epochs WHERE bot=? AND persona=?", ns.as_tuple).fetchone()
        rights = db.execute("SELECT access_epoch,delete_epoch FROM graph_authority_epochs "
            "WHERE bot=? AND persona=?", ns.as_tuple).fetchone()
        if rights != (envelope.version_guard.access_epoch, envelope.version_guard.delete_epoch):
            raise ValueError("D07 current source rights changed")
        atoms = []
        for original in self.frame.snapshot.atoms:
            row = db.execute("SELECT revision,value,valid FROM graph_atoms "
                "WHERE token=? AND bot=? AND persona=?", (original.key.token, *ns.as_tuple)).fetchone()
            atom = GraphAtom(original.key, row[0], json.loads(row[1]), bool(row[2])) if row else GraphAtom(original.key, 0, {}, False)
            if atom != original:
                raise ValueError("D07 current graph head differs from original frame")
            atoms.append(atom)
        snapshot = GraphSnapshot(tuple(atoms), (NamespaceEpoch(*ns.as_tuple, epochs[0] if epochs else 0),))
        if snapshot.epochs != self.frame.snapshot.epochs:
            raise ValueError("D07 current graph query epoch changed")
        return snapshot

    def _original(self, ref: str):
        matches = [original for original in self.frame.observed_originals if original.original_ref == ref]
        if len(matches) != 1:
            raise ValueError("D07 command lacks one independently read original: " + ref)
        return matches[0]

    def _job(self, db, envelope):
        rows = db.execute("SELECT job_id FROM runtime_jobs WHERE bot_id=? AND persona_id=? "
            "AND activity_id=? AND work_kind LIKE 'd07.%' ORDER BY job_id LIMIT 17",
            (*envelope.authority.namespace.as_tuple, envelope.identity.activity_id)).fetchall()
        if len(rows) > 16:
            raise ValueError("D07 activity job inventory exceeds bounded production limit")
        jobs = tuple(get_job(db, row[0]) for row in rows)
        active = [job for job in jobs if job.phase not in {"cancelled", "failed"}]
        if len(active) > 1:
            raise ValueError("D07 activity has conflicting execution originals")
        return active[0] if active else None

    def _execution(self, ref, db, envelope):
        self._original(ref)
        execution = self.execution_reader.read_verified_terminal(ref)
        if type(execution) is not D07ExecutionOriginalV1:
            raise ValueError("D07 installed terminal reader returned no typed actual result")
        self.verify_execution(db, envelope, execution, execution.input_digest)
        return execution

    def read_concern(self, db, envelope, request) -> D07ConcernInputsV1:
        snapshot = self._snapshot(db, envelope)
        self._original(request.trigger_original_ref)
        ns = envelope.authority.namespace
        rows = db.execute("SELECT token,revision FROM graph_atoms WHERE bot=? AND persona=? "
            "AND type_name='d07.attention_ticket.v1' ORDER BY token LIMIT 129", ns.as_tuple).fetchall()
        if len(rows) > 128:
            raise ValueError("D07 ticket inventory needs bounded continuation, not truncated fairness")
        coverage = [page for page in self.frame.query_coverage if page.type_id == 'd07.attention_ticket.v1']
        observed = tuple(GraphVersion(AtomKey.from_token(ref), rev) for ref, rev in rows)
        if (len(coverage) != 1 or not coverage[0].complete
                or tuple(coverage[0].row_versions) != observed):
            raise ValueError("D07 complete current ticket inventory coverage is missing")
        tickets, issuances = [], []
        for ref, rev in rows:
            atom = snapshot.get(AtomKey.from_token(ref))
            if atom is None or atom.revision != rev:
                raise ValueError("D07 ticket inventory absent from current frame")
            if not atom.valid:
                continue
            value = atom.value
            next(spec for spec in D07DomainProvider.type_specs() if spec.name == atom.key.type_name).validator(value)
            ticket = AttentionTicket(**{**{k: v for k, v in value.items() if k != "schema"},
                "cancel_refs": tuple(value["cancel_refs"]), "source_refs": tuple(value["source_refs"])})
            rows_issuance = db.execute("SELECT operation_id,c02_operation_id,bundle_digest FROM graph_d07_attention_issuance_v1 "
                "WHERE bot=? AND persona=? AND source_ref=?", (*ns.as_tuple, ticket.causal_root)).fetchall()
            from .post_c02_attention_driver import post_c02_attention_operation_id
            qualified = [(op, parent, digest) for op, parent, digest in rows_issuance if ticket.ticket_id ==
                "attention:" + canonical_digest({"operation_id": op})[:48]
                and op == post_c02_attention_operation_id(parent, ticket.causal_root)]
            if len(qualified) != 1:
                raise ValueError("D07 attention lacks its original adopted issuer record")
            op, _, bundle_digest = qualified[0]
            adopted = db.execute("SELECT receipt_json,digest FROM graph_bundle_operations "
                "WHERE bot=? AND persona=? AND operation_id=?", (*ns.as_tuple, op)).fetchone()
            if adopted is None or adopted[1] != bundle_digest:
                raise ValueError("D07 attention issuance was not adopted")
            tickets.append(ticket)
            issuances.append("d07-attention:" + op)
        focus = next((atom for atom in snapshot.atoms if atom.key.type_name == "d07.focus.v1" and atom.valid), None)
        if focus is None:
            raise ValueError("D07 current focus original is missing")
        job = self._job(db, envelope)
        execution = self._execution(job.result_ref, db, envelope) if job and job.result_ref else None
        choice = None
        if job and "choice" in job.continuation and job.continuation["choice"] is not None:
            choice = ConcernServiceChoiceV1(**job.continuation["choice"])
        effects = db.execute("SELECT effect_id FROM graph_bundle_operations WHERE bot=? AND persona=? "
            "AND activity_id=? AND effect_id IS NOT NULL LIMIT 129", (*ns.as_tuple, envelope.identity.activity_id)).fetchall()
        if len(effects) > 128:
            raise ValueError("D07 activity effect reconciliation exceeds bound")
        return D07ConcernInputsV1(snapshot, tuple(tickets), self.policy, tuple(issuances),
            request.trigger_original_ref, self.frame.now_utc, focus.value["focus_epoch"],
            execution, choice, tuple(sorted({row[0] for row in effects})))

    def read_reflection(self, db, envelope, request) -> D07ReflectionInputsV1:
        snapshot = self._snapshot(db, envelope)
        execution = self._execution(request.cognitive_terminal_ref, db, envelope)
        job = self._job(db, envelope)
        if job is None or job.result_ref != request.cognitive_terminal_ref:
            raise ValueError("reflection needs the original completed cognition job")
        continuation = job.continuation
        for name in ("cognition_adoption_receipt_ref", "causal_root_ref", "causal_depth_original_ref"):
            self._original(continuation[name])
        if continuation["causal_depth"] != execution.causal_depth:
            raise ValueError("reflection causal-root depth original differs")
        return D07ReflectionInputsV1(snapshot, execution, continuation["cognition_adoption_receipt_ref"],
            continuation["causal_root_ref"], continuation["causal_depth_original_ref"])

    def read_simulation(self, db, envelope, request) -> D07SimulationInputsV1:
        snapshot = self._snapshot(db, envelope)
        request_original = self._original(request.simulation_request_ref)
        self._original(request.trigger_original_ref)
        job = self._job(db, envelope)
        if job is None:
            # The installed preparation/original service owns registered request
            # bytes. A request locator is not permission to accept a caller DTO.
            registered = self.execution_reader.read_registered_simulation_request(request.simulation_request_ref)
            if type(registered) is not SimulationRequest:
                raise ValueError("simulation registered original service returned no typed request")
            budget_ref = envelope.parent_budget_lease_ref
            budget_original = self._original(budget_ref)
            if budget_original.kind != "d11.dedicated-simulation-budget":
                raise ValueError("simulation budget lacks its dedicated preparation original")
            dedicated_original_ref = budget_original.original_ref
        else:
            if job.continuation.get("simulation_request_ref") != request.simulation_request_ref:
                raise ValueError("simulation current execution job belongs to another registered request")
            value = job.continuation["registered_request"]
            registered = SimulationRequest(**{**value, "snapshot_refs": tuple(value["snapshot_refs"]),
                "alternatives": tuple(value["alternatives"]), "predictions": tuple(tuple(p) for p in value["predictions"]),
                "unknowns": tuple(value["unknowns"])})
            budget_ref = job.budget_ref
            dedicated_original_ref = job.continuation["dedicated_budget_original_ref"]
        if request_original.original_digest != canonical_digest(registered):
            raise ValueError("simulation registered original digest differs from durable job")
        lease = get_budget_lease(db, budget_ref)
        if (lease.parent_id is None or lease.state != "active"
                or (lease.bot_id, lease.persona_id) != envelope.authority.namespace.as_tuple):
            raise ValueError("simulation requires an active dedicated child budget lease")
        self._original(dedicated_original_ref)
        execution = self._execution(job.result_ref, db, envelope) if job and job.result_ref else None
        return D07SimulationInputsV1(snapshot, registered, canonical_digest(registered),
            request.trigger_original_ref, budget_ref, dedicated_original_ref, execution)

    def verify_execution(self, db, envelope, execution, input_digest) -> None:
        if execution.input_digest != input_digest:
            raise ValueError("D07 terminal does not match frozen prepared input")
        self.execution_reader.verify_prepared_terminal(execution, self.frame)
        job = self._job(db, envelope)
        if (job is None or job.result_ref != execution.terminal_ref
                or job.activity_id != execution.activity_id or job.budget_ref != execution.parent_budget_ref
                or job.cancel_epoch != 0 or job.phase not in {"running", "completed", "waiting"}
                or job.continuation.get("input_digest") != execution.input_digest):
            raise ValueError("D07 terminal differs from original durable execution job")
        for ref in execution.cost_receipt_refs:
            key = AtomKey.from_token(ref)
            if key.type_name != "runtime.cost_settlement":
                raise ValueError("D07 actual computation requires D11 cost settlement originals")
            row = db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=? AND bot=? AND persona=?",
                (ref, *envelope.authority.namespace.as_tuple)).fetchone()
            if row is None or row[0] < 1 or row[2] != 1:
                raise ValueError("D07 actual cost settlement is missing")
            value = json.loads(row[1])
            next(spec for spec in graph_type_specs() if spec.name == key.type_name).validator(value)
            if value["lease_id"] != execution.parent_budget_ref or value["status"] != "settled":
                raise ValueError("D07 actual cost settlement is unconfirmed or belongs to another budget")
            current_cost = cost_settlement_from_runtime(db, **{name: value[name] for name in (
                "bot_id", "persona_id", "activity_id", "bundle_operation_id", "effect_id",
                "settlement_id", "lease_id", "cost_operation_id", "budget_operation_id",
                "budget_phase", "prior_unknown_ref", "execution_revoked")})
            if _json(current_cost) != value:
                raise ValueError("D07 cost atom differs from independently settled D11 original")

    def _followup(self, stage, original_ref):
        envelope = stage.envelope
        ns = envelope.authority.namespace
        original = ProductionOriginalRefV1("d07.current-behavior", original_ref, stage.stage_digest, stage.read_versions)
        outbox = (ProductionOutboxStageV1(ns, envelope.identity.operation_id, "d07",
            "d07." + stage.work_kind + "." + stage.status, original),)
        jobs = ()
        if stage.status == "queued":
            if not envelope.version_guard.resource_lease_versions:
                raise ValueError("D07 queued cognitive work requires an actual admitted role resource lease")
            job_id = "d07-job:" + canonical_digest((ns, envelope.identity.operation_id, stage.work_kind))[:48]
            deadline = datetime.fromtimestamp(envelope.deadline_utc, timezone.utc).isoformat().replace("+00:00", "Z")
            continuation = {"request": _json(stage.request), "input_digest": stage.input_digest,
                "choice": _json(stage.provenance.get("choice")), "original_ref": original_ref}
            if stage.work_kind == "simulation":
                continuation.update({"simulation_request_ref": stage.request.simulation_request_ref,
                    "registered_request": _json(stage.provenance["request"]),
                    "dedicated_budget_original_ref": stage.provenance["dedicated_budget_original"]})
            jobs = (PersistentJob(job_id, envelope.identity.operation_id, envelope.identity.activity_id,
                envelope.identity.effect_id, *ns.as_tuple, original_ref, "queued", "d07." + stage.work_kind,
                continuation, None, deadline, envelope.parent_budget_lease_ref,
                envelope.version_guard.resource_lease_versions[0].ref,
                {"executor": self.installed_executor_ref, "policy": self.policy.policy_version},
                None, None, 0, 0, {}, None),)
        return jobs, outbox

    def as_staged_domain_operation(self, stage, original_ref) -> StagedDomainOperationV1:
        from ..runtime.d07_behavior_stage_codec_v1 import build_d07_staged_behavior_operation_v1
        return build_d07_staged_behavior_operation_v1(self.frame, stage)

    def stage_job_outbox(self, db, stage, original_ref) -> None:
        # W01 must have staged its canonical bundle operation row first in the
        # same transaction (graph adoption may follow). FKs prevent orphan jobs.
        envelope, ns = stage.envelope, stage.envelope.authority.namespace
        if db.execute("SELECT 1 FROM graph_bundle_operations WHERE bot=? AND persona=? AND operation_id=?",
                (*ns.as_tuple, envelope.identity.operation_id)).fetchone() is None:
            raise ValueError("D07 same-transaction W01 bundle operation original is missing")
        jobs, outbox = self._followup(stage, original_ref)
        for job in jobs:
            create_job(db, job, envelope.identity.operation_id, canonical_digest(job))
        for event in outbox:
            ref = "d07-outbox:" + event.dedupe_key[:48]
            db.execute("INSERT INTO graph_bundle_outbox VALUES (?,?,?,?,?)",
                (*ns.as_tuple, ref, envelope.identity.operation_id, "pending"))
            for job in jobs:
                db.execute("INSERT INTO graph_outbox_jobs VALUES (?,?,?,?,?)",
                    (*ns.as_tuple, ref, job.job_id, envelope.identity.operation_id))


class InstalledD07BehaviorJobHandlerV1:
    """Startup registry handler: one actual bounded executor call per claim."""
    work_kinds = ("d07.concern", "d07.reflection", "d07.simulation")

    def __init__(self, installed_execution_service):
        self.execution_service = installed_execution_service

    def execute(self, job: PersistentJob):
        if (type(job) is not PersistentJob or job.work_kind not in self.work_kinds
                or job.phase != "running" or job.cancel_epoch != 0 or job.fence < 1
                or not job.lease_holder):
            raise ValueError("D07 scheduler requires an actual current durable job claim")
        # Installed service owns D11 call admission, Authority terminal and
        # durable outcome/cost. Returning a proposal cannot claim success.
        return self.execution_service.execute_current_d07_job_v1(job)


__all__ = ["InstalledD07BehaviorPortV1", "InstalledD07BehaviorJobHandlerV1"]
