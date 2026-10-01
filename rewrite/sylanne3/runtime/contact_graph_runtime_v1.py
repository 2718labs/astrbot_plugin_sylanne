"""Installed contact stages on the real W01 store, Owner and Authority fences.

The stage dispatch is fixed. Durable attempt/permit/receipt originals share the
Graph originals table; they never introduce another budget or execution store.
"""
from contextlib import nullcontext
from dataclasses import dataclass, asdict
from datetime import datetime
import json
import time

from ..contracts import Event, Scope, StaleRead
from ..graph_store import ProductionGraphStore, GraphStore
from ..graph_types import GraphCandidate, GraphVersion, NamespaceEpoch, AtomKey
from ..runtime_contracts import (AuthorityContext, CommandEnvelope, OperationIdentity, VersionGuard,
    VersionedRef, QueryEpoch, SourceQualification, RUNTIME_SCHEMA, FenceScope, canonical_digest, canonical_serialize)
from ..authority_service.v2_contract import to_wire as permit_wire, from_wire as permit_unwire
from ..authority_service.v2_model_egress_contract import ModelEgressIntentV1
from ..authority_service.v2_model_egress_wire import from_wire as model_unwire
from ..domains.d01.production_operations_v1 import plain_v1
from ..host.authority_profile import AdminInstallationBundle
from .contact_paid_original_v1 import record_contact_original_v1, require_contact_original_v1, read_contact_original_v1
from .contact_plan_adoption_v1 import read_adopted_contact_plan_v1, require_contact_inventory_current_v1
from .contact_model_job_v1 import contact_model_ids_v1, read_contact_prepared_v1
from .contact_model_preparation_v1 import (acquire_contact_model_in_transaction_v1, seal_contact_call_in_transaction_v1,
    prepare_contact_result_read_in_transaction_v1, contact_model_draft_v1, import_contact_result_in_transaction_v1,
    read_paid_contact_result_v1, read_paid_contact_batch_v1)
from .d11_types import job_graph_write, reconcile_runtime_write
from .jobs import get_job
from .first_ingress_v2 import trusted_upper
from .restore_anchor import RestoreAnchor
from .model_cost_settlement import (read_original_model_cost, OriginalModelCostCommitV1, original_model_budget_measurement)


@dataclass(frozen=True, slots=True)
class _ContactStageWitnessV1:
    service: object
    scope: FenceScope
    owner: object
    prepared: object
    phase: str
    operation_id: str
    now: float


_ACTIVE = {}


class InstalledContactModelGraphRuntimeV1:
    def __init__(self, *, graph, bootstrap, bundle):
        graph._admin(bootstrap)
        store = graph._GraphCoordinator__store
        port = graph._GraphCoordinator__content_fence_v2
        assembly = graph._GraphCoordinator__d04_installed_joint_assembly
        if (not isinstance(store, ProductionGraphStore) or type(bundle) is not AdminInstallationBundle
                or port is None or assembly is None or assembly.admin_bundle is not bundle
                or graph._GraphCoordinator__model_terminal_cost_port is None):
            raise ValueError("contact stages require actual installed W01/Authority/model accounting")
        self.graph, self.bootstrap, self.bundle = graph, bootstrap, bundle
        self.store, self.port, self.issuer = store, port, graph._GraphCoordinator__d11_issuer
        self.resource_issuer = graph._GraphCoordinator__d02_issuer
        self._results = {}
        self._cost_facts, self._actual_cost_commits = {}, {}

    def _current(self):
        self.graph._admin(self.bootstrap)
        if self.graph._GraphCoordinator__contact_model_runtime_v1 is not self:
            raise ValueError("contact fixed runtime is not the installed W01 producer")

    def _original(self, db, contact_id, phase):
        ns = self.bundle.installation_policy.namespace
        plan, expression, raw, _ = read_adopted_contact_plan_v1(db, namespace=ns, contact_id=contact_id, issuer=self.issuer)
        prepared, frozen = read_contact_prepared_v1(db, namespace=ns, job_id=contact_model_ids_v1(plan, phase)["job"], issuer=self.issuer)
        return prepared, frozen, plan, expression, raw

    def _content(self, db, value, now, owner=None):
        from ..authority_service.contact_model_graph_v1 import require_contact_scope_current_v1
        prepared, frozen, plan, expression, raw = value
        require_contact_inventory_current_v1(db, prepared.namespace, raw)
        require_contact_scope_current_v1(db, plan, expression, now=now)
        expected = raw["owner_guard"]
        row = db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=?", (expected["grant_ref"],)).fetchone()
        if (row is None or (row[0], row[2]) != (expected["grant_revision"], 1)
                or canonical_digest(json.loads(row[1])) != expected["grant_digest"]
                or owner is not None and owner.authorization_head.removeprefix("sha256:") != expected["owner_head_digest"]):
            raise ValueError("contact preparation's actual current Owner changed")

    def read_preparation(self, *, contact_id, phase):
        self._current()
        with self.store._lock:
            db = self.store._db
            db.execute("BEGIN")
            try:
                prepared, frozen, *_ = self._original(db, contact_id, phase)
                return prepared, frozen, get_job(db, prepared.job_id)
            finally:
                db.rollback()

    def _attempt(self, value, phase, anchor, metadata, epoch):
        prepared = value[0]
        operation = (prepared.acquire_operation_id if phase == "acquire" else
            "contact-" + phase + ":" + canonical_digest((prepared.namespace, prepared.job_id, phase))[:48])
        digest = canonical_digest(("d10.contact-installed-stage.v1", prepared.digest, phase))
        attempt = "contact-stage-fence:" + canonical_digest((operation, digest))[:48]
        return operation, {"schema": "d10.contact-stage-attempt.v1", "job_id": prepared.job_id,
            "phase": phase, "request_digest": digest, "attempt_id": attempt, "anchor": asdict(anchor),
            "graph_revision": metadata.graph_revision, "graph_epoch": epoch.revision, "prepared_digest": prepared.digest}

    def _write(self, contact_id, model_phase, phase, *, result_attempt=1):
        self._current()
        if phase not in {"acquire", "paid_cost", "result_read", "terminal"}:
            raise ValueError("unregistered installed contact stage")
        graph, ns, policy = self.graph, self.bundle.installation_policy.namespace, self.bundle.installation_policy
        with self.store._lock:
            value = self._original(self.store._db, contact_id, model_phase)
            metadata, epoch = graph._v2_graph_stamp(ns)
            prepared = value[0]
            original_operation = (prepared.acquire_operation_id if phase == "acquire" else
                "contact-" + phase + ":" + canonical_digest((prepared.namespace, prepared.job_id, phase))[:48])
            if phase == "result_read":
                original_operation += ":" + str(result_attempt)
            replay_attempt = read_contact_original_v1(self.store._db, self.issuer, ns, "stage_attempt", original_operation)
            replay_permit = read_contact_original_v1(self.store._db, self.issuer, ns, "stage_permit", original_operation)
            replay_result = read_contact_original_v1(self.store._db, self.issuer, ns, "stage_receipt", original_operation)
        if replay_result is not None:
            if replay_attempt is None or replay_permit is None or replay_result[0]["prepared_digest"] != prepared.digest:
                raise ValueError("contact committed stage lost its actual attempt/permit identity")
            details = replay_attempt[0]
            permit = permit_unwire(replay_permit[0]["permit"])
            actual, state = self.port.get_fence_operation(namespace=ns, authority_namespace=policy.authority_namespace, operation_id=details["attempt_id"])
            if actual != permit or state not in {"active", "finished"}:
                raise ValueError("contact committed original ACK recovery fence differs")
            if state == "active":
                scope = FenceScope(ns, policy.authority_namespace, permit.generation, "write", details["attempt_id"], permit,
                    permit.pinned_anchor, NamespaceEpoch(*ns.as_tuple, details["graph_epoch"]), details["graph_revision"])
                finish = "sha256:" + canonical_digest(("d10.contact-stage-finish.v1", original_operation, details["request_digest"], permit.token))
                self.port.finish_fence(scope, request_id="finish:" + details["attempt_id"], request_digest=finish)
            return replay_result[0]["result"]
        anchor = self.port.current_anchor(namespace=ns, authority_namespace=policy.authority_namespace)
        if not graph._anchor_matches(metadata.requirements, anchor):
            raise StaleRead("contact current W01/Authority heads differ")
        operation, details = self._attempt(value, phase, anchor, metadata, epoch)
        if phase == "result_read":
            operation += ":" + str(result_attempt)
            details["attempt_id"] = "contact-stage-fence:" + canonical_digest((operation, details["request_digest"]))[:48]
        with self.store._lock:
            db = self.store._db
            previous = read_contact_original_v1(db, self.issuer, ns, "stage_attempt", operation)
            if previous is None:
                db.execute("BEGIN IMMEDIATE")
                try:
                    if graph._v2_graph_stamp(ns) != (metadata, epoch):
                        raise StaleRead("contact Graph changed before durable stage attempt")
                    record_contact_original_v1(db, self.issuer, ns, "stage_attempt", operation, details)
                    db.commit()
                except BaseException:
                    db.rollback()
                    raise
            else:
                saved = previous[0]
                if any(saved[key] != details[key] for key in ("job_id", "phase", "request_digest", "attempt_id", "prepared_digest")):
                    raise ValueError("contact original stage identity changed")
                details = saved
            saved_permit = read_contact_original_v1(db, self.issuer, ns, "stage_permit", operation)
            saved_result = read_contact_original_v1(db, self.issuer, ns, "stage_receipt", operation)
        if saved_permit is None:
            if (details["anchor"] != asdict(anchor) or (details["graph_revision"], details["graph_epoch"]) != (metadata.graph_revision, epoch.revision)):
                raise StaleRead("contact unresolved stage cannot replace its frozen original snapshot")
            permit = self.port.begin_fence(namespace=ns, authority_namespace=policy.authority_namespace,
                holder=policy.administrator_holder, generation=anchor.activation_generation, operation="write",
                operation_id=details["attempt_id"], expected_anchor=anchor, retain_on_unknown=True)
            state = "active"
            with self.store._lock:
                db.execute("BEGIN IMMEDIATE")
                try:
                    record_contact_original_v1(db, self.issuer, ns, "stage_permit", operation,
                        {"schema": "d10.contact-stage-permit.v1", "attempt_id": details["attempt_id"], "permit": permit_wire(permit)})
                    db.commit()
                except BaseException:
                    db.rollback()
                    raise
        else:
            permit = permit_unwire(saved_permit[0]["permit"])
            actual, state = self.port.get_fence_operation(namespace=ns, authority_namespace=policy.authority_namespace, operation_id=details["attempt_id"])
            if actual != permit or state not in {"active", "finished"}:
                raise ValueError("contact actual saved stage fence differs")
        scope = FenceScope(ns, policy.authority_namespace, permit.generation, "write", details["attempt_id"], permit,
            permit.pinned_anchor, NamespaceEpoch(*ns.as_tuple, details["graph_epoch"]), details["graph_revision"])
        finish = "sha256:" + canonical_digest(("d10.contact-stage-finish.v1", operation, details["request_digest"], permit.token))
        if saved_result is not None:
            if state == "active":
                self.port.finish_fence(scope, request_id="finish:" + details["attempt_id"], request_digest=finish)
            return saved_result[0]["result"]
        if state != "active" or self.port.validate_fence(scope) != permit:
            raise ValueError("contact original stage cannot write after its retirement")
        owner, owner_permit = self.port.get_current_background_owner_authority_for_fence_v1(namespace=ns,
            authority_namespace=policy.authority_namespace, permit=permit)
        from ..authority_service.d12_target_owner_admission_v1 import D12CurrentOwnerAuthorityV1
        if type(owner) is not D12CurrentOwnerAuthorityV1 or owner_permit != permit:
            raise ValueError("contact actual current background Owner original unavailable")
        now = trusted_upper(self.port.read_ingress_clock(self.bundle.ingress_clock))
        reader = graph._GraphCoordinator__d04_semantic_mapping_reader
        witness = _ContactStageWitnessV1(self, scope, owner, value[0], phase, operation, now)
        with (reader.current_fence(scope) if reader is not None else nullcontext()):
            with self.store._lock:
                db.execute("BEGIN IMMEDIATE")
                try:
                    if graph._v2_graph_stamp(ns) != (metadata, epoch):
                        raise StaleRead("contact Graph changed before actual stage CAS")
                    graph._scene_binding_state_locked(ns, owner.guard)
                    value = self._original(db, contact_id, model_phase)
                    self._content(db, value, now, owner.guard)
                    _ACTIVE[id(witness)] = witness
                    result = self._apply(db, witness, value, metadata, epoch, result_attempt)
                    record_contact_original_v1(db, self.issuer, ns, "stage_receipt", operation,
                        {"schema": "d10.contact-stage-receipt.v1", "prepared_digest": value[0].digest,
                         "operation_id": operation, "attempt_id": details["attempt_id"], "result": plain_v1(result)})
                    db.commit()
                except BaseException:
                    db.rollback()
                    raise
                finally:
                    _ACTIVE.pop(id(witness), None)
        self.port.finish_fence(scope, request_id="finish:" + details["attempt_id"], request_digest=finish)
        return plain_v1(result)

    def _commit(self, db, witness, metadata, epoch, writes, reads):
        if (_ACTIVE.get(id(witness)) is not witness or witness.service is not self
                or not self.store._lock._is_owned() or not db.in_transaction
                or self.graph._v2_graph_stamp(witness.prepared.namespace) != (metadata, epoch)
                or witness.scope.graph_revision != metadata.graph_revision or witness.scope.graph_epoch != epoch):
            raise ValueError("contact actual private W01 stage witness changed")
        for write in writes:
            if write.key.type_name.startswith("runtime."):
                reconcile_runtime_write(db, write)
        candidate = GraphCandidate(Event(Scope(*witness.prepared.namespace.as_tuple, witness.prepared.activity_id),
            witness.operation_id, witness.now, "d10.contact-" + witness.phase + ".v1",
            {"prepared_digest": witness.prepared.digest, "writes_digest": canonical_digest(writes)}),
            tuple(reads), tuple(writes), (epoch,))
        receipt = GraphStore._graph_commit_in_transaction(self.store, candidate,
            _capability=self.graph._GraphCoordinator__graph_capability)
        if receipt.status != "committed":
            raise ValueError("contact fixed stage Graph CAS did not commit")
        self.store.cas_graph_recovery_metadata(metadata, metadata.requirements, _capability=self.graph._GraphCoordinator__graph_capability)
        seq = db.execute("SELECT last_seq FROM graph_bundle_sequence WHERE bot=? AND persona=?", witness.prepared.namespace.as_tuple).fetchone()
        sequence = (seq[0] if seq else 0) + 1
        db.execute("INSERT INTO graph_bundle_sequence VALUES(?,?,?) ON CONFLICT(bot,persona) DO UPDATE SET last_seq=excluded.last_seq",
            (*witness.prepared.namespace.as_tuple, sequence))
        db.execute("INSERT INTO graph_bundle_operations VALUES(?,?,?,?,?,?,?,?)", (*witness.prepared.namespace.as_tuple,
            witness.operation_id, canonical_digest(candidate), witness.prepared.activity_id, None, sequence,
            canonical_serialize({"schema": "d10.contact-graph-stage.v1", "status": "committed",
                "graph_receipt_digest": canonical_digest(receipt), "ledger_refs": [], "outbox_refs": []})))
        return receipt

    def _apply(self, db, witness, value, metadata, epoch, result_attempt):
        prepared, frozen, plan, expression, raw = value
        job = get_job(db, prepared.job_id)
        if witness.phase == "acquire":
            if job.phase != "queued" or job.fence or job.cancel_epoch:
                raise ValueError("contact once acquired job cannot be replaced by another worker")
            workflow = getattr(self.bundle.model_workflows, prepared.phase)
            refs = tuple(row.key.token for row in plan.qualified_read_versions if row.key.type_name == "memory.source" and row.revision > 0)
            rights = self.graph._deletion_epochs_locked(db, prepared.namespace)
            deadline = min(plan.valid_until_utc, witness.now + min(3600, workflow.timeout_seconds + 120))
            versions = dict(db.execute("SELECT kind,version FROM graph_guard_versions WHERE bot=? AND persona=? AND ref='current' AND kind IN ('scheme','operator','policy')", prepared.namespace.as_tuple))
            authority = AuthorityContext(self.port.installation_grant.subject, "d11", "contact-original:" + prepared.digest,
                prepared.namespace, ("activity", "event", "persona", "scene"), "proposal", (plan.audience_id,),
                workflow.provider_config_ref, metadata.requirements.activation_generation)
            job_key = job_graph_write(job).key
            old = db.execute("SELECT revision FROM graph_atoms WHERE token=?", (job_key.token,)).fetchone()[0]
            envelope = CommandEnvelope(RUNTIME_SCHEMA, OperationIdentity(prepared.activity_id, None, prepared.acquire_operation_id,
                prepared.phase, prepared.acquire_operation_id, canonical_digest({"input_refs": list(refs)})), authority,
                VersionGuard((*plan.qualified_read_versions, GraphVersion(job_key, old + 1)),
                    (QueryEpoch(prepared.namespace, "all", epoch.revision + 1),), rights[0], rights[1],
                    self.store._registry.catalogue_hash, versions["scheme"], versions["operator"], versions["policy"], (), (),
                    (VersionedRef(prepared.quote_id, prepared.quote_version),)),
                SourceQualification(refs, "derived", None, witness.now, "inference", "ineligible", None, "not_applicable"),
                refs, plan.parent_budget_lease_id, deadline, time.monotonic() + deadline - witness.now,
                "contact-model:" + plan.contact_id, (raw["producing_operation_id"], prepared.prepare_operation_id))
            acquired, request, writes = acquire_contact_model_in_transaction_v1(db, envelope=envelope, prepared=prepared,
                issuer=self.issuer, installed_bundle=self.bundle, now_utc=witness.now, lease_seconds=min(3600, int(workflow.timeout_seconds) + 120))
            self._commit(db, witness, metadata, epoch, writes, (*plan.qualified_read_versions, GraphVersion(job_key, old)))
            return {"status": "acquired", "job_id": job.job_id, "request_digest": request.digest}
        if witness.phase == "result_read":
            call, _ = require_contact_original_v1(db, self.issuer, prepared.namespace, "call", prepared.job_id)
            request = prepare_contact_result_read_in_transaction_v1(db, prepared=prepared, issuer=self.issuer,
                intent=model_unwire(call, ModelEgressIntentV1), attempt=result_attempt)
            from ..authority_service.contact_model_result_contract_v1 import contact_result_to_wire_v1
            return contact_result_to_wire_v1(request)
        if witness.phase == "paid_cost":
            fact = self._fact(prepared)
            receipt = self._actual_cost_commits[prepared.job_id]
            cost = db.execute("SELECT value,valid FROM graph_atoms WHERE token=?", (receipt.cost_ref,)).fetchone()
            budget = db.execute("SELECT receipt_json FROM runtime_budget_operations WHERE bot_id=? AND persona_id=? AND operation_id=? AND phase='settle'",
                (*prepared.namespace.as_tuple, prepared.prepare_operation_id)).fetchone()
            quote = self.resource_issuer.original_signed_quote(db, prepared.quote_id, prepared.quote_version)
            from .budget import _receipt_from_json
            actual_receipt = _receipt_from_json(budget[0])
            if cost is None or cost[1] != 1 or canonical_digest(asdict(actual_receipt)) != receipt.budget_receipt_digest:
                raise ValueError("contact actual independent cost commit differs")
            _, unknown = original_model_budget_measurement(fact, quote, work_kind=prepared.phase)
            paid = {"schema": "d10.contact-paid-cost-original.v1", "prepared_digest": prepared.digest,
                "terminal_digest": canonical_digest(asdict(fact.receipt)), "cost_ref": receipt.cost_ref, "cost_value": json.loads(cost[0]),
                "budget_receipt": plain_v1(actual_receipt), "unknown_dimensions": list(unknown), "cost_operation_id": receipt.operation_id}
            record_contact_original_v1(db, self.issuer, prepared.namespace, "paid_cost", prepared.job_id, paid)
            return paid
        fact = self._fact(prepared)
        result = self._results.get(prepared.job_id)
        if result is None:
            raise ValueError("contact actual terminal delivery has not been independently read")
        candidate, writes = import_contact_result_in_transaction_v1(db, prepared=prepared, result_read=result,
            fact=fact, issuer=self.issuer, resource_issuer=self.resource_issuer, holder=job.lease_holder,
            fence=job.fence, now_utc=witness.now)
        if len(writes) != 1 or writes[0].key != job_graph_write(job).key:
            raise ValueError("contact result completion cannot repeat cost or change its fixed job write")
        old = db.execute("SELECT revision FROM graph_atoms WHERE token=?", (writes[0].key.token,)).fetchone()[0]
        receipt = self._commit(db, witness, metadata, epoch, writes,
            (*plan.qualified_read_versions, GraphVersion(writes[0].key, old)))
        return {"status": "completed", "job_id": job.job_id, "output_digest": candidate.output_digest,
            "graph_receipt_digest": canonical_digest(receipt)}

    def _fact(self, prepared):
        fact = self._cost_facts.get(prepared.job_id)
        if fact is None or fact.intent.binding_digest != prepared.digest:
            raise ValueError("contact actual Authority terminal has not been read outside W01 transaction")
        return fact

    def acquire(self, *, contact_id, phase):
        return self._write(contact_id, phase, "acquire")

    def prepare_result_read(self, *, contact_id, phase, attempt=1):
        from ..authority_service.contact_model_result_contract_v1 import contact_result_from_wire_v1, ContactModelResultReadRequestV1
        raw = self._write(contact_id, phase, "result_read", result_attempt=attempt)
        return contact_result_from_wire_v1(raw, ContactModelResultReadRequestV1)

    def read_result_attempts(self, *, contact_id, phase):
        """Read the actual bounded selector chain; never derive a new model call."""
        from .contact_paid_original_v1 import TABLE
        from ..authority_service.contact_model_result_contract_v1 import contact_result_from_wire_v1, ContactModelResultReadRequestV1
        self._current()
        ns = self.bundle.installation_policy.namespace
        job_id = "contact-model-job:" + canonical_digest((ns, contact_id, phase))[:48]
        consumer = "contact-terminal:" + canonical_digest((ns, job_id))[:48]
        with self.store._lock:
            db = self.store._db
            account, _ = require_contact_original_v1(db, self.issuer, ns, "accounting_prepared", job_id)
            refs = tuple(row[0] for row in db.execute(f"SELECT original_ref FROM {TABLE} WHERE bot=? AND persona=? AND kind='read_attempt'",
                ns.as_tuple))
            requests = []
            for ref in refs:
                raw, _ = require_contact_original_v1(db, self.issuer, ns, "read_attempt", ref)
                request = contact_result_from_wire_v1(raw, ContactModelResultReadRequestV1)
                if request.job_id == job_id:
                    if (request.consumer_operation_id != consumer or request.binding_digest != account["prepared_digest"]
                            or request.call_id != account["call_id"] or request.phase != phase or request.contact_id != contact_id):
                        raise ValueError("contact durable result selector crossed its exact once call")
                    requests.append(request)
            if len(requests) > 128:
                raise ValueError("contact durable result selector count exceeded its installed bound")
            by_ref = {request.read_attempt_id: request for request in requests}
            chain = []
            for number in range(1, len(requests) + 1):
                ref = "contact-result-read:" + canonical_digest((consumer, number))[:48]
                if ref not in by_ref:
                    raise ValueError("contact durable result selector chain is incomplete")
                chain.append(by_ref[ref])
            return tuple(chain)

    def commit_cost(self, *, contact_id, phase, intent):
        self._current()
        ns = self.bundle.installation_policy.namespace
        job_id = "contact-model-job:" + canonical_digest((ns, contact_id, phase))[:48]
        with self.store._lock:
            account, _ = require_contact_original_v1(self.store._db, self.issuer, ns, "accounting_prepared", job_id)
            saved_call, _ = require_contact_original_v1(self.store._db, self.issuer, ns, "call", job_id)
            actual_intent = model_unwire(saved_call, ModelEgressIntentV1)
            quote = self.resource_issuer.original_signed_quote(self.store._db, account["quote_id"], account["quote_version"])
        if (phase not in {"contact_generation", "contact_review"} or actual_intent != intent
                or (intent.job_id, intent.call_id, intent.binding_digest, intent.operation_id,
                    intent.budget_reservation_operation_id, intent.budget_reservation_digest, intent.budget_lease_id) !=
                   (job_id, account["call_id"], account["prepared_digest"], account["acquire_operation_id"],
                    account["prepare_operation_id"], account["reservation_digest"], account["parent_budget_lease_id"])
                or account["namespace"] != plain_v1(ns) or account["work_kind"] != phase
                or canonical_digest(quote) != account["quote_digest"]):
            raise ValueError("contact retained accounting cannot substitute another actual once call")
        fact = read_original_model_cost(self.graph._GraphCoordinator__model_terminal_cost_port, intent)
        receipt = self.graph._commit_original_model_cost_v1(self.bootstrap, ns, intent,
            quote_id=account["quote_id"], quote_version=account["quote_version"], work_kind=phase)
        self._cost_facts[job_id], self._actual_cost_commits[job_id] = fact, receipt
        # This is a post-CAS seal of the existing accounting fact. It reads no
        # Source body and therefore remains available after content deletion.
        with self.store._lock:
            db = self.store._db
            db.execute("BEGIN IMMEDIATE")
            try:
                from .budget import _receipt_from_json
                original = db.execute("SELECT receipt_json,commit_seq FROM graph_bundle_operations WHERE bot=? AND persona=? AND operation_id=?",
                    (*ns.as_tuple, receipt.operation_id)).fetchone()
                cost = db.execute("SELECT value,valid FROM graph_atoms WHERE token=?", (receipt.cost_ref,)).fetchone()
                budget = db.execute("SELECT receipt_json FROM runtime_budget_operations WHERE bot_id=? AND persona_id=? AND operation_id=? AND phase='settle'",
                    (*ns.as_tuple, account["prepare_operation_id"])).fetchone()
                if original is None or cost is None or cost[1] != 1 or budget is None:
                    raise ValueError("contact actual independent cost commit is incomplete")
                raw = json.loads(original[0])
                committed = OriginalModelCostCommitV1(**raw["original_model_cost"])
                actual_receipt = _receipt_from_json(budget[0])
                if (committed.call_id != intent.call_id or committed.operation_id != receipt.operation_id
                        or committed.commit_seq != original[1] or committed.cost_ref != receipt.cost_ref
                        or raw["original_intent_digest"] != canonical_digest(asdict(intent))
                        or raw["terminal_receipt_digest"] != canonical_digest(asdict(fact.receipt))
                        or committed.terminal_receipt_digest != canonical_digest(asdict(fact.receipt))
                        or committed.budget_receipt_digest != canonical_digest(asdict(actual_receipt))
                        or (committed.quote_id, committed.quote_version) != (quote.quote_id, quote.version)):
                    raise ValueError("contact actual committed cost/terminal/budget original differs")
                _, unknown = original_model_budget_measurement(fact, quote, work_kind=phase)
                paid = {"schema": "d10.contact-paid-cost-original.v1", "prepared_digest": account["prepared_digest"],
                    "terminal_digest": canonical_digest(asdict(fact.receipt)), "cost_ref": receipt.cost_ref, "cost_value": json.loads(cost[0]),
                    "budget_receipt": plain_v1(actual_receipt), "unknown_dimensions": list(unknown), "cost_operation_id": receipt.operation_id}
                record_contact_original_v1(db, self.issuer, ns, "paid_cost", job_id, paid)
                db.commit()
            except BaseException:
                db.rollback()
                raise
        return receipt

    async def read_result_delivery(self, *, client, grant, request):
        from ..host.authority_client import AuthorityClient
        if type(client) is not AuthorityClient:
            raise TypeError("contact delivery requires actual installed Authority client")
        result = await client.contact_model_result_read_v1(self.bundle, grant, read_request=request)
        self._results[request.job_id] = result
        return result

    def finish(self, *, contact_id, phase):
        return self._write(contact_id, phase, "terminal")

    def read_egress(self, *, contact_id, phase):
        from .natural_reply_job_v2 import _request_from_wire
        self._current()
        policy, ns = self.bundle.installation_policy, self.bundle.installation_policy.namespace
        with self.store._lock:
            metadata, _ = self.graph._v2_graph_stamp(ns)
            value = self._original(self.store._db, contact_id, phase)
        authority = AuthorityContext(self.port.installation_grant.subject, "d11", "contact-read:" + value[0].digest,
            ns, ("activity", "event", "persona", "scene"), "proposal", (value[2].audience_id,),
            value[0].provider_config_ref, metadata.requirements.activation_generation)
        current_owner = []
        now = trusted_upper(self.port.read_ingress_clock(self.bundle.ingress_clock))
        def observe(scope):
            owner, permit = self.port.get_current_owner_guard_for_fence(namespace=ns,
                authority_namespace=policy.authority_namespace, permit=scope.permit)
            if permit != scope.permit:
                raise ValueError("contact actual current Owner read permit differs")
            current_owner[:] = [owner]
            return owner, permit
        def read():
            db = self.store._db
            db.execute("BEGIN")
            try:
                metadata, epoch = self.graph._v2_graph_stamp(ns)
                value = self._original(db, contact_id, phase)
                self._content(db, value, now, current_owner[0])
                prepared, frozen, *_ = value
                job = get_job(db, prepared.job_id)
                saved, _ = require_contact_original_v1(db, self.issuer, ns, "request", prepared.job_id)
                call = _request_from_wire(saved["wire"])
                draft = contact_model_draft_v1(prepared=prepared, frozen=frozen, request=call, job=job, metadata=metadata, epoch=epoch)
                sealed = read_contact_original_v1(db, self.issuer, ns, "call", prepared.job_id)
                intent = None if sealed is None else model_unwire(sealed[0], ModelEgressIntentV1)
                return prepared, frozen, job, call, draft, intent
            finally:
                db.rollback()
        value, anchor, _, _ = self.graph._read_v2(authority, read, fence_observer=observe, return_recovery_context=True)
        return (*value, anchor)

    def seal_egress(self, *, contact_id, phase, intent, permit):
        self._current()
        policy = self.bundle.installation_policy
        actual, state = self.port.get_fence_operation(namespace=policy.namespace, authority_namespace=policy.authority_namespace,
            operation_id=intent.operation_id)
        anchor = self.port.current_anchor(namespace=policy.namespace, authority_namespace=policy.authority_namespace)
        if (actual != permit or state != "active" or permit.operation != "model_egress" or anchor != permit.pinned_anchor
                or (permit.subject, permit.token, permit.revision, permit.fence_epoch) !=
                   (intent.subject, intent.fence_token, intent.fence_revision, intent.fence_epoch)):
            raise ValueError("contact exact actual model preparation permit differs")
        now = trusted_upper(self.port.read_ingress_clock(self.bundle.ingress_clock))
        with self.store._lock:
            db = self.store._db
            db.execute("BEGIN IMMEDIATE")
            try:
                metadata, epoch = self.graph._v2_graph_stamp(policy.namespace)
                if (metadata.graph_revision, epoch.revision) != (intent.graph_revision, intent.graph_epoch):
                    raise StaleRead("contact Graph changed before actual egress seal")
                value = self._original(db, contact_id, phase)
                self._content(db, value, now)
                seal_contact_call_in_transaction_v1(db, prepared=value[0], issuer=self.issuer, intent=intent)
                db.commit()
            except BaseException:
                db.rollback()
                raise
        return {"status": "sealed", "job_id": value[0].job_id}

    def read_paid_result(self, *, contact_id, phase):
        return self._read_paid_current(contact_id, phase, batch=False)

    def read_paid_progress(self, *, contact_id, phase):
        return self._read_paid_current(contact_id, phase, batch=False, completion=True)

    def read_paid_batch(self, *, contact_id):
        return self._read_paid_current(contact_id, "contact_generation", batch=True)

    def _read_paid_current(self, contact_id, phase, *, batch, completion=False):
        self._current()
        ns, policy = self.bundle.installation_policy.namespace, self.bundle.installation_policy
        now = trusted_upper(self.port.read_ingress_clock(self.bundle.ingress_clock))
        with self.store._lock:
            value = self._original(self.store._db, contact_id, phase)
            metadata, _ = self.graph._v2_graph_stamp(ns)
        authority = AuthorityContext(self.port.installation_grant.subject, "d11", "contact-paid-read:" + value[0].digest,
            ns, ("activity", "event", "persona", "scene"), "proposal", (value[2].audience_id,), value[0].provider_config_ref,
            metadata.requirements.activation_generation)
        owner = []
        def observe(scope):
            observed, permit = self.port.get_current_owner_guard_for_fence(namespace=ns,
                authority_namespace=policy.authority_namespace, permit=scope.permit)
            if permit != scope.permit:
                raise ValueError("contact paid current Owner read fence differs")
            owner[:] = [observed]
            return observed, permit
        def read():
            db = self.store._db
            db.execute("BEGIN")
            try:
                self._content(db, self._original(db, contact_id, phase), now, owner[0])
                if batch:
                    return read_paid_contact_batch_v1(db, namespace=ns, contact_id=contact_id,
                        issuer=self.issuer, resource_issuer=self.resource_issuer, now_utc=now)
                paid = read_paid_contact_result_v1(db, namespace=ns, contact_id=contact_id, phase=phase,
                    issuer=self.issuer, resource_issuer=self.resource_issuer)
                if not completion:
                    return paid
                from ..authority_service.contact_model_result_contract_v1 import contact_result_from_wire_v1, ContactModelResultReadV1
                prepared, frozen, candidate, paid_cost = paid
                result, _ = require_contact_original_v1(db, self.issuer, ns, "result", prepared.job_id)
                actual_result = contact_result_from_wire_v1(result, ContactModelResultReadV1)
                row = db.execute("SELECT receipt_json FROM graph_bundle_operations WHERE bot=? AND persona=? AND operation_id=?",
                    (*ns.as_tuple, paid_cost["cost_operation_id"])).fetchone()
                committed = OriginalModelCostCommitV1(**json.loads(row[0])["original_model_cost"])
                return prepared, candidate, actual_result.terminal_receipt, committed
            finally:
                db.rollback()
        return self.graph._read_v2(authority, read, fence_observer=observe)


def install_contact_model_graph_runtime_v1(graph, bootstrap, bundle):
    graph._admin(bootstrap)
    from .contact_paid_original_v1 import install_contact_original_schema_v1
    if getattr(graph, "_GraphCoordinator__contact_model_runtime_v1", None) is not None:
        raise ValueError("actual contact runtime is already installed")
    store = graph._GraphCoordinator__store
    with store._lock:
        store._db.execute("BEGIN IMMEDIATE")
        try:
            install_contact_original_schema_v1(store._db)
            store._db.commit()
        except BaseException:
            store._db.rollback()
            raise
    service = InstalledContactModelGraphRuntimeV1(graph=graph, bootstrap=bootstrap, bundle=bundle)
    graph._GraphCoordinator__contact_model_runtime_v1 = service
    return service


def contact_model_runtime_v1(graph, bootstrap, bundle):
    graph._admin(bootstrap)
    service = getattr(graph, "_GraphCoordinator__contact_model_runtime_v1", None)
    if type(service) is not InstalledContactModelGraphRuntimeV1 or service.graph is not graph or service.bundle is not bundle:
        raise ValueError("actual installed contact Graph runtime is unavailable")
    return service
