"""Installed contact stages on the real W01 store, Owner and Authority fences.

The stage dispatch is fixed. Durable attempt/permit/receipt originals share the
Graph originals table; they never introduce another budget or execution store.
"""
from .contact_original_read_v3 import contact_original_point_v3
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
from ..host.model_workflows_v3 import AdminModelWorkflowsV3
from ..host.model_workflows_v4 import AdminModelWorkflowsV4
from ..host.model_workflows_v5 import AdminModelWorkflowsV5
from ..host.model_workflows_v6 import AdminModelWorkflowsV6
from ..host.model_workflows_v7 import AdminModelWorkflowsV7
from ..host.model_workflows_v8 import AdminModelWorkflowsV8
from ..host.model_workflows_v9 import AdminModelWorkflowsV9
from .contact_paid_original_v2 import record_contact_original_v2, require_contact_original_v2, read_contact_original_v2
from .contact_plan_adoption_v2 import read_adopted_contact_plan_v2, require_contact_inventory_current_v2
from .contact_model_job_v2 import contact_model_ids_v2, read_contact_prepared_v2
from .contact_model_preparation_v2 import (acquire_contact_model_in_transaction_v2, seal_contact_call_in_transaction_v2,
    prepare_contact_result_read_in_transaction_v2, contact_model_draft_v2, import_contact_result_in_transaction_v2,
    read_paid_contact_result_v2, read_paid_contact_batch_v2)
from .d11_types import job_graph_write, reconcile_runtime_write
from .jobs import get_job
from .first_ingress_v2 import trusted_upper
from .restore_anchor import RestoreAnchor
from .model_cost_settlement import (read_original_model_cost, OriginalModelCostCommitV1, original_model_budget_measurement)


@dataclass(frozen=True, slots=True)
class _ContactStageWitnessV2:
    service: object
    scope: FenceScope
    owner: object
    prepared: object
    phase: str
    operation_id: str
    now: float
    seal_intent: object = None


_ACTIVE = {}


class InstalledContactModelGraphRuntimeV2:
    def __init__(self, *, graph, bootstrap, bundle):
        graph._admin(bootstrap)
        store = graph._GraphCoordinator__store
        port = graph._GraphCoordinator__content_fence_v2
        assembly = graph._GraphCoordinator__d04_installed_joint_assembly
        if (not isinstance(store, ProductionGraphStore) or type(bundle) is not AdminInstallationBundle
                or type(bundle.model_workflows) not in (AdminModelWorkflowsV3, AdminModelWorkflowsV4,
                    AdminModelWorkflowsV5, AdminModelWorkflowsV6, AdminModelWorkflowsV7, AdminModelWorkflowsV8, AdminModelWorkflowsV9)
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
        if self.graph._GraphCoordinator__contact_model_runtime_v2 is not self:
            raise ValueError("contact fixed runtime is not the installed W01 producer")

    def _original(self, db, contact_id, phase):
        ns = self.bundle.installation_policy.namespace
        opened = not db.in_transaction
        if opened:
            db.execute("BEGIN")
        try:
            plan, expression, raw, _ = read_adopted_contact_plan_v2(db, namespace=ns, contact_id=contact_id, issuer=self.issuer)
            prepared, frozen = read_contact_prepared_v2(db, namespace=ns, job_id=contact_model_ids_v2(plan, phase)["job"], issuer=self.issuer)
            return prepared, frozen, plan, expression, raw
        finally:
            if opened:
                db.rollback()

    def _content(self, db, value, now, owner=None):
        from ..authority_service.contact_model_graph_v2 import require_contact_scope_current_v2
        prepared, frozen, plan, expression, raw = value
        require_contact_inventory_current_v2(db, prepared.namespace, raw)
        require_contact_scope_current_v2(db, plan, expression, now=now)
        expected = raw["proof"]["owner_guard"]
        row = contact_original_point_v3(db,table='graph_atoms',columns=('revision', 'value', 'valid'),key_columns=('token',),key=(lambda _contact_values: (_contact_values[0],))((expected["grant_ref"],)),legacy_reader=lambda: db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=?", (expected["grant_ref"],)).fetchone())
        if (row is None or (row[0], row[2]) != (expected["grant_revision"], 1)
                or canonical_digest(json.loads(row[1])) != expected["grant_digest"]
                or owner is not None and owner.authorization_head.removeprefix("sha256:") != expected["owner_head_digest"]):
            raise ValueError("contact preparation's actual current Owner changed")

    def read_preparation(self, *, contact_id, phase):
        self._current()
        return self._contact_host_read_work_v3(contact_id,phase,'preparation')

    def _read_contact_host_stage_data_v3(self, work):
        from .contact_host_source_v3 import require_contact_host_work_v3
        require_contact_host_work_v3(work,db=self.store._db)
        if work.service is not self or work.phase != 'semantic' or not self.store._db.in_transaction:
            raise ValueError('Contact Host stage read lost its actual installed Work/Scope')
        selector = work.selector
        if hasattr(work,'replay_operation'):
            raw,_ = require_contact_original_v2(self.store._db,self.issuer,work.namespace,'stage_receipt',work.replay_operation)
            if canonical_digest(raw) != work.stage_receipt_metadata.digest:
                raise ValueError('Contact replay body differs from the already ACKed full receipt EOF')
            return raw['result']
        if selector.stage == 'dispatch_text':
            from .contact_dispatch_host_read_v1 import read_qualified_contact_dispatch_text_v1
            return read_qualified_contact_dispatch_text_v1(work)
        if selector.stage == 'background_item':
            from ..host.installed_contact_background_driver_v1 import _qualified_contact_background_item_v3
            return _qualified_contact_background_item_v3(self,work)
        prepared,frozen,plan,expression,raw = self._original(self.store._db,selector.contact_id,selector.model_phase)
        self._content(self.store._db,(prepared,frozen,plan,expression,raw),work.now_utc,work.owner_guard)
        work.prepared = prepared
        job = get_job(self.store._db,prepared.job_id)
        if selector.stage == 'preparation':
            return prepared,frozen,job
        if selector.stage == 'egress':
            from .natural_reply_job_v2 import _request_from_wire
            request_raw,_ = require_contact_original_v2(self.store._db,self.issuer,prepared.namespace,'request',prepared.job_id)
            request = _request_from_wire(request_raw['wire'])
            draft = contact_model_draft_v2(prepared=prepared,frozen=frozen,request=request,job=job,
                metadata=work.graph_stamp[0],epoch=work.graph_stamp[1])
            sealed = read_contact_original_v2(self.store._db,self.issuer,prepared.namespace,'call',prepared.job_id)
            intent = None if sealed is None else model_unwire(sealed[0],ModelEgressIntentV1)
            return prepared,frozen,job,request,draft,intent,work.scope.pinned_anchor
        if selector.stage == 'attempts':
            from ..authority_service.contact_model_result_contract_v2 import ContactModelResultReadRequestV2,contact_result_from_wire_v2
            refs = self._contact_result_attempt_refs_v3(self.store._db,prepared)
            return tuple(contact_result_from_wire_v2(require_contact_original_v2(self.store._db,self.issuer,
                prepared.namespace,'read_attempt',ref)[0],ContactModelResultReadRequestV2) for ref in refs)
        if selector.stage in {'paid_result','paid_progress','paid_batch'}:
            if selector.stage == 'paid_batch':
                return read_paid_contact_batch_v2(self.store._db,namespace=prepared.namespace,contact_id=selector.contact_id,
                    issuer=self.issuer,resource_issuer=self.resource_issuer)
            paid = read_paid_contact_result_v2(self.store._db,namespace=prepared.namespace,contact_id=selector.contact_id,
                phase=selector.model_phase,issuer=self.issuer,resource_issuer=self.resource_issuer)
            if selector.stage == 'paid_result':
                return paid
            actual,frozen,candidate,cost = paid
            from ..authority_service.contact_model_result_contract_v2 import ContactModelResultReadV2,contact_result_from_wire_v2
            result_raw,_ = require_contact_original_v2(self.store._db,self.issuer,prepared.namespace,'result',actual.job_id)
            result = contact_result_from_wire_v2(result_raw,ContactModelResultReadV2)
            row = contact_original_point_v3(self.store._db,table='graph_bundle_operations',columns=('receipt_json',),
                key_columns=('bot','persona','operation_id'),key=(*prepared.namespace.as_tuple,cost['cost_operation_id']),
                legacy_reader=lambda:None)
            committed = OriginalModelCostCommitV1(**json.loads(row[0])['original_model_cost'])
            return actual,candidate,result.terminal_receipt,committed
        if selector.stage in {'acquire','paid_cost','result_read','terminal','seal'}:
            return prepared,frozen,plan,expression,raw
        raise ValueError('Contact Host fixed stage selector has no consumer')

    def _contact_host_read_work_v3(self, contact_id, phase, stage, *, result_attempt=1,borrowed_scope=None,seal_intent=None,seal_permit=None):
        from .contact_host_stage_work_v3 import prepare_contact_host_stage_work_v3
        work = prepare_contact_host_stage_work_v3(self,contact_id=contact_id,model_phase=phase,stage=stage,
            result_attempt=result_attempt,borrowed_scope=borrowed_scope,seal_intent=seal_intent,seal_permit=seal_permit)
        def result(state):
            if state.service is not self or not state.complete:
                raise ValueError('Contact Host result was not issued by this installed Work')
            return state.result
        work.map_terminal_v3('issuer',result,lambda error: (_ for _ in ()).throw(error))
        return work

    def _attempt(self, value, phase, anchor, metadata, epoch):
        prepared = value[0]
        operation = (prepared.acquire_operation_id if phase == "acquire" else
            "contact-" + phase + ":" + canonical_digest((prepared.namespace, prepared.job_id, phase))[:48])
        digest = canonical_digest(("d10.contact-installed-stage.v2", prepared.digest, phase))
        attempt = "contact-stage-fence:" + canonical_digest((operation, digest))[:48]
        return operation, {"schema": "d10.contact-stage-attempt.v2", "job_id": prepared.job_id,
            "phase": phase, "request_digest": digest, "attempt_id": attempt, "anchor": asdict(anchor),
            "graph_revision": metadata.graph_revision, "graph_epoch": epoch.revision, "prepared_digest": prepared.digest}

    def _write(self, contact_id, model_phase, phase, *, result_attempt=1):
        self._current()
        return self._contact_host_read_work_v3(contact_id,model_phase,phase,result_attempt=result_attempt)

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
            witness.operation_id, witness.now, "d10.contact-" + witness.phase + ".v2",
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
            canonical_serialize({"schema": "d10.contact-graph-stage.v2", "status": "committed",
                "graph_receipt_digest": canonical_digest(receipt), "ledger_refs": [], "outbox_refs": []})))
        return receipt

    def _apply(self, db, witness, value, metadata, epoch, result_attempt):
        prepared, frozen, plan, expression, raw = value
        job = get_job(db, prepared.job_id)
        if witness.phase == 'seal':
            intent = witness.seal_intent
            if type(intent) is not ModelEgressIntentV1 or intent.binding_digest != prepared.digest:
                raise ValueError('Contact seal WRITE lacks its original exact intent')
            seal_contact_call_in_transaction_v2(db,prepared=prepared,issuer=self.issuer,intent=intent)
            return {'status':'sealed','job_id':prepared.job_id,'intent_digest':canonical_digest(intent)}
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
            old = contact_original_point_v3(db,table='graph_atoms',columns=('revision',),key_columns=('token',),key=(lambda _contact_values: (_contact_values[0],))((job_key.token,)),legacy_reader=lambda: db.execute("SELECT revision FROM graph_atoms WHERE token=?", (job_key.token,)).fetchone())[0]
            envelope = CommandEnvelope(RUNTIME_SCHEMA, OperationIdentity(prepared.activity_id, None, prepared.acquire_operation_id,
                prepared.phase, prepared.acquire_operation_id, canonical_digest({"input_refs": list(refs)})), authority,
                VersionGuard((*plan.qualified_read_versions, GraphVersion(job_key, old + 1)),
                    (QueryEpoch(prepared.namespace, "all", epoch.revision + 1),), rights[0], rights[1],
                    self.store._registry.catalogue_hash, versions["scheme"], versions["operator"], versions["policy"], (), (),
                    (VersionedRef(prepared.quote_id, prepared.quote_version),)),
                SourceQualification(refs, "derived", None, witness.now, "inference", "ineligible", None, "not_applicable"),
                refs, plan.parent_budget_lease_id, deadline, time.monotonic() + deadline - witness.now,
                "contact-model:" + plan.contact_id, (raw["producing_operation_id"], prepared.prepare_operation_id))
            acquired, request, writes = acquire_contact_model_in_transaction_v2(db, envelope=envelope, prepared=prepared,
                issuer=self.issuer, installed_bundle=self.bundle, now_utc=witness.now, lease_seconds=min(3600, int(workflow.timeout_seconds) + 120))
            self._commit(db, witness, metadata, epoch, writes, (*plan.qualified_read_versions, GraphVersion(job_key, old)))
            return {"status": "acquired", "job_id": job.job_id, "request_digest": request.digest}
        if witness.phase == "result_read":
            call, _ = require_contact_original_v2(db, self.issuer, prepared.namespace, "call", prepared.job_id)
            request = prepare_contact_result_read_in_transaction_v2(db, prepared=prepared, issuer=self.issuer,
                intent=model_unwire(call, ModelEgressIntentV1), attempt=result_attempt)
            from ..authority_service.contact_model_result_contract_v2 import contact_result_to_wire_v2
            return contact_result_to_wire_v2(request)
        if witness.phase == "paid_cost":
            fact = self._fact(prepared)
            receipt = self._actual_cost_commits[prepared.job_id]
            cost = contact_original_point_v3(db,table='graph_atoms',columns=('value', 'valid'),key_columns=('token',),key=(lambda _contact_values: (_contact_values[0],))((receipt.cost_ref,)),legacy_reader=lambda: db.execute("SELECT value,valid FROM graph_atoms WHERE token=?", (receipt.cost_ref,)).fetchone())
            budget = contact_original_point_v3(db,table='runtime_budget_operations',columns=('receipt_json',),key_columns=('bot_id', 'persona_id', 'operation_id', 'phase'),key=(lambda _contact_values: (_contact_values[0],_contact_values[1],_contact_values[2],'settle'))((*prepared.namespace.as_tuple, prepared.prepare_operation_id)),legacy_reader=lambda: db.execute("SELECT receipt_json FROM runtime_budget_operations WHERE bot_id=? AND persona_id=? AND operation_id=? AND phase='settle'",
                (*prepared.namespace.as_tuple, prepared.prepare_operation_id)).fetchone())
            quote = self.resource_issuer.original_signed_quote(db, prepared.quote_id, prepared.quote_version)
            from .budget import _receipt_from_json
            actual_receipt = _receipt_from_json(budget[0])
            if cost is None or cost[1] != 1 or canonical_digest(asdict(actual_receipt)) != receipt.budget_receipt_digest:
                raise ValueError("contact actual independent cost commit differs")
            _, unknown = original_model_budget_measurement(fact, quote, work_kind=prepared.phase)
            paid = {"schema": "d10.contact-paid-cost-original.v2", "prepared_digest": prepared.digest,
                "terminal_digest": canonical_digest(asdict(fact.receipt)), "cost_ref": receipt.cost_ref, "cost_value": json.loads(cost[0]),
                "budget_receipt": plain_v1(actual_receipt), "unknown_dimensions": list(unknown), "cost_operation_id": receipt.operation_id}
            record_contact_original_v2(db, self.issuer, prepared.namespace, "paid_cost", prepared.job_id, paid)
            return paid
        fact = self._fact(prepared)
        result = self._results.get(prepared.job_id)
        if result is None:
            raise ValueError("contact actual terminal delivery has not been independently read")
        candidate, writes = import_contact_result_in_transaction_v2(db, prepared=prepared, result_read=result,
            fact=fact, issuer=self.issuer, resource_issuer=self.resource_issuer, holder=job.lease_holder,
            fence=job.fence, now_utc=witness.now)
        if len(writes) != 1 or writes[0].key != job_graph_write(job).key:
            raise ValueError("contact result completion cannot repeat cost or change its fixed job write")
        old = contact_original_point_v3(db,table='graph_atoms',columns=('revision',),key_columns=('token',),key=(lambda _contact_values: (_contact_values[0],))((writes[0].key.token,)),legacy_reader=lambda: db.execute("SELECT revision FROM graph_atoms WHERE token=?", (writes[0].key.token,)).fetchone())[0]
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
        from ..authority_service.contact_model_result_contract_v2 import contact_result_from_wire_v2, ContactModelResultReadRequestV2
        work = self._write(contact_id,phase,'result_read',result_attempt=attempt)
        work.map_terminal_v3('service',lambda raw: contact_result_from_wire_v2(raw,ContactModelResultReadRequestV2),
            lambda error: (_ for _ in ()).throw(error))
        return work

    def read_result_attempts(self, *, contact_id, phase):
        self._current()
        return self._contact_host_read_work_v3(contact_id,phase,'attempts')

    def _contact_result_attempt_refs_v3(self,db,prepared):
        from ..authority_service.contact_model_result_contract_v2 import ContactModelResultReadRequestV2,contact_result_from_wire_v2
        consumer = 'contact-terminal:'+canonical_digest((prepared.namespace,prepared.job_id))[:48]
        account,_ = require_contact_original_v2(db,self.issuer,prepared.namespace,'accounting_prepared',prepared.job_id)
        chain,missing = [],False
        for number in range(1,129):
            ref = 'contact-result-read:'+canonical_digest((consumer,number))[:48]
            original = read_contact_original_v2(db,self.issuer,prepared.namespace,'read_attempt',ref)
            if original is None:
                missing = True
                continue
            if missing:
                raise ValueError('Contact durable result attempt chain has a gap')
            request = contact_result_from_wire_v2(original[0],ContactModelResultReadRequestV2)
            if (request.job_id,request.contact_id,request.phase,request.consumer_operation_id,request.binding_digest,request.call_id) != (
                    prepared.job_id,prepared.contact_id,prepared.phase,consumer,account['prepared_digest'],account['call_id']):
                raise ValueError('Contact original result attempt crossed its exact once call')
            chain.append(ref)
        return tuple(chain)

    def commit_cost(self, *, contact_id, phase, intent):
        self._current()
        from .contact_cost_metadata_v3 import prepare_contact_cost_metadata_work_v3
        return prepare_contact_cost_metadata_work_v3(self,contact_id=contact_id,phase=phase,intent=intent)

    async def read_result_delivery(self, *, client, grant, request):
        from ..host.authority_client import AuthorityClient
        if type(client) is not AuthorityClient:
            raise TypeError("contact delivery requires actual installed Authority client")
        result = await client.contact_model_result_read_v2(self.bundle, grant, read_request=request)
        self._results[request.job_id] = result
        return result

    def finish(self, *, contact_id, phase):
        return self._write(contact_id, phase, "terminal")

    def read_egress(self, *, contact_id, phase):
        self._current()
        return self._contact_host_read_work_v3(contact_id,phase,'egress')

    def seal_egress(self, *, contact_id, phase, intent, permit):
        self._current()
        if type(intent) is not ModelEgressIntentV1:
            raise ValueError('Contact seal requires its original typed model intent')
        return self._contact_host_read_work_v3(contact_id,phase,'seal',seal_intent=intent,seal_permit=permit)

    def read_paid_result(self, *, contact_id, phase):
        return self._contact_host_read_work_v3(contact_id,phase,'paid_result')

    def read_paid_progress(self, *, contact_id, phase):
        return self._contact_host_read_work_v3(contact_id,phase,'paid_progress')

    def read_paid_batch(self, *, contact_id):
        return self._contact_host_read_work_v3(contact_id,'contact_generation','paid_batch')


def install_contact_model_graph_runtime_v2(graph, bootstrap, bundle):
    graph._admin(bootstrap)
    from .contact_paid_original_v2 import install_contact_original_schema_v2
    from .contact_plan_adoption_v3 import install_contact_plan_original_schema_v3
    from .contact_prospective_v1 import install_contact_prospective_schema_v1
    if getattr(graph, "_GraphCoordinator__contact_model_runtime_v2", None) is not None:
        raise ValueError("actual contact runtime is already installed")
    store = graph._GraphCoordinator__store
    with store._lock:
        store._db.execute("BEGIN IMMEDIATE")
        try:
            install_contact_original_schema_v2(store._db)
            install_contact_plan_original_schema_v3(store._db)
            install_contact_prospective_schema_v1(store._db)
            store._db.commit()
        except BaseException:
            store._db.rollback()
            raise
    service = InstalledContactModelGraphRuntimeV2(graph=graph, bootstrap=bootstrap, bundle=bundle)
    graph._GraphCoordinator__contact_model_runtime_v2 = service
    return service


def contact_model_runtime_v2(graph, bootstrap, bundle):
    graph._admin(bootstrap)
    service = getattr(graph, "_GraphCoordinator__contact_model_runtime_v2", None)
    if type(service) is not InstalledContactModelGraphRuntimeV2 or service.graph is not graph or service.bundle is not bundle:
        raise ValueError("actual installed contact Graph runtime is unavailable")
    return service
