"""Installed C04 worker: original inspection, once execution, cost, adoption."""
from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone

from ..contracts import Event, Scope, canonical_json
from ..domains.d04.projection_issuer_v2 import load_installed_d04_projection_assets_v2
from ..graph_coordinator import UnavailableGuard, AuthorityDenied
from ..contracts import StaleRead
from ..domains.d01.production_operations_v1 import plain_v1
from ..graph_store import GraphStore
from ..graph_types import AtomKey, GraphCandidate, GraphVersion, owner_grant_key
from ..runtime_contracts import canonical_digest
from .c04_adoption_bundle_v3 import build_current_c04_adoption_bundle_v3
from .c04_adoption_plan_v3 import build_c04_adoption_plan_v3
from .c04_internal_work_original_v1 import read_c04_internal_work_prepared_v1
from .c04_interpretation_policy_v3 import read_installed_c04_interpretation_policy_v3
from .c04_product_lifecycle_v3 import c04_terminal_proof_from_inspection_v3, read_original_c04_product_job_v3
from .d11_types import RuntimeOutboxValue, job_graph_write, outbox_graph_write
from .jobs import acquire_job, checkpoint_job, transition_job


def _timestamp(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()


def _read_original(c, namespace, operation_id):
    store = c._GraphCoordinator__store
    with store._lock:
        db = store._db
        db.execute("BEGIN")
        try:
            prepared = read_c04_internal_work_prepared_v1(db, namespace, operation_id)
            job = read_original_c04_product_job_v3(db, namespace, prepared) if prepared else None
            return prepared, job
        finally:
            db.rollback()


def acquire_current_c04_job_v3(c, authority, lease, operation_id, *, holder, lease_seconds):
    store, cap = c._GraphCoordinator__store, c._GraphCoordinator__graph_capability
    request_digest = canonical_digest(("c04.acquire.v3", authority.namespace, operation_id, holder, lease_seconds))

    def commit(db, metadata, epoch, now, owner, scope):
        prepared = read_c04_internal_work_prepared_v1(db, authority.namespace, operation_id)
        if prepared is None or prepared.binding.activation_generation != authority.activation_generation:
            raise UnavailableGuard("C04 current original preparation missing")
        job = read_original_c04_product_job_v3(db, authority.namespace, prepared)
        row = db.execute("SELECT revision FROM graph_atoms WHERE token=?", (job_graph_write(job).key.token,)).fetchone()
        instant = datetime.fromtimestamp(now, timezone.utc).isoformat().replace("+00:00", "Z")
        acquired = acquire_job(db, job.job_id, holder, now_utc=instant, lease_seconds=lease_seconds)
        write = job_graph_write(acquired)
        candidate = GraphCandidate(Event(Scope(*authority.namespace.as_tuple, job.activity_id),
            "c04-acquire-" + canonical_digest((job.job_id, acquired.fence))[:48], now,
            "c04.original-job-acquire.v3", {"binding_digest": prepared.binding.binding_digest}),
            (GraphVersion(write.key, row[0] if row else 0),), (write,), (epoch,))
        GraphStore._graph_commit_in_transaction(store, candidate, _capability=cap)
        store.cas_graph_recovery_metadata(metadata, metadata.requirements, _capability=cap)
        return {"job_id": job.job_id, "fence": acquired.fence, "binding_digest": prepared.binding.binding_digest}
    return c._owner_domain_write_v3(authority, lease,
        operation_id="c04-acquire-" + canonical_digest((operation_id, holder, lease_seconds))[:48],
        request_digest=request_digest, domains=("d04", "d06", "d07", "d11"),
        capability="c04.internal_work.prepare", commit=commit,
        new_work_admission=lambda db: c.local_module_admission.require_v1(
            ("d04", "d06", "d07", "d11"), "c04:acquire"))


def commit_current_c04_adoption_v3(c, authority, lease, *, proof, holder, fence):
    port, store = c._GraphCoordinator__c04_authority_port_v3, c._GraphCoordinator__store
    installation = c._GraphCoordinator__d04_installed_joint_assembly
    if port is None or installation is None:
        raise UnavailableGuard("installed C04 adoption authorities missing")
    verified = port.verify_terminal(proof)
    projection_policy, _asset = load_installed_d04_projection_assets_v2(
        installation.package_root, installation.installation_policy.manifest_digest,
        installation.available_cpu_features)
    namespace = authority.namespace

    def commit(db, metadata, epoch, now, owner, scope):
        prepared = read_c04_internal_work_prepared_v1(db, namespace, proof.binding.operation_id)
        if prepared is None or prepared.binding != proof.binding:
            raise UnavailableGuard("C04 prepared adoption original missing")
        job = read_original_c04_product_job_v3(db, namespace, prepared)
        if (job.phase != "running" or job.lease_holder != holder or job.fence != fence or job.cancel_epoch
                or now >= _timestamp(job.deadline_utc) or job.lease_expires_utc is None
                or now >= _timestamp(job.lease_expires_utc)):
            raise UnavailableGuard("original C04 worker cannot currently adopt")
        interpretation_policy, policy_original = read_installed_c04_interpretation_policy_v3(
            db, namespace, prepared, installation_id=installation.installation_policy.installation_id,
            manifest_digest=installation.installation_policy.manifest_digest)
        providers = c._GraphCoordinator__providers
        owner_key = owner_grant_key(*namespace.as_tuple)
        owner_row = db.execute("SELECT revision,valid FROM graph_atoms WHERE token=?", (owner_key.token,)).fetchone()
        if owner_row is None or owner_row[1] != 1:
            raise UnavailableGuard("current C04 Owner graph original missing")
        assembly = build_current_c04_adoption_bundle_v3(db, authority=authority,
            proof=proof, verified=verified, now_utc=now, query_epoch=epoch,
            current_owner_version=GraphVersion(owner_key, owner_row[0]),
            catalogue_version=store._registry.catalogue_hash, scheme=providers["d04"][0]._active_scheme,
            policy_version=c._version(db, namespace, "policy", "current"),
            projection_policy=projection_policy, interpretation_policy=interpretation_policy,
            d04_provider=providers["d04"][0], d06_provider=providers["d06"][0], d07_provider=providers["d07"][0])
        proposals = tuple(replace(p, proposal_schema=providers[p.domain][1],
            proposal_schema_hash=providers[p.domain][2]) for p in assembly.bundle.proposals)
        bundle = replace(assembly.bundle, proposals=proposals)
        plan = build_c04_adoption_plan_v3(db, namespace=namespace, operation_id=prepared.binding.operation_id,
            proof=proof, verified=verified, bundle=bundle,
            installation_id=installation.installation_policy.installation_id,
            manifest_digest=installation.installation_policy.manifest_digest)
        checkpoint_job(db, job.job_id, holder, fence,
            continuation={**job.continuation, "product_status": "adopted", "adoption_plan_digest": plan.plan_digest},
            usage={**job.usage, "cpu_ms": proof.terminal.actual_cpu_ms})
        completed = transition_job(db, job.job_id, holder, fence, target_phase="completed",
            result_ref="c04-adoption-plan:" + plan.plan_digest[:48])
        job_write = job_graph_write(completed)
        outbox_key = AtomKey.from_token(bundle.outbox_refs[0])
        outbox = RuntimeOutboxValue(*namespace.as_tuple, job.activity_id, job.operation_id, job.effect_id,
            outbox_key.name, job.job_id, job_write.key.token, "c04-adoption-plan:" + plan.plan_digest[:48],
            "c04-adopted:" + prepared.binding.binding_digest[:48], "pending", authority.activation_generation)
        runtime_writes = (job_write, outbox_graph_write(outbox, job_write.key))
        reads = {v.key: v for v in bundle.envelope.version_guard.read_versions}
        for write in runtime_writes:
            row = db.execute("SELECT revision FROM graph_atoms WHERE token=?", (write.key.token,)).fetchone()
            reads[write.key] = GraphVersion(write.key, row[0] if row else 0)
        envelope = replace(bundle.envelope, version_guard=replace(bundle.envelope.version_guard,
            read_versions=tuple(sorted(reads.values(), key=lambda v: v.key.token))))
        bundle = replace(bundle, envelope=envelope, proposals=tuple(replace(p, envelope=envelope) for p in proposals),
            persistent_job_refs=(job_write.key.token,))
        from ..authority_service.v2_contract import to_wire
        attempt = db.execute("SELECT request_digest,attempt_id FROM graph_owner_domain_attempts_v3 "
            "WHERE bot=? AND persona=? AND operation_id=?",
            (*namespace.as_tuple, "c04-adopt-" + proof.binding.binding_digest[:48])).fetchone()
        if attempt is None or attempt[1] != scope.operation_id:
            raise UnavailableGuard("C04 actual adoption fence attempt differs")
        finish_digest = "sha256:" + canonical_digest({"schema": "w01.owner-domain-write.v3",
            "operation_id": "c04-adopt-" + proof.binding.binding_digest[:48],
            "request_digest": attempt[0], "permit_token": scope.permit.token})
        receipt = c._commit_domain_bundle_fenced(bundle, lease, in_transaction=True, now_utc=now,
            v2_write=(metadata, epoch, "finish:" + scope.operation_id, finish_digest, canonical_json(to_wire(scope.permit))),
            c04_adoption_issuance_v3=(proof, verified), c04_runtime_writes_v3=runtime_writes)
        provenance = {"schema": "c04.adopted-current-interpretation-original.v3",
            "binding_digest": prepared.binding.binding_digest, "plan_digest": plan.plan_digest,
            "receipt_digest": canonical_digest(receipt), "policy_original_digest": canonical_digest(policy_original),
            "interpretation": assembly.interpretation_provenance}
        db.execute("INSERT INTO graph_c04_adoption_provenance_v3 VALUES(?,?,?,?,?)",
            (*namespace.as_tuple, prepared.binding.operation_id, canonical_json(plain_v1(provenance)), canonical_digest(plain_v1(provenance))))
        return {"status": "adopted", "operation_id": prepared.binding.operation_id,
            "binding_digest": prepared.binding.binding_digest, "plan_digest": plan.plan_digest,
            "receipt_digest": canonical_digest(receipt), "job_id": job.job_id,
            "outbox_ref": outbox_key.token, "provenance_digest": canonical_digest(provenance)}
    def checked_commit(db, metadata, epoch, now, owner, scope):
        db.execute("SAVEPOINT c04_current_adoption_v3")
        try:
            result = commit(db, metadata, epoch, now, owner, scope)
            db.execute("RELEASE c04_current_adoption_v3")
            return result
        except (UnavailableGuard, AuthorityDenied, StaleRead, ValueError) as exc:
            db.execute("ROLLBACK TO c04_current_adoption_v3")
            db.execute("RELEASE c04_current_adoption_v3")
            if c._v2_graph_stamp(namespace) != (metadata, epoch):
                raise
            c._GraphCoordinator__c04_last_adoption_refusal_v3 = exc
            return {"status": "adoption_refused", "operation_id": proof.binding.operation_id,
                "binding_digest": proof.binding.binding_digest, "reason_code": type(exc).__name__}
    result = c._owner_domain_write_v3(authority, lease,
        operation_id="c04-adopt-" + proof.binding.binding_digest[:48],
        request_digest=canonical_digest(("c04.current-adoption.v3", namespace, proof, holder, fence)),
        domains=("d04", "d06", "d07", "d11"), capability="c04.internal_work.prepare", commit=checked_commit,
        new_work_admission=lambda db: c.local_module_admission.require_v1(
            ("d04", "d06", "d07", "d11"), "c04:adopt"))
    if result["status"] == "adoption_refused":
        raise UnavailableGuard("C04 current adoption was refused after preserving its actual costs")
    return result


def advance_current_c04_product_v3(c, authority, lease, operation_id, *, holder, lease_seconds=300):
    namespace, port = authority.namespace, c._GraphCoordinator__c04_authority_port_v3
    if port is None:
        raise UnavailableGuard("installed C04 worker port missing")
    c._authorize(lease, authority, frozenset({"d04", "d06", "d07", "d11"}), owner_read=True)
    prepared, job = _read_original(c, namespace, operation_id)
    if prepared is None:
        raise UnavailableGuard("C04 original product preparation missing")
    observed = port.inspect(prepared.binding)
    proof = c04_terminal_proof_from_inspection_v3(observed)
    if proof is None and observed.claim is None:
        c.local_module_admission.require_v1(("d04", "d06", "d07", "d11"), "c04:first_native_claim")
        if job.continuation.get("schema") == "c04.prepared-job-continuation.v4":
            if job.phase != "running" or job.fence != 1 or job.cancel_epoch or job.lease_holder != holder:
                raise UnavailableGuard("C04 original prepared worker changed before its first claim")
        else:
            acquire_current_c04_job_v3(c, authority, lease, operation_id, holder=holder, lease_seconds=lease_seconds)
        observed = port.execute(prepared.binding)
        proof = c04_terminal_proof_from_inspection_v3(observed)
        prepared, job = _read_original(c, namespace, operation_id)
    if proof is None:
        return {"status": "claim_only_unknown", "operation_id": operation_id,
            "binding_digest": prepared.binding.binding_digest, "recovery_policy": "inspect_original_only"}
    bootstrap = c._GraphCoordinator__bootstrap
    cost = c.reconcile_historical_c04_cost_v1(bootstrap, namespace, operation_id)
    if proof.terminal.status != "completed" or cost["body_gap"] is not None:
        return c.reconcile_historical_c04_cost_v1(bootstrap, namespace, operation_id, close_job=True)
    from ..authority_service.installed_c04_executor_v3 import decode_completed_c04_output_v3
    actual_result = decode_completed_c04_output_v3(prepared.binding, proof.terminal)
    if not actual_result.candidates:
        # A real empty bounded search is complete computation, with no selected
        # memory to manufacture into a five-domain subjective recollection.
        closure = c.reconcile_historical_c04_cost_v1(bootstrap, namespace, operation_id, close_job=True)
        return {**closure, "status": "no_eligible_recollection",
            "result_digest": actual_result.result_digest, "stop_reason": actual_result.stop_reason}
    try:
        return commit_current_c04_adoption_v3(c, authority, lease, proof=proof, holder=holder, fence=job.fence)
    except (UnavailableGuard, AuthorityDenied, StaleRead, ValueError) as exc:
        closure = c.reconcile_historical_c04_cost_v1(bootstrap, namespace, operation_id, close_job=True)
        return {**closure, "status": "not_adopted", "adoption_failure": type(exc).__name__}
