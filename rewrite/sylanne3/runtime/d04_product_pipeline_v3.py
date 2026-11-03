"""Actual post-C02 appraisal preparation, acquisition and original adoption."""
from __future__ import annotations

from dataclasses import asdict, replace
from datetime import datetime, timezone
import json
import time

from ..contracts import Event, Scope
from ..domains.d01 import _activation_key
from ..domains.d03.context import WorldEvent
from ..domains.d06 import source_correction_head_key
from ..domains.d07 import CurrentInterpretationCandidate, Stance, EvidenceStatus
from ..graph_store import GraphStore
from ..graph_types import AtomKey, GraphAtom, GraphCandidate, GraphSnapshot, GraphVersion
from ..memory_types import access_key, SourceRecord
from ..model_broker.broker import ModelCallRequest
from ..model_broker.d04_appraisal import (AppraisalInputV1, AppraisalInstallationV1, QualifiedAppraisalSourceV1,
    BoundInterpretationV1, freeze_appraisal_request_v1, thaw_appraisal_request_v1, TEMPLATE_DIGEST)
from ..runtime_contracts import (AuthorityContext, CommandEnvelope, OperationIdentity, QueryEpoch, RUNTIME_SCHEMA,
    SourceQualification, VersionGuard, VersionedRef, canonical_digest, canonical_serialize)
from .budget import require_budget_family_admissible
from .c02_bundle_codec import c02_bundle_from_wire
from .d04_appraisal_driver_v3 import (stage_current_d04_appraisal_in_transaction_v3,
    read_current_d04_appraisal_original_v3, record_d04_original_in_transaction_v3, read_d04_original_v3,
    seal_d04_appraisal_request_in_transaction_v3, seal_d04_appraisal_call_in_transaction_v3,
    read_original_d04_request_v3, require_current_read_rows_v3,
    settle_d04_appraisal_result_in_transaction_v3, stage_current_d04_appraisal_adoption_in_transaction_v3,
    record_d04_appraisal_acceptance_after_cas_v3)
from .d04_installed_stage_fence_v3 import run_installed_d04_stage_v3
from .d11_types import job_graph_write, runtime_job_key, reconcile_runtime_write
from .issuers import ResourceQuote
from .jobs import PersistentJob, get_job, acquire_job


def ids(namespace, c02_id):
    suffix = canonical_digest(("d04.post-c02-appraisal.v3", namespace, c02_id))[:48]
    return {kind: "d04-appraisal-" + kind + ":" + suffix for kind in ("operation", "activity", "job", "quote", "call", "acquire")}


def scope_rows(db, namespace):
    rows = db.execute("SELECT token,revision,value,valid FROM graph_atoms WHERE bot=? AND persona=? "
        "AND type_name IN ('d03.role_binding','d03.account_binding','d05.boundary_rule') ORDER BY token",
        namespace.as_tuple).fetchall()
    return canonical_digest(tuple(rows))


def _freeze(graph, db, bundle, c02_id, source_ref, role, current):
    inputs, route, binding, snapshot, _query, role_read, _boundary_read, _scene, _audience = current
    namespace = bundle.installation_policy.namespace
    workflow = bundle.model_workflows.appraisal
    if workflow is None or workflow.work_kind != "d04.appraisal":
        raise ValueError("installed D04 appraisal workflow absent")
    source = inputs.source
    root_key = AtomKey.from_token(source_ref)
    correction_key = source_correction_head_key(namespace, root_key.owner.subject)
    correction = snapshot.get(correction_key)
    if correction is None or correction.revision or correction.valid:
        raise ValueError("current D04 source correction absence unavailable")
    qualified = QualifiedAppraisalSourceV1(source.source, VersionedRef(source_ref, source.source_revision),
        VersionedRef(access_key(*namespace.as_tuple, source.source.source_id).token, source.access_revision), VersionedRef(correction_key.token, 0))
    event_atom = snapshot.get(binding.arrival_event_version.key)
    if event_atom is None or not event_atom.valid or event_atom.revision != binding.arrival_event_version.revision:
        raise ValueError("D04 actual D03 arrival absent")
    event = WorldEvent(**{**event_atom.value, "source_refs": tuple(event_atom.value["source_refs"]),
        "participant_roles": tuple(tuple(item) for item in event_atom.value["participant_roles"])})
    interpretations = []
    for atom in snapshot.atoms:
        if atom.valid and atom.key.type_name == "d07.current_interpretation.v1" and atom.value.get("current") is True and source_ref in atom.value["source_refs"]:
            values = {key: value for key, value in atom.value.items() if key != "schema"}
            values["stance"], values["evidence_status"] = Stance(values["stance"]), EvidenceStatus(values["evidence_status"])
            for key in ("source_refs", "source_families", "meaningful_unknowns"):
                values[key] = tuple(values[key])
            interpretations.append(BoundInterpretationV1(VersionedRef(atom.key.token, atom.revision), CurrentInterpretationCandidate(**values)))
    if not 1 <= len(interpretations) <= 4:
        raise ValueError("D04 current competing interpretations require bounded complete coverage")
    from .d04_ordinary_readout_v3 import require_bound_d04_role_readout_v3
    prepared_role = require_bound_d04_role_readout_v3(db,namespace)
    qualification = prepared_role.owner.source_qualification
    if role is not prepared_role.control:
        raise ValueError('D04 appraisal role is not its actual selected readout control')
    view = prepared_role.project_selected_v4(role_binding_complete=role_read.status == 'complete')
    role_atom = snapshot.get(_activation_key(namespace))
    frozen = freeze_appraisal_request_v1(AppraisalInputV1(namespace, (qualified,), qualification,
        VersionedRef(event_atom.key.token, event_atom.revision), event, VersionedRef(role_atom.key.token, role_atom.revision),
        view, tuple(sorted(interpretations, key=lambda item: item.ref.ref)), binding.target_entity_ref),
        AppraisalInstallationV1(bundle.installation_policy.installation_id, workflow.provider_id, workflow.model_id,
            workflow.provider_config_ref, workflow.provider_config_digest, workflow.max_output_tokens))
    # Full source closure is independently derived by the staging validator.
    from .selected_persona_readout_v4 import require_selected_persona_control_header_v4
    for version in role.read_versions:
        require_selected_persona_control_header_v4(prepared_role.selected_readout,version.key,version.revision)
    keys = {event_atom.key, binding.binding_version.key}
    keys.update(AtomKey.from_token(item.ref.ref) for item in interpretations)
    versions = (*role.read_versions,*(GraphVersion(atom.key, atom.revision) for atom in snapshot.atoms if atom.key in keys))
    from .d04_ordinary_readout_v3 import d04_role_manifest_wire_v3,d04_role_manifest_versions_v3
    support = d04_role_manifest_versions_v3(d04_role_manifest_wire_v3(prepared_role.manifest),namespace)
    merged = {v.key:v for v in (*versions,*support)}
    return frozen, snapshot, tuple(merged.values()), route.conversation_ref


def _commit(graph, db, metadata, epoch, operation_id, activity_id, now, writes, reads, kind):
    store = graph._GraphCoordinator__store
    for write in writes:
        if write.key.type_name.startswith("runtime."):
            reconcile_runtime_write(db, write)
    candidate = GraphCandidate(Event(Scope(*metadata.requirements.namespace.as_tuple, activity_id), operation_id, now,
        kind, {"writes_digest": canonical_digest(tuple(writes))}), tuple(reads), tuple(writes), (epoch,))
    receipt = GraphStore._graph_commit_in_transaction(store, candidate, _capability=graph._GraphCoordinator__graph_capability)
    if receipt.status != "committed":
        raise ValueError("D04 installed graph stage CAS differs")
    store.cas_graph_recovery_metadata(metadata, metadata.requirements, _capability=graph._GraphCoordinator__graph_capability)
    namespace = metadata.requirements.namespace
    seq_row = db.execute("SELECT last_seq FROM graph_bundle_sequence WHERE bot=? AND persona=?", namespace.as_tuple).fetchone()
    seq = (seq_row[0] if seq_row else 0) + 1
    db.execute("INSERT INTO graph_bundle_sequence(bot,persona,last_seq) VALUES(?,?,?) "
        "ON CONFLICT(bot,persona) DO UPDATE SET last_seq=excluded.last_seq", (*namespace.as_tuple, seq))
    db.execute("INSERT INTO graph_bundle_operations(bot,persona,operation_id,digest,activity_id,effect_id,commit_seq,receipt_json) "
        "VALUES(?,?,?,?,?,NULL,?,?)", (*namespace.as_tuple, operation_id, canonical_digest(candidate), activity_id, seq,
        canonical_serialize({"schema": "d04.installed_graph_stage.v3", "stage": kind,
            "graph_receipt_digest": canonical_digest(receipt)})))
    return receipt


def prepare_current_c02_interpretation_v1(graph, bootstrap, bundle, *, c02_operation_id, source_ref):
    """Record actual input presence only when no current D07 meaning exists."""
    from ..domains.d07.c02_presence_v1 import issue_current_c02_presence_v1, POLICY
    namespace = bundle.installation_policy.namespace
    operation_id = "d07-c02-presence:" + canonical_digest((namespace, c02_operation_id))[:48]
    def commit(db, metadata, epoch, now, guard, role, current):
        inputs, route, binding, snapshot, _query, _role_read, _boundary, scene, _audience = current
        existing = tuple(atom for atom in snapshot.atoms if atom.valid
            and atom.key.type_name == "d07.current_interpretation.v1" and atom.value.get("current") is True
            and source_ref in atom.value["source_refs"])
        if existing:
            return {"status": "existing_interpretation", "refs": [atom.key.token for atom in existing]}
        record = inputs.source.source
        from .d04_source_work_v3 import require_bound_installed_d04_source_v3
        actual_source=require_bound_installed_d04_source_v3(graph,db,namespace,
            c02_operation_id=c02_operation_id,source_ref=source_ref,epoch=epoch,now_utc=now)
        qualification=actual_source.source_qualification
        refs = (source_ref, scene.ref)
        rights = graph._deletion_epochs_locked(db, namespace)
        keys = (AtomKey.from_token(source_ref), access_key(*namespace.as_tuple, record.source_id),
            source_correction_head_key(namespace, record.source_id), AtomKey.from_token(scene.ref))
        reads = tuple(GraphVersion(key, snapshot.get(key).revision) for key in keys)
        policy = bundle.installation_policy
        deadline=min(now+30.0,actual_source.operation.deadline_utc)
        envelope = CommandEnvelope(RUNTIME_SCHEMA, OperationIdentity(inputs.c02_receipt.activity_id, None,
            operation_id, "interpret", operation_id, canonical_digest({"input_refs": list(refs)})),
            AuthorityContext(graph._GraphCoordinator__content_fence_v2.installation_grant.subject,
                "d07", "installed-c02-presence:" + operation_id, namespace,
                ("activity", "event", "persona", "scene"), "context", (route.conversation_ref,),
                POLICY[0], metadata.requirements.activation_generation),
            VersionGuard(reads, (QueryEpoch(namespace, "all", epoch.revision),), rights[0], rights[1],
                graph._GraphCoordinator__store._registry.catalogue_hash, policy.scheme_version,
                policy.operator_version, policy.policy_version, (), (), ()),
            qualification, refs, policy.root_grant.lease_id, deadline,
            min(time.monotonic()+deadline-now,actual_source.initial_monotonic_deadline),
            "c02-presence:" + c02_operation_id, (c02_operation_id,))
        proposal, provenance = issue_current_c02_presence_v1(envelope=envelope, snapshot=snapshot,
            source=inputs.source, c02_receipt=inputs.c02_receipt, perspective_ref=scene.ref)
        receipt = _commit(graph, db, metadata, epoch, operation_id, inputs.c02_receipt.activity_id,
            now, proposal.typed_writes, proposal.envelope.version_guard.read_versions, "d07.c02_input_presence.v1")
        record_d04_original_in_transaction_v3(db, namespace, "c02_interpretation", operation_id,
            {**provenance, "graph_receipt_digest": canonical_digest(receipt)})
        return {"status": "meaning_unassessed", "ref": proposal.typed_writes[0].key.token}
    return run_installed_d04_stage_v3(graph, bootstrap, bundle, c02_operation_id=c02_operation_id,
        source_ref=source_ref, operation_id=operation_id, stage="interpretation",
        request_digest=canonical_digest((POLICY, namespace, c02_operation_id, source_ref)), commit=commit)


def prepare_post_c02_appraisal_v3(graph, bootstrap, bundle, *, c02_operation_id, source_ref):
    namespace, policy = bundle.installation_policy.namespace, bundle.installation_policy
    workflow = bundle.model_workflows.appraisal
    if workflow is None:
        return {"status": "not_configured", "missing_inputs": ["appraisal_workflow"]}
    interpretation = prepare_current_c02_interpretation_v1(graph, bootstrap, bundle,
        c02_operation_id=c02_operation_id, source_ref=source_ref)
    from ..graph_worker import GraphStorageWorkV3
    if type(interpretation) is GraphStorageWorkV3:
        def after_interpretation(result):
            if type(result) is not dict or result.get("status") not in {"meaning_unassessed", "existing_interpretation"}:
                raise ValueError("D04 preparation requires the actual completed interpretation stage")
            from ..graph_storage_handoff_v3 import issue_graph_storage_handoff_v3
            from .first_ingress_v2 import trusted_upper
            now = trusted_upper(graph._GraphCoordinator__content_fence_v2.read_ingress_clock(bundle.ingress_clock))
            command = canonical_serialize({"schema": "d04.appraisal-after-interpretation.v3",
                "namespace": namespace.as_tuple, "installation_id": policy.installation_id,
                "manifest_digest": policy.manifest_digest, "c02_operation_id": c02_operation_id,
                "source_ref": source_ref, "deadline_utc": interpretation.deadline_utc}).encode("utf-8")
            return issue_graph_storage_handoff_v3(interpretation,
                factory=_start_appraisal_after_interpretation_v3, command=command,
                deadline_utc=interpretation.deadline_utc, observed_utc=now)
        def failed_interpretation(error):
            raise error
        return interpretation.map_terminal_v3("service", after_interpretation, failed_interpretation)
    return _prepare_appraisal_after_interpretation_v3(graph, bootstrap, bundle,
        c02_operation_id=c02_operation_id, source_ref=source_ref)


def _start_appraisal_after_interpretation_v3(graph, command):
    """Only detached locators cross the terminal; the child opens fresh Source."""
    data = json.loads(command)
    bundle = graph._GraphCoordinator__d04_installed_joint_assembly.admin_bundle
    policy = bundle.installation_policy
    if (type(data) is not dict or set(data) != {"schema", "namespace", "installation_id",
            "manifest_digest", "c02_operation_id", "source_ref", "deadline_utc"}
            or data["schema"] != "d04.appraisal-after-interpretation.v3"
            or data["namespace"] != list(policy.namespace.as_tuple)
            or data["installation_id"] != policy.installation_id or data["manifest_digest"] != policy.manifest_digest):
        raise ValueError("D04 child changed its actual installed interpretation lineage")
    # The child can only tighten its installed Root and actual C02 deadline.
    # A known completed receipt may return synchronously; it grants no Source.
    return _prepare_appraisal_after_interpretation_v3(graph, graph._GraphCoordinator__bootstrap, bundle,
        c02_operation_id=data["c02_operation_id"], source_ref=data["source_ref"],
        original_deadline_utc=data["deadline_utc"])


def _prepare_appraisal_after_interpretation_v3(graph, bootstrap, bundle, *, c02_operation_id, source_ref, original_deadline_utc=None):
    namespace, policy = bundle.installation_policy.namespace, bundle.installation_policy
    identity = ids(namespace, c02_operation_id)
    workflow = bundle.model_workflows.appraisal
    request_digest = canonical_digest(("d04.prepare.v3", namespace, c02_operation_id, source_ref, policy.installation_id,
        {name: dict(workflow.quote_ceiling) if name == "quote_ceiling" else getattr(workflow, name)
         for name in workflow.__dataclass_fields__}))
    def commit(db, metadata, epoch, now, guard, role, current):
        frozen, snapshot, reads, conversation = _freeze(graph, db, bundle, c02_operation_id, source_ref, role, current)
        if not set((conversation,)) <= set(workflow.audiences):
            raise ValueError("D04 appraisal audience is not installed")
        issuer = graph._GraphCoordinator__d11_issuer
        grant = issuer.current_budget_grant(db, policy.root_grant.lease_id)
        if "d04.appraisal" not in grant.allowed_work_kinds or grant.valid_until_utc <= now:
            raise ValueError("current budget grant does not admit appraisal")
        require_budget_family_admissible(db, grant.lease_id)
        if any(amount > grant.max_ceiling.get(key, 0) for key, amount in workflow.quote_ceiling.items()):
            raise ValueError("D04 appraisal quote exceeds current signed grant")
        from .d04_source_work_v3 import require_bound_installed_d04_source_v3
        prepared_source=require_bound_installed_d04_source_v3(graph,db,namespace,
            c02_operation_id=c02_operation_id,source_ref=source_ref,epoch=epoch,now_utc=now)
        deadline = min(grant.valid_until_utc, now + bundle.ingress_encoding.deadline_after_seconds,
            prepared_source.operation.deadline_utc)
        snapshot_ref = "d04-appraisal-snapshot:" + frozen.frozen_input_digest[:48]
        job = PersistentJob(identity["job"], identity["operation"], identity["activity"], None, *namespace.as_tuple,
            snapshot_ref, "queued", "d04.appraisal", {"schema": "d04.post-c02-appraisal.v3", "c02_operation_id": c02_operation_id,
                "source_ref": source_ref, "frozen_input_digest": frozen.frozen_input_digest}, None,
            datetime.fromtimestamp(deadline, timezone.utc).isoformat().replace("+00:00", "Z"), grant.lease_id,
            workflow.provider_config_ref, {"resource_quote": identity["quote"] + ":1"}, None, None, 0, 0, {}, None)
        quote = ResourceQuote(identity["quote"], 1, *namespace.as_tuple, identity["activity"], identity["operation"], None,
            grant.lease_id, "d04.appraisal", snapshot_ref, deadline, workflow.provider_config_ref,
            job_graph_write(job).key.token, (), (), dict(workflow.quote_ceiling), None, deadline)
        rights = graph._deletion_epochs_locked(db, namespace)
        from .d04_ordinary_readout_v3 import require_bound_d04_role_readout_v3
        prepared_role = require_bound_d04_role_readout_v3(db,namespace,frozen=frozen)
        stage = stage_current_d04_appraisal_in_transaction_v3(db, frozen=frozen, current_frozen=frozen,
            snapshot=snapshot, read_versions=reads, job=job, call_id=identity["call"], quote=quote,
            resource_issuer=graph._GraphCoordinator__d02_issuer, model_request_digest=frozen.model_request_digest,
            audience=(conversation,), purpose="expression", activation_generation=metadata.requirements.activation_generation,
            access_epoch=rights[0], delete_epoch=rights[1],ordinary_readout=prepared_role)
        record_d04_original_in_transaction_v3(db, namespace, "appraisal_scope", job.job_id, {"scope_digest": scope_rows(db, namespace)})
        _commit(graph, db, metadata, epoch, identity["operation"], identity["activity"], now, stage.writes,
            (*stage.read_versions, GraphVersion(job_graph_write(job).key, 0)), "d04.appraisal_prepared.v3")
        return {"status": "queued", "job_id": job.job_id, "operation_id": identity["operation"], "original_digest": stage.original.digest}
    return run_installed_d04_stage_v3(graph, bootstrap, bundle, c02_operation_id=c02_operation_id, source_ref=source_ref,
        operation_id=identity["operation"], stage="prepare", request_digest=request_digest, commit=commit,
        original_deadline_utc=original_deadline_utc)


def acquire_post_c02_appraisal_v3(graph, bootstrap, bundle, *, c02_operation_id, source_ref):
    namespace, policy = bundle.installation_policy.namespace, bundle.installation_policy
    identity = ids(namespace, c02_operation_id)
    workflow = bundle.model_workflows.appraisal
    def commit(db, metadata, epoch, now, guard, role, current):
        original = read_current_d04_appraisal_original_v3(db, namespace, identity["job"])
        if original is None:
            raise ValueError("D04 appraisal original was not prepared")
        frozen, snapshot, reads, conversation = _freeze(graph, db, bundle, c02_operation_id, source_ref, role, current)
        if canonical_serialize(asdict(frozen)) != original.frozen_json:
            raise ValueError("D04 prepared current input changed")
        require_current_read_rows_v3(db, original.read_rows, namespace)
        current_job = get_job(db, identity["job"])
        if current_job.phase != "queued" or current_job.fence != 0 or current_job.cancel_epoch:
            raise ValueError("D04 acquisition cannot re-execute a claimed or cancelled original")
        holder = graph._GraphCoordinator__content_fence_v2.installation_grant.subject
        job = acquire_job(db, current_job.job_id, holder, now_utc=datetime.fromtimestamp(now, timezone.utc).isoformat().replace("+00:00", "Z"),
            lease_seconds=min(300, int(workflow.timeout_seconds) + 30))
        deadline = min(datetime.fromisoformat(job.deadline_utc.replace("Z", "+00:00")).timestamp(),
            datetime.fromisoformat(job.lease_expires_utc.replace("Z", "+00:00")).timestamp())
        job_write = job_graph_write(job)
        from .d04_ordinary_readout_v3 import d04_role_manifest_versions_v3,require_bound_d04_role_readout_v3
        require_bound_d04_role_readout_v3(db,namespace,frozen=frozen,manifest=original.role_support_manifest)
        actual_reads = tuple(GraphVersion(AtomKey.from_token(row.ref), row.revision) for row in original.read_rows)
        actual_reads = (*actual_reads,*d04_role_manifest_versions_v3(original.role_support_manifest,namespace))
        version_guard = VersionGuard((*actual_reads, GraphVersion(job_write.key, 2)), (QueryEpoch(namespace, "all", epoch.revision + 1),),
            original.access_epoch, original.delete_epoch, graph._GraphCoordinator__store._registry.catalogue_hash,
            policy.scheme_version, policy.operator_version, policy.policy_version, (), (), ())
        authority = AuthorityContext(holder, "d11", "d04-original:" + original.digest, namespace,
            ("activity", "event", "persona", "scene"), "proposal", (conversation,), workflow.provider_config_ref,
            metadata.requirements.activation_generation, worker_fence=job.fence)
        op = OperationIdentity(job.activity_id, None, identity["acquire"], "d04.appraisal", identity["acquire"],
            canonical_digest({"input_refs": [source_ref]}))
        envelope = CommandEnvelope(RUNTIME_SCHEMA, op, authority, version_guard, frozen.input.source_qualification,
            (source_ref,), job.budget_ref, deadline, time.monotonic() + deadline - now,
            "d04-appraisal:" + c02_operation_id, (c02_operation_id, original.operation_id))
        call = ModelCallRequest(envelope, original.call_id, workflow.provider_id, workflow.model_id,
            frozenset(workflow.required_capabilities), workflow.privacy_tier, TEMPLATE_DIGEST,
            json.loads(frozen.canonical_wire), workflow.timeout_seconds, workflow.max_output_tokens)
        seal_d04_appraisal_request_in_transaction_v3(db, original, call)
        _commit(graph, db, metadata, epoch, identity["acquire"], job.activity_id, now, (job_write,),
            (*actual_reads, GraphVersion(job_write.key, 1)), "d04.appraisal_acquired.v3")
        return {"status": "acquired", "job_id": job.job_id, "request_digest": call.digest}
    return run_installed_d04_stage_v3(graph, bootstrap, bundle, c02_operation_id=c02_operation_id, source_ref=source_ref,
        operation_id=identity["acquire"], stage="acquire", request_digest=canonical_digest(("d04.acquire.v3", namespace, c02_operation_id, source_ref)), commit=commit)


def read_acquired_appraisal_v3(graph, bootstrap, bundle, *, c02_operation_id, source_ref):
    """Read the exact original typed request and current model draft; no new work."""
    from ..authority_service.v2_model_egress_contract import ModelEgressDraftV1
    graph._admin(bootstrap)
    namespace, policy = bundle.installation_policy.namespace, bundle.installation_policy
    store, port = graph._GraphCoordinator__store, graph._GraphCoordinator__content_fence_v2
    identity = ids(namespace, c02_operation_id)
    with store._lock:
        metadata, _ = graph._v2_graph_stamp(namespace)
    authority = AuthorityContext(port.installation_grant.subject, "d11", "d04-original-read:" + identity["job"],
        namespace, ("activity", "event", "persona", "scene"), "proposal", ("internal",),
        bundle.model_workflows.appraisal.provider_config_ref, metadata.requirements.activation_generation)
    owner_guards = []
    def observe(scope):
        pair = port.get_current_owner_guard_for_fence(namespace=namespace, authority_namespace=policy.authority_namespace, permit=scope.permit)
        if pair[1] != scope.permit:
            raise ValueError("D04 current Owner read permit differs")
        owner_guards[:] = [pair[0]]
        return pair
    def read():
        db = store._db
        db.execute("BEGIN")
        try:
            metadata, epoch = graph._v2_graph_stamp(namespace)
            # The clock is sampled before entering SQL by the caller below.
            role, *_ = graph._scene_binding_state_locked(namespace, owner_guards[0])
            current = graph._current_natural_generation_inputs_locked(namespace, c02_operation_id, source_ref, sample_now[0], epoch)
            original = read_current_d04_appraisal_original_v3(db, namespace, identity["job"])
            if original is None:
                raise ValueError("D04 original appraisal absent")
            frozen, _snapshot, _reads, _conversation = _freeze(graph, db, bundle, c02_operation_id, source_ref, role, current)
            if original.frozen_json != canonical_serialize(asdict(frozen)):
                raise ValueError("D04 original qualified input changed")
            call = read_original_d04_request_v3(db, original)
            job = get_job(db, original.job_id)
            if job.phase == "completed":
                from .d04_appraisal_driver_v3 import D04SettledAppraisalLocatorV3
                paid = read_d04_original_v3(db, namespace, "appraisal_cost", original.job_id)
                if (paid is None or paid[0].get("paid") is not True
                        or paid[0]["prepared_digest"] != original.digest
                        or paid[0]["result_original_ref"] != job.result_ref):
                    raise ValueError("D04 completed worker lacks its original paid result")
                return D04SettledAppraisalLocatorV3(job.job_id, original.digest, job.result_ref)
            if job.phase != "running" or job.lease_holder != call.envelope.authority.actor or job.fence != call.envelope.authority.worker_fence:
                raise ValueError("D04 original worker is not running")
            quote = graph._GraphCoordinator__d02_issuer.original_signed_quote(db, original.quote_id, original.quote_version)
            sources = tuple((item.record.source_id, item.source_ref.version) for item in frozen.input.sources)
            accesses = tuple((item.record.source_id, item.access_ref.version) for item in frozen.input.sources)
            target = metadata.requirements
            draft = ModelEgressDraftV1(target.authority_id, target.authority_namespace, call.envelope.authority.actor,
                call.identity.operation_id, call.call_id, call.digest, job.job_id, job.fence,
                tuple(ref for ref, _ in sources), sources, accesses, original.access_epoch, original.delete_epoch,
                epoch.revision, metadata.graph_revision, target.activation_generation, target.revocation_epoch,
                target.deletion_seq, target.execution_seq, job.budget_ref, original.operation_id, original.reservation_digest,
                tuple(sorted(quote.ceiling.items())), call.provider_id, call.model_id,
                frozen.installation.provider_config_digest, call.max_output_tokens, acquire_operation_id=call.identity.operation_id,
                binding_digest=original.digest)
            saved_call = read_d04_original_v3(db, namespace, "appraisal_call", job.job_id)
            from ..authority_service.v2_model_egress_wire import from_wire as model_from_wire
            from ..authority_service.v2_model_egress_contract import ModelEgressIntentV1
            sealed_intent = None if saved_call is None else model_from_wire(saved_call[0], ModelEgressIntentV1)
            return original, job, call, draft, sealed_intent
        finally:
            db.rollback()
    from .first_ingress_v2 import trusted_upper
    sample_now = [trusted_upper(port.read_ingress_clock(bundle.ingress_clock))]
    result, anchor, _metadata, _epoch = graph._read_v2(authority, read, fence_observer=observe, return_recovery_context=True)
    from .d04_appraisal_driver_v3 import D04SettledAppraisalLocatorV3
    return result if type(result) is D04SettledAppraisalLocatorV3 else (*result[:4], anchor, result[4])


def seal_appraisal_egress_v3(graph, bootstrap, namespace, *, intent, permit):
    """Persist the exact Authority-issued original under that same model fence."""
    from ..runtime_contracts import FenceScope
    graph._admin(bootstrap)
    store, port = graph._GraphCoordinator__store, graph._GraphCoordinator__content_fence_v2
    with store._lock:
        metadata, epoch = graph._v2_graph_stamp(namespace)
    def require_current():
        actual, state = port.get_fence_operation(namespace=namespace, authority_namespace=intent.namespace,
            operation_id=intent.operation_id)
        anchor = port.current_anchor(namespace=namespace, authority_namespace=intent.namespace)
        if (actual != permit or state != "active" or permit.operation != "model_egress"
                or anchor != permit.pinned_anchor or permit.subject != intent.subject
                or permit.token != intent.fence_token or permit.revision != intent.fence_revision
                or permit.fence_epoch != intent.fence_epoch):
            raise ValueError("D04 actual original model fence is not current")
    require_current()
    with store._lock:
        db = store._db
        db.execute("BEGIN IMMEDIATE")
        try:
            if graph._v2_graph_stamp(namespace) != (metadata, epoch) or (metadata.graph_revision, epoch.revision) != (intent.graph_revision, intent.graph_epoch):
                raise ValueError("D04 graph changed before actual model binding")
            original = read_current_d04_appraisal_original_v3(db, namespace, intent.job_id)
            if original is None:
                raise ValueError("D04 prepared original absent")
            require_current_read_rows_v3(db, original.read_rows, namespace)
            seal_d04_appraisal_call_in_transaction_v3(db, original, intent)
            db.commit()
        except BaseException:
            db.rollback()
            raise
    require_current()


def settle_post_c02_appraisal_v3(graph, bootstrap, bundle, *, c02_operation_id, source_ref):
    """Independently read actual result/cost outside SQL; adopt only current content."""
    from ..authority_service.current_d04_appraisal_v3 import D04AppraisalResultReadRequestV3, to_wire, from_wire
    from ..authority_service.v2_model_egress_wire import from_wire as model_from_wire
    from ..authority_service.v2_model_egress_contract import ModelEgressIntentV1
    from .model_cost_settlement import read_original_model_cost
    from .d04_appraisal_driver_v3 import read_d04_appraisal_accounting_locator_v3
    graph._admin(bootstrap)
    namespace, policy = bundle.installation_policy.namespace, bundle.installation_policy
    identity = ids(namespace, c02_operation_id)
    store, port = graph._GraphCoordinator__store, graph._GraphCoordinator__content_fence_v2
    result_port = graph._GraphCoordinator__d04_appraisal_result_port
    if result_port is None:
        raise ValueError("D04 independently installed result reader unavailable")
    with store._lock:
        original = read_d04_appraisal_accounting_locator_v3(store._db, namespace, identity["job"])
        completed = read_d04_original_v3(store._db, namespace, "appraisal_cost", identity["job"])
        if completed is not None:
            return {"status": "settled", "job_id": identity["job"], "paid": True}
        call_row = read_d04_original_v3(store._db, namespace, "appraisal_call", identity["job"])
        if original is None or call_row is None:
            raise ValueError("D04 actual original call absent")
        intent = model_from_wire(call_row[0], ModelEgressIntentV1)
        if ((original.job_id,original.call_id,original.operation_id,original.digest)!=
                (intent.job_id,intent.call_id,intent.budget_reservation_operation_id,intent.binding_digest)):
            raise ValueError('D04 accounting metadata differs from actual original sealed call')
        attempts = store._db.execute("SELECT payload_json FROM graph_d04_originals_v3 WHERE bot=? AND persona=? "
            "AND kind='appraisal_result_attempt' AND json_extract(payload_json,'$.job_id')=? ORDER BY rowid",
            (*namespace.as_tuple, identity["job"])).fetchall()
    # Content may have become stale, but actual historical expenditure is
    # recorded through its separate content-free accounting route first.
    fact = read_original_model_cost(graph._GraphCoordinator__model_terminal_cost_port, intent)
    if attempts:
        result_port.recover_finish(from_wire(json.loads(attempts[-1][0]), D04AppraisalResultReadRequestV3))
    if len(attempts) >= 32:
        raise ValueError("D04 exact result read attempts require operator recovery")
    request = D04AppraisalResultReadRequestV3(policy.expected_authority_id, policy.authority_namespace, namespace,
        policy.installation_id, original.job_id, intent.acquire_operation_id, original.operation_id, original.call_id,
        original.digest, intent.request_digest, "d04-adopt:" + original.operation_id,
        "d04-read:" + canonical_digest((original.digest, len(attempts) + 1))[:48])
    with store._lock:
        db = store._db
        db.execute("BEGIN IMMEDIATE")
        try:
            record_d04_original_in_transaction_v3(db, namespace, "appraisal_result_attempt", request.read_attempt_id, to_wire(request))
            db.commit()
        except BaseException:
            db.rollback()
            raise
    try:
        result_read = result_port.read(request)
    except Exception:
        graph._commit_original_model_cost_v1(bootstrap, namespace, intent, quote_id=original.quote_id,
            quote_version=original.quote_version, work_kind="d04.appraisal")
        raise
    operation_id = "d04-settle:" + identity["operation"]
    def commit(db, metadata, epoch, now, guard, role, current):
        original_now = read_d04_appraisal_accounting_locator_v3(db, namespace, original.job_id)
        if original_now != original:
            raise ValueError("D04 paid original changed")
        job = get_job(db, original.job_id)
        paid, writes = settle_d04_appraisal_result_in_transaction_v3(db, original, result_read=result_read, fact=fact,
            resource_issuer=graph._GraphCoordinator__d02_issuer, holder=job.lease_holder, fence=job.fence)
        reads = []
        for write in writes:
            row = db.execute("SELECT revision FROM graph_atoms WHERE token=?", (write.key.token,)).fetchone()
            reads.append(GraphVersion(write.key, 0 if row is None else row[0]))
        receipt = _commit(graph, db, metadata, epoch, operation_id, job.activity_id, now, writes, reads, "d04.appraisal_settled.v3")
        return {"status": "settled" if paid["paid"] else "cost_pending", "job_id": job.job_id,
                "paid": paid["paid"], "graph_receipt_digest": canonical_digest(receipt)}
    return run_installed_d04_stage_v3(graph, bootstrap, bundle, c02_operation_id=c02_operation_id, source_ref=source_ref,
        operation_id=operation_id, stage="settle", request_digest=canonical_digest((original.digest, fact.receipt)), commit=commit)


def adopt_post_c02_appraisal_v3(graph, bootstrap, bundle, *, c02_operation_id, source_ref):
    from ..model_broker.d04_appraisal import parse_appraisal_output_v1
    namespace = bundle.installation_policy.namespace
    identity = ids(namespace, c02_operation_id)
    op = "d04-adopt:" + identity["operation"]
    def commit(db, metadata, epoch, now, guard, role, current):
        original = read_current_d04_appraisal_original_v3(db, namespace, identity["job"])
        frozen, snapshot, reads, _conversation = _freeze(graph, db, bundle, c02_operation_id, source_ref, role, current)
        if original is None or original.frozen_json != canonical_serialize(asdict(frozen)):
            raise ValueError("D04 original current appraisal input changed")
        paid = read_d04_original_v3(db, namespace, "appraisal_cost", original.job_id)
        if paid is None:
            raise ValueError("D04 actual model cost remains unresolved")
        result = read_d04_original_v3(db, namespace, "appraisal_result", paid[0]["result_original_ref"])
        text = json.loads(result[0]["observation"]["result_json"])["text"]
        suggestion = parse_appraisal_output_v1(text, frozen)
        if suggestion.bundle is None:
            record_d04_original_in_transaction_v3(db, namespace, "appraisal_no_supported_meaning", original.job_id,
                {"prepared_digest": original.digest, "result_digest": result[1], "suggestion_digest": canonical_digest(suggestion)})
            return {"status": "no_supported_meaning", "job_id": original.job_id}
        from ..graph_types import Owner
        key = AtomKey(Owner("event", *namespace.as_tuple, suggestion.bundle.event_ref), "d04.appraisal_bundle.v1", suggestion.bundle.appraisal_id)
        absent = snapshot.get(key)
        if absent is None:
            snapshot = GraphSnapshot((*snapshot.atoms, GraphAtom(key, 0, {}, False)), snapshot.epochs)
        acceptance, writes, versions = stage_current_d04_appraisal_adoption_in_transaction_v3(db, original,
            frozen=frozen, current_frozen=frozen, snapshot=snapshot, current_read_versions=reads)
        _commit(graph, db, metadata, epoch, op, identity["activity"], now, writes, versions, "d04.appraisal_adopted.v3")
        record_d04_appraisal_acceptance_after_cas_v3(db, acceptance)
        return {"status": "adopted", "job_id": original.job_id, "appraisal_ref": acceptance.appraisal_ref,
                "appraisal_original_digest": acceptance.digest}
    return run_installed_d04_stage_v3(graph, bootstrap, bundle, c02_operation_id=c02_operation_id, source_ref=source_ref,
        operation_id=op, stage="adopt", request_digest=canonical_digest(("d04.adopt.v3", namespace, c02_operation_id, source_ref)), commit=commit)


def reconcile_d04_appraisal_cost_v3(graph, bootstrap, bundle, *, c02_operation_id, source_ref):
    """Content-free exact-call accounting even after content adoption is forbidden."""
    from ..authority_service.v2_model_egress_wire import from_wire
    from ..authority_service.v2_model_egress_contract import ModelEgressIntentV1
    graph._admin(bootstrap)
    namespace = bundle.installation_policy.namespace
    job_id = ids(namespace, c02_operation_id)["job"]
    store = graph._GraphCoordinator__store
    with store._lock:
        # Select only original metadata and sealed intent; no prompt/result is read.
        row = store._db.execute("SELECT json_extract(payload_json,'$.quote_id'), json_extract(payload_json,'$.quote_version') FROM graph_d04_originals_v3 WHERE bot=? AND persona=? AND kind='appraisal' AND original_ref=?",
            (*namespace.as_tuple, job_id)).fetchone()
        call = store._db.execute("SELECT payload_json FROM graph_d04_originals_v3 WHERE bot=? AND persona=? AND kind='appraisal_call' AND original_ref=?",
            (*namespace.as_tuple, job_id)).fetchone()
    if row is None or call is None:
        return None
    intent = from_wire(json.loads(call[0]), ModelEgressIntentV1)
    return graph._commit_original_model_cost_v1(bootstrap, namespace, intent,
        quote_id=row[0], quote_version=row[1], work_kind="d04.appraisal")
