"""Exact joint member, contribution and D11 writes for one actual numeric result."""
from __future__ import annotations
from dataclasses import dataclass, replace
from ..domains.d04.joint_state_output_v1 import _write_set, joint_checkpoint_payload_v1, joint_state_payload_v1
from ..graph_types import AtomKey, GraphWrite
from ..runtime_contracts import DomainBundle, DomainProposal, DependencySet, canonical_digest
from .d04_joint_advance_v2 import ProductAdvanceEvidenceV2, ProductAdvanceMemberV2
from .d04_semantic_mapping_v3 import build_d04_product_evidence_payloads_v3
from .d04_contribution_consumption_v3 import current_contribution_writes_v3


@dataclass(frozen=True, slots=True)
class D04NumericAdoptionCandidateV3:
    bundle: DomainBundle
    payloads: object
    contribution_writes: tuple
    runtime_writes: tuple


def build_current_numeric_adoption_v3(graph, db, ready, product, runtime_writes):
    """No caller supplied output coordinate, amount, family or evidence digest."""
    from .d04_installed_numeric_v3 import D04PreparedExecutionV3
    from .d04_joint_product_assembly_v3 import D04InstalledJointProductV3
    if (not db.in_transaction or type(ready) is not D04PreparedExecutionV3
            or type(product) is not D04InstalledJointProductV3 or product.preparation != ready.preparation
            or {write.key.type_name for write in runtime_writes} != {"runtime.cost_settlement", "runtime.job"}
            or len(runtime_writes) != 2):
        raise ValueError("D04 installed product and exact D11 terminal writes are required")
    prepared, output, snapshot = ready.prepared, product.output, ready.preparation.snapshot
    binding, envelope = prepared.binding, ready.preparation.envelope
    if output.operation_id != binding.operation_id:
        raise ValueError("D04 issued output belongs to another paid execution")
    contribution_writes = current_contribution_writes_v3(db, binding.namespace, product.preparation.current.drives,
        operation_id=binding.operation_id, numeric_binding_digest=binding.digest, output_original_digest=output.original_digest)
    rows = _write_set(output.members)
    member_writes = tuple(GraphWrite(AtomKey.from_token(ref), value) for ref, _, value in rows)
    guarded = {version.key: version.revision for version in envelope.version_guard.read_versions}
    for write in (*member_writes, *contribution_writes, *runtime_writes):
        atom = snapshot.get(write.key)
        if atom is None or guarded.get(write.key) != atom.revision:
            raise ValueError("D04 final write is outside the complete prepared read set")
    payloads = build_d04_product_evidence_payloads_v3(ready.evidence_inputs, product)
    fields = payloads.evidence_fields()
    members = []
    predecessors = {item.checkpoint_ref: item for item in ready.preparation.predecessors.members}
    for member in output.members:
        old = predecessors[member.checkpoint_ref]
        members.append(ProductAdvanceMemberV2(member.checkpoint_ref, old.checkpoint.commit_operation_id,
            old.checkpoint_revision, canonical_digest(joint_checkpoint_payload_v1(old.checkpoint)),
            old.state_ref, old.state_revision, canonical_digest(joint_state_payload_v1(old.state)),
            old.checkpoint.certificate_digest, old.checkpoint.numeric_error_bound,
            old.checkpoint_revision + 1, canonical_digest(joint_checkpoint_payload_v1(member.next_checkpoint)),
            member.next_checkpoint.numeric_error_bound, old.state_ref, old.state_revision + 1,
            canonical_digest(joint_state_payload_v1(member.next_state))))
    proposals = []
    for domain, writes in (("d04", member_writes + contribution_writes), ("d11", tuple(runtime_writes))):
        registration = graph._GraphCoordinator__providers.get(domain)
        if registration is None:
            raise ValueError("D04 numeric final domain is not installed")
        historical = tuple(version for version in envelope.version_guard.read_versions if version.revision > 0
            and version.key.type_name not in {"runtime.job", "runtime.cost_settlement"}) if domain == "d04" else ()
        proposals.append(DomainProposal(domain, registration[1], registration[2], envelope, tuple(writes),
            DependencySet(historical_provenance=historical),
            tuple(write.key.name for write in contribution_writes) if domain == "d04" else (), ()))
    cost = next(write for write in runtime_writes if write.key.type_name == "runtime.cost_settlement")
    job = next(write for write in runtime_writes if write.key.type_name == "runtime.job")
    base = DomainBundle(envelope, tuple(proposals), (), (), (), (cost.key.token,),
        (binding.operation_id,), (job.key.token,), ())
    component = ready.preparation.current.component
    evidence = ProductAdvanceEvidenceV2("d11.product_advance_evidence.v3" if component.root_original_digest else "d11.product_advance_evidence.v2",
        binding.namespace, binding.operation_id, "0" * 64,
        "d04-joint:" + canonical_digest(component.checkpoint_refs), binding.execution_id,
        component.role_start, component.role_end, tuple(members), component.catalogue_hash,
        component.graph_incarnation, component.graph_revision, component.query_epoch.revision,
        component.access_epoch, component.delete_epoch,
        fields["read_versions_digest"], fields["snapshot_stamp_digest"], fields["time_mapping_digest"],
        fields["closure_digest"], fields["source_closure_digest"], fields["absent_reads_digest"], fields["asset_digest"],
        binding.native_manifest_sha256, binding.native_sha256, fields["numeric_input_digest"],
        fields["full_transcript_digest"], fields["family_loo_transcripts"], fields["output_write_set_digest"],
        fields["contribution_consumption_digest"])
    evidence = replace(evidence, bundle_digest=base.v2_digest_with(evidence))
    bundle = replace(base, product_advance=evidence)
    return D04NumericAdoptionCandidateV3(bundle, payloads, contribution_writes, tuple(runtime_writes))


@dataclass(frozen=True, slots=True, weakref_slot=True)
class _D04NumericCommitWitnessV3:
    ready: object
    product: object
    candidate: D04NumericAdoptionCandidateV3
    terminal: object
    bridge: object
    before_metadata: object
    before_epoch: object
    target_requirements: object


# Only the installed orchestrator issues these after a concrete mTLS gate
# validation. Merely constructing/parsing a bridge or witness grants nothing.
from weakref import WeakValueDictionary
_COMMIT_WITNESSES = WeakValueDictionary()


def require_current_numeric_commit_witness_v3(graph, db, bundle, witness):
    from .d04_numeric_cost_v3 import read_d04_numeric_prepared_v3, read_d04_numeric_cost_original_v3
    from ..authority_service.d04_numeric_contract_v3 import D04NumericTerminalV3
    from ..authority_service.d04_numeric_claim_bridge_v3 import D04NumericAdoptionBridgeV3
    from .d04_appraisal_driver_v3 import require_current_read_rows_v3
    if (type(witness) is not _D04NumericCommitWitnessV3 or _COMMIT_WITNESSES.get(id(witness)) is not witness
            or not db.in_transaction or bundle != witness.candidate.bundle
            or type(witness.terminal) is not D04NumericTerminalV3
            or type(witness.bridge) is not D04NumericAdoptionBridgeV3
            or witness.bridge.terminal != witness.terminal
            or witness.bridge.binding != witness.ready.prepared.binding
            or witness.terminal.measurement.status != "completed"):
        raise ValueError("D04 actual installed numeric admission witness is unavailable")
    ready, binding = witness.ready, witness.ready.prepared.binding
    if (graph._v2_graph_stamp(binding.namespace) != (witness.before_metadata, witness.before_epoch)
            or read_d04_numeric_prepared_v3(db, binding.namespace, binding.operation_id) != ready.prepared):
        raise ValueError("D04 numeric original or pre-bridge business snapshot changed")
    require_current_read_rows_v3(db, ready.evidence_inputs.read_rows, binding.namespace)
    paid = read_d04_numeric_cost_original_v3(db, binding.namespace, binding.operation_id)
    if (paid is None or paid.prepared_digest != ready.prepared.digest
            or paid.binding_digest != binding.digest or paid.terminal_digest != witness.terminal.digest
            or paid.actual_cpu_ns != witness.terminal.measurement.actual_cpu_ns
            or paid.actual_cpu_ms != witness.terminal.measurement.actual_cpu_ms or paid.status != "completed"):
        raise ValueError("D04 actual numeric CPU is not settled in this same transaction")
    rebuilt = build_current_numeric_adoption_v3(graph, db, ready, witness.product, witness.candidate.runtime_writes)
    if rebuilt != witness.candidate:
        raise ValueError("D04 member/ledger/runtime/evidence write set changed")
    return witness.target_requirements


def adopt_post_c02_joint_numeric_v3(graph, bootstrap, bundle, *, operation_id):
    """Restore actual terminal evidence, then adopt through its exact journal bridge."""
    import json
    import time
    from dataclasses import asdict
    from ..authority_service.d04_numeric_claim_bridge_v3 import numeric_bridge_to_wire_v3, numeric_bridge_from_wire_v3, D04NumericAdoptionBridgeV3
    from ..authority_service.v2_contract import to_wire
    from ..domains.d04.trusted_joint_replay import restore_installed_d04_numeric_product_v3
    from ..runtime_contracts import FenceScope, canonical_serialize
    from .c04_authority_port_v3 import InstalledC04AuthorityPortV3
    from .d04_appraisal_driver_v3 import read_d04_original_v3, record_d04_original_in_transaction_v3
    from .d04_installed_numeric_v3 import _ready_from_original_v3
    from .d04_numeric_cost_v3 import read_d04_numeric_prepared_v3, settle_d04_numeric_terminal_in_transaction_v3
    from .d04_semantic_mapping_v3 import (record_d04_joint_evidence_payloads_in_transaction_v3,
        require_current_d04_role_clock_v3, freeze_current_d04_joint_evidence_inputs_v3)
    from .first_ingress_v2 import trusted_upper
    graph._admin(bootstrap)
    store, authority = graph._GraphCoordinator__store, graph._GraphCoordinator__c04_authority_port_v3
    port, installation = graph._GraphCoordinator__content_fence_v2, graph._GraphCoordinator__d04_installed_joint_assembly
    if (type(authority) is not InstalledC04AuthorityPortV3 or authority._bundle is not bundle
            or installation.admin_bundle is not bundle):
        raise ValueError("D04 final numeric adoption requires its concrete installed assembly")
    namespace = bundle.installation_policy.namespace
    with store._lock:
        prepared = read_d04_numeric_prepared_v3(store._db, namespace, operation_id)
        committed = read_d04_original_v3(store._db, namespace, "numeric_adoption", operation_id)
        saved_gate = read_d04_original_v3(store._db, namespace, "numeric_adoption_bridge", operation_id)
    if prepared is None:
        raise ValueError("D04 original numeric preparation is absent")
    binding = prepared.binding
    if committed is not None:
        if saved_gate is None or committed[0].get("binding_digest") != binding.digest:
            raise ValueError("D04 committed numeric adoption has no exact original bridge")
        gate = numeric_bridge_from_wire_v3(saved_gate[0], D04NumericAdoptionBridgeV3)
        state = authority.numeric_gate_status(binding, gate)
        if state not in {"active", "finished"}:
            raise ValueError("D04 committed numeric bridge original is unavailable")
        if state == "active":
            authority.numeric_finish_gate(binding, gate, outcome="committed")
        return committed[0]
    # Even the ordinary happy path reconstructs from the independently
    # authenticated durable native transcript, with no second solver call.
    product = restore_installed_d04_numeric_product_v3(authority, binding, installation)
    ready = _ready_from_original_v3(prepared)
    bridge = authority.numeric_adoption_bridge(binding)
    if (bridge.prepared_digest != prepared.digest or bridge.binding != binding
            or bridge.terminal.measurement.output_original_digest != product.output.original_digest):
        raise ValueError("D04 actual terminal/bridge differs from reconstructed product")
    with store._lock:
        before, epoch = graph._v2_graph_stamp(namespace)
        encoded = store._db.execute("SELECT requirements_json FROM graph_recovery_metadata_v2 WHERE bot=? AND persona=?", namespace.as_tuple).fetchone()
    if (encoded != (bridge.before_requirements_json,) or before.graph_revision != bridge.before_graph_revision
            or ready.preparation.current.component.graph_revision != before.graph_revision
            or ready.preparation.current.component.query_epoch.revision != epoch.revision
            or not graph._anchor_matches(before.requirements, bridge.before_anchor)):
        authority.numeric_finish_gate(binding, bridge, outcome="abandoned")
        raise ValueError("D04 frozen business snapshot cannot be rebased onto another execution")
    scope = FenceScope(namespace, binding.authority_namespace, binding.activation_generation, "write",
        bridge.permit.operation_id, bridge.permit, bridge.after_anchor, epoch, before.graph_revision)
    target = replace(before.requirements, execution_seq=bridge.after_anchor.execution_seq,
        execution_digest=bridge.after_anchor.execution_digest)
    if not graph._anchor_matches(target, bridge.after_anchor):
        raise ValueError("D04 bridge may change only its exact two execution journal rows")
    topology = graph._installed_d04_authored_topology_verifier_v3()
    topology.observe_current_numeric_bridge_v3(authority, bridge, scope)
    now = trusted_upper(port.read_ingress_clock(bundle.ingress_clock))
    if now >= ready.preparation.envelope.deadline_utc:
        authority.numeric_finish_gate(binding, bridge, outcome="abandoned")
        raise ValueError("D04 adoption deadline expired; actual CPU requires historical settlement")
    local_lease, capability = graph.grant(bootstrap, actor=ready.preparation.envelope.authority.actor,
        issuer_domain="d04", namespace=namespace, domains=("d04", "d11"),
        activation_generation=binding.activation_generation, operation_id=binding.operation_id)
    if capability != ready.preparation.envelope.authority.capability_ref:
        graph.release_authority_lease(bootstrap, local_lease)
        raise ValueError("D04 frozen process capability identity differs")
    finished = False
    try:
        authority.numeric_validate_gate(binding, bridge)
        mapping_reader = graph._GraphCoordinator__d04_semantic_mapping_reader
        # The real permit pins the post-terminal journal, while the retained
        # business snapshot still names its pre-claim anchor. Only this exact
        # independently authenticated bridge may reconcile those two heads.
        # Keep this scope read-only so its exit can recheck Authority before
        # the short final adoption transaction starts.
        with mapping_reader.current_numeric_fence(scope, numeric_port=authority, bridge=bridge):
            with store._lock:
                db = store._db
                db.execute("BEGIN")
                try:
                    current_evidence = freeze_current_d04_joint_evidence_inputs_v3(
                        db, ready.preparation, clock=ready.evidence_inputs.clock,
                        installed_output_policy=graph._GraphCoordinator__d04_installed_joint_output_policy,
                        installed_mapping_reader=mapping_reader)
                    if current_evidence != ready.evidence_inputs:
                        raise ValueError("D04 current semantic/numeric evidence differs from its prepared original")
                finally:
                    db.rollback()
        with store._lock:
            db = store._db
            db.execute("BEGIN IMMEDIATE")
            witness = None
            try:
                if graph._v2_graph_stamp(namespace) != (before, epoch):
                    raise ValueError("D04 numeric final business stamp changed")
                require_current_d04_role_clock_v3(db, ready.evidence_inputs.clock)
                record_d04_original_in_transaction_v3(db, namespace, "numeric_adoption_bridge", binding.operation_id,
                    numeric_bridge_to_wire_v3(bridge))
                paid, runtime_writes = settle_d04_numeric_terminal_in_transaction_v3(db, prepared,
                    terminal=bridge.terminal, authority_original=bridge.terminal,
                    resource_issuer=graph._GraphCoordinator__d02_issuer, holder=ready.holder, fence=ready.worker_fence)
                if not runtime_writes:
                    raise ValueError("D04 numeric cost exists without its atomic adoption")
                candidate = build_current_numeric_adoption_v3(graph, db, ready, product, runtime_writes)
                witness = _D04NumericCommitWitnessV3(ready, product, candidate, bridge.terminal, bridge, before, epoch, target)
                _COMMIT_WITNESSES[id(witness)] = witness
                finish_id = bridge.permit.operation_id + ":committed"
                finish_digest = "sha256:" + canonical_digest((bridge.qualification_digest, "committed"))
                receipt = graph._commit_domain_bundle_fenced(candidate.bundle, local_lease,
                    in_transaction=True, now_utc=now,
                    v2_write=(before, epoch, finish_id, finish_digest, canonical_serialize(to_wire(bridge.permit))),
                    d04_joint_replay=product.replay, d04_joint_output=product.output,
                    d04_topology_verifier=topology, d04_numeric_issuance_v3=witness)
                record_d04_joint_evidence_payloads_in_transaction_v3(db, binding.operation_id, candidate.payloads)
                result = {"schema": "d04.numeric-adoption-receipt.v3", "status": "joint_advance_committed",
                    "operation_id": operation_id, "binding_digest": binding.digest,
                    "terminal_digest": bridge.terminal.digest, "output_original_digest": product.output.original_digest,
                    "bundle_digest": candidate.bundle.digest, "graph_receipt_digest": canonical_digest(receipt),
                    "graph_epoch": receipt.invalidated_epochs[0].revision,
                    "actual_cpu_ns": bridge.terminal.measurement.actual_cpu_ns,
                    "actual_cpu_ms": bridge.terminal.measurement.actual_cpu_ms}
                record_d04_original_in_transaction_v3(db, namespace, "numeric_adoption", operation_id, result)
                db.commit()
                finished = True
            except BaseException:
                if db.in_transaction:
                    db.rollback()
                raise
            finally:
                if witness is not None:
                    _COMMIT_WITNESSES.pop(id(witness), None)
        authority.numeric_finish_gate(binding, bridge, outcome="committed")
        return result
    except (ValueError, TypeError) as exc:
        if not finished:
            with store._lock:
                unchanged = graph._v2_graph_stamp(namespace) == (before, epoch)
            if unchanged:
                authority.numeric_finish_gate(binding, bridge, outcome="abandoned")
        raise
    finally:
        graph.release_authority_lease(bootstrap, local_lease)
