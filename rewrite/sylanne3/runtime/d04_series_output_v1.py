"""Final bounded outputs and compatible numeric originals from authenticated prefixes."""
from dataclasses import asdict, fields, replace
from ..runtime_contracts import canonical_digest
from ..native_runtime.fixed_block_transcript import _digest
from ..native_runtime.d04_series_math_v1 import read_d04_series_final_members_v1, read_d04_series_certified_box_v1
from ..native_runtime.d04_joint_product_math import D04JointProductMathCandidate
from ..domains.d04.joint_state_output_v1 import (JointStateOutputOriginalV1, JointStateOutputMemberV1,
    _axis_output, _latent_box, _write_set, _bits, joint_checkpoint_payload_v1, joint_state_payload_v1)
from ..domains.d04.authored_lineage_v3 import AuthoredFeelingStateV1, AuthoredMoodStateV1
from ..domains.d04.numeric_drive import sourced_numeric_drive_write
from ..domains.d04.encoding_baseline import CommittedRef
from ..domains.d04.numeric_coupling import REGISTERED_AXIS_IDS
from ..domains.d04.joint_numeric_receipt import compile_joint_numeric_receipt_candidate_v1
from .d04_numeric_artifact_v3 import decode_d04_numeric_prepared_input_v3


def derive_d04_series_numeric_verification_v1(numeric, summary, *, package_root, available_cpu_features=None):
    """Recompute the numeric verification from the actual installed assets."""
    from ..domains.d04.projection_issuer_v2 import load_installed_d04_projection_assets_v2
    from ..domains.d04.trusted_joint_replay import _numeric_error_from_replay
    from .d04_joint_advance_v2 import JointNumericOriginalVerificationV1
    projection, readout = load_installed_d04_projection_assets_v2(package_root,
        numeric.native_manifest_sha256, available_cpu_features=available_cpu_features)
    error = _numeric_error_from_replay(numeric, replace(summary,
        full_step=replace(summary.full_step, previous_error=summary.initial_error)), projection, readout.rows)
    return JointNumericOriginalVerificationV1(projection.policy_id, projection.version,
        canonical_digest(asdict(projection)), readout.readout_id, readout.readout_version,
        readout.asset_sha256, numeric.math_transcript_sha256, error)


def derive_d04_series_final_v1(root, chunks, installed_policy, *, adoption_stamp):
    frozen = root.frozen
    decoded = decode_d04_numeric_prepared_input_v3(root.prepared)
    preparation = decoded.preparation
    current = preparation.current
    math_members = read_d04_series_final_members_v1(frozen, chunks, root_digest=root.digest)
    endpoint = chunks[-1].endpoints[0]
    policy = installed_policy.policy
    if (installed_policy.manifest_sha256 != root.prepared.binding.native_manifest_sha256
            or policy.digest != root.prepared.binding.output_policy_digest
            or frozen.readout.asset_sha256 != policy.readout_sha256
            or frozen.readout.readout_id != policy.readout_id):
        raise ValueError("series installed final output policy differs")
    for branch in chunks[-1].endpoints:
        read_d04_series_certified_box_v1(chunks[-1], branch.output, branch.trajectory_error, policy)
    prefix = endpoint.prefix_digest
    family_prefix = tuple((item.family_id, item.prefix_digest) for item in chunks[-1].endpoints[1:])
    math_digest = canonical_digest((root.digest, tuple(chunk.digest for chunk in chunks), math_members))
    summary = D04JointProductMathCandidate(frozen.component_digest, frozen.member_refs, frozen.full_step,
        chunks[0].initial_error, prefix, family_prefix, math_members, math_digest,
        trajectory_schema="d04.joint-product-series-prefix.v1")
    numeric = compile_joint_numeric_receipt_candidate_v1(component=current.component, math_result=summary,
        drives=current.drives, families=current.families, operator_version=root.payload["operator_version"],
        native_manifest_sha256=root.prepared.binding.native_manifest_sha256,
        native_sha256=root.prepared.binding.native_sha256, native_abi_version=2)
    # The frozen mathematical component retains its original stamp. The final
    # atomic write is pinned to the current stamp after proven own CPU events.
    content = {field.name: getattr(numeric, field.name) for field in fields(numeric)
        if field.name not in {"receipt_digest", "status"}}
    content.update(graph_revision=adoption_stamp[0], graph_epoch=adoption_stamp[1])
    numeric = type(numeric)(**content, receipt_digest=canonical_digest(content))
    members = []
    for index, (prior, math_member) in enumerate(zip(preparation.predecessors.members, math_members)):
        values = endpoint.output[index * 24:(index + 1) * 24]
        boxes, scalar_error = read_d04_series_certified_box_v1(chunks[-1], values, endpoint.trajectory_error, policy)
        if (len(math_member.full.outputs) != 24 or math_member.full.asset_sha256 != policy.readout_sha256
                or math_member.full.readout_id != policy.readout_id):
            raise ValueError("series final full readout axes incomplete")
        axes = tuple(_axis_output(axis, interval.output_id, interval.lower, interval.upper,
            policy.max_readout_interval_width) for axis, interval in zip(REGISTERED_AXIS_IDS, math_member.full.outputs))
        for branch in (math_member.full, *(value for _, value in math_member.without_family)):
            for axis, interval in zip(REGISTERED_AXIS_IDS, branch.outputs):
                if interval.axis_id != axis:
                    raise ValueError("series whole-family output axis differs")
                _axis_output(axis, interval.output_id, interval.lower, interval.upper, policy.max_readout_interval_width)
        coordinates = tuple((axis.axis_id, axis.representative) for axis in axes)
        drive_rows = tuple(drive for drive in current.drives if drive.checkpoint_ref == prior.checkpoint_ref)
        driver_refs = tuple(sorted(sourced_numeric_drive_write(drive).key.token for drive in drive_rows))
        source_refs = {drive.source_ref for drive in drive_rows}
        readout_digest = canonical_digest(axes)
        state_changes = dict(coordinates=coordinates, active_driver_refs=driver_refs,
            cursor=frozen.plan.role_end, revision=prior.state_revision + 1)
        if type(prior.state) is AuthoredFeelingStateV1:
            state_changes.update(readout_proof_digest=readout_digest, status="authored_joint_continuation",
                historical_source_refs=tuple(sorted(set(prior.state.historical_source_refs) | source_refs)))
        elif type(prior.state) is AuthoredMoodStateV1:
            state_changes.update(readout_proof_digest=readout_digest, status="authored_joint_continuation",
                source_refs=tuple(sorted(set(prior.state.source_refs) | source_refs)))
        else:
            from ..domains.d04.affect import FeelingState
            if type(prior.state) is FeelingState:
                state_changes.update(historical_source_refs=tuple(sorted(set(prior.state.historical_source_refs) | source_refs)))
            else:
                state_changes.pop("active_driver_refs")
                state_changes.update(source_refs=tuple(sorted(set(prior.state.source_refs) | source_refs)))
        next_state = replace(prior.state, **state_changes)
        checkpoint_changes = dict(latent_state=values, certified_box=boxes, numeric_error_bound=scalar_error,
            certificate_digest=canonical_digest(("d04.series-endpoint-certificate.v1", root.digest, prefix,
                prior.checkpoint_ref, values, boxes, scalar_error, policy.digest)), cursor=frozen.plan.role_end,
            graph_state=CommittedRef(prior.state_ref, prior.state_revision + 1), readout_proof_digest=readout_digest,
            commit_operation_id=preparation.predecessors.operation_id, predecessor_receipt_digest=prior.predecessor_receipt_digest)
        if current.component.root_original_digest is not None:
            checkpoint_changes["status"] = "trusted_joint_advance"
        else:
            checkpoint_changes.update(certificate_source="trusted_abi2",
                predecessor_kind="root" if prior.checkpoint.predecessor_kind == "none" else "advance")
        checkpoint = replace(prior.checkpoint, **checkpoint_changes)
        members.append(JointStateOutputMemberV1(prior.checkpoint_ref, prior.checkpoint_revision,
            canonical_digest(joint_checkpoint_payload_v1(prior.checkpoint)), prior.state_ref, prior.state_revision,
            canonical_digest(joint_state_payload_v1(prior.state)), prior.checkpoint.block.kind,
            checkpoint, next_state, axes, endpoint.trajectory_error))
    members = tuple(members)
    bits = []
    for member in members:
        bits.extend(_bits(value) for value in member.next_checkpoint.latent_state)
        bits.extend(_bits(bound) for box in member.next_checkpoint.certified_box for bound in box)
        bits.extend((_bits(member.next_checkpoint.numeric_error_bound), _bits(member.native_trajectory_error_2norm)))
        for axis in member.axes:
            bits.extend(_bits(value) for value in (axis.certified_lower, axis.certified_upper, axis.representative, axis.representative_error))
    data = dict(schema="d04.joint-state-output.v2" if current.component.root_original_digest is not None else "d04.joint-state-output.v1",
        namespace=numeric.namespace, operation_id=preparation.predecessors.operation_id, component_digest=numeric.component_digest,
        graph_incarnation=numeric.graph_incarnation, graph_revision=numeric.graph_revision, graph_epoch=numeric.graph_epoch,
        access_epoch=numeric.access_epoch, delete_epoch=numeric.delete_epoch, role_start=numeric.role_start, role_end=numeric.role_end,
        member_refs=numeric.member_refs, axis_ids=REGISTERED_AXIS_IDS, full_transcript_sha256=prefix,
        family_transcripts=family_prefix, math_transcript_sha256=math_digest, full_output_sha256=_digest(endpoint.output),
        native_manifest_sha256=numeric.native_manifest_sha256, native_sha256=numeric.native_sha256, native_abi_version=2,
        policy_id=policy.policy_id, policy_version=policy.version, policy_digest=policy.digest, policy_sha256=installed_policy.policy_sha256,
        readout_id=policy.readout_id, readout_version=policy.readout_version, readout_sha256=policy.readout_sha256,
        native_trajectory_error_2norm=endpoint.trajectory_error, members=members, write_set_digest=canonical_digest(_write_set(members)),
        binary64_bits_digest=canonical_digest(tuple(bits)))
    output = JointStateOutputOriginalV1(**data, original_digest=canonical_digest(data))
    return decoded, numeric, output, summary
