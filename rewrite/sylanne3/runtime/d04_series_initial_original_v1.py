"""Read the actual historical initial set behind a frozen joint series."""

from contextvars import ContextVar
from contextlib import contextmanager
import json

from ..runtime_contracts import canonical_digest
from ..native_runtime.fixed_block_transcript import _same_float_bits
from ..domains.d04.joint_state_output_v1 import joint_checkpoint_payload_v1, joint_state_payload_v1
from ..domains.d04.authored_lineage_v3 import AuthoredNumericCheckpointV2
from .d04_numeric_artifact_v3 import decode_d04_numeric_prepared_input_v3

_ANCESTRY = ContextVar("d04_series_initial_original_scope_v1", default=None)


@contextmanager
def d04_series_original_read_scope_v1(db):
    """One nested, read-only proof scope inside an actual BEGIN.

    The outer call owns the scope lifetime. It never survives that call,
    COMMIT/ROLLBACK, an RPC, or a subsequent transaction on this connection.
    """
    if not db.in_transaction:
        raise ValueError("series original scope requires an actual read transaction")
    current = _ANCESTRY.get()
    if current is not None:
        if current[0] is not db:
            raise ValueError("series ancestry crossed its actual database snapshot")
        yield current
        return
    current = (db, {}, set(), {}, set())
    token = _ANCESTRY.set(current)
    try:
        yield current
    finally:
        _ANCESTRY.reset(token)


def require_d04_series_initial_binding_v1(root):
    """Closed structural binding; this alone does not authenticate the history."""
    decoded = decode_d04_numeric_prepared_input_v3(root.prepared)
    preparation, frozen = decoded.preparation, root.frozen
    component, members = preparation.current.component, preparation.predecessors.members
    checkpoints = tuple(member.checkpoint for member in members)
    lower = tuple(low for checkpoint in checkpoints for low, _ in checkpoint.certified_box)
    upper = tuple(high for checkpoint in checkpoints for _, high in checkpoint.certified_box)
    centers = tuple(value for checkpoint in checkpoints for value in checkpoint.latent_state)
    if (frozen.component_digest != component.candidate_digest
            or frozen.member_refs != component.checkpoint_refs
            or tuple(member.checkpoint_ref for member in members) != frozen.member_refs
            or checkpoints != preparation.current.checkpoints
            or frozen.plan.role_start != component.role_start or frozen.plan.role_end != component.role_end
            or any(member.checkpoint.cursor != frozen.plan.role_start or member.state.cursor != frozen.plan.role_start
                   for member in members)
            or not _same_float_bits(frozen.full_step.previous, centers)
            or not _same_float_bits(frozen.initial_lower, lower) or not _same_float_bits(frozen.initial_upper, upper)):
        raise ValueError("series initial set differs from the actual frozen predecessor component")
    rows = {row.ref: row for row in decoded.evidence_inputs.read_rows}
    for member in members:
        for ref, revision, value in ((member.checkpoint_ref, member.checkpoint_revision,
                joint_checkpoint_payload_v1(member.checkpoint)),
                (member.state_ref, member.state_revision, joint_state_payload_v1(member.state))):
            row = rows.get(ref)
            if row is None or row.revision != revision or not row.valid or json.loads(row.value_json) != value:
                raise ValueError("series initial checkpoint/state loses its exact frozen read row")
    return decoded


def require_d04_series_initial_original_v1(db, root):
    from .domain_background_read_v3 import background_json_loads_v3,background_json_matches_v3,background_json_digest_v3
    from .natural_producer_qualification_v1 import _producer_original_point_v3
    if not db.in_transaction:
        raise ValueError("series initial history requires the caller's actual read transaction")
    decoded = require_d04_series_initial_binding_v1(root)
    namespace = root.prepared.binding.namespace
    context = _ANCESTRY.get()
    token = None
    if context is None:
        context = (db, {}, set(), {}, set())
        token = _ANCESTRY.set(context)
    if context[0] is not db:
        raise ValueError("series initial ancestry crossed its original transaction database")
    memo, visiting = context[1:3]
    identity = (namespace, root.root_ref, root.digest)
    try:
        if identity in memo:
            return memo[identity]
        if identity in visiting:
            raise ValueError("series predecessor ancestry is cyclic")
        visiting.add(identity)
        original_rows = []
        from .joint_numeric_component import _authored_predecessor_original
        for member in decoded.preparation.predecessors.members:
            checkpoint, state = member.checkpoint, member.state
            if type(checkpoint) is not AuthoredNumericCheckpointV2:
                raise ValueError("installed invariant series requires the actual authored Owner root lineage")
            for ref, revision, value in ((member.checkpoint_ref, member.checkpoint_revision,
                    joint_checkpoint_payload_v1(checkpoint)),
                    (member.state_ref, member.state_revision, joint_state_payload_v1(state))):
                row = _producer_original_point_v3(db, table='graph_history', columns=('value', 'valid', 'event_bot', 'event_persona', 'event_id'), key_columns=('token', 'revision'), key=(lambda _producer_params_v3: (_producer_params_v3[0],_producer_params_v3[1]))((ref, revision)), legacy_reader=lambda: db.execute("SELECT value,valid,event_bot,event_persona,event_id FROM graph_history "
                    "WHERE token=? AND revision=?", (ref, revision)).fetchone())
                if (row is None or row[1:] != (1, *namespace.as_tuple, checkpoint.commit_operation_id)
                        or background_json_loads_v3(row[0]) != value):
                    raise ValueError("series initial set lacks its exact actual historical producing event")
            root_digest, receipt_digest = _authored_predecessor_original(db, namespace,
                member.checkpoint_ref, member.checkpoint_revision, checkpoint, state)
            if (root_digest != decoded.preparation.current.component.root_original_digest
                    or receipt_digest != member.predecessor_receipt_digest):
                raise ValueError("series initial ancestry differs from its genuine Owner root/commit receipt")
            original_rows.append((member.checkpoint_ref, member.checkpoint_revision,
                canonical_digest(joint_checkpoint_payload_v1(checkpoint)), member.state_ref, member.state_revision,
                canonical_digest(joint_state_payload_v1(state)), root_digest, receipt_digest))
        result = canonical_digest(tuple(original_rows))
        memo[identity] = result
        return result
    finally:
        visiting.discard(identity)
        if token is not None:
            _ANCESTRY.reset(token)
