"""Once-only C04 appends with an actual exclusive gate and journal-first commit."""
from contextlib import contextmanager
from dataclasses import asdict
import time

from ..runtime_contracts import canonical_digest
from .contract import AuthorityUnavailable, JournalHead
from .independent_append_guard_v3 import independent_append_core_guard_v3


def _operation(binding, phase):
    return "c04-exclusive:" + canonical_digest((binding.binding_digest, phase))[:48]


@contextmanager
def _frozen(bridge):
    with bridge.deletion.freeze_writes(), bridge.journal.freeze_writes():
        deletion, execution = bridge.deletion.verified_head(), bridge.journal.verified_head()
        with bridge.core._tx() as db:
            yield db, deletion, execution


def _current(bridge, db, deletion, execution, *, accounting=False):
    bridge._require_v2_mode_locked(db)
    bridge._check_deletion_locked(db, deletion)
    bridge._check_execution_head_locked(db, execution)
    row = bridge.core._row(db, bridge.namespace)
    bridge.core.require_current_storage_generation_locked(db, namespace=bridge.namespace,
        action="accounting" if accounting else "business")
    if not accounting:
        if row[0] is None or row[2] != "active" or row[3] is not None or row[4] is not None:
            raise AuthorityUnavailable("C04 installed namespace is not active")
        if bridge.deletion.has_deletion_history(bridge.namespace):
            bridge.core.require_current_content_ready_locked(db, namespace=bridge.namespace)
    return bridge.core._anchor(db, bridge.namespace, row), row


def _require_owner(bridge, db, current):
    from .v2_owner_contract import OwnerPrincipalV1
    from .v2_owner_session import OwnerSessionLoginRequestV1, _principal
    if bridge._owner_tickets is None or bridge._owner_installation_id is None:
        raise AuthorityUnavailable("C04 actual installed Owner reader is absent")
    head = bridge._owner_tickets.current_migration_head_in_tx(db, authority_namespace=bridge.namespace)
    prepared, grant = current.prepared, current.grant_value
    if (head is None or head.state != "active" or head.guard.pending_revoke_operation_id is not None
            or head.grant_revision != prepared.owner_grant_revision
            or head.grant_digest.removeprefix("sha256:") != prepared.owner_grant_digest
            or head.guard.installation_id != bridge._owner_installation_id
            or head.guard.minimum_revocation_revision >= head.guard.authorization_revision
            or head.guard.minimum_revocation_epoch or grant["installation_id"] != bridge._owner_installation_id):
        raise AuthorityUnavailable("C04 current Owner head/location differs")
    principal = OwnerPrincipalV1(**grant["principal"])
    if principal != head.issue_operation.principal:
        raise AuthorityUnavailable("C04 current Owner principal differs")
    sessions = bridge._owner_tickets._owner_sessions
    sessions._current_pairing_source.require_current_actor_in_tx(db,
        authority_namespace=bridge.namespace, installation_id=bridge._owner_installation_id,
        actor_id=current.actor, principal=principal)
    key = db.execute("SELECT credential_id,credential_epoch FROM authority_owner_credentials_v1 "
        "WHERE authority_namespace=? AND installation_id=? AND principal_json=?",
        (bridge.namespace, bridge._owner_installation_id, _principal(principal))).fetchone()
    if key is None:
        raise AuthorityUnavailable("C04 current paired Owner key is absent")
    # Use keyword construction: the signed-login DTO has distinct audience,
    # session, key and browser-origin fields. No browser token is borrowed.
    request = OwnerSessionLoginRequestV1(authority_id=head.guard.authority_id,
        authority_namespace=bridge.namespace, installation_id=bridge._owner_installation_id,
        principal=principal, credential_id=key[0], credential_epoch=key[1],
        audience="owner", dashboard_origin="https://installed.invalid")
    sessions._current_key(db, request)


def _gate(bridge, db, binding, phase):
    row = bridge.fences._row(db, _operation(binding, phase))
    if row is None:
        raise AuthorityUnavailable("C04 original exclusive gate is absent")
    permit = bridge.fences._permit(row)
    if (permit.subject != "c04-exclusive:" + binding.binding_digest
            or permit.namespace != bridge.namespace or permit.operation != ("write" if phase == "claim" else "accounting")
            or permit.command_digest != (None if phase == "claim" else "sha256:" + binding.binding_digest)
            or row[10] is not None):
        raise AuthorityUnavailable("C04 exclusive gate identity differs")
    return permit


def _reconcile(bridge, db, binding, phase, inspection):
    append = inspection.claim_append if phase == "claim" else inspection.terminal_append
    if append is None:
        raise AuthorityUnavailable("C04 exact independent append is absent")
    permit = _gate(bridge, db, binding, phase)
    before = bridge.journal.verified_predecessor_head(append.sequence)
    target = JournalHead(append.journal_id, append.sequence, append.chain_digest)
    if (permit.pinned_anchor.execution_seq != before.seq or permit.pinned_anchor.execution_digest != before.digest
            or permit.pinned_anchor.execution_journal_id != before.journal_id):
        raise AuthorityUnavailable("C04 append does not immediately consume its own gate")
    bridge.fences.finish_fence_locked(db, permit, subject=permit.subject,
        current_anchor=permit.pinned_anchor, request_id=permit.operation_id + ":consumed",
        request_digest="sha256:" + canonical_digest((binding.binding_digest, append.mutation_id, append.chain_digest)))
    row = bridge.core._row(db, bridge.namespace)
    head = bridge.core._head(row, "execution")
    if head == inspection.verified_head and head.seq >= target.seq:
        return append
    if head != before or inspection.verified_head != target:
        raise AuthorityUnavailable("C04 append recovery cannot skip another execution")
    db.execute("UPDATE authority_namespaces SET execution_seq=?,execution_digest=?,anchor_nonce=? WHERE namespace=?",
        (target.seq, target.digest, bridge.core._new_nonce(), bridge.namespace))
    bridge.core._event(db, bridge.namespace, "internal_work_" + phase, row[1],
        (binding.binding_digest, append.mutation_id, append.content_digest, target.digest))
    return append


def reconcile_exclusive_c04_v3(bridge, *, credential, binding, phase):
    bridge.core._require(credential, "execution", bridge.namespace)
    with _frozen(bridge) as (db, deletion, execution):
        inspection = bridge.journal.read_internal_work_v1(binding)
        append = _reconcile(bridge, db, binding, phase, inspection)
        return bridge.core._anchor(db, bridge.namespace, bridge.core._row(db, bridge.namespace))


def claim_exclusive_c04_v3(bridge, *, credential, binding, claim, before_head, prepared, current_reader):
    from .c04_current_execution_v3 import InstalledC04CurrentReaderV3
    if type(current_reader) is not InstalledC04CurrentReaderV3:
        raise AuthorityUnavailable("C04 claim needs its concrete installed current reader")
    bridge.core._require(credential, "execution", bridge.namespace)
    with _frozen(bridge) as (db, deletion, execution):
        observed = bridge.journal.read_internal_work_v1(binding)
        if observed.claim is not None:
            _reconcile(bridge, db, binding, "terminal" if observed.terminal else "claim", observed)
        else:
            anchor, row = _current(bridge, db, deletion, execution)
            if execution != before_head or row[1] != binding.activation_generation:
                raise AuthorityUnavailable("C04 original first-claim anchor differs")
            permit = bridge.fences.begin_fence_locked(db, subject="c04-exclusive:" + binding.binding_digest,
                holder=row[0], operation="write", current_anchor=anchor, operation_id=_operation(binding, "claim"))
    if observed.claim is not None:
        raise AuthorityUnavailable("C04 execution right is already consumed; inspect its original")
    try:
        current = current_reader.read_current(binding, permit.pinned_anchor)
        if current.prepared != prepared:
            raise AuthorityUnavailable("C04 current preparation differs from original request")
        with independent_append_core_guard_v3(bridge) as (db, deletion):
            with bridge.journal.freeze_writes():
                execution = bridge.journal.verified_head()
                anchor, row = _current(bridge, db, deletion, execution)
                bridge.fences.validate_fence_locked(db, permit, subject=permit.subject, current_anchor=anchor)
                _require_owner(bridge, db, current)
                if time.time() >= current.deadline_utc:
                    raise AuthorityUnavailable("C04 current request expired before claim")
                from .d12_lifecycle_gate_v1 import require_lifecycle_admission_in_tx_v1
                require_lifecycle_admission_in_tx_v1(db, bridge.namespace, action="first_internal_work_claim")
                bridge.journal.append_internal_work_claim_v1(binding, claim, execution)
            with bridge.journal.freeze_writes():
                result = _reconcile(bridge, db, binding, "claim", bridge.journal.read_internal_work_v1(binding))
        return result
    except BaseException:
        # Only a proven never-appended gate can close after validation fails.
        # A lost independent append/ACK keeps its exact recoverable identity.
        with _frozen(bridge) as (db, deletion, execution):
            if bridge.journal.read_internal_work_v1(binding).claim is None:
                anchor, _ = _current(bridge, db, deletion, execution)
                bridge.fences.finish_fence_locked(db, permit, subject=permit.subject, current_anchor=anchor,
                    request_id=permit.operation_id + ":unappended",
                    request_digest="sha256:" + canonical_digest((binding.binding_digest, "unappended")))
        raise


def terminal_exclusive_c04_v3(bridge, *, credential, binding, claim, terminal):
    if bridge._internal_work_terminal_verifier is None or bridge._internal_work_terminal_verifier(binding, claim, terminal) is not True:
        raise AuthorityUnavailable("C04 terminal lacks its actual installed measurement signature")
    bridge.core._require(credential, "execution", bridge.namespace)
    with _frozen(bridge) as (db, deletion, execution):
        observed = bridge.journal.read_internal_work_v1(binding)
        if observed.claim != claim:
            raise AuthorityUnavailable("C04 terminal lacks its exact committed claim")
        if observed.terminal is not None:
            if observed.terminal != terminal:
                raise AuthorityUnavailable("C04 terminal retry changes actual measurement")
            return _reconcile(bridge, db, binding, "terminal", observed)
        _reconcile(bridge, db, binding, "claim", observed)
        anchor, row = _current(bridge, db, deletion, execution, accounting=True)
        original_gate = _gate(bridge, db, binding, "claim")
        permit = bridge.fences.begin_fence_locked(db, subject="c04-exclusive:" + binding.binding_digest,
            holder=row[0] or original_gate.holder, operation="accounting", current_anchor=anchor,
            operation_id=_operation(binding, "terminal"), command_digest="sha256:" + binding.binding_digest)
    with independent_append_core_guard_v3(bridge) as (db, deletion):
        with bridge.journal.freeze_writes():
            execution = bridge.journal.verified_head()
            anchor, _ = _current(bridge, db, deletion, execution, accounting=True)
            bridge.fences.validate_fence_locked(db, permit, subject=permit.subject, current_anchor=anchor)
            bridge.journal.append_internal_work_terminal_v1(binding, claim, terminal, execution)
        with bridge.journal.freeze_writes():
            return _reconcile(bridge, db, binding, "terminal", bridge.journal.read_internal_work_v1(binding))
