"""Private D11 own-execution metadata and Owner admission.

The installed execution credential validates its own once gate and metadata.
It never gains generic WRITE, Owner-reader or accounting-budget authority.
"""
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import datetime
from threading import get_ident
from weakref import WeakKeyDictionary, ref

from .contract import AuthorityUnavailable
from .v2_contract import FencePermitV2
from ..runtime_contracts import canonical_digest

_CURRENT = ContextVar("actual_d11_own_life_execution_invocation_v1", default=None)
_INVOCATIONS = WeakKeyDictionary()
_OWNERS = WeakKeyDictionary()


class _OwnLifeInvocationV1:
    def __init__(self, service, binding, phase, permit):
        self.service, self.binding, self.phase, self.permit = ref(service), binding, phase, permit
        self.thread, self.closed, self.identity = get_ident(), False, object()
        self.header = None
        self.journal_ahead_unreconciled = None
        _INVOCATIONS[self] = self.identity


def _service(service, binding):
    from .d11_life_service_v1 import AuthorityD11LifeServiceV1
    from ..runtime.d11_life_contract_v1 import LIFE_BINDING_TYPES
    from ..host.authority_profile import AdminInstallationBundle
    if (type(service) is not AuthorityD11LifeServiceV1 or type(binding) not in LIFE_BINDING_TYPES
            or not service._execution_lock._is_owned()
            or binding.namespace != service.namespace or binding.authority_namespace != service.bridge.namespace
            or binding.installation_id != service.installation_id
            or binding.manifest_digest != service.manifest_digest
            or service.bridge.core is not service.fences.core
            or service.bridge.fences is not service.fences.fences
            or service.bridge.deletion is not service.fences.deletion
            or service.bridge.journal is not service.fences.execution
            or service.owner_service.core is not service.bridge.core
            or service.owner_service.fences is not service.fences
            or service.owner_service.tickets is not service.owner_tickets):
        raise AuthorityUnavailable("own-Life metadata requires the installed service and its actual execution lock")
    location = service.current_source_location
    if (location is None or location.core is not service.bridge.core
            or location._fences is not service.fences or location._graph_db_path != service.graph_path
            or location.installation_id != service.installation_id or location.namespace_id != service.namespace
            or location._control is not service.bridge.core._c09_storage_reader_v1
            or type(service.installed_bundle) is not AdminInstallationBundle):
        raise AuthorityUnavailable("own-Life metadata lacks its actual selected installation and Source controller")
    installed = service.installed_bundle.installation_policy
    if (installed.namespace, installed.installation_id, installed.manifest_digest) != (
            service.namespace, service.installation_id, service.manifest_digest):
        raise AuthorityUnavailable("own-Life metadata changed its protected installed bundle")
    service.bridge.core._require(service.credential, "execution", service.bridge.namespace)
    service.bridge.core._require(service.credential, "current", service.bridge.namespace)
    return location._control


@contextmanager
def own_d11_life_execution_invocation_v1(service, binding, *, phase, permit=None):
    if phase not in {"execute", "adoption_metadata"}:
        raise ValueError("closed actual Life service entry required")
    _service(service, binding)
    prior = _CURRENT.get()
    if prior is not None:
        require_own_d11_life_invocation_v1(prior, service=service, binding=binding)
        if prior.phase != phase or prior.permit != permit:
            raise AuthorityUnavailable("own-Life nested call cannot change its actual entry or original gate")
        yield prior
        return
    invocation = _OwnLifeInvocationV1(service, binding, phase, permit)
    token = _CURRENT.set(invocation)
    try:
        yield invocation
    finally:
        invocation.closed = True
        _INVOCATIONS.pop(invocation, None)
        _CURRENT.reset(token)


def require_own_d11_life_invocation_v1(invocation, *, service, binding):
    if (type(invocation) is not _OwnLifeInvocationV1
            or _INVOCATIONS.get(invocation) is not invocation.identity
            or invocation.closed or invocation.thread != get_ident()
            or invocation.service() is not service or invocation.binding != binding
            or _CURRENT.get() is not invocation):
        raise AuthorityUnavailable("Life metadata caller is not the actual registered service invocation")
    _service(service, binding)
    return invocation


def require_character_labor_execution_permission_v1(service, *, credential, subject, permit, request):
    """Pre-DB and between-quantum permission, without a Work constructor cycle."""
    from .character_labor_source_read_v1 import CharacterLaborSourceReadRequestV1,CharacterLaborAckMetadataRequestV1
    if (type(request) not in {CharacterLaborSourceReadRequestV1,CharacterLaborAckMetadataRequestV1} or type(permit) is not FencePermitV2
            or credential is not service.credential or subject != permit.subject):
        raise AuthorityUnavailable("labor permission requires its exact actual invocation request and credential")
    invocation = _CURRENT.get()
    require_own_d11_life_invocation_v1(invocation, service=service, binding=request.binding)
    if service.bridge.core._db.in_transaction:
        raise AuthorityUnavailable("execution permission must precede Core/Graph SQL")
    binding = request.binding
    if type(request) is CharacterLaborAckMetadataRequestV1:
        if request.gate.permit != permit:
            raise AuthorityUnavailable("labor ACK request changed its actual adoption gate")
        require_own_life_adoption_bridge_scope_v1(service,binding,request.gate)
    with service._frozen() as (db, deletion, execution, _):
        anchor, holder = service._current(db, deletion, execution)
        if (permit.namespace != binding.authority_namespace or permit.holder != holder
                or permit.authority_id != anchor.authority_id or permit.pinned_anchor != anchor
                or binding.namespace != service.namespace or binding.installation_id != service.installation_id):
            raise AuthorityUnavailable("labor permission changed its real namespace/holder/anchor")
        if request.phase == "claim":
            actual, row = service._gate(db, binding, "claim")
            if (invocation.phase != "execute" or actual != permit or row[6] != "active"
                    or permit.operation_id != service._gate_id(binding, "claim")
                    or subject != service._subject or permit.operation != "write"
                    or binding.activation_generation != anchor.activation_generation):
                raise AuthorityUnavailable("labor Source did not borrow its actual active once-claim WRITE gate")
            expiry = min(datetime.fromisoformat(v.replace("Z", "+00:00")).timestamp()
                for v in (binding.deadline_utc, binding.job_lease_expires_utc))
            if service._now() >= expiry:
                raise AuthorityUnavailable("labor claim cannot renew its original job or execution deadline")
        else:
            if (invocation.phase != "adoption_metadata" or invocation.permit != permit
                    or permit.operation != "write" or subject != service._subject
                    or permit.operation_id != service._gate_id(binding, "adoption")):
                raise AuthorityUnavailable("labor history requires the actual current named adoption gate")
        service.bridge.fences.validate_fence_locked(db, permit, subject=subject, current_anchor=anchor)
        head = service.owner_tickets.current_migration_head_in_tx(db, authority_namespace=service.bridge.namespace)
        if head is None or head.state != "active":
            raise AuthorityUnavailable("own-Life actual current Owner is not active")
    return invocation


def _require_work(work):
    if work.controller.kind == "character_labor_census":
        from .character_labor_census_v1 import _actual, require_character_labor_census_permission_v1
        _actual(work)
        require_character_labor_census_permission_v1(work.service, credential=work.credential,
            subject=work.subject, permit=work.permit, request=work.request)
    else:
        from .character_labor_source_read_v1 import _actual
        _actual(work)
        require_character_labor_execution_permission_v1(work.service, credential=work.credential,
            subject=work.subject, permit=work.permit, request=work.request)
    return work


def observe_d11_life_execution_owner_v1(work):
    """Complete the existing Source/Target Owner lineage on the same retained operation."""
    from .owner_location_read_v3 import (
        _owner_location_service_invocation_v3, _owner_location_complete_service_v3,
        require_owner_location_caller_proof_v3)
    from .d12_owner_storage_admission_v1 import InstalledD12OwnerStorageAdmissionServiceV1
    from .d12_target_owner_admission_v1 import D12CurrentOwnerAuthorityV1
    work = _require_work(work)
    service, owner = work.service, work.service.owner_service
    if work.db.in_transaction or service.bridge.core._db.in_transaction:
        raise AuthorityUnavailable("Life Owner metadata observation must precede Graph/Core SQL")
    previous = _OWNERS.get(work)
    if previous is not None:
        previous[1]._check_permission_v3()
        require_owner_location_caller_proof_v3(previous[2], phase="before")
        return previous[4], work.permit
    with service._frozen() as (db, deletion, execution, _):
        anchor, holder = service._current(db, deletion, execution)
        service.bridge.fences.validate_fence_locked(db, work.permit, subject=work.subject, current_anchor=anchor)
        head = service.owner_tickets.current_migration_head_in_tx(db, authority_namespace=service.bridge.namespace)
        if head is None or head.state != "active" or holder != owner.holder:
            raise AuthorityUnavailable("Life Owner current namespace/head/holder differs")
        if type(owner) is InstalledD12OwnerStorageAdmissionServiceV1:
            if owner._head_in_tx(db) != head:
                raise AuthorityUnavailable("Life Source Owner head changed")
            actor, login = owner._background_identity_in_tx(db, head)
            history = None
        else:
            history = owner._current_transfer(db, generation=anchor.activation_generation)
            actor = login = None
    context = _owner_location_service_invocation_v3(service)
    context.__enter__()
    try:
        location = _owner_location_complete_service_v3(service,
            kind=("authority_character_labor_census" if work.controller.kind == "character_labor_census"
                else "authority_d11_life_execution"), owner_service=owner, credential=work.credential,
            permit=work.permit, permission_anchor=anchor, comparison_anchor=anchor,
            head=head, history=history, deadline_utc=work.deadline_utc, execution_work=work)
        from .owner_location_read_v3 import _OWNER_LOCATION_SERVICE_INVOCATION_V3
        state = _OWNER_LOCATION_SERVICE_INVOCATION_V3.get()
        call, proof, lineage = state[1][-1]
        with service._frozen() as (db, deletion, execution, _):
            current, _ = service._current(db, deletion, execution)
            service.bridge.fences.validate_fence_locked(db, work.permit, subject=work.subject, current_anchor=current)
            if current != anchor or service.owner_tickets.current_migration_head_in_tx(
                    db, authority_namespace=service.bridge.namespace) != head:
                raise AuthorityUnavailable("Life Owner changed after complete actual metadata/lineage EOF")
            if history is None:
                if owner._background_identity_in_tx(db, head) != (actor, login):
                    raise AuthorityUnavailable("Life Source Owner actor or pairing changed")
                observed = D12CurrentOwnerAuthorityV1(head.guard, None, location[2])
            else:
                metadata, revision, grant_digest, imported, continuation = location
                observed = owner._current_background_identity_for_verified_location_in_tx_v1(db,
                    head=head, history=history, metadata=metadata, revision=revision,
                    grant_digest=grant_digest, imported=imported, continuation=continuation, anchor=current)
        _OWNERS[work] = (context, call, proof, lineage, observed)
        return observed, work.permit
    except BaseException:
        context.__exit__(None, None, None)
        raise


@contextmanager
def bind_d11_life_execution_owner_v1(work):
    from .owner_location_read_v3 import require_owner_location_caller_proof_v3
    state = _OWNERS.get(work)
    if state is None:
        raise AuthorityUnavailable("Life Source quantum has no complete original Owner lineage")
    proof, lineage = state[2], state[3]
    require_owner_location_caller_proof_v3(proof, phase="before")
    if not lineage.complete or lineage.released:
        raise AuthorityUnavailable("Life Owner lineage is not a complete retained original")
    lineage.facts.require_for_v3(proof)
    yield
    require_owner_location_caller_proof_v3(proof, phase="after")


def release_d11_life_execution_owner_v1(work):
    state = _OWNERS.pop(work, None)
    if state is not None:
        state[0].__exit__(None, None, None)

_OWN_METADATA_READS = WeakKeyDictionary()
_OWN_METADATA_ISSUER = object()


class _OwnLifePreparedMetadataReadV1:
    """A fixed bodyless read issued by the actual execute invocation."""
    def __init__(self, issuer, invocation):
        if issuer is not _OWN_METADATA_ISSUER:
            raise AuthorityUnavailable("own-Life metadata read needs its actual service producer")
        service = invocation.service()
        require_own_d11_life_invocation_v1(invocation, service=service, binding=invocation.binding)
        self.invocation, self.service, self.namespace = invocation, service, invocation.binding.namespace
        self.db = self.handle = self.operation = None
        self.closed = False
        self.identity = object()
        _OWN_METADATA_READS[self] = self.identity

    def require_current_v1(self):
        from ..runtime_storage_v3 import runtime_storage_v3
        if self.closed or _OWN_METADATA_READS.get(self) is not self.identity:
            raise AuthorityUnavailable("own-Life metadata read producer ended")
        require_own_d11_life_invocation_v1(self.invocation,
            service=self.service, binding=self.invocation.binding)
        if self.operation is not None and (self.operation.closed
                or self.operation.handle is not self.handle
                or runtime_storage_v3(self.db) is not self.handle):
            raise AuthorityUnavailable("own-Life metadata read crossed its actual selected operation")
        return self



class _OwnLifePreparedHeaderV1:
    __slots__ = ("kind", "prepared_digest", "binding")
    def __init__(self, kind, prepared_digest, binding):
        self.kind, self.prepared_digest, self.binding = kind, prepared_digest, binding


def authenticate_own_d11_life_prepared_header_v1(invocation):
    """Actual execute-entry metadata EOF; never read the Prepared Source copies."""
    import sqlite3
    from .daemon import _bootstrap_control_quantum_v3
    from ..runtime_storage_v3 import (
        bind_runtime_database_from_control_v3, begin_runtime_storage_operation_v3,
        bind_runtime_storage_operation_v3, runtime_storage_quantum_v3, finish_runtime_storage_operation_v3)
    from ..runtime.dispatch_initial_source_read_v3 import DispatchOriginalJSONReadV3
    from ..runtime.d11_life_preparation_v1 import TABLE, SIGN_KIND
    from ..runtime.d11_life_accounting_v1 import life_accounting_original_ref_v1, D11LifeAccountingPreparedV1
    from ..runtime.d11_life_contract_v1 import life_from_wire_v1, D11LifeExecutionBindingV1
    from ..runtime.d11_character_work_segment_v1 import (
        PREPARED_METADATA_KIND, character_labor_prepared_metadata_from_wire_v1)
    from ..domains.d01.production_operations_v1 import plain_v1
    from ..runtime_contracts import canonical_serialize
    from pathlib import Path
    service = invocation.service()
    require_own_d11_life_invocation_v1(invocation, service=service, binding=invocation.binding)
    if invocation.header is not None:
        return invocation.header
    if invocation.phase != "execute":
        raise AuthorityUnavailable("preclaim lookup belongs only to the actual execute invocation")
    binding, control = invocation.binding, _service(service, invocation.binding)

    owner = _OwnLifePreparedMetadataReadV1(_OWN_METADATA_ISSUER, invocation)
    try:
        with _bootstrap_control_quantum_v3(control):
            context = control.read_verified_current_storage_v3()
            context.require_current("business")
            member = next(m for m in context.manifest["members"] if m["role"] == "graph")
            if Path(member["resolved_path"]).resolve(strict=True) != service.graph_path:
                raise AuthorityUnavailable("own-Life metadata must use the current formally mapped Graph")
            owner.db = sqlite3.connect(service.graph_path.as_uri() + "?mode=ro", uri=True, isolation_level=None)
            owner.db.execute("PRAGMA query_only=ON")
            owner.handle = bind_runtime_database_from_control_v3(owner.db, control=control, role="graph")
        if owner.handle is None:
            raise AuthorityUnavailable("own-Life metadata has no actual bounded runtime handle")
        # Metadata observation has no business execution deadline. It cannot
        # reissue or extend the old job; a later fresh claim still uses its TTL.
        owner.operation = begin_runtime_storage_operation_v3(owner.db,
            "d11-own-metadata:" + binding.execution_id, None)
        metadata = column = header = None
        with bind_runtime_storage_operation_v3(owner.operation, owner.db):
            with runtime_storage_quantum_v3(owner.db) as meter:
                owner.db.execute("BEGIN")
                try:
                    headers = []
                    for kind in ("prepared", "character_labor_prepared_v1"):
                        row = meter.read_fixed_row(owner.db, TABLE,
                            ("producing_operation_id", "payload_digest", "signature"),
                            "bot=? AND persona=? AND kind=? AND original_ref=?",
                            (*binding.namespace.as_tuple, kind, binding.prepared_original_ref))
                        if row is not None:
                            service.issuer._signer.verify(SIGN_KIND, canonical_serialize((
                                binding.namespace, kind, binding.prepared_original_ref, row[1])), row[2])
                            headers.append((kind, row))
                    if len(headers) != 1 or headers[0][1][0] != binding.prepare_operation_id:
                        raise AuthorityUnavailable("own-Life lookup has no unique actual authenticated Prepared header")
                    kind, header = headers[0]
                    if kind == "character_labor_prepared_v1":
                        selected_kind, ref_value = PREPARED_METADATA_KIND, "character-labor-prepared-metadata:" + binding.execution_id
                    else:
                        selected_kind, ref_value = "accounting_prepared", life_accounting_original_ref_v1(binding)
                    metadata = meter.read_fixed_row(owner.db, TABLE,
                        ("producing_operation_id", "payload_digest", "signature"),
                        "bot=? AND persona=? AND kind=? AND original_ref=?",
                        (*binding.namespace.as_tuple, selected_kind, ref_value))
                    if metadata is None:
                        raise AuthorityUnavailable("own-Life metadata is not migrated; Prepared Body is not a fallback")
                    service.issuer._signer.verify(SIGN_KIND, canonical_serialize((
                        binding.namespace, selected_kind, ref_value, metadata[1])), metadata[2])
                    column = DispatchOriginalJSONReadV3(owner, table=TABLE, column="payload_json",
                        key_columns=("bot", "persona", "kind", "original_ref"),
                        key=(*binding.namespace.as_tuple, selected_kind, ref_value))
                except BaseException:
                    owner.db.execute("ROLLBACK")
                    raise
                else:
                    owner.db.execute("COMMIT")
        while not column.complete:
            owner.require_current_v1()
            with bind_runtime_storage_operation_v3(owner.operation, owner.db):
                with runtime_storage_quantum_v3(owner.db) as meter:
                    owner.db.execute("BEGIN")
                    try:
                        column.advance(meter)
                    except BaseException:
                        owner.db.execute("ROLLBACK")
                        raise
                    else:
                        owner.db.execute("COMMIT")
        raw = column.require_v3(owner)
        if column.sha256 != metadata[1] or metadata[0] != binding.prepare_operation_id:
            raise AuthorityUnavailable("own-Life bodyless metadata lost canonical signed EOF")
        if selected_kind == PREPARED_METADATA_KIND:
            value = character_labor_prepared_metadata_from_wire_v1(raw)
        else:
            raw = dict(raw)
            raw["binding"] = life_from_wire_v1(raw["binding"], D11LifeExecutionBindingV1)
            value = D11LifeAccountingPreparedV1(**raw)
        if value.binding != binding or value.prepared_digest != header[1]:
            raise AuthorityUnavailable("own-Life metadata differs from the actual requested binding/Prepared")
        invocation.header = _OwnLifePreparedHeaderV1(kind, header[1], binding)
        return invocation.header
    finally:
        owner.closed = True
        _OWN_METADATA_READS.pop(owner, None)
        try:
            if owner.operation is not None:
                finish_runtime_storage_operation_v3(owner.operation)
        finally:
            try:
                if owner.handle is not None:
                    owner.handle.close()
            finally:
                if owner.db is not None:
                    owner.db.close()


def read_own_d11_life_originals_v1(invocation, binding, *, work=None):
    """A closed own-lifecycle fact reader, never an accounting grant."""
    from .d11_life_journal_v1 import read_life_rows_locked_v1
    service = invocation.service()
    require_own_d11_life_invocation_v1(invocation, service=service, binding=binding)
    if work is None:
        header = authenticate_own_d11_life_prepared_header_v1(invocation)
    else:
        _require_work(work)
        from .character_labor_source_read_v1 import require_character_labor_source_metadata_v1
        metadata, _admission, _body = require_character_labor_source_metadata_v1(service, work)
        header = _OwnLifePreparedHeaderV1("character_labor_prepared_v1",
            metadata.prepared_digest, binding)
    with service._frozen() as (db, deletion, execution, _):
        from .v2_contract import JournalHead
        actual, claim, terminal, claim_row, terminal_row = read_life_rows_locked_v1(
            service.bridge.journal, binding)
        if actual != execution:
            raise AuthorityUnavailable("own-Life originals differ from the actual complete verified journal head")
        core_row = service.bridge.core._row(db, service.bridge.namespace)
        core_head = service.bridge.core._head(core_row, "execution")
        if core_head == actual:
            current, _ = service._current(db, deletion, execution)
            invocation.journal_ahead_unreconciled = None
        else:
            row = terminal_row or claim_row
            if work is not None or invocation.phase != "execute" or row is None:
                raise AuthorityUnavailable("own-Life unreconciled facts cannot qualify an adoption or Source Work")
            before = JournalHead(service.bridge.journal.journal_id, row[0] - 1, row[5])
            after = JournalHead(service.bridge.journal.journal_id, row[0], row[6])
            if core_head != before or actual != after:
                raise AuthorityUnavailable("own-Life lookup cannot skip unrelated or multiple journal-ahead rows")
            service.bridge._require_v2_mode_locked(db)
            service.bridge._check_deletion_locked(db, deletion)
            phase = "terminal" if terminal is not None else "claim"
            gate, stored = service._gate(db, binding, phase)
            current = service.bridge.core._anchor(db, service.bridge.namespace, core_row)
            if stored[6] != "active" or gate.pinned_anchor != current:
                raise AuthorityUnavailable("own-Life unreconciled fact lacks its actual original active gate")
            service.bridge.fences.validate_fence_locked(db, gate,
                subject=service._subject, current_anchor=current)
            if phase == "terminal" and gate.command_digest != "sha256:" + canonical_digest(
                    (binding.digest, claim.claim_digest)):
                raise AuthorityUnavailable("own-Life terminal-ahead continuation differs from its actual start")
            invocation.journal_ahead_unreconciled = (before, after, phase, gate)
        if work is not None:
            service.bridge.fences.validate_fence_locked(db, work.permit,
                subject=work.subject, current_anchor=current)
        elif invocation.phase != "execute":
            raise AuthorityUnavailable("own-Life history requires its current named adoption metadata Work")
        if claim is not None:
            service._verify_payload(claim.payload)
            if claim.payload.prepared_digest != header.prepared_digest:
                raise AuthorityUnavailable("own-Life start was produced for another actual Prepared")
        if terminal is not None:
            service._verify_payload(terminal.payload)
            if terminal.claim != claim or terminal.payload.prepared_digest != header.prepared_digest:
                raise AuthorityUnavailable("own-Life terminal lost its actual same-binding start")
        return claim, terminal



def require_own_life_adoption_bridge_identity_v1(service, binding, gate):
    """Authenticate an original ACK identity, without reading its retired execution history."""
    from .d11_life_bridge_v1 import D11LifeAdoptionBridgeV1, D11DraftSelfAdoptionBridgeV2
    from .d12_owner_storage_admission_v1 import InstalledD12OwnerStorageAdmissionServiceV1
    from .d12_target_owner_admission_v1 import InstalledD12TargetOwnerAdmissionServiceV1
    _service(service, binding)
    service._binding(binding)
    owner = service.owner_service
    if (type(owner) not in {InstalledD12OwnerStorageAdmissionServiceV1,InstalledD12TargetOwnerAdmissionServiceV1}
            or owner.namespace != service.bridge.namespace or owner.namespace_id != service.namespace
            or owner.installation_id != service.installation_id or owner.graph_path != service.graph_path):
        raise AuthorityUnavailable("own-Life ACK changed its actual installed Owner service")
    if (type(gate) not in {D11LifeAdoptionBridgeV1, D11DraftSelfAdoptionBridgeV2}
            or gate.binding != binding or gate.permit.operation != "write"
            or gate.permit.operation_id != service._gate_id(binding, "adoption")
            or gate.permit.namespace != service.bridge.namespace
            or gate.permit.subject != service._subject
            or gate.permit.pinned_anchor != gate.after_anchor):
        raise AuthorityUnavailable("own-Life status/finish needs its exact original named adoption bridge")
    with service._frozen() as (db, deletion, execution, _):
        current, holder = service._current(db, deletion, execution)
        row = service.bridge.fences._row(db, gate.permit.operation_id)
        if (row is None or service.bridge.fences._permit(row) != gate.permit
                or row[6] not in {"active", "finished"} or row[10] is not None
                or gate.permit.holder != holder):
            raise AuthorityUnavailable("own-Life bridge does not match its actual original Core fence")
        head = service.owner_tickets.current_migration_head_in_tx(db,authority_namespace=service.bridge.namespace)
        if (head is None or head.state != "active" or head.guard.namespace != service.namespace
                or head.guard.installation_id != service.installation_id
                or head.guard.pending_revoke_operation_id is not None):
            raise AuthorityUnavailable("own-Life ACK requires its actual current active Owner head")
        if row[6] == "finished" and row[8:10] not in {
                (gate.permit.operation_id+":"+outcome,
                    "sha256:"+canonical_digest((gate.qualification_digest,outcome)))
                for outcome in ("committed","abandoned")}:
            raise AuthorityUnavailable("own-Life ACK finished identity changed its original outcome tuple")
    return gate


def require_own_life_adoption_bridge_scope_v1(service, binding, gate):
    """Authenticate the complete actual interval for an active bridge or strict status."""
    from .d11_life_journal_v1 import read_life_rows_locked_v1
    require_own_life_adoption_bridge_identity_v1(service,binding,gate)
    with service._frozen() as (db,deletion,execution,_):
        current,holder = service._current(db,deletion,execution)
        row = service.bridge.fences._row(db,gate.permit.operation_id)
        if (row is None or service.bridge.fences._permit(row) != gate.permit
                or row[6] not in {"active","finished"} or row[10] is not None
                or gate.permit.holder != holder):
            raise AuthorityUnavailable("own-Life bridge changed after actual identity authentication")
        actual, claim, terminal, claim_row, terminal_row = read_life_rows_locked_v1(
            service.bridge.journal, binding)
        if (actual != execution or claim is None or terminal is None
                or terminal != gate.terminal or terminal.claim != claim
                or claim.payload.prepared_digest != gate.prepared_digest
                or terminal.payload.prepared_digest != gate.prepared_digest
                or claim_row[0] != gate.before_anchor.execution_seq + 1
                or claim_row[5] != gate.before_anchor.execution_digest
                or terminal_row[0] != claim_row[0] + 1 or terminal_row[5] != claim_row[6]
                or terminal_row[0] != gate.after_anchor.execution_seq
                or terminal_row[6] != gate.after_anchor.execution_digest):
            raise AuthorityUnavailable("own-Life bridge lost its complete actual start/terminal interval")
        service._verify_payload(claim.payload)
        service._verify_payload(terminal.payload)
        if row[6] == "active":
            service.bridge.fences.validate_fence_locked(db, gate.permit,
                subject=service._subject, current_anchor=current)
        elif row[8:10] not in {
                (gate.permit.operation_id + ":" + outcome,
                 "sha256:" + canonical_digest((gate.qualification_digest, outcome)))
                for outcome in ("committed", "abandoned")}:
            raise AuthorityUnavailable("own-Life finished adoption gate changed its exact outcome commitment")
    return gate
