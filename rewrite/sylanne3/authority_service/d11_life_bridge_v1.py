"""Exact own-execution continuation for an independently completed clock tick.

The wire value is evidence, not an admission. Only the concrete installed
service can reread its journal, current Owner, and frozen Graph to issue it.
"""
from ..runtime.d11_life_contract_v1 import LIFE_BINDING_TYPES, LIFE_CLAIM_TYPES, LIFE_TERMINAL_TYPES
from dataclasses import asdict, dataclass, fields
import json
import sqlite3

from .contract import AuthorityUnavailable
from ..runtime.d11_life_contract_v1 import (
    D11LifeExecutionBindingV1, D11LifeTerminalV1,
    life_from_wire_v1, life_to_wire_v1,
)
from .d11_life_journal_v1 import read_life_rows_locked_v1
from .d12_target_owner_admission_v1 import (
    D12CurrentOwnerAuthorityV1, current_owner_authority_from_wire_v1,
    current_owner_authority_to_wire_v1,
)
from .v2_contract import FencePermitV2, from_wire as fence_from_wire, to_wire as fence_to_wire
from ..runtime.restore_anchor import RestoreAnchor
from ..runtime_contracts import canonical_digest, canonical_serialize, SnapshotRequirementsV2
from ..runtime.d11_life_contract_v1 import D11DraftExecutionBindingV1,D11DraftTerminalV1
from .v2_self_identity_contract import AuthorityCurrentSelfIdentityV1,from_wire as self_from_wire,to_wire as self_to_wire


_LOCATION_FIELDS = ("authority_id", "namespace", "activation_generation", "revocation_epoch",
    "deletion_journal_id", "deletion_seq", "deletion_digest", "execution_journal_id")
_ANCHOR_FIELDS = (*_LOCATION_FIELDS, "execution_seq", "execution_digest")


def _same_location(before, after):
    return all(getattr(before, name) == getattr(after, name) for name in _LOCATION_FIELDS)


def _requirements_match(requirements, anchor):
    return (requirements.authority_namespace == anchor.namespace
        and all(getattr(requirements, name) == getattr(anchor, name)
            for name in _ANCHOR_FIELDS if name != "namespace"))


@dataclass(frozen=True, slots=True)
class D11LifeAdoptionBridgeV1:
    binding: D11LifeExecutionBindingV1
    terminal: D11LifeTerminalV1
    owner_authority: D12CurrentOwnerAuthorityV1
    owner_actor_id: str
    prepared_digest: str
    before_requirements_json: str
    before_graph_revision: int
    before_graph_epoch: int
    before_anchor: RestoreAnchor
    after_anchor: RestoreAnchor
    permit: FencePermitV2
    qualification_digest: str
    schema: str = "d11.life-tick-adoption-bridge.v1"

    def __post_init__(self):
        from ..runtime.d10_offline_tick_execution_v1 import _decode_json
        if (self.schema != "d11.life-tick-adoption-bridge.v1"
                or type(self.binding) is not D11LifeExecutionBindingV1
                or type(self.terminal) is not D11LifeTerminalV1
                or self.terminal.binding != self.binding
                or type(self.owner_authority) is not D12CurrentOwnerAuthorityV1
                or type(self.owner_actor_id) is not str or not self.owner_actor_id
                or type(self.before_anchor) is not RestoreAnchor or type(self.after_anchor) is not RestoreAnchor
                or type(self.permit) is not FencePermitV2 or self.permit.operation != "write"
                or self.permit.pinned_anchor != self.after_anchor
                or self.permit.namespace != self.binding.authority_namespace
                or self.permit.authority_id != self.binding.authority_id
                or self.permit.generation != self.binding.activation_generation
                or self.owner_authority.guard.namespace != self.binding.namespace
                or not _same_location(self.before_anchor, self.after_anchor)
                or self.terminal.claim.claim_sequence != self.before_anchor.execution_seq + 1
                or self.terminal.terminal_sequence != self.terminal.claim.claim_sequence + 1
                or self.after_anchor.execution_seq != self.terminal.terminal_sequence
                or self.after_anchor.execution_digest != self.terminal.terminal_digest
                or self.terminal.journal_id != self.after_anchor.execution_journal_id
                or self.prepared_digest != self.terminal.payload.prepared_digest
                or any(type(value) is not int or value < 0 for value in
                    (self.before_graph_revision, self.before_graph_epoch))):
            raise ValueError("life bridge is not its exact own claim/terminal transition")
        requirements = _decode_json(self.before_requirements_json, SnapshotRequirementsV2)
        if requirements.namespace != self.binding.namespace or not _requirements_match(requirements, self.before_anchor):
            raise ValueError("life bridge frozen requirements differ from original claim anchor")
        if self.qualification_digest != bridge_digest_v1(self):
            raise ValueError("life bridge qualification commitment differs")


def life_bridge_to_wire_v1(value):
    if type(value) not in {D11LifeAdoptionBridgeV1,D11DraftSelfAdoptionBridgeV2}:
        raise TypeError("exact life bridge required")
    raw = asdict(value)
    raw["binding"] = life_to_wire_v1(value.binding)
    raw["terminal"] = life_to_wire_v1(value.terminal)
    raw["owner_authority"] = current_owner_authority_to_wire_v1(value.owner_authority)
    if type(value) is D11DraftSelfAdoptionBridgeV2:raw["current_self"]=self_to_wire(value.current_self)
    raw["permit"] = fence_to_wire(value.permit)
    return raw


def bridge_digest_v1(value):
    raw = life_bridge_to_wire_v1(value)
    del raw["qualification_digest"]
    return canonical_digest(raw)


def life_bridge_from_wire_v1(raw):
    kind=D11DraftSelfAdoptionBridgeV2 if type(raw) is dict and raw.get("schema")=="d11.draft-self-adoption-bridge.v2" else D11LifeAdoptionBridgeV1
    if type(raw) is not dict or set(raw) != {field.name for field in fields(kind)}:
        raise ValueError("life bridge wire fields differ")
    values = dict(raw)
    values["binding"] = life_from_wire_v1(values["binding"], D11LifeExecutionBindingV1)
    values["terminal"] = life_from_wire_v1(values["terminal"], D11LifeTerminalV1)
    values["owner_authority"] = current_owner_authority_from_wire_v1(values["owner_authority"])
    if kind is D11DraftSelfAdoptionBridgeV2:values["current_self"]=self_from_wire(values["current_self"],AuthorityCurrentSelfIdentityV1)
    values["permit"] = fence_from_wire(values["permit"])
    for name in ("before_anchor", "after_anchor"):
        values[name] = RestoreAnchor(**values[name])
    value = kind(**values)
    if life_bridge_to_wire_v1(value) != raw:
        raise ValueError("life bridge wire is noncanonical")
    return value


@dataclass(frozen=True,slots=True)
class D11DraftSelfAdoptionBridgeV2:
    binding:D11DraftExecutionBindingV1
    terminal:D11DraftTerminalV1
    owner_authority:D12CurrentOwnerAuthorityV1
    current_self:AuthorityCurrentSelfIdentityV1
    activity_scope_ref:str
    activity_scope_digest:str
    prepared_digest:str
    before_requirements_json:str
    before_graph_revision:int
    before_graph_epoch:int
    before_anchor:RestoreAnchor
    after_anchor:RestoreAnchor
    permit:FencePermitV2
    qualification_digest:str
    schema:str="d11.draft-self-adoption-bridge.v2"

    def __post_init__(self):
        from ..runtime.d10_offline_tick_execution_v1 import _decode_json
        if (self.schema!="d11.draft-self-adoption-bridge.v2" or type(self.binding) is not D11DraftExecutionBindingV1
                or type(self.terminal) is not D11DraftTerminalV1 or self.terminal.binding!=self.binding
                or type(self.owner_authority) is not D12CurrentOwnerAuthorityV1 or type(self.current_self) is not AuthorityCurrentSelfIdentityV1
                or type(self.permit) is not FencePermitV2 or self.permit.operation!="write"
                or self.permit.pinned_anchor!=self.after_anchor or self.current_self.permit!=self.permit
                or (self.current_self.namespace,self.current_self.installation_id,self.current_self.manifest_digest,
                    self.current_self.graph_revision,self.current_self.graph_epoch)!=(self.binding.namespace,self.binding.installation_id,
                    self.binding.manifest_digest,self.before_graph_revision,self.before_graph_epoch)
                or (self.activity_scope_ref,self.activity_scope_digest)!=(self.binding.activity_scope_ref,self.binding.activity_scope_digest)
                or not _same_location(self.before_anchor,self.after_anchor)
                or self.terminal.claim.claim_sequence!=self.before_anchor.execution_seq+1
                or self.terminal.terminal_sequence!=self.terminal.claim.claim_sequence+1
                or (self.after_anchor.execution_seq,self.after_anchor.execution_digest)!=(self.terminal.terminal_sequence,self.terminal.terminal_digest)
                or self.prepared_digest!=self.terminal.payload.prepared_digest):
            raise ValueError("draft self bridge is not its exact original current-self/own-effect interval")
        requirements=_decode_json(self.before_requirements_json,SnapshotRequirementsV2)
        if not _requirements_match(requirements,self.before_anchor) or self.qualification_digest!=bridge_digest_v1(self):
            raise ValueError("draft self bridge original requirements/commitment differs")


def _draft_current_self(service,binding,permit,before,owner):
    """Actual Self service and private exact own interval; no caller anchor API."""
    from .v2_self_identity_service import AuthorityV2SelfIdentityService
    from .v2_self_identity_contract import SelfIdentityCurrentRequestV1
    actual=service.draft_self_identity
    if (type(actual) is not AuthorityV2SelfIdentityService or actual._core is not service.bridge.core
            or actual._fences is not service.fences or actual._source_location is not service.current_source_location
            or actual._graph._path!=service.graph_path or actual._installation_id!=service.installation_id):
        raise AuthorityUnavailable("actual same-installation draft current-self service absent")
    actual._core._require(service.draft_self_read_credential,"self_identity_read",binding.authority_namespace,actual._holder)
    location=service.current_source_location.observe_d11_life_interval_for_fence_v1(
        credential=service.credential,subject=service._subject,permit=permit,service=service,binding=binding)
    request=SelfIdentityCurrentRequestV1(binding.authority_id,binding.authority_namespace,binding.namespace,
        binding.installation_id,binding.manifest_digest,permit.operation_id,permit)
    with service._frozen() as (db,deletion,execution,history):
        if _originals_locked(service,db,binding,execution)[0]!=before:raise AuthorityUnavailable("draft self original interval changed")
        observed=actual._read_locked(db,deletion,execution,history,service.draft_self_read_credential,service._subject,request,location)
    if observed is None:raise AuthorityUnavailable("actual draft self registration revoked or absent")
    head,guard,anchor,_=observed
    if guard!=owner.guard:raise AuthorityUnavailable("draft current self and actual upstream Owner guards differ")
    db=sqlite3.connect(service.graph_path.as_uri()+"?mode=ro",uri=True,isolation_level=None)
    try:
        db.execute("PRAGMA query_only=ON");db.execute("BEGIN")
        service.current_source_location.require_graph_snapshot_v1(db,location)
        from ..runtime.d11_life_preparation_v1 import _read
        from ..runtime.d11_artifact_draft_contract_v1 import DraftActivityScopeV1,draft_from_wire_v1
        raw=_read(db,issuer=service.issuer,namespace=binding.namespace,kind="activity_scope",ref=binding.activity_scope_ref)
        scope=draft_from_wire_v1(raw[0],DraftActivityScopeV1) if raw else None
        if (scope is None or scope.actor_ref!=head[4] or canonical_digest(raw[0])!=binding.activity_scope_digest):
            raise AuthorityUnavailable("draft scope is not the actual pinned current self original")
        graph=actual._graph._check(db,binding.namespace,before,binding.installation_id,guard,
            location_observation=location,storage_admission=owner.storage_admission,holder=permit.holder)
    finally:db.close()
    if graph is None:raise AuthorityUnavailable("draft self actual D01 role/Owner/Graph proof unavailable")
    with service._frozen() as (db,deletion,execution,history):
        if actual._read_locked(db,deletion,execution,history,service.credential,service._subject,request,location)!=observed:
            raise AuthorityUnavailable("draft current self changed during independent exact interval read")
    incarnation,role,revision,epoch=graph
    admission=owner.storage_admission
    return AuthorityCurrentSelfIdentityV1(binding.namespace,binding.authority_namespace,binding.authority_id,
        binding.installation_id,binding.manifest_digest,binding.activation_generation,incarnation,role,revision,epoch,
        "persona:"+binding.namespace.persona_id,head[4],head[3],head[5],head[6],head[8],head[9],
        guard.authorization_revision,guard.authorization_head,guard.minimum_revocation_revision,guard.minimum_revocation_epoch,
        permit.operation_id,permit,origin_graph_incarnation=None if admission is None else admission.source_graph_incarnation,
        storage_admission_digest=None if admission is None else admission.original_digest)


def _make_bridge(**values):
    # Compute the commitment over the same closed wire before constructing the
    # strict DTO. No object identity here confers permission.
    raw = dict(values, schema="d11.life-tick-adoption-bridge.v1")
    raw["binding"] = life_to_wire_v1(values["binding"])
    raw["terminal"] = life_to_wire_v1(values["terminal"])
    raw["owner_authority"] = current_owner_authority_to_wire_v1(values["owner_authority"])
    raw["permit"] = fence_to_wire(values["permit"])
    raw["before_anchor"] = asdict(values["before_anchor"])
    raw["after_anchor"] = asdict(values["after_anchor"])
    return D11LifeAdoptionBridgeV1(**values, qualification_digest=canonical_digest(raw))


def _originals_locked(service, db, binding, execution):
    head, claim, terminal, claim_row, terminal_row = read_life_rows_locked_v1(service.bridge.journal, binding)
    if claim is None or terminal is None:
        raise AuthorityUnavailable("life adoption needs an actual durable terminal")
    service._verify_payload(claim.payload)
    service._verify_payload(terminal.payload)
    source, source_row = service._gate(db, binding, "claim")
    before = source.pinned_anchor
    if (head != execution or source_row[6] != "finished"
            or claim_row[0] != before.execution_seq + 1 or claim_row[5] != before.execution_digest
            or terminal_row[0] != claim_row[0] + 1 or terminal_row[5] != claim_row[6]
            or (execution.seq, execution.digest) != (terminal_row[0], terminal_row[6])):
        raise AuthorityUnavailable("life adoption cannot skip interleaved or later execution rows")
    return before, source, terminal


def _owner_observation(service, binding, permit, before):
    """Read actual source/target Owner over this authenticated own interval."""
    from .d12_owner_storage_admission_v1 import InstalledD12OwnerStorageAdmissionServiceV1
    owner_service = service.owner_service
    with service._frozen() as (db, deletion, execution, _):
        anchor, holder = service._current(db, deletion, execution)
        service.bridge.fences.validate_fence_locked(db, permit, subject=service._subject, current_anchor=anchor)
        actual_before, _, _ = _originals_locked(service, db, binding, execution)
        if actual_before != before or not _same_location(before, anchor) or holder != owner_service.holder:
            raise AuthorityUnavailable("life current Owner location changed")
        head = service.owner_tickets.current_migration_head_in_tx(db, authority_namespace=service.bridge.namespace)
        if head is None or head.state != "active":
            raise AuthorityUnavailable("life current Owner head unavailable")
        if type(owner_service) is InstalledD12OwnerStorageAdmissionServiceV1:
            if owner_service._head_in_tx(db) != head:
                raise AuthorityUnavailable("life source Owner differs")
            actor, _ = owner_service._background_identity_in_tx(db, head)
            history = None
        else:
            history = owner_service._current_transfer(db, generation=anchor.activation_generation)
            actor = None
    if history is None:
        _, _, admission = owner_service._read_graph(owner_head=head, anchor=before)
        observed = D12CurrentOwnerAuthorityV1(head.guard, None, admission)
    else:
        location = owner_service._read_graph(history=history, owner_head=head, anchor=before)
    with service._frozen() as (db, deletion, execution, _):
        current, _ = service._current(db, deletion, execution)
        service.bridge.fences.validate_fence_locked(db, permit, subject=service._subject, current_anchor=current)
        if current != anchor or service.owner_tickets.current_migration_head_in_tx(db,
                authority_namespace=service.bridge.namespace) != head:
            raise AuthorityUnavailable("life Owner changed during independent location read")
        if history is None:
            if owner_service._background_identity_in_tx(db, head)[0] != actor:
                raise AuthorityUnavailable("life source Owner actor changed")
        else:
            metadata, revision, grant_digest, imported, continuation = location
            observed = owner_service._current_background_identity_for_verified_location_in_tx_v1(db,
                head=head, history=history, metadata=metadata, revision=revision,
                grant_digest=grant_digest, imported=imported, continuation=continuation, anchor=current)
            actor = owner_service.sessions._current_pairing_source.current_principal_binding(
                authority_namespace=service.bridge.namespace, installation_id=service.installation_id,
                principal=head.issue_operation.principal)
            if actor is None:
                raise AuthorityUnavailable("life target current Owner actor unavailable")
    return observed, actor.actor_id


def _observe_bridge(service, binding, permit):
    with service._frozen() as (db, deletion, execution, _):
        after, holder = service._current(db, deletion, execution)
        before, source, terminal = _originals_locked(service, db, binding, execution)
        if not _same_location(before, after) or source.holder != holder:
            raise AuthorityUnavailable("life transition crossed deletion, generation or holder")
        service.bridge.fences.validate_fence_locked(db, permit, subject=service._subject, current_anchor=after)
    prepared = service._prepared(binding, for_execution=False, permit=permit)
    service._prepared_anchor(prepared, before)
    if prepared.digest != terminal.payload.prepared_digest:
        raise AuthorityUnavailable("life terminal preparation commitment changed")
    owner, actor_id = _owner_observation(service, binding, permit, before)
    current_self=_draft_current_self(service,binding,permit,before,owner) if type(binding) is D11DraftExecutionBindingV1 else None
    with service._frozen() as (db, deletion, execution, _):
        current, _ = service._current(db, deletion, execution)
        actual_before, _, actual_terminal = _originals_locked(service, db, binding, execution)
        service.bridge.fences.validate_fence_locked(db, permit, subject=service._subject, current_anchor=current)
        if (current, actual_before, actual_terminal) != (after, before, terminal):
            raise AuthorityUnavailable("life terminal interval changed after outside-SQL read")
        service._owner_current(db, binding, prepared, owner)
    if current_self is not None:
        values=dict(binding=binding,terminal=terminal,owner_authority=owner,current_self=current_self,
            activity_scope_ref=binding.activity_scope_ref,activity_scope_digest=binding.activity_scope_digest,
            prepared_digest=prepared.digest,before_requirements_json=prepared.requirements_json,
            before_graph_revision=prepared.graph_revision,before_graph_epoch=prepared.graph_epoch,
            before_anchor=before,after_anchor=after,permit=permit)
        raw=dict(values,schema="d11.draft-self-adoption-bridge.v2")
        raw["binding"]=life_to_wire_v1(binding);raw["terminal"]=life_to_wire_v1(terminal)
        raw["owner_authority"]=current_owner_authority_to_wire_v1(owner)
        raw["current_self"]=self_to_wire(current_self);raw["permit"]=fence_to_wire(permit)
        raw["before_anchor"]=asdict(before);raw["after_anchor"]=asdict(after)
        return D11DraftSelfAdoptionBridgeV2(**values,qualification_digest=canonical_digest(raw))
    return _make_bridge(binding=binding, terminal=terminal, owner_authority=owner, owner_actor_id=actor_id,
        prepared_digest=prepared.digest, before_requirements_json=prepared.requirements_json,
        before_graph_revision=prepared.graph_revision, before_graph_epoch=prepared.graph_epoch,
        before_anchor=before, after_anchor=after, permit=permit)


def operate_life_adoption_bridge_v1(service, binding, action, gate=None, outcome=None):
    from .d11_life_service_v1 import AuthorityD11LifeServiceV1
    if type(service) is not AuthorityD11LifeServiceV1 or action not in {"begin", "validate", "finish", "status"}:
        raise AuthorityUnavailable("actual installed life bridge and closed operation required")
    if action in {"finish", "status"}:
        from .d11_life_historical_accounting_v1 import _scope
        _scope(service, binding)
    else:
        service._binding(binding)
    service.bridge.core._require(service.credential, "current", service.bridge.namespace)
    operation_id = service._gate_id(binding, "adoption")
    if action != "begin" and (type(gate) not in {D11LifeAdoptionBridgeV1,D11DraftSelfAdoptionBridgeV2}
            or gate.binding != binding or gate.permit.operation_id != operation_id):
        raise AuthorityUnavailable("life exact original bridge required")
    if action in {"finish", "status"}:
        with service.bridge.core._tx() as db:
            row = service.bridge.fences._row(db, operation_id)
            if row is None or service.bridge.fences._permit(row) != gate.permit:
                raise AuthorityUnavailable("life actual bridge gate differs")
            if action == "status":
                if row[6] not in {"active", "finished"}:
                    raise AuthorityUnavailable("life gate has an unsupported state")
                return row[6]
            if outcome not in {"committed", "abandoned"}:
                raise AuthorityUnavailable("life finish requires an exact outcome")
            finish = (operation_id + ":" + outcome, "sha256:" + canonical_digest((gate.qualification_digest, outcome)))
            if row[6] == "finished":
                if row[8:10] != finish:
                    raise AuthorityUnavailable("life finished bridge replay changed outcome")
                return True
        _verify_graph_finish(service, gate, outcome)
        with service._frozen() as (db, deletion, execution, _):
            current = service.fences._current_locked(db, deletion, execution, require_clear=False)
            service.bridge.fences.validate_fence_locked(db, gate.permit, subject=service._subject, current_anchor=current)
            service.bridge.fences.finish_fence_locked(db, gate.permit, subject=service._subject,
                current_anchor=current, request_id=finish[0], request_digest=finish[1])
        return True
    if action == "begin":
        service._recover_committed_append(binding)
        with service._frozen() as (db, deletion, execution, _):
            from .d12_lifecycle_gate_v1 import require_lifecycle_admission_in_tx_v1
            after, holder = service._current(db, deletion, execution)
            before, source, _ = _originals_locked(service, db, binding, execution)
            if not _same_location(before, after) or source.holder != holder:
                raise AuthorityUnavailable("life own interval crossed its actual location")
            require_lifecycle_admission_in_tx_v1(db, service.bridge.namespace, action="life_adoption")
            permit = service.bridge.fences.begin_fence_locked(db, subject=service._subject,
                holder=holder, operation="write", current_anchor=after, operation_id=operation_id)
        try:
            return _observe_bridge(service, binding, permit)
        except BaseException:
            # No content mutation occurs during observation. Close exactly
            # this still-current unused permit; ambiguity remains recoverable.
            with service._frozen() as (db, deletion, execution, _):
                current, _ = service._current(db, deletion, execution)
                service.bridge.fences.finish_fence_locked(db, permit, subject=service._subject,
                    current_anchor=current, request_id=operation_id + ":rejected",
                    request_digest="sha256:" + canonical_digest((binding.digest, "adoption-rejected")))
            raise
    if _observe_bridge(service, binding, gate.permit) != gate:
        raise AuthorityUnavailable("life independently reread bridge changed")
    return gate


def _verify_graph_finish(service, gate, outcome):
    from ..runtime.d11_life_adoption_v1 import verify_life_adoption_commit_v1
    db = sqlite3.connect(service.graph_path.as_uri() + "?mode=ro", uri=True, isolation_level=None)
    try:
        db.execute("PRAGMA query_only=ON")
        db.execute("BEGIN")
        if outcome == "committed":
            verify_life_adoption_commit_v1(db, gate=gate, issuer=service.issuer,
                resource_issuer=service.resource_issuer)
        else:
            from ..runtime.d11_life_terminal_v1 import life_adoption_operation_id_v1
            metadata = db.execute("SELECT requirements_json,graph_revision FROM graph_recovery_metadata_v2 "
                "WHERE bot=? AND persona=?", gate.binding.namespace.as_tuple).fetchone()
            epoch = db.execute("SELECT revision FROM graph_epochs WHERE bot=? AND persona=?", gate.binding.namespace.as_tuple).fetchone()
            prior = db.execute("SELECT 1 FROM graph_bundle_operations WHERE bot=? AND persona=? AND operation_id=?",
                (*gate.binding.namespace.as_tuple, life_adoption_operation_id_v1(gate.binding))).fetchone()
            if (prior is not None or metadata != (gate.before_requirements_json, gate.before_graph_revision)
                    or epoch != (gate.before_graph_epoch,)):
                raise AuthorityUnavailable("life abandon cannot erase an actual or changed commit")
    finally:
        db.close()
