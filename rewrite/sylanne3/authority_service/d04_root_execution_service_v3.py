"""Installed independent Authority for once-only Owner-authored root CPU.

Root identities and codecs are disjoint from joint numeric jobs. Graph reads
precede short Core final checks, and journal commits precede Core consumption.
"""
from contextlib import contextmanager
from dataclasses import asdict,replace
import hashlib,hmac,json,sqlite3
from pathlib import Path
from ..runtime_contracts import NamespaceId,canonical_serialize,canonical_digest
from ..runtime.restore_anchor import RestoreAnchor
from .contract import AuthorityUnavailable,JournalHead,identifier
from .d12_target_owner_admission_v1 import current_owner_authority_material_v1
from .v2_execution_bridge import AuthorityV2ExecutionBridge
from .v2_owner_ticket_store import AuthorityV2OwnerTicketStore
from .d04_root_execution_contract_v3 import (D04RootExecutionBindingV3,D04RootExecutionClaimV3,
    D04RootExecutionMeasurementV3,D04RootExecutionTerminalV3,D04RootMeasuredCostClosureV3,
    root_execution_to_wire_v3 as to_wire,root_execution_from_wire_v3)
from .d04_root_execution_journal_v3 import (append_root_execution_entry_locked_v3,
    read_root_execution_rows_locked_v3,root_mutation_id_v3,root_gate_operation_id_v3,root_cost_closure_basis_v3)
from .d04_root_execution_bridge_v3 import D04RootOriginalAppendV3,D04RootAdoptionBridgeV3,D04RootRestoreOriginalV3

class AuthorityD04RootExecutionServiceV3:
    def __init__(self, *, bridge, owner_tickets, namespace, installation_id,
                 graph_db_path, resource_issuer, budget_issuer, credential, signing_key,
                 trusted_now_utc, installed_identity, target_owner_service=None, historical_recipe_reader=None, storage_owner_service=None):
        from ..graph_coordinator import namespace_ref
        from ..runtime.issuers import D11BudgetGrantIssuer
        if (type(bridge) is not AuthorityV2ExecutionBridge
                or type(owner_tickets) is not AuthorityV2OwnerTicketStore
                or owner_tickets._core is not bridge.core
                or type(namespace) is not NamespaceId
                or namespace_ref(namespace) != bridge.namespace
                or type(signing_key) is not bytes or len(signing_key) != 32
                or not callable(trusted_now_utc) or not isinstance(budget_issuer,D11BudgetGrantIssuer)
                or not callable(getattr(resource_issuer, "original_signed_quote", None))):
            raise AuthorityUnavailable("installed D04 root authority is incomplete")
        identifier(installation_id, "installation_id")
        required = {"algorithm_id", "algorithm_build_digest", "native_manifest_sha256",
                    "native_sha256", "output_policy_digest", "preset_id", "preset_digest"}
        if type(installed_identity) is not dict or set(installed_identity) != required:
            raise AuthorityUnavailable("D04 pinned algorithm/native/output identity unavailable")
        graph = Path(graph_db_path).resolve(strict=True)
        if not graph.is_file():
            raise AuthorityUnavailable("installed D04 Graph file unavailable")
        self.bridge, self.owner_tickets, self.namespace = bridge, owner_tickets, namespace
        self.installation_id, self.graph_path = installation_id, graph
        self.resource_issuer, self.budget_issuer, self.credential = resource_issuer, budget_issuer, credential
        self._key, self._clock, self._identity = signing_key, trusted_now_utc, dict(installed_identity)
        if target_owner_service is not None:
            from .d12_target_owner_admission_v1 import InstalledD12TargetOwnerAdmissionServiceV1
            if (type(target_owner_service) is not InstalledD12TargetOwnerAdmissionServiceV1
                    or target_owner_service.core is not bridge.core or target_owner_service.installation_id != installation_id):
                raise AuthorityUnavailable("root target Owner authority differs")
        self.target_owner_service = target_owner_service
        self.storage_owner_service=None
        if storage_owner_service is not None:self.install_storage_owner_service_v1(storage_owner_service)
        if historical_recipe_reader is not None:
            from .d12_historical_d04_recipe_v1 import InstalledHistoricalD04RecipeReaderV1
            if (type(historical_recipe_reader) is not InstalledHistoricalD04RecipeReaderV1
                    or historical_recipe_reader.namespace!=namespace or historical_recipe_reader.installation_id!=installation_id
                    or historical_recipe_reader.current_manifest_sha256!=installed_identity["native_manifest_sha256"]):
                raise AuthorityUnavailable("installed historical recipe reader differs from current composition")
        self.historical_recipe_reader=historical_recipe_reader
        self._subject = "d04-root:" + installation_id

    def install_storage_owner_service_v1(self, service):
        """One exact installed continuation; a different replacement is denied."""
        from .d12_owner_storage_admission_v1 import InstalledD12OwnerStorageAdmissionServiceV1
        if (type(service) is not InstalledD12OwnerStorageAdmissionServiceV1
                or service.core is not self.bridge.core or service.tickets is not self.owner_tickets
                or service.installation_id!=self.installation_id or service.namespace_id!=self.namespace
                or service.namespace!=self.bridge.namespace or service.graph_path!=self.graph_path
                or service.fences.fences is not self.bridge.fences
                or service.fences.deletion is not self.bridge.deletion
                or service.fences.execution is not self.bridge.journal
                or service.control is not getattr(self.bridge.core,'_c09_storage_reader_v1',None)):
            raise AuthorityUnavailable("source storage Owner service differs from actual composition")
        with self.bridge.core._lock:
            if self.storage_owner_service is not None and self.storage_owner_service is not service:
                raise AuthorityUnavailable("source storage Owner service already installed")
            self.storage_owner_service=service

    def _binding(self, binding):
        if (type(binding) is not D04RootExecutionBindingV3
                or binding.namespace != self.namespace
                or binding.authority_namespace != self.bridge.namespace
                or binding.installation_id != self.installation_id
                or any(getattr(binding, name) != value for name, value in self._identity.items())):
            raise AuthorityUnavailable("D04 root installed binding differs")

    def _binding_scope(self,binding):
        if (type(binding) is not D04RootExecutionBindingV3 or binding.namespace!=self.namespace
                or binding.authority_namespace!=self.bridge.namespace or binding.installation_id!=self.installation_id):
            raise AuthorityUnavailable("historical D04 namespace/installation differs")
        with self.bridge.core._lock:
            if binding.authority_id!=self.bridge.core._id(self.bridge.core._db):
                raise AuthorityUnavailable("historical D04 Authority identity differs")

    def _require_historical_binding(self,binding,claim):
        """Only after an actual journal lookup/strict decode; never a new claim."""
        self._binding_scope(binding)
        self._verify_claim(binding,claim)
        if all(getattr(binding,name)==value for name,value in self._identity.items()):
            return
        if self.historical_recipe_reader is None:
            raise AuthorityUnavailable("historical D04 recipe was not qualified at installed composition")
        self.historical_recipe_reader.require_qualified_recipe_v1(binding,kind="authored_root")

    def _sign(self, value):
        payload = asdict(value)
        payload.pop("signature")
        return hmac.new(self._key, canonical_serialize(payload).encode("utf-8"), hashlib.sha256).hexdigest()

    def _verify_claim(self, binding, claim):
        if (type(claim) is not D04RootExecutionClaimV3 or claim.binding_digest != binding.digest
                or claim.execution_id != binding.execution_id
                or claim.executor_installation_id != self.installation_id
                or claim.claim_id != root_mutation_id_v3(binding, "claim")
                or not hmac.compare_digest(claim.signature, self._sign(claim))):
            raise AuthorityUnavailable("D04 original signed claim differs")

    def _require_owner_locked(self, db, binding, owner_observation=None):
        from ..graph_types import owner_grant_key
        head = self.owner_tickets.current_migration_head_in_tx(
            db, authority_namespace=binding.authority_namespace)
        if (head is None or head.state != "active"
                or head.guard.authority_id != binding.authority_id
                or head.guard.namespace != binding.namespace
                or head.guard.pending_revoke_operation_id is not None
                or head.guard.minimum_revocation_epoch
                or head.guard.minimum_revocation_revision >= head.guard.authorization_revision
                or owner_grant_key(*binding.namespace.as_tuple).token != binding.owner_grant_ref
                or head.grant_revision != binding.owner_grant_revision
                or head.grant_digest.removeprefix("sha256:") != binding.owner_grant_digest):
            raise AuthorityUnavailable("D04 current committed Owner grant differs")
        if head.guard.installation_id != binding.installation_id:
            from .d12_target_owner_admission_v1 import D12CurrentOwnerAuthorityV1
            from .v2_owner_session import OwnerSessionLoginRequestV1
            observation = owner_observation
            if (type(observation) is not D12CurrentOwnerAuthorityV1 or observation.guard != head.guard
                    or observation.target_admission is None or self.target_owner_service is None):
                raise AuthorityUnavailable("root target needs current installed background admission")
            admission=observation.target_admission
            if (admission.target_installation_id!=self.installation_id or admission.source_grant_digest!=head.grant_digest
                    or admission.activation_generation!=binding.activation_generation
                    or db.execute("SELECT original_digest FROM authority_d12_target_owner_admissions_v1 WHERE original_ref=?",
                                  (admission.original_ref,)).fetchone()!=(admission.original_digest,)):
                raise AuthorityUnavailable("root target admission original differs")
            sessions=self.target_owner_service.sessions
            request=OwnerSessionLoginRequestV1(authority_id=binding.authority_id,
                authority_namespace=binding.authority_namespace,installation_id=self.installation_id,
                principal=admission.principal,credential_id=admission.target_credential_id,
                credential_epoch=admission.target_credential_epoch,audience="owner",
                dashboard_origin="https://installed.invalid")
            sessions._current_key(db,request)
            actor=sessions._current_pairing_source.require_current_actor_in_tx(db,authority_namespace=binding.authority_namespace,
                installation_id=self.installation_id,actor_id=admission.target_actor_id,principal=admission.principal)
            if actor.revision!=admission.target_actor_revision:
                raise AuthorityUnavailable("root target actor pairing changed")

    @contextmanager
    def _frozen(self):
        bridge=self.bridge
        with bridge.deletion.freeze_writes():
            with bridge.journal.freeze_writes():
                deletion=bridge.deletion.verified_head()
                execution=bridge.journal.verified_head()
                with bridge.core._tx() as db:
                    yield db,deletion,execution

    def _current_anchor_locked(self, db, deletion, execution, *, action="business"):
        bridge=self.bridge
        bridge._require_v2_mode_locked(db)
        bridge._check_deletion_locked(db,deletion)
        bridge._check_execution_head_locked(db,execution)
        row=bridge.core._row(db,bridge.namespace)
        if row[0] is None or row[2]!="active" or row[3] is not None or row[4] is not None or row[9]!="clear":
            raise AuthorityUnavailable("root installation namespace is not currently settled")
        storage=bridge.core.require_current_storage_generation_locked(db,namespace=bridge.namespace,action=action)
        graph_member=next(item for item in storage.manifest["members"] if item["role"]=="graph")
        if (graph_member["resolved_path"]!=str(self.graph_path) or graph_member["namespace"]!=bridge.namespace):
            raise AuthorityUnavailable("root installed Graph is not the selected current storage member")
        storage._reader.verify_member_v1(graph_member,prepared=False)
        if bridge.deletion.has_deletion_history(bridge.namespace):
            bridge.core.require_current_content_ready_locked(db,namespace=bridge.namespace)
        return bridge.core._anchor(db,bridge.namespace,row),row[0]

    def _gate_locked(self, db, binding, phase):
        row=self.bridge.fences._row(db,root_gate_operation_id_v3(binding,phase))
        if row is None:
            raise AuthorityUnavailable("original root exclusive gate is absent")
        permit=self.bridge.fences._permit(row)
        subject_ok=(permit.subject.startswith(self._subject+":claim:") if phase=="claim" else permit.subject==self._subject)
        if (permit.namespace!=binding.authority_namespace or not subject_ok
                or permit.generation!=binding.activation_generation or row[10] is not None):
            raise AuthorityUnavailable("original root gate identity differs")
        return permit,row

    def _consume_gate_locked(self, db, binding, phase, claim, row):
        permit,stored=self._gate_locked(db,binding,phase)
        expected=(None if phase=="claim" else "sha256:"+canonical_digest((binding.digest,claim.signature,"technical-originals")))
        expected_subject=(self._subject+":claim:"+canonical_digest((binding.digest,claim.executor_incarnation)) if phase=="claim" else self._subject)
        if permit.command_digest!=expected or permit.subject!=expected_subject or permit.operation!=("write" if phase=="claim" else "accounting"):
            raise AuthorityUnavailable("root consumed gate original commitment differs")
        if (permit.pinned_anchor.execution_seq+1!=row[0] or permit.pinned_anchor.execution_digest!=row[5]
                or phase=="claim" and row[0]!=claim.claim_sequence):
            raise AuthorityUnavailable("root append did not directly follow its exclusive gate")
        request_id=root_gate_operation_id_v3(binding,phase)+":consumed"
        request_digest="sha256:"+canonical_digest((binding.digest,claim.signature,row[1],row[6]))
        self.bridge.fences.finish_fence_locked(db,permit,subject=permit.subject,
            current_anchor=permit.pinned_anchor,request_id=request_id,request_digest=request_digest)
        return permit

    def _abandon_unappended_gate(self,binding,phase):
        # A denied preflight may close its own never-appended gate. A durable
        # claim/terminal is recovered by its original append instead, never reset.
        try:
            with self._frozen() as (db,deletion,execution):
                _,claim,_,_,terminal=read_root_execution_rows_locked_v3(self.bridge.journal,binding)
                if (claim is not None if phase=="claim" else terminal is not None):
                    return
                permit,row=self._gate_locked(db,binding,phase)
                if row[6]!="active":return
                anchor,_=self._current_anchor_locked(db,deletion,execution,action="recovery")
                self.bridge.fences.finish_fence_locked(db,permit,subject=permit.subject,current_anchor=anchor,
                    request_id=permit.operation_id+":unappended",request_digest="sha256:"+canonical_digest((binding.digest,"unappended",phase)))
        except Exception:
            # Unknown gate state is durable HOLD, never deletion or retry with
            # a fresh identity. The caller sees its original admission failure.
            return

    def _reconcile_locked(self, db, binding, row, actual_head):
        bridge = self.bridge
        bridge._require_v2_mode_locked(db)
        bridge.fences._check_schema(db)
        core_row = bridge.core._row(db, bridge.namespace)
        target = JournalHead(bridge.journal.journal_id, row[0], row[6])
        _,claim,_,claim_row,terminal_row=read_root_execution_rows_locked_v3(bridge.journal,binding)
        self._verify_claim(binding,claim)
        self._consume_gate_locked(db,binding,"claim",claim,claim_row)
        if terminal_row is not None:
            self._consume_gate_locked(db,binding,"original",claim,terminal_row)
        current = bridge.core._head(core_row, "execution")
        if current == actual_head and actual_head.seq >= target.seq:
            # A previously reconciled original remains readable after later
            # appends. The full-chain decoder proved the exact row above.
            return
        before = JournalHead(bridge.journal.journal_id, row[0] - 1, row[5])
        if actual_head != target or current != before:
            raise AuthorityUnavailable("D04 root Core head recovery requires exact next append")
        bridge.core.require_current_storage_generation_locked(db, namespace=bridge.namespace, action="recovery")
        db.execute("UPDATE authority_namespaces SET execution_seq=?,execution_digest=?,anchor_nonce=? "
                   "WHERE namespace=?", (target.seq, target.digest, bridge.core._new_nonce(), bridge.namespace))
        phase = "claim" if row[1] == root_mutation_id_v3(binding, "claim") else ("cost_only" if root_cost_closure_basis_v3(row) is not None else "terminal")
        bridge.core._event(db, bridge.namespace, "d04_root_" + phase,
                           core_row[1], (binding.digest, row[1], row[2], target.digest))

    def claim_d04_root_v3(self, binding, executor_incarnation):
        from .owner_location_read_v3 import _owner_location_service_invocation_v3
        with _owner_location_service_invocation_v3(self):
            self._binding(binding)
            identifier(executor_incarnation,"executor_incarnation")
            bridge=self.bridge
            bridge.core._require(self.credential,"execution",bridge.namespace)
            with self._frozen() as (db,deletion,before):
                _,old,_,old_row,terminal_row=read_root_execution_rows_locked_v3(bridge.journal,binding)
                if old is not None:
                    self._reconcile_locked(db,binding,terminal_row or old_row,before)
                else:
                    anchor,holder=self._current_anchor_locked(db,deletion,before)
                    if anchor.activation_generation!=binding.activation_generation:
                        raise AuthorityUnavailable("root source generation changed")
                    permit=bridge.fences.begin_fence_locked(db,
                        subject=self._subject+":claim:"+canonical_digest((binding.digest,executor_incarnation)),holder=holder,operation="write",
                        current_anchor=anchor,operation_id=root_gate_operation_id_v3(binding,"claim"))
            if old is not None:
                raise AuthorityUnavailable("D04 execution claim already consumed; inspect originals")
            try:
                # The exclusive durable permit now excludes cancellation/source
                # writes. Graph reads and any target Owner RPC are outside Core SQL.
                prepared=self._graph_read(binding)
                owner=self._owner_observation(permit,binding)
                claim=D04RootExecutionClaimV3(binding.digest,binding.execution_id,root_mutation_id_v3(binding,"claim"),
                    permit.pinned_anchor.execution_seq+1,self.installation_id,executor_incarnation,"pending")
                claim=replace(claim,signature=self._sign(claim))
                self._durable_append_v3(binding,permit,claim,None,prepared=prepared,owner=owner)
                return claim
            except BaseException:
                self._abandon_unappended_gate(binding,"claim")
                raise

    def read_d04_root_originals_v3(self, binding):
        """Content-free status; a claim-only result is unknown, never zero CPU."""
        self._binding_scope(binding)
        bridge = self.bridge
        bridge.core._require(self.credential, "current", bridge.namespace)
        with bridge.deletion.freeze_writes():
            with bridge.journal.freeze_writes():
                actual, claim, measurement, claim_row, terminal_row = read_root_execution_rows_locked_v3(bridge.journal, binding)
                if claim is None:
                    with bridge.core._tx() as db:
                        bridge._check_execution_head_locked(db, actual)
                    return None, None
                self._require_historical_binding(binding, claim)
                with bridge.core._tx() as db:
                    self._reconcile_locked(db, binding, terminal_row or claim_row, actual)
                return claim, None if terminal_row is None or root_cost_closure_basis_v3(terminal_row) is not None else self._terminal(binding, claim, measurement, terminal_row)

    def _terminal(self, binding, claim, measurement, row):
        if root_cost_closure_basis_v3(row) is not None:
            raise AuthorityUnavailable("cost-only closure is not a completed root artifact terminal")
        terminal = D04RootExecutionTerminalV3(binding, claim, measurement,
            root_mutation_id_v3(binding, "terminal"), row[0], row[6].removeprefix("sha256:"), "pending")
        return replace(terminal, signature=self._sign(terminal))

    def _read_graph_requirements_only(self):
        db=sqlite3.connect(self.graph_path.as_uri()+"?mode=ro",uri=True,isolation_level=None)
        try:
            row=db.execute("SELECT requirements_json,graph_revision FROM graph_recovery_metadata_v2 WHERE bot=? AND persona=?",self.namespace.as_tuple).fetchone()
            if row is None:raise AuthorityUnavailable("root actual Graph requirements absent")
            return json.loads(row[0]),row[1]
        finally:
            db.close()

    @staticmethod
    def _same_location_epoch(before, after):
        names=("authority_id","namespace","activation_generation","revocation_epoch",
            "deletion_journal_id","deletion_seq","deletion_digest","execution_journal_id")
        return all(getattr(before,key)==getattr(after,key) for key in names)

    def _graph_location_matches(self, metadata, anchor):
        return metadata.get("authority_namespace")==anchor.namespace and all(metadata.get(key)==getattr(anchor,key)
            for key in ("authority_id","activation_generation","revocation_epoch","deletion_journal_id",
                        "deletion_seq","deletion_digest","execution_journal_id"))

    def begin_d04_root_original_append_v3(self, binding, claim):
        """Technical-only fixed original insertion after an actually consumed claim.

        The returned accounting permit is consumed by the durable terminal
        append, not finished by a generic Graph write. No Graph epoch advances.
        Content-free measurements remain recordable after cancellation; full
        artifact bytes additionally require current source/job/Owner closure.
        """
        from .owner_location_read_v3 import _owner_location_service_invocation_v3
        with _owner_location_service_invocation_v3(self):
            self._binding(binding);self._verify_claim(binding,claim)
            bridge=self.bridge;bridge.core._require(self.credential,"execution",bridge.namespace)
            with self._frozen() as (db,deletion,execution):
                _,actual,measurement,claim_row,terminal_row=read_root_execution_rows_locked_v3(bridge.journal,binding)
                if actual!=claim:raise AuthorityUnavailable("technical original lacks its real consumed claim")
                self._reconcile_locked(db,binding,terminal_row or claim_row,execution)
                if terminal_row is not None:
                    raise AuthorityUnavailable("root terminal already durable; inspect this original")
                anchor,holder=self._current_anchor_locked(db,deletion,execution,action="accounting")
                source_permit,_=self._gate_locked(db,binding,"claim")
                if not self._same_location_epoch(source_permit.pinned_anchor,anchor):
                    raise AuthorityUnavailable("root technical append cannot restore a retired location/deletion epoch")
                permit=bridge.fences.begin_fence_locked(db,subject=self._subject,holder=holder,operation="accounting",
                    current_anchor=anchor,operation_id=root_gate_operation_id_v3(binding,"original"),
                    command_digest="sha256:"+canonical_digest((binding.digest,claim.signature,"technical-originals")))
            prepared,metadata,revision,_,_=self._read_original_payloads(binding)
            if not self._graph_location_matches(metadata,permit.pinned_anchor):
                raise AuthorityUnavailable("technical original Graph storage/deletion location differs")
            content=False;owner=None
            try:
                current_digest=self._content_retention_current(binding)
                owner=self._owner_observation(permit,binding)
                content=current_digest==prepared.digest
            except (AuthorityUnavailable,ValueError):
                # This gate has an explicitly narrower historical measurement lane.
                # It never permits source-derived artifact bytes on stale rights.
                content=False
            with self._frozen() as (db,deletion,execution):
                anchor,_=self._current_anchor_locked(db,deletion,execution,action="accounting")
                bridge.fences.validate_fence_locked(db,permit,subject=permit.subject,current_anchor=anchor)
                if content:
                    try:self._require_owner_locked(db,binding,owner)
                    except AuthorityUnavailable:content=False
            qualification=canonical_digest((binding.digest,claim.signature,prepared.digest,metadata,revision,permit,content))
            return D04RootOriginalAppendV3(binding,claim,prepared.digest,canonical_serialize(metadata),revision,source_permit.pinned_anchor,permit,content,qualification)

    def _cost_closure(self,binding,claim,measurement,row):
        basis=root_cost_closure_basis_v3(row)
        if basis is None:raise AuthorityUnavailable("root cost-only closure is absent")
        original=D04RootMeasuredCostClosureV3(binding,claim,measurement,basis["artifact_disposition"],
            basis["barrier_basis_digest"],RestoreAnchor(**basis["current_anchor"]),
            "d04-root-cost:"+binding.execution_id,row[0],row[6].removeprefix("sha256:"),"pending")
        return replace(original,signature=self._sign(original))

    def read_d04_root_measured_cost_closure_v3(self,binding):
        self._binding_scope(binding);bridge=self.bridge
        bridge.core._require(self.credential,"current",bridge.namespace)
        with self._frozen() as (db,deletion,execution):
            _,claim,measurement,claim_row,row=read_root_execution_rows_locked_v3(bridge.journal,binding)
            if claim is None:return None
            self._require_historical_binding(binding,claim)
            self._reconcile_locked(db,binding,row or claim_row,execution)
            if row is None or root_cost_closure_basis_v3(row) is None:return None
            return self._cost_closure(binding,claim,measurement,row)

    def record_d04_root_measured_cost_closure_v3(self,binding,claim,measurement):
        """Close only authenticated measured CPU when no artifact can be retained.

        Measurement status/CPU/digests are unchanged. This explicit terminal
        branch is mutually exclusive with an ordinary completed artifact and
        may never reopen execution, restore a result, or authorize adoption.
        """
        self._binding(binding);self._verify_claim(binding,claim);bridge=self.bridge
        bridge.core._require(self.credential,"execution",bridge.namespace)
        if type(measurement) is not D04RootExecutionMeasurementV3 or measurement.status!="completed":
            raise AuthorityUnavailable("cost-only closure requires exact completed measured CPU")
        with self._frozen() as (db,deletion,execution):
            _,actual,old_measurement,claim_row,old_row=read_root_execution_rows_locked_v3(bridge.journal,binding)
            if actual!=claim:raise AuthorityUnavailable("root measured-cost original lacks consumed claim")
            self._reconcile_locked(db,binding,old_row or claim_row,execution)
            if old_row is not None and old_measurement!=measurement:
                raise AuthorityUnavailable("root measured-cost replay changes actual measurement")
        if old_row is not None:
            return self._cost_closure(binding,claim,measurement,old_row)
        gate=self.begin_d04_root_original_append_v3(binding,claim)
        prepared,metadata,revision,artifact,measured=self._read_original_payloads(binding)
        if measured!=to_wire(measurement):
            raise AuthorityUnavailable("caller CPU DTO is not a durable installed measurement original")
        if artifact is not None:
            # Malformed bytes are not silently relabelled missing, and a real
            # available artifact must use the ordinary terminal path.
            self._verify_artifact(prepared,claim,measurement,artifact)
            raise AuthorityUnavailable("durable full artifact requires its ordinary terminal")
        db=sqlite3.connect(self.graph_path.as_uri()+"?mode=ro",uri=True,isolation_level=None)
        try:
            db.execute("BEGIN")
            dependency_observations=[]
            for item in json.loads(prepared.input_payload_json)["read_rows"]:
                current=db.execute("SELECT revision,value,valid FROM graph_atoms WHERE token=?",(item[0],)).fetchone()
                dependency_observations.append((item[0],None if current is None else canonical_digest(current)))
            barrier_digest=canonical_digest((gate.qualification_digest,metadata,revision,tuple(dependency_observations)))
        finally:
            db.close()
        basis={"artifact_disposition":"missing_after_crash" if gate.content_artifact_permitted else "withheld_by_current_barrier",
            "barrier_basis_digest":barrier_digest,"current_anchor":asdict(gate.permit.pinned_anchor)}
        row=self._durable_append_v3(binding,gate.permit,claim,measurement,cost_closure_basis=basis)
        return self._cost_closure(binding,claim,measurement,row)

    def begin_d04_root_adoption_bridge_v3(self,binding):
        """Only this binding's consecutive claim+terminal may bridge old Graph."""
        from .owner_location_read_v3 import _owner_location_service_invocation_v3
        with _owner_location_service_invocation_v3(self):
            self._binding(binding);bridge=self.bridge
            bridge.core._require(self.credential,"execution",bridge.namespace)
            with self._frozen() as (db,deletion,execution):
                _,claim,measurement,claim_row,terminal_row=read_root_execution_rows_locked_v3(bridge.journal,binding)
                if claim is None or terminal_row is None or measurement.status!="completed" or root_cost_closure_basis_v3(terminal_row) is not None:
                    raise AuthorityUnavailable("root adoption requires actual completed terminal")
                if measurement.actual_cpu_ms>binding.cpu_ceiling_ms:
                    raise AuthorityUnavailable("root CPU overrun permits historical accounting only")
                self._reconcile_locked(db,binding,terminal_row,execution)
                source_permit,_=self._gate_locked(db,binding,"claim")
                before=source_permit.pinned_anchor
                after,holder=self._current_anchor_locked(db,deletion,execution)
                if (not self._same_location_epoch(before,after) or source_permit.holder!=holder
                        or claim.claim_sequence!=before.execution_seq+1 or terminal_row[0]!=claim.claim_sequence+1
                        or terminal_row[5]!=claim_row[6] or after.execution_seq!=terminal_row[0] or after.execution_digest!=terminal_row[6]):
                    raise AuthorityUnavailable("root adoption cannot skip interleaved/later execution or changed storage/deletion")
                from .d12_lifecycle_gate_v1 import require_lifecycle_admission_in_tx_v1
                require_lifecycle_admission_in_tx_v1(db,bridge.namespace,action="root_adoption")
                permit=bridge.fences.begin_fence_locked(db,subject=self._subject,holder=holder,operation="write",current_anchor=after,
                    operation_id=root_gate_operation_id_v3(binding,"adoption"))
            try:
                prepared=self._graph_read(binding)
                owner=self._owner_observation(permit,binding)
                old=json.loads(prepared.authority_anchor_json)
                if (not self._graph_location_matches(old,before)
                        or (old["execution_seq"],old["execution_digest"])!=(before.execution_seq,before.execution_digest)):
                    raise AuthorityUnavailable("root adoption Graph is not its exact prepared execution prefix")
                with self._frozen() as (db,deletion,execution):
                    current,_=self._current_anchor_locked(db,deletion,execution)
                    bridge.fences.validate_fence_locked(db,permit,subject=permit.subject,current_anchor=current)
                    self._require_owner_locked(db,binding,owner)
                    self._require_root_accepting_owner_locked(db,binding,prepared,owner)
                _,metadata,revision,_,_=self._read_original_payloads(binding)
                terminal=self._terminal(binding,claim,measurement,terminal_row)
                qualification=canonical_digest((binding.digest,prepared.prepared.digest,metadata,revision,before,after,claim_row[6],terminal_row[6],permit,current_owner_authority_material_v1(owner)))
                return D04RootAdoptionBridgeV3(binding,terminal,owner,prepared.prepared.digest,canonical_serialize(metadata),revision,before,after,permit,qualification)
            except BaseException:
                # Exact unused adoption fences have no external effect. Release only
                # if their actual unchanged anchor is still current.
                with self._frozen() as (db,deletion,execution):
                    current,_=self._current_anchor_locked(db,deletion,execution,action="recovery")
                    bridge.fences.finish_fence_locked(db,permit,subject=permit.subject,current_anchor=current,
                        request_id=permit.operation_id+":rejected",request_digest="sha256:"+canonical_digest((binding.digest,"adoption-rejected")))
                raise

    def validate_d04_root_gate_v3(self,binding,gate):
        """Authenticate an exact issued bridge before the Host Graph SQL opens."""
        from .owner_location_read_v3 import _owner_location_service_invocation_v3
        with _owner_location_service_invocation_v3(self):
            if type(gate) not in {D04RootOriginalAppendV3,D04RootAdoptionBridgeV3} or gate.binding!=binding:
                raise AuthorityUnavailable("typed exact root gate required")
            self._binding(binding);bridge=self.bridge
            bridge.core._require(self.credential,"current",bridge.namespace)
            prepared,metadata,revision,_,_=self._read_original_payloads(binding)
            if (prepared.digest!=gate.prepared_digest or canonical_serialize(metadata)!=gate.before_requirements_json
                    or revision!=gate.before_graph_revision):
                raise AuthorityUnavailable("root gate old Graph requirements/revision changed")
            owner=(self._owner_observation(gate.permit,binding) if type(gate) is D04RootAdoptionBridgeV3 or gate.content_artifact_permitted else None)
            selectors=self._read_root_basis(binding) if owner is not None else None
            with self._frozen() as (db,deletion,execution):
                anchor,_=self._current_anchor_locked(db,deletion,execution,
                    action="accounting" if type(gate) is D04RootOriginalAppendV3 else "business")
                bridge.fences.validate_fence_locked(db,gate.permit,subject=gate.permit.subject,current_anchor=anchor)
                _,claim,measurement,claim_row,terminal_row=read_root_execution_rows_locked_v3(bridge.journal,binding)
                if claim is None:raise AuthorityUnavailable("root gate has no actual claim")
                self._verify_claim(binding,claim)
                source,_=self._gate_locked(db,binding,"claim")
                if type(gate) is D04RootOriginalAppendV3:
                    if gate.claim!=claim or gate.source_anchor!=source.pinned_anchor or terminal_row is not None:
                        raise AuthorityUnavailable("root technical gate original changed")
                    expected=canonical_digest((binding.digest,claim.signature,prepared.digest,metadata,revision,gate.permit,gate.content_artifact_permitted))
                else:
                    if (terminal_row is None or gate.terminal!=self._terminal(binding,claim,measurement,terminal_row)
                            or gate.before_anchor!=source.pinned_anchor or gate.after_anchor!=anchor
                            or not self._same_location_epoch(gate.before_anchor,anchor)
                            or claim_row[0]!=gate.before_anchor.execution_seq+1 or terminal_row[0]!=claim_row[0]+1
                            or execution.seq!=terminal_row[0] or terminal_row[5]!=claim_row[6]):
                        raise AuthorityUnavailable("root adoption exact consecutive transition changed")
                    self._require_owner_locked(db,binding,owner)
                    self._require_root_accepting_owner_locked(db,binding,selectors,owner)
                    expected=canonical_digest((binding.digest,prepared.digest,metadata,revision,gate.before_anchor,anchor,claim_row[6],terminal_row[6],gate.permit,current_owner_authority_material_v1(owner)))
                if type(gate) is D04RootAdoptionBridgeV3 and gate.owner_authority!=owner:
                    raise AuthorityUnavailable("root bridge current Owner identity changed")
                if gate.qualification_digest!=expected:
                    raise AuthorityUnavailable("root gate observation commitment changed")
            if type(gate) is D04RootOriginalAppendV3 and gate.content_artifact_permitted:
                if self._content_retention_current(binding)!=prepared.digest:
                    raise AuthorityUnavailable("root content artifact no longer has exact source closure")
                with self._frozen() as (db,deletion,execution):
                    anchor,_=self._current_anchor_locked(db,deletion,execution,action="accounting")
                    bridge.fences.validate_fence_locked(db,gate.permit,subject=gate.permit.subject,current_anchor=anchor)
                    self._require_owner_locked(db,binding,owner)
            return gate

    def read_d04_root_gate_state_v3(self,binding,gate):
        if type(gate) not in {D04RootOriginalAppendV3,D04RootAdoptionBridgeV3} or gate.binding!=binding:
            raise AuthorityUnavailable("exact root gate status identity required")
        self._binding_scope(binding);self.bridge.core._require(self.credential,"current",self.bridge.namespace)
        actual_claim,_=self.read_d04_root_originals_v3(binding)
        if actual_claim is None:raise AuthorityUnavailable("historical gate has no authenticated execution original")
        with self.bridge.core._tx() as db:
            saved,row=self._gate_locked(db,binding,"original" if type(gate) is D04RootOriginalAppendV3 else "adoption")
            if saved!=gate.permit or row[6] not in {"active","finished"}:
                raise AuthorityUnavailable("root original gate state differs")
            if row[6]!="finished":self._binding(binding)
            return row[6]

    def finish_d04_root_adoption_bridge_v3(self,binding,gate,*,outcome):
        """Close this same adoption permit; this method never issues adoption."""
        if type(gate) is not D04RootAdoptionBridgeV3 or gate.binding!=binding or outcome not in {"committed","abandoned"}:
            raise AuthorityUnavailable("only exact root adoption bridge can be explicitly finished")
        self._binding_scope(binding);bridge=self.bridge
        bridge.core._require(self.credential,"execution",bridge.namespace)
        with bridge.core._tx() as db:
            saved,row=self._gate_locked(db,binding,"adoption")
            if saved!=gate.permit:raise AuthorityUnavailable("root final original permit changed")
            if row[6]=="finished":
                if row[8:10]!=(gate.permit.operation_id+":"+outcome,"sha256:"+canonical_digest((gate.qualification_digest,outcome))):
                    raise AuthorityUnavailable("root final replay result changed")
                return
        self._binding(binding)
        _,metadata,revision,_,_=self._read_original_payloads(binding)
        if outcome=="committed":
            self._verify_adoption_commit(binding,gate)
            if (revision!=gate.before_graph_revision+2 or not self._graph_location_matches(metadata,gate.after_anchor)
                    or (metadata["execution_seq"],metadata["execution_digest"])!=(gate.after_anchor.execution_seq,gate.after_anchor.execution_digest)):
                raise AuthorityUnavailable("root adoption final metadata was not atomically advanced")
        elif canonical_serialize(metadata)!=gate.before_requirements_json or revision!=gate.before_graph_revision:
            raise AuthorityUnavailable("root abandonment requires unchanged original Graph")
        with self._frozen() as (db,deletion,execution):
            anchor,_=self._current_anchor_locked(db,deletion,execution,action="recovery")
            bridge.fences.finish_fence_locked(db,gate.permit,subject=gate.permit.subject,current_anchor=anchor,
                request_id=gate.permit.operation_id+":"+outcome,
                request_digest="sha256:"+canonical_digest((gate.qualification_digest,outcome)))

    def _read_root_basis(self,binding,*,current=False):
        from .current_d04_root_prepared_v3 import read_root_original_basis_v3,read_current_d04_root_prepared_v3
        self._binding(binding)
        if self.graph_path.resolve(strict=True)!=self.graph_path:raise AuthorityUnavailable("root selected Graph path changed")
        db=sqlite3.connect(self.graph_path.as_uri()+"?mode=ro",uri=True,isolation_level=None)
        try:
            db.execute("BEGIN")
            if current:return read_current_d04_root_prepared_v3(db,binding,resource_issuer=self.resource_issuer,budget_issuer=self.budget_issuer,now_utc=self._clock())
            return read_root_original_basis_v3(db,binding)
        finally:db.close()

    def _graph_read(self,binding,claim=None):
        if claim is None:return self._read_root_basis(binding,current=True)
        self._require_historical_binding(binding,claim)
        from ..runtime.d04_root_accounting_prepared_v3 import read_root_accounting_prepared_v3,decode_root_accounting_prepared_payload_v3
        from ..runtime.d04_appraisal_driver_v3 import read_d04_original_v3
        db=sqlite3.connect(self.graph_path.as_uri()+"?mode=ro",uri=True,isolation_level=None)
        try:
            db.execute("BEGIN")
            retained=read_root_accounting_prepared_v3(db,binding.namespace,binding.operation_id,
                resource_issuer=self.resource_issuer,budget_issuer=self.budget_issuer)
            if retained is None or decode_root_accounting_prepared_payload_v3(retained[0])[0]!=binding:
                raise AuthorityUnavailable("root historical signed accounting basis absent/changed")
            measured=read_d04_original_v3(db,binding.namespace,"root_measurement",binding.operation_id)
            if measured is None:raise AuthorityUnavailable("root actual measured CPU original absent")
            value=root_execution_from_wire_v3(measured[0],D04RootExecutionMeasurementV3)
            if value.binding_digest!=binding.digest or value.claim_id!=claim.claim_id:raise AuthorityUnavailable("root measurement differs from original claim")
            return value
        finally:db.close()

    def _require_root_accepting_owner_locked(self,db,binding,read,observation=None):
        from .current_d04_root_prepared_v3 import D04RootPreparedReadV3
        from .v2_owner_contract import OwnerPrincipalV1
        if type(read) is not D04RootPreparedReadV3 or read.prepared.binding!=binding:raise AuthorityUnavailable("root actual accepting Owner read required")
        self._require_owner_locked(db,binding,observation)
        head=self.owner_tickets.current_migration_head_in_tx(db,authority_namespace=binding.authority_namespace)
        owner=read.input_payload["owner"];principal=OwnerPrincipalV1(**owner["principal"])
        if (principal!=head.issue_operation.principal or principal!=read.owner_request.principal
                or owner["authorization_head"]!=head.guard.authorization_head
                or owner["authorization_revision"]!=head.guard.authorization_revision
                or owner["grant_revision"]!=binding.owner_grant_revision
                or owner["grant_digest"].removeprefix("sha256:")!=binding.owner_grant_digest
                or "workbench.activate" not in owner["capabilities"]):
            raise AuthorityUnavailable("root accepting Owner original/head changed")
        sessions=self.owner_tickets._owner_sessions
        sessions._current_key(db,read.owner_request)
        sessions._current_pairing_source.require_current_actor_in_tx(db,
            authority_namespace=binding.authority_namespace,installation_id=self.installation_id,
            actor_id=read.owner_actor,principal=principal)

    def _read_original_payloads(self,binding):
        from ..runtime.d04_appraisal_driver_v3 import read_d04_original_v3
        from ..runtime.d04_root_execution_v3 import read_root_prepared_v3
        self._binding(binding)
        db=sqlite3.connect(self.graph_path.as_uri()+"?mode=ro",uri=True,isolation_level=None)
        try:
            db.execute("BEGIN")
            prepared=read_root_prepared_v3(db,binding.namespace,binding.operation_id)
            metadata=db.execute("SELECT requirements_json,graph_revision FROM graph_recovery_metadata_v2 WHERE bot=? AND persona=?",binding.namespace.as_tuple).fetchone()
            if prepared is None or prepared.binding!=binding or metadata is None:raise AuthorityUnavailable("root actual preparation/location absent")
            artifact=read_d04_original_v3(db,binding.namespace,"root_artifact",binding.operation_id)
            measured=read_d04_original_v3(db,binding.namespace,"root_measurement",binding.operation_id)
            return prepared,json.loads(metadata[0]),metadata[1],None if artifact is None else artifact[0],None if measured is None else measured[0]
        finally:db.close()

    def _content_retention_current(self,binding):
        from .current_d04_root_prepared_v3 import read_root_original_basis_v3,require_root_read_rows_v3
        db=sqlite3.connect(self.graph_path.as_uri()+"?mode=ro",uri=True,isolation_level=None)
        try:
            db.execute("BEGIN");read=read_root_original_basis_v3(db,binding)
            require_root_read_rows_v3(db,read)
            return read.prepared.digest
        finally:db.close()

    def _require_current_artifact_source_rights(self,prepared):
        if self._content_retention_current(prepared.binding)!=prepared.digest:raise AuthorityUnavailable("root artifact source closure changed")

    def _verify_artifact(self,prepared,claim,measurement,artifact):
        from ..domains.d04.authored_root_recovery_v3 import decode_authored_root_math_artifact_v3
        if prepared.binding.digest!=measurement.binding_digest or measurement.claim_id!=claim.claim_id:raise AuthorityUnavailable("root artifact original binding differs")
        value=decode_authored_root_math_artifact_v3(artifact)
        if (value.operation_id!=prepared.binding.operation_id or value.candidate_digest!=prepared.binding.candidate_digest
                or value.artifact_digest!=measurement.artifact_digest
                or value.initial_box_proof.proof_digest!=measurement.initial_box_proof_digest
                or value.output.issuance_digest!=measurement.output_issuance_digest
                or value.output.write_set_digest!=measurement.output_write_set_digest):
            raise AuthorityUnavailable("root artifact does not match actual measured commitments")
        return value

    def _durable_append_v3(self,binding,permit,claim,measurement,*,prepared=None,owner=None,cost_closure_basis=None):
        from .d12_lifecycle_gate_v1 import require_lifecycle_admission_in_tx_v1
        from .independent_append_guard_v3 import independent_append_core_guard_v3
        from .current_d04_root_prepared_v3 import D04RootPreparedReadV3
        from datetime import datetime
        import time
        bridge=self.bridge;now=self._clock();sampled=time.monotonic()
        with independent_append_core_guard_v3(bridge) as (db,deletion):
            with bridge.journal.freeze_writes():
                before=bridge.journal.verified_head()
                anchor,_=self._current_anchor_locked(db,deletion,before,action="business" if measurement is None else "accounting")
                bridge.fences.validate_fence_locked(db,permit,subject=permit.subject,current_anchor=anchor)
                if measurement is None:
                    if type(prepared) is not D04RootPreparedReadV3 or prepared.prepared.binding!=binding:raise AuthorityUnavailable("root first claim requires its actual current preparation")
                    require_lifecycle_admission_in_tx_v1(db,bridge.namespace,action="first_d04_root_claim")
                    self._require_root_accepting_owner_locked(db,binding,prepared,owner)
                    metadata=json.loads(prepared.authority_anchor_json)
                    if (not self._graph_location_matches(metadata,anchor)
                            or (metadata["execution_seq"],metadata["execution_digest"])!=(anchor.execution_seq,anchor.execution_digest)):
                        raise AuthorityUnavailable("root prepared Graph differs from current exclusive heads")
                    accepted=bridge.fences._row(db,prepared.input_payload["prepare_attempt_id"])
                    if (accepted is None or accepted[6]!="finished"
                            or canonical_digest(bridge.fences._permit(accepted))!=prepared.input_payload["prepare_permit_digest"]):
                        raise AuthorityUnavailable("root Owner preparation fence is not actually finished")
                    if now+max(0,time.monotonic()-sampled)>=datetime.fromisoformat(binding.deadline_utc.replace("Z","+00:00")).timestamp():
                        raise AuthorityUnavailable("root execution expired before durable first claim")
                else:
                    require_lifecycle_admission_in_tx_v1(db,bridge.namespace,action="accounting",original_claimed=True)
                    if cost_closure_basis is not None and cost_closure_basis["current_anchor"]!=asdict(anchor):raise AuthorityUnavailable("root cost-only barrier changed")
                row=append_root_execution_entry_locked_v3(bridge.journal,binding=binding,claim=claim,measurement=measurement,before_head=before,cost_closure_basis=cost_closure_basis)
            with bridge.journal.freeze_writes():self._reconcile_locked(db,binding,row,bridge.journal.verified_head())
        return row

    def record_d04_root_terminal_v3(self,binding,claim,measurement):
        self._binding(binding);self._verify_claim(binding,claim)
        if type(measurement) is not D04RootExecutionMeasurementV3:raise AuthorityUnavailable("actual typed root measurement required")
        bridge=self.bridge;bridge.core._require(self.credential,"execution",bridge.namespace)
        with self._frozen() as (db,deletion,execution):
            _,old,old_measurement,claim_row,old_row=read_root_execution_rows_locked_v3(bridge.journal,binding)
            if old!=claim:raise AuthorityUnavailable("root terminal lacks its original consumed claim")
            self._reconcile_locked(db,binding,old_row or claim_row,execution)
            if old_row is not None and old_measurement!=measurement:raise AuthorityUnavailable("root terminal replay changes CPU original")
        if old_row is not None:
            return self._cost_closure(binding,claim,measurement,old_row) if root_cost_closure_basis_v3(old_row) is not None else self._terminal(binding,claim,measurement,old_row)
        gate=self.begin_d04_root_original_append_v3(binding,claim)
        prepared,metadata,_,artifact,measured=self._read_original_payloads(binding)
        if measured!=to_wire(measurement) or not self._graph_location_matches(metadata,gate.permit.pinned_anchor):raise AuthorityUnavailable("root terminal lacks exact durable installed CPU original")
        if measurement.status=="completed":
            if artifact is None:return self.record_d04_root_measured_cost_closure_v3(binding,claim,measurement)
            self._verify_artifact(prepared,claim,measurement,artifact)
        row=self._durable_append_v3(binding,gate.permit,claim,measurement)
        return self._terminal(binding,claim,measurement,row)

    def read_d04_root_restore_original_v3(self,binding):
        from .owner_location_read_v3 import _owner_location_service_invocation_v3
        with _owner_location_service_invocation_v3(self):
            self._binding(binding);bridge=self.bridge;bridge.core._require(self.credential,"current",bridge.namespace)
            with self._frozen() as (db,deletion,execution):
                _,claim,measurement,claim_row,row=read_root_execution_rows_locked_v3(bridge.journal,binding)
                if claim is None or row is None or measurement.status!="completed" or root_cost_closure_basis_v3(row) is not None:raise AuthorityUnavailable("root restore requires actual complete artifact terminal")
                self._reconcile_locked(db,binding,row,execution)
                anchor,holder=self._current_anchor_locked(db,deletion,execution,action="recovery")
                source,_=self._gate_locked(db,binding,"claim")
                if not self._same_location_epoch(source.pinned_anchor,anchor):raise AuthorityUnavailable("root restore crossed deletion/storage lineage")
                import secrets
                permit=bridge.fences.begin_fence_locked(db,subject=self._subject,holder=holder,operation="read",current_anchor=anchor,operation_id=root_gate_operation_id_v3(binding,"restore")+":"+secrets.token_hex(8))
            try:
                prepared,metadata,revision,artifact,measured=self._read_original_payloads(binding)
                if measured!=to_wire(measurement) or not self._graph_location_matches(metadata,anchor):raise AuthorityUnavailable("root restore actual measurement/location changed")
                self._verify_artifact(prepared,claim,measurement,artifact)
                self._require_current_artifact_source_rights(prepared)
                owner=self._owner_observation(permit,binding);read=self._read_root_basis(binding)
                with self._frozen() as (db,deletion,execution):
                    current,_=self._current_anchor_locked(db,deletion,execution,action="recovery")
                    bridge.fences.validate_fence_locked(db,permit,subject=permit.subject,current_anchor=current)
                    self._require_root_accepting_owner_locked(db,binding,read,owner)
                terminal=self._terminal(binding,claim,measurement,row)
                return D04RootRestoreOriginalV3(prepared,claim,measurement,artifact,terminal,
                    canonical_digest((binding.digest,terminal.digest,prepared.digest,artifact,metadata,revision,permit)))
            finally:
                with self._frozen() as (db,deletion,execution):
                    current,_=self._current_anchor_locked(db,deletion,execution,action="recovery")
                    bridge.fences.finish_fence_locked(db,permit,subject=permit.subject,current_anchor=current,
                        request_id=permit.operation_id+":closed",request_digest="sha256:"+canonical_digest((binding.digest,"restore",permit.operation_id)))

    def read_d04_root_terminal_v3(self,binding):return self.read_d04_root_originals_v3(binding)[1]

    def verify_root_journal_row_v3(self,journal,row):
        from .d04_root_execution_journal_v3 import decode_root_execution_row_v3
        if journal.namespace!=self.bridge.namespace or journal.journal_id!=self.bridge.journal.journal_id or journal.path.resolve()!=self.bridge.journal.path.resolve():raise AuthorityUnavailable("root recovery actual journal differs")
        binding,claim,measurement=decode_root_execution_row_v3(journal,row)
        self._require_historical_binding(binding,claim)
        if measurement is None:return binding,claim,None
        if self._graph_read(binding,claim)!=measurement:raise AuthorityUnavailable("root recovery durable measurement differs")
        return binding,claim,self._cost_closure(binding,claim,measurement,row) if root_cost_closure_basis_v3(row) is not None else self._terminal(binding,claim,measurement,row)

    def _owner_observation(self,permit,binding=None):
        from .owner_location_read_v3 import _owner_location_service_invocation_v3
        with _owner_location_service_invocation_v3(self):
            from .owner_location_read_v3 import prepare_owner_location_for_root_execution_v3
            return prepare_owner_location_for_root_execution_v3(self,permit=permit,binding=binding)

    def _verify_adoption_commit(self,binding,gate):
        from ..runtime.d04_appraisal_driver_v3 import read_d04_original_v3
        from ..runtime.d04_root_original_store_v3 import read_d04_root_original_v3
        from ..runtime.d04_root_execution_v3 import read_root_prepared_v3
        from ..graph_types import GraphReceipt,NamespaceEpoch,AtomKey,Owner
        from ..graph_store import GraphStore
        from .d04_root_execution_bridge_v3 import root_bridge_from_wire_v3
        from ..domains.d12.types import active_scheme_head_key
        db=sqlite3.connect(self.graph_path.as_uri()+"?mode=ro",uri=True,isolation_level=None)
        try:
            db.execute("BEGIN")
            def original(kind):
                row=read_d04_original_v3(db,binding.namespace,kind,binding.operation_id)
                if row is None:raise AuthorityUnavailable("root final required immutable original absent")
                return row[0]
            if root_bridge_from_wire_v3(original("root_adoption_bridge"),D04RootAdoptionBridgeV3)!=gate:raise AuthorityUnavailable("root final durable bridge differs")
            link=original("root_execution_link");cost=original("root_cost")
            prepared=read_root_prepared_v3(db,binding.namespace,binding.operation_id)
            if prepared is None or prepared.digest!=gate.prepared_digest:raise AuthorityUnavailable("root final preparation changed")
            artifact=self._verify_artifact(prepared,gate.terminal.claim,gate.terminal.measurement,original("root_artifact"))
            root=read_d04_root_original_v3(db,namespace=binding.namespace,operation_id=binding.operation_id)
            receipts=[];events=[]
            for session in ("d12.scheme_adoption.v1","d04.authored_root.v3"):
                event=db.execute("SELECT revisions,invalidated,epoch_revision FROM graph_events WHERE bot=? AND persona=? AND session=? AND event_id=?",(*binding.namespace.as_tuple,session,binding.operation_id)).fetchone()
                if event is None or json.loads(event[1]):raise AuthorityUnavailable("root final exact event absent/invalidated")
                events.append(event)
                receipts.append(GraphReceipt("committed",GraphStore._version_rows(event[0]),GraphStore._version_rows(event[1]),NamespaceEpoch(*binding.namespace.as_tuple,event[2])))
            raw=json.loads(prepared.input_payload_json);measurement=gate.terminal.measurement
            expected={"schema":"d04.authored-root-execution-link.v3","operation_id":binding.operation_id,
                "binding_digest":binding.digest,"prepared_digest":prepared.digest,"terminal_digest":gate.terminal.digest,
                "artifact_digest":artifact.artifact_digest,"cost_original_digest":canonical_digest(cost),
                "freeze_digest":root.signed_freeze_digest,"root_original_digest":root.original_digest,
                "head_event_session":"d12.scheme_adoption.v1","root_event_session":"d04.authored_root.v3",
                "head_receipt_digest":canonical_digest(receipts[0]),"root_receipt_digest":canonical_digest(receipts[1]),
                "graph_revision":gate.before_graph_revision+2,"graph_epoch":receipts[1].epoch.revision}
            if (any(link.get(k)!=v for k,v in expected.items()) or set(link)!=set(expected)|{"adoption_receipt"}
                    or events[0][2]!=raw["graph_epoch"]+1 or events[1][2]!=events[0][2]+1
                    or root.write_set_digest!=measurement.output_write_set_digest
                    or cost.get("binding_digest")!=binding.digest or cost.get("prepared_digest")!=prepared.digest
                    or cost.get("terminal_digest")!=gate.terminal.digest or cost.get("operation_id")!=binding.operation_id
                    or (cost.get("actual_cpu_ns"),cost.get("actual_cpu_ms"))!=(measurement.actual_cpu_ns,measurement.actual_cpu_ms)):
                raise AuthorityUnavailable("root final link/event/root/cost originals disagree")
            cost_write=json.loads(cost["graph_write_json"]);key=cost_write["key"]
            cost_ref=AtomKey(Owner(**key["owner"]),key["type_name"],key["name"]).token
            head_ref=active_scheme_head_key(binding.namespace).token
            writes={item.key.token:item.revision for item in receipts[0].revisions}
            if set(writes)!={cost_ref,head_ref}:raise AuthorityUnavailable("root head event did not atomically include exact CPU settlement")
            for ref,want in ((cost_ref,cost_write["value"]),(head_ref,{"schema":active_scheme_head_key(binding.namespace).type_name,**raw["new_head"]})):
                row=db.execute("SELECT value,valid,event_bot,event_persona,event_session,event_id FROM graph_history WHERE token=? AND revision=?",(ref,writes[ref])).fetchone()
                if (row is None or row[1:]!=(1,*binding.namespace.as_tuple,"d12.scheme_adoption.v1",binding.operation_id) or json.loads(row[0])!=want):raise AuthorityUnavailable("root head/cost actual history differs")
        finally:db.close()


