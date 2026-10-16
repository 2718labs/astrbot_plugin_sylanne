"""One independently installed Authority WRITE Work for the fixed Personal mesh.

Metadata locates the real input recipe; it is never a Source-body credential.
All selected D02/D03/D05 Source families close before the original predicate.
"""
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from types import MappingProxyType
from weakref import WeakKeyDictionary
import json
from .contract import AuthorityUnavailable
from .foreground_mesh_contract_v1 import (
    ForegroundMeshActivityRequestV1, OwnerTaskMeshActivityRequestV1,
    ForegroundMeshActivityEvidenceV1, OwnerTaskMeshActivityEvidenceV1,
    PersonalMeshQualifiedFactsV1, personal_mesh_fence_operation_id_v1,
    BIRTH_OPERATOR, BIRTH_VERSION, PersonalMeshJobMetadataV1)
from ..graph_types import AtomKey, GraphVersion
from ..runtime_contracts import NamespaceId, QueryEpoch, canonical_digest, canonical_serialize
from ..runtime.domain_production_contracts_v1 import ProductionQueryCoverageV1, ProductionOriginalRefV1
from ..runtime.c09_canonical_json_stream_v2 import C09CanonicalJSONStreamV2
from ..runtime.c09_graph_row_codec_v2 import C09MemorySourceJSONStreamV3
from ..runtime.dispatch_initial_source_read_v3 import DispatchOriginalJSONReadV3
from ..runtime.source_correction_read_v3 import _heap

_WORKS = WeakKeyDictionary()
_SOURCE_PROOFS = WeakKeyDictionary()
_SELF_WORKS = WeakKeyDictionary()
_META_FIELDS = {
    "d08.personal_plan.v1": frozenset(("source_refs", "fact_versions", "actor_ref", "goal_ref", "candidate_refs", "plan_id", "revision")),
    "d07.current_interpretation.v1": frozenset(("source_refs", "source_ids", "interpretation_ref")),
    "d10.life_project.v1": frozenset(("source_refs",)),
    "d10.activity_recipe.v1": frozenset(("source_refs",)),
    "d08.goal.v1": frozenset(("source_refs", "deadline_ref", "actor_ref")),
    "d03.entity_anchor": frozenset(("entity_id", "source_refs")),
    "d03.role_binding": frozenset(("target_entity_ref", "source_refs")),
    "d05.boundary_rule": frozenset(("target_entity_ref", "source_refs")),
    "d08.commitment.v1": frozenset(("counterparty_ref", "subject_ref", "source_refs", "deadline_ref")),
    "d08.action_intent.v1": frozenset(("source_refs", "commitment_refs")),
    "d08.action_outcome.v1": frozenset(("source_refs", "effect_id")),
    "d01.method_scoped_trial.v1": frozenset(("source_refs", "protocol_ref", "gp1_interpretation_ref")),
    "d01.method_evaluation_protocol.v1": frozenset(("source_refs",)),
    "d11.semantic_tick.v1": None,
}
_FAMILIES = ("d02.body_state.v1", "d02.body_profile.v1", "d02.reservation.v1",
    "d03.role_binding", "d05.boundary_rule", "d08.commitment.v1",
    "d08.action_intent.v1", "d08.action_outcome.v1")

def _clock_upper_v3(work):
    reading = work.controller.clock()
    return reading.utc_seconds + reading.utc_error_seconds

def require_foreground_mesh_work_v3(work):
    from .current_authority_graph_read_v3 import require_actual_authority_graph_attachment_owner_v3
    require_actual_authority_graph_attachment_owner_v3(work)
    saved = _WORKS.get(work)
    if (saved is None or saved != (work.service, work.controller, work.request,
            work.permit, work.scope, work.operation, work.credential, work.subject)
            or work.controller.kind not in ("foreground_mesh", "owner_task_mesh")
            or work.permit.operation != "write"
            or work.permit.operation_id != personal_mesh_fence_operation_id_v1(work.request)):
        raise AuthorityUnavailable("Personal mesh requires its exact installed original WRITE Work")
    return saved

def _reserve(work, value, extra=0):
    metadata = work.mesh_metadata
    retained = (metadata.rows,metadata.heads,metadata.families,metadata.roots,metadata.pending,
        metadata.original_match,metadata.history_heads)
    amount = _heap((retained,value)) + extra + 65536
    prior = work.mesh_reserved
    if amount > prior:
        work.operation.retain(amount-prior)
        work.mesh_reserved = amount

class _MetadataColumnV3(DispatchOriginalJSONReadV3):
    """Full canonical EOF with an explicit per-recipe metadata field projection."""
    def __init__(self, work, *, table, column, key_columns, key, fields=None, cell_id=None):
        require_foreground_mesh_work_v3(work)
        self.fields = fields
        super().__init__(work, table=table, column=column, key_columns=key_columns, key=key, cell_id=cell_id)
        if self.cell is not None:
            self.parser = C09CanonicalJSONStreamV2(ensure_ascii=self.cell.header[0] == "canonical-json.ascii.v1")
    def _emit(self, event):
        if self.fields is None or not event.path or event.path[0] in self.fields:
            super()._emit(event)

@dataclass(frozen=True, slots=True)
class _SourceLeafV3:
    key: AtomKey
    revision: int
    valid: bool
    metadata: object
    cell_id: str
    sha256: str
    header: tuple

class _SourceColumnV3:
    def __init__(self, work, key):
        self.work, self.key = work, key
        self.phase = "head"
        self.cell = self.parser = None
        self.fragment = b""
        self.offset = 0
        self.complete = False
    def advance(self, meter):
        from ..runtime_storage_v3 import begin_runtime_cell_read_v3
        work = self.work
        work.require_current(meter=meter)
        if self.phase == "head":
            row = meter.read_fixed_row(work.db, "graph_atoms", ("revision", "valid", "value_cell_id"),
                "bot=? AND persona=? AND token=?", (*work.namespace.as_tuple, self.key.token))
            if row is None or row[0] < 1 or row[1] != 1 or row[2] is None:
                raise AuthorityUnavailable("Personal mesh Source current metadata is absent")
            self.head = row
            self.cell = begin_runtime_cell_read_v3(work.db, row[2], erasure_owner_ref=self.key.token)
            if self.cell.header[0] not in ("canonical-json.ascii.v1", "canonical-json.utf8.v1"):
                raise AuthorityUnavailable("Personal mesh Source has an unregistered physical codec")
            self.parser = C09MemorySourceJSONStreamV3(ensure_ascii=self.cell.header[0] == "canonical-json.ascii.v1")
            self.phase = "body"
            return False
        if self.offset < len(self.fragment):
            end = min(self.offset+1024, len(self.fragment))
            _reserve(work, (work.mesh_metadata, self.parser._source_metadata), 65536)
            self.parser.feed(self.fragment[self.offset:end], lambda event: None)
            self.offset = end
            return False
        fragment = self.cell.read_fragment(meter=meter)
        if fragment is not None:
            self.fragment, self.offset = fragment, 0
            return False
        parsed = self.parser.finish()
        digest = self.cell.finish(meter=meter)
        if (parsed.sha256, parsed.byte_count) != (digest, self.cell.header[3]):
            raise AuthorityUnavailable("Personal mesh Source metadata did not reach actual canonical EOF")
        metadata = MappingProxyType({name: tuple(value) if type(value) is list else value
            for name, value in self.parser._source_metadata.items()})
        if metadata["source_id"] != self.key.owner.subject:
            raise AuthorityUnavailable("Personal mesh Source metadata key differs")
        self.leaf = _SourceLeafV3(self.key, self.head[0], True, metadata, self.head[2], digest, tuple(self.cell.header))
        self.complete = True
        self.fragment = b""
        self.parser = self.cell = None
        return True

class _MeshMetadataV3:
    def __init__(self, work):
        from ..runtime.personal_candidate_eligibility_v1 import _candidate_target_v1
        self.work = work
        original = work.request.original
        command = work.request.companion.command.candidates
        self.job_key = AtomKey.from_token(original.cycle_job_ref if type(work.request) is ForegroundMeshActivityRequestV1 else original.task_job_ref)
        self.exact = {command.plan_ref, command.goal_ref, self.job_key.token}
        self.targets = set()
        self.roots = set()
        if type(work.request) is ForegroundMeshActivityRequestV1:
            self.roots.update((original.cue_source_ref, original.plan_source_ref))
        for binding in command.bindings:
            project, entity, role, *_ = _candidate_target_v1(work.namespace, binding)
            self.exact.update((project, entity, role))
            self.targets.add(entity)
            from ..domains.d08.personal_candidate_v1 import SourceNoteCandidateBindingV1
            if type(binding) is SourceNoteCandidateBindingV1:
                self.exact.add(binding.recipe_ref)
                self.roots.add(binding.source_ref)
        self.pending = list(sorted(self.exact))
        self.family_index = 0
        self.cursor = ""
        self.column = None
        self.heads = {}
        self.rows = {}
        self.families = {}
        self.phase = "job"
        self.complete = False
        self.original_cursor = ""
        self.original_match = None
        self.history_cursor = ""
        self.history_heads = {}
    def advance(self, meter):
        work = self.work
        work.require_current(meter=meter)
        if self.phase == "job":
            row = meter.read_fixed_row(work.db, "runtime_jobs",
                ("bot_id", "persona_id", "deadline_utc", "budget_ref", "activity_id", "work_kind", "operation_id"),
                "job_id=?", (self.job_key.name,))
            if row is None or row[:2] != work.namespace.as_tuple:
                raise AuthorityUnavailable("Personal mesh has no original actual job")
            deadline = datetime.fromisoformat(row[2].replace("Z", "+00:00")).timestamp()
            if type(work.request) is ForegroundMeshActivityRequestV1:
                deadline = min(deadline, work.request.original.requested_deadline_utc)
            if _clock_upper_v3(work) >= deadline:
                raise AuthorityUnavailable("Personal mesh cannot revive an expired original job")
            work.deadline_utc = work.operation.deadline_utc = float(deadline)
            from .current_authority_graph_read_v3 import _DEADLINES
            _DEADLINES[work] = (work.operation, work.deadline_utc, None)
            work.mesh_parent_budget = row[3]
            work.mesh_activity_id = row[4]
            work.mesh_job_work_kind = row[5]
            work.mesh_job_birth_operation_id = row[6]
            from ..runtime.domain_mesh_tick_v1 import semantic_tick_key_v1
            work.mesh_tick_key = semantic_tick_key_v1(work.namespace,row[4],work.request.companion.causal_original_ref,"foreground-projection.v1")
            self.exact.add(work.mesh_tick_key.token)
            self.pending.append(work.mesh_tick_key.token)
            self.column = _MetadataColumnV3(work, table="runtime_jobs", column="operator_versions_json",
                key_columns=("job_id",), key=(self.job_key.name,))
            self.phase = "birth"
            return
        if self.column is not None:
            self.column.advance(meter)
            if not self.column.complete:
                return
            raw = self.column.require_v3(work)
            from ..runtime.natural_frozen_original_read_v3 import _unproxy_v3
            raw = _unproxy_v3(raw)
            if self.phase == "birth":
                if raw == {}:
                    work.mesh_recipe_version = "legacy.v1"
                elif raw == {BIRTH_OPERATOR:BIRTH_VERSION}:
                    work.mesh_recipe_version = "foreground-projection.v1"
                else:
                    raise AuthorityUnavailable("Unknown original job recipe version cannot enter Personal mesh")
                work.mesh_operator_versions_digest = canonical_digest(raw)
                self.column = _MetadataColumnV3(work,table="runtime_jobs",column="continuation_json",
                    key_columns=("job_id",),key=(self.job_key.name,),fields=frozenset(("schema",
                        "c02_operation_id","source_ref","authorization_original_ref","authorization_original_digest",
                        "responsibility_ref","responsibility_digest")))
                self.phase = "job_continuation"
                return
            elif self.phase == "job_continuation":
                self.job_continuation = raw
                _bind_personal_job_metadata_v3(work,self,raw)
                if type(work.request) is ForegroundMeshActivityRequestV1 and work.mesh_recipe_version != 'legacy.v1':
                    self.phase = 'foreground_birth_metadata'
                else:
                    work.mesh_budget = _MeshBudgetMetadataV3(work)
                    self.phase = "budget"
            elif self.phase == 'foreground_birth_value':
                responsibility = raw['provenance']['foreground_responsibility']
                request = work.request.original
                if (self.column.sha256 != self.birth_digest or raw['identity']['operation_id'] != work.mesh_job_birth_operation_id
                        or raw['namespace'] != {'bot_id':work.namespace.bot_id,'persona_id':work.namespace.persona_id}
                        or responsibility['c02_operation_id'] != request.c02_operation_id
                        or responsibility['source_ref'] != request.cue_source_ref
                        or responsibility['root_registration_ref'] != request.draft_root_registration_ref
                        or responsibility['parent_budget_lease_ref'] != work.mesh_parent_budget
                        or responsibility['deadline_utc'] < work.deadline_utc
                        or canonical_digest(responsibility) != self.job_continuation['responsibility_digest']):
                    raise AuthorityUnavailable('Personal candidate metadata changed its actual committed job/root responsibility')
                work.mesh_budget = _MeshBudgetMetadataV3(work)
                self.phase = 'budget'
            elif self.phase == "original_reads":
                actual_versions = tuple(GraphVersion(AtomKey.from_token(token),revision) for token,revision in raw)
                header = self.original_match
                work.mesh_causal_original = ProductionOriginalRefV1(header[1]+".current-"+header[2],
                    header[1]+"-current:"+header[3][:48],header[3])
                work.mesh_causal_read_versions = actual_versions
                for token, revision in raw:
                    key = AtomKey.from_token(token)
                    if NamespaceId.from_key(key) != work.namespace:
                        raise AuthorityUnavailable("Personal mesh causal original metadata crossed namespace")
                    if key.type_name == "memory.source" and revision > 0:
                        self.roots.add(token)
                self.phase = "owner_authorization" if type(work.request) is OwnerTaskMeshActivityRequestV1 else "c02_history"
            elif self.phase == "owner_authorization_value":
                from ..runtime.domain_production_erasure_v1 import decode_typed_production_value_v1
                from ..runtime.owner_source_note_task_contract_v1 import OwnerSourceNoteTaskAuthorizationV2
                from ..runtime.d11_life_preparation_v1 import SIGN_KIND
                auth = decode_typed_production_value_v1(raw, OwnerSourceNoteTaskAuthorizationV2)
                original = work.request.original
                if auth.original_ref != original.authorization_original_ref or auth.digest != original.authorization_original_digest:
                    raise AuthorityUnavailable("Personal mesh metadata changed the original Owner task authorization")
                work.service.issuer._signer.verify(SIGN_KIND,
                    canonical_serialize(
                        (work.namespace, self.auth_kind, auth.original_ref, auth.digest)), self.auth_signature)
                if auth.cause.parent_budget_lease_ref != work.mesh_parent_budget:
                    raise AuthorityUnavailable("Personal mesh Owner task changed its original root budget")
                work.mesh_audiences = auth.cause.audiences
                work.mesh_owner_authorization = auth
                from ..runtime.owner_source_note_task_contract_v1 import owner_source_note_task_ids_v1
                ids = owner_source_note_task_ids_v1(work.namespace,auth.cause.owner_operation_id)
                command = work.request.companion.command.candidates
                from ..domains.d08.personal_candidate_v1 import SourceNoteCandidateBindingV1
                if (self.job_key.owner.subject != ids['activity_id'] or self.job_key.name != ids['job_id']
                        or command.plan_ref != ids['plan_key'].token or command.goal_ref != ids['goal_key'].token
                        or len(command.bindings) != 1 or type(command.bindings[0]) is not SourceNoteCandidateBindingV1
                        or (command.bindings[0].project_ref,command.bindings[0].source_ref,command.bindings[0].recipe_ref,
                            command.bindings[0].target_entity_ref,command.bindings[0].role_binding_ref) !=
                           (auth.request.project_ref,auth.request.body_source_ref,auth.request.recipe_ref,
                            auth.request.target_entity_ref,auth.request.role_binding_ref)
                        or self.job_continuation['authorization_original_ref'] != auth.original_ref
                        or self.job_continuation['authorization_original_digest'] != auth.digest):
                    raise AuthorityUnavailable('Personal candidate metadata escaped its actual signed Owner task')
                self.roots.update(auth.source_refs)
                if work.deadline_utc > auth.cause.original_deadline_utc:
                    work.deadline_utc = work.operation.deadline_utc = auth.cause.original_deadline_utc
                    from .current_authority_graph_read_v3 import _DEADLINES
                    _DEADLINES[work] = (work.operation, work.deadline_utc, None)
                self.phase = "exact"
            elif self.phase == "c02_history_value":
                self.roots.update(raw.get("source_refs", ()))
                self.phase = "c02_history"
            else:
                token = self.reading
                self.rows[token] = raw
                self._expand(token, raw)
            self.column = None
            return
        if self.phase == 'foreground_birth_metadata':
            row = meter.read_fixed_row(work.db,'graph_domain_production_originals_v1',
                ('domain','operation_kind','original_digest'), 'bot=? AND persona=? AND operation_id=?',
                (*work.namespace.as_tuple,work.mesh_job_birth_operation_id))
            if row is None or row[0] != 'd11' or row[1] not in ('create_foreground_cycle','create_foreground_cycle_v2'):
                raise AuthorityUnavailable('Personal mesh new birth has no exact actual committed foreground producer')
            self.birth_digest = row[2]
            self.column = _MetadataColumnV3(work,table='graph_domain_production_originals_v1',
                column='original_payload_json',key_columns=('bot','persona','operation_id'),
                key=(*work.namespace.as_tuple,work.mesh_job_birth_operation_id),
                fields=frozenset(('identity','namespace','provenance')))
            self.phase = 'foreground_birth_value'
            return
        if self.phase == "budget":
            work.mesh_budget.advance(meter)
            if work.mesh_budget.complete:
                self.phase = "original_locator"
            return
        if self.phase == "original_locator":
            target = work.request.companion.causal_original_ref
            row = meter.read_fixed_row(work.db, "graph_domain_production_originals_v1",
                ("operation_id", "domain", "operation_kind", "original_digest"),
                "bot=? AND persona=? AND operation_id>? ORDER BY operation_id",
                (*work.namespace.as_tuple, self.original_cursor))
            if row is not None:
                self.original_cursor = row[0]
                if target == row[1]+"-current:"+row[3][:48]:
                    if self.original_match is not None:
                        raise AuthorityUnavailable("Personal mesh actual Need original locator is ambiguous")
                    self.original_match = row
                return
            if self.original_match is None:
                raise AuthorityUnavailable("Personal mesh actual Need original metadata is absent")
            if type(work.request) is ForegroundMeshActivityRequestV1:
                from ..runtime.d06_ingress_recall_v1 import ingress_recall_need_operation_id_v1,NEED_OPERATION
                from ..runtime.d07_task_history_v1 import task_no_search_operation_id_v1,OPERATION as NO_SEARCH
                original = work.request.original
                allowed = ((ingress_recall_need_operation_id_v1(work.namespace,original.c02_operation_id),NEED_OPERATION),
                    (task_no_search_operation_id_v1(work.namespace,original.c02_operation_id),NO_SEARCH))
                if self.original_match[1] != 'd07' or (self.original_match[0],self.original_match[2]) not in allowed:
                    raise AuthorityUnavailable('Personal Need metadata is outside its actual C02 causal root')
            else:
                expected = 'owner-note-need:'+canonical_digest((work.namespace,work.request.original.authorization_original_ref))[:40]
                if self.original_match[:3] != (expected,'d07','prepare_owner_source_note_need_v1'):
                    raise AuthorityUnavailable('Personal Need metadata is outside its actual signed Owner task')
            work.mesh_causal_operation_id = self.original_match[0]
            self.column = _MetadataColumnV3(work, table="graph_domain_production_originals_v1",
                column="read_versions_json", key_columns=("bot", "persona", "operation_id"),
                key=(*work.namespace.as_tuple, self.original_match[0]))
            self.phase = "original_reads"
            return
        if self.phase == "owner_authorization":
            from ..runtime.owner_source_note_task_v1 import AUTHORIZATION_KIND
            self.auth_kind = AUTHORIZATION_KIND
            row = meter.read_fixed_row(work.db, "graph_d11_life_originals_v1",
                ("payload_digest", "signature"), "bot=? AND persona=? AND kind=? AND original_ref=?",
                (*work.namespace.as_tuple, AUTHORIZATION_KIND, work.request.original.authorization_original_ref))
            if row is None or row[0] != work.request.original.authorization_original_digest:
                raise AuthorityUnavailable("Personal mesh signed Owner authorization metadata is absent")
            self.auth_signature = row[1]
            self.column = _MetadataColumnV3(work, table="graph_d11_life_originals_v1",
                column="payload_json", key_columns=("bot", "persona", "kind", "original_ref"),
                key=(*work.namespace.as_tuple, AUTHORIZATION_KIND, work.request.original.authorization_original_ref))
            self.phase = "owner_authorization_value"
            return
        if self.phase == "c02_history":
            row = meter.read_fixed_row(work.db, "graph_history", ("token", "revision", "valid", "value_cell_id"),
                "event_bot=? AND event_persona=? AND event_id=? AND token>? ORDER BY token",
                (*work.namespace.as_tuple, work.request.original.c02_operation_id, self.history_cursor))
            if row is None:
                self.phase = "exact"
                return
            self.history_cursor = row[0]
            key = AtomKey.from_token(row[0])
            if NamespaceId.from_key(key) != work.namespace:
                raise AuthorityUnavailable("Personal mesh C02 history metadata crossed namespace")
            if not row[2] or key.type_name not in ("memory.episode.v1", "memory.subjective_trace.v2"):
                return
            self.history_heads[(row[0], row[1])] = row[2:]
            if row[0] not in self.exact:
                self.exact.add(row[0])
                self.pending.append(row[0])
            self.column = _MetadataColumnV3(work, table="graph_history", column="value",
                key_columns=("token", "revision"), key=(row[0], row[1]),
                fields=frozenset(("source_refs", "episode_ref")), cell_id=row[3])
            self.phase = "c02_history_value"
            return
        if self.pending:
            self._head(meter, self.pending.pop(), required=True)
            return
        if self.family_index < len(_FAMILIES):
            name = _FAMILIES[self.family_index]
            row = meter.read_fixed_row(work.db, "graph_atoms", ("token", "revision", "valid", "value_cell_id"),
                "bot=? AND persona=? AND type_name=? AND token>? ORDER BY token",
                (*work.namespace.as_tuple, name, self.cursor))
            if row is None:
                self.families.setdefault(name, [])
                self.family_index += 1
                self.cursor = ""
                return
            self.cursor = row[0]
            entries = self.families.setdefault(name, [])
            if len(entries) >= 128:
                raise AuthorityUnavailable("Personal mesh actual fixed family exceeds complete input coverage")
            entries.append(GraphVersion(AtomKey.from_token(row[0]), row[1]))
            self.heads[row[0]] = row[1:]
            if row[2] and name in _META_FIELDS:
                self._column(row[0], row[3])
            return
        for token, raw in self.rows.items():
            name = AtomKey.from_token(token).type_name
            if token in self.exact:
                self.roots.update(raw.get("source_refs", ()))
            elif name in ("d03.role_binding", "d05.boundary_rule", "d08.commitment.v1"):
                target = raw.get("counterparty_ref") if name == "d08.commitment.v1" else raw.get("target_entity_ref")
                if target in self.target_ids or name == "d03.role_binding" and target is None:
                    self.roots.update(raw.get("source_refs", ()))
                    self.exact.add(token)
            elif name == "d01.method_scoped_trial.v1":
                self.roots.update(raw.get("source_refs", ()))
                self.exact.add(token)
        self.complete = True

    @property
    def target_ids(self):
        return {self.rows[token]["entity_id"] for token in self.targets if token in self.rows}

    def _head(self, meter, token, *, required):
        row = meter.read_fixed_row(self.work.db, "graph_atoms", ("revision", "valid", "value_cell_id"),
            "bot=? AND persona=? AND token=?", (*self.work.namespace.as_tuple, token))
        if row is None:
            self.heads[token] = (0, 0, None)
            if required and token != self.work.mesh_tick_key.token:
                raise AuthorityUnavailable("Personal mesh exact metadata head is absent")
            return
        key = AtomKey.from_token(token)
        if NamespaceId.from_key(key) != self.work.namespace:
            raise AuthorityUnavailable("Personal mesh exact metadata crossed namespace")
        self.heads[token] = row
        if row[1] and key.type_name in _META_FIELDS:
            self._column(token, row[2])

    def _column(self, token, cell):
        key = AtomKey.from_token(token)
        self.reading = token
        self.column = _MetadataColumnV3(self.work, table="graph_atoms", column="value",
            key_columns=("token",), key=(token,), fields=_META_FIELDS[key.type_name], cell_id=cell)

    def _expand(self, token, raw):
        refs = []
        if AtomKey.from_token(token).type_name == "d11.semantic_tick.v1":
            from ..runtime.domain_mesh_tick_v1 import decode_semantic_tick_v1
            tick = decode_semantic_tick_v1(raw)
            if (tick.causal_original != self.work.mesh_causal_original
                    or tick.parent_budget_lease_ref != self.work.mesh_parent_budget
                    or tick.activity_id != self.work.mesh_activity_id):
                raise AuthorityUnavailable("Personal mesh checkpoint changed its actual original causal root")
            self.work.mesh_previous_tick = tick
            self.roots.update(tick.source_roots)
        if token == self.work.request.companion.command.candidates.plan_ref:
            refs.extend(row["ref"] for row in raw.get("fact_versions", ()))
        if "deadline_ref" in raw and raw["deadline_ref"] is not None:
            refs.append(raw["deadline_ref"])
        if AtomKey.from_token(token).type_name == "d01.method_scoped_trial.v1":
            refs.extend((raw["protocol_ref"], raw["gp1_interpretation_ref"]))
        for ref in refs:
            if ref not in self.exact:
                self.exact.add(ref)
                self.pending.append(ref)
        _reserve(self.work, (self.rows, self.heads, self.families, self.roots, self.pending))


class _MeshBudgetMetadataV3:
    def __init__(self,work):
        self.work = work
        self.current = work.mesh_parent_budget
        self.seen = set()
        self.leases = {}
        self.grants = {}
        self.column = None
        self.values = {}
        self.columns = []
        self.complete = False

    def advance(self,meter):
        from ..runtime.budget import BudgetLease
        from ..runtime.issuers import _decode_grant
        work = self.work
        work.require_current(meter=meter)
        if self.column is not None:
            self.column.advance(meter)
            if not self.column.complete:
                return
            value = self.column.require_v3(work)
            if self.kind == "grant":
                encoded = canonical_serialize(value)
                work.service.issuer._signer.verify("budget-grant.v1",encoded,self.signature)
                grant = _decode_grant(encoded)
                if (grant.lease_id != self.current or (grant.bot_id,grant.persona_id) != work.namespace.as_tuple
                        or grant.version != self.grant_version):
                    raise AuthorityUnavailable("Personal mesh original signed budget metadata differs")
                deadline = min(work.deadline_utc,grant.valid_until_utc)
                if _clock_upper_v3(work) >= deadline:
                    raise AuthorityUnavailable("Personal mesh original budget deadline expired before body qualification")
                work.deadline_utc = work.operation.deadline_utc = float(deadline)
                from .current_authority_graph_read_v3 import _DEADLINES
                _DEADLINES[work] = (work.operation,work.deadline_utc,None)
                self.grants[self.current] = grant
            else:
                self.values[self.kind] = value
            self.column = None
            return
        if self.columns:
            name = self.columns.pop()
            self.kind = name
            self.column = _MetadataColumnV3(work,table="runtime_budget_leases",column=name,
                key_columns=("lease_id",),key=(self.current,))
            return
        if self.values:
            row = self.lease_head
            lease = BudgetLease(self.current,row[0],row[1],row[2],row[3],
                self.values["limits_json"],self.values["used_json"],self.values["reserved_json"],
                self.values["unconfirmed_json"],row[4],row[5])
            self.leases[self.current] = lease
            self.values = {}
            if lease.parent_id is None:
                self.complete = True
            else:
                self.current = lease.parent_id
            return
        if self.current in self.seen:
            raise AuthorityUnavailable("Personal mesh original budget ancestry contains a cycle")
        self.seen.add(self.current)
        row = meter.read_fixed_row(work.db,"runtime_budget_leases",
            ("parent_id","bot_id","persona_id","currency","version","state"),"lease_id=?",(self.current,))
        debt = meter.read_fixed_row(work.db,"runtime_budget_debt_blocks",("lease_id",),
            "lease_id=?",(self.current,))
        if row is None or row[1:3] != work.namespace.as_tuple or row[5] != "active" or debt is not None:
            raise AuthorityUnavailable("Personal mesh original budget ancestry is unavailable or has unresolved debt")
        head = meter.read_fixed_row(work.db,"runtime_budget_grants",("version","signature","status"),
            "lease_id=? ORDER BY version DESC",(self.current,))
        if head is None or head[2] != "active":
            raise AuthorityUnavailable("Personal mesh original signed budget grant is unavailable")
        self.lease_head = row
        self.grant_version,self.signature = head[:2]
        self.columns = ["limits_json","used_json","reserved_json","unconfirmed_json"]
        self.kind = "grant"
        self.column = _MetadataColumnV3(work,table="runtime_budget_grants",column="grant_json",
            key_columns=("lease_id","version"),key=(self.current,head[0]))

def begin_foreground_mesh_source_read_v3(service, *, credential, subject, permit, request):
    from .current_authority_graph_read_v3 import (
        require_authority_graph_read_controller_v3, AuthorityGraphReadWorkV3,
        _ISSUER, _track_authority_capability_v3)
    from .current_foreground_activity_v1 import InstalledCurrentForegroundActivityV1
    from .current_owner_source_note_task_v1 import InstalledCurrentOwnerSourceNoteTaskV1
    types = {InstalledCurrentForegroundActivityV1: ForegroundMeshActivityRequestV1,
        InstalledCurrentOwnerSourceNoteTaskV1: OwnerTaskMeshActivityRequestV1}
    expected = types.get(type(service))
    if type(request) is not expected or permit.operation != "write" or permit.operation_id != personal_mesh_fence_operation_id_v1(request):
        raise AuthorityUnavailable("Personal mesh changed its exact independent issuer or original WRITE")
    controller = require_authority_graph_read_controller_v3(service)
    work = AuthorityGraphReadWorkV3(_ISSUER, controller, credential=credential,
        subject=subject, permit=permit, namespace=request.original.namespace, request=request, deadline_utc=None)
    _WORKS[work] = (service, controller, request, permit, work.scope, work.operation, credential, subject)
    _track_authority_capability_v3(work, _WORKS, work)
    work.mesh_audiences = request.original.audiences if type(request) is ForegroundMeshActivityRequestV1 else None
    work.mesh_purposes = ('consolidation',) if type(request) is ForegroundMeshActivityRequestV1 else ('context','consolidation')
    work.mesh_reserved = 0
    work.mesh_previous_tick = None
    work.mesh_metadata = _MeshMetadataV3(work)
    work.phase = "mesh_metadata"
    return work

def advance_foreground_mesh_source_v3(work, meter):
    require_foreground_mesh_work_v3(work)
    work.mesh_metadata.advance(meter)
    if work.mesh_metadata.complete:
        work.phase = "mesh_owner"

def prepare_foreground_mesh_owner_quantum_v3(work):
    if work.controller.kind not in ("foreground_mesh", "owner_task_mesh"):
        return False
    if work.phase == "mesh_metadata":
        return True
    from .foreground_mesh_owner_location_v3 import prepare_foreground_mesh_owner_v3
    prepare_foreground_mesh_owner_v3(work.service.self_identity._owner_storage, work)
    return True

class _MeshRightsV3:
    def __init__(self, work):
        self.work = work
        self.pending = list(sorted(work.mesh_metadata.roots))
        self.sources, self.accesses, self.versions = {}, {}, {}
        self.column = None
        self.source = None
        self.phase = "source"
        self.complete = False
    def advance(self, meter):
        from ..memory_types import source_key, access_key, validate_access
        from ..domains.d06 import source_correction_head_key
        from ..runtime.dispatch_initial_source_read_v3 import _SourceMetadataRecordV3
        work = self.work
        work.require_current(meter=meter)
        if self.source is not None:
            self.source.advance(meter)
            if not self.source.complete:
                return
            self.leaf = self.source.leaf
            self.source = None
            key = access_key(*work.namespace.as_tuple, self.leaf.key.owner.subject)
            head = meter.read_fixed_row(work.db, "graph_atoms", ("revision", "valid", "value_cell_id"),
                "bot=? AND persona=? AND token=?", (*work.namespace.as_tuple, key.token))
            if head is None or head[1] != 1:
                raise AuthorityUnavailable("Personal mesh Source current Access metadata is absent")
            self.access_head = head
            self.column = _MetadataColumnV3(work, table="graph_atoms", column="value",
                key_columns=("token",), key=(key.token,), cell_id=head[2])
            return
        if self.column is not None:
            self.column.advance(meter)
            if not self.column.complete:
                return
            access = self.column.require_v3(work)
            validate_access(access)
            leaf = self.leaf
            record = _SourceMetadataRecordV3(leaf.metadata)
            key = leaf.key
            correction = source_correction_head_key(work.namespace, key.owner.subject)
            head = meter.read_fixed_row(work.db, "graph_atoms", ("revision", "valid"),
                "bot=? AND persona=? AND token=?", (*work.namespace.as_tuple, correction.token))
            if (head is not None or access["source_id"] != record.source_id or access["status"] != "active"
                    or not set(work.mesh_purposes) <= set(record.purposes)
                    or not set(work.mesh_purposes) <= set(access["purposes"])
                    or not set(work.mesh_audiences) <= set(record.audiences)
                    or not set(work.mesh_audiences) <= set(access["audiences"])):
                raise AuthorityUnavailable("Personal mesh Source or ancestor current purpose/access/correction differs")
            self.sources[key.token] = leaf
            self.accesses[key.token] = access
            self.versions[key] = leaf.revision
            self.versions[access_key(*work.namespace.as_tuple, key.owner.subject)] = self.access_head[0]
            self.versions[correction] = 0
            self.pending.extend(source_key(*work.namespace.as_tuple, parent).token for parent in record.parent_source_ids)
            self.column = None
            _reserve(work, (work.mesh_metadata.rows, self.sources, self.accesses, self.versions, self.pending))
            return
        while self.pending:
            ref = self.pending.pop()
            if ref in self.sources:
                continue
            if len(self.sources) >= 256:
                raise AuthorityUnavailable("Personal mesh actual Source ancestry exceeds the existing bound")
            key = AtomKey.from_token(ref)
            if NamespaceId.from_key(key) != work.namespace or key.type_name != "memory.source":
                raise AuthorityUnavailable("Personal mesh Source roots crossed the exact namespace")
            self.source = _SourceColumnV3(work, key)
            return
        active, done = set(), set()
        def visit(ref):
            if ref in active:
                raise AuthorityUnavailable("Personal mesh actual Source ancestry contains a cycle")
            if ref in done:
                return
            active.add(ref)
            for parent in self.sources[ref].metadata["parent_source_ids"]:
                visit(source_key(*work.namespace.as_tuple, parent).token)
            active.remove(ref)
            done.add(ref)
        for ref in self.sources:
            visit(ref)
        self.complete = True
        _SOURCE_PROOFS[work] = (work.operation, work.scope, work.selection_digest, work.graph_stamp, self)
        from .current_authority_graph_read_v3 import _track_authority_capability_v3
        _track_authority_capability_v3(work,_SOURCE_PROOFS,work)

class _MeshProjectionV3:
    def __init__(self, work):
        self.work = work
    def get(self, key):
        from ..graph_types import GraphAtom
        from .current_authority_graph_read_v3 import AuthorityGraphAttachmentRequiredV3
        work = self.work
        if work in _SELF_WORKS:
            _require_mesh_self_v3(work)
        else:
            require_foreground_mesh_body_v3(work)
        if NamespaceId.from_key(key) != work.namespace:
            raise AuthorityUnavailable("Personal mesh body crossed namespace")
        if key in work.members:
            return work.members[key]
        head = work.heads.get(key.token)
        if head is not None and head[0] == 0:
            return GraphAtom(key, 0, {}, False)
        request = ("graph_atoms", ("revision", "value", "valid"),
            ("token", "bot", "persona"), (key.token, *work.namespace.as_tuple))
        require_foreground_mesh_attachment_v3(work, request)
        if work.complete:
            raise AuthorityUnavailable("Personal mesh final body was not prepared by the same original Work")
        raise AuthorityGraphAttachmentRequiredV3(request)

def require_foreground_mesh_body_v3(work):
    require_foreground_mesh_work_v3(work)
    proof = _SOURCE_PROOFS.get(work)
    if (proof is None or proof[:4] != (work.operation, work.scope, work.selection_digest, work.graph_stamp)
            or not proof[4].complete or work.phase != "validate"):
        raise AuthorityUnavailable("Personal mesh body requires all selected current Source families and parents")
    from .foreground_mesh_owner_location_v3 import _OWNERS
    owner = _OWNERS.get(work)
    if owner is None or owner.observed is None:
        raise AuthorityUnavailable("Personal mesh body requires its actual current Owner EOF")
    owner._actual()
    return proof[4]

def require_foreground_mesh_attachment_v3(work, request):
    if work.controller.kind not in ("foreground_mesh", "owner_task_mesh"):
        return False
    if work in _SELF_WORKS:
        _require_mesh_self_v3(work)
        table, columns, key_columns, key = request[:4]
        if table == "graph_atoms":
            atom = AtomKey.from_token(key[0])
            if NamespaceId.from_key(atom) != work.namespace or atom.type_name not in (
                    "d11.owner_grant.v1", "d01.persona_activation.v1", "d01.persona_plan.v1", "runtime.role_resources.v1"):
                raise AuthorityUnavailable("Personal mesh Self metadata cannot decode Source or business content")
        elif (table,tuple(columns),tuple(key_columns)) not in _SELF_SHAPES:
            raise AuthorityUnavailable("Personal mesh Self metadata is outside the exact initialization originals")
        return True
    proof = require_foreground_mesh_body_v3(work)
    table, columns, key_columns, key = request[:4]
    if table in ("graph_atoms", "graph_history"):
        atom = AtomKey.from_token(key[0])
        if NamespaceId.from_key(atom) != work.namespace:
            raise AuthorityUnavailable("Personal mesh attachment crossed namespace")
        if atom.type_name == "memory.source":
            if atom.token not in proof.sources:
                raise AuthorityUnavailable("Personal mesh cannot decode a Source outside the fully qualified recipe")
        elif atom not in proof.versions and atom.token not in work.mesh_metadata.exact and atom.type_name not in _FAMILIES:
            from ..domains.d03.self_perspective import self_mapping_key
            from ..graph_types import owner_grant_key
            if atom not in (owner_grant_key(*work.namespace.as_tuple), self_mapping_key(work.namespace)):
                raise AuthorityUnavailable("Personal mesh body is outside the actual fixed metadata read plan")
        metadata = work.mesh_metadata.rows.get(atom.token)
        if metadata is not None and not set(metadata.get("source_refs", ())) <= set(proof.sources):
            raise AuthorityUnavailable("Personal mesh selected body Source closure was not wholly qualified")
    else:
        allowed = frozenset(("graph_domain_production_originals_v1", "graph_d11_life_originals_v1",
            "graph_bundle_operations", "graph_events", "graph_ingress_observations",
            "runtime_jobs", "runtime_job_operations", "runtime_budget_leases", "runtime_budget_grants",
            "runtime_budget_operations", "runtime_budget_reservations", "runtime_resource_quotes",
            "graph_owner_domain_attempts_v3", "graph_d02_production_policies_v1",
            "d02_fixed_body_policies_v1", "graph_dependencies"))
        if table not in allowed:
            raise AuthorityUnavailable("Personal mesh attachment is outside its closed original recipe")
    return True

def foreground_mesh_source_family_v3(db, *, namespace, roots, purpose, audiences):
    from .current_authority_graph_read_v3 import _authority_attachment_owner_v3
    from .original_foreground_source_read_v3 import original_foreground_work_v3,original_foreground_source_family_v3
    original=_authority_attachment_owner_v3(db)
    if original is not None and original_foreground_work_v3(original)is not None:
        return original_foreground_source_family_v3(original,namespace=namespace,roots=roots,purpose=purpose,audiences=audiences)
    from .current_authority_graph_read_v3 import _authority_attachment_owner_v3
    work = _authority_attachment_owner_v3(db)
    if work is None or work.controller.kind not in ("foreground_mesh", "owner_task_mesh"):
        return None
    proof = require_foreground_mesh_body_v3(work)
    if (namespace != work.namespace or purpose not in work.mesh_purposes
            or tuple(audiences) != tuple(work.mesh_audiences)
            or not set(roots) <= set(work.mesh_metadata.roots)):
        raise AuthorityUnavailable("Personal mesh original predicate changed its exact qualified Source group")
    return tuple(GraphVersion(key, revision) for key, revision in sorted(proof.versions.items(), key=lambda row: row[0].token))

def advance_foreground_mesh_materials_v3(work, meter):
    require_foreground_mesh_work_v3(work)
    if work.phase == "mesh_metadata":
        advance_foreground_mesh_source_v3(work, meter)
        return
    if work.phase == "mesh_owner":
        from .foreground_mesh_owner_location_v3 import _OWNERS
        owner = _OWNERS.get(work)
        if owner is None or owner.observed is None:
            raise AuthorityUnavailable("Personal mesh Owner EOF must complete outside Graph SQL")
        work.mesh_rights = _MeshRightsV3(work)
        work.phase = "mesh_rights"
        return
    if work.phase == "mesh_rights":
        work.mesh_rights.advance(meter)
        if work.mesh_rights.complete:
            work.heads = dict(work.mesh_metadata.heads)
            from ..graph_types import owner_grant_key
            from ..domains.d03.self_perspective import self_mapping_key
            for key in (owner_grant_key(*work.namespace.as_tuple), self_mapping_key(work.namespace)):
                row = meter.read_fixed_row(work.db, "graph_atoms", ("revision", "valid", "value_cell_id"),
                    "bot=? AND persona=? AND token=?", (*work.namespace.as_tuple, key.token))
                if row is None:
                    raise AuthorityUnavailable("Personal mesh original Owner/Self graph head is absent")
                work.heads[key.token] = row
            work.projection = _MeshProjectionV3(work)
            work.phase = "validate"
        return
    raise AuthorityUnavailable("Personal mesh Source Work has an unregistered phase")

def read_foreground_mesh_c02_history_v3(db, *, namespace, operation_id, legacy_reader):
    from .current_authority_graph_read_v3 import _authority_attachment_owner_v3
    from .original_foreground_source_read_v3 import original_foreground_work_v3,read_original_foreground_c02_history_v3
    original=_authority_attachment_owner_v3(db)
    if original is not None and original_foreground_work_v3(original)is not None:
        return read_original_foreground_c02_history_v3(original,namespace=namespace,operation_id=operation_id)
    from .current_authority_graph_read_v3 import _authority_attachment_owner_v3
    work = _authority_attachment_owner_v3(db)
    if work is None or work.controller.kind != "foreground_mesh":
        return legacy_reader()
    require_foreground_mesh_body_v3(work)
    if namespace != work.namespace or operation_id != work.request.original.c02_operation_id:
        raise AuthorityUnavailable("Personal mesh C02 body changed the actual fixed producer")
    result = []
    for token, revision in sorted(work.mesh_metadata.history_heads):
        row = read_foreground_mesh_point_v3(db, table="graph_history", columns=("event_id","value","valid"),
            key_columns=("token","revision"), key=(token,revision),
            legacy_reader=lambda: None)
        if row is None or row[0] != operation_id or row[2] != 1:
            raise AuthorityUnavailable("Personal mesh C02 body lost the actual history producer")
        result.append((token,revision,row[1]))
    return tuple(result)

_SELF_SHAPES = frozenset((
    ("graph_owner_issue_operations_v1",
        ("operation_id","request_digest","grant_id","grant_digest","graph_incarnation","graph_access_epoch","graph_epoch","graph_receipt_digest","proof_json"),
        ("bot","persona","operation_id")),
    ("graph_role_init_intents_v1",
        ("operation_id","input_digest","fence_attempt_id","requirements_json","anchor_json","graph_revision","graph_epoch"),("bot","persona")),
    ("graph_role_init_request_proofs_v1",("operation_id","request_digest","input_digest"),("bot","persona")),
    ("graph_role_init_receipts_v1",
        ("operation_id","input_digest","permit_json","receipt_json","pre_graph_revision","pre_graph_epoch","post_graph_revision","post_graph_epoch","finish_request_id","finish_request_digest"),
        ("bot","persona")),
))
_MESH_POINTS = _SELF_SHAPES | frozenset((
    ("graph_bundle_operations",("digest","receipt_json"),("bot","persona","operation_id")),
))

def _require_mesh_self_v3(work):
    require_foreground_mesh_work_v3(work)
    saved = _SELF_WORKS.get(work)
    if saved != (work.operation,work.scope,work.request,work.selection_digest):
        raise AuthorityUnavailable("Personal mesh Self metadata phase has no exact private original Work")
    from .foreground_mesh_owner_location_v3 import _OWNERS
    owner = _OWNERS.get(work)
    if owner is None or owner.observed is None:
        raise AuthorityUnavailable("Personal mesh Self metadata requires completed actual Owner location")
    owner._actual()

@contextmanager
def foreground_mesh_self_phase_v3(work):
    from ..graph_types import Owner, owner_grant_key
    require_foreground_mesh_work_v3(work)
    from .foreground_mesh_owner_location_v3 import _OWNERS
    owner = _OWNERS[work]
    _SELF_WORKS[work] = (work.operation,work.scope,work.request,work.selection_digest)
    work.projection = _MeshProjectionV3(work)
    work.heads = dict(work.mesh_metadata.heads)
    with work.quantum_v3() as meter:
        for key in (owner_grant_key(*work.namespace.as_tuple),
                AtomKey(Owner("persona",*work.namespace.as_tuple),"d01.persona_activation.v1","current")):
            row = meter.read_fixed_row(work.db,"graph_atoms",("revision","valid","value_cell_id"),
                "bot=? AND persona=? AND token=?",(*work.namespace.as_tuple,key.token))
            if row is None:
                raise AuthorityUnavailable("Personal mesh Self current metadata head is absent")
            work.heads[key.token] = row
    old_phase = work.phase
    work.phase = "validate"
    try:
        yield owner
    finally:
        from .current_authority_graph_read_v3 import _PREPARED
        if work.prepared is not None:
            _PREPARED.pop(work.prepared,None)
        work.complete = False
        work.prepared = None
        work.phase = old_phase
        _SELF_WORKS.pop(work,None)

def read_foreground_mesh_point_v3(db, *, table, columns, key_columns, key, legacy_reader, required_valid=False):
    from .current_authority_graph_read_v3 import _authority_attachment_owner_v3
    from .original_foreground_source_read_v3 import original_foreground_work_v3,read_original_foreground_point_v3
    original=_authority_attachment_owner_v3(db)
    if original is not None and original_foreground_work_v3(original)is not None:
        return read_original_foreground_point_v3(original,table=table,columns=columns,key_columns=key_columns,key=key,required_valid=required_valid)
    from .current_authority_graph_read_v3 import (
        _authority_attachment_owner_v3, AuthorityGraphAttachmentRequiredV3,
        read_authority_current_point_v3, _authority_json_column_cap_v3, _AuthorityAtomJSONV3, _ISSUER)
    work = _authority_attachment_owner_v3(db)
    if work is None or work.controller.kind not in ("foreground_mesh","owner_task_mesh"):
        return read_authority_current_point_v3(db,table=table,columns=columns,key_columns=key_columns,key=key,
            legacy_reader=legacy_reader,required_valid=required_valid)
    columns, key_columns, key = tuple(columns),tuple(key_columns),tuple(key)
    if table == "graph_atoms":
        locator = dict(zip(key_columns,key))
        atom_key = AtomKey.from_token(locator["token"])
        atom = work.projection.get(atom_key)
        if atom.revision == 0 or required_valid and not atom.valid:
            return None
        values = {"revision":atom.revision,"value":_AuthorityAtomJSONV3(_ISSUER,work,atom),"valid":int(atom.valid),"token":atom_key.token}
        return tuple(values[column] for column in columns)
    if (table,columns,key_columns) not in _MESH_POINTS and table != "graph_history":
        raise AuthorityUnavailable("Personal mesh current point has no exact registered recipe")
    request = (table,columns,key_columns,key)
    require_foreground_mesh_attachment_v3(work,request)
    attachment = work.attachments.get(request)
    if attachment is None:
        if work.complete:
            raise AuthorityUnavailable("Personal mesh current point is outside its original prepared EOF")
        raise AuthorityGraphAttachmentRequiredV3(request)
    from ..runtime_storage_v3 import runtime_storage_quantum_v3
    with runtime_storage_quantum_v3(db) as meter:
        row = attachment.require_row_v3(work,meter)
    if row is None:
        return None
    result = list(row)
    for index,column in enumerate(columns):
        if column in attachment.json_columns:
            result[index] = _authority_json_column_cap_v3(work,attachment,attachment.json_columns[column])
    return tuple(result)

def prepare_foreground_mesh_attachment_v3(work,request):
    if work.controller.kind not in ("foreground_mesh","owner_task_mesh"):
        return None
    require_foreground_mesh_attachment_v3(work,request)
    from ..runtime.natural_producer_qualification_v1 import _HostProducerAttachmentV3,_HOST_ATTACHMENT_SHAPES_V3
    if request[:3] not in _HOST_ATTACHMENT_SHAPES_V3 and request[:3] not in _MESH_POINTS:
        raise AuthorityUnavailable("Personal mesh attachment shape is not a fixed actual original")
    return _HostProducerAttachmentV3(work,request)

def read_foreground_mesh_self_header_v3(db, *, namespace, legacy_reader):
    from .current_authority_graph_read_v3 import _authority_attachment_owner_v3
    from .original_foreground_source_read_v3 import original_foreground_work_v3,read_original_foreground_self_header_v3
    original=_authority_attachment_owner_v3(db)
    if original is not None and original_foreground_work_v3(original)is not None:
        return read_original_foreground_self_header_v3(original,namespace=namespace)
    from .current_authority_graph_read_v3 import _authority_attachment_owner_v3
    work = _authority_attachment_owner_v3(db)
    if work is None or work not in _SELF_WORKS:
        return legacy_reader()
    _require_mesh_self_v3(work)
    if namespace != work.namespace:
        raise AuthorityUnavailable("Personal mesh Self fixed header crossed namespace")
    from .foreground_mesh_owner_location_v3 import _OWNERS
    facts = _OWNERS[work].facts
    metadata = facts.metadata
    return (("sylanne3.authority.v2",canonical_serialize(metadata.requirements),metadata.graph_revision),
        (facts.graph_epoch.revision,),tuple(facts.epochs))

def require_foreground_mesh_source_anchor_in_tx_v3(work, db, location):
    require_foreground_mesh_work_v3(work)
    identity = work.service.self_identity
    qualifier = work.controller.location
    value = qualifier._require_issued(location, purpose="business")
    if (db is not identity._core._db or not db.in_transaction or value is not work.mesh_location
            or value.permit != work.permit or value.subject != work.subject
            or value.core_anchor != work.permit.pinned_anchor
            or value.context._reader is not work.controller.control
            or (value.context.manifest_digest,value.context.pointer_version,value.context.storage_generation)
                != (work.handle.context.manifest_digest,work.handle.context.pointer_version,work.handle.context.storage_generation)):
        raise AuthorityUnavailable("Personal mesh current Source observation changed its actual installation or original permit")
    from .current_source_location_v1 import require_current_source_anchor_in_tx_v1
    row, anchor = require_current_source_anchor_in_tx_v1(db,namespace=qualifier.namespace,
        expected_anchor=value.core_anchor,holder=value.holder)
    if row[9] != "clear":
        raise AuthorityUnavailable("Personal mesh cannot open business during current erasure")
    from .d12_lifecycle_gate_v1 import require_lifecycle_admission_in_tx_v1
    require_lifecycle_admission_in_tx_v1(db,qualifier.namespace,action="graph_read")
    qualifier._fences.fences.validate_fence_locked(db,value.permit,subject=value.subject,current_anchor=anchor)

def read_bound_foreground_mesh_budget_v3(db,lease_id,*,issuer=None):
    from .current_authority_graph_read_v3 import _authority_attachment_owner_v3
    from .original_foreground_source_read_v3 import original_foreground_work_v3,read_original_foreground_budget_v3
    original=_authority_attachment_owner_v3(db)
    if original is not None and original_foreground_work_v3(original)is not None:
        return read_original_foreground_budget_v3(original,lease_id,issuer=issuer)
    from .current_authority_graph_read_v3 import _authority_attachment_owner_v3
    work = _authority_attachment_owner_v3(db)
    if work is None or work.controller.kind not in ("foreground_mesh","owner_task_mesh"):
        return False,None
    require_foreground_mesh_body_v3(work)
    if lease_id not in work.mesh_budget.leases or issuer is not None and issuer is not work.service.issuer:
        raise AuthorityUnavailable("Personal mesh budget escaped the actual verified original family")
    if issuer is not None:
        return True,work.mesh_budget.grants[lease_id]
    return True,work.mesh_budget.leases[lease_id]

def _bind_personal_job_metadata_v3(work, metadata, value):
    request = work.request.original
    if type(work.request) is ForegroundMeshActivityRequestV1:
        from ..runtime.foreground_cycle_v1 import WORK_KIND,SCHEMA,SCHEMA_V2
        from ..runtime.source_note_foreground_v1 import CONTINUATION_SCHEMA
        if (work.mesh_job_work_kind != WORK_KIND or value['schema'] not in (SCHEMA,SCHEMA_V2,CONTINUATION_SCHEMA)
                or value['c02_operation_id'] != request.c02_operation_id or value['source_ref'] != request.cue_source_ref
                or metadata.job_key.owner.subject != request.activity_id):
            raise AuthorityUnavailable('Personal mesh job metadata changed its actual original C02/Source')
        from ..runtime.d08_personal_plan_v1 import artifact_goal_plan_keys_v1
        from ..domains.d08.personal_candidate_v1 import ArtifactPhaseCandidateBindingV1,ArtifactPhaseCandidateBindingV2,ArtifactPhaseCandidateBindingV3
        command = work.request.companion.command.candidates
        goal,plan,*_ = artifact_goal_plan_keys_v1(work.namespace,c02_operation_id=request.c02_operation_id,
            root_registration_ref=request.draft_root_registration_ref)
        if (command.plan_ref != plan.token or command.goal_ref != goal.token
                or any(type(binding) not in (ArtifactPhaseCandidateBindingV1,ArtifactPhaseCandidateBindingV2,ArtifactPhaseCandidateBindingV3)
                    or binding.task.c02_operation_id != request.c02_operation_id
                    or binding.task.cycle_job_ref != request.cycle_job_ref
                    or binding.task.root_registration_ref != request.draft_root_registration_ref for binding in command.bindings)):
            raise AuthorityUnavailable('Personal candidate metadata escaped its actual foreground task/root')
    else:
        from ..runtime.owner_source_note_task_contract_v1 import TASK_WORK_KIND
        if work.mesh_job_work_kind != TASK_WORK_KIND or value['schema'] != 'd11.owner-source-note-task-continuation.v2':
            raise AuthorityUnavailable('Personal mesh cannot classify an unknown Owner task job schema')
    work.mesh_job_continuation_schema = value['schema']

