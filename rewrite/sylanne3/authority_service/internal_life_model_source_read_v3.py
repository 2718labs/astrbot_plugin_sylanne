"""InternalLife model Source qualification on its original MODEL Work.

The signed preparation/request provide locators only. Every current Source and
ancestor is independently qualified before the installed content reader runs.
"""
from __future__ import annotations
from dataclasses import fields
import json
from weakref import WeakKeyDictionary
from .contract import AuthorityUnavailable
from ..graph_types import AtomKey, GraphAtom, GraphVersion
from ..runtime_contracts import NamespaceId, canonical_serialize
from ..runtime.dispatch_initial_source_read_v3 import DispatchOriginalJSONReadV3
from ..runtime.c09_canonical_json_stream_v2 import C09CanonicalJSONStreamV2

_PHASES = WeakKeyDictionary()
_READERS = WeakKeyDictionary()
_HEADERS = WeakKeyDictionary()
_CAPABILITIES = WeakKeyDictionary()
_PHASE = "actual_internal_life_model_policy"


def _actual_work_v3(work, installed_reader):
    from .current_authority_graph_read_v3 import AuthorityGraphReadWorkV3, require_actual_authority_graph_attachment_owner_v3
    from .internal_life_model_graph_v2 import InstalledInternalLifeModelGraphReaderV2
    from .v2_model_egress_service import AuthorityV2ModelEgressService
    from .v2_model_egress_contract import ModelEgressIntentV1
    from ..host.authority_profile import AdminInstallationBundle
    if (type(work) is not AuthorityGraphReadWorkV3
            or type(installed_reader) is not InstalledInternalLifeModelGraphReaderV2
            or type(work.request) is not ModelEgressIntentV1
            or type(work.service) is not AuthorityV2ModelEgressService
            or work.controller.kind != "model"
            or work.controller.verifier._internal_life_reader_v2 is not installed_reader
            or work.controller.service is not work.service
            or type(installed_reader.bundle) is not AdminInstallationBundle
            or work.controller.verifier._artifact_draft_bundle is not installed_reader.bundle
            or work.controller.control is not installed_reader.owner_storage.control
            or work.controller.fences is not installed_reader.owner_storage.fences
            or work.controller.location._graph_db_path != installed_reader.owner_storage.graph_path
            or work.namespace != installed_reader.owner_storage.namespace_id
            or work.owner_model_work_kind != "d06.encode_internal_life_content"
            or work.permit.operation != "model_egress"
            or work.request.operation_id != work.permit.operation_id
            or work.subject != work.request.subject or work.permit.subject != work.subject
            or work.deadline_utc is None):
        raise AuthorityUnavailable("InternalLife Source requires its actual installed MODEL reader/Work/permit")
    require_actual_authority_graph_attachment_owner_v3(work)
    return work


def require_internal_life_model_phase_v3(work, installed_reader):
    _actual_work_v3(work, installed_reader)
    state = (installed_reader, work.controller, work.service, installed_reader.owner_storage,
        installed_reader.bundle, work.operation, work.scope, work.permit, work.request,
        work.selection_digest, work.deadline_utc)
    previous = _PHASES.get(work)
    if previous is None:
        _PHASES[work] = state
    elif previous != state:
        raise AuthorityUnavailable("InternalLife Source phase changed its original installed call")
    if work not in _READERS:
        _READERS[work] = InternalLifeAuthoritySourceReadV3(work, installed_reader)
    return _PHASE


def require_internal_life_owner_header_v3(proof):
    from .owner_location_read_v3 import OwnerLocationCallerProofV3
    if (type(proof) is not OwnerLocationCallerProofV3
            or proof.kind != "authority_internal_life_model_header"
            or proof.model_source_phase != _PHASE):
        raise AuthorityUnavailable("InternalLife Owner header has no actual private policy phase")
    work = proof.request
    state = _PHASES.get(work)
    if state is None:
        raise AuthorityUnavailable("InternalLife Owner header was not issued for an actual registered Work")
    reader = state[0]
    _actual_work_v3(work, reader)
    current = (reader, work.controller, work.service, reader.owner_storage, reader.bundle,
        work.operation, work.scope, work.permit, work.request, work.selection_digest, work.deadline_utc)
    if (state != current or proof.controller is not work.controller
            or proof.service is not work.service or proof.owner_service is not reader.owner_storage
            or proof.bundle is not reader.bundle or proof.retained_operation is not work.operation
            or proof.scope is not work.scope or proof.original_permit is not work.permit
            or proof.credential is not work.credential or proof.subject != work.subject
            or proof.namespace != work.namespace or proof.selection_digest != work.selection_digest
            or proof.deadline_utc != work.deadline_utc):
        raise AuthorityUnavailable("InternalLife Owner header changed its registered reader/operation/permit")
    return proof


class _FilteredMetadataV3:
    def __init__(self, column, retain):
        self.column, self.retain = column, retain
        self.parser = C09CanonicalJSONStreamV2(ensure_ascii=True)
        self.nodes = {}
        self.scalar = bytearray()
        self.value = None
        self.complete = False
    def _emit(self, event):
        if not self.retain(event.path):
            return
        if event.kind in ("object_start", "array_start"):
            self.column._reserve(1024)
            value = {} if event.kind == "object_start" else []
            self.nodes[event.path] = value
            self._put(event.path, value)
        elif event.kind == "scalar_start":
            self.scalar = bytearray()
        elif event.kind == "scalar_chunk":
            self.column._reserve(4 * len(event.raw) + 1024)
            self.scalar.extend(event.raw)
        elif event.kind == "scalar_end":
            self.column._reserve(4 * len(self.scalar) + 1024)
            self._put(event.path, json.loads(self.scalar))
            self.scalar = bytearray()
    def _put(self, path, value):
        if not path:
            self.value = value
            return
        parent = self.nodes[path[:-1]]
        if type(parent) is list:
            parent.append(value)
        else:
            parent[path[-1]] = value
    def feed(self, codepoint):
        self.parser.feed(chr(codepoint).encode("utf-8"), self._emit)
    def finish(self):
        summary = self.parser.finish()
        self.sha256 = summary.sha256
        self.complete = True


def _frozen_metadata_path_v3(path):
    # The existing input and occurrence schemas contain metadata, never Source text.
    return not path or path[0] not in {"messages", "wire_json"}


def _request_metadata_path_v3(path):
    return not path or path[0] != "payload"


class _EmbeddedMetadataStreamV3(C09CanonicalJSONStreamV2):
    def __init__(self, column):
        self.column = column
        super().__init__(ensure_ascii=True)
    def _append_decoded_codepoint(self, codepoint):
        state = self._string
        if state is not None and state["mode"] == "value" and state["path"] == (self.column.embedded_field,):
            self.column.embedded.feed(codepoint)
        return super()._append_decoded_codepoint(codepoint)


class _InternalLifeLocatorColumnV3(DispatchOriginalJSONReadV3):
    def __init__(self, reader, kind):
        from ..runtime.internal_life_content_preparation_v1 import TABLE as PREPARED_TABLE, InternalLifeContentPreparedV1
        from ..runtime.internal_life_content_worker_v2 import TABLE as REQUEST_TABLE
        self.reader, self.kind = reader, kind
        self.embedded_field = "frozen_json" if kind == "prepared" else "wire"
        self.embedded = _FilteredMetadataV3(self,
            _frozen_metadata_path_v3 if kind == "prepared" else _request_metadata_path_v3)
        self.retained = ({field.name for field in fields(InternalLifeContentPreparedV1)} - {"frozen_json"}
            if kind == "prepared" else {"schema", "binding_digest", "prepared_digest", "request_digest"})
        self.fields_seen = set()
        super().__init__(reader.work, table=PREPARED_TABLE if kind == "prepared" else REQUEST_TABLE,
            column="payload_json", key_columns=("bot", "persona", "kind", "original_ref")
            if kind == "prepared" else ("bot", "persona", "kind", "job_id"),
            key=(*reader.work.namespace.as_tuple, kind, reader.work.request.job_id))
        self.parser = _EmbeddedMetadataStreamV3(self)
    def _reserve(self, extra=0):
        from ..runtime.source_correction_read_v3 import _heap
        nested = self.embedded
        amount = _heap((self.nodes, self.scalar, self.fragment, self.value, self.fields_seen,
            nested.nodes, nested.scalar, nested.value)) + extra + 131072
        if amount > self.reserved:
            self.operation.retain(amount - self.reserved)
            self.reserved = amount
    def _emit(self, event):
        if event.kind == "key" and len(event.path) == 1:
            self.fields_seen.add(event.key)
        if event.path == (self.embedded_field,) and event.kind == "scalar_end":
            self.embedded.finish()
        if event.path and event.path[0] not in self.retained:
            return
        super()._emit(event)


class _InternalLifeSignedLocatorV3:
    def __init__(self, reader, kind):
        self.reader, self.work, self.kind = reader, reader.work, kind
        self.phase = "point"
        self.metadata = self.column = self.value = None
        self.complete = False
    def advance(self, meter):
        from ..runtime.internal_life_content_preparation_v1 import TABLE as PREPARED_TABLE, SIGN_KIND as PREPARED_SIGN, InternalLifeContentPreparedV1
        from ..runtime.internal_life_content_worker_v2 import TABLE as REQUEST_TABLE, SIGN_KIND as REQUEST_SIGN
        from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3
        work = self.work
        self.reader.require_current_v3(meter)
        prepared = self.kind == "prepared"
        if self.phase == "point":
            self.metadata = _runtime_bounded_fixed_row_v3(work.db, meter,
                PREPARED_TABLE if prepared else REQUEST_TABLE, ("payload_digest", "signature"),
                "bot=? AND persona=? AND kind=? AND " + ("original_ref" if prepared else "job_id") + "=?",
                (*work.namespace.as_tuple, self.kind, work.request.job_id))
            if self.metadata is None:
                raise AuthorityUnavailable("InternalLife Source lost its exact signed preparation/request locator")
            self.column = _InternalLifeLocatorColumnV3(self.reader, self.kind)
            self.phase = "canonical"
            return
        if not self.column.advance(meter):
            return
        if self.column.sha256 != self.metadata[0] or not self.column.embedded.complete:
            raise AuthorityUnavailable("InternalLife Source locator lacks its signed canonical whole EOF")
        self.reader.installed.readers.issuer._signer.verify(PREPARED_SIGN if prepared else REQUEST_SIGN,
            canonical_serialize((work.namespace, self.kind, work.request.job_id, self.metadata[0])),
            self.metadata[1])
        raw = self.column.require_v3(work)
        expected = ({field.name for field in fields(InternalLifeContentPreparedV1)} if prepared
            else {"schema", "binding_digest", "prepared_digest", "request_digest", "wire"})
        if self.column.fields_seen != expected:
            raise AuthorityUnavailable("InternalLife signed Source locator has another closed fieldset")
        self.value = raw
        self.embedded = self.column.embedded.value
        self.complete = True
        _HEADERS[self] = (self.reader, work, self.kind, self.metadata, self.column,
            self.value, self.embedded, work.operation, work.scope)
    def require_v3(self, reader):
        if (not self.complete or _HEADERS.get(self) != (reader, self.work, self.kind,
                self.metadata, self.column, self.value, self.embedded,
                self.work.operation, self.work.scope) or reader is not self.reader):
            raise AuthorityUnavailable("InternalLife Source metadata is not its complete actual Work original")
        reader.require_registered_v3()
        return self



_LIFE_HEADERS = WeakKeyDictionary()


class _LifePreparedMetadataStreamV3(C09CanonicalJSONStreamV2):
    def __init__(self, column):
        self.column = column
        super().__init__(ensure_ascii=True)
    def _append_decoded_codepoint(self, codepoint):
        state = self._string
        if (state is not None and state["mode"] == "value"
                and len(state["path"]) == 3 and state["path"][0] == "read_rows"
                and state["path"][2] == "value_json"):
            raw = chr(codepoint).encode("utf-8")
            self.column.value_parser.feed(raw, lambda event: None)
        return super()._append_decoded_codepoint(codepoint)


class _LifePreparedMetadataColumnV3(DispatchOriginalJSONReadV3):
    def __init__(self, reader, original_ref):
        from ..runtime.d11_life_preparation_v1 import TABLE
        self.fields_seen = set()
        self.value_parser = None
        self.value_digests = {}
        super().__init__(reader.work,table=TABLE,column="payload_json",
            key_columns=("bot","persona","kind","original_ref"),
            key=(*reader.work.namespace.as_tuple,"prepared",original_ref))
        self.parser = _LifePreparedMetadataStreamV3(self)
    def _reserve(self, extra=0):
        from ..runtime.source_correction_read_v3 import _heap
        parser = self.value_parser
        state = () if parser is None else (
            tuple((item.kind,item.path,item.state,item.previous_key,item.current_key,item.index)
                for item in parser._stack),parser._string,parser._literal,parser._number,parser._active_scalar)
        amount = _heap((self.nodes,self.scalar,self.fragment,self.value,self.fields_seen,
            self.value_digests,state)) + extra + 131072
        if amount > self.reserved:
            self.operation.retain(amount-self.reserved)
            self.reserved = amount
    def _retain_path_v3(self, path):
        if not path:
            return True
        if path[0] in {"binding","prepare_operation_id","schema"}:
            return True
        if path[0] == "plan":
            return len(path) == 1 or path[1] in {
                "schema","audiences","input_source","activity_id","effect_id","attempt_id","operation_id"}
        if path[0] == "read_rows":
            return len(path) <= 2 or len(path) == 3 and path[2] in {"ref","revision","valid"}
        return False
    def _emit(self, event):
        if event.kind == "key" and len(event.path) == 1:
            self.fields_seen.add(event.key)
        if (len(event.path) == 3 and event.path[0] == "read_rows"
                and event.path[2] == "value_json"):
            if event.kind == "scalar_start":
                self.value_parser = C09CanonicalJSONStreamV2(ensure_ascii=True)
            elif event.kind == "scalar_end":
                summary = self.value_parser.finish()
                self.value_digests[event.path[1]] = summary.sha256
                self.value_parser = None
        if not self._retain_path_v3(event.path):
            return
        super()._emit(event)


class _LifePreparedSignedMetadataV3:
    def __init__(self, reader):
        cause = reader.prepared.embedded["input"]["cause"]
        self.reader, self.work = reader, reader.work
        self.original_ref = cause["prepared_original_ref"]
        self.expected_digest = cause["prepared_original_digest"]
        self.metadata = self.column = self.value = self.binding = None
        self.phase = "point"
        self.complete = False
    def advance(self, meter):
        from ..runtime.d11_life_preparation_v1 import TABLE, SIGN_KIND, D11LifePreparedV1
        from ..runtime.d11_life_contract_v1 import D11LifeExecutionBindingV1,life_from_wire_v1
        from ..runtime_storage_v3 import _runtime_bounded_fixed_row_v3
        reader,work = self.reader,self.work
        reader.require_current_v3(meter)
        if self.phase == "point":
            self.metadata = _runtime_bounded_fixed_row_v3(work.db,meter,TABLE,
                ("producing_operation_id","payload_digest","signature"),
                "bot=? AND persona=? AND kind=? AND original_ref=?",
                (*work.namespace.as_tuple,"prepared",self.original_ref))
            if self.metadata is None or self.metadata[1] != self.expected_digest:
                raise AuthorityUnavailable("InternalLife progress metadata lost its exact signed occurrence preparation")
            self.column = _LifePreparedMetadataColumnV3(reader,self.original_ref)
            self.phase = "canonical"
            return
        if not self.column.advance(meter):
            return
        if (self.column.sha256 != self.metadata[1]
                or self.column.fields_seen != {field.name for field in fields(D11LifePreparedV1)}):
            raise AuthorityUnavailable("InternalLife progress metadata lacks its closed signed whole EOF")
        reader.installed.readers.issuer._signer.verify(SIGN_KIND,
            canonical_serialize((work.namespace,"prepared",self.original_ref,self.metadata[1])),self.metadata[2])
        raw = self.column.require_v3(work)
        binding = life_from_wire_v1(raw["binding"],D11LifeExecutionBindingV1)
        event = reader.prepared.embedded["input"]["cause"]["occurrence"]["event"]
        activity = event["activity"]
        if (raw["schema"] != "d11.life-prepared.v1"
                or binding.namespace != work.namespace or binding.prepared_original_ref != self.original_ref
                or binding.execution_id != activity["execution_id"]
                or binding.activity_id != activity["activity_id"] or binding.effect_id != activity["effect_id"]
                or binding.artifact_ref != activity["artifact_ref"]
                or binding.activation_generation != event["activation_generation"]
                or binding.authority_id != work.request.authority_id
                or binding.authority_namespace != work.request.namespace
                or raw["prepare_operation_id"] != binding.prepare_operation_id
                or self.metadata[0] != binding.prepare_operation_id
                or raw["plan"]["schema"] != "d11.registered-life-plan.v2"
                or (raw["plan"]["activity_id"],raw["plan"]["effect_id"],raw["plan"]["attempt_id"],
                    raw["plan"]["operation_id"]) !=
                    (binding.activity_id,binding.effect_id,binding.attempt_id,binding.operation_id)):
            raise AuthorityUnavailable("InternalLife progress metadata changed its actual occurrence/binding/producer")
        rows = raw["read_rows"]
        if (not rows or len(rows) > 1024 or len({row["ref"] for row in rows}) != len(rows)
                or set(self.column.value_digests) != set(range(len(rows)))):
            raise AuthorityUnavailable("InternalLife progress metadata lacks its complete exact read-row commitments")
        for index,row in enumerate(rows):
            if (set(row) != {"ref","revision","valid"}
                    or NamespaceId.from_key(AtomKey.from_token(row["ref"])) != work.namespace
                    or type(row["revision"]) is not int or row["revision"] < 0 or type(row["valid"]) is not bool):
                raise AuthorityUnavailable("InternalLife progress metadata has another read-row namespace/schema")
            row["digest"] = self.column.value_digests[index]
        self.value,self.binding,self.complete = raw,binding,True
        _LIFE_HEADERS[self] = (reader,work,self.original_ref,self.metadata,self.column,raw,binding,
            work.operation,work.scope)
    def require_v3(self, reader):
        if (reader is not self.reader or not self.complete or _LIFE_HEADERS.get(self) !=
                (reader,self.work,self.original_ref,self.metadata,self.column,self.value,self.binding,
                    self.work.operation,self.work.scope)):
            raise AuthorityUnavailable("InternalLife progress metadata is not its same-Work signed EOF")
        reader.require_registered_v3()
        return self


class InternalLifeAuthoritySourceReadV3:
    def __init__(self, work, installed):
        self.work, self.installed = work, installed
        self.prepared = _InternalLifeSignedLocatorV3(self, "prepared")
        self.request = _InternalLifeSignedLocatorV3(self, "request")
        self.life_prepared = None
        self.phase = "prepared"
        self.metadata_atoms = {}
        self.expected = {}
        self.qualified = {}
        self.versions = {}
        self.pending = []
        self.complete = False
        self.capability = None
        self.groups = ()
        self.checked_groups = set()
    def require_registered_v3(self):
        work = self.work
        _actual_work_v3(work, self.installed)
        if _READERS.get(work) is not self or work not in _PHASES:
            raise AuthorityUnavailable("InternalLife Source reader lost its actual installed private registry")
        return self
    def require_current_v3(self, meter):
        self.require_registered_v3()
        self.work.require_current(meter=meter)
        from .owner_location_read_v3 import require_owner_location_for_model_graph_read_v3
        require_owner_location_for_model_graph_read_v3(self.work.db,
            installed_reader=self.installed, intent=self.work.request)
    def _plan_v3(self):
        from ..memory_types import source_key
        self.prepared.require_v3(self)
        self.request.require_v3(self)
        work = self.work
        p, frozen, saved, wire = self.prepared.value, self.prepared.embedded, self.request.value, self.request.embedded
        from ..model_broker.internal_life_content_v1 import TEMPLATE_VERSION, TEMPLATE_DIGEST
        workflow = self.installed.workflows.life_content
        authority = wire["envelope"]["authority"]
        frozen_input = frozen["input"]
        occurrence = frozen_input["cause"]["occurrence"]
        event, episode = occurrence["event"], occurrence["episode"]
        ns = {"bot_id": work.namespace.bot_id, "persona_id": work.namespace.persona_id}
        if (p["schema"] != "d06.internal-life-content-prepared.v1"
                or saved["schema"] != "d06.internal-life-worker-request.v2"
                or p["namespace"] != ns or p["job_id"] != work.request.job_id
                or p["installation_id"] != self.installed.bundle.installation_policy.installation_id
                or p["acquire_operation_id"] != work.request.operation_id
                or p["call_id"] != work.request.call_id
                or p["frozen_digest"] != self.prepared.column.embedded.sha256
                or saved["prepared_digest"] != self.prepared.metadata[0]
                or saved["binding_digest"] != work.request.binding_digest
                or saved["request_digest"] != work.request.request_digest
                or frozen["purpose"] != "consolidation"
                or workflow.purpose != "consolidation"
                or workflow.work_kind != "d06.encode_internal_life_content"
                or workflow.template_version != TEMPLATE_VERSION
                or (frozen["template_version"],frozen["template_digest"]) != (TEMPLATE_VERSION,TEMPLATE_DIGEST)
                or wire["prompt_template_digest"] != TEMPLATE_DIGEST
                or tuple(authority["audience"]) != (frozen_input["audience"],)
                or frozen_input["audience"] not in workflow.audiences
                or authority["purpose"] != "consolidation" or authority["namespace"] != ns
                or authority["actor"] != work.subject
                or wire["envelope"]["identity"]["operation_id"] != work.request.operation_id
                or wire["call_id"] != work.request.call_id
                or event["namespace"] != ns or episode["episode_ref"] != p["episode_ref"]
                or episode["source_refs"] != [event["activity"]["source_ref"]]
                or (frozen["provider_id"], frozen["model_id"], frozen["provider_config_digest"],
                    frozen["max_output_tokens"]) != (workflow.provider_id, workflow.model_id,
                    workflow.provider_config_digest, workflow.max_output_tokens)
                or (wire["provider_id"], wire["model_id"], wire["max_output_tokens"]) !=
                    (workflow.provider_id, workflow.model_id, workflow.max_output_tokens)
                or p["provider_config_ref"] != workflow.provider_config_ref):
            raise AuthorityUnavailable("InternalLife signed metadata differs from its actual acquired workflow/Source context")
        rows = wire["envelope"]["version_guard"]["read_versions"]
        from ..runtime.domain_production_erasure_v1 import decode_typed_production_value_v1
        versions = tuple(decode_typed_production_value_v1(row, GraphVersion) for row in rows)
        self.read_versions = versions
        roots = tuple(episode["source_refs"])
        expected = {version.key.token: version.revision for version in versions
            if version.key.type_name == "memory.source"}
        for ref in roots:
            if ref not in expected:
                raise AuthorityUnavailable("InternalLife actual experience root is outside the signed acquired Source inventory")
        for ref, revision in expected.items():
            key = AtomKey.from_token(ref)
            if key != source_key(*work.namespace.as_tuple, key.owner.subject) or revision < 1:
                raise AuthorityUnavailable("InternalLife Source root differs from its exact acquired namespace/version")
        if not expected or len(expected) > 256:
            raise AuthorityUnavailable("InternalLife signed Source family exceeds its existing finite bound")
        # Every Source actually consumed by the acquired frame is a separate root.
        # The current parents below receive their own Access and Correction check.
        work.operation.retain(8192 * len(expected) + 65536)
        self.expected = expected
        self.audience = frozen_input["audience"]
        self.pending = []
        self.graph_versions = {(version.key.token, version.revision) for version in versions}
        self.graph_versions.update((row["ref"], row["revision"]) for row in occurrence["historical_reads"])
        self.graph_tokens = {ref for ref, _ in self.graph_versions}
        self.original_operations = {p["prepare_operation_id"], p["acquire_operation_id"],
            occurrence["producing_operation_id"], event["causal_operation_id"]}
        activity = event["activity"]
        self.life_activity = activity
        self.original_refs = {frozen_input["cause"]["prepared_original_ref"],
            activity["start_original_ref"], activity["terminal_original_ref"]}
        self.original_keys = {("prepared",frozen_input["cause"]["prepared_original_ref"])}
        self.execution_ids = {activity["execution_id"]}
        self.job_ids = {work.request.job_id}
        self.job_ids.update(version.key.name for version in versions if version.key.type_name == "runtime.job")
        self.quote_versions = {(p["quote_id"], p["quote_version"])}
        self.body_quote_versions = set()
        self.artifact_descriptors = {}
        self.action_refs = set()
        self.reservation_history_pairs = set()
        self.parent_budget_refs = {wire["envelope"]["parent_budget_lease_ref"]}
        self.graph_tokens.update(version.key.token for version in self.versions.values())
        self.life_prepared = _LifePreparedSignedMetadataV3(self)
        self.phase = "life_prepared_metadata"
    def _groups_v3(self):
        from ..memory_types import source_key
        self.life_prepared.require_v3(self)
        raw = self.life_prepared.value
        rows = tuple(row for row in raw["read_rows"] if AtomKey.from_token(row["ref"]).type_name == "memory.source")
        life_sources = {row["ref"]:row["revision"] for row in rows}
        input_source = raw["plan"]["input_source"]
        from .life_model_original_family_read_v3 import life_model_progress_source_group_v3
        audiences,progress_purposes,progress_roots = life_model_progress_source_group_v3(raw)
        if (not life_sources or not audiences or len(set(audiences)) != len(audiences)
                or input_source["ref"] not in life_sources
                or input_source["revision"] != life_sources[input_source["ref"]]):
            raise AuthorityUnavailable("InternalLife progress metadata lost its actual Source roots/audiences")
        for row in rows:
            ref = row["ref"]
            key = AtomKey.from_token(ref)
            witness = self.work.sources.get(ref)
            if (key != source_key(*self.work.namespace.as_tuple,key.owner.subject) or not row["valid"]
                    or row["revision"] < 1 or self.expected.get(ref) != row["revision"]
                    or witness is None or witness.revision != row["revision"]
                    or witness.canonical_semantic_digest != row["digest"]
                    or ref == input_source["ref"] and row["digest"] != input_source["digest"]):
                raise AuthorityUnavailable("InternalLife progress Source is outside its exact signed acquired/current closure; HOLD")
            witness.require_current_v3()
        self.groups = (
            ("top_model",tuple(sorted(self.expected)),("consolidation",),(self.audience,)),
            ("life_progress",tuple(sorted(progress_roots)),progress_purposes,audiences))
        from .owner_location_read_v3 import require_owner_location_for_model_graph_read_v3
        owner = require_owner_location_for_model_graph_read_v3(self.work.db,
            installed_reader=self.installed,intent=self.work.request)
        for group,roots,purposes,group_audiences in self.groups:
            if (not set(purposes) <= set(owner.grant["purposes"])
                    or not set(group_audiences) <= set(owner.grant["audiences"])):
                raise AuthorityUnavailable("InternalLife actual Owner lacks a required consumer purpose/audience; HOLD")
            self.pending.extend((group,ref,purpose,audience)
                for ref in roots for purpose in purposes for audience in group_audiences)
        self.phase = "rights"
    def advance_v3(self, meter):
        from ..memory_types import source_key, access_key
        from ..domains.d06 import source_correction_head_key
        from ..domains.d07.qualified_attention_read import _qualify_source_rights_values_v3
        self.require_current_v3(meter)
        if self.phase in ("prepared", "request"):
            header = self.prepared if self.phase == "prepared" else self.request
            header.advance(meter)
            if header.complete:
                if self.phase == "prepared":
                    self.phase = "request"
                else:
                    self._plan_v3()
            return
        if self.phase == "life_prepared_metadata":
            self.life_prepared.advance(meter)
            if self.life_prepared.complete:
                self._groups_v3()
            return
        if self.phase != "rights":
            raise AuthorityUnavailable("InternalLife Source has another actual registered phase")
        if self.pending:
            group,ref,purpose,audience = self.pending.pop()
            identity = (group,ref,purpose,audience)
            if identity in self.checked_groups:
                return
            if ref not in self.qualified and len(self.qualified) >= 256:
                raise AuthorityUnavailable("InternalLife current Source ancestors exceed the original bounded family")
            key = AtomKey.from_token(ref)
            witness = self.work.sources.get(ref)
            if (ref not in self.expected or witness is None or not witness.valid
                    or witness.revision != self.expected[ref]):
                raise AuthorityUnavailable("InternalLife current Source differs from its signed acquired root")
            witness.require_current_v3()
            access = access_key(*self.work.namespace.as_tuple, key.owner.subject)
            correction = source_correction_head_key(self.work.namespace, key.owner.subject)
            access_atom = self.metadata_atoms.get(access)
            current_correction = self.work.heads.get(correction.token)
            head = (GraphAtom(correction, 0, {}, False) if current_correction is None
                else GraphAtom(correction, current_correction[0], {}, bool(current_correction[1])))
            record = _qualify_source_rights_values_v3(self.work.namespace, ref, witness,
                access_atom, head, audience=audience, purpose=purpose, metadata_only=True)
            if record is None:
                raise AuthorityUnavailable("InternalLife Source/Access/Correction purpose/audience is denied")
            self.work.operation.retain(8192)
            self.qualified[ref] = (witness, record)
            self.checked_groups.add(identity)
            for atom in (access_atom, head):
                self.versions[atom.key] = GraphVersion(atom.key, atom.revision)
            self.versions[key] = GraphVersion(key, witness.revision)
            self.pending.extend((group,source_key(*self.work.namespace.as_tuple,parent).token,purpose,audience)
                for parent in record.parent_source_ids)
            return
        active, done = set(), set()
        def visit(ref):
            if ref in active:
                raise AuthorityUnavailable("InternalLife current Source ancestry is cyclic")
            if ref in done:
                return
            active.add(ref)
            for parent in self.qualified[ref][1].parent_source_ids:
                visit(source_key(*self.work.namespace.as_tuple, parent).token)
            active.remove(ref)
            done.add(ref)
        for ref in self.expected:
            visit(ref)
        self.graph_versions.update((version.key.token, version.revision) for version in self.versions.values())
        self.graph_tokens.update(ref for ref, _ in self.graph_versions)
        self.complete = True
        self.capability = _InternalLifeBodyCapabilityV3(self)
    def release_v3(self):
        if self.capability is not None:
            _CAPABILITIES.pop(self.capability, None)
        for header in (self.prepared, self.request):
            _HEADERS.pop(header, None)
        self.metadata_atoms.clear()
        if self.life_prepared is not None:
            _LIFE_HEADERS.pop(self.life_prepared,None)
            self.life_prepared = None
        self.groups = ()
        self.checked_groups.clear()
        self.expected.clear()
        self.qualified.clear()
        self.versions.clear()
        self.pending.clear()
        self.capability = None


class _InternalLifeBodyCapabilityV3:
    def __init__(self, reader):
        reader.require_registered_v3()
        if not reader.complete:
            raise AuthorityUnavailable("InternalLife body cannot precede every independent Source right")
        self.reader = reader
        self.work = reader.work
        self.graph_stamp = self.work.graph_stamp
        self.life_header = reader.life_prepared.require_v3(reader)
        self.consumer_groups = reader.groups
        self.consumer_coverage = frozenset(reader.checked_groups)
        self.deadline_utc = min(self.work.deadline_utc,
            reader.request.embedded["envelope"]["deadline_utc"],
            reader.prepared.embedded["input"]["expires_at_utc"])
        self.body = None
        _CAPABILITIES[self] = self._identity_v3()
    def _identity_v3(self):
        work = self.work
        return (self.reader, work, work.controller, self.reader.installed, work.operation,
            work.scope, work.permit, work.request, work.selection_digest, self.graph_stamp,
            self.deadline_utc, self.life_header, self.consumer_groups, self.consumer_coverage, self.body)
    def require_v3(self):
        reader, work = self.reader, self.work
        reader.require_registered_v3()
        if (_CAPABILITIES.get(self) != self._identity_v3() or not reader.complete
                or reader.capability is not self or work.graph_stamp != self.graph_stamp
                or reader.life_prepared is not self.life_header or reader.groups != self.consumer_groups
                or frozenset(reader.checked_groups) != self.consumer_coverage
                or work.controller.clock() >= self.deadline_utc):
            raise AuthorityUnavailable("InternalLife body capability changed its current all-Source Work/permit/TTL")
        self.life_header.require_v3(reader)
        for witness, _ in reader.qualified.values():
            witness.require_current_v3()
        return self
    def seal_v3(self, body):
        self.require_v3()
        if self.body is not None and self.body != body:
            raise AuthorityUnavailable("InternalLife body changed its actual sealed same-capability result")
        self.body = body
        _CAPABILITIES[self] = self._identity_v3()
        return body


def internal_life_model_namespace_recipe_v3(work):
    reader = _READERS.get(work)
    return None if reader is None else reader.require_registered_v3()


def internal_life_model_namespace_retains_type_v3(reader, key):
    from ..memory_types import access_key
    reader.require_registered_v3()
    return key.type_name == access_key(*reader.work.namespace.as_tuple, "source-metadata-type").type_name


class _InternalLifeAccessMetadataColumnV3(DispatchOriginalJSONReadV3):
    def __init__(self, reader, key, revision, valid, cell_id):
        reader.require_registered_v3()
        self.reader, self.key, self.revision, self.valid = reader, key, revision, bool(valid)
        super().__init__(reader.work, table="graph_atoms", column="value",
            key_columns=("token", "bot", "persona"), key=(key.token, *reader.work.namespace.as_tuple),
            cell_id=cell_id)
        self.parser = C09CanonicalJSONStreamV2(ensure_ascii=self.cell.header[0] == "canonical-json.ascii.v1")
    def finish_metadata_v3(self):
        from ..memory_types import validate_access
        value = self.require_v3(self.reader.work)
        validate_access(value)
        atom = GraphAtom(self.key, self.revision, value, self.valid)
        self.reader.metadata_atoms[self.key] = atom
        return atom


def internal_life_model_namespace_metadata_column_v3(reader, key, revision, valid, cell_id):
    if not internal_life_model_namespace_retains_type_v3(reader, key):
        raise AuthorityUnavailable("InternalLife namespace selected a protected body before Source qualification")
    return _InternalLifeAccessMetadataColumnV3(reader, key, revision, valid, cell_id)


def advance_internal_life_model_source_v3(work, meter):
    reader = internal_life_model_namespace_recipe_v3(work)
    if reader is None:
        raise AuthorityUnavailable("InternalLife Source phase has no actual installed private reader")
    reader.advance_v3(meter)
    if reader.complete:
        work.phase = "validate"


def require_internal_life_model_body_v3(db, installed_reader, intent):
    from .current_authority_graph_read_v3 import _authority_attachment_owner_v3
    work = _authority_attachment_owner_v3(db)
    if work is None:
        raise AuthorityUnavailable("InternalLife model body lacks its original actual MODEL Work")
    reader = _READERS.get(work)
    if (reader is None or reader.installed is not installed_reader or work.request is not intent
            or not db.in_transaction or reader.capability is None):
        raise AuthorityUnavailable("InternalLife body crossed its independently qualified reader/intent/SQL scope")
    reader.require_registered_v3()
    from .owner_location_read_v3 import require_owner_location_for_model_graph_read_v3
    require_owner_location_for_model_graph_read_v3(db, installed_reader=installed_reader, intent=intent)
    return reader.capability.require_v3()


def release_internal_life_model_source_v3(work):
    reader = _READERS.pop(work, None)
    if reader is not None:
        reader.release_v3()
    _PHASES.pop(work, None)

def require_internal_life_body_request_v3(work, request):
    reader = _READERS.get(work)
    if reader is None:
        return False
    if reader.capability is None:
        raise AuthorityUnavailable("InternalLife protected body cannot precede ALL independent Source EOF")
    reader.capability.require_v3()
    table = request[0]
    if table == "life_model.source_note_action_locator.v3":
        allowed = len(request) == 2 and request[1] in reader.action_refs
    elif table == "life_model.artifact_body.v3":
        allowed = len(request) == 2 and request[1] in reader.execution_ids
    elif len(request) == 4:
        key_columns, key = request[2:4]
        selected = dict(zip(key_columns, key))
        if table in {"graph_atoms", "graph_history"}:
            token = selected["token"]
            allowed = token in reader.graph_tokens
            if table == "graph_history":
                allowed = allowed and (token, selected["revision"]) in reader.graph_versions
        elif table == "graph_dependencies":
            allowed = selected["dependent_token"] in reader.graph_tokens
        elif table == "runtime_jobs":
            allowed = selected["job_id"] in reader.job_ids
        elif table == "graph_internal_life_content_originals_v1":
            allowed = (selected.get("original_ref") == work.request.job_id
                and selected.get("kind") in {"prepared", "prepare_commit"})
        elif table == "graph_internal_life_worker_originals_v2":
            allowed = (selected.get("job_id") == work.request.job_id
                and selected.get("kind") in {"binding", "request", "acquire_commit", "call"})
        elif table in {"graph_domain_production_originals_v1", "graph_bundle_operations", "graph_bundle_fences_v2"}:
            allowed = selected.get("operation_id") in reader.original_operations
        elif table == "graph_events":
            allowed = selected.get("event_id") in reader.original_operations
        elif table == "d02_body_quotes_v1":
            allowed = any(ref == selected.get("quote_id") for ref, _ in reader.body_quote_versions)
        elif table == "graph_d11_life_originals_v1":
            allowed = (selected.get("kind"),selected.get("original_ref")) in reader.original_keys
        elif table == "graph_d11_life_adoption_originals_v1":
            allowed = selected.get("execution_id") in reader.execution_ids
        elif table == "runtime_resource_quotes":
            allowed = (selected.get("quote_id"), selected.get("version")) in reader.quote_versions
        elif table == "runtime_budget_reservations":
            allowed = (selected.get("lease_id") in reader.parent_budget_refs
                and selected.get("operation_id") in reader.original_operations)
        elif table in {"runtime_budget_leases", "runtime_budget_grants"}:
            allowed = selected.get("lease_id") in reader.parent_budget_refs
        elif table == "runtime_budget_operations":
            allowed = selected.get("operation_id") in reader.original_operations
        elif table == "graph_recovery_metadata_v2":
            allowed = tuple(key) == work.namespace.as_tuple
        else:
            allowed = False
    elif len(request) == 5 and table == "graph_dependencies":
        allowed = request[3][0] in reader.graph_tokens
    else:
        allowed = False
    if not allowed:
        raise AuthorityUnavailable("InternalLife body point is outside its exact signed/qualified family")
    return True


def register_internal_life_source_body_v3(work, attachment, key, value):
    reader = _READERS.get(work)
    if reader is None or key.type_name != "memory.source":
        return
    reader.capability.require_v3()
    from ..memory_types import SourceRecord
    witness, _ = reader.qualified[key.token]
    column = attachment.json_columns["value"]
    if column.sha256 != witness.payload_sha256 or dict(zip(attachment.columns, attachment.row))["revision"] != witness.revision:
        raise AuthorityUnavailable("InternalLife Source body differs from its independently qualified complete EOF")
    record = SourceRecord.from_dict(value)
    if key.token == reader.life_activity["source_ref"]:
        payload = json.loads(record.text)
        if payload["schema"] != "d10.actual-life-activity-experience.v1":
            raise AuthorityUnavailable("InternalLife selected experience Source has another closed schema")
        reader.original_refs.add(payload["actual_provenance_ref"])
        reader.original_keys.add(("experience",payload["actual_provenance_ref"]))


def register_internal_life_prepared_body_v3(db, prepared):
    from .current_authority_graph_read_v3 import _authority_attachment_owner_v3
    work = _authority_attachment_owner_v3(db)
    reader = None if work is None else _READERS.get(work)
    if reader is None:
        return False
    reader.capability.require_v3()
    from ..runtime.d11_life_preparation_v1 import D11LifePreparedV1, SIGN_KIND
    from ..domains.d01.production_operations_v1 import plain_v1
    if type(prepared) is not D11LifePreparedV1:
        raise AuthorityUnavailable("InternalLife Body extension requires the actual signed Life preparation type")
    binding = prepared.binding
    identity = ('graph_d11_life_originals_v1',
        ('producing_operation_id','payload_json','payload_digest','signature'),
        ('bot','persona','kind','original_ref'),
        (*work.namespace.as_tuple,'prepared',binding.prepared_original_ref))
    original = work.attachments.get(identity)
    if original is None or not original.complete:
        raise AuthorityUnavailable("InternalLife Body extension lost its same-Work signed preparation column")
    row = dict(zip(original.columns, original.row))
    if original.encoded['payload_json'] != canonical_serialize(plain_v1(prepared)):
        raise AuthorityUnavailable("InternalLife Body extension changed its actual whole signed preparation")
    reader.installed.readers.issuer._signer.verify(SIGN_KIND,
        canonical_serialize((work.namespace,'prepared',binding.prepared_original_ref,row['payload_digest'])),
        row['signature'])
    header = reader.life_prepared.require_v3(reader)
    from hashlib import sha256
    observed_rows = tuple({"ref":item.ref,"revision":item.revision,"valid":item.valid,
        "digest":sha256(item.value_json.encode("ascii")).hexdigest()} for item in prepared.read_rows)
    observed_plan = {name:plain_v1(getattr(prepared.plan,name)) for name in header.value["plan"]}
    if (row["payload_digest"] != header.metadata[1] or row["producing_operation_id"] != header.metadata[0]
            or binding != header.binding
            or canonical_serialize(observed_plan) != canonical_serialize(header.value["plan"])
            or canonical_serialize(observed_rows) != canonical_serialize(header.value["read_rows"])):
        raise AuthorityUnavailable("InternalLife complete Life body differs from its pre-ALL signed metadata plan")
    if (binding.namespace != work.namespace or binding.execution_id not in reader.execution_ids
            or binding.prepared_original_ref not in reader.original_refs
            or binding.activity_id != reader.life_activity["activity_id"]
            or binding.effect_id != reader.life_activity["effect_id"]
            or binding.artifact_ref != reader.life_activity["artifact_ref"]
            or prepared.plan.input_source.ref not in reader.qualified):
        raise AuthorityUnavailable("InternalLife actual signed Life preparation crossed its qualified occurrence")
    from .life_model_original_family_read_v3 import life_model_family_plan_from_prepared_v3
    plan = life_model_family_plan_from_prepared_v3(prepared,"prepared",binding.prepared_original_ref,
        row["payload_digest"],row["producing_operation_id"])
    reader.original_operations.update(plan.operations)
    reader.original_refs.update(plan.original_refs)
    reader.original_keys.update((locator.recipe[4][2],locator.recipe[4][3]) for locator in plan.locators
        if locator.recipe[1] == "graph_d11_life_originals_v1"
        and locator.recipe[3] == ("bot","persona","kind","original_ref"))
    reader.original_keys.add(("adoption_receipt",binding.execution_id))
    reader.job_ids.update(plan.job_ids)
    reader.execution_ids.update(plan.execution_ids)
    reader.quote_versions.update(plan.quote_versions)
    reader.body_quote_versions.update(plan.body_quote_versions)
    reader.action_refs.update(plan.action_refs)
    reader.parent_budget_refs.add(binding.parent_budget_lease_ref)
    from ..runtime.d11_life_contract_v1 import LifeBodyComponentContractV1
    contract = LifeBodyComponentContractV1(**json.loads(prepared.plan.body_effect_request_json))
    reader.reservation_history_pairs.add((contract.reservation_ref,contract.body_prepare_operation_id))
    return True


def _internal_life_body_reader_v3(db):
    from .current_authority_graph_read_v3 import _authority_attachment_owner_v3
    work = _authority_attachment_owner_v3(db)
    reader = None if work is None else _READERS.get(work)
    if reader is None:
        return None
    if reader.capability is None:
        raise AuthorityUnavailable("InternalLife body dispatch cannot precede independent ALL Source EOF")
    reader.capability.require_v3()
    return reader


def read_bound_internal_life_body_point_v3(db, *, table, columns, key_columns, key):
    if _internal_life_body_reader_v3(db) is None:
        return False, None
    from .current_authority_graph_read_v3 import read_bound_authority_graph_attachment_v3
    return read_bound_authority_graph_attachment_v3(db, table=table, columns=columns,
        key_columns=key_columns, key=key)


def read_bound_internal_life_history_v3(db, token, revision, columns):
    return read_bound_internal_life_body_point_v3(db, table="graph_history", columns=tuple(columns),
        key_columns=("token", "revision"), key=(token, revision))


def read_bound_internal_life_history_by_event_v3(db, token, event_id):
    reader = _internal_life_body_reader_v3(db)
    if reader is None:
        return False, None
    if (token,event_id) not in reader.reservation_history_pairs:
        raise AuthorityUnavailable("InternalLife Body reservation history crossed its actual original family")
    from ..runtime_storage_v3 import runtime_storage_quantum_v3
    with runtime_storage_quantum_v3(db) as meter:
        item = meter.read_fixed_row(db, "graph_history", ("revision",),
            "token=? AND event_id=? ORDER BY revision", (token, event_id))
        if item is None:
            return True, ()
        more = meter.read_fixed_row(db, "graph_history", ("revision",),
            "token=? AND event_id=? AND revision>? ORDER BY revision", (token, event_id, item[0]))
        if more is not None:
            raise AuthorityUnavailable("InternalLife Body original lost its unique reservation history")
        _, row = read_bound_internal_life_history_v3(db, token, item[0],
            ("event_id","value","valid","event_bot","event_persona"))
        if row is None or row[0] != event_id or row[3:] != reader.work.namespace.as_tuple:
            raise AuthorityUnavailable("InternalLife Body reservation history crossed its exact event/namespace")
        return True, (row[:3],)



def read_bound_internal_life_artifact_v3(db, prepared):
    reader = _internal_life_body_reader_v3(db)
    if reader is None:
        return False, None
    register_internal_life_prepared_body_v3(db, prepared)
    from .current_authority_graph_read_v3 import AuthorityGraphAttachmentRequiredV3
    request = ("life_model.artifact_body.v3", prepared.binding.execution_id)
    task = reader.work.attachments.get(request)
    if task is None:
        if reader.work.complete:
            raise AuthorityUnavailable("InternalLife final artifact body was not prepared by its same Work")
        raise AuthorityGraphAttachmentRequiredV3(request)
    from ..runtime_storage_v3 import runtime_storage_quantum_v3
    with runtime_storage_quantum_v3(db) as meter:
        return True, task.require_row_v3(reader.work, meter)


def read_bound_internal_life_action_refs_v3(db, namespace, action_ref):
    reader = _internal_life_body_reader_v3(db)
    if reader is None:
        return False, None
    if namespace != reader.work.namespace or action_ref not in reader.action_refs:
        raise AuthorityUnavailable("InternalLife fixed Action locator crossed its actual signed Life plan")
    from .current_authority_graph_read_v3 import AuthorityGraphAttachmentRequiredV3
    request = ("life_model.source_note_action_locator.v3",action_ref)
    task = reader.work.attachments.get(request)
    if task is None:
        if reader.work.complete:
            raise AuthorityUnavailable("InternalLife final Action locator was not prepared by the same Work")
        raise AuthorityGraphAttachmentRequiredV3(request)
    from ..runtime_storage_v3 import runtime_storage_quantum_v3
    with runtime_storage_quantum_v3(db) as meter:
        return True, task.require_row_v3(reader.work, meter)


def register_internal_life_signed_original_v3(db, kind, original_ref, raw, operation_id):
    reader = _internal_life_body_reader_v3(db)
    if reader is None:
        return False
    work = reader.work
    if (kind,original_ref) not in reader.original_keys:
        raise AuthorityUnavailable("InternalLife protected signed original is outside its same-capability lineage")
    identity = ("graph_d11_life_originals_v1",
        ("producing_operation_id","payload_json","payload_digest","signature"),
        ("bot","persona","kind","original_ref"),(*work.namespace.as_tuple,kind,original_ref))
    original = work.attachments.get(identity)
    if original is None or not original.complete:
        raise AuthorityUnavailable("InternalLife signed body extension lacks its actual complete column")
    from ..runtime.d11_life_preparation_v1 import SIGN_KIND
    row = dict(zip(original.columns,original.row))
    if row["producing_operation_id"] != operation_id or original.encoded["payload_json"] != canonical_serialize(raw):
        raise AuthorityUnavailable("InternalLife signed body extension changed its authenticated original")
    reader.installed.readers.issuer._signer.verify(SIGN_KIND,
        canonical_serialize((work.namespace,kind,original_ref,row["payload_digest"])),row["signature"])
    reader.original_operations.add(operation_id)
    if kind == "experience":
        from ..runtime.d11_life_contract_v1 import D11LifeTerminalV1,life_from_wire_v1
        terminal = life_from_wire_v1(raw["terminal"],D11LifeTerminalV1)
        binding = terminal.binding
        if (binding.namespace != work.namespace or binding.execution_id not in reader.execution_ids
                or binding.activity_id != reader.life_activity["activity_id"]
                or binding.effect_id != reader.life_activity["effect_id"]
                or binding.artifact_ref != reader.life_activity["artifact_ref"]
                or terminal.payload.artifact_digest != reader.life_activity["artifact_digest"]):
            raise AuthorityUnavailable("InternalLife signed experience differs from its exact acquired occurrence")
        reader.artifact_descriptors[binding.execution_id] = (binding.digest,binding.artifact_ref,
            terminal.payload.artifact_digest,terminal.payload.artifact_length)
    if kind == "source_note_action":
        from ..runtime.d08_source_note_action_v1 import source_note_action_original_from_wire_v1
        value = source_note_action_original_from_wire_v1(raw)
        if value.action_intent_ref not in reader.action_refs:
            raise AuthorityUnavailable("InternalLife signed Action extension crossed its actual Life plan")
        histories = tuple((ref, revision) for ref, revision, _ in value.write_commitments)
        histories += tuple((ref, revision) for ref, revision, _, _, _ in value.context_commitments)
        if any(AtomKey.from_token(ref).type_name == "memory.source" and ref not in reader.qualified
                for ref, _ in histories):
            raise AuthorityUnavailable("InternalLife signed Action introduces a Source outside the independent ALL closure")
        reader.graph_versions.update((ref, revision) for ref, revision, _ in value.write_commitments)
        reader.graph_versions.update((ref, revision) for ref, revision, _, _, _ in value.context_commitments)
        reader.original_operations.update(operation for _, _, _, operation, _ in value.context_commitments)
        reader.graph_tokens.update(ref for ref, _ in reader.graph_versions)
    return True


def require_internal_life_model_body_request_v3(work, request):
    reader = _READERS.get(work)
    if reader is None:
        return False
    if len(request) != 5:
        raise AuthorityUnavailable("InternalLife shared body IO has another fixed recipe shape")
    recipe, table, columns, key_columns, key = request
    if recipe == "life_model.graph_body.v3" and table in {"graph_atoms","graph_history"}:
        return require_internal_life_body_request_v3(work,(table,columns,key_columns,key))
    if (recipe == "life_model.artifact_body.v3" and table == "graph_d11_life_artifact_stage_v1"
            and columns == ("binding_digest","artifact_ref","artifact_digest","artifact_length")
            and key_columns == ("bot","persona","execution_id") and tuple(key[:2]) == work.namespace.as_tuple):
        return require_internal_life_body_request_v3(work,(recipe,key[2]))
    if (recipe == "life_model.source_note_action_locator.v3" and table == "graph_d11_life_originals_v1"
            and columns == ("original_ref","payload_digest","signature")
            and key_columns == ("bot","persona","kind","action_intent_ref")
            and tuple(key[:3]) == (*work.namespace.as_tuple,"source_note_action")):
        return require_internal_life_body_request_v3(work,(recipe,key[3]))
    raise AuthorityUnavailable("InternalLife shared body IO is outside its independent closed recipe")


def internal_life_model_artifact_descriptor_v3(work, execution_id):
    reader = _READERS.get(work)
    if reader is None:
        return False, None
    require_internal_life_body_request_v3(work,("life_model.artifact_body.v3",execution_id))
    descriptor = reader.artifact_descriptors.get(execution_id)
    if descriptor is None:
        raise AuthorityUnavailable("InternalLife artifact has no actual signed experience descriptor")
    return True, descriptor


def internal_life_model_action_locator_eof_v3(work, action_ref, original_ref, column, metadata):
    reader = _READERS.get(work)
    if reader is None:
        return False
    require_internal_life_body_request_v3(work,("life_model.source_note_action_locator.v3",action_ref))
    from .life_model_original_family_read_v3 import _LifeModelActionLocatorColumnV3
    if (type(column) is not _LifeModelActionLocatorColumnV3 or column.owner is not work
            or not column.complete or column.table != "graph_d11_life_originals_v1"
            or column.column != "payload_json"
            or column.key != (*work.namespace.as_tuple,"source_note_action",original_ref)
            or metadata[0] != original_ref or column.sha256 != metadata[1]):
        raise AuthorityUnavailable("InternalLife Action locator did not emit its actual signed same-Work EOF")
    raw = column.require_v3(work)
    if raw["action_intent_ref"] != action_ref:
        raise AuthorityUnavailable("InternalLife Action locator differs from its authenticated actual Life plan")
    from ..runtime.d11_life_preparation_v1 import SIGN_KIND
    reader.installed.readers.issuer._signer.verify(SIGN_KIND,
        canonical_serialize((work.namespace,"source_note_action",original_ref,metadata[1])),metadata[2])
    reader.original_refs.add(original_ref)
    reader.original_keys.add(("source_note_action",original_ref))
    return True
