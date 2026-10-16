"""Actual Numeric model Source metadata on its own Authority Work and MODEL permit."""
from types import SimpleNamespace
from weakref import WeakKeyDictionary

from .contract import AuthorityUnavailable
from ..graph_types import AtomKey, GraphAtom, GraphVersion
from ..runtime_contracts import NamespaceId, canonical_digest
from ..runtime.dispatch_current_inventory_v3 import _detach_value_v3, _heap
from ..runtime.current_life_numeric_metadata_v1 import NumericMetadataTaskV1

_ISSUER = object()
_READERS = WeakKeyDictionary()
_WORK_READERS = WeakKeyDictionary()
_MODEL_PHASES = WeakKeyDictionary()
_RESULT_BRIDGES=WeakKeyDictionary()
_OPERATION = 'numeric_model_seal_observer_v3'


def require_authority_numeric_metadata_work_v3(reader):
    if (type(reader) is not AuthorityNumericSourceReadV3
            or _READERS.get(reader) != reader._identity_v3()
            or _WORK_READERS.get(reader.work) is not reader
            or reader.operation.closed):
        raise AuthorityUnavailable('Numeric metadata requires its exact actual Authority Work')
    reader.work._actual()
    return reader


def numeric_authority_source_reader_v3(work):
    reader = _WORK_READERS.get(work)
    return None if reader is None else require_authority_numeric_metadata_work_v3(reader)


def numeric_metadata_issuers_v3(reader):
    require_authority_numeric_metadata_work_v3(reader)
    return reader.installed_reader.readers.issuer, reader.installed_reader.readers.resource_issuer


class AuthorityNumericSourceReadV3:
    def __init__(self, issuer, work, installed_reader, owner_entry):
        from .current_life_numeric_v1 import InstalledLifeNumericModelGraphReaderV1
        from .owner_location_read_v3 import _OWNER_MODEL_LOCATION_ENTRIES_V3
        state = _OWNER_MODEL_LOCATION_ENTRIES_V3.get(work)
        if (issuer is not _ISSUER or type(installed_reader) is not InstalledLifeNumericModelGraphReaderV1
                or state is None or state[0] is not installed_reader or state[4] is not owner_entry
                or work.controller.verifier._life_numeric_reader_v1 is not installed_reader
                or work.owner_model_work_kind != 'd06.encode_internal_life_numeric'
                or work.permit.operation != 'model_egress' and work not in _RESULT_BRIDGES or work.request.job_id == ''):
            raise AuthorityUnavailable('Numeric Source recipe requires its actual installed model and Owner EOF')
        self.work, self.installed_reader, self.owner_entry = work, installed_reader, owner_entry
        self.db, self.namespace, self.operation = work.db, work.namespace, work.operation
        self.operation_kind = _OPERATION
        self.attachments = {}; self.metadata_atoms = {}; self.metadata_columns = {}
        self.selectors = {('numeric_job', 'numeric_continuation', work.request.job_id)}
        self.tasks = []; self.pending = None; self.complete = False
        self.roots = (); self.expectations = {}; self.qualified = {}; self.versions = {}
        self.phase = 'job'; self.request = None; self.binding = None
        self.family_edges={};self.family_plans={};self.graph_versions=set();self.graph_tokens=set()
        self.original_operations=set();self.original_keys=set();self.execution_ids=set();self.job_ids=set()
        self.quote_versions=set();self.body_quote_versions=set();self.action_refs=set();self.parent_budget_refs=set()
        self.artifact_descriptors={};self.life_bindings={};self.history_event_pairs={};self.family_initialized=False
        self.source_groups={};self.group_qualified={};self.progress_prepared_metadata=None
        _READERS[self] = self._identity_v3(); _WORK_READERS[work] = self
        self.operation.register_retained_state_v3(self)

    def _identity_v3(self):
        return (self.work, self.installed_reader, self.owner_entry, self.operation,
            self.work.scope, self.work.permit, self.work.request, self.work.selection_digest)

    def _runtime_retained_heap_bytes_v3(self):
        return _heap((self.attachments, self.metadata_atoms, self.metadata_columns, self.selectors,
            self.tasks, self.roots, self.expectations, self.qualified, self.versions, self.request, self.binding,
            self.family_edges,self.family_plans,self.graph_versions,self.graph_tokens,self.original_operations,self.original_keys,
            self.execution_ids,self.job_ids,self.quote_versions,self.body_quote_versions,self.action_refs,self.parent_budget_refs,
            self.artifact_descriptors,self.life_bindings,self.history_event_pairs,self.source_groups,self.group_qualified,self.progress_prepared_metadata))

    def require_registered_v3(self):
        return require_authority_numeric_metadata_work_v3(self)

    def require_current(self, *, meter=None):
        self.require_registered_v3()
        if meter is not None: self.work.require_current(meter=meter)
        return self

    def require_current_v3(self, meter):
        return self.require_current(meter=meter)

    def metadata_v3(self, mode, profile, ref, meter):
        identity = (mode, profile, ref); self.selectors.add(identity)
        task = self.attachments.get(identity)
        if task is None:
            task = NumericMetadataTaskV1(self, identity); self.attachments[identity] = task
            self.tasks.append(task)
        if not task.advance(meter): return None
        return _detach_value_v3(task.result), task

    def advance_v3(self, meter):
        self.require_current(meter=meter)
        if self.complete:
            for task in self.tasks: task.require_header_v1(meter)
            return True
        if self.phase == 'job':
            value = self.metadata_v3('numeric_job', 'numeric_continuation', self.work.request.job_id, meter)
            if value is None: return False
            continuation, task = value
            from ..model_broker.internal_life_numeric_v1 import WORK_KIND
            if task.metadata[0] != WORK_KIND:
                raise AuthorityUnavailable('Numeric model Source job has another actual work kind')
            episode = AtomKey.from_token(continuation['episode_ref'])
            from ..runtime.d06_internal_life_episode_v2 import EPISODE, PROVENANCE
            if episode.type_name != EPISODE or NamespaceId.from_key(episode) != self.namespace:
                raise AuthorityUnavailable('Numeric model Source occurrence crossed namespace')
            self.request = SimpleNamespace(episode_ref=episode.token,
                causal_operation_id=continuation['causal_operation_id'])
            self.continuation = continuation; self.provenance_ref = AtomKey(episode.owner, PROVENANCE, 'record').token
            self.phase = 'provenance'; return False
        if self.phase == 'provenance':
            value = self.metadata_v3('graph', 'episode', self.provenance_ref, meter)
            if value is None: return False
            proof, task = value; activity = proof['event']['activity']
            if (proof['episode']['episode_ref'] != self.request.episode_ref
                    or NamespaceId(**proof['event']['namespace']) != self.namespace
                    or proof['event']['causal_operation_id'] != self.request.causal_operation_id
                    or proof['episode']['source_refs'] != [activity['source_ref']]):
                raise AuthorityUnavailable('Numeric model Source occurrence/cause differs')
            self.activity = activity; self.provenance = proof
            from ..runtime.d04_life_before_original_v1 import life_d04_before_ref_v1
            from ..runtime.d06_life_numeric_context_v1 import life_numeric_context_ids_v1
            self.before_ref = life_d04_before_ref_v1(self.namespace, activity['execution_id'])
            self.context_ref = life_numeric_context_ids_v1(self.namespace, self.request.episode_ref)['original']
            self.phase = 'before'; return False
        if self.phase == 'before':
            value = self.metadata_v3('life', 'before', self.before_ref, meter)
            if value is None: return False
            self.before, self.before_task = value; self.phase = 'context'; return False
        if self.phase == 'context':
            value = self.metadata_v3('life', 'context', self.context_ref, meter)
            if value is None: return False
            context, task = value; activity = self.activity
            if (NamespaceId(**self.before['namespace']) != self.namespace
                    or self.before['original_ref'] != self.before_ref
                    or self.before['execution_id'] != activity['execution_id']
                    or NamespaceId(**context['namespace']) != self.namespace
                    or context['episode_ref'] != self.request.episode_ref
                    or context['source_ref'] != activity['source_ref']
                    or context['before_ref'] != self.before_ref
                    or context['before_digest'] != self.before_task.column.canonical_digest):
                raise AuthorityUnavailable('Numeric model Source signed Before/context differs')
            from ..model_broker.internal_life_numeric_v1 import InternalLifeNumericIdentityV1, internal_life_numeric_ids_v1
            self.identity = InternalLifeNumericIdentityV1(self.namespace, self.request.episode_ref,
                context['execution_id'], context['source_ref'], context['occurrence_digest'],
                context['before_digest'], task.column.canonical_digest)
            self.ids = internal_life_numeric_ids_v1(self.identity)
            if self.ids['job'] != self.work.request.job_id:
                raise AuthorityUnavailable('Numeric model Source derived once job differs')
            self.context_metadata=context
            self.phase = 'prepared'; return False
        if self.phase == 'prepared':
            value = self.metadata_v3('life', 'prepared', self.ids['job'], meter)
            if value is None: return False
            prepared, self.prepared_task = value
            from ..domains.d01.production_operations_v1 import plain_v1
            if (prepared['job_id'] != self.ids['job'] or prepared['frozen']['identity'] != plain_v1(self.identity)
                    or prepared['activity_id'] != self.activity['activity_id']):
                raise AuthorityUnavailable('Numeric model Source prepared identity differs')
            self.prepared_metadata = prepared
            from ..memory_types import source_key
            original_sources = {source_key(*self.namespace.as_tuple, ref).token: revision
                for ref, revision in self.work.request.source_revisions}
            prepared_sources = {}
            for row in prepared['read_rows']:
                key=AtomKey.from_token(row['ref'])
                if NamespaceId.from_key(key)!=self.namespace:
                    raise AuthorityUnavailable('Numeric signed preparation Source crossed original namespace')
                if key.type_name=='memory.source':
                    if key!=source_key(*self.namespace.as_tuple,key.owner.subject) or key.token in prepared_sources:
                        raise AuthorityUnavailable('Numeric signed preparation Source token or unique version differs')
                    prepared_sources[key.token]=row['revision']
            if (len(original_sources)!=len(self.work.request.source_revisions)
                    or prepared_sources!=original_sources or tuple(sorted(self.work.request.source_refs))!=
                    tuple(sorted(ref for ref,_ in self.work.request.source_revisions))):
                raise AuthorityUnavailable('Numeric signed preparation Source closure differs from original acquired model input; HOLD')
            self.expectations=original_sources
            roots = set(self.before['source_roots']); roots.add(self.identity.source_ref)
            for row in self.provenance['current_reads']:
                key = AtomKey.from_token(row['ref'])
                if NamespaceId.from_key(key) != self.namespace:
                    raise AuthorityUnavailable('Numeric model Source declared version crossed namespace')
                if key.type_name == 'memory.source':
                    if key.token not in self.expectations or self.expectations[key.token] != row['revision']:
                        raise AuthorityUnavailable('Numeric current Source lies outside original acquired closure or revision; HOLD')
                    roots.add(key.token)
            roots.update(prepared_sources)
            for row in self.provenance['historical_reads']:
                key=AtomKey.from_token(row['ref'])
                if NamespaceId.from_key(key)!=self.namespace:
                    raise AuthorityUnavailable('Numeric occurrence historical family crossed namespace')
            if not roots or len(roots) > 256 or not roots <= self.expectations.keys():
                raise AuthorityUnavailable('Numeric model Source roots exceed original acquired closure; HOLD')
            self.roots = tuple(sorted(roots)); self.phase = 'prepare_commit'; return False
        if self.phase == 'prepare_commit':
            value = self.metadata_v3('numeric_prepare', 'numeric_prepare_commit', self.ids['prepare'], meter)
            if value is None: return False
            original, task = value
            if (original['provenance']['prepared_digest'] != self.prepared_task.column.canonical_digest
                    or original['provenance']['numeric_input_digest'] != self.continuation['numeric_input_digest']):
                raise AuthorityUnavailable('Numeric model Source continuation lost its actual prepare original')
            self.phase = 'binding'; return False
        if self.phase == 'binding':
            value = self.metadata_v3('life', 'binding', self.ids['job'], meter)
            if value is None: return False
            raw, task = value
            from ..runtime.d06_life_numeric_worker_v1 import decode_life_numeric_worker_binding_v1
            self.binding = decode_life_numeric_worker_binding_v1(raw)
            if (self.binding.job_id != self.ids['job'] or self.binding.digest != self.work.request.binding_digest
                    or self.binding.worker_subject != self.work.subject):
                raise AuthorityUnavailable('Numeric model Source signed worker binding differs')
            self.phase = 'request'; return False
        if self.phase == 'request':
            value = self.metadata_v3('life', 'request', self.ids['job'], meter)
            if value is None: return False
            request, task = value
            if (request['prepared_digest'] != self.prepared_task.column.canonical_digest
                    or request['binding_digest'] != self.binding.digest
                    or request['request_digest'] != self.work.request.request_digest):
                raise AuthorityUnavailable('Numeric model Source committed request digest differs')
            self.request_metadata = request; self.phase = 'acquire'; return False
        if self.phase == 'acquire':
            value = self.metadata_v3('life', 'acquire_commit', self.ids['job'], meter)
            if value is None: return False
            committed, task = value
            from ..runtime.domain_production_originals_v1 import _receipt
            receipt = _receipt(committed['receipt'])
            from ..runtime.d11_types import runtime_job_key
            expected = runtime_job_key(*self.namespace.as_tuple, self.activity['activity_id'], self.ids['job'])
            if (receipt.status != 'committed' or receipt.operation_id != self.ids['acquire']
                    or len(receipt.write_versions) != 1 or receipt.write_versions[0].key != expected
                    or receipt.write_versions[0].revision < 1 or committed['receipt_digest'] != canonical_digest(receipt)
                    or (committed['prepared_digest'], committed['binding_digest'], committed['request_digest']) !=
                       (self.prepared_task.column.canonical_digest, self.binding.digest, self.work.request.request_digest)):
                raise AuthorityUnavailable('Numeric model Source exact acquisition original differs')
            self.acquisition=receipt;self.phase='progress_metadata';return False
        if self.phase=='progress_metadata':
            execution=self.activity['execution_id']
            prefix='d11-life-execution:'
            if not execution.startswith(prefix) or len(execution.removeprefix(prefix))!=48:
                raise AuthorityUnavailable('Numeric occurrence has no actual registered Life producer locator')
            self.progress_prepared_ref='d11-life-prepared:'+execution.removeprefix(prefix)
            value=self.metadata_v3('life','numeric_model_life_prepared',self.progress_prepared_ref,meter)
            if value is None:return False
            raw,task=value
            from ..runtime.d11_life_contract_v1 import D11LifeExecutionBindingV1,life_from_wire_v1
            b=life_from_wire_v1(raw['binding'],D11LifeExecutionBindingV1)
            if (b.namespace!=self.namespace or b.execution_id!=execution or b.prepared_original_ref!=self.progress_prepared_ref
                    or b.activity_id!=self.activity['activity_id'] or b.effect_id!=self.activity['effect_id']
                    or b.artifact_ref!=self.activity['artifact_ref'] or b.digest!=self.before['binding_digest']
                    or raw['prepare_operation_id']!=self.before['prepare_operation_id']
                    or task.column.canonical_digest!=self.before['prepared_digest']):
                raise AuthorityUnavailable('Numeric nested Life Source metadata differs from its actual signed Before/occurrence')
            self.progress_prepared_metadata=raw;self.progress_prepared_task=task
            self.life_bindings[b.execution_id]=b
            from .life_model_original_family_read_v3 import life_model_progress_source_group_v3
            progress_audiences,progress_purposes,progress=life_model_progress_source_group_v3(raw)
            if raw['plan']['input_source']['ref']not in progress:
                raise AuthorityUnavailable('Numeric actual signed Life progress roots omit the prepared input Source')
            progress_sources=set()
            for row in raw['read_rows']:
                key=AtomKey.from_token(row['ref'])
                if key.type_name=='memory.source':
                    if (key.token in progress_sources or key.token not in self.expectations
                            or row['revision']!=self.expectations[key.token]):
                        raise AuthorityUnavailable('Numeric signed Life progress Source lies outside unique original acquired closure or revision; HOLD')
                    progress_sources.add(key.token)
            self.source_groups={'numeric_model':(tuple(self.prepared_metadata['audience']),('consolidation',),self.roots),
                'life_progress':(progress_audiences,progress_purposes,progress)}
            grant=self.owner_entry.grant
            for audiences,purposes,roots in self.source_groups.values():
                if (not roots or not audiences or not set(audiences)<=set(grant['audiences']) or not set(purposes)<=set(grant['purposes'])
                        or len(roots)>256 or not set(roots)<=self.expectations.keys()
                        or any(NamespaceId.from_key(AtomKey.from_token(ref))!=self.namespace for ref in roots)):
                    raise AuthorityUnavailable('Numeric Source group is outside actual Owner permission or original metadata bounds')
            self.pending=[(group,ref)for group,(_,_,roots)in self.source_groups.items()for ref in roots]
            self.phase='rights';return False
        if self.phase == 'rights':
            if not self.work.namespace_reader.graph_eof: return False
            if not self.pending:
                self._finish_rights_v3(); self.complete = True; return True
            group,ref=self.pending.pop()
            if (group,ref)in self.group_qualified:return False
            from ..memory_types import source_key, access_key
            from ..domains.d06 import source_correction_head_key
            from ..domains.d07.qualified_attention_read import _qualify_source_rights_values_v3
            key = AtomKey.from_token(ref); witness = self.work.sources.get(ref)
            if (key != source_key(*self.namespace.as_tuple, key.owner.subject) or witness is None
                    or not witness.valid or ref not in self.expectations or witness.revision != self.expectations[ref]
                    or ref not in self.qualified and len(self.qualified) >= 256):
                raise AuthorityUnavailable('Numeric Source root/ancestor metadata differs from original versions')
            witness.require_current_v3(); access = self.metadata_atoms.get(access_key(*self.namespace.as_tuple, key.owner.subject))
            head = source_correction_head_key(self.namespace, key.owner.subject); saved = self.work.heads.get(head.token)
            correction = GraphAtom(head, 0 if saved is None else saved[0], {}, False if saved is None else bool(saved[1]))
            audiences,purposes,_=self.source_groups[group]
            for purpose in purposes:
                for audience in audiences:
                    record = _qualify_source_rights_values_v3(self.namespace, ref, witness, access, correction,
                        audience=audience, purpose=purpose, metadata_only=True)
                    if record is None: raise AuthorityUnavailable('Numeric Source/ancestor ACL/purpose/audience/correction denied')
            self.qualified[ref] = (witness, record)
            self.group_qualified[group,ref]=(witness,record)
            for atom in (access, correction): self.versions[atom.key] = GraphVersion(atom.key, atom.revision)
            self.versions[key] = GraphVersion(key, witness.revision)
            parents=tuple(source_key(*self.namespace.as_tuple,parent).token for parent in record.parent_source_ids)
            if any(parent not in self.expectations for parent in parents):
                raise AuthorityUnavailable('Numeric Source ancestor lies outside original acquired closure; HOLD')
            self.pending.extend((group,parent)for parent in parents)
            return False
        raise AuthorityUnavailable('unregistered Numeric Authority Source phase')

    def _finish_rights_v3(self):
        from ..memory_types import source_key
        active,done=set(),set()
        def visit(group,ref):
            key=(group,ref)
            if key in active:raise AuthorityUnavailable('Numeric Source ancestry contains a cycle')
            if key in done:return
            active.add(key)
            for parent in self.group_qualified[key][1].parent_source_ids:visit(group,source_key(*self.namespace.as_tuple,parent).token)
            active.remove(key);done.add(key)
        for group,(_,_,roots)in self.source_groups.items():
            for ref in roots:visit(group,ref)
        self.graph_versions={(row['ref'],row['revision'])for row in (*self.prepared_metadata['read_rows'],
            *self.provenance['current_reads'],*self.provenance['historical_reads'])}
        self.graph_versions.update((row['ref'],row['revision'])for member in self.before['members']for row in (member['checkpoint'],member['state']))
        self.graph_versions.update((row['ref'],row['revision'])for row in self.before['context_rows'])
        self.graph_versions.update((version.key.token,version.revision)for version in self.versions.values())
        self.graph_tokens={ref for ref,_ in self.graph_versions}
        self.original_operations={self.ids['prepare'],self.ids['acquire'],self.request.causal_operation_id,self.before['root_operation_id'],self.provenance['producing_operation_id'],self.context_metadata['operation_id']}
        self.original_keys={(kind,ref)for mode,profile,ref in self.selectors if mode=='life'
            for kind in ({'before':'d04_before_v1','context':'numeric_context_v1','prepared':'numeric_prepared_v1',
                'binding':'numeric_binding_v1','request':'numeric_request_v1','acquire_commit':'numeric_acquire_commit_v1','numeric_model_life_prepared':'prepared'}[profile],)}
        self.execution_ids={self.activity['execution_id']};self.job_ids={self.work.request.job_id}
        self.quote_versions={(self.prepared_metadata['quote_id'],1)}
        self.parent_budget_refs={self.work.request.budget_lease_id}
        bridge=_RESULT_BRIDGES.get(self.work)
        if bridge is not None:
            request=bridge['request']
            self.original_keys.update((('numeric_call_v1',self.work.request.job_id),('numeric_read_attempt_v1',request.read_attempt_id)))
            from ..runtime.model_cost_settlement import original_model_cost_operation_id_v1
            cost_operation=original_model_cost_operation_id_v1(self.namespace,self.work.request.call_id)
            self.original_operations.add(cost_operation)
            from ..runtime.d11_types import runtime_cost_settlement_key
            cost_ref=runtime_cost_settlement_key(*self.namespace.as_tuple,self.prepared_metadata['activity_id'],cost_operation).token
            self.graph_tokens.add(cost_ref);self.graph_versions.add((cost_ref,1))
        self.family_initialized=True

    def require_body_v3(self, work):
        self.require_registered_v3()
        if work is not self.work or not self.complete or self.phase != 'rights':
            raise AuthorityUnavailable('Numeric protected body requires its own complete ALL Source qualification')
        return self

    def release_v3(self):
        self.operation.unregister_retained_state_v3(self)
        from ..runtime.current_life_numeric_metadata_v1 import _COLUMNS
        from ..runtime.current_method_learning_read_v3 import _JSON_COLUMNS
        for task in self.tasks:
            if task.column is not None: _COLUMNS.pop(task.column, None); _JSON_COLUMNS.pop(task.column, None)
        _READERS.pop(self, None); _WORK_READERS.pop(self.work, None)
        self.attachments.clear(); self.metadata_atoms.clear(); self.metadata_columns.clear()
        self.tasks.clear(); self.selectors.clear(); self.qualified.clear(); self.versions.clear()
        self.family_edges.clear();self.family_plans.clear();self.graph_versions.clear();self.graph_tokens.clear()
        self.original_operations.clear();self.original_keys.clear();self.execution_ids.clear();self.job_ids.clear()
        self.quote_versions.clear();self.body_quote_versions.clear();self.action_refs.clear();self.parent_budget_refs.clear()
        self.artifact_descriptors.clear();self.life_bindings.clear();self.history_event_pairs.clear()
        self.source_groups.clear();self.group_qualified.clear();self.progress_prepared_metadata=None


def prepare_authority_numeric_source_read_v3(work, *, installed_reader, owner_entry):
    return AuthorityNumericSourceReadV3(_ISSUER, work, installed_reader, owner_entry)


def require_authority_numeric_metadata_selector_v3(reader, identity):
    require_authority_numeric_metadata_work_v3(reader)
    if identity not in reader.selectors:
        raise AuthorityUnavailable('Numeric metadata escaped its actual registered model recipe')
    return reader


def prepare_authority_numeric_model_work_v3(model_service, *, installed_reader, credential, subject, intent, permit, now_utc):
    from dataclasses import asdict
    from .current_authority_graph_read_v3 import begin_authority_model_graph_read_work_v3, require_authority_graph_read_controller_v3
    from .current_life_numeric_v1 import InstalledLifeNumericModelGraphReaderV1
    from .v2_model_egress_service import AuthorityV2ModelEgressService
    from .v2_model_egress_contract import ModelEgressIntentV1
    from .v2_contract import FencePermitV2
    if (type(model_service) is not AuthorityV2ModelEgressService
            or type(installed_reader) is not InstalledLifeNumericModelGraphReaderV1
            or type(intent) is not ModelEgressIntentV1 or type(permit) is not FencePermitV2
            or permit.operation != 'model_egress' or permit.operation_id != intent.operation_id
            or permit.subject != subject or intent.subject != subject):
        raise AuthorityUnavailable('Numeric seal requires its actual original MODEL permission')
    controller = require_authority_graph_read_controller_v3(model_service._graph_verifier)
    owner = installed_reader.owner_storage
    if (controller.service is not model_service or controller.verifier._life_numeric_reader_v1 is not installed_reader
            or controller.fences is not owner.fences or controller.control is not owner.control
            or controller.location._graph_db_path != owner.graph_path
            or installed_reader.bundle is not controller.verifier._artifact_draft_bundle):
        raise AuthorityUnavailable('Numeric seal crossed its actual installed Graph/Owner/model reader')
    fences = owner.fences
    fences.core._require(credential, 'owner_guard_read', owner.namespace, owner.holder)
    fences.validate_fence(credential=credential, subject=subject, permit=permit)
    with fences._frozen() as (db, deletion, execution, _):
        anchor = fences._current_locked(db, deletion, execution, holder=permit.holder, generation=permit.generation)
        fences.fences.validate_fence_locked(db, permit, subject=subject, current_anchor=anchor)
        record = model_service._store.read_locked(db, intent)
        if (record.intent != intent or record.state != 'prepared' or anchor != permit.pinned_anchor
                or canonical_digest(asdict(anchor)) != intent.anchor_digest
                or (permit.token, permit.fence_epoch, permit.revision) != (intent.fence_token, intent.fence_epoch, intent.fence_revision)):
            raise AuthorityUnavailable('Numeric seal lost its real original prepared model/active fence')
    work = begin_authority_model_graph_read_work_v3(controller.verifier, model_service=model_service,
        credential=credential, subject=subject, permit=permit, intent=intent, now_utc=now_utc)
    _MODEL_PHASES[work] = (model_service, installed_reader, record, permit, work.operation, work.scope, 'numeric_model_seal_observer')
    return work


def require_authority_numeric_model_phase_v3(work, installed_reader):
    saved = _MODEL_PHASES.get(work)
    if (saved is None or saved[0] is not work.service or saved[1] is not installed_reader
            or saved[2].intent != work.request or saved[2].state != 'prepared'
            or saved[3] is not work.permit or saved[4] is not work.operation or saved[5] is not work.scope):
        raise AuthorityUnavailable('Numeric Owner header has no private actual model seal phase')
    work._actual()
    return saved[6]


def release_authority_numeric_model_work_v3(work):
    reader = _WORK_READERS.get(work)
    if reader is not None: reader.release_v3()
    _MODEL_PHASES.pop(work, None)
    _RESULT_BRIDGES.pop(work,None)


def register_authority_numeric_model_policy_v3(work):
    if work.owner_model_work_kind != 'd06.encode_internal_life_numeric': return
    reader = work.controller.verifier._life_numeric_reader_v1
    owner = reader.owner_storage
    if work.service._fences is not owner.fences:
        raise AuthorityUnavailable('Numeric model policy crossed its actual installed fence service')
    with owner.fences._frozen() as (db, deletion, execution, _):
        anchor = owner.fences._current_locked(db, deletion, execution,
            holder=work.permit.holder, generation=work.permit.generation)
        owner.fences.fences.validate_fence_locked(db, work.permit, subject=work.subject, current_anchor=anchor)
        record = work.service._store.read_locked(db, work.request)
        if record.intent != work.request or record.state != 'prepared':
            raise AuthorityUnavailable('Numeric model policy requires its original prepared live model')
    _MODEL_PHASES[work] = (work.service, reader, record, work.permit, work.operation, work.scope, 'numeric_model_policy')


def numeric_authority_namespace_retains_type_v3(reader, key):
    from ..graph_types import owner_grant_key
    from ..memory_types import access_key
    from ..domains.d03.self_perspective import self_mapping_key
    require_authority_numeric_metadata_work_v3(reader)
    return (key == owner_grant_key(*reader.namespace.as_tuple) or key == self_mapping_key(reader.namespace)
        or key.type_name == access_key(*reader.namespace.as_tuple, 'source-metadata-type').type_name)


def prepare_numeric_authority_namespace_metadata_column_v3(reader, key, revision, valid, cell_id):
    from .d07_authority_model_source_read_v3 import _D07AuthorityGraphMetadataColumnV3
    if not numeric_authority_namespace_retains_type_v3(reader, key):
        raise AuthorityUnavailable('Numeric census selected an undeclared metadata schema')
    return _D07AuthorityGraphMetadataColumnV3(reader, key, revision, valid, cell_id)


def advance_authority_numeric_graph_materials_v3(work, meter):
    from .current_authority_graph_read_v3 import _AuthorityNamespaceReadV3, AuthorityGraphProjectionV3, _ISSUER as graph_issuer
    reader = numeric_authority_source_reader_v3(work)
    if reader is None: raise AuthorityUnavailable('Numeric model has no exact registered Source recipe')
    if reader.phase != 'rights':
        reader.advance_v3(meter); return
    if work.namespace_reader is None:
        work.catalogue_reader.advance_v3(meter)
        if work.catalogue_reader.complete:
            work.namespace_reader = _AuthorityNamespaceReadV3(work, catalogue=work.catalogue_reader.rows,
                catalogue_hash=work.catalogue_reader.catalogue_hash)
        return
    if not work.namespace_reader.graph_eof:
        work.namespace_reader.advance_v3(meter); return
    if work.projection is None: work.projection = AuthorityGraphProjectionV3(graph_issuer, work)
    reader.advance_v3(meter)
    if reader.complete: work.phase = 'numeric_result_validate' if work in _RESULT_BRIDGES else 'numeric_model_validate'


def require_numeric_authority_body_request_v3(work,request):
    reader=numeric_authority_source_reader_v3(work)
    if reader is None:return None
    reader.require_body_v3(work)
    if not reader.family_initialized:raise AuthorityUnavailable('Numeric model body family has not completed its actual Source roots')
    table=request[0]
    if len(request)==2:
        allowed=(table=='life_model.artifact_body.v3' and request[1]in reader.execution_ids
            or table=='life_model.source_note_action_locator.v3' and request[1]in reader.action_refs)
    elif len(request)==4:
        columns,keys,key=tuple(request[1]),tuple(request[2]),tuple(request[3])
        selected=dict(zip(keys,key))
        if len(selected)!=len(key):raise AuthorityUnavailable('Numeric body point lost its complete primary key')
        if any(selected[name]!=value for name,value in (('bot',work.namespace.bot_id),('persona',work.namespace.persona_id),
                ('bot_id',work.namespace.bot_id),('persona_id',work.namespace.persona_id))if name in selected):
            raise AuthorityUnavailable('Numeric protected body crossed actual namespace')
        if table in {'graph_atoms','graph_history'}:
            token=selected['token'];key=AtomKey.from_token(token)
            allowed=token in reader.graph_tokens and NamespaceId.from_key(key)==work.namespace
            if key.type_name=='memory.source':allowed=allowed and token in reader.qualified
            if table=='graph_history':allowed=allowed and (token,selected['revision'])in reader.graph_versions
        elif table=='runtime_jobs':allowed=selected.get('job_id')in reader.job_ids
        elif table=='graph_d11_life_originals_v1':allowed=(selected.get('kind'),selected.get('original_ref'))in reader.original_keys
        elif table in {'graph_domain_production_originals_v1','graph_bundle_operations','graph_bundle_fences_v2'}:
            allowed=selected.get('operation_id')in reader.original_operations
        elif table=='graph_events':allowed=selected.get('event_id')in reader.original_operations
        elif table=='graph_d11_life_adoption_originals_v1':allowed=selected.get('execution_id')in reader.execution_ids
        elif table=='graph_original_model_cost_attempts_v1':
            allowed=work in _RESULT_BRIDGES and selected.get('call_id')==work.request.call_id
        elif table=='runtime_resource_quotes':allowed=(selected.get('quote_id'),selected.get('version'))in reader.quote_versions
        elif table=='d02_body_quotes_v1':allowed=any(ref==selected.get('quote_id')for ref,_ in reader.body_quote_versions)
        elif table in {'runtime_budget_leases','runtime_budget_grants'}:allowed=selected.get('lease_id')in reader.parent_budget_refs
        elif table=='runtime_budget_reservations':allowed=selected.get('lease_id')in reader.parent_budget_refs and selected.get('operation_id')in reader.original_operations
        elif table=='runtime_budget_operations':allowed=selected.get('operation_id')in reader.original_operations
        elif table=='graph_recovery_metadata_v2':allowed=key==work.namespace.as_tuple
        else:allowed=False
    elif len(request)==5 and table=='graph_dependencies':
        allowed=request[3][0]in reader.graph_tokens
    else:allowed=False
    if not allowed:raise AuthorityUnavailable('Numeric protected body escaped its own signed parent family')
    return reader


def numeric_authority_graph_atom_v3(db, key):
    from .current_authority_graph_read_v3 import _authority_attachment_owner_v3, AuthorityGraphAttachmentRequiredV3
    work = _authority_attachment_owner_v3(db)
    reader = None if work is None else numeric_authority_source_reader_v3(work)
    if reader is None: return None
    reader.require_body_v3(work)
    if key in work.members: return work.members[key]
    if key.token not in work.heads: return GraphAtom(key, 0, {}, False)
    request = ('graph_atoms', ('revision', 'value', 'valid'), ('token', 'bot', 'persona'),
        (key.token, *work.namespace.as_tuple))
    require_numeric_authority_body_request_v3(work, request)
    raise AuthorityGraphAttachmentRequiredV3(request)


def require_numeric_authority_reader_body_v3(db, installed_reader, intent):
    from .current_authority_graph_read_v3 import _authority_attachment_owner_v3
    work = _authority_attachment_owner_v3(db)
    if work is None: return None
    reader = numeric_authority_source_reader_v3(work)
    if reader is None or reader.installed_reader is not installed_reader or work.request is not intent:
        raise AuthorityUnavailable('Numeric model body has no actual independent Authority Source Work')
    return reader.require_body_v3(work)


NUMERIC_MODEL_SEAL_OBSERVER_METHOD_V3 = 'numeric_current_model_seal_observe_v3'
NUMERIC_MODEL_SEAL_OBSERVER_SIGN_V3 = 'd11.numeric-current-model-seal-observation.v3'
NUMERIC_MODEL_SEAL_OBSERVER_SCHEMA_V3 = 'numeric.actual-model-seal-observation.v3'


def dispatch_current_numeric_model_seal_observe_v3(server, method, command, *, credential, profile_id, manifest_digest):
    if method != NUMERIC_MODEL_SEAL_OBSERVER_METHOD_V3: return None
    from dataclasses import asdict
    from .v2_model_egress_contract import ModelEgressIntentV1
    from .v2_model_egress_wire import from_wire as model_from_wire, to_wire as model_to_wire
    from .v2_contract import from_wire as fence_from_wire, to_wire as fence_to_wire
    from .d12_target_owner_admission_v1 import D12CurrentOwnerAuthorityV1, current_owner_authority_to_wire_v1
    from .current_authority_graph_read_v3 import read_authority_graph_current_v3, finish_authority_graph_read_work_v3
    from .owner_location_read_v3 import _OWNER_MODEL_LOCATION_ENTRIES_V3
    from ..runtime_contracts import canonical_serialize
    expected = {'namespace','installation_id','intent','permit','graph_stamp_digest','clock_policy_digest','host_selection_digest'}
    if type(command) is not dict or set(command) != expected:
        raise AuthorityUnavailable('Numeric model seal observer exact command differs')
    namespace = command['namespace']
    fences = server._bound_v2_service(credential, profile_id, manifest_digest, namespace)
    installed = server._installations_v2[(credential.certificate_sha256, profile_id)]
    subject = 'mtls:sha256:' + credential.certificate_sha256
    model = server._v2_model_egress.get(namespace)
    result_service = server._life_numeric_model_reads_v1.get(namespace)
    if model is None or result_service is None:
        raise AuthorityUnavailable('Numeric model seal observer actual installation unavailable; HOLD')
    reader = result_service._graph_reader; owner = reader.owner_storage
    intent = model_from_wire(command['intent'], ModelEgressIntentV1); permit = fence_from_wire(command['permit'])
    if (reader is not model._graph_verifier._life_numeric_reader_v1 or result_service._store is not model._store
            or result_service._fences is not fences or model._fences is not fences or owner.fences is not fences
            or owner.core is not fences.core or owner.control is not fences.core._c09_storage_reader_v1
            or result_service._path != owner.graph_path or model._graph_verifier._path != owner.graph_path
            or result_service._installation_id != installed.installation_id
            or reader.bundle.installation_policy.installation_id != installed.installation_id
            or reader.read_subject != subject or owner.holder != installed.administrator_holder
            or command['installation_id'] != installed.installation_id
            or server._model_observers_v2.get(namespace) != (credential.certificate_sha256, profile_id)):
        raise AuthorityUnavailable('Numeric model seal observer crossed its actual installed reader/Core/Owner/Graph')
    fences.core._require(credential, 'model_egress', namespace, installed.administrator_holder)
    work = prepare_authority_numeric_model_work_v3(model, installed_reader=reader, credential=credential,
        subject=subject, intent=intent, permit=permit, now_utc=model._graph_verifier._clock())
    try:
        current = read_authority_graph_current_v3(work, lambda db: reader.read(db, intent, work.now_utc))
        source = numeric_authority_source_reader_v3(work).require_body_v3(work)
        state = _OWNER_MODEL_LOCATION_ENTRIES_V3[work]; proof, facts = state[1:3]
        facts.require_for_v3(proof); stamp = (facts.metadata, facts.graph_epoch)
        if (canonical_digest(stamp) != command['graph_stamp_digest']
                or proof.clock_policy_digest != command['clock_policy_digest']
                or fences.validate_fence(credential=credential, subject=subject, permit=permit) != permit):
            raise AuthorityUnavailable('Numeric model seal current stamp/clock/original permit changed')
        work._check_permission_v3()
        with fences._frozen() as (db, deletion, execution, _):
            record = model._store.read_locked(db, intent)
            if record.intent != intent or record.state != 'prepared':
                raise AuthorityUnavailable('Numeric model seal original prepared state changed')
        from ..domains.d01.production_operations_v1 import plain_v1
        wire = {'schema':NUMERIC_MODEL_SEAL_OBSERVER_SCHEMA_V3, 'namespace':list(work.namespace.as_tuple),
            'authority_namespace':namespace, 'authority_id':intent.authority_id, 'installation_id':installed.installation_id,
            'subject':subject, 'holder':installed.administrator_holder, 'intent_digest':canonical_digest(model_to_wire(intent)),
            'permit':fence_to_wire(permit), 'graph_stamp_digest':canonical_digest(stamp),
            'clock_policy_digest':proof.clock_policy_digest,
            'current_owner_authority':current_owner_authority_to_wire_v1(D12CurrentOwnerAuthorityV1(
                current.owner_guard, None, current.storage_admission)), 'principal':plain_v1(proof.principal),
            'prepared_digest':current.prepared.digest, 'binding_digest':current.binding.digest,
            'request_digest':current.request.digest, 'episode_ref':current.prepared.episode_ref,
            'causal_operation_id':current.prepared.causal_operation_id, 'core_selection_digest':work.selection_digest,
            'host_selection_digest':command['host_selection_digest'], 'job_digest':canonical_digest(plain_v1(current.job)),
            'source_versions':plain_v1(tuple(source.versions.values())),
            'owner_grant_digest':canonical_digest(source.owner_entry.grant),
            'owner_permissions':{name:source.owner_entry.grant[name] for name in ('scope','issuer_ref','capabilities','purposes','audiences','grant_id','grant_revision')},
            'current_scope_digest':current.current_scope_digest,
            'original_deadline_utc':min(work.deadline_utc,current.valid_until_utc)}
        encoded = canonical_serialize(wire)
        if len(encoded.encode('utf8')) > 60000:
            raise AuthorityUnavailable('Numeric model seal signed metadata exceeds the installed frame bound')
        return {'observation':wire,'signature':reader.readers.issuer._signer.sign(NUMERIC_MODEL_SEAL_OBSERVER_SIGN_V3,encoded)}
    finally:
        finish_authority_graph_read_work_v3(work)


def _numeric_life_model_body_reader_v3(db):
    from .current_authority_graph_read_v3 import _authority_attachment_owner_v3
    work=_authority_attachment_owner_v3(db)
    reader=None if work is None else numeric_authority_source_reader_v3(work)
    return None if reader is None else reader.require_body_v3(work)


def register_numeric_life_model_source_body_v3(work,attachment,key,value):
    reader=numeric_authority_source_reader_v3(work)
    if reader is None or key.type_name!='memory.source':return
    reader.require_body_v3(work)
    witness=reader.qualified[key.token][0];column=attachment.json_columns['value']
    data=dict(zip(attachment.columns,attachment.row))
    if (not attachment.complete or column.owner is not work or not column.complete
            or column.sha256!=witness.payload_sha256 or data['revision']!=witness.revision):
        raise AuthorityUnavailable('Numeric Source body lost its independently qualified full EOF origin')
    if key.token!=reader.activity['source_ref']:return
    import json
    from ..memory_types import SourceRecord
    record=SourceRecord.from_dict(value);payload=json.loads(record.text)
    if (payload['schema']!='d10.actual-life-activity-experience.v1'
            or payload['activity_id']!=reader.activity['activity_id'] or payload['effect_id']!=reader.activity['effect_id']
            or payload['artifact_ref']!=reader.activity['artifact_ref'] or payload['terminal_original_ref']!=reader.activity['terminal_original_ref']):
        raise AuthorityUnavailable('Numeric actual experience Source differs from its signed occurrence metadata')
    from ..runtime_storage_v3 import runtime_storage_quantum_v3
    with runtime_storage_quantum_v3(work.db)as meter:
        origin=meter.read_fixed_row(work.db,'graph_history',('event_id','event_bot','event_persona'),
            'token=? AND revision=?',(key.token,witness.revision))
    if origin is None or origin[1:]!=work.namespace.as_tuple:
        raise AuthorityUnavailable('Numeric Source root lacks its exact current Graph origin')
    ref=payload['actual_provenance_ref'];reader.original_keys.add(('experience',ref))
    reader.family_edges[('experience',ref)]=('memory.source',key.token,canonical_digest(value),origin[0],('text','actual_provenance_ref'))


def _numeric_life_model_signed_column_v3(reader,kind,ref,raw,producer):
    from ..runtime_contracts import canonical_serialize
    from ..runtime.d11_life_preparation_v1 import SIGN_KIND
    work=reader.work;reader.require_body_v3(work)
    if (kind,ref)not in reader.original_keys:
        raise AuthorityUnavailable('Numeric signed original escaped its actual qualified parent family')
    request=('graph_d11_life_originals_v1',('producing_operation_id','payload_json','payload_digest','signature'),
        ('bot','persona','kind','original_ref'),(*work.namespace.as_tuple,kind,ref))
    column=work.attachments.get(request)
    if column is None or not column.complete:
        raise AuthorityUnavailable('Numeric signed child has no actual retained complete column')
    row=dict(zip(column.columns,column.row))
    if (row['producing_operation_id']!=producer or column.encoded['payload_json']!=canonical_serialize(raw)
            or canonical_digest(raw)!=row['payload_digest']):
        raise AuthorityUnavailable('Numeric signed child changed its complete body or original producer')
    reader.installed_reader.readers.issuer._signer.verify(SIGN_KIND,
        canonical_serialize((work.namespace,kind,ref,row['payload_digest'])),row['signature'])
    return row


def register_numeric_life_model_signed_body_v3(db,kind,ref,raw,producer):
    reader=_numeric_life_model_body_reader_v3(db)
    if reader is None:return False
    row=_numeric_life_model_signed_column_v3(reader,kind,ref,raw,producer)
    work=reader.work;reader.original_operations.add(producer)
    if kind=='experience':
        from ..runtime.d11_life_contract_v1 import D11LifeTerminalV1,life_from_wire_v1,life_to_wire_v1
        from ..runtime.d10_life_outcome_v2 import life_experience_provenance_ref_v1,life_experience_source_id_v1
        terminal=life_from_wire_v1(raw['terminal'],D11LifeTerminalV1);b=terminal.binding
        if (set(raw)!={'schema','source_ref','source_digest','binding','terminal','adopted_operation_id','experience'}
                or raw['schema']!='d11.actual-life-experience-provenance.v1' or b.namespace!=work.namespace
                or b.execution_id!=reader.activity['execution_id'] or b.activity_id!=reader.activity['activity_id']
                or b.effect_id!=reader.activity['effect_id'] or b.artifact_ref!=reader.activity['artifact_ref']
                or terminal.original_ref!=reader.activity['terminal_original_ref'] or terminal.status!='completed'
                or raw['binding']!=life_to_wire_v1(b) or ref!=life_experience_provenance_ref_v1(b)
                or raw['source_ref']!=reader.activity['source_ref']
                or AtomKey.from_token(raw['source_ref']).owner.subject!=life_experience_source_id_v1(b)):
            raise AuthorityUnavailable('Numeric signed experience differs from its actual occurrence and Source parent')
        source=work.members[AtomKey.from_token(raw['source_ref'])]
        from ..memory_types import SourceRecord
        import json
        payload=json.loads(SourceRecord.from_dict(source.value).text)
        if (raw['source_digest']!=canonical_digest(source.value) or raw['experience']!=payload
                or terminal.payload.artifact_digest!=payload['artifact_digest'] or terminal.payload.artifact_length!=payload['artifact_length']):
            raise AuthorityUnavailable('Numeric signed experience lost its exact Source body/Artifact descriptor')
        reader.life_bindings[b.execution_id]=b
        reader.artifact_descriptors[b.execution_id]=(b.digest,b.artifact_ref,terminal.payload.artifact_digest,terminal.payload.artifact_length)
        reader.original_keys.add(('prepared',b.prepared_original_ref))
        reader.family_edges[('prepared',b.prepared_original_ref)]=('experience',ref,row['payload_digest'],producer,('terminal','binding','prepared_original_ref'))
    elif kind=='source_note_action':
        from ..runtime.d08_source_note_action_v1 import source_note_action_original_from_wire_v1
        value=source_note_action_original_from_wire_v1(raw)
        if value.action_intent_ref not in reader.action_refs or NamespaceId.from_key(AtomKey.from_token(value.action_intent_ref))!=work.namespace or value.input_source_ref not in reader.qualified or value.action_operation_id!=producer:
            raise AuthorityUnavailable('Numeric signed Action lost its qualified actual prepared parent')
        histories=tuple((ref,revision)for ref,revision,_ in value.write_commitments)+tuple((ref,revision)for ref,revision,_,_,_ in value.context_commitments)
        if any(NamespaceId.from_key(AtomKey.from_token(ref))!=work.namespace or AtomKey.from_token(ref).type_name=='memory.source' and ref not in reader.qualified for ref,_ in histories):
            raise AuthorityUnavailable('Numeric Action introduces a Source outside its own ALL closure')
        parent_ref=ref
        for child_ref,revision in histories:
            reader.graph_versions.add((child_ref,revision));reader.graph_tokens.add(child_ref)
            reader.family_edges[('graph_history',child_ref,revision)]=(kind,parent_ref,row['payload_digest'],producer,('context_commitments','write_commitments'))
        reader.original_operations.update(operation for _,_,_,operation,_ in value.context_commitments)
    return True


def register_numeric_life_model_prepared_body_v3(db,prepared):
    reader=_numeric_life_model_body_reader_v3(db)
    if reader is None:return False
    from ..runtime.d11_life_preparation_v1 import D11LifePreparedV1
    from ..domains.d01.production_operations_v1 import plain_v1
    if type(prepared)is not D11LifePreparedV1:raise AuthorityUnavailable('Numeric Body extension requires its actual signed Life preparation')
    b=prepared.binding;request=('graph_d11_life_originals_v1',('producing_operation_id','payload_json','payload_digest','signature'),
        ('bot','persona','kind','original_ref'),(*reader.namespace.as_tuple,'prepared',b.prepared_original_ref))
    original=reader.work.attachments.get(request)
    if original is None or not original.complete:raise AuthorityUnavailable('Numeric Body prepared parent has not reached whole EOF')
    row=dict(zip(original.columns,original.row))
    _numeric_life_model_signed_column_v3(reader,'prepared',b.prepared_original_ref,plain_v1(prepared),row['producing_operation_id'])
    if (reader.life_bindings.get(b.execution_id)!=b or b.namespace!=reader.namespace
            or prepared.plan.input_source.ref not in reader.qualified):
        raise AuthorityUnavailable('Numeric Body prepared parent crossed its signed occurrence or ALL Source family')
    from .life_model_original_family_read_v3 import life_model_family_plan_from_prepared_v3
    plan=life_model_family_plan_from_prepared_v3(prepared,'prepared',b.prepared_original_ref,row['payload_digest'],row['producing_operation_id'])
    reader.family_plans[b.execution_id]=plan
    from ..runtime.d11_life_contract_v1 import LifeBodyComponentContractV1
    import json
    contract=LifeBodyComponentContractV1(**json.loads(prepared.plan.body_effect_request_json))
    for token in (contract.reservation_ref,contract.settlement_ref):
        if NamespaceId.from_key(AtomKey.from_token(token))!=reader.namespace:
            raise AuthorityUnavailable('Numeric signed Body contract crossed actual namespace')
        reader.graph_tokens.add(token)
    reader.history_event_pairs[(contract.reservation_ref,contract.body_prepare_operation_id)]=(
        'prepared',b.prepared_original_ref,row['payload_digest'],row['producing_operation_id'],('plan','body_effect_request_json','reservation_ref','body_prepare_operation_id'))
    for locator in plan.locators:
        reader.family_edges[locator.recipe]=(locator.parent_kind,locator.parent_ref,locator.parent_digest,locator.parent_producer,locator.field_path)
        if locator.recipe[1]=='graph_d11_life_originals_v1' and locator.recipe[3]==('bot','persona','kind','original_ref'):
            reader.original_keys.add((locator.recipe[4][2],locator.recipe[4][3]))
    reader.original_keys.add(('adoption_receipt',b.execution_id))
    reader.original_operations.update(plan.operations);reader.job_ids.update(plan.job_ids);reader.execution_ids.update(plan.execution_ids)
    reader.quote_versions.update(plan.quote_versions);reader.body_quote_versions.update(plan.body_quote_versions);reader.action_refs.update(plan.action_refs)
    reader.parent_budget_refs.add(b.parent_budget_lease_ref)
    return True


def read_bound_numeric_life_model_body_point_v3(db,*,table,columns,key_columns,key):
    reader=_numeric_life_model_body_reader_v3(db)
    if reader is None:return False,None
    request=(table,tuple(columns),tuple(key_columns),tuple(key))
    require_numeric_authority_body_request_v3(reader.work,request)
    from .current_authority_graph_read_v3 import read_bound_authority_graph_attachment_v3
    return read_bound_authority_graph_attachment_v3(db,table=table,columns=columns,key_columns=key_columns,key=key)


def read_bound_numeric_life_model_history_v3(db,token,revision,columns):
    return read_bound_numeric_life_model_body_point_v3(db,table='graph_history',columns=tuple(columns),key_columns=('token','revision'),key=(token,revision))


def read_bound_numeric_life_model_history_by_event_v3(db,token,event_id):
    reader=_numeric_life_model_body_reader_v3(db)
    if reader is None:return False,None
    parent=reader.history_event_pairs.get((token,event_id))
    if parent is None:raise AuthorityUnavailable('Numeric Body event history escaped its exact signed prepared pair')
    from ..runtime_storage_v3 import runtime_storage_quantum_v3
    with runtime_storage_quantum_v3(db)as meter:
        item=meter.read_fixed_row(db,'graph_history',('revision','event_bot','event_persona','event_id'),
            'token=? AND event_id=? ORDER BY revision',(token,event_id))
        if item is None:return True,()
        more=meter.read_fixed_row(db,'graph_history',('revision',),'token=? AND event_id=? AND revision>? ORDER BY revision',(token,event_id,item[0]))
        if more is not None or item[1:]!=(*reader.namespace.as_tuple,event_id):
            raise AuthorityUnavailable('Numeric Body event history lacks its exact namespace/origin zero/one EOF')
        reader.graph_versions.add((token,item[0]));reader.family_edges[('graph_history',token,item[0])]=parent
        _,row=read_bound_numeric_life_model_history_v3(db,token,item[0],('event_id','value','valid'))
        return True,(row,)


def read_bound_numeric_life_model_artifact_v3(db,prepared):
    reader=_numeric_life_model_body_reader_v3(db)
    if reader is None:return False,None
    register_numeric_life_model_prepared_body_v3(db,prepared)
    request=('life_model.artifact_body.v3',prepared.binding.execution_id)
    return True,_numeric_life_model_special_body_v3(reader,request)


def _numeric_life_model_special_body_v3(reader,request):
    require_numeric_authority_body_request_v3(reader.work,request)
    from .current_authority_graph_read_v3 import AuthorityGraphAttachmentRequiredV3
    task=reader.work.attachments.get(request)
    if task is None:
        if reader.work.complete:raise AuthorityUnavailable('Numeric final requested an unprepared actual Body family')
        raise AuthorityGraphAttachmentRequiredV3(request)
    from ..runtime_storage_v3 import runtime_storage_quantum_v3
    with runtime_storage_quantum_v3(reader.db)as meter:return task.require_row_v3(reader.work,meter)


def read_bound_numeric_life_model_action_refs_v3(db,namespace,action_ref):
    reader=_numeric_life_model_body_reader_v3(db)
    if reader is None:return False,None
    if namespace!=reader.namespace:raise AuthorityUnavailable('Numeric Action locator crossed its actual namespace')
    return True,_numeric_life_model_special_body_v3(reader,('life_model.source_note_action_locator.v3',action_ref))


def require_numeric_life_model_body_request_v3(work,request):
    reader=numeric_authority_source_reader_v3(work)
    if reader is None:return False
    if len(request)!=5:raise AuthorityUnavailable('Numeric shared Body IO requires its closed fixed recipe')
    recipe,table,columns,keys,key=request
    if recipe=='life_model.graph_body.v3' and table in {'graph_atoms','graph_history'}:
        require_numeric_authority_body_request_v3(work,(table,columns,keys,key));return True
    if (recipe=='life_model.artifact_body.v3' and table=='graph_d11_life_artifact_stage_v1'
            and columns==('binding_digest','artifact_ref','artifact_digest','artifact_length') and keys==('bot','persona','execution_id')
            and tuple(key[:2])==work.namespace.as_tuple):
        require_numeric_authority_body_request_v3(work,(recipe,key[2]));return True
    if (recipe=='life_model.source_note_action_locator.v3' and table=='graph_d11_life_originals_v1'
            and columns==('original_ref','payload_digest','signature') and keys==('bot','persona','kind','action_intent_ref')
            and tuple(key[:3])==(*work.namespace.as_tuple,'source_note_action')):
        require_numeric_authority_body_request_v3(work,(recipe,key[3]));return True
    raise AuthorityUnavailable('Numeric shared Body IO escaped its independent fixed recipe')


def numeric_life_model_artifact_descriptor_v3(work,execution_id):
    reader=numeric_authority_source_reader_v3(work)
    if reader is None:return False,None
    require_numeric_authority_body_request_v3(work,('life_model.artifact_body.v3',execution_id))
    if execution_id not in reader.family_plans or execution_id not in reader.artifact_descriptors:
        raise AuthorityUnavailable('Numeric Artifact lacks both actual signed terminal and prepared parent EOF')
    return True,reader.artifact_descriptors[execution_id]


def numeric_life_model_action_locator_eof_v3(work,action_ref,original_ref,column,metadata):
    reader=numeric_authority_source_reader_v3(work)
    if reader is None:return False
    require_numeric_authority_body_request_v3(work,('life_model.source_note_action_locator.v3',action_ref))
    from .life_model_original_family_read_v3 import _LifeModelActionLocatorColumnV3
    if (type(column)is not _LifeModelActionLocatorColumnV3 or column.owner is not work or not column.complete
            or column.table!='graph_d11_life_originals_v1' or column.column!='payload_json'
            or column.key!=(*work.namespace.as_tuple,'source_note_action',original_ref)
            or metadata[0]!=original_ref or column.sha256!=metadata[1]):
        raise AuthorityUnavailable('Numeric Action locator lost its same-Work whole metadata EOF')
    value=column.require_v3(work)
    if value['action_intent_ref']!=action_ref:raise AuthorityUnavailable('Numeric Action locator differs from its signed Life plan')
    from ..runtime.d11_life_preparation_v1 import SIGN_KIND
    from ..runtime_contracts import canonical_serialize
    reader.installed_reader.readers.issuer._signer.verify(SIGN_KIND,
        canonical_serialize((work.namespace,'source_note_action',original_ref,metadata[1])),metadata[2])
    reader.original_keys.add(('source_note_action',original_ref))
    parent=next(locator for plan in reader.family_plans.values()for locator in plan.locators
        if locator.recipe[-1][-1]==action_ref and locator.recipe[0]=='life_model.source_note_action_locator.v3')
    reader.family_edges[('source_note_action',original_ref)]=(parent.parent_kind,parent.parent_ref,parent.parent_digest,parent.parent_producer,parent.field_path)
    return True


def read_bound_numeric_model_budget_lease_v3(db,lease_id):
    reader=_numeric_life_model_body_reader_v3(db)
    if reader is None:return False,None
    from .current_authority_graph_read_v3 import read_authority_current_point_v3,authority_current_json_v3
    from ..runtime.budget import BudgetLease
    columns=('lease_id','parent_id','bot_id','persona_id','currency','limits_json','used_json','reserved_json','unconfirmed_json','version','state')
    request=('runtime_budget_leases',columns,('lease_id',),(lease_id,))
    require_numeric_authority_body_request_v3(reader.work,request)
    row=read_authority_current_point_v3(db,table=request[0],columns=columns,key_columns=request[2],key=request[3],legacy_reader=lambda:None)
    if row is None:raise AuthorityUnavailable('Numeric model original budget lease is absent')
    lease=BudgetLease(*row[:5],*(authority_current_json_v3(row[i])for i in range(5,9)),*row[9:])
    if (lease.bot_id,lease.persona_id)!=reader.namespace.as_tuple:
        raise AuthorityUnavailable('Numeric model budget ancestor crossed its actual namespace')
    if lease.parent_id is not None:
        reader.parent_budget_refs.add(lease.parent_id)
        reader.family_edges[('runtime_budget_leases',lease.parent_id)]=('runtime_budget_leases',lease_id,canonical_digest(lease),reader.work.request.budget_reservation_operation_id,('parent_id',))
    return True,lease


def read_bound_numeric_model_budget_grant_v3(db,issuer,lease_id,version=None):
    reader=_numeric_life_model_body_reader_v3(db)
    if reader is None:return False,None
    if issuer is not reader.installed_reader.readers.issuer or lease_id not in reader.parent_budget_refs:
        raise AuthorityUnavailable('Numeric model grant crossed its actual installed issuer or signed Root family')
    from ..runtime_storage_v3 import runtime_storage_quantum_v3
    from .current_authority_graph_read_v3 import read_authority_current_point_v3,authority_current_json_v3
    from ..runtime.issuers import _decode_grant
    from ..runtime_contracts import canonical_serialize
    if version is None:
        with runtime_storage_quantum_v3(db)as meter:
            latest=meter.read_fixed_row(db,'runtime_budget_grants',('version','status'),'lease_id=? ORDER BY version DESC',(lease_id,))
        if latest is None or latest[1]!='active':raise AuthorityUnavailable('Numeric model current signed Root grant is absent')
        version=latest[0]
    row=read_authority_current_point_v3(db,table='runtime_budget_grants',columns=('grant_json','signature'),
        key_columns=('lease_id','version'),key=(lease_id,version),legacy_reader=lambda:None)
    if row is None:raise AuthorityUnavailable('Numeric model exact signed Root grant version is absent')
    value=authority_current_json_v3(row[0]);wire=canonical_serialize(value)
    issuer._signer.verify('budget-grant.v1',wire,row[1]);grant=_decode_grant(wire)
    if (grant.lease_id,grant.version)!=(lease_id,version) or (grant.bot_id,grant.persona_id)!=reader.namespace.as_tuple:
        raise AuthorityUnavailable('Numeric model signed grant original identity differs')
    return True,(grant,row[1])


def require_numeric_result_source_bridge_v3(work,*,observe=False):
    bridge=_RESULT_BRIDGES.get(work)
    if bridge is None:return None
    from .owner_location_read_v3 import _OWNER_LIFE_RESULT_ENTRIES_V3,_OWNER_LIFE_RESULT_INVOCATIONS_V3,_OWNER_MODEL_LOCATION_ENTRIES_V3
    service,request,intent,terminal,entry,state=(bridge[name]for name in ('service','request','intent','terminal','entry','owner_state'))
    call=state[5]
    if (bridge['source_identity']!=(work,work.operation,work.selection_digest,work.scope)
            or bridge['owner_identity']!=(call,call.operation,call.selection_digest,state[4],state[1],state[2])
            or _OWNER_LIFE_RESULT_ENTRIES_V3.get(entry)is not state or _OWNER_MODEL_LOCATION_ENTRIES_V3.get(work)is not state
            or _OWNER_LIFE_RESULT_INVOCATIONS_V3.get(service,{}).get(request.read_attempt_id)!=(work.credential,request,work.permit)
            or service._inflight_deliveries.get(request.read_attempt_id)!=work.permit
            or work.request is not intent or work.permit.operation!='read' or work.permit.operation_id!=request.read_attempt_id
            or call.permit is not work.permit or call.request is not intent or call.closed or call.operation.closed
            or call.subject!=work.subject or call.permission_anchor!=work.permit.pinned_anchor
            or service._graph_reader is not state[0] or work.controller.location._graph_db_path!=service._path
            or work.operation.pool is not call.operation.pool or work.controller.control is not call.control
            or work.controller.fences is not service._fences or service._store is not work.service._store):
        raise AuthorityUnavailable('Numeric result Source lost its independent Work and same actual READ Owner bridge')
    work._actual();call._actual();state[2].require_for_v3(state[1])
    if observe:
        if work.db.in_transaction:raise AuthorityUnavailable('Numeric result current permission must precede Graph SQL')
        call._check_permission_v3()
    return bridge


def prepare_authority_numeric_result_work_v3(service,*,request,intent,terminal,entry):
    from .life_numeric_model_result_service_v1 import InstalledLifeNumericModelResultServiceV1
    from .owner_location_read_v3 import _OWNER_LIFE_RESULT_ENTRIES_V3,_OWNER_LIFE_RESULT_INVOCATIONS_V3,_OWNER_MODEL_LOCATION_ENTRIES_V3
    from .current_authority_graph_read_v3 import begin_authority_numeric_result_read_work_v3
    if type(service)is not InstalledLifeNumericModelResultServiceV1:
        raise AuthorityUnavailable('Numeric result Source requires its actual installed result producer')
    registered=_OWNER_LIFE_RESULT_INVOCATIONS_V3.get(service,{}).get(request.read_attempt_id)
    state=_OWNER_LIFE_RESULT_ENTRIES_V3.get(entry)
    if (registered is None or registered[1]is not request or state is None or state[0]is not service._graph_reader
            or state[5].service is not service or state[5].request is not intent
            or intent.call_id!=request.call_id or terminal.call_id!=intent.call_id):
        raise AuthorityUnavailable('Numeric result Source lacks its exact in-flight selector, terminal and active Owner EOF')
    credential,_,permit=registered
    work=begin_authority_numeric_result_read_work_v3(service,credential=credential,permit=permit,intent=intent)
    bridge={'service':service,'request':request,'intent':intent,'terminal':terminal,'entry':entry,'owner_state':state,
        'source_identity':(work,work.operation,work.selection_digest,work.scope),
        'owner_identity':(state[5],state[5].operation,state[5].selection_digest,state[4],state[1],state[2])}
    _RESULT_BRIDGES[work]=bridge;_OWNER_MODEL_LOCATION_ENTRIES_V3[work]=state
    try:
        require_numeric_result_source_bridge_v3(work,observe=True)
        prepare_authority_numeric_source_read_v3(work,installed_reader=service._graph_reader,owner_entry=state[4])
        work.phase='numeric_result_source'
        return work
    except BaseException:
        from .current_authority_graph_read_v3 import finish_authority_graph_read_work_v3
        finish_authority_graph_read_work_v3(work)
        raise


def read_authority_numeric_result_material_v3(work,*,location,fact):
    bridge=require_numeric_result_source_bridge_v3(work)
    if bridge is None:raise AuthorityUnavailable('Numeric result has no actual independent Source Work')
    from .current_authority_graph_read_v3 import read_authority_graph_current_v3
    def read(db):
        service,request,intent,terminal=(bridge[name]for name in ('service','request','intent','terminal'))
        service._location.require_graph_snapshot_v1(db,location,graph_db_path=service._path)
        current=service._graph_reader.read(db,intent,work.now_utc,allow_accounted_result=True)
        from ..runtime.d11_life_preparation_v1 import _read
        from ..runtime.d06_life_numeric_paid_v1 import read_life_numeric_cost_commit_v1
        from .current_life_numeric_v1 import life_numeric_result_to_wire_v1
        p,b=current.prepared,current.binding
        saved=_read(db,namespace=p.namespace,issuer=service._issuer,kind='numeric_read_attempt_v1',ref=request.read_attempt_id)
        if saved is None or saved[0]!=life_numeric_result_to_wire_v1(request) or saved[1]!=p.acquire_operation_id:
            raise AuthorityUnavailable('Numeric result lacks its real signed once selector')
        cost=read_life_numeric_cost_commit_v1(db,namespace=p.namespace,issuer=service._issuer,prepared=p,intent=intent,terminal=terminal,fact=fact)
        expected=(p.namespace,p.installation_id,p.episode_ref,p.occurrence_digest,p.causal_operation_id,p.job_id,p.acquire_operation_id,
            p.prepare_operation_id,p.call_id,b.digest,p.digest,current.request.digest)
        if (request.namespace,request.installation_id,request.episode_ref,request.occurrence_digest,request.causal_operation_id,
                request.job_id,request.acquire_operation_id,request.original_operation_id,request.call_id,request.binding_digest,
                request.prepared_digest,request.model_request_digest)!=expected:
            raise AuthorityUnavailable('Numeric result actual worker/occurrence/original binding differs')
        quote=service._issuer.resource_issuer.original_signed_quote(db,p.quote_id,p.quote_version)
        parent=service._issuer.current_budget_grant(db,quote.parent_budget_lease_ref)
        return current,cost,(quote.valid_until_utc,parent.valid_until_utc)
    return read_authority_graph_current_v3(work,read)


def read_bound_numeric_result_cost_point_v3(db,*,table,columns,key_columns,key):
    reader=_numeric_life_model_body_reader_v3(db)
    if reader is None or reader.work not in _RESULT_BRIDGES:return False,None
    from .current_authority_graph_read_v3 import read_authority_current_point_v3,authority_current_json_v3
    from ..runtime_contracts import canonical_serialize
    from ..contracts import canonical_json
    request=(table,tuple(columns),tuple(key_columns),tuple(key))
    require_numeric_authority_body_request_v3(reader.work,request)
    row=read_authority_current_point_v3(db,table=table,columns=columns,key_columns=key_columns,key=key,legacy_reader=lambda:None)
    if row is None:return True,None
    values=[]
    for name,value in zip(columns,row):
        if name in {'receipt_json','reads','revisions','value'}:
            parsed=authority_current_json_v3(value)
            value=(canonical_serialize(parsed)if name=='value'else canonical_json(parsed))
            reader.operation.retain(len(value.encode('utf-8'))+128)
        values.append(value)
    return True,tuple(values)
