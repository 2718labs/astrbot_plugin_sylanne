"""Installed Core-owned V7 frame intent, one-shot counter and cost-bound signature.

RPC arguments are locators. Source bodies, protected program paths, keys and
resource prices are reconstructed or fixed by installation composition.
"""
from __future__ import annotations
from contextlib import contextmanager, closing
from dataclasses import asdict, replace
from hashlib import sha256
from pathlib import Path
import base64
import json
import secrets
import sqlite3
import threading

from ..contracts import canonical_json
from ..runtime_storage_v3 import (read_core_payload_row_v3, insert_core_payload_row_v3,
    core_payload_schema_v3, read_graph_head_v3,
    bind_runtime_database_from_control_v3, runtime_storage_operation_v3, runtime_storage_quantum_v3)
from ..runtime_contracts import canonical_digest, canonical_serialize, NamespaceId
from .contract import AuthorityUnavailable, JournalHead
from .d13_core_counter_contract_v1 import (
    D13CurrentFramePrepareSelectorV7, D13CurrentWireCountSelectorV1,
    D13CounterCPUPrepareInstructionV1, D13CounterAwaitingAccountingV1,
    D13CoreFrameIntentHeaderV7, D13CoreFullWireEvidenceV1, D13CoreFullWireEnvelopeV1,
    _D13CounterClaimRegistryV1, d13_core_counter_from_wire_v1, D13CorePaidBlockBindingV1, SIGNING_DOMAIN)
from .d13_core_counter_source_v1 import InstalledD13CounterSourceV1
from .internal_work_contract import InternalWorkTerminalV2, _phase_id
from .internal_work_service import AuthorityInternalWorkService
from ..model_broker.d13_provider_http_template_v1 import provider_http_template_v1, serialize_provider_http_v1
from ..runtime.installed_d13_natural_frame_v7 import (
    core_collection_binding_digest_v7, core_paid_block_binding_v7, core_paid_blockset_digest_v7)

_SCHEMA = """CREATE TABLE authority_d13_counter_originals_v1 (
    namespace TEXT NOT NULL, counter_operation_id TEXT NOT NULL,
    phase TEXT NOT NULL, payload_json TEXT NOT NULL, payload_digest TEXT NOT NULL,
    PRIMARY KEY(namespace,counter_operation_id,phase)) STRICT"""
_ALGORITHM = 'd13.full_http_counter.v1'


def install_initial_d13_counter_original_schema_v1(db):
    """Installer-owned initial store schema; creates no claim, fee or permission."""
    if type(db) is not sqlite3.Connection or not db.in_transaction:
        raise AuthorityUnavailable('counter initial schema requires actual installer transaction')
    present=db.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='authority_d13_counter_originals_v1'").fetchone()
    if present is not None:raise AuthorityUnavailable('fresh counter schema refuses an existing original store')
    db.execute(_SCHEMA)
    for operation in ('UPDATE','DELETE'):
        db.execute(f"CREATE TRIGGER authority_d13_counter_no_{operation.lower()}_v1 BEFORE {operation} ON authority_d13_counter_originals_v1 BEGIN SELECT RAISE(ABORT,'Core counter original is immutable'); END")


class InstalledD13CoreCounterServiceV1:
    def __init__(self, *, source, bridge, worker, execute_credential, signing_key,
                 component_signing_key, cpu_quote_authority, body_quote_authority, cpu_policy_id, cpu_policy_version,
                 body_policy_id, body_policy_version, billing_contract_digest,
                 create=False):
        from .v2_execution_bridge import AuthorityV2ExecutionBridge
        from .d13_counter_kernel_worker_v1 import InstalledD13CounterKernelWorkerV1
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        if (type(source) is not InstalledD13CounterSourceV1
                or type(bridge) is not AuthorityV2ExecutionBridge
                or type(worker) is not InstalledD13CounterKernelWorkerV1
                or bridge.core is not source.self_identity._core
                or bridge.namespace != source.self_identity._fences.namespace
                or worker.installation_id != source.policy.installation.installation_id
                or type(signing_key) is not bytes or len(signing_key) != 32):
            raise AuthorityUnavailable('actual installed Core counter composition required')
        self.source, self.bridge, self.worker = source, bridge, worker
        self.core, self.fences = bridge.core, source.self_identity._fences
        self.policy, self.execute_credential = source.policy, execute_credential
        self.namespace = source.self_identity._namespace_id
        self._key = Ed25519PrivateKey.from_private_bytes(signing_key)
        if self._key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex() != self.policy.counter_public_key_hex:
            raise AuthorityUnavailable('counter signing key differs from installed public policy')
        for name in ('serializer_fingerprint','applicability_fingerprint','counter_policy_fingerprint'):
            if worker._manifest[name] != getattr(self.policy,name):
                raise AuthorityUnavailable('counter program applicability differs from installed policy')
        from ..runtime.d13_counter_cpu_quote_policy_v1 import D13CounterCpuQuotePolicyAuthorityV1
        from ..domains.d02.body_quote_original import D02BodyQuoteAuthority
        if type(cpu_quote_authority) is not D13CounterCpuQuotePolicyAuthorityV1 or type(body_quote_authority) is not D02BodyQuoteAuthority:
            raise AuthorityUnavailable('actual installed CPU and Body quote authorities required')
        self.cpu_quote_authority, self.body_quote_authority = cpu_quote_authority, body_quote_authority
        self.cpu_policy_id, self.cpu_policy_version = cpu_policy_id, cpu_policy_version
        self.body_policy_id, self.body_policy_version = body_policy_id, body_policy_version
        self.billing_contract_digest = billing_contract_digest
        self._lock = threading.RLock()
        self._active_claim = None
        self._claims = _D13CounterClaimRegistryV1(self._require_current_claim,self._require_recorded_execution_origin)
        self.internal_work = AuthorityInternalWorkService(bridge.journal,
            current_prepared_reader=self._read_prepared_for_binding,
            claim_port=self._claim_port,
            terminal_port=lambda binding,claim,terminal,before: bridge.append_internal_work_terminal_v1(
                credential=execute_credential,binding=binding,claim=claim,terminal=terminal,before_head=before),
            core_head_verifier=lambda head: bridge.is_current_internal_work_head_v1(credential=execute_credential,head=head),
            component_signing_key=component_signing_key,
            original_reconciler=self._reconcile_original)
        # Qualification comes from the exact live worker and protected runtime.
        self._installed_runtime = worker.require_installed_runtime_v1()
        self._installed_runtime.require_current(worker)
        self.internal_work.installed_builds = {_ALGORITHM: worker.program_sha256}
        self.internal_work.installed_runtime_verified = True
        self.internal_work.installed_runtime_scope = 'installed-d13-full-http-counter-v1'
        self.internal_work.installed_algorithm_id = _ALGORITHM
        with self.core._tx() as db:
            present = db.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='authority_d13_counter_originals_v1'").fetchone()
            if present is None and create:
                db.execute(_SCHEMA)
                for operation in ('UPDATE','DELETE'):
                    db.execute(f"CREATE TRIGGER authority_d13_counter_no_{operation.lower()}_v1 BEFORE {operation} ON authority_d13_counter_originals_v1 BEGIN SELECT RAISE(ABORT,'Core counter original is immutable'); END")
            elif present != (core_payload_schema_v3(db, "authority_d13_counter_originals_v1", _SCHEMA),):
                raise AuthorityUnavailable('installed Core counter original store unavailable')

    def _original(self, operation_id, phase):
        from ..runtime_storage_v3 import runtime_storage_v3,begin_core_payload_read_v3
        from .c09_d13_source_retirement_v3 import require_not_retired_d13_source_v3
        key=(self.bridge.namespace,operation_id,phase)
        if runtime_storage_v3(self.core._db)is None:
            with self.core._tx()as db:
                require_not_retired_d13_source_v3(db,control=getattr(self.core,'_c09_storage_reader_v1',None),
                    namespace=self.bridge.namespace,kind='counter',item_id=operation_id)
                row=read_core_payload_row_v3(db,'authority_d13_counter_originals_v1',key)
            if row is None:return None
            payload=json.loads(row[0])
            if canonical_serialize(payload)!=row[0]or canonical_digest(payload)!=row[1]:
                raise AuthorityUnavailable('protected counter original bytes differ')
            return payload
        from .d13_core_counter_source_v1 import require_counter_call_resource_scope_v3
        scope=require_counter_call_resource_scope_v3(self,operation_id)
        reader=begin_core_payload_read_v3(scope.db,'authority_d13_counter_originals_v1',key)
        try:
            while not reader.complete:
                scope=require_counter_call_resource_scope_v3(self,operation_id)
                with self.core._tx()as db:
                    with runtime_storage_quantum_v3(db)as meter:
                        require_not_retired_d13_source_v3(db,control=getattr(self.core,'_c09_storage_reader_v1',None),
                            namespace=self.bridge.namespace,kind='counter',item_id=operation_id)
                        reader.advance(meter=meter)
            with self.core._tx()as db:
                with runtime_storage_quantum_v3(db):
                    scope=require_counter_call_resource_scope_v3(self,operation_id)
                    require_not_retired_d13_source_v3(db,control=getattr(self.core,'_c09_storage_reader_v1',None),
                        namespace=self.bridge.namespace,kind='counter',item_id=operation_id)
                    proof=reader.require_v3(db,'authority_d13_counter_originals_v1',key)
                    if proof is None:reader.release_payload_v3();return None
                    payload=proof.decoded_v3(db,'authority_d13_counter_originals_v1',key)
                    scope.record_original_v3(reader,payload)
            return payload
        except BaseException:
            reader.release_payload_v3();raise

    def _record(self, operation_id, phase, payload, *, source=None):
        from .current_source_location_v1 import _material as source_location_material
        from .c09_d13_source_retirement_v3 import require_not_retired_d13_source_v3
        from ..runtime_storage_v3 import runtime_storage_v3,begin_core_payload_write_v3
        key=(self.bridge.namespace,operation_id,phase)
        if runtime_storage_v3(self.core._db)is None:
            encoded=canonical_serialize(payload);commitment=canonical_digest(payload)
            with self.core._tx()as db:
                require_not_retired_d13_source_v3(db,control=getattr(self.core,'_c09_storage_reader_v1',None),
                    namespace=self.bridge.namespace,kind='counter',item_id=operation_id)
                if source is not None:self.source.self_identity._source_location.require_current_in_tx_v1(db,source.source_location)
                prior=read_core_payload_row_v3(db,'authority_d13_counter_originals_v1',key)
                if prior is None:
                    insert_core_payload_row_v3(db,'authority_d13_counter_originals_v1',key,encoded,commitment,
                        read_proof={'phase':phase,'payload_digest':commitment,'source_location':None if source is None
                            else json.loads(canonical_serialize(source_location_material(source.source_location)))})
                elif prior!=(encoded,commitment):
                    raise AuthorityUnavailable('counter phase attempted to replace its immutable original')
                if phase=='header':
                    from .d13_provider_http_admission_v1 import register_runtime_counter_header_index_v3
                    register_runtime_counter_header_index_v3(db,counter=self,operation=operation_id,payload=payload,digest=commitment)
            return payload
        from .d13_core_counter_source_v1 import require_counter_call_resource_scope_v3
        from ..runtime_contracts import _canonical_value
        scope=require_counter_call_resource_scope_v3(self,operation_id)
        writer=begin_core_payload_write_v3(scope.db,'authority_d13_counter_originals_v1',key,payload)
        try:
            while writer.phase=='canonical':
                require_counter_call_resource_scope_v3(self,operation_id)
                with runtime_storage_quantum_v3(scope.db)as meter:writer.advance(meter=meter)
            with self.core._tx()as db:
                with runtime_storage_quantum_v3(db):
                    scope=require_counter_call_resource_scope_v3(self,operation_id)
                    require_not_retired_d13_source_v3(db,control=getattr(self.core,'_c09_storage_reader_v1',None),
                        namespace=self.bridge.namespace,kind='counter',item_id=operation_id)
                    if source is not None:self.source.self_identity._source_location.require_current_in_tx_v1(db,source.source_location)
                    writer.attach_read_proof_v3({'phase':phase,'payload_digest':writer.digest,
                        'source_location':None if source is None else _canonical_value(source_location_material(source.source_location),set())})
                while not writer.complete:
                    with runtime_storage_quantum_v3(db)as meter:
                        scope=require_counter_call_resource_scope_v3(self,operation_id)
                        require_not_retired_d13_source_v3(db,control=getattr(self.core,'_c09_storage_reader_v1',None),
                            namespace=self.bridge.namespace,kind='counter',item_id=operation_id)
                        if source is not None:self.source.self_identity._source_location.require_current_in_tx_v1(db,source.source_location)
                        writer.advance(meter=meter)
                with runtime_storage_quantum_v3(db):
                    proof=writer.require_v3(db,'authority_d13_counter_originals_v1',key)
                    result=proof.decoded_v3(db,'authority_d13_counter_originals_v1',key)
                    scope.record_original_v3(writer.verify_reader,result)
                    if phase=='header':
                        from .d13_provider_http_admission_v1 import register_runtime_counter_header_index_v3
                        register_runtime_counter_header_index_v3(db,counter=self,operation=operation_id,payload=result,digest=writer.digest)
            return result
        except BaseException:
            writer.release_payload_v3();raise

    @contextmanager
    def _current_source(self, selector, draft=None, *, read_credential, subject, operation_id=None):
        if subject != self.source.self_identity._read_subject:
            raise AuthorityUnavailable('counter read subject is not the authenticated installed peer')
        anchor = self.fences.current_anchor(credential=read_credential,subject=subject)
        permit = self.fences.begin_fence(credential=read_credential,subject=subject,
            holder=self.source.self_identity._holder,operation='read',
            operation_id=operation_id or 'd13-counter-read:'+secrets.token_hex(24),expected_anchor=anchor)
        from .d13_core_counter_source_v1 import retain_authority_counter_source_call_v3
        try:
            with retain_authority_counter_source_call_v3(self,selector=selector,credential=read_credential,
                    subject=subject,permit=permit,draft=draft):
                current = self.source.read(selector,credential=read_credential,subject=subject,permit=permit,
                    frozen_at_utc=None if draft is None else draft['frozen_at_utc'],
                    expires_at_utc=None if draft is None else draft['plan_deadline_utc'])
                if draft is not None:
                    self._require_same_source(draft,current)
                yield current,permit
        finally:
            # Claim consumes this exact read fence atomically with its independent append.
            with self.core._tx() as db:
                row = self.bridge.fences._row(db,permit.operation_id)
                active = row is not None and row[6] == 'active'
            if active:
                self.fences.finish_fence(credential=read_credential,subject=subject,permit=permit,
                    request_id=permit.operation_id+':finish',request_digest='sha256:'+canonical_digest((permit.token,'counter-source-read')))

    def _require_same_source(self, draft, current):
        from .d13_core_counter_source_v1 import require_current_authority_counter_call_work_v3
        work=require_current_authority_counter_call_work_v3(self,current)
        material=None
        if work is not None:
            from .current_authority_graph_read_v3 import bind_prepared_authority_graph_read_v3
            with work.quantum_v3()as meter:
                with bind_prepared_authority_graph_read_v3(work.prepared,service=work.service,db=work.db,meter=meter):
                    material=work.counter_pair_reader.require_counter_draft_material_v7(work)
                    material.require_same_source_v7(work,draft)
            plan_digest=material.prospective_plan_digest
        else:plan_digest=canonical_digest(current.prospective.plan)
        if (plan_digest != draft['prospective_plan_digest']
                or current.source_scope_digest != draft['source_scope_digest']
                or current.owner_grant_digest != draft['owner_grant_digest']):
            raise AuthorityUnavailable('counter original Source, prospective plan or Owner changed')
        if work is not None:
            from .current_authority_graph_read_v3 import authority_current_versions_v3
            allowed={draft['selector']['counter_operation_id']+':prepare':{'d02.reservation.v1','runtime.job'},
                draft['selector']['counter_operation_id']+':settle':{'d02.reservation.v1','d02.body_state.v1','d02.settlement.v1','runtime.job','runtime.cost_settlement'}}
            with work.quantum_v3()as meter:
                with bind_prepared_authority_graph_read_v3(work.prepared,service=work.service,db=work.db,meter=meter):
                    for session,event_id,epoch,revisions in work.counter_events:
                        writes=authority_current_versions_v3(revisions)
                        if session!='d13-counter-v1'or event_id not in allowed or not writes or any(v.key.type_name not in allowed[event_id]for v in writes):
                            raise AuthorityUnavailable('counter own Graph event changed another domain')
            return
        path = Path(current.source_location.graph_db_path)
        with closing(sqlite3.connect(path.as_uri()+'?mode=ro',uri=True)) as db:
            db.execute('BEGIN')
            self.source.self_identity._source_location.require_graph_snapshot_v1(db,current.source_location,graph_db_path=path)
            rows = db.execute('SELECT session,event_id,epoch_revision,revisions FROM graph_events WHERE bot=? AND persona=? AND epoch_revision>? ORDER BY epoch_revision',
                (*self.namespace.as_tuple,draft['graph_epoch'])).fetchall()
            if len(rows)>2 or [row[2] for row in rows] != list(range(draft['graph_epoch']+1,current.current_self.graph_epoch+1)):
                raise AuthorityUnavailable('counter current frame has an unproven Graph epoch transition')
            allowed = {draft['selector']['counter_operation_id']+':prepare': {'d02.reservation.v1','runtime.job'},
                draft['selector']['counter_operation_id']+':settle': {'d02.reservation.v1','d02.body_state.v1','d02.settlement.v1','runtime.job','runtime.cost_settlement'}}
            from ..graph_store import GraphStore
            for session,event_id,epoch,revisions in rows:
                if session!='d13-counter-v1' or event_id not in allowed:
                    raise AuthorityUnavailable('another Graph operation occurred inside the original counter frame')
                writes = GraphStore._version_rows(revisions)
                if not writes or any(v.key.type_name not in allowed[event_id] for v in writes):
                    raise AuthorityUnavailable('counter own Graph event changed another domain')
        from ..model_broker.natural_reply_history_v7 import freeze_natural_reply_request_v7, thaw_natural_reply_request_v7
        for name in ('raw','compressed'):
            frozen = getattr(current.pair,name)
            original = draft[name]
            if (frozen is None)!=(original is None):
                raise AuthorityUnavailable('counter current variant presence changed')
            if frozen is not None:
                previous = thaw_natural_reply_request_v7(original)
                selection = replace(frozen.input.history_selection,
                    collection_snapshot_commitment=previous.input.history_selection.collection_snapshot_commitment)
                replay = freeze_natural_reply_request_v7(replace(frozen.input,history_selection=selection),frozen.installation)
                if replay != previous:
                    raise AuthorityUnavailable('counter current complete semantic variant changed')

    def _new_draft(self, selector, current):
        from ..runtime.natural_reply_job_v2 import natural_job_ids_v2
        from .d13_core_counter_source_v1 import require_current_authority_counter_call_work_v3
        work=require_current_authority_counter_call_work_v3(self,current)
        material=None
        if work is not None:
            from .current_authority_graph_read_v3 import bind_prepared_authority_graph_read_v3
            with work.quantum_v3()as meter:
                with bind_prepared_authority_graph_read_v3(work.prepared,service=work.service,db=work.db,meter=meter):
                    material=work.counter_pair_reader.require_counter_draft_material_v7(work)
                    raw_frozen,compressed_frozen=material.frozen_values_v7(work)
            call_id=material.generation_call_id;input_json=material.input_json;input_digest=material.input_digest
        else:
            call_id = natural_job_ids_v2(self.namespace,selector.c02_operation_id,'generation')[3]
            templates = {name: (None if getattr(current.pair,name) is None else provider_http_template_v1(
                getattr(current.pair,name),generation_call_id=call_id,billing_contract_digest=self.billing_contract_digest,
                serializer_pin=self.policy.serializer_fingerprint)) for name in ('raw','compressed')}
            input_value = {'schema':'sylanne3.d13.counter-kernel-input.v1',
                'raw_http_template_digest':templates['raw'].template_digest,
                'compressed_http_template_digest':None if templates['compressed'] is None else templates['compressed'].template_digest,
                'raw_http_utf8':serialize_provider_http_v1(templates['raw'],request_digest='0'*64).decode('utf-8'),
                'compressed_http_utf8':None if templates['compressed'] is None else serialize_provider_http_v1(templates['compressed'],request_digest='0'*64).decode('utf-8'),
                **{name:getattr(self.policy,name) for name in ('serializer_fingerprint','applicability_fingerprint','counter_policy_fingerprint')}}
            raw_input = canonical_serialize(input_value).encode('utf-8')
            input_json=raw_input.decode('utf-8');input_digest=sha256(raw_input).hexdigest()
            raw_frozen=asdict(current.pair.raw);compressed_frozen=None if current.pair.compressed is None else asdict(current.pair.compressed)
        identity = canonical_digest((self.policy.policy_digest,selector))
        value = {'selector':asdict(selector),'frame_intent_id':'d13-frame:'+identity[:48],
            'counter_nonce':secrets.token_hex(24),'prospective_plan_digest':canonical_digest(current.prospective.plan)if material is None else material.prospective_plan_digest,
            'source_scope_digest':current.source_scope_digest,'owner_grant_digest':current.owner_grant_digest,
            'owner_responsibility_digest':canonical_digest(current.current_owner.guard),
            'frozen_at_utc':current.frozen_at_utc,'expires_at_utc':current.expires_at_utc,
            'plan_deadline_utc':current.prospective.plan.valid_until_utc,'generation_call_id':call_id,
            'graph_epoch':current.current_self.graph_epoch,
            'source_ref':asdict(current.prospective.preparation_evidence.source_ref),
            'raw':raw_frozen,'compressed':compressed_frozen,
            'input_json':input_json,'input_digest':input_digest,
            'parent_budget_lease_ref':current.prospective.grant.lease_id,
            'budget_grant_digest':canonical_digest(current.prospective.grant),
            'activity_id':'d13-counter-activity:'+identity[:40],'job_id':'d13-counter-job:'+identity[:40],
            'execution_id':'d13-counter-execution:'+identity[:40],
            'authority_id':current.current_self.authority_id,'activation_generation':current.current_self.activation_generation,
            'storage_generation':current.source_location.storage_generation,
            'selected_manifest_digest':current.source_location.manifest_digest,
            'selected_pointer_version':current.source_location.pointer_version,
            'collection_snapshot_commitment':current.pair.raw.input.history_selection.collection_snapshot_commitment,
            'collection_digest':material.collection_digest if material is not None else core_collection_binding_digest_v7(current.pair.collection,
                snapshot_commitment=current.pair.raw.input.history_selection.collection_snapshot_commitment,
                frozen_at_utc=current.frozen_at_utc),
            'block_bindings':[core_paid_block_binding_v7(item) for item in current.pair.projected_blocks]}
        value['blockset_digest']=core_paid_blockset_digest_v7(value['block_bindings'])
        if work is None:value['frame_intent_digest']=canonical_digest(value)
        else:
            from ..runtime.natural_frozen_original_read_v3 import _CanonicalComparisonV3
            digest_reader=_CanonicalComparisonV3(value,operation=work.operation)
            while True:
                with work.quantum_v3()as meter:
                    complete=digest_reader.advance(meter)
                if complete:break
            value['frame_intent_digest']=digest_reader.digest
        return value

    def _instruction(self,draft):
        from ..runtime_contracts import VersionedRef
        selector=d13_core_counter_from_wire_v1(draft['selector'],D13CurrentFramePrepareSelectorV7)
        with self._graph_db(operation_id=draft['selector']['counter_operation_id'],
                deadline_utc=draft['expires_at_utc']) as db:
            cpu_policy=self.cpu_quote_authority.read_policy(db,self.namespace,self.cpu_policy_id,self.cpu_policy_version)
            body_policy=self.body_quote_authority.policy(db,self.namespace,self.body_policy_id,self.body_policy_version)
            if (cpu_policy.algorithm_ref!=_ALGORITHM or cpu_policy.installation_id!=selector.install_id
                    or body_policy.work_kind!=_ALGORITHM or cpu_policy.valid_until_utc<draft['expires_at_utc']
                    or body_policy.valid_until<draft['expires_at_utc']):
                raise AuthorityUnavailable('counter installed actual CPU/Body policy differs')
        return D13CounterCPUPrepareInstructionV1(namespace=self.namespace,install_id=selector.install_id,
            authority_namespace=selector.authority_namespace,frame_intent_id=draft['frame_intent_id'],
            frame_intent_digest=draft['frame_intent_digest'],counter_operation_id=selector.counter_operation_id,
            c02_operation_id=selector.c02_operation_id,plan_ref=selector.plan_ref,source_ref=VersionedRef(**draft['source_ref']),
            prospective_plan_digest=draft['prospective_plan_digest'],prospective_plan_deadline_utc=draft['plan_deadline_utc'],input_digest=draft['input_digest'],
            source_scope_digest=draft['source_scope_digest'],owner_responsibility_digest=draft['owner_responsibility_digest'],
            owner_grant_digest=draft['owner_grant_digest'],parent_budget_lease_ref=draft['parent_budget_lease_ref'],
            budget_grant_digest=draft['budget_grant_digest'],activity_id=draft['activity_id'],job_id=draft['job_id'],
            execution_id=draft['execution_id'],algorithm_id=_ALGORITHM,algorithm_build_digest=self.worker.program_sha256,
            policy_ref='d13countercpupolicy:'+canonical_digest(cpu_policy)[:48],
            cpu_policy_id=self.cpu_policy_id,cpu_policy_version=self.cpu_policy_version,
            body_policy_id=self.body_policy_id,body_policy_version=self.body_policy_version,
            generation_call_id=draft['generation_call_id'],activation_generation=draft['activation_generation'],
            frozen_at_utc=draft['frozen_at_utc'],expires_at_utc=draft['expires_at_utc'])

    def prepare_current_d13_frame_v7(self, *, selector, read_credential, subject):
        self._installed_runtime.require_current(self.worker)
        if type(selector) is not D13CurrentFramePrepareSelectorV7:
            raise AuthorityUnavailable('closed current frame selector required')
        with self._lock:
            from .d13_core_counter_source_v1 import retain_counter_call_resource_scope_v3
            with retain_counter_call_resource_scope_v3(self,selector=selector,read_credential=read_credential,subject=subject):
                draft=self._original(selector.counter_operation_id,'draft')
                if draft is not None and draft['selector'] != asdict(selector):
                    raise AuthorityUnavailable('counter operation changed its original selector')
                with self._current_source(selector,draft,read_credential=read_credential,subject=subject) as (current,permit):
                    if draft is None:
                        draft=self._record(selector.counter_operation_id,'draft',self._new_draft(selector,current),source=current)
                    prepared=self._read_prepared(draft,required=False)
                    if prepared is None:
                        return self._instruction(draft)
                    header=self._header(draft,prepared)
                    self._record(selector.counter_operation_id,'header',asdict(header),source=current)
                    return header

    @contextmanager
    def _graph_db(self, *, operation_id=None, deadline_utc=None):
        path=self.source.self_identity._graph._path
        with closing(sqlite3.connect(path.as_uri()+'?mode=ro',uri=True)) as db:
            handle=bind_runtime_database_from_control_v3(db,
                control=self.source.self_identity._source_location._control,role='graph')
            db.execute('PRAGMA query_only=ON');db.execute('BEGIN')
            try:
                with runtime_storage_operation_v3(db,operation_id=operation_id,deadline_utc=deadline_utc), runtime_storage_quantum_v3(db):
                    yield db
            finally:
                db.rollback()
                if handle is not None:
                    handle.close()

    def _read_prepared(self,draft,*,required=True,current=False):
        from ..runtime.c04_internal_work_original_v1 import read_c04_internal_work_prepared_v1
        from ..runtime.budget import get_budget_lease, require_budget_family_admissible
        from ..runtime.jobs import get_job
        from ..runtime.d11_types import job_graph_write
        from datetime import datetime
        operation=draft['selector']['counter_operation_id']
        with self._graph_db(operation_id=draft['selector']['counter_operation_id'],
                deadline_utc=draft['expires_at_utc']) as db:
            exists=db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='graph_c04_internal_work_prepared_v1'").fetchone()
            prepared=None if exists is None else read_c04_internal_work_prepared_v1(db,self.namespace,operation)
            if prepared is None:
                if required:raise AuthorityUnavailable('actual W01 counter CPU preparation absent')
                return None
            b=prepared.binding
            if (b.namespace!=self.bridge.namespace or b.operation_id!=operation or b.algorithm_ref!=_ALGORITHM
                    or b.algorithm_build_digest!=self.worker.program_sha256 or b.input_digest!=draft['input_digest']
                    or b.activity_id!=draft['activity_id'] or b.execution_id!=draft['execution_id']
                    or b.parent_budget_lease_ref!=draft['parent_budget_lease_ref']
                    or b.activation_generation!=draft['activation_generation']
                    or prepared.owner_grant_digest!=draft['owner_grant_digest']):
                raise AuthorityUnavailable('actual W01 CPU binding differs from independently frozen Core frame')
            issuer=self.source.observer.issuer
            quote=issuer.resource_issuer.original_signed_quote(db,b.resource_quote_ref,b.resource_quote_version)
            policy,policy_quote=self.cpu_quote_authority.read_original_request_quote(db,self.namespace,operation)
            body=self.body_quote_authority.original_body_quote(db,b.body_quote_ref,b.body_quote_version,quote,operation)
            grant=issuer.current_budget_grant(db,b.parent_budget_lease_ref)
            if (quote!=policy_quote or canonical_digest(quote)!=b.resource_quote_digest or quote.work_kind!=_ALGORITHM
                    or quote.ceiling!={'cpu_ms':1000} or quote.parent_budget_lease_ref!=b.parent_budget_lease_ref
                    or quote.operation_id!=operation or quote.activity_id!=b.activity_id
                    or policy.policy_id!=self.cpu_policy_id or policy.version!=self.cpu_policy_version
                    or b.policy_ref!=quote.snapshot_ref or canonical_digest(body)!=b.body_quote_digest
                    or len(body.components)!=1 or body.components[0].component_id!=b.component_id
                    or body.components[0].duration_rate!=0 or canonical_digest(grant)!=draft['budget_grant_digest']
                    or _ALGORITHM not in grant.allowed_work_kinds):
                raise AuthorityUnavailable('signed actual counter CPU/Body/parent-grant originals differ')
            body_row=db.execute('SELECT policy_id,policy_version FROM d02_body_quotes_v1 WHERE bot=? AND persona=? AND quote_id=?',
                (*self.namespace.as_tuple,b.body_quote_ref)).fetchone()
            reserve=db.execute("SELECT digest,lease_id,receipt_json FROM runtime_budget_operations WHERE bot_id=? AND persona_id=? AND operation_id=? AND phase='reserve'",
                (*self.namespace.as_tuple,prepared.budget_reservation_operation_id)).fetchone()
            if (body_row!=(self.body_policy_id,self.body_policy_version) or reserve is None
                    or reserve[:2]!=(b.binding_digest,b.parent_budget_lease_ref)
                    or sha256(reserve[2].encode('utf-8')).hexdigest()!=prepared.budget_reservation_digest):
                raise AuthorityUnavailable('counter original Body policy or actual D11 reservation differs')
            if current:
                lease=get_budget_lease(db,b.parent_budget_lease_ref)
                require_budget_family_admissible(db,lease.lease_id)
                reservation=db.execute('SELECT state FROM runtime_budget_reservations WHERE lease_id=? AND operation_id=?',
                    (lease.lease_id,prepared.budget_reservation_operation_id)).fetchone()
                job=get_job(db,draft['job_id'])
                reading=self.source.observer.clock();now=reading.utc_seconds+reading.utc_error_seconds
                if (lease.state!='active' or reservation!=('reserved',) or job.phase!='running'
                        or job.cancel_epoch or job.fence<1 or job.lease_holder is None or job.lease_expires_utc is None
                        or job.operation_id!=operation or job.activity_id!=b.activity_id
                        or job.budget_ref!=b.parent_budget_lease_ref or job.resource_ref!=quote.resource_ref
                        or now>=min(draft['expires_at_utc'],grant.valid_until_utc,quote.valid_until_utc,
                            datetime.fromisoformat(job.deadline_utc.replace('Z','+00:00')).timestamp(),
                            datetime.fromisoformat(job.lease_expires_utc.replace('Z','+00:00')).timestamp())):
                    raise AuthorityUnavailable('counter current CPU job, reserve or absolute deadline differs')
                job_write=job_graph_write(job)
                row=read_graph_head_v3(db,job_write.key.token)
                if row is None or row[2]!=1 or json.loads(row[1])!=job_write.value:
                    raise AuthorityUnavailable('counter actual acquired job projection differs')
                for token,revision in prepared.read_versions:
                    row=db.execute('SELECT revision,valid FROM graph_atoms WHERE token=?',(token,)).fetchone()
                    if (row is not None if revision==0 else row!=(revision,1)):
                        raise AuthorityUnavailable('counter actual prepared prerequisite changed before claim')
            return prepared

    def _read_prepared_for_binding(self,binding):
        if self._active_claim is None or self._active_claim[3].binding!=binding:
            raise AuthorityUnavailable('counter claim lacks its actual live current Source scope')
        prepared=self._read_prepared(self._active_claim[2],current=True)
        if prepared!=self._active_claim[3]:
            raise AuthorityUnavailable('counter prepared original changed during independent current read')
        return prepared

    def _header(self,draft,prepared):
        from ..runtime_contracts import VersionedRef
        selector=draft['selector']
        return D13CoreFrameIntentHeaderV7(install_id=selector['install_id'],authority_id=draft['authority_id'],
            authority_namespace=selector['authority_namespace'],namespace=self.namespace,
            frame_intent_id=draft['frame_intent_id'],frame_intent_digest=draft['frame_intent_digest'],
            counter_operation_id=selector['counter_operation_id'],counter_nonce=draft['counter_nonce'],
            c02_operation_id=selector['c02_operation_id'],plan_ref=VersionedRef(**selector['plan_ref']),
            job_id=draft['job_id'],step_index=0,generation_call_id=draft['generation_call_id'],
            activation_generation=draft['activation_generation'],storage_generation=draft['storage_generation'],
            selected_manifest_digest=draft['selected_manifest_digest'],selected_pointer_version=draft['selected_pointer_version'],
            owner_responsibility_digest=draft['owner_responsibility_digest'],owner_grant_digest=draft['owner_grant_digest'],
            source_scope_digest=draft['source_scope_digest'],parent_budget_lease_ref=draft['parent_budget_lease_ref'],
            budget_grant_digest=draft['budget_grant_digest'],cpu_reservation_ref=prepared.budget_reservation_operation_id,
            cpu_reservation_digest=prepared.budget_reservation_digest,policy_digest=self.policy.policy_digest,
            template_digest=self.policy.template_digest,collection_digest=draft['collection_digest'],
            collection_snapshot_commitment=draft['collection_snapshot_commitment'],
            blockset_digest=draft['blockset_digest'],billing_contract_digest=self.billing_contract_digest,
            frozen_at_utc=draft['frozen_at_utc'],expires_at_utc=draft['expires_at_utc'],
            prospective_plan_deadline_utc=draft['plan_deadline_utc'],
            raw_authority_digest=draft['raw']['frozen_input_digest'],
            compressed_authority_digest=None if draft['compressed'] is None else draft['compressed']['frozen_input_digest'],
            raw_http_template_digest=json.loads(draft['input_json'])['raw_http_template_digest'],
            compressed_http_template_digest=json.loads(draft['input_json'])['compressed_http_template_digest'],
            block_bindings=tuple(D13CorePaidBlockBindingV1(**v) for v in draft['block_bindings']))

    def _current_owner_in_tx(self,db,current,draft):
        service=self.source.self_identity
        owner=service._owner_storage._head_in_tx(db)
        if owner.guard!=current.current_owner.guard or owner.grant_digest.removeprefix('sha256:')!=draft['owner_grant_digest']:
            raise AuthorityUnavailable('counter Owner head changed before actual claim')
        service._owner_storage._background_identity_in_tx(db,owner)
        head=service._head(db,self.bridge.namespace)
        value=current.current_self
        if (head is None or head[0]!=canonical_json(asdict(self.namespace))
                or head[1:8]!=(value.installation_id,value.manifest_digest,value.mapping_id,value.self_entity_ref,
                    value.mapping_revision,value.mapping_revocation_epoch,'active')
                or head[8:10]!=(value.registration_operation_id,value.registration_digest)):
            raise AuthorityUnavailable('counter registered Self mapping changed before claim')
        self.source.observer._owner_stop_reply_service_v1.require_reply_cycle_not_retired_in_tx_v1(
            db,context=current.source_location.context,c02_operation_id=draft['selector']['c02_operation_id'])

    def _claim_port(self,binding,claim,before_head,prepared):
        from .independent_append_guard_v3 import independent_append_core_guard_v3
        from .d12_lifecycle_gate_v1 import require_lifecycle_admission_in_tx_v1
        if self._active_claim is None:
            raise AuthorityUnavailable('counter has no independently qualified live Source read')
        current,permit,draft,expected=self._active_claim
        if expected!=prepared or binding!=prepared.binding:
            raise AuthorityUnavailable('counter actual current preparation changed')
        self.core._require(self.execute_credential,'execution',self.bridge.namespace)
        with independent_append_core_guard_v3(self.bridge) as (db,deletion):
            with self.bridge.journal.freeze_writes():
                execution=self.bridge.journal.verified_head()
                self.bridge._require_v2_mode_locked(db)
                self.bridge._check_deletion_locked(db,deletion)
                self.bridge._check_execution_head_locked(db,execution)
                self.source.self_identity._source_location.require_current_in_tx_v1(db,current.source_location)
                self._current_owner_in_tx(db,current,draft)
                require_lifecycle_admission_in_tx_v1(db,self.bridge.namespace,action='first_internal_work_claim')
                if execution!=before_head or self.bridge.journal.read_internal_work_v1(binding).claim is not None:
                    raise AuthorityUnavailable('counter durable execution right was already consumed')
                self.bridge.fences.finish_fence_locked(db,permit,subject=permit.subject,current_anchor=permit.pinned_anchor,
                    request_id=permit.operation_id+':claim-consumed',
                    request_digest='sha256:'+canonical_digest((binding.binding_digest,claim.mutation_id)))
                append=self.bridge.journal.append_internal_work_claim_v1(binding,claim,execution)
                row=self.core._row(db,self.bridge.namespace)
                db.execute('UPDATE authority_namespaces SET execution_seq=?,execution_digest=?,anchor_nonce=? WHERE namespace=?',
                    (append.sequence,append.chain_digest,self.core._new_nonce(),self.bridge.namespace))
                self.core._event(db,self.bridge.namespace,'internal_work_claim',row[1],
                    (binding.binding_digest,append.mutation_id,append.content_digest,append.chain_digest))
        return append

    def _require_current_claim(self,binding,claim,input_digest,expires_at_utc):
        if self._active_claim is None:
            raise AuthorityUnavailable('counter mechanical capsule is outside its installed service interval')
        current,permit,draft,prepared=self._active_claim
        if (binding!=prepared.binding or input_digest!=draft['input_digest'] or expires_at_utc!=draft['expires_at_utc']):
            raise AuthorityUnavailable('counter capsule changed its independently frozen input')
        inspection=self.internal_work.inspect(binding)
        if inspection.claim!=claim or inspection.claim_append is None:
            raise AuthorityUnavailable('counter capsule lacks its same-chain durable claim')
        if inspection.terminal is not None:
            raise AuthorityUnavailable('counter original claim is already terminal; execution cannot restart')
        reading=self.source.observer.clock()
        if reading.utc_seconds+reading.utc_error_seconds>=expires_at_utc:
            raise AuthorityUnavailable('counter original deadline expired before body input')
        with self.fences._frozen() as (db,deletion,execution,history):
            anchor=self.fences._current_locked(db,deletion,execution)
            if (anchor.activation_generation!=binding.activation_generation or execution!=inspection.verified_head
                    or anchor.execution_seq!=inspection.claim_append.sequence
                    or anchor.execution_digest!=inspection.claim_append.chain_digest):
                raise AuthorityUnavailable('counter current execution interval changed')
            self._current_owner_in_tx(db,current,draft)
        self._read_prepared(draft,current=True)

    def _terminal(self,binding,claim,observed,claimed):
        from .d13_counter_kernel_worker_v1 import ObservedD13CounterKernelV1
        if type(observed) is not ObservedD13CounterKernelV1:
            raise AuthorityUnavailable('counter lacks its actual isolated kernel observation')
        observed.require_origin(claimed,self.worker)
        if observed.status=='unknown' or observed.actual_cpu_ns is None:
            # A durable claim without an observed terminal stays unknown and cannot rerun.
            raise AuthorityUnavailable('counter kernel outcome or actual CPU is unknown')
        ms=(observed.actual_cpu_ns+999999)//1000000
        output=result_digest=None
        if observed.status=='completed':
            result=json.loads(observed.result_json)
            measured={'schema':'sylanne3.d13.counter-measured-output.v1',
                'kernel_result':result,'actual_cpu_ns':observed.actual_cpu_ns,
                'pid_identity':observed.pid_identity,'group_identity':observed.group_identity,
                'memory_peak_bytes':observed.memory_peak_bytes,'exit_code':observed.exit_code}
            result_digest=canonical_digest(measured)
            output=canonical_json({'schema':'sylanne3.d13.counter-terminal-output.v1',
                'input_digest':'sha256:'+binding.input_digest,'result_digest':'sha256:'+result_digest,
                'measurement':measured})
        terminal=InternalWorkTerminalV2(binding.binding_digest,claim.mutation_id,_phase_id(binding.binding_digest,'terminal'),
            observed.status,ms,_ALGORITHM,self.worker.program_sha256,binding.input_digest,result_digest,output,
            None if output is None else 'internal-work:component:'+binding.binding_digest,
            None if output is None else '0'*64,None if output is None else '0'*64,'0'*64)
        if output is not None:
            digest,signature=self.internal_work.sign_component_completion(binding,terminal)
            terminal=replace(terminal,component_receipt_digest=digest,component_receipt_signature=signature)
        return replace(terminal,execution_signature=self.internal_work.sign_execution_terminal(terminal))

    def _require_selector(self,selector,draft,header):
        from ..model_broker.natural_reply_history_v7 import thaw_natural_reply_request_v7
        raw=thaw_natural_reply_request_v7(draft['raw'])
        compressed=None if draft['compressed'] is None else thaw_natural_reply_request_v7(draft['compressed'])
        value=json.loads(draft['input_json'])
        if (selector.install_id!=header.install_id or selector.authority_namespace!=header.authority_namespace
                or selector.frame_intent_id!=header.frame_intent_id or selector.frame_intent_digest!=header.frame_intent_digest
                or selector.counter_operation_id!=header.counter_operation_id
                or selector.expected_raw_authority_digest!=raw.frozen_input_digest
                or selector.expected_compressed_authority_digest!=(None if compressed is None else compressed.frozen_input_digest)
                or selector.expected_raw_http_template_digest!=value['raw_http_template_digest']
                or selector.expected_compressed_http_template_digest!=value['compressed_http_template_digest']):
            raise AuthorityUnavailable('counter selector differs from complete independent Core originals')
        return raw,compressed

    def _require_kernel_result(self,draft,measurement):
        result=measurement['kernel_result'];value=json.loads(draft['input_json'])
        if (measurement['schema']!='sylanne3.d13.counter-measured-output.v1'
                or measurement['exit_code']!=0 or type(measurement['actual_cpu_ns']) is not int
                or not 0<=measurement['actual_cpu_ns']<=1000000000
                or result['input_digest']!=draft['input_digest'] or result['token_evidence']!='bounded_full_wire'):
            raise AuthorityUnavailable('counter actual measured result or resource ceiling differs')
        for name in ('serializer_fingerprint','applicability_fingerprint','counter_policy_fingerprint',
                     'raw_http_template_digest','compressed_http_template_digest'):
            if result[name]!=value[name]:
                raise AuthorityUnavailable('counter kernel result changed its complete input template or installed algorithm')
        for name in ('raw','compressed'):
            text=value[name+'_http_utf8']
            size=None if text is None else len(text.encode('utf-8'))
            if result[name+'_http_bytes']!=size:
                raise AuthorityUnavailable('counter kernel result changed complete serialized HTTP size')
        return result

    def _awaiting(self,draft,inspection):
        if inspection.terminal is None:
            raise AuthorityUnavailable('counter durable claim is unresolved; the original operation cannot rerun')
        return D13CounterAwaitingAccountingV1(self.namespace,draft['frame_intent_id'],draft['frame_intent_digest'],
            draft['selector']['counter_operation_id'],inspection.binding.binding_digest,
            inspection.terminal.terminal_digest,inspection.terminal_append.content_digest,inspection.terminal.status)

    def count_current_d13_wire_v1(self, *, selector, read_credential, subject):
        self._installed_runtime.require_current(self.worker)
        if type(selector) is not D13CurrentWireCountSelectorV1:
            raise AuthorityUnavailable('closed current wire-count selector required')
        with self._lock:
            from .d13_core_counter_source_v1 import retain_counter_call_resource_scope_v3
            with retain_counter_call_resource_scope_v3(self,selector=selector,read_credential=read_credential,subject=subject):
                draft=self._original(selector.counter_operation_id,'draft')
                saved_header=self._original(selector.counter_operation_id,'header')
                if draft is None or saved_header is None:
                    raise AuthorityUnavailable('counter actual Core frame/prepared CPU original missing')
                header=d13_core_counter_from_wire_v1(saved_header,D13CoreFrameIntentHeaderV7)
                raw,compressed=self._require_selector(selector,draft,header)
                prepare_selector=d13_core_counter_from_wire_v1(draft['selector'],D13CurrentFramePrepareSelectorV7)
                prepared=self._read_prepared(draft)
                if header!=self._header(draft,prepared):
                    raise AuthorityUnavailable('counter prepared CPU changed the original frame header')
                inspection=self.internal_work.inspect(prepared.binding)
                if inspection.claim is None:
                    with self._current_source(prepare_selector,draft,read_credential=read_credential,subject=subject,
                            operation_id=self._claim_read_operation(prepared.binding)) as (current,permit):
                        prepared=self._read_prepared(draft,current=True)
                        self._active_claim=(current,permit,draft,prepared)
                        try:
                            self.internal_work.claim(prepared.binding,before_head=inspection.verified_head)
                        except BaseException:
                            self._active_claim=None
                            raise
                    claimed=None
                    try:
                        inspection=self.internal_work.inspect(prepared.binding)
                        claimed=self._claims.issue(binding=prepared.binding,claim=inspection.claim,
                            input_bytes=draft['input_json'].encode('utf-8'),expires_at_utc=draft['expires_at_utc'],
                            installation_id=self.policy.installation.installation_id,authority_namespace=self.bridge.namespace)
                        observed=self.worker.run(claimed)
                        terminal=self._terminal(prepared.binding,inspection.claim,observed,claimed)
                        if terminal.status=='completed':
                            self._require_kernel_result(draft,json.loads(terminal.output_json)['measurement'])
                        self.internal_work.terminal(prepared.binding,inspection.claim,terminal,
                            before_head=self.bridge.journal.verified_head())
                        inspection=self.internal_work.inspect(prepared.binding)
                        self.worker.release_group(observed,claimed)
                    finally:
                        if claimed is not None:self._claims.retire(claimed)
                        self._active_claim=None
                    return self._awaiting(draft,inspection)
                if inspection.terminal is None:
                    return self._awaiting(draft,inspection)
                if not self.internal_work.verify_installed_terminal(prepared.binding,inspection.claim,inspection.terminal):
                    raise AuthorityUnavailable('counter durable terminal has no actual installed measurement signature')
                accounting=self._read_accounting(draft,prepared,inspection)
                if accounting is None:
                    return self._awaiting(draft,inspection)
                if inspection.terminal.status!='completed':
                    raise AuthorityUnavailable('counter failed execution was charged but yields no count evidence')
                with self._current_source(prepare_selector,draft,read_credential=read_credential,subject=subject) as (current,permit):
                    accounting=self._read_accounting(draft,prepared,inspection)
                    if accounting is None:
                        raise AuthorityUnavailable('counter accounting originals disappeared before signature')
                    terminal=inspection.terminal
                    output=json.loads(terminal.output_json)
                    measurement=output['measurement']
                    if (canonical_digest(measurement)!=terminal.result_digest
                            or output['input_digest']!='sha256:'+prepared.binding.input_digest
                            or terminal.actual_cpu_ms!=(measurement['actual_cpu_ns']+999999)//1000000):
                        raise AuthorityUnavailable('counter actual CPU/result differs from signed terminal original')
                    result=self._require_kernel_result(draft,measurement)
                    cpu,body,settlement_digest=accounting
                    payload=D13CoreFullWireEvidenceV1(frame=header,selector_digest=selector.selector_digest,
                        raw_authority_digest=raw.frozen_input_digest,
                        compressed_authority_digest=None if compressed is None else compressed.frozen_input_digest,
                        raw_request_digest=raw.model_request_digest,
                        compressed_request_digest=None if compressed is None else compressed.model_request_digest,
                        **{name:result[name] for name in ('raw_http_template_digest','compressed_http_template_digest',
                            'raw_http_bytes','compressed_http_bytes','token_evidence','raw_lower_tokens','raw_upper_tokens',
                            'compressed_lower_tokens','compressed_upper_tokens')},
                        **{name:getattr(self.policy,name) for name in ('counter_policy_fingerprint','tokenizer_fingerprint',
                            'wire_policy_fingerprint','serializer_fingerprint','applicability_fingerprint')},
                        cpu_execution_id=prepared.binding.execution_id,cpu_worker_binding_digest=prepared.binding.binding_digest,
                        cpu_claim_digest=canonical_digest(inspection.claim),cpu_input_digest=prepared.binding.input_digest,
                        cpu_terminal_digest=terminal.terminal_digest,actual_cpu_ns=measurement['actual_cpu_ns'],
                        cpu_settlement_ref=body.settlement_ref,cpu_settlement_digest=settlement_digest,
                        d02_accounting_digest=canonical_digest(body),d11_accounting_digest=canonical_digest(cpu))
                    signature=self._key.sign(SIGNING_DOMAIN+canonical_serialize(asdict(payload)).encode('utf-8'))
                    envelope=D13CoreFullWireEnvelopeV1(payload,self.policy.counter_key_id,base64.b64encode(signature).decode('ascii'))
                    self._record(selector.counter_operation_id,'evidence',asdict(envelope),source=current)
                    return envelope

    def _read_accounting(self,draft,prepared,inspection):
        from ..runtime.d13_counter_cpu_accounting_v1 import (
            read_d13_counter_cpu_cost_original_v1, read_d13_counter_body_cost_original_v1)
        from ..runtime.jobs import get_job
        from ..runtime.d11_types import job_graph_write
        from ..runtime.c04_product_lifecycle_v3 import c04_terminal_proof_from_inspection_v3
        proof=c04_terminal_proof_from_inspection_v3(inspection)
        if proof is None:
            raise AuthorityUnavailable('counter actual same-chain terminal proof is incomplete')
        verified=self.internal_work.verify_original_internal_work_terminal(proof)
        operation=draft['selector']['counter_operation_id']
        with self._graph_db(operation_id=draft['selector']['counter_operation_id'],
                deadline_utc=draft['expires_at_utc']) as db:
            cpu=read_d13_counter_cpu_cost_original_v1(db,self.namespace,operation)
            body=read_d13_counter_body_cost_original_v1(db,self.namespace,operation)
            if cpu is None or body is None:
                return None
            b=prepared.binding
            if (cpu.binding_digest!=b.binding_digest or body.binding_digest!=b.binding_digest
                    or cpu.prepared_digest!=prepared.prepared_digest or cpu.proof_digest!=canonical_digest(proof)
                    or body.proof_digest!=canonical_digest(proof) or cpu.actual_cpu_ms!=inspection.terminal.actual_cpu_ms
                    or cpu.terminal_receipt_digest!=verified.terminal_receipt_digest
                    or cpu.budget_lease_id!=b.parent_budget_lease_ref
                    or cpu.budget_reservation_digest!=prepared.budget_reservation_digest
                    or cpu.budget_operation_id!=prepared.budget_reservation_operation_id
                    or cpu.status!=inspection.terminal.status or cpu.component_completed!=(inspection.terminal.status=='completed')
                    or cpu.budget_receipt_status!='settled'):
                raise AuthorityUnavailable('counter actual terminal and D02/D11 cost originals differ')
            reservation=db.execute('SELECT state FROM runtime_budget_reservations WHERE lease_id=? AND operation_id=?',
                (b.parent_budget_lease_ref,prepared.budget_reservation_operation_id)).fetchone()
            settlement=read_graph_head_v3(db,body.settlement_ref)
            job=get_job(db,draft['job_id'])
            job_write=job_graph_write(job)
            job_atom=read_graph_head_v3(db,job_write.key.token,columns=('value','valid'))
            if (reservation!=('settled',) or settlement is None or settlement[2]!=1
                    or job.phase!=inspection.terminal.status or job_atom is None or job_atom[1]!=1
                    or json.loads(job_atom[0])!=job_write.value):
                raise AuthorityUnavailable('counter actual resource settlement or terminal job missing')
            return cpu,body,canonical_digest({'ref':body.settlement_ref,'revision':settlement[0],'value':json.loads(settlement[1])})


    def _require_recorded_execution_origin(self,binding,claim,input_digest,installation_id,authority_namespace):
        """Historical measurement authentication only; never new execution or admission."""
        if self._active_claim is None:
            raise AuthorityUnavailable('counter measured cost is outside its actual installed capsule interval')
        current,permit,draft,prepared=self._active_claim
        if (binding!=prepared.binding or input_digest!=binding.input_digest or input_digest!=draft['input_digest']
                or sha256(draft['input_json'].encode('utf-8')).hexdigest()!=input_digest
                or installation_id!=self.policy.installation.installation_id
                or authority_namespace!=self.bridge.namespace or binding.namespace!=authority_namespace
                or draft['selector']['install_id']!=installation_id
                or draft['selector']['authority_namespace']!=authority_namespace):
            raise AuthorityUnavailable('counter historical observation crossed actual installation, binding or input')
        inspection=self.internal_work.inspect(binding)
        if inspection.claim!=claim or inspection.claim_append is None:
            raise AuthorityUnavailable('counter historical measurement has no actual same-chain committed claim')
        if inspection.terminal is not None and not self.internal_work.verify_installed_terminal(binding,claim,inspection.terminal):
            raise AuthorityUnavailable('counter historical measurement terminal authentication differs')


    @staticmethod
    def _claim_read_operation(binding):
        return 'd13-counter-claim-read:'+binding.binding_digest[:48]

    def _reconcile_original(self,binding,phase):
        """Recover one journal-first append and consume its actual original read gate."""
        if binding.algorithm_ref!=_ALGORITHM or binding.namespace!=self.bridge.namespace or phase not in {'claim','terminal'}:
            raise AuthorityUnavailable('counter original reconciliation crossed installed execution identity')
        self.core._require(self.execute_credential,'execution',self.bridge.namespace)
        with self.bridge.deletion.freeze_writes(),self.bridge.journal.freeze_writes():
            inspection=self.bridge.journal.read_internal_work_v1(binding)
            append=inspection.claim_append if phase=='claim' else inspection.terminal_append
            if append is None or inspection.claim_append is None:
                raise AuthorityUnavailable('counter claimed original has no durable same-chain append')
            predecessor=self.bridge.journal.verified_predecessor_head(inspection.claim_append.sequence)
            with self.core._tx() as db:
                self.bridge._require_v2_mode_locked(db)
                row=self.bridge.fences._row(db,self._claim_read_operation(binding))
                if row is None or row[10] is not None:
                    raise AuthorityUnavailable('counter original claim read gate missing or pending')
                permit=self.bridge.fences._permit(row)
                if (permit.operation!='read' or permit.namespace!=binding.namespace
                        or permit.subject!=self.source.self_identity._read_subject
                        or permit.pinned_anchor.execution_journal_id!=predecessor.journal_id
                        or permit.pinned_anchor.execution_seq!=predecessor.seq
                        or permit.pinned_anchor.execution_digest!=predecessor.digest):
                    raise AuthorityUnavailable('counter durable claim did not consume its exact independent read gate')
                self.bridge.fences.finish_fence_locked(db,permit,subject=permit.subject,current_anchor=permit.pinned_anchor,
                    request_id=permit.operation_id+':claim-consumed',
                    request_digest='sha256:'+canonical_digest((binding.binding_digest,inspection.claim.mutation_id)))
                namespace_row=self.core._row(db,self.bridge.namespace)
                head=self.core._head(namespace_row,'execution')
                target=JournalHead(append.journal_id,append.sequence,append.chain_digest)
                if head==inspection.verified_head and head.seq>=target.seq:
                    return
                before=self.bridge.journal.verified_predecessor_head(append.sequence)
                if head!=before or inspection.verified_head!=target:
                    raise AuthorityUnavailable('counter original append cannot skip another unresolved execution')
                db.execute('UPDATE authority_namespaces SET execution_seq=?,execution_digest=?,anchor_nonce=? WHERE namespace=?',
                    (target.seq,target.digest,self.core._new_nonce(),self.bridge.namespace))
                self.core._event(db,self.bridge.namespace,'internal_work_'+phase,namespace_row[1],
                    (binding.binding_digest,append.mutation_id,append.content_digest,target.digest))
