"""Real Life acquisition/current SQL qualification, not model admission.

The donor authenticates real Owner/Core/C09/Graph originals and produces the
Life occurrence and content acquisition. The model-intent fence fields below
are synthetic locators, deliberately never submitted to Authority admission.
This test does not claim the Owner-held job is an installed mTLS worker or
that the content terminal, paid model result or content adoption is complete.
"""
import asyncio
import json
import sqlite3
from dataclasses import replace
from pathlib import Path

import pytest

from test_installed_internal_life_content_v1 import installed_d04_root, run_installed_life_content_preparation_case
from sylanne3.authority_service.internal_life_model_graph_v1 import InstalledInternalLifeModelGraphReaderV1
from sylanne3.authority_service.d12_owner_storage_admission_v1 import InstalledD12OwnerStorageAdmissionServiceV1
from sylanne3.authority_service.v2_scoped_erasure_store import AuthorityV2ScopedErasureStore
from sylanne3.authority_service.v2_deletion_recovery_service import AuthorityV2DeletionPendingRecovery
from sylanne3.authority_service.c09_close_apply_v1 import InstalledC09CloseApplyV1
from sylanne3.authority_service.c09_graph_application_v1 import InstalledC09GraphApplicationV1
from sylanne3.authority_service.v2_model_egress_contract import ModelEgressIntentV1
from sylanne3.runtime.d06_structured_experience_v1 import InstalledD06StructuredExperienceReadersV1
from sylanne3.runtime.internal_life_content_worker_v1 import read_committed_internal_life_request_v1
from sylanne3.runtime.internal_life_content_preparation_v1 import TABLE
from sylanne3.runtime_contracts import canonical_digest


@pytest.mark.asyncio
async def test_installed_life_acquisition_current_original_reader_refuses_drift(tmp_path, installed_d04_root):
    async def after(case):
        def read_current():
            graph, store, core, server = (case[k] for k in ('graph','store','core','server'))
            ns, authority_namespace = case['namespace'], case['authority_namespace']
            fences = server._v2_fences[authority_namespace]
            control = graph._actual_d04_authority_acceptance_v3.storage_control
            path = Path(store._db.execute('PRAGMA database_list').fetchone()[2]).resolve()
            context = control.read_verified_current_storage_v1(); context.require_current('business')
            assert context.stage == 'READY'
            close = control._applied_reader
            assert type(close) is InstalledC09CloseApplyV1 and close.control is control
            assert close.graph_application.coordinator is graph and close.graph_application.core is core
            owner = InstalledD12OwnerStorageAdmissionServiceV1(fences=fences,
                owner_tickets=server._v2_owner_tickets, graph_db_path=path, namespace_id=ns,
                installation_id=case['policy'].installation_id, holder=case['policy'].administrator_holder,
                control=control, close_apply=close)
            issuer = case['d11_issuer']
            readers = InstalledD06StructuredExperienceReadersV1(issuer=issuer,
                resource_issuer=issuer.resource_issuer, body_quote_authority=graph._GraphCoordinator__body_quote_authority)
            workflows = graph._GraphCoordinator__d04_installed_joint_assembly.admin_bundle.model_workflows
            verifier = InstalledInternalLifeModelGraphReaderV1(owner_storage=owner, structured_readers=readers, workflows=workflows)
            with sqlite3.connect(path.as_uri()+'?mode=ro', uri=True) as db:
                db.execute('PRAGMA query_only=ON'); db.execute('BEGIN')
                ids = db.execute(f"SELECT original_ref FROM {TABLE} WHERE kind='request'").fetchall()
                assert len(ids) == 1
                prepared, request = read_committed_internal_life_request_v1(db, namespace=ns, issuer=issuer, job_id=ids[0][0])
                metadata, epoch = graph._v2_graph_stamp(ns)
                quote = issuer.resource_issuer.original_signed_quote(db, prepared.quote_id, prepared.quote_version)
                with fences._frozen() as (core_db, deletion, execution, _):
                    anchor = fences._current_locked(core_db, deletion, execution)
                sources = tuple(sorted((v.key.owner.subject,v.revision) for v in request.envelope.version_guard.read_versions
                    if v.key.type_name == 'memory.source' and v.revision > 0))
                accesses = tuple(sorted((v.key.owner.subject,v.revision) for v in request.envelope.version_guard.read_versions
                    if v.key.type_name == 'memory.access' and v.revision > 0))
                intent = ModelEgressIntentV1(anchor.authority_id, anchor.namespace, request.envelope.authority.actor,
                    prepared.acquire_operation_id, prepared.call_id, request.digest, prepared.job_id, 1,
                    'a'*48, 1, 0, canonical_digest(anchor), tuple(ref for ref,_ in sources), sources, accesses,
                    request.envelope.version_guard.access_epoch, request.envelope.version_guard.delete_epoch,
                    epoch.revision, metadata.graph_revision, anchor.activation_generation, anchor.revocation_epoch,
                    anchor.deletion_seq, anchor.execution_seq, quote.parent_budget_lease_ref, prepared.prepare_operation_id,
                    prepared.reservation_digest, tuple(sorted(quote.ceiling.items())), request.provider_id, request.model_id,
                    workflows.life_content.provider_config_digest, request.max_output_tokens,
                    acquire_operation_id=prepared.acquire_operation_id, binding_digest=prepared.digest)
                import time
                actual = verifier.read(db, intent, time.time())
                assert actual.prepared == prepared and actual.request == request and actual.job.phase == 'running'
                assert actual.frozen.input.cause.execution_before_state_status == 'evidence_unavailable'
                assert db.total_changes == 0
                for changed, reason in ((replace(intent, binding_digest='b'*64), 'input identity'),
                        (replace(intent, authority_activation_generation=2), 'Owner/actor/generation'),
                        (replace(intent, subject='different-worker'), 'input identity')):
                    with pytest.raises(ValueError, match=reason): verifier.read(db, changed, time.time())
                with pytest.raises(ValueError, match='expired'):
                    verifier.read(db, intent, actual.frozen.input.expires_at_utc + 1)
            # These are explicitly synthetic SQL tamper tests, not an Owner
            # withdrawal command. Every mutation is rolled back byte-exactly.
            with store._lock:
                before = store._db.total_changes
                store._db.execute('BEGIN'); store._db.execute('SAVEPOINT life_reader_tamper')
                try:
                    source_token = next(v.key.token for v in request.envelope.version_guard.read_versions
                        if v.key.type_name == 'memory.access' and v.revision > 0)
                    old = store._db.execute('SELECT value FROM graph_atoms WHERE token=?',(source_token,)).fetchone()[0]
                    payload = json.loads(old); payload['status']='withdrawn'
                    from sylanne3.runtime_contracts import canonical_serialize
                    store._db.execute('UPDATE graph_atoms SET value=? WHERE token=?',(canonical_serialize(payload),source_token))
                    with pytest.raises(ValueError, match='current|changed|permission'):
                        verifier.read(store._db, intent, time.time())
                finally:
                    store._db.execute('ROLLBACK TO life_reader_tamper'); store._db.rollback()
                assert store._db.execute('SELECT value FROM graph_atoms WHERE token=?',(source_token,)).fetchone()==(old,)
        await asyncio.to_thread(read_current)
    await run_installed_life_content_preparation_case(tmp_path,installed_d04_root,acquire=True,after_acquire=after)
