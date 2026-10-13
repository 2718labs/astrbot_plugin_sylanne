"""Real TLS model identity RPCs remain passive, bound to one installation."""

import asyncio
from dataclasses import asdict, replace
import hashlib
import ssl
from types import MethodType

import pytest

from rewrite.host_tests.alpha1 import test_authority_mtls_loopback as loopback
from rewrite.host_tests.alpha1 import test_astrbot_model_call as model_fixture
from rewrite.tests.alpha1.authority.test_v2_model_egress_store import intent
from rewrite.tests.alpha1.model_broker.test_broker import request as broker_request
from sylanne3.authority_service import AuthorityServiceCore, JournalHead
from sylanne3.authority_service.current_model_egress_graph_verifier import PinnedCurrentModelEgressGraphVerifier
from sylanne3.authority_service.mtls_server import (
    AdministratorInstallationV2, AuthorityRpcServer, AuthorityServerTlsConfig,
    MtlsPeerCredential,
)
from sylanne3.authority_service.v2_contract import SCHEMA as AUTHORITY_V2_PROTOCOL
from sylanne3.authority_service.v2_contract import to_wire as fence_to_wire
from sylanne3.authority_service.v2_deletion_guard import AuthorityV2DeletionGuard
from sylanne3.authority_service.v2_execution_journal import AuthorityV2ExecutionJournal
from sylanne3.authority_service.v2_fence_service import AuthorityV2FenceService
from sylanne3.authority_service.v2_fence_store import AuthorityV2FenceStore
from sylanne3.authority_service.v2_model_egress_contract import ModelEgressDraftV1, ModelEgressIntentV1
from sylanne3.authority_service.v2_model_egress_service import AuthorityV2ModelEgressService
from sylanne3.authority_service.v2_model_egress_store import AuthorityV2ModelEgressStore
from sylanne3.authority_service.v2_model_egress_wire import to_wire as model_to_wire
from sylanne3.host.authority_client import (
    AUTHORITY_PROTOCOL, AuthorityClient, AuthorityProvisioningRequest,
    AuthoritySelection, PublisherPackageIdentity,
)
from sylanne3.host.authority_profile import (
    AdminIngressModelPolicy, installed_model_config_ref,
)
from sylanne3.host.astrbot_model_call import AstrBotModelProvider
from sylanne3.host.model_egress_executor import HostModelEgressExecutor
from sylanne3.host.mtls_transport import AuthorityTlsProfile, MtlsAuthorityTransport
from sylanne3.runtime.deletion import DeletionJournal
from sylanne3.runtime_contracts import NamespaceId


@pytest.mark.asyncio
@pytest.mark.parametrize('uncertain_mode', ('unknown', 'cancel', 'prepare_ack_loss', 'admit_ack_loss', 'pre_rpc_failure', 'core_capacity', 'core_capacity_tail'))
async def test_q05_registry_retirement_uses_real_authority_facts(tmp_path, monkeypatch, uncertain_mode):
    """Software fixture: real Core/mTLS originals, graph stub and local provider.

    This is not installed Host, semantic-model, numeric, or paid-call acceptance.
    """
    import json
    import sys
    from pathlib import Path
    import rewrite.tests.alpha1.runtime.test_authority_v2_rpc_content_fences as rpc_fixture
    from sylanne3.host import astrbot_model_call as registry
    from sylanne3.host.model_egress_executor import _retire_observed_local_model_v1
    from sylanne3.authority_service.v2_model_egress_contract import HostObservedModelCompletionV2
    from sylanne3.model_broker.broker import ProviderResponse
    from sylanne3.runtime_contracts import canonical_serialize

    monkeypatch.setattr(registry, '_calls', {})
    monkeypatch.setattr(registry, '_admissions', {})
    files = loopback.AuthorityMtlsLoopbackTests._certificates(tmp_path)
    peer = MtlsPeerCredential(hashlib.sha256(ssl.PEM_cert_to_DER_cert(
        files['client.pem'].read_text('ascii'))).hexdigest())
    monkeypatch.setattr(rpc_fixture, '_PEER_A', peer)
    source = rpc_fixture.rpc.__wrapped__(tmp_path)
    server = next(source)
    host = model_fixture.AstrBotModelCallTests(methodName='test_one_http_request_on_host_loop_with_usage')
    await host.asyncSetUp()
    transport = None
    try:
        manifest = tmp_path / 'release-manifest.json'
        manifest.write_text('{"software_fixture":true}', encoding='utf-8')
        manifest_sha = hashlib.sha256(manifest.read_bytes()).hexdigest()
        key = (peer.certificate_sha256, 'profile-a')
        server._installations_v2[key] = replace(server._installations_v2[key], manifest_digest=manifest_sha)
        fences = server._v2_fences['ns-a']
        # This test deliberately has no business Graph. Its exact synthetic
        # legacy originals are the only inputs accepted by the software stub.
        assert type(host.admin_model) is AdminIngressModelPolicy
        software_drafts = {}

        def require_software_original(candidate):
            assert type(candidate) in {ModelEgressDraftV1, ModelEgressIntentV1}
            draft = (candidate if type(candidate) is ModelEgressDraftV1
                     else ModelEgressDraftV1.from_intent(candidate))
            assert software_drafts.get(draft.call_id) == draft
            assert draft.job_id == 'q05-job-' + draft.call_id.removeprefix('q05-')
            assert draft.binding_digest is None and draft.acquire_operation_id is None

        def software_reply_scope(candidate):
            require_software_original(candidate)
            return None

        def software_graph_current(candidate, *, model_service, credential, subject, permit):
            require_software_original(candidate)
            assert model_service is model and credential == peer
            assert subject == candidate.subject and permit.operation_id == candidate.operation_id
            return True

        verifier = object.__new__(PinnedCurrentModelEgressGraphVerifier)
        monkeypatch.setattr(verifier, 'observe_current_reply_scope_for_model_v1', software_reply_scope)
        monkeypatch.setattr(verifier, 'complete_graph_current', software_graph_current)
        model = AuthorityV2ModelEgressService(
            AuthorityV2ModelEgressStore(fences.core._db, create=True, lock=fences.core._lock),
            fences, graph_verifier=verifier, admin_model_policy=host.admin_model)
        server._v2_model_egress['ns-a'] = model
        server._model_observers_v2['ns-a'] = (peer.certificate_sha256, 'profile-a')
        listener = await server.start('127.0.0.1', 0, AuthorityServerTlsConfig(
            str(files['server.pem']), str(files['server.key']), str(files['ca.pem']), timeout_seconds=2))
        profile = AuthorityTlsProfile('profile-a', '127.0.0.1', listener.sockets[0].getsockname()[1],
            'localhost', server._authority_id(), files['ca.pem'], files['client.pem'], files['client.key'], timeout_seconds=2)
        transport = MtlsAuthorityTransport({'profile-a': profile})
        client = AuthorityClient(AuthoritySelection('profile-a'), package_root=tmp_path, data_dir=tmp_path, transport=transport)
        assert (await client.status_v2()).state == 'paired'
        grant = await client.installation_grant_v2()
        namespace = NamespaceId('bot-a', 'persona-a')
        policy = replace(host.bundle.installation_policy, namespace=namespace, authority_namespace='ns-a',
            expected_authority_id=grant.authority_id, installation_id=grant.installation_id,
            manifest_digest=manifest_sha, administrator_holder=grant.administrator_holder,
            root_lease=replace(host.bundle.installation_policy.root_lease, bot_id='bot-a', persona_id='persona-a'),
            root_grant=replace(host.bundle.installation_policy.root_grant, bot_id='bot-a', persona_id='persona-a'))
        bundle = replace(host.bundle, installation_policy=policy, tls_profile=profile)
        adapter = AstrBotModelProvider(context=host.context, host_loop=asyncio.get_running_loop(),
            trusted_umo=model_fixture.UMO, descriptor=host.descriptor, admin_model=host.admin_model, installation_bundle=bundle)
        executor = HostModelEgressExecutor(authority=client, bundle=bundle, grant=grant, adapter=adapter)
        local = {'mode': 'completed', 'sends': 0}
        started = asyncio.Event()
        handles = {}
        issue = adapter._issue_start_from_executor_v1

        def capture(executor):
            handle = issue(executor)
            handles[handle.call_id] = handle
            return handle

        async def provider(self, request):
            local['sends'] += 1
            started.set()
            if local['mode'] == 'cancel':
                await asyncio.Event().wait()
            if local['mode'] == 'unknown':
                return ProviderResponse('unknown', None, {}, {}, None)
            return ProviderResponse('completed', {'text': 'isolated response'}, {'output_tokens': 1}, {}, 'fixture-provider')

        monkeypatch.setattr(adapter, '_issue_start_from_executor_v1', capture)
        monkeypatch.setattr(adapter, '_invoke_on_host', MethodType(provider, adapter))

        async def material(label):
            anchor = await transport.v2_current_anchor(client._v2_request, client._v2_handshake, 'ns-a')
            base = model_fixture.call_request()
            call = replace(base, call_id='q05-' + label, envelope=replace(base.envelope,
                identity=replace(base.identity, operation_id='q05-operation-' + label),
                authority=replace(base.envelope.authority, namespace=namespace, actor=grant.subject,
                    issuer_domain='d11', worker_fence=7),
                version_guard=replace(base.envelope.version_guard, read_versions=(), query_epochs=())))
            draft = ModelEgressDraftV1.from_intent(intent(authority_id=grant.authority_id, namespace='ns-a',
                subject=grant.subject, operation_id=call.identity.operation_id, call_id=call.call_id,
                job_id='q05-job-' + label, request_digest=call.digest,
                provider_config_digest=host.admin_model.provider_config_digest, max_output_tokens=64,
                budget_ceiling=(('output_tokens', 128),), authority_activation_generation=anchor.activation_generation,
                authority_revocation_epoch=anchor.revocation_epoch, authority_deletion_seq=anchor.deletion_seq,
                authority_execution_seq=anchor.execution_seq))
            assert call.identity.phase == 'propose'
            software_drafts[draft.call_id] = draft
            return draft, anchor, call

        async def prepare(label):
            draft, anchor, call = await material(label)
            record, _ = await executor.prepare_once(draft=draft, expected_anchor=anchor, request=call)
            return record.intent, anchor, call

        actual_prepare = client.model_prepare_fenced_v1
        prepares = []

        async def count_prepare(*args, **kwargs):
            prepares.append(kwargs['draft'].call_id)
            return await actual_prepare(*args, **kwargs)

        monkeypatch.setattr(client, 'model_prepare_fenced_v1', count_prepare)
        actual_complete = client.model_complete_observed_v2

        async def lost_ack(*args, **kwargs):
            await actual_complete(*args, **kwargs)
            raise TimeoutError('actual Core persisted; ACK deliberately lost')

        if uncertain_mode == 'pre_rpc_failure':
            # Actual installed-client identity check fails before its transport
            # call. Core has no model original/admission and the reservation frees.
            actual_build_request = client._build_request
            monkeypatch.setattr(client, '_build_request',
                lambda: replace(client._v2_request, profile_id='changed-local-profile'))
            with pytest.raises(RuntimeError, match='installation binding'):
                await prepare('local-binding-failure')
            assert not registry._calls and not registry._admissions and local['sends'] == 0 and not handles
            with model._store._lock:
                assert model._store._db.execute(
                    'SELECT count(*) FROM authority_model_egress_v1 WHERE call_id=?',
                    ('q05-local-binding-failure',)).fetchone()[0] == 0
                assert model._store._db.execute(
                    'SELECT count(*) FROM authority_model_admissions_v2 WHERE call_id=?',
                    ('q05-local-binding-failure',)).fetchone()[0] == 0
            monkeypatch.setattr(client, '_build_request', actual_build_request)

            # The real transport's channel check also runs before writer.write.
            # Remove the existing session only after the helper's anchor read.
            actual_context = client._model_installation_context
            removed = []
            async def missing_channel(*args, **kwargs):
                installed = await actual_context(*args, **kwargs)
                removed.append(transport._sessions.pop(profile.profile_id))
                return installed
            monkeypatch.setattr(client, '_model_installation_context', missing_channel)
            try:
                with pytest.raises(RuntimeError, match='handshake channel'):
                    await prepare('local-channel-failure')
            finally:
                monkeypatch.setattr(client, '_model_installation_context', actual_context)
                if removed:
                    transport._sessions[profile.profile_id] = removed[0]
            assert not registry._calls and not registry._admissions and local['sends'] == 0 and not handles
            with model._store._lock:
                assert model._store._db.execute(
                    'SELECT count(*) FROM authority_model_egress_v1 WHERE call_id=?',
                    ('q05-local-channel-failure',)).fetchone()[0] == 0
                assert model._store._db.execute(
                    'SELECT count(*) FROM authority_model_admissions_v2 WHERE call_id=?',
                    ('q05-local-channel-failure',)).fetchone()[0] == 0

            original, anchor, call = await prepare('after-local-failures')
            # A local admit failure must retain the earlier real prepared fact,
            # restore prepare_sent, and permit only that exact first admission.
            monkeypatch.setattr(client, '_build_request',
                lambda: replace(client._v2_request, profile_id='changed-local-profile'))
            assert await executor.execute_once(intent=original, expected_anchor=anchor, request=call) is None
            assert registry._calls[call.call_id].stage == 'prepare_sent'
            with model._store._lock:
                assert model._store._db.execute(
                    'SELECT state FROM authority_model_egress_v1 WHERE call_id=?',
                    (call.call_id,)).fetchone()[0] == 'prepared'
                assert model._store._db.execute(
                    'SELECT count(*) FROM authority_model_admissions_v2 WHERE call_id=?',
                    (call.call_id,)).fetchone()[0] == 0
            assert local['sends'] == 0 and not handles
            monkeypatch.setattr(client, '_build_request', actual_build_request)
            assert await executor.execute_once(intent=original, expected_anchor=anchor, request=call) is not None
            assert local['sends'] == 1 and not registry._calls and not registry._admissions
            return

        if uncertain_mode in {'core_capacity', 'core_capacity_tail'}:
            # Actual Core rejects a distinct original even in a fresh process
            # with an empty local registry. Qualifier remains the exact software
            # Graph stub; this does not qualify an installed Host or C09 move.
            from sylanne3.authority_service.contract import AuthorityUnavailable
            failures = []
            actual_service_prepare = model.prepare_fenced
            def observed_service_prepare(**kwargs):
                try:
                    return actual_service_prepare(**kwargs)
                except AuthorityUnavailable as error:
                    failures.append((kwargs['draft'].call_id, str(error)))
                    raise
            monkeypatch.setattr(model, 'prepare_fenced', observed_service_prepare)
            async def fresh_process_probe(label):
                other, current, _ = await material(label)
                packet = {'draft': model_to_wire(other), 'anchor': asdict(current),
                    'profile': profile.profile_id, 'port': listener.sockets[0].getsockname()[1],
                    'authority': grant.authority_id, 'root': str(tmp_path),
                    'certs': {name: str(files[name]) for name in ('ca.pem', 'client.pem', 'client.key')}}
                packet_path = tmp_path / (label + '.json')
                packet_path.write_text(json.dumps(packet), encoding='utf-8')
                child = """import asyncio,json,sys
from pathlib import Path
sys.path[:0]=json.loads(sys.argv[1]); p=json.loads(Path(sys.argv[2]).read_text())
from sylanne3.host.authority_client import AuthorityClient,AuthoritySelection
from sylanne3.host.mtls_transport import AuthorityTlsProfile,MtlsAuthorityTransport
from sylanne3.authority_service.v2_model_egress_wire import from_wire
from sylanne3.authority_service.v2_model_egress_contract import ModelEgressDraftV1
from sylanne3.runtime.restore_anchor import RestoreAnchor
from sylanne3.host import astrbot_model_call as registry
async def run():
 assert not registry._calls and not registry._admissions
 profile=AuthorityTlsProfile(p['profile'],'127.0.0.1',p['port'],'localhost',p['authority'],*[Path(p['certs'][n]) for n in ('ca.pem','client.pem','client.key')],timeout_seconds=2)
 transport=MtlsAuthorityTransport({p['profile']:profile}); client=AuthorityClient(AuthoritySelection(p['profile']),package_root=Path(p['root']),data_dir=Path(p['root']),transport=transport)
 try:
  assert (await client.status_v2()).state=='paired'; grant=await client.installation_grant_v2()
  request,handshake=client._v2_request,client._v2_handshake; anchor=RestoreAnchor(**p['anchor'])
  census=await transport.model_capacity_reconcile_v1(request,handshake,grant,namespace='ns-a',holder=grant.administrator_holder,expected_anchor=anchor)
  assert census['global_count']==1 and not census['capacity_available']
  try:
   await transport.model_prepare_fenced_v1(request,handshake,grant,namespace='ns-a',holder=grant.administrator_holder,draft=from_wire(p['draft'],ModelEgressDraftV1),expected_anchor=anchor)
  except RuntimeError: pass
  else: raise AssertionError('fresh Host bypassed Core global capacity')
  assert not registry._calls and not registry._admissions
  print('fresh-process-core-capacity-denied')
 finally: await transport.close()
asyncio.run(run())"""
                compile(child, 'q05-core-fresh-process', 'exec')
                process = await asyncio.create_subprocess_exec(sys.executable, '-B', '-c', child,
                    json.dumps(sys.path), str(packet_path), stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
                try:
                    out, err = await asyncio.wait_for(process.communicate(), 15)
                except TimeoutError:
                    process.kill(); await process.wait(); raise
                assert process.returncode == 0, err.decode()
                assert out.decode().strip() == 'fresh-process-core-capacity-denied'
                assert failures[-1] == (other.call_id, 'MODEL_CAPACITY_GLOBAL_FULL')
                with model._store._lock:
                    assert model._store._db.execute('SELECT count(*) FROM authority_model_egress_v1 WHERE call_id=?', (other.call_id,)).fetchone()[0] == 0
                return other

            async def reconnect_same_installation():
                # A rejected content RPC retires its channel by contract. Pair
                # a new channel explicitly; no original budget/deadline changes.
                from sylanne3.host.installation_grant_identity import same_installed_grant_identity_v2
                assert (await client.status_v2()).state == 'paired'
                current_grant = await client.installation_grant_v2()
                assert same_installed_grant_identity_v2(grant, current_grant)
                return current_grant, HostModelEgressExecutor(authority=client, bundle=bundle,
                    grant=current_grant, adapter=adapter)
            if uncertain_mode == 'core_capacity':
                original, anchor, call = await prepare('core-prepared')
                assert len(prepares) == 1 and local['sends'] == 0
                initial = await executor.reconcile_capacity_current_v1(expected_anchor=anchor)
                assert initial['global_count'] == initial['namespace_count'] == 1
                assert not initial['capacity_available']

                await fresh_process_probe('cold-blocked-prepared')
                changed = replace(ModelEgressDraftV1.from_intent(original), budget_lease_id='other-lease')
                with pytest.raises(RuntimeError):
                    await executor.reconcile_capacity_current_v1(expected_anchor=anchor, draft=changed, close_prepared=True)
                assert registry._calls[call.call_id].stage == 'prepare_sent' and local['sends'] == 0
                with model._store._lock:
                    assert model._store._db.execute('SELECT count(*) FROM authority_model_admissions_v2').fetchone()[0] == 0
                    assert model._store._db.execute('SELECT count(*) FROM authority_model_egress_observations_v1').fetchone()[0] == 0
                grant, executor = await reconnect_same_installation()
                closed = await executor.reconcile_capacity_current_v1(expected_anchor=anchor,
                    draft=ModelEgressDraftV1.from_intent(original), close_prepared=True)
                assert closed['status'] == 'not_dispatched' and closed['global_count'] == 0
                assert not registry._calls and not registry._admissions and local['sends'] == 0
                # model_terminal_fact_v2 requires an admission; the unadmitted
                # proof is the new exact capacity fact plus the actual old fence.
                with model._store._lock:
                    row = fences.fences._row(model._store._db, original.operation_id)
                    permit = fences.fences._permit(row)
                    assert row[6] == 'finished'
                    assert (row[8], row[9]) == (original.call_id,
                        fences.fences.model_terminal_finish_digest(original, permit, 'not_dispatched'))
                assert await executor.execute_once(intent=original, expected_anchor=anchor, request=call) is None
                assert local['sends'] == 0
                grant, executor = await reconnect_same_installation()
                recovered = await executor.reconcile_capacity_current_v1(expected_anchor=anchor,
                    draft=ModelEgressDraftV1.from_intent(original), close_prepared=True)
                assert recovered['status'] == 'not_dispatched' and not registry._calls
                with model._store._lock:
                    assert fences.fences._row(model._store._db, original.operation_id) == row

                return

            absent, anchor, _ = await material('sealed-never-begun')
            sealed = await executor.reconcile_capacity_current_v1(expected_anchor=anchor,
                draft=absent, close_prepared=True)
            assert sealed['status'] == 'never_begun' and sealed['global_count'] == 0
            with pytest.raises(RuntimeError):
                await client.model_prepare_fenced_v1(bundle, grant, draft=absent, expected_anchor=anchor)
            with model._store._lock:
                assert model._store._db.execute('SELECT count(*) FROM authority_model_egress_v1 WHERE call_id=?', (absent.call_id,)).fetchone()[0] == 0
            assert local['sends'] == 0

            grant, executor = await reconnect_same_installation()

            local['mode'] = 'unknown'
            unknown, anchor, unknown_call = await prepare('core-unknown')
            assert await executor.execute_once(intent=unknown, expected_anchor=anchor, request=unknown_call) is None
            before_entry = registry._calls[unknown_call.call_id]
            unresolved = await executor.reconcile_capacity_current_v1(expected_anchor=anchor,
                draft=ModelEgressDraftV1.from_intent(unknown), close_prepared=True)
            assert unresolved['status'] == 'unresolved' and unresolved['global_count'] == 1
            assert registry._calls[unknown_call.call_id] is before_entry and local['sends'] == 1
            await fresh_process_probe('cold-blocked-unknown')
            assert local['sends'] == 1
            return

        if uncertain_mode == 'prepare_ack_loss':
            async def lost_prepare(*args, **kwargs):
                await count_prepare(*args, **kwargs)
                raise TimeoutError('actual prepare persisted; ACK deliberately lost')
            monkeypatch.setattr(client, 'model_prepare_fenced_v1', lost_prepare)
            with pytest.raises(TimeoutError):
                await prepare(uncertain_mode)
            entry = registry._calls['q05-' + uncertain_mode]
            assert type(entry) is registry._PendingCallIdentity
            assert entry.stage == 'prepare_sent' and entry.admission_id == ''
            assert len(prepares) == 1 and local['sends'] == 0 and not handles
            with pytest.raises(registry.LocalModelCapacityDeniedV1):
                await prepare('blocked-after-prepare-loss')
            assert len(prepares) == 1 and len(registry._calls) == 1
            return

        if uncertain_mode == 'admit_ack_loss':
            original, anchor, call = await prepare(uncertain_mode)
            actual_admit = client.model_admit_dispatch_once_v2
            admits = []
            async def lost_admit(*args, **kwargs):
                admits.append(kwargs['intent'].call_id)
                await actual_admit(*args, **kwargs)
                raise TimeoutError('actual admission persisted; ACK deliberately lost')
            monkeypatch.setattr(client, 'model_admit_dispatch_once_v2', lost_admit)
            assert await executor.execute_once(intent=original, expected_anchor=anchor, request=call) is None
            entry = registry._calls[call.call_id]
            assert type(entry) is registry._PendingCallIdentity and entry.stage == 'admit_sent'
            facts = await client.model_terminal_fact_v2(bundle, grant, intent=original)
            assert facts[0].state == 'dispatch_started' and facts[3] is None
            assert len(admits) == 1 and local['sends'] == 0 and not handles
            replacement = HostModelEgressExecutor(authority=client, bundle=bundle, grant=grant, adapter=adapter)
            assert await replacement.execute_once(intent=original, expected_anchor=anchor, request=call) is None
            assert len(admits) == 1
            with pytest.raises(registry.LocalModelCapacityDeniedV1):
                await prepare('blocked-after-admit-loss')
            assert len(prepares) == 1 and len(registry._calls) == 1
            return

        if uncertain_mode == 'unknown':
            monkeypatch.setattr(client, 'model_complete_observed_v2', lost_ack)
            original, anchor, call = await prepare('ack-loss')
            assert await executor.execute_once(intent=original, expected_anchor=anchor, request=call) is None
            assert type(registry._calls[call.call_id]) is registry._CallEntry
            assert registry._calls[call.call_id].response.result['text'] == 'isolated response'
            prepare_count = len(prepares)
            with pytest.raises(registry.LocalModelCapacityDeniedV1):
                await prepare('blocked-ack-loss')
            assert len(prepares) == prepare_count and local['sends'] == 1
            facts = await client.model_terminal_fact_v2(bundle, grant, intent=original)
            assert facts[0].state == 'observed' and facts[3] is not None
            for field in facts[3].__dataclass_fields__:
                bad = 'wrong-call' if field in {'call_id', 'installation_id'} else ('sha256:' if field == 'finish_digest' else '') + 'f' * 64
                assert not _retire_observed_local_model_v1(executor, intent=original, record=facts[0],
                    permit=facts[1], admission=facts[2], receipt=replace(facts[3], **{field: bad}))
                assert call.call_id in registry._calls and facts[2].admission_id in registry._admissions
            assert await executor.recover_original_terminal(original) == facts[3]
            assert call.call_id not in registry._calls and facts[2].admission_id not in registry._admissions
            assert call.call_id not in adapter._started_calls and local['sends'] == 1
            with pytest.raises(ValueError, match='consumed'):
                await adapter.invoke_admitted(call, handles[call.call_id], asyncio.Event())
            with pytest.raises(ValueError, match='admission'):
                await adapter.invoke_admitted(call, registry.LocalModelAdmission(facts[2].admission_id,
                    adapter.host_incarnation, call.call_id, call.digest, host.admin_model.provider_config_digest), asyncio.Event())

            async def before_persist(*args, **kwargs):
                raise TimeoutError('completion never reached the Authority')

            monkeypatch.setattr(client, 'model_complete_observed_v2', before_persist)
            original, anchor, call = await prepare('unpersisted')
            assert await executor.execute_once(intent=original, expected_anchor=anchor, request=call) is None
            assert registry._calls[call.call_id].response.result['text'] == 'isolated response'
            assert await executor.recover_original_terminal(original) is None
            record, permit, admission, receipt = await client.model_terminal_fact_v2(bundle, grant, intent=original)
            assert record.state == 'dispatch_started' and receipt is None
            response = adapter.terminal_response(call.call_id, call.digest, admission.admission_id)
            report = HostObservedModelCompletionV2(admission.admission_id, admission.host_incarnation,
                call.call_id, call.digest, call.provider_id, call.model_id, admission.provider_config_digest,
                canonical_serialize(dict(response.result)), tuple(sorted(response.usage.items())), (), response.provider_call_ref)
            monkeypatch.setattr(client, 'model_complete_observed_v2', actual_complete)
            await actual_complete(bundle, grant, intent=original, expected_anchor=anchor, admission=admission, report=report)
            assert await executor.recover_original_terminal(original) is not None
            assert call.call_id not in registry._calls and local['sends'] == 2

        mode = uncertain_mode
        local['mode'] = mode
        original, anchor, call = await prepare(mode)
        started.clear()
        pending = asyncio.create_task(executor.execute_once(intent=original, expected_anchor=anchor, request=call))
        await started.wait()
        if mode == 'cancel':
            entry = registry._calls[call.call_id]
            entry.task.cancel()
        assert await pending is None
        entry = registry._calls[call.call_id]
        assert type(entry) is registry._SpentCallIdentity
        assert not hasattr(entry, 'terminal') and not hasattr(entry, 'task') and not hasattr(entry, 'response')
        assert entry.admission_id in registry._admissions and call.call_id in adapter._started_calls
        assert len(registry._calls) == 1
        assert sum(row.capacity.index_bytes for row in registry._calls.values()) <= registry._MODEL_INDEX_BYTES
        prepare_count = len(prepares)
        with pytest.raises(registry.LocalModelCapacityDeniedV1):
            await prepare('blocked-' + mode)
        assert len(prepares) == prepare_count

        # Another real namespace binding cannot bypass the process-global slot.
        foreign_namespace = NamespaceId('bot-foreign', 'persona-foreign')
        foreign_policy = replace(policy, namespace=foreign_namespace, authority_namespace='ns-foreign',
            root_lease=replace(policy.root_lease, bot_id='bot-foreign', persona_id='persona-foreign'),
            root_grant=replace(policy.root_grant, bot_id='bot-foreign', persona_id='persona-foreign'))
        foreign_bundle = replace(bundle, installation_policy=foreign_policy)
        foreign_adapter = AstrBotModelProvider(context=host.context, host_loop=asyncio.get_running_loop(),
            trusted_umo=model_fixture.UMO, descriptor=host.descriptor, admin_model=host.admin_model,
            installation_bundle=foreign_bundle)
        foreign_executor = HostModelEgressExecutor(authority=client, bundle=foreign_bundle, grant=grant,
            adapter=foreign_adapter)
        foreign_call = replace(call, call_id='q05-foreign-' + mode, envelope=replace(call.envelope,
            authority=replace(call.envelope.authority, namespace=foreign_namespace)))
        assert not foreign_adapter._claim_capacity_from_executor_v1(foreign_executor, foreign_call, preparing=True)
        assert len(registry._calls) == 1 and len(prepares) == prepare_count
        before = local['sends']
        assert await executor.execute_once(intent=original, expected_anchor=anchor, request=call) is None
        with pytest.raises(ValueError, match='consumed'):
            await adapter.invoke_admitted(call, handles[call.call_id], asyncio.Event())
        assert local['sends'] == before
        assert await executor.recover_original_terminal(original) is None

        # Fresh process/client, no local registry: the real persisted admission
        # still denies this same original; nothing may start a second provider.
        packet = {'intent': model_to_wire(original), 'request': model_to_wire(call), 'anchor': asdict(anchor),
                  'profile': profile.profile_id, 'port': listener.sockets[0].getsockname()[1],
                  'authority': grant.authority_id, 'root': str(tmp_path), 'manifest': manifest_sha,
                  'certs': {name: str(files[name]) for name in ('ca.pem', 'client.pem', 'client.key')}}
        packet_path = tmp_path / 'restart-call.json'
        packet_path.write_text(json.dumps(packet), encoding='utf-8')
        child = '''import asyncio,json,secrets,sys
from pathlib import Path
sys.path[:0]=json.loads(sys.argv[1]); p=json.loads(Path(sys.argv[2]).read_text())
from sylanne3.host.authority_client import AuthorityClient,AuthoritySelection
from sylanne3.host.mtls_transport import AuthorityTlsProfile,MtlsAuthorityTransport
from sylanne3.authority_service.v2_model_egress_wire import from_wire
from sylanne3.authority_service.v2_model_egress_contract import ModelEgressIntentV1
from sylanne3.model_broker.broker import ModelCallRequest
from sylanne3.runtime.restore_anchor import RestoreAnchor
from sylanne3.runtime_contracts import InstallationGrantV2
async def run():
 profile=AuthorityTlsProfile(p['profile'],'127.0.0.1',p['port'],'localhost',p['authority'],*[Path(p['certs'][n]) for n in ('ca.pem','client.pem','client.key')],timeout_seconds=2)
 transport=MtlsAuthorityTransport({p['profile']:profile}); client=AuthorityClient(AuthoritySelection(p['profile']),package_root=Path(p['root']),data_dir=Path(p['root']),transport=transport)
 assert (await client.status_v2()).state=='paired'; grant=await client.installation_grant_v2()
 request,handshake=client._v2_request,client._v2_handshake
 try:
  await transport.model_admit_dispatch_once_v2(request,handshake,grant,namespace='ns-a',holder=grant.administrator_holder,intent=from_wire(p['intent'],ModelEgressIntentV1),expected_anchor=RestoreAnchor(**p['anchor']),model_request=from_wire(p['request'],ModelCallRequest),host_incarnation=secrets.token_hex(32))
 except RuntimeError:
  print('restart-original-admission-denied')
 else: raise RuntimeError('second admission incorrectly issued')
 finally: await transport.close()
asyncio.run(run())'''
        process = await asyncio.create_subprocess_exec(sys.executable, '-B', '-c', child,
            json.dumps(sys.path), str(packet_path), stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        out, err = await process.communicate()
        assert process.returncode == 0, err.decode()
        assert out.decode().strip() == 'restart-original-admission-denied'
    finally:
        await host.asyncTearDown()
        if transport is not None:
            await transport.close()
        await server.aclose()
        source.close()


@pytest.mark.asyncio
async def test_model_identity_rpc_real_mtls_binding_digest_and_replay(tmp_path, monkeypatch):
    files = loopback.AuthorityMtlsLoopbackTests._certificates(tmp_path)
    manifest_path = tmp_path / "release-manifest.json"
    manifest_path.write_text('{"test":true}', encoding="utf-8")
    manifest_digest = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
    peers = {
        name: MtlsPeerCredential(hashlib.sha256(ssl.PEM_cert_to_DER_cert(
            files[f"{name}.pem"].read_text(encoding="ascii"))).hexdigest())
        for name in ("client", "second")
    }
    deletion = DeletionJournal(tmp_path / "deletion.db", create=True)
    deletion_guard = AuthorityV2DeletionGuard(tmp_path / "deletion.db")
    execution = AuthorityV2ExecutionJournal(
        tmp_path / "execution.db", namespace="ns:role", journal_id="execution", create=True)
    head = deletion.latest_head()
    deletion_head = JournalHead(head.journal_id, head.seq, head.chain_digest)

    def authorize(peer, action, namespace, holder):
        return (peer in peers.values() and namespace == "ns:role"
                and action in {"install", "seal_v2_only", "current", "model_egress"}
                and (holder is None or holder == "host:one"))

    core = AuthorityServiceCore(
        tmp_path / "authority.db", authorizer=authorize,
        deletion_verifier=lambda ns, before, current, phase:
            current == deletion_head and phase == "clear",
        execution_verifier=lambda ns, before, current, phase:
            execution.verified_head() == current,
        effect_verifier=lambda *args: True, dispatch_verifier=lambda *args: True,
        create=True)
    listener = None
    transports = []
    server = None
    host_fixture = None
    try:
        core.register_namespace(peers["client"], "ns:role", "host:one", deletion_head,
                                JournalHead("execution", 0, "genesis"))
        core.seal_v2_only(peers["client"])
        fences = AuthorityV2FenceService(
            core=core, fences=AuthorityV2FenceStore(core._db, create=True, lock=core._lock),
            deletion=deletion_guard, execution=execution, namespace="ns:role")
        verifier = object.__new__(PinnedCurrentModelEgressGraphVerifier)
        checked = []
        monkeypatch.setattr(verifier, "complete_graph_current",
                            lambda candidate: checked.append(candidate) or True)
        policy = AdminIngressModelPolicy(
            "provider-1", "model-1",
            installed_model_config_ref("provider-1", "model-1", "d" * 64),
            "d" * 64, 20.0, 256, ("text",), "private",
            ("proposal",), ("owner",), ("private",))
        model = AuthorityV2ModelEgressService(
            AuthorityV2ModelEgressStore(core._db, create=True, lock=core._lock),
            fences, graph_verifier=verifier, admin_model_policy=policy)
        server = AuthorityRpcServer(
            core, v2_fences=fences, v2_model_egress={"ns:role": model},
            model_observers_v2={"ns:role": (peers["client"].certificate_sha256, "first")},
            administrator_authorizer=lambda peer, action, namespace, holder:
                peer in peers.values() and action == "pair"
                and namespace == "authority:enrollment",
            publisher_manifest_verifier=lambda *args: True,
            installations_v2={(peers["client"].certificate_sha256, "first"):
                              AdministratorInstallationV2(
                                  "installation-a", "host:one", "publisher-policy-a",
                                  "capabilities-v2", manifest_digest)},
            namespace_bindings_v2={
                (peers["client"].certificate_sha256, "first",
                 NamespaceId("bot-a", "persona-a")): "ns:role"})
        listener = await server.start(
            "127.0.0.1", 0, AuthorityServerTlsConfig(
                str(files["server.pem"]), str(files["server.key"]), str(files["ca.pem"]),
                timeout_seconds=2, max_message_bytes=65_536))
        port = listener.sockets[0].getsockname()[1]

        async def paired(name, profile_id):
            profile = AuthorityTlsProfile(
                profile_id, "127.0.0.1", port, "localhost", server._authority_id(),
                files["ca.pem"], files[f"{name}.pem"], files[f"{name}.key"],
                timeout_seconds=2, max_message_bytes=65_536)
            transport = MtlsAuthorityTransport({profile_id: profile})
            transports.append(transport)
            request = AuthorityProvisioningRequest(
                AUTHORITY_PROTOCOL, profile_id, "astrbot_plugin_sylanne", "4.28.1",
                tmp_path, tmp_path, PublisherPackageIdentity(manifest_digest))
            handshake = await transport.handshake(request, protocol=AUTHORITY_V2_PROTOCOL)
            return transport, request, handshake

        transport, provisioning, handshake = await paired("client", "first")
        grant = await transport.installation_grant_v2(provisioning, handshake)
        anchor = await transport.v2_current_anchor(provisioning, handshake, "ns:role")
        subject = handshake.installation_identity_ref
        base = broker_request()
        envelope = replace(
            base.envelope, identity=replace(base.identity, operation_id="job-operation"),
            authority=replace(base.envelope.authority, actor=subject,
                              issuer_domain="d11", namespace=NamespaceId("bot-a", "persona-a"),
                              worker_fence=7),
            version_guard=replace(base.envelope.version_guard,
                                  read_versions=(), query_epochs=()))
        call = replace(base, envelope=envelope, call_id="call-1",
                       provider_id="provider-1", model_id="model-1",
                       required_capabilities=frozenset({"text"}),
                       timeout_seconds=20.0, max_output_tokens=256)
        draft = ModelEgressDraftV1.from_intent(intent(
            authority_id=anchor.authority_id, namespace="ns:role", subject=subject,
            authority_activation_generation=anchor.activation_generation,
            authority_revocation_epoch=anchor.revocation_epoch,
            authority_deletion_seq=anchor.deletion_seq,
            authority_execution_seq=anchor.execution_seq,
            request_digest=call.digest, budget_ceiling=(("output_tokens", 256),)))
        client = AuthorityClient(
            AuthoritySelection("first"), package_root=tmp_path, data_dir=tmp_path,
            transport=transport)
        assert (await client.status_v2()).state == "paired"
        current_grant = await client.installation_grant_v2()
        handshake = client._v2_handshake
        grant = current_grant
        installed_profile = transport.profile_for("first")
        host_fixture = model_fixture.AstrBotModelCallTests(
            methodName="test_one_http_request_on_host_loop_with_usage")
        await host_fixture.asyncSetUp()
        host_base = model_fixture.call_request()
        call2 = replace(
            host_base, call_id="call-2",
            envelope=replace(
                host_base.envelope,
                identity=replace(host_base.identity, operation_id="job-operation-2"),
                authority=replace(
                    host_base.envelope.authority, actor=subject,
                    issuer_domain="d11", namespace=NamespaceId("bot-a", "persona-a"),
                    worker_fence=7),
                version_guard=replace(host_base.envelope.version_guard,
                                      read_versions=(), query_epochs=())))
        draft2 = replace(
            draft, call_id="call-2", job_id="job-2",
            operation_id="job-operation-2", request_digest=call2.digest,
            provider_config_digest=host_fixture.admin_model.provider_config_digest,
            max_output_tokens=64, budget_ceiling=(("output_tokens", 128),))
        base_policy = host_fixture.bundle.installation_policy
        executor_policy = replace(
            base_policy, namespace=NamespaceId("bot-a", "persona-a"),
            authority_namespace="ns:role", installation_id="installation-a",
            manifest_digest=manifest_digest, administrator_holder="host:one",
            expected_authority_id=server._authority_id(),
            root_lease=replace(base_policy.root_lease,
                               bot_id="bot-a", persona_id="persona-a"),
            root_grant=replace(base_policy.root_grant,
                               bot_id="bot-a", persona_id="persona-a"))
        executor_bundle = replace(
            host_fixture.bundle, tls_profile=installed_profile,
            installation_policy=executor_policy)
        bundle = executor_bundle
        adapter = AstrBotModelProvider(
            context=host_fixture.context, host_loop=asyncio.get_running_loop(),
            trusted_umo=model_fixture.UMO, descriptor=host_fixture.descriptor,
            admin_model=host_fixture.admin_model,
            installation_bundle=executor_bundle)
        model._admin_model_policy = host_fixture.admin_model
        prepared2, _ = await client.model_prepare_fenced_v1(
            executor_bundle, grant, draft=draft2, expected_anchor=anchor)
        with pytest.raises(RuntimeError, match="request binding"):
            await client.model_admit_dispatch_once_v2(
                executor_bundle, grant,
                intent=prepared2.intent, expected_anchor=anchor,
                model_request=replace(call2, payload={"prompt": "changed"}),
                host_incarnation="b" * 64)
        assert host_fixture.requests == []
        executor = HostModelEgressExecutor(
            authority=client, bundle=executor_bundle, grant=grant, adapter=adapter)
        receipt2 = await executor.execute_once(
            intent=prepared2.intent, expected_anchor=anchor, request=call2)
        assert receipt2 is not None
        assert len(host_fixture.requests) == 1
        assert host_fixture.requests[0][1].url.host == "mock.invalid"
        assert (await client.model_recover_fenced_v1(
            executor_bundle, grant, intent=prepared2.intent))[0].state == "observed"
        with pytest.raises(RuntimeError, match="unavailable"):
            await client.model_admit_dispatch_once_v2(
                executor_bundle, grant,
                intent=prepared2.intent, expected_anchor=anchor,
                model_request=call2, host_incarnation=adapter.host_incarnation)
        assert len(host_fixture.requests) == 1
        model._admin_model_policy = policy
        prepared, permit = await transport.model_prepare_fenced_v1(
            provisioning, handshake, grant, namespace="ns:role", holder="host:one",
            draft=draft, expected_anchor=anchor)
        assert prepared.state == "prepared" and permit.subject == subject
        repeated, _ = await transport.model_prepare_fenced_v1(
            provisioning, handshake, grant, namespace="ns:role", holder="host:one",
            draft=draft, expected_anchor=anchor)
        assert repeated == prepared
        forged = {"record": model_to_wire(prepared), "permit": fence_to_wire(permit),
                  "channel_binding_sha256": handshake.channel_binding_sha256}
        forged["record"]["intent"]["request_digest"] = "e" * 64
        with pytest.raises(RuntimeError, match="response binding"):
            transport._model_response(forged, grant, draft, "prepared")
        other, other_request, other_handshake = await paired("second", "second")
        with pytest.raises(RuntimeError):
            await other.model_recover_fenced_v1(
                other_request, other_handshake, grant, namespace="ns:role",
                holder="host:one", intent=prepared.intent)
        with pytest.raises(RuntimeError, match="request binding"):
            await transport.model_admit_dispatch_once_v1(
                provisioning, handshake, grant, namespace="ns:role", holder="host:one",
                intent=prepared.intent, expected_anchor=anchor,
                model_request=replace(call, payload={"input_ref": "changed"}))
        assert (await transport.model_recover_fenced_v1(
            provisioning, handshake, grant, namespace="ns:role", holder="host:one",
            intent=prepared.intent))[0].state == "prepared"
        admitted, _ = await transport.model_admit_dispatch_once_v1(
            provisioning, handshake, grant, namespace="ns:role", holder="host:one",
            intent=prepared.intent, expected_anchor=anchor, model_request=call)
        assert admitted.state == "dispatch_started" and len(checked) == 2
        with pytest.raises(RuntimeError, match="unavailable"):
            await transport.model_admit_dispatch_once_v1(
                provisioning, handshake, grant, namespace="ns:role", holder="host:one",
                intent=prepared.intent, expected_anchor=anchor, model_request=call)
        assert len(checked) == 2
        recovered, _ = await transport.model_recover_fenced_v1(
            provisioning, handshake, grant, namespace="ns:role", holder="host:one",
            intent=prepared.intent)
        assert recovered.state == "dispatch_started"
        assert (await client.model_recover_fenced_v1(
            bundle, current_grant, intent=prepared.intent))[0].state == "dispatch_started"
        drifted = replace(
            bundle, installation_policy=replace(
                executor_policy, manifest_digest="e" * 64))
        with pytest.raises(RuntimeError, match="installation binding"):
            await client.model_recover_fenced_v1(
                drifted, current_grant, intent=prepared.intent)
    finally:
        if host_fixture is not None:
            await host_fixture.asyncTearDown()
        for transport in transports:
            await transport.close()
        if server is not None:
            await server.aclose()
        deletion.close()
        execution.close()
        core.close()
