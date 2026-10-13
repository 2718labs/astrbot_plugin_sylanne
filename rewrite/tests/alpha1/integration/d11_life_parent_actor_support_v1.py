"""Actual parent original authentication after the independent Host has exited.

Only fixture assembly lives here. The original Authority/Core and issuers stay
alive; a fresh maintenance Host creates its own connections and Owner session.
No child locator is accepted as a signed original or maintenance permission.
"""
from contextlib import AsyncExitStack, closing
from dataclasses import replace
import asyncio
import json
from pathlib import Path
import sqlite3


def _authenticate_completed(case, installation, locators):
    from sylanne3.graph_types import AtomKey
    from sylanne3.runtime_contracts import canonical_digest
    from sylanne3.runtime.internal_life_completed_original_v1 import read_completed_internal_life_original_v1
    from sylanne3.runtime.d06_internal_life_episode_v2 import (
        PROVENANCE, decode_internal_life_value_v2, validate_internal_life_episode_history_v2,
    )
    from sylanne3.runtime.d01_production_operations_v1 import raw_head_value_v1
    from sylanne3.runtime.d11_life_adoption_v1 import _read_signed, verify_life_adoption_commit_v1
    from sylanne3.authority_service.d11_life_bridge_v1 import life_bridge_from_wire_v1
    from sylanne3.runtime.d11_life_preparation_v1 import read_prepared_life_v1
    from c09_life_host_process_support_v1 import CompletedLifeLocatorsV1
    if type(locators) is not CompletedLifeLocatorsV1:
        raise TypeError('exact child locator packet required')
    issuer, resource = case['d11_issuer'], case['d02_issuer']
    if issuer.resource_issuer is not resource:
        raise ValueError('original parent D11/resource instance binding changed')
    gate = case['c09_writer_gate']
    control = gate.control
    control.lease.require_held()
    current = control.read_verified_current_storage_v1()
    current.require_current('business')
    members = {member['role']: member for member in current.manifest['members']}
    path = Path(installation.graph_path).resolve(strict=True)
    if (str(path) != members['graph']['resolved_path']
            or str(Path(case['core'].path).resolve()) != members['core']['resolved_path']
            or installation.namespace != case['namespace']):
        raise ValueError('original parent selected Core/Graph/namespace changed')
    # A new read-only connection; never use the closed old Host Graph handle.
    with closing(sqlite3.connect(path.as_uri()+'?mode=ro', uri=True)) as db:
        db.execute('PRAGMA query_only=ON')
        db.execute('BEGIN')
        completed = read_completed_internal_life_original_v1(db,
            namespace=case['namespace'], issuer=issuer, job_id=locators.job_id)
        if (completed.prepared.digest != locators.prepared_digest
                or completed.receipt.operation_id != locators.adoption_operation_id
                or canonical_digest(completed.receipt) != locators.receipt_digest):
            raise ValueError('child locators differ from original signed completed chain')
        episode_key = AtomKey.from_token(completed.prepared.episode_ref)
        raw = raw_head_value_v1(db, case['namespace'], AtomKey(episode_key.owner, PROVENANCE, 'record'))
        proof = decode_internal_life_value_v2(PROVENANCE, raw)
        validate_internal_life_episode_history_v2(db, proof)
        if proof.episode.episode_ref != completed.prepared.episode_ref:
            raise ValueError('completed content episode differs from actual history')
        activity = proof.event.activity
        saved = _read_signed(db, case['namespace'], 'adoption_bridge', activity.execution_id, issuer)
        if saved is None:
            raise ValueError('Life donor signed execution bridge is missing')
        bridge = life_bridge_from_wire_v1(saved[1])
        binding = bridge.binding
        if (binding.namespace != case['namespace'] or binding.execution_id != activity.execution_id
                or binding.artifact_ref != activity.artifact_ref
                or binding.activity_id != activity.activity_id or binding.effect_id != activity.effect_id
                or bridge.terminal.status != 'completed'
                or bridge.terminal.payload.artifact_digest != activity.artifact_digest):
            raise ValueError('actual Episode and signed donor execution differ')
        verify_life_adoption_commit_v1(db, gate=bridge, issuer=issuer,
            resource_issuer=resource, require_current_metadata=False)
        donor = read_prepared_life_v1(db, binding=binding, issuer=issuer)
        if donor is None or len(donor.plan.audiences) != 1:
            raise ValueError('actual donor preparation/audience unavailable')
        result = dict(content_prepared=completed.prepared,
            content_source_execution_id=binding.execution_id,
            source_ref=donor.plan.input_source.ref, life_audience=donor.plan.audiences[0])
        db.rollback()
    latest = control.read_verified_current_storage_v1()
    if (latest.pointer_version, latest.manifest_digest) != (current.pointer_version, current.manifest_digest):
        raise ValueError('selected parent generation changed during authentication')
    return result


async def run_parent_life_actor_v1(case, *, host_process_runner, installation, close_host_handles):
    from c09_life_host_process_support_v1 import ParentAuthorityServicesV1
    from c09_life_host_bootstrap_v1 import open_life_host_bootstrap_v1
    gate = case['c09_writer_gate']
    original = {name: case[name] for name in ('core', 'server', 'd02_issuer', 'd11_issuer',
        'c09_writer_gate', 'c09_provider_cache', 'c09_authority_graph_store', 'c09_cold_fixture')}
    if case.get('c09_daemon') is not None:
        original.update({name:case[name] for name in ('c09_daemon','c09_deployment_config','c09_maintenance_factory')})
    async with AsyncExitStack() as lifetime:
        authenticated_once = False
        async def authenticate_completed(locators):
            nonlocal authenticated_once
            if authenticated_once:
                raise ValueError('parent completed authentication callback repeated')
            authenticated = await asyncio.to_thread(_authenticate_completed, case, installation, locators)
            host = await lifetime.enter_async_context(open_life_host_bootstrap_v1(installation))
            owner_request = replace(host['owner_session_request'], audience='owner')
            challenge = await asyncio.to_thread(host['port'].begin_owner_session,
                namespace=host['namespace'], authority_namespace=host['authority_namespace'], request=owner_request)
            owner_token = await asyncio.to_thread(host['port'].accept_owner_session,
                namespace=host['namespace'], authority_namespace=host['authority_namespace'],
                challenge=challenge, signature=host['owner_key'].sign(challenge.signed_bytes()))
            host.update(owner_session_request=owner_request, owner_session_token=owner_token)
            merged = dict(case)
            merged.update(host)
            merged.update(original)
            merged.update(authenticated)
            if any(merged[name] is not value for name, value in original.items()):
                raise ValueError('parent Authority installation identity changed')
            authenticated_once = True
            return merged
        parent = ParentAuthorityServicesV1(control=gate.control, gate=gate,
            close_host_handles=close_host_handles,authenticate_completed=authenticate_completed,
            daemon=case.get('c09_daemon'),deployment_config=case.get('c09_deployment_config'),
            maintenance_factory=case.get('c09_maintenance_factory'))
        result = await host_process_runner(installation, parent)
        if not authenticated_once:
            raise ValueError('Host runner did not authenticate completed originals')
        return result
