"""Permanent installed acceptance: fresh-session finished read and exact no effects.

Uses the donor's actual same-boot Authority/Core/Graph/mTLS and ephemeral Owner
key. Deliberate SQL/clock/boot seams are refusal probes, not real reboot evidence.
"""
import json
from dataclasses import replace

import pytest


async def run_finished_contact_owner_read_case_v1(case, worker, *, operation_id, expected, model_calls):
    def exercise(graph):
        from sylanne3.authority_service.contact_finished_owner_read_v1 import OwnerContactFinishedReadUseV1, to_wire, from_wire
        from sylanne3.authority_service.contact_owner_session_v3 import from_wire as session_from_wire
        from sylanne3.authority_service.v2_owner_session import _verifier
        from sylanne3.authority_service.v2_contract import from_wire as permit_from_wire
        from sylanne3.runtime.contact_owner_invocation_v3 import read_contact_owner_invocation_v3, owner_binding_from_wire_v3, authority_from_wire_v3
        from sylanne3.runtime import contact_finished_owner_read_v1 as reader
        from sylanne3.runtime_contracts import canonical_digest, FenceScope, NamespaceId
        from sylanne3.graph_types import NamespaceEpoch
        from sylanne3.runtime.restore_anchor import RestoreAnchor
        from sylanne3.graph_coordinator import UnavailableGuard, AuthorityDenied, StaleRead
        failures = (ValueError, TypeError, RuntimeError, PermissionError, UnavailableGuard, AuthorityDenied, StaleRead)
        ns, ans, store, port = (case[k] for k in ('namespace', 'authority_namespace', 'store', 'port'))
        row = store._db.execute('SELECT request_digest FROM graph_owner_domain_attempts_v3 '
            'WHERE bot=? AND persona=? AND operation_id=?', (*ns.as_tuple, operation_id)).fetchone()
        store._db.execute('BEGIN')
        try:
            original = read_contact_owner_invocation_v3(store._db, case['d11_issuer'], ns, operation_id, row[0])
        finally:
            store._db.rollback()
        raw = json.loads(original.payload_json)
        old = session_from_wire(raw['session_observation'])
        permit = permit_from_wire(raw['scope']['permit'])
        observed, state = port.get_fence_operation(namespace=ns, authority_namespace=ans, operation_id=permit.operation_id)
        assert observed == permit and state == 'finished'
        request = case['owner_session_request']
        challenge = port.begin_owner_session(namespace=ns, authority_namespace=ans, request=request)
        token = port.accept_owner_session(namespace=ns, authority_namespace=ans, challenge=challenge,
            signature=case['owner_key'].sign(challenge.signed_bytes()))
        assert 'sha256:' + _verifier(token) != old.verifier_commitment
        finish_digest = 'sha256:' + canonical_digest(dict(schema='w01.owner-domain-write.v3',
            operation_id=operation_id, request_digest=row[0], permit_token=permit.token))
        use = OwnerContactFinishedReadUseV1(original.digest, old.commitment, 'sha256:' + _verifier(token),
            old.principal, old.actor, operation_id, row[0], old.permit_digest, 'finish:' + permit.operation_id,
            finish_digest, old.authority_id, ans, old.installation_id, permit.generation,
            raw['owner']['graph_incarnation'], raw['deadline_utc'], 'contact-read:installed-fresh-session')
        assert from_wire(to_wire(use)) == use
        with pytest.raises(ValueError):
            from_wire({**to_wire(use), 'caller_read_authorized': True})
        def read(selected=use, signature=None):
            return graph.read_finished_contact_for_owner_v1(case['bootstrap'], namespace=ns,
                operation_id=operation_id, request_digest=row[0], owner_session_token=token,
                owner_session_request=request, use=selected,
                signature=case['owner_key'].sign(selected.signed_bytes()) if signature is None else signature)
        def graph_original_bytes():
            return tuple(store._db.iterdump())
        # Exact whole Graph SQL, paid HTTP count, and active rights are unchanged.
        before = graph_original_bytes()
        changes = store._db.total_changes
        calls = tuple(model_calls)
        leases = tuple(graph._GraphCoordinator__leases.items())
        owners = tuple(graph._GraphCoordinator__owner_leases.items())
        sessions = tuple(graph._GraphCoordinator__owner_session_proofs.items())
        active_recovery = tuple(graph._GraphCoordinator__contact_recovery_leases_v3.items())
        captured = []
        actual_associate = port.associate_contact_finished_owner_read_v1
        def capture_association(**kwargs):
            value = actual_associate(**kwargs)
            captured.append((kwargs, value))
            return value
        port.associate_contact_finished_owner_read_v1 = capture_association
        try:
            assert read() == expected == raw['result']
            assert read() == expected
        finally:
            port.associate_contact_finished_owner_read_v1 = actual_associate
        assert len(expected['receipt']['write_versions']) == 11
        assert graph_original_bytes() == before and store._db.total_changes == changes
        assert tuple(model_calls) == calls and not reader._READS
        assert tuple(graph._GraphCoordinator__leases.items()) == leases
        assert tuple(graph._GraphCoordinator__owner_leases.items()) == owners
        assert tuple(graph._GraphCoordinator__owner_session_proofs.items()) == sessions
        assert tuple(graph._GraphCoordinator__contact_recovery_leases_v3.items()) == active_recovery
        for kwargs, (association, _, finished) in captured:
            assert kwargs['permit'].operation == 'read' and kwargs['old_permit'] == permit
            assert association['old_authority_observation_digest'] == old.authority_observation_digest
            assert association['new_read_guard_digest'] != old.authority_observation_digest
            assert finished.permit == permit and finished.finish_request_digest == finish_digest
        # An authentic use with a forged signature reaches real Authority
        # Ed25519 verification. Old-purpose signatures cannot authorize reading.
        with pytest.raises(failures):
            read(signature=b'\x00' * 64)
        from sylanne3.authority_service.contact_owner_session_v3 import OwnerContactRecoveryUseV3
        active_use = OwnerContactRecoveryUseV3(original.digest, old.commitment, 'sha256:' + _verifier(token),
            old.principal, old.actor, operation_id, old.permit_digest, raw['deadline_utc'])
        with pytest.raises(failures):
            read(signature=case['owner_key'].sign(active_use.signed_bytes()))
        for selected in (replace(use, invocation_digest='sha256:' + 'b' * 64),
                         replace(use, finish_request_id='finish:other'),
                         replace(use, finish_request_digest='sha256:' + 'b' * 64),
                         replace(use, old_permit_digest='sha256:' + 'b' * 64)):
            with pytest.raises(failures):
                read(selected)
        def wrong_read_permit(**kwargs):
            return actual_associate(**{**kwargs, 'permit': permit})
        port.associate_contact_finished_owner_read_v1 = wrong_read_permit
        try:
            with pytest.raises(failures):
                read()
        finally:
            port.associate_contact_finished_owner_read_v1 = actual_associate
        # A caller-created or expired authentic marker cannot escape issuance.
        parts = dict(raw['scope'])
        parts.update(namespace=NamespaceId(**parts['namespace']), graph_epoch=NamespaceEpoch(**parts['graph_epoch']),
            pinned_anchor=RestoreAnchor(**parts['pinned_anchor']), permit=permit)
        old_scope = FenceScope(**parts)
        kwargs, (_, _, finished) = captured[0]
        current_scope = replace(old_scope, operation='read', operation_id=kwargs['permit'].operation_id,
            permit=kwargs['permit'])
        forged = reader._ContactFinishedReadV1(graph, graph._GraphCoordinator__domain_production_runtime_v1,
            authority_from_wire_v3(raw['authority']), owner_binding_from_wire_v3(raw['owner']), old_scope,
            reader.PrepareCurrentContactDispatchRequestV3(**raw['request']), operation_id, row[0],
            original, current_scope, use, finished)
        with pytest.raises(ValueError):
            reader.require_contact_finished_read_v1(forged, graph, current_scope)
        current_clock = port.read_ingress_clock
        def expired_clock(*args, **kwargs):
            clock = current_clock(*args, **kwargs)
            return replace(clock, utc_upper_bound_seconds=clock.utc_upper_bound_seconds + 10000.)
        port.read_ingress_clock = expired_clock
        try:
            with pytest.raises(failures):
                read()
        finally:
            port.read_ingress_clock = current_clock
        epoch = store._db.execute('SELECT revision FROM graph_epochs WHERE bot=? AND persona=?', ns.as_tuple).fetchone()[0]
        store._db.execute('UPDATE graph_epochs SET revision=? WHERE bot=? AND persona=?', (epoch + 1, *ns.as_tuple))
        try:
            with pytest.raises(failures):
                read()
        finally:
            store._db.execute('UPDATE graph_epochs SET revision=? WHERE bot=? AND persona=?', (epoch, *ns.as_tuple))
        authority_sessions = case['server']._v2_owner_sessions
        core = authority_sessions._core
        # Expired/damaged old-session row cannot replace the full signed
        # original commitment. The fresh actual login remains unchanged.
        with core._tx() as db:
            old_expiry = db.execute('SELECT expires_at_utc FROM authority_owner_sessions_v1 WHERE verifier=?',
                (old.verifier_commitment[7:],)).fetchone()[0]
            db.execute('UPDATE authority_owner_sessions_v1 SET expires_at_utc=? WHERE verifier=?',
                ('2000-01-01T00:00:00Z', old.verifier_commitment[7:]))
        try:
            with pytest.raises(failures):
                read()
        finally:
            with core._tx() as db:
                db.execute('UPDATE authority_owner_sessions_v1 SET expires_at_utc=? WHERE verifier=?',
                    (old_expiry, old.verifier_commitment[7:]))
        with core._tx() as db:
            old_boot = db.execute('SELECT boot_id FROM authority_owner_sessions_v1 WHERE verifier=?',
                (old.verifier_commitment[7:],)).fetchone()[0]
            db.execute('UPDATE authority_owner_sessions_v1 SET boot_id=? WHERE verifier=?',
                ('different-boot-refusal-probe', old.verifier_commitment[7:]))
        try:
            with pytest.raises(failures):
                read()
        finally:
            with core._tx() as db:
                db.execute('UPDATE authority_owner_sessions_v1 SET boot_id=? WHERE verifier=?',
                    (old_boot, old.verifier_commitment[7:]))
        # True logout while the read is observing current policy wins even
        # though the fresh session/use remain valid. Do not restore a revoke.
        c04 = graph._GraphCoordinator__c04_authority_port_v3
        actual_policy = c04.contact_policy
        revoked = []
        def revoke_after_policy(*args, **kwargs):
            value = actual_policy(*args, **kwargs)
            if not revoked:
                port.logout_owner_session(namespace=ns, authority_namespace=ans,
                    request=case['owner_session_request'], token=case['owner_session_token'])
                revoked.append(True)
            return value
        c04.contact_policy = revoke_after_policy
        try:
            with pytest.raises(failures):
                read()
        finally:
            c04.contact_policy = actual_policy
        assert revoked
        with pytest.raises(failures):
            read()
        assert graph_original_bytes() == before and tuple(model_calls) == calls and not reader._READS
        observed, state = port.get_fence_operation(namespace=ns, authority_namespace=ans, operation_id=permit.operation_id)
        assert observed == permit and state == 'finished'
    await worker.call(exercise)
