"""Independent Owner-signed use of one finished Contact original, for reading.

Closed carriers are evidence. Only the installed RPC and Graph entrant may
authenticate them; neither this decoder nor the Owner signature issues a grant.
"""
from dataclasses import asdict, dataclass, fields
import hashlib
import json

from .contract import AuthorityUnavailable, identifier
from .contact_owner_session_v3 import ContactOwnerSessionObservationV3, capture_in_tx, digest
from .contact_fence_finished_v3 import ContactFenceFinishedOriginalV3, contact_finished_to_wire_v3
from .v2_owner_contract import OwnerPrincipalV1
from .v2_owner_proof import _sha256, _time, _verify_signature
from .v2_owner_session import from_wire as login_from_wire
from .v2_contract import FencePermitV2, to_wire as permit_to_wire

SCHEMA = 'sylanne3.contact-finished-owner-read.v1'
PURPOSE = 'contact_finished_original_readonly_v1'


@dataclass(frozen=True, slots=True)
class OwnerContactFinishedReadUseV1:
    invocation_digest: str
    original_session_commitment: str
    new_verifier_commitment: str
    principal: OwnerPrincipalV1
    actor: str
    operation_id: str
    request_digest: str
    old_permit_digest: str
    finish_request_id: str
    finish_request_digest: str
    authority_id: str
    authority_namespace: str
    installation_id: str
    generation: int
    graph_incarnation: str
    deadline_utc: str
    read_request_id: str
    purpose: str = PURPOSE
    schema: str = SCHEMA

    def __post_init__(self):
        if self.schema != SCHEMA or self.purpose != PURPOSE or type(self.principal) is not OwnerPrincipalV1:
            raise ValueError('finished Contact read purpose/schema/principal differs')
        for name in ('invocation_digest', 'original_session_commitment', 'new_verifier_commitment',
                     'old_permit_digest', 'finish_request_digest'):
            _sha256(getattr(self, name), name)
        for name in ('actor', 'operation_id', 'finish_request_id', 'authority_id',
                     'authority_namespace', 'installation_id', 'graph_incarnation', 'read_request_id'):
            identifier(getattr(self, name), name)
        if (type(self.request_digest) is not str or len(self.request_digest) != 64
                or any(c not in '0123456789abcdef' for c in self.request_digest)
                or type(self.generation) is not int or self.generation < 1):
            raise ValueError('finished Contact read request/generation differs')
        _time(self.deadline_utc)

    def signed_bytes(self):
        return b'Sylanne3 Owner Contact finished original READONLY use v1\n' + json.dumps(
            asdict(self), sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()


def to_wire(value):
    if type(value) is not OwnerContactFinishedReadUseV1:
        raise TypeError('closed finished Contact read use required')
    return {'kind': 'owner_contact_finished_read_use_v1', **asdict(value)}


def from_wire(raw):
    if (type(raw) is not dict or set(raw) != {f.name for f in fields(OwnerContactFinishedReadUseV1)} | {'kind'}
            or raw['kind'] != 'owner_contact_finished_read_use_v1'
            or type(raw['principal']) is not dict
            or set(raw['principal']) != {f.name for f in fields(OwnerPrincipalV1)}):
        raise ValueError('finished Contact read use closed fields differ')
    value = OwnerContactFinishedReadUseV1(**{**{k:v for k,v in raw.items() if k != 'kind'},
                                            'principal': OwnerPrincipalV1(**raw['principal'])})
    if to_wire(value) != raw:
        raise ValueError('finished Contact read use noncanonical')
    return value


def associate_in_tx(sessions, db, *, token, request, actor, original, use, signature,
                    finished, read_permit, read_guard_digest):
    """Actual current key and old/new session rows under the frozen Core tx."""
    if (type(original) is not ContactOwnerSessionObservationV3
            or type(use) is not OwnerContactFinishedReadUseV1
            or type(finished) is not ContactFenceFinishedOriginalV3
            or type(read_permit) is not FencePermitV2 or read_permit.operation != 'read'
            or not db.in_transaction or not sessions._core._lock._is_owned()):
        raise AuthorityUnavailable('finished Contact read requires actual locked closed evidence')
    current = capture_in_tx(sessions, db, token=token, request=request, actor=actor,
        permit_digest=digest(permit_to_wire(read_permit)), authority_observation_digest=read_guard_digest)
    old_permit = finished.permit
    if (use.original_session_commitment != original.commitment
            or use.new_verifier_commitment != current.verifier_commitment
            or use.principal != original.principal or use.principal != current.principal
            or use.actor != original.actor or use.actor != current.actor
            or use.old_permit_digest != original.permit_digest
            or use.old_permit_digest != digest(permit_to_wire(old_permit))
            or (use.finish_request_id, use.finish_request_digest)
                != (finished.finish_request_id, finished.finish_request_digest)
            or (use.authority_id, use.authority_namespace, use.installation_id, use.generation)
                != (current.authority_id, current.authority_namespace, current.installation_id, read_permit.generation)
            or (old_permit.authority_id, old_permit.namespace, old_permit.subject, old_permit.holder,
                old_permit.generation, old_permit.pinned_anchor)
                != (read_permit.authority_id, read_permit.namespace, read_permit.subject, read_permit.holder,
                    read_permit.generation, read_permit.pinned_anchor)
            or (original.authority_id, original.authority_namespace, original.installation_id,
                original.credential_id, original.credential_epoch, original.principal_epoch, original.boot_commitment)
                != (current.authority_id, current.authority_namespace, current.installation_id,
                    current.credential_id, current.credential_epoch, current.principal_epoch, current.boot_commitment)):
        raise AuthorityUnavailable('finished Contact read identity/finish/continuity differs; HOLD')
    old = db.execute('SELECT request_json,principal_epoch,boot_id,issued_at_utc,expires_at_utc,revoked_at_utc '
        'FROM authority_owner_sessions_v1 WHERE verifier=?', (original.verifier_commitment[7:],)).fetchone()
    if (old is None or old[5] is not None or old[1] != original.principal_epoch
            or old[2] != sessions._boot_id or digest(old[2]) != original.boot_commitment
            or old[3:5] != (original.issued_at_utc, original.expires_at_utc)
            or 'sha256:' + hashlib.sha256(old[0]).hexdigest() != original.request_digest
            or sessions._now() >= min(_time(original.expires_at_utc), _time(use.deadline_utc))):
        raise AuthorityUnavailable('finished Contact old session expired/revoked/boot changed; HOLD')
    old_request = login_from_wire({'kind': 'owner_session_login_request_v1', **json.loads(old[0])})
    if ((old_request.authority_id, old_request.authority_namespace, old_request.installation_id,
         old_request.principal, old_request.credential_id, old_request.credential_epoch)
            != (request.authority_id, request.authority_namespace, request.installation_id,
                request.principal, request.credential_id, request.credential_epoch)):
        raise AuthorityUnavailable('finished Contact original login differs')
    sessions._current_key(db, old_request)
    key = sessions._current_key(db, request)
    if type(signature) is not bytes or len(signature) != 64:
        raise AuthorityUnavailable('finished Contact readonly-use Ed25519 signature required')
    _verify_signature(key, signature, use.signed_bytes(), 'finished Contact readonly-use signature denied')
    return association_to_wire(original=original, current=current, use=use,
        finished=finished, read_permit=read_permit, read_guard_digest=read_guard_digest)


def association_to_wire(*, original, current, use, finished, read_permit, read_guard_digest):
    from .contact_owner_session_v3 import to_wire as session_to_wire
    raw = dict(schema=SCHEMA, kind='contact_finished_owner_read_association_v1',
        original=session_to_wire(original), current=session_to_wire(current), use=to_wire(use),
        finished=contact_finished_to_wire_v3(finished), read_permit=permit_to_wire(read_permit),
        old_authority_observation_digest=original.authority_observation_digest,
        new_read_guard_digest=read_guard_digest)
    return {**raw, 'association_digest': digest(raw)}


def validate_association(raw, *, original, use, finished, read_permit, read_guard_digest):
    from .contact_owner_session_v3 import from_wire as session_from_wire
    expected = {'schema', 'kind', 'original', 'current', 'use', 'finished', 'read_permit',
                'old_authority_observation_digest', 'new_read_guard_digest', 'association_digest'}
    if (type(raw) is not dict or set(raw) != expected
            or type(original) is not ContactOwnerSessionObservationV3
            or type(use) is not OwnerContactFinishedReadUseV1
            or type(finished) is not ContactFenceFinishedOriginalV3
            or type(read_permit) is not FencePermitV2 or read_permit.operation != 'read'):
        raise ValueError('finished Contact read association closed fields differ')
    current = session_from_wire(raw['current'])
    if (type(current) is not ContactOwnerSessionObservationV3
            or current.verifier_commitment != use.new_verifier_commitment
            or current.principal != use.principal or current.actor != use.actor
            or original.principal != use.principal or original.actor != use.actor
            or use.original_session_commitment != original.commitment
            or original.permit_digest != use.old_permit_digest
            or use.old_permit_digest != digest(permit_to_wire(finished.permit))
            or (use.finish_request_id, use.finish_request_digest)
                != (finished.finish_request_id, finished.finish_request_digest)
            or (use.authority_id, use.authority_namespace, use.installation_id, use.generation)
                != (current.authority_id, current.authority_namespace, current.installation_id, read_permit.generation)
            or (original.authority_id, original.authority_namespace, original.installation_id,
                original.credential_id, original.credential_epoch, original.principal_epoch, original.boot_commitment)
                != (current.authority_id, current.authority_namespace, current.installation_id,
                    current.credential_id, current.credential_epoch, current.principal_epoch, current.boot_commitment)
            or (finished.permit.authority_id, finished.permit.namespace, finished.permit.subject,
                finished.permit.holder, finished.permit.generation, finished.permit.pinned_anchor)
                != (read_permit.authority_id, read_permit.namespace, read_permit.subject,
                    read_permit.holder, read_permit.generation, read_permit.pinned_anchor)
            or current.permit_digest != digest(permit_to_wire(read_permit))
            or current.authority_observation_digest != read_guard_digest
            or raw != association_to_wire(original=original, current=current, use=use,
                finished=finished, read_permit=read_permit, read_guard_digest=read_guard_digest)):
        raise ValueError('finished Contact readonly association linkage differs')
    return current
