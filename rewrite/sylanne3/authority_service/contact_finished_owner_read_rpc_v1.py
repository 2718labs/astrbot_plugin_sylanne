"""Installed read-fence association, independent of active write recovery.

Graph invocation/eleven-member authentication belongs to the Graph entrant.
This RPC authenticates actual sessions, current read authority and finished ACK.
"""
from .contract import AuthorityUnavailable
from .contact_finished_owner_read_v1 import associate_in_tx, from_wire, digest
from .contact_owner_session_v3 import from_wire as session_from_wire
from .contact_fence_finished_v3 import ContactFenceFinishedOriginalV3, contact_finished_to_wire_v3
from .d12_target_owner_rpc_v1 import dispatch_d12_target_owner_v1, METHOD as OWNER_METHOD
from .v2_contract import FencePermitV2, from_wire as permit_from_wire, canonical_digest

METHOD = 'associate_contact_finished_owner_read_v1'
BASE = {'namespace', 'permit', 'owner_actor_id', 'owner_session_token', 'owner_session_request'}


def dispatch_contact_finished_owner_read_v1(server, method, credential, profile_id, manifest_digest, command):
    if method != METHOD:
        return None
    if type(command) is not dict or set(command) != BASE | {'original', 'use', 'signature', 'old_permit'}:
        raise AuthorityUnavailable('finished Contact read RPC closed fields differ')
    base = {k:command[k] for k in BASE}
    read_permit = permit_from_wire(command['permit'])
    old_permit = permit_from_wire(command['old_permit'])
    if (type(read_permit) is not FencePermitV2 or read_permit.operation != 'read'
            or type(old_permit) is not FencePermitV2 or old_permit.operation != 'write'):
        raise AuthorityUnavailable('finished Contact read needs independent actual read and old write permits')
    observed = dispatch_d12_target_owner_v1(server, OWNER_METHOD, credential, profile_id, manifest_digest, base)
    sessions = server._v2_owner_sessions
    namespace = command['namespace']
    fences = server._bound_v2_service(credential, profile_id, manifest_digest, namespace)
    installed = server._installations_v2[(credential.certificate_sha256, profile_id)]
    if sessions is None or sessions._core is not server._core or fences.core is not server._core:
        raise AuthorityUnavailable('finished Contact read current session/fence store unavailable')
    server._core._require(credential, 'owner_session', namespace)
    subject = 'mtls:sha256:' + credential.certificate_sha256
    fences._require_permit(credential=credential, subject=subject, permit=read_permit)
    fences._require_permit(credential=credential, subject=subject, permit=old_permit)
    kwargs = server._owner_session_kwargs(command, namespace, installed.installation_id)
    try:
        signature = bytes.fromhex(command['signature'])
    except (TypeError, ValueError) as exc:
        raise AuthorityUnavailable('finished Contact signature encoding differs') from exc
    if signature.hex() != command['signature']:
        raise AuthorityUnavailable('finished Contact signature noncanonical')
    # Keep journal guards before Core, as every protected fence operation does.
    # The live read permit pins current authority while the old finished row
    # and both live session rows are examined in this one actual transaction.
    with fences._frozen() as (db, deletion_head, execution_head, deletion_history):
        anchor = fences._current_locked(db, deletion_head, execution_head,
            holder=read_permit.holder, generation=read_permit.generation)
        if deletion_history:
            fences.core.require_current_content_ready_locked(db, namespace=namespace)
        if anchor != read_permit.pinned_anchor or anchor != old_permit.pinned_anchor:
            raise AuthorityUnavailable('finished Contact read current anchor changed')
        if fences.fences.validate_fence_locked(db, read_permit, subject=subject, current_anchor=anchor) != read_permit:
            raise AuthorityUnavailable('finished Contact actual read permit differs')
        row = fences.fences._row(db, old_permit.operation_id)
        if (row is None or row[1] != namespace or row[2] != subject
                or fences.fences._permit(row) != old_permit or row[6] != 'finished' or row[10] is not None):
            raise AuthorityUnavailable('finished Contact actual finished original unavailable; HOLD')
        finished = ContactFenceFinishedOriginalV3(old_permit, canonical_digest(old_permit), row[8], row[9], anchor)
        association = associate_in_tx(sessions, db, token=kwargs['session_token'], request=kwargs['session_request'],
            actor=command['owner_actor_id'], original=session_from_wire(command['original']),
            use=from_wire(command['use']), signature=signature, finished=finished,
            read_permit=read_permit, read_guard_digest=digest(observed))
    after = dispatch_d12_target_owner_v1(server, OWNER_METHOD, credential, profile_id, manifest_digest, base)
    after_finished = fences.read_contact_finished_original_v3(credential=credential, subject=subject, permit=old_permit)
    if after != observed or after_finished != finished:
        raise AuthorityUnavailable('finished Contact read authority/ACK drifted across association')
    return {'association': association, 'authority': observed, 'finished': contact_finished_to_wire_v3(finished)}
