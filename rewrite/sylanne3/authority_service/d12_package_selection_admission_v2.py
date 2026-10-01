"""Exact accepted forward/rollback selection identities; no pointer mutation."""
import json
from .contract import AuthorityUnavailable
from .d12_package_files_v2 import decode_package_selection_v2,next_package_selection_v2


def require_actual_package_selection_v2(service,*,intent,accepted_row,selected,purpose):
    if purpose not in {'source','rollback_source','candidate_bootstrap','rollback_bootstrap','abort_source','abort_bootstrap'}:
        raise AuthorityUnavailable('fixed accepted package selection purpose required')
    before=decode_package_selection_v2(json.loads(accepted_row[10]))
    old_installation,old=service.files.read_registered_cohort_v2(intent.old_cohort_ref)
    new_installation,new=service.files.read_registered_cohort_v2(intent.candidate_cohort_ref)
    if (old_installation!=intent.installation_id or new_installation!=intent.installation_id
            or old.cohort_digest!=intent.old_cohort_digest or new.cohort_digest!=intent.candidate_cohort_digest
            or old.package.manifest_sha256!=intent.old_manifest_sha256 or new.package.manifest_sha256!=intent.candidate_manifest_sha256
            or old.identity_commitment!=new.identity_commitment or before.selection_digest!=intent.expected_selection_digest):
        raise AuthorityUnavailable('immutable accepted configuration cohort changed')
    candidate=next_package_selection_v2(before,operation_id=intent.operation_id,package=new.package,cohort_ref=new.cohort_ref,cohort_digest=new.cohort_digest)
    rollback=next_package_selection_v2(candidate,operation_id=intent.operation_id,package=old.package,cohort_ref=old.cohort_ref,cohort_digest=old.cohort_digest)
    expected=before if purpose in {'source','abort_source','abort_bootstrap'} else rollback if purpose=='rollback_bootstrap' else candidate
    if selected!=expected:raise AuthorityUnavailable('actual selection differs from this exact accepted package stage')
    return before,candidate,rollback
