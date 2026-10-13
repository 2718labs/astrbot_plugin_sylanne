"""Optional explicit Linux cohort binding for the fixed credential directory.

A protected binding opts an installation into cohort startup. Once present, no
failed selection falls back to the historical profile payload. Keys remain on
all the original descriptor-pinned paths in authority_profile._opened_profile.
"""
from __future__ import annotations
from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path

from ..authority_service.contract import AuthorityUnavailable
from ..authority_service.d12_package_files_v2 import (InstalledPackageSelectionFilesV2, PackageSelectionV2,
    decode_package_selection_v2, _require_registered_package_protection_v2)
from ..authority_service.linux_installation_security_v1 import read_installed_json_v1, opened_installed_file_v1

BINDING_NAME='package-cohort-control.json'
BINDING_SCHEMA='sylanne3.d12.profile-cohort-binding.v2'


@dataclass(frozen=True, slots=True)
class SelectedProfileReadV2:
    descriptor: int
    selection: PackageSelectionV2
    control_directory: str
    profile_id: str


def validate_profile_cohort_binding_v2(binding,profile_dir):
    if (type(binding) is not dict or set(binding)!={'schema','control_directory','profile_id','installation_id'}
            or binding['schema']!=BINDING_SCHEMA or binding['profile_id']!=Path(profile_dir).name
            or type(binding['installation_id']) is not str or not binding['installation_id']
            or type(binding['control_directory']) is not str or not Path(binding['control_directory']).is_absolute()
            or '..' in Path(binding['control_directory']).parts):
        raise AuthorityUnavailable('fixed credential/cohort binding differs')
    return binding


@contextmanager
def selected_profile_payload_v2(profile_dir,system):
    directory=Path(profile_dir)
    if system!='Linux':
        yield None
        return
    binding_path=directory/BINDING_NAME
    try:binding_path.lstat()
    except FileNotFoundError:
        # Existing installations have no opt-in binding. The fresh cohort
        # installer creates one; malformed/unreadable bindings never fall back.
        yield None
        return
    binding=validate_profile_cohort_binding_v2(read_installed_json_v1(binding_path),directory)
    files=InstalledPackageSelectionFilesV2(control_directory=binding['control_directory'])
    selection,cohort,configuration=files.read_selected_host_cohort_v2()
    if (cohort.credential_profile_directory!=str(directory)
            or selection.installation_id!=binding['installation_id']
            or Path(cohort.credential_profile_directory).name!=binding['profile_id']):
        raise AuthorityUnavailable('selected cohort cannot change credential directory or installation')
    profile=next(item for item in cohort.files if item.role=='host_profile')
    with opened_installed_file_v1(profile.path) as fd:
        if os.fstat(fd).st_size>32768:
            raise AuthorityUnavailable('selected profile exceeds existing profile bound')
        with os.fdopen(os.dup(fd),'rb') as stream:
            if hashlib.file_digest(stream,'sha256').hexdigest()!=profile.sha256:
                raise AuthorityUnavailable('selected profile bytes changed before loading')
        os.lseek(fd,0,os.SEEK_SET)
        yield SelectedProfileReadV2(fd,selection,binding['control_directory'],binding['profile_id'])
        # The entry read already qualified this exact package and policy.
        # Exit still rereads every package byte and object permission; identical
        # bytes need no second domain registry/policy semantic reconstruction.
        after = decode_package_selection_v2(read_installed_json_v1(files.control_directory / 'selection.json'))
        installation, current_cohort = files.read_registered_cohort_v2(after.cohort_ref)
        if after != selection or installation != selection.installation_id or current_cohort != cohort:
            raise AuthorityUnavailable('selected cohort changed during credential/profile loading')
        with opened_installed_file_v1(profile.path) as current_fd:
            with os.fdopen(os.dup(current_fd), 'rb') as stream:
                if hashlib.file_digest(stream, 'sha256').hexdigest() != profile.sha256:
                    raise AuthorityUnavailable('selected profile changed during credential/profile loading')
        _require_registered_package_protection_v2(cohort.package)
        from .installed_package import verify_installed_package
        verified = verify_installed_package(cohort.package.package_root, cohort.package.manifest_sha256)
        if not verified.verified or verified.package_version != cohort.package.package_version:
            raise AuthorityUnavailable('selected package bytes changed during credential/profile loading')
        final = decode_package_selection_v2(read_installed_json_v1(files.control_directory / 'selection.json'))
        if final != selection:
            raise AuthorityUnavailable('selected cohort changed during credential/profile loading')


def require_current_bundle_selection_v2(bundle,package_root,*,require_selected_python=False,authority_private_config=False):
    """Reread actual selection before process registration; no admission grant."""
    selected=getattr(bundle,'package_selection',None)
    if selected is None:return None
    directory=Path(bundle.tls_profile.client_private_key).parent
    binding=validate_profile_cohort_binding_v2(read_installed_json_v1(directory/BINDING_NAME),directory)
    files=InstalledPackageSelectionFilesV2(control_directory=binding['control_directory'])
    current,cohort,configuration=(files.read_selected_configuration_cohort_v2() if authority_private_config
        else files.read_selected_host_cohort_v2())
    if (current!=selected or cohort.credential_profile_directory!=str(directory)
            or current.installation_id!=bundle.installation_policy.installation_id
            or current.manifest_sha256!=bundle.installation_policy.manifest_digest
            or Path(cohort.credential_profile_directory).name!=bundle.tls_profile.profile_id
            or str(Path(package_root))!=cohort.package.package_root):
        raise AuthorityUnavailable('process configuration does not match selected cohort')
    if require_selected_python and not Path(__file__).absolute().is_relative_to(Path(package_root)):
        raise AuthorityUnavailable('process Python code is not from selected package root')
    return current
