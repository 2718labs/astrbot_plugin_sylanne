"""Stage a SHA-pinned candidate without selecting it or changing any credentials.

Run through the fixed installed stage entry. A later signed Owner acceptance
and privileged maintenance operation are still required to activate this code.
"""
import argparse
from copy import deepcopy
from dataclasses import asdict
import fcntl
import hashlib
import json
import os
from pathlib import Path
import sys
from uuid import uuid4
import zipfile
sys.dont_write_bytecode=True
ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT))
from _runtime_bootstrap import load_canonical_runtime_v1
load_canonical_runtime_v1(ROOT)


def stage(args):
    from sylanne3.authority_service.linux_installation_security_v1 import require_linux_administrator_v1,opened_installed_file_v1,read_installed_json_v1
    from sylanne3.authority_service.d12_package_files_v2 import InstalledPackageSelectionFilesV2,RegisteredPackageV2,_canonical,_digest,_protected_directory
    from sylanne3.authority_service.d12_configuration_cohort_v2 import ConfigurationFileV2,RegisteredConfigurationCohortV2,COHORT_SCHEMA,derive_cohort_identity_commitment_v2,read_verified_configuration_cohort_v2
    from sylanne3.authority_service.d12_fixed_supervisor_policy_v2 import read_fixed_supervisor_policy_v2
    from scripts.alpha1.install_linux import archive_manifest,write
    require_linux_administrator_v1()
    files=InstalledPackageSelectionFilesV2(control_directory='/etc/sylanne/maintenance')
    fixed,_,_=read_fixed_supervisor_policy_v2(files)
    if ROOT!=Path(fixed['bootstrap_root'])/'runtime':raise RuntimeError('staging must use fixed installed bootstrap code')
    manifest=archive_manifest(args.package,args.package_sha256,args.manifest_sha256)
    with opened_installed_file_v1(files.control_directory/'executor.lock',private=True,allowed_gid=0) as fd:
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        selected,old,configuration=files.read_selected_configuration_cohort_v2()
        installation,registered=files.read_registered_cohorts_v2()
        matches=[c for c in registered if c.package.manifest_sha256==args.manifest_sha256]
        if matches:
            if len(matches)!=1:raise RuntimeError('ambiguous existing candidate')
            read_verified_configuration_cohort_v2(matches[0])
            return {'stage':'registered_only','cohort_ref':matches[0].cohort_ref,'selection_changed':False}
        if len(registered)>=128:raise RuntimeError('installed candidate registry bound reached')
        destination=Path('/opt/sylanne/releases')/args.manifest_sha256
        parent_fd=_protected_directory(destination.parent.parent)
        os.close(parent_fd)
        destination.parent.mkdir(mode=0o755,exist_ok=True)
        parent_fd=_protected_directory(destination.parent)
        os.close(parent_fd)
        if destination.exists() or destination.is_symlink():raise FileExistsError('existing interrupted candidate is not overwritten')
        destination.mkdir(mode=0o755)
        with zipfile.ZipFile(args.package) as archive:archive.extractall(destination)
        for directory,dirs,names in os.walk(destination):
            os.chmod(directory,0o755)
            for name in names:
                path=Path(directory)/name;os.chmod(path,0o644)
                with path.open('rb') as stream:os.fsync(stream.fileno())
        package=RegisteredPackageV2('release:'+args.manifest_sha256,str(destination),args.manifest_sha256,manifest['package_version'])
        files.verify_registered_package_v2(package)
        directory=files.control_directory/'cohorts'/args.manifest_sha256
        parent_fd=_protected_directory(directory.parent)
        os.close(parent_fd)
        directory.mkdir(mode=0o755)
        deployment=deepcopy(configuration['deployment']);assets=deepcopy(configuration['assets']);profile=deepcopy(configuration['host_profile'])
        deployment.update(package_root=str(destination),trusted_manifest_sha256=args.manifest_sha256,assets_path=str(directory/'assets.json'))
        assets['installations_v2'][0]['manifest_digest']=args.manifest_sha256
        assets['c04_installations_v3'][0].update(package_root=str(destination),formal_manifest_sha256=args.manifest_sha256)
        profile['installation_policy']['manifest_digest']=args.manifest_sha256
        identity=derive_cohort_identity_commitment_v2(deployment=deployment,assets=assets,profile=profile,
            package=package,credential_profile_directory=old.credential_profile_directory)
        if identity!=old.identity_commitment:raise RuntimeError('candidate staging cannot change non-package configuration')
        entries=[]
        for role,value in (('deployment',deployment),('assets',assets),('host_profile',profile)):
            path=directory/(role+'.json');data=_canonical(value);write(path,data,mode=0o644 if role=='host_profile' else 0o600)
            entries.append(ConfigurationFileV2(role,str(path),hashlib.sha256(data).hexdigest()))
        body=dict(schema=COHORT_SCHEMA,cohort_ref='cohort:'+args.manifest_sha256,installation_id=installation,
            package=asdict(package),files=[asdict(item) for item in entries],credential_profile_directory=old.credential_profile_directory,
            compatibility_plan_ref=old.compatibility_plan_ref,supervisor_policy_digest=old.supervisor_policy_digest,identity_commitment=identity)
        candidate=RegisteredConfigurationCohortV2(**{**body,'package':package,'files':tuple(entries),'cohort_digest':_digest(body)})
        read_verified_configuration_cohort_v2(candidate)
        current,_,_=files.read_selected_configuration_cohort_v2()
        if current!=selected:raise RuntimeError('selection changed during non-activating staging')
        registry=read_installed_json_v1(files.control_directory/'registry.json')
        if registry['cohorts']!=json.loads(_canonical([asdict(item) for item in registered])):
            raise RuntimeError('candidate registry changed during staging')
        registry['cohorts'].append(asdict(candidate))
        temp=files.control_directory/('.registry-'+str(uuid4())+'.tmp')
        write(temp,_canonical(registry),mode=0o644)
        os.replace(temp,files.control_directory/'registry.json')
        for path in (directory,directory.parent,destination,destination.parent,files.control_directory):
            fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY)
            try:os.fsync(fd)
            finally:os.close(fd)
        if files.read_registered_cohort_v2(candidate.cohort_ref)!=(installation,candidate):raise RuntimeError('registered candidate reread differs')
        if files.read_selected_configuration_cohort_v2()[0]!=selected:raise RuntimeError('staging changed selection unexpectedly')
        return {'stage':'registered_only','cohort_ref':candidate.cohort_ref,'manifest_sha256':package.manifest_sha256,'selection_changed':False}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--package',type=Path,required=True)
    parser.add_argument('--package-sha256',required=True)
    parser.add_argument('--manifest-sha256',required=True)
    args=parser.parse_args()
    print(json.dumps(stage(args),sort_keys=True,separators=(',',':')))


if __name__=='__main__':main()
