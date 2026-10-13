"""Explicit installed Root lifetime service and resource approval operations."""
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[2]
sys.dont_write_bytecode=True
sys.path.insert(0,str(ROOT))
from _runtime_bootstrap import load_canonical_runtime_v1
load_canonical_runtime_v1(ROOT)

def main():
    import argparse
    from sylanne3.authority_service.installed_root_lifetime_observer_v3 import (
        SPEC_PATH,read_installed_root_lifetime_spec_v3,run_installed_lifetime_v3,
        run_root_namespace_bootstrap_v3,install_root_lifetime_resource_approval_v3,request_installed_root_start_v3,install_root_lifetime_v3)
    parser=argparse.ArgumentParser()
    parser.add_argument('--namespace-bootstrap',action='store_true')
    sub=parser.add_subparsers(dest='operation')
    sub.add_parser('start-root')
    approval=sub.add_parser('install-resource-approval')
    install=sub.add_parser('install-lifetime')
    install.add_argument('--launch-scope',required=True)
    for command in (approval,install):
        for field in ('output','operation-ref','unit-name','cgroup-path','cpu-max','memory-max','pids-max','deadline-utc'):
            command.add_argument('--'+field,required=True)
    args=parser.parse_args()
    if args.operation=='install-lifetime':
        if args.namespace_bootstrap:parser.error('namespace bootstrap has no administrative operation')
        install_root_lifetime_v3(args.launch_scope,resource_original_path=args.output,operation_ref=args.operation_ref,
            unit_name=args.unit_name,cgroup_path=args.cgroup_path,cpu_max=args.cpu_max,memory_max=args.memory_max,
            pids_max=args.pids_max,deadline_utc=args.deadline_utc)
        return
    spec=read_installed_root_lifetime_spec_v3(SPEC_PATH)
    if args.namespace_bootstrap:
        if args.operation is not None:parser.error('namespace bootstrap has no administrative operation')
        run_root_namespace_bootstrap_v3(spec)
    elif args.operation=='install-resource-approval':
        install_root_lifetime_resource_approval_v3(args.output,spec=spec,operation_ref=args.operation_ref,
            unit_name=args.unit_name,cgroup_path=args.cgroup_path,cpu_max=args.cpu_max,
            memory_max=args.memory_max,pids_max=args.pids_max,deadline_utc=args.deadline_utc)
    elif args.operation=='start-root':
        request_installed_root_start_v3(spec)
    else:run_installed_lifetime_v3(spec)

if __name__=='__main__':main()
