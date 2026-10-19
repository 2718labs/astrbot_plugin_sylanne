"""Prepare a fresh, explicitly approved engineering Numeric/D13 suite. Never shipped in the plugin."""
from pathlib import Path
import argparse
import ast
import hashlib
import json
import os
import sys
from uuid import uuid4

SCHEMA='sylanne.test.beta1.initial-suite-declarations.v4'

def digest(raw):return hashlib.sha256(raw).hexdigest()

def fixed_entries(source):
    profile=ast.parse((source/'rewrite/host_tests/alpha1/owned_resource_profile_v1.py').read_text())
    scenarios=ast.parse((source/'rewrite/host_tests/alpha1/c09_root_phase_harness_v3.py').read_text())
    def assigned(tree,name):
        return ast.literal_eval(next(n.value for n in tree.body if isinstance(n,ast.Assign)
            and any(isinstance(t,ast.Name)and t.id==name for t in n.targets)))
    registry=next(n.value for n in profile.body if isinstance(n,ast.Assign)
        and any(isinstance(t,ast.Name)and t.id=='FIXTURE_NODES'for t in n.targets))
    nodes={ast.literal_eval(key):ast.literal_eval(value)for key,value in zip(registry.keys,registry.values,strict=True)
        if isinstance(key,ast.Constant)and key.value in {'numeric','d13','d13_v6'}}
    numeric=assigned(scenarios,'_BETA1_NUMERIC_SCENARIOS');d13=assigned(scenarios,'_BETA1_D13_SCENARIOS')
    return tuple(zip(('numeric',)*len(numeric)+('d13_full',)*len(d13),
        nodes['numeric']+nodes['d13']+nodes['d13_v6'],numeric+d13,strict=True))

def proposal(source):
    return dict(schema=SCHEMA,suite_id=str(uuid4()),package_sha256=None,manifest_sha256=None,
        engineering_source_pin=None,recall_payload=None,nodes=[dict(fixture_kind=family,node=node,scenario=scenario,
            before_root_uuid=str(uuid4()),original_budget=dict(currency=None,limits={},max_ceiling={},
                allowed_work_kinds=[],absolute_valid_until_utc=None),profile_policies={})
            for family,node,scenario in fixed_entries(source)])

def pinned(path,pin):
    path=Path(path).resolve(strict=True);raw=path.read_bytes()
    if digest(raw)!=pin:raise ValueError('externally approved input hash differs: '+str(path))
    return path,raw

def prepare(args):
    if os.name!='posix'or os.geteuid()!=0:raise PermissionError('fresh isolated Linux Root preparation required')
    source=args.source_root.resolve(strict=True)
    inventory_path=source.parent/'frozen-engineering-inventory.json'
    inventory=json.loads(inventory_path.read_bytes())
    canonical=json.dumps(inventory['files'],sort_keys=True,separators=(',',':'),ensure_ascii=True).encode()
    if(inventory['schema']!='sylanne.engineering-source-inventory.v1'or inventory['sha256']!=digest(canonical)
            or inventory['sha256']!=args.engineering_inventory_sha256):raise ValueError('frozen engineering pin differs')
    for row in inventory['files']:
        member=source/row['path']
        if(member.is_symlink()or not member.resolve(strict=True).is_relative_to(source)
                or len(member.read_bytes())!=row['bytes']or digest(member.read_bytes())!=row['sha256']):
            raise ValueError('frozen engineering source differs: '+row['path'])
    if Path(__file__).resolve()!=source/'scripts/alpha1/prepare_numeric_d13_validation.py':
        raise ValueError('execute the exact frozen engineering preparer')
    approval_path,raw=pinned(args.approved_declarations,args.approved_declarations_sha256)
    for entry in (approval_path,*approval_path.parents):
        info=entry.lstat()
        if entry.is_symlink()or info.st_uid!=0 or info.st_mode&0o022:raise ValueError('approval ancestry must remain Root protected')
    declaration=json.loads(raw)
    if(set(declaration)!={'schema','suite_id','package_sha256','manifest_sha256','engineering_source_pin','recall_payload','nodes'}
            or declaration['schema']!=SCHEMA or declaration['package_sha256']!=args.package_sha256
            or declaration['manifest_sha256']!=args.manifest_sha256
            or declaration['engineering_source_pin']!=args.engineering_inventory_sha256):
        raise ValueError('exact approved fresh suite declaration/pins required')
    expected=fixed_entries(source)
    if type(declaration['nodes'])is not list or len(declaration['nodes'])!=len(expected):raise ValueError('all fifteen original node declarations required')
    package,_=pinned(args.package,args.package_sha256)
    installed=args.installed_root.resolve(strict=True);_,manifest_raw=pinned(installed/'release-manifest.json',args.manifest_sha256)
    manifest=json.loads(manifest_raw)
    if(manifest['package_version'],manifest['build_mode'])!=('3.0.0-beta1','beta1-candidate'):raise ValueError('current Beta1 package required')
    for row in manifest['files']:
        member=installed/row['path'];body=member.read_bytes()
        if member.is_symlink()or len(body)!=row['bytes']or digest(body)!=row['sha256']:raise ValueError('actual extracted installation differs')
    sys.path[:0]=[str(installed),str(installed/'rewrite'),str(args.sdk_root.resolve(strict=True)),str(source/'rewrite/tests/alpha1/integration')]
    from _runtime_bootstrap import load_canonical_runtime_v1
    load_canonical_runtime_v1(installed)
    # Runtime ZIP intentionally omits engineering tests. Bridge only those two
    # verified source families; never append engineering paths to sylanne3.
    import importlib.machinery,importlib.util,rewrite
    if Path(rewrite.__file__).resolve()!=installed/'rewrite/__init__.py':
        raise ValueError('preparation product namespace came from outside selected package')
    for leaf in ('tests','host_tests'):
        name='rewrite.'+leaf
        spec=importlib.machinery.ModuleSpec(name,loader=None,is_package=True)
        spec.submodule_search_locations=[str(source/'rewrite'/leaf)]
        module=importlib.util.module_from_spec(spec);sys.modules[name]=module;setattr(rewrite,leaf,module)
    from m1_artifact_draft_acceptance_support_v1 import (Beta1OriginalRootBudgetTemplateV3,
        Beta1ProtectedNodeTemplateV3,prepare_protected_beta1_fixture_suite_v3)
    from sylanne3.host.identity import astrbot_namespace
    ns=astrbot_namespace('platform-1','10001','persona-reply');templates=[]
    for value,(family,node,scenario)in zip(declaration['nodes'],expected,strict=True):
        if set(value)!={'fixture_kind','node','scenario','before_root_uuid','original_budget','profile_policies'}or(value['fixture_kind'],value['node'],value['scenario'])!=(family,node,scenario):
            raise ValueError('fixed node selection differs from approved declaration')
        budget=value['original_budget']
        if set(budget)!={'currency','limits','max_ceiling','allowed_work_kinds','absolute_valid_until_utc'}:raise ValueError('original budget declaration fields differ')
        typed=Beta1OriginalRootBudgetTemplateV3(budget['currency'],tuple(sorted(budget['limits'].items())),
            tuple(sorted(budget['max_ceiling'].items())),tuple(budget['allowed_work_kinds']),budget['absolute_valid_until_utc'])
        templates.append(Beta1ProtectedNodeTemplateV3(family,node,scenario,args.setup_root/scenario,
            value['before_root_uuid'],typed,value['profile_policies'],ns,'installation-reply','lease-'+ns.persona_id,'grant-reply',1))
    result=prepare_protected_beta1_fixture_suite_v3(installed_root=installed,frozen_rewrite_root=source/'rewrite',
        setup_root=args.setup_root,sdk_root=args.sdk_root.resolve(strict=True),recall_payload=declaration['recall_payload'],
        runner_user=args.runner_user,suite_id=declaration['suite_id'],package_archive=package,
        package_sha256=args.package_sha256,manifest_sha256=args.manifest_sha256,
        engineering_inventory_sha256=args.engineering_inventory_sha256,node_templates=tuple(templates),
        expected_runtime_scope='backend-beta1-server-test')
    result.update(approved_declarations_sha256=args.approved_declarations_sha256,
        business_or_provider_executed=False,server_acceptance='NOT_RUN')
    return result

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--template',action='store_true')
    parser.add_argument('--source-root',type=Path,default=Path(__file__).resolve().parents[2])
    for name in ('package','installed-root','sdk-root','setup-root','approved-declarations'):parser.add_argument('--'+name,type=Path)
    for name in ('package-sha256','manifest-sha256','engineering-inventory-sha256','approved-declarations-sha256'):parser.add_argument('--'+name)
    parser.add_argument('--runner-user',default='ubuntu')
    args=parser.parse_args()
    if args.template:
        print(json.dumps(proposal(args.source_root.resolve(strict=True)),ensure_ascii=False,indent=2));return 0
    if any(getattr(args,name)is None for name in ('package','installed_root','sdk_root','setup_root','approved_declarations',
            'package_sha256','manifest_sha256','engineering_inventory_sha256','approved_declarations_sha256')):
        parser.error('actual package/installed/source/SDK roots, external pins, fresh setup root and approved initial declarations are required')
    print(json.dumps(prepare(args),sort_keys=True));return 0

if __name__=='__main__':raise SystemExit(main())
