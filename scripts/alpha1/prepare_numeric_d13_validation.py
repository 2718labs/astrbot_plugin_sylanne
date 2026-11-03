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
V10_SCHEMA='sylanne.test.beta1.numeric-d13-v10-v7-256-declarations.v1'
V10_COMPOSITE_SCHEMA='sylanne.beta1.protected-numeric-d13-v10-v7-256-suite.v1'
V10_ORDER=('numeric','d13_full','sdk_v10_d13_v7_256')

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

def proposal_v10(source):
    value=proposal(source)
    value.update(schema=V10_SCHEMA,native_sha256=None,source_inventory_sha256=None,
        composite_evidence_directory=None,child_runs=[dict(id=kind,spec=None,timeout_seconds=None)for kind in V10_ORDER])
    for node in value['nodes']:node['d13_counter_assets']=None
    return value


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
    v10=declaration.get('schema')==V10_SCHEMA
    fields={'schema','suite_id','package_sha256','manifest_sha256','engineering_source_pin','recall_payload','nodes'}
    if v10:fields|={'native_sha256','source_inventory_sha256','composite_evidence_directory','child_runs'}
    if(set(declaration)!=fields
            or declaration['schema']!=(V10_SCHEMA if v10 else SCHEMA) or declaration['package_sha256']!=args.package_sha256
            or declaration['manifest_sha256']!=args.manifest_sha256
            or declaration['engineering_source_pin']!=args.engineering_inventory_sha256):
        raise ValueError('exact approved fresh suite declaration/pins required')
    expected=fixed_entries(source)
    if type(declaration['nodes'])is not list or len(declaration['nodes'])!=len(expected):raise ValueError('all fifteen original node declarations required')
    package,_=pinned(args.package,args.package_sha256)
    installed=args.installed_root.resolve(strict=True);_,manifest_raw=pinned(installed/'release-manifest.json',args.manifest_sha256)
    manifest=json.loads(manifest_raw)
    if v10 and (declaration['native_sha256']!=manifest['native']['sha256']
            or declaration['source_inventory_sha256']!=manifest['source_inventory']['sha256']):
        raise ValueError('explicit fresh native/source inventory pins required')
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
        node_fields={'fixture_kind','node','scenario','before_root_uuid','original_budget','profile_policies'}
        if v10:node_fields.add('d13_counter_assets')
        if set(value)!=node_fields or(value['fixture_kind'],value['node'],value['scenario'])!=(family,node,scenario):
            raise ValueError('fixed node selection differs from approved declaration')
        budget=value['original_budget']
        if set(budget)!={'currency','limits','max_ceiling','allowed_work_kinds','absolute_valid_until_utc'}:raise ValueError('original budget declaration fields differ')
        typed=Beta1OriginalRootBudgetTemplateV3(budget['currency'],tuple(sorted(budget['limits'].items())),
            tuple(sorted(budget['max_ceiling'].items())),tuple(budget['allowed_work_kinds']),budget['absolute_valid_until_utc'])
        extra={}
        if v10:
            from sylanne3.host.model_workflows_v10 import model_workflows_v10_from_payload
            from sylanne3.authority_service.d13_installed_counter_factory_v1 import InstalledD13CounterAssetsV2
            from sylanne3.runtime_contracts import NamespaceId
            model_workflows_v10_from_payload(value['profile_policies']['model_workflows'])
            raw_assets=value['d13_counter_assets']
            if type(raw_assets)is not dict:raise ValueError('actual protected Counter asset declarations required for every fresh node')
            extra['d13_counter_assets']=InstalledD13CounterAssetsV2(**{**raw_assets,'namespace':NamespaceId(**raw_assets['namespace'])})
        templates.append(Beta1ProtectedNodeTemplateV3(family,node,scenario,args.setup_root/scenario,
            value['before_root_uuid'],typed,value['profile_policies'],ns,'installation-reply','lease-'+ns.persona_id,'grant-reply',1,**extra))
    result=prepare_protected_beta1_fixture_suite_v3(installed_root=installed,frozen_rewrite_root=source/'rewrite',
        setup_root=args.setup_root,sdk_root=args.sdk_root.resolve(strict=True),recall_payload=declaration['recall_payload'],
        runner_user=args.runner_user,suite_id=declaration['suite_id'],package_archive=package,
        package_sha256=args.package_sha256,manifest_sha256=args.manifest_sha256,
        engineering_inventory_sha256=args.engineering_inventory_sha256,node_templates=tuple(templates),
        expected_runtime_scope='backend-beta1-server-test')
    if v10:
        # The descriptor contains only node/setup locators. Match the existing
        # Root reader's exact 0644 metadata mode; old suite products are untouched.
        Path(result['suite_file']).chmod(0o644)
        result.update(_prepare_v10_composite_v1(args,declaration,result,manifest,source))
    result.update(approved_declarations_sha256=args.approved_declarations_sha256,
        business_or_provider_executed=False,server_acceptance='NOT_RUN')
    return result

def _prepare_v10_composite_v1(args,declaration,prepared,manifest,source):
    """Derive observed setup pins from approved original inputs, without running a node."""
    from dataclasses import asdict
    from rewrite.host_tests.alpha1 import owned_resource_profile_v1 as profile
    from rewrite.host_tests.alpha1.c09_root_phase_harness_v3 import _canonical
    runs=declaration['child_runs']
    if type(runs)is not list or len(runs)!=3:raise ValueError('three independent approved child specifications required')
    children=[]
    for row,kind in zip(runs,V10_ORDER,strict=True):
        if set(row)!={'id','spec','timeout_seconds'}or row['id']!=kind or type(row['spec'])is not dict:
            raise ValueError('closed original child run declaration required')
        if type(row['timeout_seconds'])is not int or not 1<=row['timeout_seconds']<=1000:
            raise ValueError('explicit original bounded child timeout required')
        raw=dict(row['spec'])
        if(raw['fixture_kind']!=kind or raw['package_path']!=str(args.package.resolve(strict=True))
                or raw['package_sha256']!=args.package_sha256 or raw['manifest_sha256']!=args.manifest_sha256
                or raw['frozen_rewrite_root']!=str(source/'rewrite')
                or raw['engineering_inventory_sha256']!=args.engineering_inventory_sha256
                or raw['suite_contract']!=V10_COMPOSITE_SCHEMA):
            raise ValueError('approved child differs from the actual fresh snapshot')
        if kind!='sdk_v10_d13_v7_256':
            if raw['phase_fixture_setup']is not None or raw['phase_fixture_setup_sha256']is not None:
                raise ValueError('fresh full15 setup pins are produced once; do not reuse old descriptors')
            raw.update(phase_fixture_setup=prepared['suite_file'],phase_fixture_setup_sha256=prepared['suite_sha256'])
        spec=profile.OwnedResourceRunV1(**raw)
        profile._pin_inputs_in_child(spec)
        children.append(dict(id=kind,runner='run_owned_resource_profile_v1',spec_schema='sylanne.owned-resource-run.v1',
            spec=asdict(spec),spec_sha256=digest(_canonical(asdict(spec))),timeout_seconds=row['timeout_seconds']))
    if len({row['spec']['operation_id']for row in children})!=3:
        raise ValueError('three distinct independently approved resource operations required')
    workflow_profiles=[]
    for node in prepared['nodes']:
        _,raw=pinned(node['setup_file'],node['setup_sha256']);setup=json.loads(raw)
        path=Path(setup['profile_root'])/setup['profile_id']/'profile.json';body=path.read_bytes()
        workflows=json.loads(body)['model_workflows']
        from sylanne3.host.model_workflows_v10 import model_workflows_v10_from_payload
        actual=model_workflows_v10_from_payload(workflows)
        workflow_profiles.append(dict(node=node['node'],path=str(path),sha256=digest(body),workflow_sha256=digest(_canonical(workflows)),
            type=type(actual).__name__,version=actual.version))
    value=dict(schema=V10_COMPOSITE_SCHEMA,suite_id=declaration['suite_id'],
        pins=dict(package_sha256=args.package_sha256,manifest_sha256=args.manifest_sha256,
            native_sha256=manifest['native']['sha256'],source_inventory_sha256=manifest['source_inventory']['sha256'],
            engineering_inventory_sha256=args.engineering_inventory_sha256),
        fixed_order=list(V10_ORDER),children=children,workflow_profiles=workflow_profiles,
        coverage={'numeric':10,'d13_full':5,'sdk_v10_d13_v7_256':1,'screen_deep':'NOT_RUN'},
        evidence_directory=declaration['composite_evidence_directory'])
    path=args.setup_root/'v10-composite.json';data=_canonical(value)
    with os.fdopen(os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600),'wb')as stream:
        stream.write(data);stream.flush();os.fsync(stream.fileno())
    return dict(composite_file=str(path),composite_sha256=digest(data),composite_node_count=16,
        screen_deep_execution='NOT_RUN',composite_execution='NOT_RUN')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--template',action='store_true')
    parser.add_argument('--suite-version',choices=(4,10),type=int,default=4)
    parser.add_argument('--source-root',type=Path,default=Path(__file__).resolve().parents[2])
    for name in ('package','installed-root','sdk-root','setup-root','approved-declarations'):parser.add_argument('--'+name,type=Path)
    for name in ('package-sha256','manifest-sha256','engineering-inventory-sha256','approved-declarations-sha256'):parser.add_argument('--'+name)
    parser.add_argument('--runner-user',default='ubuntu')
    args=parser.parse_args()
    if args.template:
        print(json.dumps((proposal_v10 if args.suite_version==10 else proposal)(args.source_root.resolve(strict=True)),ensure_ascii=False,indent=2));return 0
    if any(getattr(args,name)is None for name in ('package','installed_root','sdk_root','setup_root','approved_declarations',
            'package_sha256','manifest_sha256','engineering_inventory_sha256','approved_declarations_sha256')):
        parser.error('actual package/installed/source/SDK roots, external pins, fresh setup root and approved initial declarations are required')
    print(json.dumps(prepare(args),sort_keys=True));return 0

if __name__=='__main__':raise SystemExit(main())
