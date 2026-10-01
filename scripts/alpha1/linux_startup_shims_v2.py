"""Fixed startup shim sources, installed outside every selectable package tree.

Generating these files does not install a service or authorize maintenance.
A compatible switch must preserve the fixed Host config schema/requirements;
changing that bootstrap surface requires a separately qualified update.
"""
from __future__ import annotations
from pathlib import Path
import re


def startup_shim_sources_v2(*,profile_id,bootstrap_root='/opt/sylanne/bootstrap',control_directory='/etc/sylanne/maintenance'):
    if re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}',profile_id) is None:
        raise ValueError('installed profile required')
    for value in (bootstrap_root,control_directory):
        if not Path(value).is_absolute() or '..' in Path(value).parts:
            raise ValueError('fixed absolute bootstrap paths required')
    probe = f'''"""Read the one independently registered protected startup cohort."""
import json
from pathlib import Path
import sys
sys.dont_write_bytecode=True
sys.path.insert(0,{str(Path(bootstrap_root)/'runtime')!r})
from _runtime_bootstrap import load_canonical_runtime_v1
load_canonical_runtime_v1({str(Path(bootstrap_root)/'runtime')!r})
from sylanne3.authority_service.d12_package_files_v2 import InstalledPackageSelectionFilesV2
from dataclasses import asdict
files=InstalledPackageSelectionFilesV2(control_directory={control_directory!r})
if sys.argv[1:]==['--host']:
    selection,cohort,configuration=files.read_selected_host_cohort_v2()
    scope='host_public_only'
elif not sys.argv[1:]:
    selection,cohort,configuration=files.read_selected_configuration_cohort_v2()
    scope='authority_full_cohort'
else: raise RuntimeError('fixed startup probe mode required')
if Path(cohort.credential_profile_directory).name!={profile_id!r}:
    raise RuntimeError('selected profile differs from fixed startup shim')
paths={{entry.role:entry.path for entry in cohort.files}}
print(json.dumps(dict(selection=asdict(selection),package_root=cohort.package.package_root,
    deployment_path=paths['deployment'],profile_id={profile_id!r},verification_scope=scope),sort_keys=True,separators=(',',':')))
'''
    authority = f'''"""Fixed independent Authority launcher; no candidate-selected argv."""
import json
import os
from pathlib import Path
import subprocess
import sys
sys.dont_write_bytecode=True
result=subprocess.run([sys.executable,'-I','-B',{str(Path(bootstrap_root)/'selection_probe.py')!r}],
    check=True,capture_output=True,text=True,timeout=120)
if len(result.stdout)>65536: raise RuntimeError('startup selection response exceeds bound')
value=json.loads(result.stdout)
if set(value)!={{'selection','package_root','deployment_path','profile_id','verification_scope'}} or value['profile_id']!={profile_id!r}:
    raise RuntimeError('fixed startup selection fields differ')
if value['verification_scope']!='authority_full_cohort': raise RuntimeError('Authority requires complete private configuration verification')
selection=value['selection']
entry=Path(value['package_root'])/'scripts'/'alpha1'/'authority_linux_service.py'
os.execv(sys.executable,[sys.executable,'-B',str(entry),'--config',value['deployment_path'],
    '--selection-revision',str(selection['revision']),'--cohort-digest',selection['cohort_digest']])
'''
    plugin_init = f'''"""Fixed AstrBot package shim; a fresh Host resolves one protected cohort."""
import importlib
import json
from pathlib import Path
import subprocess
import sys
_probe=[sys.executable,'-I','-B',{str(Path(bootstrap_root)/'selection_probe.py')!r},'--host']
_result=subprocess.run(_probe,check=True,capture_output=True,text=True,timeout=120)
if len(_result.stdout)>65536: raise RuntimeError('startup selection response exceeds bound')
_selected=json.loads(_result.stdout)
if set(_selected)!={{'selection','package_root','deployment_path','profile_id','verification_scope'}} or _selected['profile_id']!={profile_id!r}:
    raise RuntimeError('fixed startup selection fields differ')
if _selected['verification_scope']!='host_public_only': raise RuntimeError('explicit Host public startup evidence required')
_root=Path(_selected['package_root'])
if not _root.is_absolute() or _root.is_symlink(): raise RuntimeError('canonical selected package required')
# This is a real package search path, not a mutable filesystem symlink. The
# fixed shim imports no old sylanne3 runtime into this Host process.
__path__=[str(_root)]
_main=importlib.import_module(__name__+'.main')
if Path(_main.__file__).absolute()!=_root/'main.py':
    raise RuntimeError('Host imported a different package main')
from astrbot.core.star.star_manager import PluginManager as _PluginManager
from astrbot.core.star.star import star_map as _star_map
_metadata=_PluginManager._load_plugin_metadata(str(_root))
if _metadata is None or _metadata.name!='astrbot_plugin_sylanne':
    raise RuntimeError('selected package plugin identity differs')
_actual=_star_map.get(_main.__name__)
if _actual is None or _actual.star_cls_type is not _main.Sylanne3Plugin:
    raise RuntimeError('selected plugin class did not register through real AstrBot')
for _name in ('name','author','desc','short_desc','version','repo','display_name','support_platforms','astrbot_version','pages','i18n'):
    setattr(_actual,_name,getattr(_metadata,_name))
_after=subprocess.run(_probe,check=True,capture_output=True,text=True,timeout=120)
if len(_after.stdout)>65536 or json.loads(_after.stdout)!=_selected:
    raise RuntimeError('selected package changed while importing Host')
# Authority still independently verifies current process/storage/native readiness.
'''
    maintenance = f'''"""Fixed privileged maintenance entry; only an accepted operation UUID."""
from pathlib import Path
import runpy
import sys
from uuid import UUID
sys.dont_write_bytecode=True
if len(sys.argv)!=3 or sys.argv[1]!='--operation': raise RuntimeError('exact accepted operation required')
_operation=UUID(sys.argv[2])
if _operation.version!=4 or str(_operation)!=sys.argv[2]: raise RuntimeError('canonical operation UUID4 required')
sys.path.insert(0,{str(Path(bootstrap_root)/'runtime')!r})
from _runtime_bootstrap import load_canonical_runtime_v1
load_canonical_runtime_v1({str(Path(bootstrap_root)/'runtime')!r})
runpy.run_path({str(Path(bootstrap_root)/'runtime'/'scripts'/'alpha1'/'authority_linux_maintain.py')!r},run_name='__main__')
'''
    def operator_entry(script, public):
        probe_args=['--host'] if public else []
        fixed=['--profile',profile_id] if public else None
        return f'''"""Fixed current-cohort operator entry."""
import json
import os
from pathlib import Path
import subprocess
import sys
sys.dont_write_bytecode=True
if any(a in {{'--config','--profile','--package-root'}} or a.startswith(('--config=','--profile=','--package-root=')) for a in sys.argv[1:]):
    raise RuntimeError('fixed current-cohort scope cannot be overridden')
result=subprocess.run([sys.executable,'-I','-B',{str(Path(bootstrap_root)/'selection_probe.py')!r},*{probe_args!r}],
    check=True,capture_output=True,text=True,timeout=120)
if len(result.stdout)>65536:raise RuntimeError('bounded fixed selection required')
value=json.loads(result.stdout)
if set(value)!={{'selection','package_root','deployment_path','profile_id','verification_scope'}} or value['profile_id']!={profile_id!r}:
    raise RuntimeError('fixed operator selection differs')
if value['verification_scope']!={('host_public_only' if public else 'authority_full_cohort')!r}:
    raise RuntimeError('operator evidence scope differs')
entry=Path(value['package_root'])/'scripts'/'alpha1'/{script!r}
fixed={fixed!r}
if fixed is None:fixed=['--config',value['deployment_path']]
os.execv(sys.executable,[sys.executable,'-B',str(entry),*fixed,*sys.argv[1:]])
'''
    staging = f'''"""Fixed candidate staging entry; never activates a package."""
from pathlib import Path
import runpy
import sys
sys.dont_write_bytecode=True
sys.path.insert(0,{str(Path(bootstrap_root)/'runtime')!r})
from _runtime_bootstrap import load_canonical_runtime_v1
load_canonical_runtime_v1({str(Path(bootstrap_root)/'runtime')!r})
runpy.run_path({str(Path(bootstrap_root)/'runtime'/'scripts'/'alpha1'/'stage_linux_package.py')!r},run_name='__main__')
'''
    return {'selection_probe.py':probe,'authority_entry.py':authority,'maintenance_entry.py':maintenance,'stage_entry.py':staging,
        'control_entry.py':operator_entry('authority_linux_control.py',True),
        'admin_entry.py':operator_entry('authority_linux_admin.py',False),
        'host/__init__.py':plugin_init,'host/main.py':"raise RuntimeError('unselected bootstrap main must never execute')\n"}
