"""Actual AstrBot Manager installs/reloads pinned ZIPs in isolated processes."""
from pathlib import Path
import hashlib
import json
import os
import subprocess
import sys
from zipfile import ZipFile

import pytest


DRIVER = r'''
from pathlib import Path
import asyncio, hashlib, inspect, json, os, shutil, sys
root=Path(sys.argv[1]); mode=sys.argv[2]
if mode != 'cold_existing': root.mkdir()
(root/'tmp').mkdir(exist_ok=True)
os.environ.update(ASTRBOT_ROOT=str(root), TMPDIR=str(root/'tmp'), ASTRBOT_DISABLE_METRICS='1', ASTRBOT_RELOAD='0')
os.chdir(root);sys.path[:0]=[sys.argv[3],str(root)]
from importlib.metadata import version
assert version('astrbot')=='4.28.2'
import astrbot.core as core
from astrbot.api.star import Context
from astrbot.core.star.star_manager import PluginManager
from astrbot.core.star.star_handler import star_handlers_registry
import astrbot.core.star.star as stars
old=Path(sys.argv[4]);new=Path(sys.argv[5]);output=Path(sys.argv[6])
manifest_pin=sys.argv[7]
async def run():
    await core.db_helper.initialize(); await core.sp.initialize()
    context=Context(asyncio.Queue(),core.astrbot_config,core.db_helper,None,None,None,None,None,None,None,None)
    manager=PluginManager(context,core.astrbot_config)
    name='astrbot_plugin_sylanne'
    async def upload(path, label):
        copy=root/(label+'.zip');shutil.copyfile(path,copy)
        return await manager.install_plugin_from_file(str(copy))
    if mode=='legacy_upgrade':
        await upload(old,'old')
        import sylanne3.host.workbench_mount as mount
        prior=mount.WorkbenchHostMount; prior_root=sys.modules['sylanne3']
        await upload(new,'new')
        metadata=context.get_registered_star(name); assert metadata is not None
        instance=metadata.star_cls
        assert not hasattr(instance,'_runtime')
        assert sys.modules['sylanne3'] is prior_root and mount.WorkbenchHostMount is prior
        assert not hasattr(sys.modules['data.plugins.astrbot_plugin_sylanne.main'],'WorkbenchHostMount')
        assert len(context.registered_web_apis)==2,context.registered_web_apis
        assert all(route[2]==['GET'] or route[2]==('GET',) for route in context.registered_web_apis)
        assert (Path(manager.plugin_store_path)/name/'_restart_required.py').is_file()
        success,error=await manager.reload(name);assert success,error
        assert sys.modules['sylanne3'] is prior_root and mount.WorkbenchHostMount is prior
        assert len(context.registered_web_apis)==2
        result={'mode':mode,'installation':'PASS','new_files_retained':True,'runtime':'blocked/runtime_restart_required','same_legacy_tree_untouched':True,'same_process_reload':'PASS still maintenance','routes':2}
    else:
        if mode=='cold_existing':
            success,error=await manager.load(specified_dir_name=name);assert success,error
        else:await upload(new,'new')
        metadata=context.get_registered_star(name);assert metadata is not None
        instance=metadata.star_cls;assert hasattr(instance,'_workbench')
        assert instance._configuration is not None
        assert instance._configuration._startup_values['model_selection']['version']==1
        import sylanne3.host.workbench_mount as mount
        assert 'setup_provider' in inspect.signature(mount.WorkbenchHostMount).parameters
        assert instance._workbench.__class__ is mount.WorkbenchHostMount
        prior=mount.WorkbenchHostMount; prior_root=sys.modules['sylanne3']
        count=len(context.registered_web_apis);assert count==16,count
        assert not instance._enabled and instance._runtime is None
        assert len(instance._local_module_admission.flags)==13 and all(instance._local_module_admission.flags.values())
        assert metadata.pages==[{'name':'workbench','title':'Sylanne WebUI / 模块状态'}]
        assert instance._webui.status_v1()['state']=='listening'
        assert instance._webui.status_v1()['startup_values']=={'enabled':True,'bind':'0.0.0.0','port':2718}
        selected=instance._local_module_admission.flags; selected['d12']=False
        metadata.config.save_config({'modules':selected})
        assert instance._local_module_admission.flags['d12'] is True
        success,error=await manager.reload(name);assert success,error
        current=context.get_registered_star(name).star_cls
        assert current._local_module_admission.flags['d12'] is False
        assert current is not instance and sys.modules['sylanne3'] is prior_root
        assert current._workbench.__class__ is prior
        assert len(context.registered_web_apis)==count
        if mode=='cold_new':
            await upload(new,'same')
            assert sys.modules['sylanne3'] is prior_root
            assert len(context.registered_web_apis)==count
            current=context.get_registered_star(name).star_cls
        assert current._webui.status_v1()['state']=='listening'
        assert current._local_module_admission.flags['d12'] is False
        from astrbot.core.core_lifecycle import AstrBotCoreLifecycle
        from astrbot.core.log import LogBroker
        from astrbot.core.umop_config_router import UmopConfigRouter
        from astrbot.core.astrbot_config_mgr import AstrBotConfigManager
        from astrbot.core.persona_mgr import PersonaManager
        from astrbot.core.provider.manager import ProviderManager
        from astrbot.core.conversation_mgr import ConversationManager
        from astrbot.core.platform_message_history_mgr import PlatformMessageHistoryManager
        from astrbot.dashboard.password_state import set_dashboard_password_hashes
        from astrbot.dashboard.server import AstrBotDashboard
        import httpx, secrets
        cfg=core.astrbot_config; password='Native9!'+secrets.token_hex(16)
        cfg['dashboard']['username']='isolated-manager-admin';cfg['dashboard']['password_change_required']=False
        set_dashboard_password_hashes(cfg,password)
        life=AstrBotCoreLifecycle(LogBroker(),core.db_helper)
        life.umop_config_router=UmopConfigRouter(sp=core.sp)
        life.astrbot_config_mgr=AstrBotConfigManager(cfg,life.umop_config_router,core.sp)
        life.persona_mgr=PersonaManager(core.db_helper,life.astrbot_config_mgr)
        life.provider_manager=ProviderManager(life.astrbot_config_mgr,core.db_helper,life.persona_mgr)
        life.conversation_manager=ConversationManager(core.db_helper)
        life.platform_message_history_manager=PlatformMessageHistoryManager(core.db_helper)
        life.platform_manager=None;life.star_context=context;life.plugin_manager=manager;life.astrbot_updater=None
        dashboard=AstrBotDashboard(life,core.db_helper,asyncio.Event())
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=dashboard.asgi_app),base_url='https://manager.test') as client:
            login=await client.post('/api/v1/auth/login',json={'username':'isolated-manager-admin','password':password})
            assert login.status_code==200
            response=await client.get('/api/v1/plugins/extensions/astrbot_plugin_sylanne/workbench/v1/host-controls/v1')
            assert response.status_code==200,response.text
            controls=response.json();assert controls['schema_version']=='sylanne.host-controls.v1'
            assert len(controls['modules']['startup_values'])==13 and controls['modules']['startup_values']['d12'] is False
            assert controls['listener']['state']=='listening' and controls['business_enabled'] is False
            assert len(life.provider_manager.provider_insts)==0
        from sylanne3.native_runtime.loader import load_production_native
        package_root=Path(manager.plugin_store_path)/name
        native=load_production_native(package_root,trusted_manifest_sha256=manifest_pin)
        assert native.capabilities.abi_version==2
        assert native.production_binding.native_sha256=='2883b3bd4af107a953fe86c6ee785da1fc51688e36e7a9f5fef7d7016d91d56c'
        result={'mode':mode,'installation':'PASS','new_mount_signature':str(inspect.signature(mount.WorkbenchHostMount)),'runtime_health':current.runtime_health.status,'same_generation_reload':'PASS','canonical_type_identity_stable':True,'routes':count,'business_runtime_started':False,'native_abi':native.capabilities.abi_version,'native_sha256':native.production_binding.native_sha256,'manifest_sha256':native.production_binding.manifest_sha256,'actual_native_path':str(native.path),'native_interval_execution':'NOT RUN','module_next_reload':'PASS actualSDKsave retainsoldFrozenPolicy thennewinstanceD12false','webui_while_D12_disabled':'listening','host_controls_authenticated_route':'PASS realSDKAuthCookie13flags; specificbeforewildcard'}
    result.update(sdk='4.28.2',fixture=str(root),package_sha256=hashlib.sha256(new.read_bytes()).hexdigest(),provider_or_platform_initialized=False,model_or_sender_calls=0,scope='actual PluginManager install/load/initialize/terminate/reload; no fake manager/namespace purge; no production permissions')
    output.write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    print(json.dumps(result,ensure_ascii=False,indent=2))
    await context.get_registered_star(name).star_cls.terminate()
asyncio.run(run())
'''


def _case(tmp_path, mode, root):
    package = os.environ.get('SYLANNE_RUNTIME_RELOAD_ZIP')
    sdk = os.environ.get('SYLANNE_SDK4282_LIBRARY')
    old = os.environ.get('SYLANNE_LEGACY_PLUGIN_ZIP')
    if not all((package,sdk,old)):
        pytest.skip('requires final package, official SDK4.28.2 and legacy ZIP')
    output=tmp_path/(mode+'.json')
    with ZipFile(package) as archive:
        manifest_pin=hashlib.sha256(archive.read('release-manifest.json')).hexdigest()
    done=subprocess.run([sys.executable,'-B','-c',DRIVER,str(root),mode,sdk,old,package,str(output),manifest_pin],
        capture_output=True,text=True,timeout=90)
    (tmp_path/(mode+'.log')).write_text(done.stdout+done.stderr)
    assert done.returncode==0,done.stdout+done.stderr
    return json.loads(output.read_text())


def test_real_manager_cold_install_same_generation_reload_and_upload(tmp_path):
    result=_case(tmp_path,'cold_new',tmp_path/'cold-root')
    assert result['routes']==16 and result['model_or_sender_calls']==0


def test_real_manager_legacy_upgrade_retains_new_files_then_cold_process_uses_new_runtime(tmp_path):
    root=tmp_path/'upgrade-root'
    result=_case(tmp_path,'legacy_upgrade',root)
    assert result['runtime']=='blocked/runtime_restart_required'
    cold=_case(tmp_path,'cold_existing',root)
    assert cold['canonical_type_identity_stable'] and cold['model_or_sender_calls']==0
