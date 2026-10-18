"""B04 isolated installed SDK lifecycle driver; no model or sender acceptance.

The Host entry is registered by the explicit v3 installer. It loads the selected
plugin through the actual SDK Manager; it does not assemble runtime authority.
The private fixture controller keeps login/proof material out of evidence.
"""
from pathlib import Path
import hashlib
import json
import os
import subprocess
import sys
import time
import zipfile
import select
import socket

import pytest


SDK_HOST_ENTRY_V1 = 'from pathlib import Path\nimport asyncio, ast, hashlib, json, os, signal, socket, struct, sys, time, traceback\nfrom importlib.metadata import version\n\nROOT=Path(\'/var/lib/sylanne-b04-host\')\nos.environ.update(ASTRBOT_ROOT=str(ROOT),ASTRBOT_DISABLE_METRICS=\'1\',ASTRBOT_RELOAD=\'0\')\nos.chdir(ROOT);sys.dont_write_bytecode=True\nsys.path.insert(0,str(ROOT))\nassert version(\'astrbot\')==\'4.28.2\'\nimport astrbot.core as core\nfrom astrbot.api.star import Context\nfrom astrbot.core.core_lifecycle import AstrBotCoreLifecycle\nfrom astrbot.core.log import LogBroker\nfrom astrbot.core.umop_config_router import UmopConfigRouter\nfrom astrbot.core.astrbot_config_mgr import AstrBotConfigManager\nfrom astrbot.core.persona_mgr import PersonaManager\nfrom astrbot.core.provider.manager import ProviderManager\nfrom astrbot.core.conversation_mgr import ConversationManager\nfrom astrbot.core.platform_message_history_mgr import PlatformMessageHistoryManager\nfrom astrbot.core.config.astrbot_config import AstrBotConfig\nfrom astrbot.core.star.star_manager import PluginManager\nfrom astrbot.dashboard.server import AstrBotDashboard\nfrom astrbot.dashboard.password_state import set_dashboard_password_hashes\nimport httpx\n\ndef private_exception(label,error):\n    sys.stderr.write(label+\'\\n\'+\'\'.join(traceback.format_exception(error)))\n    sys.stderr.flush();os.fsync(sys.stderr.fileno())\n\ndef install_fence_observation():\n    installed=Path(\'/opt/sylanne/code\')\n    sys.path.insert(0,str(installed))\n    from _runtime_bootstrap import load_canonical_runtime_v1\n    load_canonical_runtime_v1(installed)\n    from sylanne3.host.v2_fence_port import V2FencePort\n    from sylanne3.host.mtls_transport import MtlsAuthorityTransport\n    import inspect,threading\n    sources=sorted({Path(inspect.getsourcefile(value)) for value in\n        (V2FencePort,MtlsAuthorityTransport,MtlsAuthorityTransport._rpc)},key=str)\n    literals={node.value for source in sources for node in ast.walk(ast.parse(source.read_text()))\n        if isinstance(node,ast.Constant) and isinstance(node.value,str)}\n    rows=[];lock=threading.Lock()\n    def record(kind,method,started,error=None,timeout=None):\n        row={\'kind\':kind,\'method\':method,\'started_utc\':started[0],\n            \'elapsed_seconds\':time.monotonic()-started[1],\'declared_timeout_seconds\':timeout}\n        if timeout is not None:\n            row[\'declared_deadline_utc\']=started[0]+timeout\n            row[\'deadline_remaining_seconds\']=timeout-row[\'elapsed_seconds\']\n        if error is not None:\n            chain=[];current=error;seen=set()\n            while current is not None and id(current) not in seen:\n                seen.add(id(current));message=str(current)\n                chain.append({\'type\':type(current).__name__,\n                    \'static_message\':message if message in literals else None,\n                    \'frames\':[{\'file\':f.filename,\'line\':f.lineno,\'function\':f.name}\n                        for f in traceback.extract_tb(current.__traceback__)]})\n                current=current.__cause__ or current.__context__\n            row[\'exception_chain\']=chain;private_exception(\'B04_V2_INTERNAL_EXCEPTION \'+kind+\' \'+method,error)\n        with lock:\n            rows.append(row)\n            path=ROOT/\'data/v2-fence-observation.json\'\n            path.write_text(json.dumps({\'sources\':[{\'path\':str(p),\'sha256\':hashlib.sha256(p.read_bytes()).hexdigest()}\n                for p in sources],\'events\':rows},separators=(\',\',\':\')))\n            with path.open(\'rb\') as stream:os.fsync(stream.fileno())\n    original_submit=V2FencePort._submit\n    def submit(self,coroutine):\n        method=coroutine.cr_code.co_name;started=(time.time(),time.monotonic())\n        try:result=original_submit(self,coroutine)\n        except BaseException as error:record(\'fence_submit\',method,started,error,self._timeout);raise\n        record(\'fence_submit\',method,started,timeout=self._timeout);return result\n    original_rpc=MtlsAuthorityTransport._rpc\n    async def transport_rpc(self,session,profile,method,*args,**kwargs):\n        started=(time.time(),time.monotonic())\n        try:result=await original_rpc(self,session,profile,method,*args,**kwargs)\n        except BaseException as error:record(\'transport_rpc\',method,started,error,profile.timeout_seconds);raise\n        record(\'transport_rpc\',method,started,timeout=profile.timeout_seconds);return result\n    V2FencePort._submit=submit;MtlsAuthorityTransport._rpc=transport_rpc\n\n\nimport aiohttp\nfrom contextlib import AsyncExitStack\nfrom functools import partial\nfrom astrbot.core.event_bus import EventBus\nfrom astrbot.core.platform.manager import PlatformManager\nfrom astrbot.core.platform.sources.aiocqhttp.aiocqhttp_platform_adapter import AiocqhttpAdapter\nfrom astrbot.core.star.star_handler import EventType,star_handlers_registry\n\nclass LocalOneBotV11:\n    def __init__(self,adapter,self_id,token):\n        self.adapter=adapter;self.self_id=str(self_id);self.token=token\n        self.actions=[];self.sender_observations=[];self.session=None;self.ws=None;self.reader=None\n        self.m1_scenario=False;self.m1_sender_id=None\n        self.m1_boundary=None;self.m1_boundary_received=False;self.m1_boundary_release=asyncio.Event()\n\n    async def start(self):\n        assert self.adapter.host==\'127.0.0.1\'\n        self.session=aiohttp.ClientSession(trust_env=False)\n        headers={\'X-Client-Role\':\'universal\',\'X-Self-ID\':self.self_id,\n            \'Authorization\':\'Bearer \'+self.token}\n        async with asyncio.timeout(10):\n            while True:\n                try:\n                    self.ws=await self.session.ws_connect(\n                        f\'http://127.0.0.1:{int(self.adapter.port)}/ws\',headers=headers)\n                    break\n                except aiohttp.ClientConnectorError:await asyncio.sleep(.05)\n        self.reader=asyncio.create_task(self.read_actions(),name=\'b04_local_onebot_peer\')\n        await self.ws.send_json({\'time\':int(time.time()),\'self_id\':int(self.self_id),\n            \'post_type\':\'meta_event\',\'meta_event_type\':\'lifecycle\',\'sub_type\':\'connect\'})\n        login=await asyncio.wait_for(self.adapter.bot.call_action(\'get_login_info\',self_id=self.self_id),5)\n        assert str(login[\'user_id\'])==self.self_id\n\n    async def read_actions(self):\n        async for frame in self.ws:\n            if frame.type!=aiohttp.WSMsgType.TEXT:continue\n            action=json.loads(frame.data);self.actions.append(action[\'action\'])\n            result=({\'status\':\'ok\',\'retcode\':0,\'data\':{\'user_id\':int(self.self_id),\'nickname\':\'local-fixture\'}}\n                if action[\'action\']==\'get_login_info\' else {\'status\':\'failed\',\'retcode\':1404,\'data\':None})\n            if self.m1_scenario and action[\'action\'] in {\'send_private_msg\',\'send_msg\'}:\n                params=action[\'params\'];target=str(params.get(\'user_id\',\'\'))\n                assert target==self.m1_sender_id and params.get(\'group_id\') is None\n                assert action[\'action\']!=\'send_msg\' or params.get(\'message_type\',\'private\')==\'private\'\n                if len(self.sender_observations)>=8:raise RuntimeError(\'M1 local sender ceiling reached\')\n                self.sender_observations.append({\'action\':action[\'action\'],\'user_id\':target,\n                    \'message_sha256\':hashlib.sha256(json.dumps(params[\'message\'],sort_keys=True).encode()).hexdigest()})\n                result={\'status\':\'ok\',\'retcode\':0,\'data\':{\'message_id\':2718100+len(self.sender_observations)}}\n                if self.m1_boundary is not None and len(self.sender_observations)==2:\n                    self.m1_boundary_received=True\n                    if self.m1_boundary==\'stop\':\n                        await self.m1_boundary_release.wait()\n                    else:\n                        # The local receiver saw a request, but returns no acceptance ID.\n                        # The actual AstrBot sender must record UNKNOWN after its durable start.\n                        result={\'status\':\'ok\',\'retcode\':0,\'data\':{}}\n            await self.ws.send_json({**result,\'echo\':action[\'echo\']})\n\n    async def message(self,*,message_id,user_id,text):\n        await self.ws.send_json({\'time\':int(time.time()),\'self_id\':int(self.self_id),\n            \'post_type\':\'message\',\'message_type\':\'private\',\'sub_type\':\'friend\',\n            \'message_id\':message_id,\'user_id\':user_id,\'sender\':{\'user_id\':user_id,\'nickname\':\'fixture-owner\'},\n            \'message\':[{\'type\':\'text\',\'data\':{\'text\':text}}],\'raw_message\':text,\'font\':0})\n\n    async def close(self):\n        if self.ws is not None:await self.ws.close()\n        if self.reader is not None:\n            self.reader.cancel();await asyncio.gather(self.reader,return_exceptions=True)\n        if self.session is not None:await self.session.close()\n\nasync def close_listener(server):\n    server.close();await server.wait_closed()\n\nasync def actual_sdk_identity(context,adapter,peer,umo):\n    from sylanne3.host.identity import astrbot_namespace\n    login=await asyncio.wait_for(adapter.bot.call_action(\'get_login_info\',self_id=peer.self_id),5)\n    assert str(login[\'user_id\'])==peer.self_id\n    cid=await context.conversation_manager.get_curr_conversation_id(umo)\n    assert cid is not None\n    conversation=await context.conversation_manager.get_conversation(umo,cid,create_if_not_exists=False)\n    assert conversation is not None\n    selected=await context.persona_manager.resolve_selected_persona(umo=umo,\n        conversation_persona_id=conversation.persona_id,platform_name=adapter.meta().name,\n        provider_settings=context.get_config(umo))\n    assert selected[1] is not None\n    namespace=astrbot_namespace(adapter.meta().id,peer.self_id,selected[0])\n    assert await context.conversation_manager.get_curr_conversation_id(umo)==cid\n    return {\'schema\':\'sylanne.sdk-preinstall-identity.v1\',\'sdk\':version(\'astrbot\'),\n        \'platform_id\':adapter.meta().id,\'platform_name\':adapter.meta().name,\'self_id\':peer.self_id,\n        \'selected_persona_id\':selected[0],\'umo\':umo,\'conversation_id\':cid,\n        \'bot_id\':namespace.bot_id,\'persona_id\':namespace.persona_id}\n\nclass NativeIngressObservation:\n    # Original queue/scheduler/registered handler always own event execution.\n    def __init__(self,context,life,plugin_name,identity):\n        self.context=context;self.life=life;self.plugin_name=plugin_name;self.identity=identity\n        self.records={};self.completed={};self.events={};self.schedulers=[]\n        self.metadata=None;self.original_handler=None;self.generation=0;self.bus_task=None\n        self.original_put=life.event_queue.put_nowait\n        def observed_put(event):\n            key=str(event.message_obj.message_id)\n            if key in self.records:\n                self.records[key][\'queued\']+=1;self.events[key]=event\n            return self.original_put(event)\n        life.event_queue.put_nowait=observed_put\n\n    def bind_handler(self):\n        assert self.metadata is None\n        plugin=self.context.get_registered_star(self.plugin_name).star_cls\n        [metadata]=[h for h in star_handlers_registry.get_handlers_by_event_type(\n            EventType.AdapterMessageEvent,plugins_name=[self.plugin_name]) if h.handler_name==\'ingress\']\n        original=metadata.handler\n        assert isinstance(original,partial) and original.args[0] is plugin\n        self.generation+=1;generation=self.generation\n        async def observed_handler(event,**kwargs):\n            key=str(event.message_obj.message_id)\n            if key not in self.records:return await original(event,**kwargs)\n            record=self.records[key]\n            assert self.events[key] is event\n            record.update(handler_entered=True,handler_generation=generation,\n                event_module=type(event).__module__,event_class=type(event).__name__)\n            result=await original(event,**kwargs)\n            from sylanne3.host.astrbot import build_astrbot_ingress\n            envelope=await build_astrbot_ingress(event,self.context)\n            assert envelope.namespace.as_tuple==(self.identity[\'bot_id\'],self.identity[\'persona_id\'])\n            assert event.unified_msg_origin==self.identity[\'umo\']\n            record.update(handler_returned=True,namespace={\'bot_id\':envelope.namespace.bot_id,\n                \'persona_id\':envelope.namespace.persona_id},umo=event.unified_msg_origin)\n            return result\n        self.metadata=metadata;self.original_handler=original;metadata.handler=observed_handler\n\n    def unbind_handler(self):\n        if self.metadata is not None:\n            self.metadata.handler=self.original_handler\n            self.metadata=None;self.original_handler=None\n\n    def observe_scheduler(self,scheduler):\n        original=scheduler.execute\n        async def execute(event):\n            key=str(event.message_obj.message_id)\n            if key not in self.records:return await original(event)\n            record=self.records[key]\n            assert self.events[key] is event\n            record[\'pipeline_entered\']=True\n            try:\n                await original(event)\n                record[\'pipeline_returned\']=True\n            finally:self.completed[key].set()\n        scheduler.execute=execute;self.schedulers.append((scheduler,original))\n\n    async def submit(self,peer,*,message_id,user_id,text):\n        assert type(message_id) is int and message_id>1\n        assert type(text) is str and 0<len(text)<=1024\n        key=str(message_id)\n        assert key not in self.records,\'fixture input may not be retried\'\n        self.records[key]={\'message_id\':key,\'queued\':0,\'pipeline_entered\':False,\n            \'pipeline_returned\':False,\'handler_entered\':False,\'handler_returned\':False}\n        self.completed[key]=asyncio.Event()\n        await peer.message(message_id=message_id,user_id=user_id,text=text)\n        await asyncio.wait_for(self.completed[key].wait(),30)\n        result=self.records[key]\n        assert result[\'queued\']==1 and all(result[k] for k in (\n            \'pipeline_entered\',\'pipeline_returned\',\'handler_entered\',\'handler_returned\'))\n        if not peer.m1_scenario:assert all(action==\'get_login_info\' for action in peer.actions)\n        return {**result,\'scope\':\'native SDK identity and handler route; business completion requires separate actual originals\'}\n\n    async def close(self):\n        if self.bus_task is not None:\n            self.bus_task.cancel();await asyncio.gather(self.bus_task,return_exceptions=True)\n        pending=tuple(self.life.event_bus._pending_tasks) if self.bus_task is not None else ()\n        unresolved=set()\n        try:\n            if pending:\n                _,unresolved=await asyncio.wait(pending,timeout=30)\n                for task in unresolved:task.cancel()\n                await asyncio.gather(*pending,return_exceptions=True)\n        finally:\n            self.unbind_handler()\n            self.life.event_queue.put_nowait=self.original_put\n            for scheduler,original in self.schedulers:scheduler.execute=original\n        if unresolved:raise TimeoutError(\'owned native pipeline did not drain before fixture cleanup\')\n\nasync def run():\n    settings=json.loads((ROOT/\'fixture-input.json\').read_text())\n    identity_only=sys.argv[1:]==[\'--identity-only\']\n    assert identity_only or not sys.argv[1:]\n    sdk_ingress=settings.get(\'sdk_ingress\')\n    assert not identity_only or sdk_ingress is not None\n    network_requests=[];local_model_requests=[];peer=None;observer=None;identity=None\n    ingress_lock=asyncio.Lock()\n    async with AsyncExitStack() as cleanup:\n        await core.db_helper.initialize();cleanup.push_async_callback(core.db_helper.engine.dispose)\n        await core.sp.initialize()\n        def save_counters():\n            (ROOT/\'data/model-network-observation.json\').write_text(json.dumps({\n                \'requests\':len(network_requests),\'local_model_requests\':len(local_model_requests),\n                \'sender_calls\':sum(action!=\'get_login_info\' for action in peer.actions) if peer else 0}))\n        cleanup.callback(save_counters)\n        if settings.get(\'diagnostic_mode\')==\'first-v2-fence-only\' and not identity_only:install_fence_observation()\n        cfg=core.astrbot_config\n        if sdk_ingress is not None:\n            cfg[\'provider_settings\'][\'enable\']=False\n            cfg[\'platform\']=[sdk_ingress[\'platform\']]\n        cfg[\'dashboard\'][\'username\']=settings[\'dashboard_username\']\n        cfg[\'dashboard\'][\'password_change_required\']=False\n        set_dashboard_password_hashes(cfg,settings[\'dashboard_password\'])\n        life=AstrBotCoreLifecycle(LogBroker(),core.db_helper);life.start_time=int(time.time())\n        life.event_queue=asyncio.Queue()\n        life.umop_config_router=UmopConfigRouter(sp=core.sp);await life.umop_config_router.initialize()\n        life.astrbot_config_mgr=AstrBotConfigManager(cfg,life.umop_config_router,core.sp)\n        await life.astrbot_config_mgr.initialize()\n        life.persona_mgr=PersonaManager(core.db_helper,life.astrbot_config_mgr);await life.persona_mgr.initialize()\n        life.provider_manager=ProviderManager(life.astrbot_config_mgr,core.db_helper,life.persona_mgr)\n        life.conversation_manager=ConversationManager(core.db_helper)\n        life.platform_message_history_manager=PlatformMessageHistoryManager(core.db_helper)\n        life.platform_manager=PlatformManager(cfg,life.event_queue) if sdk_ingress is not None else None\n        life.astrbot_updater=None\n        context=Context(life.event_queue,cfg,core.db_helper,life.provider_manager,life.platform_manager,\n            life.conversation_manager,life.platform_message_history_manager,life.persona_mgr,life.astrbot_config_mgr,None,None)\n        manager=PluginManager(context,cfg);life.star_context=context;life.plugin_manager=manager\n        if sdk_ingress is not None:\n            cleanup.push_async_callback(life.platform_manager.terminate)\n            await life.platform_manager.load_platform(sdk_ingress[\'platform\'])\n            [adapter]=life.platform_manager.get_insts();assert type(adapter) is AiocqhttpAdapter\n            peer=LocalOneBotV11(adapter,sdk_ingress[\'self_id\'],sdk_ingress[\'platform\'][\'ws_reverse_token\'])\n            peer.m1_scenario=settings.get(\'scenario\') in (\'sdk_m1_two_messages_v1\',\'sdk_m1_first_bubble_stop_v1\',\'sdk_m1_first_bubble_unknown_v1\',\'sdk_ordinary_old_source_v1\',\'sdk_ordinary_greeting_v1\',\'sdk_d13_v6_256_current_v1\',\'sdk_d13_v7_256_current_v1\',\'sdk_a06_real_elapsed_phases_v1\',\'sdk_artifact_v3_tone_sample_v1\',\'sdk_artifact_v3_unknown_v1\');peer.m1_sender_id=str(sdk_ingress[\'user_id\'])\n            peer.m1_boundary={\'sdk_m1_first_bubble_stop_v1\':\'stop\',\'sdk_m1_first_bubble_unknown_v1\':\'unknown\'}.get(settings.get(\'scenario\'))\n            cleanup.push_async_callback(peer.close);await peer.start()\n        if identity_only:\n            candidate=Path(\'/opt/b04-candidate\')\n            assert hashlib.sha256((candidate/\'release-manifest.json\').read_bytes()).hexdigest()==settings[\'manifest_sha256\']\n            sys.path.insert(0,str(candidate))\n            from _runtime_bootstrap import load_canonical_runtime_v1\n            load_canonical_runtime_v1(candidate)\n            await life.persona_mgr.create_persona(sdk_ingress[\'persona_id\'],\'Local SDK identity fixture.\',tools=[],skills=[])\n            await peer.message(message_id=1,user_id=sdk_ingress[\'user_id\'],text=\'fixture identity observation\')\n            event=await asyncio.wait_for(life.event_queue.get(),5)\n            assert event.get_platform_id()==adapter.meta().id and event.get_self_id()==peer.self_id\n            umo=event.unified_msg_origin\n            await life.conversation_manager.new_conversation(umo,platform_id=event.get_platform_id(),persona_id=sdk_ingress[\'persona_id\'])\n            identity=await actual_sdk_identity(context,adapter,peer,umo)\n            assert identity[\'selected_persona_id\']==sdk_ingress[\'persona_id\']\n            if settings.get(\'scenario\') in (\'sdk_m1_two_messages_v1\',\'sdk_m1_first_bubble_stop_v1\',\'sdk_m1_first_bubble_unknown_v1\',\'sdk_ordinary_old_source_v1\',\'sdk_ordinary_greeting_v1\',\'sdk_d13_v6_256_current_v1\',\'sdk_d13_v7_256_current_v1\',\'sdk_a06_real_elapsed_phases_v1\',\'sdk_artifact_v3_tone_sample_v1\',\'sdk_artifact_v3_unknown_v1\'):\n                from sylanne3.host.astrbot import build_astrbot_ingress\n                observed=await build_astrbot_ingress(event,context)\n                assert observed.namespace.as_tuple==(identity[\'bot_id\'],identity[\'persona_id\']) and observed.visibility==\'private\'\n                ingress_identity={\'schema\':\'sylanne.sdk-preinstall-ingress.v1\',\'platform_ref\':observed.platform_ref,\n                    \'sender_ref\':observed.sender_ref,\'conversation_ref\':observed.conversation_ref,\'visibility\':observed.visibility}\n                ingress_target=ROOT/\'data/sdk-preinstall-ingress.json\'\n                ingress_target.write_text(json.dumps(ingress_identity,separators=(\',\',\':\')))\n                with ingress_target.open(\'rb\') as stream:os.fsync(stream.fileno())\n            target=ROOT/\'data/sdk-preinstall-identity.json\'\n            target.write_text(json.dumps(identity,separators=(\',\',\':\')))\n            with target.open(\'rb\') as stream:os.fsync(stream.fileno())\n            assert all(action==\'get_login_info\' for action in peer.actions)\n            return\n        async def local_model_observer(reader,writer):\n            await reader.readline();network_requests.append(\'request\')\n            writer.write(b\'HTTP/1.1 503 Service Unavailable\\r\\nContent-Length: 0\\r\\nConnection: close\\r\\n\\r\\n\')\n            await writer.drain();writer.close();await writer.wait_closed()\n        model_observer=await asyncio.start_server(local_model_observer,\'127.0.0.1\',19661)\n        cleanup.push_async_callback(close_listener,model_observer)\n        provider=json.loads(Path(settings[\'provider_config_path\']).read_text())\n        await life.provider_manager.load_provider(provider)\n        [model]=life.provider_manager.provider_insts\n        if sdk_ingress is not None:\n            from openai import AsyncOpenAI\n            m1_model=None\n            if settings.get(\'scenario\') in (\'sdk_m1_two_messages_v1\',\'sdk_m1_first_bubble_stop_v1\',\'sdk_m1_first_bubble_unknown_v1\',\'sdk_ordinary_old_source_v1\',\'sdk_ordinary_greeting_v1\',\'sdk_d13_v6_256_current_v1\',\'sdk_d13_v7_256_current_v1\',\'sdk_a06_real_elapsed_phases_v1\',\'sdk_artifact_v3_tone_sample_v1\',\'sdk_artifact_v3_unknown_v1\'):\n                sys.path.insert(0,\'/opt/sylanne-b04-fixture\')\n                if settings.get(\'scenario\') in (\'sdk_artifact_v3_tone_sample_v1\',\'sdk_artifact_v3_unknown_v1\'):\n                    verified_helper_pins=settings.get(\'artifact_v3_helper_sha256\')\n                    helper_names={\'sdk_m1_model_fixture_v1.py\',\'artifact_phase_counter_fixture_v1.py\'}\n                    if type(verified_helper_pins)is not dict or set(verified_helper_pins)!=helper_names:\n                        raise ValueError(\'Root-staged exact Artifact V3 helper pins are missing\')\n                    for helper_name in helper_names:\n                        helper_path=Path(\'/opt/sylanne-b04-fixture\')/helper_name\n                        info=helper_path.lstat()\n                        if (helper_path.resolve(strict=True)!=helper_path or not helper_path.is_file()\n                                or info.st_uid!=0 or info.st_mode&0o022\n                                or hashlib.sha256(helper_path.read_bytes()).hexdigest()!=verified_helper_pins[helper_name]):\n                            raise ValueError(\'actual Root SDK helper source differs\')\n                    import sdk_m1_model_fixture_v1 as fixture_model_module\n                    import artifact_phase_counter_fixture_v1 as fixture_counter_module\n                    if (Path(fixture_model_module.__file__).resolve()!=Path(\'/opt/sylanne-b04-fixture/sdk_m1_model_fixture_v1.py\')\n                            or Path(fixture_counter_module.__file__).resolve()!=Path(\'/opt/sylanne-b04-fixture/artifact_phase_counter_fixture_v1.py\')):\n                        raise ValueError(\'Artifact V3 SDK helper import origin differs\')\n                from sdk_m1_model_fixture_v1 import FiniteSdkM1ModelFixtureV1,ArtifactV3MockModelFixtureV1\n                model_type=(ArtifactV3MockModelFixtureV1 if settings.get(\'scenario\') in\n                    (\'sdk_artifact_v3_tone_sample_v1\',\'sdk_artifact_v3_unknown_v1\') else FiniteSdkM1ModelFixtureV1)\n                m1_model=model_type(settings[\'m1_model_fixture\'])\n            async def closed_model_transport(request):\n                local_model_requests.append({\'method\':request.method,\'path\':request.url.path})\n                if m1_model is None:raise RuntimeError(\'B04 SDK route fixture has no M1 model response script\')\n                installed=instance()._v2_installation\n                if installed is None:raise RuntimeError(\'M1 provider cannot run before actual installed bundle\')\n                return m1_model.respond(request,installed_bundle=installed.admin_bundle)\n            previous=model.client\n            model.client=AsyncOpenAI(api_key=model.chosen_api_key,base_url=provider[\'api_base\'],\n                default_headers=model.custom_headers,timeout=model.timeout,max_retries=0,\n                http_client=httpx.AsyncClient(transport=httpx.MockTransport(closed_model_transport),trust_env=False))\n            await previous.close()\n        cleanup.push_async_callback(model.client.close)\n        name=\'astrbot_plugin_sylanne\'\n        schema=manager._load_plugin_config_schema(\'/opt/sylanne/bootstrap/host/_conf_schema.json\')\n        plugin_config=AstrBotConfig(str(Path(manager.plugin_config_path)/(name+\'_config.json\')),schema=schema)\n        plugin_config.save_config(settings[\'plugin_configuration\'])\n        import subprocess\n        original_probe_run = subprocess.run\n        def observed_probe_run(argv, *args, **kwargs):\n            target = \'/opt/sylanne/bootstrap/selection_probe.py\'\n            if type(argv) is not list or target not in argv:\n                return original_probe_run(argv, *args, **kwargs)\n            observed_argv = [argv[0], \'-X\', \'importtime\', *argv[1:]]\n            started = time.monotonic()\n            text, status, returned = \'\', \'first_internal_failure\', None\n            try:\n                result = original_probe_run(observed_argv, *args, **kwargs)\n            except subprocess.TimeoutExpired as error:\n                text = error.stderr.decode(\'utf-8\', errors=\'replace\') if isinstance(error.stderr, bytes) else error.stderr or \'\'\n                status, returned = \'first_timeout\', None\n                raise\n            except subprocess.CalledProcessError as error:\n                text = error.stderr.decode(\'utf-8\', errors=\'replace\') if isinstance(error.stderr, bytes) else error.stderr or \'\'\n                status, returned = \'first_child_failure\', error.returncode\n                raise\n            else:\n                text, status, returned = result.stderr or \'\', \'completed\', result.returncode\n                return result\n            finally:\n                rows = [line for line in text.splitlines() if line.startswith(\'import time:\')][-256:]\n                diagnostic = {\'schema\': \'sylanne.b04.first-selection-probe-import.v1\',\n                    \'status\': status, \'returncode\': returned, \'elapsed_seconds\': time.monotonic()-started,\n                    \'declared_timeout_seconds\': kwargs.get(\'timeout\'), \'probe_mode\': \'host\' if \'--host\' in argv else \'authority\',\n                    \'script_sha256\': hashlib.sha256(Path(target).read_bytes()).hexdigest(),\n                    \'import_time_rows\': rows, \'scope\': \'Only actual module import names/timings; no output/config/credentials; original validation and timeout unchanged\'}\n                index = len(list((ROOT/\'data\').glob(\'selection-probe-import-*.json\')))\n                observed = ROOT/\'data\'/(\'selection-probe-import-\'+str(index)+\'.json\')\n                observed.write_text(json.dumps(diagnostic,indent=2))\n                with observed.open(\'rb\') as stream:os.fsync(stream.fileno())\n        subprocess.run = observed_probe_run\n        try:\n            success,error=await manager.load(specified_dir_name=name)\n        finally:\n            subprocess.run = original_probe_run\n        if not success:\n            sys.stderr.write(\'B04_SDK_LOAD_ERROR_V1 \'+json.dumps({\'error\':error,\n                \'failed_plugin\':manager.failed_plugin_dict.get(name)},separators=(\',\',\':\'))+\'\\n\')\n            sys.stderr.flush();os.fsync(sys.stderr.fileno())\n            raise RuntimeError(\'actual_sdk_plugin_load_failed\')\n        async def terminate_current_plugin():await context.get_registered_star(name).star_cls.terminate()\n        cleanup.push_async_callback(terminate_current_plugin)\n        def require_actual_sdk_namespace(plugin, identity):\n            if plugin._installed_namespace is None:\n                observation = {\'schema\':\'sylanne.b04.sdk-initialization-failure.v1\',\n                    \'runtime_stage\':plugin.runtime_health.status,\n                    \'reason_codes\':list(plugin.runtime_health.missing_capabilities),\n                    \'setup_present\':plugin._setup_installation is not None,\n                    \'runtime_present\':plugin._runtime is not None,\n                    \'installed_namespace_present\':False,\n                    \'observed_wall_time_ns\':time.time_ns(),\n                    \'observed_monotonic_ns\':time.monotonic_ns()}\n                sys.stderr.write(\'B04_SDK_INITIALIZATION_NOT_ADMITTED \'+json.dumps(observation,separators=(\',\',\':\'))+\'\\n\')\n                sys.stderr.flush();os.fsync(sys.stderr.fileno())\n                error = RuntimeError(\'actual_sdk_initialization_not_admitted\')\n                error.b04_initialization_observation = observation\n                raise error\n            assert plugin._installed_namespace.as_tuple==(identity[\'bot_id\'],identity[\'persona_id\'])\n        if sdk_ingress is not None:\n            identity=json.loads(Path(settings[\'sdk_identity_path\']).read_text())\n            assert await actual_sdk_identity(context,adapter,peer,identity[\'umo\'])=={k:v for k,v in identity.items() if k!=\'ingress_identity\'}\n            require_actual_sdk_namespace(context.get_registered_star(name).star_cls,identity)\n            observer=NativeIngressObservation(context,life,name,identity)\n            cleanup.push_async_callback(observer.close);observer.bind_handler()\n            life.pipeline_scheduler_mapping=await life.load_pipeline_scheduler()\n            for scheduler in life.pipeline_scheduler_mapping.values():observer.observe_scheduler(scheduler)\n            life.event_bus=EventBus(life.event_queue,life.pipeline_scheduler_mapping,life.astrbot_config_mgr)\n            observer.bus_task=asyncio.create_task(life.event_bus.dispatch(),name=\'b04_native_event_bus\')\n        dashboard=AstrBotDashboard(life,core.db_helper,asyncio.Event())\n        client=httpx.AsyncClient(transport=httpx.ASGITransport(app=dashboard.asgi_app),base_url=settings[\'origin\'])\n        cleanup.push_async_callback(client.aclose)\n        stopped=asyncio.Event()\n        for event in (signal.SIGTERM,signal.SIGINT):asyncio.get_running_loop().add_signal_handler(event,stopped.set)\n        def instance():return context.get_registered_star(name).star_cls\n        def health():\n            plugin=instance();runtime=plugin._runtime\n            sys.stderr.write(\'B04_RUNTIME_HEALTH_DETAIL \'+json.dumps({\'status\':plugin.runtime_health.status,\n                \'detail\':plugin.runtime_health.detail},separators=(\',\',\':\'))+\'\\n\')\n            sys.stderr.flush();os.fsync(sys.stderr.fileno())\n            package=sys.modules[\'data.plugins.\'+name+\'.main\'].PACKAGE_ROOT\n            from sylanne3.authority_service.c09_process_identity_v1 import read_process_identity_v1\n            return dict(schema=\'sylanne.b04.sdk-host-health.v1\',runtime_stage=plugin.runtime_health.status,\n                fixture_phase=settings[\'fixture_phase\'],\n                reason_codes=list(plugin.runtime_health.missing_capabilities),runtime_started=runtime is not None,\n                worker_started=runtime is not None and runtime._worker is not None,\n                package_root=str(package),main_path=str(sys.modules[\'data.plugins.\'+name+\'.main\'].__file__),\n                manifest_sha256=hashlib.sha256((package/\'release-manifest.json\').read_bytes()).hexdigest(),\n                process_id=os.getpid(),process_original=read_process_identity_v1(os.getpid()),uid=os.geteuid(),sdk=version(\'astrbot\'),\n                provider_network_requests=len(network_requests),platform_manager_initialized=life.platform_manager is not None,\n                platform_instances=len(life.platform_manager.get_insts()) if life.platform_manager else 0,\n                sender_instances=len(life.platform_manager.get_insts()) if life.platform_manager else 0,\n                sender_calls=sum(action!=\'get_login_info\' for action in peer.actions) if peer else 0,\n                local_model_requests=len(local_model_requests),sdk_identity=identity,\n                native_handler_generation=observer.generation if observer else 0,\n                model_fixture_calls=list(m1_model.calls) if settings.get(\'scenario\') in (\'sdk_m1_two_messages_v1\',\'sdk_m1_first_bubble_stop_v1\',\'sdk_m1_first_bubble_unknown_v1\',\'sdk_ordinary_old_source_v1\',\'sdk_ordinary_greeting_v1\',\'sdk_d13_v6_256_current_v1\',\'sdk_d13_v7_256_current_v1\',\'sdk_a06_real_elapsed_phases_v1\',\'sdk_artifact_v3_tone_sample_v1\',\'sdk_artifact_v3_unknown_v1\') else [],\n                sender_fixture_observations=list(peer.sender_observations) if peer else [],\n                artifact_v3_admission_probe=dict(admission_probe),\n                artifact_v3_cross_root_probe=(cross_root_probe.status() if cross_root_probe is not None else None),\n                natural_boundary_received=bool(peer and peer.m1_boundary_received),\n                model_fixture_first_failure=(getattr(m1_model,\'first_failure\',None) if settings.get(\'scenario\') in\n                    (\'sdk_artifact_v3_tone_sample_v1\',\'sdk_artifact_v3_unknown_v1\') else None))\n\n        cross_root_probe = None\n        admission_probe = {\'schema\':\'sylanne.test.artifact-v3-live-admission-probe.v1\',\n            \'state\':\'not_armed\',\'cases\':[],\'valid_forward_count\':0,\'first_failure\':None}\n\n        cancelled_job_probe={"state":"not_armed","first_failure":None}\n        cancelled_job_release=asyncio.Event()\n\n        def arm_artifact_v3_cancelled_queued_job():\n            from unittest.mock import patch\n            from sylanne3.runtime.d07_installed_execution_v1 import InstalledD07ExecutionServiceV1\n            runtime=instance()._runtime\n            service=runtime._v2_d07_execution_service\n            if (type(service)is not InstalledD07ExecutionServiceV1\n                    or cancelled_job_probe["state"]!="not_armed"or local_model_requests\n                    or admission_probe["state"]!="not_armed"or cross_root_probe is not None\n                    or settings.get("scenario")!="sdk_artifact_v3_tone_sample_v1"):\n                raise ValueError("cancelled queued job needs its own fresh actual installed V9 Root")\n            original=service._execute_current_d07_job_once_v3\n            cancelled_job_probe["state"]="armed"\n            async def observed(job):\n                if job.work_kind!="d07.concern"or not job.operation_id.startswith("artifact-phase-observe:"):\n                    return await original(job)\n                if cancelled_job_probe["state"]!="armed":\n                    raise RuntimeError("one original queued execution entry only")\n                try:\n                    if([item["phase"]for item in m1_model.calls]!=["encode","appraisal","tone_sample"]\n                            or len(local_model_requests)!=3 or network_requests\n                            or sum(item["fixture_charge_microusd"]for item in m1_model.calls)!=0):\n                        raise ValueError("actual three-call Mock baseline required")\n                    def actual_metadata(graph):\n                        from datetime import datetime\n                        from sylanne3.runtime.jobs import get_job\n                        from sylanne3.runtime.d07_execution_v1 import read_d07_original_v1\n                        from sylanne3.runtime.artifact_observation_parentage_v3 import artifact_observation_descriptor_from_metadata_v3\n                        store=graph._GraphCoordinator__store;ns=service.bundle.installation_policy.namespace\n                        with store._lock:\n                            db=store._db\n                            if db.in_transaction:raise RuntimeError("fixture read is outside business SQL")\n                            db.execute("BEGIN")\n                            try:\n                                current=get_job(db,job.job_id)\n                                row=read_d07_original_v1(db,service.d11_issuer,ns,"prepared",job.job_id)\n                                if row is None:raise ValueError("actual signed queued D07 prepared required")\n                                descriptor=artifact_observation_descriptor_from_metadata_v3(row[0],\n                                    namespace=ns,prepared_digest=row[1])\n                                if(current!=job or current.phase!="queued"or current.lease_holder is not None\n                                        or current.fence or current.cancel_epoch\n                                        or read_d07_original_v1(db,service.d11_issuer,ns,"call",job.job_id)is not None):\n                                    raise ValueError("queued child must have no acquire, Core intent or consumed worker claim")\n                                deadline=datetime.fromisoformat(job.deadline_utc.replace("Z","+00:00")).timestamp()\n                                if deadline-time.time()<15:raise TimeoutError("original deadline has insufficient observation margin")\n                                return {"job_id":job.job_id,"cycle_job_ref":descriptor.cycle_ref.key.token,\n                                    "c02_operation_id":descriptor.c02_operation_id,"prepared_digest":row[1],\n                                    "deadline_utc":deadline}\n                            finally:db.rollback()\n                    metadata=await runtime._worker.call(actual_metadata)\n                    cancelled_job_probe.update(metadata,state="paused_queued_before_acquire",\n                        provider_calls_before=3,fixture_charge_before_microusd=0)\n                    await asyncio.wait_for(cancelled_job_release.wait(),metadata["deadline_utc"]-time.time())\n                    if time.time()>=metadata["deadline_utc"]:raise TimeoutError("original deadline expired before acquire rejection")\n                    original_worker_call=service.worker.call\n                    async def observe_worker_call(function,*args):\n                        result=await original_worker_call(function,*args)\n                        code=getattr(function,"__code__",None)\n                        if (code is not None and Path(code.co_filename).name=="d07_installed_execution_v1.py"\n                                and "acquire_current_d07_execution_v1"in code.co_names\n                                and type(result)is dict):\n                            cancelled_job_probe["actual_acquire_result"]=result\n                            cancelled_job_probe["actual_acquire_callback"]={"file":code.co_filename,"line":code.co_firstlineno}\n                        return result\n                    try:\n                        with patch.object(service.worker,"call",new=observe_worker_call):\n                            result=await original(job)\n                    except Exception as error:\n                        frames=[]\n                        for frame in traceback.extract_tb(error.__traceback__):\n                            frames.append({"file":frame.filename,"line":frame.lineno,"function":frame.name})\n                        cancelled_job_probe.update(state="rejected_after_actual_cancel",\n                            rejection={"type":type(error).__name__,"message":str(error),"frames":frames},\n                            result=None)\n                        raise\n                    else:\n                        if type(result)is not dict or result.get("status")not in {"original_execution_hold"}:\n                            raise AssertionError("cancelled original execution did not return the actual D11 hold")\n                        cancelled_job_probe.update(state="rejected_after_actual_cancel",result=result,rejection=None)\n                        return result\n                    finally:\n                        if(time.time()>=metadata["deadline_utc"]or len(local_model_requests)!=3 or network_requests\n                                or sum(item["fixture_charge_microusd"]for item in m1_model.calls)!=0):\n                            raise AssertionError("expiry/provider/charge changed during the original cancelled acquire")\n                except BaseException as error:\n                    if cancelled_job_probe["state"]!="rejected_after_actual_cancel":\n                        cancelled_job_probe.update(state="first_failure",\n                            first_failure={"type":type(error).__name__,"message":str(error)})\n                    raise\n                finally:interception.stop()\n            interception=patch.object(service,"_execute_current_d07_job_once_v3",new=observed)\n            interception.start();cleanup.callback(interception.stop)\n            return dict(cancelled_job_probe)\n\n        def arm_artifact_v3_admission_negatives():\n            from dataclasses import asdict, replace\n            from unittest.mock import patch\n            from sylanne3.host.authority_client import AuthorityClient\n            from sylanne3.host.mtls_transport import MtlsAuthorityTransport\n            runtime=instance()._runtime\n            receipt=runtime._v2_natural_readiness_receipt\n            authority=receipt.authority_client\n            if (admission_probe[\'state\']!=\'not_armed\' or local_model_requests\n                    or type(authority) is not AuthorityClient\n                    or type(authority._transport) is not MtlsAuthorityTransport):\n                raise RuntimeError(\'live admission probe needs the unused actual installed client and mTLS\')\n            original=authority.model_admit_dispatch_once_v2\n            admission_probe[\'state\']=\'armed\'\n            async def financial_stamp():\n                def read(graph):\n                    store=graph._GraphCoordinator__store\n                    ns=receipt.policy.namespace.as_tuple\n                    with store._lock:\n                        db=store._db\n                        if db.in_transaction:raise RuntimeError(\'probe cannot read inside a business write\')\n                        leases=tuple(db.execute(\'SELECT * FROM runtime_budget_leases WHERE bot_id=? AND persona_id=? ORDER BY lease_id\',ns))\n                        reservations=tuple(db.execute(\'SELECT r.* FROM runtime_budget_reservations r JOIN runtime_budget_leases l USING(lease_id) WHERE l.bot_id=? AND l.persona_id=? ORDER BY r.lease_id,r.operation_id\',ns))\n                        operations=tuple(db.execute(\'SELECT * FROM runtime_budget_operations WHERE bot_id=? AND persona_id=? ORDER BY operation_id,phase\',ns))\n                    return hashlib.sha256(json.dumps([leases,reservations,operations],\n                        sort_keys=True,separators=(\',\',\':\')).encode()).hexdigest()\n                return await runtime._worker.call(read)\n            async def observed_admit(bundle,grant,*,intent,expected_anchor,model_request,host_incarnation,_on_dispatch=None):\n                if model_request.identity.phase!=\'d07.cognition\':\n                    return await original(bundle,grant,intent=intent,expected_anchor=expected_anchor,\n                        model_request=model_request,host_incarnation=host_incarnation,_on_dispatch=_on_dispatch)\n                if admission_probe[\'state\']!=\'armed\':\n                    raise RuntimeError(\'the single original D07 admission probe cannot repeat\')\n                admission_probe[\'state\']=\'checking\'\n                try:\n                    if [item[\'phase\'] for item in m1_model.calls]!=[\'encode\',\'appraisal\',\'tone_sample\']:\n                        raise RuntimeError(\'probe is not immediately before the first actual Artifact D07 admission\')\n                    before_count=len(local_model_requests)\n                    before_calls=len(m1_model.calls)\n                    if before_count!=3 or sum(item[\'fixture_charge_microusd\'] for item in m1_model.calls)!=0 or network_requests:\n                        raise RuntimeError(\'first D07 does not have the authentic three-call Mock baseline\')\n                    original_record,original_permit=await authority.model_recover_fenced_v1(bundle,grant,intent=intent)\n                    if original_record.state!=\'prepared\' or original_record.intent!=intent:\n                        raise RuntimeError(\'live negatives require the untouched actual prepared Core original\')\n                    finance=await financial_stamp()\n                    async def reject(name,candidate,candidate_grant,candidate_request,expected_error,remote,field):\n                        dispatched=[]\n                        try:\n                            await original(bundle,candidate_grant,intent=candidate,expected_anchor=expected_anchor,\n                                model_request=candidate_request,host_incarnation=host_incarnation,\n                                _on_dispatch=lambda:dispatched.append(True))\n                        except RuntimeError as error:\n                            if type(error) is not RuntimeError or str(error)!=expected_error:\n                                raise AssertionError(\'unexpected admission rejection for \'+name) from error\n                        else:\n                            raise AssertionError(\'invalid admission was accepted: \'+name)\n                        if len(dispatched)!=(1 if remote else 0):\n                            raise AssertionError(\'negative was rejected at a different transport layer: \'+name)\n                        retained,permit=await authority.model_recover_fenced_v1(bundle,grant,intent=intent)\n                        if (retained!=original_record or retained.state!=\'prepared\' or permit!=original_permit\n                                or await financial_stamp()!=finance or len(local_model_requests)!=before_count\n                                or len(m1_model.calls)!=before_calls or network_requests\n                                or sum(item[\'fixture_charge_microusd\'] for item in m1_model.calls)!=0):\n                            raise AssertionError(\'negative consumed original, provider invocation or budget: \'+name)\n                        admission_probe[\'cases\'].append({\'name\':name,\'changed_field\':field,\n                            \'layer\':\'live_core_original_identity_tamper\' if remote else \'host_before_dispatch\',\n                            \'rejection\':expected_error,\'actual_mtls_dispatch_count\':len(dispatched),\n                            \'original_core_state\':retained.state,\'financial_sha256\':finance,\n                            \'provider_call_delta\':0,\'fixture_charge_delta_microusd\':0,\n                            \'original_intent_sha256\':hashlib.sha256(json.dumps(asdict(intent),sort_keys=True).encode()).hexdigest()})\n                    def different_digest(value):\n                        return (\'1\' if value[0]!=\'1\' else \'2\')+value[1:]\n                    core_cases=(\n                        (\'sealed_grant_binding\',\'binding_digest\',different_digest(intent.binding_digest)),\n                        (\'budget_lease\',\'budget_lease_id\',intent.budget_lease_id+\':foreign\'),\n                        (\'reservation_operation\',\'budget_reservation_operation_id\',intent.budget_reservation_operation_id+\':foreign\'),\n                        (\'reservation_digest\',\'budget_reservation_digest\',different_digest(intent.budget_reservation_digest)),\n                        (\'provider_config\',\'provider_config_digest\',different_digest(intent.provider_config_digest)))\n                    local_cases=(\n                        (\'installation_grant\',\'grant\',replace(grant,installation_id=grant.installation_id+\':foreign\'),\n                            \'authority model installation binding is invalid\'),\n                        (\'expired_envelope\',\'model_request\',replace(model_request,payload=dict(model_request.payload),\n                            envelope=replace(model_request.envelope,deadline_utc=time.time()-1)),\n                            \'authority model request binding is invalid\'),\n                        (\'future_envelope\',\'model_request\',replace(model_request,payload=dict(model_request.payload),\n                            envelope=replace(model_request.envelope,deadline_utc=model_request.envelope.deadline_utc+86400)),\n                            \'authority model request binding is invalid\'))\n                    for name,field,value in core_cases:\n                        changed=replace(intent,**{field:value})\n                        if [key for key in asdict(intent) if asdict(intent)[key]!=asdict(changed)[key]]!=[field]:\n                            raise AssertionError(\'one intent field must vary\')\n                        await reject(name,changed,grant,model_request,\'authority service unavailable\',True,field)\n                    for name,field,value,error in local_cases:\n                        await reject(name,intent,value if field==\'grant\' else grant,\n                            value if field==\'model_request\' else model_request,error,False,\n                            \'installation_id\' if field==\'grant\' else \'envelope.deadline_utc\')\n                    admission_probe[\'state\']=\'forwarding_original\'\n                    admission_probe[\'valid_forward_count\']+=1\n                    actual=await original(bundle,grant,intent=intent,expected_anchor=expected_anchor,\n                        model_request=model_request,host_incarnation=host_incarnation,_on_dispatch=_on_dispatch)\n                    if actual[0].state!=\'dispatch_started\' or actual[0].intent!=intent:\n                        raise RuntimeError(\'unchanged original did not receive the actual once-only Core admission\')\n                    admission_probe[\'state\']=\'original_admitted\'\n                    return actual\n                except BaseException as error:\n                    admission_probe[\'state\']=\'first_failure\'\n                    admission_probe[\'first_failure\']={\'type\':type(error).__name__,\'message\':str(error)}\n                    raise\n                finally:\n                    interception.stop()\n\n\n            interception=patch.object(authority,\'model_admit_dispatch_once_v2\',new=observed_admit)\n            interception.start()\n            cleanup.callback(interception.stop)\n            return dict(admission_probe)\n\n        def arm_artifact_v3_cross_root(role, helper_sha256):\n            nonlocal cross_root_probe\n            if (cross_root_probe is not None or admission_probe[\'state\']!=\'not_armed\'\n                    or settings.get(\'scenario\')!=\'sdk_artifact_v3_tone_sample_v1\'\n                    or settings.get(\'artifact_v3_cross_root_helper_sha256\')!=helper_sha256):\n                raise ValueError(\'explicit fresh Root A/B fixture and protected helper pin required\')\n            import importlib.util,stat\n            helper=Path(\'/opt/sylanne-b04-fixture/artifact_v3_cross_root_witness_v1.py\')\n            info=helper.lstat()\n            if (helper.resolve(strict=True)!=helper or not stat.S_ISREG(info.st_mode)\n                    or info.st_uid!=0 or info.st_mode&0o022\n                    or hashlib.sha256(helper.read_bytes()).hexdigest()!=helper_sha256):\n                raise ValueError(\'Root-staged cross-Root helper differs from its protected exact pin\')\n            spec=importlib.util.spec_from_file_location(\'artifact_v3_cross_root_witness_v1\',helper)\n            module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)\n            runtime=instance()._runtime\n            receipt=runtime._v2_natural_readiness_receipt\n            def counts():\n                return {\'local\':len(local_model_requests),\'network\':len(network_requests),\n                    \'phases\':[item[\'phase\']for item in m1_model.calls],\n                    \'charge\':sum(item[\'fixture_charge_microusd\']for item in m1_model.calls)}\n            cross_root_probe=module.CrossRootAdmissionProbeV1(authority=receipt.authority_client,\n                runtime=runtime,bundle=receipt.bundle,grant=receipt.client_grant,\n                counts=counts,cleanup=cleanup)\n            return cross_root_probe.arm(role)\n\n        async def rpc(reader,writer):\n            try:\n                _pid,uid,_gid=struct.unpack(\'3i\',writer.get_extra_info(\'socket\').getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))\n                if uid!=0:raise PermissionError(\'fixture_controller_root_required\')\n                raw=await reader.readline()\n                if len(raw)>65536:raise ValueError(\'fixture_request_bound\')\n                request=json.loads(raw);action=request[\'action\']\n                if action==\'health\' and set(request)=={\'action\'}:\n                    result=health()\n                elif action=="artifact_v3_arm_cancelled_queued_job"and set(request)=={"action"}:\n                    result=arm_artifact_v3_cancelled_queued_job()\n                elif action=="artifact_v3_cancelled_queued_job_status"and set(request)=={"action"}:\n                    result=dict(cancelled_job_probe)\n                elif action=="artifact_v3_cancelled_queued_job_release"and set(request)=={"action"}:\n                    if cancelled_job_probe["state"]!="paused_queued_before_acquire":\n                        raise ValueError("exact queued child must be paused once")\n                    cancelled_job_release.set();result={"state":"released_once"}\n                elif action==\'artifact_v3_arm_admission_negatives\' and set(request)=={\'action\'}:\n                    if settings.get(\'scenario\')!=\'sdk_artifact_v3_tone_sample_v1\':\n                        raise ValueError(\'a separate fresh successful Artifact V3 fixture is required\')\n                    result=arm_artifact_v3_admission_negatives()\n                elif action==\'artifact_v3_cross_root_arm\' and set(request)=={\'action\',\'role\',\'helper_sha256\'}:\n                    result=arm_artifact_v3_cross_root(request[\'role\'],request[\'helper_sha256\'])\n                elif action==\'artifact_v3_cross_root_inspect\' and set(request)=={\'action\'}:\n                    if cross_root_probe is None:raise ValueError(\'cross-Root fixture is not armed\')\n                    result=await cross_root_probe.inspect()\n                elif action==\'artifact_v3_cross_root_status\' and set(request)=={\'action\'}:\n                    if cross_root_probe is None:raise ValueError(\'cross-Root fixture is not armed\')\n                    result=cross_root_probe.status()\n                elif action==\'artifact_v3_cross_root_release\' and set(request)=={\'action\',\'case\',\'witness\',\'a_snapshot\',\'b_snapshot\'}:\n                    if cross_root_probe is None:raise ValueError(\'cross-Root fixture is not armed\')\n                    result=cross_root_probe.release_case(case=request[\'case\'],witness=request[\'witness\'],\n                        a_snapshot=request[\'a_snapshot\'],b_snapshot=request[\'b_snapshot\'])\n                elif action==\'artifact_v3_checkpoint\' and set(request)=={\'action\'}:\n                    if settings.get(\'scenario\') not in (\'sdk_artifact_v3_tone_sample_v1\',\'sdk_artifact_v3_unknown_v1\'):\n                        raise ValueError(\'new isolated Artifact V3 Mock scenario required\')\n                    runtime=instance()._runtime\n                    if runtime is None or runtime._worker is None:\n                        raise RuntimeError(\'actual installed worker is unavailable\')\n                    transaction_open=await runtime._worker.call(lambda graph: graph._GraphCoordinator__store._db.in_transaction)\n                    result=health()\n                    result[\'fixture_checkpoint\']={\'event_queue_empty\':life.event_queue.empty(),\n                        \'pending_sdk_tasks\':len(life.event_bus._pending_tasks),\'worker_transaction_open\':transaction_open}\n                elif action==\'release_natural_boundary\' and set(request)=={\'action\'}:\n                    if peer is None or peer.m1_boundary!=\'stop\' or not peer.m1_boundary_received:\n                        raise RuntimeError(\'actual local Stop boundary was not reached\')\n                    peer.m1_boundary_release.set();result={\'released\':True}\n                elif action==\'natural_core_originals\' and set(request)=={\'action\',\'parent_original_id\'}:\n                    runtime=instance()._runtime\n                    def read(graph):\n                        from sylanne3.runtime.natural_same_batch_history_v3 import read_natural_roster_head_v1\n                        from sylanne3.authority_service.natural_disposition_maintenance_v1 import natural_disposition_original_ref_v1\n                        bundle=instance()._v2_installation\n                        ns=bundle.installation_policy.namespace;ans=bundle.installation_policy.authority_namespace\n                        with graph._GraphCoordinator__store._lock:\n                            head=read_natural_roster_head_v1(graph._GraphCoordinator__store._db,ns,request[\'parent_original_id\'])\n                        if head is None:return None\n                        facts=[]\n                        for ref in dict.fromkeys((head[2].birth_original_ref,head[2].authority_original_ref)):\n                            prepared=runtime._v2_port.read_natural_disposition_original_v1(namespace=ns,authority_namespace=ans,original_ref=ref)\n                            kind=\'roster_committed\' if prepared.kind==\'roster_prepared\' else \'maintenance_committed\'\n                            cref=natural_disposition_original_ref_v1(ans,bundle.installation_policy.installation_id,head[2].parent_original_id,kind,prepared.operation_id)\n                            committed=runtime._v2_port.read_natural_disposition_original_v1(namespace=ns,authority_namespace=ans,original_ref=cref)\n                            assert committed.payload[\'prepared_original_digest\']==prepared.digest\n                            assert committed.payload[\'next_payload_digest\']==prepared.payload[\'next_payload_digest\']\n                            if ref==head[2].authority_original_ref:assert prepared.payload[\'expected_next_value\']==head[2].to_wire()\n                            facts.append({\'prepared_kind\':prepared.kind,\'prepared_ref\':prepared.original_ref,\'prepared_digest\':prepared.digest,\n                                \'committed_kind\':committed.kind,\'committed_ref\':committed.original_ref,\'committed_digest\':committed.digest})\n                        return {\'roster_ref\':head[0].token,\'revision\':head[1],\'original_pairs\':facts}\n                    result=await runtime._worker.call(read)\n                elif action==\'http\' and set(request)=={\'action\',\'method\',\'path\',\'headers\',\'json\'}:\n                    response=await client.request(request[\'method\'],request[\'path\'],headers=request[\'headers\'],json=request[\'json\'])\n                    # This body remains on the private socket, never an evidence log.\n                    result={\'http_status\':response.status_code,\'json\':response.json()}\n                elif action==\'provision_original\' and set(request)=={\'action\',\'operation_id\'}:\n                    runtime=instance()._runtime\n                    original=await runtime.provision_installed_namespace(request[\'operation_id\'])\n                    from sylanne3.graph_coordinator import NamespaceProvisionReceiptV2\n                    from sylanne3.authority_service.v2_contract import from_wire as fence_from_wire\n                    if type(original) is not NamespaceProvisionReceiptV2:\n                        raise TypeError(\'actual_namespace_provision_receipt_required\')\n                    def completed_fence(_graph):\n                        return runtime._v2_port.get_fence_operation(namespace=original.namespace,\n                            authority_namespace=original.authority_namespace,operation_id=original.fence_attempt_id)\n                    observed,state=await runtime._worker.call(completed_fence)\n                    if observed!=fence_from_wire(original.permit_wire) or state!=\'finished\':\n                        raise RuntimeError(\'actual_namespace_provision_write_fence_not_finished\')\n                    from dataclasses import asdict\n                    result=asdict(original)\n                elif action==\'ordinary_ingress\' and set(request)=={\'action\',\'message_id\',\'text\'}:\n                    assert observer is not None\n                    async with ingress_lock:\n                        before=len(local_model_requests)\n                        result=await observer.submit(peer,message_id=request[\'message_id\'],\n                            user_id=sdk_ingress[\'user_id\'],text=request[\'text\'])\n                        if settings.get(\'scenario\') in (\'sdk_m1_two_messages_v1\',\'sdk_m1_first_bubble_stop_v1\',\'sdk_m1_first_bubble_unknown_v1\',\'sdk_ordinary_old_source_v1\',\'sdk_ordinary_greeting_v1\',\'sdk_d13_v6_256_current_v1\',\'sdk_d13_v7_256_current_v1\',\'sdk_a06_real_elapsed_phases_v1\',\'sdk_artifact_v3_tone_sample_v1\',\'sdk_artifact_v3_unknown_v1\'):\n                            assert request[\'message_id\'] in {item[\'message_id\'] for item in settings[\'m1_model_fixture\'][\'episodes\']}\n                            assert 0<=len(local_model_requests)-before<=6 and len(m1_model.calls)<=settings[\'m1_model_fixture\'][\'max_total_calls\'] and not network_requests\n                        else:assert len(local_model_requests)==before==0 and not network_requests\n                        result.update(sdk_identity=identity,local_model_requests=len(local_model_requests),\n                            sender_calls=sum(action!=\'get_login_info\' for action in peer.actions))\n                elif action==\'d13_v6_collection_originals\' and set(request)=={\'action\',\'source_ref\'}:\n                    if settings.get(\'scenario\') not in (\'sdk_d13_v6_256_current_v1\',\'sdk_d13_v7_256_current_v1\'):raise ValueError(\'fixed256 SDK scenario required\')\n                    from sdk_m1_fixture_contract_v1 import actual_d13_v6_collection_originals_v1\n                    plugin=instance();runtime=plugin._runtime;policy=runtime._v2_policy\n                    def read_v6_collection(graph):\n                        anchor=runtime._v2_port.current_anchor(namespace=policy.namespace,authority_namespace=policy.authority_namespace)\n                        store=graph._GraphCoordinator__store\n                        with store._lock:\n                            db=store._db;db.execute(\'BEGIN\')\n                            try:return actual_d13_v6_collection_originals_v1(db,namespace=policy.namespace,source_ref=request[\'source_ref\'],\n                                activation_generation=anchor.activation_generation,now_utc=time.time())\n                            finally:db.rollback()\n                    result=await runtime._worker.call(read_v6_collection)\n                elif action==\'d13_v6_episode_originals\' and set(request)=={\'action\',\'message_id\'}:\n                    if settings.get(\'scenario\') not in (\'sdk_d13_v6_256_current_v1\',\'sdk_d13_v7_256_current_v1\'):raise ValueError(\'fixed256 SDK scenario required\')\n                    from sdk_m1_fixture_contract_v1 import actual_d13_v6_episode_originals_v1,actual_d13_v7_episode_originals_v1\n                    episode=next(item for item in settings[\'m1_model_fixture\'][\'episodes\'] if item[\'message_id\']==request[\'message_id\'])\n                    plugin=instance();runtime=plugin._runtime\n                    def read_v6_episode(graph):\n                        store=graph._GraphCoordinator__store\n                        with store._lock:\n                            db=store._db;db.execute(\'BEGIN\')\n                            try:\n                                if settings[\'scenario\']==\'sdk_d13_v7_256_current_v1\':\n                                    return actual_d13_v7_episode_originals_v1(db,namespace=plugin._installed_namespace,\n                                        episode=episode,issuer=graph._GraphCoordinator__d11_issuer,\n                                        installed_wire_policy=plugin._setup_installation.admin_bundle.d13_wire_policy)\n                                return actual_d13_v6_episode_originals_v1(db,namespace=plugin._installed_namespace,\n                                    episode=episode,issuer=graph._GraphCoordinator__d11_issuer)\n                            finally:db.rollback()\n                    result=await runtime._worker.call(read_v6_episode)\n                elif action==\'greeting_need_originals\' and set(request)=={\'action\',\'message_id\'}:\n                    if settings.get(\'scenario\')!=\'sdk_ordinary_greeting_v1\':raise ValueError(\'greeting fixed scenario required\')\n                    from sdk_m1_fixture_contract_v1 import actual_greeting_need_original_v1\n                    episodes=[item for item in settings[\'m1_model_fixture\'][\'episodes\'] if item[\'message_id\']==request[\'message_id\']]\n                    if len(episodes)!=1:raise ValueError(\'unknown finite greeting SDK message\')\n                    plugin=instance();runtime=plugin._runtime\n                    def read_greeting(graph):\n                        store=graph._GraphCoordinator__store\n                        with store._lock:\n                            db=store._db;db.execute(\'BEGIN\')\n                            try:return actual_greeting_need_original_v1(db,namespace=plugin._installed_namespace,episode=episodes[0])\n                            finally:db.rollback()\n                    result=await runtime._worker.call(read_greeting)\n                elif action==\'ordinary_recall_originals\' and set(request)=={\'action\',\'message_id\',\'previous_source_ref\'}:\n                    if settings.get(\'scenario\')!=\'sdk_ordinary_old_source_v1\':raise ValueError(\'ordinary recall fixture scenario required\')\n                    from sdk_m1_fixture_contract_v1 import actual_ordinary_episode_originals_v1\n                    episodes=[item for item in settings[\'m1_model_fixture\'][\'episodes\'] if item[\'message_id\']==request[\'message_id\']]\n                    if len(episodes)!=1:raise ValueError(\'unknown finite ordinary SDK message\')\n                    plugin=instance();runtime=plugin._runtime\n                    def read_originals(graph):\n                        store=graph._GraphCoordinator__store\n                        with store._lock:\n                            db=store._db;db.execute(\'BEGIN\')\n                            try:return actual_ordinary_episode_originals_v1(db,namespace=plugin._installed_namespace,\n                                episode=episodes[0],issuer=graph._GraphCoordinator__d11_issuer,\n                                previous_source_ref=request[\'previous_source_ref\'])\n                            finally:db.rollback()\n                    result=await runtime._worker.call(read_originals)\n                elif action==\'real_elapsed_originals\' and set(request)=={\'action\',\'phase_index\'}:\n                    if settings.get(\'scenario\')!=\'sdk_a06_real_elapsed_phases_v1\':raise ValueError(\'real elapsed phase scenario required\')\n                    from sdk_m1_fixture_contract_v1 import REAL_ELAPSED_EPISODES,actual_episode_originals_v1,actual_ordinary_episode_originals_v1\n                    plugin=instance();runtime=plugin._runtime;index=request[\'phase_index\']\n                    if type(index) is not int or not 0<=index<=2:raise ValueError(\'actual real elapsed phase index required\')\n                    def read_phase(graph):\n                        store=graph._GraphCoordinator__store\n                        phase=actual_episode_originals_v1(graph_path=store._db.execute(\'PRAGMA database_list\').fetchone()[2],\n                            namespace=plugin._installed_namespace,episode=REAL_ELAPSED_EPISODES[0 if index==0 else 1],\n                            expected_phase=\'partial\' if index==0 else \'satisfied\',expected_version=1 if index==0 else 2,\n                            cumulative_sender_count=4 if index==2 else None)\n                        if phase is None:return None\n                        if index in (1,2):\n                            with store._lock:\n                                db=store._db;db.execute(\'BEGIN\')\n                                try:\n                                    recall=actual_ordinary_episode_originals_v1(db,namespace=plugin._installed_namespace,\n                                        episode=REAL_ELAPSED_EPISODES[index],issuer=graph._GraphCoordinator__d11_issuer,\n                                        previous_source_ref=settings[\'real_elapsed_day0_source_ref\'],\n                                        required_artifact_refs=(phase[\'work_originals\'][-1][\'work\'][\'artifact_ref\'],phase[\'work_originals\'][-1][\'readback\'][\'content_digest\']) if index==2 else ())\n                                finally:db.rollback()\n                            if recall is None:return None\n                            phase={**phase,\'day4_recall\' if index==1 else \'day5_ordinary\':recall}\n                        return phase\n                    result=await runtime._worker.call(read_phase)\n                elif action==\'real_elapsed_meter\' and set(request)=={\'action\'}:\n                    if settings.get(\'scenario\')!=\'sdk_a06_real_elapsed_phases_v1\':raise ValueError(\'real elapsed meter requires its actual schema\')\n                    result={\'calls\':list(m1_model.calls),\'max_total_calls\':18,\'max_episode_calls\':6,\'max_auxiliary_calls\':2,\n                        \'current_process_model_requests\':len(local_model_requests),\'current_process_sender_calls\':sum(a!=\'get_login_info\' for a in peer.actions),\n                        \'provider_network_requests\':len(network_requests)}\n                elif action==\'hot_reload\' and set(request)=={\'action\'}:\n                    async with ingress_lock:\n                        if observer is not None:\n                            assert not life.event_bus._pending_tasks and life.event_queue.empty()\n                            observer.unbind_handler()\n                        old=instance();old_runtime=old._runtime\n                        success,error=await manager.reload(name)\n                        if not success:raise RuntimeError(\'actual_sdk_reload_failed\')\n                        if observer is not None:\n                            assert await actual_sdk_identity(context,adapter,peer,identity[\'umo\'])==identity\n                            require_actual_sdk_namespace(instance(),identity)\n                            observer.bind_handler()\n                        result={**health(),\'new_plugin_instance\':instance() is not old,\n                            \'old_runtime_worker_closed\':old_runtime is not None and old_runtime._worker is None}\n                else:raise ValueError(\'closed_fixture_action_required\')\n                writer.write(json.dumps({\'status\':\'ok\',\'result\':result},separators=(\',\',\':\')).encode()+b\'\\n\')\n            except Exception as error:\n                private_exception(\'B04_FIXTURE_RPC_EXCEPTION\',error)\n                writer.write(json.dumps({\'status\':\'failed\',\'type\':type(error).__name__},separators=(\',\',\':\')).encode()+b\'\\n\')\n            finally:\n                await writer.drain();writer.close();await writer.wait_closed()\n        endpoint=Path(\'/run/sylanne-b04-host/fixture.sock\')\n        ready=ROOT/\'data/host-ready.json\';ready.write_text(json.dumps(health(),separators=(\',\',\':\')))\n        with ready.open(\'rb\') as stream:os.fsync(stream.fileno())\n        server=await asyncio.start_unix_server(rpc,path=endpoint,limit=65537)\n        cleanup.callback(endpoint.unlink,missing_ok=True)\n        cleanup.push_async_callback(close_listener,server)\n        os.chmod(endpoint,0o600)\n        await stopped.wait()\ntry:\n    asyncio.run(run())\nexcept BaseException as error:\n    private_exception(\'B04_HOST_FIRST_EXCEPTION\',error)\n    failure = {\'type\':type(error).__name__,\n        \'frames\':[{\'file\':f.filename,\'line\':f.lineno,\'function\':f.name}\n            for f in traceback.extract_tb(error.__traceback__)]}\n    if hasattr(error,\'b04_initialization_observation\'):\n        failure[\'initialization\'] = error.b04_initialization_observation\n    (ROOT/\'data/host-first-failure.json\').write_text(json.dumps(failure))\n    raise\n'


def host_process_command_v3(executable, executable_sha256):
    """Public exact registration for the one actual SDK entry above."""
    entry = '/opt/sylanne-b04-fixture/host_sdk_entry.py'
    return dict(fixed_executable_path=executable, executable_sha256=executable_sha256,
        fixed_entry_ref=entry, entry_sha256=hashlib.sha256(SDK_HOST_ENTRY_V1.encode()).hexdigest(),
        fixed_argv=[executable, '-B', entry], fixed_cwd='/var/lib/sylanne-b04-host',
        finite_environment_policy={'PYTHONDONTWRITEBYTECODE': '1'},
        maximum_processes=16, start_timeout=60, drain_timeout=60)


def public_install_request_v3(*, executable, executable_sha256, valid_until_utc, approved_request_v2):
    """Fresh lower-budget input; none of the previous installation IDs survives."""
    request = json.loads(json.dumps(approved_request_v2))
    if request['schema']=='sylanne3.linux-install-request.v2':
        request.pop('host_systemd_unit')
    elif request['schema']!='sylanne3.linux-install-request.v3':
        raise ValueError('approved installer request v2/v3 required')
    request.update(schema='sylanne3.linux-install-request.v3',profile_id='b04',bot_id='b04-bot',
        persona_id='b04-persona',host_uid=1000,host_gid=1000,
        astrbot_plugins_directory='/var/lib/sylanne-b04-host/data/plugins',authority_port=19653,reverse_port=19654,
        workbench_origin='https://localhost:19638',provider_id='b04-local-sdk',model_id='b04-no-model-calls',
        provider_config_path='/etc/sylanne-b04-fixture/provider.json',
        budget_valid_until_utc=valid_until_utc,model_audiences=['owner'],
        onebot_account=['b04-isolated','aiocqhttp','100000001'],onebot_adapter_ref='b04-no-sender',
        provider_cache={'provider_id':'b04-local-sdk'},host_lifecycle={'drain_timeout_seconds':300},
        host_process_command=host_process_command_v3(executable,executable_sha256))
    return request


def public_install_request_v4(*, executable, executable_sha256, approved_request):
    """Preserve explicit v4 business policy; only isolate this local host fixture."""
    request=json.loads(json.dumps(approved_request))
    if request['schema']!='sylanne3.linux-install-request.v4':
        raise ValueError('native SDK identity fixture requires an explicit v4 policy')
    assert request['budget_valid_until_utc']>time.time()
    request.update(profile_id='b04',host_uid=1000,host_gid=1000,
        astrbot_plugins_directory='/var/lib/sylanne-b04-host/data/plugins',authority_port=19653,reverse_port=19654,
        workbench_origin='https://localhost:19638',provider_config_path='/etc/sylanne-b04-fixture/provider.json',
        host_lifecycle={'drain_timeout_seconds':300},
        host_process_command=host_process_command_v3(executable,executable_sha256))
    # Namespace/account are replaced only after the real same-ROOT SDK probe exits.
    return request


NAMESPACE_PREP_V1 = r'''from pathlib import Path
import hashlib,json,os,shutil,subprocess,sys,traceback,zipfile
packet=json.loads(Path(sys.argv[1]).read_text())
assert packet['phase'] in (0,1,2)
evidence=Path(packet['evidence']);stage='private_namespace'
def failure(error):
    frames=[{'file':f.filename,'line':f.lineno,'function':f.name} for f in traceback.extract_tb(error.__traceback__)]
    (evidence/'first-failure.json').write_text(json.dumps({'stage':stage,'type':type(error).__name__,'frames':frames}))
    if isinstance(error,subprocess.CalledProcessError) and error.stderr:
        # Inherited stderr is a root-only fixture file, never a public receipt.
        sys.stderr.write(error.stderr)
def launch_ready(fixture):
    marker=fixture/'launcher-ready.json'
    body=json.dumps({'phase':packet['phase'],'proc_self':os.readlink('/proc/self'),
        'pid_namespace':os.readlink('/proc/self/ns/pid'),'mount_namespace':os.readlink('/proc/self/ns/mnt'),
        **({'authority_expectation_sha256':hashlib.sha256((fixture/'phase-two-authority-expectation.json').read_bytes()).hexdigest()}
            if packet['phase']==2 else {})})
    fd=os.open(marker,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)
    try:os.write(fd,body.encode());os.fsync(fd)
    finally:os.close(fd)
def private_json(path,value):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)
    with os.fdopen(fd,'w') as stream:
        os.fchmod(stream.fileno(),0o600)
        stream.write(json.dumps(value));stream.flush();os.fsync(stream.fileno())
def four_file_identity():
    return [{'kind':kind,'path':'/var/lib/sylanne/genesis/'+relative,
        'device':Path('/var/lib/sylanne/genesis/'+relative).stat().st_dev,
        'inode':Path('/var/lib/sylanne/genesis/'+relative).stat().st_ino}
        for kind,relative in (('core','core/core.sqlite3'),('graph','graph/graph.sqlite3'),
            ('deletion','deletion/deletion.sqlite3'),('execution','execution/execution.sqlite3'))]
def installed_profile():
    installed=Path('/opt/sylanne/code');sys.path.insert(0,str(installed))
    from _runtime_bootstrap import load_canonical_runtime_v1
    load_canonical_runtime_v1(installed)
    from sylanne3.authority_service.linux_installation_security_v1 import read_installed_json_v1
    return read_installed_json_v1('/etc/sylanne/client/profiles/b04/profile.json')
def prepare_owner_seed():
    profile=installed_profile();policy=profile['installation_policy'];namespace=policy['authority_namespace']
    installed=Path('/opt/sylanne/code')
    complete=json.loads((evidence/'phase-zero-complete.json').read_text())
    bootstrap=json.loads((fixture/'bootstrap-provision-original.json').read_text())
    assert complete['status']=='actual_namespace_provision_completed_no_owner'
    assert bootstrap['four_file_identities']==four_file_identity()
    assert bootstrap['receipt']['installation_id']==policy['installation_id']
    from sylanne3.runtime_contracts import canonical_digest
    assert complete['receipt_sha256']==canonical_digest(bootstrap['receipt'])
    assert bootstrap['receipt']['manifest_digest']==packet['manifest_sha256']
    admin=[str(executable),'-B',str(installed/'scripts/alpha1/authority_linux_admin.py'),
        '--namespace',namespace,'--profile-id','b04','--installation-id',policy['installation_id']]
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    from sylanne3.authority_service.v2_owner_contract import OwnerPrincipalV1,OwnerActorBindingV1,to_wire
    from sylanne3.authority_service.v2_owner_proof import OwnerCredentialRegistrationV1,to_wire as proof_wire
    from sylanne3.runtime_contracts import NamespaceId
    from uuid import uuid4
    from datetime import datetime,timezone,timedelta
    signer=Ed25519PrivateKey.generate();principal=OwnerPrincipalV1('b04-installed-fixture','owner',str(uuid4()))
    registration=OwnerCredentialRegistrationV1(policy['expected_authority_id'],namespace,policy['installation_id'],
        principal,'b04-owner-key',1,signer.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw),str(uuid4()))
    expiry=(datetime.now(timezone.utc)+timedelta(hours=1)).replace(microsecond=0).strftime('%Y-%m-%dT%H:%M:%SZ')
    for action,payload in [('pair-credential',{'registration':proof_wire(registration),'valid_until_utc':expiry}),
        ('pair-actor',{'binding':to_wire(OwnerActorBindingV1(policy['expected_authority_id'],policy['installation_id'],
            NamespaceId(**policy['namespace']),'b04-owner',principal,1))})]:
        subprocess.run([*admin,action],input=json.dumps(payload),check=True,capture_output=True,text=True)
    from sylanne3.host.authority_profile import _policy_from_payload
    from sylanne3.runtime_contracts import canonical_digest
    from sylanne3.graph_types import owner_grant_policy_digest_v1
    from sylanne3.authority_service.v2_owner_contract import OwnerClaimTicketV1,OwnerAuthorizationGuardV1,OwnerAuthorizationOperationV1
    from dataclasses import asdict,replace
    policy=_policy_from_payload(profile);namespace=policy.namespace
    digest=canonical_digest(policy.digest_payload());operation='namespace-provision:'+digest
    creation=bootstrap['receipt']
    assert creation['operation_id']==operation and creation['input_digest']==digest
    issue=str(uuid4());grant_id='b04-first-owner';ticket_id=str(uuid4())
    ticket=OwnerClaimTicketV1(policy.expected_authority_id,policy.installation_id,namespace,principal,ticket_id,
        operation,'sha256:'+digest,'sha256:'+digest,uuid4().hex,expiry)
    grant=dict(schema='sylanne3.graph.owner_grant.v1',authority_id=policy.expected_authority_id,
        installation_id=policy.installation_id,grant_id=grant_id,principal=asdict(principal),ticket_id=ticket_id,
        creation_operation_id=operation,creation_digest='sha256:'+digest,issue_operation_id=issue,
        grant_revision=1,state='pending_authority',scope=namespace.bot_id+'/'+namespace.persona_id,issuer_ref='authority:paired-installation',
        capabilities=sorted(['workbench.read','workbench.create','workbench.diagnose','workbench.control','workbench.maintain']+
            (['workbench.activate','d02.body_policy.install','c04.cpu_policy.install'] if packet['host_settings'].get('scenario') in ('sdk_m1_two_messages_v1','sdk_m1_first_bubble_stop_v1','sdk_m1_first_bubble_unknown_v1','sdk_ordinary_old_source_v1','sdk_ordinary_greeting_v1','sdk_d13_v6_256_current_v1','sdk_d13_v7_256_current_v1','sdk_a06_real_elapsed_phases_v1') else [])+(['d13.counter.cpu_policy.install','d13.counter.cpu.prepare'] if packet['host_settings'].get('scenario')=='sdk_d13_v7_256_current_v1' else [])),
        purposes=sorted(['workbench_view','workbench_user_action']+
            (['context','consolidation','proposal'] if packet['host_settings'].get('scenario') in ('sdk_m1_two_messages_v1','sdk_m1_first_bubble_stop_v1','sdk_m1_first_bubble_unknown_v1','sdk_ordinary_old_source_v1','sdk_ordinary_greeting_v1','sdk_d13_v6_256_current_v1','sdk_d13_v7_256_current_v1','sdk_a06_real_elapsed_phases_v1') else [])),audiences=sorted(['owner']),activation_generation=1,
        graph_incarnation=creation['graph_incarnation'])
    ticket=replace(ticket,policy_digest=owner_grant_policy_digest_v1(grant,bot=namespace.bot_id,persona=namespace.persona_id))
    guard=OwnerAuthorizationGuardV1(policy.expected_authority_id,policy.installation_id,namespace,0,'genesis',0,0)
    authorization=OwnerAuthorizationOperationV1('issue',issue,policy.expected_authority_id,policy.installation_id,
        namespace,principal,grant_id,'sha256:'+canonical_digest(grant),0,guard,ticket)
    subprocess.run([*admin,'pair-creation'],input=json.dumps({'ticket':to_wire(ticket),'valid_until_utc':expiry}),
        check=True,capture_output=True,text=True)
    first_owner={'first_owner_ticket':to_wire(ticket),'first_owner_operation':to_wire(authorization),
        'first_owner_grant_value':grant}
    policy=profile['installation_policy']
    seed={**packet,**first_owner,'registration':proof_wire(registration),'principal':__import__('dataclasses').asdict(principal),
        'signing_key':signer.private_bytes(serialization.Encoding.Raw,serialization.PrivateFormat.Raw,serialization.NoEncryption()).hex(),
        'owner_expiry':expiry,'policy':policy,'profile':profile,'bootstrap_original':bootstrap}
    private_json(fixture/'controller-seed.json',seed)
    private_json(fixture/'controller-input.json',seed)

try:
    assert os.getpid()==1 and os.geteuid()==0 and os.readlink('/proc/self')=='1'
    subprocess.run(['mount','--make-rprivate','/'],check=True)
    passwd=Path('/etc/passwd').read_bytes();groups=Path('/etc/group').read_bytes()
    persistent=Path(packet['persistent_tree'])
    for name,target in (('etc','/etc'),('opt','/opt'),('run','/run')):
        source=persistent/name;source.mkdir(exist_ok=True,mode=0o755)
        subprocess.run(['mount','--bind',str(source),target],check=True)
    if packet['phase']==0:
        Path('/etc/passwd').write_bytes(passwd);Path('/etc/group').write_bytes(groups)
    prefix=Path('/opt/sylanne-runtime');(prefix/'bin').mkdir(parents=True,exist_ok=True)
    site=prefix/'lib/python3.12/site-packages';site.mkdir(parents=True,exist_ok=True)
    dependency=json.loads(Path(packet['dependency_manifest']).read_text())
    executable=prefix/'bin/python3.12'
    raw=Path(dependency['executable_source']).read_bytes()
    assert hashlib.sha256(raw).hexdigest()==dependency['executable_sha256']
    if packet['phase']==0:
        executable.write_bytes(raw);executable.chmod(0o755)
        (prefix/'pyvenv.cfg').write_text('home = /usr/bin\ninclude-system-site-packages = false\nversion = 3.12.3\n')
    else:assert hashlib.sha256(executable.read_bytes()).hexdigest()==dependency['executable_sha256']
    for entry in dependency['entries']:
        source=Path(dependency['dependency_source'] if entry['source_kind']=='existing_dependency' else dependency['official_sdk_source'])/entry['relative_path']
        body=source.read_bytes()
        assert len(body)==entry['size'] and hashlib.sha256(body).hexdigest()==entry['sha256']
        destination=site/entry['relative_path'];destination.parent.mkdir(parents=True,exist_ok=True)
        if packet['phase']==0:destination.write_bytes(body);destination.chmod(0o644)
        else:assert destination.read_bytes()==body
    # Source libraries remain untouched. This mount makes the installed prefix immutable.
    subprocess.run(['mount','--bind',str(prefix),str(prefix)],check=True)
    subprocess.run(['mount','-o','remount,bind,ro',str(prefix)],check=True)
    observed=subprocess.run([str(executable),'-I','-B','-c',
        "import sys,json;from importlib.metadata import version;print(json.dumps({'prefix':sys.prefix,'sdk':version('astrbot'),'python':sys.version.split()[0]}))"],
        check=True,capture_output=True,text=True)
    identity=json.loads(observed.stdout)
    assert identity=={'prefix':str(prefix),'sdk':'4.28.2','python':'3.12.3'}
    (evidence/'installed-runtime-prefix.json').write_text(json.dumps({'identity':identity,
        'executable_sha256':hashlib.sha256(executable.read_bytes()).hexdigest(),
        'dependency_manifest_sha256':hashlib.sha256(Path(packet['dependency_manifest']).read_bytes()).hexdigest(),
        'dependency_files_verified':len(dependency['entries']),'readonly':True}))
    varlib=persistent/'varlib';varlib.mkdir(exist_ok=True,mode=0o755)
    subprocess.run(['mount','--bind',str(varlib),'/var/lib'],check=True)
    private_run=Path('/run/sylanne-b04-host');private_run.mkdir(mode=0o700,exist_ok=True)
    os.chown(private_run,1000,1000);private_run.chmod(0o700)
    (private_run/'fixture.sock').unlink(missing_ok=True)
    fixture=Path('/opt/sylanne-b04-fixture');fixture.mkdir(mode=0o755,exist_ok=True)
    for stale in ('host-ready.json','host-first-failure.json'):
        (Path('/var/lib/sylanne-b04-host/data')/stale).unlink(missing_ok=True)
    if packet['host_settings'].get('sdk_ingress') is not None and packet['phase']!=0:
        packet['request']=json.loads(Path('/etc/sylanne-b04-fixture/request.json').read_text())
        if packet['host_settings'].get('scenario') in ('sdk_m1_two_messages_v1','sdk_m1_first_bubble_stop_v1','sdk_m1_first_bubble_unknown_v1','sdk_ordinary_old_source_v1','sdk_ordinary_greeting_v1','sdk_d13_v6_256_current_v1','sdk_d13_v7_256_current_v1','sdk_a06_real_elapsed_phases_v1'):
            packet['host_settings']['m1_model_fixture']=json.loads(Path('/etc/sylanne-b04-fixture/m1-private-config.json').read_text())
            if packet['host_settings']['scenario']=='sdk_a06_real_elapsed_phases_v1':
                packet['host_settings']['m1_model_fixture']['phase_index']=packet['real_elapsed_phase_index']
        packet['sdk_identity']=json.loads(Path('/etc/sylanne-b04-fixture/sdk-identity.json').read_text())
    if packet['phase']==1:
        stage='offline_owner_pairing_after_completed_bootstrap'
        prepare_owner_seed()
        settings={**packet['host_settings'],'fixture_phase':1}
        private=Path('/var/lib/sylanne-b04-host/fixture-input.json')
        private_json(private,settings);os.chown(private,1000,1000)
        launch_ready(fixture)
        launcher=Path('/opt/sylanne/bootstrap/runtime/scripts/alpha1/root_process_launcher.py')
        os.execv(str(executable),[str(executable),'-B',str(launcher)])
    if packet['phase']==2:
        # Real previous PID1/Authority have exited; only now open the offline daemon.
        seed=json.loads((fixture/'controller-seed.json').read_text())
        installed=Path('/opt/sylanne/code');policy=seed['policy']
        if packet['host_settings']['scenario']=='sdk_a06_real_elapsed_phases_v1':
            from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
            from cryptography.hazmat.primitives import serialization
            from sylanne3.authority_service.v2_owner_contract import OwnerPrincipalV1
            from sylanne3.authority_service.v2_owner_proof import OwnerCredentialRegistrationV1,to_wire as proof_wire
            from datetime import datetime,timezone
            from uuid import uuid4
            signer=Ed25519PrivateKey.generate();principal=OwnerPrincipalV1(**seed['principal'])
            expiry=datetime.fromtimestamp(min(time.time()+3600,packet['request']['budget_valid_until_utc']),timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
            registration=OwnerCredentialRegistrationV1(policy['expected_authority_id'],policy['authority_namespace'],policy['installation_id'],
                principal,'b04-real-elapsed-'+str(uuid4()),1,signer.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw),str(uuid4()))
            subprocess.run([str(executable),'-B',str(installed/'scripts/alpha1/authority_linux_admin.py'),'--namespace',policy['authority_namespace'],
                '--profile-id','b04','--installation-id',policy['installation_id'],'pair-credential'],
                input=json.dumps({'registration':proof_wire(registration),'valid_until_utc':expiry}),check=True,capture_output=True,text=True)
            seed.update(registration=proof_wire(registration),owner_expiry=expiry,
                signing_key=signer.private_bytes(serialization.Encoding.Raw,serialization.PrivateFormat.Raw,serialization.NoEncryption()).hex())
            private_json(fixture/'controller-seed.json',seed)

        principal_file=Path('/etc/sylanne-b04-fixture/principal.json')
        private_json(principal_file,seed['principal'])
        result=subprocess.run([str(executable),'-B',str(installed/'scripts/alpha1/authority_linux_management.py'),
            'grant','--namespace',policy['authority_namespace'],'--profile-id','b04','--installation-id',policy['installation_id'],
            '--principal',str(principal_file),'--permission','installation.logs.read','--permission','installation.settings.read',
            '--permission','installation.settings.enabled.write','--valid-until-utc',seed['owner_expiry']],
            check=True,capture_output=True,text=True)
        (evidence/'offline-current-key-management-grant.json').write_text(result.stdout)
        assert seed['bootstrap_original']['four_file_identities']==four_file_identity()
        private_json(fixture/'controller-input.json',{**seed,**packet})
        settings={**packet['host_settings'],'fixture_phase':2}
        private=Path('/var/lib/sylanne-b04-host/fixture-input.json')
        private_json(private,settings);os.chown(private,1000,1000)
        endpoint_profile=installed_profile()
        from sylanne3.authority_service.installed_process_supervisor_v1 import load_process_supervisor_spec_v1,_read_selected_invocation
        spec=load_process_supervisor_spec_v1('/etc/sylanne/supervision/authority.json')
        selected=_read_selected_invocation(spec)
        private_json(fixture/'phase-two-authority-expectation.json',{
            'phase':2,'pid_namespace':os.readlink('/proc/self/ns/pid'),
            'expected_final_argv':selected['expected_final_argv'],
            'executable':spec.fixed_executable_path,'executable_sha256':spec.executable_sha256,
            'entry':selected['expected_final_entry'],'entry_sha256':selected['expected_final_entry_sha256'],
            'uid':spec.expected_uid,'gid':spec.expected_gid,'host':endpoint_profile['host'],'port':endpoint_profile['port'],
            'selection_revision':selected['selection_revision'],'selected_cohort_digest':selected['selected_cohort_digest'],
            'manifest_sha256':selected['selected_manifest_digest']})
        launch_ready(fixture)
        launcher=Path('/opt/sylanne/bootstrap/runtime/scripts/alpha1/root_process_launcher.py')
        os.execv(str(executable),[str(executable),'-B',str(launcher)])
    host=fixture/'host_sdk_entry.py';host.write_text(packet['host_entry']);host.chmod(0o644)
    controller=fixture/'controller.py';controller.write_text(packet['controller']);controller.chmod(0o644)
    if packet['host_settings'].get('scenario') in ('sdk_m1_two_messages_v1','sdk_m1_first_bubble_stop_v1','sdk_m1_first_bubble_unknown_v1','sdk_ordinary_old_source_v1','sdk_ordinary_greeting_v1','sdk_d13_v6_256_current_v1','sdk_d13_v7_256_current_v1','sdk_a06_real_elapsed_phases_v1'):
        for filename in packet['m1_helpers']:
            content=packet['m1_helpers'][filename]
            assert hashlib.sha256(content.encode()).hexdigest()==packet['m1_helper_pins'][filename]
            target=fixture/filename;target.write_text(content);target.chmod(0o755 if filename=='sdk_d13_v6_counter_fixture_v1.py' else 0o644)
    host_root=Path('/var/lib/sylanne-b04-host');host_root.mkdir(mode=0o755)
    (host_root/'data/plugins').mkdir(parents=True)
    for path in (host_root/'data',host_root/'data/plugins'):os.chown(path,1000,1000)
    settings={**packet['host_settings'],'fixture_phase':0};private=host_root/'fixture-input.json'
    private_json(private,settings);os.chown(private,1000,1000)
    inputs=Path('/etc/sylanne-b04-fixture');inputs.mkdir(mode=0o750);os.chown(inputs,0,1000)
    provider=inputs/'provider.json';provider.write_text(json.dumps(packet['provider']));provider.chmod(0o640);os.chown(provider,0,1000)
    request=inputs/'request.json'
    candidate=Path('/opt/b04-candidate');candidate.mkdir()
    with zipfile.ZipFile(packet['package']) as archive:archive.extractall(candidate)
    if packet['host_settings'].get('sdk_ingress') is not None:
        stage='native_sdk_identity_before_installation'
        subprocess.run([str(executable),'-B',str(host),'--identity-only'],check=True,
            user=1000,group=1000,extra_groups=(),stdout=subprocess.DEVNULL,timeout=30)
        observed=json.loads((host_root/'data/sdk-preinstall-identity.json').read_text())
        sdk=packet['host_settings']['sdk_ingress']
        assert observed['schema']=='sylanne.sdk-preinstall-identity.v1' and observed['sdk']=='4.28.2'
        assert (observed['platform_id'],observed['platform_name'],observed['self_id'],observed['selected_persona_id'])==(
            sdk['platform']['id'],'aiocqhttp',sdk['self_id'],sdk['persona_id'])
        assert packet['request']['schema']=='sylanne3.linux-install-request.v4'
        if packet['host_settings'].get('scenario') in ('sdk_m1_two_messages_v1','sdk_m1_first_bubble_stop_v1','sdk_m1_first_bubble_unknown_v1','sdk_ordinary_old_source_v1','sdk_ordinary_greeting_v1','sdk_d13_v6_256_current_v1','sdk_d13_v7_256_current_v1','sdk_a06_real_elapsed_phases_v1'):
            ingress=json.loads((host_root/'data/sdk-preinstall-ingress.json').read_text())
            assert ingress['schema']=='sylanne.sdk-preinstall-ingress.v1' and ingress['visibility']=='private'
            observed['ingress_identity']=ingress
        configured={'schema':'sylanne.astrbot.installed-namespace.v1','platform_id':observed['platform_id'],
            'self_id':observed['self_id'],'selected_persona_id':observed['selected_persona_id']}
        packet['request'].update(astrbot_namespace_v1=configured,bot_id=observed['bot_id'],persona_id=observed['persona_id'],
            onebot_account=[observed['platform_id'],observed['platform_name'],observed['self_id']])
        packet['sdk_identity']=observed
        identity_path=inputs/'sdk-identity.json';private_json(identity_path,observed)
        identity_path.chmod(0o640);os.chown(identity_path,0,1000)
        receipt={'schema':'sylanne.b04.sdk-preinstall-observation.v1','identity':observed,
            'manifest_sha256':packet['manifest_sha256'],'host_entry_sha256':hashlib.sha256(host.read_bytes()).hexdigest(),
            'identity_sha256':hashlib.sha256(identity_path.read_bytes()).hexdigest(),
            'identity_process_exited':True,'scope':'native SDK observation before installer signing; no business acceptance'}
        (evidence/'sdk-preinstall-identity.json').write_text(json.dumps(receipt))
    private_json(request,packet['request'])
    if packet['host_settings'].get('scenario') in ('sdk_m1_two_messages_v1','sdk_m1_first_bubble_stop_v1','sdk_m1_first_bubble_unknown_v1','sdk_ordinary_old_source_v1','sdk_ordinary_greeting_v1','sdk_d13_v6_256_current_v1','sdk_d13_v7_256_current_v1','sdk_a06_real_elapsed_phases_v1'):
        stage='explicit_initial_M1_policies_after_actual_SDK_identity'
        config=inputs/'m1-private-config.json'
        subprocess.run([str(executable),'-B',str(fixture/'sdk_m1_fixture_contract_v1.py'),'--prepare',
            str(candidate),str(request),str(provider),str(identity_path),str(config),
             packet['host_settings']['scenario'] if packet['host_settings']['scenario'] in ('sdk_ordinary_old_source_v1','sdk_ordinary_greeting_v1','sdk_d13_v6_256_current_v1','sdk_d13_v7_256_current_v1','sdk_a06_real_elapsed_phases_v1') else 'sdk_m1_two_messages_v1'],check=True,stdout=subprocess.DEVNULL,timeout=30)
        packet['request']=json.loads(request.read_text())
        packet['host_settings']['m1_model_fixture']=json.loads(config.read_text())
        settings={**packet['host_settings'],'fixture_phase':0};private_json(private,settings);os.chown(private,1000,1000)
        (evidence/'m1-initial-policy-pins.json').write_text(json.dumps({'request_sha256':hashlib.sha256(request.read_bytes()).hexdigest(),
            'provider_sha256':hashlib.sha256(provider.read_bytes()).hexdigest(),'helper_pins':packet['m1_helper_pins'],
            'identity_sha256':hashlib.sha256(identity_path.read_bytes()).hexdigest(),'scenario':packet['host_settings']['scenario']}))
    stage='formal_installer_plan'
    argv=[str(executable),'-B',str(candidate/'scripts/alpha1/install_linux.py'),
        '--package',packet['package'],'--package-sha256',packet['package_sha256'],
        '--manifest-sha256',packet['manifest_sha256'],'--request',str(request)]
    for flag,label in (('--plan','installer-plan'),('--install','installer-install')):
        stage=label
        result=subprocess.run([*argv,flag],check=True,capture_output=True,text=True)
        parsed=json.loads(result.stdout.splitlines()[-1]);(evidence/(label+'.json')).write_text(json.dumps(parsed))
    stage='offline_management_seed'
    installed=Path('/opt/sylanne/code')
    sys.path.insert(0,str(installed))
    from _runtime_bootstrap import load_canonical_runtime_v1
    load_canonical_runtime_v1(installed)
    from sylanne3.authority_service.linux_installation_security_v1 import read_installed_json_v1
    profile=read_installed_json_v1('/etc/sylanne/client/profiles/b04/profile.json')
    policy=profile['installation_policy'];namespace=policy['authority_namespace']
    management=[str(executable),'-B',str(installed/'scripts/alpha1/authority_linux_management.py'),
        '--namespace',namespace,'--profile-id','b04','--installation-id',policy['installation_id']]
    seed=subprocess.run([*management,'initialize','--initial-enabled','true'],check=True,capture_output=True,text=True)
    (evidence/'management-seed.json').write_text(seed.stdout)
    bootstrap={**packet,'policy':policy,'profile':profile,'four_file_identities':four_file_identity()}
    private_json(fixture/'controller-input.json',bootstrap)
    # Phase zero has no Owner identity; its sibling controller consumes actual provisioning.
    launch_ready(fixture)
    stage='actual_pid1_launcher'
    launcher=Path('/opt/sylanne/bootstrap/runtime/scripts/alpha1/root_process_launcher.py')
    os.execv(str(executable),[str(executable),'-B',str(launcher)])
except BaseException as error:
    failure(error);raise
'''


CONTROLLER_V1 = r'''from pathlib import Path
import asyncio,base64,hashlib,json,os,socket,subprocess,sys,time,traceback
from dataclasses import asdict,replace
from uuid import uuid4
if sys.argv[1]=='--authority-readiness':
    assert os.geteuid()==1000
    root=Path('/opt/sylanne/code');sys.path.insert(0,str(root));sys.dont_write_bytecode=True
    from _runtime_bootstrap import load_canonical_runtime_v1
    load_canonical_runtime_v1(root)
    from sylanne3.host.authority_profile import load_admin_installation_bundle
    from sylanne3.host.authority_client import AuthorityProvisioningRequest,PublisherPackageIdentity,AUTHORITY_PROTOCOL,AUTHORITY_V2_PROTOCOL
    from sylanne3.host.installed_package import verify_installed_backend_runtime_v1
    from sylanne3.host.mtls_transport import MtlsAuthorityTransport
    async def readonly_handshake():
        bundle=load_admin_installation_bundle('b04');policy=bundle.installation_policy
        if not verify_installed_backend_runtime_v1(root,policy.manifest_digest).verified:
            raise RuntimeError('cold_authority_current_installed_profile_changed')
        request=AuthorityProvisioningRequest(AUTHORITY_PROTOCOL,'b04','astrbot_plugin_sylanne','4.28.1',
            root,root,PublisherPackageIdentity(policy.manifest_digest))
        transport=MtlsAuthorityTransport({'b04':bundle.tls_profile})
        try:
            handshake=await transport.handshake(request,protocol=AUTHORITY_V2_PROTOCOL)
            grant=await transport.installation_grant_v2(request,handshake)
            if (not handshake.valid_pairing() or grant.installation_id!=policy.installation_id
                    or grant.authority_id!=policy.expected_authority_id or grant.manifest_digest!=policy.manifest_digest):
                raise RuntimeError('cold_authority_readonly_handshake_installation_differs')
            return {'installation_id':grant.installation_id,'authority_id':grant.authority_id,'manifest_digest':grant.manifest_digest}
        finally:await transport.close()
    print(json.dumps(asyncio.run(readonly_handshake())));raise SystemExit(0)
packet=json.loads(Path(sys.argv[1]).read_text());evidence=Path(packet['evidence'])
assert packet['phase'] in (0,1,2)
assert os.getpid()==1 and os.geteuid()==0 and os.readlink('/proc/self')=='1'
domain=evidence/('controller-domain-phase-'+str(packet['phase'])+'.json')
domain.write_text(json.dumps({'role':'fixture-controller','proc_self':os.readlink('/proc/self'),
    'uid':os.geteuid(),'pid_namespace':os.readlink('/proc/self/ns/pid'),
    'mount_namespace':os.readlink('/proc/self/ns/mnt')}))
with domain.open('rb') as stream:os.fsync(stream.fileno())
root=Path('/opt/sylanne/code');sys.path.insert(0,str(root));sys.dont_write_bytecode=True
from _runtime_bootstrap import load_canonical_runtime_v1
load_canonical_runtime_v1(root)
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sylanne3.authority_service.v2_owner_proof import from_wire as proof_from_wire
from sylanne3.authority_service.v2_owner_session import OwnerSessionLoginRequestV1,to_wire as session_wire
from sylanne3.authority_service.v2_owner_contract import (OwnerClaimTicketV1,OwnerAuthorizationGuardV1,
    OwnerAuthorizationOperationV1,OwnerAuthorizationReceiptV1,to_wire,from_wire)
from sylanne3.graph_types import owner_grant_policy_digest_v1
from sylanne3.runtime_contracts import NamespaceId,canonical_digest
from sylanne3.host.authority_profile import _policy_from_payload
from sylanne3.installation_policy import model_capability_ref
if packet['phase'] in (1,2):
    registration=proof_from_wire(packet['registration']);principal=registration.principal
    signer=Ed25519PrivateKey.from_private_bytes(bytes.fromhex(packet.pop('signing_key')))
policy=_policy_from_payload(packet['profile']);namespace=policy.namespace
base='/api/v1/plugins/extensions/astrbot_plugin_sylanne/workbench/v1'
origin=packet['request']['workbench_origin'];stage='host_startup';stages=[]
def note(name,**values):
    stages.append({'stage':name,**values});(evidence/'progress.json').write_text(json.dumps(stages))
    (evidence/('progress-phase-'+str(packet['phase'])+'.json')).write_text(json.dumps(stages))
def until(read,timeout=60):
    end=time.monotonic()+timeout
    while time.monotonic()<end:
        result=read()
        if result:return result
        time.sleep(.05)
    raise TimeoutError('bounded_fixture_stage')
def wait_host():
    def ready():
        if Path('/var/lib/sylanne-b04-host/data/host-first-failure.json').exists():
            raise RuntimeError('actual_sdk_host_failed_before_private_endpoint')
        return Path('/run/sylanne-b04-host/fixture.sock').exists()
    until(ready)
def rpc(action,**values):
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as channel:
        channel.settimeout(65);channel.connect('/run/sylanne-b04-host/fixture.sock')
        channel.sendall(json.dumps({'action':action,**values},separators=(',',':')).encode()+b'\n')
        with channel.makefile('rb') as stream:answer=json.loads(stream.readline(1048577))
    if answer['status']!='ok':raise RuntimeError('actual_host_fixture_'+answer['type'])
    return answer['result']
def observe_native_sdk_route(message_id):
    if packet['host_settings'].get('sdk_ingress') is None:return
    observation=rpc('ordinary_ingress',message_id=message_id,text='B04 local SDK identity route observation')
    assert observation['sdk_identity']==packet['sdk_identity']
    assert observation['queued']==1 and observation['handler_entered'] and observation['handler_returned']
    assert observation['pipeline_entered'] and observation['pipeline_returned']
    assert observation['local_model_requests']==observation['sender_calls']==0
    note('native_sdk_identity_and_handler_route',**observation)
    target=evidence/('sdk-ingress-phase-'+str(packet['phase'])+'-message-'+str(message_id)+'.json')
    target.write_text(json.dumps(observation,indent=2))
    with target.open('rb') as stream:os.fsync(stream.fileno())

def http(method,path,data=None,headers=None):
    result=rpc('http',method=method,path=path,headers={'Origin':origin,**(headers or {})},json=data)
    if result['http_status']!=200:
        sys.stderr.write('B04_HTTP_FAILURE '+json.dumps({'method':method,'path':path,
            'http_status':result['http_status'],'response':result['json']},separators=(',',':'))+'\n')
        sys.stderr.flush();os.fsync(sys.stderr.fileno())
        problem=result['json'].get('problem',{}).get('code','http_rejected')
        raise RuntimeError('actual_http_'+str(result['http_status'])+'_'+str(problem))
    return result['json']
def demote():os.setgroups([]);os.setgid(1000);os.setuid(1000)
def console(action,data):
    control=str(root/'scripts/alpha1/authority_linux_control.py')
    observer=r"""import json,runpy,sys,time,faulthandler
control=sys.argv[1];sys.argv=sys.argv[1:]
def trace(frame,event,arg):
    if frame.f_code.co_filename!=control:return None
    if event=='line':
        sys.stderr.write('B04_CONSOLE_STAGE '+json.dumps({'line':frame.f_lineno,'utc':time.time(),'monotonic':time.monotonic()},separators=(',',':'))+'\n')
        sys.stderr.flush()
    return trace
sys.settrace(trace)
faulthandler.dump_traceback_later(55,repeat=False,file=sys.stderr)
try:runpy.run_path(control,run_name='__main__')
finally:faulthandler.cancel_dump_traceback_later()
"""
    def record(status,stdout,stderr,returncode=None):
        if isinstance(stderr,bytes):stderr=stderr.decode('utf-8',errors='replace')
        import re
        stack_frames = []
        for line in (stderr or '').splitlines():
            matched = re.fullmatch(r'\s*File "([^"]+)", line (\d+) in (.+)', line)
            if matched:
                stack_frames.append({'file': matched[1], 'line': int(matched[2]), 'function': matched[3]})
        rows=[]
        for line in (stderr or '').splitlines():
            if not line.startswith('B04_CONSOLE_STAGE '):continue
            value=json.loads(line.removeprefix('B04_CONSOLE_STAGE '))
            if set(value)=={'line','utc','monotonic'}:rows.append(value)
        result={'action':action,'status':status,'timeout_seconds':70,'returncode':returncode,
            'stdout_bytes':len((stdout or '').encode() if isinstance(stdout,str) else stdout or b''),
            'stderr_bytes':len((stderr or '').encode()),'script_sha256':hashlib.sha256(Path(control).read_bytes()).hexdigest(),
            'stages':rows[-128:],'first_bounded_stack_frames':stack_frames,
            'scope':'actual console line positions and one55s stack only; no inputs,outputs,locals or credentials'}
        target=evidence/('console-stage-phase-'+str(packet['phase'])+'-'+str(len(list(evidence.glob('console-stage-phase-*.json'))))+'.json')
        target.write_text(json.dumps(result,indent=2))
        with target.open('rb') as stream:os.fsync(stream.fileno())
    try:
        result=subprocess.run([sys.executable,'-B','-c',observer,control,'--profile','b04',action],
            input=json.dumps(data),capture_output=True,text=True,preexec_fn=demote,timeout=70)
    except subprocess.TimeoutExpired as error:
        record('first_timeout',error.stdout,error.stderr)
        raise
    record('completed' if result.returncode==0 else 'first_child_failure',result.stdout,result.stderr,result.returncode)
    if result.returncode:
        raise RuntimeError('actual_console_'+action+'_failed')
    return json.loads(result.stdout.splitlines()[-1])
def console_login(*,audience='sylanne-owner-console'):
    request=OwnerSessionLoginRequestV1(policy.expected_authority_id,policy.authority_namespace,policy.installation_id,
        principal,registration.credential_id,registration.credential_epoch,audience,origin)
    challenge=console('challenge',{'request':session_wire(request)})
    signature=signer.sign(base64.b64decode(challenge['signing_payload_base64']))
    accepted=console('accept',{'challenge':challenge['challenge'],'signature_base64':base64.b64encode(signature).decode()})
    token=accepted['token']
    original=Path('/opt/sylanne-b04-fixture')/(('consumed-owner-login-phase-' if audience=='owner' else 'consumed-console-login-phase-')+str(packet['phase'])+'.json')
    original.write_text(json.dumps({'request':session_wire(request),'challenge':challenge['challenge'],
        'accepted_session_token_sha256':hashlib.sha256(token.encode()).hexdigest()}));original.chmod(0o600)
    return {'owner_actor_id':'b04-owner','owner_session_request':session_wire(request),'owner_session_token':token}
def dashboard_owner_login():
    http('POST','/api/v1/auth/login',{'username':packet['host_settings']['dashboard_username'],
        'password':packet['host_settings']['dashboard_password']})
    request=OwnerSessionLoginRequestV1(policy.expected_authority_id,policy.authority_namespace,policy.installation_id,
        principal,registration.credential_id,registration.credential_epoch,'owner',origin)
    challenge=http('POST',base+'/owner/challenge',{'request':session_wire(request)})
    signature=signer.sign(base64.b64decode(challenge['signing_payload_base64']))
    http('POST',base+'/owner/complete',{'challenge':challenge['challenge'],
        'signature_base64':base64.b64encode(signature).decode()})

    session=http('GET',base+'/session')
    if session['dashboard_session']!='authenticated' or session['owner_session']!='unlocked':
        raise RuntimeError('signed_owner_not_authenticated')
    return session['csrf_token']

def cold_authority_protocol_ready():
    child=subprocess.run([sys.executable,'-B','/opt/sylanne-b04-fixture/controller.py','--authority-readiness'],
        capture_output=True,text=True,preexec_fn=demote,timeout=70)
    if child.returncode:
        sys.stderr.write('B04_READINESS_CHILD_FAILURE '+json.dumps({'returncode':child.returncode,
            'stdout':child.stdout,'stderr':child.stderr},separators=(',',':'))+'\n')
        sys.stderr.flush();os.fsync(sys.stderr.fileno())
        raise RuntimeError('cold_authority_readonly_protocol_handshake_failed')
    result=json.loads(child.stdout.splitlines()[-1])
    if (result['installation_id'],result['authority_id'],result['manifest_digest'])!=(
            policy.installation_id,policy.expected_authority_id,policy.manifest_digest):
        raise RuntimeError('cold_authority_readonly_handshake_installation_differs')
    note('cold_authority_actual_pinned_tls_protocol_ready',installation_id=result['installation_id'],
        manifest_sha256=result['manifest_digest'],handshake_count=1,owner_requests=0)

def command(action,values,csrf,purpose='workbench_user_action'):
    return http('POST',base+'/commands',{'schema_version':'d12.contract.v1','action':action,
        'scope':namespace.bot_id+'/'+namespace.persona_id,'purpose':purpose,'audience':'owner','operation_id':str(uuid4()),'input':values},
        {'X-CSRF-Token':csrf})
def observe_first_lifecycle_cause(operation,credentials,started):
    deadline=min(started[1]+120,packet['diagnostic_outer_deadline_monotonic'])
    log_path=evidence.parent/('b04-namespace-phase-'+str(packet['phase'])+'.stderr')
    marker='Sylanne D12 lifecycle worker cause metadata: '
    original=None;cause=None;event=None;head=None
    private=Path('/opt/sylanne-b04-fixture/first-lifecycle-cause-original.jsonl')
    descriptor=os.open(private,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(descriptor,'w') as stream:
        os.fchmod(stream.fileno(),0o600)
        def preserve(kind,value):
            stream.write(json.dumps({'kind':kind,'observed_utc':time.time(),'value':value},separators=(',',':'))+'\n')
            stream.flush();os.fsync(stream.fileno())
        def worker_cause():
            for line in log_path.read_text().splitlines(keepends=True):
                if not line.endswith('\n') or marker not in line:continue
                chain=json.loads(line.split(marker,1)[1])
                return [{'type':item['type'],'frames':[
                    {'file':frame['file'],'line':frame['line'],'function':frame['function']}
                    for frame in item['frames']]} for item in chain]
            return None
        while time.monotonic()<deadline:
            cause=worker_cause()
            if cause is not None:
                preserve('actual_private_worker_cause',cause);event='private_worker_cause';break
            original=console('status',{**credentials,'operation_id':operation})['original']
            preserve('actual_independent_status_original',original)
            cause=worker_cause()
            if cause is not None:
                preserve('actual_private_worker_cause',cause);event='private_worker_cause';break
            if 'original_stage_reconciliation_required' in original['missing_inputs']:
                event='actual_original_hold';break
            if original['state']=='completed':
                head=console('inspect',credentials)['lifecycle_head']
                preserve('actual_lifecycle_head',head)
                if head['state']!='paused':raise RuntimeError('completed_original_without_formal_paused_head')
                event='formal_owner_pause';break
            time.sleep(.05)
        if event is None:event='observation_timeout'
    with log_path.open('rb') as stream:os.fsync(stream.fileno())
    counter_path=Path('/var/lib/sylanne-b04-host/data/model-network-observation.json')
    counter_observation={'stage':'first_lifecycle_event_before_fixture_cleanup',
        'observed_utc':time.time(),'source_path':str(counter_path),
        'state':'observed' if counter_path.is_file() else 'UNKNOWN','requests':None}
    if counter_path.is_file():
        encoded=counter_path.read_bytes()
        counter_observation.update(requests=json.loads(encoded)['requests'],
            source_sha256=hashlib.sha256(encoded).hexdigest(),source_mtime_epoch=counter_path.stat().st_mtime)
    result={'schema':'sylanne.b04.first-lifecycle-cause-diagnostic.v1',
        'status':'DIAGNOSTIC_NOT_B04_PASS','event':event,'operation_id':operation,
        'pause_started_utc':started[0],'pause_finished_utc':time.time(),
        'pause_elapsed_seconds':time.monotonic()-started[1],
        'pause_observation_ceiling_seconds':120,'actual_observation_deadline_monotonic':deadline,
        'actual_original_state':original['state'] if original is not None else None,
        'actual_missing_inputs':original['missing_inputs'] if original is not None else None,
        'actual_original_sha256':canonical_digest(original) if original is not None else None,
        'actual_formal_lifecycle_head':head,'actual_private_safe_cause':cause,
        'private_original_path':str(private),'private_source_log_path':str(log_path),
        'snapshot_sha256':packet['package_sha256'],'manifest_sha256':packet['manifest_sha256'],
        'budget_valid_until_utc':packet['request']['budget_valid_until_utc'],
        'budget_deadline_remaining_seconds':packet['request']['budget_valid_until_utc']-time.time(),
        'model_calls':counter_observation['requests'],'model_counter_observation':counter_observation,
        'sender_calls':0,'pause_submission_count':1,
        'scope':'first actual lifecycle worker cause only; no phase2/management/resume/reload/B04 qualification'}
    note('first_lifecycle_worker_diagnostic_result',event=event,operation_id=operation)
    target=evidence/'first-lifecycle-cause-diagnostic.json'
    target.write_text(json.dumps(result,indent=2))
    with target.open('rb') as stream:os.fsync(stream.fileno())
    if event=='observation_timeout':raise TimeoutError('bounded_first_lifecycle_cause_observation')
    return result

def real_elapsed_phase(csrf,*,lifecycle_epoch):
    from sdk_m1_fixture_contract_v1 import REAL_ELAPSED_EPISODES,REAL_ELAPSED_PHASES,write_real_elapsed_phase_originals_v1
    from sylanne3.runtime_contracts import canonical_digest
    index=packet['real_elapsed_phase_index'];phase=REAL_ELAPSED_PHASES[index]
    meter=rpc('real_elapsed_meter')
    if meter['provider_network_requests'] or meter['max_total_calls']!=18:raise RuntimeError('crossday actual fixture meter binding differs')
    if any(c.get('state')!='returned' for c in meter['calls']):raise RuntimeError('crossday prior model outcome unknown; no new input')
    if index in (1,2):
        prior_meter=rpc('real_elapsed_meter')
        prior=rpc('real_elapsed_originals',phase_index=0 if index==1 else 1)
        prior_phase='day0' if index==1 else 'day4'
        saved_prior=json.loads((Path(packet['real_elapsed_directory'])/(prior_phase+'-originals.json')).read_text())
        if prior is None or prior['work_originals']!=saved_prior['originals']['work_originals']:
            raise RuntimeError('crossday actual old effect readback differs before new input')
        if rpc('real_elapsed_meter')['calls']!=prior_meter['calls']:raise RuntimeError('crossday readonly old effect probe dispatched a model')
    if index==2:
        old=rpc('real_elapsed_originals',phase_index=1)
        previous=json.loads((Path(packet['real_elapsed_directory'])/'day4-originals.json').read_text())
        if old is None or old['work_originals']!=previous['originals']['work_originals']:
            raise RuntimeError('day5 same-effect actual file readback differs')
        before_replay=rpc('real_elapsed_meter')
        replay=rpc('real_elapsed_originals',phase_index=1)
        if replay!=old or rpc('real_elapsed_meter')['calls']!=before_replay['calls']:
            raise RuntimeError('day5 readback replay changed effect or billed again')
    if index and (saved_prior['initial_root_grant_digest'],saved_prior['initial_root_lease_digest'])!=(canonical_digest(policy.root_grant),canonical_digest(policy.root_lease)):
        raise RuntimeError('crossday changed its initially signed Root/grant')
    minimum_new_calls=5 if index in (0,2) else 6
    if len(meter['calls'])+minimum_new_calls>18:raise RuntimeError('crossday original cumulative eighteen-call budget insufficient')
    episode=REAL_ELAPSED_EPISODES[index]
    sdk_event=rpc('ordinary_ingress',message_id=episode['message_id'],text=episode['task_text'])
    def completed():
        original=rpc('real_elapsed_originals',phase_index=index)
        if original is None:return None
        current=rpc('real_elapsed_meter');calls=[c for c in current['calls'] if c['episode_message_id']==episode['message_id']]
        phases={c['phase'] for c in calls};required={'encode','appraisal','natural_generation','natural_review'}
        required.add('recall_routing' if index==2 else 'artifact_draft')
        if index==1:required.add('recall_routing')
        if not required<=phases:return None
        if len(current['calls'])>18 or len(calls)>6 or current['provider_network_requests']:
            raise RuntimeError('crossday actual cumulative provider cap differs')
        if current['current_process_sender_calls']<episode['semantic_segment_count']:return None
        if current['current_process_sender_calls']!=episode['semantic_segment_count']:raise RuntimeError('crossday duplicate actual sender effect')
        return original,current
    original,current=until(completed,timeout=120)
    learned=original['day5_ordinary']['learned_at'] if index==2 else original['source_learned_at']
    if index:
        previous=json.loads((Path(packet['real_elapsed_directory'])/(REAL_ELAPSED_PHASES[index-1]+'-originals.json')).read_text())
        minimum=96*3600 if index==1 else 24*3600
        if learned-previous['source_learned_at']<minimum:raise RuntimeError('actual new Source learned time has not reached real elapsed boundary')
        if index==1 and original['task_scope'].get('continuation_authorization') is None:
            raise RuntimeError('day4 continued task lacks actual fresh same-W01 authorization')
        if index==1 and (original['objective']!=previous['originals']['objective'] or original['work_originals'][0]!=previous['originals']['work_originals'][0]):
            raise RuntimeError('crossday continuation replaced original objective or first effect')
    rpc_before_pause=rpc('health')
    credentials=console_login(audience='owner');pause,epoch=lifecycle_pause(credentials,csrf,lifecycle_epoch)
    seed=Path('/opt/sylanne-b04-fixture/controller-seed.json');body=json.loads(seed.read_text())
    body.update(first_health=rpc_before_pause,pause_operation_id=pause,pause_epoch=epoch,first_stages=stages)
    seed.write_text(json.dumps(body));seed.chmod(0o600)
    (evidence/'phase-one-complete.json').write_text(json.dumps({'status':'formal_host_paused_for_fixture_maintenance',
        'pause_operation_id':pause,'lifecycle_epoch':epoch,'stages':stages}))
    value={'status':'PHASE_COMPLETE','package_sha256':packet['package_sha256'],'manifest_sha256':packet['manifest_sha256'],
        'approved_request_digest':packet['real_elapsed_approved_request_digest'],'installation_id':policy.installation_id,
        'namespace':{'bot_id':namespace.bot_id,'persona_id':namespace.persona_id},'source_learned_at':learned,
        'initial_root_grant_digest':canonical_digest(policy.root_grant),'initial_root_lease_digest':canonical_digest(policy.root_lease),
        'sdk_event':sdk_event,'originals':original,'meter':current,'pause_operation_id':pause,'pause_epoch':epoch,
        'day5_restart_readback_verified':index==2,'day5_new_input_continuity':'VERIFIED' if index==2 else 'NOT_RUN',
        'overall_a06':'PASS' if index==2 else 'INCOMPLETE','observed_real_utc':time.time()}
    return write_real_elapsed_phase_originals_v1(packet['real_elapsed_directory'],phase,value)


def lifecycle_pause(credentials,csrf,epoch):
    started=(time.time(),time.monotonic())
    answer=command('configure_or_control',{'object_ref':'installation:'+policy.installation_id,'control':'pause',
        'test_intent':None,'config_diff':{'schema':'d12.installation_control.v1','scope':'whole_host',
        'expected_lifecycle_epoch':epoch,'prior_pause_operation_id':None}},csrf)
    operation=answer['receipt']['operation_id']
    if packet['host_settings'].get('diagnostic_mode')=='first-lifecycle-cause-only':
        return observe_first_lifecycle_cause(operation,credentials,started)
    def read():
        value=console('status',{**credentials,'operation_id':operation})['original']
        return value if value['state']=='completed' else None
    original=until(read)
    head=console('inspect',credentials)['lifecycle_head']
    if head['state']!='paused':raise RuntimeError('formal_host_not_paused')
    if Path('/run/sylanne-b04-host/fixture.sock').exists():raise RuntimeError('old_host_socket_not_retired')
    note('formal_host_paused',operation_id=operation,lifecycle_epoch=head['epoch'],
        original_sha256=canonical_digest(original),coverage=original['coverage'])
    return operation,head['epoch']
try:
    ready=Path('/var/lib/sylanne-b04-host/data/host-ready.json')
    if packet['phase']==0:
        stage='no_owner_actual_namespace_provision'
        wait_host()
        first=rpc('health')
        if (first['fixture_phase']!=0 or not first['runtime_started'] or not first['worker_started']
                or first['manifest_sha256']!=packet['manifest_sha256']):
            raise RuntimeError('actual_bootstrap_sdk_generation_differs')
        note('actual_installed_main_initialize_no_owner',**first)
        observe_native_sdk_route(2)
        digest=canonical_digest(policy.digest_payload());operation='namespace-provision:'+digest
        creation=rpc('provision_original',operation_id=operation)
        from sylanne3.graph_coordinator import NamespaceProvisionReceiptV2
        from sylanne3.authority_service.v2_contract import FencePermitV2,from_wire as fence_from_wire
        if (set(creation)!=set(NamespaceProvisionReceiptV2.__dataclass_fields__)
                or creation['namespace']!=asdict(namespace) or creation['operation_id']!=operation
                or creation['input_digest']!=digest or creation['installation_id']!=policy.installation_id
                or creation['manifest_digest']!=policy.manifest_digest
                or creation['authority_id']!=policy.expected_authority_id
                or creation['authority_namespace']!=policy.authority_namespace
                or creation['generation']!=1 or not creation['graph_incarnation']
                or creation['root_lease_id']!=policy.root_lease.lease_id
                or creation['root_grant_id']!=policy.root_grant.grant_id
                or creation['root_grant_version']!=policy.root_grant.version
                or not creation['fence_attempt_id'] or not creation['finish_request_id']
                or not creation['finish_request_digest']
                or type(fence_from_wire(creation['permit_wire'])) is not FencePermitV2):
            raise RuntimeError('actual_bootstrap_namespace_original_identity_differs')
        original=Path('/opt/sylanne-b04-fixture/bootstrap-provision-original.json')
        fd=os.open(original,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,'w') as stream:
            stream.write(json.dumps({'receipt':creation,'four_file_identities':packet['four_file_identities'],
                'first_health':first},separators=(',',':')));stream.flush();os.fsync(stream.fileno())
        note('actual_namespace_provision_completed_no_owner',operation_id=operation,
            receipt_sha256=canonical_digest(creation),fence_attempt_id=creation['fence_attempt_id'],
            finish_request_id=creation['finish_request_id'])
        marker=evidence/'phase-zero-complete.json'
        marker.write_text(json.dumps({'status':'actual_namespace_provision_completed_no_owner',
            'receipt_sha256':canonical_digest(creation),'private_original_sha256':hashlib.sha256(original.read_bytes()).hexdigest(),
            'four_file_identities':packet['four_file_identities'],'stages':stages}))
        with marker.open('rb') as stream:os.fsync(stream.fileno())
    elif packet['phase']==1:
        wait_host()
        if not ready.is_file():raise RuntimeError('actual_host_ready_original_missing')
        first=rpc('health')
        if (first['fixture_phase']!=1 or not first['runtime_started'] or not first['worker_started']
                or first['manifest_sha256']!=packet['manifest_sha256']
                or first['process_original']==packet['bootstrap_original']['first_health']['process_original']):
            raise RuntimeError('actual_runtime_did_not_start')
        note('actual_installed_main_initialize',**first)
        stage='registered_signed_owner'
        console('register-credential',{'registration':packet['registration']})
        credentials=console_login()
        stage='first_owner_reverse_original'
        digest=canonical_digest(policy.digest_payload());operation='namespace-provision:'+digest
        creation=rpc('provision_original',operation_id=operation)
        if creation['operation_id']!=operation or creation['input_digest']!=digest:
            raise RuntimeError('actual_namespace_provision_original_differs')
        if creation!=packet['bootstrap_original']['receipt']:
            raise RuntimeError('actual_namespace_original_changed_after_bootstrap')
        ticket=from_wire(packet['first_owner_ticket'])
        authorization=from_wire(packet['first_owner_operation'])
        grant=packet['first_owner_grant_value'];issue=authorization.operation_id
        if (type(ticket) is not OwnerClaimTicketV1 or type(authorization) is not OwnerAuthorizationOperationV1
                or authorization.ticket!=ticket or authorization.principal!=principal
                or ticket.principal!=principal or ticket.creation_operation_id!=operation
                or ticket.creation_digest!='sha256:'+digest
                or ticket.policy_digest!=owner_grant_policy_digest_v1(grant,bot=namespace.bot_id,persona=namespace.persona_id)
                or authorization.grant_digest!='sha256:'+canonical_digest(grant)):
            raise RuntimeError('offline_creation_pairing_originals_differ')
        result=console('first-owner-issue',{'ticket':to_wire(ticket),'operation':to_wire(authorization),'grant_value':grant,
            'owner_session_token':credentials['owner_session_token'],'owner_session_request':credentials['owner_session_request']})
        committed=from_wire(result['receipt'])
        if type(committed) is not OwnerAuthorizationReceiptV1 or committed.phase!='committed' or committed.operation!=authorization:
            raise RuntimeError('first_owner_reverse_not_formally_committed')
        originals=Path('/opt/sylanne-b04-fixture/first-owner-consumed-originals.json')
        originals.write_text(json.dumps({'creation':creation,'ticket':to_wire(ticket),
            'operation':to_wire(authorization),'receipt':result['receipt']}));originals.chmod(0o600)
        note('real_signed_first_owner_reverse_graph_authority_finalize',operation_id=issue,
            receipt_sha256=canonical_digest(result),creation_original_sha256=canonical_digest(creation),
            private_consumed_originals_sha256=hashlib.sha256(originals.read_bytes()).hexdigest())
        stage='signed_dashboard_owner_and_management'
        csrf=dashboard_owner_login()
        management=http('POST',base+'/management/v1/capabilities',
            {'schema_version':'sylanne.workbench-management.v1','operation_id':str(uuid4())},{'X-CSRF-Token':csrf})
        if management['capabilities']['settings']['available']:raise RuntimeError('management_grant_was_not_explicitly_offline')
        note('actual_signed_owner_without_management_grant',response_sha256=canonical_digest(management))
        stage='actual_existing_character_creation'
        preset=json.loads((root/'resources/catalogue/d01-onboarding-presets.json').read_text())['blueprints'][0]['blueprint_ref']
        created=command('create_character',{'display_name':'B04 isolated fixture','blueprint':preset,
            'model_capability_ref':model_capability_ref(packet['request']['provider_id'],packet['request']['model_id']),
            'budget_ref':policy.root_lease.lease_id},csrf)
        note('actual_owner_character_created',receipt_sha256=canonical_digest(created))
        if packet['host_settings'].get('scenario') in ('sdk_m1_two_messages_v1','sdk_m1_first_bubble_stop_v1','sdk_m1_first_bubble_unknown_v1','sdk_ordinary_old_source_v1','sdk_ordinary_greeting_v1','sdk_d13_v6_256_current_v1','sdk_d13_v7_256_current_v1','sdk_a06_real_elapsed_phases_v1'):
            sys.path.insert(0,'/opt/sylanne-b04-fixture')
            from sdk_m1_fixture_contract_v1 import owner_initialization_v1,actual_episode_originals_v1
            stage='M1_public_Owner_initialization'
            graph_path=Path('/var/lib/sylanne/genesis/graph/graph.sqlite3')
            initial=owner_initialization_v1(lambda action,values:command(action,values,csrf),
                profile=packet['profile'],package_root=root,graph_path=graph_path)
            (evidence/'m1-initial-owner-originals.json').write_text(json.dumps(initial))
            if packet['host_settings']['scenario']=='sdk_a06_real_elapsed_phases_v1':
                phase_receipt=real_elapsed_phase(csrf,lifecycle_epoch=0)
            elif packet['host_settings']['scenario'] in ('sdk_d13_v6_256_current_v1','sdk_d13_v7_256_current_v1'):
                episodes=[];source_refs=set();c02_ids=set();started256=time.monotonic()
                for number,episode in enumerate(packet['host_settings']['m1_model_fixture']['episodes'],1):
                    version='v7' if packet['host_settings']['scenario']=='sdk_d13_v7_256_current_v1' else 'v6'
                    stage='D13_'+version.upper()+'_actual_SDK_episode_'+str(number)
                    if time.monotonic()-started256>=300:raise TimeoutError('256_original_controller_window_insufficient_no_deadline_extension')
                    observed=rpc('ordinary_ingress',message_id=episode['message_id'],text=episode['task_text'])
                    def completed256():
                        original=rpc('d13_v6_episode_originals',message_id=episode['message_id'])
                        if original is None:return None
                        current=rpc('health');calls=[item for item in current['model_fixture_calls'] if item['episode_message_id']==episode['message_id']]
                        if not {'encode','appraisal','recall_routing','natural_generation','natural_review'}<={item['phase'] for item in calls}:return None
                        if len(calls)>6 or current['local_model_requests']>1536 or current['provider_network_requests']!=0:
                            raise RuntimeError('256_actual_finite_provider_limit_differs')
                        if current['sender_calls']<number:return None
                        if current['sender_calls']!=number:raise RuntimeError('256_actual_sender_duplicate')
                        collection=rpc('d13_v6_collection_originals',source_ref=original['source_ref'])
                        if collection is None:return None
                        return {'sdk_event':observed,'originals':original,'current_collection':collection}
                    record=until(completed256,timeout=min(120,max(.01,300-(time.monotonic()-started256))))
                    original=record['originals']
                    if original['source_ref'] in source_refs or original['c02_operation_id'] in c02_ids:
                        raise RuntimeError('256_actual_Source_or_C02_reused')
                    source_refs.add(original['source_ref']);c02_ids.add(original['c02_operation_id']);episodes.append(record)
                    (evidence/('d13-'+version+'-episode-'+str(number)+'-originals.json')).write_text(json.dumps(record))
                    note('D13_'+version.upper()+'_actual_episode_completed',number=number,c02_operation_id=original['c02_operation_id'])
                last=episodes[-1]['originals']['source_ref'];before=rpc('health')
                collection=rpc('d13_v6_collection_originals',source_ref=last)
                if collection['current_turn_count']!=256 or len(collection['pages'])!=4 or collection['order_watermark']!=511:
                    raise RuntimeError('256_actual_in_out_slot_window_differs')
                if not collection['paid_originals'] or not collection['metadata_originals']:
                    raise RuntimeError('256_actual_paid_D13_original_unavailable')
                replay=rpc('d13_v6_collection_originals',source_ref=last)
                if replay['paid_originals']!=collection['paid_originals'] or replay['metadata_originals']!=collection['metadata_originals']:
                    raise RuntimeError('256_readonly_original_replay_changed_paid_facts')
                cold=rpc('hot_reload')
                if not cold['new_plugin_instance'] or not cold['old_runtime_worker_closed']:
                    raise RuntimeError('256_actual_cold_Runtime_reopen_unproven')
                reopened=rpc('d13_v6_collection_originals',source_ref=last);after=rpc('health')
                if reopened['paid_originals']!=collection['paid_originals'] or reopened['current_turn_count']!=256:
                    raise RuntimeError('256_cold_current_originals_changed')
                if after['local_model_requests']!=before['local_model_requests'] or after['sender_calls']!=before['sender_calls']:
                    raise RuntimeError('256_cold_read_replay_dispatched_again')
                m1_result={'status':'PASS','scope':'actual256 SDK Source/C02/replies and '+version.upper()+' currenttail256/paid metadata/cold readonlyreplay; no real provider or guaranteed elapsed expiry',
                    'scenario':packet['host_settings']['scenario'],'snapshot_sha256':packet['package_sha256'],
                    'manifest_sha256':packet['manifest_sha256'],'episodes':episodes,'external_provider_requests':0,
                    'simulated_provider_calls':after['local_model_requests'],'simulated_sender_calls':after['sender_calls'],
                    'current_collection':collection,'cold_collection':reopened,'expiry_reclaim_verified':reopened['physical_expiry_reclaim_verified'],'stages':stages}
            elif packet['host_settings']['scenario']=='sdk_ordinary_greeting_v1':
                episodes=[]
                for number,episode in enumerate(packet['host_settings']['m1_model_fixture']['episodes'],1):
                    stage='greeting_actual_SDK_episode_'+str(number)
                    observed=rpc('ordinary_ingress',message_id=episode['message_id'],text=episode['task_text'])
                    def completed_greeting():
                        need=rpc('greeting_need_originals',message_id=episode['message_id'])
                        if need is None:return None
                        if need['status']!='actual_no_search':raise RuntimeError('greeting has actual mandatory facts; cannot claim no_search')
                        current=rpc('health');calls=[v for v in current['model_fixture_calls'] if v['episode_message_id']==episode['message_id']]
                        phases={v['phase'] for v in calls}
                        if any(phase in phases for phase in ('recall_routing','artifact_draft')) or len(calls)>6:
                            raise RuntimeError('plain greeting dispatched unnecessary recall/artifact model')
                        if current['provider_network_requests']!=0 or current['local_model_requests']>12 or current['sender_calls']>number:
                            raise RuntimeError('greeting actual original provider/sender ceiling differs')
                        if current['sender_calls']<number:return None
                        return {'sdk_event':observed,'originals':need,'counter':current}
                    record=until(completed_greeting,timeout=120);episodes.append(record)
                    (evidence/('greeting-episode-'+str(number)+'-originals.json')).write_text(json.dumps(record))
                m1_result={'status':'PASS','scope':'actual normal SDK greeting adopted no_search/zeroC3/zeroC04; no real or paid semantic qualification',
                    'scenario':packet['host_settings']['scenario'],'snapshot_sha256':packet['package_sha256'],
                    'manifest_sha256':packet['manifest_sha256'],'episodes':episodes,'external_provider_requests':0,
                    'simulated_provider_calls':episodes[-1]['counter']['local_model_requests'],
                    'simulated_sender_calls':episodes[-1]['counter']['sender_calls'],'stages':stages}
            elif packet['host_settings']['scenario']=='sdk_ordinary_old_source_v1':
                episodes=[];previous_source=None
                for number,episode in enumerate(packet['host_settings']['m1_model_fixture']['episodes'],1):
                    stage='ordinary_actual_SDK_episode_'+str(number)
                    observed=rpc('ordinary_ingress',message_id=episode['message_id'],text=episode['task_text'])
                    prior=previous_source
                    def completed_ordinary():
                        original=rpc('ordinary_recall_originals',message_id=episode['message_id'],previous_source_ref=prior)
                        if original is None:return None
                        current=rpc('health');calls=[v for v in current['model_fixture_calls'] if v['episode_message_id']==episode['message_id']]
                        phases={v['phase'] for v in calls}
                        if not {'encode','appraisal','recall_routing','natural_generation','natural_review'}<=phases:return None
                        if 'artifact_draft' in phases or len(calls)>6 or len({v['call_id'] for v in calls})!=len(calls):
                            raise RuntimeError('ordinary actual stage/call boundary differs')
                        if current['provider_network_requests']!=0 or current['local_model_requests']>12 or current['sender_calls']>number:
                            raise RuntimeError('ordinary provider/sender original ceiling differs')
                        if current['sender_calls']<number:return None
                        return {'sdk_event':observed,'originals':original,'counter':current}
                    record=until(completed_ordinary,timeout=120)
                    if number==2 and (record['originals']['c04'] is None or record['originals']['c04']['selected_source_ref']!=previous_source):
                        raise RuntimeError('ordinary second message failed actual oldSource adoption')
                    previous_source=record['originals']['source_ref'];episodes.append(record)
                    (evidence/('ordinary-episode-'+str(number)+'-originals.json')).write_text(json.dumps(record))
                    note('ordinary_SDK_original_episode_completed',number=number,c02_operation_id=record['originals']['c02_operation_id'])
                m1_result={'status':'PASS','scope':'actual isolated normal SDK C1/C3/C03/SelfC04 and same reply root; no72/96h elapsed claim',
                    'scenario':packet['host_settings']['scenario'],'snapshot_sha256':packet['package_sha256'],
                    'manifest_sha256':packet['manifest_sha256'],'episodes':episodes,'external_provider_requests':0,
                    'simulated_provider_calls':episodes[-1]['counter']['local_model_requests'],
                    'simulated_sender_calls':episodes[-1]['counter']['sender_calls'],'stages':stages}
            else:
                episodes=[]
                for number,episode in enumerate(packet['host_settings']['m1_model_fixture']['episodes'],1):
                    stage='M1_actual_SDK_episode_'+str(number)
                    interruption=({'sdk_m1_first_bubble_stop_v1':'stop','sdk_m1_first_bubble_unknown_v1':'unknown'}.get(packet['host_settings']['scenario']) if number==2 else None)
                    stop_original=None
                    if interruption=='stop':
                        from concurrent.futures import ThreadPoolExecutor
                        with ThreadPoolExecutor(max_workers=1) as concurrent_ingress:
                            submitted=concurrent_ingress.submit(rpc,'ordinary_ingress',message_id=episode['message_id'],text=episode['task_text'])
                            until(lambda:rpc('health')['natural_boundary_received'],timeout=30)
                            try:
                                page=command('read_reply_controls',{},csrf)
                                targets=[row for row in page['items'] if row['natural_batch'] is not None and len(row['natural_batch']['children'])==2]
                                if len(targets)!=1:raise RuntimeError('actual current two-bubble Stop target is not reachable')
                                target=targets[0];operation=str(uuid4())
                                request={'schema':'d12.owner-stop-reply-request.v1','namespace':target['namespace'],
                                    'installation_id':target['installation_id'],'operation_id':operation,
                                    'cycle_job_ref':target['cycle_job_ref'],'c02_operation_id':target['c02_operation_id'],
                                    'expected_cancel_generation':target['cancel_generation']}
                                stop_original=http('POST',base+'/commands',{'schema_version':'d12.contract.v1','action':'stop_reply',
                                    'scope':namespace.bot_id+'/'+namespace.persona_id,'purpose':'workbench_user_action','audience':'owner',
                                    'operation_id':operation,'input':request},{'X-CSRF-Token':csrf})['control']
                            finally:rpc('release_natural_boundary')
                            observed=submitted.result(timeout=30)
                    else:
                        observed=rpc('ordinary_ingress',message_id=episode['message_id'],text=episode['task_text'])
                    if observed['namespace']!={'bot_id':namespace.bot_id,'persona_id':namespace.persona_id}:raise RuntimeError('M1 SDK namespace differs')
                    def completed_episode():
                        original=actual_episode_originals_v1(graph_path=graph_path,namespace=namespace,episode=episode,
                            expected_phase='partial' if number==1 else 'satisfied',expected_version=number,interruption=interruption)
                        if original is None:return None
                        current=rpc('health')
                        expected_sends=sum(item['semantic_segment_count']
                            for item in packet['host_settings']['m1_model_fixture']['episodes'][:number])-(1 if interruption else 0)
                        if current['provider_network_requests']!=0 or current['local_model_requests']>6*number or current['sender_calls']>expected_sends:
                            raise RuntimeError('M1 actual provider/sender boundary differs')
                        if current['sender_calls']<expected_sends:return None
                        calls=[v for v in current['model_fixture_calls'] if v['episode_message_id']==episode['message_id']]
                        phases={v['phase'] for v in calls}
                        if not {'encode','appraisal','artifact_draft','natural_generation','natural_review'}<=phases:
                            raise RuntimeError('M1 mandatory actual model phases not all reached')
                        if len(calls)>6 or len({v['call_id'] for v in calls})!=len(calls):raise RuntimeError('M1 actual model call identity/ceiling differs')
                        batch=None;core=None
                        if interruption:
                            page=command('read_reply_controls',{},csrf)
                            selected=[row for row in page['items'] if row['c02_operation_id']==original['c02_operation_id']]
                            if len(selected)!=1:raise RuntimeError('actual interrupted Owner parent is not reachable')
                            batch=selected[0]['natural_batch']
                            if batch is None or batch['details_state']!='adopted' or len(batch['children'])!=2:return None
                            first,remaining=batch['children']
                            if first['actual_intent_ref'] is None or first['admission_ref'] is None:return None
                            if first['authority_state']!='observed':return None
                            if interruption=='unknown' and first['observation_outcome']!='unknown':return None
                            if interruption=='stop' and first['observation_outcome'] not in {'accepted','unknown'}:return None
                            if first['read_state']!='unknown' or remaining['read_state']!='unknown':raise RuntimeError('acceptance was misrepresented as peer read')
                            if remaining['actual_intent_ref'] is not None or remaining['admission_ref'] is not None:raise RuntimeError('interrupted remaining child was adopted')
                            expected=('held','predecessor_unknown') if interruption=='unknown' else ('cancelled','owner_stop')
                            if (remaining['continuation_state'],remaining['reason_code'])!=expected:return None
                            if remaining['authority_state']!='absent':raise RuntimeError('remaining child has an actual unresolved or observed effect')
                            fees=[*batch['parent_fees'],*(fee for child in batch['children'] for fee in child['fees'])]
                            if len({fee['settlement_ref'] for fee in fees})!=len(fees):raise RuntimeError('parent model cost counted per bubble')
                            if len(batch['parent_fees'])!=2:return None
                            if any(fee['status']!='settled' for fee in batch['parent_fees']):return None
                            core=rpc('natural_core_originals',parent_original_id=original['c02_operation_id'])
                            if core is None or len(core['original_pairs'])!=2:return None
                            if {row['prepared_kind'] for row in core['original_pairs']}!={'roster_prepared','maintenance_prepared'}:raise RuntimeError('actual birth/current Core commitments are missing')
                        return {'sdk_event':observed,'originals':original,'counter':current,
                            'interruption':interruption,'owner_bubbles':batch,'core_originals':core,'stop_original':stop_original}
                    record=until(completed_episode,timeout=120)
                    episodes.append(record);(evidence/('m1-episode-'+str(number)+'-originals.json')).write_text(json.dumps(record))
                    note('M1_actual_original_episode_completed',number=number,c02_operation_id=record['originals']['c02_operation_id'],
                        goal_state=record['originals']['goal']['state'],work_count=len(record['originals']['work_originals']))
                m1_result={'status':'PASS','scope':'actual isolated SDK M1 named natural boundary; not full B04/D04/Contact/production Host',
                    'scenario':packet['host_settings']['scenario'],
                    'snapshot_sha256':packet['package_sha256'],'manifest_sha256':packet['manifest_sha256'],'episodes':episodes,
                    'external_provider_requests':0,'simulated_provider_calls':episodes[-1]['counter']['local_model_requests'],
                    'simulated_sender_calls':episodes[-1]['counter']['sender_calls'],'stages':stages}
        if packet['host_settings']['scenario']=='sdk_a06_real_elapsed_phases_v1':
            pass
        elif packet['host_settings'].get('diagnostic_mode')=='first-lifecycle-cause-only':
            stage='first_lifecycle_worker_cause_only'
            lifecycle_credentials=console_login(audience='owner')
            lifecycle_pause(lifecycle_credentials,csrf,0)
        else:
            stage='d05_read_and_support_export'
            relation=command('read_character_view',{'view_type':'relations'},csrf,'workbench_view')
            support=command('diagnose_and_export_support',{'question':'view_health','allowed_data':['view_status'],
                'retention_policy_ref':'d12.local_manual_retention.v1','local_destination':'managed'},csrf,'workbench_view')
            receipt=support['receipt'];export=Path(receipt['local_path'])
            if receipt['phase']!='local_support_export_recorded' or not export.is_file():raise RuntimeError('support_export_not_written')
            note('actual_d05_read_and_support_export',relation_sha256=canonical_digest(relation),
                export_sha256=hashlib.sha256(export.read_bytes()).hexdigest(),operation_id=receipt['operation_id'])
            stage='durable_host_quiesce_before_offline_grant'
            lifecycle_credentials=console_login(audience='owner')
            pause,epoch=lifecycle_pause(lifecycle_credentials,csrf,0)
            seed=Path('/opt/sylanne-b04-fixture/controller-seed.json')
            body=json.loads(seed.read_text());body.update(first_health=first,pause_operation_id=pause,pause_epoch=epoch,first_stages=stages)
            seed.write_text(json.dumps(body));seed.chmod(0o600)
            (evidence/'phase-one-complete.json').write_text(json.dumps({'status':'formal_host_paused_for_fixture_maintenance',
                'pause_operation_id':pause,'lifecycle_epoch':epoch,'stages':stages}))
            if packet['host_settings'].get('scenario') in ('sdk_m1_two_messages_v1','sdk_m1_first_bubble_stop_v1','sdk_m1_first_bubble_unknown_v1','sdk_ordinary_old_source_v1','sdk_ordinary_greeting_v1','sdk_d13_v6_256_current_v1','sdk_d13_v7_256_current_v1','sdk_a06_real_elapsed_phases_v1'):
                (evidence/'m1-receipt.json').write_text(json.dumps(m1_result))
    elif packet['phase']==2:
        stage='cold_authority_fresh_signed_owner_resume'
        cold_authority_protocol_ready()
        credentials=console_login(audience='owner')
        first=packet['first_health'];pause=packet['pause_operation_id'];epoch=packet['pause_epoch'];stages=packet['first_stages']
        resume=str(uuid4())
        console('resume',{**credentials,'pause_operation_id':pause,'operation_id':resume,'expected_lifecycle_epoch':epoch})
        wait_host()
        second=rpc('health')
        failed_predicates={'fixture_phase_not_two':second['fixture_phase']!=2,
            'same_process_original':second['process_original']==first['process_original'],
            'worker_not_started':not second['worker_started']}
        health_observation={'schema':'sylanne.b04.resume-health-predicate-observation.v1',
            'observed_time_ns':time.time_ns(),'actual_health':second,'failed_predicates':failed_predicates,
            'first_process_original':first['process_original'],'second_process_original':second['process_original'],
            'first_birth':first['process_original']['birth'],'second_birth':second['process_original']['birth']}
        health_path=evidence/'phase-two-resume-health-before-assertion.json'
        health_path.write_text(json.dumps(health_observation))
        with health_path.open('rb') as stream:os.fsync(stream.fileno())
        cold_assembly_diagnostic=packet['host_settings']['diagnostic_mode']=='cold-assembly-cause-only'
        if cold_assembly_diagnostic:
            diagnostic_path=evidence/'cold-assembly-cause-diagnostic.json'
            diagnostic_path.write_text(json.dumps({'schema':'sylanne.b04.cold-assembly-cause-diagnostic.v1',
                'status':'DIAGNOSTIC_NOT_B04_PASS','actual_health_observation':health_observation,
                'actual_resume_operation_id':resume,'snapshot_sha256':packet['package_sha256'],
                'manifest_sha256':packet['manifest_sha256'],'failed_predicate_observed':any(failed_predicates.values()),
                'scope':'first actual cold Host assembly observation; no phase2 management/reload or full B04 acceptance'}))
            with diagnostic_path.open('rb') as stream:os.fsync(stream.fileno())
        if (second['fixture_phase']!=2 or second['process_original']==first['process_original']
                or not second['worker_started']):
            raise RuntimeError('formal_resume_not_new_host')
        if packet['host_settings']['scenario']=='sdk_a06_real_elapsed_phases_v1':
            until(lambda:console('inspect',credentials)['lifecycle_head']['state']=='active')
            phase_receipt=real_elapsed_phase(dashboard_owner_login(),lifecycle_epoch=epoch+1)
        elif not cold_assembly_diagnostic:
            until(lambda:console('inspect',credentials)['lifecycle_head']['state']=='active')
            note('formal_resumed_new_actual_host',**second)
            observe_native_sdk_route(200)
            csrf=dashboard_owner_login()
            management=http('POST',base+'/management/v1/capabilities',
                {'schema_version':'sylanne.workbench-management.v1','operation_id':str(uuid4())},{'X-CSRF-Token':csrf})
            if not management['capabilities']['settings']['available']:raise RuntimeError('finite_management_grant_unavailable')
            settings=http('POST',base+'/management/v1/settings/read',
                {'schema_version':'sylanne.workbench-management.v1','operation_id':str(uuid4()),
                 'installation_id':policy.installation_id,'access_generation':management['access_generation']},{'X-CSRF-Token':csrf})
            note('finite_management_grant_real_settings_read',settings_sha256=canonical_digest(settings))
            updated=http('POST',base+'/management/v1/settings/update',
                {'schema_version':'sylanne.workbench-management.v1','operation_id':str(uuid4()),
                 'installation_id':policy.installation_id,'access_generation':management['access_generation'],
                 'expected_revision':settings['revision'],'patch':{'enabled':True}},{'X-CSRF-Token':csrf})
            if updated['applied']!='next_restart':raise RuntimeError('management_apply_semantics_changed')
            saved_settings=http('POST',base+'/management/v1/settings/read',
                {'schema_version':'sylanne.workbench-management.v1','operation_id':str(uuid4()),
                 'installation_id':policy.installation_id,'access_generation':management['access_generation']},{'X-CSRF-Token':csrf})
            if saved_settings['revision']!=updated['revision'] or saved_settings['values']['enabled'] is not True:
                raise RuntimeError('management_cas_write_not_read_back')
            note('finite_management_real_cas_write_and_readback',revision=updated['revision'])
            configuration=http('GET',base+'/configuration/v1')
            for enabled in (False,True):
                saved=http('POST',base+'/configuration/v1',{'schema_version':'sylanne.webui-configuration.v1',
                    'operation_id':str(uuid4()),'expected_revision':configuration['revision'],'patch':{'enabled':enabled}},
                    {'X-Sylanne-Configuration-CSRF':configuration['csrf_token']})
                configuration=http('GET',base+'/configuration/v1')
                if configuration['values']['enabled']!=enabled or configuration['startup_values']['enabled'] is not True:
                    raise RuntimeError('actual_sdk_config_save_or_next_reload_mismatch')
            note('actual_sdk_configuration_cas_saved_and_readback',revision=configuration['revision'])
            stage='same_generation_actual_sdk_hot_reload'
            reloaded=rpc('hot_reload')
            if not reloaded['new_plugin_instance'] or not reloaded['old_runtime_worker_closed'] or not reloaded['worker_started']:
                raise RuntimeError('actual_sdk_hot_reload_not_drained')
            note('plugin_hot_reload_old_worker_drained_new_runtime_started',**reloaded)
            observe_native_sdk_route(201)
            if any(value.get('provider_network_requests',0) for value in (first,second,reloaded)):
                raise RuntimeError('unexpected_model_network_request')
            csrf=dashboard_owner_login()
            configuration=http('GET',base+'/configuration/v1')
            if configuration['startup_values']['enabled'] is not True:
                raise RuntimeError('saved_host_config_not_read_at_actual_reload')
            current_management=http('POST',base+'/management/v1/capabilities',
                {'schema_version':'sylanne.workbench-management.v1','operation_id':str(uuid4())},{'X-CSRF-Token':csrf})
            restarted_settings=http('POST',base+'/management/v1/settings/read',
                {'schema_version':'sylanne.workbench-management.v1','operation_id':str(uuid4()),
                 'installation_id':policy.installation_id,'access_generation':current_management['access_generation']},
                {'X-CSRF-Token':csrf})
            if restarted_settings['revision']!=updated['revision'] or restarted_settings['values']['enabled'] is not True:
                raise RuntimeError('management_saved_source_not_read_after_reload')
            note('actual_reload_preserves_management_saved_source',revision=restarted_settings['revision'])
            again=command('read_character_view',{'view_type':'relations'},csrf,'workbench_view')
            note('d05_read_after_actual_restart_and_hot_reload',response_sha256=canonical_digest(again))
            stage='formal_fixture_final_drain'
            lifecycle_pause(credentials,csrf,2)
            observed=json.loads(Path('/var/lib/sylanne-b04-host/data/model-network-observation.json').read_text())
            if observed['requests']!=0:raise RuntimeError('unexpected_model_request_before_drain')
            if packet['host_settings'].get('sdk_ingress') is not None:
                assert observed['local_model_requests']==observed['sender_calls']==0
            result={'status':'PASS','snapshot_sha256':packet['package_sha256'],'manifest_sha256':packet['manifest_sha256'],
                'sdk':'4.28.2','stages':stages,'model_calls':0,'sender_calls':0,
                'native_sdk_identity_and_handler_route':packet['host_settings'].get('sdk_ingress') is not None,
                'scope':'installed/health/management/D05 read/quit-restart/plugin reload only; no new D05 relationship or Q02/C04/Numeric/natural/browser qualification'}
            (evidence/'receipt.json').write_text(json.dumps(result,indent=2))
except BaseException as error:
    sys.stderr.write('B04_CONTROLLER_FIRST_EXCEPTION\n'+''.join(traceback.format_exception(error)))
    sys.stderr.flush();os.fsync(sys.stderr.fileno())
    frames=[{'file':f.filename,'line':f.lineno,'function':f.name} for f in traceback.extract_tb(error.__traceback__)]
    original=Path('/var/lib/sylanne-b04-host/data/host-first-failure.json')
    (evidence/'first-failure.json').write_text(json.dumps({'stage':stage,'type':type(error).__name__,'frames':frames,
        'host_failure':json.loads(original.read_text()) if original.is_file() else None,'stages':stages}))
finally:
    Path(sys.argv[1]).unlink(missing_ok=True)
    # Only the outer holder of the real service pidfd retires that namespace.
'''


def _run_actual_installed_sdk_fixture_v1(tmp_path,*,scenario="b04",real_elapsed_directory=None,real_elapsed_phase=None):
    """One serial fresh fixture, entered only with externally pinned new input."""
    required = ('SYLANNE_B04_PACKAGE', 'SYLANNE_B04_PACKAGE_SHA256',
                'SYLANNE_B04_MANIFEST_SHA256', 'SYLANNE_B04_DEPENDENCY_MANIFEST',
                'SYLANNE_B04_APPROVED_INSTALL_REQUEST')
    if scenario not in {'b04',*('sdk_m1_two_messages_v1','sdk_m1_first_bubble_stop_v1','sdk_m1_first_bubble_unknown_v1','sdk_ordinary_old_source_v1','sdk_ordinary_greeting_v1','sdk_d13_v6_256_current_v1','sdk_d13_v7_256_current_v1','sdk_a06_real_elapsed_phases_v1')}:raise ValueError('unknown permanent SDK fixture scenario')
    if scenario in ('sdk_m1_two_messages_v1','sdk_m1_first_bubble_stop_v1','sdk_m1_first_bubble_unknown_v1','sdk_ordinary_old_source_v1','sdk_ordinary_greeting_v1','sdk_d13_v6_256_current_v1','sdk_d13_v7_256_current_v1','sdk_a06_real_elapsed_phases_v1'):required=tuple(name.replace('SYLANNE_B04_','SYLANNE_SDK_M1_') for name in required)
    diagnostic_mode=os.environ.get('SYLANNE_B04_DIAGNOSTIC_MODE') if scenario=='b04' else None
    diagnostic=diagnostic_mode in {'first-v2-fence-only', 'first-selection-probe-only'}
    probe_diagnostic=diagnostic_mode=='first-selection-probe-only'
    lifecycle_diagnostic=diagnostic_mode=='first-lifecycle-cause-only'
    cold_assembly_diagnostic=diagnostic_mode=='cold-assembly-cause-only'
    outer_started = time.monotonic()
    outer_deadline=outer_started+(270 if probe_diagnostic else 120 if diagnostic else 270) if (diagnostic or lifecycle_diagnostic) else None
    if not all(os.environ.get(name) for name in required):
        pytest.skip('requires frozen B04 package/external pins/approved runtime and request')
    package = Path(os.environ[required[0]]).resolve(strict=True)
    package_pin, manifest_pin = os.environ[required[1]], os.environ[required[2]]
    assert hashlib.sha256(package.read_bytes()).hexdigest() == package_pin
    with zipfile.ZipFile(package) as archive:
        assert archive.testzip() is None
        raw = archive.read('release-manifest.json')
        assert hashlib.sha256(raw).hexdigest() == manifest_pin
        manifest = json.loads(raw)
        for item in manifest['files']:
            body = archive.read(item['path'])
            assert len(body) == item['bytes']
            assert hashlib.sha256(body).hexdigest() == item['sha256']
        for member in archive.infolist():
            assert not Path(member.filename).is_absolute() and '..' not in Path(member.filename).parts
    dependency_path = Path(os.environ[required[3]]).resolve(strict=True)
    dependency = json.loads(dependency_path.read_text())
    assert dependency['sdk_version'] == '4.28.2' and dependency['python_version'] == '3.12.3'
    approved = json.loads(Path(os.environ[required[4]]).read_text())
    if scenario=='sdk_d13_v7_256_current_v1':
        from .sdk_d13_v7_256_root_fixture_v1 import approved_sdk_d13_v7_256_initial_request_v1
        expected=approved_sdk_d13_v7_256_initial_request_v1(executable_sha256=dependency['executable_sha256'],
            valid_until_utc=approved['budget_valid_until_utc'])
        assert approved==expected,'V7 requires independently approved fresh Root factory; no old grant rewrite'
    if scenario=='sdk_d13_v6_256_current_v1':
        from .sdk_d13_v6_256_root_fixture_v1 import approved_sdk_d13_v6_256_initial_request_v1
        expected=approved_sdk_d13_v6_256_initial_request_v1(executable_sha256=dependency['executable_sha256'],
            valid_until_utc=approved['budget_valid_until_utc'])
        assert approved==expected,'256 requires its freshly approved exact initial factory; no old grant replacement'
    native_sdk=approved['schema']=='sylanne3.linux-install-request.v4'
    if scenario in ('sdk_m1_two_messages_v1','sdk_m1_first_bubble_stop_v1','sdk_m1_first_bubble_unknown_v1','sdk_ordinary_old_source_v1','sdk_ordinary_greeting_v1','sdk_d13_v6_256_current_v1','sdk_d13_v7_256_current_v1','sdk_a06_real_elapsed_phases_v1'):assert native_sdk
    request = (public_install_request_v4(executable='/opt/sylanne-runtime/bin/python3.12',
        executable_sha256=dependency['executable_sha256'],approved_request=approved) if native_sdk else
        public_install_request_v3(executable='/opt/sylanne-runtime/bin/python3.12',
            executable_sha256=dependency['executable_sha256'],valid_until_utc=int(time.time())+3600,
            approved_request_v2=approved))
    assert request['model_quote']['output_tokens'] <= 8000
    if scenario not in ('sdk_d13_v6_256_current_v1','sdk_d13_v7_256_current_v1'):assert request['budget_limits']['output_tokens'] <= 8000
    for name in ('d13_precompression','d13_paid_precompression','d07_cognition'):
        assert request[name] is None
    real_elapsed=scenario=='sdk_a06_real_elapsed_phases_v1'
    if real_elapsed:
        from .sdk_m1_fixture_contract_v1 import REAL_ELAPSED_PHASES,real_elapsed_phase_gate_v1
        from sylanne3.runtime_contracts import canonical_digest
        phase_root=Path(real_elapsed_directory).resolve();phase_root.mkdir(mode=0o700,exist_ok=True)
        approval=json.loads(Path(os.environ['SYLANNE_SDK_M1_REAL_ELAPSED_APPROVAL']).read_text())
        request_digest=canonical_digest(approved)
        if approval!={'schema':'sylanne.sdk-real-elapsed-initial-approval.v1','approved_request_digest':request_digest,
            'package_sha256':package_pin,'manifest_sha256':manifest_pin,'max_total_calls':18,'max_episode_calls':6,'max_auxiliary_calls':2}:
            raise ValueError('real elapsed requires explicit fresh eighteen-call approval for this exact original Root/package')
        gate=real_elapsed_phase_gate_v1(phase_root,phase=real_elapsed_phase,package_sha256=package_pin,
            manifest_sha256=manifest_pin,approved_request_digest=request_digest,valid_until_utc=request['budget_valid_until_utc'])
        if gate['status']=='ALREADY_RECORDED':return gate['original']
        if gate['status']!='READY':return gate
        phase_index=gate['phase_index'];tmp_path=phase_root/real_elapsed_phase;tmp_path.mkdir(mode=0o700)
    evidence = tmp_path/('b04-installed-lifecycle' if scenario=='b04' else scenario);evidence.mkdir()
    compile(SDK_HOST_ENTRY_V1,'b04-sdk-host-entry.py','exec')
    compile(NAMESPACE_PREP_V1,'b04-namespace-controller.py','exec')
    compile(CONTROLLER_V1,'b04-private-owner-controller.py','exec')
    import secrets
    password='B04fixture9!'+secrets.token_hex(16)
    provider={'id':request['provider_id'],'type':'openai_chat_completion','model':request['model_id'],
        'key':['B04 isolated local-only canary; never a real provider key'],
        'api_base':'http://127.0.0.1:19661/v1','enable':True}
    persistent=(phase_root/'b04-durable-fixture' if real_elapsed else tmp_path/'b04-durable-fixture')
    if not real_elapsed or phase_index==0:persistent.mkdir(mode=0o700)
    packet={'package':str(package),'package_sha256':package_pin,'manifest_sha256':manifest_pin,
        'dependency_manifest':str(dependency_path),'evidence':str(evidence),
        'persistent_tree':str(persistent),'phase':0,
        'host_entry':SDK_HOST_ENTRY_V1,'controller':CONTROLLER_V1,'request':request,'provider':provider,
        'host_settings':{'dashboard_username':'b04-local-fixture','dashboard_password':password,
            'diagnostic_mode':diagnostic_mode,'scenario':scenario,
            'origin':request['workbench_origin'],'provider_config_path':request['provider_config_path'],
            'plugin_configuration':{'enabled':True,'authority_profile':'b04','llm_provider_id':request['provider_id'],
                'webui':{'enabled':False,'bind':'127.0.0.1','port':19618}}}}
    if real_elapsed:
        packet.update(real_elapsed_phase_index=phase_index,real_elapsed_directory=str(phase_root),real_elapsed_approved_request_digest=request_digest)
    if native_sdk:
        selected=request.get('astrbot_namespace_v1')
        platform_id=selected['platform_id'] if selected else request['onebot_account'][0]
        self_id=selected['self_id'] if selected else request['onebot_account'][2]
        persona_id=selected['selected_persona_id'] if selected else 'sdk-d13-v7-256-persona' if scenario=='sdk_d13_v7_256_current_v1' else 'sdk-d13-v6-256-persona' if scenario=='sdk_d13_v6_256_current_v1' else 'b04-sdk-persona'
        assert self_id.isascii() and self_id.isdigit() and int(self_id)!=100000002
        sdk={'platform':{'id':platform_id,'type':'aiocqhttp','enable':True,
            'ws_reverse_host':'127.0.0.1','ws_reverse_port':19662,'ws_reverse_token':secrets.token_hex(24)},
            'self_id':self_id,'user_id':100000002,'persona_id':persona_id}
        packet['host_settings'].update(sdk_ingress=sdk,manifest_sha256=manifest_pin,
            sdk_identity_path='/etc/sylanne-b04-fixture/sdk-identity.json')
    if scenario in ('sdk_m1_two_messages_v1','sdk_m1_first_bubble_stop_v1','sdk_m1_first_bubble_unknown_v1','sdk_ordinary_old_source_v1','sdk_ordinary_greeting_v1','sdk_d13_v6_256_current_v1','sdk_d13_v7_256_current_v1','sdk_a06_real_elapsed_phases_v1'):
        helper_names=('sdk_m1_fixture_contract_v1.py','sdk_m1_model_fixture_v1.py')
        if scenario=='sdk_d13_v6_256_current_v1':helper_names+=('sdk_d13_v6_counter_fixture_v1.py','sdk_d13_v6_256_root_fixture_v1.py')
        if scenario=='sdk_d13_v7_256_current_v1':helper_names+=('sdk_d13_v7_256_root_fixture_v1.py',)
        packet['m1_helpers']={name:(Path(__file__).parent/name).read_text() for name in helper_names}
        packet['m1_helper_pins']={name:hashlib.sha256(body.encode()).hexdigest() for name,body in packet['m1_helpers'].items()}
        for name,body in packet['m1_helpers'].items():compile(body,name,'exec')
    if real_elapsed:
        saved_packet=phase_root/'private-phase-packet.json'
        if phase_index==0:
            saved_packet.write_text(json.dumps(packet));saved_packet.chmod(0o600)
        else:
            initial=json.loads(saved_packet.read_text())
            for key in ('host_entry','controller','m1_helper_pins','package_sha256','manifest_sha256','request'):
                if initial[key]!=packet[key]:raise ValueError('crossday persistent installed fixture contract changed')
            initial.update(evidence=str(evidence),real_elapsed_phase_index=phase_index)
            initial['host_settings']['real_elapsed_day0_source_ref']=json.loads((phase_root/'day0-originals.json').read_text())['originals']['source_ref']
            packet=initial
    private=tmp_path/'b04-private-input.json'
    process=controller_process=None
    service_pidfd=controller_pidfd=None
    signal=__import__('signal')
    def pin_namespace_child(wrapper):
        deadline=time.monotonic()+5
        children_file=Path(f'/proc/{wrapper.pid}/task/{wrapper.pid}/children')
        children=[]
        while wrapper.poll() is None and time.monotonic()<deadline:
            children=children_file.read_text().split() if children_file.exists() else []
            if children:break
            time.sleep(.01)
        assert len(children)==1,'owned unshare must expose exactly its private PID1 child'
        pid=int(children[0]);handle=os.pidfd_open(pid)
        rows=dict(line.split(':',1) for line in Path(f'/proc/{pid}/status').read_text().splitlines() if ':' in line)
        assert rows['NSpid'].split()[-1]=='1'
        tail=Path(f'/proc/{pid}/stat').read_text().rsplit(')',1)[1].split()
        return pid,handle,{'host_pid':pid,'parent_pid':int(rows['PPid']),
            'uids':[int(v) for v in rows['Uid'].split()],
            'birth':Path('/proc/sys/kernel/random/boot_id').read_text().strip()+':'+tail[19],
            'pid_namespace':os.readlink(f'/proc/{pid}/ns/pid'),
            'mount_namespace':os.readlink(f'/proc/{pid}/ns/mnt')}
    def observe_domains(service,controller):
        shared=[]
        for name in ('etc/sylanne/authority/deployment.json','etc/sylanne/client/profiles/b04/client-cert.pem',
                     'opt/sylanne-b04-fixture/controller.py'):
            first=Path(f'/proc/{service}/root')/name;second=Path(f'/proc/{controller}/root')/name
            a,b=first.stat(),second.stat()
            assert (a.st_dev,a.st_ino)==(b.st_dev,b.st_ino)
            shared.append({'path':'/'+name,'device':a.st_dev,'inode':a.st_ino})
        inventory=[]
        for entry in Path(f'/proc/{service}/root/proc').iterdir():
            if not entry.name.isdecimal():continue
            try:
                rows=dict(line.split(':',1) for line in (entry/'status').read_text().splitlines() if ':' in line)
                tail=(entry/'stat').read_text().rsplit(')',1)[1].split()
                inventory.append({'pid':int(entry.name),'parent_pid':int(rows['PPid']),
                    'uids':[int(v) for v in rows['Uid'].split()],
                    'start_ticks':tail[19],'pid_namespace':os.readlink(entry/'ns/pid')})
            except FileNotFoundError:continue
        return {'shared_installed_objects':shared,'service_live_proc_inventory':inventory}
    def wait_cold_authority_listener(service,handle,identity,expected,end):
        """Observe only this owned service universe; never probe another port owner."""
        assert expected['phase']==2 and expected['pid_namespace']==identity['pid_namespace']
        started=time.monotonic()
        while process.poll() is None and time.monotonic()<end:
            if select.select([handle],[],[],0)[0]:
                raise RuntimeError('owned_service_retired_before_authority_listener')
            for entry in Path('/proc').iterdir():
                if not entry.name.isdecimal() or int(entry.name)==service:continue
                try:
                    if os.readlink(entry/'ns/pid')!=identity['pid_namespace']:continue
                    status=dict(line.split(':',1) for line in (entry/'status').read_text().splitlines() if ':' in line)
                    if int(status['PPid'])!=service:continue
                    if ([int(v) for v in status['Uid'].split()]!=[expected['uid']]*4
                            or [int(v) for v in status['Gid'].split()]!=[expected['gid']]*4):
                        raise RuntimeError('cold_authority_actual_os_principal_changed')
                    argv=[v.decode() for v in (entry/'cmdline').read_bytes().split(b'\0') if v]
                    if argv!=expected['expected_final_argv']:continue  # Actual bootstrap may still be executing.
                    tail=(entry/'stat').read_text().rsplit(')',1)[1].split()
                    birth=Path('/proc/sys/kernel/random/boot_id').read_text().strip()+':'+tail[19]
                    child_fd=os.pidfd_open(int(entry.name),0)
                    try:
                        if select.select([child_fd],[],[],0)[0]:continue
                        if (os.readlink(entry/'exe')!=expected['executable']
                                or hashlib.sha256((entry/'exe').read_bytes()).hexdigest()!=expected['executable_sha256']
                                or hashlib.sha256((entry/'root'/expected['entry'].lstrip('/')).read_bytes()).hexdigest()!=expected['entry_sha256']):
                            raise RuntimeError('cold_authority_exact_installed_exec_code_changed')
                        inodes={os.readlink(fd) for fd in (entry/'fd').iterdir()}
                        for row in (entry/'net/tcp').read_text().splitlines()[1:]:
                            fields=row.split();address,port=fields[1].split(':')
                            if (fields[3]!='0A' or int(port,16)!=expected['port']
                                    or socket.inet_ntoa(bytes.fromhex(address)[::-1])!=expected['host']
                                    or 'socket:['+fields[9]+']' not in inodes):continue
                            after=(entry/'stat').read_text().rsplit(')',1)[1].split()
                            if after[19]!=tail[19] or select.select([child_fd],[],[],0)[0]:
                                raise RuntimeError('cold_authority_birth_changed_during_listener_observation')
                            return {'scope':'fixture_OS_listener_observation_not_authorization','phase':2,
                                'authority_host_pid':int(entry.name),'authority_inner_pid':int(status['NSpid'].split()[-1]),
                                'actual_birth':birth,'pid_namespace':identity['pid_namespace'],
                                'listener_inode':fields[9],'listener_port':expected['port'],
                                'executable_sha256':expected['executable_sha256'],'entry_sha256':expected['entry_sha256'],
                                'manifest_sha256':expected['manifest_sha256'],'selection_revision':expected['selection_revision'],
                                'selected_cohort_digest':expected['selected_cohort_digest'],
                                'observed_utc':time.time(),'elapsed_seconds':time.monotonic()-started}
                    finally:os.close(child_fd)
                except (FileNotFoundError,ProcessLookupError):continue
            time.sleep(.05)
        raise TimeoutError('bounded_cold_authority_owned_listener_not_ready')
    try:
        if lifecycle_diagnostic:packet['diagnostic_outer_deadline_monotonic']=outer_deadline
        phases=(0,1) if real_elapsed and phase_index==0 else (2,) if real_elapsed else (0,1) if scenario in ('sdk_m1_two_messages_v1','sdk_m1_first_bubble_stop_v1','sdk_m1_first_bubble_unknown_v1','sdk_ordinary_old_source_v1','sdk_ordinary_greeting_v1','sdk_d13_v6_256_current_v1','sdk_d13_v7_256_current_v1') else (0,) if diagnostic else (0,1) if lifecycle_diagnostic else (0,1,2)
        for phase in phases:
            packet['phase']=phase;private.write_text(json.dumps(packet));private.chmod(0o600)
            # Planned offline maintenance boundary, never a retry with a changed fixture.
            stderr_path=tmp_path/('b04-namespace-phase-'+str(phase)+'.stderr')
            descriptor=os.open(stderr_path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
            stdout_path=tmp_path/('b04-namespace-phase-'+str(phase)+'.stdout')
            stdout_descriptor=os.open(stdout_path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
            with os.fdopen(descriptor,'w') as private_stderr, os.fdopen(stdout_descriptor,'w') as private_stdout:
                process = subprocess.Popen(['unshare','--mount','--pid','--fork','--mount-proc',
                    sys.executable,'-I','-B','-c',NAMESPACE_PREP_V1,str(private)],
                    stdout=private_stdout,stderr=private_stderr,start_new_session=True)
            service_pid,service_pidfd,service_identity=pin_namespace_child(process)
            deadline=outer_deadline if (diagnostic or lifecycle_diagnostic) else time.monotonic()+180
            ready=persistent/'opt/sylanne-b04-fixture/launcher-ready.json'
            while process.poll() is None and time.monotonic()<deadline:
                if ready.is_file() and json.loads(ready.read_text())['phase']==phase:break
                time.sleep(.05)
            else:raise AssertionError('formal preparation did not publish this phase launcher readiness')
            if phase==2:
                expected_path=persistent/'opt/sylanne-b04-fixture/phase-two-authority-expectation.json'
                expected_bytes=expected_path.read_bytes()
                assert hashlib.sha256(expected_bytes).hexdigest()==json.loads(ready.read_text())['authority_expectation_sha256']
                observation=wait_cold_authority_listener(service_pid,service_pidfd,service_identity,
                    json.loads(expected_bytes),min(deadline,time.monotonic()+60))
                target=evidence/'phase-two-owned-authority-listener-ready.json'
                target.write_text(json.dumps(observation))
                with target.open('rb') as stream:os.fsync(stream.fileno())
            if diagnostic:
                data=persistent/'varlib/sylanne-b04-host/data'
                health_path=data/'host-ready.json'
                failure_path=data/'host-first-failure.json'
                while process.poll() is None and time.monotonic()<outer_deadline:
                    if health_path.is_file() or failure_path.is_file():break
                    time.sleep(.05)
                else:raise TimeoutError('first_selection_probe_only_270_seconds' if probe_diagnostic else 'first_v2_fence_only_120_seconds')
                health_value=json.loads(health_path.read_text()) if health_path.is_file() else None
                failure_value=json.loads(failure_path.read_text()) if failure_path.is_file() else None
                observation=data/'v2-fence-observation.json'
                result={'schema':'sylanne.b04.first-v2-fence-diagnostic.v1',
                    'status':'DIAGNOSTIC_NOT_B04_PASS','health':health_value,'host_failure':failure_value,
                    'v2_observation':json.loads(observation.read_text()) if observation.is_file() else None,
                    'service_process_identity':service_identity,'elapsed_seconds':time.monotonic()-outer_started,
                    'outer_deadline_seconds':270 if probe_diagnostic else 120,'deadline_remaining_seconds':outer_deadline-time.monotonic(),
                    'fresh_budget_valid_until_utc':request['budget_valid_until_utc'],
                    'budget_deadline_remaining_seconds':request['budget_valid_until_utc']-time.time(),
                    'snapshot_sha256':package_pin,'manifest_sha256':manifest_pin,
                    'scope':'formal preparation and first actual installed SDK initialization result only; no Owner or lifecycle qualification'}
                if probe_diagnostic:
                    result['schema']='sylanne.b04.first-selection-probe-diagnostic.v1'
                    result['probe_import_originals']=[{'path':str(p),'sha256':hashlib.sha256(p.read_bytes()).hexdigest()}
                        for p in sorted(data.glob('selection-probe-import-*.json'))]
                    result['scope']='Actual first SDK selection probe import diagnosis only; original120sprobe; no Owner or fullB04qualification'
                (evidence/('first-selection-probe-diagnostic.json' if probe_diagnostic else 'first-v2-fence-diagnostic.json')).write_text(json.dumps(result,indent=2))
                return
            if phase in (0,1):
                # Actual Host bootstrap completes before the independent Owner
                # controller loads its management modules into this budget.
                data=persistent/'varlib/sylanne-b04-host/data'
                health_path=data/'host-ready.json'
                failure_path=data/'host-first-failure.json'
                endpoint=persistent/'run/sylanne-b04-host/fixture.sock'
                while process.poll() is None and time.monotonic()<deadline:
                    if failure_path.is_file():
                        raise RuntimeError('actual_sdk_host_first_failure_before_controller')
                    if health_path.is_file() and endpoint.exists():
                        actual=json.loads(health_path.read_text())
                        assert actual['fixture_phase']==phase and actual['manifest_sha256']==manifest_pin
                        break
                    time.sleep(.05)
                else:raise TimeoutError('original_host_preparation_deadline_before_controller')
            # Enter only its mount namespace; the new PID namespace is a sibling.
            argv=['nsenter',f'--mount=/proc/{service_pid}/ns/mnt','--','unshare','--mount','--pid','--fork',
                '--mount-proc','--propagation','private','/opt/sylanne-runtime/bin/python3.12','-B',
                '/opt/sylanne-b04-fixture/controller.py','/opt/sylanne-b04-fixture/controller-input.json']
            controller_stderr=tmp_path/('b04-controller-phase-'+str(phase)+'.stderr')
            fd=os.open(controller_stderr,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
            controller_stdout=tmp_path/('b04-controller-phase-'+str(phase)+'.stdout')
            out_fd=os.open(controller_stdout,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
            with os.fdopen(fd,'w') as stream, os.fdopen(out_fd,'w') as out_stream:
                controller_process=subprocess.Popen(argv,stdout=out_stream,stderr=stream,start_new_session=True)
            controller_pid,controller_pidfd,controller_identity=pin_namespace_child(controller_process)
            assert service_identity['pid_namespace']!=controller_identity['pid_namespace']
            assert service_identity['mount_namespace']!=controller_identity['mount_namespace']
            observation={'service':service_identity,'controller':controller_identity,
                'nsenter_pid_used':False,**observe_domains(service_pid,controller_pid)}
            (evidence/('process-domains-phase-'+str(phase)+'.json')).write_text(json.dumps(observation))
            controller_process.wait(timeout=outer_deadline-time.monotonic() if lifecycle_diagnostic else 360)
            assert select.select([controller_pidfd],[],[],0)[0],'owned controller PID1 has not exited'
            with controller_stderr.open('rb') as stream:os.fsync(stream.fileno())
            assert controller_process.returncode==0,'owned controller namespace failed'
            os.close(controller_pidfd);controller_pidfd=None
            if cold_assembly_diagnostic and phase==2:
                target=evidence/'cold-assembly-cause-diagnostic.json'
                observation=json.loads(target.read_text())
                assert observation['status']=='DIAGNOSTIC_NOT_B04_PASS'
                observation.update(outer_elapsed_seconds=time.monotonic()-outer_started,
                    original_controller_timeout_seconds=360,original_driver_timeout_seconds=1000,
                    cleanup_scope='owned fixture namespace retirement; not completed Host lifecycle')
                target.write_text(json.dumps(observation,indent=2))
                with target.open('rb') as stream:os.fsync(stream.fileno())
                if observation['failed_predicate_observed']:
                    raise RuntimeError('actual_cold_assembly_health_blocked_first_observation')
                return
            if lifecycle_diagnostic and phase==1:
                target=evidence/'first-lifecycle-cause-diagnostic.json'
                result=json.loads(target.read_text())
                assert result['status']=='DIAGNOSTIC_NOT_B04_PASS'
                assert result['event'] in {'private_worker_cause','actual_original_hold','formal_owner_pause'}
                assert result['pause_submission_count']==1 and result['sender_calls']==0
                assert result['model_counter_observation']['state'] in {'observed','UNKNOWN'}
                if result['model_counter_observation']['state']=='observed':assert result['model_calls']==0
                result.update(outer_elapsed_seconds=time.monotonic()-outer_started,
                    fixture_deadline_seconds=270,driver_deadline_seconds=300,cleanup_reserve_seconds=30,
                    fixture_environment_retirement='owned pidfd cleanup after diagnostic; not production Authority maintenance')
                target.write_text(json.dumps(result,indent=2))
                with target.open('rb') as stream:os.fsync(stream.fileno())
                return
            if phase==1:
                complete=evidence/'phase-one-complete.json'
                failure=evidence/'first-failure.json'
                assert complete.is_file(), (failure.read_text() if failure.is_file() else 'formal first Host drain not recorded')
            elif phase==0:
                complete=evidence/'phase-zero-complete.json'
                failure=evidence/'first-failure.json'
                assert complete.is_file(), (failure.read_text() if failure.is_file() else 'completed namespace bootstrap not recorded')
                original=json.loads(complete.read_text())
                assert original['status']=='actual_namespace_provision_completed_no_owner'
            elif phase==2:
                assert (evidence/'receipt.json').is_file(),'formal second-phase completion receipt missing'
            # Bootstrap retires only this fixture environment after completed provision;
            # phases one/two retire after their genuine formal Host pause.
            signal.pidfd_send_signal(service_pidfd,signal.SIGTERM)
            process.wait(timeout=30)
            assert select.select([service_pidfd],[],[],0)[0],'owned service PID1 has not exited'
            with stderr_path.open('rb') as stream:os.fsync(stream.fileno())
            os.close(service_pidfd);service_pidfd=None
            (evidence/('namespace-phase-'+str(phase)+'-exit.json')).write_text(json.dumps({
                'returncode':process.returncode,'controller_returncode':controller_process.returncode,
                'service_pidfd_exited':True,'controller_pidfd_exited':True,
                'scope':('fixture_environment_retired_after_completed_namespace_provision; not production shutdown or formal Host pause'
                    if phase==0 else 'owned fixture retirement after recorded formal Host drain; no production Authority maintenance claim')}))
        if real_elapsed:
            phase_receipt=json.loads((phase_root/(real_elapsed_phase+'-originals.json')).read_text())
            assert phase_receipt['status']=='PHASE_COMPLETE' and phase_receipt['package_sha256']==package_pin
            return phase_receipt
        receipt=evidence/('receipt.json' if scenario=='b04' else 'm1-receipt.json')
        failure=evidence/'first-failure.json'
        assert receipt.is_file(), ('B04 actual first failure: '+failure.read_text()
            if failure.is_file() else 'B04 namespace ended without receipt or structured first failure')
        value=json.loads(receipt.read_text())
        assert value['status']=='PASS' and value['snapshot_sha256']==package_pin
        if scenario=='b04':
            assert value['model_calls']==value['sender_calls']==0
            assert any(stage['stage']=='actual_installed_main_initialize' for stage in value['stages'])
            assert any(stage['stage']=='formal_resumed_new_actual_host' for stage in value['stages'])
        else:
            from .sdk_m1_fixture_contract_v1 import EPISODES
            assert value['external_provider_requests']==0 and 1<=value['simulated_provider_calls']<=(1536 if scenario in ('sdk_d13_v6_256_current_v1','sdk_d13_v7_256_current_v1') else 12)
            assert value['scenario']==scenario
            if scenario in ('sdk_d13_v6_256_current_v1','sdk_d13_v7_256_current_v1'):
                assert len(value['episodes'])==256 and value['simulated_sender_calls']==256
                assert value['current_collection']['current_turn_count']==256
                assert len(value['current_collection']['pages'])==4 and value['current_collection']['paid_originals']
            elif scenario=='sdk_ordinary_greeting_v1':
                assert value['simulated_sender_calls']==2 and len(value['episodes'])==2
                for item in value['episodes']:
                    original=item['originals']
                    assert original['status']=='actual_no_search' and original['routing']=='no_search'
                    assert original['c3_call_count']==original['c04_attempt_count']==0
            elif scenario=='sdk_ordinary_old_source_v1':
                assert value['simulated_sender_calls']==2 and len(value['episodes'])==2
                first,second=(item['originals'] for item in value['episodes'])
                assert first['source_ref']!=second['source_ref'] and first['learned_at']<=second['learned_at']
                assert second['c04']['selected_source_ref']==first['source_ref']
                assert second['c3_routing']['stop_reason']=='search_required'
                assert len(second['paid_reply'])==2
            else:
                assert value['simulated_sender_calls']==sum(item['semantic_segment_count'] for item in EPISODES)-(0 if scenario=='sdk_m1_two_messages_v1' else 1)
                assert len(value['episodes'])==2 and value['episodes'][0]['originals']['goal']['state']=='active'
                assert value['episodes'][1]['originals']['goal']['state']=='satisfied'
    finally:
        if controller_pidfd is not None:
            if not select.select([controller_pidfd],[],[],0)[0]:signal.pidfd_send_signal(controller_pidfd,signal.SIGTERM)
            controller_process.wait(timeout=10)
            os.close(controller_pidfd)
        if service_pidfd is not None:
            if not select.select([service_pidfd],[],[],0)[0]:signal.pidfd_send_signal(service_pidfd,signal.SIGTERM)
            process.wait(timeout=30)
            os.close(service_pidfd)
        if process is not None and process.poll() is None:
            # Only this already owned wrapper, never a numeric PID1 or UID sweep.
            wrapper_pidfd=os.pidfd_open(process.pid)
            try:signal.pidfd_send_signal(wrapper_pidfd,signal.SIGTERM);process.wait(timeout=10)
            finally:os.close(wrapper_pidfd)
        private.unlink(missing_ok=True)
        private_files=(persistent/'opt/sylanne-b04-fixture/controller-seed.json',
            persistent/'opt/sylanne-b04-fixture/controller-input.json',
            persistent/'varlib/sylanne-b04-host/fixture-input.json',
             persistent/'etc/sylanne-b04-fixture/m1-private-config.json')
        if not real_elapsed:
            for generated in private_files:generated.unlink(missing_ok=True)
        for raw_log in tmp_path.glob('b04-*.std*'):
            with raw_log.open('rb') as stream:os.fsync(stream.fileno())
        if lifecycle_diagnostic:
            counter_path=persistent/'varlib/sylanne-b04-host/data/model-network-observation.json'
            counter={'stage':'after_owned_fixture_namespace_cleanup','observed_utc':time.time(),
                'source_path':str(counter_path),'state':'observed' if counter_path.is_file() else 'UNKNOWN','requests':None,
                'not_first_cause_time_counter':True}
            if counter_path.is_file():
                encoded=counter_path.read_bytes()
                counter.update(requests=json.loads(encoded)['requests'],
                    source_sha256=hashlib.sha256(encoded).hexdigest(),source_mtime_epoch=counter_path.stat().st_mtime)
            (evidence/'first-lifecycle-cause-post-cleanup-counter.json').write_text(json.dumps(counter))
        (evidence/'fixture-cleanup.json').write_text(json.dumps({
            'namespace_process_exited':process is not None and process.poll() is not None,'private_input_remaining':private.exists(),
            'private_signer_or_plain_dashboard_input_remaining':any(path.exists() for path in private_files),
            'private_inputs_retained_for_named_real_elapsed_resume':real_elapsed,
            'global_profiles_or_services_changed':False}))


@pytest.mark.skipif(sys.platform != "linux",reason="requires actual isolated Linux installation")
def test_b04_actual_installed_sdk_owner_management_d05_quit_restart(tmp_path):
    return _run_actual_installed_sdk_fixture_v1(tmp_path,scenario="b04")


@pytest.mark.skipif(sys.platform != "linux",reason="requires actual isolated Linux installation")
def test_m1_actual_installed_sdk_two_message_task_and_reply_chain(tmp_path):
    return _run_actual_installed_sdk_fixture_v1(tmp_path,scenario="sdk_m1_two_messages_v1")


@pytest.mark.skipif(sys.platform != "linux",reason="requires actual isolated Linux installation")
def test_m1_actual_installed_sdk_first_bubble_stop_preserves_effect_and_core_roster(tmp_path):
    return _run_actual_installed_sdk_fixture_v1(tmp_path,scenario="sdk_m1_first_bubble_stop_v1")


@pytest.mark.skipif(sys.platform != "linux",reason="requires actual isolated Linux installation")
def test_m1_actual_installed_sdk_first_bubble_unknown_holds_remaining_and_parent_fees_once(tmp_path):
    return _run_actual_installed_sdk_fixture_v1(tmp_path,scenario="sdk_m1_first_bubble_unknown_v1")


@pytest.mark.skipif(sys.platform != "linux",reason="requires actual isolated Linux installation")
def test_a02_actual_installed_sdk_ordinary_related_old_source_recall_and_reply(tmp_path):
    return _run_actual_installed_sdk_fixture_v1(tmp_path,scenario="sdk_ordinary_old_source_v1")


@pytest.mark.skipif(sys.platform != "linux",reason="requires actual isolated Linux installation")
def test_a02_actual_installed_sdk_greeting_adopted_no_search_zero_c3_c04(tmp_path):
    return _run_actual_installed_sdk_fixture_v1(tmp_path,scenario="sdk_ordinary_greeting_v1")


def test_l03_actual_installed_sdk_d13_v6_256_current_paid_native_cold_replay_expiry(tmp_path):
    """Fresh protected Root only; real expiry remains separately reported if not due."""
    _run_actual_installed_sdk_fixture_v1(tmp_path,scenario="sdk_d13_v6_256_current_v1")


def test_l03_actual_installed_sdk_d13_v7_256_current_core_count_paid_native_cold_replay(tmp_path):
    """Independent V7/Core-counter installation; old V6 bound remains separate."""
    _run_actual_installed_sdk_fixture_v1(tmp_path,scenario='sdk_d13_v7_256_current_v1')


@pytest.mark.skipif(sys.platform != "linux",reason="requires actual isolated Linux installation and real elapsed days")
def test_a06_actual_installed_sdk_real_elapsed_day0_day4_day5_resume(tmp_path):
    """Run one named server phase; later invocations reuse this exact installed tree."""
    directory=os.environ.get('SYLANNE_SDK_M1_REAL_ELAPSED_DIRECTORY')
    phase=os.environ.get('SYLANNE_SDK_M1_REAL_ELAPSED_PHASE')
    if not directory or not phase or not os.environ.get('SYLANNE_SDK_M1_REAL_ELAPSED_APPROVAL'):
        pytest.skip('requires persistent real elapsed directory, day0/day4/day5 and exact eighteen-call initial approval')
    value=_run_actual_installed_sdk_fixture_v1(tmp_path,scenario='sdk_a06_real_elapsed_phases_v1',
        real_elapsed_directory=directory,real_elapsed_phase=phase)
    if value['status'] in {'WAITING','HOLD'}:pytest.skip(json.dumps(value,separators=(',',':')))
    assert value['clock_mode']=='REAL_ELAPSED_SERVER_PHASES' and value['controlled_elapsed'] is False
    if phase!='day5':pytest.skip('actual '+phase+' production originals saved; full A06 awaits remaining real elapsed phases')
    assert value['overall_a06']=='PASS' and value['day5_restart_readback_verified']
    assert value['day5_new_input_continuity']=='VERIFIED' and len(value['meter']['calls'])<=18


# Pure installer-contract regressions. These do not constitute installed acceptance.
def test_artifact_v3_request_template_is_explicit_and_preserves_approved_budget_defaults():
    from scripts.alpha1.install_linux import request_template_v5, request_template_v6
    old = request_template_v5()
    new = request_template_v6()
    assert new["schema"] == "sylanne3.linux-install-request.v6"
    for name in ("budget_limits", "budget_max_ceiling", "budget_valid_until_utc"):
        assert new[name] == old[name]
    for name in ("artifact_observation_cognition", "artifact_phase_observer", "artifact_phase_counter"):
        assert new[name] is None


def _artifact_v3_descriptor_contract_case():
    # Descriptors only: no claimed installed files, signatures or count evidence.
    from scripts.alpha1.install_linux import ARTIFACT_COUNTER_INITIAL_SCHEMA
    counter = {
        "schema": ARTIFACT_COUNTER_INITIAL_SCHEMA, "source_scope": "production",
        "model_revision": "explicit-mock-only-v1", "counter_policy_id": "test:mock-external-contract",
        "counter_policy_version": 1, "executable": "/uninstalled-test/counter",
        "program_sha256": "a"*64, "counter_public_key_hex": "b"*64,
        "tokenizer_path": "/uninstalled-test/tokenizer", "tokenizer_sha256": "c"*64,
        "applicability_path": "/uninstalled-test/applicability.json", "applicability_sha256": "d"*64,
        "encoding_rule_id": "test:mock-only-external-contract", "encoding_rule_sha256": "e"*64,
        "timeout_seconds": 60}
    observer = {"schema": "sylanne.artifact-phase-observer-installation.v2",
        "observer_id": "test:independent-observer", "observer_version": 1,
        "asset_ref": "/uninstalled-test/observer.json", "asset_sha256": "f"*64}
    return {"artifact_phase_counter": counter, "artifact_phase_observer": observer}


def test_artifact_v3_asset_descriptor_validation_issues_no_installation():
    from scripts.alpha1.install_linux import validate_artifact_v3_asset_descriptors_v1
    request = _artifact_v3_descriptor_contract_case()
    assert validate_artifact_v3_asset_descriptors_v1(request) is request


@pytest.mark.parametrize("change", ("LOCAL_FIXTURE", "unbounded_answer", "relative_path"))
def test_artifact_v3_asset_descriptors_reject_legacy_fixture_and_content_answers(change):
    from scripts.alpha1.install_linux import validate_artifact_v3_asset_descriptors_v1
    request = _artifact_v3_descriptor_contract_case()
    if change == "LOCAL_FIXTURE":
        request["artifact_phase_counter"]["source_scope"] = "LOCAL_FIXTURE"
    elif change == "unbounded_answer":
        request["artifact_phase_observer"]["expected_answer"] = True
    else:
        request["artifact_phase_counter"]["executable"] = "relative/counter"
    with pytest.raises(ValueError):
        validate_artifact_v3_asset_descriptors_v1(request)


def test_artifact_v3_fields_cannot_upgrade_a_legacy_install_request():
    from scripts.alpha1.install_linux import request_template_v5, check_request
    request = request_template_v5()
    request.update(_artifact_v3_descriptor_contract_case())
    request["artifact_observation_cognition"] = None
    with pytest.raises(ValueError, match="installation request fields differ"):
        check_request(request)


def _artifact_v3_fixture_rpc_v1(action, **values):
    import socket
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as channel:
        channel.settimeout(65)
        channel.connect("/run/sylanne-b04-host/fixture.sock")
        channel.sendall(json.dumps({"action": action, **values}, separators=(",", ":")).encode() + b"\n")
        with channel.makefile("rb") as stream:
            answer = json.loads(stream.readline(1048577))
    if answer["status"] != "ok":
        raise RuntimeError("actual SDK fixture RPC failed: " + answer["type"])
    return answer["result"]


def _run_artifact_v3_installed_snapshot_node_v1(*, unknown, admission_negatives=False):
    """One real message in an independently prepared fresh Linux installation."""
    import sqlite3
    location = os.environ.get("SYLANNE_ARTIFACT_V3_INSTALLED_SETUP")
    if location is None:
        pytest.skip("requires a new Root-approved V6/V9 installed SDK Mock fixture; old LOCAL_FIXTURE is unsupported")
    if os.name != "posix" or os.geteuid() != 0:
        raise PermissionError("the isolated fixture Root controller must run this forensic node")
    sys.path.insert(0, "/opt/sylanne/code")
    from _runtime_bootstrap import load_canonical_runtime_v1
    load_canonical_runtime_v1(Path("/opt/sylanne/code"))
    from sylanne3.authority_service.linux_installation_security_v1 import read_installed_bytes_v1
    from rewrite.tests.alpha1.integration.beta1_fixture_evidence_read_v3 import (
        backup_artifact_v3_fixture_graph_v1, verify_artifact_v3_fixture_snapshot_v1)
    setup = json.loads(read_installed_bytes_v1(location, limit=65536))
    fields = {"schema", "profile_id", "installation_id", "manifest_digest", "root_grant_digest",
        "original_deadline_utc", "approved_root_limits", "approved_root_max_ceiling", "graph_path",
        "evidence_directory", "message_id", "task_text", "unknown_observation"}
    if set(setup) != fields or setup["schema"] != "sylanne.test.artifact-v3-installed-snapshot-setup.v1" or setup["unknown_observation"] is not unknown:
        raise ValueError("exact new installed Artifact V3 setup descriptor required")
    assets = json.loads(read_installed_bytes_v1("/etc/sylanne/authority/assets.json"))
    if Path(setup["graph_path"]) != Path(assets["graph_db"]):
        raise ValueError("forensic source is not this fixture's actual installed business Graph")
    diagnostic_log = os.environ.get("SYLANNE_ARTIFACT_V3_AUTHORITY_DIAGNOSTIC_LOG")
    diagnostic_cursor = None
    if admission_negatives:
        if not diagnostic_log:
            pytest.skip("requires the actual isolated Core diagnostic log; opaque RPC errors are not concrete rejection evidence")
        from rewrite.host_tests.alpha1.artifact_v3_admission_diagnostics_v1 import capture_core_diagnostic_cursor_v1
        diagnostic_cursor = capture_core_diagnostic_cursor_v1(diagnostic_log)
    directory = Path(setup["evidence_directory"])
    directory.mkdir(mode=0o700, parents=False, exist_ok=False)
    stage = "signed_pre_episode_baseline"
    try:
        before = _artifact_v3_fixture_rpc_v1("artifact_v3_checkpoint")
        if (not before["runtime_started"] or not before["worker_started"]
                or before["manifest_sha256"] != setup["manifest_digest"]
                or before["provider_network_requests"] or before["local_model_requests"]
                or before["model_fixture_first_failure"] is not None
                or not before["fixture_checkpoint"]["event_queue_empty"]
                or before["fixture_checkpoint"]["pending_sdk_tasks"]
                or before["fixture_checkpoint"]["worker_transaction_open"]):
            raise ValueError("actual SDK is not a clean installed V9 Mock baseline")
        initial = directory / "baseline.sqlite3"
        initial_pin = backup_artifact_v3_fixture_graph_v1(graph_path=setup["graph_path"], target=initial)
        baseline = verify_artifact_v3_fixture_snapshot_v1(snapshot=initial, setup=setup, baseline=True)
        if admission_negatives:
            armed = _artifact_v3_fixture_rpc_v1("artifact_v3_arm_admission_negatives")
            if armed["state"] != "armed" or armed["cases"] or armed["valid_forward_count"]:
                raise ValueError("the actual unused AuthorityClient admission observer was not armed")
        stage = "single_actual_sdk_ingress"
        ingress = _artifact_v3_fixture_rpc_v1("ordinary_ingress", message_id=setup["message_id"], text=setup["task_text"])
        if not all(ingress.get(name) for name in ("handler_entered", "handler_returned", "pipeline_entered", "pipeline_returned")):
            raise ValueError("actual SDK handler/pipeline did not process the single message")
        stage = "actual_checkpoint_and_readonly_snapshot"
        end = min(time.monotonic() + 120, time.monotonic() + setup["original_deadline_utc"] - time.time())
        last = None
        serial = 0
        while time.monotonic() < end:
            health = _artifact_v3_fixture_rpc_v1("artifact_v3_checkpoint")
            if (health["provider_network_requests"] or health["model_fixture_first_failure"] is not None
                    or health["artifact_v3_admission_probe"]["first_failure"] is not None):
                raise RuntimeError("actual provider traffic or first Mock failure observed")
            checkpoint = health["fixture_checkpoint"]
            if not checkpoint["event_queue_empty"] or checkpoint["pending_sdk_tasks"] or checkpoint["worker_transaction_open"]:
                time.sleep(0.5)
                continue
            with sqlite3.connect(Path(setup["graph_path"]).as_uri()+"?mode=ro", uri=True) as source:
                source.execute("PRAGMA query_only=ON")
                marker = source.execute("SELECT COALESCE(MAX(commit_seq),0) FROM graph_bundle_operations").fetchone()[0]
            if marker == last:
                time.sleep(0.5)
                continue
            last = marker
            serial += 1
            snapshot = directory / ("checkpoint-" + str(serial) + ".sqlite3")
            pin = backup_artifact_v3_fixture_graph_v1(graph_path=setup["graph_path"], target=snapshot)
            result = verify_artifact_v3_fixture_snapshot_v1(snapshot=snapshot, setup=setup, unknown=unknown)
            if result is None:
                time.sleep(0.5)
                continue
            calls = health["model_fixture_calls"]
            expected = 4 if unknown else 6
            if (len(calls) != expected or len({c["call_id"] for c in calls}) != expected
                    or {c["call_id"] for c in calls} != {c["call_id"] for c in result["calls"]}
                    or sum(c["fixture_charge_microusd"] for c in calls) != 0
                    or health["local_model_requests"] != expected
                    or (unknown and health["sender_calls"] != before["sender_calls"])):
                raise ValueError("actual Mock transport calls/costs differ from authenticated snapshot originals")
            if admission_negatives:
                probe = health["artifact_v3_admission_probe"]
                expected_names = ["sealed_grant_binding", "budget_lease", "reservation_operation",
                    "reservation_digest", "provider_config", "installation_grant", "expired_envelope", "future_envelope"]
                if (probe["state"] != "original_admitted" or probe["valid_forward_count"] != 1
                        or [item["name"] for item in probe["cases"]] != expected_names
                        or [item["layer"] for item in probe["cases"]] != ["live_core_original_identity_tamper"]*5+["host_before_dispatch"]*3
                        or any(item["provider_call_delta"] or item["fixture_charge_delta_microusd"]
                            or item["original_core_state"] != "prepared" for item in probe["cases"])):
                    raise ValueError("live negative admissions did not retain the original before its one valid admission")
                from rewrite.host_tests.alpha1.artifact_v3_admission_diagnostics_v1 import require_original_intent_rejections_v1
                probe["actual_core_diagnostics"] = require_original_intent_rejections_v1(
                    diagnostic_log, diagnostic_cursor, count=5)
            output = {"schema": "sylanne.test.artifact-v3-installed-snapshot-result.v1",
                "status": "PASS", "unknown_observation": unknown, "baseline_snapshot_sha256": initial_pin,
                "snapshot_sha256": pin, "original_deadline_utc": setup["original_deadline_utc"],
                "baseline": baseline, "originals": result, "sdk_health": health,
                "provider_network_requests": 0, "fixture_model_charge_microusd": 0}
            fd = os.open(directory/"result.json", os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as stream:
                json.dump(output, stream, sort_keys=True);stream.flush();os.fsync(stream.fileno())
            return output
        raise TimeoutError("actual Artifact V3 episode did not qualify within its original deadline")
    except BaseException as exc:
        failure = {"schema": "sylanne.test.artifact-v3-first-failure.v1", "stage": stage,
            "type": type(exc).__name__, "message": str(exc), "automatic_replay": False}
        fd = os.open(directory/"first-failure.json", os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as stream:
            json.dump(failure, stream, sort_keys=True);stream.flush();os.fsync(stream.fileno())
        raise


def test_artifact_v3_installed_sdk_fresh_root_six_calls_and_delivered_receipt():
    _run_artifact_v3_installed_snapshot_node_v1(unknown=False)


def test_artifact_v3_installed_sdk_unknown_observation_never_satisfies_or_sends():
    _run_artifact_v3_installed_snapshot_node_v1(unknown=True)

def test_artifact_v3_installed_sdk_live_core_binding_tamper_then_original_six_calls():
    """A separate fresh Root: actual Core gate diagnostics and exact Host binding refusals; not valid foreign grants."""
    _run_artifact_v3_installed_snapshot_node_v1(unknown=False, admission_negatives=True)

def test_artifact_v3_installed_sdk_two_fresh_roots_actual_foreign_objects_then_one_valid_admission():
    """Actual B originals and read-only signed snapshots; never synthetic foreign digests."""
    if os.environ.get("SYLANNE_ARTIFACT_V3_CROSS_ROOT_SETUP") is None:
        pytest.skip("requires explicit protected setup for two independent fresh V6/V9 installed Roots")
    if os.name != "posix" or os.geteuid() != 0:
        raise PermissionError("the two-Root forensic node requires the isolated Linux Root controller")
    sys.path.insert(0, "/opt/sylanne/code")
    from _runtime_bootstrap import load_canonical_runtime_v1
    load_canonical_runtime_v1(Path("/opt/sylanne/code"))
    from rewrite.host_tests.alpha1.artifact_v3_cross_root_witness_v1 import run_cross_root_node_v1
    run_cross_root_node_v1()



def _artifact_v3_owner_http_v1(session,action,namespace,inputs):
    """Use a real already signed dashboard Owner session; never mint a test session."""
    import urllib.parse,urllib.request
    from uuid import uuid4
    parsed=urllib.parse.urlsplit(session["base_url"])
    if (parsed.scheme!="http" or parsed.hostname not in {"127.0.0.1","localhost"}
            or parsed.username is not None or parsed.password is not None
            or parsed.path not in {"", "/"} or parsed.query or parsed.fragment):
        raise ValueError("the isolated fixture's actual local Workbench endpoint is required")
    operation=inputs.get("operation_id",str(uuid4()))
    payload={"schema_version":"d12.contract.v1","action":action,
        "scope":namespace["bot_id"]+"/"+namespace["persona_id"],
        "purpose":"workbench_user_action","audience":"owner","operation_id":operation,"input":inputs}
    from sylanne3.workbench_api.http_transport import COMMAND_ROUTE
    origin=parsed.scheme+"://"+parsed.netloc
    request=urllib.request.Request(origin+"/api/v1/plugins/extensions"+COMMAND_ROUTE,
        data=json.dumps(payload,separators=(",",":")).encode(),method="POST",
        headers={"Content-Type":"application/json","Cookie":session["cookie"],
            "X-CSRF-Token":session["csrf_token"],"Origin":origin})
    with urllib.request.urlopen(request,timeout=30)as response:
        result=json.load(response)
    if result.get("status")!="ready":raise ValueError("actual authenticated Owner command did not become ready")
    return result


def _artifact_v3_cancelled_job_source_gate_v1(probe):
    import ast
    root=Path("/opt/sylanne/code")
    manifest=json.loads((root/"release-manifest.json").read_bytes())
    result=probe.get("actual_acquire_result")or probe.get("result");error=probe.get("rejection")
    if result is not None and error is not None:
        raise ValueError("the original runner raised after its actual acquire refusal; preserve the production failure")
    if result is not None:
        if result!={"status":"original_execution_hold","job_id":probe["job_id"]}:
            raise ValueError("actual execution did not refuse the terminal child")
        rel="rewrite/sylanne3/runtime/d07_graph_stages_v1.py"
        message="original_execution_hold"
    else:
        if (error is None or error["type"]!="AuthorityUnavailable"or error["message"]not in {
                "Host exact original cognition job/cancel metadata changed",
                "D07 special parent current cycle/cancel/C02/activity/root budget changed"}):
            raise ValueError("the actual local rejection did not identify the cancellation binding")
        rel="rewrite/sylanne3/runtime/d07_stage_content_scope_v3.py";message=error["message"]
    callback=probe.get("actual_acquire_callback")
    if probe.get("actual_acquire_result")is not None:
        callback_rel="rewrite/sylanne3/runtime/d07_installed_execution_v1.py"
        callback_source=root/callback_rel
        callback_pin=next(row for row in manifest["source_inventory"]["files"]if row["path"]==callback_rel)
        if (Path(callback["file"]).resolve()!=callback_source.resolve()
                or hashlib.sha256(callback_source.read_bytes()).hexdigest()!=callback_pin["sha256"]):
            raise ValueError("actual acquire callback is not the installed original D07 worker caller")
        calls=[node for node in ast.walk(ast.parse(callback_source.read_bytes()))if isinstance(node,ast.Lambda)
            and node.lineno==callback["line"]and any(isinstance(item,ast.Attribute)
                and item.attr=="acquire_current_d07_execution_v1"for item in ast.walk(node))]
        if len(calls)!=1:raise ValueError("actual captured callback does not call the original acquire")
    source=root/rel;encoded=source.read_bytes()
    pin=next(row for row in manifest["source_inventory"]["files"]if row["path"]==rel)
    if hashlib.sha256(encoded).hexdigest()!=pin["sha256"]:
        raise ValueError("actual Host cancellation gate differs from installed source manifest")
    tree=ast.parse(encoded);matches=[]
    for node in ast.walk(tree):
        if result is not None and isinstance(node,ast.Return)and isinstance(node.value,ast.Dict):
            for key,value in zip(node.value.keys,node.value.values):
                if isinstance(key,ast.Constant)and key.value=="status"and isinstance(value,ast.Constant)and value.value==message:
                    matches.append(node.lineno)
        elif result is None and isinstance(node,ast.Raise)and isinstance(node.exc,ast.Call)and node.exc.args:
            if isinstance(node.exc.args[0],ast.Constant)and node.exc.args[0].value==message:matches.append(node.lineno)
    if len(matches)!=1:raise ValueError("the exact installed cancellation refusal branch is not unique")
    return {"layer":"Host/D11 terminal-job refusal","source_path":rel,"source_sha256":pin["sha256"],
        "line":matches[0],"reason":message,"core_admission_test":False}



def test_artifact_v3_installed_sdk_owner_stop_cancels_queued_d07_and_refuses_original_runner():
    """A separate fresh Root: actual Owner StopReply and the real queued child's W01 cancellation."""
    from concurrent.futures import ThreadPoolExecutor
    from uuid import uuid4
    location=os.environ.get("SYLANNE_ARTIFACT_V3_INSTALLED_SETUP")
    session_path=os.environ.get("SYLANNE_ARTIFACT_V3_OWNER_HTTP_SESSION")
    if location is None or session_path is None:
        pytest.skip("requires a separate fresh V9 Root plus a real signed current Workbench Owner HTTP session")
    if os.name!="posix"or os.geteuid()!=0:raise PermissionError("isolated fixture Root controller required")
    sys.path.insert(0,"/opt/sylanne/code")
    from _runtime_bootstrap import load_canonical_runtime_v1
    load_canonical_runtime_v1(Path("/opt/sylanne/code"))
    from sylanne3.authority_service.linux_installation_security_v1 import read_installed_bytes_v1
    from rewrite.tests.alpha1.integration.beta1_fixture_evidence_read_v3 import (
        backup_artifact_v3_fixture_graph_v1,verify_artifact_v3_fixture_snapshot_v1,
        verify_artifact_v3_queued_cancel_snapshot_v1)
    setup=json.loads(read_installed_bytes_v1(location,limit=65536))
    session=json.loads(read_installed_bytes_v1(session_path,limit=16384))
    if(set(session)!={"schema","base_url","cookie","csrf_token","installation_id","manifest_digest"}
            or session["schema"]!="sylanne.test.actual-owner-http-session.v1"
            or(session["installation_id"],session["manifest_digest"])!=(setup["installation_id"],setup["manifest_digest"])
            or setup["unknown_observation"]is not False or time.time()>=setup["original_deadline_utc"]):
        raise ValueError("actual current Owner HTTP session and separate unexpired successful V9 fixture required")
    assets=json.loads(read_installed_bytes_v1("/etc/sylanne/authority/assets.json"))
    if Path(setup["graph_path"])!=Path(assets["graph_db"]):
        raise ValueError("cancel node is not bound to this isolated fixture's actual Graph")
    directory=Path(setup["evidence_directory"]);directory.mkdir(mode=0o700,parents=False,exist_ok=False)
    stage="fresh_signed_baseline"
    try:
        before_health=_artifact_v3_fixture_rpc_v1("artifact_v3_checkpoint")
        if (before_health["local_model_requests"]or before_health["provider_network_requests"]
                or before_health["model_fixture_first_failure"]is not None):
            raise ValueError("cancel node cannot reuse an already exercised Root")
        baseline=directory/"baseline.sqlite3"
        baseline_pin=backup_artifact_v3_fixture_graph_v1(graph_path=setup["graph_path"],target=baseline)
        verify_artifact_v3_fixture_snapshot_v1(snapshot=baseline,setup=setup,baseline=True)
        armed=_artifact_v3_fixture_rpc_v1("artifact_v3_arm_cancelled_queued_job")
        if armed["state"]!="armed":raise ValueError("actual asynchronous D07 runner observer did not arm")
        stage="actual_queued_child_before_acquire"
        with ThreadPoolExecutor(max_workers=1)as pool:
            ingress=pool.submit(_artifact_v3_fixture_rpc_v1,"ordinary_ingress",
                message_id=setup["message_id"],text=setup["task_text"])
            end=min(time.monotonic()+90,time.monotonic()+setup["original_deadline_utc"]-time.time())
            while time.monotonic()<end:
                paused=_artifact_v3_fixture_rpc_v1("artifact_v3_cancelled_queued_job_status")
                if paused["state"]=="first_failure":raise ValueError(paused["first_failure"])
                if paused["state"]=="paused_queued_before_acquire":break
                time.sleep(.1)
            else:raise TimeoutError("actual first D07 never reached its real queued execution entry")
            if paused["deadline_utc"]-time.time()<10:raise TimeoutError("original deadline is too close for valid cancellation")
            prepared_snapshot=directory/"queued-before-stop.sqlite3"
            prepared_pin=backup_artifact_v3_fixture_graph_v1(graph_path=setup["graph_path"],target=prepared_snapshot)
            prepared=verify_artifact_v3_queued_cancel_snapshot_v1(snapshot=prepared_snapshot,setup=setup,job_id=paused["job_id"])
            stage="real_authenticated_owner_stop_reply"
            page=_artifact_v3_owner_http_v1(session,"read_reply_controls",prepared["namespace"],{})
            targets=[row for row in page["items"]if row["cycle_job_ref"]==paused["cycle_job_ref"]]
            if len(targets)!=1:raise ValueError("the signed prepared child is absent from the real Owner inventory")
            target=targets[0];operation=str(uuid4())
            request={"schema":"d12.owner-stop-reply-request.v1","namespace":target["namespace"],
                "installation_id":target["installation_id"],"operation_id":operation,
                "cycle_job_ref":target["cycle_job_ref"],"c02_operation_id":target["c02_operation_id"],
                "expected_cancel_generation":target["cancel_generation"]}
            control=_artifact_v3_owner_http_v1(session,"stop_reply",prepared["namespace"],request)["control"]
            stage="actual_W01_cancelled_child_snapshot"
            current=_artifact_v3_owner_http_v1(session,"read_reply_control_status",prepared["namespace"],
                {"original_ref":control["original_ref"]})["control"]
            snapshot=directory/"cancelled-child.sqlite3"
            pin=backup_artifact_v3_fixture_graph_v1(graph_path=setup["graph_path"],target=snapshot)
            cancelled=verify_artifact_v3_queued_cancel_snapshot_v1(snapshot=snapshot,setup=setup,
                job_id=paused["job_id"],stop_operation_id=operation,before=prepared)
            if time.time()>=paused["deadline_utc"]:raise TimeoutError("original deadline expired before runner release")
            stage="same_original_runner_after_actual_cancel"
            _artifact_v3_fixture_rpc_v1("artifact_v3_cancelled_queued_job_release")
            while time.time()<paused["deadline_utc"]:
                refusal=_artifact_v3_fixture_rpc_v1("artifact_v3_cancelled_queued_job_status")
                if refusal["state"]=="first_failure":raise ValueError(refusal["first_failure"])
                if refusal["state"]=="rejected_after_actual_cancel":break
                time.sleep(.1)
            else:raise TimeoutError("original runner refusal did not precede its original deadline")
            gate=_artifact_v3_cancelled_job_source_gate_v1(refusal)
            ingress.result(timeout=max(.001,paused["deadline_utc"]-time.time()))
        health=_artifact_v3_fixture_rpc_v1("artifact_v3_checkpoint")
        if(time.time()>=paused["deadline_utc"]or health["local_model_requests"]!=3
                or health["provider_network_requests"]or len(health["model_fixture_calls"])!=3
                or sum(row["fixture_charge_microusd"]for row in health["model_fixture_calls"])!=0
                or health["sender_calls"]!=before_health["sender_calls"]):
            raise ValueError("deadline/provider/cost/sender changed after actual child cancellation")
        final_snapshot=directory/"after-refused-runner.sqlite3"
        final_pin=backup_artifact_v3_fixture_graph_v1(graph_path=setup["graph_path"],target=final_snapshot)
        final=verify_artifact_v3_queued_cancel_snapshot_v1(snapshot=final_snapshot,setup=setup,
            job_id=paused["job_id"],stop_operation_id=operation,before=prepared)
        output={"status":"PASS","scope":"actual Owner StopReply/W01 queued D07 cancellation; Host/D11 refusal only",
            "core_admission_test":False,"baseline_snapshot_sha256":baseline_pin,
            "queued_snapshot_sha256":prepared_pin,"cancelled_snapshot_sha256":pin,
            "final_snapshot_sha256":final_pin,"prepared":prepared,"cancelled":cancelled,"final":final,
            "stop_control":control,"runner_refusal":refusal,"actual_source_gate":gate,
            "provider_call_delta":0,"fixture_charge_delta_microusd":0}
        fd=os.open(directory/"result.json",os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,"w")as stream:
            json.dump(output,stream,sort_keys=True);stream.flush();os.fsync(stream.fileno())
        return output
    except BaseException as error:
        failure={"status":"FAIL","stage":stage,"type":type(error).__name__,"message":str(error),"automatic_replay":False}
        fd=os.open(directory/"first-failure.json",os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,"w")as stream:
            json.dump(failure,stream,sort_keys=True);stream.flush();os.fsync(stream.fileno())
        raise
