"""Fixed initial policies, public Owner setup and read-only actual M1 originals."""
from datetime import datetime,timezone
import hashlib,json,sqlite3,time
from pathlib import Path

SCENARIO="sdk_m1_two_messages_v1"
REAL_ELAPSED_SCENARIO="sdk_a06_real_elapsed_phases_v1"
REAL_ELAPSED_PHASES=("day0","day4","day5")
FILENAME="m1-draft.txt"
EPISODES=(
    {"message_id":2718001,"task_text":"请把本次任务写入 m1-draft.txt，先生成第一版草稿，等我下一条修改意见后继续修订，完成第二版后这项任务才算完成。","intent_kind":"draft_then_corrected_revision","semantic_segment_count":1,"artifact_text":"第一版草稿：整理任务背景、当前结论与待修订事项。\n"},
    {"message_id":2718002,"task_text":"继续修改 m1-draft.txt：把第一版的待修订事项改为已核对的后续安排，保留原任务和同一文件，完成第二版。","intent_kind":"continue","semantic_segment_count":2,"artifact_text":"第二版草稿：整理任务背景、当前结论与已核对的后续安排。\n"},
)
ORDINARY_SCENARIO="sdk_ordinary_old_source_v1"
GREETING_SCENARIO="sdk_ordinary_greeting_v1"
D13_256_SCENARIO="sdk_d13_v6_256_current_v1"
D13_V7_256_SCENARIO="sdk_d13_v7_256_current_v1"
D13_256_EPISODES=tuple({"message_id":2720000+i,"task_text":f"第{i+1:03d}条记录：我把编号营灯{i+1:03d}的灯具放入第{i+1:03d}个柜子。","intent_kind":None,"semantic_segment_count":1,"artifact_text":""} for i in range(256))
ORDINARY_EPISODES=(
    {"message_id":2718101,"task_text":"我把编号炉灰九的野营炉子收进了绿色箱子，箱子在书桌左边。","intent_kind":None,"semantic_segment_count":1,"artifact_text":""},
    {"message_id":2718102,"task_text":"之前提到的编号炉灰九的野营炉子，我说收在哪个箱子里？","intent_kind":None,"semantic_segment_count":1,"artifact_text":""},
)
GREETING_EPISODES=(
    {"message_id":2718111,"task_text":"你好","intent_kind":None,"semantic_segment_count":1,"artifact_text":""},
    {"message_id":2718112,"task_text":"您好","intent_kind":None,"semantic_segment_count":1,"artifact_text":""},
)
REAL_ELAPSED_EPISODES=(
    EPISODES[0],
    {**EPISODES[1],"task_text":"继续修改同一个已保存的 m1-draft.txt 文件，保留原任务和项目，把已核验的上一版按以下新要求更新：将待修订事项改为已核对的后续安排，完成第二版。"},
    {"message_id":2718003,"task_text":"昨天修订的 m1-draft.txt 现在保存的是哪一版？请回忆当初先生成第一版草稿的任务，依据实际文件和原任务记录回答，不再创建或修改文件。","intent_kind":None,"semantic_segment_count":1,"artifact_text":""},
)


def real_elapsed_phase_gate_v1(directory,*,phase,package_sha256,manifest_sha256,approved_request_digest,valid_until_utc):
    """Observe a real elapsed boundary before starting a Host or submitting input."""
    if phase not in REAL_ELAPSED_PHASES:raise ValueError("unknown real elapsed SDK phase")
    directory=Path(directory);now=time.time();index=REAL_ELAPSED_PHASES.index(phase)
    target=directory/(phase+'-originals.json')
    if target.exists():
        from sylanne3.runtime_contracts import canonical_digest
        original=json.loads(target.read_text());digest=original.pop('receipt_digest')
        if canonical_digest(original)!=digest or (original['package_sha256'],original['manifest_sha256'],original['approved_request_digest'])!=(package_sha256,manifest_sha256,approved_request_digest):
            raise ValueError('stored real elapsed phase receipt identity differs')
        return {'status':'ALREADY_RECORDED','original':{**original,'receipt_digest':digest},'new_sdk_input_submitted':False}

    if index==0:
        if (directory/'day0-originals.json').exists():raise ValueError("day0 originals already exist; no replay")
        if valid_until_utc<=now+5*86400+300:
            return {'status':'HOLD','reason':'original_approved_root_does_not_cover_day5','new_sdk_input_submitted':False}
        return {'status':'READY','phase_index':0}
    day0=json.loads((directory/'day0-originals.json').read_text())
    if (day0['package_sha256'],day0['manifest_sha256'],day0['approved_request_digest'])!=(package_sha256,manifest_sha256,approved_request_digest):
        raise ValueError("cross-day continuation changed its original package/approval")
    previous=json.loads((directory/(REAL_ELAPSED_PHASES[index-1]+'-originals.json')).read_text())
    if previous['status']!='PHASE_COMPLETE':raise ValueError("prior real elapsed phase is not complete")
    minimum=96*3600 if index==1 else 24*3600
    learned=day0['source_learned_at'] if index==1 else previous['source_learned_at']
    from sylanne3.graph_types import AtomKey
    source_ref=previous['originals']['source_ref']
    namespace=previous['namespace'];source_id=AtomKey.from_token(source_ref).owner.subject
    graph=directory/'b04-durable-fixture/varlib/sylanne/genesis/graph/graph.sqlite3'
    with sqlite3.connect(graph.as_uri()+'?mode=ro',uri=True) as db:
        actual=db.execute("SELECT learned_at,message_id,bundle_digest FROM graph_first_ingress_identity_v1 "
            "WHERE bot=? AND persona=? AND source_ref=?",(namespace['bot_id'],namespace['persona_id'],source_id)).fetchone()
    if actual is None or actual[0]!=learned or actual[1]!=previous['originals']['ingress_identity']['message_id']:
        raise ValueError('phase elapsed receipt does not match actual installed Source learning original')
    elapsed=now-actual[0]
    if elapsed<minimum:
        return {'status':'WAITING','reason':'real_elapsed_boundary_not_reached','elapsed_seconds':elapsed,
            'required_seconds':minimum,'new_sdk_input_submitted':False,'clock_mode':'REAL_ELAPSED_SERVER_PHASES'}
    if now>=valid_until_utc:
        return {'status':'HOLD','reason':'original_approved_root_expired','new_sdk_input_submitted':False}
    return {'status':'READY','phase_index':index,'elapsed_seconds':elapsed}


def write_real_elapsed_phase_originals_v1(directory,phase,value):
    """Exclusive evidence receipt from actual producers; never mutates business SQL."""
    from sylanne3.runtime_contracts import canonical_digest
    target=Path(directory)/(phase+'-originals.json')
    payload={**value,'schema':'sylanne.sdk-real-elapsed-phase-originals.v1','phase':phase,
        'clock_mode':'REAL_ELAPSED_SERVER_PHASES','controlled_elapsed':False}
    payload['receipt_digest']=canonical_digest(payload)
    with target.open('x',encoding='utf-8') as stream:
        stream.write(json.dumps(payload,ensure_ascii=False,separators=(',',':')));stream.flush()
        __import__('os').fsync(stream.fileno())
    return payload


OWNER_CAPABILITIES=("workbench.read","workbench.create","workbench.diagnose","workbench.control","workbench.maintain",
    "workbench.activate","d02.body_policy.install","c04.cpu_policy.install")
OWNER_PURPOSES=("workbench_view","workbench_user_action","context","consolidation","proposal")



def approved_initial_request_v1(*, executable_sha256, valid_until_utc):
    """Fresh public local fixture input; never changes a previously signed grant."""
    from scripts.alpha1.install_linux import request_template_v4, check_request
    from rewrite.host_tests.alpha1.test_b04_installed_lifecycle_v1 import host_process_command_v3
    from sylanne3.runtime.d04_semantic_policy import MECHANISMS
    value = request_template_v4()
    value.update(profile_id="sdk-m1", bot_id="sdk-m1-bot", persona_id="sdk-m1-persona",
        host_uid=1000, host_gid=1000,
        astrbot_plugins_directory="/var/lib/sylanne-b04-host/data/plugins",
        authority_port=19653, reverse_port=19654, workbench_origin="https://localhost:19638",
        provider_id="sdk-m1-local", model_id="sdk-m1-finite-fixture",
        provider_config_path="/etc/sylanne-b04-fixture/provider.json",
        model_quote={"input_tokens":6000, "output_tokens":1024, "model_tokens":7024, "model_microusd":100},
        local_quote={"cpu_ms":1000, "thread_cpu_ms":1000},
        budget_limits={"input_tokens":48000, "output_tokens":8000, "model_tokens":56000,
            "model_microusd":1200, "cpu_ms":120000, "thread_cpu_ms":120000},
        budget_max_ceiling={"input_tokens":48000, "output_tokens":8000, "model_tokens":56000,
            "model_microusd":1200, "cpu_ms":120000, "thread_cpu_ms":60000},
        currency="USD", budget_valid_until_utc=valid_until_utc,
        onebot_account=["sdk-m1-local", "aiocqhttp", "100000001"],
        onebot_adapter_ref="sdk-m1-private-local", provider_cache={"provider_id":"sdk-m1-local"},
        host_process_command=host_process_command_v3("/opt/sylanne-runtime/bin/python3.12", executable_sha256),
        d04_joint_numeric={"version":3, "cpu_ceiling_ms":100000, "max_iterations":256,
            "tolerance":1e-8, "job_lifetime_seconds":600})
    value["d04_semantic_drive"].update(
        mechanism_max_abs_doses={name:[0.125,0.0625,0.03125] for name in MECHANISMS},
        mechanism_max_family_share={name:1.0 for name in MECHANISMS})
    # Namespace/account are replaced by the actual SDK probe before signing.
    # Foreground/artifact rights and billing public key are installed only then.
    return check_request(value)


def approved_initial_request_for_scenario_v1(*,executable_sha256,valid_until_utc,scenario=SCENARIO):
    if scenario==D13_V7_256_SCENARIO:
        if __package__:
            from .sdk_d13_v7_256_root_fixture_v1 import approved_sdk_d13_v7_256_initial_request_v1
        else:
            from sdk_d13_v7_256_root_fixture_v1 import approved_sdk_d13_v7_256_initial_request_v1
        return approved_sdk_d13_v7_256_initial_request_v1(executable_sha256=executable_sha256,valid_until_utc=valid_until_utc)
    if scenario==D13_256_SCENARIO:
        if __package__:
            from .sdk_d13_v6_256_root_fixture_v1 import approved_sdk_d13_v6_256_initial_request_v1
        else:
            from sdk_d13_v6_256_root_fixture_v1 import approved_sdk_d13_v6_256_initial_request_v1
        return approved_sdk_d13_v6_256_initial_request_v1(executable_sha256=executable_sha256,valid_until_utc=valid_until_utc)
    if scenario not in (SCENARIO,ORDINARY_SCENARIO,GREETING_SCENARIO,REAL_ELAPSED_SCENARIO,'sdk_m1_first_bubble_stop_v1','sdk_m1_first_bubble_unknown_v1'):
        raise ValueError('unknown finite SDK initial scenario')
    return approved_initial_request_v1(executable_sha256=executable_sha256,valid_until_utc=valid_until_utc)


def initial_install_request_v1(request,provider,identity,*,sender_id,scenario=SCENARIO):
    """Before any installer signing: exact actual SDK identity and finite policies."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    from sylanne3.runtime_contracts import canonical_digest
    from sylanne3.domains.d01.production_operations_v1 import plain_v1
    from sylanne3.host.authority_profile import installed_model_config_ref
    from sylanne3.host.authority_profile import (AdminModelWorkflowV2,AdminArtifactDraftPolicyV2,
        AdminArtifactDraftToolScopeV2,AdminArtifactDraftBodyPolicyV1,AdminArtifactStandingScopeV1,
        AdminForegroundPolicyV1,AdminForegroundDeadlinePolicyV1,AdminForegroundNaturalDeadlinePolicyV1)
    from sylanne3.model_broker.artifact_draft_v1 import TEMPLATE_VERSION,WORK_KIND
    from sylanne3.runtime.foreground_call_plan_v1 import SCHEMA
    from sylanne3.model_broker.natural_reply_history_v4 import TEMPLATE_VERSION_V5
    from sylanne3.model_broker.natural_review import REVIEW_TEMPLATE_VERSION_V2
    if request["schema"]!="sylanne3.linux-install-request.v4":raise ValueError("SDK M1 requires explicit installer v4")
    value=json.loads(json.dumps(request));now=time.time();until=value["budget_valid_until_utc"]
    if not now<until:raise ValueError("original approved installation budget expired")
    if scenario not in (D13_256_SCENARIO,D13_V7_256_SCENARIO) and (value["budget_limits"]["input_tokens"]>48000 or value["budget_limits"]["output_tokens"]>8000):
        raise ValueError("M1 initial budget exceeds its fixed input/output ceiling")
    if value["budget_max_ceiling"].get("thread_cpu_ms",0)<60000 or value["budget_limits"].get("thread_cpu_ms",0)<60000:
        raise ValueError("explicit initial root CPU budget is missing; do not enlarge the approved request")
    config_digest=canonical_digest(provider)
    if (provider["id"],provider["model"])!=(value["provider_id"],value["model_id"]):
        raise ValueError("actual SDK provider differs from initial M1 request")
    quote={**value["model_quote"],"input_tokens":6000,"output_tokens":1024,"model_tokens":7024}
    draft_quote={**quote,"input_tokens":10000,"model_tokens":11024}
    for chosen in (quote,draft_quote):
        if any(amount>min(value["budget_limits"].get(dim,0),value["budget_max_ceiling"].get(dim,0)) for dim,amount in chosen.items()):
            raise ValueError("explicit initial SDK M1 quote exceeds approved original budget")
    if quote["model_microusd"]<7:raise ValueError("initial simulated final charge exceeds approved ceiling")
    value["model_quote"]=quote
    if not 1<=quote["input_tokens"]<=10000 or not 1<=quote["output_tokens"]<=2000:
        raise ValueError("approved C4 quote is outside its actual finite contract")
    workflow=AdminModelWorkflowV2(work_kind=WORK_KIND,purpose="consolidation",template_version=TEMPLATE_VERSION,
        provider_id=value["provider_id"],model_id=value["model_id"],
        provider_config_ref=installed_model_config_ref(value["provider_id"],value["model_id"],config_digest),
        provider_config_digest=config_digest,audiences=tuple(value["model_audiences"]),privacy_tier="private",
        required_capabilities=("text",),timeout_seconds=120.0,max_output_tokens=draft_quote["output_tokens"],quote_ceiling=draft_quote)
    from sylanne3.host.astrbot import _canonical
    observed=identity["ingress_identity"]
    if (observed["visibility"]!="private" or observed["platform_ref"]!=_canonical(identity["platform_id"],identity["platform_name"],identity["self_id"])
            or observed["sender_ref"]!=_canonical(identity["platform_id"],str(sender_id))):
        raise ValueError("SDK M1 standing scope lacks its actual private ingress identity")
    standing=AdminArtifactStandingScopeV1("fixture:sdk-m1-standing",1,observed["platform_ref"],
        (observed["sender_ref"],),until,min(86400,max(1,int(until-now))),300,1,"project_worker",())
    file_cpu=min(100,value["budget_limits"].get("cpu_ms",0),value["budget_max_ceiling"].get("cpu_ms",0))
    if file_cpu<1:raise ValueError("approved file CPU budget absent")
    body=AdminArtifactDraftBodyPolicyV1("body-policy:sdk-m1-file",1,"body-effect:sdk-m1-file",1,file_cpu,"export")
    draft=AdminArtifactDraftPolicyV2(workflow,AdminArtifactDraftToolScopeV2("export",FILENAME,524288,32768,65536,300,2,
        ("create","replace_verified_predecessor")),body,None,standing)
    foreground=AdminForegroundPolicyV1("sylanne.foreground-policy.v1",1,SCHEMA,6,2,1,"fixture:sdk-m1-foreground",1,
        AdminForegroundDeadlinePolicyV1("sylanne.foreground-deadline-policy.v1",
            AdminForegroundNaturalDeadlinePolicyV1("bounded_causal_window_v1",300,"original_post_c02_cause_v1"),"signed_scope_intersection_v1"))
    private=Ed25519PrivateKey.generate()
    private_hex=private.private_bytes(serialization.Encoding.Raw,serialization.PrivateFormat.Raw,serialization.NoEncryption()).hex()
    public_hex=private.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw).hex()
    value.update(foreground=plain_v1(foreground),artifact_draft=plain_v1(draft),
        provider_billing_contract_v1={"contract_id":"fixture:sdk-m1-final-charge","contract_version":1,
            "provider_ed25519_public_key_hex":public_hex,"evidence_kind":"fixture_simulated_charge","currency":"USD","unit":"model_microusd"},
        natural_template_pair_v1={"schema":"sylanne3.initial-natural-template-pair.v1","generation":TEMPLATE_VERSION_V5,"review":REVIEW_TEMPLATE_VERSION_V2})
    config={"schema":"sylanne.sdk-m1-model-fixture.v1","provider_id":value["provider_id"],"model_id":value["model_id"],
        "provider_config_digest":config_digest,"billing_private_key_hex":private_hex,"filename":FILENAME,
        "max_episode_calls":6,"max_auxiliary_calls":2,"max_total_calls":12,"episodes":list(EPISODES)}
    if scenario in (ORDINARY_SCENARIO,GREETING_SCENARIO,D13_256_SCENARIO,D13_V7_256_SCENARIO,REAL_ELAPSED_SCENARIO):
        from sylanne3.host.authority_profile import AdminD06RecallPolicyV1,AdminD06RecallProfileV1
        from sylanne3.runtime.c04_interpretation_policy_v3 import installed_c04_presence_policy_v3
        from sylanne3.model_broker.d07_cognition_v1 import RECALL_TEMPLATE_VERSION_V1
        interpretation=installed_c04_presence_policy_v3()
        recall=AdminD06RecallPolicyV1("fixture:sdk-ordinary-recall",1,
            "body-policy:sdk-ordinary-c04",1,"body-policy:sdk-ordinary-c3",1,
            "cpu-policy:sdk-ordinary-c04",1,interpretation.policy_id,interpretation.policy_version,
            (AdminD06RecallProfileV1("light",1,32,128,0),AdminD06RecallProfileV1("normal",3,64,128,1),
             AdminD06RecallProfileV1("deep",4,64,128,2)),5,32,6,768,30.0,128,64,32,2048,16,4096)
        c3_quote={**quote,"output_tokens":min(1000,quote["output_tokens"]),
            "model_tokens":quote["input_tokens"]+min(1000,quote["output_tokens"])}
        c3=AdminModelWorkflowV2(work_kind="d07.cognition",purpose="proposal",template_version=RECALL_TEMPLATE_VERSION_V1,
            provider_id=workflow.provider_id,model_id=workflow.model_id,provider_config_ref=workflow.provider_config_ref,
            provider_config_digest=workflow.provider_config_digest,audiences=workflow.audiences,
            privacy_tier=workflow.privacy_tier,required_capabilities=workflow.required_capabilities,
            timeout_seconds=120.0,max_output_tokens=c3_quote["output_tokens"],quote_ceiling=c3_quote)
        value.update(d06_recall=plain_v1(recall),d07_cognition=plain_v1(c3))
        config.update(schema="sylanne.sdk-ordinary-recall-model-fixture.v1",
            episodes=list(D13_256_EPISODES if scenario in (D13_256_SCENARIO,D13_V7_256_SCENARIO) else GREETING_EPISODES if scenario==GREETING_SCENARIO else ORDINARY_EPISODES))
        if scenario==D13_V7_256_SCENARIO:
            from sylanne3.model_broker.natural_reply_history_v7 import TEMPLATE_VERSION as V7_TEMPLATE
            value['natural_template_pair_v1']['generation']=V7_TEMPLATE
            value['d13_paid_precompression']={'history_token_budget':1024,'quote_ceiling':dict(quote),
                'deadline_after_seconds':300,'max_slots':64,'resource_ref':'runtime:installation-model'}
            config.update(schema='sylanne.sdk-d13-v7-256-model-fixture.v1',max_total_calls=1536)
            if __package__:
                from .sdk_d13_v7_256_root_fixture_v1 import configure_initial_v7_counter_v1
            else:
                from sdk_d13_v7_256_root_fixture_v1 import configure_initial_v7_counter_v1
            configure_initial_v7_counter_v1(value,metric_source_path=Path(__file__).with_name('sdk_m1_model_fixture_v1.py'))
        if scenario==D13_256_SCENARIO:
            from sylanne3.model_broker.natural_reply_history_v6 import TEMPLATE_VERSION as V6_TEMPLATE
            value["natural_template_pair_v1"]["generation"]=V6_TEMPLATE
            value["d13_paid_precompression"]={"history_token_budget":1024,"quote_ceiling":dict(quote),"deadline_after_seconds":300,"max_slots":64,"resource_ref":"runtime:installation-model"}
            config.update(schema="sylanne.sdk-d13-v6-256-model-fixture.v1",max_total_calls=1536)
            from sylanne3.authority_service.d13_wire_evidence_v6 import WIRE_POLICY,TEMPLATE_DIGEST
            import os
            counter_private=Ed25519PrivateKey.generate()
            counter_path=Path('/etc/sylanne-b04-fixture/d13-counter-private.hex')
            descriptor=os.open(counter_path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
            with os.fdopen(descriptor,'w') as stream:
                stream.write(counter_private.private_bytes(serialization.Encoding.Raw,serialization.PrivateFormat.Raw,serialization.NoEncryption()).hex())
                stream.flush();os.fsync(stream.fileno())
            counter_program=Path('/opt/sylanne-b04-fixture/sdk_d13_v6_counter_fixture_v1.py')
            rule_digest=hashlib.sha256(counter_program.read_bytes()).hexdigest()
            counter_public=counter_private.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw).hex()
            value['d13_wire_counter']={'executable':str(counter_program),'executable_sha256':rule_digest,'timeout_seconds':60}
            value['d13_wire_policy']={'schema':'sylanne3.d13.installed-wire-policy.v6','installation':'$current_installation',
                'counter_public_key_hex':counter_public,'counter_policy_id':'fixture:sdk-d13-v6-http-byte-bound','counter_policy_version':1,
                'counter_policy_fingerprint':rule_digest,'tokenizer_fingerprint':rule_digest,'wire_policy_fingerprint':rule_digest,
                'context_limit_tokens':quote['model_tokens'],'tool_reserve_tokens':0,
                'uncached_input_microusd_per_million':1,'cache_write_input_microusd_per_million':1,
                'output_microusd_per_million':1,'storage_microusd_upper':0,'allow_conservative_switch':True,
                'max_slots':256,'max_blocks':4,'wire_policy_id':WIRE_POLICY,'template_digest':TEMPLATE_DIGEST}

    elif scenario!=SCENARIO:
        raise ValueError("unknown initial SDK fixture declaration")
    if scenario==REAL_ELAPSED_SCENARIO:
        config.update(schema="sylanne.sdk-real-elapsed-model-fixture.v1",episodes=list(REAL_ELAPSED_EPISODES),
            ledger_path="/var/lib/sylanne-b04-host/data/real-elapsed-model-ledger.sqlite3",phase_index=0,max_total_calls=18)
    return value,config


def _utc(value):return datetime.fromtimestamp(value,timezone.utc).isoformat().replace("+00:00","Z")


def owner_initialization_v1(command,*,profile,package_root,graph_path):
    """Initial choices only, all writes through existing public signed Owner commands."""
    from sylanne3.host.authority_profile import _policy_from_payload
    from sylanne3.runtime_contracts import canonical_digest
    from sylanne3.domains.d01.production_operations_v1 import plain_v1
    from sylanne3.host.installed_d04_root_resources import load_installed_d04_root_preset_v3
    from sylanne3.host.installed_d04_semantic_mapping_v3 import load_installed_d04_semantic_profile_v3
    from sylanne3.domains.d04.authored_lineage_v3 import AuthoredRootBlockInputV3,RootAuthoredFacetV3
    from sylanne3.domains.d12.types import character_draft_key
    from sylanne3.domains.d02 import BodyProfile,BodyState,WorkComponent
    from sylanne3.domains.d02.body_quote_original import FixedBodyPolicyV1
    from sylanne3.runtime.d02_production_operations_v1 import SettledBodyEffectPolicyV1
    from sylanne3.runtime.domain_production_inputs_v1 import InstallCurrentBodyInputRequestV1,InstallCurrentBodyEffectInputRequestV1
    from sylanne3.runtime.d11_artifact_draft_contract_v1 import WORK_KIND as FILE_WORK_KIND
    from sylanne3.domains.d02.resource_outcome_verifier import C04_INTERNAL_CPU_WORK_KIND
    from sylanne3.runtime.c04_cpu_quote_policy import C04InternalCpuQuotePolicyV1
    from sylanne3.host.installed_d06_build import ALGORITHM_ID_V3
    policy=_policy_from_payload(profile);ns=policy.namespace;until=policy.root_grant.valid_until_utc;receipts=[]
    def submit(action,values):
        result=command(action,values)
        if result.get("status")!="ready" or "receipt" not in result:
            raise ValueError("initial public Owner action refused: "+action)
        receipts.append({"action":action,"input_digest":canonical_digest(values),"receipt":result["receipt"]})
        return result["receipt"]
    preset=load_installed_d04_root_preset_v3(package_root,policy.manifest_digest)
    blocks=tuple(AuthoredRootBlockInputV3(RootAuthoredFacetV3("sdk-m1-block:"+str(i),template.template_id,template.kind,"sdk-m1-facet:"+str(i)),
        preset.axes,(.5,)*24,((.5,.5),)*24,"sdk-m1-box:"+str(i)) for i,template in enumerate(preset.block_templates))
    submit("d04_root_draft",{"root_field":{"candidate_id":"sdk-m1-owner-initial","cursor":0.0,
        "preset_digest":preset.digest,"asset_digest":preset.assets.digest,"blocks":[plain_v1(b) for b in blocks]}})
    submit("d04_root_budget",{"parent_budget_lease_ref":policy.root_grant.lease_id,"ceiling":{"thread_cpu_ms":60000}})
    compiled=submit("compile_scheme",{"draft_ref":character_draft_key(ns).token,"budget_ref":policy.root_grant.lease_id})
    root=submit("activate_scheme",{"compiled_digest":compiled["compiled_digest"]})
    submit("d04_root_coupling",{"root_operation_id":root["operation_id"],"effective_until":86400.0})
    mapping=load_installed_d04_semantic_profile_v3(package_root,policy.manifest_digest)
    submit("d04_semantic_mapping",{"profile_digest":mapping.profile_digest,"expected_revision":0})
    now=time.time()
    submit("d11_role_clock",{"expected_version":0,"character_origin":"0","rate":"1","wall_origin_utc":_utc(now),
        "valid_from_utc":_utc(now),"valid_until_utc":_utc(until)})
    with sqlite3.connect(Path(graph_path).as_uri()+"?mode=ro",uri=True) as db:
        rows=db.execute("SELECT value FROM graph_atoms WHERE bot=? AND persona=? AND type_name='d03.role_binding' AND valid=1 ORDER BY token LIMIT 129",ns.as_tuple).fetchall()
        if len(rows)>128:raise ValueError("initial role catalogue exceeds bounded inventory")
        active=[json.loads(row[0]) for row in rows if json.loads(row[0])["status"]=="active"]
    roles=sorted({"project_worker",*(v["social_role"] for v in active)})
    norms=sorted({n for v in active for n in v["norm_refs"]})
    submit("d03_context_catalogue",{"roles":roles,"norms":norms,"budget_ref":policy.root_grant.lease_id})
    configured=profile["artifact_draft"]["body_policy"]
    body_profile=BodyProfile("body:sdk-m1-file",ns,1,("energy","fatigue","load"),(FILE_WORK_KIND,))
    body=FixedBodyPolicyV1(configured["policy_ref"],configured["policy_version"],body_profile,
        BodyState(body_profile.profile_id,1,.8,{FILE_WORK_KIND:.1},.1,0.0),FILE_WORK_KIND,WorkComponent("sdk-m1-file","body-energy",.02,0.0),until)
    def producer(kind,request):
        return submit("domain_input_"+kind,{"activity_id":"sdk-m1-initial:"+kind,"audience_ref":"owner",
            "parent_budget_lease_ref":policy.root_grant.lease_id,"request":plain_v1(request)})
    producer("initialize_body",InstallCurrentBodyInputRequestV1(body))
    effect=SettledBodyEffectPolicyV1(configured["effect_component_policy_ref"],configured["effect_component_policy_version"],
        ns,body_profile.profile_id,FILE_WORK_KIND,body.component.component_id,.01,.005)
    producer("install_body_effect_policy",InstallCurrentBodyEffectInputRequestV1(effect))
    c04_profile=BodyProfile("body:sdk-m1-c04",ns,1,("energy",),(C04_INTERNAL_CPU_WORK_KIND,))
    c04_body=FixedBodyPolicyV1("body-policy:sdk-m1-c04",1,c04_profile,BodyState(c04_profile.profile_id,1,.8,{"cognition":0.0},0.0,0.0),
        C04_INTERNAL_CPU_WORK_KIND,WorkComponent("sdk-m1-c04","cognition",.1),until)
    submit("d02_fixed_work_policy",{"policy":plain_v1(c04_body)})
    cpu=min(1000,dict(policy.root_grant.max_ceiling).get("cpu_ms",0))
    if cpu<1:raise ValueError("approved C04 CPU quote missing")
    submit("c04_cpu_policy",{"policy":plain_v1(C04InternalCpuQuotePolicyV1("cpu-policy:sdk-m1-c04",1,ns,policy.installation_id,ALGORITHM_ID_V3,cpu,until))})
    if "d06_recall" in profile:
        from sylanne3.host.authority_profile import d06_recall_policy_from_payload_v1
        from sylanne3.runtime.c04_direct_seed_v4 import ALGORITHM_ID_V4
        recall=d06_recall_policy_from_payload_v1(profile["d06_recall"])
        c3_profile=BodyProfile("body:sdk-ordinary-c3",ns,1,("energy",),("d07.cognition",))
        c3=FixedBodyPolicyV1(recall.cognition_body_policy_id,recall.cognition_body_policy_version,
            c3_profile,BodyState(c3_profile.profile_id,1,.8,{"d07.cognition":.1},.1,0.0),
            "d07.cognition",WorkComponent("sdk-ordinary-c3","body-energy",.0625,0.0),until)
        submit("d02_fixed_work_policy",{"policy":plain_v1(c3)})
        c04=FixedBodyPolicyV1(recall.body_policy_id,recall.body_policy_version,c04_profile,
            c04_body.initial_state,C04_INTERNAL_CPU_WORK_KIND,c04_body.component,until)
        submit("d02_fixed_work_policy",{"policy":plain_v1(c04)})
        submit("c04_cpu_policy",{"policy":plain_v1(C04InternalCpuQuotePolicyV1(recall.cpu_policy_id,
            recall.cpu_policy_version,ns,policy.installation_id,ALGORITHM_ID_V4,cpu,until))})
    if profile['model_workflows']['version']==7:
        from sylanne3.runtime.d13_counter_cpu_quote_policy_v1 import D13CounterCpuQuotePolicyV1,D13_COUNTER_CPU_WORK_KIND
        counter_profile=BodyProfile("body:sdk-d13-v7-counter",ns,1,("energy",),(D13_COUNTER_CPU_WORK_KIND,))
        counter_body=FixedBodyPolicyV1("body-policy:sdk-d13-v7-counter",1,counter_profile,
            BodyState(counter_profile.profile_id,1,.8,{D13_COUNTER_CPU_WORK_KIND:.1},.1,0.0),
            D13_COUNTER_CPU_WORK_KIND,WorkComponent("sdk-d13-v7-counter","body-energy",.02,0.0),until)
        submit("d02_fixed_work_policy",{"policy":plain_v1(counter_body)})
        submit("d13_counter_cpu_policy",{"policy":plain_v1(D13CounterCpuQuotePolicyV1(
            "cpu-policy:sdk-d13-v7-counter",1,ns,policy.installation_id,D13_COUNTER_CPU_WORK_KIND,1000,until))})
    return receipts


def actual_episode_originals_v1(*,graph_path,namespace,episode,expected_phase,expected_version,interruption=None,cumulative_sender_count=None):
    """Read actual immutable rows and file bytes; never manufacture business records."""
    from sylanne3.runtime_contracts import canonical_digest,canonical_serialize
    from sylanne3.contracts import canonical_json
    from sylanne3.domains.d01.production_operations_v1 import plain_v1
    from sylanne3.runtime.d11_life_contract_v1 import life_from_wire_v1,D11LifeTerminalV1
    from sylanne3.runtime.d11_life_preparation_v1 import life_prepared_from_wire_v1
    from sylanne3.runtime.d11_life_adoption_v1 import require_draft_terminal_readback_v1
    from sylanne3.runtime.natural_reply_job_v2 import read_original_preparation
    from sylanne3.domains.d10.project_checkpoint_v1 import project_checkpoint_key_v1
    with sqlite3.connect(Path(graph_path).as_uri()+"?mode=ro",uri=True) as db:
        db.execute("BEGIN")
        rows=db.execute("SELECT original_ref,payload_json FROM graph_d11_life_originals_v1 WHERE bot=? AND persona=? AND kind='c1_task_intent' AND json_extract(payload_json,'$.intent.kind')=? ORDER BY original_ref LIMIT 129",(*namespace.as_tuple,episode["intent_kind"])).fetchall()
        if len(rows)>128:raise ValueError("M1 intent inventory bound exceeded")
        selected=[]
        for ref,encoded in rows:
            value=json.loads(encoded);source=db.execute("SELECT value,valid FROM graph_atoms WHERE token=? AND bot=? AND persona=?",(value["source_ref"],*namespace.as_tuple)).fetchone()
            if source is not None and source[1]==1 and json.loads(source[0])["text"]==episode["task_text"]:selected.append((ref,value))
        if not selected:return None
        if len(selected)!=1:raise ValueError("M1 SDK message produced conflicting C1 task originals")
        intent_ref,intent=selected[0];c02=intent["c02_operation_id"]
        from sylanne3.graph_types import AtomKey
        from sylanne3.runtime.ingress_observation import read_committed_ingress_identity
        source_key=AtomKey.from_token(intent["source_ref"])
        ingress=read_committed_ingress_identity(db,namespace,source_key.owner.subject)
        if ingress is None:raise ValueError("actual SDK ingress identity original is missing")
        ingress_identity=json.loads(ingress.identity_json)
        if ingress_identity["message_id"]!=str(episode["message_id"]) or ingress_identity["visibility"]!="private":
            raise ValueError("actual SDK message identity does not join its original Source/C1/C02")
        scopes=db.execute("SELECT payload_json FROM graph_d11_life_originals_v1 WHERE bot=? AND persona=? AND kind='artifact_task_scope' AND json_extract(payload_json,'$.c02_operation_id')=?",(*namespace.as_tuple,c02)).fetchall()
        if not scopes:return None
        if len(scopes)!=1:raise ValueError("M1 message has conflicting task scopes")
        scope=json.loads(scopes[0][0])
        continuation=scope.get('continuation_authorization')
        if continuation is not None:
            from sylanne3.runtime.artifact_task_continuation_authorization_v2 import require_continuation_authorization_history_v2
            row=db.execute("SELECT producing_operation_id,payload_json,payload_digest,signature FROM graph_d11_life_originals_v1 "
                "WHERE bot=? AND persona=? AND kind='artifact_task_continuation_authorization_v2' AND original_ref=?",
                (*namespace.as_tuple,continuation['authorization_id'])).fetchone()
            if row is None or json.loads(row[1])!=continuation or canonical_digest(continuation)!=row[2] or not row[3]:
                raise ValueError('continued SDK task has no matching signed original authorization')
            require_continuation_authorization_history_v2(db,namespace=namespace,original_ref=continuation['authorization_id'],
                producing_operation_id=row[0],raw=continuation)
        objective_row=db.execute("SELECT payload_json FROM graph_d11_life_originals_v1 WHERE bot=? AND persona=? AND kind='artifact_task_objective' AND original_ref=?",(*namespace.as_tuple,scope["objective_ref"])).fetchone()
        if objective_row is None:raise ValueError("actual initial objective lost")
        objective=json.loads(objective_row[0]);goal=db.execute("SELECT value,valid FROM graph_atoms WHERE token=?",(objective["goal_ref"],)).fetchone()
        if goal is None or goal[1]!=1:return None
        plan=db.execute("SELECT value,valid FROM graph_atoms WHERE token=?",(objective["plan_ref"],)).fetchone()
        checkpoint=db.execute("SELECT value,valid FROM graph_atoms WHERE token=?",(project_checkpoint_key_v1(namespace,objective["project_ref"]).token,)).fetchone()
        if plan is None or checkpoint is None or plan[1]!=1 or checkpoint[1]!=1:return None
        goal,plan,checkpoint=map(lambda row:json.loads(row[0]),(goal,plan,checkpoint))
        if (goal["state"],plan["state"],checkpoint["state"])!=(("active","waiting","waiting") if expected_phase=="partial" else ("satisfied","satisfied","completed")):return None
        if len(checkpoint["work_version_refs"])!=expected_version:raise ValueError("wrong actual work count")
        works=[];originals=[]
        for ref in checkpoint["work_version_refs"]:
            row=db.execute("SELECT value,valid FROM graph_atoms WHERE token=?",(ref,)).fetchone()
            if row is None or row[1]!=1:raise ValueError("actual work original unavailable")
            work=json.loads(row[0]);works.append(work)
            adopted_row=db.execute("SELECT producing_operation_id,payload_json,payload_digest,signature FROM graph_d11_life_originals_v1 WHERE bot=? AND persona=? AND kind='adopted_life' AND original_ref=?",(*namespace.as_tuple,work["artifact_ref"])).fetchone()
            if adopted_row is None:raise ValueError("actual signed file adoption missing")
            adopted=json.loads(adopted_row[1]);assert canonical_serialize(adopted)==adopted_row[1] and canonical_digest(adopted)==adopted_row[2]
            terminal=life_from_wire_v1(adopted["terminal"],D11LifeTerminalV1)
            prepared_row=db.execute("SELECT payload_json,payload_digest,signature FROM graph_d11_life_originals_v1 WHERE bot=? AND persona=? AND kind='prepared' AND original_ref=?",(*namespace.as_tuple,terminal.binding.prepared_original_ref)).fetchone()
            if prepared_row is None:raise ValueError("actual signed file preparation missing")
            prepared=life_prepared_from_wire_v1(json.loads(prepared_row[0]));witness=require_draft_terminal_readback_v1(prepared=prepared,terminal=terminal)
            producer=db.execute("SELECT commit_seq,receipt_json FROM graph_bundle_operations WHERE bot=? AND persona=? AND operation_id=?",(*namespace.as_tuple,adopted_row[0])).fetchone()
            if producer is None:raise ValueError("file adoption has no actual shared Graph receipt")
            producer_receipt=json.loads(producer[1])
            if canonical_json(producer_receipt)!=producer[1] or producer_receipt["commit_seq"]!=producer[0]:
                raise ValueError("file adoption shared Graph commit metadata differs")
            history=db.execute("SELECT value,valid FROM graph_history WHERE token=? AND event_bot=? AND event_persona=? AND event_id=? ORDER BY revision DESC LIMIT 1",
                (ref,*namespace.as_tuple,adopted_row[0])).fetchone()
            if history is None or history[1]!=1 or json.loads(history[0])!=work:
                raise ValueError("work original is not an actual write of its named adoption commit")
            originals.append({"work_ref":ref,"work":work,"adoption":adopted,"adoption_signature":adopted_row[3],
                "prepared":json.loads(prepared_row[0]),"prepared_signature":prepared_row[2],"producer_receipt_digest":canonical_digest(producer_receipt),"readback":plain_v1(witness)})
        works.sort(key=lambda v:v["version"]);assert tuple(v["version"] for v in works)==tuple(range(1,expected_version+1))
        assert len({v["work_ref"] for v in works})==1
        current=max(originals,key=lambda v:v["work"]["version"]);physical=Path('/var/lib/sylanne/export')/FILENAME
        payload=physical.read_bytes();st=physical.stat();witness=current["readback"]
        assert (hashlib.sha256(payload).hexdigest(),len(payload),st.st_dev,st.st_ino)==(witness["content_digest"],witness["content_length"],witness["file_identity"]["device"],witness["file_identity"]["file_id"])
        assert payload==episode["artifact_text"].encode()
        from sylanne3.model_broker.artifact_draft_v1 import artifact_draft_task_selector_v1,artifact_draft_model_ids_v1
        selector=artifact_draft_task_selector_v1(namespace,c02_operation_id=c02,root_registration_ref=scope["root"]["registration_ref"])
        ids=artifact_draft_model_ids_v1(selector);c4={}
        for kind,key in (("c4_frozen","frozen"),("c4_prepared","job"),("c4_request","request"),("c4_result","result"),("c4_paid","paid"),("c4_adopted","adopt"),("c4_call","call")):
            row=db.execute("SELECT producing_operation_id,payload_json,payload_digest,signature FROM graph_d11_life_originals_v1 WHERE bot=? AND persona=? AND kind=? AND original_ref=?",(*namespace.as_tuple,kind,ids[key])).fetchone()
            if row is None:raise ValueError("completed file lost actual "+kind+" original")
            value=json.loads(row[1]);assert canonical_serialize(value)==row[1] and canonical_digest(value)==row[2]
            c4[kind]={"original_ref":ids[key],"producing_operation_id":row[0],"value":value,"digest":row[2],"signature":row[3]}
        natural=[];child_identities=()
        for stage in ("generation","review"):
            saved=read_original_preparation(db,namespace,c02,stage)
            if saved is None or saved.state!="terminal":return None
            if stage=="generation":
                generation_saved=saved
                question=saved.frozen.input.question
                if (saved.seal.c02_operation_id,saved.seal.source_ref,question.text)!=(c02,intent["source_ref"],episode["task_text"]):
                    raise ValueError("actual natural generation belongs to another SDK source")
                refs=(question.ref,*question.dependencies)
                if not any(v.ref==intent["source_ref"] and v.version==intent["source_revision"] for v in refs):
                    raise ValueError("actual natural question has no pinned original Source dependency")
            else:
                if saved.seal.generation_call_id!=natural[0]["call_id"]:
                    raise ValueError("actual review belongs to another protected generation")
                from sylanne3.domains.d09.natural_reply import natural_semantic_ranges_v3,natural_segment_identity_v3
                data=json.loads(saved.frozen.canonical_input)
                output={"schema":data["generation_output_schema"],"body":data["body"],
                    "units":data["units"],"semantic_segments":data["semantic_segments"]}
                if (canonical_digest(output)!=generation_saved.terminal_output_digest
                        or len(natural_semantic_ranges_v3(output))!=episode["semantic_segment_count"]):
                    raise ValueError("actual paid review does not preserve the finite wholemanifest")
                child_identities=tuple(natural_segment_identity_v3(generation_saved.frozen.input.plan,output,index)[:2]
                    for index in range(episode["semantic_segment_count"]))
            reserve=db.execute("SELECT state,actual_json FROM runtime_budget_reservations WHERE lease_id=? AND operation_id=?",(saved.seal.parent_budget_lease_id,saved.seal.reservation_operation_id)).fetchone()
            if reserve is None or reserve[0]!="settled" or reserve[1] is None:return None
            actual=json.loads(reserve[1])
            if type(actual.get("model_microusd")) is not int or actual["model_microusd"]<0:return None
            if db.execute("SELECT count(*) FROM runtime_budget_operations WHERE bot_id=? AND persona_id=? AND lease_id=? AND operation_id=? AND phase='settle'",
                    (*namespace.as_tuple,saved.seal.parent_budget_lease_id,saved.seal.reservation_operation_id)).fetchone()!=(1,):
                raise ValueError("protected stage lacks exact once settlement")
            natural.append({"stage":stage,"call_id":saved.seal.call_id,"terminal_receipt_digest":saved.terminal_receipt_digest,"actual":json.loads(reserve[1])})
        outbound=db.execute("SELECT observation_json,original_json,original_digest FROM graph_d13_outbound_observations_v1 WHERE bot=? AND persona=? ORDER BY final_operation_id LIMIT 9",namespace.as_tuple).fetchall()
        expected_outbound=(sum(item["semantic_segment_count"] for item in EPISODES[:expected_version])
            if cumulative_sender_count is None else cumulative_sender_count)
        if interruption is None:
            if len(outbound)<expected_outbound:return None
            if len(outbound)!=expected_outbound:raise ValueError("M1 unexpected actual outbound adoption count")
        elif interruption not in {"stop","unknown"} or expected_version!=2 or len(outbound)>expected_outbound-1:
            raise ValueError("M1 interrupted episode crossed its fixed actual sender boundary")
        outbound_originals=[];episode_children={}
        for observed,original,digest in outbound:
            observation=json.loads(observed);stored=json.loads(original)
            if observation["pending"]["platform_observation"]["outcome"] not in ({"accepted","delivered","unknown"} if interruption else {"accepted","delivered"}):raise ValueError("M1 outbound original remains unknown")
            assert canonical_digest(stored)==digest
            origin=observation["pending"]["platform_observation"]["binding"]["origin"]
            pair=(origin["operation_id"],origin["effect_id"])
            if pair in child_identities:
                if pair in episode_children:raise ValueError("M1 child has duplicate actual outbound adoption")
                episode_children[pair]=digest
            outbound_originals.append({"observation":observation,"original":stored,"original_digest":digest})
        if interruption is None and set(episode_children)!=set(child_identities):
            raise ValueError("M1 actual outbound originals do not cover each exact semantic child")
        return {"schema":"sylanne.sdk-m1-actual-episode.v1","c02_operation_id":c02,"source_ref":intent["source_ref"],
            "ingress_identity":{name:ingress_identity[name] for name in ("message_id","platform_ref","sender_ref","visibility")},
            "source_learned_at":ingress.learned_at,"intent_ref":intent_ref,"intent":intent,"task_scope":scope,"objective":objective,"goal":goal,"plan":plan,
            "checkpoint":checkpoint,"work_originals":originals,"c4_originals":c4,"natural":natural,"outbound_originals":outbound_originals,
            "semantic_child_originals":[{"operation_id":op,"effect_id":effect,"outbound_original_digest":digest} for (op,effect),digest in episode_children.items()],
            "interruption":interruption,
            "read_scope":"readonly actual installed SQL originals and physical bytes; no reissued signatures"}



def actual_ordinary_episode_originals_v1(db,*,namespace,episode,issuer,previous_source_ref=None,required_artifact_refs=()):
    """Actual Host-worker readonly proof; all rows precede this fixture collector."""
    from sylanne3.graph_types import AtomKey
    from sylanne3.runtime_contracts import canonical_digest,canonical_serialize
    from sylanne3.runtime.ingress_observation import read_committed_ingress_identity
    from sylanne3.runtime.jobs import get_job
    from sylanne3.runtime.d11_types import job_graph_write
    from sylanne3.runtime.foreground_cycle_v1 import foreground_cycle_from_wire_v1
    from sylanne3.runtime.domain_production_originals_v1 import read_adopted_domain_operation_v1
    from sylanne3.runtime.d07_ingress_recall_result_v1 import read_adopted_ingress_recall_routing_v1
    from sylanne3.runtime.d07_ingress_recall_preparation_v1 import ingress_recall_model_ids_v1
    from sylanne3.runtime.d07_execution_v1 import read_prepared_d07_execution_v1,read_d07_original_v1
    from sylanne3.runtime.d06_ingress_c03_selection_v1 import read_adopted_ingress_c03_selection_v1
    from sylanne3.runtime.c04_self_scope_v4 import ingress_c04_ids_v4
    from sylanne3.runtime.c04_v3_contracts import C04AdoptionPlanV3,C04AdoptionReceiptV3
    from sylanne3.runtime.natural_reply_job_v2 import read_original_preparation
    if not db.in_transaction:raise ValueError("ordinary SDK proof requires actual worker readonly transaction")
    sources=db.execute("SELECT token,value,revision FROM graph_atoms WHERE bot=? AND persona=? AND type_name='memory.source' "
        "AND valid=1 AND json_extract(value,'$.text')=? ORDER BY token LIMIT 2",(*namespace.as_tuple,episode['task_text'])).fetchall()
    if not sources:return None
    if len(sources)!=1:raise ValueError("ordinary SDK input has conflicting actual Source originals")
    source_ref,source_json,source_revision=sources[0]
    identity=read_committed_ingress_identity(db,namespace,AtomKey.from_token(source_ref).owner.subject)
    if identity is None:return None
    ingress_identity=json.loads(identity.identity_json)
    if ingress_identity['message_id']!=str(episode['message_id']):raise ValueError("ordinary Source lacks actual SDK ingress identity")
    parents=db.execute("SELECT token,value FROM graph_atoms WHERE bot=? AND persona=? AND type_name='runtime.job' "
        "AND valid=1 AND json_extract(value,'$.continuation.source_ref')=? ORDER BY token LIMIT 2",(*namespace.as_tuple,source_ref)).fetchall()
    if not parents:return None
    if len(parents)!=1:raise ValueError("ordinary input has conflicting foreground cycles")
    parent_ref,parent_json=parents[0];parent=get_job(db,AtomKey.from_token(parent_ref).name)
    if job_graph_write(parent).value!=json.loads(parent_json):raise ValueError("actual foreground SQL/Graph differs")
    cycle=foreground_cycle_from_wire_v1(parent.continuation);c02=cycle.c02_operation_id
    c02row=db.execute("SELECT receipt_json FROM graph_bundle_operations WHERE bot=? AND persona=? AND operation_id=?",(*namespace.as_tuple,c02)).fetchone()
    if c02row is None:return None
    c02receipt=json.loads(c02row[0])
    c02writes=db.execute("SELECT token FROM graph_history WHERE event_bot=? AND event_persona=? AND event_id=? ORDER BY token",
        (*namespace.as_tuple,c02)).fetchall()
    if ('first_ingress_c02' not in c02receipt or not {'memory.episode.v1','memory.subjective_trace.v2'}<=
            {AtomKey.from_token(row[0]).type_name for row in c02writes}):
        raise ValueError("ordinary C02 did not adopt actual episode/subjective originals")
    routing=read_adopted_ingress_recall_routing_v1(db,namespace=namespace,c02_operation_id=c02,issuer=issuer)
    if routing is None:return None
    ids=ingress_recall_model_ids_v1(namespace,c02);prepared=read_prepared_d07_execution_v1(db,issuer,namespace,ids['job'])
    paid=read_d07_original_v1(db,issuer,namespace,'paid_cost',prepared.job_id)
    terminal=read_d07_original_v1(db,issuer,namespace,'execution','d07-terminal:'+prepared.call_id)
    if paid is None or terminal is None:return None
    if paid[0]['paid'] is not True or paid[0]['unknown_dimensions']:raise ValueError("ordinary C3 has unknown paid model usage")
    native=None
    if previous_source_ref is None:
        if routing['stop_reason']!='no_history_needed':raise ValueError("first finite ordinary event unexpected routing")
    else:
        if routing['stop_reason']!='search_required':raise ValueError("normal related input did not request recall")
        selected=read_adopted_ingress_c03_selection_v1(db,namespace=namespace,c02_operation_id=c02)
        if selected is None:return None
        selection,original,bridge=selected
        if selection.selected_source_ref!=previous_source_ref or selection.selected_source_ref==source_ref:
            raise ValueError("actual C03 did not select the actual previous ingress Source")
        c04=ingress_c04_ids_v4(namespace,c02,original['original_digest'])
        adoption=read_adopted_domain_operation_v1(db,namespace,c04['adopt'])
        if adoption is None:return None
        if adoption['operation_kind']!='adopt_ingress_c04_v1' or adoption['payload']['provenance']['schema']!='c04.self-foreground-adoption.v4':
            raise ValueError("ordinary recall lacks its actual Self C04 adoption original")
        planrow=db.execute("SELECT plan_json,receipt_json FROM graph_c04_adoptions_v3 WHERE bot=? AND persona=? AND operation_id=?",
            (*namespace.as_tuple,c04['adopt'])).fetchone()
        if planrow is None:return None
        plan=C04AdoptionPlanV3.from_json(planrow[0]);receipt=C04AdoptionReceiptV3.from_json(planrow[1]);receipt.validate_plan(plan)
        native={'selection_ref':original['original_ref'],'selected_source_ref':selection.selected_source_ref,
            'selection_original_digest':original['original_digest'],'metadata_bridge':bridge,
            'adoption_operation_id':c04['adopt'],'plan_digest':plan.plan_digest,
            'terminal_receipt_digest':plan.terminal_receipt_digest,'cpu_settlement_digest':plan.d11_settlement_digest,
            'recollection_roots':[w.ref for w in plan.writes if AtomKey.from_token(w.ref).type_name=='d06.recollection.v1']}
        if not native['recollection_roots']:raise ValueError("C04 produced no actual recollection root")
    generation=read_original_preparation(db,namespace,c02,'generation');review=read_original_preparation(db,namespace,c02,'review')
    if generation is None or review is None:return None
    if generation.seal.source_ref!=source_ref or review.seal.c02_operation_id!=c02:raise ValueError("reply changed the ordinary ingress root")
    frozen=json.loads(generation.frozen.canonical_wire)
    if native is not None:
        def contains(value,ref):
            if type(value) is dict:return any(contains(child,ref) for child in value.values())
            if type(value) is list:return any(contains(child,ref) for child in value)
            return value==ref
        # Exact declared recollection root must occur in the actual paid frozen input.
        joined=[ref for ref in native['recollection_roots'] if contains(frozen,ref)]
        if not joined:raise ValueError("actual natural frozen reply omitted adopted oldSource recollection root")
    if required_artifact_refs:
        def qualified_blocks(value):
            if type(value) is dict:
                for key,child in value.items():
                    if key=='qualified_units':yield child
                    else:yield from qualified_blocks(child)
            elif type(value) is list:
                for child in value:yield from qualified_blocks(child)
        actual_units=tuple(qualified_blocks(frozen))
        if not actual_units or not any(contains(units,ref) for units in actual_units for ref in required_artifact_refs):
            raise ValueError('day5 actual paid reply lacks current artifact/readback qualification; fixture readback is not production knowledge')
    if generation.terminal_receipt_digest is None or review.terminal_receipt_digest is None:return None
    paid_reply=[]
    for saved in (generation,review):
        row=db.execute("SELECT state,actual_json FROM runtime_budget_reservations WHERE lease_id=? AND operation_id=?",
            (saved.seal.parent_budget_lease_id,saved.seal.reservation_operation_id)).fetchone()
        if row is None or row[0]!='settled' or row[1] is None:return None
        if db.execute("SELECT count(*) FROM runtime_budget_operations WHERE bot_id=? AND persona_id=? AND lease_id=? "
                "AND operation_id=? AND phase='settle'",(*namespace.as_tuple,saved.seal.parent_budget_lease_id,
                saved.seal.reservation_operation_id)).fetchone()!=(1,):raise ValueError("ordinary reply stage settled twice")
        paid_reply.append({'call_id':saved.seal.call_id,'terminal_receipt_digest':saved.terminal_receipt_digest,
            'actual_usage':json.loads(row[1])})
    return {'source_ref':source_ref,'source_revision':source_revision,'source_digest':canonical_digest(json.loads(source_json)),
        'learned_at':identity.learned_at,'message_id':ingress_identity['message_id'],'c02_operation_id':c02,
        'c02_receipt_digest':canonical_digest(c02receipt),'parent_job_id':parent.job_id,
        'c3_call_id':prepared.call_id,'c3_routing':routing,'c3_paid_digest':paid[1],'c3_terminal_digest':terminal[1],
        'c04':native,'paid_reply':paid_reply,'generation_input_digest':generation.frozen.frozen_input_digest,'review_input_digest':review.frozen.digest,
        'scope':'actual normal SDK input -> actual C3/C03/SelfC04 -> same paid reply root; no elapsed72/96h claim'}



def actual_greeting_need_original_v1(db,*,namespace,episode):
    """Readonly assertions after actual normal SDK handler, never explicit recall."""
    from sylanne3.graph_types import AtomKey
    from sylanne3.runtime.ingress_observation import read_committed_ingress_identity
    from sylanne3.runtime.d11_types import job_graph_write
    from sylanne3.runtime.jobs import get_job
    from sylanne3.runtime.foreground_cycle_v1 import foreground_cycle_from_wire_v1
    from sylanne3.runtime.d06_ingress_recall_v1 import read_adopted_ingress_recall_need_v1
    from sylanne3.runtime.d07_ingress_recall_preparation_v1 import ingress_recall_model_ids_v1
    rows=db.execute("SELECT token,value FROM graph_atoms WHERE bot=? AND persona=? AND type_name='memory.source' "
        "AND valid=1 AND json_extract(value,'$.text')=? ORDER BY token LIMIT 2",(*namespace.as_tuple,episode['task_text'])).fetchall()
    if not rows:return None
    if len(rows)!=1:raise ValueError('greeting actual Source identity conflicted')
    source_ref=rows[0][0]
    identity=read_committed_ingress_identity(db,namespace,AtomKey.from_token(source_ref).owner.subject)
    if identity is None:return None
    actual_identity=json.loads(identity.identity_json)
    if actual_identity['message_id']!=str(episode['message_id']) or actual_identity['visibility']!='private':
        raise ValueError('greeting Source does not join actual SDK ingress message')
    parents=db.execute("SELECT token,value FROM graph_atoms WHERE bot=? AND persona=? AND type_name='runtime.job' "
        "AND valid=1 AND json_extract(value,'$.continuation.source_ref')=? ORDER BY token LIMIT 2",(*namespace.as_tuple,source_ref)).fetchall()
    if not parents:return None
    if len(parents)!=1:raise ValueError('greeting actual parent identity conflicted')
    parent=get_job(db,AtomKey.from_token(parents[0][0]).name)
    if job_graph_write(parent).value!=json.loads(parents[0][1]):raise ValueError('greeting SQL/Graph parent differs')
    cycle=foreground_cycle_from_wire_v1(parent.continuation)
    need=read_adopted_ingress_recall_need_v1(db,namespace=namespace,c02_operation_id=cycle.c02_operation_id)
    if need is None:return None
    if (need.c02_operation_id,need.source_ref,need.cycle_job_ref)!=(cycle.c02_operation_id,source_ref,parents[0][0]):
        raise ValueError('greeting adopted need changed actual Source/parent')
    # Existing mandatory facts take priority. Do not turn a real required check into no_search.
    if need.routing!='no_search':
        if not need.required_checks and not need.missing_items and not need.triggers:
            raise ValueError('plain greeting unnecessarily requested semantic search')
        return {'status':'current_mandatory_facts_hold','c02_operation_id':need.c02_operation_id,'source_ref':need.source_ref,'routing':need.routing}
    child=ingress_recall_model_ids_v1(namespace,cycle.c02_operation_id)['job']
    if db.execute('SELECT 1 FROM runtime_jobs WHERE job_id=?',(child,)).fetchone() is not None:
        raise ValueError('plain greeting created a C3 model job')
    if any(attempt.slot in {'C3','C4'} for attempt in cycle.call_plan.attempts):
        raise ValueError('plain greeting created an unnecessary recall attempt')
    return {'status':'actual_no_search','c02_operation_id':cycle.c02_operation_id,'source_ref':source_ref,
        'parent_job_id':parent.job_id,'routing':'no_search','c3_call_count':0,'c04_attempt_count':0}


def actual_d13_v6_episode_originals_v1(db,*,namespace,episode,issuer):
    """Read the actual normal ingress/reply originals; no seeded history."""
    from sylanne3.runtime.natural_reply_job_v2 import read_original_preparation
    from sylanne3.model_broker.natural_reply_history_v6 import FrozenNaturalReplyRequestV6
    from sylanne3.runtime_contracts import canonical_digest
    result=actual_ordinary_episode_originals_v1(db,namespace=namespace,episode=episode,issuer=issuer)
    if result is None:return None
    original=read_original_preparation(db,namespace,result['c02_operation_id'],'generation')
    if type(original.frozen) is not FrozenNaturalReplyRequestV6:
        raise ValueError('256 SDK scenario did not adopt actual V6 natural request')
    selection=original.frozen.input.history_selection
    result.update(v6_selection_digest=canonical_digest(selection),v6_raw_turn_count=len(selection.raw_turn_refs),
        v6_block_refs=[ref.ref for ref in selection.block_refs],v6_page_cursors=list(selection.page_cursors),
        scope='actual normal SDK Source/C02/C3 and same paid V6 reply; no historical Source simulation')
    return result


def actual_d13_v7_episode_originals_v1(db,*,namespace,episode,issuer,installed_wire_policy):
    from sylanne3.runtime.natural_reply_job_v2 import read_original_preparation
    from sylanne3.model_broker.natural_reply_history_v7 import FrozenNaturalReplyRequestV7,TEMPLATE_DIGEST
    from sylanne3.runtime_contracts import canonical_digest
    result=actual_ordinary_episode_originals_v1(db,namespace=namespace,episode=episode,issuer=issuer)
    if result is None:return None
    saved=read_original_preparation(db,namespace,result['c02_operation_id'],'generation')
    if type(saved.frozen) is not FrozenNaturalReplyRequestV7:
        raise ValueError('V7 SDK scenario did not adopt actual independent V7 request')
    from sylanne3.authority_service.d13_wire_evidence_v7 import read_signed_d13_core_wire_original_v1
    from sylanne3.authority_service.d13_core_counter_contract_v1 import verify_signed_d13_core_wire_evidence_v1
    from sylanne3.model_broker.d13_provider_http_template_v1 import provider_http_template_v1
    count=read_signed_d13_core_wire_original_v1(db,namespace=namespace,
        c02_operation_id=result['c02_operation_id'],policy=installed_wire_policy)
    if count is None:raise ValueError('actual adopted V7 episode lacks independent Core count original')
    selector,envelope=count;frame=envelope.payload.frame
    # This collector checks historical signed originals, not current model-admission permission.
    counted=verify_signed_d13_core_wire_evidence_v1(installed_wire_policy,envelope,selector=selector,
        frame=frame,now_utc=frame.frozen_at_utc)
    if (frame.namespace!=namespace or frame.c02_operation_id!=saved.seal.c02_operation_id
            or frame.generation_call_id!=saved.seal.call_id or frame.plan_ref!=saved.frozen.input.plan.plan_ref
            or frame.parent_budget_lease_ref!=saved.seal.parent_budget_lease_id
            or frame.install_id!=saved.seal.installation_id):
        raise ValueError('actual adopted V7 reply crossed original Core CPU/count parent or lease')
    frozen=saved.frozen;selection=frozen.input.history_selection
    raw=counted.raw_authority_digest==frozen.frozen_input_digest
    if (frozen.frozen_input_digest,frozen.model_request_digest)!=(
            counted.raw_authority_digest if raw else counted.compressed_authority_digest,
            counted.raw_request_digest if raw else counted.compressed_request_digest):
        raise ValueError('actual V7 generation did not consume the independently counted semantic variant')
    template=provider_http_template_v1(frozen,generation_call_id=frame.generation_call_id,
        billing_contract_digest=frame.billing_contract_digest,serializer_pin=installed_wire_policy.serializer_fingerprint)
    if (template.template_digest,template.byte_count)!=(
            counted.raw_http_template_digest if raw else counted.compressed_http_template_digest,
            counted.raw_http_bytes if raw else counted.compressed_http_bytes):
        raise ValueError('actual V7 adopted reply HTTP template differs from Core count original')
    result['core_full_wire_original']={'evidence_digest':envelope.evidence_digest,
        'frame_intent_id':frame.frame_intent_id,'frame_intent_digest':frame.frame_intent_digest,
        'counter_operation_id':frame.counter_operation_id,'selector_digest':selector.selector_digest,
        'cpu_execution_id':counted.cpu_execution_id,'cpu_terminal_digest':counted.cpu_terminal_digest,
        'actual_cpu_ns':counted.actual_cpu_ns,'cpu_settlement_ref':counted.cpu_settlement_ref,
        'cpu_settlement_digest':counted.cpu_settlement_digest,'d02_accounting_digest':counted.d02_accounting_digest,
        'd11_accounting_digest':counted.d11_accounting_digest,'variant':'raw' if raw else 'compressed',
        'http_template_digest':template.template_digest,'http_bytes':template.byte_count,
        'billing_contract_digest':frame.billing_contract_digest}
    result.update(v7_template_digest=TEMPLATE_DIGEST,authority_input_digest=frozen.frozen_input_digest,
        semantic_projection_digest=frozen.semantic_projection_digest,model_request_digest=frozen.model_request_digest,
        v7_selection_digest=canonical_digest(selection),v7_raw_turn_count=len(selection.raw_turn_refs),
        v7_block_refs=[ref.ref for ref in selection.block_refs],v7_page_cursors=list(selection.page_cursors),
        scope='actual SDK Source/C02/C3/same paid V7 reply and independently signed historical full-wire/CPU-settlement original; no current admission or real provider claim')
    return result


def actual_d13_v6_collection_originals_v1(db,*,namespace,source_ref,activation_generation,now_utc):
    """Same-transaction current pages plus real paid metadata; never seeds slots."""
    from sylanne3.graph_types import AtomKey
    from sylanne3.runtime.ingress_observation import read_committed_ingress_identity
    from sylanne3.runtime.first_ingress_v2 import scene_ref_for_conversation
    from sylanne3.runtime.d13_current_collection_v6 import read_current_d13_collection_v6
    from sylanne3.runtime.d13_paid_coordinator_v1 import recover_paid_d13_in_transaction_v1
    from sylanne3.domains.d13.derived_block_metadata_v1 import decode_derived_block_metadata_v1
    from sylanne3.runtime.d11_derived_cache_payload_v1 import read_derived_payload_v1
    from sylanne3.runtime_contracts import canonical_digest
    if not db.in_transaction:raise ValueError('actual V6 collection requires caller readonly transaction')
    ingress=read_committed_ingress_identity(db,namespace,AtomKey.from_token(source_ref).owner.subject)
    identity=json.loads(ingress.identity_json)
    scene=scene_ref_for_conversation(namespace,identity['platform_ref'],identity['conversation_ref'])
    collection=read_current_d13_collection_v6(db,namespace,scene,identity['conversation_ref'],now_utc,
        expected_activation_generation=activation_generation,max_slots=256)
    paid=[]
    jobs=db.execute("SELECT job_ref FROM graph_d13_paid_scene_jobs_v1 WHERE bot=? AND persona=? ORDER BY job_ref",namespace.as_tuple).fetchall()
    for (job_id,) in jobs:
        saved=recover_paid_d13_in_transaction_v1(db,namespace,job_id)
        if saved.next_action!='terminal' or saved.evidence is None or saved.settlement is None:
            return None
        costs=db.execute("SELECT phase,digest,receipt_json FROM runtime_budget_operations WHERE bot_id=? AND persona_id=? AND operation_id=? ORDER BY phase",
            (*namespace.as_tuple,saved.original.budget_operation_id)).fetchall()
        if [row[0] for row in costs]!=['reserve','settle']:raise ValueError('D13 paid original lacks once settlement')
        paid.append({'job_id':job_id,'phase':saved.job.phase,'call_id':saved.original.binding.call_id,
            'original_digest':saved.original.original_digest,'read_evidence_digest':saved.evidence.evidence_digest,
            'settlement_digest':canonical_digest(saved.settlement.receipt),'cost_originals':[list(row) for row in costs]})
    metadata=[]
    for token,value,revision in db.execute("SELECT token,value,revision FROM graph_atoms WHERE bot=? AND persona=? AND type_name='d13.derived_block_metadata.v1' AND valid=1 ORDER BY token",namespace.as_tuple):
        item=decode_derived_block_metadata_v1(json.loads(value))
        payload_row=db.execute("SELECT payload_digest,length(payload_bytes) FROM graph_d11_derived_cache_payloads_v1 WHERE bot=? AND persona=? AND block_ref=?",
            (*namespace.as_tuple,item.block_ref)).fetchone()
        if item.status=='retired':
            if payload_row is not None:raise ValueError('actual retired metadata still has physical payload')
        elif now_utc<item.expires_at_utc:
            read_derived_payload_v1(db,item,now_utc=now_utc)
        metadata.append({'ref':token,'revision':revision,'metadata_digest':canonical_digest(item),
            'payload_digest':item.payload_digest,'payload_present_current':payload_row is not None,'status':item.status,
            'expires_at_utc':item.expires_at_utc,'paid_original_digest':item.paid_original_digest})
    return {'schema':'sylanne.sdk-d13-v6-current-originals.v1','current_turn_count':len(collection.window.turns),
        'order_watermark':collection.window.order_watermark,'gaps':list(collection.window.missing_ranges),
        'snapshot_commitment':collection.snapshot_commitment,'window_digest':canonical_digest(collection.window),
        'pages':[{'before_sequence':page.before_sequence,'max_slots':page.max_slots,'first_sequence':page.first_sequence,
            'last_sequence':page.last_sequence,'status':page.page_status,'turn_count':len(page.window.turns)} for page in collection.pages],
        'paid_originals':paid,'metadata_originals':metadata,'physical_expiry_reclaim_verified':any(item['status']=='retired' and not item['payload_present_current'] and item['expires_at_utc']<=now_utc for item in metadata),
        'scope':'current same-transaction source/rights pages and adopted paid originals; expiry facts only, no elapsed expiry claim'}


if __name__=="__main__":
    import os,sys
    if len(sys.argv) not in (7,8) or sys.argv[1]!="--prepare":raise ValueError("fixed preinstallation fixture builder invocation required")
    candidate,request_path,provider_path,identity_path,result_path=map(Path,sys.argv[2:7])
    scenario=sys.argv[7] if len(sys.argv)==8 else SCENARIO
    sys.path.insert(0,str(candidate))
    from _runtime_bootstrap import load_canonical_runtime_v1
    load_canonical_runtime_v1(candidate)
    request,config=initial_install_request_v1(json.loads(request_path.read_text()),json.loads(provider_path.read_text()),
        json.loads(identity_path.read_text()),sender_id=100000002,scenario=scenario)
    for path,value in ((request_path,request),(result_path,config)):
        descriptor=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_TRUNC,0o600)
        with os.fdopen(descriptor,"w") as stream:
            os.fchmod(stream.fileno(),0o600);stream.write(json.dumps(value));stream.flush();os.fsync(stream.fileno())
