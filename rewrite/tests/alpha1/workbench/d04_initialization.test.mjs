import test from 'node:test';
import assert from 'node:assert/strict';
import {initializationInput, initializationForm, initializationProjection} from '../../../../webui-src/src/d04_initialization.js';
import {makeRequest} from '../../../../webui-src/src/api/contract.js';
const profile={schema:'d12.d04_initialization_profile.v3',profile_digest:'a'.repeat(64),profile:{content_digest:'a'.repeat(64),template_shares:[['one',.5],['two',.25],['mood',.25]],calibration_status:'engineering_unvalidated_owner_selection_required'},clock_requires_explicit_rate_and_interval:true,root_budget_dimension:'thread_cpu_ms'};
test('D04 choices compile exact real command inputs and never adopt implicitly',()=>{
 for(const mode of ['d04_root_draft','d04_root_budget','d04_root_coupling','d04_semantic_mapping','d11_role_clock','compile_scheme','activate_scheme']) assert.throws(()=>initializationInput(mode,{},profile),/确认/);
 const rows=[['d04_root_draft',{root_json:'{"candidate_id":"chosen"}'},{root_field:{candidate_id:'chosen'}}],['d04_root_budget',{parent_budget_lease_ref:'actual',thread_cpu_ms:'100'},{parent_budget_lease_ref:'actual',ceiling:{thread_cpu_ms:100}}],['d04_root_coupling',{root_operation_id:'actual-root-op',effective_until:'123.5'},{root_operation_id:'actual-root-op',effective_until:123.5}],['compile_scheme',{draft_ref:'actual-draft',compile_budget_ref:'actual-budget'},{draft_ref:'actual-draft',budget_ref:'actual-budget'}],['activate_scheme',{compiled_digest:'b'.repeat(64)},{compiled_digest:'b'.repeat(64)}],['d04_semantic_mapping',{expected_revision:'2',profile_reviewed:'on'},{profile_digest:'a'.repeat(64),expected_revision:2}]];
 for(const [mode,values,expected] of rows){const input=initializationInput(mode,{...values,confirm:'on'},profile);assert.deepEqual(input,expected);assert.equal(makeRequest(mode,{scope:'bot/persona',purpose:'workbench_user_action',input}).action,mode);}
 assert.throws(()=>initializationInput('d04_semantic_mapping',{confirm:'on',profile_reviewed:'on',expected_revision:'0'},null),/资料/);
 assert.throws(()=>initializationInput('d04_root_budget',{confirm:'on',parent_budget_lease_ref:'x',thread_cpu_ms:'9007199254740993'}),/整数/);
});
test('role clock uses explicit exact decimal strings and ordered UTC interval',()=>{
 const values={confirm:'on',expected_version:'0',character_origin:'0.00000000001',rate:'0.123456789123456789',wall_origin_utc:'2026-09-30T00:00:00Z',valid_from_utc:'2026-09-30T00:00:00Z',valid_until_utc:'2026-10-01T00:00:00Z'};
 const input=initializationInput('d11_role_clock',values);assert.equal(input.rate,values.rate);assert.equal(input.character_origin,values.character_origin);
 for(const override of [{rate:''},{rate:'0'},{valid_until_utc:values.valid_from_utc},{wall_origin_utc:'2026-09-30T00:00:00'}]) assert.throws(()=>initializationInput('d11_role_clock',{...values,...override}));
 assert.doesNotMatch(initializationForm({mode:'d11_role_clock'},null),/value="1"|checked/);
});
test('complete profile is escaped, visible, and includes calibration/explicit shares',()=>{
 const p={...profile,profile:{...profile.profile,note:'<script>bad</script>'}};
 const html=initializationProjection(p,null);assert.match(html,/engineering_unvalidated/);assert.match(html,/0.25/);assert.match(html,/&lt;script&gt;/);assert.doesNotMatch(html,/<script>/);
});
