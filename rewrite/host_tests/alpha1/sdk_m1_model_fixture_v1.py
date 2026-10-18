"""Finite HTTP candidate responses for the actual installed SDK M1 fixture.

Only candidate text and explicitly simulated charges originate here. No Source,
Graph, permission, model admission, terminal or file-effect original is created.
"""
from dataclasses import replace
import hashlib
import json
import sqlite3
from pathlib import Path

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sylanne3.host.authority_profile import AdminInstallationBundle
from sylanne3.model_broker import first_ingress_encoding as encoding
from sylanne3.model_broker import d04_appraisal as appraisal
from sylanne3.model_broker import artifact_draft_v1 as artifact
from sylanne3.model_broker import natural_reply_history_v4 as natural
from sylanne3.model_broker import natural_review as review
from sylanne3.model_broker import natural_reply_history_v6 as natural_v6
from sylanne3.model_broker import natural_reply_history_v7 as natural_v7
from sylanne3.model_broker import d13_precompression as d13
from sylanne3.model_broker import d07_cognition_v1 as cognition
from sylanne3.model_broker.provider_billing_receipt_v1 import (
    EXTENSION_KEY, ProviderBillingReceiptV1, provider_billing_receipt_signing_bytes_v1,
)
from sylanne3.memory_types import source_key
from sylanne3.runtime_contracts import canonical_digest, canonical_serialize


class FiniteSdkM1ModelFixtureV1:
    def __init__(self, config):
        fields = {"schema", "provider_id", "model_id", "provider_config_digest",
            "billing_private_key_hex", "filename", "max_episode_calls",
            "max_auxiliary_calls", "max_total_calls", "episodes"}
        crossday=config.get("schema")=="sylanne.sdk-real-elapsed-model-fixture.v1"
        if crossday:fields|={"ledger_path","phase_index"}
        d13_v7 = config.get("schema") == "sylanne.sdk-d13-v7-256-model-fixture.v1"
        d13_256 = d13_v7 or config.get("schema") == "sylanne.sdk-d13-v6-256-model-fixture.v1"
        ordinary = crossday or d13_256 or config.get("schema") == "sylanne.sdk-ordinary-recall-model-fixture.v1"
        episode_count=3 if crossday else 256 if d13_256 else 2
        total_bound=18 if crossday else 1536 if d13_256 else 12
        if (type(config) is not dict or set(config) != fields
                or config["schema"] not in {"sylanne.sdk-m1-model-fixture.v1", "sylanne.sdk-ordinary-recall-model-fixture.v1", "sylanne.sdk-d13-v6-256-model-fixture.v1","sylanne.sdk-d13-v7-256-model-fixture.v1","sylanne.sdk-real-elapsed-model-fixture.v1"}
                or config["filename"] != "m1-draft.txt"
                or (config["max_episode_calls"], config["max_auxiliary_calls"],
                    config["max_total_calls"]) != (6, 2, total_bound)
                or type(config["episodes"]) is not list or len(config["episodes"]) != episode_count):
            raise ValueError("SDK M1 finite initial model fixture contract differs")
        for episode in config["episodes"]:
            if (set(episode) != {"message_id", "task_text", "intent_kind", "artifact_text", "semantic_segment_count"}
                    or type(episode["semantic_segment_count"]) is not int
                    or not 1 <= episode["semantic_segment_count"] <= 4
                    or type(episode["message_id"]) is not int
                    or type(episode["task_text"]) is not str or not episode["task_text"]
                    or not ordinary and config["filename"] not in episode["task_text"]
                    or type(episode["artifact_text"]) is not str or not ordinary and not episode["artifact_text"]):
                raise ValueError("SDK M1 exact bounded episode required")
        if (tuple(e["intent_kind"] for e in config["episodes"]) !=
                (("draft_then_corrected_revision","continue",None) if crossday else (None,)*episode_count if ordinary else ("draft_then_corrected_revision", "continue"))
                or len({e["task_text"] for e in config["episodes"]}) != episode_count):
            raise ValueError("SDK M1 requires two distinct actual task messages")
        self._crossday=crossday
        self._ordinary = ordinary
        self._d13_256 = d13_256
        self._d13_v7 = d13_v7
        self._config = config
        self._key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(config["billing_private_key_hex"]))
        self._source_episodes = {}
        self._generation_episodes = {}
        self._phase_calls = set()
        self._episode_counts = [0]*episode_count
        self.calls = []
        if crossday:
            if type(config['phase_index']) is not int or not 0<=config['phase_index']<=2:
                raise ValueError('invalid real elapsed phase index')
            self._ledger=Path(config['ledger_path'])
            self._fixture_pin=canonical_digest({k:v for k,v in config.items() if k not in {'phase_index','ledger_path'}})
            with sqlite3.connect(self._ledger) as db:
                db.execute('CREATE TABLE IF NOT EXISTS fixture_pin(pin TEXT PRIMARY KEY)')
                db.execute('CREATE TABLE IF NOT EXISTS actual_http_calls(call_id TEXT PRIMARY KEY,episode INTEGER NOT NULL,phase TEXT NOT NULL,state TEXT NOT NULL,record_json TEXT NOT NULL,UNIQUE(episode,phase))')
                pins=db.execute('SELECT pin FROM fixture_pin').fetchall()
                if pins and pins!=[(self._fixture_pin,)]:raise ValueError('real elapsed provider changed its original fixture contract')
                if not pins:
                    if config['phase_index']!=0:raise ValueError('real elapsed provider ledger is absent after day0')
                    db.execute('INSERT INTO fixture_pin VALUES(?)',(self._fixture_pin,))
                rows=db.execute('SELECT episode,phase,state,record_json FROM actual_http_calls ORDER BY rowid LIMIT 19').fetchall()
            if len(rows)>18:raise ValueError('real elapsed persisted call cap exceeded')
            for index,phase,state,encoded in rows:
                record=json.loads(encoded);self.calls.append(record);self._episode_counts[index]+=1;self._phase_calls.add((index,phase))
                if state=='returned' and record.get('source_ref') is not None:self._source_episodes[record['source_ref']]=index
                if state=='returned' and phase=='natural_generation':self._generation_episodes[record['generation_digest']]=index

    def _persist_actual_call(self,index,phase,record,*,state):
        if not self._crossday:return
        with sqlite3.connect(self._ledger) as db:
            if state=='unknown':
                db.execute('INSERT INTO actual_http_calls VALUES(?,?,?,?,?)',
                    (record['call_id'],index,phase,state,canonical_serialize(record)))
            else:
                changed=db.execute('UPDATE actual_http_calls SET state=?,record_json=? WHERE call_id=? AND state=?',
                    (state,canonical_serialize(record),record['call_id'],'unknown')).rowcount
                if changed!=1:raise ValueError('real elapsed returned call lost its original pending identity')


    def _episode(self, text):
        matches = [i for i, e in enumerate(self._config["episodes"]) if e["task_text"] == text]
        if len(matches) != 1:
            raise ValueError("SDK M1 request is not one of its actual frozen task sources")
        return matches[0]

    def _source_episode(self, ref):
        if ref not in self._source_episodes:
            raise ValueError("SDK M1 source was not observed in its actual encoding request")
        return self._source_episodes[ref]

    def _candidate(self, messages, bundle):
        if (type(messages) is not list or not messages
                or any(type(m) is not dict or set(m) != {"role", "content"} for m in messages)
                or messages[0]["role"] != "system"
                or any(m["role"] != "user" for m in messages[1:])):
            raise ValueError("SDK M1 fixed provider message layout differs")
        system = messages[0]["content"]
        data = json.loads(messages[-1]["content"])
        if system == encoding._TASK_SYSTEM_PROMPT and len(messages) == 2:
            if data["schema"] != encoding._TASK_INPUT_SCHEMA:
                raise ValueError("SDK M1 requires the actual C1 version2 input")
            src = data["source"]
            index = self._episode(src["text"])
            ref = source_key(*bundle.installation_policy.namespace.as_tuple, src["source_id"]).token
            prior = self._source_episodes.get(ref)
            if prior is not None and prior != index:
                raise ValueError("SDK M1 source identity changed between episodes")
            episode = self._config["episodes"][index]
            output = {"schema": "sylanne.d06.first_ingress_encoding_output.v2",
                "event_summary": src["text"],
                "quoted_details": [{"quote": src["text"], "salience": 1.0}],
                "possible_meanings": [], "possible_feelings": [],
                "task_intent": None if self._ordinary and not (self._crossday and index<2) else {"kind": episode["intent_kind"], "filename": self._config["filename"],
                    "source_quote": src["text"]}}
            return index, "encode", output
        if self._ordinary and system == cognition.RECALL_SYSTEM_MESSAGE_V1 and len(messages) == 2:
            if data["schema"] != cognition.RECALL_INPUT_SCHEMA_V1:
                raise ValueError("ordinary recall requires its actual C3 input")
            cue=data["cue"]["record"]
            index=self._episode(cue["text"])
            greeting=cue["text"].strip().casefold().rstrip("!！。.").strip() in {"你好","您好"}
            if greeting:
                # A real mandatory need remains mandatory. This candidate cannot
                # turn it into no_search, clear a missing original or authorize recall.
                if not (data["triggers"] or data["required_checks"] or data["missing_items"]):
                    raise ValueError("plain greeting must not have dispatched a C3 model")
                return index,"recall_routing",{"schema":cognition.RECALL_OUTPUT_SCHEMA_V1,
                    "input_digest":data["input_digest"],"need_ref":data["need_ref"],"mode":"light",
                    "triggers":data["triggers"],"query_terms":[],"selected_source_refs":[],
                    "unknowns":["current_mandatory_facts_require_qualification"],"stop_reason":"clarification_required"}
            if index==0 or self._d13_256:
                if data["triggers"] or data["required_checks"] or data["missing_items"]:
                    raise ValueError("first ordinary fact cannot suppress a mandatory actual need")
                triggers,terms,reason=[],[],"no_history_needed"
            elif self._crossday:
                term="m1-draft.txt" if index==1 else "先生成第一版草稿"
                if term not in cue['text']:raise ValueError('crossday recall term is absent from its actual cue')
                triggers,terms,reason=['explicit_past_request'],[term],'search_required'
            else:
                if "炉灰九" not in cue["text"]:
                    raise ValueError("ordinary query term is absent from its current actual cue")
                triggers,terms,reason=["explicit_past_request"],["炉灰九"],"search_required"
            return index,"recall_routing",{"schema":cognition.RECALL_OUTPUT_SCHEMA_V1,
                "input_digest":data["input_digest"],"need_ref":data["need_ref"],"mode":"normal",
                "triggers":triggers,"query_terms":terms,"selected_source_refs":[],"unknowns":[],"stop_reason":reason}
        if self._d13_256 and system == d13.SYSTEM_MESSAGE and len(messages) == 2:
            if data["schema"] != d13.INPUT_SCHEMA or not 1<=len(data["turns"])<=64:
                raise ValueError("D13 paid candidate requires actual bounded source turns")
            from sylanne3.domains.d13.precompression import _QUALIFIER
            indices=[self._episode(t["text"]) for t in data["turns"]
                if any(e["task_text"]==t["text"] for e in self._config["episodes"])]
            if not indices:raise ValueError("D13 paid window has no actually encoded ingress source")
            return max(indices),"d13_precompression",{"schema":"d13.extractive_model_output.v1",
                "turns":[{"sequence":t["sequence"],"beat":t["text"] if _QUALIFIER.search(t["text"]) else t["text"][:6],"details":[]} for t in data["turns"]]}
        if system == appraisal.SYSTEM_MESSAGE and len(messages) == 2:
            if data["schema"] != appraisal.INPUT_SCHEMA or data["namespace"] != {
                    "bot_id": bundle.installation_policy.namespace.bot_id,
                    "persona_id": bundle.installation_policy.namespace.persona_id}:
                raise ValueError("SDK M1 appraisal differs from its installed namespace")
            event_sources = data["event"]["source_refs"]
            selected = [s for s in data["sources"] if s["source_ref"]["ref"] in event_sources]
            indices = {self._source_episode(s["source_ref"]["ref"]) for s in selected}
            if len(indices) != 1 or not selected or not data["interpretations"]:
                raise ValueError("SDK M1 appraisal has no unique current task event")
            index = next(iter(indices)); refs = [s["source_ref"]["ref"] for s in selected]
            values = data["role"]["values"]
            value_ref = values[0]["rule_id"] if values else data["role"]["blocks"][0]["block_id"]
            facet = "facet:sdk-m1-task"
            output = {"schema": appraisal.OUTPUT_SCHEMA,
                "facets": [{"facet_id": facet, "target_ref": data["target_ref"],
                    "interpretation_ref": data["interpretations"][0]["ref"]["ref"],
                    "value_ref": value_ref, "responsibility_hypothesis": "unknown",
                    "controllability": None, "anticipated_impact": 0.5,
                    "relation_meaning": "Possible subjective significance of the local task",
                    "self_meaning": None, "confidence": None,
                    "unknown_fields": ["responsibility_hypothesis", "controllability", "self_meaning", "confidence"],
                    "source_refs": refs}],
                "mechanism_signals": [{"facet_id": facet, "mechanism_id": mechanism,
                    "rationale": "Subjective possibility, not an observed feeling or permission", "source_refs": refs}
                    for mechanism in data["registered_mechanisms"]],
                "possible_feelings": ["possibly attentive"], "unknown_fields": ["speaker_intent"]}
            return index, "appraisal", output
        if system == artifact.SYSTEM_MESSAGE and len(messages) == 2:
            if data["schema"] != artifact.INPUT_SCHEMA:
                raise ValueError("SDK M1 artifact input template differs")
            frozen = data["input"]
            index = self._source_episode(frozen["task_source_ref"])
            if frozen["target"]["filename"] != self._config["filename"]:
                raise ValueError("SDK M1 artifact names a different installed file")
            return index, "artifact_draft", {"schema": artifact.OUTPUT_SCHEMA,
                "input_digest": data["input_digest"],
                "draft_text": self._config["episodes"][index]["artifact_text"],
                "source_refs": [s["ref"] for s in frozen["sources"]],
                "needs_clarification": False, "gaps": []}
        if system == (natural_v7.SYSTEM_MESSAGE if self._d13_v7 else natural_v6.SYSTEM_MESSAGE if self._d13_256 else natural.SYSTEM_MESSAGE_V5) and len(messages) == 3:
            if data["schema"] != (natural_v7.INPUT_SCHEMA if self._d13_v7 else natural_v6.INPUT_SCHEMA if self._d13_256 else natural.INPUT_SCHEMA_V5):
                raise ValueError("SDK M1 requires actual natural version5 input")
            index = self._episode(data["question"]["text"])
            basis = data["qualified_units"]
            plan = data["expression_plan"]
            acts = [a for a in plan["allowed_speech_acts"] if a != "promise"]
            if not basis or not acts:
                raise ValueError("SDK M1 cannot express without actual qualified basis and speech acts")
            body = ""; units = []
            for item in basis:
                text = item["qualified_text"]
                if not text:
                    raise ValueError("SDK M1 qualified unit contains no complete meaning")
                if body: body += "\n"
                start = len(body); body += text
                units.append({"start": start, "end": len(body), "kind": item["kind"],
                    "basis_ids": [item["basis_id"]], "speech_act": acts[0], "promise_grant_id": None,
                    "slot_ids": plan["required_slots"] if not units else []})
            if len(body) > 2048 or len(units) > 16:
                raise ValueError("SDK M1 complete qualified reply exceeds the actual natural parser bound")
            # Fixture-authored whole-meaning boundaries use complete qualified units;
            # never split a unit by punctuation or introduce another model call.
            count = self._config["episodes"][index]["semantic_segment_count"]
            if len(units) < count:
                raise ValueError("SDK M1 multi-bubble fixture lacks distinct complete qualified meanings")
            boundaries = [0, *(units[position]["start"] for position in range(1, count)), len(body)]
            output = {"schema": "sylanne.d09.context_reply_output.v3", "body": body, "units": units,
                "semantic_segments": [{"start": start, "end": end}
                    for start, end in zip(boundaries, boundaries[1:])]}
            from sylanne3.domains.d09.natural_reply import natural_semantic_ranges_v3
            natural_semantic_ranges_v3(output)
            return index, "natural_generation", output
        if system == review.SYSTEM_MESSAGE_V2 and len(messages) == 2:
            if (data["schema"] != review.INPUT_SCHEMA_V2
                    or data["generation_output_digest"] not in self._generation_episodes
                    or not 1 <= len(data["semantic_segments"]) <= 4):
                raise ValueError("SDK M1 review does not join its actual complete generation")
            actual_generation = {"schema": data["generation_output_schema"],
                "body": data["body"], "units": data["units"], "semantic_segments": data["semantic_segments"]}
            digest = review.generation_output_digest_from_generation(actual_generation)
            if digest != data["generation_output_digest"]:
                raise ValueError("SDK M1 review changed the actual previously returned generation")
            index = self._generation_episodes[digest]
            if len(data["semantic_segments"]) != self._config["episodes"][index]["semantic_segment_count"]:
                raise ValueError("SDK M1 review changed the authored finite semantic manifest")
            from sylanne3.domains.d09.natural_reply import natural_semantic_ranges_v3
            natural_semantic_ranges_v3(actual_generation)
            return index, "natural_review", {"schema": review.OUTPUT_SCHEMA_V2,
                "verdict": "pass", "issues": [], "prefix_safe": True}
        raise ValueError("SDK M1 unexpected model template; no fallback or extra provider call")

    def respond(self, request, *, installed_bundle):
        if type(installed_bundle) is not AdminInstallationBundle:
            raise TypeError("SDK M1 response requires the actual installed bundle")
        if request.method != "POST" or request.url.path != "/v1/chat/completions" or len(request.content) > 262144:
            raise ValueError("SDK M1 HTTP endpoint or fixed request bound differs")
        policy = installed_bundle.provider_billing_policy_v1
        public = self._key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
        if (policy is None or policy.evidence_kind != "fixture_simulated_charge"
                or policy.provider_ed25519_public_key_hex != public
                or (policy.provider_id, policy.model_id, policy.provider_config_digest) !=
                   (self._config["provider_id"], self._config["model_id"], self._config["provider_config_digest"])):
            raise ValueError("SDK M1 simulated billing key or installed provider differs")
        raw = json.loads(request.content); metadata = raw["metadata"]
        if self._d13_256 and not self._d13_v7:
            from sdk_d13_v6_counter_fixture_v1 import require_actual_http_bound_v1
            require_actual_http_bound_v1(raw,request.content)
        if (set(metadata) != {"sylanne_call_id", "sylanne_request_digest", "sylanne_billing_contract"}
                or metadata["sylanne_billing_contract"] != policy.contract_digest
                or raw["model"] != policy.model_id
                or any(c["call_id"] == metadata["sylanne_call_id"] for c in self.calls)):
            raise ValueError("SDK M1 actual call binding differs or call identity was replayed")
        try:
            index, phase, output = self._candidate(raw["messages"], installed_bundle)
        except Exception:
            if self._crossday:
                index=self._config['phase_index'];phase='invalid_candidate:'+metadata['sylanne_call_id']
                failed={'call_id':metadata['sylanne_call_id'],'request_digest':metadata['sylanne_request_digest'],
                    'episode_message_id':self._config['episodes'][index]['message_id'],'phase':phase,
                    'http_request_sha256':hashlib.sha256(request.content).hexdigest(),'state':'unknown',
                    'installation_id':policy.installation_id,'manifest_digest':policy.manifest_digest}
                self._persist_actual_call(index,phase,failed,state='unknown');self.calls.append(failed)
                self._episode_counts[index]+=1;self._phase_calls.add((index,phase))
            raise
        if self._crossday:
            if index!=self._config['phase_index']:raise ValueError('real elapsed call crossed its selected server phase')
            auxiliary=sum(c['phase']=='recall_routing' for c in self.calls if c['episode_message_id']==self._config['episodes'][index]['message_id'])
            if phase=='recall_routing' and auxiliary>=2:raise ValueError('real elapsed episode auxiliary cap exhausted')
        if (len(self.calls) >= self._config["max_total_calls"]
                or self._episode_counts[index] >= self._config["max_episode_calls"]
                or (index, phase) in self._phase_calls):
            raise ValueError("SDK M1 finite call plan exhausted or same stage replayed")
        pending={'call_id':metadata['sylanne_call_id'],'request_digest':metadata['sylanne_request_digest'],
            'episode_message_id':self._config['episodes'][index]['message_id'],'phase':phase,
            'http_request_sha256':hashlib.sha256(request.content).hexdigest(),'state':'unknown'}
        if self._crossday:
            pending['installation_id']=policy.installation_id;pending['manifest_digest']=policy.manifest_digest
            if any(c.get('installation_id')!=policy.installation_id or c.get('manifest_digest')!=policy.manifest_digest for c in self.calls):
                raise ValueError('real elapsed call ledger crossed its actual installed binding')
            self._persist_actual_call(index,phase,pending,state='unknown')
            self.calls.append(pending);self._episode_counts[index]+=1;self._phase_calls.add((index,phase))
        content = json.dumps(output, ensure_ascii=False, separators=(",", ":"))
        prompt_tokens = max(1, (len(request.content) + 3) // 4)
        completion_tokens = max(1, (len(content.encode("utf-8")) + 3) // 4)
        if completion_tokens > raw["max_completion_tokens"] or len(content.encode("utf-8")) > 65536:
            raise ValueError("SDK M1 finite response exceeds its original installed output ceiling")
        call_ref = "fixture-sdk-m1:" + canonical_digest(metadata)[:40]
        bill = ProviderBillingReceiptV1(policy.contract_digest, "fixture_simulated_charge",
            policy.installation_id, policy.manifest_digest, policy.provider_id, policy.model_id,
            policy.provider_config_digest, metadata["sylanne_call_id"], metadata["sylanne_request_digest"],
            call_ref, "fixture-sdk-m1-bill:" + canonical_digest((metadata, index, phase))[:40],
            prompt_tokens, completion_tokens, 0, 7, "0" * 128)
        bill = replace(bill, signature_hex=self._key.sign(provider_billing_receipt_signing_bytes_v1(bill)).hex())
        envelope = {"result": {"text": content},
            "usage": {"input_tokens": prompt_tokens, "output_tokens": completion_tokens, "cached_input_tokens": 0},
            "cost": {"model_microusd": 7}, "provider_call_ref": call_ref,
            "billing_receipt_json": bill.encoded}
        if len(canonical_serialize(envelope).encode("utf-8")) > 65536:
            raise ValueError("SDK M1 full signed provider response exceeds the actual executor bound")
        response = {"id": call_ref, "object": "chat.completion", "created": 0, "model": policy.model_id,
            "choices": [{"index": 0, "message": {"role": "assistant", "content": content}, "finish_reason": "stop"}],
            "usage": {"prompt_tokens": prompt_tokens, "completion_tokens": completion_tokens,
                "total_tokens": prompt_tokens + completion_tokens, "prompt_tokens_details": {"cached_tokens": 0}},
            EXTENSION_KEY: bill.to_wire()}
        # Commit correlation only after all response/billing/size checks pass.
        # A refused HTTP response is never an observed source or generation.
        if phase == "encode":
            source = json.loads(raw["messages"][-1]["content"])["source"]
            ref = source_key(*installed_bundle.installation_policy.namespace.as_tuple, source["source_id"]).token
            self._source_episodes[ref] = index
        elif phase == "natural_generation":
            digest = review.generation_output_digest_from_generation(output)
            previous = self._generation_episodes.get(digest)
            if previous is not None and previous != index:
                raise ValueError("SDK M1 generation digest belongs to another actual episode")
            self._generation_episodes[digest] = index
        if not self._crossday:self._episode_counts[index] += 1; self._phase_calls.add((index, phase))
        record={"call_id": bill.call_id, "request_digest": bill.request_digest,
            "episode_message_id": self._config["episodes"][index]["message_id"], "phase": phase,
            "http_request_sha256": hashlib.sha256(request.content).hexdigest(),
            "output_digest": canonical_digest(output), "fixture_charge_microusd": 7,
            "input_tokens": prompt_tokens, "output_tokens": completion_tokens}
        if self._crossday:
            record.update(installation_id=policy.installation_id,manifest_digest=policy.manifest_digest,state='returned')
            if phase=='encode':record['source_ref']=ref
            if phase=='natural_generation':record['generation_digest']=digest
            self._persist_actual_call(index,phase,record,state='returned')
        if self._crossday:self.calls[-1]=record
        else:self.calls.append(record)
        return httpx.Response(200, json=response, request=request)


class ArtifactV3MockModelFixtureV1(FiniteSdkM1ModelFixtureV1):
    """Actual MockTransport responses for one fresh V9 episode; no runtime authority."""
    def __init__(self, config):
        if __package__:
            from .artifact_phase_counter_fixture_v1 import MOCK_V3_PROVIDER, MOCK_V3_MODEL
        else:
            from artifact_phase_counter_fixture_v1 import MOCK_V3_PROVIDER, MOCK_V3_MODEL
        fields = {"schema", "provider_id", "model_id", "provider_config_digest", "billing_private_key_hex",
            "filename", "max_episode_calls", "max_auxiliary_calls", "max_total_calls", "episodes",
            "sample_text", "full_text", "unknown_observation"}
        if (type(config) is not dict or set(config) != fields
                or config["schema"] != "sylanne.sdk-artifact-v3-mock-model.v1"
                or (config["provider_id"], config["model_id"]) != (MOCK_V3_PROVIDER, MOCK_V3_MODEL)
                or (config["max_episode_calls"], config["max_auxiliary_calls"], config["max_total_calls"]) != (6, 0, 6)
                or len(config["episodes"]) != 1 or type(config["unknown_observation"]) is not bool):
            raise ValueError("explicit one-episode Artifact V3 Mock model contract required")
        self._config = config
        self._key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(config["billing_private_key_hex"]))
        self._source_episodes = {}
        self._ordinary = self._crossday = self._d13_256 = self._d13_v7 = False
        self.calls = []
        self.first_failure = None
        self._expected = ("encode", "appraisal", "tone_sample", "observe:sample_check", "full", "observe:check")

    def _candidate(self, messages, bundle):
        data = json.loads(messages[-1]["content"])
        episode = self._config["episodes"][0]
        if data["schema"] == encoding._DEPENDENCY_INPUT_SCHEMA:
            text = data["source"]["text"]
            if text != episode["task_text"]:
                raise ValueError("Mock C1 did not receive its actual frozen task")
            support = [{"start": 0, "end": len(text)}]
            conditions = (("structure_explicit", "true"), ("materials_complete", "true"), ("long_draft", "true"),
                ("short_draft", "false"), ("tone_multiple_legal_readings", "true"),
                ("local_sample_permitted", "true"), ("immediate_full_draft", "false"))
            return 0, "encode", {"schema": encoding._DEPENDENCY_OUTPUT_SCHEMA, "event_summary": text,
                "quoted_details": [{"quote": text, "salience": 1.0}], "possible_meanings": [], "possible_feelings": [],
                "task_intent": {"kind": "draft_then_corrected_revision", "filename": self._config["filename"], "source_quote": text},
                "method_context_candidate": {"intent_kind": "draft_then_corrected_revision", "task_source_quote": text,
                    "conditions": [{"condition_id": name, "proposed_value": value, "support_spans": support,
                        "counter_spans": [], "meaningful_unknowns": []} for name, value in conditions]},
                "historical_dependency_candidate": {"intent_kind": "draft_then_corrected_revision", "task_source_quote": text,
                    "mode": "current_task_only", "support_spans": support, "counter_spans": [], "meaningful_unknowns": []}}
        if data["schema"] == appraisal.INPUT_SCHEMA:
            return super()._candidate(messages, bundle)
        if data["schema"] == artifact.INPUT_SCHEMA_V2:
            frozen = data["input"]
            phase = frozen["selector"]["phase_kind"]
            if phase not in {"tone_sample", "full"} or frozen["target"]["filename"] != self._config["filename"]:
                raise ValueError("Mock C4 changed actual installed phase/filename")
            return 0, phase, {"schema": artifact.OUTPUT_SCHEMA_V2, "input_digest": data["input_digest"],
                "draft_text": self._config["sample_text"] if phase == "tone_sample" else self._config["full_text"],
                "source_refs": [s["ref"] for s in frozen["sources"]], "needs_clarification": False, "gaps": []}
        if data["schema"] == cognition.INPUT_SCHEMA:
            if not data["question_key"].startswith("artifact.phase.observation:") or data["work_kind"] != "concern":
                raise ValueError("Mock C3 is not the actual independent Artifact question")
            target = json.loads(data["target_original_json"])
            target_text = target.get("text")
            phase = "sample_check" if target_text == self._config["sample_text"] else "check" if target_text == self._config["full_text"] else None
            if phase is None:
                raise ValueError("Mock independent observation lacks actual generated target content")
            unknown = self._config["unknown_observation"]
            refs = [s["source_ref"]["ref"] for s in data["sources"]]
            return 0, "observe:" + phase, {"schema": cognition.OUTPUT_SCHEMA,
                "input_digest": data["input_digest"], "question_key": data["question_key"], "work_kind": "concern",
                "resolved_slots": [], "discriminating_refs": [], "predictions": [],
                "findings": [{"proposition": "condition_satisfied", "source_refs": refs,
                    "qualification": "unknown" if unknown else "subjective",
                    "stance": "suspend" if unknown else "support", "subjective_conviction": 0.0 if unknown else 0.5,
                    "evidence_status": "insufficient" if unknown else "supported"}],
                "unknowns": ["Mock observer deliberately cannot determine this condition"] if unknown else [],
                "stop_reason": "wait_for_new_information" if unknown else "bounded_segment_complete"}
        raise ValueError("Artifact V3 Mock rejects C5/C6, recall and every unregistered call")

    def respond(self, request, *, installed_bundle):
        if __package__:
            from .artifact_phase_counter_fixture_v1 import mock_v3_input_tokens
        else:
            from artifact_phase_counter_fixture_v1 import mock_v3_input_tokens
        from sylanne3.host.model_workflows_v9 import AdminModelWorkflowsV9
        if self.first_failure is not None:
            raise RuntimeError("first Mock failure retained; automatic replay prohibited")
        try:
            if type(installed_bundle) is not AdminInstallationBundle or type(installed_bundle.model_workflows) is not AdminModelWorkflowsV9:
                raise ValueError("Mock provider requires the real installed V9 bundle")
            policy = installed_bundle.provider_billing_policy_v1
            public = self._key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
            if (policy is None or policy.evidence_kind != "fixture_simulated_charge"
                    or policy.provider_ed25519_public_key_hex != public
                    or (policy.provider_id, policy.model_id, policy.provider_config_digest) !=
                       (self._config["provider_id"], self._config["model_id"], self._config["provider_config_digest"])):
                raise ValueError("Mock billing identity is not the explicit installed test contract")
            raw = json.loads(request.content)
            metadata = raw["metadata"]
            if (raw["model"] != policy.model_id or metadata["sylanne_billing_contract"] != policy.contract_digest
                    or any(c["call_id"] == metadata["sylanne_call_id"] for c in self.calls)):
                raise ValueError("Mock actual request/billing identity changed or replayed")
            _, phase, output = self._candidate(raw["messages"], installed_bundle)
            if len(self.calls) >= 6 or phase != self._expected[len(self.calls)]:
                raise ValueError("Mock episode exceeded or changed its exact C1C2+2C4+2C3 sequence")
            content = canonical_serialize(output)
            prompt_tokens = mock_v3_input_tokens(raw["messages"])
            completion_tokens = max(1, (len(content.encode()) + 7) // 8)
            if completion_tokens > raw["max_completion_tokens"]:
                raise ValueError("Mock output exceeds the actual original quote")
            call_ref = "mock-artifact-v3:" + canonical_digest(metadata)[:40]
            bill = ProviderBillingReceiptV1(policy.contract_digest, "fixture_simulated_charge",
                policy.installation_id, policy.manifest_digest, policy.provider_id, policy.model_id,
                policy.provider_config_digest, metadata["sylanne_call_id"], metadata["sylanne_request_digest"],
                call_ref, call_ref + ":zero-charge", prompt_tokens, completion_tokens, 0, 0, "0"*128)
            bill = replace(bill, signature_hex=self._key.sign(provider_billing_receipt_signing_bytes_v1(bill)).hex())
            if phase == "encode":
                src = json.loads(raw["messages"][-1]["content"])["source"]
                self._source_episodes[source_key(*installed_bundle.installation_policy.namespace.as_tuple, src["source_id"]).token] = 0
            self.calls.append({"call_id": bill.call_id, "request_digest": bill.request_digest, "phase": phase,
                "http_request_sha256": hashlib.sha256(request.content).hexdigest(), "output_digest": canonical_digest(output),
                "input_tokens": prompt_tokens, "output_tokens": completion_tokens, "fixture_charge_microusd": 0,
                "installation_id": policy.installation_id, "manifest_digest": policy.manifest_digest})
            return httpx.Response(200, request=request, json={"id": call_ref, "object": "chat.completion", "created": 0,
                "model": policy.model_id, "choices": [{"index": 0, "finish_reason": "stop",
                    "message": {"role": "assistant", "content": content}}],
                "usage": {"prompt_tokens": prompt_tokens, "completion_tokens": completion_tokens,
                    "total_tokens": prompt_tokens + completion_tokens, "prompt_tokens_details": {"cached_tokens": 0}},
                EXTENSION_KEY: bill.to_wire()})
        except BaseException as exc:
            self.first_failure = {"type": type(exc).__name__, "stage": "MockTransport", "call_index": len(self.calls),
                "http_request_sha256": hashlib.sha256(request.content).hexdigest()}
            raise
