"""Verify and install a pinned Sylanne alpha1 bundle into a new Linux cohort.

Run --plan first. Installation is explicit, fresh-only, and never sends model
or platform traffic. Starting the generated systemd unit is a separate action.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import zipfile

SOURCE = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(SOURCE))
from _runtime_bootstrap import load_canonical_runtime_v1
load_canonical_runtime_v1(SOURCE)


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def write(path, data, *, mode=0o600, gid=0):
    path = Path(path)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        os.fchown(fd, 0, gid)
        with os.fdopen(os.dup(fd), "wb") as target:
            target.write(data)
            target.flush()
            os.fsync(target.fileno())
    finally:
        os.close(fd)
    directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)


def archive_manifest(package, expected_package, expected_manifest):
    if hashlib.sha256(package.read_bytes()).hexdigest() != expected_package:
        raise ValueError("package differs from the externally supplied SHA256")
    with zipfile.ZipFile(package) as archive:
        if len(archive.infolist()) > 5000 or sum(item.file_size for item in archive.infolist()) > 512 * 1024**2:
            raise ValueError("package exceeds installation bound")
        names = set()
        for info in archive.infolist():
            path = PurePosixPath(info.filename)
            if (path.is_absolute() or ".." in path.parts or path.as_posix() != info.filename.rstrip("/") or "\\" in info.filename
                    or info.filename in names or (info.external_attr >> 16) & 0o170000 == 0o120000):
                raise ValueError("unsafe archive member")
            names.add(info.filename)
        raw = archive.read("release-manifest.json")
        if hashlib.sha256(raw).hexdigest() != expected_manifest:
            raise ValueError("manifest differs from the externally supplied SHA256")
        manifest = json.loads(raw)
        platform = manifest.get("platform", {})
        if not isinstance(platform, dict) or (platform.get("os"), platform.get("arch"), platform.get("libc")) != ("linux", "x86_64", "glibc"):
            raise ValueError("this installer requires the Linux x86_64 glibc package")
        return manifest


HOST_PROCESS_FIELDS = frozenset((
    "fixed_executable_path", "executable_sha256", "fixed_entry_ref", "entry_sha256",
    "fixed_argv", "fixed_cwd", "finite_environment_policy", "maximum_processes",
    "start_timeout", "drain_timeout"))


def check_host_process_command_v3(command):
    if type(command) is not dict or set(command) != HOST_PROCESS_FIELDS:
        raise ValueError("exact finite Host process command required")
    for name in ("fixed_executable_path", "fixed_entry_ref", "fixed_cwd"):
        value = command[name]
        if (type(value) is not str or not Path(value).is_absolute()
                or str(Path(value)) != value or ".." in Path(value).parts):
            raise ValueError("canonical absolute Host process path required")
    for name in ("executable_sha256", "entry_sha256"):
        if type(command[name]) is not str or re.fullmatch(r"[0-9a-f]{64}", command[name]) is None:
            raise ValueError("actual Host executable and entry hashes required")
    argv = command["fixed_argv"]
    environment = command["finite_environment_policy"]
    if (type(argv) is not list or not 2 <= len(argv) <= 64
            or any(type(value) is not str or not value or "\0" in value or len(value) > 4096 for value in argv)
            or argv[0] != command["fixed_executable_path"] or command["fixed_entry_ref"] not in argv
            or type(environment) is not dict or len(environment) > 16
            or any(type(key) is not str or type(value) is not str or not key or "\0" in key + value
                   for key, value in environment.items())):
        raise ValueError("exact finite Host argv and environment required")
    for name, lower, upper in (("maximum_processes", 2, 256), ("start_timeout", 1, 60), ("drain_timeout", 1, 60)):
        if type(command[name]) is not int or not lower <= command[name] <= upper:
            raise ValueError("finite Host process limits required")
    return command


def verify_host_process_command_v3(command):
    from sylanne3.authority_service.linux_installation_security_v1 import read_installed_bytes_v1
    check_host_process_command_v3(command)
    for name, pin in (("fixed_executable_path", "executable_sha256"), ("fixed_entry_ref", "entry_sha256")):
        path = Path(command[name])
        if str(path.resolve(strict=True)) != command[name]:
            raise ValueError("registered Host code must use its actual canonical path")
        if hashlib.sha256(read_installed_bytes_v1(path, limit=64 * 1024 * 1024)).hexdigest() != command[pin]:
            raise ValueError("registered Host code bytes differ")
    if not os.access(command["fixed_executable_path"], os.X_OK):
        raise ValueError("registered Host executable is not executable")


def check_request(request):
    fields = {"schema", "profile_id", "bot_id", "persona_id", "host_uid", "host_gid", "host_systemd_unit",
        "astrbot_plugins_directory", "authority_port", "reverse_port", "workbench_origin", "clock_error_seconds",
        "provider_id", "model_id", "provider_config_path", "model_quote", "local_quote", "budget_limits",
        "budget_max_ceiling", "currency", "budget_valid_until_utc", "model_audiences", "onebot_account",
        "onebot_adapter_ref", "provider_cache", "host_lifecycle", "d04_semantic_drive", "d04_joint_numeric",
        "d13_wire_policy", "d13_wire_counter", "d13_precompression", "d13_paid_precompression", "d07_cognition"}
    version5 = request.get("schema") in {"sylanne3.linux-install-request.v5", "sylanne3.linux-install-request.v6"}
    version4 = request.get("schema") in {"sylanne3.linux-install-request.v4", "sylanne3.linux-install-request.v5", "sylanne3.linux-install-request.v6"}
    process = request.get("schema") in {"sylanne3.linux-install-request.v3", "sylanne3.linux-install-request.v4", "sylanne3.linux-install-request.v5", "sylanne3.linux-install-request.v6"}
    version6 = request.get("schema") == "sylanne3.linux-install-request.v6"
    if version6:
        fields |= {"artifact_observation_cognition", "artifact_phase_observer", "artifact_phase_counter"}
    if process:
        fields = fields - {"host_systemd_unit"} | {"host_process_command"}
    if version4:
        fields |= {"foreground", "artifact_draft"}
        if version5:
            fields |= {"general_growth_cognition", "natural_template_pair_v1"}
            if "habit_runtime" in request:
                fields.add("habit_runtime")
        if "astrbot_namespace_v1" in request:
            fields.add("astrbot_namespace_v1")
        if "d06_recall" in request:
            fields.add("d06_recall")
        if "provider_billing_contract_v1" in request:
            fields.add("provider_billing_contract_v1")
        if "natural_template_pair_v1" in request:
            fields.add("natural_template_pair_v1")
        if "d13_counter_installation_v1" in request:
            fields.add("d13_counter_installation_v1")
    if set(request) != fields or request["schema"] not in {"sylanne3.linux-install-request.v2", "sylanne3.linux-install-request.v3", "sylanne3.linux-install-request.v4", "sylanne3.linux-install-request.v5", "sylanne3.linux-install-request.v6"}:
        raise ValueError("installation request fields differ; use the bundled request template")
    if "habit_runtime" in request and (not version5 or type(request["habit_runtime"]) is not bool):
        raise ValueError("Habit runtime is an explicit fresh v5 installation boolean")
    if type(request["profile_id"]) is not str or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", request["profile_id"]):
        raise ValueError("profile_id is invalid")
    from sylanne3.authority_service.installed_platform_observation import parse_installed_onebot_account_v2
    account = parse_installed_onebot_account_v2(json.dumps(request["onebot_account"], separators=(",", ":")))
    if "astrbot_namespace_v1" in request:
        from sylanne3.host.identity import astrbot_namespace_from_configuration_v1
        configured = request["astrbot_namespace_v1"]
        derived = astrbot_namespace_from_configuration_v1(configured)
        if ((request["bot_id"], request["persona_id"]) != derived.as_tuple
                or account != (configured["platform_id"], "aiocqhttp", configured["self_id"])):
            raise ValueError("configured AstrBot namespace differs from the exact installed account/persona")
    else:
        for name in ("bot_id", "persona_id"):
            if type(request[name]) is not str or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", request[name]):
                raise ValueError(name + " is invalid")
    if process:
        check_host_process_command_v3(request["host_process_command"])
    elif not re.fullmatch(r"[A-Za-z0-9_.@-]+\.service", request["host_systemd_unit"]):
        raise ValueError("installed AstrBot systemd unit required")
    for name in ("host_uid", "host_gid"):
        if type(request[name]) is not int or request[name] < 1:
            raise ValueError("AstrBot must run under an explicit non-root UID/GID")
    if request["authority_port"] == request["reverse_port"] or any(type(request[name]) is not int or not 1024 <= request[name] <= 65535 for name in ("authority_port", "reverse_port")):
        raise ValueError("distinct unprivileged loopback ports required")
    for name in ("model_quote", "local_quote", "budget_limits", "budget_max_ceiling"):
        if not request[name] or any(type(value) is not int or value < 1 for value in request[name].values()):
            raise ValueError("explicit positive " + name + " required; the installer never chooses spending limits")
    if (type(request["budget_valid_until_utc"]) not in (int, float)
            or not math.isfinite(request["budget_valid_until_utc"])
            or request["budget_valid_until_utc"] <= datetime.now(timezone.utc).timestamp()):
        raise ValueError("explicit future budget expiry in UTC Unix seconds required")
    if request["model_quote"].get("output_tokens", 0) < 1:
        raise ValueError("model quote requires explicit output_tokens")
    for quote in (request["local_quote"], request["model_quote"]):
        for key, value in quote.items():
            if value > request["budget_max_ceiling"].get(key, 0) or value > request["budget_limits"].get(key, 0):
                raise ValueError("per-call quote exceeds approved root budget")
    from sylanne3.authority_service.d12_installed_supervisor_v1 import D12SystemdSupervisorConfigV1
    life = request["host_lifecycle"]
    if (type(life) is not dict or set(life) != ({"drain_timeout_seconds"} if process else {"supervisor", "drain_timeout_seconds"})
            or type(life["drain_timeout_seconds"]) is not int or not 1 <= life["drain_timeout_seconds"] <= 3600):
        raise ValueError("explicit bounded installed lifecycle supervision required")
    if not process:
        supervisor = D12SystemdSupervisorConfigV1(**life["supervisor"])
        if supervisor.unit_name != request["host_systemd_unit"]:
            raise ValueError("lifecycle and Host unit differ")
    for name in ("d04_semantic_drive", "d04_joint_numeric"):
        if type(request[name]) is not dict or not request[name]:
            raise ValueError("full alpha1 requires explicit " + name)
    for name in ("d13_wire_policy", "d13_wire_counter", "d13_precompression", "d13_paid_precompression", "d07_cognition"):
        if request[name] is not None and type(request[name]) is not dict:
            raise ValueError(name + " must be an explicit object or null")
    if version5 and request["general_growth_cognition"] is not None and type(request["general_growth_cognition"]) is not dict:
        raise ValueError("General workflow must be an explicit object or null")
    if request["d13_wire_counter"] is not None and request["d13_wire_policy"] is None:
        raise ValueError("counter requires its explicit signed full-wire policy")
    if (type(request["provider_cache"]) is not dict
            or request["provider_cache"].get("provider_id") != request["provider_id"]):
        raise ValueError("cache adapter must cover the installed model provider")
    if version4:
        pair=natural_template_pair_v1(request)
        from sylanne3.model_broker.natural_reply_history_v7 import TEMPLATE_VERSION as V7_TEMPLATE
        if version5:
            from sylanne3.model_broker.natural_review import REVIEW_TEMPLATE_VERSION_V2
            if pair != (V7_TEMPLATE, REVIEW_TEMPLATE_VERSION_V2):
                raise ValueError("version-5 installation requires the exact inherited V7 natural template pair")
            general_raw = request["general_growth_cognition"]
            if general_raw is not None:
                from sylanne3.host.model_workflows_v4 import model_workflow_v4_from_payload
                from sylanne3.model_broker.general_growth_cognition_v1 import PURPOSE, TEMPLATE_VERSION, WORK_KIND
                workflow = model_workflow_v4_from_payload(general_raw)
                if ((workflow.work_kind, workflow.purpose, workflow.template_version) != (WORK_KIND, PURPOSE, TEMPLATE_VERSION)
                        or set(workflow.quote_ceiling) != {"input_tokens", "output_tokens", "model_tokens", "model_microusd"}
                        or workflow.quote_ceiling["input_tokens"] > 6000
                        or workflow.quote_ceiling["output_tokens"] > 1000
                        or workflow.quote_ceiling["model_tokens"] > 7000
                        or workflow.max_output_tokens > 1000):
                    raise ValueError("General workflow must match the exact named template and original finite quote caps")
                for name, amount in workflow.quote_ceiling.items():
                    if amount > request["budget_limits"].get(name, 0) or amount > request["budget_max_ceiling"].get(name, 0):
                        raise ValueError("General quote exceeds the signed root limits")
        if pair[0]==V7_TEMPLATE:
            from sylanne3.authority_service.d13_installed_counter_factory_v1 import validate_d13_counter_initial_spec_v1
            validate_d13_counter_initial_spec_v1(request.get("d13_counter_installation_v1"))
            if request["d13_wire_policy"] is None or request["d13_wire_counter"] is not None:
                raise ValueError("V7 requires its explicit Core policy and protected initial counter assets")
        elif "d13_counter_installation_v1" in request:
            raise ValueError("Core counter assets require the explicitly selected V7 template")
        billing = request.get("provider_billing_contract_v1")
        if billing is not None:
            if (type(billing) is not dict or set(billing) != {"contract_id", "contract_version",
                    "provider_ed25519_public_key_hex", "evidence_kind", "currency", "unit"}
                    or type(billing["contract_version"]) is not int or billing["contract_version"] != 1
                    or billing["evidence_kind"] not in {"provider_final_charge", "fixture_simulated_charge"}
                    or (billing["currency"], billing["unit"]) != ("USD", "model_microusd")
                    or type(billing["contract_id"]) is not str or not 0 < len(billing["contract_id"]) <= 256
                    or type(billing["provider_ed25519_public_key_hex"]) is not str
                    or re.fullmatch("[0-9a-f]{64}", billing["provider_ed25519_public_key_hex"]) is None):
                raise ValueError("explicit finite provider billing contract/key/evidence/unit required")
        from sylanne3.host.authority_profile import foreground_policy_from_payload_v1, artifact_draft_policy_from_payload_v1
        foreground = foreground_policy_from_payload_v1(request["foreground"])
        if "d06_recall" in request:
            from sylanne3.host.authority_profile import d06_recall_policy_from_payload_v1
            d06_recall_policy_from_payload_v1(request["d06_recall"])
        if request["artifact_draft"] is None:
            if foreground.deadline_policy.draft_mode is not None:
                raise ValueError("unconfigured draft cannot request a signed-scope deadline")
        else:
            draft = artifact_draft_policy_from_payload_v1(request["artifact_draft"])
            if foreground.deadline_policy.draft_mode != "signed_scope_intersection_v1":
                raise ValueError("draft requires explicit signed-scope responsibility")
            for name, amount in draft.model_workflow.quote_ceiling.items():
                if name not in request["budget_limits"] or name not in request["budget_max_ceiling"]:
                    raise ValueError("draft quote requires all explicit root budget dimensions")
                if amount > min(request["budget_limits"][name], request["budget_max_ceiling"][name]):
                    raise ValueError("draft per-call quote exceeds approved root budget")
            if (draft.body_policy.cpu_ceiling_ms > request["budget_limits"]["cpu_ms"]
                    or draft.body_policy.cpu_ceiling_ms > request["budget_max_ceiling"]["cpu_ms"]):
                raise ValueError("draft Body ceiling exceeds approved root budget")
            if draft.observation_policy is not None and (
                    draft.observation_policy.cpu_ceiling_ms > request["budget_limits"]["cpu_ms"]
                    or draft.observation_policy.cpu_ceiling_ms > request["budget_max_ceiling"]["cpu_ms"]):
                raise ValueError("draft observation ceiling exceeds approved root budget")
    if version6:
        validate_artifact_v3_asset_descriptors_v1(request)
        from sylanne3.host.model_workflows_v4 import model_workflow_v4_from_payload
        model_workflow_v4_from_payload(request["artifact_observation_cognition"])
    return request


def natural_template_pair_v1(request):
    """Choose a registered initial workflow pair before profile signing."""
    from sylanne3.model_broker.natural_reply_history_v4 import TEMPLATE_VERSION, TEMPLATE_VERSION_V5
    from sylanne3.model_broker.natural_reply_history_v6 import TEMPLATE_VERSION as TEMPLATE_VERSION_V6
    from sylanne3.model_broker.natural_reply_history_v7 import TEMPLATE_VERSION as TEMPLATE_VERSION_V7
    from sylanne3.model_broker.natural_review import REVIEW_TEMPLATE_VERSION, REVIEW_TEMPLATE_VERSION_V2

    legacy = (TEMPLATE_VERSION, REVIEW_TEMPLATE_VERSION)
    selected = request.get("natural_template_pair_v1")
    if selected is None:
        return legacy
    if (request.get("schema") not in {"sylanne3.linux-install-request.v4", "sylanne3.linux-install-request.v5", "sylanne3.linux-install-request.v6"}
            or type(selected) is not dict
            or set(selected) != {"schema", "generation", "review"}
            or selected["schema"] != "sylanne3.initial-natural-template-pair.v1"):
        raise ValueError("exact initial natural template pair required")
    pair = (selected["generation"], selected["review"])
    if pair not in (legacy, (TEMPLATE_VERSION_V5, REVIEW_TEMPLATE_VERSION_V2), (TEMPLATE_VERSION_V6, REVIEW_TEMPLATE_VERSION_V2), (TEMPLATE_VERSION_V7, REVIEW_TEMPLATE_VERSION_V2)):
        raise ValueError("initial natural generation/review pair is not registered")
    return pair


def selected_model_request_v1(request, value):
    """Bind a public Host observation to local administrator installation input.

    The observation selects a model; it grants no rights and supplies no budget.
    The local provider configuration must still be the exact observed object.
    """
    from sylanne3.host.model_selection import parse_host_model_selection_v1
    from sylanne3.runtime_contracts import canonical_digest

    check_request(request)
    selection = parse_host_model_selection_v1(value)
    if selection.authority_profile != request["profile_id"]:
        raise ValueError("model selection belongs to a different Authority profile")
    config = json.loads(Path(request["provider_config_path"]).read_bytes())
    if type(config) is not dict:
        raise ValueError("exact local AstrBot provider configuration object required")
    if canonical_digest(config) != selection.provider_config_digest:
        raise ValueError("selected provider configuration changed; read the Host selection again")
    if (config.get("id") != selection.provider_id
            or config.get("model") != selection.model_id):
        raise ValueError("selected provider or model differs from the local configuration")
    if config.get("type") != "openai_chat_completion":
        raise ValueError("selected provider adapter is not supported by the current installation contract")
    updated = {**request, "provider_id": selection.provider_id,
               "model_id": selection.model_id,
               "provider_cache": {**request["provider_cache"], "provider_id": selection.provider_id}}
    return check_request(updated)


def tls_material():
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
    now = datetime.now(timezone.utc)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Sylanne local installation CA")])
    ca = (x509.CertificateBuilder().subject_name(issuer).issuer_name(issuer).public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=730)).add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(ca_key, hashes.SHA256()))
    def leaf(name):
        key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
        cert = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
            .issuer_name(issuer).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
            .sign(ca_key, hashes.SHA256()))
        return (cert.public_bytes(serialization.Encoding.PEM),
            key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()),
            cert.fingerprint(hashes.SHA256()).hex())
    return ca.public_bytes(serialization.Encoding.PEM), leaf("Sylanne Authority"), leaf("Sylanne AstrBot Host")


def make_profile(request, *, manifest_pin, authority_id, installation_id, registry, scheme):
    from sylanne3.graph_coordinator import namespace_ref
    from sylanne3.runtime_contracts import NamespaceId, canonical_digest
    from sylanne3.host.authority_profile import installed_model_config_ref, _policy_from_payload
    from sylanne3.model_broker.first_ingress_encoding import FIRST_INGRESS_ENCODING_TEMPLATE_VERSION
    from sylanne3.model_broker.reply_language import REPLY_TEMPLATE_VERSION
    generation_template, review_template = natural_template_pair_v1(request)
    from sylanne3.model_broker.natural_reply_history_v6 import TEMPLATE_VERSION as NATURAL_GENERATION_V6
    from sylanne3.model_broker.natural_reply_history_v7 import TEMPLATE_VERSION as NATURAL_GENERATION_V7
    from sylanne3.model_broker.d04_appraisal import TEMPLATE_VERSION as APPRAISAL_VERSION, WORK_KIND as APPRAISAL_KIND
    namespace = NamespaceId(request["bot_id"], request["persona_id"])
    provider_config = json.loads(Path(request["provider_config_path"]).read_bytes())
    if type(provider_config) is not dict:
        raise ValueError("exact AstrBot provider configuration object required")
    config_digest = canonical_digest(provider_config)
    common = dict(provider_id=request["provider_id"], model_id=request["model_id"],
        provider_config_ref=installed_model_config_ref(request["provider_id"], request["model_id"], config_digest),
        provider_config_digest=config_digest, audiences=request["model_audiences"], privacy_tier="private",
        required_capabilities=["text"], timeout_seconds=120.0, max_output_tokens=request["model_quote"]["output_tokens"],
        quote_ceiling=request["model_quote"])
    encode_template=FIRST_INGRESS_ENCODING_TEMPLATE_VERSION
    if request.get("artifact_draft") is not None:
        from sylanne3.host.authority_profile import artifact_draft_policy_from_payload_v1,AdminArtifactDraftPolicyV2
        if type(artifact_draft_policy_from_payload_v1(request["artifact_draft"])) is AdminArtifactDraftPolicyV2:
            from sylanne3.model_broker.first_ingress_encoding import FIRST_INGRESS_TASK_ENCODING_TEMPLATE_VERSION
            encode_template=FIRST_INGRESS_TASK_ENCODING_TEMPLATE_VERSION
    if request["schema"] == "sylanne3.linux-install-request.v6":
        from sylanne3.model_broker.first_ingress_encoding import FIRST_INGRESS_DEPENDENCY_ENCODING_TEMPLATE_VERSION
        encode_template = FIRST_INGRESS_DEPENDENCY_ENCODING_TEMPLATE_VERSION
    workflows = {"version": 2}
    for name, kind, purpose, template in (("encode", "d06.encode_source", "consolidation", encode_template),
        ("reply", "reply", "proposal", REPLY_TEMPLATE_VERSION), ("natural_generation", "natural_generation", "proposal", generation_template),
        ("natural_review", "natural_review", "proposal", review_template), ("appraisal", APPRAISAL_KIND, "proposal", APPRAISAL_VERSION)):
        workflows[name] = {**common, "work_kind": kind, "purpose": purpose, "template_version": template}
    if request['d07_cognition'] is not None:
        workflows['d07_cognition'] = dict(request['d07_cognition'])
        if any(workflows['d07_cognition'].get(name) != common[name]
               for name in ('provider_id', 'model_id', 'provider_config_ref', 'provider_config_digest')):
            raise ValueError('D07 cognition must explicitly match the installed main provider configuration')
    if request['schema'] in {'sylanne3.linux-install-request.v4', 'sylanne3.linux-install-request.v5', 'sylanne3.linux-install-request.v6'}:
        workflows['version'] = 4
        workflows['artifact_draft'] = None
        if request['artifact_draft'] is not None:
            configured = request['artifact_draft']['model_workflow']
            if any(configured[name] != common[name]
                    for name in ('provider_id', 'model_id', 'provider_config_ref', 'provider_config_digest')):
                raise ValueError('C4 requires the exact actual installed main provider configuration')
            workflows['artifact_draft'] = dict(configured)
    if generation_template == NATURAL_GENERATION_V7:
        workflows['version']=7
        workflows['d07_relationship_cognition']=None
        workflows['growth_cognition']=None
    if generation_template == NATURAL_GENERATION_V6:
        workflows['version'] = 6
        workflows['d07_relationship_cognition'] = None
        workflows['growth_cognition'] = None
    if request['schema'] in {'sylanne3.linux-install-request.v5', 'sylanne3.linux-install-request.v6'}:
        if generation_template != NATURAL_GENERATION_V7:
            raise ValueError('V8 workflows require their exact inherited V7 natural wire')
        workflows['version'] = 8
        workflows['d07_relationship_cognition'] = None
        workflows['growth_cognition'] = None
        configured = request['general_growth_cognition']
        workflows['general_growth_cognition'] = None
        if configured is not None:
            if any(configured[name] != common[name] for name in ('provider_id', 'model_id', 'provider_config_ref', 'provider_config_digest')):
                raise ValueError('General workflow must use the exact installed main provider configuration')
            workflows['general_growth_cognition'] = dict(configured)
    artifact_v3 = None
    if request["schema"] == "sylanne3.linux-install-request.v6":
        observation, observer, counter = _artifact_v3_configuration_v1(request,
            installation_id=installation_id, manifest_pin=manifest_pin, config_digest=config_digest,
            installed_paths=True)
        workflows["version"] = 9
        from sylanne3.domains.d01.production_operations_v1 import plain_v1
        workflows["artifact_observation_cognition"] = plain_v1(observation)
        artifact_v3 = (observer, counter)
    local = dict(deadline_after_seconds=300.0, quote_ceiling=request["local_quote"],
        snapshot_ref="installed:snapshot:v1", resource_ref="installed:resource:v1")
    kinds = ["d06.encode_source", "reply", "natural_generation", "natural_review", APPRAISAL_KIND,
        "d03.message_received", "d07.attention", "d04.encoding_baseline", "d06.first_ingress_c02",
        "d06.source_correction", "d03.self_identity_projection", "message", "d06.association_activation.v3",
        "d04.joint_numeric_cpu.v3", "d04.authored_root_adoption.v3",
        "d04.semantic_drive.adopt", "d06.c04_internal_cpu.v1", "d07.cognitive_behavior.v1"]
    for setting, kind in (("d13_precompression", "d13.precompress"),
                          ("d13_paid_precompression", "d13.precompress.paid.v1"),
                          ("d07_cognition", "d07.cognition")):
        if request[setting] is not None and kind not in kinds:
            kinds.append(kind)
    if request["schema"] in {"sylanne3.linux-install-request.v5", "sylanne3.linux-install-request.v6"}:
        from sylanne3.authority_service.conditioned_child_contract_v1 import ROOT_WORK_KIND
        kinds.append(ROOT_WORK_KIND)
        if request.get("habit_runtime", False):
            kinds.extend(("habit_subscription_v1", "d10.life.source_note.v1"))
    if request["schema"] in {"sylanne3.linux-install-request.v5", "sylanne3.linux-install-request.v6"} and request["general_growth_cognition"] is not None:
        if "d07.cognition" not in kinds:
            kinds.append("d07.cognition")
    if generation_template == NATURAL_GENERATION_V7:
        # Issue the distinct bounded counter CPU step only in this new Root.
        # The existing Root ceiling and expiry are unchanged.
        kinds.append('d13.full_http_counter.v1')
    if request['schema'] in {'sylanne3.linux-install-request.v4', 'sylanne3.linux-install-request.v5', 'sylanne3.linux-install-request.v6'}:
        kinds.append('d11.foreground_cycle.v1')
        if request['artifact_draft'] is not None:
            kinds.extend(('artifact_draft_v1', 'd10.life.artifact_draft.v1'))
            if request['artifact_draft']['observation_policy'] is not None:
                kinds.append('d11.life.artifact_observation.v1')
    if artifact_v3 is not None and "d07.cognition" not in kinds:
        kinds.append("d07.cognition")
    budget_identity = dict(bot_id=namespace.bot_id, persona_id=namespace.persona_id, currency=request["currency"])
    policy = dict(namespace=asdict(namespace), authority_namespace=namespace_ref(namespace), installation_id=installation_id,
        manifest_digest=manifest_pin, administrator_holder="host:" + request["profile_id"], expected_authority_id=authority_id,
        catalogue_hash=registry.catalogue_hash, scheme_version=scheme.scheme_version, operator_version=scheme.operator_version,
        policy_version="sylanne.embodiment.alpha1.installation.v1",
        root_lease=dict(lease_id="root:" + installation_id, parent_id=None, **budget_identity,
            limits=request["budget_limits"], used={}, reserved={}, unconfirmed={}, version=1, state="active"),
        root_grant=dict(grant_id="root-grant:" + installation_id, version=1, **budget_identity,
            lease_id="root:" + installation_id, max_ceiling=request["budget_max_ceiling"], allowed_work_kinds=kinds,
            valid_until_utc=request["budget_valid_until_utc"], policy_ref="administrator:budget:v1"))
    profile = dict(schema=2, host="127.0.0.1", port=request["authority_port"], server_name="localhost",
        expected_authority_id=authority_id, installation_policy=policy,
        ingress_clock=dict(source_id="linux:kernel-adjtimex:v1", max_utc_error_seconds=request["clock_error_seconds"], max_round_trip_seconds=2.0),
        ingress_encoding={**local, "quote_ceiling": request["model_quote"], "character_interval_ref": "character:installed:v1"},
        model_workflows=workflows, workbench_origin=request["workbench_origin"],
        **{name: dict(local) for name in ("d03_arrival", "d07_attention", "d04_encoding_baseline", "d06_first_ingress_c02", "d06_source_correction", "d03_self_identity_projection")},
        private_reply_dispatch={**local, "segment_max_chars": 1200, "host_takeover_wait_seconds": 0.5},
        d06_private_reply_source={"version": 1, "scope": "private_conversation", "grant_expression": True})
    for name in ("d04_semantic_drive", "d04_joint_numeric", "d13_precompression", "d13_paid_precompression", "d13_wire_counter"):
        if request[name] is not None:
            profile[name] = request[name]
    if request['schema'] in {'sylanne3.linux-install-request.v4', 'sylanne3.linux-install-request.v5', 'sylanne3.linux-install-request.v6'}:
        if "astrbot_namespace_v1" in request:
            profile["astrbot_namespace_v1"] = request["astrbot_namespace_v1"]
        profile['foreground'] = request['foreground']
        profile['artifact_draft'] = request['artifact_draft']
        if artifact_v3 is not None:
            observer, counter = artifact_v3
            profile["artifact_phase_observer"] = {
                "schema": "sylanne.artifact-phase-observer-installation.v2", "observer_id": observer.observer_id,
                "observer_version": observer.observer_version, "asset_ref": observer.asset_ref,
                "asset_sha256": observer.asset_digest}
            profile["artifact_phase_counter"] = asdict(counter)
        from sylanne3.host.authority_profile import _foreground_from_payload, _artifact_draft_from_payload
        _foreground_from_payload(profile)
        _artifact_draft_from_payload(profile)
        if "d06_recall" in request:
            from sylanne3.host.authority_profile import _d06_recall_from_payload
            profile["d06_recall"] = request["d06_recall"]
            _d06_recall_from_payload(profile)
        if request.get("provider_billing_contract_v1") is not None:
            from sylanne3.model_broker.provider_billing_receipt_v1 import ProviderBillingPolicyV1
            billing = ProviderBillingPolicyV1(namespace=namespace, installation_id=installation_id,
                manifest_digest=manifest_pin, provider_id=request["provider_id"], model_id=request["model_id"],
                provider_config_digest=config_digest, **request["provider_billing_contract_v1"])
            profile["provider_billing_policy_v1"] = asdict(billing)
    if request["d13_wire_policy"] is not None:
        configured = dict(request["d13_wire_policy"])
        if configured.get("installation") != "$current_installation":
            raise ValueError("fresh D13 policy must explicitly bind $current_installation")
        configured["installation"] = dict(installation_id=installation_id, provider_config_digest=config_digest,
            provider_id=request["provider_id"], model_id=request["model_id"],
            max_output_tokens=request["model_quote"]["output_tokens"])
        profile["d13_wire_policy"] = configured
    if request.get("habit_runtime", False):
        from sylanne3.host.habit_runtime_policy_v1 import HabitRuntimePolicyV1
        from sylanne3.runtime.issuers import BudgetLeaseGrant
        from sylanne3.runtime_contracts import canonical_digest
        grant = BudgetLeaseGrant(**{**policy["root_grant"],
            "allowed_work_kinds": tuple(policy["root_grant"]["allowed_work_kinds"])})
        profile["habit_runtime_policy"] = asdict(HabitRuntimePolicyV1(namespace=namespace,
            installation_id=installation_id, manifest_digest=manifest_pin,
            root_lease_id=policy["root_lease"]["lease_id"], root_grant_id=grant.grant_id,
            root_grant_version=grant.version, root_grant_digest=canonical_digest(grant)))
    parsed = _policy_from_payload(profile)
    from sylanne3.host.authority_profile import _d13_wire_policy_from_payload, _d13_wire_counter_from_payload
    _d13_wire_policy_from_payload(profile, parsed)
    _d13_wire_counter_from_payload(profile)
    if len(canonical(profile)) > 32768:
        raise ValueError("generated profile exceeds protected profile limit")
    return profile


def preflight_profile(args, request):
    """Validate real pinned assets and full policy before touching system paths."""
    from sylanne3.host.affect_scheme_asset import load_verified_affect_scheme
    archive_manifest(args.package, args.package_sha256, args.manifest_sha256)
    if request["schema"] == "sylanne3.linux-install-request.v6":
        _read_artifact_v3_assets_v1(request, installation_id="installation:preflight-only",
            manifest_pin=args.manifest_sha256)
    if request["schema"] in {"sylanne3.linux-install-request.v3", "sylanne3.linux-install-request.v4", "sylanne3.linux-install-request.v5", "sylanne3.linux-install-request.v6"}:
        verify_host_process_command_v3(request["host_process_command"])
    with tempfile.TemporaryDirectory(prefix="sylanne-install-preflight-") as directory:
        with zipfile.ZipFile(args.package) as archive:
            archive.extractall(directory)
        affect = load_verified_affect_scheme(Path(directory), args.manifest_sha256)
        make_profile(request, manifest_pin=args.manifest_sha256,
            authority_id="authority:preflight-only", installation_id="installation:preflight-only",
            registry=affect.registry.type_registry, scheme=affect.scheme)


def configure_draft_inventory_v4(request, inventory, directories):
    """Declare the actual generated export surface; no live DraftRoot is issued."""
    if request["schema"] not in {"sylanne3.linux-install-request.v4", "sylanne3.linux-install-request.v6"} or request["artifact_draft"] is None:
        return inventory
    from sylanne3.runtime_contracts import canonical_digest
    selected = [resource for resource in inventory.resources if resource.resource_id == "export"]
    if (len(selected) != 1 or selected[0].kind != "export"
            or selected[0].path != str(Path(directories["export"]).resolve())):
        raise ValueError("draft must bind the actual generated export resource")
    export = replace(selected[0], content_coverage=tuple(sorted({*selected[0].content_coverage, "jobs_drafts"})))
    resources = tuple(export if resource.resource_id == "export" else resource for resource in inventory.resources)
    commitment = canonical_digest(("sylanne3.c09.installation_filesystem_manifest.v2",
        inventory.authority_id, inventory.installation_id, inventory.namespace, resources))
    return replace(inventory, resources=resources, manifest_digest=commitment)


def install(args, request, manifest):
    from sylanne3.authority_service.linux_installation_security_v1 import require_linux_administrator_v1
    from sylanne3.authority_service.installed_policy_v2 import InstalledAuthorityPolicyV2
    from sylanne3.authority_service.installed_policy import InstalledPeerScopeV1
    from sylanne3.authority_service.installed_core_verifiers import installed_core_verifier_factory
    from sylanne3.authority_service.deployment_config import load_installed_asset_config_v1
    from sylanne3.authority_service.linux_bootstrap_v1 import initialize_fresh_authority_v1, build_initial_inventory_v1, bootstrap_current_storage_v1
    from sylanne3.authority_service.c09_storage_control_v1 import C09StorageControlV1, InstalledC09InstanceLeaseV1
    from sylanne3.host.affect_scheme_asset import load_verified_affect_scheme
    from sylanne3.graph_coordinator import namespace_ref
    from sylanne3.runtime_contracts import NamespaceId
    require_linux_administrator_v1()
    preflight_profile(args, request)
    root, config_dir = Path("/opt/sylanne"), Path("/etc/sylanne/authority")
    state, profile_root = Path("/var/lib/sylanne"), Path("/etc/sylanne/client/profiles")
    profile_dir = profile_root / request["profile_id"]
    if any(path.exists() for path in (root, config_dir, state, profile_dir)):
        raise FileExistsError("fresh installer will not overwrite an existing or interrupted installation")
    plugin = Path(request["astrbot_plugins_directory"]) / "astrbot_plugin_sylanne"
    if not plugin.parent.is_absolute() or not plugin.parent.is_dir() or plugin.exists() or plugin.is_symlink():
        raise ValueError("AstrBot plugins directory must exist and Sylanne target must be absent")
    for path in (root, config_dir, state, profile_dir, Path("/run/sylanne")):
        path.mkdir(parents=True, exist_ok=True, mode=0o755)
    code = root / "code"
    code.mkdir()
    with zipfile.ZipFile(args.package) as archive:
        archive.extractall(code)
    for directory, dirs, files in os.walk(code):
        os.chmod(directory, 0o755)
        for name in files:
            os.chmod(Path(directory) / name, 0o644)
    affect = load_verified_affect_scheme(code, args.manifest_sha256)
    namespace_id = NamespaceId(request["bot_id"], request["persona_id"])
    namespace = namespace_ref(namespace_id)
    installation_id = "installation:" + secrets.token_hex(16)
    make_profile(request, manifest_pin=args.manifest_sha256, authority_id="authority:pending-bootstrap",
        installation_id=installation_id, registry=affect.registry.type_registry, scheme=affect.scheme)
    if request["schema"] == "sylanne3.linux-install-request.v6":
        _stage_artifact_v3_assets_v1(request, profile_dir=profile_dir,
            installation_id=installation_id, manifest_pin=args.manifest_sha256, gid=request["host_gid"])
    ca, authority, host = tls_material()
    cert_dir = config_dir / "certificates"
    cert_dir.mkdir(mode=0o700)
    for name, value in (("ca.pem", ca), ("server.pem", authority[0]), ("server.key", authority[1]),
                        ("client.pem", authority[0]), ("client.key", authority[1])):
        write(cert_dir / name, value)
    gid = request["host_gid"]
    for name, value, mode in (("trust-root.pem", ca, 0o644), ("client-cert.pem", host[0], 0o644),
            ("client-key.pem", host[1], 0o640), ("reverse-trust-root.pem", ca, 0o644),
            ("reverse-cert.pem", host[0], 0o644), ("reverse-key.pem", host[1], 0o640),
            ("d02-signing.key", secrets.token_bytes(32), 0o640), ("d11-signing.key", secrets.token_bytes(32), 0o640),
            ("c04-signing.key", secrets.token_bytes(32), 0o640)):
        write(profile_dir / name, value, mode=mode, gid=gid)
    data = state / "genesis"
    data.mkdir(mode=0o755)
    files = {}
    for role in ("core", "deletion", "execution", "graph"):
        directory = data / role
        directory.mkdir(mode=0o700)
        files[role] = directory / (role + ".sqlite3")
    directories = {}
    for kind in ("controlled_backup", "export", "rebuild_temp", "cache"):
        path = state / kind
        path.mkdir(mode=0o755 if kind == "rebuild_temp" else 0o700)
        directories[kind] = path
    lock = config_dir / "authority.lock"
    write(lock, b"\0")
    holder = "host:" + request["profile_id"]
    installed = dict(certificate_sha256=host[2], profile_id=request["profile_id"], installation_id=installation_id,
        administrator_holder=holder, publisher_policy_ref="administrator:pinned-alpha1-package",
        service_capability_version="sylanne3.authority.v2", manifest_digest=args.manifest_sha256,
        source_id="linux:kernel-adjtimex:v1", max_utc_error_seconds=request["clock_error_seconds"])
    assets = dict(schema="sylanne3.authority.installed-assets.v1", authority_db=str(files["core"]),
        deletion_db=str(files["deletion"]), graph_db=str(files["graph"]), instance_lock=str(lock),
        bind_host="127.0.0.1", bind_port=request["authority_port"],
        tls=dict(certificate=str(cert_dir / "server.pem"), private_key=str(cert_dir / "server.key"),
            client_trust_root=str(cert_dir / "ca.pem"), timeout_seconds=30.0, max_message_bytes=1048576),
        execution_journals=[dict(namespace=namespace, path=str(files["execution"]), journal_id="execution:" + installation_id)],
        installations_v2=[installed], namespace_bindings_v2=[dict(certificate_sha256=host[2], profile_id=request["profile_id"],
            **asdict(namespace_id), authority_namespace=namespace)],
        reverse_handoff=[dict(namespace=namespace, profile_id=request["profile_id"], installation_id=installation_id,
            host="127.0.0.1", port=request["reverse_port"], server_name="localhost", expected_host_certificate_sha256=host[2],
            trust_root=str(cert_dir / "ca.pem"), client_certificate=str(cert_dir / "client.pem"), client_private_key=str(cert_dir / "client.key"),
            timeout_seconds=30.0, max_message_bytes=1048576, issuer_id="graph:" + installation_id)])
    if request.get("d13_counter_installation_v1") is not None:
        from sylanne3.authority_service.d13_installed_counter_factory_v1 import stage_initial_d13_counter_assets_v1
        initial_profile=make_profile(request,manifest_pin=args.manifest_sha256,authority_id="authority:pending-bootstrap",
            installation_id=installation_id,registry=affect.registry.type_registry,scheme=affect.scheme)
        assets["d13_counter_assets_v1"]=[stage_initial_d13_counter_assets_v1(
            spec=request["d13_counter_installation_v1"],profile=initial_profile,package_root=code,
            namespace_root=config_dir/"d13-counter",writer=write)]
    temporary_assets = config_dir / "bootstrap-assets.json"
    write(temporary_assets, canonical(assets))
    auth = InstalledAuthorityPolicyV2(peer_scopes={host[2]: InstalledPeerScopeV1(namespace, holder)},
        profile_peers={request["profile_id"]: host[2]}, package_root=code, trusted_manifest_sha256=args.manifest_sha256)
    config = load_installed_asset_config_v1(temporary_assets, core_authorizer=auth.core_authorizer,
        core_verifier_factory=installed_core_verifier_factory, administrator_authorizer=auth.administrator_authorizer,
        publisher_manifest_verifier=auth.publisher_manifest_verifier, utc_clock=lambda: datetime.now(timezone.utc),
        local_administrator_credential=auth.local_administrator_credential)
    with InstalledC09InstanceLeaseV1(lock) as lease:
        identities = initialize_fresh_authority_v1(config, affect.registry.type_registry, instance_lease=lease)
        inventory = build_initial_inventory_v1(authority_id=identities["authority_id"], installation_id=installation_id,
            namespace=namespace, files=files, directories=directories)
        inventory = configure_draft_inventory_v4(request, inventory, directories)
        inventory_path = config_dir / "filesystem-inventory.json"
        write(inventory_path, canonical(asdict(inventory)))
        key = config_dir / "storage-control.key"
        write(key, secrets.token_bytes(32))
        control_config = dict(control_path=str(config_dir / "storage-control.sqlite3"), key_path=str(key),
            installation_id=installation_id, authority_id=identities["authority_id"], control_store_id="control:" + installation_id,
            key_id="control-key:" + installation_id, resource_roots=[str(state)])
        control = C09StorageControlV1(**control_config, lease=lease)
        bootstrap_current_storage_v1(control=control, files=files, inventory=inventory,
            identities=dict(core=identities["authority_id"], deletion=identities["deletion_journal_id"],
                execution=identities["execution_journal_id"], graph="unprovisioned:" + installation_id))
        assets["c09_storage_v1"] = control_config
    # Only business Graph is writable by the installed non-root Host.
    os.chown(files["graph"], request["host_uid"], gid)
    os.chmod(files["graph"], 0o600)
    os.chown(files["graph"].parent, 0, gid)
    os.chmod(files["graph"].parent, 0o770)
    for role in ("core", "deletion", "execution"):
        os.chmod(files[role], 0o600)
    profile = make_profile(request, manifest_pin=args.manifest_sha256, authority_id=identities["authority_id"],
        installation_id=installation_id, registry=affect.registry.type_registry, scheme=affect.scheme)
    profile["reverse_handoff"] = dict(profile_id=request["profile_id"], listen_host="127.0.0.1", endpoint_host="127.0.0.1",
        port=request["reverse_port"], server_name="localhost", expected_authority_certificate_sha256=authority[2])
    write(profile_dir / "profile.json", canonical(profile), mode=0o644)
    socket_path = "/run/sylanne/host-admission.sock"
    write(profile_dir / "c09-storage.json", canonical(dict(schema="sylanne3.c09.host-storage-admission.v1",
        socket_path=socket_path, installation_id=installation_id, authority_id=identities["authority_id"], host_uid=request["host_uid"])), mode=0o644)
    assets["c04_installations_v3"] = [dict(namespace=namespace, package_root=str(code), formal_manifest_sha256=args.manifest_sha256,
        component_key_path=str(profile_dir / "c04-signing.key"))]
    write(config_dir / "assets.json", canonical(assets))
    deployment = dict(schema="sylanne3.authority.linux-deployment.v1", assets_path=str(config_dir / "assets.json"),
        package_root=str(code), trusted_manifest_sha256=args.manifest_sha256, profile_id=request["profile_id"],
        inventory_path=str(inventory_path), inventory_sha256=hashlib.sha256(inventory_path.read_bytes()).hexdigest(),
        host_uid=request["host_uid"], host_gid=gid, admission_socket=socket_path,
        target_directory=str(directories["rebuild_temp"]), provider_cache=request["provider_cache"],
        host_lifecycle=request["host_lifecycle"],
        host_observation=dict(adapter_ref=request["onebot_adapter_ref"], account_ref=json.dumps(request["onebot_account"], separators=(",", ":")),
            clock_source_ref="linux:kernel-adjtimex:v1"))
    process = request["schema"] in {"sylanne3.linux-install-request.v3", "sylanne3.linux-install-request.v4", "sylanne3.linux-install-request.v5", "sylanne3.linux-install-request.v6"}
    if process:
        deployment["schema"] = "sylanne3.authority.linux-deployment.v2"
    else:
        deployment["host_systemd_unit"] = request["host_systemd_unit"]
        write(config_dir / "deployment.json", canonical(deployment))
    unit = f'''[Unit]\nDescription=Sylanne alpha1 independent Authority\nAfter=network.target time-sync.target\nWants=time-sync.target\n\n[Service]\nType=simple\nUser=root\nGroup=root\nWorkingDirectory={root}\nExecStart={sys.executable} -B {root}/bootstrap/authority_entry.py\nRestart=on-failure\nRestartSec=2\nRuntimeDirectory=sylanne\nRuntimeDirectoryMode=0755\nUMask=0077\nEnvironment=PYTHONDONTWRITEBYTECODE=1\nKillMode=control-group\nTimeoutStopSec=90\n\n[Install]\nWantedBy=multi-user.target\n'''
    unit_path = config_dir / "sylanne-authority.service"
    if not process:
        write(unit_path, unit.encode(), mode=0o644)
    from scripts.alpha1.install_linux_cohort_v2 import install_fixed_cohort_v2
    with InstalledC09InstanceLeaseV1(lock) as lease:
        control = C09StorageControlV1(**control_config, lease=lease)
        cohort_result = install_fixed_cohort_v2(code=code, profile_dir=profile_dir,
            config_dir=config_dir, control=control, authority_unit_bytes=None if process else unit.encode(), writer=write,
            deployment=deployment if process else None,
            process_command=request["host_process_command"] if process else None)
    plugin.symlink_to(root / 'bootstrap' / 'host', target_is_directory=True)
    print(json.dumps(dict(status="installed_service_stopped", authority_id=identities["authority_id"],
        deployment=cohort_result['deployment'], package_selection=cohort_result['selection'],
        bootstrap_root=cohort_result['bootstrap_root'], systemd_unit_source=None if process else str(unit_path),
        process_supervision=cohort_result.get('process_supervision'),
        next=("Start the fixed root launcher as PID1 in an explicitly isolated PID/mount/proc namespace"
              if process else "Install the generated unit, run daemon-reload, then start sylanne-authority.service explicitly"))))


def request_template_v2():
    from sylanne3.runtime.d04_semantic_policy import MAPPING_VERSION, BASIS_VERSION, MECHANISMS
    return dict(schema="sylanne3.linux-install-request.v2", profile_id="FILL_PROFILE", bot_id="FILL_BOT", persona_id="FILL_PERSONA",
        host_uid=0, host_gid=0, host_systemd_unit="astrbot.service", astrbot_plugins_directory="/FILL/astrbot/data/plugins",
        authority_port=19443, reverse_port=19444, workbench_origin="https://FILL_HOST", clock_error_seconds=1.0,
        provider_id="FILL_PROVIDER", model_id="FILL_MODEL", provider_config_path="/FILL/private-provider-config.json",
        model_quote={"output_tokens": 0}, local_quote={"cpu_ms": 0, "thread_cpu_ms": 0},
        budget_limits={"output_tokens": 0, "cpu_ms": 0, "thread_cpu_ms": 0},
        budget_max_ceiling={"output_tokens": 0, "cpu_ms": 0, "thread_cpu_ms": 0}, currency="FILL_BUDGET_UNIT",
        budget_valid_until_utc=0.0, model_audiences=["owner"],
        onebot_account=["FILL_PLATFORM", "aiocqhttp", "FILL_ACCOUNT"], onebot_adapter_ref="FILL_ADAPTER",
        provider_cache={"provider_id": "FILL_PROVIDER"},
        host_lifecycle={"supervisor": {"unit_name": "astrbot.service", "systemctl_path": "/usr/bin/systemctl",
            "unit_fragment_path": "/FILL/canonical/astrbot.service", "unit_fragment_sha256": "0" * 64,
            "control_group": "/system.slice/astrbot.service", "timeout_seconds": 60}, "drain_timeout_seconds": 300},
        d04_semantic_drive={"version": 1, "mapping_version": MAPPING_VERSION, "basis_version": BASIS_VERSION,
            "mechanism_max_abs_doses": {name: [0.0, 0.0, 0.0] for name in MECHANISMS},
            "mechanism_max_family_share": {name: 0.0 for name in MECHANISMS}},
        d04_joint_numeric={"version": 3, "cpu_ceiling_ms": 0, "max_iterations": 0, "tolerance": 0.0, "job_lifetime_seconds": 0},
        d13_wire_policy=None, d13_wire_counter=None, d13_precompression=None, d13_paid_precompression=None,
        d07_cognition=None)


def request_template_v3():
    value = request_template_v2()
    value["schema"] = "sylanne3.linux-install-request.v3"
    value.pop("host_systemd_unit")
    value["host_lifecycle"] = {"drain_timeout_seconds": 300}
    value["host_process_command"] = dict(
        fixed_executable_path="/FILL/canonical/python", executable_sha256="0" * 64,
        fixed_entry_ref="/FILL/canonical/host-entry.py", entry_sha256="0" * 64,
        fixed_argv=["/FILL/canonical/python", "-B", "/FILL/canonical/host-entry.py"],
        fixed_cwd="/FILL/protected/host", finite_environment_policy={"PYTHONDONTWRITEBYTECODE": "1"},
        maximum_processes=16, start_timeout=60, drain_timeout=60)
    return value


def request_template_v4():
    """Explicit configuration template; no natural window or draft rights default."""
    value = request_template_v3()
    value["schema"] = "sylanne3.linux-install-request.v4"
    value["foreground"] = dict(schema="sylanne.foreground-policy.v1", version=1,
        call_plan_schema="d11.foreground-call-plan.v1", max_calls=6, max_auxiliary_calls=2,
        selected_steps=1, policy_ref="policy:foreground.v1", policy_version=1,
        deadline_policy=dict(schema="sylanne.foreground-deadline-policy.v1", natural=None, draft_mode=None))
    value["artifact_draft"] = None
    return value


def request_template_v5():
    from sylanne3.model_broker.natural_reply_history_v7 import TEMPLATE_VERSION
    from sylanne3.model_broker.natural_review import REVIEW_TEMPLATE_VERSION_V2
    value = request_template_v4()
    value["schema"] = "sylanne3.linux-install-request.v5"
    value["natural_template_pair_v1"] = {"schema": "sylanne3.initial-natural-template-pair.v1",
        "generation": TEMPLATE_VERSION, "review": REVIEW_TEMPLATE_VERSION_V2}
    value["general_growth_cognition"] = None
    value["habit_runtime"] = False
    return value


def configuration_plan_v4(request):
    """Review static scopes and exact budgets without issuing a responsibility."""
    if request["schema"] not in {"sylanne3.linux-install-request.v4", "sylanne3.linux-install-request.v5", "sylanne3.linux-install-request.v6"}:
        return None
    kinds = ["d11.foreground_cycle.v1"]
    if request["schema"] in {"sylanne3.linux-install-request.v5", "sylanne3.linux-install-request.v6"}:
        from sylanne3.authority_service.conditioned_child_contract_v1 import ROOT_WORK_KIND
        kinds.append(ROOT_WORK_KIND)
        if request.get("habit_runtime", False):
            kinds.extend(("habit_subscription_v1", "d10.life.source_note.v1"))
    draft = request["artifact_draft"]
    if request["schema"] in {"sylanne3.linux-install-request.v5", "sylanne3.linux-install-request.v6"} and request["general_growth_cognition"] is not None:
        kinds.append("d07.cognition")
    if draft is not None:
        kinds.extend(("artifact_draft_v1", "d10.life.artifact_draft.v1"))
        if draft["observation_policy"] is not None:
            kinds.append("d11.life.artifact_observation.v1")
    if request["schema"] == "sylanne3.linux-install-request.v6" and "d07.cognition" not in kinds:
        kinds.append("d07.cognition")
    return dict(foreground=request["foreground"], artifact_draft=draft,
        **({name: request[name] for name in ("artifact_observation_cognition", "artifact_phase_observer", "artifact_phase_counter")}
            if request["schema"] == "sylanne3.linux-install-request.v6" else {}),
        **({"habit_runtime": request.get("habit_runtime", False)}
            if request["schema"] in {"sylanne3.linux-install-request.v5", "sylanne3.linux-install-request.v6"} else {}),
        **({"astrbot_namespace_v1": request["astrbot_namespace_v1"]} if "astrbot_namespace_v1" in request else {}),
        **({"d06_recall": request["d06_recall"]} if "d06_recall" in request else {}),
        **({"natural_template_pair_v1": request["natural_template_pair_v1"]}
           if request.get("natural_template_pair_v1") is not None else {}),
        **({"general_growth_cognition": request["general_growth_cognition"]}
           if request["schema"] in {"sylanne3.linux-install-request.v5", "sylanne3.linux-install-request.v6"} else {}),
        installed_export_path="/var/lib/sylanne/export" if draft is not None else None,
        added_work_kinds=kinds, root_budget_limits=request["budget_limits"],
        root_budget_max_ceiling=request["budget_max_ceiling"],
        configuration_is_live_permission=False,
        dynamic_draft_scope="actual_current_owner_source_registration_required")



ARTIFACT_V3_REQUEST_SCHEMA = "sylanne3.linux-install-request.v6"
ARTIFACT_COUNTER_INITIAL_SCHEMA = "sylanne3.initial-artifact-phase-counter.v1"
_ARTIFACT_COUNTER_FIELDS = frozenset({
    "schema", "source_scope", "model_revision", "counter_policy_id", "counter_policy_version",
    "executable", "program_sha256", "counter_public_key_hex", "tokenizer_path", "tokenizer_sha256",
    "applicability_path", "applicability_sha256", "encoding_rule_id", "encoding_rule_sha256", "timeout_seconds"})



def validate_artifact_v3_asset_descriptors_v1(request):
    observer = request.get("artifact_phase_observer")
    counter = request.get("artifact_phase_counter")
    if (type(observer) is not dict
            or set(observer) != {"schema", "observer_id", "observer_version", "asset_ref", "asset_sha256"}
            or observer["schema"] != "sylanne.artifact-phase-observer-installation.v2"):
        raise ValueError("exact protected observer descriptor required")
    if (type(counter) is not dict or set(counter) != _ARTIFACT_COUNTER_FIELDS
            or counter["schema"] != ARTIFACT_COUNTER_INITIAL_SCHEMA or counter["source_scope"] != "production"):
        raise ValueError("exact production external-counter descriptor required")
    for path in (observer["asset_ref"], counter["executable"], counter["tokenizer_path"], counter["applicability_path"]):
        if type(path) is not str or not PurePosixPath(path).is_absolute() or ".." in PurePosixPath(path).parts:
            raise ValueError("explicit absolute protected asset path required")
    return request


def _artifact_v3_configuration_v1(request, *, installation_id, manifest_pin, config_digest, installed_paths):
    """Bind explicit assets to this fresh identity without editing any approved budget."""
    from sylanne3.host.authority_profile import artifact_draft_policy_from_payload_v1, AdminArtifactDraftPolicyV3, installed_model_config_ref
    from sylanne3.host.artifact_draft_paired_policy_v4 import AdminArtifactDraftPairedPolicyV4
    from sylanne3.host.model_workflows_v4 import model_workflow_v4_from_payload
    from sylanne3.host.artifact_phase_observer_policy_v2 import ArtifactPhaseObserverPolicyV2, INSTALLATION_SCHEMA
    from sylanne3.model_broker.artifact_phase_count_v1 import ArtifactPhaseCountPolicyV1
    from sylanne3.runtime_contracts import NamespaceId, canonical_digest
    from sylanne3.model_broker.d07_cognition_v1 import TEMPLATE_VERSION, WORK_KIND
    validate_artifact_v3_asset_descriptors_v1(request)
    draft = artifact_draft_policy_from_payload_v1(request["artifact_draft"])
    if type(draft) not in {AdminArtifactDraftPolicyV3, AdminArtifactDraftPairedPolicyV4}:
        raise ValueError("V6 requires an explicit installed phase-capable Artifact policy")
    phase = draft.phase_model_workflow
    observation = model_workflow_v4_from_payload(request["artifact_observation_cognition"])
    if ((observation.work_kind, observation.purpose, observation.template_version) != (WORK_KIND, "proposal", TEMPLATE_VERSION)
            or set(observation.quote_ceiling) != {"input_tokens", "output_tokens", "model_tokens", "model_microusd"}
            or observation.quote_ceiling["input_tokens"] > 6000 or observation.quote_ceiling["output_tokens"] > 1000
            or observation.quote_ceiling["model_tokens"] > 7000 or observation.max_output_tokens > 1000):
        raise ValueError("V6 independent D07 workflow differs from its fixed registered quote")
    for workflow in (draft.model_workflow, phase, observation):
        if (workflow.provider_id, workflow.model_id, workflow.provider_config_digest, workflow.provider_config_ref) != (
                request["provider_id"], request["model_id"], config_digest,
                installed_model_config_ref(request["provider_id"], request["model_id"], config_digest)):
            raise ValueError("V6 workflows must retain the actual selected provider/model/configuration")
        if any(amount > min(request["budget_limits"].get(name, 0), request["budget_max_ceiling"].get(name, 0))
                for name, amount in workflow.quote_ceiling.items()):
            raise ValueError("V6 workflow quote exceeds the original approved Root")
    if (set(request["model_quote"]) != {"input_tokens", "output_tokens", "model_tokens", "model_microusd"}
            or set(phase.quote_ceiling) != {"input_tokens", "output_tokens", "model_tokens", "model_microusd"}
            or request["model_quote"].get("input_tokens", 0) > 6000
            or request["model_quote"].get("output_tokens", 0) > 800
            or phase.quote_ceiling.get("input_tokens", 0) > 10000
            or phase.quote_ceiling.get("output_tokens", 0) > 2000):
        raise ValueError("V6 C1/C2/C4 quotes exceed their unchanged episode slots")
    spec = request["artifact_phase_observer"]
    if (type(spec) is not dict or set(spec) != {"schema", "observer_id", "observer_version", "asset_ref", "asset_sha256"}
            or spec["schema"] != INSTALLATION_SCHEMA):
        raise ValueError("V6 requires its exact protected independent observer specification")
    directory = PurePosixPath("/etc/sylanne/client/profiles") / request["profile_id"] / "artifact-v3"
    observer_ref = str(directory / "observer.json") if installed_paths else spec["asset_ref"]
    observer = ArtifactPhaseObserverPolicyV2(spec["observer_id"], spec["observer_version"],
        observer_ref, spec["asset_sha256"], canonical_digest(observation))
    counter_spec = request["artifact_phase_counter"]
    if (type(counter_spec) is not dict or set(counter_spec) != _ARTIFACT_COUNTER_FIELDS
            or counter_spec["schema"] != ARTIFACT_COUNTER_INITIAL_SCHEMA or counter_spec["source_scope"] != "production"):
        raise ValueError("V6 requires an explicit production external-counter contract; LOCAL_FIXTURE is not installable")
    values = {name: value for name, value in counter_spec.items() if name != "schema"}
    if installed_paths:
        values.update(executable=str(directory / "counter"), tokenizer_path=str(directory / "tokenizer"),
            applicability_path=str(directory / "applicability.json"))
    counter = ArtifactPhaseCountPolicyV1(namespace=NamespaceId(request["bot_id"], request["persona_id"]),
        installation_id=installation_id, manifest_digest=manifest_pin, profile_id=request["profile_id"],
        provider_id=phase.provider_id, model_id=phase.model_id, provider_config_digest=phase.provider_config_digest,
        template_version=phase.template_version, **values)
    return observation, observer, counter


def _read_artifact_v3_assets_v1(request, *, installation_id, manifest_pin):
    """Read pinned administrator input; no counter program or model is executed."""
    from sylanne3.authority_service.linux_installation_security_v1 import opened_installed_file_v1
    from sylanne3.authority_service.artifact_phase_counter_v1 import artifact_phase_applicability_wire_v1, _unique_json
    from sylanne3.host.artifact_phase_observer_policy_v2 import artifact_phase_observer_from_asset_v2
    from sylanne3.runtime_contracts import canonical_digest
    config = json.loads(Path(request["provider_config_path"]).read_bytes())
    if type(config) is not dict or (config.get("id"), config.get("model")) != (request["provider_id"], request["model_id"]):
        raise ValueError("V6 provider configuration differs from its declared selected identity")
    workflow, observer, counter = _artifact_v3_configuration_v1(request,
        installation_id=installation_id, manifest_pin=manifest_pin,
        config_digest=canonical_digest(config), installed_paths=False)
    assets = {}
    for name, source, pin in (
            ("observer.json", observer.asset_ref, observer.asset_digest),
            ("counter", counter.executable, counter.program_sha256),
            ("tokenizer", counter.tokenizer_path, counter.tokenizer_sha256),
            ("applicability.json", counter.applicability_path, counter.applicability_sha256)):
        with opened_installed_file_v1(source) as fd:
            with os.fdopen(os.dup(fd), "rb") as stream:
                content = stream.read()
        if hashlib.sha256(content).hexdigest() != pin:
            raise ValueError("V6 declared asset bytes differ: " + name)
        assets[name] = (source, pin, content)
    actual = artifact_phase_observer_from_asset_v2(asset_ref=observer.asset_ref,
        asset_bytes=assets["observer.json"][2], expected_digest=observer.asset_digest)
    if actual != observer:
        raise ValueError("V6 protected observer differs from its exact named workflow and completion policy")
    if json.loads(assets["applicability.json"][2], object_pairs_hook=_unique_json) != artifact_phase_applicability_wire_v1(counter):
        raise ValueError("V6 external-counter applicability differs from its actual model/rule/program")
    if not os.access(counter.executable, os.X_OK):
        raise ValueError("V6 declared external counter is not executable")
    return assets


def _stage_artifact_v3_assets_v1(request, *, profile_dir, installation_id, manifest_pin, gid):
    assets = _read_artifact_v3_assets_v1(request, installation_id=installation_id, manifest_pin=manifest_pin)
    directory = profile_dir / "artifact-v3"
    directory.mkdir(mode=0o755)
    pins = []
    for name, (source, pin, content) in assets.items():
        destination = directory / name
        write(destination, content, mode=0o755 if name == "counter" else 0o644, gid=gid)
        pins.append({"path": str(destination), "source": source, "sha256": pin, "bytes": len(content)})
    write(directory / "asset-pins.json", canonical({
        "schema": "sylanne3.initial-artifact-v3-assets.v1", "installation_id": installation_id,
        "manifest_digest": manifest_pin, "profile_id": request["profile_id"], "files": pins}), mode=0o644, gid=gid)


def request_template_v6():
    """Intentionally incomplete fresh V9 request; supply real approved assets and quotes."""
    value = request_template_v5()
    value.update(schema=ARTIFACT_V3_REQUEST_SCHEMA, artifact_observation_cognition=None,
        artifact_phase_observer=None, artifact_phase_counter=None)
    return value



def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--template", action="store_true", help="Print an intentionally non-installable template; every limit requires review")
    parser.add_argument("--template-version", choices=(2, 3, 4, 5, 6), type=int, default=2)
    parser.add_argument("--package", type=Path)
    parser.add_argument("--package-sha256")
    parser.add_argument("--manifest-sha256")
    parser.add_argument("--request", type=Path)
    parser.add_argument("--model-selection", type=Path,
                        help="public current Host LLM observation; binds a fresh installation plan to the exact local provider config")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--install", action="store_true")
    mode.add_argument("--plan", action="store_true", help="Validate the pinned package and full policy without installing")
    args = parser.parse_args()
    if args.template:
        if args.install:
            parser.error("--template cannot install")
        template = {2: request_template_v2, 3: request_template_v3, 4: request_template_v4, 5: request_template_v5, 6: request_template_v6}[args.template_version]()
        print(json.dumps(template, ensure_ascii=False, indent=2))
        return
    if any(value is None for value in (args.package, args.package_sha256, args.manifest_sha256, args.request)):
        parser.error("package, external package/manifest hashes and explicit request are required")
    request = check_request(json.loads(args.request.read_bytes()))
    selection = None
    if args.model_selection is not None:
        from sylanne3.host.model_selection import parse_host_model_selection_v1
        raw_selection = args.model_selection.read_bytes()
        if len(raw_selection) > 4096:
            parser.error("model selection exceeds its public input bound")
        value = json.loads(raw_selection)
        request = selected_model_request_v1(request, value)
        selection = parse_host_model_selection_v1(value)
    manifest = archive_manifest(args.package, args.package_sha256, args.manifest_sha256)
    if not args.install:
        preflight_profile(args, request)
        print(json.dumps(dict(status="plan_only", package_sha256=args.package_sha256, manifest_sha256=args.manifest_sha256,
            model_selection=selection.to_dict() if selection is not None else None,
            **({"foreground_configuration": configuration_plan_v4(request)} if request["schema"] in {"sylanne3.linux-install-request.v4", "sylanne3.linux-install-request.v5", "sylanne3.linux-install-request.v6"} else {}),
            configuration_semantics="fresh_install_only; existing installations require the qualified package/configuration change protocol",
            changes=["new /opt/sylanne code", "new /etc/sylanne service/profile and local credentials", "new /var/lib/sylanne four-store cohort",
                     "AstrBot plugin link", ("fixed process supervisor specs staged; no process started"
                          if request["schema"] in {"sylanne3.linux-install-request.v3", "sylanne3.linux-install-request.v4", "sylanne3.linux-install-request.v5", "sylanne3.linux-install-request.v6"}
                         else "systemd unit staged, not enabled or started")], model_calls=0, platform_sends=0)))
        return
    install(args, request, manifest)


if __name__ == "__main__":
    main()
