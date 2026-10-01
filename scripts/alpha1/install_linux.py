"""Verify and install a pinned Sylanne alpha1 bundle into a new Linux cohort.

Run --plan first. Installation is explicit, fresh-only, and never sends model
or platform traffic. Starting the generated systemd unit is a separate action.
"""
from __future__ import annotations

import argparse
from dataclasses import asdict
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


def check_request(request):
    fields = {"schema", "profile_id", "bot_id", "persona_id", "host_uid", "host_gid", "host_systemd_unit",
        "astrbot_plugins_directory", "authority_port", "reverse_port", "workbench_origin", "clock_error_seconds",
        "provider_id", "model_id", "provider_config_path", "model_quote", "local_quote", "budget_limits",
        "budget_max_ceiling", "currency", "budget_valid_until_utc", "model_audiences", "onebot_account",
        "onebot_adapter_ref", "provider_cache", "host_lifecycle", "d04_semantic_drive", "d04_joint_numeric",
        "d13_wire_policy", "d13_wire_counter", "d13_precompression", "d13_paid_precompression", "d07_cognition"}
    if set(request) != fields or request["schema"] != "sylanne3.linux-install-request.v2":
        raise ValueError("installation request fields differ; use the bundled request template")
    for name in ("profile_id", "bot_id", "persona_id"):
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", request[name]):
            raise ValueError(name + " is invalid")
    if not re.fullmatch(r"[A-Za-z0-9_.@-]+\.service", request["host_systemd_unit"]):
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
    if (type(life) is not dict or set(life) != {"supervisor", "drain_timeout_seconds"}
            or type(life["drain_timeout_seconds"]) is not int or not 1 <= life["drain_timeout_seconds"] <= 3600):
        raise ValueError("explicit bounded installed lifecycle supervision required")
    supervisor = D12SystemdSupervisorConfigV1(**life["supervisor"])
    if supervisor.unit_name != request["host_systemd_unit"]:
        raise ValueError("lifecycle and Host unit differ")
    for name in ("d04_semantic_drive", "d04_joint_numeric"):
        if type(request[name]) is not dict or not request[name]:
            raise ValueError("full alpha1 requires explicit " + name)
    for name in ("d13_wire_policy", "d13_wire_counter", "d13_precompression", "d13_paid_precompression", "d07_cognition"):
        if request[name] is not None and type(request[name]) is not dict:
            raise ValueError(name + " must be an explicit object or null")
    if request["d13_wire_counter"] is not None and request["d13_wire_policy"] is None:
        raise ValueError("counter requires its explicit signed full-wire policy")
    if (type(request["provider_cache"]) is not dict
            or request["provider_cache"].get("provider_id") != request["provider_id"]):
        raise ValueError("cache adapter must cover the installed model provider")
    return request


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
    from sylanne3.model_broker.natural_reply_history_v4 import TEMPLATE_VERSION
    from sylanne3.model_broker.natural_review import REVIEW_TEMPLATE_VERSION
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
    workflows = {"version": 2}
    for name, kind, purpose, template in (("encode", "d06.encode_source", "consolidation", FIRST_INGRESS_ENCODING_TEMPLATE_VERSION),
        ("reply", "reply", "proposal", REPLY_TEMPLATE_VERSION), ("natural_generation", "natural_generation", "proposal", TEMPLATE_VERSION),
        ("natural_review", "natural_review", "proposal", REVIEW_TEMPLATE_VERSION), ("appraisal", APPRAISAL_KIND, "proposal", APPRAISAL_VERSION)):
        workflows[name] = {**common, "work_kind": kind, "purpose": purpose, "template_version": template}
    if request['d07_cognition'] is not None:
        workflows['d07_cognition'] = dict(request['d07_cognition'])
        if any(workflows['d07_cognition'].get(name) != common[name]
               for name in ('provider_id', 'model_id', 'provider_config_ref', 'provider_config_digest')):
            raise ValueError('D07 cognition must explicitly match the installed main provider configuration')
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
        if request[setting] is not None:
            kinds.append(kind)
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
    if request["d13_wire_policy"] is not None:
        configured = dict(request["d13_wire_policy"])
        if configured.get("installation") != "$current_installation":
            raise ValueError("fresh D13 policy must explicitly bind $current_installation")
        configured["installation"] = dict(installation_id=installation_id, provider_config_digest=config_digest,
            provider_id=request["provider_id"], model_id=request["model_id"],
            max_output_tokens=request["model_quote"]["output_tokens"])
        profile["d13_wire_policy"] = configured
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
    with tempfile.TemporaryDirectory(prefix="sylanne-install-preflight-") as directory:
        with zipfile.ZipFile(args.package) as archive:
            archive.extractall(directory)
        affect = load_verified_affect_scheme(Path(directory), args.manifest_sha256)
        make_profile(request, manifest_pin=args.manifest_sha256,
            authority_id="authority:preflight-only", installation_id="installation:preflight-only",
            registry=affect.registry.type_registry, scheme=affect.scheme)


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
        host_uid=request["host_uid"], host_gid=gid, host_systemd_unit=request["host_systemd_unit"], admission_socket=socket_path,
        target_directory=str(directories["rebuild_temp"]), provider_cache=request["provider_cache"],
        host_lifecycle=request["host_lifecycle"],
        host_observation=dict(adapter_ref=request["onebot_adapter_ref"], account_ref=json.dumps(request["onebot_account"], separators=(",", ":")),
            clock_source_ref="linux:kernel-adjtimex:v1"))
    write(config_dir / "deployment.json", canonical(deployment))
    unit = f'''[Unit]\nDescription=Sylanne alpha1 independent Authority\nAfter=network.target time-sync.target\nWants=time-sync.target\n\n[Service]\nType=simple\nUser=root\nGroup=root\nWorkingDirectory={root}\nExecStart={sys.executable} -B {root}/bootstrap/authority_entry.py\nRestart=on-failure\nRestartSec=2\nRuntimeDirectory=sylanne\nRuntimeDirectoryMode=0755\nUMask=0077\nEnvironment=PYTHONDONTWRITEBYTECODE=1\nKillMode=control-group\nTimeoutStopSec=90\n\n[Install]\nWantedBy=multi-user.target\n'''
    unit_path = config_dir / "sylanne-authority.service"
    write(unit_path, unit.encode(), mode=0o644)
    from scripts.alpha1.install_linux_cohort_v2 import install_fixed_cohort_v2
    with InstalledC09InstanceLeaseV1(lock) as lease:
        control = C09StorageControlV1(**control_config, lease=lease)
        cohort_result = install_fixed_cohort_v2(code=code, profile_dir=profile_dir,
            config_dir=config_dir, control=control, authority_unit_bytes=unit.encode(), writer=write)
    plugin.symlink_to(root / 'bootstrap' / 'host', target_is_directory=True)
    print(json.dumps(dict(status="installed_service_stopped", authority_id=identities["authority_id"],
        deployment=cohort_result['deployment'], package_selection=cohort_result['selection'],
        bootstrap_root=cohort_result['bootstrap_root'], systemd_unit_source=str(unit_path),
        next="Install the generated unit, run daemon-reload, then start sylanne-authority.service explicitly")))


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
        onebot_account={"self_id": "FILL_ACCOUNT"}, onebot_adapter_ref="FILL_ADAPTER",
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--template", action="store_true", help="Print an intentionally non-installable template; every limit requires review")
    parser.add_argument("--package", type=Path)
    parser.add_argument("--package-sha256")
    parser.add_argument("--manifest-sha256")
    parser.add_argument("--request", type=Path)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--install", action="store_true")
    mode.add_argument("--plan", action="store_true", help="Validate the pinned package and full policy without installing")
    args = parser.parse_args()
    if args.template:
        if args.install:
            parser.error("--template cannot install")
        print(json.dumps(request_template_v2(), ensure_ascii=False, indent=2))
        return
    if any(value is None for value in (args.package, args.package_sha256, args.manifest_sha256, args.request)):
        parser.error("package, external package/manifest hashes and explicit request are required")
    request = check_request(json.loads(args.request.read_bytes()))
    manifest = archive_manifest(args.package, args.package_sha256, args.manifest_sha256)
    if not args.install:
        preflight_profile(args, request)
        print(json.dumps(dict(status="plan_only", package_sha256=args.package_sha256, manifest_sha256=args.manifest_sha256,
            changes=["new /opt/sylanne code", "new /etc/sylanne service/profile and local credentials", "new /var/lib/sylanne four-store cohort",
                     "AstrBot plugin link", "systemd unit staged, not enabled or started"], model_calls=0, platform_sends=0)))
        return
    install(args, request, manifest)


if __name__ == "__main__":
    main()
