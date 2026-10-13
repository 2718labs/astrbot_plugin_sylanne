"""Administrator profile loading never takes trust material from chat settings."""

from __future__ import annotations

import importlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import types
from types import SimpleNamespace
from unittest.mock import patch

import pytest

# Keep this test independent of an installed AstrBot host. Loading the two
# transport modules needs a package path, but not host/__init__.py (which
# imports AstrBot UI classes).
_host_package = sys.modules.get("sylanne3.host")
if _host_package is None:
    _host_package = types.ModuleType("sylanne3.host")
    _host_package.__path__ = [str(Path(__file__).resolve().parents[2] /
                                  "sylanne3" / "host")]
    sys.modules["sylanne3.host"] = _host_package
try:
    from sylanne3.host import authority_profile
    from sylanne3.host.mtls_transport import AuthorityTlsProfile, MtlsAuthorityTransport
finally:
    if _host_package is not None and not hasattr(_host_package, "__file__"):
        sys.modules.pop("sylanne3.host", None)


def _provision(root: Path, *, payload: dict[str, object] | None = None) -> Path:
    profile = root / "safe"
    profile.mkdir(parents=True)
    (profile / "profile.json").write_text(json.dumps(payload or {
        "schema": 1, "host": "127.0.0.1", "port": 9443,
        "server_name": "authority.example.org",
        "expected_authority_id": "authority:production",
    }), encoding="utf-8")
    for name in ("trust-root.pem", "client-cert.pem", "client-key.pem"):
        (profile / name).write_text("test fixture", encoding="ascii")
    return profile


def _schema2_payload() -> dict[str, object]:
    return {
        "schema": 2, "host": "127.0.0.1", "port": 9443,
        "server_name": "authority.example.org",
        "expected_authority_id": "authority:production",
        "installation_policy": {
            "namespace": {"bot_id": "bot-a", "persona_id": "persona-a"},
            "authority_namespace": "bot-a/persona-a",
            "installation_id": "install-a",
            "manifest_digest": "a" * 64,
            "administrator_holder": "holder-a",
            "expected_authority_id": "authority:production",
            "catalogue_hash": "b" * 64,
            "scheme_version": "scheme:v1",
            "operator_version": "operator:v1",
            "policy_version": "policy:v1",
            "root_lease": {
                "lease_id": "root-lease", "parent_id": None,
                "bot_id": "bot-a", "persona_id": "persona-a",
                "currency": "USD", "limits": {"tokens": 1000},
                "used": {}, "reserved": {}, "unconfirmed": {},
                "version": 1, "state": "active",
            },
            "root_grant": {
                "grant_id": "root-grant", "version": 1,
                "bot_id": "bot-a", "persona_id": "persona-a",
                "lease_id": "root-lease", "currency": "USD",
                "max_ceiling": {"tokens": 100},
                "allowed_work_kinds": ["reply"],
                "valid_until_utc": 4102444800,
                "policy_ref": "budget-policy:v1",
            },
        },
    }


def _source_correction_payload() -> dict[str, object]:
    payload = _schema2_payload()
    payload["d06_source_correction"] = {
        "deadline_after_seconds": 30,
        "quote_ceiling": {"tokens": 10},
        "snapshot_ref": "snapshot-a",
        "resource_ref": "resource-a",
    }
    payload["installation_policy"]["root_grant"]["allowed_work_kinds"].append(
        "d06.source_correction"
    )
    return payload


def test_source_correction_requires_installed_bounded_policy() -> None:
    legacy = _schema2_payload()
    authority_profile._policy_from_payload(legacy)
    assert authority_profile._d06_source_correction_from_payload(legacy) is None

    payload = _source_correction_payload()
    authority_profile._policy_from_payload(payload)
    correction = authority_profile._d06_source_correction_from_payload(payload)
    assert correction is not None
    assert correction.digest_payload() == payload["d06_source_correction"]
    with pytest.raises(TypeError):
        correction.quote_ceiling["tokens"] = 11


@pytest.mark.parametrize("mutation", (
    lambda p: p["installation_policy"]["root_grant"]["allowed_work_kinds"].remove(
        "d06.source_correction"),
    lambda p: p["d06_source_correction"].update(quote_ceiling={"tokens": 101}),
    lambda p: p["installation_policy"]["root_lease"].update(limits={"tokens": 9}),
    lambda p: p["d06_source_correction"].update(deadline_after_seconds=float("inf")),
    lambda p: p["d06_source_correction"].update(resource_ref="bad ref"),
    lambda p: p["d06_source_correction"].update(quote_ceiling={"tokens": True}),
    lambda p: p["d06_source_correction"].update(user_quote={"tokens": 10}),
))
def test_source_correction_rejects_invalid_or_user_supplied_price(mutation) -> None:
    payload = _source_correction_payload()
    mutation(payload)
    with pytest.raises(ValueError):
        authority_profile._policy_from_payload(payload)


def _model_workflow_payload(work_kind: str, purpose: str,
                            template: str) -> dict[str, object]:
    digest = "c" * 64
    return {
        "work_kind": work_kind, "provider_id": "provider-a",
        "model_id": "model-a",
        "provider_config_ref": authority_profile.installed_model_config_ref(
            "provider-a", "model-a", digest),
        "provider_config_digest": digest, "purpose": purpose,
        "audiences": ["private"], "privacy_tier": "private",
        "template_version": template, "required_capabilities": ["text"],
        "timeout_seconds": 20, "max_output_tokens": 32,
        "quote_ceiling": {"output_tokens": 32},
    }


def _workflow_profile_payload() -> dict[str, object]:
    payload = _schema2_payload()
    installation = payload["installation_policy"]
    installation["root_lease"]["limits"]["output_tokens"] = 128
    installation["root_grant"]["max_ceiling"]["output_tokens"] = 64
    installation["root_grant"]["allowed_work_kinds"] = [
        "d06.encode_source", "reply"]
    payload["ingress_encoding"] = {
        "deadline_after_seconds": 60, "quote_ceiling": {"output_tokens": 64},
        "snapshot_ref": "snapshot-a", "resource_ref": "resource-a",
        "character_interval_ref": "interval-a",
    }
    payload["model_workflows"] = {
        "version": 2,
        "encode": _model_workflow_payload(
            "d06.encode_source", "consolidation", "encode-template-v1"),
        "reply": _model_workflow_payload(
            "reply", "proposal", "reply-template-v1"),
    }
    return payload


def test_model_workflows_are_separate_bounded_admin_authorities() -> None:
    payload = _workflow_profile_payload()
    authority_profile._policy_from_payload(payload)
    workflows = authority_profile._model_workflows_from_payload(payload)
    assert workflows.version == 2
    assert workflows.encode.work_kind == "d06.encode_source"
    assert workflows.reply.work_kind == "reply"
    assert workflows.encode.template_version != workflows.reply.template_version
    assert workflows.encode.provider_config_ref == workflows.reply.provider_config_ref
    with pytest.raises(TypeError):
        workflows.encode.quote_ceiling["output_tokens"] = 100
    assert authority_profile._model_workflows_from_payload(_schema2_payload()) is None


def test_context_reply_workflow_is_explicit_and_version_pinned() -> None:
    payload = _workflow_profile_payload()
    payload["installation_policy"]["root_grant"]["allowed_work_kinds"].append(
        "context_reply")
    payload["model_workflows"]["context_reply"] = _model_workflow_payload(
        "context_reply", "proposal",
        authority_profile.CONTEXT_REPLY_TEMPLATE_VERSION)
    authority_profile._policy_from_payload(payload)
    workflows = authority_profile._model_workflows_from_payload(payload)
    assert workflows.context_reply.template_version == (
        authority_profile.CONTEXT_REPLY_TEMPLATE_VERSION)
    assert workflows.reply.template_version == "reply-template-v1"
    payload["installation_policy"]["root_grant"]["allowed_work_kinds"].remove(
        "context_reply")
    with pytest.raises(ValueError, match="own root grant"):
        authority_profile._policy_from_payload(payload)
    payload["installation_policy"]["root_grant"]["allowed_work_kinds"].append(
        "context_reply")
    payload["model_workflows"]["context_reply"]["template_version"] = (
        "sylanne.d09.source_reply.v1")
    with pytest.raises(ValueError):
        authority_profile._model_workflows_from_payload(payload)


def test_natural_workflows_need_independent_installed_identity_and_grants() -> None:
    payload = _workflow_profile_payload()
    workflows = payload["model_workflows"]
    assert authority_profile._model_workflows_from_payload(payload).natural_generation is None
    assert authority_profile._model_workflows_from_payload(payload).natural_review is None
    workflows["natural_generation"] = _model_workflow_payload(
        "natural_generation", "proposal",
        authority_profile.NATURAL_GENERATION_TEMPLATE_VERSION)
    workflows["natural_review"] = _model_workflow_payload(
        "natural_review", "proposal",
        authority_profile.REVIEW_TEMPLATE_VERSION)
    workflows["natural_review"]["provider_id"] = "review-provider"
    workflows["natural_review"]["provider_config_ref"] = (
        authority_profile.installed_model_config_ref(
            "review-provider", "model-a", "c" * 64))
    grant = payload["installation_policy"]["root_grant"]["allowed_work_kinds"]
    grant.extend(("natural_generation", "natural_review"))
    authority_profile._policy_from_payload(payload)
    installed = authority_profile._model_workflows_from_payload(payload)
    assert installed.natural_generation.work_kind == "natural_generation"
    assert installed.natural_review.provider_id == "review-provider"
    grant.remove("natural_review")
    with pytest.raises(ValueError, match="own root grant"):
        authority_profile._policy_from_payload(payload)
    grant.append("natural_review")
    workflows["natural_review"]["template_version"] = (
        authority_profile.NATURAL_GENERATION_TEMPLATE_VERSION)
    with pytest.raises(ValueError):
        authority_profile._model_workflows_from_payload(payload)


def test_private_reply_expression_requires_explicit_schema2_workflow() -> None:
    payload = _workflow_profile_payload()
    payload["d06_private_reply_source"] = {
        "version": 1, "scope": "private_conversation", "grant_expression": True,
    }
    authority_profile._policy_from_payload(payload)
    assert authority_profile._d06_private_reply_source_from_payload(payload) == (
        authority_profile.AdminD06PrivateReplySourcePolicy(
            1, "private_conversation", True))
    del payload["model_workflows"]
    with pytest.raises(ValueError, match="installed reply workflow"):
        authority_profile._policy_from_payload(payload)


def test_d07_attention_requires_its_own_bounded_root_grant() -> None:
    payload = _workflow_profile_payload()
    payload["d07_attention"] = {
        "deadline_after_seconds": 30,
        "quote_ceiling": {"output_tokens": 1},
        "snapshot_ref": "attention-snapshot",
        "resource_ref": "attention-resource",
    }
    with pytest.raises(ValueError, match="root grant work kind"):
        authority_profile._policy_from_payload(payload)
    payload["installation_policy"]["root_grant"]["allowed_work_kinds"].append(
        "d07.attention")
    authority_profile._policy_from_payload(payload)
    attention = authority_profile._d07_attention_from_payload(payload)
    assert attention.digest_payload() == payload["d07_attention"]


def test_legacy_ingress_model_remains_parseable_without_encoding_authority() -> None:
    payload = _schema2_payload()
    legacy = _model_workflow_payload("reply", "proposal", "reply-template-v1")
    payload["ingress_model"] = {
        key: value for key, value in legacy.items()
        if key in authority_profile._INGRESS_MODEL_FIELDS
    }
    payload["ingress_model"].update(
        allowed_purposes=["proposal"], allowed_audiences=["private"],
        allowed_privacy_tiers=["private"],
    )
    authority_profile._policy_from_payload(payload)
    assert authority_profile._ingress_model_from_payload(payload) is not None
    assert authority_profile._model_workflows_from_payload(payload) is None


@pytest.mark.parametrize("mutation", (
    lambda p: p["model_workflows"].update(version=1),
    lambda p: p["model_workflows"]["encode"].update(work_kind="reply"),
    lambda p: p["model_workflows"]["encode"].update(purpose="proposal"),
    lambda p: p["model_workflows"]["encode"].update(provider_config_digest="0" * 64),
    lambda p: p["model_workflows"]["encode"].update(quote_ceiling={"output_tokens": 65}),
    lambda p: p["model_workflows"]["reply"].update(quote_ceiling={"output_tokens": 65}),
    lambda p: p["model_workflows"]["reply"].update(audiences=[]),
    lambda p: p["model_workflows"].pop("encode"),
    lambda p: p["installation_policy"]["root_grant"].update(
        allowed_work_kinds=["reply"]),
    lambda p: p.update(ingress_model={}),
))
def test_model_workflows_fail_closed_on_invalid_scope(mutation) -> None:
    payload = _workflow_profile_payload()
    mutation(payload)
    with pytest.raises((ValueError, TypeError)):
        authority_profile._policy_from_payload(payload)


@pytest.mark.parametrize("origin", (
    "https://workbench.example.org",
    "https://workbench.example.org:8443",
    "https://127.0.0.1:6185",
    "https://[::1]:6185",
    "http://workbench.example.org",
    "http://workbench.example.org:6185",
    "http://127.0.0.1:6185",
    "http://[::1]:6185",
))
def test_schema2_workbench_origin_is_canonical_and_optional(tmp_path: Path,
                                                              origin: str) -> None:
    payload = _schema2_payload()
    profile_dir = _provision(tmp_path, payload=payload)
    loaded = authority_profile._read_profile_json(profile_dir / "profile.json")
    assert authority_profile._workbench_origin_from_payload(loaded) is None
    payload["workbench_origin"] = origin
    (profile_dir / "profile.json").write_text(json.dumps(payload), encoding="utf-8")
    loaded = authority_profile._read_profile_json(profile_dir / "profile.json")
    assert authority_profile._workbench_origin_from_payload(loaded) == origin
    authority_profile._policy_from_payload(loaded)


@pytest.mark.parametrize("origin", (
    "HTTP://workbench.example.org", "HTTPS://workbench.example.org",
    "https://Workbench.example.org", "https://workbench.example.org/",
    "https://workbench.example.org/path", "https://workbench.example.org?x=1",
    "https://workbench.example.org#fragment", "https://user@workbench.example.org",
    "https://workbench.example.org:0", "https://workbench.example.org:65536",
    "https://workbench.example.org:", "https://workbench.example.org.",
    "https://[fe80::1%25eth0]", "https://workbench.example.org:443/",
    "https://workbench.example.org@evil.example.org", "",
    "http://Workbench.example.org", "http://workbench.example.org/",
    "http://workbench.example.org/path", "http://workbench.example.org?x=1",
    "http://workbench.example.org#fragment", "http://user@workbench.example.org",
    "http://workbench.example.org:0", "http://workbench.example.org:65536",
    "http://workbench.example.org:", "http://workbench.example.org.",
    "http://[fe80::1%25eth0]", "http://workbench.example.org@evil.example.org",
    None, 12,
))
def test_schema2_workbench_origin_rejects_noncanonical_content(tmp_path: Path,
                                                                origin: object) -> None:
    payload = _schema2_payload()
    payload["workbench_origin"] = origin
    profile_dir = _provision(tmp_path, payload=payload)
    with pytest.raises(ValueError, match="workbench origin"):
        authority_profile._read_profile_json(profile_dir / "profile.json")


def test_profile_id_cannot_select_path_or_trust_material(tmp_path: Path) -> None:
    _provision(tmp_path)
    for selection in ("../safe", "safe/other", "safe\\other", "", "."):
        with pytest.raises(ValueError, match="profile identifier"):
            authority_profile._load_profile_from_root(selection, tmp_path)


def test_profile_schema_seam_uses_fixed_material_paths(tmp_path: Path) -> None:
    profile_dir = _provision(tmp_path)
    payload = authority_profile._read_profile_json(profile_dir / "profile.json")
    profile = authority_profile._profile_from_payload("safe", profile_dir, payload)
    transport = MtlsAuthorityTransport({"safe": profile})
    assert isinstance(transport, MtlsAuthorityTransport)
    assert transport.profile_for("safe") is profile
    assert profile.server_name == "authority.example.org"
    assert profile.expected_authority_id == "authority:production"
    assert profile.trust_root == profile_dir / "trust-root.pem"
    assert profile.client_certificate == profile_dir / "client-cert.pem"
    assert profile.client_private_key == profile_dir / "client-key.pem"


def test_profile_rejects_extra_fields_and_duplicate_keys(tmp_path: Path) -> None:
    profile_dir = _provision(tmp_path)
    profile_file = profile_dir / "profile.json"
    profile_file.write_text(json.dumps({
        "schema": 1, "host": "127.0.0.1", "port": 9443,
        "server_name": "authority.example.org",
        "expected_authority_id": "authority:production",
        "trust_root": "/tmp/chat-ca",
    }), encoding="utf-8")
    with pytest.raises(ValueError, match="profile schema"):
        authority_profile._read_profile_json(profile_file)
    profile_file.write_text(
        '{"schema":1,"host":"127.0.0.1","host":"evil",'
        '"port":9443,"server_name":"authority.example.org",'
        '"expected_authority_id":"authority:production"}', encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate"):
        authority_profile._read_profile_json(profile_file)
    profile_file.write_text(json.dumps({
        "schema": 1, "host": "127.0.0.1", "port": 9443,
        "server_name": "authority.example.org",
    }), encoding="utf-8")
    with pytest.raises(ValueError, match="profile schema"):
        authority_profile._read_profile_json(profile_file)


def test_schema2_policy_is_complete_bounded_and_immutable(tmp_path: Path) -> None:
    profile_dir = _provision(tmp_path, payload=_schema2_payload())
    payload = authority_profile._read_profile_json(profile_dir / "profile.json")
    policy = authority_profile._policy_from_payload(payload)
    assert policy.namespace.as_tuple == ("bot-a", "persona-a")
    assert policy.authority_namespace == "bot-a/persona-a"
    assert policy.root_lease.limits == {"tokens": 1000}
    assert policy.root_grant.max_ceiling == {"tokens": 100}
    assert policy.root_grant.policy_ref == "budget-policy:v1"
    assert policy.digest_payload()["root_grant"]["allowed_work_kinds"] == ["reply"]
    assert json.dumps(policy.digest_payload(), sort_keys=True)
    with pytest.raises(TypeError):
        policy.root_lease.limits["tokens"] = 5000
    with pytest.raises(TypeError):
        policy.root_grant.max_ceiling["tokens"] = 5000
    assert authority_profile._profile_from_payload("safe", profile_dir, payload).port == 9443


@pytest.mark.parametrize("mutate", [
    lambda p: p["installation_policy"].update({"unknown": 1}),
    lambda p: p["installation_policy"]["namespace"].update({"extra": "bad"}),
    lambda p: p["installation_policy"].update({"expected_authority_id": "authority:other"}),
    lambda p: p["installation_policy"]["root_lease"].update({"parent_id": "parent"}),
    lambda p: p["installation_policy"]["root_lease"].update({"limits": {"tokens": 0}}),
    lambda p: p["installation_policy"]["root_grant"].update({"max_ceiling": {"tokens": 1001}}),
    lambda p: p["installation_policy"]["root_grant"].update({"bot_id": "other"}),
    lambda p: p["installation_policy"]["root_grant"].update({"version": True}),
])
def test_schema2_policy_rejects_untrusted_or_inconsistent_content(mutate) -> None:
    payload = _schema2_payload()
    mutate(payload)
    with pytest.raises((TypeError, ValueError)):
        authority_profile._policy_from_payload(payload)


def test_schema2_policy_can_reload_an_expired_historical_grant() -> None:
    payload = _schema2_payload()
    payload["installation_policy"]["root_grant"]["valid_until_utc"] = 1
    policy = authority_profile._policy_from_payload(payload)
    assert policy.root_grant.valid_until_utc == 1


def test_schema2_nested_duplicate_and_oversize_rejected(tmp_path: Path) -> None:
    profile = _provision(tmp_path, payload=_schema2_payload()) / "profile.json"
    text = profile.read_text(encoding="utf-8")
    profile.write_text(text.replace('"bot_id": "bot-a"',
                                    '"bot_id": "bot-a", "bot_id": "bot-b"', 1),
                       encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate"):
        authority_profile._read_profile_json(profile)
    profile.write_text(" " * (authority_profile._MAX_PROFILE_BYTES + 1), encoding="utf-8")
    with pytest.raises(ValueError, match="bounded|too large"):
        authority_profile._read_profile_json(profile)


def test_schema1_has_no_installation_policy() -> None:
    payload = {
        "schema": 1, "host": "127.0.0.1", "port": 9443,
        "server_name": "authority.example.org",
        "expected_authority_id": "authority:production",
    }
    with pytest.raises(ValueError, match="schema 2"):
        authority_profile._policy_from_payload(payload)


def test_posix_tree_rejects_symlink_and_untrusted_write_bit(tmp_path: Path) -> None:
    profile_dir = _provision(tmp_path)
    original_lstat = authority_profile.os.lstat

    def owner_root(path: os.PathLike[str] | str):
        observed = original_lstat(path)
        mode = (0o755 if stat.S_ISDIR(observed.st_mode) else
                0o640 if Path(path).name == "client-key.pem" else 0o644)
        return SimpleNamespace(st_uid=0,
                               st_mode=stat.S_IFMT(observed.st_mode) | mode,
                               st_nlink=1, st_gid=4242)

    with patch.object(authority_profile.os, "lstat", side_effect=owner_root), \
         patch.object(authority_profile.os, "getegid", return_value=4242, create=True):
        authority_profile._check_posix_tree(profile_dir)
        def writable_key(path: os.PathLike[str] | str):
            observed = owner_root(path)
            if Path(path) == profile_dir / "client-key.pem":
                observed.st_mode = stat.S_IFREG | 0o666
            return observed
        with patch.object(authority_profile.os, "lstat", side_effect=writable_key):
            with pytest.raises(PermissionError, match="administrator"):
                authority_profile._check_posix_tree(profile_dir)
    def linked_key(path: os.PathLike[str] | str):
        observed = owner_root(path)
        if Path(path) == profile_dir / "client-key.pem":
            observed.st_mode = stat.S_IFLNK | 0o777
        return observed
    with patch.object(authority_profile.os, "lstat", side_effect=linked_key), \
         patch.object(authority_profile.os, "getegid", return_value=4242, create=True):
        with pytest.raises(PermissionError, match="administrator"):
            authority_profile._check_posix_tree(profile_dir)
    with patch.object(authority_profile.os, "lstat", side_effect=owner_root), \
         patch.object(authority_profile.os, "getegid", return_value=1234, create=True):
        with pytest.raises(PermissionError, match="private key group"):
            authority_profile._check_posix_tree(profile_dir)


def test_windows_production_uses_handle_gate() -> None:
    failure = authority_profile.AuthorityProfileUnavailable("native handle gate unavailable")
    with patch.object(authority_profile.platform, "system", return_value="Windows"), \
         patch.object(authority_profile, "_build_windows_admin_transport",
                      side_effect=failure) as build:
        with pytest.raises(authority_profile.AuthorityProfileUnavailable,
                           match="native handle gate"):
            authority_profile.build_admin_authority_transport("default")
    build.assert_called_once_with("default")


@pytest.mark.skipif(os.name != "nt", reason="native Windows file sharing required")
def test_windows_pinned_objects_cannot_be_replaced_or_written(tmp_path: Path) -> None:
    profile_dir = _provision(tmp_path)
    cert = profile_dir / "client-cert.pem"
    key = profile_dir / "client-key.pem"
    with authority_profile._opened_windows_profile(profile_dir) as handles:
        assert cert in handles and key in handles
        with pytest.raises(OSError):
            profile_dir.rename(tmp_path / "replaced-profile")
        with pytest.raises(OSError):
            cert.rename(profile_dir / "replaced-cert.pem")
        with pytest.raises(OSError):
            key.open("r+b")
        assert cert.read_text(encoding="ascii") == "test fixture"


@pytest.mark.skipif(os.name != "nt", reason="native Windows file sharing required")
def test_c04_signing_key_is_pinned_and_needs_installed_dacl(tmp_path: Path) -> None:
    profile_dir = _provision(tmp_path, payload=_schema2_payload())
    key = profile_dir / "c04-signing.key"
    key.write_bytes(b"c" * 32)
    with authority_profile._opened_windows_profile(
            profile_dir, c04_signing_key=True) as handles:
        assert authority_profile._checked_signing_key(
            authority_profile._read_windows_signing_key(handles[key]), "C04") == b"c" * 32
        with pytest.raises(OSError):
            key.rename(profile_dir / "replaced-c04.key")
    with patch.dict(sys.modules, {"sylanne3.host": _host_package}):
        windows_profile_security = importlib.import_module(
            "sylanne3.host.windows_profile_security")
        with patch.object(windows_profile_security, "programdata_profile_root",
                          return_value=tmp_path):
            with pytest.raises(PermissionError):
                authority_profile.load_admin_c04_signing_key("safe")


@pytest.mark.skipif(os.name != "nt", reason="native Windows security descriptors required")
def test_windows_dacl_policy_inspects_pinned_handles(tmp_path: Path) -> None:
    profile_dir = _provision(tmp_path)
    with authority_profile._opened_windows_profile(profile_dir) as handles:
        # The developer fixture cannot satisfy the administrator DACL policy.
        # This also exercises GetSecurityInfo on pinned Win32 handles.
        with patch.dict(sys.modules, {"sylanne3.host": _host_package}):
            with pytest.raises(PermissionError,
                               match="owner|non-admin write|bypass private-key DACL"):
                authority_profile._check_windows_handles(profile_dir, handles)


@pytest.mark.skipif(os.name != "nt", reason="native Windows administrator DACL required")
def test_installation_policy_loader_rejects_developer_owned_windows_profile(
        tmp_path: Path) -> None:
    _provision(tmp_path, payload=_schema2_payload())
    with patch.dict(sys.modules, {"sylanne3.host": _host_package}):
        windows_profile_security = importlib.import_module(
            "sylanne3.host.windows_profile_security"
        )

        with patch.object(windows_profile_security, "programdata_profile_root",
                          return_value=tmp_path):
            with pytest.raises(PermissionError,
                               match="owner|non-admin write|bypass private-key DACL"):
                authority_profile.load_admin_installation_policy("safe")


@pytest.mark.skipif(os.name != "nt" or shutil.which("openssl") is None,
                    reason="native Windows OpenSSL fixture required")
def test_windows_openssl_consumes_cert_and_key_inside_pinned_window(tmp_path: Path) -> None:
    profile_dir = _provision(tmp_path)
    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
        "-keyout", str(profile_dir / "client-key.pem"),
        "-out", str(profile_dir / "client-cert.pem"),
        "-subj", "/CN=profile-test", "-days", "1", "-config", "NUL",
    ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    shutil.copyfile(profile_dir / "client-cert.pem", profile_dir / "trust-root.pem")
    profile = AuthorityTlsProfile(
        "safe", "127.0.0.1", 9443, "authority.example.org",
        "authority:production", profile_dir / "trust-root.pem",
        profile_dir / "client-cert.pem", profile_dir / "client-key.pem",
    )
    with authority_profile._opened_windows_profile(profile_dir):
        context = profile.ssl_context()
    assert context.check_hostname is True


@pytest.mark.skipif(os.name != "nt", reason="Windows-only platform spoof")
def test_macos_cannot_be_claimed_by_platform_string_on_windows() -> None:
    with patch.object(authority_profile.platform, "system", return_value="Darwin"):
        with pytest.raises(authority_profile.AuthorityProfileUnavailable,
                           match="POSIX directory-descriptor"):
            authority_profile.build_admin_authority_transport("default")


def test_tls_descriptor_alias_fails_closed_without_matching_identity() -> None:
    with pytest.raises(authority_profile.AuthorityProfileUnavailable,
                       match="TLS descriptor alias"):
        authority_profile._tls_fd_path(999999, "Darwin")


def test_linux_acl_presence_or_unknown_semantics_fail_closed(tmp_path: Path) -> None:
    profile_dir = _provision(tmp_path)
    with patch.object(authority_profile.os, "getxattr", return_value=b"acl", create=True):
        with pytest.raises(PermissionError, match="ACL"):
            authority_profile._check_linux_acl_tree(profile_dir)
    with patch.object(authority_profile.os, "getxattr", side_effect=OSError(95, "unsupported"),
                      create=True):
        with pytest.raises(authority_profile.AuthorityProfileUnavailable,
                           match="ACL verification failed"):
            authority_profile._check_linux_acl_tree(profile_dir)


@pytest.mark.parametrize("version", (2, 3, 4))
def test_d07_recall_template_is_a_finite_installed_workflow(version):
    from sylanne3.model_broker.d07_cognition_v1 import RECALL_TEMPLATE_VERSION_V1
    payload = _workflow_profile_payload()
    payload["model_workflows"]["version"] = version
    if version == 4:
        payload["model_workflows"]["artifact_draft"] = None
    payload["installation_policy"]["root_grant"]["allowed_work_kinds"].append("d07.cognition")
    payload["model_workflows"]["d07_cognition"] = _model_workflow_payload(
        "d07.cognition", "proposal", RECALL_TEMPLATE_VERSION_V1)
    if version == 4:
        # This node checks the formal workflow codec/constructor. A complete
        # profile separately requires its explicit foreground/artifact policies.
        from sylanne3.host.model_workflows_v4 import model_workflows_v4_from_payload
        installed = model_workflows_v4_from_payload(payload["model_workflows"])
    else:
        installed = authority_profile._model_workflows_from_payload(payload)
    assert installed.d07_cognition.template_version == RECALL_TEMPLATE_VERSION_V1
    assert installed.d07_cognition.provider_config_ref == installed.reply.provider_config_ref


@pytest.mark.parametrize("slot,work_kind,purpose,template", (
    ("d07_cognition", "d07.cognition", "proposal", "unregistered-recall-template"),
    ("d07_cognition", "reply", "proposal", "sylanne.d07.ingress_recall_routing_template.v1"),
    ("d07_cognition", "d07.cognition", "consolidation", "sylanne.d07.ingress_recall_routing_template.v1"),
    ("context_reply", "d07.cognition", "proposal", "sylanne.d07.ingress_recall_routing_template.v1"),
))
def test_d07_recall_workflow_rejects_unknown_and_wrong_slot(slot, work_kind, purpose, template):
    from sylanne3.model_broker.d07_cognition_v1 import RECALL_TEMPLATE_VERSION_V1
    payload = _workflow_profile_payload()
    workflow = _model_workflow_payload(work_kind, purpose, template)
    payload["model_workflows"][slot] = workflow
    if slot == "context_reply":
        # Same object in two slots must not turn the wrong context slot into D07.
        workflow["template_version"] = RECALL_TEMPLATE_VERSION_V1
        payload["model_workflows"]["d07_cognition"] = workflow
    with pytest.raises(ValueError):
        authority_profile._model_workflows_from_payload(payload)


@pytest.mark.parametrize("failure,reason", [
    ("missing_work_kind", "own root grant"),
    ("grant_ceiling", "quote exceeds root budget"),
    ("root_lease_consistency", "root grant exceeds administrator root lease"),
])
def test_life_numeric_v3_requires_its_own_root_grant_and_lease(failure, reason):
    payload = _workflow_profile_payload()
    payload["model_workflows"]["version"] = 3
    payload["model_workflows"]["life_numeric"] = _model_workflow_payload(
        "d06.encode_internal_life_numeric", "consolidation",
        "sylanne.d06.internal_life_numeric.v1")
    grant = payload["installation_policy"]["root_grant"]
    lease = payload["installation_policy"]["root_lease"]
    grant["allowed_work_kinds"].append("d06.encode_internal_life_numeric")
    # Prove the complete typed profile passes before changing one binding.
    policy = authority_profile._policy_from_payload(payload)
    workflow = authority_profile._model_workflows_from_payload(payload).life_numeric
    assert workflow.work_kind in policy.root_grant.allowed_work_kinds
    assert workflow.quote_ceiling["output_tokens"] <= policy.root_grant.max_ceiling["output_tokens"]
    assert workflow.quote_ceiling["output_tokens"] <= policy.root_lease.limits["output_tokens"]
    if failure == "missing_work_kind":
        grant["allowed_work_kinds"].remove(workflow.work_kind)
    elif failure == "grant_ceiling":
        payload["model_workflows"]["life_numeric"]["quote_ceiling"]["output_tokens"] = 65
    else:
        lease["limits"]["output_tokens"] = 32
        payload["model_workflows"]["life_numeric"]["quote_ceiling"]["output_tokens"] = 33
    with pytest.raises(ValueError, match=reason):
        authority_profile._policy_from_payload(payload)


@pytest.mark.parametrize("explicit_none", (False, True))
def test_unconfigured_d13_wire_fields_need_no_service_helpers(explicit_none):
    payload = {"d13_wire_policy": None, "d13_wire_counter": None} if explicit_none else {}
    with patch.dict(sys.modules, {
        "sylanne3.authority_service.d13_wire_evidence_v1": None,
        "sylanne3.authority_service.d13_installed_counter_v1": None,
    }):
        assert authority_profile._d13_wire_policy_from_payload(payload, None) is None
        assert authority_profile._d13_wire_counter_from_payload(payload) is None


@pytest.mark.parametrize("field", ("d13_wire_policy", "d13_wire_counter"))
def test_configured_d13_wire_fields_still_require_exact_contracts(field):
    payload = {field: {}}
    with pytest.raises(ValueError, match="fields differ"):
        if field == "d13_wire_policy":
            authority_profile._d13_wire_policy_from_payload(payload, None)
        else:
            authority_profile._d13_wire_counter_from_payload(payload)


def test_profile_and_shared_channel_import_without_full_business_adapters():
    root = Path(__file__).resolve().parents[3]
    code = """
import sys
from pathlib import Path
sys.path.insert(0, str(Path(sys.argv[1]) / "rewrite"))
from sylanne3.host.authority_profile import AuthorityTlsProfile
from sylanne3.host.mtls_channel import MtlsAuthorityChannel
from sylanne3.host.authority_transport_contract import AuthorityTlsProfile as SharedProfile
assert AuthorityTlsProfile is SharedProfile
assert "sylanne3.host.authority_client" not in sys.modules
assert "sylanne3.host.mtls_transport" not in sys.modules
assert "sylanne3.authority_service.current_accepted_erasure_read" not in sys.modules
assert "sylanne3.model_broker.natural_reply_history_v4" not in sys.modules
"""
    subprocess.run([sys.executable, "-B", "-c", code, str(root)], check=True,
                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=30)


def _artifact_draft_v3_payload():
    main = _model_workflow_payload("artifact_draft_v1", "consolidation", "sylanne.artifact_draft_template.v1")
    main["quote_ceiling"] = {"input_tokens": 100, "output_tokens": 32, "model_tokens": 132, "model_microusd": 100}
    phase = {**main, "quote_ceiling": dict(main["quote_ceiling"]), "template_version": "sylanne.artifact_draft_phase_template.v2"}
    return {
        "model_workflow": main, "phase_model_workflow": phase,
        "tool_scope": {"resource_id": "export", "filename": "draft.txt", "mode": "create",
            "max_file_bytes": 32768, "generated_text_bytes": 32768, "readback_chunk_bytes": 65536,
            "execution_timeout_seconds": 20},
        "body_policy": {"policy_ref": "body:phase", "policy_version": 1,
            "effect_component_policy_ref": "effect:phase", "effect_component_policy_version": 1,
            "cpu_ceiling_ms": 10, "resource_id": "export"},
        "observation_policy": None,
        "standing_scope": {"policy_ref": "standing:phase", "policy_version": 1,
            "platform_ref": '["fixture","aiocqhttp","bot"]',
            "allowed_sender_refs": ['["fixture","owner"]'], "valid_until_utc": 4102444800,
            "task_lifetime_seconds": 600, "root_window_seconds": 60, "maximum_active_tasks": 1,
            "social_role": "owner", "norm_refs": [], "schema": "sylanne.artifact-standing-scope.v1"},
        "schema": "sylanne.artifact-draft-policy.v3",
    }


def _artifact_draft_v3_bundle(tmp_path, *, billing=None):
    from sylanne3.host.model_workflows_v4 import model_workflows_v4_from_payload
    artifact = authority_profile.artifact_draft_policy_from_payload_v1(_artifact_draft_v3_payload())
    payload = _workflow_profile_payload()
    payload["model_workflows"]["version"] = 4
    payload["model_workflows"]["artifact_draft"] = _artifact_draft_v3_payload()["model_workflow"]
    installation = payload["installation_policy"]
    amounts = {"input_tokens": 1000, "model_tokens": 1000, "model_microusd": 1000}
    installation["root_lease"]["limits"].update(amounts)
    installation["root_grant"]["max_ceiling"].update(amounts)
    installation["root_grant"]["allowed_work_kinds"].extend(
        ("artifact_draft_v1", "d10.life.artifact_draft.v1", "d11.foreground_cycle.v1"))
    deadline = authority_profile.AdminForegroundDeadlinePolicyV1(
        "sylanne.foreground-deadline-policy.v1", None, "signed_scope_intersection_v1")
    foreground = authority_profile.AdminForegroundPolicyV1("sylanne.foreground-policy.v1", 1,
        "d11.foreground-call-plan.v1", 6, 2, 1, "foreground:phase", 1, deadline)
    from dataclasses import asdict
    payload["foreground"] = asdict(foreground)
    payload["artifact_draft"] = _artifact_draft_v3_payload()
    foreground = authority_profile._foreground_from_payload(payload)
    artifact = authority_profile._artifact_draft_from_payload(payload)
    profile = AuthorityTlsProfile("safe", "127.0.0.1", 9443, "authority.example.org",
        "authority:production", tmp_path / "ca.pem", tmp_path / "client.pem", tmp_path / "client.key")
    return authority_profile.AdminInstallationBundle(profile, authority_profile._policy_from_payload(payload),
        b"d" * 32, b"e" * 32, model_workflows=model_workflows_v4_from_payload(payload["model_workflows"]),
        foreground=foreground, artifact_draft=artifact, provider_billing_policy_v1=billing)


def test_artifact_policy_v3_keeps_create_only_and_closed_legacy_variants():
    from copy import deepcopy
    raw = _artifact_draft_v3_payload()
    installed = authority_profile.artifact_draft_policy_from_payload_v1(raw)
    assert type(installed) is authority_profile.AdminArtifactDraftPolicyV3
    assert type(installed.tool_scope) is authority_profile.AdminArtifactDraftToolScopeV1
    assert installed.model_workflow.template_version == "sylanne.artifact_draft_template.v1"
    assert installed.phase_model_workflow.template_version == "sylanne.artifact_draft_phase_template.v2"
    legacy = deepcopy(raw)
    del legacy["phase_model_workflow"]
    legacy["schema"] = "sylanne.artifact-draft-policy.v2"
    scope = legacy["tool_scope"]
    del scope["mode"]
    scope.update(maximum_artifact_version=2, operations=["create", "replace_verified_predecessor"],
        schema="sylanne.artifact-draft-tool-scope.v2")
    assert type(authority_profile.artifact_draft_policy_from_payload_v1(legacy)) is authority_profile.AdminArtifactDraftPolicyV2
    legacy["phase_model_workflow"] = raw["phase_model_workflow"]
    with pytest.raises(ValueError, match="^artifact draft policy schema is invalid$"):
        authority_profile.artifact_draft_policy_from_payload_v1(legacy)
    expanded = deepcopy(raw)
    expanded["phase_model_workflow"]["quote_ceiling"]["input_tokens"] = 101
    with pytest.raises(ValueError, match="original C4 selection or bounds"):
        authority_profile.artifact_draft_policy_from_payload_v1(expanded)


def test_artifact_phase_identity_is_actual_installed_object(tmp_path):
    from dataclasses import replace
    bundle = _artifact_draft_v3_bundle(tmp_path)
    phase = bundle.artifact_draft.phase_model_workflow
    assert authority_profile.is_installed_artifact_draft_phase_slot_v2(bundle, phase)
    assert not authority_profile.is_installed_artifact_draft_phase_slot_v2(bundle, replace(phase))
    assert not authority_profile.is_installed_artifact_draft_phase_slot_v2(bundle, bundle.model_workflows.artifact_draft)


def test_artifact_phase_root_caps_apply_without_billing(tmp_path):
    from dataclasses import replace
    bundle = _artifact_draft_v3_bundle(tmp_path)
    grant = replace(bundle.installation_policy.root_grant,
        max_ceiling={**bundle.installation_policy.root_grant.max_ceiling, "input_tokens": 99})
    installation = replace(bundle.installation_policy, root_grant=grant)
    with pytest.raises(ValueError, match="actual installed foreground/root grant/lease"):
        replace(bundle, installation_policy=installation, provider_billing_policy_v1=None)
