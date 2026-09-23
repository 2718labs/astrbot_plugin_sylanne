"""Native Windows checks for the installed Authority profile boundary."""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest


SOURCE = Path(__file__).resolve().parents[2] / "sylanne3" / "host" / "windows_profile_security.py"
SPEC = importlib.util.spec_from_file_location("windows_profile_security", SOURCE)
assert SPEC is not None and SPEC.loader is not None
security_gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(security_gate)


def test_profile_id_cannot_escape_fixed_root() -> None:
    for value in ("../default", r"..\default", "", ".", "x/y"):
        with pytest.raises(ValueError, match="identifier"):
            security_gate.verify_admin_profile(value)


@pytest.mark.skipif(os.name != "nt", reason="Windows Known Folder API")
def test_programdata_resolution_ignores_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    original = security_gate.programdata_profile_root()
    monkeypatch.setenv("ProgramData", r"C:\attacker-chosen-programdata")
    assert security_gate.programdata_profile_root() == original
    assert original.is_absolute()
    assert original.parts[-3:] == ("Sylanne", "client", "profiles")


@pytest.mark.skipif(os.name != "nt", reason="Windows security descriptors")
def test_default_developer_temp_profile_is_rejected(tmp_path: Path) -> None:
    profile = tmp_path / "default"
    profile.mkdir()
    for name in security_gate._MATERIAL:
        (profile / name).write_bytes(b"fixture")
    with pytest.raises(PermissionError, match="Authority profile"):
        security_gate._verify_tree(profile)


@pytest.mark.skipif(os.name != "nt", reason="Windows path attributes")
@pytest.mark.parametrize("target_kind", ["ancestor", "profile", "key"])
def test_reparse_point_anywhere_in_consumed_path_is_rejected(
    tmp_path: Path, target_kind: str,
) -> None:
    profile = tmp_path / "default"
    directories = tuple(reversed(profile.parents)) + (profile,)
    target = {"ancestor": tmp_path, "profile": profile,
              "key": profile / "client-key.pem"}[target_kind]

    def attributes(path: Path) -> int:
        return (security_gate._DIRECTORY if path in directories else 0) | (
            security_gate._REPARSE_POINT if path == target else 0
        )

    with patch.object(security_gate, "_runtime_token_sids",
                      return_value=("S-1-5-21-test", {"S-1-5-21-test"})), \
         patch.object(security_gate, "_attributes", side_effect=attributes), \
         patch.object(security_gate, "_check_security_descriptor"):
        with pytest.raises(PermissionError, match="reparse point"):
            security_gate._verify_tree(profile)


def _descriptor_with_ace(kind: int, flags: int, mask: int, sid: str):
    acl = SimpleNamespace(GetAceCount=lambda: 1,
                          GetAce=lambda _: ((kind, flags), mask, sid))
    descriptor = SimpleNamespace(
        GetSecurityDescriptorOwner=lambda: "S-1-5-18",
        GetSecurityDescriptorDacl=lambda: acl,
    )
    return SimpleNamespace(
        SE_FILE_OBJECT=1, OWNER_SECURITY_INFORMATION=1,
        DACL_SECURITY_INFORMATION=4, ACCESS_ALLOWED_ACE_TYPE=0,
        ACCESS_DENIED_ACE_TYPE=1,
        GetNamedSecurityInfo=lambda *_: descriptor,
        ConvertSidToStringSid=lambda sid: sid,
    )


def test_inherited_nonadmin_allow_ace_granting_write_is_rejected() -> None:
    # INHERITED_ACE (0x10) is a real ACE flag, not a reason to omit the ACE.
    native = _descriptor_with_ace(0, 0x10, 0x00000002, "S-1-5-32-545")
    with pytest.raises(PermissionError, match="non-admin write"):
        security_gate._check_security_descriptor(
            Path(r"C:\ProgramData\Sylanne\client\profiles\default"),
            "S-1-5-21-runtime", set(),
            native, key=False,
        )


def test_unknown_ace_type_fails_closed() -> None:
    native = _descriptor_with_ace(9, 0, 0x00000001, "S-1-5-32-545")
    with pytest.raises(security_gate.WindowsProfileSecurityUnavailable,
                       match="unsupported.*ACE"):
        security_gate._check_security_descriptor(
            Path("test"), "S-1-5-21-runtime", set(), native, key=False,
        )


def test_runtime_enabled_admin_write_to_key_is_rejected() -> None:
    native = _descriptor_with_ace(0, 0, 0x00040000, "S-1-5-32-544")
    with pytest.raises(PermissionError, match="runtime account can write"):
        security_gate._check_security_descriptor(
            Path("client-key.pem"), "S-1-5-21-runtime", {"S-1-5-32-544"},
            native, key=True,
        )


@pytest.mark.parametrize("mask", [0x00000001, 0x80000000])
@pytest.mark.parametrize("principal", ["S-1-1-0", "S-1-5-32-545",
                                        "S-1-5-11", "S-1-5-21-other"])
def test_private_key_rejects_broad_read(mask: int, principal: str) -> None:
    native = _descriptor_with_ace(0, 0, mask, principal)
    with pytest.raises(PermissionError, match="broad read"):
        security_gate._check_security_descriptor(
            Path("client-key.pem"), "S-1-5-21-runtime",
            {"S-1-5-21-runtime", "S-1-5-11"}, native, key=True,
        )


@pytest.mark.parametrize("principal", ["S-1-5-18", "S-1-5-32-544",
                                        "S-1-5-21-runtime"])
def test_private_key_allows_exact_runtime_or_admin_read(principal: str) -> None:
    native = _descriptor_with_ace(0, 0, 0x80000000, principal)
    security_gate._check_security_descriptor(
        Path("client-key.pem"), "S-1-5-21-runtime",
        {"S-1-5-21-runtime"}, native, key=True,
    )


@pytest.mark.parametrize("mask", [0x00000002, 0x00000004])
def test_ancestor_allows_create_without_replacement_rights(mask: int) -> None:
    native = _descriptor_with_ace(0, 0, mask, "S-1-5-32-545")
    security_gate._check_security_descriptor(
        Path(r"C:\ProgramData"), "S-1-5-21-runtime", set(), native,
        key=False, protected=False,
    )
    with pytest.raises(PermissionError, match="non-admin write"):
        security_gate._check_security_descriptor(
            Path(r"C:\ProgramData\Sylanne"), "S-1-5-21-runtime",
            set(), native, key=False, protected=True,
        )


@pytest.mark.parametrize("mask", [0x00000040, 0x00010000, 0x00040000,
                                  0x00080000, 0x00000100, 0x40000000])
def test_ancestor_rejects_rights_to_replace_protected_entry(mask: int) -> None:
    native = _descriptor_with_ace(0, 0, mask, "S-1-5-32-545")
    with pytest.raises(PermissionError, match="non-admin write"):
        security_gate._check_security_descriptor(
            Path(r"C:\ProgramData"), "S-1-5-21-runtime", set(), native,
            key=False, protected=False,
        )


def test_null_dacl_fails_closed() -> None:
    native = _descriptor_with_ace(0, 0, 0, "S-1-5-18")
    native.GetNamedSecurityInfo = lambda *_: SimpleNamespace(
        GetSecurityDescriptorOwner=lambda: "S-1-5-18",
        GetSecurityDescriptorDacl=lambda: None,
    )
    with pytest.raises(PermissionError, match="null DACL"):
        security_gate._check_security_descriptor(
            Path("client-key.pem"), "S-1-5-21-runtime", set(), native,
            key=True,
        )


@pytest.mark.skipif(os.name != "nt", reason="Windows runtime token")
def test_restore_privilege_token_is_rejected_even_if_disabled() -> None:
    class Token:
        def Close(self) -> None:
            pass

    native = SimpleNamespace(
        TokenUser=1, TokenGroups=2, TokenPrivileges=3,
        OpenProcessToken=lambda *_: Token(),
        GetTokenInformation=lambda _token, kind: {
            1: ("S-1-5-21-user", 0), 2: [], 3: [("restore-luid", 0)],
        }[kind],
        ConvertSidToStringSid=lambda sid: sid,
        LookupPrivilegeName=lambda *_: "SeRestorePrivilege",
    )
    with pytest.raises(PermissionError, match="bypass"):
        security_gate._runtime_token_sids(native)
