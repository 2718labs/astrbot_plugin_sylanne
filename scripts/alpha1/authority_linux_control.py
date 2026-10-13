"""Independent signed-Owner lifecycle client; works while AstrBot/W09 is stopped.

Input is bounded JSON from stdin. No private key or token is accepted in argv.
This client connects to the running Authority; it does not reopen its databases.
"""
from __future__ import annotations

import argparse
import asyncio
import base64
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from _runtime_bootstrap import load_canonical_runtime_v1
load_canonical_runtime_v1(ROOT)


def command_for(action, data, namespace):
    if type(data) is not dict:
        raise ValueError("one explicit JSON object required")
    if action == "register-credential":
        from sylanne3.authority_service.v2_owner_proof import (
            OwnerCredentialRegistrationV1, from_wire as proof_from_wire, to_wire as proof_to_wire,
        )
        if set(data) != {"registration"}:
            raise ValueError("exact administrator-paired public Owner credential required")
        registration = proof_from_wire(data["registration"])
        if type(registration) is not OwnerCredentialRegistrationV1 or proof_to_wire(registration) != data["registration"]:
            raise ValueError("public Owner credential registration differs")
        return "register_owner_credential_v1", {"namespace": namespace,
            "registration": data["registration"], "rotation_signature": None}
    if action == "challenge":
        if set(data) != {"request"}:
            raise ValueError("challenge requires the exact signed-Owner login request")
        return "begin_owner_session_v1", {"namespace": namespace, "request": data["request"]}
    if action == "accept":
        if set(data) != {"challenge", "signature_base64"}:
            raise ValueError("accept requires the original challenge and local signature only")
        signature = base64.b64decode(data["signature_base64"], validate=True)
        if len(signature) != 64:
            raise ValueError("exact Ed25519 signature required")
        return "accept_owner_session_v1", {"namespace": namespace, "challenge": data["challenge"], "signature": signature.hex()}
    if action == "logout":
        if set(data) != {"request", "token"}:
            raise ValueError("logout requires exact current Owner request and token")
        return "logout_owner_session_v1", {"namespace": namespace, **data}
    if action == 'first-owner-issue':
        if set(data) != {'ticket','operation','grant_value','owner_session_token','owner_session_request'}:
            raise ValueError('exact original ticket, operation, grant and signed console session required')
        return 'first_owner_issue_v1', {'namespace': namespace, **data}
    if action in {'package-accept', 'package-status'}:
        common = {'owner_actor_id', 'owner_session_request', 'owner_session_token', 'operation_id'}
        extra = {'candidate_cohort_ref', 'expected_selection_digest', 'expected_lifecycle_epoch'} if action == 'package-accept' else set()
        if set(data) != common | extra:
            raise ValueError('exact signed Owner, original operation and registered package intent required')
        return 'd12_package_maintenance_v2', {'namespace': namespace,
            'action': 'accept' if action == 'package-accept' else 'status', **data}
    extra = {"inspect": set(), "status": {"operation_id"}, "continue": {"operation_id"},
        "resume": {"pause_operation_id", "operation_id", "expected_lifecycle_epoch"},
        "upgrade-catalogue": {"operation_id", "pause_operation_id", "target_cohort_ref", "source_catalogue_hash"}}
    common = {"owner_actor_id", "owner_session_request", "owner_session_token"}
    if action not in extra or set(data) != common | extra[action]:
        raise ValueError("exact current signed Owner and lifecycle original fields required")
    return "d12_installation_control_v1", {"namespace": namespace,
        "action": "upgrade_catalogue" if action == "upgrade-catalogue" else action, **data}


async def execute(args, data):
    from sylanne3.host.authority_profile import load_admin_installation_bundle
    from sylanne3.host.authority_transport_contract import AuthorityProvisioningRequest, PublisherPackageIdentity, AUTHORITY_PROTOCOL, AUTHORITY_V2_PROTOCOL
    from sylanne3.host.installed_package import verify_installed_backend_runtime_v1
    from sylanne3.host.mtls_channel import MtlsAuthorityChannel
    bundle = load_admin_installation_bundle(args.profile)
    policy = bundle.installation_policy
    if bundle.package_selection is not None:
        from sylanne3.host.selected_profile_cohort_v2 import BINDING_NAME, validate_profile_cohort_binding_v2
        from sylanne3.authority_service.linux_installation_security_v1 import read_installed_json_v1
        from sylanne3.authority_service.d12_package_files_v2 import InstalledPackageSelectionFilesV2
        directory = Path(bundle.tls_profile.client_private_key).parent
        binding = validate_profile_cohort_binding_v2(read_installed_json_v1(directory / BINDING_NAME), directory)
        selected, cohort, _ = InstalledPackageSelectionFilesV2(control_directory=binding['control_directory']).read_selected_host_cohort_v2()
        if selected != bundle.package_selection:
            raise ValueError('package selection changed before management connection')
        root = Path(cohort.package.package_root)
        if args.package_root is not None and Path(args.package_root) != root:
            raise ValueError('explicit package root differs from current registered selection')
    else:
        root = Path(args.package_root) if args.package_root is not None else Path('/opt/sylanne/code')
    if not root.is_absolute() or root.resolve(strict=True) != root:
        raise ValueError('canonical non-symlink installed package root required')
    checked = verify_installed_backend_runtime_v1(root, policy.manifest_digest)
    if not checked.verified:
        raise ValueError("current externally pinned installed package required")
    method, command = command_for(args.action, data, policy.authority_namespace)
    request = AuthorityProvisioningRequest(AUTHORITY_PROTOCOL, args.profile, "astrbot_plugin_sylanne", "4.28.1",
        root, root, PublisherPackageIdentity(policy.manifest_digest))
    transport = MtlsAuthorityChannel({args.profile: bundle.tls_profile})
    try:
        handshake = await transport.handshake(request, protocol=AUTHORITY_V2_PROTOCOL)
        grant = await transport.installation_grant_v2(request, handshake)
        if (not handshake.valid_pairing() or grant.installation_id != policy.installation_id
                or grant.authority_id != policy.expected_authority_id or grant.manifest_digest != policy.manifest_digest):
            raise ValueError("independent Authority installation differs")
        result = await transport._content_rpc(request, handshake, method, command, protocol=AUTHORITY_V2_PROTOCOL)
        result = {k: v for k, v in result.items() if k != "channel_binding_sha256"}
        if args.action == "challenge":
            from sylanne3.authority_service.v2_owner_session import from_wire, OwnerSessionLoginChallengeV1
            challenge = from_wire(result.get("challenge"))
            if type(challenge) is not OwnerSessionLoginChallengeV1:
                raise ValueError("signed login challenge response differs")
            result["signing_payload_base64"] = base64.b64encode(challenge.signed_bytes()).decode("ascii")
        return result
    finally:
        await transport.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--package-root", type=Path)
    parser.add_argument("action", choices=("register-credential", "challenge", "accept", "logout", "inspect", "status", "continue", "resume", 'package-accept', 'package-status', 'first-owner-issue', 'upgrade-catalogue'))
    args = parser.parse_args()
    raw = sys.stdin.buffer.read(65537)
    if len(raw) > 65536:
        raise ValueError("bounded lifecycle JSON input required")
    result = asyncio.run(execute(args, json.loads(raw)))
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False))


if __name__ == "__main__":
    main()
