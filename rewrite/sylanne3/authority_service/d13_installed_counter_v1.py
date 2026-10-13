"""Optional protected complete-wire counter adapter, called outside Graph tx.

No stock counter is fabricated. A configured installation must provide an
administrator-owned pinned program and its independently pinned Ed25519 public
policy. The program may call a documented provider counting endpoint; it must
return signed exact/bounded evidence, never a plain count_tokens integer.
"""
from __future__ import annotations
from dataclasses import asdict, dataclass
import hashlib
import json
import os
from pathlib import Path
import subprocess
import selectors
import signal
import time
import tempfile

from ..runtime_contracts import canonical_serialize
from .d13_wire_evidence_v1 import InstalledD13WirePolicyV1, verify_signed_d13_wire_envelope_v1
from .linux_installation_security_v1 import opened_installed_file_v1


@dataclass(frozen=True, slots=True)
class InstalledD13CounterCommandV1:
    executable: str
    executable_sha256: str
    timeout_seconds: int = 60

    def __post_init__(self):
        if (type(self.executable) is not str or not Path(self.executable).is_absolute()
                or type(self.executable_sha256) is not str or len(self.executable_sha256) != 64
                or any(c not in "0123456789abcdef" for c in self.executable_sha256)
                or type(self.timeout_seconds) is not int or not 1 <= self.timeout_seconds <= 300):
            raise ValueError("protected D13 counter executable pin required")

    def count_outside_graph_transaction_v1(self, *, db, policy, request):
        if type(policy) is not InstalledD13WirePolicyV1:
            raise ValueError("D13 V1 counter requires its exact installed V1 policy")
        return self._count_installed_complete_wire(db=db, policy=policy, request=request,
            request_schema="sylanne3.d13.full-wire-count-request.v1", request_limit=16 * 1024 * 1024,
            verify_envelope=verify_signed_d13_wire_envelope_v1)

    def count_outside_graph_transaction_v6(self, *, db, policy, request):
        from .d13_wire_evidence_v6 import InstalledD13WirePolicyV6, verify_signed_d13_wire_envelope_v6
        if type(policy) is not InstalledD13WirePolicyV6:
            raise ValueError("D13 V6 counter requires its exact installed V6 policy")
        return self._count_installed_complete_wire(db=db, policy=policy, request=request,
            request_schema="sylanne3.d13.full-wire-count-request.v6", request_limit=16 * 1024 * 1024,
            verify_envelope=verify_signed_d13_wire_envelope_v6)

    def _count_installed_complete_wire(self, *, db, policy, request, request_schema, request_limit, verify_envelope):
        if db.in_transaction:
            raise ValueError("D13 provider counting is forbidden inside a Graph transaction")
        if (type(request) is not dict or set(request) != {"schema", "original", "policy", "raw_wire", "compressed_wire"}
                or request["schema"] != request_schema
                or canonical_serialize(request["policy"]) != canonical_serialize(asdict(policy))
                or request["original"].get("policy_digest") != policy.policy_digest
                or any(type(request[k]) is not str for k in ("raw_wire", "compressed_wire"))
                or hashlib.sha256(request["raw_wire"].encode()).hexdigest() != request["original"].get("raw_request_digest")
                or hashlib.sha256(request["compressed_wire"].encode()).hexdigest() != request["original"].get("compressed_request_digest")):
            raise ValueError("D13 counter request must bind both actual complete wires")
        encoded = canonical_serialize(request).encode()
        if len(encoded) > request_limit:
            raise ValueError("D13 full-wire counting request exceeds installed safety limit")
        with opened_installed_file_v1(self.executable) as fd:
            with os.fdopen(os.dup(fd), "rb") as stream:
                if hashlib.file_digest(stream, "sha256").hexdigest() != self.executable_sha256:
                    raise ValueError("installed D13 counter program changed")
            # Drain both bounded pipes while the process runs. A runaway
            # installed program cannot fill a tempfile or unbounded memory.
            with tempfile.TemporaryFile() as source:
                source.write(encoded)
                source.seek(0)
                process = subprocess.Popen([f"/proc/self/fd/{fd}"], stdin=source,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, pass_fds=(fd,), start_new_session=True,
                    env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}, cwd="/")
                output, error = bytearray(), bytearray()
                deadline = time.monotonic() + self.timeout_seconds
                try:
                    with selectors.DefaultSelector() as selector:
                        selector.register(process.stdout, selectors.EVENT_READ, output)
                        selector.register(process.stderr, selectors.EVENT_READ, error)
                        while selector.get_map():
                            remaining = deadline - time.monotonic()
                            if remaining <= 0:
                                raise ValueError("installed D13 counter timed out")
                            for key, _mask in selector.select(min(remaining, 0.5)):
                                chunk = os.read(key.fileobj.fileno(), 8192)
                                if not chunk:
                                    selector.unregister(key.fileobj)
                                    continue
                                key.data.extend(chunk)
                                if len(key.data) > 65536:
                                    raise ValueError("installed D13 counter exceeded response limit")
                        if process.wait(timeout=max(0.001, deadline - time.monotonic())) != 0:
                            raise ValueError("installed D13 counter failed")
                    value = bytes(output)
                finally:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    process.wait()
                    process.stdout.close()
                    process.stderr.close()
        def unique(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("D13 counter response repeats a field")
                result[key] = value
            return result
        envelope = json.loads(value, object_pairs_hook=unique)
        payload = verify_envelope(policy, envelope)
        if any(payload.get(k) != v for k, v in request["original"].items()):
            raise ValueError("D13 counter signed a different original wire pair")
        return envelope


def installed_d13_counter_from_payload_v1(value):
    """Decode only an already authenticated administrator profile field."""
    if value is None:
        return None
    if type(value) is not dict or set(value) not in (
            {"executable", "executable_sha256"},
            {"executable", "executable_sha256", "timeout_seconds"}):
        raise ValueError("installed D13 counter fields differ")
    return InstalledD13CounterCommandV1(**value)
