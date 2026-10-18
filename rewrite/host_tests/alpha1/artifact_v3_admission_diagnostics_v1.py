"""Root-only matching of real Core rejection diagnostics for a fresh fixture.

This reads existing diagnostic records. It grants no permission and never
changes the Core, its clock, grant, reservation, transport or result.
"""
from pathlib import Path
import ast
import hashlib
import json
import os
import stat


def _open_log(path):
    if os.name != "posix" or os.geteuid() != 0:
        raise PermissionError("isolated fixture Root controller required")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    current = os.fstat(fd)
    if not stat.S_ISREG(current.st_mode) or current.st_uid != 0 or current.st_mode & 0o022:
        os.close(fd)
        raise ValueError("diagnostic log must be the protected isolated Core log")
    return fd, current


def capture_core_diagnostic_cursor_v1(path):
    fd, current = _open_log(path)
    try:
        return {"device":current.st_dev,"inode":current.st_ino,"offset":current.st_size}
    finally:
        os.close(fd)


def require_original_intent_rejections_v1(path, cursor, *, count, package_root=Path("/opt/sylanne/code")):
    source = package_root / "rewrite/sylanne3/authority_service/v2_model_egress_store.py"
    encoded = source.read_bytes()
    manifest = json.loads((package_root/"release-manifest.json").read_bytes())
    row = next(item for item in manifest["source_inventory"]["files"]
        if item["path"] == source.relative_to(package_root).as_posix())
    if hashlib.sha256(encoded).hexdigest() != row["sha256"]:
        raise ValueError("Core diagnostic gate source differs from the actual installed manifest")
    gates = [node.lineno for node in ast.walk(ast.parse(encoded)) if isinstance(node,ast.Raise)
        and isinstance(node.exc,ast.Call) and isinstance(node.exc.func,ast.Name)
        and node.exc.func.id == "AuthorityUnavailable" and len(node.exc.args) == 1
        and isinstance(node.exc.args[0],ast.Constant)
        and node.exc.args[0].value == "model egress identity changed or absent"]
    if len(gates) != 1:
        raise ValueError("the exact original-intent rejection gate is unavailable")
    fd, current = _open_log(path)
    try:
        if (current.st_dev,current.st_ino)!=(cursor["device"],cursor["inode"]) or current.st_size<cursor["offset"]:
            raise ValueError("Core diagnostic log rotated or regressed; preserve first failure")
        length=current.st_size-cursor["offset"]
        if length>131072:
            raise ValueError("Core diagnostic delta exceeded its fixed capture bound")
        delta=os.pread(fd,length,cursor["offset"])
        if len(delta)!=length:
            raise ValueError("Core diagnostic delta is incomplete")
    finally:
        os.close(fd)
    records=[]
    for line in delta.decode("utf-8").splitlines():
        if "Authority internal failure: " not in line:
            continue
        chain=json.loads(line.split("Authority internal failure: ",1)[1])
        matching=[entry for entry in chain if entry["type"]=="AuthorityUnavailable" and any(
            Path(frame["file"]).name==source.name and frame["function"]=="read_locked"
            and frame["line"]==gates[0] for frame in entry["frames"])]
        if len(matching)!=1:
            raise ValueError("first real Core rejection did not reach the exact original-intent gate")
        records.append({"exception":"AuthorityUnavailable","function":"read_locked","line":gates[0],
            "source_sha256":row["sha256"],"reason":"model egress identity changed or absent"})
    if len(records)!=count:
        raise ValueError("actual Core diagnostic count differs from the bounded submitted tamper cases")
    return {"scope":"real Core original-intent identity rejection, not a deep TTL or valid foreign-grant proof",
        "begin_offset":cursor["offset"],"end_offset":current.st_size,
        "delta_sha256":hashlib.sha256(delta).hexdigest(),"rejections":records}
