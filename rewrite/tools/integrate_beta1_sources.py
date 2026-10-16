"""Integrate reviewed source packets without dropping local or prior packet changes.

Engineering only: never imports the product, opens a database, or runs a node.
Each application has an exclusive receipt containing the exact before/after hashes.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
from pathlib import Path
import subprocess
import symtable
import tempfile


def digest(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def same_digest(value, expected):
    return expected in (digest(value), digest(value.replace("\n", "\r\n")))


def text(path):
    return path.read_text(encoding="utf-8").replace("\r\n", "\n")


def edits_for(item, after):
    result = []
    for raw in item.get("finite_edits", item.get("edits", ())):
        edit = dict(raw)
        if "before" in edit and "old" not in edit:
            edit["old"] = edit["before"]
        if "after" in edit and "new" not in edit:
            edit["new"] = edit["after"]
        for key in ("old", "new"):
            edit.setdefault(key, "")
            edit[key] = edit[key].replace("\r\n", "\n")
        if after and edit["new"] not in after and edit["new"].replace("\\n", "\n") in after:
            edit["old"] = edit["old"].replace("\\n", "\n")
            edit["new"] = edit["new"].replace("\\n", "\n")
        result.append(edit)
    return result


def entries(packet):
    for field in ("files", "finite_files", "new_files", "new_sources", "changed_sources"):
        values = packet.get(field, ())
        if isinstance(values, dict):
            for path, value in values.items():
                yield {"path": path, **({"source": value} if isinstance(value, str) else value)}
        else:
            yield from values


def source_of(item):
    value = item.get("source", item.get("candidate_source", item.get("after_source")))
    return value.replace("\r\n", "\n") if value is not None else None


def reverse_source(after, edits, expected):
    if not after or not expected:
        return None
    if edits and all("old_start_line" in edit for edit in edits):
        operations, offset = [], 0
        for edit in sorted(edits, key=lambda value: value["old_start_line"]):
            old, new = edit["old"].splitlines(keepends=True), edit["new"].splitlines(keepends=True)
            position = edit["old_start_line"] - 1 + offset
            operations.append((position, old, new))
            offset += len(new) - len(old)
        lines = after.splitlines(keepends=True)
        for position, old, new in reversed(operations):
            if lines[position:position + len(new)] != new:
                break
            lines[position:position + len(new)] = old
        else:
            before = "".join(lines)
            if same_digest(before, expected):
                return before
    before = after
    for edit in reversed(edits):
        new, old = edit["new"], edit["old"]
        count = edit.get("occurrences", 1)
        if not new or before.count(new) != count:
            return None
        before = before.replace(new, old, count)
    return before if same_digest(before, expected) else None


def rebase(current, before, after):
    """Use Git's three-way text merge; ephemeral inputs are removed on exit."""
    parent = Path(tempfile.gettempdir()).resolve()
    with tempfile.TemporaryDirectory(prefix="sylanne-source-merge-", dir=parent) as directory:
        folder = Path(directory).resolve()
        if folder.parent != parent:
            raise ValueError("merge scratch directory leaves the selected temporary directory")
        paths = [folder / name for name in ("current", "base", "candidate")]
        for path, value in zip(paths, (current, before, after), strict=True):
            path.write_bytes(value.encode("utf-8"))
        result = subprocess.run(["git", "merge-file", "--stdout", *map(str, paths)],
                                capture_output=True, check=False)
        if result.returncode:
            conflict = result.stdout.decode("utf-8", errors="replace")
            start = conflict.find("<<<<<<<")
            raise ValueError("three-way source conflict: " + conflict[max(0, start):max(0, start) + 1600])
        return result.stdout.decode("utf-8")


def apply_declared(current, edits):
    for edit in edits:
        old, new = edit["old"], edit["new"]
        count = edit.get("occurrences", 1)
        if old and current.count(old) == count:
            current = current.replace(old, new, count)
        elif new and current.count(new) == count:
            continue
        elif not old and edit.get("position") == "eof":
            current += new
        else:
            raise ValueError(f"declared source anchor is not unique: {old[:100]!r}")
    return current


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--recipe", required=True, type=Path)
    parser.add_argument("--receipt", required=True, type=Path)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    if args.receipt.exists():
        raise FileExistsError(args.receipt)
    recipe = json.loads(text(args.recipe))
    packets = [(Path(path), json.loads(text(Path(path)))) for path in recipe["packets"]]
    context = [(Path(path), json.loads(text(Path(path)))) for path in recipe.get("bases", ())]
    blobs = {}
    for _, packet in (*context, *packets):
        for item in entries(packet):
            for key in ("source", "candidate_source", "after_source", "before_source"):
                value = item.get(key)
                if isinstance(value, str):
                    normalized = value.replace("\r\n", "\n")
                    blobs[digest(value)] = normalized
                    blobs[digest(normalized)] = normalized
            after = source_of(item)
            expected = item.get("before_sha256", item.get("basis_source_sha256", item.get("actual_before_sha256")))
            before = reverse_source(after, edits_for(item, after), expected)
            if before is not None:
                blobs[expected] = before
                blobs[digest(before)] = before
    root = args.root.resolve()
    current, originals, provenance, written = {}, {}, [], []
    try:
        for packet_path, packet in packets:
            for item in entries(packet):
                relative = item["path"].replace("\\", "/")
                if relative.startswith(("runtime/", "authority_service/", "host/", "domains/")) or relative == "graph_store.py":
                    relative = "rewrite/sylanne3/" + relative
                path = (root / relative).resolve()
                if not path.is_relative_to(root):
                    raise ValueError("packet source leaves the chosen product workspace")
                if path not in current:
                    originals[path] = path.read_bytes() if path.exists() else None
                    current[path] = text(path) if path.exists() else ""
                old = current[path]
                after = source_of(item)
                edits = edits_for(item, after)
                expected = item.get("before_sha256", item.get("basis_source_sha256", item.get("actual_before_sha256")))
                if after is not None and digest(old) == digest(after):
                    continue
                if after is not None and (not old or same_digest(old, expected)):
                    updated = after
                else:
                    before = blobs.get(expected) or reverse_source(after, edits, expected)
                    if edits and all(edit["old"] or edit.get("position") == "eof" for edit in edits):
                        try:
                            updated = apply_declared(old, edits)
                        except ValueError:
                            if before is None or after is None:
                                raise
                            updated = rebase(old, before, after)
                    elif before is not None:
                        updated = rebase(old, before, after) if after is not None else apply_declared(old, edits)
                        blobs[digest(before)] = before
                    elif edits:
                        updated = apply_declared(old, edits)
                    else:
                        raise ValueError("actual source differs and packet has no recoverable base or finite edits")
                current[path] = updated
                blobs[digest(updated)] = updated
                provenance.append({"packet": str(packet_path), "path": relative,
                                   "before": digest(old), "after": digest(updated)})
        for path, source in current.items():
            if path.suffix == ".py":
                compile(source, str(path), "exec")
                ast.parse(source, filename=str(path), feature_version=(3, 12))
                symtable.symtable(source, str(path), "exec")
        if args.apply:
            for path, before in originals.items():
                if (path.read_bytes() if path.exists() else None) != before:
                    raise ValueError(f"actual product source changed while composing: {path}")
            for path, source in current.items():
                if originals[path] == source.encode("utf-8"):
                    continue
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(source.encode("utf-8"))
                written.append(str(path.relative_to(root)))
                if text(path) != source:
                    raise ValueError(f"written source differs: {path}")
        receipt = {"status": "SOURCE_APPLIED_COMPILED" if args.apply else "COMPOSED_COMPILED_NOT_APPLIED",
                   "root": str(root), "recipe": str(args.recipe), "changes": provenance,
                   "files": [{"path": str(path.relative_to(root)), "after": digest(source)}
                             for path, source in sorted(current.items())],
                   "product_imports": 0, "runtime": False, "overall": "HOLD"}
    except Exception as error:
        receipt = {"status": "FIRST_SOURCE_COMPOSITION_FAILURE", "error": str(error),
                   "packet": str(packet_path), "path": relative, "product_written": bool(written),
                   "written_files": written,
                   "completed_composition_changes": provenance, "overall": "HOLD"}
        with args.receipt.open("x", encoding="utf-8") as stream:
            json.dump(receipt, stream, ensure_ascii=False, indent=2)
        raise
    with args.receipt.open("x", encoding="utf-8") as stream:
        json.dump(receipt, stream, ensure_ascii=False, indent=2)
    print(json.dumps({"status": receipt["status"], "files": len(current),
                      "receipt": str(args.receipt)}, ensure_ascii=False))


if __name__ == "__main__":
    main()
