"""Export an actual TypeRegistry snapshot; never invent a release catalogue."""
from __future__ import annotations

import argparse
import importlib
import json
from pathlib import Path

from sylanne3.graph_types import TypeRegistry


def registrar(path: str):
    module_name, separator, symbol = path.partition(":")
    if not separator or not module_name or not symbol:
        raise ValueError("registrar must be MODULE:CALLABLE")
    callback = getattr(importlib.import_module(module_name), symbol)
    if not callable(callback):
        raise TypeError("catalogue registrar is not callable")
    return callback


def export(registrar_paths: list[str], output: Path, *, allow_incomplete: bool, expected_domains: tuple[str, ...]) -> None:
    registry = TypeRegistry()
    for path in registrar_paths:
        registrar(path)(registry)
    if not registry.specs:
        raise RuntimeError("refusing to export an empty catalogue")
    names = [spec.name for spec in registry.specs]
    if len(names) != len(set(names)):
        raise RuntimeError("refusing to export a catalogue with duplicate type names")
    rows = [{"name": spec.name, "owner_kinds": list(spec.owner_kinds),
             "storage_role": spec.storage_role, "immutable": spec.immutable,
             "schema_version": spec.schema_version, "writer_domain": spec.writer_domain,
             "schema_hash": spec.schema_hash} for spec in registry.specs]
    actual_domains = tuple(sorted({spec.writer_domain for spec in registry.specs}))
    missing_domains = tuple(domain for domain in expected_domains if domain not in actual_domains)
    document = {"schema_version": "sylanne.catalogue.v1", "catalogue_hash": registry.catalogue_hash,
                "registrars": registrar_paths, "types": rows,
                "declared_domains": actual_domains, "missing_domain_exports": missing_domains,
                "completeness": "candidate-exports-only" if allow_incomplete else "registered-exports"}
    document["activation_status"] = "candidate_only"
    document["release_eligibility"] = "HOLD: exported types are candidates; runtime activation, migration, and complete domain export evidence are required"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--registrar", action="append", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--allow-incomplete", action="store_true")
    parser.add_argument("--expected-domain", action="append", default=[f"d{number:02d}" for number in range(1, 13)])
    args = parser.parse_args()
    export(args.registrar, args.output, allow_incomplete=args.allow_incomplete, expected_domains=tuple(args.expected_domain))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
