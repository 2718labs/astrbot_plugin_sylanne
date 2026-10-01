"""Export an actual TypeRegistry snapshot; never invent a release catalogue."""
from __future__ import annotations

import argparse
import importlib
import json
from pathlib import Path

from sylanne3.domain_registry import discover_domain_registry
from sylanne3.domains.d04 import AffectAxis, AffectScheme
from sylanne3.graph_types import TypeRegistry


def registrar(path: str):
    module_name, separator, symbol = path.partition(":")
    if not separator or not module_name or not symbol:
        raise ValueError("registrar must be MODULE:CALLABLE")
    callback = getattr(importlib.import_module(module_name), symbol)
    if not callable(callback):
        raise TypeError("catalogue registrar is not callable")
    return callback


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate D04 scheme field: {key}")
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ValueError(f"invalid D04 number: {value}")


def _load_active_scheme(path: Path) -> AffectScheme:
    data = json.loads(
        path.read_bytes(), object_pairs_hook=_unique_object,
        parse_constant=_reject_constant,
    )
    fields = {"schema", "scheme_version", "operator_version", "parameter_version",
              "coupling_version", "axes", "parameter_bounds"}
    if not isinstance(data, dict) or set(data) != fields:
        raise ValueError("D04 scheme asset fields are invalid")
    return AffectScheme(
        schema=data["schema"],
        scheme_version=data["scheme_version"],
        operator_version=data["operator_version"],
        parameter_version=data["parameter_version"],
        coupling_version=data["coupling_version"],
        axes=tuple(AffectAxis(**axis) for axis in data["axes"]),
        parameter_bounds=tuple(tuple(item) for item in data["parameter_bounds"]),
    )


def export(
    registrar_paths: list[str], output: Path, *, allow_incomplete: bool,
    expected_domains: tuple[str, ...], active_affect_scheme_path: Path | None = None,
) -> None:
    if active_affect_scheme_path is None:
        registry = TypeRegistry()
        for path in registrar_paths:
            registrar(path)(registry)
        source_registrars = registrar_paths
        capabilities = None
    else:
        active = discover_domain_registry(
            active_affect_scheme=_load_active_scheme(active_affect_scheme_path),
        )
        if not active.complete:
            raise RuntimeError(f"active DomainRegistry is incomplete: {dict(active.unavailable)}")
        registry = active.type_registry
        source_registrars = []
        capabilities = {"d04": [active.active_affect_scheme.schema]}
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
                "registrars": source_registrars, "types": rows,
                "declared_domains": actual_domains, "missing_domain_exports": missing_domains,
                "completeness": "candidate-exports-only" if allow_incomplete else "registered-exports"}
    document["activation_status"] = "candidate_only"
    document["release_eligibility"] = "HOLD: exported types are candidates; runtime activation, migration, and complete domain export evidence are required"
    if capabilities is not None:
        document["runtime_registry"] = "sylanne3.domain_registry:discover_domain_registry"
        document["domain_capabilities"] = capabilities
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--registrar", action="append", default=[])
    parser.add_argument("--active-affect-scheme", type=Path,
                        help="export actual DomainRegistry with an external D04 scheme asset; remains candidate-only")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--allow-incomplete", action="store_true")
    parser.add_argument("--expected-domain", action="append", default=[f"d{number:02d}" for number in range(1, 14)])
    args = parser.parse_args()
    if args.active_affect_scheme is None and not args.registrar:
        parser.error("--registrar is required without --active-affect-scheme")
    if args.active_affect_scheme is not None and args.registrar:
        parser.error("--registrar and --active-affect-scheme are separate export modes")
    export(args.registrar, args.output, allow_incomplete=args.allow_incomplete,
           expected_domains=tuple(args.expected_domain),
           active_affect_scheme_path=args.active_affect_scheme)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
