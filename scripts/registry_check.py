#!/usr/bin/env python3
"""Validate registry/*.json catalogs: shape, unique ids, cross-references, on-disk paths.

Also cross-checks marketplace/manifest.json against registry/policy-pack-catalog.json
and validates every listed policy pack directory. See registry/README.md.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REGISTRY_DIR = ROOT / "registry"
MARKETPLACE_MANIFEST = ROOT / "marketplace/manifest.json"

sys.path.insert(0, str(Path(__file__).resolve().parent))
from validate_policy_pack import validate as validate_pack


def _load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _check_unique_ids(entries: list[dict], id_key: str, label: str, errors: list[str]) -> None:
    seen: set[str] = set()
    for entry in entries:
        entry_id = entry.get(id_key)
        if not entry_id:
            errors.append(f"{label}: entry missing '{id_key}': {entry!r}")
            continue
        if entry_id in seen:
            errors.append(f"{label}: duplicate {id_key} {entry_id!r}")
        seen.add(entry_id)


def check_capability_taxonomy(errors: list[str]) -> set[str]:
    path = REGISTRY_DIR / "capability-taxonomy.json"
    if not path.exists():
        errors.append(f"missing: {path.relative_to(ROOT)}")
        return set()
    data = _load(path)
    categories = data.get("categories", [])
    _check_unique_ids(categories, "id", "capability-taxonomy", errors)
    for cat in categories:
        for doc_path in cat.get("documentation_paths", []):
            if not (ROOT / doc_path).exists():
                errors.append(f"capability-taxonomy: {cat.get('id')} documentation_paths missing file: {doc_path}")
    return {c.get("id") for c in categories if c.get("id")}


def check_certification_levels(errors: list[str]) -> set[str]:
    path = REGISTRY_DIR / "certification-levels.json"
    if not path.exists():
        errors.append(f"missing: {path.relative_to(ROOT)}")
        return set()
    data = _load(path)
    levels = data.get("levels", [])
    _check_unique_ids(levels, "id", "certification-levels", errors)
    for level in levels:
        for doc_path in level.get("documentation_paths", []):
            if not (ROOT / doc_path).exists():
                errors.append(f"certification-levels: {level.get('id')} documentation_paths missing file: {doc_path}")
    return {lvl.get("id") for lvl in levels if lvl.get("id")}


def check_standards_catalog(errors: list[str]) -> None:
    path = REGISTRY_DIR / "standards-catalog.json"
    if not path.exists():
        errors.append(f"missing: {path.relative_to(ROOT)}")
        return
    data = _load(path)
    standards = data.get("standards", [])
    _check_unique_ids(standards, "id", "standards-catalog", errors)
    for std in standards:
        schema_path = std.get("json_schema_path")
        if schema_path and not (ROOT / schema_path).exists():
            errors.append(f"standards-catalog: {std.get('id')} json_schema_path missing file: {schema_path}")
        for doc_path in std.get("documentation_paths", []):
            if not (ROOT / doc_path).exists():
                errors.append(f"standards-catalog: {std.get('id')} documentation_paths missing file: {doc_path}")


def check_benchmark_catalog(errors: list[str]) -> None:
    path = REGISTRY_DIR / "benchmark-catalog.json"
    if not path.exists():
        errors.append(f"missing: {path.relative_to(ROOT)}")
        return
    data = _load(path)
    benchmarks = data.get("benchmarks", [])
    _check_unique_ids(benchmarks, "id", "benchmark-catalog", errors)
    for bench in benchmarks:
        for key in ("readme_path", "runner_path", "scenarios_path"):
            p = bench.get(key)
            if p and not (ROOT / p).exists():
                errors.append(f"benchmark-catalog: {bench.get('id')} {key} missing file: {p}")


def check_policy_pack_catalog_and_marketplace(
    errors: list[str], capability_ids: set[str], certification_ids: set[str]
) -> None:
    path = REGISTRY_DIR / "policy-pack-catalog.json"
    if not path.exists():
        errors.append(f"missing: {path.relative_to(ROOT)}")
        return
    data = _load(path)
    packs = data.get("policy_packs", [])
    _check_unique_ids(packs, "id", "policy-pack-catalog", errors)

    catalog_by_id = {}
    for pack in packs:
        pack_id = pack.get("id")
        catalog_by_id[pack_id] = pack

        pack_path = pack.get("path")
        if not pack_path or not (ROOT / pack_path).is_dir():
            errors.append(f"policy-pack-catalog: {pack_id} path missing: {pack_path}")
        else:
            pack_errors = validate_pack(ROOT / pack_path)
            for e in pack_errors:
                errors.append(f"policy-pack-catalog: {pack_id}: {e}")

        cert_id = pack.get("certification_level_id")
        if certification_ids and cert_id not in certification_ids:
            errors.append(f"policy-pack-catalog: {pack_id} unknown certification_level_id: {cert_id}")

        for cap_id in pack.get("capability_ids", []):
            if capability_ids and cap_id not in capability_ids:
                errors.append(f"policy-pack-catalog: {pack_id} unknown capability_id: {cap_id}")

    if not MARKETPLACE_MANIFEST.exists():
        errors.append(f"missing: {MARKETPLACE_MANIFEST.relative_to(ROOT)}")
        return

    manifest = _load(MARKETPLACE_MANIFEST)
    manifest_packs = manifest.get("packs", [])
    _check_unique_ids(manifest_packs, "id", "marketplace-manifest", errors)

    manifest_ids = {p.get("id") for p in manifest_packs if p.get("id")}
    catalog_ids = set(catalog_by_id.keys())

    for missing_from_catalog in manifest_ids - catalog_ids:
        errors.append(f"marketplace-manifest: {missing_from_catalog} not present in registry/policy-pack-catalog.json")
    for missing_from_manifest in catalog_ids - manifest_ids:
        errors.append(f"policy-pack-catalog: {missing_from_manifest} not present in marketplace/manifest.json")

    for pack in manifest_packs:
        pack_id = pack.get("id")
        catalog_entry = catalog_by_id.get(pack_id)
        if catalog_entry and catalog_entry.get("path") != pack.get("path"):
            errors.append(
                f"marketplace-manifest/policy-pack-catalog path mismatch for {pack_id}: "
                f"{pack.get('path')!r} vs {catalog_entry.get('path')!r}"
            )


def main() -> int:
    errors: list[str] = []

    capability_ids = check_capability_taxonomy(errors)
    certification_ids = check_certification_levels(errors)
    check_standards_catalog(errors)
    check_benchmark_catalog(errors)
    check_policy_pack_catalog_and_marketplace(errors, capability_ids, certification_ids)

    as_json = "--json" in sys.argv
    ok = not errors

    if as_json:
        print(json.dumps({"ok": ok, "errors": errors}, sort_keys=True))
    else:
        if ok:
            print("registry_check: OK")
        else:
            print("registry_check: FAILED", file=sys.stderr)
            for err in errors:
                print(f"  - {err}", file=sys.stderr)

    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
