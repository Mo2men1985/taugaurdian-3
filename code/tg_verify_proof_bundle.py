#!/usr/bin/env python3
"""Verify τGuardian proof bundle integrity."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    import yaml  # type: ignore
except ImportError:  # pragma: no cover
    yaml = None  # type: ignore


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_dir(path: Path) -> Dict[str, str]:
    out: Dict[str, str] = {}
    if not path.exists():
        return out
    for p in sorted(path.rglob("*")):
        if p.is_file():
            rel = str(p.relative_to(path))
            out[rel] = sha256_file(p)
    return out


def load_manifest(path: Path) -> Dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _policy_version(path: Path) -> str:
    if yaml is None:
        raise RuntimeError("PyYAML is required to verify policy versions.")
    with path.open("r", encoding="utf-8") as f:
        obj = yaml.safe_load(f)  # type: ignore[attr-defined]
    if isinstance(obj, dict):
        return str(obj.get("version") or "")
    return ""


def verify_manifest(run_dir: Path, manifest_path: Optional[Path] = None) -> Tuple[bool, List[str]]:
    errors: List[str] = []
    manifest_path = manifest_path or (run_dir / "proof_manifest.json")
    if not manifest_path.exists():
        return False, [f"manifest missing: {manifest_path}"]

    manifest = load_manifest(manifest_path)
    hashes = manifest.get("hashes") or {}

    for key in (
        "minisweagent.log",
        "preds_filled.json",
        "eval/instance_results.jsonl",
        "recomputed_governed_v2_agentic.jsonl",
        "ci_gate.txt",
    ):
        expected = hashes.get(key)
        if expected is None:
            continue
        path = run_dir / key
        if not path.exists():
            errors.append(f"missing artifact: {key}")
            continue
        actual = sha256_file(path)
        if actual != expected:
            errors.append(f"sha256 mismatch for {key}: {actual} != {expected}")

    security_expected = hashes.get("security_reports") or {}
    if security_expected:
        security_dir = run_dir / "security_reports"
        actual_security = sha256_dir(security_dir)
        for rel, expected in security_expected.items():
            actual = actual_security.get(rel)
            if actual is None:
                errors.append(f"missing security report: {rel}")
            elif actual != expected:
                errors.append(f"sha256 mismatch for security_reports/{rel}: {actual} != {expected}")
        for rel in actual_security:
            if rel not in security_expected:
                errors.append(f"unexpected security report: {rel}")

    policy = manifest.get("policy") or {}
    policy_path = policy.get("path") or ""
    policy_sha = policy.get("sha256") or ""
    policy_version = policy.get("version") or ""
    if policy_path:
        policy_path_obj = Path(policy_path)
        if not policy_path_obj.exists():
            errors.append(f"policy missing: {policy_path}")
        else:
            actual_sha = sha256_file(policy_path_obj)
            if policy_sha and actual_sha != policy_sha:
                errors.append(f"policy sha256 mismatch: {actual_sha} != {policy_sha}")
            if policy_version:
                try:
                    actual_version = _policy_version(policy_path_obj)
                except Exception as exc:
                    errors.append(f"policy version check failed: {exc}")
                else:
                    if actual_version != policy_version:
                        errors.append(
                            f"policy version mismatch: {actual_version} != {policy_version}"
                        )
    elif policy_sha or policy_version:
        errors.append("policy metadata present but policy path missing in manifest")

    return not errors, errors


def main() -> int:
    ap = argparse.ArgumentParser(description="Verify τGuardian proof bundles.")
    ap.add_argument("--run-dir", required=True, help="mini-swe-agent run directory (RUN)")
    ap.add_argument(
        "--manifest",
        default=None,
        help="Optional path to proof_manifest.json (defaults to RUN/proof_manifest.json).",
    )
    args = ap.parse_args()

    run_dir = Path(args.run_dir).resolve()
    manifest_path = Path(args.manifest).resolve() if args.manifest else None

    ok, errors = verify_manifest(run_dir, manifest_path)
    if ok:
        print(f"[verify] OK: {run_dir}")
        return 0

    print(f"[verify] FAILED: {run_dir}")
    for err in errors:
        print(f"  - {err}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
