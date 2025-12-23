#!/usr/bin/env python3
"""tg_run_audit.py

Audit utility for τGuardian SWE-bench runs.

Checks:
  - preds_filled.json (or preds.json)
  - eval/instance_results.jsonl
  - eval/instance_results.metadata.json with matching SHA
  - security_reports/*.json coverage and scan_failed flags

Exit codes:
  0 = audit passes
  2 = audit warnings (non-fatal)
  3 = audit failure (missing critical files, SHA mismatch, etc.)
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


METADATA_FILENAME = "instance_results.metadata.json"


def _compute_file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _load_json(path: Path) -> Optional[Dict[str, Any]]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _load_instance_results(path: Path) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return rows


def _select_predictions_file(msa_dir: Path) -> Optional[Path]:
    preds_filled = msa_dir / "preds_filled.json"
    if preds_filled.exists():
        return preds_filled
    preds = msa_dir / "preds.json"
    if preds.exists():
        return preds
    return None


def _audit_metadata(preds_path: Path, metadata_path: Path) -> Tuple[List[str], List[str]]:
    failures: List[str] = []
    warnings: List[str] = []

    if not metadata_path.exists():
        failures.append("metadata_missing")
        return failures, warnings

    meta = _load_json(metadata_path)
    if not meta:
        failures.append("metadata_unreadable")
        return failures, warnings

    expected_sha = _compute_file_sha256(preds_path)
    meta_sha = meta.get("predictions_sha256")
    meta_path = meta.get("predictions_path")

    if meta_sha != expected_sha:
        failures.append("predictions_sha_mismatch")
    if meta_path and meta_path != str(preds_path):
        failures.append("predictions_path_mismatch")

    if not meta.get("cli_command"):
        warnings.append("metadata_missing_cli_command")

    return failures, warnings


def _audit_security_reports(
    security_dir: Path,
    instance_ids: List[str],
) -> Tuple[List[str], List[str], int]:
    failures: List[str] = []
    warnings: List[str] = []
    scan_failed_count = 0

    if not security_dir.exists():
        failures.append("security_reports_missing")
        return failures, warnings, scan_failed_count

    reports = list(security_dir.glob("*.json"))
    missing = []
    for instance_id in instance_ids:
        report_path = security_dir / f"{instance_id}.json"
        if not report_path.exists():
            missing.append(instance_id)
            continue
        report = _load_json(report_path)
        if not report:
            warnings.append(f"security_report_unreadable:{instance_id}")
            continue
        if report.get("scan_failed") is True:
            scan_failed_count += 1

    if missing:
        failures.append(f"security_reports_missing:{len(missing)}")

    return failures, warnings, scan_failed_count


def _print_report(report: Dict[str, Any]) -> None:
    print("[tg_run_audit] Audit report")
    print(f"  predictions_path      : {report.get('predictions_path')}")
    print(f"  instance_results_path : {report.get('instance_results_path')}")
    print(f"  metadata_path         : {report.get('metadata_path')}")
    print(f"  instance_results_rows : {report.get('instance_results_count')}")
    print(f"  security_reports_dir  : {report.get('security_reports_dir')}")
    print(f"  security_reports_rows : {report.get('security_reports_count')}")
    print(f"  scan_failed_count     : {report.get('scan_failed_count')}")

    if report.get("failures"):
        print("  failures:")
        for item in report["failures"]:
            print(f"    - {item}")

    if report.get("warnings"):
        print("  warnings:")
        for item in report["warnings"]:
            print(f"    - {item}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Audit a τGuardian SWE-bench run directory")
    parser.add_argument("--msa-dir", required=True, help="mini-SWE-agent run directory (RUN)")
    args = parser.parse_args()

    msa_dir = Path(args.msa_dir).expanduser().resolve()
    eval_dir = msa_dir / "eval"
    security_dir = msa_dir / "security_reports"

    failures: List[str] = []
    warnings: List[str] = []

    preds_path = _select_predictions_file(msa_dir)
    if not preds_path:
        failures.append("predictions_missing")

    instance_results_path = eval_dir / "instance_results.jsonl"
    if not instance_results_path.exists():
        failures.append("instance_results_missing")

    metadata_path = eval_dir / METADATA_FILENAME

    instance_rows: List[Dict[str, Any]] = []
    instance_ids: List[str] = []
    if instance_results_path.exists():
        instance_rows = _load_instance_results(instance_results_path)
        instance_ids = [str(row.get("instance_id")) for row in instance_rows if row.get("instance_id")]
        if not instance_rows:
            failures.append("instance_results_empty")

    if preds_path and instance_results_path.exists():
        meta_failures, meta_warnings = _audit_metadata(preds_path, metadata_path)
        failures.extend(meta_failures)
        warnings.extend(meta_warnings)

    security_failures, security_warnings, scan_failed_count = _audit_security_reports(
        security_dir, instance_ids
    )
    failures.extend(security_failures)
    warnings.extend(security_warnings)

    report = {
        "predictions_path": str(preds_path) if preds_path else None,
        "instance_results_path": str(instance_results_path),
        "metadata_path": str(metadata_path),
        "instance_results_count": len(instance_rows),
        "security_reports_dir": str(security_dir),
        "security_reports_count": len(list(security_dir.glob("*.json"))) if security_dir.exists() else 0,
        "scan_failed_count": scan_failed_count,
        "failures": failures,
        "warnings": warnings,
    }

    _print_report(report)

    if failures:
        sys.exit(3)
    if warnings:
        sys.exit(2)
    sys.exit(0)


if __name__ == "__main__":
    main()
