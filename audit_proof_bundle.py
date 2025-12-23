#!/usr/bin/env python3
"""audit_proof_bundle.py

Minimal, dependency-light audit + manifest generator for τGuardian SWE-bench runs.

Creates: <RUN>/proof_manifest.json

This is intentionally conservative: it does not attempt to "grade" model quality;
its job is to produce an audit-friendly manifest (hashes + counts) so proof bundles
are reproducible and tamper-evident.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


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


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def read_jsonl(path: Path) -> List[dict]:
    rows: List[dict] = []
    if not path.exists():
        return rows
    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rows.append(json.loads(line))
    return rows


def is_unified_diff(s: str) -> bool:
    s = s or ""
    return ("diff --git" in s) or ("--- a/" in s and "+++ b/")


def summarize_predictions(preds_path: Path) -> Dict[str, Any]:
    if not preds_path.exists():
        return {
            "exists": False,
            "total": 0,
            "empty": 0,
            "invalid": 0,
            "valid": 0,
        }

    x = load_json(preds_path)
    items = list(x.values() if isinstance(x, dict) else x)

    empty: List[str] = []
    invalid: List[str] = []
    valid: List[str] = []

    for r in items:
        iid = r.get("instance_id") or r.get("task") or "?"
        patch = (r.get("model_patch") or r.get("patch") or r.get("prediction") or "")
        if not patch.strip():
            empty.append(iid)
        elif not is_unified_diff(patch):
            invalid.append(iid)
        else:
            valid.append(iid)

    return {
        "exists": True,
        "total": len(items),
        "empty": len(empty),
        "invalid": len(invalid),
        "valid": len(valid),
        "empty_examples": empty[:10],
        "invalid_examples": invalid[:10],
    }


def summarize_eval(instance_results_path: Path) -> Dict[str, Any]:
    if not instance_results_path.exists():
        return {"exists": False, "rows": 0, "resolved_true": 0}

    rows = read_jsonl(instance_results_path)
    resolved_true = 0
    for r in rows:
        if bool(r.get("resolved")):
            resolved_true += 1
    return {"exists": True, "rows": len(rows), "resolved_true": resolved_true}


def summarize_governance(governed_path: Path) -> Dict[str, Any]:
    if not governed_path.exists():
        return {"exists": False, "rows": 0, "by_decision": {}}

    rows = read_jsonl(governed_path)
    by: Dict[str, int] = {}
    for r in rows:
        d = r.get("final_decision") or r.get("decision") or "UNKNOWN"
        by[d] = by.get(d, 0) + 1
    return {"exists": True, "rows": len(rows), "by_decision": by}


def summarize_security(security_dir: Path) -> Dict[str, Any]:
    if not security_dir.exists():
        return {"exists": False, "reports": 0, "scan_failed": 0}

    scan_failed = 0
    reports = 0
    for p in security_dir.glob("*.json"):
        try:
            j = load_json(p)
        except Exception:
            continue
        reports += 1
        if bool(j.get("scan_failed")):
            scan_failed += 1
    return {"exists": True, "reports": reports, "scan_failed": scan_failed}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("run_dir", help="mini-swe-agent run directory (RUN)")
    ap.add_argument("--model-id", default="", help="provider model id (for manifest metadata)")
    ap.add_argument("--tag", default="", help="freeform tag (for manifest metadata)")
    args = ap.parse_args()

    run_dir = Path(args.run_dir).resolve()
    if not run_dir.exists() or not run_dir.is_dir():
        raise SystemExit(f"run_dir not found: {run_dir}")

    preds = run_dir / "preds_filled.json"
    miniswe_log = run_dir / "minisweagent.log"
    eval_results = run_dir / "eval" / "instance_results.jsonl"
    security_dir = run_dir / "security_reports"
    governed = run_dir / "recomputed_governed_v2_agentic.jsonl"
    ci_gate = run_dir / "ci_gate.txt"

    manifest: Dict[str, Any] = {
        "schema": "tauguardian.proof_manifest.v1",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "run_dir": str(run_dir),
        "model_id": args.model_id,
        "tag": args.tag,
        "artifacts": {
            "minisweagent.log": str(miniswe_log) if miniswe_log.exists() else None,
            "preds_filled.json": str(preds) if preds.exists() else None,
            "eval/instance_results.jsonl": str(eval_results) if eval_results.exists() else None,
            "security_reports/": str(security_dir) if security_dir.exists() else None,
            "recomputed_governed_v2_agentic.jsonl": str(governed) if governed.exists() else None,
            "ci_gate.txt": str(ci_gate) if ci_gate.exists() else None,
        },
        "hashes": {
            "minisweagent.log": sha256_file(miniswe_log) if miniswe_log.exists() else None,
            "preds_filled.json": sha256_file(preds) if preds.exists() else None,
            "eval/instance_results.jsonl": sha256_file(eval_results) if eval_results.exists() else None,
            "recomputed_governed_v2_agentic.jsonl": sha256_file(governed) if governed.exists() else None,
            "ci_gate.txt": sha256_file(ci_gate) if ci_gate.exists() else None,
            "security_reports": sha256_dir(security_dir),
        },
        "summary": {
            "predictions": summarize_predictions(preds),
            "eval": summarize_eval(eval_results),
            "security": summarize_security(security_dir),
            "governance": summarize_governance(governed),
        },
    }

    out_path = run_dir / "proof_manifest.json"
    out_path.write_text(json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")

    # Human-readable console summary
    pred = manifest["summary"]["predictions"]
    gov = manifest["summary"]["governance"]
    ev = manifest["summary"]["eval"]
    sec = manifest["summary"]["security"]

    print("[audit_proof_bundle] wrote:", out_path)
    print("  predictions:", pred)
    print("  eval:", ev)
    print("  security:", sec)
    print("  governance:", gov)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
