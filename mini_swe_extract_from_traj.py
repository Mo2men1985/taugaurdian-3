#!/usr/bin/env python3
"""Extract SWE-bench predictions from mini-swe-agent trajectories.

Why this exists:
- Some runs put the final patch in `info.submission`.
- Some runs never populate `info.submission` but DO include a diff in `messages`.

This script prefers `info.submission` when it looks like a real diff, otherwise
falls back to scanning `messages`.

Outputs:
- <run>/preds.json (raw)
- <run>/preds_filled.json (normalized + non-empty enforcement)

Usage:
  python mini_swe_extract_from_traj_merged.py --run-dir RUN_DIR

Exit codes:
  0 success
  2 one or more instances had no extractable diff (empty patch)
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


def _strip_code_fences(text: str) -> str:
    # Remove common markdown fences without damaging real diffs.
    t = text.strip()
    # ```diff ... ``` or ``` ... ```
    if t.startswith("```") and t.endswith("```"):
        lines = t.splitlines()
        # drop first and last fence lines
        if len(lines) >= 2:
            t = "\n".join(lines[1:-1]).strip("\n")
    return t


def _looks_like_unified_diff(text: str) -> bool:
    if not text:
        return False
    # Strong markers
    if "diff --git" in text:
        return True
    if "--- a/" in text and "+++ b/" in text:
        return True
    # Moderate marker: hunk header + file headers
    if "@@" in text and ("--- " in text or "+++ " in text):
        return True
    return False


def _iter_message_texts(messages: List[Dict[str, Any]]) -> Iterable[str]:
    for m in messages or []:
        c = m.get("content")
        if isinstance(c, str):
            yield c
        elif isinstance(c, list):
            # Some trajectory formats store content as list of blocks
            for block in c:
                if isinstance(block, dict):
                    t = block.get("text")
                    if isinstance(t, str):
                        yield t


def extract_patch_from_traj(traj: Dict[str, Any]) -> Tuple[str, str]:
    """Return (patch, source) where source is 'info.submission' or 'messages'."""
    info = traj.get("info") or {}
    submission = info.get("submission") or ""
    submission = _strip_code_fences(submission)
    if _looks_like_unified_diff(submission):
        return submission.strip("\n") + "\n", "info.submission"

    # Fallback: search messages for the first unified diff block.
    texts = list(_iter_message_texts(traj.get("messages") or []))

    # Heuristic: diffs can be large; search concatenated then extract around markers.
    joined = "\n\n".join(texts)
    joined = _strip_code_fences(joined)

    # Try to locate a diff start.
    for marker in ["diff --git", "--- a/", "*** Begin Patch"]:
        idx = joined.find(marker)
        if idx != -1:
            candidate = joined[idx:]
            # If it's unified diff, accept.
            if _looks_like_unified_diff(candidate):
                return candidate.strip("\n") + "\n", "messages"
            # If it's Begin Patch style, keep it (better than empty) but label it.
            if marker == "*** Begin Patch":
                return candidate.strip("\n") + "\n", "messages_begin_patch"

    return "", "none"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--run-dir", required=True, help="mini-swe-agent run directory")
    args = ap.parse_args()

    run_dir = Path(args.run_dir)
    traj_paths = sorted(run_dir.rglob("*.traj.json"))
    if not traj_paths:
        raise FileNotFoundError(f"No *.traj.json found under: {run_dir}")

    preds: List[Dict[str, Any]] = []
    preds_filled: List[Dict[str, Any]] = []

    missing = 0
    for p in traj_paths:
        d = json.loads(p.read_text(encoding="utf-8"))
        instance_id = d.get("instance_id") or p.stem.replace(".traj", "")
        patch, source = extract_patch_from_traj(d)
        submission_valid = _looks_like_unified_diff(patch)

        rec = {
            "model_name_or_path": "extracted_from_trajectory",
            "instance_id": instance_id,
            "model_patch": patch,
            "_patch_source": source,
            "_traj_path": str(p.relative_to(run_dir)),
            "submission_valid": submission_valid,
        }
        preds.append(
            {
                k: rec[k]
                for k in ["model_name_or_path", "instance_id", "model_patch", "submission_valid"]
            }
        )
        preds_filled.append(rec)

        if not patch:
            missing += 1

    (run_dir / "preds.json").write_text(json.dumps(preds, indent=2), encoding="utf-8")
    (run_dir / "preds_filled.json").write_text(json.dumps(preds_filled, indent=2), encoding="utf-8")

    if missing:
        print(f"[WARN] {missing}/{len(traj_paths)} instances had EMPTY extracted patches.\n"
              f"       Check the trajectory messages and your agent prompt; SWE-bench will fail to apply empty/invalid patches.")
        return 2

    print(f"[OK] Wrote {len(traj_paths)} predictions to {run_dir/'preds_filled.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
