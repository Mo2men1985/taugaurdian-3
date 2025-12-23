#!/usr/bin/env python3
"""swe_eval_wrapper.py

Thin CLI wrapper for SWE / mini-SWE evaluation in τGuardian.

This version adds:
  - SHA-256 fingerprinting of the predictions file.
  - A metadata file alongside instance_results.jsonl that records which
    predictions file was evaluated.
  - Reuse of existing instance_results.jsonl *only* when the fingerprint
    matches, to avoid stale evaluations.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shlex
import subprocess
import sys
from pathlib import Path

DEFAULT_CLI = (
    "{python} tg_swebench_cli.py --predictions-path {predictions} "
    "--run-id {run_id} --outdir {outdir}"
)

METADATA_FILENAME = "instance_results.metadata.json"


def _run_shell_command(cmd: str, cwd: Path | None, timeout: int) -> int:
    print(f"[swe_eval_wrapper] RUN: {cmd}")
    args = shlex.split(cmd)
    proc = subprocess.Popen(args, cwd=str(cwd or Path(".")))
    try:
        rc = proc.wait(timeout=timeout)
        return rc
    except subprocess.TimeoutExpired:
        proc.kill()
        raise RuntimeError(
            f"External SWE eval CLI timed out after {timeout} seconds"
        )


def _compute_file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _load_metadata(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        # Treat malformed metadata as missing; force a fresh eval.
        return {}


def _write_metadata(
    path: Path,
    *,
    predictions_path: Path,
    predictions_sha256: str,
    cli_command: str,
) -> None:
    meta = {
        "predictions_path": str(predictions_path),
        "predictions_sha256": predictions_sha256,
        "cli_command": cli_command,
    }
    path.write_text(json.dumps(meta, indent=2, sort_keys=True), encoding="utf-8")


def main() -> None:
    if sys.platform.startswith("win"):
        raise SystemExit(
            "SWE-bench harness evaluation is not supported on native Windows. "
            "Run this command from WSL/Linux (e.g., `wsl ...`) or inside a Linux environment."
        )

    parser = argparse.ArgumentParser(
        description="Wrapper around SWE / mini-SWE evaluation for τGuardian."
    )
    parser.add_argument(
        "--predictions-path",
        required=True,
        help="Path to model predictions (JSON or JSONL).",
    )
    parser.add_argument(
        "--run-id",
        required=True,
        help="Run identifier (used in output directory structure).",
    )
    parser.add_argument(
        "--outdir",
        required=True,
        help="Root output directory for evaluation results.",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=3600,
        help="Timeout in seconds for external evaluator (default: 3600).",
    )
    args = parser.parse_args()

    predictions_path = Path(args.predictions_path).expanduser().resolve()
    outdir = Path(args.outdir).expanduser().resolve()
    run_id = args.run_id
    timeout = args.timeout

    outdir.mkdir(parents=True, exist_ok=True)
    instance_results_path = outdir / "instance_results.jsonl"
    metadata_path = outdir / METADATA_FILENAME

    # Compute the fingerprint of the predictions file we are about to evaluate.
    predictions_sha256 = _compute_file_sha256(predictions_path)

    # Decide whether we can safely reuse an existing instance_results.jsonl.
    if instance_results_path.exists():
        meta = _load_metadata(metadata_path)
        if not meta:
            raise SystemExit(
                "[swe_eval_wrapper] ERROR: instance_results.jsonl exists but metadata is missing or invalid. "
                "Refusing to reuse results without a matching metadata file."
            )
        if meta.get("predictions_path") != str(predictions_path):
            raise SystemExit(
                "[swe_eval_wrapper] ERROR: predictions_path in metadata does not match the provided "
                "predictions file. Refusing to reuse results."
            )
        if meta.get("predictions_sha256") != predictions_sha256:
            raise SystemExit(
                "[swe_eval_wrapper] ERROR: predictions SHA mismatch detected. "
                "Refusing to reuse results to prevent mixing evaluations."
            )
        print(f"[swe_eval_wrapper] Reusing existing {instance_results_path}")
        print("[swe_eval_wrapper] Metadata SHA matches current predictions.")
        print(instance_results_path)
        return

    cli_template = os.environ.get("TG_SWE_EVAL_CLI")
    if cli_template:
        cli = cli_template
    else:
        python_bin = os.environ.get("PYTHON", "python")
        cli = DEFAULT_CLI.format(
            python=python_bin,
            predictions="{predictions}",
            run_id="{run_id}",
            outdir="{outdir}",
        )

    cmd = cli.format(
        predictions=str(predictions_path),
        run_id=run_id,
        outdir=str(outdir),
    )
    rc = _run_shell_command(cmd, cwd=None, timeout=timeout)
    if rc != 0:
        raise RuntimeError(f"External SWE eval CLI failed (rc={rc})")

    if not instance_results_path.exists():
        raise FileNotFoundError(
            f"Expected instance_results.jsonl at {instance_results_path} "
            "after running external CLI"
        )

    # Persist metadata that binds this instance_results.jsonl to the predictions file.
    _write_metadata(
        metadata_path,
        predictions_path=predictions_path,
        predictions_sha256=predictions_sha256,
        cli_command=cmd,
    )

    print(f"[swe_eval_wrapper] Found instance_results at {instance_results_path}")
    print(instance_results_path)


if __name__ == "__main__":
    main()
