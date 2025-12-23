# τGuardian SWE-bench pipeline (end-to-end)

This repo provides an **evidence-governed SWE-bench harness**. It wraps agentic code generation with:
- **Execution artifacts** (trajectories, patches)
- **Correctness scoring** (SWE-bench harness)
- **Post-apply delta security scan** (AST rules over *added lines*)
- **Governance decisioning** (OK / ABSTAIN / VETO)
- **CI gate + audit bundle** (proof-carrying run folder)

## Pipeline stages (canonical)

### Stage 0 — Run ID and configuration
- `run_lite_batch.sh` (root): orchestrates the whole batch run.
- Inputs:
  - mini-swe-agent config YAML (e.g., `swebench_glm46.yaml`)
  - dataset slice (e.g., `50:100`)
- Output:
  - run folder: `msa_<tag>_lite_<...>/` (referred to as `$RUN`)

### Stage 1 — Agentic patch generation (mini-swe-agent)
Command (inside `run_lite_batch.sh`):
- `mini-extra swebench --config <YAML> --subset lite --split test --slice <SLICE> --output "$RUN" --workers 1`

Outputs under `$RUN/` (one directory per instance):
- `*/<instance>.traj.json`  (trajectory transcript + tool calls + model outputs)
- `$RUN/minisweagent.log`

### Stage 2 — Extract patches from trajectories → `preds_filled.json`
- `mini_swe_extract_from_traj.py` (root) — merged/robust extractor.

Outputs:
- `$RUN/preds_filled.json` (list of `{instance_id, model_patch, ...}`)

### Stage 3 — SWE-bench evaluation
- `code/tg_swebench_cli.py` normalizes predictions and invokes SWE-bench harness.
- Writes:
  - `$RUN/eval/instance_results.jsonl` (one row per evaluated instance)

### Stage 4 — Post-apply security scan (delta scan)
- `code/tg_post_apply_security_scan.py`
- Writes:
  - `$RUN/security_reports/<instance_id>.json`
  - Each report contains `scan_failed`, `new_violations[]`, and per-rule evidence

### Stage 5 — Governance recompute
- `code/analyze_mini_swe_results.py` merges correctness + security into governed results
- Writes:
  - `$RUN/recomputed_governed_v2_agentic.jsonl`

Decision semantics (v2):
- **VETO** if SAD/high-severity violations (hard stop)
- **ABSTAIN** if scan coverage is insufficient / scan failed (soft stop)
- **OK** if resolved and no governance blockers

### Stage 6 — CI gate and audit bundle
- `code/tg_ci_gate.py` fails CI on any VETO, prints counts
- `code/tg_run_audit.py` (optional) produces a proof bundle (hashes, artifact inventory)

## Minimal artifact checklist for a “proof run”
A run is “complete” when it has:
- `$RUN/minisweagent.log`
- `>=1` `*.traj.json`
- `$RUN/preds_filled.json`
- `$RUN/eval/instance_results.jsonl`
- `$RUN/security_reports/*.json`
- `$RUN/recomputed_governed_v2_agentic.jsonl`
- CI summary from `tg_ci_gate.py`

