# τGuardian SWE-bench pipeline: end-to-end system structure (current)

This bundle contains:
- `code/` : the τGuardian harness code (evaluation, scan, governance, CI, audit)
- `run/`  : a reference proof run (`msa_glm46_lite_run20/`) with full artifacts
- `audit/`: the proof-bundle manifest + CI gate output

## A) Dataflow (single run)

1) **mini-swe-agent (mini-extra)** generates trajectories for each SWE-bench instance.
   - Output per instance: `RUN/<instance_id>/<instance_id>.traj.json`
   - This step both starts the Docker testbed image AND calls the LLM provider.

2) **Patch extraction**
   - Script: `mini_swe_extract_from_traj.py`
   - Output: `RUN/preds_filled.json` (predictions / patches)

3) **SWE-bench evaluation wrapper**
   - Script: `code/tg_swebench_cli.py` (calls SWE-bench harness and normalizes outputs)
   - Output: `RUN/eval/instance_results.jsonl`

4) **Post-apply security scan**
   - Script: `code/tg_post_apply_security_scan.py`
   - Output: `RUN/security_reports/*.json`

5) **Governance recompute (v2)**
   - Script: `code/analyze_mini_swe_results.py`
   - Input: instance_results + security reports (+ patch metadata when available)
   - Output: `RUN/*governed_v2_agentic*.jsonl`
   - Produces: `final_decision` in {OK, ABSTAIN, VETO} + `cri/sad_flag` and reasons

6) **CI Gate**
   - Script: `code/tg_ci_gate.py`
   - Fails job on any VETO (prints counts)

7) **Audit / proof bundle**
   - Script: `code/tg_run_audit.py`
   - Output: `RUN/audit/*` + top-level `audit/manifest_sha256.txt` in packaged bundles

## B) What's *not* included here
- The mini-swe-agent Python package itself (installed in your venv).
- Your provider credentials in `~/.config/mini-swe-agent/.env` (by design).


NOTE: This build includes `mini_swe_extract_from_traj.py` at repo root (merged extractor) for reproducible patch extraction.
