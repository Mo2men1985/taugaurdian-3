# Batch log (v2025-12-23)

Included from prior iterations:
- Proof bundle run artifacts (`run/msa_glm46_lite_run20/`) with governed v2 JSONL + security reports + audit + CI gate output.
- Core harness code in `code/`.

Added in this batch:
- `extras/swebench_glm46_FIXED.yaml` : GLM-4.6 config without `model_id` (compat with mini-swe-agent 1.17.3 / LitellmModelConfig).
- `extras/mini_swe_extract_from_traj_merged.py` : robust trajectory patch extractor (copy into repo if needed).
- `extras/run_lite_batch.sh` : end-to-end batch runner script (mini-extra -> extract -> eval -> scan -> governance -> CI/audit).
- `extras/patch_minisweagent_workdir.sh` : fix empty patches from wrong Docker working directory (`-w /` -> `-w /testbed`).
- `docs/SYSTEM_STRUCTURE.md` : current end-to-end pipeline map.
- `docs/TROUBLESHOOTING_DOCKER_PULL.md` : freeze / resume guidance for Docker pulls in WSL.
