# τGuardian SWE-bench Lite — Batch Proof Runs (50–100) + Cross‑Model + Variance

This is the **production runbook** for generating an end‑to‑end τGuardian proof bundle on **SWE-bench Lite (test split)** using `mini-extra swebench` + τGuardian’s evaluation / security / governance pipeline.

It is based on the **known-good 1‑instance smoke** that already produced:

- `eval/instance_results.jsonl` (SWE-bench harness)
- `security_reports/*.json` (post‑apply delta scan)
- `recomputed_governed_v2_agentic.jsonl` (OK/ABSTAIN/VETO decisions)
- `tg_ci_gate.py` PASS output

---

## A. Preconditions (do once)

### A1) Repo + venv

```bash
cd ~/projects/tau_guardian_harness9
source .venv_wsl/bin/activate
```

### A2) Provider keys for mini-swe-agent / LiteLLM

mini-swe-agent loads provider keys from:

- `~/.config/mini-swe-agent/.env`

Load them into the current shell:

```bash
set -a; source ~/.config/mini-swe-agent/.env; set +a
```

### A3) Sanity checks

```bash
python -c "import swebench, yaml; print('ok: swebench+yml')"
docker ps >/dev/null
mini-extra --help >/dev/null
```

---

## B. Make sure your agent YAML parses

For GLM‑4.6 you already use `./swebench_glm46.yaml`.

```bash
python - <<'PY'
import yaml
yaml.safe_load(open('swebench_glm46.yaml','r',encoding='utf-8'))
print('YAML OK')
PY
```

If you see an error like:

- `LitellmModelConfig.__init__() got an unexpected keyword argument 'model_id'`

then your YAML contains keys your installed mini-swe-agent version doesn’t support. The safest fix is:

- Remove `model_id:` and use `model:` (LiteLLM convention), or align to your local `LitellmModelConfig` signature.

Quick way to verify the expected kwargs in your environment:

```bash
python - <<'PY'
import inspect
from minisweagent.models.litellm_model import LitellmModelConfig
print(inspect.signature(LitellmModelConfig))
PY
```

---

## C. Batch run: 50–100 instances (end‑to‑end)

### C1) Choose a slice

SWE-bench Lite test has **300** instances (as your harness output shows). Typical batches:

- First 50: `SLICE="0:50"`
- Next 50: `SLICE="50:100"`
- First 100: `SLICE="0:100"`

### C2) Run the full pipeline (recommended: use the script)

Use the provided script (see `run_lite_batch.sh` in this bundle):

```bash
bash run_lite_batch.sh \
  --config ./swebench_glm46.yaml \
  --model-id "zai/glm-4.6" \
  --slice "50:100" \
  --tag "glm46"
```

It will produce a run directory like:

- `msa_glm46_lite_test_251223_....`

and the proof bundle artifacts inside it.

---

## D. Deliverables checklist (what “proof run” means)

A run is considered **complete** iff all exist:

- `$RUN/minisweagent.log`
- `$RUN/**/**.traj.json` (one per instance)
- `$RUN/preds_filled.json`
- `$RUN/eval/instance_results.jsonl`
- `$RUN/security_reports/*.json`
- `$RUN/recomputed_governed_v2_agentic.jsonl`
- `$RUN/ci_gate.txt`
- `$RUN/proof_manifest.json` (sha256 + counts)
- `$RUN/proof_bundle.tgz` (tarball of artifacts)

The script creates **all** of the above.

---

## E. Cross‑model replication (model‑agnostic evidence)

Goal: show τGuardian governance works across providers/models, not only GLM‑4.6.

### E1) Create a second config YAML

Copy your working YAML and change only the model string + key env var.

Example:

```bash
cp swebench_glm46.yaml swebench_modelB.yaml
# edit swebench_modelB.yaml:
# - model: "openrouter/qwen/qwen-2.5-coder-32b-instruct"   (example)
# - api_key_env: "OPENROUTER_API_KEY"                      (example)
```

Run the same slice with the second config:

```bash
bash run_lite_batch.sh \
  --config ./swebench_modelB.yaml \
  --model-id "openrouter/qwen-2.5-coder-32b-instruct" \
  --slice "50:100" \
  --tag "modelB"
```

**Important:** keep the slice identical so the comparison is apples-to-apples.

---

## F. Reproducibility / variance (same model, same slice, 3 repeats)

Run 3 repeats (different RUN IDs) for the same config/model/slice:

```bash
for i in 1 2 3; do
  bash run_lite_batch.sh \
    --config ./swebench_glm46.yaml \
    --model-id "zai/glm-4.6" \
    --slice "50:100" \
    --tag "glm46_r${i}"
done
```

Then summarize:

```bash
python summarize_runs.py msa_glm46_lite_test_* 2>/dev/null | tee variance_summary.txt
```

---

## G. Practical notes (avoid the failure modes you hit)

### G1) Avoid “commands glued together” errors

You had:

- `mkdir -p "$RUN"mini-extra ...` (missing newline)

Always run as a script, or press Enter between commands.

### G2) Empty / invalid patch troubleshooting

If SWE-bench shows:

- `patch: **** Only garbage was found in the patch input.`

Then the extracted patch is empty or malformed.

Do:

```bash
python - <<'PY'
import json
from pathlib import Path
p = Path("$RUN/preds_filled.json")
x = json.loads(p.read_text())
rec = x[0] if isinstance(x, list) else x[next(iter(x))]
patch = rec.get("model_patch","")
print("patch_len:", len(patch))
print("has_diff_markers:", ("diff --git" in patch) or ("--- a/" in patch and "+++ b/" in patch))
print("head:", repr(patch[:200]))
PY
```

The batch script fails fast if it detects empties.

### G3) Disk usage (SWE-bench images)

Your harness output showed `Unremoved images: 24`. If disk grows:

```bash
docker image ls | head
# optional cleanup (careful):
docker system df
docker image prune -f
```

---

## H. Interpretation of results (what you can claim)

For each run you will have:

- **Resolved %** (SWE-bench correctness)
- **Governance distribution** (OK/ABSTAIN/VETO)
- **Security delta violations** (new_violations per instance)
- **Artifact completeness rate** (manifest covers required files)

These are the minimum evidence to present τGuardian as:
- a **governed SWE-bench harness** with a reproducible “proof bundle” output,
- suitable for an initial funding submission.

