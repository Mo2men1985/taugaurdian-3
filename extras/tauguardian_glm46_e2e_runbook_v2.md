# τGuardian × mini-swe-agent (GLM-4.6) — End-to-End Runbook (Lite smoke 1 instance)

This is the **known-good** command sequence for a complete τGuardian SWE-bench Lite run:

1) mini-swe-agent (mini-extra) generates a trajectory (and ideally a patch submission)
2) extract a patch from the trajectory → `preds_filled.json`
3) SWE-bench harness evaluation → `eval/instance_results.jsonl`
4) post-apply security scan → `security_reports/*.json`
5) governance recompute → `recomputed_governed_v2_agentic.jsonl`
6) CI gate → OK / ABSTAIN / VETO

## 0) Preconditions

- You are in WSL (Ubuntu), inside the repo:
  - `~/projects/tau_guardian_harness9`
- venv active:
  - `.venv_wsl`
- Docker works (SWE-bench images can be pulled)
- mini-swe-agent reads your API key from:
  - `~/.config/mini-swe-agent/.env`

## 1) Start a run (1 instance smoke)

```bash
cd ~/projects/tau_guardian_harness9
source .venv_wsl/bin/activate

# Load provider keys (KEY, etc.) into the environment for this shell
set -a; source ~/.config/mini-swe-agent/.env; set +a

# Confirm your agent YAML parses
python - <<'PY'
import yaml
yaml.safe_load(open('swebench_glm46.yaml','r',encoding='utf-8'))
print('YAML OK')
PY

# Create a unique run folder name
RUN="msa_glm46_lite_smoke_$(date -u +%y%m%d_%H%M%S)"
mkdir -p "$RUN"

# Run mini-extra (SWE-bench Lite, test split, 1 instance)
mini-extra swebench \
  --config ./swebench_glm46.yaml \
  --subset lite \
  --split test \
  --slice "0:1" \
  --output "$RUN" \
  --workers 1 |& tee "$RUN/minisweagent.log"

# IMPORTANT: mini-extra prints the *actual* output dir.
# If it differs from $RUN, set RUN to what it printed before continuing.
```

## 2) Verify the trajectory contains a non-empty submission

If `info.submission_len == 0`, the model did not submit a patch (or submitted an empty patch).

```bash
python - <<'PY'
import json
from pathlib import Path
run = Path("$RUN")
traj = next(run.rglob('*.traj.json'))
d = json.loads(traj.read_text(encoding='utf-8'))
sub = (d.get('info') or {}).get('submission') or ''
print('traj:', traj)
print('exit_status:', (d.get('info') or {}).get('exit_status'))
print('submission_len:', len(sub))
print('submission_has_diff_markers:', ('diff --git' in sub) or ('--- a/' in sub and '+++ b/' in sub))
print('submission_head:\n' + '\n'.join(sub.splitlines()[:40]))
print('messages_len:', len(d.get('messages') or []))
PY
```

## 3) Extract predictions from the trajectory

This creates (or overwrites) both:
- `$RUN/preds.json`
- `$RUN/preds_filled.json`

```bash
python mini_swe_extract_from_traj.py --run-dir "$RUN"

# sanity-check patch length
python - <<'PY'
import json
from pathlib import Path
p = Path("$RUN/preds_filled.json")
x = json.loads(p.read_text(encoding='utf-8'))
rec = x[0] if isinstance(x, list) else x[next(iter(x))]
patch = rec.get('model_patch','')
print('keys:', list(rec.keys()))
print('patch_len:', len(patch))
print('patch_head:', repr(patch[:200]))
PY
```

## 4) Run SWE-bench harness evaluation

Use the dataset id that has already worked in your logs:

```bash
python tg_swebench_cli.py \
  --predictions-path "$RUN/preds_filled.json" \
  --run-id "$RUN" \
  --outdir "$RUN/eval" \
  --dataset-name "princeton-nlp/SWE-bench_Lite" \
  --split test

# confirm results exist
ls -lah "$RUN/eval" | sed -n '1,200p'
```

## 5) Post-apply security scan

```bash
python tg_post_apply_security_scan.py \
  --preds "$RUN/preds_filled.json" \
  --dataset "princeton-nlp/SWE-bench_Lite" \
  --split test \
  --outdir "$RUN/security_reports"
```

## 6) Governance recompute

```bash
python analyze_mini_swe_results.py \
  --msa-dir "$RUN" \
  --model-id "zai/glm-4.6" \
  --instance-results "$RUN/eval/instance_results.jsonl" \
  --security-reports-dir "$RUN/security_reports" \
  --output "$RUN/recomputed_governed_v2_agentic.jsonl"
```

## 7) CI Gate (OK / ABSTAIN / VETO)

```bash
python tg_ci_gate.py --input "$RUN/recomputed_governed_v2_agentic.jsonl" || true
```

## 8) If evaluation says: “Only garbage was found in the patch input”

That error almost always means the patch is **empty** or **not a valid unified diff**.

Do these checks:

```bash
cat "$RUN/eval/normalized_predictions.json"
python - <<'PY'
import json
from pathlib import Path
p = Path("$RUN/eval/normalized_predictions.json")
d = json.loads(p.read_text())
print('model_patch_len:', len(d[0].get('model_patch','')))
print('model_patch_head:', repr(d[0].get('model_patch','')[:200]))
PY
```

If the patch is empty, fix the agent prompt to **always generate the patch via `git diff`** before calling submit.
