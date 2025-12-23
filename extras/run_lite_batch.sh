#!/usr/bin/env bash
set -euo pipefail

# τGuardian SWE-bench Lite batch runner
#
# Produces a proof bundle under $RUN:
# - minisweagent trajectories
# - preds_filled.json
# - eval/instance_results.jsonl
# - security_reports/*.json
# - recomputed_governed_v2_agentic.jsonl
# - ci_gate.txt
# - proof_manifest.json (sha256 + counts)
# - proof_bundle.tgz

CONFIG=""
POLICY="policy/default_policy.yaml"
MODEL_ID=""
SLICE=""
TAG="run"

# Allow this script to be executed from either:
#  - repo root (./run_lite_batch.sh)
#  - extras/ (./extras/run_lite_batch.sh)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -d "$SCRIPT_DIR/code" ]]; then
  ROOT="$SCRIPT_DIR"
else
  ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
fi
cd "$ROOT"

# This bundle ships core harness scripts under ./code
CODE_DIR="$ROOT/code"

require_script() {
  local script="$1"
  if [[ ! -f "$CODE_DIR/$script" && ! -f "$script" ]]; then
    echo "[ERR] Missing required script: $script" >&2
    echo "      Expected at: $CODE_DIR/$script or $ROOT/$script" >&2
    exit 1
  fi
}

py() {
  # Prefer ./code/<script> if present, otherwise fall back to repo root.
  local script="$1"; shift
  if [[ -f "$CODE_DIR/$script" ]]; then
    python "$CODE_DIR/$script" "$@"
  else
    python "$script" "$@"
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --config) CONFIG="$2"; shift 2;;
    --model-id) MODEL_ID="$2"; shift 2;;
    --policy) POLICY="$2"; shift 2;;
    --slice) SLICE="$2"; shift 2;;
    --tag) TAG="$2"; shift 2;;
    *) echo "Unknown arg: $1" >&2; exit 2;;
  esac
done

# Resolve policy path (default: policy/default_policy.yaml) and export for downstream scripts.
POLICY_PATH=""
if [[ -n "${POLICY}" ]]; then
  if [[ -f "$POLICY" ]]; then
    POLICY_PATH="$(python - <<PY
from pathlib import Path
print(Path("$POLICY").expanduser().resolve())
PY
)"
  elif [[ -f "$ROOT/$POLICY" ]]; then
    POLICY_PATH="$(python - <<PY
from pathlib import Path
print((Path("$ROOT")/"$POLICY").expanduser().resolve())
PY
)"
  else
    echo "[WARN] policy not found: $POLICY (continuing without policy)"
    POLICY_PATH=""
  fi
fi
if [[ -n "$POLICY_PATH" ]]; then
  export TAUGUARDIAN_POLICY="$POLICY_PATH"
fi

if [[ -z "${CONFIG}" || -z "${MODEL_ID}" || -z "${SLICE}" ]]; then
  echo "Usage: $0 --config ./swebench_glm46.yaml --model-id \"zai/glm-4.6\" --slice \"50:100\" [--tag glm46]" >&2
  exit 2
fi

# Ensure the bundle layout is present
require_script tg_swebench_cli.py
require_script tg_post_apply_security_scan.py
require_script analyze_mini_swe_results.py
require_script tg_ci_gate.py

# Load provider keys if present (no-op if missing)
if [[ -f "$HOME/.config/mini-swe-agent/.env" ]]; then
  set -a; source "$HOME/.config/mini-swe-agent/.env"; set +a
fi

# Validate YAML
python - <<PY
import yaml
yaml.safe_load(open("${CONFIG}","r",encoding="utf-8"))
print("YAML OK:", "${CONFIG}")
PY

RUN="msa_${TAG}_lite_test_$(date -u +%y%m%d_%H%M%S)"
mkdir -p "$RUN"

echo "[RUN] $RUN"
echo "[CFG] $CONFIG"
echo "[MODEL_ID] $MODEL_ID"
echo "[SLICE] $SLICE"

# 1) mini-extra trajectories
mini-extra swebench \
  --config "$CONFIG" \
  --subset lite \
  --split test \
  --slice "$SLICE" \
  --output "$RUN" \
  --workers 1 |& tee "$RUN/minisweagent.log"

# 2) Extract patches
python "$ROOT/mini_swe_extract_from_traj.py" --run-dir "$RUN"

# Fail fast if any empty/invalid patches exist (no unified diff markers)
python - <<'PY'
import json
from pathlib import Path
run = Path("$RUN")
p = run / "preds_filled.json"
x = json.loads(p.read_text(encoding="utf-8"))
items = list(x.values() if isinstance(x, dict) else x)

def is_unified_diff(s: str) -> bool:
    s = s or ""
    return ("diff --git" in s) or ("--- a/" in s and "+++ b/")

invalid = []
empty = []
for r in items:
    patch = (r.get("model_patch") or r.get("patch") or r.get("prediction") or "")
    if len(patch.strip()) == 0:
        empty.append(r.get("instance_id"))
    elif not is_unified_diff(patch):
        invalid.append(r.get("instance_id"))

print("[CHECK] total_preds:", len(items))
print("[CHECK] empty_patches:", len(empty), " invalid_patches:", len(invalid))
if empty or invalid:
    if empty:
        print("[ERR] empty patches for:", empty[:10], "… total", len(empty))
    if invalid:
        print("[ERR] invalid (non-diff) patches for:", invalid[:10], "… total", len(invalid))
    raise SystemExit(3)
print("[OK] all patches look like unified diffs")
PY

# 3) SWE-bench evaluation
py tg_swebench_cli.py \
  --predictions-path "$RUN/preds_filled.json" \
  --run-id "$RUN" \
  --outdir "$RUN/eval" \
  --dataset-name "princeton-nlp/SWE-bench_Lite" \
  --split test

# 4) Post-apply security scan
py tg_post_apply_security_scan.py \
  --preds "$RUN/preds_filled.json" \
  --dataset "princeton-nlp/SWE-bench_Lite" \
  --split test \
  --outdir "$RUN/security_reports"

# 5) Governance recompute
# Agentic trajectory risk analysis (optional but recommended).
ARISK_FLAG=""
if [[ -d "$RUN/trajs" ]] || ls "$RUN"/*.traj.json >/dev/null 2>&1; then
  echo "[STEP] trajectory risk analysis -> agentic_risk.jsonl"
  if [[ -n "$POLICY_PATH" ]]; then
    py tg_traj_risk_analyzer.py --msa-dir "$RUN" --output "$RUN/agentic_risk.jsonl" --policy "$POLICY_PATH" |& tee "$RUN/agentic_risk.log" || true
  else
    py tg_traj_risk_analyzer.py --msa-dir "$RUN" --output "$RUN/agentic_risk.jsonl" |& tee "$RUN/agentic_risk.log" || true
  fi
fi
if [[ -f "$RUN/agentic_risk.jsonl" ]]; then
  ARISK_FLAG="--agentic-risk-jsonl $RUN/agentic_risk.jsonl"
fi

py analyze_mini_swe_results.py $ARISK_FLAG \
  --msa-dir "$RUN" \
  --model-id "$MODEL_ID" \
  --instance-results "$RUN/eval/instance_results.jsonl" \
  --security-reports-dir "$RUN/security_reports" \
  --output "$RUN/recomputed_governed_v2_agentic.jsonl" |& tee "$RUN/governance.log"

# 6) CI gate (save output)
py tg_ci_gate.py --input "$RUN/recomputed_governed_v2_agentic.jsonl" |& tee "$RUN/ci_gate.txt" || true

# 7) Audit + proof manifest + tarball
if [[ -f "$CODE_DIR/tg_run_audit.py" ]]; then
  py tg_run_audit.py --msa-dir "$RUN" |& tee "$RUN/run_audit.txt" || true
fi

if [[ -n "$POLICY_PATH" ]]; then
  python "$ROOT/audit_proof_bundle.py" "$RUN" --model-id "$MODEL_ID" --tag "$TAG" --policy "$POLICY_PATH" |& tee "$RUN/proof_manifest.log"
else
  python "$ROOT/audit_proof_bundle.py" "$RUN" --model-id "$MODEL_ID" --tag "$TAG" |& tee "$RUN/proof_manifest.log"
fi

tar -czf "$RUN/proof_bundle.tgz" \
  "$RUN/minisweagent.log" \
  "$RUN/preds_filled.json" \
  "$RUN/eval/instance_results.jsonl" \
  "$RUN/security_reports" \
  "$RUN/recomputed_governed_v2_agentic.jsonl" \
  "$RUN/ci_gate.txt" \
  "$RUN/run_audit.txt" \
  "$RUN/proof_manifest.json" \
  "$RUN/proof_manifest.log" \
  "$RUN/governance.log" 2>/dev/null || true

echo "[DONE] proof bundle: $RUN/proof_bundle.tgz"
