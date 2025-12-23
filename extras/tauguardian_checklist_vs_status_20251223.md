# τGuardian SWE-bench (Lite) — Checklist vs Current Status (as of 2025-12-23)

## Executive status

You have a **working end-to-end (E2E) proof run** for **GLM‑4.6** on **SWE-bench Lite** (1 instance) with:

- **mini-swe-agent trajectory generated**
- **preds extracted** (`preds_filled.json`)
- **SWE-bench evaluation executed** (`eval/instance_results.jsonl`)
- **post-apply delta security scan executed** (`security_reports/*.json`)
- **governance recomputed** (`recomputed_governed_v2_agentic.jsonl`)
- **CI gate PASS** (no VETO)

The next blocker for a 50‑instance slice is **Docker image pull/runtime startup timeout** inside mini‑swe‑agent when an image is not already present locally.

---

## Checklist (from your “safety sota” note) mapped to current reality

### 1) Inspect code and summarize the guardrail + where it triggers
**Checklist intent:** prove the *governance layer* is real, deterministic, and auditable.

**Status now:** **Partially satisfied**
- You have the *observable behavior* end‑to‑end (OK decision emitted + files written).
- What’s still missing is a short “trigger map” that points to exact functions/fields used to compute **CRI / SAD / τ** and decision rules (**OK/ABSTAIN/VETO**).

**Evidence you already produced:**
- `msa_glm46_lite_smoke_251222_234852/recomputed_governed_v2_agentic.jsonl` (1 row, decision=OK)
- `msa_glm46_lite_smoke_251222_234852/security_reports/*` (delta scan artifacts)
- `msa_glm46_lite_smoke_251222_234852/eval/instance_results.jsonl`

**Next action (tight):**
- Produce a 1‑page “**Governance Trigger Map**” (file/function → output field) once the 50‑instance run completes, because it is much more convincing with non‑trivial distributions.

---

### 2) Compare to SOTA and show novelty
**Checklist intent:** position τGuardian relative to existing “agent harness + safety” systems.

**Status now:** **Not done (research task)**
- You need a short literature / ecosystem comparison with citations (SWE-bench agents, patch safety scanners, CI gate systems, agent governance, etc.).

**Next action (tight):**
- Do this after you have the **first 50‑instance governed JSONL**, because you can cite your *actual measured outputs* (coverage, veto rates, scan rates, etc.) alongside the SOTA survey.

---

### 3) Check CRI/SAD and produce a “proof artifact”
**Checklist intent:** demonstrate the metrics are computed and tied to a clear decision outcome.

**Status now:** **Satisfied for a smoke proof (n=1)**
- You have CRI/SAD/decision emitted and CI gate passed.

**Gap:** you need **scale** (≥50) to show the metrics behave non‑trivially.

---

### 4) Formalize CRI & SAD mathematically
**Checklist intent:** make the system specifiable and reviewable.

**Status now:** **Not done**
- You have an implemented formula, but you still need a math definition (and versioning: v1 vs v2).

**Next action (tight):**
- After the 50‑instance run, freeze a “**Metric Spec v2.0**” page:
  - Inputs
  - Feature extraction rules
  - Formulae
  - Decision thresholds
  - Example instances

---

### 5) Suggest ablations (–SAD / –CRI / –τ / disable post‑apply scan)
**Checklist intent:** show governance is responsible for safety/quality trade‑offs.

**Status now:** **Not run**
- You need 2–4 ablation runs on a small fixed slice (e.g., 10–20 instances) to control cost.

---

### 6) Clean system diagram
**Checklist intent:** investor / reviewer comprehension.

**Status now:** **Mostly done conceptually; needs “final picture”**
- Your pipeline is already stable and you have a runbook; the diagram becomes credible once you have multiple runs and bundles.

---

### 7) Stress-test against adaptive evasion
**Checklist intent:** show robustness vs “agentic misalignment” behaviors (obfuscation, hidden payloads, etc.).

**Status now:** **Not done**
- This is a Phase 2 exercise after you stabilize throughput and proof bundles.

---

### 8) Funding readiness (Dec 2025 claim)
**Checklist intent:** decide whether to pitch now vs later.

**Status now:** **Not yet**
- A single green run is a proof of life, not a funding proof.
- Funding readiness usually needs:
  - ≥50–200 governed instances
  - cross‑model replication
  - reproducibility (variance) proof
  - clean artifacts (bundle + audit)

---

## Current run status (what you are seeing right now)

### The immediate failure you hit
During `run_lite_batch.sh` on slice `50:100`, mini‑swe‑agent tried to start a container:

- Image: `docker.io/swebench/sweb.eval.x86_64.django_1776_django-13230:latest`
- Failure: **docker run timed out after 120 seconds**
- Root cause: **image not yet pulled locally** (so `docker run` triggers a pull, which can exceed 120s)

### Your “latest download update” log indicates
You are already doing the correct mitigation:
- you generated an image list (`/tmp/swebench_images_50_100.txt`)
- you are pulling them with `xargs -P 2 docker pull`
- downloads + layer extraction are actively progressing

Once pulls finish, mini‑swe‑agent should no longer time out on container start.

---

## What to do next (minimum steps to finish the 50-instance proof bundle)

### A) Finish pre-pulling the slice images
Keep it conservative (to avoid disk/IO contention):

```bash
# Verify pulls are still running
ps aux | grep "docker pull" | grep -v grep || true

# Optional: reduce parallelism if your disk is saturated
cat /tmp/swebench_images_50_100.txt | xargs -n1 -P 1 docker pull
```

Sanity check a “problem image” exists:

```bash
docker image ls | grep "django-13230" || true
```

### B) Re-run the slice after pulls
```bash
bash run_lite_batch.sh   --config ./swebench_glm46.yaml   --model-id "zai/glm-4.6"   --slice "50:100"   --tag "glm46"
```

### C) Ensure the E2E artifacts exist
At the end you want:

- `$RUN/preds_filled.json`
- `$RUN/eval/instance_results.jsonl`
- `$RUN/security_reports/*.json`
- `$RUN/recomputed_governed_v2_agentic.jsonl`
- CI summary output from `tg_ci_gate.py`

### D) Add the two key “proof upgrades” immediately after the run
1) **Audit pass**
```bash
python tg_run_audit.py --run "$RUN" --out "$RUN/audit.json"
```

2) **Bundle hash + integrity**
```bash
tar -czf "$RUN/proof_bundle.tgz"   "$RUN/minisweagent.log"   "$RUN/preds_filled.json"   "$RUN/eval"   "$RUN/security_reports"   "$RUN/recomputed_governed_v2_agentic.jsonl"   "$RUN/audit.json"

sha256sum "$RUN/proof_bundle.tgz" | tee "$RUN/proof_bundle.sha256"
```

---

## Cross-model + reproducibility plan (the next 72 hours of “evidence work”)

### 1) Cross-model replication (model-agnostic proof)
- Run the **same slice 50:60** on a second model/provider.
- Deliverables: governed JSONL + CI gate + audit, same structure.

### 2) Reproducibility / variance
- Same model, same slice (e.g., 50:60), **3 repeats**:
  - Compare `resolved%`, `OK/ABSTAIN/VETO` distribution, artifact completeness.

---

## One decision recommendation

If your goal is **funding**, the most leverage per unit effort is:

1) **Finish one clean 50‑instance proof bundle** (GLM‑4.6)  
2) **Replicate on 1 more model** for a smaller slice (10–20)  
3) **Do 3 repeats** on that smaller slice for variance

That gives you a credible “governance is real and portable” story with minimal cost.
