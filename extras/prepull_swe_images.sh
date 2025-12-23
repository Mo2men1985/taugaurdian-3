#!/usr/bin/env bash
set -euo pipefail

# Pre-pull SWE-bench per-instance images for a slice, WITHOUT calling any LLMs.
# Usage:
#   ./prepull_swe_images.sh --slice "50:100" --subset lite --split test

SLICE=""
SUBSET="lite"
SPLIT="test"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --slice) SLICE="$2"; shift 2;;
    --subset) SUBSET="$2"; shift 2;;
    --split) SPLIT="$2"; shift 2;;
    *) echo "Unknown arg: $1" >&2; exit 2;;
  esac
done

if [[ -z "${SLICE}" ]]; then
  echo "ERROR: --slice is required (e.g., 50:100)" >&2
  exit 2
fi

python - <<PY
import json
from datasets import load_dataset
from pathlib import Path

ds = load_dataset("princeton-nlp/SWE-bench_Lite", split="${SPLIT}")
start,end = map(int,"${SLICE}".split(":"))
rows = ds.select(range(start,end))
imgs = []
for r in rows:
    imgs.append(r["instance_image"])
Path("swe_images_${SLICE//:/_}.txt").write_text("\n".join(imgs), encoding="utf-8")
print(f"[OK] Wrote {len(imgs)} images to swe_images_${SLICE//:/_}.txt")
PY

LIST="swe_images_${SLICE//:/_}.txt"

count=0
while read -r img; do
  [[ -z "$img" ]] && continue
  if docker image inspect "$img" >/dev/null 2>&1; then
    echo "[CACHED] $img"
  else
    echo "[PULL]   $img"
    # retry up to 5 times with backoff
    for attempt in 1 2 3 4 5; do
      if docker pull "$img"; then
        break
      fi
      echo "[WARN] pull failed (attempt $attempt). sleeping..." >&2
      sleep $((attempt*10))
    done
  fi
  count=$((count+1))
done < "$LIST"

echo "[DONE] processed $count images from $LIST"
