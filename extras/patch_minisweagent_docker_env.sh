#!/usr/bin/env bash
set -euo pipefail

# Safe patch for mini-swe-agent's Docker environment.
#
# Problem: Some mini-swe-agent versions start SWE-bench containers with `-w /`,
# but the SWE-bench repo lives at `/testbed` (and `/testbed/.git` exists).
# Running `git diff` from `/` causes "fatal: not a git repository" and yields empty patches.
#
# Fix: rewrite the docker run working directory argument to `/testbed`.
# Also: increase docker start timeout (first-time image pulls can be slow).
#
# This script is designed to be *syntax-safe*:
# - creates a .bak next to the installed file
# - replaces `-w "/"` with `-w "/testbed"` (no list surgery)
# - validates the patched module compiles; if not, restores backup

python - <<'PY'
from __future__ import annotations

import pathlib
import re
import sys

try:
    import minisweagent.environments.docker as d
except Exception as e:
    raise SystemExit(f"Failed to import minisweagent.environments.docker: {e}")

p = pathlib.Path(d.__file__)
orig = p.read_text(encoding="utf-8", errors="replace")

bak = p.with_suffix(p.suffix + ".bak")
if not bak.exists():
    bak.write_text(orig, encoding="utf-8")
    print("[BACKUP]", bak)
else:
    print("[BACKUP] exists:", bak)

txt = orig
changed = False

# Common exact-string patterns
replacements = [
    ('"-w", "/"', '"-w", "/testbed"'),
    ("'-w', '/'", "'-w', '/testbed'"),
    ('"-w","/"', '"-w","/testbed"'),
    ("'-w','/'", "'-w','/testbed'"),
]
for a, b in replacements:
    if a in txt:
        txt = txt.replace(a, b)
        changed = True

# Regex fallback (handles arbitrary spacing)
# Rewrites: '-w', '/'   or  "-w", "/"  -> same quotes, but /testbed
regex_txt = re.sub(r"([\"']-w[\"']\s*,\s*[\"'])/([\"'])", r"\1/testbed\2", txt)
if regex_txt != txt:
    txt = regex_txt
    changed = True

# Increase docker-run startup timeout if present
# (mini-swe-agent sometimes uses subprocess.run(..., timeout=120))
regex_txt = re.sub(r"timeout\s*=\s*120\b", "timeout=1800", txt)
if regex_txt != txt:
    txt = regex_txt
    changed = True

if not changed:
    # Restore (no-op) but be explicit.
    raise SystemExit(
        "No changes applied. Could not find a `-w '/'` working-dir literal or `timeout=120` in: "
        + str(p)
    )

# Syntax safety: ensure the patched module still compiles.
try:
    compile(txt, str(p), "exec")
except Exception as e:
    # Restore the backup before exiting.
    p.write_text(bak.read_text(encoding="utf-8"), encoding="utf-8")
    raise SystemExit(f"Patch would break Python syntax; restored backup. Error: {e}")

p.write_text(txt, encoding="utf-8")
print("[OK] Patched:", p)

# Final sanity hint (best-effort): show the first few -w occurrences
for i, line in enumerate(txt.splitlines(), 1):
    if "-w" in line and i < 4000:
        print(f"[HINT] line {i}: {line.strip()}")
        break
PY

echo "Done. Re-run your smoke slice (e.g., 50:51) and confirm patches are non-empty diffs."
