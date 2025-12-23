#!/usr/bin/env bash
set -euo pipefail

# Deprecated wrapper kept for backward compatibility.
# The authoritative, syntax-safe patch script is at repo root:
#   ./patch_minisweagent_docker_env.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

exec bash "$ROOT/patch_minisweagent_docker_env.sh"
