# HOW_TO_RUN – τGuardian SWE-bench Harness (WSL Edition)

This guide assumes:

- You are on **Windows 10/11 + WSL (Ubuntu)**.
- Your repo is in WSL at something like:  
  `~/projects/tau_guardian_harness9`  
- Docker Desktop is installed and **WSL integration enabled**.
- You already have at least one minisweagent run folder (e.g. `msa_glm46_lite_run20/`) with:
  - `preds_filled.json`
  - `security_reports/*.json`
  - `eval/` (will be created by the CLI step)

---

## 0. Activate environment (WSL)

```bash
# In WSL
cd ~/projects/tau_guardian_harness9

# If the venv already exists:
source .venv_wsl/bin/activate  # or: source .venv/bin/activate

# If you need to create it once:
# python -m venv .venv_wsl
# source .venv_wsl/bin/activate
# pip install -r requirements.txt
