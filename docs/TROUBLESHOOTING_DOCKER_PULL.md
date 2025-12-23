# Troubleshooting: Docker pulls and 'freeze' symptoms (WSL + Docker Desktop)

## 1) Confirm Docker daemon is responsive
- `docker info`
- `docker version`

If these hang, Docker Desktop / WSL integration is the problem (not SWE-bench).

## 2) Observe active pull/download activity
- `docker events --since 10m | tail -n 50`
- `ps aux | egrep 'docker|containerd' | head`

On Windows (PowerShell):
- `wsl.exe -l -v`
- `wsl.exe --status`
- `Get-Process *docker*`
- `Get-NetTCPConnection | ? { $_.OwningProcess -in (Get-Process *docker*).Id } | select -First 20`

## 3) Confirm which images are already cached
- `docker images | grep -E 'swebench/sweb.eval.x86_64' | wc -l`
- `docker image inspect <image:tag> >/dev/null && echo CACHED`

## 4) Resume pulls safely (no deletion required)
Docker pulls resume automatically. Re-run your pull loop:
- `while read -r img; do docker pull "$img"; done < /tmp/swe_images_50_100.txt`

If a specific layer is stuck, retry just that image:
- `docker pull <image:tag>`

## 5) Avoid 'docker run timed out' during evaluation
Pre-pull the entire slice images first (recommended). Then `docker run -d ...` will start quickly.
