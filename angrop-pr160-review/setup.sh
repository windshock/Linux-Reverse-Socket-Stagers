#!/usr/bin/env bash
# Rebuild the review environment from scratch (macOS/Linux, Python 3.12).
# Produces: ./angrop-src (HEAD 7976832), ./binaries (sparse), ./venv, ./bins/unexploitable
set -euo pipefail
cd "$(dirname "$0")"

PY="${PY:-python3.12}"

echo "[*] venv + angr stack (angr 10.0.7, angrop from HEAD)"
$PY -m venv venv
./venv/bin/pip -q install --upgrade pip
./venv/bin/pip -q install "angr==10.0.7" "claripy==9.3.7" "z3-solver==5.3.3.0" pytest setuptools keystone-engine

echo "[*] angrop upstream HEAD (editable)"
git clone --quiet https://github.com/angr/angrop.git angrop-src
( cd angrop-src && git checkout --quiet 7976832 )   # pin to the HEAD this review used
./venv/bin/pip -q install -e ./angrop-src

echo "[*] test binaries"
mkdir -p bins
# unexploitable + vuln_client3 are VENDORED in ./bins (the scripts read ./bins/*).
# Refetch unexploitable only if missing:
[ -f bins/unexploitable ] || curl -sL -o bins/unexploitable \
  https://raw.githubusercontent.com/angr/binaries/master/tests/x86_64/unexploitable
# Rebuild lab3 (vendored source) only if missing; needs docker (glibc 2.31 / __libc_csu_init).
if [ ! -f bins/vuln_client3 ]; then
  docker run --rm --platform=linux/amd64 -v "$PWD/bins/src":/s -v "$PWD/bins":/o ubuntu:20.04 \
    bash -c 'apt-get update >/dev/null && apt-get install -y gcc >/dev/null &&
      gcc -no-pie -fno-stack-protector -fcf-protection=none -O0 -g -w -o /o/vuln_client3 /s/vuln_client3.c'
fi

echo "[*] full binaries set (sparse) for the suite -> ./binaries (== angrop-src/../binaries)"
git clone --quiet --filter=blob:none --sparse https://github.com/angr/binaries.git binaries
( cd binaries && git sparse-checkout set \
    tests/x86_64 tests/i386 tests/armel tests/aarch64 tests/mips tests/riscv \
    tests_data/angrop_gadgets_cache )

cat <<'NOTE'

[*] done. Reproduce:

  # single-case before/after (primary evidence)
  ./venv/bin/python scripts/flip.py BEFORE
  ./venv/bin/python scripts/probe.py
  ./venv/bin/python scripts/rootcause.py
  ./venv/bin/python scripts/inspectB.py   # run AFTER applying the patch

  # apply the candidate relaxation, re-run flip, then revert
  ( cd angrop-src && git apply ../candidate-relaxation.diff )
  ./venv/bin/python scripts/flip.py AFTER
  ( cd angrop-src && git checkout -- angrop/chain_builder/func_caller.py )

  # full suite (keystone via brew on macOS; DYLD path for the dylib)
  #   brew install keystone   # macOS
  ( cd angrop-src && DYLD_LIBRARY_PATH=/opt/homebrew/lib \
      ../venv/bin/python -m pytest tests/test_chainbuilder.py -q )

  # open #3 (csu func_call cannot return/chain) and lab3 target-proof
  ./venv/bin/python scripts/open3.py
  ./venv/bin/python scripts/lab3_targetproof.py
  ./venv/bin/python scripts/lab3_why.py

  # §11 CORRECTION: low-level returning ret2csu works (set_regs + manual frame)
  ./venv/bin/python scripts/lowlevel.py

All scripts are run from THIS package directory and read ./bins/* (vendored).
NOTE
