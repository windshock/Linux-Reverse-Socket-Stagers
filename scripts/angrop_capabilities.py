#!/usr/bin/env python3
"""Report angrop API availability and lab-specific integration boundaries.

This deliberately does not claim that an API succeeds on every binary. It
reports the available builder surface and the parts that remain protocol or
layout-specific in these synthetic labs.
"""
from __future__ import annotations

import argparse
import importlib.util
from pathlib import Path


LABS = {
    "lab1-single-socket": {
        "binary": "01-single-socket-reverse-stager/vuln_client",
        "external": "socket leak, libc resolution, and stage-2 transport",
        "special": "fixed planted gadgets; no ret2csu required",
    },
    "lab2-front-load": {
        "binary": "02-front-load-source-hijack/vuln_client2",
        "external": "front-loaded memcpy placement plus socket staging",
        "special": "RIP placement is formatter-specific; angrop does not model it",
    },
    "lab3-ret2csu": {
        "binary": "03-ret2csu-flags-zero/vuln_client3",
        "external": "socket leak, libc resolution, and stage-2 transport",
        "special": "explicit ret2csu helper for the CSU indirect-call frame",
    },
}


def load_angrop():
    if importlib.util.find_spec("angr") is None or importlib.util.find_spec("angrop") is None:
        return None, "angr/angrop is not installed"
    import angr  # type: ignore
    import angrop  # noqa: F401  # type: ignore
    return angr, None


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    angr, error = load_angrop()
    print("# angrop capability report\n")
    if error:
        print(f"angr/angrop: unavailable ({error})\n")
        return 2
    print(f"angr: {angr.__version__}")
    print("\n| Capability | API surface |")
    print("|---|---|")
    # Use a tiny real project so the report reflects the installed API rather
    # than claiming support from a hard-coded list.
    probe = angr.Project("/bin/true", auto_load_libs=False)
    builder = probe.analyses.ROP().chain_builder
    for name in ("set_regs", "move_regs", "func_call", "write_to_mem",
                 "pivot", "do_syscall", "sigreturn", "ret2csu"):
        print(f"| {name} | available on ChainBuilder: {'yes' if hasattr(builder, name) else 'no'} |")

    for lab, meta in LABS.items():
        binary = args.root / meta["binary"]
        print(f"\n## {lab}")
        print(f"- binary present: {'yes' if binary.exists() else 'no'}")
        if not binary.exists():
            continue
        project = angr.Project(str(binary), auto_load_libs=False)
        builder = project.analyses.ROP().chain_builder
        print(f"- explicit `ret2csu`: {'yes' if hasattr(builder, 'ret2csu') else 'no'}")
        print(f"- external runtime boundary: {meta['external']}")
        print(f"- lab-specific boundary: {meta['special']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
