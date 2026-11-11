"""JSON-safe summaries for AI-facing experiment orchestration."""
from __future__ import annotations


def verify_execution(output: str, mode: str) -> dict:
    """Summarize a run.sh transcript without returning the full log."""
    marker = "MARKER: True" in output
    shell = "SHELL_OK" in output
    passed = marker if mode == "marker" else shell
    return {
        "ok": passed,
        "mode": mode,
        "marker": marker,
        "shell_ok": shell,
        "failure": None if passed else "execution oracle not observed",
    }


def error_summary(exc: Exception) -> dict:
    return {"ok": False, "error": {"type": type(exc).__name__, "message": str(exc)}}
