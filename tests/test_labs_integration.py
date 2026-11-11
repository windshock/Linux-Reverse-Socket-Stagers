from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
LABS = [
    (ROOT / "01-single-socket-reverse-stager", {"ANGROP": "1"}),
    (ROOT / "02-front-load-source-hijack", {"ANGROP": "1"}),
    (ROOT / "03-ret2csu-flags-zero", {"ROPBOT": "1"}),
]


@pytest.mark.integration
@pytest.mark.parametrize("lab,variables", LABS)
def test_lab_marker_and_shell_end_to_end(lab, variables):
    """Run the authoritative Docker harness for both marker and shell modes."""
    if os.environ.get("RUN_LAB_INTEGRATION") != "1":
        pytest.skip("set RUN_LAB_INTEGRATION=1 to run Docker-backed labs")
    env = os.environ.copy()
    env.update(variables)
    result = subprocess.run(
        ["./run.sh"], cwd=lab, env=env, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=240,
        check=False,
    )
    assert result.returncode == 0, result.stdout
    assert "MARKER: True" in result.stdout
    assert "SHELL_OK" in result.stdout
