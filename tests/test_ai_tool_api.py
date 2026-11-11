import json

from scripts.ai_tool_api import verify_execution


def test_verify_execution_returns_compact_json_summary():
    summary = verify_execution("MARKER: True\nPROOF\n", "marker")
    assert summary["ok"] is True
    assert summary["marker"] is True
    json.dumps(summary)


def test_verify_execution_does_not_infer_success_from_partial_output():
    summary = verify_execution("MARKER: False\n", "marker")
    assert summary["ok"] is False
    assert summary["failure"] is not None
