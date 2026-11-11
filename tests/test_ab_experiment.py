from scripts.ab_experiment import summarize


def test_ab_summary_reports_measured_metrics():
    result = summarize([
        {"condition": "direct", "run_id": 1, "input_tokens": 100,
         "output_tokens": 80, "tool_calls": 0, "tool_time_seconds": 0,
         "total_time_seconds": 4, "success": True, "retries": 1},
        {"condition": "tool", "run_id": 1, "input_tokens": 70,
         "output_tokens": 30, "tool_calls": 2, "tool_time_seconds": 1.2,
         "total_time_seconds": 2, "success": True, "retries": 0},
    ])
    assert result["status"] == "MEASURED"
    assert result["conditions"]["tool"]["success_rate"] == 1.0


def test_ab_summary_does_not_fabricate_missing_measurements():
    assert summarize([]) == {"status": "NOT_TESTED", "reason": "no experiment records"}
