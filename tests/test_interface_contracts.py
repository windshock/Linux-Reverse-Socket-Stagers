from __future__ import annotations

import importlib.util
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULES = [
    ROOT / "01-single-socket-reverse-stager/exploit/angrop_chain.py",
    ROOT / "02-front-load-source-hijack/exploit/angrop_chain.py",
]


def load_module(path):
    spec = importlib.util.spec_from_file_location("angrop_chain_test", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_structured_angrop_interface_is_exposed():
    for path in MODULES:
        module = load_module(path)
        assert callable(module.analyze_binary)
        assert callable(module.analysis_summary)
        assert callable(module.build_rop_chain)
        assert callable(module.build_rop_chain_summary)
        assert callable(module.payload)


def test_analysis_and_error_summaries_are_json_serializable():
    module = load_module(MODULES[0])
    summary = module.analysis_summary({
        "binary": "/tmp/vuln",
        "gadget_count": 3,
        "verified_gadgets": (0x401000, 0x401010),
    })
    assert summary == {
        "ok": True,
        "binary": "/tmp/vuln",
        "gadget_count": 3,
        "verified_gadgets": ["0x401000", "0x401010"],
    }
    json.dumps(summary)
