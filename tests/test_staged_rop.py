from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
MODULES = [
    ROOT / "01-single-socket-reverse-stager/exploit/staged_rop.py",
    ROOT / "02-front-load-source-hijack/exploit/staged_rop.py",
    ROOT / "03-ret2csu-flags-zero/exploit/staged_rop.py",
]


class FakeLibc:
    bits = 64

    def __init__(self, offset=0x12340):
        self.address = 0
        self.symbols = {"send": offset}


class FakeConn:
    def __init__(self, *chunks):
        self.chunks = list(chunks)
        self.sent = []

    def recv(self, _size):
        return self.chunks.pop(0) if self.chunks else b""

    def sendall(self, data):
        self.sent.append(data)


class TimeoutConn(FakeConn):
    def recv(self, _size):
        raise TimeoutError("simulated socket timeout")


def load_session(path):
    name = "staged_rop_test_" + path.parent.parent.name.replace("-", "_")
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module.StagedRopSession


@pytest.mark.parametrize("path", MODULES)
def test_fragmented_leak_rebases_and_preserves_symbol_offset(path):
    Session = load_session(path)
    libc = FakeLibc()
    offset = libc.symbols["send"]
    base1, base2 = 0x700000000000, 0x710000000000
    conn = FakeConn((base1 + offset).to_bytes(8, "little")[:3],
                    (base1 + offset).to_bytes(8, "little")[3:],
                    (base2 + offset).to_bytes(8, "little"))
    session = Session(conn, libc, 6)

    first = session.receive_leak("send")
    second = session.receive_leak("send")

    assert first.base == base1
    assert second.base == base2
    assert libc.address == base2


@pytest.mark.parametrize("path", MODULES)
def test_short_leak_fails_and_delivery_remains_explicit(path):
    Session = load_session(path)
    conn = FakeConn(b"\x01\x02")
    session = Session(conn, FakeLibc(), 6)

    with pytest.raises(RuntimeError, match="short leak"):
        session.receive_leak("send")
    session.deliver_stage2(b"stage2")
    assert conn.sent == [b"stage2"]


@pytest.mark.parametrize("path", MODULES)
def test_stage2_delivery_is_byte_exact(path):
    Session = load_session(path)
    conn = FakeConn()
    session = Session(conn, FakeLibc(), 6)
    payload = b"\x00stage2\xff"

    session.deliver_stage2(payload)

    assert conn.sent == [payload]


@pytest.mark.parametrize("path", MODULES)
def test_socket_timeout_is_not_silently_converted_to_a_leak(path):
    Session = load_session(path)
    session = Session(TimeoutConn(), FakeLibc(), 6)

    with pytest.raises(TimeoutError, match="simulated socket timeout"):
        session.receive_leak("send")
