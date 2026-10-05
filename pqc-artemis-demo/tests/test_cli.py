"""CLI smoke tests."""

from __future__ import annotations

from artemis.cli import main


def test_status_exits_0(capsys):
    assert main(["status"]) == 0
    out = capsys.readouterr().out
    assert "liboqs available" in out
    assert "ML-KEM-768" in out
    assert "ML-DSA-65" in out


def test_demo_exits_0(capsys):
    assert main(["demo", "--message", "lab ping"]) == 0
    out = capsys.readouterr().out
    assert "[OK] Hybrid KEX" in out
    assert "[OK] Session AEAD" in out
    assert "[OK] Hybrid signatures" in out
    assert "lab_only" in out
