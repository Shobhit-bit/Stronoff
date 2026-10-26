"""Regression tests for bugs found while testing (several found on the real Arch machine)."""
import os

from collectors import common
from collectors.processes import redact_cmdline
from collectors.services import parse_analyze


def test_symlink_permissions_describe_the_target(tmp_path):
    real = tmp_path / "real"
    real.write_text("x")
    real.chmod(0o644)
    link = tmp_path / "link"
    link.symlink_to(real)
    m = common.file_meta(str(link))
    assert m["is_symlink"] and m["mode"] == "0644" and m["world_writable"] is False   # not the link's own 0777
    assert m["link_target"] == str(real)
    broken = tmp_path / "broken"
    broken.symlink_to(tmp_path / "nope")
    b = common.file_meta(str(broken))
    assert b["broken_symlink"] is True and b["world_writable"] is None


def test_pacman_owners_resolves_symlinked_directories(tmp_path, monkeypatch):
    real = tmp_path / "usr_bin"
    real.mkdir()
    (tmp_path / "bin").symlink_to(real)                       # like /bin -> /usr/bin on Arch
    asked = str(tmp_path / "bin" / "sh")

    class P:
        returncode = 0
        stdout = f"{real}/sh is owned by bash 5.2-1\n"           # pacman prints the RESOLVED path
        stderr = ""

    monkeypatch.setattr(common.shutil, "which", lambda n: "/usr/bin/pacman")
    monkeypatch.setattr(common.subprocess, "run", lambda *a, **k: P())
    owners = common.pacman_owners([asked])
    assert owners[asked]["package"] == "bash"                 # not misreported as unowned


def test_cmdline_redaction_covers_embedded_secrets():
    out, red = redact_cmdline(["sh", "-c", "export DB_PASSWORD=hunter2; run --api-key abc123"])
    assert "hunter2" not in out and "abc123" not in out and red


def test_exposure_score_is_numeric():
    got = parse_analyze('[{"unit": "sshd.service", "exposure": "9.6", "predicate": "UNSAFE"}]')
    assert got["sshd.service"]["exposure"] == 9.6
