# Standard library imports
import base64
import stat
import subprocess
import sys
from typing import TYPE_CHECKING

# Third party imports
import pytest
from test_keys import B64, KEY

# First party imports
from pos_tunnel_relay import const, startup

if TYPE_CHECKING:
  # Standard library imports
  from pathlib import Path

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="relay-startup runs as root on Linux")
OWNER_ONLY = 0o600
PRIVATE = b"-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----\n"


class Recorder:
  def __init__(self) -> None:
    self.calls: list[list[str]] = []

  def __call__(self, args: list[str], **_: object) -> subprocess.CompletedProcess[str]:
    self.calls.append(list(args))
    missing_user = args[:2] == ["id", "-u"]
    return subprocess.CompletedProcess(args, 1 if missing_user else 0, "", "")


@pytest.fixture
def host(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Recorder:
  monkeypatch.setattr(const, "RUN", tmp_path / "run" / "pos-tunnel")
  monkeypatch.setattr(const, "KILL_DIR", const.RUN / "kill")
  monkeypatch.setattr(const, "SSHD_LOG", const.RUN / "sshd.log")
  monkeypatch.setattr(const, "OPERATOR_KEYS", tmp_path / "etc" / "ssh" / "operator_keys")
  monkeypatch.setattr(startup, "SSHD_CONFIG", tmp_path / "etc" / "ssh" / "sshd_config")
  monkeypatch.setattr(startup, "RELAY_KEY", tmp_path / "run" / "relay" / "ssh_host_ed25519_key")
  monkeypatch.setattr(startup, "CRON_FILE", tmp_path / "etc" / "cron.d" / "relay-killer")
  monkeypatch.setattr(startup, "PRIVSEP", tmp_path / "run" / "sshd")
  (tmp_path / "run").mkdir()
  monkeypatch.setattr(startup.os, "chown", lambda *_: None)
  monkeypatch.setenv("RELAY_SSH_PRIVATE_KEY", base64.b64encode(PRIVATE).decode())
  monkeypatch.setenv("OPERATOR_KEYS", f"alice={B64}")
  rec = Recorder()
  monkeypatch.setattr(startup.subprocess, "run", rec)
  return rec


def test_startup_prepares_accounts_keys_configuration_and_the_log_fifo(host: Recorder):
  stale = const.RUN / "kill" / "1-1"
  stale.parent.mkdir(parents=True)
  stale.touch()
  startup.main()
  assert startup.RELAY_KEY.read_bytes() == PRIVATE
  assert startup.RELAY_KEY.stat().st_mode & 0o777 == OWNER_ONLY
  assert const.OPERATOR_KEYS.read_text(encoding="utf-8") == f"{KEY} alice\n"
  assert "AuthorizedKeysCommand /app/.venv/bin/tunnel-keys %u %f" in startup.SSHD_CONFIG.read_text(encoding="utf-8")
  assert startup.CRON_FILE.read_text(encoding="utf-8").strip().endswith("root /app/.venv/bin/relay-killer")
  assert not stale.exists() and const.KILL_DIR.is_dir()
  mode = const.SSHD_LOG.stat().st_mode
  assert stat.S_ISFIFO(mode) and mode & 0o777 == OWNER_ONLY
  # It starts nothing: the supervisor runs sshd and cron ([tool.docker].daemons). It only checks sshd's configuration.
  assert [c for c in host.calls if c[0].startswith("/usr/sbin/")] == [["/usr/sbin/sshd", "-t"]]
  assert ["usermod", "--password", "*", "tunnel"] in host.calls
  assert any(c[:1] == ["useradd"] and c[-1] == "keyreader" for c in host.calls)


@pytest.mark.parametrize(
  "case",
  [
    ("RELAY_SSH_PRIVATE_KEY", "", "RELAY_SSH_PRIVATE_KEY is not set"),
    ("RELAY_SSH_PRIVATE_KEY", "not base64!", "not an OpenSSH private key"),
    ("RELAY_SSH_PRIVATE_KEY", base64.b64encode(b"hello").decode(), "not an OpenSSH private key"),
    ("OPERATOR_KEYS", "", "OPERATOR_KEYS is not set"),
    ("OPERATOR_KEYS", "alice=AAAA", "OPERATOR_KEYS: bad entry"),
  ],
)
def test_missing_or_bad_keys_stop_startup_before_anything_runs(
  host: Recorder, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], case: tuple[str, str, str]
):
  var, value, message = case
  monkeypatch.setenv(var, value)
  with pytest.raises(SystemExit, match="1"):
    startup.main()
  err = capsys.readouterr().err
  assert message in err
  assert "BEGIN OPENSSH" not in err
  assert host.calls == []
