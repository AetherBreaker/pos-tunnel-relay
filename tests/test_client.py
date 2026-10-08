# Standard library imports
import json
import os
import socket
import sys
import threading
from typing import TYPE_CHECKING

# Third party imports
import pytest

# First party imports
from pos_tunnel_relay import client, const

if TYPE_CHECKING:
  # Standard library imports
  from pathlib import Path

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="the clients use AF_UNIX on Linux")
KEY = "ssh-ed25519 AAAA"
FP = "SHA256:" + "A" * 43


class Server:
  """Answers one request with `reply` and records what it was asked."""

  def __init__(self, path: Path, reply: dict) -> None:
    self.asked: list[dict] = []
    self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    self.sock.bind(str(path))
    self.sock.listen(1)
    threading.Thread(target=self._serve, args=(reply,), daemon=True).start()

  def _serve(self, reply: dict) -> None:
    conn, _ = self.sock.accept()
    with conn:
      self.asked.append(json.loads(conn.makefile().readline()))
      conn.sendall(json.dumps(reply).encode() + b"\n")


@pytest.fixture
def ctl(short_dir: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
  path = short_dir / "ctl.sock"
  monkeypatch.setattr(const, "CTL_SOCKET", path)
  return path


def test_tunnelctl_forwards_the_command_and_the_operators_key(
  ctl: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
  server = Server(ctl, {"status": 0, "out": '{"port": 20001}'})
  auth = tmp_path / "auth"
  auth.write_text(f"publickey {KEY}\n", encoding="utf-8")
  monkeypatch.setenv("SSH_ORIGINAL_COMMAND", "tunnelctl status 20001")
  monkeypatch.setenv("SSH_USER_AUTH", str(auth))
  with pytest.raises(SystemExit) as exited:
    client.tunnelctl()
  assert exited.value.code == 0
  assert server.asked == [{"argv": ["status", "20001"], "key": KEY}]
  assert capsys.readouterr().out == '{"port": 20001}\n'


def test_a_refusal_goes_to_stderr_with_status_1(ctl: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]):
  Server(ctl, {"status": 1, "out": "error: no lease for port 20001"})
  monkeypatch.setenv("SSH_ORIGINAL_COMMAND", "renew 20001")
  monkeypatch.delenv("SSH_USER_AUTH", raising=False)
  with pytest.raises(SystemExit) as exited:
    client.tunnelctl()
  assert exited.value.code == 1
  assert capsys.readouterr().err == "error: no lease for port 20001\n"


def test_an_unreachable_daemon_says_the_relay_is_starting(
  ctl: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
  monkeypatch.setenv("SSH_ORIGINAL_COMMAND", "status")
  with pytest.raises(SystemExit) as exited:
    client.tunnelctl()
  assert exited.value.code == client.EX_UNAVAILABLE
  assert capsys.readouterr().err == client.STARTING + "\n"


def test_tunnel_keys_reports_its_connection_and_prints_the_lines_for_tunnel_only(
  ctl: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
  server = Server(ctl, {"status": 0, "out": "line one\nline two"})
  monkeypatch.setattr(sys, "argv", ["tunnel-keys", "jump", FP])
  client.tunnel_keys()
  assert capsys.readouterr().out == ""
  monkeypatch.setattr(sys, "argv", ["tunnel-keys", "tunnel", FP])
  client.tunnel_keys()
  assert capsys.readouterr().out == "line one\nline two\n"
  # sshd runs it from the connection's [priv] process, so its parent names the connection.
  assert server.asked == [{"argv": ["keys"], "pid": os.getppid(), "fingerprint": FP}]


def test_tunnel_keys_prints_nothing_when_refused_or_the_daemon_is_down(
  ctl: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
  monkeypatch.setattr(sys, "argv", ["tunnel-keys", "tunnel", FP])
  client.tunnel_keys()
  assert capsys.readouterr().out == ""
  Server(ctl, {"status": 1, "out": "error: bad connection report"})
  client.tunnel_keys()
  assert capsys.readouterr().out == ""
