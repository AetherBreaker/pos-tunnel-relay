# Standard library imports
import base64
import json
import os
from typing import TYPE_CHECKING

# Third party imports
import pytest
from test_keys import KEY

# First party imports
from pos_tunnel_relay import const, keys
from pos_tunnel_relay.daemon import Connection, Daemon, FatalError
from pos_tunnel_relay.leases import Leases

if TYPE_CHECKING:
  # Standard library imports
  from pathlib import Path

  # Third party imports
  from conftest import FakeProc

NOW = 1_000_000
PORT = 20001
IDLE = 3600
PRIV, SPARE, OTHER = 101, 102, 103
FP = keys.fingerprint(KEY)
KEY2 = "ssh-ed25519 " + base64.b64encode(keys.ED25519_PREFIX + bytes(32)).decode()
FP2 = keys.fingerprint(KEY2)


class Setup:
  def __init__(self, tmp_path: Path, proc: FakeProc) -> None:
    self.proc = proc
    self.logged: list[tuple[int, str]] = []
    self.leases = Leases(tmp_path / "leases")
    self.leases.load()
    (tmp_path / "kill").mkdir()
    self.daemon = Daemon(
      leases=self.leases,
      log=lambda level, message: self.logged.append((level, message)),
      operators={KEY: "alice"},
      proc=proc.root,
      sshd_log=tmp_path / "sshd.log",
      ctl_socket=tmp_path / "ctl.sock",
      kill_dir=tmp_path / "kill",
      killer_beat=tmp_path / "killer.beat",
      heartbeat=tmp_path / "heartbeat.txt",
      started=NOW,
    )

  def open(self, key: str = KEY, port: int = PORT) -> dict:
    argv = ["open", str(port), str(port - 20000), str(IDLE), *key.split()]
    return self.daemon.handle_request({"argv": argv, "key": KEY}, "ctl", NOW)

  def close(self, port: int, now: int) -> None:
    assert self.daemon.handle_request({"argv": ["close", str(port)], "key": KEY}, "ctl", now)["status"] == 0

  def offer(self, pid: int, fingerprint: str = FP, now: int = NOW) -> dict:
    """`tunnel-keys` run by connection `pid`'s `[priv]` process for an offered key."""
    return self.daemon.handle_request({"argv": ["keys"], "pid": pid, "fingerprint": fingerprint}, "keys", now)

  def connect(self, pid: int, start: int, *fingerprints: str) -> None:
    """A `tunnel` connection that offers `fingerprints` in order."""
    self.proc.add(pid, start=start, title="sshd: tunnel [priv]")
    for fingerprint in fingerprints:
      self.offer(pid, fingerprint)

  def kills(self) -> list[str]:
    return sorted(p.name for p in self.daemon.kill_dir.iterdir())


@pytest.fixture
def s(tmp_path: Path, proc: FakeProc) -> Setup:
  return Setup(tmp_path, proc)


def test_an_offered_key_with_a_live_lease_is_recorded_against_its_connection(s: Setup):
  s.open()
  s.proc.add(PRIV, start=500, title="sshd: tunnel [priv]")
  assert s.offer(PRIV) == {"status": 0, "out": keys.tunnel_line(PORT, KEY, NOW + IDLE)}
  s.offer(PRIV)  # sshd asks again to verify the key it accepted
  assert s.daemon.connections == {PRIV: Connection(PRIV, 500, {FP})}
  assert [m for _, m in s.logged if m.startswith("connection")] == [f"connection {PRIV} offered {FP} (port {PORT})"]


def test_a_key_without_a_live_lease_is_not_recorded(s: Setup):
  s.proc.add(PRIV, start=500, title="sshd: tunnel [priv]")
  assert s.offer(PRIV) == {"status": 0, "out": ""}
  s.open()
  assert s.offer(PRIV, now=NOW + IDLE) == {"status": 0, "out": ""}  # past its deadline: no line either
  assert s.daemon.connections == {}


def test_a_connection_whose_process_already_ended_is_not_recorded(s: Setup):
  s.open()
  assert s.offer(PRIV)["status"] == 0
  assert s.daemon.connections == {}


@pytest.mark.parametrize(
  "report",
  [
    {"fingerprint": FP},
    {"pid": str(PRIV), "fingerprint": FP},
    {"pid": True, "fingerprint": FP},
    {"pid": 1, "fingerprint": FP},
    {"pid": PRIV},
    {"pid": PRIV, "fingerprint": "MD5:00"},
    {"pid": PRIV, "fingerprint": FP + "\n"},
  ],
)
def test_a_malformed_connection_report_gets_no_key_lines(s: Setup, report: dict):
  s.open()
  s.proc.add(PRIV, start=500, title="sshd: tunnel [priv]")
  assert s.daemon.handle_request({"argv": ["keys"], **report}, "keys", NOW) == {"status": 1, "out": "error: bad connection report"}
  assert s.daemon.connections == {}


def test_a_reused_pid_starts_a_new_record(s: Setup):
  s.open()
  s.open(KEY2, PORT + 1)
  s.connect(PRIV, 500, FP)
  s.proc.remove(PRIV)
  s.connect(PRIV, 999, FP2)
  assert s.daemon.connections == {PRIV: Connection(PRIV, 999, {FP2})}


def test_sshd_log_lines_are_forwarded_whole_and_feed_no_enforcement(s: Setup):
  login = f"Accepted publickey for tunnel from 10.0.0.9 port 51000 ssh2: ED25519 {FP}"
  s.daemon.handle_log(b"Server listening on 0.0.0.0 port 2222.\r\n" + login.encode() + b"\r\nConnection clo")
  s.daemon.handle_log(b"sed by 10.0.0.9\r\n\xff\xfe\r\n")
  assert [m for _, m in s.logged] == [
    "sshd: Server listening on 0.0.0.0 port 2222.",
    f"sshd: {login}",
    "sshd: Connection closed by 10.0.0.9",
    "sshd: ��",
  ]
  assert s.daemon.connections == {}


def test_commands_reply_json_and_are_audited_with_the_operator(s: Setup):
  reply = s.open()
  assert reply["status"] == 0
  view = json.loads(reply["out"])
  assert (view["port"], view["operator"], view["idle_remaining"], view["listening"], view["connections"]) == (
    PORT,
    "alice",
    IDLE,
    False,
    0,
  )
  assert any("tunnelctl by alice: open 20001" in message for _, message in s.logged)
  s.proc.listen(PORT)
  s.connect(PRIV, 500, FP)
  listed = json.loads(s.daemon.handle_request({"argv": ["status"], "key": KEY}, "ctl", NOW + 10)["out"])
  assert [(v["port"], v["listening"], v["idle_remaining"], v["connections"]) for v in listed] == [(PORT, True, IDLE - 10, 1)]


def test_refusals_and_bad_requests(s: Setup):
  s.open()
  assert s.open() == {"status": 1, "out": "error: a lease for port 20001 exists"}
  assert s.daemon.handle_request({"argv": ["frobnicate"]}, "ctl", NOW)["status"] == 1
  assert s.daemon.handle_request({"argv": []}, "ctl", NOW)["status"] == 1
  assert s.daemon.handle_request(["not", "a", "dict"], "ctl", NOW)["status"] == 1
  assert s.daemon.handle_request({"argv": [1, 2]}, "ctl", NOW)["status"] == 1


def test_roles_limit_what_a_caller_may_ask(s: Setup):
  s.open()
  assert s.offer(PRIV) == {"status": 0, "out": keys.tunnel_line(PORT, KEY, NOW + IDLE)}
  assert s.daemon.handle_request({"argv": ["close", str(PORT)]}, "keys", NOW)["status"] == 1
  assert s.daemon.handle_request({"argv": ["keys"], "pid": PRIV, "fingerprint": FP}, "ctl", NOW)["status"] == 1
  assert s.daemon.handle_request({"argv": ["status"]}, None, NOW)["status"] == 1
  assert PORT in s.leases.by_port


def test_every_connection_of_an_ended_lease_is_killed(s: Setup):
  s.open()
  s.connect(PRIV, 500, FP)
  s.connect(SPARE, 600, FP)
  s.daemon.enforce(NOW + 1)
  assert s.kills() == []
  s.close(PORT, NOW + 2)
  s.daemon.enforce(NOW + 2)
  assert s.kills() == [f"{PRIV}-500", f"{SPARE}-600"]
  assert PORT not in s.leases.by_port


def test_offering_another_pos_key_gets_only_the_offerer_killed(s: Setup):
  s.open()
  s.open(KEY2, PORT + 1)
  s.connect(PRIV, 500, FP)  # POS 1, its own key
  s.connect(OTHER, 700, FP, FP2)  # POS 2, offering POS 1's public key before its own
  s.close(PORT + 1, NOW + 1)
  s.daemon.enforce(NOW + 1)
  assert s.kills() == [f"{OTHER}-700"]
  s.proc.remove(OTHER)  # the killer did its job
  s.close(PORT, NOW + 2)
  s.daemon.enforce(NOW + 2)
  assert s.kills() == [f"{PRIV}-500", f"{OTHER}-700"]  # POS 2's request stays: no killer runs here


def test_a_connection_whose_lease_vanished_is_killed(s: Setup):
  s.open()
  s.connect(PRIV, 500, FP)
  del s.leases.by_port[PORT]  # e.g. its file was unreadable at the last start
  s.daemon.enforce(NOW + 1)
  assert s.kills() == [f"{PRIV}-500"]


def test_ended_processes_are_forgotten_and_unrecorded_ones_reported(s: Setup):
  s.open()
  s.connect(PRIV, 500, FP)
  s.proc.remove(PRIV)
  s.proc.add(PRIV, start=999, title="sshd: tunnel [priv]")  # same pid, another process
  s.daemon.enforce(NOW + 1)
  assert s.daemon.connections == {}
  assert any(f"tunnel sshd process {PRIV} has no recorded connection" in m for _, m in s.logged)
  assert s.kills() == []


def test_liveness_fails_when_the_killer_stops(s: Setup):
  s.daemon.check_liveness(NOW + const.STALE_SECS)  # no killer beat yet: grace from start
  with pytest.raises(FatalError, match="killer"):
    s.daemon.check_liveness(NOW + const.STALE_SECS + 1)
  s.daemon.killer_beat.touch()
  os.utime(s.daemon.killer_beat, (NOW + 500, NOW + 500))
  s.daemon.check_liveness(NOW + 500 + const.STALE_SECS)
  with pytest.raises(FatalError, match="killer"):
    s.daemon.check_liveness(NOW + 501 + const.STALE_SECS)


def test_the_heartbeat_is_an_iso_timestamp(s: Setup):
  s.daemon.beat(NOW)
  assert s.daemon.heartbeat.read_text(encoding="utf-8") == "1970-01-12T13:46:40+00:00"
