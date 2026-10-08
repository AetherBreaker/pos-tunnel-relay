# Standard library imports
import os
import sys
from pathlib import Path
from typing import TYPE_CHECKING

# Third party imports
import pytest

# First party imports
from pos_tunnel_relay import const, killer

if TYPE_CHECKING:
  # Third party imports
  from conftest import FakeProc

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="SIGKILL exists only on POSIX")
type World = tuple[Path, Path, Path, list[int]]  # kill dir, daemon heartbeat, killer beat, pids killed
NOW = 1_000_000.0
PRIV, CHILD, OTHER_PRIV, OTHER_CHILD, LISTENER = 101, 102, 201, 202, 7


@pytest.fixture
def world(tmp_path: Path, proc: FakeProc, monkeypatch: pytest.MonkeyPatch) -> World:
  proc.add(LISTENER, start=1, title="sshd: /usr/sbin/sshd [listener] 0 of 10-100 startups")
  proc.add(PRIV, start=500, title="sshd: tunnel [priv]")
  proc.add(CHILD, start=501, title="sshd: tunnel", ppid=PRIV)
  proc.add(OTHER_PRIV, start=600, title="sshd: tunnel [priv]")
  proc.add(OTHER_CHILD, start=601, title="sshd: tunnel", ppid=OTHER_PRIV)
  kill_dir, heartbeat, beat = tmp_path / "kill", tmp_path / "heartbeat.txt", tmp_path / "killer.beat"
  kill_dir.mkdir()
  heartbeat.write_text("x", encoding="utf-8")
  os.utime(heartbeat, (NOW - 10, NOW - 10))
  killed: list[int] = []
  monkeypatch.setattr(killer.os, "kill", lambda pid, _sig: killed.append(pid))
  return kill_dir, heartbeat, beat, killed


def run(world: World, proc: FakeProc) -> list[int]:
  kill_dir, heartbeat, beat, killed = world
  killer.run(kill_dir, heartbeat, beat, proc.root, NOW)
  return killed


def test_a_requested_connection_and_its_child_are_killed_and_the_request_removed(world: World, proc: FakeProc):
  (world[0] / f"{PRIV}-500").touch()
  assert run(world, proc) == [CHILD, PRIV]
  assert list(world[0].iterdir()) == []
  assert world[2].stat().st_mtime == NOW


def test_a_reused_pid_is_not_killed(world: World, proc: FakeProc):
  (world[0] / f"{PRIV}-499").touch()  # PRIV now names a process that started later
  (world[0] / f"{LISTENER}-1").touch()  # right identity, but not a tunnel connection
  (world[0] / "junk").touch()
  assert run(world, proc) == []
  assert list(world[0].iterdir()) == []


def test_a_stale_daemon_heartbeat_kills_every_tunnel_connection(world: World, proc: FakeProc):
  os.utime(world[1], (NOW - const.STALE_SECS - 1, NOW - const.STALE_SECS - 1))
  assert sorted(run(world, proc)) == [PRIV, CHILD, OTHER_PRIV, OTHER_CHILD]


def test_a_missing_daemon_heartbeat_counts_as_stale(world: World, proc: FakeProc):
  world[1].unlink()
  assert sorted(run(world, proc)) == [PRIV, CHILD, OTHER_PRIV, OTHER_CHILD]
