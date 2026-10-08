# Standard library imports
import json
import logging
import os
import socket
import sys
import threading
import time
from typing import TYPE_CHECKING

# Third party imports
import pytest
from test_daemon import FP, IDLE, KEY, PORT, PRIV, Setup

if TYPE_CHECKING:
  # Standard library imports
  from collections.abc import Callable
  from pathlib import Path

  # Third party imports
  from conftest import FakeProc

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="FIFOs, AF_UNIX and SO_PEERCRED are Linux-only")
LISTENING = "Server listening on 0.0.0.0 port 2222."


def ask(path: Path, payload: object) -> dict:
  with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
    s.settimeout(5)
    s.connect(str(path))
    s.sendall(json.dumps(payload).encode() + b"\n")
    return json.loads(s.makefile().readline())


def wait_until(condition: Callable[[], bool]) -> None:
  for _ in range(100):
    if condition():
      return
    time.sleep(0.05)
  pytest.fail("timed out")


def test_the_loop_reads_sshds_log_serves_requests_by_role_and_beats(short_dir: Path, proc: FakeProc):
  s = Setup(short_dir, proc)
  s.daemon.started = time.time()  # the loop runs on the real clock; Setup's NOW would make the killer look stale
  os.mkfifo(s.daemon.sshd_log)  # relay-startup's job in the container
  roles = {os.getuid(): "ctl"}
  stop = threading.Event()
  thread = threading.Thread(target=s.daemon.serve, args=(stop.is_set, roles), daemon=True)
  thread.start()
  wait_until(lambda: s.daemon.ctl_socket.exists() and s.daemon.heartbeat.exists())
  # Non-blocking, this open fails unless the daemon holds the FIFO open: the gate sshd waits on.
  writer = os.open(s.daemon.sshd_log, os.O_WRONLY | os.O_NONBLOCK)
  os.write(writer, f"{LISTENING}\r\n".encode())
  os.close(writer)
  wait_until(lambda: (logging.INFO, f"sshd: {LISTENING}") in s.logged)
  reply = ask(s.daemon.ctl_socket, {"argv": ["open", str(PORT), "1", str(IDLE), *KEY.split()], "key": KEY})
  assert reply["status"] == 0
  proc.add(PRIV, start=500, title="sshd: tunnel [priv]")
  roles[os.getuid()] = "keys"  # serve reads this same dict per request
  reply = ask(s.daemon.ctl_socket, {"argv": ["keys"], "pid": PRIV, "fingerprint": FP})
  assert reply["status"] == 0
  assert f'permitlisten="localhost:{PORT}"' in reply["out"]
  assert PRIV in s.daemon.connections
  stop.set()
  thread.join(5)
  assert not thread.is_alive()  # it returned on stop, not on FatalError
