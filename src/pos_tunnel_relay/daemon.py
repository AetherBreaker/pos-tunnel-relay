"""The relay daemon (design 6.5): leases, connections, enforcement, `sshd`'s log, and requests from `tunnelctl` and `tunnel-keys`.

One single-threaded loop owns all relay state, so nothing needs a lock. It runs as uid 999 under
devkit-container's supervisor; anything that leaves it unable to enforce raises `FatalError`, which ends the
process and with it the container.
"""

# Standard library imports
import json
import logging
import os
import re
import selectors
import socket
import struct
import sys
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

# First party imports
from pos_tunnel_relay import const, keys, procfs
from pos_tunnel_relay.leases import LeaseError, Leases
from pos_tunnel_relay.sender import LogSender

if TYPE_CHECKING:
  # Standard library imports
  from collections.abc import Callable
  from io import FileIO
  from pathlib import Path

  # First party imports
  from pos_tunnel_relay.leases import Lease

# The killer runs every minute; a connection that outlives this after its request is asked for again.
REKILL_SECS = 90
PASS_SECS = 5
REQUEST_TIMEOUT = 2.0
MAX_REQUEST = 65536
LOG_READ = 65536  # a whole default pipe buffer
READS_PER_TURN = 100  # so a flood of log lines can't starve the enforcement pass
PEERCRED = struct.Struct("3i")  # pid, uid, gid
USAGE = (
  "usage: tunnelctl open <port> <device-id> <idle-seconds> ssh-ed25519 <base64> [--rebuild]"
  " | renew <port> | close <port> | status [<port>]"
)
# `%f` for an ed25519 key: SHA-256, unpadded base64.
FINGERPRINT = re.compile(r"SHA256:[A-Za-z0-9+/]{43}")


class FatalError(Exception):
  """The daemon can no longer enforce; the message says why."""


@dataclass
class Connection:
  """A `tunnel` connection: its `[priv]` process (pid and start time, since pids get reused) and each live-lease key it offered."""

  pid: int
  start: int
  fingerprints: set[str] = field(default_factory=set)


def _iso(epoch: int) -> str:
  return datetime.fromtimestamp(epoch, UTC).isoformat()


class Daemon:
  """The relay's state and the work its loop does."""

  def __init__(
    self,
    *,
    leases: Leases,
    log: Callable[[int, str], None],
    operators: dict[str, str],
    proc: Path = const.PROC,
    sshd_log: Path = const.SSHD_LOG,
    ctl_socket: Path = const.CTL_SOCKET,
    kill_dir: Path = const.KILL_DIR,
    killer_beat: Path = const.KILLER_BEAT,
    heartbeat: Path = const.HEARTBEAT,
    started: float | None = None,
  ) -> None:
    """Paths default to the container's (`const`); tests pass their own."""
    self.leases = leases
    self.log = log
    self.operators = operators
    self.proc = proc
    self.sshd_log = sshd_log
    self.ctl_socket = ctl_socket
    self.kill_dir = kill_dir
    self.killer_beat = killer_beat
    self.heartbeat = heartbeat
    self.started = time.time() if started is None else started
    self.connections: dict[int, Connection] = {}
    self._requested: dict[tuple[int, int], int] = {}  # (pid, start) -> when its kill was last requested
    self._reported: set[int] = set()
    self._partial = b""

  def handle_log(self, data: bytes) -> None:
    """Forward each complete line `sshd -E` wrote (the bare message, CRLF-terminated); a partial line waits for its end."""
    *lines, self._partial = (self._partial + data).split(b"\n")
    for line in lines:
      self.log(logging.INFO, "sshd: " + line.rstrip(b"\r").decode(errors="replace"))

  def handle_request(self, request: object, role: str | None, now: int) -> dict[str, Any]:
    """Answer one request: `tunnelctl` (role `ctl`) the commands of design 6.4, `tunnel-keys` (role `keys`) the key lines."""
    if not isinstance(request, dict):
      return {"status": 1, "out": USAGE}
    argv = request.get("argv")
    if not isinstance(argv, list) or not argv or not all(isinstance(word, str) for word in argv):
      return {"status": 1, "out": USAGE}
    if role == "keys" and argv == ["keys"]:
      return self._keys(request, now)
    if role != "ctl" or argv[0] == "keys":
      return {"status": 1, "out": "error: not allowed"}
    operator = self.operators.get(str(request.get("key")), "an unknown operator")
    self.log(logging.INFO, f"tunnelctl by {operator}: {' '.join(argv)}")
    try:
      out = self._command(argv[0], argv[1:], operator, now)
    except LeaseError as e:
      self.log(logging.INFO, f"tunnelctl by {operator}: refused: {e}")
      return {"status": 1, "out": f"error: {e}"}
    return {"status": 0, "out": out}

  def _keys(self, request: dict[str, Any], now: int) -> dict[str, Any]:
    """Record the offered key against its connection if a live lease holds it, then serve the key lines (design 6.3, 6.5).

    The key lines and the record use the same lease and `now`, so a key `sshd` can accept is always recorded.
    A malformed report gets no lines: no connection logs in unrecorded.
    """
    pid, fingerprint = request.get("pid"), request.get("fingerprint")
    if type(pid) is not int or pid <= 1 or not isinstance(fingerprint, str) or FINGERPRINT.fullmatch(fingerprint) is None:
      self.log(logging.WARNING, f"tunnel-keys: bad connection report: pid {pid!r}, fingerprint {fingerprint!r}")
      return {"status": 1, "out": "error: bad connection report"}
    lease = next((held for held in self.leases.by_port.values() if held.fingerprint == fingerprint and now < held.deadline), None)
    start = None if lease is None else procfs.start_time(pid, self.proc)
    if lease is not None and start is not None:  # a process already gone can't log in
      connection = self.connections.get(pid)
      if connection is None or connection.start != start:
        connection = self.connections[pid] = Connection(pid, start)
      if fingerprint not in connection.fingerprints:
        connection.fingerprints.add(fingerprint)
        self.log(logging.INFO, f"connection {pid} offered {fingerprint} (port {lease.port})")
    return {"status": 0, "out": self.leases.key_lines(now)}

  def _command(self, command: str, args: list[str], operator: str, now: int) -> str:
    match command, args:
      case "open", _:
        return json.dumps(self._view(self.leases.open(args, operator, now), now))
      case "renew", _:
        return json.dumps(self._view(self.leases.renew(args, now), now))
      case "close", _:
        return json.dumps(self._view(self.leases.close(args, now), now))
      case "status", []:
        return json.dumps([self._view(lease, now) for lease in sorted(self.leases.by_port.values(), key=lambda lease: lease.port)])
      case "status", _:
        return json.dumps(self._view(self.leases.get(args), now))
      case _:
        raise LeaseError(USAGE)

  def _view(self, lease: Lease, now: int) -> dict[str, Any]:
    return {
      "port": lease.port,
      "device_id": lease.device_id,
      "operator": lease.operator,
      "started": _iso(lease.started),
      "idle_deadline": _iso(lease.deadline),
      "absolute_deadline": _iso(lease.absolute_deadline),
      # Remaining time on the relay's clock: posctl never compares relay times with its own (design 5).
      "idle_remaining": max(0, lease.deadline - now),
      "absolute_remaining": max(0, lease.absolute_deadline - now),
      "listening": procfs.listening(lease.port, self.proc),
      "connections": sum(lease.fingerprint in c.fingerprints for c in self.connections.values()),
    }

  def enforce(self, now: int) -> None:
    """One pass (design 6.5): forget ended connections, end expired leases, request kills, report strays."""
    for pid, connection in list(self.connections.items()):
      if procfs.start_time(pid, self.proc) != connection.start:
        del self.connections[pid]
        self._requested.pop((pid, connection.start), None)
    for lease in self.leases.expire(now):
      self.log(logging.INFO, f"lease for port {lease.port} (device {lease.device_id}, opened by {lease.operator}) ended")
    live = {lease.fingerprint for lease in self.leases.by_port.values()}
    for connection in self.connections.values():
      # Any key without a lease, not only the one it logged in with: sshd doesn't say which that was.
      ended = connection.fingerprints - live
      identity = (connection.pid, connection.start)
      asked = self._requested.get(identity)
      if ended and (asked is None or now - asked > REKILL_SECS):
        (self.kill_dir / f"{connection.pid}-{connection.start}").touch()
        self._requested[identity] = now
        self.log(logging.INFO, f"ending connection {connection.pid}: no lease holds {', '.join(sorted(ended))}")
    for pid in procfs.tunnel_sshd(self.proc, privileged_only=True):
      if pid not in self.connections and pid not in self._reported:
        self._reported.add(pid)
        self.log(logging.WARNING, f"tunnel sshd process {pid} has no recorded connection; left running")

  def check_liveness(self, now: float) -> None:
    """Raise `FatalError` if the killer has stopped beating (design 6.5); devkit-container watches `sshd` and `cron`."""
    try:
      beat = self.killer_beat.stat().st_mtime
    except OSError:
      beat = self.started  # cron's first run can be up to a minute after start
    if now - max(beat, self.started) > const.STALE_SECS:
      raise FatalError(f"the killer hasn't run for over {const.STALE_SECS} s")

  def beat(self, now: float) -> None:
    """The heartbeat devkit-container's supervisor reads, written from the loop so a stalled loop stops it."""
    self.heartbeat.write_text(datetime.fromtimestamp(now, UTC).isoformat(), encoding="utf-8")

  def serve(self, stop: Callable[[], bool], roles: dict[int, str]) -> None:
    """Open `sshd`'s log, bind the request socket, then loop until `stop()`; raises `FatalError`.

    Opening the log is the startup gate: `sshd` waits for a reader before it listens (design 6.3). It is
    opened read-write because a read-only FIFO polls readable, at EOF, forever once a writer has come and
    gone (verified on bookworm), which would spin this loop.
    """
    with (
      os.fdopen(os.open(self.sshd_log, os.O_RDWR | os.O_NONBLOCK), "rb", buffering=0) as intake,
      socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as requests,
      selectors.DefaultSelector() as selector,
    ):
      self.ctl_socket.unlink(missing_ok=True)
      requests.bind(str(self.ctl_socket))
      self.ctl_socket.chmod(0o666)  # who may ask what is decided per request, from the caller's uid
      requests.listen(16)
      requests.settimeout(0)  # non-blocking
      selector.register(intake, selectors.EVENT_READ)
      selector.register(requests, selectors.EVENT_READ)
      next_pass = 0.0
      while not stop():
        for key, _ in selector.select(timeout=1.0):
          if key.fileobj is intake:
            self._drain(intake)
          else:
            self._answer(requests, roles)
        now = time.time()
        if now >= next_pass:
          self.enforce(int(now))
          self.check_liveness(now)
          self.beat(now)
          next_pass = now + PASS_SECS

  def _drain(self, intake: FileIO) -> None:
    for _ in range(READS_PER_TURN):
      data = intake.read(LOG_READ)
      if not data:  # None: empty for now. Never b"" (EOF): the daemon holds a write end itself.
        return
      self.handle_log(data)

  def _answer(self, requests: socket.socket, roles: dict[int, str]) -> None:
    try:
      conn, _ = requests.accept()
    except BlockingIOError:
      return
    with conn:
      conn.settimeout(REQUEST_TIMEOUT)
      try:
        _, uid, _ = PEERCRED.unpack(conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, PEERCRED.size))
        data = b""
        while not data.endswith(b"\n") and len(data) < MAX_REQUEST:
          chunk = conn.recv(MAX_REQUEST)
          if not chunk:
            break
          data += chunk
        reply = self.handle_request(json.loads(data), roles.get(uid), int(time.time()))
        conn.sendall(json.dumps(reply).encode() + b"\n")
      except (OSError, ValueError) as e:
        self.log(logging.WARNING, f"request dropped: {e}")


def main(stop: Callable[[], bool]) -> None:
  """Load state, serve until `stop()`, and exit 1 with the reason on `FatalError` (design 6.5)."""
  # Standard library imports
  import pwd

  sender = LogSender(logging.getLogger("pos_tunnel_relay"))
  leases = Leases(const.LEASES)
  for problem in leases.load():
    sender.put(logging.WARNING, f"lease file skipped: {problem}")
  const.HEARTBEAT.parent.mkdir(parents=True, exist_ok=True)
  daemon = Daemon(
    leases=leases,
    log=sender.put,
    operators=keys.read_operator_names(const.OPERATOR_KEYS),
  )
  roles = {pwd.getpwnam("ctl").pw_uid: "ctl", pwd.getpwnam("keyreader").pw_uid: "keys"}
  sender.put(logging.INFO, f"relay daemon up with {len(leases.by_port)} lease(s)")
  try:
    daemon.serve(stop, roles)
  except FatalError as e:
    sender.put(logging.CRITICAL, f"relay daemon exiting: {e}")
    sender.drain(10)
    print(f"run-app-pos-tunnel-relay: {e}", file=sys.stderr)
    sys.exit(1)
  sender.drain(5)
