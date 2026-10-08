"""Leases (design 6.4): which POS key may hold which port, and until when.

Times are epoch seconds on the relay's own clock (design 5); `posctl` never sends one. The daemon is
the only reader and writer, so nothing here locks.
"""

# Standard library imports
import json
import os
from dataclasses import asdict, dataclass, fields, replace
from typing import TYPE_CHECKING

# First party imports
from pos_tunnel_relay import keys

if TYPE_CHECKING:
  # Standard library imports
  from pathlib import Path

PORT_BASE = 20000  # tunnel port = 20000 + NinjaOne device id (design 4)
PORT_MAX = 65535
MAX_IDLE = 12 * 3600
MAX_LIFE = 72 * 3600
OPEN_USAGE = "usage: open <port> <device-id> <idle-seconds> ssh-ed25519 <base64> [--rebuild]"
OPEN_WORDS = 5  # port, device id, idle seconds, and the key's two words


class LeaseError(Exception):
  """A refused command; the message is for the operator."""


@dataclass(frozen=True)
class Lease:
  """One open session's lease."""

  port: int
  device_id: int
  idle_seconds: int
  started: int
  idle_deadline: int
  absolute_deadline: int
  key: str
  fingerprint: str
  operator: str
  rebuild: bool = False

  @property
  def deadline(self) -> int:
    """When the lease ends. `renew` keeps `idle_deadline` within `absolute_deadline`; a hand edit might not."""
    return min(self.idle_deadline, self.absolute_deadline)


def _number(text: str, name: str) -> int:
  if not (text.isascii() and text.isdigit()):
    raise LeaseError(f"{name} must be a whole number, got {text!r}")
  return int(text)


class Leases:
  """Every lease, in memory and as one JSON file each in `directory`."""

  def __init__(self, directory: Path) -> None:
    """Empty until `load`."""
    self.directory = directory
    self.by_port: dict[int, Lease] = {}

  def load(self) -> list[str]:
    """Read every lease file; return one problem per file that isn't a valid lease (left on disk, not loaded).

    A skipped lease serves no key line and holds no fingerprint, so its POS can't log in and the
    daemon's enforcement ends any connection still using its key.
    """
    self.directory.mkdir(parents=True, exist_ok=True)
    problems = []
    for path in sorted(self.directory.glob("*.json")):
      try:
        lease = Lease(**json.loads(path.read_text(encoding="utf-8")))
        wrong = [f.name for f in fields(Lease) if type(getattr(lease, f.name)) is not f.type]
        if wrong:
          raise ValueError(f"wrong type for {', '.join(wrong)}")
        if path.stem != str(lease.port):
          raise ValueError(f"names port {lease.port}")
        keys.parse_pos_key(lease.key)
      except (OSError, ValueError, TypeError) as e:
        problems.append(f"{path.name}: {e}")
        continue
      # Recomputed, never trusted: enforcement's whole match rests on it.
      self.by_port[lease.port] = replace(lease, fingerprint=keys.fingerprint(lease.key))
    return problems

  def _save(self, lease: Lease) -> Lease:
    tmp = self.directory / f".{lease.port}.tmp"
    tmp.write_text(json.dumps(asdict(lease), indent=2) + "\n", encoding="utf-8")
    os.replace(tmp, self.directory / f"{lease.port}.json")  # a reader never sees half a file
    self.by_port[lease.port] = lease
    return lease

  def open(self, args: list[str], operator: str, now: int) -> Lease:
    """`open <port> <device-id> <idle-seconds> ssh-ed25519 <base64> [--rebuild]` (design 6.4)."""
    rebuild = "--rebuild" in args
    words = [a for a in args if a != "--rebuild"]
    if len(words) != OPEN_WORDS:
      raise LeaseError(OPEN_USAGE)
    port, device_id, idle = (_number(text, name) for text, name in zip(words, ("port", "device-id", "idle-seconds"), strict=False))
    if not PORT_BASE < port <= PORT_MAX or port != PORT_BASE + device_id:
      raise LeaseError(f"port {port} is not {PORT_BASE} + device id {device_id} in {PORT_BASE + 1}..{PORT_MAX}")
    if not 0 < idle <= MAX_IDLE:
      raise LeaseError(f"idle-seconds must be 1..{MAX_IDLE}")
    try:
      key = keys.parse_pos_key(" ".join(words[3:]))
    except ValueError as e:
      raise LeaseError(str(e)) from None
    if port in self.by_port:
      raise LeaseError(f"a lease for port {port} exists")
    # sshd uses the first line matching a key, so a second lease's POS would get the first one's port.
    if any(lease.key == key for lease in self.by_port.values()):
      raise LeaseError("another lease holds this key")
    return self._save(Lease(port, device_id, idle, now, now + idle, now + MAX_LIFE, key, keys.fingerprint(key), operator, rebuild))

  def get(self, args: list[str]) -> Lease:
    """The lease `args` (one port) names; `LeaseError` if there is none."""
    match args:
      case [text]:
        lease = self.by_port.get(_number(text, "port"))
      case _:
        raise LeaseError("usage: <command> <port>")
    if lease is None:
      raise LeaseError(f"no lease for port {text}")
    return lease

  def renew(self, args: list[str], now: int) -> Lease:
    """`renew <port>`: `idle_deadline = min(now + idle_seconds, absolute_deadline)`."""
    lease = self.get(args)
    if now >= lease.deadline:
      raise LeaseError(f"the lease for port {lease.port} has expired")
    return self._save(replace(lease, idle_deadline=min(now + lease.idle_seconds, lease.absolute_deadline)))

  def close(self, args: list[str], now: int) -> Lease:
    """`close <port>`: end the lease now; the next enforcement pass removes it."""
    return self._save(replace(self.get(args), idle_deadline=now))

  def expire(self, now: int) -> list[Lease]:
    """Drop every lease past its deadline, file and all, and return them."""
    ended = [lease for lease in self.by_port.values() if now >= lease.deadline]
    for lease in ended:
      (self.directory / f"{lease.port}.json").unlink(missing_ok=True)
      del self.by_port[lease.port]
    return ended

  def key_lines(self, now: int) -> str:
    """The `tunnel` key lines `tunnel-keys` prints: one per lease not yet past its deadline."""
    live = sorted((lease for lease in self.by_port.values() if now < lease.deadline), key=lambda lease: lease.port)
    return "\n".join(keys.tunnel_line(lease.port, lease.key, lease.deadline) for lease in live)
