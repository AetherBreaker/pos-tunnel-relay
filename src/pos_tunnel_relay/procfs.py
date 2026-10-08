"""`/proc` reads (design 6.5): process identity and listening ports, all readable as the daemon's uid."""

# Standard library imports
import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
  # Standard library imports
  from pathlib import Path

# The titles `sshd` gives a `tunnel` connection: `sshd: tunnel [priv]` (root; `tunnel-keys`'s parent,
# so the pid the daemon records) and `sshd: tunnel` or `sshd: tunnel@notty` (the unprivileged child). Not `[preauth]`.
TUNNEL_TITLE = re.compile(r"sshd: tunnel(?: \[priv\]|@\S*)?")
PRIVILEGED_TITLE = "sshd: tunnel [priv]"
TCP_LISTEN = "0A"  # the `st` column of /proc/net/tcp


def _stat(pid: int, proc: Path) -> list[str] | None:
  """`/proc/<pid>/stat` from field 3 on, or `None` when the process is gone.

  Field 2, the command name, may hold spaces and parentheses, so fields are counted from its last `)`.
  """
  try:
    stat = (proc / str(pid) / "stat").read_text(encoding="utf-8", errors="replace")
  except OSError:
    return None
  return stat[stat.rindex(")") + 2 :].split()


def start_time(pid: int, proc: Path) -> int | None:
  """Field 22, start time in clock ticks since boot: with the pid, a process's identity (pids get reused)."""
  fields = _stat(pid, proc)
  return None if fields is None else int(fields[19])


def title(pid: int, proc: Path) -> str | None:
  """The command line as `ps` shows it (`sshd` retitles its processes), or `None` when the process is gone."""
  try:
    raw = (proc / str(pid) / "cmdline").read_bytes()
  except OSError:
    return None
  return raw.replace(b"\0", b" ").decode(errors="replace").strip()


def _pids(proc: Path) -> list[int]:
  return sorted(int(entry.name) for entry in proc.iterdir() if entry.name.isdigit())


def children(pid: int, proc: Path) -> list[int]:
  """Pids whose parent (stat field 4) is `pid`."""
  return [child for child in _pids(proc) if (fields := _stat(child, proc)) is not None and fields[1] == str(pid)]


def tunnel_sshd(proc: Path, *, privileged_only: bool = False) -> list[int]:
  """Pids of `tunnel` connection processes: all of them, or only the root `[priv]` ones the daemon records."""
  found = []
  for pid in _pids(proc):
    name = title(pid, proc)
    if name is not None and (name == PRIVILEGED_TITLE if privileged_only else TUNNEL_TITLE.fullmatch(name) is not None):
      found.append(pid)
  return found


def listening(port: int, proc: Path) -> bool:
  """Whether a TCP socket listens on `port`, any address, from `/proc/net/tcp` and `tcp6`."""
  suffix = f":{port:04X}"
  for table in ("tcp", "tcp6"):
    try:
      rows = (proc / "net" / table).read_text(encoding="utf-8").splitlines()[1:]
    except OSError:
      continue
    for row in rows:
      fields = row.split()
      if fields[1].endswith(suffix) and fields[3] == TCP_LISTEN:
        return True
  return False
