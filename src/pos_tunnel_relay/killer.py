"""`relay-killer` (design 6.5): root `cron` job, every minute. The relay's one privileged step; it decides nothing.

It carries out the daemon's kill requests, and fails closed when the daemon has stopped beating: a
stalled daemon can no longer enforce deadlines, so no tunnel may outlive it. It logs nothing; the
daemon sees each disconnect in `sshd`'s log.
"""

# Standard library imports
import os
import signal
import time
from contextlib import suppress
from typing import TYPE_CHECKING

# First party imports
from pos_tunnel_relay import const, procfs

if TYPE_CHECKING:
  # Standard library imports
  from pathlib import Path


def _kill(pids: list[int]) -> None:
  for pid in pids:
    with suppress(ProcessLookupError):
      os.kill(pid, signal.SIGKILL)


def run(kill_dir: Path, heartbeat: Path, beat: Path, proc: Path, now: float) -> None:
  """One run: the requested kills, the fail-closed check, then this run's own beat."""
  for request in sorted(kill_dir.iterdir()):
    pid, _, start = request.name.partition("-")
    # Pid, start time and title must all still match: a reused pid names someone else's process.
    if (
      pid.isdigit()
      and start.isdigit()
      and procfs.start_time(int(pid), proc) == int(start)
      and procfs.title(int(pid), proc) == procfs.PRIVILEGED_TITLE
    ):
      _kill([*procfs.children(int(pid), proc), int(pid)])
    request.unlink(missing_ok=True)
  try:
    stale = now - heartbeat.stat().st_mtime > const.STALE_SECS
  except OSError:
    stale = True  # no heartbeat: the daemon never started, so no tunnel exists to lose
  if stale:
    _kill(procfs.tunnel_sshd(proc))
  beat.touch()
  os.utime(beat, (now, now))


def main() -> None:
  """Entry point for `relay-killer`."""
  run(const.KILL_DIR, const.HEARTBEAT, const.KILLER_BEAT, const.PROC, time.time())
