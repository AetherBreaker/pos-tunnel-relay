"""The daemon's way to `aeth_ext` (design 6.5): a bounded queue and one sender thread.

`aeth_ext` sends synchronously on the logging thread, up to 30 s per record while the log server is
slow, and `sshd` blocks on every log line until the daemon reads it. So the daemon's loop only queues,
and a stalled log server stalls this thread, never a login.
"""

# Standard library imports
import queue
import threading
import time
from typing import TYPE_CHECKING

if TYPE_CHECKING:
  # Standard library imports
  import logging

CAPACITY = 10_000


class LogSender:
  """Queue records for `logger` without blocking; on overflow drop and count, and report the count when delivery resumes."""

  def __init__(self, logger: logging.Logger, capacity: int = CAPACITY) -> None:
    """Start the sender thread."""
    self._logger = logger
    self._queue: queue.Queue[tuple[int, str]] = queue.Queue(capacity)
    # `put` alone writes `_dropped` and the thread alone writes `_reported`, so neither needs a lock.
    self._dropped = 0
    self._reported = 0
    threading.Thread(target=self._run, name="log-sender", daemon=True).start()

  def put(self, level: int, message: str) -> None:
    """Queue one record, or drop it when the queue is full."""
    try:
      self._queue.put_nowait((level, message))
    except queue.Full:
      self._dropped += 1

  def drain(self, timeout: float) -> None:
    """Wait up to `timeout` s for everything queued to be sent (at exit, so the last lines get out)."""
    deadline = time.monotonic() + timeout
    while self._queue.unfinished_tasks and time.monotonic() < deadline:
      time.sleep(0.05)

  def _run(self) -> None:
    while True:
      level, message = self._queue.get()
      dropped = self._dropped
      if dropped > self._reported:
        self._logger.warning("dropped %d log line(s) while the log server was behind", dropped - self._reported)
        self._reported = dropped
      self._logger.log(level, "%s", message)
      self._queue.task_done()
