# Standard library imports
import logging
import threading
from typing import override

# First party imports
from pos_tunnel_relay.sender import LogSender


class Gate(logging.Handler):
  """Records messages; blocks emitting while `open` is clear, like aeth_ext stuck on a slow server."""

  def __init__(self) -> None:
    super().__init__()
    self.messages: list[str] = []
    self.open = threading.Event()
    self.open.set()

  @override
  def emit(self, record: logging.LogRecord) -> None:
    self.open.wait()
    self.messages.append(record.getMessage())


def make(capacity: int) -> tuple[LogSender, Gate]:
  logger = logging.getLogger(f"test-sender-{capacity}-{id(object())}")
  logger.propagate = False
  logger.setLevel(logging.DEBUG)
  gate = Gate()
  logger.addHandler(gate)
  return LogSender(logger, capacity), gate


def test_lines_arrive_in_order():
  sender, gate = make(10)
  for i in range(5):
    sender.put(logging.INFO, f"line {i}")
  sender.drain(5)
  assert gate.messages == [f"line {i}" for i in range(5)]


def test_put_never_blocks_and_drops_are_reported_once_delivery_resumes():
  sender, gate = make(2)
  gate.open.clear()
  sender.put(logging.INFO, "held")  # taken by the thread, which now blocks in emit
  for i in range(10):
    sender.put(logging.INFO, f"queued {i}")  # returns at once even though nothing drains
  gate.open.set()
  sender.drain(5)
  sender.put(logging.INFO, "after")
  sender.drain(5)
  dropped = [m for m in gate.messages if m.startswith("dropped")]
  assert len(dropped) == 1
  assert dropped[0].startswith("dropped 8 log line(s)") or dropped[0].startswith("dropped 9 log line(s)")
  assert gate.messages[-1] == "after"
