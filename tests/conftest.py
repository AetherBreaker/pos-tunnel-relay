# Standard library imports
import os
import shutil
import tempfile
from pathlib import Path

# Third party imports
import pytest

# `aeth_ext` builds its settings at import time and requires the alert password; in the container
# the compose file sets it, here a placeholder does (no test sends mail).
os.environ.setdefault("ALERTS_EMAIL_PWD", "test-placeholder")


class FakeProc:
  """A directory shaped like the parts of /proc the relay reads."""

  def __init__(self, root: Path) -> None:
    self.root = root
    (root / "net").mkdir(parents=True)
    self._listening: list[int] = []

  def add(self, pid: int, *, start: int, title: str, ppid: int = 1) -> None:
    d = self.root / str(pid)
    d.mkdir(exist_ok=True)
    # Fields from 3 on: state, ppid, 17 fillers (fields 5-21), start time (22), the rest.
    fields = ["S", str(ppid), *["0"] * 17, str(start), *["0"] * 30]
    (d / "stat").write_text(f"{pid} (sshd: a b) " + " ".join(fields) + "\n", encoding="utf-8")
    (d / "cmdline").write_bytes(title.encode() + b"\0")

  def remove(self, pid: int) -> None:
    shutil.rmtree(self.root / str(pid))

  def listen(self, port: int) -> None:
    self._listening.append(port)
    rows = ["  sl  local_address rem_address   st"]
    rows += [f"   0: 0100007F:{p:04X} 00000000:0000 0A 0:0 0:0 0 0 0 1" for p in self._listening]
    (self.root / "net" / "tcp").write_text("\n".join(rows) + "\n", encoding="utf-8")


@pytest.fixture
def proc(tmp_path: Path) -> FakeProc:
  return FakeProc(tmp_path / "proc")


@pytest.fixture
def short_dir():
  # AF_UNIX paths are limited to 108 bytes; pytest's tmp_path can be longer.
  d = Path(tempfile.mkdtemp(prefix="relay-", dir="/tmp" if Path("/tmp").is_dir() else None))
  yield d
  shutil.rmtree(d, ignore_errors=True)
