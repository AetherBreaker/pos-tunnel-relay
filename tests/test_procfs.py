# Standard library imports
from typing import TYPE_CHECKING

# First party imports
from pos_tunnel_relay import procfs

if TYPE_CHECKING:
  # Third party imports
  from conftest import FakeProc

PRIV, CHILD, OTHER = 17, 19, 23
START = 4242
PORT = 20001


def test_start_time_and_title_survive_spaces_and_parentheses_in_the_name(proc: FakeProc):
  proc.add(PRIV, start=START, title="sshd: tunnel [priv]")
  assert procfs.start_time(PRIV, proc.root) == START
  assert procfs.title(PRIV, proc.root) == "sshd: tunnel [priv]"


def test_a_gone_process_reads_as_none(proc: FakeProc):
  assert procfs.start_time(PRIV, proc.root) is None
  assert procfs.title(PRIV, proc.root) is None


def test_tunnel_connections_are_found_by_title(proc: FakeProc):
  proc.add(PRIV, start=1, title="sshd: tunnel [priv]")
  proc.add(CHILD, start=2, title="sshd: tunnel", ppid=PRIV)
  proc.add(OTHER, start=3, title="sshd: ctl [priv]")
  proc.add(29, start=4, title="sshd: tunnel [preauth]")
  assert procfs.tunnel_sshd(proc.root) == [PRIV, CHILD]
  assert procfs.tunnel_sshd(proc.root, privileged_only=True) == [PRIV]
  assert procfs.children(PRIV, proc.root) == [CHILD]


def test_listening_reads_the_tcp_tables(proc: FakeProc):
  assert not procfs.listening(PORT, proc.root)
  proc.listen(PORT)
  assert procfs.listening(PORT, proc.root)
  assert not procfs.listening(PORT + 1, proc.root)
