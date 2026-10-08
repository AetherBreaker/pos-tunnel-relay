# Standard library imports
import json
from dataclasses import replace
from typing import TYPE_CHECKING

# Third party imports
import pytest
from test_keys import KEY

# First party imports
from pos_tunnel_relay import keys
from pos_tunnel_relay.leases import MAX_IDLE, MAX_LIFE, LeaseError, Leases

if TYPE_CHECKING:
  # Standard library imports
  from pathlib import Path

NOW = 1_000_000
DEVICE = 1
PORT = 20001
IDLE = 3600


@pytest.fixture
def leases(tmp_path: Path) -> Leases:
  store = Leases(tmp_path / "leases")
  store.load()
  return store


def opened(leases: Leases, *extra: str) -> None:
  leases.open([str(PORT), str(DEVICE), str(IDLE), *KEY.split(), *extra], "alice", NOW)


def test_open_records_the_lease_and_its_file(leases: Leases):
  opened(leases)
  lease = leases.by_port[PORT]
  assert (lease.started, lease.idle_deadline, lease.absolute_deadline) == (NOW, NOW + IDLE, NOW + MAX_LIFE)
  assert (lease.operator, lease.fingerprint, lease.rebuild) == ("alice", keys.fingerprint(KEY), False)
  assert json.loads((leases.directory / f"{PORT}.json").read_text(encoding="utf-8"))["key"] == KEY


@pytest.mark.parametrize(
  ("args", "message"),
  [
    ([str(PORT), str(DEVICE), str(IDLE)], "usage"),
    ([str(PORT + 1), str(DEVICE), str(IDLE), *KEY.split()], "is not 20000 \\+ device id"),
    ([str(PORT), str(DEVICE), str(MAX_IDLE + 1), *KEY.split()], "idle-seconds"),
    ([str(PORT), str(DEVICE), "0", *KEY.split()], "idle-seconds"),
    ([str(PORT), "x", str(IDLE), *KEY.split()], "whole number"),
    ([str(PORT), str(DEVICE), str(IDLE), "ssh-rsa", KEY.split()[1]], "not an ssh-ed25519"),
  ],
)
def test_open_validates(leases: Leases, args: list[str], message: str):
  with pytest.raises(LeaseError, match=message):
    leases.open(args, "alice", NOW)
  assert leases.by_port == {}


def test_open_refuses_a_taken_port_or_a_key_in_use(leases: Leases):
  opened(leases)
  with pytest.raises(LeaseError, match="exists"):
    opened(leases)
  with pytest.raises(LeaseError, match="another lease holds this key"):
    leases.open([str(PORT + 1), str(DEVICE + 1), str(IDLE), *KEY.split()], "alice", NOW)


def test_renew_extends_up_to_the_absolute_deadline_and_refuses_after_expiry(leases: Leases):
  opened(leases)
  assert leases.renew([str(PORT)], NOW + 100).idle_deadline == NOW + 100 + IDLE
  near_end = NOW + 200
  leases.by_port[PORT] = replace(leases.by_port[PORT], absolute_deadline=near_end)
  assert leases.renew([str(PORT)], NOW + 150).idle_deadline == near_end
  with pytest.raises(LeaseError, match="expired"):
    leases.renew([str(PORT)], near_end)
  with pytest.raises(LeaseError, match="no lease for port 20002"):
    leases.renew([str(PORT + 1)], NOW)


def test_close_ends_at_now_and_expire_removes_lease_and_file(leases: Leases):
  opened(leases)
  assert leases.close([str(PORT)], NOW + 5).deadline == NOW + 5
  assert leases.expire(NOW + 4) == []
  assert [lease.port for lease in leases.expire(NOW + 5)] == [PORT]
  assert leases.by_port == {}
  assert not (leases.directory / f"{PORT}.json").exists()


def test_key_lines_serve_only_live_leases(leases: Leases):
  opened(leases)
  assert leases.key_lines(NOW) == keys.tunnel_line(PORT, KEY, NOW + IDLE)
  assert leases.key_lines(NOW + IDLE) == ""


def test_leases_survive_a_restart(leases: Leases):
  opened(leases, "--rebuild")
  again = Leases(leases.directory)
  assert again.load() == []
  assert again.by_port == leases.by_port
  assert again.by_port[PORT].rebuild


def test_unreadable_files_are_skipped_and_reported(leases: Leases):
  opened(leases)
  good = json.loads((leases.directory / f"{PORT}.json").read_text(encoding="utf-8"))
  (leases.directory / "20002.json").write_text("{not json", encoding="utf-8")
  (leases.directory / "20003.json").write_text(json.dumps(good), encoding="utf-8")  # port doesn't match name
  (leases.directory / "20004.json").write_text(json.dumps({**good, "port": 20004, "idle_deadline": "soon"}), encoding="utf-8")
  (leases.directory / "20005.json").write_text(json.dumps({**good, "port": 20005, "key": f"{KEY} x"}), encoding="utf-8")
  again = Leases(leases.directory)
  problems = again.load()
  assert sorted(p.split(":")[0] for p in problems) == ["20002.json", "20003.json", "20004.json", "20005.json"]
  assert list(again.by_port) == [PORT]


def test_the_fingerprint_is_recomputed_from_the_key_at_load(leases: Leases):
  opened(leases)
  path = leases.directory / f"{PORT}.json"
  path.write_text(json.dumps({**json.loads(path.read_text(encoding="utf-8")), "fingerprint": "SHA256:forged"}), encoding="utf-8")
  again = Leases(leases.directory)
  again.load()
  assert again.by_port[PORT].fingerprint == keys.fingerprint(KEY)
