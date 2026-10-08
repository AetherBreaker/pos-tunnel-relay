# Standard library imports
import base64
import hashlib
from typing import TYPE_CHECKING

# Third party imports
import pytest

# First party imports
from pos_tunnel_relay import keys

if TYPE_CHECKING:
  # Standard library imports
  from pathlib import Path

RAW = bytes(range(32))
B64 = base64.b64encode(keys.ED25519_PREFIX + RAW).decode()
KEY = f"ssh-ed25519 {B64}"
PORT = 20001
DEADLINE = 1_767_225_600  # 2026-01-01T00:00:00Z


def test_a_bare_ed25519_key_passes():
  assert keys.parse_pos_key(KEY) == KEY


@pytest.mark.parametrize(
  "text",
  [
    f"{KEY} comment",
    f'command="sh" {KEY}',
    f"{KEY}\nssh-ed25519 {B64}",
    f"ssh-rsa {B64}",
    f"ssh-ed25519 {base64.b64encode(b'short').decode()}",
    f"ssh-ed25519 {B64[:-4]}!!!!",
    "",
  ],
)
def test_anything_but_a_bare_ed25519_key_is_refused(text: str):
  with pytest.raises(ValueError, match="not an ssh-ed25519 public key"):
    keys.parse_pos_key(text)


def test_the_fingerprint_is_sshds():
  digest = hashlib.sha256(keys.ED25519_PREFIX + RAW).digest()
  assert keys.fingerprint(KEY) == "SHA256:" + base64.b64encode(digest).decode().rstrip("=")


def test_the_tunnel_line_limits_the_key_to_its_port_until_the_deadline_utc():
  assert keys.tunnel_line(PORT, KEY, DEADLINE) == (
    f'restrict,port-forwarding,permitlisten="localhost:{PORT}",expiry-time="20260101000000Z" {KEY}'
  )


def test_operator_keys_parse_and_bad_entries_are_named():
  assert keys.parse_operator_env(f"alice={B64}, bob={B64}") == [("alice", KEY), ("bob", KEY)]
  with pytest.raises(ValueError, match="'mallory=AAAA'"):
    keys.parse_operator_env(f"alice={B64},mallory=AAAA")
  with pytest.raises(ValueError, match="bad entry"):
    keys.parse_operator_env("")


def test_operator_names_come_from_the_key_file(tmp_path: Path):
  path = tmp_path / "operator_keys"
  path.write_text(f"{KEY} alice\n\njunk\n", encoding="utf-8")
  assert keys.read_operator_names(path) == {KEY: "alice"}
