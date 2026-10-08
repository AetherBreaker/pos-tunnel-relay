"""Public keys (design 6.3, 6.4): POS key validation, fingerprints, the `tunnel` key line, operator keys."""

# Standard library imports
import base64
import binascii
import hashlib
import re
from datetime import UTC, datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
  # Standard library imports
  from pathlib import Path

ED25519 = re.compile(r"ssh-ed25519 ([A-Za-z0-9+/]+={0,2})")
# An ed25519 public key's SSH wire form: the length-prefixed type name, then the 32-byte key.
ED25519_PREFIX = b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20"
ED25519_BLOB = len(ED25519_PREFIX) + 32
OPERATOR_NAME = re.compile(r"[A-Za-z0-9._-]+")


def _is_ed25519(b64: str) -> bool:
  try:
    blob = base64.b64decode(b64, validate=True)
  except binascii.Error:
    return False
  return len(blob) == ED25519_BLOB and blob.startswith(ED25519_PREFIX)


def parse_pos_key(text: str) -> str:
  """Return `text` if it is exactly `ssh-ed25519 <base64>` of a well-formed key; else raise `ValueError`.

  The value comes from a POS-writable custom field. Only the two fields pass, so no option, comment
  or second line can reach the key line built from it.
  """
  match = ED25519.fullmatch(text)
  if match is None or not _is_ed25519(match[1]):
    raise ValueError("not an ssh-ed25519 public key")
  return text


def fingerprint(key: str) -> str:
  """`SHA256:<unpadded base64>` of a validated key, the form `sshd` logs."""
  digest = hashlib.sha256(base64.b64decode(key.split()[1])).digest()
  return "SHA256:" + base64.b64encode(digest).decode().rstrip("=")


def tunnel_line(port: int, key: str, deadline: int) -> str:
  """The `tunnel` key line for one lease (design 6.3); `expiry-time` in UTC (the `Z` suffix)."""
  expiry = datetime.fromtimestamp(deadline, UTC).strftime("%Y%m%d%H%M%SZ")
  return f'restrict,port-forwarding,permitlisten="localhost:{port}",expiry-time="{expiry}" {key}'


def parse_operator_env(value: str) -> list[tuple[str, str]]:
  """`OPERATOR_KEYS` (`<name>=<ed25519 base64>`, comma-separated) as `(name, key)`; `ValueError` names a bad entry."""
  pairs: list[tuple[str, str]] = []
  for entry in value.split(","):
    name, _, b64 = entry.strip().partition("=")
    if not OPERATOR_NAME.fullmatch(name) or not _is_ed25519(b64):
      raise ValueError(f"bad entry {entry.strip()!r}: expected <name>=<ed25519 base64>")
    pairs.append((name, f"ssh-ed25519 {b64}"))
  return pairs


def read_operator_names(path: Path) -> dict[str, str]:
  """`{"ssh-ed25519 <base64>": name}` from the operator key file relay-startup writes."""
  names: dict[str, str] = {}
  for line in path.read_text(encoding="utf-8").splitlines():
    match line.split():
      case [kind, b64, name]:
        names[f"{kind} {b64}"] = name
      case _:
        pass
  return names
