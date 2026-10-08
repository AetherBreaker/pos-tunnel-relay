"""`tunnelctl` and `tunnel-keys` (design 6.3, 6.4): thin clients of the daemon's request socket.

Both are run by `sshd`, so they start fast and import nothing heavy: no `aeth_ext`, no logging. The
daemon logs every request.
"""

# Standard library imports
import json
import os
import socket
import sys
from pathlib import Path
from typing import Any, NoReturn

# First party imports
from pos_tunnel_relay import const

EX_UNAVAILABLE = 75  # posctl reads it as "relay starting" (design 7.2)
STARTING = "relay starting: POS logins paused until the relay daemon is ready"
MAX_REPLY = 1 << 20


def request(payload: dict[str, Any], socket_path: Path | None = None, timeout: float = 5.0) -> dict[str, Any] | None:
  """Send one request to the daemon; its reply, or `None` if it isn't answering (not up yet, or stalled)."""
  try:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
      s.settimeout(timeout)
      s.connect(str(socket_path or const.CTL_SOCKET))
      s.sendall(json.dumps(payload).encode() + b"\n")
      data = b""
      while not data.endswith(b"\n") and len(data) < MAX_REPLY:
        chunk = s.recv(65536)
        if not chunk:
          break
        data += chunk
    reply = json.loads(data)
  except OSError, ValueError:
    return None
  return reply if isinstance(reply, dict) else None


def tunnelctl() -> NoReturn:
  """`ctl`'s forced command: forward `SSH_ORIGINAL_COMMAND` and the operator's public key, print the reply."""
  argv = os.environ.get("SSH_ORIGINAL_COMMAND", "").split()
  if argv[:1] == ["tunnelctl"]:
    argv = argv[1:]
  key = None
  # ExposeAuthInfo: one `publickey <type> <base64>` line for the key that logged in.
  if auth := os.environ.get("SSH_USER_AUTH"):
    for line in Path(auth).read_text(encoding="utf-8").splitlines():
      if line.startswith("publickey "):
        key = " ".join(line.split()[1:3])
        break
  reply = request({"argv": argv, "key": key})
  if reply is None:
    print(STARTING, file=sys.stderr)
    sys.exit(EX_UNAVAILABLE)
  print(reply.get("out", ""), file=sys.stdout if reply.get("status") == 0 else sys.stderr)
  sys.exit(reply.get("status", 1))


def tunnel_keys() -> None:
  """`AuthorizedKeysCommand tunnel-keys %u %f` for `tunnel` (run as `keyreader`): print the daemon's key lines, or nothing.

  Each call also reports the connection to the daemon: its parent is the connection's `[priv]` process
  (verified on OpenSSH 9.2), and `%f` is the offered key's fingerprint (design 6.3).
  """
  match sys.argv[1:]:
    case ["tunnel", fingerprint]:
      reply = request({"argv": ["keys"], "pid": os.getppid(), "fingerprint": fingerprint})
    case _:
      return
  if reply is not None and reply.get("status") == 0 and reply.get("out"):
    print(reply["out"])
