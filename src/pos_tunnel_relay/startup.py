"""`relay-startup` (design 6.1): runs once as root, with the full environment, before the supervisor starts anything.

Everything the daemon (uid 999) can't do itself: the accounts, the relay's private key and the operator
keys from the environment, `sshd`'s and `cron`'s configuration, and a clean `/run/pos-tunnel` holding the
FIFO `sshd` logs to. devkit-container then starts `sshd` and `cron` (`[tool.docker].daemons`) and the
daemon. The private key only ever goes to its file; no message names it.
"""

# Standard library imports
import base64
import binascii
import os
import shutil
import subprocess
import sys
from importlib import resources
from pathlib import Path
from typing import NoReturn

# First party imports
from pos_tunnel_relay import const, keys

APP_UID = 999  # devkit-container's nonroot, the daemon's uid
SSHD_CONFIG = Path("/etc/ssh/sshd_config")
RELAY_KEY = Path("/run/relay/ssh_host_ed25519_key")
CRON_FILE = Path("/etc/cron.d/relay-killer")
PRIVSEP = Path("/run/sshd")  # sshd's privilege separation directory
CRON_LINE = "# The relay's killer (design 6.5).\n* * * * * root /app/.venv/bin/relay-killer\n"
# Home `/` so sshd doesn't complain to every client about a missing home directory.
USERS = (("tunnel", "/usr/sbin/nologin"), ("jump", "/usr/sbin/nologin"), ("ctl", "/bin/sh"), ("keyreader", "/usr/sbin/nologin"))


def _fail(message: str) -> NoReturn:
  print(f"relay-startup: {message}", file=sys.stderr)
  sys.exit(1)


def _run(args: list[str]) -> None:
  done = subprocess.run(args, capture_output=True, text=True, check=False)
  if done.returncode != 0:
    _fail(f"`{' '.join(args)}` exited {done.returncode}: {done.stderr.strip()}")


def _write(path: Path, data: bytes, mode: int) -> None:
  path.parent.mkdir(parents=True, exist_ok=True)
  path.write_bytes(data)
  path.chmod(mode)


def main() -> None:
  """Prepare the container for `sshd`, `cron` and the daemon (design 6.1, `relay-startup` steps 1-4)."""
  encoded = os.environ.get("RELAY_SSH_PRIVATE_KEY", "").strip()
  if not encoded:
    _fail("RELAY_SSH_PRIVATE_KEY is not set")
  try:
    private = base64.b64decode(encoded, validate=True)
  except binascii.Error:
    private = b""
  if not private.startswith(b"-----BEGIN OPENSSH PRIVATE KEY-----"):
    _fail("RELAY_SSH_PRIVATE_KEY is not an OpenSSH private key in base64")
  operator_env = os.environ.get("OPERATOR_KEYS", "").strip()
  if not operator_env:
    _fail("OPERATOR_KEYS is not set")
  try:
    operators = keys.parse_operator_env(operator_env)
  except ValueError as e:
    _fail(f"OPERATOR_KEYS: {e}")

  for name, shell in USERS:
    # A restarted container keeps its filesystem, accounts included.
    if subprocess.run(["id", "-u", name], capture_output=True, check=False).returncode != 0:
      _run(["useradd", "--system", "--no-create-home", "--home-dir", "/", "--shell", shell, name])
    _run(["usermod", "--password", "*", name])  # unusable but not locked: sshd refuses locked accounts even for keys

  RELAY_KEY.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
  _write(RELAY_KEY, private, 0o600)
  _write(const.OPERATOR_KEYS, "".join(f"{key} {name}\n" for name, key in operators).encode(), 0o644)
  _write(SSHD_CONFIG, resources.files("pos_tunnel_relay").joinpath("sshd_config").read_bytes(), 0o644)
  _write(CRON_FILE, CRON_LINE.encode(), 0o644)

  # A restart keeps the filesystem and pids start over, so old state would name unrelated processes.
  shutil.rmtree(const.RUN, ignore_errors=True)
  const.RUN.mkdir(parents=True)
  const.KILL_DIR.mkdir()
  os.mkfifo(const.SSHD_LOG)
  # The FIFO is the daemon's alone to read; root's sshd writes it regardless of its mode.
  for path, mode in ((const.RUN, 0o755), (const.KILL_DIR, 0o755), (const.SSHD_LOG, 0o600)):
    path.chmod(mode)
    os.chown(path, APP_UID, APP_UID)

  PRIVSEP.mkdir(mode=0o755, exist_ok=True)
  # A bad configuration or key stops the container here, with sshd's reason, not as a daemon exit.
  _run(["/usr/sbin/sshd", "-t"])
  print(f"relay-startup: ready; {len(operators)} operator key(s)", file=sys.stderr)
