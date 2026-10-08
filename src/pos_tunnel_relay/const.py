"""Paths and limits shared by the relay's programs (design 6.1, 6.5)."""

# Standard library imports
from pathlib import Path

# relay-startup recreates it empty at each start, owned by the daemon's uid (999).
RUN = Path("/run/pos-tunnel")
SSHD_LOG = RUN / "sshd.log"  # a FIFO: `sshd -E` writes it, the daemon reads it ([tool.docker].daemons)
CTL_SOCKET = RUN / "ctl.sock"
KILL_DIR = RUN / "kill"
KILLER_BEAT = RUN / "killer.beat"

PERSISTED = Path("/app/persisted_data")
LEASES = PERSISTED / "state" / "leases"
# devkit-container's supervisor reads its content; the killer reads its mtime.
HEARTBEAT = PERSISTED / "logs" / "heartbeat.txt"

OPERATOR_KEYS = Path("/etc/ssh/operator_keys")
PROC = Path("/proc")

# A beat older than this means its writer stalled: the killer then drops every tunnel, the daemon exits.
STALE_SECS = 180
