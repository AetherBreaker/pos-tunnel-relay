# Standard library imports
import base64
import os
import subprocess
import time
import uuid
from pathlib import Path
from typing import TYPE_CHECKING

# Third party imports
import pytest

if TYPE_CHECKING:
  # Standard library imports
  from collections.abc import Callable

pytestmark = pytest.mark.skipif(os.environ.get("POS_RELAY_DOCKER") != "1", reason="Docker tests: set POS_RELAY_DOCKER=1")
ROOT = Path(__file__).resolve().parents[2]
PORT = 20001
DEVICE = 1
IDLE = 3600
SSH_FAILED = 255  # ssh's own failure status: refused login, refused forward
SSH_OPTS = [
  "-p",
  "2222",
  "-o",
  "StrictHostKeyChecking=no",
  "-o",
  "UserKnownHostsFile=/dev/null",
  "-o",
  "BatchMode=yes",
  "-o",
  "LogLevel=ERROR",
]


def sh(*args: str, check: bool = True, timeout: int = 600) -> subprocess.CompletedProcess[str]:
  return subprocess.run(list(args), capture_output=True, text=True, check=check, timeout=timeout)


def wait_for(what: str, condition: Callable[[], bool], timeout: float, every: float = 1.0) -> None:
  deadline = time.monotonic() + timeout
  while time.monotonic() < deadline:
    if condition():
      return
    time.sleep(every)
  pytest.fail(f"timed out after {timeout:g} s waiting for {what}")


def keygen(directory: Path, name: str) -> tuple[Path, str]:
  path = directory / name
  sh("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "", "-f", str(path))
  return path, " ".join(path.with_suffix(".pub").read_text(encoding="utf-8").split()[:2])


class Stack:
  def __init__(self, tag: str, keys_dir: Path) -> None:
    self.tag = tag
    self.network, self.volume = f"relay-net-{tag}", f"relay-data-{tag}"
    self.relay, self.client, self.logserver = f"relay-{tag}", f"relay-client-{tag}", f"relay-logs-{tag}"
    self.keys_dir = keys_dir
    self.relay_key, self.relay_pub = keygen(keys_dir, "relay")
    self.operator_key, self.operator_pub = keygen(keys_dir, "alice")
    self.pos_key, self.pos_pub = keygen(keys_dir, "pos")
    self.pos2_key, self.pos2_pub = keygen(keys_dir, "pos2")

  def up(self) -> None:
    sh("docker", "build", "-q", "-f", "tests/integration/Dockerfile", "-t", "pos-tunnel-relay:test", str(ROOT))
    sh("docker", "build", "-q", "-f", "tests/integration/logserver.Dockerfile", "-t", "pos-tunnel-relay-logs:test", str(ROOT))
    sh("docker", "network", "create", self.network)
    sh("docker", "volume", "create", self.volume)
    # -i keeps the log server's stdin open: it shuts down when stdin closes.
    sh(
      "docker",
      "run",
      "-d",
      "-i",
      "--name",
      self.logserver,
      "--network",
      self.network,
      "--network-alias",
      "logserver",
      "pos-tunnel-relay-logs:test",
    )
    # The relay exits if the log server isn't listening yet (aeth_ext's startup probe): wait for its ready line.
    wait_for("the log server", lambda: '"log_port"' in sh("docker", "logs", self.logserver).stdout, timeout=60)
    private = base64.b64encode(self.relay_key.read_bytes()).decode()
    sh(
      "docker", "run", "-d", "--name", self.relay, "--network", self.network, "--network-alias", "relay",
      "-v", f"{self.volume}:/app/persisted_data",
      "-e", f"RELAY_SSH_PRIVATE_KEY={private}", "-e", f"OPERATOR_KEYS=alice={self.operator_pub.split()[1]}",
      "-e", "ALERTS_EMAIL_PWD=unused", "-e", "LOG_CONN_HOST=logserver", "-e", "LOG_CONN_PORT=9020",
      "pos-tunnel-relay:test",
    )  # fmt: skip
    sh(
      "docker",
      "run",
      "-d",
      "--name",
      self.client,
      "--network",
      self.network,
      "--entrypoint",
      "sleep",
      "pos-tunnel-relay:test",
      "infinity",
    )
    for key in (self.operator_key, self.pos_key, self.pos2_key):
      sh("docker", "cp", str(key), f"{self.client}:/root/{key.name}")
      sh("docker", "exec", self.client, "chmod", "600", f"/root/{key.name}")
    wait_for("the relay daemon", lambda: self.ctl("status").returncode == 0, timeout=90, every=2)

  def down(self) -> None:
    for name in (self.client, self.relay, self.logserver):
      sh("docker", "rm", "-f", name, check=False)
    sh("docker", "network", "rm", self.network, check=False)
    sh("docker", "volume", "rm", self.volume, check=False)

  def ssh(self, user: str, *args: str, key: str, timeout: int = 20) -> subprocess.CompletedProcess[str]:
    return sh(
      "docker",
      "exec",
      self.client,
      "timeout",
      str(timeout),
      "ssh",
      *SSH_OPTS,
      "-i",
      f"/root/{key}",
      f"{user}@relay",
      *args,
      check=False,
      timeout=timeout + 10,
    )

  def ctl(self, *command: str) -> subprocess.CompletedProcess[str]:
    return self.ssh("ctl", *command, key="alice")

  def tunnel(self, port: int, *, key: str = "pos", exit_on_failure: bool = True) -> None:
    """A POS's `ssh -N -R` in the background; it forwards to the relay's own sshd so jump has something to reach."""
    sh(
      "docker", "exec", "-d", self.client, "ssh", *SSH_OPTS, "-i", f"/root/{key}", "-N",
      "-o", f"ExitOnForwardFailure={'yes' if exit_on_failure else 'no'}", "-R", f"{port}:relay:2222", "tunnel@relay",
    )  # fmt: skip

  def tunnels(self) -> list[str]:
    out = sh("docker", "exec", self.client, "pgrep", "-af", "tunnel@relay", check=False).stdout
    return [line for line in out.splitlines() if "-R" in line]

  def relay_exec(self, *args: str) -> subprocess.CompletedProcess[str]:
    return sh("docker", "exec", self.relay, *args, check=False)


@pytest.fixture(scope="module")
def stack(tmp_path_factory: pytest.TempPathFactory):
  s = Stack(uuid.uuid4().hex[:8], tmp_path_factory.mktemp("keys"))
  try:
    s.up()
    yield s
  finally:
    if os.environ.get("POS_RELAY_KEEP") != "1":
      s.down()


def open_lease(stack: Stack, pub: str, port: int = PORT) -> subprocess.CompletedProcess[str]:
  return stack.ctl("tunnelctl", "open", str(port), str(port - 20000), str(IDLE), *pub.split())


def logged(stack: Stack, text: str) -> bool:
  """Whether the central log server has received `text`."""
  return sh("docker", "exec", stack.logserver, "grep", "-rqF", text, "/logs", check=False).returncode == 0


def test_the_relay_presents_its_configured_public_key(stack: Stack):
  scanned = sh("docker", "exec", stack.client, "ssh-keyscan", "-p", "2222", "-t", "ed25519", "relay").stdout
  assert stack.relay_pub.split()[1] in scanned


def test_a_pos_without_a_lease_is_refused(stack: Stack):
  result = stack.ssh("tunnel", "-N", "-R", f"{PORT}:relay:2222", key="pos", timeout=10)
  assert result.returncode == SSH_FAILED
  assert "Permission denied" in result.stderr


def test_open_lets_the_pos_forward_its_own_port_only(stack: Stack):
  opened = open_lease(stack, stack.pos_pub)
  assert opened.returncode == 0, opened.stderr
  wrong = stack.ssh("tunnel", "-N", "-o", "ExitOnForwardFailure=yes", "-R", f"{PORT + 1}:relay:2222", key="pos", timeout=10)
  assert wrong.returncode == SSH_FAILED
  assert "remote port forwarding failed" in wrong.stderr
  stack.tunnel(PORT)
  wait_for("the tunnel to listen", lambda: '"listening": true' in stack.ctl("tunnelctl", "status", str(PORT)).stdout, timeout=30)
  # The refused attempt above is forgotten at the next 5 s pass.
  wait_for("one connection", lambda: '"connections": 1' in stack.ctl("tunnelctl", "status", str(PORT)).stdout, timeout=20)
  # The parent-pid link (design 6.3): the pid tunnel-keys reported is the tunnel's [priv] process.
  privileged = stack.relay_exec("pgrep", "-f", r"^sshd: tunnel \[priv\]").stdout.split()
  assert len(privileged) == 1
  wait_for("the recorded connection", lambda: logged(stack, f"connection {privileged[0]} offered "), timeout=30)
  again = open_lease(stack, stack.pos_pub, PORT + 1)
  assert again.returncode == 1
  assert "another lease holds this key" in again.stderr


def test_jump_reaches_tunnel_ports_on_localhost_only(stack: Stack):
  through = stack.ssh("jump", "-W", f"localhost:{PORT}", key="alice", timeout=10)
  assert through.stdout.startswith("SSH-2.0-OpenSSH_9.2")  # the relay's sshd, reached through the POS tunnel
  elsewhere = stack.ssh("jump", "-W", "logserver:9020", key="alice", timeout=10)
  # PermitOpen localhost:* refuses it; LogLevel=ERROR hides the "administratively prohibited" detail.
  assert elsewhere.returncode == SSH_FAILED
  assert "stdio forwarding failed" in elsewhere.stderr


def test_ctl_and_jump_refuse_a_pos_key_and_tunnel_refuses_an_operator_key(stack: Stack):
  assert stack.ssh("ctl", "status", key="pos", timeout=10).returncode == SSH_FAILED
  assert stack.ssh("jump", "-W", f"localhost:{PORT}", key="pos", timeout=10).returncode == SSH_FAILED
  assert stack.ssh("tunnel", "-N", "-R", f"{PORT}:relay:2222", key="alice", timeout=10).returncode == SSH_FAILED


def test_close_ends_the_tunnel_and_frees_the_port(stack: Stack):
  assert stack.ctl("tunnelctl", "close", str(PORT)).returncode == 0
  wait_for("the tunnel to be killed", lambda: stack.tunnels() == [], timeout=100, every=2)
  # Killing the [priv] process ended its child and freed the port (design 11).
  wait_for("the port to be released", lambda: stack.ctl("tunnelctl", "status").stdout.strip() == "[]", timeout=20)
  assert stack.relay_exec("sh", "-c", f"grep -qi ':{PORT:04X} ' /proc/net/tcp").returncode != 0


def test_a_spare_connection_dies_with_its_lease(stack: Stack):
  assert open_lease(stack, stack.pos2_pub).returncode == 0
  stack.tunnel(PORT, key="pos2")
  wait_for("the holder", lambda: '"listening": true' in stack.ctl("tunnelctl", "status", str(PORT)).stdout, timeout=30)
  stack.tunnel(PORT, key="pos2", exit_on_failure=False)  # logs in, can't bind, stays connected
  wait_for("both connections", lambda: '"connections": 2' in stack.ctl("tunnelctl", "status", str(PORT)).stdout, timeout=30)
  assert stack.ctl("tunnelctl", "close", str(PORT)).returncode == 0
  wait_for("every connection of the lease to die", lambda: stack.tunnels() == [], timeout=100, every=2)


def test_logs_reach_the_central_log_server(stack: Stack):
  wait_for("sshd's login line", lambda: logged(stack, "sshd: Accepted publickey for tunnel"), timeout=30)
  assert logged(stack, "tunnelctl by alice: open 20001")
  assert logged(stack, "no lease holds SHA256:")


def test_a_stalled_daemon_drops_every_tunnel(stack: Stack):
  assert open_lease(stack, stack.pos_pub).returncode == 0
  stack.tunnel(PORT)
  wait_for("the tunnel", lambda: '"listening": true' in stack.ctl("tunnelctl", "status", str(PORT)).stdout, timeout=30)
  assert stack.relay_exec("pkill", "-STOP", "-f", "run-app-pos-tunnel-relay").returncode == 0
  try:
    # Heartbeat stale after 180 s, then the killer's next minute.
    wait_for("the killer to fail closed", lambda: stack.tunnels() == [], timeout=330, every=5)
    status = stack.ssh("ctl", "status", key="alice", timeout=15)
    assert status.returncode in {75, 124}  # the daemon doesn't answer: "relay starting", or the login itself is held
  finally:
    stack.relay_exec("pkill", "-CONT", "-f", "run-app-pos-tunnel-relay")


def test_the_container_stops_when_sshd_dies(stack: Stack):
  stack.relay_exec("pkill", "-f", "sshd: /usr/sbin/sshd")
  wait_for(
    "the container to exit",
    lambda: sh("docker", "inspect", "-f", "{{.State.Running}}", stack.relay).stdout.strip() == "false",
    timeout=30,
  )
  # devkit-container's supervisor ends the run when a daemon exits ([tool.docker].daemons).
  assert sh("docker", "inspect", "-f", "{{.State.ExitCode}}", stack.relay).stdout.strip() == "1"
  logs = sh("docker", "logs", stack.relay)
  assert 'daemon "/usr/sbin/sshd -D -E /run/pos-tunnel/sshd.log" exited' in logs.stdout + logs.stderr
