"""`run-app-pos-tunnel-relay`: the relay daemon (design 6.5), devkit-container's supervised app."""


def run_app() -> None:
  """Start aeth_ext's socket logging, then run the daemon until SIGTERM/SIGINT (aeth_ext's `SHUTDOWN`)."""
  # Third party imports
  from aeth_ext import initialize
  from aeth_ext.errors.shutdown import SHUTDOWN

  # First party imports
  from pos_tunnel_relay import daemon

  # Exits if the log server is unreachable now (aeth_ext TODO item 14); restart: always retries.
  initialize(logging="socket")
  daemon.main(SHUTDOWN.is_set)


if __name__ == "__main__":
  run_app()
