# pos-tunnel-relay

The relay of [pos-tunnel](https://github.com/AetherBreaker/pos-tunnel): `sshd` on port 2222 plus a
daemon that owns POS leases, records which connection holds which key, enforces deadlines and logs
through `aeth_ext`. Design: pos-tunnel's `docs/design.md`, section 6.

Deployed by Coolify from `docker/compose.yaml`, with `RELAY_SSH_PRIVATE_KEY` and `OPERATOR_KEYS`
(printed by `posctl-admin`) and `ALERTS_EMAIL_PWD` in its environment.

Tests: `uv run pytest`; the Docker end-to-end tests run with `POS_RELAY_DOCKER=1`.
