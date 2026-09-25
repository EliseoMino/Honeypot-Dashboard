# Cowrie

Configuration and documentation for the Cowrie honeypot used during
local development.

Cowrie is an external dependency. Its source code must not be copied
into this repository; the official Docker image is used instead.

Runtime directories used by `compose.yaml`:

- `etc/` — configuration files mounted into the container.
- `data/` — generated honeypot data. Ignored by git.

Security notes:

- Expose the honeypot only on an isolated network segment.
- Do not commit real honeypot logs.
- Do not mount sensitive host paths into the container.
