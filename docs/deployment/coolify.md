# Deploy VPS via Coolify

This document describes how to deploy Honeypot-Dashboard on a Coolify VPS using
`compose.coolify.yaml`.

## Access model (MVP)

```
Internet
├── Cowrie       -> public port dedicated (NEXT PHASE, not yet exposed)
└── Dashboard    -> private, only reachable via SSH tunnel
```

- The dashboard binds to `127.0.0.1` on the VPS and is assigned **no domain**,
  so Coolify's Traefik never exposes it. Reach it through the host's own sshd
  (port 22), no bastion/jump host needed.
- PostgreSQL, the agent and the backend are **not published** to the host. They
  communicate over the Compose network by service name.
- The backend is never reachable from outside: only the nginx proxy on the
  dashboard talks to it, over mutual TLS with a client certificate.

## Prerequisites

- Coolify installed on the VPS, with the server added (local SSH access).
- A VPS whose sshd owns port 22. Cowrie does not use it.
- A git remote containing this repository.

## SSH keys: who is who

An SSH key is a **pair** of files that identifies you to a server:

- **Private key**: secret, never leaves your machine (e.g. `~/.ssh/id_ed25519`).
- **Public key**: safe to share, ends with `.pub` (e.g.
  `~/.ssh/id_ed25519.pub`). Its content starts with `ssh-ed25519` (or `ssh-rsa`)
  and is the part that goes into the server's `~/.ssh/authorized_keys`.

There are two distinct key pairs in this setup:

| Key | Owned by | Public key lives | Used for |
| --- | --- | --- | --- |
| Coolify's server key | Coolify | generated when you add the server, viewable in Coolify UI (Server -> Keys) | Coolify runs the deploy on the VPS |
| Your workstation key | You | copied into the VPS `authorized_keys` of the deploy/ssh user | the SSH tunnel to the dashboard |

No SSH password is involved on a key-only setup (recommended:
`PasswordAuthentication no` in `/etc/ssh/sshd_config`). The server proves you
are you by asking your key to sign a challenge.

If you have no local key yet, generate one:

```sh
ssh-keygen -t ed25519 -C "you@workstation"
# ~/.ssh/id_ed25519 (private) + ~/.ssh/id_ed25519.pub (public)
```

Then append `id_ed25519.pub` to the VPS user's `authorized_keys`. Never commit
private keys or SSH passwords to the repository.

## SSH tunnel to the dashboard

A convenient `~/.ssh/config` alias on your workstation:

```
Host honeypot-vps
    HostName <ip-vps>
    User <user>
    LocalForward 3000 127.0.0.1:3000
```

`ssh honeypot-vps` then gives you both the tunnel and a shell. The dashboard is
**http://127.0.0.1:3000** on your browser. The tunnel only exposes the nginx
dashboard; Cowrie's loopback ports are not forwarded.

## Deploy steps in Coolify

1. Create a new resource of type **Application** with the **Docker Compose**
   build pack, pointing at your git repository.
2. Set the **Compose file location** to `compose.coolify.yaml`. Coolify builds
   the four service images on the VPS from the repository Dockerfiles.
3. In **Environment Variables**, enter at least:
   - `POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_DB` (required; deploy fails
     without them)
   - optionally `COWRIE_IMAGE`, `COWRIE_SSH_PORT`, `COWRIE_TELNET_PORT`,
     `DASHBOARD_PORT`, `LOG_LEVEL`
   - See the commented "VPS / Coolify deployment" block in `.env.example`.
4. **Do not assign a domain** to any service and do not enable *Connect to
   Predefined Network*: the Compose brings its own `edge` and `data` networks
   and nothing has to be exposed through Traefik.
5. Deploy.

## Verify on the VPS

```sh
# Confirm the host bindings stayed on loopback (Coolify respects them):
ss -tlnp | grep -E ':3000|:2222|:2223'

# All containers healthy:
docker ps
```

- `127.0.0.1:3000` -> dashboard (nginx, internal :8080)
- `127.0.0.1:2222` / `127.0.0.1:2223` -> Cowrie (loopback only for now)
- PostgreSQL has **no** host binding.
- No public route: the resource has no domain, so Traefik ignores it.

From your workstation, tunnel into the dashboard (see the SSH section above for
the one-shot command and the `~/.ssh/config` alias):

```sh
ssh -N -L 3000:127.0.0.1:3000 user@vps
open http://127.0.0.1:3000
```

Then make an SSH connection to the VPS on port 2222 once (or attach a carry) and
confirm events appear in the dashboard: agent -> backend (mTLS) -> PostgreSQL.

## Persistence and redeploys

| Data                      | Storage                           | Survives redeploy |
|---------------------------|-----------------------------------|-------------------|
| PostgreSQL                | volume `pgdata`                   | yes               |
| Cowrie logs / host keys   | volume `cowrie-var`               | yes               |
| Backend spool             | volume `spool`                    | yes               |
| Agent checkpoint          | volume `agentstate`               | yes               |
| PKI (CA + certificates)   | volume `certs`                    | yes               |

Cowrie's log and the agent checkpoint are intentionally kept aligned: a redeploy
does not rotate the CA nor replay the pre-redeploy history into a fresh database
(`AGENT_START_AT_END=true` in `compose.coolify.yaml`).

Config that the containers read from the repository (Cowrie `cowrie.cfg`,
detection `rules.toml`) is mounted read-only and changes on redeploy.

## Updates

Push to the tracked branch and redeploy the resource in Coolify (or wire the
webhook). Images that did not change are cached by the build layer cache.

## Next phase (not implemented yet)

- **Public Cowrie port**: publish SSH/Telnet on a public port distinct from the
  host's sshd, backed by a deliberate VPS provider firewall rule. Review the
  provider ToS first: an open honeypot port guarantees forensic traffic against
  the hosting account, and some providers null-route accounts that host it.
- **Dashboard access hardening** beyond the SSH tunnel (e.g. authenticated
  tunnel, WireGuard, or application authentication) once the MVP validates.

## Out of scope / not to do

- Do not modify or republish port 22 (`sshd`) on the VPS.
- Do not publish PostgreSQL, the agent or the backend to the host: the services
  reach each other by name on the Compose network.
- Do not attach this Compose to Traefik with a public domain: the dashboard is
  private by design.
- Do not touch resources of the unrelated project (VMR) hosted on the same VPS.