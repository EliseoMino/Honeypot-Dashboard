# Deploy VPS via Coolify

This document describes how to deploy Honeypot-Dashboard on a Coolify VPS using
`compose.coolify.yaml`.

## Access model (MVP)

```
Internet
├── Cowrie SSH   -> host TCP 22
├── Cowrie Telnet -> host TCP 23
└── Dashboard    -> private, only reachable via SSH tunnel
```

- The dashboard binds to `127.0.0.1` on the VPS and is assigned **no domain**,
  so Coolify's Traefik never exposes it. Reach it through the host's own sshd
  on TCP port `22222`, no bastion/jump host needed.
- The VPS administrator's sshd listens on TCP port `22222`. Cowrie owns public
  TCP ports `22` (SSH) and `23` (Telnet). Do not restore sshd to port `22` while
  these mappings are deployed.
- PostgreSQL, the agent and the backend are **not published** to the host. They
  communicate over the Compose network by service name.
- The backend is never reachable from outside: only the nginx proxy on the
  dashboard talks to it, over mutual TLS with a client certificate.

## Prerequisites

- Coolify installed on the VPS, with the server added (local SSH access).
- A VPS whose host sshd listens on TCP port `22222`, leaving `22` for Cowrie.
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

SSH can use either the configured password or an authorized public key. For
key-only access, set `PasswordAuthentication no` after every administrator and
Coolify connection has a tested key. Keep each person's private key on their
own workstation; add only its public key to the corresponding server account.

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
    Port 22222
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
   - optionally `COWRIE_IMAGE`, `DASHBOARD_PORT`, `LOG_LEVEL`
   - See the commented "VPS / Coolify deployment" block in `.env.example`.
4. **Do not assign a domain** to any service and do not enable *Connect to
   Predefined Network*: the Compose brings its own `edge` and `data` networks
   and nothing has to be exposed through Traefik.
5. Deploy.

## Verify on the VPS

```sh
# Confirm SSH admin, dashboard, and Cowrie host bindings:
ss -tlnp | grep -E ':22222|:3000|:22|:23'

# All containers healthy:
docker ps
```

- `0.0.0.0:22` -> Cowrie SSH (container :2222)
- `0.0.0.0:23` -> Cowrie Telnet (container :2223)
- `127.0.0.1:3000` -> dashboard (nginx, internal :8080)
- host sshd -> TCP `22222`
- PostgreSQL has **no** host binding.
- The dashboard has no public route: the resource has no domain, so Traefik ignores it.

From your workstation, tunnel into the dashboard (see the SSH section above for
the one-shot command and the `~/.ssh/config` alias):

```sh
ssh -p 22222 -N -L 3000:127.0.0.1:3000 user@vps
open http://127.0.0.1:3000
```

Keep an SSH tunnel open to the dashboard using administrator port `22222`.
Separately, connect to Cowrie on port `22` from an external network and confirm
events appear in the dashboard: agent -> backend (mTLS) -> PostgreSQL.

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

## Public exposure and firewall

- Allow TCP `22` and `23` in the VPS provider firewall so Cowrie can receive
  public SSH and Telnet traffic. Keep TCP `22222` available for administration;
  restrict it to trusted source IPs if practical.
- Review the provider ToS: an open honeypot port will receive unsolicited
  traffic, and some providers restrict honeypots or may null-route accounts.
- **Dashboard access hardening** beyond the SSH tunnel (e.g. authenticated
  tunnel, WireGuard, or application authentication) once the MVP validates.

## Out of scope / not to do

- Do not move the host sshd back to port 22 while Cowrie is published there.
- Do not publish PostgreSQL, the agent or the backend to the host: the services
  reach each other by name on the Compose network.
- Do not attach this Compose to Traefik with a public domain: the dashboard is
  private by design.
- Do not touch resources of the unrelated project (VMR) hosted on the same VPS.
