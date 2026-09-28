# Cowrie

Configuration and documentation for the Cowrie honeypot used during local
development.

Cowrie is an external dependency. Its source code must not be copied into this
repository; the official Docker image is used instead, pinned to the tag in
`COWRIE_IMAGE`.

## Layout

| Path | Role |
| --- | --- |
| `etc/cowrie.cfg` | Operator configuration, bind mounted as a single file. |
| `data/` | The honeypot's `var/` tree, bind mounted read/write. |

### `etc/cowrie.cfg`

The compose file mounts this one file at `/cowrie/cowrie-git/etc/cowrie.cfg`
rather than the whole `etc/` directory, so everything else Cowrie expects to
find there stays exactly as the image ships it. Because the image declares
`/cowrie/cowrie-git/etc` as a volume, Docker materialises an anonymous volume
for that directory and the file mount lands inside it.

Only overrides belong in this file. Copying the bundled
`src/cowrie/data/etc/cowrie.cfg.dist` here would freeze every default at this
version and silently ignore future upstream changes.

The `[output_jsonlog]` section name is Cowrie 3.x. The 2.x `[output_json]` with a
`file` key is ignored without an error, which would leave the agent with no file
to tail.

### `data/`

The image declares `/cowrie/cowrie-git/var` as a volume containing `log/`,
`lib/` and `run/`. Binding a host directory over that path replaces the tree
entirely, and Cowrie does not create the log directory it writes to: without the
skeleton it fails with
`No such file or directory: 'var/log/cowrie/cowrie.json'`.

So the skeleton is tracked, each directory carrying its own `.gitignore` the same
way the image does. `data/` is the *inside* of the mount point, so `data/log/` is
`var/log/` inside the container. The generated files stay untracked:

| Host path | Contents |
| --- | --- |
| `data/log/cowrie/cowrie.json` | The structured event log the agent tails. |
| `data/log/cowrie/cowrie.log` | Plain text log, kept for manual investigation. |
| `data/lib/cowrie/ssh_host_*` | Generated SSH host keys. |
| `data/lib/cowrie/uuid` | The sensor identity. |
| `data/lib/cowrie/downloads/` | Artefacts the attacker asked the honeypot to fetch. |
| `data/lib/cowrie/tty/` | Terminal transcripts. |

If the skeleton is ever lost, `git checkout -- infrastructure/cowrie/data`
restores it.

The agent mounts the same directory read only at `/cowrie/var`: it must observe
the log, never alter it.

## Two things worth knowing about the honeypot

**Credentials.** Without an `etc/userdb.txt` the image falls back to built-in
users, and the accepted passwords are not the obvious ones. Probe the honeypot
rather than assuming; `root/root` is rejected.

**Downloads.** Cowrie refuses to contact any address that is not globally
routable, as SSRF protection. A download from another container on the compose
network is silently blocked, so `wget http://some-service:8099/x` produces
`cowrie.command.input` and nothing else. Exercising
`cowrie.session.file_download` locally needs a genuinely public URL.

## Security notes

- Expose the honeypot only on an isolated network segment.
- Do not commit real honeypot logs.
- Do not mount sensitive host paths into the container.
