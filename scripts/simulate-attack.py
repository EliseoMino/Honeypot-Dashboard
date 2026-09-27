"""Drive the local Cowrie honeypot through realistic attack sequences.

This is a development tool, not part of the product. It exists so the ingestion
pipeline can be exercised on demand, repeatably, without waiting for a real
attacker and without handcrafting each scenario with ad hoc scripts.

Every scenario names the Cowrie event ids it is expected to produce, so the
output can be compared against what the dashboard actually shows.

    python scripts/simulate-attack.py --list
    python scripts/simulate-attack.py --all
    python scripts/simulate-attack.py bruteforce session
    python scripts/simulate-attack.py --target 192.168.1.50:2222 download

Requires paramiko, which is a development extra:

    pip install -e "agent[dev]"
"""

from __future__ import annotations

import argparse
import io
import sys
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field

try:
    import paramiko
except ModuleNotFoundError:  # pragma: no cover - guidance for a missing extra
    raise SystemExit(
        "This script needs paramiko, a development extra. Install it with:\n"
        '    pip install -e "agent[dev]"'
    ) from None

DEFAULT_TARGET = "127.0.0.1:2222"

#: The interactive commands that make Cowrie emit ``cowrie.command.success``. Only
#: a few commands that read further input report that event; running `ls` does
#: not, so it would not cover RF-01.
INTERACTIVE_COMMAND = "php"
INTERACTIVE_INPUT = "<?php system($_GET['c']); ?>"

#: A command Cowrie has no implementation for, so it reports
#: ``cowrie.command.failed``.
UNKNOWN_COMMAND = "definitely-not-a-real-command --now"

#: Cowrie refuses to contact any address that is not globally routable, as SSRF
#: protection, so a download scenario needs a genuinely public URL. Anything on
#: the compose network, or the host's own address, is silently skipped.
PUBLIC_DOWNLOAD_URL = "http://example.com/index.html"

#: Credentials to probe. Cowrie's built in users are not the obvious ones, so the
#: accepted pair is discovered rather than assumed: with this image root/root is
#: rejected while oracle/oracle is accepted.
CREDENTIAL_CANDIDATES = (
    ("root", "root"),
    ("root", "password"),
    ("root", "123456"),
    ("admin", "admin"),
    ("oracle", "oracle"),
    ("guest", "guest"),
    ("ftp", "ftp"),
    ("support", "support"),
)

SETTLE_SECONDS = 1.5


@dataclass(frozen=True, slots=True)
class Scenario:
    """One attack sequence and the events it should produce."""

    name: str
    summary: str
    expected: tuple[str, ...]
    run: Callable[["Client"], None]
    note: str = ""


@dataclass(slots=True)
class Client:
    """A thin wrapper that keeps one SSH connection open per scenario."""

    host: str
    port: int
    password: str = ""
    _client: paramiko.SSHClient | None = field(default=None, init=False, repr=False)
    _channel: paramiko.Channel | None = field(default=None, init=False, repr=False)

    def connect(self, username: str, password: str) -> None:
        self.password = password
        client = paramiko.SSHClient()
        # A honeypot presents a throwaway host key; refusing to accept it would
        # only get in the way of the scenario.
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            self.host,
            port=self.port,
            username=username,
            password=password,
            look_for_keys=False,
            allow_agent=False,
            timeout=20,
        )
        self._client = client

    def open_shell(self) -> None:
        assert self._client is not None
        channel = self._client.get_transport().open_session()
        channel.get_pty()
        channel.invoke_shell()
        self._channel = channel
        time.sleep(SETTLE_SECONDS)

    def run(self, line: str, pause: float = SETTLE_SECONDS) -> str:
        assert self._channel is not None
        self._channel.send(line + "\n")
        time.sleep(pause)
        data = self._channel.recv(65535).decode("utf-8", "replace")
        return " ".join(data.split())

    def close(self) -> None:
        if self._channel is not None:
            self._channel.close()
            self._channel = None
        if self._client is not None:
            self._client.close()
            self._client = None

    def __enter__(self) -> Client:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


def _try_credentials(client: Client) -> tuple[str, str] | None:
    """Probe credentials and return the first pair the honeypot accepts."""

    for username, password in CREDENTIAL_CANDIDATES:
        probe = Client(host=client.host, port=client.port)
        try:
            probe.connect(username, password)
        except paramiko.AuthenticationException:
            print(f"    {username}/{password}: rejected")
        except Exception as exc:  # noqa: BLE001 - a refused attempt is the point
            print(f"    {username}/{password}: {type(exc).__name__}: {exc}")
        else:
            print(f"    {username}/{password}: ACCEPTED")
            return username, password
        finally:
            probe.close()
        time.sleep(0.3)
    return None


def _find_credentials(client: Client) -> tuple[str, str]:
    found = _try_credentials(client)
    if found is None:
        raise SystemExit(
            "the honeypot accepted none of the probed credentials. "
            "Check that Cowrie is running and that its user database is unchanged."
        )
    return found


def _connect_session(client: Client) -> None:
    username, password = _find_credentials(client)
    print(f"    logging in as {username}")
    client.connect(username, password)
    client.open_shell()


def scenario_churn(client: Client) -> None:
    """Open and drop connections without authenticating."""

    count = 12
    print(f"    opening {count} connections and closing them immediately")
    for _ in range(count):
        probe = Client(host=client.host, port=client.port)
        try:
            probe.connect("root", "not-even-tried")
        except paramiko.AuthenticationException:
            pass
        except Exception:  # noqa: BLE001 - the connection itself is the event
            pass
        finally:
            probe.close()
        time.sleep(0.2)


def scenario_bruteforce(client: Client) -> None:
    """Fail authentication repeatedly, to cross the brute force threshold."""

    attempts = 8
    print(f"    attempting {attempts} logins with wrong passwords")
    for index in range(attempts):
        probe = Client(host=client.host, port=client.port)
        try:
            probe.connect("root", f"wrong-{index}")
        except paramiko.AuthenticationException:
            pass
        except Exception:  # noqa: BLE001
            pass
        finally:
            probe.close()
        time.sleep(0.4)


def scenario_session(client: Client) -> None:
    """Log in and run commands, including one Cowrie does not know."""

    _connect_session(client)
    print("    uname -a")
    client.run("uname -a")
    print("    cat /etc/shadow")
    client.run("cat /etc/shadow")
    print(f"    {UNKNOWN_COMMAND}  (unknown, so command.failed)")
    client.run(UNKNOWN_COMMAND)
    print(f"    {INTERACTIVE_COMMAND}  (reads input, so command.success)")
    client.run(INTERACTIVE_COMMAND)
    client.run(INTERACTIVE_INPUT)
    client.run("exit", pause=1.0)


def scenario_download(client: Client) -> None:
    """Ask the honeypot to fetch a file, which produces a download event."""

    _connect_session(client)
    print(f"    wget {PUBLIC_DOWNLOAD_URL}")
    output = client.run(f"wget {PUBLIC_DOWNLOAD_URL}", pause=6.0)
    print(f"    honeypot said: {output[:160]}")


def scenario_pubkey(client: Client) -> None:
    """Offer a public key, which is the only way to get a fingerprint event."""

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    key = ed25519.Ed25519PrivateKey.generate()
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.OpenSSH,
        encryption_algorithm=serialization.NoEncryption(),
    )
    # paramiko wants a file object, not the encoded bytes.
    loaded = paramiko.Ed25519Key.from_private_key(io.StringIO(pem.decode()))

    print(f"    offering an ephemeral ed25519 key as {client.host}")
    attempt = paramiko.SSHClient()
    attempt.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        attempt.connect(
            client.host,
            port=client.port,
            username="root",
            pkey=loaded,
            look_for_keys=False,
            allow_agent=False,
            timeout=20,
        )
    except Exception as exc:  # noqa: BLE001 - the honeypot is meant to refuse
        print(f"    refused, as expected: {type(exc).__name__}")
    else:
        print("    accepted, which is not the configured behaviour")
        attempt.close()
        return
    finally:
        attempt.close()


SCENARIOS: tuple[Scenario, ...] = (
    Scenario(
        name="churn",
        summary="open and drop connections without authenticating",
        expected=("cowrie.session.connect", "cowrie.session.closed"),
        run=scenario_churn,
    ),
    Scenario(
        name="bruteforce",
        summary="fail authentication repeatedly, to cross the brute force threshold",
        expected=("cowrie.login.failed",),
        run=scenario_bruteforce,
    ),
    Scenario(
        name="session",
        summary="log in and run commands, including one Cowrie does not know",
        expected=(
            "cowrie.login.success",
            "cowrie.command.input",
            "cowrie.command.success",
            "cowrie.command.failed",
        ),
        run=scenario_session,
    ),
    Scenario(
        name="download",
        summary="ask the honeypot to fetch a public URL",
        expected=("cowrie.session.file_download",),
        run=scenario_download,
        note="needs outbound internet, and Cowrie only fetches globally routable addresses",
    ),
    Scenario(
        name="pubkey",
        summary="offer a public key, which is the only source of a fingerprint event",
        expected=("cowrie.client.fingerprint",),
        run=scenario_pubkey,
    ),
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="simulate-attack",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "names",
        nargs="*",
        help="scenarios to run, or --all for every one",
    )
    parser.add_argument(
        "--target",
        default=DEFAULT_TARGET,
        help=f"honeypot as host:port (default: {DEFAULT_TARGET})",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="run every scenario",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="list the scenarios and the events they produce, then exit",
    )
    return parser


def _print_scenarios() -> None:
    width = max(len(s.name) for s in SCENARIOS)
    for scenario in SCENARIOS:
        print(f"  {scenario.name.ljust(width)}  {scenario.summary}")
        print(f"  {' ' * width}  -> {', '.join(scenario.expected)}")
        if scenario.note:
            print(f"  {' ' * width}  note: {scenario.note}")


def _select(names: Sequence[str]) -> list[Scenario]:
    if not names:
        raise SystemExit("name at least one scenario, or pass --all or --list")
    known = {scenario.name: scenario for scenario in SCENARIOS}
    unknown = [name for name in names if name not in known]
    if unknown:
        raise SystemExit(
            f"unknown scenario(s): {', '.join(unknown)}. "
            f"Available: {', '.join(known)}"
        )
    return [known[name] for name in names]


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.list:
        _print_scenarios()
        return 0

    names = [s.name for s in SCENARIOS] if args.all else args.names
    selected = _select(names)

    host, _, port = args.target.rpartition(":")
    if not host or not port.isdigit():
        raise SystemExit(f"--target must look like host:port, got {args.target!r}")
    port_number = int(port)

    print(f"target: {host}:{port_number}")
    for scenario in selected:
        print(f"\n[{scenario.name}] {scenario.summary}")
        client = Client(host=host, port=port_number)
        try:
            scenario.run(client)
        except SystemExit:
            raise
        except Exception as exc:  # noqa: BLE001 - one bad scenario must not hide the rest
            print(f"    failed: {type(exc).__name__}: {exc}")
        finally:
            client.close()

    print("\nExpected in the dashboard:")
    for scenario in selected:
        print(f"  {scenario.name}: {', '.join(scenario.expected)}")

    print(
        "\nThe agent tails and ships asynchronously, so give it a few seconds.\n"
        "Rules run on demand rather than on ingest, so to turn these events into\n"
        "alerts you also need to trigger a detection run:\n"
        "  docker compose logs -f agent\n"
        "  curl -s -X POST http://127.0.0.1:3000/api/v1/detections/run \\\n"
        "       -H 'Content-Type: application/json' -d '{}'\n"
        "  curl -s http://127.0.0.1:3000/api/v1/events/summary"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
