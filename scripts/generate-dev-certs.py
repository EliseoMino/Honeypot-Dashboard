"""Generate the development PKI used by the ingestion transport (RF-01).

The backend only serves TLS 1.3 and requires a client certificate signed by a
local CA, so a fresh checkout needs a CA plus three certificate/key pairs
before anything can talk to it:

``ca``
    The trust anchor. The backend verifies client certificates against it, and
    the agent and nginx verify the server certificate with it.
``server``
    The backend certificate. It carries the ``backend`` DNS name so the agent
    can verify the server by name on the compose network, plus ``localhost``
    and ``127.0.0.1`` so a backend running on the host can be verified too.
``agent``
    The ingestion agent client certificate. Only the backend uses it.
``proxy``
    The nginx client certificate. It lets the browser reach the backend without
    the browser ever holding a private key.
``probe``
    A throwaway client certificate for the backend container healthcheck. It
    exists so the backend only has to hold a key of its own and never the agent
    or nginx private key.

The material is for local development only. It is generated outside the
repository (``var/certs``) and must never be deployed.

The script is idempotent. Without ``--force`` an existing pair is kept as long
as it is still valid, so restarting the stack does not rotate the CA and
invalidate the certificates the other services already loaded. ``--force``
regenerates the whole set, which is the way to recover from expired or
corrupted material.

Usage::

    python scripts/generate-dev-certs.py --out var/certs
    python scripts/generate-dev-certs.py --out var/certs --force

``compose.yaml`` runs the same script through the ``cert-init`` service, writing
into the ``certs`` volume with ``--key-mode 0644`` so that the unprivileged
uids in the backend, agent and dashboard containers can all read it.
"""

from __future__ import annotations

import argparse
import getpass
import ipaddress
import os
import subprocess
import sys
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

CA_CERT_NAME = "ca.crt"
CA_KEY_NAME = "ca.key"

CA_DAYS = 3650
LEAF_DAYS = 825

#: Renew this long before expiry, so a stack that is left running for weeks does
#: not fail the morning after the certificates expire.
RENEWAL_MARGIN = timedelta(days=1)

#: A development compromise: 3072 bits keeps generation well under a second while
#: staying a size nobody would flag in a certificate audit.
KEY_SIZE = 3072

#: The names the backend certificate must answer to. ``backend`` is the compose
#: service name the agent connects to, and the loopback entries let a backend
#: running on the host be verified without disabling hostname checking.
SERVER_DNS_NAMES = ("backend", "localhost")
SERVER_IP_ADDRESSES = ("127.0.0.1",)

ORGANIZATION = "Honeypot-Dashboard"

PrivateKey = rsa.RSAPrivateKey


@dataclass(frozen=True, slots=True)
class LeafSpec:
    """A certificate pair to generate, identified by its role."""

    name: str
    common_name: str
    usages: tuple[x509.ObjectIdentifier, ...]
    server_auth: bool = False

    @property
    def cert_path(self) -> str:
        return f"{self.name}.crt"

    @property
    def key_path(self) -> str:
        return f"{self.name}.key"


LEAF_SPECS = (
    LeafSpec("server", "backend", (ExtendedKeyUsageOID.SERVER_AUTH,), server_auth=True),
    LeafSpec("agent", "honeypot-agent", (ExtendedKeyUsageOID.CLIENT_AUTH,)),
    LeafSpec("proxy", "dashboard-proxy", (ExtendedKeyUsageOID.CLIENT_AUTH,)),
    LeafSpec("probe", "backend-probe", (ExtendedKeyUsageOID.CLIENT_AUTH,)),
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="generate-dev-certs",
        description="Generate the development PKI for the TLS 1.3 mutual TLS transport.",
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=Path("var/certs"),
        help="directory that receives the certificate and key files (default: var/certs)",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="regenerate every pair, including the CA, even when valid material already exists",
    )
    parser.add_argument(
        "--key-mode",
        default="0600",
        choices=["0600", "0640", "0644"],
        help=(
            "octal permissions for the private keys (default: 0600). Use 0644 when the "
            "material is written to a Docker volume that several unprivileged "
            "containers have to read, as the compose file does"
        ),
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    out: Path = args.out
    out.mkdir(parents=True, exist_ok=True)
    key_mode = int(args.key_mode, 8)

    ca_cert_path = out / CA_CERT_NAME
    ca_key_path = out / CA_KEY_NAME
    if args.force or not _is_usable(ca_cert_path, ca_key_path):
        if ca_cert_path.exists() or ca_key_path.exists():
            print(f"replacing the development CA in {out}")
        ca_key, ca_cert = _create_ca()
        _write_pair(ca_cert, ca_key, ca_cert_path, ca_key_path, key_mode)
        print(f"generated the development CA -> {ca_cert_path}")
    else:
        ca_cert, ca_key = _load_pair(ca_cert_path, ca_key_path)
        print(f"reusing the CA in {ca_cert_path}")

    for spec in LEAF_SPECS:
        cert_path = out / spec.cert_path
        key_path = out / spec.key_path
        if not args.force and _is_usable(cert_path, key_path):
            print(f"reusing the {spec.name} certificate")
            continue
        certificate, key = _create_leaf(spec, ca_key, ca_cert)
        _write_pair(certificate, key, cert_path, key_path, key_mode)
        print(f"generated the {spec.name} certificate -> {cert_path}")

    return 0


def _generate_key() -> PrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=KEY_SIZE)


def _create_ca() -> tuple[PrivateKey, x509.Certificate]:
    key = _generate_key()
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, ORGANIZATION),
            x509.NameAttribute(NameOID.COMMON_NAME, f"{ORGANIZATION} development CA"),
        ]
    )
    now = datetime.now(UTC)
    certificate = (
        _builder(subject=subject, key=key, now=now, days=CA_DAYS)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    return key, certificate


def _create_leaf(spec: LeafSpec, ca_key: PrivateKey, ca_cert: x509.Certificate) -> tuple[x509.Certificate, PrivateKey]:
    """Create a leaf certificate and return it together with its key.

    The key is returned instead of only being used internally so the caller
    writes exactly the key the certificate was built for.
    """

    key = _generate_key()
    now = datetime.now(UTC)
    builder = _builder(
        subject=x509.Name(
            [
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, ORGANIZATION),
                x509.NameAttribute(NameOID.COMMON_NAME, spec.common_name),
            ]
        ),
        key=key,
        now=now,
        days=LEAF_DAYS,
        issuer=ca_cert.subject,
    )
    builder = builder.add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    builder = builder.add_extension(
        x509.KeyUsage(
            digital_signature=True,
            content_commitment=False,
            key_encipherment=True,
            data_encipherment=False,
            key_agreement=False,
            key_cert_sign=False,
            crl_sign=False,
            encipher_only=False,
            decipher_only=False,
        ),
        critical=True,
    )
    builder = builder.add_extension(x509.ExtendedKeyUsage(spec.usages), critical=False)
    builder = builder.add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
    builder = builder.add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_cert.public_key()),
        critical=False,
    )
    if spec.server_auth:
        names: list[x509.GeneralName] = [x509.DNSName(name) for name in SERVER_DNS_NAMES]
        names.extend(x509.IPAddress(ipaddress.ip_address(value)) for value in SERVER_IP_ADDRESSES)
        builder = builder.add_extension(x509.SubjectAlternativeName(names), critical=False)
    return builder.sign(ca_key, hashes.SHA256()), key


def _builder(
    *,
    subject: x509.Name,
    key: PrivateKey,
    now: datetime,
    days: int,
    issuer: x509.Name | None = None,
) -> x509.CertificateBuilder:
    """Start a certificate builder with the validity window every pair shares.

    ``not_valid_before`` is backdated five minutes so a container whose clock is
    slightly behind the host still accepts a certificate generated moments ago.
    """

    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer if issuer is not None else subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=days))
    )


def _write_pair(
    certificate: x509.Certificate,
    key: PrivateKey,
    cert_path: Path,
    key_path: Path,
    key_mode: int,
) -> None:
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    _write_private_key(key, key_path, key_mode)


def _write_private_key(key: PrivateKey, path: Path, key_mode: int) -> None:
    """Write an unencrypted PKCS#8 key with the requested permissions.

    An unencrypted key is deliberate: the containers mount the certificates read
    only and have to start without an interactive passphrase, and this material
    is disposable local development output.

    On Windows the permission bits have no equivalent, so the owner-only ACL is
    applied instead. That ACL is what the default ``0600`` means there; a wider
    ``--key-mode`` requested for a shared Docker volume cannot be expressed
    there, which is not a problem because the compose file writes to a volume
    inside Linux containers.
    """

    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    if sys.platform == "win32":
        path.write_bytes(pem)
        _restrict_windows_acl(path)
        return
    path.write_bytes(pem)
    path.chmod(key_mode)


def _restrict_windows_acl(path: Path) -> None:
    user = getpass.getuser()
    domain = os.environ.get("USERDOMAIN")
    account = f"{domain}\\{user}" if domain else user
    try:
        subprocess.run(
            ["icacls", str(path), "/inheritance:r", "/grant:r", f"{account}:(R,W)"],
            check=True,
            capture_output=True,
        )
    except (OSError, subprocess.CalledProcessError) as exc:
        print(f"warning: could not restrict the ACL of {path}: {exc}", file=sys.stderr)


def _is_usable(cert_path: Path, key_path: Path) -> bool:
    """Whether a pair exists, parses, matches and is not about to expire."""

    if not cert_path.is_file() or not key_path.is_file():
        return False
    try:
        certificate, _ = _load_pair(cert_path, key_path)
    except Exception as exc:  # noqa: BLE001 - unusable material is simply replaced
        print(f"replacing unusable certificate {cert_path}: {exc}", file=sys.stderr)
        return False
    return certificate.not_valid_after_utc > datetime.now(UTC) + RENEWAL_MARGIN


def _load_pair(cert_path: Path, key_path: Path) -> tuple[x509.Certificate, PrivateKey]:
    certificate = x509.load_pem_x509_certificate(cert_path.read_bytes())
    key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
    if not isinstance(key, rsa.RSAPrivateKey):
        raise ValueError(f"{key_path} is not an RSA private key")
    if certificate.public_key().public_numbers() != key.public_key().public_numbers():
        raise ValueError(f"{cert_path} and {key_path} do not belong together")
    return certificate, key


if __name__ == "__main__":
    raise SystemExit(main())
