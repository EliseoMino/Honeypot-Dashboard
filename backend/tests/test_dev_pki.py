"""Tests for the development PKI generator.

The generator is a repository script rather than a package module, so it is
loaded from its path. These tests cover the properties the running stack depends
on: every role gets a usable pair, the leaves chain to the CA, the server
certificate answers to the names the agent and the healthcheck use, the client
certificates carry the clientAuth EKU and nothing else, and a second run reuses
the material instead of rotating the CA under the running services.
"""

from __future__ import annotations

import importlib.util
import os
import stat
import sys
from datetime import UTC, datetime
from pathlib import Path
from types import ModuleType

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "generate-dev-certs.py"


def _load_generator() -> ModuleType:
    spec = importlib.util.spec_from_file_location("generate_dev_certs", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


generator = _load_generator()


@pytest.fixture(scope="module")
def generated(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """A freshly generated PKI, generated once for the whole module."""
    out = tmp_path_factory.mktemp("pki")
    assert generator.main(["--out", str(out)]) == 0
    return out


def _load_cert(path: Path) -> x509.Certificate:
    return x509.load_pem_x509_certificate(path.read_bytes())


def _load_key(path: Path) -> rsa.RSAPrivateKey:
    key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    assert isinstance(key, rsa.RSAPrivateKey)
    return key


def _sans(cert: x509.Certificate) -> set[str]:
    entry = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    return set(entry.get_values_for_type(x509.DNSName)) | {
        str(ip) for ip in entry.get_values_for_type(x509.IPAddress)
    }


def _assert_signed_by_ca(out: Path, name: str) -> None:
    """Verify the signature with the CA public key.

    Issuer equality alone would not notice a certificate that merely claims the
    CA's name, so the signature itself has to check out.
    """
    ca_cert = _load_cert(out / generator.CA_CERT_NAME)
    leaf = _load_cert(out / f"{name}.crt")
    ca_cert.public_key().verify(  # type: ignore[arg-type]
        leaf.signature,
        leaf.tbs_certificate_bytes,
        padding.PKCS1v15(),
        leaf.signature_hash_algorithm,  # type: ignore[arg-type]
    )


@pytest.mark.parametrize("spec", generator.LEAF_SPECS, ids=lambda spec: spec.name)
def test_every_role_gets_a_usable_pair(generated: Path, spec: generator.LeafSpec) -> None:
    cert_path = generated / spec.cert_path
    key_path = generated / spec.key_path
    assert cert_path.is_file(), f"{spec.name} certificate missing"
    assert key_path.is_file(), f"{spec.name} key missing"

    cert = _load_cert(cert_path)
    key = _load_key(key_path)
    assert cert.public_key().public_numbers() == key.public_key().public_numbers(), (
        f"{spec.name} certificate and key do not belong together"
    )


def test_ca_is_written_and_self_signed(generated: Path) -> None:
    ca_cert = _load_cert(generated / generator.CA_CERT_NAME)
    ca_key = _load_key(generated / generator.CA_KEY_NAME)

    assert ca_cert.subject == ca_cert.issuer, "the CA must be self signed"
    assert ca_cert.public_key().public_numbers() == ca_key.public_key().public_numbers()
    basic = ca_cert.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert basic.ca is True, "the CA must be marked as a certificate authority"
    assert ca_cert.extensions.get_extension_for_class(x509.KeyUsage).value.key_cert_sign is True


@pytest.mark.parametrize("spec", generator.LEAF_SPECS, ids=lambda spec: spec.name)
def test_leaf_is_signed_by_the_ca(generated: Path, spec: generator.LeafSpec) -> None:
    ca_cert = _load_cert(generated / generator.CA_CERT_NAME)
    leaf = _load_cert(generated / spec.cert_path)

    assert leaf.issuer == ca_cert.subject, f"{spec.name} was not issued by the CA"
    basic = leaf.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert basic.ca is False, f"{spec.name} must not be able to sign other certificates"
    _assert_signed_by_ca(generated, spec.name)


def test_server_certificate_covers_the_names_the_stack_connects_to(generated: Path) -> None:
    server = _load_cert(generated / "server.crt")
    sans = _sans(server)
    for expected in ("backend", "localhost", "127.0.0.1"):
        assert expected in sans, f"the server certificate is missing {expected}"

    eku = server.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert ExtendedKeyUsageOID.SERVER_AUTH in eku
    assert ExtendedKeyUsageOID.CLIENT_AUTH not in eku, (
        "the backend must not be able to authenticate as a client"
    )


@pytest.mark.parametrize("name", ["agent", "proxy", "probe"])
def test_client_certificates_are_client_auth_only(generated: Path, name: str) -> None:
    cert = _load_cert(generated / f"{name}.crt")
    eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert ExtendedKeyUsageOID.CLIENT_AUTH in eku
    assert ExtendedKeyUsageOID.SERVER_AUTH not in eku, (
        f"{name} must not be usable as a server certificate"
    )


@pytest.mark.parametrize("spec", generator.LEAF_SPECS, ids=lambda spec: spec.name)
def test_certificates_are_currently_valid(generated: Path, spec: generator.LeafSpec) -> None:
    now = datetime.now(UTC)
    cert = _load_cert(generated / spec.cert_path)
    assert cert.not_valid_before_utc <= now < cert.not_valid_after_utc


def test_keys_use_the_configured_size(generated: Path) -> None:
    ca_key = _load_key(generated / generator.CA_KEY_NAME)
    assert ca_key.key_size == generator.KEY_SIZE


def test_second_run_reuses_the_existing_material(tmp_path: Path) -> None:
    out = tmp_path / "certs"
    assert generator.main(["--out", str(out)]) == 0
    ca_before = (out / generator.CA_CERT_NAME).read_bytes()
    agent_before = (out / "agent.crt").read_bytes()

    assert generator.main(["--out", str(out)]) == 0
    assert (out / generator.CA_CERT_NAME).read_bytes() == ca_before, (
        "a rerun must not rotate the CA out from under the running services"
    )
    assert (out / "agent.crt").read_bytes() == agent_before


def test_force_rotates_every_pair(tmp_path: Path) -> None:
    out = tmp_path / "certs"
    assert generator.main(["--out", str(out)]) == 0
    ca_before = (out / generator.CA_CERT_NAME).read_bytes()

    assert generator.main(["--out", str(out), "--force"]) == 0
    assert (out / generator.CA_CERT_NAME).read_bytes() != ca_before, "--force must replace the CA"


def test_rotated_ca_reissues_the_leaves(tmp_path: Path) -> None:
    out = tmp_path / "certs"
    assert generator.main(["--out", str(out)]) == 0
    first_ca = (out / generator.CA_CERT_NAME).read_bytes()
    first_agent = (out / "agent.crt").read_bytes()

    assert generator.main(["--out", str(out), "--force"]) == 0
    assert (out / generator.CA_CERT_NAME).read_bytes() != first_ca
    assert (out / "agent.crt").read_bytes() != first_agent, (
        "leaves must be reissued, otherwise they chain to a CA nobody trusts any more"
    )
    _assert_signed_by_ca(out, "agent")


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits only")
def test_default_key_mode_is_private(tmp_path: Path) -> None:
    out = tmp_path / "certs"
    assert generator.main(["--out", str(out)]) == 0
    for key in out.glob("*.key"):
        mode = stat.S_IMODE(key.stat().st_mode)
        assert mode == 0o600, f"{key.name} is {mode:o}, expected 600"


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits only")
def test_key_mode_is_configurable(tmp_path: Path) -> None:
    out = tmp_path / "certs"
    assert generator.main(["--out", str(out), "--key-mode", "0644"]) == 0
    for key in out.glob("*.key"):
        mode = stat.S_IMODE(key.stat().st_mode)
        assert mode == 0o644, f"{key.name} is {mode:o}, expected 644"
    for cert in out.glob("*.crt"):
        assert cert.stat().st_mode & stat.S_IWOTH == 0, f"{cert.name} must not be world writable"


def test_rejects_an_unknown_key_mode(tmp_path: Path) -> None:
    with pytest.raises(SystemExit):
        generator.main(["--out", str(tmp_path / "certs"), "--key-mode", "0777"])


def test_organization_and_common_names(generated: Path) -> None:
    ca_cert = _load_cert(generated / generator.CA_CERT_NAME)
    assert ca_cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)[0].value == (
        generator.ORGANIZATION
    )
    server = _load_cert(generated / "server.crt")
    assert server.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value == "backend"


def test_certificate_files_are_pem(generated: Path) -> None:
    for path in sorted(generated.iterdir()):
        body = path.read_bytes()
        assert body.startswith(b"-----BEGIN "), f"{path.name} is not PEM encoded"
        if path.suffix == ".crt":
            assert b"-----END CERTIFICATE-----" in body
        else:
            assert b"PRIVATE KEY" in body.splitlines()[0], f"{path.name} is not a private key"
