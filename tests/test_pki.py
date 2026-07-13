"""PKI generation tests — mini-CA and per-agent key pairs."""
import stat
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509.oid import ExtendedKeyUsageOID

PKI_DIR = Path(__file__).parent.parent / "pki"
CERT_DIR = PKI_DIR / "certs"
GENERATOR = PKI_DIR / "generate_certs.py"

AGENT_NAMES = ["gateway", "orchestrator", "peer", "event-trigger"]


@pytest.fixture(scope="module")
def generated_certs(tmp_path_factory):
    """Run the generator into a temp dir and return that dir."""
    out = tmp_path_factory.mktemp("certs")
    result = subprocess.run(
        [sys.executable, str(PKI_DIR / "generate_certs.py"), "--out", str(out)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, f"generator failed: {result.stderr}"
    return out


def test_ca_cert_created(generated_certs):
    ca_path = generated_certs / "ca.crt"
    assert ca_path.exists()
    ca = x509.load_pem_x509_certificate(ca_path.read_bytes())
    # A CA must be marked as one, or it cannot sign.
    basic = ca.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert basic.ca is True


@pytest.mark.parametrize("agent", AGENT_NAMES)
def test_agent_keypair_created(generated_certs, agent):
    key_path = generated_certs / f"{agent}.key"
    crt_path = generated_certs / f"{agent}.crt"
    assert key_path.exists(), f"missing key for {agent}"
    assert crt_path.exists(), f"missing cert for {agent}"

    cert = x509.load_pem_x509_certificate(crt_path.read_bytes())
    cn = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
    assert cn == f"agent-{agent}"

    # Private key must load and must be the pair of the cert's public key.
    key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
    assert key.public_key().public_numbers() == cert.public_key().public_numbers()

    # SAN must include localhost — Phase 2 mTLS depends on this.
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert "localhost" in san.get_values_for_type(x509.DNSName)


@pytest.mark.parametrize("agent", AGENT_NAMES)
def test_agent_cert_has_client_auth_eku(generated_certs, agent):
    """Agent certs act as both client and server in the mesh; stricter TLS
    stacks may reject certs without an ExtendedKeyUsage extension."""
    crt_path = generated_certs / f"{agent}.crt"
    cert = x509.load_pem_x509_certificate(crt_path.read_bytes())
    eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert ExtendedKeyUsageOID.CLIENT_AUTH in eku
    assert ExtendedKeyUsageOID.SERVER_AUTH in eku


@pytest.mark.parametrize("agent", AGENT_NAMES)
def test_agent_cert_signed_by_ca(generated_certs, agent):
    ca = x509.load_pem_x509_certificate((generated_certs / "ca.crt").read_bytes())
    cert = x509.load_pem_x509_certificate((generated_certs / f"{agent}.crt").read_bytes())
    assert cert.issuer == ca.subject
    # Raises InvalidSignature if the CA did not sign this cert.
    ca.public_key().verify(
        cert.signature,
        cert.tbs_certificate_bytes,
        padding.PKCS1v15(),
        cert.signature_hash_algorithm,
    )


@pytest.mark.skipif(sys.platform.startswith("win"), reason="POSIX file modes only")
def test_ca_key_is_owner_only(generated_certs):
    mode = stat.S_IMODE((generated_certs / "ca.key").stat().st_mode)
    assert mode == 0o600


@pytest.mark.skipif(sys.platform.startswith("win"), reason="POSIX file modes only")
@pytest.mark.parametrize("agent", AGENT_NAMES)
def test_agent_key_is_owner_only(generated_certs, agent):
    mode = stat.S_IMODE((generated_certs / f"{agent}.key").stat().st_mode)
    assert mode == 0o600


@pytest.mark.skipif(sys.platform.startswith("win"), reason="POSIX file modes only")
def test_ca_crt_is_not_restricted(generated_certs):
    # Public certs are meant to be shared — only private keys are locked down.
    mode = stat.S_IMODE((generated_certs / "ca.crt").stat().st_mode)
    assert mode != 0o600


def test_refuses_to_overwrite_existing_certs_without_force(tmp_path):
    first = subprocess.run(
        [sys.executable, str(GENERATOR), "--out", str(tmp_path)],
        capture_output=True,
        text=True,
    )
    assert first.returncode == 0, f"first run failed: {first.stderr}"

    ca_key_before = (tmp_path / "ca.key").read_bytes()

    second = subprocess.run(
        [sys.executable, str(GENERATOR), "--out", str(tmp_path)],
        capture_output=True,
        text=True,
    )
    assert second.returncode != 0
    combined_output = second.stdout + second.stderr
    assert "--force" in combined_output
    assert "Entra" in combined_output

    # Existing key must be untouched.
    assert (tmp_path / "ca.key").read_bytes() == ca_key_before


def test_force_overwrites_existing_certs(tmp_path):
    first = subprocess.run(
        [sys.executable, str(GENERATOR), "--out", str(tmp_path)],
        capture_output=True,
        text=True,
    )
    assert first.returncode == 0, f"first run failed: {first.stderr}"

    ca_key_before = (tmp_path / "ca.key").read_bytes()

    second = subprocess.run(
        [sys.executable, str(GENERATOR), "--out", str(tmp_path), "--force"],
        capture_output=True,
        text=True,
    )
    assert second.returncode == 0, f"forced run failed: {second.stderr}"

    # A fresh key must have been generated — different from the first run.
    assert (tmp_path / "ca.key").read_bytes() != ca_key_before
