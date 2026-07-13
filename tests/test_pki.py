"""PKI generation tests — mini-CA and per-agent key pairs."""
import subprocess
import sys
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding

PKI_DIR = Path(__file__).parent.parent / "pki"
CERT_DIR = PKI_DIR / "certs"

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
