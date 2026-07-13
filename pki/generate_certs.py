"""Generate a local mini-CA and one key pair per agent.

The private key signs Entra client assertions; the public certificate is
uploaded to that agent's app registration. In Phase 2 the same certs serve
as mTLS identities.

Production note: an enterprise CA (AWS Private CA, DigiCert, Vault PKI)
replaces this script without any code change downstream — Entra verifies
the assertion against the uploaded public cert and does not walk a chain.
"""
import argparse
import datetime
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

AGENT_NAMES = ["gateway", "orchestrator", "peer", "event-trigger"]
KEY_SIZE = 2048
CA_VALID_DAYS = 3650
AGENT_VALID_DAYS = 365


def _write(path: Path, data: bytes) -> None:
    path.write_bytes(data)
    print(f"wrote {path}")


def _private_key_pem(key: rsa.RSAPrivateKey) -> bytes:
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


def _make_ca(out: Path) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=KEY_SIZE)
    subject = x509.Name([
        x509.NameAttribute(x509.NameOID.COMMON_NAME, "identity-agent-poc-root-ca"),
        x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, "identity-agent-poc"),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=CA_VALID_DAYS))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(key, hashes.SHA256())
    )
    _write(out / "ca.key", _private_key_pem(key))
    _write(out / "ca.crt", cert.public_bytes(serialization.Encoding.PEM))
    return key, cert


def _make_agent_cert(
    out: Path, name: str, ca_key: rsa.RSAPrivateKey, ca_cert: x509.Certificate
) -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=KEY_SIZE)
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(x509.NameOID.COMMON_NAME, f"agent-{name}"),
            x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, "identity-agent-poc"),
        ]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=AGENT_VALID_DAYS))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        # localhost SAN so these same certs work for mTLS in Phase 2.
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )
    _write(out / f"{name}.key", _private_key_pem(key))
    _write(out / f"{name}.crt", cert.public_bytes(serialization.Encoding.PEM))


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate mini-CA and agent certs")
    parser.add_argument(
        "--out",
        default=str(Path(__file__).parent / "certs"),
        help="output directory (default: pki/certs)",
    )
    args = parser.parse_args()

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)

    ca_key, ca_cert = _make_ca(out)
    for name in AGENT_NAMES:
        _make_agent_cert(out, name, ca_key, ca_cert)

    print(f"\nDone. Upload each <agent>.crt to its Entra app registration.")


if __name__ == "__main__":
    main()
